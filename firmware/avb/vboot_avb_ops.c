/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Implementation of callbacks needed by libavb library
 */

#include <libavb.h>

#include "2avb.h"
#include "2common.h"
#include "2load_android_kernel.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2secdata.h"
#include "cgptlib.h"
#include "cgptlib_internal.h"
#include "gpt_misc.h"
#include "vb2_android_bootimg.h"

struct avb_preload_buffer {
	uint8_t *buffer;
	size_t alloced_size;
	size_t loaded_size;
};

struct vboot_avb_ctx {
	GptData *gpt;
	vb2ex_disk_handle_t disk_handle;
	struct vb2_kernel_params *params;
	struct avb_preload_buffer preloaded[GPT_ANDROID_PRELOADED_NUM];
	const char *slot_suffix;
	struct vb2_context *vb2_ctx;
};

static inline struct vboot_avb_ctx *user_data(AvbOps *ops)
{
	return ops->user_data;
}

static AvbIOResult load_partition(GptData *gpt, vb2ex_disk_handle_t dh,
				  const char *partition_name, int64_t offset_from_partition,
				  size_t num_bytes, void *buf, size_t *out_num_read)
{
	VbExStream_t stream;
	uint64_t part_bytes, part_start_sector;
	GptEntry *e;

	if (out_num_read)
		*out_num_read = 0;

	e = GptFindEntryByName(gpt, partition_name, NULL);
	if (e == NULL) {
		VB2_DEBUG("Unable to find %s partition\n", partition_name);
		return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
	}

	part_bytes = GptGetEntrySizeBytes(gpt, e);
	part_start_sector = e->starting_lba;

	if (offset_from_partition < 0)
		offset_from_partition += part_bytes;

	if (offset_from_partition < 0 || offset_from_partition > part_bytes) {
		VB2_DEBUG("Incorrect offset from partition %" PRId64
			  "for partition %s with size %" PRIu64 "\n",
			  offset_from_partition, partition_name, part_bytes);
		return AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION;
	}

	if (num_bytes > part_bytes - offset_from_partition) {
		VB2_DEBUG("Trying to read %zu bytes from %s@%" PRIu64
			  ", but only %" PRIu64 " bytes long\n",
			  num_bytes, partition_name, offset_from_partition,
			  part_bytes - offset_from_partition);
		num_bytes = part_bytes - offset_from_partition;
	}

	if (VbExStreamOpen(dh, part_start_sector, GptGetEntrySizeLba(e), &stream)) {
		VB2_DEBUG("Unable to open disk handle\n");
		return AVB_IO_RESULT_ERROR_IO;
	}

	if (VbExStreamSkip(stream, offset_from_partition)) {
		VB2_DEBUG("Unable to skip %" PRIi64 " bytes from %s partition (part start %"
			  PRIu64 ")\n", offset_from_partition, partition_name,
			  part_start_sector);
		return AVB_IO_RESULT_ERROR_IO;
	}

	if (VbExStreamRead(stream, num_bytes, buf)) {
		VB2_DEBUG("Unable to read %s partition\n", partition_name);
		return AVB_IO_RESULT_ERROR_IO;
	}

	if (out_num_read)
		*out_num_read = num_bytes;

	VbExStreamClose(stream);

	return AVB_IO_RESULT_OK;
}

static AvbIOResult read_from_partition(AvbOps *ops,
				       const char *partition_name,
				       int64_t offset_from_partition,
				       size_t num_bytes,
				       void *buf,
				       size_t *out_num_read)
{
	struct vboot_avb_ctx *avbctx = user_data(ops);

	return load_partition(avbctx->gpt, avbctx->disk_handle, partition_name,
			      offset_from_partition, num_bytes, buf, out_num_read);
}

static AvbIOResult get_partition_size(GptData *gpt, const char *name,
				      const char *suffix, uint64_t *size)
{
	GptEntry *e = GptFindEntryByName(gpt, name, suffix);
	if (!e) {
		VB2_DEBUG("Unable to find %s%s\n", name, suffix);
		return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
	}

	*size = GptGetEntrySizeBytes(gpt, e);

	return AVB_IO_RESULT_OK;
}

static AvbIOResult reserve_buffers(AvbOps *ops)
{
	struct vboot_avb_ctx *avbctx = user_data(ops);
	GptData *gpt = avbctx->gpt;
	struct vb2_kernel_params *params = avbctx->params;
	struct avb_preload_buffer *parts = avbctx->preloaded;
	const char *slot_suffix = avbctx->slot_suffix;
	uint64_t size, available;
	const char *partition_name;
	AvbIOResult err;

	uint8_t *buffer = params->kernel_buffer;
	uint8_t *const kernel_buffer_end = buffer + params->kernel_buffer_size;
	enum GptPartition part;

	for (part = GPT_ANDROID_BOOT; part < GPT_ANDROID_PRELOADED_NUM; part++) {
		/* Skip pvmfw for now and set up it later */
		if (part == GPT_ANDROID_PVMFW)
			continue;

		partition_name = GptPartitionNames[part];
		err = get_partition_size(gpt, partition_name, slot_suffix, &size);
		if (err)
			continue;

		available = kernel_buffer_end - buffer;
		if (size > available)
			goto overflow;

		parts[part].buffer = buffer;
		parts[part].alloced_size = size;
		parts[part].loaded_size = 0;
		VB2_DEBUG("Reserved buffer for '%s' %p[%zx]\n", partition_name,
			  parts[part].buffer, parts[part].alloced_size);
		buffer += size;
	}

	/* If pvmfw is not requested to load then skip any preparions */
	if (params->pvmfw_buffer_size == 0)
		return AVB_IO_RESULT_OK;

	partition_name = GptPartitionNames[GPT_ANDROID_PVMFW];
	err = get_partition_size(gpt, partition_name, slot_suffix, &size);
	if (err)
		return AVB_IO_RESULT_OK;

	/* Make sure the buffer is big enough */
	available = params->pvmfw_buffer_size;
	if (size > available)
		goto overflow;

	parts[GPT_ANDROID_PVMFW].buffer = params->pvmfw_buffer;
	parts[GPT_ANDROID_PVMFW].alloced_size = params->pvmfw_buffer_size;
	parts[GPT_ANDROID_PVMFW].loaded_size = 0;

	return AVB_IO_RESULT_OK;
overflow:
	VB2_DEBUG("Buffer too small for '%s': has %lu requested %" PRIu64 "\n",
			partition_name, kernel_buffer_end - buffer, size);

	return AVB_IO_RESULT_ERROR_INSUFFICIENT_SPACE;

}

AvbIOResult vb2_android_get_buffer(AvbOps *ops,
				   enum GptPartition name,
				   void **buffer,
				   size_t *data_size)
{
	struct vboot_avb_ctx *avbctx = user_data(ops);
	struct avb_preload_buffer *parts = avbctx->preloaded;

	if (name >= GPT_ANDROID_PRELOADED_NUM || parts[name].loaded_size == 0)
		return AVB_IO_RESULT_ERROR_IO;

	*buffer = parts[name].buffer;
	*data_size = parts[name].loaded_size;

	return AVB_IO_RESULT_OK;
}

/*
 * Instead of using heap (huge allocations) lets use the buffer which is intended
 * to have kernel and ramdisk images anyway.
 * */
static AvbIOResult get_preloaded_partition(AvbOps *ops,
					   const char *partition,
					   size_t num_bytes,
					   uint8_t **out_pointer,
					   size_t *out_num_bytes_preloaded)
{
	struct vboot_avb_ctx *avbctx = user_data(ops);
	GptData *gpt = avbctx->gpt;
	vb2ex_disk_handle_t disk_handle = avbctx->disk_handle;
	struct avb_preload_buffer *parts = avbctx->preloaded;
	enum GptPartition gpt_part;
	int err;

	if (!avbctx->preloaded[0].alloced_size) {
		err = reserve_buffers(ops);
		if (err) {
			VB2_DEBUG("Failed to reserve buffers: %d", err);
			return err;
		}
	}

	*out_pointer = NULL;
	*out_num_bytes_preloaded = 0;

	const char *suffix = strrchr(partition, '_');
	/* We still need to return AVB_IO_RESULT_OK, even if we do not preload the partition */
	if (!suffix || strcmp(suffix, avbctx->slot_suffix) != 0)
		return AVB_IO_RESULT_OK;

	size_t namelen = suffix - partition;

	for (gpt_part = GPT_ANDROID_BOOT; gpt_part < GPT_ANDROID_PRELOADED_NUM; gpt_part++) {
		if (!strncmp(partition, GptPartitionNames[gpt_part], namelen))
			break;
	}

	if (gpt_part == GPT_ANDROID_PRELOADED_NUM)
		return AVB_IO_RESULT_OK;

	struct avb_preload_buffer *part = &parts[gpt_part];
	if (part->loaded_size >= num_bytes) {
		*out_pointer = part->buffer;
		*out_num_bytes_preloaded = num_bytes;
		return AVB_IO_RESULT_OK;
	}

	if (num_bytes > part->alloced_size) {
		VB2_DEBUG("Try to load too many bytes (%ld) into buffer of size (%ld) for %s\n",
			  num_bytes, part->alloced_size, partition);
		num_bytes = part->alloced_size;
	}

	size_t data_size;
	err = load_partition(gpt, disk_handle, partition, 0, num_bytes,
			     part->buffer, &data_size);
	if (err)
		return err;

	*out_pointer = part->buffer;
	*out_num_bytes_preloaded = VB2_MIN(num_bytes, data_size);
	part->loaded_size = data_size;
	VB2_DEBUG("Load %s into %p bytes:%lx\n", partition, *out_pointer, num_bytes);

	return AVB_IO_RESULT_OK;
}

static AvbIOResult read_rollback_index(AvbOps *ops,
				       size_t rollback_index_slot,
				       uint64_t *out_rollback_index)
{
	/*
	 * TODO(b/324230492): Implement rollback protection
	 * For now we always return 0 as the stored rollback index.
	 */
	VB2_DEBUG("TODO: not implemented yet\n");
	if (out_rollback_index != NULL)
		*out_rollback_index = 0;

	return AVB_IO_RESULT_OK;
}

static AvbIOResult read_is_device_unlocked(AvbOps *ops, bool *out_is_unlocked)
{
	struct vboot_avb_ctx *avbctx = user_data(ops);

	if (vb2_need_kernel_verification(avbctx->vb2_ctx))
		*out_is_unlocked = false;
	else if (avbctx->vb2_ctx->boot_mode == VB2_BOOT_MODE_DEVELOPER &&
	    vb2_secdata_fwmp_get_flag(avbctx->vb2_ctx, VB2_SECDATA_FWMP_DEV_USE_KEY_HASH))
		*out_is_unlocked = false;
	else
		*out_is_unlocked = true;

	VB2_DEBUG("%s\n", *out_is_unlocked ? "true" : "false");

	return AVB_IO_RESULT_OK;
}

static AvbIOResult get_unique_guid_for_partition(AvbOps *ops,
						 const char *partition,
						 char *guid_buf,
						 size_t guid_buf_size)
{
	struct vboot_avb_ctx *avbctx;
	GptData *gpt;
	GptEntry *e;

	VB2_ASSERT(ops && ops->user_data);

	avbctx = user_data(ops);
	gpt = avbctx->gpt;
	VB2_ASSERT(gpt);

	e = GptFindEntryByName(gpt, partition, NULL);
	if (e == NULL)
		return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;

	GptGuidToStr(&e->unique, guid_buf, guid_buf_size, GPT_GUID_LOWERCASE);
	return AVB_IO_RESULT_OK;
}

static AvbIOResult get_size_of_partition(AvbOps *ops,
					 const char *partition_name,
					 uint64_t *out_size)
{
	struct vboot_avb_ctx *avbctx = user_data(ops);

	return get_partition_size(avbctx->gpt, partition_name, NULL, out_size);
}

static AvbIOResult validate_vbmeta_public_key(AvbOps *ops,
					      const uint8_t *public_key_data,
					      size_t public_key_length,
					      const uint8_t *public_key_metadata,
					      size_t public_key_metadata_length,
					      bool *out_key_is_trusted)
{
	struct vboot_avb_ctx *avbctx = user_data(ops);
	struct vb2_shared_data *sd = vb2_get_sd(avbctx->vb2_ctx);
	struct vb2_public_key kernel_key;
	AvbRSAPublicKeyHeader h;
	uint8_t *key_data;
	uint32_t key_size;
	uint32_t arrsize;
	const uint32_t *avb_n, *avb_rr;
	vb2_error_t rv;

	*out_key_is_trusted = false;
	key_data = vb2_member_of(sd, sd->kernel_key_offset);
	key_size = sd->kernel_key_size;
	rv = vb2_unpack_key_buffer(&kernel_key, key_data, key_size);
	if (rv != VB2_SUCCESS) {
		VB2_DEBUG("Problem with unpacking key buffer: %#x\n", rv);
		goto out;
	}

	/*
	 * Convert key format stored in the vbmeta image - it has different
	 * endianness and size units compared to the kernel key stored in
	 * flash
	 */
	if (public_key_length < sizeof(AvbRSAPublicKeyHeader)) {
		VB2_DEBUG("Public key length too small: %zu\n", public_key_length);
		goto out;
	}

	if (!avb_rsa_public_key_header_validate_and_byteswap(
		(const AvbRSAPublicKeyHeader *)public_key_data, &h)) {
		VB2_DEBUG("Invalid vbmeta public key\n");
		goto out;
	}

	if (public_key_length < sizeof(AvbRSAPublicKeyHeader) + h.key_num_bits / 8 * 2) {
		VB2_DEBUG("Invalid vbmeta public key length: %zu, key_num_bits: %d\n",
			  public_key_length, h.key_num_bits);
		goto out;
	}

	arrsize = kernel_key.arrsize;
	if (arrsize != (h.key_num_bits / 32)) {
		VB2_DEBUG("Mismatch in key length! arrsize: %u key_num_bits: %u\n",
			  arrsize, h.key_num_bits);
		goto out;
	}

	if (kernel_key.n0inv != h.n0inv) {
		VB2_DEBUG("Mismatch in n0inv value: %x! Expected: %x\n",
			  h.n0inv, kernel_key.n0inv);
		goto out;
	}

	avb_n = (uint32_t *)(public_key_data + sizeof(AvbRSAPublicKeyHeader));
	avb_rr = avb_n + arrsize;
	for (int i = 0; i < arrsize; i++) {
		if (kernel_key.n[i] != be32toh(avb_n[arrsize - 1 - i])) {
			VB2_DEBUG("Mismatch in n key component!\n");
			goto out;
		}
		if (kernel_key.rr[i] != be32toh(avb_rr[arrsize - 1 - i])) {
			VB2_DEBUG("Mismatch in rr key component!\n");
			goto out;
		}
	}

	*out_key_is_trusted = true;
out:
	return AVB_IO_RESULT_OK;
}

/*
 * Initialize platform callbacks used within libavb.
 *
 * @param  vb2_ctx     Vboot context
 * @param  params      Vboot kernel parameters
 * @param  gpt         Pointer to gpt struct correlated with boot disk
 * @param  disk_handle Handle to boot disk
 * @param  slot_suffix Suffix of active partition
 * @return pointer to AvbOps structure which should be used for invocation of
 *         libavb methods.
 */
AvbOps *vboot_avb_ops_new(struct vb2_context *vb2_ctx,
			  struct vb2_kernel_params *params,
			  GptData *gpt,
			  vb2ex_disk_handle_t disk_handle,
			  const char *slot_suffix)
{
	struct vboot_avb_ctx *avbctx;
	AvbOps *avb_ops;

	avb_ops = malloc(sizeof(*avb_ops));
	if (avb_ops == NULL)
		return NULL;
	memset(avb_ops, 0, sizeof(*avb_ops));

	avbctx = malloc(sizeof(*avbctx));
	if (avbctx == NULL) {
		free(avb_ops);
		return NULL;
	}
	memset(avbctx, 0, sizeof(*avbctx));

	avbctx->disk_handle = disk_handle;
	avbctx->gpt = gpt;
	avbctx->params = params;
	avbctx->slot_suffix = slot_suffix;
	avbctx->vb2_ctx = vb2_ctx;
	avb_ops->user_data = avbctx;

	avb_ops->read_from_partition = read_from_partition;
	avb_ops->get_preloaded_partition = get_preloaded_partition;
	avb_ops->read_rollback_index = read_rollback_index;
	avb_ops->read_is_device_unlocked = read_is_device_unlocked;
	avb_ops->get_unique_guid_for_partition = get_unique_guid_for_partition;
	avb_ops->get_size_of_partition = get_size_of_partition;
	avb_ops->validate_vbmeta_public_key = validate_vbmeta_public_key;

	return avb_ops;
}

void vboot_avb_ops_free(AvbOps *ops)
{
	if (ops == NULL)
		return;

	free(ops->user_data);
	free(ops);
}
