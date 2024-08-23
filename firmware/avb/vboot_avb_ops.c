/* Copyright 2024 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Implementation of callbacks needed by libavb library
*/

#include <libavb.h>

#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2secdata.h"
#include "vb2_common.h"
#include "vboot_avb_ops.h"
#include "cgptlib.h"
#include "cgptlib_internal.h"
#include "android_image_hdr.h"

struct vboot_avb_data {
	LoadKernelParams *params;
	GptData *gpt;
	VbExStream_t stream; /* Stream opened for kernel partition read */
	VbExDiskHandle_t disk_handle;
	struct vb2_context *vb2_ctx;
};

void vboot_avb_ops_free(AvbOps *ops)
{
	if (ops == NULL)
		return;

	avb_free(ops->user_data);
	avb_free(ops);
}

static AvbIOResult vboot_avb_read_from_partition(AvbOps *ops,
				       const char *partition_name,
				       int64_t offset_from_partition,
				       size_t num_bytes,
				       void *buf,
				       size_t *out_num_read)
{
	struct vboot_avb_data *ctx = (struct vboot_avb_data *)ops->user_data;
	VbExStream_t stream;
	uint64_t part_start, part_size;
	uint64_t start_sector, sectors_to_read, pre_misalign;
	uint8_t *tmp_buf;

	if (GptFindOffsetByName(ctx->gpt, partition_name, &part_start, &part_size) !=
	    GPT_SUCCESS) {
		VB2_DEBUG("Unable to find %s partition\n", partition_name);
		return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
	}

	if (offset_from_partition >= 0) {
		start_sector = (offset_from_partition / ctx->gpt->sector_bytes) + part_start;
		pre_misalign = offset_from_partition % ctx->gpt->sector_bytes;
	} else {
		if (-offset_from_partition > part_size * ctx->gpt->sector_bytes)
			return AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION;

		start_sector = part_start +
			       (part_size * ctx->gpt->sector_bytes + offset_from_partition) /
				ctx->gpt->sector_bytes;
		pre_misalign = ctx->gpt->sector_bytes -
			       (-offset_from_partition % ctx->gpt->sector_bytes);
		if (pre_misalign == ctx->gpt->sector_bytes)
			pre_misalign = 0;
	}

	sectors_to_read = (pre_misalign + num_bytes) / ctx->gpt->sector_bytes;
	if ((pre_misalign + num_bytes) % ctx->gpt->sector_bytes)
		sectors_to_read += 1;

	if (sectors_to_read > part_size) {
		VB2_DEBUG("Read request bigger than available data\n");
		return AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION;
	}

	if (VbExStreamOpen(ctx->disk_handle, start_sector, sectors_to_read,
			   &stream)) {
		VB2_DEBUG("Unable to open disk handle.\n");
		return AVB_IO_RESULT_ERROR_IO;
	}

	if (pre_misalign != 0 || (num_bytes % ctx->gpt->sector_bytes)) {
		tmp_buf = malloc(sectors_to_read * ctx->gpt->sector_bytes);
		if (tmp_buf == NULL) {
			VB2_DEBUG("Cannot allocate buffer for unaligned read\n");
			return AVB_IO_RESULT_ERROR_OOM;
		}
	} else {
		tmp_buf = buf;
	}

	if (VbExStreamRead(stream, sectors_to_read * ctx->gpt->sector_bytes, tmp_buf)) {
		VB2_DEBUG("Unable to read ramdisk partition\n");
		return AVB_IO_RESULT_ERROR_IO;
	}

	/*
	 * TODO(b/331881159): "Add support for non-sector size reads in
	 * depthcharge block driver
	 */
	if (pre_misalign != 0 || (num_bytes % ctx->gpt->sector_bytes)) {
		memcpy(buf, tmp_buf + pre_misalign, num_bytes);
		free(tmp_buf);
	}
	*out_num_read = num_bytes;

	VbExStreamClose(stream);

	return AVB_IO_RESULT_OK;
}


static AvbIOResult vboot_avb_get_size_of_partition(AvbOps *ops,
					 const char *partition_name,
					 uint64_t *out_size)
{
	struct vboot_avb_data *ctx = (struct vboot_avb_data *)ops->user_data;
	uint64_t part_start, part_size;

	if (GptFindOffsetByName(ctx->gpt, partition_name, &part_start, &part_size) !=
	    GPT_SUCCESS) {
		VB2_DEBUG("Unable to find %s partition\n", partition_name);
		return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
	}

	*out_size = ctx->gpt->sector_bytes * part_size;

	return AVB_IO_RESULT_OK;
}

static AvbIOResult vboot_avb_read_is_device_unlocked(AvbOps *ops, bool *out_is_unlocked)
{
	struct vboot_avb_data *ctx = (struct vboot_avb_data *)ops->user_data;

	*out_is_unlocked = false;

	int dev_mode = ctx->vb2_ctx->flags & VB2_CONTEXT_DEVELOPER_MODE;

	/* FWMP can require developer mode to use signed images */
	int fwmp_locked = vb2_secdata_fwmp_get_flag(
		ctx->vb2_ctx, VB2_SECDATA_FWMP_DEV_ENABLE_OFFICIAL_ONLY);

	/* Developers may require signed images */
	int nv_dev_locked  = vb2_nv_get(ctx->vb2_ctx, VB2_NV_DEV_BOOT_SIGNED_ONLY);

	/*
	 * If developer mode is enabled and signed image is not required,
	 * then unlocked is TRUE
	 */
	if (dev_mode && !fwmp_locked && !nv_dev_locked)
		*out_is_unlocked = true;

	return AVB_IO_RESULT_OK;
}

static AvbIOResult vboot_avb_read_rollback_index(AvbOps *ops,
				       size_t rollback_index_slot,
				       uint64_t *out_rollback_index) {
	/*
	 * TODO(b/324230492): Implement rollback protection
	 * For now we always return 0 as the stored rollback index.
	 */
	avb_debug("TODO: implement read_rollback_index().\n");
	if (out_rollback_index != NULL)
		*out_rollback_index = 0;

	return AVB_IO_RESULT_OK;
}

static AvbIOResult get_unique_guid_for_partition(AvbOps *ops,
						 const char *partition,
						 char *guid_buf,
						 size_t guid_buf_size)
{
	/* TODO(b/324233168): Implement getter for vbmeta partition GUID */
	/*
	 * Use test UUID from android codebase as a placeholder for now. As it
	 * is informational only, there is no harm. Leaving it empty may cause
	 * issues with cmdline properties formatting.
	 */
	char tmp[] = "aa08f1a4-c7c9-402e-9a66-9707cafa9ceb";
	memcpy(guid_buf, &tmp, sizeof(tmp));
	avb_debug("TODO: function not implemented yet\n");
	return AVB_IO_RESULT_OK;
}

static AvbIOResult validate_vbmeta_public_key(AvbOps *ops,
					      const uint8_t *public_key_data,
					      size_t public_key_length,
					      const uint8_t *public_key_metadata,
					      size_t public_key_metadata_length,
					      bool *out_key_is_trusted)
{
	struct vboot_avb_data *ctx = (struct vboot_avb_data *)ops->user_data;
	struct vb2_shared_data *sd = vb2_get_sd(ctx->vb2_ctx);
	struct vb2_public_key kernel_key;
	AvbRSAPublicKeyHeader h;
	uint8_t *key_data;
	uint32_t key_size;
	uint32_t avb_key_len;
	const uint8_t *n, *rr;
	uint32_t *tmp_buf = NULL;

	if (out_key_is_trusted == NULL)
		return AVB_IO_RESULT_ERROR_NO_SUCH_VALUE;

	*out_key_is_trusted = false;
	key_data = vb2_member_of(sd, sd->kernel_key_offset);
	key_size = sd->kernel_key_size;
	vb2_unpack_key_buffer(&kernel_key, key_data, key_size);

	/*
	 * Convert key format stored in the vbmeta image - it has different
	 * endianness and size units compared to the kernel_subkey stored in
	 * flash
	 */
	if (!avb_rsa_public_key_header_validate_and_byteswap(
		(const AvbRSAPublicKeyHeader *)public_key_data, &h)) {
		avb_error("Invalid vbmeta pulic key\n");
		goto out;
	}

	/* Kernel key length is stored as number of uint32_t */
	avb_key_len = h.key_num_bits / 32;

	if (kernel_key.arrsize != avb_key_len) {
		avb_error("Mismatch in key length!\n");
		goto out;
	}

	if (kernel_key.n0inv != h.n0inv) {
		avb_error("Mismatch in n0inv value!\n");
		goto out;
	}

	tmp_buf = malloc(h.key_num_bits / 8);

	n = public_key_data + sizeof(AvbRSAPublicKeyHeader);
	for (int i = 0; i < avb_key_len; i++)
		tmp_buf[i] = avb_be32toh(((uint32_t *)n)[avb_key_len - 1 - i]);

	if (memcmp(kernel_key.n, tmp_buf, kernel_key.arrsize)) {
		avb_error("Mismatch in n key component!\n");
		goto out;
	}

	rr = public_key_data + sizeof(AvbRSAPublicKeyHeader) + h.key_num_bits / 8;
	for (int i = 0; i < avb_key_len; i++)
		tmp_buf[i] = avb_be32toh(((uint32_t *)rr)[avb_key_len - 1 - i]);

	if (memcmp(kernel_key.rr, tmp_buf, kernel_key.arrsize)) {
		avb_error("Mismatch in rr key component!\n");
		goto out;
	}

	*out_key_is_trusted = true;

out:
	free(tmp_buf);
	return AVB_IO_RESULT_OK;
}

static vb2_error_t vb2_load_ramdisk(GptData *gpt, struct LoadKernelParams *params,
				    VbExDiskHandle_t disk_handle,
				    uint64_t *part_start, uint64_t *part_size,
				    uint32_t *bytes_used)
{
	VbExStream_t stream;
	uint32_t read_ms = 0, start_ts;
	uint64_t part_bytes;
	uint8_t *part_ramdisk_buf;
	vb2_error_t res = VB2_ERROR_LOAD_PARTITION_READ_BODY;

	if (VbExStreamOpen(disk_handle, *part_start, *part_size,
			   &stream)) {
		VB2_DEBUG("Unable to open disk handle.\n");
		return res;
	}

	part_bytes = gpt->sector_bytes * *part_size;
	if (part_bytes > (params->kernel_buffer_size - *bytes_used)) {
		VB2_DEBUG("No space left to load ramdisk partition\n");
		goto out;
	}

	part_ramdisk_buf = params->kernel_buffer + *bytes_used;
	/* Load partition to memory */
	start_ts = vb2ex_mtime();
	if (VbExStreamRead(stream, part_bytes, part_ramdisk_buf)) {
		VB2_DEBUG("Unable to read ramdisk partition\n");
		goto out;
	}
	read_ms += vb2ex_mtime() - start_ts;

	if (read_ms == 0)  /* Avoid division by 0 in speed calculation */
		read_ms = 1;
	VB2_DEBUG("read %u KB in %u ms at %u KB/s.\n",
		  (uint32_t)(part_bytes) / 1024, read_ms,
		  (uint32_t)(((part_bytes) * VB2_MSEC_PER_SEC) /
			  (read_ms * 1024)));

	*bytes_used += part_bytes;

	res = VB2_SUCCESS;
out:
	VbExStreamClose(stream);
	return res;
}

static vb2_error_t vb2_load_vendor_boot_ramdisk(struct vb2_context *ctx, GptData *gpt,
						struct LoadKernelParams *params,
						VbExDiskHandle_t disk_handle,
						uint32_t *bytes_used)
{
	uint64_t part_start, part_size;

	if (GptFindVendorBoot(gpt, &part_start, &part_size) != GPT_SUCCESS) {
		VB2_DEBUG("Unable to find vendor_boot partition\n");
		return VB2_ERROR_LOAD_PARTITION_READ_BODY;
	}

	params->vendor_boot_offset = *bytes_used;

	if (vb2_load_ramdisk(gpt, params, disk_handle, &part_start,
			     &part_size, bytes_used)) {
		VB2_DEBUG("Unable to load vendor_boot partition\n");
		return VB2_ERROR_LOAD_PARTITION_READ_BODY;
	}

	return VB2_SUCCESS;
}

static vb2_error_t vb2_load_init_boot_ramdisk(struct vb2_context *ctx, GptData *gpt,
					      struct LoadKernelParams *params,
					      VbExDiskHandle_t disk_handle,
					      uint32_t *bytes_used)
{
	uint64_t part_start, part_size;

	if (GptFindInitBoot(gpt, &part_start, &part_size) != GPT_SUCCESS) {
		VB2_DEBUG("Unable to find init_boot partition\n");
		return VB2_ERROR_LOAD_PARTITION_READ_BODY;
	}

	params->init_boot_offset = *bytes_used;

	if (vb2_load_ramdisk(gpt, params, disk_handle, &part_start,
			     &part_size, bytes_used)) {
		VB2_DEBUG("Unable to load init_boot partition\n");
		return VB2_ERROR_LOAD_PARTITION_READ_BODY;
	}

	params->init_boot_size = *bytes_used - params->init_boot_offset;

	return VB2_SUCCESS;
}

static vb2_error_t vb2_load_android_ramdisks(struct vb2_context *ctx, GptData *gpt,
					     struct LoadKernelParams *params,
					     VbExDiskHandle_t disk_handle,
					     uint32_t *bytes_used)
{
	vb2_error_t ret;

	ret = vb2_load_vendor_boot_ramdisk(ctx, gpt, params, disk_handle, bytes_used);
	if (ret != VB2_SUCCESS) {
		VB2_DEBUG("Unable to read vendor_boot partition\n");
		return ret;
	}

	ret = vb2_load_init_boot_ramdisk(ctx, gpt, params, disk_handle, bytes_used);
	if (ret != VB2_SUCCESS) {
		VB2_DEBUG("Unable to read init_boot partition\n");
		return ret;
	}

	/* Update flags to mark loaded GKI image */
	params->flags &= ~VB2_KERNEL_TYPE_MASK;
	params->flags |= VB2_KERNEL_TYPE_ANDROID_GKI;

	return VB2_SUCCESS;
}

static vb2_error_t load_android_kernel(struct LoadKernelParams *params,
				       VbExStream_t stream, uint32_t num_bytes)
{
	uint32_t read_ms, start_ts;
	uint8_t *kernbuf;
	uint32_t kernbuf_size;
	struct boot_img_hdr_v4 *hdr;

	kernbuf = params->kernel_buffer;
	kernbuf_size = params->kernel_buffer_size;
	if (!kernbuf || !kernbuf_size) {
		VB2_DEBUG("Caller have not defined kernel_buffer and it's size\n");
		return VB2_ERROR_LOAD_PARTITION_BODY_SIZE;
	}

	if (kernbuf_size < num_bytes) {
		VB2_DEBUG("Not enough space for kernel\n");
		return VB2_ERROR_LOAD_PARTITION_BODY_SIZE;
	}

	/* Read kernel data starting from kernel header till end of partition */
	start_ts = vb2ex_mtime();
	if (VbExStreamRead(stream, num_bytes, kernbuf)) {
		VB2_DEBUG("Unable to read kernel data.\n");
		return VB2_ERROR_LOAD_PARTITION_READ_BODY;
	}

	read_ms = vb2ex_mtime() - start_ts;
	if (read_ms == 0)  /* Avoid division by 0 in speed calculation */
		read_ms = 1;
	VB2_DEBUG("read %u KB in %u ms at %u KB/s.\n",
		  (uint32_t)(num_bytes / 1024), read_ms,
		  (uint32_t)((num_bytes *
				  VB2_MSEC_PER_SEC) / (read_ms * 1024)));

	/* Validate read partition */
	hdr = (struct boot_img_hdr_v4 *)kernbuf;
	if (memcmp(hdr->magic, BOOT_MAGIC, BOOT_MAGIC_SIZE)) {
		VB2_DEBUG("BOOT_MAGIC mismatch!\n");
		return VB2_ERROR_LK_NO_KERNEL_FOUND;
	}
	if (hdr->header_version != 4) {
		VB2_DEBUG("Unsupported header version %d\n", hdr->header_version);
		return VB2_ERROR_LK_NO_KERNEL_FOUND;
	}

	return VB2_SUCCESS;
}

/*
 * Do all the heavy lifting here. Instead of using heap (huge
 * allocations) lets use the buffer which is intended to have kernel and
 * ramdisk images anyway.
 * */
static AvbIOResult vboot_avb_get_preloaded_partition(AvbOps *ops,
				       const char *partition,
				       size_t num_bytes,
				       uint8_t **out_pointer,
				       size_t *out_num_bytes_preloaded)
{

	/* Keep this through the invocation of this function to properly lay
	 * content in memory */
	static uint32_t bytes_used;
	static bool ramdisk_preloaded = false;
	struct vboot_avb_data *avb_data = (struct vboot_avb_data *)ops->user_data;
	char *suffix = NULL;
	char *short_partition_name;
	int ret;

	/*
	 * Only load the partitions with suffix matching to the currently
	 * selected slot.
	 */
	ret = GptGetActiveKernelPartitionSuffix(avb_data->gpt, &suffix);
	if (ret != GPT_SUCCESS) {
		VB2_DEBUG("Unable to get kernel partition suffix\n");
		return ret;
	}
	if (strcmp(&partition[strlen(partition) - strlen(suffix)], suffix)) {
		free(suffix);
		return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
	}

	/*
	 * Below we only need to compare partition name without suffix, since
	 * the suffix is already verified above.
	 */
	short_partition_name = malloc(strlen(partition) - strlen(suffix) + 1);
	memcpy(short_partition_name, partition, strlen(partition) - strlen(suffix));
	short_partition_name[strlen(partition) - strlen(suffix)] = '\0';
	free(suffix);

	*out_pointer = NULL;
	if (!strcmp(short_partition_name, "boot")) {
		if (load_android_kernel(avb_data->params, avb_data->stream, num_bytes)) {
			ret = AVB_IO_RESULT_ERROR_IO;
			goto out;
		}
		bytes_used = num_bytes;
		*out_num_bytes_preloaded = num_bytes;
		*out_pointer = (uint8_t *)avb_data->params->kernel_buffer;

		ret = AVB_IO_RESULT_OK;
	} else if (!strcmp(short_partition_name, "vendor_boot") ||
		   !strcmp(short_partition_name, "init_boot")) {

		if (!ramdisk_preloaded) {
			ret = vb2_load_android_ramdisks(avb_data->vb2_ctx,
						avb_data->gpt, avb_data->params,
						avb_data->disk_handle, &bytes_used);
			if (ret) {
				ret = AVB_IO_RESULT_ERROR_IO;
				goto out;
			}
			ramdisk_preloaded = true;
		}

		*out_num_bytes_preloaded = num_bytes;
		if (!strcmp(short_partition_name, "vendor_boot"))
			*out_pointer = (uint8_t *)avb_data->params->kernel_buffer +
				       avb_data->params->vendor_boot_offset;
		if (!strcmp(short_partition_name, "init_boot"))
			*out_pointer = (uint8_t *)avb_data->params->kernel_buffer +
				       avb_data->params->init_boot_offset;

		ret = AVB_IO_RESULT_OK;
	}

out:
	free(short_partition_name);
	return ret;

}

/*
 * Initialize platform callbacks used within libavb.
 *
 * @param  vb2_ctx     Vboot context
 * @param  params      Vboot kernel parameters
 * @param  stream      Open stream to kernel partition
 * @param  gpt         Pointer to gpt struct correlated with boot disk
 * @param  disk_handle Handle to boot disk
 * @return pointer to AvbOps structure which should be used for invocation of
 *         libavb methods. This should be freed using vboot_avb_ops_free().
 *         NULL in case of error.
 */
AvbOps *vboot_avb_ops_new(struct vb2_context *vb2_ctx,
			  LoadKernelParams *params,
			  VbExStream_t stream,
			  GptData *gpt,
			  VbExDiskHandle_t disk_handle)
{
	struct vboot_avb_data *data;
	AvbOps *ops;

	ops = avb_calloc(sizeof(AvbOps));
	if (ops == NULL)
		return NULL;

	data = avb_calloc(sizeof(struct vboot_avb_data));
	if (data == NULL) {
		avb_free(ops);
		return NULL;
	}

	ops->user_data = data;

	data->gpt = gpt;
	data->params = params;
	data->stream = stream;
	data->vb2_ctx = vb2_ctx;
	data->disk_handle = disk_handle;

	ops->read_from_partition = vboot_avb_read_from_partition;
	ops->get_size_of_partition = vboot_avb_get_size_of_partition;
	ops->read_is_device_unlocked = vboot_avb_read_is_device_unlocked;
	ops->read_rollback_index = vboot_avb_read_rollback_index;
	ops->get_unique_guid_for_partition = get_unique_guid_for_partition;
	ops->validate_vbmeta_public_key = validate_vbmeta_public_key;
	ops->get_preloaded_partition = vboot_avb_get_preloaded_partition;

	return ops;
}
