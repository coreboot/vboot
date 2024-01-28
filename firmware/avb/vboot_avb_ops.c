/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Implementation of callbacks needed by libavb library
 */

#include <libavb.h>

#include "2avb.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2secdata.h"
#include "cgptlib.h"
#include "cgptlib_internal.h"
#include "gpt_misc.h"

struct vboot_avb_ctx {
	GptData *gpt;
	vb2ex_disk_handle_t disk_handle;
	struct vb2_context *vb2_ctx;
};

static inline struct vboot_avb_ctx *user_data(AvbOps *ops)
{
	return ops->user_data;
}

static AvbIOResult read_from_partition(AvbOps *ops,
				       const char *partition_name,
				       int64_t offset_from_partition,
				       size_t num_bytes,
				       void *buf,
				       size_t *out_num_read)
{
	struct vboot_avb_ctx *avbctx;
	VbExStream_t stream;
	uint64_t part_bytes, part_start_sector;
	uint64_t start_sector, sectors_to_read;
	uint32_t sector_bytes;
	GptData *gpt;
	GptEntry *e;

	avbctx = user_data(ops);
	gpt = avbctx->gpt;
	*out_num_read = 0;

	e = GptFindEntryByName(gpt, partition_name, NULL);
	if (e == NULL) {
		VB2_DEBUG("Unable to find %s partition\n", partition_name);
		return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
	}

	part_bytes = GptGetEntrySizeBytes(gpt, e);
	part_start_sector = e->starting_lba;
	sector_bytes = gpt->sector_bytes;

	if (part_start_sector * sector_bytes > (part_start_sector * sector_bytes) + part_bytes)
		return AVB_IO_RESULT_ERROR_IO;

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

	/* TODO(b/331881159): remove this check when misaligned read implemented */
	if ((offset_from_partition % sector_bytes) || (num_bytes % sector_bytes)) {
		VB2_DEBUG("Misaligned read from %s, offset %" PRId64 " num_bytes %zu\n",
			  partition_name, offset_from_partition, num_bytes);
		return AVB_IO_RESULT_ERROR_IO;
	}

	start_sector = part_start_sector +  offset_from_partition / sector_bytes;
	sectors_to_read = num_bytes / sector_bytes;

	if (VbExStreamOpen(avbctx->disk_handle, start_sector, sectors_to_read,
			   &stream)) {
		VB2_DEBUG("Unable to open disk handle\n");
		return AVB_IO_RESULT_ERROR_IO;
	}

	if (VbExStreamRead(stream, sectors_to_read * sector_bytes, buf)) {
		VB2_DEBUG("Unable to read ramdisk partition\n");
		return AVB_IO_RESULT_ERROR_IO;
	}

	*out_num_read = num_bytes;

	VbExStreamClose(stream);

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

	GptGuidToStr(&e->unique, guid_buf, guid_buf_size, GPT_GUID_UPPERCASE);
	return AVB_IO_RESULT_OK;
}

static AvbIOResult get_size_of_partition(AvbOps *ops,
					 const char *partition_name,
					 uint64_t *out_size)
{
	struct vboot_avb_ctx *avbctx = user_data(ops);
	GptEntry *e;

	e = GptFindEntryByName(avbctx->gpt, partition_name, NULL);
	if (e == NULL) {
		VB2_DEBUG("Unable to find %s partition\n", partition_name);
		return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
	}

	*out_size = GptGetEntrySizeBytes(avbctx->gpt, e);

	return AVB_IO_RESULT_OK;
}

/*
 * Initialize platform callbacks used within libavb.
 *
 * @param  vb2_ctx     Vboot context
 * @param  gpt         Pointer to gpt struct correlated with boot disk
 * @param  disk_handle Handle to boot disk
 * @return pointer to AvbOps structure which should be used for invocation of
 *         libavb methods.
 */
AvbOps *vboot_avb_ops_new(struct vb2_context *vb2_ctx,
			  GptData *gpt,
			  vb2ex_disk_handle_t disk_handle)
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
	avbctx->vb2_ctx = vb2_ctx;
	avb_ops->user_data = avbctx;

	avb_ops->read_from_partition = read_from_partition;
	avb_ops->read_rollback_index = read_rollback_index;
	avb_ops->read_is_device_unlocked = read_is_device_unlocked;
	avb_ops->get_unique_guid_for_partition = get_unique_guid_for_partition;
	avb_ops->get_size_of_partition = get_size_of_partition;

	return avb_ops;
}

void vboot_avb_ops_free(AvbOps *ops)
{
	if (ops == NULL)
		return;

	free(ops->user_data);
	free(ops);
}
