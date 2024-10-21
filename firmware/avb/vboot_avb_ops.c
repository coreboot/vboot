/* Copyright 2024 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Implementation of callbacks needed by libavb library
*/

#include <libavb.h>

#include "2common.h"
#include "2nvstorage.h"
#include "2secdata.h"
#include "vboot_avb_ops.h"
#include "cgptlib.h"
#include "cgptlib_internal.h"

struct vboot_avb_data {
	struct vb2_context *vb2_ctx;
};

void vboot_avb_ops_free(AvbOps *ops)
{
	if (ops == NULL)
		return;

	avb_free(ops->user_data);
	avb_free(ops);
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
	struct vboot_avb_data *data;
	GptData *gpt;
	GptEntry *e;
	int ret;

	if (guid_buf_size < GUID_STRLEN || !ops || !ops->user_data)
		return AVB_IO_RESULT_ERROR_NO_SUCH_VALUE;

	data = (struct vboot_avb_data *)ops->user_data;
	gpt = data->gpt;
	if (!gpt)
		return AVB_IO_RESULT_ERROR_NO_SUCH_VALUE;


	e = GptFindEntryByName(gpt, partition, NULL);
	if (e == NULL)
		return AVB_IO_RESULT_ERROR_IO;

	ret = snprintf(guid_buf, guid_buf_size,
		       "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		       le32toh(e->unique.u.Uuid.time_low),
		       le16toh(e->unique.u.Uuid.time_mid),
		       le16toh(e->unique.u.Uuid.time_high_and_version),
		       e->unique.u.Uuid.clock_seq_high_and_reserved,
		       e->unique.u.Uuid.clock_seq_low,
		       e->unique.u.Uuid.node[0], e->unique.u.Uuid.node[1],
		       e->unique.u.Uuid.node[2], e->unique.u.Uuid.node[3],
		       e->unique.u.Uuid.node[4], e->unique.u.Uuid.node[5]);

	if (ret != (GUID_STRLEN - 1))
		return AVB_IO_RESULT_ERROR_IO;

	return AVB_IO_RESULT_OK;
}

/*
 * Initialize platform callbacks used within libavb.
 *
 * @param  vb2_ctx     Vboot context
 * @return pointer to AvbOps structure which should be used for invocation of
 *         libavb methods. This should be freed using vboot_avb_ops_free().
 *         NULL in case of error.
 */
AvbOps *vboot_avb_ops_new(struct vb2_context *vb2_ctx)
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

	data->vb2_ctx = vb2_ctx;

	ops->read_is_device_unlocked = vboot_avb_read_is_device_unlocked;
	ops->read_rollback_index = vboot_avb_read_rollback_index;
	ops->get_unique_guid_for_partition = get_unique_guid_for_partition;

	return ops;
}
