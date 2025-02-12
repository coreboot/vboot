/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef VBOOT_REFERENCE_2AVB_H_
#define VBOOT_REFERENCE_2AVB_H_

#include "2api.h"
#include "2common.h"
#include "cgptlib.h"
#include "gpt_misc.h"
#include "vboot_api.h"

#include <libavb.h>

/**
 * Gets address of buffer and size of preloaded partition.
 *
 * @param ops			AVB ops struct
 * @param name			Name of partition
 * @param buffer		Address of the pointer to buffer
 * @param data_size		Address of the partition size variable
 * @return AVB_IO_RESULT_OK on success or AVB_IO_RESULT_ERROR_IO otherwise.
 */
AvbIOResult vb2_android_get_buffer(AvbOps *ops,
				   enum GptPartition name,
				   void **buffer,
				   size_t *data_size);

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
			  const char *slot_suffix);

/*
 * Free structure associated with AvbOps structure.
 *
 * @param  ops    pointer AvbOps structure
 */
void vboot_avb_ops_free(AvbOps *ops);

#endif // VBOOT_REFERENCE_2AVB_H_
