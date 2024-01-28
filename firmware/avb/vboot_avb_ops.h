/* Copyright 2024 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef VBOOT_AVB_OPS_H_
#define VBOOT_AVB_OPS_H_

#include "2common.h"
#include "gpt_misc.h"
#include "load_kernel_fw.h"
#include "vboot_api.h"

#include <libavb.h>

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
			  VbSelectAndLoadKernelParams *params,
			  VbExStream_t stream,
			  GptData *gpt,
			  VbExDiskHandle_t disk_handle);

void vboot_avb_ops_free(AvbOps *ops);

#endif // VBOOT_AVB_OPS_H_
