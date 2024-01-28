/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef VBOOT_REFERENCE_2AVB_H_
#define VBOOT_REFERENCE_2AVB_H_

#include "2api.h"
#include "2common.h"
#include "gpt_misc.h"
#include "vboot_api.h"

#include <libavb.h>

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
			  vb2ex_disk_handle_t disk_handle);

/*
 * Free structure associated with AvbOps structure.
 *
 * @param  ops    pointer AvbOps structure
 */
void vboot_avb_ops_free(AvbOps *ops);

#endif // VBOOT_REFERENCE_2AVB_H_
