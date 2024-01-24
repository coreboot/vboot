/* Copyright 2024 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef VBOOT_AVB_OPS_H_
#define VBOOT_AVB_OPS_H_

#include "2common.h"
#include "gpt_misc.h"
#include "vboot_api.h"

#include <libavb.h>

/*
 * Initialize platform callbacks used within libavb.
 *
 * @param  vb2_ctx     Vboot context
 * @return pointer to AvbOps structure which should be used for invocation of
 *         libavb methods. This should be freed using vboot_avb_ops_free().
 *         NULL in case of error.
 */
AvbOps *vboot_avb_ops_new(struct vb2_context *vb2_ctx);

void vboot_avb_ops_free(AvbOps *ops);

#endif // VBOOT_AVB_OPS_H_
