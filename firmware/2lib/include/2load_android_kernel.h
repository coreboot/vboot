/* Copyright 2024 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Functions to load and verify an Android kernel.
 */

#ifndef VBOOT_REFERENCE_2LOAD_ANDROID_KERNEL_H_
#define VBOOT_REFERENCE_2LOAD_ANDROID_KERNEL_H_

#include "2api.h"
#include "gpt_misc.h"
#include "vboot_api.h"

/**
 * Load and verify Android kernel partitions (boot, init_boot, vendor_boot,
 * pvmfw) from the stream.
 *
 * @param ctx			Vboot context
 * @param params		Load-kernel parameters
 * @param stream		Stream to load kernel from
 * @param gpt			Partition table from the disk
 * @param disk_handle		Handle to the disk containing kernel
 * @param need_keyblock_valid	Controls if successful verification is required
 * @return VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2_load_android_kernel(
	struct vb2_context *ctx, struct vb2_kernel_params *params,
	VbExStream_t stream, GptData *gpt, vb2ex_disk_handle_t disk_handle,
	int need_keyblock_valid);

#endif  /* VBOOT_REFERENCE_2LOAD_ANDROID_KERNEL_H_ */