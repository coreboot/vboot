/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Functions to load and verify an Android kernel.
 */

#ifndef VBOOT_REFERENCE_2LOAD_ANDROID_KERNEL_H_
#define VBOOT_REFERENCE_2LOAD_ANDROID_KERNEL_H_

#include "2api.h"
#include "2avb.h"
#include "cgptlib.h"
#include "gpt_misc.h"
#include "vboot_api.h"

/**
 * Loads and verifies Android partitions (boot, init_boot, vendor_boot, pvmfw).
 *
 * @param ctx			Vboot context
 * @param gpt			Partition table from the disk
 * @param entry			GPT entry with VBMETA partition
 * @param params		Load-kernel parameters
 * @param disk_handle		Handle to the disk containing kernel
 * @return VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2_load_android(
	struct vb2_context *ctx,
	GptData *gpt,
	GptEntry *entry,
	struct vb2_kernel_params *params,
	vb2ex_disk_handle_t disk_handle);

#endif  /* VBOOT_REFERENCE_2LOAD_ANDROID_KERNEL_H_ */
