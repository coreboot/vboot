/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * High-level firmware API for loading and verifying kernel.
 * (Firmware Portion)
 */

#ifndef VBOOT_REFERENCE_LOAD_KERNEL_FW_H_
#define VBOOT_REFERENCE_LOAD_KERNEL_FW_H_

#include "vboot_api.h"

/**
 * Attempt to load kernel from the specified device.
 *
 * @param ctx		Vboot context
 * @param params	Params specific to loading the kernel
 * @param disk_info	Disk from which to read kernel
 *
 * Returns VB2_SUCCESS if successful.  If unsuccessful, returns an error code.
 */
vb2_error_t LoadKernel(struct vb2_context *ctx,
		       VbSelectAndLoadKernelParams *params,
		       VbDiskInfo *disk_info);

/**
 * Attempt to load miniOS kernel from the specified device.
 *
 * @param ctx		Vboot context
 * @param params	Params specific to loading the kernel
 * @param disk_info	Disk from which to read kernel
 *
 * Returns VB2_SUCCESS if successful.  If unsuccessful, returns an error code.
 */
vb2_error_t LoadMiniOsKernel(struct vb2_context *ctx,
			     VbSelectAndLoadKernelParams *params,
			     VbDiskInfo *disk_info);

#endif  /* VBOOT_REFERENCE_LOAD_KERNEL_FW_H_ */
