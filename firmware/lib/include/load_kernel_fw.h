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

struct vb2_context;

/* Interface provided by verified boot library to BDS */

typedef struct LoadKernelParams {
	/* Inputs to LoadKernel() */
	/* Disk handle for current device */
	VbExDiskHandle_t disk_handle;
	/* Destination buffer for kernel (normally at 0x100000) */
	void *kernel_buffer;
	/* Size of kernel buffer in bytes */
	uint64_t kernel_buffer_size;

	/*
	 * Outputs from LoadKernel(); valid only if LoadKernel() returns
	 * LOAD_KERNEL_SUCCESS
	 */
	/* Partition number to boot on current device (1...M) */
	uint32_t partition_number;
	/* Address of bootloader image in RAM */
	uint64_t bootloader_address;
	/* Size of bootloader image in bytes */
	uint32_t bootloader_size;
	/* UniquePartitionGuid for boot partition */
	uint8_t  partition_guid[16];
	/* Flags passed in by signer */
	uint32_t flags;
} LoadKernelParams;

/**
 * Attempt to load the kernel from the current device.
 *
 * @param ctx		Vboot context
 * @param params	Params specific to loading the kernel
 *
 * Returns VB2_SUCCESS if successful.  If unsuccessful, returns an error code.
 */
vb2_error_t LoadKernel(struct vb2_context *ctx, LoadKernelParams *params,
		       VbDiskInfo *disk_info);

#endif  /* VBOOT_REFERENCE_LOAD_KERNEL_FW_H_ */
