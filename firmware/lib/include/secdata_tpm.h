/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Functions for querying, manipulating and locking secure data spaces
 * stored in the TPM NVRAM.
 */

#ifndef VBOOT_REFERENCE_SECDATA_TPM_H_
#define VBOOT_REFERENCE_SECDATA_TPM_H_

#include "2api.h"

/* TPM NVRAM location indices. */
#define FIRMWARE_NV_INDEX 0x1007
#define KERNEL_NV_INDEX 0x1008
/* BACKUP_NV_INDEX (size 16) used to live at 0x1009; now deprecated */
#define FWMP_NV_INDEX 0x100a
#define REC_HASH_NV_INDEX 0x100b
#define REC_HASH_NV_SIZE VB2_SHA256_DIGEST_SIZE
/* Space to hold a temporary SHA256 digest of a public key for USB autoconfig;
 * see crbug.com/845589. */
#define OOBE_USB_AUTOCONFIG_KEY_DIGEST_NV_INDEX 0x100c
#define OOBE_USB_AUTOCONFIG_KEY_DIGEST_NV_SIZE VB2_SHA256_DIGEST_SIZE

/* All functions return TPM_SUCCESS (zero) if successful, non-zero if error */
uint32_t secdata_firmware_write(struct vb2_context *ctx);
uint32_t secdata_kernel_read(struct vb2_context *ctx);
uint32_t secdata_kernel_write(struct vb2_context *ctx);
uint32_t secdata_kernel_lock(struct vb2_context *ctx);
uint32_t secdata_fwmp_read(struct vb2_context *ctx);

#endif  /* VBOOT_REFERENCE_SECDATA_TPM_H_ */
