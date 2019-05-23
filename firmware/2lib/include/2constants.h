/* Copyright 2019 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * General vboot-related constants.
 *
 * Constants that need to be exposed to assembly files or linker scripts
 * may be placed here and imported via vb2_constants.h.
 */

#ifndef VBOOT_REFERENCE_2CONSTANTS_H_
#define VBOOT_REFERENCE_2CONSTANTS_H_

/*
 * Size of non-volatile data used by vboot.
 *
 * If you only support non-volatile data format V1, then use VB2_NVDATA_SIZE.
 * If you support V2, use VB2_NVDATA_SIZE_V2 and set context flag
 * VB2_CONTEXT_NVDATA_V2.
 */
#define VB2_NVDATA_SIZE 16
#define VB2_NVDATA_SIZE_V2 64

/* Size of secure data spaces used by vboot */
#define VB2_SECDATA_SIZE 10
#define VB2_SECDATAK_SIZE 14

/*
 * Recommended size of work buffer for firmware verification stage.
 *
 * TODO: The recommended size really depends on which key algorithms are
 * used.  Should have a better / more accurate recommendation than this.
 */
#define VB2_FIRMWARE_WORKBUF_RECOMMENDED_SIZE (12 * 1024)

/*
 * Recommended size of work buffer for kernel verification stage.
 *
 * This is bigger because vboot 2.0 kernel preambles are usually padded to
 * 64 KB.
 *
 * TODO: The recommended size really depends on which key algorithms are
 * used.  Should have a better / more accurate recommendation than this.
 */
#define VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE (80 * 1024)

/* Recommended buffer size for vb2api_get_pcr_digest. */
#define VB2_PCR_DIGEST_RECOMMENDED_SIZE 32

#endif  /* VBOOT_REFERENCE_2CONSTANTS_H_ */
