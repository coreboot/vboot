/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Non-volatile storage routines
 */

#ifndef VBOOT_REFERENCE_2NVSTORAGE_H_
#define VBOOT_REFERENCE_2NVSTORAGE_H_

#include "2nvstorage_params.h"

struct vb2_context;

/*
 * Default value for VB2_NV_FIRMWARE_MAX_ROLLFORWARD on V1.  This preserves the
 * existing behavior that V1 systems will always roll forward the firmware
 * version when possible.
 */
#define VB2_FW_MAX_ROLLFORWARD_V1_DEFAULT 0xfffffffe

/**
 * Return the size of the non-volatile storage data in the context.
 *
 * This may be called before vb2_context_init(), but you must set
 * VB2_CONTEXT_NVDATA_V2 if you support V2 record size.
 *
 * @param ctx		Context pointer
 * @return Size of the non-volatile storage data in bytes.
 */
int vb2_nv_get_size(const struct vb2_context *ctx);

/**
 * Check the CRC of the non-volatile storage context.
 *
 * Use this if reading from non-volatile storage may be flaky, and you want to
 * retry reading it several times.
 *
 * This may be called before vb2_context_init().
 *
 * @param ctx		Context pointer
 * @return VB2_SUCCESS, or non-zero error code if error.
 */
vb2_error_t vb2_nv_check_crc(const struct vb2_context *ctx);

/**
 * Initialize the non-volatile storage context and verify its CRC.
 *
 * This may be called before vb2_context_init(), as long as:
 *
 *    1) The ctx structure has been cleared to 0.
 *    2) Existing non-volatile data, if any, has been stored to ctx->nvdata[].
 *
 * This is to support using the non-volatile storage functions to request
 * recovery if there is an error allocating the workbuf for the context.  It
 * also allows host-side code to use this library without setting up a bunch of
 * extra context.
 *
 * @param ctx		Context pointer
 */
void vb2_nv_init(struct vb2_context *ctx);

/**
 * Read a non-volatile value.
 *
 * Valid only after calling vb2_nv_init().
 *
 * @param ctx		Context pointer
 * @param param		Parameter to read
 * @return The value of the parameter.  If you somehow force an invalid
 *         parameter number, returns 0.
 */
uint32_t vb2_nv_get(struct vb2_context *ctx, enum vb2_nv_param param);

/**
 * Write a non-volatile value.
 *
 * Ignores writes to unknown params.  Valid only after calling vb2_nv_init().
 * If this changes ctx->nvdata[], it will set VB2_CONTEXT_NVDATA_CHANGED in
 * ctx->flags.
 *
 * @param ctx		Context pointer
 * @param param		Parameter to write
 * @param value		New value
 */
void vb2_nv_set(struct vb2_context *ctx,
		enum vb2_nv_param param,
		uint32_t value);

#endif  /* VBOOT_REFERENCE_2NVSTORAGE_H_ */
