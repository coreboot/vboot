/* Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Secure non-volatile storage routines
 */

#ifndef VBOOT_REFERENCE_2SECDATA_H_
#define VBOOT_REFERENCE_2SECDATA_H_

/* Avoid circular dependency with 2api.h */
struct vb2_context;
typedef uint32_t vb2_error_t;

/*****************************************************************************/
/* Firmware version space */

#define VB2_SECDATA_FIRMWARE_VERSION 2

/* Flags for firmware space */
enum vb2_secdata_firmware_flags {
	/*
	 * Last boot was developer mode.  TPM ownership is cleared when
	 * transitioning to/from developer mode.  Set/cleared by
	 * vb2_check_dev_switch().
	 */
	VB2_SECDATA_FIRMWARE_FLAG_LAST_BOOT_DEVELOPER = (1 << 0),

	/*
	 * Virtual developer mode switch is on.  Set/cleared by the
	 * keyboard-controlled dev screens in recovery mode.  Cleared by
	 * vb2_check_dev_switch().
	 */
	VB2_SECDATA_FIRMWARE_FLAG_DEV_MODE = (1 << 1),
};

struct vb2_secdata_firmware {
	/* Struct version, for backwards compatibility */
	uint8_t struct_version;

	/* Flags; see vb2_secdata_firmware_flags */
	uint8_t flags;

	/* Firmware versions */
	uint32_t fw_versions;

	/* Reserved for future expansion */
	uint8_t reserved[3];

	/* CRC; must be last field in struct */
	uint8_t crc8;
} __attribute__((packed));

/* Which param to get/set for vb2_secdata_firmware_get/set() */
enum vb2_secdata_firmware_param {
	/* Flags; see vb2_secdata_firmware_flags */
	VB2_SECDATA_FIRMWARE_FLAGS = 0,

	/* Firmware versions */
	VB2_SECDATA_FIRMWARE_VERSIONS,
};

/*****************************************************************************/
/* Kernel version space */

/* Kernel space - KERNEL_NV_INDEX, locked with physical presence. */
#define VB2_SECDATA_KERNEL_VERSION 2
#define VB2_SECDATA_KERNEL_UID 0x4752574c  /* 'GRWL' */

struct vb2_secdata_kernel {
	/* Struct version, for backwards compatibility */
	uint8_t struct_version;

	/* Unique ID to detect space redefinition */
	uint32_t uid;

	/* Kernel versions */
	uint32_t kernel_versions;

	/* Reserved for future expansion */
	uint8_t reserved[3];

	/* CRC; must be last field in struct */
	uint8_t crc8;
} __attribute__((packed));

/* Which param to get/set for vb2_secdata_kernel_get/set() */
enum vb2_secdata_kernel_param {
	/* Kernel versions */
	VB2_SECDATA_KERNEL_VERSIONS = 0,
};

/*****************************************************************************/
/* Firmware secure storage space functions */

/**
 * Initialize firmware secure storage context and verify its CRC.
 *
 * This must be called before vb2_secdata_firmware_get/set().
 *
 * @param ctx		Context pointer
 * @return VB2_SUCCESS, or non-zero error code if error.
 */
vb2_error_t vb2_secdata_firmware_init(struct vb2_context *ctx);

/**
 * Read a firmware secure storage value.
 *
 * @param ctx		Context pointer
 * @param param		Parameter to read
 * @param dest		Destination for value
 * @return VB2_SUCCESS, or non-zero error code if error.
 */
vb2_error_t vb2_secdata_firmware_get(struct vb2_context *ctx,
				     enum vb2_secdata_firmware_param param,
				     uint32_t *dest);

/**
 * Write a firmware secure storage value.
 *
 * @param ctx		Context pointer
 * @param param		Parameter to write
 * @param value		New value
 * @return VB2_SUCCESS, or non-zero error code if error.
 */
vb2_error_t vb2_secdata_firmware_set(struct vb2_context *ctx,
				     enum vb2_secdata_firmware_param param,
				     uint32_t value);

/*****************************************************************************/
/* Kernel secure storage space functions
 *
 * These are separate functions so that they don't bloat the size of the early
 * boot code which uses the firmware version space functions.
 */

/**
 * Initialize kernel secure storage context and verify its CRC.
 *
 * This must be called before vb2_secdata_kernel_get/set().
 *
 * @param ctx		Context pointer
 * @return VB2_SUCCESS, or non-zero error code if error.
 */
vb2_error_t vb2_secdata_kernel_init(struct vb2_context *ctx);

/**
 * Read a kernel secure storage value.
 *
 * @param ctx		Context pointer
 * @param param		Parameter to read
 * @param dest		Destination for value
 * @return VB2_SUCCESS, or non-zero error code if error.
 */
vb2_error_t vb2_secdata_kernel_get(struct vb2_context *ctx,
				   enum vb2_secdata_kernel_param param,
				   uint32_t *dest);

/**
 * Write a kernel secure storage value.
 *
 * @param ctx		Context pointer
 * @param param		Parameter to write
 * @param value		New value
 * @return VB2_SUCCESS, or non-zero error code if error.
 */
vb2_error_t vb2_secdata_kernel_set(struct vb2_context *ctx,
				   enum vb2_secdata_kernel_param param,
				   uint32_t value);

#endif  /* VBOOT_REFERENCE_2SECDATA_H_ */
