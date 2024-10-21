/* Copyright 2024 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Layout of an Android misc partition.
 */

#ifndef VBOOT_REFERENCE_VB2_ANDROID_MISC_H_
#define VBOOT_REFERENCE_VB2_ANDROID_MISC_H_

#include <stdbool.h>

/* BCB structure from Android recovery bootloader_message.h */
struct vb2_bootloader_message {
	char command[32];
	char status[32];
	char recovery[768];
	char stage[32];
	char reserved[1184];
};
_Static_assert(sizeof(struct vb2_bootloader_message) == 2048,
	       "vb2_bootloader_message size is incorrect");

/*
 * Reserve space for fastboot oem cmdline on misc partition. Use for that vendor
 * space which is at 2K - 16K range in misc. Skip 2K - 4K range as it may be
 * optionally used as bootloader_message_ab struct.
 */
#define VB2_MISC_VENDOR_SPACE_FASTBOOT_CMDLINE_OFFSET (1024 * 4)
#define VB2_MISC_VENDOR_SPACE_FASTBOOT_CMDLINE_SIZE (1024 * 2)
/* Hex values for ASCII "FCML" */
#define VB2_MISC_VENDOR_SPACE_FASTBOOT_CMDLINE_MAGIC 0x46434d4c
struct vb2_fastboot_cmdline {
	uint8_t version;
	uint32_t magic;
	/* Fletcher-32 checksum of len and cmdline up to len bytes */
	uint32_t fletcher;
	uint16_t len;
	char cmdline[2037];
} __attribute__((packed));
_Static_assert(sizeof(struct vb2_fastboot_cmdline) ==
	       VB2_MISC_VENDOR_SPACE_FASTBOOT_CMDLINE_SIZE,
	       "vb2_fastboot_cmdline size is incorrect");

/*
 * Check if vb2_fastboot_cmdline structure is valid, i.e if magic is correct,
 * len property doesn't exceed cmdline size, fletcher checksum is valid.
 *
 * @param fb_cmd	Fastboot cmdline structure from misc partition.
 * @returns 1 if structure data pass all checks, 0 otherwise.
 */
bool vb2_is_fastboot_cmdline_valid(struct vb2_fastboot_cmdline *fb_cmd);

/*
 * Calculate and set checksum property of given vb2_fastboot_cmdline structure.
 * If len property exceed cmdline size, then checksum is not calculated.
 *
 * @param fb_cmd	Fastboot cmdline structure from misc partition.
 * @returns 1 if checksum is set, 0 otherwise.
 */
bool vb2_update_fastboot_cmdline_checksum(struct vb2_fastboot_cmdline *fb_cmd);

#endif  /* VBOOT_REFERENCE_VB2_ANDROID_MISC_H_ */
