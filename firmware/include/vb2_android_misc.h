/* Copyright 2024 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Layout of an Android misc partition.
 */

#ifndef VBOOT_REFERENCE_VB2_ANDROID_MISC_H_
#define VBOOT_REFERENCE_VB2_ANDROID_MISC_H_

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

#endif  /* VBOOT_REFERENCE_VB2_ANDROID_MISC_H_ */
