/* Copyright 2026 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Variables located in non-volatile storage
 */

#ifndef VBOOT_REFERENCE_2NVSTORAGE_PARAMS_H_
#define VBOOT_REFERENCE_2NVSTORAGE_PARAMS_H_

enum vb2_nv_param {
	/*
	 * Parameter values have been reset to defaults (flag for firmware).
	 * 0=clear; 1=set.
	 */
	VB2_NV_FIRMWARE_SETTINGS_RESET = 0,
	/*
	 * Parameter values have been reset to defaults (flag for kernel).
	 * 0=clear; 1=set.
	 */
	VB2_NV_KERNEL_SETTINGS_RESET,
	/* Request debug reset on next S3->S0 transition.  0=clear; 1=set. */
	VB2_NV_DEBUG_RESET_MODE,
	/* Firmware slot to try next.  0=A, 1=B */
	VB2_NV_TRY_NEXT,
	/*
	 * Number of times to try booting RW firmware slot B before slot A.
	 * Valid range: 0-15.
	 *
	 * For VB2, number of times to try booting the slot indicated by
	 * VB2_NV_TRY_NEXT.  On a 1->0 transition of try count, VB2_NV_TRY_NEXT
	 * will be set to the other slot.
	 */
	VB2_NV_TRY_COUNT,
	/*
	 * Request recovery mode on next boot; see 2recovery_reason.h for
	 * currently defined reason codes.  8-bit value.
	 */
	VB2_NV_RECOVERY_REQUEST,
	/*
	 * Localization index for screen bitmaps displayed by firmware.
	 * 8-bit value.
	 */
	VB2_NV_LOCALIZATION_INDEX,
	/* Field reserved for kernel/user-mode use; 16-bit value. */
	VB2_NV_KERNEL_FIELD,
	/* Allow booting from external disk in developer mode.  0=no, 1=yes. */
	VB2_NV_DEV_BOOT_EXTERNAL,
	/* Allow booting of legacy OSes in developer mode.  0=no, 1=yes. */
	VB2_NV_DEV_BOOT_ALTFW,
	/* Only boot Google-signed images in developer mode.  0=no, 1=yes. */
	VB2_NV_DEV_BOOT_SIGNED_ONLY,
	/*
	 * Allow full fastboot capability in firmware in developer mode.
	 * 0=no, 1=yes.  Deprecated; see chromium:995172.
	 */
	VB2_NV_DEPRECATED_DEV_BOOT_FASTBOOT_FULL_CAP,
	/* Set default boot mode (see vb2_dev_default_boot_target) */
	VB2_NV_DEV_DEFAULT_BOOT,
	/* Enable USB Device Controller */
	VB2_NV_DEV_ENABLE_UDC,
	/*
	 * Set by userspace to request that RO firmware disable dev-mode on the
	 * next boot. This is likely only possible if the dev-switch is
	 * virtual.
	 */
	VB2_NV_DISABLE_DEV_REQUEST,
	/* Set and cleared by vboot to request that display be initialized
	   at boot time, so that BIOS screens can be displayed. 0=no, 1=yes. */
	VB2_NV_DISPLAY_REQUEST,
	/* Request that the firmware clear the TPM owner on the next boot. */
	VB2_NV_CLEAR_TPM_OWNER_REQUEST,
	/* Flag that TPM owner was cleared on request. */
	VB2_NV_CLEAR_TPM_OWNER_DONE,
	/* TPM requested a reboot already. */
	VB2_NV_TPM_REQUESTED_REBOOT,
	/* More details on recovery reason */
	VB2_NV_RECOVERY_SUBCODE,
	/* Request that NVRAM be backed up at next boot if possible. */
	VB2_NV_BACKUP_NVRAM_REQUEST,
	/* Firmware slot tried this boot (0=A, 1=B) */
	VB2_NV_FW_TRIED,
	/* Result of trying that firmware (see vb2_fw_result) */
	VB2_NV_FW_RESULT,
	/* Firmware slot tried previous boot (0=A, 1=B) */
	VB2_NV_FW_PREV_TRIED,
	/* Result of trying that firmware (see vb2_fw_result) */
	VB2_NV_FW_PREV_RESULT,
	/* Request wipeout of the device by the app. */
	VB2_NV_REQ_WIPEOUT,

	/* Allow fastboot in developer mode, 0=no, 1=yes. */
	VB2_NV_DEV_ENABLE_FASTBOOT,
	/* Boot system when AC detected (0=no, 1=yes). */
	VB2_NV_BOOT_ON_AC_DETECT,
	/*
	 * Try to update the EC-RO image after updating the EC-RW image
	 * (0=no, 1=yes).
	 */
	VB2_NV_DEPRECATED_TRY_RO_SYNC,
	/* Cut off battery and shutdown on next boot. */
	VB2_NV_BATTERY_CUTOFF_REQUEST,
	/* Maximum kernel version to roll forward to */
	VB2_NV_KERNEL_MAX_ROLLFORWARD,

	/*** Fields only available in NV storage V2 ***/

	/*
	 * Maximum firmware version to roll forward to.  Returns
	 * VB2_MAX_ROLLFORWARD_MAX_V1_DEFAULT for V1.
	 */
	VB2_NV_FW_MAX_ROLLFORWARD,
	/* Deprecated: Enable AltOS Mode on next boot. */
	VB2_NV_DEPRECATED_ENABLE_ALT_OS_REQUEST,
	/* Deprecated: Disable AltOS Mode on next boot. */
	VB2_NV_DEPRECATED_DISABLE_ALT_OS_REQUEST,
	/*
	 * Add a short delay after EC software sync for any interaction
	 * with EC-RW (persistent).  Formerly used for programmatically
	 * testing Alt OS booting.
	 */
	VB2_NV_POST_EC_SYNC_DELAY,
	/* Request booting of diagnostic rom.  0=no, 1=yes. */
	VB2_NV_DIAG_REQUEST,
	/* Priority of miniOS partition to load: 0=MINIOS-A, 1=MINIOS-B. */
	VB2_NV_MINIOS_PRIORITY,
	/* OEM lock: 0=disabled, 1=enabled. */
	VB2_NV_OEM_LOCK,
};

#endif  /* VBOOT_REFERENCE_2NVSTORAGE_PARAMS_H_ */
