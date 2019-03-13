/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * High-level firmware wrapper API - user interface for RW firmware
 */

#include "sysincludes.h"

#include "2sysincludes.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2rsa.h"
#include "ec_sync.h"
#include "gbb_access.h"
#include "gbb_header.h"
#include "load_kernel_fw.h"
#include "rollback_index.h"
#include "tlcl.h"
#include "utility.h"
#include "vb2_common.h"
#include "vboot_api.h"
#include "vboot_audio.h"
#include "vboot_common.h"
#include "vboot_display.h"
#include "vboot_kernel.h"
#include "vboot_ui_common.h"

/* Global variables */
static int power_button_released;

static void vb2_init_ui(void)
{
	power_button_released = 0;
}

static void VbAllowUsbBoot(struct vb2_context *ctx)
{
	VB2_DEBUG(".");
	vb2_nv_set(ctx, VB2_NV_DEV_BOOT_USB, 1);
}

/**
 * Checks GBB flags against VbExIsShutdownRequested() shutdown request to
 * determine if a shutdown is required.
 *
 * Returns zero or more of the following flags (if any are set then typically
 * shutdown is required):
 * VB_SHUTDOWN_REQUEST_LID_CLOSED
 * VB_SHUTDOWN_REQUEST_POWER_BUTTON
 */
static int VbWantShutdown(struct vb2_context *ctx, uint32_t key)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	uint32_t shutdown_request = VbExIsShutdownRequested();

	/*
	 * Ignore power button push until after we have seen it released.
	 * This avoids shutting down immediately if the power button is still
	 * being held on startup.
	 */
	if (shutdown_request & VB_SHUTDOWN_REQUEST_POWER_BUTTON) {
		if (!power_button_released)
			shutdown_request &= ~VB_SHUTDOWN_REQUEST_POWER_BUTTON;
	} else {
		power_button_released = 1;
	}

	if (key == VB_BUTTON_POWER_SHORT_PRESS)
		shutdown_request |= VB_SHUTDOWN_REQUEST_POWER_BUTTON;

	/* If desired, ignore shutdown request due to lid closure. */
	if (sd->gbb_flags & GBB_FLAG_DISABLE_LID_SHUTDOWN)
		shutdown_request &= ~VB_SHUTDOWN_REQUEST_LID_CLOSED;

	return shutdown_request;
}

uint32_t VbTryUsb(struct vb2_context *ctx)
{
	uint32_t retval = VbTryLoadKernel(ctx, VB_DISK_FLAG_REMOVABLE);
	if (VBERROR_SUCCESS == retval) {
		VB2_DEBUG("VbBootDeveloper() - booting USB\n");
	} else {
		vb2_error_notify("Could not boot from USB",
				 "VbBootDeveloper() - no kernel found on USB\n",
				 VB_BEEP_FAILED);
		/*
		 * Clear recovery requests from failed
		 * kernel loading, so that powering off
		 * at this point doesn't put us into
		 * recovery mode.
		 */
		vb2_nv_set(ctx, VB2_NV_RECOVERY_REQUEST,
			   VB2_RECOVERY_NOT_REQUESTED);
	}
	return retval;
}

#define CONFIRM_KEY_DELAY 20  /* Check confirm screen keys every 20ms */

int VbUserConfirms(struct vb2_context *ctx, uint32_t confirm_flags)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	VbSharedDataHeader *shared = sd->vbsd;
	uint32_t key;
	uint32_t key_flags;
	uint32_t btn;
	int rec_button_was_pressed = 0;

	VB2_DEBUG("Entering(%x)\n", confirm_flags);

	/* Await further instructions */
	while (1) {
		key = VbExKeyboardReadWithFlags(&key_flags);
		if (VbWantShutdown(ctx, key))
			return -1;
		switch (key) {
		case VB_KEY_ENTER:
			/* If we require a trusted keyboard for confirmation,
			 * but the keyboard may be faked (for instance, a USB
			 * device), beep and keep waiting.
			 */
			if (confirm_flags & VB_CONFIRM_MUST_TRUST_KEYBOARD &&
			    !(key_flags & VB_KEY_FLAG_TRUSTED_KEYBOARD)) {
				vb2_error_notify("Please use internal keyboard "
					"to confirm\n",
					"VbUserConfirms() - "
					"Trusted keyboard is requierd\n",
					VB_BEEP_NOT_ALLOWED);
				break;
			}
			VB2_DEBUG("Yes (1)\n");
			return 1;
			break;
		case ' ':
			VB2_DEBUG("Space (%d)\n",
				  confirm_flags & VB_CONFIRM_SPACE_MEANS_NO);
			if (confirm_flags & VB_CONFIRM_SPACE_MEANS_NO)
				return 0;
			break;
		case VB_KEY_ESC:
			VB2_DEBUG("No (0)\n");
			return 0;
			break;
		default:
			/* If the recovery button is physical, and is pressed,
			 * this is also a YES, but must wait for release.
			 */
			btn = VbExGetSwitches(
				VB_SWITCH_FLAG_REC_BUTTON_PRESSED);
			if (!(shared->flags & VBSD_BOOT_REC_SWITCH_VIRTUAL)) {
				if (btn) {
					VB2_DEBUG("Rec button pressed\n");
					rec_button_was_pressed = 1;
				} else if (rec_button_was_pressed) {
					VB2_DEBUG("Rec button (1)\n");
					return 1;
				}
			}
			VbCheckDisplayKey(ctx, key, NULL);
		}
		VbExSleepMs(CONFIRM_KEY_DELAY);
	}

	/* Not reached, but compiler will complain without it */
	return -1;
}

/* Delay in developer ui */
#define DEV_KEY_DELAY        20       /* Check keys every 20ms */

/*
 * User interface for selecting alternative firmware
 *
 * This shows the user a list of bootloaders and allows selection of one of
 * them. We loop forever until something is chosen or Escape is pressed.
 */
VbError_t vb2_altfw_ui(struct vb2_context *ctx)
{
	int active = 1;

	VbDisplayScreen(ctx, VB_SCREEN_ALT_FW_PICK, 0, NULL);

	/* We'll loop until the user decides what to do */
	do {
		uint32_t key = VbExKeyboardRead();

		if (VbWantShutdown(ctx, key)) {
			VB2_DEBUG("VbBootDeveloper() - shutdown requested!\n");
			return VBERROR_SHUTDOWN_REQUESTED;
		}
		switch (key) {
		case 0:
			/* nothing pressed */
			break;
		case VB_KEY_ESC:
			/* Escape pressed - return to developer screen */
			VB2_DEBUG("VbBootDeveloper() - user pressed Esc:"
				  "exit to Developer screen\n");
			active = 0;
			break;
		/* We allow selection of the default '0' bootloader here */
		case '0'...'9':
			VB2_DEBUG("VbBootDeveloper() - "
				  "user pressed key '%c': Boot alternative "
				  "firmware\n", key);
			/*
			 * This will not return if successful. Drop out to
			 * developer mode on failure.
			 */
			vb2_run_altfw(ctx, key - '0');
			active = 0;
			break;
		default:
			VB2_DEBUG("VbBootDeveloper() - pressed key %d\n", key);
			VbCheckDisplayKey(ctx, key, NULL);
			break;
		}
		VbExSleepMs(DEV_KEY_DELAY);
	} while (active);

	/* Back to developer screen */
	VbDisplayScreen(ctx, VB_SCREEN_DEVELOPER_WARNING, 0, NULL);

	return 0;
}

static inline int is_vowel(uint32_t key) {
	return key == 'A' || key == 'E' || key == 'I' ||
	       key == 'O' || key == 'U';
}

/*
 * Prompt the user to enter the vendor data
 */
VbError_t vb2_enter_vendor_data_ui(struct vb2_context *ctx, char *data_value)
{
	int len = 0;
	VbScreenData data = {
		.vendor_data = { data_value }
	};

	data_value[0] = '\0';
	VbDisplayScreen(ctx, VB_SCREEN_SET_VENDOR_DATA, 1, &data);

	/* We'll loop until the user decides what to do */
	do {
		uint32_t key = VbExKeyboardRead();

		if (VbWantShutdown(ctx, key)) {
			VB2_DEBUG("Vendor Data UI - shutdown requested!\n");
			return VBERROR_SHUTDOWN_REQUESTED;
		}
		switch (key) {
		case 0:
			/* nothing pressed */
			break;
		case VB_KEY_ESC:
			/* Escape pressed - return to developer screen */
			VB2_DEBUG("Vendor Data UI - user pressed Esc: "
				  "exit to Developer screen\n");
			data_value[0] = '\0';
			return VBERROR_SUCCESS;
		case 'a'...'z':
			key = toupper(key);
		case '0'...'9':
		case 'A'...'Z':
			if ((len > 0 && is_vowel(key)) ||
			     len >= VENDOR_DATA_LENGTH) {
				vb2_error_beep(VB_BEEP_NOT_ALLOWED);
			} else {
				data_value[len++] = key;
				data_value[len] = '\0';
				VbDisplayScreen(ctx, VB_SCREEN_SET_VENDOR_DATA,
						1, &data);
			}

			VB2_DEBUG("Vendor Data UI - vendor_data: %s\n",
				  data_value);
			break;
		case VB_KEY_BACKSPACE:
			if (len > 0) {
				data_value[--len] = '\0';
				VbDisplayScreen(ctx, VB_SCREEN_SET_VENDOR_DATA,
						1, &data);
			}

			VB2_DEBUG("Vendor Data UI - vendor_data: %s\n",
				  data_value);
			break;
		case VB_KEY_ENTER:
			if (len == VENDOR_DATA_LENGTH) {
				/* Enter pressed - confirm input */
				VB2_DEBUG("Vendor Data UI - user pressed "
					  "Enter: confirm vendor data\n");
				return VBERROR_SUCCESS;
			} else {
				vb2_error_beep(VB_BEEP_NOT_ALLOWED);
			}
			break;
		default:
			VB2_DEBUG("Vendor Data UI - pressed key %d\n", key);
			VbCheckDisplayKey(ctx, key, &data);
			break;
		}
		VbExSleepMs(DEV_KEY_DELAY);
	} while (1);

	return VBERROR_SUCCESS;
}

/*
 * User interface for setting the vendor data in VPD
 */
VbError_t vb2_vendor_data_ui(struct vb2_context *ctx)
{
	char data_value[VENDOR_DATA_LENGTH + 1];
	VbScreenData data = {
		.vendor_data = { data_value }
	};

	VbError_t ret = vb2_enter_vendor_data_ui(ctx, data_value);

	if (ret)
		return ret;

	/* Vendor data was not entered just return */
	if (data_value[0] == '\0')
		return VBERROR_SUCCESS;

	VbDisplayScreen(ctx, VB_SCREEN_CONFIRM_VENDOR_DATA, 1, &data);
	/* We'll loop until the user decides what to do */
	do {
		uint32_t key = VbExKeyboardRead();

		if (VbWantShutdown(ctx, key)) {
			VB2_DEBUG("Vendor Data UI - shutdown requested!\n");
			return VBERROR_SHUTDOWN_REQUESTED;
		}
		switch (key) {
		case 0:
			/* nothing pressed */
			break;
		case VB_KEY_ESC:
			/* Escape pressed - return to developer screen */
			VB2_DEBUG("Vendor Data UI - user pressed Esc: "
				  "exit to Developer screen\n");
			return VBERROR_SUCCESS;
		case VB_KEY_ENTER:
			/* Enter pressed - write vendor data */
			VB2_DEBUG("Vendor Data UI - user pressed Enter: "
				  "write vendor data (%s) to VPD\n",
				  data_value);
			ret = VbExSetVendorData(data_value);

			if (ret == VBERROR_SUCCESS) {
				vb2_nv_set(ctx, VB2_NV_DISABLE_DEV_REQUEST, 1);
				return VBERROR_REBOOT_REQUIRED;
			} else {
				vb2_error_notify(
					"ERROR: Vendor data was not set.\n"
					"System will now shutdown\n",
					NULL,
					VB_BEEP_FAILED);
				VbExSleepMs(5000);
				return VBERROR_SHUTDOWN_REQUESTED;
			}
		default:
			VB2_DEBUG("Vendor Data UI - pressed key %d\n", key);
			VbCheckDisplayKey(ctx, key, &data);
			break;
		}
		VbExSleepMs(DEV_KEY_DELAY);
	} while (1);

	return VBERROR_SUCCESS;
}

/*
 * User interface for confirming launch of diagnostics rom
 *
 * This asks the user to confirm the launch of the diagnostics rom. The user
 * can press the power button to confirm or press escape. There is a 30-second
 * timeout which acts the same as escape.
 */
VbError_t vb2_diagnostics_ui(struct vb2_context *ctx)
{
	int active = 1;
	int power_button_was_pressed = 0;
	VbError_t result = VBERROR_REBOOT_REQUIRED;
	int action_confirmed = 0;
	uint64_t start_time_us;

	VbDisplayScreen(ctx, VB_SCREEN_CONFIRM_DIAG, 0, NULL);

	start_time_us = VbExGetTimer();

	/* We'll loop until the user decides what to do */
	do {
		uint32_t key = VbExKeyboardRead();
		/*
		 * VbExIsShutdownRequested() is almost an adequate substitute
		 * for adding a new flag to VbExGetSwitches().  The main
		 * issue is that the former doesn't consult the power button
		 * on detachables, and this function wants to see for itself
		 * that the power button isn't currently pressed.
		 */
		uint32_t power_pressed =
			VbExGetSwitches(VB_SWITCH_FLAG_PHYS_PRESENCE_PRESSED);
		/*
		 * TODO(delco): Remove this workaround.  On Wilco a button
		 * press is only reported a single time regardless of the
		 * duration of the press. Until it's changed to report the
		 * live/current status of the button we can't ignore when
		 * VbWantShutdown() reports a button press (well, we can
		 * ignore it but the user might have to press the power button
		 * more than once for this code to react).
		 */
		int shutdown = VbWantShutdown(ctx, 0);
		if (shutdown & VB_SHUTDOWN_REQUEST_POWER_BUTTON) {
			power_pressed = 1;
		}

		if (power_pressed) {
			power_button_was_pressed = 1;
		} else if (power_button_was_pressed) {
			VB2_DEBUG("vb2_diagnostics_ui() - power released\n");
			action_confirmed = 1;
			active = 0;
			break;
		}

		/* Check the lid and ignore the power button. */
		if (shutdown & VB_SHUTDOWN_REQUEST_LID_CLOSED) {
			VB2_DEBUG("vb2_diagnostics_ui() - shutdown request\n");
			result = VBERROR_SHUTDOWN_REQUESTED;
			active = 0;
			break;
		}

		switch (key) {
		case 0:
			/* nothing pressed */
			break;
		case VB_KEY_ESC:
			/* Escape pressed - reboot */
			VB2_DEBUG("vb2_diagnostics_ui() - user pressed Esc\n");
			active = 0;
			break;
		default:
			VB2_DEBUG("vb2_diagnostics_ui() - pressed key %d\n",
				  key);
			VbCheckDisplayKey(ctx, key, NULL);
			break;
		}
		if (VbExGetTimer() - start_time_us >= 30 * VB_USEC_PER_SEC) {
			VB2_DEBUG("vb2_diagnostics_ui() - timeout\n");
			break;
		}
		if (active) {
			VbExSleepMs(DEV_KEY_DELAY);
		}
	} while (active);

	VbDisplayScreen(ctx, VB_SCREEN_BLANK, 0, NULL);

	if (action_confirmed) {
		VB2_DEBUG("Diagnostic requested, running\n");

		/*
		 * The following helps avoid use of the TPM after
		 * it's disabled (e.g., when vb2_run_altfw() calls
		 * RollbackKernelLock() ).
		 */

		if (RollbackKernelLock(0)) {
			VB2_DEBUG("Failed to lock TPM PP\n");
			vb2_fail(ctx, VB2_RECOVERY_TPM_DISABLE_FAILED, 0);
		} else if (vb2ex_tpm_set_mode(VB2_TPM_MODE_DISABLED) !=
			   VB2_SUCCESS) {
			VB2_DEBUG("Failed to disable TPM\n");
			vb2_fail(ctx, VB2_RECOVERY_TPM_DISABLE_FAILED, 0);
		} else {
			vb2_run_altfw(ctx, VB_ALTFW_DIAGNOSTIC);
			VB2_DEBUG("Diagnostic failed to run\n");
			/*
			 * Assuming failure was due to bad hash, though
			 * the rom could just be missing or invalid.
			 */
			vb2_fail(ctx, VB2_RECOVERY_ALTFW_HASH_FAILED, 0);
		}
	}

	return result;
}

static const char dev_disable_msg[] =
	"Developer mode is disabled on this device by system policy.\n"
	"For more information, see http://dev.chromium.org/chromium-os/fwmp\n"
	"\n";

VbError_t vb2_developer_ui(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	VbSharedDataHeader *shared = sd->vbsd;

	uint32_t disable_dev_boot = 0;
	uint32_t use_usb = 0;
	uint32_t use_legacy = 0;
	uint32_t ctrl_d_pressed = 0;

	VB2_DEBUG("Entering\n");

	/* Check if USB booting is allowed */
	uint32_t allow_usb = vb2_nv_get(ctx, VB2_NV_DEV_BOOT_USB);
	uint32_t allow_legacy = vb2_nv_get(ctx, VB2_NV_DEV_BOOT_LEGACY);

	/* Check if the default is to boot using disk, usb, or legacy */
	uint32_t default_boot = vb2_nv_get(ctx, VB2_NV_DEV_DEFAULT_BOOT);

	if(default_boot == VB2_DEV_DEFAULT_BOOT_USB)
		use_usb = 1;
	if(default_boot == VB2_DEV_DEFAULT_BOOT_LEGACY)
		use_legacy = 1;

	/* Handle GBB flag override */
	if (sd->gbb_flags & VB2_GBB_FLAG_FORCE_DEV_BOOT_USB)
		allow_usb = 1;
	if (sd->gbb_flags & VB2_GBB_FLAG_FORCE_DEV_BOOT_LEGACY)
		allow_legacy = 1;
	if (sd->gbb_flags & VB2_GBB_FLAG_DEFAULT_DEV_BOOT_LEGACY) {
		use_legacy = 1;
		use_usb = 0;
	}

	/* Handle FWMP override */
	uint32_t fwmp_flags = vb2_get_fwmp_flags();
	if (fwmp_flags & FWMP_DEV_ENABLE_USB)
		allow_usb = 1;
	if (fwmp_flags & FWMP_DEV_ENABLE_LEGACY)
		allow_legacy = 1;
	if (fwmp_flags & FWMP_DEV_DISABLE_BOOT) {
		if (sd->gbb_flags & VB2_GBB_FLAG_FORCE_DEV_SWITCH_ON) {
			VB2_DEBUG("FWMP_DEV_DISABLE_BOOT rejected by "
				  "FORCE_DEV_SWITCH_ON\n");
		} else {
			disable_dev_boot = 1;
		}
	}

	/* If dev mode is disabled, only allow TONORM */
	while (disable_dev_boot) {
		VB2_DEBUG("dev_disable_boot is set\n");
		VbDisplayScreen(ctx,
				VB_SCREEN_DEVELOPER_TO_NORM, 0, NULL);
		VbExDisplayDebugInfo(dev_disable_msg, 0);

		/* Ignore space in VbUserConfirms()... */
		switch (VbUserConfirms(ctx, 0)) {
		case 1:
			VB2_DEBUG("leaving dev-mode\n");
			vb2_nv_set(ctx, VB2_NV_DISABLE_DEV_REQUEST, 1);
			VbDisplayScreen(ctx,
				VB_SCREEN_TO_NORM_CONFIRMED, 0, NULL);
			VbExSleepMs(5000);
			return VBERROR_REBOOT_REQUIRED;
		case -1:
			VB2_DEBUG("shutdown requested\n");
			return VBERROR_SHUTDOWN_REQUESTED;
		default:
			/* Ignore user attempt to cancel */
			VB2_DEBUG("ignore cancel TONORM\n");
		}
	}

	/* Show the dev mode warning screen */
	VbDisplayScreen(ctx, VB_SCREEN_DEVELOPER_WARNING, 0, NULL);

	/* Initialize audio/delay context */
	vb2_audio_start(ctx);

	/* We'll loop until we finish the delay or are interrupted */
	do {
		uint32_t key = VbExKeyboardRead();
		if (VbWantShutdown(ctx, key)) {
			VB2_DEBUG("VbBootDeveloper() - shutdown requested!\n");
			return VBERROR_SHUTDOWN_REQUESTED;
		}

		switch (key) {
		case 0:
			/* nothing pressed */
			break;
		case VB_KEY_ENTER:
			/* Only disable virtual dev switch if allowed by GBB */
			if (!(sd->gbb_flags &
			      VB2_GBB_FLAG_ENTER_TRIGGERS_TONORM))
				break;
		case ' ':
			/* See if we should disable virtual dev-mode switch. */
			VB2_DEBUG("shared->flags=0x%x\n", shared->flags);
			if (shared->flags & VBSD_HONOR_VIRT_DEV_SWITCH &&
			    shared->flags & VBSD_BOOT_DEV_SWITCH_ON) {
				/* Stop the countdown while we go ask... */
				if (sd->gbb_flags &
				    GBB_FLAG_FORCE_DEV_SWITCH_ON) {
					/*
					 * TONORM won't work (only for
					 * non-shipping devices).
					 */
					vb2_error_notify(
						"WARNING: TONORM prohibited by "
						"GBB FORCE_DEV_SWITCH_ON.\n",
						NULL,
						VB_BEEP_NOT_ALLOWED);
					break;
				}
				VbDisplayScreen(ctx,
					VB_SCREEN_DEVELOPER_TO_NORM,
					0, NULL);
				/* Ignore space in VbUserConfirms()... */
				switch (VbUserConfirms(ctx, 0)) {
				case 1:
					VB2_DEBUG("leaving dev-mode\n");
					vb2_nv_set(ctx, VB2_NV_DISABLE_DEV_REQUEST,
						1);
					VbDisplayScreen(ctx,
						VB_SCREEN_TO_NORM_CONFIRMED,
						0, NULL);
					VbExSleepMs(5000);
					return VBERROR_REBOOT_REQUIRED;
				case -1:
					VB2_DEBUG("shutdown requested\n");
					return VBERROR_SHUTDOWN_REQUESTED;
				default:
					/* Stay in dev-mode */
					VB2_DEBUG("stay in dev-mode\n");
					VbDisplayScreen(ctx,
						VB_SCREEN_DEVELOPER_WARNING,
						0, NULL);
					/* Start new countdown */
					vb2_audio_start(ctx);
				}
			} else {
				/*
				 * No virtual dev-mode switch, so go directly
				 * to recovery mode.
				 */
				VB2_DEBUG("going to recovery\n");
				vb2_nv_set(ctx, VB2_NV_RECOVERY_REQUEST,
					   VB2_RECOVERY_RW_DEV_SCREEN);
				return VBERROR_LOAD_KERNEL_RECOVERY;
			}
			break;
		case VB_KEY_CTRL('D'):
			/* Ctrl+D = dismiss warning; advance to timeout */
			VB2_DEBUG("VbBootDeveloper() - "
				  "user pressed Ctrl+D; skip delay\n");
			ctrl_d_pressed = 1;
			goto fallout;
			break;
		case VB_KEY_CTRL('L'):
			VB2_DEBUG("VbBootDeveloper() - "
				  "user pressed Ctrl+L; Try alt firmware\n");
			if (allow_legacy) {
				int ret;

				ret = vb2_altfw_ui(ctx);
				if (ret)
					return ret;
			} else {
				vb2_error_no_altfw();
			}
			break;
		case VB_KEY_CTRL('S'):
			if (VENDOR_DATA_LENGTH == 0)
				break;
			/*
			 * Only show the vendor data ui if it is tag is settable
			 */
			if (ctx->flags & VB2_CONTEXT_VENDOR_DATA_SETTABLE) {
				int ret;

				VB2_DEBUG("VbBootDeveloper() - user pressed "
					  "Ctrl+S; Try set vendor data\n");

				ret = vb2_vendor_data_ui(ctx);
				if (ret) {
					return ret;
				} else {
					/* Show dev mode warning screen again */
					VbDisplayScreen(ctx,
						VB_SCREEN_DEVELOPER_WARNING,
						0, NULL);
				}
			} else {
				vb2_error_notify(
					"WARNING: Vendor data cannot be "
					"changed because it is already set.\n",
					NULL,
					VB_BEEP_NOT_ALLOWED);
			}
			break;
		case VB_KEY_CTRL_ENTER:
			/*
			 * The Ctrl-Enter is special for Lumpy test purpose;
			 * fall through to Ctrl+U handler.
			 */
		case VB_KEY_CTRL('U'):
			/* Ctrl+U = try USB boot, or beep if failure */
			VB2_DEBUG("VbBootDeveloper() - "
				  "user pressed Ctrl+U; try USB\n");
			if (!allow_usb) {
				vb2_error_notify(
					"WARNING: Booting from external media "
					"(USB/SD) has not been enabled. Refer "
					"to the developer-mode documentation "
					"for details.\n",
					"VbBootDeveloper() - "
					"USB booting is disabled\n",
					VB_BEEP_NOT_ALLOWED);
			} else {
				/*
				 * Clear the screen to show we get the Ctrl+U
				 * key press.
				 */
				VbDisplayScreen(ctx, VB_SCREEN_BLANK, 0, NULL);
				if (VBERROR_SUCCESS == VbTryUsb(ctx)) {
					return VBERROR_SUCCESS;
				} else {
					/* Show dev mode warning screen again */
					VbDisplayScreen(ctx,
						VB_SCREEN_DEVELOPER_WARNING,
						0, NULL);
				}
			}
			break;
		/* We allow selection of the default '0' bootloader here */
		case '0'...'9':
			VB2_DEBUG("VbBootDeveloper() - "
				  "user pressed key '%c': Boot alternative "
				  "firmware\n", key);
			vb2_try_alt_fw(ctx, allow_legacy, key - '0');
			break;
		default:
			VB2_DEBUG("VbBootDeveloper() - pressed key %d\n", key);
			VbCheckDisplayKey(ctx, key, NULL);
			break;
		}

		VbExSleepMs(DEV_KEY_DELAY);
	} while(vb2_audio_looping());

 fallout:

	/* If defaulting to legacy boot, try that unless Ctrl+D was pressed */
	if (use_legacy && !ctrl_d_pressed) {
		VB2_DEBUG("VbBootDeveloper() - defaulting to legacy\n");
		vb2_try_alt_fw(ctx, allow_legacy, 0);
	}

	if ((use_usb && !ctrl_d_pressed) && allow_usb) {
		if (VBERROR_SUCCESS == VbTryUsb(ctx)) {
			return VBERROR_SUCCESS;
		}
	}

	/* Timeout or Ctrl+D; attempt loading from fixed disk */
	VB2_DEBUG("VbBootDeveloper() - trying fixed disk\n");
	return VbTryLoadKernel(ctx, VB_DISK_FLAG_FIXED);
}

VbError_t VbBootDeveloper(struct vb2_context *ctx)
{
	vb2_init_ui();
	VbError_t retval = vb2_developer_ui(ctx);
	VbDisplayScreen(ctx, VB_SCREEN_BLANK, 0, NULL);
	return retval;
}

VbError_t VbBootDiagnostic(struct vb2_context *ctx)
{
	vb2_init_ui();
	VbError_t retval = vb2_diagnostics_ui(ctx);
	VbDisplayScreen(ctx, VB_SCREEN_BLANK, 0, NULL);
	return retval;
}

/* Delay in recovery mode */
#define REC_DISK_DELAY       1000     /* Check disks every 1s */
#define REC_KEY_DELAY        20       /* Check keys every 20ms */
#define REC_MEDIA_INIT_DELAY 500      /* Check removable media every 500ms */

static VbError_t recovery_ui(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	VbSharedDataHeader *shared = sd->vbsd;
	uint32_t retval;
	uint32_t key;
	int i;
	const char release_button_msg[] =
		"Release the recovery button and try again\n";
	const char recovery_pressed_msg[] =
		"^D but recovery switch is pressed\n";

	VB2_DEBUG("VbBootRecovery() start\n");

	if (!vb2_allow_recovery(ctx)) {
		/*
		 * We have to save the reason here so that it will survive
		 * coming up three-finger-salute. We're saving it in
		 * VB2_RECOVERY_SUBCODE to avoid a recovery loop.
		 * If we save the reason in VB2_RECOVERY_REQUEST, we will come
		 * back here, thus, we won't be able to give a user a chance to
		 * reboot to workaround a boot hiccup.
		 */
		VB2_DEBUG("VbBootRecovery() saving recovery reason (%#x)\n",
			 shared->recovery_reason);
		vb2_nv_set(ctx, VB2_NV_RECOVERY_SUBCODE,
			   shared->recovery_reason);
		/*
		 * Commit NV now, because it won't get saved if the user forces
		 * manual recovery via the three-finger salute.
		 */
		vb2_nv_commit(ctx);

		VbDisplayScreen(ctx, VB_SCREEN_OS_BROKEN, 0, NULL);
		VB2_DEBUG("VbBootRecovery() waiting for manual recovery\n");
		while (1) {
			key = VbExKeyboardRead();
			VbCheckDisplayKey(ctx, key, NULL);
			if (VbWantShutdown(ctx, key))
				return VBERROR_SHUTDOWN_REQUESTED;
			VbExSleepMs(REC_KEY_DELAY);
		}
	}

	/* Loop and wait for a recovery image */
	VB2_DEBUG("VbBootRecovery() waiting for a recovery image\n");
	while (1) {
		VB2_DEBUG("VbBootRecovery() attempting to load kernel2\n");
		retval = VbTryLoadKernel(ctx, VB_DISK_FLAG_REMOVABLE);

		/*
		 * Clear recovery requests from failed kernel loading, since
		 * we're already in recovery mode.  Do this now, so that
		 * powering off after inserting an invalid disk doesn't leave
		 * us stuck in recovery mode.
		 */
		vb2_nv_set(ctx, VB2_NV_RECOVERY_REQUEST,
			   VB2_RECOVERY_NOT_REQUESTED);

		if (VBERROR_SUCCESS == retval)
			break; /* Found a recovery kernel */

		VbDisplayScreen(ctx, VBERROR_NO_DISK_FOUND == retval ?
				VB_SCREEN_RECOVERY_INSERT :
				VB_SCREEN_RECOVERY_NO_GOOD,
				0, NULL);

		/*
		 * Scan keyboard more frequently than media, since x86
		 * platforms don't like to scan USB too rapidly.
		 */
		for (i = 0; i < REC_DISK_DELAY; i += REC_KEY_DELAY) {
			key = VbExKeyboardRead();
			/*
			 * We might want to enter dev-mode from the Insert
			 * screen if all of the following are true:
			 *   - user pressed Ctrl-D
			 *   - we can honor the virtual dev switch
			 *   - not already in dev mode
			 *   - user forced recovery mode
			 */
			if (key == VB_KEY_CTRL('D') &&
			    shared->flags & VBSD_HONOR_VIRT_DEV_SWITCH &&
			    !(shared->flags & VBSD_BOOT_DEV_SWITCH_ON) &&
			    (shared->flags & VBSD_BOOT_REC_SWITCH_ON)) {
				if (!(shared->flags &
				      VBSD_BOOT_REC_SWITCH_VIRTUAL) &&
				    VbExGetSwitches(
				    VB_SWITCH_FLAG_REC_BUTTON_PRESSED)) {
					/*
					 * Is the recovery button stuck?  In
					 * any case we don't like this.  Beep
					 * and ignore.
					 */
					vb2_error_notify(release_button_msg,
							 recovery_pressed_msg,
							 VB_BEEP_NOT_ALLOWED);
					continue;
				}

				/* Ask the user to confirm entering dev-mode */
				VbDisplayScreen(ctx,
						VB_SCREEN_RECOVERY_TO_DEV,
						0, NULL);
				/* SPACE means no... */
				uint32_t vbc_flags =
					VB_CONFIRM_SPACE_MEANS_NO |
					VB_CONFIRM_MUST_TRUST_KEYBOARD;
				switch (VbUserConfirms(ctx, vbc_flags)) {
				case 1:
					VB2_DEBUG("Enabling dev-mode...\n");
					if (TPM_SUCCESS != SetVirtualDevMode(1))
						return VBERROR_TPM_SET_BOOT_MODE_STATE;
					VB2_DEBUG("Reboot so it will take "
						  "effect\n");
					if (VbExGetSwitches
					    (VB_SWITCH_FLAG_ALLOW_USB_BOOT))
						VbAllowUsbBoot(ctx);
					return VBERROR_EC_REBOOT_TO_RO_REQUIRED;
				case -1:
					VB2_DEBUG("Shutdown requested\n");
					return VBERROR_SHUTDOWN_REQUESTED;
				default: /* zero, actually */
					VB2_DEBUG("Not enabling dev-mode\n");
					/*
					 * Jump out of the outer loop to
					 * refresh the display quickly.
					 */
					i = 4;
					break;
				}
			} else if (DIAGNOSTIC_UI &&
				   (key == VB_KEY_CTRL('C') ||
				    key == 0x114)) {       /* F12 */
				VB2_DEBUG("Diagnostic requested, rebooting\n");
                                if (shared->flags & VBSD_OPROM_MATTERS)
					vb2_nv_set(ctx, VB2_NV_OPROM_NEEDED, 1);
				vb2_nv_set(ctx, VB2_NV_DIAG_REQUEST, 1);
				return VBERROR_REBOOT_REQUIRED;
			} else {
				VbCheckDisplayKey(ctx, key, NULL);
			}
			if (VbWantShutdown(ctx, key))
				return VBERROR_SHUTDOWN_REQUESTED;
			VbExSleepMs(REC_KEY_DELAY);
		}
	}

	return VBERROR_SUCCESS;
}

VbError_t VbBootRecovery(struct vb2_context *ctx)
{
	vb2_init_ui();
	VbError_t retval = recovery_ui(ctx);
	VbDisplayScreen(ctx, VB_SCREEN_BLANK, 0, NULL);
	return retval;
}
