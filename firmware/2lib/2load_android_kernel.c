/* Copyright 2024 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Functions to load and verify an Android kernel.
 */

#include "2api.h"
#include "2common.h"
#include "2load_android_kernel.h"
#include "cgptlib.h"
#include "cgptlib_internal.h"
#include "gpt_misc.h"
#include "vb2_android_misc.h"
#include "vboot_api.h"
#include "vboot_avb_ops.h"

/* Bytes to read at start of the boot/init_boot/vendor_boot partitions */
#define BOOT_HDR_GKI_SIZE 4096

/* Possible values of BCB command */
#define BCB_CMD_BOOTONCE_BOOTLOADER "bootonce-bootloader"
#define BCB_CMD_BOOT_RECOVERY "boot-recovery"

#define VERIFIED_BOOT_PROPERTY_NAME "androidboot.verifiedbootstate="

static enum vb2_boot_command vb2_bcb_command(AvbOps *ops)
{
	struct vb2_bootloader_message bcb;
	AvbIOResult io_ret;
	size_t num_bytes_read;
	enum vb2_boot_command cmd;

	io_ret = ops->read_from_partition(ops,
					  GPT_ENT_NAME_ANDROID_MISC,
					  0,
					  sizeof(struct vb2_bootloader_message),
					  &bcb,
					  &num_bytes_read);
	if (io_ret != AVB_IO_RESULT_OK ||
	    num_bytes_read != sizeof(struct vb2_bootloader_message)) {
		/*
		 * TODO(b/349304841): Handle IO errors, for now just try to boot
		 *                    normally
		 */
		VB2_DEBUG("Cannot read misc partition.\n");
		return VB2_BOOT_CMD_NORMAL_BOOT;
	}

	/* BCB command field is for the bootloader */
	if (!strncmp(bcb.command, BCB_CMD_BOOT_RECOVERY,
		     VB2_MIN(sizeof(BCB_CMD_BOOT_RECOVERY) - 1, sizeof(bcb.command)))) {
		cmd = VB2_BOOT_CMD_RECOVERY_BOOT;
	} else if (!strncmp(bcb.command, BCB_CMD_BOOTONCE_BOOTLOADER,
			    VB2_MIN(sizeof(BCB_CMD_BOOTONCE_BOOTLOADER) - 1,
				    sizeof(bcb.command)))) {
		cmd = VB2_BOOT_CMD_BOOTLOADER_BOOT;
	} else {
		/* If empty or unknown command, just boot normally */
		if (bcb.command[0] != '\0')
			VB2_DEBUG("Unknown boot command \"%.*s\". Use normal boot.",
				  (int)sizeof(bcb.command), bcb.command);
		cmd = VB2_BOOT_CMD_NORMAL_BOOT;
	}

	return cmd;
}

vb2_error_t vb2_load_android_kernel(
	struct vb2_context *ctx, struct vb2_kernel_params *params,
	VbExStream_t stream, GptData *gpt, vb2ex_disk_handle_t disk_handle,
	int need_keyblock_valid)
{
	char *ab_suffix = NULL;
	AvbSlotVerifyData *verify_data = NULL;
	AvbOps *avb_ops;
	const char *boot_partitions[] = {
		GPT_ENT_NAME_ANDROID_BOOT,
		GPT_ENT_NAME_ANDROID_INIT_BOOT,
		GPT_ENT_NAME_ANDROID_VENDOR_BOOT,
		GPT_ENT_NAME_ANDROID_PVMFW,
		NULL,
	};
	AvbSlotVerifyFlags avb_flags;
	AvbSlotVerifyResult result;
	vb2_error_t ret;
	char *verified_str;

	/*
	 * Check if the buffer is zero sized (ie. pvmfw loading is not
	 * requested) or the pvmfw partition does not exist. If so skip
	 * loading and verifying it.
	 */
	uint64_t pvmfw_start;
	uint64_t pvmfw_size;
	if (params->pvmfw_buffer_size == 0 ||
	    GptFindPvmfw(gpt, &pvmfw_start, &pvmfw_size) != GPT_SUCCESS) {
		if (params->pvmfw_buffer_size != 0)
			VB2_DEBUG("Couldn't find pvmfw partition. Ignoring.\n");

		boot_partitions[3] = NULL;
		params->pvmfw_size = 0;
	}

	ret = GptGetActiveKernelPartitionSuffix(gpt, &ab_suffix);
	if (ret != GPT_SUCCESS) {
		VB2_DEBUG("Unable to get kernel partition suffix\n");
		return VB2_ERROR_LK_NO_KERNEL_FOUND;
	}

	avb_ops = vboot_avb_ops_new(ctx, params, stream, gpt, disk_handle);
	if (avb_ops == NULL) {
		free(ab_suffix);
		VB2_DEBUG("Cannot allocate memory for AVB ops\n");
		return VB2_ERROR_LK_NO_KERNEL_FOUND;
	}

	avb_flags = AVB_SLOT_VERIFY_FLAGS_NONE;
	if (!need_keyblock_valid)
		avb_flags |= AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR;

	result = avb_slot_verify(avb_ops,
			boot_partitions,
			ab_suffix,
			avb_flags,
			AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
			&verify_data);
	free(ab_suffix);

	/* Ignore verification errors in developer mode */
	if (ctx->flags & VB2_CONTEXT_DEVELOPER_MODE) {
		switch (result) {
		case AVB_SLOT_VERIFY_RESULT_OK:
		case AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION:
		case AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX:
		case AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED:
			ret = AVB_SLOT_VERIFY_RESULT_OK;
			break;
		default:
			ret = VB2_ERROR_LK_NO_KERNEL_FOUND;
		}
	} else {
		ret = result;
	}

	/*
	 * Return from this function early so that caller can try fallback to
	 * other partition in case of error.
	 */
	if (ret != AVB_SLOT_VERIFY_RESULT_OK) {
		if (verify_data != NULL)
			avb_slot_verify_data_free(verify_data);
		vboot_avb_ops_free(avb_ops);
		return ret;
	}

	params->boot_command = vb2_bcb_command(avb_ops);
	vboot_avb_ops_free(avb_ops);

	/* TODO(b/335901799): Add support for marking verifiedbootstate yellow */
	/* Possible values for this property are "yellow", "orange" and "green"
	 * so allocate 6 bytes plus 1 byte for NULL terminator.
	 */
	verified_str = malloc(strlen(VERIFIED_BOOT_PROPERTY_NAME) + 7);
	if (verified_str == NULL)
		return VB2_ERROR_LK_NO_KERNEL_FOUND;
	sprintf(verified_str, "%s%s", VERIFIED_BOOT_PROPERTY_NAME,
		(ctx->flags & VB2_CONTEXT_DEVELOPER_MODE) ? "orange" : "green");

	if ((strlen(verify_data->cmdline) + strlen(verified_str) + 1) >=
	    params->kernel_cmdline_size)
		return VB2_ERROR_LOAD_PARTITION_WORKBUF;

	strcpy(params->kernel_cmdline_buffer, verify_data->cmdline);

	/* Append verifiedbootstate property to cmdline */
	strcat(params->kernel_cmdline_buffer, " ");
	strcat(params->kernel_cmdline_buffer, verified_str);

	free(verified_str);

	/* No need for slot data, partitions should be already at correct
	 * locations in memory since we are using "get_preloaded_partitions"
	 * callbacks.
	 */
	avb_slot_verify_data_free(verify_data);

	/*
	 * Bootloader expects kernel image at the very beginning of
	 * kernel_buffer, but verification requires boot header before
	 * kernel. Since the verification is done, we need to move kernel
	 * at proper address.
	 */
	memmove((uint8_t *)params->kernel_buffer,
	       (uint8_t *)params->kernel_buffer + BOOT_HDR_GKI_SIZE,
	       params->vendor_boot_offset - BOOT_HDR_GKI_SIZE);

	return ret;
}
