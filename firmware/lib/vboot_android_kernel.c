/* Copyright 2024 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Functions to load and verify an Android kernel.
 */

#include "2common.h"
#include "vboot_android_kernel.h"
#include "cgptlib.h"
#include "cgptlib_internal.h"
#include "vboot_avb_ops.h"

/* Size of the buffer to convey cmdline properties to bootloader */
#define AVB_CMDLINE_BUF_SIZE 1024

/* Bytes to read at start of the boot/init_boot/vendor_boot partitions */
#define BOOT_HDR_GKI_SIZE 4096
/* BCB structure from Android recovery bootloader_message.h */
struct bootloader_message {
	char command[32];
	char status[32];
	char recovery[768];
	char stage[32];
	char reserved[1184];
};
_Static_assert(sizeof(struct bootloader_message) == 2048,
	       "bootloader_message size is incorrect");

/* Possible values of BCB command */
#define BCB_CMD_BOOTONCE_BOOTLOADER "bootonce-bootloader"
#define BCB_CMD_BOOT_RECOVERY "boot-recovery"

#define VERIFIED_BOOT_PROPERTY_NAME "androidboot.verifiedbootstate="

#define LOWEST_TPM_VERSION 0xffffffff

static enum vb2_boot_command vb2_bcb_command(AvbOps *ops)
{
	struct bootloader_message bcb;
	AvbIOResult io_ret;
	size_t num_bytes_read;
	enum vb2_boot_command cmd;

	io_ret = ops->read_from_partition(ops,
					  GPT_ENT_NAME_ANDROID_MISC,
					  0,
					  sizeof(struct bootloader_message),
					  &bcb,
					  &num_bytes_read);
	if (io_ret != AVB_IO_RESULT_OK ||
	    num_bytes_read != sizeof(struct bootloader_message)) {
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
	struct vb2_context *ctx, VbExStream_t stream,
	VbSharedDataKernelPart *shpart, LoadKernelParams *params,
	GptData *gpt)
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
	int need_keyblock_valid = require_official_os(ctx, params);
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
		shpart->check_result = VBSD_LKC_CHECK_INVALID_PARTITIONS;
		return VB2_ERROR_LK_NO_KERNEL_FOUND;
	}

	avb_ops = vboot_avb_ops_new(ctx, params, stream, gpt,
				    params->disk_handle);
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
		shpart->check_result = VBSD_LKP_CHECK_VERIFY_DATA;
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

	/*
	 * Use a buffer before the GKI header for copying avb cmdline string for
	 * bootloader.
	 */
	params->vboot_cmdline_offset = params->kernel_buffer_size -
	    BOOT_HDR_GKI_SIZE - AVB_CMDLINE_BUF_SIZE;

	if ((params->init_boot_offset + params->init_boot_size) >
	    params->vboot_cmdline_offset)
		return VB2_ERROR_LOAD_PARTITION_WORKBUF;

	if ((strlen(verify_data->cmdline) + strlen(verified_str) + 1) >=
	    AVB_CMDLINE_BUF_SIZE)
		return VB2_ERROR_LOAD_PARTITION_WORKBUF;

	strcpy((char *)(params->kernel_buffer + params->vboot_cmdline_offset),
	       verify_data->cmdline);

	/* Append verifiedbootstate property to cmdline */
	strcat((char *)(params->kernel_buffer + params->vboot_cmdline_offset),
	       " ");
	strcat((char *)(params->kernel_buffer + params->vboot_cmdline_offset),
	       verified_str);

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

	shpart->check_result = VBSD_LKP_CHECK_KERNEL_GOOD;
	/* XXX: Rollback protection hasn't been implemented yet. */
	shpart->combined_version = LOWEST_TPM_VERSION;

	return ret;
}
