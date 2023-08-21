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
#include "vboot_api.h"
#include "vboot_avb_ops.h"

static int vb2_map_libavb_errors(AvbSlotVerifyResult avb_error)
{
	/* Map AVB error into VB2 */
	switch (avb_error) {
	case AVB_SLOT_VERIFY_RESULT_OK:
		return VB2_SUCCESS;
	case AVB_SLOT_VERIFY_RESULT_ERROR_OOM:
		return VB2_ERROR_AVB_OOM;
	case AVB_SLOT_VERIFY_RESULT_ERROR_IO:
		return VB2_ERROR_AVB_ERROR_IO;
	case AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION:
		return VB2_ERROR_AVB_ERROR_VERIFICATION;
	case AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX:
		return VB2_ERROR_AVB_ERROR_ROLLBACK_INDEX;
	case AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED:
		return VB2_ERROR_AVB_ERROR_PUBLIC_KEY_REJECTED;
	case AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA:
		return VB2_ERROR_AVB_ERROR_INVALID_METADATA;
	case AVB_SLOT_VERIFY_RESULT_ERROR_UNSUPPORTED_VERSION:
		return VB2_ERROR_AVB_ERROR_UNSUPPORTED_VERSION;
	case AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT:
		return VB2_ERROR_AVB_ERROR_INVALID_ARGUMENT;
	default:
		return VB2_ERROR_AVB_ERROR_VERIFICATION;
	}
}

#define VERIFIED_BOOT_PROPERTY_NAME "androidboot.verifiedbootstate="

vb2_error_t vb2_load_android_kernel(
	struct vb2_context *ctx, struct vb2_kernel_params *params,
	VbExStream_t stream, GptData *gpt, vb2ex_disk_handle_t disk_handle,
	int need_keyblock_valid)
{
	AvbSlotVerifyData *verify_data = NULL;
	AvbOps *avb_ops;
	AvbSlotVerifyFlags avb_flags;
	AvbSlotVerifyResult result;
	vb2_error_t ret;
	const char *boot_part;
	char *verified_str;
	GptEntry *entries = (GptEntry *)gpt->primary_entries;
	GptEntry *e;
	const char *boot_partitions[] = {
		GptPartitionNames[GPT_ANDROID_BOOT],
		GptPartitionNames[GPT_ANDROID_INIT_BOOT],
		GptPartitionNames[GPT_ANDROID_VENDOR_BOOT],
		NULL,
	};

	e = &entries[gpt->current_kernel];
	boot_part = GptPartitionNames[GPT_ANDROID_BOOT];
	if (GptEntryHasName(e, boot_part, GPT_ENT_NAME_ANDROID_A_SUFFIX))
		gpt->current_ab_slot = GPT_ENT_NAME_ANDROID_A_SUFFIX;
	else if (GptEntryHasName(e, boot_part, GPT_ENT_NAME_ANDROID_B_SUFFIX))
		gpt->current_ab_slot = GPT_ENT_NAME_ANDROID_B_SUFFIX;
	else
		return VB2_ERROR_LK_NO_KERNEL_FOUND;

	avb_ops = vboot_avb_ops_new(ctx, params, stream, gpt, disk_handle);
	if (avb_ops == NULL) {
		VB2_DEBUG("Cannot allocate memory for AVB ops\n");
		return VB2_ERROR_LK_NO_KERNEL_FOUND;
	}

	avb_flags = AVB_SLOT_VERIFY_FLAGS_NONE;
	if (!need_keyblock_valid)
		avb_flags |= AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR;

	result = avb_slot_verify(avb_ops,
			boot_partitions,
			gpt->current_ab_slot,
			avb_flags,
			AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
			&verify_data);
	vboot_avb_ops_free(avb_ops);

	/* Ignore verification errors in developer mode */
	if (!need_keyblock_valid && ctx->flags & VB2_CONTEXT_DEVELOPER_MODE) {
		switch (result) {
		case AVB_SLOT_VERIFY_RESULT_OK:
		case AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION:
		case AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX:
		case AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED:
			result = AVB_SLOT_VERIFY_RESULT_OK;
			break;
		default:
			result = AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION;
			break;
		}
	}

	/* Map AVB return code into VB2 code */
	ret = vb2_map_libavb_errors(result);

	/*
	 * Return from this function early so that caller can try fallback to
	 * other partition in case of error.
	 */
	if (ret != VB2_SUCCESS) {
		if (verify_data != NULL)
			avb_slot_verify_data_free(verify_data);
		return ret;
	}

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
	    params->vboot_cmdline_size)
		return VB2_ERROR_LOAD_PARTITION_WORKBUF;

	strcpy(params->vboot_cmdline_buffer, verify_data->cmdline);

	/* Append verifiedbootstate property to cmdline */
	strcat(params->vboot_cmdline_buffer, " ");
	strcat(params->vboot_cmdline_buffer, verified_str);

	free(verified_str);

	/* No need for slot data, partitions should be already at correct
	 * locations in memory since we are using "get_preloaded_partitions"
	 * callbacks.
	 */
	avb_slot_verify_data_free(verify_data);

	return ret;
}
