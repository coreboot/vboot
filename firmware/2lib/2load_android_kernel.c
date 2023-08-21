/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Functions to load and verify an Android kernel.
 */

#include "2api.h"
#include "2avb.h"
#include "2common.h"
#include "2load_android_kernel.h"
#include "2misc.h"
#include "cgptlib.h"
#include "cgptlib_internal.h"
#include "gpt_misc.h"
#include "vboot_api.h"
#include "vb2_android_bootimg.h"

#define GPT_ENT_NAME_ANDROID_A_SUFFIX "_a"
#define GPT_ENT_NAME_ANDROID_B_SUFFIX "_b"

static vb2_error_t vb2_map_libavb_errors(AvbSlotVerifyResult avb_error)
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

vb2_error_t vb2_load_android(struct vb2_context *ctx, GptData *gpt, GptEntry *entry,
			     struct vb2_kernel_params *params, vb2ex_disk_handle_t disk_handle)
{
	AvbSlotVerifyData *verify_data = NULL;
	AvbOps *avb_ops;
	AvbSlotVerifyFlags avb_flags;
	AvbSlotVerifyResult result;
	vb2_error_t rv;
	const char *boot_partitions[] = {
		GptPartitionNames[GPT_ANDROID_BOOT],
		GptPartitionNames[GPT_ANDROID_INIT_BOOT],
		GptPartitionNames[GPT_ANDROID_VENDOR_BOOT],
		NULL,
	};
	const char *slot_suffix = NULL;
	bool need_verification = vb2_need_kernel_verification(ctx);

	/* Update flags to mark loaded GKI image */
	params->flags = VB2_KERNEL_TYPE_BOOTIMG;

	const char *vbmeta = GptPartitionNames[GPT_ANDROID_VBMETA];
	if (GptEntryHasName(entry, vbmeta, GPT_ENT_NAME_ANDROID_A_SUFFIX))
		slot_suffix = GPT_ENT_NAME_ANDROID_A_SUFFIX;
	else if (GptEntryHasName(entry, vbmeta, GPT_ENT_NAME_ANDROID_B_SUFFIX))
		slot_suffix = GPT_ENT_NAME_ANDROID_B_SUFFIX;
	else
		return VB2_ERROR_ANDROID_INVALID_SLOT_SUFFIX;

	avb_ops = vboot_avb_ops_new(ctx, params, gpt, disk_handle, slot_suffix);
	if (!avb_ops)
		return VB2_ERROR_ANDROID_MEMORY_ALLOC;

	avb_flags = AVB_SLOT_VERIFY_FLAGS_NONE;
	if (!need_verification)
		avb_flags |= AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR;

	result = avb_slot_verify(avb_ops, boot_partitions, slot_suffix, avb_flags,
				 AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
				 &verify_data);

	/* Ignore verification errors in developer mode */
	if (!need_verification) {
		switch (result) {
		case AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION:
		case AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX:
		case AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED:
			result = AVB_SLOT_VERIFY_RESULT_OK;
			break;
		default:
			break;
		}
	}

	/* Map AVB return code into VB2 code */
	rv = vb2_map_libavb_errors(result);

	/* No need for slot data */
	if (verify_data != NULL)
		avb_slot_verify_data_free(verify_data);

	vboot_avb_ops_free(avb_ops);

	return rv;
}
