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

/*
 * Copy bootconfig into separate buffer, it can be overwritten when ramdisks
 * are concatenated. Bootconfig buffer will be processed by depthcharge.
 */
static vb2_error_t save_bootconfig(struct vendor_boot_img_hdr_v4 *vendor_hdr,
				   size_t total_size,
				   struct vb2_kernel_params *params)
{
	uint8_t *bootconfig;
	size_t bootconfig_offset;
	uint32_t page_size = vendor_hdr->page_size;

	if (!vendor_hdr->bootconfig_size)
		return VB2_SUCCESS;

	bootconfig_offset = VB2_ALIGN_UP(sizeof(struct vendor_boot_img_hdr_v4), page_size) +
			    VB2_ALIGN_UP(vendor_hdr->vendor_ramdisk_size, page_size) +
			    VB2_ALIGN_UP(vendor_hdr->dtb_size, page_size) +
			    VB2_ALIGN_UP(vendor_hdr->vendor_ramdisk_table_size, page_size);
	if (bootconfig_offset > total_size ||
	    total_size - bootconfig_offset < vendor_hdr->bootconfig_size) {
		VB2_DEBUG("Broken 'vendor_boot' image\n");
		return VB2_ERROR_ANDROID_BROKEN_VENDOR_BOOT;
	}

	params->bootconfig = malloc(vendor_hdr->bootconfig_size);
	if (!params->bootconfig) {
		VB2_DEBUG("Cannot malloc %u bytes for bootconfig", vendor_hdr->bootconfig_size);
		return VB2_ERROR_ANDROID_MEMORY_ALLOC;
	}

	bootconfig = (uint8_t *)vendor_hdr + bootconfig_offset;
	memcpy(params->bootconfig, bootconfig, vendor_hdr->bootconfig_size);
	params->bootconfig_size = vendor_hdr->bootconfig_size;
	return VB2_SUCCESS;
}


/*
 * This function validates the partitions magic numbers and move them into place requested
 * from linux.
 */
static vb2_error_t rearrange_partitions(AvbOps *avb_ops,
					struct vb2_kernel_params *params)
{
	struct vendor_boot_img_hdr_v4 *vendor_hdr;
	struct boot_img_hdr_v4 *init_hdr;
	size_t vendor_boot_size, init_boot_size;
	uint8_t *vendor_ramdisk_end = 0;

	if (vb2_android_get_buffer(avb_ops, GPT_ANDROID_VENDOR_BOOT, (void **)&vendor_hdr,
				   &vendor_boot_size) ||
	    vb2_android_get_buffer(avb_ops, GPT_ANDROID_INIT_BOOT, (void **)&init_hdr,
				   &init_boot_size)) {
		VB2_DEBUG("Cannot get information about preloaded paritition\n");
		return VB2_ERROR_ANDROID_RAMDISK_ERROR;
	}

	if (vendor_boot_size < sizeof(*vendor_hdr) ||
	    memcmp(vendor_hdr->magic, VENDOR_BOOT_MAGIC, VENDOR_BOOT_MAGIC_SIZE)) {
		VB2_DEBUG("Incorrect magic or size (%zx) of 'vendor_boot' image\n",
			  vendor_boot_size);
		return VB2_ERROR_ANDROID_BROKEN_VENDOR_BOOT;
	}

	/* Save bootconfig for depthcharge, it can be overwritten when ramdisk are moved */
	VB2_TRY(save_bootconfig(vendor_hdr, vendor_boot_size, params));

	/* Validate init_boot partition */
	if (init_boot_size < BOOT_HEADER_SIZE ||
	    init_boot_size - BOOT_HEADER_SIZE < init_hdr->ramdisk_size ||
	    init_hdr->kernel_size != 0 ||
	    memcmp(init_hdr->magic, BOOT_MAGIC, BOOT_MAGIC_SIZE)) {
		VB2_DEBUG("Incorrect 'init_boot' header, total size: %zx\n",
			  init_boot_size);
		return VB2_ERROR_ANDROID_BROKEN_INIT_BOOT;
	}

	/* On init_boot there's no kernel, so ramdisk follows the header */
	uint8_t *init_boot_ramdisk = (uint8_t *)init_hdr + BOOT_HEADER_SIZE;
	size_t init_boot_ramdisk_size = init_hdr->ramdisk_size;

	/*
	 * Move init_boot ramdisk to directly follow the vendor_boot ramdisk.
	 * This is a requirement from Android system. The cpio/gzip/lz4
	 * compression formats support this type of concatenation. After
	 * the kernel decompresses, it extracts concatenated file into
	 * an initramfs, which results in a file structure that's a generic
	 * ramdisk (from init_boot) overlaid on the vendor ramdisk (from
	 * vendor_boot) file structure.
	 */
	vendor_ramdisk_end = (uint8_t *)vendor_hdr +
		VB2_ALIGN_UP(sizeof(*vendor_hdr), vendor_hdr->page_size) +
		vendor_hdr->vendor_ramdisk_size;
	VB2_ASSERT(vendor_ramdisk_end < init_boot_ramdisk);
	memmove(vendor_ramdisk_end, init_boot_ramdisk, init_boot_ramdisk_size);
	params->ramdisk_size += init_boot_ramdisk_size;

	/* Save vendor cmdline for booting */
	vendor_hdr->cmdline[sizeof(vendor_hdr->cmdline) - 1] = '\0';
	params->vendor_cmdline_buffer = (char *)vendor_hdr->cmdline;

	return VB2_SUCCESS;
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
	if (rv != VB2_SUCCESS)
		goto out;

	/*
	 * Before booting we need to rearrange buffers with partition data, which includes:
	 * - save bootconfig in separate buffer, so depthcharge can modify it
	 * - concatenate ramdisks from vendor_boot & init_boot partitions
	 */
	rv = rearrange_partitions(avb_ops, params);

out:
	/* No need for slot data */
	if (verify_data != NULL)
		avb_slot_verify_data_free(verify_data);

	vboot_avb_ops_free(avb_ops);

	return rv;
}
