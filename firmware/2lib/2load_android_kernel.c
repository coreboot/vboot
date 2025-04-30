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

#define VERIFIED_BOOT_PROPERTY_NAME "androidboot.verifiedbootstate"
#define SLOT_SUFFIX_BOOT_PROPERTY_NAME "androidboot.slot_suffix"
#define ANDROID_FORCE_NORMAL_BOOT_PROPERTY_NAME "androidboot.force_normal_boot"

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

static bool gki_ramdisk_fragment_needed(struct vendor_ramdisk_table_entry_v4 *fragment,
					bool recovery_boot)
{
	/* Ignore all other properties except ramdisk type */
	switch (fragment->ramdisk_type) {
	case VENDOR_RAMDISK_TYPE_PLATFORM:
	case VENDOR_RAMDISK_TYPE_DLKM:
		return true;

	case VENDOR_RAMDISK_TYPE_RECOVERY:
		return recovery_boot;

	default:
		printf("Unknown ramdisk type 0x%x\n", fragment->ramdisk_type);
		return false;
	}
}

/* Function for finding a loaded partition in AvbSlotVerifyData */
static AvbPartitionData *avb_find_part(AvbSlotVerifyData *verify_data, enum GptPartition name)
{
	size_t i;
	AvbPartitionData *part;

	for (i = 0; i < verify_data->num_loaded_partitions; i++) {
		part = &verify_data->loaded_partitions[i];

		if (!strcmp(part->partition_name, GptPartitionNames[name]))
			return part;
	}

	return NULL;
}

/*
 * This function removes unnecessary ramdisks from ramdisk table, concatenates rest of
 * them and returns start and end of new ramdisk.
 */
static vb2_error_t prepare_vendor_ramdisks(struct vendor_boot_img_hdr_v4 *vendor_hdr,
					   size_t total_size,
					   bool recovery_boot,
					   uint8_t **vendor_ramdisk,
					   uint8_t **vendor_ramdisk_end)
{
	uint32_t ramdisk_offset;
	uint32_t ramdisk_table_offset;
	uint32_t ramdisk_table_size = vendor_hdr->vendor_ramdisk_table_size;
	uint32_t ramdisk_table_entry_size = vendor_hdr->vendor_ramdisk_table_entry_size;
	uint32_t ramdisk_table_entry_num = vendor_hdr->vendor_ramdisk_table_entry_num;
	uint32_t page_size = vendor_hdr->page_size;
	uintptr_t fragment_ptr;

	/* Calculate address offset of vendor_ramdisk section on vendor_boot partition */
	ramdisk_offset = VB2_ALIGN_UP(sizeof(struct vendor_boot_img_hdr_v4), page_size);
	ramdisk_table_offset = ramdisk_offset +
		VB2_ALIGN_UP(vendor_hdr->vendor_ramdisk_size, page_size) +
		VB2_ALIGN_UP(vendor_hdr->dtb_size, page_size);

	/* Check if vendor ramdisk table is correct */
	if (ramdisk_offset > total_size ||
	    ramdisk_table_offset > total_size ||
	    ramdisk_table_entry_size < sizeof(struct vendor_ramdisk_table_entry_v4) ||
	    total_size - ramdisk_offset < vendor_hdr->vendor_ramdisk_size ||
	    total_size - ramdisk_table_offset < ramdisk_table_size ||
	    ramdisk_table_size < (ramdisk_table_entry_num * ramdisk_table_entry_size)) {
		VB2_DEBUG("Broken 'vendor_boot' image\n");
		return VB2_ERROR_ANDROID_BROKEN_VENDOR_BOOT;
	}

	*vendor_ramdisk = (uint8_t *)vendor_hdr + ramdisk_offset;
	*vendor_ramdisk_end = *vendor_ramdisk;
	fragment_ptr = (uintptr_t)vendor_hdr + ramdisk_table_offset;
	/* Go through all ramdisk fragments and keep only the required ones */
	for (int i = 0; i < ramdisk_table_entry_num;
	    fragment_ptr += ramdisk_table_entry_size, i++) {
		struct vendor_ramdisk_table_entry_v4 *fragment;
		uint8_t *fragment_src;

		fragment = (struct vendor_ramdisk_table_entry_v4 *)fragment_ptr;
		if (!gki_ramdisk_fragment_needed(fragment, recovery_boot))
			continue;

		uint32_t fragment_size = fragment->ramdisk_size;
		uint32_t fragment_offset = fragment->ramdisk_offset;

		if (fragment_offset > vendor_hdr->vendor_ramdisk_size ||
		    vendor_hdr->vendor_ramdisk_size - fragment_offset < fragment_size) {
			VB2_DEBUG("Incorrect fragment - offset:%x size:%x, ramdisk_size: %x\n",
				  fragment_offset, fragment_size,
				  vendor_hdr->vendor_ramdisk_size);
		}
		fragment_src = *vendor_ramdisk + fragment_offset;
		if (*vendor_ramdisk_end != fragment_src)
			/*
			 * A fragment was skipped before, we need to move current one
			 * at the correct place.
			 */
			memmove(*vendor_ramdisk_end, fragment_src, fragment_size);

		/* Update location of the end of vendor ramdisk */
		*vendor_ramdisk_end += fragment_size;
	}

	return VB2_SUCCESS;
}

static vb2_error_t prepare_pvmfw(AvbSlotVerifyData *verify_data,
				 struct vb2_kernel_params *params)
{
	AvbPartitionData *part;
	struct boot_img_hdr_v4 *pvmfw_hdr;

	part = avb_find_part(verify_data, GPT_ANDROID_PVMFW);
	if (!part) {
		VB2_DEBUG("Ignoring lack of pvmfw partition\n");
		params->pvmfw_out_size = 0;
		return VB2_SUCCESS;
	}

	pvmfw_hdr = (void *)part->data;

	/* If loaded pvmfw is smaller then boot header or the boot header magic is invalid
	 * or the header kernel size exceeds buffer size, then fail */
	if (part->data_size < BOOT_HEADER_SIZE ||
	    memcmp(pvmfw_hdr->magic, BOOT_MAGIC, BOOT_MAGIC_SIZE) ||
	    part->data_size - BOOT_HEADER_SIZE < pvmfw_hdr->kernel_size) {
		VB2_DEBUG("Incorrect magic or size (%zx) of 'pvmfw' image\n", part->data_size);
		return VB2_ERROR_ANDROID_BROKEN_PVMFW;
	}

	/* Get pvmfw code size */
	params->pvmfw_out_size = pvmfw_hdr->kernel_size;

	/* pvmfw code starts after the boot header. Discard the boot header, by
	 * moving the buffer start and trimming its size. */
	params->pvmfw_buffer = ((void *)pvmfw_hdr) + BOOT_HEADER_SIZE;
	params->pvmfw_buffer_size -= BOOT_HEADER_SIZE;

	return VB2_SUCCESS;
}

/*
 * This function validates the partitions magic numbers and move them into place requested
 * from linux.
 */
static vb2_error_t rearrange_partitions(AvbOps *avb_ops,
					struct vb2_kernel_params *params,
					bool recovery_boot)
{
	struct vendor_boot_img_hdr_v4 *vendor_hdr;
	struct boot_img_hdr_v4 *init_hdr;
	size_t vendor_boot_size, init_boot_size;
	uint8_t *vendor_ramdisk_end = 0;

	if (vb2_android_get_buffer(avb_ops, GPT_ANDROID_VENDOR_BOOT, (void **)&vendor_hdr,
				   &vendor_boot_size) ||
	    vb2_android_get_buffer(avb_ops, GPT_ANDROID_INIT_BOOT, (void **)&init_hdr,
				   &init_boot_size)) {
		VB2_DEBUG("Cannot get information about preloaded partition\n");
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

	/* Remove unused ramdisks */
	VB2_TRY(prepare_vendor_ramdisks(vendor_hdr, vendor_boot_size, recovery_boot,
					&params->ramdisk, &vendor_ramdisk_end));
	params->ramdisk_size = vendor_ramdisk_end - params->ramdisk;

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
	enum vb2_android_bootmode bootmode = VB2_ANDROID_NORMAL_BOOT;
	AvbSlotVerifyData *verify_data = NULL;
	AvbOps *avb_ops;
	AvbSlotVerifyFlags avb_flags;
	AvbSlotVerifyResult result;
	vb2_error_t rv;
	const char *boot_partitions[] = {
		GptPartitionNames[GPT_ANDROID_BOOT],
		GptPartitionNames[GPT_ANDROID_INIT_BOOT],
		GptPartitionNames[GPT_ANDROID_VENDOR_BOOT],
		GptPartitionNames[GPT_ANDROID_PVMFW],
		NULL,
	};
	const char *slot_suffix = NULL;
	bool need_verification = vb2_need_kernel_verification(ctx);

	/*
	 * Check if the pvmfw buffer is zero sized
	 * (ie. pvmfw loading is not requested)
	 */
	if (params->pvmfw_buffer_size == 0) {
		VB2_DEBUG("Not loading pvmfw: not requested.\n");
		boot_partitions[3] = NULL;
		params->pvmfw_out_size = 0;
	}

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

	if (result == AVB_SLOT_VERIFY_RESULT_OK) {
		struct vb2_shared_data *sd = vb2_get_sd(ctx);
		sd->flags |= VB2_SD_FLAG_KERNEL_SIGNED;
	}

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

	rv = vb2ex_get_android_bootmode(ctx, disk_handle, gpt, &bootmode);
	if (rv != VB2_SUCCESS) {
		VB2_DEBUG("Unable to get android bootmode\n");
		goto out;
	}
	bool recovery_boot = bootmode == VB2_ANDROID_RECOVERY_BOOT;

	/*
	 * Before booting we need to rearrange buffers with partition data, which includes:
	 * - save bootconfig in separate buffer, so depthcharge can modify it
	 * - remove unused ramdisks depending on boot type (normal/recovery)
	 * - concatenate ramdisks from vendor_boot & init_boot partitions
	 */
	rv = rearrange_partitions(avb_ops, params, recovery_boot);
	if (rv)
		goto out;

	/*
	 * Use orange verifiedbootstate if OS wasn't verified (e.g. in developer mode) or
	 * when booting to recovery with GBB enabled fastboot to unlock all commands of
	 * fastbootd (normally when we boot to recovery with green flag, fastbootd would be
	 * locked).
	 */
	bool orange = !need_verification ||
		      (recovery_boot && ctx->flags & VB2_GBB_FLAG_FORCE_UNLOCK_FASTBOOT);

	/*
	 * TODO(b/335901799): Add support for marking verifiedbootstate yellow
	 */
	int chars = snprintf(params->vboot_cmdline_buffer, params->vboot_cmdline_size,
			     "%s %s=%s %s=%s %s=%s", verify_data->cmdline,
			     VERIFIED_BOOT_PROPERTY_NAME,
			     orange ? "orange" : "green",
			     SLOT_SUFFIX_BOOT_PROPERTY_NAME, slot_suffix,
			     ANDROID_FORCE_NORMAL_BOOT_PROPERTY_NAME, recovery_boot ? "0" : "1"
			     );
	if (chars < 0 || chars >= params->vboot_cmdline_size) {
		VB2_DEBUG("ERROR: Command line doesn't fit provided buffer: %s\n",
			  verify_data->cmdline);
		rv = VB2_ERROR_ANDROID_CMDLINE_BUF_TOO_SMALL;
		goto out;
	}

	rv = prepare_pvmfw(verify_data, params);

out:
	/* No need for slot data */
	if (verify_data != NULL)
		avb_slot_verify_data_free(verify_data);

	vboot_avb_ops_free(avb_ops);

	return rv;
}
