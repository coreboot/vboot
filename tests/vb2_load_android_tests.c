/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for vboot_kernel.c
 */

#include "2api.h"
#include "2avb.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "cgptlib.h"
#include "cgptlib_internal.h"
#include "common/boot_mode.h"
#include "common/tests.h"
#include "gpt.h"
#include "vb2_android_bootimg.h"
#include "vboot_api.h"

#define INIT_KERN_SECDATA 0x20001

#define NUM_OF_ENTRIES 8
#define BYTES_PER_LBA 512

#define PART_SIZE 16
#define VBMETA_LBA 100
#define BOOT_LBA (VBMETA_LBA + PART_SIZE)
#define VENDOR_BOOT_LBA (BOOT_LBA + PART_SIZE)
#define INIT_BOOT_LBA (VENDOR_BOOT_LBA + PART_SIZE)

GptHeader gpt_hdr;
GptEntry entries[NUM_OF_ENTRIES];
struct vendor_boot_img_hdr_v4 vendor_boot_hdr;
struct boot_img_hdr_v4 init_boot_hdr;

uint64_t rollback_value;
bool avb_verification_fails;
bool init_boot_missing, vendor_boot_missing;
uint64_t sector_to_read;

static const uint16_t vbmeta_a_name[] = {'v', 'b', 'm', 'e', 't', 'a', '_', 'a', 0};
static const uint16_t boot_a_name[] = {'b', 'o', 'o', 't', '_', 'a', 0};
static const uint16_t vendor_boot_a_name[] = {'v', 'e', 'n', 'd', 'o', 'r', '_', 'b', 'o', 'o', 't', '_', 'a', 0};
static const uint16_t init_boot_a_name[] = {'i', 'n', 'i', 't', '_', 'b', 'o', 'o', 't', '_', 'a', 0};

static const char fake_guid[] = "FakeGuid";
static uint8_t kernel_buffer[80000];
static char bootconfig_cmdline[1000];

/* Mock data */
static struct vb2_gbb_header gbb;
static struct vb2_kernel_params lkp;
static struct vb2_disk_info disk_info;
static uint8_t workbuf[VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE]
	__attribute__((aligned(VB2_WORKBUF_ALIGN)));
static struct vb2_context *ctx;
static struct vb2_shared_data *sd;

/* Mocked functions */
int AllocAndReadGptData(vb2ex_disk_handle_t disk_handle, GptData *gptdata)
{
	/* No data to be written yet */
	gptdata->modified = 0;
	/* This should get overwritten by GptInit() */
	gptdata->ignored = 0;

	/* Allocate all buffers */
	gptdata->primary_header = (uint8_t *)&gpt_hdr;
	gptdata->secondary_header = (uint8_t *)&gpt_hdr;
	gptdata->primary_entries = (uint8_t *)&entries;
	gptdata->secondary_entries = (uint8_t *)&entries;

	return 0;
}

int WriteAndFreeGptData(vb2ex_disk_handle_t disk_handle, GptData *gptdata) { return 0; }

int GptInit(GptData *gpt)
{

	gpt->modified = 0;
	gpt->current_kernel = CGPT_KERNEL_ENTRY_NOT_FOUND;
	gpt->current_priority = 999;

	return GPT_SUCCESS;
}

AvbSlotVerifyResult avb_slot_verify(AvbOps *ops, const char *const *requested_partitions,
				    const char *ab_suffix, AvbSlotVerifyFlags flags,
				    AvbHashtreeErrorMode hashtree_error_mode,
				    AvbSlotVerifyData **out_data)
{
	AvbSlotVerifyData *verify_data;
	uint8_t *out_pointer;
	size_t num_bytes, part_size_bytes;

	part_size_bytes = PART_SIZE * BYTES_PER_LBA;
	ops->get_preloaded_partition(ops, "boot_a", part_size_bytes, &out_pointer, &num_bytes);
	if (!init_boot_missing)
		ops->get_preloaded_partition(ops, "init_boot_a", part_size_bytes, &out_pointer,
					&num_bytes);
	if (!vendor_boot_missing)
		ops->get_preloaded_partition(ops, "vendor_boot_a", part_size_bytes, &out_pointer,
					&num_bytes);

	verify_data = malloc(sizeof(*verify_data));
	verify_data->rollback_indexes[0] = rollback_value;
	*out_data = verify_data;

	if (avb_verification_fails)
		return AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION;
	else
		return AVB_SLOT_VERIFY_RESULT_OK;
}

void avb_slot_verify_data_free(AvbSlotVerifyData *data)
{
	free(data);
}

vb2_error_t VbExStreamOpen(vb2ex_disk_handle_t handle, uint64_t lba_start, uint64_t lba_count,
			   VbExStream_t *stream_ptr)
{
	sector_to_read = lba_start;
	return VB2_SUCCESS;
}

vb2_error_t VbExStreamSkip(VbExStream_t stream, uint32_t bytes) { return VB2_SUCCESS; }

vb2_error_t VbExStreamRead(VbExStream_t stream, uint32_t bytes, void *buffer)
{
	if (sector_to_read == VENDOR_BOOT_LBA)
		memcpy(buffer, &vendor_boot_hdr, sizeof(vendor_boot_hdr));
	else if (sector_to_read == INIT_BOOT_LBA)
		memcpy(buffer, &init_boot_hdr, sizeof(init_boot_hdr));

	return VB2_SUCCESS;
}

void VbExStreamClose(VbExStream_t stream) {}

/* Reset mock data (for use before each test) */
static void reset_mocks(void)
{
	rollback_value = 0x1;
	avb_verification_fails = false;
	init_boot_missing = false;
	vendor_boot_missing = false;

	memset(&gbb, 0, sizeof(gbb));
	gbb.major_version = VB2_GBB_MAJOR_VER;
	gbb.minor_version = VB2_GBB_MINOR_VER;
	gbb.flags = 0;

	memset(&lkp, 0, sizeof(lkp));
	lkp.kernel_buffer = kernel_buffer;
	lkp.kernel_buffer_size = sizeof(kernel_buffer);
	lkp.bootconfig_cmdline_buffer = bootconfig_cmdline;
	lkp.bootconfig_cmdline_size = sizeof(bootconfig_cmdline);

	memset(&disk_info, 0, sizeof(disk_info));
	disk_info.bytes_per_lba = BYTES_PER_LBA;
	disk_info.streaming_lba_count = 1024;
	disk_info.lba_count = 1024;
	disk_info.handle = (vb2ex_disk_handle_t)1;

	memset(&gpt_hdr, 0, sizeof(gpt_hdr));
	gpt_hdr.number_of_entries = NUM_OF_ENTRIES;
	memset(&entries, 0, sizeof(entries));
	entries[0].starting_lba = VBMETA_LBA;
	entries[0].ending_lba = VBMETA_LBA;
	memcpy(&entries[0].unique, fake_guid, sizeof(fake_guid));
	memcpy(&entries[0].type, &guid_android_vbmeta, sizeof(guid_android_vbmeta));
	memcpy(&entries[0].name, &vbmeta_a_name, sizeof(vbmeta_a_name));
	SetEntrySuccessful(&entries[0], 1);
	SetEntryPriority(&entries[0], 1);

	entries[1].starting_lba = BOOT_LBA;
	entries[1].ending_lba = (BOOT_LBA + PART_SIZE - 1);
	memcpy(&entries[1].name, &boot_a_name, sizeof(boot_a_name));

	entries[2].starting_lba = VENDOR_BOOT_LBA;
	entries[2].ending_lba = (VENDOR_BOOT_LBA + PART_SIZE - 1);
	memcpy(&entries[2].name, &vendor_boot_a_name, sizeof(vendor_boot_a_name));

	entries[3].starting_lba = INIT_BOOT_LBA;
	entries[3].ending_lba = (INIT_BOOT_LBA + PART_SIZE - 1);
	memcpy(&entries[3].name, &init_boot_a_name, sizeof(init_boot_a_name));

	memcpy(vendor_boot_hdr.magic, VENDOR_BOOT_MAGIC, VENDOR_BOOT_MAGIC_SIZE);
	vendor_boot_hdr.vendor_ramdisk_table_entry_size =
		sizeof(struct vendor_ramdisk_table_entry_v4);
	vendor_boot_hdr.page_size = 512;
	memcpy(init_boot_hdr.magic, BOOT_MAGIC, BOOT_MAGIC_SIZE);

	vb2api_init(workbuf, sizeof(workbuf), &ctx);
	vb2_nv_init(ctx);
	vb2_nv_set(ctx, VB2_NV_KERNEL_MAX_ROLLFORWARD, 0xfffffffe);

	sd = vb2_get_sd(ctx);

	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_NORMAL);
}

static void load_android_tests(void)
{
	reset_mocks();
	TEST_EQ(vb2api_load_kernel(ctx, &lkp, &disk_info), VB2_SUCCESS, "Boot android");
	TEST_EQ(lkp.flags, VB2_KERNEL_TYPE_BOOTIMG, "  bootimg type flag");
	TEST_STR_EQ((char *)lkp.partition_guid.u.raw, fake_guid, "  guid");
	TEST_NEQ(sd->flags & VB2_SD_FLAG_KERNEL_SIGNED, 0, "  use signature");

	// No valid slot (successful=0 and tries=0)
	reset_mocks();
	SetEntrySuccessful(&entries[0], 0);
	TEST_EQ(vb2api_load_kernel(ctx, &lkp, &disk_info), VB2_ERROR_LK_NO_KERNEL_FOUND,
		"No valid slot");

	// Incorrect slot '_c'
	reset_mocks();
	entries[0].name[7] = 'c';
	TEST_EQ(vb2api_load_kernel(ctx, &lkp, &disk_info), VB2_ERROR_LK_INVALID_KERNEL_FOUND,
		"Incorrect slot type");

	// AVB verification fails
	reset_mocks();
	avb_verification_fails = true;
	TEST_EQ(vb2api_load_kernel(ctx, &lkp, &disk_info), VB2_ERROR_LK_INVALID_KERNEL_FOUND,
		"AVB verification fails");

	// AVB verification fails in developer mode
	reset_mocks();
	avb_verification_fails = true;
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DEVELOPER);
	TEST_EQ(vb2api_load_kernel(ctx, &lkp, &disk_info), VB2_SUCCESS,
		"AVB verification fails in developer mode");

	// Missing init_boot partition
	reset_mocks();
	init_boot_missing = true;
	TEST_EQ(vb2api_load_kernel(ctx, &lkp, &disk_info), VB2_ERROR_LK_INVALID_KERNEL_FOUND,
		"Missing init_boot partition");

	// init_boot partition too small
	reset_mocks();
	entries[3].ending_lba = INIT_BOOT_LBA;
	TEST_EQ(vb2api_load_kernel(ctx, &lkp, &disk_info), VB2_ERROR_LK_INVALID_KERNEL_FOUND,
		"init_boot partition too small");

	// init_boot with non-zero kernel size
	reset_mocks();
	init_boot_hdr.kernel_size = 0x1000;
	TEST_EQ(vb2api_load_kernel(ctx, &lkp, &disk_info), VB2_ERROR_LK_INVALID_KERNEL_FOUND,
		"Non zero kernel size");

	// Missing vendor_boot
	reset_mocks();
	vendor_boot_missing = true;
	TEST_EQ(vb2api_load_kernel(ctx, &lkp, &disk_info), VB2_ERROR_LK_INVALID_KERNEL_FOUND,
		"Missing vendor_boot partition");

	// vendor_boot partition too small
	reset_mocks();
	entries[2].ending_lba = VENDOR_BOOT_LBA;
	TEST_EQ(vb2api_load_kernel(ctx, &lkp, &disk_info), VB2_ERROR_LK_INVALID_KERNEL_FOUND,
		"vendor_boot partition too small");

	// ramdisk table size too big
	reset_mocks();
	vendor_boot_hdr.vendor_ramdisk_size = 16384;
	TEST_EQ(vb2api_load_kernel(ctx, &lkp, &disk_info), VB2_ERROR_LK_INVALID_KERNEL_FOUND,
		"vendor_boot ramdisk table too big");
}

int main(void)
{
	load_android_tests();

	return gTestSuccess ? 0 : 255;
}
