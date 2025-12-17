/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for keyblock hash verification
 */
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

#include "2avb.h"
#include "2common.h"
#include "2nvstorage.h"
#include "2secdata.h"
#include "2struct.h"
#include "cgptlib_internal.h"
#include "common/tests.h"
#include "host_key.h"

#define NUM_OF_ENTRIES 8
#define BYTES_PER_LBA 512

#define PART_SIZE 16
#define VBMETA_LBA 100
#define BOOT_LBA (VBMETA_LBA + PART_SIZE)
#define VENDOR_BOOT_LBA (BOOT_LBA + PART_SIZE)
#define INIT_BOOT_LBA (VENDOR_BOOT_LBA + PART_SIZE)

#define KERNEL_BUFFER_SIZE 0x10000
#define KERNEL_VERSION_SECDATA 1

// Disk related variables
GptHeader gpt_hdr;
GptEntry entries[NUM_OF_ENTRIES];
GptData gptdata;
static struct vb2_disk_info disk_info;
static const uint16_t vbmeta_a_name[] = {'v', 'b', 'm', 'e', 't', 'a', '_', 'a', 0};
static const uint16_t vbmeta_b_name[] = {'v', 'b', 'm', 'e', 't', 'a', '_', 'b', 0};
static const uint16_t boot_a_name[] = {'b', 'o', 'o', 't', '_', 'a', 0};
static const uint16_t boot_b_name[] = {'b', 'o', 'o', 't', '_', 'b', 0};

// Verification related variables
static uint8_t *avb_key_data;
static size_t avb_key_len;
static char *keys_dir;
static const char *const key_len[] = {"1024", "2048", "4096", "8192"};
static int key_alg[] = {VB2_ALG_RSA1024_SHA256, VB2_ALG_RSA2048_SHA256, VB2_ALG_RSA4096_SHA256,
			VB2_ALG_RSA8192_SHA256};

// VBOOT API variables
uint8_t kernel_buffer[KERNEL_BUFFER_SIZE];
static uint8_t workbuf[VB2_FIRMWARE_WORKBUF_RECOMMENDED_SIZE]
	__attribute__((aligned(VB2_WORKBUF_ALIGN)));
static struct vb2_context *vb2_ctx;
static struct vb2_shared_data *sd;
struct vb2_gbb_header gbb_hdr;

// Mocks
struct vb2_gbb_header *vb2_get_gbb(struct vb2_context *ctx) { return &gbb_hdr; }

vb2_error_t VbExStreamOpen(vb2ex_disk_handle_t handle, uint64_t lba_start, uint64_t lba_count,
			   VbExStream_t *stream_ptr)
{
	return VB2_SUCCESS;
}

vb2_error_t VbExStreamSkip(VbExStream_t stream, uint32_t bytes) { return VB2_SUCCESS; }

vb2_error_t VbExStreamRead(VbExStream_t stream, uint32_t bytes, void *buffer)
{
	return VB2_SUCCESS;
}

void VbExStreamClose(VbExStream_t stream) {}

static int prepare_cros_key(const char *filename, uint32_t alg)
{
	struct vb2_packed_key *test_key;

	test_key = vb2_read_packed_keyb(filename, alg, 1);
	if (!test_key) {
		fprintf(stderr, "Error reading test key\n");
		return -1;
	}
	sd->kernel_key_offset = sizeof(*sd);
	sd->kernel_key_size =
		sizeof(*test_key) + vb2_packed_key_size(vb2_crypto_to_signature(alg));
	memcpy(sd + 1, test_key, sd->kernel_key_size);
	free(test_key);

	return 0;
}

static int prepare_avb_key(const char *filename)
{
	FILE *fp;
	struct stat sb;
	int rv = 0;

	fp = fopen(filename, "rb");
	if (!fp) {
		fprintf(stderr, "Couldn't open file %s!\n", filename);
		return -1;
	}

	if (fstat(fileno(fp), &sb)) {
		fprintf(stderr, "Can't fstat %s: %s\n", filename, strerror(errno));
		goto err;
	}

	avb_key_len = sb.st_size;
	avb_key_data = malloc(sb.st_size);
	if (!avb_key_data)
		goto err;

	if (fread(avb_key_data, avb_key_len, 1, fp) != 1) {
		fprintf(stderr, "Unable to read from %s: %s\n", filename, strerror(errno));
		goto err;
	}

	fclose(fp);
	return 0;

err:
	if (avb_key_data) {
		free(avb_key_data);
		avb_key_data = NULL;
		avb_key_len = 0;
	}
	fclose(fp);
	return rv;
}

static int setup(int key_num)
{
	char filename[256];

	snprintf(filename, sizeof(filename), "%s/key_rsa%s.keyb", keys_dir, key_len[key_num]);
	if (prepare_cros_key(filename, key_alg[key_num])) {
		fprintf(stderr, "Error preparing AVB key\n");
		return -1;
	}

	snprintf(filename, sizeof(filename), "%s/key_rsa%s.avb", keys_dir, key_len[key_num]);
	if (prepare_avb_key(filename)) {
		fprintf(stderr, "Error preparing AVB key\n");
		return -1;
	}

	return 0;
}

static void clean(void)
{
	if (avb_key_data) {
		free(avb_key_data);
		avb_key_data = NULL;
	}

	avb_key_len = 0;
}

static void setup_storage(void)
{
	memset(&disk_info, 0, sizeof(disk_info));
	disk_info.bytes_per_lba = BYTES_PER_LBA;
	disk_info.streaming_lba_count = 1024;
	disk_info.lba_count = 1024;
	disk_info.handle = (vb2ex_disk_handle_t)1;

	memset(&gpt_hdr, 0, sizeof(gpt_hdr));
	gpt_hdr.number_of_entries = NUM_OF_ENTRIES;

	memset(&entries, 0, sizeof(entries));

	uint64_t lba = 0x100;
	entries[0].starting_lba = lba;
	entries[0].ending_lba = lba + PART_SIZE - 1;
	lba += PART_SIZE;
	memcpy(&entries[0].type, &guid_android_vbmeta, sizeof(guid_android_vbmeta));
	memcpy(&entries[0].unique, &guid_basic_data, sizeof(guid_basic_data));
	memcpy(&entries[0].name, &vbmeta_a_name, sizeof(vbmeta_a_name));

	entries[1].starting_lba = lba;
	entries[1].ending_lba = lba + PART_SIZE - 1;
	lba += PART_SIZE;
	memcpy(&entries[1].name, &boot_a_name, sizeof(boot_a_name));
	memcpy(&entries[1].unique, &guid_linux_data, sizeof(guid_linux_data));

	entries[2].starting_lba = lba;
	entries[2].ending_lba = lba + PART_SIZE - 1;
	lba += PART_SIZE;
	memcpy(&entries[2].name, &vbmeta_b_name, sizeof(vbmeta_b_name));
	memcpy(&entries[2].unique, &guid_efi, sizeof(guid_efi));

	entries[3].starting_lba = lba;
	entries[3].ending_lba = lba + PART_SIZE - 1;
	lba += PART_SIZE;
	memcpy(&entries[3].name, &boot_b_name, sizeof(boot_b_name));
	memcpy(&entries[3].unique, &guid_unused, sizeof(guid_unused));

	/* No data to be written yet */
	gptdata.modified = 0;
	/* This should get overwritten by GptInit() */
	gptdata.ignored = 0;

	/* Allocate all buffers */
	gptdata.primary_header = (uint8_t *)&gpt_hdr;
	gptdata.secondary_header = (uint8_t *)&gpt_hdr;
	gptdata.primary_entries = (uint8_t *)&entries;
	gptdata.secondary_entries = (uint8_t *)&entries;
	gptdata.sector_bytes = 512;
}

static void validate_vbmeta_public_key_tests(AvbOps *avb_ops)
{
	AvbIOResult ret;
	bool key_is_trusted;
	int i;

	for (i = 0; i < ARRAY_SIZE(key_len); i++) {

		// Successful validation
		TEST_EQ_S(setup(i), 0);
		ret = avb_ops->validate_vbmeta_public_key(avb_ops, avb_key_data, avb_key_len,
							  NULL, 0, &key_is_trusted);
		TEST_EQ(ret, AVB_IO_RESULT_OK, "validate_vbmeta_public_key - successful");
		TEST_EQ(key_is_trusted, true, "Key is trusted");
		clean();

		// Key size lesser than required
		TEST_EQ_S(setup(i), 0);
		avb_key_len = sizeof(AvbRSAPublicKeyHeader) - 1;
		ret = avb_ops->validate_vbmeta_public_key(avb_ops, avb_key_data, avb_key_len,
							  NULL, 0, &key_is_trusted);
		TEST_EQ(ret, AVB_IO_RESULT_OK, "validate_vbmeta_public_key - successful");
		TEST_EQ(key_is_trusted, false, "Key rejected - incorrect key size");
		clean();

		// n0inv corruption
		TEST_EQ_S(setup(i), 0);
		avb_key_data[4] ^= avb_key_data[4];
		ret = avb_ops->validate_vbmeta_public_key(avb_ops, avb_key_data, avb_key_len,
							  NULL, 0, &key_is_trusted);
		TEST_EQ(ret, AVB_IO_RESULT_OK, "validate_vbmeta_public_key - successful");
		TEST_EQ(key_is_trusted, false, "Key rejected - n0inv corrupted");
		clean();

		// rr corruption
		TEST_EQ_S(setup(i), 0);
		avb_key_data[avb_key_len - 1] ^= avb_key_data[avb_key_len - 1];
		ret = avb_ops->validate_vbmeta_public_key(avb_ops, avb_key_data, avb_key_len,
							  NULL, 0, &key_is_trusted);
		TEST_EQ(ret, AVB_IO_RESULT_OK, "validate_vbmeta_public_key - successful");
		TEST_EQ(key_is_trusted, false, "Key rejected - rr corrupted");
		clean();

		// n corruption
		TEST_EQ_S(setup(i), 0);
		avb_key_data[sizeof(AvbRSAPublicKeyHeader)] ^=
			avb_key_data[sizeof(AvbRSAPublicKeyHeader)];
		ret = avb_ops->validate_vbmeta_public_key(avb_ops, avb_key_data, avb_key_len,
							  NULL, 0, &key_is_trusted);
		TEST_EQ(ret, AVB_IO_RESULT_OK, "validate_vbmeta_public_key - successful");
		TEST_EQ(key_is_trusted, false, "Key rejected - n corrupted");
		clean();
	}

	// Try 2 different keys of the same length
	char filename[256];
	snprintf(filename, sizeof(filename), "%s/key_rsa2048_exp3.keyb", keys_dir);
	TEST_EQ(prepare_cros_key(filename, VB2_ALG_RSA2048_SHA256), 0, "Prepare cros key");
	snprintf(filename, sizeof(filename), "%s/key_rsa2048.avb", keys_dir);
	TEST_EQ(prepare_avb_key(filename), 0, "Prepare avb key");
	ret = avb_ops->validate_vbmeta_public_key(avb_ops, avb_key_data, avb_key_len, NULL, 0,
						  &key_is_trusted);
	TEST_EQ(ret, AVB_IO_RESULT_OK, "validate_vbmeta_public_key - successful");
	TEST_EQ(key_is_trusted, false, "Key rejected - different keys");
}

static void read_from_partition_tests(AvbOps *avb_ops)
{
	char buffer[1024];
	size_t bytes;

	TEST_EQ(avb_ops->read_from_partition(avb_ops, "vbmeta_a", 0, 0x200, buffer, &bytes),
		AVB_IO_RESULT_OK, "read_from_partition: vbmeta_a");
	TEST_EQ(bytes, 0x200, "correct bytes read");

	TEST_EQ(avb_ops->read_from_partition(avb_ops, "boot_b", 0, 0x300, buffer, &bytes),
		AVB_IO_RESULT_OK, "read_from_partition: boot_b");
	TEST_EQ(bytes, 0x300, "correct bytes read");

	TEST_EQ(avb_ops->read_from_partition(avb_ops, "not_exists", 0, 0x300, buffer, &bytes),
		AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION, "read from non-existed partition");
	TEST_EQ(bytes, 0x0, "correct bytes read");

	TEST_EQ(avb_ops->read_from_partition(avb_ops, "vbmeta_a", -(PART_SIZE * 0x200 + 1),
					     0x300, buffer, &bytes),
		AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION, "negative offset");
	TEST_EQ(bytes, 0x0, "correct bytes read");

	TEST_EQ(avb_ops->read_from_partition(avb_ops, "vbmeta_b", 0, (PART_SIZE + 1) * 0x200,
					     buffer, &bytes),
		AVB_IO_RESULT_OK, "truncate if expected too much to read");
	TEST_EQ(bytes, PART_SIZE * 0x200, "correct bytes read");
}

static void get_preload_partition_tests(AvbOps *avb_ops)
{
	uint8_t *out_pointer;
	size_t out_num_bytes;

	out_pointer = NULL;
	out_num_bytes = 0;
	TEST_EQ(avb_ops->get_preloaded_partition(avb_ops, "boot_a", 0x200, &out_pointer,
						 &out_num_bytes),
		AVB_IO_RESULT_OK, "get_preloaded_partitions: boot_a");
	TEST_EQ(out_num_bytes, 0x200, "correct bytes read");
	TEST_PTR_NEQ(out_pointer, NULL, "valid partition pointer");

	out_pointer = NULL;
	out_num_bytes = 0;
	TEST_EQ(avb_ops->get_preloaded_partition(avb_ops, "boot", 0x200, &out_pointer,
						 &out_num_bytes),
		AVB_IO_RESULT_OK, "get_preloaded_partitions: name without suffix");
	TEST_EQ(out_num_bytes, 0, "correct bytes read");
	TEST_PTR_EQ(out_pointer, NULL, "nulled partition pointer");

	out_pointer = NULL;
	out_num_bytes = 0;
	TEST_EQ(avb_ops->get_preloaded_partition(avb_ops, "boot_b", 0x200, &out_pointer,
						 &out_num_bytes),
		AVB_IO_RESULT_OK, "get_preloaded_partitions: incorrect suffix");
	TEST_EQ(out_num_bytes, 0, "correct bytes read");
	TEST_PTR_EQ(out_pointer, NULL, "nulled partition pointer");

	out_pointer = NULL;
	out_num_bytes = 0;
	TEST_EQ(avb_ops->get_preloaded_partition(avb_ops, "boot_a", 0x2200, &out_pointer,
						 &out_num_bytes),
		AVB_IO_RESULT_OK, "get_preloaded_partitions: truncate to partition size");
	TEST_EQ(out_num_bytes, 0x2000, "correct bytes read");
	TEST_PTR_NEQ(out_pointer, NULL, "nulled partition pointer");
}

static void read_rollback_tests(AvbOps *avb_ops)
{
	uint64_t rollback_index;

	TEST_EQ(avb_ops->read_rollback_index(avb_ops, 0, &rollback_index), AVB_IO_RESULT_OK,
		"read rollback index with success");
	TEST_EQ(rollback_index, KERNEL_VERSION_SECDATA, "correct rollback index");

	gbb_hdr.flags = VB2_GBB_FLAG_DISABLE_ROLLBACK_CHECK;
	TEST_EQ(avb_ops->read_rollback_index(avb_ops, 0, &rollback_index), AVB_IO_RESULT_OK,
		"read rollback - disable check flag");
	TEST_EQ(rollback_index, 0, "correct rollback index");
	gbb_hdr.flags = 0;

	TEST_EQ(avb_ops->read_rollback_index(avb_ops, 1, &rollback_index),
		AVB_IO_RESULT_ERROR_NO_SUCH_VALUE, "read rollback - incorrect index");

	TEST_EQ(avb_ops->read_rollback_index(avb_ops, 0, NULL),
		AVB_IO_RESULT_ERROR_NO_SUCH_VALUE, "read rollback - nulled pointer");
}

static void read_is_device_unlocked(AvbOps *avb_ops)
{
	bool unlocked = true;

	sd->status |= VB2_SD_STATUS_SECDATA_FWMP_INIT;
	struct vb2_secdata_fwmp *fwmp = (struct vb2_secdata_fwmp *)vb2_ctx->secdata_fwmp;

	vb2_ctx->flags = 0;
	sd->flags = 0;
	vb2_set_boot_mode(vb2_ctx);
	TEST_EQ(avb_ops->read_is_device_unlocked(avb_ops, &unlocked), AVB_IO_RESULT_OK,
		"normal boot");
	TEST_EQ(unlocked, false, "locked mode");

	vb2_ctx->flags = VB2_CONTEXT_DEVELOPER_MODE;
	sd->flags = VB2_SD_FLAG_DEV_MODE_ENABLED;
	vb2_set_boot_mode(vb2_ctx);
	TEST_EQ(avb_ops->read_is_device_unlocked(avb_ops, &unlocked), AVB_IO_RESULT_OK,
		"developer boot");
	TEST_EQ(unlocked, true, "unlocked mode");

	vb2_ctx->flags = VB2_CONTEXT_DEVELOPER_MODE;
	sd->flags = VB2_SD_FLAG_DEV_MODE_ENABLED;
	vb2_set_boot_mode(vb2_ctx);
	fwmp->flags = VB2_SECDATA_FWMP_DEV_USE_KEY_HASH;
	TEST_EQ(avb_ops->read_is_device_unlocked(avb_ops, &unlocked), AVB_IO_RESULT_OK,
		"developer mode - fwmp dev use key hash");
	TEST_EQ(unlocked, false, "locked mode");

	vb2_ctx->flags = VB2_CONTEXT_DEVELOPER_MODE;
	sd->flags = VB2_SD_FLAG_DEV_MODE_ENABLED;
	vb2_set_boot_mode(vb2_ctx);
	fwmp->flags = VB2_SECDATA_FWMP_DEV_ENABLE_OFFICIAL_ONLY;
	TEST_EQ(avb_ops->read_is_device_unlocked(avb_ops, &unlocked), AVB_IO_RESULT_OK,
		"developer mode - fwmp dev enable official only");
	TEST_EQ(unlocked, false, "locked mode");

	vb2_ctx->flags = VB2_CONTEXT_DEVELOPER_MODE;
	sd->flags = VB2_SD_FLAG_DEV_MODE_ENABLED;
	vb2_set_boot_mode(vb2_ctx);
	vb2_nv_set(vb2_ctx, VB2_NV_DEV_BOOT_SIGNED_ONLY, 1);
	TEST_EQ(avb_ops->read_is_device_unlocked(avb_ops, &unlocked), AVB_IO_RESULT_OK,
		"developer mode - boot signed only");
	TEST_EQ(unlocked, false, "locked mode");
}

static void get_unique_guid_for_partition_test(AvbOps *avb_ops)
{
	char guid[GUID_STRLEN], expected[GUID_STRLEN];

	TEST_EQ(avb_ops->get_unique_guid_for_partition(avb_ops, "vbmeta_a", guid, GUID_STRLEN),
		AVB_IO_RESULT_OK, "vbmeta_a - unique");
	GptGuidToStr(&guid_basic_data, expected, GUID_STRLEN, GPT_GUID_LOWERCASE);
	TEST_STR_EQ(guid, expected, "correct guid");

	TEST_EQ(avb_ops->get_unique_guid_for_partition(avb_ops, "vbmeta_b", guid, GUID_STRLEN),
		AVB_IO_RESULT_OK, "vbmeta_b - unique");
	GptGuidToStr(&guid_efi, expected, GUID_STRLEN, GPT_GUID_LOWERCASE);
	TEST_STR_EQ(guid, expected, "correct guid");

	TEST_EQ(avb_ops->get_unique_guid_for_partition(avb_ops, "boot_a", guid, GUID_STRLEN),
		AVB_IO_RESULT_OK, "boot_a - unique");
	GptGuidToStr(&guid_linux_data, expected, GUID_STRLEN, GPT_GUID_LOWERCASE);
	TEST_STR_EQ(guid, expected, "correct guid");

	TEST_EQ(avb_ops->get_unique_guid_for_partition(avb_ops, "boot_b", guid, GUID_STRLEN),
		AVB_IO_RESULT_OK, "boot_b - unique");
	GptGuidToStr(&guid_unused, expected, GUID_STRLEN, GPT_GUID_LOWERCASE);
	TEST_STR_EQ(guid, expected, "correct guid");

	TEST_EQ(avb_ops->get_unique_guid_for_partition(avb_ops, "boot", guid, GUID_STRLEN),
		AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION, "unique for non exist partition");
}

int main(int argc, char *argv[])
{
	struct vb2_kernel_params vb2_kp = {
		.kernel_buffer = kernel_buffer,
		.kernel_buffer_size = KERNEL_BUFFER_SIZE,
	};
	AvbOps *avb_ops;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <keys_dir>", argv[0]);
		return -1;
	}

	keys_dir = argv[1];

	setup_storage();

	/* Set up context */
	if (vb2api_init(workbuf, sizeof(workbuf), &vb2_ctx)) {
		printf("Failed to initialize workbuf.\n");
		return -1;
	}

	sd = vb2_get_sd(vb2_ctx);
	sd->kernel_version_secdata = KERNEL_VERSION_SECDATA;
	avb_ops = vboot_avb_ops_new(vb2_ctx, &vb2_kp, &gptdata, NULL, "_a");

	validate_vbmeta_public_key_tests(avb_ops);
	read_from_partition_tests(avb_ops);
	get_preload_partition_tests(avb_ops);
	read_rollback_tests(avb_ops);
	read_is_device_unlocked(avb_ops);
	get_unique_guid_for_partition_test(avb_ops);

	vboot_avb_ops_free(avb_ops);

	return gTestSuccess ? 0 : 255;
}
