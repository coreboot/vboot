/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "unit_tests.h"
#include "updater.h"
#include "cgptlib_internal.h"
#include "file_type.h"
#include "futility_options.h"
#include "host_misc.h"
#include <sys/mman.h>

#define IMAGE_MAIN	 GET_WORK_COPY_TEST_DATA_FILE_PATH("image.bin")
#define FILE_TEMP	 GET_WORK_COPY_TEST_DATA_FILE_PATH("file-temp")
#define FILE_SMALL	 GET_WORK_COPY_TEST_DATA_FILE_PATH("file-small")
#define FILE_NONEXISTENT GET_WORK_COPY_TEST_DATA_FILE_PATH("nonexistent")
#define FILE_READONLY	 GET_WORK_COPY_TEST_DATA_FILE_PATH("read-only")

const char small_data[] = "small";
#define FILE_SMALL_SIZE (ARRAY_SIZE(small_data) - 1)

static enum unit_result prepare_test_data(void)
{
	UNIT_TEST_BEGIN;

	UNIT_ASSERT(system("rm -rf " WORK_COPY_TEST_DATA_DIR) == 0);
	UNIT_ASSERT(system("mkdir -p " WORK_COPY_TEST_DATA_DIR) == 0);

	UNIT_ASSERT(futil_copy_file(GET_SOURCE_TEST_DATA_FILE_PATH("image-steelix.bin"),
				    IMAGE_MAIN) != -1);
	UNIT_ASSERT(vb2_write_file(FILE_SMALL, small_data, FILE_SMALL_SIZE) == VB2_SUCCESS);
	remove(FILE_NONEXISTENT);
	UNIT_ASSERT(system("touch " FILE_READONLY) == 0);
	UNIT_ASSERT(system("chmod 444 " FILE_READONLY) == 0);

unit_cleanup:
	UNIT_TEST_RETURN;
}

static enum unit_result test_gbb(void)
{
	UNIT_TEST_BEGIN;
	struct firmware_image image = {0};
	FmapAreaHeader *ah = NULL;
	uint8_t *ptr = NULL;
	uint32_t maxlen;
	struct vb2_gbb_header *gbb, good_gbb = {0};
	char *str = NULL;

	UNIT_ASSERT(load_firmware_image(&image, IMAGE_MAIN, NULL) == 0);
	ptr = fmap_find_by_name(image.data, image.size, image.fmap_header, "GBB", &ah);
	UNIT_ASSERT(ptr != NULL);
	gbb = (struct vb2_gbb_header *)ptr;
	good_gbb = *gbb;

	TEST_EQ(ft_recognize_gbb(ptr, ah->area_size), FILE_TYPE_GBB,
		"File type recognize GBB: correct");
	TEST_EQ(futil_valid_gbb_header(gbb, ah->area_size, &maxlen), 1,
		"Futil valid GBB header: correct");

	TEST_EQ(ft_recognize_gbb(ptr, sizeof(struct vb2_gbb_header) - 1), FILE_TYPE_UNKNOWN,
		"File type recognize GBB: too small");
	TEST_EQ(futil_valid_gbb_header(gbb, gbb->header_size - 1, NULL), 0,
		"Futil valid GBB header: too small");

	memset(gbb->signature, 0, sizeof(gbb->signature));
	TEST_EQ(ft_recognize_gbb(ptr, ah->area_size), FILE_TYPE_UNKNOWN,
		"File type recognize GBB: invalid signature");
	TEST_EQ(futil_valid_gbb_header(gbb, ah->area_size, NULL), 0,
		"Futil valid GBB header: invalid signature");

	*gbb = good_gbb;
	gbb->major_version = UINT16_MAX;
	TEST_EQ(ft_recognize_gbb(ptr, ah->area_size), FILE_TYPE_UNKNOWN,
		"File type recognize GBB: invalid major version");
	TEST_EQ(futil_valid_gbb_header(gbb, ah->area_size, NULL), 0,
		"Futil valid GBB header: invalid major version");

	*gbb = good_gbb;
	gbb->header_size = ah->area_size + 1;
	TEST_EQ(futil_valid_gbb_header(gbb, ah->area_size, NULL), 0,
		"Futil valid GBB header: invalid header_size");

	*gbb = good_gbb;
	gbb->hwid_offset = EXPECTED_VB2_GBB_HEADER_SIZE - 1;
	TEST_EQ(futil_valid_gbb_header(gbb, ah->area_size, NULL), 0,
		"Futil valid GBB header: invalid hwid_offset");

	*gbb = good_gbb;
	gbb->hwid_offset = ah->area_size + 1;
	gbb->hwid_size = 0;
	TEST_EQ(futil_valid_gbb_header(gbb, ah->area_size, NULL), 0,
		"Futil valid GBB header: invalid hwid_offset or hwid_size");

	*gbb = good_gbb;
	gbb->rootkey_offset = ah->area_size + 1;
	gbb->rootkey_size = 0;
	TEST_EQ(futil_valid_gbb_header(gbb, ah->area_size, NULL), 0,
		"Futil valid GBB header: invalid rootkey_offset or rootkey_size");

	*gbb = good_gbb;
	gbb->bmpfv_offset = ah->area_size + 1;
	gbb->bmpfv_size = 0;
	TEST_EQ(futil_valid_gbb_header(gbb, ah->area_size, NULL), 0,
		"Futil valid GBB header: invalid bmpfv_offset or bmpfv_size");

	*gbb = good_gbb;
	gbb->recovery_key_offset = EXPECTED_VB2_GBB_HEADER_SIZE - 1;
	TEST_EQ(futil_valid_gbb_header(gbb, ah->area_size, NULL), 0,
		"Futil valid GBB header: invalid recovery_key_offset");

	*gbb = good_gbb;
	gbb->recovery_key_size = ah->area_size + 1;
	gbb->recovery_key_offset = EXPECTED_VB2_GBB_HEADER_SIZE;
	TEST_EQ(futil_valid_gbb_header(gbb, ah->area_size, NULL), 0,
		"Futil valid GBB header: invalid recovery_key_offset or recovery_key_offset");

	*gbb = good_gbb;
	str = calloc(1, gbb->hwid_size + 2);
	UNIT_ASSERT(str != NULL);
	memset(str, 'X', gbb->hwid_size + 1);
	TEST_EQ(futil_set_gbb_hwid(gbb, str), -1, "Futil set GBB HWID: too big");
	free(str);

	*gbb = good_gbb;
	str = (char *)"M";
	TEST_EQ(futil_set_gbb_hwid(gbb, str), 0, "Futil set GBB HWID: valid");
	TEST_EQ(strncmp((char *)gbb + gbb->hwid_offset, str, 2), 0, "Verifying");

	*gbb = good_gbb;
	gbb->minor_version = 1;
	str = (char *)"N";
	TEST_EQ(futil_set_gbb_hwid(gbb, str), 0, "Futil set GBB HWID: minor < 2");
	TEST_EQ(strncmp((char *)gbb + gbb->hwid_offset, str, 2), 0, "Verifying");

	str = NULL;
unit_cleanup:
	free_firmware_image(&image);
	UNIT_TEST_RETURN;
}

static enum unit_result test_futil_file_helpers(void)
{
	UNIT_TEST_BEGIN;
	int fd = -1;

	TEST_EQ(futil_copy_file(FILE_SMALL, FILE_TEMP), FILE_SMALL_SIZE,
		"Futil copy file: valid");
	TEST_NEQ(futil_copy_file(FILE_NONEXISTENT, FILE_TEMP), 0,
		 "Futil copy file: nonexistent");
	TEST_NEQ(futil_copy_file(FILE_TEMP, FILE_READONLY), 0, "Futil copy file: invalid");

	TEST_EQ(futil_open_file(FILE_TEMP, &fd, FILE_RW), FILE_ERR_NONE, "Futil open file: rw");
	TEST_TRUE(fd >= 0, "Verifying fd");
	TEST_EQ(futil_close_file(fd), FILE_ERR_NONE, "Futil close file: rw");
	TEST_EQ(futil_open_file(FILE_NONEXISTENT, &fd, FILE_RW), FILE_ERR_OPEN,
		"Futil open file: rw nonexistent");

	fd = -1;
	TEST_EQ(futil_open_file(FILE_TEMP, &fd, FILE_RO), FILE_ERR_NONE, "Futil open file: ro");
	TEST_TRUE(fd >= 0, "Verifying fd");
	TEST_EQ(futil_close_file(fd), FILE_ERR_NONE, "Futil close file: ro");
	TEST_EQ(futil_open_file(FILE_NONEXISTENT, &fd, FILE_RO), FILE_ERR_OPEN,
		"Futil open file: ro nonexistent");

	fd = -1;
	UNIT_ASSERT(futil_open_file(FILE_TEMP, &fd, FILE_RW) == FILE_ERR_NONE);
	TEST_TRUE(fd >= 0, "Verifying fd");
	UNIT_ASSERT(futil_close_file(fd) == FILE_ERR_NONE);
	TEST_EQ(futil_close_file(fd), FILE_ERR_CLOSE, "Futil close file: invalid");

unit_cleanup:
	UNIT_TEST_RETURN;
}

static enum unit_result test_files_mmap(void)
{
	UNIT_TEST_BEGIN;
	int fd = -1;
	uint8_t *data = NULL;
	uint32_t size = 0;

	TEST_EQ(futil_map_file(-1, FILE_RO, &data, &size), FILE_ERR_STAT,
		"Futil map file: invalid fd");

	fd = -1;
	data = NULL;
	size = 0;
	UNIT_ASSERT(futil_open_file(FILE_TEMP, &fd, FILE_RO) == FILE_ERR_NONE);
	TEST_TRUE(fd >= 0, "Verifying fd");
	TEST_EQ(futil_map_file(fd, FILE_RO, &data, &size), FILE_ERR_NONE, "Futil map file");
	TEST_EQ(futil_unmap_file(fd, FILE_RO, data, size), FILE_ERR_NONE, "Futil unmap file");
	UNIT_ASSERT(futil_close_file(fd) == FILE_ERR_NONE);

	fd = -1;
	data = NULL;
	size = 0;
	TEST_NEQ(futil_open_and_map_file(FILE_NONEXISTENT, &fd, FILE_RO, &data, &size),
		 FILE_ERR_NONE, "Futil open and map file: nonexistent");

	fd = -1;
	data = NULL;
	size = 0;
	TEST_EQ(futil_open_and_map_file(FILE_TEMP, &fd, FILE_RO, &data, &size), FILE_ERR_NONE,
		"Futil open and map file");
	TEST_TRUE(fd >= 0, "Verifying fd");
	TEST_EQ(futil_unmap_and_close_file(fd, FILE_RO, data, size), FILE_ERR_NONE,
		"Futil unmap and close file");
	TEST_NEQ(futil_unmap_and_close_file(fd, FILE_RO, data, size), FILE_ERR_NONE,
		 "Futil unmap and close file: invalid fd");

unit_cleanup:
	UNIT_TEST_RETURN;
}

static enum unit_result test_misc(void)
{
	UNIT_TEST_BEGIN;
	size_t len = 4096;
	uint8_t *ptr = malloc(4096);
	GptHeader *h = (GptHeader *)(ptr + 512);
	uint8_t *data = (uint8_t *)strdup("test");

	UNIT_ASSERT(ptr != NULL && data != NULL);

	/* Pretend we have a valid GPT. */
	memcpy(h->signature, GPT_HEADER_SIGNATURE2, GPT_HEADER_SIGNATURE_SIZE);
	h->revision = GPT_HEADER_REVISION;
	h->size = MIN_SIZE_OF_HEADER + 1;
	h->header_crc32 = HeaderCrc(h);

	TEST_EQ(ft_recognize_gpt(ptr, len), FILE_TYPE_CHROMIUMOS_DISK,
		"File type recognize GPT: valid");

	memcpy(h->signature, "12345678", GPT_HEADER_SIGNATURE_SIZE);
	TEST_EQ(ft_recognize_gpt(ptr, len), FILE_TYPE_UNKNOWN,
		"File type recognize GPT: invalid signature");
	memcpy(h->signature, GPT_HEADER_SIGNATURE2, GPT_HEADER_SIGNATURE_SIZE);

	h->revision = ~GPT_HEADER_REVISION;
	TEST_EQ(ft_recognize_gpt(ptr, len), FILE_TYPE_UNKNOWN,
		"File type recognize GPT: invalid revision");
	h->revision = GPT_HEADER_REVISION;

	h->size = MAX_SIZE_OF_HEADER + 1;
	TEST_EQ(ft_recognize_gpt(ptr, len), FILE_TYPE_UNKNOWN,
		"File type recognize GPT: invalid size");
	h->size = MIN_SIZE_OF_HEADER + 1;

	h->header_crc32 = ~h->header_crc32; /* To change the checksum. */
	TEST_EQ(ft_recognize_gpt(ptr, len), FILE_TYPE_UNKNOWN,
		"File type recognize GPT: invalid crc32");

	len = strlen((char *)data);

	TEST_NEQ(write_to_file("test", FILE_READONLY, data, len), 0,
		 "Write to file: invalid file");
	TEST_EQ(write_to_file("test", FILE_TEMP, data, 0), 0, "Write to file: zero bytes");
	TEST_EQ(write_to_file("test", FILE_TEMP, data, len), 0, "Write to file: valid");

unit_cleanup:
	free(data);
	free(ptr);
	UNIT_TEST_RETURN;
}

int main(int argc, char *argv[])
{
	if (prepare_test_data() == UNIT_FAIL) {
		ERROR("Failed to prepare data.\n");
		return 1;
	}

	test_gbb();
	test_futil_file_helpers();
	test_files_mmap();
	test_misc();

	return !gTestSuccess;
}
