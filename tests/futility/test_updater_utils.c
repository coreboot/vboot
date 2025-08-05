/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#define __USE_GNU

#include <stdlib.h>
#include "futility.h"
#include "updater.h"
#include "2struct.h"
#include "common/tests.h"

#include "updater_utils.c"

#define DATA_PATH "tests/futility/data_copy/"
#define IMAGE_MAIN DATA_PATH "image.bin"
#define ARCHIVE DATA_PATH "images.zip"
#define FILE_NONEXISTENT DATA_PATH "nonexistent"
#define FILE_READONLY DATA_PATH "read-only"

/* When a custom image needs to be created, it will be written to this file. It also acts as a
   temporary file. */
#define TARGET DATA_PATH "target"

enum unit_result {
	UNIT_FAIL = 0,
	UNIT_SUCCESS = 1
};

/* IMPORTANT! Every function that uses `ASSERT` has to implement `unit_cleanup` label. The
   function must also start with `UNIT_TEST_BEGIN` and end with `UNIT_TEST_RETURN` */

/* This should be called once at the beginning of any function that uses ASSERT. */
#define UNIT_TEST_BEGIN int __unit_test_return_value = UNIT_SUCCESS

/* This should be called once at the end of any function that uses ASSERT. */
#define UNIT_TEST_RETURN return __unit_test_return_value

/* If assertion fails, will set the resulf of the current unit test to UNIT_FAIL and go to
   `unit_cleanup`. To use this, `UNIT_TEST_BEGIN` has to be called at the beginning of the
   function. */
#define ASSERT(value)                                                                          \
	do {                                                                                   \
		if ((value) != UNIT_SUCCESS) {                                                 \
			TEST_EQ(0, 1, "Assertion failed: " #value);                            \
			__unit_test_return_value = UNIT_FAIL;                                  \
			goto unit_cleanup;                                                     \
		}                                                                              \
	} while (0)

static enum unit_result create_image_missing_fmap(void)
{
	UNIT_TEST_BEGIN;
	struct firmware_image image = {0};
	FmapAreaHeader *ah = NULL; /* Do not free. */

	ASSERT(load_firmware_image(&image, IMAGE_MAIN, NULL) == 0);
	ASSERT(image.fmap_header != NULL);
	ASSERT(fmap_find_by_name(image.data, image.size, image.fmap_header, FMAP_RO_FMAP,
				 &ah) != NULL);
	memset(image.data + ah->area_offset, 0, ah->area_size);

	ASSERT(vb2_write_file(TARGET, image.data, image.size) == VB2_SUCCESS);

unit_cleanup:
	free_firmware_image(&image);
	UNIT_TEST_RETURN;
}

static enum unit_result create_image_missing_ro_frid_in_fmap(void)
{
	UNIT_TEST_BEGIN;
	struct firmware_image image = {0};
	FmapAreaHeader *ah = NULL; /* Do not free. */

	ASSERT(load_firmware_image(&image, IMAGE_MAIN, NULL) == 0);
	ASSERT(image.fmap_header != NULL);
	ASSERT(fmap_find_by_name(image.data, image.size, image.fmap_header, FMAP_RO_FRID,
				 &ah) != NULL);
	ah->area_name[0] = '\0';

	ASSERT(vb2_write_file(TARGET, image.data, image.size) == VB2_SUCCESS);

unit_cleanup:
	free_firmware_image(&image);
	UNIT_TEST_RETURN;
}

static enum unit_result create_image_missing_rw_fwid_in_fmap(void)
{
	UNIT_TEST_BEGIN;
	struct firmware_image image = {0};
	FmapAreaHeader *ah = NULL; /* Do not free. */

	ASSERT(load_firmware_image(&image, IMAGE_MAIN, NULL) == 0);
	ASSERT(image.fmap_header != NULL);
	if (fmap_find_by_name(image.data, image.size, image.fmap_header, FMAP_RW_FWID_A, &ah) !=
	    NULL)
		ah->area_name[0] = '\0';
	if (fmap_find_by_name(image.data, image.size, image.fmap_header, FMAP_RW_FWID_B, &ah) !=
	    NULL)
		ah->area_name[0] = '\0';
	if (fmap_find_by_name(image.data, image.size, image.fmap_header, FMAP_RW_FWID, &ah) !=
	    NULL)
		ah->area_name[0] = '\0';

	ASSERT(vb2_write_file(TARGET, image.data, image.size) == VB2_SUCCESS);

unit_cleanup:
	free_firmware_image(&image);
	UNIT_TEST_RETURN;
}

static enum unit_result copy_image(const char *path)
{
	UNIT_TEST_BEGIN;
	uint8_t *ptr = NULL;
	uint32_t size;

	ASSERT(path != NULL);
	ASSERT(vb2_read_file(path, &ptr, &size) == VB2_SUCCESS);
	ASSERT(vb2_write_file(TARGET, ptr, size) == VB2_SUCCESS);

unit_cleanup:
	free(ptr);
	UNIT_TEST_RETURN;
}

static enum unit_result test_temp_file(void)
{
	UNIT_TEST_BEGIN;
	struct firmware_image image = {0};
	struct tempfile head = {0};
	const char *file = create_temp_file(&head); /* Do not free. */

	TEST_PTR_NEQ(file, NULL, "Create temp file");

	ASSERT(load_firmware_image(&image, IMAGE_MAIN, NULL) == 0);
	TEST_PTR_NEQ(get_firmware_image_temp_file(&image, &head), NULL,
		     "Get temp file for image");

unit_cleanup:
	remove_all_temp_files(&head);
	free_firmware_image(&image);
	UNIT_TEST_RETURN;
}

/* Both `load_firmware_image` and `parse_firmware_image` are tested here.  */
static enum unit_result test_load_firmware_image(void)
{
	UNIT_TEST_BEGIN;
	struct firmware_image image = {0};
	struct u_archive *archive = NULL;
	uint8_t *ref_ptr = NULL;
	uint32_t ref_size;

	ASSERT(vb2_read_file(IMAGE_MAIN, &ref_ptr, &ref_size) == VB2_SUCCESS);

	TEST_EQ(load_firmware_image(&image, IMAGE_MAIN, NULL), 0, "Load normal image");
	TEST_EQ(ref_size == image.size, 1, "Verifying size");
	TEST_EQ(memcmp(ref_ptr, image.data, ref_size), 0, "Verifying data");
	TEST_PTR_NEQ(image.fmap_header, NULL, "Verifying FMAP");
	check_firmware_versions(&image);
	free_firmware_image(&image);

	TEST_EQ(load_firmware_image(&image, NULL, NULL), IMAGE_READ_FAILURE,
		"Load NULL filename");
	free_firmware_image(&image);

	TEST_EQ(load_firmware_image(&image, "", NULL), IMAGE_READ_FAILURE,
		"Load empty filename");
	free_firmware_image(&image);

	TEST_EQ(load_firmware_image(&image, FILE_NONEXISTENT, NULL), IMAGE_READ_FAILURE,
		"Load invalid file");
	free_firmware_image(&image);

	image = (struct firmware_image){0};
	archive = archive_open(ARCHIVE);
	ASSERT(archive != NULL);

	TEST_EQ(load_firmware_image(&image, IMAGE_MAIN, archive), 0, "Load from archive");
	TEST_EQ(ref_size == image.size, 1, "Verifying size");
	TEST_EQ(memcmp(ref_ptr, image.data, ref_size), 0, "Verifying data");
	TEST_PTR_NEQ(image.fmap_header, NULL, "Verifying FMAP");
	check_firmware_versions(&image);
	free_firmware_image(&image);

	TEST_EQ(load_firmware_image(&image, FILE_NONEXISTENT, archive), IMAGE_READ_FAILURE,
		"Load invalid file from archive");
	free_firmware_image(&image);

unit_cleanup:
	archive_close(archive);
	free(ref_ptr);
	free_firmware_image(&image);
	UNIT_TEST_RETURN;
}

static enum unit_result test_parse_firmware_image(void)
{
	UNIT_TEST_BEGIN;
	struct firmware_image image = {0};

	memset(&image, 0, sizeof(image));
	ASSERT(vb2_read_file(IMAGE_MAIN, &image.data, &image.size) == VB2_SUCCESS);
	TEST_EQ(parse_firmware_image(&image), IMAGE_LOAD_SUCCESS,
		"Parse firmware image: valid");
	TEST_PTR_EQ(fmap_find(image.data, image.size), image.fmap_header, "Verifying FMAP");
	free_firmware_image(&image);
	image = (struct firmware_image){0};

	memset(&image, 0, sizeof(image));
	ASSERT(create_image_missing_fmap());
	ASSERT(vb2_read_file(TARGET, &image.data, &image.size) == VB2_SUCCESS);
	TEST_EQ(parse_firmware_image(&image), IMAGE_PARSE_FAILURE,
		"Parse firmware image: missing FMAP");
	free_firmware_image(&image);
	image = (struct firmware_image){0};

	memset(&image, 0, sizeof(image));
	ASSERT(create_image_missing_ro_frid_in_fmap());
	ASSERT(vb2_read_file(TARGET, &image.data, &image.size) == VB2_SUCCESS);
	TEST_EQ(parse_firmware_image(&image), IMAGE_PARSE_FAILURE,
		"Parse firmware image: missing RO_FRID");
	free_firmware_image(&image);
	image = (struct firmware_image){0};

	memset(&image, 0, sizeof(image));
	ASSERT(create_image_missing_rw_fwid_in_fmap());
	ASSERT(vb2_read_file(TARGET, &image.data, &image.size) == VB2_SUCCESS);
	TEST_EQ(parse_firmware_image(&image), IMAGE_PARSE_FAILURE,
		"Parse firmware image: missing RW_FWID");

unit_cleanup:
	free_firmware_image(&image);
	UNIT_TEST_RETURN;
}

static enum unit_result test_firmware_version(void)
{
	UNIT_TEST_BEGIN;
	struct firmware_image image = {0};
	FmapAreaHeader *ah = NULL; /* Do not free. */
	char *version = NULL;

	ASSERT(load_firmware_image(&image, IMAGE_MAIN, NULL) == 0);

	TEST_NEQ(load_firmware_version(&image, NULL, &version), 0,
		 "Load firmware version: NULL section");
	TEST_STR_EQ(version, "", "Verifying");
	free(version);
	version = NULL;

	TEST_NEQ(load_firmware_version(&image, "<invalid section>", &version), 0,
		 "Load firmware version: invalid section");
	TEST_STR_EQ(version, "", "Verifying");
	free(version);
	version = NULL;

	TEST_EQ(load_firmware_version(&image, FMAP_RO_FRID, &version), 0,
		"Load firmware version: valid");
	TEST_STR_NEQ(version, "", "Verifying");
	free(version);
	version = NULL;

	/* It would be difficult to overwrite the cbfs file without cbfstool (which is not
	   available on some boards...), so we just set the entire section to zero. */
	ASSERT(fmap_find_by_name(image.data, image.size, image.fmap_header, FMAP_RW_FW_MAIN_A,
				 &ah) != NULL);
	memset(image.data + ah->area_offset, 0, ah->area_size);
	version = load_ecrw_version(&image, TARGET, FMAP_RW_FW_MAIN_A);
	TEST_STR_EQ(version, "", "Load ECRW version: invalid");

unit_cleanup:
	free(version);
	free_firmware_image(&image);
	UNIT_TEST_RETURN;
}

static enum unit_result test_reload_firmware_image(void)
{
	UNIT_TEST_BEGIN;
	struct firmware_image image = {0};

	ASSERT(load_firmware_image(&image, IMAGE_MAIN, NULL) == 0);
	TEST_EQ(reload_firmware_image(IMAGE_MAIN, &image), 0, "Reload image");
	free_firmware_image(&image);

	TEST_EQ(reload_firmware_image(IMAGE_MAIN, &image), 0, "Reload unloaded image");

unit_cleanup:
	free_firmware_image(&image);
	UNIT_TEST_RETURN;
}

static enum unit_result test_system_firmware(void)
{
	UNIT_TEST_BEGIN;
	struct updater_config_arguments args = {0};
	struct updater_config *cfg = updater_new_config();
	const char *programmer = NULL; /* Do not free. */
	const char *regions[1] = {FMAP_RW_LEGACY};
	uint8_t *ptr = NULL; /* Do not free. */
	int value;
	uint64_t offset;

	TEST_PTR_NEQ(cfg, NULL, "Create updater config");

	args.use_flash = 1;
	args.image = (char *)IMAGE_MAIN;
	copy_image(IMAGE_MAIN);
	args.emulation = (char *)TARGET;

	TEST_EQ(updater_setup_config(cfg, &args), 0, "Set up config");
	cfg->quirks[QUIRK_EXTRA_RETRIES].value = 2;

	programmer = cfg->image_current.programmer;
	cfg->image_current.programmer = "<invalid programmer>";
	TEST_NEQ(load_system_firmware(cfg, &cfg->image_current), 0, "Invalid programmer");
	cfg->image_current.programmer = programmer;

	TEST_EQ(write_system_firmware(cfg, &cfg->image, NULL, 0), 0,
		"Write system firmware (entire)");
	TEST_EQ(load_system_firmware(cfg, &cfg->image_current), 0, "Load system firmware");
	TEST_TRUE(cfg->image.size == cfg->image_current.size, "Verifying size");
	TEST_EQ(memcmp(cfg->image.data, cfg->image_current.data, cfg->image.size), 0,
		"Verifying contents");

	/* Change one byte to verify that the data gets written. */
	ptr = fmap_find_by_name(cfg->image.data, cfg->image.size, cfg->image.fmap_header,
				FMAP_RW_LEGACY, NULL);
	ptr[0] ^= 255; /* This will change the first byte to a different value. */
	value = ptr[0];
	offset = ptr - cfg->image.data;
	TEST_EQ(write_system_firmware(cfg, &cfg->image, regions, ARRAY_SIZE(regions)), 0,
		"Write system firmware (partial)");
	ASSERT(load_system_firmware(cfg, &cfg->image_current) == 0);
	TEST_EQ(cfg->image_current.data[offset], value, "Verifying written region");

	regions[0] = "<invalid region>";
	TEST_NEQ(write_system_firmware(cfg, &cfg->image, regions, ARRAY_SIZE(regions)), 0,
		 "Write invalid region");

unit_cleanup:
	updater_delete_config(cfg);
	UNIT_TEST_RETURN;
}

static enum unit_result test_programmer(void)
{
	UNIT_TEST_BEGIN;
	struct firmware_image image1 = {0}, image2 = {0};
	ASSERT(load_firmware_image(&image1, IMAGE_MAIN, NULL) == 0);
	ASSERT(load_firmware_image(&image2, IMAGE_MAIN, NULL) == 0);

	image1.programmer = image2.programmer = "<same programmer>";
	TEST_EQ(is_the_same_programmer(&image1, &image2), 1, "Test programmer: same address");

	image2.programmer = strdup(image1.programmer);
	TEST_EQ(is_the_same_programmer(&image1, &image2), 1, "Test programmer: same value");

	image1.programmer = "<another programmer>";
	TEST_EQ(is_the_same_programmer(&image1, &image2), 0, "Test programmer: different");

	image1.programmer = NULL;
	TEST_EQ(is_the_same_programmer(&image1, &image2), 0,
		"Test programmer: different (NULL)");

	free((char *)image2.programmer);
	image2.programmer = NULL;
	TEST_EQ(is_the_same_programmer(&image1, &image2), 1, "Test programmer: same (NULL)");

unit_cleanup:
	free_firmware_image(&image1);
	free_firmware_image(&image2);
	UNIT_TEST_RETURN;
}

static enum unit_result test_firmware_sections(void)
{
	UNIT_TEST_BEGIN;
	struct firmware_image image = {0};
	struct firmware_section section = {0};

	ASSERT(load_firmware_image(&image, IMAGE_MAIN, NULL) == 0);

	TEST_EQ(find_firmware_section(&section, &image, "RO_FRID"), 0, "Find firmware section");
	TEST_EQ(firmware_section_exists(&image, "RO_FRID"), 1, "Firmware section exists");

	memset(image.data, 0, image.size);

	TEST_NEQ(find_firmware_section(&section, &image, "RO_FRID"), 0,
		 "Find missing firmware section");
	TEST_NEQ(firmware_section_exists(&image, "RO_FRID"), 1,
		 "Firmware section doesn't exist");

unit_cleanup:
	free_firmware_image(&image);
	UNIT_TEST_RETURN;
}

static enum unit_result test_preserve_firmware_section(void)
{
	UNIT_TEST_BEGIN;
	struct firmware_image image_from = {0}, image_to = {0};
	FmapAreaHeader *ah = NULL; /* Do not free. */
	uint8_t *ptr = NULL;	   /* Do not free. */
	uint8_t *data = NULL, byte;

	ASSERT(load_firmware_image(&image_from, IMAGE_MAIN, NULL) == 0);
	ASSERT(load_firmware_image(&image_to, IMAGE_MAIN, NULL) == 0);

	TEST_EQ(preserve_firmware_section(&image_from, &image_to, FMAP_RW_LEGACY), 0,
		"Preserve section");
	TEST_EQ(memcmp(image_from.data, image_to.data, image_from.size), 0,
		"Verifying section");

	ptr = fmap_find_by_name(image_to.data, image_to.size, image_to.fmap_header,
				FMAP_RW_LEGACY, &ah);

	strcpy(ah->area_name, "<invalid name>");
	TEST_NEQ(preserve_firmware_section(&image_from, &image_to, FMAP_RW_LEGACY), 0,
		 "Preserve invalid section");

	/* Modify last byte to check that it doesn't get written because
	   preserve_firmware_section will truncate section. */
	strcpy(ah->area_name, FMAP_RW_LEGACY);
	byte = *(ptr + ah->area_size - 1); /* Last byte. */
	/* A different byte to write. Should not be written. */
	image_from.data[ah->area_offset + ah->area_size - 1] = 255 ^ byte;
	ah->area_size--;
	TEST_EQ(preserve_firmware_section(&image_from, &image_to, FMAP_RW_LEGACY), 0,
		"Preserve section (truncated)");
	TEST_EQ(*(ptr + ah->area_size), byte, "Verifying truncated section");
	ah->area_size++;

	ASSERT(reload_firmware_image(IMAGE_MAIN, &image_to) == 0);
	ptr = fmap_find_by_name(image_to.data, image_to.size, image_to.fmap_header,
				FMAP_RW_LEGACY, &ah);
	data = (uint8_t *)malloc(ah->area_size);
	memcpy(data, ptr, ah->area_size);
	for (int i = 0; i < ah->area_size; i++)
		data[i] ^= 255; /* Some different data. */

	TEST_NEQ(overwrite_section(&image_to, "<invalid section>", 0, ah->area_size, data), 0,
		 "Overwrite missing section");

	TEST_NEQ(overwrite_section(&image_to, FMAP_RW_LEGACY, 0, ah->area_size + 1, data), 0,
		 "Overwrite section and beyond");

	TEST_EQ(overwrite_section(&image_to, FMAP_RW_LEGACY, 0, ah->area_size, ptr), 0,
		"Overwrite section with same data");

	TEST_EQ(overwrite_section(&image_to, FMAP_RW_LEGACY, 0, ah->area_size, data), 0,
		"Overwrite section");
	TEST_EQ(memcmp(ptr, data, ah->area_size), 0, "Verifying section");

unit_cleanup:
	free(data);
	free_firmware_image(&image_from);
	free_firmware_image(&image_to);
	UNIT_TEST_RETURN;
}

static enum unit_result test_gbb(void)
{
	UNIT_TEST_BEGIN;
	struct firmware_image image = {0};
	FmapAreaHeader *ah = NULL; /* Do not free */
	uint8_t *ptr = NULL;	   /* Do not free */

	ASSERT(load_firmware_image(&image, IMAGE_MAIN, NULL) == 0);

	TEST_PTR_NEQ(get_firmware_rootkey_hash(&image), NULL, "Get firmware rootkey hash");
	TEST_PTR_NEQ(find_gbb(&image), NULL, "Find GBB");

	ptr = fmap_find_by_name(image.data, image.size, image.fmap_header, "GBB", &ah);

	strcpy(ah->area_name, "<invalid name>");
	TEST_PTR_EQ(get_firmware_rootkey_hash(&image), NULL,
		    "Get firmware rootkey hash from missing GBB");
	TEST_PTR_EQ(find_gbb(&image), NULL, "Find missing GBB");

	strcpy(ah->area_name, "GBB");
	memset(ptr, 0, ah->area_size);
	TEST_PTR_EQ(get_firmware_rootkey_hash(&image), NULL,
		    "Get firmware rootkey hash from invalid GBB");
	TEST_PTR_EQ(find_gbb(&image), NULL, "Find invalid GBB");

unit_cleanup:
	free_firmware_image(&image);
	UNIT_TEST_RETURN;
}

static enum unit_result test_misc(void)
{
	UNIT_TEST_BEGIN;
	char message_buf[4096];
	char *s = NULL, *res_shell = NULL;
	const char *pattern = NULL, *res = NULL; /* Do not free. */
	struct updater_config_arguments args = {0};
	struct updater_config *cfg = NULL;
	struct dut_property *prop = NULL; /* Do not free. */
	char *model = NULL;

	s = strdup("hello \n \t ");
	pattern = NULL;
	res = "hello";
	strip_string(s, pattern);
	TEST_EQ(strcmp(s, res), 0, "Strip: NULL pattern");
	free(s);

	s = strdup("helloABC");
	pattern = "ABC";
	res = "hello";
	strip_string(s, pattern);
	TEST_EQ(strcmp(s, res), 0, "Strip: entire");
	free(s);

	s = strdup("helloABC");
	pattern = "AC";
	res = "helloAB";
	strip_string(s, pattern);
	TEST_EQ(strcmp(s, res), 0, "Strip: partial");
	free(s);

	s = strdup("helloABC");
	pattern = "B";
	res = "helloABC";
	strip_string(s, pattern);
	TEST_EQ(strcmp(s, res), 0, "Strip: no effect");
	free(s);

	TEST_NEQ(save_file_from_stdin(FILE_READONLY), 0, "Save file from stdin: readonly");

	cfg = updater_new_config();
	s = NULL;
	ASSERT(cfg != NULL);
	ASSERT(updater_setup_config(cfg, &args) == 0);
	ASSERT(load_firmware_image(&cfg->image, IMAGE_MAIN, NULL) == 0);

	/* Test uninitialized and initialized. */
	prop = &cfg->dut_properties[DUT_PROP_WP_HW];
	prop->initialized = 0;
	prop = &cfg->dut_properties[DUT_PROP_WP_SW_AP];
	prop->initialized = 1;
	prop->value = 0;
	TEST_EQ(is_ap_write_protection_enabled(cfg), 0,
		"Check AP write protection HW=uninitialized SW=0");

	/* Test all initialized cases. */
	for (int mask = 0; mask < 4; mask++) {
		prop = &cfg->dut_properties[DUT_PROP_WP_HW];
		prop->initialized = 1;
		prop->value = mask & 1;
		prop = &cfg->dut_properties[DUT_PROP_WP_SW_AP];
		prop->initialized = 1;
		prop->value = !!(mask & 2);
		snprintf(message_buf, sizeof(message_buf),
			 "Check AP write protection HW=%d, SW=%d", mask & 1, !!(mask & 2));
		TEST_EQ(is_ap_write_protection_enabled(cfg), mask == 3, message_buf);
	}

	/* Test uninitialized and initialized. */
	prop = &cfg->dut_properties[DUT_PROP_WP_HW];
	prop->initialized = 0;
	prop = &cfg->dut_properties[DUT_PROP_WP_SW_EC];
	prop->initialized = 1;
	prop->value = 0;
	TEST_EQ(is_ec_write_protection_enabled(cfg), 0,
		"Check EC write protection HW=uninitialized SW=0");

	/* Test all initialized cases. */
	for (int mask = 0; mask < 4; mask++) {
		prop = &cfg->dut_properties[DUT_PROP_WP_HW];
		prop->initialized = 1;
		prop->value = mask & 1;
		prop = &cfg->dut_properties[DUT_PROP_WP_SW_EC];
		prop->initialized = 1;
		prop->value = !!(mask & 2);
		snprintf(message_buf, sizeof(message_buf),
			 "Check EC write protection HW=%d, SW=%d", mask & 1, !!(mask & 2));
		TEST_EQ(is_ec_write_protection_enabled(cfg), mask == 3, message_buf);
	}

	updater_delete_config(cfg);
	cfg = NULL;

	res_shell = host_shell("echo test");
	TEST_STR_EQ(res_shell, "test", "Host shell: echo");
	free(res_shell);

	res_shell = host_shell(")certainly_not_a_valid_thing");
	TEST_STR_EQ(res_shell, "", "Host shell: invalid command");
	free(res_shell);

	model = get_model_from_frid("some.frid");
	TEST_STR_EQ(model, "some", "Get model from frid: valid");
	free(model);

	model = get_model_from_frid("somefrid");
	TEST_PTR_EQ(model, NULL, "Get model from frid: no dot");

	res_shell = NULL;
	model = NULL;

unit_cleanup:
	free(model);
	free(res_shell);
	if (cfg)
		updater_delete_config(cfg);
	UNIT_TEST_RETURN;
}

int main(int argc, char *argv[])
{
	remove(FILE_NONEXISTENT);

	test_temp_file();
	test_load_firmware_image();
	test_parse_firmware_image();
	test_firmware_version();
	test_reload_firmware_image();
	test_system_firmware();
	test_programmer();
	test_firmware_sections();
	test_preserve_firmware_section();
	test_gbb();
	test_misc();

	return !gTestSuccess;
}
