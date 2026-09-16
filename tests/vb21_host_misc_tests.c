/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for host misc library vboot2 functions
 */

#include <stdio.h>
#include <unistd.h>

#include "2common.h"
#include "2sysincludes.h"
#include "common/tests.h"
#include "host_common.h"
#include "host_common21.h"
#include "host_misc.h"

static void misc_tests(void)
{
	TEST_EQ(roundup32(0), 0, "roundup32(0)");
	TEST_EQ(roundup32(15), 16, "roundup32(15)");
	TEST_EQ(roundup32(16), 16, "roundup32(16)");

	TEST_EQ(vb2_desc_size(NULL), 0, "desc size null");
	TEST_EQ(vb2_desc_size(""), 0, "desc size empty");
	TEST_EQ(vb2_desc_size("foo"), 4, "desc size 'foo'");
	TEST_EQ(vb2_desc_size("foob"), 8, "desc size 'foob'");
}

static void property_string_tests(void)
{
	TEST_FALSE(is_valid_property_string(NULL), "is_valid_property_string(NULL)");
	TEST_TRUE(is_valid_property_string(""), "is_valid_property_string(empty)");
	TEST_TRUE(is_valid_property_string("Google_Corsola.15194.0.0"),
		  "is_valid_property_string(valid FWID)");
	TEST_TRUE(is_valid_property_string("KRANE C2A-B3C-D4E"),
		  "is_valid_property_string(valid HWID)");
	TEST_TRUE(is_valid_property_string("normal"),
		  "is_valid_property_string(valid mainfw_type)");

	/* Forbidden characters */
	TEST_FALSE(is_valid_property_string("foo\nbar"),
		   "is_valid_property_string(newline)");
	TEST_FALSE(is_valid_property_string("foo\rbar"),
		   "is_valid_property_string(carriage return)");
	TEST_FALSE(is_valid_property_string("foo\tbar"),
		   "is_valid_property_string(tab)");
	TEST_FALSE(is_valid_property_string("foo=bar"),
		   "is_valid_property_string('=')");
	TEST_FALSE(is_valid_property_string("foo\\bar"),
		   "is_valid_property_string('\\')");
	TEST_FALSE(is_valid_property_string("foo'bar"),
		   "is_valid_property_string('\'')");
	TEST_FALSE(is_valid_property_string("foo\"bar"),
		   "is_valid_property_string('\"')");

	/* Non-ASCII and control characters */
	TEST_FALSE(is_valid_property_string("foo\037bar"),
		   "is_valid_property_string(control char 0x1f)");
	TEST_FALSE(is_valid_property_string("foo\177bar"),
		   "is_valid_property_string(DEL 0x7f)");
	TEST_FALSE(is_valid_property_string("foo\200bar"),
		   "is_valid_property_string(non-ASCII 0x80)");
}

static void file_tests(const char *temp_dir)
{
	char *testfile;
	const uint8_t test_data[] = "Some test data";
	uint8_t *read_data;
	uint32_t read_size;

	uint8_t cbuf[sizeof(struct vb21_struct_common) + 12];
	struct vb21_struct_common *c = (struct vb21_struct_common *)cbuf;

	xasprintf(&testfile, "%s/file_tests.dat", temp_dir);

	unlink(testfile);

	TEST_EQ(vb2_read_file(testfile, &read_data, &read_size),
		VB2_ERROR_READ_FILE_OPEN, "vb2_read_file() missing");
	TEST_EQ(vb2_write_file("no/such/dir", test_data, sizeof(test_data)),
		VB2_ERROR_WRITE_FILE_OPEN, "vb2_write_file() open");

	TEST_SUCC(vb2_write_file(testfile, test_data, sizeof(test_data)),
		  "vb2_write_file() good");
	TEST_SUCC(vb2_read_file(testfile, &read_data, &read_size),
		  "vb2_read_file() good");
	TEST_EQ(read_size, sizeof(test_data), "  data size");
	TEST_EQ(memcmp(read_data, test_data, read_size), 0, "  data");
	free(read_data);
	unlink(testfile);

	memset(cbuf, 0, sizeof(cbuf));
	c->fixed_size = sizeof(*c);
	c->total_size = sizeof(cbuf);
	c->magic = 0x1234;
	cbuf[sizeof(cbuf) - 1] = 0xed;  /* Some non-zero data at the end */
	TEST_SUCC(vb21_write_object(testfile, c), "vb2_write_object() good");
	TEST_SUCC(vb2_read_file(testfile, &read_data, &read_size),
		  "vb2_read_file() object");
	TEST_EQ(read_size, c->total_size, "  data size");
	/* Compare the entire buffer, including the non-zero data at the end */
	TEST_EQ(memcmp(read_data, c, read_size), 0, "  data");
	free(read_data);
	unlink(testfile);
}

int main(int argc, char* argv[])
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <temp_dir>\n", argv[0]);
		return -1;
	}
	const char *temp_dir = argv[1];

	misc_tests();
	property_string_tests();
	file_tests(temp_dir);

	return gTestSuccess ? 0 : 255;
}
