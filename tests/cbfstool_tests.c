/* Copyright 2024 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "2return_codes.h"
#include "cbfstool.h"
#include "common/tests.h"

#define IMAGE "tests/futility/data/bios_coachz_cbfs.bin"

static void cbfstool_get_config_value_tests(void)
{
	char *value;
	vb2_error_t rv;

	/* File not found */
	value = NULL;
	rv = cbfstool_get_config_value("no_such_file", NULL,
				       "CONFIG_CHROMEOS", &value);
	TEST_FAIL(rv, "file not found");

	/* Config not found */
	value = NULL;
	rv = cbfstool_get_config_value(IMAGE, NULL,
				       "CONFIG_NOT_FOUND", &value);
	TEST_SUCC(rv, "config not found");
	TEST_PTR_EQ(value, NULL, "  value is null");

	/* Config CHROMEOS (bool) */
	value = NULL;
	rv = cbfstool_get_config_value(IMAGE, NULL,
				       "CONFIG_CHROMEOS", &value);
	TEST_SUCC(rv, "get CHROMEOS value");
	TEST_PTR_NEQ(value, NULL, "  value not null");
	TEST_EQ(strcmp(value, "y"), 0, "  value is y");

	/* Config CHROMEOS (bool) from FW_MAIN_A */
	value = NULL;
	rv = cbfstool_get_config_value(IMAGE, "FW_MAIN_A",
				       "CONFIG_CHROMEOS", &value);
	TEST_SUCC(rv, "get CHROMEOS value from FW_MAIN_A");
	TEST_PTR_NEQ(value, NULL, "  value not null");
	TEST_EQ(strcmp(value, "y"), 0, "  value is y");

	/* Config MAINBOARD_PART_NUMBER (str) */
	value = NULL;
	rv = cbfstool_get_config_value(IMAGE, NULL,
				       "CONFIG_MAINBOARD_PART_NUMBER", &value);
	TEST_SUCC(rv, "get MAINBOARD_PART_NUMBER value");
	TEST_PTR_NEQ(value, NULL, "  value not null");
	TEST_EQ(strcmp(value, "\"Coachz\""), 0, "  value is \"Coachz\"");
}

int main(int argc, char *argv[])
{
	cbfstool_get_config_value_tests();

	return gTestSuccess ? 0 : 255;
}
