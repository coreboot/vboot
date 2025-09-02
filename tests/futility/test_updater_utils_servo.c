/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "unit_tests.h"
#include "updater_utils.h"

enum {
	SHELL_SHOW_DEFAULT = 0,
	SHELL_SHOW_SERVO_V2,
	SHELL_SHOW_SERVO_MICRO,
	SHELL_SHOW_CCD_CR50,
	SHELL_SHOW_CCD_GSC,
	SHELL_SHOW_CCD_TI50,
	SHELL_SHOW_C2D2,
	SHELL_SHOW_UNKNOWN,
	SHELL_SHOW_INVALID,
	SHELL_SHOW_EMPTY,
	SHELL_SHOW_SERIAL_NUMBER,
};

static int host_shell_show;

/* To emulate servo responses. */
char *host_shell(const char *command)
{
	switch (host_shell_show) {
	case SHELL_SHOW_SERVO_V2:
		host_shell_show = SHELL_SHOW_SERIAL_NUMBER;
		return strdup("servo_v2");
	case SHELL_SHOW_SERVO_MICRO:
		host_shell_show = SHELL_SHOW_SERIAL_NUMBER;
		return strdup("servo_micro");
	case SHELL_SHOW_CCD_CR50:
		host_shell_show = SHELL_SHOW_SERIAL_NUMBER;
		return strdup("ccd_cr50");
	case SHELL_SHOW_CCD_GSC:
		host_shell_show = SHELL_SHOW_SERIAL_NUMBER;
		return strdup("ccd_gsc");
	case SHELL_SHOW_CCD_TI50:
		host_shell_show = SHELL_SHOW_SERIAL_NUMBER;
		return strdup("ccd_ti50");
	case SHELL_SHOW_C2D2:
		host_shell_show = SHELL_SHOW_SERIAL_NUMBER;
		return strdup("c2d2");
	case SHELL_SHOW_UNKNOWN:
		host_shell_show = SHELL_SHOW_SERIAL_NUMBER;
		return strdup("<unknown>");
	case SHELL_SHOW_INVALID:
		host_shell_show = SHELL_SHOW_EMPTY;
		return strdup("<invalid>");
	case SHELL_SHOW_EMPTY:
		return strdup("");
	case SHELL_SHOW_SERIAL_NUMBER:
		return strdup("serial-number");
	default:
		return NULL;
	}
}

static void test_servo(int _)
{
	const char *ctrl;
	char *prog;

	setenv(ENV_SERVOD_PORT, "1234", 1);
	setenv(ENV_SERVOD_NAME, "some-servo-name", 1);

	host_shell_show = SHELL_SHOW_SERVO_V2;
	prog = host_detect_servo(&ctrl);
	TEST_EQ(strcmp(prog, "ft2232_spi:type=google-servo-v2,serial=serial-number") ||
			strcmp(ctrl, "cpu_fw_spi"),
		0, "Servo servo_v2");

	host_shell_show = SHELL_SHOW_SERVO_MICRO;
	prog = host_detect_servo(&ctrl);
	TEST_EQ(strcmp(prog, "raiden_debug_spi:serial=serial-number") ||
			strcmp(ctrl, "cpu_fw_spi"),
		0, "Servo servo_micro");

	host_shell_show = SHELL_SHOW_CCD_CR50;
	prog = host_detect_servo(&ctrl);
	TEST_EQ(strcmp(prog,
		       "raiden_debug_spi:target=AP,custom_rst=true,serial=serial-number") ||
			strcmp(ctrl, "ccd_cpu_fw_spi"),
		0, "Servo ccd_cr50");

	host_shell_show = SHELL_SHOW_CCD_GSC;
	prog = host_detect_servo(&ctrl);
	TEST_EQ(strcmp(prog,
		       "raiden_debug_spi:target=AP,custom_rst=true,serial=serial-number") ||
			strcmp(ctrl, "ccd_cpu_fw_spi"),
		0, "Servo ccd_gsc");

	host_shell_show = SHELL_SHOW_CCD_TI50;
	prog = host_detect_servo(&ctrl);
	TEST_EQ(strcmp(prog,
		       "raiden_debug_spi:target=AP,custom_rst=true,serial=serial-number") ||
			strcmp(ctrl, "ccd_cpu_fw_spi"),
		0, "Servo ccd_ti50");

	host_shell_show = SHELL_SHOW_C2D2;
	prog = host_detect_servo(&ctrl);
	TEST_EQ(strcmp(prog, "raiden_debug_spi:serial=serial-number") ||
			strcmp(ctrl, "cpu_fw_spi"),
		0, "Servo c2d2");

	host_shell_show = SHELL_SHOW_UNKNOWN;
	prog = host_detect_servo(&ctrl);
	TEST_EQ(strcmp(prog, "raiden_debug_spi:serial=serial-number") ||
			strcmp(ctrl, "cpu_fw_spi"),
		0, "Servo unknown");

	host_shell_show = SHELL_SHOW_INVALID;
	prog = host_detect_servo(&ctrl);
	TEST_EQ(prog == NULL && ctrl == NULL, 1, "Servo invalid");

	setenv(ENV_SERVOD_PORT, "", 1);
	setenv(ENV_SERVOD_NAME, "some-servo-name", 1);
	host_shell_show = SHELL_SHOW_SERVO_V2;
	prog = host_detect_servo(&ctrl);
	TEST_EQ(strcmp(prog, "ft2232_spi:type=google-servo-v2,serial=serial-number") ||
			strcmp(ctrl, "cpu_fw_spi"),
		0, "Servo no port");

	setenv(ENV_SERVOD_PORT, "1234", 1);
	setenv(ENV_SERVOD_NAME, "", 1);
	host_shell_show = SHELL_SHOW_SERVO_V2;
	prog = host_detect_servo(&ctrl);
	TEST_EQ(strcmp(prog, "ft2232_spi:type=google-servo-v2,serial=serial-number") ||
			strcmp(ctrl, "cpu_fw_spi"),
		0, "Servo no name");

	setenv(ENV_SERVOD_PORT, "", 1);
	setenv(ENV_SERVOD_NAME, "", 1);
	host_shell_show = SHELL_SHOW_UNKNOWN;
	prog = host_detect_servo(&ctrl);
	TEST_EQ(strcmp(prog, "raiden_debug_spi:serial=serial-number") ||
			strcmp(ctrl, "cpu_fw_spi"),
		0, "Servo nothing");

	prepare_servo_control("cpu_fw_spi", "on");
	prepare_servo_control("cpu_fw_spi", "off");
}

int main(int argc, char *argv[])
{
	test_servo(0);

	return !gTestSuccess;
}
