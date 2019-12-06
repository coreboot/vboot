/* Copyright 2019 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdlib.h>
#include <string.h>

#include "subprocess.h"
#include "test_common.h"

#define TEST_STRING "hello world"
#define TEST_STRING_LN TEST_STRING "\n"

static void test_subprocess_output_to_buffer(void)
{
	char output_buffer[__builtin_strlen(TEST_STRING_LN)];

	struct subprocess_target output = {
		.type = TARGET_BUFFER,
		.buffer = {
			.buf = output_buffer,
			.size = sizeof(output_buffer),
		},
	};
	const char *const argv[] = {
		"echo", TEST_STRING, NULL
	};

	TEST_EQ(subprocess_run(argv, &subprocess_null, &output, NULL), 0,
		"Return value of \"echo 'hello world'\" is 0");
	TEST_EQ(memcmp(output_buffer, TEST_STRING_LN, sizeof(output_buffer)), 0,
		"Output is \"hello world\\n\"");
	TEST_EQ(output.buffer.bytes_consumed, sizeof(output_buffer),
		"The entire output buffer should have been used.");
}

static void test_subprocess_output_to_buffer_null_terminated(void)
{
	char output_buffer[__builtin_strlen(TEST_STRING_LN) + 1];

	struct subprocess_target output = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = output_buffer,
			.size = sizeof(output_buffer),
		},
	};
	const char *const argv[] = {
		"echo", TEST_STRING, NULL
	};

	TEST_EQ(subprocess_run(argv, &subprocess_null, &output, NULL), 0,
		"Return value of \"echo 'hello world'\" is 0");
	TEST_STR_EQ(output_buffer, TEST_STRING_LN,
		    "Output is \"hello world\\n\"");
	TEST_EQ(output.buffer.bytes_consumed, sizeof(output_buffer) - 1,
		"The entire output buffer should have been used.");
}

#define TEST_STRING_2 "hello\0world!"

static void test_subprocess_input_buffer(void)
{
	char input_buffer[sizeof(TEST_STRING_2)];
	char output_buffer[20];
	char error_buffer[20];

	memcpy(input_buffer, TEST_STRING_2, sizeof(input_buffer));

	struct subprocess_target input = {
		.type = TARGET_BUFFER,
		.buffer = {
			.buf = input_buffer,
			.size = sizeof(input_buffer),
		},
	};
	struct subprocess_target output = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = output_buffer,
			.size = sizeof(output_buffer),
		},
	};
	struct subprocess_target error = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = error_buffer,
			.size = sizeof(error_buffer),
		},
	};
	const char *const argv[] = {"cat", NULL};

	TEST_EQ(subprocess_run(argv, &input, &output, &error), 0,
		"Return value of \"cat\" is 0");
	TEST_EQ(memcmp(output_buffer, TEST_STRING_2, sizeof(TEST_STRING_2)),
		0, "Output is \"hello\\0world!\"");
	TEST_STR_EQ(error_buffer, "", "No output captured on stderr");
	TEST_EQ(output.buffer.bytes_consumed, sizeof(TEST_STRING_2),
		"Bytes consumed is correct");
	TEST_EQ(error.buffer.bytes_consumed, 0, "No bytes used for error");
}

static void test_subprocess_input_null_terminated(void)
{
	char input_buffer[20];
	char output_buffer[20];
	char error_buffer[20];

	memcpy(input_buffer, TEST_STRING_2, sizeof(TEST_STRING_2));

	struct subprocess_target input = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = input_buffer,
		},
	};
	struct subprocess_target output = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = output_buffer,
			.size = sizeof(output_buffer),
		},
	};
	struct subprocess_target error = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = error_buffer,
			.size = sizeof(error_buffer),
		},
	};
	const char *const argv[] = {"cat", NULL};

	TEST_EQ(subprocess_run(argv, &input, &output, &error), 0,
		"Return value of \"cat\" is 0");
	TEST_STR_EQ(output_buffer, "hello", "Output is \"hello\"");
	TEST_STR_EQ(error_buffer, "", "No output captured on stderr");
	TEST_EQ(output.buffer.bytes_consumed, 5, "5 bytes used");
	TEST_EQ(error.buffer.bytes_consumed, 0, "No bytes used for error");
}

static void test_subprocess_small_output_buffer(void)
{
	char output_buffer[3];

	struct subprocess_target output = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = output_buffer,
			.size = sizeof(output_buffer),
		},
	};
	const char *const argv[] = {
		"echo", TEST_STRING, NULL
	};

	TEST_EQ(subprocess_run(argv, &subprocess_null, &output, NULL), 0,
		"Return value of \"echo 'hello world'\" is 0");
	TEST_STR_EQ(output_buffer, "he",
		    "Output is \"he\" (truncated to small buffer)");
	TEST_EQ(output.buffer.bytes_consumed, sizeof(output_buffer) - 1,
		"The entire output buffer should have been used.");
}

static void test_subprocess_return_code_failure(void)
{
	const char *const argv[] = {"false"};

	TEST_NEQ(subprocess_run(argv, NULL, NULL, NULL), 0,
		 "Return value of \"false\" is nonzero");
}

int main(int argc, char *argv[])
{
	test_subprocess_output_to_buffer();
	test_subprocess_output_to_buffer_null_terminated();
	test_subprocess_input_buffer();
	test_subprocess_input_null_terminated();
	test_subprocess_small_output_buffer();
	test_subprocess_return_code_failure();

	if (!gTestSuccess)
		return 255;
	return 0;
}
