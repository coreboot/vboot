/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef TESTS_FUTILITY_UNIT_TESTS_H_
#define TESTS_FUTILITY_UNIT_TESTS_H_

#define __USE_GNU

#include <stdlib.h>
#include <string.h>

#include "futility.h"
#include "common/tests.h"

/* Test data must be placed in `SOURCE_TEST_DATA_DIR`. Unit tests must copy data to
   `WORK_COPY_TEST_DATA_DIR` and only use the copied data via
   `GET_WORK_COPY_TEST_DATA_FILE_PATH()` macro. */

#define SOURCE_TEST_DATA_DIR			"tests/futility/data/"
#define GET_SOURCE_TEST_DATA_FILE_PATH(item)	SOURCE_TEST_DATA_DIR item
#define WORK_COPY_TEST_DATA_DIR			"tests/futility/data_copy/"
#define GET_WORK_COPY_TEST_DATA_FILE_PATH(item) WORK_COPY_TEST_DATA_DIR item

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

/* If assertion fails, will set the result of the current unit test to UNIT_FAIL and go to
   `unit_cleanup`. To use this, `UNIT_TEST_BEGIN` has to be called at the beginning of the
   function. */
#define UNIT_ASSERT(value)                                                                     \
	do {                                                                                   \
		if ((value) != UNIT_SUCCESS) {                                                 \
			TEST_EQ(0, 1, "Assertion failed: " #value);                            \
			__unit_test_return_value = UNIT_FAIL;                                  \
			goto unit_cleanup;                                                     \
		}                                                                              \
	} while (0)
#endif
