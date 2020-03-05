/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for developer and recovery mode UIs.
 */

#include "test_common.h"

/* Tests */

static void developer_tests(void)
{
	/* TODO(roccochen) */
}

static void broken_recovery_tests(void)
{
	/* TODO(roccochen) */
}

static void manual_recovery_tests(void)
{
	/* TODO(roccochen) */
}

int main(void)
{
	developer_tests();
	broken_recovery_tests();
	manual_recovery_tests();

	return gTestSuccess ? 0 : 255;
}
