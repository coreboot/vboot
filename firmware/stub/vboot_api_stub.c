/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Stub implementations of firmware-provided API functions.
 */

#include <stdint.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "2api.h"
#include "2common.h"
#include "vboot_api.h"
#include "vboot_test.h"

__attribute__((weak))
vb2_error_t vb2ex_run_altfw(uint32_t altfw_id)
{
	return VB2_SUCCESS;
}
