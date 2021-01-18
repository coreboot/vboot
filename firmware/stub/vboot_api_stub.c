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
uint32_t VbExKeyboardRead(void)
{
	return 0;
}

__attribute__((weak))
uint32_t VbExKeyboardReadWithFlags(uint32_t *flags_ptr)
{
	return 0;
}

__attribute__((weak))
uint32_t VbExIsShutdownRequested(void)
{
	return 0;
}

__attribute__((weak))
int vb2ex_ec_trusted(void)
{
	return 1;
}

__attribute__((weak))
vb2_error_t vb2ex_ec_running_rw(int *in_rw)
{
	*in_rw = 0;
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_ec_jump_to_rw(void)
{
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_ec_disable_jump(void)
{
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_ec_hash_image(enum vb2_firmware_selection select,
				const uint8_t **hash, int *hash_size)
{
	static const uint8_t fake_hash[32] = {1, 2, 3, 4};

	*hash = fake_hash;
	*hash_size = sizeof(fake_hash);
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_ec_get_expected_image_hash(enum vb2_firmware_selection select,
					     const uint8_t **hash, int *hash_size)
{
	static const uint8_t fake_hash[32] = {1, 2, 3, 4};

	*hash = fake_hash;
	*hash_size = sizeof(fake_hash);
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_ec_update_image(enum vb2_firmware_selection select)
{
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_ec_protect(enum vb2_firmware_selection select)
{
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_ec_vboot_done(struct vb2_context *ctx)
{
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_ec_battery_cutoff(void)
{
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_auxfw_check(enum vb2_auxfw_update_severity *severity)
{
	*severity = VB2_AUXFW_NO_UPDATE;
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_auxfw_update(void)
{
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t VbExLegacy(enum VbAltFwIndex_t altfw_num)
{
	return VB2_SUCCESS;
}
