/* Copyright 2015 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for kernel secure storage library.
 */

#include "2api.h"
#include "2common.h"
#include "2crc8.h"
#include "2misc.h"
#include "2secdata.h"
#include "2sysincludes.h"
#include "test_common.h"
#include "vboot_common.h"

static void test_changed(struct vb2_context *c, int changed, const char *why)
{
	if (changed)
		TEST_NEQ(c->flags & VB2_CONTEXT_SECDATAK_CHANGED, 0, why);
	else
		TEST_EQ(c->flags & VB2_CONTEXT_SECDATAK_CHANGED, 0, why);

	c->flags &= ~VB2_CONTEXT_SECDATAK_CHANGED;
};

static void secdatak_test(void)
{
	uint8_t workbuf[VB2_FIRMWARE_WORKBUF_RECOMMENDED_SIZE]
		__attribute__ ((aligned (VB2_WORKBUF_ALIGN)));
	struct vb2_context c = {
		.flags = 0,
		.workbuf = workbuf,
		.workbuf_size = sizeof(workbuf),
	};
	struct vb2_secdatak *sec = (struct vb2_secdatak *)c.secdatak;
	struct vb2_shared_data *sd = vb2_get_sd(&c);
	uint32_t v = 1;

	/* Check size constant */
	TEST_EQ(VB2_SECDATAK_SIZE, sizeof(struct vb2_secdatak),
		"Struct size constant");

	/* Blank data is invalid */
	memset(c.secdatak, 0xa6, sizeof(c.secdatak));
	TEST_EQ(vb2api_secdatak_check(&c),
		VB2_ERROR_SECDATAK_CRC, "Check blank CRC");
	TEST_EQ(vb2_secdatak_init(&c),
		VB2_ERROR_SECDATAK_CRC, "Init blank CRC");

	/* Ensure zeroed buffers are invalid */
	memset(c.secdatak, 0, sizeof(c.secdatak));
	TEST_EQ(vb2_secdatak_init(&c), VB2_ERROR_SECDATAK_VERSION,
		"Zeroed buffer (invalid version)");

	/* Try with bad version */
	TEST_SUCC(vb2api_secdatak_create(&c), "Create");
	sec->struct_version -= 1;
	sec->crc8 = vb2_crc8(sec, offsetof(struct vb2_secdatak, crc8));
	TEST_EQ(vb2api_secdatak_check(&c),
		VB2_ERROR_SECDATAK_VERSION, "Check invalid version");
	TEST_EQ(vb2_secdatak_init(&c),
		VB2_ERROR_SECDATAK_VERSION, "Init invalid version");

	/* Create good data */
	TEST_SUCC(vb2api_secdatak_create(&c), "Create");
	TEST_SUCC(vb2api_secdatak_check(&c), "Check created CRC");
	TEST_SUCC(vb2_secdatak_init(&c), "Init created CRC");
	TEST_NEQ(sd->status & VB2_SD_STATUS_SECDATAK_INIT, 0,
		 "Init set SD status");
	sd->status &= ~VB2_SD_STATUS_SECDATAK_INIT;
	test_changed(&c, 1, "Create changes data");

	/* Now corrupt it */
	c.secdatak[2]++;
	TEST_EQ(vb2api_secdatak_check(&c),
		VB2_ERROR_SECDATAK_CRC, "Check invalid CRC");
	TEST_EQ(vb2_secdatak_init(&c),
		VB2_ERROR_SECDATAK_CRC, "Init invalid CRC");

	/* Make sure UID is checked */
	vb2api_secdatak_create(&c);
	sec->uid++;
	sec->crc8 = vb2_crc8(sec, offsetof(struct vb2_secdatak, crc8));
	TEST_EQ(vb2_secdatak_init(&c), VB2_ERROR_SECDATAK_UID,
		"Init invalid struct UID");

	/* Read/write versions */
	vb2api_secdatak_create(&c);
	vb2_secdatak_init(&c);
	c.flags = 0;
	TEST_SUCC(vb2_secdatak_get(&c, VB2_SECDATAK_VERSIONS, &v),
		  "Get versions");
	TEST_EQ(v, 0, "Versions created 0");
	test_changed(&c, 0, "Get doesn't change data");
	TEST_SUCC(vb2_secdatak_set(&c, VB2_SECDATAK_VERSIONS, 0x123456ff),
		  "Set versions");
	test_changed(&c, 1, "Set changes data");
	TEST_SUCC(vb2_secdatak_set(&c, VB2_SECDATAK_VERSIONS, 0x123456ff),
		  "Set versions 2");
	test_changed(&c, 0, "Set again doesn't change data");
	TEST_SUCC(vb2_secdatak_get(&c, VB2_SECDATAK_VERSIONS, &v),
		  "Get versions 2");
	TEST_EQ(v, 0x123456ff, "Versions changed");

	/* Invalid field fails */
	TEST_EQ(vb2_secdatak_get(&c, -1, &v),
		VB2_ERROR_SECDATAK_GET_PARAM, "Get invalid");
	TEST_EQ(vb2_secdatak_set(&c, -1, 456),
		VB2_ERROR_SECDATAK_SET_PARAM, "Set invalid");
	test_changed(&c, 0, "Set invalid field doesn't change data");

	/* Read/write uninitialized data fails */
	sd->status &= ~VB2_SD_STATUS_SECDATAK_INIT;
	TEST_EQ(vb2_secdatak_get(&c, VB2_SECDATAK_VERSIONS, &v),
		VB2_ERROR_SECDATAK_GET_UNINITIALIZED, "Get uninitialized");
	test_changed(&c, 0, "Get uninitialized doesn't change data");
	TEST_EQ(vb2_secdatak_set(&c, VB2_SECDATAK_VERSIONS, 0x123456ff),
		VB2_ERROR_SECDATAK_SET_UNINITIALIZED, "Set uninitialized");
	test_changed(&c, 0, "Set uninitialized doesn't change data");
}

int main(int argc, char* argv[])
{
	secdatak_test();

	return gTestSuccess ? 0 : 255;
}
