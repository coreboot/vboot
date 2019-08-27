/* Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for firmware secure storage library.
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
		TEST_NEQ(c->flags & VB2_CONTEXT_SECDATA_FIRMWARE_CHANGED,
			 0, why);
	else
		TEST_EQ(c->flags & VB2_CONTEXT_SECDATA_FIRMWARE_CHANGED,
			0, why);

	c->flags &= ~VB2_CONTEXT_SECDATA_FIRMWARE_CHANGED;
};

static void secdata_firmware_test(void)
{
	uint8_t workbuf[VB2_FIRMWARE_WORKBUF_RECOMMENDED_SIZE]
		__attribute__ ((aligned (VB2_WORKBUF_ALIGN)));
	struct vb2_context c = {
		.flags = 0,
		.workbuf = workbuf,
		.workbuf_size = sizeof(workbuf),
	};
	struct vb2_secdata_firmware *sec =
		(struct vb2_secdata_firmware *)c.secdata_firmware;
	struct vb2_shared_data *sd = vb2_get_sd(&c);
	uint32_t v = 1;

	/* Check size constant */
	TEST_EQ(VB2_SECDATA_FIRMWARE_SIZE, sizeof(struct vb2_secdata_firmware),
		"Struct size constant");

	/* Blank data is invalid */
	memset(c.secdata_firmware, 0xa6, sizeof(c.secdata_firmware));
	TEST_EQ(vb2api_secdata_firmware_check(&c),
		VB2_ERROR_SECDATA_FIRMWARE_CRC, "Check blank CRC");
	TEST_EQ(vb2_secdata_firmware_init(&c),
		VB2_ERROR_SECDATA_FIRMWARE_CRC, "Init blank CRC");

	/* Ensure zeroed buffers are invalid (coreboot relies on this) */
	memset(c.secdata_firmware, 0, sizeof(c.secdata_firmware));
	TEST_EQ(vb2_secdata_firmware_init(&c),
		VB2_ERROR_SECDATA_FIRMWARE_VERSION,
		"Zeroed buffer (invalid version)");

	/* Try with bad version */
	TEST_SUCC(vb2api_secdata_firmware_create(&c), "Create");
	sec->struct_version -= 1;
	sec->crc8 = vb2_crc8(sec, offsetof(struct vb2_secdata_firmware, crc8));
	TEST_EQ(vb2api_secdata_firmware_check(&c),
		VB2_ERROR_SECDATA_FIRMWARE_VERSION, "Check invalid version");
	TEST_EQ(vb2_secdata_firmware_init(&c),
		VB2_ERROR_SECDATA_FIRMWARE_VERSION, "Init invalid version");

	/* Create good data */
	TEST_SUCC(vb2api_secdata_firmware_create(&c), "Create");
	TEST_SUCC(vb2api_secdata_firmware_check(&c), "Check created CRC");
	TEST_SUCC(vb2_secdata_firmware_init(&c), "Init created CRC");
	TEST_NEQ(sd->status & VB2_SD_STATUS_SECDATA_FIRMWARE_INIT, 0,
		 "Init set SD status");
	sd->status &= ~VB2_SD_STATUS_SECDATA_FIRMWARE_INIT;
	test_changed(&c, 1, "Create changes data");

	/* Now corrupt it */
	c.secdata_firmware[2]++;
	TEST_EQ(vb2api_secdata_firmware_check(&c),
		VB2_ERROR_SECDATA_FIRMWARE_CRC, "Check invalid CRC");
	TEST_EQ(vb2_secdata_firmware_init(&c),
		VB2_ERROR_SECDATA_FIRMWARE_CRC, "Init invalid CRC");

	/* Read/write flags */
	vb2api_secdata_firmware_create(&c);
	vb2_secdata_firmware_init(&c);
	c.flags = 0;
	TEST_SUCC(vb2_secdata_firmware_get(&c, VB2_SECDATA_FIRMWARE_FLAGS, &v),
		  "Get flags");
	TEST_EQ(v, 0, "Flags created 0");
	test_changed(&c, 0, "Get doesn't change data");
	TEST_SUCC(vb2_secdata_firmware_set(&c, VB2_SECDATA_FIRMWARE_FLAGS,
					   0x12),
		  "Set flags");
	test_changed(&c, 1, "Set changes data");
	TEST_SUCC(vb2_secdata_firmware_set(&c, VB2_SECDATA_FIRMWARE_FLAGS,
					   0x12),
		  "Set flags 2");
	test_changed(&c, 0, "Set again doesn't change data");
	TEST_SUCC(vb2_secdata_firmware_get(&c, VB2_SECDATA_FIRMWARE_FLAGS, &v),
		  "Get flags 2");
	TEST_EQ(v, 0x12, "Flags changed");
	TEST_EQ(vb2_secdata_firmware_set(&c, VB2_SECDATA_FIRMWARE_FLAGS, 0x100),
		VB2_ERROR_SECDATA_FIRMWARE_SET_FLAGS, "Bad flags");

	/* Read/write versions */
	TEST_SUCC(vb2_secdata_firmware_get(&c, VB2_SECDATA_FIRMWARE_VERSIONS,
					   &v),
		  "Get versions");
	TEST_EQ(v, 0, "Versions created 0");
	test_changed(&c, 0, "Get doesn't change data");
	TEST_SUCC(vb2_secdata_firmware_set(&c, VB2_SECDATA_FIRMWARE_VERSIONS,
					   0x123456ff),
		  "Set versions");
	test_changed(&c, 1, "Set changes data");
	TEST_SUCC(vb2_secdata_firmware_set(&c, VB2_SECDATA_FIRMWARE_VERSIONS,
					   0x123456ff),
		  "Set versions 2");
	test_changed(&c, 0, "Set again doesn't change data");
	TEST_SUCC(vb2_secdata_firmware_get(&c, VB2_SECDATA_FIRMWARE_VERSIONS, &v),
		  "Get versions 2");
	TEST_EQ(v, 0x123456ff, "Versions changed");

	/* Invalid field fails */
	TEST_EQ(vb2_secdata_firmware_get(&c, -1, &v),
		VB2_ERROR_SECDATA_FIRMWARE_GET_PARAM, "Get invalid");
	TEST_EQ(vb2_secdata_firmware_set(&c, -1, 456),
		VB2_ERROR_SECDATA_FIRMWARE_SET_PARAM, "Set invalid");
	test_changed(&c, 0, "Set invalid field doesn't change data");

	/* Read/write uninitialized data fails */
	sd->status &= ~VB2_SD_STATUS_SECDATA_FIRMWARE_INIT;
	TEST_EQ(vb2_secdata_firmware_get(&c, VB2_SECDATA_FIRMWARE_VERSIONS, &v),
		VB2_ERROR_SECDATA_FIRMWARE_GET_UNINITIALIZED,
		"Get uninitialized");
	test_changed(&c, 0, "Get uninitialized doesn't change data");
	TEST_EQ(vb2_secdata_firmware_set(&c, VB2_SECDATA_FIRMWARE_VERSIONS,
					 0x123456ff),
		VB2_ERROR_SECDATA_FIRMWARE_SET_UNINITIALIZED,
		"Set uninitialized");
	test_changed(&c, 0, "Set uninitialized doesn't change data");
}

int main(int argc, char* argv[])
{
	secdata_firmware_test();

	return gTestSuccess ? 0 : 255;
}
