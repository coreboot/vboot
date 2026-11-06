/* Copyright 2026 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for TPM2 command marshaling and response unmarshaling.
 */

#include "2common.h"
#include "2sysincludes.h"
#include "common/tests.h"
#include "tpm2_marshaling.h"

static uint8_t buf[TPM_BUFFER_SIZE];
static size_t buf_len;

static void put_u16(uint16_t v)
{
	buf[buf_len++] = v >> 8;
	buf[buf_len++] = v;
}

static void put_u32(uint32_t v)
{
	put_u16(v >> 16);
	put_u16(v);
}

/* Start a response with a header; the size field is not checked. */
static void start_response(void)
{
	memset(buf, 0, sizeof(buf));
	buf_len = 0;
	put_u16(TPM_ST_NO_SESSIONS);
	put_u32(0);
	put_u32(TPM_SUCCESS);
}

static void unmarshal_response_tests(void)
{
	struct tpm2_response resp;

	/* Response shorter than the header */
	start_response();
	TEST_EQ(tpm_unmarshal_response(TPM2_NV_ReadPublic, buf, 4, &resp), -1,
		"Response shorter than header");

	/* Negative response size */
	start_response();
	TEST_EQ(tpm_unmarshal_response(TPM2_NV_ReadPublic, buf, -1, &resp), -1,
		"Negative response size");

	/* Well-formed NV_ReadPublic response */
	start_response();
	put_u16(14);		/* TPMS_NV_PUBLIC size */
	put_u32(0x1007);	/* nvIndex */
	put_u16(0x000b);	/* nameAlg */
	put_u32(0x12345678);	/* attributes */
	put_u16(0);		/* authPolicy size */
	put_u16(32);		/* dataSize */
	put_u16(2);		/* nvName size */
	put_u16(0xabcd);	/* nvName */
	TEST_EQ(tpm_unmarshal_response(TPM2_NV_ReadPublic, buf, buf_len, &resp), 0,
		"NV_ReadPublic");
	TEST_EQ(resp.nv_read_public.nvPublic.nvIndex, 0x1007, "  nvIndex");
	TEST_EQ(resp.nv_read_public.nvPublic.attributes, 0x12345678, "  attributes");
	TEST_EQ(resp.nv_read_public.nvPublic.dataSize, 32, "  dataSize");
	TEST_EQ(resp.nv_read_public.nvName.size, 2, "  nvName size");

	/*
	 * TPMS_NV_PUBLIC too small for its fields. Unmarshaling must stop at
	 * the first failure instead of reading past the TPMS_NV_PUBLIC data.
	 */
	start_response();
	put_u16(2);		/* TPMS_NV_PUBLIC size */
	put_u16(0);		/* Truncated nvIndex */
	put_u16(0);		/* nvName size */
	TEST_EQ(tpm_unmarshal_response(TPM2_NV_ReadPublic, buf, buf_len, &resp), -1,
		"NV_ReadPublic with truncated TPMS_NV_PUBLIC");

	/* Truncated object handle in CreatePrimary response */
	start_response();
	put_u16(0);
	TEST_EQ(tpm_unmarshal_response(TPM2_CreatePrimary, buf, buf_len, &resp), -1,
		"CreatePrimary with truncated handle");
}

static void marshal_command_tests(void)
{
	uint8_t data[64];
	struct tpm2_nv_write_cmd nv_write = {
		.nvIndex = 0x1007,
		.data = {
			.size = sizeof(data),
			.buffer = data,
		},
	};
	/* Room for the header and one handle only */
	const int buffer_size = sizeof(struct tpm_header) + sizeof(uint32_t);
	int i;

	memset(data, 0x5a, sizeof(data));
	memset(buf, 0xcc, sizeof(buf));
	TEST_TRUE(tpm_marshal_command(TPM2_NV_Write, &nv_write, buf, buffer_size) <= 0,
		  "NV_Write to small buffer fails");
	for (i = buffer_size; i < sizeof(buf); i++)
		if (buf[i] != 0xcc)
			break;
	TEST_EQ(i, sizeof(buf), "  nothing written past the buffer");
}

int main(void)
{
	unmarshal_response_tests();
	marshal_command_tests();

	return gTestSuccess ? 0 : 255;
}
