/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for keyblock hash verification
 */

#include <stdio.h>
#include "2common.h"
#include "2struct.h"
#include "common/tests.h"

static struct vb2_workbuf wb;

struct {
	struct vb2_keyblock kb;
	char data_key_data[16];
	uint8_t hash[VB2_SHA512_DIGEST_SIZE];
} mock_kb;

static void rehash_keyblock(void)
{
	struct vb2_keyblock *kb = &mock_kb.kb;
	struct vb2_signature *hashsig = &mock_kb.kb.keyblock_hash;
	struct vb2_digest_context dc;

	hashsig->sig_offset = vb2_offset_of(hashsig, mock_kb.hash);
	hashsig->sig_size = sizeof(mock_kb.hash);
	hashsig->data_size = sizeof(mock_kb.kb) + sizeof(mock_kb.data_key_data);
	vb2_digest_init(&dc, false, VB2_HASH_SHA512, 0);
	vb2_digest_extend(&dc, (const uint8_t *)kb, hashsig->data_size);
	vb2_digest_finalize(&dc, mock_kb.hash, hashsig->sig_size);
}

static void reset_common_data(void)
{
	struct vb2_keyblock *kb = &mock_kb.kb;

	kb->keyblock_size = sizeof(mock_kb);
	memcpy(kb->magic, VB2_KEYBLOCK_MAGIC, VB2_KEYBLOCK_MAGIC_SIZE);

	kb->keyblock_flags = VB2_KEYBLOCK_FLAG_DEVELOPER_1 |
		VB2_KEYBLOCK_FLAG_DEVELOPER_0 |
		VB2_KEYBLOCK_FLAG_RECOVERY_1 | VB2_KEYBLOCK_FLAG_RECOVERY_0;
	kb->header_version_major = VB2_KEYBLOCK_VERSION_MAJOR;
	kb->header_version_minor = VB2_KEYBLOCK_VERSION_MINOR;
	kb->data_key.algorithm = 7;
	kb->data_key.key_version = 2;
	kb->data_key.key_offset =
		vb2_offset_of(&mock_kb, &mock_kb.data_key_data) -
		vb2_offset_of(&mock_kb, &kb->data_key);
	kb->data_key.key_size = sizeof(mock_kb.data_key_data);
	strcpy(mock_kb.data_key_data, "data key data!!");
	rehash_keyblock();
};

/* Tests */
static void verify_keyblock_hash_tests(void)
{
	struct vb2_keyblock *kb = &mock_kb.kb;

	/* Test successful call */
	reset_common_data();
	TEST_SUCC(vb2_verify_keyblock_hash(kb, kb->keyblock_size, &wb),
		  "Keyblock hash good");

	/* Validity check keyblock */
	reset_common_data();
	kb->magic[0] ^= 0xd0;
	TEST_EQ(vb2_verify_keyblock_hash(kb, kb->keyblock_size, &wb),
		VB2_ERROR_KEYBLOCK_MAGIC, "Keyblock validity check");

	/*
	 * Validity check should be looking at the keyblock hash struct, not
	 * the keyblock signature struct.
	 */
	reset_common_data();
	kb->keyblock_hash.data_size = sizeof(*kb) - 1;
	TEST_EQ(vb2_verify_keyblock_hash(kb, kb->keyblock_size, &wb),
		VB2_ERROR_KEYBLOCK_SIGNED_TOO_LITTLE,
		"Keyblock check hash sig");

	reset_common_data();
	mock_kb.data_key_data[0] ^= 0xa0;
	TEST_EQ(vb2_verify_keyblock_hash(kb, kb->keyblock_size, &wb),
		VB2_ERROR_KEYBLOCK_HASH_INVALID_IN_DEV_MODE,
		"Keyblock check hash invalid");
}

int main(int argc, char *argv[])
{
	verify_keyblock_hash_tests();

	return gTestSuccess ? 0 : 255;
}
