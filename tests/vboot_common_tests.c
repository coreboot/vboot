/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for firmware vboot_common.c
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "2common.h"
#include "host_common.h"
#include "test_common.h"
#include "utility.h"
#include "vboot_common.h"

/* Public key utility functions */
static void PublicKeyTest(void)
{
	struct vb2_packed_key k[3];
	struct vb2_packed_key j[5];

	/* Fill some bits of the public key data */
	memset(j, 0, sizeof(j));
	memset(k, 0x42, sizeof(k));
	k[1].key_size = 12345;
	k[2].key_version = 67;

	PublicKeyInit(k, (uint8_t*)(k + 1), 2 * sizeof(struct vb2_packed_key));
	TEST_EQ(k->key_offset, sizeof(struct vb2_packed_key),
		"PublicKeyInit key_offset");
	TEST_EQ(k->key_size, 2 * sizeof(struct vb2_packed_key),
		"PublicKeyInit key_size");
	TEST_EQ(k->algorithm, VB2_ALG_COUNT, "PublicKeyInit algorithm");
	TEST_EQ(k->key_version, 0, "PublicKeyInit key_version");

	/* Set algorithm and version, so we can tell if they get copied */
	k->algorithm = 3;
	k->key_version = 21;

	/* Copying to a smaller destination should fail */
	PublicKeyInit(j, (uint8_t*)(j + 1),
		      2 * sizeof(struct vb2_packed_key) - 1);
	TEST_NEQ(0, PublicKeyCopy(j, k), "PublicKeyCopy too small");

	/* Copying to same or larger size should succeed */
	PublicKeyInit(j, (uint8_t*)(j + 2),
		      2 * sizeof(struct vb2_packed_key) + 1);
	TEST_EQ(0, PublicKeyCopy(j, k), "PublicKeyCopy same");
	/* Offset in destination shouldn't have been modified */
	TEST_EQ(j->key_offset, 2 * sizeof(struct vb2_packed_key),
		"PublicKeyCopy key_offset");
	/* Size should have been reduced to match the source */
	TEST_EQ(k->key_size, 2 * sizeof(struct vb2_packed_key),
		"PublicKeyCopy key_size");
	/* Other fields should have been copied */
	TEST_EQ(k->algorithm, j->algorithm, "PublicKeyCopy algorithm");
	TEST_EQ(k->key_version, j->key_version, "PublicKeyCopy key_version");
	/* Data should have been copied */
	TEST_EQ(0,
		memcmp(vb2_packed_key_data(k),
		       vb2_packed_key_data(j), k->key_size),
		"PublicKeyCopy data");
}

int main(int argc, char* argv[])
{
	PublicKeyTest();

	return gTestSuccess ? 0 : 255;
}
