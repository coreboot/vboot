/*
 * Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * All hacks to enable building firmware updater on old branches.
 */
#ifndef VBOOT_REFERENCE_FUTILITY_UPDATER_COMPAT_H_
#define VBOOT_REFERENCE_FUTILITY_UPDATER_COMPAT_H_

#define _STUB_IMPLEMENTATION_
#include <stdio.h>
#include <unistd.h>
#include "2sysincludes.h"
#include "2rsa.h"
#include "2sha.h"
#include "vb2_struct.h"
#include "host_key.h"
#include "vboot_api.h"

struct vb2_packed_key;
static inline int packed_key_looks_ok(
		const struct vb2_packed_key *key, uint32_t size)
{
	VbPublicKey *pub = (VbPublicKey *)key;
	return PublicKeyLooksOkay(pub, size);
}

static inline const char *packed_key_sha1_string(
		const struct vb2_packed_key *key)
{
	static char dest[VB2_SHA1_DIGEST_SIZE * 2 + 1];

	uint8_t *input = ((uint8_t *)key) + key->key_offset;
	uint32_t inlen = key->key_size;

	uint8_t *digest = DigestBuf(input, inlen, SHA1_DIGEST_ALGORITHM);
	char *dnext = dest;
	int i;

	for (i = 0; i < SHA1_DIGEST_SIZE; i++)
		dnext += sprintf(dnext, "%02x", digest[i]);
	VbExFree(digest);
	return dest;
}

static inline int vb2_read_file(
		const char *filename, uint8_t **data_ptr, uint32_t *size_ptr)
{
	FILE *f;
	uint8_t *buf;
	long size;

	*data_ptr = NULL;
	*size_ptr = 0;

	f = fopen(filename, "rb");
	if (!f) {
		return 1;
	}

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	rewind(f);

	if (size < 0 || size > UINT32_MAX) {
		fclose(f);
		return 1;
	}

	buf = malloc(size);
	if (!buf) {
		fclose(f);
		return 1;
	}

	if(1 != fread(buf, size, 1, f)) {
		fclose(f);
		free(buf);
		return 1;
	}

	fclose(f);

	*data_ptr = buf;
	*size_ptr = size;
	return 0;
}

static inline int vb2_write_file(
		const char *filename, const void *buf, uint32_t size)
{
	FILE *f = fopen(filename, "wb");

	if (!f) {
		return 1;
	}

	if (1 != fwrite(buf, size, 1, f)) {
		fclose(f);
		unlink(filename);  /* Delete any partial file */
		return 1;
	}

	fclose(f);
	return 0;
}

#define vb2_unpack_key2(key, packed_key) \
	vb2_unpack_key(key, (const uint8_t *)packed_key, \
		       packed_key->key_offset + packed_key->key_size)

#endif /* VBOOT_REFERENCE_FUTILITY_UPDATER_COMPAT_H_ */
