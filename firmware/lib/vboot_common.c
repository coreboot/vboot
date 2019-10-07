/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Common functions between firmware and kernel verified boot.
 * (Firmware portion)
 */

#include "2common.h"
#include "2misc.h"
#include "2rsa.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "utility.h"
#include "vboot_api.h"
#include "vboot_common.h"

void PublicKeyInit(struct vb2_packed_key *key,
		   uint8_t *key_data, uint64_t key_size)
{
	key->key_offset = vb2_offset_of(key, key_data);
	key->key_size = key_size;
	key->algorithm = VB2_ALG_COUNT; /* Key not present yet */
	key->key_version = 0;
}

int PublicKeyCopy(struct vb2_packed_key *dest, const struct vb2_packed_key *src)
{
	if (dest->key_size < src->key_size)
		return 1;

	dest->key_size = src->key_size;
	dest->algorithm = src->algorithm;
	dest->key_version = src->key_version;
	memcpy(vb2_packed_key_data_mutable(dest),
	       vb2_packed_key_data(src),
	       src->key_size);
	return 0;
}
