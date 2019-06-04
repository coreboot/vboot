/* Copyright 2019 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Packed key related functions.
 */

#include "2common.h"

const uint8_t *vb2_packed_key_data(const struct vb2_packed_key *key)
{
	return (const uint8_t *)key + key->key_offset;
}

int vb2_verify_packed_key_inside(const void *parent,
				 uint32_t parent_size,
				 const struct vb2_packed_key *key)
{
	return vb2_verify_member_inside(parent, parent_size,
					key, sizeof(*key),
					key->key_offset, key->key_size);
}
