/* Copyright 2011 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Utility functions for file and key handling.
 */

#include <stdlib.h>
#include <string.h>

#include "2common.h"
#include "2return_codes.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "file_keys.h"
#include "host_misc.h"

vb2_error_t DigestFile(char *input_file, enum vb2_hash_algorithm alg,
		       uint8_t *digest, uint32_t digest_size)
{
	uint8_t *buf = NULL;
	uint32_t size = 0;
	struct vb2_hash hash;

	if (digest_size < vb2_digest_size(alg))
		return VB2_ERROR_SHA_FINALIZE_DIGEST_SIZE;

	VB2_TRY(vb2_read_file(input_file, &buf, &size));
	vb2_error_t rv = vb2_hash_calculate(false, buf, size, alg, &hash);
	free(buf);
	if (rv == VB2_SUCCESS)
		memcpy(digest, hash.raw, vb2_digest_size(alg));
	return rv;
}
