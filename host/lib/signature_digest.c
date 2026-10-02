/* Copyright 2010 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>

#include "2common.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "host_common.h"
#include "host_signature21.h"
#include "signature_digest.h"

uint8_t* PrependDigestInfo(enum vb2_hash_algorithm hash_alg, uint8_t* digest)
{
	const int digest_size = vb2_digest_size(hash_alg);
	uint32_t digestinfo_size = 0;
	const uint8_t* digestinfo = NULL;

	if (VB2_SUCCESS != vb2_digest_info(hash_alg, &digestinfo,
					   &digestinfo_size))
		return NULL;

	uint8_t* p = malloc(digestinfo_size + digest_size);
	memcpy(p, digestinfo, digestinfo_size);
	memcpy(p + digestinfo_size, digest, digest_size);
	return p;
}

uint8_t* SignatureDigest(const uint8_t* buf, uint64_t len,
			 unsigned int algorithm)
{
	uint8_t* info_digest  = NULL;

	struct vb2_hash hash;

	if (algorithm >= VB2_ALG_COUNT) {
		fprintf(stderr,
			"SignatureDigest(): Called with invalid algorithm!\n");
		return NULL;
	}

	if (VB2_SUCCESS == vb2_hash_calculate(false, buf, len,
					      vb2_crypto_to_hash(algorithm),
					      &hash)) {
		info_digest = PrependDigestInfo(hash.algo, hash.raw);
	}
	return info_digest;
}
