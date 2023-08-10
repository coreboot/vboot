/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdlib.h>
#include <strings.h>

#include "vboot_host.h"
#include "openssl_compat.h"

static int lookup_helper(const char *str, const char *table[], size_t size,
			 unsigned int *out)
{
	unsigned int algo;
	char *e;

	/* try string first */
	for (algo = 0; algo < size; algo++)
		if (table[algo] && !strcasecmp(table[algo], str))
			goto found;

	/* fine, try number */
	algo = strtoul(str, &e, 0);
	if (!*str || (e && *e))
		/* that's not a number */
		return false;
	if (algo >= size || !table[algo])
		/* that's not a valid algorithm */
		return false;

 found:
	*out = algo;
	return true;
}

bool vb2_lookup_sig_alg(const char *str, enum vb2_signature_algorithm *sig_alg)
{
	return lookup_helper(str, vb2_sig_names, VB2_SIG_ALG_COUNT, sig_alg);
}

bool vb2_lookup_hash_alg(const char *str, enum vb2_hash_algorithm *hash_alg)
{
	return lookup_helper(str, vb2_hash_names, VB2_HASH_ALG_COUNT, hash_alg);
}

enum vb2_signature_algorithm vb2_get_sig_alg(uint32_t exp, uint32_t bits)
{
	switch (exp) {
	case RSA_3:
		switch (bits) {
		case 2048:
			return VB2_SIG_RSA2048_EXP3;
		case 3072:
			return VB2_SIG_RSA3072_EXP3;
		}
		break;
	case RSA_F4:
		switch (bits) {
		case 1024:
			return VB2_SIG_RSA1024;
		case 2048:
			return VB2_SIG_RSA2048;
		case 4096:
			return VB2_SIG_RSA4096;
		case 8192:
			return VB2_SIG_RSA8192;
		}
	}

	/* no clue */
	return VB2_SIG_INVALID;
}
