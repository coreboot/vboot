/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Implementation of SHA256 required by libavb, using hardware accelerator by leveraging
 * existing vboot library.
 */

#include "2api.h"
#include "avb_sha.h"

void avb_sha256_init(AvbSHA256Ctx *avb_ctx)
{
	vb2ex_hwcrypto_digest_init(VB2_HASH_SHA256, 0);
}

void avb_sha256_update(AvbSHA256Ctx *avb_ctx, const uint8_t *data, size_t len)
{
	vb2ex_hwcrypto_digest_extend(data, len);
}

uint8_t *avb_sha256_final(AvbSHA256Ctx *avb_ctx)
{
	vb2ex_hwcrypto_digest_finalize(avb_ctx->buf, VB2_SHA256_DIGEST_SIZE);

	return avb_ctx->buf;
}
