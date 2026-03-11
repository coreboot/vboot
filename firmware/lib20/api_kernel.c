/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Externally-callable APIs
 * (Kernel portion)
 */

#include "2api.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2rsa.h"
#include "2secdata.h"
#include "2sha.h"
#include "2sysincludes.h"

vb2_error_t vb2api_verify_kernel_data(struct vb2_context *ctx, const void *buf,
				      uint32_t size)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	struct vb2_kernel_preamble *pre;
	struct vb2_digest_context *dc;
	struct vb2_public_key key;
	struct vb2_workbuf wb;

	uint8_t *digest;
	uint32_t digest_size;

	vb2_workbuf_from_ctx(ctx, &wb);

	/* Get preamble pointer */
	if (!sd->preamble_size)
		return VB2_ERROR_API_VERIFY_KDATA_PREAMBLE;

	pre = (struct vb2_kernel_preamble *)
		vb2_member_of(sd, sd->preamble_offset);

	/* Make sure we were passed the right amount of data */
	if (size != pre->body_signature.data_size)
		return VB2_ERROR_API_VERIFY_KDATA_SIZE;

	/* Allocate workbuf space for the hash */
	dc = vb2_workbuf_alloc(&wb, sizeof(*dc));
	if (!dc)
		return VB2_ERROR_API_VERIFY_KDATA_WORKBUF;

	/*
	 * Unpack the kernel data key to see which hashing algorithm we
	 * should use.
	 *
	 * TODO: really, the kernel body should be hashed, and not signed,
	 * because the signature we're checking is already signed as part of
	 * the kernel preamble.  But until we can change the signing scripts,
	 * we're stuck with a signature here instead of a hash.
	 */
	if (!sd->data_key_size)
		return VB2_ERROR_API_VERIFY_KDATA_KEY;

	VB2_TRY(vb2_unpack_key_buffer(&key,
				      vb2_member_of(sd, sd->data_key_offset),
				      sd->data_key_size));

	VB2_TRY(vb2_digest_init(dc, vb2api_hwcrypto_allowed(ctx),
				key.hash_alg, size));

	VB2_TRY(vb2_digest_extend(dc, buf, size));

	digest_size = vb2_digest_size(key.hash_alg);
	digest = vb2_workbuf_alloc(&wb, digest_size);
	if (!digest)
		return VB2_ERROR_API_CHECK_HASH_WORKBUF_DIGEST;

	VB2_TRY(vb2_digest_finalize(dc, digest, digest_size));

	/*
	 * The body signature is currently a *signature* of the body data, not
	 * just its hash.  So we need to verify the signature.
	 */

	/*
	 * Check digest vs. signature.  Note that this destroys the signature.
	 * That's ok, because we only check each signature once per boot.
	 */
	return vb2_verify_digest(&key, &pre->body_signature, digest, &wb);
}
