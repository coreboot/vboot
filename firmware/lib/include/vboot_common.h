/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Common functions between firmware and kernel verified boot.
 */

#ifndef VBOOT_REFERENCE_VBOOT_COMMON_H_
#define VBOOT_REFERENCE_VBOOT_COMMON_H_

#include "2api.h"
#include "2struct.h"
#include "vboot_struct.h"

/* Error Codes for all common functions. */
enum {
	VBOOT_SUCCESS = 0,
	/* Keyblock internal structure is invalid, or not a keyblock */
	VBOOT_KEYBLOCK_INVALID,
	/* Keyblock signature check failed */
	VBOOT_KEYBLOCK_SIGNATURE,
	/* Keyblock hash check failed */
	VBOOT_KEYBLOCK_HASH,
	/* Invalid public key passed to a signature verficiation function. */
	VBOOT_PUBLIC_KEY_INVALID,
	/* Preamble internal structure is invalid */
	VBOOT_PREAMBLE_INVALID,
	/* Preamble signature check failed */
	VBOOT_PREAMBLE_SIGNATURE,
	/* Shared data is invalid. */
	VBOOT_SHARED_DATA_INVALID,
	/* Kernel Preamble does not contain flags */
	VBOOT_KERNEL_PREAMBLE_NO_FLAGS,
	VBOOT_ERROR_MAX,
};
extern const char *kVbootErrors[VBOOT_ERROR_MAX];

/*
 * Helper functions to get data pointed to by a public key or signature.
 */

uint8_t *GetPublicKeyData(struct vb2_packed_key *key);
const uint8_t *GetPublicKeyDataC(const struct vb2_packed_key *key);
uint8_t *GetSignatureData(struct vb2_signature *sig);
const uint8_t *GetSignatureDataC(const struct vb2_signature *sig);

/*
 * Helper functions to verify the data pointed to by a subfield is inside the
 * parent data.
 */

vb2_error_t VerifyPublicKeyInside(const void *parent, uint64_t parent_size,
				  const struct vb2_packed_key *key);

vb2_error_t VerifySignatureInside(const void *parent, uint64_t parent_size,
				  const struct vb2_signature *sig);

/**
 * Initialize a public key to refer to [key_data].
 */
void PublicKeyInit(struct vb2_packed_key *key,
		   uint8_t *key_data, uint64_t key_size);

/**
 * Copy a public key from [src] to [dest].
 *
 * Returns 0 if success, non-zero if error.
 */
int PublicKeyCopy(struct vb2_packed_key *dest,
		  const struct vb2_packed_key *src);

/**
 * Retrieve the 16-bit vmlinuz header address and size from the kernel preamble
 * if there is one.  These are only available in Kernel Preamble Header version
 * >= 2.1.  If given a header 2.0 or lower, will set address and size to 0 (this
 * is not considered an error).
 *
 * Returns VBOOT_SUCCESS if successful.
 */
vb2_error_t VbGetKernelVmlinuzHeader(const VbKernelPreambleHeader *preamble,
				     uint64_t *vmlinuz_header_address,
				     uint64_t *vmlinuz_header_size);

/**
 * Checks if the kernel preamble has flags field. This is available only if the
 * Kernel Preamble Header version >=2.2. If give a header of 2.1 or lower, it
 * will return VBOOT_KERNEL_PREAMBLE_NO_FLAGS.
 *
 * Returns VBOOT_SUCCESS if version is >=2.2.
 */
vb2_error_t VbKernelHasFlags(const VbKernelPreambleHeader *preamble);

/**
 * Verify that the Vmlinuz Header is contained inside of the kernel blob.
 *
 * Returns VBOOT_SUCCESS or VBOOT_PREAMBLE_INVALID on error
 */
vb2_error_t VerifyVmlinuzInsideKBlob(uint64_t kblob, uint64_t kblob_size,
				     uint64_t header, uint64_t header_size);
/**
 * Initialize a verified boot shared data structure.
 *
 * Returns 0 if success, non-zero if error.
 */
vb2_error_t VbSharedDataInit(VbSharedDataHeader *header, uint64_t size);

/**
 * Reserve [size] bytes of the shared data area.  Returns the offset of the
 * reserved data from the start of the shared data buffer, or 0 if error.
 */
uint64_t VbSharedDataReserve(VbSharedDataHeader *header, uint64_t size);

/**
 * Copy the kernel subkey into the shared data.
 *
 * Returns 0 if success, non-zero if error.
 */
vb2_error_t VbSharedDataSetKernelKey(VbSharedDataHeader *header,
				     const struct vb2_packed_key *src);

/**
 * Check whether recovery is allowed or not.
 *
 * The only way to pass this check and proceed to the recovery process is to
 * physically request a recovery (a.k.a. manual recovery). All other recovery
 * requests including manual recovery requested by a (compromised) host will
 * end up with 'broken' screen.
 *
 * @param ctx vboot2 context pointer
 * @return 1: Yes. 0: No or not sure.
 */
int vb2_allow_recovery(struct vb2_context *ctx);

#endif  /* VBOOT_REFERENCE_VBOOT_COMMON_H_ */
