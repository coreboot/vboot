/* Copyright 2021 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Constants & macro for sha algorithms.
 */

#ifndef VBOOT_REFERENCE_2SHA_PRIVATE_H_
#define VBOOT_REFERENCE_2SHA_PRIVATE_H_

/* Sha256 padding is consisted of 0x80 + zeros + length of message (8 byte).
 * So minimum length for padding is 9.
 */
#define SHA256_MIN_PAD_LEN 9

/* Beginning of sha256 padding is always 0x80 when messages are in bytes
 */
#define SHA256_PAD_BEGIN 0x80

extern const uint32_t vb2_sha256_h0[8];
extern const uint32_t vb2_sha256_k[64];

#define UNPACK32(x, str)				\
	{						\
		*((str) + 3) = (uint8_t) ((x)      );	\
		*((str) + 2) = (uint8_t) ((x) >>  8);	\
		*((str) + 1) = (uint8_t) ((x) >> 16);	\
		*((str) + 0) = (uint8_t) ((x) >> 24);	\
	}

#define PACK32(str, x)						\
	{							\
		*(x) =   ((uint32_t) *((str) + 3)      )	\
			| ((uint32_t) *((str) + 2) <<  8)       \
			| ((uint32_t) *((str) + 1) << 16)       \
			| ((uint32_t) *((str) + 0) << 24);      \
	}
#endif  /* VBOOT_REFERENCE_2SHA_PRIVATE_H_ */
