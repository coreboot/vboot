/* Copyright 2026 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * This file enables support in the EC (Zephyr) build system for including
 * a SHA256 checksum for a defined area within a binary. This feature is
 * necessary to ensure flash integrity of the RO section in scenarios where
 * secure boot is disabled, but an integrity check is still required.
 */

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "2common.h"
#include "2rsa.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "file_type.h"
#include "fmap.h"
#include "futility.h"
#include "futility_options.h"
#include "host_common.h"
#include "host_common21.h"
#include "host_key21.h"
#include "host_misc.h"
#include "host_signature21.h"
#include "util_misc.h"

/* macro to ensure consistency in name string and avoid typos */
#define RO_CHECKSUM_STR "RO_CHECKSUM"

static void show_chksum(const char *fname, const struct vb2_hash *hash,
	const struct vb2_hash *mismatch, uint32_t file_size)
{
	int i = 0;

	if (fname)
		printf("Name:              %s\n", fname);

	if (file_size)
		printf("  Size:            %d\n", file_size);

	printf("  Hash algorithm:  %s\n", VB2_SHA256_ALG_NAME);
	printf("  Hash digest:     ");
	for (i = 0; i < VB2_SHA256_DIGEST_SIZE; i++)
		printf("%02x", hash->sha256[i]);

	printf("\n");

	if (mismatch) {
		fprintf(stdout, "  Mismatched hash: ");
		for (i = 0; i < VB2_SHA256_DIGEST_SIZE; i++)
			printf("%02x", mismatch->sha256[i]);

		printf("\n");
	}

}

int ft_show_ro_chksum(const char *fname)
{
	const uint32_t hash_size = VB2_SHA256_DIGEST_SIZE;
	uint32_t data_size = 0;
	uint8_t *data = NULL;
	FmapHeader *fmap;
	int fd = -1;
	uint8_t *buf;
	uint32_t len;
	int rv = 1;
	struct vb2_hash hash;
	struct vb2_hash calc_hash;

	if (futil_open_and_map_file(fname, &fd, FILE_RO, &buf, &len))
		return 1;

	VB2_DEBUG("Open file %s of size 0x%08x (%d)\n", fname, len, len);


	if (len == hash_size) {
		/* Case 1: RO_CHKSUM file */
		memcpy(hash.sha256, buf, hash_size);
		show_chksum(fname, &hash, NULL, len);

		if (show_option.fv) {
			data = show_option.fv;
			data_size = show_option.fv_size - hash_size;
		} else {
			/*
			* If we have only the 32 byte hash/checksum,
			* skip hash calculation and return success
			*/
			rv = 0;
			goto done;
		}
	} else {
		fmap = fmap_find(buf, len);
		if (fmap) {
			/* Case 2: Full firmware image file */
			uint8_t *ro_chksum_fmap_ptr;
			FmapAreaHeader *fmaparea;

			VB2_DEBUG("Found an FMAP!\n");

			ro_chksum_fmap_ptr = (uint8_t *)fmap_find_by_name(
				buf, len, fmap, RO_CHECKSUM_STR, &fmaparea);
			if (!ro_chksum_fmap_ptr) {
				ERROR("No %s in FMAP.\n", RO_CHECKSUM_STR);
				goto done;
			}

			if (fmaparea->area_size != hash_size) {
				ERROR("%s area in FMAP has incorrect size=%d\n",
				      RO_CHECKSUM_STR, fmaparea->area_size);
				goto done;
			}

			memcpy(hash.sha256, ro_chksum_fmap_ptr, hash_size);

			data = fmap_find_by_name(buf, len, fmap, "WP_RO", &fmaparea);
			if (!data) {
				ERROR("No WP_RO in FMAP.\n");
				goto done;
			}

			if (hash_size > fmaparea->area_size) {
				ERROR("WP_RO size too small (%d) to contain checksum of "
				      "size=%d.\n",
				      fmaparea->area_size, hash_size);
				goto done;
			}

			data_size = fmaparea->area_size - hash_size;

		} else {
			/* Case 3: Partial WP_RO file */
			if (len < hash_size) {
				ERROR("File is too small\n");
				goto done;
			}

			VB2_DEBUG("Looking for checksum at %#x\n", len - hash_size);
			memcpy(hash.sha256, buf + len - hash_size, hash_size);

			data = buf;
			data_size = len - hash_size;
		}
	}

	/* Now calculate and verify hash*/
	VB2_DEBUG("data_size = 0x%x\n", data_size);
	vb2_hash_calculate(false, data, data_size, VB2_HASH_SHA256, &calc_hash);

	if (memcmp(hash.sha256, calc_hash.sha256, hash_size)) {
		show_chksum(fname, &calc_hash, &hash, hash_size);
		ERROR("Invalid Hash found.\n");
		goto done;
	}

	show_chksum(fname, &hash, NULL, hash_size);

	printf("Hash verification succeeded.\n");
	rv = 0;
done:
	futil_unmap_and_close_file(fd, FILE_RO, buf, len);
	return rv;
}

int ft_sign_ro_chksum(const char *fname)
{
	const uint32_t hash_size = VB2_SHA256_DIGEST_SIZE;
	uint8_t *data; /* data to be signed */
	uint32_t r, data_size;
	int rv = 1;
	uint8_t *ro_chksum_fmap_ptr;
	FmapHeader *fmap = NULL;
	FmapAreaHeader *fmaparea;
	struct vb2_hash old_hash, calc_hash;
	uint8_t *buf = NULL;
	uint32_t len;
	int fd = -1;

	if (futil_open_and_map_file(fname, &fd, FILE_MODE_SIGN(sign_option), &buf, &len))
		return 1;

	data = buf;
	data_size = len;

	VB2_DEBUG("Open file %s of size 0x%08x (%d)\n", fname, len, len);

	/* If we don't have a distinct OUTFILE, look for an existing checksum */
	if (sign_option.inout_file_count < 2) {
		fmap = fmap_find(data, len);

		if (fmap) {
			/* This looks like a full image. */
			VB2_DEBUG("Found an FMAP!\n");

			ro_chksum_fmap_ptr =
				fmap_find_by_name(buf, len, fmap, RO_CHECKSUM_STR, &fmaparea);
			if (!ro_chksum_fmap_ptr) {
				ERROR("No %s in FMAP.\n", RO_CHECKSUM_STR);
				goto done;
			}

			if (fmaparea->area_size != hash_size) {
				ERROR("%s area in FMAP has incorrect size=%d\n",
				      RO_CHECKSUM_STR, fmaparea->area_size);
				goto done;
			}

			memcpy(old_hash.sha256, ro_chksum_fmap_ptr, hash_size);

			VB2_DEBUG("Looking for checksum at %#tx (%#x)\n",
				  (uint8_t *)ro_chksum_fmap_ptr - buf, hash_size);

			data = fmap_find_by_name(buf, len, fmap, "WP_RO", &fmaparea);
			if (!data) {
				VB2_DEBUG("No WP_RO in FMAP.\n");
				goto done;
			}

			data_size = fmaparea->area_size - hash_size;

		} else {
			/*
			 * Or maybe this is just the RO portion, that does not
			 * contain a FMAP.
			 */
			VB2_DEBUG("Looking for old checksum at %#x\n", len - hash_size);

			if (len < hash_size) {
				ERROR("File is too small\n");
				goto done;
			}

			/* Take a look */
			memcpy(old_hash.sha256, buf + len - hash_size, hash_size);
			data_size = len - hash_size;
		}
	}

	/* Verify that user specified data size doesn't overrun buffer */
	if (sign_option.data_size > data_size) {
		ERROR("User specified data size (%d) exceeds buffer space (%d)\n",
		      sign_option.data_size, data_size);
		goto done;
	}

	/* Unless overridden */
	if (sign_option.data_size)
		data_size = sign_option.data_size;

	/* calculate the checksum */
	vb2_hash_calculate(false, data, data_size, VB2_HASH_SHA256, &calc_hash);
	show_chksum(fname, &calc_hash, NULL, data_size);

	if (sign_option.inout_file_count < 2) {
		/* Overwrite the old checksum */
		if (fmap) {
			/* Confirm ro_chksum_ptr is valid */
			if (!ro_chksum_fmap_ptr) {
				ERROR("RO Checksum pointer is invalid, couldn't find %s\n",
				      RO_CHECKSUM_STR);
				goto done;
			}

			/* Confirm that size is valid*/
			if (fmaparea->area_size < hash_size) {
				ERROR("%s,  FMAP area is too small (%u < %d)\n",
				      RO_CHECKSUM_STR, fmaparea->area_size, hash_size);
				goto done;
			}

			VB2_DEBUG("Writing new hash to FMAP %s section\n", RO_CHECKSUM_STR);
			memset(ro_chksum_fmap_ptr, 0xff, fmaparea->area_size);
			memcpy(ro_chksum_fmap_ptr, calc_hash.sha256, hash_size);
		} else {
			/* Non-FMAP in-place write */
			uint32_t current_hash_size = hash_size;
			if (len < current_hash_size) {
				ERROR("File too small for non-FMAP in-place sign\n");
				goto done;
			}

			uint8_t *hash_ptr = buf + len - current_hash_size;
			VB2_DEBUG("Writing new hash to end of file\n");
			memcpy(hash_ptr, calc_hash.sha256, hash_size);
		}
	} else {
		/* Write the hash to a new file */
		VB2_DEBUG("Write the hash to a new file: %s, size=%zd\n", sign_option.outfile,
			  sizeof(calc_hash.sha256));

		show_chksum(fname, &calc_hash, NULL, data_size);
		r = vb2_write_file(sign_option.outfile, calc_hash.sha256,
				   hash_size);

		if (r) {
			ERROR("Unable to write checksum (error 0x%08x)\n", r);
			goto done;
		}
	}

	/* Finally */
	rv = 0;

done:
	futil_unmap_and_close_file(fd, FILE_MODE_SIGN(sign_option), buf, len);

	return rv;
}

enum futil_file_type ft_recognize_ro_chksum(uint8_t *buf, uint32_t len)
{
	const uint8_t *data_ptr = NULL;

	FmapHeader *fmap = fmap_find(buf, len);
	if (fmap) {
		/* This looks like a full image. */
		FmapAreaHeader *fmaparea;

		data_ptr = fmap_find_by_name(buf, len, fmap, RO_CHECKSUM_STR,
					     &fmaparea);

		/* Verify that hash was found and of the expected size */
		if (!data_ptr || (fmaparea->area_size != VB2_SHA256_DIGEST_SIZE))
			return FILE_TYPE_UNKNOWN;

		/* Looks like an RO checksum file */
		return FILE_TYPE_RO_CHKSUM;
	}

	return FILE_TYPE_UNKNOWN;
}
