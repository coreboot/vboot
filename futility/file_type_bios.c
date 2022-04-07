/* Copyright 2014 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cbfstool.h"
#include "file_type_bios.h"
#include "file_type.h"
#include "fmap.h"
#include "futility.h"
#include "futility_options.h"
#include "host_common.h"
#include "vb1_helper.h"

static const char * const fmap_name[] = {
	"GBB",					/* BIOS_FMAP_GBB */
	"FW_MAIN_A",				/* BIOS_FMAP_FW_MAIN_A */
	"FW_MAIN_B",				/* BIOS_FMAP_FW_MAIN_B */
	"VBLOCK_A",				/* BIOS_FMAP_VBLOCK_A */
	"VBLOCK_B",				/* BIOS_FMAP_VBLOCK_B */
};
_Static_assert(ARRAY_SIZE(fmap_name) == NUM_BIOS_COMPONENTS,
	       "Size of fmap_name[] should match NUM_BIOS_COMPONENTS");

static void fmap_limit_area(FmapAreaHeader *ah, uint32_t len)
{
	uint32_t sum = ah->area_offset + ah->area_size;
	if (sum < ah->area_size || sum > len) {
		VB2_DEBUG("%.*s %#x + %#x > %#x\n", FMAP_NAMELEN,
			  ah->area_name, ah->area_offset, ah->area_size, len);
		ah->area_offset = 0;
		ah->area_size = 0;
	}
}

/** Show functions **/

static int show_gbb_buf(const char *name, uint8_t *buf, uint32_t len,
			void *data)
{
	struct vb2_gbb_header *gbb = (struct vb2_gbb_header *)buf;
	struct bios_state_s *state = (struct bios_state_s *)data;
	int retval = 0;
	uint32_t maxlen = 0;

	if (!len) {
		printf("GBB header:              %s <invalid>\n", name);
		return 1;
	}

	/* It looks like a GBB or we wouldn't be called. */
	if (!futil_valid_gbb_header(gbb, len, &maxlen))
		retval = 1;

	printf("GBB header:              %s\n", name);
	printf("  Version:               %d.%d\n",
	       gbb->major_version, gbb->minor_version);
	printf("  Flags:                 0x%08x\n", gbb->flags);
	printf("  Regions:                 offset       size\n");
	printf("    hwid                 0x%08x   0x%08x\n",
	       gbb->hwid_offset, gbb->hwid_size);
	printf("    bmpvf                0x%08x   0x%08x\n",
	       gbb->bmpfv_offset, gbb->bmpfv_size);
	printf("    rootkey              0x%08x   0x%08x\n",
	       gbb->rootkey_offset, gbb->rootkey_size);
	printf("    recovery_key         0x%08x   0x%08x\n",
	       gbb->recovery_key_offset, gbb->recovery_key_size);

	printf("  Size:                  0x%08x / 0x%08x%s\n",
	       maxlen, len, maxlen > len ? "  (not enough)" : "");

	if (retval) {
		printf("GBB header is invalid, ignoring content\n");
		return retval;
	}

	printf("GBB content:\n");
	printf("  HWID:                  %s\n", buf + gbb->hwid_offset);
	print_hwid_digest(gbb, "     digest:             ", "\n");

	struct vb2_packed_key *pubkey =
		(struct vb2_packed_key *)(buf + gbb->rootkey_offset);
	if (vb2_packed_key_looks_ok(pubkey, gbb->rootkey_size) == VB2_SUCCESS) {
		if (state) {
			state->rootkey.offset =
				state->area[BIOS_FMAP_GBB].offset +
				gbb->rootkey_offset;
			state->rootkey.buf = buf + gbb->rootkey_offset;
			state->rootkey.len = gbb->rootkey_size;
			state->rootkey.is_valid = 1;
		}
		printf("  Root Key:\n");
		show_pubkey(pubkey, "    ");
	} else {
		retval = 1;
		printf("  Root Key:              <invalid>\n");
	}

	pubkey = (struct vb2_packed_key *)(buf + gbb->recovery_key_offset);
	if (vb2_packed_key_looks_ok(pubkey, gbb->recovery_key_size)
	    == VB2_SUCCESS) {
		if (state) {
			state->recovery_key.offset =
				state->area[BIOS_FMAP_GBB].offset +
				gbb->recovery_key_offset;
			state->recovery_key.buf = buf +
				gbb->recovery_key_offset;
			state->recovery_key.len = gbb->recovery_key_size;
			state->recovery_key.is_valid = 1;
		}
		printf("  Recovery Key:\n");
		show_pubkey(pubkey, "    ");
	} else {
		retval = 1;
		printf("  Recovery Key:          <invalid>\n");
	}

	if (!retval && state)
		state->area[BIOS_FMAP_GBB].is_valid = 1;

	return retval;
}

int ft_show_gbb(const char *name, void *data)
{
	int retval = 0;
	int fd = -1;
	uint8_t *buf;
	uint32_t len;

	retval = futil_open_and_map_file(name, &fd, FILE_RO, &buf, &len);
	if (retval)
		return 1;

	retval = show_gbb_buf(name, buf, len, data);

	futil_unmap_and_close_file(fd, FILE_RO, buf, len);
	return retval;
}

/*
 * This handles FW_MAIN_A and FW_MAIN_B while processing a BIOS image.
 *
 * The data is just the RW firmware blob, so there's nothing useful to show
 * about it. We'll just mark it as present so when we encounter corresponding
 * VBLOCK area, we'll have this to verify.
 */
static int fmap_show_fw_main(const char *name, uint8_t *buf, uint32_t len,
			     void *data)
{
	struct bios_state_s *state = (struct bios_state_s *)data;

	if (!len) {
		printf("Firmware body:           %s <invalid>\n", name);
		return 1;
	}

	printf("Firmware body:           %s\n", name);
	printf("  Offset:                0x%08x\n",
	       state->area[state->c].offset);
	printf("  Size:                  0x%08x\n", len);

	state->area[state->c].is_valid = 1;

	return 0;
}

/* Functions to call to show the bios components */
static int (*fmap_show_fn[])(const char *name, uint8_t *buf, uint32_t len,
			       void *data) = {
	show_gbb_buf,
	fmap_show_fw_main,
	fmap_show_fw_main,
	show_fw_preamble_buf,
	show_fw_preamble_buf,
};
_Static_assert(ARRAY_SIZE(fmap_show_fn) == NUM_BIOS_COMPONENTS,
	       "Size of fmap_show_fn[] should match NUM_BIOS_COMPONENTS");

int ft_show_bios(const char *name, void *data)
{
	FmapHeader *fmap;
	FmapAreaHeader *ah = 0;
	char ah_name[FMAP_NAMELEN + 1];
	enum bios_component c;
	int retval = 0;
	struct bios_state_s state;
	int fd = -1;
	uint8_t *buf;
	uint32_t len;

	retval = futil_open_and_map_file(name, &fd, FILE_RO, &buf, &len);
	if (retval)
		return 1;

	memset(&state, 0, sizeof(state));

	printf("BIOS:                    %s\n", name);

	/* We've already checked, so we know this will work. */
	fmap = fmap_find(buf, len);
	for (c = 0; c < NUM_BIOS_COMPONENTS; c++) {
		/* We know one of these will work, too */
		if (fmap_find_by_name(buf, len, fmap, fmap_name[c], &ah)) {
			/* But the file might be truncated */
			fmap_limit_area(ah, len);
			/* The name is not necessarily null-terminated */
			snprintf(ah_name, sizeof(ah_name), "%s", ah->area_name);

			/* Update the state we're passing around */
			state.c = c;
			state.area[c].offset = ah->area_offset;
			state.area[c].buf = buf + ah->area_offset;
			state.area[c].len = ah->area_size;

			VB2_DEBUG("showing FMAP area %d (%s),"
				  " offset=0x%08x len=0x%08x\n",
				  c, ah_name, ah->area_offset, ah->area_size);

			/* Go look at it. */
			if (fmap_show_fn[c])
				retval += fmap_show_fn[c](ah_name,
							  state.area[c].buf,
							  state.area[c].len,
							  &state);
		}
	}

	futil_unmap_and_close_file(fd, FILE_RO, buf, len);
	return retval;
}

/** Sign functions **/

static int write_new_preamble(struct bios_area_s *vblock,
			      struct bios_area_s *fw_body,
			      struct vb2_private_key *signkey,
			      struct vb2_keyblock *keyblock)
{
	struct vb2_signature *body_sig = NULL;
	struct vb2_fw_preamble *preamble = NULL;
	int retval = 1;

	body_sig = vb2_calculate_signature(fw_body->buf, fw_body->len, signkey);
	if (!body_sig) {
		ERROR("Error calculating body signature\n");
		goto end;
	}

	preamble = vb2_create_fw_preamble(vblock->version,
			(struct vb2_packed_key *)sign_option.kernel_subkey,
			body_sig,
			signkey,
			vblock->flags);
	if (!preamble) {
		ERROR("Error creating firmware preamble.\n");
		free(body_sig);
		goto end;
	}

	if (keyblock->keyblock_size + preamble->preamble_size > vblock->len) {
		ERROR("Keyblock and preamble do not fit in VBLOCK.\n");
		goto end;
	}

	/* Write the new keyblock */
	uint32_t more = keyblock->keyblock_size;
	memcpy(vblock->buf, keyblock, more);
	/* and the new preamble */
	memcpy(vblock->buf + more, preamble, preamble->preamble_size);
	retval = 0;

end:
	free(preamble);
	free(body_sig);

	return retval;
}

static int write_loem(const char *ab, struct bios_area_s *vblock)
{
	char filename[PATH_MAX];
	int n;
	n = snprintf(filename, sizeof(filename), "%s/vblock_%s.%s",
		     sign_option.loemdir ? sign_option.loemdir : ".",
		     ab, sign_option.loemid);
	if (n >= sizeof(filename)) {
		fprintf(stderr, "LOEM args produce bogus filename\n");
		return 1;
	}

	FILE *fp = fopen(filename, "w");
	if (!fp) {
		fprintf(stderr, "Can't open %s for writing: %s\n",
			filename, strerror(errno));
		return 1;
	}

	if (1 != fwrite(vblock->buf, vblock->len, 1, fp)) {
		fprintf(stderr, "Can't write to %s: %s\n",
			filename, strerror(errno));
		fclose(fp);
		return 1;
	}
	if (fclose(fp)) {
		fprintf(stderr, "Failed closing loem output: %s\n",
			strerror(errno));
		return 1;
	}

	return 0;
}

/* This signs a full BIOS image after it's been traversed. */
static int sign_bios_at_end(struct bios_state_s *state)
{
	struct bios_area_s *vblock_a = &state->area[BIOS_FMAP_VBLOCK_A];
	struct bios_area_s *vblock_b = &state->area[BIOS_FMAP_VBLOCK_B];
	struct bios_area_s *fw_a = &state->area[BIOS_FMAP_FW_MAIN_A];
	struct bios_area_s *fw_b = &state->area[BIOS_FMAP_FW_MAIN_B];
	int retval = 0;

	if (!vblock_a->is_valid || !fw_a->is_valid) {
		fprintf(stderr, "Something's wrong. Not changing anything\n");
		return 1;
	}

	retval |= write_new_preamble(vblock_a, fw_a, sign_option.signprivate,
				     sign_option.keyblock);

	if (vblock_b->is_valid && fw_b->is_valid)
		retval |= write_new_preamble(vblock_b, fw_b,
					     sign_option.signprivate,
					     sign_option.keyblock);
	else
		INFO("BIOS image does not have %s. Signing only %s\n",
		     fmap_name[BIOS_FMAP_FW_MAIN_B],
		     fmap_name[BIOS_FMAP_FW_MAIN_A]);

	if (sign_option.loemid) {
		retval |= write_loem("A", vblock_a);
		if (vblock_b->is_valid)
			retval |= write_loem("B", vblock_b);
	}

	return retval;
}

/* Prepare firmware slot for signing.
   If fw_size is not zero, then it will be used as new length of signed area,
   for zero the length will be taken form FlashMap or preamble. */
static int prepare_slot(uint8_t *buf, uint32_t len, size_t fw_size,
			enum bios_component fw_c, enum bios_component vblock_c,
			struct bios_state_s *state)
{
	FmapHeader *fmap;
	FmapAreaHeader *ah;
	const char *fw_main_name = fmap_name[fw_c];
	const char *vblock_name = fmap_name[vblock_c];
	static uint8_t workbuf[VB2_FIRMWARE_WORKBUF_RECOMMENDED_SIZE]
		__attribute__((aligned(VB2_WORKBUF_ALIGN)));
	static struct vb2_workbuf wb;

	fmap = fmap_find(buf, len);
	vb2_workbuf_init(&wb, workbuf, sizeof(workbuf));

	VB2_DEBUG("Preparing areas: %s and %s\n", fw_main_name, vblock_name);

	/* FW_MAIN */
	if (!fmap_find_by_name(buf, len, fmap, fw_main_name, &ah)) {
		ERROR("%s area not found in FMAP\n", fw_main_name);
		return 1;
	}
	fmap_limit_area(ah, len);
	state->area[fw_c].buf = buf + ah->area_offset;
	state->area[fw_c].is_valid = 1;
	if (fw_size > ah->area_size) {
		ERROR("%s size is incorrect.\n", fmap_name[fw_c]);
		return 1;
	} else if (fw_size) {
		state->area[fw_c].len = fw_size;
	} else {
		WARN("%s does not contain CBFS. Trying to sign entire area.\n",
		     fmap_name[fw_c]);
		state->area[fw_c].len = ah->area_size;
	}

	/* Corresponding VBLOCK */
	if (!fmap_find_by_name(buf, len, fmap, vblock_name, &ah)) {
		ERROR("%s area not found in FMAP\n", vblock_name);
		return 1;
	}
	fmap_limit_area(ah, len);
	state->area[vblock_c].buf = buf + ah->area_offset;
	state->area[vblock_c].len = ah->area_size;

	struct vb2_keyblock *keyblock =
		(struct vb2_keyblock *)state->area[vblock_c].buf;
	int keyblock_valid = 0;

	if (vb2_verify_keyblock_hash(keyblock, state->area[vblock_c].len,
				     &wb) != VB2_SUCCESS) {
		WARN("%s keyblock is invalid.\n", vblock_name);
		goto end;
	}

	if (vb2_packed_key_looks_ok(&keyblock->data_key,
				    keyblock->data_key.key_offset +
					    keyblock->data_key.key_size)) {
		WARN("%s public key is invalid.\n", vblock_name);
		goto end;
	}

	struct vb2_public_key data_key;
	if (vb2_unpack_key(&data_key, &keyblock->data_key) != VB2_SUCCESS) {
		WARN("%s data key is invalid. Failed to parse.\n", vblock_name);
		goto end;
	}

	if (keyblock->keyblock_size + sizeof(struct vb2_fw_preamble) >
	    state->area[vblock_c].len) {
		ERROR("%s is invalid. Keyblock and preamble do not fit.\n",
		      vblock_name);
		goto end;
	}

	struct vb2_fw_preamble *preamble =
		(struct vb2_fw_preamble *)(state->area[vblock_c].buf +
					   keyblock->keyblock_size);
	if (vb2_verify_fw_preamble(preamble,
				   state->area[vblock_c].len -
					   keyblock->keyblock_size,
				   &data_key, &wb)) {
		WARN("%s preamble is invalid.\n", vblock_name);
		goto end;
	}

	if (fw_size == 0) {
		if (preamble->body_signature.data_size >
		    state->area[fw_c].len) {
			ERROR("%s says the firmware is larger than we have.\n",
			      vblock_name);
			goto end;
		} else {
			state->area[fw_c].len =
				preamble->body_signature.data_size;
		}
	}

	keyblock_valid = 1;

end:
	if (sign_option.flags_specified)
		state->area[vblock_c].flags = sign_option.flags;
	else if (keyblock_valid)
		state->area[vblock_c].flags = preamble->flags;
	else
		state->area[vblock_c].flags = 0;

	if (sign_option.version_specified)
		state->area[vblock_c].version = sign_option.version;
	else if (keyblock_valid)
		state->area[vblock_c].version = preamble->firmware_version;
	else
		state->area[vblock_c].version = 1;

	state->area[vblock_c].is_valid = 1;

	return 0;
}

int ft_sign_bios(const char *name, void *data)
{
	int retval = 0;
	struct bios_state_s state;
	int fd = -1;
	uint8_t *buf = NULL;
	uint32_t len = 0;
	size_t fw_main_a_size = 0;
	size_t fw_main_b_size = 0;

	bool fw_main_a_in_cbfs_mode =
		cbfstool_truncate(name, fmap_name[BIOS_FMAP_FW_MAIN_A],
				  &fw_main_a_size) == VB2_SUCCESS;

	bool fw_main_b_in_cbfs_mode =
		cbfstool_truncate(name, fmap_name[BIOS_FMAP_FW_MAIN_B],
				  &fw_main_b_size) == VB2_SUCCESS;

	if (fw_main_a_in_cbfs_mode)
		VB2_DEBUG("CBFS found in area %s\n",
			  fmap_name[BIOS_FMAP_FW_MAIN_A]);
	else
		VB2_DEBUG("CBFS not found in area %s\n",
			  fmap_name[BIOS_FMAP_FW_MAIN_A]);

	if (fw_main_b_in_cbfs_mode)
		VB2_DEBUG("CBFS found in area %s\n",
			  fmap_name[BIOS_FMAP_FW_MAIN_B]);
	else
		VB2_DEBUG("CBFS not found in area %s\n",
			  fmap_name[BIOS_FMAP_FW_MAIN_B]);

	if (futil_open_and_map_file(name, &fd, FILE_MODE_SIGN(sign_option),
				    &buf, &len))
		return 1;

	memset(&state, 0, sizeof(state));

	retval = prepare_slot(buf, len, fw_main_a_size, BIOS_FMAP_FW_MAIN_A,
			      BIOS_FMAP_VBLOCK_A, &state);
	if (retval)
		goto done;

	retval = prepare_slot(buf, len, fw_main_b_size, BIOS_FMAP_FW_MAIN_B,
			      BIOS_FMAP_VBLOCK_B, &state);
	if (retval && state.area[BIOS_FMAP_FW_MAIN_B].is_valid)
		goto done;

	retval = sign_bios_at_end(&state);
done:
	futil_unmap_and_close_file(fd, FILE_MODE_SIGN(sign_option), buf, len);
	return retval;
}

enum futil_file_type ft_recognize_bios_image(uint8_t *buf, uint32_t len)
{
	FmapHeader *fmap;

	fmap = fmap_find(buf, len);
	if (!fmap)
		return FILE_TYPE_UNKNOWN;

	/* Correct BIOS image should contain at least GBB, FW_MAIN_A and
	   VBLOCK_A areas. FW_MAIN_B and VBLOCK_B are optional, but will be
	   signed or shown if present. */
	const int gbb_and_a_slot_ok =
		fmap_find_by_name(buf, len, fmap, fmap_name[BIOS_FMAP_GBB],
				  0) != NULL &&
		fmap_find_by_name(buf, len, fmap,
				  fmap_name[BIOS_FMAP_FW_MAIN_A], 0) != NULL &&
		fmap_find_by_name(buf, len, fmap, fmap_name[BIOS_FMAP_VBLOCK_A],
				  0) != NULL;

	if (gbb_and_a_slot_ok)
		return FILE_TYPE_BIOS_IMAGE;

	return FILE_TYPE_UNKNOWN;
}
