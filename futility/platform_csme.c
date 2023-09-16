/* Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Utility functions for Intel Flash Descriptor (ifd) and the 'Converged
 * Security and Manageability Engine' (CSME).
 */

#include <string.h>
#include "platform_csme.h"
#include "updater.h"

/* Structure from coreboot util/ifdtool/ifdtool.h */
// flash descriptor
struct fdbar {
	uint32_t flvalsig;
	uint32_t flmap0;
	uint32_t flmap1;
	uint32_t flmap2;
	uint32_t flmap3; // Exist for 500 series onwards
} __attribute__((packed));

// flash master
struct fmba {
	uint32_t flmstr1;
	uint32_t flmstr2;
	uint32_t flmstr3;
	uint32_t flmstr4;
	uint32_t flmstr5;
	uint32_t flmstr6;
} __attribute__((packed));

static struct fmba * const find_fmba(const struct firmware_image *image) {
	struct firmware_section section;
	const uint32_t signature = 0x0FF0A55A;
	const struct fdbar *fd;

	if (!image->size)
		return NULL;
	if (find_firmware_section(&section, image, FMAP_SI_DESC))
		return NULL;

	if (section.size < sizeof(*fd) + sizeof(struct fmba))
		return NULL;
	fd = memmem(section.data, section.size - sizeof(*fd),
		    (const void *)&signature, sizeof(signature));
	if (!fd)
		return NULL;

	const uint64_t offset = (fd->flmap1 & 0xff) << 4;
	if (offset + sizeof(struct fmba) > section.size)
		return NULL;

	return (struct fmba * const)(section.data + offset);
}

static bool is_flmstr1_locked(const struct fmba * const fmba)
{
	/*
	 * (from idftool.c) There are multiple versions of IFD but there are no
	 * version tags in the descriptor. Starting from Apollolake all
	 * Chromebooks should be using IFD v2 so we'll check only the v2 values.
	 * V2: unlocked FLMSTR is 0xfffffff?? (31:20=write, 19:8=read)
	 */
	const bool is_locked = (fmba->flmstr1 & 0xfff00000) != 0xfff00000;
	VB2_DEBUG("FLMSTR1 = %#08x (%s)\n", fmba->flmstr1, is_locked ? "LOCKED" : "unlocked");

	return is_locked;
}

bool is_flash_descriptor_locked(const struct firmware_image *image)
{
	/*
	 * TODO(roccochen) When the flashrom supports exporting FRAP,
	 * we can replace the parsing of FLMSTRs to rely on FRAP for deciding if
	 * AP RO is locked or not.
	 */
	const struct fmba *fmba = find_fmba(image);
	if (!fmba) {
		WARN("Failed to find flash master. Assuming unlocked.\n");
		return false;
	}
	return is_flmstr1_locked(fmba);
}

/*
 * Unlock the flash descriptor by rewriting the FLMSTR1.
 *
 * Returns 0 on success, any other values for failure.
 */
static int unlock_flmstrs(struct firmware_image *image,
			  uint32_t flmstr1, uint32_t flmstr2, uint32_t flmstr3)
{
	struct fmba * const fmba = find_fmba(image);

	if (!fmba) {
		ERROR("Failed to unlock the Flash Master values.\n");
		return -1;
	}

	if (fmba->flmstr1 == flmstr1 &&
	    fmba->flmstr2 == flmstr2 &&
	    fmba->flmstr3 == flmstr3) {
		VB2_DEBUG("No need to change the Flash Master values.\n");
		return 0;
	}
	VB2_DEBUG("Change flmstr1=%#08x->%#08x\n", fmba->flmstr1, flmstr1);
	VB2_DEBUG("Change flmstr2=%#08x->%#08x\n", fmba->flmstr2, flmstr2);
	VB2_DEBUG("Change flmstr3=%#08x->%#08x\n", fmba->flmstr3, flmstr3);

	fmba->flmstr1 = flmstr1;
	fmba->flmstr2 = flmstr2;
	fmba->flmstr3 = flmstr3;
	INFO("Changed Flash Master values to unlocked.\n");
	return 0;
}

/*
 * Unlock the flash descriptor for Skylake and Kabylake platforms.
 *
 * The FLMSTR settings are dedicated for the Skylake (glados) and Kabylake (eve)
 * platforms, and are slightly different to those in the common
 * unlock_flash_master() function. The common settings might work, but we keep
 * these as is for now to avoid breaking things on old devices. These settings
 * are also hardcoded in postinst scripts (e.g. https://crrev.com/i/252522), so
 * those would probably need to be changed too.
 */
int unlock_csme_eve(struct firmware_image *image)
{
	return unlock_flmstrs(image, 0xffffff00, 0xffffff00, 0xffffff00);
}
