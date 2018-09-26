/*
 * Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * The board-specific quirks needed by firmware updater.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "updater.h"
#include "host_misc.h"

struct quirks_record {
	const char * const match;
	const char * const quirks;
};

static const struct quirks_record quirks_records[] = {
	{ .match = "Google_Whirlwind.", .quirks = "enlarge_image" },
	{ .match = "Google_Arkham.", .quirks = "enlarge_image" },
	{ .match = "Google_Storm.", .quirks = "enlarge_image" },
	{ .match = "Google_Gale.", .quirks = "enlarge_image" },

	{ .match = "Google_Chell.", .quirks = "unlock_me_for_update" },
	{ .match = "Google_Lars.", .quirks = "unlock_me_for_update" },
	{ .match = "Google_Sentry.", .quirks = "unlock_me_for_update" },
	{ .match = "Google_Asuka.", .quirks = "unlock_me_for_update" },
	{ .match = "Google_Caroline.", .quirks = "unlock_me_for_update" },
	{ .match = "Google_Cave.", .quirks = "unlock_me_for_update" },

	{ .match = "Google_Poppy.", .quirks = "min_platform_version=6" },
	{ .match = "Google_Scarlet.", .quirks = "min_platform_version=1" },
};

/*
 * Helper function to write a firmware image into file on disk.
 * Returns the result from vb2_write_file.
 */
static int write_image(const char *file_path, struct firmware_image *image)
{
	return vb2_write_file(file_path, image->data, image->size);
}

/* Preserves meta data and reload image contents from given file path. */
static int reload_image(const char *file_path, struct firmware_image *image)
{
	const char *programmer = image->programmer;
	free_image(image);
	image->programmer = programmer;
	return load_image(file_path, image);
}

/*
 * Quirk to enlarge a firmware image to match flash size. This is needed by
 * devices using multiple SPI flash with different sizes, for example 8M and
 * 16M. The image_to will be padded with 0xFF using the size of image_from.
 * Returns 0 on success, otherwise failure.
 */
static int quirk_enlarge_image(struct updater_config *cfg)
{
	struct firmware_image *image_from = &cfg->image_current,
			      *image_to = &cfg->image;
	const char *tmp_path;
	size_t to_write;
	FILE *fp;

	if (image_from->size <= image_to->size)
		return 0;

	tmp_path = create_temp_file(cfg);
	if (!tmp_path)
		return -1;

	DEBUG("Resize image from %u to %u.", image_to->size, image_from->size);
	to_write = image_from->size - image_to->size;
	write_image(tmp_path, image_to);
	fp = fopen(tmp_path, "ab");
	if (!fp) {
		ERROR("Cannot open temporary file %s.", tmp_path);
		return -1;
	}
	while (to_write-- > 0)
		fputc('\xff', fp);
	fclose(fp);
	return reload_image(tmp_path, image_to);
}

/*
 * Quirk to unlock a firmware image with SI_ME (management engine) when updating
 * so the system has a chance to make sure SI_ME won't be corrupted on next boot
 * before locking the Flash Master values in SI_DESC.
 * Returns 0 on success, otherwise failure.
 */
static int quirk_unlock_me_for_update(struct updater_config *cfg)
{
	struct firmware_section section;
	struct firmware_image *image_to = &cfg->image;
	const int flash_master_offset = 128;
	const uint8_t flash_master[] = {
		0x00, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff,
		0xff, 0xff
	};

	find_firmware_section(&section, image_to, FMAP_SI_DESC);
	if (section.size < flash_master_offset + ARRAY_SIZE(flash_master))
		return 0;
	if (memcmp(section.data + flash_master_offset, flash_master,
		   ARRAY_SIZE(flash_master)) == 0) {
		DEBUG("Target ME not locked.");
		return 0;
	}
	/*
	 * b/35568719: We should only update with unlocked ME and let
	 * board-postinst lock it.
	 */
	printf("%s: Changed Flash Master Values to unlocked.\n", __FUNCTION__);
	memcpy(section.data + flash_master_offset, flash_master,
	       ARRAY_SIZE(flash_master));
	return 0;
}

/*
 * Checks and returns 0 if the platform version of current system is larger
 * or equal to given number, otherwise non-zero.
 */
static int quirk_min_platform_version(struct updater_config *cfg)
{
	int min_version = get_config_quirk(QUIRK_MIN_PLATFORM_VERSION, cfg);
	int platform_version = get_system_property(SYS_PROP_PLATFORM_VER, cfg);

	DEBUG("Minimum required version=%d, current platform version=%d",
	      min_version, platform_version);

	if (platform_version >= min_version)
		return 0;
	ERROR("Need platform version >= %d (current is %d). "
	      "This firmware will only run on newer systems.",
	      min_version, platform_version);
	return -1;
}

/*
 * Registers known quirks to a updater_config object.
 */
void updater_register_quirks(struct updater_config *cfg)
{
	struct quirk_entry *quirks;

	assert(ARRAY_SIZE(cfg->quirks) == QUIRK_MAX);
	quirks = &cfg->quirks[QUIRK_ENLARGE_IMAGE];
	quirks->name = "enlarge_image";
	quirks->help = "Enlarge firmware image by flash size.";
	quirks->apply = quirk_enlarge_image;

	quirks = &cfg->quirks[QUIRK_MIN_PLATFORM_VERSION];
	quirks->name = "min_platform_version";
	quirks->help = "Minimum compatible platform version "
			"(also known as Board ID version).";
	quirks->apply = quirk_min_platform_version;

	quirks = &cfg->quirks[QUIRK_UNLOCK_ME_FOR_UPDATE];
	quirks->name = "unlock_me_for_update";
	quirks->help = "b/35568719; only lock management engine in "
			"board-postinst.";
	quirks->apply = quirk_unlock_me_for_update;

}

/*
 * Gets the default quirk config string for target image.
 * Returns a string (in same format as --quirks) to load or NULL if no quirks.
 */
const char * const updater_get_default_quirks(struct updater_config *cfg)
{
	const char *pattern = cfg->image.ro_version;
	int i;

	if (!pattern) {
		DEBUG("Cannot identify system for default quirks.");
		return NULL;
	}

	for (i = 0; i < ARRAY_SIZE(quirks_records); i++) {
		const struct quirks_record *r = &quirks_records[i];
		if (strncmp(r->match, pattern, strlen(r->match)) != 0)
		    continue;
		DEBUG("Found system default quirks: %s", r->quirks);
		return r->quirks;
	}
	return NULL;
}
