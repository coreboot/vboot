/*
 * Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * A reference implementation for AP (and supporting images) firmware updater.
 */

#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "fmap.h"
#include "futility.h"
#include "host_misc.h"
#include "utility.h"

#define RETURN_ON_FAILURE(x) do {int r = (x); if (r) return r;} while (0);

/* FMAP section names. */
static const char * const FMAP_RO_FRID = "RO_FRID",
		  * const FMAP_RW_FWID = "RW_FWID",
		  * const FMAP_RW_FWID_A = "RW_FWID_A",
		  * const FMAP_RW_FWID_B = "RW_FWID_B";

/* flashrom programmers. */
static const char * const PROG_HOST = "host",
		  * const PROG_EMULATE = "dummy:emulate",
		  * const PROG_EC = "ec",
		  * const PROG_PD = "ec:dev=1";

enum flashrom_ops {
	FLASHROM_READ,
	FLASHROM_WRITE,
};

struct firmware_image {
	const char *programmer;
	char *emulation;
	uint32_t size;
	uint8_t *data;
	char *file_name;
	char *ro_version, *rw_version_a, *rw_version_b;
	FmapHeader *fmap_header;
};

struct firmware_section {
	uint8_t *data;
	size_t size;
};

struct updater_config {
	struct firmware_image image, image_current;
	struct firmware_image ec_image, pd_image;
	int emulate;
};

/*
 * A helper function to invoke flashrom(8) command.
 * Returns 0 if success, non-zero if error.
 */
static int host_flashrom(enum flashrom_ops op, const char *image_path,
			 const char *programmer, int verbose,
			 const char *section_name)
{
	char *command;
	const char *op_cmd, *dash_i = "-i", *postfix = "", *ignore_lock = "";
	int r;

	if (debugging_enabled)
		verbose = 1;

	if (!verbose)
		postfix = " >/dev/null 2>&1";

	if (!section_name || !*section_name) {
		dash_i = "";
		section_name = "";
	}

	if (strncmp(programmer, PROG_EMULATE, strlen(PROG_EMULATE)) == 0) {
		ignore_lock = "--ignore-lock";
	}

	switch (op) {
	case FLASHROM_READ:
		op_cmd = "-r";
		assert(image_path);
		break;

	case FLASHROM_WRITE:
		op_cmd = "-w";
		assert(image_path);
		break;

	default:
		assert(0);
		return -1;
	}

	/* TODO(hungte) In future we should link with flashrom directly. */
	r = asprintf(&command, "flashrom %s %s -p %s %s %s %s %s", op_cmd,
		     image_path, programmer, dash_i, section_name, ignore_lock,
		     postfix);

	if (r == -1) {
		/* `command` will be not available. */
		Error("%s: Cannot allocate memory for command to execute.\n",
		      __FUNCTION__);
		return -1;
	}

	if (verbose)
		printf("Executing: %s\n", command);

	r = system(command);
	free(command);
	return r;
}

/*
 * Finds a firmware section by given name in the firmware image.
 * If successful, return zero and *section argument contains the address and
 * size of the section; otherwise failure.
 */
static int find_firmware_section(struct firmware_section *section,
				 const struct firmware_image *image,
				 const char *section_name)
{
	FmapAreaHeader *fah = NULL;
	uint8_t *ptr;

	section->data = NULL;
	section->size = 0;
	ptr = fmap_find_by_name(
			image->data, image->size, image->fmap_header,
			section_name, &fah);
	if (!ptr)
		return -1;
	section->data = (uint8_t *)ptr;
	section->size = fah->area_size;
	return 0;
}

/*
 * Returns true if the given FMAP section exists in the firmware image.
 */
static int firmware_section_exists(const struct firmware_image *image,
				   const char *section_name)
{
	struct firmware_section section;
	find_firmware_section(&section, image, section_name);
	return section.data != NULL;
}

/*
 * Loads the firmware information from an FMAP section in loaded firmware image.
 * The section should only contain ASCIIZ string as firmware version.
 * If successful, the return value is zero and *version points to a newly
 * allocated string as firmware version (caller must free it); otherwise
 * failure.
 */
static int load_firmware_version(struct firmware_image *image,
				 const char *section_name,
				 char **version)
{
	struct firmware_section fwid;
	find_firmware_section(&fwid, image, section_name);
	if (fwid.size) {
		*version = strndup((const char*)fwid.data, fwid.size);
		return 0;
	}
	*version = strdup("");
	return -1;
}

/*
 * Loads a firmware image from file.
 * Returns 0 on success, otherwise failure.
 */
static int load_image(const char *file_name, struct firmware_image *image)
{
	Debug("%s: Load image file from %s...\n", __FUNCTION__, file_name);

	if (vb2_read_file(file_name, &image->data, &image->size) != VB2_SUCCESS)
	{
		Error("%s: Failed to load %s\n", __FUNCTION__, file_name);
		return -1;
	}

	Debug("%s: Image size: %d\n", __FUNCTION__, image->size);
	assert(image->data);
	image->file_name = strdup(file_name);

	image->fmap_header = fmap_find(image->data, image->size);
	if (!image->fmap_header) {
		Error("Invalid image file (missing FMAP): %s\n", file_name);
		return -1;
	}

	if (!firmware_section_exists(image, FMAP_RO_FRID)) {
		Error("Does not look like VBoot firmware image: %s", file_name);
		return -1;
	}

	load_firmware_version(image, FMAP_RO_FRID, &image->ro_version);
	if (firmware_section_exists(image, FMAP_RW_FWID_A)) {
		char **a = &image->rw_version_a, **b = &image->rw_version_b;
		load_firmware_version(image, FMAP_RW_FWID_A, a);
		load_firmware_version(image, FMAP_RW_FWID_B, b);
	} else if (firmware_section_exists(image, FMAP_RW_FWID)) {
		char **a = &image->rw_version_a, **b = &image->rw_version_b;
		load_firmware_version(image, FMAP_RW_FWID, a);
		load_firmware_version(image, FMAP_RW_FWID, b);
	} else {
		Error("Unsupported VBoot firmware (no RW ID): %s", file_name);
	}
	return 0;
}

/*
 * Loads and emulates system firmware by an image file.
 * This will set a emulation programmer in image->emulation so flashrom
 * can access the file as system firmware storage.
 * Returns 0 if success, non-zero if error.
 */
static int emulate_system_image(const char *file_name,
				struct firmware_image *image)
{
	if (load_image(file_name, image))
		return -1;

	if (asprintf(&image->emulation,
		     "%s=VARIABLE_SIZE,image=%s,size=%u",
		     PROG_EMULATE, file_name, image->size) < 0) {
		Error("%s: Failed to allocate buffer for programmer: %s.\n",
		      __FUNCTION__, file_name);
		return -1;
	}
	return 0;
}

/*
 * Loads the active system firmware image (usually from SPI flash chip).
 * Returns 0 if success, non-zero if error.
 */
static int load_system_image(struct updater_config *cfg,
			     struct firmware_image *image)
{
	/* TODO(hungte) replace by mkstemp */
	const char *tmp_file = "/tmp/.fwupdate.read";

	RETURN_ON_FAILURE(host_flashrom(
			FLASHROM_READ, tmp_file, image->programmer, 0, NULL));
	return load_image(tmp_file, image);
}

/*
 * Frees the allocated resource from a firmware image object.
 */
static void free_image(struct firmware_image *image)
{
	free(image->data);
	free(image->file_name);
	free(image->ro_version);
	free(image->rw_version_a);
	free(image->rw_version_b);
	free(image->emulation);
	memset(image, 0, sizeof(*image));
}

enum updater_error_codes {
	UPDATE_ERR_DONE,
	UPDATE_ERR_NO_IMAGE,
	UPDATE_ERR_SYSTEM_IMAGE,
	UPDATE_ERR_UNKNOWN,
};

static const char * const updater_error_messages[] = {
	[UPDATE_ERR_DONE] = "Done (no error)",
	[UPDATE_ERR_NO_IMAGE] = "No image to update; try specify with -i.",
	[UPDATE_ERR_SYSTEM_IMAGE] = "Cannot load system active firmware.",
	[UPDATE_ERR_UNKNOWN] = "Unknown error.",
};

/*
 * The main updater to update system firmware using the configuration parameter.
 * Returns UPDATE_ERR_DONE if success, otherwise failure.
 */
static enum updater_error_codes update_firmware(struct updater_config *cfg)
{
	struct firmware_image *image_from = &cfg->image_current,
			      *image_to = &cfg->image;
	if (!image_to->data)
		return UPDATE_ERR_NO_IMAGE;

	printf(">> Target image: %s (RO:%s, RW/A:%s, RW/B:%s).\n",
	       image_to->file_name, image_to->ro_version,
	       image_to->rw_version_a, image_to->rw_version_b);

	if (!image_from->data) {
		/*
		 * TODO(hungte) Read only RO_SECTION, VBLOCK_A, VBLOCK_B,
		 * RO_VPD, RW_VPD, RW_NVRAM, RW_LEGACY.
		 */
		printf("Loading current system firmware...\n");
		if (load_system_image(cfg, image_from) != 0)
			return UPDATE_ERR_SYSTEM_IMAGE;
	}
	printf(">> Current system: %s (RO:%s, RW/A:%s, RW/B:%s).\n",
	       image_from->file_name, image_from->ro_version,
	       image_from->rw_version_a, image_from->rw_version_b);

	return UPDATE_ERR_DONE;
}

/*
 * Releases all loaded images in an updater configuration object.
 */
static void unload_updater_config(struct updater_config *cfg)
{
	free_image(&cfg->image);
	free_image(&cfg->image_current);
	free_image(&cfg->ec_image);
	free_image(&cfg->pd_image);
	cfg->emulate = 0;
}

/* Command line options */
static struct option const long_opts[] = {
	/* name  has_arg *flag val */
	{"image", 1, NULL, 'i'},
	{"ec_image", 1, NULL, 'e'},
	{"pd_image", 1, NULL, 'P'},
	{"emulate", 1, NULL, 'E'},
	{"help", 0, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static const char * const short_opts = "hi:e:";

static void print_help(int argc, char *argv[])
{
	printf("\n"
		"Usage:  " MYNAME " %s [OPTIONS]\n"
		"\n"
		"-i, --image=FILE    \tAP (host) firmware image (image.bin)\n"
		"-e, --ec_image=FILE \tEC firmware image (i.e, ec.bin)\n"
		"    --pd_image=FILE \tPD firmware image (i.e, pd.bin)\n"
		"\n"
		"Debugging and testing options:\n"
		"    --emulate=FILE  \tEmulate system firmware using file\n"
		"",
		argv[0]);
}

static int do_update(int argc, char *argv[])
{
	int i, errorcnt = 0;
	struct updater_config cfg = {
		.image = { .programmer = PROG_HOST, },
		.image_current = { .programmer = PROG_HOST, },
		.ec_image = { .programmer = PROG_EC, },
		.pd_image = { .programmer = PROG_PD, },
	};

	printf(">> Firmware updater started.\n");

	opterr = 0;
	while ((i = getopt_long(argc, argv, short_opts, long_opts, 0)) != -1) {
		switch (i) {
		case 'i':
			errorcnt += load_image(optarg, &cfg.image);
			break;
		case 'e':
			errorcnt += load_image(optarg, &cfg.ec_image);
			break;
		case 'P':
			errorcnt += load_image(optarg, &cfg.pd_image);
			break;
		case 'E':
			cfg.emulate = 1;
			errorcnt += emulate_system_image(
					optarg, &cfg.image_current);
			/* Both image and image_current need emulation. */
			if (!errorcnt) {
				cfg.image.emulation = strdup(
						cfg.image_current.emulation);
			}
			break;

		case 'h':
			print_help(argc, argv);
			return !!errorcnt;
		case '?':
			errorcnt++;
			if (optopt)
				Error("Unrecognized option: -%c\n", optopt);
			else if (argv[optind - 1])
				Error("Unrecognized option (possibly '%s')\n",
				      argv[optind - 1]);
			else
				Error("Unrecognized option.\n");
			break;
		default:
			errorcnt++;
			Error("Failed parsing options.\n");
		}
	}
	if (optind < argc) {
		errorcnt++;
		Error("Unexpected arguments.\n");
	}
	if (!errorcnt) {
		int r = update_firmware(&cfg);
		if (r != UPDATE_ERR_DONE) {
			r = Min(r, UPDATE_ERR_UNKNOWN);
			Error("%s\n", updater_error_messages[r]);
			errorcnt++;
		}
	}
	printf(">> %s: Firmware updater %s.\n",
	       errorcnt ? "FAILED": "DONE",
	       errorcnt ? "stopped due to error" : "exited successfully");

	unload_updater_config(&cfg);
	return !!errorcnt;
}

DECLARE_FUTIL_COMMAND(update, do_update, VBOOT_VERSION_ALL,
		      "Update system firmware");
