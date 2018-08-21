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

#include "futility.h"
#include "host_misc.h"
#include "utility.h"

/* flashrom programmers. */
static const char * const PROG_HOST = "host",
		  * const PROG_EC = "ec",
		  * const PROG_PD = "ec:dev=1";

struct firmware_image {
	const char *programmer;
	uint32_t size;
	uint8_t *data;
	char *file_name;
	char *ro_version, *rw_version_a, *rw_version_b;
};

struct updater_config {
	struct firmware_image image, image_current;
	struct firmware_image ec_image, pd_image;
};

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

	return 0;
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
	memset(image, 0, sizeof(*image));
}

enum updater_error_codes {
	UPDATE_ERR_DONE,
	UPDATE_ERR_UNKNOWN,
};

static const char * const updater_error_messages[] = {
	[UPDATE_ERR_DONE] = "Done (no error)",
	[UPDATE_ERR_UNKNOWN] = "Unknown error.",
};

/*
 * The main updater to update system firmware using the configuration parameter.
 * Returns UPDATE_ERR_DONE if success, otherwise failure.
 */
static enum updater_error_codes update_firmware(struct updater_config *cfg)
{
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
}

/* Command line options */
static struct option const long_opts[] = {
	/* name  has_arg *flag val */
	{"image", 1, NULL, 'i'},
	{"ec_image", 1, NULL, 'e'},
	{"pd_image", 1, NULL, 'P'},
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
