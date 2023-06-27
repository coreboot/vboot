/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "flash_helpers.h"
#include "futility.h"
#include "updater.h"

#ifdef USE_FLASHROM

/* Command line options */
static struct option const long_opts[] = {
	SHARED_FLASH_ARGS_LONGOPTS
	/* name  has_arg *flag val */
	{"help", 0, NULL, 'h'},
	{"debug", 0, NULL, 'd'},
	{"region", 1, NULL, 'r'},
	{"verbose", 0, NULL, 'v'},
	{NULL, 0, NULL, 0},
};

static const char *const short_opts = "hdrv" SHARED_FLASH_ARGS_SHORTOPTS;

static void print_help(int argc, char *argv[])
{
	printf("\n"
	       "Usage:  " MYNAME " %s [OPTIONS] FILE\n"
	       "\n"
	       "Reads AP firmware to the FILE\n"
	       "-d, --debug         \tPrint debugging messages\n"
	       "-r, --region        \tThe comma delimited regions to read (optional)\n"
	       "-v, --verbose       \tPrint verbose messages\n"
	       SHARED_FLASH_ARGS_HELP,
	       argv[0]);
}

static int read_flash_to_file(struct updater_config *cfg, const char *path,
			const char *regions)
{
	/* full image read. */
	if (!regions) {
		if (write_to_file("Wrote AP firmware to", path,
				  cfg->image_current.data,
				  cfg->image_current.size)) {
			return -1;
		}
		return 0;
	}

	char *savedptr;
	char *region = strtok_r((char *)regions, ",", &savedptr);
	while (region) {
		struct firmware_section section;
		if (find_firmware_section(&section, &cfg->image_current,
					  region)) {
			ERROR("Region '%s' not found in image.\n", region);
			return -1;
		}
		const size_t fpath_sz = strlen(path) + strlen(region) + 1; /* +1 for underscore. */
		char *fpath = calloc(1, fpath_sz + 1); /* +1 for null termination. */
		if (!fpath)
			return -1;
		snprintf(fpath, fpath_sz + 1, "%s_%s", path, region);
		if (write_to_file("Wrote AP firmware region to",
				  fpath, section.data, section.size)) {
			free(fpath);
			return -1;
		}
		free(fpath);

		/* next region to read.. */
		region = strtok_r(NULL, ",", &savedptr);
	}

	return 0;
}

static int do_read(int argc, char *argv[])
{
	struct updater_config *cfg = NULL;
	struct updater_config_arguments args = {0};
	int i, errorcnt = 0;
	char *regions = NULL;

	opterr = 0;
	while ((i = getopt_long(argc, argv, short_opts, long_opts, 0)) != -1) {
		if (handle_flash_argument(&args, i, optarg))
			continue;
		switch (i) {
		case 'h':
			print_help(argc, argv);
			return 0;
		case 'd':
			debugging_enabled = 1;
			args.verbosity++;
			break;
		case 'r':
			regions = optarg;
			break;
		case 'v':
			args.verbosity++;
			break;
		case '?':
			errorcnt++;
			if (optopt)
				ERROR("Unrecognized option: -%c\n", optopt);
			else if (argv[optind - 1])
				ERROR("Unrecognized option (possibly '%s')\n",
				      argv[optind - 1]);
			else
				ERROR("Unrecognized option.\n");
			break;
		default:
			errorcnt++;
			ERROR("Failed parsing options.\n");
		}
	}
	if (argc - optind < 1) {
		ERROR("Missing output filename\n");
		print_help(argc, argv);
		return 1;
	}
	const char *output_file_name = argv[optind++];
	if (optind < argc) {
		ERROR("Unexpected arguments.\n");
		return 1;
	}

	if (setup_flash(&cfg, &args, false)) {
		ERROR("While preparing flash\n");
		return 1;
	}

	int r = load_system_firmware(cfg, &cfg->image_current);
	/*
	 * Ignore a parse error as we still want to write the file
	 * out in that case
	 */
	if (r && r != IMAGE_PARSE_FAILURE) {
		errorcnt++;
		goto err;
	}

	if (read_flash_to_file(cfg, output_file_name, regions) < 0)
		errorcnt++;

err:
	teardown_flash(cfg);
	return !!errorcnt;
}
#define CMD_HELP_STR "Read AP firmware"

#else /* USE_FLASHROM */

static int do_read(int argc, char *argv[])
{
	FATAL(MYNAME " was built without flashrom support, `read` command unavailable!\n");
	return -1;
}
#define CMD_HELP_STR "Read system firmware (unavailable in this build)"

#endif /* !USE_FLASHROM */

DECLARE_FUTIL_COMMAND(read, do_read, VBOOT_VERSION_ALL, CMD_HELP_STR);
