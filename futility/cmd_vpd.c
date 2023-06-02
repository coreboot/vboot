/* Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>

#include "flash_helpers.h"
#include "futility.h"
#include "subprocess.h"
#include "updater.h"

#ifdef USE_FLASHROM
#define FLASH_ARG_HELP                                                         \
	"    --flash         \tRead from and write to flash"                   \
	", ignore file arguments.\n"
#define FLASH_MORE_HELP                                                        \
	"The following options modify the "                                    \
	"behaviour of flashing. Presence of any of these implies "             \
	"--flash.\n"                                                           \
	SHARED_FLASH_ARGS_HELP                                                 \
	"\n"
#define CMD_HELP_STR "Read VPD data from system firmware or file"
#else /* USE_FLASHROM */
#define FLASH_ARG_HELP
#define FLASH_MORE_HELP
#define CMD_HELP_STR "Read VPD data from system firmware (unavailable in this build) or file"
#endif /* !USE_FLASHROM */

#define COMMAND_BUFFER_SIZE 256

/* Command line options */
enum {
	OPT_FLASH = 0x1000,
};

static struct option const long_opts[] = {
	SHARED_FLASH_ARGS_LONGOPTS
	/* name  has_arg *flag val */
	{"help", 0, NULL, 'h'},
	{"debug", 0, NULL, 'd'},
	{"verbose", 0, NULL, 'v'},
	{"flash", 0, NULL, OPT_FLASH},
	{NULL, 0, NULL, 0},
};

static const char *const short_opts = "hdv" SHARED_FLASH_ARGS_SHORTOPTS;

static void print_help(int argc, char *argv[])
{
	printf("\n"
	       "Usage:  " MYNAME " %s [OPTIONS] [image_file]\n"
	       "\n"
	       "Reads VPD data from system firmware\n"
	       "-d, --debug         \tPrint debugging messages\n"
	       "-v, --verbose       \tPrint verbose messages\n"
	       FLASH_ARG_HELP
	       "\n"
	       FLASH_MORE_HELP,
	       argv[0]);
}

static int vpd_get_list(const char *fpath, char *buf, size_t buf_size)
{
	const char *const command[] = {
		"/usr/sbin/vpd",
		"-l",
		"-f",
		fpath,
		NULL,
	};
	struct subprocess_target output = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = buf,
			.size = buf_size,
		},
	};

	int status = subprocess_run(command, &subprocess_null, &output, NULL);
	if (status) {
		ERROR("VPD invocation failed. (exit status %d)\n", status);
		return -1;
	}

	return 0;
}

static int get_vpd_from_file(const char *fpath)
{
	/* The vpd command does not have large output. */
	char buf[COMMAND_BUFFER_SIZE];
	int rv = vpd_get_list(fpath, buf, ARRAY_SIZE(buf));
	if (rv) {
		ERROR("No valid VPD data found from flash.\n");
		return -1;
	}
	/* It is fine if VPD is empty or the partition is not formatted. */
	if (!buf[0])
		WARN("VPD is empty.\n");
	else
		printf("%s", buf);

	return 0;
}

static int read_vpd_from_flash(struct updater_config *cfg)
{
#ifdef USE_FLASHROM
	/* always need to read the FMAP to find regions. */
	const char *const regions[] = {FMAP_RO_FMAP, FMAP_RO_VPD, FMAP_RW_VPD};

	/* Read only the specified regions */
	if (flashrom_read_image(&cfg->image_current, regions,
				ARRAY_SIZE(regions), cfg->verbosity + 1)) {
		return -1;
	}

	const char *fpath = create_temp_file(&cfg->tempfiles);
	if (!fpath)
		return -1;

	if (write_to_file(NULL, fpath,
			  cfg->image_current.data,
			  cfg->image_current.size)) {
		return -1;
	}

	return get_vpd_from_file(fpath);
#else
	return -1;
#endif /* USE_FLASHROM */
}

static int do_vpd(int argc, char *argv[])
{
	struct updater_config *cfg = NULL;
	struct updater_config_arguments args = {0};
	int i, errorcnt = 0;

	opterr = 0;
	while ((i = getopt_long(argc, argv, short_opts, long_opts, 0)) != -1) {
#ifdef USE_FLASHROM
		if (handle_flash_argument(&args, i, optarg))
			continue;
#endif /* USE_FLASHROM */
		switch (i) {
		case 'h':
			print_help(argc, argv);
			return 0;
		case 'd':
			debugging_enabled = 1;
			args.verbosity++;
			break;
		case 'v':
			args.verbosity++;
			break;
		case OPT_FLASH:
#ifndef USE_FLASHROM
			ERROR("futility was built without flashrom support\n");
			return 1;
#endif /* USE_FLASHROM */
			args.use_flash = 1;
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

	if (args.use_flash) {
		if (optind < argc) {
			print_help(argc, argv);
			ERROR("Unexpected arguments.\n");
			return 1;
		}

		if (setup_flash(&cfg, &args)) {
			ERROR("While preparing flash\n");
			return 1;
		}

		if (read_vpd_from_flash(cfg) < 0)
			errorcnt++;

		teardown_flash(cfg);
	} else {
		if (argc - optind < 1) {
			print_help(argc, argv);
			ERROR("Missing input filename\n");
			return 1;
		}
		char *infile = argv[optind++];
		if (access(infile, F_OK | R_OK) != 0) {
			ERROR("File %s does not exist or is not readable.\n",
			      infile);
			return 1;
		}
		if (get_vpd_from_file(infile) < 0)
			errorcnt++;
	}

	return !!errorcnt;
}

DECLARE_FUTIL_COMMAND(vpd, do_vpd, VBOOT_VERSION_ALL, CMD_HELP_STR);
