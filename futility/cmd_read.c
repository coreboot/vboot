/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "futility.h"
#include "updater.h"

#ifdef USE_FLASHROM

/* Command line options */
static struct option const long_opts[] = {
	SHARED_FLASH_ARGS_LONGOPTS
	/* name  has_arg *flag val */
	{"help", 0, NULL, 'h'},
	{"debug", 0, NULL, 'd'},
	{"verbose", 0, NULL, 'v'},
	{NULL, 0, NULL, 0},
};

static const char *const short_opts = "hdv" SHARED_FLASH_ARGS_SHORTOPTS;

static void print_help(int argc, char *argv[])
{
	printf("\n"
	       "Usage:  " MYNAME " %s [OPTIONS] FILE\n"
	       "\n"
	       "Reads AP firmware to the FILE\n"
	       "-d, --debug         \tPrint debugging messages\n"
	       "-v, --verbose       \tPrint verbose messages\n"
	       SHARED_FLASH_ARGS_HELP,
	       argv[0]);
}

static int do_read(int argc, char *argv[])
{
	struct updater_config *cfg;
	struct updater_config_arguments args = {0};
	int i, errorcnt = 0, update_needed = 1;
	const char *prepare_ctrl_name = NULL;
	char *servo_programmer = NULL;
	char *output_file_name = NULL;

	cfg = updater_new_config();
	assert(cfg);

	opterr = 0;
	while ((i = getopt_long(argc, argv, short_opts, long_opts, 0)) != -1) {
		if (handle_flash_argument(&args, i, optarg))
			continue;
		switch (i) {
		case 'h':
			print_help(argc, argv);
			updater_delete_config(cfg);
			return !!errorcnt;
		case 'd':
			debugging_enabled = 1;
			args.verbosity++;
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
		fprintf(stderr, "\nERROR: missing output filename\n");
		print_help(argc, argv);
		return 1;
	}
	output_file_name = argv[optind++];
	if (optind < argc) {
		errorcnt++;
		ERROR("Unexpected arguments.\n");
	}

	if (!errorcnt && args.detect_servo) {
		servo_programmer = host_detect_servo(&prepare_ctrl_name);

		if (!servo_programmer)
			errorcnt++;
		else if (!args.programmer)
			args.programmer = servo_programmer;
	}

	if (!errorcnt)
		errorcnt += updater_setup_config(cfg, &args, &update_needed);
	if (!errorcnt && update_needed) {
		prepare_servo_control(prepare_ctrl_name, 1);
		int r = load_system_firmware(cfg, &cfg->image_current);
		/*
		 * Ignore a parse error as we still want to write the file
		 * out in that case
		 */
		if (r && r != IMAGE_PARSE_FAILURE)
			errorcnt++;
		prepare_servo_control(prepare_ctrl_name, 0);
	}
	if (!errorcnt)
		if (write_to_file("Wrote AP firmware to", output_file_name,
				  cfg->image_current.data,
				  cfg->image_current.size))
			errorcnt++;

	free(servo_programmer);
	updater_delete_config(cfg);
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
