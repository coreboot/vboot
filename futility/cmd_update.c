/*
 * Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * The command line tool to invoke firmware updater.
 */

#include <assert.h>
#include <stdio.h>
#include <getopt.h>

#include "futility.h"
#include "updater.h"
#include "utility.h"


/* Command line options */
static struct option const long_opts[] = {
	/* name  has_arg *flag val */
	{"image", 1, NULL, 'i'},
	{"ec_image", 1, NULL, 'e'},
	{"pd_image", 1, NULL, 'P'},
	{"try", 0, NULL, 't'},
	{"archive", 1, NULL, 'a'},
	{"quirks", 1, NULL, 'f'},
	{"list-quirks", 0, NULL, 'L'},
	{"mode", 1, NULL, 'm'},
	{"factory", 0, NULL, 'Y'},
	{"force", 0, NULL, 'F'},
	{"programmer", 1, NULL, 'p'},
	{"wp", 1, NULL, 'W'},
	{"emulate", 1, NULL, 'E'},
	{"sys_props", 1, NULL, 'S'},
	{"debug", 0, NULL, 'd'},
	{"verbose", 0, NULL, 'v'},
	{"help", 0, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static const char * const short_opts = "hi:e:ta:m:p:dv";

static void print_help(int argc, char *argv[])
{
	printf("\n"
		"Usage:  " MYNAME " %s [OPTIONS]\n"
		"\n"
		"-i, --image=FILE    \tAP (host) firmware image (image.bin)\n"
		"-e, --ec_image=FILE \tEC firmware image (i.e, ec.bin)\n"
		"    --pd_image=FILE \tPD firmware image (i.e, pd.bin)\n"
		"-t, --try           \tTry A/B update on reboot if possible\n"
		"-a, --archive=PATH  \tRead resources from archive\n"
		"-p, --programmer=PRG\tChange AP (host) flashrom programmer\n"
		"    --quirks=LIST   \tSpecify the quirks to apply\n"
		"    --list-quirks   \tPrint all available quirks\n"
		"\n"
		"Legacy and compatibility options:\n"
		"-m, --mode=MODE     \tRun updater in given mode\n"
		"    --factory       \tAlias for --mode=factory\n"
		"    --force         \tForce update (skip checking contents)\n"
		"\n"
		"Debugging and testing options:\n"
		"    --wp=1|0        \tSpecify write protection status\n"
		"    --emulate=FILE  \tEmulate system firmware using file\n"
		"    --sys_props=LIST\tList of system properties to override\n"
		"-d, --debug         \tPrint debugging messages\n"
		"-v, --verbose       \tPrint verbose messages\n"
		"",
		argv[0]);
}

static int do_update(int argc, char *argv[])
{
	const char *opt_image = NULL,
	           *opt_ec_image = NULL,
		   *opt_pd_image = NULL,
		   *opt_archive = NULL,
		   *opt_quirks = NULL,
		   *opt_mode = NULL,
		   *opt_programmer = NULL,
		   *opt_emulation = NULL,
		   *opt_sys_props = NULL,
		   *opt_write_protection = NULL;
	int opt_is_factory = 0, opt_try_update = 0, opt_force_update = 0,
	    opt_verbosity = 0;
	int i, errorcnt = 0;
	struct updater_config *cfg;

	printf(">> Firmware updater started.\n");
	cfg = updater_new_config();
	assert(cfg);

	opterr = 0;
	while ((i = getopt_long(argc, argv, short_opts, long_opts, 0)) != -1) {
		switch (i) {
		case 'i':
			opt_image = optarg;
			break;
		case 'e':
			opt_ec_image = optarg;
			break;
		case 'P':
			opt_pd_image = optarg;
			break;
		case 't':
			opt_try_update = 1;
			break;
		case 'a':
			opt_archive = optarg;
			break;
		case 'f':
			opt_quirks = optarg;
			break;
		case 'L':
			updater_list_config_quirks(cfg);
			return 0;
		case 'm':
			opt_mode = optarg;
			break;
		case 'Y':
			opt_is_factory = 1;
			break;
		case 'W':
			opt_write_protection = optarg;
			break;
		case 'E':
			opt_emulation = optarg;
			break;
		case 'p':
			opt_programmer = optarg;
			break;
		case 'F':
			opt_force_update = 1;
			break;
		case 'S':
			opt_sys_props = optarg;
			break;
		case 'v':
			opt_verbosity++;
			break;
		case 'd':
			debugging_enabled = 1;
			opt_verbosity++;
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
	if (!errorcnt)
		errorcnt += updater_setup_config(
				cfg, opt_image, opt_ec_image, opt_pd_image,
				opt_archive, opt_quirks, opt_mode,
				opt_programmer, opt_emulation, opt_sys_props,
				opt_write_protection, opt_is_factory,
				opt_try_update, opt_force_update,
				opt_verbosity);
	if (!errorcnt) {
		int r = update_firmware(cfg);
		if (r != UPDATE_ERR_DONE) {
			r = Min(r, UPDATE_ERR_UNKNOWN);
			Error("%s\n", updater_error_messages[r]);
			errorcnt++;
		}
	}
	printf(">> %s: Firmware updater %s.\n",
	       errorcnt ? "FAILED": "DONE",
	       errorcnt ? "stopped due to error" : "exited successfully");

	updater_delete_config(cfg);
	return !!errorcnt;
}

DECLARE_FUTIL_COMMAND(update, do_update, VBOOT_VERSION_ALL,
		      "Update system firmware");
