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
	{"model", 1, NULL, 'M'},
	{"signature_id", 1, NULL, 'G'},
	{"manifest", 0, NULL, 'A'},
	{"repack", 1, NULL, 'k'},
	{"unpack", 1, NULL, 'u'},
	{"factory", 0, NULL, 'Y'},
	{"force", 0, NULL, 'F'},
	{"programmer", 1, NULL, 'p'},
	{"wp", 1, NULL, 'W'},
	{"host_only", 0, NULL, 'H'},
	{"emulate", 1, NULL, 'E'},
	{"output_dir", 1, NULL, 'U'},
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
		"    --manifest      \tPrint out a JSON manifest and exit\n"
		"    --repack=DIR    \tUpdates archive from DIR\n"
		"    --unpack=DIR    \tExtracts archive to DIR\n"
		"-p, --programmer=PRG\tChange AP (host) flashrom programmer\n"
		"    --quirks=LIST   \tSpecify the quirks to apply\n"
		"    --list-quirks   \tPrint all available quirks\n"
		"\n"
		"Legacy and compatibility options:\n"
		"-m, --mode=MODE     \tRun updater in given mode\n"
		"    --factory       \tAlias for --mode=factory\n"
		"    --force         \tForce update (skip checking contents)\n"
		"    --output_dir=DIR\tSpecify the target for --mode=output\n"
		"\n"
		"Debugging and testing options:\n"
		"    --wp=1|0        \tSpecify write protection status\n"
		"    --host_only     \tUpdate only AP (host) firmware\n"
		"    --emulate=FILE  \tEmulate system firmware using file\n"
		"    --model=MODEL   \tOverride system model for images\n"
		"    --signature_id=S\tOverride signature ID for key files\n"
		"    --sys_props=LIST\tList of system properties to override\n"
		"-d, --debug         \tPrint debugging messages\n"
		"-v, --verbose       \tPrint verbose messages\n"
		"",
		argv[0]);
}

static int do_update(int argc, char *argv[])
{
	struct updater_config *cfg;
	struct updater_config_arguments args = {0};
	int i, errorcnt = 0, do_update = 1;

	cfg = updater_new_config();
	assert(cfg);

	opterr = 0;
	while ((i = getopt_long(argc, argv, short_opts, long_opts, 0)) != -1) {
		switch (i) {
		case 'i':
			args.image = optarg;
			break;
		case 'e':
			args.ec_image = optarg;
			break;
		case 'P':
			args.pd_image = optarg;
			break;
		case 't':
			args.try_update = 1;
			break;
		case 'a':
			args.archive = optarg;
			break;
		case 'k':
			args.repack = optarg;
			break;
		case 'u':
			args.unpack = optarg;
			break;
		case 'f':
			args.quirks = optarg;
			break;
		case 'L':
			updater_list_config_quirks(cfg);
			return 0;
		case 'm':
			args.mode = optarg;
			break;
		case 'U':
			args.output_dir = optarg;
			break;
		case 'M':
			args.model = optarg;
			break;
		case 'G':
			args.signature_id = optarg;
			break;
		case 'A':
			args.do_manifest = 1;
			break;
		case 'Y':
			args.is_factory = 1;
			break;
		case 'W':
			args.write_protection = optarg;
			break;
		case 'H':
			args.host_only = 1;
			break;
		case 'E':
			args.emulation = optarg;
			break;
		case 'p':
			args.programmer = optarg;
			break;
		case 'F':
			args.force_update = 1;
			break;
		case 'S':
			args.sys_props = optarg;
			break;
		case 'v':
			args.verbosity++;
			break;
		case 'd':
			debugging_enabled = 1;
			args.verbosity++;
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
		errorcnt += updater_setup_config(cfg, &args, &do_update);
	if (!errorcnt && do_update) {
		int r;
		STATUS("Starting firmware updater.");
		r = update_firmware(cfg);
		if (r != UPDATE_ERR_DONE) {
			r = Min(r, UPDATE_ERR_UNKNOWN);
			Error("%s\n", updater_error_messages[r]);
			errorcnt++;
		}
		/* Use stdout for the final result. */
		printf(">> %s: Firmware updater %s.\n",
			errorcnt ? "FAILED": "DONE",
			errorcnt ? "aborted" : "exits successfully");
	}

	updater_delete_config(cfg);
	return !!errorcnt;
}

DECLARE_FUTIL_COMMAND(update, do_update, VBOOT_VERSION_ALL,
		      "Update system firmware");
