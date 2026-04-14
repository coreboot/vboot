/* Copyright 2012 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <getopt.h>
#include <string.h>

#include "cgpt.h"
#include "vboot_host.h"

extern const char *progname;

static void Usage(void)
{
	printf("\nUsage: %s legacy [OPTIONS] DRIVE\n\n"
	       "Switch GPT header signature to \"CHROMEOS\".\n\n"
	       "Options:\n"
	       "  -e           Switch GPT header signature back to \"EFI PART\"\n"
	       "  -p           Switch primary GPT header signature to \"IGNOREME\"\n"
	       "\n",
	       progname);
}

int cmd_legacy(int argc, char *argv[])
{
	CgptLegacyParams params;
	memset(&params, 0, sizeof(params));

	int c;
	int errorcnt = 0;

	opterr = 0; // quiet, you
	while ((c = getopt(argc, argv, ":hep")) != -1) {
		switch (c) {
		case 'e':
			if (params.mode) {
				Error("Incompatible flags, pick either -e or -p\n");
				errorcnt++;
			}
			params.mode = CGPT_LEGACY_MODE_EFIPART;
			break;
		case 'p':
			if (params.mode) {
				Error("Incompatible flags, pick either -e or -p\n");
				errorcnt++;
			}
			params.mode = CGPT_LEGACY_MODE_IGNORE_PRIMARY;
			break;
		case 'h':
			Usage();
			return CGPT_OK;
		case '?':
			Error("unrecognized option: -%c\n", optopt);
			errorcnt++;
			break;
		case ':':
			Error("missing argument to -%c\n", optopt);
			errorcnt++;
			break;
		default:
			errorcnt++;
			break;
		}
	}
	if (errorcnt) {
		Usage();
		return CGPT_FAILED;
	}

	if (optind >= argc) {
		Usage();
		return CGPT_FAILED;
	}

	params.drive_name = argv[optind];

	return CgptLegacy(&params);
}
