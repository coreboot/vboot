/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/* For strdup */
#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "2api.h"
#include "2return_codes.h"
#include "host_misc.h"
#include "flashrom.h"
#include "subprocess.h"

#define FLASHROM_EXEC_NAME "flashrom"

static vb2_error_t run_flashrom(const char *const argv[])
{
	int status = subprocess_run(argv, &subprocess_null, &subprocess_null,
				    &subprocess_null);
	if (status) {
		fprintf(stderr, "Flashrom invocation failed (exit status %d):",
			status);

		for (const char *const *argp = argv; *argp; argp++)
			fprintf(stderr, " %s", *argp);

		fprintf(stderr, "\n");
		return VB2_ERROR_FLASHROM;
	}

	return VB2_SUCCESS;
}

vb2_error_t flashrom_read_region(struct firmware_image *image, const char *region,
				 int verbosity)
{
	/* TODO(b/445126698): Handle verbosity. */
	char *tmpfile;
	char region_param[PATH_MAX];
	vb2_error_t rv;

	image->data = NULL;
	image->size = 0;

	VB2_TRY(vb2_write_temp_file(NULL, 0, &tmpfile));

	/* TODO(b/445126698): Remove support for NULL region to align with flashrom_drv.c. */
	if (region)
		snprintf(region_param, sizeof(region_param), "%s:%s", region,
			 tmpfile);

	const char *const argv[] = {
		FLASHROM_EXEC_NAME,
		"-p",
		image->programmer,
		"-r",
		region ? "-i" : tmpfile,
		region ? region_param : NULL,
		NULL,
	};

	rv = run_flashrom(argv);
	if (rv == VB2_SUCCESS)
		rv = vb2_read_file(tmpfile, &image->data, &image->size);

	unlink(tmpfile);
	free(tmpfile);
	return rv;
}

vb2_error_t flashrom_write_region(const struct firmware_image *image, const char *region,
				  bool do_verify, int verbosity)
{
	/* TODO(b/445126698): Handle do_verify and verbosity. */
	char *tmpfile;
	char region_param[PATH_MAX];
	vb2_error_t rv;

	VB2_TRY(vb2_write_temp_file(image->data, image->size, &tmpfile));

	/* TODO(b/445126698): Remove support for NULL region to align with flashrom_drv.c. */
	if (region)
		snprintf(region_param, sizeof(region_param), "%s:%s", region,
			 tmpfile);

	const char *const argv[] = {
		FLASHROM_EXEC_NAME,
		"-p",
		image->programmer,
		"--noverify-all",
		"-w",
		region ? "-i" : tmpfile,
		region ? region_param : NULL,
		NULL,
	};

	rv = run_flashrom(argv);
	unlink(tmpfile);
	free(tmpfile);
	return rv;
}
