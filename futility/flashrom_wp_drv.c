/* Copyright 2021 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * The utility functions for firmware updater.
 */

#include <libflashrom.h>

#include "updater.h"

#define FLASHROM_OUTPUT_WP_PATTERN "write protect is "

/* System environment values. */
static const char * const FLASHROM_OUTPUT_WP_ENABLED =
			  FLASHROM_OUTPUT_WP_PATTERN "enabled",
		  * const FLASHROM_OUTPUT_WP_DISABLED =
			  FLASHROM_OUTPUT_WP_PATTERN "disabled";


/* Helper function to return write protection status via given programmer. */
enum wp_state flashrom_get_wp(const char *programmer)
{
	char *command, *result;
	const char *postfix;
	int r;

	/* grep is needed because host_shell only returns 1 line. */
	postfix = " 2>/dev/null | grep \"" FLASHROM_OUTPUT_WP_PATTERN "\"";


	/* TODO(b/203715651): link with flashrom directly. */
	ASPRINTF(&command, "flashrom --wp-status -p %s %s", programmer, postfix);

	/* invokes flashrom(8) with non-zero result if error. */
	result = host_shell(command);
	strip_string(result, NULL);
	free(command);
	VB2_DEBUG("wp-status: %s\n", result);

	if (strstr(result, FLASHROM_OUTPUT_WP_ENABLED))
		r = WP_ENABLED;
	else if (strstr(result, FLASHROM_OUTPUT_WP_DISABLED))
		r = WP_DISABLED;
	else
		r = WP_ERROR;
	free(result);

	return r;
}
