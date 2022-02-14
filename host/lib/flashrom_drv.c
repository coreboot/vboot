/* Copyright 2021 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * The utility functions for firmware updater.
 */

#include <libflashrom.h>

#include "2common.h"
#include "crossystem.h"
#include "host_misc.h"
#include "util_misc.h"
//#include "updater.h"
#include "../../futility/futility.h"
#include "flashrom.h"

// global to allow verbosity level to be injected into callback.
static enum flashrom_log_level g_verbose_screen = FLASHROM_MSG_INFO;

static int flashrom_print_cb(enum flashrom_log_level level, const char *fmt,
			     va_list ap)
{
	int ret = 0;
	FILE *output_type = (level < FLASHROM_MSG_INFO) ? stderr : stdout;

	if (level > g_verbose_screen)
		return ret;

	ret = vfprintf(output_type, fmt, ap);
	/* msg_*spew often happens inside chip accessors
	 * in possibly time-critical operations.
	 * Don't slow them down by flushing.
	 */
	if (level != FLASHROM_MSG_SPEW)
		fflush(output_type);

	return ret;
}

static char *flashrom_extract_params(const char *str, char **prog, char **params)
{
	char *tmp = strdup(str);
	*prog = strtok(tmp, ":");
	*params = strtok(NULL, "");
	return tmp;
}

int flashrom_read_image(struct firmware_image *image, const char *region,
			int verbosity)
{
	int r = 0;
	size_t len = 0;

	g_verbose_screen = (verbosity == -1) ? FLASHROM_MSG_INFO : verbosity;

	char *programmer, *params;
	char *tmp = flashrom_extract_params(image->programmer, &programmer, &params);

	struct flashrom_programmer *prog = NULL;
	struct flashrom_flashctx *flashctx = NULL;
	struct flashrom_layout *layout = NULL;

	flashrom_set_log_callback((flashrom_log_callback *)&flashrom_print_cb);

	if (flashrom_init(1)
		|| flashrom_programmer_init(&prog, programmer, params)) {
		r = -1;
		goto err_init;
	}
	if (flashrom_flash_probe(&flashctx, prog, NULL)) {
		r = -1;
		goto err_probe;
	}

	len = flashrom_flash_getsize(flashctx);

	if (region) {
		r = flashrom_layout_read_fmap_from_buffer(
			&layout, flashctx, (const uint8_t *)image->data,
			image->size);
		if (r > 0) {
			WARN("could not read fmap from image, r=%d, "
				"falling back to read from rom\n", r);
			r = flashrom_layout_read_fmap_from_rom(
				&layout, flashctx, 0, len);
			if (r > 0) {
				ERROR("could not read fmap from rom, r=%d\n", r);
				r = -1;
				goto err_cleanup;
			}
		}
		// empty region causes seg fault in API.
		r |= flashrom_layout_include_region(layout, region);
		if (r > 0) {
			ERROR("could not include region = '%s'\n", region);
			r = -1;
			goto err_cleanup;
		}
		flashrom_layout_set(flashctx, layout);
	}

	image->data = calloc(1, len);
	image->size = len;
	image->file_name = strdup("<sys-flash>");

	r |= flashrom_image_read(flashctx, image->data, len);

err_cleanup:
	flashrom_layout_release(layout);
	flashrom_flash_release(flashctx);

err_probe:
	r |= flashrom_programmer_shutdown(prog);

err_init:
	free(tmp);
	return r;
}

int flashrom_write_image(const struct firmware_image *image,
			const char *region,
			const struct firmware_image *diff_image,
			int do_verify, int verbosity)
{
	int r = 0;
	size_t len = 0;

	g_verbose_screen = (verbosity == -1) ? FLASHROM_MSG_INFO : verbosity;

	char *programmer, *params;
	char *tmp = flashrom_extract_params(image->programmer, &programmer, &params);

	struct flashrom_programmer *prog = NULL;
	struct flashrom_flashctx *flashctx = NULL;
	struct flashrom_layout *layout = NULL;

	flashrom_set_log_callback((flashrom_log_callback *)&flashrom_print_cb);

	if (flashrom_init(1)
		|| flashrom_programmer_init(&prog, programmer, params)) {
		r = -1;
		goto err_init;
	}
	if (flashrom_flash_probe(&flashctx, prog, NULL)) {
		r = -1;
		goto err_probe;
	}

	len = flashrom_flash_getsize(flashctx);
	if (len == 0) {
		ERROR("zero sized flash detected\n");
		r = -1;
		goto err_cleanup;
	}

	if (diff_image) {
		if (diff_image->size != image->size) {
			ERROR("diff_image->size != image->size");
			r = -1;
			goto err_cleanup;
		}
	}

	if (region) {
		r = flashrom_layout_read_fmap_from_buffer(
			&layout, flashctx, (const uint8_t *)image->data,
			image->size);
		if (r > 0) {
			WARN("could not read fmap from image, r=%d, "
				"falling back to read from rom\n", r);
			r = flashrom_layout_read_fmap_from_rom(
				&layout, flashctx, 0, len);
			if (r > 0) {
				ERROR("could not read fmap from rom, r=%d\n", r);
				r = -1;
				goto err_cleanup;
			}
		}
		// empty region causes seg fault in API.
		r |= flashrom_layout_include_region(layout, region);
		if (r > 0) {
			ERROR("could not include region = '%s'\n", region);
			r = -1;
			goto err_cleanup;
		}
		flashrom_layout_set(flashctx, layout);
	}

	flashrom_flag_set(flashctx, FLASHROM_FLAG_VERIFY_WHOLE_CHIP, true);
	flashrom_flag_set(flashctx, FLASHROM_FLAG_VERIFY_AFTER_WRITE, true);
	if (!do_verify)
		flashrom_flag_set(flashctx, FLASHROM_FLAG_VERIFY_AFTER_WRITE, false);

	r |= flashrom_image_write(flashctx, image->data, image->size,
				  diff_image ? diff_image->data : NULL);

err_cleanup:
	flashrom_layout_release(layout);
	flashrom_flash_release(flashctx);

err_probe:
	r |= flashrom_programmer_shutdown(prog);

err_init:
	free(tmp);
	return r;
}
