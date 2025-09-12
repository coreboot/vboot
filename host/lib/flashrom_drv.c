/* Copyright 2021 The ChromiumOS Authors
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
#include "../../futility/futility.h"
#include "flashrom.h"

/* global to allow verbosity level to be injected into callback. */
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

/**
 * Prepares flash for operations by initializing `flashctx` and `prog`.
 * If `len` is provided, it will be set to the size of the flash.
 *
 * The caller is responsible for shutting down the programmer `prog`.
 */
static vb2_error_t flashrom_setup(struct flashrom_flashctx **flashctx,
				  struct flashrom_programmer **prog, size_t *len,
				  const char *image_programmer)
{
	char *tmp, *programmer, *params;

	tmp = flashrom_extract_params(image_programmer, &programmer, &params);
	if (!tmp) {
		ERROR("Could not setup programmer: out of memory.\n");
		return VB2_ERROR_FLASHROM;
	}

	*prog = NULL;
	*flashctx = NULL;
	flashrom_set_log_callback((flashrom_log_callback *)&flashrom_print_cb);

	if (flashrom_init(1) || flashrom_programmer_init(prog, programmer, params)) {
		ERROR("Flashrom initialization failed.\n");
		goto err_init;
	}

	if (flashrom_flash_probe(flashctx, *prog, NULL)) {
		ERROR("Flash probing failed.\n");
		goto err_probe;
	}

	if (len) {
		*len = flashrom_flash_getsize(*flashctx);
		if (!*len) {
			ERROR("Chip found had zero length, probing probably failed.\n");
			goto err_cleanup;
		}
	}

	flashrom_flag_set(*flashctx, FLASHROM_FLAG_SKIP_UNREADABLE_REGIONS, true);
	flashrom_flag_set(*flashctx, FLASHROM_FLAG_SKIP_UNWRITABLE_REGIONS, true);

	return VB2_SUCCESS;

err_cleanup:
	flashrom_flash_release(*flashctx);

err_probe:
	flashrom_programmer_shutdown(*prog);

err_init:
	free(tmp);

	return VB2_ERROR_FLASHROM;
}

/*
 * NOTE: When `regions` contains multiple regions, `region_start` and
 * `region_len` will be filled with the data of the first region.
 */
static vb2_error_t flashrom_read_image_impl(struct firmware_image *image,
					    const char *const regions[],
					    const size_t regions_len,
					    unsigned int *region_start,
					    unsigned int *region_len, int verbosity)
{
	vb2_error_t r = VB2_ERROR_FLASHROM;
	size_t len = 0;
	*region_start = 0;
	*region_len = 0;

	g_verbose_screen = (verbosity == -1) ? FLASHROM_MSG_INFO : verbosity;

	struct flashrom_programmer *prog = NULL;
	struct flashrom_flashctx *flashctx = NULL;
	struct flashrom_layout *layout = NULL;

	if (flashrom_setup(&flashctx, &prog, &len, image->programmer) != VB2_SUCCESS)
		return r;

	if (regions_len) {
		int i;
		if (flashrom_layout_read_fmap_from_rom(&layout, flashctx, 0, len)) {
			ERROR("Could not read FMAP from ROM.\n");
			goto err_cleanup;
		}
		for (i = 0; i < regions_len; i++) {
			// empty region causes seg fault in API.
			if (flashrom_layout_include_region(layout, regions[i])) {
				ERROR("Could not include region = '%s'\n",
				      regions[i]);
				goto err_cleanup;
			}
		}
		flashrom_layout_set(flashctx, layout);
	}

	image->data = calloc(1, len);
	if (!image->data) {
		ERROR("Could not allocate image data (%zu bytes)\n", len);
		goto err_cleanup;
	}
	image->size = len;
	image->file_name = strdup("<sys-flash>");

	if (flashrom_image_read(flashctx, image->data, len))
		goto err_cleanup;

	if (regions_len &&
		flashrom_layout_get_region_range(layout, regions[0], region_start, region_len))
		goto err_cleanup;

	r = VB2_SUCCESS;

err_cleanup:
	flashrom_layout_release(layout);
	flashrom_flash_release(flashctx);
	if (flashrom_programmer_shutdown(prog))
		r = VB2_ERROR_FLASHROM;

	if (r != VB2_SUCCESS && image->data) {
		free(image->data);
		free(image->file_name);
		image->data = NULL;
		image->file_name = NULL;
	}
	return r;
}

vb2_error_t flashrom_read_image(struct firmware_image *image, const char *const regions[],
				const size_t regions_len, int verbosity)
{
	unsigned int start, len;
	return flashrom_read_image_impl(image, regions, regions_len, &start, &len, verbosity);
}

vb2_error_t flashrom_read_region(struct firmware_image *image, const char *region,
				 int verbosity)
{
	const char *const regions[] = {region};
	unsigned int start, len;
	if (region == NULL) {
		ERROR("Region name must be specified\n");
		return VB2_ERROR_FLASHROM;
	}
	vb2_error_t r = flashrom_read_image_impl(image, regions, ARRAY_SIZE(regions),
						 &start, &len, verbosity);
	if (r != VB2_SUCCESS)
		return r;

	memmove(image->data, image->data + start, len);
	image->size = len;
	return VB2_SUCCESS;
}

vb2_error_t flashrom_write_image(const struct firmware_image *image,
				 const char *const regions[], const size_t regions_len,
				 const struct firmware_image *diff_image,
				 bool do_verify, int verbosity)
{
	vb2_error_t r = VB2_ERROR_FLASHROM;
	size_t len = 0;

	g_verbose_screen = (verbosity == -1) ? FLASHROM_MSG_INFO : verbosity;

	struct flashrom_programmer *prog = NULL;
	struct flashrom_flashctx *flashctx = NULL;
	struct flashrom_layout *layout = NULL;

	if (flashrom_setup(&flashctx, &prog, &len, image->programmer) != VB2_SUCCESS)
		return r;

	if (diff_image) {
		if (diff_image->size != image->size) {
			ERROR("diff_image->size != image->size");
			goto err_cleanup;
		}
	}

	if (image->size != len) {
		ERROR("Image size (%u) does not match the flash size (%zu)\n",
		      image->size, len);
		goto err_cleanup;
	}

	if (regions_len) {
		if (flashrom_layout_read_fmap_from_buffer(&layout, flashctx,
							  (const uint8_t *)image->data,
							  image->size)) {
			WARN("Could not read FMAP from image, falling back to read from ROM\n");
			if (flashrom_layout_read_fmap_from_rom(&layout, flashctx, 0, len)) {
				ERROR("Could not read FMAP from ROM\n");
				goto err_cleanup;
			}
		}
		for (int i = 0; i < regions_len; i++) {
			INFO(" including region '%s'\n", regions[i]);
			// empty region causes seg fault in API.
			if (flashrom_layout_include_region(layout, regions[i])) {
				ERROR("Could not include region = '%s'\n", regions[i]);
				goto err_cleanup;
			}
		}
		flashrom_layout_set(flashctx, layout);
	}

	flashrom_flag_set(flashctx, FLASHROM_FLAG_VERIFY_WHOLE_CHIP, false);
	flashrom_flag_set(flashctx, FLASHROM_FLAG_VERIFY_AFTER_WRITE, do_verify);

	if (flashrom_image_write(flashctx, image->data, image->size,
				 diff_image ? diff_image->data : NULL) == 0)
		r = VB2_SUCCESS;

err_cleanup:
	flashrom_layout_release(layout);
	flashrom_flash_release(flashctx);
	if (flashrom_programmer_shutdown(prog))
		r = VB2_ERROR_FLASHROM;

	return r;
}

vb2_error_t flashrom_write_region(const struct firmware_image *image, const char *region,
				  bool do_verify, int verbosity)
{
	vb2_error_t r = VB2_ERROR_FLASHROM;
	size_t len = 0;

	if (region == NULL) {
		ERROR("Region name must be specified\n");
		return VB2_ERROR_FLASHROM;
	}

	g_verbose_screen = (verbosity == -1) ? FLASHROM_MSG_INFO : verbosity;

	struct flashrom_programmer *prog = NULL;
	struct flashrom_flashctx *flashctx = NULL;
	struct flashrom_layout *layout = NULL;

	/* `full_image_data` is allocated here as the full-size buffer passed to
	   libflashrom, and `full_image_size` is set to the total flash size. */
	uint8_t *full_image_data = NULL;
	size_t full_image_size = 0;

	if (flashrom_setup(&flashctx, &prog, &len, image->programmer) != VB2_SUCCESS)
		return r;

	if (flashrom_layout_read_fmap_from_rom(&layout, flashctx, 0, len)) {
		ERROR("Could not read FMAP from ROM.\n");
		goto err_cleanup;
	}
	/* Get the region_start and region_len. */
	if (flashrom_layout_include_region(layout, region)) {
		ERROR("Region '%s' not found in FMAP\n", region);
		goto err_cleanup;
	}
	unsigned int region_start, region_len;
	if (flashrom_layout_get_region_range(layout, region, &region_start, &region_len)) {
		ERROR("Could not get range for region '%s'\n", region);
		goto err_cleanup;
	}
	if (image->size != region_len) {
		ERROR("Image size (%u) does not match region '%s' size (%u)\n",
		      image->size, region, region_len);
		goto err_cleanup;
	}
	/* Prepare the full-layout image buffer. */
	full_image_size = len;
	full_image_data = malloc(full_image_size);
	if (!full_image_data) {
		ERROR("Could not allocate memory for full image (%zu bytes)\n", len);
		goto err_cleanup;
	}
	memset(full_image_data, 0xff, full_image_size);
	memcpy(full_image_data + region_start, image->data, image->size);

	flashrom_layout_set(flashctx, layout);

	flashrom_flag_set(flashctx, FLASHROM_FLAG_VERIFY_WHOLE_CHIP, false);
	flashrom_flag_set(flashctx, FLASHROM_FLAG_VERIFY_AFTER_WRITE, do_verify);

	if (flashrom_image_write(flashctx, full_image_data, full_image_size, NULL) == 0)
		r = VB2_SUCCESS;

err_cleanup:
	flashrom_layout_release(layout);
	flashrom_flash_release(flashctx);
	if (flashrom_programmer_shutdown(prog))
		r = VB2_ERROR_FLASHROM;

	if (full_image_data)
		free(full_image_data);

	return r;
}

vb2_error_t flashrom_get_wp(const char *prog_with_params, bool *wp_mode,
			    uint32_t *wp_start, uint32_t *wp_len, int verbosity)
{
	vb2_error_t r = VB2_ERROR_FLASHROM;

	g_verbose_screen = (verbosity == -1) ? FLASHROM_MSG_INFO : verbosity;

	struct flashrom_programmer *prog = NULL;
	struct flashrom_flashctx *flashctx = NULL;
	struct flashrom_wp_cfg *cfg = NULL;

	if (flashrom_setup(&flashctx, &prog, NULL, prog_with_params) != VB2_SUCCESS)
		return r;

	if (flashrom_wp_cfg_new(&cfg) != FLASHROM_WP_OK)
		goto err_cleanup;

	if (flashrom_wp_read_cfg(cfg, flashctx) != FLASHROM_WP_OK)
		goto err_read_cfg;

	/* size_t tmp variables for libflashrom compatibility */
	size_t tmp_wp_start, tmp_wp_len;
	flashrom_wp_get_range(&tmp_wp_start, &tmp_wp_len, cfg);

	if (wp_start != NULL)
		*wp_start = tmp_wp_start;
	if (wp_start != NULL)
		*wp_len = tmp_wp_len;
	if (wp_mode != NULL)
		*wp_mode = flashrom_wp_get_mode(cfg) != FLASHROM_WP_MODE_DISABLED;

	r = VB2_SUCCESS;

err_read_cfg:
	flashrom_wp_cfg_release(cfg);

err_cleanup:
	flashrom_flash_release(flashctx);
	if (flashrom_programmer_shutdown(prog))
		r = VB2_ERROR_FLASHROM;

	return r;
}

vb2_error_t flashrom_set_wp(const char *prog_with_params, bool wp_mode,
			    uint32_t wp_start, uint32_t wp_len, int verbosity)
{
	vb2_error_t r = VB2_ERROR_FLASHROM;

	g_verbose_screen = (verbosity == -1) ? FLASHROM_MSG_INFO : verbosity;

	struct flashrom_programmer *prog = NULL;
	struct flashrom_flashctx *flashctx = NULL;
	struct flashrom_wp_cfg *cfg = NULL;

	if (flashrom_setup(&flashctx, &prog, NULL, prog_with_params) != VB2_SUCCESS)
		return r;

	if (flashrom_wp_cfg_new(&cfg) != FLASHROM_WP_OK)
		goto err_cleanup;

	enum flashrom_wp_mode mode = wp_mode ?
			FLASHROM_WP_MODE_HARDWARE : FLASHROM_WP_MODE_DISABLED;
	flashrom_wp_set_mode(cfg, mode);
	flashrom_wp_set_range(cfg, wp_start, wp_len);

	if (flashrom_wp_write_cfg(flashctx, cfg) != FLASHROM_WP_OK)
		goto err_write_cfg;

	r = VB2_SUCCESS;

err_write_cfg:
	flashrom_wp_cfg_release(cfg);

err_cleanup:
	flashrom_flash_release(flashctx);
	if (flashrom_programmer_shutdown(prog))
		r = VB2_ERROR_FLASHROM;

	return r;
}

vb2_error_t flashrom_get_info(const char *prog_with_params, char **vendor, char **name,
			      uint32_t *vid, uint32_t *pid, uint32_t *flash_len, int verbosity)
{
	vb2_error_t r = VB2_SUCCESS;

	g_verbose_screen = (verbosity == -1) ? FLASHROM_MSG_INFO : verbosity;

	struct flashrom_programmer *prog = NULL;
	struct flashrom_flashctx *flashctx = NULL;

	if (flashrom_setup(&flashctx, &prog, NULL, prog_with_params) != VB2_SUCCESS)
		return VB2_ERROR_FLASHROM;

	struct flashrom_flashchip_info info;
	flashrom_flash_getinfo(flashctx, &info);

	*vendor = strdup(info.vendor);
	*name = strdup(info.name);
	*vid = info.manufacture_id;
	*pid = info.model_id;
	*flash_len = info.total_size * 1024;

	flashrom_flash_release(flashctx);
	if (flashrom_programmer_shutdown(prog))
		r = VB2_ERROR_FLASHROM;

	return r;
}

vb2_error_t flashrom_get_size(const char *prog_with_params, uint32_t *flash_len, int verbosity)
{
	vb2_error_t r = VB2_SUCCESS;

	g_verbose_screen = (verbosity == -1) ? FLASHROM_MSG_INFO : verbosity;

	struct flashrom_programmer *prog = NULL;
	struct flashrom_flashctx *flashctx = NULL;
	size_t len;

	if (flashrom_setup(&flashctx, &prog, &len, prog_with_params) != VB2_SUCCESS)
		return VB2_ERROR_FLASHROM;
	*flash_len = len;

	flashrom_flash_release(flashctx);
	if (flashrom_programmer_shutdown(prog))
		r = VB2_ERROR_FLASHROM;

	return r;
}
