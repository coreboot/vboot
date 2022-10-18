/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Host utilites to execute flashrom command.
 */

#include <stdint.h>

#include "2return_codes.h"
#include "fmap.h"

#define FLASHROM_PROGRAMMER_INTERNAL_AP "host"
#define FLASHROM_PROGRAMMER_INTERNAL_EC "ec"

/* Utilities for firmware images and (FMAP) sections */
struct firmware_image {
	/**
	 * programmer	The name of the programmer to use. Use either
	 *		FLASHROM_PROGRAMMER_INTERNAL_AP or,
	 *		FLASHROM_PROGRAMMER_INTERNAL_EC
	 *		for the AP and EC respectively.
	 */
	const char *programmer;
	uint32_t size; /* buffer size. */
	uint8_t *data; /* data allocated buffer to read/write with. */
	char *file_name;
	char *ro_version, *rw_version_a, *rw_version_b;
	FmapHeader *fmap_header;
};

/**
 * Read using flashrom into an allocated buffer.
 *
 * @param image		The parameter that contains the programmer, buffer and
 *			size to use in the read operation.
 * @param region	The name of the fmap region to read, or NULL to
 *			read the entire flash chip.
 *
 * @return VB2_SUCCESS on success, or a relevant error.
 */
vb2_error_t flashrom_read(struct firmware_image *image, const char *region);
int flashrom_read_image(struct firmware_image *image, int verbosity);
int flashrom_read_region(struct firmware_image *image, const char *region,
			 int verbosity);

/**
 * Write using flashrom from a buffer.
 *
 * @param image		The parameter that contains the programmer, buffer and
 *			size to use in the write operation.
 * @param regions	A list of the names of the fmap regions to write, or
 *			NULL to write the entire flash chip. The list must be
 *			ended with a NULL pointer.
 *
 * @return VB2_SUCCESS on success, or a relevant error.
 */
vb2_error_t flashrom_write(struct firmware_image *image, const char *region);
int flashrom_write_image(const struct firmware_image *image,
			const char * const regions[],
			const struct firmware_image *diff_image,
			int do_verify, int verbosity);

enum wp_state {
	WP_ERROR = -1,
	WP_DISABLED = 0,
	WP_ENABLED,
};

/**
 * Get wp state using flashrom.
 *
 * @param programmer	The name of the programmer to use for reading the
 *                      writeprotect state.
 *
 * @return WP_DISABLED, WP_ENABLED, ot a relevant error.
 */
enum wp_state flashrom_get_wp(const char *programmer, int verbosity);
