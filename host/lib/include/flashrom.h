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
 * flashrom_read subprocesses the flashrom binary and returns a buffer truncated
 * to the region.
 *
 * flashrom_read_image reads the returns a full sized buffer with only the
 * regions filled with data.
 *
 * flashrom_read_region returns the buffer truncated to the region.
 *
 * @param image		The parameter that contains the programmer, buffer and
 *			size to use in the read operation.
 * @param regions	A list of the names of the fmap regions to read, or NULL
 *			to read the entire flash chip.
 *
 * @return VB2_SUCCESS on success, or a relevant error.
 */
vb2_error_t flashrom_read(struct firmware_image *image, const char *region);
int flashrom_read_image(struct firmware_image *image,
			const char * const regions[],
			int verbosity);
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

/**
 * Get wp state using flashrom.
 *
 * @param programmer	The name of the programmer to use for reading the
 *                      writeprotect state.
 * @param wp_mode       Pointer to a bool to store the WP mode. Will be set to
 *                      false if WP is disabled, true if WP is enabled.
 *                      NULL can be passed if not needed.
 * @param wp_start      Pointer to a uint32_t to store the WP start addr.
 *                      NULL can be passed if not needed.
 * @param wp_len        Pointer to a uint32_t to store the WP region length.
 *                      NULL can be passed if not needed.
 *
 * @return 0 on success, or a relevant error.
 */
int flashrom_get_wp(const char *programmer, bool *wp_mode,
		    uint32_t *wp_start, uint32_t *wp_len, int verbosity);
