/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Host utilites to execute flashrom command.
 */

#include <stdint.h>

#include "2return_codes.h"
#include "fmap.h"

#define FLASHROM_PROGRAMMER_INTERNAL_AP "internal"
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
	/* AP RW sections may contain a special ECRW binary for syncing EC
	   firmware on boot. These 2 fields are valid only for AP image. */
	char *ecrw_version_a, *ecrw_version_b;
	FmapHeader *fmap_header;
};

/**
 * Reads one or more FMAP regions, or the entire flash chip, into a newly allocated buffer.
 *
 * This function allocates a buffer equal to the size of the ENTIRE flash chip. It then reads
 * the specified FMAP region(s) into the corresponding offsets within that buffer. The contents
 * of the buffer outside of the specified regions are undefined.
 *
 * The caller is responsible for freeing image->data and image->file_name.
 *
 * @param image		Firmware image struct. The `programmer` field must be set by the caller.
 *			The `data`, `size`, and `file_name` fields will be populated by this
 *			function upon success.
 * @param regions	An array of FMAP region names to read.
 * @param regions_len	The number of strings in the `regions` array. If 0, the entire flash
 *			chip is read.
 * @param verbosity	Controls the verbosity level of the flashrom command.
 *
 * @return VB2_SUCCESS on success, or a relevant error code on failure.
 */
vb2_error_t flashrom_read_image(struct firmware_image *image, const char *const regions[],
				size_t regions_len, int verbosity);

/**
 * Reads a single FMAP region from flash into a newly allocated, fitted buffer.
 *
 * This function allocates a buffer that is sized to be exactly the size of the requested
 * region, and the buffer contains only the data from that region.
 *
 * The caller is responsible for freeing image->data and image->file_name.
 *
 * @param image		Firmware image struct. The `programmer` field must be set by the caller.
 *			The `data`, `size`, and `file_name` fields will be populated by this
 *			function upon success.
 * @param region	The name of the single FMAP region to read. Must not be NULL.
 * @param verbosity	Controls the verbosity level of the flashrom command.
 *
 * @return VB2_SUCCESS on success, or a relevant error code on failure.
 */
vb2_error_t flashrom_read_region(struct firmware_image *image, const char *region,
				 int verbosity);

/**
 * Write one or more FMAP regions, or the entire flash chip, from a buffer.
 *
 * The `image` buffer is expected to be the size of the entire flash chip, with the data for
 * each specified region at the correct offset.
 *
 * @param image		Firmware image struct containing the data to write. The `programmer`,
 *			`data`, and `size` fields must be set.
 * @param regions	An array of FMAP region names to write.
 * @param regions_len	The number of strings in the `regions` array. If 0, the entire flash
 *			chip is written.
 * @param diff_image	Optional. If not NULL, flashrom will only write the blocks that are
 *			different between `image` and `diff_image`, potentially speeding up the
 *			write operation.
 * @param do_verify	If true, flashrom will read back the data after writing to verify
 *			its integrity.
 * @param verbosity	Controls the verbosity level of the flashrom command.
 *
 * @return VB2_SUCCESS on success, or a relevant error.
 */
vb2_error_t flashrom_write_image(const struct firmware_image *image,
				 const char *const regions[], size_t regions_len,
				 const struct firmware_image *diff_image, bool do_verify,
				 int verbosity);

/**
 * Write a single FMAP region to flash from a fitted buffer.
 *
 * The `image` buffer is expected to contain only the data for the specified region and its size
 * should match that region's size in the FMAP.
 *
 * @param image		Firmware image struct containing the data to write. The `programmer`,
 *			`data`, and `size` fields must be set.
 * @param region	The name of a single FMAP region to write. Must not be NULL.
 * @param do_verify	If true, flashrom will read back the data after writing to verify
 *			its integrity.
 * @param verbosity	Controls the verbosity level of the flashrom command.
 *
 * @return VB2_SUCCESS on success, or a relevant error.
 */
vb2_error_t flashrom_write_region(const struct firmware_image *image, const char *region,
				  bool do_verify, int verbosity);

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
 * @return VB2_SUCCESS on success, or a relevant error.
 */
vb2_error_t flashrom_get_wp(const char *programmer, bool *wp_mode,
			    uint32_t *wp_start, uint32_t *wp_len, int verbosity);

/**
 * Set wp state using flashrom.
 *
 * @param programmer	The name of the programmer to use for writing the
 *                      writeprotect state.
 * @param wp_mode       WP mode to set. true to enable, false disable WP.
 * @param wp_start      WP start addr to set
 * @param wp_len        WP region length set
 *
 * @return VB2_SUCCESS on success, or a relevant error.
 */
vb2_error_t flashrom_set_wp(const char *programmer, bool wp_mode,
			    uint32_t wp_start, uint32_t wp_len, int verbosity);

/**
 * Get flash info using flashrom.
 *
 * @param programmer	The name of the programmer to use.
 * @param vendor        The chip vendor name, non-NULLable.
 * @param name          The chip product name, non-NULLable.
 * @param vid           The chip vendor id, non-NULLable.
 * @param pid           The chip product id, non-NULLable.
 * @param flash_len     Pointer to a uint32_t to store chip length, non-NULLable.
 *
 * @return VB2_SUCCESS on success, or a relevant error.
 */
vb2_error_t flashrom_get_info(const char *prog_with_params, char **vendor, char **name,
			      uint32_t *vid, uint32_t *pid, uint32_t *flash_len, int verbosity);

/**
 * Get flash size using flashrom.
 *
 * @param programmer	The name of the programmer to use.
 * @param flash_len     Pointer to a uint32_t to store chip length.
 *
 * @return VB2_SUCCESS on success, or a relevant error.
 */
vb2_error_t flashrom_get_size(const char *programmer, uint32_t *flash_len, int verbosity);
