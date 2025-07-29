/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef VBOOT_REFERENCE_FUTILITY_ARCHIVE_LIBZIPARCHIVE_WRAPPER_H_
#define VBOOT_REFERENCE_FUTILITY_ARCHIVE_LIBZIPARCHIVE_WRAPPER_H_

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

/*
 * Lazy read / write wrapper over libziparchive.
 *
 * Only one kind of operations can be executed on
 * an archive (simultaneous reading and writing is not supported).
 *
 * The archive is opened when
 * the first determining (whether this archive will be read or written) operation is executed.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Redefinition of error codes from libziparchive/zip_error.h
 */
enum libziparchive_error : int {
	LIBZIPARCHIVE_SUCCESS = 0,
	LIBZIPARCHIVE_ITERATION_END = -1,
	LIBZIPARCHIVE_ZLIB_ERROR = -2,
	LIBZIPARCHIVE_INVALID_FILE = -3,
	LIBZIPARCHIVE_INVALID_HANDLE = -4,
	LIBZIPARCHIVE_DUPLICATE_ENTRY = -5,
	LIBZIPARCHIVE_EMPTY_ARCHIVE = -6,
	LIBZIPARCHIVE_ENTRY_NOT_FOUND = -7,
	LIBZIPARCHIVE_INVALID_OFFSET = -8,
	LIBZIPARCHIVE_INCONSISTENT_INFORMATION = -9,
	LIBZIPARCHIVE_INVALID_ENTRY_NAME = -10,
	LIBZIPARCHIVE_IO_ERROR = -11,
	LIBZIPARCHIVE_MMAP_FAILED = -12,
	LIBZIPARCHIVE_ALLOCATION_FAILED = -13,
	LIBZIPARCHIVE_UNSUPPORTED_ENTRY_SIZE = -14,
	LIBZIPARCHIVE_WRAPPER_FAILURE = -1000
};

struct libziparchive_handle;
struct libziparchive_cookie;
struct libziparchive_entry;

/*
 * Lazily opens the archive file. Filename is stored, but the actual file is not yet opened.
 * Returns NULL on failure.
 */
struct libziparchive_handle *libziparchive_open(const char *filename);

/*
 * Closes the opened archive. Returns zero on success.
 */
int libziparchive_close(struct libziparchive_handle *handle);

/*
 * Allocates a new entry on the heap.
 */
struct libziparchive_entry *libziparchive_alloc_entry(void);

/*
 * Deallocates the entry.
 */
void libziparchive_release_entry(struct libziparchive_entry *entry);

/*
 * Starts iteration over entries in the archive. `cookie` is set to an allocated cookie.
 * Returns zero on success.
 */
int libziparchive_start_iteration(struct libziparchive_handle *handle,
				  struct libziparchive_cookie **cookie);

/*
 * Stops iteration. Deallocates `cookie`.
 */
void libziparchive_stop_iteration(struct libziparchive_cookie *cookie);

/*
 * Advances to the next entry in the archive. Sets `name` to the name of the entry. Caller is
 * responsible for releasing `name`. Returns zero on success, LIBZIPARCHIVE_ITERATION_END if
 * there are no more entries, other values on failure.
 */
int libziparchive_next(struct libziparchive_cookie *cookie, struct libziparchive_entry *entry,
		       char **name);

/*
 * Locates an entry in the archive with the given name. Returns zero on success.
 */
int libziparchive_find_entry(struct libziparchive_handle *handle, const char *name,
			     struct libziparchive_entry *entry);

/*
 * Returns modification time of the entry.
 */
int32_t libziparchive_get_mtime(struct libziparchive_entry *entry);

/*
 * Extracts contents of the entry. `data` is set to the allocated data buffer, `size` is set to
 * the size of the entry. Caller is responsible for releasing `data`. Returns zero on success.
 *
 */
int libziparchive_extract_entry(struct libziparchive_handle *handle,
				struct libziparchive_entry *entry, uint8_t **data,
				size_t *size);

/*
 * Writes a new entry in the archive. Returns zero on success.
 */
int libziparchive_write_entry(struct libziparchive_handle *handle, const char *name,
			      uint8_t *data, size_t size, int32_t mtime);

#ifdef __cplusplus
}
#endif

#endif /* VBOOT_REFERENCE_FUTILITY_ARCHIVE_LIBZIPARCHIVE_WRAPPER_H_*/
