/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef VBOOT_REFERENCE_FUTILITY_ARCHIVE_UPDATER_ARCHIVE_H_
#define VBOOT_REFERENCE_FUTILITY_ARCHIVE_UPDATER_ARCHIVE_H_

#include <stdint.h>

/*
 * A firmware update package (archive) is a file packed by either shar(1) or
 * zip(1). See https://chromium.googlesource.com/chromiumos/platform/firmware/
 * for more information.
 */
struct u_archive {
	void *handle;

	void * (*open)(const char *name);
	int (*close)(void *handle);

	int (*walk)(void *handle, void *arg,
		    int (*callback)(const char *path, void *arg));
	int (*has_entry)(void *handle, const char *name);
	int (*read_file)(void *handle, const char *fname,
			 uint8_t **data, uint32_t *size, int64_t *mtime);
	int (*write_file)(void *handle, const char *fname,
			  uint8_t *data, uint32_t size, int64_t mtime);
};

#if defined(HAVE_LIBZIP)
extern struct u_archive archive_zip;
#endif
#if defined(HAVE_LIBARCHIVE)
extern struct u_archive archive_libarchive;
#endif
extern struct u_archive archive_fallback;

#endif /* VBOOT_REFERENCE_FUTILITY_ARCHIVE_UPDATER_ARCHIVE_H_ */
