/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <assert.h>
#include <errno.h>
#include <fts.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#if defined(__OpenBSD__)
#include <sys/types.h>
#endif
#include <unistd.h>

#include "2common.h"
#include "futility.h"
#include "host_misc.h"
#include "updater_archive.h"
#include "updater_utils.h"

/*
 * -- The fallback driver (using general file system). --
 */

/* Callback for archive_open on a general file system. */
static void *archive_fallback_open(const char *name)
{
	assert(name && *name);
	return strdup(name);
}

/* Callback for archive_close on a general file system. */
static int archive_fallback_close(void *handle)
{
	free(handle);
	return 0;
}

/* Callback for archive_walk on a general file system. */
static int archive_fallback_walk(
		void *handle, void *arg,
		int (*callback)(const char *path, void *arg))
{
	FTS *fts_handle;
	FTSENT *ent;
	char *fts_argv[2] = {};
	char default_path[] = ".";
	char *root = default_path;
	size_t root_len;

	if (handle)
		root = (char *)handle;
	root_len = strlen(root);
	fts_argv[0] = root;

	fts_handle = fts_open(fts_argv, FTS_NOCHDIR, NULL);
	if (!fts_handle)
		return -1;

	while ((ent = fts_read(fts_handle)) != NULL) {
		char *path = ent->fts_path + root_len;
		if (ent->fts_info != FTS_F && ent->fts_info != FTS_SL)
			continue;
		while (*path == '/')
			path++;
		if (!*path)
			continue;
		if (callback(path, arg))
			break;
	}
	return 0;
}

/* Callback for fallback drivers to get full path easily. */
static const char *archive_fallback_get_path(void *handle, const char *fname,
					     char **temp_path)
{
	if (handle && *fname != '/') {
		ASPRINTF(temp_path, "%s/%s", (char *)handle, fname);
		return *temp_path;
	}
	return fname;
}

/* Callback for archive_has_entry on a general file system. */
static int archive_fallback_has_entry(void *handle, const char *fname)
{
	int r;
	char *temp_path = NULL;
	const char *path = archive_fallback_get_path(handle, fname, &temp_path);

	VB2_DEBUG("Checking %s\n", path);
	r = access(path, R_OK);
	free(temp_path);
	return r == 0;
}

/* Callback for archive_read_file on a general file system. */
static int archive_fallback_read_file(void *handle, const char *fname,
				      uint8_t **data, uint32_t *size, int64_t *mtime)
{
	int r;
	char *temp_path = NULL;
	const char *path = archive_fallback_get_path(handle, fname, &temp_path);
	struct stat st;

	VB2_DEBUG("Reading %s\n", path);
	*data = NULL;
	*size = 0;
	/* vb2_read_file already has an extra '\0' in the end. */
	r = vb2_read_file(path, data, size) != VB2_SUCCESS;
	if (mtime) {
		if (stat(path, &st) == 0)
			*mtime = st.st_mtime;
		else
			WARN("Unable to stat %s: %s\n", path, strerror(errno));
	}
	free(temp_path);
	return r;
}

/* Callback for archive_write_file on a general file system. */
static int archive_fallback_write_file(void *handle, const char *fname,
				       uint8_t *data, uint32_t size, int64_t mtime)
{
	int r;
	char *temp_path = NULL;
	const char *path = archive_fallback_get_path(handle, fname, &temp_path);

	VB2_DEBUG("Writing %s\n", path);
	if (strchr(path, '/')) {
		char *dirname = strdup(path);
		*strrchr(dirname, '/') = '\0';
		/* TODO(hungte): call mkdir(2) instead of shell invocation. */
		if (access(dirname, W_OK) != 0) {
			char *command;
			ASPRINTF(&command, "mkdir -p %s", dirname);
			free(host_shell(command));
			free(command);
		}
		free(dirname);
	}
	r = vb2_write_file(path, data, size) != VB2_SUCCESS;
	if (mtime) {
		struct timeval times[2] = {
			{.tv_sec = mtime, .tv_usec = 0},
			{.tv_sec = mtime, .tv_usec = 0},
		};
		if (utimes(path, times) != 0)
			WARN("Unable to set times on %s: %s\n", path, strerror(errno));
	}
	free(temp_path);
	return r;
}

struct u_archive archive_fallback = {
	.open = archive_fallback_open,
	.close = archive_fallback_close,
	.walk = archive_fallback_walk,
	.has_entry = archive_fallback_has_entry,
	.read_file = archive_fallback_read_file,
	.write_file = archive_fallback_write_file,
};
