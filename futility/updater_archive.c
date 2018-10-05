/*
 * Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Accessing updater resources from an archive.
 */

#include <assert.h>
#include <fts.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAVE_LIBZIP
#include <zip.h>
#endif

#include "host_misc.h"
#include "updater.h"
#include "vb2_common.h"

/*
 * A firmware update package (archive) is a file packed by either shar(1) or
 * zip(1). See https://chromium.googlesource.com/chromiumos/platform/firmware/
 * for more information.
 *
 * A package for single board (i.e., not Unified Build) will have all the image
 * files in top folder:
 *  - host: 'bios.bin'
 *  - ec: 'ec.bin'
 *  - pd: 'pd.bin'
 * If white label is supported, a 'keyset/' folder will be available, with key
 * files in it:
 *  - rootkey.$WLTAG
 *  - vblock_A.$WLTAG
 *  - vblock_B.$WLTAG
 * The $WLTAG should come from VPD value 'whitelabel_tag', or the
 * 'customization_id'. Note 'customization_id' is in format LOEM[-VARIANT] and
 * we can only take LOEM as $WLTAG, for example A-B => $WLTAG=A.
 *
 * A package for Unified Build is more complicated. There will be a models/
 * folder, and each model (by $(mosys platform model) ) should appear as a sub
 * folder, with a 'setvars.sh' file inside. The 'setvars.sh' is a shell script
 * describing what files should be used and the signature ID ($SIGID) to use.
 *
 * Similar to write label in non-Unified-Build, the keys and vblock files will
 * be in 'keyset/' folder:
 *  - rootkey.$SIGID
 *  - vblock_A.$SIGID
 *  - vblock_B.$SIGID
 * If $SIGID starts with 'sig-id-in-*' then we have to replace it by VPD value
 * 'whitelabel_tag' as '$MODEL-$WLTAG'.
 */

static const char * const SETVARS_IMAGE_MAIN = "IMAGE_MAIN",
		  * const SETVARS_IMAGE_EC = "IMAGE_EC",
		  * const SETVARS_IMAGE_PD = "IMAGE_PD",
		  * const SETVARS_SIGNATURE_ID = "SIGNATURE_ID",
		  * const SIG_ID_IN_VPD_PREFIX = "sig-id-in",
		  * const DIR_KEYSET = "keyset",
		  * const DIR_MODELS = "models",
		  * const DEFAULT_MODEL_NAME = "default",
		  * const PATH_STARTSWITH_KEYSET = "keyset/",
		  * const PATH_ENDSWITH_SERVARS = "/setvars.sh";

struct archive {
	void *handle;

	void * (*open)(const char *name);
	int (*close)(void *handle);

	int (*walk)(void *handle, void *arg,
		    int (*callback)(const char *path, void *arg));
	int (*has_entry)(void *handle, const char *name);
	int (*read_file)(void *handle, const char *fname,
			 uint8_t **data, uint32_t *size);
};

/*
 * -- Begin of archive implementations --
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
		while (*path == '/')
			path++;
		if (!*path)
			continue;
		if (callback(path, arg))
			break;
	}
	return 0;
}

/* Callback for archive_has_entry on a general file system. */
static int archive_fallback_has_entry(void *handle, const char *fname)
{
	int r;
	const char *path = fname;
	char *temp_path = NULL;

	if (handle && *fname != '/') {
		ASPRINTF(&temp_path, "%s/%s", (char *)handle, fname);
		path = temp_path;
	}

	DEBUG("Checking %s", path);
	r = access(path, R_OK);
	free(temp_path);
	return r == 0;
}

/* Callback for archive_read_file on a general file system. */
static int archive_fallback_read_file(void *handle, const char *fname,
				      uint8_t **data, uint32_t *size)
{
	int r;
	const char *path = fname;
	char *temp_path = NULL;

	*data = NULL;
	*size = 0;
	if (handle && *fname != '/') {
		ASPRINTF(&temp_path, "%s/%s", (char *)handle, fname);
		path = temp_path;
	}
	DEBUG("Reading %s", path);
	r = vb2_read_file(path, data, size) != VB2_SUCCESS;
	free(temp_path);
	return r;
}

#ifdef HAVE_LIBZIP

/* Callback for archive_open on a ZIP file. */
static void *archive_zip_open(const char *name)
{
	return zip_open(name, 0, NULL);
}

/* Callback for archive_close on a ZIP file. */
static int archive_zip_close(void *handle)
{
	struct zip *zip = (struct zip *)handle;

	if (zip)
		return zip_close(zip);
	return 0;
}

/* Callback for archive_has_entry on a ZIP file. */
static int archive_zip_has_entry(void *handle, const char *fname)
{
	struct zip *zip = (struct zip *)handle;
	assert(zip);
	return zip_name_locate(zip, fname, 0) != -1;
}

/* Callback for archive_walk on a ZIP file. */
static int archive_zip_walk(
		void *handle, void *arg,
		int (*callback)(const char *name, void *arg))
{
	zip_int64_t num, i;
	struct zip *zip = (struct zip *)handle;
	assert(zip);

	num = zip_get_num_entries(zip, 0);
	if (num < 0)
		return 1;
	for (i = 0; i < num; i++) {
		if (callback(zip_get_name(zip, i, 0), arg))
			break;
	}
	return 0;
}

/* Callback for archive_zip_read_file on a ZIP file. */
static int archive_zip_read_file(void *handle, const char *fname,
			     uint8_t **data, uint32_t *size)
{
	struct zip *zip = (struct zip *)handle;
	struct zip_file *fp;
	struct zip_stat stat;

	assert(zip);
	*data = NULL;
	*size = 0;
	zip_stat_init(&stat);
	if (zip_stat(zip, fname, 0, &stat)) {
		ERROR("Fail to stat entry in ZIP: %s", fname);
		return 1;
	}
	fp = zip_fopen(zip, fname, 0);
	if (!fp) {
		ERROR("Failed to open entry in ZIP: %s", fname);
		return 1;
	}
	*data = (uint8_t *)malloc(stat.size);
	if (*data) {
		if (zip_fread(fp, *data, stat.size) == stat.size) {
			*size = stat.size;
		} else {
			ERROR("Failed to read entry in zip: %s", fname);
			free(*data);
			*data = NULL;
		}
	}
	zip_fclose(fp);
	return *data == NULL;
}
#endif

/*
 * Opens an archive from given path.
 * The type of archive will be determined automatically.
 * Returns a pointer to reference to archive (must be released by archive_close
 * when not used), otherwise NULL on error.
 */
struct archive *archive_open(const char *path)
{
	struct stat path_stat;
	struct archive *ar;

	if (stat(path, &path_stat) != 0) {
		ERROR("Cannot identify type of path: %s", path);
		return NULL;
	}

	ar = (struct archive *)malloc(sizeof(*ar));
	if (!ar) {
		ERROR("Internal error: allocation failure.");
		return NULL;
	}

	if (S_ISDIR(path_stat.st_mode)) {
		DEBUG("Found directory, use fallback (fs) driver: %s", path);
		/* Regular file system. */
		ar->open = archive_fallback_open;
		ar->close = archive_fallback_close;
		ar->walk = archive_fallback_walk;
		ar->has_entry = archive_fallback_has_entry;
		ar->read_file = archive_fallback_read_file;
	} else {
#ifdef HAVE_LIBZIP
		DEBUG("Found file, use ZIP driver: %s", path);
		ar->open = archive_zip_open;
		ar->close = archive_zip_close;
		ar->walk = archive_zip_walk;
		ar->has_entry = archive_zip_has_entry;
		ar->read_file = archive_zip_read_file;
#else
		ERROR("Found file, but no drivers were enabled: %s", path);
		free(ar);
		return NULL;
#endif
	}
	ar->handle = ar->open(path);
	if (!ar->handle) {
		ERROR("Failed to open archive: %s", path);
		free(ar);
		return NULL;
	}
	return ar;
}

/*
 * Closes an archive reference.
 * Returns 0 on success, otherwise non-zero as failure.
 */
int archive_close(struct archive *ar)
{
	int r = ar->close(ar->handle);
	free(ar);
	return r;
}

/*
 * Checks if an entry (either file or directory) exists in archive.
 * If entry name (fname) is an absolute path (/file), always check
 * with real file system.
 * Returns 1 if exists, otherwise 0
 */
int archive_has_entry(struct archive *ar, const char *name)
{
	if (!ar || *name == '/')
		return archive_fallback_has_entry(NULL, name);
	return ar->has_entry(ar->handle, name);
}

/*
 * Traverses all entries within archive.
 * For every entry, the path (relative the archive root) will be passed to
 * callback function, until the callback returns non-zero.
 * The arg argument will also be passed to callback.
 * Be aware that some archive may not store "directory" type entries.
 * Returns 0 on success otherwise non-zero as failure.
 */
int archive_walk(
		struct archive *ar, void *arg,
		int (*callback)(const char *path, void *arg))
{
	if (!ar)
		return archive_fallback_walk(NULL, arg, callback);
	return ar->walk(ar->handle, arg, callback);
}

/*
 * Reads a file from archive.
 * If entry name (fname) is an absolute path (/file), always read
 * from real file system.
 * Returns 0 on success (data and size reflects the file content),
 * otherwise non-zero as failure.
 */
int archive_read_file(struct archive *ar, const char *fname,
		      uint8_t **data, uint32_t *size)
{
	if (!ar || *fname == '/')
		return archive_fallback_read_file(NULL, fname, data, size);
	return ar->read_file(ar->handle, fname, data, size);
}

/*
 * -- End of archive implementations --
 */

/* Returns 1 if name ends by given pattern, otherwise 0. */
static int str_endswith(const char *name, const char *pattern)
{
	size_t name_len = strlen(name), pattern_len = strlen(pattern);
	if (name_len < pattern_len)
		return 0;
	return strcmp(name + name_len - pattern_len, pattern) == 0;
}

/* Returns 1 if name starts by given pattern, otherwise 0. */
static int str_startswith(const char *name, const char *pattern)
{
	return strncmp(name, pattern, strlen(pattern)) == 0;
}

/*
 * Reads and parses a setvars type file from archive, then stores into config.
 * Returns 0 on success (at least one entry found), otherwise failure.
 */
static int model_config_parse_setvars_file(
		struct model_config *cfg, struct archive *archive,
		const char *fpath)
{
	uint8_t *data;
	uint32_t len;

	char *ptr_line, *ptr_token;
	char *line, *k, *v;
	int valid = 0;

	if (archive_read_file(archive, fpath, &data, &len) != 0) {
		ERROR("Failed reading: %s", fpath);
		return -1;
	}

	/* Valid content should end with \n, or \"; ensure ASCIIZ for parsing */
	if (len)
		data[len - 1] = '\0';

	for (line = strtok_r((char *)data, "\n\r", &ptr_line); line;
	     line = strtok_r(NULL, "\n\r", &ptr_line)) {
		/* Format: KEY="value" */
		k = strtok_r(line, "=", &ptr_token);
		if (!k)
			continue;
		v = strtok_r(NULL, "\"", &ptr_token);
		if (!v)
			continue;

		if (strcmp(k, SETVARS_IMAGE_MAIN) == 0)
			cfg->image = strdup(v);
		else if (strcmp(k, SETVARS_IMAGE_EC) == 0)
			cfg->ec_image = strdup(v);
		else if (strcmp(k, SETVARS_IMAGE_PD) == 0)
			cfg->pd_image = strdup(v);
		else if (strcmp(k, SETVARS_SIGNATURE_ID) == 0)
			cfg->signature_id = strdup(v);
		else
			continue;
		valid++;
	}
	free(data);
	return valid == 0;
}

/*
 * Adds and copies one new model config to the existing list of given manifest.
 * Returns a pointer to the newly allocated config, or NULL on failure.
 */
static struct model_config *manifest_add_model(
		struct manifest *manifest,
		const struct model_config *cfg)
{
	struct model_config *model;
	manifest->num++;
	manifest->models = (struct model_config *)realloc(
			manifest->models, manifest->num * sizeof(*model));
	if (!manifest->models) {
		ERROR("Internal error: failed to allocate buffer.");
		return NULL;
	}
	model = &manifest->models[manifest->num - 1];
	memcpy(model, cfg, sizeof(*model));
	return model;
}

/*
 * A callback function for manifest to scan files in archive.
 * Returns 0 to keep scanning, or non-zero to stop.
 */
static int manifest_scan_entries(const char *name, void *arg)
{
	struct manifest *manifest = (struct manifest *)arg;
	struct archive *archive = manifest->archive;
	struct model_config model = {0};
	char *slash;

	if (str_startswith(name, PATH_STARTSWITH_KEYSET))
		manifest->has_keyset = 1;
	if (!str_endswith(name, PATH_ENDSWITH_SERVARS))
		return 0;

	/* name: models/$MODEL/setvars.sh */
	model.name = strdup(strchr(name, '/') + 1);
	slash = strchr(model.name, '/');
	if (slash)
		*slash = '\0';

	DEBUG("Found model <%s> setvars: %s", model.name, name);
	if (model_config_parse_setvars_file(&model, archive, name)) {
		ERROR("Invalid setvars file: %s", name);
		return 0;
	}

	/* In legacy setvars.sh, the ec_image and pd_image may not exist. */
	if (model.ec_image && !archive_has_entry(archive, model.ec_image)) {
		DEBUG("Ignore non-exist EC image: %s", model.ec_image);
		free(model.ec_image);
		model.ec_image = NULL;
	}
	if (model.pd_image && !archive_has_entry(archive, model.pd_image)) {
		DEBUG("Ignore non-exist PD image: %s", model.pd_image);
		free(model.pd_image);
		model.pd_image = NULL;
	}
	return !manifest_add_model(manifest, &model);
}

/*
 * Creates a new manifest object by scanning files in archive.
 * Returns the manifest on success, otherwise NULL for failure.
 */
struct manifest *new_manifest_from_archive(struct archive *archive)
{
	struct manifest manifest = {0}, *new_manifest;
	struct model_config model = {0};
	const char * const image_name = "bios.bin",
	           * const ec_name = "ec.bin",
		   * const pd_name = "pd.bin";

	manifest.archive = archive;
	manifest.default_model = -1;
	archive_walk(archive, &manifest, manifest_scan_entries);
	if (manifest.num == 0) {
		/* Try to load from current folder. */
		if (!archive_has_entry(archive, image_name))
			return 0;
		model.image = strdup(image_name);
		if (archive_has_entry(archive, ec_name))
			model.ec_image = strdup(ec_name);
		if (archive_has_entry(archive, pd_name))
			model.pd_image = strdup(pd_name);
		model.name = strdup(DEFAULT_MODEL_NAME);
		manifest_add_model(&manifest, &model);
		manifest.default_model = manifest.num - 1;
	}
	DEBUG("%d model(s) loaded.", manifest.num);
	if (!manifest.num) {
		ERROR("No valid configurations found from archive.");
		return NULL;
	}

	new_manifest = (struct manifest *)malloc(sizeof(manifest));
	if (!new_manifest) {
		ERROR("Internal error: memory allocation error.");
		return NULL;
	}
	memcpy(new_manifest, &manifest, sizeof(manifest));
	return new_manifest;
}

/* Releases all resources allocated by given manifest object. */
void delete_manifest(struct manifest *manifest)
{
	int i;
	assert(manifest);
	for (i = 0; i < manifest->num; i++) {
		struct model_config *model = &manifest->models[i];
		free(model->name);
		free(model->signature_id);
		free(model->image);
		free(model->ec_image);
		free(model->pd_image);
	}
	free(manifest->models);
	free(manifest);
}

/* Prints the information of given image file in JSON format. */
static void print_json_image(
		const char *name, const char *fpath, struct archive *archive,
		int indent, int is_host)
{
	struct firmware_image image = {0};
	if (!fpath)
		return;
	load_firmware_image(&image, fpath, archive);
	if (!is_host)
		printf(",\n");
	printf("%*s\"%s\": { \"versions\": { \"ro\": \"%s\", \"rw\": \"%s\" },",
	       indent, "", name, image.ro_version, image.rw_version_a);
	printf("\n%*s\"image\": \"%s\" }", indent + 2, "", fpath);
	free_firmware_image(&image);
}

/* Prints the information of objects in manifest (models and images) in JSON. */
void print_json_manifest(const struct manifest *manifest)
{
	int i, indent;
	struct archive *ar = manifest->archive;

	printf("{\n");
	for (i = 0, indent = 2; i < manifest->num; i++) {
		struct model_config *m = &manifest->models[i];
		printf("%s%*s\"%s\": {\n", i ? ",\n" : "", indent, "", m->name);
		indent += 2;
		print_json_image("host", m->image, ar, indent, 1);
		print_json_image("ec", m->ec_image, ar, indent, 0);
		print_json_image("pd", m->pd_image, ar, indent, 0);
		if (m->signature_id)
			printf(",\n%*s\"signature_id\": \"%s\"", indent, "",
			       m->signature_id);
		printf("\n  }");
		indent -= 2;
		assert(indent == 2);
	}
	printf("\n}\n");
}
