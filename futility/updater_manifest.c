/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Build up the list of updater resources from an archive.
 */

#include <assert.h>
#if defined(__OpenBSD__)
#include <sys/types.h>
#endif

#ifdef HAVE_CROSID
#include <crosid.h>
#endif

#include "updater.h"
#include "util_misc.h"

/*
 * The updater reads image files from a package. The package is usually an
 * archive (see updater_archive.c) with image files and configuration files, and
 * the meta data is maintained by a "manifest" that described below.
 *
 * A package for a single board (i.e., not Unified Build) will have all the
 * image files in the top folder:
 *  - host: 'image.bin' (or 'bios.bin' as legacy name before CL:1318712)
 *  - ec: 'ec.bin'
 *  - pd: 'pd.bin'
 *
 * If custom label is supported, a 'keyset/' folder will be available, with key
 * files in it:
 *  - rootkey.$CLTAG
 *  - vblock_A.$CLTAG
 *  - vblock_B.$CLTAG
 *
 * The $CLTAG should come from VPD value 'custom_label_tag'. For legacy devices,
 * the VPD name may be 'whitelabel_tag', or 'customization_id'.
 * The 'customization_id' has a different format: LOEM[-VARIANT] and we can only
 * take LOEM as $CLTAG, for example A-B => $CLTAG=A.
 *
 * A package for Unified Build is more complicated.
 *
 * You need to look at the signer_config.csv file to find image files and their
 * firmware manifest key (usually the same as the model name), then search for
 * patch files in the keyset/ folder.
 *
 * Similar to custom label in non-Unified-Build, the keys and vblock files will
 * be available in the 'keyset/' folder:
 *  - rootkey.$MANIFEST_KEY
 *  - vblock_A.$MANIFEST_KEY
 *  - vblock_B.$MANIFEST_KEY
 *
 * Historically (the original design in Unified Build) there should also be a
 * models/ folder, and each model should appear as a sub folder, with
 * a 'setvars.sh' file inside. The 'setvars.sh' is a shell script
 * describing what files should be used and the signature ID ($SIGID) to
 * use as firmware manifest key. If $SIGID starts with 'sig-id-in-*' then we
 * have to replace it by VPD value 'custom_label_tag' as '$MODEL-$CLTAG'.
 *
 * The current implementation is to first look at `setvars.sh` first, and then
 * fallback to `signer_config.csv` if needed.
 */

static const char * const SETVARS_IMAGE_MAIN = "IMAGE_MAIN",
		  * const SETVARS_IMAGE_EC = "IMAGE_EC",
		  * const SETVARS_IMAGE_PD = "IMAGE_PD",
		  * const SETVARS_SIGNATURE_ID = "SIGNATURE_ID",
		  * const SIG_ID_IN_VPD_PREFIX = "sig-id-in",
		  * const DIR_KEYSET = "keyset",
		  * const DIR_MODELS = "models",
		  * const DEFAULT_MODEL_NAME = "default",
		  * const VPD_CUSTOM_LABEL_TAG = "custom_label_tag",
		  * const VPD_CUSTOM_LABEL_TAG_LEGACY = "whitelabel_tag",
		  * const VPD_CUSTOMIZATION_ID = "customization_id",
		  * const ENV_VAR_MODEL_DIR = "${MODEL_DIR}",
		  * const PATH_STARTSWITH_KEYSET = "keyset/",
		  * const PATH_SIGNER_CONFIG = "signer_config.csv",
		  * const PATH_ENDSWITH_SETVARS = "/setvars.sh";

/* Utility function to convert a string. */
static void str_convert(char *s, int (*convert)(int c))
{
	int c;

	for (; *s; s++) {
		c = *s;
		if (!isascii(c))
			continue;
		*s = convert(c);
	}
}

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

/* Returns the VPD value by given key name, or NULL on error (or no value). */
static char *vpd_get_value(const char *fpath, const char *key)
{
	char *command, *result;

	assert(fpath);
	ASPRINTF(&command, "vpd -g %s -f %s 2>/dev/null", key, fpath);
	result = host_shell(command);
	free(command);

	if (result && !*result) {
		free(result);
		result = NULL;
	}
	return result;
}

/*
 * Reads and parses a setvars type file from archive, then stores into config.
 * Returns 0 on success (at least one entry found), otherwise failure.
 */
static int model_config_parse_setvars_file(
		struct model_config *cfg, struct u_archive *archive,
		const char *fpath)
{
	uint8_t *data;
	uint32_t len;

	char *ptr_line = NULL, *ptr_token = NULL;
	char *line, *k, *v;
	int valid = 0;

	if (archive_read_file(archive, fpath, &data, &len, NULL) != 0) {
		ERROR("Failed reading: %s\n", fpath);
		return -1;
	}

	/* Valid content should end with \n, or \"; ensure ASCIIZ for parsing */
	if (len)
		data[len - 1] = '\0';

	for (line = strtok_r((char *)data, "\n\r", &ptr_line); line;
	     line = strtok_r(NULL, "\n\r", &ptr_line)) {
		char *expand_path = NULL;
		int found_valid = 1;

		/* Format: KEY="value" */
		k = strtok_r(line, "=", &ptr_token);
		if (!k)
			continue;
		v = strtok_r(NULL, "\"", &ptr_token);
		if (!v)
			continue;

		/* Some legacy updaters may be still using ${MODEL_DIR}. */
		if (str_startswith(v, ENV_VAR_MODEL_DIR)) {
			ASPRINTF(&expand_path, "%s/%s%s", DIR_MODELS, cfg->name,
				 v + strlen(ENV_VAR_MODEL_DIR));
		}

		if (strcmp(k, SETVARS_IMAGE_MAIN) == 0)
			cfg->image = strdup(v);
		else if (strcmp(k, SETVARS_IMAGE_EC) == 0)
			cfg->ec_image = strdup(v);
		else if (strcmp(k, SETVARS_IMAGE_PD) == 0)
			cfg->pd_image = strdup(v);
		else if (strcmp(k, SETVARS_SIGNATURE_ID) == 0) {
			cfg->signature_id = strdup(v);
			if (str_startswith(v, SIG_ID_IN_VPD_PREFIX))
				cfg->is_custom_label = 1;
		} else
			found_valid = 0;
		free(expand_path);
		valid += found_valid;
	}
	free(data);
	return valid == 0;
}

/*
 * Changes the rootkey in firmware GBB to given new key.
 * Returns 0 on success, otherwise failure.
 */
static int change_gbb_rootkey(struct firmware_image *image,
			      const char *section_name,
			      const uint8_t *rootkey, uint32_t rootkey_len)
{
	const struct vb2_gbb_header *gbb = find_gbb(image);
	uint8_t *gbb_rootkey;
	if (!gbb) {
		ERROR("Cannot find GBB in image %s.\n", image->file_name);
		return -1;
	}
	if (gbb->rootkey_size < rootkey_len) {
		ERROR("New root key (%u bytes) larger than GBB (%u bytes).\n",
		      rootkey_len, gbb->rootkey_size);
		return -1;
	}

	gbb_rootkey = (uint8_t *)gbb + gbb->rootkey_offset;
	/* See cmd_gbb_utility: root key must be first cleared with zero. */
	memset(gbb_rootkey, 0, gbb->rootkey_size);
	memcpy(gbb_rootkey, rootkey, rootkey_len);
	return 0;
}

/*
 * Changes the firmware section (for example vblock or GSCVD) to new data.
 * Returns 0 on success, otherwise failure.
 */
static int change_section(struct firmware_image *image,
			  const char *section_name,
			  const uint8_t *data, uint32_t data_len)
{
	struct firmware_section section;

	find_firmware_section(&section, image, section_name);
	if (!section.data) {
		ERROR("Need section %s in image %s.\n", section_name,
		      image->file_name);
		return -1;
	}
	if (section.size < data_len) {
		ERROR("'%s' is too small (%zu bytes) for patching %u bytes.\n",
		      section_name, section.size, data_len);
		return -1;
	}
	/* First erase (0xff) the section in case the new data is smaller. */
	memset(section.data, 0xff, section.size);
	memcpy(section.data, data, data_len);
	return 0;
}

/*
 * Applies a key file to firmware image.
 * Returns 0 on success, otherwise failure.
 */
static int apply_key_file(
		struct firmware_image *image, const char *path,
		struct u_archive *archive, const char *section_name,
		int (*apply)(struct firmware_image *image, const char *section,
			     const uint8_t *data, uint32_t len))
{
	int r = 0;
	uint8_t *data = NULL;
	uint32_t len;

	r = archive_read_file(archive, path, &data, &len, NULL);
	if (r == 0) {
		VB2_DEBUG("Loaded file: %s\n", path);
		r = apply(image, section_name, data, len);
		if (r)
			ERROR("Failed applying %s to %s\n", path, section_name);
	} else {
		ERROR("Failed reading: %s\n", path);
	}
	free(data);
	return r;
}

/*
 * Modifies a firmware image from patch information specified in model config.
 * Returns 0 on success, otherwise number of failures.
 */
int patch_image_by_model(
		struct firmware_image *image, const struct model_config *model,
		struct u_archive *archive)
{
	int err = 0;
	if (model->patches.rootkey)
		err += !!apply_key_file(
				image, model->patches.rootkey, archive,
				FMAP_RO_GBB, change_gbb_rootkey);
	if (model->patches.vblock_a)
		err += !!apply_key_file(
				image, model->patches.vblock_a, archive,
				FMAP_RW_VBLOCK_A, change_section);
	if (model->patches.vblock_b)
		err += !!apply_key_file(
				image, model->patches.vblock_b, archive,
				FMAP_RW_VBLOCK_B, change_section);
	if (model->patches.gscvd)
		err += !!apply_key_file(
				image, model->patches.gscvd, archive,
				FMAP_RO_GSCVD, change_section);
	return err;
}

/*
 * Finds available patch files by given model.
 * Updates `model` argument with path of patch files.
 */
static void find_patches_for_model(struct model_config *model,
				   struct u_archive *archive,
				   const char *signature_id)
{
	char *path;
	int i;

	const char * const names[] = {
		"rootkey",
		"vblock_A",
		"vblock_B",
		"gscvd",
	};

	char **targets[] = {
		&model->patches.rootkey,
		&model->patches.vblock_a,
		&model->patches.vblock_b,
		&model->patches.gscvd,
	};

	assert(ARRAY_SIZE(names) == ARRAY_SIZE(targets));
	for (i = 0; i < ARRAY_SIZE(names); i++) {
		ASPRINTF(&path, "%s/%s.%s", DIR_KEYSET, names[i], signature_id);
		if (archive_has_entry(archive, path))
			*targets[i] = path;
		else
			free(path);
	}
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
		ERROR("Internal error: failed to allocate buffer.\n");
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
	struct u_archive *archive = manifest->archive;
	struct model_config model = {0};
	char *slash;

	if (str_startswith(name, PATH_STARTSWITH_KEYSET))
		manifest->has_keyset = 1;
	if (!str_endswith(name, PATH_ENDSWITH_SETVARS))
		return 0;

	/* name: models/$MODEL/setvars.sh */
	model.name = strdup(strchr(name, '/') + 1);
	slash = strchr(model.name, '/');
	if (slash)
		*slash = '\0';

	VB2_DEBUG("Found model <%s> setvars: %s\n", model.name, name);
	if (model_config_parse_setvars_file(&model, archive, name)) {
		ERROR("Invalid setvars file: %s\n", name);
		return 0;
	}

	/* In legacy setvars.sh, the ec_image and pd_image may not exist. */
	if (model.ec_image && !archive_has_entry(archive, model.ec_image)) {
		VB2_DEBUG("Ignore non-exist EC image: %s\n", model.ec_image);
		free(model.ec_image);
		model.ec_image = NULL;
	}
	if (model.pd_image && !archive_has_entry(archive, model.pd_image)) {
		VB2_DEBUG("Ignore non-exist PD image: %s\n", model.pd_image);
		free(model.pd_image);
		model.pd_image = NULL;
	}

	/* Find patch files. */
	if (model.signature_id)
		find_patches_for_model(&model, archive, model.signature_id);

	return !manifest_add_model(manifest, &model);
}

/*
 * A callback function for manifest to scan files in raw /firmware archive.
 * Returns 0 to keep scanning, or non-zero to stop.
 */
static int manifest_scan_raw_entries(const char *name, void *arg)
{
	struct manifest *manifest = (struct manifest *)arg;
	struct u_archive *archive = manifest->archive;
	struct model_config model = {0};
	char *ec_name = NULL;
	int chars_read = 0;

	/*
	 * /build/$BOARD/firmware (or CPFE firmware archives) layout:
	 * - image-${MODEL}{,.serial,.dev...}.bin
	 * - ${MODEL}/ec.bin
	 */

	if (sscanf(name, "image-%m[^.].bin%n", &model.name, &chars_read) != 1)
		return 0;

	/* Ignore the names with extra modifiers like image-$MODEL.serial.bin */
	if (!chars_read || name[chars_read]) {
		free(model.name);
		return 0;
	}

	VB2_DEBUG("Found model <%s>: %s\n", model.name, name);
	model.image = strdup(name);

	ASPRINTF(&ec_name, "%s/ec.bin", model.name);
	if (archive_has_entry(archive, ec_name))
		model.ec_image = strdup(ec_name);
	free(ec_name);

	return !manifest_add_model(manifest, &model);
}

/* Returns the matched model config from the manifest, or NULL if not found. */
static struct model_config *manifest_get_model_config(
		const struct manifest *manifest, const char *name)
{
	int i = 0;

	for (i = 0; i < manifest->num; i++) {
		if (!strcmp(name, manifest->models[i].name))
			return &manifest->models[i];
	}
	return NULL;
}

/* Releases (and zeros) the data inside a patch config. */
static void clear_patch_config(struct patch_config *patch)
{
	free(patch->rootkey);
	free(patch->vblock_a);
	free(patch->vblock_b);
	free(patch->gscvd);
	memset(patch, 0, sizeof(*patch));
}

/*
 * Creates the manifest from the 'signer_config.csv' file.
 * Returns 0 on success (loaded), otherwise failure.
 */
static int manifest_from_signer_config(struct manifest *manifest)
{
	struct u_archive *archive = manifest->archive;
	uint32_t size;
	uint8_t *data;
	char *s, *tok_ptr = NULL;

	if (!archive_has_entry(archive, PATH_SIGNER_CONFIG))
		return -1;

	/*
	 * CSV format: model_name,firmware_image,key_id,ec_image
	 *
	 * Note the key_id is not signature_id and won't be used, and ec_image
	 * may be optional (for example sarien).
	 */

	if (archive_read_file(archive, PATH_SIGNER_CONFIG, &data, &size,NULL)) {
		ERROR("Failed reading: %s\n", PATH_SIGNER_CONFIG);
		return -1;
	}

	/* Skip headers. */
	s = strtok_r((char *)data, "\n", &tok_ptr);
	if (!s || !strchr(s, ',')) {
		ERROR("Invalid %s: missing header.\n", PATH_SIGNER_CONFIG);
		free(data);
		return -1;
	}

	for (s = strtok_r(NULL, "\n", &tok_ptr); s != NULL;
	     s = strtok_r(NULL, "\n", &tok_ptr)) {

		struct model_config model = {0};
		int discard_model = 0;

		/*
		 * Both keyid (%3) and ec_image (%4) are optional so we want to
		 * read at least 2 fields.
		 */
		if (sscanf(s, "%m[^,],%m[^,],%*[^,],%m[^,]",
		    &model.name, &model.image, &model.ec_image) < 2) {
			ERROR("Invalid entry(%s): %s\n", PATH_SIGNER_CONFIG, s);
			discard_model = 1;
		} else if (strchr(model.name, '-')) {
			/* format: BaseModel-CustomLabel */
			char *tok_dash;
			char *base_model;
			struct model_config *base_model_config;

			VB2_DEBUG("Found custom-label: %s\n", model.name);
			discard_model = 1;
			base_model = strtok_r(model.name, "-", &tok_dash);
			assert(base_model);

			/*
			 * Currently we assume the base model (e.g., base_model)
			 * is always listed before CL models in the CSV file -
			 * this is based on how the signerbot and the
			 * chromeos-config works today (validated on octopus).
			 */
			base_model_config = manifest_get_model_config(
					manifest, base_model);

			if (!base_model_config) {
				ERROR("Invalid CL-model: %s\n", base_model);
			} else if (!base_model_config->is_custom_label) {
				base_model_config->is_custom_label = 1;
				/*
				 * Rewriting signature_id is not necessary,
				 * but in order to generate the same manifest
				 * from setvars, we want to temporarily use
				 * the special value.
				 */
				free(base_model_config->signature_id);
				base_model_config->signature_id = strdup(
						"sig-id-in-customization-id");
				/*
				 * Historically (e.g., setvars.sh), custom label
				 * devices will have signature ID set to
				 * 'sig-id-in-*' so the patch files will be
				 * discovered later from VPD. We want to
				 * follow that behavior until fully migrated.
				 */
				clear_patch_config(
						&base_model_config->patches);
			}
		}

		if (discard_model) {
			free(model.name);
			free(model.image);
			free(model.ec_image);
			continue;
		}

		/* Find patch files. */
		find_patches_for_model(&model, archive, model.name);

		model.signature_id = strdup(model.name);
		if (!manifest_add_model(manifest, &model))
			break;
	}
	free(data);
	return 0;
}

/*
 * Creates the manifest from a simple (legacy) folder with only 1 set of
 * firmware images.
 * Returns 0 on success (loaded), otherwise failure.
 */
static int manifest_from_simple_folder(struct manifest *manifest)
{
	const char * const host_image_name = "image.bin",
		   * const old_host_image_name = "bios.bin",
		   * const ec_name = "ec.bin",
		   * const pd_name = "pd.bin";
	struct u_archive *archive = manifest->archive;
	const char *image_name = NULL;
	struct firmware_image image = {0};
	struct model_config model = {0};

	/* Try to load from current folder. */
	if (archive_has_entry(archive, old_host_image_name))
		image_name = old_host_image_name;
	else if (archive_has_entry(archive, host_image_name))
		image_name = host_image_name;
	else
		return 1;

	model.image = strdup(image_name);
	if (archive_has_entry(archive, ec_name))
		model.ec_image = strdup(ec_name);
	if (archive_has_entry(archive, pd_name))
		model.pd_image = strdup(pd_name);
	/* Extract model name from FWID: $Vendor_$Platform.$Version */
	if (!load_firmware_image(&image, image_name, archive)) {
		char *token = NULL;
		if (strtok(image.ro_version, "_"))
			token = strtok(NULL, ".");
		if (token && *token) {
			str_convert(token, tolower);
			model.name = strdup(token);
		}
		free_firmware_image(&image);
	}
	if (!model.name)
		model.name = strdup(DEFAULT_MODEL_NAME);
	if (manifest->has_keyset)
		model.is_custom_label = 1;
	manifest_add_model(manifest, &model);
	manifest->default_model = manifest->num - 1;

	return 0;
}

/**
 * get_manifest_key() - Wrapper to get the firmware manifest key from crosid
 *
 * @manifest_key_out - Output parameter of the firmware manifest key.
 *
 * Returns:
 * - <0 if libcrosid is unavailable or there was an error reading
 *   device data
 * - >=0 (the matched device index) success
 */
static int get_manifest_key(char **manifest_key_out)
{
#ifdef HAVE_CROSID
	return crosid_get_firmware_manifest_key(manifest_key_out);
#else
	ERROR("This version of futility was compiled without libcrosid "
	      "(perhaps compiled outside of the Chrome OS build system?) and "
	      "the update command is not fully supported.  Either compile "
	      "from the Chrome OS build, or pass --model to manually specify "
	      "the machine model.\n");
	return -1;
#endif
}

/*
 * Finds the existing model_config from manifest that best matches current
 * system (as defined by model_name).
 * Returns a model_config from manifest, or NULL if not found.
 */
const struct model_config *manifest_find_model(const struct manifest *manifest,
					       const char *model_name)
{
	char *manifest_key = NULL;
	const struct model_config *model = NULL;
	int i;
	int matched_index;

	/*
	 * For manifest with single model defined, we should just return because
	 * there are other mechanisms like platform name check to double confirm
	 * if the firmware is valid.
	 */
	if (manifest->num == 1)
		return &manifest->models[0];

	if (!model_name) {
		matched_index = get_manifest_key(&manifest_key);
		if (matched_index < 0) {
			ERROR("Failed to get device identity.  "
			      "Run \"crosid -v\" for explanation.\n");
			return NULL;
		}

		INFO("Identified the device using libcrosid, "
		     "matched chromeos-config index: %d, "
		     "manifest key (model): %s\n",
		     matched_index, manifest_key);
		model_name = manifest_key;
	}

	model = manifest_get_model_config(manifest, model_name);

	if (!model) {
		ERROR("Unsupported model: '%s'.\n", model_name);

		fprintf(stderr,
			"The firmware manifest key '%s' is not present in this "
			"updater archive. The known keys to this updater "
			"archive are:\n", model_name);

		for (i = 0; i < manifest->num; i++)
			fprintf(stderr, " %s", manifest->models[i].name);
		fprintf(stderr, "\n\n");
		fprintf(stderr,
			"Perhaps you are trying to use an updater archive for "
			"the wrong board, or designed for an older OS version "
			"before this model was supported.\n");
		fprintf(stderr,
			"Hint: Read the FIRMWARE_MANIFEST_KEY from the output "
			"of the crosid command.\n");
	}


	free(manifest_key);
	return model;
}

const struct model_config *
manifest_detect_model_from_frid(struct updater_config *cfg,
				struct manifest *manifest)
{
	const struct model_config *result = NULL;
	struct firmware_image current_ro_frid = {0};
	current_ro_frid.programmer = cfg->image_current.programmer;
	int error = flashrom_read_region(&current_ro_frid, FMAP_RO_FRID,
					 cfg->verbosity + 1);
	const char *from_dot;
	int len;

	if (error)
		return NULL;

	current_ro_frid.data[current_ro_frid.size - 1] = '\0';
	from_dot = strchr((const char *)current_ro_frid.data, '.');
	if (!from_dot) {
		VB2_DEBUG("Missing dot (%s)\n",
			  (const char *)current_ro_frid.data);
		goto cleanup;
	}
	len = from_dot - (const char *)current_ro_frid.data + 1;

	for (int i = 0; i < manifest->num && !result; ++i) {
		struct model_config *m = &manifest->models[i];
		struct firmware_image image = {0};

		if (load_firmware_image(&image, m->image, manifest->archive))
			return NULL;

		VB2_DEBUG("Comparing '%*.*s' with '%*.*s'\n", len, len,
			  (const char *)current_ro_frid.data, len, len,
			  image.ro_version);
		if (strncasecmp((const char *)current_ro_frid.data,
				image.ro_version, len) == 0) {
			result = m;
		}
		free_firmware_image(&image);
	}
	if (result) {
		INFO("Detected model: '%s'\n", result->name);
	} else {
		ERROR("Unsupported FRID: '%*.*s'.\n", len - 1, len - 1,
		      (const char *)current_ro_frid.data);
	}
cleanup:
	free_firmware_image(&current_ro_frid);

	return result;
}

/*
 * Determines the signature ID to use for custom label.
 * Returns the signature ID for looking up rootkey and vblock files.
 * Caller must free the returned string.
 */
static char *resolve_signature_id(struct model_config *model, const char *image)
{
	int is_unibuild = model->signature_id ? 1 : 0;
	char *tag = vpd_get_value(image, VPD_CUSTOM_LABEL_TAG);
	char *sig_id = NULL;

	if (tag == NULL)
		tag = vpd_get_value(image, VPD_CUSTOM_LABEL_TAG_LEGACY);

	/* Unified build: $model.$tag, or $model (b/126800200). */
	if (is_unibuild) {
		if (!tag) {
			WARN("No VPD '%s' set for custom label. "
			     "Use model name '%s' as default.\n",
			     VPD_CUSTOM_LABEL_TAG, model->name);
			return strdup(model->name);
		}

		ASPRINTF(&sig_id, "%s-%s", model->name, tag);
		free(tag);
		return sig_id;
	}

	/* Non-Unibuild: Upper($tag), or Upper(${cid%%-*}). */
	if (!tag) {
		char *cid = vpd_get_value(image, VPD_CUSTOMIZATION_ID);
		if (cid) {
			/* customization_id in format LOEM[-VARIANT]. */
			char *dash = strchr(cid, '-');
			if (dash)
				*dash = '\0';
			tag = cid;
		}
	}
	if (tag)
		str_convert(tag, toupper);
	return tag;
}

/*
 * Applies custom label information to an existing model configuration.
 * Collects signature ID information from either parameter signature_id or
 * image file (via VPD) and updates model.patches for key files.
 * Returns 0 on success, otherwise failure.
 */
int model_apply_custom_label(
		struct model_config *model,
		struct u_archive *archive,
		const char *signature_id,
		const char *image)
{
	char *sig_id = NULL;
	int r = 0;

	if (!signature_id) {
		sig_id = resolve_signature_id(model, image);
		signature_id = sig_id;
	}

	if (signature_id) {
		VB2_DEBUG("Find custom label patches by signature ID: '%s'.\n",
		      signature_id);
		find_patches_for_model(model, archive, signature_id);
	} else {
		signature_id = "";
		WARN("No VPD '%s' set for custom label - use default keys.\n",
		     VPD_CUSTOM_LABEL_TAG);
	}
	if (!model->patches.rootkey) {
		ERROR("No keys found for signature_id: '%s'\n", signature_id);
		r = 1;
	} else {
		INFO("Applied for custom label: %s\n", signature_id);
	}
	free(sig_id);
	return r;
}

/*
 * Creates a new manifest object by scanning files in archive.
 * Returns the manifest on success, otherwise NULL for failure.
 */
struct manifest *new_manifest_from_archive(struct u_archive *archive)
{
	struct manifest manifest = {0}, *new_manifest;

	manifest.archive = archive;
	manifest.default_model = -1;

	VB2_DEBUG("Try to build a manifest from *%s\n", PATH_ENDSWITH_SETVARS);
	archive_walk(archive, &manifest, manifest_scan_entries);

	if (manifest.num == 0) {
		VB2_DEBUG("Try to build a manifest from %s\n",
			  PATH_SIGNER_CONFIG);
		manifest_from_signer_config(&manifest);
	}
	if (manifest.num == 0) {
		VB2_DEBUG("Try to build a manifest from a */firmware folder\n");
		archive_walk(archive, &manifest, manifest_scan_raw_entries);
	}
	if (manifest.num == 0) {
		VB2_DEBUG("Try to build a manifest from a simple folder\n");
		manifest_from_simple_folder(&manifest);
	}

	VB2_DEBUG("%d model(s) loaded.\n", manifest.num);
	if (!manifest.num) {
		ERROR("No valid configurations found from archive.\n");
		return NULL;
	}

	new_manifest = (struct manifest *)malloc(sizeof(manifest));
	if (!new_manifest) {
		ERROR("Internal error: memory allocation error.\n");
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
		clear_patch_config(&model->patches);
	}
	free(manifest->models);
	free(manifest);
}

static const char *get_gbb_key_hash(const struct vb2_gbb_header *gbb,
				    int32_t offset, int32_t size)
{
	struct vb2_packed_key *key;

	if (!gbb)
		return "<No GBB>";
	key = (struct vb2_packed_key *)((uint8_t *)gbb + offset);
	if (vb2_packed_key_looks_ok(key, size))
		return "<Invalid key>";
	return packed_key_sha1_string(key);
}

/* Prints the information of given image file in JSON format. */
static void print_json_image(
		const char *name, const char *fpath, struct model_config *m,
		struct u_archive *archive, int indent, int is_host)
{
	struct firmware_image image = {0};
	const struct vb2_gbb_header *gbb = NULL;
	if (!fpath)
		return;
	if (load_firmware_image(&image, fpath, archive))
		return;
	if (!is_host)
		printf(",\n");
	printf("%*s\"%s\": { \"versions\": { \"ro\": \"%s\", \"rw\": \"%s\" },",
	       indent, "", name, image.ro_version, image.rw_version_a);
	indent += 2;
	if (is_host) {
		if (patch_image_by_model(&image, m, archive))
			ERROR("Failed to patch images by model: %s\n", m->name);
		else
			gbb = find_gbb(&image);
	}
	if (gbb != NULL) {
		printf("\n%*s\"keys\": { \"root\": \"%s\", ",
		       indent, "",
		       get_gbb_key_hash(gbb, gbb->rootkey_offset,
					gbb->rootkey_size));
		printf("\"recovery\": \"%s\" },",
		       get_gbb_key_hash(gbb, gbb->recovery_key_offset,
					gbb->recovery_key_size));
	}
	printf("\n%*s\"image\": \"%s\" }", indent, "", fpath);
	free_firmware_image(&image);
}

/* Prints the information of objects in manifest (models and images) in JSON. */
void print_json_manifest(const struct manifest *manifest)
{
	int i, indent;
	struct u_archive *ar = manifest->archive;

	printf("{\n");
	for (i = 0, indent = 2; i < manifest->num; i++) {
		struct model_config *m = &manifest->models[i];
		printf("%s%*s\"%s\": {\n", i ? ",\n" : "", indent, "", m->name);
		indent += 2;
		print_json_image("host", m->image, m, ar, indent, 1);
		print_json_image("ec", m->ec_image, m, ar, indent, 0);
		print_json_image("pd", m->pd_image, m, ar, indent, 0);
		if (m->patches.rootkey) {
			struct patch_config *p = &m->patches;
			printf(",\n%*s\"patches\": { \"rootkey\": \"%s\", "
			       "\"vblock_a\": \"%s\", \"vblock_b\": \"%s\"",
			       indent, "", p->rootkey, p->vblock_a,
			       p->vblock_b);
			if (p->gscvd)
				printf(", \"gscvd\": \"%s\"", p->gscvd);
			printf(" }");
		}
		if (m->signature_id)
			printf(",\n%*s\"signature_id\": \"%s\"", indent, "",
			       m->signature_id);
		printf("\n  }");
		indent -= 2;
		assert(indent == 2);
	}
	printf("\n}\n");
}
