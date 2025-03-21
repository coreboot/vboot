/* Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * A reference implementation for AP (and supporting images) firmware updater.
 */

#ifndef VBOOT_REFERENCE_FUTILITY_UPDATER_H_
#define VBOOT_REFERENCE_FUTILITY_UPDATER_H_

#include "futility.h"
#include "updater_utils.h"

/* FMAP section names. */
static const char * const FMAP_RO = "WP_RO",
		  * const FMAP_RO_FMAP = "FMAP",
		  * const FMAP_RO_FRID = "RO_FRID",
		  * const FMAP_RO_SECTION = "RO_SECTION",
		  * const FMAP_RO_CBFS = "COREBOOT",
		  * const FMAP_RO_GBB = "GBB",
		  * const FMAP_RO_GSCVD = "RO_GSCVD",
		  * const FMAP_RO_VPD = "RO_VPD",
		  * const FMAP_RW_VBLOCK_A = "VBLOCK_A",
		  * const FMAP_RW_VBLOCK_B = "VBLOCK_B",
		  * const FMAP_RW_FW_MAIN_A = "FW_MAIN_A",
		  * const FMAP_RW_FW_MAIN_B = "FW_MAIN_B",
		  * const FMAP_RW_SECTION_A = "RW_SECTION_A",
		  * const FMAP_RW_SECTION_B = "RW_SECTION_B",
		  * const FMAP_RW_FWID = "RW_FWID",
		  * const FMAP_RW_FWID_A = "RW_FWID_A",
		  * const FMAP_RW_FWID_B = "RW_FWID_B",
		  * const FMAP_RW_SHARED = "RW_SHARED",
		  * const FMAP_RW_LEGACY = "RW_LEGACY",
		  * const FMAP_RW_VPD = "RW_VPD",
		  * const FMAP_RW_DIAG_NVRAM = "DIAG_NVRAM",
		  * const FMAP_SI_DESC = "SI_DESC",
		  * const FMAP_SI_ME = "SI_ME";

struct updater_config;
struct quirk_entry {
	const char *name;
	const char *help;
	int (*apply)(struct updater_config *cfg);
	int value;
};

enum quirk_types {
	/* Platform-independent quirks */
	QUIRK_NO_CHECK_PLATFORM,
	QUIRK_NO_VERIFY,
	QUIRK_ENLARGE_IMAGE,
	QUIRK_MIN_PLATFORM_VERSION,
	QUIRK_EXTRA_RETRIES,
	/* Arch-specific quirks */
	QUIRK_EC_PARTIAL_RECOVERY,
	QUIRK_CLEAR_MRC_DATA,
	QUIRK_PRESERVE_ME,
	/* Platform-specific quirks (removed after AUE) */
	QUIRK_OVERRIDE_CUSTOM_LABEL,
	QUIRK_EVE_SMM_STORE,
	QUIRK_UNLOCK_CSME_EVE,
	QUIRK_UNLOCK_CSME,
	/* End of quirks */
	QUIRK_MAX,
};

/* Return values from QUIRK_EC_PARTIAL_RECOVERY. */
enum {
	EC_RECOVERY_FULL = 0,  /* Must be 0 as default value of quirks. */
	EC_RECOVERY_RO,
	EC_RECOVERY_DONE
};

enum try_update_type {
	TRY_UPDATE_OFF = 0,
	TRY_UPDATE_AUTO,
	TRY_UPDATE_DEFERRED_HOLD,
	TRY_UPDATE_DEFERRED_APPLY,
};

struct updater_config {
	struct firmware_image image, image_current;
	struct firmware_image ec_image;
	struct dut_property dut_properties[DUT_PROP_MAX];
	struct quirk_entry quirks[QUIRK_MAX];
	struct u_archive *archive;
	struct tempfile tempfiles;
	enum try_update_type try_update;
	int force_update;
	int legacy_update;
	int factory_update;
	int check_platform;
	int use_diff_image;
	int do_verify;
	int verbosity;
	const char *emulation;
	char *emulation_programmer;
	const char *original_programmer;
	const char *prepare_ctrl_name;
	int override_gbb_flags;
	uint32_t gbb_flags;
	bool detect_model;
	bool dut_is_remote;
	bool output_only;
};

enum manifest_print_format {
	MANIFEST_PRINT_FORMAT_JSON = 0,
	MANIFEST_PRINT_FORMAT_PARSEABLE,
};

struct updater_config_arguments {
	char *image, *ec_image;
	char *archive, *quirks, *mode;
	const char *programmer, *write_protection;
	char *model;
	char *emulation, *sys_props;
	char *output_dir;
	char *repack, *unpack;
	int is_factory, try_update, force_update, do_manifest, host_only;
	enum manifest_print_format manifest_format;
	int fast_update;
	int verbosity;
	int override_gbb_flags;
	int detect_servo;
	int use_flash;
	uint32_t gbb_flags;
	bool detect_model_only;
	bool unlock_me;
};

/*
 * Shared getopt arguments controlling flash behaviour.
 * These are shared by multiple commands.
 */
enum {
	OPT_CCD = 0x100,
	OPT_EMULATE,
	OPT_SERVO,
	OPT_SERVO_PORT,
};

#ifdef USE_FLASHROM
#define SHARED_FLASH_ARGS_SHORTOPTS "p:"

#define SHARED_FLASH_ARGS_LONGOPTS                                             \
	{"programmer", 1, NULL, 'p'},                                          \
	{"ccd_without_servod", 2, NULL, OPT_CCD},                              \
	{"servo", 0, NULL, OPT_SERVO},                                         \
	{"servo_port", 1, NULL, OPT_SERVO_PORT},                               \
	{"emulate", 1, NULL, OPT_EMULATE},

#define SHARED_FLASH_ARGS_HELP                                                 \
	"-p, --programmer=PRG\tChange AP (host) flashrom programmer\n"         \
	"    --ccd_without_servod[=SERIAL] \tFlash via CCD without servod\n"   \
	"    --emulate=FILE  \tEmulate system firmware using file\n"           \
	"    --servo         \tFlash using Servo (v2, v4, micro, ...)\n"       \
	"    --servo_port=PRT\tOverride servod port, implies --servo\n"
#else
#define SHARED_FLASH_ARGS_HELP
#define SHARED_FLASH_ARGS_LONGOPTS
#define SHARED_FLASH_ARGS_SHORTOPTS
#endif /* USE_FLASHROM */

struct patch_config {
	char *rootkey;
	char *vblock_a;
	char *vblock_b;
	char *gscvd;
};

struct model_config {
	char *name;
	char *image, *ec_image;
	struct patch_config patches;
	bool has_custom_label;
};

struct manifest {
	int num;
	struct model_config *models;
	struct u_archive *archive;
	int default_model;
};

enum updater_error_codes {
	UPDATE_ERR_DONE,
	UPDATE_ERR_NEED_RO_UPDATE,
	UPDATE_ERR_NO_IMAGE,
	UPDATE_ERR_SYSTEM_IMAGE,
	UPDATE_ERR_INVALID_IMAGE,
	UPDATE_ERR_SET_COOKIES,
	UPDATE_ERR_WRITE_FIRMWARE,
	UPDATE_ERR_PLATFORM,
	UPDATE_ERR_TARGET,
	UPDATE_ERR_ROOT_KEY,
	UPDATE_ERR_TPM_ROLLBACK,
	UPDATE_ERR_UNLOCK_CSME,
	UPDATE_ERR_UNKNOWN,
};

/* Messages explaining enum updater_error_codes. */
extern const char * const updater_error_messages[];

/*
 * Returns a valid root key from GBB header, or NULL on failure.
 */
const struct vb2_packed_key *get_rootkey(
		const struct vb2_gbb_header *gbb);

/*
 * The main updater to update system firmware using the configuration parameter.
 * Returns UPDATE_ERR_DONE if success, otherwise failure.
 */
enum updater_error_codes update_firmware(struct updater_config *cfg);

/*
 * Allocates and initializes a updater_config object with default values.
 * Returns the newly allocated object, or NULL on error.
 */
struct updater_config *updater_new_config(void);

/*
 * Releases all resources in an updater configuration object.
 */
void updater_delete_config(struct updater_config *cfg);

/*
 * Handle an argument if it is a shared updater option.
 * Returns 1 if argument was used.
 */
int handle_flash_argument(struct updater_config_arguments *args, int opt,
			  char *optarg);

/**
 * Helper function to setup an allocated updater_config object.
 * Returns number of failures, or 0 on success.
 * @param[out]  updater_config,
 * @param[int]  updater_config_arguments,
 */
int updater_setup_config(struct updater_config *cfg,
			 const struct updater_config_arguments *arg);

/**
 * Helper function to determine if to perform a update.
 * Returns true to perform update otherwise false.
 * @param[in]  updater_config_arguments,
 */
bool updater_should_update(const struct updater_config_arguments *arg);

/* Prints the name and description from all supported quirks. */
void updater_list_config_quirks(const struct updater_config *cfg);

/*
 * Registers known quirks to a updater_config object.
 */
void updater_register_quirks(struct updater_config *cfg);

/* Gets the value (setting) of specified quirks from updater configuration. */
int get_config_quirk(enum quirk_types quirk, const struct updater_config *cfg);

/*
 * Gets the default quirk config string from target image name.
 * Returns a string (in same format as --quirks) to load or NULL if no quirks.
 */
const char * const updater_get_model_quirks(struct updater_config *cfg);

/*
 * Gets the quirk config string from target image CBFS.
 * Returns a string (in same format as --quirks) to load or NULL if no quirks.
 */
char * updater_get_cbfs_quirks(struct updater_config *cfg);

/*
 * Overrides the custom label config if the device was shipped with known
 * special rootkey.
 */
const struct model_config *quirk_override_custom_label(
		struct updater_config *cfg,
		const struct manifest *manifest,
		const struct model_config *model);

/* Functions from updater_archive.c */

/*
 * Opens an archive from given path.
 * The type of archive will be determined automatically.
 * Returns a pointer to reference to archive (must be released by archive_close
 * when not used), otherwise NULL on error.
 */
struct u_archive *archive_open(const char *path);

/*
 * Closes an archive reference.
 * Returns 0 on success, otherwise non-zero as failure.
 */
int archive_close(struct u_archive *ar);

/*
 * Checks if an entry (either file or directory) exists in archive.
 * Returns 1 if exists, otherwise 0
 */
int archive_has_entry(struct u_archive *ar, const char *name);

/*
 * Reads a file from archive.
 * Returns 0 on success (data and size reflects the file content),
 * otherwise non-zero as failure.
 */
int archive_read_file(struct u_archive *ar, const char *fname,
		      uint8_t **data, uint32_t *size, int64_t *mtime);

/*
 * Writes a file into archive.
 * If entry name (fname) is an absolute path (/file), always write into real
 * file system.
 * Returns 0 on success, otherwise non-zero as failure.
 */
int archive_write_file(struct u_archive *ar, const char *fname,
		       uint8_t *data, uint32_t size, int64_t mtime);

/*
 * Traverses all files within archive (directories are ignored).
 * For every entry, the path (relative the archive root) will be passed to
 * callback function, until the callback returns non-zero.
 * The arg argument will also be passed to callback.
 * Returns 0 on success otherwise non-zero as failure.
 */
int archive_walk(struct u_archive *ar, void *arg,
		 int (*callback)(const char *path, void *arg));

/*
 * Copies all entries from one archive to another.
 * Returns 0 on success, otherwise non-zero as failure.
 */
int archive_copy(struct u_archive *from, struct u_archive *to);

/*
 * Creates a new manifest object by scanning files in archive.
 * Returns the manifest on success, otherwise NULL for failure.
 */
struct manifest *new_manifest_from_archive(struct u_archive *archive);

/* Releases all resources allocated by given manifest object. */
void delete_manifest(struct manifest *manifest);

/* Prints the information of objects in manifest (models and images) in JSON. */
void print_json_manifest(const struct manifest *manifest);

/* Prints the manifest in parseable double-colon-separated tokens format. */
void print_parseable_manifest(const struct manifest *manifest);

/*
 * Modifies a firmware image from patch information specified in model config.
 * Returns 0 on success, otherwise number of failures.
 */
int patch_image_by_model(
		struct firmware_image *image, const struct model_config *model,
		struct u_archive *archive);

/*
 * Finds the existing model_config from manifest that best matches current
 * system (as defined by model_name).
 * Returns a model_config from manifest, or NULL if not found.
 */
const struct model_config *manifest_find_model(struct updater_config *cfg,
					       const struct manifest *manifest,
					       const char *model_name);

/*
 * Finds the first existing model_config from manifest that matches current
 * system by reading RO_FRID from the existing host firmware.
 * Returns a model_config from manifest, or NULL if not found.
 */
const struct model_config *
manifest_detect_model_from_frid(struct updater_config *cfg,
				struct manifest *manifest);

/*
 * Finds the custom label model config from the base model + system tag.
 * The system tag came from the firmware VPD section.
 * Returns the matched model_config, base if no applicable custom label data,
 * or NULL for any critical error.
 */
const struct model_config *manifest_find_custom_label_model(
		struct updater_config *cfg,
		const struct manifest *manifest,
		const struct model_config *base_model);

#endif  /* VBOOT_REFERENCE_FUTILITY_UPDATER_H_ */
