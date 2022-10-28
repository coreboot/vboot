/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * The utility functions for firmware updater.
 */

#include <assert.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#if defined (__FreeBSD__) || defined(__OpenBSD__)
#include <sys/wait.h>
#endif

#include "2common.h"
#include "crossystem.h"
#include "host_misc.h"
#include "util_misc.h"
#include "updater.h"

#define COMMAND_BUFFER_SIZE 256

/* System environment values. */
static const char * const STR_REV = "rev";

/*
 * Strips a string (usually from shell execution output) by removing all the
 * trailing characters in pattern. If pattern is NULL, match by space type
 * characters (space, new line, tab, ... etc).
 */
void strip_string(char *s, const char *pattern)
{
	int len;
	assert(s);

	len = strlen(s);
	while (len-- > 0) {
		if (pattern) {
			if (!strchr(pattern, s[len]))
				break;
		} else {
			if (!isascii(s[len]) || !isspace(s[len]))
				break;
		}
		s[len] = '\0';
	}
}

/*
 * Saves everything from stdin to given output file.
 * Returns 0 on success, otherwise failure.
 */
int save_file_from_stdin(const char *output)
{
	FILE *in = stdin, *out = fopen(output, "wb");
	char buffer[4096];
	size_t sz;

	assert(in);
	if (!out)
		return -1;

	while (!feof(in)) {
		sz = fread(buffer, 1, sizeof(buffer), in);
		if (fwrite(buffer, 1, sz, out) != sz) {
			fclose(out);
			return -1;
		}
	}
	fclose(out);
	return 0;
}

/*
 * Returns 1 if a given file (cbfs_entry_name) exists inside a particular CBFS
 * section of an image file, otherwise 0.
 */
int cbfs_file_exists(const char *image_file,
		     const char *section_name,
		     const char *cbfs_entry_name)
{
	char *cmd;
	int r;

	ASPRINTF(&cmd,
		 "cbfstool '%s' print -r %s 2>/dev/null | grep -q '^%s '",
		 image_file, section_name, cbfs_entry_name);
	r = system(cmd);
	free(cmd);
	return !r;
}

/*
 * Extracts files from a CBFS on given region (section) of image_file.
 * Returns the path to a temporary file on success, otherwise NULL.
 */
const char *cbfs_extract_file(const char *image_file,
			      const char *cbfs_region,
			      const char *cbfs_name,
			      struct tempfile *tempfiles)
{
	const char *output = create_temp_file(tempfiles);
	char *command, *result;

	if (!output)
		return NULL;

	ASPRINTF(&command, "cbfstool \"%s\" extract -r %s -n \"%s\" "
		 "-f \"%s\" 2>&1", image_file, cbfs_region,
		 cbfs_name, output);

	result = host_shell(command);
	free(command);

	if (!*result)
		output = NULL;

	free(result);
	return output;
}

/*
 * Loads the firmware information from an FMAP section in loaded firmware image.
 * The section should only contain ASCIIZ string as firmware version.
 * Returns 0 if a non-empty version string is stored in *version, otherwise -1.
 */
static int load_firmware_version(struct firmware_image *image,
				 const char *section_name,
				 char **version)
{
	struct firmware_section fwid;
	int len = 0;

	/*
	 * section_name is NULL when parsing the RW versions on a non-vboot
	 * image (and already warned in load_firmware_image). We still need to
	 * initialize *version with empty string.
	 */
	if (section_name) {
		find_firmware_section(&fwid, image, section_name);
		if (fwid.size)
			len = fwid.size;
		else
			WARN("No valid section '%s', missing version info.\n",
			     section_name);
	}

	if (!len) {
		*version = strdup("");
		return -1;
	}

	/*
	 * For 'system current' images, the version string may contain
	 * invalid characters that we do want to strip.
	 */
	*version = strndup((const char *)fwid.data, len);
	strip_string(*version, "\xff");
	return 0;
}

static int parse_firmware_image(struct firmware_image *image)
{
	int ret = IMAGE_LOAD_SUCCESS;
	const char *section_a = NULL, *section_b = NULL;

	VB2_DEBUG("Image size: %d\n", image->size);
	assert(image->data);

	image->fmap_header = fmap_find(image->data, image->size);

	if (!image->fmap_header) {
		ERROR("Invalid image file (missing FMAP): %s\n", image->file_name);
		ret = IMAGE_PARSE_FAILURE;
	}

	if (load_firmware_version(image, FMAP_RO_FRID, &image->ro_version))
		ret = IMAGE_PARSE_FAILURE;

	if (firmware_section_exists(image, FMAP_RW_FWID_A)) {
		section_a = FMAP_RW_FWID_A;
		section_b = FMAP_RW_FWID_B;
	} else if (firmware_section_exists(image, FMAP_RW_FWID)) {
		section_a = FMAP_RW_FWID;
		section_b = FMAP_RW_FWID;
	} else if (!ret) {
		ERROR("Unsupported VBoot firmware (no RW ID): %s\n", image->file_name);
		ret = IMAGE_PARSE_FAILURE;
	}

	/*
	 * Load and initialize both RW A and B sections.
	 * Note some unit tests will create only RW A.
	 */
	load_firmware_version(image, section_a, &image->rw_version_a);
	load_firmware_version(image, section_b, &image->rw_version_b);

	return ret;
}

/*
 * Loads a firmware image from file.
 * If archive is provided and file_name is a relative path, read the file from
 * archive.
 * Returns IMAGE_LOAD_SUCCESS on success, IMAGE_READ_FAILURE on file I/O
 * failure, or IMAGE_PARSE_FAILURE for non-vboot images.
 */
int load_firmware_image(struct firmware_image *image, const char *file_name,
			struct u_archive *archive)
{
	if (!file_name) {
		ERROR("No file name given\n");
		return IMAGE_READ_FAILURE;
	}

	VB2_DEBUG("Load image file from %s...\n", file_name);

	if (!archive_has_entry(archive, file_name)) {
		ERROR("Does not exist: %s\n", file_name);
		return IMAGE_READ_FAILURE;
	}
	if (archive_read_file(archive, file_name, &image->data, &image->size,
			      NULL) != VB2_SUCCESS) {
		ERROR("Failed to load %s\n", file_name);
		return IMAGE_READ_FAILURE;
	}

	image->file_name = strdup(file_name);

	return parse_firmware_image(image);
}

/*
 * Generates a temporary file for snapshot of firmware image contents.
 *
 * Returns a file path if success, otherwise NULL.
 */
const char *get_firmware_image_temp_file(const struct firmware_image *image,
					 struct tempfile *tempfiles)
{
	const char *tmp_path = create_temp_file(tempfiles);
	if (!tmp_path)
		return NULL;

	if (vb2_write_file(tmp_path, image->data, image->size) != VB2_SUCCESS) {
		ERROR("Failed writing %s firmware image (%u bytes) to %s.\n",
		      image->programmer ? image->programmer : "temp",
		      image->size, tmp_path);
		return NULL;
	}
	return tmp_path;
}

/*
 * Frees the allocated resource from a firmware image object.
 */
void free_firmware_image(struct firmware_image *image)
{
	/*
	 * The programmer is not allocated by load_firmware_image and must be
	 * preserved explicitly.
	 */
	const char *programmer = image->programmer;

	free(image->data);
	free(image->file_name);
	free(image->ro_version);
	free(image->rw_version_a);
	free(image->rw_version_b);
	memset(image, 0, sizeof(*image));
	image->programmer = programmer;
}

/*
 * Finds a firmware section by given name in the firmware image.
 * If successful, return zero and *section argument contains the address and
 * size of the section; otherwise failure.
 */
int find_firmware_section(struct firmware_section *section,
			  const struct firmware_image *image,
			  const char *section_name)
{
	FmapAreaHeader *fah = NULL;
	uint8_t *ptr;

	section->data = NULL;
	section->size = 0;
	ptr = fmap_find_by_name(
			image->data, image->size, image->fmap_header,
			section_name, &fah);
	if (!ptr)
		return -1;
	section->data = (uint8_t *)ptr;
	section->size = fah->area_size;
	return 0;
}

/*
 * Returns true if the given FMAP section exists in the firmware image.
 */
int firmware_section_exists(const struct firmware_image *image,
			    const char *section_name)
{
	struct firmware_section section;
	find_firmware_section(&section, image, section_name);
	return section.data != NULL;
}

/*
 * Preserves (copies) the given section (by name) from image_from to image_to.
 * The offset may be different, and the section data will be directly copied.
 * If the section does not exist on either images, return as failure.
 * If the source section is larger, contents on destination be truncated.
 * If the source section is smaller, the remaining area is not modified.
 * Returns 0 if success, non-zero if error.
 */
int preserve_firmware_section(const struct firmware_image *image_from,
			      struct firmware_image *image_to,
			      const char *section_name)
{
	struct firmware_section from, to;

	find_firmware_section(&from, image_from, section_name);
	find_firmware_section(&to, image_to, section_name);
	if (!from.data || !to.data) {
		VB2_DEBUG("Cannot find section %.*s: from=%p, to=%p\n",
			  FMAP_NAMELEN, section_name, from.data, to.data);
		return -1;
	}
	if (from.size > to.size) {
		WARN("Section %.*s is truncated after updated.\n",
		     FMAP_NAMELEN, section_name);
	}
	/* Use memmove in case if we need to deal with sections that overlap. */
	memmove(to.data, from.data, VB2_MIN(from.size, to.size));
	return 0;
}

/*
 * Finds the GBB (Google Binary Block) header on a given firmware image.
 * Returns a pointer to valid GBB header, or NULL on not found.
 */
const struct vb2_gbb_header *find_gbb(const struct firmware_image *image)
{
	struct firmware_section section;
	struct vb2_gbb_header *gbb_header;

	find_firmware_section(&section, image, FMAP_RO_GBB);
	gbb_header = (struct vb2_gbb_header *)section.data;
	if (!futil_valid_gbb_header(gbb_header, section.size, NULL)) {
		ERROR("Cannot find GBB in image: %s.\n", image->file_name);
		return NULL;
	}
	return gbb_header;
}

/*
 * Executes a command on current host and returns stripped command output.
 * If the command has failed (exit code is not zero), returns an empty string.
 * The caller is responsible for releasing the returned string.
 */
char *host_shell(const char *command)
{
	/* Currently all commands we use do not have large output. */
	char buf[COMMAND_BUFFER_SIZE];

	int result;
	FILE *fp = popen(command, "r");

	VB2_DEBUG("%s\n", command);
	buf[0] = '\0';
	if (!fp) {
		VB2_DEBUG("Execution error for %s.\n", command);
		return strdup(buf);
	}

	if (fgets(buf, sizeof(buf), fp))
		strip_string(buf, NULL);
	result = pclose(fp);
	if (!WIFEXITED(result) || WEXITSTATUS(result) != 0) {
		VB2_DEBUG("Execution failure with exit code %d: %s\n",
			  WEXITSTATUS(result), command);
		/*
		 * Discard all output if command failed, for example command
		 * syntax failure may lead to garbage in stdout.
		 */
		buf[0] = '\0';
	}
	return strdup(buf);
}


/* An helper function to return "mainfw_act" system property.  */
static int host_get_mainfw_act(void)
{
	char buf[VB_MAX_STRING_PROPERTY];

	if (!VbGetSystemPropertyString("mainfw_act", buf, sizeof(buf)))
		return SLOT_UNKNOWN;

	if (strcmp(buf, FWACT_A) == 0)
		return SLOT_A;
	else if (strcmp(buf, FWACT_B) == 0)
		return SLOT_B;

	return SLOT_UNKNOWN;
}

/* A helper function to return the "tpm_fwver" system property. */
static int host_get_tpm_fwver(void)
{
	return VbGetSystemPropertyInt("tpm_fwver");
}

/* A helper function to return the "hardware write protection" status. */
static int host_get_wp_hw(void)
{
	/* wpsw refers to write protection 'switch', not 'software'. */
	return VbGetSystemPropertyInt("wpsw_cur") ? WP_ENABLED : WP_DISABLED;
}

/* A helper function to return "fw_vboot2" system property. */
static int host_get_fw_vboot2(void)
{
	return VbGetSystemPropertyInt("fw_vboot2");
}

/* A help function to get $(mosys platform version). */
static int host_get_platform_version(void)
{
	char *result = host_shell("mosys platform version");
	long rev = -1;

	/* Result should be 'revN' */
	if (strncmp(result, STR_REV, strlen(STR_REV)) == 0)
		rev = strtol(result + strlen(STR_REV), NULL, 0);

	/* we should never have negative or extremely large versions,
	 * but clamp just to be sure
	 */
	if (rev < 0)
		rev = 0;
	if (rev > INT_MAX)
		rev = INT_MAX;

	VB2_DEBUG("Raw data = [%s], parsed version is %ld\n", result, rev);

	free(result);
	return rev;
}

/*
 * Helper function to detect type of Servo board attached to host.
 * Returns a string as programmer parameter on success, otherwise NULL.
 */
char *host_detect_servo(const char **prepare_ctrl_name)
{
	const char *servo_port = getenv(ENV_SERVOD_PORT);
	const char *servo_name = getenv(ENV_SERVOD_NAME);
	char *servo_type = host_shell("dut-control -o servo_type 2>/dev/null");
	const char *programmer = NULL;
	char *ret = NULL;
	char *servo_serial = NULL;

	static const char * const cpu_fw_spi = "cpu_fw_spi";
	static const char * const ccd_cpu_fw_spi = "ccd_cpu_fw_spi";

	/* By default, no control is needed. */
	*prepare_ctrl_name = NULL;
	VB2_DEBUG("servo_type: %s\n", servo_type);

	/* Get serial name if servo port is provided. */
	if ((servo_port && *servo_port) || (servo_name && *servo_name)) {
		const char *cmd = "dut-control -o serialname 2>/dev/null";

		VB2_DEBUG("Select servod using port: %s or name: %s\n",
			  servo_port, servo_name);
		if (strstr(servo_type, "with_servo_micro"))
			cmd = ("dut-control -o servo_micro_serialname"
			       " 2>/dev/null");
		else if (strstr(servo_type, "with_c2d2"))
			cmd = ("dut-control -o c2d2_serialname"
			       " 2>/dev/null");
		else if (strstr(servo_type, "with_ccd"))
			cmd = "dut-control -o ccd_serialname 2>/dev/null";

		servo_serial = host_shell(cmd);
		VB2_DEBUG("Servo SN=%s (serial cmd: %s)\n", servo_serial, cmd);
	}

	/* servo_type names: chromite/lib/firmware/servo_lib.py */
	if (!*servo_type) {
		ERROR("Failed to get servo type. Check servod.\n");
	} else if (servo_serial && !*servo_serial) {
		ERROR("Failed to get serial at servo port %s.\n", servo_port);
	} else if (strcmp(servo_type, "servo_v2") == 0) {
		VB2_DEBUG("Selected Servo V2.\n");
		programmer = "ft2232_spi:type=google-servo-v2";
		*prepare_ctrl_name = cpu_fw_spi;
	} else if (strstr(servo_type, "ccd_cr50") ||
		   strstr(servo_type, "ccd_gsc") ||
		   strstr(servo_type, "ccd_ti50")) {
		VB2_DEBUG("Selected CCD.\n");
		programmer = "raiden_debug_spi:target=AP,custom_rst=true";
		*prepare_ctrl_name = ccd_cpu_fw_spi;
	} else {
		if (strstr(servo_type, "servo_micro"))
			VB2_DEBUG("Selected Servo Micro.\n");
		else if (strstr(servo_type, "c2d2"))
			VB2_DEBUG("Selected C2D2.\n");
		else
			WARN("Unknown servo: %s\n", servo_type);
		programmer = "raiden_debug_spi";
		*prepare_ctrl_name = cpu_fw_spi;
	}

	if (programmer) {
		if (!servo_serial) {
			ret = strdup(programmer);
		} else {
			const char prefix = strchr(programmer, ':') ? ',' : ':';
			ASPRINTF(&ret, "%s%cserial=%s", programmer, prefix,
				 servo_serial);
		}
		VB2_DEBUG("Servo programmer: %s\n", ret);
	}

	free(servo_type);
	free(servo_serial);

	return ret;
}
/*
 * Returns 1 if the programmers in image1 and image2 are the same.
 */
static int is_the_same_programmer(const struct firmware_image *image1,
				  const struct firmware_image *image2)
{
	assert(image1 && image2);

	/* Including if both are NULL. */
	if (image1->programmer == image2->programmer)
		return 1;

	/* Not the same if either one is NULL. */
	if (!image1->programmer || !image2->programmer)
		return 0;

	return strcmp(image1->programmer, image2->programmer) == 0;
}

enum flash_command {
	FLASH_READ = 0,
	FLASH_WRITE,
};

/* Converts the flashrom_params to an equivalent flashrom command. */
static char *get_flashrom_command(enum flash_command flash_cmd,
				  struct flashrom_params *params,
				  const char *image_name,
				  const char *contents_name)
{
	int i, len = 0;
	char *partial = NULL;
	char *cmd = NULL;

	if (!image_name)
		image_name = "<IMAGE>";
	if (!contents_name)
		contents_name = "<OLD-IMAGE>";

	for (i = 0; params->regions && params->regions[i]; i++)
		len += strlen(params->regions[i]) + strlen(" -i ");

	if (len) {
		partial = (char *)malloc(len + 1);
		if (!partial) {
			ERROR("Failed to allocate a string buffer.\n");
			return NULL;
		}

		partial[0] = '\0';
		for (i = 0; params->regions[i]; i++) {
			strcat(partial, " -i ");
			strcat(partial, params->regions[i]);
		}
		assert(strlen(partial) == len);
	}

	switch (flash_cmd) {
	case FLASH_READ:
		ASPRINTF(&cmd, "flashrom -r %s -p %s%s%s",
			 image_name,
			 params->image->programmer,
			 params->verbose > 1 ? " -V" : "",
			 partial ? partial : "");
		break;

	case FLASH_WRITE:
		ASPRINTF(&cmd, "flashrom -w %s -p %s%s%s%s%s%s",
			 image_name,
			 params->image->programmer,
			 params->flash_contents ? " --flash-contents " : "",
			 params->flash_contents ? contents_name : "",
			 params->noverify ? " --noverify" : "",
			 params->verbose > 1 ? " -V" : "",
			 partial ? partial : "");
		break;

	default:
		ERROR("Unknown command: %d.\n", flash_cmd);
		break;
	}
	free(partial);
	return cmd;
}

/*
 * Emulates writing a firmware image to the system.
 * Returns 0 if success, non-zero if error.
 */
static int emulate_write_firmware(const char *filename,
				  const struct firmware_image *image,
				  const char * const sections[])
{
	int i, errorcnt = 0;
	struct firmware_image to_image = {0};

	INFO("Writing from %s to %s (emu=%s).\n",
	     image->file_name, image->programmer, filename);

	if (load_firmware_image(&to_image, filename, NULL)) {
		ERROR("Cannot load image from %s.\n", filename);
		return -1;
	}

	if (image->size != to_image.size) {
		ERROR("Image size is different (%s:%d != %s:%d)\n",
		      image->file_name, image->size, to_image.file_name,
		      to_image.size);
		errorcnt++;
		goto exit;
	}

	if (!sections) {
		VB2_DEBUG(" - write the whole image.\n");
		memmove(to_image.data, image->data, image->size);
	}
	for (i = 0; sections && sections[i]; i++) {
		VB2_DEBUG(" - write the section: %s.\n", sections[i]);
		if (preserve_firmware_section(image, &to_image, sections[i])) {
			ERROR("Failed to write the section: %s\n", sections[i]);
			errorcnt++;
			/*
			 * Exit the loop, but still write the file to reflect
			 * the partial changes - same as real flashrom behavior.
			 */
			break;
		}
	}

	if (vb2_write_file(filename, to_image.data, to_image.size)) {
		ERROR("Failed writing to file: %s\n", filename);
		errorcnt++;
		goto exit;
	}

exit:
	free_firmware_image(&to_image);
	return errorcnt;
}

static int external_flashrom(enum flash_command flash_cmd,
			     struct flashrom_params *params,
			     struct tempfile *tempfiles)
{
	int r;
	char *cmd;
	const char *image_name = NULL, *contents_name = NULL;

	switch (flash_cmd) {
	case FLASH_READ:
		image_name = create_temp_file(tempfiles);
		break;

	case FLASH_WRITE:
		image_name = get_firmware_image_temp_file(
				params->image, tempfiles);
		if (params->flash_contents)
			contents_name = get_firmware_image_temp_file(
					params->flash_contents, tempfiles);
		break;

	default:
		ERROR("Unknown command: %d\n", flash_cmd);
		return -1;
	}

	cmd = get_flashrom_command(flash_cmd, params, image_name,
				   contents_name);
	if (!cmd)
		return -1;

	VB2_DEBUG(cmd);
	r = system(cmd);
	free(cmd);
	if (r)
		return r;

	switch (flash_cmd) {
	case FLASH_READ:
		r = load_firmware_image(params->image, image_name, NULL);
		break;
	default:
		break;
	}

	return r;
}

static int read_flash(struct flashrom_params *params,
		      struct updater_config *cfg)
{
	if (get_config_quirk(QUIRK_EXTERNAL_FLASHROM, cfg))
		return external_flashrom(FLASH_READ, params, &cfg->tempfiles);

	return flashrom_read_image(params->image, NULL, params->verbose);
}

static int write_flash(struct flashrom_params *params,
		       struct updater_config *cfg)
{
	int r;

	if (get_config_quirk(QUIRK_EXTERNAL_FLASHROM, cfg))
		return external_flashrom(FLASH_WRITE, params, &cfg->tempfiles);

	r = flashrom_write_image(params->image,
				 params->regions,
				 params->flash_contents,
				 !params->noverify,
				 params->verbose);
	/*
	 * Force a newline to flush stdout in case if
	 * flashrom_write_image left some messages in the buffer.
	 */
	fprintf(stdout, "\n");
	return r;
}

/*
 * Loads the active system firmware image (usually from SPI flash chip).
 * Returns 0 if success, non-zero if error.
 */
int load_system_firmware(struct updater_config *cfg,
			 struct firmware_image *image)
{
	int r, i;
	char *cmd;
	const int tries = 1 + get_config_quirk(QUIRK_EXTRA_RETRIES, cfg);
	struct flashrom_params params = {0};

	params.image = image;
	params.verbose = cfg->verbosity + 1; /* libflashrom verbose 1 = WARN. */

	cmd = get_flashrom_command(FLASH_READ, &params, NULL, NULL);
	INFO("%s\n", cmd);
	free(cmd);

	for (i = 1, r = -1; i <= tries && r != 0; i++, params.verbose++) {
		if (i > 1)
			WARN("Retry reading firmware (%d/%d)...\n", i, tries);
		r = read_flash(&params, cfg);
	}
	if (!r)
		r = parse_firmware_image(image);
	return r;
}

/*
 * Writes sections from a given firmware image to the system firmware.
 * Regions should be NULL for writing the whole image, or a list of
 * FMAP section names (and ended with a NULL).
 * Returns 0 if success, non-zero if error.
 */
int write_system_firmware(struct updater_config *cfg,
			  const struct firmware_image *image,
			  const char * const sections[])
{
	int r = 0, i;
	char *cmd;
	const int tries = 1 + get_config_quirk(QUIRK_EXTRA_RETRIES, cfg);
	struct flashrom_params params = {0};
	struct firmware_image *flash_contents = NULL;

	if (cfg->emulation)
		return emulate_write_firmware(cfg->emulation, image, sections);

	if (cfg->use_diff_image && cfg->image_current.data &&
	    is_the_same_programmer(&cfg->image_current, image))
		flash_contents = &cfg->image_current;

	params.image = (struct firmware_image *)image;
	params.flash_contents = flash_contents;
	params.regions = sections;
	params.noverify = !cfg->do_verify;
	params.noverify_all = true;
	params.verbose = cfg->verbosity + 1; /* libflashrom verbose 1 = WARN. */

	cmd = get_flashrom_command(FLASH_WRITE, &params, NULL, NULL);
	INFO("%s\n", cmd);
	free(cmd);

	for (i = 1, r = -1; i <= tries && r != 0; i++, params.verbose++) {
		if (i > 1)
			WARN("Retry writing firmware (%d/%d)...\n", i, tries);
		r = write_flash(&params, cfg);
	}
	return r;
}

/* Helper function to return host software write protection status. */
static int host_get_wp_sw(void)
{
	return flashrom_get_wp(PROG_HOST, -1);
}

/* Helper function to configure all properties. */
void init_system_properties(struct system_property *props, int num)
{
	memset(props, 0, num * sizeof(*props));
	assert(num >= SYS_PROP_MAX);
	props[SYS_PROP_MAINFW_ACT].getter = host_get_mainfw_act;
	props[SYS_PROP_TPM_FWVER].getter = host_get_tpm_fwver;
	props[SYS_PROP_FW_VBOOT2].getter = host_get_fw_vboot2;
	props[SYS_PROP_PLATFORM_VER].getter = host_get_platform_version;
	props[SYS_PROP_WP_HW].getter = host_get_wp_hw;
	props[SYS_PROP_WP_SW].getter = host_get_wp_sw;
}

/*
 * Helper function to create a new temporary file.
 * All files created will be removed remove_all_temp_files().
 * Returns the path of new file, or NULL on failure.
 */
const char *create_temp_file(struct tempfile *head)
{
	struct tempfile *new_temp;
	char new_path[] = P_tmpdir "/fwupdater.XXXXXX";
	int fd;
	mode_t umask_save;

	/* Set the umask before mkstemp for security considerations. */
	umask_save = umask(077);
	fd = mkstemp(new_path);
	umask(umask_save);
	if (fd < 0) {
		ERROR("Failed to create new temp file in %s\n", new_path);
		return NULL;
	}
	close(fd);
	new_temp = (struct tempfile *)malloc(sizeof(*new_temp));
	if (new_temp)
		new_temp->filepath = strdup(new_path);
	if (!new_temp || !new_temp->filepath) {
		remove(new_path);
		free(new_temp);
		ERROR("Failed to allocate buffer for new temp file.\n");
		return NULL;
	}
	VB2_DEBUG("Created new temporary file: %s.\n", new_path);
	new_temp->next = NULL;
	while (head->next)
		head = head->next;
	head->next = new_temp;
	return new_temp->filepath;
}

/*
 * Helper function to remove all files created by create_temp_file().
 * This is intended to be called only once at end of program execution.
 */
void remove_all_temp_files(struct tempfile *head)
{
	/* head itself is dummy and should not be removed. */
	assert(!head->filepath);
	struct tempfile *next = head->next;
	head->next = NULL;
	while (next) {
		head = next;
		next = head->next;
		assert(head->filepath);
		VB2_DEBUG("Remove temporary file: %s.\n", head->filepath);
		remove(head->filepath);
		free(head->filepath);
		free(head);
	}
}

/*
 * Returns rootkey hash of firmware image, or NULL on failure.
 */
const char *get_firmware_rootkey_hash(const struct firmware_image *image)
{
	const struct vb2_gbb_header *gbb = NULL;
	const struct vb2_packed_key *rootkey = NULL;

	assert(image->data);

	gbb = find_gbb(image);
	if (!gbb) {
		WARN("No GBB found in image.\n");
		return NULL;
	}

	rootkey = get_rootkey(gbb);
	if (!rootkey) {
		WARN("No rootkey found in image.\n");
		return NULL;
	}

	return packed_key_sha1_string(rootkey);
}
