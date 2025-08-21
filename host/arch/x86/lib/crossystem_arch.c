/* Copyright 2012 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#if !defined(HAVE_MACOS) && !defined (__FreeBSD__) && !defined(__OpenBSD__)
#include <linux/fs.h>
#include <linux/gpio.h>
#include <linux/nvram.h>
#include <linux/version.h>
#endif
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "crossystem_arch.h"
#include "crossystem.h"
#include "crossystem_vbnv.h"
#include "gpio_uapi.h"
#include "host_common.h"
#include "vboot_struct.h"

/* ACPI constants from Chrome OS Main Processor Firmware Spec */
/* Boot reasons from BINF.0, from early H2C firmware */
/* Unknown */
#define BINF0_UNKNOWN                  0
/* Normal boot to Chrome OS */
#define BINF0_NORMAL                   1
/* Developer mode boot (developer mode warning displayed) */
#define BINF0_DEVELOPER                2
/* Recovery initiated by user, using recovery button */
#define BINF0_RECOVERY_BUTTON          3
/* Recovery initiated by user pressing a key at developer mode warning
 * screen */
#define BINF0_RECOVERY_DEV_SCREEN_KEY  4
/* Recovery caused by BIOS failed signature check (neither rewritable
 * firmware was valid) */
#define BINF0_RECOVERY_RW_FW_BAD       5
/* Recovery caused by no OS kernel detected */
#define BINF0_RECOVERY_NO_OS           6
/* Recovery caused by OS kernel failed signature check */
#define BINF0_RECOVERY_BAD_OS          7
/* Recovery initiated by OS */
#define BINF0_RECOVERY_OS_INITIATED    8
/* OS-initiated S3 diagnostic path (debug mode boot) */
#define BINF0_S3_DIAGNOSTIC_PATH       9
/* S3 resume failed */
#define BINF0_S3_RESUME_FAILED        10
/* Recovery caused by TPM error */
#define BINF0_RECOVERY_TPM_ERROR      11
/* CHSW bitflags */
#define CHSW_RECOVERY_BOOT     0x00000002
#define CHSW_RECOVERY_EC_BOOT  0x00000004
#define CHSW_DEV_BOOT          0x00000020
/* CMOS reboot field bitflags */
#define CMOSRF_RECOVERY        0x80
#define CMOSRF_DEBUG_RESET     0x40
#define CMOSRF_TRY_B           0x20
/* GPIO signal types */
#define GPIO_SIGNAL_TYPE_RECOVERY 1
#define GPIO_SIGNAL_TYPE_DEPRECATED_DEV 2  /* Deprecated; see chromium:942901 */
#define GPIO_SIGNAL_TYPE_WP 3
#define GPIO_SIGNAL_TYPE_PHASE_ENFORCEMENT 4

/* Base for SMBIOS information files */
#define SMBIOS_BASE_PATH "/sys/class/dmi/id"
#define SMBIOS_PRODUCT_VERSION_PATH SMBIOS_BASE_PATH "/product_version"
#define SMBIOS_PRODUCT_SKU_PATH SMBIOS_BASE_PATH "/product_sku"

/* Filename for NVRAM file */
#define NVRAM_PATH "/dev/nvram"

/* Filename for legacy firmware update tries */
#define NEED_FWUPDATE_PATH "/mnt/stateful_partition/.need_firmware_update"

/* Filenames for PCI Vendor and Device IDs */
#define PCI_VENDOR_ID_PATH "/sys/bus/pci/devices/0000:00:00.0/vendor"
#define PCI_DEVICE_ID_PATH "/sys/bus/pci/devices/0000:00:00.0/device"

typedef struct {
	unsigned int base;
	unsigned int uid;
} Basemapping;

static void VbFixCmosChecksum(FILE* file)
{
#if !defined(__FreeBSD__) && !defined(__OpenBSD__)
	int fd = fileno(file);
	ioctl(fd, NVRAM_SETCKS);
#endif
}


/*
 * Get ChromeOS ACPI sysfs path.
 *
 * Note: the returned pointer should be passed to free(3) to release
 * the allocated storage when it is no longer needed.
 */
static char* GetAcpiSysfsPath(const char* name)
{
	/*
	 * TODO: revert the legacy driver path lookup once all ChromeOS kernels
	 * switch to use CHROMEOS_ACPI.
	 */
	static const char* legacy_driver_path = "/sys/devices/platform/chromeos_acpi";
	static const char* legacy_fw_path = "/sys/devices/platform/GGL0001:00";
	static const char* current_path = "/sys/devices/platform/GOOG0016:00";
	char* path;
	struct stat fs;
	int ret = -1;

	if (stat(legacy_driver_path, &fs) == 0 && S_ISDIR(fs.st_mode))
		ret = asprintf(&path, "%s/%s", legacy_driver_path, name);
	else if (stat(legacy_fw_path, &fs) == 0 && S_ISDIR(fs.st_mode))
		ret = asprintf(&path, "%s/%s", legacy_fw_path, name);
	else if (stat(current_path, &fs) == 0 && S_ISDIR(fs.st_mode))
		ret = asprintf(&path, "%s/%s", current_path, name);

	if (ret == -1)
		fprintf(stderr, "ERROR: %s: Failed to get ChromeOS ACPI sysfs path %s\n",
			__func__, name);

	return ret == -1 ? NULL : path;
}


static char* ReadAcpiSysfsString(char* dest, int size, const char* name)
{
	char* path;
	char* ret;

	path = GetAcpiSysfsPath(name);
	if (!path)
		return NULL;

	ret = ReadFileFirstLine(dest, size, path);
	free(path);
	return ret;
}


static int ReadAcpiSysfsInt(const char* name, unsigned* value)
{
	char* path;
	int ret;

	path = GetAcpiSysfsPath(name);
	if (!path)
		return -1;

	ret = ReadFileInt(path, value);
	free(path);
	return ret;
}


static int ReadAcpiSysfsBit(const char* name, int bitmask)
{
	char* path;
	int ret;

	path = GetAcpiSysfsPath(name);
	if (!path)
		return -1;

	ret = ReadFileBit(path, bitmask);
	free(path);
	return ret;
}


static int VbCmosRead(unsigned offs, size_t size, void *ptr)
{
	size_t res;
	FILE* f;

	f = fopen(NVRAM_PATH, "rb");
	if (!f) {
		fprintf(stderr, "ERROR: %s: Failed to open %s: %s\n", __func__, NVRAM_PATH,
			strerror(errno));
		return -1;
	}

	if (0 != fseek(f, offs, SEEK_SET)) {
		fprintf(stderr, "ERROR: %s: fseek failed: %s\n", __func__, strerror(errno));
		fclose(f);
		return -1;
	}

	res = fread(ptr, size, 1, f);
	if (1 != res && errno == EIO && ferror(f)) {
		VbFixCmosChecksum(f);
		res = fread(ptr, size, 1, f);
	}

	if (res != 1)
		fprintf(stderr, "ERROR: %s: Failed to read data from %s: %s\n", __func__,
			NVRAM_PATH, strerror(errno));

	fclose(f);
	return (1 == res) ? 0 : -1;
}


static int VbCmosWrite(unsigned offs, size_t size, const void *ptr)
{
	size_t res;
	FILE* f;

	f = fopen(NVRAM_PATH, "w+b");
	if (!f) {
		fprintf(stderr, "ERROR: %s: Failed to open %s: %s\n", __func__, NVRAM_PATH,
			strerror(errno));
		return -1;
	}

	if (0 != fseek(f, offs, SEEK_SET)) {
		fprintf(stderr, "ERROR: %s: fseek failed: %s\n", __func__, strerror(errno));
		fclose(f);
		return -1;
	}

	res = fwrite(ptr, size, 1, f);
	if (1 != res && errno == EIO && ferror(f)) {
		VbFixCmosChecksum(f);
		res = fwrite(ptr, size, 1, f);
	}

	if (res != 1)
		fprintf(stderr, "ERROR: %s: Failed to write data to %s: %s\n", __func__,
			NVRAM_PATH, strerror(errno));

	fclose(f);
	return (1 == res) ? 0 : -1;
}


int vb2_read_nv_storage(struct vb2_context *ctx)
{
	unsigned offs, blksz;
	unsigned expectsz = vb2_nv_get_size(ctx);

	/* Get the byte offset from VBNV */
	if (ReadAcpiSysfsInt("VBNV.0", &offs) < 0)
		return -1;
	if (ReadAcpiSysfsInt("VBNV.1", &blksz) < 0)
		return -1;
	if (expectsz > blksz) {
		fprintf(stderr, "ERROR: %s: NV storage block is too small.\n", __func__);
		return -1;  /* NV storage block is too small */
	}

	if (0 != VbCmosRead(offs, expectsz, ctx->nvdata))
		return -1;

	return 0;
}


int vb2_write_nv_storage(struct vb2_context *ctx)
{
	unsigned offs, blksz;
	unsigned expectsz = vb2_nv_get_size(ctx);

	if (!(ctx->flags & VB2_CONTEXT_NVDATA_CHANGED))
		return 0;  /* Nothing changed, so no need to write */

	/* Get the byte offset from VBNV */
	if (ReadAcpiSysfsInt("VBNV.0", &offs) < 0)
		return -1;
	if (ReadAcpiSysfsInt("VBNV.1", &blksz) < 0)
		return -1;
	if (expectsz > blksz) {
		fprintf(stderr, "ERROR: %s: NV storage block is too small.\n", __func__);
		return -1;  /* NV storage block is too small */
	}

	if (0 != VbCmosWrite(offs, expectsz, ctx->nvdata))
		return -1;

	/* Also attempt to write using flashrom if using vboot2 */
	VbSharedDataHeader *sh = VbSharedDataRead();
	if (sh) {
		if (sh->flags & VBSD_BOOT_FIRMWARE_VBOOT2)
			vb2_write_nv_storage_flashrom(ctx);
		free(sh);
	}

	return 0;
}


/*
 * Get buffer data from ACPI.
 *
 * Buffer data is expected to be represented by a file which is a text dump of
 * the buffer, representing each byte by two hex numbers, space and newline
 * separated.
 *
 * On success, stores the amount of data read in bytes to *buffer_size; on
 * erros, sets *buffer_size=0.
 *
 * Input - ACPI file name to get data from.
 *
 * Output: a pointer to AcpiBuffer structure containing the binary
 *         representation of the data. The caller is responsible for
 *         deallocating the pointer, this will take care of both the structure
 *         and the buffer. Null in case of error.
 */
static uint8_t* VbGetBuffer(const char* filename, int* buffer_size)
{
	FILE* f = NULL;
	char* file_buffer = NULL;
	uint8_t* output_buffer = NULL;
	uint8_t* return_value = NULL;

	/* Assume error until proven otherwise */
	if (buffer_size)
		*buffer_size = 0;

	do {
		struct stat fs;
		uint8_t* output_ptr;
		int rv, i, real_size;
		int parsed_size = 0;

		int fd = open(filename, O_RDONLY);
		if (fd == -1)
			break;

		rv = fstat(fd, &fs);
		if (rv || !S_ISREG(fs.st_mode)) {
			close(fd);
			break;
		}

		f = fdopen(fd, "r");
		if (!f) {
			close(fd);
			break;
		}

		file_buffer = malloc(fs.st_size + 1);
		if (!file_buffer)
			break;

		real_size = fread(file_buffer, 1, fs.st_size, f);
		if (!real_size)
			break;
		file_buffer[real_size] = '\0';

		/* Each byte in the output will replace two characters and a
		 * space in the input, so the output size does not exceed input
		 * side/3 (a little less if account for newline characters). */
		output_buffer = malloc(real_size/3);
		if (!output_buffer)
			break;
		output_ptr = output_buffer;

		/* process the file contents */
		for (i = 0; i < real_size; i++) {
			char* base, *end;

			base = file_buffer + i;

			if (!isxdigit(*base))
				continue;

			output_ptr[parsed_size++] =
					strtol(base, &end, 16) & 0xff;

			if ((end - base) != 2)
				/* Input file format error */
				break;

			/* skip the second character and the following space */
			i += 2;
		}

		if (i == real_size) {
			/* all is well */
			return_value = output_buffer;
			output_buffer = NULL; /* prevent it from deallocating */
			if (buffer_size)
				*buffer_size = parsed_size;
		}
	} while (0);

	/* wrap up */
	if (f)
		fclose(f);

	if (file_buffer)
		free(file_buffer);

	if (output_buffer)
		free(output_buffer);

	return return_value;
}


VbSharedDataHeader* VbSharedDataRead(void)
{
	VbSharedDataHeader* sh;
	int got_size = 0;
	int expect_size;
	char* path;

	path = GetAcpiSysfsPath("VDAT");
	if (!path)
		return NULL;

	sh = (VbSharedDataHeader*)VbGetBuffer(path, &got_size);
	free(path);
	if (!sh)
		return NULL;

	/* Make sure the size is sufficient for the struct version we got.
	 * Check supported old versions first. */
	if (1 == sh->struct_version)
		expect_size = VB_SHARED_DATA_HEADER_SIZE_V1;
	else {
		/* There'd better be enough data for the current header size. */
		expect_size = sizeof(VbSharedDataHeader);
	}

	if (got_size < expect_size) {
		free(sh);
		return NULL;
	}
	if (sh->data_size > got_size)
		sh->data_size = got_size;  /* Truncated read */

	return sh;
}


/* Read the CMOS reboot field in NVRAM.
 *
 * Returns 0 if the mask is clear in the field, 1 if set, or -1 if error. */
static int VbGetCmosRebootField(uint8_t mask)
{
	unsigned chnv;
	uint8_t nvbyte;

	/* Get the byte offset from CHNV */
	if (ReadAcpiSysfsInt("CHNV", &chnv) < 0)
		return -1;

	if (0 != VbCmosRead(chnv, 1, &nvbyte))
		return -1;

	return (nvbyte & mask ? 1 : 0);
}


/* Write the CMOS reboot field in NVRAM.
 *
 * Sets (value=0) or clears (value!=0) the mask in the byte.
 *
 * Returns 0 if success, or -1 if error. */
static int VbSetCmosRebootField(uint8_t mask, int value)
{
	unsigned chnv;
	uint8_t nvbyte;

	/* Get the byte offset from CHNV */
	if (ReadAcpiSysfsInt("CHNV", &chnv) < 0)
		return -1;

	if (0 != VbCmosRead(chnv, 1, &nvbyte))
		return -1;

	/* Set/clear the mask */
	if (value)
		nvbyte |= mask;
	else
		nvbyte &= ~mask;

	/* Write the byte back */
	if (0 != VbCmosWrite(chnv, 1, &nvbyte))
		return -1;

	/* Success */
	return 0;
}


/* Read the active main firmware type into the destination buffer.
 * Passed the destination and its size.  Returns the destination, or
 * NULL if error. */
static const char* VbReadMainFwType(char* dest, int size)
{
	unsigned value;

	/* Try reading type from BINF.3 */
	if (ReadAcpiSysfsInt("BINF.3", &value) == 0) {
		switch(value) {
			case BINF3_LEGACY:
				return StrCopy(dest, "legacy", size);
			case BINF3_NETBOOT:
				return StrCopy(dest, "netboot", size);
			case BINF3_RECOVERY:
				return StrCopy(dest, "recovery", size);
			case BINF3_NORMAL:
				return StrCopy(dest, "normal", size);
			case BINF3_DEVELOPER:
				return StrCopy(dest, "developer", size);
			default:
				break;  /* Fall through to legacy handling */
		}
	}

	/* Fall back to BINF.0 for legacy systems like Mario. */
	if (ReadAcpiSysfsInt("BINF.0", &value) < 0)
		/* Both BINF.0 and BINF.3 are missing, so this isn't Chrome OS
		 * firmware. */
		return StrCopy(dest, "nonchrome", size);

	switch(value) {
		case BINF0_NORMAL:
			return StrCopy(dest, "normal", size);
		case BINF0_DEVELOPER:
			return StrCopy(dest, "developer", size);
		case BINF0_RECOVERY_BUTTON:
		case BINF0_RECOVERY_DEV_SCREEN_KEY:
		case BINF0_RECOVERY_RW_FW_BAD:
		case BINF0_RECOVERY_NO_OS:
		case BINF0_RECOVERY_BAD_OS:
		case BINF0_RECOVERY_OS_INITIATED:
		case BINF0_RECOVERY_TPM_ERROR:
			/* Assorted flavors of recovery boot reason. */
			return StrCopy(dest, "recovery", size);
		default:
			/* Other values don't map cleanly to firmware type. */
			return NULL;
	}
}


/* Read the recovery reason.  Returns the reason code or -1 if error. */
static vb2_error_t VbGetRecoveryReason(void)
{
	unsigned value;

	/* Try reading type from BINF.4 */
	if (ReadAcpiSysfsInt("BINF.4", &value) == 0)
		return value;

	/* Fall back to BINF.0 for legacy systems like Mario. */
	if (ReadAcpiSysfsInt("BINF.0", &value) < 0)
		return -1;
	switch(value) {
		case BINF0_NORMAL:
		case BINF0_DEVELOPER:
			return VB2_RECOVERY_NOT_REQUESTED;
		case BINF0_RECOVERY_BUTTON:
			return VB2_RECOVERY_RO_MANUAL;
		case BINF0_RECOVERY_RW_FW_BAD:
			return VB2_RECOVERY_RO_INVALID_RW;
		case BINF0_RECOVERY_NO_OS:
			return VB2_RECOVERY_RW_NO_KERNEL;
		case BINF0_RECOVERY_BAD_OS:
			return VB2_RECOVERY_RW_INVALID_OS;
		case BINF0_RECOVERY_OS_INITIATED:
			return VB2_RECOVERY_LEGACY;
		default:
			/* Other values don't map cleanly to firmware type. */
			return -1;
	}
}

static int get_controller_number_from_name(const char *name)
{
	int num;
	const char *p = strrchr(name, ':');
	char *end;

	/* No controller offset in the name. Default to zero. */
	if (!p)
		return 0;

	/* Controller number is a hex number.
	   Skip the colon at index zero. */
	num = strtol(&p[1], &end, 16);
	if (end == &p[1])
		return -1;

	return num;
}

/* Read a GPIO of the specified signal type (see ACPI GPIO SignalType).
 *
 * Returns 1 if the signal is asserted, 0 if not asserted, or -1 if error. */
static int ReadGpio(unsigned signal_type)
{
	char name[256];
	int index = 0;
	unsigned gpio_type;
	unsigned active_high;
	unsigned pin_num;
	char controller_name[128];
	int controller_num = 0;
	char base_path[128];
	char* path;

	path = GetAcpiSysfsPath("GPIO");
	if (!path)
		return -1;
	strncpy(base_path, path, sizeof(base_path) - 1);
	base_path[sizeof(base_path) - 1] = 0;
	free(path);

	/* Scan GPIO.* to find a matching signal type */
	for (index = 0; ; index++) {
		snprintf(name, sizeof(name), "%s.%d/GPIO.0", base_path, index);
		if (ReadFileInt(name, &gpio_type) < 0)
			return -1; /* Ran out of GPIOs before finding a match */
		if (gpio_type == signal_type)
			break;
	}

	/* Read attributes and controller info for the GPIO */
	snprintf(name, sizeof(name), "%s.%d/GPIO.1", base_path, index);
	if (ReadFileInt(name, &active_high) < 0)
		return -1;
	snprintf(name, sizeof(name), "%s.%d/GPIO.2", base_path, index);
	if (ReadFileInt(name, &pin_num) < 0)
		return -1;
	/* Do not attempt to read GPIO that is set to -1 in ACPI */
	if (pin_num == 0xFFFFFFFF)
		return -1;
	snprintf(name, sizeof(name), "%s.%d/GPIO.3", base_path, index);
	if (!ReadFileFirstLine(controller_name, sizeof(controller_name), name))
		return -1;
	controller_num = get_controller_number_from_name(controller_name);
	if (controller_num == -1) {
		fprintf(stderr, "Unable to parse controller name: %s\n", controller_name);
		return -1;
	}

	return gpio_read_value_by_idx(controller_num, pin_num, !active_high);
}

int VbGetSystemSkuId(uint32_t *sku_id)
{
	int ret = -1;
	FILE *f;
	uint32_t read_sku_id;

	f = fopen(SMBIOS_PRODUCT_SKU_PATH, "r");
	if (!f)
		return -1;

	if (fscanf(f, "sku%u\n", &read_sku_id) == 1) {
		*sku_id = read_sku_id;
		ret = 0;
	}

	fclose(f);
	return ret;
}

static int GetBoardId(void)
{
	/*
	 * Can't use vb2_read_file here, as it expects to be able to
	 * seek to the end of the file to tell the size, and the sysfs
	 * SMBIOS implementation will seek to offset 4096.
	 */
	int board_id = -1;
	FILE *f = fopen(SMBIOS_PRODUCT_VERSION_PATH, "r");

	if (!f)
		return -1;

	if (fscanf(f, "rev%d\n", &board_id) != 1)
		board_id = -1;

	fclose(f);
	return board_id;
}

int VbGetArchPropertyInt(const char* name)
{
	int value = -1;

	/* Switch positions */
	if (!strcasecmp(name,"devsw_cur")) {
		/* Systems with virtual developer switches return at-boot
		 * value */
		value = VbGetSystemPropertyInt("devsw_boot");
	} else if (!strcasecmp(name,"recoverysw_cur")) {
		value = ReadGpio(GPIO_SIGNAL_TYPE_RECOVERY);
	} else if (!strcasecmp(name,"wpsw_cur")) {
		value = ReadGpio(GPIO_SIGNAL_TYPE_WP);
	} else if (!strcasecmp(name,"recoverysw_ec_boot")) {
		value = ReadAcpiSysfsBit("CHSW", CHSW_RECOVERY_EC_BOOT);
	} else if (!strcasecmp(name,"phase_enforcement")) {
		value = ReadGpio(GPIO_SIGNAL_TYPE_PHASE_ENFORCEMENT);
	}

	/* Fields for old systems which don't have VbSharedData */
	if (VbSharedDataVersion() < 2) {
		if (!strcasecmp(name,"recovery_reason")) {
			value = VbGetRecoveryReason();
		} else if (!strcasecmp(name,"devsw_boot")) {
			value = ReadAcpiSysfsBit("CHSW", CHSW_DEV_BOOT);
		} else if (!strcasecmp(name,"recoverysw_boot")) {
			value = ReadAcpiSysfsBit("CHSW", CHSW_RECOVERY_BOOT);
		}
	}

	/* NV storage values.  If unable to get from NV storage, fall back to
	 * the CMOS reboot field used by older BIOS (e.g. Mario). */
	if (!strcasecmp(name,"recovery_request")) {
		value = vb2_get_nv_storage(VB2_NV_RECOVERY_REQUEST);
		if (-1 == value)
			value = VbGetCmosRebootField(CMOSRF_RECOVERY);
	} else if (!strcasecmp(name,"dbg_reset")) {
		value = vb2_get_nv_storage(VB2_NV_DEBUG_RESET_MODE);
		if (-1 == value)
			value = VbGetCmosRebootField(CMOSRF_DEBUG_RESET);
	}

	/* Firmware update tries is now stored in the kernel field.  On
	 * older systems where it's not, it was stored in a file in the
	 * stateful partition. */
	if (!strcasecmp(name,"fwupdate_tries")) {
		unsigned fwupdate_value;
		if (-1 != vb2_get_nv_storage(VB2_NV_KERNEL_FIELD))
			return -1;  /* NvStorage supported; fail through
				     * arch-specific implementation to normal
				     * implementation. */
		/* Read value from file; missing file means value=0. */
		if (ReadFileInt(NEED_FWUPDATE_PATH, &fwupdate_value) < 0)
			value = 0;
		else
			value = (int)fwupdate_value;
	}

	if (!strcasecmp(name, "board_id"))
		return GetBoardId();

	return value;
}


const char* VbGetArchPropertyString(const char* name, char* dest,
				    size_t size)
{
	unsigned value;

	if (!strcasecmp(name,"arch")) {
		return StrCopy(dest, "x86", size);
	} else if (!strcasecmp(name,"hwid")) {
		return ReadAcpiSysfsString(dest, size, "HWID");
	} else if (!strcasecmp(name,"fwid")) {
		return ReadAcpiSysfsString(dest, size, "FWID");
	} else if (!strcasecmp(name,"ro_fwid")) {
		return ReadAcpiSysfsString(dest, size, "FRID");
	} else if (!strcasecmp(name,"mainfw_act")) {
		if (ReadAcpiSysfsInt("BINF.1", &value) < 0)
			return NULL;
		switch(value) {
			case 0:
				return StrCopy(dest, "recovery", size);
			case 1:
				return StrCopy(dest, "A", size);
			case 2:
				return StrCopy(dest, "B", size);
			default:
				return NULL;
		}
	} else if (!strcasecmp(name,"mainfw_type")) {
		return VbReadMainFwType(dest, size);
	} else if (!strcasecmp(name,"ecfw_act")) {
		if (ReadAcpiSysfsInt("BINF.2", &value) < 0)
			return NULL;
		switch(value) {
			case 0:
				return StrCopy(dest, "RO", size);
			case 1:
				return StrCopy(dest, "RW", size);
			default:
				return NULL;
		}
	}

	return NULL;
}


int VbSetArchPropertyInt(const char* name, int value)
{
	/* NV storage values.  If unable to get from NV storage, fall back to
	 * the CMOS reboot field used by older BIOS. */
	if (!strcasecmp(name,"recovery_request")) {
		if (0 == vb2_set_nv_storage(VB2_NV_RECOVERY_REQUEST, value))
			return 0;
		return VbSetCmosRebootField(CMOSRF_RECOVERY, value);
	} else if (!strcasecmp(name,"dbg_reset")) {
		if (0 == vb2_set_nv_storage(VB2_NV_DEBUG_RESET_MODE, value))
			return 0;
		return  VbSetCmosRebootField(CMOSRF_DEBUG_RESET, value);
	}
	/* Firmware update tries is now stored in the kernel field.  On
	 * older systems where it's not, it was stored in a file in the
	 * stateful partition. */
	else if (!strcasecmp(name,"fwupdate_tries")) {
		if (-1 != vb2_get_nv_storage(VB2_NV_KERNEL_FIELD))
			return -1;  /* NvStorage supported; fail through
				     * arch-specific implementation to normal
				     * implementation */

		if (value) {
			char buf[32];
			snprintf(buf, sizeof(buf), "%d", value);
			return WriteFile(NEED_FWUPDATE_PATH, buf, strlen(buf));
		} else {
			/* No update tries, so remove file if it exists. */
			unlink(NEED_FWUPDATE_PATH);
			return 0;
		}
	}

	return -1;
}

int VbSetArchPropertyString(const char* name, const char* value)
{
	/* If there were settable architecture-dependent string properties,
	 * they'd be here. */
	return -1;
}
