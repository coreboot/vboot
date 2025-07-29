/* Copyright 2012 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#if !defined(HAVE_MACOS) && !defined (__FreeBSD__) && !defined(__OpenBSD__)
#include <linux/fs.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>

#include "crossystem_arch.h"
#include "crossystem.h"
#include "crossystem_vbnv.h"
#include "gpio_uapi.h"
#include "host_common.h"

/* Base name for firmware FDT files */
#define FDT_BASE_PATH "/proc/device-tree"
/* The /firmware/chromeos path in FDT */
#define FDT_CHROMEOS "firmware/chromeos/"
/* Path to compatible FDT entry */
#define FDT_COMPATIBLE_PATH "/proc/device-tree/compatible"
/* Path to the chromeos_arm platform device (deprecated) */
#define PLATFORM_DEV_PATH "/sys/devices/platform/chromeos_arm"
/* These should match the Linux GPIO name (i.e., 'gpio-line-names'). */
#define GPIO_NAME_RECOVERY_SW_L "RECOVERY_SW_L"
#define GPIO_NAME_RECOVERY_SW "RECOVERY_SW"
#define GPIO_NAME_WP_L "AP_FLASH_WP_L"
#define GPIO_NAME_WP "AP_FLASH_WP"
/* Device for NVCTX write */
#define NVCTX_PATH "/dev/mmcblk%d"
/* Name of NvStorage type property */
#define FDT_NVSTORAGE_TYPE_PROP FDT_CHROMEOS "nonvolatile-context-storage"
/* Errors */
#define E_FAIL      -1
#define E_FILEOP    -2
#define E_MEM       -3
/* Common constants */
#define FNAME_SIZE  80
#define SECTOR_SIZE 512
#define MAX_NMMCBLK 9

static int FindEmmcDev(void)
{
	int mmcblk;
	unsigned value;
	char filename[FNAME_SIZE];
	for (mmcblk = 0; mmcblk < MAX_NMMCBLK; mmcblk++) {
		/* Get first non-removable mmc block device */
		snprintf(filename, sizeof(filename),
			 "/sys/block/mmcblk%d/removable", mmcblk);
		if (ReadFileInt(filename, &value) < 0)
			continue;
		if (value == 0)
			return mmcblk;
	}
	/* eMMC not found */
	return E_FAIL;
}

static int ReadFdtUint32(const char *property, uint32_t *value)
{
	char filename[FNAME_SIZE];
	FILE *file;
	uint32_t data = 0;

	snprintf(filename, sizeof(filename), FDT_BASE_PATH "/%s", property);
	file = fopen(filename, "rb");
	if (!file) {
		fprintf(stderr, "Unable to open FDT property %s\n", property);
		return E_FILEOP;
	}

	if (fread(&data, 1, sizeof(data), file) != sizeof(data)) {
		fprintf(stderr, "Unable to read FDT property %s\n", property);
		return E_FILEOP;
	}
	fclose(file);

	if (value)
		*value = ntohl(data); /* FDT is network byte order */

	return 0;
}

static void GetFdtPropertyPath(const char *property, char *path, size_t size)
{
	if (property[0] == '/')
		StrCopy(path, property, size);
	else
		snprintf(path, size, FDT_BASE_PATH "/%s", property);
}

static int FdtPropertyExist(const char *property)
{
	char filename[FNAME_SIZE];
	struct stat file_status;

	GetFdtPropertyPath(property, filename, sizeof(filename));
	if (!stat(filename, &file_status))
		return 1; // It exists!
	else
		return 0; // It does not exist or some error happened.
}

static int ReadFdtBlock(const char *property, void **block, size_t *size)
{
	char filename[FNAME_SIZE];
	FILE *file;
	size_t property_size;
	char *data;

	if (!block)
		return E_FAIL;

	GetFdtPropertyPath(property, filename, sizeof(filename));
	file = fopen(filename, "rb");
	if (!file) {
		fprintf(stderr, "Unable to open FDT property %s\n", property);
		return E_FILEOP;
	}

	fseek(file, 0, SEEK_END);
	property_size = ftell(file);
	rewind(file);

	data = malloc(property_size +1);
	if (!data) {
		fclose(file);
		return E_MEM;
	}
	data[property_size] = 0;

	if (1 != fread(data, property_size, 1, file)) {
		fprintf(stderr, "Unable to read from property %s\n", property);
		fclose(file);
		free(data);
		return E_FILEOP;
	}

	fclose(file);
	*block = data;
	if (size)
		*size = property_size;

	return 0;
}

static char * ReadFdtString(const char *property)
{
	void *str = NULL;
	/* Do not need property size */
	ReadFdtBlock(property, &str, 0);
	return (char *)str;
}

static int VbGetPlatformGpioStatus(const char* name)
{
	char gpio_name[FNAME_SIZE];
	unsigned value;

	snprintf(gpio_name, sizeof(gpio_name), "%s/%s/value",
		 PLATFORM_DEV_PATH, name);
	if (ReadFileInt(gpio_name, &value) < 0)
		return -1;

	return (int)value;
}

static int vb2_read_nv_storage_disk(struct vb2_context *ctx)
{
	int nvctx_fd = -1;
	uint8_t sector[SECTOR_SIZE];
	int rv = -1;
	char nvctx_path[FNAME_SIZE];
	int emmc_dev;
	uint32_t lba, offset, size;

	if (ReadFdtUint32(FDT_CHROMEOS "nonvolatile-context-lba", &lba) ||
	    ReadFdtUint32(FDT_CHROMEOS "nonvolatile-context-offset", &offset) ||
	    ReadFdtUint32(FDT_CHROMEOS "nonvolatile-context-size", &size))
		return E_FAIL;

	emmc_dev = FindEmmcDev();
	if (emmc_dev < 0)
		return E_FAIL;
	snprintf(nvctx_path, sizeof(nvctx_path), NVCTX_PATH, emmc_dev);

	if (size != vb2_nv_get_size(ctx) || (size + offset > SECTOR_SIZE))
		return E_FAIL;

	nvctx_fd = open(nvctx_path, O_RDONLY);
	if (nvctx_fd == -1) {
		fprintf(stderr, "%s: failed to open %s\n", __FUNCTION__,
			nvctx_path);
		goto out;
	}
	lseek(nvctx_fd, lba * SECTOR_SIZE, SEEK_SET);

	rv = read(nvctx_fd, sector, SECTOR_SIZE);
	if (size <= 0) {
		fprintf(stderr, "%s: failed to read nvctx from device %s\n",
			__FUNCTION__, nvctx_path);
		goto out;
	}
	memcpy(ctx->nvdata, sector+offset, size);
	rv = 0;

out:
	if (nvctx_fd > 0)
		close(nvctx_fd);

	return rv;
}

static int vb2_write_nv_storage_disk(struct vb2_context *ctx)
{
	int nvctx_fd = -1;
	uint8_t sector[SECTOR_SIZE];
	int rv = -1;
	char nvctx_path[FNAME_SIZE];
	int emmc_dev;
	uint32_t lba, offset, size;

	if (ReadFdtUint32(FDT_CHROMEOS "nonvolatile-context-lba", &lba) ||
	    ReadFdtUint32(FDT_CHROMEOS "nonvolatile-context-offset", &offset) ||
	    ReadFdtUint32(FDT_CHROMEOS "nonvolatile-context-size", &size))
		return E_FAIL;

	emmc_dev = FindEmmcDev();
	if (emmc_dev < 0)
		return E_FAIL;
	snprintf(nvctx_path, sizeof(nvctx_path), NVCTX_PATH, emmc_dev);

	if (size != vb2_nv_get_size(ctx) || (size + offset > SECTOR_SIZE))
		return E_FAIL;

	do {
		nvctx_fd = open(nvctx_path, O_RDWR);
		if (nvctx_fd == -1) {
			fprintf(stderr, "%s: failed to open %s\n",
				__FUNCTION__, nvctx_path);
			break;
		}
		lseek(nvctx_fd, lba * SECTOR_SIZE, SEEK_SET);
		rv = read(nvctx_fd, sector, SECTOR_SIZE);
		if (rv <= 0) {
			fprintf(stderr,
				"%s: failed to read nvctx from device %s\n",
				__FUNCTION__, nvctx_path);
			break;
		}
		memcpy(sector+offset, ctx->nvdata, size);
		lseek(nvctx_fd, lba * SECTOR_SIZE, SEEK_SET);
		rv = write(nvctx_fd, sector, SECTOR_SIZE);
		if (rv <= 0) {
			fprintf(stderr,
				"%s: failed to write nvctx to device %s\n",
				__FUNCTION__, nvctx_path);
			break;
		}
#ifndef HAVE_MACOS
		/* Must flush buffer cache here to make sure it goes to disk */
		rv = ioctl(nvctx_fd, BLKFLSBUF, 0);
		if (rv < 0) {
			fprintf(stderr,
				"%s: failed to flush nvctx to device %s\n",
				__FUNCTION__, nvctx_path);
			break;
		}
#endif
		rv = 0;
	} while (0);

	if (nvctx_fd > 0)
		close(nvctx_fd);

	return rv;
}

int vb2_read_nv_storage(struct vb2_context *ctx)
{
	/* Default to disk for older firmware which does not provide storage
	 * type */
	char *media;
	if (!FdtPropertyExist(FDT_NVSTORAGE_TYPE_PROP))
		return vb2_read_nv_storage_disk(ctx);
	media = ReadFdtString(FDT_NVSTORAGE_TYPE_PROP);
	if (!strcmp(media, "disk"))
		return vb2_read_nv_storage_disk(ctx);
	if (!strcmp(media, "flash"))
		return vb2_read_nv_storage_flashrom(ctx);
	return -1;
}

int vb2_write_nv_storage(struct vb2_context *ctx)
{
	/* Default to disk for older firmware which does not provide storage
	 * type */
	char *media;
	if (!FdtPropertyExist(FDT_NVSTORAGE_TYPE_PROP))
		return vb2_write_nv_storage_disk(ctx);
	media = ReadFdtString(FDT_NVSTORAGE_TYPE_PROP);
	if (!strcmp(media, "disk"))
		return vb2_write_nv_storage_disk(ctx);
	if (!strcmp(media, "flash"))
		return vb2_write_nv_storage_flashrom(ctx);
	return -1;
}

VbSharedDataHeader *VbSharedDataRead(void)
{
	void *block = NULL;
	size_t size = 0;
	if (ReadFdtBlock(FDT_CHROMEOS "vboot-shared-data", &block, &size))
		return NULL;
	VbSharedDataHeader *p = (VbSharedDataHeader *)block;
	if (p->magic != VB_SHARED_DATA_MAGIC) {
		fprintf(stderr,  "%s: failed to validate magic in "
			"VbSharedDataHeader (%x != %x)\n",
			__FUNCTION__, p->magic, VB_SHARED_DATA_MAGIC);
		return NULL;
	}
	return (VbSharedDataHeader *)block;
}

int VbGetArchPropertyInt(const char* name)
{
	if (!strcasecmp(name, "devsw_cur")) {
		/* Systems with virtual developer switches return at-boot
		 * value */
		return VbGetSystemPropertyInt("devsw_boot");
	} else if (!strcasecmp(name, "recoverysw_cur")) {
		int value;
		/* Try GPIO chardev API first. */
		value = gpio_read_value_by_name(GPIO_NAME_RECOVERY_SW_L, true);
		if (value != -1)
			return value;
		value = gpio_read_value_by_name(GPIO_NAME_RECOVERY_SW, false);
		if (value != -1)
			return value;
		/* Try the deprecated chromeos_arm platform device next. */
		return VbGetPlatformGpioStatus("recovery");
	} else if (!strcasecmp(name, "wpsw_cur")) {
		int value;
		/* Try GPIO chardev API first. */
		value = gpio_read_value_by_name(GPIO_NAME_WP_L, true);
		if (value != -1)
			return value;
		value = gpio_read_value_by_name(GPIO_NAME_WP, false);
		if (value != -1)
			return value;
		/* Try the deprecated chromeos_arm platform device next. */
		return VbGetPlatformGpioStatus("write-protect");
	} else if (!strcasecmp(name, "recoverysw_ec_boot")) {
		/* TODO: read correct value using ectool */
		return 0;
	} else if (!strcasecmp(name, "board_id")) {
		uint32_t board_id;
		if (ReadFdtUint32("firmware/coreboot/board-id", &board_id))
			return -1;
		return board_id;
	} else {
		return -1;
	}
}

const char* VbGetArchPropertyString(const char* name, char* dest,
                                    size_t size)
{
	char *str = NULL;
	char *rv = NULL;
	const char *prop = NULL;

	if (!strcasecmp(name,"arch"))
		return StrCopy(dest, "arm", size);

	/* Properties from fdt */
	if (!strcasecmp(name, "ro_fwid"))
		prop = FDT_CHROMEOS "readonly-firmware-version";
	else if (!strcasecmp(name, "hwid"))
		prop = FDT_CHROMEOS "hardware-id";
	else if (!strcasecmp(name, "fwid"))
		prop = FDT_CHROMEOS "firmware-version";
	else if (!strcasecmp(name, "mainfw_type"))
		prop = FDT_CHROMEOS "firmware-type";
	else if (!strcasecmp(name, "ecfw_act"))
		prop = FDT_CHROMEOS "active-ec-firmware";
	if (prop)
		str = ReadFdtString(prop);

	if (str) {
		rv = StrCopy(dest, str, size);
		free(str);
		return rv;
	}
	return NULL;
}

int VbSetArchPropertyInt(const char* name, int value)
{
	/* All is handled in arch independent fashion */
	return -1;
}

int VbSetArchPropertyString(const char* name, const char* value)
{
	/* All is handled in arch independent fashion */
	return -1;
}
