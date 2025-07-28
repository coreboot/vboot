/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <dirent.h>
#include <fcntl.h>
#if !defined(HAVE_MACOS) && !defined (__FreeBSD__) && !defined(__OpenBSD__)
#include <linux/fs.h>
#include <linux/gpio.h>
#endif
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "gpio_uapi.h"

#if defined(GPIO_V2_GET_LINE_IOCTL)
static int gpio_uapi_v2_read_value(int chip_fd, int idx, bool active_low)
{
	struct gpio_v2_line_request request;
	struct gpio_v2_line_values line_value;
	int trynum;
	int ret;

	memset(&request, 0, sizeof(request));
	memset(&line_value, 0, sizeof(line_value));

	/* Request a single line with an input mode and corresponding active state.
	   Set consumer to allow for easy identification of access. */
	request.offsets[0] = idx;
	request.num_lines = 1,
	request.config.flags =
		GPIO_V2_LINE_FLAG_INPUT | (active_low ? GPIO_V2_LINE_FLAG_ACTIVE_LOW : 0);
	strcpy(request.consumer, "vboot");

	/* Set first bit corresponding to the first an only index/offset from the request. */
	line_value.mask = 0x1;

	/*
	 * If two callers try to read the same GPIO at the same time then
	 * one of the two will get back EBUSY. There's no great way to
	 * solve this, so we'll just retry a bunch with a small sleep in
	 * between.
	 */
	for (trynum = 0; true; trynum++) {
		ret = ioctl(chip_fd, GPIO_V2_GET_LINE_IOCTL, &request);

		/*
		 * Not part of the loop condition so usleep doesn't clobber
		 * errno (implicitly used by perror).
		 */
		if (ret >= 0 || errno != EBUSY || trynum >= 50)
			break;

		usleep(trynum * 1000);
	}

	if (ret < 0) {
		perror("GPIO_V2_GET_LINE_IOCTL");
		return -1;
	}

	if (request.fd < 0) {
		fprintf(stderr, "bad LINE fd %d\n", request.fd);
		return -1;
	}

	ret = ioctl(request.fd, GPIO_V2_LINE_GET_VALUES_IOCTL, &line_value);
	if (ret < 0) {
		perror("GPIO_V2_LINE_GET_VALUES_IOCTL");
		close(request.fd);
		return -1;
	}
	close(request.fd);
	return line_value.bits & 0x1;
}

/*
 * Checks if the pin name at the @idx index is equal to the @name.
 * Returns -1 on failure, 0 on match, 1 on mismatch.
 */
static int gpio_uapi_v2_name_match(int chip_fd, int idx, const char *name)
{
	struct gpio_v2_line_info info;

	memset(&info, 0, sizeof(info));
	info.offset = idx;

	if (ioctl(chip_fd, GPIO_V2_GET_LINEINFO_IOCTL, &info) < 0) {
		perror("GPIO_V2_GET_LINEINFO_IOCTL");
		return -1;
	}

	return strncmp(info.name, name, sizeof(info.name)) != 0;
}

#elif defined(GPIO_GET_LINEHANDLE_IOCTL)

static int gpio_uapi_v1_read_value(int chip_fd, int idx, bool active_low)
{
	struct gpiohandle_request request = {
		.lineoffsets = {idx},
		.flags = GPIOHANDLE_REQUEST_INPUT |
			 (active_low ? GPIOHANDLE_REQUEST_ACTIVE_LOW : 0),
		.lines = 1,
	};
	struct gpiohandle_data data;
	int trynum;
	int ret;

	/*
	 * If two callers try to read the same GPIO at the same time then
	 * one of the two will get back EBUSY. There's no great way to
	 * solve this, so we'll just retry a bunch with a small sleep in
	 * between.
	 */
	for (trynum = 0; true; trynum++) {
		ret = ioctl(chip_fd, GPIO_GET_LINEHANDLE_IOCTL, &request);

		/*
		 * Not part of the loop condition so usleep doesn't clobber
		 * errno (implicitly used by perror).
		 */
		if (ret >= 0 || errno != EBUSY || trynum >= 50)
			break;

		usleep(trynum * 1000);
	}

	if (ret < 0) {
		perror("GPIO_GET_LINEHANDLE_IOCTL");
		return -1;
	}

	if (request.fd < 0) {
		fprintf(stderr, "bad LINEHANDLE fd %d\n", request.fd);
		return -1;
	}

	ret = ioctl(request.fd, GPIOHANDLE_GET_LINE_VALUES_IOCTL, &data);
	if (ret < 0) {
		perror("GPIOHANDLE_GET_LINE_VALUES_IOCTL");
		close(request.fd);
		return -1;
	}
	close(request.fd);
	return data.values[0];
}

/*
 * Checks if the pin name at the @idx index is equal to the @name.
 * Returns -1 on failure, 0 on match, 1 on mismatch.
 */
static int gpio_uapi_v1_name_match(int chip_fd, int idx, const char *name)
{
	struct gpioline_info info;

	memset(&info, 0, sizeof(info));
	info.line_offset = idx;

	if (ioctl(chip_fd, GPIO_GET_LINEINFO_IOCTL, &info) < 0) {
		perror("GPIO_GET_LINEINFO_IOCTL");
		return -1;
	}

	return strncmp(info.name, name, sizeof(info.name)) != 0;
}
#endif

static int gpio_uapi_read_value_by_idx(int fd, int idx, bool active_low)
{
#if defined(GPIO_V2_GET_LINE_IOCTL)
	return gpio_uapi_v2_read_value(fd, idx, active_low);
#elif defined(GPIO_GET_LINEHANDLE_IOCTL)
	return gpio_uapi_v1_read_value(fd, idx, active_low);
#else
	return -1;
#endif
}

static int gpio_uapi_read_value_by_name(int chip_fd, const char *name, bool active_low)
{
	struct gpiochip_info info;
	int ret;

	if (ioctl(chip_fd, GPIO_GET_CHIPINFO_IOCTL, &info) < 0) {
		perror("GPIO_GET_CHIPINFO_IOCTL");
		return -1;
	}

	for (int i = 0; i < info.lines; i++) {
#if defined(GPIO_V2_GET_LINE_IOCTL)
		ret = gpio_uapi_v2_name_match(chip_fd, i, name);
#elif defined(GPIO_GET_LINEHANDLE_IOCTL)
		ret = gpio_uapi_v1_name_match(chip_fd, i, name);
#else
		return -1;
#endif
		if (ret < 0)
			return -1;
		/* No match */
		if (ret)
			continue;
		return gpio_uapi_read_value_by_idx(chip_fd, i, active_low);
	}

	return -1;
}

/* Return nonzero for entries with a 'gpiochip'-prefixed name. */
static int gpiochip_scan_filter(const struct dirent *d)
{
	const char prefix[] = "gpiochip";
	return !strncmp(prefix, d->d_name, strlen(prefix));
}

int gpio_read_value_by_name(const char *name, bool active_low)
{
	struct dirent **list;
	int i, entries_num, ret;

	ret = scandir("/dev", &list, gpiochip_scan_filter, alphasort);
	if (ret < 0) {
		perror("scandir");
		return -1;
	}
	entries_num = ret;
	/* No /dev/gpiochip* -- API not supported. */
	if (!entries_num)
		return -1;

	for (i = 0; i < entries_num; i++) {
		char buf[5 + NAME_MAX + 1];
		int fd;

		snprintf(buf, sizeof(buf), "/dev/%s", list[i]->d_name);
		ret = open(buf, O_RDWR);
		if (ret < 0) {
			perror("open");
			break;
		}
		fd = ret;

		ret = gpio_uapi_read_value_by_name(fd, name, active_low);

		close(fd);
		if (ret >= 0)
			break;
	}

	for (i = 0; i < entries_num; i++)
		free(list[i]);
	free(list);

	return ret;
}

int gpio_read_value_by_idx(int controller_num, int idx, bool active_low)
{
	int fd, ret;
	char path[5 + NAME_MAX + 1];

	snprintf(path, sizeof(path), "/dev/gpiochip%d", controller_num);

	fd = open(path, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Unable to open %s\n", path);
		perror("open");
		return -1;
	}

	ret = gpio_uapi_read_value_by_idx(fd, idx, active_low);

	close(fd);
	return ret;
}
