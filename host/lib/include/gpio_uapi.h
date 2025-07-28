/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef VBOOT_REFERENCE_GPIO_UAPI_H
#define VBOOT_REFERENCE_GPIO_UAPI_H

#include <stdbool.h>

/*
 * This module uses Linux UAPI to access GPIO pin values.
 */

/**
 * Get the value of a GPIO pin with a matching name.
 *
 * Returns negative value on error, 1 for active state, 0 for inactive.
 */
int gpio_read_value_by_name(const char *name, bool active_low);

/**
 * Get the value of a GPIO pin on a specified index from a specified controller.
 * Controller number is equivalent to the number of /dev/gpiochipX.
 *
 * Returns negative value on error, 1 for active state, 0 for inactive.
 */
int gpio_read_value_by_idx(int controller_num, int idx, bool active_low);

#endif  /* VBOOT_REFERENCE_GPIO_UAPI_H */
