/*
 * Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * A reference implementation for AP (and supporting images) firmware updater.
 */
#ifndef VBOOT_REFERENCE_FUTILITY_UPDATER_H_
#define VBOOT_REFERENCE_FUTILITY_UPDATER_H_

#include "futility.h"

#define DEBUG(format, ...) Debug("%s: " format "\n", __FUNCTION__,##__VA_ARGS__)
#define ERROR(format, ...) Error("%s: " format "\n", __FUNCTION__,##__VA_ARGS__)

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
	UPDATE_ERR_UNKNOWN,
};

/* Messages explaining enum updater_error_codes. */
extern const char * const updater_error_messages[];

struct updater_config;

/*
 * The main updater to update system firmware using the configuration parameter.
 * Returns UPDATE_ERR_DONE if success, otherwise failure.
 */
enum updater_error_codes update_firmware(struct updater_config *cfg);

/*
 * Allocates and initializes a updater_config object with default values.
 * Returns the newly allocated object, or NULL on error.
 */
struct updater_config *updater_new_config();

/*
 * Releases all resources in an updater configuration object.
 */
void updater_delete_config(struct updater_config *cfg);

/*
 * Helper function to setup an allocated updater_config object.
 * Returns number of failures, or 0 on success.
 */
int updater_setup_config(struct updater_config *cfg,
			  const char *image,
			  const char *ec_image,
			  const char *pd_image,
			  const char *quirks,
			  const char *mode,
			  const char *programmer,
			  const char *emulation,
			  const char *sys_props,
			  const char *write_protection,
			  int is_factory,
			  int try_update,
			  int force_update);

/* Prints the name and description from all supported quirks. */
void updater_list_config_quirks(const struct updater_config *cfg);

#endif  /* VBOOT_REFERENCE_FUTILITY_UPDATER_H_ */
