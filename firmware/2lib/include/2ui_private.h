/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Private declarations for 2ui.c. Defined here for testing purposes.
 */

#include "2api.h"

#ifndef VBOOT_REFERENCE_2UI_PRIVATE_H_
#define VBOOT_REFERENCE_2UI_PRIVATE_H_

enum power_button_state {
	POWER_BUTTON_HELD_SINCE_BOOT = 0,
	POWER_BUTTON_RELEASED,
	POWER_BUTTON_PRESSED,  /* Must have been previously released */
};
extern enum power_button_state power_button;
int shutdown_required(struct vb2_context *ctx, uint32_t key);

extern int invalid_disk_last;

struct input_action {
	int key;
	vb2_error_t (*action)(struct vb2_ui_context *ui);
};

vb2_error_t menu_up_action(struct vb2_ui_context *ui);
vb2_error_t menu_down_action(struct vb2_ui_context *ui);
vb2_error_t menu_select_action(struct vb2_ui_context *ui);
vb2_error_t menu_back_action(struct vb2_ui_context *ui);
vb2_error_t (*input_action_lookup(int key))(struct vb2_ui_context *ui);

void change_screen(struct vb2_ui_context *ui, enum vb2_screen id);
void validate_selection(struct vb2_screen_state *state);
vb2_error_t ui_loop(struct vb2_context *ctx, enum vb2_screen root_screen_id,
		    vb2_error_t (*global_action)(struct vb2_ui_context *ui));

vb2_error_t try_recovery_action(struct vb2_ui_context *ui);

#endif  /* VBOOT_REFERENCE_2UI_PRIVATE_H_ */
