/* Copyright (c) 2015-2018, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __DPU_WB_H__
#define __DPU_WB_H__

#include <linux/platform_device.h>

#include "msm_kms.h"
#include "dpu_kms.h"
#include "dpu_connector.h"

/**
 * struct dpu_wb_device - Writeback device context
 * @drm_dev:		Pointer to controlling DRM device
 * @index:		Index of hardware instance from device tree
 * @wb_idx:		Writeback identifier of enum dpu_wb
 * @wb_cfg:		Writeback configuration catalog
 * @name:		Name of writeback device from device tree
 * @display_type:	Display type from device tree
 * @wb_list		List of all writeback devices
 * @wb_lock		Serialization lock for writeback context structure
 * @connector:		Connector associated with writeback device
 * @encoder:		Encoder associated with writeback device
 * @max_mixer_width:    Max width supported by DPU LM HW block
 * @count_modes:	Length of writeback connector modes array
 * @modes:		Writeback connector modes array
 */
struct dpu_wb_device {
	struct drm_device *drm_dev;

	u32 index;
	u32 wb_idx;
	struct dpu_wb_cfg *wb_cfg;
	const char *name;

	struct list_head wb_list;
	struct mutex wb_lock;

	struct drm_connector *connector;
	struct drm_encoder *encoder;

	enum drm_connector_status detect_status;
	u32 max_mixer_width;

	u32 count_modes;
	struct drm_mode_modeinfo *modes;
};

/**
 * dpu_wb_get_index - get device index of the given writeback device
 * @wb_dev:	Pointer to writeback device
 * Returns:	Index of hardware instance
 */
static inline
int dpu_wb_get_index(struct dpu_wb_device *wb_dev)
{
	return wb_dev ? wb_dev->index : -1;
}

/**
 * dpu_wb_get_output_fb - get framebuffer in current atomic state
 * @wb_dev:	Pointer to writeback device
 * Returns:	Pointer to framebuffer
 */
struct drm_framebuffer *dpu_wb_get_output_fb(struct dpu_wb_device *wb_dev);

/**
 * dpu_wb_get_output_roi - get region-of-interest in current atomic state
 * @wb_dev:	Pointer to writeback device
 * @roi:	Pointer to region of interest
 * Returns:	0 if success; error code otherwise
 */
int dpu_wb_get_output_roi(struct dpu_wb_device *wb_dev, struct dpu_rect *roi);

/**
 * dpu_wb_get_num_of_displays - get total number of writeback devices
 * Returns:	Number of writeback devices
 */
u32 dpu_wb_get_num_of_displays(void);

/**
 * wb_display_get_displays - returns pointers for supported display devices
 * @display_array: Pointer to display array to be filled
 * @max_display_count: Size of display_array
 * @Returns: Number of display entries filled
 */
int wb_display_get_displays(void **display_array, u32 max_display_count);

void dpu_wb_set_active_state(struct dpu_wb_device *wb_dev, bool is_active);
bool dpu_wb_is_active(struct dpu_wb_device *wb_dev);

/**
 * dpu_wb_drm_init - perform DRM initialization
 * @wb_dev:	Pointer to writeback device
 * @encoder:	Pointer to associated encoder
 * Returns:	0 if success; error code otherwise
 */
int dpu_wb_drm_init(struct dpu_wb_device *wb_dev, struct drm_encoder *encoder);

/**
 * dpu_wb_drm_deinit - perform DRM de-initialization
 * @wb_dev:	Pointer to writeback device
 * Returns:	0 if success; error code otherwise
 */
int dpu_wb_drm_deinit(struct dpu_wb_device *wb_dev);

/**
 * dpu_wb_config - setup connection status and available drm modes of the
 *			given writeback connector
 * @drm_dev:	Pointer to DRM device
 * @data:	Pointer to writeback configuration
 * @file_priv:	Pointer file private data
 * Returns:	0 if success; error code otherwise
 *
 * This function will initiate hot-plug detection event.
 */
int dpu_wb_config(struct drm_device *drm_dev, void *data,
				struct drm_file *file_priv);

/**
 * dpu_wb_connector_post_init - perform writeback specific initialization
 * @connector: Pointer to drm connector structure
 * @info: Pointer to connector info
 * @display: Pointer to private display structure
 * Returns: Zero on success
 */
int dpu_wb_connector_post_init(struct drm_connector *connector,
		void *info,
		void *display);

/**
 * dpu_wb_connector_detect - perform writeback connection status detection
 * @connector:	Pointer to connector
 * @force:	Indicate force detection
 * @display:	Pointer to writeback device
 * Returns:	connector status
 */
enum drm_connector_status
dpu_wb_connector_detect(struct drm_connector *connector,
		bool force,
		void *display);

/**
 * dpu_wb_connector_get_modes - get display modes of connector
 * @connector:	Pointer to connector
 * @display:	Pointer to writeback device
 * Returns:	Number of modes
 *
 * If display modes are not specified in writeback configuration IOCTL, this
 * function will install default EDID modes up to maximum resolution support.
 */
int dpu_wb_connector_get_modes(struct drm_connector *connector, void *display);

/**
 * dpu_wb_connector_set_property - set atomic connector property
 * @connector: Pointer to drm connector structure
 * @state: Pointer to drm connector state structure
 * @property_index: DRM property index
 * @value: Incoming property value
 * @display: Pointer to private display structure
 * Returns: Zero on success
 */
int dpu_wb_connector_set_property(struct drm_connector *connector,
		struct drm_connector_state *state,
		int property_index,
		uint64_t value,
		void *display);

/**
 * dpu_wb_get_info - retrieve writeback 'display' information
 * @info: Pointer to display info structure
 * @display: Pointer to private display structure
 * Returns: Zero on success
 */
int dpu_wb_get_info(struct msm_display_info *info, void *display);

/**
 * dpu_wb_get_mode_info - retrieve information of the mode selected
 * @drm_mode: Display mode set for the display
 * @mode_info: Out parameter. information of the mode.
 * @max_mixer_width: max width supported by HW layer mixer
 * Returns: zero on success
 */
int dpu_wb_get_mode_info(const struct drm_display_mode *drm_mode,
		struct msm_mode_info *mode_info, u32 max_mixer_width);

/**
 * dpu_wb_connector_get_wb - retrieve writeback device of the given connector
 * @connector: Pointer to drm connector
 * Returns: Pointer to writeback device on success; NULL otherwise
 */
static inline
struct dpu_wb_device *dpu_wb_connector_get_wb(struct drm_connector *connector)
{
	if (!connector ||
		(connector->connector_type != DRM_MODE_CONNECTOR_VIRTUAL)) {
		DPU_ERROR("invalid params\n");
		return NULL;
	}

	return dpu_connector_get_display(connector);
}

/**
 * dpu_wb_connector_state_get_output_fb - get framebuffer of given state
 * @state:	Pointer to connector state
 * Returns:	Pointer to framebuffer
 */
struct drm_framebuffer *
dpu_wb_connector_state_get_output_fb(struct drm_connector_state *state);

/**
 * dpu_wb_connector_state_get_output_roi - get roi from given atomic state
 * @state:	Pointer to atomic state
 * @roi:	Pointer to region of interest
 * Returns:	0 if success; error code otherwise
 */
int dpu_wb_connector_state_get_output_roi(struct drm_connector_state *state,
		struct dpu_rect *roi);

#endif /* __DPU_WB_H__ */

