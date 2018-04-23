/*
 * Copyright (c) 2015-2018, The Linux Foundation. All rights reserved.
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

#define pr_fmt(fmt)	"[drm:%s:%d] " fmt, __func__, __LINE__

#include <uapi/drm/dpu_drm.h>

#include "msm_kms.h"
#include "dpu_kms.h"
#include "dpu_wb.h"
#include "dpu_formats.h"

/* maximum display mode resolution if not available from catalog */
#define DPU_WB_MODE_MAX_WIDTH	4096
#define DPU_WB_MODE_MAX_HEIGHT	4096

/* Serialization lock for dpu_wb_list */
static DEFINE_MUTEX(dpu_wb_list_lock);

/* List of all writeback devices installed */
static LIST_HEAD(dpu_wb_list);

/**
 * dpu_wb_is_format_valid - check if given format/modifier is supported
 * @wb_dev:	Pointer to writeback device
 * @pixel_format:	Fourcc pixel format
 * @format_modifier:	Format modifier
 * Returns:		true if valid; false otherwise
 */
static int dpu_wb_is_format_valid(struct dpu_wb_device *wb_dev,
		u32 pixel_format, u64 format_modifier)
{
	const struct dpu_format_extended *fmts = wb_dev->wb_cfg->format_list;
	int i;

	if (!fmts)
		return false;

	for (i = 0; fmts[i].fourcc_format; i++)
		if ((fmts[i].modifier == format_modifier) &&
				(fmts[i].fourcc_format == pixel_format))
			return true;

	return false;
}

enum drm_connector_status
dpu_wb_connector_detect(struct drm_connector *connector,
		bool force,
		void *display)
{
	enum drm_connector_status rc = connector_status_unknown;

	DPU_DEBUG("\n");

	if (display)
		rc = ((struct dpu_wb_device *)display)->detect_status;

	return rc;
}

int dpu_wb_connector_get_modes(struct drm_connector *connector, void *display)
{
	struct dpu_wb_device *wb_dev;
	int num_modes = 0;

	if (!connector || !display)
		return 0;

	wb_dev = display;

	DPU_DEBUG("\n");

	mutex_lock(&wb_dev->wb_lock);
	if (wb_dev->count_modes && wb_dev->modes) {
		struct drm_display_mode *mode;
		int i, ret;

		for (i = 0; i < wb_dev->count_modes; i++) {
			mode = drm_mode_create(connector->dev);
			if (!mode) {
				DPU_ERROR("failed to create mode\n");
				break;
			}
			ret = drm_mode_convert_umode(mode,
					&wb_dev->modes[i]);
			if (ret) {
				DPU_ERROR("failed to convert mode %d\n", ret);
				break;
			}

			drm_mode_probed_add(connector, mode);
			num_modes++;
		}
	} else {
		u32 max_width = (wb_dev->wb_cfg && wb_dev->wb_cfg->sblk) ?
				wb_dev->wb_cfg->sblk->maxlinewidth :
				DPU_WB_MODE_MAX_WIDTH;

		num_modes = drm_add_modes_noedid(connector, max_width,
				DPU_WB_MODE_MAX_HEIGHT);
	}
	mutex_unlock(&wb_dev->wb_lock);
	return num_modes;
}

struct drm_framebuffer *
dpu_wb_connector_state_get_output_fb(struct drm_connector_state *state)
{
	if (!state || !state->connector ||
		(state->connector->connector_type !=
				DRM_MODE_CONNECTOR_VIRTUAL)) {
		DPU_ERROR("invalid params\n");
		return NULL;
	}

	DPU_DEBUG("\n");

	return dpu_connector_get_out_fb(state);
}

int dpu_wb_connector_state_get_output_roi(struct drm_connector_state *state,
		struct dpu_rect *roi)
{
	if (!state || !roi || !state->connector ||
		(state->connector->connector_type !=
				DRM_MODE_CONNECTOR_VIRTUAL)) {
		DPU_ERROR("invalid params\n");
		return -EINVAL;
	}

	DPU_DEBUG("\n");

	roi->x = dpu_connector_get_property(state, CONNECTOR_PROP_DST_X);
	roi->y = dpu_connector_get_property(state, CONNECTOR_PROP_DST_Y);
	roi->w = dpu_connector_get_property(state, CONNECTOR_PROP_DST_W);
	roi->h = dpu_connector_get_property(state, CONNECTOR_PROP_DST_H);

	return 0;
}

/**
 * dpu_wb_connector_set_modes - set writeback modes and connection status
 * @wb_dev:	Pointer to write back device
 * @count_modes:	Count of modes
 * @modes:	Pointer to writeback mode requested
 * @connected:	Connection status requested
 * Returns:	0 if success; error code otherwise
 */
static
int dpu_wb_connector_set_modes(struct dpu_wb_device *wb_dev,
		u32 count_modes, struct drm_mode_modeinfo __user *modes,
		bool connected)
{
	int ret = 0;

	if (!wb_dev || !wb_dev->connector ||
			(wb_dev->connector->connector_type !=
			 DRM_MODE_CONNECTOR_VIRTUAL)) {
		DPU_ERROR("invalid params\n");
		return -EINVAL;
	}

	DPU_DEBUG("\n");

	if (connected) {
		DPU_DEBUG("connect\n");

		if (wb_dev->modes) {
			wb_dev->count_modes = 0;

			kfree(wb_dev->modes);
			wb_dev->modes = NULL;
		}

		if (count_modes && modes) {
			wb_dev->modes = kcalloc(count_modes,
					sizeof(struct drm_mode_modeinfo),
					GFP_KERNEL);
			if (!wb_dev->modes) {
				DPU_ERROR("invalid params\n");
				ret = -ENOMEM;
				goto error;
			}

			if (copy_from_user(wb_dev->modes, modes,
					count_modes *
					sizeof(struct drm_mode_modeinfo))) {
				DPU_ERROR("failed to copy modes\n");
				kfree(wb_dev->modes);
				wb_dev->modes = NULL;
				ret = -EFAULT;
				goto error;
			}

			wb_dev->count_modes = count_modes;
		}

		wb_dev->detect_status = connector_status_connected;
	} else {
		DPU_DEBUG("disconnect\n");

		if (wb_dev->modes) {
			wb_dev->count_modes = 0;

			kfree(wb_dev->modes);
			wb_dev->modes = NULL;
		}

		wb_dev->detect_status = connector_status_disconnected;
	}

error:
	return ret;
}

int dpu_wb_connector_set_property(struct drm_connector *connector,
		struct drm_connector_state *state,
		int property_index,
		uint64_t value,
		void *display)
{
	struct dpu_wb_device *wb_dev = display;
	struct drm_framebuffer *out_fb;
	int rc = 0;

	DPU_DEBUG("\n");

	if (state && (property_index == CONNECTOR_PROP_OUT_FB)) {
		const struct dpu_format *dpu_format;

		out_fb = dpu_connector_get_out_fb(state);
		if (!out_fb)
			goto done;

		dpu_format = dpu_get_dpu_format_ext(out_fb->format->format,
				out_fb->modifier);
		if (!dpu_format) {
			DPU_ERROR("failed to get dpu format\n");
			rc = -EINVAL;
			goto done;
		}

		if (!dpu_wb_is_format_valid(wb_dev, out_fb->format->format,
				out_fb->modifier)) {
			DPU_ERROR("unsupported writeback format 0x%x/0x%llx\n",
					out_fb->format->format,
					out_fb->modifier);
			rc = -EINVAL;
			goto done;
		}
	}

done:
	return rc;
}

int dpu_wb_get_info(struct msm_display_info *info, void *display)
{
	struct dpu_wb_device *wb_dev = display;

	if (!info || !wb_dev) {
		pr_err("invalid params\n");
		return -EINVAL;
	}

	memset(info, 0, sizeof(struct msm_display_info));
	info->intf_type = DRM_MODE_CONNECTOR_VIRTUAL;
	info->num_of_h_tiles = 1;
	info->h_tile_instance[0] = dpu_wb_get_index(display);
	info->is_connected = true;
	info->capabilities = MSM_DISPLAY_CAP_HOT_PLUG | MSM_DISPLAY_CAP_EDID;
	info->max_width = (wb_dev->wb_cfg && wb_dev->wb_cfg->sblk) ?
			wb_dev->wb_cfg->sblk->maxlinewidth :
			DPU_WB_MODE_MAX_WIDTH;
	info->max_height = DPU_WB_MODE_MAX_HEIGHT;
	return 0;
}

int dpu_wb_get_mode_info(const struct drm_display_mode *drm_mode,
	struct msm_mode_info *mode_info, u32 max_mixer_width)
{
	const u32 dual_lm = 2;
	const u32 single_lm = 1;
	const u32 single_intf = 1;
	const u32 no_enc = 0;
	struct msm_display_topology *topology;

	if (!drm_mode || !mode_info || !max_mixer_width) {
		pr_err("invalid params\n");
		return -EINVAL;
	}

	topology = &mode_info->topology;
	topology->num_lm = (max_mixer_width <= drm_mode->hdisplay) ?
							dual_lm : single_lm;
	topology->num_enc = no_enc;
	topology->num_intf = single_intf;

	return 0;
}

int dpu_wb_connector_post_init(struct drm_connector *connector,
		void *info,
		void *display)
{
	struct dpu_connector *c_conn;
	struct dpu_wb_device *wb_dev = display;
	const struct dpu_format_extended *format_list;

	if (!connector || !info || !display || !wb_dev->wb_cfg) {
		DPU_ERROR("invalid params\n");
		return -EINVAL;
	}

	c_conn = to_dpu_connector(connector);
	wb_dev->connector = connector;
	wb_dev->detect_status = connector_status_connected;
	format_list = wb_dev->wb_cfg->format_list;

	/*
	 * Add extra connector properties
	 */
	msm_property_install_range(&c_conn->property_info, "FB_ID",
			0x0, 0, ~0, ~0, CONNECTOR_PROP_OUT_FB);
	msm_property_install_range(&c_conn->property_info, "DST_X",
			0x0, 0, UINT_MAX, 0, CONNECTOR_PROP_DST_X);
	msm_property_install_range(&c_conn->property_info, "DST_Y",
			0x0, 0, UINT_MAX, 0, CONNECTOR_PROP_DST_Y);
	msm_property_install_range(&c_conn->property_info, "DST_W",
			0x0, 0, UINT_MAX, 0, CONNECTOR_PROP_DST_W);
	msm_property_install_range(&c_conn->property_info, "DST_H",
			0x0, 0, UINT_MAX, 0, CONNECTOR_PROP_DST_H);

	/*
	 * Populate info buffer
	 */
	if (format_list) {
		dpu_kms_info_start(info, "pixel_formats");
		while (format_list->fourcc_format) {
			dpu_kms_info_append_format(info,
					format_list->fourcc_format,
					format_list->modifier);
			++format_list;
		}
		dpu_kms_info_stop(info);
	}

	dpu_kms_info_add_keyint(info,
			"wb_intf_index",
			wb_dev->wb_idx - WB_0);

	dpu_kms_info_add_keyint(info,
			"maxlinewidth",
			wb_dev->wb_cfg->sblk->maxlinewidth);

	dpu_kms_info_start(info, "features");
	if (wb_dev->wb_cfg && (wb_dev->wb_cfg->features & DPU_WB_UBWC))
		dpu_kms_info_append(info, "wb_ubwc");
	dpu_kms_info_stop(info);

	return 0;
}

struct drm_framebuffer *dpu_wb_get_output_fb(struct dpu_wb_device *wb_dev)
{
	struct drm_framebuffer *fb;

	if (!wb_dev || !wb_dev->connector) {
		DPU_ERROR("invalid params\n");
		return NULL;
	}

	DPU_DEBUG("\n");

	mutex_lock(&wb_dev->wb_lock);
	fb = dpu_wb_connector_state_get_output_fb(wb_dev->connector->state);
	mutex_unlock(&wb_dev->wb_lock);

	return fb;
}

int dpu_wb_get_output_roi(struct dpu_wb_device *wb_dev, struct dpu_rect *roi)
{
	int rc;

	if (!wb_dev || !wb_dev->connector || !roi) {
		DPU_ERROR("invalid params\n");
		return -EINVAL;
	}

	DPU_DEBUG("\n");

	mutex_lock(&wb_dev->wb_lock);
	rc = dpu_wb_connector_state_get_output_roi(
			wb_dev->connector->state, roi);
	mutex_unlock(&wb_dev->wb_lock);

	return rc;
}

u32 dpu_wb_get_num_of_displays(void)
{
	u32 count = 0;
	struct dpu_wb_device *wb_dev;

	DPU_DEBUG("\n");

	mutex_lock(&dpu_wb_list_lock);
	list_for_each_entry(wb_dev, &dpu_wb_list, wb_list) {
		count++;
	}
	mutex_unlock(&dpu_wb_list_lock);

	return count;
}

int wb_display_get_displays(void **display_array, u32 max_display_count)
{
	struct dpu_wb_device *curr;
	int i = 0;

	DPU_DEBUG("\n");

	if (!display_array || !max_display_count) {
		if (!display_array)
			DPU_ERROR("invalid param\n");
		return 0;
	}

	mutex_lock(&dpu_wb_list_lock);
	list_for_each_entry(curr, &dpu_wb_list, wb_list) {
		if (i >= max_display_count)
			break;
		display_array[i++] = curr;
	}
	mutex_unlock(&dpu_wb_list_lock);

	return i;
}

int dpu_wb_config(struct drm_device *drm_dev, void *data,
				struct drm_file *file_priv)
{
	struct dpu_drm_wb_cfg *config = data;
	struct msm_drm_private *priv;
	struct dpu_wb_device *wb_dev = NULL;
	struct dpu_wb_device *curr;
	struct drm_connector *connector;
	uint32_t flags;
	uint32_t connector_id;
	uint32_t count_modes;
	uint64_t modes;
	int rc;

	if (!drm_dev || !data) {
		DPU_ERROR("invalid params\n");
		return -EINVAL;
	}

	DPU_DEBUG("\n");

	flags = config->flags;
	connector_id = config->connector_id;
	count_modes = config->count_modes;
	modes = config->modes;

	priv = drm_dev->dev_private;

	connector = drm_connector_lookup(drm_dev, NULL, connector_id);
	if (!connector) {
		DPU_ERROR("failed to find connector\n");
		rc = -ENOENT;
		goto fail;
	}

	mutex_lock(&dpu_wb_list_lock);
	list_for_each_entry(curr, &dpu_wb_list, wb_list) {
		if (curr->connector == connector) {
			wb_dev = curr;
			break;
		}
	}
	mutex_unlock(&dpu_wb_list_lock);

	if (!wb_dev) {
		DPU_ERROR("failed to find wb device\n");
		rc = -ENOENT;
		goto fail;
	}

	mutex_lock(&wb_dev->wb_lock);

	rc = dpu_wb_connector_set_modes(wb_dev, count_modes,
		(struct drm_mode_modeinfo __user *) (uintptr_t) modes,
		(flags & DPU_DRM_WB_CFG_FLAGS_CONNECTED) ? true : false);

	mutex_unlock(&wb_dev->wb_lock);
	drm_helper_hpd_irq_event(drm_dev);
fail:
	return rc;
}

/**
 * _dpu_wb_dev_init - perform device initialization
 * @wb_dev:	Pointer to writeback device
 */
static int _dpu_wb_dev_init(struct dpu_wb_device *wb_dev)
{
	int rc = 0;

	if (!wb_dev) {
		DPU_ERROR("invalid params\n");
		return -EINVAL;
	}

	DPU_DEBUG("\n");

	return rc;
}

/**
 * _dpu_wb_dev_deinit - perform device de-initialization
 * @wb_dev:	Pointer to writeback device
 */
static int _dpu_wb_dev_deinit(struct dpu_wb_device *wb_dev)
{
	int rc = 0;

	if (!wb_dev) {
		DPU_ERROR("invalid params\n");
		return -EINVAL;
	}

	DPU_DEBUG("\n");

	return rc;
}

/**
 * dpu_wb_bind - bind writeback device with controlling device
 * @dev:        Pointer to base of platform device
 * @master:     Pointer to container of drm device
 * @data:       Pointer to private data
 * Returns:     Zero on success
 */
static int dpu_wb_bind(struct device *dev, struct device *master, void *data)
{
	struct dpu_wb_device *wb_dev;

	if (!dev || !master) {
		DPU_ERROR("invalid params\n");
		return -EINVAL;
	}

	wb_dev = platform_get_drvdata(to_platform_device(dev));
	if (!wb_dev) {
		DPU_ERROR("invalid wb device\n");
		return -EINVAL;
	}

	DPU_DEBUG("\n");

	mutex_lock(&wb_dev->wb_lock);
	wb_dev->drm_dev = dev_get_drvdata(master);
	mutex_unlock(&wb_dev->wb_lock);

	return 0;
}

/**
 * dpu_wb_unbind - unbind writeback from controlling device
 * @dev:        Pointer to base of platform device
 * @master:     Pointer to container of drm device
 * @data:       Pointer to private data
 */
static void dpu_wb_unbind(struct device *dev,
		struct device *master, void *data)
{
	struct dpu_wb_device *wb_dev;

	if (!dev) {
		DPU_ERROR("invalid params\n");
		return;
	}

	wb_dev = platform_get_drvdata(to_platform_device(dev));
	if (!wb_dev) {
		DPU_ERROR("invalid wb device\n");
		return;
	}

	DPU_DEBUG("\n");

	mutex_lock(&wb_dev->wb_lock);
	wb_dev->drm_dev = NULL;
	mutex_unlock(&wb_dev->wb_lock);
}

static const struct component_ops dpu_wb_comp_ops = {
	.bind = dpu_wb_bind,
	.unbind = dpu_wb_unbind,
};

/**
 * dpu_wb_drm_init - perform DRM initialization
 * @wb_dev:	Pointer to writeback device
 * @encoder:	Pointer to associated encoder
 */
int dpu_wb_drm_init(struct dpu_wb_device *wb_dev, struct drm_encoder *encoder)
{
	int rc = 0;

	if (!wb_dev || !wb_dev->drm_dev || !encoder) {
		DPU_ERROR("invalid params\n");
		return -EINVAL;
	}

	DPU_DEBUG("\n");

	mutex_lock(&wb_dev->wb_lock);

	if (wb_dev->drm_dev->dev_private) {
		struct msm_drm_private *priv = wb_dev->drm_dev->dev_private;
		struct dpu_kms *dpu_kms = to_dpu_kms(priv->kms);

		if (wb_dev->index < dpu_kms->catalog->wb_count) {
			wb_dev->wb_idx = dpu_kms->catalog->wb[wb_dev->index].id;
			wb_dev->wb_cfg = &dpu_kms->catalog->wb[wb_dev->index];
		}
	}

	wb_dev->drm_dev = encoder->dev;
	wb_dev->encoder = encoder;
	mutex_unlock(&wb_dev->wb_lock);
	return rc;
}

int dpu_wb_drm_deinit(struct dpu_wb_device *wb_dev)
{
	int rc = 0;

	if (!wb_dev) {
		DPU_ERROR("invalid params\n");
		return -EINVAL;
	}

	DPU_DEBUG("\n");

	return rc;
}

/**
 * dpu_wb_probe - load writeback module
 * @pdev:	Pointer to platform device
 */
static int dpu_wb_probe(struct platform_device *pdev)
{
	struct dpu_wb_device *wb_dev;
	int ret;

	wb_dev = devm_kzalloc(&pdev->dev, sizeof(*wb_dev), GFP_KERNEL);
	if (!wb_dev)
		return -ENOMEM;

	DPU_DEBUG("\n");

	ret = of_property_read_u32(pdev->dev.of_node, "cell-index",
			&wb_dev->index);
	if (ret) {
		DPU_DEBUG("cell index not set, default to 0\n");
		wb_dev->index = 0;
	}

	wb_dev->name = of_get_property(pdev->dev.of_node, "label", NULL);
	if (!wb_dev->name) {
		DPU_DEBUG("label not set, default to unknown\n");
		wb_dev->name = "unknown";
	}

	wb_dev->wb_idx = DPU_NONE;

	mutex_init(&wb_dev->wb_lock);
	platform_set_drvdata(pdev, wb_dev);

	mutex_lock(&dpu_wb_list_lock);
	list_add(&wb_dev->wb_list, &dpu_wb_list);
	mutex_unlock(&dpu_wb_list_lock);

	if (!_dpu_wb_dev_init(wb_dev)) {
		ret = component_add(&pdev->dev, &dpu_wb_comp_ops);
		if (ret)
			pr_err("component add failed\n");
	}

	return ret;
}

/**
 * dpu_wb_remove - unload writeback module
 * @pdev:	Pointer to platform device
 */
static int dpu_wb_remove(struct platform_device *pdev)
{
	struct dpu_wb_device *wb_dev;
	struct dpu_wb_device *curr, *next;

	wb_dev = platform_get_drvdata(pdev);
	if (!wb_dev)
		return 0;

	DPU_DEBUG("\n");

	(void)_dpu_wb_dev_deinit(wb_dev);

	mutex_lock(&dpu_wb_list_lock);
	list_for_each_entry_safe(curr, next, &dpu_wb_list, wb_list) {
		if (curr == wb_dev) {
			list_del(&wb_dev->wb_list);
			break;
		}
	}
	mutex_unlock(&dpu_wb_list_lock);

	kfree(wb_dev->modes);
	mutex_destroy(&wb_dev->wb_lock);

	platform_set_drvdata(pdev, NULL);
	devm_kfree(&pdev->dev, wb_dev);

	return 0;
}

static const struct of_device_id dt_match[] = {
	{ .compatible = "qcom,wb-display"},
	{}
};

static struct platform_driver dpu_wb_driver = {
	.probe = dpu_wb_probe,
	.remove = dpu_wb_remove,
	.driver = {
		.name = "dpu_wb",
		.of_match_table = dt_match,
	},
};

static int __init dpu_wb_register(void)
{
	return platform_driver_register(&dpu_wb_driver);
}

static void __exit dpu_wb_unregister(void)
{
	platform_driver_unregister(&dpu_wb_driver);
}

module_init(dpu_wb_register);
module_exit(dpu_wb_unregister);
