// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/of_gpio.h>
#include <linux/of_graph.h>
#include <linux/of_irq.h>
#include <linux/regulator/consumer.h>
#include <drm/drmP.h>
#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_mipi_dsi.h>

struct sn65dsi86_reg_cfg {
	u8 reg;
	u8 val;
	int sleep_in_ms;
};

struct sn65dsi86_video_cfg {
	u32 h_active;
	u32 h_front_porch;
	u32 h_pulse_width;
	u32 h_back_porch;
	bool h_polarity;
	u32 v_active;
	u32 v_front_porch;
	u32 v_pulse_width;
	u32 v_back_porch;
	bool v_polarity;
	u32 pclk_khz;
	u32 num_of_lanes;
};

struct sn65dsi86_gpios {
	u32 irq_gpio;
	u32 enable_gpio;
	u32 i2c_sda;
	u32 i2c_scl;
	u32 panel_bias_en;
	u32 panel_bklt_en;
	u32 panel_bklt_ctrl;
};

struct sn65dsi86_reg_cfg reg_cfg_proto_0[] = {
	{0x5c, 0x01, 0x0},	/* Disable HPD */
	{0x0A, 0x02, 0x0},	/* REFCLK 19.2MHz */
	{0x10, 0x26, 0x14},	/* DSI lanes */
	{0x12, 0x7B, 0x0},	/* DSIA CLK FREQ 309.03MHz */
	{0x5A, 0x05, 0x0},	/* enhanced framing and ASSR */
	{0x93, 0x30, 0x0},	/* 4 DP lanes no SSC */
	{0x94, 0x80, 0x0},	/* HBR */
	{0x0D, 0x01, 0x0},	/* PLL ENABLE */
	{0x95, 0x00, 0x0},	/* POST-Cursor2 0dB */
	{0x64, 0x01, 0x0},	/* WriteDPCD Register 0x0010A in Sink */
	{0x74, 0x00, 0x0},
	{0x75, 0x01, 0x0},
	{0x76, 0x0A, 0x0},
	{0x77, 0x01, 0x0},
	{0x78, 0x81, 0x14},
	{0x96, 0x0A, 0x14},	/* Semi-Auto TRAIN */
	{0x20, 0x70, 0x0},	/* CHA_ACTIVE_LINE_LENGTH */
	{0x21, 0x08, 0x0},
	{0x24, 0xA0, 0x0},	/* CHA_VERTICAL_DISPLAY_SIZE */
	{0x25, 0x05, 0x0},
	{0x2C, 0x20, 0x0},	/* CHA_HSYNC_PULSE_WIDTH */
	{0x2D, 0x80, 0x0},
	{0x30, 0x0A, 0x0},	/* CHA_VSYNC_PULSE_WIDTH */
	{0x31, 0x80, 0x0},
	{0x34, 0x50, 0x0},	/* CHA_HORIZONTAL_BACK_PORCH */
	{0x36, 0x1B, 0x0},	/* CHA_VERTICAL_BACK_PORCH */
	{0x38, 0x30, 0x0},	/* CHA_HORIZONTAL_FRONT_PORCH */
	{0x3A, 0x03, 0x0},	/* CHA_VERTICAL_FRONT_PORCH */
	{0x5B, 0x00, 0x0},	/* DP- 24bpp */
	{0x3C, 0x00, 0x14},	/* COLOR BAR disabled */
	{0x5A, 0x0D, 0x0},	/* Ehnc framing, ASSR, Vstream enable */
};

struct sn65dsi86 {
	struct device *dev;
	struct drm_bridge bridge;
	struct drm_connector connector;

	struct device_node *host_node;
	struct mipi_dsi_device *dsi;

	u8 i2c_addr;
	int irq;

	struct sn65dsi86_gpios gpios;

	unsigned int num_supplies;
	struct regulator_bulk_data *supplies;

	struct i2c_client *i2c_client;

	enum drm_connector_status connector_status;
	bool power_on;

	bool is_pluggable;
	u32 num_of_modes;
	struct list_head mode_list;
	struct edid *edid;

	struct drm_display_mode curr_mode;
	struct sn65dsi86_video_cfg video_cfg;
};

static int sn65dsi86_write(struct sn65dsi86 *pdata, u8 reg, u8 val)
{
	struct i2c_client *client = pdata->i2c_client;
	u8 buf[2] = {reg, val};
	struct i2c_msg msg = {
		.addr = client->addr,
		.flags = 0,
		.len = 2,
		.buf = buf,
	};

	if (i2c_transfer(client->adapter, &msg, 1) < 1) {
		pr_err("i2c write failed\n");
		return -EIO;
	}

	return 0;
}

static int sn65dsi86_read(struct sn65dsi86 *pdata, u8 reg, char *buf, u32 size)
{
	struct i2c_client *client = pdata->i2c_client;
	struct i2c_msg msg[2] = {
		{
			.addr = client->addr,
			.flags = 0,
			.len = 1,
			.buf = &reg,
		},
		{
			.addr = client->addr,
			.flags = I2C_M_RD,
			.len = size,
			.buf = buf,
		}
	};

	if (i2c_transfer(client->adapter, msg, 2) != 2) {
		pr_err("i2c read failed\n");
		return -EIO;
	}

	return 0;
}

static int sn65dsi86_write_array(struct sn65dsi86 *pdata,
	struct sn65dsi86_reg_cfg *cfg, int size)
{
	int ret = 0;
	int i;
	char x;

	size = size / sizeof(struct sn65dsi86_reg_cfg);
	for (i = 0; i < size; i++) {
		ret = sn65dsi86_write(pdata, cfg[i].reg, cfg[i].val);

		if (ret != 0) {
			pr_err("reg writes failed. Last write %02X to %02X\n",
				cfg[i].val, cfg[i].reg);
			goto w_regs_fail;
		}

		if (cfg[i].sleep_in_ms)
			msleep(cfg[i].sleep_in_ms);
	}

	sn65dsi86_read(pdata, 0x0a, &x, 1);
	pr_info("0x0a reg: 0x%02x\n", x);
	sn65dsi86_read(pdata, 0x96, &x, 1);
	pr_info("0x96 reg: 0x%02x\n", x);
	sn65dsi86_read(pdata, 0xf0, &x, 1);
	pr_info("0xf0 reg: 0x%02x\n", x);
	sn65dsi86_read(pdata, 0xf1, &x, 1);
	pr_info("0xf1 reg: 0x%02x\n", x);
	sn65dsi86_read(pdata, 0xf2, &x, 1);
	pr_info("0xf2 reg: 0x%02x\n", x);
	sn65dsi86_read(pdata, 0xf3, &x, 1);
	pr_info("0xf3 reg: 0x%02x\n", x);
	sn65dsi86_read(pdata, 0xf4, &x, 1);
	pr_info("0xf4 reg: 0x%02x\n", x);
	sn65dsi86_read(pdata, 0xf5, &x, 1);
	pr_info("0xf5 reg: 0x%02x\n", x);
	sn65dsi86_read(pdata, 0xf6, &x, 1);
	pr_info("0xf6 reg: 0x%02x\n", x);
	sn65dsi86_read(pdata, 0xf7, &x, 1);
	pr_info("0xf7 reg: 0x%02x\n", x);
	sn65dsi86_read(pdata, 0xf8, &x, 1);
	pr_info("0xf8 reg: 0x%02x\n", x);
	pr_info("clearing out any ECC erorrs\n");
	sn65dsi86_write(pdata, 0xf1, 0xff);

w_regs_fail:
	if (ret != 0)
		pr_err("exiting with ret = %d after %d writes\n", ret, i);

	return ret;
}

static int sn65dsi86_gpio_configure(struct sn65dsi86 *pdata, bool on)
{
	int ret = 0;

	if (on) {
		ret = gpio_request(pdata->gpios.enable_gpio,
			"sn65dsi86-enable-gpio");
		if (ret) {
			pr_err("sn65dsi86 enable gpio request failed\n");
			goto error;
		}

		ret = gpio_direction_output(pdata->gpios.enable_gpio, 1);
		if (ret) {
			pr_err("sn65dsi86 enable gpio direction failed\n");
			goto enable_error;
		}

		if (gpio_is_valid(pdata->gpios.irq_gpio)) {
			ret = gpio_request(pdata->gpios.irq_gpio,
				"sn65dsi86-irq-gpio");
			if (ret) {
				pr_err("sn65dsi86 irq gpio request failed\n");
				goto i2c_scl_error;
			}

			ret = gpio_direction_input(pdata->gpios.irq_gpio);
			if (ret) {
				pr_err("sn65dsi86 irq gpio direction failed\n");
				goto irq_error;
			}
		}

		if (gpio_is_valid(pdata->gpios.panel_bias_en)) {
			ret = gpio_request(pdata->gpios.panel_bias_en,
				"sn65dsi86-panel-bias-gpio");
			if (ret) {
				pr_err("sn65dsi86 bias en request failed\n");
				goto irq_error;
			}

			ret = gpio_direction_output(
					pdata->gpios.panel_bias_en, 1);
			if (ret) {
				pr_err("sn65dsi86 bias en direction failed\n");
				goto panel_bias_error;
			}
		}

		if (gpio_is_valid(pdata->gpios.panel_bklt_en)) {
			ret = gpio_request(pdata->gpios.panel_bklt_en,
				"sn65dsi86-panel-bklt-en");
			if (ret) {
				pr_err("sn65dsi86 bklt en request failed\n");
				goto panel_bias_error;
			}

			ret = gpio_direction_output(
					pdata->gpios.panel_bklt_en, 1);
			if (ret) {
				pr_err("sn65dsi86 bklt en direction failed\n");
				goto panel_bklt_en_error;
			}
		}

		if (gpio_is_valid(pdata->gpios.panel_bklt_ctrl)) {
			ret = gpio_request(pdata->gpios.panel_bklt_ctrl,
				"sn65dsi86-panel-bklt-ctrl");
			if (ret) {
				pr_err("sn65dsi86 bklt ctrl request failed\n");
				goto panel_bklt_en_error;
			}

			ret = gpio_direction_output(
					pdata->gpios.panel_bklt_ctrl, 1);
			if (ret) {
				pr_err("sn65dsi86 bklt ctl direction failed\n");
				goto panel_bklt_ctrl_error;
			}
		}

	} else {
		if (gpio_is_valid(pdata->gpios.panel_bklt_ctrl))
			gpio_free(pdata->gpios.panel_bklt_ctrl);
		if (gpio_is_valid(pdata->gpios.panel_bklt_en))
			gpio_free(pdata->gpios.panel_bklt_en);
		if (gpio_is_valid(pdata->gpios.panel_bias_en))
			gpio_free(pdata->gpios.panel_bias_en);
		if (gpio_is_valid(pdata->gpios.irq_gpio))
			gpio_free(pdata->gpios.irq_gpio);
		gpio_free(pdata->gpios.enable_gpio);
	}

	return ret;

panel_bklt_ctrl_error:
	if (gpio_is_valid(pdata->gpios.panel_bklt_ctrl))
		gpio_free(pdata->gpios.panel_bklt_ctrl);
panel_bklt_en_error:
	if (gpio_is_valid(pdata->gpios.panel_bklt_en))
		gpio_free(pdata->gpios.panel_bklt_en);
panel_bias_error:
	if (gpio_is_valid(pdata->gpios.panel_bias_en))
		gpio_free(pdata->gpios.panel_bias_en);
irq_error:
	if (gpio_is_valid(pdata->gpios.irq_gpio))
		gpio_free(pdata->gpios.irq_gpio);
i2c_scl_error:
	if (gpio_is_valid(pdata->gpios.i2c_scl))
		gpio_free(pdata->gpios.i2c_scl);
enable_error:
	gpio_free(pdata->gpios.enable_gpio);
error:
	return ret;
}

static void sn65dsi86_power_ctrl(struct sn65dsi86 *pdata, bool enable)
{
	if (!pdata)
		return;

	if (!pdata->power_on && enable) {
		if (sn65dsi86_gpio_configure(pdata, true)) {
			pr_err("bridge gpio enable failed\n");
			return;
		}

		if (regulator_bulk_enable(pdata->num_supplies,
						pdata->supplies)) {
			pr_err("bridge regulator enable failed\n");
			return;
		}
		pdata->power_on = true;
	} else if (pdata->power_on && !enable) {
		regulator_bulk_disable(pdata->num_supplies, pdata->supplies);

		sn65dsi86_gpio_configure(pdata, false);
		pdata->power_on = false;
	} else {
		pr_debug("unnecessary call to power control\n");
	}
}

/* Connector funcs */
static struct sn65dsi86 *connector_to_sn65dsi86(struct drm_connector *connector)
{
	return container_of(connector, struct sn65dsi86, connector);
}

static int sn65dsi86_send_aux_cmd(struct sn65dsi86 *pdata,
				  u8 cmd, u8 addr, u8 length, int w_data)
{
	u8 read = 0;
	int retry_cnt = 10;

	sn65dsi86_write(pdata, 0x78, (cmd << 4));	/* AUX_CMD */
	sn65dsi86_write(pdata, 0x76, addr);		/* AUX_ADDR */
	sn65dsi86_write(pdata, 0x77, length);		/* AUX_LENGTH */
	if (w_data >= 0)
		sn65dsi86_write(pdata, 0x64, (u8)w_data);	/* AUX_WDATA0 */

	/* set SEND bit */
	sn65dsi86_read(pdata, 0x78, &read, 1);
	read |= BIT(0);
	sn65dsi86_write(pdata, 0x78, read);

	/* poll for bridge to ack SEND bit */
	while (retry_cnt) {
		sn65dsi86_read(pdata, 0x78, &read, 0x1);
		if (!(read & BIT(0)))
			break;
		retry_cnt--;
		udelay(1000);
	}

	if (!retry_cnt) {
		pr_err("aux_cmd transfer failed\n");
		return -EINVAL;
	}
	return 0;
}

static int sn65dsi86_read_edid(struct sn65dsi86 *pdata, u8 *buf)
{
	int i = 0;
	u8 addr = 0x79;	/* AUX_RDATA0 */
	u8 *data = buf;

	if (!data)
		return -ENOMEM;

	if (sn65dsi86_send_aux_cmd(pdata, 0x4, 0x50, 0x0, -1) ||
		sn65dsi86_send_aux_cmd(pdata, 0x4, 0x50, 0x01, 0x0) ||
		sn65dsi86_send_aux_cmd(pdata, 0x5, 0x50, 0x0, -1) ||
		sn65dsi86_send_aux_cmd(pdata, 0x5, 0x50, 0x10, -1))
		goto error;

	for (i = 0; i < 16; i++) {
		if (sn65dsi86_read(pdata, addr, data, 0x1))
			goto error;
		addr++;
		data++;
	}

	return 0;
error:
	pr_err("edid read over i2c failed\n");
	return -EINVAL;
}

static int sn65dsi86_read_edid_block(struct sn65dsi86 *pdata,
			       u8 *buf, unsigned int block)
{
	if (block == 0) {
		if (sn65dsi86_read_edid(pdata, buf))
			goto error;
	} else if (block == 1) {
		/* move segment pointer */
		if (sn65dsi86_send_aux_cmd(pdata, 0x4, 0x30, 0x0, -1) ||
			sn65dsi86_send_aux_cmd(pdata, 0x4, 0x30, 0x01, 0x1) ||
			sn65dsi86_send_aux_cmd(pdata, 0x0, 0x30, 0x00, -1))
			goto error;
		else
			if (sn65dsi86_read_edid(pdata, buf))
				goto error;
	} else {
		pr_debug("unsupported edid block\n");
		goto error;
	}

	return 0;
error:
	pr_err("edid block read failed\n");
	return -EINVAL;
}

static int sn65dsi86_get_edid_block(void *data, u8 *buf, unsigned int block,
				  size_t len)
{
	struct sn65dsi86 *pdata = data;
	int ret = 0;

	pr_debug("get edid block: block=%d, len=%d\n", block, (int)len);

	if (len > 128 || block > 1)
		return -EINVAL;

	ret = sn65dsi86_read_edid_block(pdata, buf, block);
	if (ret) {
		pr_err("edid read failed for block: %d ret: %d\n", block, ret);
		return ret;
	}

	return 0;
}

static int sn65dsi86_connector_get_modes(struct drm_connector *connector)
{
	struct sn65dsi86 *pdata = connector_to_sn65dsi86(connector);
	struct drm_display_mode *mode, *m;

	if (pdata->edid)
		return drm_add_edid_modes(connector, pdata->edid);

	if (pdata->is_pluggable) {
		pdata->edid = drm_do_get_edid(connector,
				sn65dsi86_get_edid_block, pdata);

		drm_mode_connector_update_edid_property(connector, pdata->edid);
		pdata->num_of_modes = drm_add_edid_modes(connector,
								pdata->edid);
	}

	if (!pdata->is_pluggable || !pdata->num_of_modes) {
		/*
		 * if device does not support HPD or due to some reason
		 * EDID read failed then fall back to mode_list which is
		 * already parsed from dt.
		 */
		list_for_each_entry(mode, &pdata->mode_list, head) {
			m = drm_mode_duplicate(connector->dev, mode);
			if (!m) {
				pr_err("failed to get mode %dx%d\n",
					mode->hdisplay, mode->vdisplay);
				break;
			}
			drm_mode_probed_add(connector, m);
		}
	}

	return pdata->num_of_modes;
}

static enum drm_mode_status
sn65dsi86_connector_mode_valid(struct drm_connector *connector,
			     struct drm_display_mode *mode)
{
	struct sn65dsi86 *pdata = connector_to_sn65dsi86(connector);
	struct drm_display_mode *m;

	if (pdata->edid)
		return MODE_OK;

	if (!pdata->is_pluggable) {
		list_for_each_entry(m, &pdata->mode_list, head) {
			if (m->hdisplay == mode->hdisplay &&
				m->vdisplay == mode->vdisplay)
				return MODE_OK;
		}
	}

	return MODE_BAD;
}

static struct drm_connector_helper_funcs sn65dsi86_connector_helper_funcs = {
	.get_modes = sn65dsi86_connector_get_modes,
	.mode_valid = sn65dsi86_connector_mode_valid,
};

static enum drm_connector_status
sn65dsi86_connector_detect(struct drm_connector *connector, bool force)
{
	struct sn65dsi86 *pdata = connector_to_sn65dsi86(connector);

	pdata->connector_status = pdata->power_on ?
		connector_status_connected : connector_status_disconnected;

	return pdata->connector_status;
}

static const struct drm_connector_funcs sn65dsi86_connector_funcs = {
	.fill_modes = drm_helper_probe_single_connector_modes,
	.detect = sn65dsi86_connector_detect,
	.destroy = drm_connector_cleanup,
	.reset = drm_atomic_helper_connector_reset,
	.atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_connector_destroy_state,
};

static struct sn65dsi86 *bridge_to_sn65dsi86(struct drm_bridge *bridge)
{
	return container_of(bridge, struct sn65dsi86, bridge);
}

static int sn65dsi86_read_device_rev(struct sn65dsi86 *pdata)
{
	u8 rev = 0;
	int ret = 0;

	ret = sn65dsi86_read(pdata, 0x08, &rev, 1);

	if (!ret) {
		if (rev == 0x2) {
			pr_info("SN65DSI86 revision id: 0x%x\n", rev);
		} else {
			pr_warn("SN65DSI86 revision id mismatch\n");
			ret = -EINVAL;
		}
	}

	return ret;
}

static irqreturn_t sn65dsi86_irq_thread_handler(int irq, void *dev_id)
{
	return IRQ_HANDLED;
}

static const char * const sn65dsi86_supply_names[] = {
	"vcca",
};

static int sn65dsi86_init_regulators(struct sn65dsi86 *pdata)
{
	const char * const *supply_names;
	unsigned int i;
	int ret;

	supply_names = sn65dsi86_supply_names;
	pdata->num_supplies = ARRAY_SIZE(sn65dsi86_supply_names);

	pdata->supplies = devm_kcalloc(pdata->dev, pdata->num_supplies,
				     sizeof(*pdata->supplies), GFP_KERNEL);
	if (!pdata->supplies)
		return -ENOMEM;

	for (i = 0; i < pdata->num_supplies; i++)
		pdata->supplies[i].supply = supply_names[i];

	ret = devm_regulator_bulk_get(pdata->dev,
			pdata->num_supplies, pdata->supplies);
	if (ret)
		return ret;

	regulator_set_load(pdata->supplies[0].consumer, 300000);
	return regulator_bulk_enable(pdata->num_supplies, pdata->supplies);
}

static int sn65dsi86_bridge_attach(struct drm_bridge *bridge)
{
	struct mipi_dsi_host *host;
	struct mipi_dsi_device *dsi;
	struct sn65dsi86 *pdata = bridge_to_sn65dsi86(bridge);
	int ret;
	const struct mipi_dsi_device_info info = { .type = "sn65dsi86",
						   .channel = 0,
						   .node = NULL,
						 };

	if (!bridge->encoder) {
		DRM_ERROR("Parent encoder object not found");
		return -ENODEV;
	}

	/* No HPD */
	pdata->connector.polled = 0;

	ret = drm_connector_init(bridge->dev, &pdata->connector,
				 &sn65dsi86_connector_funcs,
				 DRM_MODE_CONNECTOR_eDP);
	if (ret) {
		DRM_ERROR("Failed to initialize connector with drm\n");
		return ret;
	}

	drm_connector_helper_add(&pdata->connector,
				 &sn65dsi86_connector_helper_funcs);
	drm_mode_connector_attach_encoder(&pdata->connector, bridge->encoder);

	host = of_find_mipi_dsi_host_by_node(pdata->host_node);
	if (!host) {
		pr_err("failed to find dsi host\n");
		return -ENODEV;
	}

	dsi = mipi_dsi_device_register_full(host, &info);
	if (IS_ERR(dsi)) {
		pr_err("failed to create dsi device\n");
		ret = PTR_ERR(dsi);
		goto err_dsi_device;
	}

	/* setting to 4 lanes always for now */
	dsi->lanes = 4;
	dsi->format = MIPI_DSI_FMT_RGB888;
	dsi->mode_flags = MIPI_DSI_MODE_VIDEO | MIPI_DSI_MODE_VIDEO_SYNC_PULSE |
			  MIPI_DSI_MODE_EOT_PACKET | MIPI_DSI_MODE_VIDEO_HSE;

	ret = mipi_dsi_attach(dsi);
	if (ret < 0) {
		pr_err("failed to attach dsi to host\n");
		goto err_dsi_attach;
	}

	pdata->dsi = dsi;

	pr_debug("bridge attached\n");

	return 0;

err_dsi_attach:
	mipi_dsi_device_unregister(dsi);
err_dsi_device:
	return ret;
}

static void sn65dsi86_set_video_cfg(struct sn65dsi86 *pdata,
	struct drm_display_mode *mode,
	struct sn65dsi86_video_cfg *video_cfg)
{
	video_cfg->h_active = mode->hdisplay;
	video_cfg->v_active = mode->vdisplay;
	video_cfg->h_front_porch = mode->hsync_start - mode->hdisplay;
	video_cfg->v_front_porch = mode->vsync_start - mode->vdisplay;
	video_cfg->h_back_porch = mode->htotal - mode->hsync_end;
	video_cfg->v_back_porch = mode->vtotal - mode->vsync_end;
	video_cfg->h_pulse_width = mode->hsync_end - mode->hsync_start;
	video_cfg->v_pulse_width = mode->vsync_end - mode->vsync_start;
	video_cfg->pclk_khz = mode->clock;

	video_cfg->h_polarity = !!(mode->flags & DRM_MODE_FLAG_PHSYNC);
	video_cfg->v_polarity = !!(mode->flags & DRM_MODE_FLAG_PVSYNC);

	/* setting to 4 lanes always for now */
	video_cfg->num_of_lanes = 4;

	pr_debug("video=h[%d,%d,%d,%d] v[%d,%d,%d,%d] pclk=%d lane=%d\n",
		video_cfg->h_active, video_cfg->h_front_porch,
		video_cfg->h_pulse_width, video_cfg->h_back_porch,
		video_cfg->v_active, video_cfg->v_front_porch,
		video_cfg->v_pulse_width, video_cfg->v_back_porch,
		video_cfg->pclk_khz, video_cfg->num_of_lanes);
}

static void sn65dsi86_bridge_mode_set(struct drm_bridge *bridge,
				    struct drm_display_mode *mode,
				    struct drm_display_mode *adj_mode)
{
	struct sn65dsi86 *pdata = bridge_to_sn65dsi86(bridge);
	struct sn65dsi86_video_cfg *video_cfg = &pdata->video_cfg;
	int ret = 0;

	pr_debug("bridge mode_set: hdisplay=%d, vdisplay=%d, vrefresh=%d, clock=%d\n",
		adj_mode->hdisplay, adj_mode->vdisplay,
		adj_mode->vrefresh, adj_mode->clock);

	drm_mode_copy(&pdata->curr_mode, adj_mode);

	memset(video_cfg, 0, sizeof(struct sn65dsi86_video_cfg));
	sn65dsi86_set_video_cfg(pdata, adj_mode, video_cfg);

	if (video_cfg->num_of_lanes != pdata->dsi->lanes) {
		mipi_dsi_detach(pdata->dsi);
		pdata->dsi->lanes = video_cfg->num_of_lanes;
		ret = mipi_dsi_attach(pdata->dsi);
		if (ret)
			pr_err("failed to change host lanes\n");
	}
}

static void sn65dsi86_bridge_disable(struct drm_bridge *bridge)
{
	struct sn65dsi86 *pdata = bridge_to_sn65dsi86(bridge);

	sn65dsi86_power_ctrl(pdata, false);

	pdata->connector_status =  connector_status_disconnected;
}

static void sn65dsi86_bridge_pre_enable(struct drm_bridge *bridge)
{
	struct sn65dsi86 *pdata = bridge_to_sn65dsi86(bridge);

	sn65dsi86_power_ctrl(pdata, true);
}

static void sn65dsi86_bridge_enable(struct drm_bridge *bridge)
{
	struct sn65dsi86 *pdata = bridge_to_sn65dsi86(bridge);

	sn65dsi86_write_array(pdata, reg_cfg_proto_0, sizeof(reg_cfg_proto_0));
}

static const struct drm_bridge_funcs sn65dsi86_bridge_funcs = {
	.attach = sn65dsi86_bridge_attach,
	.pre_enable = sn65dsi86_bridge_pre_enable,
	.enable = sn65dsi86_bridge_enable,
	.disable = sn65dsi86_bridge_disable,
	.mode_set = sn65dsi86_bridge_mode_set,
};

static int sn65dsi86_parse_dt_modes(struct device_node *np,
					struct list_head *head,
					u32 *num_of_modes)
{
	int rc = 0;
	struct drm_display_mode *mode;
	u32 mode_count = 0;
	struct device_node *node = NULL;
	struct device_node *root_node = NULL;
	u32 h_front_porch, h_pulse_width, h_back_porch;
	u32 v_front_porch, v_pulse_width, v_back_porch;
	bool h_active_high, v_active_high;
	u32 flags = 0;

	root_node = of_get_child_by_name(np, "sn,custom-modes");
	if (!root_node) {
		root_node = of_parse_phandle(np, "sn,custom-modes", 0);
		if (!root_node) {
			pr_info("No modes present for sn,custom-modes");
			goto end;
		}
	}

	for_each_child_of_node(root_node, node) {
		rc = 0;
		mode = kzalloc(sizeof(*mode), GFP_KERNEL);
		if (!mode) {
			rc =  -ENOMEM;
			goto end;
		}

		of_property_read_u32(node, "sn,mode-h-active",
						&mode->hdisplay);

		of_property_read_u32(node, "sn,mode-h-front-porch",
						&h_front_porch);
		of_property_read_u32(node, "sn,mode-h-pulse-width",
						&h_pulse_width);

		of_property_read_u32(node, "sn,mode-h-back-porch",
						&h_back_porch);

		h_active_high = of_property_read_bool(node,
						"sn,mode-h-active-high");

		of_property_read_u32(node, "sn,mode-v-active",
						&mode->vdisplay);
		of_property_read_u32(node, "sn,mode-v-front-porch",
						&v_front_porch);

		of_property_read_u32(node, "sn,mode-v-pulse-width",
						&v_pulse_width);
		of_property_read_u32(node, "sn,mode-v-back-porch",
						&v_back_porch);
		v_active_high = of_property_read_bool(node,
						"sn,mode-v-active-high");

		of_property_read_u32(node, "sn,mode-refresh-rate",
						&mode->vrefresh);

		of_property_read_u32(node, "sn,mode-clock-in-khz",
						&mode->clock);

		mode->hsync_start = mode->hdisplay + h_front_porch;
		mode->hsync_end = mode->hsync_start + h_pulse_width;
		mode->htotal = mode->hsync_end + h_back_porch;
		mode->vsync_start = mode->vdisplay + v_front_porch;
		mode->vsync_end = mode->vsync_start + v_pulse_width;
		mode->vtotal = mode->vsync_end + v_back_porch;

		if (!mode->htotal || !mode->vtotal) {
			rc = -EINVAL;
			goto fail;
		}

		if (h_active_high)
			flags |= DRM_MODE_FLAG_PHSYNC;
		else
			flags |= DRM_MODE_FLAG_NHSYNC;
		if (v_active_high)
			flags |= DRM_MODE_FLAG_PVSYNC;
		else
			flags |= DRM_MODE_FLAG_NVSYNC;
		mode->flags = flags;

		if (!rc) {
			mode_count++;
			list_add_tail(&mode->head, head);
		}

		drm_mode_set_name(mode);

		pr_debug("mode[%s] h[%d,%d,%d,%d] v[%d,%d,%d,%d] %d %x %dkHZ\n",
			mode->name, mode->hdisplay, mode->hsync_start,
			mode->hsync_end, mode->htotal, mode->vdisplay,
			mode->vsync_start, mode->vsync_end, mode->vtotal,
			mode->vrefresh, mode->flags, mode->clock);
fail:
		if (rc) {
			kfree(mode);
			continue;
		}
	}

	if (num_of_modes)
		*num_of_modes = mode_count;

end:
	return rc;
}

static int sn65dsi86_parse_gpios(struct device_node *np,
					struct sn65dsi86 *pdata)
{
	int ret = 0;

	pdata->gpios.irq_gpio =
		of_get_named_gpio(np, "sn,irq-gpio", 0);
	if (!gpio_is_valid(pdata->gpios.irq_gpio)) {
		pr_err("irq gpio not specified\n");
		ret = -EINVAL;
		goto exit;
	}

	pdata->gpios.enable_gpio =
		of_get_named_gpio(np, "sn,enable-gpio", 0);
	if (!gpio_is_valid(pdata->gpios.enable_gpio)) {
		pr_err("enable gpio not specified\n");
		ret = -EINVAL;
		goto exit;
	}

	pdata->gpios.panel_bias_en =
		of_get_named_gpio(np, "sn,panel-bias-en", 0);
	if (!gpio_is_valid(pdata->gpios.panel_bias_en)) {
		pr_err("panel bias gpio not specified\n");
		ret = -EINVAL;
		goto exit;
	}

	pdata->gpios.panel_bklt_en =
		of_get_named_gpio(np, "sn,panel-bklt-en", 0);
	if (!gpio_is_valid(pdata->gpios.panel_bklt_en)) {
		pr_err("panel bklt en gpio not specified\n");
		ret = -EINVAL;
		goto exit;
	}

	pdata->gpios.panel_bklt_ctrl =
		of_get_named_gpio(np, "sn,panel-bklt-ctrl", 0);
	if (!gpio_is_valid(pdata->gpios.panel_bklt_ctrl)) {
		pr_err("panel bklt ctrl gpio not specified\n");
		ret = -EINVAL;
		goto exit;
	}

exit:
	return ret;
}

static int sn65dsi86_parse_dt(struct device *dev, struct sn65dsi86 *pdata)
{
	struct device_node *np = dev->of_node;
	struct device_node *end_node;
	int ret = 0;

	end_node = of_graph_get_endpoint_by_regs(np, 0, 0);
	if (!end_node) {
		pr_err("remote endpoint not found\n");
		return -ENODEV;
	}

	pdata->host_node = of_graph_get_remote_port_parent(end_node);
	of_node_put(end_node);
	if (!pdata->host_node) {
		pr_err("remote node not found\n");
		return -ENODEV;
	}
	of_node_put(pdata->host_node);

	ret = sn65dsi86_parse_gpios(np, pdata);

	pdata->is_pluggable = of_property_read_bool(np, "sn,is-pluggable");
	pr_debug("is_pluggable = %d\n", pdata->is_pluggable);
	if (!pdata->is_pluggable) {
		INIT_LIST_HEAD(&pdata->mode_list);
		sn65dsi86_parse_dt_modes(np,
			&pdata->mode_list, &pdata->num_of_modes);
	}

	return ret;
}

static int sn65dsi86_probe(struct i2c_client *client,
	 const struct i2c_device_id *id)
{
	struct sn65dsi86 *pdata;
	int ret = 0;
	struct drm_display_mode *mode, *n;

	if (!client || !client->dev.of_node) {
		pr_err("invalid input\n");
		return -EINVAL;
	}

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		pr_err("device doesn't support I2C\n");
		return -ENODEV;
	}

	pdata = devm_kzalloc(&client->dev,
		sizeof(struct sn65dsi86), GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;

	pdata->power_on = false;
	pdata->is_pluggable = false;
	pdata->connector_status = connector_status_disconnected;
	pdata->dev = &client->dev;
	pdata->i2c_client = client;
	pr_debug("I2C address is %x\n", client->addr);

	ret = sn65dsi86_parse_dt(&client->dev, pdata);
	if (ret) {
		pr_err("failed to parse device tree\n");
		goto err_dt_parse;
	}

	ret = sn65dsi86_gpio_configure(pdata, true);
	if (ret) {
		pr_err("failed to configure GPIOs\n");
		goto err_gpio_config;
	}

	ret = sn65dsi86_init_regulators(pdata);
	if (ret) {
		pr_err("failed to enable regulators\n");
		goto err_gpio_config;
	}

	ret = sn65dsi86_read_device_rev(pdata);
	if (ret) {
		pr_err("failed to read chip rev\n");
		goto err_gpio_config;
	} else {
		pr_err("bridge chip enabled successfully\n");
		pdata->power_on = true;
	}

	pdata->irq = gpio_to_irq(pdata->gpios.irq_gpio);
	ret = request_threaded_irq(pdata->irq, NULL,
			sn65dsi86_irq_thread_handler,
			IRQF_TRIGGER_FALLING | IRQF_ONESHOT,
			"sn65dsi86", pdata);

	i2c_set_clientdata(client, pdata);
	dev_set_drvdata(&client->dev, pdata);

	/*
	 * power down the bridge chip until
	 * drm bridge enable or drm get modes APIs
	 * are invoked.
	 *
	 * sn65dsi86_power_ctrl(pdata, false);
	 */

	pdata->bridge.funcs = &sn65dsi86_bridge_funcs;
	pdata->bridge.of_node = client->dev.of_node;

	drm_bridge_add(&pdata->bridge);

	return ret;

err_gpio_config:
	sn65dsi86_gpio_configure(pdata, false);
err_dt_parse:
	if (!pdata->is_pluggable) {
		list_for_each_entry_safe(mode, n, &pdata->mode_list, head) {
			list_del(&mode->head);
			kfree(mode);
		}
		pdata->num_of_modes = 0;
	}
	devm_kfree(&client->dev, pdata);
	return ret;
}

static int sn65dsi86_remove(struct i2c_client *client)
{
	int ret = -EINVAL;
	struct sn65dsi86 *pdata = i2c_get_clientdata(client);
	struct drm_display_mode *mode, *n;

	if (!pdata)
		goto end;

	mipi_dsi_detach(pdata->dsi);
	mipi_dsi_device_unregister(pdata->dsi);

	drm_bridge_remove(&pdata->bridge);

	disable_irq(pdata->irq);
	free_irq(pdata->irq, pdata);

	ret = sn65dsi86_gpio_configure(pdata, false);

	if (!pdata->is_pluggable) {
		list_for_each_entry_safe(mode, n, &pdata->mode_list, head) {
			list_del(&mode->head);
			kfree(mode);
		}
	}

	devm_kfree(&client->dev, pdata);

end:
	return ret;
}

static struct i2c_device_id sn65dsi86_id[] = {
	{ "ti,sn65dsi86", 0},
	{}
};
MODULE_DEVICE_TABLE(i2c, sn65dsi86_id);

static const struct of_device_id sn65dsi86_match_table[] = {
	{.compatible = "ti,sn65dsi86"},
	{}
};
MODULE_DEVICE_TABLE(of, sn65dsi86_match_table);

static struct i2c_driver sn65dsi86_driver = {
	.driver = {
		.name = "sn65dsi86",
		.owner = THIS_MODULE,
		.of_match_table = sn65dsi86_match_table,
	},
	.probe = sn65dsi86_probe,
	.remove = sn65dsi86_remove,
	.id_table = sn65dsi86_id,
};

module_i2c_driver(sn65dsi86_driver);
MODULE_DESCRIPTION("SN65DSI86 DSI to eDP bridge driver");
