/*
 * Copyright (c) 2015-2018 The Linux Foundation. All rights reserved.
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
#include <linux/debugfs.h>
#include <uapi/drm/dpu_drm.h>

#include "dpu_encoder_phys.h"
#include "dpu_formats.h"
#include "dpu_hw_top.h"
#include "dpu_hw_interrupts.h"
#include "dpu_core_irq.h"
#include "dpu_wb.h"
#include "dpu_vbif.h"
#include "dpu_crtc.h"

#define to_dpu_encoder_phys_wb(x) \
	container_of(x, struct dpu_encoder_phys_wb, base)

#define WBID(wb_enc) ((wb_enc) ? wb_enc->wb_dev->wb_idx : -1)

#define TO_S15D16(_x_)	((_x_) << 7)

/**
 * dpu_rgb2yuv_601l - rgb to yuv color space conversion matrix
 *
 */
static struct dpu_csc_cfg dpu_encoder_phys_wb_rgb2yuv_601l = {
	{
		TO_S15D16(0x0083), TO_S15D16(0x0102), TO_S15D16(0x0032),
		TO_S15D16(0x1fb5), TO_S15D16(0x1f6c), TO_S15D16(0x00e1),
		TO_S15D16(0x00e1), TO_S15D16(0x1f45), TO_S15D16(0x1fdc)
	},
	{ 0x00, 0x00, 0x00 },
	{ 0x0040, 0x0200, 0x0200 },
	{ 0x000, 0x3ff, 0x000, 0x3ff, 0x000, 0x3ff },
	{ 0x040, 0x3ac, 0x040, 0x3c0, 0x040, 0x3c0 },
};

/**
 * dpu_encoder_phys_wb_is_master - report wb always as master encoder
 */
static bool dpu_encoder_phys_wb_is_master(struct dpu_encoder_phys *phys_enc)
{
	return true;
}

/**
 * dpu_encoder_phys_wb_get_intr_type - get interrupt type based on block mode
 * @hw_wb:	Pointer to h/w writeback driver
 */
static enum dpu_intr_type dpu_encoder_phys_wb_get_intr_type(
		struct dpu_hw_wb *hw_wb)
{
	return (hw_wb->caps->features & BIT(DPU_WB_BLOCK_MODE)) ?
			DPU_IRQ_TYPE_WB_ROT_COMP : DPU_IRQ_TYPE_WB_WFD_COMP;
}

/**
 * dpu_encoder_phys_wb_set_ot_limit - set OT limit for writeback interface
 * @phys_enc:	Pointer to physical encoder
 */
static void dpu_encoder_phys_wb_set_ot_limit(
		struct dpu_encoder_phys *phys_enc)
{
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);
	struct dpu_hw_wb *hw_wb = wb_enc->hw_wb;
	struct dpu_vbif_set_ot_params ot_params;

	memset(&ot_params, 0, sizeof(ot_params));
	ot_params.xin_id = hw_wb->caps->xin_id;
	ot_params.num = hw_wb->idx - WB_0;
	ot_params.width = wb_enc->wb_roi.w;
	ot_params.height = wb_enc->wb_roi.h;
	ot_params.is_wfd = true;
	ot_params.frame_rate = phys_enc->cached_mode.vrefresh;
	ot_params.vbif_idx = hw_wb->caps->vbif_idx;
	ot_params.clk_ctrl = hw_wb->caps->clk_ctrl;
	ot_params.rd = false;

	dpu_vbif_set_ot_limit(phys_enc->dpu_kms, &ot_params);
}

/**
 * dpu_encoder_phys_wb_set_traffic_shaper - set traffic shaper for writeback
 * @phys_enc:	Pointer to physical encoder
 */
static void dpu_encoder_phys_wb_set_traffic_shaper(
		struct dpu_encoder_phys *phys_enc)
{
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);
	struct dpu_hw_wb_cfg *wb_cfg = &wb_enc->wb_cfg;

	/* traffic shaper is only enabled for rotator */
	wb_cfg->ts_cfg.en = false;
}

/**
 * dpu_encoder_phys_wb_set_qos_remap - set QoS remapper for writeback
 * @phys_enc:	Pointer to physical encoder
 */
static void dpu_encoder_phys_wb_set_qos_remap(
		struct dpu_encoder_phys *phys_enc)
{
	struct dpu_encoder_phys_wb *wb_enc;
	struct dpu_hw_wb *hw_wb;
	struct drm_crtc *crtc;
	struct dpu_vbif_set_qos_params qos_params;

	if (!phys_enc || !phys_enc->parent || !phys_enc->parent->crtc) {
		DPU_ERROR("invalid arguments\n");
		return;
	}

	wb_enc = to_dpu_encoder_phys_wb(phys_enc);
	crtc = phys_enc->parent->crtc;

	if (!wb_enc->hw_wb || !wb_enc->hw_wb->caps) {
		DPU_ERROR("invalid writeback hardware\n");
		return;
	}

	hw_wb = wb_enc->hw_wb;

	memset(&qos_params, 0, sizeof(qos_params));
	qos_params.vbif_idx = hw_wb->caps->vbif_idx;
	qos_params.xin_id = hw_wb->caps->xin_id;
	qos_params.clk_ctrl = hw_wb->caps->clk_ctrl;
	qos_params.num = hw_wb->idx - WB_0;
	qos_params.is_rt = dpu_crtc_get_client_type(crtc) != NRT_CLIENT;

	DPU_DEBUG("[qos_remap] wb:%d vbif:%d xin:%d rt:%d\n",
			qos_params.num,
			qos_params.vbif_idx,
			qos_params.xin_id, qos_params.is_rt);

	dpu_vbif_set_qos_remap(phys_enc->dpu_kms, &qos_params);
}

/**
 * dpu_encoder_phys_setup_cdm - setup chroma down block
 * @phys_enc:	Pointer to physical encoder
 * @fb:		Pointer to output framebuffer
 * @format:	Output format
 */
void dpu_encoder_phys_setup_cdm(struct dpu_encoder_phys *phys_enc,
		struct drm_framebuffer *fb, const struct dpu_format *format,
		struct dpu_rect *wb_roi)
{
	struct dpu_hw_cdm *hw_cdm;
	struct dpu_hw_cdm_cfg *cdm_cfg;
	int ret;

	if (!phys_enc || !format)
		return;

	cdm_cfg = &phys_enc->cdm_cfg;
	hw_cdm = phys_enc->hw_cdm;
	if (!hw_cdm)
		return;

	if (!DPU_FORMAT_IS_YUV(format)) {
		DPU_DEBUG("[cdm_disable fmt:%x]\n",
				format->base.pixel_format);

		if (hw_cdm && hw_cdm->ops.disable)
			hw_cdm->ops.disable(hw_cdm);

		return;
	}

	memset(cdm_cfg, 0, sizeof(struct dpu_hw_cdm_cfg));

	if (!wb_roi)
		return;

	cdm_cfg->output_width = wb_roi->w;
	cdm_cfg->output_height = wb_roi->h;
	cdm_cfg->output_fmt = format;
	cdm_cfg->output_type = CDM_CDWN_OUTPUT_WB;
	cdm_cfg->output_bit_depth = DPU_FORMAT_IS_DX(format) ?
		CDM_CDWN_OUTPUT_10BIT : CDM_CDWN_OUTPUT_8BIT;

	/* enable 10 bit logic */
	switch (cdm_cfg->output_fmt->chroma_sample) {
	case DPU_CHROMA_RGB:
		cdm_cfg->h_cdwn_type = CDM_CDWN_DISABLE;
		cdm_cfg->v_cdwn_type = CDM_CDWN_DISABLE;
		break;
	case DPU_CHROMA_H2V1:
		cdm_cfg->h_cdwn_type = CDM_CDWN_COSITE;
		cdm_cfg->v_cdwn_type = CDM_CDWN_DISABLE;
		break;
	case DPU_CHROMA_420:
		cdm_cfg->h_cdwn_type = CDM_CDWN_COSITE;
		cdm_cfg->v_cdwn_type = CDM_CDWN_OFFSITE;
		break;
	case DPU_CHROMA_H1V2:
	default:
		DPU_ERROR("unsupported chroma sampling type\n");
		cdm_cfg->h_cdwn_type = CDM_CDWN_DISABLE;
		cdm_cfg->v_cdwn_type = CDM_CDWN_DISABLE;
		break;
	}

	DPU_DEBUG("[cdm_enable:%d,%d,%X,%d,%d,%d,%d]\n",
			cdm_cfg->output_width,
			cdm_cfg->output_height,
			cdm_cfg->output_fmt->base.pixel_format,
			cdm_cfg->output_type,
			cdm_cfg->output_bit_depth,
			cdm_cfg->h_cdwn_type,
			cdm_cfg->v_cdwn_type);

	if (hw_cdm && hw_cdm->ops.setup_csc_data) {
		ret = hw_cdm->ops.setup_csc_data(hw_cdm,
				&dpu_encoder_phys_wb_rgb2yuv_601l);
		if (ret < 0) {
			DPU_ERROR("failed to setup CSC %d\n", ret);
			return;
		}
	}

	if (hw_cdm && hw_cdm->ops.setup_cdwn) {
		ret = hw_cdm->ops.setup_cdwn(hw_cdm, cdm_cfg);
		if (ret < 0) {
			DPU_ERROR("failed to setup CDM %d\n", ret);
			return;
		}
	}

	if (hw_cdm && hw_cdm->ops.enable) {
		ret = hw_cdm->ops.enable(hw_cdm, cdm_cfg);
		if (ret < 0) {
			DPU_ERROR("failed to enable CDM %d\n", ret);
			return;
		}
	}
}

/**
 * dpu_encoder_phys_wb_setup_fb - setup output framebuffer
 * @phys_enc:	Pointer to physical encoder
 * @fb:		Pointer to output framebuffer
 * @wb_roi:	Pointer to output region of interest
 */
static void dpu_encoder_phys_wb_setup_fb(struct dpu_encoder_phys *phys_enc,
		struct drm_framebuffer *fb, struct dpu_rect *wb_roi)
{
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);
	struct dpu_hw_wb *hw_wb;
	struct dpu_hw_wb_cfg *wb_cfg;
	struct dpu_hw_wb_cdp_cfg *cdp_cfg;
	const struct msm_format *format;
	int ret;
	struct msm_gem_address_space *aspace;

	if (!phys_enc || !phys_enc->dpu_kms || !phys_enc->dpu_kms->catalog ||
			!phys_enc->connector) {
		DPU_ERROR("invalid encoder\n");
		return;
	}

	hw_wb = wb_enc->hw_wb;
	wb_cfg = &wb_enc->wb_cfg;
	cdp_cfg = &wb_enc->cdp_cfg;
	memset(wb_cfg, 0, sizeof(struct dpu_hw_wb_cfg));

	wb_cfg->intf_mode = phys_enc->intf_mode;

	aspace = phys_enc->dpu_kms->base.aspace;

	ret = msm_framebuffer_prepare(fb, aspace);
	if (ret) {
		DPU_ERROR("prep fb failed, %d\n", ret);
		return;
	}

	/* cache framebuffer for cleanup in writeback done */
	wb_enc->wb_fb = fb;

	format = msm_framebuffer_format(fb);
	if (!format) {
		DPU_DEBUG("invalid format for fb\n");
		return;
	}

	wb_cfg->dest.format = dpu_get_dpu_format_ext(
			format->pixel_format,
			fb->modifier);
	if (!wb_cfg->dest.format) {
		/* this error should be detected during atomic_check */
		DPU_ERROR("failed to get format %x\n", format->pixel_format);
		return;
	}
	wb_cfg->roi = *wb_roi;

	if (hw_wb->caps->features & BIT(DPU_WB_XY_ROI_OFFSET)) {
		ret = dpu_format_populate_layout(aspace, fb, &wb_cfg->dest);
		if (ret) {
			DPU_DEBUG("failed to populate layout %d\n", ret);
			return;
		}
		wb_cfg->dest.width = fb->width;
		wb_cfg->dest.height = fb->height;
		wb_cfg->dest.num_planes = wb_cfg->dest.format->num_planes;
	} else {
		ret = dpu_format_populate_layout_with_roi(aspace, fb, wb_roi,
			&wb_cfg->dest);
		if (ret) {
			/* this error should be detected during atomic_check */
			DPU_DEBUG("failed to populate layout %d\n", ret);
			return;
		}
	}

	if ((wb_cfg->dest.format->fetch_planes == DPU_PLANE_PLANAR) &&
			(wb_cfg->dest.format->element[0] == C1_B_Cb))
		swap(wb_cfg->dest.plane_addr[1], wb_cfg->dest.plane_addr[2]);

	DPU_DEBUG("[fb_offset:%8.8x,%8.8x,%8.8x,%8.8x]\n",
			wb_cfg->dest.plane_addr[0],
			wb_cfg->dest.plane_addr[1],
			wb_cfg->dest.plane_addr[2],
			wb_cfg->dest.plane_addr[3]);
	DPU_DEBUG("[fb_stride:%8.8x,%8.8x,%8.8x,%8.8x]\n",
			wb_cfg->dest.plane_pitch[0],
			wb_cfg->dest.plane_pitch[1],
			wb_cfg->dest.plane_pitch[2],
			wb_cfg->dest.plane_pitch[3]);

	if (hw_wb->ops.setup_roi)
		hw_wb->ops.setup_roi(hw_wb, wb_cfg);

	if (hw_wb->ops.setup_outformat)
		hw_wb->ops.setup_outformat(hw_wb, wb_cfg);

	if (hw_wb->ops.setup_cdp) {
		memset(cdp_cfg, 0, sizeof(struct dpu_hw_wb_cdp_cfg));

		cdp_cfg->enable = phys_enc->dpu_kms->catalog->perf.cdp_cfg
				[DPU_PERF_CDP_USAGE_NRT].wr_enable;
		cdp_cfg->ubwc_meta_enable =
				DPU_FORMAT_IS_UBWC(wb_cfg->dest.format);
		cdp_cfg->tile_amortize_enable =
				DPU_FORMAT_IS_UBWC(wb_cfg->dest.format) ||
				DPU_FORMAT_IS_TILE(wb_cfg->dest.format);
		cdp_cfg->preload_ahead = DPU_WB_CDP_PRELOAD_AHEAD_64;

		hw_wb->ops.setup_cdp(hw_wb, cdp_cfg);
	}

	if (hw_wb->ops.setup_outaddress) {
		DPU_EVT32(hw_wb->idx,
				wb_cfg->dest.width,
				wb_cfg->dest.height,
				wb_cfg->dest.plane_addr[0],
				wb_cfg->dest.plane_size[0],
				wb_cfg->dest.plane_addr[1],
				wb_cfg->dest.plane_size[1],
				wb_cfg->dest.plane_addr[2],
				wb_cfg->dest.plane_size[2],
				wb_cfg->dest.plane_addr[3],
				wb_cfg->dest.plane_size[3]);
		hw_wb->ops.setup_outaddress(hw_wb, wb_cfg);
	}
}

/**
 * dpu_encoder_phys_wb_setup_cdp - setup chroma down prefetch block
 * @phys_enc:	Pointer to physical encoder
 */
static void dpu_encoder_phys_wb_setup_cdp(struct dpu_encoder_phys *phys_enc)
{
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);
	struct dpu_hw_wb *hw_wb = wb_enc->hw_wb;
	struct dpu_hw_intf_cfg *intf_cfg = &wb_enc->intf_cfg;

	memset(intf_cfg, 0, sizeof(struct dpu_hw_intf_cfg));

	intf_cfg->intf = DPU_NONE;
	intf_cfg->wb = hw_wb->idx;
	intf_cfg->mode_3d = dpu_encoder_helper_get_3d_blend_mode(phys_enc);

	if (phys_enc->hw_ctl && phys_enc->hw_ctl->ops.setup_intf_cfg)
		phys_enc->hw_ctl->ops.setup_intf_cfg(phys_enc->hw_ctl,
				intf_cfg);
}

/**
 * dpu_encoder_phys_wb_atomic_check - verify and fixup given atomic states
 * @phys_enc:	Pointer to physical encoder
 * @crtc_state:	Pointer to CRTC atomic state
 * @conn_state:	Pointer to connector atomic state
 */
static int dpu_encoder_phys_wb_atomic_check(
		struct dpu_encoder_phys *phys_enc,
		struct drm_crtc_state *crtc_state,
		struct drm_connector_state *conn_state)
{
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);
	struct dpu_hw_wb *hw_wb = wb_enc->hw_wb;
	const struct dpu_wb_cfg *wb_cfg = hw_wb->caps;
	struct drm_framebuffer *fb;
	const struct dpu_format *fmt;
	struct dpu_rect wb_roi;
	const struct drm_display_mode *mode = &crtc_state->mode;
	int rc;

	DPU_DEBUG("[atomic_check:%d,%d,\"%s\",%d,%d]\n",
			hw_wb->idx - WB_0, mode->base.id, mode->name,
			mode->hdisplay, mode->vdisplay);

	if (!conn_state || !conn_state->connector) {
		DPU_ERROR("invalid connector state\n");
		return -EINVAL;
	} else if (conn_state->connector->status !=
			connector_status_connected) {
		DPU_ERROR("connector not connected %d\n",
				conn_state->connector->status);
		return -EINVAL;
	}

	memset(&wb_roi, 0, sizeof(struct dpu_rect));

	rc = dpu_wb_connector_state_get_output_roi(conn_state, &wb_roi);
	if (rc) {
		DPU_ERROR("failed to get roi %d\n", rc);
		return rc;
	}

	DPU_DEBUG("[roi:%u,%u,%u,%u]\n", wb_roi.x, wb_roi.y,
			wb_roi.w, wb_roi.h);

	fb = dpu_wb_connector_state_get_output_fb(conn_state);
	if (!fb) {
		DPU_ERROR("no output framebuffer\n");
		return -EINVAL;
	}

	DPU_DEBUG("[fb_id:%u][fb:%u,%u]\n", fb->base.id,
			fb->width, fb->height);

	fmt = dpu_get_dpu_format_ext(fb->format->format, fb->modifier);
	if (!fmt) {
		DPU_ERROR("unsupported output pixel format:%x\n",
				fb->format->format);
		return -EINVAL;
	}

	DPU_DEBUG("[fb_fmt:%x,%llx]\n", fb->format->format,
			fb->modifier);

	if (DPU_FORMAT_IS_YUV(fmt) &&
			!(wb_cfg->features & BIT(DPU_WB_YUV_CONFIG))) {
		DPU_ERROR("invalid output format %x\n", fmt->base.pixel_format);
		return -EINVAL;
	}

	if (DPU_FORMAT_IS_UBWC(fmt) &&
			!(wb_cfg->features & BIT(DPU_WB_UBWC))) {
		DPU_ERROR("invalid output format %x\n", fmt->base.pixel_format);
		return -EINVAL;
	}

	if (DPU_FORMAT_IS_YUV(fmt) != !!phys_enc->hw_cdm)
		crtc_state->mode_changed = true;

	if (wb_roi.w && wb_roi.h) {
		if (wb_roi.w != mode->hdisplay) {
			DPU_ERROR("invalid roi w=%d, mode w=%d\n", wb_roi.w,
					mode->hdisplay);
			return -EINVAL;
		} else if (wb_roi.h != mode->vdisplay) {
			DPU_ERROR("invalid roi h=%d, mode h=%d\n", wb_roi.h,
					mode->vdisplay);
			return -EINVAL;
		} else if (wb_roi.x + wb_roi.w > fb->width) {
			DPU_ERROR("invalid roi x=%d, w=%d, fb w=%d\n",
					wb_roi.x, wb_roi.w, fb->width);
			return -EINVAL;
		} else if (wb_roi.y + wb_roi.h > fb->height) {
			DPU_ERROR("invalid roi y=%d, h=%d, fb h=%d\n",
					wb_roi.y, wb_roi.h, fb->height);
			return -EINVAL;
		} else if (wb_roi.w > wb_cfg->sblk->maxlinewidth) {
			DPU_ERROR("invalid roi w=%d, maxlinewidth=%u\n",
					wb_roi.w, wb_cfg->sblk->maxlinewidth);
			return -EINVAL;
		}
	} else {
		if (wb_roi.x || wb_roi.y) {
			DPU_ERROR("invalid roi x=%d, y=%d\n",
					wb_roi.x, wb_roi.y);
			return -EINVAL;
		} else if (fb->width != mode->hdisplay) {
			DPU_ERROR("invalid fb w=%d, mode w=%d\n", fb->width,
					mode->hdisplay);
			return -EINVAL;
		} else if (fb->height != mode->vdisplay) {
			DPU_ERROR("invalid fb h=%d, mode h=%d\n", fb->height,
					mode->vdisplay);
			return -EINVAL;
		} else if (fb->width > wb_cfg->sblk->maxlinewidth) {
			DPU_ERROR("invalid fb w=%d, maxlinewidth=%u\n",
					fb->width, wb_cfg->sblk->maxlinewidth);
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * _dpu_encoder_phys_wb_update_flush - flush hardware update
 * @phys_enc:	Pointer to physical encoder
 */
static void _dpu_encoder_phys_wb_update_flush(struct dpu_encoder_phys *phys_enc)
{
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);
	struct dpu_hw_wb *hw_wb;
	struct dpu_hw_ctl *hw_ctl;
	struct dpu_hw_cdm *hw_cdm;
	u32 flush_mask = 0;

	if (!phys_enc)
		return;

	hw_wb = wb_enc->hw_wb;
	hw_ctl = phys_enc->hw_ctl;
	hw_cdm = phys_enc->hw_cdm;

	DPU_DEBUG("[wb:%d]\n", hw_wb->idx - WB_0);

	if (!hw_ctl) {
		DPU_DEBUG("[wb:%d] no ctl assigned\n", hw_wb->idx - WB_0);
		return;
	}

	if (hw_ctl->ops.get_bitmask_wb)
		hw_ctl->ops.get_bitmask_wb(hw_ctl, &flush_mask, hw_wb->idx);

	if (hw_ctl->ops.get_bitmask_cdm && hw_cdm)
		hw_ctl->ops.get_bitmask_cdm(hw_ctl, &flush_mask, hw_cdm->idx);

	if (hw_ctl->ops.update_pending_flush)
		hw_ctl->ops.update_pending_flush(hw_ctl, flush_mask);

	if (hw_ctl->ops.get_pending_flush)
		flush_mask = hw_ctl->ops.get_pending_flush(hw_ctl);

	DPU_DEBUG("Pending flush mask for CTL_%d is 0x%x, WB %d\n",
			hw_ctl->idx - CTL_0, flush_mask, hw_wb->idx - WB_0);
}

/**
 * dpu_encoder_phys_wb_setup - setup writeback encoder
 * @phys_enc:	Pointer to physical encoder
 */
static void dpu_encoder_phys_wb_setup(
		struct dpu_encoder_phys *phys_enc)
{
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);
	struct dpu_hw_wb *hw_wb = wb_enc->hw_wb;
	struct drm_display_mode mode = phys_enc->cached_mode;
	struct drm_framebuffer *fb;
	struct dpu_rect *wb_roi = &wb_enc->wb_roi;

	DPU_DEBUG("[mode_set:%d,%d,\"%s\",%d,%d]\n",
			hw_wb->idx - WB_0, mode.base.id, mode.name,
			mode.hdisplay, mode.vdisplay);

	memset(wb_roi, 0, sizeof(struct dpu_rect));

	/* clear writeback framebuffer - will be updated in setup_fb */
	wb_enc->wb_fb = NULL;

	if (phys_enc->enable_state == DPU_ENC_DISABLING) {
		fb = wb_enc->fb_disable;
		wb_roi->w = 0;
		wb_roi->h = 0;
	} else {
		fb = dpu_wb_get_output_fb(wb_enc->wb_dev);
		dpu_wb_get_output_roi(wb_enc->wb_dev, wb_roi);
	}

	if (!fb) {
		DPU_DEBUG("no output framebuffer\n");
		return;
	}

	DPU_DEBUG("[fb_id:%u][fb:%u,%u]\n", fb->base.id,
			fb->width, fb->height);

	if (wb_roi->w == 0 || wb_roi->h == 0) {
		wb_roi->x = 0;
		wb_roi->y = 0;
		wb_roi->w = fb->width;
		wb_roi->h = fb->height;
	}

	DPU_DEBUG("[roi:%u,%u,%u,%u]\n", wb_roi->x, wb_roi->y,
			wb_roi->w, wb_roi->h);

	wb_enc->wb_fmt = dpu_get_dpu_format_ext(fb->format->format,
							fb->modifier);
	if (!wb_enc->wb_fmt) {
		DPU_ERROR("unsupported output pixel format: %d\n",
				fb->format->format);
		return;
	}

	DPU_DEBUG("[fb_fmt:%x,%llx]\n", fb->format->format,
			fb->modifier);

	dpu_encoder_phys_wb_set_ot_limit(phys_enc);

	dpu_encoder_phys_wb_set_traffic_shaper(phys_enc);

	dpu_encoder_phys_wb_set_qos_remap(phys_enc);

	dpu_encoder_phys_setup_cdm(phys_enc, fb, wb_enc->wb_fmt, wb_roi);

	dpu_encoder_phys_wb_setup_fb(phys_enc, fb, wb_roi);

	dpu_encoder_phys_wb_setup_cdp(phys_enc);
}

/**
 * dpu_encoder_phys_wb_unregister_irq - unregister writeback interrupt handler
 * @phys_enc:	Pointer to physical encoder
 */
static int dpu_encoder_phys_wb_unregister_irq(
		struct dpu_encoder_phys *phys_enc)
{
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);
	struct dpu_hw_wb *hw_wb = wb_enc->hw_wb;

	if (wb_enc->bypass_irqreg)
		return 0;

	dpu_core_irq_disable(phys_enc->dpu_kms, &wb_enc->irq_idx, 1);
	dpu_core_irq_unregister_callback(phys_enc->dpu_kms, wb_enc->irq_idx,
			&wb_enc->irq_cb);

	DPU_DEBUG("un-register IRQ for wb %d, irq_idx=%d\n",
			hw_wb->idx - WB_0,
			wb_enc->irq_idx);

	return 0;
}

/**
 * dpu_encoder_phys_wb_done_irq - writeback interrupt handler
 * @arg:	Pointer to writeback encoder
 * @irq_idx:	interrupt index
 */
static void dpu_encoder_phys_wb_done_irq(void *arg, int irq_idx)
{
	struct dpu_encoder_phys_wb *wb_enc = arg;
	struct dpu_encoder_phys *phys_enc = &wb_enc->base;
	struct dpu_hw_wb *hw_wb = wb_enc->hw_wb;
	u32 event = 0;

	DPU_DEBUG("[wb:%d,%u]\n", hw_wb->idx - WB_0,
			wb_enc->frame_count);

	/* don't notify upper layer for internal commit */
	if (phys_enc->enable_state == DPU_ENC_DISABLING)
		goto complete;

	event = DPU_ENCODER_FRAME_EVENT_DONE;

	if (phys_enc->parent_ops.handle_frame_done)
		phys_enc->parent_ops.handle_frame_done(phys_enc->parent,
				phys_enc, event);

	if (phys_enc->parent_ops.handle_vblank_virt)
		phys_enc->parent_ops.handle_vblank_virt(phys_enc->parent,
				phys_enc);

	DPU_EVT32_IRQ(DRMID(phys_enc->parent), hw_wb->idx - WB_0, event);

complete:
	complete_all(&wb_enc->wbdone_complete);
}

/**
 * dpu_encoder_phys_wb_register_irq - register writeback interrupt handler
 * @phys_enc:	Pointer to physical encoder
 */
static int dpu_encoder_phys_wb_register_irq(struct dpu_encoder_phys *phys_enc)
{
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);
	struct dpu_hw_wb *hw_wb = wb_enc->hw_wb;
	struct dpu_irq_callback *irq_cb = &wb_enc->irq_cb;
	enum dpu_intr_type intr_type;
	int ret = 0;

	if (wb_enc->bypass_irqreg)
		return 0;

	intr_type = dpu_encoder_phys_wb_get_intr_type(hw_wb);
	wb_enc->irq_idx = dpu_core_irq_idx_lookup(phys_enc->dpu_kms,
			intr_type, hw_wb->idx);
	if (wb_enc->irq_idx < 0) {
		DPU_ERROR(
			"failed to lookup IRQ index for WB_DONE with wb=%d\n",
			hw_wb->idx - WB_0);
		return -EINVAL;
	}

	irq_cb->func = dpu_encoder_phys_wb_done_irq;
	irq_cb->arg = wb_enc;
	ret = dpu_core_irq_register_callback(phys_enc->dpu_kms,
			wb_enc->irq_idx, irq_cb);
	if (ret) {
		DPU_ERROR("failed to register IRQ callback WB_DONE\n");
		return ret;
	}

	ret = dpu_core_irq_enable(phys_enc->dpu_kms, &wb_enc->irq_idx, 1);
	if (ret) {
		DPU_ERROR(
			"failed to enable IRQ for WB_DONE, wb %d, irq_idx=%d\n",
				hw_wb->idx - WB_0,
				wb_enc->irq_idx);
		wb_enc->irq_idx = -EINVAL;

		/* Unregister callback on IRQ enable failure */
		dpu_core_irq_unregister_callback(phys_enc->dpu_kms,
				wb_enc->irq_idx, irq_cb);
		return ret;
	}

	DPU_DEBUG("registered IRQ for wb %d, irq_idx=%d\n",
			hw_wb->idx - WB_0,
			wb_enc->irq_idx);

	return ret;
}

/**
 * dpu_encoder_phys_wb_mode_set - set display mode
 * @phys_enc:	Pointer to physical encoder
 * @mode:	Pointer to requested display mode
 * @adj_mode:	Pointer to adjusted display mode
 */
static void dpu_encoder_phys_wb_mode_set(
		struct dpu_encoder_phys *phys_enc,
		struct drm_display_mode *mode,
		struct drm_display_mode *adj_mode)
{
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);
	struct dpu_rm *rm = &phys_enc->dpu_kms->rm;
	struct dpu_hw_wb *hw_wb = wb_enc->hw_wb;
	struct dpu_rm_hw_iter iter;
	int i, instance;

	phys_enc->cached_mode = *adj_mode;
	instance = phys_enc->split_role == ENC_ROLE_SLAVE ? 1 : 0;

	DPU_DEBUG("[mode_set_cache:%d,%d,\"%s\",%d,%d]\n",
			hw_wb->idx - WB_0, mode->base.id,
			mode->name, mode->hdisplay, mode->vdisplay);

	phys_enc->hw_ctl = NULL;
	phys_enc->hw_cdm = NULL;

	/* Retrieve previously allocated HW Resources. CTL shouldn't fail */
	dpu_rm_init_hw_iter(&iter, phys_enc->parent->base.id, DPU_HW_BLK_CTL);
	for (i = 0; i <= instance; i++) {
		dpu_rm_get_hw(rm, &iter);
		if (i == instance)
			phys_enc->hw_ctl = (struct dpu_hw_ctl *) iter.hw;
	}

	if (IS_ERR_OR_NULL(phys_enc->hw_ctl)) {
		DPU_ERROR("failed init ctl: %ld\n", PTR_ERR(phys_enc->hw_ctl));
		phys_enc->hw_ctl = NULL;
		return;
	}

	/* CDM is optional */
	dpu_rm_init_hw_iter(&iter, phys_enc->parent->base.id, DPU_HW_BLK_CDM);
	for (i = 0; i <= instance; i++) {
		dpu_rm_get_hw(rm, &iter);
		if (i == instance)
			phys_enc->hw_cdm = (struct dpu_hw_cdm *) iter.hw;
	}

	if (IS_ERR(phys_enc->hw_cdm)) {
		DPU_ERROR("CDM required but not allocated: %ld\n",
				PTR_ERR(phys_enc->hw_cdm));
		phys_enc->hw_ctl = NULL;
	}
}

/**
 * dpu_encoder_phys_wb_wait_for_commit_done - wait until request is committed
 * @phys_enc:	Pointer to physical encoder
 */
static int dpu_encoder_phys_wb_wait_for_commit_done(
		struct dpu_encoder_phys *phys_enc)
{
	unsigned long ret;
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);
	u32 irq_status, event = 0;
	u64 wb_time = 0;
	int rc = 0;
	u32 timeout = max_t(u32, wb_enc->wbdone_timeout, KICKOFF_TIMEOUT_MS);

	/* Return EWOULDBLOCK since we know the wait isn't necessary */
	if (phys_enc->enable_state == DPU_ENC_DISABLED) {
		DPU_ERROR("encoder already disabled\n");
		return -EWOULDBLOCK;
	}

	DPU_EVT32(DRMID(phys_enc->parent), WBID(wb_enc), wb_enc->frame_count);

	ret = wait_for_completion_timeout(&wb_enc->wbdone_complete,
			msecs_to_jiffies(timeout));

	if (!ret) {
		DPU_EVT32(DRMID(phys_enc->parent), WBID(wb_enc),
				wb_enc->frame_count);
		irq_status = dpu_core_irq_read(phys_enc->dpu_kms,
				wb_enc->irq_idx, true);
		if (irq_status) {
			DPU_DEBUG("wb:%d done but irq not triggered\n",
					wb_enc->wb_dev->wb_idx - WB_0);
			dpu_encoder_phys_wb_done_irq(wb_enc, wb_enc->irq_idx);
		} else {
			DPU_ERROR("wb:%d kickoff timed out\n",
					wb_enc->wb_dev->wb_idx - WB_0);

			event = DPU_ENCODER_FRAME_EVENT_ERROR;
			if (phys_enc->parent_ops.handle_frame_done)
				phys_enc->parent_ops.handle_frame_done(
					phys_enc->parent, phys_enc, event);
			rc = -ETIMEDOUT;
		}
	}

	dpu_encoder_phys_wb_unregister_irq(phys_enc);

	if (!rc)
		wb_enc->end_time = ktime_get();

	/* once operation is done, disable traffic shaper */
	if (wb_enc->wb_cfg.ts_cfg.en && wb_enc->hw_wb &&
			wb_enc->hw_wb->ops.setup_trafficshaper) {
		wb_enc->wb_cfg.ts_cfg.en = false;
		wb_enc->hw_wb->ops.setup_trafficshaper(
				wb_enc->hw_wb, &wb_enc->wb_cfg);
	}

	/* remove vote for iommu/clk/bus */
	wb_enc->frame_count++;

	if (!rc) {
		wb_time = (u64)ktime_to_us(wb_enc->end_time) -
				(u64)ktime_to_us(wb_enc->start_time);
		DPU_DEBUG("wb:%d took %llu us\n",
			wb_enc->wb_dev->wb_idx - WB_0, wb_time);
	}

	/* cleanup writeback framebuffer */
	if (wb_enc->wb_fb) {
		msm_framebuffer_cleanup(wb_enc->wb_fb, phys_enc->dpu_kms->base.aspace);
		wb_enc->wb_fb = NULL;
	}

	DPU_EVT32(DRMID(phys_enc->parent), WBID(wb_enc), wb_enc->frame_count,
			wb_time, event, rc);

	return rc;
}

/**
 * dpu_encoder_phys_wb_prepare_for_kickoff - pre-kickoff processing
 * @phys_enc:	Pointer to physical encoder
 * @params:	kickoff parameters
 */
static void dpu_encoder_phys_wb_prepare_for_kickoff(
		struct dpu_encoder_phys *phys_enc,
		struct dpu_encoder_kickoff_params *params)
{
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);
	int ret;

	DPU_DEBUG("[wb:%d,%u]\n", wb_enc->hw_wb->idx - WB_0,
			wb_enc->kickoff_count);

	reinit_completion(&wb_enc->wbdone_complete);

	ret = dpu_encoder_phys_wb_register_irq(phys_enc);
	if (ret) {
		DPU_ERROR("failed to register irq %d\n", ret);
		return;
	}

	wb_enc->kickoff_count++;

	/* set OT limit & enable traffic shaper */
	dpu_encoder_phys_wb_setup(phys_enc);

	_dpu_encoder_phys_wb_update_flush(phys_enc);

	/* vote for iommu/clk/bus */
	wb_enc->start_time = ktime_get();

	DPU_EVT32(DRMID(phys_enc->parent), WBID(wb_enc), wb_enc->kickoff_count);
}

/**
 * dpu_encoder_phys_wb_handle_post_kickoff - post-kickoff processing
 * @phys_enc:	Pointer to physical encoder
 */
static void dpu_encoder_phys_wb_handle_post_kickoff(
		struct dpu_encoder_phys *phys_enc)
{
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);

	DPU_DEBUG("[wb:%d]\n", wb_enc->hw_wb->idx - WB_0);

	DPU_EVT32(DRMID(phys_enc->parent), WBID(wb_enc));
}

/**
 * _dpu_encoder_phys_wb_init_internal_fb - create fb for internal commit
 * @wb_enc:		Pointer to writeback encoder
 * @pixel_format:	DRM pixel format
 * @width:		Desired fb width
 * @height:		Desired fb height
 * @pitch:		Desired fb pitch
 */
static int _dpu_encoder_phys_wb_init_internal_fb(
		struct dpu_encoder_phys_wb *wb_enc,
		uint32_t pixel_format, uint32_t width,
		uint32_t height, uint32_t pitch)
{
	struct drm_device *dev;
	struct drm_framebuffer *fb;
	struct drm_mode_fb_cmd2 mode_cmd;
	uint32_t size;
	int nplanes, i, ret;
	struct msm_gem_address_space *aspace;

	if (!wb_enc || !wb_enc->base.parent || !wb_enc->base.dpu_kms) {
		DPU_ERROR("invalid params\n");
		return -EINVAL;
	}

	aspace = wb_enc->base.dpu_kms->base.aspace;
	if (!aspace) {
		DPU_ERROR("invalid address space\n");
		return -EINVAL;
	}

	dev = wb_enc->base.dpu_kms->dev;
	if (!dev) {
		DPU_ERROR("invalid dev\n");
		return -EINVAL;
	}

	memset(&mode_cmd, 0, sizeof(mode_cmd));
	mode_cmd.pixel_format = pixel_format;
	mode_cmd.width = width;
	mode_cmd.height = height;
	mode_cmd.pitches[0] = pitch;

	size = dpu_format_get_framebuffer_size(pixel_format,
			mode_cmd.width, mode_cmd.height,
			mode_cmd.pitches, 0);
	if (!size) {
		DPU_DEBUG("not creating zero size buffer\n");
		return -EINVAL;
	}

	/* allocate gem tracking object */
	nplanes = drm_format_num_planes(pixel_format);
	if (nplanes > DPU_MAX_PLANES) {
		DPU_ERROR("requested format has too many planes\n");
		return -EINVAL;
	}
	mutex_lock(&dev->struct_mutex);
	wb_enc->bo_disable[0] = msm_gem_new(dev, size,
			MSM_BO_SCANOUT | MSM_BO_WC);
	mutex_unlock(&dev->struct_mutex);

	if (IS_ERR_OR_NULL(wb_enc->bo_disable[0])) {
		ret = PTR_ERR(wb_enc->bo_disable[0]);
		wb_enc->bo_disable[0] = NULL;

		DPU_ERROR("failed to create bo, %d\n", ret);
		return ret;
	}

	for (i = 0; i < nplanes; ++i) {
		wb_enc->bo_disable[i] = wb_enc->bo_disable[0];
		mode_cmd.pitches[i] = width *
			drm_format_plane_cpp(pixel_format, i);
	}

	fb = msm_framebuffer_init(dev, &mode_cmd, wb_enc->bo_disable);
	if (IS_ERR_OR_NULL(fb)) {
		ret = PTR_ERR(fb);
		drm_gem_object_put(wb_enc->bo_disable[0]);
		wb_enc->bo_disable[0] = NULL;

		DPU_ERROR("failed to init fb, %d\n", ret);
		return ret;
	}

	/* prepare the backing buffer now so that it's available later */
	ret = msm_framebuffer_prepare(fb, aspace);
	if (!ret)
		wb_enc->fb_disable = fb;
	return ret;
}

/**
 * _dpu_encoder_phys_wb_destroy_internal_fb - deconstruct internal fb
 * @wb_enc:		Pointer to writeback encoder
 */
static void _dpu_encoder_phys_wb_destroy_internal_fb(
		struct dpu_encoder_phys_wb *wb_enc)
{
	if (!wb_enc)
		return;

	if (wb_enc->fb_disable) {
		drm_framebuffer_unregister_private(wb_enc->fb_disable);
		drm_framebuffer_remove(wb_enc->fb_disable);
		wb_enc->fb_disable = NULL;
	}

	if (wb_enc->bo_disable[0]) {
		drm_gem_object_put(wb_enc->bo_disable[0]);
		wb_enc->bo_disable[0] = NULL;
	}
}

/**
 * dpu_encoder_phys_wb_enable - enable writeback encoder
 * @phys_enc:	Pointer to physical encoder
 */
static void dpu_encoder_phys_wb_enable(struct dpu_encoder_phys *phys_enc)
{
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);
	struct dpu_hw_wb *hw_wb = wb_enc->hw_wb;
	struct drm_device *dev;
	struct drm_connector *connector;

	DPU_DEBUG("[wb:%d]\n", hw_wb->idx - WB_0);

	if (!wb_enc->base.parent || !wb_enc->base.parent->dev) {
		DPU_ERROR("invalid drm device\n");
		return;
	}
	dev = wb_enc->base.parent->dev;

	/* find associated writeback connector */
	connector = phys_enc->connector;

	if (!connector || connector->encoder != phys_enc->parent) {
		DPU_ERROR("failed to find writeback connector\n");
		return;
	}
	wb_enc->wb_dev = dpu_wb_connector_get_wb(connector);

	phys_enc->enable_state = DPU_ENC_ENABLED;
}

/**
 * dpu_encoder_phys_wb_disable - disable writeback encoder
 * @phys_enc:	Pointer to physical encoder
 */
static void dpu_encoder_phys_wb_disable(struct dpu_encoder_phys *phys_enc)
{
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);
	struct dpu_hw_wb *hw_wb = wb_enc->hw_wb;

	DPU_DEBUG("[wb:%d]\n", hw_wb->idx - WB_0);

	if (phys_enc->enable_state == DPU_ENC_DISABLED) {
		DPU_ERROR("encoder is already disabled\n");
		return;
	}

	if (wb_enc->frame_count != wb_enc->kickoff_count) {
		DPU_DEBUG("[wait_for_done: wb:%d, frame:%u, kickoff:%u]\n",
				hw_wb->idx - WB_0, wb_enc->frame_count,
				wb_enc->kickoff_count);
		dpu_encoder_phys_wb_wait_for_commit_done(phys_enc);
	}

	if (!phys_enc->hw_ctl || !phys_enc->parent ||
			!phys_enc->dpu_kms || !wb_enc->fb_disable) {
		DPU_DEBUG("invalid enc, skipping extra commit\n");
		goto exit;
	}

	/* reset h/w before final flush */
	if (dpu_encoder_helper_hw_release(phys_enc, wb_enc->fb_disable))
		goto exit;

	phys_enc->enable_state = DPU_ENC_DISABLING;
	dpu_encoder_phys_wb_prepare_for_kickoff(phys_enc, NULL);
	if (phys_enc->hw_ctl->ops.trigger_flush)
		phys_enc->hw_ctl->ops.trigger_flush(phys_enc->hw_ctl);
	dpu_encoder_helper_trigger_start(phys_enc);
	dpu_encoder_phys_wb_wait_for_commit_done(phys_enc);
exit:
	phys_enc->enable_state = DPU_ENC_DISABLED;
}

/**
 * dpu_encoder_phys_wb_get_hw_resources - get hardware resources
 * @phys_enc:	Pointer to physical encoder
 * @hw_res:	Pointer to encoder resources
 */
static void dpu_encoder_phys_wb_get_hw_resources(
		struct dpu_encoder_phys *phys_enc,
		struct dpu_encoder_hw_resources *hw_res,
		struct drm_connector_state *conn_state)
{
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);
	struct dpu_hw_wb *hw_wb;
	struct drm_framebuffer *fb;
	const struct dpu_format *fmt;

	if (!phys_enc) {
		DPU_ERROR("invalid encoder\n");
		return;
	}

	fb = dpu_wb_connector_state_get_output_fb(conn_state);
	if (!fb) {
		DPU_ERROR("no output framebuffer\n");
		return;
	}

	fmt = dpu_get_dpu_format_ext(fb->format->format, fb->modifier);
	if (!fmt) {
		DPU_ERROR("unsupported output pixel format:%d\n",
				fb->format->format);
		return;
	}

	hw_wb = wb_enc->hw_wb;
	hw_res->wbs[hw_wb->idx - WB_0] = phys_enc->intf_mode;
	hw_res->needs_cdm = DPU_FORMAT_IS_YUV(fmt);
	DPU_DEBUG("[wb:%d] intf_mode=%d needs_cdm=%d\n", hw_wb->idx - WB_0,
			hw_res->wbs[hw_wb->idx - WB_0],
			hw_res->needs_cdm);
}

#ifdef CONFIG_DEBUG_FS
/**
 * dpu_encoder_phys_wb_init_debugfs - initialize writeback encoder debugfs
 * @phys_enc:		Pointer to physical encoder
 * @debugfs_root:	Pointer to virtual encoder's debugfs_root dir
 */
static int dpu_encoder_phys_wb_init_debugfs(
		struct dpu_encoder_phys *phys_enc, struct dentry *debugfs_root)
{
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);

	if (!phys_enc || !wb_enc->hw_wb || !debugfs_root)
		return -EINVAL;

	if (!debugfs_create_u32("wbdone_timeout", 0600,
			debugfs_root, &wb_enc->wbdone_timeout)) {
		DPU_ERROR("failed to create debugfs/wbdone_timeout\n");
		return -ENOMEM;
	}

	if (!debugfs_create_u32("bypass_irqreg", 0600,
			debugfs_root, &wb_enc->bypass_irqreg)) {
		DPU_ERROR("failed to create debugfs/bypass_irqreg\n");
		return -ENOMEM;
	}

	return 0;
}
#else
static int dpu_encoder_phys_wb_init_debugfs(
		struct dpu_encoder_phys *phys_enc, struct dentry *debugfs_root)
{
	return 0;
}
#endif

static int dpu_encoder_phys_wb_late_register(struct dpu_encoder_phys *phys_enc,
		struct dentry *debugfs_root)
{
	return dpu_encoder_phys_wb_init_debugfs(phys_enc, debugfs_root);
}

/**
 * dpu_encoder_phys_wb_destroy - destroy writeback encoder
 * @phys_enc:	Pointer to physical encoder
 */
static void dpu_encoder_phys_wb_destroy(struct dpu_encoder_phys *phys_enc)
{
	struct dpu_encoder_phys_wb *wb_enc = to_dpu_encoder_phys_wb(phys_enc);
	struct dpu_hw_wb *hw_wb = wb_enc->hw_wb;

	DPU_DEBUG("[wb:%d]\n", hw_wb->idx - WB_0);

	if (!phys_enc)
		return;

	_dpu_encoder_phys_wb_destroy_internal_fb(wb_enc);

	kfree(wb_enc);
}

/**
 * dpu_encoder_phys_wb_init_ops - initialize writeback operations
 * @ops:	Pointer to encoder operation table
 */
static void dpu_encoder_phys_wb_init_ops(struct dpu_encoder_phys_ops *ops)
{
	ops->late_register = dpu_encoder_phys_wb_late_register;
	ops->is_master = dpu_encoder_phys_wb_is_master;
	ops->mode_set = dpu_encoder_phys_wb_mode_set;
	ops->enable = dpu_encoder_phys_wb_enable;
	ops->disable = dpu_encoder_phys_wb_disable;
	ops->destroy = dpu_encoder_phys_wb_destroy;
	ops->atomic_check = dpu_encoder_phys_wb_atomic_check;
	ops->get_hw_resources = dpu_encoder_phys_wb_get_hw_resources;
	ops->wait_for_commit_done = dpu_encoder_phys_wb_wait_for_commit_done;
	ops->prepare_for_kickoff = dpu_encoder_phys_wb_prepare_for_kickoff;
	ops->handle_post_kickoff = dpu_encoder_phys_wb_handle_post_kickoff;
	ops->trigger_start = dpu_encoder_helper_trigger_start;
	ops->hw_reset = dpu_encoder_helper_hw_reset;
}

/**
 * dpu_encoder_phys_wb_init - initialize writeback encoder
 * @init:	Pointer to init info structure with initialization params
 */
struct dpu_encoder_phys *dpu_encoder_phys_wb_init(
		struct dpu_enc_phys_init_params *p)
{
	struct dpu_encoder_phys *phys_enc;
	struct dpu_encoder_phys_wb *wb_enc;
	struct dpu_hw_mdp *hw_mdp;
	int ret = 0;

	DPU_DEBUG("\n");

	if (!p || !p->parent) {
		DPU_ERROR("invalid params\n");
		ret = -EINVAL;
		goto fail_alloc;
	}

	wb_enc = kzalloc(sizeof(*wb_enc), GFP_KERNEL);
	if (!wb_enc) {
		DPU_ERROR("failed to allocate wb enc\n");
		ret = -ENOMEM;
		goto fail_alloc;
	}
	wb_enc->irq_idx = -EINVAL;
	wb_enc->wbdone_timeout = KICKOFF_TIMEOUT_MS;
	init_completion(&wb_enc->wbdone_complete);

	phys_enc = &wb_enc->base;

	hw_mdp = dpu_rm_get_mdp(&p->dpu_kms->rm);
	if (IS_ERR_OR_NULL(hw_mdp)) {
		ret = PTR_ERR(hw_mdp);
		DPU_ERROR("failed to init hw_top: %d\n", ret);
		goto fail_mdp_init;
	}
	phys_enc->hw_mdptop = hw_mdp;

	/**
	 * hw_wb resource permanently assigned to this encoder
	 * Other resources allocated at atomic commit time by use case
	 */
	if (p->wb_idx != DPU_NONE) {
		struct dpu_rm_hw_iter iter;

		dpu_rm_init_hw_iter(&iter, 0, DPU_HW_BLK_WB);
		while (dpu_rm_get_hw(&p->dpu_kms->rm, &iter)) {
			struct dpu_hw_wb *hw_wb = (struct dpu_hw_wb *)iter.hw;

			if (hw_wb->idx == p->wb_idx) {
				wb_enc->hw_wb = hw_wb;
				break;
			}
		}

		if (!wb_enc->hw_wb) {
			ret = -EINVAL;
			DPU_ERROR("failed to init hw_wb%d\n", p->wb_idx - WB_0);
			goto fail_wb_init;
		}
	} else {
		ret = -EINVAL;
		DPU_ERROR("invalid wb_idx\n");
		goto fail_wb_check;
	}

	dpu_encoder_phys_wb_init_ops(&phys_enc->ops);
	phys_enc->parent = p->parent;
	phys_enc->parent_ops = p->parent_ops;
	phys_enc->dpu_kms = p->dpu_kms;
	phys_enc->split_role = p->split_role;
	phys_enc->intf_mode = INTF_MODE_WB_LINE;
	phys_enc->intf_idx = p->intf_idx;
	phys_enc->enc_spinlock = p->enc_spinlock;
	INIT_LIST_HEAD(&wb_enc->irq_cb.list);

	/* create internal buffer for disable logic */
	if (_dpu_encoder_phys_wb_init_internal_fb(wb_enc,
				DRM_FORMAT_RGB888, 2, 1, 6)) {
		DPU_ERROR("failed to init internal fb\n");
		goto fail_wb_init;
	}

	DPU_DEBUG("Created dpu_encoder_phys_wb for wb %d\n",
			wb_enc->hw_wb->idx - WB_0);

	return phys_enc;

fail_wb_init:
fail_wb_check:
fail_mdp_init:
	kfree(wb_enc);
fail_alloc:
	return ERR_PTR(ret);
}

