/* Copyright (c) 2017-2018, The Linux Foundation. All rights reserved.
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

#include "dpu_reg_dma.h"
#include "dpu_hw_reg_dma_v1.h"
#include "dpu_dbg.h"

static int default_check_support(enum dpu_reg_dma_features feature,
		     enum dpu_reg_dma_blk blk,
		     bool *is_supported)
{

	if (!is_supported)
		return -EINVAL;

	*is_supported = false;
	return 0;
}

static int default_setup_payload(struct dpu_reg_dma_setup_ops_cfg *cfg)
{
	DRM_ERROR("not implemented\n");
	return -EINVAL;
}

static int default_kick_off(struct dpu_reg_dma_kickoff_cfg *cfg)
{
	DRM_ERROR("not implemented\n");
	return -EINVAL;

}

static int default_reset(struct dpu_hw_ctl *ctl)
{
	DRM_ERROR("not implemented\n");
	return -EINVAL;
}

struct dpu_reg_dma_buffer *default_alloc_reg_dma_buf(u32 size)
{
	DRM_ERROR("not implemented\n");
	return ERR_PTR(-EINVAL);
}

int default_dealloc_reg_dma(struct dpu_reg_dma_buffer *lut_buf)
{
	DRM_ERROR("not implemented\n");
	return -EINVAL;
}

static int default_buf_reset_reg_dma(struct dpu_reg_dma_buffer *lut_buf)
{
	DRM_ERROR("not implemented\n");
	return -EINVAL;
}

static int default_last_command(struct dpu_hw_ctl *ctl,
		enum dpu_reg_dma_queue q)
{
	return 0;
}

static struct dpu_hw_reg_dma reg_dma = {
	.ops = {default_check_support, default_setup_payload,
		default_kick_off, default_reset, default_alloc_reg_dma_buf,
		default_dealloc_reg_dma, default_buf_reset_reg_dma,
		default_last_command},
};

int dpu_reg_dma_init(void __iomem *addr, struct dpu_mdss_cfg *m,
		struct drm_device *dev)
{
	int rc = 0;

	if (!addr || !m || !dev) {
		DRM_DEBUG("invalid addr %pK catalog %pK dev %pK\n", addr, m,
				dev);
		return 0;
	}

	reg_dma.drm_dev = dev;
	reg_dma.caps = &m->dma_cfg;
	reg_dma.addr = addr;

	if (!m->reg_dma_count)
		return 0;

	switch (reg_dma.caps->version) {
	case 1:
		rc = init_v1(&reg_dma);
		if (rc)
			DRM_DEBUG("init v1 dma ops failed\n");
		else
			dpu_dbg_reg_register_base("reg_dma", addr,
					reg_dma.caps->len);
		break;
	default:
		break;
	}

	return 0;
}

struct dpu_hw_reg_dma_ops *dpu_reg_dma_get_ops(void)
{
	return &reg_dma.ops;
}

void dpu_reg_dma_deinit(void)
{
	struct dpu_hw_reg_dma op = {
	.ops = {default_check_support, default_setup_payload,
		default_kick_off, default_reset, default_alloc_reg_dma_buf,
		default_dealloc_reg_dma, default_buf_reset_reg_dma,
		default_last_command},
	};

	if (!reg_dma.drm_dev || !reg_dma.caps)
		return;

	switch (reg_dma.caps->version) {
	case 1:
		deinit_v1();
		break;
	default:
		break;
	}
	memset(&reg_dma, 0, sizeof(reg_dma));
	memcpy(&reg_dma.ops, &op.ops, sizeof(op.ops));
}
