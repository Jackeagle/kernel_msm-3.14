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
#include <drm/msm_drm_pp.h>
#include "dpu_hw_mdss.h"
#include "dpu_hwio.h"
#include "dpu_hw_catalog.h"
#include "dpu_hw_dspp.h"
#include "dpu_hw_color_processing.h"
#include "dpu_dbg.h"
#include "dpu_ad4.h"
#include "dpu_kms.h"

static struct dpu_dspp_cfg *_dspp_offset(enum dpu_dspp dspp,
		struct dpu_mdss_cfg *m,
		void __iomem *addr,
		struct dpu_hw_blk_reg_map *b)
{
	int i;

	if (!m || !addr || !b)
		return ERR_PTR(-EINVAL);

	for (i = 0; i < m->dspp_count; i++) {
		if (dspp == m->dspp[i].id) {
			b->base_off = addr;
			b->blk_off = m->dspp[i].base;
			b->length = m->dspp[i].len;
			b->hwversion = m->hwversion;
			b->log_mask = DPU_DBG_MASK_DSPP;
			return &m->dspp[i];
		}
	}

	return ERR_PTR(-EINVAL);
}

static void _setup_dspp_ops(struct dpu_hw_dspp *c, unsigned long features)
{
	int i = 0, ret;

	if (!c || !c->cap || !c->cap->sblk)
		return;

	for (i = 0; i < DPU_DSPP_MAX; i++) {
		if (!test_bit(i, &features))
			continue;
		switch (i) {
		case DPU_DSPP_PCC:
			if (c->cap->sblk->pcc.version ==
				(DPU_COLOR_PROCESS_VER(0x1, 0x7)))
				c->ops.setup_pcc = dpu_setup_dspp_pcc_v1_7;
			else if (c->cap->sblk->pcc.version ==
					(DPU_COLOR_PROCESS_VER(0x4, 0x0))) {
				ret = reg_dmav1_init_dspp_op_v4(i, c->idx);
				if (!ret)
					c->ops.setup_pcc =
						reg_dmav1_setup_dspp_pccv4;
				else
					c->ops.setup_pcc =
						dpu_setup_dspp_pccv4;
			}
			break;
		case DPU_DSPP_HSIC:
			if (c->cap->sblk->hsic.version ==
				(DPU_COLOR_PROCESS_VER(0x1, 0x7)))
				c->ops.setup_hue = dpu_setup_dspp_pa_hue_v1_7;
			break;
		case DPU_DSPP_VLUT:
			if (c->cap->sblk->vlut.version ==
				(DPU_COLOR_PROCESS_VER(0x1, 0x7))) {
				c->ops.setup_vlut =
				    dpu_setup_dspp_pa_vlut_v1_7;
			} else if (c->cap->sblk->vlut.version ==
					(DPU_COLOR_PROCESS_VER(0x1, 0x8))) {
				ret = reg_dmav1_init_dspp_op_v4(i, c->idx);
				if (!ret)
					c->ops.setup_vlut =
					reg_dmav1_setup_dspp_vlutv18;
				else
					c->ops.setup_vlut =
					dpu_setup_dspp_pa_vlut_v1_8;
			}
			break;
		case DPU_DSPP_GAMUT:
			if (c->cap->sblk->gamut.version ==
					DPU_COLOR_PROCESS_VER(0x4, 0)) {
				ret = reg_dmav1_init_dspp_op_v4(i, c->idx);
				if (!ret)
					c->ops.setup_gamut =
						reg_dmav1_setup_dspp_3d_gamutv4;
				else
					c->ops.setup_gamut =
						dpu_setup_dspp_3d_gamutv4;
			}
			break;
		case DPU_DSPP_GC:
			if (c->cap->sblk->gc.version ==
					DPU_COLOR_PROCESS_VER(0x1, 8)) {
				ret = reg_dmav1_init_dspp_op_v4(i, c->idx);
				if (!ret)
					c->ops.setup_gc =
						reg_dmav1_setup_dspp_gcv18;
				/** programming for v18 through ahb is same
				 * as v17 hence assign v17 function
				 */
				else
					c->ops.setup_gc =
						dpu_setup_dspp_gc_v1_7;
			}
			break;
		case DPU_DSPP_IGC:
			if (c->cap->sblk->igc.version ==
					DPU_COLOR_PROCESS_VER(0x3, 0x1)) {
				ret = reg_dmav1_init_dspp_op_v4(i, c->idx);
				if (!ret)
					c->ops.setup_igc =
						reg_dmav1_setup_dspp_igcv31;
				else
					c->ops.setup_igc =
						dpu_setup_dspp_igcv3;
			}
			break;
		case DPU_DSPP_AD:
			if (c->cap->sblk->ad.version ==
			    DPU_COLOR_PROCESS_VER(4, 0)) {
				c->ops.setup_ad = dpu_setup_dspp_ad4;
				c->ops.ad_read_intr_resp =
					dpu_read_intr_resp_ad4;
				c->ops.validate_ad = dpu_validate_dspp_ad4;
			}
			break;
		default:
			break;
		}
	}
}

static struct dpu_hw_blk_ops dpu_hw_ops = {
	.start = NULL,
	.stop = NULL,
};

struct dpu_hw_dspp *dpu_hw_dspp_init(enum dpu_dspp idx,
			void __iomem *addr,
			struct dpu_mdss_cfg *m)
{
	struct dpu_hw_dspp *c;
	struct dpu_dspp_cfg *cfg;
	int rc;

	if (!addr || !m)
		return ERR_PTR(-EINVAL);

	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c)
		return ERR_PTR(-ENOMEM);

	cfg = _dspp_offset(idx, m, addr, &c->hw);
	if (IS_ERR_OR_NULL(cfg)) {
		kfree(c);
		return ERR_PTR(-EINVAL);
	}

	/* Populate DSPP Top HW block */
	c->hw_top.base_off = addr;
	c->hw_top.blk_off = m->dspp_top.base;
	c->hw_top.length = m->dspp_top.len;
	c->hw_top.hwversion = m->hwversion;
	c->hw_top.log_mask = DPU_DBG_MASK_DSPP;

	/* Assign ops */
	c->idx = idx;
	c->cap = cfg;
	_setup_dspp_ops(c, c->cap->features);

	rc = dpu_hw_blk_init(&c->base, DPU_HW_BLK_DSPP, idx, &dpu_hw_ops);
	if (rc) {
		DPU_ERROR("failed to init hw blk %d\n", rc);
		goto blk_init_error;
	}

	dpu_dbg_reg_register_dump_range(DPU_DBG_NAME, cfg->name, c->hw.blk_off,
			c->hw.blk_off + c->hw.length, c->hw.xin_id);

	return c;

blk_init_error:
	kzfree(c);

	return ERR_PTR(rc);
}

void dpu_hw_dspp_destroy(struct dpu_hw_dspp *dspp)
{
	if (dspp) {
		reg_dmav1_deinit_dspp_ops(dspp->idx);
		dpu_hw_blk_destroy(&dspp->base);
	}
	kfree(dspp);
}
