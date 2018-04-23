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

#include "dpu_hw_ds.h"
#include "dpu_formats.h"
#include "dpu_dbg.h"
#include "dpu_kms.h"

/* Destination scaler TOP registers */
#define DEST_SCALER_OP_MODE     0x00
#define DEST_SCALER_HW_VERSION  0x10

static void dpu_hw_ds_setup_opmode(struct dpu_hw_ds *hw_ds,
				u32 op_mode)
{
	struct dpu_hw_blk_reg_map *hw = &hw_ds->hw;

	DPU_REG_WRITE(hw, DEST_SCALER_OP_MODE, op_mode);
}

static void dpu_hw_ds_setup_scaler3(struct dpu_hw_ds *hw_ds,
			void *scaler_cfg, void *scaler_lut_cfg)
{
	struct dpu_hw_scaler3_cfg *scl3_cfg = scaler_cfg;
	struct dpu_hw_scaler3_lut_cfg *scl3_lut_cfg = scaler_lut_cfg;

	if (!hw_ds || !hw_ds->scl || !scl3_cfg || !scl3_lut_cfg)
		return;

	/*
	 * copy LUT values to scaler structure
	 */
	if (scl3_lut_cfg->is_configured) {
		scl3_cfg->dir_lut = scl3_lut_cfg->dir_lut;
		scl3_cfg->dir_len = scl3_lut_cfg->dir_len;
		scl3_cfg->cir_lut = scl3_lut_cfg->cir_lut;
		scl3_cfg->cir_len = scl3_lut_cfg->cir_len;
		scl3_cfg->sep_lut = scl3_lut_cfg->sep_lut;
		scl3_cfg->sep_len = scl3_lut_cfg->sep_len;
	}

	dpu_hw_setup_scaler3(&hw_ds->hw, scl3_cfg,
			 hw_ds->scl->base,
			 hw_ds->scl->version,
			 dpu_get_dpu_format(DRM_FORMAT_XBGR2101010));
}

static void _setup_ds_ops(struct dpu_hw_ds_ops *ops, unsigned long features)
{
	ops->setup_opmode = dpu_hw_ds_setup_opmode;

	if (test_bit(DPU_SSPP_SCALER_QSEED3, &features))
		ops->setup_scaler = dpu_hw_ds_setup_scaler3;
}

static struct dpu_ds_cfg *_ds_offset(enum dpu_ds ds,
		struct dpu_mdss_cfg *m,
		void __iomem *addr,
		struct dpu_hw_blk_reg_map *b)
{
	int i;

	if (!m || !addr || !b)
		return ERR_PTR(-EINVAL);

	for (i = 0; i < m->ds_count; i++) {
		if ((ds == m->ds[i].id) &&
			 (m->ds[i].top)) {
			b->base_off = addr;
			b->blk_off = m->ds[i].top->base;
			b->length = m->ds[i].top->len;
			b->hwversion = m->hwversion;
			b->log_mask = DPU_DBG_MASK_DS;
			return &m->ds[i];
		}
	}

	return ERR_PTR(-EINVAL);
}

static struct dpu_hw_blk_ops dpu_hw_ops = {
	.start = NULL,
	.stop = NULL,
};

struct dpu_hw_ds *dpu_hw_ds_init(enum dpu_ds idx,
			void __iomem *addr,
			struct dpu_mdss_cfg *m)
{
	struct dpu_hw_ds *hw_ds;
	struct dpu_ds_cfg *cfg;
	int rc;

	if (!addr || !m)
		return ERR_PTR(-EINVAL);

	hw_ds = kzalloc(sizeof(*hw_ds), GFP_KERNEL);
	if (!hw_ds)
		return ERR_PTR(-ENOMEM);

	cfg = _ds_offset(idx, m, addr, &hw_ds->hw);
	if (IS_ERR_OR_NULL(cfg)) {
		DPU_ERROR("failed to get ds cfg\n");
		kfree(hw_ds);
		return ERR_PTR(-EINVAL);
	}

	/* Assign ops */
	hw_ds->idx = idx;
	hw_ds->scl = cfg;
	_setup_ds_ops(&hw_ds->ops, hw_ds->scl->features);

	rc = dpu_hw_blk_init(&hw_ds->base, DPU_HW_BLK_DS, idx, &dpu_hw_ops);
	if (rc) {
		DPU_ERROR("failed to init hw blk %d\n", rc);
		goto blk_init_error;
	}

	if (cfg->len) {
		dpu_dbg_reg_register_dump_range(DPU_DBG_NAME, cfg->name,
				hw_ds->hw.blk_off + cfg->base,
				hw_ds->hw.blk_off + cfg->base + cfg->len,
				hw_ds->hw.xin_id);
	}

	return hw_ds;

blk_init_error:
	kzfree(hw_ds);

	return ERR_PTR(rc);

}

void dpu_hw_ds_destroy(struct dpu_hw_ds *hw_ds)
{
	if (hw_ds)
		dpu_hw_blk_destroy(&hw_ds->base);
	kfree(hw_ds);
}
