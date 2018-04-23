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
#include <drm/msm_drm_pp.h>
#include "dpu_hw_color_proc_common_v4.h"
#include "dpu_hw_color_proc_v4.h"

static int dpu_write_3d_gamut(struct dpu_hw_blk_reg_map *hw,
		struct drm_msm_3d_gamut *payload, u32 base,
		u32 *opcode)
{
	u32 reg, tbl_len, tbl_off, scale_off, i, j;
	u32 scale_tbl_len, scale_tbl_off;
	u32 *scale_data;

	if (!payload || !opcode || !hw) {
		DRM_ERROR("invalid payload %pK opcode %pK hw %pK\n",
			payload, opcode, hw);
		return -EINVAL;
	}

	switch (payload->mode) {
	case GAMUT_3D_MODE_17:
		tbl_len = GAMUT_3D_MODE17_TBL_SZ;
		tbl_off = 0;
		scale_off = GAMUT_SCALEA_OFFSET_OFF;
		*opcode = gamut_mode_17 << 2;
		break;
	case GAMUT_3D_MODE_13:
		*opcode = (*opcode & (BIT(4) - 1)) >> 2;
		if (*opcode == gamut_mode_13a)
			*opcode = gamut_mode_13b;
		else
			*opcode = gamut_mode_13a;
		tbl_len = GAMUT_3D_MODE13_TBL_SZ;
		tbl_off = (*opcode == gamut_mode_13a) ? 0 :
			GAMUT_MODE_13B_OFF;
		scale_off = (*opcode == gamut_mode_13a) ?
			GAMUT_SCALEA_OFFSET_OFF : GAMUT_SCALEB_OFFSET_OFF;
		*opcode <<= 2;
		break;
	case GAMUT_3D_MODE_5:
		*opcode = gamut_mode_5 << 2;
		tbl_len = GAMUT_3D_MODE5_TBL_SZ;
		tbl_off = GAMUT_MODE_5_OFF;
		scale_off = GAMUT_SCALEB_OFFSET_OFF;
		break;
	default:
		DRM_ERROR("invalid mode %d\n", payload->mode);
		return -EINVAL;
	}

	if (payload->flags & GAMUT_3D_MAP_EN)
		*opcode |= GAMUT_MAP_EN;
	*opcode |= GAMUT_EN;

	for (i = 0; i < GAMUT_3D_TBL_NUM; i++) {
		reg = GAMUT_TABLE0_SEL << i;
		reg |= ((tbl_off) & (BIT(11) - 1));
		DPU_REG_WRITE(hw, base + GAMUT_TABLE_SEL_OFF, reg);
		for (j = 0; j < tbl_len; j++) {
			DPU_REG_WRITE(hw, base + GAMUT_LOWER_COLOR_OFF,
					payload->col[i][j].c2_c1);
			DPU_REG_WRITE(hw, base + GAMUT_UPPER_COLOR_OFF,
					payload->col[i][j].c0);
		}
	}

	if ((*opcode & GAMUT_MAP_EN)) {
		if (scale_off == GAMUT_SCALEA_OFFSET_OFF)
			scale_tbl_len = GAMUT_3D_SCALE_OFF_SZ;
		else
			scale_tbl_len = GAMUT_3D_SCALEB_OFF_SZ;
		for (i = 0; i < GAMUT_3D_SCALE_OFF_TBL_NUM; i++) {
			scale_tbl_off = base + scale_off +
					i * scale_tbl_len * sizeof(u32);
			scale_data = &payload->scale_off[i][0];
			for (j = 0; j < scale_tbl_len; j++)
				DPU_REG_WRITE(hw,
					scale_tbl_off + (j * sizeof(u32)),
					scale_data[j]);
		}
	}
	DPU_REG_WRITE(hw, base, *opcode);
	return 0;
}

void dpu_setup_dspp_3d_gamutv4(struct dpu_hw_dspp *ctx, void *cfg)
{
	struct drm_msm_3d_gamut *payload;
	struct dpu_hw_cp_cfg *hw_cfg = cfg;
	u32 op_mode;

	if (!ctx || !cfg) {
		DRM_ERROR("invalid param ctx %pK cfg %pK\n", ctx, cfg);
		return;
	}

	op_mode = DPU_REG_READ(&ctx->hw, ctx->cap->sblk->gamut.base);
	if (!hw_cfg->payload) {
		DRM_DEBUG_DRIVER("disable gamut feature\n");
		DPU_REG_WRITE(&ctx->hw, ctx->cap->sblk->gamut.base, 0);
		return;
	}

	payload = hw_cfg->payload;
	dpu_write_3d_gamut(&ctx->hw, payload, ctx->cap->sblk->gamut.base,
		&op_mode);

}

void dpu_setup_dspp_igcv3(struct dpu_hw_dspp *ctx, void *cfg)
{
	struct drm_msm_igc_lut *lut_cfg;
	struct dpu_hw_cp_cfg *hw_cfg = cfg;
	int i = 0, j = 0;
	u32 *addr = NULL;
	u32 offset = 0;

	if (!ctx || !cfg) {
		DRM_ERROR("invalid param ctx %pK cfg %pK\n", ctx, cfg);
		return;
	}

	if (!hw_cfg->payload) {
		DRM_DEBUG_DRIVER("disable igc feature\n");
		DPU_REG_WRITE(&ctx->hw, IGC_OPMODE_OFF, 0);
		return;
	}

	if (hw_cfg->len != sizeof(struct drm_msm_igc_lut)) {
		DRM_ERROR("invalid size of payload len %d exp %zd\n",
				hw_cfg->len, sizeof(struct drm_msm_igc_lut));
		return;
	}

	lut_cfg = hw_cfg->payload;

	for (i = 0; i < IGC_TBL_NUM; i++) {
		addr = lut_cfg->c0 + (i * ARRAY_SIZE(lut_cfg->c0));
		offset = IGC_C0_OFF + (i * sizeof(u32));

		for (j = 0; j < IGC_TBL_LEN; j++) {
			addr[j] &= IGC_DATA_MASK;
			addr[j] |= IGC_DSPP_SEL_MASK(ctx->idx - 1);
			if (j == 0)
				addr[j] |= IGC_INDEX_UPDATE;
			/* IGC lut registers are part of DSPP Top HW block */
			DPU_REG_WRITE(&ctx->hw_top, offset, addr[j]);
		}
	}

	if (lut_cfg->flags & IGC_DITHER_ENABLE) {
		DPU_REG_WRITE(&ctx->hw, IGC_DITHER_OFF,
			lut_cfg->strength & IGC_DITHER_DATA_MASK);
	}

	DPU_REG_WRITE(&ctx->hw, IGC_OPMODE_OFF, IGC_EN);
}

void dpu_setup_dspp_pccv4(struct dpu_hw_dspp *ctx, void *cfg)
{
	struct dpu_hw_cp_cfg *hw_cfg = cfg;
	struct drm_msm_pcc *pcc_cfg;
	struct drm_msm_pcc_coeff *coeffs = NULL;
	int i = 0;
	u32 base = 0;

	if (!ctx || !cfg) {
		DRM_ERROR("invalid param ctx %pK cfg %pK\n", ctx, cfg);
		return;
	}

	if (!hw_cfg->payload) {
		DRM_DEBUG_DRIVER("disable pcc feature\n");
		DPU_REG_WRITE(&ctx->hw, ctx->cap->sblk->pcc.base, 0);
		return;
	}

	if (hw_cfg->len != sizeof(struct drm_msm_pcc)) {
		DRM_ERROR("invalid size of payload len %d exp %zd\n",
				hw_cfg->len, sizeof(struct drm_msm_pcc));
		return;
	}

	pcc_cfg = hw_cfg->payload;

	for (i = 0; i < PCC_NUM_PLANES; i++) {
		base = ctx->cap->sblk->pcc.base + (i * sizeof(u32));
		switch (i) {
		case 0:
			coeffs = &pcc_cfg->r;
			DPU_REG_WRITE(&ctx->hw,
				base + PCC_RR_OFF, pcc_cfg->r_rr);
			DPU_REG_WRITE(&ctx->hw,
				base + PCC_GG_OFF, pcc_cfg->r_gg);
			DPU_REG_WRITE(&ctx->hw,
				base + PCC_BB_OFF, pcc_cfg->r_bb);
			break;
		case 1:
			coeffs = &pcc_cfg->g;
			DPU_REG_WRITE(&ctx->hw,
				base + PCC_RR_OFF, pcc_cfg->g_rr);
			DPU_REG_WRITE(&ctx->hw,
				base + PCC_GG_OFF, pcc_cfg->g_gg);
			DPU_REG_WRITE(&ctx->hw,
				base + PCC_BB_OFF, pcc_cfg->g_bb);
			break;
		case 2:
			coeffs = &pcc_cfg->b;
			DPU_REG_WRITE(&ctx->hw,
				base + PCC_RR_OFF, pcc_cfg->b_rr);
			DPU_REG_WRITE(&ctx->hw,
				base + PCC_GG_OFF, pcc_cfg->b_gg);
			DPU_REG_WRITE(&ctx->hw,
				base + PCC_BB_OFF, pcc_cfg->b_bb);
			break;
		default:
			DRM_ERROR("invalid pcc plane: %d\n", i);
			return;
		}

		DPU_REG_WRITE(&ctx->hw, base + PCC_C_OFF, coeffs->c);
		DPU_REG_WRITE(&ctx->hw, base + PCC_R_OFF, coeffs->r);
		DPU_REG_WRITE(&ctx->hw, base + PCC_G_OFF, coeffs->g);
		DPU_REG_WRITE(&ctx->hw, base + PCC_B_OFF, coeffs->b);
		DPU_REG_WRITE(&ctx->hw, base + PCC_RG_OFF, coeffs->rg);
		DPU_REG_WRITE(&ctx->hw, base + PCC_RB_OFF, coeffs->rb);
		DPU_REG_WRITE(&ctx->hw, base + PCC_GB_OFF, coeffs->gb);
		DPU_REG_WRITE(&ctx->hw, base + PCC_RGB_OFF, coeffs->rgb);
	}

	DPU_REG_WRITE(&ctx->hw, ctx->cap->sblk->pcc.base, PCC_EN);
}
