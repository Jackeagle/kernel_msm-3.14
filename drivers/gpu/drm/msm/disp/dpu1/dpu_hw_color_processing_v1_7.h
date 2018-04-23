/* Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
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

#ifndef _DPU_HW_COLOR_PROCESSING_V1_7_H
#define _DPU_HW_COLOR_PROCESSING_V1_7_H

#include "dpu_hw_sspp.h"
#include "dpu_hw_dspp.h"

/**
 * dpu_setup_pipe_pa_hue_v1_7 - setup SSPP hue feature in v1.7 hardware
 * @ctx: Pointer to pipe context
 * @cfg: Pointer to hue data
 */
void dpu_setup_pipe_pa_hue_v1_7(struct dpu_hw_pipe *ctx, void *cfg);

/**
 * dpu_setup_pipe_pa_sat_v1_7 - setup SSPP saturation feature in v1.7 hardware
 * @ctx: Pointer to pipe context
 * @cfg: Pointer to saturation data
 */
void dpu_setup_pipe_pa_sat_v1_7(struct dpu_hw_pipe *ctx, void *cfg);

/**
 * dpu_setup_pipe_pa_val_v1_7 - setup SSPP value feature in v1.7 hardware
 * @ctx: Pointer to pipe context
 * @cfg: Pointer to value data
 */
void dpu_setup_pipe_pa_val_v1_7(struct dpu_hw_pipe *ctx, void *cfg);

/**
 * dpu_setup_pipe_pa_cont_v1_7 - setup SSPP contrast feature in v1.7 hardware
 * @ctx: Pointer to pipe context
 * @cfg: Pointer to contrast data
 */
void dpu_setup_pipe_pa_cont_v1_7(struct dpu_hw_pipe *ctx, void *cfg);

/**
 * dpu_setup_pipe_pa_memcol_v1_7 - setup SSPP memory color in v1.7 hardware
 * @ctx: Pointer to pipe context
 * @type: Memory color type (Skin, sky, or foliage)
 * @cfg: Pointer to memory color config data
 */
void dpu_setup_pipe_pa_memcol_v1_7(struct dpu_hw_pipe *ctx,
				   enum dpu_memcolor_type type,
				   void *cfg);

/**
 * dpu_setup_dspp_pcc_v1_7 - setup DSPP PCC veature in v1.7 hardware
 * @ctx: Pointer to dspp context
 * @cfg: Pointer to PCC data
 */
void dpu_setup_dspp_pcc_v1_7(struct dpu_hw_dspp *ctx, void *cfg);

/**
 * dpu_setup_dspp_pa_hue_v1_7 - setup DSPP hue feature in v1.7 hardware
 * @ctx: Pointer to DSPP context
 * @cfg: Pointer to hue data
 */
void dpu_setup_dspp_pa_hue_v1_7(struct dpu_hw_dspp *ctx, void *cfg);

/**
 * dpu_setup_dspp_pa_vlut_v1_7 - setup DSPP PA vLUT feature in v1.7 hardware
 * @ctx: Pointer to DSPP context
 * @cfg: Pointer to vLUT data
 */
void dpu_setup_dspp_pa_vlut_v1_7(struct dpu_hw_dspp *ctx, void *cfg);

/**
 * dpu_setup_dspp_pa_vlut_v1_8 - setup DSPP PA vLUT feature in v1.8 hardware
 * @ctx: Pointer to DSPP context
 * @cfg: Pointer to vLUT data
 */
void dpu_setup_dspp_pa_vlut_v1_8(struct dpu_hw_dspp *ctx, void *cfg);

/**
 * dpu_setup_dspp_gc_v1_7 - setup DSPP gc feature in v1.7 hardware
 * @ctx: Pointer to DSPP context
 * @cfg: Pointer to gc data
 */
void dpu_setup_dspp_gc_v1_7(struct dpu_hw_dspp *ctx, void *cfg);

#endif
