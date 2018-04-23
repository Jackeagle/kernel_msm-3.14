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
#ifndef _DPU_HW_COLOR_PROC_V4_H_
#define _DPU_HW_COLOR_PROC_V4_H_

#include "dpu_hw_util.h"
#include "dpu_hw_catalog.h"
#include "dpu_hw_dspp.h"
/**
 * dpu_setup_dspp_3d_gamutv4 - Function for 3d gamut v4 version feature
 *                             programming.
 * @ctx: dspp ctx pointer
 * @cfg: pointer to dpu_hw_cp_cfg
 */
void dpu_setup_dspp_3d_gamutv4(struct dpu_hw_dspp *ctx, void *cfg);
/**
 * dpu_setup_dspp_igcv3 - Function for igc v3 version feature
 *                             programming.
 * @ctx: dspp ctx pointer
 * @cfg: pointer to dpu_hw_cp_cfg
 */
void dpu_setup_dspp_igcv3(struct dpu_hw_dspp *ctx, void *cfg);
/**
 * dpu_setup_dspp_pccv4 - Function for pcc v4 version feature
 *                             programming.
 * @ctx: dspp ctx pointer
 * @cfg: pointer to dpu_hw_cp_cfg
 */
void dpu_setup_dspp_pccv4(struct dpu_hw_dspp *ctx, void *cfg);

#endif /* _DPU_HW_COLOR_PROC_V4_H_ */
