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

#ifndef _DPU_HW_DS_H
#define _DPU_HW_DS_H

#include "dpu_hw_mdss.h"
#include "dpu_hw_util.h"
#include "dpu_hw_catalog.h"
#include "dpu_hw_blk.h"

struct dpu_hw_ds;

/* Destination Scaler DUAL mode overfetch pixel count */
#define DPU_DS_OVERFETCH_SIZE 5

/* Destination scaler DUAL mode operation bit */
#define DPU_DS_OP_MODE_DUAL BIT(16)

/* struct dpu_hw_ds_cfg - destination scaler config
 * @ndx          : DS selection index
 * @flags        : Flag to switch between mode for DS
 * @lm_width     : Layer mixer width configuration
 * @lm_heigh     : Layer mixer height configuration
 * @set_lm_flush : LM flush bit
 * @scl3_cfg     : Pointer to dpu_hw_scaler3_cfg.
 */
struct dpu_hw_ds_cfg {
	u32 ndx;
	int flags;
	u32 lm_width;
	u32 lm_height;
	bool set_lm_flush;
	struct dpu_hw_scaler3_cfg *scl3_cfg;
};

/**
 * struct dpu_hw_ds_ops - interface to the destination scaler
 * hardware driver functions
 * Caller must call the init function to get the ds context for each ds
 * Assumption is these functions will be called after clocks are enabled
 */
struct dpu_hw_ds_ops {
	/**
	 * setup_opmode - destination scaler op mode setup
	 * @hw_ds   : Pointer to ds context
	 * @op_mode : Op mode configuration
	 */
	void (*setup_opmode)(struct dpu_hw_ds *hw_ds,
				u32 op_mode);

	/**
	 * setup_scaler - destination scaler block setup
	 * @hw_ds          : Pointer to ds context
	 * @scaler_cfg     : Pointer to scaler data
	 * @scaler_lut_cfg : Pointer to scaler lut
	 */
	void (*setup_scaler)(struct dpu_hw_ds *hw_ds,
				void *scaler_cfg,
				void *scaler_lut_cfg);

};

/**
 * struct dpu_hw_ds - destination scaler description
 * @base : Hardware block base structure
 * @hw   : Block hardware details
 * @idx  : Destination scaler index
 * @scl  : Pointer to
 *          - scaler offset relative to top offset
 *          - capabilities
 * @ops  : Pointer to operations for this DS
 */
struct dpu_hw_ds {
	struct dpu_hw_blk base;
	struct dpu_hw_blk_reg_map hw;
	enum dpu_ds idx;
	const struct dpu_ds_cfg *scl;
	struct dpu_hw_ds_ops ops;
};

/**
 * dpu_hw_ds_init - initializes the destination scaler
 * hw driver object and should be called once before
 * accessing every destination scaler
 * @idx : DS index for which driver object is required
 * @addr: Mapped register io address of MDP
 * @m   : MDSS catalog information
 * @Return: pointer to structure or ERR_PTR
 */
struct dpu_hw_ds *dpu_hw_ds_init(enum dpu_ds idx,
			void __iomem *addr,
			struct dpu_mdss_cfg *m);

/**
 * dpu_hw_ds_destroy - destroys destination scaler
 * driver context
 * @hw_ds:   Pointer to DS context
 */
void dpu_hw_ds_destroy(struct dpu_hw_ds *hw_ds);

#endif /*_DPU_HW_DS_H */
