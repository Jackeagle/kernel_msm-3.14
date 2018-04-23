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

#ifndef _DPU_HW_WB_H
#define _DPU_HW_WB_H

#include "dpu_hw_catalog.h"
#include "dpu_hw_mdss.h"
#include "dpu_hw_top.h"
#include "dpu_hw_util.h"

struct dpu_hw_wb;

struct dpu_hw_wb_cfg {
	struct dpu_hw_fmt_layout dest;
	enum dpu_intf_mode intf_mode;
	struct traffic_shaper_cfg ts_cfg;
	struct dpu_rect roi;
};

/**
 * enum CDP preload ahead address size
 */
enum {
	DPU_WB_CDP_PRELOAD_AHEAD_32,
	DPU_WB_CDP_PRELOAD_AHEAD_64
};

/**
 * struct dpu_hw_wb_cdp_cfg : CDP configuration
 * @enable: true to enable CDP
 * @ubwc_meta_enable: true to enable ubwc metadata preload
 * @tile_amortize_enable: true to enable amortization control for tile format
 * @preload_ahead: number of request to preload ahead
 *	DPU_WB_CDP_PRELOAD_AHEAD_32,
 *	DPU_WB_CDP_PRELOAD_AHEAD_64
 */
struct dpu_hw_wb_cdp_cfg {
	bool enable;
	bool ubwc_meta_enable;
	bool tile_amortize_enable;
	u32 preload_ahead;
};

/**
 * struct dpu_hw_wb_qos_cfg : Writeback pipe QoS configuration
 * @danger_lut: LUT for generate danger level based on fill level
 * @safe_lut: LUT for generate safe level based on fill level
 * @creq_lut: LUT for generate creq level based on fill level
 * @danger_safe_en: enable danger safe generation
 */
struct dpu_hw_wb_qos_cfg {
	u32 danger_lut;
	u32 safe_lut;
	u64 creq_lut;
	bool danger_safe_en;
};

/**
 *
 * struct dpu_hw_wb_ops : Interface to the wb Hw driver functions
 *  Assumption is these functions will be called after clocks are enabled
 */
struct dpu_hw_wb_ops {
	void (*setup_csc_data)(struct dpu_hw_wb *ctx,
			struct dpu_csc_cfg *data);

	void (*setup_outaddress)(struct dpu_hw_wb *ctx,
		struct dpu_hw_wb_cfg *wb);

	void (*setup_outformat)(struct dpu_hw_wb *ctx,
		struct dpu_hw_wb_cfg *wb);

	void (*setup_rotator)(struct dpu_hw_wb *ctx,
		struct dpu_hw_wb_cfg *wb);

	void (*setup_dither)(struct dpu_hw_wb *ctx,
		struct dpu_hw_wb_cfg *wb);

	void (*setup_cdwn)(struct dpu_hw_wb *ctx,
		struct dpu_hw_wb_cfg *wb);

	void (*setup_trafficshaper)(struct dpu_hw_wb *ctx,
		struct dpu_hw_wb_cfg *wb);

	void (*setup_roi)(struct dpu_hw_wb *ctx,
		struct dpu_hw_wb_cfg *wb);

	/**
	 * setup_danger_safe_lut - setup danger safe LUTs
	 * @ctx: Pointer to pipe context
	 * @cfg: Pointer to pipe QoS configuration
	 */
	void (*setup_danger_safe_lut)(struct dpu_hw_wb *ctx,
			struct dpu_hw_wb_qos_cfg *cfg);

	/**
	 * setup_creq_lut - setup CREQ LUT
	 * @ctx: Pointer to pipe context
	 * @cfg: Pointer to pipe QoS configuration
	 */
	void (*setup_creq_lut)(struct dpu_hw_wb *ctx,
			struct dpu_hw_wb_qos_cfg *cfg);

	/**
	 * setup_qos_ctrl - setup QoS control
	 * @ctx: Pointer to pipe context
	 * @cfg: Pointer to pipe QoS configuration
	 */
	void (*setup_qos_ctrl)(struct dpu_hw_wb *ctx,
			struct dpu_hw_wb_qos_cfg *cfg);

	/**
	 * setup_cdp - setup CDP
	 * @ctx: Pointer to pipe context
	 * @cfg: Pointer to pipe CDP configuration
	 */
	void (*setup_cdp)(struct dpu_hw_wb *ctx,
			struct dpu_hw_wb_cdp_cfg *cfg);
};

/**
 * struct dpu_hw_wb : WB driver object
 * @base: hardware block base structure
 * @hw: block hardware details
 * @catalog: back pointer to catalog
 * @mdp: pointer to associated mdp portion of the catalog
 * @idx: hardware index number within type
 * @wb_hw_caps: hardware capabilities
 * @ops: function pointers
 * @hw_mdp: MDP top level hardware block
 */
struct dpu_hw_wb {
	struct dpu_hw_blk base;
	struct dpu_hw_blk_reg_map hw;
	struct dpu_mdss_cfg *catalog;
	struct dpu_mdp_cfg *mdp;

	/* wb path */
	int idx;
	const struct dpu_wb_cfg *caps;

	/* ops */
	struct dpu_hw_wb_ops ops;

	struct dpu_hw_mdp *hw_mdp;
};

/**
 * dpu_hw_wb - convert base object dpu_hw_base to container
 * @hw: Pointer to base hardware block
 * return: Pointer to hardware block container
 */
static inline struct dpu_hw_wb *to_dpu_hw_wb(struct dpu_hw_blk *hw)
{
	return container_of(hw, struct dpu_hw_wb, base);
}

/**
 * dpu_hw_wb_init(): Initializes and return writeback hw driver object.
 * @idx:  wb_path index for which driver object is required
 * @addr: mapped register io address of MDP
 * @m :   pointer to mdss catalog data
 * @hw_mdp: pointer to mdp top hw driver object
 */
struct dpu_hw_wb *dpu_hw_wb_init(enum dpu_wb idx,
		void __iomem *addr,
		struct dpu_mdss_cfg *m,
		struct dpu_hw_mdp *hw_mdp);

/**
 * dpu_hw_wb_destroy(): Destroy writeback hw driver object.
 * @hw_wb:  Pointer to writeback hw driver object
 */
void dpu_hw_wb_destroy(struct dpu_hw_wb *hw_wb);

#endif /*_DPU_HW_WB_H */
