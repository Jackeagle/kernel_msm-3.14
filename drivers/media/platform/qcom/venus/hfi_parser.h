/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018 Linaro Ltd. */
#ifndef __VENUS_HFI_PARSER_H__
#define __VENUS_HFI_PARSER_H__

#include "core.h"

u32 hfi_parser(struct venus_core *core, struct venus_inst *inst,
	       u32 num_properties, void *buf, u32 size);

static inline struct hfi_capability *get_cap(struct venus_inst *inst, u32 type)
{
	struct venus_core *core = inst->core;
	struct venus_caps *caps;
	unsigned int i;

	caps = venus_caps_by_codec(core, inst->hfi_codec, inst->session_type);
	if (!caps)
		return ERR_PTR(-EINVAL);

	for (i = 0; i < MAX_CAP_ENTRIES; i++) {
		if (caps->caps[i].capability_type == type)
			return &caps->caps[i];
	}

	return ERR_PTR(-EINVAL);
}

#define CAP_MIN(inst, type)	((get_cap(inst, type))->min)
#define CAP_MAX(inst, type)	((get_cap(inst, type))->max)
#define CAP_STEP(inst, type)	((get_cap(inst, type))->step_size)

#define FRAME_WIDTH_MIN(inst)	CAP_MIN(inst, HFI_CAPABILITY_FRAME_WIDTH)
#define FRAME_WIDTH_MAX(inst)	CAP_MAX(inst, HFI_CAPABILITY_FRAME_WIDTH)
#define FRAME_WIDTH_STEP(inst)	CAP_STEP(inst, HFI_CAPABILITY_FRAME_WIDTH)

#define FRAME_HEIGHT_MIN(inst)	CAP_MIN(inst, HFI_CAPABILITY_FRAME_HEIGHT)
#define FRAME_HEIGHT_MAX(inst)	CAP_MAX(inst, HFI_CAPABILITY_FRAME_HEIGHT)
#define FRAME_HEIGHT_STEP(inst)	CAP_STEP(inst, HFI_CAPABILITY_FRAME_HEIGHT)

#define FRATE_MIN(inst)		CAP_MIN(inst, HFI_CAPABILITY_FRAMERATE)
#define FRATE_MAX(inst)		CAP_MAX(inst, HFI_CAPABILITY_FRAMERATE)
#define FRATE_STEP(inst)	CAP_STEP(inst, HFI_CAPABILITY_FRAMERATE)

#endif
