// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018 Linaro Ltd.
 *
 * Author: Stanimir Varbanov <stanimir.varbanov@linaro.org>
 */
#include <linux/kernel.h>

#include "core.h"
#include "hfi_helper.h"
#include "hfi_parser.h"

typedef void (*func)(struct venus_caps *cap, void *data, unsigned int size);

static void init_codecs_vcaps(struct venus_core *core)
{
	struct venus_caps *caps = core->caps;
	struct venus_caps *cap;
	unsigned int i;

	for (i = 0; i < 8 * sizeof(core->dec_codecs); i++) {
		if ((1 << i) & core->dec_codecs) {
			cap = &caps[core->codecs_count++];
			cap->codec = (1 << i) & core->dec_codecs;
			cap->domain = VIDC_SESSION_TYPE_DEC;
			cap->valid = false;
		}
	}

	for (i = 0; i < 8 * sizeof(core->enc_codecs); i++) {
		if ((1 << i) & core->enc_codecs) {
			cap = &caps[core->codecs_count++];
			cap->codec = (1 << i) & core->enc_codecs;
			cap->domain = VIDC_SESSION_TYPE_ENC;
			cap->valid = false;
		}
	}
}

static void for_each_codec(struct venus_caps *caps, unsigned int caps_num,
			   u32 codecs, u32 domain, func cb, void *data,
			   unsigned int size)
{
	struct venus_caps *cap;
	unsigned int i;

	for (i = 0; i < caps_num; i++) {
		cap = &caps[i];
		if (cap->valid && cap->domain == domain)
			continue;
		if (cap->codec & codecs && cap->domain == domain)
			cb(cap, data, size);
	}
}

static void fill_buf_mode(struct venus_caps *cap, void *data, unsigned int num)
{
	u32 *type = data;

	if (*type == HFI_BUFFER_MODE_DYNAMIC)
		cap->cap_bufs_mode_dynamic = true;
}

static void parse_alloc_mode(struct venus_core *core, struct venus_inst *inst,
			     u32 codecs, u32 domain, void *data)
{
	struct hfi_buffer_alloc_mode_supported *mode = data;
	u32 num_entries = mode->num_entries;
	u32 *type;

	if (num_entries > 16)
		return;

	type = mode->data;

	while (num_entries--) {
		if (mode->buffer_type == HFI_BUFFER_OUTPUT ||
		    mode->buffer_type == HFI_BUFFER_OUTPUT2)
			for_each_codec(core->caps, ARRAY_SIZE(core->caps),
				       codecs, domain, fill_buf_mode, type, 1);

		type++;
	}
}

static void parse_profile_level(u32 codecs, u32 domain, void *data)
{
	struct hfi_profile_level_supported *pl = data;
	struct hfi_profile_level *proflevel = pl->profile_level;
	u32 count = pl->profile_count;

	if (count > HFI_MAX_PROFILE_COUNT)
		return;

	while (count) {
		proflevel = (void *)proflevel + sizeof(*proflevel);
		count--;
	}
}

static void fill_caps(struct venus_caps *cap, void *data, unsigned int num)
{
	struct hfi_capability *caps = data;
	unsigned int i;

	for (i = 0; i < num; i++)
		cap->caps[cap->num_caps++] = caps[i];
}

static void parse_caps(struct venus_core *core, struct venus_inst *inst,
		       u32 codecs, u32 domain, void *data)
{
	struct hfi_capabilities *caps = data;
	struct hfi_capability *cap = caps->data;
	u32 num_caps = caps->num_capabilities;
	struct hfi_capability caps_arr[MAX_CAP_ENTRIES] = {};
	unsigned int i = 0;

	if (num_caps > MAX_CAP_ENTRIES)
		return;

	while (num_caps) {
		caps_arr[i++] = *cap;
		cap = (void *)cap + sizeof(*cap);
		num_caps--;
	}

	for_each_codec(core->caps, ARRAY_SIZE(core->caps), codecs, domain,
		       fill_caps, caps_arr, i);
}

static void fill_raw_fmts(struct venus_caps *cap, void *fmts,
			  unsigned int num_fmts)
{
	struct raw_formats *formats = fmts;
	unsigned int i;

	for (i = 0; i < num_fmts; i++)
		cap->fmts[cap->num_fmts++] = formats[i];
}

static void parse_raw_formats(struct venus_core *core, struct venus_inst *inst,
			      u32 codecs, u32 domain, void *data)
{
	struct hfi_uncompressed_format_supported *fmt = data;
	struct hfi_uncompressed_plane_info *pinfo = fmt->format_info;
	struct hfi_uncompressed_plane_constraints *constr;
	u32 entries = fmt->format_entries;
	u32 num_planes;
	struct raw_formats rfmts[MAX_FMT_ENTRIES] = {};
	unsigned int i = 0;

	while (entries) {
		num_planes = pinfo->num_planes;

		rfmts[i].fmt = pinfo->format;
		rfmts[i].buftype = fmt->buffer_type;
		i++;

		if (pinfo->num_planes > MAX_PLANES)
			break;

		constr = pinfo->plane_format;

		while (pinfo->num_planes) {
			constr = (void *)constr + sizeof(*constr);
			pinfo->num_planes--;
		}

		pinfo = (void *)pinfo + sizeof(*constr) * num_planes +
			2 * sizeof(u32);
		entries--;
	}

	for_each_codec(core->caps, ARRAY_SIZE(core->caps), codecs, domain,
		       fill_raw_fmts, rfmts, i);
}

static void parse_codecs(struct venus_core *core, void *data)
{
	struct hfi_codec_supported *codecs = data;

	core->dec_codecs = codecs->dec_codecs;
	core->enc_codecs = codecs->enc_codecs;

	if (core->res->hfi_version == HFI_VERSION_1XX) {
		core->dec_codecs &= ~HFI_VIDEO_CODEC_HEVC;
		core->dec_codecs &= ~HFI_VIDEO_CODEC_SPARK;
	}
}

static void parse_max_sessions(struct venus_core *core, void *data)
{
	struct hfi_max_sessions_supported *sessions = data;

	core->max_sessions_supported = sessions->max_sessions;
}

static void parse_codecs_mask(u32 *codecs, u32 *domain, void *data)
{
	struct hfi_codec_mask_supported *mask = data;

	*codecs = mask->codecs;
	*domain = mask->video_domains;
}

static void parser_init(struct venus_core *core, struct venus_inst *inst,
			u32 *codecs, u32 *domain)
{
	if (core->res->hfi_version != HFI_VERSION_1XX)
		return;

	if (!inst)
		return;

	*codecs = inst->hfi_codec;
	*domain = inst->session_type;
}

static void parser_fini(struct venus_core *core, struct venus_inst *inst,
			u32 codecs, u32 domain)
{
	struct venus_caps *caps = core->caps;
	struct venus_caps *cap;
	u32 dom;
	unsigned int i;

	if (core->res->hfi_version != HFI_VERSION_1XX)
		return;

	if (!inst)
		return;

	dom = inst->session_type;

	for (i = 0; i < MAX_CODEC_NUM; i++) {
		cap = &caps[i];
		if (cap->codec & codecs && cap->domain == dom)
			cap->valid = true;
	}
}

u32 hfi_parser(struct venus_core *core, struct venus_inst *inst,
	       u32 num_properties, void *buf, u32 size)
{
	unsigned int words_count = size >> 2;
	u32 *word = buf, *data, codecs = 0, domain = 0;

	if (size % 4)
		return HFI_ERR_SYS_INSUFFICIENT_RESOURCES;

	parser_init(core, inst, &codecs, &domain);

	while (words_count) {
		data = word + 1;

		switch (*word) {
		case HFI_PROPERTY_PARAM_CODEC_SUPPORTED:
			parse_codecs(core, data);
			init_codecs_vcaps(core);
			break;
		case HFI_PROPERTY_PARAM_MAX_SESSIONS_SUPPORTED:
			parse_max_sessions(core, data);
			break;
		case HFI_PROPERTY_PARAM_CODEC_MASK_SUPPORTED:
			parse_codecs_mask(&codecs, &domain, data);
			break;
		case HFI_PROPERTY_PARAM_UNCOMPRESSED_FORMAT_SUPPORTED:
			parse_raw_formats(core, inst, codecs, domain, data);
			break;
		case HFI_PROPERTY_PARAM_CAPABILITY_SUPPORTED:
			parse_caps(core, inst, codecs, domain, data);
			break;
		case HFI_PROPERTY_PARAM_PROFILE_LEVEL_SUPPORTED:
			parse_profile_level(codecs, domain, data);
			break;
		case HFI_PROPERTY_PARAM_BUFFER_ALLOC_MODE_SUPPORTED:
			parse_alloc_mode(core, inst, codecs, domain, data);
			break;
		default:
			break;
		}

		word++;
		words_count--;
	}

	parser_fini(core, inst, codecs, domain);

	return HFI_ERR_NONE;
}
