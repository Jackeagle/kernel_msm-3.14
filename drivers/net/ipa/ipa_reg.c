// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#define pr_fmt(fmt)	"ipa_reg %s:%d " fmt, __func__, __LINE__

#include <linux/io.h>

#include "field_mask.h"
#include "ipa_reg.h"

/* I/O remapped base address of IPA register space */
static void __iomem *ipa_reg_virt;

/* struct ipa_reg_desc - descriptor for an abstracted hardware register
 *
 * @construct - fn to construct the register value from its field structure
 * @parse - function to parse register field values into its field structure
 * @offset - register offset relative to base address
 * @n_ofst - size multiplier for "N-parameterized" registers
 */
struct ipa_reg_desc {
	u32 (*construct)(enum ipa_reg reg, const void *fields);
	void (*parse)(enum ipa_reg reg, void *fields, u32 val);
	u32 offset;
	u16 n_ofst;
};

/* IPA_ROUTE register */
#define ROUTE_DIS_FMASK			0x00000001
#define ROUTE_DEF_PIPE_FMASK		0x0000003e
#define ROUTE_DEF_HDR_TABLE_FMASK	0x00000040
#define ROUTE_DEF_HDR_OFST_FMASK	0x0001ff80
#define ROUTE_FRAG_DEF_PIPE_FMASK	0x003e0000
#define ROUTE_DEF_RETAIN_HDR_FMASK	0x01000000

static u32 ipa_reg_construct_route(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_route *route = fields;
	u32 val;

	val = field_gen(route->route_dis, ROUTE_DIS_FMASK);
	val |= field_gen(route->route_def_pipe, ROUTE_DEF_PIPE_FMASK);
	val |= field_gen(route->route_def_hdr_table, ROUTE_DEF_HDR_TABLE_FMASK);
	val |= field_gen(route->route_def_hdr_ofst, ROUTE_DEF_HDR_OFST_FMASK);
	val |= field_gen(route->route_frag_def_pipe, ROUTE_FRAG_DEF_PIPE_FMASK);
	val |= field_gen(route->route_def_retain_hdr,
			 ROUTE_DEF_RETAIN_HDR_FMASK);

	return val;
}

/* IPA_ENDP_INIT_HDR_N register */

static void
ipa_reg_endp_init_hdr_common(struct ipa_reg_endp_init_hdr *init_hdr)
{
	init_hdr->hdr_additional_const_len = 0;	/* XXX description? */
	init_hdr->hdr_a5_mux = 0;		/* XXX description? */
	init_hdr->hdr_len_inc_deagg_hdr = 0;	/* XXX description? */
	init_hdr->hdr_metadata_reg_valid = 0;	/* XXX description? */
}

void ipa_reg_endp_init_hdr_cons(struct ipa_reg_endp_init_hdr *init_hdr,
				u32 header_size, u32 metadata_offset,
				u32 length_offset)
{
	init_hdr->hdr_len = header_size;
	init_hdr->hdr_ofst_metadata_valid = 1;
	init_hdr->hdr_ofst_metadata = metadata_offset;	/* XXX ignored */
	init_hdr->hdr_ofst_pkt_size_valid = 1;
	init_hdr->hdr_ofst_pkt_size = length_offset;

	ipa_reg_endp_init_hdr_common(init_hdr);
}

void ipa_reg_endp_init_hdr_prod(struct ipa_reg_endp_init_hdr *init_hdr,
				u32 header_size, u32 metadata_offset,
				u32 length_offset)
{
	init_hdr->hdr_len = header_size;
	init_hdr->hdr_ofst_metadata_valid = 1;
	init_hdr->hdr_ofst_metadata = metadata_offset;
	init_hdr->hdr_ofst_pkt_size_valid = 1;
	init_hdr->hdr_ofst_pkt_size = length_offset;	/* XXX ignored */

	ipa_reg_endp_init_hdr_common(init_hdr);
}

#define HDR_LEN_FMASK			0x0000003f
#define HDR_OFST_METADATA_VALID_FMASK	0x00000040
#define HDR_OFST_METADATA_FMASK		0x00001f80
#define HDR_ADDITIONAL_CONST_LEN_FMASK	0x0007e000
#define HDR_OFST_PKT_SIZE_VALID_FMASK	0x00080000
#define HDR_OFST_PKT_SIZE_FMASK		0x03f00000
#define HDR_A5_MUX_FMASK		0x04000000
#define HDR_LEN_INC_DEAGG_HDR_FMASK	0x08000000
#define HDR_METADATA_REG_VALID_FMASK	0x10000000

static u32
ipa_reg_construct_endp_init_hdr_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_endp_init_hdr *init_hdr = fields;
	u32 val;

	val = field_gen(init_hdr->hdr_len, HDR_LEN_FMASK);
	val |= field_gen(init_hdr->hdr_ofst_metadata_valid,
			 HDR_OFST_METADATA_VALID_FMASK);
	val |= field_gen(init_hdr->hdr_ofst_metadata, HDR_OFST_METADATA_FMASK);
	val |= field_gen(init_hdr->hdr_additional_const_len,
			 HDR_ADDITIONAL_CONST_LEN_FMASK);
	val |= field_gen(init_hdr->hdr_ofst_pkt_size_valid,
			 HDR_OFST_PKT_SIZE_VALID_FMASK);
	val |= field_gen(init_hdr->hdr_ofst_pkt_size, HDR_OFST_PKT_SIZE_FMASK);
	val |= field_gen(init_hdr->hdr_a5_mux, HDR_A5_MUX_FMASK);
	val |= field_gen(init_hdr->hdr_len_inc_deagg_hdr,
			 HDR_LEN_INC_DEAGG_HDR_FMASK);
	val |= field_gen(init_hdr->hdr_metadata_reg_valid,
			 HDR_METADATA_REG_VALID_FMASK);

	return val;
}

/* IPA_ENDP_INIT_HDR_EXT_N register */

void ipa_reg_endp_init_hdr_ext_common(struct ipa_reg_endp_init_hdr_ext *hdr_ext)
{
	hdr_ext->hdr_endianness = 1;			/* big endian */
	hdr_ext->hdr_total_len_or_pad_valid = 1;
	hdr_ext->hdr_total_len_or_pad = 0;		/* pad */
	hdr_ext->hdr_total_len_or_pad_offset = 0;	/* XXX description? */
}

void ipa_reg_endp_init_hdr_ext_cons(struct ipa_reg_endp_init_hdr_ext *hdr_ext,
				    u32 pad_align, bool pad_included)
{
	hdr_ext->hdr_payload_len_inc_padding = pad_included ? 1 : 0;
	hdr_ext->hdr_pad_to_alignment = pad_align;

	ipa_reg_endp_init_hdr_ext_common(hdr_ext);
}

void ipa_reg_endp_init_hdr_ext_prod(struct ipa_reg_endp_init_hdr_ext *hdr_ext,
				    u32 pad_align)
{
	hdr_ext->hdr_payload_len_inc_padding = 0;
	hdr_ext->hdr_pad_to_alignment = pad_align;	/* XXX ignored */

	ipa_reg_endp_init_hdr_ext_common(hdr_ext);
}

#define HDR_ENDIANNESS_FMASK			0x00000001
#define HDR_TOTAL_LEN_OR_PAD_VALID_FMASK	0x00000002
#define HDR_TOTAL_LEN_OR_PAD_FMASK		0x00000004
#define HDR_PAYLOAD_LEN_INC_PADDING_FMASK	0x00000008
#define HDR_TOTAL_LEN_OR_PAD_OFFSET_FMASK	0x000003f0
#define HDR_PAD_TO_ALIGNMENT_FMASK		0x00003c00

static u32
ipa_reg_construct_endp_init_hdr_ext_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_endp_init_hdr_ext *init_hdr_ext = fields;
	u32 val;

	/* 0 = little endian; 1 = big endian */
	val = field_gen(1, HDR_ENDIANNESS_FMASK);
	val |= field_gen(init_hdr_ext->hdr_total_len_or_pad_valid,
			 HDR_TOTAL_LEN_OR_PAD_VALID_FMASK);
	val |= field_gen(init_hdr_ext->hdr_total_len_or_pad,
			 HDR_TOTAL_LEN_OR_PAD_FMASK);
	val |= field_gen(init_hdr_ext->hdr_payload_len_inc_padding,
			 HDR_PAYLOAD_LEN_INC_PADDING_FMASK);
	val |= field_gen(0, HDR_TOTAL_LEN_OR_PAD_OFFSET_FMASK);
	val |= field_gen(init_hdr_ext->hdr_pad_to_alignment,
			 HDR_PAD_TO_ALIGNMENT_FMASK);

	return val;
}

/* IPA_ENDP_INIT_AGGR_N register */

static void
ipa_reg_endp_init_aggr_common(struct ipa_reg_endp_init_aggr *init_aggr)
{
	init_aggr->aggr_force_close = 0;	/* XXX description?  */
	init_aggr->aggr_hard_byte_limit_en = 0;	/* XXX ignored for PROD? */
}

void ipa_reg_endp_init_aggr_cons(struct ipa_reg_endp_init_aggr *init_aggr,
				 u32 byte_limit, u32 packet_limit,
				 bool close_on_eof)
{
	init_aggr->aggr_en = IPA_ENABLE_AGGR;
	init_aggr->aggr_type = IPA_GENERIC;
	init_aggr->aggr_byte_limit = byte_limit;
	init_aggr->aggr_time_limit = IPA_AGGR_TIME_LIMIT_DEFAULT;
	init_aggr->aggr_pkt_limit = packet_limit;
	init_aggr->aggr_sw_eof_active = close_on_eof ? 1 : 0;

	ipa_reg_endp_init_aggr_common(init_aggr);
}

void ipa_reg_endp_init_aggr_prod(struct ipa_reg_endp_init_aggr *init_aggr,
				 enum ipa_aggr_en aggr_en,
				 enum ipa_aggr_type aggr_type)
{
	init_aggr->aggr_en = (u32)aggr_en;
	init_aggr->aggr_type = aggr_en == IPA_BYPASS_AGGR ? 0 : (u32)aggr_type;
	init_aggr->aggr_byte_limit = 0;		/* ignored */
	init_aggr->aggr_time_limit = 0;		/* ignored */
	init_aggr->aggr_pkt_limit = 0;		/* ignored */
	init_aggr->aggr_sw_eof_active = 0;	/* ignored */

	ipa_reg_endp_init_aggr_common(init_aggr);
}

#define AGGR_EN_FMASK				0x00000003
#define AGGR_TYPE_FMASK				0x0000001c
#define AGGR_BYTE_LIMIT_FMASK			0x000003e0
#define AGGR_TIME_LIMIT_FMASK			0x00007c00
#define AGGR_PKT_LIMIT_FMASK			0x001f8000
#define AGGR_SW_EOF_ACTIVE_FMASK		0x00200000
#define AGGR_FORCE_CLOSE_FMASK			0x00400000
#define AGGR_HARD_BYTE_LIMIT_ENABLE_FMASK	0x01000000

static u32
ipa_reg_construct_endp_init_aggr_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_endp_init_aggr *init_aggr = fields;
	u32 val;

	val = field_gen(init_aggr->aggr_en, AGGR_EN_FMASK);
	val |= field_gen(init_aggr->aggr_type, AGGR_TYPE_FMASK);
	val |= field_gen(init_aggr->aggr_byte_limit, AGGR_BYTE_LIMIT_FMASK);
	val |= field_gen(init_aggr->aggr_time_limit, AGGR_TIME_LIMIT_FMASK);
	val |= field_gen(init_aggr->aggr_pkt_limit, AGGR_PKT_LIMIT_FMASK);
	val |= field_gen(init_aggr->aggr_sw_eof_active,
			 AGGR_SW_EOF_ACTIVE_FMASK);
	val |= field_gen(init_aggr->aggr_force_close, AGGR_FORCE_CLOSE_FMASK);
	val |= field_gen(init_aggr->aggr_hard_byte_limit_en,
			 AGGR_HARD_BYTE_LIMIT_ENABLE_FMASK);

	return val;
}

static void
ipa_reg_parse_endp_init_aggr_n(enum ipa_reg reg, void *fields, u32 val)
{
	struct ipa_reg_endp_init_aggr *init_aggr = fields;

	memset(init_aggr, 0, sizeof(*init_aggr));

	init_aggr->aggr_en = field_val(val, AGGR_EN_FMASK);
	init_aggr->aggr_type = field_val(val, AGGR_TYPE_FMASK);
	init_aggr->aggr_byte_limit = field_val(val, AGGR_BYTE_LIMIT_FMASK);
	init_aggr->aggr_time_limit = field_val(val, AGGR_TIME_LIMIT_FMASK);
	init_aggr->aggr_pkt_limit = field_val(val, AGGR_PKT_LIMIT_FMASK);
	init_aggr->aggr_sw_eof_active =
			field_val(val, AGGR_SW_EOF_ACTIVE_FMASK);
	init_aggr->aggr_force_close = field_val(val, AGGR_SW_EOF_ACTIVE_FMASK);
	init_aggr->aggr_hard_byte_limit_en =
			field_val(val, AGGR_HARD_BYTE_LIMIT_ENABLE_FMASK);
}

/* IPA_AGGR_FORCE_CLOSE register */
#define PIPE_BITMAP_FMASK	0x000fffff

static u32
ipa_reg_construct_aggr_force_close(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_aggr_force_close *force_close = fields;

	return field_gen(force_close->pipe_bitmap, PIPE_BITMAP_FMASK);
}

/* IPA_ENDP_INIT_MODE_N register */

static void
ipa_reg_endp_init_mode_common(struct ipa_reg_endp_init_mode *init_mode)
{
	init_mode->byte_threshold = 0;		/* XXX description? */
	init_mode->pipe_replication_en = 0;	/* XXX description? */
	init_mode->pad_en = 0;			/* XXX description? */
	init_mode->hdr_ftch_disable = 0;	/* XXX description? */
}

/* IPA_ENDP_INIT_MODE is not valid for consumer pipes */
void ipa_reg_endp_init_mode_cons(struct ipa_reg_endp_init_mode *init_mode)
{
	init_mode->mode = 0;            /* ignored */
	init_mode->dest_pipe_index = 0; /* ignored */

	ipa_reg_endp_init_mode_common(init_mode);
}

void ipa_reg_endp_init_mode_prod(struct ipa_reg_endp_init_mode *init_mode,
				 enum ipa_mode mode, u32 dest_endp)
{
	init_mode->mode = mode;
	init_mode->dest_pipe_index = mode == IPA_DMA ? dest_endp : 0;

	ipa_reg_endp_init_mode_common(init_mode);
}

#define MODE_FMASK			0x00000007
#define DEST_PIPE_INDEX_FMASK		0x000001f0
#define BYTE_THRESHOLD_FMASK		0x0ffff000
#define PIPE_REPLICATION_EN_FMASK	0x10000000
#define PAD_EN_FMASK			0x20000000
#define HDR_FTCH_DISABLE_FMASK		0x40000000

static u32
ipa_reg_construct_endp_init_mode_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_endp_init_mode *init_mode = fields;
	u32 val;

	val = field_gen(init_mode->mode, MODE_FMASK);
	val |= field_gen(init_mode->dest_pipe_index, DEST_PIPE_INDEX_FMASK);
	val |= field_gen(init_mode->byte_threshold, BYTE_THRESHOLD_FMASK);
	val |= field_gen(init_mode->pipe_replication_en,
			PIPE_REPLICATION_EN_FMASK);
	val |= field_gen(init_mode->pad_en, PAD_EN_FMASK);
	val |= field_gen(init_mode->hdr_ftch_disable, HDR_FTCH_DISABLE_FMASK);

	return val;
}

/* IPA_ENDP_INIT_CTRL_N register */
#define ENDP_SUSPEND_FMASK	0x00000001
#define ENDP_DELAY_FMASK	0x00000002

static u32
ipa_reg_construct_endp_init_ctrl_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_endp_init_ctrl *init_ctrl = fields;
	u32 val;

	val = field_gen(init_ctrl->endp_suspend, ENDP_SUSPEND_FMASK);
	val |= field_gen(init_ctrl->endp_delay, ENDP_DELAY_FMASK);

	return val;
}

static void
ipa_reg_parse_endp_init_ctrl_n(enum ipa_reg reg, void *fields, u32 val)
{
	struct ipa_reg_endp_init_ctrl *init_ctrl = fields;

	memset(init_ctrl, 0, sizeof(*init_ctrl));

	init_ctrl->endp_suspend = field_val(val, ENDP_SUSPEND_FMASK);
	init_ctrl->endp_delay = field_val(val, ENDP_DELAY_FMASK);
}

/* IPA_ENDP_INIT_DEAGGR_N register */

static void
ipa_reg_endp_init_deaggr_common(struct ipa_reg_endp_init_deaggr *init_deaggr)
{
	init_deaggr->deaggr_hdr_len = 0;		/* XXX description? */
	init_deaggr->packet_offset_valid = 0;		/* XXX description? */
	init_deaggr->packet_offset_location = 0;	/* XXX description? */
	init_deaggr->max_packet_len = 0;		/* XXX description? */
}

/* XXX The deaggr setting seems not to be valid for consumer endpoints */
void
ipa_reg_endp_init_deaggr_cons(struct ipa_reg_endp_init_deaggr *init_deaggr)
{
	ipa_reg_endp_init_deaggr_common(init_deaggr);
}

void
ipa_reg_endp_init_deaggr_prod(struct ipa_reg_endp_init_deaggr *init_deaggr)
{
	ipa_reg_endp_init_deaggr_common(init_deaggr);
}

#define DEAGGR_HDR_LEN_FMASK		0x0000003f
#define PACKET_OFFSET_VALID_FMASK	0x00000080
#define PACKET_OFFSET_LOCATION_FMASK	0x00003f00
#define MAX_PACKET_LEN_FMASK		0xffff0000

static u32
ipa_reg_construct_endp_init_deaggr_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_endp_init_deaggr *init_deaggr = fields;
	u32 val;

	/* fields value is completely ignored (can be NULL) */
	val = field_gen(init_deaggr->deaggr_hdr_len, DEAGGR_HDR_LEN_FMASK);
	val |= field_gen(init_deaggr->packet_offset_valid,
			 PACKET_OFFSET_VALID_FMASK);
	val |= field_gen(init_deaggr->packet_offset_location,
			 PACKET_OFFSET_LOCATION_FMASK);
	val |= field_gen(init_deaggr->max_packet_len, MAX_PACKET_LEN_FMASK);

	return val;
}

/* IPA_ENDP_INIT_SEQ_N register */

static void
ipa_reg_endp_init_seq_common(struct ipa_reg_endp_init_seq *init_seq)
{
	init_seq->dps_seq_type = 0;	/* XXX description? */
	init_seq->hps_rep_seq_type = 0;	/* XXX description? */
	init_seq->dps_rep_seq_type = 0;	/* XXX description? */
}

void ipa_reg_endp_init_seq_cons(struct ipa_reg_endp_init_seq *init_seq)
{
	init_seq->hps_seq_type = 0;	/* ignored */

	ipa_reg_endp_init_seq_common(init_seq);
}

void ipa_reg_endp_init_seq_prod(struct ipa_reg_endp_init_seq *init_seq,
				enum ipa_seq_type seq_type)
{
	init_seq->hps_seq_type = (u32)seq_type;

	ipa_reg_endp_init_seq_common(init_seq);
}

#define HPS_SEQ_TYPE_FMASK	0x0000000f
#define DPS_SEQ_TYPE_FMASK	0x000000f0
#define HPS_REP_SEQ_TYPE_FMASK	0x00000f00
#define DPS_REP_SEQ_TYPE_FMASK	0x0000f000

static u32
ipa_reg_construct_endp_init_seq_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_endp_init_seq *init_seq = fields;
	u32 val;

	val = field_gen(init_seq->hps_seq_type, HPS_SEQ_TYPE_FMASK);
	val |= field_gen(init_seq->dps_seq_type, DPS_SEQ_TYPE_FMASK);
	val |= field_gen(init_seq->hps_rep_seq_type, HPS_REP_SEQ_TYPE_FMASK);
	val |= field_gen(init_seq->dps_rep_seq_type, DPS_REP_SEQ_TYPE_FMASK);

	return val;
}

/* IPA_ENDP_INIT_CFG_N register */

static void
ipa_reg_endp_init_cfg_common(struct ipa_reg_endp_init_cfg *init_cfg)
{
	init_cfg->frag_offload_en = 0;		/* XXX description?  */
	init_cfg->cs_gen_qmb_master_sel = 0;	/* XXX description?  */
}

void ipa_reg_endp_init_cfg_cons(struct ipa_reg_endp_init_cfg *init_cfg,
				enum ipa_cs_offload_en offload_type)
{
	init_cfg->cs_offload_en = offload_type;
	init_cfg->cs_metadata_hdr_offset = 0;	/* ignored */

	ipa_reg_endp_init_cfg_common(init_cfg);
}

void ipa_reg_endp_init_cfg_prod(struct ipa_reg_endp_init_cfg *init_cfg,
				enum ipa_cs_offload_en offload_type,
				u32 metadata_offset)
{
	init_cfg->cs_offload_en = offload_type;
	init_cfg->cs_metadata_hdr_offset = metadata_offset;

	ipa_reg_endp_init_cfg_common(init_cfg);
}

#define FRAG_OFFLOAD_EN_FMASK		0x00000001
#define CS_OFFLOAD_EN_FMASK		0x00000006
#define CS_METADATA_HDR_OFFSET_FMASK	0x00000078
#define CS_GEN_QMB_MASTER_SEL_FMASK	0x00000100

static u32
ipa_reg_construct_endp_init_cfg_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_endp_init_cfg *init_cfg = fields;
	u32 val;

	val = field_gen(init_cfg->frag_offload_en, FRAG_OFFLOAD_EN_FMASK);
	val |= field_gen(init_cfg->cs_offload_en, CS_OFFLOAD_EN_FMASK);
	val |= field_gen(init_cfg->cs_metadata_hdr_offset,
			 CS_METADATA_HDR_OFFSET_FMASK);
	val |= field_gen(init_cfg->cs_gen_qmb_master_sel,
			 CS_GEN_QMB_MASTER_SEL_FMASK);

	return val;
}

/* IPA_ENDP_INIT_HDR_METADATA_MASK_N register */

void ipa_reg_endp_init_hdr_metadata_mask_cons(
		struct ipa_reg_endp_init_hdr_metadata_mask *metadata_mask,
		u32 mask)
{
	metadata_mask->metadata_mask = mask;
}

/* IPA_ENDP_INIT_HDR_METADATA_MASK is not valid for producer pipes */
void ipa_reg_endp_init_hdr_metadata_mask_prod(
		struct ipa_reg_endp_init_hdr_metadata_mask *metadata_mask)
{
	metadata_mask->metadata_mask = 0;	/* ignored */
}


#define METADATA_MASK_FMASK	0xffffffff

static u32 ipa_reg_construct_endp_init_hdr_metadata_mask_n(enum ipa_reg reg,
							  const void *fields)
{
	const struct ipa_reg_endp_init_hdr_metadata_mask *metadata_mask;

	metadata_mask = fields;

	return field_gen(metadata_mask->metadata_mask, METADATA_MASK_FMASK);
}

/* IPA_SHARED_MEM_SIZE register */
#define SHARED_MEM_SIZE_FMASK	0x0000ffff
#define SHARED_MEM_BADDR_FMASK	0xffff0000

static void
ipa_reg_parse_shared_mem_size(enum ipa_reg reg, void *fields, u32 val)
{
	struct ipa_reg_shared_mem_size *mem_size = fields;

	memset(mem_size, 0, sizeof(*mem_size));

	mem_size->shared_mem_size = field_val(val, SHARED_MEM_SIZE_FMASK);
	mem_size->shared_mem_baddr = field_val(val, SHARED_MEM_BADDR_FMASK);
}

/* IPA_ENDP_STATUS_N register */

static void ipa_reg_endp_status_common(struct ipa_reg_endp_status *endp_status)
{
	endp_status->status_pkt_suppress = 0;	/* XXX description?  */
}

void ipa_reg_endp_status_cons(struct ipa_reg_endp_status *endp_status,
			      bool enable)
{
	endp_status->status_en = enable ? 1 : 0;
	endp_status->status_endp = 0;		/* ignored */
	endp_status->status_location = 0;	/* before packet data */

	ipa_reg_endp_status_common(endp_status);
}

void ipa_reg_endp_status_prod(struct ipa_reg_endp_status *endp_status,
			      bool enable, u32 endp)
{
	endp_status->status_en = enable ? 1 : 0;
	endp_status->status_endp = endp;
	endp_status->status_location = 0;	/* ignored */

	ipa_reg_endp_status_common(endp_status);
}

#define STATUS_EN_FMASK			0x00000001
#define STATUS_ENDP_FMASK		0x0000003e
#define STATUS_LOCATION_FMASK		0x00000100
#define STATUS_PKT_SUPPRESS_FMASK	0x00000200

static u32 ipa_reg_construct_endp_status_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_endp_status *endp_status = fields;
	u32 val;

	val = field_gen(endp_status->status_en, STATUS_EN_FMASK);
	val |= field_gen(endp_status->status_endp, STATUS_ENDP_FMASK);
	val |= field_gen(endp_status->status_location, STATUS_LOCATION_FMASK);
	val |= field_gen(0, STATUS_PKT_SUPPRESS_FMASK);

	return val;
}

/* IPA_ENDP_FILTER_ROUTER_HSH_CFG_N register */
#define FILTER_HASH_MSK_SRC_ID_FMASK	0x00000001
#define FILTER_HASH_MSK_SRC_IP_FMASK	0x00000002
#define FILTER_HASH_MSK_DST_IP_FMASK	0x00000004
#define FILTER_HASH_MSK_SRC_PORT_FMASK	0x00000008
#define FILTER_HASH_MSK_DST_PORT_FMASK	0x00000010
#define FILTER_HASH_MSK_PROTOCOL_FMASK	0x00000020
#define FILTER_HASH_MSK_METADATA_FMASK	0x00000040
#define FILTER_HASH_UNDEFINED1_FMASK	0x0000ff80

#define ROUTER_HASH_MSK_SRC_ID_FMASK	0x00010000
#define ROUTER_HASH_MSK_SRC_IP_FMASK	0x00020000
#define ROUTER_HASH_MSK_DST_IP_FMASK	0x00040000
#define ROUTER_HASH_MSK_SRC_PORT_FMASK	0x00080000
#define ROUTER_HASH_MSK_DST_PORT_FMASK	0x00100000
#define ROUTER_HASH_MSK_PROTOCOL_FMASK	0x00200000
#define ROUTER_HASH_MSK_METADATA_FMASK	0x00400000
#define ROUTER_HASH_UNDEFINED2_FMASK	0xff800000

static u32 ipa_reg_construct_hash_cfg_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_ep_filter_router_hsh_cfg *hsh_cfg = fields;
	u32 val;

	val = field_gen(hsh_cfg->flt.src_id, FILTER_HASH_MSK_SRC_ID_FMASK);
	val |= field_gen(hsh_cfg->flt.src_ip, FILTER_HASH_MSK_SRC_IP_FMASK);
	val |= field_gen(hsh_cfg->flt.dst_ip, FILTER_HASH_MSK_DST_IP_FMASK);
	val |= field_gen(hsh_cfg->flt.src_port, FILTER_HASH_MSK_SRC_PORT_FMASK);
	val |= field_gen(hsh_cfg->flt.dst_port, FILTER_HASH_MSK_DST_PORT_FMASK);
	val |= field_gen(hsh_cfg->flt.protocol, FILTER_HASH_MSK_PROTOCOL_FMASK);
	val |= field_gen(hsh_cfg->flt.metadata, FILTER_HASH_MSK_METADATA_FMASK);
	val |= field_gen(hsh_cfg->undefined1, FILTER_HASH_UNDEFINED1_FMASK);

	val |= field_gen(hsh_cfg->rt.src_id, ROUTER_HASH_MSK_SRC_ID_FMASK);
	val |= field_gen(hsh_cfg->rt.src_ip, ROUTER_HASH_MSK_SRC_IP_FMASK);
	val |= field_gen(hsh_cfg->rt.dst_ip, ROUTER_HASH_MSK_DST_IP_FMASK);
	val |= field_gen(hsh_cfg->rt.src_port, ROUTER_HASH_MSK_SRC_PORT_FMASK);
	val |= field_gen(hsh_cfg->rt.dst_port, ROUTER_HASH_MSK_DST_PORT_FMASK);
	val |= field_gen(hsh_cfg->rt.protocol, ROUTER_HASH_MSK_PROTOCOL_FMASK);
	val |= field_gen(hsh_cfg->rt.metadata, ROUTER_HASH_MSK_METADATA_FMASK);
	val |= field_gen(hsh_cfg->undefined2, ROUTER_HASH_UNDEFINED2_FMASK);

	return val;
}

static void ipa_reg_parse_hash_cfg_n(enum ipa_reg reg, void *fields, u32 val)
{
	struct ipa_ep_filter_router_hsh_cfg *hsh_cfg = fields;

	memset(hsh_cfg, 0, sizeof(*hsh_cfg));

	hsh_cfg->flt.src_id = field_val(val, FILTER_HASH_MSK_SRC_ID_FMASK);
	hsh_cfg->flt.src_ip = field_val(val, FILTER_HASH_MSK_SRC_IP_FMASK);
	hsh_cfg->flt.dst_ip = field_val(val, FILTER_HASH_MSK_DST_IP_FMASK);
	hsh_cfg->flt.src_port = field_val(val, FILTER_HASH_MSK_SRC_PORT_FMASK);
	hsh_cfg->flt.dst_port = field_val(val, FILTER_HASH_MSK_DST_PORT_FMASK);
	hsh_cfg->flt.protocol = field_val(val, FILTER_HASH_MSK_PROTOCOL_FMASK);
	hsh_cfg->flt.metadata = field_val(val, FILTER_HASH_MSK_METADATA_FMASK);
	hsh_cfg->undefined1 = field_val(val, FILTER_HASH_UNDEFINED1_FMASK);

	hsh_cfg->rt.src_id = field_val(val, ROUTER_HASH_MSK_SRC_ID_FMASK);
	hsh_cfg->rt.src_ip = field_val(val, ROUTER_HASH_MSK_SRC_IP_FMASK);
	hsh_cfg->rt.dst_ip = field_val(val, ROUTER_HASH_MSK_DST_IP_FMASK);
	hsh_cfg->rt.src_port = field_val(val, ROUTER_HASH_MSK_SRC_PORT_FMASK);
	hsh_cfg->rt.dst_port = field_val(val, ROUTER_HASH_MSK_DST_PORT_FMASK);
	hsh_cfg->rt.protocol = field_val(val, ROUTER_HASH_MSK_PROTOCOL_FMASK);
	hsh_cfg->rt.metadata = field_val(val, ROUTER_HASH_MSK_METADATA_FMASK);
	hsh_cfg->undefined2 = field_val(val, ROUTER_HASH_UNDEFINED2_FMASK);
}

/* IPA_RSRC_GRP_XY_RSRC_TYPE_n register */
#define X_MIN_LIM_FMASK	0x0000003f
#define X_MAX_LIM_FMASK	0x00003f00
#define Y_MIN_LIM_FMASK	0x003f0000
#define Y_MAX_LIM_FMASK	0x3f000000

static u32 ipa_reg_construct_rsrg_grp_xy(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_rsrc_grp_cfg *grp_cfg = fields;
	u32 val;

	val = field_gen(grp_cfg->x_min, X_MIN_LIM_FMASK);
	val |= field_gen(grp_cfg->x_max, X_MAX_LIM_FMASK);

	/* DST_23 register has only X fields at ipa V3_5 */
	if (reg == IPA_DST_RSRC_GRP_23_RSRC_TYPE_N)
		return val;

	val |= field_gen(grp_cfg->y_min, Y_MIN_LIM_FMASK);
	val |= field_gen(grp_cfg->y_max, Y_MAX_LIM_FMASK);

	return val;
}

/* IPA_QSB_MAX_WRITES register */
#define GEN_QMB_0_MAX_WRITES_FMASK	0x0000000f
#define GEN_QMB_1_MAX_WRITES_FMASK	0x000000f0

static u32
ipa_reg_construct_qsb_max_writes(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_qsb_max_writes *max_writes = fields;
	u32 val;

	val = field_gen(max_writes->qmb_0_max_writes,
			GEN_QMB_0_MAX_WRITES_FMASK);
	val |= field_gen(max_writes->qmb_1_max_writes,
			 GEN_QMB_1_MAX_WRITES_FMASK);

	return val;
}

/* IPA_QSB_MAX_READS register */
#define GEN_QMB_0_MAX_READS_FMASK	0x0000000f
#define GEN_QMB_1_MAX_READS_FMASK	0x000000f0

static u32 ipa_reg_construct_qsb_max_reads(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_qsb_max_reads *max_reads = fields;
	u32 val;

	val = field_gen(max_reads->qmb_0_max_reads, GEN_QMB_0_MAX_READS_FMASK);
	val |= field_gen(max_reads->qmb_1_max_reads, GEN_QMB_1_MAX_READS_FMASK);

	return val;
}

/* IPA_IDLE_INDICATION_CFG regiser */
#define ENTER_IDLE_DEBOUNCE_THRESH_FMASK	0x0000ffff
#define CONST_NON_IDLE_ENABLE_FMASK		0x00010000

static u32
ipa_reg_construct_idle_indication_cfg(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_idle_indication_cfg *indication_cfg;
	u32 val;

	indication_cfg = fields;

	val = field_gen(indication_cfg->enter_idle_debounce_thresh,
			ENTER_IDLE_DEBOUNCE_THRESH_FMASK);
	val |= field_gen(indication_cfg->const_non_idle_enable,
			 CONST_NON_IDLE_ENABLE_FMASK);

	return val;
}

/* The entries in the following table have the following constraints:
 * - 0 is not a valid offset (it represents an unused entry).  It is
 *   a bug for code to attempt to access a register which has an
 *   undefined (zero) offset value.
 * - If a construct function is supplied, the register must be
 *   written using ipa_write_reg_n_fields() (or its wrapper
 *   function ipa_write_reg_fields()).
 * - Generally, if a parse function is supplied, the register should
 *   read using ipa_read_reg_n_fields() (or ipa_read_reg_fields()).
 *   (Currently some debug code reads some registers directly, without
 *   parsing.)
 */
#define cfunc(f)	ipa_reg_construct_ ## f
#define pfunc(f)	ipa_reg_parse_ ## f
#define reg_obj_common(id, cf, pf, o, n)	\
	[id] = {				\
		.construct = cf,		\
		.parse = pf,			\
		.offset = o,			\
		.n_ofst = n,			\
	}
#define reg_obj_cfunc(id, f, o, n)		\
	reg_obj_common(id, cfunc(f), NULL, o, n)
#define reg_obj_pfunc(id, f, o, n)		\
	reg_obj_common(id, NULL, pfunc(f), o, n)
#define reg_obj_both(id, f, o, n)		\
	reg_obj_common(id, cfunc(f), pfunc(f), o, n)
#define reg_obj_nofunc(id, o, n)		\
	reg_obj_common(id, NULL, NULL, o, n)

/* IPAv3.5.1 */
static const struct ipa_reg_desc ipa_reg[] = {
	reg_obj_cfunc(IPA_ROUTE, route,			0x00000048,	0x0000),
	reg_obj_nofunc(IPA_IRQ_STTS_EE_N,		0x00003008,	0x1000),
	reg_obj_nofunc(IPA_IRQ_EN_EE_N,			0x0000300c,	0x1000),
	reg_obj_nofunc(IPA_IRQ_CLR_EE_N,		0x00003010,	0x1000),
	reg_obj_nofunc(IPA_IRQ_SUSPEND_INFO_EE_N,	0x00003030,	0x1000),
	reg_obj_nofunc(IPA_SUSPEND_IRQ_EN_EE_N,		0x00003034,	0x1000),
	reg_obj_nofunc(IPA_SUSPEND_IRQ_CLR_EE_N,	0x00003038,	0x1000),
	reg_obj_nofunc(IPA_BCR,				0x000001d0,	0x0000),
	reg_obj_nofunc(IPA_ENABLED_PIPES,		0x00000038,	0x0000),
	reg_obj_nofunc(IPA_TAG_TIMER,			0x00000060,	0x0000),
	reg_obj_nofunc(IPA_STATE_AGGR_ACTIVE,		0x0000010c,	0x0000),
	reg_obj_cfunc(IPA_ENDP_INIT_HDR_N,
		      endp_init_hdr_n,			0x00000810,	0x0070),
	reg_obj_cfunc(IPA_ENDP_INIT_HDR_EXT_N,
		      endp_init_hdr_ext_n,		0x00000814,	0x0070),
	reg_obj_both(IPA_ENDP_INIT_AGGR_N,
		     endp_init_aggr_n,			0x00000824,	0x0070),
	reg_obj_cfunc(IPA_AGGR_FORCE_CLOSE,
		     aggr_force_close,			0x000001ec,	0x0000),
	reg_obj_cfunc(IPA_ENDP_INIT_MODE_N,
		      endp_init_mode_n,			0x00000820,	0x0070),
	reg_obj_both(IPA_ENDP_INIT_CTRL_N,
		     endp_init_ctrl_n,			0x00000800,	0x0070),
	reg_obj_cfunc(IPA_ENDP_INIT_DEAGGR_N,
		      endp_init_deaggr_n,		0x00000834,	0x0070),
	reg_obj_cfunc(IPA_ENDP_INIT_SEQ_N,
		      endp_init_seq_n,			0x0000083c,	0x0070),
	reg_obj_cfunc(IPA_ENDP_INIT_CFG_N,
		      endp_init_cfg_n,			0x00000808,	0x0070),
	reg_obj_nofunc(IPA_IRQ_EE_UC_N,			0x0000301c,	0x1000),
	reg_obj_cfunc(IPA_ENDP_INIT_HDR_METADATA_MASK_N,
		      endp_init_hdr_metadata_mask_n,	0x00000818,	0x0070),
	reg_obj_pfunc(IPA_SHARED_MEM_SIZE,
		      shared_mem_size,			0x00000054,	0x0000),
	reg_obj_nofunc(IPA_SRAM_DIRECT_ACCESS_N,	0x00007000,	0x0004),
	reg_obj_nofunc(IPA_LOCAL_PKT_PROC_CNTXT_BASE,	0x000001e8,	0x0000),
	reg_obj_cfunc(IPA_ENDP_STATUS_N,
		      endp_status_n,			0x00000840,	0x0070),
	reg_obj_both(IPA_ENDP_FILTER_ROUTER_HSH_CFG_N,
		     hash_cfg_n,			0x0000085c,	0x0070),
	reg_obj_cfunc(IPA_SRC_RSRC_GRP_01_RSRC_TYPE_N,
		      rsrg_grp_xy,			0x00000400,	0x0020),
	reg_obj_cfunc(IPA_SRC_RSRC_GRP_23_RSRC_TYPE_N,
		      rsrg_grp_xy,			0x00000404,	0x0020),
	reg_obj_cfunc(IPA_DST_RSRC_GRP_01_RSRC_TYPE_N,
		      rsrg_grp_xy,			0x00000500,	0x0020),
	reg_obj_cfunc(IPA_DST_RSRC_GRP_23_RSRC_TYPE_N,
		      rsrg_grp_xy,			0x00000504,	0x0020),
	reg_obj_cfunc(IPA_QSB_MAX_WRITES,
		      qsb_max_writes,			0x00000074,	0x0000),
	reg_obj_cfunc(IPA_QSB_MAX_READS,
		      qsb_max_reads,			0x00000078,	0x0000),
	reg_obj_cfunc(IPA_IDLE_INDICATION_CFG,
		      idle_indication_cfg,		0x00000220,	0x0000),
};

#undef reg_obj_nofunc
#undef reg_obj_both
#undef reg_obj_pfunc
#undef reg_obj_cfunc
#undef reg_obj_common
#undef pfunc
#undef cfunc

void ipa_reg_init(void __iomem *base)
{
	ipa_reg_virt = base;
}

void ipa_reg_exit(void)
{
	ipa_reg_virt = NULL;
}

/* Get the offset of an "n parameterized" register */
u32 ipa_reg_n_offset(enum ipa_reg reg, u32 n)
{
	return ipa_reg[reg].offset + n * ipa_reg[reg].n_ofst;
}

/* ipa_read_reg_n() - Get an "n parameterized" register's value */
u32 ipa_read_reg_n(enum ipa_reg reg, u32 n)
{
	return ioread32(ipa_reg_virt + ipa_reg_n_offset(reg, n));
}

/* ipa_write_reg_n() - Write a raw value to an "n parameterized" register */
void ipa_write_reg_n(enum ipa_reg reg, u32 n, u32 val)
{
	iowrite32(val, ipa_reg_virt + ipa_reg_n_offset(reg, n));
}

/* ipa_read_reg_n_fields() - Parse value of an "n parameterized" register */
void ipa_read_reg_n_fields(enum ipa_reg reg, u32 n, void *fields)
{
	u32 val = ipa_read_reg_n(reg, n);

	ipa_reg[reg].parse(reg, fields, val);
}

/* ipa_write_reg_n_fields() - Construct a vlaue to write to an "n
 * parameterized" register
 */
void ipa_write_reg_n_fields(enum ipa_reg reg, u32 n, const void *fields)
{
	u32 val = ipa_reg[reg].construct(reg, fields);

	ipa_write_reg_n(reg, n, val);
}

/* Maximum representable aggregation byte limit value */
u32 ipa_reg_aggr_max_byte_limit(void)
{
	return field_max(AGGR_BYTE_LIMIT_FMASK);
}

/* Maximum representable aggregation packet limit value */
u32 ipa_reg_aggr_max_packet_limit(void)
{
	return field_max(AGGR_PKT_LIMIT_FMASK);
}
