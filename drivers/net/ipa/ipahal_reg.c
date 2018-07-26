// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#define pr_fmt(fmt)	"ipahal %s:%d " fmt, __func__, __LINE__

#ifndef __KERNEL__
#include <stdint.h>
#include <stddef.h>
#include <sys/stat.h>
#endif
#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include "ipahal_i.h"
#include "ipahal_reg.h"
#include "ipahal_reg_i.h"

/* struct ipahal_reg_obj - Register H/W information for specific IPA version
 * @construct - CB to construct register value from abstracted structure
 * @parse - CB to parse register value to abstracted structure
 * @offset - register offset relative to base address
 * @n_ofst - N parameterized register sub-offset
 */
struct ipahal_reg_obj {
	u32 (*construct)(enum ipahal_reg reg, const void *fields);
	void (*parse)(enum ipahal_reg reg, void *fields, u32 val);
	u32 offset;
	u16 n_ofst;
};

static u32 ipareg_construct_rsrg_grp_xy(enum ipahal_reg reg, const void *fields)
{
	const struct ipahal_reg_rsrc_grp_cfg *grp = fields;
	u32 val;

	val = field_gen(grp->x_min, X_MIN_LIM_BMSK);
	val |= field_gen(grp->x_max, X_MAX_LIM_BMSK);

	/* DST_23 register has only X fields at ipa V3_5 */
	if (reg == IPA_DST_RSRC_GRP_23_RSRC_TYPE_n)
		return val;

	val |= field_gen(grp->y_min, Y_MIN_LIM_BMSK);
	val |= field_gen(grp->y_max, Y_MAX_LIM_BMSK);

	return val;
}

static u32 ipareg_construct_hash_cfg_n(enum ipahal_reg reg, const void *fields)
{
	const struct ipahal_reg_fltrt_hash_tuple *tuple = fields;
	u32 val;

	val = field_gen(tuple->flt.src_id, FILTER_HASH_MSK_SRC_ID_BMSK);
	val |= field_gen(tuple->flt.src_ip_addr, FILTER_HASH_MSK_SRC_IP_BMSK);
	val |= field_gen(tuple->flt.dst_ip_addr, FILTER_HASH_MSK_DST_IP_BMSK);
	val |= field_gen(tuple->flt.src_port, FILTER_HASH_MSK_SRC_PORT_BMSK);
	val |= field_gen(tuple->flt.dst_port, FILTER_HASH_MSK_DST_PORT_BMSK);
	val |= field_gen(tuple->flt.protocol, FILTER_HASH_MSK_PROTOCOL_BMSK);
	val |= field_gen(tuple->flt.meta_data, FILTER_HASH_MSK_METADATA_BMSK);
	val |= field_gen(tuple->undefined1, FILTER_HASH_UNDEFINED1_BMSK);

	val |= field_gen(tuple->rt.src_id, ROUTER_HASH_MSK_SRC_ID_BMSK);
	val |= field_gen(tuple->rt.src_ip_addr, ROUTER_HASH_MSK_SRC_IP_BMSK);
	val |= field_gen(tuple->rt.dst_ip_addr, ROUTER_HASH_MSK_DST_IP_BMSK);
	val |= field_gen(tuple->rt.src_port, ROUTER_HASH_MSK_SRC_PORT_BMSK);
	val |= field_gen(tuple->rt.dst_port, ROUTER_HASH_MSK_DST_PORT_BMSK);
	val |= field_gen(tuple->rt.protocol, ROUTER_HASH_MSK_PROTOCOL_BMSK);
	val |= field_gen(tuple->rt.meta_data, ROUTER_HASH_MSK_METADATA_BMSK);
	val |= field_gen(tuple->undefined2, ROUTER_HASH_UNDEFINED2_BMSK);

	return val;
}

static void ipareg_parse_hash_cfg_n(enum ipahal_reg reg, void *fields, u32 val)
{
	struct ipahal_reg_fltrt_hash_tuple *tuple = fields;

	memset(tuple, 0, sizeof(*tuple));

	tuple->flt.src_id = field_val(val, FILTER_HASH_MSK_SRC_ID_BMSK);
	tuple->flt.src_ip_addr = field_val(val, FILTER_HASH_MSK_SRC_IP_BMSK);
	tuple->flt.dst_ip_addr = field_val(val, FILTER_HASH_MSK_DST_IP_BMSK);
	tuple->flt.src_port = field_val(val, FILTER_HASH_MSK_SRC_PORT_BMSK);
	tuple->flt.dst_port = field_val(val, FILTER_HASH_MSK_DST_PORT_BMSK);
	tuple->flt.protocol = field_val(val, FILTER_HASH_MSK_PROTOCOL_BMSK);
	tuple->flt.meta_data = field_val(val, FILTER_HASH_MSK_METADATA_BMSK);
	tuple->undefined1 = field_val(val, FILTER_HASH_UNDEFINED1_BMSK);

	tuple->rt.src_id = field_val(val, ROUTER_HASH_MSK_SRC_ID_BMSK);
	tuple->rt.src_ip_addr = field_val(val, ROUTER_HASH_MSK_SRC_IP_BMSK);
	tuple->rt.dst_ip_addr = field_val(val, ROUTER_HASH_MSK_DST_IP_BMSK);
	tuple->rt.src_port = field_val(val, ROUTER_HASH_MSK_SRC_PORT_BMSK);
	tuple->rt.dst_port = field_val(val, ROUTER_HASH_MSK_DST_PORT_BMSK);
	tuple->rt.protocol = field_val(val, ROUTER_HASH_MSK_PROTOCOL_BMSK);
	tuple->rt.meta_data = field_val(val, ROUTER_HASH_MSK_METADATA_BMSK);
	tuple->undefined2 = field_val(val, ROUTER_HASH_UNDEFINED2_BMSK);
}

static u32
ipareg_construct_endp_status_n(enum ipahal_reg reg, const void *fields)
{
	const struct ipahal_reg_ep_cfg_status *ep_status = fields;
	u32 val;

	val = field_gen(ep_status->status_en, STATUS_EN_BMSK);
	val |= field_gen(ep_status->status_ep, STATUS_ENDP_BMSK);
	val |= field_gen(ep_status->status_location, STATUS_LOCATION_BMSK);

	return val;
}

static void
ipareg_parse_shared_mem_size(enum ipahal_reg reg, void *fields, u32 val)
{
	struct ipahal_reg_shared_mem_size *smem_sz = fields;

	memset(smem_sz, 0, sizeof(*smem_sz));

	smem_sz->shared_mem_sz = field_val(val, SHARED_MEM_SIZE_BMSK);
	smem_sz->shared_mem_baddr = field_val(val, SHARED_MEM_BADDR_BMSK);
}

static u32
ipareg_construct_endp_init_hdr_metadata_mask_n(enum ipahal_reg reg,
					       const void *fields)
{
	const struct ipa_ep_cfg_metadata_mask *metadata_mask = fields;

	return field_gen(metadata_mask->metadata_mask, METADATA_MASK_BMSK);
}

static bool cs_offload_en_valid(u8 cs_offload_en, enum ipahal_reg reg)
{
	switch (cs_offload_en) {
	case IPA_DISABLE_CS_OFFLOAD:
	case IPA_ENABLE_CS_OFFLOAD_UL:
	case IPA_ENABLE_CS_OFFLOAD_DL:
		return true;
	default:
		return false;
	}
}

static u32
ipareg_construct_endp_init_cfg_n(enum ipahal_reg reg, const void *fields)
{
	const struct ipa_ep_cfg_cfg *cfg = fields;
	u32 val;

	ipa_assert(cs_offload_en_valid(cfg->cs_offload_en, reg));

	val = field_gen(cfg->frag_offload_en ? 1 : 0, FRAG_OFFLOAD_EN_BMSK);
	val |= field_gen(cfg->cs_offload_en, CS_OFFLOAD_EN_BMSK);
	val |= field_gen(cfg->cs_metadata_hdr_offset,
			CS_METADATA_HDR_OFFSET_BMSK);
	val |= field_gen(cfg->gen_qmb_master_sel, CS_GEN_QMB_MASTER_SEL_BMSK);

	return val;
}

static u32
ipareg_construct_endp_init_deaggr_n(enum ipahal_reg reg, const void *fields)
{
	const struct ipa_ep_cfg_deaggr *ep_deaggr = fields;
	u32 val;

	val = field_gen(ep_deaggr->deaggr_hdr_len, DEAGGR_HDR_LEN_BMSK);
	val |= field_gen(ep_deaggr->packet_offset_valid,
			PACKET_OFFSET_VALID_BMSK);
	val |= field_gen(ep_deaggr->packet_offset_location,
			PACKET_OFFSET_LOCATION_BMSK);
	val |= field_gen(ep_deaggr->max_packet_len, MAX_PACKET_LEN_BMSK);

	return val;
}

static u32
ipareg_construct_endp_init_ctrl_n(enum ipahal_reg reg, const void *fields)
{
	const struct ipa_ep_cfg_ctrl *ep_ctrl = fields;
	u32 val;

	val = field_gen(ep_ctrl->ipa_ep_suspend, ENDP_SUSPEND_BMSK);
	val |= field_gen(ep_ctrl->ipa_ep_delay, ENDP_DELAY_BMSK);

	return val;
}

static void
ipareg_parse_endp_init_ctrl_n(enum ipahal_reg reg, void *fields, u32 val)
{
	struct ipa_ep_cfg_ctrl *ep_ctrl = fields;

	memset(ep_ctrl, 0, sizeof(*ep_ctrl));

	ep_ctrl->ipa_ep_suspend = field_val(val, ENDP_SUSPEND_BMSK);
	ep_ctrl->ipa_ep_delay = field_val(val, ENDP_DELAY_BMSK);
}

static u32
ipareg_construct_endp_init_mode_n(enum ipahal_reg reg, const void *fields)
{
	const struct ipahal_reg_endp_init_mode *init_mode = fields;
	u32 val;

	val = field_gen(init_mode->ep_mode.mode, MODE_BMSK);
	val |= field_gen(init_mode->dst_pipe_number, DEST_PIPE_INDEX_BMSK);

	return val;
}

static void
ipareg_parse_endp_init_aggr_n(enum ipahal_reg reg, void *fields, u32 val)
{
	struct ipa_ep_cfg_aggr *ep_aggr = fields;

	memset(ep_aggr, 0, sizeof(*ep_aggr));

	ep_aggr->aggr_en = field_val(val, AGGR_EN_BMSK) == IPA_ENABLE_AGGR;
	ep_aggr->aggr = field_val(val, AGGR_TYPE_BMSK);
	ep_aggr->aggr_byte_limit = field_val(val, AGGR_BYTE_LIMIT_BMSK);
	ep_aggr->aggr_time_limit = field_val(val, AGGR_TIME_LIMIT_BMSK);
	ep_aggr->aggr_pkt_limit = field_val(val, AGGR_PKT_LIMIT_BMSK);
	ep_aggr->aggr_sw_eof_active = field_val(val, AGGR_SW_EOF_ACTIVE_BMSK);
	ep_aggr->aggr_hard_byte_limit_en
			= field_val(val, AGGR_HARD_BYTE_LIMIT_ENABLE_BMSK);
}

static u32
ipareg_construct_endp_init_aggr_n(enum ipahal_reg reg, const void *fields)
{
	const struct ipa_ep_cfg_aggr *ep_aggr = fields;
	u32 val;

	val = field_gen(ep_aggr->aggr_en, AGGR_EN_BMSK);
	val |= field_gen(ep_aggr->aggr, AGGR_TYPE_BMSK);
	val |= field_gen(ep_aggr->aggr_byte_limit, AGGR_BYTE_LIMIT_BMSK);
	val |= field_gen(ep_aggr->aggr_time_limit, AGGR_TIME_LIMIT_BMSK);
	val |= field_gen(ep_aggr->aggr_pkt_limit, AGGR_PKT_LIMIT_BMSK);
	val |= field_gen(ep_aggr->aggr_sw_eof_active, AGGR_SW_EOF_ACTIVE_BMSK);
	val |= field_gen(ep_aggr->aggr_hard_byte_limit_en,
			AGGR_HARD_BYTE_LIMIT_ENABLE_BMSK);

	return val;
}

static u32
ipareg_construct_endp_init_hdr_ext_n(enum ipahal_reg reg, const void *fields)
{
	const struct ipa_ep_cfg_hdr_ext *ep_hdr_ext = fields;
	u8 hdr_endianness = ep_hdr_ext->hdr_little_endian ? 0 : 1;
	u32 val;

	val = field_gen(ep_hdr_ext->hdr_pad_to_alignment,
			HDR_PAD_TO_ALIGNMENT_BMSK);
	val |= field_gen(ep_hdr_ext->hdr_total_len_or_pad_offset,
			HDR_TOTAL_LEN_OR_PAD_OFFSET_BMSK);
	val |= field_gen(ep_hdr_ext->hdr_payload_len_inc_padding,
			HDR_PAYLOAD_LEN_INC_PADDING_BMSK);
	val |= field_gen(ep_hdr_ext->hdr_total_len_or_pad,
			HDR_TOTAL_LEN_OR_PAD_BMSK);
	val |= field_gen(ep_hdr_ext->hdr_total_len_or_pad_valid,
			HDR_TOTAL_LEN_OR_PAD_VALID_BMSK);
	val |= field_gen(hdr_endianness, HDR_ENDIANNESS_BMSK);

	return val;
}

static u32
ipareg_construct_endp_init_hdr_n(enum ipahal_reg reg, const void *fields)
{
	const struct ipa_ep_cfg_hdr *ep_hdr = fields;
	u32 val;

	val = field_gen(ep_hdr->hdr_metadata_reg_valid,
			HDR_METADATA_REG_VALID_BMSK);
	val |= field_gen(ep_hdr->hdr_remove_additional,
			HDR_LEN_INC_DEAGG_HDR_BMSK);
	val |= field_gen(0, HDR_A5_MUX_BMSK);
	val |= field_gen(ep_hdr->hdr_ofst_pkt_size, HDR_OFST_PKT_SIZE_BMSK);
	val |= field_gen(ep_hdr->hdr_ofst_pkt_size_valid,
			HDR_OFST_PKT_SIZE_VALID_BMSK);
	val |= field_gen(0, HDR_ADDITIONAL_CONST_LEN_BMSK);
	val |= field_gen(ep_hdr->hdr_ofst_metadata, HDR_OFST_METADATA_BMSK);
	val |= field_gen(ep_hdr->hdr_ofst_metadata_valid,
			HDR_OFST_METADATA_VALID_BMSK);
	val |= field_gen(ep_hdr->hdr_len, HDR_LEN_BMSK);

	return val;
}

static u32
ipareg_construct_route(enum ipahal_reg reg, const void *fields)
{
	const struct ipahal_reg_route *route = fields;
	u32 val;

	val = field_gen(route->route_dis, ROUTE_DIS_BMSK);
	val |= field_gen(route->route_def_pipe, ROUTE_DEF_PIPE_BMSK);
	val |= field_gen(route->route_def_hdr_table, ROUTE_DEF_HDR_TABLE_BMSK);
	val |= field_gen(route->route_def_hdr_ofst, ROUTE_DEF_HDR_OFST_BMSK);
	val |= field_gen(route->route_frag_def_pipe, ROUTE_FRAG_DEF_PIPE_BMSK);
	val |= field_gen(route->route_def_retain_hdr,
			ROUTE_DEF_RETAIN_HDR_BMSK);

	return val;
}

static u32
ipareg_construct_qsb_max_writes(enum ipahal_reg reg, const void *fields)
{
	const struct ipahal_reg_qsb_max_writes *max_writes = fields;
	u32 val;

	val = field_gen(max_writes->qmb_0_max_writes,
			GEN_QMB_0_MAX_WRITES_BMSK);
	val |= field_gen(max_writes->qmb_1_max_writes,
			 GEN_QMB_1_MAX_WRITES_BMSK);

	return val;
}

static u32
ipareg_construct_qsb_max_reads(enum ipahal_reg reg, const void *fields)
{
	const struct ipahal_reg_qsb_max_reads *max_reads = fields;
	u32 val;

	val = field_gen(max_reads->qmb_0_max_reads, GEN_QMB_0_MAX_READS_BMSK);
	val |= field_gen(max_reads->qmb_1_max_reads, GEN_QMB_1_MAX_READS_BMSK);

	return val;
}

static u32
ipareg_construct_idle_indication_cfg(enum ipahal_reg reg, const void *fields)
{
	const struct ipahal_reg_idle_indication_cfg *idle_indication_cfg;
	u32 val;

	idle_indication_cfg = fields;

	val = field_gen(idle_indication_cfg->enter_idle_debounce_thresh,
			ENTER_IDLE_DEBOUNCE_THRESH_BMSK);
	val |= field_gen(idle_indication_cfg->const_non_idle_enable,
			CONST_NON_IDLE_ENABLE_BMSK);

	return val;
}

/* The entries in the following table have the following constraints:
 * - 0 is not a valid offset (it represents an unused entry).  It is
 *   a bug for code to attempt to access a register which has an
 *   undefined (zero) offset value.
 * - If a construct function is supplied, the register must be
 *   written using ipahal_write_reg_n_fields() (or its wrapper
 *   function ipahal_write_reg_fields()).
 * - Generally, if a parse function is supplied, the register should
 *   read using ipahal_read_reg_n_fields() (or ipahal_read_reg_fields()).
 *   (Currently some debug code reads some registers directly, without
 *   parsing.)
 */
#define cfunc(f)	ipareg_construct_ ## f
#define pfunc(f)	ipareg_parse_ ## f
#define idsym(id)	IPA_ ## id
#define reg_obj_common(id, cf, pf, o, n)	\
	[idsym(id)] = {				\
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
static const struct ipahal_reg_obj ipahal_regs[] = {
	reg_obj_cfunc(ROUTE, route,		0x00000048,	0x0000),
	reg_obj_nofunc(IRQ_STTS_EE_n,		0x00003008,	0x1000),
	reg_obj_nofunc(IRQ_EN_EE_n,		0x0000300c,	0x1000),
	reg_obj_nofunc(IRQ_CLR_EE_n,		0x00003010,	0x1000),
	reg_obj_nofunc(IRQ_SUSPEND_INFO_EE_n,	0x00003030,	0x1000),
	reg_obj_nofunc(SUSPEND_IRQ_EN_EE_n,	0x00003034,	0x1000),
	reg_obj_nofunc(SUSPEND_IRQ_CLR_EE_n,	0x00003038,	0x1000),
	reg_obj_nofunc(BCR,			0x000001d0,	0x0000),
	reg_obj_nofunc(ENABLED_PIPES,		0x00000038,	0x0000),
	reg_obj_nofunc(TAG_TIMER,		0x00000060,	0x0000),
	reg_obj_nofunc(SPARE_REG_1,		0x00002780,	0x0000),
	reg_obj_nofunc(STATE_AGGR_ACTIVE,	0x0000010c,	0x0000),
	reg_obj_cfunc(ENDP_INIT_HDR_n,
			endp_init_hdr_n,	0x00000810,	0x0070),
	reg_obj_cfunc(ENDP_INIT_HDR_EXT_n,
			endp_init_hdr_ext_n,	0x00000814,	0x0070),
	reg_obj_both(ENDP_INIT_AGGR_n,
			endp_init_aggr_n,	0x00000824,	0x0070),
	reg_obj_nofunc(AGGR_FORCE_CLOSE,	0x000001ec,	0x0000),
	reg_obj_cfunc(ENDP_INIT_MODE_n,
			endp_init_mode_n,	0x00000820,	0x0070),
	reg_obj_both(ENDP_INIT_CTRL_n,
			endp_init_ctrl_n,	0x00000800,	0x0070),
	reg_obj_cfunc(ENDP_INIT_DEAGGR_n,
			endp_init_deaggr_n,	0x00000834,	0x0070),
	reg_obj_nofunc(ENDP_INIT_SEQ_n,		0x0000083c,	0x0070),
	reg_obj_cfunc(ENDP_INIT_CFG_n,
			endp_init_cfg_n,	0x00000808,	0x0070),
	reg_obj_nofunc(IRQ_EE_UC_n,		0x0000301c,	0x1000),
	reg_obj_cfunc(ENDP_INIT_HDR_METADATA_MASK_n,
			endp_init_hdr_metadata_mask_n, 0x00000818, 0x070),
	reg_obj_pfunc(SHARED_MEM_SIZE,
			shared_mem_size,	0x00000054,	0x0000),
	reg_obj_nofunc(SRAM_DIRECT_ACCESS_n,	0x00007000,	0x0004),
	reg_obj_nofunc(LOCAL_PKT_PROC_CNTXT_BASE,
			/* checkpatch! */	0x000001e8,	0x0000),
	reg_obj_cfunc(ENDP_STATUS_n,
			endp_status_n,		0x00000840,	0x0070),
	reg_obj_both(ENDP_FILTER_ROUTER_HSH_CFG_n,
			hash_cfg_n,		0x0000085c,	0x0070),
	reg_obj_cfunc(SRC_RSRC_GRP_01_RSRC_TYPE_n,
			rsrg_grp_xy,		0x00000400,	0x0020),
	reg_obj_cfunc(SRC_RSRC_GRP_23_RSRC_TYPE_n,
			rsrg_grp_xy,		0x00000404,	0x0020),
	reg_obj_cfunc(DST_RSRC_GRP_01_RSRC_TYPE_n,
			rsrg_grp_xy,		0x00000500,	0x0020),
	reg_obj_cfunc(DST_RSRC_GRP_23_RSRC_TYPE_n,
			rsrg_grp_xy,		0x00000504,	0x0020),
	reg_obj_cfunc(QSB_MAX_WRITES,
			qsb_max_writes,		0x00000074,	0x0000),
	reg_obj_cfunc(QSB_MAX_READS,
			qsb_max_reads,		0x00000078,	0x0000),
	reg_obj_cfunc(IDLE_INDICATION_CFG,
			idle_indication_cfg,	0x00000220,	0x0000),
	reg_obj_nofunc(DPS_SEQUENCER_FIRST,	0x0001e000,	0x0000),
	reg_obj_nofunc(HPS_SEQUENCER_FIRST,	0x0001e080,	0x0000),
	reg_obj_nofunc(ENABLE_GSI,		0x00002790,	0x0000),
	reg_obj_nofunc(ENDP_GSI_CFG_TLV_n,	0x00002924,	0x0004),
	reg_obj_nofunc(ENDP_GSI_CFG_AOS_n,	0x000029a8,	0x0004),
	reg_obj_nofunc(ENDP_GSI_CFG1_n,		0x00002794,	0x0004),
	reg_obj_nofunc(ENDP_GSI_CFG2_n,		0x00002a2c,	0x0004),
};

#undef reg_obj_nofunc
#undef reg_obj_both
#undef reg_obj_pfunc
#undef reg_obj_cfunc
#undef reg_obj_common
#undef idsym
#undef pfunc
#undef cfunc

/* Get the offset of an "n parameterized" register */
u32 ipahal_reg_n_offset(enum ipahal_reg reg, u32 n)
{
	u32 offset;

	offset = ipahal_regs[reg].offset;
	offset += ipahal_regs[reg].n_ofst * n;

	return offset;
}

/* ipahal_read_reg_n() - Get an "n parameterized" register's value */
u32 ipahal_read_reg_n(enum ipahal_reg reg, u32 n)
{
	return ioread32(ipahal_ctx->base + ipahal_reg_n_offset(reg, n));
}

/* ipahal_write_reg_n() - Write a raw value to an "n parameterized" register */
void ipahal_write_reg_n(enum ipahal_reg reg, u32 n, u32 val)
{
	iowrite32(val, ipahal_ctx->base + ipahal_reg_n_offset(reg, n));
}

/* ipahal_read_reg_n_fields() - Parse value of an "n parameterized" register */
void ipahal_read_reg_n_fields(enum ipahal_reg reg, u32 n, void *fields)
{
	u32 val = ipahal_read_reg_n(reg, n);

	ipa_assert(ipahal_regs[reg].parse);

	ipahal_regs[reg].parse(reg, fields, val);
}

/* ipahal_write_reg_n_fields() - Construct a vlaue to write to an "n
 * parameterized" register
 */
void ipahal_write_reg_n_fields(enum ipahal_reg reg, u32 n, const void *fields)
{
	u32 val;

	ipa_assert(ipahal_regs[reg].construct);

	val = ipahal_regs[reg].construct(reg, fields);
	ipahal_write_reg_n(reg, n, val);
}

u32 ipahal_aggr_get_max_byte_limit(void)
{
	return field_val(0xffffffff, AGGR_BYTE_LIMIT_BMSK);
}

u32 ipahal_aggr_get_max_pkt_limit(void)
{
	return field_val(0xffffffff, AGGR_PKT_LIMIT_BMSK);
}
