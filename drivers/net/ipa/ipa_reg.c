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

#include "field_mask.h"
#include "ipahal_i.h"
#include "ipa_reg.h"

/* I/O remapped base address of IPA register space */
static void __iomem *ipa_reg_virt;

/* struct ipa_reg_obj - Register H/W information for specific IPA version
 * @construct - CB to construct register value from abstracted structure
 * @parse - CB to parse register value to abstracted structure
 * @offset - register offset relative to base address
 * @n_ofst - N parameterized register sub-offset
 */
struct ipa_reg_obj {
	u32 (*construct)(enum ipa_reg reg, const void *fields);
	void (*parse)(enum ipa_reg reg, void *fields, u32 val);
	u32 offset;
	u16 n_ofst;
};

/* IPA_ROUTE register */
#define ROUTE_DIS_BMSK			0x00000001
#define ROUTE_DEF_PIPE_BMSK		0x0000003e
#define ROUTE_DEF_HDR_TABLE_BMSK	0x00000040
#define ROUTE_DEF_HDR_OFST_BMSK		0x0001ff80
#define ROUTE_FRAG_DEF_PIPE_BMSK	0x003e0000
#define ROUTE_DEF_RETAIN_HDR_BMSK	0x01000000

static u32
ipareg_construct_route(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_route *route = fields;
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

/* IPA_ENDP_INIT_HDR_N register */
#define HDR_LEN_BMSK			0x0000003f
#define HDR_OFST_METADATA_VALID_BMSK	0x00000040
#define HDR_OFST_METADATA_BMSK		0x00001f80
#define HDR_ADDITIONAL_CONST_LEN_BMSK	0x0007e000
#define HDR_OFST_PKT_SIZE_VALID_BMSK	0x00080000
#define HDR_OFST_PKT_SIZE_BMSK		0x03f00000
#define HDR_A5_MUX_BMSK			0x04000000
#define HDR_LEN_INC_DEAGG_HDR_BMSK	0x08000000
#define HDR_METADATA_REG_VALID_BMSK	0x10000000

static u32
ipareg_construct_endp_init_hdr_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_ep_cfg_hdr *ep_hdr = fields;
	u32 val;

	val = field_gen(ep_hdr->hdr_len, HDR_LEN_BMSK);
	val |= field_gen(ep_hdr->hdr_ofst_metadata_valid,
			 HDR_OFST_METADATA_VALID_BMSK);
	val |= field_gen(ep_hdr->hdr_ofst_metadata, HDR_OFST_METADATA_BMSK);
	val |= field_gen(0, HDR_ADDITIONAL_CONST_LEN_BMSK);
	val |= field_gen(ep_hdr->hdr_ofst_pkt_size_valid,
			 HDR_OFST_PKT_SIZE_VALID_BMSK);
	val |= field_gen(ep_hdr->hdr_ofst_pkt_size, HDR_OFST_PKT_SIZE_BMSK);
	val |= field_gen(0, HDR_A5_MUX_BMSK);
	val |= field_gen(0, HDR_LEN_INC_DEAGG_HDR_BMSK);
	val |= field_gen(0, HDR_METADATA_REG_VALID_BMSK);

	return val;
}

/* IPA_ENDP_INIT_HDR_EXT_N register */
#define HDR_ENDIANNESS_BMSK			0x00000001
#define HDR_TOTAL_LEN_OR_PAD_VALID_BMSK		0x00000002
#define HDR_TOTAL_LEN_OR_PAD_BMSK		0x00000004
#define HDR_PAYLOAD_LEN_INC_PADDING_BMSK	0x00000008
#define HDR_TOTAL_LEN_OR_PAD_OFFSET_BMSK	0x000003f0
#define HDR_PAD_TO_ALIGNMENT_BMSK		0x00003c00

static u32
ipareg_construct_endp_init_hdr_ext_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_ep_cfg_hdr_ext *ep_hdr_ext = fields;
	u32 val;

	/* 0 = little endian; 1 = big endian */
	val = field_gen(1, HDR_ENDIANNESS_BMSK);
	val |= field_gen(ep_hdr_ext->hdr_total_len_or_pad_valid ? 1 : 0,
			 HDR_TOTAL_LEN_OR_PAD_VALID_BMSK);
	val |= field_gen(ep_hdr_ext->hdr_total_len_or_pad,
			 HDR_TOTAL_LEN_OR_PAD_BMSK);
	val |= field_gen(ep_hdr_ext->hdr_payload_len_inc_padding ? 1 : 0,
			 HDR_PAYLOAD_LEN_INC_PADDING_BMSK);
	val |= field_gen(0, HDR_TOTAL_LEN_OR_PAD_OFFSET_BMSK);
	val |= field_gen(ep_hdr_ext->hdr_pad_to_alignment,
			 HDR_PAD_TO_ALIGNMENT_BMSK);

	return val;
}

/* IPA_ENDP_INIT_AGGR_N register */
#define AGGR_EN_BMSK				0x00000003
#define AGGR_TYPE_BMSK				0x0000001c
#define AGGR_BYTE_LIMIT_BMSK			0x000003e0
#define AGGR_TIME_LIMIT_BMSK			0x00007c00
#define AGGR_PKT_LIMIT_BMSK			0x001f8000
#define AGGR_SW_EOF_ACTIVE_BMSK			0x00200000
#define AGGR_FORCE_CLOSE_BMSK			0x00400000
#define AGGR_HARD_BYTE_LIMIT_ENABLE_BMSK	0x01000000

static u32
ipareg_construct_endp_init_aggr_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_ep_cfg_aggr *ep_aggr = fields;
	u32 val;

	val = field_gen(ep_aggr->aggr_en, AGGR_EN_BMSK);
	val |= field_gen(ep_aggr->aggr, AGGR_TYPE_BMSK);
	val |= field_gen(ep_aggr->aggr_byte_limit, AGGR_BYTE_LIMIT_BMSK);
	val |= field_gen(ep_aggr->aggr_time_limit, AGGR_TIME_LIMIT_BMSK);
	val |= field_gen(ep_aggr->aggr_pkt_limit, AGGR_PKT_LIMIT_BMSK);
	val |= field_gen(ep_aggr->aggr_sw_eof_active ? 1 : 0,
			 AGGR_SW_EOF_ACTIVE_BMSK);
	val |= field_gen(ep_aggr->aggr_hard_byte_limit_en,
			 AGGR_HARD_BYTE_LIMIT_ENABLE_BMSK);

	return val;
}

static void
ipareg_parse_endp_init_aggr_n(enum ipa_reg reg, void *fields, u32 val)
{
	struct ipa_ep_cfg_aggr *ep_aggr = fields;

	memset(ep_aggr, 0, sizeof(*ep_aggr));

	ep_aggr->aggr_en = field_val(val, AGGR_EN_BMSK) == IPA_ENABLE_AGGR;
	ep_aggr->aggr = field_val(val, AGGR_TYPE_BMSK);
	ep_aggr->aggr_byte_limit = field_val(val, AGGR_BYTE_LIMIT_BMSK);
	ep_aggr->aggr_time_limit = field_val(val, AGGR_TIME_LIMIT_BMSK);
	ep_aggr->aggr_pkt_limit = field_val(val, AGGR_PKT_LIMIT_BMSK);
	ep_aggr->aggr_sw_eof_active = !!field_val(val, AGGR_SW_EOF_ACTIVE_BMSK);
	ep_aggr->aggr_hard_byte_limit_en =
			field_val(val, AGGR_HARD_BYTE_LIMIT_ENABLE_BMSK);
}

/* IPA_AGGR_FORCE_CLOSE register */
#define PIPE_BITMAP_BMSK	0x000fffff

static u32
ipareg_construct_aggr_force_close(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_aggr_force_close *force_close = fields;

	return field_gen(force_close->pipe_bitmap, PIPE_BITMAP_BMSK);
}

/* IPA_ENDP_INIT_MODE_N register */
#define MODE_BMSK			0x00000007
#define DEST_PIPE_INDEX_BMSK		0x000001f0
#define BYTE_THRESHOLD_BMSK		0x0ffff000
#define PIPE_REPLICATION_EN_BMSK	0x10000000
#define PAD_EN_BMSK			0x20000000
#define HDR_FTCH_DISABLE_BMSK		0x40000000

static u32
ipareg_construct_endp_init_mode_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_endp_init_mode *init_mode = fields;
	u32 val;

	val = field_gen(init_mode->ep_mode.mode, MODE_BMSK);
	val |= field_gen(init_mode->dst_pipe_number, DEST_PIPE_INDEX_BMSK);
	val |= field_gen(0, BYTE_THRESHOLD_BMSK);
	val |= field_gen(0, PIPE_REPLICATION_EN_BMSK);
	val |= field_gen(0, PAD_EN_BMSK);
	val |= field_gen(0, HDR_FTCH_DISABLE_BMSK);

	return val;
}

/* IPA_ENDP_INIT_CTRL_N register */
#define ENDP_SUSPEND_BMSK	0x00000001
#define ENDP_DELAY_BMSK		0x00000002

static u32
ipareg_construct_endp_init_ctrl_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_ep_init_ctrl *ep_ctrl = fields;
	u32 val;

	val = field_gen(ep_ctrl->ipa_ep_suspend, ENDP_SUSPEND_BMSK);
	val |= field_gen(ep_ctrl->ipa_ep_delay, ENDP_DELAY_BMSK);

	return val;
}

static void
ipareg_parse_endp_init_ctrl_n(enum ipa_reg reg, void *fields, u32 val)
{
	struct ipa_reg_ep_init_ctrl *ep_ctrl = fields;

	memset(ep_ctrl, 0, sizeof(*ep_ctrl));

	ep_ctrl->ipa_ep_suspend = field_val(val, ENDP_SUSPEND_BMSK);
	ep_ctrl->ipa_ep_delay = field_val(val, ENDP_DELAY_BMSK);
}

/* IPA_ENDP_INIT_DEAGGR_N register */
#define DEAGGR_HDR_LEN_BMSK		0x0000003f
#define PACKET_OFFSET_VALID_BMSK	0x00000080
#define PACKET_OFFSET_LOCATION_BMSK	0x00003f00
#define MAX_PACKET_LEN_BMSK		0xffff0000

static u32
ipareg_construct_endp_init_deaggr_n(enum ipa_reg reg, const void *fields)
{
	u32 val;

	/* fields value is completely ignored (can be NULL) */
	val = field_gen(0, DEAGGR_HDR_LEN_BMSK);
	val |= field_gen(0, PACKET_OFFSET_VALID_BMSK);
	val |= field_gen(0, PACKET_OFFSET_LOCATION_BMSK);
	val |= field_gen(0, MAX_PACKET_LEN_BMSK);

	return val;
}

/* IPA_ENDP_INIT_SEQ_N register */
#define HPS_SEQ_TYPE_BMSK	0x0000000f
#define DPS_SEQ_TYPE_BMSK	0x000000f0
#define HPS_REP_SEQ_TYPE_BMSK	0x00000f00
#define DPS_REP_SEQ_TYPE_BMSK	0x0000f000

static u32
ipareg_construct_endp_init_seq_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_ep_init_seq *ep_seq = fields;
	u32 val;

	val = field_gen(0, DPS_REP_SEQ_TYPE_BMSK);
	val |= field_gen(0, HPS_REP_SEQ_TYPE_BMSK);
	val |= field_gen(0, DPS_SEQ_TYPE_BMSK);
	val |= field_gen(ep_seq->hps_seq_type, HPS_SEQ_TYPE_BMSK);

	return val;
}

/* IPA_ENDP_INIT_CFG_N register */
#define FRAG_OFFLOAD_EN_BMSK		0x00000001
#define CS_OFFLOAD_EN_BMSK		0x00000006
#define CS_METADATA_HDR_OFFSET_BMSK	0x00000078
#define CS_GEN_QMB_MASTER_SEL_BMSK	0x00000100

static u32
ipareg_construct_endp_init_cfg_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_ep_cfg_cfg *cfg = fields;
	u32 val;

	val = field_gen(0, FRAG_OFFLOAD_EN_BMSK);
	val |= field_gen(cfg->cs_offload_en, CS_OFFLOAD_EN_BMSK);
	val |= field_gen(cfg->cs_metadata_hdr_offset,
			 CS_METADATA_HDR_OFFSET_BMSK);
	val |= field_gen(0, CS_GEN_QMB_MASTER_SEL_BMSK);

	return val;
}

/* IPA_ENDP_INIT_HDR_METADATA_MASK_N register */
#define METADATA_MASK_BMSK	0xffffffff

static u32
ipareg_construct_endp_init_hdr_metadata_mask_n(enum ipa_reg reg,
					       const void *fields)
{
	const struct ipa_ep_cfg_metadata_mask *metadata_mask = fields;

	return field_gen(metadata_mask->metadata_mask, METADATA_MASK_BMSK);
}

/* IPA_SHARED_MEM_SIZE register */
#define SHARED_MEM_SIZE_BMSK	0x0000ffff
#define SHARED_MEM_BADDR_BMSK	0xffff0000

static void
ipareg_parse_shared_mem_size(enum ipa_reg reg, void *fields, u32 val)
{
	struct ipa_reg_shared_mem_size *smem_sz = fields;

	memset(smem_sz, 0, sizeof(*smem_sz));

	smem_sz->shared_mem_sz = field_val(val, SHARED_MEM_SIZE_BMSK);
	smem_sz->shared_mem_baddr = field_val(val, SHARED_MEM_BADDR_BMSK);
}

/* IPA_ENDP_STATUS_N register */
#define STATUS_EN_BMSK			0x00000001
#define STATUS_ENDP_BMSK		0x0000003e
#define STATUS_LOCATION_BMSK		0x00000100
#define STATUS_PKT_SUPPRESS_BMSK	0x00000200

static u32
ipareg_construct_endp_status_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_ep_status *ep_status = fields;
	u32 val;

	val = field_gen(ep_status->status_en, STATUS_EN_BMSK);
	val |= field_gen(ep_status->status_ep, STATUS_ENDP_BMSK);
	val |= field_gen(ep_status->status_location, STATUS_LOCATION_BMSK);
	val |= field_gen(0, STATUS_PKT_SUPPRESS_BMSK);

	return val;
}

/* IPA_ENDP_FILTER_ROUTER_HSH_CFG_N register */
#define FILTER_HASH_MSK_SRC_ID_BMSK	0x00000001
#define FILTER_HASH_MSK_SRC_IP_BMSK	0x00000002
#define FILTER_HASH_MSK_DST_IP_BMSK	0x00000004
#define FILTER_HASH_MSK_SRC_PORT_BMSK	0x00000008
#define FILTER_HASH_MSK_DST_PORT_BMSK	0x00000010
#define FILTER_HASH_MSK_PROTOCOL_BMSK	0x00000020
#define FILTER_HASH_MSK_METADATA_BMSK	0x00000040
#define FILTER_HASH_UNDEFINED1_BMSK	0x0000ff80

#define ROUTER_HASH_MSK_SRC_ID_BMSK	0x00010000
#define ROUTER_HASH_MSK_SRC_IP_BMSK	0x00020000
#define ROUTER_HASH_MSK_DST_IP_BMSK	0x00040000
#define ROUTER_HASH_MSK_SRC_PORT_BMSK	0x00080000
#define ROUTER_HASH_MSK_DST_PORT_BMSK	0x00100000
#define ROUTER_HASH_MSK_PROTOCOL_BMSK	0x00200000
#define ROUTER_HASH_MSK_METADATA_BMSK	0x00400000
#define ROUTER_HASH_UNDEFINED2_BMSK	0xff800000

static u32 ipareg_construct_hash_cfg_n(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_fltrt_hash_tuple *tuple = fields;
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

static void ipareg_parse_hash_cfg_n(enum ipa_reg reg, void *fields, u32 val)
{
	struct ipa_reg_fltrt_hash_tuple *tuple = fields;

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

/* IPA_RSRC_GRP_XY_RSRC_TYPE_n register */
#define X_MIN_LIM_BMSK	0x0000003f
#define X_MAX_LIM_BMSK	0x00003f00
#define Y_MIN_LIM_BMSK	0x003f0000
#define Y_MAX_LIM_BMSK	0x3f000000

static u32 ipareg_construct_rsrg_grp_xy(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_rsrc_grp_cfg *grp = fields;
	u32 val;

	val = field_gen(grp->x_min, X_MIN_LIM_BMSK);
	val |= field_gen(grp->x_max, X_MAX_LIM_BMSK);

	/* DST_23 register has only X fields at ipa V3_5 */
	if (reg == IPA_DST_RSRC_GRP_23_RSRC_TYPE_N)
		return val;

	val |= field_gen(grp->y_min, Y_MIN_LIM_BMSK);
	val |= field_gen(grp->y_max, Y_MAX_LIM_BMSK);

	return val;
}

/* IPA_QSB_MAX_WRITES register */
#define GEN_QMB_0_MAX_WRITES_BMSK	0x0000000f
#define GEN_QMB_1_MAX_WRITES_BMSK	0x000000f0

static u32
ipareg_construct_qsb_max_writes(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_qsb_max_writes *max_writes = fields;
	u32 val;

	val = field_gen(max_writes->qmb_0_max_writes,
			GEN_QMB_0_MAX_WRITES_BMSK);
	val |= field_gen(max_writes->qmb_1_max_writes,
			 GEN_QMB_1_MAX_WRITES_BMSK);

	return val;
}

/* IPA_QSB_MAX_READS register */
#define GEN_QMB_0_MAX_READS_BMSK	0x0000000f
#define GEN_QMB_1_MAX_READS_BMSK	0x000000f0

static u32
ipareg_construct_qsb_max_reads(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_qsb_max_reads *max_reads = fields;
	u32 val;

	val = field_gen(max_reads->qmb_0_max_reads, GEN_QMB_0_MAX_READS_BMSK);
	val |= field_gen(max_reads->qmb_1_max_reads, GEN_QMB_1_MAX_READS_BMSK);

	return val;
}

/* IPA_IDLE_INDICATION_CFG regiser */
#define ENTER_IDLE_DEBOUNCE_THRESH_BMSK	0x0000ffff
#define CONST_NON_IDLE_ENABLE_BMSK	0x00010000

static u32
ipareg_construct_idle_indication_cfg(enum ipa_reg reg, const void *fields)
{
	const struct ipa_reg_idle_indication_cfg *idle_indication_cfg;
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
static const struct ipa_reg_obj ipa_regs[] = {
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
	return ipa_regs[reg].offset + n * ipa_regs[reg].n_ofst;
}

/* ipahal_read_reg_n() - Get an "n parameterized" register's value */
u32 ipahal_read_reg_n(enum ipa_reg reg, u32 n)
{
	return ioread32(ipa_reg_virt + ipa_reg_n_offset(reg, n));
}

/* ipahal_write_reg_n() - Write a raw value to an "n parameterized" register */
void ipahal_write_reg_n(enum ipa_reg reg, u32 n, u32 val)
{
	iowrite32(val, ipa_reg_virt + ipa_reg_n_offset(reg, n));
}

/* ipahal_read_reg_n_fields() - Parse value of an "n parameterized" register */
void ipahal_read_reg_n_fields(enum ipa_reg reg, u32 n, void *fields)
{
	u32 val = ipahal_read_reg_n(reg, n);

	ipa_regs[reg].parse(reg, fields, val);
}

/* ipahal_write_reg_n_fields() - Construct a vlaue to write to an "n
 * parameterized" register
 */
void ipahal_write_reg_n_fields(enum ipa_reg reg, u32 n, const void *fields)
{
	u32 val = ipa_regs[reg].construct(reg, fields);

	ipahal_write_reg_n(reg, n, val);
}

/* Maximum representable aggregation byte limit value */
u32 ipahal_aggr_get_max_byte_limit(void)
{
	return field_max(AGGR_BYTE_LIMIT_BMSK);
}

/* Maximum representable aggregation packet limit value */
u32 ipahal_aggr_get_max_pkt_limit(void)
{
	return field_max(AGGR_PKT_LIMIT_BMSK);
}
