/* Copyright (c) 2012-2017, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
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
#include "ipahal_i.h"
#include "ipahal_reg.h"
#include "ipahal_reg_i.h"

/*
 * struct ipahal_reg_obj - Register H/W information for specific IPA version
 * @construct - CB to construct register value from abstracted structure
 * @parse - CB to parse register value to abstracted structure
 * @name - register "name" (i.e., symbolic identifier)
 * @offset - register offset relative to base address (or OFFSET_INVAL)
 * @n_ofst - N parameterized register sub-offset
 */
struct ipahal_reg_obj {
	u32 (*construct)(enum ipahal_reg reg, const void *fields);
	void (*parse)(enum ipahal_reg reg, void *fields, u32 val);
	const char *name;
	u32 offset;
	u16 n_ofst;
};

static struct ipahal_reg_obj ipahal_regs[IPA_REG_MAX];

static u32
ipareg_construct_rx_hps_clients_depth0_v3_5(enum ipahal_reg reg,
		const void *fields)
{
	const struct ipahal_reg_rx_hps_clients *clients = fields;
	u32 val;

	val = field_gen(clients->client_minmax[0],
			MINMAX_DEPTH_X_CLIENT_n_BMSK_V3_5(0));
	val |= field_gen(clients->client_minmax[1],
			MINMAX_DEPTH_X_CLIENT_n_BMSK_V3_5(1));
	val |= field_gen(clients->client_minmax[2],
			MINMAX_DEPTH_X_CLIENT_n_BMSK_V3_5(2));
	val |= field_gen(clients->client_minmax[3],
			MINMAX_DEPTH_X_CLIENT_n_BMSK_V3_5(3));

	return val;
}

static u32
ipareg_construct_rsrg_grp_xy_v3_5(enum ipahal_reg reg, const void *fields)
{
	const struct ipahal_reg_rsrc_grp_cfg *grp = fields;
	u32 val;

	val = field_gen(grp->x_min, X_MIN_LIM_BMSK_V3_5);
	val |= field_gen(grp->x_max, X_MAX_LIM_BMSK_V3_5);

	/* DST_23 register has only X fields at ipa V3_5 */
	if (reg == IPA_DST_RSRC_GRP_23_RSRC_TYPE_n)
		return val;

	val |= field_gen(grp->y_min, Y_MIN_LIM_BMSK_V3_5);
	val |= field_gen(grp->y_max, Y_MAX_LIM_BMSK_V3_5);

	return val;
}

static u32
ipareg_construct_hash_cfg_n(enum ipahal_reg reg, const void *fields)
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

static void
ipareg_parse_hash_cfg_n(enum ipahal_reg reg, void *fields, u32 val)
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

static u32
ipareg_construct_qcncm(enum ipahal_reg reg, const void *fields)
{
	const struct ipahal_reg_qcncm *qcncm = fields;
	u32 val;

	val = field_gen(qcncm->mode_en ? 1 : 0, MODE_EN_BMSK);
	val |= field_gen(qcncm->mode_val, MODE_VAL_BMSK);
	val |= field_gen(qcncm->undef1, QCNCM_UNDEFINED1_BMSK);
	val |= field_gen(qcncm->undef2, MODE_UNDEFINED2_BMSK);

	return val;
}

static void
ipareg_parse_qcncm(enum ipahal_reg reg, void *fields, u32 val)
{
	struct ipahal_reg_qcncm *qcncm = fields;

	memset(qcncm, 0, sizeof(*qcncm));

	qcncm->mode_en = field_val(val, MODE_EN_BMSK);
	qcncm->mode_val = field_val(val, MODE_VAL_BMSK);
	qcncm->undef1 = field_val(val, QCNCM_UNDEFINED1_BMSK);
	qcncm->undef2 = field_val(val, MODE_UNDEFINED2_BMSK);
}

static u32
ipareg_construct_single_ndp_mode(enum ipahal_reg reg, const void *fields)
{
	const struct ipahal_reg_single_ndp_mode *mode = fields;
	u32 val;

	val = field_gen(mode->single_ndp_en ? 1 : 0, SINGLE_NDP_EN_BMSK);
	val |= field_gen(mode->undefined, SINGLE_NDP_UNDEFINED_BMSK);

	return val;
}

static void
ipareg_parse_single_ndp_mode(enum ipahal_reg reg, void *fields, u32 val)
{
	struct ipahal_reg_single_ndp_mode *mode = fields;

	memset(mode, 0, sizeof(*mode));

	mode->single_ndp_en = field_val(val, SINGLE_NDP_EN_BMSK);
	mode->undefined = field_val(val, SINGLE_NDP_UNDEFINED_BMSK);
}

static bool
debug_cnt_ctrl_type_valid(u8 dbg_cnt_ctrl_type, enum ipahal_reg reg)
{
	switch (dbg_cnt_ctrl_type) {
	case DBG_CNT_TYPE_IPV4_FLTR:
	case DBG_CNT_TYPE_IPV4_ROUT:
	case DBG_CNT_TYPE_GENERAL:
	case DBG_CNT_TYPE_IPV6_FLTR:
	case DBG_CNT_TYPE_IPV6_ROUT:
		return true;
	default:
		break;
	}

	ipa_err("Invalid dbg_cnt_ctrl type (%hhu) for %s\n",
			dbg_cnt_ctrl_type, ipahal_regs[reg].name);

	return false;
}

static u32
ipareg_construct_debug_cnt_ctrl_n(enum ipahal_reg reg, const void *fields)
{
	const struct ipahal_reg_debug_cnt_ctrl *dbg_cnt_ctrl = fields;
	u32 val;
	u8 type = (u8)dbg_cnt_ctrl->type;

	if (WARN_ON(!debug_cnt_ctrl_type_valid(type, reg)))
		return 0;

	if (type == DBG_CNT_TYPE_IPV4_FLTR || type == DBG_CNT_TYPE_IPV6_FLTR)
		if (WARN_ON(!dbg_cnt_ctrl->rule_idx_pipe_rule))
			ipa_err("No FLT global rules\n");

	val = field_gen(dbg_cnt_ctrl->en ? 1 : 0, DBG_CNT_EN_BMSK);
	val |= field_gen(type, DBG_CNT_TYPE_BMSK);
	val |= field_gen(dbg_cnt_ctrl->product ? 1 : 0, PRODUCT_BMSK);
	val |= field_gen(dbg_cnt_ctrl->src_pipe, SOURCE_PIPE_BMSK);
	val |= field_gen(dbg_cnt_ctrl->rule_idx, RULE_INDEX_BMSK_V3_5);

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
ipareg_construct_endp_init_rsrc_grp_n_v3_5(enum ipahal_reg reg,
		const void *fields)
{
	const struct ipahal_reg_endp_init_rsrc_grp *rsrc_grp = fields;

	return field_gen(rsrc_grp->rsrc_grp, RSRC_GRP_BMSK_v3_5);
}

static u32
ipareg_construct_endp_init_hdr_metadata_n(enum ipahal_reg reg,
		const void *fields)
{
	const struct ipa_ep_cfg_metadata *metadata = fields;

	return field_gen(metadata->qmap_id, METADATA_BMSK);
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
		break;
	}

	ipa_err("Invalid cs_offload_en value for %s\n", ipahal_regs[reg].name);

	return false;
}

static u32
ipareg_construct_endp_init_cfg_n(enum ipahal_reg reg, const void *fields)
{
	const struct ipa_ep_cfg_cfg *cfg = fields;
	u32 val;

	if (WARN_ON(!cs_offload_en_valid(cfg->cs_offload_en, reg)))
		return 0;

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
ipareg_construct_endp_init_hol_block_en_n(enum ipahal_reg reg,
		const void *fields)
{
	const struct ipa_ep_cfg_holb *ep_holb = fields;

	return field_gen(ep_holb->en, HOL_BLOCK_EN_BMSK);
}

static u32
ipareg_construct_endp_init_hol_block_timer_n(enum ipahal_reg reg,
		const void *fields)
{
	const struct ipa_ep_cfg_holb *ep_holb = fields;

	return field_gen(ep_holb->tmr_val, TIMER_BMSK);
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
ipareg_parse_endp_init_ctrl_n(enum ipahal_reg reg,void *fields, u32 val)
{
	struct ipa_ep_cfg_ctrl *ep_ctrl = fields;

	memset(ep_ctrl, 0, sizeof(*ep_ctrl));

	ep_ctrl->ipa_ep_suspend = field_val(val, ENDP_SUSPEND_BMSK);
	ep_ctrl->ipa_ep_delay = field_val(val, ENDP_DELAY_BMSK);
}

static u32
ipareg_construct_endp_init_ctrl_scnd_n(enum ipahal_reg reg, const void *fields)
{
	const struct ipahal_ep_cfg_ctrl_scnd *ep_ctrl_scnd = fields;

	return field_gen(ep_ctrl_scnd->endp_delay, ENDP_DELAY_BMSK);
}

static u32
ipareg_construct_endp_init_nat_n(enum ipahal_reg reg, const void *fields)
{
	const struct ipa_ep_cfg_nat *ep_nat = fields;

	return field_gen(ep_nat->nat_en, NAT_EN_BMSK);
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

static u32
ipareg_construct_endp_init_route_n(enum ipahal_reg reg, const void *fields)
{
	const struct ipahal_reg_endp_init_route *ep_init_rt = fields;

	return field_gen(ep_init_rt->route_table_index, ROUTE_TABLE_INDEX_BMSK);
}

static void
ipareg_parse_endp_init_aggr_n(enum ipahal_reg reg,void *fields, u32 val)
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
			HDR_PAD_TO_ALIGNMENT_BMSK_v3_0);
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
			HDR_METADATA_REG_VALID_BMSK_v2);
	val |= field_gen(ep_hdr->hdr_remove_additional,
			HDR_LEN_INC_DEAGG_HDR_BMSK_v2);
	val |= field_gen(ep_hdr->hdr_a5_mux, HDR_A5_MUX_BMSK);
	val |= field_gen(ep_hdr->hdr_ofst_pkt_size, HDR_OFST_PKT_SIZE_BMSK);
	val |= field_gen(ep_hdr->hdr_ofst_pkt_size_valid,
			HDR_OFST_PKT_SIZE_VALID_BMSK);
	val |= field_gen(ep_hdr->hdr_additional_const_len,
			HDR_ADDITIONAL_CONST_LEN_BMSK);
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

static void
ipareg_parse_tx_cfg(enum ipahal_reg reg,void *fields, u32 val)
{
	struct ipahal_reg_tx_cfg *tx_cfg = fields;

	memset(tx_cfg, 0, sizeof(*tx_cfg));

	tx_cfg->tx0_prefetch_disable =
		field_val(val, TX0_PREFETCH_DISABLE_BMSK_V3_5);
	tx_cfg->tx1_prefetch_disable =
		field_val(val, TX1_PREFETCH_DISABLE_BMSK_V3_5);
	tx_cfg->tx0_prefetch_almost_empty_size =
		field_val(val, PREFETCH_ALMOST_EMPTY_SIZE_BMSK_V3_5);
	tx_cfg->tx1_prefetch_almost_empty_size =
		tx_cfg->tx0_prefetch_almost_empty_size;
}

static u32
ipareg_construct_tx_cfg(enum ipahal_reg reg, const void *fields)
{
	const struct ipahal_reg_tx_cfg *tx_cfg = fields;
	u32 val;

	val = field_gen(tx_cfg->tx0_prefetch_disable,
			TX0_PREFETCH_DISABLE_BMSK_V3_5);
	val |= field_gen(tx_cfg->tx1_prefetch_disable,
			TX1_PREFETCH_DISABLE_BMSK_V3_5);
	val |= field_gen(tx_cfg->tx0_prefetch_almost_empty_size,
			PREFETCH_ALMOST_EMPTY_SIZE_BMSK_V3_5);

	return val;
}

static u32
ipareg_construct_idle_indication_cfg(enum ipahal_reg reg, const void *fields)
{
	const struct ipahal_reg_idle_indication_cfg *idle_indication_cfg;
	u32 val;

	idle_indication_cfg = fields;

	val = field_gen(idle_indication_cfg->enter_idle_debounce_thresh,
			ENTER_IDLE_DEBOUNCE_THRESH_BMSK_V3_5);
	val |= field_gen(idle_indication_cfg->const_non_idle_enable,
			CONST_NON_IDLE_ENABLE_BMSK_V3_5);

	return val;
}

static u32
ipareg_construct_hps_queue_weights(enum ipahal_reg reg, const void *fields)
{
	const struct ipahal_reg_rx_hps_weights *hps_weights = fields;
	u32 val;

	val = field_gen(hps_weights->hps_queue_weight_0,
			RX_HPS_QUEUE_WEIGHT_0_BMSK);
	val |= field_gen(hps_weights->hps_queue_weight_1,
			RX_HPS_QUEUE_WEIGHT_1_BMSK);
	val |= field_gen(hps_weights->hps_queue_weight_2,
			RX_HPS_QUEUE_WEIGHT_2_BMSK);
	val |= field_gen(hps_weights->hps_queue_weight_3,
			RX_HPS_QUEUE_WEIGHT_3_BMSK);

	return val;
}

static void
ipareg_parse_hps_queue_weights(enum ipahal_reg reg, void *fields, u32 val)
{
	struct ipahal_reg_rx_hps_weights *hps_weights = fields;

	memset(hps_weights, 0, sizeof(*hps_weights));

	hps_weights->hps_queue_weight_0 =
		field_val(val, RX_HPS_QUEUE_WEIGHT_0_BMSK);
	hps_weights->hps_queue_weight_1 =
		field_val(val, RX_HPS_QUEUE_WEIGHT_1_BMSK);
	hps_weights->hps_queue_weight_2 =
		field_val(val, RX_HPS_QUEUE_WEIGHT_2_BMSK);
	hps_weights->hps_queue_weight_3 =
		field_val(val, RX_HPS_QUEUE_WEIGHT_3_BMSK);
}

/*
 * The offsets of certain registers may change between different
 * versions of IPA hardware.  In addition, the format of information
 * read or written for a particular register change slightly for new
 * hardware.  The "ipahal" layer hides this by abstracting register
 * access, allowing access to each register to be performed using a
 * symbolic name.
 *
 * The following table consists of blocks of "register object"
 * definitions associated with versions of IPA hardware.  The first
 * version of IPA hardware supported by the "ipahal" layer is 3.5.1;
 * essentially all registers needed for IPA operation have a
 * register object associated with IPA_HW_v3_5_1.
 *
 * Versions of IPA hardware newer than 3.1 do not need to specify
 * register object entries if they are accessed the same way as was
 * defined by an older version.  The only entries defined for newer
 * hardware are registers whose offset or data format has changed,
 * or registers that are new and not present in older hardware.
 *
 * XXX The rest of this will be fixed after other versions are removed
 *
 * IPA version 3.1, for example, has only three entries defined:
 * IPA_IRQ_SUSPEND_INFO_EE_n, which is located at a different
 * offset than in IPA version 3.0; and IPA_SUSPEND_IRQ_EN_EE_n
 * and IPA_SUSPEND_IRQ_CLR_EE_n, which were not previously defined.
 * All other registers will use the access method defined for IPA
 * version 3.0.
 *
 * The definitions used for each hardware version is based on the
 * definition used by the next earlier version.  So IPA hardware
 * version 3.5 uses definitions for version 3.1, and its block of
 * register objects will consist only of overrides, or registers
 * not defined prior to version 3.5.
 *
 * The entries in this table have the following constraints:
 * - 0 is not a valid offset; an entry having a 0 offset is
 *   indicates the corresponding register is accessed according
 *   to a register object defined for an earlier hardware version.
 *   It is a bug for code to attempt to access a register which
 *   has an undefined (zero) offset value.
 * - An offset of OFFSET_INVAL indicates that a register is not
 *   supported for a particular hardware version.  It is a bug for
 *   code to attempt to access an unsupported register.
 * - If a construct function is supplied, the register must be
 *   written using ipahal_write_reg_n_fields() (or its wrapper
 *   function ipahal_write_reg_fields()).
 * - Generally, if a parse function is supplied, the register should
 *   generally only be read using ipahal_read_reg_n_fields() (or
 *   ipahal_read_reg_fields()).  (Currently some debug code reads
 *   some registers directly, without parsing.)
 */
#define OFFSET_INVAL	((u32)0xffffffff)

#define cfunc(f)	ipareg_construct_ ## f
#define pfunc(f)	ipareg_parse_ ## f
#define idsym(id)	IPA_ ## id
#define reg_obj_common(id, cf, pf, o, n)	\
	[idsym(id)] = {				\
		.construct = cf,		\
		.parse = pf,			\
		.name = #id,			\
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

static const struct ipahal_reg_obj ipahal_reg_objs[][IPA_REG_MAX] = {
	/* IPAv3.5.1 */
	[IPA_HW_v3_5_1] = {
		reg_obj_cfunc(ROUTE, route,		0x00000048,	0x0000),
		reg_obj_nofunc(IRQ_STTS_EE_n,		0x00003008,	0x1000),
		reg_obj_nofunc(IRQ_EN_EE_n,		0x0000300c,	0x1000),
		reg_obj_nofunc(IRQ_CLR_EE_n,		0x00003010,	0x1000),
		reg_obj_nofunc(IRQ_SUSPEND_INFO_EE_n,	0x00003030,	0x1000),
		reg_obj_nofunc(SUSPEND_IRQ_EN_EE_n,	0x00003034,	0x1000),
		reg_obj_nofunc(SUSPEND_IRQ_CLR_EE_n,	0x00003038,	0x1000),
		reg_obj_nofunc(BCR,			0x000001d0,	0x0000),
		reg_obj_nofunc(ENABLED_PIPES,		0x00000038,	0x0000),
		reg_obj_nofunc(COMP_SW_RESET,		0x00000040,	0x0000),
		reg_obj_nofunc(VERSION,			0x00000034,	0x0000),
		reg_obj_nofunc(TAG_TIMER,		0x00000060,	0x0000),
		reg_obj_nofunc(COMP_HW_VERSION,		0x00000030,	0x0000),
		reg_obj_nofunc(SPARE_REG_1,		0x00002780,	0x0000),
		reg_obj_nofunc(SPARE_REG_2,		0x00002784,	0x0000),
		reg_obj_nofunc(COMP_CFG,		0x0000003c,	0x0000),
		reg_obj_nofunc(STATE_AGGR_ACTIVE,	0x0000010c,	0x0000),
		reg_obj_cfunc(ENDP_INIT_HDR_n, endp_init_hdr_n,
							0x00000810,	0x0070),
		reg_obj_cfunc(ENDP_INIT_HDR_EXT_n, endp_init_hdr_ext_n,
							0x00000814,	0x0070),
		reg_obj_both(ENDP_INIT_AGGR_n, endp_init_aggr_n,
							0x00000824,	0x0070),
		reg_obj_nofunc(AGGR_FORCE_CLOSE,	0x000001ec,	0x0000),
		reg_obj_cfunc(ENDP_INIT_ROUTE_n, endp_init_route_n,
							0x00000828,	0x0070),
		reg_obj_cfunc(ENDP_INIT_MODE_n, endp_init_mode_n,
							0x00000820,	0x0070),
		reg_obj_cfunc(ENDP_INIT_NAT_n, endp_init_nat_n,
							0x0000080c,	0x0070),
		reg_obj_both(ENDP_INIT_CTRL_n, endp_init_ctrl_n,
							0x00000800,	0x0070),
		reg_obj_cfunc(ENDP_INIT_CTRL_SCND_n, endp_init_ctrl_scnd_n,
							0x00000804,	0x0070),
		reg_obj_cfunc(ENDP_INIT_HOL_BLOCK_EN_n,
				endp_init_hol_block_en_n,
							0x0000082c,	0x0070),
		reg_obj_cfunc(ENDP_INIT_HOL_BLOCK_TIMER_n,
				endp_init_hol_block_timer_n,
							0x00000830,	0x0070),
		reg_obj_cfunc(ENDP_INIT_DEAGGR_n, endp_init_deaggr_n,
							0x00000834,	0x0070),
		reg_obj_nofunc(ENDP_INIT_SEQ_n,		0x0000083c,	0x0070),
		reg_obj_nofunc(DEBUG_CNT_REG_n,		0x00000600,	0x0004),
		reg_obj_cfunc(ENDP_INIT_CFG_n, endp_init_cfg_n,
							0x00000808,	0x0070),
		reg_obj_nofunc(IRQ_EE_UC_n,		0x0000301c,	0x1000),
		reg_obj_cfunc(ENDP_INIT_HDR_METADATA_MASK_n,
				endp_init_hdr_metadata_mask_n,
							0x00000818,	0x0070),
		reg_obj_cfunc(ENDP_INIT_HDR_METADATA_n,
				endp_init_hdr_metadata_n,
							0x0000081c,	0x0070),
		reg_obj_cfunc(ENDP_INIT_RSRC_GRP_n, endp_init_rsrc_grp_n_v3_5,
							0x00000838,	0x0070),
		reg_obj_pfunc(SHARED_MEM_SIZE, shared_mem_size,
							0x00000054,	0x0000),
		reg_obj_nofunc(SRAM_DIRECT_ACCESS_n,	0x00007000,	0x0004),
		reg_obj_cfunc(DEBUG_CNT_CTRL_n, debug_cnt_ctrl_n,
							0x00000640,	0x0004),
		reg_obj_nofunc(UC_MAILBOX_m_n,		0x00032000,	0x0004),
		reg_obj_nofunc(FILT_ROUT_HASH_FLUSH,	0x00000090,	0x0000),
		reg_obj_both(SINGLE_NDP_MODE, single_ndp_mode,
							0x00000068,	0x0000),
		reg_obj_both(QCNCM, qcncm,		0x00000064,	0x0000),
		reg_obj_nofunc(SYS_PKT_PROC_CNTXT_BASE, 0x000001e0,	0x0000),
		reg_obj_nofunc(LOCAL_PKT_PROC_CNTXT_BASE,
							0x000001e8,	0x0000),
		reg_obj_cfunc(ENDP_STATUS_n, endp_status_n,
							0x00000840,	0x0070),
		reg_obj_both(ENDP_FILTER_ROUTER_HSH_CFG_n, hash_cfg_n,
							0x0000085c,	0x0070),
		reg_obj_cfunc(SRC_RSRC_GRP_01_RSRC_TYPE_n, rsrg_grp_xy_v3_5,
							0x00000400,	0x0020),
		reg_obj_cfunc(SRC_RSRC_GRP_23_RSRC_TYPE_n, rsrg_grp_xy_v3_5,
							0x00000404,	0x0020),
		reg_obj_nofunc(SRC_RSRC_GRP_45_RSRC_TYPE_n,
							OFFSET_INVAL,	0x0000),
		reg_obj_nofunc(SRC_RSRC_GRP_67_RSRC_TYPE_n,
							OFFSET_INVAL,	0x0000),
		reg_obj_cfunc(DST_RSRC_GRP_01_RSRC_TYPE_n, rsrg_grp_xy_v3_5,
							0x00000500,	0x0020),
		reg_obj_cfunc(DST_RSRC_GRP_23_RSRC_TYPE_n, rsrg_grp_xy_v3_5,
							0x00000504,	0x0020),
		reg_obj_nofunc(DST_RSRC_GRP_45_RSRC_TYPE_n,
							OFFSET_INVAL,	0x0000),
		reg_obj_nofunc(DST_RSRC_GRP_67_RSRC_TYPE_n,
							OFFSET_INVAL,	0x0000),
		reg_obj_cfunc(RX_HPS_CLIENTS_MIN_DEPTH_0,
				rx_hps_clients_depth0_v3_5,
							0x000023c4,	0x0000),
		reg_obj_nofunc(RX_HPS_CLIENTS_MIN_DEPTH_1,
							OFFSET_INVAL,	0x0000),
		reg_obj_cfunc(RX_HPS_CLIENTS_MAX_DEPTH_0,
				rx_hps_clients_depth0_v3_5,
							0x000023cc,	0x0000),
		reg_obj_nofunc(RX_HPS_CLIENTS_MAX_DEPTH_1,
							OFFSET_INVAL,	0x0000),
		reg_obj_both(HPS_FTCH_ARB_QUEUE_WEIGHT, hps_queue_weights,
							0x000005a4,	0x0000),
		reg_obj_cfunc(QSB_MAX_WRITES, qsb_max_writes,
							0x00000074,	0x0000),
		reg_obj_cfunc(QSB_MAX_READS, qsb_max_reads,
							0x00000078,	0x0000),
		reg_obj_both(TX_CFG, tx_cfg,		0x000001fc,	0x0000),
		reg_obj_cfunc(IDLE_INDICATION_CFG, idle_indication_cfg,
							0x00000220,	0x0000),
		reg_obj_nofunc(DPS_SEQUENCER_FIRST,	0x0001e000,	0x0000),
		reg_obj_nofunc(HPS_SEQUENCER_FIRST,	0x0001e080,	0x0000),
	},
};
#undef reg_obj_nofunc
#undef reg_obj_both
#undef reg_obj_pfunc
#undef reg_obj_cfunc
#undef reg_obj_common
#undef idsym
#undef pfunc
#undef cfunc

/*
 * ipahal_reg_init() - Build the registers information table
 *  See ipahal_reg_objs[][] comments
 *
 * Note: As global variables are initialized with zero, any un-overridden
 *  register entry will be zero. By this we recognize them.
 */
void ipahal_reg_init(enum ipa_hw_version hw_version)
{
	int i;
	int j;

	ipa_assert(hw_version < ARRAY_SIZE(ipahal_reg_objs));

	ipa_debug_low("Entry - HW_TYPE=%d\n", hw_version);

	/* Build up the register descriptions we'll use */
	for (i = 0; i < IPA_REG_MAX ; i++) {
		for (j = hw_version; j >= 0; j--) {
			const struct ipahal_reg_obj *reg;

			reg = &ipahal_reg_objs[j][i];
			if (reg->offset) {
				ipahal_regs[i] = *reg;
				break;
			}
		}
	}
}

/*
 * Get the offset of a n parameterized register
 */
u32 ipahal_reg_n_offset(enum ipahal_reg reg, u32 n)
{
	u32 offset;

	ipa_debug_low("get offset of %s n=%u\n", ipahal_regs[reg].name, n);
	offset = ipahal_regs[reg].offset;
	ipa_assert(offset != OFFSET_INVAL);
	offset += ipahal_regs[reg].n_ofst * n;

	return offset;
}

/*
 * ipahal_read_reg_n() - Get n parameterized reg value
 */
u32 ipahal_read_reg_n(enum ipahal_reg reg, u32 n)
{
	return ioread32(ipahal_ctx->base + ipahal_reg_n_offset(reg, n));
}

/*
 * ipahal_write_reg_n() - Write to n parameterized reg a raw value
 */
void ipahal_write_reg_n(enum ipahal_reg reg, u32 n, u32 val)
{
	iowrite32(val, ipahal_ctx->base + ipahal_reg_n_offset(reg, n));
}

/*
 * ipahal_read_reg_n_fields() - Get the parsed value of n parameterized reg
 */
void ipahal_read_reg_n_fields(enum ipahal_reg reg, u32 n, void *fields)
{
	u32 val = ipahal_read_reg_n(reg, n);

	if (WARN_ON(!ipahal_regs[reg].parse))
		ipa_err("No parse function for %s\n", ipahal_regs[reg].name);
	else
		ipahal_regs[reg].parse(reg, fields, val);
}

/*
 * ipahal_write_reg_n_fields() - Write to n parameterized reg a parsed value
 */
void ipahal_write_reg_n_fields(enum ipahal_reg reg, u32 n,
		const void *fields)
{
	u32 val = 0;

	if (WARN_ON(!ipahal_regs[reg].construct))
		ipa_err("No construct function for %s\n",
			ipahal_regs[reg].name);
	else
		val = ipahal_regs[reg].construct(reg, fields);

	ipahal_write_reg_n(reg, n, val);
}

/*
 * Specific functions
 * These functions supply specific register values for specific operations
 *  that cannot be reached by generic functions.
 * E.g. To disable aggregation, need to write to specific bits of the AGGR
 *  register. The other bits should be untouched. This oeprate is very specific
 *  and cannot be generically defined. For such operations we define these
 *  specific functions.
 */

void ipahal_get_disable_aggr_valmask(struct ipahal_reg_valmask *valmask)
{
	valmask->val = field_val(0xffffffff, AGGR_FORCE_CLOSE_BMSK);
	valmask->mask = AGGR_FORCE_CLOSE_BMSK;

	valmask->val |= field_val(0x00000000, AGGR_EN_BMSK);
	valmask->mask |= AGGR_EN_BMSK;
}

u32 ipahal_aggr_get_max_byte_limit(void)
{
	return field_val(0xffffffff, AGGR_BYTE_LIMIT_BMSK);
}

u32 ipahal_aggr_get_max_pkt_limit(void)
{
	return field_val(0xffffffff, AGGR_PKT_LIMIT_BMSK);
}

void ipahal_get_aggr_force_close_valmask(int ep_idx,
	struct ipahal_reg_valmask *valmask)
{
	ipa_assert(ep_idx < sizeof(valmask->val) * 8);

	valmask->val |= field_gen(1U << ep_idx, PIPE_BITMAP_BMSK_V3_5);
	valmask->mask = PIPE_BITMAP_BMSK_V3_5;
}

void
ipahal_get_status_ep_valmask(int pipe_num, struct ipahal_reg_valmask *valmask)
{
	valmask->val = field_gen(pipe_num, STATUS_ENDP_BMSK);
	valmask->mask = STATUS_ENDP_BMSK;
}
