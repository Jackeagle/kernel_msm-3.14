/* Copyright (c) 2012-2017, The Linux Foundation. All rights reserved.
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

static const char *ipareg_name_to_str[IPA_REG_MAX] = {
	__stringify(IPA_ROUTE),
	__stringify(IPA_IRQ_STTS_EE_n),
	__stringify(IPA_IRQ_EN_EE_n),
	__stringify(IPA_IRQ_CLR_EE_n),
	__stringify(IPA_IRQ_SUSPEND_INFO_EE_n),
	__stringify(IPA_SUSPEND_IRQ_EN_EE_n),
	__stringify(IPA_SUSPEND_IRQ_CLR_EE_n),
	__stringify(IPA_BCR),
	__stringify(IPA_ENABLED_PIPES),
	__stringify(IPA_COMP_SW_RESET),
	__stringify(IPA_VERSION),
	__stringify(IPA_TAG_TIMER),
	__stringify(IPA_COMP_HW_VERSION),
	__stringify(IPA_SPARE_REG_1),
	__stringify(IPA_SPARE_REG_2),
	__stringify(IPA_COMP_CFG),
	__stringify(IPA_STATE_AGGR_ACTIVE),
	__stringify(IPA_ENDP_INIT_HDR_n),
	__stringify(IPA_ENDP_INIT_HDR_EXT_n),
	__stringify(IPA_ENDP_INIT_AGGR_n),
	__stringify(IPA_AGGR_FORCE_CLOSE),
	__stringify(IPA_ENDP_INIT_ROUTE_n),
	__stringify(IPA_ENDP_INIT_MODE_n),
	__stringify(IPA_ENDP_INIT_NAT_n),
	__stringify(IPA_ENDP_INIT_CONN_TRACK_n),
	__stringify(IPA_ENDP_INIT_CTRL_n),
	__stringify(IPA_ENDP_INIT_CTRL_SCND_n),
	__stringify(IPA_ENDP_INIT_HOL_BLOCK_EN_n),
	__stringify(IPA_ENDP_INIT_HOL_BLOCK_TIMER_n),
	__stringify(IPA_ENDP_INIT_DEAGGR_n),
	__stringify(IPA_ENDP_INIT_SEQ_n),
	__stringify(IPA_DEBUG_CNT_REG_n),
	__stringify(IPA_ENDP_INIT_CFG_n),
	__stringify(IPA_IRQ_EE_UC_n),
	__stringify(IPA_ENDP_INIT_HDR_METADATA_MASK_n),
	__stringify(IPA_ENDP_INIT_HDR_METADATA_n),
	__stringify(IPA_ENDP_INIT_RSRC_GRP_n),
	__stringify(IPA_SHARED_MEM_SIZE),
	__stringify(IPA_SRAM_DIRECT_ACCESS_n),
	__stringify(IPA_DEBUG_CNT_CTRL_n),
	__stringify(IPA_UC_MAILBOX_m_n),
	__stringify(IPA_FILT_ROUT_HASH_FLUSH),
	__stringify(IPA_SINGLE_NDP_MODE),
	__stringify(IPA_QCNCM),
	__stringify(IPA_SYS_PKT_PROC_CNTXT_BASE),
	__stringify(IPA_LOCAL_PKT_PROC_CNTXT_BASE),
	__stringify(IPA_ENDP_STATUS_n),
	__stringify(IPA_ENDP_FILTER_ROUTER_HSH_CFG_n),
	__stringify(IPA_SRC_RSRC_GRP_01_RSRC_TYPE_n),
	__stringify(IPA_SRC_RSRC_GRP_23_RSRC_TYPE_n),
	__stringify(IPA_SRC_RSRC_GRP_45_RSRC_TYPE_n),
	__stringify(IPA_SRC_RSRC_GRP_67_RSRC_TYPE_n),
	__stringify(IPA_DST_RSRC_GRP_01_RSRC_TYPE_n),
	__stringify(IPA_DST_RSRC_GRP_23_RSRC_TYPE_n),
	__stringify(IPA_DST_RSRC_GRP_45_RSRC_TYPE_n),
	__stringify(IPA_DST_RSRC_GRP_67_RSRC_TYPE_n),
	__stringify(IPA_RX_HPS_CLIENTS_MIN_DEPTH_0),
	__stringify(IPA_RX_HPS_CLIENTS_MIN_DEPTH_1),
	__stringify(IPA_RX_HPS_CLIENTS_MAX_DEPTH_0),
	__stringify(IPA_RX_HPS_CLIENTS_MAX_DEPTH_1),
	__stringify(IPA_HPS_FTCH_ARB_QUEUE_WEIGHT),
	__stringify(IPA_QSB_MAX_WRITES),
	__stringify(IPA_QSB_MAX_READS),
	__stringify(IPA_TX_CFG),
	__stringify(IPA_IDLE_INDICATION_CFG),
	__stringify(IPA_DPS_SEQUENCER_FIRST),
	__stringify(IPA_HPS_SEQUENCER_FIRST),
	__stringify(IPA_CLKON_CFG),
	__stringify(IPA_STAT_QUOTA_BASE_n),
	__stringify(IPA_STAT_QUOTA_MASK_n),
	__stringify(IPA_STAT_TETHERING_BASE_n),
	__stringify(IPA_STAT_TETHERING_MASK_n),
	__stringify(IPA_STAT_FILTER_IPV4_BASE),
	__stringify(IPA_STAT_FILTER_IPV6_BASE),
	__stringify(IPA_STAT_ROUTER_IPV4_BASE),
	__stringify(IPA_STAT_ROUTER_IPV6_BASE),
	__stringify(IPA_STAT_FILTER_IPV4_START_ID),
	__stringify(IPA_STAT_FILTER_IPV6_START_ID),
	__stringify(IPA_STAT_ROUTER_IPV4_START_ID),
	__stringify(IPA_STAT_ROUTER_IPV6_START_ID),
	__stringify(IPA_STAT_FILTER_IPV4_END_ID),
	__stringify(IPA_STAT_FILTER_IPV6_END_ID),
	__stringify(IPA_STAT_ROUTER_IPV4_END_ID),
	__stringify(IPA_STAT_ROUTER_IPV6_END_ID),
	__stringify(IPA_STAT_DROP_CNT_BASE_n),
	__stringify(IPA_STAT_DROP_CNT_MASK_n),
};

static void ipareg_construct_rx_hps_clients_depth1(
	enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipahal_reg_rx_hps_clients *clients =
		(struct ipahal_reg_rx_hps_clients *)fields;

	IPA_SETFIELD_IN_REG(*val, clients->client_minmax[0],
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_SHFT(0),
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_BMSK(0));

	IPA_SETFIELD_IN_REG(*val, clients->client_minmax[1],
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_SHFT(1),
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_BMSK(1));
}

static void ipareg_construct_rx_hps_clients_depth0(
	enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipahal_reg_rx_hps_clients *clients =
		(struct ipahal_reg_rx_hps_clients *)fields;

	IPA_SETFIELD_IN_REG(*val, clients->client_minmax[0],
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_SHFT(0),
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_BMSK(0));

	IPA_SETFIELD_IN_REG(*val, clients->client_minmax[1],
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_SHFT(1),
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_BMSK(1));

	IPA_SETFIELD_IN_REG(*val, clients->client_minmax[2],
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_SHFT(2),
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_BMSK(2));

	IPA_SETFIELD_IN_REG(*val, clients->client_minmax[3],
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_SHFT(3),
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_BMSK(3));
}

static void ipareg_construct_rx_hps_clients_depth0_v3_5(
	enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipahal_reg_rx_hps_clients *clients =
		(struct ipahal_reg_rx_hps_clients *)fields;

	IPA_SETFIELD_IN_REG(*val, clients->client_minmax[0],
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_SHFT(0),
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_BMSK_V3_5(0));

	IPA_SETFIELD_IN_REG(*val, clients->client_minmax[1],
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_SHFT(1),
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_BMSK_V3_5(1));

	IPA_SETFIELD_IN_REG(*val, clients->client_minmax[2],
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_SHFT(2),
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_BMSK_V3_5(2));

	IPA_SETFIELD_IN_REG(*val, clients->client_minmax[3],
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_SHFT(3),
		IPA_RX_HPS_CLIENTS_MINMAX_DEPTH_X_CLIENT_n_BMSK_V3_5(3));
}

static void ipareg_construct_rsrg_grp_xy(
	enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipahal_reg_rsrc_grp_cfg *grp =
		(struct ipahal_reg_rsrc_grp_cfg *)fields;

	IPA_SETFIELD_IN_REG(*val, grp->x_min,
		IPA_RSRC_GRP_XY_RSRC_TYPE_n_X_MIN_LIM_SHFT,
		IPA_RSRC_GRP_XY_RSRC_TYPE_n_X_MIN_LIM_BMSK);
	IPA_SETFIELD_IN_REG(*val, grp->x_max,
		IPA_RSRC_GRP_XY_RSRC_TYPE_n_X_MAX_LIM_SHFT,
		IPA_RSRC_GRP_XY_RSRC_TYPE_n_X_MAX_LIM_BMSK);
	IPA_SETFIELD_IN_REG(*val, grp->y_min,
		IPA_RSRC_GRP_XY_RSRC_TYPE_n_Y_MIN_LIM_SHFT,
		IPA_RSRC_GRP_XY_RSRC_TYPE_n_Y_MIN_LIM_BMSK);
	IPA_SETFIELD_IN_REG(*val, grp->y_max,
		IPA_RSRC_GRP_XY_RSRC_TYPE_n_Y_MAX_LIM_SHFT,
		IPA_RSRC_GRP_XY_RSRC_TYPE_n_Y_MAX_LIM_BMSK);
}

static void ipareg_construct_rsrg_grp_xy_v3_5(
	enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipahal_reg_rsrc_grp_cfg *grp =
		(struct ipahal_reg_rsrc_grp_cfg *)fields;

	IPA_SETFIELD_IN_REG(*val, grp->x_min,
		IPA_RSRC_GRP_XY_RSRC_TYPE_n_X_MIN_LIM_SHFT_V3_5,
		IPA_RSRC_GRP_XY_RSRC_TYPE_n_X_MIN_LIM_BMSK_V3_5);
	IPA_SETFIELD_IN_REG(*val, grp->x_max,
		IPA_RSRC_GRP_XY_RSRC_TYPE_n_X_MAX_LIM_SHFT_V3_5,
		IPA_RSRC_GRP_XY_RSRC_TYPE_n_X_MAX_LIM_BMSK_V3_5);

	/* DST_23 register has only X fields at ipa V3_5 */
	if (reg == IPA_DST_RSRC_GRP_23_RSRC_TYPE_n)
		return;

	IPA_SETFIELD_IN_REG(*val, grp->y_min,
		IPA_RSRC_GRP_XY_RSRC_TYPE_n_Y_MIN_LIM_SHFT_V3_5,
		IPA_RSRC_GRP_XY_RSRC_TYPE_n_Y_MIN_LIM_BMSK_V3_5);
	IPA_SETFIELD_IN_REG(*val, grp->y_max,
		IPA_RSRC_GRP_XY_RSRC_TYPE_n_Y_MAX_LIM_SHFT_V3_5,
		IPA_RSRC_GRP_XY_RSRC_TYPE_n_Y_MAX_LIM_BMSK_V3_5);
}

static void ipareg_construct_hash_cfg_n(
	enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipahal_reg_fltrt_hash_tuple *tuple =
		(struct ipahal_reg_fltrt_hash_tuple *)fields;

	IPA_SETFIELD_IN_REG(*val, tuple->flt.src_id,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_SRC_ID_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_SRC_ID_BMSK);
	IPA_SETFIELD_IN_REG(*val, tuple->flt.src_ip_addr,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_SRC_IP_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_SRC_IP_BMSK);
	IPA_SETFIELD_IN_REG(*val, tuple->flt.dst_ip_addr,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_DST_IP_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_DST_IP_BMSK);
	IPA_SETFIELD_IN_REG(*val, tuple->flt.src_port,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_SRC_PORT_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_SRC_PORT_BMSK);
	IPA_SETFIELD_IN_REG(*val, tuple->flt.dst_port,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_DST_PORT_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_DST_PORT_BMSK);
	IPA_SETFIELD_IN_REG(*val, tuple->flt.protocol,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_PROTOCOL_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_PROTOCOL_BMSK);
	IPA_SETFIELD_IN_REG(*val, tuple->flt.meta_data,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_METADATA_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_METADATA_BMSK);
	IPA_SETFIELD_IN_REG(*val, tuple->undefined1,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_UNDEFINED1_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_UNDEFINED1_BMSK);
	IPA_SETFIELD_IN_REG(*val, tuple->rt.src_id,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_SRC_ID_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_SRC_ID_BMSK);
	IPA_SETFIELD_IN_REG(*val, tuple->rt.src_ip_addr,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_SRC_IP_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_SRC_IP_BMSK);
	IPA_SETFIELD_IN_REG(*val, tuple->rt.dst_ip_addr,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_DST_IP_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_DST_IP_BMSK);
	IPA_SETFIELD_IN_REG(*val, tuple->rt.src_port,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_SRC_PORT_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_SRC_PORT_BMSK);
	IPA_SETFIELD_IN_REG(*val, tuple->rt.dst_port,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_DST_PORT_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_DST_PORT_BMSK);
	IPA_SETFIELD_IN_REG(*val, tuple->rt.protocol,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_PROTOCOL_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_PROTOCOL_BMSK);
	IPA_SETFIELD_IN_REG(*val, tuple->rt.meta_data,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_METADATA_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_METADATA_BMSK);
	IPA_SETFIELD_IN_REG(*val, tuple->undefined2,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_UNDEFINED2_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_UNDEFINED2_BMSK);
}

static void ipareg_parse_hash_cfg_n(
	enum ipahal_reg_name reg, void *fields, u32 val)
{
	struct ipahal_reg_fltrt_hash_tuple *tuple =
		(struct ipahal_reg_fltrt_hash_tuple *)fields;

	tuple->flt.src_id =
		IPA_GETFIELD_FROM_REG(val,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_SRC_ID_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_SRC_ID_BMSK);
	tuple->flt.src_ip_addr =
		IPA_GETFIELD_FROM_REG(val,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_SRC_IP_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_SRC_IP_BMSK);
	tuple->flt.dst_ip_addr =
		IPA_GETFIELD_FROM_REG(val,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_DST_IP_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_DST_IP_BMSK);
	tuple->flt.src_port =
		IPA_GETFIELD_FROM_REG(val,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_SRC_PORT_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_SRC_PORT_BMSK);
	tuple->flt.dst_port =
		IPA_GETFIELD_FROM_REG(val,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_DST_PORT_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_DST_PORT_BMSK);
	tuple->flt.protocol =
		IPA_GETFIELD_FROM_REG(val,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_PROTOCOL_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_PROTOCOL_BMSK);
	tuple->flt.meta_data =
		IPA_GETFIELD_FROM_REG(val,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_METADATA_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_FILTER_HASH_MSK_METADATA_BMSK);
	tuple->undefined1 =
		IPA_GETFIELD_FROM_REG(val,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_UNDEFINED1_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_UNDEFINED1_BMSK);
	tuple->rt.src_id =
		IPA_GETFIELD_FROM_REG(val,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_SRC_ID_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_SRC_ID_BMSK);
	tuple->rt.src_ip_addr =
		IPA_GETFIELD_FROM_REG(val,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_SRC_IP_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_SRC_IP_BMSK);
	tuple->rt.dst_ip_addr =
		IPA_GETFIELD_FROM_REG(val,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_DST_IP_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_DST_IP_BMSK);
	tuple->rt.src_port =
		IPA_GETFIELD_FROM_REG(val,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_SRC_PORT_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_SRC_PORT_BMSK);
	tuple->rt.dst_port =
		IPA_GETFIELD_FROM_REG(val,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_DST_PORT_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_DST_PORT_BMSK);
	tuple->rt.protocol =
		IPA_GETFIELD_FROM_REG(val,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_PROTOCOL_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_PROTOCOL_BMSK);
	tuple->rt.meta_data =
		IPA_GETFIELD_FROM_REG(val,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_METADATA_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_ROUTER_HASH_MSK_METADATA_BMSK);
	tuple->undefined2 =
		IPA_GETFIELD_FROM_REG(val,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_UNDEFINED2_SHFT,
		IPA_ENDP_FILTER_ROUTER_HSH_CFG_n_UNDEFINED2_BMSK);
}

static void ipareg_construct_endp_status_n(
	enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipahal_reg_ep_cfg_status *ep_status =
		(struct ipahal_reg_ep_cfg_status *)fields;

	IPA_SETFIELD_IN_REG(*val, ep_status->status_en,
			IPA_ENDP_STATUS_n_STATUS_EN_SHFT,
			IPA_ENDP_STATUS_n_STATUS_EN_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_status->status_ep,
			IPA_ENDP_STATUS_n_STATUS_ENDP_SHFT,
			IPA_ENDP_STATUS_n_STATUS_ENDP_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_status->status_location,
			IPA_ENDP_STATUS_n_STATUS_LOCATION_SHFT,
			IPA_ENDP_STATUS_n_STATUS_LOCATION_BMSK);
}

static void ipareg_construct_endp_status_n_v4_0(
	enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipahal_reg_ep_cfg_status *ep_status =
		(struct ipahal_reg_ep_cfg_status *)fields;

	IPA_SETFIELD_IN_REG(*val, ep_status->status_en,
			IPA_ENDP_STATUS_n_STATUS_EN_SHFT,
			IPA_ENDP_STATUS_n_STATUS_EN_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_status->status_ep,
			IPA_ENDP_STATUS_n_STATUS_ENDP_SHFT,
			IPA_ENDP_STATUS_n_STATUS_ENDP_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_status->status_location,
			IPA_ENDP_STATUS_n_STATUS_LOCATION_SHFT,
			IPA_ENDP_STATUS_n_STATUS_LOCATION_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_status->status_pkt_suppress,
			IPA_ENDP_STATUS_n_STATUS_PKT_SUPPRESS_SHFT,
			IPA_ENDP_STATUS_n_STATUS_PKT_SUPPRESS_BMSK);
}

static void ipareg_construct_qcncm(
	enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipahal_reg_qcncm *qcncm =
		(struct ipahal_reg_qcncm *)fields;

	IPA_SETFIELD_IN_REG(*val, qcncm->mode_en ? 1 : 0,
		IPA_QCNCM_MODE_EN_SHFT,
		IPA_QCNCM_MODE_EN_BMSK);
	IPA_SETFIELD_IN_REG(*val, qcncm->mode_val,
		IPA_QCNCM_MODE_VAL_SHFT,
		IPA_QCNCM_MODE_VAL_BMSK);
	IPA_SETFIELD_IN_REG(*val, qcncm->undefined,
		0, IPA_QCNCM_MODE_VAL_BMSK);
}

static void ipareg_parse_qcncm(
	enum ipahal_reg_name reg, void *fields, u32 val)
{
	struct ipahal_reg_qcncm *qcncm =
		(struct ipahal_reg_qcncm *)fields;

	memset(qcncm, 0, sizeof(struct ipahal_reg_qcncm));
	qcncm->mode_en = IPA_GETFIELD_FROM_REG(val,
		IPA_QCNCM_MODE_EN_SHFT,
		IPA_QCNCM_MODE_EN_BMSK);
	qcncm->mode_val = IPA_GETFIELD_FROM_REG(val,
		IPA_QCNCM_MODE_VAL_SHFT,
		IPA_QCNCM_MODE_VAL_BMSK);
	qcncm->undefined = IPA_GETFIELD_FROM_REG(val,
		0, IPA_QCNCM_UNDEFINED1_BMSK);
	qcncm->undefined |= IPA_GETFIELD_FROM_REG(val,
		0, IPA_QCNCM_MODE_UNDEFINED2_BMSK);
}

static void ipareg_construct_single_ndp_mode(
	enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipahal_reg_single_ndp_mode *mode =
		(struct ipahal_reg_single_ndp_mode *)fields;

	IPA_SETFIELD_IN_REG(*val, mode->single_ndp_en ? 1 : 0,
		IPA_SINGLE_NDP_MODE_SINGLE_NDP_EN_SHFT,
		IPA_SINGLE_NDP_MODE_SINGLE_NDP_EN_BMSK);

	IPA_SETFIELD_IN_REG(*val, mode->undefined,
		IPA_SINGLE_NDP_MODE_UNDEFINED_SHFT,
		IPA_SINGLE_NDP_MODE_UNDEFINED_BMSK);
}

static void ipareg_parse_single_ndp_mode(
	enum ipahal_reg_name reg, void *fields, u32 val)
{
	struct ipahal_reg_single_ndp_mode *mode =
		(struct ipahal_reg_single_ndp_mode *)fields;

	memset(mode, 0, sizeof(struct ipahal_reg_single_ndp_mode));
	mode->single_ndp_en = IPA_GETFIELD_FROM_REG(val,
		IPA_SINGLE_NDP_MODE_SINGLE_NDP_EN_SHFT,
		IPA_SINGLE_NDP_MODE_SINGLE_NDP_EN_BMSK);
	mode->undefined = IPA_GETFIELD_FROM_REG(val,
		IPA_SINGLE_NDP_MODE_UNDEFINED_SHFT,
		IPA_SINGLE_NDP_MODE_UNDEFINED_BMSK);
}

static void ipareg_construct_debug_cnt_ctrl_n(
	enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipahal_reg_debug_cnt_ctrl *dbg_cnt_ctrl =
		(struct ipahal_reg_debug_cnt_ctrl *)fields;
	u8 type;

	IPA_SETFIELD_IN_REG(*val, dbg_cnt_ctrl->en ? 1 : 0,
		IPA_DEBUG_CNT_CTRL_n_DBG_CNT_EN_SHFT,
		IPA_DEBUG_CNT_CTRL_n_DBG_CNT_EN_BMSK);

	switch (dbg_cnt_ctrl->type) {
	case DBG_CNT_TYPE_IPV4_FLTR:
		type = 0x0;
		if (!dbg_cnt_ctrl->rule_idx_pipe_rule) {
			ipa_err("No FLT global rules\n");
			WARN_ON(1);
		}
		break;
	case DBG_CNT_TYPE_IPV4_ROUT:
		type = 0x1;
		break;
	case DBG_CNT_TYPE_GENERAL:
		type = 0x2;
		break;
	case DBG_CNT_TYPE_IPV6_FLTR:
		type = 0x4;
		if (!dbg_cnt_ctrl->rule_idx_pipe_rule) {
			ipa_err("No FLT global rules\n");
			WARN_ON(1);
		}
		break;
	case DBG_CNT_TYPE_IPV6_ROUT:
		type = 0x5;
		break;
	default:
		ipa_err("Invalid dbg_cnt_ctrl type (%d) for %s\n",
			dbg_cnt_ctrl->type, ipareg_name_to_str[reg]);
		WARN_ON(1);
		return;

	};

	IPA_SETFIELD_IN_REG(*val, type,
		IPA_DEBUG_CNT_CTRL_n_DBG_CNT_TYPE_SHFT,
		IPA_DEBUG_CNT_CTRL_n_DBG_CNT_TYPE_BMSK);

	IPA_SETFIELD_IN_REG(*val, dbg_cnt_ctrl->product ? 1 : 0,
		IPA_DEBUG_CNT_CTRL_n_DBG_CNT_PRODUCT_SHFT,
		IPA_DEBUG_CNT_CTRL_n_DBG_CNT_PRODUCT_BMSK);

	IPA_SETFIELD_IN_REG(*val, dbg_cnt_ctrl->src_pipe,
		IPA_DEBUG_CNT_CTRL_n_DBG_CNT_SOURCE_PIPE_SHFT,
		IPA_DEBUG_CNT_CTRL_n_DBG_CNT_SOURCE_PIPE_BMSK);

	if (ipahal_ctx->hw_type <= IPA_HW_v3_1) {
		IPA_SETFIELD_IN_REG(*val, dbg_cnt_ctrl->rule_idx,
			IPA_DEBUG_CNT_CTRL_n_DBG_CNT_RULE_INDEX_SHFT,
			IPA_DEBUG_CNT_CTRL_n_DBG_CNT_RULE_INDEX_BMSK);
		IPA_SETFIELD_IN_REG(*val, dbg_cnt_ctrl->rule_idx_pipe_rule,
			IPA_DEBUG_CNT_CTRL_n_DBG_CNT_RULE_INDEX_PIPE_RULE_SHFT,
			IPA_DEBUG_CNT_CTRL_n_DBG_CNT_RULE_INDEX_PIPE_RULE_BMSK
			);
	} else {
		IPA_SETFIELD_IN_REG(*val, dbg_cnt_ctrl->rule_idx,
			IPA_DEBUG_CNT_CTRL_n_DBG_CNT_RULE_INDEX_SHFT,
			IPA_DEBUG_CNT_CTRL_n_DBG_CNT_RULE_INDEX_BMSK_V3_5);
	}
}

static void ipareg_parse_shared_mem_size(
	enum ipahal_reg_name reg, void *fields, u32 val)
{
	struct ipahal_reg_shared_mem_size *smem_sz =
		(struct ipahal_reg_shared_mem_size *)fields;

	memset(smem_sz, 0, sizeof(struct ipahal_reg_shared_mem_size));
	smem_sz->shared_mem_sz = IPA_GETFIELD_FROM_REG(val,
		IPA_SHARED_MEM_SIZE_SHARED_MEM_SIZE_SHFT,
		IPA_SHARED_MEM_SIZE_SHARED_MEM_SIZE_BMSK);

	smem_sz->shared_mem_baddr = IPA_GETFIELD_FROM_REG(val,
		IPA_SHARED_MEM_SIZE_SHARED_MEM_BADDR_SHFT,
		IPA_SHARED_MEM_SIZE_SHARED_MEM_BADDR_BMSK);
}

static void ipareg_construct_endp_init_rsrc_grp_n(
		enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipahal_reg_endp_init_rsrc_grp *rsrc_grp =
		(struct ipahal_reg_endp_init_rsrc_grp *)fields;

	IPA_SETFIELD_IN_REG(*val, rsrc_grp->rsrc_grp,
		IPA_ENDP_INIT_RSRC_GRP_n_RSRC_GRP_SHFT,
		IPA_ENDP_INIT_RSRC_GRP_n_RSRC_GRP_BMSK);
}

static void ipareg_construct_endp_init_rsrc_grp_n_v3_5(
		enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipahal_reg_endp_init_rsrc_grp *rsrc_grp =
		(struct ipahal_reg_endp_init_rsrc_grp *)fields;

	IPA_SETFIELD_IN_REG(*val, rsrc_grp->rsrc_grp,
		IPA_ENDP_INIT_RSRC_GRP_n_RSRC_GRP_SHFT_v3_5,
		IPA_ENDP_INIT_RSRC_GRP_n_RSRC_GRP_BMSK_v3_5);
}

static void ipareg_construct_endp_init_hdr_metadata_n(
		enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipa_ep_cfg_metadata *metadata =
		(struct ipa_ep_cfg_metadata *)fields;

	IPA_SETFIELD_IN_REG(*val, metadata->qmap_id,
			IPA_ENDP_INIT_HDR_METADATA_n_METADATA_SHFT,
			IPA_ENDP_INIT_HDR_METADATA_n_METADATA_BMSK);
}

static void ipareg_construct_endp_init_hdr_metadata_mask_n(
		enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipa_ep_cfg_metadata_mask *metadata_mask =
		(struct ipa_ep_cfg_metadata_mask *)fields;

	IPA_SETFIELD_IN_REG(*val, metadata_mask->metadata_mask,
			IPA_ENDP_INIT_HDR_METADATA_MASK_n_METADATA_MASK_SHFT,
			IPA_ENDP_INIT_HDR_METADATA_MASK_n_METADATA_MASK_BMSK);
}

static void ipareg_construct_endp_init_cfg_n(
	enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipa_ep_cfg_cfg *cfg =
		(struct ipa_ep_cfg_cfg *)fields;
	u32 cs_offload_en;

	switch (cfg->cs_offload_en) {
	case IPA_DISABLE_CS_OFFLOAD:
		cs_offload_en = 0;
		break;
	case IPA_ENABLE_CS_OFFLOAD_UL:
		cs_offload_en = 1;
		break;
	case IPA_ENABLE_CS_OFFLOAD_DL:
		cs_offload_en = 2;
		break;
	default:
		ipa_err("Invalid cs_offload_en value for %s\n",
			ipareg_name_to_str[reg]);
		WARN_ON(1);
		return;
	}

	IPA_SETFIELD_IN_REG(*val, cfg->frag_offload_en ? 1 : 0,
			IPA_ENDP_INIT_CFG_n_FRAG_OFFLOAD_EN_SHFT,
			IPA_ENDP_INIT_CFG_n_FRAG_OFFLOAD_EN_BMSK);
	IPA_SETFIELD_IN_REG(*val, cs_offload_en,
			IPA_ENDP_INIT_CFG_n_CS_OFFLOAD_EN_SHFT,
			IPA_ENDP_INIT_CFG_n_CS_OFFLOAD_EN_BMSK);
	IPA_SETFIELD_IN_REG(*val, cfg->cs_metadata_hdr_offset,
			IPA_ENDP_INIT_CFG_n_CS_METADATA_HDR_OFFSET_SHFT,
			IPA_ENDP_INIT_CFG_n_CS_METADATA_HDR_OFFSET_BMSK);
	IPA_SETFIELD_IN_REG(*val, cfg->gen_qmb_master_sel,
			IPA_ENDP_INIT_CFG_n_CS_GEN_QMB_MASTER_SEL_SHFT,
			IPA_ENDP_INIT_CFG_n_CS_GEN_QMB_MASTER_SEL_BMSK);

}

static void ipareg_construct_endp_init_deaggr_n(
		enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipa_ep_cfg_deaggr *ep_deaggr =
		(struct ipa_ep_cfg_deaggr *)fields;

	IPA_SETFIELD_IN_REG(*val, ep_deaggr->deaggr_hdr_len,
		IPA_ENDP_INIT_DEAGGR_n_DEAGGR_HDR_LEN_SHFT,
		IPA_ENDP_INIT_DEAGGR_n_DEAGGR_HDR_LEN_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_deaggr->packet_offset_valid,
		IPA_ENDP_INIT_DEAGGR_n_PACKET_OFFSET_VALID_SHFT,
		IPA_ENDP_INIT_DEAGGR_n_PACKET_OFFSET_VALID_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_deaggr->packet_offset_location,
		IPA_ENDP_INIT_DEAGGR_n_PACKET_OFFSET_LOCATION_SHFT,
		IPA_ENDP_INIT_DEAGGR_n_PACKET_OFFSET_LOCATION_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_deaggr->max_packet_len,
		IPA_ENDP_INIT_DEAGGR_n_MAX_PACKET_LEN_SHFT,
		IPA_ENDP_INIT_DEAGGR_n_MAX_PACKET_LEN_BMSK);
}

static void ipareg_construct_endp_init_hol_block_en_n(
	enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipa_ep_cfg_holb *ep_holb =
		(struct ipa_ep_cfg_holb *)fields;

	IPA_SETFIELD_IN_REG(*val, ep_holb->en,
		IPA_ENDP_INIT_HOL_BLOCK_EN_n_EN_SHFT,
		IPA_ENDP_INIT_HOL_BLOCK_EN_n_EN_BMSK);
}

static void ipareg_construct_endp_init_hol_block_timer_n(
	enum ipahal_reg_name reg, const void *fields, u32 *val)
{
	struct ipa_ep_cfg_holb *ep_holb =
		(struct ipa_ep_cfg_holb *)fields;

	IPA_SETFIELD_IN_REG(*val, ep_holb->tmr_val,
		IPA_ENDP_INIT_HOL_BLOCK_TIMER_n_TIMER_SHFT,
		IPA_ENDP_INIT_HOL_BLOCK_TIMER_n_TIMER_BMSK);
}

static void ipareg_construct_endp_init_ctrl_n(enum ipahal_reg_name reg,
	const void *fields, u32 *val)
{
	struct ipa_ep_cfg_ctrl *ep_ctrl =
		(struct ipa_ep_cfg_ctrl *)fields;

	IPA_SETFIELD_IN_REG(*val, ep_ctrl->ipa_ep_suspend,
		IPA_ENDP_INIT_CTRL_n_ENDP_SUSPEND_SHFT,
		IPA_ENDP_INIT_CTRL_n_ENDP_SUSPEND_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_ctrl->ipa_ep_delay,
		IPA_ENDP_INIT_CTRL_n_ENDP_DELAY_SHFT,
		IPA_ENDP_INIT_CTRL_n_ENDP_DELAY_BMSK);
}

static void ipareg_parse_endp_init_ctrl_n(enum ipahal_reg_name reg,
	void *fields, u32 val)
{
	struct ipa_ep_cfg_ctrl *ep_ctrl =
		(struct ipa_ep_cfg_ctrl *)fields;

	ep_ctrl->ipa_ep_suspend =
		((val & IPA_ENDP_INIT_CTRL_n_ENDP_SUSPEND_BMSK) >>
			IPA_ENDP_INIT_CTRL_n_ENDP_SUSPEND_SHFT);

	ep_ctrl->ipa_ep_delay =
		((val & IPA_ENDP_INIT_CTRL_n_ENDP_DELAY_BMSK) >>
		IPA_ENDP_INIT_CTRL_n_ENDP_DELAY_SHFT);
}

static void ipareg_construct_endp_init_ctrl_n_v4_0(enum ipahal_reg_name reg,
	const void *fields, u32 *val)
{
	struct ipa_ep_cfg_ctrl *ep_ctrl =
		(struct ipa_ep_cfg_ctrl *)fields;

	WARN_ON(ep_ctrl->ipa_ep_suspend);

	IPA_SETFIELD_IN_REG(*val, ep_ctrl->ipa_ep_delay,
		IPA_ENDP_INIT_CTRL_n_ENDP_DELAY_SHFT,
		IPA_ENDP_INIT_CTRL_n_ENDP_DELAY_BMSK);
}

static void ipareg_construct_endp_init_ctrl_scnd_n(enum ipahal_reg_name reg,
	const void *fields, u32 *val)
{
	struct ipahal_ep_cfg_ctrl_scnd *ep_ctrl_scnd =
		(struct ipahal_ep_cfg_ctrl_scnd *)fields;

	IPA_SETFIELD_IN_REG(*val, ep_ctrl_scnd->endp_delay,
		IPA_ENDP_INIT_CTRL_SCND_n_ENDP_DELAY_SHFT,
		IPA_ENDP_INIT_CTRL_SCND_n_ENDP_DELAY_BMSK);
}

static void ipareg_construct_endp_init_nat_n(enum ipahal_reg_name reg,
		const void *fields, u32 *val)
{
	struct ipa_ep_cfg_nat *ep_nat =
		(struct ipa_ep_cfg_nat *)fields;

	IPA_SETFIELD_IN_REG(*val, ep_nat->nat_en,
		IPA_ENDP_INIT_NAT_n_NAT_EN_SHFT,
		IPA_ENDP_INIT_NAT_n_NAT_EN_BMSK);
}

static void ipareg_construct_endp_init_conn_track_n(enum ipahal_reg_name reg,
	const void *fields, u32 *val)
{
	struct ipa_ep_cfg_conn_track *ep_ipv6ct =
		(struct ipa_ep_cfg_conn_track *)fields;

	IPA_SETFIELD_IN_REG(*val, ep_ipv6ct->conn_track_en,
		IPA_ENDP_INIT_CONN_TRACK_n_CONN_TRACK_EN_SHFT,
		IPA_ENDP_INIT_CONN_TRACK_n_CONN_TRACK_EN_BMSK);
}

static void ipareg_construct_endp_init_mode_n(enum ipahal_reg_name reg,
		const void *fields, u32 *val)
{
	struct ipahal_reg_endp_init_mode *init_mode =
		(struct ipahal_reg_endp_init_mode *)fields;

	IPA_SETFIELD_IN_REG(*val, init_mode->ep_mode.mode,
		IPA_ENDP_INIT_MODE_n_MODE_SHFT,
		IPA_ENDP_INIT_MODE_n_MODE_BMSK);

	IPA_SETFIELD_IN_REG(*val, init_mode->dst_pipe_number,
		IPA_ENDP_INIT_MODE_n_DEST_PIPE_INDEX_SHFT,
		IPA_ENDP_INIT_MODE_n_DEST_PIPE_INDEX_BMSK);
}

static void ipareg_construct_endp_init_route_n(enum ipahal_reg_name reg,
	const void *fields, u32 *val)
{
	struct ipahal_reg_endp_init_route *ep_init_rt =
		(struct ipahal_reg_endp_init_route *)fields;

	IPA_SETFIELD_IN_REG(*val, ep_init_rt->route_table_index,
		IPA_ENDP_INIT_ROUTE_n_ROUTE_TABLE_INDEX_SHFT,
		IPA_ENDP_INIT_ROUTE_n_ROUTE_TABLE_INDEX_BMSK);

}

static void ipareg_parse_endp_init_aggr_n(enum ipahal_reg_name reg,
	void *fields, u32 val)
{
	struct ipa_ep_cfg_aggr *ep_aggr =
		(struct ipa_ep_cfg_aggr *)fields;

	memset(ep_aggr, 0, sizeof(struct ipa_ep_cfg_aggr));

	ep_aggr->aggr_en =
		(((val & IPA_ENDP_INIT_AGGR_n_AGGR_EN_BMSK) >>
			IPA_ENDP_INIT_AGGR_n_AGGR_EN_SHFT)
			== IPA_ENABLE_AGGR);
	ep_aggr->aggr =
		((val & IPA_ENDP_INIT_AGGR_n_AGGR_TYPE_BMSK) >>
			IPA_ENDP_INIT_AGGR_n_AGGR_TYPE_SHFT);
	ep_aggr->aggr_byte_limit =
		((val & IPA_ENDP_INIT_AGGR_n_AGGR_BYTE_LIMIT_BMSK) >>
			IPA_ENDP_INIT_AGGR_n_AGGR_BYTE_LIMIT_SHFT);
	ep_aggr->aggr_time_limit =
		((val & IPA_ENDP_INIT_AGGR_n_AGGR_TIME_LIMIT_BMSK) >>
			IPA_ENDP_INIT_AGGR_n_AGGR_TIME_LIMIT_SHFT);
	ep_aggr->aggr_pkt_limit =
		((val & IPA_ENDP_INIT_AGGR_n_AGGR_PKT_LIMIT_BMSK) >>
			IPA_ENDP_INIT_AGGR_n_AGGR_PKT_LIMIT_SHFT);
	ep_aggr->aggr_sw_eof_active =
		((val & IPA_ENDP_INIT_AGGR_n_AGGR_SW_EOF_ACTIVE_BMSK) >>
			IPA_ENDP_INIT_AGGR_n_AGGR_SW_EOF_ACTIVE_SHFT);
	ep_aggr->aggr_hard_byte_limit_en =
		((val & IPA_ENDP_INIT_AGGR_n_AGGR_HARD_BYTE_LIMIT_ENABLE_BMSK)
			>>
			IPA_ENDP_INIT_AGGR_n_AGGR_HARD_BYTE_LIMIT_ENABLE_SHFT);
}

static void ipareg_construct_endp_init_aggr_n(enum ipahal_reg_name reg,
	const void *fields, u32 *val)
{
	struct ipa_ep_cfg_aggr *ep_aggr =
		(struct ipa_ep_cfg_aggr *)fields;

	IPA_SETFIELD_IN_REG(*val, ep_aggr->aggr_en,
		IPA_ENDP_INIT_AGGR_n_AGGR_EN_SHFT,
		IPA_ENDP_INIT_AGGR_n_AGGR_EN_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_aggr->aggr,
		IPA_ENDP_INIT_AGGR_n_AGGR_TYPE_SHFT,
		IPA_ENDP_INIT_AGGR_n_AGGR_TYPE_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_aggr->aggr_byte_limit,
		IPA_ENDP_INIT_AGGR_n_AGGR_BYTE_LIMIT_SHFT,
		IPA_ENDP_INIT_AGGR_n_AGGR_BYTE_LIMIT_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_aggr->aggr_time_limit,
		IPA_ENDP_INIT_AGGR_n_AGGR_TIME_LIMIT_SHFT,
		IPA_ENDP_INIT_AGGR_n_AGGR_TIME_LIMIT_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_aggr->aggr_pkt_limit,
		IPA_ENDP_INIT_AGGR_n_AGGR_PKT_LIMIT_SHFT,
		IPA_ENDP_INIT_AGGR_n_AGGR_PKT_LIMIT_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_aggr->aggr_sw_eof_active,
		IPA_ENDP_INIT_AGGR_n_AGGR_SW_EOF_ACTIVE_SHFT,
		IPA_ENDP_INIT_AGGR_n_AGGR_SW_EOF_ACTIVE_BMSK);

	/* At IPAv3 hard_byte_limit is not supported */
	ep_aggr->aggr_hard_byte_limit_en = 0;
	IPA_SETFIELD_IN_REG(*val, ep_aggr->aggr_hard_byte_limit_en,
		IPA_ENDP_INIT_AGGR_n_AGGR_HARD_BYTE_LIMIT_ENABLE_SHFT,
		IPA_ENDP_INIT_AGGR_n_AGGR_HARD_BYTE_LIMIT_ENABLE_BMSK);
}

static void ipareg_construct_endp_init_hdr_ext_n(enum ipahal_reg_name reg,
	const void *fields, u32 *val)
{
	struct ipa_ep_cfg_hdr_ext *ep_hdr_ext;
	u8 hdr_endianness;

	ep_hdr_ext = (struct ipa_ep_cfg_hdr_ext *)fields;
	hdr_endianness = ep_hdr_ext->hdr_little_endian ? 0 : 1;

	IPA_SETFIELD_IN_REG(*val, ep_hdr_ext->hdr_pad_to_alignment,
		IPA_ENDP_INIT_HDR_EXT_n_HDR_PAD_TO_ALIGNMENT_SHFT,
		IPA_ENDP_INIT_HDR_EXT_n_HDR_PAD_TO_ALIGNMENT_BMSK_v3_0);

	IPA_SETFIELD_IN_REG(*val, ep_hdr_ext->hdr_total_len_or_pad_offset,
		IPA_ENDP_INIT_HDR_EXT_n_HDR_TOTAL_LEN_OR_PAD_OFFSET_SHFT,
		IPA_ENDP_INIT_HDR_EXT_n_HDR_TOTAL_LEN_OR_PAD_OFFSET_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_hdr_ext->hdr_payload_len_inc_padding,
		IPA_ENDP_INIT_HDR_EXT_n_HDR_PAYLOAD_LEN_INC_PADDING_SHFT,
		IPA_ENDP_INIT_HDR_EXT_n_HDR_PAYLOAD_LEN_INC_PADDING_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_hdr_ext->hdr_total_len_or_pad,
		IPA_ENDP_INIT_HDR_EXT_n_HDR_TOTAL_LEN_OR_PAD_SHFT,
		IPA_ENDP_INIT_HDR_EXT_n_HDR_TOTAL_LEN_OR_PAD_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_hdr_ext->hdr_total_len_or_pad_valid,
		IPA_ENDP_INIT_HDR_EXT_n_HDR_TOTAL_LEN_OR_PAD_VALID_SHFT,
		IPA_ENDP_INIT_HDR_EXT_n_HDR_TOTAL_LEN_OR_PAD_VALID_BMSK);

	IPA_SETFIELD_IN_REG(*val, hdr_endianness,
		IPA_ENDP_INIT_HDR_EXT_n_HDR_ENDIANNESS_SHFT,
		IPA_ENDP_INIT_HDR_EXT_n_HDR_ENDIANNESS_BMSK);
}

static void ipareg_construct_endp_init_hdr_n(enum ipahal_reg_name reg,
	const void *fields, u32 *val)
{
	struct ipa_ep_cfg_hdr *ep_hdr;

	ep_hdr = (struct ipa_ep_cfg_hdr *)fields;

	IPA_SETFIELD_IN_REG(*val, ep_hdr->hdr_metadata_reg_valid,
		IPA_ENDP_INIT_HDR_n_HDR_METADATA_REG_VALID_SHFT_v2,
		IPA_ENDP_INIT_HDR_n_HDR_METADATA_REG_VALID_BMSK_v2);

	IPA_SETFIELD_IN_REG(*val, ep_hdr->hdr_remove_additional,
		IPA_ENDP_INIT_HDR_n_HDR_LEN_INC_DEAGG_HDR_SHFT_v2,
		IPA_ENDP_INIT_HDR_n_HDR_LEN_INC_DEAGG_HDR_BMSK_v2);

	IPA_SETFIELD_IN_REG(*val, ep_hdr->hdr_a5_mux,
		IPA_ENDP_INIT_HDR_n_HDR_A5_MUX_SHFT,
		IPA_ENDP_INIT_HDR_n_HDR_A5_MUX_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_hdr->hdr_ofst_pkt_size,
		IPA_ENDP_INIT_HDR_n_HDR_OFST_PKT_SIZE_SHFT,
		IPA_ENDP_INIT_HDR_n_HDR_OFST_PKT_SIZE_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_hdr->hdr_ofst_pkt_size_valid,
		IPA_ENDP_INIT_HDR_n_HDR_OFST_PKT_SIZE_VALID_SHFT,
		IPA_ENDP_INIT_HDR_n_HDR_OFST_PKT_SIZE_VALID_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_hdr->hdr_additional_const_len,
		IPA_ENDP_INIT_HDR_n_HDR_ADDITIONAL_CONST_LEN_SHFT,
		IPA_ENDP_INIT_HDR_n_HDR_ADDITIONAL_CONST_LEN_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_hdr->hdr_ofst_metadata,
		IPA_ENDP_INIT_HDR_n_HDR_OFST_METADATA_SHFT,
		IPA_ENDP_INIT_HDR_n_HDR_OFST_METADATA_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_hdr->hdr_ofst_metadata_valid,
		IPA_ENDP_INIT_HDR_n_HDR_OFST_METADATA_VALID_SHFT,
		IPA_ENDP_INIT_HDR_n_HDR_OFST_METADATA_VALID_BMSK);

	IPA_SETFIELD_IN_REG(*val, ep_hdr->hdr_len,
		IPA_ENDP_INIT_HDR_n_HDR_LEN_SHFT,
		IPA_ENDP_INIT_HDR_n_HDR_LEN_BMSK);
}

static void ipareg_construct_route(enum ipahal_reg_name reg,
	const void *fields, u32 *val)
{
	struct ipahal_reg_route *route;

	route = (struct ipahal_reg_route *)fields;

	IPA_SETFIELD_IN_REG(*val, route->route_dis,
		IPA_ROUTE_ROUTE_DIS_SHFT,
		IPA_ROUTE_ROUTE_DIS_BMSK);

	IPA_SETFIELD_IN_REG(*val, route->route_def_pipe,
		IPA_ROUTE_ROUTE_DEF_PIPE_SHFT,
		IPA_ROUTE_ROUTE_DEF_PIPE_BMSK);

	IPA_SETFIELD_IN_REG(*val, route->route_def_hdr_table,
		IPA_ROUTE_ROUTE_DEF_HDR_TABLE_SHFT,
		IPA_ROUTE_ROUTE_DEF_HDR_TABLE_BMSK);

	IPA_SETFIELD_IN_REG(*val, route->route_def_hdr_ofst,
		IPA_ROUTE_ROUTE_DEF_HDR_OFST_SHFT,
		IPA_ROUTE_ROUTE_DEF_HDR_OFST_BMSK);

	IPA_SETFIELD_IN_REG(*val, route->route_frag_def_pipe,
		IPA_ROUTE_ROUTE_FRAG_DEF_PIPE_SHFT,
		IPA_ROUTE_ROUTE_FRAG_DEF_PIPE_BMSK);

	IPA_SETFIELD_IN_REG(*val, route->route_def_retain_hdr,
		IPA_ROUTE_ROUTE_DEF_RETAIN_HDR_SHFT,
		IPA_ROUTE_ROUTE_DEF_RETAIN_HDR_BMSK);
}

static void ipareg_construct_qsb_max_writes(enum ipahal_reg_name reg,
	const void *fields, u32 *val)
{
	struct ipahal_reg_qsb_max_writes *max_writes;

	max_writes = (struct ipahal_reg_qsb_max_writes *)fields;

	IPA_SETFIELD_IN_REG(*val, max_writes->qmb_0_max_writes,
			    IPA_QSB_MAX_WRITES_GEN_QMB_0_MAX_WRITES_SHFT,
			    IPA_QSB_MAX_WRITES_GEN_QMB_0_MAX_WRITES_BMSK);
	IPA_SETFIELD_IN_REG(*val, max_writes->qmb_1_max_writes,
			    IPA_QSB_MAX_WRITES_GEN_QMB_1_MAX_WRITES_SHFT,
			    IPA_QSB_MAX_WRITES_GEN_QMB_1_MAX_WRITES_BMSK);
}

static void ipareg_construct_qsb_max_reads(enum ipahal_reg_name reg,
	const void *fields, u32 *val)
{
	struct ipahal_reg_qsb_max_reads *max_reads;

	max_reads = (struct ipahal_reg_qsb_max_reads *)fields;

	IPA_SETFIELD_IN_REG(*val, max_reads->qmb_0_max_reads,
			    IPA_QSB_MAX_READS_GEN_QMB_0_MAX_READS_SHFT,
			    IPA_QSB_MAX_READS_GEN_QMB_0_MAX_READS_BMSK);
	IPA_SETFIELD_IN_REG(*val, max_reads->qmb_1_max_reads,
			    IPA_QSB_MAX_READS_GEN_QMB_1_MAX_READS_SHFT,
			    IPA_QSB_MAX_READS_GEN_QMB_1_MAX_READS_BMSK);
}

static void ipareg_construct_qsb_max_reads_v4_0(enum ipahal_reg_name reg,
	const void *fields, u32 *val)
{
	struct ipahal_reg_qsb_max_reads *max_reads;

	max_reads = (struct ipahal_reg_qsb_max_reads *)fields;

	IPA_SETFIELD_IN_REG(*val, max_reads->qmb_0_max_reads,
			    IPA_QSB_MAX_READS_GEN_QMB_0_MAX_READS_SHFT,
			    IPA_QSB_MAX_READS_GEN_QMB_0_MAX_READS_BMSK);
	IPA_SETFIELD_IN_REG(*val, max_reads->qmb_1_max_reads,
			    IPA_QSB_MAX_READS_GEN_QMB_1_MAX_READS_SHFT,
			    IPA_QSB_MAX_READS_GEN_QMB_1_MAX_READS_BMSK);
	IPA_SETFIELD_IN_REG(*val, max_reads->qmb_0_max_read_beats,
		    IPA_QSB_MAX_READS_GEN_QMB_0_MAX_READS_BEATS_SHFT_V4_0,
		    IPA_QSB_MAX_READS_GEN_QMB_0_MAX_READS_BEATS_BMSK_V4_0);
	IPA_SETFIELD_IN_REG(*val, max_reads->qmb_1_max_read_beats,
		    IPA_QSB_MAX_READS_GEN_QMB_1_MAX_READS_BEATS_SHFT_V4_0,
		    IPA_QSB_MAX_READS_GEN_QMB_1_MAX_READS_BEATS_BMSK_V4_0);
}

static void ipareg_parse_tx_cfg(enum ipahal_reg_name reg,
	void *fields, u32 val)
{
	struct ipahal_reg_tx_cfg *tx_cfg;

	tx_cfg = (struct ipahal_reg_tx_cfg *)fields;

	tx_cfg->tx0_prefetch_disable = IPA_GETFIELD_FROM_REG(val,
		IPA_TX_CFG_TX0_PREFETCH_DISABLE_SHFT_V3_5,
		IPA_TX_CFG_TX0_PREFETCH_DISABLE_BMSK_V3_5);

	tx_cfg->tx1_prefetch_disable = IPA_GETFIELD_FROM_REG(val,
		IPA_TX_CFG_TX1_PREFETCH_DISABLE_SHFT_V3_5,
		IPA_TX_CFG_TX1_PREFETCH_DISABLE_BMSK_V3_5);

	tx_cfg->tx0_prefetch_almost_empty_size = IPA_GETFIELD_FROM_REG(val,
		IPA_TX_CFG_PREFETCH_ALMOST_EMPTY_SIZE_SHFT_V3_5,
		IPA_TX_CFG_PREFETCH_ALMOST_EMPTY_SIZE_BMSK_V3_5);

	tx_cfg->tx1_prefetch_almost_empty_size =
		tx_cfg->tx0_prefetch_almost_empty_size;
}

static void ipareg_parse_tx_cfg_v4_0(enum ipahal_reg_name reg,
	void *fields, u32 val)
{
	struct ipahal_reg_tx_cfg *tx_cfg;

	tx_cfg = (struct ipahal_reg_tx_cfg *)fields;

	tx_cfg->tx0_prefetch_almost_empty_size = IPA_GETFIELD_FROM_REG(val,
		IPA_TX_CFG_PREFETCH_ALMOST_EMPTY_SIZE_TX0_SHFT_V4_0,
		IPA_TX_CFG_PREFETCH_ALMOST_EMPTY_SIZE_TX0_BMSK_V4_0);

	tx_cfg->tx1_prefetch_almost_empty_size = IPA_GETFIELD_FROM_REG(val,
		IPA_TX_CFG_PREFETCH_ALMOST_EMPTY_SIZE_TX1_SHFT_V4_0,
		IPA_TX_CFG_PREFETCH_ALMOST_EMPTY_SIZE_TX1_BMSK_V4_0);

	tx_cfg->dmaw_scnd_outsd_pred_en = IPA_GETFIELD_FROM_REG(val,
		IPA_TX_CFG_DMAW_SCND_OUTSD_PRED_EN_SHFT_V4_0,
		IPA_TX_CFG_DMAW_SCND_OUTSD_PRED_EN_BMSK_V4_0);

	tx_cfg->dmaw_scnd_outsd_pred_threshold = IPA_GETFIELD_FROM_REG(val,
		IPA_TX_CFG_DMAW_SCND_OUTSD_PRED_THRESHOLD_SHFT_V4_0,
		IPA_TX_CFG_DMAW_SCND_OUTSD_PRED_THRESHOLD_BMSK_V4_0);

	tx_cfg->dmaw_max_beats_256_dis = IPA_GETFIELD_FROM_REG(val,
		IPA_TX_CFG_DMAW_MAX_BEATS_256_DIS_SHFT_V4_0,
		IPA_TX_CFG_DMAW_MAX_BEATS_256_DIS_BMSK_V4_0);

	tx_cfg->pa_mask_en = IPA_GETFIELD_FROM_REG(val,
		IPA_TX_CFG_PA_MASK_EN_SHFT_V4_0,
		IPA_TX_CFG_PA_MASK_EN_BMSK_V4_0);
}

static void ipareg_construct_tx_cfg(enum ipahal_reg_name reg,
	const void *fields, u32 *val)
{
	struct ipahal_reg_tx_cfg *tx_cfg;

	tx_cfg = (struct ipahal_reg_tx_cfg *)fields;

	if (tx_cfg->tx0_prefetch_almost_empty_size !=
			tx_cfg->tx1_prefetch_almost_empty_size)
		ipa_assert();

	IPA_SETFIELD_IN_REG(*val, tx_cfg->tx0_prefetch_disable,
		IPA_TX_CFG_TX0_PREFETCH_DISABLE_SHFT_V3_5,
		IPA_TX_CFG_TX0_PREFETCH_DISABLE_BMSK_V3_5);

	IPA_SETFIELD_IN_REG(*val, tx_cfg->tx1_prefetch_disable,
		IPA_TX_CFG_TX1_PREFETCH_DISABLE_SHFT_V3_5,
		IPA_TX_CFG_TX1_PREFETCH_DISABLE_BMSK_V3_5);

	IPA_SETFIELD_IN_REG(*val, tx_cfg->tx0_prefetch_almost_empty_size,
		IPA_TX_CFG_PREFETCH_ALMOST_EMPTY_SIZE_SHFT_V3_5,
		IPA_TX_CFG_PREFETCH_ALMOST_EMPTY_SIZE_BMSK_V3_5);
}

static void ipareg_construct_tx_cfg_v4_0(enum ipahal_reg_name reg,
	const void *fields, u32 *val)
{
	struct ipahal_reg_tx_cfg *tx_cfg;

	tx_cfg = (struct ipahal_reg_tx_cfg *)fields;

	IPA_SETFIELD_IN_REG(*val, tx_cfg->tx0_prefetch_almost_empty_size,
		IPA_TX_CFG_PREFETCH_ALMOST_EMPTY_SIZE_TX0_SHFT_V4_0,
		IPA_TX_CFG_PREFETCH_ALMOST_EMPTY_SIZE_TX0_BMSK_V4_0);

	IPA_SETFIELD_IN_REG(*val, tx_cfg->tx1_prefetch_almost_empty_size,
		IPA_TX_CFG_PREFETCH_ALMOST_EMPTY_SIZE_TX1_SHFT_V4_0,
		IPA_TX_CFG_PREFETCH_ALMOST_EMPTY_SIZE_TX1_BMSK_V4_0);

	IPA_SETFIELD_IN_REG(*val, tx_cfg->dmaw_scnd_outsd_pred_threshold,
		IPA_TX_CFG_DMAW_SCND_OUTSD_PRED_THRESHOLD_SHFT_V4_0,
		IPA_TX_CFG_DMAW_SCND_OUTSD_PRED_THRESHOLD_BMSK_V4_0);

	IPA_SETFIELD_IN_REG(*val, tx_cfg->dmaw_max_beats_256_dis,
		IPA_TX_CFG_DMAW_MAX_BEATS_256_DIS_SHFT_V4_0,
		IPA_TX_CFG_DMAW_MAX_BEATS_256_DIS_BMSK_V4_0);

	IPA_SETFIELD_IN_REG(*val, tx_cfg->dmaw_scnd_outsd_pred_en,
		IPA_TX_CFG_DMAW_SCND_OUTSD_PRED_EN_SHFT_V4_0,
		IPA_TX_CFG_DMAW_SCND_OUTSD_PRED_EN_BMSK_V4_0);

	IPA_SETFIELD_IN_REG(*val, tx_cfg->pa_mask_en,
		IPA_TX_CFG_PA_MASK_EN_SHFT_V4_0,
		IPA_TX_CFG_PA_MASK_EN_BMSK_V4_0);
}

static void ipareg_construct_idle_indication_cfg(enum ipahal_reg_name reg,
	const void *fields, u32 *val)
{
	struct ipahal_reg_idle_indication_cfg *idle_indication_cfg;

	idle_indication_cfg = (struct ipahal_reg_idle_indication_cfg *)fields;

	IPA_SETFIELD_IN_REG(*val,
		idle_indication_cfg->enter_idle_debounce_thresh,
		IPA_IDLE_INDICATION_CFG_ENTER_IDLE_DEBOUNCE_THRESH_SHFT_V3_5,
		IPA_IDLE_INDICATION_CFG_ENTER_IDLE_DEBOUNCE_THRESH_BMSK_V3_5);

	IPA_SETFIELD_IN_REG(*val,
		idle_indication_cfg->const_non_idle_enable,
		IPA_IDLE_INDICATION_CFG_CONST_NON_IDLE_ENABLE_SHFT_V3_5,
		IPA_IDLE_INDICATION_CFG_CONST_NON_IDLE_ENABLE_BMSK_V3_5);
}

static void ipareg_construct_hps_queue_weights(enum ipahal_reg_name reg,
	const void *fields, u32 *val)
{
	struct ipahal_reg_rx_hps_weights *hps_weights;

	hps_weights = (struct ipahal_reg_rx_hps_weights *)fields;

	IPA_SETFIELD_IN_REG(*val,
		hps_weights->hps_queue_weight_0,
		IPA_HPS_FTCH_ARB_QUEUE_WEIGHTS_RX_HPS_QUEUE_WEIGHT_0_SHFT,
		IPA_HPS_FTCH_ARB_QUEUE_WEIGHTS_RX_HPS_QUEUE_WEIGHT_0_BMSK);

	IPA_SETFIELD_IN_REG(*val,
		hps_weights->hps_queue_weight_1,
		IPA_HPS_FTCH_ARB_QUEUE_WEIGHTS_RX_HPS_QUEUE_WEIGHT_1_SHFT,
		IPA_HPS_FTCH_ARB_QUEUE_WEIGHTS_RX_HPS_QUEUE_WEIGHT_1_BMSK);

	IPA_SETFIELD_IN_REG(*val,
		hps_weights->hps_queue_weight_2,
		IPA_HPS_FTCH_ARB_QUEUE_WEIGHTS_RX_HPS_QUEUE_WEIGHT_2_SHFT,
		IPA_HPS_FTCH_ARB_QUEUE_WEIGHTS_RX_HPS_QUEUE_WEIGHT_2_BMSK);

	IPA_SETFIELD_IN_REG(*val,
		hps_weights->hps_queue_weight_3,
		IPA_HPS_FTCH_ARB_QUEUE_WEIGHTS_RX_HPS_QUEUE_WEIGHT_3_SHFT,
		IPA_HPS_FTCH_ARB_QUEUE_WEIGHTS_RX_HPS_QUEUE_WEIGHT_3_BMSK);
}

static void ipareg_parse_hps_queue_weights(
	enum ipahal_reg_name reg, void *fields, u32 val)
{
	struct ipahal_reg_rx_hps_weights *hps_weights =
		(struct ipahal_reg_rx_hps_weights *)fields;

	memset(hps_weights, 0, sizeof(struct ipahal_reg_rx_hps_weights));

	hps_weights->hps_queue_weight_0 = IPA_GETFIELD_FROM_REG(val,
		IPA_HPS_FTCH_ARB_QUEUE_WEIGHTS_RX_HPS_QUEUE_WEIGHT_0_SHFT,
		IPA_HPS_FTCH_ARB_QUEUE_WEIGHTS_RX_HPS_QUEUE_WEIGHT_0_BMSK);

	hps_weights->hps_queue_weight_1 = IPA_GETFIELD_FROM_REG(val,
		IPA_HPS_FTCH_ARB_QUEUE_WEIGHTS_RX_HPS_QUEUE_WEIGHT_1_SHFT,
		IPA_HPS_FTCH_ARB_QUEUE_WEIGHTS_RX_HPS_QUEUE_WEIGHT_1_BMSK);

	hps_weights->hps_queue_weight_2 = IPA_GETFIELD_FROM_REG(val,
		IPA_HPS_FTCH_ARB_QUEUE_WEIGHTS_RX_HPS_QUEUE_WEIGHT_2_SHFT,
		IPA_HPS_FTCH_ARB_QUEUE_WEIGHTS_RX_HPS_QUEUE_WEIGHT_2_BMSK);

	hps_weights->hps_queue_weight_3 = IPA_GETFIELD_FROM_REG(val,
		IPA_HPS_FTCH_ARB_QUEUE_WEIGHTS_RX_HPS_QUEUE_WEIGHT_3_SHFT,
		IPA_HPS_FTCH_ARB_QUEUE_WEIGHTS_RX_HPS_QUEUE_WEIGHT_3_BMSK);
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
 * version of IPA hardware supported by the "ipahal" layer is 3.0;
 * essentially all registers needed for IPA operation have a
 * register object associated with IPA_HW_v3_0.
 *
 * Versions of IPA hardware newer than 3.0 do not need to specify
 * register object entries if they are accessed the same way as was
 * defined by an older version.  The only entries defined for newer
 * hardware are registers whose offset or data format has changed,
 * or registers that are new and not present in older hardware.
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

/*
 * struct ipahal_reg_obj - Register H/W information for specific IPA version
 * @construct - CB to construct register value from abstracted structure
 * @parse - CB to parse register value to abstracted structure
 * @offset - register offset relative to base address (or OFFSET_INVAL)
 * @n_ofst - N parameterized register sub-offset
 */
#define OFFSET_INVAL	((u32)0xffffffff)
struct ipahal_reg_obj {
	void (*construct)(enum ipahal_reg_name reg, const void *fields,
		u32 *val);
	void (*parse)(enum ipahal_reg_name reg, void *fields,
		u32 val);
	u32 offset;
	u16 n_ofst;
};

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

static const struct ipahal_reg_obj ipahal_reg_objs[][IPA_REG_MAX] = {
	/* IPAv3 */
	[IPA_HW_v3_0] = {
		reg_obj_cfunc(ROUTE, route,		0x00000048,	0x0000),
		reg_obj_nofunc(IRQ_STTS_EE_n,		0x00003008,	0x1000),
		reg_obj_nofunc(IRQ_EN_EE_n,		0x0000300c,	0x1000),
		reg_obj_nofunc(IRQ_CLR_EE_n,		0x00003010,	0x1000),
		reg_obj_nofunc(IRQ_SUSPEND_INFO_EE_n,	0x00003098,	0x1000),
		reg_obj_nofunc(BCR,			0x000001d0,	0x0000),
		reg_obj_nofunc(ENABLED_PIPES,		0x00000038,	0x0000),
		reg_obj_nofunc(COMP_SW_RESET,		0x00000040,	0x0000),
		reg_obj_nofunc(VERSION,			0x00000034,	0x0000),
		reg_obj_nofunc(TAG_TIMER,		0x00000060,	0x0000),
		reg_obj_nofunc(COMP_HW_VERSION,		0x00000030,	0x0000),
		reg_obj_nofunc(SPARE_REG_1,		0x00005090,	0x0000),
		reg_obj_nofunc(SPARE_REG_2,		0x00005094,	0x0000),
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
		reg_obj_cfunc(ENDP_INIT_RSRC_GRP_n, endp_init_rsrc_grp_n,
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
		reg_obj_nofunc(SYS_PKT_PROC_CNTXT_BASE,	0x000001e0,	0x0000),
		reg_obj_nofunc(LOCAL_PKT_PROC_CNTXT_BASE,
							0x000001e8,	0x0000),
		reg_obj_cfunc(ENDP_STATUS_n, endp_status_n,
							0x00000840,	0x0070),
		reg_obj_both(ENDP_FILTER_ROUTER_HSH_CFG_n, hash_cfg_n,
							0x0000085c,	0x0070),
		reg_obj_cfunc(SRC_RSRC_GRP_01_RSRC_TYPE_n, rsrg_grp_xy,
							0x00000400,	0x0020),
		reg_obj_cfunc(SRC_RSRC_GRP_23_RSRC_TYPE_n, rsrg_grp_xy,
							0x00000404,	0x0020),
		reg_obj_cfunc(SRC_RSRC_GRP_45_RSRC_TYPE_n, rsrg_grp_xy,
							0x00000408,	0x0020),
		reg_obj_cfunc(SRC_RSRC_GRP_67_RSRC_TYPE_n, rsrg_grp_xy,
							0x0000040c,	0x0020),
		reg_obj_cfunc(DST_RSRC_GRP_01_RSRC_TYPE_n, rsrg_grp_xy,
							0x00000500,	0x0020),
		reg_obj_cfunc(DST_RSRC_GRP_23_RSRC_TYPE_n, rsrg_grp_xy,
							0x00000504,	0x0020),
		reg_obj_cfunc(DST_RSRC_GRP_45_RSRC_TYPE_n, rsrg_grp_xy,
							0x00000508,	0x0020),
		reg_obj_cfunc(DST_RSRC_GRP_67_RSRC_TYPE_n, rsrg_grp_xy,
							0x0000050c,	0x0020),
		reg_obj_cfunc(RX_HPS_CLIENTS_MIN_DEPTH_0, rx_hps_clients_depth0,
							0x000023c4,	0x0000),
		reg_obj_cfunc(RX_HPS_CLIENTS_MIN_DEPTH_1, rx_hps_clients_depth1,
							0x000023c8,	0x0000),
		reg_obj_cfunc(RX_HPS_CLIENTS_MAX_DEPTH_0, rx_hps_clients_depth0,
							0x000023cc,	0x0000),
		reg_obj_cfunc(RX_HPS_CLIENTS_MAX_DEPTH_1, rx_hps_clients_depth1,
							0x000023d0,	0x0000),
		reg_obj_cfunc(QSB_MAX_WRITES, qsb_max_writes,
							0x00000074,	0x0000),
		reg_obj_cfunc(QSB_MAX_READS, qsb_max_reads,
							0x00000078,	0x0000),
		reg_obj_nofunc(DPS_SEQUENCER_FIRST,	0x0001e000,	0x0000),
		reg_obj_nofunc(HPS_SEQUENCER_FIRST,	0x0001e080,	0x0000),
	},

	/* IPAv3.1 */
	[IPA_HW_v3_1] = {
		reg_obj_nofunc(IRQ_SUSPEND_INFO_EE_n,	0x00003030,	0x1000),
		reg_obj_nofunc(SUSPEND_IRQ_EN_EE_n,	0x00003034,	0x1000),
		reg_obj_nofunc(SUSPEND_IRQ_CLR_EE_n,	0x00003038,	0x1000),
	},


	/* IPAv3.5 */
	[IPA_HW_v3_5] = {
		reg_obj_both(TX_CFG, tx_cfg,		0x000001fc,	0x0000),
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
		reg_obj_cfunc(ENDP_INIT_RSRC_GRP_n, endp_init_rsrc_grp_n_v3_5,
							0x00000838,	0x0070),
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
		reg_obj_nofunc(SPARE_REG_1,		0x00002780,	0x0000),
		reg_obj_nofunc(SPARE_REG_2,		0x00002784,	0x0000),
		reg_obj_cfunc(IDLE_INDICATION_CFG, idle_indication_cfg,
							0x00000220,	0x0000),
		reg_obj_both(HPS_FTCH_ARB_QUEUE_WEIGHT, hps_queue_weights,
							0x000005a4,	0x0000),
	},


	/* IPAv3.5.1 */
	[IPA_HW_v3_5_1] = {
		/* All inherited from IPA_HW_v3_5. */
	},


	/* IPAv4.0 */
	[IPA_HW_v4_0] = {
		reg_obj_cfunc(ENDP_INIT_CTRL_n, endp_init_ctrl_n_v4_0,
							0x00000800,	0x0070),
		reg_obj_both(TX_CFG, tx_cfg_v4_0,	0x000001fc,	0x0000),
		reg_obj_nofunc(DEBUG_CNT_REG_n,		OFFSET_INVAL,	0x0000),
		reg_obj_cfunc(DEBUG_CNT_CTRL_n, debug_cnt_ctrl_n,
							OFFSET_INVAL,	0x0000),
		reg_obj_both(QCNCM, qcncm,		OFFSET_INVAL,	0x0000),
		reg_obj_both(SINGLE_NDP_MODE, single_ndp_mode,
							OFFSET_INVAL,	0x0000),
		reg_obj_cfunc(QSB_MAX_READS, qsb_max_reads_v4_0,
							0x00000078,	0x0000),
		reg_obj_nofunc(FILT_ROUT_HASH_FLUSH,	0x0000014c,	0x0000),
		reg_obj_nofunc(STATE_AGGR_ACTIVE,	0x000000b4,	0x0000),
		reg_obj_cfunc(ENDP_INIT_ROUTE_n, endp_init_route_n,
							OFFSET_INVAL,	0x0000),
		reg_obj_cfunc(ENDP_STATUS_n, endp_status_n_v4_0,
							0x00000840,	0x0070),
		reg_obj_nofunc(CLKON_CFG,		0x00000044,	0x0000),
		reg_obj_cfunc(ENDP_INIT_CONN_TRACK_n, endp_init_conn_track_n,
							0x00000850,	0x0070),
		reg_obj_nofunc(STAT_QUOTA_BASE_n,	0x00000700,	0x0004),
		reg_obj_nofunc(STAT_QUOTA_MASK_n,	0x00000708,	0x0004),
		reg_obj_nofunc(STAT_TETHERING_BASE_n,	0x00000710,	0x0004),
		reg_obj_nofunc(STAT_TETHERING_MASK_n,	0x00000718,	0x0004),
		reg_obj_nofunc(STAT_FILTER_IPV4_BASE,	0x00000720,	0x0000),
		reg_obj_nofunc(STAT_FILTER_IPV6_BASE,	0x00000724,	0x0000),
		reg_obj_nofunc(STAT_ROUTER_IPV4_BASE,	0x00000728,	0x0000),
		reg_obj_nofunc(STAT_ROUTER_IPV6_BASE,	0x0000072c,	0x0000),
		reg_obj_nofunc(STAT_FILTER_IPV4_START_ID,
							0x00000730,	0x0000),
		reg_obj_nofunc(STAT_FILTER_IPV6_START_ID,
							0x00000734,	0x0000),
		reg_obj_nofunc(STAT_ROUTER_IPV4_START_ID,
							0x00000738,	0x0000),
		reg_obj_nofunc(STAT_ROUTER_IPV6_START_ID,
							0x0000073c,	0x0000),
		reg_obj_nofunc(STAT_FILTER_IPV4_END_ID,
							0x00000740,	0x0000),
		reg_obj_nofunc(STAT_FILTER_IPV6_END_ID,
							0x00000744,	0x0000),
		reg_obj_nofunc(STAT_ROUTER_IPV4_END_ID,
							0x00000748,	0x0000),
		reg_obj_nofunc(STAT_ROUTER_IPV6_END_ID,
							0x0000074c,	0x0000),
		reg_obj_nofunc(STAT_DROP_CNT_BASE_n,	0x00000750,	0x0004),
		reg_obj_nofunc(STAT_DROP_CNT_MASK_n,	0x00000758,	0x0004),
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

static struct ipahal_reg_obj ipahal_regs[IPA_REG_MAX];

/*
 * ipahal_reg_init() - Build the registers information table
 *  See ipahal_reg_objs[][] comments
 *
 * Note: As global variables are initialized with zero, any un-overridden
 *  register entry will be zero. By this we recognize them.
 */
void ipahal_reg_init(void)
{
	int i;
	int j;

	ipa_debug_low("Entry - HW_TYPE=%d\n", ipahal_ctx->hw_type);

	/* Build up a the register descriptions we'll use */
	for (i = 0; i < IPA_REG_MAX ; i++) {
		for (j = ipahal_ctx->hw_type; j >= IPA_HW_v3_0; j--) {
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
u32 ipahal_reg_n_offset(enum ipahal_reg_name reg, u32 n)
{
	u32 offset;

	ipa_debug_low("get offset of %s n=%u\n", ipareg_name_to_str[reg], n);
	offset = ipahal_regs[reg].offset;
	BUG_ON(!offset || offset == OFFSET_INVAL);
	offset += ipahal_regs[reg].n_ofst * n;

	return offset;
}

/*
 * ipahal_read_reg_n() - Get n parameterized reg value
 */
u32 ipahal_read_reg_n(enum ipahal_reg_name reg, u32 n)
{
	return ioread32(ipahal_ctx->base + ipahal_reg_n_offset(reg, n));
}

/*
 * ipahal_write_reg_n() - Write to n parameterized reg a raw value
 */
void ipahal_write_reg_n(enum ipahal_reg_name reg, u32 n, u32 val)
{
	iowrite32(val, ipahal_ctx->base + ipahal_reg_n_offset(reg, n));
}

/*
 * ipahal_read_reg_n_fields() - Get the parsed value of n parameterized reg
 */
void ipahal_read_reg_n_fields(enum ipahal_reg_name reg, u32 n, void *fields)
{
	u32 val = ipahal_read_reg_n(reg, n);

	if (WARN_ON(!ipahal_regs[reg].parse))
		ipa_err("No parse function for %s\n", ipareg_name_to_str[reg]);
	else
		ipahal_regs[reg].parse(reg, fields, val);
}

/*
 * ipahal_write_reg_n_fields() - Write to n parameterized reg a parsed value
 */
void ipahal_write_reg_n_fields(enum ipahal_reg_name reg, u32 n,
		const void *fields)
{
	u32 val = 0;

	if (WARN_ON(!ipahal_regs[reg].construct))
		ipa_err("No construct function for %s\n",
			ipareg_name_to_str[reg]);
	else
		ipahal_regs[reg].construct(reg, fields, &val);

	ipahal_write_reg_n(reg, n, val);
}

u32 ipahal_get_reg_base(void)
{
	return 0x00040000;
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
	if (!valmask) {
		ipa_err("Input error\n");
		return;
	}

	valmask->val = (1 & IPA_ENDP_INIT_AGGR_n_AGGR_FORCE_CLOSE_BMSK) <<
		IPA_ENDP_INIT_AGGR_n_AGGR_FORCE_CLOSE_SHFT;
	valmask->mask = IPA_ENDP_INIT_AGGR_n_AGGR_FORCE_CLOSE_BMSK <<
		IPA_ENDP_INIT_AGGR_n_AGGR_FORCE_CLOSE_SHFT;

	valmask->val |= ((0 & IPA_ENDP_INIT_AGGR_n_AGGR_EN_BMSK) <<
		IPA_ENDP_INIT_AGGR_n_AGGR_EN_SHFT);
	valmask->mask |= ((IPA_ENDP_INIT_AGGR_n_AGGR_EN_BMSK <<
		IPA_ENDP_INIT_AGGR_n_AGGR_EN_SHFT));
}

u32 ipahal_aggr_get_max_byte_limit(void)
{
	return
		IPA_ENDP_INIT_AGGR_n_AGGR_BYTE_LIMIT_BMSK >>
		IPA_ENDP_INIT_AGGR_n_AGGR_BYTE_LIMIT_SHFT;
}

u32 ipahal_aggr_get_max_pkt_limit(void)
{
	return
		IPA_ENDP_INIT_AGGR_n_AGGR_PKT_LIMIT_BMSK >>
		IPA_ENDP_INIT_AGGR_n_AGGR_PKT_LIMIT_SHFT;
}

void ipahal_get_aggr_force_close_valmask(int ep_idx,
	struct ipahal_reg_valmask *valmask)
{
	u32 shft;
	u32 bmsk;

	if (!valmask) {
		ipa_err("Input error\n");
		return;
	}

	if (ipahal_ctx->hw_type <= IPA_HW_v3_1) {
		shft = IPA_AGGR_FORCE_CLOSE_AGGR_FORCE_CLOSE_PIPE_BITMAP_SHFT;
		bmsk = IPA_AGGR_FORCE_CLOSE_AGGR_FORCE_CLOSE_PIPE_BITMAP_BMSK;
	} else if (ipahal_ctx->hw_type <= IPA_HW_v3_5_1) {
		shft =
		IPA_AGGR_FORCE_CLOSE_AGGR_FORCE_CLOSE_PIPE_BITMAP_SHFT_V3_5;
		bmsk =
		IPA_AGGR_FORCE_CLOSE_AGGR_FORCE_CLOSE_PIPE_BITMAP_BMSK_V3_5;
	} else {
		shft =
		IPA_AGGR_FORCE_CLOSE_AGGR_FORCE_CLOSE_PIPE_BITMAP_SHFT_V4_0;
		bmsk =
		IPA_AGGR_FORCE_CLOSE_AGGR_FORCE_CLOSE_PIPE_BITMAP_BMSK_V4_0;
	}

	if (ep_idx > (sizeof(valmask->val) * 8 - 1)) {
		ipa_err("too big ep_idx %d\n", ep_idx);
		ipa_assert();
		return;
	}
	IPA_SETFIELD_IN_REG(valmask->val, 1 << ep_idx, shft, bmsk);
	valmask->mask = bmsk << shft;
}

void ipahal_get_fltrt_hash_flush_valmask(
	struct ipahal_reg_fltrt_hash_flush *flush,
	struct ipahal_reg_valmask *valmask)
{
	if (!flush || !valmask) {
		ipa_err("Input error: flush=%p ; valmask=%p\n",
			flush, valmask);
		return;
	}

	memset(valmask, 0, sizeof(struct ipahal_reg_valmask));

	if (flush->v6_rt)
		valmask->val |=
			(1<<IPA_FILT_ROUT_HASH_FLUSH_IPv6_ROUT_SHFT);
	if (flush->v6_flt)
		valmask->val |=
			(1<<IPA_FILT_ROUT_HASH_FLUSH_IPv6_FILT_SHFT);
	if (flush->v4_rt)
		valmask->val |=
			(1<<IPA_FILT_ROUT_HASH_FLUSH_IPv4_ROUT_SHFT);
	if (flush->v4_flt)
		valmask->val |=
			(1<<IPA_FILT_ROUT_HASH_FLUSH_IPv4_FILT_SHFT);

	valmask->mask = valmask->val;
}

void ipahal_get_status_ep_valmask(int pipe_num,
	struct ipahal_reg_valmask *valmask)
{
	if (!valmask) {
		ipa_err("Input error\n");
		return;
	}

	valmask->val =
		(pipe_num & IPA_ENDP_STATUS_n_STATUS_ENDP_BMSK) <<
		IPA_ENDP_STATUS_n_STATUS_ENDP_SHFT;

	valmask->mask =
		IPA_ENDP_STATUS_n_STATUS_ENDP_BMSK <<
		IPA_ENDP_STATUS_n_STATUS_ENDP_SHFT;
}
