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

#define pr_fmt(fmt)    "ipa %s:%d " fmt, __func__, __LINE__

#include <net/ip.h>
#include <linux/genalloc.h>	/* gen_pool_alloc() */
#include <linux/io.h>
#include <linux/ratelimit.h>
#include <linux/msm-bus.h>
#include <linux/msm-bus-board.h>
#include <linux/elf.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include "ipa_i.h"
#include "ipahal/ipahal.h"
#include "ipahal/ipahal_fltrt.h"


/* Offset past base of IPA "wrapper" space for register access */
#define IPA_REG_BASE_OFFSET	0x00040000

#define IPA_V4_0_CLK_RATE_SVS (125 * 1000 * 1000UL)
#define IPA_V4_0_CLK_RATE_NOMINAL (220 * 1000 * 1000UL)
#define IPA_V4_0_CLK_RATE_TURBO (250 * 1000 * 1000UL)

#define IPA_V3_0_BW_THRESHOLD_TURBO_MBPS (1000)
#define IPA_V3_0_BW_THRESHOLD_NOMINAL_MBPS (600)
#define IPA_V3_0_BW_THRESHOLD_SVS_MBPS (310)

#define IPA_ENDP_INIT_HDR_METADATA_n_MUX_ID_BMASK 0xFF0000
#define IPA_ENDP_INIT_HDR_METADATA_n_MUX_ID_SHFT 0x10

/* Max pipes + ICs for TAG process */
#define IPA_TAG_MAX_DESC (IPA3_MAX_NUM_PIPES + 6)

#define IPA_TAG_SLEEP_MIN_USEC (1000)
#define IPA_TAG_SLEEP_MAX_USEC (2000)
#define IPA_FORCE_CLOSE_TAG_PROCESS_TIMEOUT (10 * HZ)
#define IPA_BCR_REG_VAL_v3_5 (0x0000003B)
#define IPA_BCR_REG_VAL_v4_0 (0x00000039)
#define IPA_CLKON_CFG_v4_0 (0x30000000)
#define IPA_AGGR_GRAN_MIN (1)
#define IPA_AGGR_GRAN_MAX (32)
#define IPA_EOT_COAL_GRAN_MIN (1)
#define IPA_EOT_COAL_GRAN_MAX (16)

#define IPA_DMA_TASK_FOR_GSI_TIMEOUT_MSEC (15)

#define IPA_AGGR_BYTE_LIMIT (\
		IPA_ENDP_INIT_AGGR_N_AGGR_BYTE_LIMIT_BMSK >> \
		IPA_ENDP_INIT_AGGR_N_AGGR_BYTE_LIMIT_SHFT)
#define IPA_AGGR_PKT_LIMIT (\
		IPA_ENDP_INIT_AGGR_n_AGGR_PKT_LIMIT_BMSK >> \
		IPA_ENDP_INIT_AGGR_n_AGGR_PKT_LIMIT_SHFT)

/* In IPAv3 only endpoints 0-3 can be configured to deaggregation */
#define IPA_EP_SUPPORTS_DEAGGR(idx) ((idx) >= 0 && (idx) <= 3)

/* configure IPA spare register 1 in order to have correct IPA version
 * set bits 0,2,3 and 4. see SpareBits documentation.xlsx
 */

/* HPS, DPS sequencers Types*/
#define IPA_DPS_HPS_SEQ_TYPE_DMA_ONLY  0x00000000
/* DMA + DECIPHER/CIPHER */
#define IPA_DPS_HPS_SEQ_TYPE_DMA_DEC 0x00000011
/* Packet Processing + no decipher + uCP (for Ethernet Bridging) */
#define IPA_DPS_HPS_SEQ_TYPE_PKT_PROCESS_NO_DEC_UCP 0x00000002
/* Packet Processing + decipher + uCP */
#define IPA_DPS_HPS_SEQ_TYPE_PKT_PROCESS_DEC_UCP 0x00000013
/* 2 Packet Processing pass + no decipher + uCP */
#define IPA_DPS_HPS_SEQ_TYPE_2ND_PKT_PROCESS_PASS_NO_DEC_UCP 0x00000004
/* 2 Packet Processing pass + decipher + uCP */
#define IPA_DPS_HPS_SEQ_TYPE_2ND_PKT_PROCESS_PASS_DEC_UCP 0x00000015
/* Packet Processing + no decipher + no uCP */
#define IPA_DPS_HPS_SEQ_TYPE_PKT_PROCESS_NO_DEC_NO_UCP 0x00000006
/* Packet Processing + no decipher + no uCP */
#define IPA_DPS_HPS_SEQ_TYPE_PKT_PROCESS_DEC_NO_UCP 0x00000017
/* COMP/DECOMP */
#define IPA_DPS_HPS_SEQ_TYPE_DMA_COMP_DECOMP 0x00000020
/* Invalid sequencer type */
#define IPA_DPS_HPS_SEQ_TYPE_INVALID 0xFFFFFFFF

#define IPA_DPS_HPS_SEQ_TYPE_IS_DMA(seq_type) \
	(seq_type == IPA_DPS_HPS_SEQ_TYPE_DMA_ONLY || \
	seq_type == IPA_DPS_HPS_SEQ_TYPE_DMA_DEC || \
	seq_type == IPA_DPS_HPS_SEQ_TYPE_DMA_COMP_DECOMP)

#define QMB_MASTER_SELECT_DDR  (0)
#define QMB_MASTER_SELECT_PCIE (1)

/* Resource Group index*/
#define IPA_v3_0_GROUP_UL               (0)
#define IPA_v3_0_GROUP_DL               (1)
#define IPA_v3_0_GROUP_DPL              IPA_v3_0_GROUP_DL
#define IPA_v3_0_GROUP_DIAG             (2)
#define IPA_v3_0_GROUP_DMA              (3)
#define IPA_v3_0_GROUP_IMM_CMD          IPA_v3_0_GROUP_UL
#define IPA_v3_0_GROUP_Q6ZIP            (4)
#define IPA_v3_0_GROUP_Q6ZIP_GENERAL    IPA_v3_0_GROUP_Q6ZIP
#define IPA_v3_0_GROUP_UC_RX_Q          (5)
#define IPA_v3_0_GROUP_Q6ZIP_ENGINE     IPA_v3_0_GROUP_UC_RX_Q
#define IPA_v3_0_GROUP_MAX              (6)

#define IPA_v3_5_GROUP_LWA_DL           (0) /* currently not used */
#define IPA_v3_5_MHI_GROUP_PCIE IPA_v3_5_GROUP_LWA_DL
#define IPA_v3_5_GROUP_UL_DL            (1)
#define IPA_v3_5_MHI_GROUP_DDR          IPA_v3_5_GROUP_UL_DL
#define IPA_v3_5_MHI_GROUP_DMA          (2)
#define IPA_v3_5_GROUP_UC_RX_Q          (3) /* currently not used */
#define IPA_v3_5_SRC_GROUP_MAX          (4)
#define IPA_v3_5_DST_GROUP_MAX          (3)

#define IPA_v4_0_GROUP_LWA_DL           (0)
#define IPA_v4_0_MHI_GROUP_PCIE         (0)
#define IPA_v4_0_ETHERNET               (0)
#define IPA_v4_0_GROUP_UL_DL            (1)
#define IPA_v4_0_MHI_GROUP_DDR          (1)
#define IPA_v4_0_MHI_GROUP_DMA          (2)
#define IPA_v4_0_GROUP_UC_RX_Q          (3)
#define IPA_v4_0_SRC_GROUP_MAX          (4)
#define IPA_v4_0_DST_GROUP_MAX          (4)

#define IPA_GROUP_MAX IPA_v3_0_GROUP_MAX

enum ipa_rsrc_grp_type_src {
        IPA_v3_0_RSRC_GRP_TYPE_SRC_PKT_CONTEXTS,
        IPA_v3_0_RSRC_GRP_TYPE_SRC_HDR_SECTORS,
        IPA_v3_0_RSRC_GRP_TYPE_SRC_HDRI1_BUFFER,
        IPA_v3_0_RSRC_GRP_TYPE_SRS_DESCRIPTOR_LISTS,
        IPA_v3_0_RSRC_GRP_TYPE_SRC_DESCRIPTOR_BUFF,
        IPA_v3_0_RSRC_GRP_TYPE_SRC_HDRI2_BUFFERS,
        IPA_v3_0_RSRC_GRP_TYPE_SRC_HPS_DMARS,
        IPA_v3_0_RSRC_GRP_TYPE_SRC_ACK_ENTRIES,
        IPA_v3_0_RSRC_GRP_TYPE_SRC_MAX,

        IPA_v3_5_RSRC_GRP_TYPE_SRC_PKT_CONTEXTS = 0,
        IPA_v3_5_RSRC_GRP_TYPE_SRS_DESCRIPTOR_LISTS,
        IPA_v3_5_RSRC_GRP_TYPE_SRC_DESCRIPTOR_BUFF,
        IPA_v3_5_RSRC_GRP_TYPE_SRC_HPS_DMARS,
        IPA_v3_5_RSRC_GRP_TYPE_SRC_ACK_ENTRIES,
        IPA_v3_5_RSRC_GRP_TYPE_SRC_MAX,

        IPA_v4_0_RSRC_GRP_TYPE_SRC_PKT_CONTEXTS = 0,
        IPA_v4_0_RSRC_GRP_TYPE_SRS_DESCRIPTOR_LISTS,
        IPA_v4_0_RSRC_GRP_TYPE_SRC_DESCRIPTOR_BUFF,
        IPA_v4_0_RSRC_GRP_TYPE_SRC_HPS_DMARS,
        IPA_v4_0_RSRC_GRP_TYPE_SRC_ACK_ENTRIES,
        IPA_v4_0_RSRC_GRP_TYPE_SRC_MAX
};

#define IPA_RSRC_GRP_TYPE_SRC_MAX IPA_v3_0_RSRC_GRP_TYPE_SRC_MAX

enum ipa_rsrc_grp_type_dst {
        IPA_v3_0_RSRC_GRP_TYPE_DST_DATA_SECTORS,
        IPA_v3_0_RSRC_GRP_TYPE_DST_DATA_SECTOR_LISTS,
        IPA_v3_0_RSRC_GRP_TYPE_DST_DPS_DMARS,
        IPA_v3_0_RSRC_GRP_TYPE_DST_MAX,

        IPA_v3_5_RSRC_GRP_TYPE_DST_DATA_SECTORS = 0,
        IPA_v3_5_RSRC_GRP_TYPE_DST_DPS_DMARS,
        IPA_v3_5_RSRC_GRP_TYPE_DST_MAX,

        IPA_v4_0_RSRC_GRP_TYPE_DST_DATA_SECTORS = 0,
        IPA_v4_0_RSRC_GRP_TYPE_DST_DPS_DMARS,
        IPA_v4_0_RSRC_GRP_TYPE_DST_MAX,
};
#define IPA_RSRC_GRP_TYPE_DST_MAX IPA_v3_0_RSRC_GRP_TYPE_DST_MAX

enum ipa_rsrc_grp_type_rx {
	IPA_RSRC_GRP_TYPE_RX_HPS_CMDQ,
	IPA_RSRC_GRP_TYPE_RX_MAX
};

enum ipa_rsrc_grp_rx_hps_weight_config {
	IPA_RSRC_GRP_TYPE_RX_HPS_WEIGHT_CONFIG,
	IPA_RSRC_GRP_TYPE_RX_HPS_WEIGHT_MAX
};

struct rsrc_min_max {
	u32 min;
	u32 max;
};

enum ipa_ver {
	IPA_3_0,
	IPA_3_5,
	IPA_3_5_1,
	IPA_4_0,
	IPA_VER_MAX,
};

static const struct rsrc_min_max ipa3_rsrc_src_grp_config
	[IPA_VER_MAX][IPA_RSRC_GRP_TYPE_SRC_MAX][IPA_GROUP_MAX] = {
	[IPA_3_5_1] = {
		/* LWA_DL  UL_DL    not used  UC_RX_Q, other are invalid */
		[IPA_v3_5_RSRC_GRP_TYPE_SRC_PKT_CONTEXTS] = {
		{1, 63}, {1, 63}, {0, 0}, {1, 63}, {0, 0}, {0, 0} },
		[IPA_v3_5_RSRC_GRP_TYPE_SRS_DESCRIPTOR_LISTS] = {
		{10, 10}, {10, 10}, {0, 0}, {8, 8}, {0, 0}, {0, 0} },
		[IPA_v3_5_RSRC_GRP_TYPE_SRC_DESCRIPTOR_BUFF] = {
		{12, 12}, {14, 14}, {0, 0}, {8, 8}, {0, 0}, {0, 0} },
		[IPA_v3_5_RSRC_GRP_TYPE_SRC_HPS_DMARS] = {
		{0, 63}, {0, 63}, {0, 255}, {0, 255},  {0, 0}, {0, 0} },
		[IPA_v3_5_RSRC_GRP_TYPE_SRC_ACK_ENTRIES] = {
		{14, 14}, {20, 20}, {0, 0}, {14, 14}, {0, 0}, {0, 0} },
	},
	[IPA_4_0] = {
		/* LWA_DL  UL_DL    not used  UC_RX_Q, other are invalid */
		[IPA_v4_0_RSRC_GRP_TYPE_SRC_PKT_CONTEXTS] = {
		{1, 255}, {1, 255}, {0, 0}, {1, 255}, {0, 0}, {0, 0} },
		[IPA_v4_0_RSRC_GRP_TYPE_SRS_DESCRIPTOR_LISTS] = {
		{10, 10}, {10, 10}, {0, 0}, {8, 8}, {0, 0}, {0, 0} },
		[IPA_v4_0_RSRC_GRP_TYPE_SRC_DESCRIPTOR_BUFF] = {
		{12, 12}, {14, 14}, {0, 0}, {8, 8}, {0, 0}, {0, 0} },
		[IPA_v4_0_RSRC_GRP_TYPE_SRC_HPS_DMARS] = {
		{0, 255}, {0, 255}, {0, 255}, {0, 255},  {0, 0}, {0, 0} },
		[IPA_v4_0_RSRC_GRP_TYPE_SRC_ACK_ENTRIES] = {
		{14, 14}, {20, 20}, {0, 0}, {14, 14}, {0, 0}, {0, 0} },
	}
};

static const struct rsrc_min_max ipa3_rsrc_dst_grp_config
	[IPA_VER_MAX][IPA_RSRC_GRP_TYPE_DST_MAX][IPA_GROUP_MAX] = {
	[IPA_3_5_1] = {
		/* LWA_DL UL/DL/DPL unused N/A   N/A     N/A */
		[IPA_v3_5_RSRC_GRP_TYPE_DST_DATA_SECTORS] = {
		{4, 4}, {4, 4}, {3, 3}, {0, 0}, {0, 0}, {0, 0} },
		[IPA_v3_5_RSRC_GRP_TYPE_DST_DPS_DMARS] = {
		{2, 63}, {1, 63}, {1, 2}, {0, 0}, {0, 0}, {0, 0} },
	},
	[IPA_4_0] = {
		/*LWA_DL UL/DL/DPL uC, other are invalid */
		[IPA_v4_0_RSRC_GRP_TYPE_DST_DATA_SECTORS] = {
		{4, 4}, {4, 4}, {3, 3}, {2, 2}, {0, 0}, {0, 0} },
		[IPA_v4_0_RSRC_GRP_TYPE_DST_DPS_DMARS] = {
		{2, 255}, {1, 255}, {1, 2}, {0, 2}, {0, 0}, {0, 0} },
	}
};

static const struct rsrc_min_max ipa3_rsrc_rx_grp_config
	[IPA_VER_MAX][IPA_RSRC_GRP_TYPE_RX_MAX][IPA_GROUP_MAX] = {
	[IPA_3_5_1] = {
		/* LWA_DL UL_DL	unused   UC_RX_Q N/A     N/A */
		[IPA_RSRC_GRP_TYPE_RX_HPS_CMDQ] = {
		{3, 3}, {7, 7}, {0, 0}, {2, 2}, {0, 0}, {0, 0} },
	},
	[IPA_4_0] = {
		/* LWA_DL UL_DL	not used UC_RX_Q, other are invalid */
		[IPA_RSRC_GRP_TYPE_RX_HPS_CMDQ] = {
		{3, 3}, {7, 7}, {0, 0}, {2, 2}, {0, 0}, {0, 0} },
	}
};

static const u32 ipa3_rsrc_rx_grp_hps_weight_config
	[IPA_VER_MAX][IPA_RSRC_GRP_TYPE_RX_HPS_WEIGHT_MAX][IPA_GROUP_MAX] = {
	[IPA_3_5_1] = {
		/* LWA_DL UL_DL	unused   UC_RX_Q N/A     N/A */
		[IPA_RSRC_GRP_TYPE_RX_HPS_WEIGHT_CONFIG] = { 1, 1, 1, 1, 0, 0 },
	},
	[IPA_4_0] = {
		/* LWA_DL UL_DL	not used UC_RX_Q, other are invalid */
		[IPA_RSRC_GRP_TYPE_RX_HPS_WEIGHT_CONFIG] = { 1, 1, 1, 1, 0, 0 },
	}
};

enum ipa_ees {
	IPA_EE_AP = 0,
	IPA_EE_Q6 = 1,
	IPA_EE_UC = 2,
};

struct ipa_ep_configuration {
	bool valid;
	int group_num;
	bool support_flt;
	int sequencer_type;
	u8 qmb_master_sel;
	struct ipa_gsi_ep_config ipa_gsi_ep_info;
};

/* clients not included in the list below are considered as invalid */
static const struct ipa_ep_configuration ipa3_ep_mapping
					[IPA_VER_MAX][IPA_CLIENT_MAX] = {
	/* IPA_3_5_1 */
	[IPA_3_5_1][IPA_CLIENT_APPS_LAN_PROD] = {
			true, IPA_v3_5_GROUP_UL_DL, false,
			IPA_DPS_HPS_SEQ_TYPE_PKT_PROCESS_NO_DEC_UCP,
			QMB_MASTER_SELECT_DDR,
			{ 8, 7, 8, 16, IPA_EE_AP } },
	[IPA_3_5_1][IPA_CLIENT_APPS_WAN_PROD] = {
			true, IPA_v3_5_GROUP_UL_DL, true,
			IPA_DPS_HPS_SEQ_TYPE_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
			QMB_MASTER_SELECT_DDR,
			{ 2, 3, 16, 32, IPA_EE_AP } },
	[IPA_3_5_1][IPA_CLIENT_APPS_CMD_PROD]		= {
			true, IPA_v3_5_GROUP_UL_DL, false,
			IPA_DPS_HPS_SEQ_TYPE_DMA_ONLY,
			QMB_MASTER_SELECT_DDR,
			{ 5, 4, 20, 23, IPA_EE_AP } },
	[IPA_3_5_1][IPA_CLIENT_Q6_LAN_PROD]         = {
			true, IPA_v3_5_GROUP_UL_DL, true,
			IPA_DPS_HPS_SEQ_TYPE_PKT_PROCESS_NO_DEC_UCP,
			QMB_MASTER_SELECT_DDR,
			{ 3, 0, 16, 32, IPA_EE_Q6 } },
	[IPA_3_5_1][IPA_CLIENT_Q6_WAN_PROD]         = {
			true, IPA_v3_5_GROUP_UL_DL, true,
			IPA_DPS_HPS_SEQ_TYPE_PKT_PROCESS_NO_DEC_UCP,
			QMB_MASTER_SELECT_DDR,
			{ 6, 4, 12, 30, IPA_EE_Q6 } },
	[IPA_3_5_1][IPA_CLIENT_Q6_CMD_PROD]	    = {
			true, IPA_v3_5_GROUP_UL_DL, false,
			IPA_DPS_HPS_SEQ_TYPE_PKT_PROCESS_NO_DEC_UCP,
			QMB_MASTER_SELECT_DDR,
			{ 4, 1, 20, 23, IPA_EE_Q6 } },
	[IPA_3_5_1][IPA_CLIENT_APPS_LAN_CONS]       = {
			true, IPA_v3_5_GROUP_UL_DL, false,
			IPA_DPS_HPS_SEQ_TYPE_INVALID,
			QMB_MASTER_SELECT_DDR,
			{ 9, 5, 8, 12, IPA_EE_AP } },
	[IPA_3_5_1][IPA_CLIENT_APPS_WAN_CONS]       = {
			true, IPA_v3_5_GROUP_UL_DL, false,
			IPA_DPS_HPS_SEQ_TYPE_INVALID,
			QMB_MASTER_SELECT_DDR,
			{ 10, 6, 8, 12, IPA_EE_AP } },
	[IPA_3_5_1][IPA_CLIENT_Q6_LAN_CONS]         = {
			true, IPA_v3_5_GROUP_UL_DL, false,
			IPA_DPS_HPS_SEQ_TYPE_INVALID,
			QMB_MASTER_SELECT_DDR,
			{ 13, 3, 8, 12, IPA_EE_Q6 } },
	[IPA_3_5_1][IPA_CLIENT_Q6_WAN_CONS]         = {
			true, IPA_v3_5_GROUP_UL_DL, false,
			IPA_DPS_HPS_SEQ_TYPE_INVALID,
			QMB_MASTER_SELECT_DDR,
			{ 12, 2, 8, 12, IPA_EE_Q6 } },
	/* Dummy consumer (pipe 31) is used in L2TP rt rule */
	[IPA_3_5_1][IPA_CLIENT_DUMMY_CONS]          = {
			true, IPA_v3_5_GROUP_UL_DL,
			false,
			IPA_DPS_HPS_SEQ_TYPE_INVALID,
			QMB_MASTER_SELECT_DDR,
			{ 31, 31, 8, 8, IPA_EE_AP } },

	/* IPA_4_0 */
	[IPA_4_0][IPA_CLIENT_APPS_LAN_PROD]   = {
			true, IPA_v4_0_GROUP_UL_DL,
			false,
			IPA_DPS_HPS_SEQ_TYPE_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
			QMB_MASTER_SELECT_DDR,
			{ 8, 10, 8, 16, IPA_EE_AP } },
	[IPA_4_0][IPA_CLIENT_APPS_WAN_PROD] = {
			true, IPA_v4_0_GROUP_UL_DL,
			true,
			IPA_DPS_HPS_SEQ_TYPE_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
			QMB_MASTER_SELECT_DDR,
			{ 2, 3, 16, 32, IPA_EE_AP } },
	[IPA_4_0][IPA_CLIENT_APPS_CMD_PROD]	  = {
			true, IPA_v4_0_GROUP_UL_DL,
			false,
			IPA_DPS_HPS_SEQ_TYPE_DMA_ONLY,
			QMB_MASTER_SELECT_DDR,
			{ 5, 4, 20, 24, IPA_EE_AP } },
	[IPA_4_0][IPA_CLIENT_Q6_LAN_PROD]         = {
			true, IPA_v4_0_GROUP_UL_DL,
			true,
			IPA_DPS_HPS_SEQ_TYPE_PKT_PROCESS_NO_DEC_UCP,
			QMB_MASTER_SELECT_DDR,
			{ 6, 2, 12, 24, IPA_EE_Q6 } },
	[IPA_4_0][IPA_CLIENT_Q6_WAN_PROD]         = {
			true, IPA_v4_0_GROUP_UL_DL,
			true,
			IPA_DPS_HPS_SEQ_TYPE_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
			QMB_MASTER_SELECT_DDR,
			{ 3, 0, 16, 32, IPA_EE_Q6 } },
	[IPA_4_0][IPA_CLIENT_Q6_CMD_PROD]	  = {
			true, IPA_v4_0_GROUP_UL_DL,
			false,
			IPA_DPS_HPS_SEQ_TYPE_PKT_PROCESS_NO_DEC_UCP,
			QMB_MASTER_SELECT_DDR,
			{ 4, 1, 20, 24, IPA_EE_Q6 } },

	[IPA_4_0][IPA_CLIENT_APPS_LAN_CONS]       = {
			true, IPA_v4_0_GROUP_UL_DL,
			false,
			IPA_DPS_HPS_SEQ_TYPE_INVALID,
			QMB_MASTER_SELECT_DDR,
			{ 10, 5, 9, 9, IPA_EE_AP } },
	[IPA_4_0][IPA_CLIENT_APPS_WAN_CONS]       = {
			true, IPA_v4_0_GROUP_UL_DL,
			false,
			IPA_DPS_HPS_SEQ_TYPE_INVALID,
			QMB_MASTER_SELECT_DDR,
			{ 11, 6, 9, 9, IPA_EE_AP } },
	[IPA_4_0][IPA_CLIENT_Q6_LAN_CONS]         = {
			true, IPA_v4_0_GROUP_UL_DL,
			false,
			IPA_DPS_HPS_SEQ_TYPE_INVALID,
			QMB_MASTER_SELECT_DDR,
			{ 14, 4, 9, 9, IPA_EE_Q6 } },
	[IPA_4_0][IPA_CLIENT_Q6_WAN_CONS]         = {
			true, IPA_v4_0_GROUP_UL_DL,
			false,
			IPA_DPS_HPS_SEQ_TYPE_INVALID,
			QMB_MASTER_SELECT_DDR,
			{ 13, 3, 9, 9, IPA_EE_Q6 } },
	[IPA_4_0][IPA_CLIENT_Q6_LTE_WIFI_AGGR_CONS] = {
			true, IPA_v4_0_GROUP_UL_DL,
			false,
			IPA_DPS_HPS_SEQ_TYPE_INVALID,
			QMB_MASTER_SELECT_DDR,
			{ 16, 5, 9, 9, IPA_EE_Q6 } },
	/* Only for test purpose */
	/* Dummy consumer (pipe 31) is used in L2TP rt rule */
	[IPA_4_0][IPA_CLIENT_DUMMY_CONS]          = {
			true, IPA_v4_0_GROUP_UL_DL,
			false,
			IPA_DPS_HPS_SEQ_TYPE_INVALID,
			QMB_MASTER_SELECT_DDR,
			{ 31, 31, 8, 8, IPA_EE_AP } }

};

static struct msm_bus_vectors ipa_min_vectors_v3_0[] = {
	{
		.src = MSM_BUS_MASTER_IPA,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 0 * 1000ULL,
		.ib = 0 * 1000ULL,
	},
	{
		.src = MSM_BUS_MASTER_IPA,
		.dst = MSM_BUS_SLAVE_OCIMEM,
		.ab = 0 * 1000ULL,
		.ib = 0 * 1000ULL,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_IPA_CFG,
		.ab = 0 * 1000ULL,
		.ib = 0 * 1000ULL,
	},
	{
		.src = MSM_BUS_MASTER_IPA_CORE,
		.dst = MSM_BUS_SLAVE_IPA_CORE,
		.ab = 0 * 1000ULL,
		.ib = 0 * 1000ULL,
	},
};

static struct msm_bus_vectors ipa_svs2_vectors_v3_0[] = {
	{
		.src = MSM_BUS_MASTER_IPA,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 80000 * 1000ULL,
		.ib = 600000 * 1000ULL,
	},
	{
		.src = MSM_BUS_MASTER_IPA,
		.dst = MSM_BUS_SLAVE_OCIMEM,
		.ab = 80000 * 1000ULL,
		.ib = 350000 * 1000ULL,
	},
	{	/*gcc_config_noc_clk_src */
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_IPA_CFG,
		.ab = 40000 * 1000ULL,
		.ib = 40000 * 1000ULL,
	},
	{
		.src = MSM_BUS_MASTER_IPA_CORE,
		.dst = MSM_BUS_SLAVE_IPA_CORE,
		.ab = 0 * 1000ULL,
		.ib = 75 * 1000ULL, /* IB defined for IPA2X_clk in MHz*/
	},
};

static struct msm_bus_vectors ipa_svs_vectors_v3_0[] = {
	{
		.src = MSM_BUS_MASTER_IPA,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 80000 * 1000ULL,
		.ib = 640000 * 1000ULL,
	},
	{
		.src = MSM_BUS_MASTER_IPA,
		.dst = MSM_BUS_SLAVE_OCIMEM,
		.ab = 80000 * 1000ULL,
		.ib = 640000 * 1000ULL,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_IPA_CFG,
		.ab = 80000 * 1000ULL,
		.ib = 80000 * 1000ULL,
	},
	{
		.src = MSM_BUS_MASTER_IPA_CORE,
		.dst = MSM_BUS_SLAVE_IPA_CORE,
		.ab = 0 * 1000ULL,
		.ib = 150 * 1000ULL, /* IB defined for IPA2X_clk in MHz*/
	},
};

static struct msm_bus_vectors ipa_nominal_perf_vectors_v3_0[] = {
	{
		.src = MSM_BUS_MASTER_IPA,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 206000 * 1000ULL,
		.ib = 960000 * 1000ULL,
	},
	{
		.src = MSM_BUS_MASTER_IPA,
		.dst = MSM_BUS_SLAVE_OCIMEM,
		.ab = 206000 * 1000ULL,
		.ib = 960000 * 1000ULL,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_IPA_CFG,
		.ab = 206000 * 1000ULL,
		.ib = 160000 * 1000ULL,
	},
	{
		.src = MSM_BUS_MASTER_IPA_CORE,
		.dst = MSM_BUS_SLAVE_IPA_CORE,
		.ab = 0 * 1000ULL,
		.ib = 300 * 1000ULL, /* IB defined for IPA2X_clk in MHz*/
	},
};

static struct msm_bus_vectors ipa_turbo_perf_vectors_v3_0[] = {
	{
		.src = MSM_BUS_MASTER_IPA,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 206000 * 1000ULL,
		.ib = 3600000 * 1000ULL,
	},
	{
		.src = MSM_BUS_MASTER_IPA,
		.dst = MSM_BUS_SLAVE_OCIMEM,
		.ab = 206000 * 1000ULL,
		.ib = 3600000 * 1000ULL,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_IPA_CFG,
		.ab = 206000 * 1000ULL,
		.ib = 300000 * 1000ULL,
	},
	{
		.src = MSM_BUS_MASTER_IPA_CORE,
		.dst = MSM_BUS_SLAVE_IPA_CORE,
		.ab = 0 * 1000ULL,
		.ib = 355 * 1000ULL, /* IB defined for IPA clk in MHz*/
	},
};

static struct msm_bus_paths ipa_usecases_v3_0[]  = {
	{
		.num_paths = ARRAY_SIZE(ipa_min_vectors_v3_0),
		.vectors = ipa_min_vectors_v3_0,
	},
	{
		.num_paths = ARRAY_SIZE(ipa_svs2_vectors_v3_0),
		.vectors = ipa_svs2_vectors_v3_0,
	},
	{
		.num_paths = ARRAY_SIZE(ipa_svs_vectors_v3_0),
		.vectors = ipa_svs_vectors_v3_0,
	},
	{
		.num_paths = ARRAY_SIZE(ipa_nominal_perf_vectors_v3_0),
		.vectors = ipa_nominal_perf_vectors_v3_0,
	},
	{
		.num_paths = ARRAY_SIZE(ipa_turbo_perf_vectors_v3_0),
		.vectors = ipa_turbo_perf_vectors_v3_0,
	},
};

static struct msm_bus_scale_pdata ipa_bus_client_pdata_v3_0 = {
	.usecase = ipa_usecases_v3_0,
	.num_usecases = ARRAY_SIZE(ipa_usecases_v3_0),
	.name = "ipa",
};

/**
 * ipa3_should_pipe_be_suspended() - returns true when the client's pipe should
 * be suspended during a power save scenario. False otherwise.
 *
 * @client: [IN] IPA client
 */
bool ipa3_should_pipe_be_suspended(enum ipa_client_type client)
{
	int ipa_ep_idx;

	ipa_ep_idx = ipa3_get_ep_mapping(client);
	if (ipa_ep_idx < 0) {
		ipa_err("Invalid client.\n");
		WARN_ON(1);
		return false;
	}

	return false;
}

 /**
 * _ipa_sram_settings_read_v3_0() - Read SRAM settings from HW
 *
 * Returns:	None
 */
void _ipa_sram_settings_read_v3_0(void)
{
	struct ipahal_reg_shared_mem_size smem_sz;

	ipahal_read_reg_fields(IPA_SHARED_MEM_SIZE, &smem_sz);

	/* reg fields are in 8B units */
	ipa3_ctx->smem_restricted_bytes = smem_sz.shared_mem_baddr * 8;
	ipa3_ctx->smem_sz = smem_sz.shared_mem_sz * 8;

	ipa3_ctx->smem_reqd_sz = ipa3_mem(END_OFST);
}

/**
 * ipa3_cfg_qsb() - Configure IPA QSB maximal reads and writes
 *
 * Returns:	None
 */
void ipa3_cfg_qsb(void)
{
	struct ipahal_reg_qsb_max_reads max_reads = { 0 };
	struct ipahal_reg_qsb_max_writes max_writes = { 0 };

	max_reads.qmb_0_max_reads = 8,
	max_reads.qmb_1_max_reads = 12;

	max_writes.qmb_0_max_writes = 8;
	max_writes.qmb_1_max_writes = 4;

	ipahal_write_reg_fields(IPA_QSB_MAX_WRITES, &max_writes);
	ipahal_write_reg_fields(IPA_QSB_MAX_READS, &max_reads);
}

/**
 * ipa3_init_hw() - initialize HW
 *
 * Return codes:
 * 0: success
 */
int ipa3_init_hw(void)
{
	u32 ipa_version = 0;

	/* Read IPA version and make sure we have access to the registers */
	ipa_version = ipahal_read_reg(IPA_VERSION);
	if (ipa_version == 0)
		return -EFAULT;

	/* SDM845 has IPA version 3.5.1 */
	ipahal_write_reg(IPA_BCR, IPA_BCR_REG_VAL_v3_5);

	ipa3_cfg_qsb();

	return 0;
}

static const struct ipa_ep_configuration *
ep_configuration(enum ipa_client_type client)
{
	const struct ipa_ep_configuration *ep_config;

	if (client >= IPA_CLIENT_MAX || client < 0) {
		pr_err_ratelimited("Bad client number! client =%d\n", client);
		return NULL;
	}

	ep_config = &ipa3_ep_mapping[IPA_3_5_1][client];
	if (ep_config->valid)
		return ep_config;

	return NULL;
}

/**
 * ipa3_get_gsi_ep_info() - provide gsi ep information
 * @client: IPA client value
 *
 * Return value: pointer to ipa_gsi_ep_info
 */
const struct ipa_gsi_ep_config *
ipa3_get_gsi_ep_info(enum ipa_client_type client)
{
	const struct ipa_ep_configuration *ep_config;

	ep_config = ep_configuration(client);
	if (ep_config)
		return &ep_config->ipa_gsi_ep_info;

	return NULL;
}

/**
 * ipa3_get_ep_mapping() - provide endpoint mapping
 * @client: client type
 *
 * Return value: endpoint mapping
 */
int ipa3_get_ep_mapping(enum ipa_client_type client)
{
	const struct ipa_gsi_ep_config *ep_info;
	int ipa_ep_idx;

	ep_info = ipa3_get_gsi_ep_info(client);
	if (!ep_info)
		return -ESRCH;

	ipa_ep_idx = ep_info->ipa_ep_num;
	if (ipa_ep_idx < 0)
		return -ENOENT;
	if (ipa_ep_idx < IPA3_MAX_NUM_PIPES || client == IPA_CLIENT_DUMMY_CONS)
		return ipa_ep_idx;

	return -ENOENT;
}

/**
 * ipa_get_ep_group() - provide endpoint group by client
 * @client: client type
 *
 * Return value: endpoint group
 */
int ipa_get_ep_group(enum ipa_client_type client)
{
	const struct ipa_ep_configuration *ep_config;

	ep_config = ep_configuration(client);
	if (ep_config)
		return ep_config->group_num;

	return -EINVAL;
}

/**
 * ipa3_get_qmb_master_sel() - provide QMB master selection for the client
 * @client: client type
 *
 * Return value: QMB master index
 */
u8 ipa3_get_qmb_master_sel(enum ipa_client_type client)
{
	const struct ipa_ep_configuration *ep_config;

	ep_config = ep_configuration(client);
	if (ep_config)
		return ep_config->qmb_master_sel;

	return -EINVAL;
}

/* ipa3_set_client() - provide client mapping
 * @client: client type
 *
 * Return value: none
 */


/**
 * ipa3_get_client_mapping() - provide client mapping
 * @pipe_idx: IPA end-point number
 *
 * Return value: client mapping
 */
enum ipa_client_type ipa3_get_client_mapping(int pipe_idx)
{
	if (pipe_idx >= ipa3_ctx->ipa_num_pipes || pipe_idx < 0) {
		ipa_err("Bad pipe index!\n");
		return -EINVAL;
	}

	return ipa3_ctx->ep[pipe_idx].client;
}

/**
 * ipa_init_ep_flt_bitmap() - Initialize the bitmap
 * that represents the End-points that supports filtering
 */
void ipa_init_ep_flt_bitmap(void)
{
	enum ipa_client_type cl;
	u8 hw_type_idx = IPA_3_5_1;
	u32 bitmap = 0;

	BUG_ON(ipa3_ctx->ep_flt_bitmap);

	for (cl = 0; cl < IPA_CLIENT_MAX ; cl++) {
		const struct ipa_ep_configuration *ep_config;

		ep_config = &ipa3_ep_mapping[hw_type_idx][cl];
		if (ep_config->support_flt) {
			u32 pipe_num = ep_config->ipa_gsi_ep_info.ipa_ep_num;

			bitmap |= BIT(pipe_num);
			if (bitmap != ipa3_ctx->ep_flt_bitmap) {
				ipa3_ctx->ep_flt_bitmap = bitmap;
				ipa3_ctx->ep_flt_num++;
			}
		}
	}
}

/**
 * ipa_is_ep_support_flt() - Given an End-point check
 * whether it supports filtering or not.
 *
 * @pipe_idx:
 *
 * Return values:
 * true if supports and false if not
 */
bool ipa_is_ep_support_flt(int pipe_idx)
{
	if (pipe_idx >= ipa3_ctx->ipa_num_pipes || pipe_idx < 0) {
		ipa_err("Bad pipe index!\n");
		return false;
	}

	return ipa3_ctx->ep_flt_bitmap & BIT(pipe_idx);
}

#define client_handle_valid(clnt_hdl) \
	_client_handle_valid(__func__, (clnt_hdl))
static bool _client_handle_valid(const char *func, u32 clnt_hdl)
{
	if (clnt_hdl >= ipa3_ctx->ipa_num_pipes)
		ipa_err("%s: bad clnt_hdl %u", func, clnt_hdl);
	else if (!ipa3_ctx->ep[clnt_hdl].valid)
		ipa_err("%s: clnt_hdl %u not valid", func, clnt_hdl);
	else
		return true;

	return false;
}

static const char *ipa3_get_mode_type_str(enum ipa_mode_type mode)
{
	switch (mode) {
	case (IPA_BASIC):
		return "Basic";
	case (IPA_ENABLE_FRAMING_HDLC):
		return "HDLC framing";
	case (IPA_ENABLE_DEFRAMING_HDLC):
		return "HDLC de-framing";
	case (IPA_DMA):
		return "DMA";
	}

	return "undefined";
}

static const char *ipa3_get_aggr_enable_str(enum ipa_aggr_en_type aggr_en)
{
	switch (aggr_en) {
	case (IPA_BYPASS_AGGR):
			return "no aggregation";
	case (IPA_ENABLE_AGGR):
			return "aggregation enabled";
	case (IPA_ENABLE_DEAGGR):
		return "de-aggregation enabled";
	}

	return "undefined";
}

static const char *ipa3_get_aggr_type_str(enum ipa_aggr_type aggr_type)
{
	switch (aggr_type) {
	case (IPA_MBIM_16):
			return "MBIM_16";
	case (IPA_HDLC):
		return "HDLC";
	case (IPA_TLP):
			return "TLP";
	case (IPA_RNDIS):
			return "RNDIS";
	case (IPA_GENERIC):
			return "GENERIC";
	case (IPA_QCMAP):
			return "QCMAP";
	}
	return "undefined";
}

/**
 * ipa3_cfg_ep_aggr() - IPA end-point aggregation configuration
 * @clnt_hdl:	[in] opaque client handle assigned by IPA to client
 * @ipa_ep_cfg:	[in] IPA end-point configuration params
 *
 * Returns:	0 on success, negative on failure
 *
 * Note:	Should not be called from atomic context
 */
static int ipa3_cfg_ep_aggr(u32 clnt_hdl, const struct ipa_ep_cfg_aggr *ep_aggr)
{
	if (!client_handle_valid(clnt_hdl))
		return -EINVAL;

	if (ep_aggr->aggr_en == IPA_ENABLE_DEAGGR &&
	    !IPA_EP_SUPPORTS_DEAGGR(clnt_hdl)) {
		ipa_err("pipe=%d cannot be configured to DEAGGR\n", clnt_hdl);
		WARN_ON(1);
		return -EINVAL;
	}

	ipa_debug("pipe=%d en=%d(%s), type=%d(%s), byte_limit=%d, time_limit=%d\n",
			clnt_hdl,
			ep_aggr->aggr_en,
			ipa3_get_aggr_enable_str(ep_aggr->aggr_en),
			ep_aggr->aggr,
			ipa3_get_aggr_type_str(ep_aggr->aggr),
			ep_aggr->aggr_byte_limit,
			ep_aggr->aggr_time_limit);
	ipa_debug("hard_byte_limit_en=%d aggr_sw_eof_active=%d\n",
		ep_aggr->aggr_hard_byte_limit_en,
		ep_aggr->aggr_sw_eof_active);

	/* copy over EP cfg */
	ipa3_ctx->ep[clnt_hdl].cfg.aggr = *ep_aggr;

	IPA_ACTIVE_CLIENTS_INC_EP(ipa3_get_client_mapping(clnt_hdl));

	ipahal_write_reg_n_fields(IPA_ENDP_INIT_AGGR_n, clnt_hdl, ep_aggr);

	IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));

	return 0;
}

/**
 * ipa3_cfg_ep_cfg() - IPA end-point cfg configuration
 * @clnt_hdl:	[in] opaque client handle assigned by IPA to client
 * @ipa_ep_cfg:	[in] IPA end-point configuration params
 *
 * Returns:	0 on success, negative on failure
 *
 * Note:	Should not be called from atomic context
 */
static int ipa3_cfg_ep_cfg(u32 clnt_hdl, const struct ipa_ep_cfg_cfg *cfg)
{
	u8 qmb_master_sel;

	if (!client_handle_valid(clnt_hdl))
		return -EINVAL;

	/* copy over EP cfg */
	ipa3_ctx->ep[clnt_hdl].cfg.cfg = *cfg;

	/* Override QMB master selection */
	qmb_master_sel = ipa3_get_qmb_master_sel(ipa3_ctx->ep[clnt_hdl].client);
	ipa3_ctx->ep[clnt_hdl].cfg.cfg.gen_qmb_master_sel = qmb_master_sel;
	ipa_debug(
	       "pipe=%d, frag_ofld_en=%d cs_ofld_en=%d mdata_hdr_ofst=%d gen_qmb_master_sel=%d\n",
			clnt_hdl,
			ipa3_ctx->ep[clnt_hdl].cfg.cfg.frag_offload_en,
			ipa3_ctx->ep[clnt_hdl].cfg.cfg.cs_offload_en,
			ipa3_ctx->ep[clnt_hdl].cfg.cfg.cs_metadata_hdr_offset,
			ipa3_ctx->ep[clnt_hdl].cfg.cfg.gen_qmb_master_sel);

	IPA_ACTIVE_CLIENTS_INC_EP(ipa3_get_client_mapping(clnt_hdl));

	ipahal_write_reg_n_fields(IPA_ENDP_INIT_CFG_n, clnt_hdl,
				  &ipa3_ctx->ep[clnt_hdl].cfg.cfg);

	IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));

	return 0;
}

/**
 * ipa3_cfg_ep_mode() - IPA end-point mode configuration
 * @clnt_hdl:	[in] opaque client handle assigned by IPA to client
 * @ipa_ep_cfg:	[in] IPA end-point configuration params
 *
 * Returns:	0 on success, negative on failure
 *
 * Note:	Should not be called from atomic context
 */
static int ipa3_cfg_ep_mode(u32 clnt_hdl, const struct ipa_ep_cfg_mode *ep_mode)
{
	int ep;
	struct ipahal_reg_endp_init_mode init_mode;

	if (!client_handle_valid(clnt_hdl))
		return -EINVAL;

	if (IPA_CLIENT_IS_CONS(ipa3_ctx->ep[clnt_hdl].client)) {
		ipa_err("MODE does not apply to IPA out EP %d\n", clnt_hdl);
		return -EINVAL;
	}

	ep = ipa3_get_ep_mapping(ep_mode->dst);
	if (ep < 0 && ep_mode->mode == IPA_DMA) {
		ipa_err("dst %d does not exist in DMA mode\n", ep_mode->dst);
		return -EINVAL;
	}

	WARN_ON(ep_mode->mode == IPA_DMA && IPA_CLIENT_IS_PROD(ep_mode->dst));

	if (!IPA_CLIENT_IS_CONS(ep_mode->dst))
		ep = ipa3_get_ep_mapping(IPA_CLIENT_APPS_LAN_CONS);

	ipa_debug("pipe=%d mode=%d(%s), dst_client_number=%d",
			clnt_hdl,
			ep_mode->mode,
			ipa3_get_mode_type_str(ep_mode->mode),
			ep_mode->dst);

	/* copy over EP cfg */
	ipa3_ctx->ep[clnt_hdl].cfg.mode = *ep_mode;
	ipa3_ctx->ep[clnt_hdl].dst_pipe_index = ep;

	IPA_ACTIVE_CLIENTS_INC_EP(ipa3_get_client_mapping(clnt_hdl));

	init_mode.dst_pipe_number = ipa3_ctx->ep[clnt_hdl].dst_pipe_index;
	init_mode.ep_mode = *ep_mode;
	ipahal_write_reg_n_fields(IPA_ENDP_INIT_MODE_n, clnt_hdl, &init_mode);

	IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));

	return 0;
}

/**
 * ipa3_cfg_ep_seq() - IPA end-point HPS/DPS sequencer type configuration
 * @clnt_hdl:	[in] opaque client handle assigned by IPA to client
 *
 * Returns:	0 on success, negative on failure
 *
 * Note:	Should not be called from atomic context
 */
static int ipa3_cfg_ep_seq(u32 clnt_hdl, const struct ipa_ep_cfg_seq *seq_cfg)
{
	int type;

	if (!client_handle_valid(clnt_hdl))
		return -EINVAL;

	if (IPA_CLIENT_IS_CONS(ipa3_ctx->ep[clnt_hdl].client)) {
		ipa_err("SEQ does not apply to IPA consumer EP %d\n", clnt_hdl);
		return -EINVAL;
	}

	if (seq_cfg->set_dynamic)
		type = seq_cfg->seq_type;
	else
		type = ipa3_ep_mapping[IPA_3_5_1]
			[ipa3_ctx->ep[clnt_hdl].client].sequencer_type;

	if (type != IPA_DPS_HPS_SEQ_TYPE_INVALID) {
		if (ipa3_ctx->ep[clnt_hdl].cfg.mode.mode == IPA_DMA &&
			!IPA_DPS_HPS_SEQ_TYPE_IS_DMA(type)) {
			ipa_err("Configuring non-DMA SEQ type to DMA pipe\n");
			BUG();
		}
		IPA_ACTIVE_CLIENTS_INC_EP(ipa3_get_client_mapping(clnt_hdl));
		/* Configure sequencers type*/

		ipa_debug("set sequencers to sequence 0x%x, ep = %d\n", type,
				clnt_hdl);
		ipahal_write_reg_n(IPA_ENDP_INIT_SEQ_n, clnt_hdl, type);

		IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));
	} else {
		ipa_debug("should not set sequencer type of ep = %d\n", clnt_hdl);
	}

	return 0;
}

/**
 * ipa3_cfg_ep_deaggr() -  IPA end-point deaggregation configuration
 * @clnt_hdl:	[in] opaque client handle assigned by IPA to client
 * @ep_deaggr:	[in] IPA end-point configuration params
 *
 * Returns:	0 on success, negative on failure
 *
 * Note:	Should not be called from atomic context
 */
static int ipa3_cfg_ep_deaggr(u32 clnt_hdl,
			const struct ipa_ep_cfg_deaggr *ep_deaggr)
{
	struct ipa3_ep_context *ep;

	if (!client_handle_valid(clnt_hdl))
		return -EINVAL;

	ipa_debug("pipe=%d deaggr_hdr_len=%d\n",
		clnt_hdl,
		ep_deaggr->deaggr_hdr_len);

	ipa_debug("packet_offset_valid=%d\n",
		ep_deaggr->packet_offset_valid);

	ipa_debug("packet_offset_location=%d max_packet_len=%d\n",
		ep_deaggr->packet_offset_location,
		ep_deaggr->max_packet_len);

	ep = &ipa3_ctx->ep[clnt_hdl];

	/* copy over EP cfg */
	ep->cfg.deaggr = *ep_deaggr;

	IPA_ACTIVE_CLIENTS_INC_EP(ipa3_get_client_mapping(clnt_hdl));

	ipahal_write_reg_n_fields(IPA_ENDP_INIT_DEAGGR_n, clnt_hdl,
		&ep->cfg.deaggr);

	IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));

	return 0;
}

/**
 * ipa3_cfg_ep_metadata_mask() - IPA end-point meta-data mask configuration
 * @clnt_hdl:	[in] opaque client handle assigned by IPA to client
 * @ipa_ep_cfg:	[in] IPA end-point configuration params
 *
 * Returns:	0 on success, negative on failure
 *
 * Note:	Should not be called from atomic context
 */
static int ipa3_cfg_ep_metadata_mask(u32 clnt_hdl,
		const struct ipa_ep_cfg_metadata_mask
		*metadata_mask)
{
	if (!client_handle_valid(clnt_hdl))
		return -EINVAL;

	ipa_debug("pipe=%d, metadata_mask=0x%x\n",
			clnt_hdl,
			metadata_mask->metadata_mask);

	/* copy over EP cfg */
	ipa3_ctx->ep[clnt_hdl].cfg.metadata_mask = *metadata_mask;

	IPA_ACTIVE_CLIENTS_INC_EP(ipa3_get_client_mapping(clnt_hdl));

	ipahal_write_reg_n_fields(IPA_ENDP_INIT_HDR_METADATA_MASK_n,
		clnt_hdl, metadata_mask);

	IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));

	return 0;
}

/**
 * ipa3_cfg_ep - IPA end-point configuration
 * @clnt_hdl:	[in] opaque client handle assigned by IPA to client
 * @ipa_ep_cfg:	[in] IPA end-point configuration params
 *
 * This includes nat, IPv6CT, header, mode, aggregation and route settings and
 * is a one shot API to configure the IPA end-point fully
 *
 * Returns:	0 on success, negative on failure
 *
 * Note:	Should not be called from atomic context
 */
int ipa3_cfg_ep(u32 clnt_hdl, const struct ipa_ep_cfg *ipa_ep_cfg)
{
	int result;

	if (!client_handle_valid(clnt_hdl))
		return -EINVAL;

	result = ipa3_cfg_ep_hdr(clnt_hdl, &ipa_ep_cfg->hdr);
	if (result)
		return result;

	result = ipa3_cfg_ep_hdr_ext(clnt_hdl, &ipa_ep_cfg->hdr_ext);
	if (result)
		return result;

	result = ipa3_cfg_ep_aggr(clnt_hdl, &ipa_ep_cfg->aggr);
	if (result)
		return result;

	result = ipa3_cfg_ep_cfg(clnt_hdl, &ipa_ep_cfg->cfg);
	if (result)
		return result;

	if (IPA_CLIENT_IS_PROD(ipa3_ctx->ep[clnt_hdl].client)) {
		result = ipa3_cfg_ep_mode(clnt_hdl, &ipa_ep_cfg->mode);
		if (result)
			return result;

		result = ipa3_cfg_ep_seq(clnt_hdl, &ipa_ep_cfg->seq);
		if (result)
			return result;

		result = ipa3_cfg_ep_deaggr(clnt_hdl, &ipa_ep_cfg->deaggr);
		if (result)
			return result;
	} else {
		result = ipa3_cfg_ep_metadata_mask(clnt_hdl,
				&ipa_ep_cfg->metadata_mask);
		if (result)
			return result;
	}

	return 0;
}

/**
 * ipa3_cfg_ep_status() - IPA end-point status configuration
 * @clnt_hdl:	[in] opaque client handle assigned by IPA to client
 * @ipa_ep_cfg:	[in] IPA end-point configuration params
 *
 * Returns:	0 on success, negative on failure
 *
 * Note:	Should not be called from atomic context
 */
int ipa3_cfg_ep_status(u32 clnt_hdl,
	const struct ipahal_reg_ep_cfg_status *ep_status)
{
	if (!client_handle_valid(clnt_hdl))
		return -EINVAL;

	ipa_debug("pipe=%d, status_en=%d status_ep=%d status_location=%d\n",
			clnt_hdl,
			ep_status->status_en,
			ep_status->status_ep,
			ep_status->status_location);

	/* copy over EP cfg */
	ipa3_ctx->ep[clnt_hdl].status = *ep_status;

	IPA_ACTIVE_CLIENTS_INC_EP(ipa3_get_client_mapping(clnt_hdl));

	ipahal_write_reg_n_fields(IPA_ENDP_STATUS_n, clnt_hdl, ep_status);

	IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));

	return 0;
}

/**
 * ipa3_cfg_ep_hdr() -  IPA end-point header configuration
 * @clnt_hdl:	[in] opaque client handle assigned by IPA to client
 * @ipa_ep_cfg:	[in] IPA end-point configuration params
 *
 * Returns:	0 on success, negative on failure
 *
 * Note:	Should not be called from atomic context
 */
int ipa3_cfg_ep_hdr(u32 clnt_hdl, const struct ipa_ep_cfg_hdr *ep_hdr)
{
	struct ipa3_ep_context *ep;

	if (!client_handle_valid(clnt_hdl))
		return -EINVAL;

	ipa_debug("pipe=%d metadata_reg_valid=%d\n",
		clnt_hdl,
		ep_hdr->hdr_metadata_reg_valid);

	ipa_debug("remove_additional=%d, a5_mux=%d, ofst_pkt_size=0x%x\n",
		ep_hdr->hdr_remove_additional,
		ep_hdr->hdr_a5_mux,
		ep_hdr->hdr_ofst_pkt_size);

	ipa_debug("ofst_pkt_size_valid=%d, additional_const_len=0x%x\n",
		ep_hdr->hdr_ofst_pkt_size_valid,
		ep_hdr->hdr_additional_const_len);

	ipa_debug("ofst_metadata=0x%x, ofst_metadata_valid=%d, len=0x%x",
		ep_hdr->hdr_ofst_metadata,
		ep_hdr->hdr_ofst_metadata_valid,
		ep_hdr->hdr_len);

	ep = &ipa3_ctx->ep[clnt_hdl];

	/* copy over EP cfg */
	ep->cfg.hdr = *ep_hdr;

	IPA_ACTIVE_CLIENTS_INC_EP(ipa3_get_client_mapping(clnt_hdl));

	ipahal_write_reg_n_fields(IPA_ENDP_INIT_HDR_n, clnt_hdl, &ep->cfg.hdr);

	IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));

	return 0;
}

/**
 * ipa3_cfg_ep_hdr_ext() -  IPA end-point extended header configuration
 * @clnt_hdl:	[in] opaque client handle assigned by IPA to client
 * @ep_hdr_ext:	[in] IPA end-point configuration params
 *
 * Returns:	0 on success, negative on failure
 *
 * Note:	Should not be called from atomic context
 */
int ipa3_cfg_ep_hdr_ext(u32 clnt_hdl,
		       const struct ipa_ep_cfg_hdr_ext *ep_hdr_ext)
{
	struct ipa3_ep_context *ep;

	if (!client_handle_valid(clnt_hdl))
		return -EINVAL;

	ipa_debug("pipe=%d hdr_pad_to_alignment=%d\n",
		clnt_hdl,
		ep_hdr_ext->hdr_pad_to_alignment);

	ipa_debug("hdr_total_len_or_pad_offset=%d\n",
		ep_hdr_ext->hdr_total_len_or_pad_offset);

	ipa_debug("hdr_payload_len_inc_padding=%d hdr_total_len_or_pad=%d\n",
		ep_hdr_ext->hdr_payload_len_inc_padding,
		ep_hdr_ext->hdr_total_len_or_pad);

	ipa_debug("hdr_total_len_or_pad_valid=%d hdr_little_endian=%d\n",
		ep_hdr_ext->hdr_total_len_or_pad_valid,
		ep_hdr_ext->hdr_little_endian);

	ep = &ipa3_ctx->ep[clnt_hdl];

	/* copy over EP cfg */
	ep->cfg.hdr_ext = *ep_hdr_ext;

	IPA_ACTIVE_CLIENTS_INC_EP(ipa3_get_client_mapping(clnt_hdl));

	ipahal_write_reg_n_fields(IPA_ENDP_INIT_HDR_EXT_n, clnt_hdl,
		&ep->cfg.hdr_ext);

	IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));

	return 0;
}

/**
 * ipa3_cfg_ep_ctrl() -  IPA end-point Control configuration
 * @clnt_hdl:	[in] opaque client handle assigned by IPA to client
 * @ipa_ep_cfg_ctrl:	[in] IPA end-point configuration params
 *
 * Returns:	0 on success, negative on failure
 */
int ipa3_cfg_ep_ctrl(u32 clnt_hdl, const struct ipa_ep_cfg_ctrl *ep_ctrl)
{
	if (clnt_hdl >= ipa3_ctx->ipa_num_pipes) {
		ipa_err("bad parm, clnt_hdl = %d\n", clnt_hdl);
		return -EINVAL;
	}

	ipa_debug("pipe=%d ep_suspend=%d, ep_delay=%d\n",
		clnt_hdl,
		ep_ctrl->ipa_ep_suspend,
		ep_ctrl->ipa_ep_delay);

	ipahal_write_reg_n_fields(IPA_ENDP_INIT_CTRL_n, clnt_hdl, ep_ctrl);

	if (ep_ctrl->ipa_ep_suspend == true &&
			IPA_CLIENT_IS_CONS(ipa3_ctx->ep[clnt_hdl].client))
		ipa3_suspend_active_aggr_wa(clnt_hdl);

	return 0;
}

/**
 * ipa3_cfg_ep_holb() - IPA end-point holb configuration
 *
 * If an IPA producer pipe is full, IPA HW by default will block
 * indefinitely till space opens up. During this time no packets
 * including those from unrelated pipes will be processed. Enabling
 * HOLB means IPA HW will be allowed to drop packets as/when needed
 * and indefinite blocking is avoided.
 *
 * @clnt_hdl:	[in] opaque client handle assigned by IPA to client
 * @ipa_ep_cfg:	[in] IPA end-point configuration params
 *
 * Returns:	0 on success, negative on failure
 */
int ipa3_cfg_ep_holb(u32 clnt_hdl, const struct ipa_ep_cfg_holb *ep_holb)
{
	if (!client_handle_valid(clnt_hdl))
		return -EINVAL;

	if (ep_holb->tmr_val > ipa3_ctx->ctrl->max_holb_tmr_val ||
	    ep_holb->en > 1) {
		ipa_err("bad parm.\n");
		return -EINVAL;
	}

	if (IPA_CLIENT_IS_PROD(ipa3_ctx->ep[clnt_hdl].client)) {
		ipa_err("HOLB does not apply to IPA in EP %d\n", clnt_hdl);
		return -EINVAL;
	}

	ipa3_ctx->ep[clnt_hdl].holb = *ep_holb;

	IPA_ACTIVE_CLIENTS_INC_EP(ipa3_get_client_mapping(clnt_hdl));

	ipahal_write_reg_n_fields(IPA_ENDP_INIT_HOL_BLOCK_EN_n, clnt_hdl,
		ep_holb);

	ipahal_write_reg_n_fields(IPA_ENDP_INIT_HOL_BLOCK_TIMER_n, clnt_hdl,
		ep_holb);

	IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));

	ipa_debug("cfg holb %u ep=%d tmr=%d\n", ep_holb->en, clnt_hdl,
				ep_holb->tmr_val);

	return 0;
}

/**
 * ipa3_cfg_ep_metadata() - IPA end-point metadata configuration
 * @clnt_hdl:	[in] opaque client handle assigned by IPA to client
 * @ipa_ep_cfg:	[in] IPA end-point configuration params
 *
 * Returns:	0 on success, negative on failure
 *
 * Note:	Should not be called from atomic context
 */
int ipa3_cfg_ep_metadata(u32 clnt_hdl, const struct ipa_ep_cfg_metadata *ep_md)
{
	u32 qmap_id = 0;
	struct ipa_ep_cfg_metadata ep_md_reg_wrt;

	if (!client_handle_valid(clnt_hdl))
		return -EINVAL;

	ipa_debug("pipe=%d, mux id=%d\n", clnt_hdl, ep_md->qmap_id);

	/* copy over EP cfg */
	ipa3_ctx->ep[clnt_hdl].cfg.meta = *ep_md;

	IPA_ACTIVE_CLIENTS_INC_EP(ipa3_get_client_mapping(clnt_hdl));

	ep_md_reg_wrt = *ep_md;
	qmap_id = (ep_md->qmap_id <<
		IPA_ENDP_INIT_HDR_METADATA_n_MUX_ID_SHFT) &
		IPA_ENDP_INIT_HDR_METADATA_n_MUX_ID_BMASK;

	ep_md_reg_wrt.qmap_id = qmap_id;
	ipahal_write_reg_n_fields(IPA_ENDP_INIT_HDR_METADATA_n, clnt_hdl,
		&ep_md_reg_wrt);
	ipa3_ctx->ep[clnt_hdl].cfg.hdr.hdr_metadata_reg_valid = 1;
	ipahal_write_reg_n_fields(IPA_ENDP_INIT_HDR_n, clnt_hdl,
		&ipa3_ctx->ep[clnt_hdl].cfg.hdr);

	IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));

	return 0;
}


/**
 * ipa3_dump_buff_internal() - dumps buffer for debug purposes
 * @base: buffer base address
 * @phy_base: buffer physical base address
 * @size: size of the buffer
 */
void ipa3_dump_buff_internal(void *base, dma_addr_t phy_base, u32 size)
{
	int i;
	u32 *cur = (u32 *)base;
	u8 *byt;

	ipa_debug("system phys addr=%pa len=%u\n", &phy_base, size);
	for (i = 0; i < size / 4; i++) {
		byt = (u8 *)(cur + i);
		ipa_debug("%2d %08x   %02x %02x %02x %02x\n", i, *(cur + i),
				byt[0], byt[1], byt[2], byt[3]);
	}
	ipa_debug("END\n");
}

/**
 * ipa3_set_aggr_mode() - Set the aggregation mode which is a global setting
 * @mode:	[in] the desired aggregation mode for e.g. straight MBIM, QCNCM,
 * etc
 *
 * Returns:	0 on success
 */
int ipa3_set_aggr_mode(enum ipa_aggr_mode mode)
{
	struct ipahal_reg_qcncm qcncm;

	IPA_ACTIVE_CLIENTS_INC_SIMPLE();
	ipahal_read_reg_fields(IPA_QCNCM, &qcncm);
	qcncm.mode_en = mode;
	ipahal_write_reg_fields(IPA_QCNCM, &qcncm);
	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();

	return 0;
}

/**
 * ipa3_straddle_boundary() - Checks whether a memory buffer straddles a
 * boundary
 * @start: start address of the memory buffer
 * @end: end address of the memory buffer
 * @boundary: boundary
 *
 * Return value:
 * 1: if the interval [start, end] straddles boundary
 * 0: otherwise
 */
int ipa3_straddle_boundary(u32 start, u32 end, u32 boundary)
{
	u32 next_start;
	u32 prev_end;

	ipa_debug("start=%u end=%u boundary=%u\n", start, end, boundary);

	next_start = (start + (boundary - 1)) & ~(boundary - 1);
	prev_end = ((end + (boundary - 1)) & ~(boundary - 1)) - boundary;

	while (next_start < prev_end)
		next_start += boundary;

	if (next_start == prev_end)
		return 1;
	else
		return 0;
}

#define IPA_MEM_OFST_START			0x280
#define IPA_MEM_NAT_OFST			0x0
#define IPA_MEM_NAT_SIZE			0x0
#define IPA_MEM_V4_FLT_HASH_OFST		0x288
#define IPA_MEM_V4_FLT_HASH_OFST_ALIGN		8
#define IPA_MEM_V4_FLT_HASH_SIZE		0x78
#define IPA_MEM_V4_FLT_HASH_SIZE_DDR		0x4000
#define IPA_MEM_V4_FLT_NHASH_OFST		0x308
#define IPA_MEM_V4_FLT_NHASH_OFST_ALIGN		8
#define IPA_MEM_V4_FLT_NHASH_SIZE		0x78
#define IPA_MEM_V4_FLT_NHASH_SIZE_DDR		0x4000
#define IPA_MEM_V6_FLT_HASH_OFST		0x388
#define IPA_MEM_V6_FLT_HASH_OFST_ALIGN		8
#define IPA_MEM_V6_FLT_HASH_SIZE		0x78
#define IPA_MEM_V6_FLT_HASH_SIZE_DDR		0x4000
#define IPA_MEM_V6_FLT_NHASH_OFST		0x408
#define IPA_MEM_V6_FLT_NHASH_OFST_ALIGN		8
#define IPA_MEM_V6_FLT_NHASH_SIZE		0x78
#define IPA_MEM_V6_FLT_NHASH_SIZE_DDR		0x4000
#define IPA_MEM_V4_RT_NUM_INDEX			0xf
#define IPA_MEM_V4_MODEM_RT_INDEX_LO		0x0
#define IPA_MEM_V4_MODEM_RT_INDEX_HI		0x7
#define IPA_MEM_V4_APPS_RT_INDEX_LO		0x8
#define IPA_MEM_V4_APPS_RT_INDEX_HI		0xe
#define IPA_MEM_V4_RT_HASH_OFST			0x488
#define IPA_MEM_V4_RT_HASH_OFST_ALIGN		8
#define IPA_MEM_V4_RT_HASH_SIZE			0x78
#define IPA_MEM_V4_RT_HASH_SIZE_DDR		0x4000
#define IPA_MEM_V4_RT_NHASH_OFST		0x508
#define IPA_MEM_V4_RT_NHASH_OFST_ALIGN		8
#define IPA_MEM_V4_RT_NHASH_SIZE		0x78
#define IPA_MEM_V4_RT_NHASH_SIZE_DDR		0x4000
#define IPA_MEM_V6_RT_NUM_INDEX			0xf
#define IPA_MEM_V6_MODEM_RT_INDEX_LO		0x0
#define IPA_MEM_V6_MODEM_RT_INDEX_HI		0x7
#define IPA_MEM_V6_APPS_RT_INDEX_LO		0x8
#define IPA_MEM_V6_APPS_RT_INDEX_HI		0xe
#define IPA_MEM_V6_RT_HASH_OFST			0x588
#define IPA_MEM_V6_RT_HASH_OFST_ALIGN		8
#define IPA_MEM_V6_RT_HASH_SIZE			0x78
#define IPA_MEM_V6_RT_HASH_SIZE_DDR		0x4000
#define IPA_MEM_V6_RT_NHASH_OFST		0x608
#define IPA_MEM_V6_RT_NHASH_OFST_ALIGN		8
#define IPA_MEM_V6_RT_NHASH_SIZE		0x78
#define IPA_MEM_V6_RT_NHASH_SIZE_DDR		0x4000
#define IPA_MEM_MODEM_HDR_OFST			0x688
#define IPA_MEM_MODEM_HDR_OFST_ALIGN		8
#define IPA_MEM_MODEM_HDR_SIZE			140
#define IPA_MEM_APPS_HDR_OFST			0x7c8
#define IPA_MEM_APPS_HDR_OFST_ALIGN		8
#define IPA_MEM_APPS_HDR_SIZE			0x0
#define IPA_MEM_APPS_HDR_SIZE_DDR		0x800
#define IPA_MEM_MODEM_HDR_PROC_CTX_OFST		0x7d0
#define IPA_MEM_MODEM_HDR_PROC_CTX_OFST_ALIGN	8
#define IPA_MEM_MODEM_HDR_PROC_CTX_SIZE		0x200
#define IPA_MEM_APPS_HDR_PROC_CTX_OFST		0x9d0
#define IPA_MEM_APPS_HDR_PROC_CTX_OFST_ALIGN	8
#define IPA_MEM_APPS_HDR_PROC_CTX_SIZE		0x200
#define IPA_MEM_APPS_HDR_PROC_CTX_SIZE_DDR	0x0
#define IPA_MEM_MODEM_COMP_DECOMP_OFST		0x0
#define IPA_MEM_MODEM_COMP_DECOMP_SIZE		0x0
#define IPA_MEM_MODEM_OFST			0xbd8
#define IPA_MEM_MODEM_OFST_ALIGN		8
#define IPA_MEM_MODEM_SIZE			0x1024
#define IPA_MEM_APPS_V4_FLT_HASH_OFST		0x2000
#define IPA_MEM_APPS_V4_FLT_HASH_SIZE		0x0
#define IPA_MEM_APPS_V4_FLT_NHASH_OFST		0x2000
#define IPA_MEM_APPS_V4_FLT_NHASH_SIZE		0x0
#define IPA_MEM_APPS_V6_FLT_HASH_OFST		0x2000
#define IPA_MEM_APPS_V6_FLT_HASH_SIZE		0x0
#define IPA_MEM_APPS_V6_FLT_NHASH_OFST		0x2000
#define IPA_MEM_APPS_V6_FLT_NHASH_SIZE		0x0
#define IPA_MEM_UC_INFO_OFST			0x80
#define IPA_MEM_UC_INFO_OFST_ALIGN		4
#define IPA_MEM_UC_INFO_SIZE			0x200
#define IPA_MEM_END_OFST			0x2000
#define IPA_MEM_APPS_V4_RT_HASH_OFST		0x2000
#define IPA_MEM_APPS_V4_RT_NHASH_OFST		0x2000
#define IPA_MEM_APPS_V4_RT_NHASH_SIZE		0x0
#define IPA_MEM_APPS_V6_RT_HASH_OFST		0x2000
#define IPA_MEM_APPS_V6_RT_HASH_SIZE		0x0
#define IPA_MEM_APPS_V6_RT_NHASH_OFST		0x2000
#define IPA_MEM_APPS_V6_RT_NHASH_SIZE		0x0
#define IPA_MEM_UC_EVENT_RING_OFST		0x1c00
#define IPA_MEM_UC_EVENT_RING_OFST_ALIGN	1024
#define IPA_MEM_UC_EVENT_RING_SIZE		0x400
#define IPA_MEM_PDN_CONFIG_OFST			0x0
#define IPA_MEM_PDN_CONFIG_OFST_ALIGN		8
#define IPA_MEM_PDN_CONFIG_SIZE			0x0
#define IPA_MEM_STATS_QUOTA_OFST		0x0
#define IPA_MEM_STATS_QUOTA_SIZE		0x0
#define IPA_MEM_STATS_TETHERING_OFST		0x0
#define IPA_MEM_STATS_TETHERING_SIZE		0x0
#define IPA_MEM_STATS_FLT_V4_OFST		0x0
#define IPA_MEM_STATS_FLT_V4_SIZE		0x0
#define IPA_MEM_STATS_FLT_V6_OFST		0x0
#define IPA_MEM_STATS_FLT_V6_SIZE		0x0
#define IPA_MEM_STATS_RT_V4_OFST		0x0
#define IPA_MEM_STATS_RT_V4_SIZE		0x0
#define IPA_MEM_STATS_RT_V6_OFST		0x0
#define IPA_MEM_STATS_RT_V6_SIZE		0x0
#define IPA_MEM_STATS_DROP_OFST			0x0
#define IPA_MEM_STATS_DROP_SIZE			0x0

#define ALIGN_CHECK(name)	BUILD_BUG_ON(name % name ## _ALIGN)
#define NONZERO_CHECK(name)	BUILD_BUG_ON(!name)
#define LO_HI_CHECK(name)	BUILD_BUG_ON(name ## _LO > name ## _HI)
static int mem_partition_valid(void)
{
	/* Verify what we can at compile time */

	ALIGN_CHECK(IPA_MEM_V4_FLT_HASH_OFST);
	ALIGN_CHECK(IPA_MEM_V4_FLT_NHASH_OFST);
	ALIGN_CHECK(IPA_MEM_V6_FLT_HASH_OFST);
	ALIGN_CHECK(IPA_MEM_V6_FLT_NHASH_OFST);
	ALIGN_CHECK(IPA_MEM_V4_RT_HASH_OFST);
	ALIGN_CHECK(IPA_MEM_V4_RT_NHASH_OFST);
	ALIGN_CHECK(IPA_MEM_V6_RT_HASH_OFST);
	ALIGN_CHECK(IPA_MEM_V6_RT_NHASH_OFST);
	ALIGN_CHECK(IPA_MEM_MODEM_HDR_OFST);
	ALIGN_CHECK(IPA_MEM_APPS_HDR_OFST);
	ALIGN_CHECK(IPA_MEM_MODEM_HDR_PROC_CTX_OFST);
	ALIGN_CHECK(IPA_MEM_PDN_CONFIG_OFST);
	ALIGN_CHECK(IPA_MEM_UC_EVENT_RING_OFST);
	ALIGN_CHECK(IPA_MEM_APPS_HDR_PROC_CTX_OFST);
	ALIGN_CHECK(IPA_MEM_MODEM_OFST);
	ALIGN_CHECK(IPA_MEM_UC_INFO_OFST);

	NONZERO_CHECK(IPA_MEM_V4_FLT_HASH_SIZE);
	NONZERO_CHECK(IPA_MEM_V4_FLT_NHASH_SIZE);
	NONZERO_CHECK(IPA_MEM_V4_RT_NUM_INDEX);
	NONZERO_CHECK(IPA_MEM_V4_RT_HASH_SIZE);
	NONZERO_CHECK(IPA_MEM_V4_RT_NHASH_SIZE);
	NONZERO_CHECK(IPA_MEM_V6_FLT_HASH_SIZE);
	NONZERO_CHECK(IPA_MEM_V6_FLT_NHASH_SIZE);
	NONZERO_CHECK(IPA_MEM_V6_RT_NUM_INDEX);
	NONZERO_CHECK(IPA_MEM_V6_RT_HASH_SIZE);
	NONZERO_CHECK(IPA_MEM_V6_RT_NHASH_SIZE);

	LO_HI_CHECK(IPA_MEM_V4_MODEM_RT_INDEX);
	LO_HI_CHECK(IPA_MEM_V6_MODEM_RT_INDEX);

	return 0;
}
#undef LO_HI_CHECK
#undef NONZERO_CHECK
#undef ALIGN_CHECK

/**
 * ipa3_init_mem_partition() - Reads IPA memory map from DTS, performs alignment
 * checks and logs the fetched values.
 *
 * Returns:	0 on success
 */
int ipa3_init_mem_partition(struct device_node *node)
{
	u32 *mem = &ipa3_ctx->ctrl->mem_partition[0];

	memset(mem, 0, sizeof(ipa3_ctx->ctrl->mem_partition));

	mem[OFST_START] = IPA_MEM_OFST_START;
	ipa_debug("RAM OFST 0x%x\n", mem[OFST_START]);

	mem[NAT_OFST] = IPA_MEM_NAT_OFST;
	mem[NAT_SIZE] = IPA_MEM_NAT_SIZE;
	ipa_debug("NAT OFST 0x%x SIZE 0x%x\n", mem[NAT_OFST], mem[NAT_SIZE]);

	mem[V4_FLT_HASH_OFST] = IPA_MEM_V4_FLT_HASH_OFST;
	mem[V4_FLT_HASH_SIZE] = IPA_MEM_V4_FLT_HASH_SIZE;
	mem[V4_FLT_HASH_SIZE_DDR] = IPA_MEM_V4_FLT_HASH_SIZE_DDR;
	ipa_debug("V4 FLT HASHABLE OFST 0x%x SIZE 0x%x DDR SIZE 0x%x\n",
		mem[V4_FLT_HASH_OFST],
		mem[V4_FLT_HASH_SIZE],
		mem[V4_FLT_HASH_SIZE_DDR]);

	mem[V4_FLT_NHASH_OFST] = IPA_MEM_V4_FLT_NHASH_OFST;
	mem[V4_FLT_NHASH_SIZE] = IPA_MEM_V4_FLT_NHASH_SIZE;
	mem[V4_FLT_NHASH_SIZE_DDR] = IPA_MEM_V4_FLT_NHASH_SIZE_DDR;
	ipa_debug("V4 FLT NON-HASHABLE OFST 0x%x SIZE 0x%x DDR SIZE 0x%x\n",
		mem[V4_FLT_NHASH_OFST],
		mem[V4_FLT_NHASH_SIZE],
		mem[V4_FLT_NHASH_SIZE_DDR]);

	mem[V6_FLT_HASH_OFST] = IPA_MEM_V6_FLT_HASH_OFST;
	mem[V6_FLT_HASH_SIZE] = IPA_MEM_V6_FLT_HASH_SIZE;
	mem[V6_FLT_HASH_SIZE_DDR] = IPA_MEM_V6_FLT_HASH_SIZE_DDR;
	ipa_debug("V6 FLT HASHABLE OFST 0x%x SIZE 0x%x DDR SIZE 0x%x\n",
		mem[V6_FLT_HASH_OFST], mem[V6_FLT_HASH_SIZE],
		mem[V6_FLT_HASH_SIZE_DDR]);

	mem[V6_FLT_NHASH_OFST] = IPA_MEM_V6_FLT_NHASH_OFST;
	mem[V6_FLT_NHASH_SIZE] = IPA_MEM_V6_FLT_NHASH_SIZE;
	mem[V6_FLT_NHASH_SIZE_DDR] = IPA_MEM_V6_FLT_NHASH_SIZE_DDR;
	ipa_debug("V6 FLT NON-HASHABLE OFST 0x%x SIZE 0x%x DDR SIZE 0x%x\n",
		mem[V6_FLT_NHASH_OFST],
		mem[V6_FLT_NHASH_SIZE],
		mem[V6_FLT_NHASH_SIZE_DDR]);

	mem[V4_RT_NUM_INDEX] = IPA_MEM_V4_RT_NUM_INDEX;
	ipa_debug("V4 RT NUM INDEX 0x%x\n", mem[V4_RT_NUM_INDEX]);

	mem[V4_MODEM_RT_INDEX_LO] = IPA_MEM_V4_MODEM_RT_INDEX_LO;
	mem[V4_MODEM_RT_INDEX_HI] = IPA_MEM_V4_MODEM_RT_INDEX_HI;
	ipa_debug("V4 RT MODEM INDEXES 0x%x - 0x%x\n",
		mem[V4_MODEM_RT_INDEX_LO],
		mem[V4_MODEM_RT_INDEX_HI]);

	mem[V4_APPS_RT_INDEX_LO] = IPA_MEM_V4_APPS_RT_INDEX_LO;
	mem[V4_APPS_RT_INDEX_HI] = IPA_MEM_V4_APPS_RT_INDEX_HI;
	ipa_debug("V4 RT APPS INDEXES 0x%x - 0x%x\n",
		mem[V4_APPS_RT_INDEX_LO],
		mem[V4_APPS_RT_INDEX_HI]);

	mem[V4_RT_HASH_OFST] = IPA_MEM_V4_RT_HASH_OFST;
	mem[V4_RT_HASH_SIZE] = IPA_MEM_V4_RT_HASH_SIZE;
	mem[V4_RT_HASH_SIZE_DDR] = IPA_MEM_V4_RT_HASH_SIZE_DDR;
	ipa_debug("V4 RT HASHABLE OFST 0x%x SIZE 0x%x DDR SIZE 0x%x\n",
		mem[V4_RT_HASH_OFST],
		mem[V4_RT_HASH_SIZE],
		mem[V4_RT_HASH_SIZE_DDR]);

	mem[V4_RT_NHASH_OFST] = IPA_MEM_V4_RT_NHASH_OFST;
	mem[V4_RT_NHASH_SIZE] = IPA_MEM_V4_RT_NHASH_SIZE;
	mem[V4_RT_NHASH_SIZE_DDR] = IPA_MEM_V4_RT_NHASH_SIZE_DDR;
	ipa_debug("V4 RT NON-HASHABLE OFST 0x%x SIZE 0x%x DDR SIZE 0x%x\n",
		mem[V4_RT_NHASH_OFST],
		mem[V4_RT_NHASH_SIZE],
		mem[V4_RT_NHASH_SIZE_DDR]);

	mem[V6_RT_NUM_INDEX] = IPA_MEM_V6_RT_NUM_INDEX;
	ipa_debug("V6 RT NUM INDEX 0x%x\n", mem[V6_RT_NUM_INDEX]);

	mem[V6_MODEM_RT_INDEX_LO] = IPA_MEM_V6_MODEM_RT_INDEX_LO;
	mem[V6_MODEM_RT_INDEX_HI] = IPA_MEM_V6_MODEM_RT_INDEX_HI;
	ipa_debug("V6 RT MODEM INDEXES 0x%x - 0x%x\n",
		mem[V6_MODEM_RT_INDEX_LO],
		mem[V6_MODEM_RT_INDEX_HI]);

	mem[V6_APPS_RT_INDEX_LO] = IPA_MEM_V6_APPS_RT_INDEX_LO;
	mem[V6_APPS_RT_INDEX_HI] = IPA_MEM_V6_APPS_RT_INDEX_HI;
	ipa_debug("V6 RT APPS INDEXES 0x%x - 0x%x\n",
		mem[V6_APPS_RT_INDEX_LO],
		mem[V6_APPS_RT_INDEX_HI]);

	mem[V6_RT_HASH_OFST] = IPA_MEM_V6_RT_HASH_OFST;
	mem[V6_RT_HASH_SIZE] = IPA_MEM_V6_RT_HASH_SIZE;
	mem[V6_RT_HASH_SIZE_DDR] = IPA_MEM_V6_RT_HASH_SIZE_DDR;
	ipa_debug("V6 RT HASHABLE OFST 0x%x SIZE 0x%x DDR SIZE 0x%x\n",
		mem[V6_RT_HASH_OFST],
		mem[V6_RT_HASH_SIZE],
		mem[V6_RT_HASH_SIZE_DDR]);

	mem[V6_RT_NHASH_OFST] = IPA_MEM_V6_RT_NHASH_OFST;
	mem[V6_RT_NHASH_SIZE] = IPA_MEM_V6_RT_NHASH_SIZE;
	mem[V6_RT_NHASH_SIZE_DDR] = IPA_MEM_V6_RT_NHASH_SIZE_DDR;
	ipa_debug("V6 RT NON-HASHABLE OFST 0x%x SIZE 0x%x DDR SIZE 0x%x\n",
		mem[V6_RT_NHASH_OFST],
		mem[V6_RT_NHASH_SIZE],
		mem[V6_RT_NHASH_SIZE_DDR]);

	mem[MODEM_HDR_OFST] = IPA_MEM_MODEM_HDR_OFST;
	mem[MODEM_HDR_SIZE] = IPA_MEM_MODEM_HDR_SIZE;
	ipa_debug("MODEM HDR OFST 0x%x SIZE 0x%x\n",
		mem[MODEM_HDR_OFST],
		mem[MODEM_HDR_SIZE]);

	mem[APPS_HDR_OFST] = IPA_MEM_APPS_HDR_OFST;
	mem[APPS_HDR_SIZE] = IPA_MEM_APPS_HDR_SIZE;
	mem[APPS_HDR_SIZE_DDR] = IPA_MEM_APPS_HDR_SIZE_DDR;
	ipa_debug("APPS HDR OFST 0x%x SIZE 0x%x DDR SIZE 0x%x\n",
		mem[APPS_HDR_OFST],
		mem[APPS_HDR_SIZE],
		mem[APPS_HDR_SIZE_DDR]);

	mem[MODEM_HDR_PROC_CTX_OFST] = IPA_MEM_MODEM_HDR_PROC_CTX_OFST;
	mem[MODEM_HDR_PROC_CTX_SIZE] = IPA_MEM_MODEM_HDR_PROC_CTX_SIZE;
	ipa_debug("MODEM HDR PROC CTX OFST 0x%x SIZE 0x%x\n",
		mem[MODEM_HDR_PROC_CTX_OFST],
		mem[MODEM_HDR_PROC_CTX_SIZE]);

	mem[APPS_HDR_PROC_CTX_OFST] = IPA_MEM_APPS_HDR_PROC_CTX_OFST;
	mem[APPS_HDR_PROC_CTX_SIZE] = IPA_MEM_APPS_HDR_PROC_CTX_SIZE;
	mem[APPS_HDR_PROC_CTX_SIZE_DDR] =
			IPA_MEM_APPS_HDR_PROC_CTX_SIZE_DDR;
	ipa_debug("APPS HDR PROC CTX OFST 0x%x SIZE 0x%x DDR SIZE 0x%x\n",
		mem[APPS_HDR_PROC_CTX_OFST],
		mem[APPS_HDR_PROC_CTX_SIZE],
		mem[APPS_HDR_PROC_CTX_SIZE_DDR]);

	mem[MODEM_COMP_DECOMP_OFST] = IPA_MEM_MODEM_COMP_DECOMP_OFST;
	mem[MODEM_COMP_DECOMP_SIZE] = IPA_MEM_MODEM_COMP_DECOMP_SIZE;

	mem[MODEM_OFST] = IPA_MEM_MODEM_OFST;
	mem[MODEM_SIZE] = IPA_MEM_MODEM_SIZE;
	ipa_debug("MODEM OFST 0x%x SIZE 0x%x\n",
		mem[MODEM_OFST],
		mem[MODEM_SIZE]);

	mem[APPS_V4_FLT_HASH_OFST] = IPA_MEM_APPS_V4_FLT_HASH_OFST;
	mem[APPS_V4_FLT_HASH_SIZE] = IPA_MEM_APPS_V4_FLT_HASH_SIZE;
	ipa_debug("V4 APPS HASHABLE FLT OFST 0x%x SIZE 0x%x\n",
		mem[APPS_V4_FLT_HASH_OFST],
		mem[APPS_V4_FLT_HASH_SIZE]);

	mem[APPS_V4_FLT_NHASH_OFST] = IPA_MEM_APPS_V4_FLT_NHASH_OFST;
	mem[APPS_V4_FLT_NHASH_SIZE] = IPA_MEM_APPS_V4_FLT_NHASH_SIZE;
	ipa_debug("V4 APPS NON-HASHABLE FLT OFST 0x%x SIZE 0x%x\n",
		mem[APPS_V4_FLT_NHASH_OFST],
		mem[APPS_V4_FLT_NHASH_SIZE]);

	mem[APPS_V6_FLT_HASH_OFST] = IPA_MEM_APPS_V6_FLT_HASH_OFST;
	mem[APPS_V6_FLT_HASH_SIZE] = IPA_MEM_APPS_V6_FLT_HASH_SIZE;
	ipa_debug("V6 APPS HASHABLE FLT OFST 0x%x SIZE 0x%x\n",
		mem[APPS_V6_FLT_HASH_OFST],
		mem[APPS_V6_FLT_HASH_SIZE]);

	mem[APPS_V6_FLT_NHASH_OFST] = IPA_MEM_APPS_V6_FLT_NHASH_OFST;
	mem[APPS_V6_FLT_NHASH_SIZE] = IPA_MEM_APPS_V6_FLT_NHASH_SIZE;
	ipa_debug("V6 APPS NON-HASHABLE FLT OFST 0x%x SIZE 0x%x\n",
		mem[APPS_V6_FLT_NHASH_OFST],
		mem[APPS_V6_FLT_NHASH_SIZE]);

	mem[UC_INFO_OFST] = IPA_MEM_UC_INFO_OFST;
	mem[UC_INFO_SIZE] = IPA_MEM_UC_INFO_SIZE;
	ipa_debug("UC INFO OFST 0x%x SIZE 0x%x\n",
		mem[UC_INFO_OFST], mem[UC_INFO_SIZE]);

	mem[END_OFST] = IPA_MEM_END_OFST;
	ipa_debug("RAM END OFST 0x%x\n",
		mem[END_OFST]);

	mem[APPS_V4_RT_HASH_OFST] = IPA_MEM_APPS_V4_RT_HASH_OFST;
	ipa_debug("V4 APPS HASHABLE RT OFST 0x%x SIZE 0x%x\n",
		mem[APPS_V4_RT_HASH_OFST],
		mem[APPS_V4_RT_HASH_SIZE]);

	mem[APPS_V4_RT_NHASH_OFST] = IPA_MEM_APPS_V4_RT_NHASH_OFST;
	mem[APPS_V4_RT_NHASH_SIZE] = IPA_MEM_APPS_V4_RT_NHASH_SIZE;
	ipa_debug("V4 APPS NON-HASHABLE RT OFST 0x%x SIZE 0x%x\n",
		mem[APPS_V4_RT_NHASH_OFST],
		mem[APPS_V4_RT_NHASH_SIZE]);

	mem[APPS_V6_RT_HASH_OFST] = IPA_MEM_APPS_V6_RT_HASH_OFST;
	mem[APPS_V6_RT_HASH_SIZE] = IPA_MEM_APPS_V6_RT_HASH_SIZE;
	ipa_debug("V6 APPS HASHABLE RT OFST 0x%x SIZE 0x%x\n",
		mem[APPS_V6_RT_HASH_OFST],
		mem[APPS_V6_RT_HASH_SIZE]);

	mem[APPS_V6_RT_NHASH_OFST] = IPA_MEM_APPS_V6_RT_NHASH_OFST;
	mem[APPS_V6_RT_NHASH_SIZE] = IPA_MEM_APPS_V6_RT_NHASH_SIZE;
	ipa_debug("V6 APPS NON-HASHABLE RT OFST 0x%x SIZE 0x%x\n",
		mem[APPS_V6_RT_NHASH_OFST],
		mem[APPS_V6_RT_NHASH_SIZE]);

	mem[UC_EVENT_RING_OFST] = IPA_MEM_UC_EVENT_RING_OFST;
	mem[UC_EVENT_RING_SIZE] = IPA_MEM_UC_EVENT_RING_SIZE;
	ipa_debug("UC EVENT RING OFST 0x%x SIZE 0x%x\n",
		mem[UC_EVENT_RING_OFST],
		mem[UC_EVENT_RING_SIZE]);

	/* End of fields supported for SDM670 and SDM845 */

	mem[PDN_CONFIG_OFST] = IPA_MEM_PDN_CONFIG_OFST;
	ipa_debug("PDN CONFIG OFST 0x%x SIZE 0x%x\n",
		mem[PDN_CONFIG_OFST],
		mem[PDN_CONFIG_SIZE]);

	mem[PDN_CONFIG_SIZE] = IPA_MEM_PDN_CONFIG_SIZE;
	mem[STATS_QUOTA_OFST] = IPA_MEM_STATS_QUOTA_OFST;
	mem[STATS_QUOTA_SIZE] = IPA_MEM_STATS_QUOTA_SIZE;
	mem[STATS_TETHERING_OFST] = IPA_MEM_STATS_TETHERING_OFST;
	mem[STATS_TETHERING_SIZE] = IPA_MEM_STATS_TETHERING_SIZE;
	mem[STATS_FLT_V4_OFST] = IPA_MEM_STATS_FLT_V4_OFST;
	mem[STATS_FLT_V4_SIZE] = IPA_MEM_STATS_FLT_V4_SIZE;
	mem[STATS_FLT_V6_OFST] = IPA_MEM_STATS_DROP_SIZE;
	mem[STATS_FLT_V6_SIZE] = IPA_MEM_STATS_FLT_V6_OFST;
	mem[STATS_RT_V4_OFST] = IPA_MEM_STATS_FLT_V6_SIZE;
	mem[STATS_RT_V4_SIZE] = IPA_MEM_STATS_RT_V4_OFST;
	mem[STATS_RT_V6_OFST] = IPA_MEM_STATS_RT_V4_SIZE;
	mem[STATS_RT_V6_SIZE] = IPA_MEM_STATS_RT_V6_OFST;
	mem[STATS_DROP_OFST] = IPA_MEM_STATS_RT_V6_SIZE;
	mem[STATS_DROP_SIZE] = IPA_MEM_STATS_DROP_OFST;

	return mem_partition_valid();
}

static struct ipa3_controller ipa_controller_v3 = {
	.ipa_init_rt4		= _ipa_init_rt4_v3,
	.ipa_init_rt6		= _ipa_init_rt6_v3,
	.ipa_init_flt4		= _ipa_init_flt4_v3,
	.ipa_init_flt6		= _ipa_init_flt6_v3,
	.ipa3_read_ep_reg	= _ipa_read_ep_reg_v3_0,
	.ipa3_enable_clks	= _ipa_enable_clks_v3_0,
	.ipa3_disable_clks	= _ipa_disable_clks_v3_0,
	.msm_bus_data_ptr	= &ipa_bus_client_pdata_v3_0,
	.clock_scaling_bw_threshold_nominal =
				IPA_V3_0_BW_THRESHOLD_NOMINAL_MBPS,
	.clock_scaling_bw_threshold_turbo =
				IPA_V3_0_BW_THRESHOLD_TURBO_MBPS,
	.ipa_reg_base_ofst	= IPA_REG_BASE_OFFSET,
	.ipa_init_sram		= _ipa_init_sram_v3,
	.ipa_sram_read_settings	= _ipa_sram_settings_read_v3_0,
	.ipa_init_hdr		= _ipa_init_hdr_v3_0,
};

u32 ipa3_mem(enum ipa3_mem_partition index)
{
	return ipa3_ctx->ctrl->mem_partition[index];
}

/**
 * ipa_controller_init() - return the appropriate methods for IPA Driver
 */
struct ipa3_controller *ipa3_controller_init(void)
{
	return &ipa_controller_v3;
}

void ipa3_skb_recycle(struct sk_buff *skb)
{
	struct skb_shared_info *shinfo;

	shinfo = skb_shinfo(skb);
	memset(shinfo, 0, offsetof(struct skb_shared_info, dataref));
	atomic_set(&shinfo->dataref, 1);

	memset(skb, 0, offsetof(struct sk_buff, tail));
	skb->data = skb->head + NET_SKB_PAD;
	skb_reset_tail_pointer(skb);
}

void ipa3_tag_destroy_imm(void *user1, int user2)
{
	ipahal_destroy_imm_cmd(user1);
}

static void ipa3_tag_free_skb(void *user1, int user2)
{
	dev_kfree_skb_any((struct sk_buff *)user1);
}

#define REQUIRED_TAG_PROCESS_DESCRIPTORS 4

/* ipa3_tag_process() - Initiates a tag process. Incorporates the input
 * descriptors
 *
 * @desc:	descriptors with commands for IC
 * @desc_size:	amount of descriptors in the above variable
 *
 * Note: The descriptors are copied (if there's room), the client needs to
 * free his descriptors afterwards
 *
 * Return: 0 or negative in case of failure
 */
int ipa3_tag_process(struct ipa3_desc desc[],
	int descs_num,
	unsigned long timeout)
{
	struct ipa3_sys_context *sys;
	struct ipa3_desc *tag_desc;
	int desc_idx = 0;
	struct ipahal_imm_cmd_ip_packet_init pktinit_cmd;
	struct ipahal_imm_cmd_pyld *cmd_pyld = NULL;
	struct ipahal_imm_cmd_ip_packet_tag_status status;
	int i;
	struct sk_buff *dummy_skb;
	int res;
	struct ipa3_tag_completion *comp;
	int ep_idx;

	/* Not enough room for the required descriptors for the tag process */
	if (IPA_TAG_MAX_DESC - descs_num < REQUIRED_TAG_PROCESS_DESCRIPTORS) {
		ipa_err("up to %d descriptors are allowed (received %d)\n",
		       IPA_TAG_MAX_DESC - REQUIRED_TAG_PROCESS_DESCRIPTORS,
		       descs_num);
		return -ENOMEM;
	}

	ep_idx = ipa3_get_ep_mapping(IPA_CLIENT_APPS_CMD_PROD);
	if (ep_idx < 0) {
		ipa_err("Client %u is not mapped\n",
			IPA_CLIENT_APPS_CMD_PROD);
		return -EFAULT;
	}
	sys = ipa3_ctx->ep[ep_idx].sys;

	tag_desc = kzalloc(sizeof(*tag_desc) * IPA_TAG_MAX_DESC, GFP_KERNEL);
	if (!tag_desc) {
		ipa_err("failed to allocate memory\n");
		return -ENOMEM;
	}

	/* Copy the required descriptors from the client now */
	if (desc) {
		memcpy(&(tag_desc[0]), desc, descs_num *
			sizeof(tag_desc[0]));
		desc_idx += descs_num;
	}

	/* NO-OP IC for ensuring that IPA pipeline is empty */
	cmd_pyld = ipahal_construct_nop_imm_cmd();
	if (!cmd_pyld) {
		ipa_err("failed to construct NOP imm cmd\n");
		res = -ENOMEM;
		goto fail_free_tag_desc;
	}
	ipa_desc_fill_imm_cmd(&tag_desc[desc_idx], cmd_pyld);
	tag_desc[desc_idx].callback = ipa3_tag_destroy_imm;
	tag_desc[desc_idx].user1 = cmd_pyld;
	desc_idx++;

	/* IP_PACKET_INIT IC for tag status to be sent to apps */
	pktinit_cmd.destination_pipe_index =
		ipa3_get_ep_mapping(IPA_CLIENT_APPS_LAN_CONS);
	cmd_pyld = ipahal_construct_imm_cmd(IPA_IMM_CMD_IP_PACKET_INIT,
						&pktinit_cmd);
	if (!cmd_pyld) {
		ipa_err("failed to construct ip_packet_init imm cmd\n");
		res = -ENOMEM;
		goto fail_free_desc;
	}
	ipa_desc_fill_imm_cmd(&tag_desc[desc_idx], cmd_pyld);
	tag_desc[desc_idx].callback = ipa3_tag_destroy_imm;
	tag_desc[desc_idx].user1 = cmd_pyld;
	desc_idx++;

	/* status IC */
	status.tag = IPA_COOKIE;
	cmd_pyld = ipahal_construct_imm_cmd(
				IPA_IMM_CMD_IP_PACKET_TAG_STATUS,
				&status);
	if (!cmd_pyld) {
		ipa_err("failed to construct ip_packet_tag_status imm cmd\n");
		res = -ENOMEM;
		goto fail_free_desc;
	}
	ipa_desc_fill_imm_cmd(&tag_desc[desc_idx], cmd_pyld);
	tag_desc[desc_idx].callback = ipa3_tag_destroy_imm;
	tag_desc[desc_idx].user1 = cmd_pyld;
	desc_idx++;

	comp = kzalloc(sizeof(*comp), GFP_KERNEL);
	if (!comp) {
		ipa_err("no mem\n");
		res = -ENOMEM;
		goto fail_free_desc;
	}
	init_completion(&comp->comp);

	/* completion needs to be released from both here and rx handler */
	atomic_set(&comp->cnt, 2);

	/* dummy packet to send to IPA. packet payload is a completion object */
	dummy_skb = alloc_skb(sizeof(comp), GFP_KERNEL);
	if (!dummy_skb) {
		ipa_err("failed to allocate memory\n");
		res = -ENOMEM;
		goto fail_free_comp;
	}

	memcpy(skb_put(dummy_skb, sizeof(comp)), &comp, sizeof(comp));

	tag_desc[desc_idx].pyld = dummy_skb->data;
	tag_desc[desc_idx].len = dummy_skb->len;
	tag_desc[desc_idx].type = IPA_DATA_DESC_SKB;
	tag_desc[desc_idx].callback = ipa3_tag_free_skb;
	tag_desc[desc_idx].user1 = dummy_skb;
	desc_idx++;

	/* send all descriptors to IPA with single EOT */
	res = ipa3_send(sys, desc_idx, tag_desc, true);
	if (res) {
		ipa_err("failed to send TAG packets %d\n", res);
		res = -ENOMEM;
		goto fail_free_comp;
	}
	kfree(tag_desc);
	tag_desc = NULL;

	ipa_debug("waiting for TAG response\n");
	res = wait_for_completion_timeout(&comp->comp, timeout);
	if (res == 0) {
		ipa_err("timeout (%lu msec) on waiting for TAG response\n",
			timeout);
		WARN_ON(1);
		if (atomic_dec_return(&comp->cnt) == 0)
			kfree(comp);
		return -ETIME;
	}

	ipa_debug("TAG response arrived!\n");
	if (atomic_dec_return(&comp->cnt) == 0)
		kfree(comp);

	/*
	 * sleep for short period to ensure IPA wrote all packets to
	 * the transport
	 */
	usleep_range(IPA_TAG_SLEEP_MIN_USEC, IPA_TAG_SLEEP_MAX_USEC);

	return 0;

fail_free_comp:
	kfree(comp);
fail_free_desc:
	/*
	 * Free only the first descriptors allocated here.
	 * [nop, pkt_init, status, dummy_skb]
	 * The user is responsible to free his allocations
	 * in case of failure.
	 * The min is required because we may fail during
	 * of the initial allocations above
	 */
	for (i = descs_num;
		i < min(REQUIRED_TAG_PROCESS_DESCRIPTORS, desc_idx); i++)
		if (tag_desc[i].callback)
			tag_desc[i].callback(tag_desc[i].user1,
				tag_desc[i].user2);
fail_free_tag_desc:
	kfree(tag_desc);
	return res;
}

/**
 * ipa3_tag_generate_force_close_desc() - generate descriptors for force close
 *					 immediate command
 *
 * @desc: descriptors for IC
 * @desc_size: desc array size
 * @start_pipe: first pipe to close aggregation
 * @end_pipe: last (non-inclusive) pipe to close aggregation
 *
 * Return: number of descriptors written or negative in case of failure
 */
static int ipa3_tag_generate_force_close_desc(struct ipa3_desc desc[],
	int desc_size, int start_pipe, int end_pipe)
{
	int i;
	struct ipa_ep_cfg_aggr ep_aggr;
	int desc_idx = 0;
	int res;
	struct ipahal_imm_cmd_register_write reg_write_agg_close;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	struct ipahal_reg_valmask valmask;

	for (i = start_pipe; i < end_pipe; i++) {
		ipahal_read_reg_n_fields(IPA_ENDP_INIT_AGGR_n, i, &ep_aggr);
		if (!ep_aggr.aggr_en)
			continue;
		ipa_debug("Force close ep: %d\n", i);
		if (desc_idx + 1 > desc_size) {
			ipa_err("Internal error - no descriptors\n");
			res = -EFAULT;
			goto fail_no_desc;
		}

		reg_write_agg_close.skip_pipeline_clear = false;
		reg_write_agg_close.pipeline_clear_options =
			IPAHAL_FULL_PIPELINE_CLEAR;
		reg_write_agg_close.offset =
			ipahal_reg_offset(IPA_AGGR_FORCE_CLOSE);
		ipahal_get_aggr_force_close_valmask(i, &valmask);
		reg_write_agg_close.value = valmask.val;
		reg_write_agg_close.value_mask = valmask.mask;
		cmd_pyld = ipahal_construct_imm_cmd(
				IPA_IMM_CMD_REGISTER_WRITE,
				&reg_write_agg_close);
		if (!cmd_pyld) {
			ipa_err("failed to construct register_write imm cmd\n");
			res = -ENOMEM;
			goto fail_alloc_reg_write_agg_close;
		}
		ipa_desc_fill_imm_cmd(&desc[desc_idx], cmd_pyld);
		desc[desc_idx].callback = ipa3_tag_destroy_imm;
		desc[desc_idx].user1 = cmd_pyld;
		desc_idx++;
	}

	return desc_idx;

fail_alloc_reg_write_agg_close:
	for (i = 0; i < desc_idx; i++)
		if (desc[desc_idx].callback)
			desc[desc_idx].callback(desc[desc_idx].user1,
				desc[desc_idx].user2);
fail_no_desc:
	return res;
}

/**
 * ipa3_tag_aggr_force_close() - Force close aggregation
 *
 * @pipe_num: pipe number or -1 for all pipes
 */
int ipa3_tag_aggr_force_close(int pipe_num)
{
	struct ipa3_desc *desc;
	int res = -1;
	int start_pipe;
	int end_pipe;
	int num_descs;
	int num_aggr_descs;

	if (pipe_num < -1 || pipe_num >= (int)ipa3_ctx->ipa_num_pipes) {
		ipa_err("Invalid pipe number %d\n", pipe_num);
		return -EINVAL;
	}

	if (pipe_num == -1) {
		start_pipe = 0;
		end_pipe = ipa3_ctx->ipa_num_pipes;
	} else {
		start_pipe = pipe_num;
		end_pipe = pipe_num + 1;
	}

	num_descs = end_pipe - start_pipe;

	desc = kcalloc(num_descs, sizeof(*desc), GFP_KERNEL);
	if (!desc) {
		ipa_err("no mem\n");
		return -ENOMEM;
	}

	/* Force close aggregation on all valid pipes with aggregation */
	num_aggr_descs = ipa3_tag_generate_force_close_desc(desc, num_descs,
						start_pipe, end_pipe);
	if (num_aggr_descs < 0) {
		ipa_err("ipa3_tag_generate_force_close_desc failed %d\n",
			num_aggr_descs);
		goto fail_free_desc;
	}

	res = ipa3_tag_process(desc, num_aggr_descs,
			      IPA_FORCE_CLOSE_TAG_PROCESS_TIMEOUT);

fail_free_desc:
	kfree(desc);

	return res;
}

/**
 * ipa3_proxy_clk_unvote() - called to remove IPA clock proxy vote
 *
 * Return value: none
 */
void ipa3_proxy_clk_unvote(void)
{
	if (ipa3_ctx->q6_proxy_clk_vote_valid) {
		IPA_ACTIVE_CLIENTS_DEC_SPECIAL("PROXY_CLK_VOTE");
		ipa3_ctx->q6_proxy_clk_vote_valid = false;
	}
}

/**
 * ipa3_proxy_clk_vote() - called to add IPA clock proxy vote
 *
 * Return value: none
 */
void ipa3_proxy_clk_vote(void)
{
	if (!ipa3_ctx->q6_proxy_clk_vote_valid) {
		IPA_ACTIVE_CLIENTS_INC_SPECIAL("PROXY_CLK_VOTE");
		ipa3_ctx->q6_proxy_clk_vote_valid = true;
	}
}

/**
 * ipa3_get_smem_restr_bytes()- Return IPA smem restricted bytes
 *
 * Return value: u16 - number of IPA smem restricted bytes
 */
u16 ipa3_get_smem_restr_bytes(void)
{
	return ipa3_ctx->smem_restricted_bytes;
}

u32 ipa3_get_num_pipes(void)
{
	return ipahal_read_reg(IPA_ENABLED_PIPES);
}

/**
 * ipa3_disable_apps_wan_cons_deaggr()-
 * set ipa_ctx->ipa_client_apps_wan_cons_agg_gro
 *
 * Return value: 0 or negative in case of failure
 */
int ipa3_disable_apps_wan_cons_deaggr(uint32_t agg_size, uint32_t agg_count)
{
	u32 limit;

	/* checking if IPA-HW can support */
	limit = ipahal_aggr_get_max_byte_limit();
	if ((agg_size >> 10) > limit) {
		ipa_err("IPA-AGG byte limit %d\n", limit);
		ipa_err("exceed aggr_byte_limit\n");
		return -1;
	}

	limit = ipahal_aggr_get_max_pkt_limit();
	if (agg_count > limit) {
		ipa_err("IPA-AGG pkt limit %d\n", limit);
		ipa_err("exceed aggr_pkt_limit\n");
		return -1;
	}

	ipa3_ctx->ipa_client_apps_wan_cons_agg_gro = true;

	return 0;
}

void __ipa_ipc_logging(bool only_low, const char *fmt, ...)
{
	va_list arg_list;

	va_start(arg_list, fmt);
	if (!only_low)
		(void)ipc_log_va_list(ipa3_ctx->logbuf, fmt, arg_list);
	(void)ipc_log_va_list(ipa3_ctx->logbuf_low, fmt, arg_list);
	va_end(arg_list);
}

/**
 * ipa_is_modem_pipe()- Checks if pipe is owned by the modem
 *
 * @pipe_idx: pipe number
 * Return value: true if owned by modem, false otherwize
 */
bool ipa_is_modem_pipe(int pipe_idx)
{
	int client_idx;

	if (pipe_idx >= ipa3_ctx->ipa_num_pipes || pipe_idx < 0) {
		ipa_err("Bad pipe index!\n");
		return false;
	}

	for (client_idx = 0; client_idx < IPA_CLIENT_MAX; client_idx++) {
		if (!IPA_CLIENT_IS_Q6_CONS(client_idx) &&
			!IPA_CLIENT_IS_Q6_PROD(client_idx))
			continue;
		if (ipa3_get_ep_mapping(client_idx) == pipe_idx)
			return true;
	}

	return false;
}

static void ipa3_write_rsrc_grp_type_reg(int group_index,
			enum ipa_rsrc_grp_type_src n, bool src,
			struct ipahal_reg_rsrc_grp_cfg *val)
{
	if (src) {
		switch (group_index) {
		case IPA_v3_5_GROUP_LWA_DL:
		case IPA_v3_5_GROUP_UL_DL:
			ipahal_write_reg_n_fields(
				IPA_SRC_RSRC_GRP_01_RSRC_TYPE_n,
				n, val);
			break;
		case IPA_v3_5_GROUP_UC_RX_Q:
			ipahal_write_reg_n_fields(
				IPA_SRC_RSRC_GRP_23_RSRC_TYPE_n,
				n, val);
			break;
		default:
			ipa_err(
			" Invalid source resource group,index #%d\n",
			group_index);
			break;
		}
	} else {
		switch (group_index) {
		case IPA_v3_5_GROUP_LWA_DL:
		case IPA_v3_5_GROUP_UL_DL:
			ipahal_write_reg_n_fields(
				IPA_DST_RSRC_GRP_01_RSRC_TYPE_n,
				n, val);
			break;
		default:
			ipa_err(
			" Invalid destination resource group,index #%d\n",
			group_index);
			break;
		}
	}
}

void ipa3_set_resorce_groups_min_max_limits(void)
{
	int i;
	int j;
	int src_rsrc_type_max;
	int dst_rsrc_type_max;
	int src_grp_idx_max;
	int dst_grp_idx_max;
	struct ipahal_reg_rsrc_grp_cfg val;

	ipa_debug("ENTER\n");
	ipa_debug("Assign source rsrc groups min-max limits\n");

	src_rsrc_type_max = IPA_v3_5_RSRC_GRP_TYPE_SRC_MAX;
	dst_rsrc_type_max = IPA_v3_5_RSRC_GRP_TYPE_DST_MAX;
	src_grp_idx_max = IPA_v3_5_SRC_GROUP_MAX;
	dst_grp_idx_max = IPA_v3_5_DST_GROUP_MAX;

	for (i = 0; i < src_rsrc_type_max; i++) {
		for (j = 0; j < src_grp_idx_max; j = j + 2) {
			val.x_min =
			ipa3_rsrc_src_grp_config[IPA_3_5_1][i][j].min;
			val.x_max =
			ipa3_rsrc_src_grp_config[IPA_3_5_1][i][j].max;
			val.y_min =
			ipa3_rsrc_src_grp_config[IPA_3_5_1][i][j + 1].min;
			val.y_max =
			ipa3_rsrc_src_grp_config[IPA_3_5_1][i][j + 1].max;
			ipa3_write_rsrc_grp_type_reg(j, i, true, &val);
		}
	}

	ipa_debug("Assign destination rsrc groups min-max limits\n");

	for (i = 0; i < dst_rsrc_type_max; i++) {
		for (j = 0; j < dst_grp_idx_max; j = j + 2) {
			val.x_min =
			ipa3_rsrc_dst_grp_config[IPA_3_5_1][i][j].min;
			val.x_max =
			ipa3_rsrc_dst_grp_config[IPA_3_5_1][i][j].max;
			val.y_min =
			ipa3_rsrc_dst_grp_config[IPA_3_5_1][i][j + 1].min;
			val.y_max =
			ipa3_rsrc_dst_grp_config[IPA_3_5_1][i][j + 1].max;
			ipa3_write_rsrc_grp_type_reg(j, i, false, &val);
		}
	}

	/* Resource group configuration is done by TZ */
	ipa_err("skip configuring ipa_rx_hps_clients from HLOS\n");
}

static void ipa3_gsi_poll_after_suspend(struct ipa3_ep_context *ep)
{
	ipa_debug("switch ch %ld to poll\n", ep->gsi_chan_hdl);
	gsi_config_channel_mode(ep->gsi_chan_hdl, GSI_CHAN_MODE_POLL);
	if (!gsi_is_channel_empty(ep->gsi_chan_hdl)) {
		ipa_debug("ch %ld not empty\n", ep->gsi_chan_hdl);
		/* queue a work to start polling if don't have one */
		atomic_set(&ipa3_ctx->transport_pm.eot_activity, 1);
		if (!atomic_read(&ep->sys->curr_polling_state)) {
			ipa3_inc_acquire_wakelock();
			atomic_set(&ep->sys->curr_polling_state, 1);
			queue_work(ep->sys->wq, &ep->sys->work);
		}
	}
}

void ipa3_suspend_apps_pipes(bool suspend)
{
	struct ipa_ep_cfg_ctrl cfg;
	int ipa_ep_idx;
	struct ipa3_ep_context *ep;

	memset(&cfg, 0, sizeof(cfg));
	cfg.ipa_ep_suspend = suspend;

	ipa_ep_idx = ipa3_get_ep_mapping(IPA_CLIENT_APPS_LAN_CONS);
	if (ipa_ep_idx < 0) {
		ipa_err("IPA client mapping failed\n");
		ipa_assert();
		return;
	}
	ep = &ipa3_ctx->ep[ipa_ep_idx];
	if (ep->valid) {
		ipa_debug("%s pipe %d\n", suspend ? "suspend" : "unsuspend",
			ipa_ep_idx);
		ipa3_cfg_ep_ctrl(ipa_ep_idx, &cfg);
		if (suspend)
			ipa3_gsi_poll_after_suspend(ep);
		else if (!atomic_read(&ep->sys->curr_polling_state))
			gsi_config_channel_mode(ep->gsi_chan_hdl,
				GSI_CHAN_MODE_CALLBACK);
	}

	ipa_ep_idx = ipa3_get_ep_mapping(IPA_CLIENT_APPS_WAN_CONS);
	/* Considering the case for SSR. */
	if (ipa_ep_idx == -1) {
		ipa_debug("Invalid client.\n");
		return;
	}
	ep = &ipa3_ctx->ep[ipa_ep_idx];
	if (ep->valid) {
		ipa_debug("%s pipe %d\n", suspend ? "suspend" : "unsuspend",
			ipa_ep_idx);
		ipa3_cfg_ep_ctrl(ipa_ep_idx, &cfg);
		if (suspend)
			ipa3_gsi_poll_after_suspend(ep);
		else if (!atomic_read(&ep->sys->curr_polling_state))
			gsi_config_channel_mode(ep->gsi_chan_hdl,
				GSI_CHAN_MODE_CALLBACK);
	}
}

int ipa3_allocate_dma_task_for_gsi(void)
{
	struct ipa_mem_buffer *mem = &ipa3_ctx->dma_task_info.mem;
	struct ipahal_imm_cmd_dma_task_32b_addr cmd = { 0 };

	ipa_debug("Allocate mem\n");

	if (ipahal_dma_alloc(mem, IPA_GSI_CHANNEL_STOP_PKT_SIZE, GFP_KERNEL))
		return -EFAULT;

	cmd.flsh = 1;
	cmd.size1 = ipa3_ctx->dma_task_info.mem.size;
	cmd.addr1 = ipa3_ctx->dma_task_info.mem.phys_base;
	cmd.packet_size = ipa3_ctx->dma_task_info.mem.size;
	ipa3_ctx->dma_task_info.cmd_pyld = ipahal_construct_imm_cmd(
			IPA_IMM_CMD_DMA_TASK_32B_ADDR, &cmd);
	if (!ipa3_ctx->dma_task_info.cmd_pyld) {
		ipa_err("failed to construct dma_task_32b_addr cmd\n");
		ipahal_dma_free(mem);
		return -EFAULT;
	}

	return 0;
}

void ipa3_free_dma_task_for_gsi(void)
{
	struct ipa_mem_buffer *mem = &ipa3_ctx->dma_task_info.mem;

	ipahal_destroy_imm_cmd(ipa3_ctx->dma_task_info.cmd_pyld);
	ipa3_ctx->dma_task_info.cmd_pyld = NULL;
	ipahal_dma_free(mem);
}

/**
 * ipa3_inject_dma_task_for_gsi()- Send DMA_TASK to IPA for GSI stop channel
 *
 * Send a DMA_TASK of 1B to IPA to unblock GSI channel in STOP_IN_PROG.
 * Return value: 0 on success, negative otherwise
 */
int ipa3_inject_dma_task_for_gsi(void)
{
	struct ipa3_desc desc = {0};

	ipa_desc_fill_imm_cmd(&desc, ipa3_ctx->dma_task_info.cmd_pyld);

	ipa_debug("sending 1B packet to IPA\n");
	if (ipa3_send_cmd_timeout(1, &desc,
		IPA_DMA_TASK_FOR_GSI_TIMEOUT_MSEC)) {
		ipa_err("ipa3_send_cmd failed\n");
		return -EFAULT;
	}

	return 0;
}

/**
 * ipa3_stop_gsi_channel()- Stops a GSI channel in IPA
 * @chan_hdl: GSI channel handle
 *
 * This function implements the sequence to stop a GSI channel
 * in IPA. This function returns when the channel is is STOP state.
 *
 * Return value: 0 on success, negative otherwise
 */
int ipa3_stop_gsi_channel(u32 clnt_hdl)
{
	struct ipa_mem_buffer mem;
	int res = 0;
	int i;
	struct ipa3_ep_context *ep;

	if (!client_handle_valid(clnt_hdl))
		return -EINVAL;

	ep = &ipa3_ctx->ep[clnt_hdl];

	IPA_ACTIVE_CLIENTS_INC_EP(ipa3_get_client_mapping(clnt_hdl));

	memset(&mem, 0, sizeof(mem));

	if (IPA_CLIENT_IS_PROD(ep->client)) {
		ipa_debug("Calling gsi_stop_channel ch:%lu\n",
			ep->gsi_chan_hdl);
		res = gsi_stop_channel(ep->gsi_chan_hdl);
		ipa_debug("gsi_stop_channel ch: %lu returned %d\n",
			ep->gsi_chan_hdl, res);
		goto end_sequence;
	}

	for (i = 0; i < IPA_GSI_CHANNEL_STOP_MAX_RETRY; i++) {
		ipa_debug("Calling gsi_stop_channel ch:%lu\n",
			ep->gsi_chan_hdl);
		res = gsi_stop_channel(ep->gsi_chan_hdl);
		ipa_debug("gsi_stop_channel ch: %lu returned %d\n",
			ep->gsi_chan_hdl, res);
		if (res != -EAGAIN && res != -ETIMEDOUT)
			goto end_sequence;

		ipa_debug("Inject a DMA_TASK with 1B packet to IPA\n");
		/* Send a 1B packet DMA_TASK to IPA and try again */
		res = ipa3_inject_dma_task_for_gsi();
		if (res) {
			ipa_err("Failed to inject DMA TASk for GSI\n");
			goto end_sequence;
		}

		/* sleep for short period to flush IPA */
		usleep_range(IPA_GSI_CHANNEL_STOP_SLEEP_MIN_USEC,
			IPA_GSI_CHANNEL_STOP_SLEEP_MAX_USEC);
	}

	ipa_err("Failed  to stop GSI channel with retries\n");
	res = -EFAULT;
end_sequence:
	IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));

	return res;
}

static int ipa3_load_single_fw(const struct firmware *firmware,
	const struct elf32_phdr *phdr)
{
	uint32_t *fw_mem_base;
	int index;
	const uint32_t *elf_data_ptr;

	if (phdr->p_offset > firmware->size) {
		ipa_err("Invalid ELF: offset=%u is beyond elf_size=%zu\n",
			phdr->p_offset, firmware->size);
		return -EINVAL;
	}
	if ((firmware->size - phdr->p_offset) < phdr->p_filesz) {
		ipa_err("Invalid ELF: offset=%u filesz=%u elf_size=%zu\n",
			phdr->p_offset, phdr->p_filesz, firmware->size);
		return -EINVAL;
	}

	if (phdr->p_memsz % sizeof(uint32_t)) {
		ipa_err("FW mem size %u doesn't align to 32bit\n",
			phdr->p_memsz);
		return -EFAULT;
	}

	if (phdr->p_filesz > phdr->p_memsz) {
		ipa_err("FW image too big src_size=%u dst_size=%u\n",
			phdr->p_filesz, phdr->p_memsz);
		return -EFAULT;
	}

	fw_mem_base = ioremap(phdr->p_vaddr, phdr->p_memsz);
	if (!fw_mem_base) {
		ipa_err("Failed to map 0x%x for the size of %u\n",
			phdr->p_vaddr, phdr->p_memsz);
		return -ENOMEM;
	}

	/* Set the entire region to 0s */
	memset(fw_mem_base, 0, phdr->p_memsz);

	elf_data_ptr = (uint32_t *)(firmware->data + phdr->p_offset);

	/* Write the FW */
	for (index = 0; index < phdr->p_filesz/sizeof(uint32_t); index++) {
		writel_relaxed(*elf_data_ptr, &fw_mem_base[index]);
		elf_data_ptr++;
	}

	iounmap(fw_mem_base);

	return 0;
}

/**
 * ipa3_load_fws() - Load the IPAv3 FWs into IPA&GSI SRAM.
 *
 * @firmware: Structure which contains the FW data from the user space.
 * @gsi_mem_base: GSI base address
 *
 * Return value: 0 on success, negative otherwise
 *
 */
int ipa3_load_fws(const struct firmware *firmware, phys_addr_t gsi_mem_base)
{
	const struct elf32_hdr *ehdr;
	const struct elf32_phdr *phdr;
	unsigned long gsi_iram_ofst;
	unsigned long gsi_iram_size;
	phys_addr_t ipa_reg_mem_base;
	u32 ipa_reg_ofst;
	int rc;

	if (!gsi_mem_base) {
		ipa_err("Invalid GSI base address\n");
		return -EINVAL;
	}

	ipa_assert_on(!firmware);
	/* One program header per FW image: GSI, DPS and HPS */
	if (firmware->size < (sizeof(*ehdr) + 3 * sizeof(*phdr))) {
		ipa_err("Missing ELF and Program headers firmware size=%zu\n",
			firmware->size);
		return -EINVAL;
	}

	ehdr = (struct elf32_hdr *) firmware->data;
	ipa_assert_on(!ehdr);
	if (ehdr->e_phnum != 3) {
		ipa_err("Unexpected number of ELF program headers\n");
		return -EINVAL;
	}
	phdr = (struct elf32_phdr *)(firmware->data + sizeof(*ehdr));

	/*
	 * Each ELF program header represents a FW image and contains:
	 *  p_vaddr : The starting address to which the FW needs to loaded.
	 *  p_memsz : The size of the IRAM (where the image loaded)
	 *  p_filesz: The size of the FW image embedded inside the ELF
	 *  p_offset: Absolute offset to the image from the head of the ELF
	 */

	/* Load GSI FW image */
	gsi_get_inst_ram_offset_and_size(&gsi_iram_ofst, &gsi_iram_size);
	if (phdr->p_vaddr != (gsi_mem_base + gsi_iram_ofst)) {
		ipa_err(
			"Invalid GSI FW img load addr vaddr=0x%x gsi_mem_base=%pa gsi_iram_ofst=0x%lx\n"
			, phdr->p_vaddr, &gsi_mem_base, gsi_iram_ofst);
		return -EINVAL;
	}
	if (phdr->p_memsz > gsi_iram_size) {
		ipa_err("Invalid GSI FW img size memsz=%d gsi_iram_size=%lu\n",
			phdr->p_memsz, gsi_iram_size);
		return -EINVAL;
	}
	rc = ipa3_load_single_fw(firmware, phdr);
	if (rc)
		return rc;

	phdr++;
	ipa_reg_mem_base = ipa3_ctx->ipa_wrapper_base +
				ipa3_ctx->ctrl->ipa_reg_base_ofst;

	/* Load IPA DPS FW image */
	ipa_reg_ofst = ipahal_reg_offset(IPA_DPS_SEQUENCER_FIRST);
	if (phdr->p_vaddr != (ipa_reg_mem_base + ipa_reg_ofst)) {
		ipa_err(
			"Invalid IPA DPS img load addr vaddr=0x%x ipa_reg_mem_base=%pa ipa_reg_ofst=%u\n"
			, phdr->p_vaddr, &ipa_reg_mem_base, ipa_reg_ofst);
		return -EINVAL;
	}
	if (phdr->p_memsz > ipahal_get_dps_img_mem_size()) {
		ipa_err("Invalid IPA DPS img size memsz=%d dps_mem_size=%u\n",
			phdr->p_memsz, ipahal_get_dps_img_mem_size());
		return -EINVAL;
	}
	rc = ipa3_load_single_fw(firmware, phdr);
	if (rc)
		return rc;

	phdr++;

	/* Load IPA HPS FW image */
	ipa_reg_ofst = ipahal_reg_offset(IPA_HPS_SEQUENCER_FIRST);
	if (phdr->p_vaddr != (ipa_reg_mem_base + ipa_reg_ofst)) {
		ipa_err(
			"Invalid IPA HPS img load addr vaddr=0x%x ipa_reg_mem_base=%pa ipa_reg_ofst=%u\n"
			, phdr->p_vaddr, &ipa_reg_mem_base, ipa_reg_ofst);
		return -EINVAL;
	}
	if (phdr->p_memsz > ipahal_get_hps_img_mem_size()) {
		ipa_err("Invalid IPA HPS img size memsz=%d dps_mem_size=%u\n",
			phdr->p_memsz, ipahal_get_hps_img_mem_size());
		return -EINVAL;
	}
	rc = ipa3_load_single_fw(firmware, phdr);
	if (rc)
		return rc;

	ipa_debug("IPA FWs (GSI FW, DPS and HPS) loaded successfully\n");
	return 0;
}

/**
 * ipa3_enable_dcd() - enable dynamic clock division on IPA
 *
 * Return value: Non applicable
 *
 */
void ipa3_enable_dcd(void)
{
	struct ipahal_reg_idle_indication_cfg idle_indication_cfg;

	/* recommended values for IPA 3.5 according to IPA HPG */
	idle_indication_cfg.const_non_idle_enable = 0;
	idle_indication_cfg.enter_idle_debounce_thresh = 256;

	ipahal_write_reg_fields(IPA_IDLE_INDICATION_CFG,
			&idle_indication_cfg);
}

/**
 * ipa3_set_flt_tuple_mask() - Sets the flt tuple masking for the given pipe
 *  Pipe must be for AP EP (not modem) and support filtering
 *  updates the the filtering masking values without changing the rt ones.
 *
 * @pipe_idx: filter pipe index to configure the tuple masking
 * @tuple: the tuple members masking
 * Returns:     0 on success, negative on failure
 *
 */
int ipa3_set_flt_tuple_mask(int pipe_idx, struct ipahal_reg_hash_tuple *tuple)
{
        struct ipahal_reg_fltrt_hash_tuple fltrt_tuple;

        if (!tuple) {
                ipa_err("bad tuple\n");
                return -EINVAL;
        }

        if (pipe_idx >= ipa3_ctx->ipa_num_pipes || pipe_idx < 0) {
                ipa_err("bad pipe index!\n");
                return -EINVAL;
        }

        if (!ipa_is_ep_support_flt(pipe_idx)) {
                ipa_err("pipe %d not filtering pipe\n", pipe_idx);
                return -EINVAL;
        }

        if (ipa_is_modem_pipe(pipe_idx)) {
                ipa_err("modem pipe tuple is not configured by AP\n");
                return -EINVAL;
        }

        ipahal_read_reg_n_fields(IPA_ENDP_FILTER_ROUTER_HSH_CFG_n,
                pipe_idx, &fltrt_tuple);
        fltrt_tuple.flt = *tuple;
        ipahal_write_reg_n_fields(IPA_ENDP_FILTER_ROUTER_HSH_CFG_n,
                pipe_idx, &fltrt_tuple);

        return 0;
}

/**
 * ipa_write_64() - convert 64 bit value to byte array
 * @w: 64 bit integer
 * @dest: byte array
 *
 * Return value: converted value
 */
u8 *ipa_write_64(u64 w, u8 *dest)
{
	if (unlikely(dest == NULL)) {
		ipa_err("ipa_write_64: NULL address!\n");
		return dest;
	}
	*dest++ = (u8)((w) & 0xFF);
	*dest++ = (u8)((w >> 8) & 0xFF);
	*dest++ = (u8)((w >> 16) & 0xFF);
	*dest++ = (u8)((w >> 24) & 0xFF);
	*dest++ = (u8)((w >> 32) & 0xFF);
	*dest++ = (u8)((w >> 40) & 0xFF);
	*dest++ = (u8)((w >> 48) & 0xFF);
	*dest++ = (u8)((w >> 56) & 0xFF);

	return dest;
}

const char *ipa_clients_strings[IPA_CLIENT_MAX] = {
	[IPA_CLIENT_A2_EMBEDDED_PROD] = __stringify(IPA_CLIENT_A2_EMBEDDED_PROD),
	[IPA_CLIENT_A2_EMBEDDED_CONS] = __stringify(IPA_CLIENT_A2_EMBEDDED_CONS),
	[IPA_CLIENT_APPS_LAN_PROD] = __stringify(IPA_CLIENT_APPS_LAN_PROD),
	[IPA_CLIENT_APPS_LAN_CONS] = __stringify(IPA_CLIENT_APPS_LAN_CONS),
	[IPA_CLIENT_APPS_WAN_PROD] = __stringify(IPA_CLIENT_APPS_WAN_PROD),
	[IPA_CLIENT_APPS_WAN_CONS] = __stringify(IPA_CLIENT_APPS_WAN_CONS),
	[IPA_CLIENT_APPS_CMD_PROD] = __stringify(IPA_CLIENT_APPS_CMD_PROD),
	[IPA_CLIENT_A5_LAN_WAN_CONS] = __stringify(IPA_CLIENT_A5_LAN_WAN_CONS),
	[IPA_CLIENT_Q6_LAN_PROD] = __stringify(IPA_CLIENT_Q6_LAN_PROD),
	[IPA_CLIENT_Q6_LAN_CONS] = __stringify(IPA_CLIENT_Q6_LAN_CONS),
	[IPA_CLIENT_Q6_WAN_PROD] = __stringify(IPA_CLIENT_Q6_WAN_PROD),
	[IPA_CLIENT_Q6_WAN_CONS] = __stringify(IPA_CLIENT_Q6_WAN_CONS),
	[IPA_CLIENT_Q6_CMD_PROD] = __stringify(IPA_CLIENT_Q6_CMD_PROD),
	[IPA_CLIENT_Q6_DUN_CONS] = __stringify(IPA_CLIENT_Q6_DUN_CONS),
	[IPA_CLIENT_MEMCPY_DMA_SYNC_PROD] = __stringify(IPA_CLIENT_MEMCPY_DMA_SYNC_PROD),
	[IPA_CLIENT_MEMCPY_DMA_SYNC_CONS] = __stringify(IPA_CLIENT_MEMCPY_DMA_SYNC_CONS),
	[IPA_CLIENT_MEMCPY_DMA_ASYNC_PROD] = __stringify(IPA_CLIENT_MEMCPY_DMA_ASYNC_PROD),
	[IPA_CLIENT_MEMCPY_DMA_ASYNC_CONS] = __stringify(IPA_CLIENT_MEMCPY_DMA_ASYNC_CONS),
	[IPA_CLIENT_Q6_DECOMP_PROD] = __stringify(IPA_CLIENT_Q6_DECOMP_PROD),
	[IPA_CLIENT_Q6_DECOMP_CONS] = __stringify(IPA_CLIENT_Q6_DECOMP_CONS),
	[IPA_CLIENT_Q6_DECOMP2_PROD] = __stringify(IPA_CLIENT_Q6_DECOMP2_PROD),
	[IPA_CLIENT_Q6_DECOMP2_CONS] = __stringify(IPA_CLIENT_Q6_DECOMP2_CONS),
	[IPA_CLIENT_Q6_LTE_WIFI_AGGR_CONS] = __stringify(IPA_CLIENT_Q6_LTE_WIFI_AGGR_CONS),
};

void ipa_assert(void)
{
	ipa_err("IPA: unrecoverable error has occurred, asserting\n");
	BUG();
}

/**
 * ipa3_set_rt_tuple_mask() - Sets the rt tuple masking for the given tbl
 *  table index must be for AP EP (not modem)
 *  updates the the routing masking values without changing the flt ones.
 *
 * @tbl_idx: routing table index to configure the tuple masking
 * @tuple: the tuple members masking
 * Returns:	 0 on success, negative on failure
 *
 */
int ipa3_set_rt_tuple_mask(int tbl_idx, struct ipahal_reg_hash_tuple *tuple)
{
	struct ipahal_reg_fltrt_hash_tuple fltrt_tuple;

	if (!tuple) {
			ipa_err("bad tuple\n");
			return -EINVAL;
	}

	if (tbl_idx >=
			max(ipa3_mem(V6_RT_NUM_INDEX),
			ipa3_mem(V4_RT_NUM_INDEX)) ||
			tbl_idx < 0) {
			ipa_err("bad table index\n");
			return -EINVAL;
	}

	if (tbl_idx >= ipa3_mem(V4_MODEM_RT_INDEX_LO) &&
			tbl_idx <= ipa3_mem(V4_MODEM_RT_INDEX_HI)) {
			ipa_err("cannot configure modem v4 rt tuple by AP\n");
			return -EINVAL;
	}

	if (tbl_idx >= ipa3_mem(V6_MODEM_RT_INDEX_LO) &&
			tbl_idx <= ipa3_mem(V6_MODEM_RT_INDEX_HI)) {
			ipa_err("cannot configure modem v6 rt tuple by AP\n");
			return -EINVAL;
	}

	ipahal_read_reg_n_fields(IPA_ENDP_FILTER_ROUTER_HSH_CFG_n,
			tbl_idx, &fltrt_tuple);
	fltrt_tuple.rt = *tuple;
	ipahal_write_reg_n_fields(IPA_ENDP_FILTER_ROUTER_HSH_CFG_n,
			tbl_idx, &fltrt_tuple);

	return 0;
}

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("IPA HW device driver");
