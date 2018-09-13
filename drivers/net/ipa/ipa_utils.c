// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#define pr_fmt(fmt)    "ipa %s:%d " fmt, __func__, __LINE__

#include <net/ip.h>
#include <linux/genalloc.h>	/* gen_pool_alloc() */
#include <linux/io.h>
#include <linux/ratelimit.h>
#include <linux/interconnect.h>
#include <linux/elf.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>

#include "ipa_dma.h"
#include "ipa_i.h"
#include "ipahal.h"

#define IPA_BCR_REG_VAL			0x0000003b

#define IPA_GSI_DMA_TASK_TIMEOUT	15	/* milliseconds */

#define IPA_GSI_CHANNEL_STOP_SLEEP_MIN	1000	/* microseconds */
#define IPA_GSI_CHANNEL_STOP_SLEEP_MAX	2000	/* microseconds */

#define QMB_MASTER_SELECT_DDR		0

/* Resource Group index*/
#define IPA_GROUP_LWA_DL		0 /* currently not used */
#define IPA_GROUP_UL_DL			1
#define IPA_MHI_GROUP_DMA		2
#define IPA_GROUP_UC_RX_Q		3 /* currently not used */

#define IPA_SRC_GROUP_MAX		4
#define IPA_DST_GROUP_MAX		3

enum ipa_rsrc_grp_type_src {
	IPA_RSRC_GRP_TYPE_SRC_PKT_CONTEXTS,
	IPA_RSRC_GRP_TYPE_SRS_DESCRIPTOR_LISTS,
	IPA_RSRC_GRP_TYPE_SRC_DESCRIPTOR_BUFF,
	IPA_RSRC_GRP_TYPE_SRC_HPS_DMARS,
	IPA_RSRC_GRP_TYPE_SRC_ACK_ENTRIES,
	IPA_RSRC_GRP_TYPE_SRC_MAX,
};

enum ipa_rsrc_grp_type_dst {
	IPA_RSRC_GRP_TYPE_DST_DATA_SECTORS,
	IPA_RSRC_GRP_TYPE_DST_DPS_DMARS,
	IPA_RSRC_GRP_TYPE_DST_MAX,
};

enum ipa_rsrc_grp_type_rx {
	IPA_RSRC_GRP_TYPE_RX_HPS_CMDQ,
	IPA_RSRC_GRP_TYPE_RX_MAX
};

struct rsrc_min_max {
	u32 min;
	u32 max;
};

/* IPA_HW_v3_5_1 */
static const struct rsrc_min_max ipa_rsrc_src_grp_config
	[IPA_RSRC_GRP_TYPE_SRC_MAX][IPA_SRC_GROUP_MAX] = {
	[IPA_RSRC_GRP_TYPE_SRC_PKT_CONTEXTS] = {
		[IPA_GROUP_LWA_DL]	= { .min = 1,	.max = 63, },
		[IPA_GROUP_UL_DL]	= { .min = 1,	.max = 63, },
		[IPA_MHI_GROUP_DMA]	= { .min = 0,	.max = 0, },
		[IPA_GROUP_UC_RX_Q]	= { .min = 1,	.max = 63, },
	},
	[IPA_RSRC_GRP_TYPE_SRS_DESCRIPTOR_LISTS] = {
		[IPA_GROUP_LWA_DL]	= { .min = 10,	.max = 10, },
		[IPA_GROUP_UL_DL]	= { .min = 10,	.max = 10, },
		[IPA_MHI_GROUP_DMA]	= { .min = 0,	.max = 0, },
		[IPA_GROUP_UC_RX_Q]	= { .min = 8,	.max = 8, },
	},
	[IPA_RSRC_GRP_TYPE_SRC_DESCRIPTOR_BUFF] = {
		[IPA_GROUP_LWA_DL]	= { .min = 12,	.max = 12, },
		[IPA_GROUP_UL_DL]	= { .min = 14,	.max = 14, },
		[IPA_MHI_GROUP_DMA]	= { .min = 0,	.max = 0, },
		[IPA_GROUP_UC_RX_Q]	= { .min = 8,	.max = 8, },
	},
	[IPA_RSRC_GRP_TYPE_SRC_HPS_DMARS] = {
		[IPA_GROUP_LWA_DL]	= { .min = 0,	.max = 63, },
		[IPA_GROUP_UL_DL]	= { .min = 0,	.max = 63, },
		[IPA_MHI_GROUP_DMA]	= { .min = 0,	.max = 255, },
		[IPA_GROUP_UC_RX_Q]	= { .min = 0,	.max = 255, },
	},
	[IPA_RSRC_GRP_TYPE_SRC_ACK_ENTRIES] = {
		[IPA_GROUP_LWA_DL]	= { .min = 14,	.max = 14, },
		[IPA_GROUP_UL_DL]	= { .min = 20,	.max = 20, },
		[IPA_MHI_GROUP_DMA]	= { .min = 0,	.max = 0, },
		[IPA_GROUP_UC_RX_Q]	= { .min = 14,	.max = 14, },
	},
};

/* IPA_HW_v3_5_1 */
static const struct rsrc_min_max ipa_rsrc_dst_grp_config
	[IPA_RSRC_GRP_TYPE_DST_MAX][IPA_DST_GROUP_MAX] = {
	/* LWA_DL UL/DL/DPL unused N/A	 N/A	 N/A */
	[IPA_RSRC_GRP_TYPE_DST_DATA_SECTORS] = {
		[IPA_GROUP_LWA_DL]	= { .min = 4,	.max = 4, },
		[IPA_GROUP_UL_DL]	= { .min = 4,	.max = 4, },
		[IPA_MHI_GROUP_DMA]	= { .min = 3,	.max = 3, },
	},
	[IPA_RSRC_GRP_TYPE_DST_DPS_DMARS] = {
		[IPA_GROUP_LWA_DL]	= { .min = 2,	.max = 63, },
		[IPA_GROUP_UL_DL]	= { .min = 1,	.max = 63, },
		[IPA_MHI_GROUP_DMA]	= { .min = 1,	.max = 2, },
	},
};

struct ipa_ep_configuration {
	bool valid;
	bool support_flt;
	enum ipa_seq_type seq_type;
	struct ipa_gsi_ep_config ipa_gsi_ep_info;
};

/* IPA_HW_v3_5_1 */
/* clients not included in the list below are considered as invalid */
static const struct ipa_ep_configuration ipa_ep_configuration[] = {
	[IPA_CLIENT_WLAN1_PROD] = {
		.valid		= true,
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 7,
			.ipa_gsi_chan_num	= 1,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 16,
			.ee			= IPA_EE_UC,
		},
	},
	[IPA_CLIENT_USB_PROD] = {
		.valid		= true,
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 0,
			.ipa_gsi_chan_num	= 0,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 16,
			.ee			= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_APPS_LAN_PROD] = {
		.valid		= true,
		.support_flt	= false,
		.seq_type	= IPA_SEQ_PKT_PROCESS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 8,
			.ipa_gsi_chan_num	= 7,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 16,
			.ee			= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_APPS_WAN_PROD] = {
		.valid		= true,
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 2,
			.ipa_gsi_chan_num	= 3,
			.ipa_if_tlv		= 16,
			.ipa_if_aos		= 32,
			.ee			= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_APPS_CMD_PROD] = {
		.valid		= true,
		.support_flt	= false,
		.seq_type	= IPA_SEQ_DMA_ONLY,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 5,
			.ipa_gsi_chan_num	= 4,
			.ipa_if_tlv		= 20,
			.ipa_if_aos		= 23,
			.ee			= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_Q6_LAN_PROD] = {
		.valid		= true,
		.support_flt	= true,
		.seq_type	= IPA_SEQ_PKT_PROCESS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 3,
			.ipa_gsi_chan_num	= 0,
			.ipa_if_tlv		= 16,
			.ipa_if_aos		= 32,
			.ee			= IPA_EE_Q6,
		},
	},
	[IPA_CLIENT_Q6_WAN_PROD] = {
		.valid		= true,
		.support_flt	= true,
		.seq_type	= IPA_SEQ_PKT_PROCESS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 6,
			.ipa_gsi_chan_num	= 4,
			.ipa_if_tlv		= 12,
			.ipa_if_aos		= 30,
			.ee			= IPA_EE_Q6,
		},
	},
	[IPA_CLIENT_Q6_CMD_PROD] = {
		.valid		= true,
		.support_flt	= false,
		.seq_type	= IPA_SEQ_PKT_PROCESS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 4,
			.ipa_gsi_chan_num	= 1,
			.ipa_if_tlv		= 20,
			.ipa_if_aos		= 23,
			.ee			= IPA_EE_Q6,
		},
	},
	[IPA_CLIENT_TEST_CONS] = {
		.valid		= true,
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 14,
			.ipa_gsi_chan_num	= 5,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 8,
			.ee			= IPA_EE_Q6,
		},
	},
	[IPA_CLIENT_TEST1_CONS] = {
		.valid		= true,
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 15,
			.ipa_gsi_chan_num	= 2,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 8,
			.ee			= IPA_EE_UC,
		},
	},
	/* Only for testing */
	[IPA_CLIENT_TEST_PROD] = {
		.valid		= true,
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 0,
			.ipa_gsi_chan_num	= 0,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 16,
			.ee			= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_TEST1_PROD] = {
		.valid		= true,
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 0,
			.ipa_gsi_chan_num	= 0,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 15,
			.ee			= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_TEST2_PROD] = {
		.valid		= true,
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 2,
			.ipa_gsi_chan_num	= 3,
			.ipa_if_tlv		= 16,
			.ipa_if_aos		= 32,
			.ee			= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_TEST3_PROD] = {
		.valid		= true,
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 4,
			.ipa_gsi_chan_num	= 1,
			.ipa_if_tlv		= 20,
			.ipa_if_aos		= 23,
			.ee			= IPA_EE_Q6,
		},
	},
	[IPA_CLIENT_TEST4_PROD] = {
		.valid		= true,
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 1,
			.ipa_gsi_chan_num	= 0,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 16,
			.ee			= IPA_EE_UC,
		},
	},
	[IPA_CLIENT_WLAN1_CONS] = {
		.valid		= true,
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 16,
			.ipa_gsi_chan_num	= 3,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 8,
			.ee			= IPA_EE_UC,
		},
	},
	[IPA_CLIENT_WLAN2_CONS] = {
		.valid		= true,
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 18,
			.ipa_gsi_chan_num	= 9,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 8,
			.ee			= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_WLAN3_CONS] = {
		.valid		= true,
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 19,
			.ipa_gsi_chan_num	= 10,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 8,
			.ee			= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_USB_CONS] = {
		.valid		= true,
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 17,
			.ipa_gsi_chan_num	= 8,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 8,
			.ee			= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_USB_DPL_CONS] = {
		.valid		= true,
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 11,
			.ipa_gsi_chan_num	= 2,
			.ipa_if_tlv		= 4,
			.ipa_if_aos		= 6,
			.ee			= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_APPS_LAN_CONS] = {
		.valid		= true,
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 9,
			.ipa_gsi_chan_num	= 5,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 12,
			.ee			= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_APPS_WAN_CONS] = {
		.valid		= true,
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 10,
			.ipa_gsi_chan_num	= 6,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 12,
			.ee			= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_Q6_LAN_CONS] = {
		.valid		= true,
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 13,
			.ipa_gsi_chan_num	= 3,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 12,
			.ee			= IPA_EE_Q6,
		},
	},
	[IPA_CLIENT_Q6_WAN_CONS] = {
		.valid		= true,
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 12,
			.ipa_gsi_chan_num	= 2,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 12,
			.ee			= IPA_EE_Q6,
		},
	},
	/* Only for testing */
	[IPA_CLIENT_TEST2_CONS] = {
		.valid		= true,
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 18,
			.ipa_gsi_chan_num	= 9,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 8,
			.ee			= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_TEST3_CONS] = {
		.valid		= true,
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 19,
			.ipa_gsi_chan_num	= 10,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 8,
			.ee			= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_TEST4_CONS] = {
		.valid		= true,
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 11,
			.ipa_gsi_chan_num	= 2,
			.ipa_if_tlv		= 4,
			.ipa_if_aos		= 6,
			.ee			= IPA_EE_AP,
		},
	},
/* Dummy consumer (pipe 31) is used in L2TP rt rule */
	[IPA_CLIENT_DUMMY_CONS] = {
		.valid		= true,
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ipa_ep_num		= 31,
			.ipa_gsi_chan_num	= 31,
			.ipa_if_tlv		= 8,
			.ipa_if_aos		= 8,
			.ee			= IPA_EE_AP,
		},
	},
};

static const struct ipa_ep_configuration *
ep_configuration(enum ipa_client_type client)
{
	return &ipa_ep_configuration[client];
}

/** ipa_get_gsi_ep_info() - provide gsi ep information
 * @client: IPA client value
 *
 * Return value: pointer to ipa_gsi_ep_info
 */
const struct ipa_gsi_ep_config *
ipa_get_gsi_ep_info(enum ipa_client_type client)
{
	const struct ipa_ep_configuration *ep_config;

	ep_config = ep_configuration(client);
	if (ep_config->valid)
		return &ep_config->ipa_gsi_ep_info;

	return NULL;
}

/** ipa_get_ep_mapping() - provide endpoint mapping
 * @client: client type
 *
 * Return value: endpoint mapping
 */
u32 ipa_get_ep_mapping(enum ipa_client_type client)
{
	const struct ipa_gsi_ep_config *ep_info = ipa_get_gsi_ep_info(client);

	ipa_assert(ep_info);

	return ep_info->ipa_ep_num;
}

struct ipa_ep_context *ipa_get_ep_context(enum ipa_client_type client)
{
	u32 ipa_ep_idx = ipa_get_ep_mapping(client);

	return &ipa_ctx->ep[ipa_ep_idx];
}

/** ipa_get_client_mapping() - provide client mapping
 * @pipe_idx: IPA end-point number
 *
 * Return value: client mapping
 */
enum ipa_client_type ipa_get_client_mapping(u32 pipe_idx)
{
	return ipa_ctx->ep[pipe_idx].client;
}

enum ipa_seq_type ipa_endp_seq_type(u32 ipa_ep_idx)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ipa_ep_idx];

	return ep_configuration(ep->client)->seq_type;
}

/** ipa_sram_settings_read() - Read SRAM settings from HW
 *
 * Returns:	None
 */
void ipa_sram_settings_read(void)
{
	struct ipa_reg_shared_mem_size mem_size;

	ipa_read_reg_fields(IPA_SHARED_MEM_SIZE, &mem_size);

	/* reg fields are in 8B units */
	ipa_ctx->smem_offset = mem_size.shared_mem_baddr * 8;
	ipa_ctx->smem_size = mem_size.shared_mem_size * 8;
}

/** ipa_cfg_qsb() - Configure IPA QSB maximal reads and writes
 *
 * Returns:	None
 */
void ipa_cfg_qsb(void)
{
	struct ipa_reg_qsb_max_reads max_reads = { };
	struct ipa_reg_qsb_max_writes max_writes = { };

	max_reads.qmb_0_max_reads = 8,
	max_reads.qmb_1_max_reads = 12;

	max_writes.qmb_0_max_writes = 8;
	max_writes.qmb_1_max_writes = 4;

	ipa_write_reg_fields(IPA_QSB_MAX_WRITES, &max_writes);
	ipa_write_reg_fields(IPA_QSB_MAX_READS, &max_reads);
}

/** ipa_init_hw() - initialize HW */
void ipa_init_hw(void)
{
	/* SDM845 has IPA version 3.5.1 */
	ipa_write_reg(IPA_BCR, IPA_BCR_REG_VAL);

	ipa_cfg_qsb();
}

/** ipa_filter_bitmap_init() - Initialize the bitmap
 * that represents the End-points that supports filtering
 */
u32 ipa_filter_bitmap_init(void)
{
	enum ipa_client_type cl;
	u32 filter_bitmap = 0;

	for (cl = 0; cl < IPA_CLIENT_MAX ; cl++) {
		const struct ipa_ep_configuration *ep_config;

		ep_config = ep_configuration(cl);
		if (!ep_config->support_flt)
			continue;
		filter_bitmap |= BIT(ep_config->ipa_gsi_ep_info.ipa_ep_num);
	}

	return filter_bitmap;
}

/* In IPAv3 only endpoints 0-3 can be configured to deaggregation */
bool ipa_endp_aggr_support(u32 ipa_ep_idx)
{
	return ipa_ep_idx < 4;
}

/** ipa_endp_init_hdr_write()
 *
 * @ipa_ep_idx:	endpoint whose header config register should be written
 */
static void ipa_endp_init_hdr_write(u32 ipa_ep_idx)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ipa_ep_idx];

	ipa_write_reg_n_fields(IPA_ENDP_INIT_HDR_N, ipa_ep_idx, &ep->init_hdr);
}

/** ipa_endp_init_hdr_ext_write() - write endpoint extended header register
 *
 * @ipa_ep_idx:	endpoint whose register should be written
 */
static void
ipa_endp_init_hdr_ext_write(u32 ipa_ep_idx)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ipa_ep_idx];

	ipa_write_reg_n_fields(IPA_ENDP_INIT_HDR_EXT_N, ipa_ep_idx,
			       &ep->hdr_ext);
}

/** ipa_endp_init_aggr_write() write endpoint aggregation register
 *
 * @ipa_ep_idx:	endpoint whose aggregation config register should be written
 */
static void ipa_endp_init_aggr_write(u32 clnt_hdl)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[clnt_hdl];

	ipa_write_reg_n_fields(IPA_ENDP_INIT_AGGR_N, clnt_hdl,
			       &ep->init_aggr);
}

/** ipa_endp_init_cfg_write() - write endpoint configuration register
 *
 * @ipa_ep_idx:	endpoint whose configuration register should be written
 */
static void ipa_endp_init_cfg_write(u32 ipa_ep_idx)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ipa_ep_idx];

	ipa_write_reg_n_fields(IPA_ENDP_INIT_CFG_N, ipa_ep_idx, &ep->init_cfg);
}

/** ipa_endp_init_mode_write() - write endpoint mode register
 *
 * @ipa_ep_idx:	endpoint whose register should be written
 */
static void ipa_endp_init_mode_write(u32 ipa_ep_idx)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ipa_ep_idx];

	ipa_write_reg_n_fields(IPA_ENDP_INIT_MODE_N, ipa_ep_idx,
			       &ep->init_mode);
}

/** ipa_endp_init_seq_write() - write endpoint sequencer register
 *
 * @ipa_ep_idx:	endpoint whose register should be written
 */
static void ipa_endp_init_seq_write(u32 ipa_ep_idx)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ipa_ep_idx];

	ipa_write_reg_n_fields(IPA_ENDP_INIT_SEQ_N, ipa_ep_idx, &ep->init_seq);
}

/** ipa_endp_init_deaggr_write() - write endpoint deaggregation register
 *
 * @ipa_ep_idx:	endpoint whose register should be written
 */
void ipa_endp_init_deaggr_write(u32 ipa_ep_idx)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ipa_ep_idx];

	ipa_write_reg_n_fields(IPA_ENDP_INIT_DEAGGR_N, ipa_ep_idx,
			       &ep->init_deaggr);
}

/** ipa_endp_init_hdr_metadata_mask_write() - endpoint metadata mask register
 *
 * @ipa_ep_idx:	endpoint whose register should be written
 */
static void ipa_endp_init_hdr_metadata_mask_write(u32 ipa_ep_idx)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ipa_ep_idx];

	ipa_write_reg_n_fields(IPA_ENDP_INIT_HDR_METADATA_MASK_N, ipa_ep_idx,
			       &ep->metadata_mask);
}

/** ipa_endp_init_hdr_metadata_mask_write() - endpoint metadata mask register
 *
 * @ipa_ep_idx:	endpoint whose register should be written
 */
static void ipa_endp_status_write(u32 ipa_ep_idx)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ipa_ep_idx];

	ipa_write_reg_n_fields(IPA_ENDP_STATUS_N, ipa_ep_idx, &ep->status);
}

/** ipa_cfg_ep - IPA end-point configuration
 * @clnt_hdl:	[in] opaque client handle assigned by IPA to client
 * @dst:	[in] destination client handle (ignored for consumer clients)
 *
 * This includes nat, IPv6CT, header, mode, aggregation and route settings and
 * is a one shot API to configure the IPA end-point fully
 *
 * Returns:	0 on success, negative on failure
 *
 * Note:	Should not be called from atomic context
 */
void ipa_cfg_ep(u32 clnt_hdl)
{
	ipa_endp_init_hdr_write(clnt_hdl);
	ipa_endp_init_hdr_ext_write(clnt_hdl);

	ipa_endp_init_aggr_write(clnt_hdl);
	ipa_endp_init_cfg_write(clnt_hdl);

	if (ipa_producer(ipa_ctx->ep[clnt_hdl].client)) {
		ipa_endp_init_mode_write(clnt_hdl);
		ipa_endp_init_seq_write(clnt_hdl);
		ipa_endp_init_deaggr_write(clnt_hdl);
	} else {
		ipa_endp_init_hdr_metadata_mask_write(clnt_hdl);
	}

	ipa_endp_status_write(clnt_hdl);
}

static void suspend_consumer_endpoint(u32 ipa_ep_idx)
{
	struct ipa_reg_endp_init_ctrl init_ctrl = { .endp_suspend = 1 };

	ipa_write_reg_n_fields(IPA_ENDP_INIT_CTRL_N, ipa_ep_idx, &init_ctrl);

	/* Due to a hardware bug, a client suspended with an open
	 * aggregation frame will not generate a SUSPEND IPA interrupt.
	 * We work around this by force-closing the aggregation frame,
	 * then simulating the arrival of such an interrupt.
	 */
	ipa_suspend_active_aggr_wa(ipa_ep_idx);
}

static void resume_consumer_endpoint(u32 ipa_ep_idx)
{
	struct ipa_reg_endp_init_ctrl init_ctrl = { .endp_suspend = 0 };

	ipa_write_reg_n_fields(IPA_ENDP_INIT_CTRL_N, ipa_ep_idx, &init_ctrl);
}

/* Interconnect path bandwidths (each times 1000 bytes per second) */
#define IPA_MEMORY_AVG	80000
#define IPA_MEMORY_PEAK	600000

#define IPA_IMEM_AVG	80000
#define IPA_IMEM_PEAK	350000

#define IPA_CONFIG_AVG	40000
#define IPA_CONFIG_PEAK	40000

int ipa_interconnect_init(struct device *dev)
{
	struct icc_path *path;

	path = of_icc_get(dev, "memory");
	if (IS_ERR(path))
		goto err_return;
	ipa_ctx->memory_path = path;

	path = of_icc_get(dev, "imem");
	if (IS_ERR(path))
		goto err_memory_path_put;
	ipa_ctx->imem_path = path;

	path = of_icc_get(dev, "config");
	if (IS_ERR(path))
		goto err_imem_path_put;
	ipa_ctx->config_path = path;

	return 0;

err_imem_path_put:
	icc_put(ipa_ctx->imem_path);
	ipa_ctx->imem_path = NULL;
err_memory_path_put:
	icc_put(ipa_ctx->memory_path);
	ipa_ctx->memory_path = NULL;
err_return:

	return PTR_ERR(path);
}

void ipa_interconnect_exit(void)
{
	icc_put(ipa_ctx->config_path);
	ipa_ctx->config_path = NULL;

	icc_put(ipa_ctx->imem_path);
	ipa_ctx->imem_path = NULL;

	icc_put(ipa_ctx->memory_path);
	ipa_ctx->memory_path = NULL;
}

/* Currently we only use bandwidth level, so just "enable" interconnects */
int ipa_interconnect_enable(void)
{
	int ret;

	ret = icc_set(ipa_ctx->memory_path, IPA_MEMORY_AVG, IPA_MEMORY_PEAK);
	if (ret)
		return ret;

	ret = icc_set(ipa_ctx->imem_path, IPA_IMEM_AVG, IPA_IMEM_PEAK);
	if (ret)
		goto err_disable_memory_path;

	ret = icc_set(ipa_ctx->config_path, IPA_CONFIG_AVG, IPA_CONFIG_PEAK);
	if (!ret)
		return 0;	/* Success */

	(void)icc_set(ipa_ctx->imem_path, 0, 0);
err_disable_memory_path:
	(void)icc_set(ipa_ctx->memory_path, 0, 0);

	return ret;
}

/* To disable an interconnect, we just its bandwidth to 0 */
int ipa_interconnect_disable(void)
{
	int ret;

	ret = icc_set(ipa_ctx->memory_path, 0, 0);
	if (ret)
		return ret;

	ret = icc_set(ipa_ctx->imem_path, 0, 0);
	if (ret)
		goto err_reenable_memory_path;

	ret = icc_set(ipa_ctx->config_path, 0, 0);
	if (!ret)
		return 0;	/* Success */

	/* Re-enable things in the event of an error */
	(void)icc_set(ipa_ctx->imem_path, IPA_IMEM_AVG, IPA_IMEM_PEAK);
err_reenable_memory_path:
	(void)icc_set(ipa_ctx->memory_path, IPA_MEMORY_AVG, IPA_MEMORY_PEAK);

	return ret;
}

/** ipa_proxy_clk_unvote() - called to remove IPA clock proxy vote
 *
 * Return value: none
 */
void ipa_proxy_clk_unvote(void)
{
	if (ipa_ctx->q6_proxy_clk_vote_valid) {
		ipa_client_remove();
		ipa_ctx->q6_proxy_clk_vote_valid = false;
	}
}

/** ipa_proxy_clk_vote() - called to add IPA clock proxy vote
 *
 * Return value: none
 */
void ipa_proxy_clk_vote(void)
{
	if (!ipa_ctx->q6_proxy_clk_vote_valid) {
		ipa_client_add();
		ipa_ctx->q6_proxy_clk_vote_valid = true;
	}
}

u32 ipa_get_num_pipes(void)
{
	return ipa_read_reg(IPA_ENABLED_PIPES);
}

/** ipa_is_modem_pipe()- Checks if pipe is owned by the modem
 *
 * @pipe_idx: pipe number
 * Return value: true if owned by modem, false otherwize
 */
bool ipa_is_modem_pipe(u32 pipe_idx)
{
	int client_idx;

	for (client_idx = 0; client_idx < IPA_CLIENT_MAX; client_idx++) {
		if (!ipa_modem_consumer(client_idx) &&
		    !ipa_modem_producer(client_idx))
			continue;
		if (ipa_get_ep_mapping(client_idx) == pipe_idx)
			return true;
	}

	return false;
}

static void write_src_rsrc_grp_limits(enum ipa_reg reg,
				      enum ipa_rsrc_grp_type_src n,
				      const struct rsrc_min_max *x_limits,
				      const struct rsrc_min_max *y_limits)
{
	struct ipa_reg_rsrc_grp_cfg val;

	val.x_min = x_limits->min;
	val.x_max = x_limits->max;
	val.y_min = y_limits->min;
	val.y_max = y_limits->max;

	ipa_write_reg_n_fields(reg, n, &val);
}

static void
ipa_write_src_rsrc_grp_type_reg(int group_index, enum ipa_rsrc_grp_type_src n)
{
	const struct rsrc_min_max *x_limits;
	const struct rsrc_min_max *y_limits;
	enum ipa_reg reg;

	if (group_index == IPA_GROUP_UC_RX_Q) {
		reg = IPA_SRC_RSRC_GRP_23_RSRC_TYPE_N;
	} else {
		ipa_assert(group_index == IPA_GROUP_LWA_DL ||
			   group_index == IPA_GROUP_UL_DL);
		reg = IPA_SRC_RSRC_GRP_01_RSRC_TYPE_N;
	}

	x_limits = &ipa_rsrc_src_grp_config[n][group_index];
	y_limits = &ipa_rsrc_src_grp_config[n][group_index + 1];

	write_src_rsrc_grp_limits(reg, n, x_limits, y_limits);
}

static void
ipa_write_dst_rsrc_grp_type_reg(int group_index, enum ipa_rsrc_grp_type_src n)
{
	enum ipa_reg reg = IPA_DST_RSRC_GRP_01_RSRC_TYPE_N;
	const struct rsrc_min_max *x_limits;
	const struct rsrc_min_max *y_limits;

	ipa_assert(group_index == IPA_GROUP_LWA_DL ||
		   group_index == IPA_GROUP_UL_DL);

	x_limits = &ipa_rsrc_dst_grp_config[n][group_index];
	y_limits = &ipa_rsrc_dst_grp_config[n][group_index + 1];

	write_src_rsrc_grp_limits(reg, n, x_limits, y_limits);
}

void ipa_set_resource_groups_min_max_limits(void)
{
	int src_rsrc_type_max = IPA_RSRC_GRP_TYPE_SRC_MAX;
	int dst_rsrc_type_max = IPA_RSRC_GRP_TYPE_DST_MAX;
	int src_grp_idx_max = IPA_SRC_GROUP_MAX;
	int dst_grp_idx_max = IPA_DST_GROUP_MAX;
	int i;
	int j;

	ipa_debug("ENTER\n");

	ipa_debug("Assign source rsrc groups min-max limits\n");
	for (i = 0; i < src_rsrc_type_max; i++)
		for (j = 0; j < src_grp_idx_max; j = j + 2)
			if (j != IPA_MHI_GROUP_DMA)
				ipa_write_src_rsrc_grp_type_reg(j, i);

	ipa_debug("Assign destination rsrc groups min-max limits\n");
	for (i = 0; i < dst_rsrc_type_max; i++)
		for (j = 0; j < dst_grp_idx_max; j = j + 2)
			if (j != IPA_MHI_GROUP_DMA)
				ipa_write_dst_rsrc_grp_type_reg(j, i);
}

static void ipa_gsi_poll_after_suspend(struct ipa_ep_context *ep)
{
	ipa_debug("switch ch %ld to poll\n", ep->gsi_chan_hdl);
	ipa_rx_switch_to_poll_mode(ep->sys);
}

/* Suspend a consumer pipe */
static void suspend_consumer_pipe(enum ipa_client_type client)
{
	u32 ipa_ep_idx = ipa_get_ep_mapping(client);
	struct ipa_ep_context *ep = &ipa_ctx->ep[ipa_ep_idx];

	ipa_debug("pipe %u\n", ipa_ep_idx);

	suspend_consumer_endpoint(ipa_ep_idx);
	ipa_gsi_poll_after_suspend(ep);
}

void ipa_suspend_apps_pipes(void)
{
	suspend_consumer_pipe(IPA_CLIENT_APPS_WAN_CONS);
	suspend_consumer_pipe(IPA_CLIENT_APPS_LAN_CONS);
}

/* Resume a suspended consumer pipe */
static void resume_consumer_pipe(enum ipa_client_type client)
{
	u32 ipa_ep_idx = ipa_get_ep_mapping(client);
	struct ipa_ep_context *ep = &ipa_ctx->ep[ipa_ep_idx];

	ipa_debug("pipe %u\n", ipa_ep_idx);

	resume_consumer_endpoint(ipa_ep_idx);
	if (!ipa_ep_polling(ep))
		gsi_channel_intr_enable(ipa_ctx->gsi, ep->gsi_chan_hdl);
}

void ipa_resume_apps_pipes(void)
{
	resume_consumer_pipe(IPA_CLIENT_APPS_LAN_CONS);
	resume_consumer_pipe(IPA_CLIENT_APPS_WAN_CONS);
}

/** ipa_cfg_route() - configure IPA route
 * @route: IPA route
 *
 * Return codes:
 * 0: success
 */
void ipa_cfg_default_route(enum ipa_client_type client)
{
	struct ipa_reg_route route = { };
	u32 ipa_ep_idx;

	ipa_ep_idx = ipa_get_ep_mapping(client);

	ipa_debug("dis=0, def_pipe=%u, hdr_tbl=1 hdr_ofst=0\n", ipa_ep_idx);
	ipa_debug("frag_def_pipe=%u def_retain_hdr=1\n", ipa_ep_idx);

	route.route_def_pipe = ipa_ep_idx;
	route.route_def_hdr_table = 1;
	route.route_frag_def_pipe = ipa_ep_idx;
	route.route_def_retain_hdr = 1;

	ipa_client_add();

	ipa_write_reg_fields(IPA_ROUTE, &route);

	ipa_client_remove();
}

/* In certain cases we need to issue a command to reliably clear the
 * IPA pipeline.  Sending a 1-byte DMA task is sufficient, and this
 * function preallocates a command to do just that.  There are
 * conditions (process context in KILL state) where DMA allocations
 * can fail, and we need to be able to issue this command to put the
 * hardware in a known state.  By preallocating the command here we
 * guarantee it can't fail for that reason.
 */
int ipa_gsi_dma_task_alloc(void)
{
	struct ipa_dma_mem *mem = &ipa_ctx->dma_task_info.mem;

	if (ipa_dma_alloc(mem, IPA_GSI_CHANNEL_STOP_PKT_SIZE, GFP_KERNEL))
		return -ENOMEM;

	ipa_ctx->dma_task_info.cmd_pyld = ipahal_dma_task_32b_addr_pyld(mem);
	if (!ipa_ctx->dma_task_info.cmd_pyld) {
		ipa_err("failed to construct dma_task_32b_addr cmd\n");
		ipa_dma_free(mem);

		return -ENOMEM;
	}

	return 0;
}

void ipa_gsi_dma_task_free(void)
{
	struct ipa_dma_mem *mem = &ipa_ctx->dma_task_info.mem;

	ipahal_destroy_imm_cmd(ipa_ctx->dma_task_info.cmd_pyld);
	ipa_ctx->dma_task_info.cmd_pyld = NULL;
	ipa_dma_free(mem);
}

/** ipa_gsi_dma_task_inject()- Send DMA_TASK to IPA for GSI stop channel
 *
 * Send a DMA_TASK of 1B to IPA to unblock GSI channel in STOP_IN_PROG.
 * Return value: 0 on success, negative otherwise
 */
int ipa_gsi_dma_task_inject(void)
{
	struct ipa_desc desc = { };

	ipa_desc_fill_imm_cmd(&desc, ipa_ctx->dma_task_info.cmd_pyld);

	ipa_debug("sending 1B packet to IPA\n");
	if (ipa_send_cmd_timeout(&desc, IPA_GSI_DMA_TASK_TIMEOUT)) {
		ipa_err("ipa_send_cmd failed\n");

		return -EFAULT;
	}

	return 0;
}

/** ipa_stop_gsi_channel()- Stops a GSI channel in IPA
 * @chan_hdl: GSI channel handle
 *
 * This function implements the sequence to stop a GSI channel
 * in IPA. This function returns when the channel is is STOP state.
 *
 * Return value: 0 on success, negative otherwise
 */
int ipa_stop_gsi_channel(u32 clnt_hdl)
{
	int res = 0;
	int i;
	struct ipa_ep_context *ep;

	ep = &ipa_ctx->ep[clnt_hdl];

	ipa_client_add();

	if (ipa_producer(ep->client)) {
		ipa_debug("Calling gsi_stop_channel ch:%lu\n",
			  ep->gsi_chan_hdl);
		res = gsi_stop_channel(ipa_ctx->gsi, ep->gsi_chan_hdl);
		ipa_debug("gsi_stop_channel ch: %lu returned %d\n",
			  ep->gsi_chan_hdl, res);
		goto end_sequence;
	}

	for (i = 0; i < IPA_GSI_CHANNEL_STOP_MAX_RETRY; i++) {
		ipa_debug("Calling gsi_stop_channel ch:%lu\n",
			  ep->gsi_chan_hdl);
		res = gsi_stop_channel(ipa_ctx->gsi, ep->gsi_chan_hdl);
		ipa_debug("gsi_stop_channel ch: %lu returned %d\n",
			  ep->gsi_chan_hdl, res);
		if (res != -EAGAIN && res != -ETIMEDOUT)
			goto end_sequence;

		ipa_debug("Inject a DMA_TASK with 1B packet to IPA\n");
		/* Send a 1B packet DMA_TASK to IPA and try again */
		res = ipa_gsi_dma_task_inject();
		if (res) {
			ipa_err("Failed to inject DMA TASk for GSI\n");
			goto end_sequence;
		}

		/* sleep for short period to flush IPA */
		usleep_range(IPA_GSI_CHANNEL_STOP_SLEEP_MIN,
			     IPA_GSI_CHANNEL_STOP_SLEEP_MAX);
	}

	ipa_err("Failed	 to stop GSI channel with retries\n");
	res = -EFAULT;
end_sequence:
	ipa_client_remove();

	return res;
}

/** ipa_enable_dcd() - enable dynamic clock division on IPA
 *
 * Return value: Non applicable
 *
 */
void ipa_enable_dcd(void)
{
	struct ipa_reg_idle_indication_cfg idle_indication_cfg;

	/* recommended values for IPA 3.5 according to IPA HPG */
	idle_indication_cfg.const_non_idle_enable = 0;
	idle_indication_cfg.enter_idle_debounce_thresh = 256;

	ipa_write_reg_fields(IPA_IDLE_INDICATION_CFG, &idle_indication_cfg);
}

/** ipa_set_flt_tuple_mask() - Sets the flt tuple masking for the given pipe
 *  Pipe must be for AP EP (not modem) and support filtering
 *  updates the the filtering masking values without changing the rt ones.
 *
 * @pipe_idx: filter pipe index to configure the tuple masking
 * @tuple: the tuple members masking
 * Returns:	0 on success, negative on failure
 *
 */
void ipa_set_flt_tuple_mask(u32 pipe_idx, struct ipa_reg_hash_tuple *tuple)
{
	struct ipa_ep_filter_router_hsh_cfg hsh_cfg;

	ipa_read_reg_n_fields(IPA_ENDP_FILTER_ROUTER_HSH_CFG_N, pipe_idx,
			      &hsh_cfg);

	hsh_cfg.flt.src_id = tuple->src_id;
	hsh_cfg.flt.src_ip = tuple->src_ip;
	hsh_cfg.flt.dst_ip = tuple->dst_ip;
	hsh_cfg.flt.src_port = tuple->src_port;
	hsh_cfg.flt.dst_port = tuple->dst_port;
	hsh_cfg.flt.protocol = tuple->protocol;
	hsh_cfg.flt.metadata = tuple->metadata;

	ipa_write_reg_n_fields(IPA_ENDP_FILTER_ROUTER_HSH_CFG_N, pipe_idx,
			       &hsh_cfg);
}

/** ipa_set_rt_tuple_mask() - Sets the rt tuple masking for the given tbl
 *  table index must be for AP EP (not modem)
 *  updates the the routing masking values without changing the flt ones.
 *
 * @tbl_idx: routing table index to configure the tuple masking
 * @tuple: the tuple members masking
 * Returns:	 0 on success, negative on failure
 *
 */
void ipa_set_rt_tuple_mask(int tbl_idx, struct ipa_reg_hash_tuple *tuple)
{
	struct ipa_ep_filter_router_hsh_cfg hsh_cfg;

	ipa_read_reg_n_fields(IPA_ENDP_FILTER_ROUTER_HSH_CFG_N, tbl_idx,
			      &hsh_cfg);

	hsh_cfg.rt.src_id = tuple->src_id;
	hsh_cfg.rt.src_ip = tuple->src_ip;
	hsh_cfg.rt.dst_ip = tuple->dst_ip;
	hsh_cfg.rt.src_port = tuple->src_port;
	hsh_cfg.rt.dst_port = tuple->dst_port;
	hsh_cfg.rt.protocol = tuple->protocol;
	hsh_cfg.rt.metadata = tuple->metadata;

	ipa_write_reg_n_fields(IPA_ENDP_FILTER_ROUTER_HSH_CFG_N, tbl_idx,
			       &hsh_cfg);
}

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("IPA HW device driver");
