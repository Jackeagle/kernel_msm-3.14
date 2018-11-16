// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */

#include <linux/types.h>
#include <linux/device.h>
#include <linux/interconnect.h>
#include <linux/module.h>
#include <linux/delay.h>

#include "ipa_i.h"
#include "ipahal.h"

#define IPA_BCR_REG_VAL			0x0000003b

#define IPA_GSI_DMA_TASK_TIMEOUT	15	/* milliseconds */

#define IPA_GSI_CHANNEL_STOP_SLEEP_MIN	1000	/* microseconds */
#define IPA_GSI_CHANNEL_STOP_SLEEP_MAX	2000	/* microseconds */

#define QMB_MASTER_SELECT_DDR		0

enum ipa_rsrc_group {
	IPA_RSRC_GROUP_LWA_DL,	/* currently not used */
	IPA_RSRC_GROUP_UL_DL,
	IPA_RSRC_GROUP_MAX,
};

enum ipa_rsrc_grp_type_src {
	IPA_RSRC_GRP_TYPE_SRC_PKT_CONTEXTS,
	IPA_RSRC_GRP_TYPE_SRS_DESCRIPTOR_LISTS,
	IPA_RSRC_GRP_TYPE_SRC_DESCRIPTOR_BUFF,
	IPA_RSRC_GRP_TYPE_SRC_HPS_DMARS,
	IPA_RSRC_GRP_TYPE_SRC_ACK_ENTRIES,
};

enum ipa_rsrc_grp_type_dst {
	IPA_RSRC_GRP_TYPE_DST_DATA_SECTORS,
	IPA_RSRC_GRP_TYPE_DST_DPS_DMARS,
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
static const struct rsrc_min_max ipa_src_rsrc_grp[][IPA_RSRC_GROUP_MAX] = {
	[IPA_RSRC_GRP_TYPE_SRC_PKT_CONTEXTS] = {
		[IPA_RSRC_GROUP_LWA_DL]	= { .min = 1,	.max = 63, },
		[IPA_RSRC_GROUP_UL_DL]	= { .min = 1,	.max = 63, },
	},
	[IPA_RSRC_GRP_TYPE_SRS_DESCRIPTOR_LISTS] = {
		[IPA_RSRC_GROUP_LWA_DL]	= { .min = 10,	.max = 10, },
		[IPA_RSRC_GROUP_UL_DL]	= { .min = 10,	.max = 10, },
	},
	[IPA_RSRC_GRP_TYPE_SRC_DESCRIPTOR_BUFF] = {
		[IPA_RSRC_GROUP_LWA_DL]	= { .min = 12,	.max = 12, },
		[IPA_RSRC_GROUP_UL_DL]	= { .min = 14,	.max = 14, },
	},
	[IPA_RSRC_GRP_TYPE_SRC_HPS_DMARS] = {
		[IPA_RSRC_GROUP_LWA_DL]	= { .min = 0,	.max = 63, },
		[IPA_RSRC_GROUP_UL_DL]	= { .min = 0,	.max = 63, },
	},
	[IPA_RSRC_GRP_TYPE_SRC_ACK_ENTRIES] = {
		[IPA_RSRC_GROUP_LWA_DL]	= { .min = 14,	.max = 14, },
		[IPA_RSRC_GROUP_UL_DL]	= { .min = 20,	.max = 20, },
	},
};

/* IPA_HW_v3_5_1 */
static const struct rsrc_min_max ipa_dst_rsrc_grp[][IPA_RSRC_GROUP_MAX] = {
	[IPA_RSRC_GRP_TYPE_DST_DATA_SECTORS] = {
		[IPA_RSRC_GROUP_LWA_DL]	= { .min = 4,	.max = 4, },
		[IPA_RSRC_GROUP_UL_DL]	= { .min = 4,	.max = 4, },
	},
	[IPA_RSRC_GRP_TYPE_DST_DPS_DMARS] = {
		[IPA_RSRC_GROUP_LWA_DL]	= { .min = 2,	.max = 63, },
		[IPA_RSRC_GROUP_UL_DL]	= { .min = 1,	.max = 63, },
	},
};

/**
 * struct ipa_gsi_ep_config - GSI endpoint configuration.
 * @ep_id:	IPA endpoint identifier.
 * @channel_id:	GSI channel number used for this endpoint.
 * @tlv_count:	The number of TLV (type-length-value) entries for the channel.
 * @ee:		Execution environment endpoint is associated with.
 *
 * Each GSI endpoint has a set of configuration parameters defined within
 * entries in the ipa_ep_configuration[] array.  Its @ep_id field uniquely
 * defines the endpoint, and @channel_id defines which data channel (ring
 * buffer) is used for the endpoint.
 * XXX TLV
 * XXX ee is never used in the code
 */
struct ipa_gsi_ep_config {
	u32 ep_id;
	u32 channel_id;
	u32 tlv_count;
	u32 ee;
};

struct ipa_ep_configuration {
	bool support_flt;
	enum ipa_seq_type seq_type;
	struct ipa_gsi_ep_config ipa_gsi_ep_info;
};

/* IPA_HW_v3_5_1 */
/* clients not included in the list below are considered as invalid */
static const struct ipa_ep_configuration ipa_ep_configuration[] = {
	[IPA_CLIENT_WLAN1_PROD] = {
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ep_id		= 7,
			.channel_id	= 1,
			.tlv_count	= 8,
			.ee		= IPA_EE_UC,
		},
	},
	[IPA_CLIENT_USB_PROD] = {
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ep_id		= 0,
			.channel_id	= 0,
			.tlv_count	= 8,
			.ee		= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_APPS_LAN_PROD] = {
		.support_flt	= false,
		.seq_type	= IPA_SEQ_PKT_PROCESS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ep_id		= 8,
			.channel_id	= 7,
			.tlv_count	= 8,
			.ee		= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_APPS_WAN_PROD] = {
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ep_id		= 2,
			.channel_id	= 3,
			.tlv_count	= 16,
			.ee		= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_APPS_CMD_PROD] = {
		.support_flt	= false,
		.seq_type	= IPA_SEQ_DMA_ONLY,
		.ipa_gsi_ep_info = {
			.ep_id		= 5,
			.channel_id	= 4,
			.tlv_count	= 20,
			.ee		= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_Q6_LAN_PROD] = {
		.support_flt	= true,
		.seq_type	= IPA_SEQ_PKT_PROCESS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ep_id		= 3,
			.channel_id	= 0,
			.tlv_count	= 16,
			.ee		= IPA_EE_Q6,
		},
	},
	[IPA_CLIENT_Q6_WAN_PROD] = {
		.support_flt	= true,
		.seq_type	= IPA_SEQ_PKT_PROCESS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ep_id		= 6,
			.channel_id	= 4,
			.tlv_count	= 12,
			.ee		= IPA_EE_Q6,
		},
	},
	[IPA_CLIENT_Q6_CMD_PROD] = {
		.support_flt	= false,
		.seq_type	= IPA_SEQ_PKT_PROCESS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ep_id		= 4,
			.channel_id	= 1,
			.tlv_count	= 20,
			.ee		= IPA_EE_Q6,
		},
	},
	[IPA_CLIENT_TEST_CONS] = {
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ep_id		= 14,
			.channel_id	= 5,
			.tlv_count	= 8,
			.ee		= IPA_EE_Q6,
		},
	},
	[IPA_CLIENT_TEST1_CONS] = {
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ep_id		= 15,
			.channel_id	= 2,
			.tlv_count	= 8,
			.ee		= IPA_EE_UC,
		},
	},
	/* Only for testing */
	[IPA_CLIENT_TEST_PROD] = {
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ep_id		= 0,
			.channel_id	= 0,
			.tlv_count	= 8,
			.ee		= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_TEST1_PROD] = {
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ep_id		= 0,
			.channel_id	= 0,
			.tlv_count	= 8,
			.ee		= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_TEST2_PROD] = {
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ep_id		= 2,
			.channel_id	= 3,
			.tlv_count	= 16,
			.ee		= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_TEST3_PROD] = {
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ep_id		= 4,
			.channel_id	= 1,
			.tlv_count	= 20,
			.ee		= IPA_EE_Q6,
		},
	},
	[IPA_CLIENT_TEST4_PROD] = {
		.support_flt	= true,
		.seq_type	= IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP,
		.ipa_gsi_ep_info = {
			.ep_id		= 1,
			.channel_id	= 0,
			.tlv_count	= 8,
			.ee		= IPA_EE_UC,
		},
	},
	[IPA_CLIENT_WLAN1_CONS] = {
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ep_id		= 16,
			.channel_id	= 3,
			.tlv_count	= 8,
			.ee		= IPA_EE_UC,
		},
	},
	[IPA_CLIENT_WLAN2_CONS] = {
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ep_id		= 18,
			.channel_id	= 9,
			.tlv_count	= 8,
			.ee		= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_WLAN3_CONS] = {
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ep_id		= 19,
			.channel_id	= 10,
			.tlv_count	= 8,
			.ee		= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_USB_CONS] = {
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ep_id		= 17,
			.channel_id	= 8,
			.tlv_count	= 8,
			.ee		= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_USB_DPL_CONS] = {
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ep_id		= 11,
			.channel_id	= 2,
			.tlv_count	= 4,
			.ee		= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_APPS_LAN_CONS] = {
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ep_id		= 9,
			.channel_id	= 5,
			.tlv_count	= 8,
			.ee		= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_APPS_WAN_CONS] = {
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ep_id		= 10,
			.channel_id	= 6,
			.tlv_count	= 8,
			.ee		= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_Q6_LAN_CONS] = {
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ep_id		= 13,
			.channel_id	= 3,
			.tlv_count	= 8,
			.ee		= IPA_EE_Q6,
		},
	},
	[IPA_CLIENT_Q6_WAN_CONS] = {
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ep_id		= 12,
			.channel_id	= 2,
			.tlv_count	= 8,
			.ee		= IPA_EE_Q6,
		},
	},
	/* Only for testing */
	[IPA_CLIENT_TEST2_CONS] = {
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ep_id		= 18,
			.channel_id	= 9,
			.tlv_count	= 8,
			.ee		= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_TEST3_CONS] = {
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ep_id		= 19,
			.channel_id	= 10,
			.tlv_count	= 8,
			.ee		= IPA_EE_AP,
		},
	},
	[IPA_CLIENT_TEST4_CONS] = {
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ep_id		= 11,
			.channel_id	= 2,
			.tlv_count	= 4,
			.ee		= IPA_EE_AP,
		},
	},
/* Dummy consumer (endpoint 31) is used in L2TP rt rule */
	[IPA_CLIENT_DUMMY_CONS] = {
		.support_flt	= false,
		.seq_type	= IPA_SEQ_INVALID,
		.ipa_gsi_ep_info = {
			.ep_id		= 31,
			.channel_id	= 31,
			.tlv_count	= 8,
			.ee		= IPA_EE_AP,
		},
	},
};

/** ipa_client_ep_id() - provide endpoint mapping
 * @client: client type
 *
 * Return value: endpoint mapping
 */
u32 ipa_client_ep_id(enum ipa_client_type client)
{
	return ipa_ep_configuration[client].ipa_gsi_ep_info.ep_id;
}

u32 ipa_client_channel_id(enum ipa_client_type client)
{
	return ipa_ep_configuration[client].ipa_gsi_ep_info.channel_id;
}

u32 ipa_client_tlv_count(enum ipa_client_type client)
{
	return ipa_ep_configuration[client].ipa_gsi_ep_info.tlv_count;
}

enum ipa_seq_type ipa_endp_seq_type(u32 ep_id)
{
	return ipa_ep_configuration[ipa_ctx->ep[ep_id].client].seq_type;
}

/** ipa_hardware_init() - Primitive hardware initialization */
void ipa_hardware_init(struct ipa_context *ipa)
{
	struct ipa_reg_qsb_max_writes max_writes;
	struct ipa_reg_qsb_max_reads max_reads;

	/* SDM845 has IPA version 3.5.1 */
	ipa_write_reg(IPA_BCR, IPA_BCR_REG_VAL);

	ipa_reg_qsb_max_writes(&max_writes, 8, 4);
	ipa_write_reg_fields(IPA_QSB_MAX_WRITES, &max_writes);

	ipa_reg_qsb_max_reads(&max_reads, 8, 12);
	ipa_write_reg_fields(IPA_QSB_MAX_READS, &max_reads);
}

/** ipa_filter_bitmap_init() - Initialize the bitmap
 * that represents the End-points that supports filtering
 */
u32 ipa_filter_bitmap_init(void)
{
	enum ipa_client_type client;
	u32 filter_bitmap = 0;
	u32 count = 0;

	for (client = 0; client < IPA_CLIENT_MAX ; client++) {
		const struct ipa_ep_configuration *ep_config;

		ep_config = &ipa_ep_configuration[client];
		if (!ep_config->support_flt)
			continue;
		if (++count > IPA_MEM_FLT_COUNT)
			return 0;	/* Too many filtering endpoints */

		filter_bitmap |= BIT(ep_config->ipa_gsi_ep_info.ep_id);
	}

	return filter_bitmap;
}

/* In IPAv3 only endpoints 0-3 can be configured to deaggregation */
bool ipa_endp_aggr_support(u32 ep_id)
{
	return ep_id < 4;
}

/** ipa_endp_init_hdr_write()
 *
 * @ep_id:	endpoint whose header config register should be written
 */
static void ipa_endp_init_hdr_write(u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ep_id];

	ipa_write_reg_n_fields(IPA_ENDP_INIT_HDR_N, ep_id, &ep->init_hdr);
}

/** ipa_endp_init_hdr_ext_write() - write endpoint extended header register
 *
 * @ep_id:	endpoint whose register should be written
 */
static void
ipa_endp_init_hdr_ext_write(u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ep_id];

	ipa_write_reg_n_fields(IPA_ENDP_INIT_HDR_EXT_N, ep_id,
			       &ep->hdr_ext);
}

/** ipa_endp_init_aggr_write() write endpoint aggregation register
 *
 * @ep_id:	endpoint whose aggregation config register should be written
 */
static void ipa_endp_init_aggr_write(u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ep_id];

	ipa_write_reg_n_fields(IPA_ENDP_INIT_AGGR_N, ep_id, &ep->init_aggr);
}

/** ipa_endp_init_cfg_write() - write endpoint configuration register
 *
 * @ep_id:	endpoint whose configuration register should be written
 */
static void ipa_endp_init_cfg_write(u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ep_id];

	ipa_write_reg_n_fields(IPA_ENDP_INIT_CFG_N, ep_id, &ep->init_cfg);
}

/** ipa_endp_init_mode_write() - write endpoint mode register
 *
 * @ep_id:	endpoint whose register should be written
 */
static void ipa_endp_init_mode_write(u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ep_id];

	ipa_write_reg_n_fields(IPA_ENDP_INIT_MODE_N, ep_id,
			       &ep->init_mode);
}

/** ipa_endp_init_seq_write() - write endpoint sequencer register
 *
 * @ep_id:	endpoint whose register should be written
 */
static void ipa_endp_init_seq_write(u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ep_id];

	ipa_write_reg_n_fields(IPA_ENDP_INIT_SEQ_N, ep_id, &ep->init_seq);
}

/** ipa_endp_init_deaggr_write() - write endpoint deaggregation register
 *
 * @ep_id:	endpoint whose register should be written
 */
void ipa_endp_init_deaggr_write(u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ep_id];

	ipa_write_reg_n_fields(IPA_ENDP_INIT_DEAGGR_N, ep_id,
			       &ep->init_deaggr);
}

/** ipa_endp_init_hdr_metadata_mask_write() - endpoint metadata mask register
 *
 * @ep_id:	endpoint whose register should be written
 */
static void ipa_endp_init_hdr_metadata_mask_write(u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ep_id];

	ipa_write_reg_n_fields(IPA_ENDP_INIT_HDR_METADATA_MASK_N, ep_id,
			       &ep->metadata_mask);
}

/** ipa_endp_init_hdr_metadata_mask_write() - endpoint metadata mask register
 *
 * @ep_id:	endpoint whose register should be written
 */
static void ipa_endp_status_write(u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ep_id];

	ipa_write_reg_n_fields(IPA_ENDP_STATUS_N, ep_id, &ep->status);
}

/** ipa_cfg_ep - IPA end-point configuration
 * @ep_id:	[in] endpoint id assigned by IPA to client
 * @dst:	[in] destination client handle (ignored for consumer clients)
 *
 * This includes nat, IPv6CT, header, mode, aggregation and route settings and
 * is a one shot API to configure the IPA end-point fully
 *
 * Returns:	0 on success, negative on failure
 *
 * Note:	Should not be called from atomic context
 */
void ipa_cfg_ep(u32 ep_id)
{
	ipa_endp_init_hdr_write(ep_id);
	ipa_endp_init_hdr_ext_write(ep_id);

	ipa_endp_init_aggr_write(ep_id);
	ipa_endp_init_cfg_write(ep_id);

	if (ipa_producer(ipa_ctx->ep[ep_id].client)) {
		ipa_endp_init_mode_write(ep_id);
		ipa_endp_init_seq_write(ep_id);
		ipa_endp_init_deaggr_write(ep_id);
	} else {
		ipa_endp_init_hdr_metadata_mask_write(ep_id);
	}

	ipa_endp_status_write(ep_id);
}

int ipa_ep_init(struct ipa_context *ipa)
{
	ipa->ep_count = ipa_read_reg(IPA_ENABLED_PIPES);
	ipa_debug("endpoint count %u\n", ipa->ep_count);
	ipa->ep = kcalloc(ipa->ep_count, sizeof(*ipa->ep), GFP_KERNEL);
	if (ipa->ep)
		return 0;	/* Success */

	ipa->ep_count = 0;

	return -ENOMEM;
}

void ipa_ep_exit(struct ipa_context *ipa)
{
	kfree(ipa->ep);
	ipa->ep = NULL;
	ipa->ep_count = 0;
}

/** ipa_is_modem_ep()- Checks if endpoint is owned by the modem
 *
 * @ep_id: endpoint identifier
 * Return value: true if owned by modem, false otherwize
 */
bool ipa_is_modem_ep(u32 ep_id)
{
	int client_idx;

	for (client_idx = 0; client_idx < IPA_CLIENT_MAX; client_idx++) {
		if (!ipa_modem_consumer(client_idx) &&
		    !ipa_modem_producer(client_idx))
			continue;
		if (ipa_client_ep_id(client_idx) == ep_id)
			return true;
	}

	return false;
}

static void ipa_src_rsrc_grp_init(enum ipa_rsrc_grp_type_src n)
{
	struct ipa_reg_rsrc_grp_xy_rsrc_type_n limits;
	const struct rsrc_min_max *x_limits;
	const struct rsrc_min_max *y_limits;

	x_limits = &ipa_src_rsrc_grp[n][IPA_RSRC_GROUP_LWA_DL];
	y_limits = &ipa_src_rsrc_grp[n][IPA_RSRC_GROUP_UL_DL];
	ipa_reg_rsrc_grp_xy_rsrc_type_n(&limits, x_limits->min, x_limits->max,
				        y_limits->min, y_limits->max);

	ipa_write_reg_n_fields(IPA_SRC_RSRC_GRP_01_RSRC_TYPE_N, n, &limits);
}

static void ipa_dst_rsrc_grp_init(enum ipa_rsrc_grp_type_src n)
{
	struct ipa_reg_rsrc_grp_xy_rsrc_type_n limits;
	const struct rsrc_min_max *x_limits;
	const struct rsrc_min_max *y_limits;

	x_limits = &ipa_dst_rsrc_grp[n][IPA_RSRC_GROUP_LWA_DL];
	y_limits = &ipa_dst_rsrc_grp[n][IPA_RSRC_GROUP_UL_DL];
	ipa_reg_rsrc_grp_xy_rsrc_type_n(&limits, x_limits->min, x_limits->max,
				        y_limits->min, y_limits->max);

	ipa_write_reg_n_fields(IPA_DST_RSRC_GRP_01_RSRC_TYPE_N, n, &limits);
}

void ipa_set_resource_groups_min_max_limits(void)
{
	ipa_src_rsrc_grp_init(IPA_RSRC_GRP_TYPE_SRC_PKT_CONTEXTS);
	ipa_src_rsrc_grp_init(IPA_RSRC_GRP_TYPE_SRS_DESCRIPTOR_LISTS);
	ipa_src_rsrc_grp_init(IPA_RSRC_GRP_TYPE_SRC_DESCRIPTOR_BUFF);
	ipa_src_rsrc_grp_init(IPA_RSRC_GRP_TYPE_SRC_HPS_DMARS);
	ipa_src_rsrc_grp_init(IPA_RSRC_GRP_TYPE_SRC_ACK_ENTRIES);

	ipa_dst_rsrc_grp_init(IPA_RSRC_GRP_TYPE_DST_DATA_SECTORS);
	ipa_dst_rsrc_grp_init(IPA_RSRC_GRP_TYPE_DST_DPS_DMARS);
}

static void ipa_gsi_poll_after_suspend(struct ipa_ep_context *ep)
{
	ipa_rx_switch_to_poll_mode(ep->sys);
}

/* Suspend a consumer endpoint */
static void
ipa_ep_cons_suspend(struct ipa_context *ipa, enum ipa_client_type client)
{
	struct ipa_reg_endp_init_ctrl init_ctrl;
	u32 ep_id = ipa_client_ep_id(client);

	ipa_reg_endp_init_ctrl(&init_ctrl, true);
	ipa_write_reg_n_fields(IPA_ENDP_INIT_CTRL_N, ep_id, &init_ctrl);

	/* Due to a hardware bug, a client suspended with an open
	 * aggregation frame will not generate a SUSPEND IPA interrupt.
	 * We work around this by force-closing the aggregation frame,
	 * then simulating the arrival of such an interrupt.
	 */
	ipa_suspend_active_aggr_wa(ep_id);

	ipa_gsi_poll_after_suspend(&ipa->ep[ep_id]);
}

void ipa_ep_suspend_all(struct ipa_context *ipa)
{
	ipa_ep_cons_suspend(ipa, IPA_CLIENT_APPS_WAN_CONS);
	ipa_ep_cons_suspend(ipa, IPA_CLIENT_APPS_LAN_CONS);
}

/* Resume a suspended consumer endpoint */
static void
ipa_ep_cons_resume(struct ipa_context *ipa, enum ipa_client_type client)
{
	struct ipa_reg_endp_init_ctrl init_ctrl;
	struct ipa_ep_context *ep;
	u32 ep_id;

	ep_id = ipa_client_ep_id(client);
	ep = &ipa->ep[ep_id];

	ipa_reg_endp_init_ctrl(&init_ctrl, false);
	ipa_write_reg_n_fields(IPA_ENDP_INIT_CTRL_N, ep_id, &init_ctrl);

	if (!ipa_ep_polling(ep))
		gsi_channel_intr_enable(ipa->gsi, ep->channel_id);
}

void ipa_ep_resume_all(struct ipa_context *ipa)
{
	ipa_ep_cons_resume(ipa, IPA_CLIENT_APPS_LAN_CONS);
	ipa_ep_cons_resume(ipa, IPA_CLIENT_APPS_WAN_CONS);
}

/** ipa_cfg_route() - configure IPA route
 * @route: IPA route
 *
 * Return codes:
 * 0: success
 */
void ipa_cfg_default_route(struct ipa_context *ipa, enum ipa_client_type client)
{
	struct ipa_reg_route route;

	ipa_reg_route(&route, ipa_client_ep_id(client));
	ipa_write_reg_fields(IPA_ROUTE, &route);
}

/* In certain cases we need to issue a command to reliably clear the
 * IPA pipeline.  Sending a 1-byte DMA task is sufficient, and this
 * function preallocates a command to do just that.  There are
 * conditions (process context in KILL state) where DMA allocations
 * can fail, and we need to be able to issue this command to put the
 * hardware in a known state.  By preallocating the command here we
 * guarantee it can't fail for that reason.
 */
int ipa_gsi_dma_task_alloc(struct ipa_context *ipa)
{
	struct ipa_dma_task_info *info = &ipa->dma_task_info;
	size_t size = IPA_GSI_CHANNEL_STOP_PKT_SIZE;
	struct device *dev = &ipa->pdev->dev;
	dma_addr_t phys;

	info->virt = dma_zalloc_coherent(dev, size, &phys, GFP_KERNEL);
	if (!info->virt)
		return -ENOMEM;

	/* IPA_IMM_CMD_DMA_TASK_32B_ADDR */
	ipa->dma_task_info.payload = ipahal_dma_task_32b_addr_pyld(phys,
								       size);
	if (!ipa->dma_task_info.payload) {
		dma_free_coherent(dev, size, info->virt, phys);
		info->virt = NULL;

		return -ENOMEM;
	}
	info->phys = phys;

	return 0;
}

void ipa_gsi_dma_task_free(struct ipa_context *ipa)
{
	struct ipa_dma_task_info *info = &ipa->dma_task_info;
	size_t size = IPA_GSI_CHANNEL_STOP_PKT_SIZE;
	struct device *dev = &ipa->pdev->dev;

	ipahal_payload_free(ipa->dma_task_info.payload);
	ipa->dma_task_info.payload = NULL;
	dma_free_coherent(dev, size, info->virt, info->phys);
	info->phys = 0;
	info->virt = NULL;
}

/** ipa_gsi_dma_task_inject()- Send DMA_TASK to IPA for GSI stop channel
 *
 * Send a DMA_TASK of 1B to IPA to unblock GSI channel in STOP_IN_PROG.
 * Return value: 0 on success, negative otherwise
 */
static int ipa_gsi_dma_task_inject(void)
{
	struct ipa_desc desc = { };

	desc.type = IPA_IMM_CMD_DESC;
	desc.len_opcode = IPA_IMM_CMD_DMA_TASK_32B_ADDR;
	desc.payload = ipa_ctx->dma_task_info.payload;

	return ipa_send_cmd_timeout(&desc, IPA_GSI_DMA_TASK_TIMEOUT);
}

/** ipa_stop_gsi_channel()- Stops a GSI channel in IPA
 * @chan_hdl: GSI channel handle
 *
 * This function implements the sequence to stop a GSI channel
 * in IPA. This function returns when the channel is is STOP state.
 *
 * Return value: 0 on success, negative otherwise
 */
int ipa_stop_gsi_channel(u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ep_id];
	int ret;
	int i;

	if (ipa_producer(ep->client))
		return gsi_channel_stop(ipa_ctx->gsi, ep->channel_id);

	for (i = 0; i < IPA_GSI_CHANNEL_STOP_MAX_RETRY; i++) {
		ret = gsi_channel_stop(ipa_ctx->gsi, ep->channel_id);
		if (ret != -EAGAIN && ret != -ETIMEDOUT)
			return ret;

		/* Send a 1B packet DMA_TASK to IPA and try again */
		ret = ipa_gsi_dma_task_inject();
		if (ret)
			return ret;

		/* sleep for short period to flush IPA */
		usleep_range(IPA_GSI_CHANNEL_STOP_SLEEP_MIN,
			     IPA_GSI_CHANNEL_STOP_SLEEP_MAX);
	}

	ipa_err("Failed	 to stop GSI channel with retries\n");

	return -EFAULT;
}

/** ipa_enable_dcd() - enable dynamic clock division on IPA
 *
 * Return value: Non applicable
 *
 */
void ipa_enable_dcd(void)
{
	struct ipa_reg_idle_indication_cfg indication;

	/* recommended values for IPA 3.5 according to IPA HPG */
	ipa_reg_idle_indication_cfg(&indication, 256, 0);
	ipa_write_reg_fields(IPA_IDLE_INDICATION_CFG, &indication);
}

/** ipa_set_flt_tuple_mask() - Sets the flt tuple masking for the given
 * endpoint.  Endpoint must be for AP (not modem) and support filtering.
 * Updates the the filtering masking values without changing the rt ones.
 *
 * @ep_id: filter endpoint to configure the tuple masking
 * @tuple: the tuple members masking
 * Returns:	0 on success, negative on failure
 *
 */
void ipa_set_flt_tuple_mask(u32 ep_id)
{
	struct ipa_ep_filter_router_hsh_cfg hsh_cfg;

	ipa_read_reg_n_fields(IPA_ENDP_FILTER_ROUTER_HSH_CFG_N, ep_id,
			      &hsh_cfg);

	ipa_reg_hash_tuple(&hsh_cfg.flt);

	ipa_write_reg_n_fields(IPA_ENDP_FILTER_ROUTER_HSH_CFG_N, ep_id,
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
void ipa_set_rt_tuple_mask(int tbl_idx)
{
	struct ipa_ep_filter_router_hsh_cfg hsh_cfg;

	ipa_read_reg_n_fields(IPA_ENDP_FILTER_ROUTER_HSH_CFG_N, tbl_idx,
			      &hsh_cfg);

	ipa_reg_hash_tuple(&hsh_cfg.rt);

	ipa_write_reg_n_fields(IPA_ENDP_FILTER_ROUTER_HSH_CFG_N, tbl_idx,
			       &hsh_cfg);
}

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("IPA HW device driver");
