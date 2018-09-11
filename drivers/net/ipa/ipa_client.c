// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#define pr_fmt(fmt)    "ipa %s:%d " fmt, __func__, __LINE__

#include <asm/barrier.h>
#include <linux/delay.h>
#include <linux/device.h>

#include "ipa_dma.h"
#include "ipa_i.h"

/* These values were determined empirically and shows good E2E bi-
 * directional throughputs
 */
#define IPA_HOLB_TMR_EN			0x1
#define IPA_HOLB_TMR_DIS		0x0
#define IPA_POLL_AGGR_STATE_RETRIES_NUM	3
#define IPA_POLL_AGGR_STATE_SLEEP_MSEC	1

#define IPA_PKT_FLUSH_TO_US		100

static int
ipa_reconfigure_channel_to_gpi(struct ipa_ep_context *ep,
			       struct gsi_chan_props *orig_props,
			       struct ipa_dma_mem *chan_dma)
{
	struct gsi_chan_props props = { };

	/* Allocate the DMA space first; it can fail */
	if (ipa_dma_alloc(chan_dma, 2 * GSI_RING_ELEMENT_SIZE, GFP_KERNEL))
		return -ENOMEM;

	/* Set up channel properties */
	props.from_gsi = true;
	props.ch_id = orig_props->ch_id;
	props.evt_ring_hdl = orig_props->evt_ring_hdl;
	props.mem = *chan_dma;
	props.use_db_engine = false;
	props.low_weight = 1;
	props.chan_user_data = NULL;

	if (gsi_set_channel_cfg(ipa_ctx->gsi, ep->gsi_chan_hdl, &props)) {
		ipa_err("Error setting channel properties\n");
		ipa_dma_free(chan_dma);
		return -EFAULT;
	}

	return 0;
}

static int
ipa_restore_channel_properties(struct ipa_ep_context *ep,
			       struct gsi_chan_props *props)
{
	if (gsi_set_channel_cfg(ipa_ctx->gsi, ep->gsi_chan_hdl, props)) {
		ipa_err("Error restoring channel properties\n");
		return -EFAULT;
	}

	return 0;
}

static int
ipa_reset_with_open_aggr_frame_wa(u32 clnt_hdl, struct ipa_ep_context *ep)
{
	struct ipa_reg_aggr_force_close force_close;
	int result;
	int gsi_res;
	struct gsi_chan_props orig_props = { };
	struct ipa_dma_mem chan_dma;
	struct ipa_dma_mem dma_byte;
	struct gsi_xfer_elem xfer_elem = { };
	int i;
	int aggr_active_bitmap = 0;
	bool pipe_suspended = false;
	struct ipa_reg_endp_init_ctrl init_ctrl;

	ipa_debug("Applying reset channel with open aggregation frame WA\n");

	force_close.pipe_bitmap = BIT(clnt_hdl);
	ipa_write_reg_fields(IPA_AGGR_FORCE_CLOSE, &force_close);

	/* Reset channel */
	gsi_res = gsi_reset_channel(ipa_ctx->gsi, ep->gsi_chan_hdl);
	if (gsi_res) {
		ipa_err("Error resetting channel: %d\n", gsi_res);
		return -EFAULT;
	}

	/* Reconfigure channel to dummy GPI channel */
	gsi_res = gsi_get_channel_cfg(ipa_ctx->gsi, ep->gsi_chan_hdl,
				      &orig_props);
	if (gsi_res) {
		ipa_err("Error getting channel properties: %d\n", gsi_res);
		return -EFAULT;
	}
	result = ipa_reconfigure_channel_to_gpi(ep, &orig_props, &chan_dma);
	if (result)
		return -EFAULT;

	ipa_read_reg_n_fields(IPA_ENDP_INIT_CTRL_N, clnt_hdl, &init_ctrl);
	if (init_ctrl.endp_suspend) {
		ipa_debug("pipe is suspended, remove suspend\n");
		pipe_suspended = true;
		init_ctrl.endp_suspend = 0;
		ipa_write_reg_n_fields(IPA_ENDP_INIT_CTRL_N, clnt_hdl,
				       &init_ctrl);
	}

	/* Start channel and put 1 Byte descriptor on it */
	gsi_res = gsi_start_channel(ipa_ctx->gsi, ep->gsi_chan_hdl);
	if (gsi_res) {
		ipa_err("Error starting channel: %d\n", gsi_res);
		result = -EFAULT;
		goto start_chan_fail;
	}

	if (ipa_dma_alloc(&dma_byte, 1, GFP_KERNEL)) {
		ipa_err("Error allocating DMA\n");
		result = -ENOMEM;
		goto dma_alloc_fail;
	}

	xfer_elem.addr = dma_byte.phys;
	xfer_elem.len = 1;	/* = dma_byte.size; */
	xfer_elem.flags = GSI_XFER_FLAG_EOT;
	xfer_elem.type = GSI_XFER_ELEM_DATA;

	gsi_res = gsi_queue_xfer(ipa_ctx->gsi, ep->gsi_chan_hdl, 1, &xfer_elem,
				 true);
	if (gsi_res) {
		result = -EFAULT;
		goto queue_xfer_fail;
	}

	/* Wait for aggregation frame to be closed and stop channel*/
	for (i = 0; i < IPA_POLL_AGGR_STATE_RETRIES_NUM; i++) {
		aggr_active_bitmap = ipa_read_reg(IPA_STATE_AGGR_ACTIVE);
		if (!(aggr_active_bitmap & BIT(clnt_hdl)))
			break;
		msleep(IPA_POLL_AGGR_STATE_SLEEP_MSEC);
	}

	ipa_bug_on(aggr_active_bitmap & BIT(clnt_hdl));

	ipa_dma_free(&dma_byte);

	result = ipa_stop_gsi_channel(clnt_hdl);
	if (result) {
		ipa_err("Error stopping channel: %d\n", result);
		goto start_chan_fail;
	}

	/* Reset channel */
	gsi_res = gsi_reset_channel(ipa_ctx->gsi, ep->gsi_chan_hdl);
	if (gsi_res) {
		ipa_err("Error resetting channel: %d\n", gsi_res);
		result = -EFAULT;
		goto start_chan_fail;
	}

	/* Need to sleep for 1ms as required by H/W verified
	 * sequence for resetting GSI channel
	 */
	msleep(IPA_POLL_AGGR_STATE_SLEEP_MSEC);

	if (pipe_suspended) {
		ipa_debug("suspend the pipe again\n");
		init_ctrl.endp_suspend = 1;
		ipa_write_reg_n_fields(IPA_ENDP_INIT_CTRL_N, clnt_hdl,
				       &init_ctrl);
	}

	/* Restore channels properties */
	result = ipa_restore_channel_properties(ep, &orig_props);
	if (result)
		goto restore_props_fail;
	ipa_dma_free(&chan_dma);

	return 0;

queue_xfer_fail:
	ipa_dma_free(&dma_byte);
dma_alloc_fail:
	ipa_stop_gsi_channel(clnt_hdl);
start_chan_fail:
	if (pipe_suspended) {
		ipa_debug("suspend the pipe again\n");
		init_ctrl.endp_suspend = 1;
		ipa_write_reg_n_fields(IPA_ENDP_INIT_CTRL_N, clnt_hdl,
				       &init_ctrl);
	}
	ipa_restore_channel_properties(ep, &orig_props);
restore_props_fail:
	ipa_dma_free(&chan_dma);

	return result;
}

void ipa_reset_gsi_channel(u32 clnt_hdl)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[clnt_hdl];
	u32 aggr_active_bitmap;

	ipa_client_add();

	/* Check for open aggregation frame on Consumer EP -
	 * reset with open aggregation frame WA
	 */
	if (ipa_consumer(ep->client))
		aggr_active_bitmap = ipa_read_reg(IPA_STATE_AGGR_ACTIVE);
	else
		aggr_active_bitmap = 0;

	if (aggr_active_bitmap & BIT(clnt_hdl)) {
		ipa_bug_on(ipa_reset_with_open_aggr_frame_wa(clnt_hdl, ep));
	} else {
		/* If the reset called after stop, need to wait 1ms */
		msleep(IPA_POLL_AGGR_STATE_SLEEP_MSEC);
		ipa_bug_on(gsi_reset_channel(ipa_ctx->gsi, ep->gsi_chan_hdl));
	}

	ipa_client_remove();
}
