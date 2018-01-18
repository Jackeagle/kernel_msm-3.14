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

#include <asm/barrier.h>
#include <linux/delay.h>
#include <linux/device.h>
#include "ipa_i.h"

/*
 * These values were determined empirically and shows good E2E bi-
 * directional throughputs
 */
#define IPA_HOLB_TMR_EN 0x1
#define IPA_HOLB_TMR_DIS 0x0
#define IPA_POLL_AGGR_STATE_RETRIES_NUM 3
#define IPA_POLL_AGGR_STATE_SLEEP_MSEC 1

#define IPA_PKT_FLUSH_TO_US 100

int ipa3_enable_data_path(u32 clnt_hdl)
{
	struct ipa3_ep_context *ep = &ipa3_ctx->ep[clnt_hdl];
	struct ipa_ep_cfg_holb holb_cfg;
	struct ipa_ep_cfg_ctrl ep_cfg_ctrl;
	int res = 0;
	struct ipahal_reg_endp_init_rsrc_grp rsrc_grp;

	/* Assign the resource group for pipe */
	memset(&rsrc_grp, 0, sizeof(rsrc_grp));
	rsrc_grp.rsrc_grp = ipa_get_ep_group(ep->client);
	if (rsrc_grp.rsrc_grp == -1) {
		ipa_err("invalid group for client %d\n", ep->client);
		WARN_ON(1);
		return -EFAULT;
	}

	ipa_debug("Setting group %d for pipe %d\n",
		rsrc_grp.rsrc_grp, clnt_hdl);
	ipahal_write_reg_n_fields(IPA_ENDP_INIT_RSRC_GRP_n, clnt_hdl,
		&rsrc_grp);

	ipa_debug("Enabling data path\n");
	if (IPA_CLIENT_IS_CONS(ep->client)) {
		memset(&holb_cfg, 0, sizeof(holb_cfg));
		holb_cfg.en = IPA_HOLB_TMR_DIS;
		holb_cfg.tmr_val = 0;
		res = ipa3_cfg_ep_holb(clnt_hdl, &holb_cfg);
	}

	/* Enable the pipe */
	if (IPA_CLIENT_IS_CONS(ep->client) &&
		(ep->keep_ipa_awake ||
		!ipa3_should_pipe_be_suspended(ep->client))) {
		memset(&ep_cfg_ctrl, 0, sizeof(ep_cfg_ctrl));
		ep_cfg_ctrl.ipa_ep_suspend = false;
		res = ipa3_cfg_ep_ctrl(clnt_hdl, &ep_cfg_ctrl);
	}

	return res;
}

static void ipa_chan_err_cb(struct gsi_chan_err_notify *notify)
{
	if (notify) {
		switch (notify->evt_id) {
		case GSI_CHAN_INVALID_TRE_ERR:
			ipa_err("Received GSI_CHAN_INVALID_TRE_ERR\n");
			break;
		case GSI_CHAN_NON_ALLOCATED_EVT_ACCESS_ERR:
			ipa_err("Received GSI_CHAN_NON_ALLOC_EVT_ACCESS_ERR\n");
			break;
		case GSI_CHAN_OUT_OF_BUFFERS_ERR:
			ipa_err("Received GSI_CHAN_OUT_OF_BUFFERS_ERR\n");
			break;
		case GSI_CHAN_OUT_OF_RESOURCES_ERR:
			ipa_err("Received GSI_CHAN_OUT_OF_RESOURCES_ERR\n");
			break;
		case GSI_CHAN_UNSUPPORTED_INTER_EE_OP_ERR:
			ipa_err("Received GSI_CHAN_UNSUPP_INTER_EE_OP_ERR\n");
			break;
		case GSI_CHAN_HWO_1_ERR:
			ipa_err("Received GSI_CHAN_HWO_1_ERR\n");
			break;
		default:
			ipa_err("Unexpected err evt: %d\n", notify->evt_id);
		}
		BUG();
	}
}

static void ipa_xfer_cb(struct gsi_chan_xfer_notify *notify)
{
}

static int ipa3_reconfigure_channel_to_gpi(struct ipa3_ep_context *ep,
	struct gsi_chan_props *orig_chan_props,
	struct ipa_mem_buffer *chan_dma)
{
	struct device *dev = ipa3_ctx->ap_smmu_cb.dev;
	struct gsi_chan_props chan_props;
	int gsi_res;
	dma_addr_t chan_dma_addr;
	int result;

	/* Set up channel properties */
	memset(&chan_props, 0, sizeof(struct gsi_chan_props));
	chan_props.dir = GSI_CHAN_DIR_FROM_GSI;
	chan_props.ch_id = orig_chan_props->ch_id;
	chan_props.evt_ring_hdl = orig_chan_props->evt_ring_hdl;
	chan_props.re_size = GSI_CHAN_RE_SIZE_16B;
	chan_props.ring_len = 2 * GSI_CHAN_RE_SIZE_16B;
	chan_props.ring_base_vaddr =
		dma_alloc_coherent(dev, chan_props.ring_len,
		&chan_dma_addr, GFP_KERNEL);

	if (!chan_props.ring_base_vaddr)
		return -ENOMEM;
	chan_props.ring_base_addr = chan_dma_addr;

	chan_dma->base = chan_props.ring_base_vaddr;
	chan_dma->phys_base = chan_props.ring_base_addr;
	chan_dma->size = chan_props.ring_len;
	chan_props.use_db_eng = GSI_CHAN_DIRECT_MODE;
	chan_props.max_prefetch = GSI_ONE_PREFETCH_SEG;
	chan_props.low_weight = 1;
	chan_props.chan_user_data = NULL;
	chan_props.err_cb = ipa_chan_err_cb;
	chan_props.xfer_cb = ipa_xfer_cb;

	gsi_res = gsi_set_channel_cfg(ep->gsi_chan_hdl, &chan_props, NULL);
	if (gsi_res) {
		ipa_err("Error setting channel properties\n");
		result = -EFAULT;
		goto set_chan_cfg_fail;
	}

	return 0;

set_chan_cfg_fail:
	dma_free_coherent(dev, chan_dma->size,
		chan_dma->base, chan_dma->phys_base);
	return result;
}

static int ipa3_restore_channel_properties(struct ipa3_ep_context *ep,
	struct gsi_chan_props *chan_props,
	union gsi_channel_scratch *chan_scratch)
{
	int gsi_res;

	gsi_res = gsi_set_channel_cfg(ep->gsi_chan_hdl, chan_props,
		chan_scratch);
	if (gsi_res) {
		ipa_err("Error restoring channel properties\n");
		return -EFAULT;
	}

	return 0;
}

static int ipa3_reset_with_open_aggr_frame_wa(u32 clnt_hdl,
	struct ipa3_ep_context *ep)
{
	struct device *dev = ipa3_ctx->ap_smmu_cb.dev;
	int result = -EFAULT;
	int gsi_res;
	struct gsi_chan_props orig_chan_props;
	union gsi_channel_scratch orig_chan_scratch;
	struct ipa_mem_buffer chan_dma;
	void *buff;
	dma_addr_t dma_addr;
	struct gsi_xfer_elem xfer_elem;
	int i;
	int aggr_active_bitmap = 0;
	bool pipe_suspended = false;
	struct ipa_ep_cfg_ctrl ctrl;

	ipa_debug("Applying reset channel with open aggregation frame WA\n");
	ipahal_write_reg(IPA_AGGR_FORCE_CLOSE, (1 << clnt_hdl));

	/* Reset channel */
	gsi_res = gsi_reset_channel(ep->gsi_chan_hdl);
	if (gsi_res) {
		ipa_err("Error resetting channel: %d\n", gsi_res);
		return -EFAULT;
	}

	/* Reconfigure channel to dummy GPI channel */
	memset(&orig_chan_props, 0, sizeof(struct gsi_chan_props));
	memset(&orig_chan_scratch, 0, sizeof(union gsi_channel_scratch));
	gsi_res = gsi_get_channel_cfg(ep->gsi_chan_hdl, &orig_chan_props,
		&orig_chan_scratch);
	if (gsi_res) {
		ipa_err("Error getting channel properties: %d\n", gsi_res);
		return -EFAULT;
	}
	memset(&chan_dma, 0, sizeof(struct ipa_mem_buffer));
	result = ipa3_reconfigure_channel_to_gpi(ep, &orig_chan_props,
		&chan_dma);
	if (result)
		return -EFAULT;

	ipahal_read_reg_n_fields(IPA_ENDP_INIT_CTRL_n, clnt_hdl, &ctrl);
	if (ctrl.ipa_ep_suspend) {
		ipa_debug("pipe is suspended, remove suspend\n");
		pipe_suspended = true;
		ctrl.ipa_ep_suspend = false;
		ipahal_write_reg_n_fields(IPA_ENDP_INIT_CTRL_n,
			clnt_hdl, &ctrl);
	}

	/* Start channel and put 1 Byte descriptor on it */
	gsi_res = gsi_start_channel(ep->gsi_chan_hdl);
	if (gsi_res) {
		ipa_err("Error starting channel: %d\n", gsi_res);
		result = -EFAULT;
		goto start_chan_fail;
	}

	memset(&xfer_elem, 0, sizeof(struct gsi_xfer_elem));
	buff = dma_alloc_coherent(dev, 1, &dma_addr, GFP_KERNEL);
	if (!buff) {
		ipa_err("Error allocating DMA\n");
		result = -ENOMEM;
		goto dma_alloc_fail;
	}
	xfer_elem.addr = dma_addr;
	xfer_elem.len = 1;
	xfer_elem.flags = GSI_XFER_FLAG_EOT;
	xfer_elem.type = GSI_XFER_ELEM_DATA;

	gsi_res = gsi_queue_xfer(ep->gsi_chan_hdl, 1, &xfer_elem,
		true);
	if (gsi_res) {
		ipa_err("Error queueing xfer: %d\n", gsi_res);
		result = -EFAULT;
		goto queue_xfer_fail;
	}

	/* Wait for aggregation frame to be closed and stop channel*/
	for (i = 0; i < IPA_POLL_AGGR_STATE_RETRIES_NUM; i++) {
		aggr_active_bitmap = ipahal_read_reg(IPA_STATE_AGGR_ACTIVE);
		if (!(aggr_active_bitmap & (1 << clnt_hdl)))
			break;
		msleep(IPA_POLL_AGGR_STATE_SLEEP_MSEC);
	}

	if (aggr_active_bitmap & (1 << clnt_hdl)) {
		ipa_err("Failed closing aggr frame for client: %d\n",
			clnt_hdl);
		BUG();
	}

	dma_free_coherent(dev, 1, buff, dma_addr);

	result = ipa3_stop_gsi_channel(clnt_hdl);
	if (result) {
		ipa_err("Error stopping channel: %d\n", result);
		goto start_chan_fail;
	}

	/* Reset channel */
	gsi_res = gsi_reset_channel(ep->gsi_chan_hdl);
	if (gsi_res) {
		ipa_err("Error resetting channel: %d\n", gsi_res);
		result = -EFAULT;
		goto start_chan_fail;
	}

	/*
	 * Need to sleep for 1ms as required by H/W verified
	 * sequence for resetting GSI channel
	 */
	msleep(IPA_POLL_AGGR_STATE_SLEEP_MSEC);

	if (pipe_suspended) {
		ipa_debug("suspend the pipe again\n");
		ctrl.ipa_ep_suspend = true;
		ipahal_write_reg_n_fields(IPA_ENDP_INIT_CTRL_n,
			clnt_hdl, &ctrl);
	}

	/* Restore channels properties */
	result = ipa3_restore_channel_properties(ep, &orig_chan_props,
		&orig_chan_scratch);
	if (result)
		goto restore_props_fail;
	dma_free_coherent(dev, chan_dma.size,
		chan_dma.base, chan_dma.phys_base);

	return 0;

queue_xfer_fail:
	dma_free_coherent(dev, 1, buff, dma_addr);
dma_alloc_fail:
	ipa3_stop_gsi_channel(clnt_hdl);
start_chan_fail:
	if (pipe_suspended) {
		ipa_debug("suspend the pipe again\n");
		ctrl.ipa_ep_suspend = true;
		ipahal_write_reg_n_fields(IPA_ENDP_INIT_CTRL_n,
			clnt_hdl, &ctrl);
	}
	ipa3_restore_channel_properties(ep, &orig_chan_props,
		&orig_chan_scratch);
restore_props_fail:
	dma_free_coherent(dev, chan_dma.size,
		chan_dma.base, chan_dma.phys_base);
	return result;
}

int ipa3_reset_gsi_channel(u32 clnt_hdl)
{
	struct ipa3_ep_context *ep;
	int result = -EFAULT;
	int gsi_res;
	int aggr_active_bitmap = 0;

	ipa_debug("entry\n");
	if (clnt_hdl >= ipa3_ctx->ipa_num_pipes ||
		ipa3_ctx->ep[clnt_hdl].valid == 0) {
		ipa_err("Bad parameter.\n");
		return -EINVAL;
	}

	ep = &ipa3_ctx->ep[clnt_hdl];

	if (!ep->keep_ipa_awake)
		IPA_ACTIVE_CLIENTS_INC_EP(ipa3_get_client_mapping(clnt_hdl));
	/*
	 * Check for open aggregation frame on Consumer EP -
	 * reset with open aggregation frame WA
	 */
	if (IPA_CLIENT_IS_CONS(ep->client)) {
		aggr_active_bitmap = ipahal_read_reg(IPA_STATE_AGGR_ACTIVE);
		if (aggr_active_bitmap & (1 << clnt_hdl)) {
			result = ipa3_reset_with_open_aggr_frame_wa(clnt_hdl,
				ep);
			if (result)
				goto reset_chan_fail;
			goto finish_reset;
		}
	}

	/*
	 * Reset channel
	 * If the reset called after stop, need to wait 1ms
	 */
	msleep(IPA_POLL_AGGR_STATE_SLEEP_MSEC);
	gsi_res = gsi_reset_channel(ep->gsi_chan_hdl);
	if (gsi_res) {
		ipa_err("Error resetting channel: %d\n", gsi_res);
		result = -EFAULT;
		goto reset_chan_fail;
	}

finish_reset:
	if (!ep->keep_ipa_awake)
		IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));

	ipa_debug("exit\n");
	return 0;

reset_chan_fail:
	if (!ep->keep_ipa_awake)
		IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));
	return result;
}
