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
#define IPA_HOLB_TMR_DEFAULT_VAL 0x1ff
#define IPA_POLL_AGGR_STATE_RETRIES_NUM 3
#define IPA_POLL_AGGR_STATE_SLEEP_MSEC 1

#define IPA_PKT_FLUSH_TO_US 100

#define IPA_POLL_FOR_EMPTINESS_NUM 50
#define IPA_POLL_FOR_EMPTINESS_SLEEP_USEC 20
#define IPA_CHANNEL_STOP_IN_PROC_TO_MSEC 5
#define IPA_CHANNEL_STOP_IN_PROC_SLEEP_USEC 200

/* xfer_rsc_idx should be 7 bits */
#define IPA_XFER_RSC_IDX_MAX 127

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
		IPAERR("invalid group for client %d\n", ep->client);
		WARN_ON(1);
		return -EFAULT;
	}

	IPADBG("Setting group %d for pipe %d\n",
		rsrc_grp.rsrc_grp, clnt_hdl);
	ipahal_write_reg_n_fields(IPA_ENDP_INIT_RSRC_GRP_n, clnt_hdl,
		&rsrc_grp);

	IPADBG("Enabling data path\n");
	if (IPA_CLIENT_IS_CONS(ep->client)) {
		memset(&holb_cfg, 0, sizeof(holb_cfg));
		holb_cfg.en = IPA_HOLB_TMR_DIS;
		holb_cfg.tmr_val = 0;
		res = ipa3_cfg_ep_holb(clnt_hdl, &holb_cfg);
	}

	/* Enable the pipe */
	if (ipa3_ctx->ipa_hw_type < IPA_HW_v4_0) {
		if (IPA_CLIENT_IS_CONS(ep->client) &&
		    (ep->keep_ipa_awake ||
		    ipa3_ctx->resume_on_connect[ep->client] ||
		    !ipa3_should_pipe_be_suspended(ep->client))) {
			memset(&ep_cfg_ctrl, 0, sizeof(ep_cfg_ctrl));
			ep_cfg_ctrl.ipa_ep_suspend = false;
			res = ipa3_cfg_ep_ctrl(clnt_hdl, &ep_cfg_ctrl);
		}
	}

	return res;
}

int ipa3_disable_data_path(u32 clnt_hdl)
{
	struct ipa3_ep_context *ep = &ipa3_ctx->ep[clnt_hdl];
	struct ipa_ep_cfg_holb holb_cfg;
	struct ipa_ep_cfg_ctrl ep_cfg_ctrl;
	struct ipa_ep_cfg_aggr ep_aggr;
	int res = 0;

	IPADBG("Disabling data path\n");
	if (IPA_CLIENT_IS_CONS(ep->client)) {
		memset(&holb_cfg, 0, sizeof(holb_cfg));
		holb_cfg.en = IPA_HOLB_TMR_EN;
		holb_cfg.tmr_val = 0;
		res = ipa3_cfg_ep_holb(clnt_hdl, &holb_cfg);
	}

	/*
	 * for IPA 4.0 and above aggregation frame is closed together with
	 * channel STOP
	 */
	if (ipa3_ctx->ipa_hw_type < IPA_HW_v4_0) {
		/* Suspend the pipe */
		if (IPA_CLIENT_IS_CONS(ep->client)) {
			/*
			 * for RG10 workaround uC needs to be loaded before
			 * pipe can be suspended in this case.
			 */
			if (ipa3_ctx->apply_rg10_wa && ipa3_uc_state_check()) {
				IPADBG("uC is not loaded yet, waiting...\n");
				res = wait_for_completion_timeout(
					&ipa3_ctx->uc_loaded_completion_obj,
					60 * HZ);
				if (res == 0)
					IPADBG("timeout waiting for uC load\n");
			}

			memset(&ep_cfg_ctrl, 0, sizeof(struct ipa_ep_cfg_ctrl));
			ep_cfg_ctrl.ipa_ep_suspend = true;
			res = ipa3_cfg_ep_ctrl(clnt_hdl, &ep_cfg_ctrl);
		}

		udelay(IPA_PKT_FLUSH_TO_US);
		ipahal_read_reg_n_fields(IPA_ENDP_INIT_AGGR_n, clnt_hdl,
			&ep_aggr);
		if (ep_aggr.aggr_en) {
			res = ipa3_tag_aggr_force_close(clnt_hdl);
			if (res) {
				IPAERR("tag process timeout client:%d err:%d\n",
					clnt_hdl, res);
				ipa_assert();
			}
		}
	}

	return res;
}

static void ipa_chan_err_cb(struct gsi_chan_err_notify *notify)
{
	if (notify) {
		switch (notify->evt_id) {
		case GSI_CHAN_INVALID_TRE_ERR:
			IPAERR("Received GSI_CHAN_INVALID_TRE_ERR\n");
			break;
		case GSI_CHAN_NON_ALLOCATED_EVT_ACCESS_ERR:
			IPAERR("Received GSI_CHAN_NON_ALLOC_EVT_ACCESS_ERR\n");
			break;
		case GSI_CHAN_OUT_OF_BUFFERS_ERR:
			IPAERR("Received GSI_CHAN_OUT_OF_BUFFERS_ERR\n");
			break;
		case GSI_CHAN_OUT_OF_RESOURCES_ERR:
			IPAERR("Received GSI_CHAN_OUT_OF_RESOURCES_ERR\n");
			break;
		case GSI_CHAN_UNSUPPORTED_INTER_EE_OP_ERR:
			IPAERR("Received GSI_CHAN_UNSUPP_INTER_EE_OP_ERR\n");
			break;
		case GSI_CHAN_HWO_1_ERR:
			IPAERR("Received GSI_CHAN_HWO_1_ERR\n");
			break;
		default:
			IPAERR("Unexpected err evt: %d\n", notify->evt_id);
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
		dma_alloc_coherent(ipa3_ctx->pdev, chan_props.ring_len,
		&chan_dma_addr, 0);
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
		IPAERR("Error setting channel properties\n");
		result = -EFAULT;
		goto set_chan_cfg_fail;
	}

	return 0;

set_chan_cfg_fail:
	dma_free_coherent(ipa3_ctx->pdev, chan_dma->size,
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
		IPAERR("Error restoring channel properties\n");
		return -EFAULT;
	}

	return 0;
}

static int ipa3_reset_with_open_aggr_frame_wa(u32 clnt_hdl,
	struct ipa3_ep_context *ep)
{
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

	IPADBG("Applying reset channel with open aggregation frame WA\n");
	ipahal_write_reg(IPA_AGGR_FORCE_CLOSE, (1 << clnt_hdl));

	/* Reset channel */
	gsi_res = gsi_reset_channel(ep->gsi_chan_hdl);
	if (gsi_res) {
		IPAERR("Error resetting channel: %d\n", gsi_res);
		return -EFAULT;
	}

	/* Reconfigure channel to dummy GPI channel */
	memset(&orig_chan_props, 0, sizeof(struct gsi_chan_props));
	memset(&orig_chan_scratch, 0, sizeof(union gsi_channel_scratch));
	gsi_res = gsi_get_channel_cfg(ep->gsi_chan_hdl, &orig_chan_props,
		&orig_chan_scratch);
	if (gsi_res) {
		IPAERR("Error getting channel properties: %d\n", gsi_res);
		return -EFAULT;
	}
	memset(&chan_dma, 0, sizeof(struct ipa_mem_buffer));
	result = ipa3_reconfigure_channel_to_gpi(ep, &orig_chan_props,
		&chan_dma);
	if (result)
		return -EFAULT;

	ipahal_read_reg_n_fields(IPA_ENDP_INIT_CTRL_n, clnt_hdl, &ctrl);
	if (ctrl.ipa_ep_suspend) {
		IPADBG("pipe is suspended, remove suspend\n");
		pipe_suspended = true;
		ctrl.ipa_ep_suspend = false;
		ipahal_write_reg_n_fields(IPA_ENDP_INIT_CTRL_n,
			clnt_hdl, &ctrl);
	}

	/* Start channel and put 1 Byte descriptor on it */
	gsi_res = gsi_start_channel(ep->gsi_chan_hdl);
	if (gsi_res) {
		IPAERR("Error starting channel: %d\n", gsi_res);
		result = -EFAULT;
		goto start_chan_fail;
	}

	memset(&xfer_elem, 0, sizeof(struct gsi_xfer_elem));
	buff = dma_alloc_coherent(ipa3_ctx->pdev, 1, &dma_addr,
		GFP_KERNEL);
	xfer_elem.addr = dma_addr;
	xfer_elem.len = 1;
	xfer_elem.flags = GSI_XFER_FLAG_EOT;
	xfer_elem.type = GSI_XFER_ELEM_DATA;

	gsi_res = gsi_queue_xfer(ep->gsi_chan_hdl, 1, &xfer_elem,
		true);
	if (gsi_res) {
		IPAERR("Error queueing xfer: %d\n", gsi_res);
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
		IPAERR("Failed closing aggr frame for client: %d\n",
			clnt_hdl);
		BUG();
	}

	dma_free_coherent(ipa3_ctx->pdev, 1, buff, dma_addr);

	result = ipa3_stop_gsi_channel(clnt_hdl);
	if (result) {
		IPAERR("Error stopping channel: %d\n", result);
		goto start_chan_fail;
	}

	/* Reset channel */
	gsi_res = gsi_reset_channel(ep->gsi_chan_hdl);
	if (gsi_res) {
		IPAERR("Error resetting channel: %d\n", gsi_res);
		result = -EFAULT;
		goto start_chan_fail;
	}

	/*
	 * Need to sleep for 1ms as required by H/W verified
	 * sequence for resetting GSI channel
	 */
	msleep(IPA_POLL_AGGR_STATE_SLEEP_MSEC);

	if (pipe_suspended) {
		IPADBG("suspend the pipe again\n");
		ctrl.ipa_ep_suspend = true;
		ipahal_write_reg_n_fields(IPA_ENDP_INIT_CTRL_n,
			clnt_hdl, &ctrl);
	}

	/* Restore channels properties */
	result = ipa3_restore_channel_properties(ep, &orig_chan_props,
		&orig_chan_scratch);
	if (result)
		goto restore_props_fail;
	dma_free_coherent(ipa3_ctx->pdev, chan_dma.size,
		chan_dma.base, chan_dma.phys_base);

	return 0;

queue_xfer_fail:
	ipa3_stop_gsi_channel(clnt_hdl);
	dma_free_coherent(ipa3_ctx->pdev, 1, buff, dma_addr);
start_chan_fail:
	if (pipe_suspended) {
		IPADBG("suspend the pipe again\n");
		ctrl.ipa_ep_suspend = true;
		ipahal_write_reg_n_fields(IPA_ENDP_INIT_CTRL_n,
			clnt_hdl, &ctrl);
	}
	ipa3_restore_channel_properties(ep, &orig_chan_props,
		&orig_chan_scratch);
restore_props_fail:
	dma_free_coherent(ipa3_ctx->pdev, chan_dma.size,
		chan_dma.base, chan_dma.phys_base);
	return result;
}

int ipa3_reset_gsi_channel(u32 clnt_hdl)
{
	struct ipa3_ep_context *ep;
	int result = -EFAULT;
	int gsi_res;
	int aggr_active_bitmap = 0;

	IPADBG("entry\n");
	if (clnt_hdl >= ipa3_ctx->ipa_num_pipes ||
		ipa3_ctx->ep[clnt_hdl].valid == 0) {
		IPAERR("Bad parameter.\n");
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
		IPAERR("Error resetting channel: %d\n", gsi_res);
		result = -EFAULT;
		goto reset_chan_fail;
	}

finish_reset:
	if (!ep->keep_ipa_awake)
		IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));

	IPADBG("exit\n");
	return 0;

reset_chan_fail:
	if (!ep->keep_ipa_awake)
		IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));
	return result;
}

int ipa3_reset_gsi_event_ring(u32 clnt_hdl)
{
	struct ipa3_ep_context *ep;
	int result = -EFAULT;
	int gsi_res;

	IPADBG("entry\n");
	if (clnt_hdl >= ipa3_ctx->ipa_num_pipes ||
		ipa3_ctx->ep[clnt_hdl].valid == 0) {
		IPAERR("Bad parameter.\n");
		return -EINVAL;
	}

	ep = &ipa3_ctx->ep[clnt_hdl];

	if (!ep->keep_ipa_awake)
		IPA_ACTIVE_CLIENTS_INC_EP(ipa3_get_client_mapping(clnt_hdl));
	/* Reset event ring */
	gsi_res = gsi_reset_evt_ring(ep->gsi_evt_ring_hdl);
	if (gsi_res) {
		IPAERR("Error resetting event: %d\n", gsi_res);
		result = -EFAULT;
		goto reset_evt_fail;
	}

	if (!ep->keep_ipa_awake)
		IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));

	IPADBG("exit\n");
	return 0;

reset_evt_fail:
	if (!ep->keep_ipa_awake)
		IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));
	return result;
}

static bool ipa3_is_legal_params(struct ipa_request_gsi_channel_params *params)
{
	if (params->client >= IPA_CLIENT_MAX)
		return false;
	else
		return true;
}

int ipa3_smmu_map_peer_reg(phys_addr_t phys_addr, bool map)
{
	struct iommu_domain *smmu_domain;
	int res;

	if (ipa3_ctx->smmu_s1_bypass)
		return 0;

	smmu_domain = ipa3_get_smmu_domain();
	if (!smmu_domain) {
		IPAERR("invalid smmu domain\n");
		return -EINVAL;
	}

	if (map) {
		res = ipa3_iommu_map(smmu_domain, phys_addr, phys_addr,
			PAGE_SIZE, IOMMU_READ | IOMMU_WRITE | IOMMU_MMIO);
	} else {
		res = iommu_unmap(smmu_domain, phys_addr, PAGE_SIZE);
		res = (res != PAGE_SIZE);
	}
	if (res) {
		IPAERR("Fail to %s reg 0x%pa\n", map ? "map" : "unmap",
			&phys_addr);
		return -EINVAL;
	}

	IPADBG("Peer reg 0x%pa %s\n", &phys_addr, map ? "map" : "unmap");

	return 0;
}

int ipa3_smmu_map_peer_buff(u64 iova, phys_addr_t phys_addr, u32 size, bool map)
{
	struct iommu_domain *smmu_domain;
	int res;

	if (ipa3_ctx->smmu_s1_bypass)
		return 0;

	smmu_domain = ipa3_get_smmu_domain();
	if (!smmu_domain) {
		IPAERR("invalid smmu domain\n");
		return -EINVAL;
	}

	if (map) {
		res = ipa3_iommu_map(smmu_domain,
			rounddown(iova, PAGE_SIZE),
			rounddown(phys_addr, PAGE_SIZE),
			roundup(size + iova - rounddown(iova, PAGE_SIZE),
			PAGE_SIZE),
			IOMMU_READ | IOMMU_WRITE);
		if (res) {
			IPAERR("Fail to map 0x%llx->0x%pa\n", iova, &phys_addr);
			return -EINVAL;
		}
	} else {
		res = iommu_unmap(smmu_domain,
			rounddown(iova, PAGE_SIZE),
			roundup(size + iova - rounddown(iova, PAGE_SIZE),
			PAGE_SIZE));
		if (res != roundup(size + iova - rounddown(iova, PAGE_SIZE),
			PAGE_SIZE)) {
			IPAERR("Fail to unmap 0x%llx->0x%pa\n",
				iova, &phys_addr);
			return -EINVAL;
		}
	}

	IPADBG("Peer buff %s 0x%llx->0x%pa\n", map ? "map" : "unmap",
		iova, &phys_addr);

	return 0;
}


int ipa3_request_gsi_channel(struct ipa_request_gsi_channel_params *params,
			     struct ipa_req_chan_out_params *out_params)
{
	int ipa_ep_idx;
	int result = -EFAULT;
	struct ipa3_ep_context *ep;
	struct ipahal_reg_ep_cfg_status ep_status;
	unsigned long gsi_dev_hdl;
	int gsi_res;
	const struct ipa_gsi_ep_config *gsi_ep_cfg_ptr;

	IPADBG("entry\n");
	if (params == NULL || out_params == NULL ||
		!ipa3_is_legal_params(params)) {
		IPAERR("bad parameters\n");
		return -EINVAL;
	}

	ipa_ep_idx = ipa3_get_ep_mapping(params->client);
	if (ipa_ep_idx == -1) {
		IPAERR("fail to alloc EP.\n");
		goto fail;
	}

	ep = &ipa3_ctx->ep[ipa_ep_idx];

	if (ep->valid) {
		IPAERR("EP already allocated.\n");
		goto fail;
	}

	memset(&ipa3_ctx->ep[ipa_ep_idx], 0, sizeof(struct ipa3_ep_context));
	IPA_ACTIVE_CLIENTS_INC_SIMPLE();

	ep->skip_ep_cfg = params->skip_ep_cfg;
	ep->valid = 1;
	ep->client = params->client;
	ep->client_notify = params->notify;
	ep->priv = params->priv;
	ep->keep_ipa_awake = params->keep_ipa_awake;

	if (!ep->skip_ep_cfg) {
		if (ipa3_cfg_ep(ipa_ep_idx, &params->ipa_ep_cfg)) {
			IPAERR("fail to configure EP.\n");
			goto ipa_cfg_ep_fail;
		}
		/* Setting EP status 0 */
		memset(&ep_status, 0, sizeof(ep_status));
		if (ipa3_cfg_ep_status(ipa_ep_idx, &ep_status)) {
			IPAERR("fail to configure status of EP.\n");
			goto ipa_cfg_ep_fail;
		}
		IPADBG("ep configuration successful\n");
	} else {
		IPADBG("Skipping endpoint configuration.\n");
	}

	out_params->clnt_hdl = ipa_ep_idx;

	result = ipa3_enable_data_path(out_params->clnt_hdl);
	if (result) {
		IPAERR("enable data path failed res=%d clnt=%d.\n", result,
				out_params->clnt_hdl);
		goto ipa_cfg_ep_fail;
	}

	gsi_dev_hdl = ipa3_ctx->gsi_dev_hdl;
	gsi_res = gsi_alloc_evt_ring(&params->evt_ring_params, gsi_dev_hdl,
		&ep->gsi_evt_ring_hdl);
	if (gsi_res) {
		IPAERR("Error allocating event ring: %d\n", gsi_res);
		result = -EFAULT;
		goto ipa_cfg_ep_fail;
	}

	gsi_res = gsi_write_evt_ring_scratch(ep->gsi_evt_ring_hdl,
		params->evt_scratch);
	if (gsi_res) {
		IPAERR("Error writing event ring scratch: %d\n", gsi_res);
		result = -EFAULT;
		goto write_evt_scratch_fail;
	}

	gsi_ep_cfg_ptr = ipa3_get_gsi_ep_info(ep->client);
	if (gsi_ep_cfg_ptr == NULL) {
		IPAERR("Error ipa3_get_gsi_ep_info ret NULL\n");
		result = -EFAULT;
		goto write_evt_scratch_fail;
	}

	params->chan_params.evt_ring_hdl = ep->gsi_evt_ring_hdl;
	params->chan_params.ch_id = gsi_ep_cfg_ptr->ipa_gsi_chan_num;
	gsi_res = gsi_alloc_channel(&params->chan_params, gsi_dev_hdl,
		&ep->gsi_chan_hdl);
	if (gsi_res) {
		IPAERR("Error allocating channel: %d, chan_id: %d\n", gsi_res,
			params->chan_params.ch_id);
		result = -EFAULT;
		goto write_evt_scratch_fail;
	}

	memcpy(&ep->chan_scratch, &params->chan_scratch,
		sizeof(union __packed gsi_channel_scratch));
	gsi_res = gsi_write_channel_scratch(ep->gsi_chan_hdl,
		params->chan_scratch);
	if (gsi_res) {
		IPAERR("Error writing channel scratch: %d\n", gsi_res);
		result = -EFAULT;
		goto write_chan_scratch_fail;
	}

	gsi_res = gsi_query_channel_db_addr(ep->gsi_chan_hdl,
		&out_params->db_reg_phs_addr_lsb,
		&out_params->db_reg_phs_addr_msb);
	if (gsi_res) {
		IPAERR("Error querying channel DB registers addresses: %d\n",
			gsi_res);
		result = -EFAULT;
		goto write_chan_scratch_fail;
	}

	ep->gsi_mem_info.evt_ring_len = params->evt_ring_params.ring_len;
	ep->gsi_mem_info.evt_ring_base_addr =
		params->evt_ring_params.ring_base_addr;
	ep->gsi_mem_info.evt_ring_base_vaddr =
		params->evt_ring_params.ring_base_vaddr;
	ep->gsi_mem_info.chan_ring_len = params->chan_params.ring_len;
	ep->gsi_mem_info.chan_ring_base_addr =
		params->chan_params.ring_base_addr;
	ep->gsi_mem_info.chan_ring_base_vaddr =
		params->chan_params.ring_base_vaddr;

	ipa3_ctx->skip_ep_cfg_shadow[ipa_ep_idx] = ep->skip_ep_cfg;
	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();

	IPADBG("client %d (ep: %d) connected\n", params->client, ipa_ep_idx);
	IPADBG("exit\n");

	return 0;

write_chan_scratch_fail:
	gsi_dealloc_channel(ep->gsi_chan_hdl);
write_evt_scratch_fail:
	gsi_dealloc_evt_ring(ep->gsi_evt_ring_hdl);
ipa_cfg_ep_fail:
	memset(&ipa3_ctx->ep[ipa_ep_idx], 0, sizeof(struct ipa3_ep_context));
	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
fail:
	return result;
}

int ipa3_enable_force_clear(u32 request_id, bool throttle_source,
	u32 source_pipe_bitmask)
{
	struct ipa_enable_force_clear_datapath_req_msg_v01 req;
	int result;

	memset(&req, 0, sizeof(req));
	req.request_id = request_id;
	req.source_pipe_bitmask = source_pipe_bitmask;
	if (throttle_source) {
		req.throttle_source_valid = 1;
		req.throttle_source = 1;
	}
	result = ipa3_qmi_enable_force_clear_datapath_send(&req);
	if (result) {
		IPAERR("ipa3_qmi_enable_force_clear_datapath_send failed %d\n",
			result);
		return result;
	}

	return 0;
}

int ipa3_disable_force_clear(u32 request_id)
{
	struct ipa_disable_force_clear_datapath_req_msg_v01 req;
	int result;

	memset(&req, 0, sizeof(req));
	req.request_id = request_id;
	result = ipa3_qmi_disable_force_clear_datapath_send(&req);
	if (result) {
		IPAERR("ipa3_qmi_disable_force_clear_datapath_send failed %d\n",
			result);
		return result;
	}

	return 0;
}

int ipa3_release_gsi_channel(u32 clnt_hdl)
{
	struct ipa3_ep_context *ep;
	int result = -EFAULT;
	int gsi_res;

	IPADBG("entry\n");
	if (clnt_hdl >= ipa3_ctx->ipa_num_pipes ||
		ipa3_ctx->ep[clnt_hdl].valid == 0) {
		IPAERR("Bad parameter.\n");
		return -EINVAL;
	}

	ep = &ipa3_ctx->ep[clnt_hdl];

	if (!ep->keep_ipa_awake)
		IPA_ACTIVE_CLIENTS_INC_EP(ipa3_get_client_mapping(clnt_hdl));

	gsi_res = gsi_dealloc_channel(ep->gsi_chan_hdl);
	if (gsi_res) {
		IPAERR("Error deallocating channel: %d\n", gsi_res);
		goto dealloc_chan_fail;
	}

	gsi_res = gsi_dealloc_evt_ring(ep->gsi_evt_ring_hdl);
	if (gsi_res) {
		IPAERR("Error deallocating event: %d\n", gsi_res);
		goto dealloc_chan_fail;
	}

	if (!ep->keep_ipa_awake)
		IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));

	memset(&ipa3_ctx->ep[clnt_hdl], 0, sizeof(struct ipa3_ep_context));

	IPADBG("exit\n");
	return 0;

dealloc_chan_fail:
	if (!ep->keep_ipa_awake)
		IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));
	return result;
}

int ipa3_start_gsi_channel(u32 clnt_hdl)
{
	struct ipa3_ep_context *ep;
	int result = -EFAULT;
	int gsi_res;

	IPADBG("entry\n");
	if (clnt_hdl >= ipa3_ctx->ipa_num_pipes  ||
		ipa3_ctx->ep[clnt_hdl].valid == 0) {
		IPAERR("Bad parameters.\n");
		return -EINVAL;
	}

	ep = &ipa3_ctx->ep[clnt_hdl];

	if (!ep->keep_ipa_awake)
		IPA_ACTIVE_CLIENTS_INC_EP(ipa3_get_client_mapping(clnt_hdl));

	gsi_res = gsi_start_channel(ep->gsi_chan_hdl);
	if (gsi_res) {
		IPAERR("Error starting channel: %d\n", gsi_res);
		goto start_chan_fail;
	}

	if (!ep->keep_ipa_awake)
		IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));

	IPADBG("exit\n");
	return 0;

start_chan_fail:
	if (!ep->keep_ipa_awake)
		IPA_ACTIVE_CLIENTS_DEC_EP(ipa3_get_client_mapping(clnt_hdl));
	return result;
}
