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

static int ipa_reset_with_open_aggr_frame_wa(u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ep_id];
	struct ipa_reg_aggr_force_close force_close;
	struct ipa_reg_endp_init_ctrl init_ctrl;
	struct ipa_dma_mem dma_byte;
	struct gsi_xfer_elem xfer_elem = { };
	int aggr_active_bitmap = 0;
	bool ep_suspended = false;
	int ret;
	int i;

	ipa_debug("Applying reset channel with open aggregation frame WA\n");

	ipa_reg_aggr_force_close(&force_close, BIT(ep_id));
	ipa_write_reg_fields(IPA_AGGR_FORCE_CLOSE, &force_close);

	/* Reset channel */
	ret = gsi_reset_channel(ipa_ctx->gsi, ep->channel_id);
	if (ret)
		return ret;

	/* Turn off the doorbell engine.  We're going to poll until
	 * we know aggregation isn't active.
	 */
	gsi_set_channel_cfg(ipa_ctx->gsi, ep->channel_id, false);

	ipa_read_reg_n_fields(IPA_ENDP_INIT_CTRL_N, ep_id, &init_ctrl);
	if (init_ctrl.endp_suspend) {
		ipa_debug("endpoint is suspended, remove suspend\n");
		ep_suspended = true;
		ipa_reg_endp_init_ctrl(&init_ctrl, false);
		ipa_write_reg_n_fields(IPA_ENDP_INIT_CTRL_N, ep_id, &init_ctrl);
	}

	/* Start channel and put 1 Byte descriptor on it */
	ret = gsi_start_channel(ipa_ctx->gsi, ep->channel_id);
	if (ret)
		goto out_suspend_again;

	if (ipa_dma_alloc(&dma_byte, 1, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto err_stop_channel;
	}

	xfer_elem.addr = dma_byte.phys;
	xfer_elem.len = 1;	/* = dma_byte.size; */
	xfer_elem.flags = GSI_XFER_FLAG_EOT;
	xfer_elem.type = GSI_XFER_ELEM_DATA;

	ret = gsi_queue_xfer(ipa_ctx->gsi, ep->channel_id, 1, &xfer_elem, true);
	if (ret)
		goto err_dma_free;

	/* Wait for aggregation frame to be closed and stop channel*/
	for (i = 0; i < IPA_POLL_AGGR_STATE_RETRIES_NUM; i++) {
		aggr_active_bitmap = ipa_read_reg(IPA_STATE_AGGR_ACTIVE);
		if (!(aggr_active_bitmap & BIT(ep_id)))
			break;
		msleep(IPA_POLL_AGGR_STATE_SLEEP_MSEC);
	}

	ipa_bug_on(aggr_active_bitmap & BIT(ep_id));

	ipa_dma_free(&dma_byte);

	ret = ipa_stop_gsi_channel(ep_id);
	if (ret)
		goto out_suspend_again;

	/* Reset the channel.  If successful we need to sleep for 1
	 * msec to complete the GSI channel reset sequence.  Either
	 * way we finish by suspending the channel again (if necessary)
	 * and re-enabling its doorbell engine.
	 */
	ret = gsi_reset_channel(ipa_ctx->gsi, ep->channel_id);
	if (!ret)
		msleep(IPA_POLL_AGGR_STATE_SLEEP_MSEC);
	goto out_suspend_again;

err_dma_free:
	ipa_dma_free(&dma_byte);
err_stop_channel:
	ipa_stop_gsi_channel(ep_id);
out_suspend_again:
	if (ep_suspended) {
		ipa_debug("suspend the endpoint again\n");
		ipa_reg_endp_init_ctrl(&init_ctrl, true);
		ipa_write_reg_n_fields(IPA_ENDP_INIT_CTRL_N, ep_id, &init_ctrl);
	}
	/* Turn on the doorbell engine again */
	gsi_set_channel_cfg(ipa_ctx->gsi, ep->channel_id, true);

	return ret;
}

void ipa_reset_gsi_channel(u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ep_id];
	u32 aggr_active_bitmap;

	/* Check for open aggregation frame on Consumer EP -
	 * reset with open aggregation frame WA
	 */
	if (ipa_consumer(ep->client))
		aggr_active_bitmap = ipa_read_reg(IPA_STATE_AGGR_ACTIVE);
	else
		aggr_active_bitmap = 0;

	if (aggr_active_bitmap & BIT(ep_id)) {
		ipa_bug_on(ipa_reset_with_open_aggr_frame_wa(ep_id));
	} else {
		/* If the reset called after stop, need to wait 1ms */
		msleep(IPA_POLL_AGGR_STATE_SLEEP_MSEC);
		ipa_bug_on(gsi_reset_channel(ipa_ctx->gsi, ep->channel_id));
	}
}
