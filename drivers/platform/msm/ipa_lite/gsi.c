/* Copyright (c) 2015-2017, The Linux Foundation. All rights reserved.
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

#define pr_fmt(fmt)    "gsi %s:%d " fmt, __func__, __LINE__

#include <linux/of.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include "gsi.h"
#include "gsi_reg.h"

#define GSI_CMD_TIMEOUT (5*HZ)
#define GSI_STOP_CMD_TIMEOUT_MS 20
#define GSI_MAX_CH_LOW_WEIGHT 15
#define GSI_MHI_ER_START 10
#define GSI_MHI_ER_END 16

#define GSI_RESET_WA_MIN_SLEEP 1000
#define GSI_RESET_WA_MAX_SLEEP 2000

struct gsi_ctx *gsi_ctx;

static void gsi_irq_set(uint32_t offset, uint32_t val)
{
	gsi_writel(val, offset);
}

static void gsi_irq_update(uint32_t offset, uint32_t mask, uint32_t val)
{
	uint32_t curr;

	curr = gsi_readl(offset);
	val = (curr & ~mask) | (val & mask);
	gsi_writel(val, offset);
}

static void gsi_irq_control_event(uint32_t ee, uint8_t evt_id, bool enable)
{
	uint32_t mask = 1U << evt_id;
	uint32_t val = enable ? ~0 : 0;

	gsi_irq_update(GSI_EE_n_CNTXT_SRC_IEOB_IRQ_MSK_OFFS(ee), mask, val);
}

static void gsi_irq_control_all(uint32_t ee, bool enable)
{
	uint32_t val = enable ? ~0 : 0;

	/* Inter EE commands / interrupt are no supported. */
	gsi_irq_set(GSI_EE_n_CNTXT_TYPE_IRQ_MSK_OFFS(ee), val);
	gsi_irq_set(GSI_EE_n_CNTXT_SRC_GSI_CH_IRQ_MSK_OFFS(ee), val);
	gsi_irq_set(GSI_EE_n_CNTXT_SRC_EV_CH_IRQ_MSK_OFFS(ee), val);
	gsi_irq_set(GSI_EE_n_CNTXT_SRC_IEOB_IRQ_MSK_OFFS(ee), val);
	gsi_irq_set(GSI_EE_n_CNTXT_GLOB_IRQ_EN_OFFS(ee), val);
	/* Never enable GSI_BREAK_POINT */
	val &= ~GSI_EE_n_CNTXT_GSI_IRQ_CLR_GSI_BREAK_POINT_BMSK;
	gsi_irq_set(GSI_EE_n_CNTXT_GSI_IRQ_EN_OFFS(ee), val);
}

static void gsi_handle_ch_ctrl(int ee)
{
	uint32_t ch;
	int i;
	uint32_t val;
	struct gsi_chan_ctx *ctx;

	ch = gsi_readl(GSI_EE_n_CNTXT_SRC_GSI_CH_IRQ_OFFS(ee));
	gsi_writel(ch, GSI_EE_n_CNTXT_SRC_GSI_CH_IRQ_CLR_OFFS(ee));
	ipa_debug("ch %x\n", ch);
	for (i = 0; i < GSI_CHAN_MAX; i++) {
		if ((1 << i) & ch) {
			if (i >= gsi_ctx->max_ch) {
				ipa_err("invalid channel %d\n", i);
				break;
			}

			ctx = &gsi_ctx->chan[i];
			val = gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_0_OFFS(i, ee));
			ctx->state = (val &
				GSI_EE_n_GSI_CH_k_CNTXT_0_CHSTATE_BMSK) >>
				GSI_EE_n_GSI_CH_k_CNTXT_0_CHSTATE_SHFT;
			ipa_debug("ch %u state updated to %u\n", i, ctx->state);
			complete(&ctx->compl);
			gsi_ctx->ch_dbg[i].cmd_completed++;
		}
	}
}

static void gsi_handle_ev_ctrl(int ee)
{
	uint32_t ch;
	int i;
	uint32_t val;
	struct gsi_evt_ctx *ctx;

	ch = gsi_readl(GSI_EE_n_CNTXT_SRC_EV_CH_IRQ_OFFS(ee));
	gsi_writel(ch, GSI_EE_n_CNTXT_SRC_EV_CH_IRQ_CLR_OFFS(ee));
	ipa_debug("ev %x\n", ch);
	for (i = 0; i < GSI_EVT_RING_MAX; i++) {
		if ((1 << i) & ch) {
			if (i >= gsi_ctx->max_ev) {
				ipa_err("invalid event %d\n", i);
				break;
			}

			ctx = &gsi_ctx->evtr[i];
			val = gsi_readl(GSI_EE_n_EV_CH_k_CNTXT_0_OFFS(i, ee));
			ctx->state = (val &
				GSI_EE_n_EV_CH_k_CNTXT_0_CHSTATE_BMSK) >>
				GSI_EE_n_EV_CH_k_CNTXT_0_CHSTATE_SHFT;
			ipa_debug("evt %u state updated to %u\n", i, ctx->state);
			complete(&ctx->compl);
		}
	}
}

#define CASE(x)						\
	case GSI_EVT_ ## x ## _ERR:			\
		ipa_err("Got GSI_EVT_ " #x "_ERR\n");	\
		break

static void gsi_evt_ring_err(enum gsi_evt_err evt_id)
{
	switch (evt_id) {
	CASE(OUT_OF_BUFFERS);
	CASE(OUT_OF_RESOURCES);
	CASE(UNSUPPORTED_INTER_EE_OP);
	CASE(EVT_RING_EMPTY);
	default:
		ipa_err("Unexpected err evt: %d\n", (int)evt_id);
	}
}
#undef CASE

static void gsi_handle_glob_err(uint32_t err)
{
	struct gsi_log_err *log;
	struct gsi_chan_ctx *ch;
	struct gsi_evt_ctx *ev;
	struct gsi_chan_err_notify chan_notify;
	struct gsi_evt_err_notify evt_notify;
	uint32_t val;

	log = (struct gsi_log_err *)&err;
	ipa_err("log err_type=%u ee=%u idx=%u\n", log->err_type, log->ee,
			log->virt_idx);
	ipa_err("code=%u arg1=%u arg2=%u arg3=%u\n", log->code, log->arg1,
			log->arg2, log->arg3);
	switch (log->err_type) {
	case GSI_ERR_TYPE_GLOB:
		ipa_err("Got global GP ERROR\n");
		ipa_err("Err_desc = 0x%04x\n", err & 0xffff);
		BUG();
		break;
	case GSI_ERR_TYPE_CHAN:
		if (log->virt_idx >= gsi_ctx->max_ch) {
			ipa_err("Unexpected ch %d\n", log->virt_idx);
			WARN_ON(1);
			return;
		}

		ch = &gsi_ctx->chan[log->virt_idx];
		chan_notify.chan_user_data = ch->props.chan_user_data;
		chan_notify.err_desc = err & 0xFFFF;
		if (log->code == GSI_INVALID_TRE_ERR) {
			BUG_ON(log->ee != gsi_ctx->ee);
			val = gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_0_OFFS(log->virt_idx,
					gsi_ctx->ee));
			ch->state = (val &
				GSI_EE_n_GSI_CH_k_CNTXT_0_CHSTATE_BMSK) >>
				GSI_EE_n_GSI_CH_k_CNTXT_0_CHSTATE_SHFT;
			ipa_debug("ch %u state updated to %u\n", log->virt_idx,
					ch->state);
			ch->stats.invalid_tre_error++;
			BUG_ON(ch->state != GSI_CHAN_STATE_ERROR);
			chan_notify.evt_id = GSI_CHAN_INVALID_TRE_ERR;
		} else if (log->code == GSI_OUT_OF_BUFFERS_ERR) {
			BUG_ON(log->ee != gsi_ctx->ee);
			chan_notify.evt_id = GSI_CHAN_OUT_OF_BUFFERS_ERR;
		} else if (log->code == GSI_OUT_OF_RESOURCES_ERR) {
			BUG_ON(log->ee != gsi_ctx->ee);
			chan_notify.evt_id = GSI_CHAN_OUT_OF_RESOURCES_ERR;
			complete(&ch->compl);
		} else if (log->code == GSI_UNSUPPORTED_INTER_EE_OP_ERR) {
			chan_notify.evt_id =
				GSI_CHAN_UNSUPPORTED_INTER_EE_OP_ERR;
		} else if (log->code == GSI_NON_ALLOCATED_EVT_ACCESS_ERR) {
			BUG_ON(log->ee != gsi_ctx->ee);
			chan_notify.evt_id =
				GSI_CHAN_NON_ALLOCATED_EVT_ACCESS_ERR;
		} else if (log->code == GSI_HWO_1_ERR) {
			BUG_ON(log->ee != gsi_ctx->ee);
			chan_notify.evt_id = GSI_CHAN_HWO_1_ERR;
		} else {
			BUG();
		}
		if (ch->props.err_cb)
			ch->props.err_cb(&chan_notify);
		else
			WARN_ON(1);
		break;
	case GSI_ERR_TYPE_EVT:
		if (log->virt_idx >= gsi_ctx->max_ev) {
			ipa_err("Unexpected ev %d\n", log->virt_idx);
			WARN_ON(1);
			return;
		}

		ev = &gsi_ctx->evtr[log->virt_idx];
		evt_notify.err_desc = err & 0xFFFF;
		if (log->code == GSI_OUT_OF_BUFFERS_ERR) {
			BUG_ON(log->ee != gsi_ctx->ee);
			evt_notify.evt_id = GSI_EVT_OUT_OF_BUFFERS_ERR;
		} else if (log->code == GSI_OUT_OF_RESOURCES_ERR) {
			BUG_ON(log->ee != gsi_ctx->ee);
			evt_notify.evt_id = GSI_EVT_OUT_OF_RESOURCES_ERR;
			complete(&ev->compl);
		} else if (log->code == GSI_UNSUPPORTED_INTER_EE_OP_ERR) {
			evt_notify.evt_id = GSI_EVT_UNSUPPORTED_INTER_EE_OP_ERR;
		} else if (log->code == GSI_EVT_RING_EMPTY_ERR) {
			BUG_ON(log->ee != gsi_ctx->ee);
			evt_notify.evt_id = GSI_EVT_EVT_RING_EMPTY_ERR;
		} else {
			BUG();
		}
		gsi_evt_ring_err(evt_notify.evt_id);
		break;
	default:
		WARN_ON(1);
	}
}

static void gsi_handle_gp_int1(void)
{
	complete(&gsi_ctx->gen_ee_cmd_compl);
}

static void gsi_handle_glob_ee(int ee)
{
	uint32_t val;
	uint32_t err;
	uint32_t clr = ~0;

	val = gsi_readl(GSI_EE_n_CNTXT_GLOB_IRQ_STTS_OFFS(ee));

	if (val & GSI_EE_n_CNTXT_GLOB_IRQ_STTS_ERROR_INT_BMSK) {
		err = gsi_readl(GSI_EE_n_ERROR_LOG_OFFS(ee));
		gsi_writel(0, GSI_EE_n_ERROR_LOG_OFFS(ee));
		gsi_writel(clr, GSI_EE_n_ERROR_LOG_CLR_OFFS(ee));
		gsi_handle_glob_err(err);
	}

	if (val & GSI_EE_n_CNTXT_GLOB_IRQ_EN_GP_INT1_BMSK) {
		gsi_handle_gp_int1();
	}

	if (val & GSI_EE_n_CNTXT_GLOB_IRQ_EN_GP_INT2_BMSK) {
		ipa_err("Got global GP INT2\n");
		BUG();
	}

	if (val & GSI_EE_n_CNTXT_GLOB_IRQ_EN_GP_INT3_BMSK) {
		ipa_err("Got global GP INT3\n");
		BUG();
	}

	gsi_writel(val, GSI_EE_n_CNTXT_GLOB_IRQ_CLR_OFFS(ee));
}

static void gsi_incr_ring_wp(struct gsi_ring_ctx *ctx)
{
	ctx->wp_local += ctx->elem_sz;
	if (ctx->wp_local == ctx->end)
		ctx->wp_local = ctx->mem.phys_base;
}

static void gsi_incr_ring_rp(struct gsi_ring_ctx *ctx)
{
	ctx->rp_local += ctx->elem_sz;
	if (ctx->rp_local == ctx->end)
		ctx->rp_local = ctx->mem.phys_base;
}

uint16_t gsi_find_idx_from_addr(struct gsi_ring_ctx *ctx, uint64_t addr)
{
	BUG_ON(addr < ctx->mem.phys_base || addr >= ctx->end);

	return (uint32_t)(addr - ctx->mem.phys_base)/ctx->elem_sz;
}

static void gsi_process_chan(struct gsi_xfer_compl_evt *evt,
		struct gsi_chan_xfer_notify *notify, bool callback)
{
	uint32_t ch_id;
	struct gsi_chan_ctx *ch_ctx;
	uint16_t rp_idx;
	uint64_t rp;

	ch_id = evt->chid;
	if (ch_id >= gsi_ctx->max_ch) {
		ipa_err("Unexpected ch %d\n", ch_id);
		WARN_ON(1);
		return;
	}

	ch_ctx = &gsi_ctx->chan[ch_id];
	rp = evt->xfer_ptr;

	while (ch_ctx->ring.rp_local != rp) {
		gsi_incr_ring_rp(&ch_ctx->ring);
		ch_ctx->stats.completed++;
	}

	/* the element at RP is also processed */
	gsi_incr_ring_rp(&ch_ctx->ring);
	ch_ctx->stats.completed++;

	ch_ctx->ring.rp = ch_ctx->ring.rp_local;

	rp_idx = gsi_find_idx_from_addr(&ch_ctx->ring, rp);
	notify->xfer_user_data = ch_ctx->user_data[rp_idx];
	notify->chan_user_data = ch_ctx->props.chan_user_data;
	notify->evt_id = evt->code;
	notify->bytes_xfered = evt->len;
	if (callback) {
		if (atomic_read(&ch_ctx->poll_mode)) {
			ipa_err("Calling client callback in polling mode\n");
			WARN_ON(1);
		}
		ch_ctx->props.xfer_cb(notify);
	}
}

static void gsi_process_evt_re(struct gsi_evt_ctx *ctx,
		struct gsi_chan_xfer_notify *notify, bool callback)
{
	struct gsi_xfer_compl_evt *evt;
	uint16_t idx;

	idx = gsi_find_idx_from_addr(&ctx->ring, ctx->ring.rp_local);
	evt = ctx->ring.mem.base + idx * ctx->ring.elem_sz;
	gsi_process_chan(evt, notify, callback);
	gsi_incr_ring_rp(&ctx->ring);
	/* recycle this element */
	gsi_incr_ring_wp(&ctx->ring);
	ctx->stats.completed++;
}

static void gsi_ring_evt_doorbell(struct gsi_evt_ctx *ctx)
{
	uint32_t val;

	/*
	 * The doorbell 0 and 1 registers store the low-order and
	 * high-order 32 bits of the event ring doorbell register,
	 * respectively.  LSB (doorbell 0) must be written last.
	 */
	val = ctx->ring.wp_local >> 32;
	gsi_writel(val, GSI_EE_n_EV_CH_k_DOORBELL_1_OFFS(ctx->id,
				gsi_ctx->ee));
	val = ctx->ring.wp_local & GENMASK(31, 0);
	gsi_writel(val, GSI_EE_n_EV_CH_k_DOORBELL_0_OFFS(ctx->id,
				gsi_ctx->ee));
}

static void gsi_ring_chan_doorbell(struct gsi_chan_ctx *ctx)
{
	uint32_t val;

	/*
	 * allocate new events for this channel first
	 * before submitting the new TREs.
	 * for TO_GSI channels the event ring doorbell is rang as part of
	 * interrupt handling.
	 */
	if (ctx->evtr && ctx->props.dir == GSI_CHAN_DIR_FROM_GSI)
		gsi_ring_evt_doorbell(ctx->evtr);
	ctx->ring.wp = ctx->ring.wp_local;

	/*
	 * The doorbell 0 and 1 registers store the low-order and
	 * high-order 32 bits of the channel ring doorbell register,
	 * respectively.  LSB (doorbell 0) must be written last.
	 */
	val = ctx->ring.wp_local >> 32;
	gsi_writel(val, GSI_EE_n_GSI_CH_k_DOORBELL_1_OFFS(ctx->props.ch_id,
				gsi_ctx->ee));
	val = ctx->ring.wp_local & GENMASK(31, 0);
	gsi_writel(val, GSI_EE_n_GSI_CH_k_DOORBELL_0_OFFS(ctx->props.ch_id,
				gsi_ctx->ee));
}

static void gsi_handle_ieob(int ee)
{
	uint32_t ch;
	int i;
	uint64_t rp;
	struct gsi_evt_ctx *ctx;
	struct gsi_chan_xfer_notify notify;
	unsigned long flags;
	unsigned long cntr;
	uint32_t msk;

	ch = gsi_readl(GSI_EE_n_CNTXT_SRC_IEOB_IRQ_OFFS(ee));
	msk = gsi_readl(GSI_EE_n_CNTXT_SRC_IEOB_IRQ_MSK_OFFS(ee));
	gsi_writel(ch & msk, GSI_EE_n_CNTXT_SRC_IEOB_IRQ_CLR_OFFS(ee));

	for (i = 0; i < GSI_EVT_RING_MAX; i++) {
		if ((1 << i) & ch & msk) {
			if (i >= gsi_ctx->max_ev) {
				ipa_err("invalid event %d\n", i);
				break;
			}
			ctx = &gsi_ctx->evtr[i];

			spin_lock_irqsave(&ctx->ring.slock, flags);
check_again:
			cntr = 0;
			rp = gsi_readl(GSI_EE_n_EV_CH_k_CNTXT_4_OFFS(i, ee));
			rp |= ctx->ring.rp & 0xFFFFFFFF00000000;

			ctx->ring.rp = rp;
			while (ctx->ring.rp_local != rp) {
				++cntr;
				if (ctx->exclusive &&
					atomic_read(&ctx->chan->poll_mode)) {
					cntr = 0;
					break;
				}
				gsi_process_evt_re(ctx, &notify, true);
			}
			gsi_ring_evt_doorbell(ctx);
			if (cntr != 0)
				goto check_again;
			spin_unlock_irqrestore(&ctx->ring.slock, flags);
		}
	}
}

static void gsi_handle_inter_ee_ch_ctrl(int ee)
{
	uint32_t ch;
	int i;

	ch = gsi_readl(GSI_INTER_EE_n_SRC_GSI_CH_IRQ_OFFS(ee));
	gsi_writel(ch, GSI_INTER_EE_n_SRC_GSI_CH_IRQ_CLR_OFFS(ee));
	for (i = 0; i < GSI_CHAN_MAX; i++) {
		if ((1 << i) & ch) {
			/* not currently expected */
			ipa_err("ch %u was inter-EE changed\n", i);
		}
	}
}

static void gsi_handle_inter_ee_ev_ctrl(int ee)
{
	uint32_t ch;
	int i;

	ch = gsi_readl(GSI_INTER_EE_n_SRC_EV_CH_IRQ_OFFS(ee));
	gsi_writel(ch, GSI_INTER_EE_n_SRC_EV_CH_IRQ_CLR_OFFS(ee));
	for (i = 0; i < GSI_EVT_RING_MAX; i++) {
		if ((1 << i) & ch) {
			/* not currently expected */
			ipa_err("evt %u was inter-EE changed\n", i);
		}
	}
}

static void gsi_handle_general(int ee)
{
	uint32_t val;

	val = gsi_readl(GSI_EE_n_CNTXT_GSI_IRQ_STTS_OFFS(ee));

	if (val & GSI_EE_n_CNTXT_GSI_IRQ_CLR_GSI_MCS_STACK_OVRFLOW_BMSK) {
		ipa_err("Got MCS stack overflow\n");
		BUG();
	}

	if (val & GSI_EE_n_CNTXT_GSI_IRQ_CLR_GSI_CMD_FIFO_OVRFLOW_BMSK) {
		ipa_err("Got command FIFO overflow\n");
		BUG();
	}

	if (val & GSI_EE_n_CNTXT_GSI_IRQ_CLR_GSI_BUS_ERROR_BMSK) {
		ipa_err("Got bus error\n");
		BUG();
	}

	if (val & GSI_EE_n_CNTXT_GSI_IRQ_CLR_GSI_BREAK_POINT_BMSK)
		ipa_err("Got breakpoint\n");

	gsi_writel(val, GSI_EE_n_CNTXT_GSI_IRQ_CLR_OFFS(ee));
}

#define GSI_ISR_MAX_ITER 50

static void gsi_handle_irq(void)
{
	uint32_t type;
	int ee = gsi_ctx->ee;
	unsigned long cnt = 0;

	while (1) {
		type = gsi_readl(GSI_EE_n_CNTXT_TYPE_IRQ_OFFS(ee));
		if (!type)
			break;

		ipa_debug_low("type %x\n", type);

		if (type & GSI_EE_n_CNTXT_TYPE_IRQ_CH_CTRL_BMSK)
			gsi_handle_ch_ctrl(ee);

		if (type & GSI_EE_n_CNTXT_TYPE_IRQ_EV_CTRL_BMSK)
			gsi_handle_ev_ctrl(ee);

		if (type & GSI_EE_n_CNTXT_TYPE_IRQ_GLOB_EE_BMSK)
			gsi_handle_glob_ee(ee);

		if (type & GSI_EE_n_CNTXT_TYPE_IRQ_IEOB_BMSK)
			gsi_handle_ieob(ee);

		if (type & GSI_EE_n_CNTXT_TYPE_IRQ_INTER_EE_CH_CTRL_BMSK)
			gsi_handle_inter_ee_ch_ctrl(ee);

		if (type & GSI_EE_n_CNTXT_TYPE_IRQ_INTER_EE_EV_CTRL_BMSK)
			gsi_handle_inter_ee_ev_ctrl(ee);

		if (type & GSI_EE_n_CNTXT_TYPE_IRQ_GENERAL_BMSK)
			gsi_handle_general(ee);

		if (++cnt > GSI_ISR_MAX_ITER)
			BUG();
	}
}

static irqreturn_t gsi_isr(int irq, void *ctxt)
{
	BUG_ON(ctxt != gsi_ctx);

	gsi_handle_irq();

	return IRQ_HANDLED;
}

static uint32_t gsi_get_max_channels(void)
{
	uint32_t reg;

	/* SDM845 uses GSI hardware version 1.3.0 */
	reg = gsi_readl(GSI_V1_3_EE_n_GSI_HW_PARAM_2_OFFS(gsi_ctx->ee));
	reg = (reg & GSI_V1_3_EE_n_GSI_HW_PARAM_2_GSI_NUM_CH_PER_EE_BMSK) >>
		GSI_V1_3_EE_n_GSI_HW_PARAM_2_GSI_NUM_CH_PER_EE_SHFT;

	if (WARN_ON(reg > GSI_CHAN_MAX)) {
		ipa_err("bad gsi max channels %u\n", reg);

		return 0;
	}
	ipa_debug("max channels %d\n", reg);

	return reg;
}

static uint32_t gsi_get_max_event_rings(void)
{
	uint32_t reg;

	/* SDM845 uses GSI hardware version 1.3.0 */
	reg = gsi_readl(GSI_V1_3_EE_n_GSI_HW_PARAM_2_OFFS(gsi_ctx->ee));
	reg = (reg & GSI_V1_3_EE_n_GSI_HW_PARAM_2_GSI_NUM_EV_PER_EE_BMSK) >>
		GSI_V1_3_EE_n_GSI_HW_PARAM_2_GSI_NUM_EV_PER_EE_SHFT;

	if (WARN_ON(reg > GSI_EVT_RING_MAX)) {
		ipa_err("bad gsi max event rings %u\n", reg);

		return 0;
	}
	ipa_debug("max event rings %d\n", reg);

	return reg;
}

int gsi_register_device(u32 ee)
{
	struct platform_device *ipa3_pdev = to_platform_device(gsi_ctx->dev);
	struct resource *res;
	resource_size_t size;
	int ret;
	uint32_t val;

	if (gsi_ctx->per_registered) {
		ipa_err("per already registered\n");
		return -ENOTSUPP;
	}

	gsi_ctx->ee = ee;

	/* Get IPA GSI IRQ number */
	ret = platform_get_irq_byname(ipa3_pdev, "gsi-irq");
	if (ret < 0) {
		ipa_err(":failed to get gsi-irq!\n");
		return -ENODEV;
	}
	gsi_ctx->irq = ret;
	ipa_debug(": gsi-irq = %d\n", gsi_ctx->irq);

	spin_lock_init(&gsi_ctx->slock);
	ret = devm_request_irq(gsi_ctx->dev, gsi_ctx->irq, gsi_isr,
				IRQF_TRIGGER_HIGH, "gsi", gsi_ctx);
	if (ret) {
		ipa_err("failed to register isr for %u\n", gsi_ctx->irq);
		return -EIO;
	}

	ret = enable_irq_wake(gsi_ctx->irq);
	if (ret)
		ipa_err("failed to enable wake irq %u\n", gsi_ctx->irq);
	else
		ipa_err("GSI irq is wake enabled %u\n", gsi_ctx->irq);

	/* Get IPA GSI address */
	res = platform_get_resource_byname(ipa3_pdev, IORESOURCE_MEM,
			"gsi-base");
	if (!res) {
		ipa_err(":get resource failed for gsi-base!\n");
		return -ENODEV;
	}
	size = resource_size(res);
	ipa_debug(": gsi-base = %pa, size = %pa\n", &res->start, &size);

	gsi_ctx->base = devm_ioremap_nocache(gsi_ctx->dev, res->start, size);
	if (!gsi_ctx->base) {
		ipa_err("failed to remap GSI HW\n");
		return -ENOMEM;
	}


	val = gsi_readl(GSI_EE_n_GSI_STATUS_OFFS(gsi_ctx->ee));
	if (!(val & GSI_EE_n_GSI_STATUS_ENABLED_BMSK)) {
		ipa_err("Manager EE has not enabled GSI, GSI un-usable\n");
		return -EIO;
	}

	gsi_ctx->per_registered = true;
	mutex_init(&gsi_ctx->mlock);
	atomic_set(&gsi_ctx->num_chan, 0);
	atomic_set(&gsi_ctx->num_evt_ring, 0);

	gsi_ctx->max_ch = gsi_get_max_channels();
	if (!gsi_ctx->max_ch) {
		ipa_err("failed to get max channels\n");
		return -EIO;
	}
	gsi_ctx->max_ev = gsi_get_max_event_rings();
	if (!gsi_ctx->max_ev) {
		ipa_err("failed to get max event rings\n");
		return -EIO;
	}

	/* bitmap is max events excludes reserved events */
	gsi_ctx->evt_bmap = ~((1 << gsi_ctx->max_ev) - 1);
	gsi_ctx->evt_bmap |= ((1 << (GSI_MHI_ER_END + 1)) - 1) ^
		((1 << GSI_MHI_ER_START) - 1);

	/* Enable all interrupts */
	gsi_irq_control_all(gsi_ctx->ee, true);

	gsi_writel(GSI_INTR_IRQ, GSI_EE_n_CNTXT_INTSET_OFFS(gsi_ctx->ee));

	gsi_writel(0, GSI_EE_n_ERROR_LOG_OFFS(gsi_ctx->ee));

	return 0;
}

int gsi_deregister_device(void)
{
	if (atomic_read(&gsi_ctx->num_chan)) {
		ipa_err("%u channels are allocated\n",
				atomic_read(&gsi_ctx->num_chan));
		return -ENOTSUPP;
	}

	if (atomic_read(&gsi_ctx->num_evt_ring)) {
		ipa_err("%u evt rings are allocated\n",
				atomic_read(&gsi_ctx->num_evt_ring));
		return -ENOTSUPP;
	}

	/*
	 * Don't bother clearing the error log again (ERROR_LOG) or
	 * setting the interrupt type again (INTSET).  Disable all
	 * interrupts.
	 */
	gsi_irq_control_all(gsi_ctx->ee, false);

	/* Clean up everything else set up by gsi_register_device() */
	gsi_ctx->evt_bmap = 0;
	gsi_ctx->max_ev = 0;
	gsi_ctx->max_ch = 0;
	gsi_ctx->per_registered = false;
	/* XXX We don't know whether enabling this succeeded */
	/* (void)disable_irq_wake(gsi_ctx->irq); */

	return 0;
}

/* Compute the value to write to the event ring context 0 register */
static u32 evt_ring_ctx_0_val(enum gsi_evt_chtype chtype,
			enum gsi_intr_type intr_type, u32 re_size)
{
	u32 val;

	val = ((u32)chtype << GSI_EE_n_EV_CH_k_CNTXT_0_CHTYPE_SHFT) &
			GSI_EE_n_EV_CH_k_CNTXT_0_CHTYPE_BMSK;
	val |= ((u32)intr_type << GSI_EE_n_EV_CH_k_CNTXT_0_INTYPE_SHFT) &
			GSI_EE_n_EV_CH_k_CNTXT_0_INTYPE_BMSK;
	val |= (re_size << GSI_EE_n_EV_CH_k_CNTXT_0_ELEMENT_SIZE_SHFT)
			& GSI_EE_n_EV_CH_k_CNTXT_0_ELEMENT_SIZE_BMSK;

	return val;
}

/* Compute the value to write to the event ring context 8 register */
static u32 evt_ring_ctx_8_val(u32 int_modt, u32 int_modc)
{
	u32 val;

	val = (int_modt << GSI_EE_n_EV_CH_k_CNTXT_8_INT_MODT_SHFT) &
			GSI_EE_n_EV_CH_k_CNTXT_8_INT_MODT_BMSK;
	val |= (int_modc << GSI_EE_n_EV_CH_k_CNTXT_8_INT_MODC_SHFT) &
			GSI_EE_n_EV_CH_k_CNTXT_8_INT_MODC_BMSK;

	return val;
}

static void gsi_program_evt_ring_ctx(struct ipa_mem_buffer *mem,
		uint8_t evt_id, u16 int_modt)
{
	unsigned int ee = gsi_ctx->ee;
	u32 int_modc = 1;	/* moderation always comes from channel*/
	u32 val;

	ipa_debug("intf=GPI intr=IRQ re=%u\n", GSI_EVT_RING_ELEMENT_SIZE);

	val = evt_ring_ctx_0_val(GSI_EVT_CHTYPE_GPI_EV, GSI_INTR_IRQ,
					GSI_EVT_RING_ELEMENT_SIZE);
	gsi_writel(val, GSI_EE_n_EV_CH_k_CNTXT_0_OFFS(evt_id, ee));

	val = (mem->size & GSI_EE_n_EV_CH_k_CNTXT_1_R_LENGTH_BMSK) <<
		GSI_EE_n_EV_CH_k_CNTXT_1_R_LENGTH_SHFT;
	gsi_writel(val, GSI_EE_n_EV_CH_k_CNTXT_1_OFFS(evt_id, ee));

	/*
	 * The context 2 and 3 registers store the low-order and
	 * high-order 32 bits of the address of the event ring,
	 * respectively.
	 */
	val = mem->phys_base & GENMASK(31, 0);
	gsi_writel(val, GSI_EE_n_EV_CH_k_CNTXT_2_OFFS(evt_id, ee));

	val = mem->phys_base >> 32;
	gsi_writel(val, GSI_EE_n_EV_CH_k_CNTXT_3_OFFS(evt_id, ee));

	val = evt_ring_ctx_8_val(int_modt, int_modc);
	gsi_writel(val, GSI_EE_n_EV_CH_k_CNTXT_8_OFFS(evt_id, ee));

	/* No MSI write data, and MSI address high and low address is 0 */
	gsi_writel(0, GSI_EE_n_EV_CH_k_CNTXT_9_OFFS(evt_id, ee));
	gsi_writel(0, GSI_EE_n_EV_CH_k_CNTXT_10_OFFS(evt_id, ee));
	gsi_writel(0, GSI_EE_n_EV_CH_k_CNTXT_11_OFFS(evt_id, ee));

	/* We don't need to get event read pointer updates */
	gsi_writel(0, GSI_EE_n_EV_CH_k_CNTXT_12_OFFS(evt_id, ee));
	gsi_writel(0, GSI_EE_n_EV_CH_k_CNTXT_13_OFFS(evt_id, ee));
}

static void gsi_init_ring(struct gsi_ring_ctx *ctx, struct ipa_mem_buffer *mem)
{
	ctx->mem = *mem;
	ctx->wp = mem->phys_base;
	ctx->rp = mem->phys_base;
	ctx->wp_local = mem->phys_base;
	ctx->rp_local = mem->phys_base;
	ctx->elem_sz = GSI_EVT_RING_ELEMENT_SIZE;
	ctx->max_num_elem = mem->size / ctx->elem_sz - 1;
	ctx->end = mem->phys_base + (ctx->max_num_elem + 1) * ctx->elem_sz;
}

static void gsi_prime_evt_ring(struct gsi_evt_ctx *ctx)
{
	unsigned long flags;

	spin_lock_irqsave(&ctx->ring.slock, flags);
	memset(ctx->ring.mem.base, 0, ctx->ring.mem.size);
	ctx->ring.wp_local = ctx->ring.mem.phys_base +
		ctx->ring.max_num_elem * ctx->ring.elem_sz;
	gsi_ring_evt_doorbell(ctx);
	spin_unlock_irqrestore(&ctx->ring.slock, flags);
}

/* Compute the value to write to the event ring command register */
static u32 evt_ring_cmd_val(unsigned long evt_id, enum gsi_evt_ch_cmd_opcode op)
{
	u32 val;

	val = ((u32)evt_id << GSI_EE_n_EV_CH_CMD_CHID_SHFT) &
			GSI_EE_n_EV_CH_CMD_CHID_BMSK;
	val |= ((u32)op << GSI_EE_n_EV_CH_CMD_OPCODE_SHFT) &
			GSI_EE_n_EV_CH_CMD_OPCODE_BMSK;

	return val;
}

/* Note: only GPI interfaces, IRQ interrupts are currently supported */
long gsi_alloc_evt_ring(struct gsi_evt_ring_props *props, u32 size,
		uint16_t int_modt, bool excl)
{
	unsigned long evt_id;
	unsigned long required_alignment = roundup_pow_of_two(size);
	uint32_t val;
	struct gsi_evt_ctx *ctx;
	int ret;
	int ee = gsi_ctx->ee;
	unsigned long flags;

	/* Start by allocating the event id to use */
	mutex_lock(&gsi_ctx->mlock);
	evt_id = find_first_zero_bit(&gsi_ctx->evt_bmap, BITS_PER_LONG);
	if (evt_id == BITS_PER_LONG) {
		ipa_err("failed to alloc event ID\n");
		mutex_unlock(&gsi_ctx->mlock);
		return -ENOMEM;
	}
	set_bit(evt_id, &gsi_ctx->evt_bmap);
	mutex_unlock(&gsi_ctx->mlock);	/* acquired again below */

	ipa_debug("Using %lu as virt evt id\n", evt_id);

	ctx = &gsi_ctx->evtr[evt_id];
	memset(ctx, 0, sizeof(*ctx));
	ctx->id = evt_id;

	/* ipa_assert(!(size % GSI_EVT_RING_ELEMENT_SIZE)); */

	if (ipahal_dma_alloc(&ctx->mem, size, GFP_KERNEL)) {
		ipa_err("fail to dma alloc %u bytes\n", size);
		ret = -ENOMEM;
		goto err_clear_bit;
	}

	/* Verify the result meets our alignment requirements */
	if (ctx->mem.phys_base % required_alignment) {
		ipa_err("ring base %pad not aligned to 0x%lx\n",
				&ctx->mem.phys_base, required_alignment);
		ret = -EINVAL;
		goto err_free_dma;
	}

	ctx->int_modt = int_modt;
	ctx->exclusive = excl;
	mutex_init(&ctx->mlock);
	init_completion(&ctx->compl);
	atomic_set(&ctx->chan_ref_cnt, 0);

	mutex_lock(&gsi_ctx->mlock);
	val = evt_ring_cmd_val(evt_id, GSI_EVT_ALLOCATE);
	gsi_writel(val, GSI_EE_n_EV_CH_CMD_OFFS(ee));
	if (!wait_for_completion_timeout(&ctx->compl, GSI_CMD_TIMEOUT)) {
		ipa_err("evt_id=%lu timed out\n", evt_id);
		ret = -ETIMEDOUT;
		goto err_unlock;
	}

	if (ctx->state != GSI_EVT_RING_STATE_ALLOCATED) {
		ipa_err("evt_id=%lu allocation failed state=%u\n",
				evt_id, ctx->state);
		ret = -ENOMEM;
		goto err_unlock;
	}

	gsi_program_evt_ring_ctx(&ctx->mem, evt_id, int_modt);

	spin_lock_init(&ctx->ring.slock);
	gsi_init_ring(&ctx->ring, &ctx->mem);

	atomic_inc(&gsi_ctx->num_evt_ring);
	gsi_prime_evt_ring(ctx);
	mutex_unlock(&gsi_ctx->mlock);

	spin_lock_irqsave(&gsi_ctx->slock, flags);
	val = 1 << evt_id;
	gsi_writel(val, GSI_EE_n_CNTXT_SRC_IEOB_IRQ_CLR_OFFS(ee));

	/* enable ieob interrupts */
	gsi_irq_control_event(gsi_ctx->ee, ctx->id, true);
	spin_unlock_irqrestore(&gsi_ctx->slock, flags);

	return evt_id;

err_unlock:
	mutex_unlock(&gsi_ctx->mlock);
err_free_dma:
	ipahal_dma_free(&ctx->mem);
err_clear_bit:
	smp_mb__before_atomic();
	clear_bit(evt_id, &gsi_ctx->evt_bmap);
	smp_mb__after_atomic();

	return ret;
}

static void __gsi_write_evt_ring_scratch(unsigned long evt_ring_hdl,
		union __packed gsi_evt_scratch val)
{
	gsi_writel(val.data.word1, GSI_EE_n_EV_CH_k_SCRATCH_0_OFFS(evt_ring_hdl,
			gsi_ctx->ee));
	gsi_writel(val.data.word2, GSI_EE_n_EV_CH_k_SCRATCH_1_OFFS(evt_ring_hdl,
			gsi_ctx->ee));
}

int gsi_dealloc_evt_ring(unsigned long evt_ring_hdl)
{
	uint32_t val;
	struct gsi_evt_ctx *ctx;

	if (evt_ring_hdl >= gsi_ctx->max_ev) {
		ipa_err("bad params evt_ring_hdl=%lu\n", evt_ring_hdl);
		return -EINVAL;
	}

	ctx = &gsi_ctx->evtr[evt_ring_hdl];

	if (atomic_read(&ctx->chan_ref_cnt)) {
		ipa_err("%d channels still using this event ring\n",
			atomic_read(&ctx->chan_ref_cnt));
		return -ENOTSUPP;
	}

	/* TODO: add check for ERROR state */
	if (ctx->state != GSI_EVT_RING_STATE_ALLOCATED) {
		ipa_err("bad state %d\n", ctx->state);
		return -ENOTSUPP;
	}

	mutex_lock(&gsi_ctx->mlock);
	reinit_completion(&ctx->compl);

	val = evt_ring_cmd_val(evt_ring_hdl, GSI_EVT_DE_ALLOC);
	gsi_writel(val, GSI_EE_n_EV_CH_CMD_OFFS(gsi_ctx->ee));
	if (!wait_for_completion_timeout(&ctx->compl, GSI_CMD_TIMEOUT)) {
		ipa_err("evt_id=%lu timed out\n", evt_ring_hdl);
		mutex_unlock(&gsi_ctx->mlock);
		return -ETIMEDOUT;
	}

	if (ctx->state != GSI_EVT_RING_STATE_NOT_ALLOCATED) {
		ipa_err("evt_id=%lu unexpected state=%u\n", evt_ring_hdl,
				ctx->state);
		BUG();
	}

	clear_bit(evt_ring_hdl, &gsi_ctx->evt_bmap);
	mutex_unlock(&gsi_ctx->mlock);

	ctx->exclusive = 0;
	ctx->int_modt = 0;
	ipahal_dma_free(&ctx->mem);

	atomic_dec(&gsi_ctx->num_evt_ring);

	return 0;
}

int gsi_reset_evt_ring(unsigned long evt_ring_hdl)
{
	uint32_t val;
	struct gsi_evt_ctx *ctx;

	if (evt_ring_hdl >= gsi_ctx->max_ev) {
		ipa_err("bad params evt_ring_hdl=%lu\n", evt_ring_hdl);
		return -EINVAL;
	}

	ctx = &gsi_ctx->evtr[evt_ring_hdl];

	if (ctx->state != GSI_EVT_RING_STATE_ALLOCATED) {
		ipa_err("bad state %d\n", ctx->state);
		return -ENOTSUPP;
	}

	mutex_lock(&gsi_ctx->mlock);
	reinit_completion(&ctx->compl);

	val = evt_ring_cmd_val(evt_ring_hdl, GSI_EVT_RESET);
	gsi_writel(val, GSI_EE_n_EV_CH_CMD_OFFS(gsi_ctx->ee));
	if (!wait_for_completion_timeout(&ctx->compl, GSI_CMD_TIMEOUT)) {
		ipa_err("evt_id=%lu timed out\n", evt_ring_hdl);
		mutex_unlock(&gsi_ctx->mlock);
		return -ETIMEDOUT;
	}

	if (ctx->state != GSI_EVT_RING_STATE_ALLOCATED) {
		ipa_err("evt_id=%lu unexpected state=%u\n", evt_ring_hdl,
				ctx->state);
		BUG();
	}

	gsi_program_evt_ring_ctx(&ctx->mem, evt_ring_hdl, ctx->int_modt);
	gsi_init_ring(&ctx->ring, &ctx->mem);

	/* restore scratch */
	__gsi_write_evt_ring_scratch(evt_ring_hdl, ctx->scratch);

	gsi_prime_evt_ring(ctx);
	mutex_unlock(&gsi_ctx->mlock);

	return 0;
}

static void gsi_program_chan_ctx(struct gsi_chan_props *props, unsigned int ee,
		uint8_t erindex)
{
	uint32_t val;

	val = (((GSI_CHAN_PROT_GPI << GSI_EE_n_GSI_CH_k_CNTXT_0_CHTYPE_PROTOCOL_SHFT)
			& GSI_EE_n_GSI_CH_k_CNTXT_0_CHTYPE_PROTOCOL_BMSK) |
		((props->dir << GSI_EE_n_GSI_CH_k_CNTXT_0_CHTYPE_DIR_SHFT) &
			 GSI_EE_n_GSI_CH_k_CNTXT_0_CHTYPE_DIR_BMSK) |
		((erindex << GSI_EE_n_GSI_CH_k_CNTXT_0_ERINDEX_SHFT) &
			 GSI_EE_n_GSI_CH_k_CNTXT_0_ERINDEX_BMSK) |
		((GSI_CHAN_RING_ELEMENT_SIZE << GSI_EE_n_GSI_CH_k_CNTXT_0_ELEMENT_SIZE_SHFT)
			 & GSI_EE_n_GSI_CH_k_CNTXT_0_ELEMENT_SIZE_BMSK));
	gsi_writel(val, GSI_EE_n_GSI_CH_k_CNTXT_0_OFFS(props->ch_id, ee));

	val = (props->mem.size & GSI_EE_n_GSI_CH_k_CNTXT_1_R_LENGTH_BMSK) <<
		GSI_EE_n_GSI_CH_k_CNTXT_1_R_LENGTH_SHFT;
	gsi_writel(val, GSI_EE_n_GSI_CH_k_CNTXT_1_OFFS(props->ch_id, ee));

	/*
	 * The context 2 and 3 registers store the low-order and
	 * high-order 32 bits of the address of the channel ring,
	 * respectively.
	 */
	val = props->mem.phys_base & GENMASK(31, 0);
	gsi_writel(val, GSI_EE_n_GSI_CH_k_CNTXT_2_OFFS(props->ch_id, ee));

	val = props->mem.phys_base >> 32;
	gsi_writel(val, GSI_EE_n_GSI_CH_k_CNTXT_3_OFFS(props->ch_id, ee));

	val = (((props->low_weight << GSI_EE_n_GSI_CH_k_QOS_WRR_WEIGHT_SHFT) &
				GSI_EE_n_GSI_CH_k_QOS_WRR_WEIGHT_BMSK) |
		((props->max_prefetch <<
			 GSI_EE_n_GSI_CH_k_QOS_MAX_PREFETCH_SHFT) &
			 GSI_EE_n_GSI_CH_k_QOS_MAX_PREFETCH_BMSK) |
		((props->use_db_eng << GSI_EE_n_GSI_CH_k_QOS_USE_DB_ENG_SHFT) &
			 GSI_EE_n_GSI_CH_k_QOS_USE_DB_ENG_BMSK));
	gsi_writel(val, GSI_EE_n_GSI_CH_k_QOS_OFFS(props->ch_id, ee));
}

static int gsi_validate_channel_props(struct gsi_chan_props *props)
{
	dma_addr_t last;

	if (props->ch_id >= gsi_ctx->max_ch) {
		ipa_err("ch_id %u invalid\n", props->ch_id);
		return -EINVAL;
	}

	if (props->mem.size % 16) {
		ipa_err("bad params mem.size %u not a multiple of re size %u\n",
				props->mem.size, GSI_CHAN_RING_ELEMENT_SIZE);
		return -EINVAL;
	}

	if (props->mem.phys_base % roundup_pow_of_two(props->mem.size)) {
		ipa_err("bad params ring base not aligned 0x%llx align 0x%lx\n",
				props->mem.phys_base,
				roundup_pow_of_two(props->mem.size));
		return -EINVAL;
	}

	last = props->mem.phys_base + props->mem.size -
			GSI_CHAN_RING_ELEMENT_SIZE;

	/* MSB should stay same within the ring */
	if ((props->mem.phys_base & 0xFFFFFFFF00000000ULL) !=
	    (last & 0xFFFFFFFF00000000ULL)) {
		ipa_err("MSB is not fixed on ring base 0x%llx size 0x%x\n",
			props->mem.phys_base,
			props->mem.size);
		return -EINVAL;
	}

	if (!props->mem.base) {
		ipa_err("GPI protocol requires ring base VA\n");
		return -EINVAL;
	}

	if (props->low_weight > GSI_MAX_CH_LOW_WEIGHT) {
		ipa_err("invalid channel low weight %u\n", props->low_weight);
		return -EINVAL;
	}

	if (!props->xfer_cb) {
		ipa_err("xfer callback must be provided\n");
		return -EINVAL;
	}

	if (!props->err_cb) {
		ipa_err("err callback must be provided\n");
		return -EINVAL;
	}

	return 0;
}

long gsi_alloc_channel(struct gsi_chan_props *props)
{
	struct gsi_chan_ctx *ctx;
	uint32_t val;
	int res;
	int ee = gsi_ctx->ee;
	enum gsi_ch_cmd_opcode op = GSI_CH_ALLOCATE;
	uint8_t erindex;
	void **user_data;
	long chan_id;

	if (gsi_validate_channel_props(props)) {
		ipa_err("bad params\n");
		return -EINVAL;
	}

	if (props->evt_ring_hdl != GSI_NO_EVT_ERINDEX) {
		if (props->evt_ring_hdl >= GSI_EVT_RING_MAX) {
			ipa_err("invalid evt ring=%lu\n", props->evt_ring_hdl);
			return -EINVAL;
		}

		if (atomic_read(
			&gsi_ctx->evtr[props->evt_ring_hdl].chan_ref_cnt) &&
			gsi_ctx->evtr[props->evt_ring_hdl].exclusive) {
			ipa_err("evt ring=%lu exclusively in use\n",
				props->evt_ring_hdl);
			return -ENOTSUPP;
		}
	}

	chan_id = (long)props->ch_id;
	ctx = &gsi_ctx->chan[chan_id];
	if (ctx->allocated) {
		ipa_err("chan %ld already allocated\n", chan_id);
		return -ENODEV;
	}

	memset(ctx, 0, sizeof(*ctx));
	user_data = devm_kzalloc(gsi_ctx->dev,
		(props->mem.size / GSI_CHAN_RING_ELEMENT_SIZE) * sizeof(void *),
		GFP_KERNEL);
	if (user_data == NULL) {
		ipa_err("%s:%d gsi context not allocated\n", __func__, __LINE__);
		return -ENOMEM;
	}

	mutex_init(&ctx->mlock);
	init_completion(&ctx->compl);
	atomic_set(&ctx->poll_mode, GSI_CHAN_MODE_CALLBACK);
	ctx->props = *props;

	mutex_lock(&gsi_ctx->mlock);
	gsi_ctx->ch_dbg[chan_id].ch_allocate++;
	val = ((((uint32_t)chan_id << GSI_EE_n_GSI_CH_CMD_CHID_SHFT) &
				GSI_EE_n_GSI_CH_CMD_CHID_BMSK) |
		((op << GSI_EE_n_GSI_CH_CMD_OPCODE_SHFT) &
			 GSI_EE_n_GSI_CH_CMD_OPCODE_BMSK));
	gsi_writel(val, GSI_EE_n_GSI_CH_CMD_OFFS(ee));
	res = wait_for_completion_timeout(&ctx->compl, GSI_CMD_TIMEOUT);
	if (res == 0) {
		ipa_err("chan_id=%ld timed out\n", chan_id);
		mutex_unlock(&gsi_ctx->mlock);
		devm_kfree(gsi_ctx->dev, user_data);
		return -ETIMEDOUT;
	}
	if (ctx->state != GSI_CHAN_STATE_ALLOCATED) {
		ipa_err("chan_id=%ld allocation failed state=%d\n",
				chan_id, ctx->state);
		mutex_unlock(&gsi_ctx->mlock);
		devm_kfree(gsi_ctx->dev, user_data);
		return -ENOMEM;
	}
	mutex_unlock(&gsi_ctx->mlock);

	erindex = props->evt_ring_hdl;
	if (erindex != GSI_NO_EVT_ERINDEX) {
		ctx->evtr = &gsi_ctx->evtr[erindex];
		atomic_inc(&ctx->evtr->chan_ref_cnt);
		if (ctx->evtr->exclusive)
			ctx->evtr->chan = ctx;
	}

	gsi_program_chan_ctx(props, gsi_ctx->ee, erindex);

	spin_lock_init(&ctx->ring.slock);
	gsi_init_ring(&ctx->ring, &props->mem);
	if (!props->max_re_expected)
		ctx->props.max_re_expected = ctx->ring.max_num_elem;
	ctx->user_data = user_data;
	ctx->allocated = true;
	ctx->stats.dp.last_timestamp = jiffies_to_msecs(jiffies);
	atomic_inc(&gsi_ctx->num_chan);

	return chan_id;
}

static void __gsi_write_channel_scratch(unsigned long chan_hdl,
		union __packed gsi_channel_scratch val)
{
	uint32_t reg;

	gsi_writel(val.data.word1, GSI_EE_n_GSI_CH_k_SCRATCH_0_OFFS(chan_hdl,
			gsi_ctx->ee));
	gsi_writel(val.data.word2, GSI_EE_n_GSI_CH_k_SCRATCH_1_OFFS(chan_hdl,
			gsi_ctx->ee));
	gsi_writel(val.data.word3, GSI_EE_n_GSI_CH_k_SCRATCH_2_OFFS(chan_hdl,
			gsi_ctx->ee));
	/* below sequence is not atomic. assumption is sequencer specific fields
	 * will remain unchanged across this sequence
	 */
	reg = gsi_readl(GSI_EE_n_GSI_CH_k_SCRATCH_3_OFFS(chan_hdl,
			gsi_ctx->ee));
	reg &= 0xFFFF;
	reg |= (val.data.word4 & 0xFFFF0000);
	gsi_writel(reg, GSI_EE_n_GSI_CH_k_SCRATCH_3_OFFS(chan_hdl,
			gsi_ctx->ee));
}

int gsi_write_channel_scratch(unsigned long chan_hdl,
		union __packed gsi_channel_scratch val)
{
	struct gsi_chan_ctx *ctx;

	if (chan_hdl >= gsi_ctx->max_ch) {
		ipa_err("bad params chan_hdl=%lu\n", chan_hdl);
		return -EINVAL;
	}

	if (gsi_ctx->chan[chan_hdl].state != GSI_CHAN_STATE_ALLOCATED &&
		gsi_ctx->chan[chan_hdl].state != GSI_CHAN_STATE_STOPPED) {
		ipa_err("bad state %d\n",
				gsi_ctx->chan[chan_hdl].state);
		return -ENOTSUPP;
	}

	ctx = &gsi_ctx->chan[chan_hdl];

	mutex_lock(&ctx->mlock);
	ctx->scratch = val;
	__gsi_write_channel_scratch(chan_hdl, val);
	mutex_unlock(&ctx->mlock);

	return 0;
}

int gsi_start_channel(unsigned long chan_hdl)
{
	enum gsi_ch_cmd_opcode op = GSI_CH_START;
	int res;
	uint32_t val;
	struct gsi_chan_ctx *ctx;

	if (chan_hdl >= gsi_ctx->max_ch) {
		ipa_err("bad params chan_hdl=%lu\n", chan_hdl);
		return -EINVAL;
	}

	ctx = &gsi_ctx->chan[chan_hdl];

	if (ctx->state != GSI_CHAN_STATE_ALLOCATED &&
		ctx->state != GSI_CHAN_STATE_STOP_IN_PROC &&
		ctx->state != GSI_CHAN_STATE_STOPPED) {
		ipa_err("bad state %d\n", ctx->state);
		return -ENOTSUPP;
	}

	mutex_lock(&gsi_ctx->mlock);
	reinit_completion(&ctx->compl);

	gsi_ctx->ch_dbg[chan_hdl].ch_start++;
	val = (((chan_hdl << GSI_EE_n_GSI_CH_CMD_CHID_SHFT) &
			GSI_EE_n_GSI_CH_CMD_CHID_BMSK) |
		((op << GSI_EE_n_GSI_CH_CMD_OPCODE_SHFT) &
		 GSI_EE_n_GSI_CH_CMD_OPCODE_BMSK));
	gsi_writel(val, GSI_EE_n_GSI_CH_CMD_OFFS(gsi_ctx->ee));
	res = wait_for_completion_timeout(&ctx->compl, GSI_CMD_TIMEOUT);
	if (res == 0) {
		ipa_err("chan_hdl=%lu timed out\n", chan_hdl);
		mutex_unlock(&gsi_ctx->mlock);
		return -ETIMEDOUT;
	}
	if (ctx->state != GSI_CHAN_STATE_STARTED) {
		ipa_err("chan=%lu unexpected state=%u\n", chan_hdl, ctx->state);
		BUG();
	}

	mutex_unlock(&gsi_ctx->mlock);

	return 0;
}

int gsi_stop_channel(unsigned long chan_hdl)
{
	enum gsi_ch_cmd_opcode op = GSI_CH_STOP;
	int res;
	uint32_t val;
	struct gsi_chan_ctx *ctx;

	if (chan_hdl >= gsi_ctx->max_ch) {
		ipa_err("bad params chan_hdl=%lu\n", chan_hdl);
		return -EINVAL;
	}

	ctx = &gsi_ctx->chan[chan_hdl];

	if (ctx->state == GSI_CHAN_STATE_STOPPED) {
		ipa_debug("chan_hdl=%lu already stopped\n", chan_hdl);
		return 0;
	}

	if (ctx->state != GSI_CHAN_STATE_STARTED &&
		ctx->state != GSI_CHAN_STATE_STOP_IN_PROC &&
		ctx->state != GSI_CHAN_STATE_ERROR) {
		ipa_err("bad state %d\n", ctx->state);
		return -ENOTSUPP;
	}

	mutex_lock(&gsi_ctx->mlock);
	reinit_completion(&ctx->compl);

	gsi_ctx->ch_dbg[chan_hdl].ch_stop++;
	val = (((chan_hdl << GSI_EE_n_GSI_CH_CMD_CHID_SHFT) &
			GSI_EE_n_GSI_CH_CMD_CHID_BMSK) |
		((op << GSI_EE_n_GSI_CH_CMD_OPCODE_SHFT) &
		 GSI_EE_n_GSI_CH_CMD_OPCODE_BMSK));
	gsi_writel(val, GSI_EE_n_GSI_CH_CMD_OFFS(gsi_ctx->ee));
	res = wait_for_completion_timeout(&ctx->compl,
			msecs_to_jiffies(GSI_STOP_CMD_TIMEOUT_MS));
	if (res == 0) {
		/*
		 * check channel state here in case the channel is stopped but
		 * the interrupt was not handled yet.
		 */
		val = gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_0_OFFS(chan_hdl,
			gsi_ctx->ee));
		ctx->state = (val &
			GSI_EE_n_GSI_CH_k_CNTXT_0_CHSTATE_BMSK) >>
			GSI_EE_n_GSI_CH_k_CNTXT_0_CHSTATE_SHFT;
		if (ctx->state == GSI_CHAN_STATE_STOPPED) {
			res = 0;
			goto free_lock;
		}
		ipa_debug("chan_hdl=%lu timed out\n", chan_hdl);
		res = -ETIMEDOUT;
		goto free_lock;
	}

	if (ctx->state != GSI_CHAN_STATE_STOPPED &&
		ctx->state != GSI_CHAN_STATE_STOP_IN_PROC) {
		ipa_err("chan=%lu unexpected state=%u\n", chan_hdl, ctx->state);
		res = -EBUSY;
		goto free_lock;
	}

	if (ctx->state == GSI_CHAN_STATE_STOP_IN_PROC) {
		ipa_err("chan=%lu busy try again\n", chan_hdl);
		res = -EAGAIN;
		goto free_lock;
	}

	res = 0;

free_lock:
	mutex_unlock(&gsi_ctx->mlock);
	return res;
}

int gsi_reset_channel(unsigned long chan_hdl)
{
	enum gsi_ch_cmd_opcode op = GSI_CH_RESET;
	int res;
	uint32_t val;
	struct gsi_chan_ctx *ctx;
	bool reset_done = false;

	if (chan_hdl >= gsi_ctx->max_ch) {
		ipa_err("bad params chan_hdl=%lu\n", chan_hdl);
		return -EINVAL;
	}

	ctx = &gsi_ctx->chan[chan_hdl];

	if (ctx->state != GSI_CHAN_STATE_STOPPED) {
		ipa_err("bad state %d\n", ctx->state);
		return -ENOTSUPP;
	}

	mutex_lock(&gsi_ctx->mlock);

reset:
	reinit_completion(&ctx->compl);
	gsi_ctx->ch_dbg[chan_hdl].ch_reset++;
	val = (((chan_hdl << GSI_EE_n_GSI_CH_CMD_CHID_SHFT) &
			GSI_EE_n_GSI_CH_CMD_CHID_BMSK) |
		((op << GSI_EE_n_GSI_CH_CMD_OPCODE_SHFT) &
		 GSI_EE_n_GSI_CH_CMD_OPCODE_BMSK));
	gsi_writel(val, GSI_EE_n_GSI_CH_CMD_OFFS(gsi_ctx->ee));
	res = wait_for_completion_timeout(&ctx->compl, GSI_CMD_TIMEOUT);
	if (res == 0) {
		ipa_err("chan_hdl=%lu timed out\n", chan_hdl);
		mutex_unlock(&gsi_ctx->mlock);
		return -ETIMEDOUT;
	}

	if (ctx->state != GSI_CHAN_STATE_ALLOCATED) {
		ipa_err("chan_hdl=%lu unexpected state=%u\n", chan_hdl,
				ctx->state);
		BUG();
	}

	/* workaround: reset GSI producers again */
	if (ctx->props.dir == GSI_CHAN_DIR_FROM_GSI && !reset_done) {
		usleep_range(GSI_RESET_WA_MIN_SLEEP, GSI_RESET_WA_MAX_SLEEP);
		reset_done = true;
		goto reset;
	}

	gsi_program_chan_ctx(&ctx->props, gsi_ctx->ee,
			ctx->evtr ? ctx->evtr->id : GSI_NO_EVT_ERINDEX);
	gsi_init_ring(&ctx->ring, &ctx->props.mem);

	/* restore scratch */
	__gsi_write_channel_scratch(chan_hdl, ctx->scratch);

	mutex_unlock(&gsi_ctx->mlock);

	return 0;
}

int gsi_dealloc_channel(unsigned long chan_hdl)
{
	enum gsi_ch_cmd_opcode op = GSI_CH_DE_ALLOC;
	int res;
	uint32_t val;
	struct gsi_chan_ctx *ctx;

	if (chan_hdl >= gsi_ctx->max_ch) {
		ipa_err("bad params chan_hdl=%lu\n", chan_hdl);
		return -EINVAL;
	}

	ctx = &gsi_ctx->chan[chan_hdl];

	if (ctx->state != GSI_CHAN_STATE_ALLOCATED) {
		ipa_err("bad state %d\n", ctx->state);
		return -ENOTSUPP;
	}

	mutex_lock(&gsi_ctx->mlock);
	reinit_completion(&ctx->compl);

	gsi_ctx->ch_dbg[chan_hdl].ch_de_alloc++;
	val = (((chan_hdl << GSI_EE_n_GSI_CH_CMD_CHID_SHFT) &
			GSI_EE_n_GSI_CH_CMD_CHID_BMSK) |
		((op << GSI_EE_n_GSI_CH_CMD_OPCODE_SHFT) &
		 GSI_EE_n_GSI_CH_CMD_OPCODE_BMSK));
	gsi_writel(val, GSI_EE_n_GSI_CH_CMD_OFFS(gsi_ctx->ee));
	res = wait_for_completion_timeout(&ctx->compl, GSI_CMD_TIMEOUT);
	if (res == 0) {
		ipa_err("chan_hdl=%lu timed out\n", chan_hdl);
		mutex_unlock(&gsi_ctx->mlock);
		return -ETIMEDOUT;
	}
	if (ctx->state != GSI_CHAN_STATE_NOT_ALLOCATED) {
		ipa_err("chan_hdl=%lu unexpected state=%u\n", chan_hdl,
				ctx->state);
		BUG();
	}

	mutex_unlock(&gsi_ctx->mlock);

	devm_kfree(gsi_ctx->dev, ctx->user_data);
	ctx->allocated = false;
	if (ctx->evtr)
		atomic_dec(&ctx->evtr->chan_ref_cnt);
	atomic_dec(&gsi_ctx->num_chan);

	return 0;
}

void gsi_update_ch_dp_stats(struct gsi_chan_ctx *ctx, uint16_t used)
{
	unsigned long now = jiffies_to_msecs(jiffies);
	unsigned long elapsed;

	if (used == 0) {
		elapsed = now - ctx->stats.dp.last_timestamp;
		if (ctx->stats.dp.empty_time < elapsed)
			ctx->stats.dp.empty_time = elapsed;
	}

	if (used <= ctx->props.max_re_expected / 3)
		++ctx->stats.dp.ch_below_lo;
	else if (used <= 2 * ctx->props.max_re_expected / 3)
		++ctx->stats.dp.ch_below_hi;
	else
		++ctx->stats.dp.ch_above_hi;
	ctx->stats.dp.last_timestamp = now;
}

static uint16_t __gsi_query_channel_free_re(struct gsi_chan_ctx *ctx)
{
	uint16_t start;
	uint16_t end;
	uint64_t rp;
	int ee = gsi_ctx->ee;
	uint16_t used;

	if (!ctx->evtr) {
		rp = gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_4_OFFS(ctx->props.ch_id, ee));
		rp |= ctx->ring.rp & 0xFFFFFFFF00000000;

		ctx->ring.rp = rp;
	} else {
		rp = ctx->ring.rp_local;
	}

	start = gsi_find_idx_from_addr(&ctx->ring, rp);
	end = gsi_find_idx_from_addr(&ctx->ring, ctx->ring.wp_local);

	if (end >= start)
		used = end - start;
	else
		used = ctx->ring.max_num_elem + 1 - (start - end);

	return ctx->ring.max_num_elem - used;
}

bool gsi_is_channel_empty(unsigned long chan_hdl)
{
	struct gsi_chan_ctx *ctx;
	spinlock_t *slock;
	unsigned long flags;
	uint64_t rp;
	uint64_t wp;
	int ee = gsi_ctx->ee;
	bool is_empty;

	ctx = &gsi_ctx->chan[chan_hdl];
	if (ctx->evtr)
		slock = &ctx->evtr->ring.slock;
	else
		slock = &ctx->ring.slock;

	spin_lock_irqsave(slock, flags);

	rp = gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_4_OFFS(ctx->props.ch_id, ee));
	rp |= ctx->ring.rp & 0xFFFFFFFF00000000;
	ctx->ring.rp = rp;

	wp = gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_6_OFFS(ctx->props.ch_id, ee));
	wp |= ctx->ring.wp & 0xFFFFFFFF00000000;
	ctx->ring.wp = wp;

	if (ctx->props.dir == GSI_CHAN_DIR_FROM_GSI)
		is_empty = (ctx->ring.rp_local == rp) ? true : false;
	else
		is_empty = (wp == rp) ? true : false;

	spin_unlock_irqrestore(slock, flags);

	ipa_debug("ch=%lu RP=0x%llx WP=0x%llx RP_LOCAL=0x%llx\n",
			chan_hdl, rp, wp, ctx->ring.rp_local);

	return is_empty;
}

int gsi_queue_xfer(unsigned long chan_hdl, uint16_t num_xfers,
		struct gsi_xfer_elem *xfer, bool ring_db)
{
	struct gsi_chan_ctx *ctx;
	uint16_t free;
	struct gsi_tre tre;
	struct gsi_tre *tre_ptr;
	uint16_t idx;
	uint64_t wp_rollback;
	int i;
	spinlock_t *slock;
	unsigned long flags;

	if (chan_hdl >= gsi_ctx->max_ch || !num_xfers || !xfer) {
		ipa_err("bad params chan_hdl=%lu num_xfers=%u xfer=%p\n",
				chan_hdl, num_xfers, xfer);
		return -EINVAL;
	}

	ctx = &gsi_ctx->chan[chan_hdl];
	if (ctx->evtr)
		slock = &ctx->evtr->ring.slock;
	else
		slock = &ctx->ring.slock;

	spin_lock_irqsave(slock, flags);
	free = __gsi_query_channel_free_re(ctx);

	if (num_xfers > free) {
		ipa_err("chan_hdl=%lu num_xfers=%u free=%u\n",
				chan_hdl, num_xfers, free);
		spin_unlock_irqrestore(slock, flags);
		return -ENOSPC;
	}

	wp_rollback = ctx->ring.wp_local;
	for (i = 0; i < num_xfers; i++) {
		memset(&tre, 0, sizeof(tre));
		tre.buffer_ptr = xfer[i].addr;
		tre.buf_len = xfer[i].len;
		if (xfer[i].type == GSI_XFER_ELEM_DATA) {
			tre.re_type = GSI_RE_XFER;
		} else if (xfer[i].type == GSI_XFER_ELEM_IMME_CMD) {
			tre.re_type = GSI_RE_IMMD_CMD;
		} else if (xfer[i].type == GSI_XFER_ELEM_NOP) {
			tre.re_type = GSI_RE_NOP;
		} else {
			ipa_err("chan_hdl=%lu bad RE type=%u\n", chan_hdl,
				xfer[i].type);
			break;
		}
		tre.bei = (xfer[i].flags & GSI_XFER_FLAG_BEI) ? 1 : 0;
		tre.ieot = (xfer[i].flags & GSI_XFER_FLAG_EOT) ? 1 : 0;
		tre.ieob = (xfer[i].flags & GSI_XFER_FLAG_EOB) ? 1 : 0;
		tre.chain = (xfer[i].flags & GSI_XFER_FLAG_CHAIN) ? 1 : 0;

		idx = gsi_find_idx_from_addr(&ctx->ring, ctx->ring.wp_local);
		tre_ptr = ctx->ring.mem.base + idx * ctx->ring.elem_sz;

		/* write the TRE to ring */
		*tre_ptr = tre;
		ctx->user_data[idx] = xfer[i].xfer_user_data;
		gsi_incr_ring_wp(&ctx->ring);
	}

	if (i != num_xfers) {
		/* reject all the xfers */
		ctx->ring.wp_local = wp_rollback;
		spin_unlock_irqrestore(slock, flags);
		return -EINVAL;
	}

	ctx->stats.queued += num_xfers;

	/* ensure TRE is set before ringing doorbell */
	wmb();

	if (ring_db)
		gsi_ring_chan_doorbell(ctx);

	spin_unlock_irqrestore(slock, flags);

	return 0;
}

int gsi_start_xfer(unsigned long chan_hdl)
{
	struct gsi_chan_ctx *ctx;

	if (chan_hdl >= gsi_ctx->max_ch) {
		ipa_err("bad params chan_hdl=%lu\n", chan_hdl);
		return -EINVAL;
	}

	ctx = &gsi_ctx->chan[chan_hdl];
	if (ctx->state != GSI_CHAN_STATE_STARTED) {
		ipa_err("bad state %d\n", ctx->state);
		return -ENOTSUPP;
	}

	if (ctx->ring.wp == ctx->ring.wp_local)
		return 0;

	gsi_ring_chan_doorbell(ctx);

	return 0;
}

int gsi_poll_channel(unsigned long chan_hdl,
		struct gsi_chan_xfer_notify *notify)
{
	struct gsi_chan_ctx *ctx;
	uint64_t rp;
	int ee = gsi_ctx->ee;
	unsigned long flags;

	if (chan_hdl >= gsi_ctx->max_ch || !notify) {
		ipa_err("bad params chan_hdl=%lu notify=%p\n", chan_hdl, notify);
		return -EINVAL;
	}

	ctx = &gsi_ctx->chan[chan_hdl];
	if (!ctx->evtr) {
		ipa_err("no event ring associated chan_hdl=%lu\n", chan_hdl);
		return -ENOTSUPP;
	}

	spin_lock_irqsave(&ctx->evtr->ring.slock, flags);
	if (ctx->evtr->ring.rp == ctx->evtr->ring.rp_local) {
		/* update rp to see of we have anything new to process */
		rp = gsi_readl(GSI_EE_n_EV_CH_k_CNTXT_4_OFFS(ctx->evtr->id, ee));
		rp |= ctx->ring.rp & 0xFFFFFFFF00000000;

		ctx->evtr->ring.rp = rp;
	}

	if (ctx->evtr->ring.rp == ctx->evtr->ring.rp_local) {
		spin_unlock_irqrestore(&ctx->evtr->ring.slock, flags);
		ctx->stats.poll_empty++;
		return -ENOENT;
	}

	gsi_process_evt_re(ctx->evtr, notify, false);
	spin_unlock_irqrestore(&ctx->evtr->ring.slock, flags);
	ctx->stats.poll_ok++;

	return 0;
}

int gsi_config_channel_mode(unsigned long chan_hdl, enum gsi_chan_mode mode)
{
	struct gsi_chan_ctx *ctx;
	enum gsi_chan_mode curr;
	unsigned long flags;

	if (chan_hdl >= gsi_ctx->max_ch) {
		ipa_err("bad params chan_hdl=%lu mode=%u\n", chan_hdl, mode);
		return -EINVAL;
	}

	ctx = &gsi_ctx->chan[chan_hdl];
	if (!ctx->evtr || !ctx->evtr->exclusive) {
		ipa_err("cannot configure mode on chan_hdl=%lu\n",
				chan_hdl);
		return -ENOTSUPP;
	}

	if (atomic_read(&ctx->poll_mode))
		curr = GSI_CHAN_MODE_POLL;
	else
		curr = GSI_CHAN_MODE_CALLBACK;

	if (mode == curr) {
		ipa_err("already in requested mode %u chan_hdl=%lu\n",
				curr, chan_hdl);
		return -ENOTSUPP;
	}

	spin_lock_irqsave(&gsi_ctx->slock, flags);
	if (curr == GSI_CHAN_MODE_CALLBACK &&
			mode == GSI_CHAN_MODE_POLL) {
		gsi_irq_control_event(gsi_ctx->ee, ctx->evtr->id, false);
		ctx->stats.callback_to_poll++;
	}

	if (curr == GSI_CHAN_MODE_POLL &&
			mode == GSI_CHAN_MODE_CALLBACK) {
		gsi_irq_control_event(gsi_ctx->ee, ctx->evtr->id, true);
		ctx->stats.poll_to_callback++;
	}
	atomic_set(&ctx->poll_mode, mode);
	spin_unlock_irqrestore(&gsi_ctx->slock, flags);

	return 0;
}

int gsi_get_channel_cfg(unsigned long chan_hdl, struct gsi_chan_props *props,
		union gsi_channel_scratch *scr)
{
	struct gsi_chan_ctx *ctx = &gsi_ctx->chan[chan_hdl];

	if (ctx->state == GSI_CHAN_STATE_NOT_ALLOCATED) {
		ipa_err("bad state %d\n", ctx->state);
		return -ENOTSUPP;
	}

	mutex_lock(&ctx->mlock);
	*props = ctx->props;
	*scr = ctx->scratch;
	mutex_unlock(&ctx->mlock);

	return 0;
}

int gsi_set_channel_cfg(unsigned long chan_hdl, struct gsi_chan_props *props,
		union gsi_channel_scratch *scr)
{
	struct gsi_chan_ctx *ctx;

	if (gsi_validate_channel_props(props)) {
		ipa_err("bad params props=%p\n", props);
		return -EINVAL;
	}

	if (chan_hdl >= gsi_ctx->max_ch) {
		ipa_err("bad params chan_hdl=%lu\n", chan_hdl);
		return -EINVAL;
	}

	ctx = &gsi_ctx->chan[chan_hdl];

	if (ctx->state != GSI_CHAN_STATE_ALLOCATED) {
		ipa_err("bad state %d\n", ctx->state);
		return -ENOTSUPP;
	}

	if (ctx->props.ch_id != props->ch_id ||
		ctx->props.evt_ring_hdl != props->evt_ring_hdl) {
		ipa_err("changing immutable fields not supported\n");
		return -ENOTSUPP;
	}

	mutex_lock(&ctx->mlock);
	ctx->props = *props;
	if (scr)
		ctx->scratch = *scr;
	gsi_program_chan_ctx(&ctx->props, gsi_ctx->ee,
			ctx->evtr ? ctx->evtr->id : GSI_NO_EVT_ERINDEX);
	gsi_init_ring(&ctx->ring, &ctx->props.mem);

	/* restore scratch */
	__gsi_write_channel_scratch(chan_hdl, ctx->scratch);
	mutex_unlock(&ctx->mlock);

	return 0;
}

static void gsi_configure_ieps(void __iomem *gsi_base)
{
	writel(1, gsi_base + GSI_GSI_IRAM_PTR_CH_CMD_OFFS);
	writel(2, gsi_base + GSI_GSI_IRAM_PTR_CH_DB_OFFS);
	writel(3, gsi_base + GSI_GSI_IRAM_PTR_CH_DIS_COMP_OFFS);
	writel(4, gsi_base + GSI_GSI_IRAM_PTR_CH_EMPTY_OFFS);
	writel(5, gsi_base + GSI_GSI_IRAM_PTR_EE_GENERIC_CMD_OFFS);
	writel(6, gsi_base + GSI_GSI_IRAM_PTR_EVENT_GEN_COMP_OFFS);
	writel(7, gsi_base + GSI_GSI_IRAM_PTR_INT_MOD_STOPED_OFFS);
	writel(8, gsi_base + GSI_GSI_IRAM_PTR_PERIPH_IF_TLV_IN_0_OFFS);
	writel(9, gsi_base + GSI_GSI_IRAM_PTR_PERIPH_IF_TLV_IN_2_OFFS);
	writel(10, gsi_base + GSI_GSI_IRAM_PTR_PERIPH_IF_TLV_IN_1_OFFS);
	writel(11, gsi_base + GSI_GSI_IRAM_PTR_NEW_RE_OFFS);
	writel(12, gsi_base + GSI_GSI_IRAM_PTR_READ_ENG_COMP_OFFS);
	writel(13, gsi_base + GSI_GSI_IRAM_PTR_TIMER_EXPIRED_OFFS);
}

static void gsi_configure_bck_prs_matrix(void __iomem *gsi_base)
{
	/*
	 * For now, these are default values. In the future, GSI FW image will
	 * produce optimized back-pressure values based on the FW image.
	 */
	writel(0xfffffffe, gsi_base + GSI_IC_DISABLE_CHNL_BCK_PRS_LSB_OFFS);
	writel(0xffffffff, gsi_base + GSI_IC_DISABLE_CHNL_BCK_PRS_MSB_OFFS);
	writel(0xffffffbf, gsi_base + GSI_IC_GEN_EVNT_BCK_PRS_LSB_OFFS);
	writel(0xffffffff, gsi_base + GSI_IC_GEN_EVNT_BCK_PRS_MSB_OFFS);
	writel(0xffffefff, gsi_base + GSI_IC_GEN_INT_BCK_PRS_LSB_OFFS);
	writel(0xffffffff, gsi_base + GSI_IC_GEN_INT_BCK_PRS_MSB_OFFS);
	writel(0xffffefff, gsi_base + GSI_IC_STOP_INT_MOD_BCK_PRS_LSB_OFFS);
	writel(0xffffffff, gsi_base + GSI_IC_STOP_INT_MOD_BCK_PRS_MSB_OFFS);
	writel(0x00000000, gsi_base + GSI_IC_PROCESS_DESC_BCK_PRS_LSB_OFFS);
	writel(0x00000000, gsi_base + GSI_IC_PROCESS_DESC_BCK_PRS_MSB_OFFS);
	writel(0xf9ffffff, gsi_base + GSI_IC_TLV_STOP_BCK_PRS_LSB_OFFS);
	writel(0xffffffff, gsi_base + GSI_IC_TLV_STOP_BCK_PRS_MSB_OFFS);
	writel(0xf9ffffff, gsi_base + GSI_IC_TLV_RESET_BCK_PRS_LSB_OFFS);
	writel(0xffffffff, gsi_base + GSI_IC_TLV_RESET_BCK_PRS_MSB_OFFS);
	writel(0xffffffff, gsi_base + GSI_IC_RGSTR_TIMER_BCK_PRS_LSB_OFFS);
	writel(0xfffffffe, gsi_base + GSI_IC_RGSTR_TIMER_BCK_PRS_MSB_OFFS);
	writel(0xffffffff, gsi_base + GSI_IC_READ_BCK_PRS_LSB_OFFS);
	writel(0xffffefff, gsi_base + GSI_IC_READ_BCK_PRS_MSB_OFFS);
	writel(0xffffffff, gsi_base + GSI_IC_WRITE_BCK_PRS_LSB_OFFS);
	writel(0xffffdfff, gsi_base + GSI_IC_WRITE_BCK_PRS_MSB_OFFS);
	writel(0xffffffff, gsi_base + GSI_IC_UCONTROLLER_GPR_BCK_PRS_LSB_OFFS);
	writel(0xff03ffff, gsi_base + GSI_IC_UCONTROLLER_GPR_BCK_PRS_MSB_OFFS);
}

int gsi_configure_regs(phys_addr_t gsi_base_addr, u32 gsi_size,
		phys_addr_t per_base_addr)
{
	void __iomem *gsi_base;

	gsi_base = ioremap_nocache(gsi_base_addr, gsi_size);
	if (!gsi_base) {
		ipa_err("ioremap failed for 0x%pa\n", &gsi_base_addr);
		return -ENOMEM;
	}
	writel(0, gsi_base + GSI_GSI_PERIPH_BASE_ADDR_MSB_OFFS);
	writel(per_base_addr, gsi_base + GSI_GSI_PERIPH_BASE_ADDR_LSB_OFFS);
	gsi_configure_bck_prs_matrix(gsi_base);
	gsi_configure_ieps(gsi_base);
	iounmap(gsi_base);

	return 0;
}

int gsi_enable_fw(phys_addr_t gsi_base_addr, u32 gsi_size)
{
	void __iomem *gsi_base;
	uint32_t value;

	gsi_base = ioremap_nocache(gsi_base_addr, gsi_size);
	if (!gsi_base) {
		ipa_err("ioremap failed for 0x%pa\n", &gsi_base_addr);
		return -ENOMEM;
	}

	/* Enable the MCS and set to x2 clocks */
	value = ((1 << GSI_GSI_MCS_CFG_MCS_ENABLE_SHFT) &
			GSI_GSI_MCS_CFG_MCS_ENABLE_BMSK);
	writel(value, gsi_base + GSI_GSI_MCS_CFG_OFFS);

	value = (((1 << GSI_GSI_CFG_GSI_ENABLE_SHFT) &
			GSI_GSI_CFG_GSI_ENABLE_BMSK) |
		((0 << GSI_GSI_CFG_MCS_ENABLE_SHFT) &
			GSI_GSI_CFG_MCS_ENABLE_BMSK) |
		((1 << GSI_GSI_CFG_DOUBLE_MCS_CLK_FREQ_SHFT) &
			GSI_GSI_CFG_DOUBLE_MCS_CLK_FREQ_BMSK) |
		((0 << GSI_GSI_CFG_UC_IS_MCS_SHFT) &
			GSI_GSI_CFG_UC_IS_MCS_BMSK) |
		((0 << GSI_GSI_CFG_GSI_PWR_CLPS_SHFT) &
			GSI_GSI_CFG_GSI_PWR_CLPS_BMSK) |
		((0 << GSI_GSI_CFG_BP_MTRIX_DISABLE_SHFT) &
			GSI_GSI_CFG_BP_MTRIX_DISABLE_BMSK));
	writel(value, gsi_base + GSI_GSI_CFG_OFFS);

	iounmap(gsi_base);

	return 0;

}

void gsi_get_inst_ram_offset_and_size(unsigned long *base_offset,
		unsigned long *size)
{
	if (base_offset)
		*base_offset = GSI_GSI_INST_RAM_n_OFFS(0);
	if (size)
		*size = GSI_GSI_INST_RAM_n_WORD_SZ *
			(GSI_GSI_INST_RAM_n_MAXn + 1);
}

int gsi_halt_channel_ee(unsigned int chan_idx, unsigned int ee, int *code)
{
	enum gsi_generic_ee_cmd_opcode op = GSI_GEN_EE_CMD_HALT_CHANNEL;
	uint32_t val;
	int res;

	if (chan_idx >= gsi_ctx->max_ch || !code) {
		ipa_err("bad params chan_idx=%d\n", chan_idx);
		return -EINVAL;
	}

	mutex_lock(&gsi_ctx->mlock);
	reinit_completion(&gsi_ctx->gen_ee_cmd_compl);

	/* invalidate the response */
	gsi_ctx->scratch.word0.val =
		gsi_readl(GSI_EE_n_CNTXT_SCRATCH_0_OFFS(gsi_ctx->ee));
	gsi_ctx->scratch.word0.s.generic_ee_cmd_return_code = 0;
	gsi_writel(gsi_ctx->scratch.word0.val,
			GSI_EE_n_CNTXT_SCRATCH_0_OFFS(gsi_ctx->ee));

	gsi_ctx->gen_ee_cmd_dbg.halt_channel++;
	val = (((op << GSI_EE_n_GSI_EE_GENERIC_CMD_OPCODE_SHFT) &
		GSI_EE_n_GSI_EE_GENERIC_CMD_OPCODE_BMSK) |
		((chan_idx << GSI_EE_n_GSI_EE_GENERIC_CMD_VIRT_CHAN_IDX_SHFT) &
			GSI_EE_n_GSI_EE_GENERIC_CMD_VIRT_CHAN_IDX_BMSK) |
		((ee << GSI_EE_n_GSI_EE_GENERIC_CMD_EE_SHFT) &
			GSI_EE_n_GSI_EE_GENERIC_CMD_EE_BMSK));
	gsi_writel(val, GSI_EE_n_GSI_EE_GENERIC_CMD_OFFS(gsi_ctx->ee));

	res = wait_for_completion_timeout(&gsi_ctx->gen_ee_cmd_compl,
		msecs_to_jiffies(GSI_CMD_TIMEOUT));
	if (res == 0) {
		ipa_err("chan_idx=%u ee=%u timed out\n", chan_idx, ee);
		res = -ETIMEDOUT;
		goto free_lock;
	}

	gsi_ctx->scratch.word0.val =
		gsi_readl(GSI_EE_n_CNTXT_SCRATCH_0_OFFS(gsi_ctx->ee));
	if (gsi_ctx->scratch.word0.s.generic_ee_cmd_return_code == 0) {
		ipa_err("No response received\n");
		res = -EIO;
		goto free_lock;
	}

	res = 0;
	*code = gsi_ctx->scratch.word0.s.generic_ee_cmd_return_code;
free_lock:
	mutex_unlock(&gsi_ctx->mlock);

	return res;
}

/* Initialize GSI driver */
struct gsi_ctx *msm_gsi_init(struct platform_device *pdev, void *logbuf)
{
	struct device *dev = &pdev->dev;

	pr_err("gsi_probe\n");
	gsi_ctx = devm_kzalloc(dev, sizeof(*gsi_ctx), GFP_KERNEL);
	if (!gsi_ctx) {
		dev_err(dev, "failed to allocated gsi context\n");
		return ERR_PTR(-ENOMEM);
	}

	gsi_ctx->ipc_logbuf = logbuf;
	if (!logbuf)
		ipa_err("no IPC log, continue...\n");

	gsi_ctx->dev = dev;
	init_completion(&gsi_ctx->gen_ee_cmd_compl);
	gsi_debugfs_init();
	pr_err("gsi_probe complete\n");

	return gsi_ctx;
}

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Generic Software Interface (GSI)");
