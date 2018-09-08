// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2015-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#define pr_fmt(fmt)    "gsi %s:%d " fmt, __func__, __LINE__

#include <linux/of.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/delay.h>

#include "field_mask.h"
#include "ipa_dma.h"
#include "ipa_i.h"
#include "gsi.h"
#include "gsi_reg.h"

#define GSI_CHAN_MAX		31
#define GSI_EVT_RING_MAX	23

#define GSI_CMD_TIMEOUT		msecs_to_jiffies(5 * MSEC_PER_SEC)

#define GSI_MHI_ER_START	10	/* First reserved event number */
#define GSI_MHI_ER_END		16	/* Last reserved event number */

#define GSI_RESET_WA_MIN_SLEEP	1000	/* microseconds */
#define GSI_RESET_WA_MAX_SLEEP	2000	/* microseconds */

#define GSI_MAX_PREFETCH	0	/* 0 means 1 segment; 1 means 2 */

#define GSI_ISR_MAX_ITER	50

/* Hardware values from the error log register code field */
enum gsi_err_code {
	GSI_INVALID_TRE_ERR			= 0x1,
	GSI_OUT_OF_BUFFERS_ERR			= 0x2,
	GSI_OUT_OF_RESOURCES_ERR		= 0x3,
	GSI_UNSUPPORTED_INTER_EE_OP_ERR		= 0x4,
	GSI_EVT_RING_EMPTY_ERR			= 0x5,
	GSI_NON_ALLOCATED_EVT_ACCESS_ERR	= 0x6,
	GSI_HWO_1_ERR				= 0x8,
};

/* Hardware values used when programming an event ring context */
enum gsi_evt_chtype {
	GSI_EVT_CHTYPE_MHI_EV	= 0x0,
	GSI_EVT_CHTYPE_XHCI_EV	= 0x1,
	GSI_EVT_CHTYPE_GPI_EV	= 0x2,
	GSI_EVT_CHTYPE_XDCI_EV	= 0x3,
};

/* Hardware values used when programming a channel context */
enum gsi_chan_prot {
	GSI_CHAN_PROT_MHI	= 0x0,
	GSI_CHAN_PROT_XHCI	= 0x1,
	GSI_CHAN_PROT_GPI	= 0x2,
	GSI_CHAN_PROT_XDCI	= 0x3,
};

/* Hardware values returned in a transfer completion event structure */
enum gsi_chan_evt {
	GSI_CHAN_EVT_INVALID	= 0x0,
	GSI_CHAN_EVT_SUCCESS	= 0x1,
	GSI_CHAN_EVT_EOT	= 0x2,
	GSI_CHAN_EVT_OVERFLOW	= 0x3,
	GSI_CHAN_EVT_EOB	= 0x4,
	GSI_CHAN_EVT_OOB	= 0x5,
	GSI_CHAN_EVT_DB_MODE	= 0x6,
	GSI_CHAN_EVT_UNDEFINED	= 0x10,
	GSI_CHAN_EVT_RE_ERROR	= 0x11,
};

/* Hardware values signifying the state of an event ring */
enum gsi_evt_ring_state {
	GSI_EVT_RING_STATE_NOT_ALLOCATED	= 0x0,
	GSI_EVT_RING_STATE_ALLOCATED		= 0x1,
	GSI_EVT_RING_STATE_ERROR		= 0xf,
};

/* Hardware values signifying the state of a channel */
enum gsi_chan_state {
	GSI_CHAN_STATE_NOT_ALLOCATED	= 0x0,
	GSI_CHAN_STATE_ALLOCATED	= 0x1,
	GSI_CHAN_STATE_STARTED		= 0x2,
	GSI_CHAN_STATE_STOPPED		= 0x3,
	GSI_CHAN_STATE_STOP_IN_PROC	= 0x4,
	GSI_CHAN_STATE_ERROR		= 0xf,
};

struct gsi_ring_ctx {
	spinlock_t slock;		/* protects wp, rp updates */
	struct ipa_dma_mem mem;
	u64 wp;
	u64 rp;
	u64 wp_local;
	u64 rp_local;
	u64 end;			/* physical addr past last element */
};

struct gsi_chan_ctx {
	struct gsi_chan_props props;
	enum gsi_chan_state state;
	struct gsi_ring_ctx ring;
	void **user_data;
	struct gsi_evt_ctx *evtr;
	struct mutex mlock;		/* protects chan_scratch updates */
	struct completion compl;
	bool allocated;
	atomic_t poll_mode;
	u32 tlv_size;			/* # slots in TLV */
};

struct gsi_evt_ctx {
	struct ipa_dma_mem mem;
	u16 int_modt;
	enum gsi_evt_ring_state state;
	u8 id;
	struct gsi_ring_ctx ring;
	struct completion compl;
	struct gsi_chan_ctx *chan;
	atomic_t chan_ref_cnt;
};

struct ch_debug_stats {
	unsigned long ch_allocate;
	unsigned long ch_start;
	unsigned long ch_stop;
	unsigned long ch_reset;
	unsigned long ch_de_alloc;
	unsigned long ch_db_stop;
	unsigned long cmd_completed;
};

struct gsi {
	void __iomem *base;
	struct device *dev;
	u32 phys;
	unsigned int irq;
	bool irq_wake_enabled;
	spinlock_t slock;	/* protects global register updates */
	struct mutex mlock;	/* protects 1-at-a-time commands, evt_bmap */
	atomic_t num_chan;
	atomic_t num_evt_ring;
	struct gsi_chan_ctx chan[GSI_CHAN_MAX];
	struct ch_debug_stats ch_dbg[GSI_CHAN_MAX];
	struct gsi_evt_ctx evtr[GSI_EVT_RING_MAX];
	unsigned long evt_bmap;
	u32 max_ch;
	u32 max_ev;
};

/* Hardware values representing a transfer element type */
enum gsi_re_type {
	GSI_RE_XFER	= 0x2,
	GSI_RE_IMMD_CMD	= 0x3,
	GSI_RE_NOP	= 0x4,
};

struct gsi_tre {
	u64 buffer_ptr;
	u16 buf_len;
	u16 rsvd1;
	u8  chain	: 1,
	    rsvd4	: 7;
	u8  ieob	: 1,
	    ieot	: 1,
	    bei		: 1,
	    rsvd3	: 5;
	u8 re_type;
	u8 rsvd2;
} __packed;

struct gsi_xfer_compl_evt {
	u64 xfer_ptr;
	u16 len;
	u8 rsvd1;
	u8 code;  /* see gsi_chan_evt */
	u16 rsvd;
	u8 type;
	u8 chid;
} __packed;

/* Hardware values from the error log register error type field */
enum gsi_err_type {
	GSI_ERR_TYPE_GLOB	= 0x1,
	GSI_ERR_TYPE_CHAN	= 0x2,
	GSI_ERR_TYPE_EVT	= 0x3,
};

struct gsi_log_err {
	u8  arg3	: 4,
	    arg2	: 4;
	u8  arg1	: 4,
	    code	: 4;
	u8  rsvd	: 3,
	    virt_idx	: 5;
	u8  err_type	: 4,
	    ee		: 4;
} __packed;

/* Hardware values repreasenting a channel immediate command opcode */
enum gsi_ch_cmd_opcode {
	GSI_CH_ALLOCATE	= 0x0,
	GSI_CH_START	= 0x1,
	GSI_CH_STOP	= 0x2,
	GSI_CH_RESET	= 0x9,
	GSI_CH_DE_ALLOC	= 0xa,
	GSI_CH_DB_STOP	= 0xb,
};

/* Hardware values repreasenting an event ring immediate command opcode */
enum gsi_evt_ch_cmd_opcode {
	GSI_EVT_ALLOCATE	= 0x0,
	GSI_EVT_RESET		= 0x9,
	GSI_EVT_DE_ALLOC	= 0xa,
};

/** gsi_gpi_channel_scratch - GPI protocol SW config area of channel scratch
 *
 * @max_outstanding_tre: Used for the prefetch management sequence by the
 *			 sequencer. Defines the maximum number of allowed
 *			 outstanding TREs in IPA/GSI (in Bytes). RE engine
 *			 prefetch will be limited by this configuration. It
 *			 is suggested to configure this value to IPA_IF
 *			 channel TLV queue size times element size. To disable
 *			 the feature in doorbell mode (DB Mode=1). Maximum
 *			 outstanding TREs should be set to 64KB
 *			 (or any value larger or equal to ring length . RLEN)
 * @outstanding_threshold: Used for the prefetch management sequence by the
 *			 sequencer. Defines the threshold (in Bytes) as to when
 *			 to update the channel doorbell. Should be smaller than
 *			 Maximum outstanding TREs. value. It is suggested to
 *			 configure this value to 2 * element size.
 */
struct gsi_gpi_channel_scratch {
	u64 rsvd1;
	u16 rsvd2;
	u16 max_outstanding_tre;
	u16 rsvd3;
	u16 outstanding_threshold;
} __packed;

/** gsi_channel_scratch - channel scratch SW config area */
union gsi_channel_scratch {
	struct gsi_gpi_channel_scratch gpi;
	struct {
		u32 word1;
		u32 word2;
		u32 word3;
		u32 word4;
	} data;
} __packed;

/* Read a value from the given offset into the I/O space defined in
 * the GSI context.
 */
static u32 gsi_readl(struct gsi *gsi, u32 offset)
{
	return readl(gsi->base + offset);
}

/* Write the provided value to the given offset into the I/O space
 * defined in the GSI context.
 */
static void gsi_writel(struct gsi *gsi, u32 v, u32 offset)
{
	writel(v, gsi->base + offset);
}

static void _gsi_irq_control_event(struct gsi *gsi, u8 evt_id, bool enable)
{
	u32 mask = BIT(evt_id);
	u32 val;

	val = gsi_readl(gsi, GSI_CNTXT_SRC_IEOB_IRQ_MSK_OFFS);
	if (enable)
		val |= mask;
	else
		val &= ~mask;
	gsi_writel(gsi, val, GSI_CNTXT_SRC_IEOB_IRQ_MSK_OFFS);
}

static void gsi_irq_disable_event(struct gsi *gsi, u8 evt_id)
{
	_gsi_irq_control_event(gsi, evt_id, false);
}

static void gsi_irq_enable_event(struct gsi *gsi, u8 evt_id)
{
	_gsi_irq_control_event(gsi, evt_id, true);
}

static void _gsi_irq_control_all(struct gsi *gsi, bool enable)
{
	u32 val = enable ? ~0 : 0;

	/* Inter EE commands / interrupt are no supported. */
	gsi_writel(gsi, val, GSI_CNTXT_TYPE_IRQ_MSK_OFFS);
	gsi_writel(gsi, val, GSI_CNTXT_SRC_CH_IRQ_MSK_OFFS);
	gsi_writel(gsi, val, GSI_CNTXT_SRC_EV_CH_IRQ_MSK_OFFS);
	gsi_writel(gsi, val, GSI_CNTXT_SRC_IEOB_IRQ_MSK_OFFS);
	gsi_writel(gsi, val, GSI_CNTXT_GLOB_IRQ_EN_OFFS);
	/* Never enable GSI_BREAK_POINT */
	val &= ~field_gen(1, EN_BREAK_POINT_FMASK);
	gsi_writel(gsi, val, GSI_CNTXT_GSI_IRQ_EN_OFFS);
}

static void gsi_irq_disable_all(struct gsi *gsi)
{
	_gsi_irq_control_all(gsi, false);
}

static void gsi_irq_enable_all(struct gsi *gsi)
{
	_gsi_irq_control_all(gsi, true);
}

static enum gsi_chan_state gsi_chan_state(struct gsi *gsi, u32 chan_id)
{
	u32 val = gsi_readl(gsi, GSI_CH_K_CNTXT_0_OFFS(chan_id));

	return (enum gsi_chan_state)field_val(val, CHSTATE_FMASK);
}

static enum gsi_evt_ring_state gsi_evtr_state(struct gsi *gsi, u32 evt_id)
{
	u32 val = gsi_readl(gsi, GSI_EV_CH_K_CNTXT_0_OFFS(evt_id));

	return (enum gsi_evt_ring_state)field_val(val, EV_CHSTATE_FMASK);
}

static void gsi_handle_chan_ctrl(struct gsi *gsi)
{
	u32 valid_mask = GENMASK(gsi->max_ch - 1, 0);
	u32 ch_mask;

	ch_mask = gsi_readl(gsi, GSI_CNTXT_SRC_CH_IRQ_OFFS);
	gsi_writel(gsi, ch_mask, GSI_CNTXT_SRC_CH_IRQ_CLR_OFFS);

	ipa_debug("ch_mask %x\n", ch_mask);
	if (ch_mask & ~valid_mask) {
		ipa_err("invalid channels (> %u)\n", gsi->max_ch);
		ch_mask &= valid_mask;
	}

	while (ch_mask) {
		int i = __ffs(ch_mask);
		struct gsi_chan_ctx *chan = &gsi->chan[i];

		chan->state = gsi_chan_state(gsi, i);

		complete(&chan->compl);

		ch_mask ^= BIT(i);
	}
}

static void gsi_handle_evt_ctrl(struct gsi *gsi)
{
	u32 valid_mask = GENMASK(gsi->max_ev - 1, 0);
	u32 evt_mask;

	evt_mask = gsi_readl(gsi, GSI_CNTXT_SRC_EV_CH_IRQ_OFFS);
	gsi_writel(gsi, evt_mask, GSI_CNTXT_SRC_EV_CH_IRQ_CLR_OFFS);

	ipa_debug("evt_mask %x\n", evt_mask);
	if (evt_mask & ~valid_mask) {
		ipa_err("invalid events (> %u)\n", gsi->max_ev);
		evt_mask &= valid_mask;
	}

	while (evt_mask) {
		int i = __ffs(evt_mask);
		struct gsi_evt_ctx *evtr = &gsi->evtr[i];

		evtr->state = gsi_evtr_state(gsi, i);

		complete(&evtr->compl);

		evt_mask ^= BIT(i);
	}
}

static void
handle_glob_chan_err(struct gsi *gsi, u32 err_ee, u32 chan_id, u32 code)
{
	struct gsi_chan_ctx *chan = &gsi->chan[chan_id];

	if (err_ee != IPA_EE_AP)
		ipa_bug_on(code != GSI_UNSUPPORTED_INTER_EE_OP_ERR);

	if (WARN_ON(chan_id >= gsi->max_ch)) {
		ipa_err("unexpected chan_id %u\n", chan_id);
		return;
	}

	switch (code) {
	case GSI_INVALID_TRE_ERR:
		ipa_err("got INVALID_TRE_ERR\n");
		chan->state = gsi_chan_state(gsi, chan_id);
		ipa_bug_on(chan->state != GSI_CHAN_STATE_ERROR);
		break;
	case GSI_OUT_OF_BUFFERS_ERR:
		ipa_err("got OUT_OF_BUFFERS_ERR\n");
		break;
	case GSI_OUT_OF_RESOURCES_ERR:
		ipa_err("got OUT_OF_RESOURCES_ERR\n");
		complete(&chan->compl);
		break;
	case GSI_UNSUPPORTED_INTER_EE_OP_ERR:
		ipa_err("got UNSUPPORTED_INTER_EE_OP_ERR\n");
		break;
	case GSI_NON_ALLOCATED_EVT_ACCESS_ERR:
		ipa_err("got NON_ALLOCATED_EVT_ACCESS_ERR\n");
		break;
	case GSI_HWO_1_ERR:
		ipa_err("got HWO_1_ERR\n");
		break;
	default:
		ipa_err("unexpected channel error code %u\n", code);
		ipa_bug();
	}
	ipa_assert(chan->props.chan_user_data);
}

static void
handle_glob_evt_err(struct gsi *gsi, u32 err_ee, u32 evt_id, u32 code)
{
	struct gsi_evt_ctx *evtr = &gsi->evtr[evt_id];

	if (err_ee != IPA_EE_AP)
		ipa_bug_on(code != GSI_UNSUPPORTED_INTER_EE_OP_ERR);

	if (WARN_ON(evt_id >= gsi->max_ev)) {
		ipa_err("unexpected evt_id %u\n", evt_id);
		return;
	}

	switch (code) {
	case GSI_OUT_OF_BUFFERS_ERR:
		ipa_err("got OUT_OF_BUFFERS_ERR\n");
		break;
	case GSI_OUT_OF_RESOURCES_ERR:
		ipa_err("got OUT_OF_RESOURCES_ERR\n");
		complete(&evtr->compl);
		break;
	case GSI_UNSUPPORTED_INTER_EE_OP_ERR:
		ipa_err("got UNSUPPORTED_INTER_EE_OP_ERR\n");
		break;
	case GSI_EVT_RING_EMPTY_ERR:
		ipa_err("got EVT_RING_EMPTY_ERR\n");
		break;
	default:
		ipa_err("unexpected event error code %u\n", code);
		ipa_bug();
	}
}

static void gsi_handle_glob_err(struct gsi *gsi, u32 err)
{
	struct gsi_log_err *log = (struct gsi_log_err *)&err;

	ipa_err("log err_type %u ee %u idx %u\n", log->err_type, log->ee,
		log->virt_idx);
	ipa_err("log code 0x%1x arg1 0x%1x arg2 0x%1x arg3 0x%1x\n", log->code,
		log->arg1, log->arg2, log->arg3);

	ipa_bug_on(log->err_type == GSI_ERR_TYPE_GLOB);

	switch (log->err_type) {
	case GSI_ERR_TYPE_CHAN:
		handle_glob_chan_err(gsi, log->ee, log->virt_idx, log->code);
		break;
	case GSI_ERR_TYPE_EVT:
		handle_glob_evt_err(gsi, log->ee, log->virt_idx, log->code);
		break;
	default:
		WARN_ON(1);
	}
}

static void gsi_handle_glob_ee(struct gsi *gsi)
{
	u32 val;

	val = gsi_readl(gsi, GSI_CNTXT_GLOB_IRQ_STTS_OFFS);

	if (val & ERROR_INT_FMASK) {
		u32 err = gsi_readl(gsi, GSI_ERROR_LOG_OFFS);

		gsi_writel(gsi, 0, GSI_ERROR_LOG_OFFS);
		gsi_writel(gsi, ~0, GSI_ERROR_LOG_CLR_OFFS);

		gsi_handle_glob_err(gsi, err);
	}

	if (val & EN_GP_INT1_FMASK)
		ipa_err("unexpected GP INT1 received\n");

	ipa_bug_on(val & EN_GP_INT2_FMASK);
	ipa_bug_on(val & EN_GP_INT3_FMASK);

	gsi_writel(gsi, val, GSI_CNTXT_GLOB_IRQ_CLR_OFFS);
}

static void ring_wp_local_inc(struct gsi_ring_ctx *ring)
{
	ring->wp_local += GSI_RING_ELEMENT_SIZE;
	if (ring->wp_local == ring->end)
		ring->wp_local = ring->mem.phys;
}

static void ring_rp_local_inc(struct gsi_ring_ctx *ring)
{
	ring->rp_local += GSI_RING_ELEMENT_SIZE;
	if (ring->rp_local == ring->end)
		ring->rp_local = ring->mem.phys;
}

static u16 ring_rp_local_index(struct gsi_ring_ctx *ring)
{
	return (u16)(ring->rp_local - ring->mem.phys) / GSI_RING_ELEMENT_SIZE;
}

static u16 ring_wp_local_index(struct gsi_ring_ctx *ring)
{
	return (u16)(ring->wp_local - ring->mem.phys) / GSI_RING_ELEMENT_SIZE;
}

static void chan_xfer_cb(struct gsi_chan_ctx *chan, u16 count)
{
	void *xfer_data;

	if (!chan->props.from_gsi) {
		xfer_data = chan->user_data[ring_rp_local_index(&chan->ring)];
		ipa_gsi_irq_tx_notify_cb(xfer_data);
	} else {
		ipa_gsi_irq_rx_notify_cb(chan->props.chan_user_data, count);
	}
}

static u16 gsi_process_chan(struct gsi *gsi, struct gsi_xfer_compl_evt *evt,
			    bool callback)
{
	struct gsi_chan_ctx *chan;
	u32 chan_id = evt->chid;

	ipa_assert(chan_id < gsi->max_ch);

	/* Event tells us the last completed channel ring element */
	chan = &gsi->chan[chan_id];
	chan->ring.rp_local = evt->xfer_ptr;

	if (callback) {
		if (evt->code == GSI_CHAN_EVT_EOT)
			chan_xfer_cb(chan, evt->len);
		else
			ipa_err("ch %hhu unexpected %sX event id %hhu\n",
				chan_id, chan->props.from_gsi ? "R" : "T",
				evt->code);
	}

	/* Record that we've processed this channel ring element. */
	ring_rp_local_inc(&chan->ring);
	chan->ring.rp = chan->ring.rp_local;

	return evt->len;
}

static void gsi_ring_evt_doorbell(struct gsi *gsi, struct gsi_evt_ctx *evtr)
{
	u32 val;

	/* The doorbell 0 and 1 registers store the low-order and
	 * high-order 32 bits of the event ring doorbell register,
	 * respectively.  LSB (doorbell 0) must be written last.
	 */
	val = evtr->ring.wp_local >> 32;
	gsi_writel(gsi, val, GSI_EV_CH_K_DOORBELL_1_OFFS(evtr->id));

	val = evtr->ring.wp_local & GENMASK(31, 0);
	gsi_writel(gsi, val, GSI_EV_CH_K_DOORBELL_0_OFFS(evtr->id));
}

static void
gsi_ring_chan_doorbell(struct gsi *gsi, struct gsi_chan_ctx *chan)
{
	u32 val;
	u8 ch_id = chan->props.ch_id;

	/* allocate new events for this channel first
	 * before submitting the new TREs.
	 * for TO_GSI channels the event ring doorbell is rang as part of
	 * interrupt handling.
	 */
	if (chan->props.from_gsi)
		gsi_ring_evt_doorbell(gsi, chan->evtr);
	chan->ring.wp = chan->ring.wp_local;

	/* The doorbell 0 and 1 registers store the low-order and
	 * high-order 32 bits of the channel ring doorbell register,
	 * respectively.  LSB (doorbell 0) must be written last.
	 */
	val = chan->ring.wp_local >> 32;
	gsi_writel(gsi, val, GSI_CH_K_DOORBELL_1_OFFS(ch_id));
	val = chan->ring.wp_local & GENMASK(31, 0);
	gsi_writel(gsi, val, GSI_CH_K_DOORBELL_0_OFFS(ch_id));
}

static void handle_event(struct gsi *gsi, int evt_id)
{
	struct gsi_evt_ctx *evtr = &gsi->evtr[evt_id];
	unsigned long flags;
	bool check_again;

	spin_lock_irqsave(&evtr->ring.slock, flags);

	do {
		u32 val = gsi_readl(gsi, GSI_EV_CH_K_CNTXT_4_OFFS(evt_id));

		evtr->ring.rp = (evtr->ring.rp & GENMASK_ULL(63, 32)) | val;

		check_again = false;
		while (evtr->ring.rp_local != evtr->ring.rp) {
			struct gsi_xfer_compl_evt *evt;

			if (atomic_read(&evtr->chan->poll_mode)) {
				check_again = false;
				break;
			}
			check_again = true;

			evt = ipa_dma_phys_to_virt(&evtr->ring.mem,
						      evtr->ring.rp_local);
			(void)gsi_process_chan(gsi, evt, true);

			ring_rp_local_inc(&evtr->ring);
			ring_wp_local_inc(&evtr->ring); /* recycle element */
		}

		gsi_ring_evt_doorbell(gsi, evtr);
	} while (check_again);

	spin_unlock_irqrestore(&evtr->ring.slock, flags);
}

static void gsi_handle_ieob(struct gsi *gsi)
{
	u32 valid_mask = GENMASK(gsi->max_ev - 1, 0);
	u32 evt_mask;

	evt_mask = gsi_readl(gsi, GSI_CNTXT_SRC_IEOB_IRQ_OFFS);
	evt_mask &= gsi_readl(gsi, GSI_CNTXT_SRC_IEOB_IRQ_MSK_OFFS);
	gsi_writel(gsi, evt_mask, GSI_CNTXT_SRC_IEOB_IRQ_CLR_OFFS);

	if (evt_mask & ~valid_mask) {
		ipa_err("invalid events (> %u)\n", gsi->max_ev);
		evt_mask &= valid_mask;
	}

	while (evt_mask) {
		int i = __ffs(evt_mask);

		handle_event(gsi, i);

		evt_mask ^= BIT(i);
	}
}

static void gsi_handle_inter_ee_chan_ctrl(struct gsi *gsi)
{
	u32 valid_mask = GENMASK(gsi->max_ch - 1, 0);
	u32 ch_mask;

	ch_mask = gsi_readl(gsi, GSI_INTER_EE_SRC_CH_IRQ_OFFS);
	gsi_writel(gsi, ch_mask, GSI_INTER_EE_SRC_CH_IRQ_CLR_OFFS);

	if (ch_mask & ~valid_mask) {
		ipa_err("invalid channels (> %u)\n", gsi->max_ch);
		ch_mask &= valid_mask;
	}

	while (ch_mask) {
		int i = __ffs(ch_mask);

		/* not currently expected */
		ipa_err("ch %d was inter-EE changed\n", i);
		ch_mask ^= BIT(i);
	}
}

static void gsi_handle_inter_ee_evt_ctrl(struct gsi *gsi)
{
	u32 valid_mask = GENMASK(gsi->max_ev - 1, 0);
	u32 evt_mask;

	evt_mask = gsi_readl(gsi, GSI_INTER_EE_SRC_EV_CH_IRQ_OFFS);
	gsi_writel(gsi, evt_mask, GSI_INTER_EE_SRC_EV_CH_IRQ_CLR_OFFS);

	if (evt_mask & ~valid_mask) {
		ipa_err("invalid events (> %u)\n", gsi->max_ev);
		evt_mask &= valid_mask;
	}

	while (evt_mask) {
		int i = __ffs(evt_mask);

		/* not currently expected */
		ipa_err("evt %d was inter-EE changed\n", i);
		evt_mask ^= BIT(i);
	}
}

static void gsi_handle_general(struct gsi *gsi)
{
	u32 val;

	val = gsi_readl(gsi, GSI_CNTXT_GSI_IRQ_STTS_OFFS);

	ipa_bug_on(val & CLR_MCS_STACK_OVRFLOW_FMASK);
	ipa_bug_on(val & CLR_CMD_FIFO_OVRFLOW_FMASK);
	ipa_bug_on(val & CLR_BUS_ERROR_FMASK);

	if (val & CLR_BREAK_POINT_FMASK)
		ipa_err("got breakpoint\n");

	gsi_writel(gsi, val, GSI_CNTXT_GSI_IRQ_CLR_OFFS);
}

/* Returns a bitmask of pending GSI interrupts */
static u32 gsi_interrupt_type(struct gsi *gsi)
{
	return gsi_readl(gsi, GSI_CNTXT_TYPE_IRQ_OFFS);
}

static irqreturn_t gsi_isr(int irq, void *dev_id)
{
	struct gsi *gsi = dev_id;
	u32 cnt = 0;
	u32 type;

	while ((type = gsi_interrupt_type(gsi))) {
		do {
			u32 single = BIT(__ffs(type));

			switch (single) {
			case CH_CTRL_FMASK:
				gsi_handle_chan_ctrl(gsi);
				break;
			case EV_CTRL_FMASK:
				gsi_handle_evt_ctrl(gsi);
				break;
			case GLOB_EE_FMASK:
				gsi_handle_glob_ee(gsi);
				break;
			case IEOB_FMASK:
				gsi_handle_ieob(gsi);
				break;
			case INTER_EE_CH_CTRL_FMASK:
				gsi_handle_inter_ee_chan_ctrl(gsi);
				break;
			case INTER_EE_EV_CTRL_FMASK:
				gsi_handle_inter_ee_evt_ctrl(gsi);
				break;
			case GENERAL_FMASK:
				gsi_handle_general(gsi);
				break;
			default:
				WARN(true, "%s: unrecognized type 0x%08x\n",
				     __func__, single);
				break;
			}
			type ^= single;
		} while (type);

		ipa_bug_on(++cnt > GSI_ISR_MAX_ITER);
	}

	return IRQ_HANDLED;
}

static u32 gsi_get_max_channels(struct gsi *gsi)
{
	u32 val = gsi_readl(gsi, GSI_GSI_HW_PARAM_2_OFFS);

	return field_val(val, NUM_CH_PER_EE_FMASK);
}

static u32 gsi_get_max_event_rings(struct gsi *gsi)
{
	u32 val = gsi_readl(gsi, GSI_GSI_HW_PARAM_2_OFFS);

	return field_val(val, NUM_EV_PER_EE_FMASK);
}

/* Zero bits in an event bitmap represent event numbers available
 * for allocation.  Initialize the map so all events supported by
 * the hardware are available; then preclude any reserved events
 * from allocation.
 */
static u32 gsi_evt_bmap(u32 max_ev)
{
	u32 evt_bmap = GENMASK(BITS_PER_LONG - 1, max_ev);

	return evt_bmap | GENMASK(GSI_MHI_ER_END, GSI_MHI_ER_START);
}

/* gsi->mlock is assumed held by caller */
static unsigned long gsi_evt_bmap_alloc(struct gsi *gsi)
{
	unsigned long evt_id;

	ipa_assert(gsi->evt_bmap != ~0UL);

	evt_id = ffz(gsi->evt_bmap);
	gsi->evt_bmap |= BIT(evt_id);

	return evt_id;
}

/* gsi->mlock is assumed held by caller */
static void gsi_evt_bmap_free(struct gsi *gsi, unsigned long evt_id)
{
	ipa_assert(gsi->evt_bmap & BIT(evt_id));

	gsi->evt_bmap &= ~BIT(evt_id);
}

int gsi_register_device(struct gsi *gsi)
{
	u32 val;
	u32 max_ch;
	u32 max_ev;
	int ret;

	val = gsi_readl(gsi, GSI_GSI_STATUS_OFFS);
	if (!(val & ENABLED_FMASK)) {
		ipa_err("manager EE has not enabled GSI, GSI un-usable\n");
		return -EIO;
	}

	max_ch = gsi_get_max_channels(gsi);
	if (WARN_ON(max_ch > GSI_CHAN_MAX))
		return -EIO;

	max_ev = gsi_get_max_event_rings(gsi);
	if (WARN_ON(max_ev > GSI_EVT_RING_MAX))
		return -EIO;

	ret = request_irq(gsi->irq, gsi_isr, IRQF_TRIGGER_HIGH, "gsi", gsi);
	if (ret) {
		ipa_err("failed to register isr for %u\n", gsi->irq);
		return -EIO;
	}

	ret = enable_irq_wake(gsi->irq);
	if (ret)
		ipa_err("error %d enabling gsi wake irq\n", ret);
	gsi->irq_wake_enabled = !ret;

	gsi->max_ch = max_ch;
	gsi->max_ev = max_ev;
	gsi->evt_bmap = gsi_evt_bmap(max_ev);

	/* Enable all IPA interrupts */
	gsi_irq_enable_all(gsi);

	/* Writing 1 indicates IRQ interrupts; 0 would be MSI */
	gsi_writel(gsi, 1, GSI_CNTXT_INTSET_OFFS);

	/* Initialize the error log */
	gsi_writel(gsi, 0, GSI_ERROR_LOG_OFFS);

	return 0;
}

void gsi_deregister_device(struct gsi *gsi)
{
	ipa_assert(!atomic_read(&gsi->num_chan));
	ipa_assert(!atomic_read(&gsi->num_evt_ring));

	/* Don't bother clearing the error log again (ERROR_LOG) or
	 * setting the interrupt type again (INTSET).
	 */
	gsi_irq_disable_all(gsi);

	/* Clean up everything else set up by gsi_register_device() */
	gsi->evt_bmap = 0;
	gsi->max_ev = 0;
	gsi->max_ch = 0;
	if (gsi->irq_wake_enabled) {
		(void)disable_irq_wake(gsi->irq);
		gsi->irq_wake_enabled = false;
	}
	free_irq(gsi->irq, gsi);
	gsi->irq = 0;
}

static void gsi_program_evt_ring_ctx(struct gsi *gsi, u8 evt_id, u32 size,
				     u64 phys, u16 int_modt)
{
	u32 int_modc = 1;	/* moderation always comes from channel*/
	u32 val;

	ipa_debug("intf GPI intr IRQ RE size %u\n", GSI_RING_ELEMENT_SIZE);

	val = field_gen(GSI_EVT_CHTYPE_GPI_EV, EV_CHTYPE_FMASK);
	val |= field_gen(1, EV_INTYPE_FMASK);
	val |= field_gen(GSI_RING_ELEMENT_SIZE, EV_ELEMENT_SIZE_FMASK);
	gsi_writel(gsi, val, GSI_EV_CH_K_CNTXT_0_OFFS(evt_id));

	val = field_gen(size, EV_R_LENGTH_FMASK);
	gsi_writel(gsi, val, GSI_EV_CH_K_CNTXT_1_OFFS(evt_id));

	/* The context 2 and 3 registers store the low-order and
	 * high-order 32 bits of the address of the event ring,
	 * respectively.
	 */
	val = phys & GENMASK(31, 0);
	gsi_writel(gsi, val, GSI_EV_CH_K_CNTXT_2_OFFS(evt_id));

	val = phys >> 32;
	gsi_writel(gsi, val, GSI_EV_CH_K_CNTXT_3_OFFS(evt_id));

	val = field_gen(int_modt, MODT_FMASK);
	val |= field_gen(int_modc, MODC_FMASK);
	gsi_writel(gsi, val, GSI_EV_CH_K_CNTXT_8_OFFS(evt_id));

	/* No MSI write data, and MSI address high and low address is 0 */
	gsi_writel(gsi, 0, GSI_EV_CH_K_CNTXT_9_OFFS(evt_id));
	gsi_writel(gsi, 0, GSI_EV_CH_K_CNTXT_10_OFFS(evt_id));
	gsi_writel(gsi, 0, GSI_EV_CH_K_CNTXT_11_OFFS(evt_id));

	/* We don't need to get event read pointer updates */
	gsi_writel(gsi, 0, GSI_EV_CH_K_CNTXT_12_OFFS(evt_id));
	gsi_writel(gsi, 0, GSI_EV_CH_K_CNTXT_13_OFFS(evt_id));
}

static void gsi_init_ring(struct gsi_ring_ctx *ring, struct ipa_dma_mem *mem)
{
	spin_lock_init(&ring->slock);
	ring->mem = *mem;
	ring->wp = mem->phys;
	ring->rp = mem->phys;
	ring->wp_local = mem->phys;
	ring->rp_local = mem->phys;
	ring->end = mem->phys + mem->size;
}

static void gsi_prime_evt_ring(struct gsi *gsi, struct gsi_evt_ctx *evtr)
{
	unsigned long flags;

	spin_lock_irqsave(&evtr->ring.slock, flags);
	memset(evtr->ring.mem.virt, 0, evtr->ring.mem.size);
	evtr->ring.wp_local = evtr->ring.end - GSI_RING_ELEMENT_SIZE;
	gsi_ring_evt_doorbell(gsi, evtr);
	spin_unlock_irqrestore(&evtr->ring.slock, flags);
}

/* Issue a GSI command by writing a value to a register, then wait
 * for completion to be signaled.  Returns 0 if a timeout occurred,
 * non-zero (positive) othwerwise.  Note that the register offset
 * is first, value to write is second (reverse of writel() order).
 */
static u32
command(struct gsi *gsi, u32 reg, u32 val, struct completion *compl)
{
	gsi_writel(gsi, val, reg);

	return (u32)wait_for_completion_timeout(compl, GSI_CMD_TIMEOUT);
}

/* Issue an event ring command and wait for it to complete */
static u32 evt_ring_command(struct gsi *gsi, unsigned long evt_id,
			    enum gsi_evt_ch_cmd_opcode op)
{
	struct completion *compl = &gsi->evtr[evt_id].compl;
	u32 val;

	reinit_completion(compl);

	val = field_gen((u32)evt_id, EV_CHID_FMASK);
	val |= field_gen((u32)op, EV_OPCODE_FMASK);

	val = command(gsi, GSI_EV_CH_CMD_OFFS, val, compl);
	if (!val)
		ipa_err("evt_id %lu timed out\n", evt_id);

	return val;
}

/* Issue a channel command and wait for it to complete */
static u32 channel_command(struct gsi *gsi, unsigned long chan_id,
			   enum gsi_ch_cmd_opcode op)
{
	struct completion *compl = &gsi->chan[chan_id].compl;
	u32 val;

	reinit_completion(compl);

	val = field_gen((u32)chan_id, CH_CHID_FMASK);
	val |= field_gen((u32)op, CH_OPCODE_FMASK);

	val = command(gsi, GSI_CH_CMD_OFFS, val, compl);
	if (!val)
		ipa_err("chan_id %lu timed out\n", chan_id);

	return val;
}

/* Note: only GPI interfaces, IRQ interrupts are currently supported */
long gsi_alloc_evt_ring(struct gsi *gsi, u32 ring_count, u16 int_modt)
{
	u32 size = ring_count * GSI_RING_ELEMENT_SIZE;
	unsigned long evt_id;
	struct gsi_evt_ctx *evtr;
	unsigned long flags;
	u32 completed;
	u32 val;
	int ret;

	/* Get the mutex to allocate from the bitmap and issue a command */
	mutex_lock(&gsi->mlock);

	/* Start by allocating the event id to use */
	evt_id = gsi_evt_bmap_alloc(gsi);
	evtr = &gsi->evtr[evt_id];
	ipa_debug("Using %lu as virt evt id\n", evt_id);

	if (ipa_dma_alloc(&evtr->mem, size, GFP_KERNEL)) {
		ipa_err("fail to dma alloc %u bytes\n", size);
		ret = -ENOMEM;
		goto err_free_bmap;
	}
	ipa_assert(!(evtr->mem.phys % roundup_pow_of_two(size)));

	evtr->id = evt_id;
	evtr->int_modt = int_modt;
	init_completion(&evtr->compl);
	atomic_set(&evtr->chan_ref_cnt, 0);

	completed = evt_ring_command(gsi, evt_id, GSI_EVT_ALLOCATE);
	if (!completed) {
		ret = -ETIMEDOUT;
		goto err_free_dma;
	}

	if (evtr->state != GSI_EVT_RING_STATE_ALLOCATED) {
		ipa_err("evt_id %lu allocation failed state %u\n",
			evt_id, evtr->state);
		ret = -ENOMEM;
		goto err_free_dma;
	}
	atomic_inc(&gsi->num_evt_ring);

	gsi_program_evt_ring_ctx(gsi, evt_id, evtr->mem.size,
				 evtr->mem.phys, evtr->int_modt);
	gsi_init_ring(&evtr->ring, &evtr->mem);

	gsi_prime_evt_ring(gsi, evtr);

	mutex_unlock(&gsi->mlock);

	spin_lock_irqsave(&gsi->slock, flags);

	/* Enable the event interrupt (clear it first in case pending) */
	val = BIT(evt_id);
	gsi_writel(gsi, val, GSI_CNTXT_SRC_IEOB_IRQ_CLR_OFFS);
	gsi_irq_enable_event(gsi, evt_id);

	spin_unlock_irqrestore(&gsi->slock, flags);

	return evt_id;

err_free_dma:
	ipa_dma_free(&evtr->mem);
	memset(evtr, 0, sizeof(*evtr));
err_free_bmap:
	gsi_evt_bmap_free(gsi, evt_id);

	mutex_unlock(&gsi->mlock);

	return ret;
}

static void
__gsi_zero_evt_ring_scratch(struct gsi *gsi, unsigned long evt_id)
{
	gsi_writel(gsi, 0, GSI_EV_CH_K_SCRATCH_0_OFFS(evt_id));
	gsi_writel(gsi, 0, GSI_EV_CH_K_SCRATCH_1_OFFS(evt_id));
}

void gsi_dealloc_evt_ring(struct gsi *gsi, unsigned long evt_id)
{
	struct gsi_evt_ctx *evtr = &gsi->evtr[evt_id];
	u32 completed;

	ipa_bug_on(atomic_read(&evtr->chan_ref_cnt));

	/* TODO: add check for ERROR state */
	ipa_bug_on(evtr->state != GSI_EVT_RING_STATE_ALLOCATED);

	mutex_lock(&gsi->mlock);

	completed = evt_ring_command(gsi, evt_id, GSI_EVT_DE_ALLOC);
	ipa_bug_on(!completed);

	ipa_bug_on(evtr->state != GSI_EVT_RING_STATE_NOT_ALLOCATED);

	gsi_evt_bmap_free(gsi, evtr->id);

	mutex_unlock(&gsi->mlock);

	evtr->int_modt = 0;
	ipa_dma_free(&evtr->mem);
	memset(evtr, 0, sizeof(*evtr));

	atomic_dec(&gsi->num_evt_ring);
}

void gsi_reset_evt_ring(struct gsi *gsi, unsigned long evt_id)
{
	struct gsi_evt_ctx *evtr = &gsi->evtr[evt_id];
	u32 completed;

	ipa_bug_on(evtr->state != GSI_EVT_RING_STATE_ALLOCATED);

	mutex_lock(&gsi->mlock);

	completed = evt_ring_command(gsi, evt_id, GSI_EVT_RESET);
	ipa_bug_on(!completed);

	ipa_bug_on(evtr->state != GSI_EVT_RING_STATE_ALLOCATED);

	gsi_program_evt_ring_ctx(gsi, evt_id, evtr->mem.size,
				 evtr->mem.phys, evtr->int_modt);
	gsi_init_ring(&evtr->ring, &evtr->mem);

	__gsi_zero_evt_ring_scratch(gsi, evt_id);

	gsi_prime_evt_ring(gsi, evtr);
	mutex_unlock(&gsi->mlock);
}

static void
gsi_program_chan_ctx(struct gsi *gsi, struct gsi_chan_props *props, u8 evt_id)
{
	u32 val;

	val = field_gen(GSI_CHAN_PROT_GPI, CHTYPE_PROTOCOL_FMASK);
	val |= field_gen(props->from_gsi ? 0 : 1, CHTYPE_DIR_FMASK);
	val |= field_gen(evt_id, ERINDEX_FMASK);
	val |= field_gen(GSI_RING_ELEMENT_SIZE, ELEMENT_SIZE_FMASK);
	gsi_writel(gsi, val, GSI_CH_K_CNTXT_0_OFFS(props->ch_id));

	val = field_gen(props->mem.size, R_LENGTH_FMASK);
	gsi_writel(gsi, val, GSI_CH_K_CNTXT_1_OFFS(props->ch_id));

	/* The context 2 and 3 registers store the low-order and
	 * high-order 32 bits of the address of the channel ring,
	 * respectively.
	 */
	val = props->mem.phys & GENMASK(31, 0);
	gsi_writel(gsi, val, GSI_CH_K_CNTXT_2_OFFS(props->ch_id));

	val = props->mem.phys >> 32;
	gsi_writel(gsi, val, GSI_CH_K_CNTXT_3_OFFS(props->ch_id));

	val = field_gen(props->low_weight, WRR_WEIGHT_FMASK);
	val |= field_gen(GSI_MAX_PREFETCH, MAX_PREFETCH_FMASK);
	val |= field_gen(props->use_db_engine ? 1 : 0, USE_DB_ENG_FMASK);
	gsi_writel(gsi, val, GSI_CH_K_QOS_OFFS(props->ch_id));
}

long gsi_alloc_channel(struct gsi *gsi, struct gsi_chan_props *props)
{
	u32 size = props->ring_count * GSI_RING_ELEMENT_SIZE;
	u8 evt_id = (u8)props->evt_ring_hdl;
	struct gsi_evt_ctx *evtr = &gsi->evtr[evt_id];
	long chan_id = (long)props->ch_id;
	struct gsi_chan_ctx *chan = &gsi->chan[chan_id];
	void **user_data;
	u32 completed;

	if (ipa_dma_alloc(&props->mem, size, GFP_KERNEL)) {
		ipa_err("fail to dma alloc %u bytes\n", size);
		return -ENOMEM;
	}
	ipa_assert(!(props->mem.size % roundup_pow_of_two(size)));
	ipa_assert(!(props->mem.phys % roundup_pow_of_two(size)));

	if (atomic_read(&evtr->chan_ref_cnt)) {
		ipa_err("evt ring %hhu in use\n", evt_id);
		ipa_dma_free(&props->mem);
		return -ENOTSUPP;
	}

	if (chan->allocated) {
		ipa_err("chan %ld already allocated\n", chan_id);
		ipa_dma_free(&props->mem);
		return -ENODEV;
	}
	memset(chan, 0, sizeof(*chan));

	user_data = kcalloc(props->ring_count, sizeof(void *), GFP_KERNEL);
	if (!user_data) {
		ipa_dma_free(&props->mem);
		return -ENOMEM;
	}

	mutex_init(&chan->mlock);
	init_completion(&chan->compl);
	atomic_set(&chan->poll_mode, 0);	/* Initially in callback mode */
	chan->props = *props;

	mutex_lock(&gsi->mlock);

	completed = channel_command(gsi, chan_id, GSI_CH_ALLOCATE);
	if (!completed) {
		chan_id = -ETIMEDOUT;
		goto err_mutex_unlock;
	}
	if (chan->state != GSI_CHAN_STATE_ALLOCATED) {
		ipa_err("chan_id %ld allocation failed state %d\n",
			chan_id, chan->state);
		chan_id = -ENOMEM;
		goto err_mutex_unlock;
	}

	gsi->ch_dbg[chan_id].ch_allocate++;

	mutex_unlock(&gsi->mlock);

	chan->evtr = evtr;
	atomic_inc(&evtr->chan_ref_cnt);
	evtr->chan = chan;

	gsi_program_chan_ctx(gsi, props, evt_id);
	gsi_init_ring(&chan->ring, &props->mem);

	chan->user_data = user_data;
	chan->allocated = true;
	atomic_inc(&gsi->num_chan);

	return chan_id;

err_mutex_unlock:
	mutex_unlock(&gsi->mlock);
	kfree(user_data);
	ipa_dma_free(&chan->props.mem);

	return chan_id;
}

static void
__gsi_write_channel_scratch(struct gsi *gsi, unsigned long chan_id)
{
	struct gsi_chan_ctx *chan = &gsi->chan[chan_id];
	union gsi_channel_scratch scr = { };
	struct gsi_gpi_channel_scratch *gpi = &scr.gpi;
	u32 val;

	/* See comments above definition of gsi_gpi_channel_scratch */
	gpi->max_outstanding_tre = chan->tlv_size * GSI_RING_ELEMENT_SIZE;
	gpi->outstanding_threshold = 2 * GSI_RING_ELEMENT_SIZE;

	val = scr.data.word1;
	gsi_writel(gsi, val, GSI_CH_K_SCRATCH_0_OFFS(chan_id));

	val = scr.data.word2;
	gsi_writel(gsi, val, GSI_CH_K_SCRATCH_1_OFFS(chan_id));

	val = scr.data.word3;
	gsi_writel(gsi, val, GSI_CH_K_SCRATCH_2_OFFS(chan_id));

	/* We must preserve the upper 16 bits of the last scratch
	 * register.  The next sequence assumes those bits remain
	 * unchanged between the read and the write.
	 */
	val = gsi_readl(gsi, GSI_CH_K_SCRATCH_3_OFFS(chan_id));
	val = (scr.data.word4 & GENMASK(31, 16)) | (val & GENMASK(15, 0));
	gsi_writel(gsi, val, GSI_CH_K_SCRATCH_3_OFFS(chan_id));
}

int
gsi_write_channel_scratch(struct gsi *gsi, unsigned long chan_id, u32 tlv_size)
{
	struct gsi_chan_ctx *chan = &gsi->chan[chan_id];

	chan->tlv_size = tlv_size;

	mutex_lock(&chan->mlock);

	__gsi_write_channel_scratch(gsi, chan_id);

	mutex_unlock(&chan->mlock);

	return 0;
}

int gsi_start_channel(struct gsi *gsi, unsigned long chan_id)
{
	struct gsi_chan_ctx *chan = &gsi->chan[chan_id];
	u32 completed;

	if (chan->state != GSI_CHAN_STATE_ALLOCATED &&
	    chan->state != GSI_CHAN_STATE_STOP_IN_PROC &&
	    chan->state != GSI_CHAN_STATE_STOPPED) {
		ipa_err("bad state %d\n", chan->state);
		return -ENOTSUPP;
	}

	mutex_lock(&gsi->mlock);

	gsi->ch_dbg[chan_id].ch_start++;

	completed = channel_command(gsi, chan_id, GSI_CH_START);
	if (!completed) {
		mutex_unlock(&gsi->mlock);
		return -ETIMEDOUT;
	}
	if (chan->state != GSI_CHAN_STATE_STARTED) {
		ipa_err("chan %lu unexpected state %u\n", chan_id, chan->state);
		ipa_bug();
	}

	mutex_unlock(&gsi->mlock);

	return 0;
}

int gsi_stop_channel(struct gsi *gsi, unsigned long chan_id)
{
	struct gsi_chan_ctx *chan = &gsi->chan[chan_id];
	u32 completed;
	int ret;

	if (chan->state == GSI_CHAN_STATE_STOPPED) {
		ipa_debug("chan_id %lu already stopped\n", chan_id);
		return 0;
	}

	if (chan->state != GSI_CHAN_STATE_STARTED &&
	    chan->state != GSI_CHAN_STATE_STOP_IN_PROC &&
	    chan->state != GSI_CHAN_STATE_ERROR) {
		ipa_err("bad state %d\n", chan->state);
		return -ENOTSUPP;
	}

	mutex_lock(&gsi->mlock);

	gsi->ch_dbg[chan_id].ch_stop++;

	completed = channel_command(gsi, chan_id, GSI_CH_STOP);
	if (!completed) {
		/* check channel state here in case the channel is stopped but
		 * the interrupt was not handled yet.
		 */
		chan->state = gsi_chan_state(gsi, chan_id);
		if (chan->state == GSI_CHAN_STATE_STOPPED) {
			ret = 0;
			goto free_lock;
		}
		ret = -ETIMEDOUT;
		goto free_lock;
	}

	if (chan->state != GSI_CHAN_STATE_STOPPED &&
	    chan->state != GSI_CHAN_STATE_STOP_IN_PROC) {
		ipa_err("chan %lu unexpected state %u\n", chan_id, chan->state);
		ret = -EBUSY;
		goto free_lock;
	}

	if (chan->state == GSI_CHAN_STATE_STOP_IN_PROC) {
		ipa_err("chan %lu busy try again\n", chan_id);
		ret = -EAGAIN;
		goto free_lock;
	}

	ret = 0;

free_lock:
	mutex_unlock(&gsi->mlock);

	return ret;
}

int gsi_reset_channel(struct gsi *gsi, unsigned long chan_id)
{
	struct gsi_chan_ctx *chan = &gsi->chan[chan_id];
	bool reset_done = false;
	u32 completed;

	if (chan->state != GSI_CHAN_STATE_STOPPED) {
		ipa_err("bad state %d\n", chan->state);
		return -ENOTSUPP;
	}

	mutex_lock(&gsi->mlock);
reset:

	gsi->ch_dbg[chan_id].ch_reset++;

	completed = channel_command(gsi, chan_id, GSI_CH_RESET);
	if (!completed) {
		ipa_err("chan_id %lu timed out\n", chan_id);
		mutex_unlock(&gsi->mlock);
		return -ETIMEDOUT;
	}

	if (chan->state != GSI_CHAN_STATE_ALLOCATED) {
		ipa_err("chan_id %lu unexpected state %u\n", chan_id,
			chan->state);
		ipa_bug();
	}

	/* workaround: reset GSI producers again */
	if (chan->props.from_gsi && !reset_done) {
		usleep_range(GSI_RESET_WA_MIN_SLEEP, GSI_RESET_WA_MAX_SLEEP);
		reset_done = true;
		goto reset;
	}

	gsi_program_chan_ctx(gsi, &chan->props, chan->evtr->id);
	gsi_init_ring(&chan->ring, &chan->props.mem);

	/* restore scratch */
	__gsi_write_channel_scratch(gsi, chan_id);

	mutex_unlock(&gsi->mlock);

	return 0;
}

void gsi_dealloc_channel(struct gsi *gsi, unsigned long chan_id)
{
	struct gsi_chan_ctx *chan = &gsi->chan[chan_id];
	u32 completed;

	ipa_bug_on(chan->state != GSI_CHAN_STATE_ALLOCATED);

	mutex_lock(&gsi->mlock);

	gsi->ch_dbg[chan_id].ch_de_alloc++;

	completed = channel_command(gsi, chan_id, GSI_CH_DE_ALLOC);
	ipa_bug_on(!completed);

	ipa_bug_on(chan->state != GSI_CHAN_STATE_NOT_ALLOCATED);

	mutex_unlock(&gsi->mlock);

	kfree(chan->user_data);
	ipa_dma_free(&chan->props.mem);
	chan->allocated = false;
	atomic_dec(&chan->evtr->chan_ref_cnt);
	atomic_dec(&gsi->num_chan);
}

static u16 __gsi_query_ring_free_re(struct gsi_ring_ctx *ring)
{
	u64 delta;

	if (ring->wp_local < ring->rp_local)
		delta = ring->rp_local - ring->wp_local;
	else
		delta = ring->end - ring->wp_local + ring->rp_local;

	return (u16)(delta / GSI_RING_ELEMENT_SIZE - 1);
}

bool gsi_is_channel_empty(struct gsi *gsi, unsigned long chan_id)
{
	struct gsi_chan_ctx *chan;
	unsigned long flags;
	bool empty;
	u32 val;

	chan = &gsi->chan[chan_id];

	spin_lock_irqsave(&chan->evtr->ring.slock, flags);

	val = gsi_readl(gsi, GSI_CH_K_CNTXT_4_OFFS(chan->props.ch_id));
	chan->ring.rp = (chan->ring.rp & GENMASK_ULL(63, 32)) | val;

	val = gsi_readl(gsi, GSI_CH_K_CNTXT_6_OFFS(chan->props.ch_id));
	chan->ring.wp = (chan->ring.wp & GENMASK_ULL(63, 32)) | val;

	if (chan->props.from_gsi)
		empty = chan->ring.rp_local == chan->ring.rp;
	else
		empty = chan->ring.wp == chan->ring.rp;

	spin_unlock_irqrestore(&chan->evtr->ring.slock, flags);

	ipa_debug("chan_id %lu RP 0x%llx WP 0x%llx RP_LOCAL 0x%llx\n", chan_id,
		  chan->ring.rp, chan->ring.wp, chan->ring.rp_local);

	return empty;
}

int gsi_queue_xfer(struct gsi *gsi, unsigned long chan_id, u16 num_xfers,
		   struct gsi_xfer_elem *xfer, bool ring_db)
{
	struct gsi_chan_ctx *chan = &gsi->chan[chan_id];
	unsigned long flags;
	u32 i;

	spin_lock_irqsave(&chan->evtr->ring.slock, flags);

	if (num_xfers > __gsi_query_ring_free_re(&chan->ring)) {
		spin_unlock_irqrestore(&chan->evtr->ring.slock, flags);

		return -ENOSPC;
	}

	for (i = 0; i < num_xfers; i++) {
		struct gsi_tre *tre_ptr;
		u16 idx = ring_wp_local_index(&chan->ring);

		chan->user_data[idx] = xfer[i].xfer_user_data;

		tre_ptr = ipa_dma_phys_to_virt(&chan->ring.mem,
						  chan->ring.wp_local);

		tre_ptr->buffer_ptr = xfer[i].addr;
		tre_ptr->buf_len = xfer[i].len;
		tre_ptr->bei = xfer[i].flags & GSI_XFER_FLAG_BEI ? 1 : 0;
		tre_ptr->ieot = xfer[i].flags & GSI_XFER_FLAG_EOT ? 1 : 0;
		tre_ptr->ieob = xfer[i].flags & GSI_XFER_FLAG_EOB ? 1 : 0;
		tre_ptr->chain = xfer[i].flags & GSI_XFER_FLAG_CHAIN ? 1 : 0;

		if (xfer[i].type == GSI_XFER_ELEM_DATA)
			tre_ptr->re_type = GSI_RE_XFER;
		else if (xfer[i].type == GSI_XFER_ELEM_IMME_CMD)
			tre_ptr->re_type = GSI_RE_IMMD_CMD;
		else if (xfer[i].type == GSI_XFER_ELEM_NOP)
			tre_ptr->re_type = GSI_RE_NOP;
		else
			ipa_bug_on("invalid xfer type");

		ring_wp_local_inc(&chan->ring);
	}

	wmb();	/* Ensure TRE is set before ringing doorbell */

	if (ring_db)
		gsi_ring_chan_doorbell(gsi, chan);

	spin_unlock_irqrestore(&chan->evtr->ring.slock, flags);

	return 0;
}

int gsi_start_xfer(struct gsi *gsi, unsigned long chan_id)
{
	struct gsi_chan_ctx *chan = &gsi->chan[chan_id];

	if (chan->state != GSI_CHAN_STATE_STARTED) {
		ipa_err("bad state %d\n", chan->state);
		return -ENOTSUPP;
	}

	if (chan->ring.wp == chan->ring.wp_local)
		return 0;

	gsi_ring_chan_doorbell(gsi, chan);

	return 0;
}

int gsi_poll_channel(struct gsi *gsi, unsigned long chan_id)
{
	struct gsi_chan_ctx *chan = &gsi->chan[chan_id];
	struct gsi_evt_ctx *evtr = chan->evtr;
	unsigned long flags;
	int size;

	spin_lock_irqsave(&evtr->ring.slock, flags);

	/* update rp to see of we have anything new to process */
	if (evtr->ring.rp == evtr->ring.rp_local) {
		u32 val;

		val = gsi_readl(gsi, GSI_EV_CH_K_CNTXT_4_OFFS(evtr->id));
		evtr->ring.rp = (chan->ring.rp & GENMASK_ULL(63, 32)) | val;
	}

	if (evtr->ring.rp != evtr->ring.rp_local) {
		struct gsi_xfer_compl_evt *evt;

		evt = ipa_dma_phys_to_virt(&evtr->ring.mem,
					      evtr->ring.rp_local);
		size = gsi_process_chan(gsi, evt, false);

		ring_rp_local_inc(&evtr->ring);
		ring_wp_local_inc(&evtr->ring); /* recycle element */
	} else {
		size = -ENOENT;
	}

	spin_unlock_irqrestore(&evtr->ring.slock, flags);

	return size;
}

static void
gsi_config_channel_mode(struct gsi *gsi, unsigned long chan_id, bool polling)
{
	struct gsi_chan_ctx *chan = &gsi->chan[chan_id];
	unsigned long flags;

	spin_lock_irqsave(&gsi->slock, flags);
	if (polling)
		gsi_irq_disable_event(gsi, chan->evtr->id);
	else
		gsi_irq_enable_event(gsi, chan->evtr->id);
	atomic_set(&chan->poll_mode, polling ? 1 : 0);
	spin_unlock_irqrestore(&gsi->slock, flags);
}

void gsi_channel_intr_enable(struct gsi *gsi, unsigned long chan_id)
{
	gsi_config_channel_mode(gsi, chan_id, false);
}

void gsi_channel_intr_disable(struct gsi *gsi, unsigned long chan_id)
{
	gsi_config_channel_mode(gsi, chan_id, true);
}

int gsi_get_channel_cfg(struct gsi *gsi, unsigned long chan_id,
			struct gsi_chan_props *props)
{
	struct gsi_chan_ctx *chan = &gsi->chan[chan_id];

	if (chan->state == GSI_CHAN_STATE_NOT_ALLOCATED) {
		ipa_err("bad state %d\n", chan->state);
		return -ENOTSUPP;
	}

	mutex_lock(&chan->mlock);
	*props = chan->props;
	mutex_unlock(&chan->mlock);

	return 0;
}

int gsi_set_channel_cfg(struct gsi *gsi, unsigned long chan_id,
			struct gsi_chan_props *props)
{
	struct gsi_chan_ctx *chan;

	chan = &gsi->chan[chan_id];
	if (chan->state != GSI_CHAN_STATE_ALLOCATED) {
		ipa_err("bad state %d\n", chan->state);
		return -ENOTSUPP;
	}

	if (chan->props.ch_id != props->ch_id ||
	    chan->props.evt_ring_hdl != props->evt_ring_hdl) {
		ipa_err("changing immutable fields not supported\n");
		return -ENOTSUPP;
	}

	mutex_lock(&chan->mlock);
	chan->props = *props;

	gsi_program_chan_ctx(gsi, &chan->props, chan->evtr->id);
	gsi_init_ring(&chan->ring, &chan->props.mem);

	/* restore scratch */
	__gsi_write_channel_scratch(gsi, chan_id);
	mutex_unlock(&chan->mlock);

	return 0;
}

/* Initialize GSI driver */
struct gsi *gsi_init(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct resource *res;
	resource_size_t size;
	struct gsi *gsi;
	int irq;

	/* Get GSI memory range and map it */
	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "gsi");
	if (!res) {
		ipa_err("missing \"gsi\" property in DTB\n");
		return ERR_PTR(-EINVAL);
	}

	size = resource_size(res);
	if (res->start > U32_MAX || size > U32_MAX) {
		ipa_err("\"gsi\" values out of range\n");
		return ERR_PTR(-EINVAL);
	}

	/* Get IPA GSI IRQ number */
	irq = platform_get_irq_byname(pdev, "gsi");
	if (irq < 0) {
		ipa_err("failed to get gsi IRQ!\n");
		return ERR_PTR(irq);
	}
	ipa_debug("GSI irq %u\n", irq);

	gsi = kzalloc(sizeof(*gsi), GFP_KERNEL);
	if (!gsi)
		return ERR_PTR(-ENOMEM);

	gsi->base = devm_ioremap_nocache(dev, res->start, size);
	if (!gsi->base) {
		kfree(gsi);

		return ERR_PTR(-ENOMEM);
	}
	gsi->dev = dev;
	gsi->phys = (u32)res->start;
	gsi->irq = irq;
	spin_lock_init(&gsi->slock);
	mutex_init(&gsi->mlock);
	atomic_set(&gsi->num_chan, 0);
	atomic_set(&gsi->num_evt_ring, 0);

	return gsi;
}
