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
#include <linux/qcom_scm.h>

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
enum gsi_channel_protocol {
	GSI_CHANNEL_PROTOCOL_MHI	= 0x0,
	GSI_CHANNEL_PROTOCOL_XHCI	= 0x1,
	GSI_CHANNEL_PROTOCOL_GPI	= 0x2,
	GSI_CHANNEL_PROTOCOL_XDCI	= 0x3,
};

/* Hardware values returned in a transfer completion event structure */
enum gsi_channel_evt {
	GSI_CHANNEL_EVT_INVALID		= 0x0,
	GSI_CHANNEL_EVT_SUCCESS		= 0x1,
	GSI_CHANNEL_EVT_EOT		= 0x2,
	GSI_CHANNEL_EVT_OVERFLOW	= 0x3,
	GSI_CHANNEL_EVT_EOB		= 0x4,
	GSI_CHANNEL_EVT_OOB		= 0x5,
	GSI_CHANNEL_EVT_DB_MODE		= 0x6,
	GSI_CHANNEL_EVT_UNDEFINED	= 0x10,
	GSI_CHANNEL_EVT_RE_ERROR	= 0x11,
};

/* Hardware values signifying the state of an event ring */
enum gsi_evt_ring_state {
	GSI_EVT_RING_STATE_NOT_ALLOCATED	= 0x0,
	GSI_EVT_RING_STATE_ALLOCATED		= 0x1,
	GSI_EVT_RING_STATE_ERROR		= 0xf,
};

/* Hardware values signifying the state of a channel */
enum gsi_channel_state {
	GSI_CHANNEL_STATE_NOT_ALLOCATED	= 0x0,
	GSI_CHANNEL_STATE_ALLOCATED	= 0x1,
	GSI_CHANNEL_STATE_STARTED	= 0x2,
	GSI_CHANNEL_STATE_STOPPED	= 0x3,
	GSI_CHANNEL_STATE_STOP_IN_PROC	= 0x4,
	GSI_CHANNEL_STATE_ERROR		= 0xf,
};

struct gsi_ring {
	spinlock_t slock;		/* protects wp, rp updates */
	struct ipa_dma_mem mem;
	u64 wp;
	u64 rp;
	u64 wp_local;
	u64 rp_local;
	u64 end;			/* physical addr past last element */
};

struct gsi_channel {
	struct gsi_channel_props props;
	enum gsi_channel_state state;
	struct gsi_ring ring;
	void **user_data;
	struct gsi_evt_ring *evt_ring;
	struct mutex mlock;		/* protects channel_scratch updates */
	struct completion compl;
	bool allocated;
	atomic_t poll_mode;
	u32 tlv_size;			/* # slots in TLV */
};

struct gsi_evt_ring {
	struct ipa_dma_mem mem;
	u16 int_modt;
	enum gsi_evt_ring_state state;
	u32 id;
	struct gsi_ring ring;
	struct completion compl;
	struct gsi_channel *channel;
	atomic_t channel_ref_cnt;
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
	atomic_t channel_count;
	atomic_t evt_ring_count;
	struct gsi_channel channel[GSI_CHAN_MAX];
	struct ch_debug_stats ch_dbg[GSI_CHAN_MAX];
	struct gsi_evt_ring evt_ring[GSI_EVT_RING_MAX];
	unsigned long evt_bmap;
	u32 channel_max;
	u32 evt_ring_max;
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
	u8 code;  /* see gsi_channel_evt */
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

static void
_gsi_irq_control_event(struct gsi *gsi, u32 evt_ring_id, bool enable)
{
	u32 mask = BIT(evt_ring_id);
	u32 val;

	val = gsi_readl(gsi, GSI_CNTXT_SRC_IEOB_IRQ_MSK_OFFS);
	if (enable)
		val |= mask;
	else
		val &= ~mask;
	gsi_writel(gsi, val, GSI_CNTXT_SRC_IEOB_IRQ_MSK_OFFS);
}

static void gsi_irq_disable_event(struct gsi *gsi, u32 evt_ring_id)
{
	_gsi_irq_control_event(gsi, evt_ring_id, false);
}

static void gsi_irq_enable_event(struct gsi *gsi, u32 evt_ring_id)
{
	_gsi_irq_control_event(gsi, evt_ring_id, true);
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

static enum gsi_channel_state gsi_channel_state(struct gsi *gsi, u32 channel_id)
{
	u32 val = gsi_readl(gsi, GSI_CH_K_CNTXT_0_OFFS(channel_id));

	return (enum gsi_channel_state)field_val(val, CHSTATE_FMASK);
}

static enum gsi_evt_ring_state
gsi_evt_ring_state(struct gsi *gsi, u32 evt_ring_id)
{
	u32 val = gsi_readl(gsi, GSI_EV_CH_K_CNTXT_0_OFFS(evt_ring_id));

	return (enum gsi_evt_ring_state)field_val(val, EV_CHSTATE_FMASK);
}

static void gsi_handle_chan_ctrl(struct gsi *gsi)
{
	u32 valid_mask = GENMASK(gsi->channel_max - 1, 0);
	u32 channel_mask;

	channel_mask = gsi_readl(gsi, GSI_CNTXT_SRC_CH_IRQ_OFFS);
	gsi_writel(gsi, channel_mask, GSI_CNTXT_SRC_CH_IRQ_CLR_OFFS);

	ipa_debug("channel_mask %x\n", channel_mask);
	if (channel_mask & ~valid_mask) {
		ipa_err("invalid channels (> %u)\n", gsi->channel_max);
		channel_mask &= valid_mask;
	}

	while (channel_mask) {
		int i = __ffs(channel_mask);
		struct gsi_channel *channel = &gsi->channel[i];

		channel->state = gsi_channel_state(gsi, i);

		complete(&channel->compl);

		channel_mask ^= BIT(i);
	}
}

static void gsi_handle_evt_ctrl(struct gsi *gsi)
{
	u32 valid_mask = GENMASK(gsi->evt_ring_max - 1, 0);
	u32 evt_mask;

	evt_mask = gsi_readl(gsi, GSI_CNTXT_SRC_EV_CH_IRQ_OFFS);
	gsi_writel(gsi, evt_mask, GSI_CNTXT_SRC_EV_CH_IRQ_CLR_OFFS);

	ipa_debug("evt_mask %x\n", evt_mask);
	if (evt_mask & ~valid_mask) {
		ipa_err("invalid events (> %u)\n", gsi->evt_ring_max);
		evt_mask &= valid_mask;
	}

	while (evt_mask) {
		int i = __ffs(evt_mask);
		struct gsi_evt_ring *evt_ring = &gsi->evt_ring[i];

		evt_ring->state = gsi_evt_ring_state(gsi, i);

		complete(&evt_ring->compl);

		evt_mask ^= BIT(i);
	}
}

static void
handle_glob_chan_err(struct gsi *gsi, u32 err_ee, u32 channel_id, u32 code)
{
	struct gsi_channel *channel = &gsi->channel[channel_id];

	if (err_ee != IPA_EE_AP)
		ipa_bug_on(code != GSI_UNSUPPORTED_INTER_EE_OP_ERR);

	if (WARN_ON(channel_id >= gsi->channel_max)) {
		ipa_err("unexpected channel_id %u\n", channel_id);
		return;
	}

	switch (code) {
	case GSI_INVALID_TRE_ERR:
		ipa_err("got INVALID_TRE_ERR\n");
		channel->state = gsi_channel_state(gsi, channel_id);
		ipa_bug_on(channel->state != GSI_CHANNEL_STATE_ERROR);
		break;
	case GSI_OUT_OF_BUFFERS_ERR:
		ipa_err("got OUT_OF_BUFFERS_ERR\n");
		break;
	case GSI_OUT_OF_RESOURCES_ERR:
		ipa_err("got OUT_OF_RESOURCES_ERR\n");
		complete(&channel->compl);
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
	ipa_assert(channel->props.user_data);
}

static void
handle_glob_evt_err(struct gsi *gsi, u32 err_ee, u32 evt_ring_id, u32 code)
{
	struct gsi_evt_ring *evt_ring = &gsi->evt_ring[evt_ring_id];

	if (err_ee != IPA_EE_AP)
		ipa_bug_on(code != GSI_UNSUPPORTED_INTER_EE_OP_ERR);

	if (WARN_ON(evt_ring_id >= gsi->evt_ring_max)) {
		ipa_err("unexpected evt_ring_id %u\n", evt_ring_id);
		return;
	}

	switch (code) {
	case GSI_OUT_OF_BUFFERS_ERR:
		ipa_err("got OUT_OF_BUFFERS_ERR\n");
		break;
	case GSI_OUT_OF_RESOURCES_ERR:
		ipa_err("got OUT_OF_RESOURCES_ERR\n");
		complete(&evt_ring->compl);
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

static void ring_wp_local_inc(struct gsi_ring *ring)
{
	ring->wp_local += GSI_RING_ELEMENT_SIZE;
	if (ring->wp_local == ring->end)
		ring->wp_local = ring->mem.phys;
}

static void ring_rp_local_inc(struct gsi_ring *ring)
{
	ring->rp_local += GSI_RING_ELEMENT_SIZE;
	if (ring->rp_local == ring->end)
		ring->rp_local = ring->mem.phys;
}

static u16 ring_rp_local_index(struct gsi_ring *ring)
{
	return (u16)(ring->rp_local - ring->mem.phys) / GSI_RING_ELEMENT_SIZE;
}

static u16 ring_wp_local_index(struct gsi_ring *ring)
{
	return (u16)(ring->wp_local - ring->mem.phys) / GSI_RING_ELEMENT_SIZE;
}

static void channel_xfer_cb(struct gsi_channel *channel, u16 count)
{
	void *xfer_data;

	if (!channel->props.from_gsi) {
		u16 ring_rp_local = ring_rp_local_index(&channel->ring);

		xfer_data = channel->user_data[ring_rp_local];;
		ipa_gsi_irq_tx_notify_cb(xfer_data);
	} else {
		ipa_gsi_irq_rx_notify_cb(channel->props.user_data, count);
	}
}

static u16 gsi_process_channel(struct gsi *gsi, struct gsi_xfer_compl_evt *evt,
			       bool callback)
{
	struct gsi_channel *channel;
	u32 channel_id = (u32)evt->chid;

	ipa_assert(channel_id < gsi->channel_max);

	/* Event tells us the last completed channel ring element */
	channel = &gsi->channel[channel_id];
	channel->ring.rp_local = evt->xfer_ptr;

	if (callback) {
		if (evt->code == GSI_CHANNEL_EVT_EOT)
			channel_xfer_cb(channel, evt->len);
		else
			ipa_err("ch %u unexpected %sX event id %hhu\n",
				channel_id, channel->props.from_gsi ? "R" : "T",
				evt->code);
	}

	/* Record that we've processed this channel ring element. */
	ring_rp_local_inc(&channel->ring);
	channel->ring.rp = channel->ring.rp_local;

	return evt->len;
}

static void
gsi_evt_ring_doorbell(struct gsi *gsi, struct gsi_evt_ring *evt_ring)
{
	u32 val;

	/* The doorbell 0 and 1 registers store the low-order and
	 * high-order 32 bits of the event ring doorbell register,
	 * respectively.  LSB (doorbell 0) must be written last.
	 */
	val = evt_ring->ring.wp_local >> 32;
	gsi_writel(gsi, val, GSI_EV_CH_K_DOORBELL_1_OFFS(evt_ring->id));

	val = evt_ring->ring.wp_local & GENMASK(31, 0);
	gsi_writel(gsi, val, GSI_EV_CH_K_DOORBELL_0_OFFS(evt_ring->id));
}

static void gsi_channel_doorbell(struct gsi *gsi, struct gsi_channel *channel)
{
	u32 val;
	u8 channel_id = channel->props.channel_id;

	/* allocate new events for this channel first
	 * before submitting the new TREs.
	 * for TO_GSI channels the event ring doorbell is rang as part of
	 * interrupt handling.
	 */
	if (channel->props.from_gsi)
		gsi_evt_ring_doorbell(gsi, channel->evt_ring);
	channel->ring.wp = channel->ring.wp_local;

	/* The doorbell 0 and 1 registers store the low-order and
	 * high-order 32 bits of the channel ring doorbell register,
	 * respectively.  LSB (doorbell 0) must be written last.
	 */
	val = channel->ring.wp_local >> 32;
	gsi_writel(gsi, val, GSI_CH_K_DOORBELL_1_OFFS(channel_id));
	val = channel->ring.wp_local & GENMASK(31, 0);
	gsi_writel(gsi, val, GSI_CH_K_DOORBELL_0_OFFS(channel_id));
}

static void handle_event(struct gsi *gsi, u32 evt_ring_id)
{
	struct gsi_evt_ring *evt_ring = &gsi->evt_ring[evt_ring_id];
	unsigned long flags;
	bool check_again;

	spin_lock_irqsave(&evt_ring->ring.slock, flags);

	do {
		u32 val = gsi_readl(gsi, GSI_EV_CH_K_CNTXT_4_OFFS(evt_ring_id));

		evt_ring->ring.rp = evt_ring->ring.rp & GENMASK_ULL(63, 32);
		evt_ring->ring.rp |= val;

		check_again = false;
		while (evt_ring->ring.rp_local != evt_ring->ring.rp) {
			struct gsi_xfer_compl_evt *evt;

			if (atomic_read(&evt_ring->channel->poll_mode)) {
				check_again = false;
				break;
			}
			check_again = true;

			evt = ipa_dma_phys_to_virt(&evt_ring->ring.mem,
						   evt_ring->ring.rp_local);
			(void)gsi_process_channel(gsi, evt, true);

			ring_rp_local_inc(&evt_ring->ring);
			ring_wp_local_inc(&evt_ring->ring); /* recycle */
		}

		gsi_evt_ring_doorbell(gsi, evt_ring);
	} while (check_again);

	spin_unlock_irqrestore(&evt_ring->ring.slock, flags);
}

static void gsi_handle_ieob(struct gsi *gsi)
{
	u32 valid_mask = GENMASK(gsi->evt_ring_max - 1, 0);
	u32 evt_mask;

	evt_mask = gsi_readl(gsi, GSI_CNTXT_SRC_IEOB_IRQ_OFFS);
	evt_mask &= gsi_readl(gsi, GSI_CNTXT_SRC_IEOB_IRQ_MSK_OFFS);
	gsi_writel(gsi, evt_mask, GSI_CNTXT_SRC_IEOB_IRQ_CLR_OFFS);

	if (evt_mask & ~valid_mask) {
		ipa_err("invalid events (> %u)\n", gsi->evt_ring_max);
		evt_mask &= valid_mask;
	}

	while (evt_mask) {
		u32 i = (u32)__ffs(evt_mask);

		handle_event(gsi, i);

		evt_mask ^= BIT(i);
	}
}

static void gsi_handle_inter_ee_chan_ctrl(struct gsi *gsi)
{
	u32 valid_mask = GENMASK(gsi->channel_max - 1, 0);
	u32 channel_mask;

	channel_mask = gsi_readl(gsi, GSI_INTER_EE_SRC_CH_IRQ_OFFS);
	gsi_writel(gsi, channel_mask, GSI_INTER_EE_SRC_CH_IRQ_CLR_OFFS);

	if (channel_mask & ~valid_mask) {
		ipa_err("invalid channels (> %u)\n", gsi->channel_max);
		channel_mask &= valid_mask;
	}

	while (channel_mask) {
		int i = __ffs(channel_mask);

		/* not currently expected */
		ipa_err("ch %d was inter-EE changed\n", i);
		channel_mask ^= BIT(i);
	}
}

static void gsi_handle_inter_ee_evt_ctrl(struct gsi *gsi)
{
	u32 valid_mask = GENMASK(gsi->evt_ring_max - 1, 0);
	u32 evt_mask;

	evt_mask = gsi_readl(gsi, GSI_INTER_EE_SRC_EV_CH_IRQ_OFFS);
	gsi_writel(gsi, evt_mask, GSI_INTER_EE_SRC_EV_CH_IRQ_CLR_OFFS);

	if (evt_mask & ~valid_mask) {
		ipa_err("invalid events (> %u)\n", gsi->evt_ring_max);
		evt_mask &= valid_mask;
	}

	while (evt_mask) {
		u32 i = (u32)__ffs(evt_mask);

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

static u32 gsi_get_channel_max(struct gsi *gsi)
{
	u32 val = gsi_readl(gsi, GSI_GSI_HW_PARAM_2_OFFS);

	return field_val(val, NUM_CH_PER_EE_FMASK);
}

static u32 gsi_evt_ring_max(struct gsi *gsi)
{
	u32 val = gsi_readl(gsi, GSI_GSI_HW_PARAM_2_OFFS);

	return field_val(val, NUM_EV_PER_EE_FMASK);
}

/* Zero bits in an event bitmap represent event numbers available
 * for allocation.  Initialize the map so all events supported by
 * the hardware are available; then preclude any reserved events
 * from allocation.
 */
static u32 gsi_evt_bmap(u32 evt_ring_max)
{
	u32 evt_bmap = GENMASK(BITS_PER_LONG - 1, evt_ring_max);

	return evt_bmap | GENMASK(GSI_MHI_ER_END, GSI_MHI_ER_START);
}

/* gsi->mlock is assumed held by caller */
static u32 gsi_evt_bmap_alloc(struct gsi *gsi)
{
	u32 evt_ring_id;

	ipa_assert(gsi->evt_bmap != ~0UL);

	evt_ring_id = (u32)ffz(gsi->evt_bmap);
	gsi->evt_bmap |= BIT(evt_ring_id);

	return evt_ring_id;
}

/* gsi->mlock is assumed held by caller */
static void gsi_evt_bmap_free(struct gsi *gsi, u32 evt_ring_id)
{
	ipa_assert(gsi->evt_bmap & BIT(evt_ring_id));

	gsi->evt_bmap &= ~BIT(evt_ring_id);
}

int gsi_register_device(struct gsi *gsi)
{
	u32 val;
	u32 channel_max;
	u32 evt_ring_max;
	int ret;

	val = gsi_readl(gsi, GSI_GSI_STATUS_OFFS);
	if (!(val & ENABLED_FMASK)) {
		ipa_err("manager EE has not enabled GSI, GSI un-usable\n");
		return -EIO;
	}

	channel_max = gsi_get_channel_max(gsi);
	if (WARN_ON(channel_max > GSI_CHAN_MAX))
		return -EIO;

	evt_ring_max = gsi_evt_ring_max(gsi);
	if (WARN_ON(evt_ring_max > GSI_EVT_RING_MAX))
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
	gsi->channel_max = channel_max;
	gsi->evt_ring_max = evt_ring_max;
	gsi->evt_bmap = gsi_evt_bmap(evt_ring_max);

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
	ipa_assert(!atomic_read(&gsi->channel_count));
	ipa_assert(!atomic_read(&gsi->evt_ring_count));

	/* Don't bother clearing the error log again (ERROR_LOG) or
	 * setting the interrupt type again (INTSET).
	 */
	gsi_irq_disable_all(gsi);

	/* Clean up everything else set up by gsi_register_device() */
	gsi->evt_bmap = 0;
	gsi->evt_ring_max = 0;
	gsi->channel_max = 0;
	if (gsi->irq_wake_enabled) {
		(void)disable_irq_wake(gsi->irq);
		gsi->irq_wake_enabled = false;
	}
	free_irq(gsi->irq, gsi);
	gsi->irq = 0;
}

static void gsi_program_evt_ring_ctx(struct gsi *gsi, u32 evt_ring_id, u32 size,
				     u64 phys, u16 int_modt)
{
	u32 int_modc = 1;	/* moderation always comes from channel*/
	u32 val;

	ipa_debug("intf GPI intr IRQ RE size %u\n", GSI_RING_ELEMENT_SIZE);

	val = field_gen(GSI_EVT_CHTYPE_GPI_EV, EV_CHTYPE_FMASK);
	val |= field_gen(1, EV_INTYPE_FMASK);
	val |= field_gen(GSI_RING_ELEMENT_SIZE, EV_ELEMENT_SIZE_FMASK);
	gsi_writel(gsi, val, GSI_EV_CH_K_CNTXT_0_OFFS(evt_ring_id));

	val = field_gen(size, EV_R_LENGTH_FMASK);
	gsi_writel(gsi, val, GSI_EV_CH_K_CNTXT_1_OFFS(evt_ring_id));

	/* The context 2 and 3 registers store the low-order and
	 * high-order 32 bits of the address of the event ring,
	 * respectively.
	 */
	val = phys & GENMASK(31, 0);
	gsi_writel(gsi, val, GSI_EV_CH_K_CNTXT_2_OFFS(evt_ring_id));

	val = phys >> 32;
	gsi_writel(gsi, val, GSI_EV_CH_K_CNTXT_3_OFFS(evt_ring_id));

	val = field_gen(int_modt, MODT_FMASK);
	val |= field_gen(int_modc, MODC_FMASK);
	gsi_writel(gsi, val, GSI_EV_CH_K_CNTXT_8_OFFS(evt_ring_id));

	/* No MSI write data, and MSI address high and low address is 0 */
	gsi_writel(gsi, 0, GSI_EV_CH_K_CNTXT_9_OFFS(evt_ring_id));
	gsi_writel(gsi, 0, GSI_EV_CH_K_CNTXT_10_OFFS(evt_ring_id));
	gsi_writel(gsi, 0, GSI_EV_CH_K_CNTXT_11_OFFS(evt_ring_id));

	/* We don't need to get event read pointer updates */
	gsi_writel(gsi, 0, GSI_EV_CH_K_CNTXT_12_OFFS(evt_ring_id));
	gsi_writel(gsi, 0, GSI_EV_CH_K_CNTXT_13_OFFS(evt_ring_id));
}

static void gsi_init_ring(struct gsi_ring *ring, struct ipa_dma_mem *mem)
{
	spin_lock_init(&ring->slock);
	ring->mem = *mem;
	ring->wp = mem->phys;
	ring->rp = mem->phys;
	ring->wp_local = mem->phys;
	ring->rp_local = mem->phys;
	ring->end = mem->phys + mem->size;
}

static void gsi_prime_evt_ring(struct gsi *gsi, struct gsi_evt_ring *evt_ring)
{
	unsigned long flags;

	spin_lock_irqsave(&evt_ring->ring.slock, flags);
	memset(evt_ring->ring.mem.virt, 0, evt_ring->ring.mem.size);
	evt_ring->ring.wp_local = evt_ring->ring.end - GSI_RING_ELEMENT_SIZE;
	gsi_evt_ring_doorbell(gsi, evt_ring);
	spin_unlock_irqrestore(&evt_ring->ring.slock, flags);
}

/* Issue a GSI command by writing a value to a register, then wait
 * for completion to be signaled.  Returns true if successful or
 * false if a timeout occurred.  Note that the register offset is
 * first, value to write is second (reverse of writel() order).
 */
static bool command(struct gsi *gsi, u32 reg, u32 val, struct completion *compl)
{
	bool ret;

	gsi_writel(gsi, val, reg);
	ret = !!wait_for_completion_timeout(compl, GSI_CMD_TIMEOUT);
	if (!ret)
		ipa_err("command timeout\n");

	return ret;
}

/* Issue an event ring command and wait for it to complete */
static bool evt_ring_command(struct gsi *gsi, u32 evt_ring_id,
			     enum gsi_evt_ch_cmd_opcode op)
{
	struct completion *compl = &gsi->evt_ring[evt_ring_id].compl;
	u32 val;

	reinit_completion(compl);

	val = field_gen(evt_ring_id, EV_CHID_FMASK);
	val |= field_gen((u32)op, EV_OPCODE_FMASK);

	return command(gsi, GSI_EV_CH_CMD_OFFS, val, compl);
}

/* Issue a channel command and wait for it to complete */
static bool
channel_command(struct gsi *gsi, u32 channel_id, enum gsi_ch_cmd_opcode op)
{
	struct completion *compl = &gsi->channel[channel_id].compl;
	u32 val;

	reinit_completion(compl);

	val = field_gen(channel_id, CH_CHID_FMASK);
	val |= field_gen((u32)op, CH_OPCODE_FMASK);

	return command(gsi, GSI_CH_CMD_OFFS, val, compl);
}

/* Note: only GPI interfaces, IRQ interrupts are currently supported */
int gsi_alloc_evt_ring(struct gsi *gsi, u32 ring_count, u16 int_modt)
{
	u32 size = ring_count * GSI_RING_ELEMENT_SIZE;
	u32 evt_ring_id;
	struct gsi_evt_ring *evt_ring;
	unsigned long flags;
	u32 val;
	int ret;

	/* Get the mutex to allocate from the bitmap and issue a command */
	mutex_lock(&gsi->mlock);

	/* Start by allocating the event id to use */
	evt_ring_id = gsi_evt_bmap_alloc(gsi);
	evt_ring = &gsi->evt_ring[evt_ring_id];
	ipa_debug("Using %u as virt evt id\n", evt_ring_id);

	if (ipa_dma_alloc(&evt_ring->mem, size, GFP_KERNEL)) {
		ipa_err("fail to dma alloc %u bytes\n", size);
		ret = -ENOMEM;
		goto err_free_bmap;
	}
	ipa_assert(!(evt_ring->mem.phys % roundup_pow_of_two(size)));

	evt_ring->id = evt_ring_id;
	evt_ring->int_modt = int_modt;
	init_completion(&evt_ring->compl);
	atomic_set(&evt_ring->channel_ref_cnt, 0);

	if (!evt_ring_command(gsi, evt_ring_id, GSI_EVT_ALLOCATE)) {
		ret = -ETIMEDOUT;
		goto err_free_dma;
	}

	if (evt_ring->state != GSI_EVT_RING_STATE_ALLOCATED) {
		ipa_err("evt_ring_id %u allocation failed state %u\n",
			evt_ring_id, evt_ring->state);
		ret = -ENOMEM;
		goto err_free_dma;
	}
	atomic_inc(&gsi->evt_ring_count);

	gsi_program_evt_ring_ctx(gsi, evt_ring_id, evt_ring->mem.size,
				 evt_ring->mem.phys, evt_ring->int_modt);
	gsi_init_ring(&evt_ring->ring, &evt_ring->mem);

	gsi_prime_evt_ring(gsi, evt_ring);

	mutex_unlock(&gsi->mlock);

	spin_lock_irqsave(&gsi->slock, flags);

	/* Enable the event interrupt (clear it first in case pending) */
	val = BIT(evt_ring_id);
	gsi_writel(gsi, val, GSI_CNTXT_SRC_IEOB_IRQ_CLR_OFFS);
	gsi_irq_enable_event(gsi, evt_ring_id);

	spin_unlock_irqrestore(&gsi->slock, flags);

	return evt_ring_id;

err_free_dma:
	ipa_dma_free(&evt_ring->mem);
	memset(evt_ring, 0, sizeof(*evt_ring));
err_free_bmap:
	gsi_evt_bmap_free(gsi, evt_ring_id);

	mutex_unlock(&gsi->mlock);

	return ret;
}

static void __gsi_zero_evt_ring_scratch(struct gsi *gsi, u32 evt_ring_id)
{
	gsi_writel(gsi, 0, GSI_EV_CH_K_SCRATCH_0_OFFS(evt_ring_id));
	gsi_writel(gsi, 0, GSI_EV_CH_K_SCRATCH_1_OFFS(evt_ring_id));
}

void gsi_dealloc_evt_ring(struct gsi *gsi, u32 evt_ring_id)
{
	struct gsi_evt_ring *evt_ring = &gsi->evt_ring[evt_ring_id];
	bool completed;

	ipa_bug_on(atomic_read(&evt_ring->channel_ref_cnt));

	/* TODO: add check for ERROR state */
	ipa_bug_on(evt_ring->state != GSI_EVT_RING_STATE_ALLOCATED);

	mutex_lock(&gsi->mlock);

	completed = evt_ring_command(gsi, evt_ring_id, GSI_EVT_DE_ALLOC);
	ipa_bug_on(!completed);

	ipa_bug_on(evt_ring->state != GSI_EVT_RING_STATE_NOT_ALLOCATED);

	gsi_evt_bmap_free(gsi, evt_ring->id);

	mutex_unlock(&gsi->mlock);

	evt_ring->int_modt = 0;
	ipa_dma_free(&evt_ring->mem);
	memset(evt_ring, 0, sizeof(*evt_ring));

	atomic_dec(&gsi->evt_ring_count);
}

void gsi_reset_evt_ring(struct gsi *gsi, u32 evt_ring_id)
{
	struct gsi_evt_ring *evt_ring = &gsi->evt_ring[evt_ring_id];
	bool completed;

	ipa_bug_on(evt_ring->state != GSI_EVT_RING_STATE_ALLOCATED);

	mutex_lock(&gsi->mlock);

	completed = evt_ring_command(gsi, evt_ring_id, GSI_EVT_RESET);
	ipa_bug_on(!completed);

	ipa_bug_on(evt_ring->state != GSI_EVT_RING_STATE_ALLOCATED);

	gsi_program_evt_ring_ctx(gsi, evt_ring_id, evt_ring->mem.size,
				 evt_ring->mem.phys, evt_ring->int_modt);
	gsi_init_ring(&evt_ring->ring, &evt_ring->mem);

	__gsi_zero_evt_ring_scratch(gsi, evt_ring_id);

	gsi_prime_evt_ring(gsi, evt_ring);
	mutex_unlock(&gsi->mlock);
}

static void gsi_program_channel(struct gsi *gsi,
				struct gsi_channel_props *props,
				u32 evt_ring_id)
{
	u32 val;

	val = field_gen(GSI_CHANNEL_PROTOCOL_GPI, CHTYPE_PROTOCOL_FMASK);
	val |= field_gen(props->from_gsi ? 0 : 1, CHTYPE_DIR_FMASK);
	val |= field_gen(evt_ring_id, ERINDEX_FMASK);
	val |= field_gen(GSI_RING_ELEMENT_SIZE, ELEMENT_SIZE_FMASK);
	gsi_writel(gsi, val, GSI_CH_K_CNTXT_0_OFFS(props->channel_id));

	val = field_gen(props->mem.size, R_LENGTH_FMASK);
	gsi_writel(gsi, val, GSI_CH_K_CNTXT_1_OFFS(props->channel_id));

	/* The context 2 and 3 registers store the low-order and
	 * high-order 32 bits of the address of the channel ring,
	 * respectively.
	 */
	val = props->mem.phys & GENMASK(31, 0);
	gsi_writel(gsi, val, GSI_CH_K_CNTXT_2_OFFS(props->channel_id));

	val = props->mem.phys >> 32;
	gsi_writel(gsi, val, GSI_CH_K_CNTXT_3_OFFS(props->channel_id));

	val = field_gen(props->low_weight, WRR_WEIGHT_FMASK);
	val |= field_gen(GSI_MAX_PREFETCH, MAX_PREFETCH_FMASK);
	val |= field_gen(props->use_db_engine ? 1 : 0, USE_DB_ENG_FMASK);
	gsi_writel(gsi, val, GSI_CH_K_QOS_OFFS(props->channel_id));
}

int gsi_alloc_channel(struct gsi *gsi, struct gsi_channel_props *props)
{
	u32 size = props->ring_count * GSI_RING_ELEMENT_SIZE;
	u32 evt_ring_id = props->evt_ring_id;
	struct gsi_evt_ring *evt_ring = &gsi->evt_ring[evt_ring_id];
	int channel_id = (int)props->channel_id;
	struct gsi_channel *channel = &gsi->channel[channel_id];
	void **user_data;

	if (ipa_dma_alloc(&props->mem, size, GFP_KERNEL)) {
		ipa_err("fail to dma alloc %u bytes\n", size);
		return -ENOMEM;
	}
	ipa_assert(!(props->mem.size % roundup_pow_of_two(size)));
	ipa_assert(!(props->mem.phys % roundup_pow_of_two(size)));

	if (atomic_read(&evt_ring->channel_ref_cnt)) {
		ipa_err("evt ring %u in use\n", evt_ring_id);
		ipa_dma_free(&props->mem);
		return -ENOTSUPP;
	}

	if (channel->allocated) {
		ipa_err("channel %d already allocated\n", channel_id);
		ipa_dma_free(&props->mem);
		return -ENODEV;
	}
	memset(channel, 0, sizeof(*channel));

	user_data = kcalloc(props->ring_count, sizeof(void *), GFP_KERNEL);
	if (!user_data) {
		ipa_dma_free(&props->mem);
		return -ENOMEM;
	}

	mutex_init(&channel->mlock);
	init_completion(&channel->compl);
	atomic_set(&channel->poll_mode, 0);	/* Initially in callback mode */
	channel->props = *props;

	mutex_lock(&gsi->mlock);

	if (!channel_command(gsi, (u32)channel_id, GSI_CH_ALLOCATE)) {
		channel_id = -ETIMEDOUT;
		goto err_mutex_unlock;
	}
	if (channel->state != GSI_CHANNEL_STATE_ALLOCATED) {
		ipa_err("channel_id %d allocation failed state %d\n",
			channel_id, channel->state);
		channel_id = -ENOMEM;
		goto err_mutex_unlock;
	}

	gsi->ch_dbg[channel_id].ch_allocate++;

	mutex_unlock(&gsi->mlock);

	channel->evt_ring = evt_ring;
	atomic_inc(&evt_ring->channel_ref_cnt);
	evt_ring->channel = channel;

	gsi_program_channel(gsi, props, evt_ring_id);
	gsi_init_ring(&channel->ring, &props->mem);

	channel->user_data = user_data;
	channel->allocated = true;
	atomic_inc(&gsi->channel_count);

	return channel_id;

err_mutex_unlock:
	mutex_unlock(&gsi->mlock);
	kfree(user_data);
	ipa_dma_free(&channel->props.mem);

	return channel_id;
}

static void __gsi_write_channel_scratch(struct gsi *gsi, u32 channel_id)
{
	struct gsi_channel *channel = &gsi->channel[channel_id];
	union gsi_channel_scratch scr = { };
	struct gsi_gpi_channel_scratch *gpi = &scr.gpi;
	u32 val;

	/* See comments above definition of gsi_gpi_channel_scratch */
	gpi->max_outstanding_tre = channel->tlv_size * GSI_RING_ELEMENT_SIZE;
	gpi->outstanding_threshold = 2 * GSI_RING_ELEMENT_SIZE;

	val = scr.data.word1;
	gsi_writel(gsi, val, GSI_CH_K_SCRATCH_0_OFFS(channel_id));

	val = scr.data.word2;
	gsi_writel(gsi, val, GSI_CH_K_SCRATCH_1_OFFS(channel_id));

	val = scr.data.word3;
	gsi_writel(gsi, val, GSI_CH_K_SCRATCH_2_OFFS(channel_id));

	/* We must preserve the upper 16 bits of the last scratch
	 * register.  The next sequence assumes those bits remain
	 * unchanged between the read and the write.
	 */
	val = gsi_readl(gsi, GSI_CH_K_SCRATCH_3_OFFS(channel_id));
	val = (scr.data.word4 & GENMASK(31, 16)) | (val & GENMASK(15, 0));
	gsi_writel(gsi, val, GSI_CH_K_SCRATCH_3_OFFS(channel_id));
}

void gsi_write_channel_scratch(struct gsi *gsi, u32 channel_id, u32 tlv_size)
{
	struct gsi_channel *channel = &gsi->channel[channel_id];

	channel->tlv_size = tlv_size;

	mutex_lock(&channel->mlock);

	__gsi_write_channel_scratch(gsi, channel_id);

	mutex_unlock(&channel->mlock);
}

int gsi_start_channel(struct gsi *gsi, u32 channel_id)
{
	struct gsi_channel *channel = &gsi->channel[channel_id];

	if (channel->state != GSI_CHANNEL_STATE_ALLOCATED &&
	    channel->state != GSI_CHANNEL_STATE_STOP_IN_PROC &&
	    channel->state != GSI_CHANNEL_STATE_STOPPED) {
		ipa_err("bad state %d\n", channel->state);
		return -ENOTSUPP;
	}

	mutex_lock(&gsi->mlock);

	gsi->ch_dbg[channel_id].ch_start++;

	if (!channel_command(gsi, channel_id, GSI_CH_START)) {
		mutex_unlock(&gsi->mlock);
		return -ETIMEDOUT;
	}
	if (channel->state != GSI_CHANNEL_STATE_STARTED) {
		ipa_err("channel %u unexpected state %u\n", channel_id,
			channel->state);
		ipa_bug();
	}

	mutex_unlock(&gsi->mlock);

	return 0;
}

int gsi_stop_channel(struct gsi *gsi, u32 channel_id)
{
	struct gsi_channel *channel = &gsi->channel[channel_id];
	int ret;

	if (channel->state == GSI_CHANNEL_STATE_STOPPED) {
		ipa_debug("channel_id %u already stopped\n", channel_id);
		return 0;
	}

	if (channel->state != GSI_CHANNEL_STATE_STARTED &&
	    channel->state != GSI_CHANNEL_STATE_STOP_IN_PROC &&
	    channel->state != GSI_CHANNEL_STATE_ERROR) {
		ipa_err("bad state %d\n", channel->state);
		return -ENOTSUPP;
	}

	mutex_lock(&gsi->mlock);

	gsi->ch_dbg[channel_id].ch_stop++;

	if (!channel_command(gsi, channel_id, GSI_CH_STOP)) {
		/* check channel state here in case the channel is stopped but
		 * the interrupt was not handled yet.
		 */
		channel->state = gsi_channel_state(gsi, channel_id);
		if (channel->state == GSI_CHANNEL_STATE_STOPPED) {
			ret = 0;
			goto free_lock;
		}
		ret = -ETIMEDOUT;
		goto free_lock;
	}

	if (channel->state != GSI_CHANNEL_STATE_STOPPED &&
	    channel->state != GSI_CHANNEL_STATE_STOP_IN_PROC) {
		ipa_err("channel %u unexpected state %u\n", channel_id,
			channel->state);
		ret = -EBUSY;
		goto free_lock;
	}

	if (channel->state == GSI_CHANNEL_STATE_STOP_IN_PROC) {
		ipa_err("channel %u busy try again\n", channel_id);
		ret = -EAGAIN;
		goto free_lock;
	}

	ret = 0;

free_lock:
	mutex_unlock(&gsi->mlock);

	return ret;
}

int gsi_reset_channel(struct gsi *gsi, u32 channel_id)
{
	struct gsi_channel *channel = &gsi->channel[channel_id];
	bool reset_done = false;

	if (channel->state != GSI_CHANNEL_STATE_STOPPED) {
		ipa_err("bad state %d\n", channel->state);
		return -ENOTSUPP;
	}

	mutex_lock(&gsi->mlock);
reset:

	gsi->ch_dbg[channel_id].ch_reset++;

	if (!channel_command(gsi, channel_id, GSI_CH_RESET)) {
		mutex_unlock(&gsi->mlock);
		return -ETIMEDOUT;
	}

	if (channel->state != GSI_CHANNEL_STATE_ALLOCATED) {
		ipa_err("channel_id %u unexpected state %u\n", channel_id,
			channel->state);
		ipa_bug();
	}

	/* workaround: reset GSI producers again */
	if (channel->props.from_gsi && !reset_done) {
		usleep_range(GSI_RESET_WA_MIN_SLEEP, GSI_RESET_WA_MAX_SLEEP);
		reset_done = true;
		goto reset;
	}

	gsi_program_channel(gsi, &channel->props, channel->evt_ring->id);
	gsi_init_ring(&channel->ring, &channel->props.mem);

	/* restore scratch */
	__gsi_write_channel_scratch(gsi, channel_id);

	mutex_unlock(&gsi->mlock);

	return 0;
}

void gsi_dealloc_channel(struct gsi *gsi, u32 channel_id)
{
	struct gsi_channel *channel = &gsi->channel[channel_id];
	bool completed;

	ipa_bug_on(channel->state != GSI_CHANNEL_STATE_ALLOCATED);

	mutex_lock(&gsi->mlock);

	gsi->ch_dbg[channel_id].ch_de_alloc++;

	completed = channel_command(gsi, channel_id, GSI_CH_DE_ALLOC);
	ipa_bug_on(!completed);

	ipa_bug_on(channel->state != GSI_CHANNEL_STATE_NOT_ALLOCATED);

	mutex_unlock(&gsi->mlock);

	kfree(channel->user_data);
	ipa_dma_free(&channel->props.mem);
	channel->allocated = false;
	atomic_dec(&channel->evt_ring->channel_ref_cnt);
	atomic_dec(&gsi->channel_count);
}

static u16 __gsi_query_ring_free_re(struct gsi_ring *ring)
{
	u64 delta;

	if (ring->wp_local < ring->rp_local)
		delta = ring->rp_local - ring->wp_local;
	else
		delta = ring->end - ring->wp_local + ring->rp_local;

	return (u16)(delta / GSI_RING_ELEMENT_SIZE - 1);
}

bool gsi_is_channel_empty(struct gsi *gsi, u32 channel_id)
{
	struct gsi_channel *channel = &gsi->channel[channel_id];
	unsigned long flags;
	bool empty;
	u32 val;

	spin_lock_irqsave(&channel->evt_ring->ring.slock, flags);

	val = gsi_readl(gsi, GSI_CH_K_CNTXT_4_OFFS(channel->props.channel_id));
	channel->ring.rp = (channel->ring.rp & GENMASK_ULL(63, 32)) | val;

	val = gsi_readl(gsi, GSI_CH_K_CNTXT_6_OFFS(channel->props.channel_id));
	channel->ring.wp = (channel->ring.wp & GENMASK_ULL(63, 32)) | val;

	if (channel->props.from_gsi)
		empty = channel->ring.rp_local == channel->ring.rp;
	else
		empty = channel->ring.wp == channel->ring.rp;

	spin_unlock_irqrestore(&channel->evt_ring->ring.slock, flags);

	ipa_debug("channel_id %u RP 0x%llx WP 0x%llx RP_LOCAL 0x%llx\n",
		  channel_id, channel->ring.rp, channel->ring.wp,
		  channel->ring.rp_local);

	return empty;
}

int gsi_queue_xfer(struct gsi *gsi, u32 channel_id, u16 num_xfers,
		   struct gsi_xfer_elem *xfer, bool ring_db)
{
	struct gsi_channel *channel = &gsi->channel[channel_id];
	unsigned long flags;
	u32 i;

	spin_lock_irqsave(&channel->evt_ring->ring.slock, flags);

	if (num_xfers > __gsi_query_ring_free_re(&channel->ring)) {
		spin_unlock_irqrestore(&channel->evt_ring->ring.slock, flags);
		ipa_err("no space for %u-element transfer on ch %u\n",
			num_xfers, channel_id);

		return -ENOSPC;
	}

	for (i = 0; i < num_xfers; i++) {
		struct gsi_tre *tre_ptr;
		u16 idx = ring_wp_local_index(&channel->ring);

		channel->user_data[idx] = xfer[i].user_data;

		tre_ptr = ipa_dma_phys_to_virt(&channel->ring.mem,
						  channel->ring.wp_local);

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

		ring_wp_local_inc(&channel->ring);
	}

	wmb();	/* Ensure TRE is set before ringing doorbell */

	if (ring_db)
		gsi_channel_doorbell(gsi, channel);

	spin_unlock_irqrestore(&channel->evt_ring->ring.slock, flags);

	return 0;
}

int gsi_start_xfer(struct gsi *gsi, u32 channel_id)
{
	struct gsi_channel *channel = &gsi->channel[channel_id];

	if (channel->state != GSI_CHANNEL_STATE_STARTED) {
		ipa_err("bad state %d\n", channel->state);
		return -ENOTSUPP;
	}

	if (channel->ring.wp == channel->ring.wp_local)
		return 0;

	gsi_channel_doorbell(gsi, channel);

	return 0;
}

int gsi_poll_channel(struct gsi *gsi, u32 channel_id)
{
	struct gsi_channel *channel = &gsi->channel[channel_id];
	struct gsi_evt_ring *evt_ring = channel->evt_ring;
	unsigned long flags;
	int size;

	spin_lock_irqsave(&evt_ring->ring.slock, flags);

	/* update rp to see of we have anything new to process */
	if (evt_ring->ring.rp == evt_ring->ring.rp_local) {
		u32 val;

		val = gsi_readl(gsi, GSI_EV_CH_K_CNTXT_4_OFFS(evt_ring->id));
		evt_ring->ring.rp = channel->ring.rp & GENMASK_ULL(63, 32);
		evt_ring->ring.rp |= val;
	}

	if (evt_ring->ring.rp != evt_ring->ring.rp_local) {
		struct gsi_xfer_compl_evt *evt;

		evt = ipa_dma_phys_to_virt(&evt_ring->ring.mem,
					   evt_ring->ring.rp_local);
		size = gsi_process_channel(gsi, evt, false);

		ring_rp_local_inc(&evt_ring->ring);
		ring_wp_local_inc(&evt_ring->ring); /* recycle element */
	} else {
		size = -ENOENT;
	}

	spin_unlock_irqrestore(&evt_ring->ring.slock, flags);

	return size;
}

static void
gsi_config_channel_mode(struct gsi *gsi, u32 channel_id, bool polling)
{
	struct gsi_channel *channel = &gsi->channel[channel_id];
	unsigned long flags;

	spin_lock_irqsave(&gsi->slock, flags);
	if (polling)
		gsi_irq_disable_event(gsi, channel->evt_ring->id);
	else
		gsi_irq_enable_event(gsi, channel->evt_ring->id);
	atomic_set(&channel->poll_mode, polling ? 1 : 0);
	spin_unlock_irqrestore(&gsi->slock, flags);
}

void gsi_channel_intr_enable(struct gsi *gsi, u32 channel_id)
{
	gsi_config_channel_mode(gsi, channel_id, false);
}

void gsi_channel_intr_disable(struct gsi *gsi, u32 channel_id)
{
	gsi_config_channel_mode(gsi, channel_id, true);
}

int gsi_get_channel_cfg(struct gsi *gsi, u32 channel_id,
			struct gsi_channel_props *props)
{
	struct gsi_channel *channel = &gsi->channel[channel_id];

	if (channel->state == GSI_CHANNEL_STATE_NOT_ALLOCATED) {
		ipa_err("bad state %d\n", channel->state);
		return -ENOTSUPP;
	}

	mutex_lock(&channel->mlock);
	*props = channel->props;
	mutex_unlock(&channel->mlock);

	return 0;
}

int gsi_set_channel_cfg(struct gsi *gsi, u32 channel_id,
		        struct gsi_channel_props *props)
{
	struct gsi_channel *channel = &gsi->channel[channel_id];

	if (channel->state != GSI_CHANNEL_STATE_ALLOCATED) {
		ipa_err("bad state %d\n", channel->state);
		return -ENOTSUPP;
	}

	if (channel->props.channel_id != props->channel_id ||
	    channel->props.evt_ring_id != props->evt_ring_id) {
		ipa_err("changing immutable fields not supported\n");
		return -ENOTSUPP;
	}

	mutex_lock(&channel->mlock);
	channel->props = *props;

	gsi_program_channel(gsi, &channel->props, channel->evt_ring->id);
	gsi_init_ring(&channel->ring, &channel->props.mem);

	/* restore scratch */
	__gsi_write_channel_scratch(gsi, channel_id);
	mutex_unlock(&channel->mlock);

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
	atomic_set(&gsi->channel_count, 0);
	atomic_set(&gsi->evt_ring_count, 0);

	return gsi;
}
