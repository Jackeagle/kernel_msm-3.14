// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */

#include <linux/types.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/netdevice.h>

#include "ipa_i.h"	/* ipa_err() */
#include "ipa_clock.h"
#include "ipahal.h"

/**
 * DOC:  The IPA Data Path
 *
 * The IPA is used to transmit data between execution environments.
 * The data path code uses functions and structures supplied by the
 * GSI to interact with the IPA hardware.  A packet to be transmitted
 * or received is held in a socket buffer.  Each has a "wrapper"
 * structure associated with it.  A GSI transfer request refers to
 * the packet wrapper, and when queued to the hardware the packet
 * wrapper is added to a list of outstanding requests for an endpoint
 * (maintained in the head_desc_list in the endpoint's system context).
 * When the GSI transfer completes, a callback function is provided
 * the packet wrapper pointer, allowing it to be released after the
 * received socket buffer has been passed up the stack, or a buffer
 * whose data has been transmitted has been freed.
 *
 * Producer (PROD) endpoints are used to send data from the AP toward
 * the IPA.  The common function for sending data on producer endpoints
 * is ipa_send().  It takes a system context and an array of IPA
 * descriptors as arguments.  Each descriptor is given a TX packet
 * wrapper, and its content is translated into an equivalent GSI
 * transfer element  structure after its memory address is mapped for
 * DMA.  The GSI transfer element array is finally passed to the GSI
 * layer using gsi_channel_queue().
 *
 * The code provides a "no_intr" feature, allowing endpoints to have
 * their transmit completions not produce an interrupt.  (This
 * behavior is used only for the modem producer.)  In this case, a
 * no-op request is generated every 200 milliseconds while transmit
 * requests are outstanding.  The no-op will generate an interrupt
 * when it's complete, and its completion implies the completion of
 * all transmit requests issued before it.  The GSI will call
 * ipa_gsi_irq_tx_notify_cb() in response to interrupts on a producer
 * endpoint.
 *
 * Receive buffers are passed to consumer (CONS) channels to be
 * available to hold incoming data.  Arriving data is placed
 * in these buffers, leading to events being generated on the event
 * ring assciated with a channel.  When an interrupt occurs on a
 * consumer endpoint, the GSI layer calls ipa_gsi_irq_rx_notify_cb().
 * This causes the endpoint to switch to polling mode.  The
 * completion of a receive also leads to ipa_replenish_rx_cache()
 * being called, to replace the consumed buffer.
 *
 * Consumer enpoints optionally use NAPI (only the modem consumer,
 * WWAN_CONS, does currently).  An atomic variable records whether
 * the endpoint is in polling mode or not.  This is needed because
 * switching to polling mode is currently done in a workqueue.  Once
 * NAPI polling completes, and endpoint switches back to interrupt
 * mode.
 */

/**
 * struct ipa_tx_pkt_wrapper - IPA transmit packet wrapper
 * @type:	type of descriptor
 * @sys:	Corresponding IPA sys context
 * @mem:	Memory buffer used by this packet
 * @callback:	IPA client provided callback
 * @user1:	Cookie1 for above callback
 * @user2:	Cookie2 for above callback
 * @link:	Links for the endpoint's sys->head_desc_list
 * @cnt:	Number of descriptors in request
 * @done_work:	Work structure used when complete
 */
struct ipa_tx_pkt_wrapper {
	enum ipa_desc_type type;
	struct ipa_sys_context *sys;
	void *virt;
	dma_addr_t phys;
	size_t size;
	void (*callback)(void *user1, int user2);
	void *user1;
	int user2;
	struct list_head link;
	u32 cnt;
	struct work_struct done_work;
};

/** struct ipa_rx_pkt_wrapper - IPA Rx packet wrapper
 * @link:	Links for the endpoint's sys->head_desc_list
 * @skb:	Socket buffer containing the received packet
 * @len:	How many bytes are copied into skb's buffer
 */
struct ipa_rx_pkt_wrapper {
	struct list_head link;
	struct sk_buff *skb;
	dma_addr_t dma_addr;
};

/** struct ipa_sys_context - IPA GPI endpoint context
 * @len:	The number of entries in @head_desc_list
 * @tx:		Details related to AP->IPA endpoints
 * @rx:		Details related to IPA->AP endpoints
 * @ep:		Associated endpoint
 * @head_desc_list: List of packets
 * @spinlock:	Lock protecting the descriptor list
 * @workqueue:	Workqueue used for this endpoint
 */
struct ipa_sys_context {
	u32 len;
	union {
		struct {	/* Consumer endpoints only */
			u32 len_pending_xfer;
			atomic_t curr_polling_state;
			struct delayed_work switch_to_intr_work; /* sys->wq */
			void (*pyld_hdlr)(struct sk_buff *,
					  struct ipa_sys_context *);
			u32 buff_sz;
			u32 pool_sz;
			struct sk_buff *prev_skb;
			unsigned int len_rem;
			unsigned int len_pad;		/* APPS_LAN only */
			unsigned int len_partial;	/* APPS_LAN only */
			bool drop_packet;		/* APPS_LAN only */

			struct work_struct work; /* sys->wq */
			struct delayed_work replenish_work; /* sys->wq */
		} rx;
		struct {	/* Producer endpoints only */
			/* no_intr/nop is APPS_WAN_PROD only */
			bool no_intr;
			atomic_t nop_pending;
			struct hrtimer nop_timer;
			struct work_struct nop_work; /* sys->wq */
		} tx;
	};

	/* ordering is important - mutable fields go above */
	struct ipa_ep_context *ep;
	struct list_head head_desc_list; /* contains len entries */
	spinlock_t spinlock;		/* protects head_desc list */
	struct workqueue_struct *wq;
	/* ordering is important - other immutable fields go below */
};

/**
 * struct ipa_tag_completion - Reference counted completion object
 * @comp:	Completion when last reference is dropped
 * @cnt:	Reference count
 */
struct ipa_tag_completion {
	struct completion comp;
	atomic_t cnt;
};

#define CHANNEL_RESET_AGGR_RETRY_COUNT	3
#define CHANNEL_RESET_DELAY		1	/* milliseconds */

#define IPA_QMAP_HEADER_LENGTH		4

#define IPA_WAN_AGGR_PKT_CNT		5
#define POLLING_INACTIVITY_RX		40
#define POLLING_MIN_SLEEP_RX		1010	/* microseconds */
#define POLLING_MAX_SLEEP_RX		1050	/* microseconds */

#define IPA_RX_BUFFER_ORDER	1	/* Default RX buffer is 2^1 pages */
#define IPA_RX_BUFFER_SIZE	(1 << (IPA_RX_BUFFER_ORDER + PAGE_SHIFT))

/* The amount of RX buffer space consumed by standard skb overhead */
#define IPA_RX_BUFFER_RESERVED \
	(IPA_RX_BUFFER_SIZE - SKB_MAX_ORDER(NET_SKB_PAD, IPA_RX_BUFFER_ORDER))

/* RX buffer space remaining after standard overhead is consumed */
#define IPA_RX_BUFFER_AVAILABLE(X)	((X) - IPA_RX_BUFFER_RESERVED)

#define IPA_RX_BUFF_CLIENT_HEADROOM	256

#define IPA_SIZE_DL_CSUM_META_TRAILER	8

#define IPA_REPL_XFER_THRESH		10

/* How long before sending an interrupting no-op to handle TX completions */
#define IPA_TX_NOP_DELAY_NS		(2 * 1000 * 1000)	/* 2 msec */

static void ipa_rx_switch_to_intr_mode(struct ipa_sys_context *sys);

static void ipa_replenish_rx_cache(struct ipa_sys_context *sys);
static void ipa_replenish_rx_work_func(struct work_struct *work);
static void ipa_wq_handle_rx(struct work_struct *work);
static void ipa_rx_common(struct ipa_sys_context *sys, u32 size);
static void ipa_cleanup_rx(struct ipa_sys_context *sys);
static int ipa_poll_gsi_pkt(struct ipa_sys_context *sys);

static void ipa_tx_complete(struct ipa_tx_pkt_wrapper *tx_pkt)
{
	struct device *dev = &ipa_ctx->pdev->dev;

	/* If DMA memory was mapped, unmap it */
	if (tx_pkt->virt) {
		if (tx_pkt->type == IPA_DATA_DESC_SKB_PAGED)
			dma_unmap_page(dev, tx_pkt->phys, tx_pkt->size,
				       DMA_TO_DEVICE);
		else
			dma_unmap_single(dev, tx_pkt->phys, tx_pkt->size,
					 DMA_TO_DEVICE);
	}

	if (tx_pkt->callback)
		tx_pkt->callback(tx_pkt->user1, tx_pkt->user2);

	kmem_cache_free(ipa_ctx->tx_pkt_wrapper_cache, tx_pkt);
}

static void
ipa_wq_write_done_common(struct ipa_sys_context *sys,
			 struct ipa_tx_pkt_wrapper *tx_pkt)
{
	struct ipa_tx_pkt_wrapper *next_pkt;
	int cnt;
	int i;

	cnt = tx_pkt->cnt;
	for (i = 0; i < cnt; i++) {
		ipa_assert(!list_empty(&sys->head_desc_list));

		spin_lock_bh(&sys->spinlock);

		next_pkt = list_next_entry(tx_pkt, link);
		list_del(&tx_pkt->link);
		sys->len--;

		spin_unlock_bh(&sys->spinlock);

		ipa_tx_complete(tx_pkt);

		tx_pkt = next_pkt;
	}
}

/**
 * ipa_wq_write_done() - Work function executed when TX completes
 * * @done_work:	work_struct used by the work queue
 */
static void ipa_wq_write_done(struct work_struct *done_work)
{
	struct ipa_tx_pkt_wrapper *this_pkt;
	struct ipa_tx_pkt_wrapper *tx_pkt;
	struct ipa_sys_context *sys;

	tx_pkt = container_of(done_work, struct ipa_tx_pkt_wrapper, done_work);
	sys = tx_pkt->sys;
	spin_lock_bh(&sys->spinlock);
	this_pkt = list_first_entry(&sys->head_desc_list,
				    struct ipa_tx_pkt_wrapper, link);
	while (tx_pkt != this_pkt) {
		spin_unlock_bh(&sys->spinlock);
		ipa_wq_write_done_common(sys, this_pkt);
		spin_lock_bh(&sys->spinlock);
		this_pkt = list_first_entry(&sys->head_desc_list,
					    struct ipa_tx_pkt_wrapper, link);
	}
	spin_unlock_bh(&sys->spinlock);
	ipa_wq_write_done_common(sys, tx_pkt);
}

/**
 * ipa_rx_poll() - Poll the rx packets from IPA hardware
 * @ep_id:	Endpoint to poll
 * @weight:	NAPI poll weight
 *
 * Return:	The number of received packets.
 */
int ipa_rx_poll(u32 ep_id, int weight)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ep_id];
	static int total_cnt;
	int cnt = 0;

	while (cnt < weight && ipa_ep_polling(ep)) {
		int ret;

		ret = ipa_poll_gsi_pkt(ep->sys);
		if (ret < 0)
			break;

		ipa_rx_common(ep->sys, (u32)ret);
		cnt += IPA_WAN_AGGR_PKT_CNT;
		total_cnt++;

		/* Force switch back to interrupt mode if no more packets */
		if (!ep->sys->len || total_cnt >= ep->sys->rx.pool_sz) {
			total_cnt = 0;
			cnt--;
			break;
		}
	}

	if (cnt < weight) {
		ep->client_notify(ep->priv, IPA_CLIENT_COMP_NAPI, 0);
		ipa_rx_switch_to_intr_mode(ep->sys);

		/* Matching enable is in ipa_gsi_irq_rx_notify_cb() */
		ipa_clock_put(ipa_ctx);
	}

	return cnt;
}

/**
 * ipa_send_nop() - Send an interrupting no-op request to a producer endpoint.
 * @sys:	System context for the endpoint
 *
 * Normally an interrupt is generated upon completion of every transfer
 * performed by an endpoint, but a producer endpoint can be configured
 * to avoid getting these interrupts.  Instead, once a transfer has been
 * initiated, a no-op is scheduled to be sent after a short delay.  This
 * no-op request will interrupt when it is complete, and in handling that
 * interrupt, previously-completed transfers will be handled as well.  If
 * a no-op is already scheduled, another is not initiated (there's only
 * one pending at a time).
 */
static bool ipa_send_nop(struct ipa_sys_context *sys)
{
	struct gsi_xfer_elem nop_xfer = { };
	struct ipa_tx_pkt_wrapper *nop_pkt;
	u32 channel_id;

	nop_pkt = kmem_cache_zalloc(ipa_ctx->tx_pkt_wrapper_cache,
				    GFP_KERNEL);
	if (!nop_pkt)
		return false;

	nop_pkt->type = IPA_DATA_DESC;
	/* No-op packet uses no memory for data */
	INIT_WORK(&nop_pkt->done_work, ipa_wq_write_done);
	nop_pkt->sys = sys;
	nop_pkt->cnt = 1;

	nop_xfer.type = GSI_XFER_ELEM_NOP;
	nop_xfer.flags = GSI_XFER_FLAG_EOT;
	nop_xfer.user_data = nop_pkt;

	spin_lock_bh(&sys->spinlock);
	list_add_tail(&nop_pkt->link, &sys->head_desc_list);
	spin_unlock_bh(&sys->spinlock);

	channel_id = sys->ep->channel_id;
	if (!gsi_channel_queue(ipa_ctx->gsi, channel_id, 1, &nop_xfer, true))
		return true;	/* Success */

	spin_lock_bh(&sys->spinlock);
	list_del(&nop_pkt->link);
	spin_unlock_bh(&sys->spinlock);

	kmem_cache_free(ipa_ctx->tx_pkt_wrapper_cache, nop_pkt);

	return false;
}

/**
 * ipa_send_nop_work() - Work function for sending a no-op request
 * nop_work:	Work structure for the request
 *
 * Try to send the no-op request.  If it fails, arrange to try again.
 */
static void ipa_send_nop_work(struct work_struct *nop_work)
{
	struct ipa_sys_context *sys;

	sys = container_of(nop_work, struct ipa_sys_context, tx.nop_work);

	/* If sending a no-op request fails, schedule another try */
	if (!ipa_send_nop(sys))
		queue_work(sys->wq, nop_work);
}

/**
 * ipa_nop_timer_expiry() - Timer function to schedule a no-op request
 * @timer:	High-resolution timer structure
 *
 * The delay before sending the no-op request is implemented by a
 * high resolution timer, which will call this in interrupt context.
 * Arrange to send the no-op in workqueue context when it expires.
 */
static enum hrtimer_restart ipa_nop_timer_expiry(struct hrtimer *timer)
{
	struct ipa_sys_context *sys;

	sys = container_of(timer, struct ipa_sys_context, tx.nop_timer);
	atomic_set(&sys->tx.nop_pending, 0);
	queue_work(sys->wq, &sys->tx.nop_work);

	return HRTIMER_NORESTART;
}

static void ipa_nop_timer_schedule(struct ipa_sys_context *sys)
{
	ktime_t time;

	if (atomic_xchg(&sys->tx.nop_pending, 1))
		return;

	time = ktime_set(0, IPA_TX_NOP_DELAY_NS);
	hrtimer_start(&sys->tx.nop_timer, time, HRTIMER_MODE_REL);
}

/**
 * ipa_no_intr_init() - Configure endpoint point for no-op requests
 * @prod_ep_id:	Endpoint that will use interrupting no-ops
 *
 * For some producer endpoints we don't interrupt on completions.
 * Instead we schedule an interrupting NOP command to be issued on
 * the endpoint after a short delay (if one is not already scheduled).
 * When the NOP completes it signals all preceding transfers have
 * completed also.
 */
void ipa_no_intr_init(u32 prod_ep_id)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[prod_ep_id];

	INIT_WORK(&ep->sys->tx.nop_work, ipa_send_nop_work);
	atomic_set(&ep->sys->tx.nop_pending, 0);
	hrtimer_init(&ep->sys->tx.nop_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	ep->sys->tx.nop_timer.function = ipa_nop_timer_expiry;
	ep->sys->tx.no_intr = true;
}

/**
 * ipa_send() - Send descriptors to hardware as a single transaction
 * @sys:	System context for endpoint
 * @num_desc:	Number of descriptors
 * @desc:	Transfer descriptors to send
 *
 * Return:	0 iff successful, or a negative error code.
 */
static int
ipa_send(struct ipa_sys_context *sys, u32 num_desc, struct ipa_desc *desc)
{
	struct device *dev = &ipa_ctx->pdev->dev;
	struct ipa_tx_pkt_wrapper *tx_pkt;
	struct ipa_tx_pkt_wrapper *first;
	struct ipa_tx_pkt_wrapper *next;
	struct gsi_xfer_elem *xfer_elem;
	LIST_HEAD(pkt_list);
	int ret;
	int i;

	ipa_assert(num_desc);
	ipa_assert(num_desc <= ipa_client_tlv_count(sys->ep->client));

	xfer_elem = kcalloc(num_desc, sizeof(*xfer_elem), GFP_ATOMIC);
	if (!xfer_elem)
		return -ENOMEM;

	/* Within loop, all errors are allocation or DMA mapping */
	ret = -ENOMEM;
	first = NULL;
	for (i = 0; i < num_desc; i++) {
		dma_addr_t phys;

		tx_pkt = kmem_cache_zalloc(ipa_ctx->tx_pkt_wrapper_cache,
					   GFP_ATOMIC);
		if (!tx_pkt)
			goto err_unwind;

		if (!first)
			first = tx_pkt;

		if (desc[i].type == IPA_DATA_DESC_SKB_PAGED)
			phys = skb_frag_dma_map(dev, desc[i].payload, 0,
						desc[i].len_opcode,
						DMA_TO_DEVICE);
		else
			phys = dma_map_single(dev, desc[i].payload,
					      desc[i].len_opcode,
					      DMA_TO_DEVICE);
		if (dma_mapping_error(dev, phys)) {
			ipa_err("dma mapping error on descriptor\n");
			kmem_cache_free(ipa_ctx->tx_pkt_wrapper_cache,
					tx_pkt);
			goto err_unwind;
		}

		tx_pkt->type = desc[i].type;
		tx_pkt->sys = sys;
		tx_pkt->virt = desc[i].payload;
		tx_pkt->phys = phys;
		tx_pkt->size = desc[i].len_opcode;
		tx_pkt->callback = desc[i].callback;
		tx_pkt->user1 = desc[i].user1;
		tx_pkt->user2 = desc[i].user2;
		list_add_tail(&tx_pkt->link, &pkt_list);

		xfer_elem[i].addr = tx_pkt->phys;
		if (desc[i].type == IPA_IMM_CMD_DESC)
			xfer_elem[i].type = GSI_XFER_ELEM_IMME_CMD;
		else
			xfer_elem[i].type = GSI_XFER_ELEM_DATA;
		xfer_elem[i].len_opcode = desc[i].len_opcode;
		if (i < num_desc - 1)
			xfer_elem[i].flags = GSI_XFER_FLAG_CHAIN;
	}

	/* Fill in extra fields in the first TX packet */
	first->cnt = num_desc;
	INIT_WORK(&first->done_work, ipa_wq_write_done);

	/* Fill in extra fields in the last transfer element */
	if (!sys->tx.no_intr) {
		xfer_elem[num_desc - 1].flags = GSI_XFER_FLAG_EOT;
		xfer_elem[num_desc - 1].flags |= GSI_XFER_FLAG_BEI;
	}
	xfer_elem[num_desc - 1].user_data = first;

	spin_lock_bh(&sys->spinlock);

	list_splice_tail_init(&pkt_list, &sys->head_desc_list);
	ret = gsi_channel_queue(ipa_ctx->gsi, sys->ep->channel_id, num_desc,
				xfer_elem, true);
	if (ret)
		list_cut_end(&pkt_list, &sys->head_desc_list, &first->link);

	spin_unlock_bh(&sys->spinlock);

	kfree(xfer_elem);

	if (!ret) {
		if (sys->tx.no_intr)
			ipa_nop_timer_schedule(sys);
		return 0;
	}
err_unwind:
	list_for_each_entry_safe(tx_pkt, next, &pkt_list, link) {
		list_del(&tx_pkt->link);
		tx_pkt->callback = NULL; /* Avoid doing the callback */
		ipa_tx_complete(tx_pkt);
	}

	return ret;
}

/**
 * ipa_send_cmd_timeout_complete() - Command completion callback
 * @user1:	Opaque value carried by the command
 * @ignored:	Second opaque value (ignored)
 *
 * Schedule a completion to signal that a command is done.  Free the
 * tag_completion structure if its reference count reaches zero.
 */
static void ipa_send_cmd_timeout_complete(void *user1, int ignored)
{
	struct ipa_tag_completion *comp = user1;

	complete(&comp->comp);
	if (!atomic_dec_return(&comp->cnt))
		kfree(comp);
}

/**
 * ipa_send_cmd_timeout() - Send an immediate command with timeout
 * @desc:	descriptor structure
 * @timeout:	milliseconds to wait (or 0 to wait indefinitely)
 *
 * Send an immediate command, and wait for it to complete.  If
 * timeout is non-zero it indicates the number of milliseconds to
 * wait to receive the acknowledgment from the hardware before
 * timing out.  If 0 is supplied, wait will not time out.
 *
 * Return:	0 if successful, or a negative error code
 */
int ipa_send_cmd_timeout(struct ipa_desc *desc, u32 timeout)
{
	struct ipa_tag_completion *comp;
	unsigned long timeout_jiffies;
	struct ipa_ep_context *ep;
	int ret;

	comp = kzalloc(sizeof(*comp), GFP_KERNEL);
	if (!comp)
		return -ENOMEM;

	/* The reference count is decremented both here and in ack
	 * callback.  Whichever reaches 0 frees the structure.
	 */
	atomic_set(&comp->cnt, 2);
	init_completion(&comp->comp);

	/* Fill in the callback info (the sole descriptor is the last) */
	desc->callback = ipa_send_cmd_timeout_complete;
	desc->user1 = comp;

	ep = &ipa_ctx->ep[ipa_client_ep_id(IPA_CLIENT_APPS_CMD_PROD)];
	ret = ipa_send(ep->sys, 1, desc);
	if (ret) {
		/* Callback won't run; drop reference on its behalf */
		atomic_dec(&comp->cnt);
		goto out;
	}

	timeout_jiffies = msecs_to_jiffies(timeout);
	if (!timeout_jiffies) {
		wait_for_completion(&comp->comp);
	} else if (!wait_for_completion_timeout(&comp->comp, timeout_jiffies)) {
		ret = -ETIMEDOUT;
		ipa_err("command timed out\n");
	}
out:
	if (!atomic_dec_return(&comp->cnt))
		kfree(comp);

	return ret;
}

/**
 * ipa_handle_rx_core() - Core packet reception handling
 * @sys:	System context for endpoint receiving packets
 *
 * Return:	The number of packets processed, or a negative error code
 */
static int ipa_handle_rx_core(struct ipa_sys_context *sys)
{
	int cnt;

	/* Stop if the endpoint leaves polling state */
	cnt = 0;
	while (ipa_ep_polling(sys->ep)) {
		int ret = ipa_poll_gsi_pkt(sys);

		if (ret < 0)
			break;

		ipa_rx_common(sys, (u32)ret);

		cnt++;
	}

	return cnt;
}

/**
 * ipa_rx_switch_to_intr_mode() - Switch from polling to interrupt mode
 * @sys:	System context for endpoint switching mode
 */
static void ipa_rx_switch_to_intr_mode(struct ipa_sys_context *sys)
{
	if (!atomic_xchg(&sys->rx.curr_polling_state, 0)) {
		ipa_err("already in intr mode\n");
		queue_delayed_work(sys->wq, &sys->rx.switch_to_intr_work,
				   msecs_to_jiffies(1));
		return;
	}
	ipa_dec_release_wakelock(ipa_ctx);
	gsi_channel_intr_enable(ipa_ctx->gsi, sys->ep->channel_id);
}

void ipa_rx_switch_to_poll_mode(struct ipa_sys_context *sys)
{
	if (atomic_xchg(&sys->rx.curr_polling_state, 1))
		return;
	gsi_channel_intr_disable(ipa_ctx->gsi, sys->ep->channel_id);
	ipa_inc_acquire_wakelock(ipa_ctx);
	queue_work(sys->wq, &sys->rx.work);
}

/**
 * ipa_handle_rx() - Handle packet reception.
 * @sys:	System context for endpoint receiving packets
 */
static void ipa_handle_rx(struct ipa_sys_context *sys)
{
	int inactive_cycles = 0;
	int cnt;

	ipa_clock_get(ipa_ctx);
	do {
		cnt = ipa_handle_rx_core(sys);
		if (cnt == 0)
			inactive_cycles++;
		else
			inactive_cycles = 0;

		usleep_range(POLLING_MIN_SLEEP_RX, POLLING_MAX_SLEEP_RX);

		/* if endpoint is out of buffers there is no point polling for
		 * completed descs; release the worker so delayed work can
		 * run in a timely manner
		 */
		if (sys->len - sys->rx.len_pending_xfer == 0)
			break;

	} while (inactive_cycles <= POLLING_INACTIVITY_RX);

	ipa_rx_switch_to_intr_mode(sys);
	ipa_clock_put(ipa_ctx);
}

static void ipa_switch_to_intr_rx_work_func(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct ipa_sys_context *sys;

	sys = container_of(dwork, struct ipa_sys_context,
			   rx.switch_to_intr_work);

	/* For NAPI, interrupt mode is done in ipa_rx_poll context */
	ipa_assert(!sys->ep->napi_enabled);

	ipa_handle_rx(sys);
}

static struct ipa_sys_context *ipa_ep_sys_create(enum ipa_client_type client)
{
	const unsigned int wq_flags = WQ_MEM_RECLAIM | WQ_UNBOUND;
	struct ipa_sys_context *sys;

	/* Caller will zero all "mutable" fields; we fill in the rest */
	sys = kmalloc(sizeof(*sys), GFP_KERNEL);
	if (!sys)
		return NULL;

	sys->wq = alloc_workqueue("ipawq%u", wq_flags, 1, (u32)client);
	if (!sys->wq) {
		kfree(sys);
		return NULL;
	}

	/* Caller assigns sys->ep = ep */
	INIT_LIST_HEAD(&sys->head_desc_list);
	spin_lock_init(&sys->spinlock);

	return sys;
}

/**
 * ipa_tx_dp_complete() - Transmit complete callback
 * @user1:	Caller-supplied pointer value
 * @user2:	Caller-supplied integer value
 *
 * Calls the endpoint's client_notify function if it exists;
 * otherwise just frees the socket buffer (supplied in user1).
 */
static void ipa_tx_dp_complete(void *user1, int user2)
{
	struct sk_buff *skb = user1;
	int ep_id = user2;

	if (ipa_ctx->ep[ep_id].client_notify) {
		unsigned long data;
		void *priv;

		priv = ipa_ctx->ep[ep_id].priv;
		data = (unsigned long)skb;
		ipa_ctx->ep[ep_id].client_notify(priv, IPA_WRITE_DONE, data);
	} else {
		dev_kfree_skb_any(skb);
	}
}

/**
 * ipa_tx_dp() - Transmit a socket buffer for APPS_WAN_PROD
 * @client:	IPA client that is sending packets (WAN producer)
 * @skb:	The socket buffer to send
 *
 * Returns:	0 if successful, or a negative error code
 */
int ipa_tx_dp(enum ipa_client_type client, struct sk_buff *skb)
{
	struct ipa_desc _desc = { };	/* Used for common case */
	struct ipa_desc *desc;
	u32 tlv_count;
	int data_idx;
	u32 nr_frags;
	u32 ep_id;
	int ret;
	u32 f;

	if (!skb->len)
		return -EINVAL;

	ep_id = ipa_client_ep_id(client);

	/* Make sure source endpoint's TLV FIFO has enough entries to
	 * hold the linear portion of the skb and all its frags.
	 * If not, see if we can linearize it before giving up.
	 */
	nr_frags = skb_shinfo(skb)->nr_frags;
	tlv_count = ipa_client_tlv_count(client);
	if (1 + nr_frags > tlv_count) {
		if (skb_linearize(skb))
			return -ENOMEM;
		nr_frags = 0;
	}
	if (nr_frags) {
		desc = kcalloc(1 + nr_frags, sizeof(*desc), GFP_ATOMIC);
		if (!desc)
			return -ENOMEM;
	} else {
		desc = &_desc;	/* Default, linear case */
	}

	/* Fill in the IPA request descriptors--one for the linear
	 * data in the skb, one each for each of its fragments.
	 */
	data_idx = 0;
	desc[data_idx].payload = skb->data;
	desc[data_idx].len_opcode = skb_headlen(skb);
	desc[data_idx].type = IPA_DATA_DESC_SKB;
	for (f = 0; f < nr_frags; f++) {
		data_idx++;
		desc[data_idx].payload = &skb_shinfo(skb)->frags[f];
		desc[data_idx].type = IPA_DATA_DESC_SKB_PAGED;
		desc[data_idx].len_opcode =
				skb_frag_size(desc[data_idx].payload);
	}

	/* Have the skb be freed after the last descriptor completes. */
	desc[data_idx].callback = ipa_tx_dp_complete;
	desc[data_idx].user1 = skb;
	desc[data_idx].user2 = ep_id;

	ret = ipa_send(ipa_ctx->ep[ep_id].sys, data_idx + 1, desc);

	if (nr_frags)
		kfree(desc);

	return ret;
}

static void ipa_wq_handle_rx(struct work_struct *work)
{
	struct ipa_sys_context *sys;

	sys = container_of(work, struct ipa_sys_context, rx.work);

	if (sys->ep->napi_enabled) {
		ipa_clock_get(ipa_ctx);
		sys->ep->client_notify(sys->ep->priv, IPA_CLIENT_START_POLL, 0);
	} else {
		ipa_handle_rx(sys);
	}
}

static int
queue_rx_cache(struct ipa_sys_context *sys, struct ipa_rx_pkt_wrapper *rx_pkt)
{
	struct gsi_xfer_elem gsi_xfer_elem;
	bool ring_doorbell;
	int ret;

	/* Don't bother zeroing this; we fill all fields */
	gsi_xfer_elem.addr = rx_pkt->dma_addr;
	gsi_xfer_elem.len_opcode = sys->rx.buff_sz;
	gsi_xfer_elem.flags = GSI_XFER_FLAG_EOT;
	gsi_xfer_elem.flags |= GSI_XFER_FLAG_EOB;
	gsi_xfer_elem.type = GSI_XFER_ELEM_DATA;
	gsi_xfer_elem.user_data = rx_pkt;

	/* Doorbell is expensive; only ring it when a batch is queued */
	ring_doorbell = sys->rx.len_pending_xfer++ >= IPA_REPL_XFER_THRESH;

	ret = gsi_channel_queue(ipa_ctx->gsi, sys->ep->channel_id,
				1, &gsi_xfer_elem, ring_doorbell);
	if (ret)
		return ret;

	if (ring_doorbell)
		sys->rx.len_pending_xfer = 0;

	return 0;
}

/**
 * ipa_replenish_rx_cache() - Replenish the Rx packets cache.
 * @sys:	System context for IPA->AP endpoint
 *
 * Allocate RX packet wrapper structures with maximal socket buffers
 * for an endpoint.  These are supplied to the hardware, which fills
 * them with incoming data.
 */
static void ipa_replenish_rx_cache(struct ipa_sys_context *sys)
{
	struct device *dev = &ipa_ctx->pdev->dev;
	struct ipa_rx_pkt_wrapper *rx_pkt;
	u32 rx_len_cached = sys->len;

	while (rx_len_cached < sys->rx.pool_sz) {
		gfp_t flag = GFP_NOWAIT | __GFP_NOWARN;
		void *ptr;
		int ret;

		rx_pkt = kmem_cache_zalloc(ipa_ctx->rx_pkt_wrapper_cache,
					   flag);
		if (!rx_pkt)
			goto fail_kmem_cache_alloc;

		INIT_LIST_HEAD(&rx_pkt->link);

		rx_pkt->skb = __dev_alloc_skb(sys->rx.buff_sz, flag);
		if (!rx_pkt->skb) {
			ipa_err("failed to alloc skb\n");
			goto fail_skb_alloc;
		}
		ptr = skb_put(rx_pkt->skb, sys->rx.buff_sz);
		rx_pkt->dma_addr = dma_map_single(dev, ptr, sys->rx.buff_sz,
						  DMA_FROM_DEVICE);
		if (dma_mapping_error(dev, rx_pkt->dma_addr)) {
			ipa_err("dma_map_single failure %p for %p\n",
				(void *)rx_pkt->dma_addr, ptr);
			goto fail_dma_mapping;
		}

		list_add_tail(&rx_pkt->link, &sys->head_desc_list);
		rx_len_cached = ++sys->len;

		ret = queue_rx_cache(sys, rx_pkt);
		if (ret)
			goto fail_provide_rx_buffer;
	}

	return;

fail_provide_rx_buffer:
	list_del(&rx_pkt->link);
	rx_len_cached = --sys->len;
	dma_unmap_single(dev, rx_pkt->dma_addr, sys->rx.buff_sz,
			 DMA_FROM_DEVICE);
fail_dma_mapping:
	dev_kfree_skb_any(rx_pkt->skb);
fail_skb_alloc:
	kmem_cache_free(ipa_ctx->rx_pkt_wrapper_cache, rx_pkt);
fail_kmem_cache_alloc:
	if (rx_len_cached - sys->rx.len_pending_xfer == 0)
		queue_delayed_work(sys->wq, &sys->rx.replenish_work,
				   msecs_to_jiffies(1));
}

static void ipa_replenish_rx_work_func(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct ipa_sys_context *sys;

	sys = container_of(dwork, struct ipa_sys_context, rx.replenish_work);
	ipa_clock_get(ipa_ctx);
	ipa_replenish_rx_cache(sys);
	ipa_clock_put(ipa_ctx);
}

/** ipa_cleanup_rx() - release RX queue resources */
static void ipa_cleanup_rx(struct ipa_sys_context *sys)
{
	struct device *dev = &ipa_ctx->pdev->dev;
	struct ipa_rx_pkt_wrapper *rx_pkt;
	struct ipa_rx_pkt_wrapper *r;

	list_for_each_entry_safe(rx_pkt, r, &sys->head_desc_list, link) {
		list_del(&rx_pkt->link);
		dma_unmap_single(dev, rx_pkt->dma_addr, sys->rx.buff_sz,
				 DMA_FROM_DEVICE);
		dev_kfree_skb_any(rx_pkt->skb);
		kmem_cache_free(ipa_ctx->rx_pkt_wrapper_cache, rx_pkt);
	}
}

static struct sk_buff *ipa_skb_copy_for_client(struct sk_buff *skb, int len)
{
	struct sk_buff *skb2;

	skb2 = __dev_alloc_skb(len + IPA_RX_BUFF_CLIENT_HEADROOM, GFP_KERNEL);
	if (likely(skb2)) {
		/* Set the data pointer */
		skb_reserve(skb2, IPA_RX_BUFF_CLIENT_HEADROOM);
		memcpy(skb2->data, skb->data, len);
		skb2->len = len;
		skb_set_tail_pointer(skb2, len);
	}

	return skb2;
}

static struct sk_buff *ipa_join_prev_skb(struct sk_buff *prev_skb,
					 struct sk_buff *skb, unsigned int len)
{
	struct sk_buff *skb2;

	skb2 = skb_copy_expand(prev_skb, 0, len, GFP_KERNEL);
	if (likely(skb2))
		memcpy(skb_put(skb2, len), skb->data, len);
	else
		ipa_err("copy expand failed\n");
	dev_kfree_skb_any(prev_skb);

	return skb2;
}

static bool ipa_status_opcode_supported(enum ipahal_pkt_status_opcode opcode)
{
	return opcode == IPAHAL_PKT_STATUS_OPCODE_PACKET ||
		opcode == IPAHAL_PKT_STATUS_OPCODE_DROPPED_PACKET ||
		opcode == IPAHAL_PKT_STATUS_OPCODE_SUSPENDED_PACKET ||
		opcode == IPAHAL_PKT_STATUS_OPCODE_PACKET_2ND_PASS;
}

static void
ipa_lan_rx_pyld_hdlr(struct sk_buff *skb, struct ipa_sys_context *sys)
{
	struct ipahal_pkt_status status;
	struct sk_buff *skb2;
	unsigned long unused;
	unsigned char *buf;
	unsigned int align;
	unsigned int used;
	int pad_len_byte;
	u32 ep_id;
	int len;
	int len2;

	used = *(unsigned int *)skb->cb;
	align = ALIGN(used, 32);
	unused = IPA_RX_BUFFER_SIZE - used;

	ipa_assert(skb->len);

	if (sys->rx.len_partial) {
		buf = skb_push(skb, sys->rx.len_partial);
		memcpy(buf, sys->rx.prev_skb->data, sys->rx.len_partial);
		sys->rx.len_partial = 0;
		dev_kfree_skb_any(sys->rx.prev_skb);
		sys->rx.prev_skb = NULL;
		goto begin;
	}

	/* this endpoint has TX comp (status only) + mux-ed LAN RX data
	 * (status+data)
	 */
	if (sys->rx.len_rem) {
		if (sys->rx.len_rem <= skb->len) {
			if (sys->rx.prev_skb) {
				skb2 = skb_copy_expand(sys->rx.prev_skb, 0,
						       sys->rx.len_rem,
						       GFP_KERNEL);
				if (likely(skb2)) {
					memcpy(skb_put(skb2, sys->rx.len_rem),
					       skb->data, sys->rx.len_rem);
					skb_trim(skb2,
						 skb2->len - sys->rx.len_pad);
					skb2->truesize = skb2->len +
						sizeof(struct sk_buff);
					if (sys->rx.drop_packet)
						dev_kfree_skb_any(skb2);
					else
						sys->ep->client_notify(
							sys->ep->priv,
							IPA_RECEIVE,
							(unsigned long)(skb2));
				} else {
					ipa_err("copy expand failed\n");
				}
				dev_kfree_skb_any(sys->rx.prev_skb);
			}
			skb_pull(skb, sys->rx.len_rem);
			sys->rx.prev_skb = NULL;
			sys->rx.len_rem = 0;
			sys->rx.len_pad = 0;
		} else {
			if (sys->rx.prev_skb) {
				skb2 = ipa_join_prev_skb(sys->rx.prev_skb, skb,
							 skb->len);
				dev_kfree_skb_any(sys->rx.prev_skb);
				sys->rx.prev_skb = skb2;
			}
			sys->rx.len_rem -= skb->len;
			return;
		}
	}

begin:
	while (skb->len) {
		size_t status_size;

		sys->rx.drop_packet = false;

		status_size = ipahal_pkt_status_parse(skb, &status);
		if (!status_size) {
			WARN_ON(sys->rx.prev_skb);
			sys->rx.prev_skb = skb_copy(skb, GFP_KERNEL);
			sys->rx.len_partial = skb->len;
			return;
		}

		if (!ipa_status_opcode_supported(status.status_opcode)) {
			ipa_err("unsupported opcode(%d)\n",
				status.status_opcode);
			skb_pull(skb, status_size);
			continue;
		}

		if (status.pkt_len == 0) {
			skb_pull(skb, status_size);
			continue;
		}

		if (status.endp_dest_idx == (sys->ep - ipa_ctx->ep)) {
			/* RX data */
			ep_id = status.endp_src_idx;

			/* A packet which is received back to the AP after
			 * there was no route match.
			 */

			if (status.exception ==
				IPAHAL_PKT_STATUS_EXCEPTION_NONE &&
			    status.rt_miss)
				sys->rx.drop_packet = true;
			if (skb->len == status_size &&
			    status.exception ==
					IPAHAL_PKT_STATUS_EXCEPTION_NONE) {
				WARN_ON(sys->rx.prev_skb);
				sys->rx.prev_skb = skb_copy(skb, GFP_KERNEL);
				sys->rx.len_partial = skb->len;
				return;
			}

			pad_len_byte = ((status.pkt_len + 3) & ~3) -
					status.pkt_len;

			len = status.pkt_len + pad_len_byte +
				IPA_SIZE_DL_CSUM_META_TRAILER;

			if (status.exception ==
					IPAHAL_PKT_STATUS_EXCEPTION_DEAGGR) {
				sys->rx.drop_packet = true;
			}

			len2 = min(status.pkt_len + status_size,
				   (size_t)skb->len);
			skb2 = ipa_skb_copy_for_client(skb, len2);
			if (likely(skb2)) {
				if (skb->len < len + status_size) {
					sys->rx.prev_skb = skb2;
					sys->rx.len_rem = len - skb->len +
						status_size;
					sys->rx.len_pad = pad_len_byte;
					skb_pull(skb, skb->len);
				} else {
					skb_trim(skb2, status.pkt_len +
							status_size);
					if (sys->rx.drop_packet) {
						dev_kfree_skb_any(skb2);
					} else {
						skb2->truesize =
							skb2->len +
							sizeof(struct sk_buff) +
							(ALIGN(len +
							status_size, 32) *
							unused / align);
						sys->ep->client_notify(
							sys->ep->priv,
							IPA_RECEIVE,
							(unsigned long)(skb2));
					}
					skb_pull(skb, len +
							status_size);
				}
			} else {
				ipa_err("fail to alloc skb\n");
				if (skb->len < len) {
					sys->rx.prev_skb = NULL;
					sys->rx.len_rem = len - skb->len +
						status_size;
					sys->rx.len_pad = pad_len_byte;
					skb_pull(skb, skb->len);
				} else {
					skb_pull(skb, len +
							status_size);
				}
			}
		} else {
			skb_pull(skb, status_size);
		}
	}
}

static void
ipa_wan_rx_handle_splt_pyld(struct sk_buff *skb, struct ipa_sys_context *sys)
{
	struct sk_buff *skb2;

	if (sys->rx.len_rem <= skb->len) {
		if (sys->rx.prev_skb) {
			skb2 = ipa_join_prev_skb(sys->rx.prev_skb, skb,
						 sys->rx.len_rem);
			if (likely(skb2)) {
				skb_pull(skb2, ipahal_pkt_status_get_size());
				skb2->truesize = skb2->len +
					sizeof(struct sk_buff);
				sys->ep->client_notify(sys->ep->priv,
						       IPA_RECEIVE,
						       (unsigned long)skb2);
			}
		}
		skb_pull(skb, sys->rx.len_rem);
		sys->rx.prev_skb = NULL;
		sys->rx.len_rem = 0;
	} else {
		if (sys->rx.prev_skb) {
			skb2 = ipa_join_prev_skb(sys->rx.prev_skb, skb,
						 skb->len);
			sys->rx.prev_skb = skb2;
		}
		sys->rx.len_rem -= skb->len;
		skb_pull(skb, skb->len);
	}
}

static void
ipa_wan_rx_pyld_hdlr(struct sk_buff *skb, struct ipa_sys_context *sys)
{
	struct ipahal_pkt_status status;
	unsigned char *skb_data;
	struct sk_buff *skb2;
	u16 pkt_len_with_pad;
	size_t status_size;
	unsigned long unused;
	unsigned int align;
	unsigned int used;
	int frame_len;
	u32 qmap_hdr;
	int checksum;
	int ep_id;

	used = *(unsigned int *)skb->cb;
	align = ALIGN(used, 32);
	unused = IPA_RX_BUFFER_SIZE - used;

	ipa_assert(skb->len);

	if (ipa_ctx->ipa_client_apps_wan_cons_agg_gro) {
		sys->ep->client_notify(sys->ep->priv, IPA_RECEIVE,
				       (unsigned long)(skb));
		return;
	}

	/* payload splits across 2 buff or more,
	 * take the start of the payload from rx.prev_skb
	 */
	if (sys->rx.len_rem)
		ipa_wan_rx_handle_splt_pyld(skb, sys);

	status_size = ipahal_pkt_status_get_size();
	while (skb->len) {
		u32 status_mask;

		status_size = ipahal_pkt_status_parse(skb, &status);
		if (!status_size) {
			ipa_err("%zu status bytes dropped\n", status_size);
			dev_kfree_skb_any(skb);
			return;
		}
		skb_data = skb->data;

		if (!ipa_status_opcode_supported(status.status_opcode) ||
		    status.status_opcode ==
				IPAHAL_PKT_STATUS_OPCODE_SUSPENDED_PACKET) {
			ipa_err("unsupported opcode(%d)\n",
				status.status_opcode);
			skb_pull(skb, status_size);
			continue;
		}

		if (status.pkt_len == 0) {
			skb_pull(skb, status_size);
			continue;
		}
		ep_id = ipa_client_ep_id(IPA_CLIENT_APPS_WAN_CONS);
		if (status.endp_dest_idx != ep_id) {
			ipa_err("expected endp_dest_idx %d received %d\n",
				ep_id, status.endp_dest_idx);
			WARN_ON(1);
			goto bail;
		}
		/* RX data */
		if (skb->len == status_size) {
			ipa_err("Ins header in next buffer\n");
			WARN_ON(1);
			goto bail;
		}
		qmap_hdr = *(u32 *)(skb_data + status_size);

		/* Take the pkt_len_with_pad from the last 2 bytes of the QMAP
		 * header
		 */
		/*QMAP is BE: convert the pkt_len field from BE to LE*/
		pkt_len_with_pad = ntohs((qmap_hdr >> 16) & 0xffff);
		/*get the CHECKSUM_PROCESS bit*/
		status_mask = status.status_mask;
		checksum = status_mask & IPAHAL_PKT_STATUS_MASK_CKSUM_PROCESS;

		frame_len = status_size + IPA_QMAP_HEADER_LENGTH +
			    pkt_len_with_pad;
		if (checksum)
			frame_len += IPA_DL_CHECKSUM_LENGTH;

		skb2 = skb_clone(skb, GFP_ATOMIC);
		if (likely(skb2)) {
			/* the len of actual data is smaller than expected
			 * payload split across 2 buff
			 */
			if (skb->len < frame_len) {
				sys->rx.prev_skb = skb2;
				sys->rx.len_rem = frame_len - skb->len;
				skb_pull(skb, skb->len);
			} else {
				skb_trim(skb2, frame_len);
				skb_pull(skb2, status_size);
				skb2->truesize = skb2->len +
					sizeof(struct sk_buff) +
					(ALIGN(frame_len, 32) *
					 unused / align);
				sys->ep->client_notify(sys->ep->priv,
						       IPA_RECEIVE,
						       (unsigned long)(skb2));
				skb_pull(skb, frame_len);
			}
		} else {
			ipa_err("fail to clone\n");
			if (skb->len < frame_len) {
				sys->rx.prev_skb = NULL;
				sys->rx.len_rem = frame_len - skb->len;
				skb_pull(skb, skb->len);
			} else {
				skb_pull(skb, frame_len);
			}
		}
	}
bail:
	dev_kfree_skb_any(skb);
}

void ipa_lan_rx_cb(void *priv, enum ipa_dp_evt_type evt, unsigned long data)
{
	struct sk_buff *rx_skb = (struct sk_buff *)data;
	struct ipahal_pkt_status status;
	struct ipa_ep_context *ep;
	size_t status_size;
	u32 metadata;
	u32 ep_id;

	status_size = ipahal_pkt_status_parse(rx_skb, &status);
	if (!status_size) {
		ipa_err("%zu status bytes dropped\n", status_size);
		dev_kfree_skb_any(rx_skb);
		return;
	}

	ep_id = status.endp_src_idx;
	metadata = status.metadata;
	ep = &ipa_ctx->ep[ep_id];

	/* Consume the status packet, and if no exception, the header */
	skb_pull(rx_skb, status_size);
	if (status.exception == IPAHAL_PKT_STATUS_EXCEPTION_NONE)
		skb_pull(rx_skb, IPA_LAN_RX_HEADER_LENGTH);

	/* Metadata Info
	 *  ------------------------------------------
	 *  |	3     |	  2	|    1	      |	 0   |
	 *  | fw_desc | vdev_id | qmap mux id | Resv |
	 *  ------------------------------------------
	 */
	*(u16 *)rx_skb->cb = ((metadata >> 16) & 0xffff);

	ep->client_notify(ep->priv, IPA_RECEIVE, (unsigned long)rx_skb);
}

static void ipa_rx_common(struct ipa_sys_context *sys, u32 size)
{
	struct device *dev = &ipa_ctx->pdev->dev;
	struct ipa_rx_pkt_wrapper *rx_pkt;
	struct sk_buff *rx_skb;

	ipa_assert(!list_empty(&sys->head_desc_list));

	spin_lock_bh(&sys->spinlock);

	rx_pkt = list_first_entry(&sys->head_desc_list,
				  struct ipa_rx_pkt_wrapper, link);
	list_del(&rx_pkt->link);
	sys->len--;

	spin_unlock_bh(&sys->spinlock);

	rx_skb = rx_pkt->skb;
	dma_unmap_single(dev, rx_pkt->dma_addr, sys->rx.buff_sz,
			 DMA_FROM_DEVICE);

	skb_trim(rx_skb, size);

	*(unsigned int *)rx_skb->cb = rx_skb->len;
	rx_skb->truesize = size + sizeof(struct sk_buff);

	sys->rx.pyld_hdlr(rx_skb, sys);
	kmem_cache_free(ipa_ctx->rx_pkt_wrapper_cache, rx_pkt);
	ipa_replenish_rx_cache(sys);
}

/**
 * ipa_aggr_byte_limit_buf_size()
 * @byte_limit:	Desired limit (in bytes) for aggregation
 *
 * Compute the buffer size required to support a requested aggregation
 * byte limit.  Aggregration will close when *more* than the configured
 * number of bytes have been added to an aggregation frame.  Our
 * buffers therefore need to to be big enough to receive one complete
 * packet once the configured byte limit has been consumed.
 *
 * An incoming packet can have as much as IPA_MTU of data in it, but
 * the buffer also needs to be large enough to accomodate the standard
 * socket buffer overhead (NET_SKB_PAD of headroom, plus an implied
 * skb_shared_info structure at the end).
 *
 * So we compute the required buffer size by adding the standard
 * socket buffer overhead and MTU to the requested size.  We round
 * that down to a power of 2 in an effort to avoid fragmentation due
 * to unaligned buffer sizes.
 *
 * After accounting for all of this, we return the number of bytes
 * of buffer space the IPA hardware will know is available to hold
 * received data (without any overhead).
 *
 * Return:	The computes size of buffer space available
 */
u32 ipa_aggr_byte_limit_buf_size(u32 byte_limit)
{
	/* Account for one additional packet, including overhead */
	byte_limit += IPA_RX_BUFFER_RESERVED;
	byte_limit += IPA_MTU;

	/* Convert this size to a nearby power-of-2.  We choose one
	 * that's *less than* the limit we seek--so we start by
	 * subracting 1.  The highest set bit in that is used to
	 * compute the power of 2.
	 *
	 * XXX Why is this *less than* and not possibly equal?
	 */
	byte_limit = 1 << __fls(byte_limit - 1);

	/* Given that size, figure out how much buffer space that
	 * leaves us for received data.
	 */
	return IPA_RX_BUFFER_AVAILABLE(byte_limit);
}

void ipa_gsi_irq_tx_notify_cb(void *xfer_data)
{
	struct ipa_tx_pkt_wrapper *tx_pkt = xfer_data;

	queue_work(tx_pkt->sys->wq, &tx_pkt->done_work);
}

void ipa_gsi_irq_rx_notify_cb(void *chan_data, u16 count)
{
	struct ipa_sys_context *sys = chan_data;

	sys->ep->bytes_xfered_valid = true;
	sys->ep->bytes_xfered = count;

	ipa_rx_switch_to_poll_mode(sys);
}

static int ipa_gsi_setup_channel(struct ipa_ep_context *ep, u32 channel_count,
				 u32 evt_ring_mult)
{
	u32 channel_id = ipa_client_channel_id(ep->client);
	u32 tlv_count = ipa_client_tlv_count(ep->client);
	bool from_ipa = ipa_consumer(ep->client);
	bool moderation;
	bool priority;
	int ret;

	priority = ep->client == IPA_CLIENT_APPS_CMD_PROD;
	moderation = !ep->sys->tx.no_intr;

	ret = gsi_channel_alloc(ipa_ctx->gsi, channel_id, channel_count,
				from_ipa, priority, evt_ring_mult, moderation,
				ep->sys);
	if (ret)
		return ret;
	ep->channel_id = channel_id;

	gsi_channel_scratch_write(ipa_ctx->gsi, ep->channel_id, tlv_count);

	ret = gsi_channel_start(ipa_ctx->gsi, ep->channel_id);
	if (ret)
		gsi_channel_free(ipa_ctx->gsi, ep->channel_id);

	return ret;
}

void ipa_endp_init_hdr_cons(struct ipa_context *ipa, u32 ep_id, u32 header_size,
			    u32 metadata_offset, u32 length_offset)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];

	ipa_reg_endp_init_hdr_cons(&ep->init_hdr, header_size, metadata_offset,
				   length_offset);
}

void ipa_endp_init_hdr_prod(struct ipa_context *ipa, u32 ep_id, u32 header_size,
			    u32 metadata_offset, u32 length_offset)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];

	ipa_reg_endp_init_hdr_prod(&ep->init_hdr, header_size, metadata_offset,
				   length_offset);
}

void
ipa_endp_init_hdr_ext_cons(struct ipa_context *ipa, u32 ep_id, u32 pad_align,
			   bool pad_included)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];

	ipa_reg_endp_init_hdr_ext_cons(&ep->hdr_ext, pad_align, pad_included);
}

void ipa_endp_init_hdr_ext_prod(struct ipa_context *ipa, u32 ep_id,
				u32 pad_align)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];

	ipa_reg_endp_init_hdr_ext_prod(&ep->hdr_ext, pad_align);
}

void
ipa_endp_init_aggr_cons(struct ipa_context *ipa, u32 ep_id, u32 size, u32 count,
			bool close_on_eof)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];

	ipa_reg_endp_init_aggr_cons(&ep->init_aggr, size, count, close_on_eof);
}

void ipa_endp_init_aggr_prod(struct ipa_context *ipa, u32 ep_id,
			     enum ipa_aggr_en aggr_en,
			     enum ipa_aggr_type aggr_type)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];

	ipa_reg_endp_init_aggr_prod(&ep->init_aggr, aggr_en, aggr_type);
}

void ipa_endp_init_cfg_cons(struct ipa_context *ipa, u32 ep_id,
			    enum ipa_cs_offload_en offload_type)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];

	ipa_reg_endp_init_cfg_cons(&ep->init_cfg, offload_type);
}

void ipa_endp_init_cfg_prod(struct ipa_context *ipa, u32 ep_id,
			    enum ipa_cs_offload_en offload_type,
			    u32 metadata_offset)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];

	ipa_reg_endp_init_cfg_prod(&ep->init_cfg, offload_type,
				   metadata_offset);
}

void ipa_endp_init_hdr_metadata_mask_cons(struct ipa_context *ipa, u32 ep_id,
					  u32 mask)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];

	ipa_reg_endp_init_hdr_metadata_mask_cons(&ep->metadata_mask, mask);
}

void ipa_endp_init_hdr_metadata_mask_prod(struct ipa_context *ipa, u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];

	ipa_reg_endp_init_hdr_metadata_mask_prod(&ep->metadata_mask);
}

void ipa_endp_status_cons(struct ipa_context *ipa, u32 ep_id, bool enable)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];

	ipa_reg_endp_status_cons(&ep->status, enable);
}

void ipa_endp_status_prod(struct ipa_context *ipa, u32 ep_id, bool enable,
			  enum ipa_client_type status_client)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];
	u32 status_ep_id;

	status_ep_id = ipa_client_ep_id(status_client);

	ipa_reg_endp_status_prod(&ep->status, enable, status_ep_id);
}


/* Note that the mode setting is not valid for consumer endpoints */
void ipa_endp_init_mode_cons(struct ipa_context *ipa, u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];

	ipa_reg_endp_init_mode_cons(&ep->init_mode);
}

void ipa_endp_init_mode_prod(struct ipa_context *ipa, u32 ep_id,
			     enum ipa_mode mode,
			     enum ipa_client_type dst_client)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];
	u32 dst_ep_id;

	dst_ep_id = ipa_client_ep_id(dst_client);

	ipa_reg_endp_init_mode_prod(&ep->init_mode, mode, dst_ep_id);
}

/* XXX The sequencer setting seems not to be valid for consumer endpoints */
void ipa_endp_init_seq_cons(struct ipa_context *ipa, u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];

	ipa_reg_endp_init_seq_cons(&ep->init_seq);
}

void ipa_endp_init_seq_prod(struct ipa_context *ipa, u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];
	u32 seq_type;

	seq_type = (u32)ipa_endp_seq_type(ep_id);

	ipa_reg_endp_init_seq_prod(&ep->init_seq, seq_type);
}

/* XXX The deaggr setting seems not to be valid for consumer endpoints */
void ipa_endp_init_deaggr_cons(struct ipa_context *ipa, u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];

	ipa_reg_endp_init_deaggr_cons(&ep->init_deaggr);
}

void ipa_endp_init_deaggr_prod(struct ipa_context *ipa, u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];

	ipa_reg_endp_init_deaggr_prod(&ep->init_deaggr);
}

int ipa_ep_alloc(struct ipa_context *ipa, enum ipa_client_type client)
{
	u32 ep_id = ipa_client_ep_id(client);
	struct ipa_sys_context *sys;
	struct ipa_ep_context *ep;

	ep = &ipa->ep[ep_id];

	ipa_assert(!ep->allocated);

	/* Reuse the endpoint's sys pointer if it is initialized */
	sys = ep->sys;
	if (!sys) {
		sys = ipa_ep_sys_create(client);
		if (!sys)
			return -ENOMEM;
		sys->ep = ep;
	}

	/* Zero the "mutable" part of the system context */
	memset(sys, 0, offsetof(struct ipa_sys_context, ep));

	/* Initialize the endpoint context */
	memset(ep, 0, sizeof(*ep));
	ep->sys = sys;
	ep->client = client;
	ep->allocated = true;

	return ep_id;
}

void ipa_ep_free(struct ipa_context *ipa, u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];

	ipa_assert(ep->allocated);

	ep->allocated = false;
}

/**
 * ipa_ep_setup() - Set up an IPA endpoint
 * @ep_id:		Endpoint to set up
 * @channel_count:	Number of transfer elements in the channel
 * @evt_ring_mult:	Used to determine number of elements in event ring
 * @rx_buffer_size:	Receive buffer size to use (or 0 for TX endpoitns)
 * @client_notify:	Notify function to call on completion
 * @priv:		Value supplied to the notify function
 *
 * Returns:	0 if successful, or a negative error code
 */
int ipa_ep_setup(struct ipa_context *ipa, u32 ep_id, u32 channel_count,
		 u32 evt_ring_mult, u32 rx_buffer_size,
		 void (*client_notify)(void *priv, enum ipa_dp_evt_type type,
				       unsigned long data),
		 void *priv)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];
	int ret;

	if (ipa_consumer(ep->client)) {
		atomic_set(&ep->sys->rx.curr_polling_state, 0);
		INIT_DELAYED_WORK(&ep->sys->rx.switch_to_intr_work,
				  ipa_switch_to_intr_rx_work_func);
		if (ep->client == IPA_CLIENT_APPS_LAN_CONS)
			ep->sys->rx.pyld_hdlr = ipa_lan_rx_pyld_hdlr;
		else
			ep->sys->rx.pyld_hdlr = ipa_wan_rx_pyld_hdlr;
		ep->sys->rx.buff_sz = rx_buffer_size;
		ep->sys->rx.pool_sz = IPA_GENERIC_RX_POOL_SZ;
		INIT_WORK(&ep->sys->rx.work, ipa_wq_handle_rx);
		INIT_DELAYED_WORK(&ep->sys->rx.replenish_work,
				  ipa_replenish_rx_work_func);
	}

	ep->client_notify = client_notify;
	ep->priv = priv;
	ep->napi_enabled = ep->client == IPA_CLIENT_APPS_WAN_CONS;

	ipa_clock_get(ipa_ctx);

	ipa_cfg_ep(ep_id);

	ret = ipa_gsi_setup_channel(ep, channel_count, evt_ring_mult);
	if (ret)
		goto err_client_remove;

	if (ipa_consumer(ep->client))
		ipa_replenish_rx_cache(ep->sys);
err_client_remove:
	ipa_clock_put(ipa_ctx);

	return ret;
}

/**
 * ipa_channel_reset_aggr() - Reset with aggregation active
 * @ep_id:	Endpoint on which reset is performed
 *
 * If aggregation is active on a channel when a reset is performed,
 * a special sequence of actions must be taken.  This is a workaround
 * for a hardware limitation.
 *
 * Return:	0 if successful, or a negative error code.
 */
static int ipa_channel_reset_aggr(u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ep_id];
	struct ipa_reg_aggr_force_close force_close;
	struct device *dev = &ipa_ctx->pdev->dev;
	struct ipa_reg_endp_init_ctrl init_ctrl;
	struct gsi_xfer_elem xfer_elem = { };
	int aggr_active_bitmap = 0;
	bool ep_suspended = false;
	dma_addr_t phys;
	size_t size;
	void *virt;
	int ret;
	int i;

	ipa_reg_aggr_force_close(&force_close, BIT(ep_id));
	ipa_write_reg_fields(IPA_AGGR_FORCE_CLOSE, &force_close);

	/* Reset channel */
	ret = gsi_channel_reset(ipa_ctx->gsi, ep->channel_id);
	if (ret)
		return ret;

	/* Turn off the doorbell engine.  We're going to poll until
	 * we know aggregation isn't active.
	 */
	gsi_channel_config(ipa_ctx->gsi, ep->channel_id, false);

	ipa_read_reg_n_fields(IPA_ENDP_INIT_CTRL_N, ep_id, &init_ctrl);
	if (init_ctrl.endp_suspend) {
		ep_suspended = true;
		ipa_reg_endp_init_ctrl(&init_ctrl, false);
		ipa_write_reg_n_fields(IPA_ENDP_INIT_CTRL_N, ep_id, &init_ctrl);
	}

	/* Start channel and put 1 Byte descriptor on it */
	ret = gsi_channel_start(ipa_ctx->gsi, ep->channel_id);
	if (ret)
		goto out_suspend_again;

	size = 1;
	virt = dma_zalloc_coherent(dev, size, &phys, GFP_KERNEL);
	if (!virt) {
		ret = -ENOMEM;
		goto err_stop_channel;
	}

	xfer_elem.addr = phys;
	xfer_elem.len_opcode = size;
	xfer_elem.flags = GSI_XFER_FLAG_EOT;
	xfer_elem.type = GSI_XFER_ELEM_DATA;

	ret = gsi_channel_queue(ipa_ctx->gsi, ep->channel_id, 1, &xfer_elem,
				true);
	if (ret)
		goto err_dma_free;

	/* Wait for aggregation frame to be closed */
	for (i = 0; i < CHANNEL_RESET_AGGR_RETRY_COUNT; i++) {
		aggr_active_bitmap = ipa_read_reg(IPA_STATE_AGGR_ACTIVE);
		if (!(aggr_active_bitmap & BIT(ep_id)))
			break;
		msleep(CHANNEL_RESET_DELAY);
	}
	ipa_bug_on(aggr_active_bitmap & BIT(ep_id));

	dma_free_coherent(dev, size, virt, phys);

	ret = ipa_stop_gsi_channel(ep_id);
	if (ret)
		goto out_suspend_again;

	/* Reset the channel.  If successful we need to sleep for 1
	 * msec to complete the GSI channel reset sequence.  Either
	 * way we finish by suspending the channel again (if necessary)
	 * and re-enabling its doorbell engine.
	 */
	ret = gsi_channel_reset(ipa_ctx->gsi, ep->channel_id);
	if (!ret)
		msleep(CHANNEL_RESET_DELAY);
	goto out_suspend_again;

err_dma_free:
	dma_free_coherent(dev, size, virt, phys);
err_stop_channel:
	ipa_stop_gsi_channel(ep_id);
out_suspend_again:
	if (ep_suspended) {
		ipa_reg_endp_init_ctrl(&init_ctrl, true);
		ipa_write_reg_n_fields(IPA_ENDP_INIT_CTRL_N, ep_id, &init_ctrl);
	}
	/* Turn on the doorbell engine again */
	gsi_channel_config(ipa_ctx->gsi, ep->channel_id, true);

	return ret;
}

static void ipa_reset_gsi_channel(u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[ep_id];
	u32 aggr_active_bitmap = 0;

	/* For consumer endpoints, a hardware limitation prevents us
	 * from issuing a channel reset if aggregation is active.
	 * Check for this case, and if detected, perform a special
	 * reset sequence.  Otherwise just do a "normal" reset.
	 */
	if (ipa_consumer(ep->client))
		aggr_active_bitmap = ipa_read_reg(IPA_STATE_AGGR_ACTIVE);

	if (aggr_active_bitmap & BIT(ep_id)) {
		ipa_bug_on(ipa_channel_reset_aggr(ep_id));
	} else {
		/* In case the reset follows stop, need to wait 1 msec */
		msleep(CHANNEL_RESET_DELAY);
		ipa_bug_on(gsi_channel_reset(ipa_ctx->gsi, ep->channel_id));
	}
}

/**
 * ipa_ep_teardown() - Tear down an endpoint
 * @ep_id:	The endpoint to tear down
 */
void ipa_ep_teardown(struct ipa_context *ipa, u32 ep_id)
{
	struct ipa_ep_context *ep = &ipa->ep[ep_id];
	int ret;
	int i;

	if (ep->napi_enabled)
		while (ipa_ep_polling(ep))
			usleep_range(95, 105);

	if (ipa_producer(ep->client)) {
		bool empty = false;

		do {
			spin_lock_bh(&ep->sys->spinlock);
			empty = list_empty(&ep->sys->head_desc_list);
			spin_unlock_bh(&ep->sys->spinlock);
			if (!empty)
				usleep_range(95, 105);
		} while (!empty);
	}

	if (ipa_consumer(ep->client))
		cancel_delayed_work_sync(&ep->sys->rx.replenish_work);
	flush_workqueue(ep->sys->wq);
	/* channel stop might fail on timeout if IPA is busy */
	for (i = 0; i < IPA_GSI_CHANNEL_STOP_MAX_RETRY; i++) {
		ret = ipa_stop_gsi_channel(ep_id);
		if (!ret)
			break;
		ipa_bug_on(ret != -EAGAIN && ret != -ETIMEDOUT);
	}

	ipa_reset_gsi_channel(ep_id);
	gsi_channel_free(ipa->gsi, ep->channel_id);

	if (ipa_consumer(ep->client))
		ipa_cleanup_rx(ep->sys);

	ipa_ep_free(ipa, ep_id);
}

static int ipa_poll_gsi_pkt(struct ipa_sys_context *sys)
{
	if (sys->ep->bytes_xfered_valid) {
		sys->ep->bytes_xfered_valid = false;

		return (int)sys->ep->bytes_xfered;
	}

	return gsi_channel_poll(ipa_ctx->gsi, sys->ep->channel_id);
}

bool ipa_ep_polling(struct ipa_ep_context *ep)
{
	ipa_assert(ipa_consumer(ep->client));

	return !!atomic_read(&ep->sys->rx.curr_polling_state);
}

int ipa_dp_init(struct ipa_context *ipa)
{
	struct kmem_cache *cache;

	cache = kmem_cache_create("IPA_TX_PKT_WRAPPER",
				  sizeof(struct ipa_tx_pkt_wrapper),
				  0, 0, NULL);
	if (!cache)
		return -ENOMEM;
	ipa->tx_pkt_wrapper_cache = cache;

	cache = kmem_cache_create("IPA_RX_PKT_WRAPPER",
				  sizeof(struct ipa_rx_pkt_wrapper),
				  0, 0, NULL);
	if (!cache) {
		kmem_cache_destroy(ipa->tx_pkt_wrapper_cache);
		return -ENOMEM;
	}
	ipa->rx_pkt_wrapper_cache = cache;

	return 0;
}

void ipa_dp_exit(struct ipa_context *ipa)
{
	kmem_cache_destroy(ipa->rx_pkt_wrapper_cache);
	ipa->rx_pkt_wrapper_cache = NULL;
	kmem_cache_destroy(ipa->tx_pkt_wrapper_cache);
	ipa->tx_pkt_wrapper_cache = NULL;
}
