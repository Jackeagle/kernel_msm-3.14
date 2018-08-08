// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#define pr_fmt(fmt)    "ipa %s:%d " fmt, __func__, __LINE__

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dmapool.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include "ipa_i.h"
#include "ipahal.h"
#include "ipahal_fltrt.h"

/** struct ipa_tx_pkt_wrapper - IPA Tx packet wrapper
 * @type: specify if this packet is for the skb or immediate command
 * @mem: memory buffer used by this Tx packet
 * @work: work struct for current Tx packet
 * @link: linked to the wrappers on that pipe
 * @callback: IPA client provided callback
 * @user1: cookie1 for above callback
 * @user2: cookie2 for above callback
 * @sys: corresponding IPA sys context
 * @cnt: 1 for single transfers,
 * >1 and <0xFFFF for first of a "multiple" transfer,
 * 0xFFFF for last desc, 0 for rest of "multiple' transfer
 *
 * This struct can wrap both data packet and immediate command packet.
 */
struct ipa_tx_pkt_wrapper {
	enum ipa_desc_type type;
	struct ipa_mem_buffer mem;
	struct work_struct done_work;
	struct list_head link;
	void (*callback)(void *user1, int user2);
	void *user1;
	int user2;
	struct ipa_sys_context *sys;
	u32 cnt;
};

/** struct ipa_rx_pkt_wrapper - IPA Rx packet wrapper
 * @link: linked to the Rx packets on that pipe
 * @data: skb and DMA address of the received packet
 * @len: how many bytes are copied into skb's flat buffer
 */
struct ipa_rx_pkt_wrapper {
	struct list_head link;
	struct sk_buff *skb;
	dma_addr_t dma_addr;
	struct ipa_sys_context *sys;
};

/** struct ipa_sys_context - IPA GPI pipes context
 * @head_desc_list: header descriptors list
 * @len: the size of the above list
 * @spinlock: protects the list and its size
 * @ep: IPA EP context
 *
 * IPA context specific to the GPI pipes a.k.a LAN IN/OUT and WAN
 */
struct ipa_sys_context {
	u32 len;
	union {
		struct {	/* Consumer pipes only */
			u32 len_pending_xfer;
			atomic_t curr_polling_state;
			struct delayed_work switch_to_intr_work; /* sys->wq */
			int (*pyld_hdlr)(struct sk_buff *,
					 struct ipa_sys_context *);
			struct sk_buff *(*get_skb)(unsigned int, gfp_t);
			void (*free_skb)(struct sk_buff *);
			void (*free_wrapper)(struct ipa_rx_pkt_wrapper *);
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
		struct {	/* Producer pipes only */
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

/** struct ipa_dp - IPA data path information
 * @tx_pkt_wrapper_cache: Tx packets cache
 * @rx_pkt_wrapper_cache: Rx packets cache
 */
struct ipa_dp {
	struct kmem_cache *tx_pkt_wrapper_cache;
	struct kmem_cache *rx_pkt_wrapper_cache;
};

struct ipa_tag_completion {
	struct completion comp;
	atomic_t cnt;
};

#define IPA_QMAP_HEADER_LENGTH 4

#define IPA_WAN_AGGR_PKT_CNT 5
#define POLLING_INACTIVITY_RX 40
#define POLLING_MIN_SLEEP_RX 1010	/* microseconds */
#define POLLING_MAX_SLEEP_RX 1050	/* microseconds */

#define IPA_GENERIC_AGGR_BYTE_LIMIT 6
#define IPA_GENERIC_AGGR_TIME_LIMIT 1
#define IPA_GENERIC_AGGR_PKT_LIMIT 0

#define IPA_GENERIC_RX_BUFF_BASE_SZ 8192
#define IPA_REAL_GENERIC_RX_BUFF_SZ(X) (SKB_DATA_ALIGN(\
		(X) + NET_SKB_PAD) +\
		SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))
#define IPA_GENERIC_RX_BUFF_SZ(X) \
	({ typeof(X) _x = (X); (_x - (IPA_REAL_GENERIC_RX_BUFF_SZ(_x) - _x)); })
#define IPA_GENERIC_RX_BUFF_LIMIT (\
		IPA_REAL_GENERIC_RX_BUFF_SZ(\
		IPA_GENERIC_RX_BUFF_BASE_SZ) -\
		IPA_GENERIC_RX_BUFF_BASE_SZ)

/* less 1 nominal MTU (1500 bytes) rounded to units of KB */
#define IPA_MTU 1500
#define IPA_ADJUST_AGGR_BYTE_LIMIT(X) (((X) - IPA_MTU) / 1000)

#define IPA_RX_BUFF_CLIENT_HEADROOM 256

#define IPA_SIZE_DL_CSUM_META_TRAILER 8

#define IPA_GSI_MAX_CH_LOW_WEIGHT 15
#define IPA_GSI_EVT_RING_INT_MODT (32 * 1) /* 1ms under 32KHz clock */

#define IPA_DEFAULT_SYS_YELLOW_WM 32
#define IPA_REPL_XFER_THRESH 10

/* How long before sending an interrupting no-op to handle TX completions */
#define IPA_TX_NOP_DELAY_NS (2 * 1000 * 1000)	/* 2 msec */

static void ipa_rx_switch_to_intr_mode(struct ipa_sys_context *sys);

static struct sk_buff *ipa_get_skb_ipa_rx(unsigned int len, gfp_t flags);
static void ipa_replenish_rx_cache(struct ipa_sys_context *sys);
static void ipa_replenish_rx_work_func(struct work_struct *work);
static void ipa_wq_handle_rx(struct work_struct *work);
static void ipa_rx_common(struct ipa_sys_context *sys, u32 size);
static int ipa_assign_policy(struct ipa_sys_connect_params *in,
			     struct ipa_sys_context *sys);
static void ipa_cleanup_rx(struct ipa_sys_context *sys);
static int ipa_gsi_setup_channel(struct ipa_sys_connect_params *in,
				 struct ipa_ep_context *ep);
static int ipa_poll_gsi_pkt(struct ipa_sys_context *sys);
static struct ipa_tx_pkt_wrapper *tag_to_pointer_wa(u64 tag);

static u32 ipa_adjust_ra_buff_base_sz(u32 aggr_byte_limit);

static void
ipa_wq_write_done_common(struct ipa_sys_context *sys,
			 struct ipa_tx_pkt_wrapper *tx_pkt)
{
	struct device *dev = ipa_ctx->dev;
	struct ipa_tx_pkt_wrapper *next_pkt;
	int i, cnt;

	cnt = tx_pkt->cnt;
	ipa_debug_low("cnt: %d\n", cnt);
	for (i = 0; i < cnt; i++) {
		spin_lock_bh(&sys->spinlock);
		if (unlikely(list_empty(&sys->head_desc_list))) {
			spin_unlock_bh(&sys->spinlock);
			return;
		}
		next_pkt = list_next_entry(tx_pkt, link);
		list_del(&tx_pkt->link);
		sys->len--;
		spin_unlock_bh(&sys->spinlock);

		/* If DMA memory was mapped, unmap it */
		if (tx_pkt->mem.base) {
			if (tx_pkt->type != IPA_DATA_DESC_SKB_PAGED) {
				dma_unmap_single(dev, tx_pkt->mem.phys_base,
						 tx_pkt->mem.size,
						 DMA_TO_DEVICE);
			} else {
				dma_unmap_page(dev, tx_pkt->mem.phys_base,
					       tx_pkt->mem.size, DMA_TO_DEVICE);
			}
		}

		if (tx_pkt->callback)
			tx_pkt->callback(tx_pkt->user1, tx_pkt->user2);

		kmem_cache_free(ipa_ctx->dp->tx_pkt_wrapper_cache, tx_pkt);
		tx_pkt = next_pkt;
	}
}

static void
ipa_wq_write_done_status(int src_pipe, struct ipa_tx_pkt_wrapper *tx_pkt)
{
	struct ipa_sys_context *sys;

	WARN_ON(src_pipe >= ipa_ctx->ipa_num_pipes);

	if (!ipa_ctx->ep[src_pipe].status.status_en)
		return;

	sys = ipa_ctx->ep[src_pipe].sys;
	if (!sys)
		return;

	if (likely(tx_pkt))
		ipa_wq_write_done_common(sys, tx_pkt);
	else
		ipa_err("tx_pkt is NULL\n");
}

/** ipa_write_done() - this function will be (eventually) called when a Tx
 * operation is complete
 * * @done_work:	work_struct used by the work queue
 *
 * Will be called in deferred context.
 * - invoke the callback supplied by the client who sent this command
 * - iterate over all packets and validate that
 *   the order for sent packet is the same as expected
 * - delete all the tx packet descriptors from the system
 *   pipe context (not needed anymore)
 */
static void ipa_wq_write_done(struct work_struct *done_work)
{
	struct ipa_tx_pkt_wrapper *tx_pkt;
	struct ipa_sys_context *sys;
	struct ipa_tx_pkt_wrapper *this_pkt;

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

/** ipa_rx_poll() - Poll the rx packets from IPA HW.
 *
 * This function is executed in softirq context.
 *
 * Returns the number of received packets, and switches to interrupt
 * mode if that's less than weight.
 */
int ipa_rx_poll(u32 clnt_hdl, int weight)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[clnt_hdl];
	int cnt = 0;
	static int total_cnt;

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
	};

	if (cnt < weight) {
		ep->client_notify(ep->priv, IPA_CLIENT_COMP_NAPI, 0);
		ipa_rx_switch_to_intr_mode(ep->sys);

		/* Matching enable is in ipa_gsi_irq_rx_notify_cb() */
		ipa_client_remove();
	}

	return cnt;
}

static struct workqueue_struct *
ipa_alloc_workqueue(const char *name, enum ipa_client_type client)
{
	char namebuf[IPA_RESOURCE_NAME_MAX];
	unsigned int wq_flags = WQ_MEM_RECLAIM | WQ_UNBOUND;
	struct workqueue_struct *wq;
	int ret;

	ret = snprintf(namebuf, sizeof(namebuf), "%s%u", name, (u32)client);
	ipa_assert(ret < sizeof(namebuf));

	wq = alloc_workqueue(namebuf, wq_flags, 1);
	if (!wq)
		ipa_err("error creating wq %s for client %d\n", name, client);

	return wq;
}

/* Send an interrupting no-op request to a producer pipe.  Normally
 * an interrupt is generated upon completion of every transfer
 * performed by a pipe, but a producer pipe can be configured to
 * avoid getting these interrupts.  Instead, once a transfer has
 * been initiated, a no-op is scheduled to be sent after a short
 * delay.  This no-op request will interrupt when it is complete,
 * and in handling that interrupt, previously-completed transfers
 * will be handled as well.  If a no-op is already scheduled,
 * another is not initiated (there's only one pending at a time).
 */
static bool ipa_send_nop(struct ipa_sys_context *sys)
{
	unsigned long chan_id = sys->ep->gsi_chan_hdl;
	struct ipa_tx_pkt_wrapper *nop_pkt;
	struct gsi_xfer_elem nop_xfer = { };

	nop_pkt = kmem_cache_zalloc(ipa_ctx->dp->tx_pkt_wrapper_cache, GFP_KERNEL);
	if (!nop_pkt)
		return false;

	nop_pkt->type = IPA_DATA_DESC;
	/* No-op packet uses no memory for data */
	INIT_WORK(&nop_pkt->done_work, ipa_wq_write_done);
	nop_pkt->sys = sys;
	nop_pkt->cnt = 1;

	nop_xfer.type = GSI_XFER_ELEM_NOP;
	nop_xfer.flags = GSI_XFER_FLAG_EOT;
	nop_xfer.xfer_user_data = nop_pkt;

	spin_lock_bh(&sys->spinlock);
	list_add_tail(&nop_pkt->link, &sys->head_desc_list);
	spin_unlock_bh(&sys->spinlock);

	if (!gsi_queue_xfer(chan_id, 1, &nop_xfer, true))
		return true;	/* Success */

	spin_lock_bh(&sys->spinlock);
	list_del(&nop_pkt->link);
	spin_unlock_bh(&sys->spinlock);

	kmem_cache_free(ipa_ctx->dp->tx_pkt_wrapper_cache, nop_pkt);

	return false;
}

/* Try to send the no-op request.  If it fails, arrange to try again. */
static void ipa_send_nop_work(struct work_struct *nop_work)
{
	struct ipa_sys_context *sys;

	sys = container_of(nop_work, struct ipa_sys_context, tx.nop_work);

	/* If sending a no-op request fails, schedule another try */
	if (!ipa_send_nop(sys))
		queue_work(sys->wq, nop_work);
}

/* The delay before sending the no-op request is implemented by a
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

/* For some producer pipes we don't interrupt on completions.
 * Instead we schedule an interrupting NOP command to be issued on
 * the pipe after a short delay (if one is not already scheduled).
 * When the NOP completes it signals all preceding transfers have
 * completed also.
 */
static void ipa_no_intr_init(struct ipa_sys_context *sys)
{
	INIT_WORK(&sys->tx.nop_work, ipa_send_nop_work);
	atomic_set(&sys->tx.nop_pending, 0);
	hrtimer_init(&sys->tx.nop_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	sys->tx.nop_timer.function = ipa_nop_timer_expiry;
	sys->tx.no_intr = true;
}

/** ipa_send() - Send multiple descriptors in one HW transaction
 * @sys: system pipe context
 * @num_desc: number of packets
 * @desc: packets to send (may be immediate command or data)
 *
 * This function is used for GPI connection.
 * - ipa_tx_pkt_wrapper will be used for each ipa
 *   descriptor (allocated from wrappers cache)
 * - The wrapper struct will be configured for each ipa-desc payload and will
 *   contain information which will be later used by the user callbacks
 * - Each packet (command or data) that will be sent will also be saved in
 *   ipa_sys_context for later check that all data was sent
 *
 * Return codes: 0: success, -EFAULT: failure
 */
static int
ipa_send(struct ipa_sys_context *sys, u32 num_desc, struct ipa_desc *desc)
{
	struct device *dev = ipa_ctx->dev;
	struct ipa_ep_context *ep = sys->ep;
	struct ipa_tx_pkt_wrapper *tx_pkt, *tx_pkt_first;
	struct gsi_xfer_elem *xfer_elem;
	int i;
	int j;
	int result;

	ipa_assert(num_desc <= ipa_get_gsi_ep_info(ep->client)->ipa_if_tlv);

	xfer_elem = kcalloc(num_desc, sizeof(*xfer_elem), GFP_ATOMIC);
	if (!xfer_elem)
		return -ENOMEM;

	spin_lock_bh(&sys->spinlock);

	/* Within loop, all errors are allocation or DMA mapping */
	result = -ENOMEM;
	for (i = 0; i < num_desc; i++) {
		tx_pkt = kmem_cache_zalloc(ipa_ctx->dp->tx_pkt_wrapper_cache,
					   GFP_ATOMIC);
		if (!tx_pkt)
			goto failure;

		INIT_LIST_HEAD(&tx_pkt->link);

		if (i == 0) {
			tx_pkt_first = tx_pkt;
			tx_pkt->cnt = num_desc;
			INIT_WORK(&tx_pkt->done_work, ipa_wq_write_done);
		}

		tx_pkt->type = desc[i].type;

		if (desc[i].type != IPA_DATA_DESC_SKB_PAGED) {
			tx_pkt->mem.base = desc[i].pyld;
			tx_pkt->mem.size = desc[i].len;
			tx_pkt->mem.phys_base =
					dma_map_single(dev, tx_pkt->mem.base,
						       tx_pkt->mem.size,
						       DMA_TO_DEVICE);
		} else {
			tx_pkt->mem.base = desc[i].frag;
			tx_pkt->mem.size = desc[i].len;
			tx_pkt->mem.phys_base =
					skb_frag_dma_map(dev, desc[i].frag, 0,
							 tx_pkt->mem.size,
							 DMA_TO_DEVICE);
		}
		if (dma_mapping_error(dev, tx_pkt->mem.phys_base)) {
			ipa_err("failed to do dma map.\n");
			goto failure_dma_map;
		}

		tx_pkt->sys = sys;
		tx_pkt->callback = desc[i].callback;
		tx_pkt->user1 = desc[i].user1;
		tx_pkt->user2 = desc[i].user2;

		list_add_tail(&tx_pkt->link, &sys->head_desc_list);

		xfer_elem[i].addr = tx_pkt->mem.phys_base;

		/* Special treatment for immediate commands, where
		 * the structure of the descriptor is different
		 */
		if (desc[i].type == IPA_IMM_CMD_DESC) {
			xfer_elem[i].len = desc[i].opcode;
			xfer_elem[i].type = GSI_XFER_ELEM_IMME_CMD;
		} else {
			xfer_elem[i].len = desc[i].len;
			xfer_elem[i].type = GSI_XFER_ELEM_DATA;
		}

		if (i == (num_desc - 1)) {
			if (!sys->tx.no_intr) {
				xfer_elem[i].flags |= GSI_XFER_FLAG_EOT;
				xfer_elem[i].flags |= GSI_XFER_FLAG_BEI;
			}
			xfer_elem[i].xfer_user_data = tx_pkt_first;
		} else {
			xfer_elem[i].flags |= GSI_XFER_FLAG_CHAIN;
		}
	}

	ipa_debug_low("ch:%lu queue xfer\n", ep->gsi_chan_hdl);
	result = gsi_queue_xfer(ep->gsi_chan_hdl, num_desc, xfer_elem,
				true);
	if (result)
		goto failure;
	kfree(xfer_elem);

	spin_unlock_bh(&sys->spinlock);

	if (sys->tx.no_intr)
		ipa_nop_timer_schedule(sys);

	return 0;

failure_dma_map:
	kmem_cache_free(ipa_ctx->dp->tx_pkt_wrapper_cache, tx_pkt);

failure:
	tx_pkt = tx_pkt_first;
	for (j = 0; j < i; j++) {
		struct ipa_tx_pkt_wrapper *next_pkt;

		next_pkt = list_next_entry(tx_pkt, link);
		list_del(&tx_pkt->link);

		if (desc[j].type != IPA_DATA_DESC_SKB_PAGED) {
			dma_unmap_single(dev, tx_pkt->mem.phys_base,
					 tx_pkt->mem.size, DMA_TO_DEVICE);
		} else {
			dma_unmap_page(dev, tx_pkt->mem.phys_base,
				       tx_pkt->mem.size, DMA_TO_DEVICE);
		}
		kmem_cache_free(ipa_ctx->dp->tx_pkt_wrapper_cache, tx_pkt);
		tx_pkt = next_pkt;
	}

	kfree(xfer_elem);
	spin_unlock_bh(&sys->spinlock);

	return result;
}

/** ipa_send_cmd_timeout_complete - callback function which will be
 * called by the transport driver after an immediate command is complete.
 * This function will also free the completion object once it is done.
 * @tag_comp: pointer to the completion object
 * @ignored: parameter not used
 */
static void ipa_send_cmd_timeout_complete(void *tag_comp, int ignored)
{
	struct ipa_tag_completion *comp = tag_comp;

	complete(&comp->comp);
	if (!atomic_dec_return(&comp->cnt))
		kfree(comp);
}

/** ipa_send_cmd_timeout - send one immediate command with timeout
 * @desc:	descriptor structure
 * @timeout:	milliseconds to wait (or 0 to wait indefinitely)
 *
 * Send an immediate command, and wait for it to complete.  If
 * timeout is non-zero it indicates the number of milliseconds to
 * wait to receive the acknowledgement from the hardware before
 * timing out.  If 0 is supplied, wait will not time out.
 */
int ipa_send_cmd_timeout(struct ipa_desc *desc, u32 timeout)
{
	unsigned long timeout_jiffies = msecs_to_jiffies(timeout);
	struct ipa_tag_completion *comp;
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

	ep = ipa_get_ep_context(IPA_CLIENT_APPS_CMD_PROD);

	ret = ipa_send(ep->sys, 1, desc);
	if (ret) {
		/* Callback won't run; drop reference on its behalf */
		atomic_dec(&comp->cnt);
		goto out;
	}

	if (!timeout_jiffies)
		wait_for_completion(&comp->comp);
	else if (!wait_for_completion_timeout(&comp->comp, timeout_jiffies))
		ret = -ETIMEDOUT;
out:
	if (!atomic_dec_return(&comp->cnt))
		kfree(comp);

	return ret;
}

int ipa_send_cmd(struct ipa_desc *desc)
{
	int ret;

	ipa_client_add();

	ret = ipa_send_cmd_timeout(desc, 0);

	ipa_client_remove();

	return ret;
}

/** ipa_handle_rx_core() - The core functionality of packet reception. This
 * function is read from multiple code paths.
 *
 * All the packets on the Rx data path are received on the IPA_A5_LAN_WAN_IN
 * endpoint. The function runs as long as there are packets in the pipe.
 * For each packet:
 *  - Disconnect the packet from the system pipe linked list
 *  - Unmap the packets skb, make it non DMAable
 *  - Free the packet from the cache
 *  - Prepare a proper skb
 *  - Call the endpoints notify function, passing the skb in the parameters
 *  - Replenish the rx cache
 */
static int ipa_handle_rx_core(struct ipa_sys_context *sys)
{
	int ret;
	int cnt = 0;

	/* Stop if the leave polling state */
	while (ipa_ep_polling(sys->ep)) {
		ret = ipa_poll_gsi_pkt(sys);
		if (ret < 0)
			break;

		ipa_rx_common(sys, (u32)ret);

		++cnt;
	}
	return cnt;
}

/** ipa_rx_switch_to_intr_mode() - Operate the Rx data path in interrupt mode */
static void ipa_rx_switch_to_intr_mode(struct ipa_sys_context *sys)
{
	if (!atomic_xchg(&sys->rx.curr_polling_state, 0)) {
		ipa_err("already in intr mode\n");
		queue_delayed_work(sys->wq, &sys->rx.switch_to_intr_work,
				   msecs_to_jiffies(1));
		return;
	}
	ipa_dec_release_wakelock();
	gsi_channel_intr_enable(sys->ep->gsi_chan_hdl);
}

void ipa_rx_switch_to_poll_mode(struct ipa_sys_context *sys)
{
	if (atomic_xchg(&sys->rx.curr_polling_state, 1))
		return;
	gsi_channel_intr_disable(sys->ep->gsi_chan_hdl);
	ipa_inc_acquire_wakelock();
	queue_work(sys->wq, &sys->rx.work);
}

/** ipa_handle_rx() - handle packet reception. This function is executed in the
 * context of a work queue.
 * @work: work struct needed by the work queue
 *
 * ipa_handle_rx_core() is run in polling mode. After all packets has been
 * received, the driver switches back to interrupt mode.
 */
static void ipa_handle_rx(struct ipa_sys_context *sys)
{
	int inactive_cycles = 0;
	int cnt;

	ipa_client_add();
	do {
		cnt = ipa_handle_rx_core(sys);
		if (cnt == 0)
			inactive_cycles++;
		else
			inactive_cycles = 0;

		usleep_range(POLLING_MIN_SLEEP_RX, POLLING_MAX_SLEEP_RX);

		/* if pipe is out of buffers there is no point polling for
		 * completed descs; release the worker so delayed work can
		 * run in a timely manner
		 */
		if (sys->len - sys->rx.len_pending_xfer == 0)
			break;

	} while (inactive_cycles <= POLLING_INACTIVITY_RX);

	ipa_rx_switch_to_intr_mode(sys);
	ipa_client_remove();
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
	struct ipa_sys_context *sys;

	/* Caller will zero all "mutable" fields; we fill in the rest */
	sys = kmalloc(sizeof(*sys), GFP_KERNEL);
	if (!sys)
		return NULL;

	/* Caller assigns sys->ep = ep */
	INIT_LIST_HEAD(&sys->head_desc_list);
	spin_lock_init(&sys->spinlock);

	sys->wq = ipa_alloc_workqueue("ipawq", client);
	if (!sys->wq) {
		kfree(sys);
		return NULL;
	}

	return sys;
}

/** ipa_setup_sys_pipe() - Setup an IPA GPI pipe and perform
 * IPA EP configuration
 * @sys_in:	[in] input needed to setup the pipe and configure EP
 *
 *  - configure the end-point registers with the supplied
 *    parameters from the user.
 *  - Creates a GPI connection with IPA.
 *  - allocate descriptor FIFO
 *
 * Returns:	client handle on success, negative on failure
 */
int ipa_setup_sys_pipe(struct ipa_sys_connect_params *sys_in)
{
	u32 ipa_ep_idx = ipa_get_ep_mapping(sys_in->client);
	struct ipa_ep_context *ep = &ipa_ctx->ep[ipa_ep_idx];
	struct ipa_sys_context *sys;
	int ret;

	if (ep->valid)
		return -EINVAL;

	ipa_client_add();

	/* Reuse the endpoint's sys pointer if it is initialized */
	sys = ep->sys;
	if (!sys) {
		ret = -ENOMEM;
		sys = ipa_ep_sys_create(sys_in->client);
		if (!sys)
			goto err_client_remove;
		sys->ep = ep;
	}
	/* Zero the "mutable" part of the system context */
	memset(sys, 0, offsetof(struct ipa_sys_context, ep));

	/* Zero the endpoint structure and record its sys pointer */
	memset(ep, 0, sizeof(*ep));
	ep->sys = sys;

	if (ipa_assign_policy(sys_in, ep->sys)) {
		ipa_err("failed to sys ctx for client %d\n", sys_in->client);
		ret = -ENOMEM;
		goto err_client_remove;
	}

	ep->valid = true;
	ep->client = sys_in->client;
	ep->client_notify = sys_in->notify;
	ep->napi_enabled = sys_in->napi_enabled;
	ep->priv = sys_in->priv;

	ipa_cfg_ep(ipa_ep_idx, &sys_in->ipa_ep_cfg);

	ipa_cfg_ep_status(ipa_ep_idx, &ep->status);

	ipa_debug("ep %u configuration successful\n", ipa_ep_idx);

	ret = ipa_gsi_setup_channel(sys_in, ep);
	if (ret) {
		ipa_err("Failed to setup GSI channel\n");
		goto err_client_remove;
	}

	if (ipa_consumer(sys_in->client))
		ipa_replenish_rx_cache(ep->sys);

	ipa_client_remove();

	ipa_debug("client %d (ep: %u) connected sys=%p\n", sys_in->client,
		  ipa_ep_idx, ep->sys);

	return ipa_ep_idx;

err_client_remove:
	ipa_client_remove();

	return ret;
}

/** ipa_teardown_sys_pipe() - Teardown the GPI pipe and cleanup IPA EP
 * @clnt_hdl:	[in] the handle obtained from ipa_setup_sys_pipe
 *
 * Returns:	0 on success, negative on failure
 */
void ipa_teardown_sys_pipe(u32 clnt_hdl)
{
	struct ipa_ep_context *ep = &ipa_ctx->ep[clnt_hdl];
	int empty;
	int result;
	int i;

	ipa_client_add();

	if (ep->napi_enabled) {
		do {
			usleep_range(95, 105);
		} while (ipa_ep_polling(ep));
	}

	if (ipa_producer(ep->client)) {
		do {
			spin_lock_bh(&ep->sys->spinlock);
			empty = list_empty(&ep->sys->head_desc_list);
			spin_unlock_bh(&ep->sys->spinlock);
			if (!empty)
				usleep_range(95, 105);
			else
				break;
		} while (1);
	}

	if (ipa_consumer(ep->client))
		cancel_delayed_work_sync(&ep->sys->rx.replenish_work);
	flush_workqueue(ep->sys->wq);
	/* channel stop might fail on timeout if IPA is busy */
	for (i = 0; i < IPA_GSI_CHANNEL_STOP_MAX_RETRY; i++) {
		result = ipa_stop_gsi_channel(clnt_hdl);
		if (!result)
			break;
		ipa_bug_on(result != -EAGAIN && result != -ETIMEDOUT);
	}

	ipa_reset_gsi_channel(clnt_hdl);
	gsi_dealloc_channel(ep->gsi_chan_hdl);
	gsi_reset_evt_ring(ep->gsi_evt_ring_hdl);
	gsi_dealloc_evt_ring(ep->gsi_evt_ring_hdl);

	if (ipa_consumer(ep->client))
		ipa_cleanup_rx(ep->sys);

	ep->valid = false;
	ipa_client_remove();

	ipa_debug("client (ep: %d) disconnected\n", clnt_hdl);
}

/** ipa_tx_dp_complete() - Callback function which will call the
 * user supplied callback function to release the skb, or release it on
 * its own if no callback function was supplied.
 * @user1
 * @user2
 *
 * This notified callback is for the destination client.
 */
static void ipa_tx_dp_complete(void *user1, int user2)
{
	struct sk_buff *skb = (struct sk_buff *)user1;
	int ep_idx = user2;

	ipa_debug_low("skb=%p ep=%d\n", skb, ep_idx);

	if (ipa_ctx->ep[ep_idx].client_notify) {
		void *priv = ipa_ctx->ep[ep_idx].priv;
		unsigned long data = (unsigned long)skb;

		ipa_ctx->ep[ep_idx].client_notify(priv, IPA_WRITE_DONE, data);
	} else {
		dev_kfree_skb_any(skb);
	}
}

void ipa_tx_cmd_comp(void *user1, int user2)
{
	ipahal_destroy_imm_cmd(user1);
}

/** ipa_tx_dp() - Data-path tx handler for APPS_WAN_PROD client
 *
 * @client:	[in] which IPA client is sending packets (WAN producer)
 * @skb:	[in] the packet to send
 *
 * Data-path transmit handler.  This is currently used only for the
 * for the WLAN hardware data-path.
 *
 * Returns:	0 on success, negative on failure
 */
int ipa_tx_dp(enum ipa_client_type client, struct sk_buff *skb)
{
	struct ipa_desc _desc = { };
	struct ipa_desc *desc = &_desc;	/* Default, linear case */
	const struct ipa_gsi_ep_config *gsi_ep;
	u32 src_ep_idx;
	int data_idx;
	u32 nr_frags;
	u32 f;
	int ret;

	if (!skb->len)
		return -EINVAL;

	src_ep_idx = ipa_get_ep_mapping(client);
	gsi_ep = ipa_get_gsi_ep_info(ipa_ctx->ep[src_ep_idx].client);

	/* Make sure source pipe's TLV FIFO has enough entries to
	 * hold the linear portion of the skb and all its frags.
	 * If not, see if we can linearize it before giving up.
	 */
	nr_frags = skb_shinfo(skb)->nr_frags;
	if (1 + nr_frags > gsi_ep->ipa_if_tlv) {
		if (skb_linearize(skb))
			return -ENOMEM;
		nr_frags = 0;
	}
	if (nr_frags) {
		desc = kcalloc(1 + nr_frags, sizeof(*desc), GFP_ATOMIC);
		if (!desc)
			return -ENOMEM;
	}

	/* Fill in the IPA request descriptors--one for the linear
	 * data in the skb, one each for each of its fragments.
	 */
	data_idx = 0;
	desc[data_idx].pyld = skb->data;
	desc[data_idx].len = skb_headlen(skb);
	desc[data_idx].type = IPA_DATA_DESC_SKB;
	for (f = 0; f < nr_frags; f++) {
		data_idx++;
		desc[data_idx].frag = &skb_shinfo(skb)->frags[f];
		desc[data_idx].type = IPA_DATA_DESC_SKB_PAGED;
		desc[data_idx].len = skb_frag_size(desc[data_idx].frag);
	}

	/* Have the skb be freed after the last descriptor completes. */
	desc[data_idx].callback = ipa_tx_dp_complete;
	desc[data_idx].user1 = skb;
	desc[data_idx].user2 = src_ep_idx;

	ret = ipa_send(ipa_ctx->ep[src_ep_idx].sys, data_idx + 1, desc);

	if (nr_frags)
		kfree(desc);

	return ret;
}

static void ipa_wq_handle_rx(struct work_struct *work)
{
	struct ipa_sys_context *sys;

	sys = container_of(work, struct ipa_sys_context, rx.work);

	if (sys->ep->napi_enabled) {
		ipa_client_add();
		sys->ep->client_notify(sys->ep->priv, IPA_CLIENT_START_POLL, 0);
	} else {
		ipa_handle_rx(sys);
	}
}

static int
queue_rx_cache(struct ipa_sys_context *sys, struct ipa_rx_pkt_wrapper *rx_pkt)
{
	struct gsi_xfer_elem gsi_xfer_elem;
	int ret;

	/* Don't bother zeroing this; we fill all fields */
	gsi_xfer_elem.addr = rx_pkt->dma_addr;
	gsi_xfer_elem.len = sys->rx.buff_sz;
	gsi_xfer_elem.flags = GSI_XFER_FLAG_EOT;
	gsi_xfer_elem.flags |= GSI_XFER_FLAG_EOB;
	gsi_xfer_elem.type = GSI_XFER_ELEM_DATA;
	gsi_xfer_elem.xfer_user_data = rx_pkt;

	ret = gsi_queue_xfer(sys->ep->gsi_chan_hdl, 1, &gsi_xfer_elem, false);
	if (ret)
		return ret;

	/* As doorbell is a costly operation, notify to GSI
	 * of new buffers if threshold is exceeded
	 */
	if (++sys->rx.len_pending_xfer >= IPA_REPL_XFER_THRESH) {
		sys->rx.len_pending_xfer = 0;
		gsi_start_xfer(sys->ep->gsi_chan_hdl);
	}

	return 0;
}

/** ipa_replenish_rx_cache() - Replenish the Rx packets cache.
 *
 * The function allocates buffers in the rx_pkt_wrapper_cache cache until there
 * are IPA_RX_POOL_CEIL buffers in the cache.
 *   - Allocate a buffer in the cache
 *   - Initialized the packets link
 *   - Initialize the packets work struct
 *   - Allocate the packets socket buffer (skb)
 *   - Fill the packets skb with data
 *   - Make the packet DMAable
 *   - Add the packet to the system pipe linked list
 */
static void ipa_replenish_rx_cache(struct ipa_sys_context *sys)
{
	struct device *dev = ipa_ctx->dev;
	void *ptr;
	struct ipa_rx_pkt_wrapper *rx_pkt;
	int ret;
	int rx_len_cached = 0;
	gfp_t flag = GFP_NOWAIT | __GFP_NOWARN;

	rx_len_cached = sys->len;

	while (rx_len_cached < sys->rx.pool_sz) {
		rx_pkt = kmem_cache_zalloc(ipa_ctx->dp->rx_pkt_wrapper_cache, flag);
		if (!rx_pkt)
			goto fail_kmem_cache_alloc;

		INIT_LIST_HEAD(&rx_pkt->link);
		rx_pkt->sys = sys;

		rx_pkt->skb = sys->rx.get_skb(sys->rx.buff_sz, flag);
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
	sys->rx.free_skb(rx_pkt->skb);
fail_skb_alloc:
	kmem_cache_free(ipa_ctx->dp->rx_pkt_wrapper_cache, rx_pkt);
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
	ipa_client_add();
	ipa_replenish_rx_cache(sys);
	ipa_client_remove();
}

/** ipa_cleanup_rx() - release RX queue resources */
static void ipa_cleanup_rx(struct ipa_sys_context *sys)
{
	struct device *dev = ipa_ctx->dev;
	struct ipa_rx_pkt_wrapper *rx_pkt;
	struct ipa_rx_pkt_wrapper *r;

	list_for_each_entry_safe(rx_pkt, r, &sys->head_desc_list, link) {
		list_del(&rx_pkt->link);
		dma_unmap_single(dev, rx_pkt->dma_addr, sys->rx.buff_sz,
				 DMA_FROM_DEVICE);
		sys->rx.free_skb(rx_pkt->skb);
		kmem_cache_free(ipa_ctx->dp->rx_pkt_wrapper_cache, rx_pkt);
	}
}

static struct sk_buff *ipa_skb_copy_for_client(struct sk_buff *skb, int len)
{
	struct sk_buff *skb2 = NULL;

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

static bool ipa_status_opcode_supported(enum ipahal_pkt_status_opcode opcode)
{
	return opcode == IPAHAL_PKT_STATUS_OPCODE_PACKET ||
		opcode == IPAHAL_PKT_STATUS_OPCODE_DROPPED_PACKET ||
		opcode == IPAHAL_PKT_STATUS_OPCODE_SUSPENDED_PACKET ||
		opcode == IPAHAL_PKT_STATUS_OPCODE_PACKET_2ND_PASS;
}

static int
ipa_lan_rx_pyld_hdlr(struct sk_buff *skb, struct ipa_sys_context *sys)
{
	int rc = 0;
	struct ipahal_pkt_status status;
	u32 pkt_status_sz;
	struct sk_buff *skb2;
	int pad_len_byte;
	int len;
	int len2;
	unsigned char *buf;
	int src_pipe;
	unsigned int used = *(unsigned int *)skb->cb;
	unsigned int used_align = ALIGN(used, 32);
	unsigned long unused = IPA_GENERIC_RX_BUFF_BASE_SZ - used;
	struct ipa_tx_pkt_wrapper *tx_pkt = NULL;

	if (skb->len == 0) {
		ipa_err("ZLT\n");
		return rc;
	}

	if (sys->rx.len_partial) {
		buf = skb_push(skb, sys->rx.len_partial);
		memcpy(buf, sys->rx.prev_skb->data, sys->rx.len_partial);
		sys->rx.len_partial = 0;
		sys->rx.free_skb(sys->rx.prev_skb);
		sys->rx.prev_skb = NULL;
		goto begin;
	}

	/* this pipe has TX comp (status only) + mux-ed LAN RX data
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
				skb2 = skb_copy_expand(sys->rx.prev_skb, 0,
						       skb->len, GFP_KERNEL);
				if (likely(skb2)) {
					memcpy(skb_put(skb2, skb->len),
					       skb->data, skb->len);
				} else {
					ipa_err("copy expand failed\n");
				}
				dev_kfree_skb_any(sys->rx.prev_skb);
				sys->rx.prev_skb = skb2;
			}
			sys->rx.len_rem -= skb->len;
			return rc;
		}
	}

begin:
	pkt_status_sz = ipahal_pkt_status_get_size();
	while (skb->len) {
		sys->rx.drop_packet = false;

		if (skb->len < pkt_status_sz) {
			WARN_ON(sys->rx.prev_skb);
			sys->rx.prev_skb = skb_copy(skb, GFP_KERNEL);
			sys->rx.len_partial = skb->len;
			return rc;
		}

		ipahal_pkt_status_parse(skb->data, &status);

		if (!ipa_status_opcode_supported(status.status_opcode)) {
			ipa_err("unsupported opcode(%d)\n",
				status.status_opcode);
			skb_pull(skb, pkt_status_sz);
			continue;
		}

		if (status.endp_dest_idx >= ipa_ctx->ipa_num_pipes ||
		    status.endp_src_idx >= ipa_ctx->ipa_num_pipes) {
			ipa_err("status fields invalid\n");
			ipa_err("STATUS opcode=%d src=%d dst=%d len=%d\n",
				status.status_opcode, status.endp_src_idx,
				status.endp_dest_idx, status.pkt_len);
			ipa_bug();
		}
		if (status.status_mask & IPAHAL_PKT_STATUS_MASK_TAG_VALID) {
			struct ipa_tag_completion *comp;

			if (status.tag_info == IPA_COOKIE) {
				skb_pull(skb, pkt_status_sz);
				if (skb->len < sizeof(comp)) {
					ipa_err("TAG arrived without packet\n");
					return rc;
				}
				memcpy(&comp, skb->data, sizeof(comp));
				skb_pull(skb, sizeof(comp) +
						IPA_SIZE_DL_CSUM_META_TRAILER);
				complete(&comp->comp);
				if (atomic_dec_return(&comp->cnt) == 0)
					kfree(comp);
				continue;
			} else {
				tx_pkt = tag_to_pointer_wa(status.tag_info);
			}
		}
		if (status.pkt_len == 0) {
			skb_pull(skb, pkt_status_sz);
			continue;
		}

		if (status.endp_dest_idx == (sys->ep - ipa_ctx->ep)) {
			/* RX data */
			src_pipe = status.endp_src_idx;

			/* A packet which is received back to the AP after
			 * there was no route match.
			 */

			if (status.exception ==
				IPAHAL_PKT_STATUS_EXCEPTION_NONE &&
				ipahal_is_rule_miss_id(status.rt_rule_id))
				sys->rx.drop_packet = true;
			if (skb->len == pkt_status_sz &&
			    status.exception ==
					IPAHAL_PKT_STATUS_EXCEPTION_NONE) {
				WARN_ON(sys->rx.prev_skb);
				sys->rx.prev_skb = skb_copy(skb, GFP_KERNEL);
				sys->rx.len_partial = skb->len;
				return rc;
			}

			pad_len_byte = ((status.pkt_len + 3) & ~3) -
					status.pkt_len;

			len = status.pkt_len + pad_len_byte +
				IPA_SIZE_DL_CSUM_META_TRAILER;

			if (status.exception ==
					IPAHAL_PKT_STATUS_EXCEPTION_DEAGGR) {
				sys->rx.drop_packet = true;
			}

			len2 = min(status.pkt_len + pkt_status_sz, skb->len);
			skb2 = ipa_skb_copy_for_client(skb, len2);
			if (likely(skb2)) {
				if (skb->len < len + pkt_status_sz) {
					sys->rx.prev_skb = skb2;
					sys->rx.len_rem = len - skb->len +
						pkt_status_sz;
					sys->rx.len_pad = pad_len_byte;
					skb_pull(skb, skb->len);
				} else {
					skb_trim(skb2, status.pkt_len +
							pkt_status_sz);
					if (sys->rx.drop_packet) {
						dev_kfree_skb_any(skb2);
					} else if (status.pkt_len >
						   IPA_GENERIC_AGGR_BYTE_LIMIT *
						   1024) {
						ipa_err("packet size invalid\n");
						ipa_err("STATUS opcode=%d\n",
							status.status_opcode);
						ipa_err("src=%d dst=%d len=%d\n",
							status.endp_src_idx,
							status.endp_dest_idx,
							status.pkt_len);
						ipa_bug();
					} else {
						skb2->truesize =
							skb2->len +
							sizeof(struct sk_buff) +
							(ALIGN(len +
							pkt_status_sz, 32) *
							unused / used_align);
						sys->ep->client_notify(
							sys->ep->priv,
							IPA_RECEIVE,
							(unsigned long)(skb2));
					}
					skb_pull(skb, len + pkt_status_sz);
				}
			} else {
				ipa_err("fail to alloc skb\n");
				if (skb->len < len) {
					sys->rx.prev_skb = NULL;
					sys->rx.len_rem = len - skb->len +
						pkt_status_sz;
					sys->rx.len_pad = pad_len_byte;
					skb_pull(skb, skb->len);
				} else {
					skb_pull(skb, len + pkt_status_sz);
				}
			}
			/* TX comp */
			ipa_wq_write_done_status(src_pipe, tx_pkt);
		} else {
			/* TX comp */
			ipa_wq_write_done_status(status.endp_src_idx, tx_pkt);
			skb_pull(skb, pkt_status_sz);
		}
	};

	return rc;
}

static struct sk_buff *ipa_join_prev_skb(struct sk_buff *prev_skb,
					 struct sk_buff *skb, unsigned int len)
{
	struct sk_buff *skb2;

	skb2 = skb_copy_expand(prev_skb, 0, len, GFP_KERNEL);
	if (likely(skb2)) {
		memcpy(skb_put(skb2, len), skb->data, len);
	} else {
		ipa_err("copy expand failed\n");
		skb2 = NULL;
	}
	dev_kfree_skb_any(prev_skb);

	return skb2;
}

static void
ipa_wan_rx_handle_splt_pyld(struct sk_buff *skb, struct ipa_sys_context *sys)
{
	struct sk_buff *skb2;

	ipa_debug_low("rem %d skb %d\n", sys->rx.len_rem, skb->len);
	if (sys->rx.len_rem <= skb->len) {
		if (sys->rx.prev_skb) {
			skb2 = ipa_join_prev_skb(sys->rx.prev_skb, skb,
						 sys->rx.len_rem);
			if (likely(skb2)) {
				ipa_debug_low(
					"removing Status element from skb and sending to WAN client");
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
			skb2 = ipa_join_prev_skb(sys->rx.prev_skb, skb, skb->len);
			sys->rx.prev_skb = skb2;
		}
		sys->rx.len_rem -= skb->len;
		skb_pull(skb, skb->len);
	}
}

static int
ipa_wan_rx_pyld_hdlr(struct sk_buff *skb, struct ipa_sys_context *sys)
{
	int rc = 0;
	struct ipahal_pkt_status status;
	unsigned char *skb_data;
	u32 pkt_status_sz;
	struct sk_buff *skb2;
	u16 pkt_len_with_pad;
	u32 qmap_hdr;
	int checksum;
	int frame_len;
	int ep_idx;
	unsigned int used = *(unsigned int *)skb->cb;
	unsigned int used_align = ALIGN(used, 32);
	unsigned long unused = IPA_GENERIC_RX_BUFF_BASE_SZ - used;

	if (skb->len == 0) {
		ipa_err("ZLT\n");
		goto bail;
	}

	if (ipa_ctx->ipa_client_apps_wan_cons_agg_gro) {
		sys->ep->client_notify(sys->ep->priv, IPA_RECEIVE,
				       (unsigned long)(skb));
		return rc;
	}

	/* payload splits across 2 buff or more,
	 * take the start of the payload from rx.prev_skb
	 */
	if (sys->rx.len_rem)
		ipa_wan_rx_handle_splt_pyld(skb, sys);

	pkt_status_sz = ipahal_pkt_status_get_size();
	while (skb->len) {
		u32 status_mask;

		if (skb->len < pkt_status_sz) {
			ipa_err("status straddles buffer\n");
			WARN_ON(1);
			goto bail;
		}
		ipahal_pkt_status_parse(skb->data, &status);
		skb_data = skb->data;

		if (!ipa_status_opcode_supported(status.status_opcode) ||
			status.status_opcode ==
				IPAHAL_PKT_STATUS_OPCODE_SUSPENDED_PACKET) {
			ipa_err("unsupported opcode(%d)\n",
				status.status_opcode);
			skb_pull(skb, pkt_status_sz);
			continue;
		}

		if (status.endp_dest_idx >= ipa_ctx->ipa_num_pipes ||
		    status.endp_src_idx >= ipa_ctx->ipa_num_pipes ||
		    status.pkt_len > IPA_GENERIC_AGGR_BYTE_LIMIT * 1024) {
			ipa_err("status fields invalid\n");
			WARN_ON(1);
			goto bail;
		}
		if (status.pkt_len == 0) {
			skb_pull(skb, pkt_status_sz);
			continue;
		}
		ep_idx = ipa_get_ep_mapping(IPA_CLIENT_APPS_WAN_CONS);
		if (status.endp_dest_idx != ep_idx) {
			ipa_err("expected endp_dest_idx %d received %d\n",
				ep_idx, status.endp_dest_idx);
			WARN_ON(1);
			goto bail;
		}
		/* RX data */
		if (skb->len == pkt_status_sz) {
			ipa_err("Ins header in next buffer\n");
			WARN_ON(1);
			goto bail;
		}
		qmap_hdr = *(u32 *)(skb_data + pkt_status_sz);

		/* Take the pkt_len_with_pad from the last 2 bytes of the QMAP
		 * header
		 */
		/*QMAP is BE: convert the pkt_len field from BE to LE*/
		pkt_len_with_pad = ntohs((qmap_hdr >> 16) & 0xffff);
		/*get the CHECKSUM_PROCESS bit*/
		status_mask = status.status_mask;
		checksum = status_mask & IPAHAL_PKT_STATUS_MASK_CKSUM_PROCESS;

		frame_len = pkt_status_sz + IPA_QMAP_HEADER_LENGTH +
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
				skb_pull(skb2, pkt_status_sz);
				skb2->truesize = skb2->len +
					sizeof(struct sk_buff) +
					(ALIGN(frame_len, 32) *
					 unused / used_align);
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
	};
bail:
	sys->rx.free_skb(skb);
	return rc;
}

static struct sk_buff *ipa_get_skb_ipa_rx(unsigned int len, gfp_t flags)
{
	return __dev_alloc_skb(len, flags);
}

static void ipa_free_skb_rx(struct sk_buff *skb)
{
	dev_kfree_skb_any(skb);
}

void ipa_lan_rx_cb(void *priv, enum ipa_dp_evt_type evt, unsigned long data)
{
	struct sk_buff *rx_skb = (struct sk_buff *)data;
	struct ipahal_pkt_status status;
	struct ipa_ep_context *ep;
	unsigned int src_pipe;
	u32 metadata;

	ipahal_pkt_status_parse(rx_skb->data, &status);
	src_pipe = status.endp_src_idx;
	metadata = status.metadata;
	ep = &ipa_ctx->ep[src_pipe];
	if (src_pipe >= ipa_ctx->ipa_num_pipes || !ep->valid ||
	    !ep->client_notify) {
		ipa_err("drop pipe=%d ep_valid=%s client_notify=%p\n",
			src_pipe, ep->valid ? "true" : "false",
			ep->client_notify);
		dev_kfree_skb_any(rx_skb);
		return;
	}

	/* Consume the status packet, and if no exception, the header */
	skb_pull(rx_skb, ipahal_pkt_status_get_size());
	if (status.exception == IPAHAL_PKT_STATUS_EXCEPTION_NONE)
		skb_pull(rx_skb, IPA_LAN_RX_HEADER_LENGTH);

	/* Metadata Info
	 *  ------------------------------------------
	 *  |	3     |	  2	|    1	      |	 0   |
	 *  | fw_desc | vdev_id | qmap mux id | Resv |
	 *  ------------------------------------------
	 */
	*(u16 *)rx_skb->cb = ((metadata >> 16) & 0xFFFF);
	ipa_debug_low("meta_data: 0x%x cb: 0x%x\n", metadata,
		      *(u32 *)rx_skb->cb);

	ep->client_notify(ep->priv, IPA_RECEIVE, (unsigned long)(rx_skb));
}

static void ipa_rx_common(struct ipa_sys_context *sys, u32 size)
{
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
	dma_unmap_single(ipa_ctx->dev, rx_pkt->dma_addr, sys->rx.buff_sz,
			 DMA_FROM_DEVICE);

	skb_trim(rx_skb, size);

	*(unsigned int *)rx_skb->cb = rx_skb->len;
	rx_skb->truesize = size + sizeof(struct sk_buff);

	sys->rx.pyld_hdlr(rx_skb, sys);
	sys->rx.free_wrapper(rx_pkt);
	ipa_replenish_rx_cache(sys);
}

static void ipa_free_rx_wrapper(struct ipa_rx_pkt_wrapper *rk_pkt)
{
	kmem_cache_free(ipa_ctx->dp->rx_pkt_wrapper_cache, rk_pkt);
}

static int ipa_assign_policy(struct ipa_sys_connect_params *in,
			     struct ipa_sys_context *sys)
{
	struct ipa_ep_cfg_aggr *ep_cfg_aggr;

	if (in->client == IPA_CLIENT_APPS_CMD_PROD)
		return 0;

	if (in->client == IPA_CLIENT_APPS_WAN_PROD) {
		/* enable source notification status for exception packets
		 * (i.e. QMAP commands) to be routed to modem.
		 */
		sys->ep->status.status_en = true;
		sys->ep->status.status_ep =
			ipa_get_ep_mapping(IPA_CLIENT_Q6_WAN_CONS);

		/* For the WAN producer, use a deferred interrupting no-op */
		ipa_no_intr_init(sys);

		return 0;
	}

	/* Client is a consumer (APPS_LAN_CONS or APPS_WAN_CONS) */
	sys->ep->status.status_en = true;

	INIT_WORK(&sys->rx.work, ipa_wq_handle_rx);
	INIT_DELAYED_WORK(&sys->rx.switch_to_intr_work,
			  ipa_switch_to_intr_rx_work_func);
	INIT_DELAYED_WORK(&sys->rx.replenish_work,
			  ipa_replenish_rx_work_func);

	atomic_set(&sys->rx.curr_polling_state, 0);
	sys->rx.buff_sz = IPA_GENERIC_RX_BUFF_SZ(IPA_GENERIC_RX_BUFF_BASE_SZ);
	sys->rx.pool_sz = IPA_GENERIC_RX_POOL_SZ;
	sys->rx.get_skb = ipa_get_skb_ipa_rx;
	sys->rx.free_skb = ipa_free_skb_rx;

	ep_cfg_aggr = &in->ipa_ep_cfg.aggr;
	ep_cfg_aggr->aggr_en = IPA_ENABLE_AGGR;
	ep_cfg_aggr->aggr = IPA_GENERIC;
	ep_cfg_aggr->aggr_time_limit = IPA_GENERIC_AGGR_TIME_LIMIT;
	sys->rx.free_wrapper = ipa_free_rx_wrapper;

	if (in->client == IPA_CLIENT_APPS_LAN_CONS) {
		sys->rx.pyld_hdlr = ipa_lan_rx_pyld_hdlr;
		ep_cfg_aggr->aggr_byte_limit = IPA_GENERIC_AGGR_BYTE_LIMIT;
		ep_cfg_aggr->aggr_pkt_limit = IPA_GENERIC_AGGR_PKT_LIMIT;

		return 0;
	}

	/* in->client == IPA_CLIENT_APPS_WAN_CONS */
	sys->rx.pyld_hdlr = ipa_wan_rx_pyld_hdlr;

	ep_cfg_aggr->aggr_sw_eof_active = true;
	if (ipa_ctx->ipa_client_apps_wan_cons_agg_gro) {
		u32 limit;
		u32 adjusted;

		limit = ep_cfg_aggr->aggr_byte_limit;
		adjusted = ipa_adjust_ra_buff_base_sz(limit);

		/* disable ipa_status */
		sys->ep->status.status_en = false;

		ipa_err("get close-by %u\n", adjusted);
		adjusted = IPA_GENERIC_RX_BUFF_SZ(adjusted);
		ipa_err("set rx.buff_sz %u\n", adjusted);
		sys->rx.buff_sz = adjusted;

		if (sys->rx.buff_sz < limit)
			limit = sys->rx.buff_sz;
		limit = IPA_ADJUST_AGGR_BYTE_LIMIT(limit);
		ipa_err("set aggr_limit %u\n", limit);
		ep_cfg_aggr->aggr_byte_limit = limit;
	} else {
		ep_cfg_aggr->aggr_byte_limit = IPA_GENERIC_AGGR_BYTE_LIMIT;
		ep_cfg_aggr->aggr_pkt_limit = IPA_GENERIC_AGGR_PKT_LIMIT;
	}

	return 0;
}

void ipa_gsi_irq_tx_notify_cb(void *xfer_data)
{
	struct ipa_tx_pkt_wrapper *tx_pkt = xfer_data;

	ipa_debug_low("event EOT notified\n");

	queue_work(tx_pkt->sys->wq, &tx_pkt->done_work);
}

void ipa_gsi_irq_rx_notify_cb(void *chan_data, u16 count)
{
	struct ipa_sys_context *sys = chan_data;

	sys->ep->bytes_xfered_valid = true;
	sys->ep->bytes_xfered = count;

	ipa_rx_switch_to_poll_mode(sys);
}

/* GSI ring length is calculated based on the fifo_count which
 * defines the descriptor FIFO.
 * For producer pipes there is also an additional descriptor
 * for TAG STATUS immediate command.  An exception to this is the
 * APPS_WAN_PROD pipe, which uses event ring rather than TAG STATUS
 * based completions.
 */
static u32
ipa_gsi_ring_count(enum ipa_client_type client, u32 fifo_count)
{
	if (client == IPA_CLIENT_APPS_CMD_PROD)
		return 4 * fifo_count;

	return 2 * fifo_count;
}

/* Returns the event ring handle to use for the given endpoint
 * context, or a negative error code if an error occurs.
 *
 * If successful, the returned handle will be either the common
 * event ring handle or a new handle.  Caller is responsible for
 * deallocating the event ring *unless* it is the common one.
 */
static long evt_ring_hdl_get(struct ipa_ep_context *ep, u32 fifo_count)
{
	u32 ring_count;
	u16 modt = ep->sys->tx.no_intr ? 0 : IPA_GSI_EVT_RING_INT_MODT;

	ipa_debug("client=%d moderation threshold cycles=%u cnt=1\n",
		  ep->client, modt);

	ring_count = ipa_gsi_ring_count(ep->client, fifo_count);

	return gsi_alloc_evt_ring(ring_count, modt);
}

static int ipa_gsi_setup_channel(struct ipa_sys_connect_params *in,
				 struct ipa_ep_context *ep)
{
	struct gsi_chan_props gsi_channel_props = { };
	const struct ipa_gsi_ep_config *gsi_ep_info;
	int result;

	result = evt_ring_hdl_get(ep, in->fifo_count);
	if (result < 0)
		return result;
	ep->gsi_evt_ring_hdl = result;

	gsi_ep_info = ipa_get_gsi_ep_info(ep->client);

	gsi_channel_props.from_gsi = ipa_consumer(ep->client);
	gsi_channel_props.ch_id = gsi_ep_info->ipa_gsi_chan_num;
	gsi_channel_props.evt_ring_hdl = ep->gsi_evt_ring_hdl;
	gsi_channel_props.use_db_engine = true;
	if (ep->client == IPA_CLIENT_APPS_CMD_PROD)
		gsi_channel_props.low_weight = IPA_GSI_MAX_CH_LOW_WEIGHT;
	else
		gsi_channel_props.low_weight = 1;
	gsi_channel_props.chan_user_data = ep->sys;

	gsi_channel_props.ring_count = ipa_gsi_ring_count(ep->client,
							    in->fifo_count);

	result = gsi_alloc_channel(&gsi_channel_props);
	if (result < 0)
		goto fail_alloc_channel;
	ep->gsi_chan_hdl = result;

	result = gsi_write_channel_scratch(ep->gsi_chan_hdl,
					   gsi_ep_info->ipa_if_tlv);
	if (result) {
		ipa_err("failed to write scratch %d\n", result);
		goto fail_write_channel_scratch;
	}

	result = gsi_start_channel(ep->gsi_chan_hdl);
	if (!result)
		return 0;	/* Success */

fail_write_channel_scratch:
	gsi_dealloc_channel(ep->gsi_chan_hdl);
fail_alloc_channel:
	ipa_err("Return with err: %d\n", result);

	return result;
}

static int ipa_poll_gsi_pkt(struct ipa_sys_context *sys)
{
	if (sys->ep->bytes_xfered_valid) {
		sys->ep->bytes_xfered_valid = false;

		return (int)sys->ep->bytes_xfered;
	}

	return gsi_poll_channel(sys->ep->gsi_chan_hdl);
}

static struct ipa_tx_pkt_wrapper *tag_to_pointer_wa(u64 tag)
{
	u64 addr = GENMASK(63, 48) | tag;

	return (struct ipa_tx_pkt_wrapper *)addr;
}

/** ipa_adjust_ra_buff_base_sz()
 *
 * Return value: the largest power of two which is smaller
 * than the input value
 */
static u32 ipa_adjust_ra_buff_base_sz(u32 aggr_byte_limit)
{
	aggr_byte_limit += IPA_MTU;
	aggr_byte_limit += IPA_GENERIC_RX_BUFF_LIMIT;

	BUILD_BUG_ON(IPA_MTU + IPA_GENERIC_RX_BUFF_LIMIT == 0);

	/* We want a power-of-2 that's *less than* the value, so we
	 * start by subracting 1.  We find the highest set bit in
	 * that, and use that to compute a power of 2.
	 */

	return 1 << __fls(aggr_byte_limit - 1);
}

bool ipa_ep_polling(struct ipa_ep_context *ep)
{
	ipa_assert(ipa_consumer(ep->client));

	return !!atomic_read(&ep->sys->rx.curr_polling_state);
}

struct ipa_dp *ipa_dp_init(void)
{
	struct ipa_dp *dp;
	struct kmem_cache *cache;

	dp = kzalloc(sizeof(*dp), GFP_KERNEL);
	if (!dp)
		return NULL;

	cache = kmem_cache_create("IPA_TX_PKT_WRAPPER",
				  sizeof(struct ipa_tx_pkt_wrapper),
				  0, 0, NULL);
	if (!cache) {
		kfree(dp);
		return NULL;
	}
	dp->tx_pkt_wrapper_cache = cache;

	cache = kmem_cache_create("IPA_RX_PKT_WRAPPER",
				  sizeof(struct ipa_rx_pkt_wrapper),
				  0, 0, NULL);
	if (!cache) {
		kmem_cache_destroy(dp->tx_pkt_wrapper_cache);
		kfree(dp);
		return NULL;
	}
	dp->rx_pkt_wrapper_cache = cache;

	return dp;
}

void ipa_dp_exit(struct ipa_dp *dp)
{
	kmem_cache_destroy(dp->rx_pkt_wrapper_cache);
	kmem_cache_destroy(dp->tx_pkt_wrapper_cache);
	kfree(dp);
}
