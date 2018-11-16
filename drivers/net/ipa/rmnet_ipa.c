// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2014-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */

/* WWAN Transport Network Driver. */

#include <linux/completion.h>
#include <linux/errno.h>
#include <linux/if_arp.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of_device.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <net/pkt_sched.h>

#include "msm_rmnet.h"
#include "rmnet_config.h"
#include "ipa_clock.h"
#include "ipa_qmi.h"
#include "ipa_i.h"

#define DRIVER_NAME		"wwan_ioctl"
#define IPA_WWAN_DEV_NAME	"rmnet_ipa%d"

#define MUX_CHANNEL_MAX		10	/* max mux channels */

#define NAPI_WEIGHT		60

#define WWAN_DATA_LEN		2000
#define HEADROOM_FOR_QMAP	8	/* for mux header */
#define TAILROOM		0	/* for padding by mux layer */

#define DEFAULT_OUTSTANDING_HIGH	128
#define DEFAULT_OUTSTANDING_HIGH_CTL	(DEFAULT_OUTSTANDING_HIGH + 32)
#define DEFAULT_OUTSTANDING_LOW		64

#define IPA_APPS_WWAN_CONS_RING_COUNT	256
#define IPA_APPS_WWAN_PROD_RING_COUNT	512

static int ipa_rmnet_poll(struct napi_struct *napi, int budget);

/** struct ipa_wwan_private - WWAN private data
 * @net: network interface struct implemented by this driver
 * @stats: iface statistics
 * @outstanding_high: number of outstanding packets allowed
 * @outstanding_low: number of outstanding packets which shall cause
 *
 * WWAN private - holds all relevant info about WWAN driver
 */
struct ipa_wwan_private {
	struct net_device_stats stats;
	atomic_t outstanding_pkts;
	int outstanding_high_ctl;
	int outstanding_high;
	int outstanding_low;
	struct napi_struct napi;
};

struct rmnet_ipa_context {
	struct net_device *netdev;
	struct mutex mux_id_mutex;		/* protects mux_id[] */
	u32 mux_id_count;
	u32 mux_id[MUX_CHANNEL_MAX];
	u32 wan_prod_ep_id;
	u32 wan_cons_ep_id;
	struct mutex ep_setup_mutex;		/* endpoint setup/teardown */
};

static struct rmnet_ipa_context rmnet_ipa_ctx_struct;
static struct rmnet_ipa_context *rmnet_ipa_ctx = &rmnet_ipa_ctx_struct;

/** wwan_open() - Opens the wwan network interface */
static int ipa_wwan_open(struct net_device *dev)
{
	struct ipa_wwan_private *wwan_ptr = netdev_priv(dev);

	napi_enable(&wwan_ptr->napi);
	netif_start_queue(dev);

	return 0;
}

/** ipa_wwan_stop() - Stops the wwan network interface. */
static int ipa_wwan_stop(struct net_device *dev)
{
	struct ipa_wwan_private *wwan_ptr = netdev_priv(dev);

	netif_stop_queue(dev);
	napi_disable(&wwan_ptr->napi);

	return 0;
}

/** ipa_wwan_xmit() - Transmits an skb.
 *
 * @skb: skb to be transmitted
 * @dev: network device
 *
 * Return codes:
 * NETDEV_TX_OK: Success
 * NETDEV_TX_BUSY: Error while transmitting the skb. Try again later
 */
static int ipa_wwan_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ipa_wwan_private *wwan_ptr = netdev_priv(dev);
	unsigned int skb_len;
	int outstanding;

	if (skb->protocol != htons(ETH_P_MAP)) {
		dev_kfree_skb_any(skb);
		dev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}

	/* Control packets are sent even if queue is stopped.  We
	 * always honor the data and control high-water marks.
	 */
	outstanding = atomic_read(&wwan_ptr->outstanding_pkts);
	if (!RMNET_MAP_GET_CD_BIT(skb)) {	/* Data packet? */
		if (netif_queue_stopped(dev))
			return NETDEV_TX_BUSY;
		if (outstanding >= wwan_ptr->outstanding_high)
			return NETDEV_TX_BUSY;
	} else if (outstanding >= wwan_ptr->outstanding_high_ctl) {
		return NETDEV_TX_BUSY;
	}

	/* both data packets and commands will be routed to
	 * IPA_CLIENT_Q6_WAN_CONS based on status configuration.
	 */
	skb_len = skb->len;
	if (ipa_tx_dp(IPA_CLIENT_APPS_WAN_PROD, skb))
		return NETDEV_TX_BUSY;

	atomic_inc(&wwan_ptr->outstanding_pkts);
	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb_len;

	return NETDEV_TX_OK;
}

/** apps_ipa_tx_complete_notify() - Rx notify
 *
 * @priv: driver context
 * @evt: event type
 * @data: data provided with event
 *
 * Check that the packet is the one we sent and release it
 * This function will be called in defered context in IPA wq.
 */
static void apps_ipa_tx_complete_notify(void *priv, enum ipa_dp_evt_type evt,
					unsigned long data)
{
	struct ipa_wwan_private *wwan_ptr;
	struct net_device *dev = priv;
	struct sk_buff *skb;

	skb = (struct sk_buff *)data;

	if (dev != rmnet_ipa_ctx->netdev) {
		dev_kfree_skb_any(skb);
		return;
	}

	if (evt != IPA_WRITE_DONE) {
		ipa_err("unsupported evt on Tx callback, Drop the packet\n");
		dev_kfree_skb_any(skb);
		dev->stats.tx_dropped++;
		return;
	}

	wwan_ptr = netdev_priv(dev);
	atomic_dec(&wwan_ptr->outstanding_pkts);
	__netif_tx_lock_bh(netdev_get_tx_queue(dev, 0));
	if (netif_queue_stopped(dev) &&
	    atomic_read(&wwan_ptr->outstanding_pkts) <
				wwan_ptr->outstanding_low) {
		netif_wake_queue(dev);
	}

	__netif_tx_unlock_bh(netdev_get_tx_queue(dev, 0));
	dev_kfree_skb_any(skb);
}

/** apps_ipa_packet_receive_notify() - Rx notify
 *
 * @priv: driver context
 * @evt: event type
 * @data: data provided with event
 *
 * IPA will pass a packet to the Linux network stack with skb->data
 */
static void apps_ipa_packet_receive_notify(void *priv, enum ipa_dp_evt_type evt,
					   unsigned long data)
{
	struct ipa_wwan_private *wwan_ptr;
	struct net_device *dev = priv;

	wwan_ptr = netdev_priv(dev);
	if (evt == IPA_RECEIVE) {
		struct sk_buff *skb = (struct sk_buff *)data;
		int ret;
		unsigned int packet_len = skb->len;

		skb->dev = rmnet_ipa_ctx->netdev;
		skb->protocol = htons(ETH_P_MAP);

		ret = netif_receive_skb(skb);
		if (ret) {
			pr_err_ratelimited("fail on netif_receive_skb\n");
			dev->stats.rx_dropped++;
		}
		dev->stats.rx_packets++;
		dev->stats.rx_bytes += packet_len;
	} else if (evt == IPA_CLIENT_START_POLL) {
		napi_schedule(&wwan_ptr->napi);
	} else if (evt == IPA_CLIENT_COMP_NAPI) {
		napi_complete(&wwan_ptr->napi);
	} else {
		ipa_err("Invalid evt %d received in wan_ipa_receive\n", evt);
	}
}

/** handle_ingress_format() - Ingress data format configuration */
static int handle_ingress_format(struct net_device *dev,
				 struct rmnet_ioctl_extended_s *in)
{
	enum ipa_cs_offload_en offload_type;
	enum ipa_client_type client;
	u32 metadata_offset;
	u32 rx_buffer_size;
	u32 channel_count;
	u32 length_offset;
	u32 header_size;
	bool aggr_active;
	u32 aggr_bytes;
	u32 aggr_count;
	u32 aggr_size;	/* in KB */
	u32 ep_id;
	int ret;

	client = IPA_CLIENT_APPS_WAN_CONS;
	channel_count = IPA_APPS_WWAN_CONS_RING_COUNT;
	header_size = sizeof(struct rmnet_map_header_s);
	metadata_offset = offsetof(struct rmnet_map_header_s, mux_id);
	length_offset = offsetof(struct rmnet_map_header_s, pkt_len);
	offload_type = IPA_CS_OFFLOAD_NONE;
	aggr_bytes = IPA_GENERIC_AGGR_BYTE_LIMIT;
	aggr_count = IPA_GENERIC_AGGR_PKT_LIMIT;
	aggr_active = false;

	if (in->u.data & RMNET_IOCTL_INGRESS_FORMAT_CHECKSUM)
		offload_type = IPA_CS_OFFLOAD_DL;

	if (in->u.data & RMNET_IOCTL_INGRESS_FORMAT_AGG_DATA) {
		aggr_size = in->u.ingress_format.agg_size;
		aggr_count = in->u.ingress_format.agg_count;
		aggr_active = true;
	}

	if (aggr_size > ipa_reg_aggr_max_byte_limit())
		return -EINVAL;

	if (aggr_count > ipa_reg_aggr_max_packet_limit())
		return -EINVAL;

	/* Compute the buffer size required to handle the requested
	 * aggregation byte limit.  The aggr_byte_limit value is
	 * expressed as a number of KB, but we derive that value
	 * after computing the buffer size to use (in bytes).  The
	 * buffer must be sufficient to hold one IPA_MTU-sized
	 * packet *after* the limit is reached.
	 *
	 * The buffer will be sufficient to hold one IPA_MTU-sized
	 * packet after the limit is reached.  (The size returned is
	 * the computed maximum number of data bytes that can be
	 * held in the buffer--no metadata/headers.)
	 */
	rx_buffer_size = ipa_aggr_byte_limit_buf_size(aggr_size * SZ_1K);

	/* Account for the extra IPA_MTU past the limit in the
	 * buffer, and convert the result to the KB units the
	 * aggr_byte_limit uses.
	 */
	aggr_size = (rx_buffer_size - IPA_MTU) / SZ_1K;

	mutex_lock(&rmnet_ipa_ctx->ep_setup_mutex);

	if (rmnet_ipa_ctx->wan_cons_ep_id != IPA_EP_ID_BAD) {
		ret = -EBUSY;
		goto out_unlock;
	}

	ret = ipa_ep_alloc(ipa_ctx, client);
	if (ret < 0)
		goto out_unlock;
	ep_id = ret;

	/* Record our endpoint configuration parameters */
	ipa_endp_init_hdr_cons(ipa_ctx, ep_id, header_size, metadata_offset,
			       length_offset);
	ipa_endp_init_hdr_ext_cons(ipa_ctx, ep_id, 0, true);
	ipa_endp_init_aggr_cons(ipa_ctx, ep_id, aggr_size, aggr_count, true);
	ipa_endp_init_cfg_cons(ipa_ctx, ep_id, offload_type);
	ipa_endp_init_hdr_metadata_mask_cons(ipa_ctx, ep_id, 0xff000000);
	ipa_endp_status_cons(ipa_ctx, ep_id, !aggr_active);

	ipa_ctx->ipa_client_apps_wan_cons_agg_gro = aggr_active;

	ret = ipa_ep_setup(ipa_ctx, ep_id, channel_count, 1, rx_buffer_size,
			   apps_ipa_packet_receive_notify, dev);
	if (ret)
		ipa_ep_free(ipa_ctx, ep_id);
	else
		rmnet_ipa_ctx->wan_cons_ep_id = ep_id;
out_unlock:
	mutex_unlock(&rmnet_ipa_ctx->ep_setup_mutex);

	return ret;
}

/** handle_egress_format() - Egress data format configuration */
static int handle_egress_format(struct net_device *dev,
				struct rmnet_ioctl_extended_s *e)
{
	enum ipa_cs_offload_en offload_type;
	enum ipa_client_type dst_client;
	enum ipa_client_type client;
	enum ipa_aggr_type aggr_type;
	enum ipa_aggr_en aggr_en;
	u32 channel_count;
	u32 length_offset;
	u32 header_align;
	u32 header_offset;
	u32 header_size;
	u32 ep_id;
	int ret;

	client = IPA_CLIENT_APPS_WAN_PROD;
	dst_client = IPA_CLIENT_APPS_LAN_CONS;
	channel_count = IPA_APPS_WWAN_PROD_RING_COUNT;
	header_size = sizeof(struct rmnet_map_header_s);
	offload_type = IPA_CS_OFFLOAD_NONE;
	aggr_en = IPA_BYPASS_AGGR;
	aggr_type = 0;	/* ignored if BYPASS */
	header_offset = 0;
	length_offset = 0;
	header_align = 0;

	if (e->u.data & RMNET_IOCTL_EGRESS_FORMAT_CHECKSUM) {
		offload_type = IPA_CS_OFFLOAD_UL;
		header_offset = sizeof(struct rmnet_map_header_s) / 4;
		header_size += sizeof(u32);
	}

	if (e->u.data & RMNET_IOCTL_EGRESS_FORMAT_AGGREGATION) {
		aggr_en = IPA_ENABLE_DEAGGR;
		aggr_type = IPA_QCMAP;
		length_offset = offsetof(struct rmnet_map_header_s, pkt_len);
		header_align = ilog2(sizeof(u32));
	}

	mutex_lock(&rmnet_ipa_ctx->ep_setup_mutex);

	if (rmnet_ipa_ctx->wan_prod_ep_id != IPA_EP_ID_BAD) {
		ret = -EBUSY;
		goto out_unlock;
	}

	ret = ipa_ep_alloc(ipa_ctx, client);
	if (ret < 0)
		goto out_unlock;
	ep_id = ret;

	if (aggr_en == IPA_ENABLE_DEAGGR && !ipa_endp_aggr_support(ep_id)) {
		ret = -ENOTSUPP;
		goto out_unlock;
	}

	/* We really do want 0 metadata offset */
	ipa_endp_init_hdr_prod(ipa_ctx, ep_id, header_size, 0, length_offset);
	ipa_endp_init_hdr_ext_prod(ipa_ctx, ep_id, header_align);
	ipa_endp_init_mode_prod(ipa_ctx, ep_id, IPA_BASIC, dst_client);
	ipa_endp_init_aggr_prod(ipa_ctx, ep_id, aggr_en, aggr_type);
	ipa_endp_init_cfg_prod(ipa_ctx, ep_id, offload_type, header_offset);
	ipa_endp_init_seq_prod(ipa_ctx, ep_id);
	ipa_endp_init_deaggr_prod(ipa_ctx, ep_id);
	/* Enable source notification status for exception packets
	 * (i.e. QMAP commands) to be routed to modem.
	 */
	ipa_endp_status_prod(ipa_ctx, ep_id, true, IPA_CLIENT_Q6_WAN_CONS);

	/* Use a deferred interrupting no-op to reduce completion interrupts */
	ipa_no_intr_init(ep_id);

	ret = ipa_ep_setup(ipa_ctx, ep_id, channel_count, 1, 0,
			   apps_ipa_tx_complete_notify, dev);
	if (ret)
		ipa_ep_free(ipa_ctx, ep_id);
	else
		rmnet_ipa_ctx->wan_prod_ep_id = ep_id;

out_unlock:
	mutex_unlock(&rmnet_ipa_ctx->ep_setup_mutex);

	return ret;
}

/** ipa_wwan_add_mux_channel() - add a mux_id */
static int ipa_wwan_add_mux_channel(u32 mux_id)
{
	int ret;
	u32 i;

	mutex_lock(&rmnet_ipa_ctx->mux_id_mutex);

	if (rmnet_ipa_ctx->mux_id_count >= MUX_CHANNEL_MAX) {
		ret = -EFAULT;
		goto out;
	}

	for (i = 0; i < rmnet_ipa_ctx->mux_id_count; i++)
		if (mux_id == rmnet_ipa_ctx->mux_id[i])
			break;

	/* Record the mux_id if it hasn't already been seen */
	if (i == rmnet_ipa_ctx->mux_id_count)
		rmnet_ipa_ctx->mux_id[rmnet_ipa_ctx->mux_id_count++] = mux_id;
	ret = 0;
out:
	mutex_unlock(&rmnet_ipa_ctx->mux_id_mutex);

	return ret;
}

/** ipa_wwan_ioctl_extended() - rmnet extended I/O control */
static int ipa_wwan_ioctl_extended(struct net_device *dev, void __user *data)
{
	struct rmnet_ioctl_extended_s edata = { };
	size_t size = sizeof(edata);

	if (copy_from_user(&edata, data, size))
		return -EFAULT;

	switch (edata.extended_ioctl) {
	case RMNET_IOCTL_GET_SUPPORTED_FEATURES:	/* Get features */
		edata.u.data = RMNET_IOCTL_FEAT_NOTIFY_MUX_CHANNEL;
		edata.u.data |= RMNET_IOCTL_FEAT_SET_EGRESS_DATA_FORMAT;
		edata.u.data |= RMNET_IOCTL_FEAT_SET_INGRESS_DATA_FORMAT;
		goto copy_out;

	case RMNET_IOCTL_GET_EPID:			/* Get endpoint ID */
		edata.u.data = 1;
		goto copy_out;

	case RMNET_IOCTL_GET_DRIVER_NAME:		/* Get driver name */
		memcpy(&edata.u.if_name, rmnet_ipa_ctx->netdev->name, IFNAMSIZ);
		goto copy_out;

	case RMNET_IOCTL_ADD_MUX_CHANNEL:		/* Add MUX ID */
		return ipa_wwan_add_mux_channel(edata.u.rmnet_mux_val.mux_id);

	case RMNET_IOCTL_SET_EGRESS_DATA_FORMAT:	/* Egress data format */
		return handle_egress_format(dev, &edata) ? -EFAULT : 0;

	case RMNET_IOCTL_SET_INGRESS_DATA_FORMAT:	/* Ingress format */
		return handle_ingress_format(dev, &edata) ? -EFAULT : 0;

	case RMNET_IOCTL_GET_EP_PAIR:			/* Get endpoint pair */
		edata.u.ipa_ep_pair.consumer_pipe_num =
				ipa_client_ep_id(IPA_CLIENT_APPS_WAN_PROD);
		edata.u.ipa_ep_pair.producer_pipe_num =
				ipa_client_ep_id(IPA_CLIENT_APPS_WAN_CONS);
		goto copy_out;

	case RMNET_IOCTL_GET_SG_SUPPORT:		/* Get SG support */
		edata.u.data = 1;	/* Scatter/gather is always supported */
		goto copy_out;

	/* Unsupported requests */
	case RMNET_IOCTL_SET_MRU:			/* Set MRU */
	case RMNET_IOCTL_GET_MRU:			/* Get MRU */
	case RMNET_IOCTL_GET_AGGREGATION_COUNT:		/* Get agg count */
	case RMNET_IOCTL_SET_AGGREGATION_COUNT:		/* Set agg count */
	case RMNET_IOCTL_GET_AGGREGATION_SIZE:		/* Get agg size */
	case RMNET_IOCTL_SET_AGGREGATION_SIZE:		/* Set agg size */
	case RMNET_IOCTL_FLOW_CONTROL:			/* Do flow control */
	case RMNET_IOCTL_GET_DFLT_CONTROL_CHANNEL:	/* For legacy use */
	case RMNET_IOCTL_GET_HWSW_MAP:			/* Get HW/SW map */
	case RMNET_IOCTL_SET_RX_HEADROOM:		/* Set RX Headroom */
	case RMNET_IOCTL_SET_QOS_VERSION:		/* Set 8/6 byte QoS */
	case RMNET_IOCTL_GET_QOS_VERSION:		/* Get 8/6 byte QoS */
	case RMNET_IOCTL_GET_SUPPORTED_QOS_MODES:	/* Get QoS modes */
	case RMNET_IOCTL_SET_SLEEP_STATE:		/* Set sleep state */
	case RMNET_IOCTL_SET_XLAT_DEV_INFO:		/* xlat dev name */
	case RMNET_IOCTL_DEREGISTER_DEV:		/* Deregister netdev */
		return -ENOTSUPP;	/* Defined, but unsupported command */

	default:
		return -EINVAL;		/* Invalid (unrecognized) command */
	}

copy_out:
	return copy_to_user(data, &edata, size) ? -EFAULT : 0;
}

/** ipa_wwan_ioctl() - I/O control for wwan network driver */
static int ipa_wwan_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct rmnet_ioctl_data_s ioctl_data = { };
	void __user *data;
	size_t size;

	data = ifr->ifr_ifru.ifru_data;
	size = sizeof(ioctl_data);

	switch (cmd) {
	/* These features are implied; alternatives are not supported */
	case RMNET_IOCTL_SET_LLP_IP:		/* RAW IP protocol */
	case RMNET_IOCTL_SET_QOS_DISABLE:	/* QoS header disabled */
		return 0;

	/* These features are not supported; use alternatives */
	case RMNET_IOCTL_SET_LLP_ETHERNET:	/* Ethernet protocol */
	case RMNET_IOCTL_SET_QOS_ENABLE:	/* QoS header enabled */
	case RMNET_IOCTL_GET_OPMODE:		/* Get operation mode */
	case RMNET_IOCTL_FLOW_ENABLE:		/* Flow enable */
	case RMNET_IOCTL_FLOW_DISABLE:		/* Flow disable */
	case RMNET_IOCTL_FLOW_SET_HNDL:		/* Set flow handle */
		return -ENOTSUPP;

	case RMNET_IOCTL_GET_LLP:		/* Get link protocol */
		ioctl_data.u.operation_mode = RMNET_MODE_LLP_IP;
		goto copy_out;

	case RMNET_IOCTL_GET_QOS:		/* Get QoS header state */
		ioctl_data.u.operation_mode = RMNET_MODE_NONE;
		goto copy_out;

	case RMNET_IOCTL_OPEN:			/* Open transport port */
	case RMNET_IOCTL_CLOSE:			/* Close transport port */
		return 0;

	case RMNET_IOCTL_EXTENDED:		/* Extended IOCTLs */
		return ipa_wwan_ioctl_extended(dev, data);

	default:
		return -EINVAL;
	}

copy_out:
	return copy_to_user(data, &ioctl_data, size) ? -EFAULT : 0;
}

static const struct net_device_ops ipa_wwan_ops_ip = {
	.ndo_open	= ipa_wwan_open,
	.ndo_stop	= ipa_wwan_stop,
	.ndo_start_xmit	= ipa_wwan_xmit,
	.ndo_do_ioctl	= ipa_wwan_ioctl,
};

/** wwan_setup() - Setup the wwan network driver */
static void ipa_wwan_setup(struct net_device *dev)
{
	dev->netdev_ops = &ipa_wwan_ops_ip;
	ether_setup(dev);
	dev->header_ops = NULL;	 /* No header (override ether_setup() value) */
	dev->type = ARPHRD_RAWIP;
	dev->hard_header_len = 0;
	dev->max_mtu = WWAN_DATA_LEN;
	dev->mtu = dev->max_mtu;
	dev->addr_len = 0;
	dev->flags &= ~(IFF_BROADCAST | IFF_MULTICAST);
	dev->needed_headroom = HEADROOM_FOR_QMAP;
	dev->needed_tailroom = TAILROOM;
	dev->watchdog_timeo = msecs_to_jiffies(10 * MSEC_PER_SEC);
}

/** rmnet_ipa_suspend() - suspend callback for runtime_pm
 * @dev: pointer to device
 *
 * This callback will be invoked by the runtime_pm framework when an AP suspend
 * operation is invoked, usually by pressing a suspend button.
 *
 * Returns -EAGAIN to runtime_pm framework in case there are pending packets
 * in the Tx queue. This will postpone the suspend operation until all the
 * pending packets will be transmitted.
 *
 * In case there are no packets to send, releases the WWAN0_PROD entity.
 * As an outcome, the number of IPA active clients should be decremented
 * until IPA clocks can be gated.
 */
int rmnet_ipa_suspend(void *data)
{
	struct rmnet_ipa_context *wwan = data;
	struct ipa_wwan_private *wwan_ptr;
	struct net_device *netdev;
	int ret;

	netdev = wwan->netdev;
	if (!netdev)
		return 0;

	ret = 0;
	netif_tx_lock_bh(netdev);
	wwan_ptr = netdev_priv(netdev);
	if (!wwan_ptr)
		goto out_unlock;

	/* Only not allow suspend if there are no outstanding packets */
	if (!atomic_read(&wwan_ptr->outstanding_pkts)) {
		netif_stop_queue(netdev);
		ipa_clock_put(ipa_ctx);
	} else {
		ret = -EAGAIN;
	}
out_unlock:
	netif_tx_unlock_bh(netdev);

	return ret;
}

/** rmnet_ipa_resume() - resume callback for runtime_pm
 * @dev: pointer to device
 *
 * This callback will be invoked by the runtime_pm framework when an AP resume
 * operation is invoked.
 *
 * Enables the network interface queue and returns success to the
 * runtime_pm framework.
 */
void rmnet_ipa_resume(void *data)
{
	struct rmnet_ipa_context *wwan = data;
	struct net_device *netdev = wwan->netdev;

	ipa_clock_get(ipa_ctx);
	if (netdev)
		netif_wake_queue(netdev);
}

void *ipa_wwan_init(void)
{
	struct rmnet_ipa_context *wwan = rmnet_ipa_ctx;
	struct ipa_wwan_private *wwan_ptr;
	struct net_device *netdev;
	int ret;

	/* Zero modem shared memory before we begin */
	ret = ipa_modem_smem_init(ipa_ctx);
	if (ret)
		return ERR_PTR(ret);

	/* Start QMI communication with the modem */
	ret = ipa_qmi_init();
	if (ret)
		return ERR_PTR(ret);

	netdev = alloc_netdev(sizeof(struct ipa_wwan_private),
			      IPA_WWAN_DEV_NAME, NET_NAME_UNKNOWN,
			      ipa_wwan_setup);
	if (!netdev) {
		ret = -ENOMEM;
		goto err_qmi_exit;
	}
	/* Enable SG support in netdevice. */
	netdev->hw_features |= NETIF_F_SG;

	wwan->netdev = netdev;
	mutex_init(&wwan->mux_id_mutex);
	wwan->wan_prod_ep_id = IPA_EP_ID_BAD;
	wwan->wan_cons_ep_id = IPA_EP_ID_BAD;
	mutex_init(&wwan->ep_setup_mutex);

	wwan_ptr = netdev_priv(netdev);
	atomic_set(&wwan_ptr->outstanding_pkts, 0);
	wwan_ptr->outstanding_high_ctl = DEFAULT_OUTSTANDING_HIGH_CTL;
	wwan_ptr->outstanding_high = DEFAULT_OUTSTANDING_HIGH;
	wwan_ptr->outstanding_low = DEFAULT_OUTSTANDING_LOW;
	netif_napi_add(netdev, &wwan_ptr->napi, ipa_rmnet_poll, NAPI_WEIGHT);

	ret = register_netdev(netdev);
	if (ret)
		goto err_napi_del;

	/* Take a clock reference; a suspend request will remove this */
	ipa_clock_get(ipa_ctx);
	ipa_clock_proxy_put(ipa_ctx);

	return wwan;

err_napi_del:
	netif_napi_del(&wwan_ptr->napi);
	memset(wwan_ptr, 0, sizeof(*wwan_ptr));
	free_netdev(netdev);
	mutex_destroy(&wwan->ep_setup_mutex);
	mutex_destroy(&wwan->mux_id_mutex);
	memset(wwan, 0, sizeof(*wwan));
err_qmi_exit:
	ipa_qmi_exit();

	return ERR_PTR(ret);
}

void ipa_wwan_cleanup(void *data)
{
	struct rmnet_ipa_context *wwan = data;
	struct ipa_wwan_private *wwan_ptr;

	mutex_lock(&wwan->ep_setup_mutex);

	ipa_clock_get(ipa_ctx);

	if (wwan->wan_cons_ep_id != IPA_EP_ID_BAD) {
		ipa_ep_teardown(ipa_ctx, wwan->wan_cons_ep_id);
		wwan->wan_cons_ep_id = IPA_EP_ID_BAD;
	}

	if (wwan->wan_prod_ep_id != IPA_EP_ID_BAD) {
		ipa_ep_teardown(ipa_ctx, wwan->wan_prod_ep_id);
		wwan->wan_prod_ep_id = IPA_EP_ID_BAD;
	}

	ipa_clock_put(ipa_ctx);

	if (wwan->netdev) {
		wwan_ptr = netdev_priv(wwan->netdev);
		netif_napi_del(&wwan_ptr->napi);

		unregister_netdev(wwan->netdev);
		free_netdev(wwan->netdev);
		wwan->netdev = NULL;
	}

	mutex_unlock(&wwan->ep_setup_mutex);
	mutex_destroy(&wwan->ep_setup_mutex);

	mutex_destroy(&wwan->mux_id_mutex);

	memset(wwan, 0, sizeof(*wwan));
}

static int ipa_rmnet_poll(struct napi_struct *napi, int budget)
{
	return ipa_rx_poll(rmnet_ipa_ctx->wan_cons_ep_id, budget);
}

MODULE_DESCRIPTION("WWAN Network Interface");
MODULE_LICENSE("GPL v2");
