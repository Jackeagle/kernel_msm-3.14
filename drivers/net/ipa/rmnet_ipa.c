// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2014-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */

/* WWAN Transport Network Driver. */

#define pr_fmt(fmt)    "ipa-wan %s:%d " fmt, __func__, __LINE__

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
#include "net_map.h"
#include "msm_rmnet.h"
#include "rmnet_config.h"
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

#define IPA_APPS_WWAN_CONS_RING_COUNT	128
#define IPA_APPS_WWAN_PROD_RING_COUNT	256

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
	struct net_device *dev;
	struct mutex mux_id_mutex;		/* protects mux_id[] */
	u32 mux_id_count;
	u32 mux_id[MUX_CHANNEL_MAX];
	u32 wan_prod_hdl;
	u32 wan_cons_hdl;
	struct mutex pipe_setup_mutex;		/* pipe setup/teardown */
	struct ipa_sys_connect_params wan_prod_cfg;
	struct ipa_sys_connect_params wan_cons_cfg;
};

static bool initialized;	/* Avoid duplicate initialization */

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
	netif_stop_queue(dev);

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
	struct sk_buff *skb = (struct sk_buff *)data;
	struct net_device *dev = (struct net_device *)priv;
	struct ipa_wwan_private *wwan_ptr;

	if (dev != rmnet_ipa_ctx->dev) {
		ipa_debug("Received pre-SSR packet completion\n");
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
		ipa_debug_low("Outstanding low (%d) - waking up queue\n",
			      wwan_ptr->outstanding_low);
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
	struct net_device *dev = priv;
	struct ipa_wwan_private *wwan_ptr = netdev_priv(dev);

	if (evt == IPA_RECEIVE) {
		struct sk_buff *skb = (struct sk_buff *)data;
		int result;
		unsigned int packet_len = skb->len;

		ipa_debug("Rx packet was received\n");
		skb->dev = rmnet_ipa_ctx->dev;
		skb->protocol = htons(ETH_P_MAP);

		result = netif_receive_skb(skb);
		if (result) {
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

static void ipa_ep_cons_header(struct ipa_ep_cfg_hdr *hdr, u32 header_size,
			       u32 metadata_offset, u32 length_offset)
{
	hdr->hdr_len = header_size;
	hdr->hdr_ofst_metadata_valid = 1;
	hdr->hdr_ofst_metadata = metadata_offset;
	hdr->hdr_ofst_pkt_size_valid = 1;
	hdr->hdr_ofst_pkt_size = length_offset;
}

static void ipa_ep_cons_header_ext(struct ipa_ep_cfg_hdr_ext *hdr_ext,
				   u32 pad_align, bool pad_included)
{
	hdr_ext->hdr_pad_to_alignment = pad_align;
	hdr_ext->hdr_payload_len_inc_padding = pad_included;
	hdr_ext->hdr_total_len_or_pad = IPA_HDR_PAD;
	hdr_ext->hdr_total_len_or_pad_valid = true;
}

static void
ipa_ep_cons_aggregation(struct ipa_ep_cfg_aggr *aggr, u32 size, u32 count)
{
	aggr->aggr_byte_limit = size;
	aggr->aggr_pkt_limit = count;
}

static void ipa_ep_cons_cs_offload_enable(struct ipa_ep_cfg_cfg *cfg)
{
	cfg->cs_offload_en = IPA_CS_OFFLOAD_DL;
}

static void ipa_ep_cons_metadata_mask(struct ipa_ep_cfg_metadata_mask *mask,
				       u32 metadata_mask)
{
	mask->metadata_mask = metadata_mask;
}

static void ipa_ep_prod_header(struct ipa_ep_cfg_hdr *hdr, u32 header_size,
			       u32 metadata_offset, u32 length_offset)
{
	hdr->hdr_len = header_size;
	hdr->hdr_ofst_metadata_valid = 1;
	hdr->hdr_ofst_metadata = 0;		/* Want offset at 0! */
	hdr->hdr_ofst_pkt_size_valid = 0;	/* XXX */
	hdr->hdr_ofst_pkt_size = length_offset;
}

static void
ipa_ep_prod_header_pad(struct ipa_ep_cfg_hdr_ext *hdr_ext, u32 pad_align)
{
	hdr_ext->hdr_pad_to_alignment = pad_align;
	hdr_ext->hdr_payload_len_inc_padding = true;
	hdr_ext->hdr_total_len_or_pad = IPA_HDR_PAD;
	hdr_ext->hdr_total_len_or_pad_valid = true;
}

static void
ipa_ep_prod_header_mode(struct ipa_ep_cfg_mode *mode, enum ipa_mode_type type)
{
	mode->mode = type;
}

static void ipa_ep_prod_aggregation(struct ipa_ep_cfg_aggr *aggr,
				    enum ipa_aggr_en_type aggr_en,
				    enum ipa_aggr_type aggr_type)
{
	aggr->aggr_en = aggr_en;
	aggr->aggr = aggr_type;  /* Ignored if aggr_en == IPA_BYPASS_AGGR */
	/* The rest are set later */
	aggr->aggr_byte_limit = 0;
	aggr->aggr_time_limit = 0;
	aggr->aggr_pkt_limit = 0;
	aggr->aggr_hard_byte_limit_en = false;
	aggr->aggr_sw_eof_active = false;
}

/** handle_egress_format() - Ingress data format configuration */
static int handle_ingress_format(struct net_device *dev,
				 struct rmnet_ioctl_extended_s *in)
{
	enum ipa_client_type client = IPA_CLIENT_APPS_WAN_CONS;
	u32 chan_count = IPA_APPS_WWAN_CONS_RING_COUNT;
	struct ipa_sys_connect_params *wan_cfg = &rmnet_ipa_ctx->wan_cons_cfg;
	struct ipa_ep_cfg *ep_cfg = &wan_cfg->ipa_ep_cfg;
	u32 header_size = sizeof(struct rmnet_map_header_s);
	u32 metadata_offset = offsetof(struct rmnet_map_header_s, mux_id);
	u32 length_offset = offsetof(struct rmnet_map_header_s, pkt_len);
	int ret;

	if (in->u.data & RMNET_IOCTL_INGRESS_FORMAT_CHECKSUM)
		ipa_ep_cons_cs_offload_enable(&ep_cfg->cfg);

	if (in->u.data & RMNET_IOCTL_INGRESS_FORMAT_AGG_DATA) {
		u32 agg_size = in->u.ingress_format.agg_size;
		u32 agg_count = in->u.ingress_format.agg_count;

		if (agg_size > ipa_reg_aggr_max_byte_limit())
			return -EINVAL;
		if (agg_count > ipa_reg_aggr_max_packet_limit())
			return -EINVAL;

		ipa_ep_cons_aggregation(&ep_cfg->aggr, agg_size, agg_count);

		ipa_ctx->ipa_client_apps_wan_cons_agg_gro = true;
	}

	ipa_ep_cons_header(&ep_cfg->hdr, header_size, metadata_offset,
			   length_offset);

	ipa_ep_cons_header_ext(&ep_cfg->hdr_ext, 0, true);

	ipa_ep_cons_metadata_mask(&ep_cfg->metadata_mask, 0xff000000);

	wan_cfg->notify = apps_ipa_packet_receive_notify;
	wan_cfg->priv = dev;

	wan_cfg->napi_enabled = true;

	mutex_lock(&rmnet_ipa_ctx->pipe_setup_mutex);

	ret = ipa_setup_sys_pipe(client, client, chan_count, wan_cfg);
	if (ret < 0) {
		mutex_unlock(&rmnet_ipa_ctx->pipe_setup_mutex);

		return ret;
	}
	rmnet_ipa_ctx->wan_cons_hdl = ret;

	mutex_unlock(&rmnet_ipa_ctx->pipe_setup_mutex);

	return 0;
}

/** handle_egress_format() - Egress data format configuration */
static int handle_egress_format(struct net_device *dev,
				struct rmnet_ioctl_extended_s *e)
{
	struct ipa_sys_connect_params *wan_cfg;
	enum ipa_client_type client = IPA_CLIENT_APPS_WAN_PROD;
	enum ipa_client_type dst = IPA_CLIENT_APPS_WAN_PROD;
	u32 chan_count = IPA_APPS_WWAN_PROD_RING_COUNT;
	struct ipa_ep_cfg *ep_cfg;
	u32 header_size = sizeof(struct rmnet_map_header_s);
	u32 length_offset;
	int ret;

	wan_cfg = &rmnet_ipa_ctx->wan_prod_cfg;
	ep_cfg = &wan_cfg->ipa_ep_cfg;

	if (e->u.data & RMNET_IOCTL_EGRESS_FORMAT_CHECKSUM) {
		header_size += sizeof(u32);
		ep_cfg->cfg.cs_offload_en = IPA_CS_OFFLOAD_UL;
		ep_cfg->cfg.cs_metadata_hdr_offset =
				sizeof(struct rmnet_map_header_s) / 4;
	}

	if (e->u.data & RMNET_IOCTL_EGRESS_FORMAT_AGGREGATION) {
		ipa_ep_prod_aggregation(&ep_cfg->aggr, IPA_ENABLE_DEAGGR,
				        IPA_QCMAP);

		length_offset = offsetof(struct rmnet_map_header_s, pkt_len);

		ipa_ep_prod_header_pad(&ep_cfg->hdr_ext, ilog2(sizeof(u32)));
	} else {
		ipa_ep_prod_aggregation(&ep_cfg->aggr, IPA_BYPASS_AGGR, 0);
		length_offset = 0;
	}

	ipa_ep_prod_header(&ep_cfg->hdr, header_size, 0, length_offset);

	ipa_ep_prod_header_mode(&ep_cfg->mode, IPA_BASIC);

	wan_cfg->notify = apps_ipa_tx_complete_notify;
	wan_cfg->priv = dev;

	mutex_lock(&rmnet_ipa_ctx->pipe_setup_mutex);

	ret = ipa_setup_sys_pipe(client, dst, chan_count, wan_cfg);
	if (ret < 0) {
		mutex_unlock(&rmnet_ipa_ctx->pipe_setup_mutex);

		return ret;
	}
	rmnet_ipa_ctx->wan_prod_hdl = ret;

	mutex_unlock(&rmnet_ipa_ctx->pipe_setup_mutex);

	return 0;
}

/** ipa_wwan_add_mux_channel() - add a mux_id */
static int ipa_wwan_add_mux_channel(u32 mux_id)
{
	u32 i;
	int ret = -EFAULT;

	mutex_lock(&rmnet_ipa_ctx->mux_id_mutex);

	if (rmnet_ipa_ctx->mux_id_count >= MUX_CHANNEL_MAX)
		goto out;

	ret = 0;
	for (i = 0; i < rmnet_ipa_ctx->mux_id_count; i++)
		if (mux_id == rmnet_ipa_ctx->mux_id[i])
			break;

	/* Record the mux_id if it hasn't already been seen */
	if (i == rmnet_ipa_ctx->mux_id_count)
		rmnet_ipa_ctx->mux_id[rmnet_ipa_ctx->mux_id_count++] = mux_id;
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

	ipa_debug("extended cmd 0x%08x\n", edata.extended_ioctl);

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
		memcpy(&edata.u.if_name, rmnet_ipa_ctx->dev->name, IFNAMSIZ);
		goto copy_out;

	case RMNET_IOCTL_ADD_MUX_CHANNEL:		/* Add MUX ID */
		return ipa_wwan_add_mux_channel(edata.u.rmnet_mux_val.mux_id);

	case RMNET_IOCTL_SET_EGRESS_DATA_FORMAT:	/* Egress data format */
		return handle_egress_format(dev, &edata) ? -EFAULT : 0;

	case RMNET_IOCTL_SET_INGRESS_DATA_FORMAT:	/* Ingress format */
		return handle_ingress_format(dev, &edata) ? -EFAULT : 0;

	case RMNET_IOCTL_GET_EP_PAIR:			/* Get endpoint pair */
		edata.u.ipa_ep_pair.consumer_pipe_num =
				ipa_get_ep_mapping(IPA_CLIENT_APPS_WAN_PROD);
		edata.u.ipa_ep_pair.producer_pipe_num =
				ipa_get_ep_mapping(IPA_CLIENT_APPS_WAN_CONS);
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
	void __user *data = ifr->ifr_ifru.ifru_data;
	size_t size = sizeof(ioctl_data);

	ipa_debug("cmd 0x%08x", cmd);

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

/** ipa_wwan_probe() - Network probe function */
static int ipa_wwan_probe(struct platform_device *pdev)
{
	int ret;
	struct net_device *dev;
	struct ipa_wwan_private *wwan_ptr;

	mutex_init(&rmnet_ipa_ctx->pipe_setup_mutex);
	mutex_init(&rmnet_ipa_ctx->mux_id_mutex);

	/* Mark client handles bad until we initialize them */
	rmnet_ipa_ctx->wan_prod_hdl = IPA_CLNT_HDL_BAD;
	rmnet_ipa_ctx->wan_cons_hdl = IPA_CLNT_HDL_BAD;

	ret = ipa_init_q6_smem();
	if (ret) {
		ipa_err("ipa_init_q6_smem failed!\n");
		goto err_clear_ctx;
	}

	/* start A7 QMI service/client */
	ipa_qmi_init();

	/* initialize wan-driver netdev */
	dev = alloc_netdev(sizeof(struct ipa_wwan_private),
			   IPA_WWAN_DEV_NAME,
			   NET_NAME_UNKNOWN,
			   ipa_wwan_setup);
	if (!dev) {
		ipa_err("no memory for netdev\n");
		ret = -ENOMEM;
		goto err_clear_ctx;
	}
	rmnet_ipa_ctx->dev = dev;
	wwan_ptr = netdev_priv(dev);
	ipa_debug("wwan_ptr (private) = %p", wwan_ptr);
	wwan_ptr->outstanding_high_ctl = DEFAULT_OUTSTANDING_HIGH_CTL;
	wwan_ptr->outstanding_high = DEFAULT_OUTSTANDING_HIGH;
	wwan_ptr->outstanding_low = DEFAULT_OUTSTANDING_LOW;
	atomic_set(&wwan_ptr->outstanding_pkts, 0);

	/* Enable SG support in netdevice. */
	dev->hw_features |= NETIF_F_SG;

	netif_napi_add(dev, &wwan_ptr->napi, ipa_rmnet_poll, NAPI_WEIGHT);
	ret = register_netdev(dev);
	if (ret) {
		ipa_err("unable to register ipa_netdev %d rc=%d\n", 0, ret);
		goto err_napi_del;
	}

	ipa_debug("IPA-WWAN devices (%s) initialization ok :>>>>\n", dev->name);
	/* offline charging mode */
	ipa_proxy_clk_unvote();

	/* Till the system is suspended, we keep the clock open */
	ipa_client_add();

	initialized = true;

	return 0;

err_napi_del:
	netif_napi_del(&wwan_ptr->napi);
	free_netdev(dev);
err_clear_ctx:
	memset(&rmnet_ipa_ctx_struct, 0, sizeof(rmnet_ipa_ctx_struct));

	return ret;
}

static int ipa_wwan_remove(struct platform_device *pdev)
{
	struct ipa_wwan_private *wwan_ptr = netdev_priv(rmnet_ipa_ctx->dev);

	ipa_info("rmnet_ipa started deinitialization\n");
	mutex_lock(&rmnet_ipa_ctx->pipe_setup_mutex);
	if (rmnet_ipa_ctx->wan_cons_hdl != IPA_CLNT_HDL_BAD) {
		ipa_teardown_sys_pipe(rmnet_ipa_ctx->wan_cons_hdl);
		rmnet_ipa_ctx->wan_cons_hdl = IPA_CLNT_HDL_BAD;
	}

	if (rmnet_ipa_ctx->wan_prod_hdl != IPA_CLNT_HDL_BAD) {
		ipa_teardown_sys_pipe(rmnet_ipa_ctx->wan_prod_hdl);
		rmnet_ipa_ctx->wan_prod_hdl = IPA_CLNT_HDL_BAD;
	}

	netif_napi_del(&wwan_ptr->napi);
	mutex_unlock(&rmnet_ipa_ctx->pipe_setup_mutex);
	unregister_netdev(rmnet_ipa_ctx->dev);

	if (rmnet_ipa_ctx->dev)
		free_netdev(rmnet_ipa_ctx->dev);
	rmnet_ipa_ctx->dev = NULL;

	mutex_destroy(&rmnet_ipa_ctx->mux_id_mutex);
	mutex_destroy(&rmnet_ipa_ctx->pipe_setup_mutex);

	initialized = false;
	ipa_info("rmnet_ipa completed deinitialization\n");

	return 0;
}

/** rmnet_ipa_ap_suspend() - suspend callback for runtime_pm
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
static int rmnet_ipa_ap_suspend(struct device *dev)
{
	struct net_device *netdev = rmnet_ipa_ctx->dev;
	struct ipa_wwan_private *wwan_ptr;
	int ret;

	ipa_debug("Enter...\n");
	if (!netdev) {
		ipa_err("netdev is NULL.\n");
		ret = 0;
		goto bail;
	}

	netif_tx_lock_bh(netdev);
	wwan_ptr = netdev_priv(netdev);
	if (!wwan_ptr) {
		ipa_err("wwan_ptr is NULL.\n");
		ret = 0;
		goto unlock_and_bail;
	}

	/* Do not allow A7 to suspend in case there are outstanding packets */
	if (atomic_read(&wwan_ptr->outstanding_pkts) != 0) {
		ipa_debug("Outstanding packets, postponing AP suspend.\n");
		ret = -EAGAIN;
		goto unlock_and_bail;
	}

	/* Make sure that there is no Tx operation ongoing */
	netif_stop_queue(netdev);

	ret = 0;
	ipa_client_remove();
	ipa_debug("IPA clocks disabled\n");

unlock_and_bail:
	netif_tx_unlock_bh(netdev);
bail:
	ipa_debug("Exit with %d\n", ret);

	return ret;
}

/** rmnet_ipa_ap_resume() - resume callback for runtime_pm
 * @dev: pointer to device
 *
 * This callback will be invoked by the runtime_pm framework when an AP resume
 * operation is invoked.
 *
 * Enables the network interface queue and returns success to the
 * runtime_pm framework.
 */
static int rmnet_ipa_ap_resume(struct device *dev)
{
	struct net_device *netdev = rmnet_ipa_ctx->dev;

	ipa_client_add();
	ipa_debug("IPA clocks enabled\n");
	if (netdev)
		netif_wake_queue(netdev);
	ipa_debug("Exit\n");

	return 0;
}

static const struct of_device_id rmnet_ipa_dt_match[] = {
	{.compatible = "qcom,rmnet-ipa"},
	{},
};
MODULE_DEVICE_TABLE(of, rmnet_ipa_dt_match);

static const struct dev_pm_ops rmnet_ipa_pm_ops = {
	.suspend_noirq = rmnet_ipa_ap_suspend,
	.resume_noirq = rmnet_ipa_ap_resume,
};

static struct platform_driver rmnet_ipa_driver = {
	.driver = {
		.name = "rmnet_ipa",
		.owner = THIS_MODULE,
		.pm = &rmnet_ipa_pm_ops,
		.of_match_table = rmnet_ipa_dt_match,
	},
	.probe = ipa_wwan_probe,
	.remove = ipa_wwan_remove,
};

int ipa_wwan_init(void)
{
	if (initialized)
		return 0;

	return platform_driver_register(&rmnet_ipa_driver);
}

void ipa_wwan_cleanup(void)
{
	platform_driver_unregister(&rmnet_ipa_driver);
	memset(&rmnet_ipa_ctx_struct, 0, sizeof(rmnet_ipa_ctx_struct));
}

static int ipa_rmnet_poll(struct napi_struct *napi, int budget)
{
	int rcvd_pkts;

	rcvd_pkts = ipa_rx_poll(rmnet_ipa_ctx->wan_cons_hdl, budget);
	ipa_debug_low("rcvd packets: %d\n", rcvd_pkts);

	return rcvd_pkts;
}

MODULE_DESCRIPTION("WWAN Network Interface");
MODULE_LICENSE("GPL v2");
