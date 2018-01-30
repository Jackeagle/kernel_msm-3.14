/* Copyright (c) 2014-2017, The Linux Foundation. All rights reserved.
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

/*
 * WWAN Transport Network Driver.
 */

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
#include <linux/ipc_logging.h>
#include <net/pkt_sched.h>
#include <soc/qcom/subsystem_restart.h>
#include <soc/qcom/subsystem_notif.h>
#include "net_map.h"
#include "msm_rmnet.h"
#include "rmnet_config.h"
#include "ipa_qmi_service.h"

#define WWAN_METADATA_SHFT 24
#define WWAN_METADATA_MASK 0xFF000000
#define WWAN_DATA_LEN 2000
#define IPA_RM_INACTIVITY_TIMER 100 /* IPA_RM */
#define HEADROOM_FOR_QMAP   8 /* for mux header */
#define TAILROOM            0 /* for padding by mux layer */
#define MAX_NUM_OF_MUX_CHANNEL  10 /* max mux channels */
#define UL_FILTER_RULE_HANDLE_START 69
#define DEFAULT_OUTSTANDING_HIGH 128
#define DEFAULT_OUTSTANDING_HIGH_CTL (DEFAULT_OUTSTANDING_HIGH+32)
#define DEFAULT_OUTSTANDING_LOW 64

#define IPA_WWAN_DEV_NAME "rmnet_ipa%d"
#define IPA_UPSTEAM_WLAN_IFACE_NAME "wlan0"

#define IPA_WWAN_RX_SOFTIRQ_THRESH 16

#define INVALID_MUX_ID 0xFF
#define IPA_QUOTA_REACH_ALERT_MAX_SIZE 64
#define IPA_QUOTA_REACH_IF_NAME_MAX_SIZE 64
#define IPA_UEVENT_NUM_EVNP 4 /* number of event pointers */
#define NAPI_WEIGHT 60
#define DRIVER_NAME "wwan_ioctl"

#define IPA_NETDEV() \
	((rmnet_ipa3_ctx && rmnet_ipa3_ctx->wwan_priv) ? \
	  rmnet_ipa3_ctx->wwan_priv->net : NULL)

#define IPA_WWAN_CONS_DESC_FIFO_SZ 256

static void ipa3_rmnet_rx_cb(void *priv);
static int ipa3_rmnet_poll(struct napi_struct *napi, int budget);

static void ipa3_wake_tx_queue(struct work_struct *work);
static DECLARE_WORK(ipa3_tx_wakequeue_work, ipa3_wake_tx_queue);

struct ipa3_rmnet_plat_drv_res {
	bool ipa_rmnet_ssr;
	bool ipa_loaduC;
	bool ipa_advertise_sg_support;
	bool ipa_napi_enable;
	u32 wan_rx_desc_size;
};

/**
 * struct ipa3_wwan_private - WWAN private data
 * @net: network interface struct implemented by this driver
 * @stats: iface statistics
 * @outstanding_pkts: number of packets sent to IPA without TX complete ACKed
 * @outstanding_high: number of outstanding packets allowed
 * @outstanding_low: number of outstanding packets which shall cause
 * @ch_id: channel id
 * @lock: spinlock for mutual exclusion
 * @device_active: true if device is active
 *
 * WWAN private - holds all relevant info about WWAN driver
 */
struct ipa3_wwan_private {
	struct net_device *net;
	struct net_device_stats stats;
	atomic_t outstanding_pkts;
	int outstanding_high_ctl;
	int outstanding_high;
	int outstanding_low;
	spinlock_t lock;
	bool device_active;
	struct napi_struct napi;
};

struct rmnet_ipa3_context {
	struct ipa3_wwan_private *wwan_priv;
	struct ipa_sys_connect_params apps_to_ipa_ep_cfg;
	struct ipa_sys_connect_params ipa_to_apps_ep_cfg;
	u32 qmap_hdr_hdl;
	u32 dflt_v4_wan_rt_hdl;
	u32 dflt_v6_wan_rt_hdl;
	struct ipa3_rmnet_mux_val mux_channel[MAX_NUM_OF_MUX_CHANNEL];
	int num_q6_rules;
	int old_num_q6_rules;
	int rmnet_index;
	bool egress_set;
	bool a7_ul_flt_set;
	struct workqueue_struct *rm_q6_wq;
	atomic_t is_initialized;
	atomic_t is_ssr;
	void *subsys_notify_handle;
	u32 apps_to_ipa3_hdl;
	u32 ipa3_to_apps_hdl;
	struct mutex pipe_handle_guard;
	struct mutex add_mux_channel_lock;
};

static struct rmnet_ipa3_context *rmnet_ipa3_ctx;
static struct ipa3_rmnet_plat_drv_res ipa3_rmnet_res;

static int ipa3_find_mux_channel_index(uint32_t mux_id)
{
	int i;

	for (i = 0; i < MAX_NUM_OF_MUX_CHANNEL; i++) {
		if (mux_id == rmnet_ipa3_ctx->mux_channel[i].mux_id)
			return i;
	}
	return MAX_NUM_OF_MUX_CHANNEL;
}

/**
 * wwan_open() - Opens the wwan network interface. Opens logical
 * channel on A2 MUX driver and starts the network stack queue
 *
 * @dev: network device
 *
 * Return codes:
 * 0: success
 */
static int ipa3_wwan_open(struct net_device *dev)
{
	struct ipa3_wwan_private *wwan_ptr = netdev_priv(dev);

	ipa_debug("[%s] wwan_open()\n", dev->name);
	wwan_ptr->device_active = true;
	if (ipa3_rmnet_res.ipa_napi_enable)
		napi_enable(&wwan_ptr->napi);
	netif_start_queue(dev);

	return 0;
}

/**
 * ipa3_wwan_stop() - Stops the wwan network interface. Closes
 * logical channel on A2 MUX driver and stops the network stack
 * queue
 *
 * @dev: network device
 *
 * Return codes:
 * 0: success
 */
static int ipa3_wwan_stop(struct net_device *dev)
{
	struct ipa3_wwan_private *wwan_ptr = netdev_priv(dev);

	ipa_debug("[%s] ipa3_wwan_stop()\n", dev->name);
	wwan_ptr->device_active = false;
	netif_stop_queue(dev);

	return 0;
}

static int ipa3_wwan_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu > WWAN_DATA_LEN)
		return -EINVAL;

	ipa_debug("[%s] MTU change: old=%d new=%d\n",
		dev->name, dev->mtu, new_mtu);
	dev->mtu = new_mtu;

	return 0;
}

/**
 * ipa3_wwan_xmit() - Transmits an skb.
 *
 * @skb: skb to be transmitted
 * @dev: network device
 *
 * Return codes:
 * 0: success
 * NETDEV_TX_BUSY: Error while transmitting the skb. Try again
 * later
 * -EFAULT: Error while transmitting the skb
 */
static int ipa3_wwan_xmit(struct sk_buff *skb, struct net_device *dev)
{
	int ret = 0;
	bool qmap_check;
	struct ipa3_wwan_private *wwan_ptr = netdev_priv(dev);

	if (skb->protocol != htons(ETH_P_MAP)) {
		ipa_debug_low
		("SW filtering out none QMAP packet received from %s",
		current->comm);
		dev_kfree_skb_any(skb);
		dev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}

	qmap_check = RMNET_MAP_GET_CD_BIT(skb);
	if (netif_queue_stopped(dev)) {
		if (qmap_check &&
			atomic_read(&wwan_ptr->outstanding_pkts) <
					wwan_ptr->outstanding_high_ctl) {
			ipa_err("[%s]Queue stop, send ctrl pkts\n", dev->name);
			goto send;
		} else {
			ipa_err("[%s]fatal: ipa3_wwan_xmit stopped\n",
				  dev->name);
			return NETDEV_TX_BUSY;
		}
	}

	/* checking High WM hit */
	if (atomic_read(&wwan_ptr->outstanding_pkts) >=
					wwan_ptr->outstanding_high) {
		if (!qmap_check) {
			ipa_debug_low("pending(%d)/(%d)- stop(%d)\n",
				atomic_read(&wwan_ptr->outstanding_pkts),
				wwan_ptr->outstanding_high,
				netif_queue_stopped(dev));
			ipa_debug_low("qmap_chk(%d)\n", qmap_check);
			netif_stop_queue(dev);
			return NETDEV_TX_BUSY;
		}
	}

send:
	/*
	 * both data packts and command will be routed to
	 * IPA_CLIENT_Q6_WAN_CONS based on status configuration.
	 */
	ret = ipa3_tx_dp(IPA_CLIENT_APPS_WAN_PROD, skb, NULL);

	if (ret) {
		ret = NETDEV_TX_BUSY;
		goto out;
	}

	atomic_inc(&wwan_ptr->outstanding_pkts);
	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb->len;
	ret = NETDEV_TX_OK;
out:
	/* disable clock */
	return ret;
}

static void ipa3_wwan_tx_timeout(struct net_device *dev)
{
	ipa_err("[%s] ipa3_wwan_tx_timeout(), data stall in UL\n", dev->name);
}

/**
 * apps_ipa_tx_complete_notify() - Rx notify
 *
 * @priv: driver context
 * @evt: event type
 * @data: data provided with event
 *
 * Check that the packet is the one we sent and release it
 * This function will be called in defered context in IPA wq.
 */
static void apps_ipa_tx_complete_notify(void *priv,
		enum ipa_dp_evt_type evt,
		unsigned long data)
{
	struct sk_buff *skb = (struct sk_buff *)data;
	struct net_device *dev = (struct net_device *)priv;
	struct ipa3_wwan_private *wwan_ptr;

	if (dev != IPA_NETDEV()) {
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
	if (!atomic_read(&rmnet_ipa3_ctx->is_ssr) &&
		netif_queue_stopped(wwan_ptr->net) &&
		atomic_read(&wwan_ptr->outstanding_pkts) <
					(wwan_ptr->outstanding_low)) {
		ipa_debug_low("Outstanding low (%d) - waking up queue\n",
				wwan_ptr->outstanding_low);
		netif_wake_queue(wwan_ptr->net);
	}

	__netif_tx_unlock_bh(netdev_get_tx_queue(dev, 0));
	dev_kfree_skb_any(skb);
}

/**
 * apps_ipa_packet_receive_notify() - Rx notify
 *
 * @priv: driver context
 * @evt: event type
 * @data: data provided with event
 *
 * IPA will pass a packet to the Linux network stack with skb->data
 */
static void apps_ipa_packet_receive_notify(void *priv,
		enum ipa_dp_evt_type evt,
		unsigned long data)
{
	struct net_device *dev = (struct net_device *)priv;

	if (evt == IPA_RECEIVE) {
		struct sk_buff *skb = (struct sk_buff *)data;
		int result;
		unsigned int packet_len = skb->len;

		ipa_debug("Rx packet was received\n");
		skb->dev = IPA_NETDEV();
		skb->protocol = htons(ETH_P_MAP);

		if (ipa3_rmnet_res.ipa_napi_enable) {
			result = netif_receive_skb(skb);
		} else {
			if (dev->stats.rx_packets % IPA_WWAN_RX_SOFTIRQ_THRESH
					== 0) {
				result = netif_rx_ni(skb);
			} else
				result = netif_rx(skb);
		}

		if (result)	{
			pr_err_ratelimited("fail on netif_receive_skb\n");
			dev->stats.rx_dropped++;
		}
		dev->stats.rx_packets++;
		dev->stats.rx_bytes += packet_len;
	} else if (evt == IPA_CLIENT_START_POLL)
		ipa3_rmnet_rx_cb(priv);
	else if (evt == IPA_CLIENT_COMP_NAPI) {
		if (ipa3_rmnet_res.ipa_napi_enable)
			napi_complete(&(rmnet_ipa3_ctx->wwan_priv->napi));
	} else
		ipa_err("Invalid evt %d received in wan_ipa_receive\n", evt);
}

static int handle3_ingress_format(struct net_device *dev,
			struct rmnet_ioctl_extended_s *in)
{
	int ret = 0;
	struct ipa_sys_connect_params *ipa_wan_ep_cfg;

	ipa_debug("Get RMNET_IOCTL_SET_INGRESS_DATA_FORMAT\n");
	ipa_wan_ep_cfg = &rmnet_ipa3_ctx->ipa_to_apps_ep_cfg;
	if ((in->u.data) & RMNET_IOCTL_INGRESS_FORMAT_CHECKSUM)
		ipa_wan_ep_cfg->ipa_ep_cfg.cfg.cs_offload_en =
		   IPA_ENABLE_CS_OFFLOAD_DL;

	if ((in->u.data) & RMNET_IOCTL_INGRESS_FORMAT_AGG_DATA) {
		ipa_debug("get AGG size %d count %d\n",
				  in->u.ingress_format.agg_size,
				  in->u.ingress_format.agg_count);

		ret = ipa3_disable_apps_wan_cons_deaggr(
			  in->u.ingress_format.agg_size,
			  in->u.ingress_format.agg_count);

		if (!ret) {
			ipa_wan_ep_cfg->ipa_ep_cfg.aggr.aggr_byte_limit =
			   in->u.ingress_format.agg_size;
			ipa_wan_ep_cfg->ipa_ep_cfg.aggr.aggr_pkt_limit =
			   in->u.ingress_format.agg_count;
		}
	}

	ipa_wan_ep_cfg->ipa_ep_cfg.hdr.hdr_len = 4;
	ipa_wan_ep_cfg->ipa_ep_cfg.hdr.hdr_ofst_metadata_valid = 1;
	ipa_wan_ep_cfg->ipa_ep_cfg.hdr.hdr_ofst_metadata = 1;
	ipa_wan_ep_cfg->ipa_ep_cfg.hdr.hdr_ofst_pkt_size_valid = 1;
	ipa_wan_ep_cfg->ipa_ep_cfg.hdr.hdr_ofst_pkt_size = 2;

	ipa_wan_ep_cfg->ipa_ep_cfg.hdr_ext.hdr_total_len_or_pad_valid = true;
	ipa_wan_ep_cfg->ipa_ep_cfg.hdr_ext.hdr_total_len_or_pad = 0;
	ipa_wan_ep_cfg->ipa_ep_cfg.hdr_ext.hdr_payload_len_inc_padding = true;
	ipa_wan_ep_cfg->ipa_ep_cfg.hdr_ext.hdr_total_len_or_pad_offset = 0;
	ipa_wan_ep_cfg->ipa_ep_cfg.hdr_ext.hdr_little_endian = 0;
	ipa_wan_ep_cfg->ipa_ep_cfg.metadata_mask.metadata_mask = 0xFF000000;

	ipa_wan_ep_cfg->client = IPA_CLIENT_APPS_WAN_CONS;
	ipa_wan_ep_cfg->notify = apps_ipa_packet_receive_notify;
	ipa_wan_ep_cfg->priv = dev;

	ipa_wan_ep_cfg->napi_enabled = ipa3_rmnet_res.ipa_napi_enable;
	ipa_wan_ep_cfg->desc_fifo_sz =
		ipa3_rmnet_res.wan_rx_desc_size * IPA_FIFO_ELEMENT_SIZE;

	mutex_lock(&rmnet_ipa3_ctx->pipe_handle_guard);

	if (atomic_read(&rmnet_ipa3_ctx->is_ssr)) {
		ipa_debug("In SSR sequence/recovery\n");
		mutex_unlock(&rmnet_ipa3_ctx->pipe_handle_guard);
		return -EFAULT;
	}
	ret = ipa3_setup_sys_pipe(&rmnet_ipa3_ctx->ipa_to_apps_ep_cfg,
	   &rmnet_ipa3_ctx->ipa3_to_apps_hdl);

	mutex_unlock(&rmnet_ipa3_ctx->pipe_handle_guard);

	if (ret)
		ipa_err("failed to configure ingress\n");

	return ret;
}

/**
 * handle3_egress_format() - Egress data format configuration
 *
 * Setup IPA egress system pipe and Configure:
 *	header handling, checksum, de-aggregation and fifo size
 *
 * @dev: network device
 * @e: egress configuration
 */
static int handle3_egress_format(struct net_device *dev,
			struct rmnet_ioctl_extended_s *e)
{
	int rc;
	struct ipa_sys_connect_params *ipa_wan_ep_cfg;

	ipa_debug("get RMNET_IOCTL_SET_EGRESS_DATA_FORMAT\n");
	ipa_wan_ep_cfg = &rmnet_ipa3_ctx->apps_to_ipa_ep_cfg;
	if ((e->u.data) & RMNET_IOCTL_EGRESS_FORMAT_CHECKSUM) {
		ipa_wan_ep_cfg->ipa_ep_cfg.hdr.hdr_len = 8;
		ipa_wan_ep_cfg->ipa_ep_cfg.cfg.cs_offload_en =
			IPA_ENABLE_CS_OFFLOAD_UL;
		ipa_wan_ep_cfg->ipa_ep_cfg.cfg.cs_metadata_hdr_offset = 1;
	} else {
		ipa_wan_ep_cfg->ipa_ep_cfg.hdr.hdr_len = 4;
	}

	if ((e->u.data) & RMNET_IOCTL_EGRESS_FORMAT_AGGREGATION) {
		ipa_err("WAN UL Aggregation enabled\n");

		ipa_wan_ep_cfg->ipa_ep_cfg.aggr.aggr_en = IPA_ENABLE_DEAGGR;
		ipa_wan_ep_cfg->ipa_ep_cfg.aggr.aggr = IPA_QCMAP;

		ipa_wan_ep_cfg->ipa_ep_cfg.deaggr.packet_offset_valid = false;

		ipa_wan_ep_cfg->ipa_ep_cfg.hdr.hdr_ofst_pkt_size = 2;

		ipa_wan_ep_cfg->ipa_ep_cfg.hdr_ext.hdr_total_len_or_pad_valid =
			true;
		ipa_wan_ep_cfg->ipa_ep_cfg.hdr_ext.hdr_total_len_or_pad =
			IPA_HDR_PAD;
		ipa_wan_ep_cfg->ipa_ep_cfg.hdr_ext.hdr_pad_to_alignment =
			2;
		ipa_wan_ep_cfg->ipa_ep_cfg.hdr_ext.hdr_payload_len_inc_padding =
			true;
		ipa_wan_ep_cfg->ipa_ep_cfg.hdr_ext.hdr_total_len_or_pad_offset =
			0;
		ipa_wan_ep_cfg->ipa_ep_cfg.hdr_ext.hdr_little_endian =
			false;
	} else {
		ipa_debug("WAN UL Aggregation disabled\n");
		ipa_wan_ep_cfg->ipa_ep_cfg.aggr.aggr_en = IPA_BYPASS_AGGR;
	}

	ipa_wan_ep_cfg->ipa_ep_cfg.hdr.hdr_ofst_metadata_valid = 1;
	/* modem want offset at 0! */
	ipa_wan_ep_cfg->ipa_ep_cfg.hdr.hdr_ofst_metadata = 0;

	ipa_wan_ep_cfg->ipa_ep_cfg.mode.dst = IPA_CLIENT_APPS_WAN_PROD;
	ipa_wan_ep_cfg->ipa_ep_cfg.mode.mode = IPA_BASIC;

	ipa_wan_ep_cfg->client = IPA_CLIENT_APPS_WAN_PROD;
	ipa_wan_ep_cfg->notify = apps_ipa_tx_complete_notify;
	ipa_wan_ep_cfg->desc_fifo_sz = IPA_SYS_TX_DATA_DESC_FIFO_SZ;
	ipa_wan_ep_cfg->priv = dev;

	mutex_lock(&rmnet_ipa3_ctx->pipe_handle_guard);
	if (atomic_read(&rmnet_ipa3_ctx->is_ssr)) {
		ipa_debug("In SSR sequence/recovery\n");
		mutex_unlock(&rmnet_ipa3_ctx->pipe_handle_guard);
		return -EFAULT;
	}
	rc = ipa3_setup_sys_pipe(
		ipa_wan_ep_cfg, &rmnet_ipa3_ctx->apps_to_ipa3_hdl);
	if (rc) {
		ipa_err("failed to config egress endpoint\n");
		mutex_unlock(&rmnet_ipa3_ctx->pipe_handle_guard);
		return rc;
	}
	mutex_unlock(&rmnet_ipa3_ctx->pipe_handle_guard);

	if (rmnet_ipa3_ctx->num_q6_rules != 0) {
		rmnet_ipa3_ctx->a7_ul_flt_set = true;
	} else {
		/* wait Q6 UL filter rules*/
		ipa_debug("no UL-rules\n");
	}
	rmnet_ipa3_ctx->egress_set = true;

	return rc;
}

/**
 * ipa3_wwan_ioctl() - I/O control for wwan network driver.
 *
 * @dev: network device
 * @ifr: ignored
 * @cmd: cmd to be excecuded. can be one of the following:
 * IPA_WWAN_IOCTL_OPEN - Open the network interface
 * IPA_WWAN_IOCTL_CLOSE - Close the network interface
 *
 * Return codes:
 * 0: success
 * NETDEV_TX_BUSY: Error while transmitting the skb. Try again
 * later
 * -EFAULT: Error while transmitting the skb
 */
static int ipa3_wwan_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	int rc = 0;
	int mru = 1000, epid = 1, mux_index;
	struct rmnet_ioctl_extended_s extend_ioctl_data;
	struct rmnet_ioctl_data_s ioctl_data;
	struct ipa3_rmnet_mux_val *mux_channel;
	int rmnet_index;

	ipa_debug("rmnet_ipa got ioctl number 0x%08x", cmd);
	switch (cmd) {
	/*  Set Ethernet protocol  */
	case RMNET_IOCTL_SET_LLP_ETHERNET:
		break;
	/*  Set RAWIP protocol  */
	case RMNET_IOCTL_SET_LLP_IP:
		break;
	/*  Get link protocol  */
	case RMNET_IOCTL_GET_LLP:
		ioctl_data.u.operation_mode = RMNET_MODE_LLP_IP;
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &ioctl_data,
			sizeof(struct rmnet_ioctl_data_s)))
			rc = -EFAULT;
		break;
	/*  Set QoS header enabled  */
	case RMNET_IOCTL_SET_QOS_ENABLE:
		return -EINVAL;
	/*  Set QoS header disabled  */
	case RMNET_IOCTL_SET_QOS_DISABLE:
		break;
	/*  Get QoS header state  */
	case RMNET_IOCTL_GET_QOS:
		ioctl_data.u.operation_mode = RMNET_MODE_NONE;
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &ioctl_data,
			sizeof(struct rmnet_ioctl_data_s)))
			rc = -EFAULT;
		break;
	/*  Get operation mode */
	case RMNET_IOCTL_GET_OPMODE:
		ioctl_data.u.operation_mode = RMNET_MODE_LLP_IP;
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &ioctl_data,
			sizeof(struct rmnet_ioctl_data_s)))
			rc = -EFAULT;
		break;
	/*  Open transport port  */
	case RMNET_IOCTL_OPEN:
		break;
	/*  Close transport port  */
	case RMNET_IOCTL_CLOSE:
		break;
	/*  Flow enable  */
	case RMNET_IOCTL_FLOW_ENABLE:
		ipa_err("RMNET_IOCTL_FLOW_ENABLE not supported\n");
		rc = -EFAULT;
		break;
	/*  Flow disable  */
	case RMNET_IOCTL_FLOW_DISABLE:
		ipa_err("RMNET_IOCTL_FLOW_DISABLE not supported\n");
		rc = -EFAULT;
		break;
	/*  Set flow handle  */
	case RMNET_IOCTL_FLOW_SET_HNDL:
		break;

	/*  Extended IOCTLs  */
	case RMNET_IOCTL_EXTENDED:
		ipa_debug("get ioctl: RMNET_IOCTL_EXTENDED\n");
		if (copy_from_user(&extend_ioctl_data,
			(u8 *)ifr->ifr_ifru.ifru_data,
			sizeof(struct rmnet_ioctl_extended_s))) {
			ipa_err("failed to copy extended ioctl data\n");
			rc = -EFAULT;
			break;
		}
		switch (extend_ioctl_data.extended_ioctl) {
		/*  Get features  */
		case RMNET_IOCTL_GET_SUPPORTED_FEATURES:
			ipa_debug("get RMNET_IOCTL_GET_SUPPORTED_FEATURES\n");
			extend_ioctl_data.u.data =
				(RMNET_IOCTL_FEAT_NOTIFY_MUX_CHANNEL |
				RMNET_IOCTL_FEAT_SET_EGRESS_DATA_FORMAT |
				RMNET_IOCTL_FEAT_SET_INGRESS_DATA_FORMAT);
			if (copy_to_user((u8 *)ifr->ifr_ifru.ifru_data,
				&extend_ioctl_data,
				sizeof(struct rmnet_ioctl_extended_s)))
				rc = -EFAULT;
			break;
		/*  Set MRU  */
		case RMNET_IOCTL_SET_MRU:
			mru = extend_ioctl_data.u.data;
			ipa_debug("get MRU size %d\n",
				extend_ioctl_data.u.data);
			break;
		/*  Get MRU  */
		case RMNET_IOCTL_GET_MRU:
			extend_ioctl_data.u.data = mru;
			if (copy_to_user((u8 *)ifr->ifr_ifru.ifru_data,
				&extend_ioctl_data,
				sizeof(struct rmnet_ioctl_extended_s)))
				rc = -EFAULT;
			break;
		/* GET SG support */
		case RMNET_IOCTL_GET_SG_SUPPORT:
			extend_ioctl_data.u.data =
				ipa3_rmnet_res.ipa_advertise_sg_support;
			if (copy_to_user((u8 *)ifr->ifr_ifru.ifru_data,
				&extend_ioctl_data,
				sizeof(struct rmnet_ioctl_extended_s)))
				rc = -EFAULT;
			break;
		/*  Get endpoint ID  */
		case RMNET_IOCTL_GET_EPID:
			ipa_debug("get ioctl: RMNET_IOCTL_GET_EPID\n");
			extend_ioctl_data.u.data = epid;
			if (copy_to_user((u8 *)ifr->ifr_ifru.ifru_data,
				&extend_ioctl_data,
				sizeof(struct rmnet_ioctl_extended_s)))
				rc = -EFAULT;
			if (copy_from_user(&extend_ioctl_data,
				(u8 *)ifr->ifr_ifru.ifru_data,
				sizeof(struct rmnet_ioctl_extended_s))) {
				ipa_err("copy extended ioctl data failed\n");
				rc = -EFAULT;
			break;
			}
			ipa_debug("RMNET_IOCTL_GET_EPID return %d\n",
					extend_ioctl_data.u.data);
			break;
		/*  Endpoint pair  */
		case RMNET_IOCTL_GET_EP_PAIR:
			ipa_debug("get ioctl: RMNET_IOCTL_GET_EP_PAIR\n");
			extend_ioctl_data.u.ipa_ep_pair.consumer_pipe_num =
			ipa3_get_ep_mapping(IPA_CLIENT_APPS_WAN_PROD);
			extend_ioctl_data.u.ipa_ep_pair.producer_pipe_num =
			ipa3_get_ep_mapping(IPA_CLIENT_APPS_WAN_CONS);
			if (copy_to_user((u8 *)ifr->ifr_ifru.ifru_data,
				&extend_ioctl_data,
				sizeof(struct rmnet_ioctl_extended_s)))
				rc = -EFAULT;
			if (copy_from_user(&extend_ioctl_data,
				(u8 *)ifr->ifr_ifru.ifru_data,
				sizeof(struct rmnet_ioctl_extended_s))) {
				ipa_err("copy extended ioctl data failed\n");
				rc = -EFAULT;
			break;
		}
			ipa_debug("RMNET_IOCTL_GET_EP_PAIR c: %d p: %d\n",
			extend_ioctl_data.u.ipa_ep_pair.consumer_pipe_num,
			extend_ioctl_data.u.ipa_ep_pair.producer_pipe_num);
			break;
		/*  Get driver name  */
		case RMNET_IOCTL_GET_DRIVER_NAME:
			memcpy(&extend_ioctl_data.u.if_name,
				IPA_NETDEV()->name,
							sizeof(IFNAMSIZ));
			if (copy_to_user((u8 *)ifr->ifr_ifru.ifru_data,
					&extend_ioctl_data,
					sizeof(struct rmnet_ioctl_extended_s)))
				rc = -EFAULT;
			break;
		/*  Add MUX ID  */
		case RMNET_IOCTL_ADD_MUX_CHANNEL:
			mux_index = ipa3_find_mux_channel_index(
				extend_ioctl_data.u.rmnet_mux_val.mux_id);
			if (mux_index < MAX_NUM_OF_MUX_CHANNEL) {
				ipa_debug("already setup mux(%d)\n",
					extend_ioctl_data.u.
					rmnet_mux_val.mux_id);
				return rc;
			}
			mutex_lock(&rmnet_ipa3_ctx->add_mux_channel_lock);
			if (rmnet_ipa3_ctx->rmnet_index
				>= MAX_NUM_OF_MUX_CHANNEL) {
				ipa_err("Exceed mux_channel limit(%d)\n",
				rmnet_ipa3_ctx->rmnet_index);
				mutex_unlock(&rmnet_ipa3_ctx->
					add_mux_channel_lock);
				return -EFAULT;
			}
			ipa_debug("ADD_MUX_CHANNEL(%d, name: %s)\n",
			extend_ioctl_data.u.rmnet_mux_val.mux_id,
			extend_ioctl_data.u.rmnet_mux_val.vchannel_name);
			/* cache the mux name and id */
			mux_channel = rmnet_ipa3_ctx->mux_channel;
			rmnet_index = rmnet_ipa3_ctx->rmnet_index;

			mux_channel[rmnet_index].mux_id =
				extend_ioctl_data.u.rmnet_mux_val.mux_id;
			memcpy(mux_channel[rmnet_index].vchannel_name,
				extend_ioctl_data.u.rmnet_mux_val.vchannel_name,
				sizeof(mux_channel[rmnet_index]
					.vchannel_name));
			mux_channel[rmnet_index].vchannel_name[
				IFNAMSIZ - 1] = '\0';

			ipa_debug("cashe device[%s:%d] in IPA_wan[%d]\n",
				mux_channel[rmnet_index].vchannel_name,
				mux_channel[rmnet_index].mux_id,
				rmnet_index);
			rmnet_ipa3_ctx->rmnet_index++;
			mutex_unlock(&rmnet_ipa3_ctx->add_mux_channel_lock);
			break;
		case RMNET_IOCTL_SET_EGRESS_DATA_FORMAT:
			if (handle3_egress_format(dev, &extend_ioctl_data))
				rc = -EFAULT;
			break;
		case RMNET_IOCTL_SET_INGRESS_DATA_FORMAT:/*  Set IDF  */
			if (handle3_ingress_format(dev, &extend_ioctl_data))
				rc = -EFAULT;
			break;
		/*  Get agg count  */
		case RMNET_IOCTL_GET_AGGREGATION_COUNT:
			break;
		/*  Set agg count  */
		case RMNET_IOCTL_SET_AGGREGATION_COUNT:
			break;
		/*  Get agg size  */
		case RMNET_IOCTL_GET_AGGREGATION_SIZE:
			break;
		/*  Set agg size  */
		case RMNET_IOCTL_SET_AGGREGATION_SIZE:
			break;
		/*  Do flow control  */
		case RMNET_IOCTL_FLOW_CONTROL:
			break;
		/*  For legacy use  */
		case RMNET_IOCTL_GET_DFLT_CONTROL_CHANNEL:
			break;
		/*  Get HW/SW map  */
		case RMNET_IOCTL_GET_HWSW_MAP:
			break;
		/*  Set RX Headroom  */
		case RMNET_IOCTL_SET_RX_HEADROOM:
			break;
		default:
			ipa_err("[%s] unsupported extended cmd[%d]",
				dev->name,
				extend_ioctl_data.extended_ioctl);
			rc = -EINVAL;
		}
		break;
	default:
			ipa_err("[%s] unsupported cmd[%d]",
				dev->name, cmd);
			rc = -EINVAL;
	}
	return rc;
}

static const struct net_device_ops ipa3_wwan_ops_ip = {
	.ndo_open = ipa3_wwan_open,
	.ndo_stop = ipa3_wwan_stop,
	.ndo_start_xmit = ipa3_wwan_xmit,
	.ndo_tx_timeout = ipa3_wwan_tx_timeout,
	.ndo_do_ioctl = ipa3_wwan_ioctl,
	.ndo_change_mtu = ipa3_wwan_change_mtu,
	.ndo_set_mac_address = 0,
	.ndo_validate_addr = 0,
};

/**
 * wwan_setup() - Setups the wwan network driver.
 *
 * @dev: network device
 *
 * Return codes:
 * None
 */
static void ipa3_wwan_setup(struct net_device *dev)
{
	dev->netdev_ops = &ipa3_wwan_ops_ip;
	ether_setup(dev);
	dev->header_ops = NULL;  /* No header (override ether_setup() value) */
	dev->type = ARPHRD_RAWIP;
	dev->hard_header_len = 0;
	dev->mtu = WWAN_DATA_LEN;
	dev->addr_len = 0;
	dev->flags &= ~(IFF_BROADCAST | IFF_MULTICAST);
	dev->needed_headroom = HEADROOM_FOR_QMAP;
	dev->needed_tailroom = TAILROOM;
	dev->watchdog_timeo = 10 * HZ;
}

static void ipa3_wake_tx_queue(struct work_struct *work)
{
	if (IPA_NETDEV()) {
		__netif_tx_lock_bh(netdev_get_tx_queue(IPA_NETDEV(), 0));
		netif_wake_queue(IPA_NETDEV());
		__netif_tx_unlock_bh(netdev_get_tx_queue(IPA_NETDEV(), 0));
	}
}

static int ipa3_ssr_notifier_cb(struct notifier_block *this,
			   unsigned long code,
			   void *data);

static struct notifier_block ipa3_ssr_notifier = {
	.notifier_call = ipa3_ssr_notifier_cb,
};

static int get_ipa_rmnet_dts_configuration(struct platform_device *pdev,
		struct ipa3_rmnet_plat_drv_res *ipa_rmnet_drv_res)
{
	int result;

	ipa_rmnet_drv_res->wan_rx_desc_size = IPA_WWAN_CONS_DESC_FIFO_SZ;
	ipa_rmnet_drv_res->ipa_rmnet_ssr =
			of_property_read_bool(pdev->dev.of_node,
			"qcom,rmnet-ipa-ssr");
	ipa_info("IPA SSR support = %s\n",
		ipa_rmnet_drv_res->ipa_rmnet_ssr ? "True" : "False");
	ipa_rmnet_drv_res->ipa_loaduC =
			of_property_read_bool(pdev->dev.of_node,
			"qcom,ipa-loaduC");
	ipa_info("IPA ipa-loaduC = %s\n",
		ipa_rmnet_drv_res->ipa_loaduC ? "True" : "False");

	ipa_rmnet_drv_res->ipa_advertise_sg_support =
		of_property_read_bool(pdev->dev.of_node,
		"qcom,ipa-advertise-sg-support");
	ipa_info("IPA SG support = %s\n",
		ipa_rmnet_drv_res->ipa_advertise_sg_support ? "True" : "False");

	ipa_rmnet_drv_res->ipa_napi_enable =
		of_property_read_bool(pdev->dev.of_node,
			"qcom,ipa-napi-enable");
	ipa_info("IPA Napi Enable = %s\n",
		ipa_rmnet_drv_res->ipa_napi_enable ? "True" : "False");

	/* Get IPA WAN RX desc fifo size */
	result = of_property_read_u32(pdev->dev.of_node,
			"qcom,wan-rx-desc-size",
			&ipa_rmnet_drv_res->wan_rx_desc_size);
	if (result)
		ipa_info("using default for wan-rx-desc-size = %u\n",
				ipa_rmnet_drv_res->wan_rx_desc_size);
	else
		ipa_debug(": found ipa_drv_res->wan-rx-desc-size = %u\n",
				ipa_rmnet_drv_res->wan_rx_desc_size);

	return 0;
}

struct ipa3_rmnet_context ipa3_rmnet_ctx;

/**
 * ipa3_wwan_probe() - Initialized the module and registers as a
 * network interface to the network stack
 *
 * Note: In case IPA driver hasn't initialized already, the probe function
 * will return immediately after registering a callback to be invoked when
 * IPA driver initialization is complete.
 *
 * Return codes:
 * 0: success
 * -ENOMEM: No memory available
 * -EFAULT: Internal error
 */
static int ipa3_wwan_probe(struct platform_device *pdev)
{
	int ret, i;
	struct net_device *dev;

	ipa_info("rmnet_ipa3 started initialization\n");

	if (atomic_read(&ipa3_ctx->state) != IPA_STATE_READY) {
		ipa_debug("IPA driver not ready, deferring\n");
		return -EPROBE_DEFER;
	}

	ret = get_ipa_rmnet_dts_configuration(pdev, &ipa3_rmnet_res);
	ipa3_rmnet_ctx.ipa_rmnet_ssr = ipa3_rmnet_res.ipa_rmnet_ssr;

	ret = ipa3_init_q6_smem();
	if (ret) {
		ipa_err("ipa3_init_q6_smem failed!\n");
		return ret;
	}

	/* initialize tx/rx endpoint setup */
	memset(&rmnet_ipa3_ctx->apps_to_ipa_ep_cfg, 0,
		sizeof(struct ipa_sys_connect_params));
	memset(&rmnet_ipa3_ctx->ipa_to_apps_ep_cfg, 0,
		sizeof(struct ipa_sys_connect_params));

	/* initialize ex property setup */
	rmnet_ipa3_ctx->num_q6_rules = 0;
	rmnet_ipa3_ctx->old_num_q6_rules = 0;
	rmnet_ipa3_ctx->rmnet_index = 0;
	rmnet_ipa3_ctx->egress_set = false;
	rmnet_ipa3_ctx->a7_ul_flt_set = false;
	for (i = 0; i < MAX_NUM_OF_MUX_CHANNEL; i++)
		memset(&rmnet_ipa3_ctx->mux_channel[i], 0,
				sizeof(struct ipa3_rmnet_mux_val));

	/* start A7 QMI service/client */
	if (ipa3_rmnet_res.ipa_loaduC)
		/* Android platform loads uC */
		ipa3_qmi_service_init(QMI_IPA_PLATFORM_TYPE_MSM_ANDROID_V01);
	else
		/* LE platform not loads uC */
		ipa3_qmi_service_init(QMI_IPA_PLATFORM_TYPE_LE_V01);

	/* initialize wan-driver netdev */
	dev = alloc_netdev(sizeof(struct ipa3_wwan_private),
			   IPA_WWAN_DEV_NAME,
			   NET_NAME_UNKNOWN,
			   ipa3_wwan_setup);
	if (!dev) {
		ipa_err("no memory for netdev\n");
		ret = -ENOMEM;
		goto alloc_netdev_err;
	}
	rmnet_ipa3_ctx->wwan_priv = netdev_priv(dev);
	ipa_debug("wwan_ptr (private) = %p", rmnet_ipa3_ctx->wwan_priv);
	rmnet_ipa3_ctx->wwan_priv->net = dev;
	rmnet_ipa3_ctx->wwan_priv->outstanding_high = DEFAULT_OUTSTANDING_HIGH;
	rmnet_ipa3_ctx->wwan_priv->outstanding_low = DEFAULT_OUTSTANDING_LOW;
	atomic_set(&rmnet_ipa3_ctx->wwan_priv->outstanding_pkts, 0);
	spin_lock_init(&rmnet_ipa3_ctx->wwan_priv->lock);

	/* Enable SG support in netdevice. */
	if (ipa3_rmnet_res.ipa_advertise_sg_support)
		dev->hw_features |= NETIF_F_SG;

	if (ipa3_rmnet_res.ipa_napi_enable)
		netif_napi_add(dev, &(rmnet_ipa3_ctx->wwan_priv->napi),
		       ipa3_rmnet_poll, NAPI_WEIGHT);
	ret = register_netdev(dev);
	if (ret) {
		ipa_err("unable to register ipa_netdev %d rc=%d\n", 0, ret);
		goto config_err;
	}

	ipa_debug("IPA-WWAN devices (%s) initialization ok :>>>>\n", dev->name);
	atomic_set(&rmnet_ipa3_ctx->is_initialized, 1);
	if (!atomic_read(&rmnet_ipa3_ctx->is_ssr)) {
		/* offline charging mode */
		ipa3_proxy_clk_unvote();
	}
	atomic_set(&rmnet_ipa3_ctx->is_ssr, 0);

	/* Till the system is suspended, we keep the clock open */
	IPA_ACTIVE_CLIENTS_INC_SIMPLE();
	ipa_err("rmnet_ipa completed initialization\n");
	return 0;
config_err:
	if (ipa3_rmnet_res.ipa_napi_enable)
		netif_napi_del(&(rmnet_ipa3_ctx->wwan_priv->napi));
	unregister_netdev(dev);

alloc_netdev_err:
	atomic_set(&rmnet_ipa3_ctx->is_ssr, 0);

	return ret;
}

static int ipa3_wwan_remove(struct platform_device *pdev)
{
	int ret;

	ipa_info("rmnet_ipa started deinitialization\n");
	mutex_lock(&rmnet_ipa3_ctx->pipe_handle_guard);
	ret = ipa3_teardown_sys_pipe(rmnet_ipa3_ctx->ipa3_to_apps_hdl);
	if (ret < 0)
		ipa_err("Failed to teardown IPA->APPS pipe\n");
	else
		rmnet_ipa3_ctx->ipa3_to_apps_hdl = -1;
	ret = ipa3_teardown_sys_pipe(rmnet_ipa3_ctx->apps_to_ipa3_hdl);
	if (ret < 0)
		ipa_err("Failed to teardown APPS->IPA pipe\n");
	else
		rmnet_ipa3_ctx->apps_to_ipa3_hdl = -1;
	if (ipa3_rmnet_res.ipa_napi_enable)
		netif_napi_del(&(rmnet_ipa3_ctx->wwan_priv->napi));
	mutex_unlock(&rmnet_ipa3_ctx->pipe_handle_guard);
	unregister_netdev(IPA_NETDEV());

	cancel_work_sync(&ipa3_tx_wakequeue_work);
	if (IPA_NETDEV())
		free_netdev(IPA_NETDEV());
	rmnet_ipa3_ctx->wwan_priv = NULL;

	atomic_set(&rmnet_ipa3_ctx->is_initialized, 0);
	ipa_info("rmnet_ipa completed deinitialization\n");
	return 0;
}

/**
* rmnet_ipa_ap_suspend() - suspend callback for runtime_pm
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
	struct net_device *netdev = IPA_NETDEV();
	struct ipa3_wwan_private *wwan_ptr;
	int ret;

	ipa_debug("Enter...\n");
	if (netdev == NULL) {
		ipa_err("netdev is NULL.\n");
		ret = 0;
		goto bail;
	}

	netif_tx_lock_bh(netdev);
	wwan_ptr = netdev_priv(netdev);
	if (wwan_ptr == NULL) {
		ipa_err("wwan_ptr is NULL.\n");
		ret = 0;
		goto unlock_and_bail;
	}

	/* Do not allow A7 to suspend in case there are oustanding packets */
	if (atomic_read(&wwan_ptr->outstanding_pkts) != 0) {
		ipa_debug("Outstanding packets, postponing AP suspend.\n");
		ret = -EAGAIN;
		goto unlock_and_bail;
	}

	/* Make sure that there is no Tx operation ongoing */
	netif_stop_queue(netdev);

	ret = 0;
	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
	ipa_debug("IPA clocks disabled\n");

unlock_and_bail:
	netif_tx_unlock_bh(netdev);
bail:
	ipa_debug("Exit with %d\n", ret);

	return ret;
}

/**
* rmnet_ipa_ap_resume() - resume callback for runtime_pm
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
	struct net_device *netdev = IPA_NETDEV();

	IPA_ACTIVE_CLIENTS_INC_SIMPLE();
	ipa_debug("IPA clocks enabled\n");
	if (netdev)
		netif_wake_queue(netdev);
	ipa_debug("Exit\n");

	return 0;
}

static void ipa_stop_polling_stats(void)
{
	ipa3_rmnet_ctx.polling_interval = 0;
}

static const struct of_device_id rmnet_ipa_dt_match[] = {
	{.compatible = "qcom,rmnet-ipa3"},
	{},
};
MODULE_DEVICE_TABLE(of, rmnet_ipa_dt_match);

static const struct dev_pm_ops rmnet_ipa_pm_ops = {
	.suspend_noirq = rmnet_ipa_ap_suspend,
	.resume_noirq = rmnet_ipa_ap_resume,
};

static struct platform_driver rmnet_ipa_driver = {
	.driver = {
		.name = "rmnet_ipa3",
		.owner = THIS_MODULE,
		.pm = &rmnet_ipa_pm_ops,
		.of_match_table = rmnet_ipa_dt_match,
	},
	.probe = ipa3_wwan_probe,
	.remove = ipa3_wwan_remove,
};

static int ipa3_ssr_notifier_cb(struct notifier_block *this,
			   unsigned long code,
			   void *data)
{
	if (!ipa3_rmnet_ctx.ipa_rmnet_ssr)
		return NOTIFY_DONE;

	switch (code) {
	case SUBSYS_BEFORE_SHUTDOWN:
		ipa_info("IPA received MPSS BEFORE_SHUTDOWN\n");
		atomic_set(&rmnet_ipa3_ctx->is_ssr, 1);
		ipa3_q6_pre_shutdown_cleanup();
		if (IPA_NETDEV())
			netif_stop_queue(IPA_NETDEV());

		ipa3_qmi_stop_workqueues();
		ipa_stop_polling_stats();
		if (atomic_read(&rmnet_ipa3_ctx->is_initialized))
			platform_driver_unregister(&rmnet_ipa_driver);
		ipa_info("IPA BEFORE_SHUTDOWN handling is complete\n");
		break;
	case SUBSYS_AFTER_SHUTDOWN:
		ipa_info("IPA Received MPSS AFTER_SHUTDOWN\n");
		if (atomic_read(&rmnet_ipa3_ctx->is_ssr))
			ipa3_q6_post_shutdown_cleanup();
		ipa_info("IPA AFTER_SHUTDOWN handling is complete\n");
		break;
	case SUBSYS_BEFORE_POWERUP:
		ipa_info("IPA received MPSS BEFORE_POWERUP\n");
		if (atomic_read(&rmnet_ipa3_ctx->is_ssr))
			/* clean up cached QMI msg/handlers */
			ipa3_qmi_service_exit();

		/*hold a proxy vote for the modem*/
		ipa3_proxy_clk_vote();
		ipa3_reset_freeze_vote();
		ipa_info("IPA BEFORE_POWERUP handling is complete\n");
		break;
	case SUBSYS_AFTER_POWERUP:
		ipa_info("%s:%d IPA received MPSS AFTER_POWERUP\n",
			__func__, __LINE__);
		if (!atomic_read(&rmnet_ipa3_ctx->is_initialized) &&
		       atomic_read(&rmnet_ipa3_ctx->is_ssr))
			platform_driver_register(&rmnet_ipa_driver);

		ipa_info("IPA AFTER_POWERUP handling is complete\n");
		break;
	default:
		ipa_debug("Unsupported subsys notification, IPA received: %lu",
			code);
		break;
	}

	ipa_debug_low("Exit\n");
	return NOTIFY_DONE;
}


/**
 * ipa3_q6_handshake_complete() - Perform operations once Q6 is up
 * @ssr_bootup - Indicates whether this is a cold boot-up or post-SSR.
 *
 * This function is invoked once the handshake between the IPA AP driver
 * and IPA Q6 driver is complete. At this point, it is possible to perform
 * operations which can't be performed until IPA Q6 driver is up.
 *
 */
void ipa3_q6_handshake_complete(bool ssr_bootup)
{
	/* It is required to recover the network stats after SSR recovery */
	if (ssr_bootup) {
		/*
		 * In case the uC is required to be loaded by the Modem,
		 * the proxy vote will be removed only when uC loading is
		 * complete and indication is received by the AP. After SSR,
		 * uC is already loaded. Therefore, proxy vote can be removed
		 * once Modem init is complete.
		 */
		ipa3_proxy_clk_unvote();
	}
}

static int __init ipa3_wwan_init(void)
{
	rmnet_ipa3_ctx = kzalloc(sizeof(*rmnet_ipa3_ctx), GFP_KERNEL);
	if (!rmnet_ipa3_ctx) {
		ipa_err("no memory\n");
		return -ENOMEM;
	}

	atomic_set(&rmnet_ipa3_ctx->is_initialized, 0);
	atomic_set(&rmnet_ipa3_ctx->is_ssr, 0);

	mutex_init(&rmnet_ipa3_ctx->pipe_handle_guard);
	mutex_init(&rmnet_ipa3_ctx->add_mux_channel_lock);
	rmnet_ipa3_ctx->ipa3_to_apps_hdl = -1;
	rmnet_ipa3_ctx->apps_to_ipa3_hdl = -1;

	/* Register for Modem SSR */
	rmnet_ipa3_ctx->subsys_notify_handle = subsys_notif_register_notifier(
			SUBSYS_MODEM,
			&ipa3_ssr_notifier);
	if (!IS_ERR(rmnet_ipa3_ctx->subsys_notify_handle))
		return platform_driver_register(&rmnet_ipa_driver);
	else
		return (int)PTR_ERR(rmnet_ipa3_ctx->subsys_notify_handle);
}

static void __exit ipa3_wwan_cleanup(void)
{
	int ret;

	mutex_destroy(&rmnet_ipa3_ctx->pipe_handle_guard);
	mutex_destroy(&rmnet_ipa3_ctx->add_mux_channel_lock);
	ret = subsys_notif_unregister_notifier(
		rmnet_ipa3_ctx->subsys_notify_handle, &ipa3_ssr_notifier);
	if (ret)
		ipa_err(
		"Error subsys_notif_unregister_notifier system %s, ret=%d\n",
		SUBSYS_MODEM, ret);
	platform_driver_unregister(&rmnet_ipa_driver);
	kfree(rmnet_ipa3_ctx);
	rmnet_ipa3_ctx = NULL;
}

static void ipa3_rmnet_rx_cb(void *priv)
{
	ipa_debug_low("\n");
	napi_schedule(&(rmnet_ipa3_ctx->wwan_priv->napi));
}

static int ipa3_rmnet_poll(struct napi_struct *napi, int budget)
{
	int rcvd_pkts = 0;

	rcvd_pkts = ipa3_rx_poll(rmnet_ipa3_ctx->ipa3_to_apps_hdl,
					NAPI_WEIGHT);
	ipa_debug_low("rcvd packets: %d\n", rcvd_pkts);
	return rcvd_pkts;
}

late_initcall(ipa3_wwan_init);
module_exit(ipa3_wwan_cleanup);
MODULE_DESCRIPTION("WWAN Network Interface");
MODULE_LICENSE("GPL v2");
