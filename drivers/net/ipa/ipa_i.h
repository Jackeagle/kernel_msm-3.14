// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#ifndef _IPA_I_H_
#define _IPA_I_H_

#include <linux/types.h>
#include <linux/sizes.h>
#include <linux/bug.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/device.h>
#include <linux/workqueue.h>
#include <linux/interconnect.h>
#include <linux/pm_wakeup.h>
#include <linux/skbuff.h>

#include "ipa_reg.h"
#include "gsi.h"

#define IPA_MTU				1500

#define IPA_LAN_RX_HEADER_LENGTH	0
#define IPA_DL_CHECKSUM_LENGTH		8
#define IPA_GENERIC_RX_POOL_SZ		192

#define IPA_GENERIC_AGGR_BYTE_LIMIT	(6 * SZ_1K)	/* bytes */
#define IPA_GENERIC_AGGR_TIME_LIMIT	1		/* milliseconds */
#define IPA_GENERIC_AGGR_PKT_LIMIT	0

#define IPA_MAX_STATUS_STAT_NUM		30

/* An explicitly bad endpoint identifier value */
#define IPA_EP_ID_BAD			(~(u32)0)

#define IPA_MEM_CANARY_VAL		0xdeadbeef

#define IPA_GSI_CHANNEL_STOP_MAX_RETRY	10
#define IPA_GSI_CHANNEL_STOP_PKT_SIZE	1

/**
 * DOC:
 * The IPA has a block of shared memory, divided into regions used for
 * specific purposes.  Values below define this layout (i.e., the
 * sizes and locations of all these regions).  One or two "canary"
 * values sit between some regions, as a check for erroneous writes
 * outside a region.  There are combinations of and routing tables,
 * covering IPv4 and IPv6, and for each of those, hashed and
 * non-hashed variants.  About half of routing table entries are
 * reserved for modem use.
 */

/* The maximum number of filter table entries (IPv4, IPv6; hashed and not) */
#define IPA_MEM_FLT_COUNT	14

/* The number of routing table entries (IPv4, IPv6; hashed and not) */
#define IPA_MEM_RT_COUNT			15

 /* Which routing table entries are for the modem */
#define IPA_MEM_MODEM_RT_COUNT			8
#define IPA_MEM_MODEM_RT_INDEX_MIN		0
#define IPA_MEM_MODEM_RT_INDEX_MAX \
               (IPA_MEM_MODEM_RT_INDEX_MIN + IPA_MEM_MODEM_RT_COUNT - 1)

#define IPA_MEM_V4_FLT_HASH_OFST		0x288
#define IPA_MEM_V4_FLT_NHASH_OFST		0x308
#define IPA_MEM_V6_FLT_HASH_OFST		0x388
#define IPA_MEM_V6_FLT_NHASH_OFST		0x408
#define IPA_MEM_V4_RT_HASH_OFST			0x488
#define IPA_MEM_V4_RT_NHASH_OFST		0x508
#define IPA_MEM_V6_RT_HASH_OFST			0x588
#define IPA_MEM_V6_RT_NHASH_OFST		0x608
#define IPA_MEM_MODEM_HDR_OFST			0x688
#define IPA_MEM_MODEM_HDR_SIZE			0x140
#define IPA_MEM_APPS_HDR_OFST			0x7c8
#define IPA_MEM_APPS_HDR_SIZE			0x0
#define IPA_MEM_MODEM_HDR_PROC_CTX_OFST		0x7d0
#define IPA_MEM_MODEM_HDR_PROC_CTX_SIZE		0x200
#define IPA_MEM_APPS_HDR_PROC_CTX_OFST		0x9d0
#define IPA_MEM_APPS_HDR_PROC_CTX_SIZE		0x200
#define IPA_MEM_MODEM_OFST			0xbd8
#define IPA_MEM_MODEM_SIZE			0x1024
#define IPA_MEM_END_OFST			0x2000
#define IPA_MEM_UC_EVENT_RING_OFST		0x1c00	/* v3.5 and later */

#define ipa_debug(fmt, args...) \
		dev_dbg(&ipa_ctx->pdev->dev, fmt, ## args)
#define ipa_err(fmt, args...) \
		dev_err(&ipa_ctx->pdev->dev, fmt, ## args)

#define ipa_bug() \
	do {								\
		ipa_err("an unrecoverable error has occurred\n");	\
		BUG();							\
	} while (0)

#define ipa_bug_on(condition)						\
	do {								\
		if (condition) {				\
			ipa_err("ipa_bug_on(%s) failed!\n", #condition); \
			ipa_bug();					\
		}							\
	} while (0)

#ifdef CONFIG_IPA_ASSERT

/* Communicate a condition assumed by the code.  This is intended as
 * an informative statement about something that should always be true.
 *
 * N.B.:  Conditions asserted must not incorporate code with side-effects
 *	  that are necessary for correct execution.  And an assertion
 *	  failure should not be expected to force a crash (because all
 *	  assertion code is optionally compiled out).
 */
#define ipa_assert(cond) \
	do {								\
		if (!(cond)) {				\
			ipa_err("ipa_assert(%s) failed!\n", #cond);	\
			ipa_bug();					\
		}							\
	} while (0)
#else	/* !CONFIG_IPA_ASSERT */

#define ipa_assert(expr)	((void)0)

#endif	/* !CONFIG_IPA_ASSERT */

enum ipa_ees {
	IPA_EE_AP	= 0,
	IPA_EE_Q6	= 1,
	IPA_EE_UC	= 2,
};

/**
 * enum ipa_client_type - names for the various IPA "clients"
 *
 * These are from the perspective of the clients, e.g. HSIC1_PROD
 * means HSIC client is the producer and IPA is the consumer.
 * PROD clients are always even, and CONS clients are always odd.
 */
enum ipa_client_type {
	IPA_CLIENT_WLAN1_PROD                   = 10,
	IPA_CLIENT_WLAN1_CONS                   = 11,

	IPA_CLIENT_WLAN2_CONS                   = 13,

	IPA_CLIENT_WLAN3_CONS                   = 15,

	IPA_CLIENT_USB_PROD                     = 18,
	IPA_CLIENT_USB_CONS                     = 19,

	IPA_CLIENT_USB_DPL_CONS                 = 27,

	IPA_CLIENT_APPS_LAN_PROD		= 32,
	IPA_CLIENT_APPS_LAN_CONS		= 33,

	IPA_CLIENT_APPS_WAN_PROD		= 34,
	IPA_CLIENT_APPS_WAN_CONS		= 35,

	IPA_CLIENT_APPS_CMD_PROD		= 36,

	IPA_CLIENT_Q6_LAN_PROD			= 50,
	IPA_CLIENT_Q6_LAN_CONS			= 51,

	IPA_CLIENT_Q6_WAN_PROD			= 52,
	IPA_CLIENT_Q6_WAN_CONS			= 53,

	IPA_CLIENT_Q6_CMD_PROD			= 54,

	IPA_CLIENT_TEST_PROD                    = 62,
	IPA_CLIENT_TEST_CONS                    = 63,

	IPA_CLIENT_TEST1_PROD                   = 64,
	IPA_CLIENT_TEST1_CONS                   = 65,

	IPA_CLIENT_TEST2_PROD                   = 66,
	IPA_CLIENT_TEST2_CONS                   = 67,

	IPA_CLIENT_TEST3_PROD                   = 68,
	IPA_CLIENT_TEST3_CONS                   = 69,

	IPA_CLIENT_TEST4_PROD                   = 70,
	IPA_CLIENT_TEST4_CONS                   = 71,

	IPA_CLIENT_DUMMY_CONS			= 73,

	IPA_CLIENT_MAX,
};

static inline bool ipa_producer(enum ipa_client_type client)
{
	return !((u32)client & 1);	/* Even numbers are producers */
}

static inline bool ipa_consumer(enum ipa_client_type client)
{
	return !ipa_producer(client);
}

static inline bool ipa_modem_consumer(enum ipa_client_type client)
{
	return client == IPA_CLIENT_Q6_LAN_CONS ||
		client == IPA_CLIENT_Q6_WAN_CONS;
}

static inline bool ipa_modem_producer(enum ipa_client_type client)
{
	return client == IPA_CLIENT_Q6_LAN_PROD ||
		client == IPA_CLIENT_Q6_WAN_PROD ||
		client == IPA_CLIENT_Q6_CMD_PROD;
}

static inline bool ipa_ap_consumer(enum ipa_client_type client)
{
	return client == IPA_CLIENT_APPS_LAN_CONS ||
		client == IPA_CLIENT_APPS_WAN_CONS;
}

/**
 * enum ipa_irq_type - IPA Interrupt Type
 *
 * Used to register handlers for IPA interrupts.
 */
enum ipa_irq_type {
	IPA_INVALID_IRQ = 0,
	IPA_UC_IRQ_0,
	IPA_UC_IRQ_1,
	IPA_TX_SUSPEND_IRQ,
	IPA_IRQ_MAX
};

/**
 * typedef ipa_irq_handler_t - irq handler/callback type
 * @param ipa_irq_type		- interrupt type
 * @param interrupt_data	- interrupt information data
 *
 * Callback function registered by ipa_add_interrupt_handler() to
 * handle a specific interrupt type
 */
typedef void (*ipa_irq_handler_t)(enum ipa_irq_type interrupt,
				  u32 interrupt_data);

/**
 * struct ipa_tx_suspend_irq_data - Interrupt data for IPA_TX_SUSPEND_IRQ
 * @endpoints:	Bitmask of endpoints which cause IPA_TX_SUSPEND_IRQ interrupt
 */
struct ipa_tx_suspend_irq_data {
	u32 endpoints;
};

/**
 * enum ipa_dp_evt_type - Data path event type
 */
enum ipa_dp_evt_type {
	IPA_RECEIVE,
	IPA_WRITE_DONE,
	IPA_CLIENT_START_POLL,
	IPA_CLIENT_COMP_NAPI,
};

typedef void (*ipa_notify_cb)(void *priv, enum ipa_dp_evt_type evt,
			      unsigned long data);

/**
 * struct ipa_ep_context - IPA end point context
 * @allocated:	True when the endpoint has been allocated
 * @client:	Client associated with the endpoint
 * @channel_id:	EP's GSI channel
 * @evt_ring_id: EP's GSI channel event ring
 * @priv:	Pointer supplied when client_notify is called
 *	  notified for new data avail
 * @client_notify: Function called for event notification
 * @napi_enabled: Endpoint uses NAPI
 */
struct ipa_ep_context {
	bool allocated;
	enum ipa_client_type client;
	u32 channel_id;
	u32 evt_ring_id;
	bool bytes_xfered_valid;
	u16 bytes_xfered;

	struct ipa_reg_endp_init_hdr init_hdr;
	struct ipa_reg_endp_init_hdr_ext hdr_ext;
	struct ipa_reg_endp_init_mode init_mode;
	struct ipa_reg_endp_init_aggr init_aggr;
	struct ipa_reg_endp_init_cfg init_cfg;
	struct ipa_reg_endp_init_seq init_seq;
	struct ipa_reg_endp_init_deaggr init_deaggr;
	struct ipa_reg_endp_init_hdr_metadata_mask metadata_mask;
	struct ipa_reg_endp_status status;

	void (*client_notify)(void *priv, enum ipa_dp_evt_type evt,
			      unsigned long data);
	void *priv;
	bool napi_enabled;
	struct ipa_sys_context *sys;
};

/**
 * enum ipa_desc_type - IPA decriptor type
 */
enum ipa_desc_type {
	IPA_DATA_DESC,
	IPA_DATA_DESC_SKB,
	IPA_DATA_DESC_SKB_PAGED,
	IPA_IMM_CMD_DESC,
};

/**
 * struct ipa_desc - IPA descriptor
 * @type:	Type of data in the descriptor
 * @len_opcode: Length of the payload, or opcode for immediate commands
 * @payload:	Points to descriptor payload (e.g., socket buffer)
 * @callback:	Completion callback
 * @user1:	Pointer data supplied to callback
 * @user2:	Integer data supplied with callback
 */
struct ipa_desc {
	enum ipa_desc_type type;
	u16 len_opcode;
	void *payload;
	void (*callback)(void *user1, int user2);
	void *user1;
	int user2;
};

/**
 * enum ipahal_imm_cmd:	IPA immediate commands
 *
 * All immediate commands are issued using the APPS_CMD_PROD
 * endpoint.  The numeric values here are the opcodes for IPA v3.5.1
 * hardware
 */
enum ipahal_imm_cmd {
	IPA_IMM_CMD_IP_V4_FILTER_INIT		= 3,
	IPA_IMM_CMD_IP_V6_FILTER_INIT		= 4,
	IPA_IMM_CMD_IP_V4_ROUTING_INIT		= 7,
	IPA_IMM_CMD_IP_V6_ROUTING_INIT		= 8,
	IPA_IMM_CMD_HDR_INIT_LOCAL		= 9,
	IPA_IMM_CMD_DMA_TASK_32B_ADDR		= 17,
	IPA_IMM_CMD_DMA_SHARED_MEM		= 19,
};

/**
 * struct ipa_transport_pm - Transport power management data
 * @dec_clients:	?
 * @transport_pm_mutex:	Mutex to protect the transport_pm functionality.
 */
struct ipa_transport_pm {
	atomic_t dec_clients;
	struct mutex transport_pm_mutex;	/* XXX comment this */
};

struct ipa_smp2p_info {
	struct qcom_smem_state *valid_state;
	struct qcom_smem_state *enabled_state;
	unsigned int valid_bit;
	unsigned int enabled_bit;
	unsigned int clock_query_irq;
	unsigned int post_init_irq;
	bool ipa_clk_on;
	bool res_sent;
};

struct ipa_dma_task_info {
	void *virt;
	dma_addr_t phys;
	void *payload;
};

/**
 * struct ipa_context - IPA context
 * @filter_bitmap:	End-points supporting filtering bitmap
 * @ipa_irq:		IRQ number used for IPA
 * @ipa_phys:		Physical address of IPA register memory
 * @gsi:		Pointer to GSI structure
 * @pdev:		IPA platform device structure
 * @ep:			Endpoint array
 * @dp:			Data path information
 * @smem_size:		Size of shared memory
 * @smem_offset:	Offset of the usable area in shared memory
 * @active_clients_mutex: Used when active clients count changes from/to 0
 * @active_clients_count: Active client count
 * @clock_wq:		Workqueue for removing last clock reference
 * @transport_pm:	Transport power management related information
 * @cmd_prod_ep_id:	Endpoint for APPS_CMD_PROD
 * @lan_cons_ep_id:	Endpoint for APPS_LAN_CONS
 * @memory_path:	Path for memory interconnect
 * @imem_path:		Path for internal memory interconnect
 * @config_path:	Path for configuration interconnect
 * @proxy_held:		Whether proxy clock reference is held for modem
 * @ep_count:		Number of endpoints available in hardware
 * @uc_ctx:		Microcontroller context
 * @wakeup_lock:	Lock protecting updates to wakeup_count
 * @wakeup_count:	Count of times wakelock is acquired
 * @wakeup:		Wakeup source
 * @ipa_client_apps_wan_cons_agg_gro: APPS_WAN_CONS generic receive offload
 * @smp2p_info:		Information related to SMP2P
 * @dma_task_info:	Preallocated DMA task
 */
struct ipa_context {
	struct platform_device *pdev;
	struct ipa_smp2p_info smp2p_info;
	struct clk *core_clock;
	struct icc_path *memory_path;
	struct icc_path *imem_path;
	struct icc_path *config_path;
	struct workqueue_struct *clock_wq;
	struct work_struct clock_work;
	struct mutex clock_mutex;
	atomic_t clock_count;
	phys_addr_t ipa_phys;
	void *route_virt;
	dma_addr_t route_phys;
	u32 filter_bitmap;
	u32 filter_count;	/* Number of set bits in filter_bitmap */
	void *filter_virt;
	dma_addr_t filter_phys;
	u32 ipa_irq;
	struct gsi *gsi;
	u32 cmd_prod_ep_id;
	u32 lan_cons_ep_id;

	u32 ep_count;
	u32 smem_size;
	u16 smem_offset;

	struct kmem_cache *tx_pkt_wrapper_cache;
	struct kmem_cache *rx_pkt_wrapper_cache;
	struct ipa_transport_pm transport_pm;
	struct ipa_dma_task_info dma_task_info;
	u32 wakeup_count;
	struct wakeup_source wakeup;
	spinlock_t wakeup_lock;		/* protects updates to wakeup_count */
	struct mutex post_init_mutex;

	struct ipa_ep_context *ep;
	struct ipa_uc_ctx *uc_ctx;
	struct notifier_block panic_notifier;
	bool proxy_held;
	void *wwan;
	bool post_init_complete;
	bool shutting_down;

	/* RMNET_IOCTL_INGRESS_FORMAT_AGG_DATA */
	bool ipa_client_apps_wan_cons_agg_gro;
};

extern struct ipa_context *ipa_ctx;

void *ipa_wwan_init(void);
void ipa_wwan_cleanup(void *data);

int rmnet_ipa_ap_suspend(void *data);
void rmnet_ipa_ap_resume(void *data);

int ipa_stop_gsi_channel(u32 ep_id);

void ipa_cfg_ep(u32 ep_id);

int ipa_tx_dp(enum ipa_client_type dst, struct sk_buff *skb);

bool ipa_endp_aggr_support(u32 ep_id);
enum ipa_seq_type ipa_endp_seq_type(u32 ep_id);

void ipa_endp_init_hdr_cons(struct ipa_context *ipa, u32 ep_id, u32 header_size,
			    u32 metadata_offset, u32 length_offset);
void ipa_endp_init_hdr_prod(struct ipa_context *ipa, u32 ep_id, u32 header_size,
			    u32 metadata_offset, u32 length_offset);
void ipa_endp_init_hdr_ext_cons(struct ipa_context *ipa, u32 ep_id,
				u32 pad_align, bool pad_included);
void ipa_endp_init_hdr_ext_prod(struct ipa_context *ipa, u32 ep_id,
				u32 pad_align);
void ipa_endp_init_mode_cons(struct ipa_context *ipa, u32 ep_id);
void ipa_endp_init_mode_prod(struct ipa_context *ipa, u32 ep_id,
			     enum ipa_mode mode,
			     enum ipa_client_type dst_client);
void ipa_endp_init_aggr_cons(struct ipa_context *ipa, u32 ep_id, u32 size,
			     u32 count, bool close_on_eof);
void ipa_endp_init_aggr_prod(struct ipa_context *ipa, u32 ep_id,
			     enum ipa_aggr_en aggr_en,
			     enum ipa_aggr_type aggr_type);
void ipa_endp_init_cfg_cons(struct ipa_context *ipa, u32 ep_id,
			    enum ipa_cs_offload_en offload_type);
void ipa_endp_init_cfg_prod(struct ipa_context *ipa, u32 ep_id,
			    enum ipa_cs_offload_en offload_type,
			    u32 metadata_offset);
void ipa_endp_init_seq_cons(struct ipa_context *ipa, u32 ep_id);
void ipa_endp_init_seq_prod(struct ipa_context *ipa, u32 ep_id);
void ipa_endp_init_deaggr_cons(struct ipa_context *ipa, u32 ep_id);
void ipa_endp_init_deaggr_prod(struct ipa_context *ipa, u32 ep_id);
void ipa_endp_init_hdr_metadata_mask_cons(struct ipa_context *ipa, u32 ep_id,
					  u32 mask);
void ipa_endp_init_hdr_metadata_mask_prod(struct ipa_context *ipa, u32 ep_id);
void ipa_endp_status_cons(struct ipa_context *ipa, u32 ep_id, bool enable);
void ipa_endp_status_prod(struct ipa_context *ipa, u32 ep_id, bool enable,
			  enum ipa_client_type client);
int ipa_ep_alloc(struct ipa_context *ipa, enum ipa_client_type client);
void ipa_ep_free(struct ipa_context *ipa, u32 ep_id);

void ipa_no_intr_init(u32 prod_ep_id);

int ipa_ep_setup(struct ipa_context *ipa, u32 ep_id, u32 channel_count,
		 u32 evt_ring_mult, u32 rx_buffer_size,
		 void (*client_notify)(void *priv, enum ipa_dp_evt_type type,
				       unsigned long data),
		 void *priv);

void ipa_ep_teardown(struct ipa_context *ipa, u32 ep_id);

void ipa_rx_switch_to_poll_mode(struct ipa_sys_context *sys);

void ipa_add_interrupt_handler(enum ipa_irq_type interrupt,
			       ipa_irq_handler_t handler);

void ipa_remove_interrupt_handler(enum ipa_irq_type interrupt);

u32 ipa_filter_bitmap_init(void);

bool ipa_is_modem_ep(u32 ep_id);

u32 ipa_client_ep_id(enum ipa_client_type client);
u32 ipa_client_channel_id(enum ipa_client_type client);
u32 ipa_client_tlv_count(enum ipa_client_type client);

void ipa_hardware_init(struct ipa_context *ipa);

int ipa_send_cmd_timeout(struct ipa_desc *desc, u32 timeout);
static inline int ipa_send_cmd(struct ipa_desc *desc)
{
	return ipa_send_cmd_timeout(desc, 0);
}

u32 ipa_aggr_byte_limit_buf_size(u32 byte_limit);

void ipa_cfg_default_route(struct ipa_context *ipa,
			   enum ipa_client_type client);

int ipa_interrupts_init(struct ipa_context *ipa);
void ipa_interrupts_exit(struct ipa_context *ipa);

void ipa_suspend_active_aggr_wa(u32 ep_id);
void ipa_lan_rx_cb(void *priv, enum ipa_dp_evt_type evt, unsigned long data);

int ipa_modem_smem_init(struct ipa_context *ipa);

struct ipa_uc_ctx *ipa_uc_init(phys_addr_t phys_addr);
bool ipa_uc_loaded(void);
void ipa_uc_panic_notifier(void);

int ipa_ep_init(struct ipa_context *ipa);
void ipa_ep_exit(struct ipa_context *ipa);

int ipa_ap_suspend(struct device *dev);
int ipa_ap_resume(struct device *dev);
void ipa_set_resource_groups_min_max_limits(void);
void ipa_ep_suspend_all(void);
void ipa_ep_resume_all(void);
void ipa_inc_acquire_wakelock(struct ipa_context *ipa);
void ipa_dec_release_wakelock(struct ipa_context *ipa);
int ipa_rx_poll(u32 ep_id, int budget);
void ipa_reset_freeze_vote(struct ipa_context *ipa);
void ipa_enable_dcd(void);

int ipa_gsi_dma_task_alloc(struct ipa_context *ipa);
void ipa_gsi_dma_task_free(struct ipa_context *ipa);

void ipa_set_flt_tuple_mask(u32 ep_id);
void ipa_set_rt_tuple_mask(int tbl_idx);

void ipa_gsi_irq_rx_notify_cb(void *chan_data, u16 count);
void ipa_gsi_irq_tx_notify_cb(void *xfer_data);

bool ipa_ep_polling(struct ipa_ep_context *ep);

int ipa_dp_init(struct ipa_context *ipa);
void ipa_dp_exit(struct ipa_context *ipa);

#endif /* _IPA_I_H_ */
