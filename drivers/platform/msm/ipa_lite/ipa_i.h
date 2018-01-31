/* Copyright (c) 2012-2017, The Linux Foundation. All rights reserved.
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

#ifndef _IPA3_I_H_
#define _IPA3_I_H_

#include <linux/bitops.h>
#include <linux/cdev.h>
#include <linux/export.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <asm/dma-iommu.h>
#include <linux/iommu.h>
#include <linux/platform_device.h>
#include <linux/firmware.h>
#include "ipa_common_i.h"
#include "ipahal/ipahal_reg.h"
#include "ipahal/ipahal.h"
#include "gsi.h"
#include "ipa_qmi_service.h"
#include "ipa_qmi_service_v01.h"


#define DRV_NAME "ipa"
#define IPA_COOKIE 0x57831603

#define IPA3_MAX_NUM_PIPES 31
#define IPA_SYS_DESC_FIFO_SZ 0x800
#define IPA_SYS_TX_DATA_DESC_FIFO_SZ 0x1000
#define IPA_COMMON_EVENT_RING_SIZE 0x7C00
#define IPA_LAN_RX_HEADER_LENGTH (2)
#define IPA_QMAP_HEADER_LENGTH (4)
#define IPA_DL_CHECKSUM_LENGTH (8)
#define IPA_GENERIC_RX_POOL_SZ 192
/*
 * The transport descriptor size was changed to GSI_CHAN_RE_SIZE_16B, but
 * IPA users still use sps_iovec size as FIFO element size.
 */
#define IPA_FIFO_ELEMENT_SIZE 8

#define IPA_MAX_STATUS_STAT_NUM 30

#define IPA_IPC_LOG_PAGES 100

#define IPA_MEM_CANARY_VAL 0xdeadbeef

#define IPA_STATS

#ifdef IPA_STATS
#define IPA_STATS_INC_CNT(val) (++val)
#define IPA_STATS_DEC_CNT(val) (--val)
#define IPA_STATS_EXCP_CNT(__excp, __base) do {				\
	if (__excp < 0 || __excp >= IPAHAL_PKT_STATUS_EXCEPTION_MAX)	\
		break;							\
	++__base[__excp];						\
	} while (0)
#else
#define IPA_STATS_INC_CNT(x) do { } while (0)
#define IPA_STATS_DEC_CNT(x)
#define IPA_STATS_EXCP_CNT(__excp, __base) do { } while (0)
#endif

#define IPA_HDR_BIN0 0
#define IPA_HDR_BIN1 1
#define IPA_HDR_BIN2 2
#define IPA_HDR_BIN3 3
#define IPA_HDR_BIN4 4
#define IPA_HDR_BIN_MAX 5

#define IPA_HDR_PROC_CTX_BIN0 0
#define IPA_HDR_PROC_CTX_BIN1 1
#define IPA_HDR_PROC_CTX_BIN_MAX 2

#define IPA_RX_POOL_CEIL 32
#define IPA_RX_SKB_SIZE 1792

#define IPA_A5_MUX_HDR_NAME "ipa_excp_hdr"
#define IPA_LAN_RX_HDR_NAME "ipa_lan_hdr"
#define IPA_INVALID_L4_PROTOCOL 0xFF

#define IPA_HDR_PROC_CTX_TABLE_ALIGNMENT_BYTE 8
#define IPA_HDR_PROC_CTX_TABLE_ALIGNMENT(start_ofst) \
	(((start_ofst) + IPA_HDR_PROC_CTX_TABLE_ALIGNMENT_BYTE - 1) & \
	~(IPA_HDR_PROC_CTX_TABLE_ALIGNMENT_BYTE - 1))

#define IPA_GSI_CHANNEL_STOP_MAX_RETRY 10
#define IPA_GSI_CHANNEL_STOP_PKT_SIZE 1

#define IPA_GSI_CHANNEL_EMPTY_MAX_RETRY 15

#define IPA_SLEEP_CLK_RATE_KHZ (32)

#define IPA3_ACTIVE_CLIENTS_LOG_BUFFER_SIZE_LINES 120
#define IPA3_ACTIVE_CLIENTS_LOG_LINE_LEN 96
#define IPA3_ACTIVE_CLIENTS_LOG_HASHTABLE_SIZE 50
#define IPA3_ACTIVE_CLIENTS_LOG_NAME_LEN 40
#define FEATURE_ENUM_VAL(feature, opcode) ((feature << 5) | opcode)
#define IPA_HW_NUM_FEATURES 0x8
#define IPA_WAN_MSG_IPv6_ADDR_GW_LEN 4

/**
 * struct ipa_tx_suspend_irq_data - interrupt data for IPA_TX_SUSPEND_IRQ
 * @endpoints: bitmask of endpoints which case IPA_TX_SUSPEND_IRQ interrupt
 * @dma_addr: DMA address of this Rx packet
 */
struct ipa_tx_suspend_irq_data {
        u32 endpoints;
};


typedef void (*ipa_notify_cb)(void *priv, enum ipa_dp_evt_type evt,
                       unsigned long data);

/**
 * typedef ipa_irq_handler_t - irq handler/callback type
 * @param ipa_irq_type - [in] interrupt type
 * @param private_data - [in, out] the client private data
 * @param interrupt_data - [out] interrupt information data
 *
 * callback registered by ipa_add_interrupt_handler function to
 * handle a specific interrupt type
 *
 * No return value
 */
typedef void (*ipa_irq_handler_t)(enum ipa_irq_type interrupt,
                                void *private_data,
                                void *interrupt_data);

/**
 * struct ipa_sys_connect_params - information needed to setup an IPA end-point
 * in system-BAM mode
 * @ipa_ep_cfg: IPA EP configuration
 * @client:     the type of client who "owns" the EP
 * @desc_fifo_sz: size of desc FIFO. This number is used to allocate the desc
 *              fifo for BAM. For GSI, this size is used by IPA driver as a
 *              baseline to calculate the GSI ring size in the following way:
 *              For PROD pipes, GSI ring is 4 * desc_fifo_sz.
                For PROD pipes, GSI ring is 2 * desc_fifo_sz.
 * @priv:       callback cookie
 * @notify:     callback
 *              priv - callback cookie
 *              evt - type of event
 *              data - data relevant to event.  May not be valid. See event_type
 *              enum for valid cases.
 * @skip_ep_cfg: boolean field that determines if EP should be configured
 *  by IPA driver
 * @keep_ipa_awake: when true, IPA will not be clock gated
 * @napi_enabled: when true, IPA call client callback to start polling
 */
struct ipa_sys_connect_params {
        struct ipa_ep_cfg ipa_ep_cfg;
        enum ipa_client_type client;
        u32 desc_fifo_sz;
        void *priv;
        ipa_notify_cb notify;
        bool skip_ep_cfg;
        bool keep_ipa_awake;
        bool napi_enabled;
        bool recycle_enabled;
};

/**
 * struct ipa_tx_meta - meta-data for the TX packet
 * @dma_address: dma mapped address of TX packet
 * @dma_address_valid: is above field valid?
 */
struct ipa_tx_meta {
        u8 pkt_init_dst_ep;
        bool pkt_init_dst_ep_valid;
        bool pkt_init_dst_ep_remote;
        dma_addr_t dma_address;
        bool dma_address_valid;
};

struct ipa3_active_client_htable_entry {
	struct hlist_node list;
	char id_string[IPA3_ACTIVE_CLIENTS_LOG_NAME_LEN];
	int count;
	enum ipa_active_client_log_type type;
};

struct ipa3_active_clients_log_ctx {
	spinlock_t lock;
	char *log_buffer[IPA3_ACTIVE_CLIENTS_LOG_BUFFER_SIZE_LINES];
	int log_head;
	int log_tail;
	bool log_rdy;
	struct hlist_head htable[IPA3_ACTIVE_CLIENTS_LOG_HASHTABLE_SIZE];
};

struct ipa_smmu_cb_ctx {
	struct device *dev;
	struct dma_iommu_mapping *mapping;
	dma_addr_t va_start;
	dma_addr_t va_end;
	bool s1_bypass;
};

struct ipa3_status_stats {
	struct ipahal_pkt_status status[IPA_MAX_STATUS_STAT_NUM];
	unsigned int curr;
};

/* Possible values for the ipa3_ctx->state field */
#define IPA_STATE_INITIAL	0	/* Initial state (assumed 0) */
#define IPA_STATE_STARTING	1	/* Starting up, not ready */
#define IPA_STATE_READY		2	/* Ready to use */

/**
 * struct ipa3_ep_context - IPA end point context
 * @valid: flag indicating id EP context is valid
 * @client: EP client type
 * @gsi_chan_hdl: EP's GSI channel handle
 * @gsi_chan_ring_mem: EP's GSI channel ring memory info
 * @gsi_evt_ring_hdl: EP's GSI channel event ring handle
 * @chan_scratch: EP's GSI channel scratch info
 * @cfg: EP cionfiguration
 * @dst_pipe_index: destination pipe index
 * @rt_tbl_idx: routing table index
 * @priv: user provided information which will forwarded once the user is
 *        notified for new data avail
 * @client_notify: user provided CB for EP events notification, the event is
 *                 data revived.
 * @skip_ep_cfg: boolean field that determines if EP should be configured
 *  by IPA driver
 * @keep_ipa_awake: when true, IPA will not be clock gated
 * @disconnect_in_progress: Indicates client disconnect in progress.
 * @qmi_request_sent: Indicates whether QMI request to enable clear data path
 *					request is sent or not.
 * @napi_enabled: when true, IPA call client callback to start polling
 */
struct ipa3_ep_context {
	int valid;
	enum ipa_client_type client;
	unsigned long gsi_chan_hdl;
	struct ipa_mem_buffer gsi_chan_ring_mem;
	unsigned long gsi_evt_ring_hdl;
	union __packed gsi_channel_scratch chan_scratch;
	bool bytes_xfered_valid;
	u16 bytes_xfered;
	dma_addr_t phys_base;
	struct ipa_ep_cfg cfg;
	struct ipa_ep_cfg_holb holb;
	struct ipahal_reg_ep_cfg_status status;
	u32 dst_pipe_index;
	u32 rt_tbl_idx;
	void *priv;
	void (*client_notify)(void *priv, enum ipa_dp_evt_type evt,
		       unsigned long data);
	atomic_t avail_fifo_desc;
	u32 dflt_flt4_rule_hdl;
	u32 dflt_flt6_rule_hdl;
	bool skip_ep_cfg;
	bool keep_ipa_awake;
	u32 uc_offload_state;
	bool disconnect_in_progress;
	u32 qmi_request_sent;
	bool napi_enabled;
	u32 eot_in_poll_err;

	/* sys MUST be the last element of this struct */
	struct ipa3_sys_context *sys;
};

enum ipa3_sys_pipe_policy {
	IPA_POLICY_INTR_MODE,
	IPA_POLICY_INTR_POLL_MODE,
};


#define IPA_HW_NUM_FEATURES 0x8
#define FEATURE_ENUM_VAL(feature, opcode) ((feature << 5) | opcode)

/**
 * enum ipa3_hw_features - Values that represent the features supported
 * in IPA HW
 * @IPA_HW_FEATURE_COMMON : Feature related to common operation of IPA HW
 *
 */
enum ipa3_hw_features {
        IPA_HW_FEATURE_COMMON           =       0x0,
        IPA_HW_FEATURE_MAX              =       IPA_HW_NUM_FEATURES
};

/**
 * enum ipa3_hw_2_cpu_events - Values that represent HW event to be sent to CPU.
 * @IPA_HW_2_CPU_EVENT_NO_OP : No event present
 * @IPA_HW_2_CPU_EVENT_ERROR : Event specify a system error is detected by the
 *  device
 * @IPA_HW_2_CPU_EVENT_LOG_INFO : Event providing logging specific information
 */
enum ipa_hw_2_cpu_events {
        IPA_HW_2_CPU_EVENT_NO_OP     =
                FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 0),
        IPA_HW_2_CPU_EVENT_ERROR     =
                FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 1),
        IPA_HW_2_CPU_EVENT_LOG_INFO  =
                FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 2),
};

/**
 * enum ipa3_hw_errors - Common error types.
 * @IPA_HW_ERROR_NONE : No error persists
 * @IPA_HW_INVALID_DOORBELL_ERROR : Invalid data read from doorbell
 * @IPA_HW_DMA_ERROR : Unexpected DMA error
 * @IPA_HW_FATAL_SYSTEM_ERROR : HW has crashed and requires reset.
 * @IPA_HW_INVALID_OPCODE : Invalid opcode sent
 * @IPA_HW_INVALID_PARAMS : Invalid params for the requested command
 * @IPA_HW_GSI_CH_NOT_EMPTY_FAILURE : GSI channel emptiness validation failed
 */
enum ipa_hw_errors {
        IPA_HW_ERROR_NONE              =
                FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 0),
        IPA_HW_INVALID_DOORBELL_ERROR  =
                FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 1),
        IPA_HW_DMA_ERROR               =
                FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 2),
        IPA_HW_FATAL_SYSTEM_ERROR      =
                FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 3),
        IPA_HW_INVALID_OPCODE          =
                FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 4),
        IPA_HW_INVALID_PARAMS        =
                FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 5),
        IPA_HW_CONS_DISABLE_CMD_GSI_STOP_FAILURE =
                FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 6),
        IPA_HW_PROD_DISABLE_CMD_GSI_STOP_FAILURE =
                FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 7),
        IPA_HW_GSI_CH_NOT_EMPTY_FAILURE =
                FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 8)
};


struct ipa3_repl_ctx {
	struct ipa3_rx_pkt_wrapper **cache;
	atomic_t head_idx;
	atomic_t tail_idx;
	u32 capacity;
};

/**
 * struct ipa3_sys_context - IPA GPI pipes context
 * @head_desc_list: header descriptors list
 * @len: the size of the above list
 * @spinlock: protects the list and its size
 * @ep: IPA EP context
 *
 * IPA context specific to the GPI pipes a.k.a LAN IN/OUT and WAN
 */
struct ipa3_sys_context {
	u32 len;
	u32 len_pending_xfer;
	atomic_t curr_polling_state;
	struct delayed_work switch_to_intr_work;
	enum ipa3_sys_pipe_policy policy;
	bool use_comm_evt_ring;
	int (*pyld_hdlr)(struct sk_buff *skb, struct ipa3_sys_context *sys);
	struct sk_buff * (*get_skb)(unsigned int len, gfp_t flags);
	void (*free_skb)(struct sk_buff *skb);
	void (*free_rx_wrapper)(struct ipa3_rx_pkt_wrapper *rk_pkt);
	u32 rx_buff_sz;
	u32 rx_pool_sz;
	struct sk_buff *prev_skb;
	unsigned int len_rem;
	unsigned int len_pad;
	unsigned int len_partial;
	bool drop_packet;
	struct work_struct work;
	struct delayed_work replenish_rx_work;
	struct work_struct repl_work;
	void (*repl_hdlr)(struct ipa3_sys_context *sys);
	struct ipa3_repl_ctx repl;

	/* ordering is important - mutable fields go above */
	struct ipa3_ep_context *ep;
	struct list_head head_desc_list;
	struct list_head rcycl_list;
	spinlock_t spinlock;
	struct hrtimer db_timer;
	struct workqueue_struct *wq;
	struct workqueue_struct *repl_wq;
	struct ipa3_status_stats *status_stat;
	/* ordering is important - other immutable fields go below */
};

/**
 * enum ipa3_desc_type - IPA decriptors type
 *
 * IPA decriptors type, IPA supports DD and ICD but no CD
 */
enum ipa3_desc_type {
	IPA_DATA_DESC,
	IPA_DATA_DESC_SKB,
	IPA_DATA_DESC_SKB_PAGED,
	IPA_IMM_CMD_DESC,
};

/**
 * struct ipa3_tx_pkt_wrapper - IPA Tx packet wrapper
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
 * @bounce: va of bounce buffer
 * @unmap_dma: in case this is true, the buffer will not be dma unmapped
 *
 * This struct can wrap both data packet and immediate command packet.
 */
struct ipa3_tx_pkt_wrapper {
	enum ipa3_desc_type type;
	struct ipa_mem_buffer mem;
	struct work_struct work;
	struct list_head link;
	void (*callback)(void *user1, int user2);
	void *user1;
	int user2;
	struct ipa3_sys_context *sys;
	u32 cnt;
	void *bounce;
	bool no_unmap_dma;
};

/**
 * struct ipa3_desc - IPA descriptor
 * @type: skb or immediate command or plain old data
 * @pyld: points to skb
 * @frag: points to paged fragment
 * or kmalloc'ed immediate command parameters/plain old data
 * @dma_address: dma mapped address of pyld
 * @dma_address_valid: valid field for dma_address
 * @is_tag_status: flag for IP_PACKET_TAG_STATUS imd cmd
 * @len: length of the pyld
 * @opcode: for immediate commands
 * @callback: IPA client provided completion callback
 * @user1: cookie1 for above callback
 * @user2: cookie2 for above callback
 * @xfer_done: completion object for sync completion
 * @skip_db_ring: specifies whether GSI doorbell should not be rang
 */
struct ipa3_desc {
	enum ipa3_desc_type type;
	void *pyld;
	skb_frag_t *frag;
	dma_addr_t dma_address;
	bool dma_address_valid;
	bool is_tag_status;
	u16 len;
	u16 opcode;
	void (*callback)(void *user1, int user2);
	void *user1;
	int user2;
	struct completion xfer_done;
	bool skip_db_ring;
};

/*
 * Helper function to fill in some IPA descriptor fields for an
 * immediate command using an immediate command payload returned by
 * ipahal_construct_imm_cmd().
 */
static inline void
ipa_desc_fill_imm_cmd(struct ipa3_desc *desc, struct ipahal_imm_cmd_pyld *pyld)
{
	desc->type = IPA_IMM_CMD_DESC;
	desc->pyld = ipahal_imm_cmd_pyld_data(pyld);
	desc->len = pyld->len;
	desc->opcode = pyld->opcode;
}

/**
 * struct  ipa_rx_data - information needed
 * to send to wlan driver on receiving data from ipa hw
 * @skb: skb
 * @dma_addr: DMA address of this Rx packet
 */
struct ipa_rx_data {
        struct sk_buff *skb;
        dma_addr_t dma_addr;
};

/**
 * struct ipa3_rx_pkt_wrapper - IPA Rx packet wrapper
 * @skb: skb
 * @dma_address: DMA address of this Rx packet
 * @link: linked to the Rx packets on that pipe
 * @len: how many bytes are copied into skb's flat buffer
 */
struct ipa3_rx_pkt_wrapper {
	struct list_head link;
	struct ipa_rx_data data;
	u32 len;
	struct work_struct work;
	struct ipa3_sys_context *sys;
};

struct ipa3_stats {
	u32 tx_sw_pkts;
	u32 tx_hw_pkts;
	u32 rx_pkts;
	u32 rx_excp_pkts[IPAHAL_PKT_STATUS_EXCEPTION_MAX];
	u32 rx_repl_repost;
	u32 tx_pkts_compl;
	u32 rx_q_len;
	u32 stat_compl;
	u32 aggr_close;
	u32 wan_aggr_close;
	u32 wan_rx_empty;
	u32 wan_repl_rx_empty;
	u32 lan_rx_empty;
	u32 lan_repl_rx_empty;
	u32 flow_enable;
	u32 flow_disable;
	u32 tx_non_linear;
};

struct ipa3_active_clients {
	struct mutex mutex;
	atomic_t cnt;
};

struct ipa3_wakelock_ref_cnt {
	spinlock_t spinlock;
	int cnt;
};

struct ipa3_tag_completion {
	struct completion comp;
	atomic_t cnt;
};

/**
 * enum ipa3_mem_partition - IPA RAM Map is defined as an array of
 * 32-bit values read from DTS whose order is defined by this type.
 * Order and type of members should not be changed without a suitable change
 * to DTS file or the code that reads it.
 *
 * IPA SRAM memory layout:
 * +-------------------------+
 * |    UC MEM               |
 * +-------------------------+
 * |    UC INFO              |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * | V4 FLT HDR HASHABLE     |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * | V4 FLT HDR NON-HASHABLE |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * | V6 FLT HDR HASHABLE     |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * | V6 FLT HDR NON-HASHABLE |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * | V4 RT HDR HASHABLE      |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * | V4 RT HDR NON-HASHABLE  |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * | V6 RT HDR HASHABLE      |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * | V6 RT HDR NON-HASHABLE  |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |  MODEM HDR              |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * | MODEM PROC CTX          |
 * +-------------------------+
 * | APPS PROC CTX           |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * | PDN CONFIG              |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * | QUOTA STATS             |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * | TETH STATS              |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * | V4 FLT STATS            |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * | V6 FLT STATS            |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * | V4 RT STATS             |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * | V6 RT STATS             |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * | DROP STATS              |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |  MODEM MEM              |
 * +-------------------------+
 * |    CANARY               |
 * +-------------------------+
 * |  UC EVENT RING          | From IPA 3.5
 * +-------------------------+
 */
enum ipa3_mem_partition {
	OFST_START,
	NAT_OFST,
	NAT_SIZE,
	V4_FLT_HASH_OFST,
	V4_FLT_HASH_SIZE,
	V4_FLT_HASH_SIZE_DDR,
	V4_FLT_NHASH_OFST,
	V4_FLT_NHASH_SIZE,
	V4_FLT_NHASH_SIZE_DDR,
	V6_FLT_HASH_OFST,
	V6_FLT_HASH_SIZE,
	V6_FLT_HASH_SIZE_DDR,
	V6_FLT_NHASH_OFST,
	V6_FLT_NHASH_SIZE,
	V6_FLT_NHASH_SIZE_DDR,
	V4_RT_NUM_INDEX,
	V4_MODEM_RT_INDEX_LO,
	V4_MODEM_RT_INDEX_HI,
	V4_APPS_RT_INDEX_LO,
	V4_APPS_RT_INDEX_HI,
	V4_RT_HASH_OFST,
	V4_RT_HASH_SIZE,
	V4_RT_HASH_SIZE_DDR,
	V4_RT_NHASH_OFST,
	V4_RT_NHASH_SIZE,
	V4_RT_NHASH_SIZE_DDR,
	V6_RT_NUM_INDEX,
	V6_MODEM_RT_INDEX_LO,
	V6_MODEM_RT_INDEX_HI,
	V6_APPS_RT_INDEX_LO,
	V6_APPS_RT_INDEX_HI,
	V6_RT_HASH_OFST,
	V6_RT_HASH_SIZE,
	V6_RT_HASH_SIZE_DDR,
	V6_RT_NHASH_OFST,
	V6_RT_NHASH_SIZE,
	V6_RT_NHASH_SIZE_DDR,
	MODEM_HDR_OFST,
	MODEM_HDR_SIZE,
	APPS_HDR_OFST,
	APPS_HDR_SIZE,
	APPS_HDR_SIZE_DDR,
	MODEM_HDR_PROC_CTX_OFST,
	MODEM_HDR_PROC_CTX_SIZE,
	APPS_HDR_PROC_CTX_OFST,
	APPS_HDR_PROC_CTX_SIZE,
	APPS_HDR_PROC_CTX_SIZE_DDR,
	MODEM_COMP_DECOMP_OFST,
	MODEM_COMP_DECOMP_SIZE,
	MODEM_OFST,
	MODEM_SIZE,
	APPS_V4_FLT_HASH_OFST,
	APPS_V4_FLT_HASH_SIZE,
	APPS_V4_FLT_NHASH_OFST,
	APPS_V4_FLT_NHASH_SIZE,
	APPS_V6_FLT_HASH_OFST,
	APPS_V6_FLT_HASH_SIZE,
	APPS_V6_FLT_NHASH_OFST,
	APPS_V6_FLT_NHASH_SIZE,
	UC_INFO_OFST,
	UC_INFO_SIZE,
	END_OFST,
	APPS_V4_RT_HASH_OFST,
	APPS_V4_RT_HASH_SIZE,
	APPS_V4_RT_NHASH_OFST,
	APPS_V4_RT_NHASH_SIZE,
	APPS_V6_RT_HASH_OFST,
	APPS_V6_RT_HASH_SIZE,
	APPS_V6_RT_NHASH_OFST,
	APPS_V6_RT_NHASH_SIZE,
	UC_EVENT_RING_OFST,
	UC_EVENT_RING_SIZE,
	PDN_CONFIG_OFST,
	PDN_CONFIG_SIZE,
	STATS_QUOTA_OFST,
	STATS_QUOTA_SIZE,
	STATS_TETHERING_OFST,
	STATS_TETHERING_SIZE,
	STATS_FLT_V4_OFST,
	STATS_FLT_V4_SIZE,
	STATS_FLT_V6_OFST,
	STATS_FLT_V6_SIZE,
	STATS_RT_V4_OFST,
	STATS_RT_V4_SIZE,
	STATS_RT_V6_OFST,
	STATS_RT_V6_SIZE,
	STATS_DROP_OFST,
	STATS_DROP_SIZE,
	IPA_MEM_MAX,
};

struct ipa3_controller {
	u32 mem_partition[IPA_MEM_MAX];
	u32 ipa_clk_rate_turbo;
	u32 ipa_clk_rate_nominal;
	u32 ipa_clk_rate_svs;
	u32 clock_scaling_bw_threshold_turbo;
	u32 clock_scaling_bw_threshold_nominal;
	u32 ipa_reg_base_ofst;
	u32 max_holb_tmr_val;
	void (*ipa_sram_read_settings)(void);
	int (*ipa_init_sram)(void);
	int (*ipa_init_hdr)(void);
	int (*ipa_init_rt4)(void);
	int (*ipa_init_rt6)(void);
	int (*ipa_init_flt4)(void);
	int (*ipa_init_flt6)(void);
	int (*ipa3_read_ep_reg)(char *buff, int max_len, int pipe);
	int (*ipa3_commit_flt)(enum ipa_ip_type ip);
        int (*ipa3_commit_rt)(enum ipa_ip_type ip);
        int (*ipa3_commit_hdr)(void);
	void (*ipa3_enable_clks)(void);
	void (*ipa3_disable_clks)(void);
	struct msm_bus_scale_pdata *msm_bus_data_ptr;
};

/**
 * union IpaHwErrorEventData_t - HW->CPU Common Events
 * @errorType : Entered when a system error is detected by the HW. Type of
 * error is specified by IPA_HW_ERRORS
 * @reserved : Reserved
 */
union IpaHwErrorEventData_t {
        struct IpaHwErrorEventParams_t {
                u32 errorType:8;
                u32 reserved:24;
        } __packed params;
        u32 raw32b;
} __packed;

/**
 * struct IpaHwSharedMemCommonMapping_t - Structure referring to the common
 * section in 128B shared memory located in offset zero of SW Partition in IPA
 * SRAM.
 * @cmdOp : CPU->HW command opcode. See IPA_CPU_2_HW_COMMANDS
 * @cmdParams : CPU->HW command parameter lower 32bit.
 * @cmdParams_hi : CPU->HW command parameter higher 32bit.
 * of parameters (immediate parameters) and point on structure in system memory
 * (in such case the address must be accessible for HW)
 * @responseOp : HW->CPU response opcode. See IPA_HW_2_CPU_RESPONSES
 * @responseParams : HW->CPU response parameter. The parameter filed can hold 32
 * bits of parameters (immediate parameters) and point on structure in system
 * memory
 * @eventOp : HW->CPU event opcode. See IPA_HW_2_CPU_EVENTS
 * @eventParams : HW->CPU event parameter. The parameter filed can hold 32
 *              bits of parameters (immediate parameters) and point on
 *              structure in system memory
 * @firstErrorAddress : Contains the address of first error-source on SNOC
 * @hwState : State of HW. The state carries information regarding the
 *                              error type.
 * @warningCounter : The warnings counter. The counter carries information
 *                                              regarding non fatal errors in HW
 * @interfaceVersionCommon : The Common interface version as reported by HW
 *
 * The shared memory is used for communication between IPA HW and CPU.
 */
struct IpaHwSharedMemCommonMapping_t {
        u8  cmdOp;
        u8  reserved_01;
        u16 reserved_03_02;
        u32 cmdParams;
        u32 cmdParams_hi;
        u8  responseOp;
        u8  reserved_0D;
        u16 reserved_0F_0E;
        u32 responseParams;
        u8  eventOp;
        u8  reserved_15;
        u16 reserved_17_16;
        u32 eventParams;
        u32 firstErrorAddress;
        u8  hwState;
        u8  warningCounter;
        u16 reserved_23_22;
        u16 interfaceVersionCommon;
        u16 reserved_27_26;
} __packed;

/**
 * struct ipa3_uc_ctx - IPA uC context
 * @uc_inited: Indicates if uC interface has been initialized
 * @uc_loaded: Indicates if uC has loaded
 * @uc_failed: Indicates if uC has failed / returned an error
 * @uc_lock: uC interface lock to allow only one uC interaction at a time
 * @uc_completation: Completion mechanism to wait for uC commands
 * @uc_sram_mmio: Pointer to uC mapped memory
 * @pending_cmd: The last command sent waiting to be ACKed
 * @uc_status: The last status provided by the uC
 * @uc_error_type: error type from uC error event
 * @uc_error_timestamp: tag timer sampled after uC crashed
 */
struct ipa3_uc_ctx {
	bool uc_inited;
	bool uc_loaded;
	bool uc_failed;
	struct mutex uc_lock;
	struct completion uc_completion;
	struct IpaHwSharedMemCommonMapping_t *uc_sram_mmio;
	u32 uc_event_top_ofst;
	u32 pending_cmd;
	u32 uc_status;
	u32 uc_error_type;
	u32 uc_error_timestamp;
	phys_addr_t rdy_ring_base_pa;
	phys_addr_t rdy_ring_rp_pa;
	u32 rdy_ring_size;
	phys_addr_t rdy_comp_ring_base_pa;
	phys_addr_t rdy_comp_ring_wp_pa;
	u32 rdy_comp_ring_size;
	u32 *rdy_ring_rp_va;
	u32 *rdy_comp_ring_wp_va;
};

/**
 * struct ipa3_transport_pm - transport power management related members
 * @transport_pm_mutex: Mutex to protect the transport_pm functionality.
 */
struct ipa3_transport_pm {
	atomic_t dec_clients;
	atomic_t eot_activity;
	struct mutex transport_pm_mutex;
};

struct ipa3_smp2p_info {
	u32 out_base_id;
	u32 in_base_id;
	bool ipa_clk_on;
	bool res_sent;
};

struct ipa_dma_task_info {
	struct ipa_mem_buffer mem;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
};

/**
 * struct ipa3_context - IPA context
 * @class: pointer to the struct class
 * @dev_num: device number
 * @dev: the dev_t of the device
 * @cdev: cdev of the device
 * @ep: list of all end points
  power-save
 * @ep_flt_bitmap: End-points supporting filtering bitmap
 * @ep_flt_num: End-points supporting filtering number
 * @flt_tbl: list of all IPA filter tables
 * @mode: IPA operating mode
 * @mmio: iomem
 * @ipa_wrapper_base: IPA wrapper base address
 * @rt_tbl_set: list of routing tables each of which is a list of rules
 * @reap_rt_tbl_set: list of sys mem routing tables waiting to be reaped
 * @tx_pkt_wrapper_cache: Tx packets cache
 * @rx_pkt_wrapper_cache: Rx packets cache
 * @lock: this does NOT protect the linked lists within ipa3_sys_context
 * @smem_sz: shared memory size available for SW use starting
 *  from non-restricted bytes
 * @smem_restricted_bytes: the bytes that SW should not use in the shared mem
 * @nat_mem: NAT memory
 * @hdr_mem: header memory
 * @hdr_proc_ctx_mem: processing context memory
 * @power_mgmt_wq: workqueue for power management
 * @transport_power_mgmt_wq: workqueue transport related power management
 * @tag_process_before_gating: indicates whether to start tag process before
 *  gating IPA clocks
 * @transport_pm: transport power management related information
 * @ipa3_active_clients: structure for reference counting connected IPA clients
 * @logbuf: ipc log buffer for high priority messages
 * @logbuf_low: ipc log buffer for low priority messages
 * @ipa_bus_hdl: msm driver handle for the data path bus
 * @ctrl: holds the core specific operations based on
 *  core version (vtable like)
 * @pkt_init_imm_opcode: opcode for IP_PACKET_INIT imm cmd
 * @curr_ipa_clk_rate: IPA current clock rate
 * @wcstats: wlan common buffer stats
 * @uc_ctx: uC interface context
 * @uc_wdi_ctx: WDI specific fields for uC interface
 * @ipa_num_pipes: The number of pipes used by IPA HW
 * @ipa_client_apps_wan_cons_agg_gro: RMNET_IOCTL_INGRESS_FORMAT_AGG_DATA
 * @w_lock: Indicates the wakeup source.
 * @wakelock_ref_cnt: Indicates the number of times wakelock is acquired
 * @init_completion_obj: Completion object to be used in case IPA driver hasn't
 *  finished initializing. Example of use - IOCTLs to /dev/ipa
 * IPA context - holds all relevant info about IPA driver and its state
 */
struct ipa3_context {
	struct platform_device *ipa3_pdev;
	struct gsi_ctx *gsi_ctx;

	struct ipa_smmu_cb_ctx ap_smmu_cb;
	struct ipa_smmu_cb_ctx uc_smmu_cb;

	struct class *class;
	dev_t dev_num;
	atomic_t state;
	struct device *dev;
	struct cdev cdev;

	struct ipa3_ep_context ep[IPA3_MAX_NUM_PIPES];
	u32 ep_flt_bitmap;
	u32 ep_flt_num;
	void __iomem *mmio;
	u32 ipa_wrapper_base;
	u32 ipa_wrapper_size;
	struct kmem_cache *tx_pkt_wrapper_cache;
	struct kmem_cache *rx_pkt_wrapper_cache;
	struct mutex lock;
	u16 smem_sz;
	u16 smem_restricted_bytes;
	u16 smem_reqd_sz;
	struct ipa3_active_clients ipa3_active_clients;
	struct ipa3_active_clients_log_ctx ipa3_active_clients_logging;
	char *active_clients_table_buf;
	struct workqueue_struct *power_mgmt_wq;
	struct workqueue_struct *transport_power_mgmt_wq;
	bool tag_process_before_gating;
	struct ipa3_transport_pm transport_pm;
	unsigned long gsi_evt_comm_hdl;
	u32 gsi_evt_comm_ring_rem;
	u32 clnt_hdl_cmd;
	u32 clnt_hdl_data_in;
	u32 clnt_hdl_data_out;
	/* featurize if memory footprint becomes a concern */
	struct ipa3_stats stats;
	void *logbuf;
	void *logbuf_low;
	u32 ipa_bus_hdl;
	struct ipa3_controller *ctrl;
	u32 curr_ipa_clk_rate;
	bool q6_proxy_clk_vote_valid;
	u32 ipa_num_pipes;
	dma_addr_t pkt_init_imm[IPA3_MAX_NUM_PIPES];
	u32 pkt_init_imm_opcode;
	struct ipa_mem_buffer pkt_init_mem;

	struct ipa3_uc_ctx uc_ctx;

	u32 ee;
	struct wakeup_source w_lock;
	struct ipa3_wakelock_ref_cnt wakelock_ref_cnt;
	/* RMNET_IOCTL_INGRESS_FORMAT_AGG_DATA */
	bool ipa_client_apps_wan_cons_agg_gro;
	/* M-release support to know client pipes */
	struct completion init_completion_obj;
	struct ipa3_smp2p_info smp2p_info;
	struct ipa_dma_task_info dma_task_info;
};

extern struct ipa3_context *ipa3_ctx;

struct ipa_req_chan_out_params {
	u32 clnt_hdl;
	u32 db_reg_phs_addr_lsb;
	u32 db_reg_phs_addr_msb;
};

/* public APIs */
/* Generic GSI channels functions */

int ipa3_stop_gsi_channel(u32 clnt_hdl);

int ipa3_reset_gsi_channel(u32 clnt_hdl);

/*
 * Configuration
 */
int ipa3_cfg_ep(u32 clnt_hdl, const struct ipa_ep_cfg *ipa_ep_cfg);

int ipa3_cfg_ep_holb(u32 clnt_hdl, const struct ipa_ep_cfg_holb *ipa_ep_cfg);

int ipa3_cfg_ep_ctrl(u32 clnt_hdl, const struct ipa_ep_cfg_ctrl *ep_ctrl);

/*
 * Data path
 */
int ipa3_tx_dp(enum ipa_client_type dst, struct sk_buff *skb,
		struct ipa_tx_meta *metadata);

/*
 * System pipes
 */
int ipa3_setup_sys_pipe(struct ipa_sys_connect_params *sys_in, u32 *clnt_hdl);

int ipa3_teardown_sys_pipe(u32 clnt_hdl);

u16 ipa3_get_smem_restr_bytes(void);

/*
 * interrupts
 */
int ipa3_add_interrupt_handler(enum ipa_irq_type interrupt,
		ipa_irq_handler_t handler,
		bool deferred_flag,
		void *private_data);

int ipa3_remove_interrupt_handler(enum ipa_irq_type interrupt);

/*
 * Miscellaneous
 */
void ipa3_proxy_clk_vote(void);
void ipa3_proxy_clk_unvote(void);

enum ipa_client_type ipa3_get_client_mapping(int pipe_idx);

void ipa_init_ep_flt_bitmap(void);

bool ipa_is_ep_support_flt(int pipe_idx);

u8 ipa3_get_qmb_master_sel(enum ipa_client_type client);

/* internal functions */

bool ipa_is_modem_pipe(int pipe_idx);

int ipa3_send_one(struct ipa3_sys_context *sys, struct ipa3_desc *desc,
		bool in_atomic);
int ipa3_send(struct ipa3_sys_context *sys,
		u32 num_desc,
		struct ipa3_desc *desc,
		bool in_atomic);

int ipa3_get_ep_mapping(enum ipa_client_type client);
struct ipa3_ep_context *ipa3_get_ep_context(enum ipa_client_type client);
int ipa_get_ep_group(enum ipa_client_type client);

int ipa3_init_hw(void);
void ipa3_debugfs_init(void);

void ipa3_dump_buff_internal(void *base, dma_addr_t phy_base, u32 size);
#ifdef IPA_DEBUG
#define IPA_DUMP_BUFF(base, phy_base, size) \
	ipa3_dump_buff_internal(base, phy_base, size)
#else
#define IPA_DUMP_BUFF(base, phy_base, size)
#endif
int ipa3_init_mem_partition(struct device_node *dev_node);
u32 ipa3_mem(enum ipa3_mem_partition index);

struct ipa3_controller *ipa3_controller_init(void);
int ipa3_send_cmd_timeout(u16 num_desc, struct ipa3_desc *descr, u32 timeout);
int ipa3_send_cmd(u16 num_desc, struct ipa3_desc *descr);

int ipa3_straddle_boundary(u32 start, u32 end, u32 boundary);
void ipa3_enable_clks(void);
void ipa3_disable_clks(void);
void ipa3_inc_client_enable_clks(struct ipa_active_client_logging_info *id);
int ipa3_inc_client_enable_clks_no_block(struct ipa_active_client_logging_info
		*id);
void ipa3_dec_client_disable_clks(struct ipa_active_client_logging_info *id);
void ipa3_dec_client_disable_clks_no_block(
	struct ipa_active_client_logging_info *id);
int ipa3_active_clients_log_print_buffer(char *buf, int size);
int ipa3_active_clients_log_print_table(char *buf, int size);
void ipa3_active_clients_log_clear(void);
int ipa3_interrupts_init(u32 ipa_irq, u32 ee, struct device *ipa_dev);

int _ipa_read_ep_reg_v3_0(char *buf, int max_len, int pipe);
int _ipa_read_ep_reg_v4_0(char *buf, int max_len, int pipe);
void _ipa_enable_clks_v3_0(void);
void _ipa_disable_clks_v3_0(void);
void ipa3_suspend_active_aggr_wa(u32 clnt_hdl);
void ipa3_suspend_handler(enum ipa_irq_type interrupt,
				void *private_data,
				void *interrupt_data);
void ipa3_lan_rx_cb(void *priv, enum ipa_dp_evt_type evt, unsigned long data);

int _ipa_init_sram_v3(void);
int _ipa_init_hdr_v3_0(void);
int _ipa_init_rt4_v3(void);
int _ipa_init_rt6_v3(void);
int _ipa_init_flt4_v3(void);
int _ipa_init_flt6_v3(void);

void ipa3_skb_recycle(struct sk_buff *skb);
int ipa3_enable_data_path(u32 clnt_hdl);

int ipa3_cfg_ep_status(u32 clnt_hdl,
		const struct ipahal_reg_ep_cfg_status *ipa_ep_cfg);

bool ipa3_should_pipe_be_suspended(enum ipa_client_type client);
int ipa3_tag_aggr_force_close(int pipe_num);

int ipa3_tag_process(struct ipa3_desc *desc, int num_descs,
		    unsigned long timeout);

void ipa3_q6_pre_shutdown_cleanup(void);
void ipa3_q6_post_shutdown_cleanup(void);
int ipa3_init_q6_smem(void);

int ipa3_uc_interface_init(void);
int ipa3_uc_is_gsi_channel_empty(enum ipa_client_type ipa_client);
int ipa3_uc_loaded_check(void);
void ipa3_tag_destroy_imm(void *user1, int user2);
const struct ipa_gsi_ep_config *ipa3_get_gsi_ep_info
	(enum ipa_client_type client);

u32 ipa3_get_num_pipes(void);
int ipa3_ap_suspend(struct device *dev);
int ipa3_ap_resume(struct device *dev);
void ipa3_set_resorce_groups_min_max_limits(void);
void ipa3_suspend_apps_pipes(bool suspend);
int ipa3_inject_dma_task_for_gsi(void);
int ipa3_uc_panic_notifier(struct notifier_block *this,
	unsigned long event, void *ptr);
void ipa3_inc_acquire_wakelock(void);
void ipa3_dec_release_wakelock(void);
int ipa3_load_fws(const struct firmware *firmware, phys_addr_t gsi_mem_base);
const char *ipa_hw_error_str(enum ipa_hw_errors err_type);
int ipa3_rx_poll(u32 clnt_hdl, int budget);
void ipa3_reset_freeze_vote(void);
void ipa3_enable_dcd(void);
int ipa3_allocate_dma_task_for_gsi(void);
void ipa3_free_dma_task_for_gsi(void);
int ipa3_disable_apps_wan_cons_deaggr(uint32_t agg_size, uint32_t agg_count);
int ipa3_plat_drv_probe(struct platform_device *pdev_p);

void ipa3_set_flt_tuple_mask(int pipe_idx, struct ipahal_reg_hash_tuple *tuple);
void ipa3_set_rt_tuple_mask(int tbl_idx, struct ipahal_reg_hash_tuple *tuple);

#endif /* _IPA3_I_H_ */
