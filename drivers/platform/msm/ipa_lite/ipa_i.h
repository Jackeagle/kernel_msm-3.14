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
#include "gsi/gsi.h"
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

#define IPA_IPC_LOG_PAGES 50

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

#define MAX_RESOURCE_TO_CLIENTS (IPA_CLIENT_MAX)
#define IPA_MEM_PART(x_) (ipa3_ctx->ctrl->mem_partition.x_)

#define IPA_GSI_CHANNEL_STOP_MAX_RETRY 10
#define IPA_GSI_CHANNEL_STOP_PKT_SIZE 1

#define IPA_GSI_CHANNEL_EMPTY_MAX_RETRY 15
#define IPA_GSI_CHANNEL_EMPTY_SLEEP_MIN_USEC (1000)
#define IPA_GSI_CHANNEL_EMPTY_SLEEP_MAX_USEC (2000)

#define IPA_SLEEP_CLK_RATE_KHZ (32)

#define IPA3_ACTIVE_CLIENTS_LOG_BUFFER_SIZE_LINES 120
#define IPA3_ACTIVE_CLIENTS_LOG_LINE_LEN 96
#define IPA3_ACTIVE_CLIENTS_LOG_HASHTABLE_SIZE 50
#define IPA3_ACTIVE_CLIENTS_LOG_NAME_LEN 40
#define FEATURE_ENUM_VAL(feature, opcode) ((feature << 5) | opcode)
#define IPA_HW_NUM_FEATURES 0x8
#define IPA_WAN_MSG_IPv6_ADDR_GW_LEN 4

/**
 * enum ipa_voltage_level - IPA Voltage levels
 */
enum ipa_voltage_level {
        IPA_VOLTAGE_UNSPECIFIED,
        IPA_VOLTAGE_SVS2 = IPA_VOLTAGE_UNSPECIFIED,
        IPA_VOLTAGE_SVS,
        IPA_VOLTAGE_NOMINAL,
        IPA_VOLTAGE_TURBO,
        IPA_VOLTAGE_MAX,
};

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
 * enum ipa_aggr_mode - global aggregation mode
 */
enum ipa_aggr_mode {
        IPA_MBIM_AGGR,
        IPA_QCNCM_AGGR,
};

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
 * struct  ipa_tx_data_desc - information needed
 * to send data packet to HW link: link to data descriptors
 * priv: client specific private data
 * @pyld_buffer: pointer to the data buffer that holds frame
 * @pyld_len: length of the data packet
 */
struct ipa_tx_data_desc {
        struct list_head link;
        void *priv;
        void *pyld_buffer;
        u16  pyld_len;
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

struct ipa3_client_names {
	enum ipa_client_type names[MAX_RESOURCE_TO_CLIENTS];
	int length;
};

struct ipa_smmu_cb_ctx {
	struct device *dev;
	struct dma_iommu_mapping *mapping;
	u32 va_start;
	u32 va_end;
};

/**
 * struct ipa3_hdr_offset_entry - IPA header offset entry
 * @link: entry's link in global processing context header offset entries list
 * @offset: the offset
 * @bin: bin
 */
struct ipa3_hdr_proc_ctx_offset_entry {
	struct list_head link;
	u32 offset;
	u32 bin;
};

struct ipa_gsi_ep_mem_info {
	u16 evt_ring_len;
	u64 evt_ring_base_addr;
	void *evt_ring_base_vaddr;
	u16 chan_ring_len;
	u64 chan_ring_base_addr;
	void *chan_ring_base_vaddr;
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
 * @gsi_evt_ring_hdl: EP's GSI channel event ring handle
 * @gsi_mem_info: EP's GSI channel rings info
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
	unsigned long gsi_evt_ring_hdl;
	struct ipa_gsi_ep_mem_info gsi_mem_info;
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

/**
 * ipa_request_gsi_channel_params - gsi channel related properties
 *
 * @ipa_ep_cfg:          IPA EP configuration
 * @client:              type of "client"
 * @priv:                callback cookie
 * @notify:              callback
 *           priv - callback cookie evt - type of event data - data relevant
 *           to event.  May not be valid. See event_type enum for valid
 *           cases.
 * @skip_ep_cfg:         boolean field that determines if EP should be
 *                       configured by IPA driver
 * @keep_ipa_awake:      when true, IPA will not be clock gated
 * @evt_ring_params:     parameters for the channel's event ring
 * @evt_scratch:         parameters for the channel's event ring scratch
 * @chan_params:         parameters for the channel
 * @chan_scratch:        parameters for the channel's scratch
 *
 */
struct ipa_request_gsi_channel_params {
	struct ipa_ep_cfg ipa_ep_cfg;
	enum ipa_client_type client;
	void *priv;
	ipa_notify_cb notify;
	bool skip_ep_cfg;
	bool keep_ipa_awake;
	struct gsi_evt_ring_props evt_ring_params;
	union __packed gsi_evt_scratch evt_scratch;
	struct gsi_chan_props chan_params;
	union __packed gsi_channel_scratch chan_scratch;
};

enum ipa3_sys_pipe_policy {
	IPA_POLICY_INTR_MODE,
	IPA_POLICY_NOINTR_MODE,
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
 * struct ipa3_dma_xfer_wrapper - IPADMA transfer descr wrapper
 * @phys_addr_src: physical address of the source data to copy
 * @phys_addr_dest: physical address to store the copied data
 * @len: len in bytes to copy
 * @link: linked to the wrappers list on the proper(sync/async) cons pipe
 * @xfer_done: completion object for sync_memcpy completion
 * @callback: IPADMA client provided completion callback
 * @user1: cookie1 for above callback
 *
 * This struct can wrap both sync and async memcpy transfers descriptors.
 */
struct ipa3_dma_xfer_wrapper {
	u64 phys_addr_src;
	u64 phys_addr_dest;
	u16 len;
	struct list_head link;
	struct completion xfer_done;
	void (*callback)(void *user1);
	void *user1;
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

enum ipa3_config_this_ep {
	IPA_CONFIGURE_THIS_EP,
	IPA_DO_NOT_CONFIGURE_THIS_EP,
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

struct ipa3_controller;


/**
 * union Ipa3HwFeatureInfoData_t - parameters for stats/config blob
 *
 * @offset : Location of a feature within the EventInfoData
 * @size : Size of the feature
 */
union Ipa3HwFeatureInfoData_t {
        struct IpaHwFeatureInfoParams_t {
                u32 offset:16;
                u32 size:16;
        } __packed params;
        u32 raw32b;
} __packed;

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
 * struct Ipa3HwEventInfoData_t - Structure holding the parameters for
 * statistics and config info
 *
 * @baseAddrOffset : Base Address Offset of the statistics or config
 * structure from IPA_WRAPPER_BASE
 * @Ipa3HwFeatureInfoData_t : Location and size of each feature within
 * the statistics or config structure
 *
 * @note    Information about each feature in the featureInfo[]
 * array is populated at predefined indices per the IPA_HW_FEATURES
 * enum definition
 */
struct Ipa3HwEventInfoData_t {
        u32 baseAddrOffset;
        union Ipa3HwFeatureInfoData_t featureInfo[IPA_HW_NUM_FEATURES];
} __packed;

/**
 * struct IpaHwEventLogInfoData_t - Structure holding the parameters for
 * IPA_HW_2_CPU_EVENT_LOG_INFO Event
 *
 * @featureMask : Mask indicating the features enabled in HW.
 * Refer IPA_HW_FEATURE_MASK
 * @circBuffBaseAddrOffset : Base Address Offset of the Circular Event
 * Log Buffer structure
 * @statsInfo : Statistics related information
 * @configInfo : Configuration related information
 *
 * @note    The offset location of this structure from IPA_WRAPPER_BASE
 * will be provided as Event Params for the IPA_HW_2_CPU_EVENT_LOG_INFO
 * Event
 */
struct IpaHwEventLogInfoData_t {
        u32 featureMask;
        u32 circBuffBaseAddrOffset;
        struct Ipa3HwEventInfoData_t statsInfo;
        struct Ipa3HwEventInfoData_t configInfo;

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
 * struct ipa3_uc_hdlrs - IPA uC callback functions
 * @ipa_uc_loaded_hdlr: Function handler when uC is loaded
 * @ipa_uc_event_hdlr: Event handler function
 * @ipa3_uc_response_hdlr: Response handler function
 * @ipa_uc_event_log_info_hdlr: Log event handler function
 */
struct ipa3_uc_hdlrs {
	void (*ipa_uc_loaded_hdlr)(void);

	void (*ipa_uc_event_hdlr)
		(struct IpaHwSharedMemCommonMapping_t *uc_sram_mmio);

	int (*ipa3_uc_response_hdlr)
		(struct IpaHwSharedMemCommonMapping_t *uc_sram_mmio,
		u32 *uc_status);

	void (*ipa_uc_event_log_info_hdlr)
		(struct IpaHwEventLogInfoData_t *uc_event_top_mmio);
};

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
	struct IpaHwEventLogInfoData_t *uc_event_top_mmio;
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
	struct device *pdev;
	u32 curr_ipa_clk_rate;
	bool q6_proxy_clk_vote_valid;
	u32 ipa_num_pipes;
	dma_addr_t pkt_init_imm[IPA3_MAX_NUM_PIPES];
	u32 pkt_init_imm_opcode;

	struct ipa3_uc_ctx uc_ctx;

	void *gsi_dev_hdl;
	u32 ee;
	struct wakeup_source w_lock;
	struct ipa3_wakelock_ref_cnt wakelock_ref_cnt;
	/* RMNET_IOCTL_INGRESS_FORMAT_AGG_DATA */
	bool ipa_client_apps_wan_cons_agg_gro;
	/* M-release support to know client pipes */
	struct completion init_completion_obj;
	struct completion uc_loaded_completion_obj;
	struct ipa3_smp2p_info smp2p_info;
	struct ipa_dma_task_info dma_task_info;
};

/**
 * struct ipa3_mem_partition - represents IPA RAM Map as read from DTS
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
struct ipa3_mem_partition {
	u32 ofst_start;
	u32 nat_ofst;
	u32 nat_size;
	u32 v4_flt_hash_ofst;
	u32 v4_flt_hash_size;
	u32 v4_flt_hash_size_ddr;
	u32 v4_flt_nhash_ofst;
	u32 v4_flt_nhash_size;
	u32 v4_flt_nhash_size_ddr;
	u32 v6_flt_hash_ofst;
	u32 v6_flt_hash_size;
	u32 v6_flt_hash_size_ddr;
	u32 v6_flt_nhash_ofst;
	u32 v6_flt_nhash_size;
	u32 v6_flt_nhash_size_ddr;
	u32 v4_rt_num_index;
	u32 v4_modem_rt_index_lo;
	u32 v4_modem_rt_index_hi;
	u32 v4_apps_rt_index_lo;
	u32 v4_apps_rt_index_hi;
	u32 v4_rt_hash_ofst;
	u32 v4_rt_hash_size;
	u32 v4_rt_hash_size_ddr;
	u32 v4_rt_nhash_ofst;
	u32 v4_rt_nhash_size;
	u32 v4_rt_nhash_size_ddr;
	u32 v6_rt_num_index;
	u32 v6_modem_rt_index_lo;
	u32 v6_modem_rt_index_hi;
	u32 v6_apps_rt_index_lo;
	u32 v6_apps_rt_index_hi;
	u32 v6_rt_hash_ofst;
	u32 v6_rt_hash_size;
	u32 v6_rt_hash_size_ddr;
	u32 v6_rt_nhash_ofst;
	u32 v6_rt_nhash_size;
	u32 v6_rt_nhash_size_ddr;
	u32 modem_hdr_ofst;
	u32 modem_hdr_size;
	u32 apps_hdr_ofst;
	u32 apps_hdr_size;
	u32 apps_hdr_size_ddr;
	u32 modem_hdr_proc_ctx_ofst;
	u32 modem_hdr_proc_ctx_size;
	u32 apps_hdr_proc_ctx_ofst;
	u32 apps_hdr_proc_ctx_size;
	u32 apps_hdr_proc_ctx_size_ddr;
	u32 modem_comp_decomp_ofst;
	u32 modem_comp_decomp_size;
	u32 modem_ofst;
	u32 modem_size;
	u32 apps_v4_flt_hash_ofst;
	u32 apps_v4_flt_hash_size;
	u32 apps_v4_flt_nhash_ofst;
	u32 apps_v4_flt_nhash_size;
	u32 apps_v6_flt_hash_ofst;
	u32 apps_v6_flt_hash_size;
	u32 apps_v6_flt_nhash_ofst;
	u32 apps_v6_flt_nhash_size;
	u32 uc_info_ofst;
	u32 uc_info_size;
	u32 end_ofst;
	u32 apps_v4_rt_hash_ofst;
	u32 apps_v4_rt_hash_size;
	u32 apps_v4_rt_nhash_ofst;
	u32 apps_v4_rt_nhash_size;
	u32 apps_v6_rt_hash_ofst;
	u32 apps_v6_rt_hash_size;
	u32 apps_v6_rt_nhash_ofst;
	u32 apps_v6_rt_nhash_size;
	u32 uc_event_ring_ofst;
	u32 uc_event_ring_size;
	u32 pdn_config_ofst;
	u32 pdn_config_size;
	u32 stats_quota_ofst;
	u32 stats_quota_size;
	u32 stats_tethering_ofst;
	u32 stats_tethering_size;
	u32 stats_flt_v4_ofst;
	u32 stats_flt_v4_size;
	u32 stats_flt_v6_ofst;
	u32 stats_flt_v6_size;
	u32 stats_rt_v4_ofst;
	u32 stats_rt_v4_size;
	u32 stats_rt_v6_ofst;
	u32 stats_rt_v6_size;
	u32 stats_drop_ofst;
	u32 stats_drop_size;
};

struct ipa3_controller {
	struct ipa3_mem_partition mem_partition;
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

int ipa3_cfg_ep_conn_track(u32 clnt_hdl,
	const struct ipa_ep_cfg_conn_track *ep_conn_track);

int ipa3_cfg_ep_hdr(u32 clnt_hdl, const struct ipa_ep_cfg_hdr *ipa_ep_cfg);

int ipa3_cfg_ep_hdr_ext(u32 clnt_hdl,
			const struct ipa_ep_cfg_hdr_ext *ipa_ep_cfg);

int ipa3_cfg_ep_mode(u32 clnt_hdl, const struct ipa_ep_cfg_mode *ipa_ep_cfg);

int ipa3_cfg_ep_aggr(u32 clnt_hdl, const struct ipa_ep_cfg_aggr *ipa_ep_cfg);

int ipa3_cfg_ep_deaggr(u32 clnt_hdl,
		      const struct ipa_ep_cfg_deaggr *ipa_ep_cfg);


int ipa3_cfg_ep_holb(u32 clnt_hdl, const struct ipa_ep_cfg_holb *ipa_ep_cfg);

int ipa3_cfg_ep_cfg(u32 clnt_hdl, const struct ipa_ep_cfg_cfg *ipa_ep_cfg);

int ipa3_cfg_ep_metadata_mask(u32 clnt_hdl,
		const struct ipa_ep_cfg_metadata_mask *ipa_ep_cfg);

int ipa3_cfg_ep_holb_by_client(enum ipa_client_type client,
				const struct ipa_ep_cfg_holb *ipa_ep_cfg);

int ipa3_cfg_ep_ctrl(u32 clnt_hdl, const struct ipa_ep_cfg_ctrl *ep_ctrl);

/*
 * Aggregation
 */
int ipa3_set_aggr_mode(enum ipa_aggr_mode mode);

int ipa3_set_qcncm_ndp_sig(char sig[3]);

int ipa3_set_single_ndp_per_mbim(bool enable);

/*
 * Data path
 */
int ipa3_tx_dp(enum ipa_client_type dst, struct sk_buff *skb,
		struct ipa_tx_meta *metadata);

/*
 * To transfer multiple data packets
 * While passing the data descriptor list, the anchor node
 * should be of type struct ipa_tx_data_desc not list_head
*/
int ipa3_tx_dp_mul(enum ipa_client_type dst,
			struct ipa_tx_data_desc *data_desc);

void ipa3_free_skb(struct ipa_rx_data *);

/*
 * System pipes
 */
int ipa3_setup_sys_pipe(struct ipa_sys_connect_params *sys_in, u32 *clnt_hdl);

int ipa3_teardown_sys_pipe(u32 clnt_hdl);

int ipa3_sys_setup(struct ipa_sys_connect_params *sys_in,
	unsigned long *ipa_transport_hdl,
	u32 *ipa_pipe_num, u32 *clnt_hdl, bool en_status);

int ipa3_sys_teardown(u32 clnt_hdl);

int ipa3_sys_update_gsi_hdls(u32 clnt_hdl, unsigned long gsi_ch_hdl,
	unsigned long gsi_ev_hdl);

u16 ipa3_get_smem_restr_bytes(void);
int ipa3_tear_down_uc_offload_pipes(int ipa_ep_idx_ul, int ipa_ep_idx_dl);

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

enum ipa_rm_resource_name ipa3_get_rm_resource_from_ep(int pipe_idx);

u8 ipa3_get_qmb_master_sel(enum ipa_client_type client);

/* internal functions */

bool ipa_is_modem_pipe(int pipe_idx);

int ipa3_send_one(struct ipa3_sys_context *sys, struct ipa3_desc *desc,
		bool in_atomic);
int ipa3_send(struct ipa3_sys_context *sys,
		u32 num_desc,
		struct ipa3_desc *desc,
		bool in_atomic);

int ipa3_qmi_enable_force_clear_datapath_send(
		struct ipa_enable_force_clear_datapath_req_msg_v01 *req);


int ipa3_get_ep_mapping(enum ipa_client_type client);
int ipa_get_ep_group(enum ipa_client_type client);

int ipa3_init_hw(void);
struct ipa3_rt_tbl *__ipa3_find_rt_tbl(enum ipa_ip_type ip, const char *name);
int ipa3_set_single_ndp_per_mbim(bool);
void ipa3_debugfs_init(void);

void ipa3_dump_buff_internal(void *base, dma_addr_t phy_base, u32 size);
#ifdef IPA_DEBUG
#define IPA_DUMP_BUFF(base, phy_base, size) \
	ipa3_dump_buff_internal(base, phy_base, size)
#else
#define IPA_DUMP_BUFF(base, phy_base, size)
#endif
int ipa3_init_mem_partition(struct device_node *dev_node);
int ipa3_controller_static_bind(struct ipa3_controller *controller);
int ipa3_cfg_route(struct ipahal_reg_route *route);
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
void ipa3_active_clients_log_dec(struct ipa_active_client_logging_info *id,
		bool int_ctx);
void ipa3_active_clients_log_inc(struct ipa_active_client_logging_info *id,
		bool int_ctx);
int ipa3_active_clients_log_print_buffer(char *buf, int size);
int ipa3_active_clients_log_print_table(char *buf, int size);
void ipa3_active_clients_log_clear(void);
int ipa3_interrupts_init(u32 ipa_irq, u32 ee, struct device *ipa_dev);
int __ipa3_del_hdr(u32 hdr_hdl, bool by_user);
int __ipa3_release_hdr(u32 hdr_hdl);
int __ipa3_release_hdr_proc_ctx(u32 proc_ctx_hdl);
int _ipa_read_ep_reg_v3_0(char *buf, int max_len, int pipe);
int _ipa_read_ep_reg_v4_0(char *buf, int max_len, int pipe);
void _ipa_enable_clks_v3_0(void);
void _ipa_disable_clks_v3_0(void);
void ipa3_suspend_active_aggr_wa(u32 clnt_hdl);
void ipa3_suspend_handler(enum ipa_irq_type interrupt,
				void *private_data,
				void *interrupt_data);
void wwan_cleanup(void);

void ipa3_lan_rx_cb(void *priv, enum ipa_dp_evt_type evt, unsigned long data);

int _ipa_init_sram_v3(void);
int _ipa_init_hdr_v3_0(void);
int _ipa_init_rt4_v3(void);
int _ipa_init_rt6_v3(void);
int _ipa_init_flt4_v3(void);
int _ipa_init_flt6_v3(void);

void ipa3_skb_recycle(struct sk_buff *skb);
void ipa3_install_dflt_flt_rules(u32 ipa_ep_idx);
void ipa3_delete_dflt_flt_rules(u32 ipa_ep_idx);

int ipa3_enable_data_path(u32 clnt_hdl);
int ipa3_alloc_rule_id(struct idr *rule_ids);
int ipa3_id_alloc(void *ptr);
void *ipa3_id_find(u32 id);
void ipa3_id_remove(u32 id);

int ipa3_set_required_perf_profile(enum ipa_voltage_level floor_voltage,
				  u32 bandwidth_mbps);

int ipa3_cfg_ep_status(u32 clnt_hdl,
		const struct ipahal_reg_ep_cfg_status *ipa_ep_cfg);

int ipa3_suspend_resource_no_block(enum ipa_rm_resource_name name);
int ipa3_suspend_resource_sync(enum ipa_rm_resource_name name);
bool ipa3_should_pipe_be_suspended(enum ipa_client_type client);
int ipa3_tag_aggr_force_close(int pipe_num);

void ipa3_active_clients_unlock(void);
int ipa3_tag_process(struct ipa3_desc *desc, int num_descs,
		    unsigned long timeout);

void ipa3_q6_pre_shutdown_cleanup(void);
void ipa3_q6_post_shutdown_cleanup(void);
int ipa3_init_q6_smem(void);

int ipa3_uc_interface_init(void);
int ipa3_uc_is_gsi_channel_empty(enum ipa_client_type ipa_client);
int ipa3_uc_state_check(void);
int ipa3_uc_loaded_check(void);
int ipa3_uc_send_cmd(u32 cmd, u32 opcode, u32 expected_status,
		    bool polling_mode, unsigned long timeout_jiffies);
void ipa3_uc_register_handlers(enum ipa3_hw_features feature,
			      struct ipa3_uc_hdlrs *hdlrs);
int ipa3_uc_notify_clk_state(bool enabled);
int ipa3_uc_update_hw_flags(u32 flags);
void ipa3_tag_destroy_imm(void *user1, int user2);
const struct ipa_gsi_ep_config *ipa3_get_gsi_ep_info
	(enum ipa_client_type client);

int ipa_reset_all_drop_stats(void);
u32 ipa3_get_num_pipes(void);
int ipa3_ap_suspend(struct device *dev);
int ipa3_ap_resume(struct device *dev);
int ipa3_set_rt_tuple_mask(int tbl_idx, struct ipahal_reg_hash_tuple *tuple);
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
void ipa3_recycle_wan_skb(struct sk_buff *skb);
void ipa3_reset_freeze_vote(void);
struct dentry *ipa_debugfs_get_root(void);
void ipa3_enable_dcd(void);
long ipa3_alloc_common_event_ring(void);
int ipa3_allocate_dma_task_for_gsi(void);
void ipa3_free_dma_task_for_gsi(void);
int ipa3_disable_apps_wan_cons_deaggr(uint32_t agg_size, uint32_t agg_count);
int ipa3_plat_drv_probe(struct platform_device *pdev_p);
int ipa3_add_hdr(struct ipa_ioc_add_hdr *hdrs);

int ipa3_set_flt_tuple_mask(int pipe_idx, struct ipahal_reg_hash_tuple *tuple);
int ipa3_set_rt_tuple_mask(int tbl_idx, struct ipahal_reg_hash_tuple *tuple);

#endif /* _IPA3_I_H_ */
