// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#ifndef _IPA_I_H_
#define _IPA_I_H_

#include <linux/bitops.h>
#include <linux/cdev.h>
#include <linux/export.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/iommu.h>
#include <linux/platform_device.h>
#include <linux/firmware.h>

#include "ipa_dma.h"
#include "ipa_common_i.h"
#include "ipa_reg.h"
#include "ipahal.h"
#include "gsi.h"

#define DRV_NAME		"ipa"
#define IPA_COOKIE		0x57831603

#define IPA_MTU			1500

#define IPA_MAX_NUM_PIPES		31
#define IPA_LAN_RX_HEADER_LENGTH	2
#define IPA_DL_CHECKSUM_LENGTH		8
#define IPA_GENERIC_RX_POOL_SZ		192

#define IPA_MAX_STATUS_STAT_NUM		30

/* An explicitly bad client handle value */
#define IPA_CLNT_HDL_BAD		(~(u32)0)

#define IPA_MEM_CANARY_VAL		0xdeadbeef

#define IPA_GSI_CHANNEL_STOP_MAX_RETRY	10
#define IPA_GSI_CHANNEL_STOP_PKT_SIZE	1

/** The IPA has a block of shared memory, divided into regions used for
 * specific purposes.  The following values define this layout (i.e.,
 * the sizes and locations of all these regions).  One or two "canary"
 * values sit between some regions, as a check for erroneous writes
 * outside a region.
 *
 * IPA SRAM memory layout:
 * +-------------------------+
 * |	UC MEM		     |
 * +-------------------------+
 * |	UC INFO		     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * | V4 FLT HDR HASHABLE     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * | V4 FLT HDR NON-HASHABLE |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * | V6 FLT HDR HASHABLE     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * | V6 FLT HDR NON-HASHABLE |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * | V4 RT HDR HASHABLE	     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * | V4 RT HDR NON-HASHABLE  |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * | V6 RT HDR HASHABLE	     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * | V6 RT HDR NON-HASHABLE  |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * |  MODEM HDR		     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * | MODEM PROC CTX	     |
 * +-------------------------+
 * | APPS PROC CTX	     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * |  MODEM MEM		     |
 * +-------------------------+
 * |	CANARY		     |
 * +-------------------------+
 * |  UC EVENT RING	     | From IPA 3.5
 * +-------------------------+
 */
#define IPA_MEM_V4_FLT_HASH_OFST		0x288
#define IPA_MEM_V4_FLT_HASH_SIZE		0x78
#define IPA_MEM_V4_FLT_NHASH_OFST		0x308
#define IPA_MEM_V4_FLT_NHASH_SIZE		0x78
#define IPA_MEM_V6_FLT_HASH_OFST		0x388
#define IPA_MEM_V6_FLT_HASH_SIZE		0x78
#define IPA_MEM_V6_FLT_NHASH_OFST		0x408
#define IPA_MEM_V6_FLT_NHASH_SIZE		0x78
#define IPA_MEM_V4_RT_NUM_INDEX			0xf
#define IPA_MEM_V4_MODEM_RT_INDEX_LO		0x0
#define IPA_MEM_V4_MODEM_RT_INDEX_HI		0x7
#define IPA_MEM_V4_RT_HASH_OFST			0x488
#define IPA_MEM_V4_RT_HASH_SIZE			0x78
#define IPA_MEM_V4_RT_NHASH_OFST		0x508
#define IPA_MEM_V4_RT_NHASH_SIZE		0x78
#define IPA_MEM_V6_RT_NUM_INDEX			0xf
#define IPA_MEM_V6_MODEM_RT_INDEX_LO		0x0
#define IPA_MEM_V6_MODEM_RT_INDEX_HI		0x7
#define IPA_MEM_V6_RT_HASH_OFST			0x588
#define IPA_MEM_V6_RT_HASH_SIZE			0x78
#define IPA_MEM_V6_RT_NHASH_OFST		0x608
#define IPA_MEM_V6_RT_NHASH_SIZE		0x78
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
#define IPA_MEM_UC_EVENT_RING_OFST		0x1c00

enum ipa_ees {
	IPA_EE_AP	= 0,
	IPA_EE_Q6	= 1,
	IPA_EE_UC	= 2,
};

/** struct ipa_tx_suspend_irq_data - interrupt data for IPA_TX_SUSPEND_IRQ
 * @endpoints: bitmask of endpoints which case IPA_TX_SUSPEND_IRQ interrupt
 * @dma_addr: DMA address of this Rx packet
 */
struct ipa_tx_suspend_irq_data {
	u32 endpoints;
};

typedef void (*ipa_notify_cb)(void *priv, enum ipa_dp_evt_type evt,
		       unsigned long data);

/** typedef ipa_irq_handler_t - irq handler/callback type
 * @param ipa_irq_type - [in] interrupt type
 * @param interrupt_data - [out] interrupt information data
 *
 * callback registered by ipa_add_interrupt_handler function to
 * handle a specific interrupt type
 *
 * No return value
 */
typedef void (*ipa_irq_handler_t)(enum ipa_irq_type interrupt,
				  u32 interrupt_data);

/** struct ipa_sys_connect_params - information needed to setup an IPA end-point
 * in system-BAM mode
 * @priv:	callback cookie
 * @notify:	callback
 *		priv - callback cookie
 *		evt - type of event
 *		data - data relevant to event.  May not be valid. See event_type
 *		enum for valid cases.
 * @napi_enabled: when true, IPA call client callback to start polling
 */
struct ipa_sys_connect_params {
	void *priv;
	ipa_notify_cb notify;
	bool napi_enabled;
};

/** struct ipa_ep_context - IPA end point context
 * @allocated: flag indicating endpoint has been allocated
 * @client: EP client type
 * @gsi_chan_hdl: EP's GSI channel handle
 * @gsi_evt_ring_hdl: EP's GSI channel event ring handle
 * @chan_scratch: EP's GSI channel scratch info
 * @cfg: EP cionfiguration
 * @dst_pipe_index: destination pipe index
 * @rt_tbl_idx: routing table index
 * @priv: user provided information which will forwarded once the user is
 *	  notified for new data avail
 * @client_notify: user provided CB for EP events notification, the event is
 *		   data revived.
 * @disconnect_in_progress: Indicates client disconnect in progress.
 * @qmi_request_sent: Indicates whether QMI request to enable clear data path
 *					request is sent or not.
 * @napi_enabled: when true, IPA call client callback to start polling
 */
struct ipa_ep_context {
	bool allocated;
	enum ipa_client_type client;
	unsigned long gsi_chan_hdl;
	unsigned long gsi_evt_ring_hdl;
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

	u32 dst_pipe_index;
	u32 rt_tbl_idx;
	void *priv;
	void (*client_notify)(void *priv, enum ipa_dp_evt_type evt,
			      unsigned long data);
	u32 dflt_flt4_rule_hdl;
	u32 dflt_flt6_rule_hdl;
	u32 uc_offload_state;
	bool disconnect_in_progress;
	u32 qmi_request_sent;
	bool napi_enabled;
	u32 eot_in_poll_err;
	struct ipa_sys_context *sys;
};

struct ipa_dp;	/* Data path information */

struct ipa_sys_context;

/** enum ipa_desc_type - IPA decriptors type
 *
 * IPA decriptors type, IPA supports DD and ICD but no CD
 */
enum ipa_desc_type {
	IPA_DATA_DESC,
	IPA_DATA_DESC_SKB,
	IPA_DATA_DESC_SKB_PAGED,
	IPA_IMM_CMD_DESC,
};

/** struct ipa_desc - IPA descriptor
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
struct ipa_desc {
	enum ipa_desc_type type;
	u16 len;
	u16 opcode;
	union {
		void *pyld;
		skb_frag_t *frag;
	};
	void (*callback)(void *user1, int user2);
	void *user1;
	int user2;
};

/* Helper function to fill in some IPA descriptor fields for an
 * immediate command using an immediate command payload returned by
 * ipahal_construct_imm_cmd().
 */
static inline void
ipa_desc_fill_imm_cmd(struct ipa_desc *desc, struct ipahal_imm_cmd_pyld *pyld)
{
	desc->type = IPA_IMM_CMD_DESC;
	desc->len = pyld->len;
	desc->opcode = pyld->opcode;
	desc->pyld = ipahal_imm_cmd_pyld_data(pyld);
}

struct ipa_active_clients {
	struct mutex mutex;	/* protects when cnt changes from/to 0 */
	atomic_t cnt;
};

struct ipa_wakelock_ref_cnt {
	spinlock_t spinlock;	/* protects updates to cnt */
	int cnt;
};

struct ipa_uc_ctx;

/** struct ipa_transport_pm - transport power management related members
 * @transport_pm_mutex: Mutex to protect the transport_pm functionality.
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
	bool ipa_clk_on;
	bool res_sent;
};

struct ipa_dma_task_info {
	struct ipa_dma_mem mem;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
};

/** struct ipa_context - IPA context
 * @class: pointer to the struct class
 * @dev_num: device number
 * @dev: the dev_t of the device
 * @cdev: cdev of the device
 * @ep: list of all end points
 * @filter_bitmap: End-points supporting filtering bitmap
 * @flt_tbl: list of all IPA filter tables
 * @mode: IPA operating mode
 * @mmio: iomem
 * @ipa_phys: physical address of IPA register memory
 * @rt_tbl_set: list of routing tables each of which is a list of rules
 * @reap_rt_tbl_set: list of sys mem routing tables waiting to be reaped
 * @dp: data path information
 * @lock: this does NOT protect the linked lists within ipa_sys_context
 * @smem_size: shared memory size available for SW use starting
 *  from non-restricted bytes (i.e. starting at smem_offset)
 * @smem_offset: the offset of the usable area in shared memory
 * @nat_mem: NAT memory
 * @hdr_mem: header memory
 * @hdr_proc_ctx_mem: processing context memory
 * @power_mgmt_wq: workqueue for power management
 * @tag_process_before_gating: indicates whether to start tag process before
 *  gating IPA clocks
 * @transport_pm: transport power management related information
 * @ipa_active_clients: structure for reference counting connected IPA clients
 * @logbuf: ipc log buffer for high priority messages
 * @logbuf_low: ipc log buffer for low priority messages
 * @ipa_bus_hdl: msm driver handle for the data path bus
 * @ctrl: holds the core specific operations based on
 *  core version (vtable like)
 * @wcstats: wlan common buffer stats
 * @uc_ctx: uC interface context
 * @uc_wdi_ctx: WDI specific fields for uC interface
 * @ipa_num_pipes: The number of pipes used by IPA HW
 * @ipa_client_apps_wan_cons_agg_gro: RMNET_IOCTL_INGRESS_FORMAT_AGG_DATA
 * @w_lock: Indicates the wakeup source.
 * @wakelock_ref_cnt: Indicates the number of times wakelock is acquired
 *  finished initializing. Example of use - IOCTLs to /dev/ipa
 * IPA context - holds all relevant info about IPA driver and its state
 */
struct ipa_context {
	u32 filter_bitmap;
	u32 ipa_irq;
	phys_addr_t ipa_phys;
	void __iomem *ipa_mmio;
	struct gsi *gsi;
	struct device *dev;

	struct ipa_ep_context ep[IPA_MAX_NUM_PIPES];
	struct ipa_dp *dp;
	u32 smem_size;
	u16 smem_offset;
	struct ipa_active_clients ipa_active_clients;
	struct workqueue_struct *power_mgmt_wq;
	struct ipa_transport_pm transport_pm;
	u32 clnt_hdl_cmd;
	u32 clnt_hdl_lan_cons;
	struct icc_path *memory_path;
	struct icc_path *imem_path;
	struct icc_path *config_path;
	bool q6_proxy_clk_vote_valid;
	u32 ipa_num_pipes;

	struct ipa_uc_ctx *uc_ctx;

	struct wakeup_source w_lock;
	struct ipa_wakelock_ref_cnt wakelock_ref_cnt;
	/* RMNET_IOCTL_INGRESS_FORMAT_AGG_DATA */
	bool ipa_client_apps_wan_cons_agg_gro;
	/* M-release support to know client pipes */
	struct ipa_smp2p_info smp2p_info;
	struct ipa_dma_task_info dma_task_info;
};

extern struct ipa_context *ipa_ctx;

/* public APIs */

int ipa_wwan_init(void);
void ipa_wwan_cleanup(void);

/* Generic GSI channels functions */

int ipa_stop_gsi_channel(u32 clnt_hdl);

void ipa_reset_gsi_channel(u32 clnt_hdl);

/* Configuration */
void ipa_cfg_ep(u32 clnt_hdl);

/* Data path */
int ipa_tx_dp(enum ipa_client_type dst, struct sk_buff *skb);

/* System pipes */
bool ipa_endp_aggr_support(u32 ipa_ep_idx);
enum ipa_seq_type ipa_endp_seq_type(u32 ipa_ep_idx);

void ipa_endp_init_hdr_cons(u32 ipa_ep_idx, u32 header_size,
			    u32 metadata_offset, u32 length_offset);
void ipa_endp_init_hdr_prod(u32 ipa_ep_idx, u32 header_size,
			    u32 metadata_offset, u32 length_offset);
void ipa_endp_init_hdr_ext_cons(u32 ipa_ep_idx, u32 pad_align,
				bool pad_included);
void ipa_endp_init_hdr_ext_prod(u32 ipa_ep_idx, u32 pad_align);
void ipa_endp_init_mode_cons(u32 ipa_ep_idx);
void ipa_endp_init_mode_prod(u32 ipa_ep_idx, enum ipa_mode mode,
			     enum ipa_client_type dst_client);
void ipa_endp_init_aggr_cons(u32 ipa_ep_idx, u32 size, u32 count,
			     bool close_on_eof);
void ipa_endp_init_aggr_prod(u32 ipa_ep_idx, enum ipa_aggr_en aggr_en,
			     enum ipa_aggr_type aggr_type);
void ipa_endp_init_cfg_cons(u32 ipa_ep_idx,
			    enum ipa_cs_offload_en offload_type);
void ipa_endp_init_cfg_prod(u32 ipa_ep_idx, enum ipa_cs_offload_en offload_type,
			    u32 metadata_offset);
void ipa_endp_init_seq_cons(u32 ipa_ep_idx);
void ipa_endp_init_seq_prod(u32 ipa_ep_idx);
void ipa_endp_init_deaggr_cons(u32 ipa_ep_idx);
void ipa_endp_init_deaggr_prod(u32 ipa_ep_idx);
void ipa_endp_init_hdr_metadata_mask_cons(u32 ipa_ep_idx, u32 mask);
void ipa_endp_init_hdr_metadata_mask_prod(u32 ipa_ep_idx);
void ipa_endp_status_cons(u32 ipa_ep_idx, bool enable);
void ipa_endp_status_prod(u32 ipa_ep_idx, bool enable,
			  enum ipa_client_type client);
int ipa_ep_alloc(enum ipa_client_type client);
void ipa_ep_free(u32 ipa_ep_idx);

void ipa_no_intr_init(u32 prod_ep_idx);

int ipa_setup_sys_pipe(u32 client_hdl, u32 chan_count, u32 rx_buffer_size,
		       struct ipa_sys_connect_params *sys_in);

void ipa_teardown_sys_pipe(u32 clnt_hdl);

void ipa_rx_switch_to_poll_mode(struct ipa_sys_context *sys);

/* interrupts */
void ipa_add_interrupt_handler(enum ipa_irq_type interrupt,
			       ipa_irq_handler_t handler);

void ipa_remove_interrupt_handler(enum ipa_irq_type interrupt);

/* Miscellaneous */
void ipa_proxy_clk_vote(void);
void ipa_proxy_clk_unvote(void);

enum ipa_client_type ipa_get_client_mapping(u32 pipe_idx);

u32 ipa_filter_bitmap_init(void);

/* internal functions */

bool ipa_is_modem_pipe(u32 pipe_idx);

u32 ipa_get_ep_mapping(enum ipa_client_type client);
struct ipa_ep_context *ipa_get_ep_context(enum ipa_client_type client);

void ipa_init_hw(void);

int ipa_interconnect_init(struct device *dev);
void ipa_interconnect_exit(void);

int ipa_interconnect_enable(void);
int ipa_interconnect_disable(void);

int ipa_send_cmd_timeout(struct ipa_desc *desc, u32 timeout);
int ipa_send_cmd(struct ipa_desc *desc);

void ipa_client_add(void);
bool ipa_client_add_additional(void);
void ipa_client_remove(void);
void ipa_client_remove_wait(void);

u32 ipa_aggr_byte_limit_buf_size(u32 byte_limit);

void ipa_cfg_default_route(enum ipa_client_type client);

int ipa_interrupts_init(void);

void ipa_suspend_active_aggr_wa(u32 clnt_hdl);
void ipa_lan_rx_cb(void *priv, enum ipa_dp_evt_type evt, unsigned long data);

void ipa_sram_settings_read(void);

int ipa_init_q6_smem(void);

/* Defined in "ipa_uc.c" */
struct ipa_uc_ctx *ipa_uc_init(phys_addr_t phys_addr);
bool ipa_uc_loaded(void);
void ipa_uc_panic_notifier(void);

const struct ipa_gsi_ep_config *ipa_get_gsi_ep_info
	(enum ipa_client_type client);
u32 ipa_get_num_pipes(void);
int ipa_ap_suspend(struct device *dev);
int ipa_ap_resume(struct device *dev);
void ipa_set_resource_groups_min_max_limits(void);
void ipa_suspend_apps_pipes(void);
void ipa_resume_apps_pipes(void);
void ipa_inc_acquire_wakelock(void);
void ipa_dec_release_wakelock(void);
int ipa_rx_poll(u32 clnt_hdl, int budget);
void ipa_reset_freeze_vote(void);
void ipa_enable_dcd(void);

int ipa_gsi_dma_task_alloc(void);
void ipa_gsi_dma_task_free(void);
int ipa_gsi_dma_task_inject(void);

void ipa_set_flt_tuple_mask(u32 pipe_idx, struct ipa_reg_hash_tuple *tuple);
void ipa_set_rt_tuple_mask(int tbl_idx, struct ipa_reg_hash_tuple *tuple);

void ipa_gsi_irq_rx_notify_cb(void *chan_data, u16 count);
void ipa_gsi_irq_tx_notify_cb(void *xfer_data);

bool ipa_ep_polling(struct ipa_ep_context *ep);

struct ipa_dp *ipa_dp_init(void);
void ipa_dp_exit(struct ipa_dp *dp);

#endif /* _IPA_I_H_ */
