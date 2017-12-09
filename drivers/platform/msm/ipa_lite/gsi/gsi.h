/* Copyright (c) 2015-2017, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#ifndef GSI_LITE_H
#define GSI_LITE_H

#include <linux/device.h>
#include <linux/types.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/ipc_logging.h>
#include <linux/platform_device.h>

#include <linux/msm_gsi.h>

#define GSI_CHAN_MAX      31
#define GSI_EVT_RING_MAX  23
#define GSI_NO_EVT_ERINDEX 31

#define GSI_IPC_LOGGING(buf, fmt, args...) \
	do { \
		if (buf) \
			ipc_log_string((buf), fmt, __func__, __LINE__, \
				## args); \
	} while (0)

#define GSIDBG(fmt, args...) \
	do { \
		dev_dbg(gsi_ctx->dev, "%s:%d " fmt, __func__, __LINE__, \
		## args);\
		if (gsi_ctx) { \
			GSI_IPC_LOGGING(gsi_ctx->ipc_logbuf, \
				"%s:%d " fmt, ## args); \
			GSI_IPC_LOGGING(gsi_ctx->ipc_logbuf_low, \
				"%s:%d " fmt, ## args); \
		} \
	} while (0)

#define GSIDBG_LOW(fmt, args...) \
	do { \
		dev_dbg(gsi_ctx->dev, "%s:%d " fmt, __func__, __LINE__, \
		## args);\
		if (gsi_ctx) { \
			GSI_IPC_LOGGING(gsi_ctx->ipc_logbuf_low, \
				"%s:%d " fmt, ## args); \
		} \
	} while (0)

#define GSIERR(fmt, args...) \
	do { \
		dev_err(gsi_ctx->dev, "%s:%d " fmt, __func__, __LINE__, \
		## args);\
		if (gsi_ctx) { \
			GSI_IPC_LOGGING(gsi_ctx->ipc_logbuf, \
				"%s:%d " fmt, ## args); \
			GSI_IPC_LOGGING(gsi_ctx->ipc_logbuf_low, \
				"%s:%d " fmt, ## args); \
		} \
	} while (0)

#define GSI_IPC_LOG_PAGES 50
#define IPA_GSI_CHANNEL_STOP_SLEEP_MIN_USEC (1000)
#define IPA_GSI_CHANNEL_STOP_SLEEP_MAX_USEC (2000)


/* msm_gsi.h */

/**
 * struct ipa_gsi_ep_config - IPA GSI endpoint configurations
 *
 * @ipa_ep_num: IPA EP pipe number
 * @ipa_gsi_chan_num: GSI channel number
 * @ipa_if_tlv: number of IPA_IF TLV
 * @ipa_if_aos: number of IPA_IF AOS
 * @ee: Execution environment
 */
struct ipa_gsi_ep_config {
        int ipa_ep_num;
        int ipa_gsi_chan_num;
        int ipa_if_tlv;
        int ipa_if_aos;
        int ee;
};



/**
 * gsi_mhi_evt_scratch - MHI protocol SW config area of
 * event scratch
 */
struct __packed gsi_mhi_evt_scratch {
        uint32_t resvd1;
        uint32_t resvd2;
};

/**
 * gsi_xdci_evt_scratch - xDCI protocol SW config area of
 * event scratch
 *
 */
struct __packed gsi_xdci_evt_scratch {
        uint32_t gevntcount_low_addr;
        uint32_t gevntcount_hi_addr:8;
        uint32_t resvd1:24;
};

/**
 * gsi_evt_scratch - event scratch SW config area
 *
 */
union __packed gsi_evt_scratch {
        struct __packed gsi_mhi_evt_scratch mhi;
        struct __packed gsi_xdci_evt_scratch xdci;
        struct __packed {
                uint32_t word1;
                uint32_t word2;
        } data;
};

/**
 * gsi_device_scratch - EE scratch config parameters
 *
 * @mhi_base_chan_idx_valid: is mhi_base_chan_idx valid?
 * @mhi_base_chan_idx:       base index of IPA MHI channel indexes.
 *                           IPA MHI channel index = GSI channel ID +
 *                           MHI base channel index
 * @max_usb_pkt_size_valid:  is max_usb_pkt_size valid?
 * @max_usb_pkt_size:        max USB packet size in bytes (valid values are
 *                           512 and 1024)
 */
struct gsi_device_scratch {
        bool mhi_base_chan_idx_valid;
        uint8_t mhi_base_chan_idx;
        bool max_usb_pkt_size_valid;
        uint16_t max_usb_pkt_size;
};

/**
 * gsi_per_props - Peripheral related properties
 *
 * @ee:         EE where this driver and peripheral driver runs
 * @irq:        IRQ number
 * @phys_addr:  physical address of GSI block
 * @size:       register size of GSI block
 * @notify_cb:  general notification callback
 *
 * All the callbacks are in interrupt context
 *
 */
struct gsi_per_props {
	unsigned int irq;
};

enum gsi_chan_mode {
	GSI_CHAN_MODE_CALLBACK = 0x0,
	GSI_CHAN_MODE_POLL = 0x1,
};

enum gsi_xfer_flag {
	GSI_XFER_FLAG_CHAIN = 0x1,
	GSI_XFER_FLAG_EOB = 0x100,
	GSI_XFER_FLAG_EOT = 0x200,
	GSI_XFER_FLAG_BEI = 0x400
};

/**
 * gsi_chan_info - information about channel occupancy
 *
 * @wp: channel write pointer (physical address)
 * @rp: channel read pointer (physical address)
 * @evt_valid: is evt* info valid?
 * @evt_wp: event ring write pointer (physical address)
 * @evt_rp: event ring read pointer (physical address)
 */
struct gsi_chan_info {
	uint64_t wp;
	uint64_t rp;
	bool evt_valid;
	uint64_t evt_wp;
	uint64_t evt_rp;
};

/* msm_gsi.h */

enum gsi_evt_ring_state {
	GSI_EVT_RING_STATE_NOT_ALLOCATED = 0x0,
	GSI_EVT_RING_STATE_ALLOCATED = 0x1,
	GSI_EVT_RING_STATE_ERROR = 0xf
};

enum gsi_chan_state {
	GSI_CHAN_STATE_NOT_ALLOCATED = 0x0,
	GSI_CHAN_STATE_ALLOCATED = 0x1,
	GSI_CHAN_STATE_STARTED = 0x2,
	GSI_CHAN_STATE_STOPPED = 0x3,
	GSI_CHAN_STATE_STOP_IN_PROC = 0x4,
	GSI_CHAN_STATE_ERROR = 0xf
};

struct gsi_ring_ctx {
	spinlock_t slock;
	unsigned long base_va;
	uint64_t base;
	uint64_t wp;
	uint64_t rp;
	uint64_t wp_local;
	uint64_t rp_local;
	uint16_t len;
	uint8_t elem_sz;
	uint16_t max_num_elem;
	uint64_t end;
};

struct gsi_chan_dp_stats {
	unsigned long ch_below_lo;
	unsigned long ch_below_hi;
	unsigned long ch_above_hi;
	unsigned long empty_time;
	unsigned long last_timestamp;
};

struct gsi_chan_stats {
	unsigned long queued;
	unsigned long completed;
	unsigned long callback_to_poll;
	unsigned long poll_to_callback;
	unsigned long invalid_tre_error;
	unsigned long poll_ok;
	unsigned long poll_empty;
	struct gsi_chan_dp_stats dp;
};

/**
 * gsi_gpi_channel_scratch - GPI protocol SW config area of
 * channel scratch
 *
 * @max_outstanding_tre: Used for the prefetch management sequence by the
 *                       sequencer. Defines the maximum number of allowed
 *                       outstanding TREs in IPA/GSI (in Bytes). RE engine
 *                       prefetch will be limited by this configuration. It
 *                       is suggested to configure this value to IPA_IF
 *                       channel TLV queue size times element size. To disable
 *                       the feature in doorbell mode (DB Mode=1). Maximum
 *                       outstanding TREs should be set to 64KB
 *                       (or any value larger or equal to ring length . RLEN)
 * @outstanding_threshold: Used for the prefetch management sequence by the
 *                       sequencer. Defines the threshold (in Bytes) as to when
 *                       to update the channel doorbell. Should be smaller than
 *                       Maximum outstanding TREs. value. It is suggested to
 *                       configure this value to 2 * element size.
 */
struct __packed gsi_gpi_channel_scratch {
        uint64_t resvd1;
        uint32_t resvd2:16;
        uint32_t max_outstanding_tre:16;
        uint32_t resvd3:16;
        uint32_t outstanding_threshold:16;
};


/**
 * gsi_channel_scratch - channel scratch SW config area
 *
 */
union __packed gsi_channel_scratch {
        struct __packed gsi_gpi_channel_scratch gpi;
        struct __packed {
                uint32_t word1;
                uint32_t word2;
                uint32_t word3;
                uint32_t word4;
        } data;
};

struct gsi_chan_ctx {
	struct gsi_chan_props props;
	enum gsi_chan_state state;
	struct gsi_ring_ctx ring;
	void **user_data;
	struct gsi_evt_ctx *evtr;
	struct mutex mlock;
	struct completion compl;
	bool allocated;
	atomic_t poll_mode;
	union __packed gsi_channel_scratch scratch;
	struct gsi_chan_stats stats;
	bool enable_dp_stats;
	bool print_dp_stats;
};

struct gsi_evt_stats {
	unsigned long completed;
};

struct gsi_evt_ctx {
	struct gsi_evt_ring_props props;
	enum gsi_evt_ring_state state;
	uint8_t id;
	struct gsi_ring_ctx ring;
	struct mutex mlock;
	struct completion compl;
	struct gsi_chan_ctx *chan;
	atomic_t chan_ref_cnt;
	union __packed gsi_evt_scratch scratch;
	struct gsi_evt_stats stats;
};

struct gsi_ee_scratch {
	union __packed {
		struct {
			uint32_t inter_ee_cmd_return_code:3;
			uint32_t resvd1:2;
			uint32_t generic_ee_cmd_return_code:3;
			uint32_t resvd2:7;
			uint32_t max_usb_pkt_size:1;
			uint32_t resvd3:8;
			uint32_t mhi_base_chan_idx:8;
		} s;
		uint32_t val;
	} word0;
	uint32_t word1;
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

struct gsi_generic_ee_cmd_debug_stats {
	unsigned long halt_channel;
};

struct gsi_ctx {
	void __iomem *base;
	struct device *dev;
	u32 ee;
	struct gsi_per_props per;
	bool per_registered;
	struct gsi_chan_ctx chan[GSI_CHAN_MAX];
	struct ch_debug_stats ch_dbg[GSI_CHAN_MAX];
	struct gsi_evt_ctx evtr[GSI_EVT_RING_MAX];
	struct gsi_generic_ee_cmd_debug_stats gen_ee_cmd_dbg;
	struct mutex mlock;
	spinlock_t slock;
	unsigned long evt_bmap;
	atomic_t num_chan;
	atomic_t num_evt_ring;
	struct gsi_ee_scratch scratch;
	int num_ch_dp_stats;
	struct workqueue_struct *dp_stat_wq;
	u32 max_ch;
	u32 max_ev;
	struct completion gen_ee_cmd_compl;
	void *ipc_logbuf;
	void *ipc_logbuf_low;
};

enum gsi_re_type {
	GSI_RE_XFER = 0x2,
	GSI_RE_IMMD_CMD = 0x3,
	GSI_RE_NOP = 0x4,
};

struct __packed gsi_tre {
	uint64_t buffer_ptr;
	uint16_t buf_len;
	uint16_t resvd1;
	uint16_t chain:1;
	uint16_t resvd4:7;
	uint16_t ieob:1;
	uint16_t ieot:1;
	uint16_t bei:1;
	uint16_t resvd3:5;
	uint8_t re_type;
	uint8_t resvd2;
};

struct __packed gsi_xfer_compl_evt {
	uint64_t xfer_ptr;
	uint16_t len;
	uint8_t resvd1;
	uint8_t code;  /* see gsi_chan_evt */
	uint16_t resvd;
	uint8_t type;
	uint8_t chid;
};

enum gsi_err_type {
	GSI_ERR_TYPE_GLOB = 0x1,
	GSI_ERR_TYPE_CHAN = 0x2,
	GSI_ERR_TYPE_EVT = 0x3,
};

enum gsi_err_code {
	GSI_INVALID_TRE_ERR = 0x1,
	GSI_OUT_OF_BUFFERS_ERR = 0x2,
	GSI_OUT_OF_RESOURCES_ERR = 0x3,
	GSI_UNSUPPORTED_INTER_EE_OP_ERR = 0x4,
	GSI_EVT_RING_EMPTY_ERR = 0x5,
	GSI_NON_ALLOCATED_EVT_ACCESS_ERR = 0x6,
	GSI_HWO_1_ERR = 0x8
};

struct __packed gsi_log_err {
	uint32_t arg3:4;
	uint32_t arg2:4;
	uint32_t arg1:4;
	uint32_t code:4;
	uint32_t resvd:3;
	uint32_t virt_idx:5;
	uint32_t err_type:4;
	uint32_t ee:4;
};

enum gsi_ch_cmd_opcode {
	GSI_CH_ALLOCATE = 0x0,
	GSI_CH_START = 0x1,
	GSI_CH_STOP = 0x2,
	GSI_CH_RESET = 0x9,
	GSI_CH_DE_ALLOC = 0xa,
	GSI_CH_DB_STOP = 0xb,
};

enum gsi_evt_ch_cmd_opcode {
	GSI_EVT_ALLOCATE = 0x0,
	GSI_EVT_RESET = 0x9,  /* TODO: is this valid? */
	GSI_EVT_DE_ALLOC = 0xa,
};

enum gsi_generic_ee_cmd_opcode {
	GSI_GEN_EE_CMD_HALT_CHANNEL = 0x1,
};

enum gsi_generic_ee_cmd_return_code {
	GSI_GEN_EE_CMD_RETURN_CODE_SUCCESS = 0x1,
	GSI_GEN_EE_CMD_RETURN_CODE_CHANNEL_NOT_RUNNING = 0x2,
	GSI_GEN_EE_CMD_RETURN_CODE_INCORRECT_DIRECTION = 0x3,
	GSI_GEN_EE_CMD_RETURN_CODE_INCORRECT_CHANNEL_TYPE = 0x4,
	GSI_GEN_EE_CMD_RETURN_CODE_INCORRECT_CHANNEL_INDEX = 0x5,
};

extern struct gsi_ctx *gsi_ctx;
void gsi_debugfs_init(void);
uint16_t gsi_find_idx_from_addr(struct gsi_ring_ctx *ctx, uint64_t addr);
void gsi_update_ch_dp_stats(struct gsi_chan_ctx *ctx, uint16_t used);
int msm_gsi_init(struct platform_device *pdev);

/*
 * Read a value from the given offset into the I/O space defined in
 * the GSI context.
 */
static inline u32 gsi_readl(u32 offset)
{
	return readl(gsi_ctx->base + offset);
}

/*
 * Write the provided value to the given offset into the I/O space
 * defined in the GSI context.
 */
static inline void gsi_writel(u32 v, u32 offset)
{
	writel(v, gsi_ctx->base + offset);
}

/**
 * gsi_register_device - Peripheral should call this function to
 * register itself with GSI before invoking any other APIs
 *
 * @ee:  AP execution environment (EE) number to use
 *
 * @Return -GSI_STATUS_AGAIN if request should be re-tried later
 *	   other error codes for failure
 */
void *gsi_register_device(u32 ee);

/**
 * gsi_deregister_device - Peripheral should call this function to
 * de-register itself with GSI
 *
 * @dev_hdl:  Client handle previously obtained from gsi_register_device
 *
 * @Return 0, or a negative errno
 */
int gsi_deregister_device(void *dev_hdl);

/**
 * gsi_alloc_evt_ring - Peripheral should call this function to
 * allocate an event ring
 *
 * @props:	   Event ring properties
 * @dev_hdl:	   Client handle previously obtained from gsi_register_device
 *
 * This function can sleep
 *
 * @Return Client handle populated by GSI, or a negative errno
 */
long gsi_alloc_evt_ring(struct gsi_evt_ring_props *props, void *dev_hdl);

/**
 * gsi_dealloc_evt_ring - Peripheral should call this function to
 * de-allocate an event ring. There should not exist any active
 * channels using this event ring
 *
 * @evt_ring_hdl:  Client handle previously obtained from gsi_alloc_evt_ring
 *
 * This function can sleep
 *
 * @Return 0, or a negative errno
 */
int gsi_dealloc_evt_ring(unsigned long evt_ring_hdl);

/**
 * gsi_reset_evt_ring - Peripheral should call this function to
 * reset an event ring to recover from error state
 *
 * @evt_ring_hdl:  Client handle previously obtained from
 *             gsi_alloc_evt_ring
 *
 * This function can sleep
 *
 * @Return gsi_status
 */
int gsi_reset_evt_ring(unsigned long evt_ring_hdl);

/**
 * gsi_alloc_channel - Peripheral should call this function to
 * allocate a channel
 *
 * @props:     Channel properties
 * @dev_hdl:   Client handle previously obtained from gsi_register_device
 *
 * This function can sleep
 *
 * @Return Channel handle populated by GSI, opaque to client, or negative errno
 */
long gsi_alloc_channel(struct gsi_chan_props *props, void *dev_hdl);

/**
 * gsi_write_channel_scratch - Peripheral should call this function to
 * write to the scratch area of the channel context
 *
 * @chan_hdl:  Client handle previously obtained from
 *             gsi_alloc_channel
 * @val:       Value to write
 *
 * @Return gsi_status
 */
int gsi_write_channel_scratch(unsigned long chan_hdl,
		union __packed gsi_channel_scratch val);

/**
 * gsi_start_channel - Peripheral should call this function to
 * start a channel i.e put into running state
 *
 * @chan_hdl:  Client handle previously obtained from
 *             gsi_alloc_channel
 *
 * This function can sleep
 *
 * @Return gsi_status
 */
int gsi_start_channel(unsigned long chan_hdl);

/**
 * gsi_stop_channel - Peripheral should call this function to
 * stop a channel. Stop will happen on a packet boundary
 *
 * @chan_hdl:  Client handle previously obtained from
 *             gsi_alloc_channel
 *
 * This function can sleep
 *
 * @Return -GSI_STATUS_AGAIN if client should call stop/stop_db again
 *	   other error codes for failure
 */
int gsi_stop_channel(unsigned long chan_hdl);

/**
 * gsi_reset_channel - Peripheral should call this function to
 * reset a channel to recover from error state
 *
 * @chan_hdl:  Client handle previously obtained from
 *             gsi_alloc_channel
 *
 * This function can sleep
 *
 * @Return gsi_status
 */
int gsi_reset_channel(unsigned long chan_hdl);

/**
 * gsi_dealloc_channel - Peripheral should call this function to
 * de-allocate a channel
 *
 * @chan_hdl:  Client handle previously obtained from
 *             gsi_alloc_channel
 *
 * This function can sleep
 *
 * @Return 0, or a negative errno
 */
int gsi_dealloc_channel(unsigned long chan_hdl);

/**
 * gsi_is_channel_empty - Peripheral can call this function to query if
 * the channel is empty. This is only applicable to GPI. "Empty" means
 * GSI has consumed all descriptors for a TO_GSI channel and SW has
 * processed all completed descriptors for a FROM_GSI channel.
 *
 * @chan_hdl:  Client handle previously obtained from gsi_alloc_channel
 *
 * @Return true if channel is empty, false otherwise
 */
bool gsi_is_channel_empty(unsigned long chan_hdl);

/**
 * gsi_get_channel_cfg - This function returns the current config
 * of the specified channel
 *
 * @chan_hdl:  Client handle previously obtained from
 *             gsi_alloc_channel
 * @props:     where to copy properties to
 * @scr:       where to copy scratch info to
 *
 * @Return gsi_status
 */
int gsi_get_channel_cfg(unsigned long chan_hdl, struct gsi_chan_props *props,
		union gsi_channel_scratch *scr);

/**
 * gsi_set_channel_cfg - This function applies the supplied config
 * to the specified channel
 *
 * ch_id and evt_ring_hdl of the channel cannot be changed after
 * gsi_alloc_channel
 *
 * @chan_hdl:  Client handle previously obtained from
 *             gsi_alloc_channel
 * @props:     the properties to apply
 * @scr:       the scratch info to apply
 *
 * @Return gsi_status
 */
int gsi_set_channel_cfg(unsigned long chan_hdl, struct gsi_chan_props *props,
		union gsi_channel_scratch *scr);

/**
 * gsi_poll_channel - Peripheral should call this function to query for
 * completed transfer descriptors.
 *
 * @chan_hdl:  Client handle previously obtained from
 *             gsi_alloc_channel
 * @notify:    Information about the completed transfer if any
 *
 * @Return gsi_status (GSI_STATUS_POLL_EMPTY is returned if no transfers
 * completed)
 */
int gsi_poll_channel(unsigned long chan_hdl,
		struct gsi_chan_xfer_notify *notify);

/**
 * gsi_config_channel_mode - Peripheral should call this function
 * to configure the channel mode.
 *
 * @chan_hdl:  Client handle previously obtained from
 *             gsi_alloc_channel
 * @mode:      Mode to move the channel into
 *
 * @Return gsi_status
 */
int gsi_config_channel_mode(unsigned long chan_hdl, enum gsi_chan_mode mode);

/**
 * gsi_queue_xfer - Peripheral should call this function
 * to queue transfers on the given channel
 *
 * @chan_hdl:  Client handle previously obtained from
 *             gsi_alloc_channel
 * @num_xfers: Number of transfer in the array @ xfer
 * @xfer:      Array of num_xfers transfer descriptors
 * @ring_db:   If true, tell HW about these queued xfers
 *             If false, do not notify HW at this time
 *
 * @Return gsi_status
 */
int gsi_queue_xfer(unsigned long chan_hdl, uint16_t num_xfers,
		struct gsi_xfer_elem *xfer, bool ring_db);

/**
 * gsi_start_xfer - Peripheral should call this function to
 * inform HW about queued xfers
 *
 * @chan_hdl:  Client handle previously obtained from
 *             gsi_alloc_channel
 *
 * @Return gsi_status
 */
int gsi_start_xfer(unsigned long chan_hdl);

/**
 * gsi_configure_regs - Peripheral should call this function
 * to configure the GSI registers before/after the FW is
 * loaded but before it is enabled.
 *
 * @gsi_base_addr: Base address of GSI register space
 * @gsi_size: Mapping size of the GSI register space
 * @per_base_addr: Base address of the peripheral using GSI
 *
 * @Return gsi_status
 */
int gsi_configure_regs(phys_addr_t gsi_base_addr, u32 gsi_size,
		phys_addr_t per_base_addr);

/**
 * gsi_enable_fw - Peripheral should call this function
 * to enable the GSI FW after the FW has been loaded to the SRAM.
 *
 * @gsi_base_addr: Base address of GSI register space
 * @gsi_size: Mapping size of the GSI register space

 * @Return gsi_status
 */
int gsi_enable_fw(phys_addr_t gsi_base_addr, u32 gsi_size);

/**
 * gsi_get_inst_ram_offset_and_size - Peripheral should call this function
 * to get instruction RAM base address offset and size. Peripheral typically
 * uses this info to load GSI FW into the IRAM.
 *
 * @base_offset:[OUT] - IRAM base offset address
 * @size:	[OUT] - IRAM size

 * @Return none
 */
void gsi_get_inst_ram_offset_and_size(unsigned long *base_offset,
		unsigned long *size);

/**
 * gsi_halt_channel_ee - Peripheral should call this function
 * to stop other EE's channel. This is usually used in SSR clean
 *
 * @chan_idx: Virtual channel index
 * @ee: EE
 * @code: [out] response code for operation

 * @Return gsi_status
 */
int gsi_halt_channel_ee(unsigned int chan_idx, unsigned int ee, int *code);


#endif
