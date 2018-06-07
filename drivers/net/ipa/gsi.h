// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2015-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#ifndef GSI_LITE_H
#define GSI_LITE_H

#include <linux/device.h>
#include <linux/types.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/platform_device.h>

#include "ipahal.h"

#define GSI_CHAN_MAX	  31
#define GSI_EVT_RING_MAX  23
#define GSI_NO_EVT_ERINDEX 31

#define GSI_EVT_RING_ELEMENT_SIZE	16	/* bytes */
#define GSI_CHAN_RING_ELEMENT_SIZE	16	/* bytes */

#define IPA_GSI_CHANNEL_STOP_SLEEP_MIN_USEC (1000)
#define IPA_GSI_CHANNEL_STOP_SLEEP_MAX_USEC (2000)


/* gsi.h */

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
	u32 ipa_ep_num;
	u32 ipa_gsi_chan_num;
	u32 ipa_if_tlv;
	u32 ipa_if_aos;
	u32 ee;
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
 * @mhi_base_chan_idx:	     base index of IPA MHI channel indexes.
 *			     IPA MHI channel index = GSI channel ID +
 *			     MHI base channel index
 * @max_usb_pkt_size_valid:  is max_usb_pkt_size valid?
 * @max_usb_pkt_size:	     max USB packet size in bytes (valid values are
 *			     512 and 1024)
 */
struct gsi_device_scratch {
	bool mhi_base_chan_idx_valid;
	uint8_t mhi_base_chan_idx;
	bool max_usb_pkt_size_valid;
	uint16_t max_usb_pkt_size;
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

/* gsi.h */

enum gsi_intr_type {
	GSI_INTR_MSI = 0x0,
	GSI_INTR_IRQ = 0x1
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

enum gsi_evt_err {
	GSI_EVT_OUT_OF_BUFFERS_ERR		= GSI_OUT_OF_BUFFERS_ERR,
	GSI_EVT_OUT_OF_RESOURCES_ERR		= GSI_OUT_OF_RESOURCES_ERR,
	GSI_EVT_UNSUPPORTED_INTER_EE_OP_ERR	= GSI_UNSUPPORTED_INTER_EE_OP_ERR,
	GSI_EVT_EVT_RING_EMPTY_ERR		= GSI_EVT_RING_EMPTY_ERR,
};

enum gsi_evt_chtype {
	GSI_EVT_CHTYPE_MHI_EV = 0x0,
	GSI_EVT_CHTYPE_XHCI_EV = 0x1,
	GSI_EVT_CHTYPE_GPI_EV = 0x2,
	GSI_EVT_CHTYPE_XDCI_EV = 0x3
};

enum gsi_chan_prot {
	GSI_CHAN_PROT_MHI = 0x0,
	GSI_CHAN_PROT_XHCI = 0x1,
	GSI_CHAN_PROT_GPI = 0x2,
	GSI_CHAN_PROT_XDCI = 0x3
};

enum gsi_chan_dir {
	GSI_CHAN_DIR_FROM_GSI = 0x0,
	GSI_CHAN_DIR_TO_GSI = 0x1
};

enum gsi_chan_evt {
	GSI_CHAN_EVT_INVALID = 0x0,
	GSI_CHAN_EVT_SUCCESS = 0x1,
	GSI_CHAN_EVT_EOT = 0x2,
	GSI_CHAN_EVT_OVERFLOW = 0x3,
	GSI_CHAN_EVT_EOB = 0x4,
	GSI_CHAN_EVT_OOB = 0x5,
	GSI_CHAN_EVT_DB_MODE = 0x6,
	GSI_CHAN_EVT_UNDEFINED = 0x10,
	GSI_CHAN_EVT_RE_ERROR = 0x11,
};

/**
 * gsi_chan_xfer_notify - Channel callback info
 *
 * @chan_user_data: cookie supplied in gsi_alloc_channel
 * @xfer_user_data: cookie of the gsi_xfer_elem that caused the
 *		    event to be generated
 * @evt_id:	    type of event triggered by the associated TRE
 *		    (corresponding to xfer_user_data)
 * @bytes_xfered:   number of bytes transferred by the associated TRE
 *		    (corresponding to xfer_user_data)
 *
 */
struct gsi_chan_xfer_notify {
	void *chan_user_data;
	void *xfer_user_data;
	enum gsi_chan_evt evt_id;
	uint16_t bytes_xfered;
};

enum gsi_chan_err {
	GSI_CHAN_INVALID_TRE_ERR		= GSI_INVALID_TRE_ERR,
	GSI_CHAN_NON_ALLOCATED_EVT_ACCESS_ERR	= GSI_NON_ALLOCATED_EVT_ACCESS_ERR,
	GSI_CHAN_OUT_OF_BUFFERS_ERR		= GSI_OUT_OF_BUFFERS_ERR,
	GSI_CHAN_OUT_OF_RESOURCES_ERR		= GSI_OUT_OF_RESOURCES_ERR,
	GSI_CHAN_UNSUPPORTED_INTER_EE_OP_ERR	= GSI_UNSUPPORTED_INTER_EE_OP_ERR,
	GSI_CHAN_HWO_1_ERR			= GSI_HWO_1_ERR,
};

enum gsi_chan_use_db_eng {
	GSI_CHAN_DIRECT_MODE = 0x0,
	GSI_CHAN_DB_MODE = 0x1,
};

/**
 * gsi_chan_props - Channel related properties
 *
 * @dir:	     channel direction
 * @ch_id:	     virtual channel ID
 * @evt_ring_hdl:    handle of associated event ring. set to ~0 if no
 *		     event ring associated
 * @re_size:	     size of channel ring element
 * @ring_len:	     length of ring in bytes (must be integral multiple of
 *		     re_size)
 * @ring_base_addr:  physical base address of ring. Address must be aligned to
 *		     ring_len rounded to power of two
 * @ring_base_vaddr: virtual base address of ring (set to NULL when not
 *		     applicable)
 * @use_db_eng:	     0 => direct mode (doorbells are written directly to RE
 *		     engine)
 *		     1 => DB mode (doorbells are written to DB engine)
 * @max_prefetch:    limit number of pre-fetch segments for channel
 * @low_weight:	     low channel weight (priority of channel for RE engine
 *		     round robin algorithm); must be >= 1
 * @xfer_cb:	     transfer notification callback (or NULL if not needed)
 *		     this callback happens on event boundaries
 *
 *		     e.g. 1
 *
 *		     out TD with 3 REs
 *
 *		     RE1: EOT=0, EOB=0, CHAIN=1;
 *		     RE2: EOT=0, EOB=0, CHAIN=1;
 *		     RE3: EOT=1, EOB=0, CHAIN=0;
 *
 *		     the callback will be triggered for RE3 using the
 *		     xfer_user_data of that RE
 *
 *		     e.g. 2
 *
 *		     in REs
 *
 *		     RE1: EOT=1, EOB=0, CHAIN=0;
 *		     RE2: EOT=1, EOB=0, CHAIN=0;
 *		     RE3: EOT=1, EOB=0, CHAIN=0;
 *
 *		     received packet consumes all of RE1, RE2 and part of RE3
 *		     for EOT condition. there will be three callbacks in below
 *		     order
 *
 *		     callback for RE1 using GSI_CHAN_EVT_OVERFLOW
 *		     callback for RE2 using GSI_CHAN_EVT_OVERFLOW
 *		     callback for RE3 using GSI_CHAN_EVT_EOT
 *
 * @chan_user_data:  cookie used for notifications
 *
 * All the callbacks are in interrupt context
 *
 */
struct gsi_chan_props {
	struct ipa_mem_buffer mem;
	enum gsi_chan_dir dir;
	uint8_t ch_id;
	unsigned long evt_ring_hdl;
	enum gsi_chan_use_db_eng use_db_eng;
	uint8_t low_weight;
	void (*xfer_cb)(struct gsi_chan_xfer_notify *notify);
	void *chan_user_data;
};

enum gsi_xfer_elem_type {
	GSI_XFER_ELEM_DATA,
	GSI_XFER_ELEM_IMME_CMD,
	GSI_XFER_ELEM_NOP,
};

/**
 * gsi_xfer_elem - Metadata about a single transfer
 *
 * @addr:	    physical address of buffer
 * @len:	    size of buffer for GSI_XFER_ELEM_DATA:
 *		    for outbound transfers this is the number of bytes to
 *		    transfer.
 *		    for inbound transfers, this is the maximum number of
 *		    bytes the host expects from device in this transfer
 *
 *		    immediate command opcode for GSI_XFER_ELEM_IMME_CMD
 * @flags:	    transfer flags, OR of all the applicable flags
 *
 *		    GSI_XFER_FLAG_BEI: Block event interrupt
 *		    1: Event generated by this ring element must not assert
 *		    an interrupt to the host
 *		    0: Event generated by this ring element must assert an
 *		    interrupt to the host
 *
 *		    GSI_XFER_FLAG_EOT: Interrupt on end of transfer
 *		    1: If an EOT condition is encountered when processing
 *		    this ring element, an event is generated by the device
 *		    with its completion code set to EOT.
 *		    0: If an EOT condition is encountered for this ring
 *		    element, a completion event is not be generated by the
 *		    device, unless IEOB is 1
 *
 *		    GSI_XFER_FLAG_EOB: Interrupt on end of block
 *		    1: Device notifies host after processing this ring element
 *		    by sending a completion event
 *		    0: Completion event is not required after processing this
 *		    ring element
 *
 *		    GSI_XFER_FLAG_CHAIN: Chain bit that identifies the ring
 *		    elements in a TD
 *
 * @type:	    transfer type
 *
 *		    GSI_XFER_ELEM_DATA: for all data transfers
 *		    GSI_XFER_ELEM_IMME_CMD: for IPA immediate commands
 *		    GSI_XFER_ELEM_NOP: for event generation only
 *
 * @xfer_user_data: cookie used in xfer_cb
 *
 */
struct gsi_xfer_elem {
	uint64_t addr;
	uint16_t len;
	uint16_t flags;
	enum gsi_xfer_elem_type type;
	void *xfer_user_data;
};

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
	struct ipa_mem_buffer mem;
	uint64_t wp;
	uint64_t rp;
	uint64_t wp_local;
	uint64_t rp_local;
	uint8_t elem_sz;
	uint16_t max_num_elem;
	uint64_t end;
};

/**
 * gsi_gpi_channel_scratch - GPI protocol SW config area of
 * channel scratch
 *
 * @max_outstanding_tre: Used for the prefetch management sequence by the
 *			 sequencer. Defines the maximum number of allowed
 *			 outstanding TREs in IPA/GSI (in Bytes). RE engine
 *			 prefetch will be limited by this configuration. It
 *			 is suggested to configure this value to IPA_IF
 *			 channel TLV queue size times element size. To disable
 *			 the feature in doorbell mode (DB Mode=1). Maximum
 *			 outstanding TREs should be set to 64KB
 *			 (or any value larger or equal to ring length . RLEN)
 * @outstanding_threshold: Used for the prefetch management sequence by the
 *			 sequencer. Defines the threshold (in Bytes) as to when
 *			 to update the channel doorbell. Should be smaller than
 *			 Maximum outstanding TREs. value. It is suggested to
 *			 configure this value to 2 * element size.
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
};

struct gsi_evt_stats {
	unsigned long completed;
};

struct gsi_evt_ctx {
	struct ipa_mem_buffer mem;
	uint16_t int_modt;
	bool exclusive;
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
	u32 phys_base;
	unsigned int irq;
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
	u32 max_ch;
	u32 max_ev;
	struct completion gen_ee_cmd_compl;
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

extern struct gsi_ctx *gsi_ctx;
void gsi_debugfs_init(void);
u16 gsi_find_idx_from_addr(struct gsi_ring_ctx *ctx, u64 addr);
struct gsi_ctx *gsi_init(struct platform_device *pdev, u32 ee);

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
u32 gsi_max_channel_get(void);

/**
 * gsi_register_device - Peripheral should call this function to
 * register itself with GSI before invoking any other APIs
 *
 * @Return 0 if successful or a negative error code otherwise.
 */
int gsi_register_device(void);

/**
 * gsi_deregister_device - Peripheral should call this function to
 * de-register itself with GSI
 *
 * @Return 0, or a negative errno
 */
int gsi_deregister_device(void);

/**
 * gsi_firmware_size_ok - Verify that a firmware image having the
 * given base address and size is suitable
 *
 * @Return true if values are OK, false otherise
 */
bool gsi_firmware_size_ok(u32 base, u32 size);

/**
 * gsi_firmware_enable - Enable firmware after loading
 */
void gsi_firmware_enable(void);

/**
 * gsi_alloc_evt_ring - Peripheral should call this function to
 * allocate an event ring once gsi_register_device() has been called
 *
 * This function can sleep
 *
 * @Return Client handle populated by GSI, or a negative errno
 */
long gsi_alloc_evt_ring(u32 size, u16 int_modt, bool excl);

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
 *	       gsi_alloc_evt_ring
 *
 * This function can sleep
 *
 * @Return gsi_status
 */
int gsi_reset_evt_ring(unsigned long evt_ring_hdl);

/**
 * gsi_alloc_channel - Peripheral should call this function to
 * allocate a channel once gsi_register_device() has been called
 *
 * @props:     Channel properties
 *
 * This function can sleep
 *
 * @Return Channel handle populated by GSI, opaque to client, or negative errno
 */
long gsi_alloc_channel(struct gsi_chan_props *props);

/**
 * gsi_write_channel_scratch - Peripheral should call this function to
 * write to the scratch area of the channel context
 *
 * @chan_hdl:  Client handle previously obtained from gsi_alloc_channel
 * @tlv_size:  Number of elements in channel TLV queue
 *
 * @Return gsi_status
 */
int gsi_write_channel_scratch(unsigned long chan_hdl, u32 tlv_size);

/**
 * gsi_start_channel - Peripheral should call this function to
 * start a channel i.e put into running state
 *
 * @chan_hdl:  Client handle previously obtained from
 *	       gsi_alloc_channel
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
 *	       gsi_alloc_channel
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
 *	       gsi_alloc_channel
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
 *	       gsi_alloc_channel
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
 *	       gsi_alloc_channel
 * @props:     where to copy properties to
 * @scr:       where to copy scratch info to
 *
 * @Return gsi_status
 */
int gsi_get_channel_cfg(unsigned long chan_hdl, struct gsi_chan_props *props);

/**
 * gsi_set_channel_cfg - This function applies the supplied config
 * to the specified channel
 *
 * ch_id and evt_ring_hdl of the channel cannot be changed after
 * gsi_alloc_channel
 *
 * @chan_hdl:  Client handle previously obtained from gsi_alloc_channel
 * @props:     the properties to apply
 *
 * @Return gsi_status
 */
int gsi_set_channel_cfg(unsigned long chan_hdl, struct gsi_chan_props *props);

/**
 * gsi_poll_channel - Peripheral should call this function to query for
 * completed transfer descriptors.
 *
 * @chan_hdl:  Client handle previously obtained from
 *	       gsi_alloc_channel
 *
 * @Return number of bytes transferred, or a negative error code
 */
int gsi_poll_channel(unsigned long chan_hdl);

/**
 * gsi_config_channel_mode - Peripheral should call this function
 * to configure the channel mode.
 *
 * @chan_hdl:  Client handle previously obtained from
 *	       gsi_alloc_channel
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
 *	       gsi_alloc_channel
 * @num_xfers: Number of transfer in the array @ xfer
 * @xfer:      Array of num_xfers transfer descriptors
 * @ring_db:   If true, tell HW about these queued xfers
 *	       If false, do not notify HW at this time
 *
 * @Return gsi_status
 */
int gsi_queue_xfer(unsigned long chan_hdl, u16 num_xfers,
		struct gsi_xfer_elem *xfer, bool ring_db);

/**
 * gsi_start_xfer - Peripheral should call this function to
 * inform HW about queued xfers
 *
 * @chan_hdl:  Client handle previously obtained from
 *	       gsi_alloc_channel
 *
 * @Return gsi_status
 */
int gsi_start_xfer(unsigned long chan_hdl);

/**
 * gsi_halt_channel_ee - Peripheral should call this function
 * to stop other EE's channel. This is usually used in SSR clean
 *
 * @chan_idx: Virtual channel index
 * @ee: EE
 * @code: [out] response code for operation

 * @Return gsi_status
 */
int gsi_halt_channel_ee(u32 chan_idx, unsigned int ee, int *code);

#endif
