// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */

#include <linux/types.h>
#include <linux/slab.h>

#include "ipahal.h"
#include "ipa_i.h"	/* ipa_err() */

/**
 * DOC:  IPA Immediate Commands
 *
 * The APPS_CMD_PROD channel is used to issue immediate commands to
 * the IPA.  An immediate command is generally used to request the
 * IPA do something other than data transfer.
 *
 * An immediate command is represented by a GSI transfer element.
 * Each immediate command has a well-defined format, with a known
 * length.  The transfer element's length field can therefore be
 * used to hold a command's opcode.  The "payload" of an immediate
 * command contains additional information required for the command.
 * It resides in DRAM and is referred to using the DMA memory data
 * pointer (the same one used to refer to the data in a "normal"
 * transfer).
 *
 * Immediate commands are issued to the IPA through the APPS_CMD_PROD
 * channel using the normal GSI queueing mechanism.  And each command's
 * completion is handled using the normal GSI transfer completion
 * mechanisms.
 */

/* enum ipa_pipeline_clear_option - Values for pipeline clear waiting options
 * @IPAHAL_HPS_CLEAR: Wait for HPS clear. All queues except high priority queue
 *  shall not be serviced until HPS is clear of packets or immediate commands.
 *  The high priority Rx queue / Q6ZIP group shall still be serviced normally.
 *
 * @IPAHAL_SRC_GRP_CLEAR: Wait for originating source group to be clear
 *  (for no packet contexts allocated to the originating source group).
 *  The source group / Rx queue shall not be serviced until all previously
 *  allocated packet contexts are released. All other source groups/queues shall
 *  be serviced normally.
 *
 * @IPAHAL_FULL_PIPELINE_CLEAR: Wait for full pipeline to be clear.
 *  All groups / Rx queues shall not be serviced until IPA pipeline is fully
 *  clear. This should be used for debug only.
 *
 *  The values assigned to these are assumed by the REGISTER_WRITE
 *  (struct ipa_imm_cmd_hw_register_write) and the DMA_SHARED_MEM
 *  (struct ipa_imm_cmd_hw_dma_shared_mem) immediate commands for
 *  IPA version 3 hardware.  They are also used to modify the opcode
 *  used to implement these commands for IPA version 4 hardware.
 */
enum ipahal_pipeline_clear_option {
	IPAHAL_HPS_CLEAR		= 0,
	IPAHAL_SRC_GRP_CLEAR		= 1,
	IPAHAL_FULL_PIPELINE_CLEAR	= 2,
};

/* Immediate commands H/W structures */

/* struct ipa_imm_cmd_hw_ip_fltrt_init - IP_V*_FILTER_INIT/IP_V*_ROUTING_INIT
 * command payload in H/W format.
 * Inits IPv4/v6 routing or filter block.
 * @hash_rules_addr: Addr in system mem where hashable flt/rt rules starts
 * @hash_rules_size: Size in bytes of the hashable tbl to cpy to local mem
 * @hash_local_addr: Addr in shared mem where hashable flt/rt tbl should
 *  be copied to
 * @nhash_rules_size: Size in bytes of the non-hashable tbl to cpy to local mem
 * @nhash_local_addr: Addr in shared mem where non-hashable flt/rt tbl should
 *  be copied to
 * @rsvd: reserved
 * @nhash_rules_addr: Addr in sys mem where non-hashable flt/rt tbl starts
 */
struct ipa_imm_cmd_hw_ip_fltrt_init {
	u64 hash_rules_addr;
	u64 hash_rules_size	: 12,
	    hash_local_addr	: 16,
	    nhash_rules_size	: 12,
	    nhash_local_addr	: 16,
	    rsvd		: 8;
	u64 nhash_rules_addr;
};

/* struct ipa_imm_cmd_hw_hdr_init_local - HDR_INIT_LOCAL command payload
 *  in H/W format.
 * Inits hdr table within local mem with the hdrs and their length.
 * @hdr_table_addr: Word address in sys mem where the table starts (SRC)
 * @size_hdr_table: Size of the above (in bytes)
 * @hdr_addr: header address in IPA sram (used as DST for memory copy)
 * @rsvd: reserved
 * @pad: explicit pad (present in the structure even if not defined)
 */
struct ipa_imm_cmd_hw_hdr_init_local {
	u64 hdr_table_addr;
	u32 size_hdr_table	: 12,
	    hdr_addr		: 16,
	    rsvd		: 4;
	u32 pad;
};

/* struct ipa_imm_cmd_hw_dma_shared_mem - DMA_SHARED_MEM command payload
 *  in H/W format.
 * Perform mem copy into or out of the SW area of IPA local mem
 * @sw_rsvd: Ignored by H/W. My be used by S/W
 * @size: Size in bytes of data to copy. Expected size is up to 2K bytes
 * @local_addr: Address in IPA local memory
 * @direction: Read or write?
 *	0: IPA write, Write to local address from system address
 *	1: IPA read, Read from local address to system address
 * @skip_pipeline_clear: 0 to wait until IPA pipeline is clear. 1 don't wait
 * @pipeline_clear_options: options for pipeline to clear
 *	0: HPS - no pkt inside HPS (not grp specific)
 *	1: source group - The immediate cmd src grp does npt use any pkt ctxs
 *	2: Wait until no pkt reside inside IPA pipeline
 *	3: reserved
 * @rsvd: reserved - should be set to zero
 * @system_addr: Address in system memory
 */
struct ipa_imm_cmd_hw_dma_shared_mem {
	u16 sw_rsvd;
	u16 size;
	u16 local_addr;
	u16 direction			: 1,
	    skip_pipeline_clear		: 1,
	    pipeline_clear_options	: 2,
	    rsvd			: 12;
	u64 system_addr;
};

/* struct ipa_imm_cmd_hw_dma_task_32b_addr -
 *	IPA_DMA_TASK_32B_ADDR command payload in H/W format.
 * Used by clients using 32bit addresses. Used to perform DMA operation on
 *  multiple descriptors.
 *  The Opcode is dynamic, where it holds the number of buffer to process
 * @sw_rsvd: Ignored by H/W. My be used by S/W
 * @cmplt: Complete flag: When asserted IPA will interrupt SW when the entire
 *  DMA related data was completely xfered to its destination.
 * @eof: Enf Of Frame flag: When asserted IPA will assert the EOT to the
 *  dest client. This is used used for aggr sequence
 * @flsh: Flush flag: When asserted, pkt will go through the IPA blocks but
 *  will not be xfered to dest client but rather will be discarded
 * @lock: Lock endpoint flag: When asserted, IPA will stop processing
 *  descriptors from other EPs in the same src grp (RX queue)
 * @unlock: Unlock endpoint flag: When asserted, IPA will stop exclusively
 *  servicing current EP out of the src EPs of the grp (RX queue)
 * @size1: Size of buffer1 data
 * @addr1: Pointer to buffer1 data
 * @packet_size: Total packet size. If a pkt send using multiple DMA_TASKs,
 *  only the first one needs to have this field set. It will be ignored
 *  in subsequent DMA_TASKs until the packet ends (EOT). First DMA_TASK
 *  must contain this field (2 or more buffers) or EOT.
 */
struct ipa_imm_cmd_hw_dma_task_32b_addr {
	u16 sw_rsvd	: 11,
	    cmplt	: 1,
	    eof		: 1,
	    flsh	: 1,
	    lock	: 1,
	    unlock	: 1;
	u16 size1;
	u32 addr1;
	u16 packet_size;
	u16 rsvd1;
	u32 rsvd2;
};

/* IPA Status packet H/W structures and info */

/* struct ipa_status_pkt_hw - IPA status packet payload in H/W format.
 *  This structure describes the status packet H/W structure for the
 *   following statuses: IPA_STATUS_PACKET, IPA_STATUS_DROPPED_PACKET,
 *   IPA_STATUS_SUSPENDED_PACKET.
 *  Other statuses types has different status packet structure.
 * @status_opcode: The Type of the status (Opcode).
 * @exception: (not bitmask) - the first exception that took place.
 *  In case of exception, src endp and pkt len are always valid.
 * @status_mask: Bit mask specifying on which H/W blocks the pkt was processed.
 * @pkt_len: Pkt payload len including hdr, include retained hdr if used. Does
 *  not include padding or checksum trailer len.
 * @endp_src_idx: Source end point index.
 * @rsvd1: reserved
 * @endp_dest_idx: Destination end point index.
 *  Not valid in case of exception
 * @rsvd2: reserved
 * @metadata: meta data value used by packet
 * @flt_local: Filter table location flag: Does matching flt rule belongs to
 *  flt tbl that resides in lcl memory? (if not, then system mem)
 * @flt_hash: Filter hash hit flag: Does matching flt rule was in hash tbl?
 * @flt_global: Global filter rule flag: Does matching flt rule belongs to
 *  the global flt tbl? (if not, then the per endp tables)
 * @flt_ret_hdr: Retain header in filter rule flag: Does matching flt rule
 *  specifies to retain header?
 * @flt_rule_id: The ID of the matching filter rule. This info can be combined
 *  with endp_src_idx to locate the exact rule. ID=0x3ff reserved to specify
 *  flt miss. In case of miss, all flt info to be ignored
 * @rt_local: Route table location flag: Does matching rt rule belongs to
 *  rt tbl that resides in lcl memory? (if not, then system mem)
 * @rt_hash: Route hash hit flag: Does matching rt rule was in hash tbl?
 * @ucp: UC Processing flag.
 * @rt_tbl_idx: Index of rt tbl that contains the rule on which was a match
 * @rt_rule_id: The ID of the matching rt rule. This info can be combined
 *  with rt_tbl_idx to locate the exact rule. ID=0x3ff reserved to specify
 *  rt miss. In case of miss, all rt info to be ignored
 * @nat_hit: NAT hit flag: Was their NAT hit?
 * @nat_entry_idx: Index of the NAT entry used of NAT processing
 * @nat_type: Defines the type of the NAT operation (ignored for now)
 * @tag_info: S/W defined value provided via immediate command
 * @seq_num: Per source endp unique packet sequence number
 * @time_of_day_ctr: running counter from IPA clock
 * @hdr_local: Header table location flag: In header insertion, was the header
 *  taken from the table resides in local memory? (If no, then system mem)
 * @hdr_offset: Offset of used header in the header table
 * @frag_hit: Frag hit flag: Was their frag rule hit in H/W frag table?
 * @frag_rule: Frag rule index in H/W frag table in case of frag hit
 * @hw_specific: H/W specific reserved value
 */
#define IPA_RULE_ID_BITS	10	/* See ipahal_is_rule_miss_id() */
struct ipa_pkt_status_hw {
	u8  status_opcode;
	u8  exception;
	u16 status_mask;
	u16 pkt_len;
	u8  endp_src_idx	: 5,
	    rsvd1		: 3;
	u8  endp_dest_idx	: 5,
	    rsvd2		: 3;
	u32 metadata;
	u16 flt_local		: 1,
	    flt_hash		: 1,
	    flt_global		: 1,
	    flt_ret_hdr		: 1,
	    flt_rule_id		: IPA_RULE_ID_BITS,
	    rt_local		: 1,
	    rt_hash		: 1;
	u16 ucp			: 1,
	    rt_tbl_idx		: 5,
	    rt_rule_id		: IPA_RULE_ID_BITS;
	u64 nat_hit		: 1,
	    nat_entry_idx	: 13,
	    nat_type		: 2,
	    tag_info		: 48;
	u32 seq_num		: 8,
	    time_of_day_ctr	: 24;
	u16 hdr_local		: 1,
	    hdr_offset		: 10,
	    frag_hit		: 1,
	    frag_rule		: 4;
	u16 hw_specific;
};

void *ipahal_dma_shared_mem_write_pyld(dma_addr_t phys, size_t size, u32 offset)
{
	struct ipa_imm_cmd_hw_dma_shared_mem *data;

	ipa_assert(size < 1 << 16);	/* size is 16 bits wide */
	ipa_assert(offset < 1 << 16);	/* local_addr is 16 bits wide */

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return NULL;

	data->size = size;
	data->local_addr = offset;
	data->direction = 0;	/* 0 = write to IPA; 1 = read from IPA */
	data->skip_pipeline_clear = 0;
	data->pipeline_clear_options = IPAHAL_HPS_CLEAR;
	data->system_addr = phys;

	return data;
}

void *ipahal_hdr_init_local_pyld(dma_addr_t phys, size_t size, u32 offset)
{
	struct ipa_imm_cmd_hw_hdr_init_local *data;

	ipa_assert(size < 1 << 12);	/* size_hdr_table is 12 bits wide */
	ipa_assert(offset < 1 << 16);	/* hdr_addr is 16 bits wide */

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return NULL;

	data->hdr_table_addr = phys;
	data->size_hdr_table = size;
	data->hdr_addr = offset;

	return data;
}

void *ipa_imm_ip_fltrt_init_pyld(dma_addr_t phys, size_t size, u32 hash_offset,
				 u32 nhash_offset)
{
	struct ipa_imm_cmd_hw_ip_fltrt_init *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return NULL;

	data->hash_rules_addr = (u64)phys;
	data->hash_rules_size = (u32)size;
	data->hash_local_addr = hash_offset;
	data->nhash_rules_addr = (u64)phys;
	data->nhash_rules_size = (u32)size;
	data->nhash_local_addr = nhash_offset;

	return data;
}

void *ipahal_dma_task_32b_addr_pyld(dma_addr_t phys, size_t size)
{
	struct ipa_imm_cmd_hw_dma_task_32b_addr *data;

	/* size1 and packet_size are both 16 bits wide */
	ipa_assert(size < 1 << 16);

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return NULL;

	data->cmplt = 0;
	data->eof = 0;
	data->flsh = 1;
	data->lock = 0;
	data->unlock = 0;
	data->size1 = size;
	data->addr1 = phys;
	data->packet_size = size;

	return data;
}

void ipahal_payload_free(void *payload)
{
	kfree(payload);
}

/* IPA Packet Status Logic */

/* Maps an exception type returned in a ipa_pkt_status_hw structure
 * to the ipahal_pkt_status_exception value that represents it in
 * the exception field of a ipahal_pkt_status structure.  Returns
 * IPAHAL_PKT_STATUS_EXCEPTION_MAX for an unrecognized value.
 */
static enum ipahal_pkt_status_exception
exception_map(u8 exception, bool is_ipv6)
{
	switch (exception) {
	case 0x00:	return IPAHAL_PKT_STATUS_EXCEPTION_NONE;
	case 0x01:	return IPAHAL_PKT_STATUS_EXCEPTION_DEAGGR;
	case 0x04:	return IPAHAL_PKT_STATUS_EXCEPTION_IPTYPE;
	case 0x08:	return IPAHAL_PKT_STATUS_EXCEPTION_PACKET_LENGTH;
	case 0x10:	return IPAHAL_PKT_STATUS_EXCEPTION_FRAG_RULE_MISS;
	case 0x20:	return IPAHAL_PKT_STATUS_EXCEPTION_SW_FILT;
	case 0x40:	return is_ipv6 ? IPAHAL_PKT_STATUS_EXCEPTION_IPV6CT
				       : IPAHAL_PKT_STATUS_EXCEPTION_NAT;
	default:	return IPAHAL_PKT_STATUS_EXCEPTION_MAX;
	}
}

/* ipahal_pkt_status_get_size() - Get H/W size of packet status */
u32 ipahal_pkt_status_get_size(void)
{
	return sizeof(struct ipa_pkt_status_hw);
}

size_t
ipahal_pkt_status_parse(struct sk_buff *skb, struct ipahal_pkt_status *status)
{
	const struct ipa_pkt_status_hw *hw_status;
	bool is_ipv6;

	if (skb->len < sizeof(*hw_status))
		return 0;

	hw_status = (struct ipa_pkt_status_hw *)skb->data;

	status->status_opcode =
			(enum ipahal_pkt_status_opcode)hw_status->status_opcode;
	is_ipv6 = hw_status->status_mask & BIT(7) ? false : true;
	/* If hardware status values change we may have to re-map this */
	status->status_mask =
			(enum ipahal_pkt_status_mask)hw_status->status_mask;
	status->exception = exception_map(hw_status->exception, is_ipv6);
	status->pkt_len = hw_status->pkt_len;
	status->endp_src_idx = hw_status->endp_src_idx;
	status->endp_dest_idx = hw_status->endp_dest_idx;
	status->metadata = hw_status->metadata;
	status->rt_miss = ipahal_is_rule_miss_id(hw_status->rt_rule_id);

	return sizeof(*hw_status);
}

/* Does the given rule ID represent a routing or filter rule miss?
 * A rule miss is indicated as an all-1's value in the rt_rule_id
 * or flt_rule_id field of the ipahal_pkt_status structure.
 */
bool ipahal_is_rule_miss_id(u32 id)
{
	BUILD_BUG_ON(IPA_RULE_ID_BITS < 2);

	return id == (1U << IPA_RULE_ID_BITS) - 1;
}
