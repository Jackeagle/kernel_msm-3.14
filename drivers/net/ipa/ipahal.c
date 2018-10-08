// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#define pr_fmt(fmt)	"ipahal %s:%d " fmt, __func__, __LINE__

#include <linux/debugfs.h>
#include <asm/unaligned.h>

#include "ipa_dma.h"
#include "ipa_i.h"
#include "ipahal.h"

/* struct ipahal_context - HAL global context data
 *
 * @empty_fltrt_tbl: Empty table to be used at tables init.
 */
static struct ipahal_context {
	struct ipa_dma_mem empty_fltrt_tbl;
} ipahal_ctx_struct;
static struct ipahal_context *ipahal_ctx = &ipahal_ctx_struct;

/* Immediate commands; value is the opcode for IPA v3.5.1 hardware */
enum ipahal_imm_cmd {
	IPA_IMM_CMD_IP_V4_FILTER_INIT		= 3,
	IPA_IMM_CMD_IP_V6_FILTER_INIT		= 4,
	IPA_IMM_CMD_IP_V4_ROUTING_INIT		= 7,
	IPA_IMM_CMD_IP_V6_ROUTING_INIT		= 8,
	IPA_IMM_CMD_HDR_INIT_LOCAL		= 9,
	IPA_IMM_CMD_REGISTER_WRITE		= 12,
	IPA_IMM_CMD_IP_PACKET_INIT		= 16,
	IPA_IMM_CMD_DMA_TASK_32B_ADDR		= 17,
	IPA_IMM_CMD_DMA_SHARED_MEM		= 19,
	IPA_IMM_CMD_IP_PACKET_TAG_STATUS	= 20,
};

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
 */
struct ipa_imm_cmd_hw_hdr_init_local {
	u64 hdr_table_addr;
	u32 size_hdr_table	: 12,
	    hdr_addr		: 16,
	    rsvd		: 4;
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
 * @pkt_len: Pkt pyld len including hdr, include retained hdr if used. Does
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
 * @nat_type: Defines the type of the NAT operation:
 *	00: No NAT
 *	01: Source NAT
 *	10: Destination NAT
 *	11: Reserved
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

static struct ipahal_imm_cmd_pyld *
ipahal_imm_cmd_pyld_alloc(u16 opcode, size_t pyld_size)
{
	struct ipahal_imm_cmd_pyld *pyld;

	pyld = kzalloc(sizeof(*pyld) + pyld_size, GFP_KERNEL);
	if (pyld) {
		pyld->opcode = opcode;
		pyld->len = pyld_size;
	}

	return pyld;
}

struct ipahal_imm_cmd_pyld *
ipahal_dma_shared_mem_write_pyld(struct ipa_dma_mem *mem, u32 offset)
{
	struct ipa_imm_cmd_hw_dma_shared_mem *data;
	struct ipahal_imm_cmd_pyld *pyld;
	u16 opcode;

	ipa_assert(mem->size < 1 << 16);	/* size is 16 bits wide */
	ipa_assert(offset < 1 << 16);		/* local_addr is 16 bits wide */

	opcode = IPA_IMM_CMD_DMA_SHARED_MEM;
	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->size = mem->size;
	data->local_addr = offset;
	data->direction = 0;	/* 0 = write to IPA; 1 = read from IPA */
	data->skip_pipeline_clear = 0;
	data->pipeline_clear_options = IPAHAL_HPS_CLEAR;
	data->system_addr = mem->phys;

	return pyld;
}

struct ipahal_imm_cmd_pyld *
ipahal_hdr_init_local_pyld(struct ipa_dma_mem *mem, u32 offset)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_hdr_init_local *data;
	u16 opcode;

	ipa_assert(mem->size < 1 << 12);  /* size_hdr_table is 12 bits wide */
	ipa_assert(offset < 1 << 16);		/* hdr_addr is 16 bits wide */

	opcode = IPA_IMM_CMD_HDR_INIT_LOCAL;
	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->hdr_table_addr = mem->phys;
	data->size_hdr_table = mem->size;
	data->hdr_addr = offset;

	return pyld;
}

static struct ipahal_imm_cmd_pyld *
fltrt_init_common(u16 opcode, struct ipa_dma_mem *mem, u32 hash_offset,
		  u32 nhash_offset)
{
	struct ipa_imm_cmd_hw_ip_fltrt_init *data;
	struct ipahal_imm_cmd_pyld *pyld;

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	ipa_debug("putting hashable rules to phys 0x%x\n", hash_offset);
	ipa_debug("putting non-hashable rules to phys 0x%x\n", nhash_offset);

	data->hash_rules_addr = (u64)mem->phys;
	data->hash_rules_size = (u32)mem->size;
	data->hash_local_addr = hash_offset;
	data->nhash_rules_addr = (u64)mem->phys;
	data->nhash_rules_size = (u32)mem->size;
	data->nhash_local_addr = nhash_offset;

	return pyld;
}

struct ipahal_imm_cmd_pyld *
ipahal_ip_v4_routing_init_pyld(struct ipa_dma_mem *mem, u32 hash_offset,
			       u32 nhash_offset)
{
	u16 opcode = IPA_IMM_CMD_IP_V4_ROUTING_INIT;

	ipa_debug("IPv4 routing\n");

	return fltrt_init_common(opcode, mem, hash_offset, nhash_offset);
}

struct ipahal_imm_cmd_pyld *
ipahal_ip_v6_routing_init_pyld(struct ipa_dma_mem *mem, u32 hash_offset,
			       u32 nhash_offset)
{
	u16 opcode = IPA_IMM_CMD_IP_V6_ROUTING_INIT;

	ipa_debug("IPv6 routing\n");

	return fltrt_init_common(opcode, mem, hash_offset, nhash_offset);
}

struct ipahal_imm_cmd_pyld *
ipahal_ip_v4_filter_init_pyld(struct ipa_dma_mem *mem, u32 hash_offset,
			      u32 nhash_offset)
{
	u16 opcode = IPA_IMM_CMD_IP_V4_FILTER_INIT;

	ipa_debug("IPv4 filtering\n");

	return fltrt_init_common(opcode, mem, hash_offset, nhash_offset);
}

struct ipahal_imm_cmd_pyld *
ipahal_ip_v6_filter_init_pyld(struct ipa_dma_mem *mem, u32 hash_offset,
			      u32 nhash_offset)
{
	u16 opcode = IPA_IMM_CMD_IP_V6_FILTER_INIT;

	ipa_debug("IPv6 filtering\n");

	return fltrt_init_common(opcode, mem, hash_offset, nhash_offset);
}

struct ipahal_imm_cmd_pyld *
ipahal_dma_task_32b_addr_pyld(struct ipa_dma_mem *mem)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_dma_task_32b_addr *data;
	u16 opcode = IPA_IMM_CMD_DMA_TASK_32B_ADDR;

	/* size1 and packet_size are both 16 bits wide */
	ipa_assert(mem->size < 1 << 16);

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->cmplt = 0;
	data->eof = 0;
	data->flsh = 1;
	data->lock = 0;
	data->unlock = 0;
	data->size1 = mem->size;
	data->addr1 = mem->phys;
	data->packet_size = mem->size;

	return pyld;
}

/* IPA Packet Status Logic */

static bool status_opcode_valid(u8 status_opcode)
{
	switch ((enum ipahal_pkt_status_opcode)status_opcode) {
	case IPAHAL_PKT_STATUS_OPCODE_PACKET:
	case IPAHAL_PKT_STATUS_OPCODE_NEW_FRAG_RULE:
	case IPAHAL_PKT_STATUS_OPCODE_DROPPED_PACKET:
	case IPAHAL_PKT_STATUS_OPCODE_SUSPENDED_PACKET:
	case IPAHAL_PKT_STATUS_OPCODE_LOG:
	case IPAHAL_PKT_STATUS_OPCODE_DCMP:
	case IPAHAL_PKT_STATUS_OPCODE_PACKET_2ND_PASS:
		return true;
	default:
		return false;
	}
}

static bool nat_type_valid(u8 nat_type)
{
	switch (nat_type) {
	case IPAHAL_PKT_STATUS_NAT_NONE:
	case IPAHAL_PKT_STATUS_NAT_SRC:
	case IPAHAL_PKT_STATUS_NAT_DST:
		return true;
	default:
		return false;
	}
}

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

/* ipahal_pkt_status_parse() - Parse Packet Status payload to abstracted form
 * @unparsed_status: Pointer to H/W format of the packet status as read from H/W
 * @status: Pointer to pre-allocated buffer where the parsed info will be stored
 */
void ipahal_pkt_status_parse(const void *unparsed_status,
			     struct ipahal_pkt_status *status)
{
	const struct ipa_pkt_status_hw *hw_status = unparsed_status;
	u8 status_opcode = (u8)hw_status->status_opcode;
	u8 nat_type = (u8)hw_status->nat_type;
	enum ipahal_pkt_status_exception exception;
	bool is_ipv6;

	ipa_debug_low("Parse Status Packet\n");
	memset(status, 0, sizeof(*status));

	is_ipv6 = (hw_status->status_mask & 0x80) ? false : true;

	status->pkt_len = hw_status->pkt_len;
	status->endp_src_idx = hw_status->endp_src_idx;
	status->endp_dest_idx = hw_status->endp_dest_idx;
	status->metadata = hw_status->metadata;
	status->flt_local = hw_status->flt_local;
	status->flt_hash = hw_status->flt_hash;
	status->flt_global = hw_status->flt_hash;
	status->flt_ret_hdr = hw_status->flt_ret_hdr;
	status->flt_miss = ipahal_is_rule_miss_id(hw_status->flt_rule_id);
	status->flt_rule_id = hw_status->flt_rule_id;
	status->rt_local = hw_status->rt_local;
	status->rt_hash = hw_status->rt_hash;
	status->ucp = hw_status->ucp;
	status->rt_tbl_idx = hw_status->rt_tbl_idx;
	status->rt_miss = ipahal_is_rule_miss_id(hw_status->rt_rule_id);
	status->rt_rule_id = hw_status->rt_rule_id;
	status->nat_hit = hw_status->nat_hit;
	status->nat_entry_idx = hw_status->nat_entry_idx;
	status->tag_info = hw_status->tag_info;
	status->seq_num = hw_status->seq_num;
	status->time_of_day_ctr = hw_status->time_of_day_ctr;
	status->hdr_local = hw_status->hdr_local;
	status->hdr_offset = hw_status->hdr_offset;
	status->frag_hit = hw_status->frag_hit;
	status->frag_rule = hw_status->frag_rule;

	if (WARN_ON(!status_opcode_valid(status_opcode)))
		ipa_err("unsupported Status Opcode 0x%x\n", status_opcode);
	else
		status->status_opcode = status_opcode;

	if (WARN_ON(!nat_type_valid((nat_type))))
		ipa_err("unsupported Status NAT type 0x%x\n", nat_type);
	else
		status->nat_type = nat_type;

	exception = exception_map((u8)hw_status->exception, is_ipv6);
	if (WARN_ON(exception == IPAHAL_PKT_STATUS_EXCEPTION_MAX))
		ipa_err("unsupported Status Exception type 0x%x\n",
			hw_status->exception);
	else
		status->exception = exception;

	/* If hardware status values change we may have to re-map this */
	status->status_mask = hw_status->status_mask;
}

int ipahal_init(void)
{
	struct ipa_dma_mem *mem = &ipahal_ctx->empty_fltrt_tbl;

	/* Set up an empty filter/route table entry in system
	 * memory.  This will be used, for example, to delete a
	 * route safely.
	 */
	if (ipa_dma_alloc(mem, IPA_HW_TBL_WIDTH, GFP_KERNEL)) {
		ipa_err("error allocating empty filter/route table\n");
		return -ENOMEM;
	}

	return 0;
}

void ipahal_exit(void)
{
	ipa_dma_free(&ipahal_ctx->empty_fltrt_tbl);
}

/* Does the given rule ID represent a routing or filter rule miss?
 *
 * A rule miss is indicated as an all-1's value in the rt_rule_id
 * or flt_rule_id field of the ipahal_pkt_status structure.
 */
bool ipahal_is_rule_miss_id(u32 id)
{
	BUILD_BUG_ON(IPA_RULE_ID_BITS < 2);

	return id == (1U << IPA_RULE_ID_BITS) - 1;
}

/* ipahal_rt_generate_empty_img() - Generate empty route table header
 *
 * @route_count: number of table entries
 * @mem: mem object representing the header structure
 *
 * Allocates and fills an "empty" route table header having the given
 * number of entries.  Each entry in the table contains the DMA address
 * of a routing entry.
 *
 * This function initializes all entries to point at the preallocated
 * empty routing entry in system RAM.
 */
int ipahal_rt_generate_empty_img(u32 route_count, struct ipa_dma_mem *mem)
{
	u64 addr;
	int i;

	BUILD_BUG_ON(!IPA_HW_TBL_HDR_WIDTH);

	if (ipa_dma_alloc(mem, route_count * IPA_HW_TBL_HDR_WIDTH, GFP_KERNEL))
		return -ENOMEM;

	addr = (u64)ipahal_ctx->empty_fltrt_tbl.phys;
	for (i = 0; i < route_count; i++)
		put_unaligned(addr, mem->virt + i * IPA_HW_TBL_HDR_WIDTH);

	return 0;
}

/* ipahal_flt_generate_empty_img() - Generate empty filter table header
 *
 * @filter_bitmap: bitmap representing which endpoints support filtering
 * @mem: mem object representing the header structure
 *
 * Allocates and fills an "empty" filter table header based on the
 * given filter bitmap.
 *
 * The first slot in a filter table header is a 64-bit bitmap whose
 * set bits define which endpoints support filtering.  Following
 * this, each set bit in the mask has the DMA address of the filter
 * used for the corresponding endpoint.
 *
 * This function initializes all endpoints that support filtering to
 * point at the preallocated empty filter in system RAM.
 *
 * Note:  the (software) bitmap here uses bit 0 to represent
 * endpoint 0, bit 1 for endpoint 1, and so on.  This is different
 * from the hardware (which uses bit 1 to represent filter 0, etc.).
 */
int ipahal_flt_generate_empty_img(u64 filter_bitmap, struct ipa_dma_mem *mem)
{
	u32 filter_count = hweight32(filter_bitmap) + 1;
	u64 addr;
	int i;

	ipa_assert(filter_bitmap);

	if (ipa_dma_alloc(mem, filter_count * IPA_HW_TBL_HDR_WIDTH, GFP_KERNEL))
		return -ENOMEM;

	/* Save the endpoint bitmap in the first slot of the table.
	 * Convert it from software to hardware representation by
	 * shifting it left one position.
	 * XXX Does bit position 0 represent global?  At IPA3, global
	 * XXX configuration is possible but not used.
	 */
	put_unaligned(filter_bitmap << 1, mem->virt);

	/* Point every entry in the table at the empty filter */
	addr = (u64)ipahal_ctx->empty_fltrt_tbl.phys;
	for (i = 1; i < filter_count; i++)
		put_unaligned(addr, mem->virt + i * IPA_HW_TBL_HDR_WIDTH);

	return 0;
}

void ipahal_free_empty_img(struct ipa_dma_mem *mem)
{
	ipa_dma_free(mem);
}
