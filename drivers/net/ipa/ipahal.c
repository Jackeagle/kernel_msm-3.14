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
#include "ipahal_i.h"

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

static struct ipahal_imm_cmd_pyld *
ipahal_imm_cmd_pyld_alloc(u16 opcode, size_t pyld_size)
{
	struct ipahal_imm_cmd_pyld *pyld;

	ipa_debug_low("immediate command: %u\n", opcode);

	pyld = kzalloc(sizeof(*pyld) + pyld_size, GFP_KERNEL);
	if (unlikely(!pyld)) {
		ipa_err("kzalloc err (opcode %hu pyld_size %zu)\n", opcode,
			pyld_size);
		return NULL;
	}
	pyld->opcode = opcode;
	pyld->len = pyld_size;

	return pyld;
}

/* Returns true if the value provided is too big to be represented
 * in the given number of bits.  In this case, WARN_ON() is called,
 * and a message is printed using ipa_err().
 *
 * Returns false if the value is OK (not too big).
 */
static bool check_too_big(char *name, u64 value, u8 bits)
{
	if (!WARN_ON(value & ~GENMASK((bits) - 1, 0)))
		return false;

	ipa_err("%s is bigger than %hhubit width 0x%llx\n", name, bits, value);

	return true;
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

	if (check_too_big("hash_rules_size", mem->size, 12))
		return NULL;
	if (check_too_big("hash_local_addr", hash_offset, 16))
		return NULL;
	if (check_too_big("nhash_rules_size", mem->size, 12))
		return NULL;
	if (check_too_big("nhash_local_addr", nhash_offset, 16))
		return NULL;

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
