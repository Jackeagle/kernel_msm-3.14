// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#define pr_fmt(fmt)	"ipahal %s:%d " fmt, __func__, __LINE__

#include <linux/debugfs.h>
#include "ipahal.h"
#include "ipahal_i.h"
#include "ipahal_reg_i.h"

/* Produce a contiguous bitmask with a positive number of low-order bits set. */
#define MASK(bits)	GENMASK((bits) - 1, 0)

static struct ipahal_context ipahal_ctx_struct;
struct ipahal_context *ipahal_ctx = &ipahal_ctx_struct;

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
ipahal_imm_cmd_pyld_alloc_common(u16 opcode, size_t pyld_size, gfp_t flags)
{
	struct ipahal_imm_cmd_pyld *pyld;

	ipa_debug_low("immediate command: %u\n", opcode);

	pyld = kzalloc(sizeof(*pyld) + pyld_size, flags);
	if (unlikely(!pyld)) {
		ipa_err("kzalloc err (opcode %hu pyld_size %zu)\n", opcode,
			pyld_size);
		return NULL;
	}
	pyld->opcode = opcode;
	pyld->len = pyld_size;

	return pyld;
}

static struct ipahal_imm_cmd_pyld *
ipahal_imm_cmd_pyld_alloc(u16 opcode, size_t pyld_size)
{
	return ipahal_imm_cmd_pyld_alloc_common(opcode, pyld_size, GFP_KERNEL);
}

static struct ipahal_imm_cmd_pyld *
ipahal_imm_cmd_pyld_alloc_atomic(u16 opcode, size_t pyld_size)
{
	return ipahal_imm_cmd_pyld_alloc_common(opcode, pyld_size, GFP_ATOMIC);
}

/* Returns true if the value provided is too big to be represented
 * in the given number of bits.  In this case, WARN_ON() is called,
 * and a message is printed using ipa_err().
 *
 * Returns false if the value is OK (not too big).
 */
static bool check_too_big(char *name, u64 value, u8 bits)
{
	if (!WARN_ON(value & ~MASK(bits)))
		return false;

	ipa_err("%s is bigger than %hhubit width 0x%llx\n", name, bits, value);

	return true;
}

struct ipahal_imm_cmd_pyld *
ipahal_dma_shared_mem_write_pyld(struct ipa_mem_buffer *mem, u32 offset)
{
	struct ipa_imm_cmd_hw_dma_shared_mem *data;
	struct ipahal_imm_cmd_pyld *pyld;
	u16 opcode;

	if (check_too_big("size", mem->size, 16))
		return NULL;
	if (check_too_big("offset", offset, 16))
		return NULL;

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
	data->system_addr = mem->phys_base;

	return pyld;
}

struct ipahal_imm_cmd_pyld *
ipahal_register_write_pyld(u32 offset, u32 value, u32 mask, bool clear)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_register_write *data;
	u16 opcode;

	if (check_too_big("offset", offset, 16))
		return NULL;

	opcode = IPA_IMM_CMD_REGISTER_WRITE;
	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->skip_pipeline_clear = 0;
	data->offset = offset;
	data->value = value;
	data->value_mask = mask;
	data->pipeline_clear_options = clear ? IPAHAL_FULL_PIPELINE_CLEAR
					     : IPAHAL_HPS_CLEAR;

	return pyld;
}

struct ipahal_imm_cmd_pyld *
ipahal_hdr_init_local_pyld(struct ipa_mem_buffer *mem, u32 offset)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_hdr_init_local *data;
	u16 opcode;

	if (check_too_big("size", mem->size, 12))
		return NULL;
	if (check_too_big("offset", offset, 16))
		return NULL;

	opcode = IPA_IMM_CMD_HDR_INIT_LOCAL;
	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->hdr_table_addr = mem->phys_base;
	data->size_hdr_table = mem->size;
	data->hdr_addr = offset;

	return pyld;
}

struct ipahal_imm_cmd_pyld *ipahal_ip_packet_init_pyld(u32 dest_pipe_idx)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_ip_packet_init *data;
	u16 opcode;

	if (check_too_big("dest_pipe_idx", dest_pipe_idx, 5))
		return NULL;

	opcode = IPA_IMM_CMD_IP_PACKET_INIT;
	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->destination_pipe_index = dest_pipe_idx;

	return pyld;
}

static struct ipahal_imm_cmd_pyld *
fltrt_init_common(u16 opcode, struct ipa_mem_buffer *mem, u32 hash_offset,
		  u32 nhash_offset)
{
	struct ipa_imm_cmd_hw_ip_fltrt_init *data;
	struct ipahal_imm_cmd_pyld *pyld;

	if (check_too_big("hash_rules_size", mem->size, 12))
		return false;
	if (check_too_big("hash_local_addr", hash_offset, 16))
		return false;
	if (check_too_big("nhash_rules_size", mem->size, 12))
		return false;
	if (check_too_big("nhash_local_addr", nhash_offset, 16))
		return false;

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	ipa_debug("putting hashable rules to phys 0x%x\n", hash_offset);
	ipa_debug("putting non-hashable rules to phys 0x%x\n", nhash_offset);

	data->hash_rules_addr = (u64)mem->phys_base;
	data->hash_rules_size = (u32)mem->size;
	data->hash_local_addr = hash_offset;
	data->nhash_rules_addr = (u64)mem->phys_base;
	data->nhash_rules_size = (u32)mem->size;
	data->nhash_local_addr = nhash_offset;

	return pyld;
}

struct ipahal_imm_cmd_pyld *
ipahal_ip_v4_routing_init_pyld(struct ipa_mem_buffer *mem, u32 hash_offset,
			       u32 nhash_offset)
{
	u16 opcode = IPA_IMM_CMD_IP_V4_ROUTING_INIT;

	ipa_debug("IPv4 routing\n");

	return fltrt_init_common(opcode, mem, hash_offset, nhash_offset);
}

struct ipahal_imm_cmd_pyld *
ipahal_ip_v6_routing_init_pyld(struct ipa_mem_buffer *mem, u32 hash_offset,
			       u32 nhash_offset)
{
	u16 opcode = IPA_IMM_CMD_IP_V6_ROUTING_INIT;

	ipa_debug("IPv6 routing\n");

	return fltrt_init_common(opcode, mem, hash_offset, nhash_offset);
}

struct ipahal_imm_cmd_pyld *
ipahal_ip_v4_filter_init_pyld(struct ipa_mem_buffer *mem, u32 hash_offset,
			      u32 nhash_offset)
{
	u16 opcode = IPA_IMM_CMD_IP_V4_FILTER_INIT;

	ipa_debug("IPv4 filtering\n");

	return fltrt_init_common(opcode, mem, hash_offset, nhash_offset);
}

struct ipahal_imm_cmd_pyld *
ipahal_ip_v6_filter_init_pyld(struct ipa_mem_buffer *mem, u32 hash_offset,
			      u32 nhash_offset)
{
	u16 opcode = IPA_IMM_CMD_IP_V6_FILTER_INIT;

	ipa_debug("IPv6 filtering\n");

	return fltrt_init_common(opcode, mem, hash_offset, nhash_offset);
}

/* NOTE:  this function is called in atomic state */
struct ipahal_imm_cmd_pyld *ipahal_ip_packet_tag_status_pyld(u64 tag)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_ip_packet_tag_status *data;
	u16 opcode = IPA_IMM_CMD_IP_PACKET_TAG_STATUS;

	if (check_too_big("tag", tag, 48))
		return NULL;

	pyld = ipahal_imm_cmd_pyld_alloc_atomic(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->tag = tag;

	return pyld;
}

struct ipahal_imm_cmd_pyld *
ipahal_dma_task_32b_addr_pyld(struct ipa_mem_buffer *mem)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_dma_task_32b_addr *data;
	u16 opcode = IPA_IMM_CMD_DMA_TASK_32B_ADDR;

	if (check_too_big("size", mem->size, 16))
		return NULL;
	if (check_too_big("packet_size", mem->size, 16))
		return NULL;

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
	data->addr1 = mem->phys_base;
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
	status->flt_miss = ~(hw_status->flt_rule_id) ? false : true;
	status->flt_rule_id = hw_status->flt_rule_id;
	status->rt_local = hw_status->rt_local;
	status->rt_hash = hw_status->rt_hash;
	status->ucp = hw_status->ucp;
	status->rt_tbl_idx = hw_status->rt_tbl_idx;
	status->rt_miss = ~(hw_status->rt_rule_id) ? false : true;
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

int ipahal_dma_alloc(struct ipa_mem_buffer *mem, u32 size, gfp_t gfp)
{
	dma_addr_t phys;
	void *cpu_addr;

	cpu_addr = dma_zalloc_coherent(ipahal_ctx->ipa_pdev, size, &phys, gfp);
	if (!cpu_addr) {
		ipa_err("failed to alloc DMA buff of size %u\n", size);
		return -ENOMEM;
	}

	mem->base = cpu_addr;
	mem->phys_base = phys;
	mem->size = size;

	return 0;
}

void ipahal_dma_free(struct ipa_mem_buffer *mem)
{
	dma_free_coherent(ipahal_ctx->ipa_pdev, mem->size, mem->base,
			  mem->phys_base);
	memset(mem, 0, sizeof(*mem));
}

void *ipahal_dma_phys_to_virt(struct ipa_mem_buffer *mem, dma_addr_t phys)
{
	return mem->base + (phys - mem->phys_base);
}

void ipahal_init(enum ipa_hw_version hw_version, void __iomem *base)
{
	ipa_debug("Entry - IPA HW TYPE=%d base=%p\n", hw_version, base);

	ipahal_ctx->base = base;
	/* ipahal_ctx->ipa_pdev must be set by a call to ipahal_dev_init() */
}

/* Assign the IPA HAL's device pointer.  Once it's assigned we can
 * initialize the empty table entry.
 */
int ipahal_dev_init(struct device *dev)
{
	int ret;

	ipa_debug("IPA HAL ipa_pdev=%p\n", dev);

	ipahal_ctx->ipa_pdev = dev;
	ret = ipahal_empty_fltrt_init();
	if (ret)
		ipahal_ctx->ipa_pdev = NULL;

	return ret;
}

void ipahal_dev_destroy(void)
{
	ipahal_empty_fltrt_destroy();
	ipahal_ctx->ipa_pdev = NULL;
}

void ipahal_destroy(void)
{
	ipa_debug("Entry\n");
}
