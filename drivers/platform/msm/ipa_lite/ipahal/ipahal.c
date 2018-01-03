/* Copyright (c) 2016-2017, The Linux Foundation. All rights reserved.
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

#define pr_fmt(fmt)	"ipahal %s:%d " fmt, __func__, __LINE__

#include <linux/debugfs.h>
#include "ipahal.h"
#include "ipahal_i.h"
#include "ipahal_reg_i.h"

/* Produce a contiguous bitmask with a positive number of low-order bits set. */
#define MASK(bits)	GENMASK((bits) - 1, 0)

struct ipahal_context *ipahal_ctx;

static const char *ipahal_pkt_status_exception_to_str[] = {
	__stringify(IPAHAL_PKT_STATUS_EXCEPTION_NONE),
	__stringify(IPAHAL_PKT_STATUS_EXCEPTION_DEAGGR),
	__stringify(IPAHAL_PKT_STATUS_EXCEPTION_IPTYPE),
	__stringify(IPAHAL_PKT_STATUS_EXCEPTION_PACKET_LENGTH),
	__stringify(IPAHAL_PKT_STATUS_EXCEPTION_PACKET_THRESHOLD),
	__stringify(IPAHAL_PKT_STATUS_EXCEPTION_FRAG_RULE_MISS),
	__stringify(IPAHAL_PKT_STATUS_EXCEPTION_SW_FILT),
	__stringify(IPAHAL_PKT_STATUS_EXCEPTION_NAT),
	__stringify(IPAHAL_PKT_STATUS_EXCEPTION_IPV6CT),
};

static struct ipahal_imm_cmd_pyld *
ipahal_imm_cmd_pyld_alloc_common(u16 opcode, size_t pyld_size, gfp_t flags)
{
	struct ipahal_imm_cmd_pyld *pyld;

	pyld = kzalloc(sizeof(*pyld) + pyld_size, flags);
	if (unlikely(!pyld)) {
		ipa_err("kzalloc err (opcode %hu pyld_size %zu)\n",
				opcode, pyld_size);
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

static struct ipahal_imm_cmd_pyld *
ipa_imm_cmd_construct_dma_task_32b_addr(u16 opcode, const void *params)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_dma_task_32b_addr *data;
	const struct ipahal_imm_cmd_dma_task_32b_addr *dma_params = params;

	if (WARN_ON(dma_params->size1 & ~MASK(16))) {
		ipa_err("Size1 is bigger than 16bit width 0x%x\n",
			dma_params->size1);
		return NULL;
	}
	if (WARN_ON(dma_params->packet_size & ~MASK(16))) {
		ipa_err("Pkt size is bigger than 16bit width 0x%x\n",
			dma_params->packet_size);
		return NULL;
	}

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	pyld->opcode += 1 << 8;	/* Currently supports only one packet */

	data->cmplt = dma_params->cmplt ? 1 : 0;
	data->eof = dma_params->eof ? 1 : 0;
	data->flsh = dma_params->flsh ? 1 : 0;
	data->lock = dma_params->lock ? 1 : 0;
	data->unlock = dma_params->unlock ? 1 : 0;
	data->size1 = dma_params->size1;
	data->addr1 = dma_params->addr1;
	data->packet_size = dma_params->packet_size;

	return pyld;
}

/* NOTE:  this function is called in atomic state */
static struct ipahal_imm_cmd_pyld *
ipa_imm_cmd_construct_ip_packet_tag_status(u16 opcode, const void *params)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_ip_packet_tag_status *data;
	const struct ipahal_imm_cmd_ip_packet_tag_status *tag_params = params;

	if (WARN_ON(tag_params->tag & ~MASK(48))) {
		ipa_err("tag is bigger than 48bit width 0x%llx\n",
			tag_params->tag);
		return NULL;
	}

	pyld = ipahal_imm_cmd_pyld_alloc_atomic(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->tag = tag_params->tag;

	return pyld;
}

static bool pipeline_clear_options_bad(u16 option)
{
	switch (option) {
	case IPAHAL_HPS_CLEAR:
	case IPAHAL_SRC_GRP_CLEAR:
	case IPAHAL_FULL_PIPELINE_CLEAR:
		return false;
	default:
		break;
	}

	ipa_err("unsupported pipeline clear option %hu\n", option);

	return WARN_ON(true);
}

static struct ipahal_imm_cmd_pyld *
ipa_imm_cmd_construct_dma_shared_mem(u16 opcode, const void *params)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_dma_shared_mem *data;
	const struct ipahal_imm_cmd_dma_shared_mem *mem_params = params;
	u16 pipeline_clear_options = (u16)mem_params->pipeline_clear_options;

	if (WARN_ON(mem_params->size & ~MASK(16))) {
		ipa_err("Size is bigger than 16bit width 0x%x\n",
			mem_params->size);
		return NULL;
	}
	if (WARN_ON(mem_params->local_addr & ~MASK(16))) {
		ipa_err("Local addr is bigger than 16bit width 0x%x\n",
			mem_params->local_addr);
		return NULL;
	}
	if (pipeline_clear_options_bad(pipeline_clear_options))
		return NULL;

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->direction = mem_params->is_read ? 1 : 0;
	data->size = mem_params->size;
	data->local_addr = mem_params->local_addr;
	data->system_addr = mem_params->system_addr;
	data->skip_pipeline_clear = mem_params->skip_pipeline_clear ? 1 : 0;
	data->pipeline_clear_options = pipeline_clear_options;

	return pyld;
}

static struct ipahal_imm_cmd_pyld *
ipa_imm_cmd_construct_dma_shared_mem_v_4_0(u16 opcode, const void *params)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_dma_shared_mem_v_4_0 *data;
	const struct ipahal_imm_cmd_dma_shared_mem *mem_params = params;
	u16 pipeline_clear_options = (u16)mem_params->pipeline_clear_options;

	if (WARN_ON(mem_params->size & ~MASK(16))) {
		ipa_err("Size is bigger than 16bit width 0x%x\n",
			mem_params->size);
		return NULL;
	}
	if (WARN_ON(mem_params->local_addr & ~MASK(16))) {
		ipa_err("Local addr is bigger than 16bit width 0x%x\n",
			mem_params->local_addr);
		return NULL;
	}
	if (pipeline_clear_options_bad(pipeline_clear_options))
		return NULL;

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	pyld->opcode |= (mem_params->skip_pipeline_clear ? 1 : 0) << 8;
	pyld->opcode |= pipeline_clear_options << 9;

	data->direction = mem_params->is_read ? 1 : 0;
	data->clear_after_read = mem_params->clear_after_read;
	data->size = mem_params->size;
	data->local_addr = mem_params->local_addr;
	data->system_addr = mem_params->system_addr;

	return pyld;
}

static struct ipahal_imm_cmd_pyld *
ipa_imm_cmd_construct_register_write(u16 opcode, const void *params)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_register_write *data;
	const struct ipahal_imm_cmd_register_write *regwrt_params = params;
	u16 pipeline_clear_options = (u16)regwrt_params->pipeline_clear_options;

	if (WARN_ON(regwrt_params->offset & ~MASK(16))) {
		ipa_err("Offset is bigger than 16bit width 0x%x\n",
			regwrt_params->offset);
		return NULL;
	}
	if (pipeline_clear_options_bad(pipeline_clear_options))
		return NULL;

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->offset = regwrt_params->offset;
	data->value = regwrt_params->value;
	data->value_mask = regwrt_params->value_mask;
	data->skip_pipeline_clear = regwrt_params->skip_pipeline_clear ? 1 : 0;
	data->pipeline_clear_options = pipeline_clear_options;

	return pyld;
}

static struct ipahal_imm_cmd_pyld *
ipa_imm_cmd_construct_register_write_v_4_0(u16 opcode, const void *params)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_register_write_v_4_0 *data;
	const struct ipahal_imm_cmd_register_write *regwrt_params = params;
	u16 pipeline_clear_options = (u16)regwrt_params->pipeline_clear_options;

	if (WARN_ON(regwrt_params->offset & ~MASK(16))) {
		ipa_err("Offset is bigger than 16bit width 0x%x\n",
			regwrt_params->offset);
		return NULL;
	}
	if (pipeline_clear_options_bad(pipeline_clear_options))
		return NULL;

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	if (regwrt_params->skip_pipeline_clear)
		pyld->opcode |= BIT(8);
	pyld->opcode |= pipeline_clear_options << 9;

	data->offset = regwrt_params->offset;
	data->offset_high = regwrt_params->offset >> 16;
	data->value = regwrt_params->value;
	data->value_mask = regwrt_params->value_mask;

	return pyld;
}

static struct ipahal_imm_cmd_pyld *
ipa_imm_cmd_construct_ip_packet_init(u16 opcode, const void *params)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_ip_packet_init *data;
	const struct ipahal_imm_cmd_ip_packet_init *pktinit_params = params;

	if (WARN_ON(pktinit_params->destination_pipe_index & ~MASK(5))) {
		ipa_err("Dst pipe idx is bigger than 5bit width 0x%x\n",
			pktinit_params->destination_pipe_index);
		return NULL;
	}

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->destination_pipe_index = pktinit_params->destination_pipe_index;

	return pyld;
}

static struct ipahal_imm_cmd_pyld *
ipa_imm_cmd_construct_nat_dma(u16 opcode, const void *params)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_nat_dma *data;
	const struct ipahal_imm_cmd_nat_dma *nat_params = params;

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (unlikely(!pyld))
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->table_index = nat_params->table_index;
	data->base_addr = nat_params->base_addr;
	data->offset = nat_params->offset;
	data->data = nat_params->data;

	return pyld;
}

static struct ipahal_imm_cmd_pyld *
ipa_imm_cmd_construct_table_dma_ipav4(u16 opcode, const void *params)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_table_dma_ipav4 *data;
	const struct ipahal_imm_cmd_table_dma *nat_params = params;

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->table_index = nat_params->table_index;
	data->base_addr = nat_params->base_addr;
	data->offset = nat_params->offset;
	data->data = nat_params->data;

	return pyld;
}

static struct ipahal_imm_cmd_pyld *
ipa_imm_cmd_construct_hdr_init_system(u16 opcode, const void *params)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_hdr_init_system *data;
	const struct ipahal_imm_cmd_hdr_init_system *syshdr_params = params;

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->hdr_table_addr = syshdr_params->hdr_table_addr;

	return pyld;
}

static struct ipahal_imm_cmd_pyld *
ipa_imm_cmd_construct_hdr_init_local(u16 opcode, const void *params)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_hdr_init_local *data;
	const struct ipahal_imm_cmd_hdr_init_local *lclhdr_params = params;

	if (WARN_ON(lclhdr_params->size_hdr_table & ~MASK(12))) {
		ipa_err("Hdr tble size is bigger than 12bit width 0x%x\n",
			lclhdr_params->size_hdr_table);
		return NULL;
	}

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->hdr_table_addr = lclhdr_params->hdr_table_addr;
	data->size_hdr_table = lclhdr_params->size_hdr_table;
	data->hdr_addr = lclhdr_params->hdr_addr;

	return pyld;
}

static struct ipahal_imm_cmd_pyld *
ipa_imm_cmd_construct_ip_v6_routing_init(u16 opcode, const void *params)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_ip_v6_routing_init *data;
	const struct ipahal_imm_cmd_ip_v6_routing_init *rt6_params = params;

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->hash_rules_addr = rt6_params->hash_rules_addr;
	data->hash_rules_size = rt6_params->hash_rules_size;
	data->hash_local_addr = rt6_params->hash_local_addr;
	data->nhash_rules_addr = rt6_params->nhash_rules_addr;
	data->nhash_rules_size = rt6_params->nhash_rules_size;
	data->nhash_local_addr = rt6_params->nhash_local_addr;

	return pyld;
}

static struct ipahal_imm_cmd_pyld *
ipa_imm_cmd_construct_ip_v4_routing_init(u16 opcode, const void *params)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_ip_v4_routing_init *data;
	const struct ipahal_imm_cmd_ip_v4_routing_init *rt4_params = params;

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->hash_rules_addr = rt4_params->hash_rules_addr;
	data->hash_rules_size = rt4_params->hash_rules_size;
	data->hash_local_addr = rt4_params->hash_local_addr;
	data->nhash_rules_addr = rt4_params->nhash_rules_addr;
	data->nhash_rules_size = rt4_params->nhash_rules_size;
	data->nhash_local_addr = rt4_params->nhash_local_addr;

	return pyld;
}

static struct ipahal_imm_cmd_pyld *
ipa_imm_cmd_construct_ip_v4_nat_init(u16 opcode, const void *params)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_ip_v4_nat_init *data;
	const struct ipahal_imm_cmd_ip_v4_nat_init *nat4_params = params;

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->ipv4_rules_addr = nat4_params->ipv4_rules_addr;
	data->ipv4_expansion_rules_addr =
		nat4_params->ipv4_expansion_rules_addr;
	data->index_table_addr = nat4_params->index_table_addr;
	data->index_table_expansion_addr =
		nat4_params->index_table_expansion_addr;
	data->table_index = nat4_params->table_index;
	data->ipv4_rules_addr_type =
		nat4_params->ipv4_rules_addr_shared ? 1 : 0;
	data->ipv4_expansion_rules_addr_type =
		nat4_params->ipv4_expansion_rules_addr_shared ? 1 : 0;
	data->index_table_addr_type =
		nat4_params->index_table_addr_shared ? 1 : 0;
	data->index_table_expansion_addr_type =
		nat4_params->index_table_expansion_addr_shared ? 1 : 0;
	data->size_base_tables = nat4_params->size_base_tables;
	data->size_expansion_tables = nat4_params->size_expansion_tables;
	data->public_ip_addr = nat4_params->public_ip_addr;

	return pyld;
}

static struct ipahal_imm_cmd_pyld *
ipa_imm_cmd_construct_ip_v6_filter_init(u16 opcode, const void *params)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_ip_v6_filter_init *data;
	const struct ipahal_imm_cmd_ip_v6_filter_init *flt6_params = params;

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->hash_rules_addr = flt6_params->hash_rules_addr;
	data->hash_rules_size = flt6_params->hash_rules_size;
	data->hash_local_addr = flt6_params->hash_local_addr;
	data->nhash_rules_addr = flt6_params->nhash_rules_addr;
	data->nhash_rules_size = flt6_params->nhash_rules_size;
	data->nhash_local_addr = flt6_params->nhash_local_addr;

	return pyld;
}

static struct ipahal_imm_cmd_pyld *
ipa_imm_cmd_construct_ip_v4_filter_init(u16 opcode, const void *params)
{
	struct ipahal_imm_cmd_pyld *pyld;
	struct ipa_imm_cmd_hw_ip_v4_filter_init *data;
	const struct ipahal_imm_cmd_ip_v4_filter_init *flt4_params = params;

	pyld = ipahal_imm_cmd_pyld_alloc(opcode, sizeof(*data));
	if (!pyld)
		return NULL;
	data = ipahal_imm_cmd_pyld_data(pyld);

	data->hash_rules_addr = flt4_params->hash_rules_addr;
	data->hash_rules_size = flt4_params->hash_rules_size;
	data->hash_local_addr = flt4_params->hash_local_addr;
	data->nhash_rules_addr = flt4_params->nhash_rules_addr;
	data->nhash_rules_size = flt4_params->nhash_rules_size;
	data->nhash_local_addr = flt4_params->nhash_local_addr;

	return pyld;
}

/*
 * struct ipahal_imm_cmd_obj - immediate command H/W information for
 *  specific IPA version
 * @construct - CB to construct imm command payload from abstracted structure
 * @opcode - Immediate command OpCode
 */
struct ipahal_imm_cmd_obj {
	struct ipahal_imm_cmd_pyld *(*construct)(u16 opcode,
		const void *params);
	u16 opcode;
};

/*
 * The The opcode used for certain immediate commands may change
 * between different versions of IPA hardare.  The format of the
 * command data passed to the IPA can change slightly with new
 * hardware.  The "ipahal" layer uses the ipahal_imm_cmd_obj[][]
 * table to hide the version-specific details of creating immediate
 * commands.
 *
 * The following table consists of blocks of "immediate command
 * object" definitions associated with versions of IPA hardware.
 * The entries for each immediate command contain a construct
 * functino and an opcode to use for a given version of IPA
 * hardware.  The first version of IPA hardware supported by the
 * "ipahal" layer is 3.0.
 *
 * Versions of IPA hardware newer than 3.0 do not need to specify
 * immediate command object entries if they are accessed the same
 * way as was defined by an older version.  The only entries defined
 * for newer hardware are for immediate commands whose opcode or
 * command format has changed, or immediate commands that are new
 * and not present in older hardware.
 *
 * The construct function for an immediate command is given an IPA
 * opcode, plus a non-null pointer to a command-specific parameter
 * block used to initialize the command.  The construct function
 * allocates a buffer to hold the command payload, and a pointer to
 * that buffer is returned once the parameters have been formatted
 * into it.  It is the caller's responsibility to ensure this buffer
 * gets freed when it is no longer needed.  The construct function
 * returns null if the buffer could not be allocated.
 *
 * No opcodes or command formats changed between IPA version 3.0
 * and IPA version 3.5.1, so all definitions from version 3.0 are
 * inherited by these newer versions.  We know, however, that some
 * of these *are* changing for upcoming hardware.
 *
 * The entries in this table have the following constraints:
 * - 0 is not a valid opcode; an entry having a 0 opcode indicates
 *   that the corresponding immediate command is formatted according
 *   to an immediate command object defined for an earlier hardware
 *   version.
 * - An opcode of OPCODE_INVAL indicates that a command is not
 *   supported for a particular hardware version.  It is an error
 *   for code to attempt to execute a command that is not
 *   unsupported by the current IPA hardware.
 *
 * A caller constructs an immediate command by providing a command
 * id and a parameter block to ipahal_construct_imm_cmd().  Such
 * calls are subject to these constraints:
 * - The command id supplied must be valid:
 *     - It must be a member of the ipahal_imm_cmd_name enumerated
 *       type less than IPA_IMM_CMD_MAX
 *     - It must be a command supported by the underlying hardware
 * - The parameter block must be a non-null pointer referring to
 *   parameter data that is formatted properly for the command.
 */
#define OPCODE_INVAL	((u16)0xffff)
static const struct ipahal_imm_cmd_obj
		ipahal_imm_cmd_objs[][IPA_IMM_CMD_MAX] = {
	/* IPAv3 */
	[IPA_HW_v3_0] = {
		[IPA_IMM_CMD_IP_V4_FILTER_INIT] = {
			ipa_imm_cmd_construct_ip_v4_filter_init, 3,
		},
		[IPA_IMM_CMD_IP_V6_FILTER_INIT] = {
			ipa_imm_cmd_construct_ip_v6_filter_init, 4,
		},
		[IPA_IMM_CMD_IP_V4_NAT_INIT] = {
			ipa_imm_cmd_construct_ip_v4_nat_init, 5,
		},
		[IPA_IMM_CMD_IP_V4_ROUTING_INIT] = {
			ipa_imm_cmd_construct_ip_v4_routing_init, 7,
		},
		[IPA_IMM_CMD_IP_V6_ROUTING_INIT] = {
			ipa_imm_cmd_construct_ip_v6_routing_init, 8,
		},
		[IPA_IMM_CMD_HDR_INIT_LOCAL] = {
			ipa_imm_cmd_construct_hdr_init_local, 9,
		},
		[IPA_IMM_CMD_HDR_INIT_SYSTEM] = {
			ipa_imm_cmd_construct_hdr_init_system, 10,
		},
		[IPA_IMM_CMD_REGISTER_WRITE] = {
			ipa_imm_cmd_construct_register_write, 12,
		},
		[IPA_IMM_CMD_NAT_DMA] = {
			ipa_imm_cmd_construct_nat_dma, 14,
		},
		[IPA_IMM_CMD_IP_PACKET_INIT] = {
			ipa_imm_cmd_construct_ip_packet_init, 16,
		},
		[IPA_IMM_CMD_DMA_TASK_32B_ADDR] = {
			ipa_imm_cmd_construct_dma_task_32b_addr, 17,
		},
		[IPA_IMM_CMD_DMA_SHARED_MEM] = {
			ipa_imm_cmd_construct_dma_shared_mem, 19,
		},
		[IPA_IMM_CMD_IP_PACKET_TAG_STATUS] = {
			ipa_imm_cmd_construct_ip_packet_tag_status, 20,
		},
	},

	/* IPAv3.1 */
	[IPA_HW_v3_1] = {
		/* All inherited from IPA_HW_v3_0. */
	},

	/* IPAv3.5 */
	[IPA_HW_v3_5] = {
		/* All inherited from IPA_HW_v3_1. */
	},

	/* IPAv3.5.1 */
	[IPA_HW_v3_5_1] = {
		/* All inherited from IPA_HW_v3_5. */
	},

	/* IPAv4 */
	[IPA_HW_v4_0] = {
		[IPA_IMM_CMD_REGISTER_WRITE] = {
			ipa_imm_cmd_construct_register_write_v_4_0, 12,
		},
		/* NAT_DMA was renamed to TABLE_DMA for IPAv4 */
		[IPA_IMM_CMD_NAT_DMA] = {
			NULL, OPCODE_INVAL,
		},
		[IPA_IMM_CMD_TABLE_DMA] = {
			ipa_imm_cmd_construct_table_dma_ipav4, 14,
		},
		[IPA_IMM_CMD_DMA_SHARED_MEM] = {
			ipa_imm_cmd_construct_dma_shared_mem_v_4_0, 19,
		},
	},
};

static const char *ipahal_imm_cmd_name_to_str[IPA_IMM_CMD_MAX] = {
	__stringify(IPA_IMM_CMD_IP_V4_FILTER_INIT),
	__stringify(IPA_IMM_CMD_IP_V6_FILTER_INIT),
	__stringify(IPA_IMM_CMD_IP_V4_NAT_INIT),
	__stringify(IPA_IMM_CMD_IP_V4_ROUTING_INIT),
	__stringify(IPA_IMM_CMD_IP_V6_ROUTING_INIT),
	__stringify(IPA_IMM_CMD_HDR_INIT_LOCAL),
	__stringify(IPA_IMM_CMD_HDR_INIT_SYSTEM),
	__stringify(IPA_IMM_CMD_REGISTER_WRITE),
	__stringify(IPA_IMM_CMD_NAT_DMA),
	__stringify(IPA_IMM_CMD_IP_PACKET_INIT),
	__stringify(IPA_IMM_CMD_DMA_SHARED_MEM),
	__stringify(IPA_IMM_CMD_IP_PACKET_TAG_STATUS),
	__stringify(IPA_IMM_CMD_DMA_TASK_32B_ADDR),
	__stringify(IPA_IMM_CMD_TABLE_DMA),
};

static struct ipahal_imm_cmd_obj ipahal_imm_cmds[IPA_IMM_CMD_MAX];

/*
 * ipahal_imm_cmd_init() - Build the Immediate command information table
 *  See ipahal_imm_cmd_objs[][] comments
 */
static void ipahal_imm_cmd_init(void)
{
	int i;
	int j;

	ipa_debug_low("Entry - HW_TYPE=%d\n", ipahal_ctx->hw_type);

	/* Build up a the immediate command descriptions we'll use */
	for (i = 0; i < IPA_IMM_CMD_MAX ; i++) {
		for (j = ipahal_ctx->hw_type; j >= IPA_HW_v3_0; j--) {
			const struct ipahal_imm_cmd_obj *imm_cmd;

			imm_cmd = &ipahal_imm_cmd_objs[j][i];
			if (imm_cmd->opcode) {
				BUG_ON(!imm_cmd->construct);
				ipahal_imm_cmds[i] = *imm_cmd;
				break;
			}
		}
	}
}

/*
 * ipahal_construct_imm_cmd() - Construct immdiate command
 * This function builds imm cmd bulk that can be be sent to IPA
 * The command will be allocated dynamically.
 * After done using it, call ipahal_destroy_imm_cmd() to release it
 */
struct ipahal_imm_cmd_pyld *
ipahal_construct_imm_cmd(enum ipahal_imm_cmd_name cmd, const void *params)

{
	u16 opcode = ipahal_imm_cmds[cmd].opcode;

	ipa_debug_low("construct IMM_CMD:%s\n",
			ipahal_imm_cmd_name_to_str[cmd]);

	return ipahal_imm_cmds[cmd].construct(opcode, params);
}

/*
 * ipahal_construct_nop_imm_cmd() - Construct immediate comamnd for NO-Op
 * Core driver may want functionality to inject NOP commands to IPA
 *  to ensure e.g., PIPLINE clear before someother operation.
 * The functionality given by this function can be reached by
 *  ipahal_construct_imm_cmd(). This function is helper to the core driver
 *  to reach this NOP functionlity easily.
 */
struct ipahal_imm_cmd_pyld *ipahal_construct_nop_imm_cmd(void)
{
	struct ipahal_imm_cmd_register_write cmd;
	struct ipahal_imm_cmd_pyld *cmd_pyld;

	cmd.offset = 0;
	cmd.value = 0;
	cmd.value_mask = 0x0;
	cmd.skip_pipeline_clear = false;
	cmd.pipeline_clear_options = IPAHAL_FULL_PIPELINE_CLEAR;

	cmd_pyld = ipahal_construct_imm_cmd(IPA_IMM_CMD_REGISTER_WRITE, &cmd);
	if (!cmd_pyld)
		ipa_err("failed to construct register_write imm cmd\n");

	return cmd_pyld;
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

/*
 * Maps an exception type returned in a ipa_pkt_status_hw structure
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

static void ipa_pkt_status_parse(
	const void *unparsed_status, struct ipahal_pkt_status *status)
{
	const struct ipa_pkt_status_hw *hw_status = unparsed_status;
	u8 status_opcode = (u8)hw_status->status_opcode;
	u8 nat_type = (u8)hw_status->nat_type;
	enum ipahal_pkt_status_exception exception;
	bool is_ipv6;

	/* Our packet status struct has to match what hardware supplies */
	BUILD_BUG_ON(sizeof(struct ipa_pkt_status_hw) !=
		IPA3_0_PKT_STATUS_SIZE);

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

/*
 * ipahal_pkt_status_get_size() - Get H/W size of packet status
 */
u32 ipahal_pkt_status_get_size(void)
{
	return IPA3_0_PKT_STATUS_SIZE;
}

/*
 * ipahal_pkt_status_parse() - Parse Packet Status payload to abstracted form
 * @unparsed_status: Pointer to H/W format of the packet status as read from H/W
 * @status: Pointer to pre-allocated buffer where the parsed info will be stored
 */
void ipahal_pkt_status_parse(const void *unparsed_status,
	struct ipahal_pkt_status *status)
{
	ipa_debug_low("Parse Status Packet\n");
	memset(status, 0, sizeof(*status));
	ipa_pkt_status_parse(unparsed_status, status);
}

/*
 * ipahal_pkt_status_exception_str() - returns string represents exception type
 * @exception: [in] The exception type
 */
const char *
ipahal_pkt_status_exception_str(enum ipahal_pkt_status_exception exception)
{
	return ipahal_pkt_status_exception_to_str[exception];
}

/*
 * ipahal_cp_hdr_to_hw_buff() - copy header to hardware buffer according to
 * base address and offset given.
 * @base: dma base address
 * @offset: offset from base address where the data will be copied
 * @hdr: the header to be copied
 * @hdr_len: the length of the header
 */
void ipahal_cp_hdr_to_hw_buff(void *base, u32 offset, u8 *const hdr,
		u32 hdr_len)
{
	ipa_debug_low("Entry\n");
	ipa_debug("base %p, offset %d, hdr %p, hdr_len %d\n", base,
			offset, hdr, hdr_len);
	if (!base || !hdr_len || !hdr) {
		ipa_err("failed on validating params");
		return;
	}

	/* Copy the header to the hardware buffer */
	memcpy(base + offset, hdr, hdr_len);

	ipa_debug_low("Exit\n");
}

/*
 * Get IPA Data Processing Star image memory size at IPA SRAM
 */
u32 ipahal_get_dps_img_mem_size(void)
{
	return IPA_HW_DPS_IMG_MEM_SIZE_V3_0;
}

/*
 * Get IPA Header Processing Star image memory size at IPA SRAM
 */
u32 ipahal_get_hps_img_mem_size(void)
{
	return IPA_HW_HPS_IMG_MEM_SIZE_V3_0;
}

int ipahal_init(enum ipa_hw_type ipa_hw_type, void __iomem *base,
	struct device *ipa_pdev)
{
	ipa_debug("Entry - IPA HW TYPE=%d base=%p ipa_pdev=%p\n",
		ipa_hw_type, base, ipa_pdev);

	if (ipa_hw_type != IPA_HW_v3_5_1) {
		ipa_err("ipahal supported on IPAv3.5.1 only\n");
		return -EINVAL;
	}

	ipahal_ctx = kzalloc(sizeof(*ipahal_ctx), GFP_KERNEL);
	if (!ipahal_ctx) {
		ipa_err("kzalloc err for ipahal_ctx\n");
		return -ENOMEM;
	}

	ipahal_ctx->hw_type = ipa_hw_type;
	ipahal_ctx->base = base;
	ipahal_ctx->ipa_pdev = ipa_pdev;

	/* Packet status parsing code requires no initialization */
	ipahal_reg_init();
	ipahal_imm_cmd_init();

	if (ipahal_fltrt_init()) {
		kfree(ipahal_ctx);
		ipahal_ctx = NULL;
		return -EFAULT;
	}

	return 0;
}

void ipahal_destroy(void)
{
	ipa_debug("Entry\n");
	kfree(ipahal_ctx);
	ipahal_ctx = NULL;
}

void ipahal_free_dma_mem(struct ipa_mem_buffer *mem)
{
	if (likely(mem)) {
		dma_free_coherent(ipahal_ctx->ipa_pdev, mem->size, mem->base,
			mem->phys_base);
		mem->size = 0;
		mem->base = NULL;
		mem->phys_base = 0;
	}
}
