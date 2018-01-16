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

#define pr_fmt(fmt)	"ipahal %s:%d " fmt, __func__, __LINE__

#include <linux/ipc_logging.h>
#include <linux/debugfs.h>
#include "ipahal.h"
#include "ipahal_fltrt.h"
#include "ipahal_fltrt_i.h"
#include "ipahal_i.h"

/*
 * Width and alignment values for H/W structures.  Values could
 * differ for different versions of IPA hardware.
 */
#define IPA3_0_HW_TBL_WIDTH		8
#define IPA3_0_HW_TBL_SYSADDR_ALIGN	128
#define IPA3_0_HW_TBL_LCLADDR_ALIGN	8
#define IPA3_0_HW_TBL_BLK_SIZE_ALIGN	128
#define IPA3_0_HW_RULE_START_ALIGN	8
#define IPA3_0_HW_TBL_HDR_WIDTH		8
#define IPA3_0_HW_TBL_ADDR_MASK		127
#define IPA3_0_HW_RULE_BUF_SIZE		256

/*
 * Rules Priority.
 * Needed due to rules classification to hashable and non-hashable.
 * Higher priority is lower in number. i.e. 0 is highest priority
 */
#define IPA3_0_RULE_MAX_PRIORITY	0
#define IPA3_0_RULE_MIN_PRIORITY	1023

/*
 * RULE ID, bit length (e.g. 10 bits).
 */
#define IPA3_0_RULE_ID_BIT_LEN		10
#define IPA3_0_LOW_RULE_ID		1

/*
 * struct ipahal_fltrt_obj - Flt/Rt H/W information for specific IPA version
 * @support_hash: Is hashable tables supported
 * @tbl_width: Width of table in bytes
 * @sysaddr_align: System table address alignment
 * @lcladdr_align: Local table offset alignment
 * @blk_sz_align: Rules block size alignment
 * @rule_start_align: Rule start address alignment
 * @tbl_hdr_width: Width of the header structure in bytes
 * @tbl_addr_mask: Masking for Table address
 * @rule_max_prio: Max possible priority of a rule
 * @rule_min_prio: Min possible priority of a rule
 * @low_rule_id: Low value of Rule ID that can be used
 * @rule_id_bit_len: Rule is high (MSB) bit len
 * @rule_buf_size: Max size rule may utilize.
 * @write_val_to_hdr: Write address or offset to header entry
 * @create_flt_bitmap: Create bitmap in H/W format using given bitmap
 * @create_tbl_addr: Given raw table address, create H/W formated one
 * @parse_tbl_addr: Parse the given H/W address (hdr format)
 * @rt_generate_hw_rule: Generate RT rule in H/W format
 * @flt_generate_hw_rule: Generate FLT rule in H/W format
 * @flt_generate_eq: Generate flt equation attributes from rule attributes
 * @rt_parse_hw_rule: Parse rt rule read from H/W
 * @flt_parse_hw_rule: Parse flt rule read from H/W
 * @eq_bitfield: Array of the bit fields of the support equations
 */
struct ipahal_fltrt_obj {
	bool support_hash;
	u32 tbl_width;
	u32 sysaddr_align;
	u32 lcladdr_align;
	u32 blk_sz_align;
	u32 rule_start_align;
	u32 tbl_hdr_width;
	u32 tbl_addr_mask;
	int rule_max_prio;
	int rule_min_prio;
	u32 low_rule_id;
	u32 rule_id_bit_len;
	u32 rule_buf_size;
	u8* (*write_val_to_hdr)(u64 val, u8 *hdr);
	u64 (*create_flt_bitmap)(u64 ep_bitmap);
	u64 (*create_tbl_addr)(bool is_sys, u64 addr);
	void (*parse_tbl_addr)(u64 hwaddr, u64 *addr, bool *is_sys);
	u8 eq_bitfield[IPA_EQ_MAX];
};

static struct ipahal_fltrt_obj ipahal_fltrt;

static u64 ipa_fltrt_create_flt_bitmap(u64 ep_bitmap)
{
	/* At IPA3, there global configuration is possible but not used */
	return (ep_bitmap << 1) & ~0x1;
}

static u64 ipa_fltrt_create_tbl_addr(bool is_sys, u64 addr)
{
	if (is_sys) {
		if (addr % ipahal_fltrt.sysaddr_align) {
			ipa_err(
				"sys addr is not aligned accordingly addr=0x%pad\n",
				&addr);
			ipa_assert();
			return 0;
		}
	} else {
		if (addr % ipahal_fltrt.lcladdr_align) {
			ipa_err("addr/ofst isn't lcl addr aligned %llu\n",
				addr);
			ipa_assert();
			return 0;
		}
		/*
		 * for local tables (at sram) offsets is used as tables
		 * addresses. offset need to be in 8B units
		 * (local address aligned) and left shifted to its place.
		 * Local bit need to be enabled.
		 */
		addr /= ipahal_fltrt.lcladdr_align;
		addr *= ipahal_fltrt.tbl_addr_mask + 1;
		addr += 1;
	}

	return addr;
}

static void ipa_fltrt_parse_tbl_addr(u64 hwaddr, u64 *addr, bool *is_sys)
{
	ipa_debug_low("Parsing hwaddr 0x%llx\n", hwaddr);

	*is_sys = !(hwaddr & 0x1);
	hwaddr &= (~0ULL - 1);
	if (hwaddr % ipahal_fltrt.sysaddr_align) {
		ipa_err(
			"sys addr is not aligned accordingly addr=0x%pad\n",
			&hwaddr);
		ipa_assert();
		return;
	}

	if (!*is_sys) {
		hwaddr /= ipahal_fltrt.tbl_addr_mask + 1;
		hwaddr *= ipahal_fltrt.lcladdr_align;
	}

	*addr = hwaddr;
}

/*
 * The IPA implements offloaded packet filtering and routing
 * capabilities.  This is managed by programming IPA-resident
 * tables of rules that define the processing that should be
 * performed by the IPA and the conditions under which they
 * should be applied.  Aspects of these rules are constrained
 * by things like table entry sizes and alignment requirements.
 * As IPA technology evolves, some of these constraints may
 * change, and the following table specifies the parameters
 * that should be used for particular versions of IPA hardware.
 *
 * The table consists of a set of "filter/route objects", each of
 * which is a structure that defines the constraints that must be
 * used for a particular version of IPA hardware.  There are also a
 * few functions that format data related to these tables to be sent
 * to the IPA, or parse an address coming from it.  The first
 * version of IPA hardware supported by the "ipahal" layer is 3.0.
 *
 * A version of IPA hardware newer than 3.0 does not need to
 * provide an entry in the following array if the constraints for
 * that version are the same as was defined by an older version;
 * it only requires an entry if one or more parameters differ from
 * what's used in the previous version.  If a slot below is empty
 * (indicated by a 0 tbl_width field) the corresponding hardware
 * version's properties are taken from an older hardware version.
 *
 * The entries in this table have the following constraints.  Much
 * of this will be dictated by the hardware; the following statements
 * document assumptions of the code:
 * - 0 is not a valid table width; a 0 tbl_width value in an
 *   entry indicates the entry contains no definitions, and
 *   the definitions for that corresponding hardware version
 *   are inherited from an earlier version's entry.
 * - sysaddr_align is non-zero, and is a power of 2
 * - lcladdr_align is non-zero, and is a power of 2.
 * - blk_sz_align is non-zero, and is a power of 2.
 * - rule_start_align is non-zero, and is a power of 2.
 * - tbl_hdr_width is non-zero
 * - tbl_addr_mask is non-zero and is one less than a power of 2
 * - rule_min_prio is not less than rule_max_prio (0 is max prio)
 * - rule_id_bit_len is 2 or more
 * - write_val_to_hdr, create_flt_bitmap, create_tbl_addr, and
 *   parse_tbl_addr must be non-null function pointers
 */
static const struct ipahal_fltrt_obj ipahal_fltrt_objs[] = {
	/* IPAv3 */
	[IPA_HW_v3_0] = {
		.support_hash		= true,
		.tbl_width		= IPA3_0_HW_TBL_WIDTH,
		.sysaddr_align		= IPA3_0_HW_TBL_SYSADDR_ALIGN,
		.lcladdr_align		= IPA3_0_HW_TBL_LCLADDR_ALIGN,
		.blk_sz_align		= IPA3_0_HW_TBL_BLK_SIZE_ALIGN,
		.rule_start_align	= IPA3_0_HW_RULE_START_ALIGN,
		.tbl_hdr_width		= IPA3_0_HW_TBL_HDR_WIDTH,
		.tbl_addr_mask		= IPA3_0_HW_TBL_ADDR_MASK,
		.rule_max_prio		= IPA3_0_RULE_MAX_PRIORITY,
		.rule_min_prio		= IPA3_0_RULE_MIN_PRIORITY,
		.low_rule_id		= IPA3_0_LOW_RULE_ID,
		.rule_id_bit_len	= IPA3_0_RULE_ID_BIT_LEN,
		.rule_buf_size		= IPA3_0_HW_RULE_BUF_SIZE,
		.write_val_to_hdr	= ipa_write_64,
		.create_flt_bitmap	= ipa_fltrt_create_flt_bitmap,
		.create_tbl_addr	= ipa_fltrt_create_tbl_addr,
		.parse_tbl_addr		= ipa_fltrt_parse_tbl_addr,
		.eq_bitfield = {
			[IPA_TOS_EQ]			= 0,
			[IPA_PROTOCOL_EQ]		= 1,
			[IPA_TC_EQ]			= 2,
			[IPA_OFFSET_MEQ128_0]		= 3,
			[IPA_OFFSET_MEQ128_1]		= 4,
			[IPA_OFFSET_MEQ32_0]		= 5,
			[IPA_OFFSET_MEQ32_1]		= 6,
			[IPA_IHL_OFFSET_MEQ32_0]	= 7,
			[IPA_IHL_OFFSET_MEQ32_1]	= 8,
			[IPA_METADATA_COMPARE]		= 9,
			[IPA_IHL_OFFSET_RANGE16_0]	= 10,
			[IPA_IHL_OFFSET_RANGE16_1]	= 11,
			[IPA_IHL_OFFSET_EQ_32]		= 12,
			[IPA_IHL_OFFSET_EQ_16]		= 13,
			[IPA_FL_EQ]			= 14,
			[IPA_IS_FRAG]			= 15,
		},
	},

	/* IPAv3.1 */
	[IPA_HW_v3_1] = {
		/* All inherited from IPA_HW_v3_0. */
	},

	/* IPAv3.5 */
	[IPA_HW_v3_5] = {
	},
		/* All inherited from IPA_HW_v3_1. */

	/* IPAv3.5.1 */
	[IPA_HW_v3_5_1] = {
		/* All inherited from IPA_HW_v3_5. */
	},

	/* IPAv4 */
	[IPA_HW_v4_0] = {
		.support_hash		= true,
		.tbl_width		= IPA3_0_HW_TBL_WIDTH,
		.sysaddr_align		= IPA3_0_HW_TBL_SYSADDR_ALIGN,
		.lcladdr_align		= IPA3_0_HW_TBL_LCLADDR_ALIGN,
		.blk_sz_align		= IPA3_0_HW_TBL_BLK_SIZE_ALIGN,
		.rule_start_align	= IPA3_0_HW_RULE_START_ALIGN,
		.tbl_hdr_width		= IPA3_0_HW_TBL_HDR_WIDTH,
		.tbl_addr_mask		= IPA3_0_HW_TBL_ADDR_MASK,
		.rule_max_prio		= IPA3_0_RULE_MAX_PRIORITY,
		.rule_min_prio		= IPA3_0_RULE_MIN_PRIORITY,
		.low_rule_id		= IPA3_0_LOW_RULE_ID,
		.rule_id_bit_len	= IPA3_0_RULE_ID_BIT_LEN,
		.rule_buf_size		= IPA3_0_HW_RULE_BUF_SIZE,
		.write_val_to_hdr	= ipa_write_64,
		.create_flt_bitmap	= ipa_fltrt_create_flt_bitmap,
		.create_tbl_addr	= ipa_fltrt_create_tbl_addr,
		.parse_tbl_addr		= ipa_fltrt_parse_tbl_addr,
		.eq_bitfield = {
			[IPA_TOS_EQ]			= 0,
			[IPA_PROTOCOL_EQ]		= 1,
			[IPA_TC_EQ]			= 2,
			[IPA_OFFSET_MEQ128_0]		= 3,
			[IPA_OFFSET_MEQ128_1]		= 4,
			[IPA_OFFSET_MEQ32_0]		= 5,
			[IPA_OFFSET_MEQ32_1]		= 6,
			[IPA_IHL_OFFSET_MEQ32_0]	= 7,
			[IPA_IHL_OFFSET_MEQ32_1]	= 8,
			[IPA_METADATA_COMPARE]		= 9,
			[IPA_IHL_OFFSET_RANGE16_0]	= 10,
			[IPA_IHL_OFFSET_RANGE16_1]	= 11,
			[IPA_IHL_OFFSET_EQ_32]		= 12,
			[IPA_IHL_OFFSET_EQ_16]		= 13,
			[IPA_FL_EQ]			= 14,
			[IPA_IS_FRAG]			= 15,
		},
	},
};

/*
 * Set up an empty table in system memory.  This will be used, for
 * example, to delete a route table safely.
 */
static int ipahal_empty_fltrt_init(void)
{
	struct device *dev = ipahal_ctx->ipa_pdev;
	size_t size = ipahal_fltrt.tbl_width;
	dma_addr_t phys_base;
	void *base;

	base = dma_alloc_coherent(dev, size, &phys_base, GFP_KERNEL);
	if (!base) {
		ipa_err("DMA buff alloc fail %zu bytes for empty tbl\n", size);
		return -ENOMEM;
	}

	if (phys_base % ipahal_fltrt.sysaddr_align) {
		ipa_err("Empty table buf is not address aligned 0x%pad\n",
			&phys_base);
		dma_free_coherent(dev, size, base, phys_base);

		return -EFAULT;
	}

	ipahal_ctx->empty_fltrt_tbl.size = ipahal_fltrt.tbl_width;
	ipahal_ctx->empty_fltrt_tbl.base = base;
	ipahal_ctx->empty_fltrt_tbl.phys_base = phys_base;

	ipa_debug("empty table allocated in system memory");

	return 0;
}

static void ipahal_empty_fltrt_destroy(void)
{
	struct ipa_mem_buffer *mem = &ipahal_ctx->empty_fltrt_tbl;
	struct device *dev = ipahal_ctx->ipa_pdev;

	dma_free_coherent(dev, mem->size, mem->base, mem->phys_base);
	memset(mem, 0, sizeof(*mem));
}

/*
 * ipahal_fltrt_init() - Build the FLT/RT information table
 *  See ipahal_fltrt_objs[] comments
 */
int ipahal_fltrt_init(void)
{
	int i;

	ipa_debug("Entry - HW_TYPE=%d\n", ipahal_ctx->hw_type);

       /* Build up a the filter/route table descriptions we'll use */
	for (i = ipahal_ctx->hw_type; i >= IPA_HW_v3_0; i--) {
		const struct ipahal_fltrt_obj *fltrt;

		fltrt = &ipahal_fltrt_objs[i];
		if (fltrt->tbl_width) {
			ipahal_fltrt = *fltrt;
			break;
		}
	}

	return ipahal_empty_fltrt_init();
}

void ipahal_fltrt_destroy(void)
{
	ipa_debug("Entry\n");

	if (ipahal_ctx)
		ipahal_empty_fltrt_destroy();
}

/* Get the H/W table (flt/rt) header width */
u32 ipahal_get_hw_tbl_hdr_width(void)
{
	return ipahal_fltrt.tbl_hdr_width;
}

/* Get the H/W local table (SRAM) address alignment
 * Tables headers references to local tables via offsets in SRAM
 * This function return the alignment of the offset that IPA expects
 */
u32 ipahal_get_lcl_tbl_addr_alignment(void)
{
	return ipahal_fltrt.lcladdr_align - 1;
}

/*
 * Rule priority is used to distinguish rules order
 * at the integrated table consisting from hashable and
 * non-hashable tables. Max priority are rules that once are
 * scanned by IPA, IPA will not look for further rules and use it.
 */
int ipahal_get_rule_max_priority(void)
{
	return ipahal_fltrt.rule_max_prio;
}

/* Given a priority, calc and return the next lower one if it is in
 * legal range.
 */
int ipahal_rule_decrease_priority(int *prio)
{
	if (!prio) {
		ipa_err("Invalid Input\n");
		return -EINVAL;
	}

	/* Priority logic is reverse. 0 priority considred max priority */
	if (*prio > ipahal_fltrt.rule_min_prio ||
			*prio < ipahal_fltrt.rule_max_prio) {
		ipa_err("Invalid given priority %d\n", *prio);
		return -EINVAL;
	}

	*prio += 1;

	if (*prio > ipahal_fltrt.rule_min_prio) {
		ipa_err("Cannot decrease priority. Already on min\n");
		*prio -= 1;
		return -EFAULT;
	}

	return 0;
}

/* Does the given ID represents rule miss?
 * Rule miss ID, is always the max ID possible in the bit-pattern
 */
bool ipahal_is_rule_miss_id(u32 id)
{
	return id == ((1U << ipahal_fltrt.rule_id_bit_len) - 1);
}

/* Get rule ID with high bit only asserted
 * Used e.g. to create groups of IDs according to this bit
 */
u32 ipahal_get_rule_id_hi_bit(void)
{
	return BIT(ipahal_fltrt.rule_id_bit_len - 1);
}

/* Get the low value possible to be used for rule-id */
u32 ipahal_get_low_rule_id(void)
{
	return ipahal_fltrt.low_rule_id;
}

/*
 * ipahal_rt_generate_empty_img() - Generate empty route image
 *  Creates routing header buffer for the given tables number.
 *  For each table, make it point to the empty table on DDR.
 * @tbls_num: Number of tables. For each will have an entry in the header
 * @hash_hdr_size: SRAM buf size of the hash tbls hdr. Used for space check
 * @nhash_hdr_size: SRAM buf size of the nhash tbls hdr. Used for space check
 * @mem: mem object that points to DMA mem representing the hdr structure
 * @atomic: should DMA allocation be executed with atomic flag
 */
int ipahal_rt_generate_empty_img(u32 tbls_num, u32 hash_hdr_size,
	u32 nhash_hdr_size, struct ipa_mem_buffer *mem, bool atomic)
{
	int i;
	u64 addr;
	int flag;

	ipa_debug("Entry\n");

	flag = atomic ? GFP_ATOMIC : GFP_KERNEL;

	if (!tbls_num || !nhash_hdr_size) {
		ipa_err("Input Error: tbls_num=%d nhash_hdr_sz=%d mem=%p\n",
			tbls_num, nhash_hdr_size, mem);
		return -EINVAL;
	}
	if (ipahal_fltrt.support_hash && !hash_hdr_size) {
		ipa_err("Input Error: hash_hdr_sz=%d\n", hash_hdr_size);
		return -EINVAL;
	}

	if (nhash_hdr_size < (tbls_num * ipahal_fltrt.tbl_hdr_width)) {
		ipa_err("No enough spc at non-hash hdr blk for all tbls\n");
		WARN_ON(1);
		return -EINVAL;
	}
	if (ipahal_fltrt.support_hash &&
		(hash_hdr_size < (tbls_num * ipahal_fltrt.tbl_hdr_width))) {
		ipa_err("No enough spc at hash hdr blk for all tbls\n");
		WARN_ON(1);
		return -EINVAL;
	}

	mem->size = tbls_num * ipahal_fltrt.tbl_hdr_width;
	mem->base = dma_alloc_coherent(ipahal_ctx->ipa_pdev, mem->size,
		&mem->phys_base, flag);
	if (!mem->base) {
		ipa_err("fail to alloc DMA buff of size %d\n", mem->size);
		return -ENOMEM;
	}

	addr = ipahal_fltrt.create_tbl_addr(true,
		ipahal_ctx->empty_fltrt_tbl.phys_base);
	for (i = 0; i < tbls_num; i++)
		ipahal_fltrt.write_val_to_hdr(addr,
			mem->base + i * ipahal_fltrt.tbl_hdr_width);

	return 0;
}

/*
 * ipahal_flt_generate_empty_img() - Generate empty filter image
 *  Creates filter header buffer for the given tables number.
 *  For each table, make it point to the empty table on DDR.
 * @tbls_num: Number of tables. For each will have an entry in the header
 * @hash_hdr_size: SRAM buf size of the hash tbls hdr. Used for space check
 * @nhash_hdr_size: SRAM buf size of the nhash tbls hdr. Used for space check
 * @ep_bitmap: Bitmap representing the EP that has flt tables. The format
 *  should be: bit0->EP0, bit1->EP1
 *  If bitmap is zero -> create tbl without bitmap entry
 * @mem: mem object that points to DMA mem representing the hdr structure
 * @atomic: should DMA allocation be executed with atomic flag
 */
int ipahal_flt_generate_empty_img(u32 tbls_num, u32 hash_hdr_size,
	u32 nhash_hdr_size, u64 ep_bitmap, struct ipa_mem_buffer *mem,
	bool atomic)
{
	int flt_spc;
	u64 flt_bitmap;
	int i;
	u64 addr;
	int flag;

	ipa_debug("Entry - ep_bitmap 0x%llx\n", ep_bitmap);

	flag = atomic ? GFP_ATOMIC : GFP_KERNEL;

	if (!tbls_num || !nhash_hdr_size || !mem) {
		ipa_err("Input Error: tbls_num=%d nhash_hdr_sz=%d mem=%p\n",
			tbls_num, nhash_hdr_size, mem);
		return -EINVAL;
	}

	if (ipahal_fltrt.support_hash && !hash_hdr_size) {
		ipa_err("Input Error: hash_hdr_sz=%d\n", hash_hdr_size);
		return -EINVAL;
	}

	if (ipahal_fltrt.support_hash) {
		flt_spc = hash_hdr_size;
		/* bitmap word */
		if (ep_bitmap)
			flt_spc -= ipahal_fltrt.tbl_hdr_width;
		flt_spc /= ipahal_fltrt.tbl_hdr_width;
		if (tbls_num > flt_spc)  {
			ipa_err("space for hash flt hdr is too small\n");
			WARN_ON(1);
			return -EPERM;
		}
	}

	flt_spc = nhash_hdr_size;
	/* bitmap word */
	if (ep_bitmap)
		flt_spc -= ipahal_fltrt.tbl_hdr_width;
	flt_spc /= ipahal_fltrt.tbl_hdr_width;
	if (tbls_num > flt_spc)  {
		ipa_err("space for non-hash flt hdr is too small\n");
		WARN_ON(1);
		return -EPERM;
	}

	mem->size = tbls_num * ipahal_fltrt.tbl_hdr_width;
	if (ep_bitmap)
		mem->size += ipahal_fltrt.tbl_hdr_width;
	mem->base = dma_alloc_coherent(ipahal_ctx->ipa_pdev, mem->size,
		&mem->phys_base, flag);
	if (!mem->base) {
		ipa_err("fail to alloc DMA buff of size %d\n", mem->size);
		return -ENOMEM;
	}

	if (ep_bitmap) {
		flt_bitmap = ipahal_fltrt.create_flt_bitmap(ep_bitmap);
		ipa_debug("flt bitmap 0x%llx\n", flt_bitmap);
		ipahal_fltrt.write_val_to_hdr(flt_bitmap, mem->base);
	}

	addr = ipahal_fltrt.create_tbl_addr(true,
		ipahal_ctx->empty_fltrt_tbl.phys_base);

	if (ep_bitmap) {
		for (i = 1; i <= tbls_num; i++)
			ipahal_fltrt.write_val_to_hdr(addr,
				mem->base + i * ipahal_fltrt.tbl_hdr_width);
	} else {
		for (i = 0; i < tbls_num; i++)
			ipahal_fltrt.write_val_to_hdr(addr,
				mem->base + i * ipahal_fltrt.tbl_hdr_width);
	}

	return 0;
}
