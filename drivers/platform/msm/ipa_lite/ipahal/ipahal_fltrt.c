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
 * struct ipahal_fltrt_obj - Flt/Rt H/W information for specific IPA version
 * @support_hash: Is hashable tables supported
 * @tbl_width: Width of table in bytes
 * @sysaddr_alignment: System table address alignment
 * @lcladdr_alignment: Local table offset alignment
 * @blk_sz_alignment: Rules block size alignment
 * @rule_start_alignment: Rule start address alignment
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
	u32 sysaddr_alignment;
	u32 lcladdr_alignment;
	u32 blk_sz_alignment;
	u32 rule_start_alignment;
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


static u64 ipa_fltrt_create_flt_bitmap(u64 ep_bitmap)
{
	/* At IPA3, there global configuration is possible but not used */
	return (ep_bitmap << 1) & ~0x1;
}

static u64 ipa_fltrt_create_tbl_addr(bool is_sys, u64 addr)
{
	if (is_sys) {
		if (addr & IPA3_0_HW_TBL_SYSADDR_ALIGNMENT) {
			IPAHAL_ERR(
				"sys addr is not aligned accordingly addr=0x%pad\n",
				&addr);
			ipa_assert();
			return 0;
		}
	} else {
		if (addr & IPA3_0_HW_TBL_LCLADDR_ALIGNMENT) {
			IPAHAL_ERR("addr/ofst isn't lcl addr aligned %llu\n",
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
		addr /= IPA3_0_HW_TBL_LCLADDR_ALIGNMENT + 1;
		addr *= IPA3_0_HW_TBL_ADDR_MASK + 1;
		addr += 1;
	}

	return addr;
}

static void ipa_fltrt_parse_tbl_addr(u64 hwaddr, u64 *addr, bool *is_sys)
{
	IPAHAL_DBG_LOW("Parsing hwaddr 0x%llx\n", hwaddr);

	*is_sys = !(hwaddr & 0x1);
	hwaddr &= (~0ULL - 1);
	if (hwaddr & IPA3_0_HW_TBL_SYSADDR_ALIGNMENT) {
		IPAHAL_ERR(
			"sys addr is not aligned accordingly addr=0x%pad\n",
			&hwaddr);
		ipa_assert();
		return;
	}

	if (!*is_sys) {
		hwaddr /= IPA3_0_HW_TBL_ADDR_MASK + 1;
		hwaddr *= IPA3_0_HW_TBL_LCLADDR_ALIGNMENT + 1;
	}

	*addr = hwaddr;
}

/* Update these tables of the number of equations changes */
static const int ipa3_0_ofst_meq32[] = { IPA_OFFSET_MEQ32_0,
					IPA_OFFSET_MEQ32_1};
static const int ipa3_0_ofst_meq128[] = { IPA_OFFSET_MEQ128_0,
					IPA_OFFSET_MEQ128_1};
static const int ipa3_0_ihl_ofst_rng16[] = { IPA_IHL_OFFSET_RANGE16_0,
					IPA_IHL_OFFSET_RANGE16_1};
static const int ipa3_0_ihl_ofst_meq32[] = { IPA_IHL_OFFSET_MEQ32_0,
					IPA_IHL_OFFSET_MEQ32_1};

#define IPA_IS_RAN_OUT_OF_EQ(__eq_array, __eq_index) \
	(ARRAY_SIZE(__eq_array) <= (__eq_index))

#define IPA_GET_RULE_EQ_BIT_PTRN(__eq) \
	(BIT(ipahal_fltrt_objs[ipahal_ctx->hw_type].eq_bitfield[(__eq)]))

/*
 * This array contains the FLT/RT info for IPAv3 and later.
 * All the information on IPAv3 are statically defined below.
 * If information is missing regarding on some IPA version,
 *  the init function will fill it with the information from the previous
 *  IPA version.
 * Information is considered missing if all of the fields are 0.
 */
static struct ipahal_fltrt_obj ipahal_fltrt_objs[IPA_HW_MAX] = {
	/* IPAv3 */
	[IPA_HW_v3_0] = {
		true,
		IPA3_0_HW_TBL_WIDTH,
		IPA3_0_HW_TBL_SYSADDR_ALIGNMENT,
		IPA3_0_HW_TBL_LCLADDR_ALIGNMENT,
		IPA3_0_HW_TBL_BLK_SIZE_ALIGNMENT,
		IPA3_0_HW_RULE_START_ALIGNMENT,
		IPA3_0_HW_TBL_HDR_WIDTH,
		IPA3_0_HW_TBL_ADDR_MASK,
		IPA3_0_RULE_MAX_PRIORITY,
		IPA3_0_RULE_MIN_PRIORITY,
		IPA3_0_LOW_RULE_ID,
		IPA3_0_RULE_ID_BIT_LEN,
		IPA3_0_HW_RULE_BUF_SIZE,
		ipa_write_64,
		ipa_fltrt_create_flt_bitmap,
		ipa_fltrt_create_tbl_addr,
		ipa_fltrt_parse_tbl_addr,
		{
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

	/* IPAv4 */
	[IPA_HW_v4_0] = {
		true,
		IPA3_0_HW_TBL_WIDTH,
		IPA3_0_HW_TBL_SYSADDR_ALIGNMENT,
		IPA3_0_HW_TBL_LCLADDR_ALIGNMENT,
		IPA3_0_HW_TBL_BLK_SIZE_ALIGNMENT,
		IPA3_0_HW_RULE_START_ALIGNMENT,
		IPA3_0_HW_TBL_HDR_WIDTH,
		IPA3_0_HW_TBL_ADDR_MASK,
		IPA3_0_RULE_MAX_PRIORITY,
		IPA3_0_RULE_MIN_PRIORITY,
		IPA3_0_LOW_RULE_ID,
		IPA3_0_RULE_ID_BIT_LEN,
		IPA3_0_HW_RULE_BUF_SIZE,
		ipa_write_64,
		ipa_fltrt_create_flt_bitmap,
		ipa_fltrt_create_tbl_addr,
		ipa_fltrt_parse_tbl_addr,
		{
			[IPA_TOS_EQ] = 0,
			[IPA_PROTOCOL_EQ] = 1,
			[IPA_TC_EQ] = 2,
			[IPA_OFFSET_MEQ128_0] = 3,
			[IPA_OFFSET_MEQ128_1] = 4,
			[IPA_OFFSET_MEQ32_0] = 5,
			[IPA_OFFSET_MEQ32_1] = 6,
			[IPA_IHL_OFFSET_MEQ32_0] = 7,
			[IPA_IHL_OFFSET_MEQ32_1] = 8,
			[IPA_METADATA_COMPARE] = 9,
			[IPA_IHL_OFFSET_RANGE16_0] = 10,
			[IPA_IHL_OFFSET_RANGE16_1] = 11,
			[IPA_IHL_OFFSET_EQ_32] = 12,
			[IPA_IHL_OFFSET_EQ_16] = 13,
			[IPA_FL_EQ] = 14,
			[IPA_IS_FRAG] = 15,
		},
	},
};

/*
 * ipahal_fltrt_init() - Build the FLT/RT information table
 *  See ipahal_fltrt_objs[] comments
 *
 * Note: As global variables are initialized with zero, any un-overridden
 *  register entry will be zero. By this we recognize them.
 */
int ipahal_fltrt_init(enum ipa_hw_type ipa_hw_type)
{
	struct ipahal_fltrt_obj zero_obj;
	int i;
	struct ipa_mem_buffer *mem;
	int rc = -EFAULT;

	IPAHAL_DBG("Entry - HW_TYPE=%d\n", ipa_hw_type);

	if (ipa_hw_type >= IPA_HW_MAX) {
		IPAHAL_ERR("Invalid H/W type\n");
		return -EFAULT;
	}

	memset(&zero_obj, 0, sizeof(zero_obj));
	for (i = IPA_HW_v3_0 ; i < ipa_hw_type ; i++) {
		if (!memcmp(&ipahal_fltrt_objs[i+1], &zero_obj,
			sizeof(struct ipahal_fltrt_obj))) {
			memcpy(&ipahal_fltrt_objs[i+1],
				&ipahal_fltrt_objs[i],
				sizeof(struct ipahal_fltrt_obj));
		} else {
			/*
			 * explicitly overridden FLT RT info
			 * Check validity
			 */
			if (!ipahal_fltrt_objs[i+1].tbl_width) {
				IPAHAL_ERR(
				 "Zero tbl width ipaver=%d\n",
				 i+1);
				WARN_ON(1);
			}
			if (!ipahal_fltrt_objs[i+1].sysaddr_alignment) {
				IPAHAL_ERR(
				  "No tbl sysaddr alignment ipaver=%d\n",
				  i+1);
				WARN_ON(1);
			}
			if (!ipahal_fltrt_objs[i+1].lcladdr_alignment) {
				IPAHAL_ERR(
				  "No tbl lcladdr alignment ipaver=%d\n",
				  i+1);
				WARN_ON(1);
			}
			if (!ipahal_fltrt_objs[i+1].blk_sz_alignment) {
				IPAHAL_ERR(
				  "No blk sz alignment ipaver=%d\n",
				  i+1);
				WARN_ON(1);
			}
			if (!ipahal_fltrt_objs[i+1].rule_start_alignment) {
				IPAHAL_ERR(
				  "No rule start alignment ipaver=%d\n",
				  i+1);
				WARN_ON(1);
			}
			if (!ipahal_fltrt_objs[i+1].tbl_hdr_width) {
				IPAHAL_ERR(
				 "Zero tbl hdr width ipaver=%d\n",
				 i+1);
				WARN_ON(1);
			}
			if (!ipahal_fltrt_objs[i+1].tbl_addr_mask) {
				IPAHAL_ERR(
				 "Zero tbl hdr width ipaver=%d\n",
				 i+1);
				WARN_ON(1);
			}
			if (ipahal_fltrt_objs[i+1].rule_id_bit_len < 2) {
				IPAHAL_ERR(
				 "Too little bits for rule_id ipaver=%d\n",
				 i+1);
				WARN_ON(1);
			}
			if (!ipahal_fltrt_objs[i+1].rule_buf_size) {
				IPAHAL_ERR(
				 "zero rule buf size ipaver=%d\n",
				 i+1);
				WARN_ON(1);
			}
			if (!ipahal_fltrt_objs[i+1].write_val_to_hdr) {
				IPAHAL_ERR(
				  "No write_val_to_hdr CB ipaver=%d\n",
				  i+1);
				WARN_ON(1);
			}
			if (!ipahal_fltrt_objs[i+1].create_flt_bitmap) {
				IPAHAL_ERR(
				  "No create_flt_bitmap CB ipaver=%d\n",
				  i+1);
				WARN_ON(1);
			}
			if (!ipahal_fltrt_objs[i+1].create_tbl_addr) {
				IPAHAL_ERR(
				  "No create_tbl_addr CB ipaver=%d\n",
				  i+1);
				WARN_ON(1);
			}
			if (!ipahal_fltrt_objs[i+1].parse_tbl_addr) {
				IPAHAL_ERR(
				  "No parse_tbl_addr CB ipaver=%d\n",
				  i+1);
				WARN_ON(1);
			}
		}
	}

	mem = &ipahal_ctx->empty_fltrt_tbl;

	/* setup an empty  table in system memory; This will
	 * be used, for example, to delete a rt tbl safely
	 */
	mem->size = ipahal_fltrt_objs[ipa_hw_type].tbl_width;
	mem->base = dma_alloc_coherent(ipahal_ctx->ipa_pdev, mem->size,
		&mem->phys_base, GFP_KERNEL);
	if (!mem->base) {
		IPAHAL_ERR("DMA buff alloc fail %d bytes for empty tbl\n",
			mem->size);
		return -ENOMEM;
	}

	if (mem->phys_base &
		ipahal_fltrt_objs[ipa_hw_type].sysaddr_alignment) {
		IPAHAL_ERR("Empty table buf is not address aligned 0x%pad\n",
			&mem->phys_base);
		rc = -EFAULT;
		goto clear_empty_tbl;
	}

	memset(mem->base, 0, mem->size);
	IPAHAL_DBG("empty table allocated in system memory");

	return 0;

clear_empty_tbl:
	dma_free_coherent(ipahal_ctx->ipa_pdev, mem->size, mem->base,
		mem->phys_base);
	return rc;
}

void ipahal_fltrt_destroy(void)
{
	IPAHAL_DBG("Entry\n");

	if (ipahal_ctx && ipahal_ctx->empty_fltrt_tbl.base)
		dma_free_coherent(ipahal_ctx->ipa_pdev,
			ipahal_ctx->empty_fltrt_tbl.size,
			ipahal_ctx->empty_fltrt_tbl.base,
			ipahal_ctx->empty_fltrt_tbl.phys_base);
}

/* Get the H/W table (flt/rt) header width */
u32 ipahal_get_hw_tbl_hdr_width(void)
{
	return ipahal_fltrt_objs[ipahal_ctx->hw_type].tbl_hdr_width;
}

/* Get the H/W local table (SRAM) address alignment
 * Tables headers references to local tables via offsets in SRAM
 * This function return the alignment of the offset that IPA expects
 */
u32 ipahal_get_lcl_tbl_addr_alignment(void)
{
	return ipahal_fltrt_objs[ipahal_ctx->hw_type].lcladdr_alignment;
}

/*
 * Rule priority is used to distinguish rules order
 * at the integrated table consisting from hashable and
 * non-hashable tables. Max priority are rules that once are
 * scanned by IPA, IPA will not look for further rules and use it.
 */
int ipahal_get_rule_max_priority(void)
{
	return ipahal_fltrt_objs[ipahal_ctx->hw_type].rule_max_prio;
}

/* Given a priority, calc and return the next lower one if it is in
 * legal range.
 */
int ipahal_rule_decrease_priority(int *prio)
{
	struct ipahal_fltrt_obj *obj;

	obj = &ipahal_fltrt_objs[ipahal_ctx->hw_type];

	if (!prio) {
		IPAHAL_ERR("Invalid Input\n");
		return -EINVAL;
	}

	/* Priority logic is reverse. 0 priority considred max priority */
	if (*prio > obj->rule_min_prio || *prio < obj->rule_max_prio) {
		IPAHAL_ERR("Invalid given priority %d\n", *prio);
		return -EINVAL;
	}

	*prio += 1;

	if (*prio > obj->rule_min_prio) {
		IPAHAL_ERR("Cannot decrease priority. Already on min\n");
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
	return (id ==
		((1U << ipahal_fltrt_objs[ipahal_ctx->hw_type].rule_id_bit_len)
		-1));
}

/* Get rule ID with high bit only asserted
 * Used e.g. to create groups of IDs according to this bit
 */
u32 ipahal_get_rule_id_hi_bit(void)
{
	return BIT(ipahal_fltrt_objs[ipahal_ctx->hw_type].rule_id_bit_len - 1);
}

/* Get the low value possible to be used for rule-id */
u32 ipahal_get_low_rule_id(void)
{
	return  ipahal_fltrt_objs[ipahal_ctx->hw_type].low_rule_id;
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
	struct ipahal_fltrt_obj *obj;
	int flag;

	IPAHAL_DBG("Entry\n");

	flag = atomic ? GFP_ATOMIC : GFP_KERNEL;
	obj = &ipahal_fltrt_objs[ipahal_ctx->hw_type];

	if (!tbls_num || !nhash_hdr_size || !mem) {
		IPAHAL_ERR("Input Error: tbls_num=%d nhash_hdr_sz=%d mem=%p\n",
			tbls_num, nhash_hdr_size, mem);
		return -EINVAL;
	}
	if (obj->support_hash && !hash_hdr_size) {
		IPAHAL_ERR("Input Error: hash_hdr_sz=%d\n", hash_hdr_size);
		return -EINVAL;
	}

	if (nhash_hdr_size < (tbls_num * obj->tbl_hdr_width)) {
		IPAHAL_ERR("No enough spc at non-hash hdr blk for all tbls\n");
		WARN_ON(1);
		return -EINVAL;
	}
	if (obj->support_hash &&
		(hash_hdr_size < (tbls_num * obj->tbl_hdr_width))) {
		IPAHAL_ERR("No enough spc at hash hdr blk for all tbls\n");
		WARN_ON(1);
		return -EINVAL;
	}

	mem->size = tbls_num * obj->tbl_hdr_width;
	mem->base = dma_alloc_coherent(ipahal_ctx->ipa_pdev, mem->size,
		&mem->phys_base, flag);
	if (!mem->base) {
		IPAHAL_ERR("fail to alloc DMA buff of size %d\n", mem->size);
		return -ENOMEM;
	}

	addr = obj->create_tbl_addr(true,
		ipahal_ctx->empty_fltrt_tbl.phys_base);
	for (i = 0; i < tbls_num; i++)
		obj->write_val_to_hdr(addr,
			mem->base + i * obj->tbl_hdr_width);

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
	struct ipahal_fltrt_obj *obj;
	int flag;

	IPAHAL_DBG("Entry - ep_bitmap 0x%llx\n", ep_bitmap);

	flag = atomic ? GFP_ATOMIC : GFP_KERNEL;
	obj = &ipahal_fltrt_objs[ipahal_ctx->hw_type];

	if (!tbls_num || !nhash_hdr_size || !mem) {
		IPAHAL_ERR("Input Error: tbls_num=%d nhash_hdr_sz=%d mem=%p\n",
			tbls_num, nhash_hdr_size, mem);
		return -EINVAL;
	}

	if (obj->support_hash && !hash_hdr_size) {
		IPAHAL_ERR("Input Error: hash_hdr_sz=%d\n", hash_hdr_size);
		return -EINVAL;
	}

	if (obj->support_hash) {
		flt_spc = hash_hdr_size;
		/* bitmap word */
		if (ep_bitmap)
			flt_spc -= obj->tbl_hdr_width;
		flt_spc /= obj->tbl_hdr_width;
		if (tbls_num > flt_spc)  {
			IPAHAL_ERR("space for hash flt hdr is too small\n");
			WARN_ON(1);
			return -EPERM;
		}
	}

	flt_spc = nhash_hdr_size;
	/* bitmap word */
	if (ep_bitmap)
		flt_spc -= obj->tbl_hdr_width;
	flt_spc /= obj->tbl_hdr_width;
	if (tbls_num > flt_spc)  {
		IPAHAL_ERR("space for non-hash flt hdr is too small\n");
		WARN_ON(1);
		return -EPERM;
	}

	mem->size = tbls_num * obj->tbl_hdr_width;
	if (ep_bitmap)
		mem->size += obj->tbl_hdr_width;
	mem->base = dma_alloc_coherent(ipahal_ctx->ipa_pdev, mem->size,
		&mem->phys_base, flag);
	if (!mem->base) {
		IPAHAL_ERR("fail to alloc DMA buff of size %d\n", mem->size);
		return -ENOMEM;
	}

	if (ep_bitmap) {
		flt_bitmap = obj->create_flt_bitmap(ep_bitmap);
		IPAHAL_DBG("flt bitmap 0x%llx\n", flt_bitmap);
		obj->write_val_to_hdr(flt_bitmap, mem->base);
	}

	addr = obj->create_tbl_addr(true,
		ipahal_ctx->empty_fltrt_tbl.phys_base);

	if (ep_bitmap) {
		for (i = 1; i <= tbls_num; i++)
			obj->write_val_to_hdr(addr,
				mem->base + i * obj->tbl_hdr_width);
	} else {
		for (i = 0; i < tbls_num; i++)
			obj->write_val_to_hdr(addr,
				mem->base + i * obj->tbl_hdr_width);
	}

	return 0;
}
