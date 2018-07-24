// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#define pr_fmt(fmt)	"ipahal %s:%d " fmt, __func__, __LINE__

#include <linux/debugfs.h>
#include "ipahal.h"
#include "ipahal_fltrt.h"
#include "ipahal_fltrt_i.h"
#include "ipahal_i.h"

/* Width and alignment values for H/W structures.  Values could
 * differ for different versions of IPA hardware.
 */
#define IPA_HW_TBL_WIDTH		8
#define IPA_HW_TBL_SYSADDR_ALIGN	128
#define IPA_HW_TBL_HDR_WIDTH		8

/* RULE ID, bit length (e.g. 10 bits).  */
#define IPA_RULE_ID_BIT_LEN		10
#define IPA_LOW_RULE_ID			1

/* struct ipahal_fltrt_obj - Flt/Rt H/W information for specific IPA version
 * @tbl_width: Width of table in bytes
 * @sysaddr_align: System table address alignment
 * @tbl_hdr_width: Width of the header structure in bytes
 * @low_rule_id: Low value of Rule ID that can be used
 * @rule_id_bit_len: Rule is high (MSB) bit len
 * @create_tbl_addr: Given raw table address, create H/W formated one
 * @rt_generate_hw_rule: Generate RT rule in H/W format
 * @flt_generate_hw_rule: Generate FLT rule in H/W format
 * @flt_generate_eq: Generate flt equation attributes from rule attributes
 * @rt_parse_hw_rule: Parse rt rule read from H/W
 * @flt_parse_hw_rule: Parse flt rule read from H/W
 */
struct ipahal_fltrt_obj {
	u32 tbl_width;
	u32 sysaddr_align;
	u32 tbl_hdr_width;
	u32 low_rule_id;
	u32 rule_id_bit_len;
};

/* The IPA implements offloaded packet filtering and routing
 * capabilities.  This is managed by programming IPA-resident
 * tables of rules that define the processing that should be
 * performed by the IPA and the conditions under which they
 * should be applied.  Aspects of these rules are constrained
 * by things like table entry sizes and alignment requirements.
 *
 * The table consists of a set of "filter/route objects", which is a
 * structure that defines the constraints that must be used for the
 * IPA hardware.  There are also a few functions that format data
 * related to these tables to be sent to the IPA, or parse an
 * address coming from it.
 *
 * The entries in this table have the following constraints.  Much
 * of this will be dictated by the hardware; the following statements
 * document assumptions of the code:
 * - 0 is not a valid table width; a 0 tbl_width value in an
 *   entry indicates the entry contains no definitions
 * - sysaddr_align is non-zero, and is a power of 2
 * - tbl_hdr_width is non-zero
 * - rule_id_bit_len is 2 or more
 */
/* IPAv3.5.1 */
static const struct ipahal_fltrt_obj ipahal_fltrt = {
	.tbl_width		= IPA_HW_TBL_WIDTH,
	.sysaddr_align		= IPA_HW_TBL_SYSADDR_ALIGN,
	.tbl_hdr_width		= IPA_HW_TBL_HDR_WIDTH,
	.low_rule_id		= IPA_LOW_RULE_ID,
	.rule_id_bit_len	= IPA_RULE_ID_BIT_LEN,
};

static u64 ipa_fltrt_create_flt_bitmap(u64 ep_bitmap)
{
	/* At IPA3, global configuration is possible but not used */
	return ep_bitmap << 1;
}

/* Set up an empty table in system memory.  This will be used, for
 * example, to delete a route table safely.  If successful, record
 * the table and also the dev pointer in the IPA HAL context.
 */
int ipahal_empty_fltrt_init(void)
{
	struct ipa_mem_buffer *mem = &ipahal_ctx->empty_fltrt_tbl;
	u32 size = ipahal_fltrt.tbl_width;

	if (ipahal_dma_alloc(mem, size, GFP_KERNEL)) {
		ipa_err("DMA buff alloc fail %u bytes for empty tbl\n", size);
		return -ENOMEM;
	}

	if (mem->phys_base % ipahal_fltrt.sysaddr_align) {
		ipa_err("Empty table buf is not address aligned 0x%pad\n",
			&mem->phys_base);
		ipahal_dma_free(mem);

		return -EFAULT;
	}

	ipa_debug("empty table allocated in system memory");

	return 0;
}

void ipahal_empty_fltrt_destroy(void)
{
	ipahal_dma_free(&ipahal_ctx->empty_fltrt_tbl);
}

/* Get the H/W table (flt/rt) header width */
u32 ipahal_get_hw_tbl_hdr_width(void)
{
	return ipahal_fltrt.tbl_hdr_width;
}

/* Does the given ID represents rule miss?
 * Rule miss ID, is always the max ID possible in the bit-pattern
 */
bool ipahal_is_rule_miss_id(u32 id)
{
	return id == ((1U << ipahal_fltrt.rule_id_bit_len) - 1);
}

void ipahal_free_empty_img(struct ipa_mem_buffer *mem)
{
	ipahal_dma_free(mem);
}

/* ipahal_rt_generate_empty_img() - Generate empty route image
 *  Creates routing header buffer for the given tables number.
 *  For each table, make it point to the empty table on DDR.
 * @tbls_num: Number of tables. For each will have an entry in the header
 * @mem: mem object that points to DMA mem representing the hdr structure
 * @gfp: GFP flag to supply with DMA allocation request
 */
int ipahal_rt_generate_empty_img(u32 tbls_num, struct ipa_mem_buffer *mem,
				 gfp_t gfp)
{
	u32 width = ipahal_fltrt.tbl_hdr_width;
	int i = 0;
	u64 addr;

	ipa_debug("Entry\n");

	if (ipahal_dma_alloc(mem, tbls_num * width, gfp))
		return -ENOMEM;

	addr = (u64)ipahal_ctx->empty_fltrt_tbl.phys_base;
	while (i < tbls_num)
		ipa_write_64(addr, mem->base + i++ * width);

	return 0;
}

/* ipahal_flt_generate_empty_img() - Generate empty filter image
 *  Creates filter header buffer for the given tables number.
 *  For each table, make it point to the empty table on DDR.
 * @tbls_num: Number of tables. For each will have an entry in the header
 * @ep_bitmap: Bitmap representing the EP that has flt tables. The format
 *  should be: bit0->EP0, bit1->EP1
 *  If bitmap is zero -> create tbl without bitmap entry
 * @mem: mem object that points to DMA mem representing the hdr structure
 * @gfp: GFP flag to supply with DMA allocation request
 */
int ipahal_flt_generate_empty_img(u32 tbls_num, u64 ep_bitmap,
				  struct ipa_mem_buffer *mem, gfp_t gfp)
{
	u32 width = ipahal_fltrt.tbl_hdr_width;
	int i = 0;
	u64 addr;

	ipa_debug("Entry - ep_bitmap 0x%llx\n", ep_bitmap);

	if (ep_bitmap)
		tbls_num++;

	if (ipahal_dma_alloc(mem, tbls_num * width, gfp))
		return -ENOMEM;

	if (ep_bitmap) {
		u64 flt_bitmap = ipa_fltrt_create_flt_bitmap(ep_bitmap);

		ipa_debug("flt bitmap 0x%llx\n", flt_bitmap);
		ipa_write_64(flt_bitmap, mem->base);
		i++;
	}

	addr = (u64)ipahal_ctx->empty_fltrt_tbl.phys_base;
	while (i < tbls_num)
		ipa_write_64(addr, mem->base + i++ * width);

	return 0;
}
