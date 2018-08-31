// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#define pr_fmt(fmt)	"ipahal %s:%d " fmt, __func__, __LINE__

#include <linux/debugfs.h>
#include <asm/unaligned.h>
#include "ipahal.h"
#include "ipahal_fltrt.h"
#include "ipahal_fltrt_i.h"
#include "ipahal_i.h"

/* The IPA implements offloaded packet filtering and routing
 * capabilities.  This is managed by programming IPA-resident
 * tables of rules that define the processing that should be
 * performed by the IPA and the conditions under which they
 * should be applied.  Aspects of these rules are constrained
 * by things like table entry sizes and alignment requirements;
 * all but one of these are in units of bytes.  These definitions
 * are subject to some constraints:
 * - IPA_HW_TBL_WIDTH must be non-zero
 * - IPA_HW_TBL_SYSADDR_ALIGN must be a non-zero power of 2
 * - IPA_HW_TBL_HDR_WIDTH must be non-zero
 * - IPA_RULE_ID_BIT_LEN must be 2 or more
 *
 * Values could differ for different versions of IPA hardware.
 * These values are for v3.5.1, found in the SDM845.
 */
#define IPA_HW_TBL_WIDTH		8
#define IPA_HW_TBL_SYSADDR_ALIGN	128
#define IPA_HW_TBL_HDR_WIDTH		8
#define IPA_RULE_ID_BIT_LEN		10	/* number of bits */

static u64 ipa_fltrt_create_flt_bitmap(u64 ep_bitmap)
{
	/* At IPA3, global configuration is possible but not used */
	return ep_bitmap << 1;
}

/* Set up an empty table in system memory.  This will be used, for
 * example, to delete a route table safely.  If successful, record
 * the table and also the dev pointer in the IPA HAL context.
 */
int ipahal_empty_fltrt_init(struct ipa_mem_buffer *mem)
{
	u32 size = IPA_HW_TBL_WIDTH;

	if (ipahal_dma_alloc(mem, size, GFP_KERNEL)) {
		ipa_err("DMA buff alloc fail %u bytes for empty tbl\n", size);
		return -ENOMEM;
	}

	if (mem->phys_base % IPA_HW_TBL_SYSADDR_ALIGN) {
		ipa_err("Empty table buf is not address aligned 0x%pad\n",
			&mem->phys_base);
		ipahal_dma_free(mem);

		return -EFAULT;
	}

	ipa_debug("empty table allocated in system memory");

	return 0;
}

void ipahal_empty_fltrt_destroy(struct ipa_mem_buffer *mem)
{
	ipahal_dma_free(mem);
}

/* Get the H/W table (flt/rt) header width */
u32 ipahal_get_hw_tbl_hdr_width(void)
{
	return IPA_HW_TBL_HDR_WIDTH;
}

/* Does the given ID represents rule miss?
 * Rule miss ID, is always the max ID possible in the bit-pattern
 */
bool ipahal_is_rule_miss_id(u32 id)
{
	return id == (1U << IPA_RULE_ID_BIT_LEN) - 1;
}

/* ipahal_rt_generate_empty_img() - Generate empty route image
 *  Creates routing header buffer for the given tables number.
 *  For each table, make it point to the empty table on DDR.
 * @tbls_num: Number of tables. For each will have an entry in the header
 * @mem: mem object that points to DMA mem representing the hdr structure
 */
int ipahal_rt_generate_empty_img(u32 tbls_num, struct ipa_mem_buffer *mem)
{
	u32 width = IPA_HW_TBL_HDR_WIDTH;
	int i = 0;
	u64 addr;

	ipa_debug("Entry\n");

	if (ipahal_dma_alloc(mem, tbls_num * width, GFP_KERNEL))
		return -ENOMEM;

	addr = (u64)ipahal_ctx->empty_fltrt_tbl.phys_base;
	while (i < tbls_num)
		put_unaligned(addr, mem->base + i++ * width);

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
 */
int ipahal_flt_generate_empty_img(u32 tbls_num, u64 ep_bitmap,
				  struct ipa_mem_buffer *mem)
{
	u32 width = IPA_HW_TBL_HDR_WIDTH;
	int i = 0;
	u64 addr;

	ipa_debug("Entry - ep_bitmap 0x%llx\n", ep_bitmap);

	if (ep_bitmap)
		tbls_num++;

	if (ipahal_dma_alloc(mem, tbls_num * width, GFP_KERNEL))
		return -ENOMEM;

	if (ep_bitmap) {
		u64 flt_bitmap = ipa_fltrt_create_flt_bitmap(ep_bitmap);

		ipa_debug("flt bitmap 0x%llx\n", flt_bitmap);
		put_unaligned(flt_bitmap, mem->base);
		i++;
	}

	addr = (u64)ipahal_ctx->empty_fltrt_tbl.phys_base;
	while (i < tbls_num)
		put_unaligned(addr, mem->base + i++ * width);

	return 0;
}

void ipahal_free_empty_img(struct ipa_mem_buffer *mem)
{
	ipahal_dma_free(mem);
}
