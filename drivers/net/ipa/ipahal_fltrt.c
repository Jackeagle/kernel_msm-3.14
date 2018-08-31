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

/* The IPA implements offloaded packet filtering and routing
 * capabilities.  This is managed by programming IPA-resident
 * tables of rules that define the processing that should be
 * performed by the IPA and the conditions under which they
 * should be applied.  Aspects of these rules are constrained
 * by things like table entry sizes and alignment requirements;
 * all of these are in units of bytes.  These definitions are
 * subject to some constraints:
 * - IPA_HW_TBL_WIDTH must be non-zero
 * - IPA_HW_TBL_SYSADDR_ALIGN must be a non-zero power of 2
 * - IPA_HW_TBL_HDR_WIDTH must be non-zero
 *
 * Values could differ for different versions of IPA hardware.
 * These values are for v3.5.1, found in the SDM845.
 */
#define IPA_HW_TBL_WIDTH		8
#define IPA_HW_TBL_SYSADDR_ALIGN	128
#define IPA_HW_TBL_HDR_WIDTH		8

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
