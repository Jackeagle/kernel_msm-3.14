// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#ifndef _IPAHAL_FLTRT_H_
#define _IPAHAL_FLTRT_H_

#include "ipa_common_i.h"

/* Get the H/W table (flt/rt) header width */
u32 ipahal_get_hw_tbl_hdr_width(void);

/* Does the given ID represents rule miss? */
bool ipahal_is_rule_miss_id(u32 id);

/* Get rule ID with high bit only asserted
 * Used e.g. to create groups of IDs according to this bit
 */
u32 ipahal_get_rule_id_hi_bit(void);

/* Get the low value possible to be used for rule-id */
u32 ipahal_get_low_rule_id(void);

/* ipahal_rt_generate_empty_img() - Generate empty route image
 *  Creates routing header buffer for the given tables number.
 * For each table, make it point to the empty table on DDR.
 * @tbls_num: Number of tables. For each will have an entry in the header
 * @mem: mem object that points to DMA mem representing the hdr structure
 * @atomic: should DMA allocation be executed with atomic flag
 */
int ipahal_rt_generate_empty_img(u32 tbls_num, struct ipa_mem_buffer *mem,
				 gfp_t gfp);

/* ipahal_flt_generate_empty_img() - Generate empty filter image
 *  Creates filter header buffer for the given tables number.
 *  For each table, make it point to the empty table on DDR.
 * @tbls_num: Number of tables. For each will have an entry in the header
 * @ep_bitmap: Bitmap representing the EP that has flt tables. The format
 *  should be: bit0->EP0, bit1->EP1
 * @mem: mem object that points to DMA mem representing the hdr structure
 * @atomic: should DMA allocation be executed with atomic flag
 */
int ipahal_flt_generate_empty_img(u32 tbls_num, u64 ep_bitmap,
				  struct ipa_mem_buffer *mem, gfp_t gfp);

/* ipahal_free_empty_img() - free empty filter or route image
 */
void ipahal_free_empty_img(struct ipa_mem_buffer *mem);

#endif /* _IPAHAL_FLTRT_H_ */
