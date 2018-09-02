// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#ifndef _IPA_DMA_H_
#define _IPA_DMA_H_

#include <linux/types.h>
#include <linux/device.h>

/** struct ipa_mem_buffer - IPA memory buffer
 * @base: base
 * @phys_base: physical base address
 * @size: size of memory buffer
 */
struct ipa_mem_buffer {
	void *base;
	dma_addr_t phys_base;
	u32 size;
};

/* ipa_dma_init() - initialize IPA DMA system; returns 0 or an error code */
bool ipa_dma_init(struct device *dev, u32 align);

/* ipa_dma_exit() - shut down/clean up IPA DMA system */
void ipa_dma_exit(void);

/* ipa_dma_alloc() - allocate a DMA buffer, describe it in mem struct */
int ipa_dma_alloc(struct ipa_mem_buffer *mem, u32 size, gfp_t gfp);

/* ipa_dma_free() - free a previously-allocated DMA buffer */
void ipa_dma_free(struct ipa_mem_buffer *mem);

/* ipa_dma_phys_to_virt() - return the virtual equivalent of a DMA address */
void *ipa_dma_phys_to_virt(struct ipa_mem_buffer *mem, dma_addr_t phys);

#endif /* !_IPA_DMA_H_ */
