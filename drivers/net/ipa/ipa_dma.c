// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */

#include "ipa_i.h"
#include "ipa_dma.h"

bool ipa_dma_init(struct device *dev, u32 align)
{
	/* Ensure DMA addresses will have the alignment we require */
	if (dma_get_cache_alignment() % align)
		return -ENOTSUPP;

	return dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
}

void ipa_dma_exit(void)
{
}

int ipa_dma_alloc(struct ipa_mem_buffer *mem, u32 size, gfp_t gfp)
{
	dma_addr_t phys;
	void *cpu_addr;

	cpu_addr = dma_zalloc_coherent(ipa_ctx->dev, size, &phys, gfp);
	if (!cpu_addr)
		return -ENOMEM;

	mem->base = cpu_addr;
	mem->phys_base = phys;
	mem->size = size;

	return 0;
}

void ipa_dma_free(struct ipa_mem_buffer *mem)
{
	dma_free_coherent(ipa_ctx->dev, mem->size, mem->base, mem->phys_base);
	memset(mem, 0, sizeof(*mem));
}

void *ipa_dma_phys_to_virt(struct ipa_mem_buffer *mem, dma_addr_t phys)
{
	return mem->base + (phys - mem->phys_base);
}
