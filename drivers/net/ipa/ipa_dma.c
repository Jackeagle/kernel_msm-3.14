// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */

#include <linux/dma-mapping.h>

#include "ipa_dma.h"

static struct device *ipa_dma_dev;

bool ipa_dma_init(struct device *dev, u32 align)
{
	int ret;

	/* Ensure DMA addresses will have the alignment we require */
	if (dma_get_cache_alignment() % align)
		return -ENOTSUPP;

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (!ret)
		ipa_dma_dev = dev;

	return ret;
}

void ipa_dma_exit(void)
{
	ipa_dma_dev = NULL;
}

int ipa_dma_alloc(struct ipa_dma_mem *mem, size_t size, gfp_t gfp)
{
	dma_addr_t phys;
	void *virt;

	virt = dma_zalloc_coherent(ipa_dma_dev, size, &phys, gfp);
	if (!virt)
		return -ENOMEM;

	mem->virt = virt;
	mem->phys = phys;
	mem->size = size;

	return 0;
}

void ipa_dma_free(struct ipa_dma_mem *mem)
{
	dma_free_coherent(ipa_dma_dev, mem->size, mem->virt, mem->phys);
	memset(mem, 0, sizeof(*mem));
}

void *ipa_dma_phys_to_virt(struct ipa_dma_mem *mem, dma_addr_t phys)
{
	return mem->virt + (phys - mem->phys);
}
