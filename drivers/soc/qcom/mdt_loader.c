/*
 * Qualcomm Peripheral Image Loader
 *
 * Copyright (C) 2018 The Linux Foundation. All rights reserved.
 * Copyright (C) 2016 Linaro Ltd
 * Copyright (C) 2015 Sony Mobile Communications Inc
 * Copyright (c) 2012-2013, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/device.h>
#include <linux/elf.h>
#include <linux/firmware.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/qcom_scm.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/soc/qcom/mdt_loader.h>
#include <linux/of_device.h>
#include <linux/io.h>
#include <linux/of_address.h>

static bool disable_timeouts;

bool is_timeout_disabled(void)
{
	return disable_timeouts;
}
EXPORT_SYMBOL_GPL(is_timeout_disabled);

static bool mdt_phdr_valid(const struct elf32_phdr *phdr)
{
	if (phdr->p_type != PT_LOAD)
		return false;

	if ((phdr->p_flags & QCOM_MDT_TYPE_MASK) == QCOM_MDT_TYPE_HASH)
		return false;

	if (!phdr->p_memsz)
		return false;

	return true;
}

int qcom_mdt_write_image_info(struct device *dev,
	struct qcom_mdt_image_info *info, unsigned int qcom_mdt_image_id)
{
	struct device_node *np;
	static void __iomem *pil_info_base;
	void __iomem *addr;
	struct resource res;
	struct qcom_mdt_image_info *qcom_mdt_info;
	int i;

	if (!pil_info_base) {
		np = of_find_compatible_node(NULL, NULL, "qcom,msm-imem-pil");
		if (!np) {
			dev_err(dev, "pil: failed to find qcom,msm-imem-pil node\n");
			return -EPROBE_DEFER;
		}
		if (of_address_to_resource(np, 0, &res)) {
			dev_err(dev, "pil: address to resource on imem region failed\n");
			return -EPROBE_DEFER;
		}

		pil_info_base = ioremap(res.start, resource_size(&res));

		if (!pil_info_base) {
			dev_err(dev, "pil: could not map imem region\n");
			return -EPROBE_DEFER;
		}

		if (__raw_readl(pil_info_base) == 0x53444247)
			disable_timeouts = true;
	}

	if (!info)
		return -EINVAL;

	addr = pil_info_base + sizeof(struct qcom_mdt_image_info) *
		qcom_mdt_image_id;

	qcom_mdt_info = (struct qcom_mdt_image_info __iomem *)addr;

	for (i = 0; i < sizeof(struct qcom_mdt_image_info)/sizeof(int); i++)
		writel_relaxed(0, addr + (i * sizeof(int)));

	__iowrite32_copy(&qcom_mdt_info->name, info->name,
			sizeof(qcom_mdt_info->name)/4);
	__iowrite32_copy(&qcom_mdt_info->start, &info->start,
			sizeof(qcom_mdt_info->start)/4);

	writel_relaxed(info->size, &qcom_mdt_info->size);

	return 0;
}
EXPORT_SYMBOL_GPL(qcom_mdt_write_image_info);

/**
 * qcom_mdt_get_size() - acquire size of the memory region needed to load mdt
 * @fw:		firmware object for the mdt file
 *
 * Returns size of the loaded firmware blob, or -EINVAL on failure.
 */
ssize_t qcom_mdt_get_size(const struct firmware *fw)
{
	const struct elf32_phdr *phdrs;
	const struct elf32_phdr *phdr;
	const struct elf32_hdr *ehdr;
	phys_addr_t min_addr = (phys_addr_t)ULLONG_MAX;
	phys_addr_t max_addr = 0;
	int i;

	ehdr = (struct elf32_hdr *)fw->data;
	phdrs = (struct elf32_phdr *)(ehdr + 1);

	for (i = 0; i < ehdr->e_phnum; i++) {
		phdr = &phdrs[i];

		if (!mdt_phdr_valid(phdr))
			continue;

		if (phdr->p_paddr < min_addr)
			min_addr = phdr->p_paddr;

		if (phdr->p_paddr + phdr->p_memsz > max_addr)
			max_addr = ALIGN(phdr->p_paddr + phdr->p_memsz, SZ_4K);
	}

	return min_addr < max_addr ? max_addr - min_addr : -EINVAL;
}
EXPORT_SYMBOL_GPL(qcom_mdt_get_size);

/**
 * qcom_mdt_load() - load the firmware which header is loaded as fw
 * @dev:	device handle to associate resources with
 * @fw:		firmware object for the mdt file
 * @firmware:	name of the firmware, for construction of segment file names
 * @pas_id:	PAS identifier
 * @mem_region:	allocated memory region to load firmware into
 * @mem_phys:	physical address of allocated memory region
 * @mem_size:	size of the allocated memory region
 * @reloc_base:	adjusted physical address after relocation
 *
 * Returns 0 on success, negative errno otherwise.
 */
int qcom_mdt_load(struct device *dev, const struct firmware *fw,
		  const char *firmware, int pas_id, void *mem_region,
		  phys_addr_t mem_phys, size_t mem_size,
		  phys_addr_t *reloc_base)
{
	const struct elf32_phdr *phdrs;
	const struct elf32_phdr *phdr;
	const struct elf32_hdr *ehdr;
	const struct firmware *seg_fw;
	phys_addr_t mem_reloc;
	phys_addr_t min_addr = (phys_addr_t)ULLONG_MAX;
	phys_addr_t max_addr = 0;
	size_t fw_name_len;
	ssize_t offset;
	char *fw_name;
	bool relocate = false;
	void *ptr;
	int ret;
	int i;

	if (!fw || !mem_region || !mem_phys || !mem_size)
		return -EINVAL;

	ehdr = (struct elf32_hdr *)fw->data;
	phdrs = (struct elf32_phdr *)(ehdr + 1);

	fw_name_len = strlen(firmware);
	if (fw_name_len <= 4)
		return -EINVAL;

	fw_name = kstrdup(firmware, GFP_KERNEL);
	if (!fw_name)
		return -ENOMEM;

	ret = qcom_scm_pas_init_image(pas_id, fw->data, fw->size);
	if (ret) {
		dev_err(dev, "invalid firmware metadata\n");
		goto out;
	}

	for (i = 0; i < ehdr->e_phnum; i++) {
		phdr = &phdrs[i];

		if (!mdt_phdr_valid(phdr))
			continue;

		if (phdr->p_flags & QCOM_MDT_RELOCATABLE)
			relocate = true;

		if (phdr->p_paddr < min_addr)
			min_addr = phdr->p_paddr;

		if (phdr->p_paddr + phdr->p_memsz > max_addr)
			max_addr = ALIGN(phdr->p_paddr + phdr->p_memsz, SZ_4K);
	}

	if (relocate) {
		ret = qcom_scm_pas_mem_setup(pas_id, mem_phys, max_addr - min_addr);
		if (ret) {
			dev_err(dev, "unable to setup relocation\n");
			goto out;
		}

		/*
		 * The image is relocatable, so offset each segment based on
		 * the lowest segment address.
		 */
		mem_reloc = min_addr;
	} else {
		/*
		 * Image is not relocatable, so offset each segment based on
		 * the allocated physical chunk of memory.
		 */
		mem_reloc = mem_phys;
	}

	for (i = 0; i < ehdr->e_phnum; i++) {
		phdr = &phdrs[i];

		if (!mdt_phdr_valid(phdr))
			continue;

		offset = phdr->p_paddr - mem_reloc;
		if (offset < 0 || offset + phdr->p_memsz > mem_size) {
			dev_err(dev, "segment outside memory range\n");
			ret = -EINVAL;
			break;
		}

		ptr = mem_region + offset;

		if (phdr->p_filesz) {
			sprintf(fw_name + fw_name_len - 3, "b%02d", i);
			ret = request_firmware_into_buf(&seg_fw, fw_name, dev,
							ptr, phdr->p_filesz);
			if (ret) {
				dev_err(dev, "failed to load %s\n", fw_name);
				break;
			}

			release_firmware(seg_fw);
		}

		if (phdr->p_memsz > phdr->p_filesz)
			memset(ptr + phdr->p_filesz, 0, phdr->p_memsz - phdr->p_filesz);
	}

	if (reloc_base)
		*reloc_base = mem_reloc;

out:
	kfree(fw_name);

	return ret;
}
EXPORT_SYMBOL_GPL(qcom_mdt_load);

MODULE_DESCRIPTION("Firmware parser for Qualcomm MDT format");
MODULE_LICENSE("GPL v2");
