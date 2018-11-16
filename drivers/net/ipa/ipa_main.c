// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */

#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/workqueue.h>
#include <linux/bug.h>
#include <linux/io.h>
#include <linux/clk.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/interrupt.h>
#include <linux/notifier.h>
#include <linux/remoteproc.h>
#include <linux/pm_wakeup.h>
#include <linux/kconfig.h>
#include <linux/qcom_scm.h>
#include <linux/soc/qcom/mdt_loader.h>
#include <linux/soc/qcom/smem.h>
#include <linux/soc/qcom/smem_state.h>
#include <linux/module.h>

#include "ipa_i.h"
#include "ipa_clock.h"
#include "ipahal.h"

/* The name of the main firmware file relative to /lib/firmware */
#define IPA_FWS_PATH		"ipa_fws.mdt"
#define IPA_PAS_ID		15

#define IPA_APPS_CMD_PROD_RING_COUNT	256
#define IPA_APPS_LAN_CONS_RING_COUNT	256

/* Details of the initialization sequence are determined by who is
 * responsible for doing some early IPA hardware initialization.
 * The Device Tree compatible string defines what to expect.
 */
enum ipa_init_type {
	ipa_undefined_init = 0,
	ipa_tz_init,
	ipa_modem_init,
};

struct ipa_match_data {
	enum ipa_init_type init_type;
};

static struct ipa_context ipa_ctx_struct;
struct ipa_context *ipa_ctx = &ipa_ctx_struct;

static struct ipa_context *ipa_create(struct platform_device *pdev)
{
	struct ipa_context *ipa = ipa_ctx;

	ipa->pdev = pdev;
	dev_set_drvdata(&ipa->pdev->dev, ipa);

	return ipa;
}

static void ipa_destroy(struct ipa_context *ipa)
{
	dev_set_drvdata(&ipa->pdev->dev, NULL);
	ipa->pdev = NULL;
}

static int hdr_init_local_cmd(struct ipa_context *ipa, u32 offset, u32 size)
{
	struct device *dev = &ipa->pdev->dev;
	struct ipa_desc desc = { };
	dma_addr_t phys;
	void *payload;
	void *virt;
	int ret;

	virt = dma_zalloc_coherent(dev, size, &phys, GFP_KERNEL);
	if (!virt)
		return -ENOMEM;

	offset += ipa->smem_offset;

	payload = ipahal_hdr_init_local_pyld(phys, size, offset);
	if (!payload) {
		ret = -ENOMEM;
		goto err_dma_free;
	}

	desc.type = IPA_IMM_CMD_DESC;
	desc.len_opcode = IPA_IMM_CMD_HDR_INIT_LOCAL;
	desc.payload = payload;

	ret = ipa_send_cmd(&desc);

	ipahal_payload_free(payload);
err_dma_free:
	dma_free_coherent(dev, size, virt, phys);

	return ret;
}

static int
dma_shared_mem_zero_cmd(struct ipa_context *ipa, u32 offset, u32 size)
{
	struct device *dev = &ipa->pdev->dev;
	struct ipa_desc desc = { };
	dma_addr_t phys;
	void *payload;
	void *virt;
	int ret;

	ipa_assert(size > 0);

	virt = dma_zalloc_coherent(dev, size, &phys, GFP_KERNEL);
	if (!virt)
		return -ENOMEM;

	offset += ipa->smem_offset;

	payload = ipahal_dma_shared_mem_write_pyld(phys, size, offset);
	if (!payload) {
		ret = -ENOMEM;
		goto err_dma_free;
	}

	desc.type = IPA_IMM_CMD_DESC;
	desc.len_opcode = IPA_IMM_CMD_DMA_SHARED_MEM;
	desc.payload = payload;

	ret = ipa_send_cmd(&desc);

	ipahal_payload_free(payload);
err_dma_free:
	dma_free_coherent(dev, size, virt, phys);

	return ret;
}

/**
 * ipa_modem_smem_init() - Initialize modem general memory and header memory
 */
int ipa_modem_smem_init(struct ipa_context *ipa)
{
	int ret;

	ret = dma_shared_mem_zero_cmd(ipa, IPA_MEM_MODEM_OFST,
				      IPA_MEM_MODEM_SIZE);
	if (ret)
		return ret;

	ret = dma_shared_mem_zero_cmd(ipa, IPA_MEM_MODEM_HDR_OFST,
				      IPA_MEM_MODEM_HDR_SIZE);
	if (ret)
		return ret;

	return dma_shared_mem_zero_cmd(ipa, IPA_MEM_MODEM_HDR_PROC_CTX_OFST,
				       IPA_MEM_MODEM_HDR_PROC_CTX_SIZE);
}

static int ipa_ep_apps_cmd_prod_setup(struct ipa_context *ipa)
{
	enum ipa_client_type dst_client;
	enum ipa_client_type client;
	u32 channel_count;
	u32 ep_id;
	int ret;

	client = IPA_CLIENT_APPS_CMD_PROD;
	dst_client = IPA_CLIENT_APPS_LAN_CONS;
	channel_count = IPA_APPS_CMD_PROD_RING_COUNT;

	ret = ipa_ep_alloc(ipa, client);
	if (ret < 0)
		return ret;
	ep_id = ret;

	ipa_endp_init_mode_prod(ipa, ep_id, IPA_DMA, dst_client);
	ipa_endp_init_seq_prod(ipa, ep_id);
	ipa_endp_init_deaggr_prod(ipa, ep_id);

	ret = ipa_ep_setup(ipa, ep_id, channel_count, 2, 0, NULL, NULL);
	if (ret)
		ipa_ep_free(ipa, ep_id);
	else
		ipa->cmd_prod_ep_id = ep_id;

	return ret;
}

/* Only used for IPA_MEM_UC_EVENT_RING_OFST, which must be 1KB aligned */
static __always_inline void sram_set_canary(u32 *sram_mmio, u32 offset)
{
	BUILD_BUG_ON(offset < sizeof(*sram_mmio));
	BUILD_BUG_ON(offset % 1024);

	sram_mmio += offset / sizeof(*sram_mmio);
	*--sram_mmio = IPA_MEM_CANARY_VAL;
}

static __always_inline void sram_set_canaries(u32 *sram_mmio, u32 offset)
{
	BUILD_BUG_ON(offset < 2 * sizeof(*sram_mmio));
	BUILD_BUG_ON(offset % 8);

	sram_mmio += offset / sizeof(*sram_mmio);
	*--sram_mmio = IPA_MEM_CANARY_VAL;
	*--sram_mmio = IPA_MEM_CANARY_VAL;
}

/**
 * ipa_smem_init() - Initialize IPA shared memory
 *
 * Return:	0 if successful, or a negative error code
 */
static int ipa_smem_init(struct ipa_context *ipa)
{
	struct ipa_reg_shared_mem_size mem_size;
	phys_addr_t phys_addr;
	u32 *ipa_sram_mmio;
	u32 size;

	/* Get the location and size of the shared memory area */
	ipa_read_reg_fields(IPA_SHARED_MEM_SIZE, &mem_size);

	/* The fields in the register are in 8 byte units */
	size = mem_size.shared_mem_size * 8;
	ipa_debug("sram size 0x%x bytes\n", size);
	if (size < IPA_MEM_END_OFST)
		return -ENOSPC;
	ipa->smem_size = size;

	ipa->smem_offset = mem_size.shared_mem_baddr * 8;
	ipa_debug("sram offset 0x%x bytes\n", ipa->smem_offset);

	/* Now write "canary" values at the end of subsections of
	 * the shared memory area.  (They're actually written
	 * *before* section offsets, but the effect is the same.)
	 */
	phys_addr = ipa->ipa_phys;
	phys_addr += ipa_reg_n_offset(IPA_SRAM_DIRECT_ACCESS_N, 0);
	phys_addr += ipa->smem_offset;

	ipa_sram_mmio = ioremap(phys_addr, ipa->smem_size);
	if (!ipa_sram_mmio) {
		ipa->smem_offset = 0;
		ipa->smem_size = 0;
		return -ENOMEM;
	}

	sram_set_canaries(ipa_sram_mmio, IPA_MEM_V4_FLT_HASH_OFST);
	sram_set_canaries(ipa_sram_mmio, IPA_MEM_V4_FLT_NHASH_OFST);
	sram_set_canaries(ipa_sram_mmio, IPA_MEM_V6_FLT_HASH_OFST);
	sram_set_canaries(ipa_sram_mmio, IPA_MEM_V6_FLT_NHASH_OFST);
	sram_set_canaries(ipa_sram_mmio, IPA_MEM_V4_RT_HASH_OFST);
	sram_set_canaries(ipa_sram_mmio, IPA_MEM_V4_RT_NHASH_OFST);
	sram_set_canaries(ipa_sram_mmio, IPA_MEM_V6_RT_HASH_OFST);
	sram_set_canaries(ipa_sram_mmio, IPA_MEM_V6_RT_NHASH_OFST);
	sram_set_canaries(ipa_sram_mmio, IPA_MEM_MODEM_HDR_OFST);
	sram_set_canaries(ipa_sram_mmio, IPA_MEM_MODEM_HDR_PROC_CTX_OFST);
	sram_set_canaries(ipa_sram_mmio, IPA_MEM_MODEM_OFST);

	/* Only one canary precedes the microcontroller ring */
	sram_set_canary(ipa_sram_mmio, IPA_MEM_UC_EVENT_RING_OFST);

	iounmap(ipa_sram_mmio);

	return 0;
}

static void ipa_smem_exit(struct ipa_context *ipa)
{
	ipa->smem_offset = 0;
	ipa->smem_size = 0;
}

/**
 * ipa_header_config() - Configure IPA AP and modem header areas
 *
 * Initialize memory areas used for AP and modem header structures.
 * No inverse is required for this function.
 *
 * Return:	0 if successful, or a negative error code
 */
static int ipa_header_config(struct ipa_context *ipa)
{
	int ret;

	if (IPA_MEM_MODEM_HDR_SIZE) {
		ret = hdr_init_local_cmd(ipa, IPA_MEM_MODEM_HDR_OFST,
					 IPA_MEM_MODEM_HDR_SIZE);
		if (ret)
			return ret;
	}

	if (IPA_MEM_APPS_HDR_SIZE) {
		BUILD_BUG_ON(IPA_MEM_APPS_HDR_OFST % 8);
		ret = hdr_init_local_cmd(ipa, IPA_MEM_APPS_HDR_OFST,
					 IPA_MEM_APPS_HDR_SIZE);
		if (ret)
			return ret;
	}

	if (IPA_MEM_MODEM_HDR_PROC_CTX_SIZE) {
		ret = dma_shared_mem_zero_cmd(ipa,
					      IPA_MEM_MODEM_HDR_PROC_CTX_OFST,
					      IPA_MEM_MODEM_HDR_PROC_CTX_SIZE);
		if (ret)
			return ret;
	}

	if (IPA_MEM_APPS_HDR_PROC_CTX_SIZE) {
		BUILD_BUG_ON(IPA_MEM_APPS_HDR_PROC_CTX_OFST % 8);
		ret = dma_shared_mem_zero_cmd(ipa,
					      IPA_MEM_APPS_HDR_PROC_CTX_OFST,
					      IPA_MEM_APPS_HDR_PROC_CTX_SIZE);
		if (ret)
			return ret;
	}

	ipa_write_reg(IPA_LOCAL_PKT_PROC_CNTXT_BASE,
		      ipa->smem_offset + IPA_MEM_MODEM_HDR_PROC_CTX_OFST);

	return 0;
}

/**
 * ipa_route_ipv4_config() - Configure IPA routing for IPv4.
 *
 * Configure IPA for IPv4 routing.  This function requires no inverse.
 *
 * Return:	0 if successful, or a negative error code
 */
static int
ipa_route_ipv4_config(struct ipa_context *ipa, dma_addr_t phys, size_t size)
{
	struct ipa_desc desc = { };
	u32 nhash_offset;
	u32 hash_offset;
	void *payload;
	int ret;

	hash_offset = ipa->smem_offset + IPA_MEM_V4_RT_HASH_OFST;
	nhash_offset = ipa->smem_offset + IPA_MEM_V4_RT_NHASH_OFST;
	payload = ipa_imm_ip_fltrt_init_pyld(phys, size, hash_offset,
					     nhash_offset);
	if (!payload)
		return -ENOMEM;

	desc.type = IPA_IMM_CMD_DESC;
	desc.len_opcode = IPA_IMM_CMD_IP_V4_ROUTING_INIT;
	desc.payload = payload;

	ret = ipa_send_cmd(&desc);

	ipahal_payload_free(payload);

	return ret;
}

/**
 * ipa_route_ipv6_config() - Configure IPA routing for IPv4.
 *
 * Configure IPA for IPv6 routing.  This function requires no inverse.
 *
 * Return:	0 if successful, or a negative error code
 */
static int
ipa_route_ipv6_config(struct ipa_context *ipa, dma_addr_t phys, size_t size)
{
	struct ipa_desc desc = { };
	u32 nhash_offset;
	u32 hash_offset;
	void *payload;
	int ret;

	hash_offset = ipa->smem_offset + IPA_MEM_V6_RT_HASH_OFST;
	nhash_offset = ipa->smem_offset + IPA_MEM_V6_RT_NHASH_OFST;
	payload = ipa_imm_ip_fltrt_init_pyld(phys, size, hash_offset,
					     nhash_offset);
	if (!payload)
		return -ENOMEM;

	desc.type = IPA_IMM_CMD_DESC;
	desc.len_opcode = IPA_IMM_CMD_IP_V6_ROUTING_INIT;
	desc.payload = payload;

	ret = ipa_send_cmd(&desc);

	ipahal_payload_free(payload);

	return ret;
}

/**
 * ipa_filter_ipv4_config() - Configure IPA filtering for IPv4.
 *
 * Configure IPA for IPv4 filtering.  This function requires no inverse.
 *
 * Return:	0 if successful, or a negative error code
 */
static int
ipa_filter_ipv4_config(struct ipa_context *ipa, dma_addr_t phys, size_t size)
{
	struct ipa_desc desc = { };
	u32 nhash_offset;
	u32 hash_offset;
	void *payload;
	int ret;

	hash_offset = ipa->smem_offset + IPA_MEM_V4_FLT_HASH_OFST;
	nhash_offset = ipa->smem_offset + IPA_MEM_V4_FLT_NHASH_OFST;
	payload = ipa_imm_ip_fltrt_init_pyld(phys, size, hash_offset,
					     nhash_offset);
	if (!payload)
		return -ENOMEM;

	desc.type = IPA_IMM_CMD_DESC;
	desc.len_opcode = IPA_IMM_CMD_IP_V4_FILTER_INIT;
	desc.payload = payload;

	ret = ipa_send_cmd(&desc);

	ipahal_payload_free(payload);

	return ret;
}

/**
 * ipa_filter_ipv6_config() - Configure IPA filtering for IPv6.
 *
 * Configure IPA for IPv6 filtering.  This function requires no inverse.
 *
 * Return:	0 if successful, or a negative error code
 */
static int
ipa_filter_ipv6_config(struct ipa_context *ipa, dma_addr_t phys, size_t size)
{
	struct ipa_desc desc = { };
	u32 nhash_offset;
	u32 hash_offset;
	void *payload;
	int ret;

	hash_offset = ipa->smem_offset + IPA_MEM_V6_FLT_HASH_OFST;
	nhash_offset = ipa->smem_offset + IPA_MEM_V6_FLT_NHASH_OFST;
	payload = ipa_imm_ip_fltrt_init_pyld(phys, size, hash_offset,
					     nhash_offset);
	if (!payload)
		return -ENOMEM;

	desc.type = IPA_IMM_CMD_DESC;
	desc.len_opcode = IPA_IMM_CMD_IP_V6_FILTER_INIT;
	desc.payload = payload;

	ret = ipa_send_cmd(&desc);

	ipahal_payload_free(payload);

	return ret;
}

static void ipa_filter_hash_tuple_config(struct ipa_context *ipa)
{
	u32 ep_mask = ipa->filter_bitmap;

	while (ep_mask) {
		u32 i = __ffs(ep_mask);

		ep_mask ^= BIT(i);
		if (!ipa_is_modem_ep(i))
			ipa_set_flt_tuple_mask(i);
	}
}

static void ipa_route_hash_tuple_config(struct ipa_context *ipa)
{
	u32 route_mask;
	u32 modem_mask;

	BUILD_BUG_ON(!IPA_MEM_MODEM_RT_COUNT);
	BUILD_BUG_ON(IPA_MEM_RT_COUNT < IPA_MEM_MODEM_RT_COUNT);

	/* Compute a mask representing non-modem route table entries */
	route_mask = GENMASK(IPA_MEM_RT_COUNT - 1, 0);
	modem_mask = GENMASK(IPA_MEM_MODEM_RT_INDEX_MAX,
			     IPA_MEM_MODEM_RT_INDEX_MIN);
	route_mask &= ~modem_mask;

	while (route_mask) {
		u32 i = __ffs(route_mask);

		route_mask ^= BIT(i);
		ipa_set_rt_tuple_mask(i);
	}
}

static int ipa_ep_apps_lan_cons_setup(struct ipa_context *ipa)
{
	enum ipa_client_type client;
	u32 rx_buffer_size;
	u32 channel_count;
	u32 aggr_count;
	u32 aggr_bytes;
	u32 aggr_size;
	u32 ep_id;
	int ret;

	client = IPA_CLIENT_APPS_LAN_CONS;
	channel_count = IPA_APPS_LAN_CONS_RING_COUNT;
	aggr_count = IPA_GENERIC_AGGR_PKT_LIMIT;
	aggr_bytes = IPA_GENERIC_AGGR_BYTE_LIMIT;

	if (aggr_bytes > ipa_reg_aggr_max_byte_limit())
		return -EINVAL;

	if (aggr_count > ipa_reg_aggr_max_packet_limit())
		return -EINVAL;

	if (ipa->lan_cons_ep_id != IPA_EP_ID_BAD)
		return -EBUSY;

	/* Compute the buffer size required to handle the requested
	 * aggregation byte limit.  The aggr_byte_limit value is
	 * expressed as a number of KB, but we derive that value
	 * after computing the buffer size to use (in bytes).  The
	 * buffer must be sufficient to hold one IPA_MTU-sized
	 * packet *after* the limit is reached.
	 *
	 * (Note that the rx_buffer_size value reflects only the
	 * space for data, not any standard metadata or headers.)
	 */
	rx_buffer_size = ipa_aggr_byte_limit_buf_size(aggr_bytes);

	/* Account for the extra IPA_MTU past the limit in the
	 * buffer, and convert the result to the KB units the
	 * aggr_byte_limit uses.
	 */
	aggr_size = (rx_buffer_size - IPA_MTU) / SZ_1K;

	ret = ipa_ep_alloc(ipa, client);
	if (ret < 0)
		return ret;
	ep_id = ret;

	ipa_endp_init_hdr_cons(ipa, ep_id, IPA_LAN_RX_HEADER_LENGTH, 0, 0);
	ipa_endp_init_hdr_ext_cons(ipa, ep_id, ilog2(sizeof(u32)), false);
	ipa_endp_init_aggr_cons(ipa, ep_id, aggr_size, aggr_count, false);
	ipa_endp_init_cfg_cons(ipa, ep_id, IPA_CS_OFFLOAD_DL);
	ipa_endp_init_hdr_metadata_mask_cons(ipa, ep_id, 0x0);
	ipa_endp_status_cons(ipa, ep_id, true);

	ret = ipa_ep_setup(ipa, ep_id, channel_count, 1, rx_buffer_size,
			   ipa_lan_rx_cb, NULL);
	if (ret)
		ipa_ep_free(ipa, ep_id);
	else
		ipa->lan_cons_ep_id = ep_id;

	return ret;
}

/**
 * ipa_route_init() - Initialize an empty route table
 *
 * Each entry in the route table contains the DMA address of a route
 * descriptor.  A special zero descriptor is allocated that represents
 * "no route" and this function initializes all its entries to point
 * at that zero route.  The zero route is allocated with the table,
 * immediately past its end.
 *
 * Return:	0 if successful or -ENOMEM.
 */
static int ipa_route_init(struct ipa_context *ipa)
{
	struct device *dev = &ipa->pdev->dev;
	u64 zero_route_phys;
	dma_addr_t phys;
	size_t size;
	u64 *virt;	/* Assumes IPA_TABLE_ENTRY_SIZE is 64 bits */
	u32 i;

	/* Allocate the route table, with enough space at the end of
	 * the table to hold the zero route descriptor.  Initialize
	 * all filter table entries to point to the zero route.
	 */
	size = IPA_MEM_RT_COUNT * IPA_TABLE_ENTRY_SIZE;
	virt = dma_zalloc_coherent(dev, size + IPA_ROUTE_SIZE, &phys,
				   GFP_KERNEL);
	if (!virt)
		return -ENOMEM;
	ipa->route_virt = virt;
	ipa->route_phys = phys;

	/* Zero route is immediately after the route table */
	zero_route_phys = (u64)phys + size;

	for (i = 0; i < IPA_MEM_RT_COUNT; i++)
		*virt++ = zero_route_phys;

	ipa_route_ipv4_config(ipa, ipa->route_phys, size);
	ipa_route_ipv6_config(ipa, ipa->route_phys, size);

	ipa_route_hash_tuple_config(ipa);

	return 0;
}

/**
 * ipa_route_exit() - Inverse of ipa_route_init().
 */
static void ipa_route_exit(struct ipa_context *ipa)
{
	struct device *dev = &ipa->pdev->dev;
	size_t size;

	size = IPA_MEM_RT_COUNT * IPA_TABLE_ENTRY_SIZE;
	size += IPA_ROUTE_SIZE;

	dma_free_coherent(dev, size, ipa->route_virt, ipa->route_phys);
	ipa->route_virt = NULL;
	ipa->route_phys = 0;
}

/**
 * ipa_filter_init() - Initialize an empty filter table
 *
 * The filter table consists of a bitmask representing which endpoints
 * support filtering, followed by one table entry for each set bit
 * in the mask.  Each entry in the filter table contains the DMA
 * address of a filter descriptor.  A special zero descriptor is
 * allocated that represents "no filter" and this function initializes
 * all its entries to point at that zero filter.  The zero filter is
 * allocated with the table, immediately past its end.
 *
 * Return:	0 if successful or a negative error code.
 */
static int ipa_filter_init(struct ipa_context *ipa)
{
	struct device *dev = &ipa->pdev->dev;
	u64 zero_filter_phys;
	dma_addr_t phys;
	size_t size;
	u64 *virt;	/* Assumes IPA_TABLE_ENTRY_SIZE is 64 bits */
	u32 i;

	/* Compute the bitmap of endpoints that support filtering. */
	ipa->filter_bitmap = ipa_filter_bitmap_init();
	ipa_debug("filter_bitmap 0x%08x\n", ipa->filter_bitmap);
	if (!ipa->filter_bitmap)
		return -EINVAL;

	/* Allocate the filter table, with an extra slot for the bitmap.
	 * Also allocate enough space at the end of the table to hold
	 * the * zero filter descriptor.  Initialize all filter table
	 * entries point to that.
	 */
	ipa->filter_count = hweight32(ipa->filter_bitmap);
	size = (ipa->filter_count + 1) * IPA_TABLE_ENTRY_SIZE;
	virt = dma_zalloc_coherent(dev, size + IPA_FILTER_SIZE, &phys,
				   GFP_KERNEL);
	if (!virt)
		goto err_clear_filter_count;
	ipa->filter_virt = virt;
	ipa->filter_phys = phys;

	/* Zero filter is immediately after the filter table */
	zero_filter_phys = (u64)phys + size;

	/* Save the filter table bitmap.  The "soft" bitmap value
	 * must be converted to the hardware representation by
	 * shifting it left one position.  (Bit 0 represents global
	 * filtering, which is possible but not used.)
	 */
	*virt++ = (u64)ipa->filter_bitmap << 1;

	/* Now point every entry in the table at the empty filter */
	for (i = 0; i < ipa->filter_count; i++)
		*virt++ = zero_filter_phys;

	ipa_filter_ipv4_config(ipa, ipa->filter_phys, size);
	ipa_filter_ipv6_config(ipa, ipa->filter_phys, size);

	ipa_filter_hash_tuple_config(ipa);

	return 0;

err_clear_filter_count:
	ipa->filter_count = 0;
	ipa->filter_bitmap = 0;

	return -ENOMEM;
}

/**
 * ipa_filter_exit() - Inverse of ipa_filter_init().
 */
static void ipa_filter_exit(struct ipa_context *ipa)
{
	struct device *dev = &ipa->pdev->dev;
	size_t size;

	size = (ipa->filter_count + 1) * IPA_TABLE_ENTRY_SIZE;
	size += IPA_FILTER_SIZE;

	dma_free_coherent(dev, size, ipa->filter_virt, ipa->filter_phys);
	ipa->filter_virt = NULL;
	ipa->filter_phys = 0;
	ipa->filter_count = 0;
	ipa->filter_bitmap = 0;
}

static int ipa_irq_init(struct ipa_context *ipa)
{
	int ret;

	ret = platform_get_irq_byname(ipa->pdev, "ipa");
	if (ret < 0)
		return ret;
	ipa->ipa_irq = ret;

	return 0;
}

static void ipa_irq_exit(struct ipa_context *ipa)
{
	ipa->ipa_irq = 0;
}

static int ipa_ep_apps_setup(struct ipa_context *ipa)
{
	int ret;

	/* We need to use the AP command out endpoint to perform
	 * initialization, so we set that up first.
	 */
	ret = ipa_ep_apps_cmd_prod_setup(ipa);
	if (ret < 0)
		return ret;

	ret = ipa_header_config(ipa);
	if (ret)
		goto err_cmd_prod_teardown;

	ret = ipa_route_init(ipa);
	if (ret)
		goto err_cmd_prod_teardown;

	ret = ipa_filter_init(ipa);
	if (ret)
		goto err_route_exit;

	/* LAN IN (IPA->AP)
	 *
	 * Even without supporting LAN traffic, we use the LAN consumer
	 * endpoint for receiving some information from the IPA.  If we issue
	 * a tagged command, we arrange to be notified of its completion
	 * through this endpoint.  In addition, we arrange for this endpoint
	 * to be used as the IPA's default route; the IPA will notify the AP
	 * of exceptions (unroutable packets, but other events as well)
	 * through this endpoint.
	 */
	ret = ipa_ep_apps_lan_cons_setup(ipa);
	if (ret < 0)
		goto err_filter_exit;

	ipa_cfg_default_route(ipa, IPA_CLIENT_APPS_LAN_CONS);

	return 0;

err_filter_exit:
	ipa_filter_exit(ipa);
err_route_exit:
	ipa_route_exit(ipa);
err_cmd_prod_teardown:
	ipa_ep_teardown(ipa, ipa->cmd_prod_ep_id);
	ipa->cmd_prod_ep_id = IPA_EP_ID_BAD;

	return ret;
}

static void ipa_ep_apps_teardown(struct ipa_context *ipa)
{
	ipa_ep_teardown(ipa, ipa->lan_cons_ep_id);
	ipa->lan_cons_ep_id = IPA_EP_ID_BAD;

	ipa_filter_exit(ipa);
	ipa_route_exit(ipa);

	ipa_ep_teardown(ipa, ipa->cmd_prod_ep_id);
	ipa->cmd_prod_ep_id = IPA_EP_ID_BAD;
}

static int ipa_mem_init(struct ipa_context *ipa)
{
	struct resource *res;
	int ret;

	ret = dma_set_mask_and_coherent(&ipa->pdev->dev, DMA_BIT_MASK(64));
	if (ret)
		return ret;

	/* Get IPA memory range */
	res = platform_get_resource_byname(ipa->pdev, IORESOURCE_MEM, "ipa");
	if (!res)
		return -ENODEV;

	/* Setup IPA register access */
	ret = ipa_reg_init(res->start, (size_t)resource_size(res));
	if (ret)
		return ret;

	ipa->ipa_phys = res->start;

	return 0;
}

static void ipa_mem_exit(struct ipa_context *ipa)
{
	ipa->ipa_phys = 0;
	ipa_reg_exit();
}

/** ipa_inc_acquire_wakelock() - Increase active clients counter, and
 * acquire wakelock if necessary
 */
void ipa_inc_acquire_wakelock(struct ipa_context *ipa)
{
	unsigned long flags;

	spin_lock_irqsave(&ipa->wakeup_lock, flags);

	ipa->wakeup_count++;
	if (ipa->wakeup_count == 1)
		__pm_stay_awake(&ipa->wakeup);

	spin_unlock_irqrestore(&ipa->wakeup_lock, flags);
}

/** ipa_dec_release_wakelock() - Decrease active clients counter
 *
 * In case if the ref count is 0, release the wakelock.
 */
void ipa_dec_release_wakelock(struct ipa_context *ipa)
{
	unsigned long flags;

	spin_lock_irqsave(&ipa->wakeup_lock, flags);

	ipa->wakeup_count--;
	if (ipa->wakeup_count == 0)
		__pm_relax(&ipa->wakeup);

	spin_unlock_irqrestore(&ipa->wakeup_lock, flags);
}

/** ipa_suspend_handler() - Handle the suspend interrupt
 * @interrupt:	Interrupt type
 * @endpoints:	Interrupt specific information data
 */
static void ipa_suspend_handler(enum ipa_irq_type interrupt, u32 interrupt_data)
{
	u32 endpoints = interrupt_data;

	while (endpoints) {
		enum ipa_client_type client;
		u32 i = __ffs(endpoints);

		endpoints ^= BIT(i);

		if (!ipa_ctx->ep[i].allocated)
			continue;

		client = ipa_ctx->ep[i].client;
		if (!ipa_ap_consumer(client))
			continue;

		/* endpoint will be unsuspended by enabling IPA clocks */
		mutex_lock(&ipa_ctx->transport_pm.transport_pm_mutex);
		if (!atomic_read(&ipa_ctx->transport_pm.dec_clients)) {
			ipa_clock_get(ipa_ctx);

			atomic_set(&ipa_ctx->transport_pm.dec_clients, 1);
		}
		mutex_unlock(&ipa_ctx->transport_pm.transport_pm_mutex);
	}
}

static void ipa_freeze_clock_vote_and_notify_modem(struct ipa_context *ipa)
{
	u32 value;
	u32 mask;

	if (ipa->smp2p_info.res_sent)
		return;

	if (!ipa->smp2p_info.enabled_state) {
		ipa_err("smp2p out gpio not assigned\n");
		return;
	}

	ipa->smp2p_info.ipa_clk_on = ipa_clock_get_additional(ipa);

	/* Signal whether the clock is enabled */
	mask = BIT(ipa->smp2p_info.enabled_bit);
	value = ipa->smp2p_info.ipa_clk_on ? mask : 0;
	qcom_smem_state_update_bits(ipa->smp2p_info.enabled_state, mask, value);

	/* Now indicate that the enabled flag is valid */
	mask = BIT(ipa->smp2p_info.valid_bit);
	value = mask;
	qcom_smem_state_update_bits(ipa->smp2p_info.valid_state, mask, value);

	ipa->smp2p_info.res_sent = true;
}

void ipa_reset_freeze_vote(struct ipa_context *ipa)
{
	u32 mask;

	if (!ipa->smp2p_info.res_sent)
		return;

	if (ipa->smp2p_info.ipa_clk_on)
		ipa_clock_put(ipa);

	/* Reset the clock enabled valid flag */
	mask = BIT(ipa->smp2p_info.valid_bit);
	qcom_smem_state_update_bits(ipa->smp2p_info.valid_state, mask, 0);

	/* Mark the clock disabled for good measure... */
	mask = BIT(ipa->smp2p_info.enabled_bit);
	qcom_smem_state_update_bits(ipa->smp2p_info.enabled_state, mask, 0);

	ipa->smp2p_info.res_sent = false;
	ipa->smp2p_info.ipa_clk_on = false;
}

static int
ipa_panic_notifier(struct notifier_block *nb, unsigned long action, void *data)
{
	struct ipa_context *ipa;

	ipa = container_of(nb, struct ipa_context, panic_notifier);
	ipa_freeze_clock_vote_and_notify_modem(ipa);
	ipa_uc_panic_notifier();

	return NOTIFY_DONE;
}

static int ipa_panic_notifier_register(struct ipa_context *ipa)
{
	/* IPA panic handler needs to run before modem shuts down */
	ipa->panic_notifier.notifier_call = ipa_panic_notifier;
	ipa->panic_notifier.priority = INT_MAX;	/* Do it early */

	return atomic_notifier_chain_register(&panic_notifier_list,
					      &ipa->panic_notifier);
}

static void ipa_panic_notifier_unregister(struct ipa_context *ipa)
{
	atomic_notifier_chain_unregister(&panic_notifier_list,
					 &ipa->panic_notifier);
	memset(&ipa->panic_notifier, 0, sizeof(ipa->panic_notifier));
}

/* Remoteproc callbacks for SSR events: prepare, start, stop, unprepare */
int ipa_ssr_prepare(struct rproc_subdev *subdev)
{
	printk("======== SSR prepare received ========\n");
	return 0;
}
EXPORT_SYMBOL_GPL(ipa_ssr_prepare);

int ipa_ssr_start(struct rproc_subdev *subdev)
{
	printk("======== SSR start received ========\n");
	return 0;
}
EXPORT_SYMBOL_GPL(ipa_ssr_start);

void ipa_ssr_stop(struct rproc_subdev *subdev, bool crashed)
{
	printk("======== SSR stop received ========\n");
}
EXPORT_SYMBOL_GPL(ipa_ssr_stop);

void ipa_ssr_unprepare(struct rproc_subdev *subdev)
{
	printk("======== SSR unprepare received ========\n");
}
EXPORT_SYMBOL_GPL(ipa_ssr_unprepare);

/**
 * ipa_post_init() - Initialize the IPA Driver (Part II).
 *
 * Perform initialization that requires interaction with IPA hardware.
 */
static int ipa_post_init(struct ipa_context *ipa)
{
	int ret;

	ipa_debug("ipa_post_init() started\n");

	ipa->gsi = gsi_init(ipa->pdev);
	if (IS_ERR(ipa->gsi)) {
		ret = PTR_ERR(ipa->gsi);
		ipa->gsi = NULL;
		return ret;
	}

	/* setup the AP-IPA endpoints */
	ret = ipa_ep_apps_setup(ipa);
	if (ret)
		goto err_gsi_exit;

	ipa->uc_ctx = ipa_uc_init(ipa->ipa_phys);
	if (!ipa->uc_ctx) {
		ret = -ENOMEM;
		goto err_ep_teardown;
	}

	ret = ipa_panic_notifier_register(ipa);
	if (ret)
		goto err_uc_exit;

	ipa->proxy_held = true;

	ipa->wwan = ipa_wwan_init();
	if (IS_ERR(ipa->wwan)) {
		ret = PTR_ERR(ipa->wwan);
		goto err_clear_wwan;
	}

	ipa->post_init_complete = true;

	dev_info(&ipa->pdev->dev,
		 "IPA driver initialization was successful.\n");

	return 0;

err_clear_wwan:
	ipa->wwan = NULL;
	ipa_panic_notifier_unregister(ipa);
err_uc_exit:
	/* XXX ipa_uc_exit(); */
err_ep_teardown:
	ipa_ep_apps_teardown(ipa);
err_gsi_exit:
	gsi_exit(ipa->gsi);

	return ret;
}

static void ipa_post_exit(struct ipa_context *ipa)
{
	ipa->post_init_complete = false;

	if (ipa->wwan) {
		ipa_wwan_cleanup(ipa->wwan);
		ipa->wwan = NULL;
	}

	ipa_panic_notifier_unregister(ipa);

	ipa_ep_apps_teardown(ipa);
	gsi_exit(ipa->gsi);
}

/** ipa_pre_init() - Initialize the IPA Driver.
 *
 * Perform initialization which doesn't require access to IPA hardware.
 */
static int ipa_pre_init(struct ipa_context *ipa)
{
	int ret;

	ipa->cmd_prod_ep_id = IPA_EP_ID_BAD;
	ipa->lan_cons_ep_id = IPA_EP_ID_BAD;

	ipa_clock_get(ipa);

	ipa_hardware_init(ipa);

	ret = ipa_smem_init(ipa);
	if (ret)
		goto err_clock_put;

	ret = ipa_ep_init(ipa);
	if (ret)
		goto err_smem_exit;

	ret = ipa_dp_init(ipa);
	if (ret)
		goto err_ep_exit;

	/* allocate memory for DMA_TASK workaround */
	mutex_init(&ipa->transport_pm.transport_pm_mutex);

	ret = ipa_gsi_dma_task_alloc(ipa);
	if (ret)
		goto err_dp_exit;

	/* Create a wakeup source. */
	wakeup_source_init(&ipa->wakeup, "IPA_WS");
	spin_lock_init(&ipa->wakeup_lock);

	mutex_init(&ipa->post_init_mutex);

	/* Note enabling dynamic clock division must not be
	 * attempted for IPA hardware versions prior to 3.5.
	 */
	ipa_enable_dcd();

	/* Assign resource limitation to each group */
	ipa_set_resource_groups_min_max_limits();

	ret = ipa_interrupts_init(ipa);
	if (ret)
		goto err_dp_exit;

	ipa_add_interrupt_handler(IPA_TX_SUSPEND_IRQ, ipa_suspend_handler);

	return 0;

err_dp_exit:
	ipa_dp_exit(ipa);
err_ep_exit:
	ipa_ep_exit(ipa);
err_smem_exit:
	ipa_smem_exit(ipa);
err_clock_put:
	ipa_clock_put(ipa);
	ipa->lan_cons_ep_id = 0;
	ipa->cmd_prod_ep_id = 0;

	return ret;
}

static void ipa_pre_exit(struct ipa_context *ipa)
{
	ipa_remove_interrupt_handler(IPA_TX_SUSPEND_IRQ);
	ipa_interrupts_exit(ipa);
	mutex_destroy(&ipa->post_init_mutex);
	wakeup_source_trash(&ipa->wakeup);
	ipa_gsi_dma_task_free(ipa);
	mutex_destroy(&ipa->transport_pm.transport_pm_mutex);
	ipa_dp_exit(ipa);
	ipa_ep_exit(ipa);
	ipa_smem_exit(ipa);
	ipa_clock_put(ipa);
}

static int ipa_firmware_load(struct device *dev)
{
	const struct firmware *fw;
	struct device_node *node;
	struct resource res;
	phys_addr_t phys;
	ssize_t size;
	void *virt;
	int ret;

	ret = request_firmware(&fw, IPA_FWS_PATH, dev);
	if (ret)
		return ret;

	node = of_parse_phandle(dev->of_node, "memory-region", 0);
	if (!node) {
		dev_err(dev, "memory-region not specified\n");
		ret = -EINVAL;
		goto out_release_firmware;
	}

	ret = of_address_to_resource(node, 0, &res);
	if (ret)
		goto out_release_firmware;

	phys = res.start,
	size = (size_t)resource_size(&res);
	virt = memremap(phys, size, MEMREMAP_WC);
	if (!virt) {
		ret = -ENOMEM;
		goto out_release_firmware;
	}

	ret = qcom_mdt_load(dev, fw, IPA_FWS_PATH, IPA_PAS_ID,
			    virt, phys, size, NULL);
	if (!ret)
		ret = qcom_scm_pas_auth_and_reset(IPA_PAS_ID);

	memunmap(virt);
out_release_firmware:
	release_firmware(fw);

	return ret;
}

/* Threaded IRQ handler for modem "ipa-clock-query" SMP2P interrupt */
static irqreturn_t ipa_smp2p_modem_clk_query_isr(int irq, void *dev_id)
{
	struct ipa_context *ipa = dev_id;

	ipa_freeze_clock_vote_and_notify_modem(ipa);

	return IRQ_HANDLED;
}

/* Threaded IRQ handler for modem "ipa-post-init" SMP2P interrupt */
static irqreturn_t ipa_smp2p_modem_post_init_isr(int irq, void *dev_id)
{
	struct ipa_context *ipa = dev_id;

	mutex_lock(&ipa->post_init_mutex);
	if (!ipa->shutting_down)
		(void)ipa_post_init(ipa);
	mutex_lock(&ipa->post_init_mutex);

	return IRQ_HANDLED;
}

static int ipa_smp2p_irq_init(struct ipa_context *ipa, const char *name,
			      irq_handler_t handler)
{
	unsigned int irq;
	int ret;

	ret = platform_get_irq_byname(ipa->pdev, name);
	if (ret < 0)
		return ret;
	if (!ret)
		return -EINVAL;		/* IRQ mapping failure */
	irq = ret;

	ret = request_threaded_irq(irq, NULL, handler, 0, name, ipa);
	if (ret)
		return ret;

	return irq;
}

static void ipa_smp2p_irq_exit(struct ipa_context *ipa, unsigned int irq)
{
	free_irq(irq, ipa);
}

static int ipa_smp2p_init(struct ipa_context *ipa, bool modem_init)
{
	struct qcom_smem_state *enabled_state;
	struct device *dev = &ipa->pdev->dev;
	struct qcom_smem_state *valid_state;
	unsigned int enabled_bit;
	unsigned int valid_bit;
	unsigned int clock_irq;
	int ret;

	valid_state = qcom_smem_state_get(dev, "ipa-clock-enabled-valid",
					  &valid_bit);
	if (IS_ERR(valid_state))
		return PTR_ERR(valid_state);

	enabled_state = qcom_smem_state_get(dev, "ipa-clock-enabled",
					    &enabled_bit);
	if (IS_ERR(enabled_state)) {
		ret = PTR_ERR(enabled_state);
		ipa_err("error %d getting ipa-clock-enabled state\n", ret);

		return ret;
	}

	ret = ipa_smp2p_irq_init(ipa, "ipa-clock-query",
				 ipa_smp2p_modem_clk_query_isr);
	if (ret < 0)
		return ret;
	clock_irq = ret;

	if (modem_init) {
		/* Result will be non-zero (negative for error) */
		ret = ipa_smp2p_irq_init(ipa, "ipa-post-init",
					 ipa_smp2p_modem_post_init_isr);
		if (ret < 0) {
			ipa_smp2p_irq_exit(ipa, clock_irq);

			return ret;
		}
	}

	/* Success.  Record our smp2p information */
	ipa->smp2p_info.valid_state = valid_state;
	ipa->smp2p_info.valid_bit = valid_bit;
	ipa->smp2p_info.enabled_state = enabled_state;
	ipa->smp2p_info.enabled_bit = enabled_bit;
	ipa->smp2p_info.clock_query_irq = clock_irq;
	ipa->smp2p_info.post_init_irq = modem_init ? ret : 0;

	return 0;
}

static void ipa_smp2p_exit(struct ipa_context *ipa)
{
	if (ipa->smp2p_info.post_init_irq)
		ipa_smp2p_irq_exit(ipa, ipa->smp2p_info.post_init_irq);
	ipa_smp2p_irq_exit(ipa, ipa->smp2p_info.clock_query_irq);

	memset(&ipa->smp2p_info, 0, sizeof(ipa->smp2p_info));
}

static const struct ipa_match_data tz_init = {
	.init_type = ipa_tz_init,
};

static const struct ipa_match_data modem_init = {
	.init_type = ipa_modem_init,
};

static const struct of_device_id ipa_plat_drv_match[] = {
	{
		.compatible = "qcom,sdm845-ipa-tz-init",
		.data = &tz_init,
	},
	{
		.compatible = "qcom,sdm845-ipa-modem-init",
		.data = &modem_init,
	},
	{}
};

static int ipa_plat_drv_probe(struct platform_device *pdev)
{
	const struct ipa_match_data *match_data;
	struct ipa_context *ipa;
	struct device *dev = &pdev->dev;
	bool modem_init;
	int ret;

	/* We assume we're working on 64-bit hardware */
	BUILD_BUG_ON(!IS_ENABLED(CONFIG_64BIT));
	BUILD_BUG_ON(ARCH_DMA_MINALIGN % IPA_TABLE_ALIGN);

	match_data = of_device_get_match_data(dev);
	modem_init = match_data->init_type == ipa_modem_init;

	/* If we need Trust Zone, make sure it's ready */
	if (!modem_init)
		if (!qcom_scm_is_available())
			return -EPROBE_DEFER;

	ipa = ipa_create(pdev);
	if (!ipa)
		return -ENOMEM;

	/* Initialize the smp2p driver early.  It might not be ready
	 * when we're probed, so it might return -EPROBE_DEFER.
	 */
	ret = ipa_smp2p_init(ipa, modem_init);
	if (ret)
		goto out_ipa_destroy;

	/* Initialize the clock and interconnects early too.  They
	 * could also return -EPROBE_DEFER.
	 */
	ret = ipa_clock_init(ipa);
	if (ret)
		goto out_smp2p_exit;

	ret = ipa_mem_init(ipa);
	if (ret)
		goto err_clock_exit;

	ret = ipa_irq_init(ipa);
	if (ret)
		goto err_mem_exit;

	/* Proceed to real initialization */
	ret = ipa_pre_init(ipa);
	if (ret)
		goto err_clear_ep_ids;

	/* If the modem is not verifying and loading firmware we need to
	 * get it loaded ourselves.  Only then can we proceed with the
	 * second stage of IPA initialization.  If the modem is doing it,
	 * it will send an SMP2P interrupt to signal this has been done,
	 * and that will trigger the "post init".
	 */
	if (!modem_init) {
		ret = ipa_firmware_load(dev);
		if (!ret)
			ret = ipa_post_init(ipa);
	}

	if (!ret)
		return 0;	/* Success */

	ipa_pre_exit(ipa);
err_clear_ep_ids:
	ipa_irq_exit(ipa);
err_mem_exit:
	ipa_mem_exit(ipa);
err_clock_exit:
	ipa_clock_exit(ipa);
out_smp2p_exit:
	ipa_smp2p_exit(ipa);
out_ipa_destroy:
	ipa_destroy(ipa);

	return ret;
}

static bool ipa_post_init_complete(struct ipa_context *ipa)
{
	if (ipa->smp2p_info.post_init_irq) {
		disable_irq(ipa->smp2p_info.post_init_irq);
		mutex_lock(&ipa->post_init_mutex);
		ipa->shutting_down = true;
		mutex_unlock(&ipa->post_init_mutex);
	}

	return ipa->post_init_complete;
}

static int ipa_plat_drv_remove(struct platform_device *pdev)
{
	struct ipa_context *ipa = dev_get_drvdata(&pdev->dev);

	if (ipa_post_init_complete(ipa))
		ipa_post_exit(ipa);

	ipa_pre_exit(ipa);
	if (ipa->lan_cons_ep_id != IPA_EP_ID_BAD) {
		ipa_ep_free(ipa, ipa->lan_cons_ep_id);
		ipa->lan_cons_ep_id = IPA_EP_ID_BAD;
	}
	if (ipa->cmd_prod_ep_id != IPA_EP_ID_BAD) {
		ipa_ep_free(ipa, ipa->cmd_prod_ep_id);
		ipa->cmd_prod_ep_id = IPA_EP_ID_BAD;
	}
	/* XXX ipa_gsi_exit(ipa) */
	ipa->gsi = NULL;
	ipa_mem_exit(ipa);
	ipa_irq_exit(ipa);
	ipa_clock_exit(ipa);
	ipa_smp2p_exit(ipa);
	ipa_destroy(ipa);

	return 0;
}

/**
 * ipa_ap_suspend() - suspend callback for runtime_pm
 * @dev:	IPA device structure
 *
 * This callback will be invoked by the runtime_pm framework when an AP suspend
 * operation is invoked, usually by pressing a suspend button.
 *
 * Return: 	0 if successful, -EAGAIN if IPA is in use
 */
int ipa_ap_suspend(struct device *dev)
{
	int ret;
	u32 i;

	ret = rmnet_ipa_ap_suspend(ipa_ctx->wwan);
	if (ret)
		return ret;

	/* In case there is a tx/rx handler in polling mode fail to suspend */
	for (i = 0; i < ipa_ctx->ep_count; i++) {
		struct ipa_ep_context *ep = &ipa_ctx->ep[i];

		if (ipa_consumer(ep->client) && ep->sys && ipa_ep_polling(ep)) {
			ret = -EAGAIN;
			break;
		}
	}
	if (ret)
		rmnet_ipa_ap_resume(ipa_ctx->wwan);

	return ret;
}

/**
 * ipa_ap_resume() - resume callback for runtime_pm
 * @dev:	IPA device structure
 *
 * This callback will be invoked by the runtime_pm framework when an AP resume
 * operation is invoked.
 *
 * Return:	Zero
 */
int ipa_ap_resume(struct device *dev)
{
	rmnet_ipa_ap_resume(ipa_ctx->wwan);

	return 0;
}

static const struct dev_pm_ops ipa_pm_ops = {
	.suspend_noirq = ipa_ap_suspend,
	.resume_noirq = ipa_ap_resume,
};

static struct platform_driver ipa_plat_drv = {
	.probe = ipa_plat_drv_probe,
	.remove = ipa_plat_drv_remove,
	.driver = {
		.name = "ipa",
		.owner = THIS_MODULE,
		.pm = &ipa_pm_ops,
		.of_match_table = ipa_plat_drv_match,
	},
};

builtin_platform_driver(ipa_plat_drv);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("IPA HW device driver");
