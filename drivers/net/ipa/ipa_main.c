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
#include "ipa_dma.h"
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

static void ipa_client_remove_deferred(struct work_struct *work);
static DECLARE_WORK(ipa_client_remove_work, ipa_client_remove_deferred);

static struct ipa_context ipa_ctx_struct;
struct ipa_context *ipa_ctx = &ipa_ctx_struct;

static int hdr_init_local_cmd(u32 offset, u32 size)
{
	struct ipa_desc desc = { };
	dma_addr_t phys;
	void *payload;
	void *virt;
	int ret;

	virt = dma_zalloc_coherent(ipa_ctx->dev, size, &phys, GFP_KERNEL);
	if (!virt)
		return -ENOMEM;

	offset += ipa_ctx->smem_offset;

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
	dma_free_coherent(ipa_ctx->dev, size, virt, phys);

	return ret;
}

static int dma_shared_mem_zero_cmd(u32 offset, u32 size)
{
	struct ipa_desc desc = { };
	struct ipa_dma_mem mem;
	void *payload;
	int ret;

	ipa_assert(size > 0);

	if (ipa_dma_alloc(&mem, size, GFP_KERNEL))
		return -ENOMEM;

	offset += ipa_ctx->smem_offset;

	payload = ipahal_dma_shared_mem_write_pyld(mem.phys, mem.size, offset);
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
	ipa_dma_free(&mem);

	return ret;
}

/**
 * ipa_modem_smem_init() - Initialize modem general memory and header memory
 */
int ipa_modem_smem_init(void)
{
	int ret;

	ret = dma_shared_mem_zero_cmd(IPA_MEM_MODEM_OFST, IPA_MEM_MODEM_SIZE);
	if (ret)
		return ret;

	ret = dma_shared_mem_zero_cmd(IPA_MEM_MODEM_HDR_OFST,
				      IPA_MEM_MODEM_HDR_SIZE);
	if (ret)
		return ret;

	return dma_shared_mem_zero_cmd(IPA_MEM_MODEM_HDR_PROC_CTX_OFST,
				       IPA_MEM_MODEM_HDR_PROC_CTX_SIZE);
}

static int ipa_ep_apps_cmd_prod_setup(void)
{
	enum ipa_client_type dst_client;
	enum ipa_client_type client;
	u32 channel_count;
	u32 ep_id;
	int ret;

	if (ipa_ctx->cmd_prod_ep_id != IPA_EP_ID_BAD)
		ret = -EBUSY;

	client = IPA_CLIENT_APPS_CMD_PROD;
	dst_client = IPA_CLIENT_APPS_LAN_CONS;
	channel_count = IPA_APPS_CMD_PROD_RING_COUNT;

	ret = ipa_ep_alloc(client);
	if (ret < 0)
		return ret;
	ep_id = ret;


	ipa_endp_init_mode_prod(ep_id, IPA_DMA, dst_client);
	ipa_endp_init_seq_prod(ep_id);
	ipa_endp_init_deaggr_prod(ep_id);

	ret = ipa_ep_setup(ep_id, channel_count, 2, 0, NULL, NULL);
	if (ret)
		ipa_ep_free(ep_id);
	else
		ipa_ctx->cmd_prod_ep_id = ep_id;

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
 * ipa_init_sram() - Initialize IPA local SRAM.
 *
 * Return:	0 if successful, or a negative error code
 */
static int ipa_init_sram(void)
{
	phys_addr_t phys_addr;
	u32 *ipa_sram_mmio;

	phys_addr = ipa_ctx->ipa_phys;
	phys_addr += ipa_reg_n_offset(IPA_SRAM_DIRECT_ACCESS_N, 0);
	phys_addr += ipa_ctx->smem_offset;

	ipa_sram_mmio = ioremap(phys_addr, ipa_ctx->smem_size);
	if (!ipa_sram_mmio) {
		ipa_err("fail to ioremap IPA SRAM\n");
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

/**
 * ipa_init_hdr() - Initialize IPA header block.
 *
 * Return:	0 if successful, or a negative error code
 */
static int ipa_init_hdr(void)
{
	int ret;

	if (IPA_MEM_MODEM_HDR_SIZE) {
		ret = hdr_init_local_cmd(IPA_MEM_MODEM_HDR_OFST,
					 IPA_MEM_MODEM_HDR_SIZE);
		if (ret)
			return ret;
	}

	if (IPA_MEM_APPS_HDR_SIZE) {
		BUILD_BUG_ON(IPA_MEM_APPS_HDR_OFST % 8);
		ret = hdr_init_local_cmd(IPA_MEM_APPS_HDR_OFST,
					 IPA_MEM_APPS_HDR_SIZE);
		if (ret)
			return ret;
	}

	if (IPA_MEM_MODEM_HDR_PROC_CTX_SIZE) {
		ret = dma_shared_mem_zero_cmd(IPA_MEM_MODEM_HDR_PROC_CTX_OFST,
					      IPA_MEM_MODEM_HDR_PROC_CTX_SIZE);
		if (ret)
			return ret;
	}

	if (IPA_MEM_APPS_HDR_PROC_CTX_SIZE) {
		BUILD_BUG_ON(IPA_MEM_APPS_HDR_PROC_CTX_OFST % 8);
		ret = dma_shared_mem_zero_cmd(IPA_MEM_APPS_HDR_PROC_CTX_OFST,
					      IPA_MEM_APPS_HDR_PROC_CTX_SIZE);
		if (ret)
			return ret;
	}

	ipa_write_reg(IPA_LOCAL_PKT_PROC_CNTXT_BASE, 0);

	return 0;
}

/**
 * ipa_init_rt4() - Initialize IPA routing block for IPv4.
 *
 * Return:	0 if successful, or a negative error code
 */
static int ipa_init_rt4(dma_addr_t phys, size_t size)
{
	struct ipa_desc desc = { };
	u32 nhash_offset;
	u32 hash_offset;
	void *payload;
	int ret;

	hash_offset = ipa_ctx->smem_offset + IPA_MEM_V4_RT_HASH_OFST;
	nhash_offset = ipa_ctx->smem_offset + IPA_MEM_V4_RT_NHASH_OFST;
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
 * ipa_init_rt6() - Initialize IPA routing block for IPv6.
 *
 * Return:	0 if successful, or a negative error code
 */
static int ipa_init_rt6(dma_addr_t phys, size_t size)
{
	struct ipa_desc desc = { };
	u32 nhash_offset;
	u32 hash_offset;
	void *payload;
	int ret;

	hash_offset = ipa_ctx->smem_offset + IPA_MEM_V6_RT_HASH_OFST;
	nhash_offset = ipa_ctx->smem_offset + IPA_MEM_V6_RT_NHASH_OFST;
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
 * ipa_init_flt4() - Initialize IPA filtering block for IPv4.
 *
 * Return:	0 if successful, or a negative error code
 */
static int ipa_init_flt4(dma_addr_t phys, size_t size)
{
	struct ipa_desc desc = { };
	u32 nhash_offset;
	u32 hash_offset;
	void *payload;
	int ret;

	hash_offset = ipa_ctx->smem_offset + IPA_MEM_V4_FLT_HASH_OFST;
	nhash_offset = ipa_ctx->smem_offset + IPA_MEM_V4_FLT_NHASH_OFST;
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
 * ipa_init_flt6() - Initialize IPA filtering block for IPv6.
 *
 * Return:	0 if successful, or a negative error code
 */
static int ipa_init_flt6(dma_addr_t phys, size_t size)
{
	struct ipa_desc desc = { };
	u32 nhash_offset;
	u32 hash_offset;
	void *payload;
	int ret;

	hash_offset = ipa_ctx->smem_offset + IPA_MEM_V6_FLT_HASH_OFST;
	nhash_offset = ipa_ctx->smem_offset + IPA_MEM_V6_FLT_NHASH_OFST;
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

static void ipa_setup_flt_hash_tuple(void)
{
	u32 ep_mask = ipa_ctx->filter_bitmap;

	while (ep_mask) {
		u32 i = __ffs(ep_mask);

		ep_mask ^= BIT(i);
		if (!ipa_is_modem_ep(i))
			ipa_set_flt_tuple_mask(i);
	}
}

static void ipa_setup_rt_hash_tuple(void)
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

static int ipa_ep_apps_lan_cons_setup(void)
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

	if (ipa_ctx->lan_cons_ep_id != IPA_EP_ID_BAD)
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

	ret = ipa_ep_alloc(client);
	if (ret < 0)
		return ret;
	ep_id = ret;

	ipa_endp_init_hdr_cons(ep_id, IPA_LAN_RX_HEADER_LENGTH, 0, 0);
	ipa_endp_init_hdr_ext_cons(ep_id, ilog2(sizeof(u32)), false);
	ipa_endp_init_aggr_cons(ep_id, aggr_size, aggr_count, false);
	ipa_endp_init_cfg_cons(ep_id, IPA_CS_OFFLOAD_DL);
	ipa_endp_init_hdr_metadata_mask_cons(ep_id, 0x0);
	ipa_endp_status_cons(ep_id, true);

	ret = ipa_ep_setup(ep_id, channel_count, 1, rx_buffer_size,
			   ipa_lan_rx_cb, NULL);
	if (ret)
		ipa_ep_free(ep_id);
	else
		ipa_ctx->lan_cons_ep_id = ep_id;

	return ret;
}

/**
 * ipa_route_table_init() - Initialize an empty route table
 *
 * Each entry in the route table contains the DMA address of a route
 * descriptor.  This function allocates that zero route, then allocates
 * the route table and initializes all its entries to point at the zero
 * route.
 *
 * Return:	0 if successful or -ENOMEM.
 */
static int ipa_route_table_init(void)
{
	u64 zero_route_phys;
	dma_addr_t phys;
	size_t size;
	u64 *virt;
	u32 i;

	/* Allocate the route table, with enough space at the end of
	 * the table to hold the zero route descriptor.  Initialize
	 * all filter table entries to point to the zero route.
	 */
	size = IPA_MEM_RT_COUNT * IPA_TABLE_ENTRY_SIZE;
	virt = dma_zalloc_coherent(ipa_ctx->dev, size + IPA_ROUTE_SIZE,
			&phys, GFP_KERNEL);
	if (!virt)
		return -ENOMEM;
	ipa_ctx->route_table_virt = virt;
	ipa_ctx->route_table_phys = phys;

	/* Zero route is immediately after the filter table */
	zero_route_phys = phys + size;

	for (i = 0; i < IPA_MEM_RT_COUNT; i++)
		*virt++ = zero_route_phys;

	return 0;
}

/**
 * ipa_route_table_exit() - Inverse of ipa_route_table_init().
 */
static void ipa_route_table_exit(void)
{
	size_t size;

	size = IPA_MEM_RT_COUNT * IPA_TABLE_ENTRY_SIZE;
	size += IPA_ROUTE_SIZE;

	dma_free_coherent(ipa_ctx->dev, size, ipa_ctx->route_table_virt,
			  ipa_ctx->route_table_phys);
	ipa_ctx->route_table_virt = NULL;
	ipa_ctx->route_table_phys = 0;
}

/**
 * ipa_filter_table_init() - Initialize an empty filter table
 *
 * Each entry in the filter table contains the DMA address of a filter
 * descriptor.  This function allocates the zero filter, allocates the
 * filter table.  It saves a bitmap of endpoints that support filtering
 * in the first slot, and initializes the remaining entries to point at
 * the zero filter.
 *
 * Return:	0 if successful or a negative error code.
 */
static int ipa_filter_table_init(void)
{
	u64 zero_filter_phys;
	dma_addr_t phys;
	size_t size;
	u64 *virt;
	u32 i;

	/* Compute the bitmap of endpoints that support filtering. */
	ipa_ctx->filter_bitmap = ipa_filter_bitmap_init();
	ipa_debug("filter_bitmap 0x%08x\n", ipa_ctx->filter_bitmap);
	if (!ipa_ctx->filter_bitmap)
		return -EINVAL;

	/* Allocate the filter table, with an extra slot for the bitmap.
	 * Also allocate enough space at the end of the table to hold
	 * the * zero filter descriptor.  Initialize all filter table
	 * entries point to that.
	 */
	ipa_ctx->filter_count = hweight32(ipa_ctx->filter_bitmap);
	size = (ipa_ctx->filter_count + 1) * IPA_TABLE_ENTRY_SIZE;
	virt = dma_zalloc_coherent(ipa_ctx->dev, size + IPA_FILTER_SIZE,
				   &phys, GFP_KERNEL);
	if (!virt)
		goto err_clear_filter_count;
	ipa_ctx->filter_table_virt = virt;
	ipa_ctx->filter_table_phys = phys;

	/* Zero filter is immediately after the filter table */
	zero_filter_phys = phys + size;

	/* Save the filter table bitmap.  The "soft" bitmap value
	 * must be converted to the hardware representation by
	 * shifting it left one position.  (Bit 0 represents global
	 * filtering, which is possible but not used.)
	 */
	*virt++ = (u64)ipa_ctx->filter_bitmap << 1;

	/* Now point every entry in the table at the empty filter */
	for (i = 0; i < ipa_ctx->filter_count; i++)
		*virt++ = zero_filter_phys;

	return 0;

err_clear_filter_count:
	ipa_ctx->filter_count = 0;
	ipa_ctx->filter_bitmap = 0;

	return -ENOMEM;
}

/**
 * ipa_filter_table_exit() - Inverse of ipa_filter_table_init().
 */
static void ipa_filter_table_exit(void)
{
	size_t size;

	size = (ipa_ctx->filter_count + 1) * IPA_TABLE_ENTRY_SIZE;
	size += IPA_FILTER_SIZE;

	dma_free_coherent(ipa_ctx->dev, size, ipa_ctx->filter_table_virt,
			  ipa_ctx->filter_table_phys);
	ipa_ctx->filter_table_virt = NULL;
	ipa_ctx->filter_table_phys = 0;
	ipa_ctx->filter_count = 0;
	ipa_ctx->filter_bitmap = 0;
}

static int ipa_ep_apps_setup(void)
{
	u32 size;
	int ret;

	/* CMD OUT (AP->IPA) */
	ret = ipa_ep_apps_cmd_prod_setup();
	if (ret < 0)
		return ret;

	ipa_init_sram();
	ipa_init_hdr();

	size = IPA_MEM_RT_COUNT * IPA_TABLE_ENTRY_SIZE;
	ipa_init_rt4(ipa_ctx->route_table_phys, size);
	ipa_init_rt6(ipa_ctx->route_table_phys, size);

	size = (ipa_ctx->filter_count + 1) * IPA_TABLE_ENTRY_SIZE;
	ipa_init_flt4(ipa_ctx->filter_table_phys, size);
	ipa_init_flt6(ipa_ctx->filter_table_phys, size);

	ipa_setup_flt_hash_tuple();
	ipa_setup_rt_hash_tuple();

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
	ret = ipa_ep_apps_lan_cons_setup();
	if (ret < 0)
		goto fail_flt_hash_tuple;

	ipa_cfg_default_route(IPA_CLIENT_APPS_LAN_CONS);

	return 0;

fail_flt_hash_tuple:
	ipa_ep_teardown(ipa_ctx->cmd_prod_ep_id);
	ipa_ctx->cmd_prod_ep_id = IPA_EP_ID_BAD;

	return ret;
}

/**
 * ipa_enable_clks() - Turn on IPA clocks
 */
static void ipa_enable_clks(void)
{
	WARN_ON(ipa_interconnect_enable());
}

/**
 * ipa_disable_clks() - Turn off IPA clocks
 */
static void ipa_disable_clks(void)
{
	WARN_ON(ipa_interconnect_disable());
}

/* Add an IPA client under protection of the mutex.  This is called
 * for the first client, but a race could mean another caller gets
 * the first reference.  When the first reference is taken, IPA
 * clocks are enabled endpoints are resumed.  A positive reference count
 * means the endpoints are active; this doesn't set the first reference
 * until after this is complete (and the mutex, not the atomic
 * count, is what protects this).
 */
static void ipa_client_add_first(void)
{
	mutex_lock(&ipa_ctx->active_clients_mutex);

	/* A reference might have been added while awaiting the mutex. */
	if (!atomic_inc_not_zero(&ipa_ctx->active_clients_count)) {
		ipa_enable_clks();
		ipa_ep_resume_all();
		atomic_inc(&ipa_ctx->active_clients_count);
	} else {
		ipa_assert(atomic_read(&ipa_ctx->active_clients_count) > 1);
	}

	mutex_unlock(&ipa_ctx->active_clients_mutex);
}

/* Attempt to add an IPA client reference, but only if this does not
 * represent the initiaal reference.  Returns true if the reference
 * was taken, false otherwise.
 */
static bool ipa_client_add_not_first(void)
{
	return !!atomic_inc_not_zero(&ipa_ctx->active_clients_count);
}

/* Add an IPA client, but only if the reference count is already
 * non-zero.  (This is used to avoid blocking.)  Returns true if the
 * additional reference was added successfully, or false otherwise.
 */
bool ipa_client_add_additional(void)
{
	return ipa_client_add_not_first();
}

/* Add an IPA client.  If this is not the first client, the
 * reference count is updated and return is immediate.  Otherwise
 * ipa_client_add_first() will safely add the first client, enabling
 * clocks and setting up (resuming) endpoints before returning.
 */
void ipa_client_add(void)
{
	/* There's nothing more to do if this isn't the first reference */
	if (!ipa_client_add_not_first())
		ipa_client_add_first();
}

/* Remove an IPA client under protection of the mutex.  This is
 * called for the last remaining client, but a race could mean
 * another caller gets an additional reference before the mutex
 * is acquired.  When the final reference is dropped, endpoints are
 * suspended and IPA clocks disabled.
 */
static void ipa_client_remove_final(void)
{
	mutex_lock(&ipa_ctx->active_clients_mutex);

	/* A reference might have been removed while awaiting the mutex. */
	if (!atomic_dec_return(&ipa_ctx->active_clients_count)) {
		ipa_ep_suspend_all();
		ipa_disable_clks();
	}

	mutex_unlock(&ipa_ctx->active_clients_mutex);
}

/* Decrement the active clients reference count, and if the result
 * is 0, suspend the endpoints and disable clocks.
 *
 * This function runs in work queue context, scheduled to run whenever
 * the last reference would be dropped in ipa_client_remove().
 */
static void ipa_client_remove_deferred(struct work_struct *work)
{
	ipa_client_remove_final();
}

/* Attempt to remove a client reference, but only if this is not the
 * only reference remaining.  Returns true if the reference was
 * removed, or false if doing so would produce a zero reference
 * count.
 */
static bool ipa_client_remove_not_final(void)
{
	return !!atomic_add_unless(&ipa_ctx->active_clients_count, -1, 1);
}

/* Attempt to remove an IPA client reference.  If this represents
 * the last reference arrange for ipa_client_remove_final() to be
 * called in workqueue context, dropping the last reference under
 * protection of the mutex.
 */
void ipa_client_remove(void)
{
	if (!ipa_client_remove_not_final())
		queue_work(ipa_ctx->power_mgmt_wq, &ipa_client_remove_work);
}

/** ipa_inc_acquire_wakelock() - Increase active clients counter, and
 * acquire wakelock if necessary
 */
void ipa_inc_acquire_wakelock(void)
{
	unsigned long flags;

	spin_lock_irqsave(&ipa_ctx->wakeup_lock, flags);

	ipa_ctx->wakeup_count++;
	if (ipa_ctx->wakeup_count == 1)
		__pm_stay_awake(&ipa_ctx->wakeup);

	spin_unlock_irqrestore(&ipa_ctx->wakeup_lock, flags);
}

/** ipa_dec_release_wakelock() - Decrease active clients counter
 *
 * In case if the ref count is 0, release the wakelock.
 */
void ipa_dec_release_wakelock(void)
{
	unsigned long flags;

	spin_lock_irqsave(&ipa_ctx->wakeup_lock, flags);

	ipa_ctx->wakeup_count--;
	if (ipa_ctx->wakeup_count == 0)
		__pm_relax(&ipa_ctx->wakeup);

	spin_unlock_irqrestore(&ipa_ctx->wakeup_lock, flags);
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
			ipa_client_add();

			atomic_set(&ipa_ctx->transport_pm.dec_clients, 1);
		}
		mutex_unlock(&ipa_ctx->transport_pm.transport_pm_mutex);
	}
}

/**
 * ipa_init_interrupts() - Initialize IPA interrupts
 */
static int ipa_init_interrupts(void)
{
	int ret;

	ret = ipa_interrupts_init();
	if (!ret)
		return ret;

	ipa_add_interrupt_handler(IPA_TX_SUSPEND_IRQ, ipa_suspend_handler);

	return 0;
}

static void ipa_freeze_clock_vote_and_notify_modem(void)
{
	u32 value;
	u32 mask;

	if (ipa_ctx->smp2p_info.res_sent)
		return;

	if (!ipa_ctx->smp2p_info.enabled_state) {
		ipa_err("smp2p out gpio not assigned\n");
		return;
	}

	ipa_ctx->smp2p_info.ipa_clk_on = ipa_client_add_additional();

	/* Signal whether the clock is enabled */
	mask = BIT(ipa_ctx->smp2p_info.enabled_bit);
	value = ipa_ctx->smp2p_info.ipa_clk_on ? mask : 0;
	qcom_smem_state_update_bits(ipa_ctx->smp2p_info.enabled_state, mask,
				    value);

	/* Now indicate that the enabled flag is valid */
	mask = BIT(ipa_ctx->smp2p_info.valid_bit);
	value = mask;
	qcom_smem_state_update_bits(ipa_ctx->smp2p_info.valid_state, mask,
				    value);

	ipa_ctx->smp2p_info.res_sent = true;
}

void ipa_reset_freeze_vote(void)
{
	u32 mask;

	if (!ipa_ctx->smp2p_info.res_sent)
		return;

	if (ipa_ctx->smp2p_info.ipa_clk_on)
		ipa_client_remove();

	/* Reset the clock enabled valid flag */
	mask = BIT(ipa_ctx->smp2p_info.valid_bit);
	qcom_smem_state_update_bits(ipa_ctx->smp2p_info.valid_state, mask, 0);

	/* Mark the clock disabled for good measure... */
	mask = BIT(ipa_ctx->smp2p_info.enabled_bit);
	qcom_smem_state_update_bits(ipa_ctx->smp2p_info.enabled_state, mask, 0);

	ipa_ctx->smp2p_info.res_sent = false;
	ipa_ctx->smp2p_info.ipa_clk_on = false;
}

static int
ipa_panic_notifier(struct notifier_block *this, unsigned long event, void *ptr)
{
	ipa_freeze_clock_vote_and_notify_modem();
	ipa_uc_panic_notifier();

	return NOTIFY_DONE;
}

static struct notifier_block ipa_panic_blk = {
	.notifier_call = ipa_panic_notifier,
	/* IPA panic handler needs to run before modem shuts down */
	.priority = INT_MAX,
};

static void ipa_register_panic_hdlr(void)
{
	atomic_notifier_chain_register(&panic_notifier_list, &ipa_panic_blk);
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
static void ipa_post_init(void)
{
	int ret;

	ipa_debug("ipa_post_init() started\n");

	ret = gsi_device_init(ipa_ctx->gsi);
	if (ret) {
		ipa_err(":gsi register error - %d\n", ret);
		return;
	}

	/* setup the AP-IPA endpoints */
	if (ipa_ep_apps_setup()) {
		ipa_err(":failed to setup IPA-Apps endpoints\n");
		gsi_device_exit(ipa_ctx->gsi);

		return;
	}

	ipa_ctx->uc_ctx = ipa_uc_init(ipa_ctx->ipa_phys);
	if (!ipa_ctx->uc_ctx)
		ipa_err("microcontroller init failed\n");

	ipa_register_panic_hdlr();

	ipa_ctx->modem_clk_vote_valid = true;

	if (ipa_wwan_init())
		ipa_err("WWAN init failed (ignoring)\n");

	dev_info(ipa_ctx->dev, "IPA driver initialization was successful.\n");
}

/** ipa_pre_init() - Initialize the IPA Driver.
 *
 * Perform initialization which doesn't require access to IPA hardware.
 */
static int ipa_pre_init(void)
{
	int ret = 0;

	/* enable IPA clocks explicitly to allow the initialization */
	ipa_enable_clks();

	ipa_init_hw();

	ipa_ctx->ep_count = ipa_get_ep_count();
	ipa_debug("ep_count %u\n", ipa_get_ep_count());
	ipa_assert(ipa_ctx->ep_count <= IPA_EP_COUNT_MAX);

	ipa_sram_settings_read();
	if (ipa_ctx->smem_size < IPA_MEM_END_OFST) {
		ipa_err("insufficient memory: %hu bytes available, need %u\n",
			ipa_ctx->smem_size, IPA_MEM_END_OFST);
		ret = -ENOMEM;
		goto err_disable_clks;
	}

	mutex_init(&ipa_ctx->active_clients_mutex);
	atomic_set(&ipa_ctx->active_clients_count, 1);

	/* Create workqueues for power management */
	ipa_ctx->power_mgmt_wq =
		create_singlethread_workqueue("ipa_power_mgmt");
	if (!ipa_ctx->power_mgmt_wq) {
		ipa_err("failed to create power mgmt wq\n");
		ret = -ENOMEM;
		goto err_disable_clks;
	}

	mutex_init(&ipa_ctx->transport_pm.transport_pm_mutex);

	/* init the lookaside cache */

	ipa_ctx->dp = ipa_dp_init();
	if (!ipa_ctx->dp)
		goto err_destroy_pm_wq;

	/* allocate memory for DMA_TASK workaround */
	ret = ipa_gsi_dma_task_alloc();
	if (ret)
		goto err_dp_exit;

	/* Create a wakeup source. */
	wakeup_source_init(&ipa_ctx->wakeup, "IPA_WS");
	spin_lock_init(&ipa_ctx->wakeup_lock);

	/* Note enabling dynamic clock division must not be
	 * attempted for IPA hardware versions prior to 3.5.
	 */
	ipa_enable_dcd();

	/* Assign resource limitation to each group */
	ipa_set_resource_groups_min_max_limits();

	ret = ipa_init_interrupts();
	if (!ret)
		return 0;	/* Success! */

	ipa_err("ipa initialization of interrupts failed\n");
err_dp_exit:
	ipa_dp_exit(ipa_ctx->dp);
	ipa_ctx->dp = NULL;
err_destroy_pm_wq:
	destroy_workqueue(ipa_ctx->power_mgmt_wq);
err_disable_clks:
	ipa_disable_clks();

	return ret;
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
static irqreturn_t ipa_smp2p_modem_clk_query_isr(int irq, void *ctxt)
{
	ipa_freeze_clock_vote_and_notify_modem();

	return IRQ_HANDLED;
}

/* Threaded IRQ handler for modem "ipa-post-init" SMP2P interrupt */
static irqreturn_t ipa_smp2p_modem_post_init_isr(int irq, void *ctxt)
{
	ipa_post_init();

	return IRQ_HANDLED;
}

static int
ipa_smp2p_irq_init(struct device *dev, const char *name, irq_handler_t handler)
{
	struct device_node *node = dev->of_node;
	unsigned int irq;
	int ret;

	ret = of_irq_get_byname(node, name);
	if (ret < 0)
		return ret;
	if (!ret)
		return -EINVAL;		/* IRQ mapping failure */
	irq = ret;

	ret = devm_request_threaded_irq(dev, irq, NULL, handler, 0, name, dev);
	if (ret)
		return ret;

	return irq;
}

static void
ipa_smp2p_irq_exit(struct device *dev, unsigned int irq)
{
	devm_free_irq(dev, irq, dev);
}

static int ipa_smp2p_init(struct device *dev, bool modem_init)
{
	struct qcom_smem_state *enabled_state;
	struct qcom_smem_state *valid_state;
	struct device_node *node;
	unsigned int enabled_bit;
	unsigned int valid_bit;
	unsigned int clock_irq;
	int ret;

	node = dev->of_node;

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

	ret = ipa_smp2p_irq_init(dev, "ipa-clock-query",
				 ipa_smp2p_modem_clk_query_isr);
	if (ret < 0)
		return ret;
	clock_irq = ret;

	if (modem_init) {
		/* Result will be non-zero (negative for error) */
		ret = ipa_smp2p_irq_init(dev, "ipa-post-init",
					 ipa_smp2p_modem_post_init_isr);
		if (ret < 0) {
			ipa_smp2p_irq_exit(dev, clock_irq);

			return ret;
		}
	}

	/* Success.  Record our smp2p information */
	ipa_ctx->smp2p_info.valid_state = valid_state;
	ipa_ctx->smp2p_info.valid_bit = valid_bit;
	ipa_ctx->smp2p_info.enabled_state = enabled_state;
	ipa_ctx->smp2p_info.enabled_bit = enabled_bit;
	ipa_ctx->smp2p_info.clock_query_irq = clock_irq;
	ipa_ctx->smp2p_info.post_init_irq = modem_init ? ret : 0;

	return 0;
}

static void ipa_smp2p_exit(struct device *dev)
{
	if (ipa_ctx->smp2p_info.post_init_irq)
		ipa_smp2p_irq_exit(dev, ipa_ctx->smp2p_info.post_init_irq);
	ipa_smp2p_irq_exit(dev, ipa_ctx->smp2p_info.clock_query_irq);

	memset(&ipa_ctx->smp2p_info, 0, sizeof(ipa_ctx->smp2p_info));
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
	struct resource *res;
	struct device *dev;
	bool modem_init;
	int ret;

	/* We assume we're working on 64-bit hardware */
	BUILD_BUG_ON(!IS_ENABLED(CONFIG_64BIT));

	dev = &pdev->dev;

	match_data = of_device_get_match_data(dev);
	modem_init = match_data->init_type == ipa_modem_init;

	/* If we need Trust Zone, make sure it's ready */
	if (!modem_init)
		if (!qcom_scm_is_available())
			return -EPROBE_DEFER;

	/* Initialize the smp2p driver early.  It might not be ready
	 * when we're probed, so it might return -EPROBE_DEFER.
	 */
	ret = ipa_smp2p_init(dev, modem_init);
	if (ret)
		return ret;

	/* Initialize the interconnect driver early too.  It might
	 * also return -EPROBE_DEFER.
	 */
	ret = ipa_interconnect_init(dev);
	if (ret)
		goto out_smp2p_exit;

	ipa_ctx->dev = dev;	/* Set early for ipa_err()/ipa_debug() */

	ret = ipa_dma_init(dev, IPA_HW_TBL_SYSADDR_ALIGN);
	if (ret)
		goto err_interconnect_exit;

	ret = ipa_route_table_init();
	if (ret)
		goto err_dma_exit;

	ret = ipa_filter_table_init();
	if (ret)
		goto err_route_table_exit;

	ret = platform_get_irq_byname(pdev, "ipa");
	if (ret < 0)
		goto err_filter_table_exit;
	ipa_ctx->ipa_irq = ret;

	/* Get IPA memory range */
	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "ipa");
	if (!res) {
		ret = -ENODEV;
		goto err_clear_ipa_irq;
	}

	/* Setup IPA register access */
	ret = ipa_reg_init(res->start, (size_t)resource_size(res));
	if (ret)
		goto err_clear_ipa_irq;
	ipa_ctx->ipa_phys = res->start;

	ipa_ctx->gsi = gsi_init(pdev);
	if (IS_ERR(ipa_ctx->gsi)) {
		ret = PTR_ERR(ipa_ctx->gsi);
		goto err_clear_gsi;
	}

	ipa_ctx->cmd_prod_ep_id = IPA_EP_ID_BAD;
	ipa_ctx->lan_cons_ep_id = IPA_EP_ID_BAD;

	/* Proceed to real initialization */
	ret = ipa_pre_init();
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
		if (ret)
			goto err_undo_pre_init;

		/* Now we can proceed to stage two initialization */
		ipa_post_init();
	}

	return 0;	/* Success */

err_undo_pre_init:
	/* XXX This needs to be implemented */
err_clear_ep_ids:
	ipa_ctx->lan_cons_ep_id = 0;
	ipa_ctx->cmd_prod_ep_id = 0;
	/* XXX gsi_exit(pdev); */
err_clear_gsi:
	ipa_ctx->gsi = NULL;
	ipa_ctx->ipa_phys = 0;
	ipa_reg_exit();
err_clear_ipa_irq:
	ipa_ctx->ipa_irq = 0;
err_filter_table_exit:
	ipa_filter_table_exit();
err_route_table_exit:
	ipa_route_table_exit();
err_dma_exit:
	ipa_dma_exit();
	ipa_ctx->dev = NULL;
err_interconnect_exit:
	ipa_interconnect_exit();
out_smp2p_exit:
	ipa_smp2p_exit(dev);

	return ret;
}

static int ipa_plat_drv_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;

	ipa_ctx->dev = NULL;
	ipa_filter_table_exit();
	ipa_route_table_exit();
	ipa_dma_exit();
	ipa_ctx->gsi = NULL;	/* XXX ipa_gsi_exit() */
	ipa_reg_exit();

	ipa_ctx->ipa_phys = 0;

	if (ipa_ctx->lan_cons_ep_id != IPA_EP_ID_BAD) {
		ipa_ep_free(ipa_ctx->lan_cons_ep_id);
		ipa_ctx->lan_cons_ep_id = IPA_EP_ID_BAD;
	}
	if (ipa_ctx->cmd_prod_ep_id != IPA_EP_ID_BAD) {
		ipa_ep_free(ipa_ctx->cmd_prod_ep_id);
		ipa_ctx->cmd_prod_ep_id = IPA_EP_ID_BAD;
	}
	ipa_ctx->ipa_irq = 0;	/* XXX Need to de-initialize? */
	ipa_ctx->filter_bitmap = 0;
	ipa_interconnect_exit();
	ipa_smp2p_exit(dev);

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
	u32 i;

	/* In case there is a tx/rx handler in polling mode fail to suspend */
	for (i = 0; i < ipa_ctx->ep_count; i++) {
		struct ipa_ep_context *ep = &ipa_ctx->ep[i];

		if (ipa_producer(ep->client))
			continue;
		if (ep->sys && ipa_ep_polling(ep)) {
			ipa_err("EP %d is polling, do not suspend\n", i);
			return -EAGAIN;
		}
	}

	return 0;
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
