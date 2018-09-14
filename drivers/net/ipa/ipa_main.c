// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#define pr_fmt(fmt)    "ipa %s:%d " fmt, __func__, __LINE__

#include <linux/version.h>

#include <linux/clk.h>
#include <linux/compat.h>
#include <linux/device.h>
#include <linux/dmapool.h>
#include <linux/genalloc.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/rbtree.h>
#include <linux/of_gpio.h>
#include <linux/of_irq.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/interconnect.h>
#include <linux/netdevice.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/soc/qcom/smem.h>
#include <linux/soc/qcom/smem_state.h>
#include <asm/cacheflush.h>

#include "ipa_dma.h"
#include "ipa_i.h"
#include "ipahal.h"

#define IPA_APPS_CMD_PROD_RING_COUNT	128
#define IPA_APPS_LAN_CONS_RING_COUNT	128

static void ipa_post_init(struct work_struct *unused);
static DECLARE_WORK(ipa_post_init_work, ipa_post_init);

static void ipa_client_remove_deferred(struct work_struct *work);
static DECLARE_WORK(ipa_client_remove_work, ipa_client_remove_deferred);

static struct ipa_context ipa_ctx_struct;
struct ipa_context *ipa_ctx = &ipa_ctx_struct;

static int hdr_init_local_cmd(u32 offset, u32 size)
{
	struct ipa_dma_mem mem;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	struct ipa_desc desc = { };
	int ret;

	if (ipa_dma_alloc(&mem, size, GFP_KERNEL))
		return -ENOMEM;

	offset += ipa_ctx->smem_offset;

	cmd_pyld = ipahal_hdr_init_local_pyld(&mem, offset);
	if (!cmd_pyld) {
		ipa_err("error allocating command payload\n");
		ret = -ENOMEM;
		goto err_dma_free;
	}
	ipa_desc_fill_imm_cmd(&desc, cmd_pyld);

	ret = ipa_send_cmd(&desc);
	if (ret)
		ipa_err("error sending command\n");

	ipahal_destroy_imm_cmd(cmd_pyld);
err_dma_free:
	ipa_dma_free(&mem);

	return ret;
}

static int dma_shared_mem_zero_cmd(u32 offset, u32 size)
{
	struct ipa_dma_mem mem;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	struct ipa_desc desc = { };
	int ret;

	ipa_assert(size > 0);

	if (ipa_dma_alloc(&mem, size, GFP_KERNEL))
		return -ENOMEM;

	offset += ipa_ctx->smem_offset;

	cmd_pyld = ipahal_dma_shared_mem_write_pyld(&mem, offset);
	if (!cmd_pyld) {
		ipa_err("error allocating command payload\n");
		ret = -ENOMEM;
		goto err_dma_free;
	}
	ipa_desc_fill_imm_cmd(&desc, cmd_pyld);

	ret = ipa_send_cmd(&desc);
	if (ret)
		ipa_err("error sending command\n");

	ipahal_destroy_imm_cmd(cmd_pyld);
err_dma_free:
	ipa_dma_free(&mem);

	return ret;
}

/** ipa_init_q6_smem() - Initialize Q6 general memory and
 *		       header memory regions in IPA.
 *
 * Return codes:
 * 0: success
 * -ENOMEM: failed to allocate dma memory
 * -EFAULT: failed to send IPA command to initialize the memory
 */
int ipa_init_q6_smem(void)
{
	int rc;
	char *what;

	ipa_client_add();

	rc = dma_shared_mem_zero_cmd(IPA_MEM_MODEM_OFST, IPA_MEM_MODEM_SIZE);
	if (rc) {
		what = "Modem RAM";
		goto out_client_remove;
	}

	rc = dma_shared_mem_zero_cmd(IPA_MEM_MODEM_HDR_OFST,
				     IPA_MEM_MODEM_HDR_SIZE);
	if (rc) {
		what = "Modem HDRs RAM";
		goto out_client_remove;
	}

	rc = dma_shared_mem_zero_cmd(IPA_MEM_MODEM_HDR_PROC_CTX_OFST,
				     IPA_MEM_MODEM_HDR_PROC_CTX_SIZE);
	if (rc)
		what = "Modem proc ctx RAM";
out_client_remove:
	ipa_client_remove();
	if (rc)
		ipa_err("failed to initialize modem %s memory\n", what);

	return rc;
}

static int setup_apps_cmd_prod_pipe(void)
{
	struct ipa_sys_connect_params sys_in = { };
	enum ipa_client_type client = IPA_CLIENT_APPS_CMD_PROD;
	enum ipa_client_type dst_client = IPA_CLIENT_APPS_LAN_CONS;
	u32 chan_count = IPA_APPS_CMD_PROD_RING_COUNT;
	u32 prod_hdl;
	int ret;

	if (ipa_ctx->clnt_hdl_cmd != IPA_CLNT_HDL_BAD)
		ret = -EBUSY;

	ret = ipa_ep_alloc(client);
	if (ret < 0)
		return ret;
	prod_hdl = ret;

	ipa_endp_init_mode_prod(prod_hdl, IPA_DMA, dst_client);
	ipa_endp_init_seq_prod(prod_hdl);
	ipa_endp_init_deaggr_prod(prod_hdl);

	ret = ipa_setup_sys_pipe(prod_hdl, chan_count, 0, &sys_in);
	if (ret)
		ipa_ep_free(prod_hdl);
	else
		ipa_ctx->clnt_hdl_cmd = prod_hdl;

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

/** ipa_init_sram() - Initialize IPA local SRAM.
 *
 * Return codes: 0 for success, negative value for failure
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

/** ipa_init_hdr() - Initialize IPA header block.
 *
 * Return codes: 0 for success, negative value for failure
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

/** ipa_init_rt4() - Initialize IPA routing block for IPv4.
 *
 * Return codes: 0 for success, negative value for failure
 */
static int ipa_init_rt4(void)
{
	struct ipa_desc desc = { };
	struct ipa_dma_mem mem;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	u32 hash_offset;
	u32 nhash_offset;
	int rc;

	rc = ipahal_rt_generate_empty_img(IPA_MEM_V4_RT_NUM_INDEX, &mem);
	if (rc) {
		ipa_err("fail generate empty v4 rt img\n");
		return rc;
	}

	hash_offset = ipa_ctx->smem_offset + IPA_MEM_V4_RT_HASH_OFST;
	nhash_offset = ipa_ctx->smem_offset + IPA_MEM_V4_RT_NHASH_OFST;
	cmd_pyld =
		ipahal_ip_v4_routing_init_pyld(&mem, hash_offset, nhash_offset);
	if (!cmd_pyld) {
		ipa_err("fail construct ip_v4_rt_init imm cmd\n");
		rc = -EPERM;
		goto free_mem;
	}
	ipa_desc_fill_imm_cmd(&desc, cmd_pyld);

	if (ipa_send_cmd(&desc)) {
		ipa_err("fail to send immediate command\n");
		rc = -EFAULT;
	}

	ipahal_destroy_imm_cmd(cmd_pyld);

free_mem:
	ipahal_free_empty_img(&mem);
	return rc;
}

/** ipa_init_rt6() - Initialize IPA routing block for IPv6.
 *
 * Return codes: 0 for success, negative value for failure
 */
static int ipa_init_rt6(void)
{
	struct ipa_desc desc = { };
	struct ipa_dma_mem mem;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	u32 hash_offset;
	u32 nhash_offset;
	int rc;

	rc = ipahal_rt_generate_empty_img(IPA_MEM_V6_RT_NUM_INDEX, &mem);
	if (rc) {
		ipa_err("fail generate empty v6 rt img\n");
		return rc;
	}

	hash_offset = ipa_ctx->smem_offset + IPA_MEM_V6_RT_HASH_OFST;
	nhash_offset = ipa_ctx->smem_offset + IPA_MEM_V6_RT_NHASH_OFST;
	cmd_pyld =
		ipahal_ip_v6_routing_init_pyld(&mem, hash_offset, nhash_offset);
	if (!cmd_pyld) {
		ipa_err("fail construct ip_v6_rt_init imm cmd\n");
		rc = -EPERM;
		goto free_mem;
	}
	ipa_desc_fill_imm_cmd(&desc, cmd_pyld);

	if (ipa_send_cmd(&desc)) {
		ipa_err("fail to send immediate command\n");
		rc = -EFAULT;
	}

	ipahal_destroy_imm_cmd(cmd_pyld);

free_mem:
	ipahal_free_empty_img(&mem);
	return rc;
}

/** ipa_init_flt4() - Initialize IPA filtering block for IPv4.
 *
 * Return codes: 0 for success, negative value for failure
 */
static int ipa_init_flt4(void)
{
	struct ipa_desc desc = { };
	struct ipa_dma_mem mem;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	u32 hash_offset;
	u32 nhash_offset;
	int rc;

	rc = ipahal_flt_generate_empty_img(ipa_ctx->filter_bitmap, &mem);
	if (rc) {
		ipa_err("fail generate empty v4 flt img\n");
		return rc;
	}

	hash_offset = ipa_ctx->smem_offset + IPA_MEM_V4_FLT_HASH_OFST;
	nhash_offset = ipa_ctx->smem_offset + IPA_MEM_V4_FLT_NHASH_OFST;
	cmd_pyld = ipahal_ip_v4_filter_init_pyld(&mem, hash_offset,
						 nhash_offset);
	if (!cmd_pyld) {
		ipa_err("fail construct ip_v4_flt_init imm cmd\n");
		rc = -EPERM;
		goto free_mem;
	}
	ipa_desc_fill_imm_cmd(&desc, cmd_pyld);

	if (ipa_send_cmd(&desc)) {
		ipa_err("fail to send immediate command\n");
		rc = -EFAULT;
	}

	ipahal_destroy_imm_cmd(cmd_pyld);

free_mem:
	ipahal_free_empty_img(&mem);
	return rc;
}

/** ipa_init_flt6() - Initialize IPA filtering block for IPv6.
 *
 * Return codes: 0 for success, negative value for failure
 */
static int ipa_init_flt6(void)
{
	struct ipa_desc desc = { };
	struct ipa_dma_mem mem;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	u32 hash_offset;
	u32 nhash_offset;
	int rc;

	rc = ipahal_flt_generate_empty_img(ipa_ctx->filter_bitmap, &mem);
	if (rc) {
		ipa_err("fail generate empty v6 flt img\n");
		return rc;
	}

	hash_offset = ipa_ctx->smem_offset + IPA_MEM_V6_FLT_HASH_OFST;
	nhash_offset = ipa_ctx->smem_offset + IPA_MEM_V6_FLT_NHASH_OFST;
	cmd_pyld = ipahal_ip_v6_filter_init_pyld(&mem, hash_offset,
						 nhash_offset);
	if (!cmd_pyld) {
		ipa_err("fail construct ip_v6_flt_init imm cmd\n");
		rc = -EPERM;
		goto free_mem;
	}
	ipa_desc_fill_imm_cmd(&desc, cmd_pyld);

	if (ipa_send_cmd(&desc)) {
		ipa_err("fail to send immediate command\n");
		rc = -EFAULT;
	}

	ipahal_destroy_imm_cmd(cmd_pyld);

free_mem:
	ipahal_free_empty_img(&mem);
	return rc;
}

static void ipa_setup_flt_hash_tuple(void)
{
	struct ipa_reg_hash_tuple tuple = { };	/* All fields zero */
	u32 pipe_idx;

	for (pipe_idx = 0; pipe_idx < ipa_ctx->ipa_num_pipes; pipe_idx++) {
		if (ipa_is_modem_pipe(pipe_idx))
			continue;
		if (ipa_ctx->filter_bitmap & BIT(pipe_idx))
			ipa_set_flt_tuple_mask(pipe_idx, &tuple);
	}
}

static void ipa_setup_rt_hash_tuple(void)
{
	struct ipa_reg_hash_tuple tuple = { };	/* All fields zero */
	int tbl_idx;
	int limit = max(IPA_MEM_V6_RT_NUM_INDEX, IPA_MEM_V4_RT_NUM_INDEX);

	for (tbl_idx = 0; tbl_idx < limit; tbl_idx++) {
		if (tbl_idx >= IPA_MEM_V4_MODEM_RT_INDEX_LO &&
		    tbl_idx <= IPA_MEM_V4_MODEM_RT_INDEX_HI)
			continue;

		if (tbl_idx >= IPA_MEM_V6_MODEM_RT_INDEX_LO &&
		    tbl_idx <= IPA_MEM_V6_MODEM_RT_INDEX_HI)
			continue;

		ipa_set_rt_tuple_mask(tbl_idx, &tuple);
	}
}

static int setup_apps_lan_cons_pipe(void)
{
	struct ipa_sys_connect_params sys_in = { };
	enum ipa_client_type client = IPA_CLIENT_APPS_LAN_CONS;
	u32 chan_count = IPA_APPS_LAN_CONS_RING_COUNT;
	u32 aggr_size = IPA_GENERIC_AGGR_BYTE_LIMIT;
	u32 aggr_count = IPA_GENERIC_AGGR_PKT_LIMIT;
	u32 rx_buffer_size;
	u32 byte_limit;
	u32 cons_hdl;
	int ret;

	if (aggr_size > ipa_reg_aggr_max_byte_limit())
		return -EINVAL;

	if (aggr_count > ipa_reg_aggr_max_packet_limit())
		return -EINVAL;

	if (ipa_ctx->clnt_hdl_lan_cons != IPA_CLNT_HDL_BAD)
		return -EBUSY;

	/* Compute the buffer size required to handle the requested
	 * aggregation byte limit.  The aggr_byte_limit value is
	 * expressed as a number of KB, so we need to convert it to
	 * bytes to determine the buffer size.
	 *
	 * The buffer will be sufficient to hold one IPA_MTU-sized
	 * packet after the limit is reached.  (The size returned is
	 * the computed maximum number of data bytes that can be
	 * held in the buffer--no metadata/headers.)
	 */
	byte_limit = aggr_size * SZ_1K;
	rx_buffer_size = ipa_aggr_byte_limit_buf_size(byte_limit);

	/* Account for the extra IPA_MTU past the limit in the
	 * buffer, and convert the result to the KB units the
	 * aggr_byte_limit uses.
	 */
	aggr_size = (rx_buffer_size - IPA_MTU) / SZ_1K;

	ret = ipa_ep_alloc(client);
	if (ret < 0)
		return ret;
	cons_hdl = ret;

	ipa_endp_init_hdr_cons(cons_hdl, IPA_LAN_RX_HEADER_LENGTH, 0, 0);
	ipa_endp_init_hdr_ext_cons(cons_hdl, ilog2(sizeof(u32)), false);
	ipa_endp_init_aggr_cons(cons_hdl, aggr_size, aggr_count, false);
	ipa_endp_init_cfg_cons(cons_hdl, IPA_CS_OFFLOAD_DL);
	ipa_endp_init_hdr_metadata_mask_cons(cons_hdl, 0x0);
	ipa_endp_status_cons(cons_hdl, true);

	sys_in.notify = ipa_lan_rx_cb;
	sys_in.priv = NULL;
	sys_in.napi_enabled = false;

	ret = ipa_setup_sys_pipe(cons_hdl, chan_count, rx_buffer_size, &sys_in);
	if (ret)
		ipa_ep_free(cons_hdl);
	else
		ipa_ctx->clnt_hdl_lan_cons = cons_hdl;

	return ret;
}

static int ipa_setup_apps_pipes(void)
{
	int result;

	/* CMD OUT (AP->IPA) */
	result = setup_apps_cmd_prod_pipe();
	if (result < 0)
		return result;

	ipa_debug("Apps to IPA cmd pipe is connected\n");

	ipa_init_sram();
	ipa_debug("SRAM initialized\n");

	ipa_init_hdr();
	ipa_debug("HDR initialized\n");

	ipa_init_rt4();
	ipa_debug("V4 RT initialized\n");

	ipa_init_rt6();
	ipa_debug("V6 RT initialized\n");

	ipa_init_flt4();
	ipa_debug("V4 FLT initialized\n");

	ipa_init_flt6();
	ipa_debug("V6 FLT initialized\n");

	ipa_setup_flt_hash_tuple();
	ipa_debug("flt hash tuple is configured\n");

	ipa_setup_rt_hash_tuple();
	ipa_debug("rt hash tuple is configured\n");

	/* LAN IN (IPA->AP)
	 *
	 * Even without supporting LAN traffic, we use the LAN consumer
	 * pipe for receiving some information from the IPA.  If we issue
	 * a tagged command, we arrange to be notified of its completion
	 * through this pipe.  In addition, we arrange for this pipe to
	 * be used as the IPA's default route; the IPA will notify the AP
	 * of exceptions (unroutable packets, but other events as well)
	 * through this pipe.
	 */
	result = setup_apps_lan_cons_pipe();
	if (result < 0)
		goto fail_flt_hash_tuple;

	ipa_cfg_default_route(IPA_CLIENT_APPS_LAN_CONS);

	return 0;

fail_flt_hash_tuple:
	ipa_teardown_sys_pipe(ipa_ctx->clnt_hdl_cmd);
	ipa_ctx->clnt_hdl_cmd = IPA_CLNT_HDL_BAD;

	return result;
}

/** ipa_enable_clks() - Turn on IPA clocks
 *
 * Return codes:
 * None
 */
static void ipa_enable_clks(void)
{
	ipa_debug("enabling IPA clocks and bus voting\n");

	WARN_ON(ipa_interconnect_enable());
}

/** ipa_disable_clks() - Turn off IPA clocks
 *
 * Return codes:
 * None
 */
static void ipa_disable_clks(void)
{
	ipa_debug("disabling IPA clocks and bus voting\n");

	WARN_ON(ipa_interconnect_disable());
}

/* Add an IPA client under protection of the mutex.  This is called
 * for the first client, but a race could mean another caller gets
 * the first reference.  When the first reference is taken, IPA
 * clocks are enabled pipes are resumed.  A positive reference count
 * means the pipes are active; this doesn't set the first reference
 * until after this is complete (and the mutex, not the atomic
 * count, is what protects this).
 */
static void ipa_client_add_first(void)
{
	mutex_lock(&ipa_ctx->ipa_active_clients.mutex);

	/* A reference might have been added while awaiting the mutex. */
	if (!atomic_inc_not_zero(&ipa_ctx->ipa_active_clients.cnt)) {
		ipa_enable_clks();
		ipa_resume_apps_pipes();
		atomic_inc(&ipa_ctx->ipa_active_clients.cnt);
	} else {
		ipa_assert(atomic_read(&ipa_ctx->ipa_active_clients.cnt) > 1);
	}

	mutex_unlock(&ipa_ctx->ipa_active_clients.mutex);
}

/* Attempt to add an IPA client reference, but only if this does not
 * represent the initiaal reference.  Returns true if the reference
 * was taken, false otherwise.
 */
static bool ipa_client_add_not_first(void)
{
	return !!atomic_inc_not_zero(&ipa_ctx->ipa_active_clients.cnt);
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
 * clocks and setting up (resuming) pipes before returning.
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
 * is acquired.  When the final reference is dropped, pipes are
 * suspended and IPA clocks disabled.
 */
static void ipa_client_remove_final(void)
{
	mutex_lock(&ipa_ctx->ipa_active_clients.mutex);

	/* A reference might have been removed while awaiting the mutex. */
	if (!atomic_dec_return(&ipa_ctx->ipa_active_clients.cnt)) {
		ipa_suspend_apps_pipes();
		ipa_disable_clks();
	}

	mutex_unlock(&ipa_ctx->ipa_active_clients.mutex);
}

/* Decrement the active clients reference count, and if the result
 * is 0, suspend the pipes and disable clocks.
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
	return !!atomic_add_unless(&ipa_ctx->ipa_active_clients.cnt, -1, 1);
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

/* Remove an IPA client reference.  If other references remain
 * return is immediate.  For the last reference, this function
 * blocks until it can be safely removed under mutex protection.
 * Unless another client can be added concurrently, the reference
 * count will be 0 (and pipes will be suspended and clocks stopped)
 * upon return for the final reference.
 */
void ipa_client_remove_wait(void)
{
	if (!ipa_client_remove_not_final())
		ipa_client_remove_final();
}

/** ipa_inc_acquire_wakelock() - Increase active clients counter, and
 * acquire wakelock if necessary
 *
 * Return codes:
 * None
 */
void ipa_inc_acquire_wakelock(void)
{
	unsigned long flags;

	spin_lock_irqsave(&ipa_ctx->wakelock_ref_cnt.spinlock, flags);
	ipa_ctx->wakelock_ref_cnt.cnt++;
	if (ipa_ctx->wakelock_ref_cnt.cnt == 1)
		__pm_stay_awake(&ipa_ctx->w_lock);
	ipa_debug_low("active wakelock ref cnt = %d\n",
		      ipa_ctx->wakelock_ref_cnt.cnt);
	spin_unlock_irqrestore(&ipa_ctx->wakelock_ref_cnt.spinlock, flags);
}

/** ipa_dec_release_wakelock() - Decrease active clients counter
 *
 * In case if the ref count is 0, release the wakelock.
 *
 * Return codes:
 * None
 */
void ipa_dec_release_wakelock(void)
{
	unsigned long flags;

	spin_lock_irqsave(&ipa_ctx->wakelock_ref_cnt.spinlock, flags);
	ipa_ctx->wakelock_ref_cnt.cnt--;
	ipa_debug_low("active wakelock ref cnt = %d\n",
		      ipa_ctx->wakelock_ref_cnt.cnt);
	if (ipa_ctx->wakelock_ref_cnt.cnt == 0)
		__pm_relax(&ipa_ctx->w_lock);
	spin_unlock_irqrestore(&ipa_ctx->wakelock_ref_cnt.spinlock, flags);
}

/** ipa_suspend_handler() - Handles the suspend interrupt:
 * wakes up the suspended peripheral by requesting its consumer
 * @interrupt:	Interrupt type
 * @endpoints:	Interrupt specific information data
 */
static void ipa_suspend_handler(enum ipa_irq_type interrupt, u32 interrupt_data)
{
	u32 endpoints = interrupt_data;

	ipa_debug("interrupt=%d, endpoints=0x%08x\n", interrupt, endpoints);

	while (endpoints) {
		enum ipa_client_type client;
		u32 i = __ffs(endpoints);

		endpoints ^= BIT(i);

		if (!ipa_ctx->ep[i].allocated)
			continue;

		client = ipa_ctx->ep[i].client;
		if (!ipa_ap_consumer(client))
			continue;

		/* pipe will be unsuspended as part of enabling IPA clocks */
		mutex_lock(&ipa_ctx->transport_pm.transport_pm_mutex);
		if (!atomic_read(&ipa_ctx->transport_pm.dec_clients)) {
			ipa_client_add();

			ipa_debug_low("Pipes un-suspended.\n");
			ipa_debug_low("Enter poll mode.\n");
			atomic_set(&ipa_ctx->transport_pm.dec_clients, 1);
		}
		mutex_unlock(&ipa_ctx->transport_pm.transport_pm_mutex);
	}
}

/** ipa_init_interrupts() - Register to IPA IRQs */
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
	u32 mask;
	u32 value;

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
	ipa_debug("IPA clocks are %s\n",
		  ipa_ctx->smp2p_info.ipa_clk_on ? "ON" : "OFF");
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

/** ipa_post_init() - Initialize the IPA Driver (Part II).
 * This part contains all initialization which requires interaction with
 * IPA HW (via GSI).
 *
 * Function initialization process:
 * - Initialize endpoints bitmaps
 * - Initialize resource groups min and max values
 * - Initialize filtering lists heads and idr
 * - Initialize interrupts
 * - Register GSI
 * - Setup APPS pipes
 * - Initialize IPA debugfs
 * - Initialize IPA uC interface
 * - Initialize WDI interface
 * - Initialize USB interface
 * - Register for panic handler
 * - Trigger IPA ready callbacks (to all subscribers)
 * - Trigger IPA completion object (to all who wait on it)
 */
static void ipa_post_init(struct work_struct *unused)
{
	int result;

	/* Assign resource limitation to each group */
	ipa_set_resource_groups_min_max_limits();

	result = ipa_init_interrupts();
	if (result) {
		ipa_err("ipa initialization of interrupts failed\n");
		return;
	}

	result = gsi_register_device(ipa_ctx->gsi);
	if (result) {
		ipa_err(":gsi register error - %d\n", result);
		return;
	}
	ipa_debug("IPA gsi is registered\n");

	/* setup the AP-IPA pipes */
	if (ipa_setup_apps_pipes()) {
		ipa_err(":failed to setup IPA-Apps pipes\n");
		gsi_deregister_device(ipa_ctx->gsi);

		return;
	}
	ipa_debug("IPA GPI pipes were connected\n");

	ipa_ctx->uc_ctx = ipa_uc_init(ipa_ctx->ipa_phys);
	if (!ipa_ctx->uc_ctx)
		ipa_err("microcontroller init failed\n");

	ipa_register_panic_hdlr();

	ipa_ctx->q6_proxy_clk_vote_valid = true;

	if (ipa_wwan_init())
		ipa_err("WWAN init failed (ignoring)\n");

	ipa_info("IPA driver initialization was successful.\n");
}

static bool config_valid(u32 filter_bitmap)
{
	u32 filter_count;
	u32 required_size;

	/* The size of a filter or route table entry must be non-zero */
	BUILD_BUG_ON(!IPA_HW_TBL_HDR_WIDTH);

	/* The number of entries in the AP route tables must be non-zero,
	 * for both IPv4 and IPv6.  (This is not true for filter tables.)
	 */
	BUILD_BUG_ON(!IPA_MEM_V4_RT_NUM_INDEX);
	BUILD_BUG_ON(!IPA_MEM_V6_RT_NUM_INDEX);

	/* The size set aside for the AP route tables for IPv4 and
	 * IPv6, both hashed and un-hashed, must be big enough to
	 * hold all of the entries (the number of entries times the
	 * size of each entry).
	 */
	BUILD_BUG_ON(IPA_MEM_V4_RT_NUM_INDEX * IPA_HW_TBL_HDR_WIDTH
		     > IPA_MEM_V4_RT_HASH_SIZE);
	BUILD_BUG_ON(IPA_MEM_V4_RT_NUM_INDEX * IPA_HW_TBL_HDR_WIDTH
		     > IPA_MEM_V4_RT_NHASH_SIZE);
	BUILD_BUG_ON(IPA_MEM_V6_RT_NUM_INDEX * IPA_HW_TBL_HDR_WIDTH
		     > IPA_MEM_V6_RT_HASH_SIZE);
	BUILD_BUG_ON(IPA_MEM_V6_RT_NUM_INDEX * IPA_HW_TBL_HDR_WIDTH
		     > IPA_MEM_V6_RT_NHASH_SIZE);

	/* The lower bound for the modem route table must not exceed
	 * upper bound, for both IPv4 and IPv6.
	 */
	BUILD_BUG_ON(IPA_MEM_V4_MODEM_RT_INDEX_LO >
		     IPA_MEM_V4_MODEM_RT_INDEX_HI);
	BUILD_BUG_ON(IPA_MEM_V6_MODEM_RT_INDEX_LO >
		     IPA_MEM_V6_MODEM_RT_INDEX_HI);

	/* The size set aside for the modem route tables for IPv4
	 * and IPv6, both hashed and un-hashed, must be big enough
	 * to hold all of the entries (the number of entries times
	 * the size of each entry).
	 */
#define NENTS (IPA_MEM_V4_MODEM_RT_INDEX_HI - IPA_MEM_V4_MODEM_RT_INDEX_LO + 1)
	BUILD_BUG_ON(NENTS * IPA_HW_TBL_HDR_WIDTH > IPA_MEM_V4_RT_HASH_SIZE);
	BUILD_BUG_ON(NENTS * IPA_HW_TBL_HDR_WIDTH > IPA_MEM_V4_RT_NHASH_SIZE);
#undef NENTS
#define NENTS (IPA_MEM_V6_MODEM_RT_INDEX_HI - IPA_MEM_V6_MODEM_RT_INDEX_LO + 1)
	BUILD_BUG_ON(NENTS * IPA_HW_TBL_HDR_WIDTH > IPA_MEM_V6_RT_HASH_SIZE);
	BUILD_BUG_ON(NENTS * IPA_HW_TBL_HDR_WIDTH > IPA_MEM_V6_RT_NHASH_SIZE);
#undef NENTS

	/* The endpoints that support filtering is determined at
	 * runtime, so we can't use BUILD_BUG_ON().  We require at
	 * least one pipe that supports filtering.
	 *
	 * The size set aside for the filter tables for IPv4 and IPv6,
	 * both hashed and un-hashed, must be big enough to hold all
	 * of the entries (the number of entries times the size of each
	 * entry).  Note that filter tables need an extra entry to hold
	 * an endpoint bitmap.
	 */
	if (!ipa_ctx->filter_bitmap)
		return false;
	filter_count = hweight32(ipa_ctx->filter_bitmap);
	required_size = (filter_count + 1) * IPA_HW_TBL_HDR_WIDTH;
	if (required_size > IPA_MEM_V4_FLT_HASH_SIZE)
		return false;
	if (required_size > IPA_MEM_V4_FLT_NHASH_SIZE)
		return false;
	if (required_size > IPA_MEM_V6_FLT_HASH_SIZE)
		return false;
	if (required_size > IPA_MEM_V6_FLT_NHASH_SIZE)
		return false;

	return true;
}

/** ipa_pre_init() - Initialize the IPA Driver.
 * This part contains all initialization which doesn't require IPA HW, such
 * as structure allocations and initializations, register writes, etc.
 *
 * @pdev:	The platform device structure representing the IPA driver
 *
 * Function initialization process:
 * Allocate memory for the driver context data struct
 * Initializing the ipa_ctx with :
 *    1)parsed values from the dts file
 *    2)parameters passed to the module initialization
 *    3)read HW values(such as core memory size)
 * Map IPA core registers to CPU memory
 * Restart IPA core(HW reset)
 * Initialize the look-aside caches(kmem_cache/slab) for filter,
 *   routing and IPA-tree
 * Create memory pool with 4 objects for DMA operations(each object
 *   is 512Bytes long), this object will be use for tx(A5->IPA)
 * Initialize lists head(routing, hdr, system pipes)
 * Initialize mutexes (for ipa_ctx and NAT memory mutexes)
 * Initialize spinlocks (for list related to A5<->IPA pipes)
 * Initialize 2 single-threaded work-queue named "ipa rx wq" and "ipa tx wq"
 * Initialize Red-Black-Tree(s) for handles of header,routing rule,
 *  routing table ,filtering rule
 * Initialize the filter block by committing IPV4 and IPV6 default rules
 * Create empty routing table in system memory(no committing)
 * Create a char-device for IPA
 * Initialize IPA RM (resource manager)
 * Configure GSI registers (in GSI case)
 */
static int ipa_pre_init(void)
{
	int result = 0;

	ipa_debug("IPA Driver initialization started\n");

	/* enable IPA clocks explicitly to allow the initialization */
	ipa_enable_clks();

	ipa_init_hw();

	ipa_debug("IPA HW initialization sequence completed");

	ipa_ctx->ipa_num_pipes = ipa_get_num_pipes();
	if (ipa_ctx->ipa_num_pipes > IPA_MAX_NUM_PIPES) {
		ipa_err("IPA has more pipes then supported! has %d, max %d\n",
			ipa_ctx->ipa_num_pipes, IPA_MAX_NUM_PIPES);
		result = -ENODEV;
		goto err_disable_clks;
	}

	ipa_sram_settings_read();
	ipa_debug("SRAM, size: 0x%x, restricted bytes: 0x%x\n",
		  ipa_ctx->smem_size, ipa_ctx->smem_offset);

	ipa_debug("hdr_lcl=0 ip4_rt_hash=0 ip4_rt_nonhash=0\n");
	ipa_debug("ip6_rt_hash=0 ip6_rt_nonhash=0\n");
	ipa_debug("ip4_flt_hash=0 ip4_flt_nonhash=0\n");
	ipa_debug("ip6_flt_hash=0 ip6_flt_nonhash=0\n");

	if (ipa_ctx->smem_size < IPA_MEM_END_OFST) {
		ipa_err("insufficient memory: %hu bytes available, need %u\n",
			ipa_ctx->smem_size, IPA_MEM_END_OFST);
		result = -ENOMEM;
		goto err_disable_clks;
	}

	mutex_init(&ipa_ctx->ipa_active_clients.mutex);
	atomic_set(&ipa_ctx->ipa_active_clients.cnt, 1);

	/* Create workqueues for power management */
	ipa_ctx->power_mgmt_wq =
		create_singlethread_workqueue("ipa_power_mgmt");
	if (!ipa_ctx->power_mgmt_wq) {
		ipa_err("failed to create power mgmt wq\n");
		result = -ENOMEM;
		goto err_disable_clks;
	}

	mutex_init(&ipa_ctx->transport_pm.transport_pm_mutex);

	/* init the lookaside cache */

	ipa_ctx->dp = ipa_dp_init();
	if (!ipa_ctx->dp)
		goto err_destroy_pm_wq;

	/* allocate memory for DMA_TASK workaround */
	result = ipa_gsi_dma_task_alloc();
	if (result) {
		ipa_err("failed to allocate dma task\n");
		goto err_dp_exit;
	}

	/* Create a wakeup source. */
	wakeup_source_init(&ipa_ctx->w_lock, "IPA_WS");
	spin_lock_init(&ipa_ctx->wakelock_ref_cnt.spinlock);

	/* Note enabling dynamic clock division must not be
	 * attempted for IPA hardware versions prior to 3.5.
	 */
	ipa_enable_dcd();

	return 0;

err_dp_exit:
	ipa_dp_exit(ipa_ctx->dp);
	ipa_ctx->dp = NULL;
err_destroy_pm_wq:
	destroy_workqueue(ipa_ctx->power_mgmt_wq);
err_disable_clks:
	ipa_disable_clks();

	return result;
}

static irqreturn_t ipa_smp2p_modem_clk_query_isr(int irq, void *ctxt)
{
	ipa_freeze_clock_vote_and_notify_modem();

	return IRQ_HANDLED;
}

static irqreturn_t ipa_smp2p_modem_post_init_isr(int irq, void *ctxt)
{
	queue_work(ipa_ctx->power_mgmt_wq, &ipa_post_init_work);

	return IRQ_HANDLED;
}

static int
ipa_smp2p_irq(struct device *dev, const char *name, irq_handler_t handler)
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

static int ipa_smp2p_init(struct device *dev)
{
	struct device_node *node = dev->of_node;
	struct qcom_smem_state *valid_state;
	struct qcom_smem_state *enabled_state;
	unsigned int valid_bit;
	unsigned int enabled_bit;
	int res;

	ipa_debug("node->name=%s\n", node->name);
	valid_state = qcom_smem_state_get(dev, "ipa-clock-enabled-valid",
					  &valid_bit);
	if (IS_ERR(valid_state)) {
		res = PTR_ERR(valid_state);
		ipa_err("error %d getting ipa-clock-enabled-valid state\n",
			res);

		return res;
	}

	enabled_state = qcom_smem_state_get(dev, "ipa-clock-enabled",
					    &enabled_bit);
	if (IS_ERR(enabled_state)) {
		res = PTR_ERR(enabled_state);
		ipa_err("error %d getting ipa-clock-enabled state\n", res);

		return res;
	}

	res = ipa_smp2p_irq(dev, "ipa-clock-query",
			    ipa_smp2p_modem_clk_query_isr);
	if (res < 0)
		return res;

	res = ipa_smp2p_irq(dev, "ipa-post-init",
			    ipa_smp2p_modem_post_init_isr);
	if (res < 0)
		return res;

	/* Success.  Record our smp2p information */
	ipa_ctx->smp2p_info.valid_state = valid_state;
	ipa_ctx->smp2p_info.valid_bit = valid_bit;
	ipa_ctx->smp2p_info.enabled_state = enabled_state;
	ipa_ctx->smp2p_info.enabled_bit = enabled_bit;

	return 0;
}

static void ipa_smp2p_exit(void)
{
	memset(&ipa_ctx->smp2p_info, 0, sizeof(ipa_ctx->smp2p_info));
	/* IRQ will be released when device goes away */
}

static const struct of_device_id ipa_plat_drv_match[] = {
	{ .compatible = "qcom,ipa-sdm845", },
	{}
};

static int ipa_plat_drv_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct resource *res;
	size_t size;
	int result;

	/* We assume we're working on 64-bit hardware */
	BUILD_BUG_ON(!IS_ENABLED(CONFIG_64BIT));

	ipa_debug("IPA driver: probing\n");

	/* Initialize the smp2p driver first.  It might not be ready
	 * when we're probed, so it might return -EPROBE_DEFER (meaning
	 * we'll get probed again).
	 */
	result = ipa_smp2p_init(dev);
	if (result)
		return result;

	/* Initialize the interconnect driver early too.  It might
	 * also return -EPROBE_DEFER.
	 */
	result = ipa_interconnect_init(dev);
	if (result)
		goto out_smp2p_exit;

	/* Compute a bitmask representing which endpoints support filtering */
	ipa_ctx->filter_bitmap = ipa_filter_bitmap_init();

	/* Now make sure we have a valid configuration before proceeding */
	if (!config_valid(ipa_ctx->filter_bitmap)) {
		ipa_err("invalid configuration\n");
		result = -EFAULT;
		goto err_clear_filter_bitmap;
	}

	result = platform_get_irq_byname(pdev, "ipa");
	if (result < 0)
		goto err_clear_filter_bitmap;
	ipa_ctx->ipa_irq = result;

	/* Get IPA memory range */
	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "ipa");
	if (!res) {
		result = -ENODEV;
		goto err_clear_ipa_irq;
	}
	ipa_ctx->ipa_phys = res->start;
	size = (size_t)resource_size(res);
	ipa_debug("ipa phys %pap size 0x%08zx\n", &ipa_ctx->ipa_phys, size);

	/* Setup IPA register access */
	ipa_ctx->ipa_mmio = ioremap(ipa_ctx->ipa_phys, size);
	if (!ipa_ctx->ipa_mmio) {
		result = -EFAULT;
		goto err_clear_addr;
	}

	ipa_reg_init(ipa_ctx->ipa_mmio);

	ipa_ctx->gsi = gsi_init(pdev);
	if (IS_ERR(ipa_ctx->gsi)) {
		result = PTR_ERR(ipa_ctx->gsi);
		goto err_clear_gsi;
	}

	result = ipa_dma_init(dev, IPA_HW_TBL_SYSADDR_ALIGN);
	if (result)
		goto err_clear_gsi;

	if (ipahal_init()) {
		result = -EFAULT;
		goto err_dma_exit;
	}
	ipa_ctx->dev = dev;
	ipa_ctx->clnt_hdl_cmd = IPA_CLNT_HDL_BAD;
	ipa_ctx->clnt_hdl_lan_cons = IPA_CLNT_HDL_BAD;

	/* Proceed to real initialization */
	result = ipa_pre_init();
	if (!result)
		return 0;	/* Success */

	ipa_ctx->dev = NULL;
	ipahal_exit();
err_dma_exit:
	ipa_dma_exit();
err_clear_gsi:
	ipa_ctx->gsi = NULL;
	ipa_reg_exit();
	iounmap(ipa_ctx->ipa_mmio);
	ipa_ctx->ipa_mmio = NULL;
err_clear_addr:
	ipa_ctx->clnt_hdl_lan_cons = 0;
	ipa_ctx->clnt_hdl_cmd = 0;
	ipa_ctx->ipa_phys = 0;
err_clear_ipa_irq:
	ipa_ctx->ipa_irq = 0;
err_clear_filter_bitmap:
	ipa_ctx->filter_bitmap = 0;
	ipa_interconnect_exit();
out_smp2p_exit:
	ipa_smp2p_exit();

	return result;
}

/** ipa_ap_suspend() - suspend callback for runtime_pm
 * @dev: pointer to device
 *
 * This callback will be invoked by the runtime_pm framework when an AP suspend
 * operation is invoked, usually by pressing a suspend button.
 *
 * Returns -EAGAIN to runtime_pm framework in case IPA is in use by AP.
 * This will postpone the suspend operation until IPA is no longer used by AP.
 */
int ipa_ap_suspend(struct device *dev)
{
	int i;

	ipa_debug("Enter...\n");

	/* In case there is a tx/rx handler in polling mode fail to suspend */
	for (i = 0; i < ipa_ctx->ipa_num_pipes; i++) {
		if (ipa_ctx->ep[i].sys && ipa_ep_polling(&ipa_ctx->ep[i])) {
			ipa_err("EP %d is in polling state, do not suspend\n",
				i);
			return -EAGAIN;
		}
	}

	ipa_debug("Exit\n");

	return 0;
}

/** ipa_ap_resume() - resume callback for runtime_pm
 * @dev: pointer to device
 *
 * This callback will be invoked by the runtime_pm framework when an AP resume
 * operation is invoked.
 *
 * Always returns 0 since resume should always succeed.
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
	.driver = {
		.name = DRV_NAME,
		.owner = THIS_MODULE,
		.pm = &ipa_pm_ops,
		.of_match_table = ipa_plat_drv_match,
	},
};

builtin_platform_driver(ipa_plat_drv);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("IPA HW device driver");
