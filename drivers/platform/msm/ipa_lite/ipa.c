/* Copyright (c) 2012-2017, The Linux Foundation. All rights reserved.
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt)    "ipa %s:%d " fmt, __func__, __LINE__

#include <linux/clk.h>
#include <linux/compat.h>
#include <linux/device.h>
#include <linux/dmapool.h>
#include <linux/fs.h>
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
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/msm-bus.h>
#include <linux/msm-bus-board.h>
#include <linux/netdevice.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <soc/qcom/subsystem_restart.h>
#include <soc/qcom/smem.h>
#include <soc/qcom/scm.h>
#include <asm/cacheflush.h>

#define IPA_SUBSYSTEM_NAME "ipa_fws"
#include "ipa_i.h"
#include "ipahal/ipahal.h"
#include "ipahal/ipahal_fltrt.h"

#define IPA_GPIO_IN_QUERY_CLK_IDX 0
#define IPA_GPIO_OUT_CLK_RSP_CMPLT_IDX 0
#define IPA_GPIO_OUT_CLK_VOTE_IDX 1

#define CLEANUP_TAG_PROCESS_TIMEOUT 500

#define IPA_ACTIVE_CLIENTS_TABLE_BUF_SIZE 2048

#define IPA3_ACTIVE_CLIENT_LOG_TYPE_EP 0
#define IPA3_ACTIVE_CLIENT_LOG_TYPE_SIMPLE 1
#define IPA3_ACTIVE_CLIENT_LOG_TYPE_RESOURCE 2
#define IPA3_ACTIVE_CLIENT_LOG_TYPE_SPECIAL 3

#define IPA_SMEM_SIZE (8 * 1024)

static int ipa3_q6_clean_q6_tables(void);
static void ipa3_start_tag_process(struct work_struct *work);
static DECLARE_WORK(ipa3_tag_work, ipa3_start_tag_process);

static void ipa3_post_init_wq(struct work_struct *work);
static DECLARE_WORK(ipa3_post_init_work, ipa3_post_init_wq);

static void ipa_dec_clients_disable_clks_on_wq(struct work_struct *work);
static DECLARE_WORK(ipa_dec_clients_disable_clks_on_wq_work,
	ipa_dec_clients_disable_clks_on_wq);

static struct ipa3_context ipa3_ctx_struct;
struct ipa3_context *ipa3_ctx = &ipa3_ctx_struct;

int ipa3_active_clients_log_print_buffer(char *buf, int size)
{
	int i;
	int nbytes;
	int cnt = 0;
	int start_idx;
	int end_idx;
	unsigned long flags;

	spin_lock_irqsave(&ipa3_ctx->ipa3_active_clients_logging.lock, flags);
	start_idx = (ipa3_ctx->ipa3_active_clients_logging.log_tail + 1) %
			IPA3_ACTIVE_CLIENTS_LOG_BUFFER_SIZE_LINES;
	end_idx = ipa3_ctx->ipa3_active_clients_logging.log_head;
	for (i = start_idx; i != end_idx;
		i = (i + 1) % IPA3_ACTIVE_CLIENTS_LOG_BUFFER_SIZE_LINES) {
		nbytes = scnprintf(buf + cnt, size - cnt, "%s\n",
				ipa3_ctx->ipa3_active_clients_logging
				.log_buffer[i]);
		cnt += nbytes;
	}
	spin_unlock_irqrestore(&ipa3_ctx->ipa3_active_clients_logging.lock,
		flags);

	return cnt;
}

int ipa3_active_clients_log_print_table(char *buf, int size)
{
	int i;
	struct ipa3_active_client_htable_entry *iterator;
	int cnt = 0;
	unsigned long flags;

	spin_lock_irqsave(&ipa3_ctx->ipa3_active_clients_logging.lock, flags);
	cnt = scnprintf(buf, size, "\n---- Active Clients Table ----\n");
	hash_for_each(ipa3_ctx->ipa3_active_clients_logging.htable, i,
			iterator, list) {
		switch (iterator->type) {
		case IPA3_ACTIVE_CLIENT_LOG_TYPE_EP:
			cnt += scnprintf(buf + cnt, size - cnt,
					"%-40s %-3d ENDPOINT\n",
					iterator->id_string, iterator->count);
			break;
		case IPA3_ACTIVE_CLIENT_LOG_TYPE_SIMPLE:
			cnt += scnprintf(buf + cnt, size - cnt,
					"%-40s %-3d SIMPLE\n",
					iterator->id_string, iterator->count);
			break;
		case IPA3_ACTIVE_CLIENT_LOG_TYPE_RESOURCE:
			cnt += scnprintf(buf + cnt, size - cnt,
					"%-40s %-3d RESOURCE\n",
					iterator->id_string, iterator->count);
			break;
		case IPA3_ACTIVE_CLIENT_LOG_TYPE_SPECIAL:
			cnt += scnprintf(buf + cnt, size - cnt,
					"%-40s %-3d SPECIAL\n",
					iterator->id_string, iterator->count);
			break;
		default:
			ipa_err("Trying to print illegal active_clients type");
			break;
		}
	}
	cnt += scnprintf(buf + cnt, size - cnt,
			"\nTotal active clients count: %d\n",
			atomic_read(&ipa3_ctx->ipa3_active_clients.cnt));
	spin_unlock_irqrestore(&ipa3_ctx->ipa3_active_clients_logging.lock,
		flags);

	return cnt;
}

static int ipa3_active_clients_panic_notifier(struct notifier_block *this,
		unsigned long event, void *ptr)
{
	mutex_lock(&ipa3_ctx->ipa3_active_clients.mutex);
	ipa3_active_clients_log_print_table(ipa3_ctx->active_clients_table_buf,
			IPA_ACTIVE_CLIENTS_TABLE_BUF_SIZE);
	ipa_err("%s", ipa3_ctx->active_clients_table_buf);
	mutex_unlock(&ipa3_ctx->ipa3_active_clients.mutex);

	return NOTIFY_DONE;
}

static struct notifier_block ipa3_active_clients_panic_blk = {
	.notifier_call	= ipa3_active_clients_panic_notifier,
};

static int ipa3_active_clients_log_insert(const char *string)
{
	int head;
	int tail;

	if (!ipa3_ctx->ipa3_active_clients_logging.log_rdy)
		return -EPERM;

	head = ipa3_ctx->ipa3_active_clients_logging.log_head;
	tail = ipa3_ctx->ipa3_active_clients_logging.log_tail;

	memset(ipa3_ctx->ipa3_active_clients_logging.log_buffer[head], '_',
			IPA3_ACTIVE_CLIENTS_LOG_LINE_LEN);
	strlcpy(ipa3_ctx->ipa3_active_clients_logging.log_buffer[head], string,
			(size_t)IPA3_ACTIVE_CLIENTS_LOG_LINE_LEN);
	head = (head + 1) % IPA3_ACTIVE_CLIENTS_LOG_BUFFER_SIZE_LINES;
	if (tail == head)
		tail = (tail + 1) % IPA3_ACTIVE_CLIENTS_LOG_BUFFER_SIZE_LINES;

	ipa3_ctx->ipa3_active_clients_logging.log_tail = tail;
	ipa3_ctx->ipa3_active_clients_logging.log_head = head;

	return 0;
}

static int ipa3_active_clients_log_init(void)
{
	int i;

	spin_lock_init(&ipa3_ctx->ipa3_active_clients_logging.lock);
	ipa3_ctx->ipa3_active_clients_logging.log_buffer[0] = kzalloc(
			IPA3_ACTIVE_CLIENTS_LOG_BUFFER_SIZE_LINES *
				IPA3_ACTIVE_CLIENTS_LOG_LINE_LEN,
			GFP_KERNEL);
	ipa3_ctx->active_clients_table_buf =
			kzalloc(IPA_ACTIVE_CLIENTS_TABLE_BUF_SIZE, GFP_KERNEL);
	if (ipa3_ctx->ipa3_active_clients_logging.log_buffer == NULL) {
		ipa_err("Active Clients Logging memory allocation failed");
		goto bail;
	}
	for (i = 0; i < IPA3_ACTIVE_CLIENTS_LOG_BUFFER_SIZE_LINES; i++) {
		ipa3_ctx->ipa3_active_clients_logging.log_buffer[i] =
			ipa3_ctx->ipa3_active_clients_logging.log_buffer[0] +
			(IPA3_ACTIVE_CLIENTS_LOG_LINE_LEN * i);
	}
	ipa3_ctx->ipa3_active_clients_logging.log_head = 0;
	ipa3_ctx->ipa3_active_clients_logging.log_tail =
			IPA3_ACTIVE_CLIENTS_LOG_BUFFER_SIZE_LINES - 1;
	hash_init(ipa3_ctx->ipa3_active_clients_logging.htable);
	atomic_notifier_chain_register(&panic_notifier_list,
			&ipa3_active_clients_panic_blk);
	ipa3_ctx->ipa3_active_clients_logging.log_rdy = 1;

	return 0;

bail:
	return -ENOMEM;
}

void ipa3_active_clients_log_clear(void)
{
	unsigned long flags;

	spin_lock_irqsave(&ipa3_ctx->ipa3_active_clients_logging.lock, flags);
	ipa3_ctx->ipa3_active_clients_logging.log_head = 0;
	ipa3_ctx->ipa3_active_clients_logging.log_tail =
			IPA3_ACTIVE_CLIENTS_LOG_BUFFER_SIZE_LINES - 1;
	spin_unlock_irqrestore(&ipa3_ctx->ipa3_active_clients_logging.lock,
		flags);
}

static void ipa3_active_clients_log_destroy(void)
{
	kfree(ipa3_ctx->active_clients_table_buf);
	kfree(ipa3_ctx->ipa3_active_clients_logging.log_buffer[0]);
	memset(&ipa3_ctx->ipa3_active_clients_logging, 0,
		sizeof(ipa3_ctx->ipa3_active_clients_logging));
}

static int
ipa3_init_smem_region(u32 memory_region_size, u32 memory_region_offset)
{
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	struct ipa3_desc desc = { 0 };
	struct ipa_mem_buffer mem;
	u32 offset;
	int rc;

	if (memory_region_size == 0)
		return 0;

	if (ipahal_dma_alloc(&mem, memory_region_size, GFP_KERNEL)) {
		ipa_err("failed to alloc DMA buff of size %d\n", mem.size);
		return -ENOMEM;
	}

	offset = ipa3_ctx->smem_restricted_bytes + memory_region_offset;
	cmd_pyld = ipahal_dma_shared_mem_write_pyld(&mem, offset);
	if (!cmd_pyld) {
		ipa_err("failed to construct dma_shared_mem imm cmd\n");
		ipahal_dma_free(&mem);
		return -ENOMEM;
	}
	ipa_desc_fill_imm_cmd(&desc, cmd_pyld);

	rc = ipa3_send_cmd(1, &desc);
	if (rc) {
		ipa_err("failed to send immediate command (error %d)\n", rc);
		rc = -EFAULT;
	}

	ipahal_destroy_imm_cmd(cmd_pyld);
	ipahal_dma_free(&mem);

	return rc;
}

/**
* ipa3_init_q6_smem() - Initialize Q6 general memory and
*		       header memory regions in IPA.
*
* Return codes:
* 0: success
* -ENOMEM: failed to allocate dma memory
* -EFAULT: failed to send IPA command to initialize the memory
*/
int ipa3_init_q6_smem(void)
{
	int rc;

	IPA_ACTIVE_CLIENTS_INC_SIMPLE();

	rc = ipa3_init_smem_region(ipa3_mem(MODEM_SIZE),
		ipa3_mem(MODEM_OFST));
	if (rc) {
		ipa_err("failed to initialize Modem RAM memory\n");
		IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
		return rc;
	}

	rc = ipa3_init_smem_region(ipa3_mem(MODEM_HDR_SIZE),
		ipa3_mem(MODEM_HDR_OFST));
	if (rc) {
		ipa_err("failed to initialize Modem HDRs RAM memory\n");
		IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
		return rc;
	}

	rc = ipa3_init_smem_region(ipa3_mem(MODEM_HDR_PROC_CTX_SIZE),
		ipa3_mem(MODEM_HDR_PROC_CTX_OFST));
	if (rc) {
		ipa_err("failed to initialize Modem proc ctx RAM memory\n");
		IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
		return rc;
	}

	rc = ipa3_init_smem_region(ipa3_mem(MODEM_COMP_DECOMP_SIZE),
		ipa3_mem(MODEM_COMP_DECOMP_OFST));
	if (rc) {
		ipa_err("failed to initialize Modem Comp/Decomp RAM memory\n");
		IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
		return rc;
	}
	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();

	return rc;
}

static void ipa3_destroy_imm(void *user1, int user2)
{
	ipahal_destroy_imm_cmd(user1);
}

static void ipa3_q6_pipe_delay(bool delay)
{
	int client_idx;
	int ep_idx;
	struct ipa_ep_cfg_ctrl ep_ctrl;

	memset(&ep_ctrl, 0, sizeof(struct ipa_ep_cfg_ctrl));
	ep_ctrl.ipa_ep_delay = delay;

	for (client_idx = 0; client_idx < IPA_CLIENT_MAX; client_idx++) {
		if (IPA_CLIENT_IS_Q6_PROD(client_idx)) {
			ep_idx = ipa3_get_ep_mapping(client_idx);
			if (ep_idx < 0)
				continue;

			ipahal_write_reg_n_fields(IPA_ENDP_INIT_CTRL_n,
				ep_idx, &ep_ctrl);
		}
	}
}

static void ipa3_q6_avoid_holb(void)
{
	int ep_idx;
	int client_idx;
	struct ipa_ep_cfg_ctrl ep_suspend;
	struct ipa_ep_cfg_holb ep_holb;

	memset(&ep_suspend, 0, sizeof(ep_suspend));
	memset(&ep_holb, 0, sizeof(ep_holb));

	ep_suspend.ipa_ep_suspend = true;
	ep_holb.tmr_val = 0;
	ep_holb.en = 1;

	for (client_idx = 0; client_idx < IPA_CLIENT_MAX; client_idx++) {
		if (IPA_CLIENT_IS_Q6_CONS(client_idx)) {
			ep_idx = ipa3_get_ep_mapping(client_idx);
			if (ep_idx < 0)
				continue;

			/*
			 * ipa3_cfg_ep_holb is not used here because we are
			 * setting HOLB on Q6 pipes, and from APPS perspective
			 * they are not valid, therefore, the above function
			 * will fail.
			 */
			ipahal_write_reg_n_fields(
				IPA_ENDP_INIT_HOL_BLOCK_TIMER_n,
				ep_idx, &ep_holb);
			ipahal_write_reg_n_fields(
				IPA_ENDP_INIT_HOL_BLOCK_EN_n,
				ep_idx, &ep_holb);

			ipahal_write_reg_n_fields(IPA_ENDP_INIT_CTRL_n,
					ep_idx, &ep_suspend);
		}
	}
}

static void ipa3_halt_q6_cons_gsi_channels(void)
{
	int ep_idx;
	int client_idx;
	const struct ipa_gsi_ep_config *gsi_ep_cfg;
	int ret;
	int code = 0;

	for (client_idx = 0; client_idx < IPA_CLIENT_MAX; client_idx++) {
		if (IPA_CLIENT_IS_Q6_CONS(client_idx)) {
			ep_idx = ipa3_get_ep_mapping(client_idx);
			if (ep_idx < 0)
				continue;

			gsi_ep_cfg = ipa3_get_gsi_ep_info(client_idx);
			if (!gsi_ep_cfg) {
				ipa_err("failed to get GSI config\n");
				ipa_assert();
				return;
			}

			ret = gsi_halt_channel_ee(
				gsi_ep_cfg->ipa_gsi_chan_num, gsi_ep_cfg->ee,
				&code);
			if (!ret)
				ipa_debug("halted gsi ch %u ee %d with code %d\n",
				gsi_ep_cfg->ipa_gsi_chan_num,
				gsi_ep_cfg->ee,
				code);
			else
				ipa_err("failed to halt ch %u ee %d code %d\n",
				gsi_ep_cfg->ipa_gsi_chan_num,
				gsi_ep_cfg->ee,
				code);
		}
	}
}

static int ipa3_q6_set_ex_path_to_apps(void)
{
	int ep_idx;
	int client_idx;
	struct ipa3_desc *desc;
	int num_descs = 0;
	int index;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	int retval;

	desc = kcalloc(ipa3_ctx->ipa_num_pipes, sizeof(*desc), GFP_KERNEL);
	if (!desc) {
		ipa_err("failed to allocate memory\n");
		return -ENOMEM;
	}

	/* Set the exception path to AP */
	for (client_idx = 0; client_idx < IPA_CLIENT_MAX; client_idx++) {
		ep_idx = ipa3_get_ep_mapping(client_idx);
		if (ep_idx < 0)
			continue;

		/* disable statuses for modem producers */
		if (IPA_CLIENT_IS_Q6_PROD(client_idx)) {
			u32 offset;

			ipa_assert_on(num_descs >= ipa3_ctx->ipa_num_pipes);

			offset = ipahal_reg_n_offset(IPA_ENDP_STATUS_n, ep_idx);
			cmd_pyld = ipahal_register_write_pyld(0, ~0, offset,
								false);
			if (!cmd_pyld) {
				ipa_err("fail construct register_write cmd\n");
				ipa_assert();
				return -EFAULT;
			}
			ipa_desc_fill_imm_cmd(&desc[num_descs], cmd_pyld);
			desc[num_descs].callback = ipa3_destroy_imm;
			desc[num_descs].user1 = cmd_pyld;

			num_descs++;
		}
	}

	/* Will wait 500msecs for IPA tag process completion */
	retval = ipa3_tag_process(desc, num_descs,
		msecs_to_jiffies(CLEANUP_TAG_PROCESS_TIMEOUT));
	if (retval) {
		ipa_err("TAG process failed! (error %d)\n", retval);
		/* For timeout error ipa3_destroy_imm cb will destroy user1 */
		if (retval != -ETIME) {
			for (index = 0; index < num_descs; index++)
				if (desc[index].callback)
					desc[index].callback(desc[index].user1,
						desc[index].user2);
			retval = -EINVAL;
		}
	}

	kfree(desc);

	return retval;
}

/**
* ipa3_q6_pre_shutdown_cleanup() - A cleanup for all Q6 related configuration
*		     in IPA HW. This is performed in case of SSR.
*
* This is a mandatory procedure, in case one of the steps fails, the
* AP needs to restart.
*/
void ipa3_q6_pre_shutdown_cleanup(void)
{
	ipa_debug_low("ENTER\n");

	IPA_ACTIVE_CLIENTS_INC_SIMPLE();

	ipa3_q6_pipe_delay(true);
	ipa3_q6_avoid_holb();

	if (ipa3_q6_clean_q6_tables()) {
		ipa_err("Failed to clean Q6 tables\n");
		BUG();
	}
	if (ipa3_q6_set_ex_path_to_apps()) {
		ipa_err("Failed to redirect exceptions to APPS\n");
		BUG();
	}
	/* Remove delay from Q6 PRODs to avoid pending descriptors
	  * on pipe reset procedure
	  */
	ipa3_q6_pipe_delay(false);

	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
	ipa_debug_low("Exit with success\n");
}

/*
 * ipa3_q6_post_shutdown_cleanup() - As part of this cleanup
 * check if GSI channel related to Q6 producer client is empty.
 *
 * Q6 GSI channel emptiness is needed to garantee no descriptors with invalid
 *  info are injected into IPA RX from IPA_IF, while modem is restarting.
 */
void ipa3_q6_post_shutdown_cleanup(void)
{
	int client_idx;
	int ep_idx;

	ipa_debug_low("ENTER\n");

	if (!ipa3_ctx->uc_ctx.uc_loaded) {
		ipa_err("uC is not loaded. Skipping\n");
		return;
	}

	IPA_ACTIVE_CLIENTS_INC_SIMPLE();

	/* Handle the issue where SUSPEND was removed for some reason */
	ipa3_q6_avoid_holb();
	ipa3_halt_q6_cons_gsi_channels();

	for (client_idx = 0; client_idx < IPA_CLIENT_MAX; client_idx++)
		if (IPA_CLIENT_IS_Q6_PROD(client_idx)) {
			ep_idx = ipa3_get_ep_mapping(client_idx);
			if (ep_idx < 0)
				continue;

			if (ipa3_uc_is_gsi_channel_empty(client_idx)) {
				ipa_err("fail to validate Q6 ch emptiness %d\n",
					client_idx);
				BUG();
				return;
			}
		}

	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
	ipa_debug_low("Exit with success\n");
}

static inline void ipa3_sram_set_canary(u32 *sram_mmio, int offset)
{
	/* Set 4 bytes of CANARY before the offset */
	sram_mmio[(offset - 4) / 4] = IPA_MEM_CANARY_VAL;
}

/**
 * _ipa_init_sram_v3() - Initialize IPA local SRAM.
 *
 * Return codes: 0 for success, negative value for failure
 */
int _ipa_init_sram_v3(void)
{
	u32 *ipa_sram_mmio;
	unsigned long phys_addr;

	phys_addr = ipa3_ctx->ipa_wrapper_base +
		ipa3_ctx->ctrl->ipa_reg_base_ofst +
		ipahal_reg_n_offset(IPA_SRAM_DIRECT_ACCESS_n,
			ipa3_ctx->smem_restricted_bytes / 4);

	ipa_sram_mmio = ioremap(phys_addr, ipa3_ctx->smem_sz);
	if (!ipa_sram_mmio) {
		ipa_err("fail to ioremap IPA SRAM\n");
		return -ENOMEM;
	}

	/* Consult with ipa_i.h on the location of the CANARY values */
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(V4_FLT_HASH_OFST) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(V4_FLT_HASH_OFST));
	ipa3_sram_set_canary(ipa_sram_mmio,
		ipa3_mem(V4_FLT_NHASH_OFST) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(V4_FLT_NHASH_OFST));
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(V6_FLT_HASH_OFST) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(V6_FLT_HASH_OFST));
	ipa3_sram_set_canary(ipa_sram_mmio,
		ipa3_mem(V6_FLT_NHASH_OFST) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(V6_FLT_NHASH_OFST));
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(V4_RT_HASH_OFST) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(V4_RT_HASH_OFST));
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(V4_RT_NHASH_OFST) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(V4_RT_NHASH_OFST));
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(V6_RT_HASH_OFST) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(V6_RT_HASH_OFST));
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(V6_RT_NHASH_OFST) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(V6_RT_NHASH_OFST));
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(MODEM_HDR_OFST) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(MODEM_HDR_OFST));
	ipa3_sram_set_canary(ipa_sram_mmio,
		ipa3_mem(MODEM_HDR_PROC_CTX_OFST) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio,
		ipa3_mem(MODEM_HDR_PROC_CTX_OFST));
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(MODEM_OFST) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(MODEM_OFST));
	ipa3_sram_set_canary(ipa_sram_mmio, ipa3_mem(UC_EVENT_RING_OFST));

	iounmap(ipa_sram_mmio);

	return 0;
}

/**
 * _ipa_init_hdr_v3_0() - Initialize IPA header block.
 *
 * Return codes: 0 for success, negative value for failure
 */
int _ipa_init_hdr_v3_0(void)
{
	struct ipa3_desc desc = { 0 };
	struct ipa_mem_buffer mem;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	u32 dma_size;
	u32 offset;

	dma_size = ipa3_mem(MODEM_HDR_SIZE) + ipa3_mem(APPS_HDR_SIZE);
	if (ipahal_dma_alloc(&mem, dma_size, GFP_KERNEL)) {
		ipa_err("fail to alloc DMA buff of size %u\n", dma_size);
		return -ENOMEM;
	}

	offset = ipa3_ctx->smem_restricted_bytes + ipa3_mem(MODEM_HDR_OFST);
	cmd_pyld = ipahal_hdr_init_local_pyld(&mem, offset);
	if (!cmd_pyld) {
		ipa_err("fail to construct hdr_init_local imm cmd\n");
		ipahal_dma_free(&mem);
		return -EFAULT;
	}
	ipa_desc_fill_imm_cmd(&desc, cmd_pyld);
	IPA_DUMP_BUFF(mem.base, mem.phys_base, mem.size);

	if (ipa3_send_cmd(1, &desc)) {
		ipa_err("fail to send immediate command\n");
		ipahal_destroy_imm_cmd(cmd_pyld);
		ipahal_dma_free(&mem);
		return -EFAULT;
	}

	ipahal_destroy_imm_cmd(cmd_pyld);
	ipahal_dma_free(&mem);

	dma_size = ipa3_mem(MODEM_HDR_PROC_CTX_SIZE) +
			ipa3_mem(APPS_HDR_PROC_CTX_SIZE);
	if (ipahal_dma_alloc(&mem, dma_size, GFP_KERNEL)) {
		ipa_err("fail to alloc DMA buff of size %u\n", dma_size);
		return -ENOMEM;
	}

	offset = ipa3_ctx->smem_restricted_bytes +
			ipa3_mem(MODEM_HDR_PROC_CTX_OFST);
	cmd_pyld = ipahal_dma_shared_mem_write_pyld(&mem, offset);
	if (!cmd_pyld) {
		ipa_err("fail to construct dma_shared_mem imm\n");
		ipahal_dma_free(&mem);
		return -EFAULT;
	}

	memset(&desc, 0, sizeof(desc));
	ipa_desc_fill_imm_cmd(&desc, cmd_pyld);
	IPA_DUMP_BUFF(mem.base, mem.phys_base, mem.size);

	if (ipa3_send_cmd(1, &desc)) {
		ipa_err("fail to send immediate command\n");
		ipahal_destroy_imm_cmd(cmd_pyld);
		ipahal_dma_free(&mem);
		return -EFAULT;
	}
	ipahal_destroy_imm_cmd(cmd_pyld);

	ipahal_write_reg(IPA_LOCAL_PKT_PROC_CNTXT_BASE, 0);

	ipahal_dma_free(&mem);

	return 0;
}

/**
 * _ipa_init_rt4_v3() - Initialize IPA routing block for IPv4.
 *
 * Return codes: 0 for success, negative value for failure
 */
int _ipa_init_rt4_v3(void)
{
	struct ipa3_desc desc = { 0 };
	struct ipa_mem_buffer mem;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	u32 hash_offset;
	u32 nhash_offset;
	int rc;

	rc = ipahal_rt_generate_empty_img(ipa3_mem(V4_RT_NUM_INDEX), &mem,
						GFP_KERNEL);
	if (rc) {
		ipa_err("fail generate empty v4 rt img\n");
		return rc;
	}

	hash_offset = ipa3_ctx->smem_restricted_bytes +
				ipa3_mem(V4_RT_HASH_OFST);
	nhash_offset = ipa3_ctx->smem_restricted_bytes +
				ipa3_mem(V4_RT_NHASH_OFST);
	cmd_pyld =
		ipahal_ip_v4_routing_init_pyld(&mem, hash_offset, nhash_offset);
	if (!cmd_pyld) {
		ipa_err("fail construct ip_v4_rt_init imm cmd\n");
		rc = -EPERM;
		goto free_mem;
	}
	ipa_desc_fill_imm_cmd(&desc, cmd_pyld);
	IPA_DUMP_BUFF(mem.base, mem.phys_base, mem.size);

	if (ipa3_send_cmd(1, &desc)) {
		ipa_err("fail to send immediate command\n");
		rc = -EFAULT;
	}

	ipahal_destroy_imm_cmd(cmd_pyld);

free_mem:
	ipahal_free_empty_img(&mem);
	return rc;
}

/**
 * _ipa_init_rt6_v3() - Initialize IPA routing block for IPv6.
 *
 * Return codes: 0 for success, negative value for failure
 */
int _ipa_init_rt6_v3(void)
{
	struct ipa3_desc desc = { 0 };
	struct ipa_mem_buffer mem;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	u32 hash_offset;
	u32 nhash_offset;
	int rc;

	rc = ipahal_rt_generate_empty_img(ipa3_mem(V6_RT_NUM_INDEX), &mem,
						GFP_KERNEL);
	if (rc) {
		ipa_err("fail generate empty v6 rt img\n");
		return rc;
	}

	hash_offset = ipa3_ctx->smem_restricted_bytes +
				ipa3_mem(V6_RT_HASH_OFST);
	nhash_offset = ipa3_ctx->smem_restricted_bytes +
				ipa3_mem(V6_RT_NHASH_OFST);
	cmd_pyld =
		ipahal_ip_v6_routing_init_pyld(&mem, hash_offset, nhash_offset);
	if (!cmd_pyld) {
		ipa_err("fail construct ip_v6_rt_init imm cmd\n");
		rc = -EPERM;
		goto free_mem;
	}
	ipa_desc_fill_imm_cmd(&desc, cmd_pyld);
	IPA_DUMP_BUFF(mem.base, mem.phys_base, mem.size);

	if (ipa3_send_cmd(1, &desc)) {
		ipa_err("fail to send immediate command\n");
		rc = -EFAULT;
	}

	ipahal_destroy_imm_cmd(cmd_pyld);

free_mem:
	ipahal_free_empty_img(&mem);
	return rc;
}

/**
 * _ipa_init_flt4_v3() - Initialize IPA filtering block for IPv4.
 *
 * Return codes: 0 for success, negative value for failure
 */
int _ipa_init_flt4_v3(void)
{
	struct ipa3_desc desc = { 0 };
	struct ipa_mem_buffer mem;
	struct ipahal_imm_cmd_ip_v4_filter_init v4_cmd;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	int rc;

	rc = ipahal_flt_generate_empty_img(ipa3_ctx->ep_flt_num,
					ipa3_ctx->ep_flt_bitmap, &mem,
					GFP_KERNEL);
	if (rc) {
		ipa_err("fail generate empty v4 flt img\n");
		return rc;
	}

	v4_cmd.hash_rules_addr = mem.phys_base;
	v4_cmd.hash_rules_size = mem.size;
	v4_cmd.hash_local_addr = ipa3_ctx->smem_restricted_bytes +
		ipa3_mem(V4_FLT_HASH_OFST);
	v4_cmd.nhash_rules_addr = mem.phys_base;
	v4_cmd.nhash_rules_size = mem.size;
	v4_cmd.nhash_local_addr = ipa3_ctx->smem_restricted_bytes +
		ipa3_mem(V4_FLT_NHASH_OFST);
	ipa_debug("putting hashable filtering IPv4 rules to phys 0x%x\n",
				v4_cmd.hash_local_addr);
	ipa_debug("putting non-hashable filtering IPv4 rules to phys 0x%x\n",
				v4_cmd.nhash_local_addr);
	cmd_pyld = ipahal_construct_imm_cmd(IPA_IMM_CMD_IP_V4_FILTER_INIT,
						&v4_cmd);
	if (!cmd_pyld) {
		ipa_err("fail construct ip_v4_flt_init imm cmd\n");
		rc = -EPERM;
		goto free_mem;
	}
	ipa_desc_fill_imm_cmd(&desc, cmd_pyld);
	IPA_DUMP_BUFF(mem.base, mem.phys_base, mem.size);

	if (ipa3_send_cmd(1, &desc)) {
		ipa_err("fail to send immediate command\n");
		rc = -EFAULT;
	}

	ipahal_destroy_imm_cmd(cmd_pyld);

free_mem:
	ipahal_free_empty_img(&mem);
	return rc;
}

/**
 * _ipa_init_flt6_v3() - Initialize IPA filtering block for IPv6.
 *
 * Return codes: 0 for success, negative value for failure
 */
int _ipa_init_flt6_v3(void)
{
	struct ipa3_desc desc = { 0 };
	struct ipa_mem_buffer mem;
	struct ipahal_imm_cmd_ip_v6_filter_init v6_cmd;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	int rc;

	rc = ipahal_flt_generate_empty_img(ipa3_ctx->ep_flt_num,
					ipa3_ctx->ep_flt_bitmap, &mem,
					GFP_KERNEL);
	if (rc) {
		ipa_err("fail generate empty v6 flt img\n");
		return rc;
	}

	v6_cmd.hash_rules_addr = mem.phys_base;
	v6_cmd.hash_rules_size = mem.size;
	v6_cmd.hash_local_addr = ipa3_ctx->smem_restricted_bytes +
		ipa3_mem(V6_FLT_HASH_OFST);
	v6_cmd.nhash_rules_addr = mem.phys_base;
	v6_cmd.nhash_rules_size = mem.size;
	v6_cmd.nhash_local_addr = ipa3_ctx->smem_restricted_bytes +
		ipa3_mem(V6_FLT_NHASH_OFST);
	ipa_debug("putting hashable filtering IPv6 rules to phys 0x%x\n",
				v6_cmd.hash_local_addr);
	ipa_debug("putting non-hashable filtering IPv6 rules to phys 0x%x\n",
				v6_cmd.nhash_local_addr);

	cmd_pyld = ipahal_construct_imm_cmd(IPA_IMM_CMD_IP_V6_FILTER_INIT,
						&v6_cmd);
	if (!cmd_pyld) {
		ipa_err("fail construct ip_v6_flt_init imm cmd\n");
		rc = -EPERM;
		goto free_mem;
	}
	ipa_desc_fill_imm_cmd(&desc, cmd_pyld);
	IPA_DUMP_BUFF(mem.base, mem.phys_base, mem.size);

	if (ipa3_send_cmd(1, &desc)) {
		ipa_err("fail to send immediate command\n");
		rc = -EFAULT;
	}

	ipahal_destroy_imm_cmd(cmd_pyld);

free_mem:
	ipahal_free_empty_img(&mem);
	return rc;
}


static void ipa3_setup_flt_hash_tuple(void)
{
	int pipe_idx;
	struct ipahal_reg_hash_tuple tuple;

	memset(&tuple, 0, sizeof(struct ipahal_reg_hash_tuple));

	for (pipe_idx = 0; pipe_idx < ipa3_ctx->ipa_num_pipes ; pipe_idx++) {
		if (!ipa_is_ep_support_flt(pipe_idx))
			continue;

		if (ipa_is_modem_pipe(pipe_idx))
			continue;

		ipa3_set_flt_tuple_mask(pipe_idx, &tuple);
	}
}

static void ipa3_setup_rt_hash_tuple(void)
{
	int tbl_idx;
	struct ipahal_reg_hash_tuple tuple;

	memset(&tuple, 0, sizeof(struct ipahal_reg_hash_tuple));

	for (tbl_idx = 0;
		tbl_idx < max(ipa3_mem(V6_RT_NUM_INDEX),
		ipa3_mem(V4_RT_NUM_INDEX));
		tbl_idx++) {

		if (tbl_idx >= ipa3_mem(V4_MODEM_RT_INDEX_LO) &&
			tbl_idx <= ipa3_mem(V4_MODEM_RT_INDEX_HI))
			continue;

		if (tbl_idx >= ipa3_mem(V6_MODEM_RT_INDEX_LO) &&
			tbl_idx <= ipa3_mem(V6_MODEM_RT_INDEX_HI))
			continue;

		ipa3_set_rt_tuple_mask(tbl_idx, &tuple);
	}
}

static long ipa3_setup_apps_pipes(void)
{
	struct ipa_sys_connect_params sys_in;
	long result;

	/*
	 * Memory size must be a multiple of the ring element size.
	 * Note that ipa_gsi_chan_mem_size() assumes a multipler
	 * (4 for producer, 2 for consumer) times the desc_fifo_sz
	 * set below (reproduced here; 2 is the more restrictive case).
	 */
	BUILD_BUG_ON((2 * IPA_SYS_DESC_FIFO_SZ) % GSI_EVT_RING_ELEMENT_SIZE);

	/* allocate the common PROD event ring */
	result = gsi_alloc_evt_ring(IPA_COMMON_EVENT_RING_SIZE, 0, false);
	if (result < 0) {
		ipa_err("ipa3_alloc_common_event_ring failed.\n");
		result = -EPERM;
		goto fail_ch20_wa;
	}
	ipa3_ctx->gsi_evt_comm_hdl = result;
	ipa3_ctx->gsi_evt_comm_ring_rem = IPA_COMMON_EVENT_RING_SIZE;

	/* CMD OUT (AP->IPA) */
	memset(&sys_in, 0, sizeof(struct ipa_sys_connect_params));
	sys_in.client = IPA_CLIENT_APPS_CMD_PROD;
	sys_in.desc_fifo_sz = IPA_SYS_DESC_FIFO_SZ;
	sys_in.ipa_ep_cfg.mode.mode = IPA_DMA;
	sys_in.ipa_ep_cfg.mode.dst = IPA_CLIENT_APPS_LAN_CONS;
	if (ipa3_setup_sys_pipe(&sys_in, &ipa3_ctx->clnt_hdl_cmd)) {
		ipa_err(":setup sys pipe (APPS_CMD_PROD) failed.\n");
		result = -EPERM;
		goto fail_ch20_wa;
	}
	ipa_debug("Apps to IPA cmd pipe is connected\n");

	ipa3_ctx->ctrl->ipa_init_sram();
	ipa_debug("SRAM initialized\n");

	ipa3_ctx->ctrl->ipa_init_hdr();
	ipa_debug("HDR initialized\n");

	ipa3_ctx->ctrl->ipa_init_rt4();
	ipa_debug("V4 RT initialized\n");

	ipa3_ctx->ctrl->ipa_init_rt6();
	ipa_debug("V6 RT initialized\n");

	ipa3_ctx->ctrl->ipa_init_flt4();
	ipa_debug("V4 FLT initialized\n");

	ipa3_ctx->ctrl->ipa_init_flt6();
	ipa_debug("V6 FLT initialized\n");

	ipa3_setup_flt_hash_tuple();
	ipa_debug("flt hash tuple is configured\n");

	ipa3_setup_rt_hash_tuple();
	ipa_debug("rt hash tuple is configured\n");

	/* LAN IN (IPA->AP) */
	memset(&sys_in, 0, sizeof(struct ipa_sys_connect_params));
	sys_in.client = IPA_CLIENT_APPS_LAN_CONS;
	sys_in.desc_fifo_sz = IPA_SYS_DESC_FIFO_SZ;
	sys_in.notify = ipa3_lan_rx_cb;
	sys_in.priv = NULL;
	sys_in.ipa_ep_cfg.hdr.hdr_len = IPA_LAN_RX_HEADER_LENGTH;
	sys_in.ipa_ep_cfg.hdr_ext.hdr_little_endian = false;
	sys_in.ipa_ep_cfg.hdr_ext.hdr_total_len_or_pad_valid = true;
	sys_in.ipa_ep_cfg.hdr_ext.hdr_total_len_or_pad = IPA_HDR_PAD;
	sys_in.ipa_ep_cfg.hdr_ext.hdr_payload_len_inc_padding = false;
	sys_in.ipa_ep_cfg.hdr_ext.hdr_total_len_or_pad_offset = 0;
	sys_in.ipa_ep_cfg.hdr_ext.hdr_pad_to_alignment = 2;
	sys_in.ipa_ep_cfg.cfg.cs_offload_en = IPA_ENABLE_CS_OFFLOAD_DL;
	if (ipa3_setup_sys_pipe(&sys_in, &ipa3_ctx->clnt_hdl_data_in)) {
		ipa_err(":setup sys pipe (LAN_CONS) failed.\n");
		result = -EPERM;
		goto fail_flt_hash_tuple;
	}

	return 0;

fail_flt_hash_tuple:
	ipa3_teardown_sys_pipe(ipa3_ctx->clnt_hdl_cmd);
fail_ch20_wa:
	return result;
}

/**
 * _ipa_enable_clks_v3_0() - Enable IPA clocks.
 */
void _ipa_enable_clks_v3_0(void)
{
	ipa_debug_low("curr_ipa_clk_rate=%d", ipa3_ctx->curr_ipa_clk_rate);
}

static unsigned int ipa3_get_bus_vote(void)
{
	unsigned int idx = 1;

	if (ipa3_ctx->curr_ipa_clk_rate == ipa3_ctx->ctrl->ipa_clk_rate_svs) {
		idx = 1;
	} else if (ipa3_ctx->curr_ipa_clk_rate ==
			ipa3_ctx->ctrl->ipa_clk_rate_nominal) {
		if (ipa3_ctx->ctrl->msm_bus_data_ptr->num_usecases <= 2)
			idx = 1;
		else
			idx = 2;
	} else if (ipa3_ctx->curr_ipa_clk_rate ==
			ipa3_ctx->ctrl->ipa_clk_rate_turbo) {
		idx = ipa3_ctx->ctrl->msm_bus_data_ptr->num_usecases - 1;
	} else {
		WARN_ON(1);
	}

	ipa_debug("curr %d idx %d\n", ipa3_ctx->curr_ipa_clk_rate, idx);

	return idx;
}

/**
* ipa3_enable_clks() - Turn on IPA clocks
*
* Return codes:
* None
*/
void ipa3_enable_clks(void)
{
	ipa_debug("enabling IPA clocks and bus voting\n");

	if (msm_bus_scale_client_update_request(ipa3_ctx->ipa_bus_hdl,
	    ipa3_get_bus_vote()))
		WARN_ON(1);

	ipa3_ctx->ctrl->ipa3_enable_clks();
}


/**
 * _ipa_disable_clks_v3_0() - Disable IPA clocks.
 */
void _ipa_disable_clks_v3_0(void)
{
	ipa3_suspend_apps_pipes(true);
}

/**
* ipa3_disable_clks() - Turn off IPA clocks
*
* Return codes:
* None
*/
void ipa3_disable_clks(void)
{
	ipa_debug("disabling IPA clocks and bus voting\n");

	ipa3_ctx->ctrl->ipa3_disable_clks();

	if (msm_bus_scale_client_update_request(ipa3_ctx->ipa_bus_hdl, 0))
		WARN_ON(1);
}

/**
 * ipa3_start_tag_process() - Send TAG packet and wait for it to come back
 *
 * This function is called prior to clock gating when active client counter
 * is 1. TAG process ensures that there are no packets inside IPA HW that
 * were not submitted to the IPA client via the transport. During TAG process
 * all aggregation frames are (force) closed.
 *
 * Return codes:
 * None
 */
static void ipa3_start_tag_process(struct work_struct *work)
{
	int res;

	ipa_debug("starting TAG process\n");
	/* close aggregation frames on all pipes */
	res = ipa3_tag_aggr_force_close(-1);
	if (res)
		ipa_err("ipa3_tag_aggr_force_close failed %d\n", res);
	IPA_ACTIVE_CLIENTS_DEC_SPECIAL("TAG_PROCESS");

	ipa_debug("TAG process done\n");
}

/**
* ipa3_active_clients_log_mod() - Log a modification in the active clients
* reference count
*
* This method logs any modification in the active clients reference count:
* It logs the modification in the circular history buffer
* It logs the modification in the hash table - looking for an entry,
* creating one if needed and deleting one if needed.
*
* @id: ipa3_active client logging info struct to hold the log information
* @inc: a boolean variable to indicate whether the modification is an increase
* or decrease
* @int_ctx: a boolean variable to indicate whether this call is being made from
* an interrupt context and therefore should allocate GFP_ATOMIC memory
*
* Method process:
* - Hash the unique identifier string
* - Find the hash in the table
*    1)If found, increase or decrease the reference count
*    2)If not found, allocate a new hash table entry struct and initialize it
* - Remove and deallocate unneeded data structure
* - Log the call in the circular history buffer (unless it is a simple call)
*/
static void
ipa3_active_clients_log_mod(struct ipa_active_client_logging_info *id,
		bool inc, bool int_ctx)
{
	char temp_str[IPA3_ACTIVE_CLIENTS_LOG_LINE_LEN];
	unsigned long long t;
	unsigned long nanosec_rem;
	struct ipa3_active_client_htable_entry *hentry;
	struct ipa3_active_client_htable_entry *hfound;
	u32 hkey;
	char str_to_hash[IPA3_ACTIVE_CLIENTS_LOG_NAME_LEN];
	unsigned long flags;

	spin_lock_irqsave(&ipa3_ctx->ipa3_active_clients_logging.lock, flags);
	int_ctx = true;
	hfound = NULL;
	memset(str_to_hash, 0, IPA3_ACTIVE_CLIENTS_LOG_NAME_LEN);
	strlcpy(str_to_hash, id->id_string, IPA3_ACTIVE_CLIENTS_LOG_NAME_LEN);
	hkey = jhash(str_to_hash, IPA3_ACTIVE_CLIENTS_LOG_NAME_LEN,
			0);
	hash_for_each_possible(ipa3_ctx->ipa3_active_clients_logging.htable,
			hentry, list, hkey) {
		if (!strcmp(hentry->id_string, id->id_string)) {
			hentry->count = hentry->count + (inc ? 1 : -1);
			hfound = hentry;
		}
	}
	if (hfound == NULL) {
		hentry = kzalloc(sizeof(*hentry),
				int_ctx ? GFP_ATOMIC : GFP_KERNEL);
		if (hentry == NULL) {
			ipa_err("failed allocating active clients hash entry");
			spin_unlock_irqrestore(
				&ipa3_ctx->ipa3_active_clients_logging.lock,
				flags);
			return;
		}
		hentry->type = id->type;
		strlcpy(hentry->id_string, id->id_string,
				IPA3_ACTIVE_CLIENTS_LOG_NAME_LEN);
		INIT_HLIST_NODE(&hentry->list);
		hentry->count = inc ? 1 : -1;
		hash_add(ipa3_ctx->ipa3_active_clients_logging.htable,
				&hentry->list, hkey);
	} else if (hfound->count == 0) {
		hash_del(&hfound->list);
		kfree(hfound);
	}

	if (id->type != SIMPLE) {
		t = local_clock();
		nanosec_rem = t % 1000000000;	/* nanoseconds */
		t /= 1000000000;		/* whole seconds */
		snprintf(temp_str, IPA3_ACTIVE_CLIENTS_LOG_LINE_LEN,
				"[%5llu.%06lu] %c %s, %s: %d",
				t, nanosec_rem / 1000, inc ? '^' : 'v',
				id->id_string, id->file, id->line);
		ipa3_active_clients_log_insert(temp_str);
	}
	spin_unlock_irqrestore(&ipa3_ctx->ipa3_active_clients_logging.lock,
		flags);
}

static void
ipa3_active_clients_log_dec(struct ipa_active_client_logging_info *id,
		bool int_ctx)
{
	ipa3_active_clients_log_mod(id, false, int_ctx);
}

static void
ipa3_active_clients_log_inc(struct ipa_active_client_logging_info *id,
		bool int_ctx)
{
	ipa3_active_clients_log_mod(id, true, int_ctx);
}

/**
* ipa3_inc_client_enable_clks() - Increase active clients counter, and
* enable ipa clocks if necessary
*
* Return codes:
* None
*/
void ipa3_inc_client_enable_clks(struct ipa_active_client_logging_info *id)
{
	int ret;

	ipa3_active_clients_log_inc(id, false);
	ret = atomic_inc_not_zero(&ipa3_ctx->ipa3_active_clients.cnt);
	if (ret) {
		ipa_debug_low("active clients = %d\n",
			atomic_read(&ipa3_ctx->ipa3_active_clients.cnt));
		return;
	}

	mutex_lock(&ipa3_ctx->ipa3_active_clients.mutex);

	/* somebody might voted to clocks meanwhile */
	ret = atomic_inc_not_zero(&ipa3_ctx->ipa3_active_clients.cnt);
	if (ret) {
		mutex_unlock(&ipa3_ctx->ipa3_active_clients.mutex);
		ipa_debug_low("active clients = %d\n",
			atomic_read(&ipa3_ctx->ipa3_active_clients.cnt));
		return;
	}

	ipa3_enable_clks();
	atomic_inc(&ipa3_ctx->ipa3_active_clients.cnt);
	ipa_debug_low("active clients = %d\n",
		atomic_read(&ipa3_ctx->ipa3_active_clients.cnt));
	ipa3_suspend_apps_pipes(false);
	mutex_unlock(&ipa3_ctx->ipa3_active_clients.mutex);
}

/**
* ipa3_inc_client_enable_clks_no_block() - Only increment the number of active
* clients if no asynchronous actions should be done. Asynchronous actions are
* locking a mutex and waking up IPA HW.
*
* Return codes: 0 for success
*		-EPERM if an asynchronous action should have been done
*/
int ipa3_inc_client_enable_clks_no_block(struct ipa_active_client_logging_info
		*id)
{
	int ret;

	ret = atomic_inc_not_zero(&ipa3_ctx->ipa3_active_clients.cnt);
	if (ret) {
		ipa3_active_clients_log_inc(id, true);
		ipa_debug_low("active clients = %d\n",
			atomic_read(&ipa3_ctx->ipa3_active_clients.cnt));
		return 0;
	}

	return -EPERM;
}

static void __ipa3_dec_client_disable_clks(void)
{
	int ret;

	if (!atomic_read(&ipa3_ctx->ipa3_active_clients.cnt)) {
		ipa_err("trying to disable clocks with refcnt is 0!\n");
		ipa_assert();
		return;
	}

	ret = atomic_add_unless(&ipa3_ctx->ipa3_active_clients.cnt, -1, 1);
	if (ret)
		goto bail;

	/* seems like this is the only client holding the clocks */
	mutex_lock(&ipa3_ctx->ipa3_active_clients.mutex);
	if (atomic_read(&ipa3_ctx->ipa3_active_clients.cnt) == 1 &&
	    ipa3_ctx->tag_process_before_gating) {
		ipa3_ctx->tag_process_before_gating = false;
		/*
		 * When TAG process ends, active clients will be
		 * decreased
		 */
		queue_work(ipa3_ctx->power_mgmt_wq, &ipa3_tag_work);
		goto unlock_mutex;
	}

	/* a different context might increase the clock reference meanwhile */
	ret = atomic_sub_return(1, &ipa3_ctx->ipa3_active_clients.cnt);
	if (ret > 0)
		goto unlock_mutex;
	ipa3_disable_clks();

unlock_mutex:
	mutex_unlock(&ipa3_ctx->ipa3_active_clients.mutex);
bail:
	ipa_debug_low("active clients = %d\n",
		atomic_read(&ipa3_ctx->ipa3_active_clients.cnt));
}

/**
 * ipa3_dec_client_disable_clks() - Decrease active clients counter
 *
 * In case that there are no active clients this function also starts
 * TAG process. When TAG progress ends ipa clocks will be gated.
 * start_tag_process_again flag is set during this function to signal TAG
 * process to start again as there was another client that may send data to ipa
 *
 * Return codes:
 * None
 */
void ipa3_dec_client_disable_clks(struct ipa_active_client_logging_info *id)
{
	ipa3_active_clients_log_dec(id, false);
	__ipa3_dec_client_disable_clks();
}

static void ipa_dec_clients_disable_clks_on_wq(struct work_struct *work)
{
	__ipa3_dec_client_disable_clks();
}

/**
 * ipa3_dec_client_disable_clks_no_block() - Decrease active clients counter
 * if possible without blocking. If this is the last client then the desrease
 * will happen from work queue context.
 *
 * Return codes:
 * None
 */
void ipa3_dec_client_disable_clks_no_block(
	struct ipa_active_client_logging_info *id)
{
	int ret;

	ipa3_active_clients_log_dec(id, true);
	ret = atomic_add_unless(&ipa3_ctx->ipa3_active_clients.cnt, -1, 1);
	if (ret) {
		ipa_debug_low("active clients = %d\n",
			atomic_read(&ipa3_ctx->ipa3_active_clients.cnt));
		return;
	}

	/* seems like this is the only client holding the clocks */
	queue_work(ipa3_ctx->power_mgmt_wq,
		&ipa_dec_clients_disable_clks_on_wq_work);
}

/**
* ipa3_inc_acquire_wakelock() - Increase active clients counter, and
* acquire wakelock if necessary
*
* Return codes:
* None
*/
void ipa3_inc_acquire_wakelock(void)
{
	unsigned long flags;

	spin_lock_irqsave(&ipa3_ctx->wakelock_ref_cnt.spinlock, flags);
	ipa3_ctx->wakelock_ref_cnt.cnt++;
	if (ipa3_ctx->wakelock_ref_cnt.cnt == 1)
		__pm_stay_awake(&ipa3_ctx->w_lock);
	ipa_debug_low("active wakelock ref cnt = %d\n",
		ipa3_ctx->wakelock_ref_cnt.cnt);
	spin_unlock_irqrestore(&ipa3_ctx->wakelock_ref_cnt.spinlock, flags);
}

/**
 * ipa3_dec_release_wakelock() - Decrease active clients counter
 *
 * In case if the ref count is 0, release the wakelock.
 *
 * Return codes:
 * None
 */
void ipa3_dec_release_wakelock(void)
{
	unsigned long flags;

	spin_lock_irqsave(&ipa3_ctx->wakelock_ref_cnt.spinlock, flags);
	ipa3_ctx->wakelock_ref_cnt.cnt--;
	ipa_debug_low("active wakelock ref cnt = %d\n",
		ipa3_ctx->wakelock_ref_cnt.cnt);
	if (ipa3_ctx->wakelock_ref_cnt.cnt == 0)
		__pm_relax(&ipa3_ctx->w_lock);
	spin_unlock_irqrestore(&ipa3_ctx->wakelock_ref_cnt.spinlock, flags);
}

/**
* ipa3_suspend_handler() - Handles the suspend interrupt:
* wakes up the suspended peripheral by requesting its consumer
* @interrupt:		Interrupt type
* @private_data:	The client's private data
* @interrupt_data:	Interrupt specific information data
*/
void ipa3_suspend_handler(enum ipa_irq_type interrupt,
				void *private_data,
				void *interrupt_data)
{
	/*enum ipa_rm_resource_name resource;*/
	u32 suspend_data =
		((struct ipa_tx_suspend_irq_data *)interrupt_data)->endpoints;
	u32 bmsk = 1;
	u32 i = 0;
	struct ipa_ep_cfg_holb holb_cfg;

	ipa_debug("interrupt=%d, interrupt_data=%u\n",
		interrupt, suspend_data);
	memset(&holb_cfg, 0, sizeof(holb_cfg));
	holb_cfg.tmr_val = 0;

	for (i = 0; i < ipa3_ctx->ipa_num_pipes; i++) {
		if ((suspend_data & bmsk) && (ipa3_ctx->ep[i].valid)) {
			if (IPA_CLIENT_IS_APPS_CONS(ipa3_ctx->ep[i].client)) {
				/*
				 * pipe will be unsuspended as part of
				 * enabling IPA clocks
				 */
				mutex_lock(&ipa3_ctx->transport_pm.
					transport_pm_mutex);
				if (!atomic_read(
					&ipa3_ctx->transport_pm.dec_clients)
					) {
					IPA_ACTIVE_CLIENTS_INC_EP(
						ipa3_ctx->ep[i].client);
					ipa_debug_low("Pipes un-suspended.\n");
					ipa_debug_low("Enter poll mode.\n");
					atomic_set(
					&ipa3_ctx->transport_pm.dec_clients,
					1);
				}
				mutex_unlock(&ipa3_ctx->transport_pm.
					transport_pm_mutex);
				}
		}
		bmsk = bmsk << 1;
	}
}
/**
 * ipa3_init_interrupts() - Register to IPA IRQs
 *
 * Return codes: 0 in success, negative in failure
 *
 */
static int ipa3_init_interrupts(void)
{
	int result;
	int ipa_irq;

	/* Get IPA IRQ number */
	ipa_irq = platform_get_irq_byname(ipa3_ctx->ipa3_pdev, "ipa-irq");
	if (ipa_irq < 0) {
		ipa_err(":failed to get ipa-irq!\n");
		return -ENODEV;
	}
	ipa_debug(":ipa-irq = %d\n", ipa_irq);

	/*register IPA IRQ handler*/
	result = ipa3_interrupts_init(ipa_irq, 0, &ipa3_ctx->ipa3_pdev->dev);
	if (result) {
		ipa_err("ipa interrupts initialization failed\n");
		return -ENODEV;
	}

	/*add handler for suspend interrupt*/
	result = ipa3_add_interrupt_handler(IPA_TX_SUSPEND_IRQ,
			ipa3_suspend_handler, false, NULL);
	if (result) {
		ipa_err("register handler for suspend interrupt failed\n");
		result = -ENODEV;
		goto fail_add_interrupt_handler;
	}

	return 0;

fail_add_interrupt_handler:
	free_irq(ipa_irq, &ipa3_ctx->ipa3_pdev->dev);
	return result;
}

static void ipa3_freeze_clock_vote_and_notify_modem(void)
{
	int res;
	struct ipa_active_client_logging_info log_info;

	if (ipa3_ctx->smp2p_info.res_sent)
		return;

	if (ipa3_ctx->smp2p_info.out_base_id == 0) {
		ipa_err("smp2p out gpio not assigned\n");
		return;
	}

	IPA_ACTIVE_CLIENTS_PREP_SPECIAL(log_info, "FREEZE_VOTE");
	res = ipa3_inc_client_enable_clks_no_block(&log_info);
	if (res)
		ipa3_ctx->smp2p_info.ipa_clk_on = false;
	else
		ipa3_ctx->smp2p_info.ipa_clk_on = true;

	gpio_set_value(ipa3_ctx->smp2p_info.out_base_id +
		IPA_GPIO_OUT_CLK_VOTE_IDX,
		ipa3_ctx->smp2p_info.ipa_clk_on);
	gpio_set_value(ipa3_ctx->smp2p_info.out_base_id +
		IPA_GPIO_OUT_CLK_RSP_CMPLT_IDX, 1);

	ipa3_ctx->smp2p_info.res_sent = true;
	ipa_debug("IPA clocks are %s\n",
		ipa3_ctx->smp2p_info.ipa_clk_on ? "ON" : "OFF");
}

void ipa3_reset_freeze_vote(void)
{
	if (ipa3_ctx->smp2p_info.res_sent == false)
		return;

	if (ipa3_ctx->smp2p_info.ipa_clk_on)
		IPA_ACTIVE_CLIENTS_DEC_SPECIAL("FREEZE_VOTE");

	gpio_set_value(ipa3_ctx->smp2p_info.out_base_id +
		IPA_GPIO_OUT_CLK_VOTE_IDX, 0);
	gpio_set_value(ipa3_ctx->smp2p_info.out_base_id +
		IPA_GPIO_OUT_CLK_RSP_CMPLT_IDX, 0);

	ipa3_ctx->smp2p_info.res_sent = false;
	ipa3_ctx->smp2p_info.ipa_clk_on = false;
}

static int ipa3_panic_notifier(struct notifier_block *this,
	unsigned long event, void *ptr)
{
	int res;

	ipa3_freeze_clock_vote_and_notify_modem();

	ipa_debug("Calling uC panic handler\n");
	res = ipa3_uc_panic_notifier(this, event, ptr);
	if (res)
		ipa_err("uC panic handler failed %d\n", res);

	return NOTIFY_DONE;
}

static struct notifier_block ipa3_panic_blk = {
	.notifier_call = ipa3_panic_notifier,
	/* IPA panic handler needs to run before modem shuts down */
	.priority = INT_MAX,
};

static void ipa3_register_panic_hdlr(void)
{
	atomic_notifier_chain_register(&panic_notifier_list,
		&ipa3_panic_blk);
}

/**
 * ipa3_post_init() - Initialize the IPA Driver (Part II).
 * This part contains all initialization which requires interaction with
 * IPA HW (via GSI).
 *
 * @pdev:	The platform device structure representing the IPA driver
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
static int ipa3_post_init(struct device *ipa_dev)
{
	int result;

	/* Assign resource limitation to each group */
	ipa3_set_resource_groups_min_max_limits();

	result = ipa3_init_interrupts();
	if (result) {
		ipa_err("ipa initialization of interrupts failed\n");
		result = -ENODEV;
		goto fail_register_device;
	}

	result = gsi_register_device(ipa3_ctx->ee);
	if (result) {
		ipa_err(":gsi register error - %d\n", result);
		result = -ENODEV;
		goto fail_register_device;
	}
	ipa_debug("IPA gsi is registered\n");

	/* setup the AP-IPA pipes */
	if (ipa3_setup_apps_pipes()) {
		ipa_err(":failed to setup IPA-Apps pipes\n");
		result = -ENODEV;
		goto fail_setup_apps_pipes;
	}
	ipa_debug("IPA GPI pipes were connected\n");

	ipa3_debugfs_init();

	result = ipa3_uc_interface_init();
	if (result)
		ipa_err(":ipa Uc interface init failed (%d)\n", -result);
	else
		ipa_debug(":ipa Uc interface init ok\n");

	ipa3_register_panic_hdlr();

	ipa3_ctx->q6_proxy_clk_vote_valid = true;

	atomic_set(&ipa3_ctx->state, IPA_STATE_READY);

	complete_all(&ipa3_ctx->init_completion_obj);
	ipa_info("IPA driver initialization was successful.\n");

	return 0;

fail_setup_apps_pipes:
	gsi_deregister_device();
fail_register_device:
	/* Maybe it'll work another time?  (Doubtful...) */
	atomic_set(&ipa3_ctx->state, IPA_STATE_INITIAL);

	return result;
}

static void ipa3_post_init_wq(struct work_struct *work)
{
	ipa3_post_init(ipa3_ctx->dev);
}


static ssize_t ipa3_write(struct file *file, const char __user *buf,
	 size_t count, loff_t *ppos);

static int ipa3_open(struct inode *inode, struct file *filp);


static const struct file_operations ipa3_drv_fops = {
	.write = ipa3_write,
	.open = ipa3_open
};

static int ipa3_pil_load_ipa_fws(void)
{
	void *subsystem_get_retval = NULL;

	ipa_debug("PIL FW loading process initiated\n");

	subsystem_get_retval = subsystem_get(IPA_SUBSYSTEM_NAME);
	if (IS_ERR_OR_NULL(subsystem_get_retval)) {
		ipa_err("Unable to trigger PIL process for FW loading\n");
		return -EINVAL;
	}

	ipa_debug("PIL FW loading process is complete\n");
	return 0;
}

static int ipa3_open(struct inode *inode, struct file *filp)
{
	struct ipa3_context *ctx = NULL;

	ipa_debug_low("ENTER\n");

	ctx = container_of(inode->i_cdev, struct ipa3_context, cdev);
	filp->private_data = ctx;
	return 0;
}

static ssize_t ipa3_write(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	atomic_t *statep;
	int result;

	if (!count)
		return 0;

	/* Only proceed if we're in initial state; ignore otherwise */
	statep = &ipa3_ctx->state;
	result = atomic_cmpxchg(statep, IPA_STATE_INITIAL, IPA_STATE_STARTING);
	if (result != IPA_STATE_INITIAL)
		return count;

	IPA_ACTIVE_CLIENTS_INC_SIMPLE();

	result = ipa3_pil_load_ipa_fws();

	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();

	if (result) {
		ipa_err("IPA FW loading process has failed\n");
		/* Maybe it'll work another time?  (Doubtful...) */
		atomic_set(statep, IPA_STATE_INITIAL);

		return result;
	}
	ipa_info("IPA FW loaded successfully\n");

	queue_work(ipa3_ctx->transport_power_mgmt_wq, &ipa3_post_init_work);

	return count;
}

static int ipa3_alloc_pkt_init(void)
{
	struct ipa_mem_buffer *mem = &ipa3_ctx->pkt_init_mem;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	dma_addr_t pyld_phys;
	void *pyld_virt;
	u32 size;
	int i;

	/* First create a payload just to get its size */
	cmd_pyld = ipahal_ip_packet_init_pyld(0);
	if (!cmd_pyld) {
		ipa_err("failed to construct IMM cmd\n");
		return -ENOMEM;
	}
	size = cmd_pyld->len;
	ipahal_destroy_imm_cmd(cmd_pyld);

	/* Allocate enough DMA memory to hold a payload for each pipe */
	if (ipahal_dma_alloc(mem, size * ipa3_ctx->ipa_num_pipes, GFP_KERNEL)) {
		ipa_err("failed to alloc DMA buff of size %d\n", mem->size);
		return -ENOMEM;
	}

	/* Fill in an IP packet init payload for each pipe */
	pyld_phys = mem->phys_base;
	pyld_virt = mem->base;
	for (i = 0; i < ipa3_ctx->ipa_num_pipes; i++) {
		cmd_pyld = ipahal_ip_packet_init_pyld(i);
		if (!cmd_pyld) {
			ipa_err("failed to construct IMM cmd\n");
			goto err_dma_free;
		}

		memcpy(pyld_virt, ipahal_imm_cmd_pyld_data(cmd_pyld), size);
		ipa3_ctx->pkt_init_imm[i] = pyld_phys;

		ipahal_destroy_imm_cmd(cmd_pyld);

		pyld_virt += size;
		pyld_phys += size;
	}

	return 0;
err_dma_free:
	memset(&ipa3_ctx->pkt_init_imm[0], 0, i * sizeof(dma_addr_t));
	ipahal_dma_free(mem);

	return -ENOMEM;
}

static void ipa3_free_pkt_init(void)
{
	memset(&ipa3_ctx->pkt_init_imm, 0, sizeof(ipa3_ctx->pkt_init_imm));
	ipahal_dma_free(&ipa3_ctx->pkt_init_mem);
}

static bool config_valid(void)
{
	u32 width = ipahal_get_hw_tbl_hdr_width();
	u32 required_size;
	u32 hi_index;
	u32 lo_index;
	u32 table_count;

	required_size = ipa3_mem(V4_RT_NUM_INDEX) * width;
	if (ipa3_mem(V4_RT_HASH_SIZE) < required_size) {
		ipa_err("V4_RT_HASH_SIZE too small (%u < %u * %u)\n",
			ipa3_mem(V4_RT_HASH_SIZE), ipa3_mem(V4_RT_NUM_INDEX),
			width);
		return false;
	}
	if (ipa3_mem(V4_RT_NHASH_SIZE) < required_size) {
		ipa_err("V4_RT_NHASH_SIZE too small (%u < %u * %u)\n",
			ipa3_mem(V4_RT_NHASH_SIZE), ipa3_mem(V4_RT_NUM_INDEX),
			width);
		return false;
	}

	required_size = ipa3_mem(V6_RT_NUM_INDEX) * width;
	if (ipa3_mem(V6_RT_HASH_SIZE) < required_size) {
		ipa_err("V6_RT_HASH_SIZE too small (%u < %u * %u)\n",
			ipa3_mem(V6_RT_HASH_SIZE), ipa3_mem(V6_RT_NUM_INDEX),
			width);
		return false;
	}
	if (ipa3_mem(V6_RT_NHASH_SIZE) < required_size) {
		ipa_err("V6_RT_NHASH_SIZE too small (%u < %u * %u)\n",
			ipa3_mem(V6_RT_NHASH_SIZE), ipa3_mem(V6_RT_NUM_INDEX),
			width);
		return false;
	}

	hi_index = ipa3_mem(V4_MODEM_RT_INDEX_HI);
	lo_index = ipa3_mem(V4_MODEM_RT_INDEX_LO);
	table_count = hi_index - lo_index + 1;
	required_size = table_count * width;
	if (ipa3_mem(V4_RT_HASH_SIZE) < required_size) {
		ipa_err("V4_RT_HASH_SIZE too small for modem (%u < %u * %u)\n",
			ipa3_mem(V4_RT_HASH_SIZE), table_count, width);
		return false;
	}
	if (ipa3_mem(V4_RT_NHASH_SIZE) < required_size) {
		ipa_err("V4_RT_NHASH_SIZE too small for modem (%u < %u * %u)\n",
			ipa3_mem(V4_RT_NHASH_SIZE), table_count, width);
		return false;
	}

	hi_index = ipa3_mem(V6_MODEM_RT_INDEX_HI);
	lo_index = ipa3_mem(V6_MODEM_RT_INDEX_LO);
	table_count = hi_index - lo_index + 1;
	required_size = table_count * width;
	if (ipa3_mem(V6_RT_HASH_SIZE) < required_size) {
		ipa_err("V6_RT_HASH_SIZE too small for modem (%u < %u * %u)\n",
			ipa3_mem(V6_RT_HASH_SIZE), table_count, width);
		return false;
	}
	if (ipa3_mem(V6_RT_NHASH_SIZE) < required_size) {
		ipa_err("V6_RT_NHASH_SIZE too small for modem (%u < %u * %u)\n",
			ipa3_mem(V6_RT_NHASH_SIZE), table_count, width);
		return false;
	}

	/* Filter tables need an extra slot to hold an endpoint bitmap */
	table_count = ipa3_ctx->ep_flt_num + 1;
	required_size = table_count * width;
	if (ipa3_mem(V4_FLT_HASH_SIZE) < required_size) {
		ipa_err("V4_FLT_HASH_SIZE too small  (%u < %u * %u)\n",
			ipa3_mem(V4_RT_HASH_SIZE), table_count, width);
		return false;
	}
	if (ipa3_mem(V4_FLT_NHASH_SIZE) < required_size) {
		ipa_err("V4_FLT_NHASH_SIZE too small (%u < %u * %u)\n",
			ipa3_mem(V4_FLT_NHASH_SIZE), table_count, width);
		return false;
	}

	if (ipa3_mem(V6_FLT_HASH_SIZE) < required_size) {
		ipa_err("V6_FLT_HASH_SIZE too small  (%u < %u * %u)\n",
			ipa3_mem(V6_FLT_HASH_SIZE), table_count, width);
		return false;
	}
	if (ipa3_mem(V6_FLT_NHASH_SIZE) < required_size) {
		ipa_err("V6_FLT_NHASH_SIZE too small (%u < %u * %u)\n",
			ipa3_mem(V6_FLT_NHASH_SIZE), table_count, width);
		return false;
	}

	return true;
}

/**
* ipa3_pre_init() - Initialize the IPA Driver.
* This part contains all initialization which doesn't require IPA HW, such
* as structure allocations and initializations, register writes, etc.
*
* @pdev:	The platform device structure representing the IPA driver
*
* Function initialization process:
* Allocate memory for the driver context data struct
* Initializing the ipa3_ctx with :
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
static int ipa3_pre_init(void)
{
	int result = 0;
	struct ipa_active_client_logging_info log_info;

	ipa_debug("IPA Driver initialization started\n");

	/* Clock scaling is enabled */
	ipa3_ctx->curr_ipa_clk_rate = ipa3_ctx->ctrl->ipa_clk_rate_turbo;

	/* enable IPA clocks explicitly to allow the initialization */
	ipa3_enable_clks();

	result = ipa3_init_hw();
	if (result) {
		ipa_err(":error initializing HW.\n");
		result = -ENODEV;
		goto fail_init_hw;
	}

	ipa_debug("IPA HW initialization sequence completed");

	ipa3_ctx->ipa_num_pipes = ipa3_get_num_pipes();
	if (ipa3_ctx->ipa_num_pipes > IPA3_MAX_NUM_PIPES) {
		ipa_err("IPA has more pipes then supported! has %d, max %d\n",
			ipa3_ctx->ipa_num_pipes, IPA3_MAX_NUM_PIPES);
		result = -ENODEV;
		goto fail_init_hw;
	}

	ipa3_ctx->ctrl->ipa_sram_read_settings();
	ipa_debug("SRAM, size: 0x%x, restricted bytes: 0x%x\n",
		ipa3_ctx->smem_sz, ipa3_ctx->smem_restricted_bytes);

	ipa_debug("hdr_lcl=0 ip4_rt_hash=0 ip4_rt_nonhash=0\n");
	ipa_debug("ip6_rt_hash=0 ip6_rt_nonhash=0\n");
	ipa_debug("ip4_flt_hash=0 ip4_flt_nonhash=0\n");
	ipa_debug("ip6_flt_hash=0 ip6_flt_nonhash=0\n");

	if (ipa3_ctx->smem_reqd_sz > ipa3_ctx->smem_sz) {
		ipa_err("SW expect more core memory, needed %d, avail %d\n",
			ipa3_ctx->smem_reqd_sz, ipa3_ctx->smem_sz);
		result = -ENOMEM;
		goto fail_init_hw;
	}

	mutex_init(&ipa3_ctx->ipa3_active_clients.mutex);
	IPA_ACTIVE_CLIENTS_PREP_SPECIAL(log_info, "PROXY_CLK_VOTE");
	ipa3_active_clients_log_inc(&log_info, false);
	atomic_set(&ipa3_ctx->ipa3_active_clients.cnt, 1);

	/* Create workqueues for power management */
	ipa3_ctx->power_mgmt_wq =
		create_singlethread_workqueue("ipa_power_mgmt");
	if (!ipa3_ctx->power_mgmt_wq) {
		ipa_err("failed to create power mgmt wq\n");
		result = -ENOMEM;
		goto fail_init_hw;
	}

	ipa3_ctx->transport_power_mgmt_wq =
		create_singlethread_workqueue("transport_power_mgmt");
	if (!ipa3_ctx->transport_power_mgmt_wq) {
		ipa_err("failed to create transport power mgmt wq\n");
		result = -ENOMEM;
		goto fail_create_transport_wq;
	}

	mutex_init(&ipa3_ctx->transport_pm.transport_pm_mutex);

	/* init the lookaside cache */

	ipa3_ctx->tx_pkt_wrapper_cache =
	   kmem_cache_create("IPA_TX_PKT_WRAPPER",
			   sizeof(struct ipa3_tx_pkt_wrapper), 0, 0, NULL);
	if (!ipa3_ctx->tx_pkt_wrapper_cache) {
		ipa_err(":ipa tx pkt wrapper cache create failed\n");
		result = -ENOMEM;
		goto fail_tx_pkt_wrapper_cache;
	}
	ipa3_ctx->rx_pkt_wrapper_cache =
	   kmem_cache_create("IPA_RX_PKT_WRAPPER",
			   sizeof(struct ipa3_rx_pkt_wrapper), 0, 0, NULL);
	if (!ipa3_ctx->rx_pkt_wrapper_cache) {
		ipa_err(":ipa rx pkt wrapper cache create failed\n");
		result = -ENOMEM;
		goto fail_rx_pkt_wrapper_cache;
	}

	/* allocate memory for DMA_TASK workaround */
	result = ipa3_allocate_dma_task_for_gsi();
	if (result) {
		ipa_err("failed to allocate dma task\n");
		goto fail_dma_task;
	}

	mutex_init(&ipa3_ctx->lock);

	ipa3_ctx->class = class_create(THIS_MODULE, DRV_NAME);

	result = alloc_chrdev_region(&ipa3_ctx->dev_num, 0, 1, DRV_NAME);
	if (result) {
		ipa_err("alloc_chrdev_region err.\n");
		result = -ENODEV;
		goto fail_alloc_chrdev_region;
	}

	ipa3_ctx->dev = device_create(ipa3_ctx->class, NULL, ipa3_ctx->dev_num,
			ipa3_ctx, DRV_NAME);
	if (IS_ERR(ipa3_ctx->dev)) {
		ipa_err(":device_create err.\n");
		result = -ENODEV;
		goto fail_device_create;
	}

	/* Create a wakeup source. */
	wakeup_source_init(&ipa3_ctx->w_lock, "IPA_WS");
	spin_lock_init(&ipa3_ctx->wakelock_ref_cnt.spinlock);

	result = ipa3_alloc_pkt_init();
	if (result) {
		ipa_err("Failed to alloc pkt_init payload\n");
		result = -ENODEV;
		goto fail_create_apps_resource;
	}

	/*
	 * Note enabling dynamic clock division must not be
	 * attempted for IPA hardware versions prior to 3.5.
	 */
	ipa3_enable_dcd();

	init_completion(&ipa3_ctx->init_completion_obj);

	cdev_init(&ipa3_ctx->cdev, &ipa3_drv_fops);
	ipa3_ctx->cdev.owner = THIS_MODULE;
	result = cdev_add(&ipa3_ctx->cdev, ipa3_ctx->dev_num, 1);
	if (result) {
		ipa_err(":cdev_add err=%d\n", -result);
		result = -ENODEV;
		goto err_free_pkt_init;
	}
	ipa_debug("ipa cdev added successful. major:%d minor:%d\n",
			MAJOR(ipa3_ctx->dev_num),
			MINOR(ipa3_ctx->dev_num));

	return 0;

err_free_pkt_init:
	ipa3_free_pkt_init();
fail_create_apps_resource:
	device_destroy(ipa3_ctx->class, ipa3_ctx->dev_num);
fail_device_create:
	unregister_chrdev_region(ipa3_ctx->dev_num, 1);
fail_alloc_chrdev_region:
	ipa3_free_dma_task_for_gsi();
fail_dma_task:
fail_rx_pkt_wrapper_cache:
	kmem_cache_destroy(ipa3_ctx->rx_pkt_wrapper_cache);
fail_tx_pkt_wrapper_cache:
	kmem_cache_destroy(ipa3_ctx->tx_pkt_wrapper_cache);
fail_create_transport_wq:
	destroy_workqueue(ipa3_ctx->power_mgmt_wq);
fail_init_hw:
	ipa3_disable_clks();

	return result;
}

/* Return the IPA hardware version, or IPA_HW_None for any error */
static enum ipa_hw_version ipa_version_get(struct platform_device *pdev)
{
	struct device_node *node = pdev->dev.of_node;
	u32 ipa_version = 0;

	if (of_property_read_u32(node, "qcom,ipa-hw-ver", &ipa_version))
		return IPA_HW_None;

	/* Translate the DTB value to the value we use internally */
	if (ipa_version == QCOM_IPA_HW_VER_v3_5_1)
		return IPA_HW_v3_5_1;

	ipa_err("unsupported IPA hardware version %u\n", ipa_version);

	return IPA_HW_None;
}

static int ipa3_iommu_map(struct iommu_domain *domain,
	unsigned long iova, phys_addr_t paddr, size_t size)
{
	struct ipa_smmu_cb_ctx *ap_cb = &ipa3_ctx->ap_smmu_cb;
	int prot = IOMMU_READ | IOMMU_WRITE | IOMMU_MMIO;

	/*
	 * Round physical and I/O virtual addresses down to PAGE_SIZE
	 * boundaries, and extend the size to reflect the effect of
	 * rounding.  Round the size up to a PAGE_SIZE multiple.
	 */
	iova = rounddown(iova, PAGE_SIZE);
	size += paddr % PAGE_SIZE;
	size = roundup(size, PAGE_SIZE);
	paddr = rounddown(paddr, PAGE_SIZE);

	ipa_debug("mapping 0x%lx to 0x%pa size %zu\n", iova, &paddr, size);

	ipa_debug("domain =0x%p iova 0x%lx\n", domain, iova);
	ipa_debug("paddr =0x%pa size 0x%x\n", &paddr, (u32)size);

	/* make sure no overlapping */
	if (iova >= ap_cb->va_start && iova < ap_cb->va_end) {
		ipa_err("iommu AP overlap addr 0x%lx\n", iova);
		ipa_assert();
		return -EFAULT;
	}

	return iommu_map(domain, iova, paddr, size, prot);
}

/* Returns negative on error, 1 if S1 bypass, 0 otherwise. */
static int
ipa_smmu_domain_attr_set(struct device *dev, struct iommu_domain *domain)
{
	struct device_node *node = dev->of_node;
	enum iommu_attr attr;
	char *attr_string;
	int data = 1;
	int ret;

	if (of_property_read_bool(node, "qcom,qcom,smmu-s1-bypass")) {
		attr = DOMAIN_ATTR_S1_BYPASS;
		attr_string = "S1 bypass";
	} else {
		attr = DOMAIN_ATTR_ATOMIC;
		attr_string = "atomic";
	}

	ipa_debug("CB PROBE pdev=%p set attribute %s\n", dev, attr_string);

	ret = iommu_domain_set_attr(domain, attr, &data);
	if (ret) {
		ipa_err("couldn't set %s\n", attr_string);
		return ret;
	}

	ipa_debug("SMMU %s\n", attr_string);

	return attr == DOMAIN_ATTR_S1_BYPASS ? 1 : 0;
}

/*
 * Common probe processing for SMMU context blocks.  This function
 * populates all of the fields of the SMMU CB context provided.
 *
 * If successful, this function returns a created mapping in
 * cb->mapping.  The mapping will have beeen attached to the device
 * provided.  In the event of a subsequent error, the caller is
 * responsible for detaching the mapping from the device and
 * releasing mapping.
 */
static int ipa_smmu_attach(struct device *dev, struct ipa_smmu_cb_ctx *cb)
{
	struct device_node *node = dev->of_node;
	struct dma_iommu_mapping *mapping;
	u32 iova_mapping[2];
	dma_addr_t va_start;
	size_t va_size;
	int ret;
	bool s1_bypass;

	ret = of_property_read_u32_array(node, "qcom,iova-mapping",
						iova_mapping, 2);
	if (ret) {
		ipa_err("Fail to read start/size iova addresses\n");
		return ret;
	}
	va_start = (dma_addr_t)iova_mapping[0];
	va_size = (size_t)iova_mapping[1];
	ipa_debug("va_start=%pad va_size=0x%zx\n", &va_start, va_size);

	mapping = arm_iommu_create_mapping(dev->bus, va_start, va_size);
	if (IS_ERR_OR_NULL(mapping)) {
		ipa_debug("Fail to create mapping\n");
		/* assume this failure is because iommu driver is not ready */
		return -EPROBE_DEFER;
	}
	ipa_debug("SMMU mapping created\n");

	ret = ipa_smmu_domain_attr_set(dev, mapping->domain);
	if (ret < 0) {
		ret = -EIO;
		goto err_release_mapping;
	}
	s1_bypass = !!ret;

	if (dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64))) {
		ipa_err("DMA set 64bit mask failed\n");
		ret = -EOPNOTSUPP;
		goto err_release_mapping;
	}

	ipa_debug("CB PROBE pdev=%p attaching IOMMU device\n", dev);
	ret = arm_iommu_attach_device(dev, mapping);
	if (ret) {
		ipa_err("could not attach device ret=%d\n", ret);
		goto err_release_mapping;
	}

	cb->dev = dev;
	cb->mapping = mapping;
	cb->va_start = va_start;
	cb->va_end = va_start + va_size;
	cb->s1_bypass = s1_bypass;

	return 0;

err_release_mapping:
	arm_iommu_release_mapping(mapping);

	return ret;
}

/* Un-do the side-effects of a successful call to ipa_smmu_attach(). */
static void ipa_smmu_detach(struct ipa_smmu_cb_ctx *cb)
{
	arm_iommu_detach_device(cb->dev);
	arm_iommu_release_mapping(cb->mapping);

	memset(cb, 0, sizeof(*cb));
}

static int ipa_smmu_uc_cb_probe(struct device *dev)
{
	ipa_debug("UC CB PROBE sub pdev=%p\n", dev);

	return ipa_smmu_attach(dev, &ipa3_ctx->uc_smmu_cb);
}

static int ipa_smmu_ap_cb_probe(struct device *dev)
{
	struct ipa_smmu_cb_ctx *cb = &ipa3_ctx->ap_smmu_cb;
	int result;
	u32 add_map_size;
	const u32 *add_map;
	void *smem_addr;
	int i;

	ipa_debug("AP CB probe: sub pdev=%p\n", dev);

	result = ipa_smmu_attach(dev, cb);
	if (result)
		return result;

	if (ipahal_dev_init(dev)) {
		ipa_smmu_detach(cb);
		ipa_err("failed to assign IPA HAL dev pointer\n");
		return -EFAULT;
	}

	add_map = of_get_property(dev->of_node,
		"qcom,additional-mapping", &add_map_size);
	if (add_map) {
		/* mapping size is an array of 3-tuple of u32 */
		if (add_map_size % (3 * sizeof(u32))) {
			ipa_err("wrong additional mapping format\n");
			ipahal_dev_destroy();
			ipa_smmu_detach(cb);
			return -EFAULT;
		}

		/* iterate of each entry of the additional mapping array */
		for (i = 0; i < add_map_size / sizeof(u32); i += 3) {
			u32 iova = be32_to_cpu(add_map[i]);
			u32 pa = be32_to_cpu(add_map[i + 1]);
			u32 size = be32_to_cpu(add_map[i + 2]);

			ipa3_iommu_map(cb->mapping->domain, iova, pa, size);
		}
	}

	/* map SMEM memory for IPA table accesses */
	smem_addr = smem_alloc(SMEM_IPA_FILTER_TABLE, IPA_SMEM_SIZE,
		SMEM_MODEM, 0);
	if (smem_addr) {
		phys_addr_t iova = smem_virt_to_phys(smem_addr);
		phys_addr_t pa = iova;

		ipa3_iommu_map(cb->mapping->domain, iova, pa, IPA_SMEM_SIZE);
	}

	/* Proceed to real initialization */
	result = ipa3_pre_init();
	if (result) {
		ipa_err("ipa_init failed\n");
		ipahal_dev_destroy();
		ipa_smmu_detach(cb);
	}

	return result;
}

static irqreturn_t ipa3_smp2p_modem_clk_query_isr(int irq, void *ctxt)
{
	ipa3_freeze_clock_vote_and_notify_modem();

	return IRQ_HANDLED;
}

static int ipa3_smp2p_probe(struct device *dev)
{
	struct device_node *node = dev->of_node;
	int res;

	ipa_debug("node->name=%s\n", node->name);
	if (strcmp("qcom,smp2pgpio_map_ipa_1_out", node->name) == 0) {
		res = of_get_gpio(node, 0);
		if (res < 0) {
			ipa_debug("of_get_gpio returned %d\n", res);
			return res;
		}

		ipa3_ctx->smp2p_info.out_base_id = res;
		ipa_debug("smp2p out_base_id=%d\n",
			ipa3_ctx->smp2p_info.out_base_id);
	} else if (strcmp("qcom,smp2pgpio_map_ipa_1_in", node->name) == 0) {
		int irq;

		res = of_get_gpio(node, 0);
		if (res < 0) {
			ipa_debug("of_get_gpio returned %d\n", res);
			return res;
		}

		ipa3_ctx->smp2p_info.in_base_id = res;
		ipa_debug("smp2p in_base_id=%d\n",
			ipa3_ctx->smp2p_info.in_base_id);

		/* register for modem clk query */
		irq = gpio_to_irq(ipa3_ctx->smp2p_info.in_base_id +
			IPA_GPIO_IN_QUERY_CLK_IDX);
		if (irq < 0) {
			ipa_err("gpio_to_irq failed %d\n", irq);
			return -ENODEV;
		}
		ipa_debug("smp2p irq#=%d\n", irq);
		res = request_irq(irq,
			(irq_handler_t)ipa3_smp2p_modem_clk_query_isr,
			IRQF_TRIGGER_RISING, "ipa_smp2p_clk_vote", dev);
		if (res) {
			ipa_err("fail to register smp2p irq=%d\n", irq);
			return -ENODEV;
		}
		res = enable_irq_wake(ipa3_ctx->smp2p_info.in_base_id +
			IPA_GPIO_IN_QUERY_CLK_IDX);
		if (res)
			ipa_err("failed to enable irq wake\n");
	}

	return 0;
}

static const struct of_device_id ipa_plat_drv_match[] = {
	{ .compatible = "qcom,ipa", },
	{ .compatible = "qcom,ipa-smmu-ap-cb", },
	{ .compatible = "qcom,ipa-smmu-uc-cb", },
	{ .compatible = "qcom,smp2pgpio-map-ipa-1-in", },
	{ .compatible = "qcom,smp2pgpio-map-ipa-1-out", },
	{}
};

int ipa3_plat_drv_probe(struct platform_device *pdev_p)
{
	struct device *dev = &pdev_p->dev;
	struct device_node *node = dev->of_node;
	enum ipa_hw_version hw_version;
	struct resource *res;
	int result;

	/* We assume we're working on 64-bit hardware */
	BUILD_BUG_ON(!IS_ENABLED(CONFIG_64BIT));

	ipa_debug("IPA driver probing started\n");
	ipa_debug("dev->of_node->name = %s\n", node->name);

	if (of_device_is_compatible(node, "qcom,ipa-smmu-ap-cb"))
		return ipa_smmu_ap_cb_probe(dev);

	if (of_device_is_compatible(node, "qcom,ipa-smmu-uc-cb"))
		return ipa_smmu_uc_cb_probe(dev);

	if (of_device_is_compatible(node, "qcom,smp2pgpio-map-ipa-1-in"))
		return ipa3_smp2p_probe(dev);

	if (of_device_is_compatible(node, "qcom,smp2pgpio-map-ipa-1-out"))
		return ipa3_smp2p_probe(dev);

	ipa3_ctx->ipa3_pdev = pdev_p;
	/* Initialize the log buffer right away, to capture all messages */
	ipa3_ctx->logbuf = ipc_log_context_create(IPA_IPC_LOG_PAGES, "ipa", 0);
	if (!ipa3_ctx->logbuf)
		ipa_err("failed to create IPC log, continue...\n");

	/* Find out whether we're working with supported hardware */
	hw_version = ipa_version_get(pdev_p);
	if (hw_version == IPA_HW_None) {
		result = -ENODEV;
		goto err_destroy_logbuf;
	}
	ipa_debug(": ipa_version = %d", hw_version);

	result = of_property_read_u32(node, "qcom,ee", &ipa3_ctx->ee);
	if (result)
		ipa3_ctx->ee = 0;	/* Default to 0 if not found */

	/* Get IPA wrapper address */
	res = platform_get_resource_byname(pdev_p, IORESOURCE_MEM, "ipa-base");
	if (!res) {
		ipa_err(":get resource failed for ipa-base!\n");
		result = -ENODEV;
		goto err_clear_ee;
	}
	ipa3_ctx->ipa_wrapper_base = res->start;
	ipa3_ctx->ipa_wrapper_size = resource_size(res);
	ipa_debug(": ipa-base = 0x%x, size = 0x%x\n",
			ipa3_ctx->ipa_wrapper_base,
			ipa3_ctx->ipa_wrapper_size);

	ipa3_ctx->ctrl = ipa3_controller_init();

	/* setup IPA register access */
	ipa_debug("Mapping 0x%x\n", ipa3_ctx->ipa_wrapper_base +
		ipa3_ctx->ctrl->ipa_reg_base_ofst);
	ipa3_ctx->mmio = ioremap(ipa3_ctx->ipa_wrapper_base +
				ipa3_ctx->ctrl->ipa_reg_base_ofst,
				ipa3_ctx->ipa_wrapper_size);
	if (!ipa3_ctx->mmio) {
		ipa_err(":ipa-base ioremap err.\n");
		result = -EFAULT;
		goto err_clear_ctrl;
	}

	ipahal_init(hw_version, ipa3_ctx->mmio);

	result = ipa3_init_mem_partition(node);
	if (result) {
		ipa_err(":ipa3_init_mem_partition failed!\n");
		result = -ENODEV;
		goto err_hal_destroy;
	}

	ipa_init_ep_flt_bitmap();
	if (!ipa3_ctx->ep_flt_num) {
		ipa_err("no endpoints support filtering\n");
		result = -ENODEV;
		goto err_hal_destroy;
	}
	ipa_debug("EP with flt support bitmap 0x%x (%u pipes)\n",
		ipa3_ctx->ep_flt_bitmap, ipa3_ctx->ep_flt_num);

	/* Make sure we have a valid configuration before proceeding */
	if (!config_valid()) {
		ipa_err("invalid configuration\n");
		result = -EFAULT;
		goto err_hal_destroy;
	}

	/* get BUS handle */
	ipa3_ctx->ipa_bus_hdl = msm_bus_scale_register_client(
					ipa3_ctx->ctrl->msm_bus_data_ptr);
	if (!ipa3_ctx->ipa_bus_hdl) {
		ipa_err("fail to register with bus mgr!\n");
		result = -ENODEV;
		goto err_hal_destroy;
	}

	/* init active_clients_log */
	if (ipa3_active_clients_log_init()) {
		result	=-ENOMEM;
		goto err_unregister_bus_handle;
	}

	ipa3_ctx->gsi_ctx = msm_gsi_init(pdev_p);
	if (IS_ERR(ipa3_ctx->gsi_ctx)) {
		ipa_err("ipa: error initializing gsi driver.\n");
		result = PTR_ERR(ipa3_ctx->gsi_ctx);
		goto err_clear_gsi_ctx;
	}

	result = of_platform_populate(node, ipa_plat_drv_match, NULL, dev);
	if (result) {
		ipa_err("failed to populate platform\n");
		goto err_clear_gsi_ctx;
	}

	return 0;

err_clear_gsi_ctx:
	ipa3_ctx->gsi_ctx = NULL;
	ipa3_active_clients_log_destroy();
err_unregister_bus_handle:
	msm_bus_scale_unregister_client(ipa3_ctx->ipa_bus_hdl);
	ipa3_ctx->ipa_bus_hdl = 0;
err_hal_destroy:
	ipahal_destroy();
	iounmap(ipa3_ctx->mmio);
	ipa3_ctx->mmio = NULL;
err_clear_ctrl:
	ipa3_ctx->ctrl = NULL;
	ipa3_ctx->ipa_wrapper_size = 0;
	ipa3_ctx->ipa_wrapper_base = 0;
err_clear_ee:
	ipa3_ctx->ee = 0;
err_destroy_logbuf:
	if (ipa3_ctx->logbuf) {
		(void)ipc_log_context_destroy(ipa3_ctx->logbuf);
		ipa3_ctx->logbuf = NULL;
	}
	ipa3_ctx->ipa3_pdev = NULL;

	return result;

}

/**
 * ipa3_ap_suspend() - suspend callback for runtime_pm
 * @dev: pointer to device
 *
 * This callback will be invoked by the runtime_pm framework when an AP suspend
 * operation is invoked, usually by pressing a suspend button.
 *
 * Returns -EAGAIN to runtime_pm framework in case IPA is in use by AP.
 * This will postpone the suspend operation until IPA is no longer used by AP.
 */
int ipa3_ap_suspend(struct device *dev)
{
	int i;

	ipa_debug("Enter...\n");

	/* In case there is a tx/rx handler in polling mode fail to suspend */
	for (i = 0; i < ipa3_ctx->ipa_num_pipes; i++) {
		if (ipa3_ctx->ep[i].sys &&
			atomic_read(&ipa3_ctx->ep[i].sys->curr_polling_state)) {
			ipa_err("EP %d is in polling state, do not suspend\n",
				i);
			return -EAGAIN;
		}
	}

	/*
	 * Release transport IPA resource without waiting for inactivity timer
	 */
	atomic_set(&ipa3_ctx->transport_pm.eot_activity, 0);
	//ipa3_disable_clks();
	ipa_debug("Exit\n");

	return 0;
}

/**
* ipa3_ap_resume() - resume callback for runtime_pm
* @dev: pointer to device
*
* This callback will be invoked by the runtime_pm framework when an AP resume
* operation is invoked.
*
* Always returns 0 since resume should always succeed.
*/
int ipa3_ap_resume(struct device *dev)
{
	//ipa3_enable_clks();
	return 0;
}

static int ipa3_q6_clean_q6_flt_tbls(enum ipa_ip_type ip,
	enum ipa_rule_type rlt)
{
	struct ipa3_desc *desc;
	struct ipahal_imm_cmd_pyld **cmd_pyld;
	int retval = 0;
	int pipe_idx;
	int flt_idx = 0;
	int num_cmds = 0;
	int index;
	u32 lcl_addr_mem_part;
	struct ipa_mem_buffer mem;
	u32 width = ipahal_get_hw_tbl_hdr_width();

	ipa_debug("Entry\n");

	if ((ip >= IPA_IP_MAX) || (rlt >= IPA_RULE_TYPE_MAX)) {
		ipa_err("Input Err: ip=%d ; rlt=%d\n", ip, rlt);
		return -EINVAL;
	}

	/* Up to filtering pipes we have filtering tables */
	desc = kcalloc(ipa3_ctx->ep_flt_num, sizeof(*desc), GFP_KERNEL);
	if (!desc) {
		ipa_err("failed to allocate memory\n");
		return -ENOMEM;
	}

	cmd_pyld = kcalloc(ipa3_ctx->ep_flt_num, sizeof(*cmd_pyld), GFP_KERNEL);
	if (!cmd_pyld) {
		ipa_err("failed to allocate memory\n");
		retval = -ENOMEM;
		goto free_desc;
	}

	if (ip == IPA_IP_v4) {
		if (rlt == IPA_RULE_HASHABLE)
			lcl_addr_mem_part = ipa3_mem(V4_FLT_HASH_OFST);
		else
			lcl_addr_mem_part = ipa3_mem(V4_FLT_NHASH_OFST);
	} else {
		if (rlt == IPA_RULE_HASHABLE)
			lcl_addr_mem_part = ipa3_mem(V6_FLT_HASH_OFST);
		else
			lcl_addr_mem_part = ipa3_mem(V6_FLT_NHASH_OFST);
	}

	retval = ipahal_flt_generate_empty_img(1, 0, &mem, GFP_ATOMIC);
	if (retval) {
		ipa_err("failed to generate flt single tbl empty img\n");
		goto free_cmd_pyld;
	}

	for (pipe_idx = 0; pipe_idx < ipa3_ctx->ipa_num_pipes; pipe_idx++) {
		if (!ipa_is_ep_support_flt(pipe_idx))
			continue;

		/*
		 * Iterating over all the filtering pipes that are
		 * invalid but connected.
		 */
		if (!ipa3_ctx->ep[pipe_idx].valid) {
			u32 offset;

			offset = ipa3_ctx->smem_restricted_bytes +
					lcl_addr_mem_part +
					flt_idx * (width + 1);
			cmd_pyld[num_cmds] =
				ipahal_dma_shared_mem_write_pyld(&mem, offset);
			if (!cmd_pyld[num_cmds]) {
				ipa_err("fail construct dma_shared_mem cmd\n");
				retval = -ENOMEM;
				goto free_empty_img;
			}
			ipa_desc_fill_imm_cmd(&desc[num_cmds],
						cmd_pyld[num_cmds]);
			num_cmds++;
		}

		flt_idx++;
	}

	ipa_debug("Sending %d descriptors for flt tbl clearing\n", num_cmds);
	retval = ipa3_send_cmd(num_cmds, desc);
	if (retval) {
		ipa_err("failed to send immediate command (err %d)\n", retval);
		retval = -EFAULT;
	}

free_empty_img:
	ipahal_free_empty_img(&mem);
free_cmd_pyld:
	for (index = 0; index < num_cmds; index++)
		ipahal_destroy_imm_cmd(cmd_pyld[index]);
	kfree(cmd_pyld);
free_desc:
	kfree(desc);
	return retval;
}

static int ipa3_q6_clean_q6_rt_tbls(enum ipa_ip_type ip,
	enum ipa_rule_type rlt)
{
	struct ipa3_desc *desc;
	struct ipahal_imm_cmd_pyld *cmd_pyld = NULL;
	int retval = 0;
	u32 modem_rt_index_lo;
	u32 modem_rt_index_hi;
	u32 lcl_addr_mem_part;
	struct ipa_mem_buffer mem;
	u32 width = ipahal_get_hw_tbl_hdr_width();
	u32 offset;

	ipa_debug("Entry\n");

	if ((ip >= IPA_IP_MAX) || (rlt >= IPA_RULE_TYPE_MAX)) {
		ipa_err("Input Err: ip=%d ; rlt=%d\n", ip, rlt);
		return -EINVAL;
	}

	if (ip == IPA_IP_v4) {
		modem_rt_index_lo = ipa3_mem(V4_MODEM_RT_INDEX_LO);
		modem_rt_index_hi = ipa3_mem(V4_MODEM_RT_INDEX_HI);
		if (rlt == IPA_RULE_HASHABLE)
			lcl_addr_mem_part = ipa3_mem(V4_RT_HASH_OFST);
		else
			lcl_addr_mem_part = ipa3_mem(V4_RT_NHASH_OFST);
	} else {
		modem_rt_index_lo = ipa3_mem(V6_MODEM_RT_INDEX_LO);
		modem_rt_index_hi = ipa3_mem(V6_MODEM_RT_INDEX_HI);
		if (rlt == IPA_RULE_HASHABLE)
			lcl_addr_mem_part = ipa3_mem(V6_RT_HASH_OFST);
		else
			lcl_addr_mem_part = ipa3_mem(V6_RT_NHASH_OFST);
	}

	retval = ipahal_rt_generate_empty_img(
		modem_rt_index_hi - modem_rt_index_lo + 1, &mem, GFP_ATOMIC);
	if (retval) {
		ipa_err("fail generate empty rt img\n");
		return -ENOMEM;
	}

	desc = kzalloc(sizeof(*desc), GFP_KERNEL);
	if (!desc) {
		ipa_err("failed to allocate memory\n");
		goto free_empty_img;
	}

	offset = ipa3_ctx->smem_restricted_bytes + lcl_addr_mem_part +
			modem_rt_index_lo * width;
	cmd_pyld = ipahal_dma_shared_mem_write_pyld(&mem, offset);
	if (!cmd_pyld) {
		ipa_err("failed to construct dma_shared_mem imm cmd\n");
		retval = -ENOMEM;
		goto free_desc;
	}
	ipa_desc_fill_imm_cmd(desc, cmd_pyld);

	ipa_debug("Sending 1 descriptor for rt tbl clearing\n");
	retval = ipa3_send_cmd(1, desc);
	if (retval) {
		ipa_err("failed to send immediate command (err %d)\n", retval);
		retval = -EFAULT;
	}

	ipahal_destroy_imm_cmd(cmd_pyld);
free_desc:
	kfree(desc);
free_empty_img:
	ipahal_free_empty_img(&mem);
	return retval;
}


static int ipa3_q6_clean_q6_tables(void)
{
	struct ipa3_desc *desc;
	struct ipahal_imm_cmd_pyld *cmd_pyld = NULL;
	struct ipahal_reg_fltrt_hash_flush flush;
	struct ipahal_reg_valmask valmask;
	u32 offset;
	int retval;

	ipa_debug("Entry\n");


	if (ipa3_q6_clean_q6_flt_tbls(IPA_IP_v4, IPA_RULE_HASHABLE)) {
		ipa_err("failed to clean q6 flt tbls (v4/hashable)\n");
		return -EFAULT;
	}
	if (ipa3_q6_clean_q6_flt_tbls(IPA_IP_v6, IPA_RULE_HASHABLE)) {
		ipa_err("failed to clean q6 flt tbls (v6/hashable)\n");
		return -EFAULT;
	}
	if (ipa3_q6_clean_q6_flt_tbls(IPA_IP_v4, IPA_RULE_NON_HASHABLE)) {
		ipa_err("failed to clean q6 flt tbls (v4/non-hashable)\n");
		return -EFAULT;
	}
	if (ipa3_q6_clean_q6_flt_tbls(IPA_IP_v6, IPA_RULE_NON_HASHABLE)) {
		ipa_err("failed to clean q6 flt tbls (v6/non-hashable)\n");
		return -EFAULT;
	}

	if (ipa3_q6_clean_q6_rt_tbls(IPA_IP_v4, IPA_RULE_HASHABLE)) {
		ipa_err("failed to clean q6 rt tbls (v4/hashable)\n");
		return -EFAULT;
	}
	if (ipa3_q6_clean_q6_rt_tbls(IPA_IP_v6, IPA_RULE_HASHABLE)) {
		ipa_err("failed to clean q6 rt tbls (v6/hashable)\n");
		return -EFAULT;
	}
	if (ipa3_q6_clean_q6_rt_tbls(IPA_IP_v4, IPA_RULE_NON_HASHABLE)) {
		ipa_err("failed to clean q6 rt tbls (v4/non-hashable)\n");
		return -EFAULT;
	}
	if (ipa3_q6_clean_q6_rt_tbls(IPA_IP_v6, IPA_RULE_NON_HASHABLE)) {
		ipa_err("failed to clean q6 rt tbls (v6/non-hashable)\n");
		return -EFAULT;
	}

	/* Flush rules cache */
	desc = kzalloc(sizeof(*desc), GFP_KERNEL);
	if (!desc) {
		ipa_err("failed to allocate memory\n");
		return -ENOMEM;
	}

	flush.v4_flt = true;
	flush.v4_rt = true;
	flush.v6_flt = true;
	flush.v6_rt = true;
	ipahal_get_fltrt_hash_flush_valmask(&flush, &valmask);
	offset = ipahal_reg_offset(IPA_FILT_ROUT_HASH_FLUSH);
	cmd_pyld = ipahal_register_write_pyld(offset, valmask.val, valmask.mask,
						false);
	if (!cmd_pyld) {
		ipa_err("fail construct register_write imm cmd\n");
		retval = -EFAULT;
		goto bail_desc;
	}
	ipa_desc_fill_imm_cmd(desc, cmd_pyld);

	ipa_debug("Sending 1 descriptor for tbls flush\n");
	retval = ipa3_send_cmd(1, desc);
	if (retval) {
		ipa_err("failed to send immediate command (err %d)\n", retval);
		retval = -EFAULT;
	}

	ipahal_destroy_imm_cmd(cmd_pyld);

bail_desc:
	kfree(desc);
	ipa_debug("Done - retval = %d\n", retval);
	return retval;
}

static const struct dev_pm_ops ipa_pm_ops = {
	.suspend_noirq = ipa3_ap_suspend,
	.resume_noirq = ipa3_ap_resume,
};

static struct platform_driver ipa_plat_drv = {
	.probe = ipa3_plat_drv_probe,
	.driver = {
		.name = DRV_NAME,
		.owner = THIS_MODULE,
		.pm = &ipa_pm_ops,
		.of_match_table = ipa_plat_drv_match,
	},
};

static int __init ipa_module_init(void)
{
	ipa_debug("IPA module init\n");

	/* Register as a platform device driver */

	return platform_driver_register(&ipa_plat_drv);
}
subsys_initcall(ipa_module_init);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("IPA HW device driver");
