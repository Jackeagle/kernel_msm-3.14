/* Copyright (c) 2012-2017, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

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
#include "gsi/gsi.h"

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

/* round addresses for closes page per SMMU requirements */
#define IPA_SMMU_ROUND_TO_PAGE(iova, pa, size, iova_p, pa_p, size_p) \
	do { \
		(iova_p) = rounddown((iova), PAGE_SIZE); \
		(pa_p) = rounddown((pa), PAGE_SIZE); \
		(size_p) = roundup((size) + (pa) - (pa_p), PAGE_SIZE); \
	} while (0)


/* The relative location in /lib/firmware where the FWs will reside */
#define IPA_FWS_PATH "ipa/ipa_fws.elf"

struct tz_smmu_ipa_protect_region_iovec_s {
	u64 input_addr;
	u64 output_addr;
	u64 size;
	u32 attr;
} __packed;

struct tz_smmu_ipa_protect_region_s {
	phys_addr_t iovec_buf;
	u32 size_bytes;
} __packed;

static int ipa3_q6_clean_q6_tables(void);
static void ipa3_start_tag_process(struct work_struct *work);
static DECLARE_WORK(ipa3_tag_work, ipa3_start_tag_process);

static void ipa_gsi_notify_cb(struct gsi_per_notify *notify);

static void ipa3_post_init_wq(struct work_struct *work);
static DECLARE_WORK(ipa3_post_init_work, ipa3_post_init_wq);

static void ipa_dec_clients_disable_clks_on_wq(struct work_struct *work);
static DECLARE_WORK(ipa_dec_clients_disable_clks_on_wq_work,
	ipa_dec_clients_disable_clks_on_wq);

static struct ipa3_plat_drv_res ipa3_res = {0, };
struct msm_bus_scale_pdata *ipa3_bus_scale_table;

static struct clk *ipa3_clk;

struct ipa3_context *ipa3_ctx;
static struct device *master_dev;
struct platform_device *ipa3_pdev;
static struct {
	bool present;
	bool fast_map;
	bool s1_bypass;
	u32 ipa_base;
	u32 ipa_size;
} smmu_info;

static char *active_clients_table_buf;

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
			IPAERR("Trying to print illegal active_clients type");
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
	ipa3_active_clients_log_print_table(active_clients_table_buf,
			IPA_ACTIVE_CLIENTS_TABLE_BUF_SIZE);
	IPAERR("%s", active_clients_table_buf);
	mutex_unlock(&ipa3_ctx->ipa3_active_clients.mutex);

	return NOTIFY_DONE;
}

static struct notifier_block ipa3_active_clients_panic_blk = {
	.notifier_call  = ipa3_active_clients_panic_notifier,
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
			sizeof(char[IPA3_ACTIVE_CLIENTS_LOG_LINE_LEN]),
			GFP_KERNEL);
	active_clients_table_buf = kzalloc(sizeof(
			char[IPA_ACTIVE_CLIENTS_TABLE_BUF_SIZE]), GFP_KERNEL);
	if (ipa3_ctx->ipa3_active_clients_logging.log_buffer == NULL) {
		pr_err("Active Clients Logging memory allocation failed");
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
	unsigned long flags;

	spin_lock_irqsave(&ipa3_ctx->ipa3_active_clients_logging.lock, flags);
	ipa3_ctx->ipa3_active_clients_logging.log_rdy = 0;
	kfree(ipa3_ctx->ipa3_active_clients_logging.log_buffer[0]);
	ipa3_ctx->ipa3_active_clients_logging.log_head = 0;
	ipa3_ctx->ipa3_active_clients_logging.log_tail =
			IPA3_ACTIVE_CLIENTS_LOG_BUFFER_SIZE_LINES - 1;
	spin_unlock_irqrestore(&ipa3_ctx->ipa3_active_clients_logging.lock,
		flags);
}

enum ipa_smmu_cb_type {
	IPA_SMMU_CB_AP,
	IPA_SMMU_CB_UC,
	IPA_SMMU_CB_MAX

};

static struct ipa_smmu_cb_ctx smmu_cb[IPA_SMMU_CB_MAX];

struct iommu_domain *ipa3_get_smmu_domain(void)
{
	if (smmu_cb[IPA_SMMU_CB_AP].valid)
		return smmu_cb[IPA_SMMU_CB_AP].mapping->domain;

	IPAERR("CB not valid\n");

	return NULL;
}

struct iommu_domain *ipa3_get_uc_smmu_domain(void)
{
	if (smmu_cb[IPA_SMMU_CB_UC].valid)
		return smmu_cb[IPA_SMMU_CB_UC].mapping->domain;

	IPAERR("CB not valid\n");

	return NULL;
}

/**
 * ipa3_get_smmu_ctx()- Return the smmu context
 *
 * Return value: pointer to smmu context address
 */
struct ipa_smmu_cb_ctx *ipa3_get_smmu_ctx(void)
{
	return &smmu_cb[IPA_SMMU_CB_AP];
}

/**
 * ipa3_get_uc_smmu_ctx()- Return the uc smmu context
 *
 * Return value: pointer to smmu context address
 */
struct ipa_smmu_cb_ctx *ipa3_get_uc_smmu_ctx(void)
{
	return &smmu_cb[IPA_SMMU_CB_UC];
}

#if 0
static int ipa3_setup_exception_path(void)
{

	struct ipahal_reg_route route = { 0 };
	int ret;
	struct ipa_ioc_add_hdr *hdr;
	struct ipa_hdr_add *hdr_entry;

	/* install the basic exception header */
	hdr = kzalloc(sizeof(struct ipa_ioc_add_hdr) + 1 *
		      sizeof(struct ipa_hdr_add), GFP_KERNEL);
	if (!hdr) {
		IPAERR("fail to alloc exception hdr\n");
		return -ENOMEM;
	}
	hdr->num_hdrs = 1;
	hdr->commit = 1;
	hdr_entry = &hdr->hdr[0];

	strlcpy(hdr_entry->name, IPA_LAN_RX_HDR_NAME, IPA_RESOURCE_NAME_MAX);
	hdr_entry->hdr_len = IPA_LAN_RX_HEADER_LENGTH;

	if (ipa3_add_hdr(hdr)) {
		IPAERR("fail to add exception hdr\n");
		ret = -EPERM;
		goto bail;
	}

	if (hdr_entry->status) {
		IPAERR("fail to add exception hdr\n");
		ret = -EPERM;
		goto bail;
	}

	ipa3_ctx->excp_hdr_hdl = hdr_entry->hdr_hdl;
	/* set the route register to pass exception packets to Apps */
	route.route_def_pipe = ipa3_get_ep_mapping(IPA_CLIENT_APPS_LAN_CONS);
	route.route_frag_def_pipe = ipa3_get_ep_mapping(
		IPA_CLIENT_APPS_LAN_CONS);
	route.route_def_hdr_table = !ipa3_ctx->hdr_tbl_lcl;
	route.route_def_retain_hdr = 1;

	if (ipa3_cfg_route(&route)) {
		IPAERR("fail to add exception hdr\n");
		ret = -EPERM;
		goto bail;
	}

	ret = 0;
bail:
	return ret;
}
#endif

static int ipa3_init_smem_region(int memory_region_size,
				int memory_region_offset)
{
	struct ipahal_imm_cmd_dma_shared_mem cmd;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	struct ipa3_desc desc;
	struct ipa_mem_buffer mem;
	int rc;

	if (memory_region_size == 0)
		return 0;

	memset(&desc, 0, sizeof(desc));
	memset(&cmd, 0, sizeof(cmd));
	memset(&mem, 0, sizeof(mem));

	mem.size = memory_region_size;
	mem.base = dma_alloc_coherent(ipa3_ctx->pdev, mem.size,
		&mem.phys_base, GFP_KERNEL);
	if (!mem.base) {
		IPAERR("failed to alloc DMA buff of size %d\n", mem.size);
		return -ENOMEM;
	}

	memset(mem.base, 0, mem.size);
	cmd.is_read = false;
	cmd.skip_pipeline_clear = false;
	cmd.pipeline_clear_options = IPAHAL_HPS_CLEAR;
	cmd.size = mem.size;
	cmd.system_addr = mem.phys_base;
	cmd.local_addr = ipa3_ctx->smem_restricted_bytes +
		memory_region_offset;
	cmd_pyld = ipahal_construct_imm_cmd(
		IPA_IMM_CMD_DMA_SHARED_MEM, &cmd, false);
	if (!cmd_pyld) {
		IPAERR("failed to construct dma_shared_mem imm cmd\n");
		return -ENOMEM;
	}
	desc.opcode = cmd_pyld->opcode;
	desc.pyld = cmd_pyld->data;
	desc.len = cmd_pyld->len;
	desc.type = IPA_IMM_CMD_DESC;

	rc = ipa3_send_cmd(1, &desc);
	if (rc) {
		IPAERR("failed to send immediate command (error %d)\n", rc);
		rc = -EFAULT;
	}

	ipahal_destroy_imm_cmd(cmd_pyld);
	dma_free_coherent(ipa3_ctx->pdev, mem.size, mem.base,
		mem.phys_base);

	return rc;
}

/**
* ipa3_init_q6_smem() - Initialize Q6 general memory and
*                      header memory regions in IPA.
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

	rc = ipa3_init_smem_region(IPA_MEM_PART(modem_size),
		IPA_MEM_PART(modem_ofst));
	if (rc) {
		IPAERR("failed to initialize Modem RAM memory\n");
		IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
		return rc;
	}

	rc = ipa3_init_smem_region(IPA_MEM_PART(modem_hdr_size),
		IPA_MEM_PART(modem_hdr_ofst));
	if (rc) {
		IPAERR("failed to initialize Modem HDRs RAM memory\n");
		IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
		return rc;
	}

	rc = ipa3_init_smem_region(IPA_MEM_PART(modem_hdr_proc_ctx_size),
		IPA_MEM_PART(modem_hdr_proc_ctx_ofst));
	if (rc) {
		IPAERR("failed to initialize Modem proc ctx RAM memory\n");
		IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
		return rc;
	}

	rc = ipa3_init_smem_region(IPA_MEM_PART(modem_comp_decomp_size),
		IPA_MEM_PART(modem_comp_decomp_ofst));
	if (rc) {
		IPAERR("failed to initialize Modem Comp/Decomp RAM memory\n");
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
			if (ep_idx == -1)
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
			if (ep_idx == -1)
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
			if (ep_idx == -1)
				continue;

			gsi_ep_cfg = ipa3_get_gsi_ep_info(client_idx);
			if (!gsi_ep_cfg) {
				IPAERR("failed to get GSI config\n");
				ipa_assert();
				return;
			}

			ret = gsi_halt_channel_ee(
				gsi_ep_cfg->ipa_gsi_chan_num, gsi_ep_cfg->ee,
				&code);
			if (!ret)
				IPADBG("halted gsi ch %d ee %d with code %d\n",
				gsi_ep_cfg->ipa_gsi_chan_num,
				gsi_ep_cfg->ee,
				code);
			else
				IPAERR("failed to halt ch %d ee %d code %d\n",
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
	struct ipahal_imm_cmd_register_write reg_write;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	int retval;
	struct ipahal_reg_valmask valmask;

	desc = kcalloc(ipa3_ctx->ipa_num_pipes, sizeof(struct ipa3_desc),
			GFP_KERNEL);
	if (!desc) {
		IPAERR("failed to allocate memory\n");
		return -ENOMEM;
	}

	/* Set the exception path to AP */
	for (client_idx = 0; client_idx < IPA_CLIENT_MAX; client_idx++) {
		ep_idx = ipa3_get_ep_mapping(client_idx);
		if (ep_idx == -1)
			continue;

		if (ipa3_ctx->ep[ep_idx].valid &&
			ipa3_ctx->ep[ep_idx].skip_ep_cfg) {
			BUG_ON(num_descs >= ipa3_ctx->ipa_num_pipes);

			reg_write.skip_pipeline_clear = false;
			reg_write.pipeline_clear_options =
				IPAHAL_HPS_CLEAR;
			reg_write.offset =
				ipahal_get_reg_n_ofst(IPA_ENDP_STATUS_n,
					ep_idx);
			ipahal_get_status_ep_valmask(
				ipa3_get_ep_mapping(IPA_CLIENT_APPS_LAN_CONS),
				&valmask);
			reg_write.value = valmask.val;
			reg_write.value_mask = valmask.mask;
			cmd_pyld = ipahal_construct_imm_cmd(
				IPA_IMM_CMD_REGISTER_WRITE, &reg_write, false);
			if (!cmd_pyld) {
				IPAERR("fail construct register_write cmd\n");
				BUG();
			}

			desc[num_descs].opcode = cmd_pyld->opcode;
			desc[num_descs].type = IPA_IMM_CMD_DESC;
			desc[num_descs].callback = ipa3_destroy_imm;
			desc[num_descs].user1 = cmd_pyld;
			desc[num_descs].pyld = cmd_pyld->data;
			desc[num_descs].len = cmd_pyld->len;
			num_descs++;
		}

		/* disable statuses for modem producers */
		if (IPA_CLIENT_IS_Q6_PROD(client_idx)) {
			ipa_assert_on(num_descs >= ipa3_ctx->ipa_num_pipes);

			reg_write.skip_pipeline_clear = false;
			reg_write.pipeline_clear_options =
				IPAHAL_HPS_CLEAR;
			reg_write.offset =
				ipahal_get_reg_n_ofst(IPA_ENDP_STATUS_n,
					ep_idx);
			reg_write.value = 0;
			reg_write.value_mask = ~0;
			cmd_pyld = ipahal_construct_imm_cmd(
				IPA_IMM_CMD_REGISTER_WRITE, &reg_write, false);
			if (!cmd_pyld) {
				IPAERR("fail construct register_write cmd\n");
				ipa_assert();
				return -EFAULT;
			}

			desc[num_descs].opcode = cmd_pyld->opcode;
			desc[num_descs].type = IPA_IMM_CMD_DESC;
			desc[num_descs].callback = ipa3_destroy_imm;
			desc[num_descs].user1 = cmd_pyld;
			desc[num_descs].pyld = cmd_pyld->data;
			desc[num_descs].len = cmd_pyld->len;
			num_descs++;
		}
	}

	/* Will wait 500msecs for IPA tag process completion */
	retval = ipa3_tag_process(desc, num_descs,
		msecs_to_jiffies(CLEANUP_TAG_PROCESS_TIMEOUT));
	if (retval) {
		IPAERR("TAG process failed! (error %d)\n", retval);
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
*                    in IPA HW. This is performed in case of SSR.
*
* This is a mandatory procedure, in case one of the steps fails, the
* AP needs to restart.
*/
void ipa3_q6_pre_shutdown_cleanup(void)
{
	IPADBG_LOW("ENTER\n");

	IPA_ACTIVE_CLIENTS_INC_SIMPLE();

	ipa3_q6_pipe_delay(true);
	ipa3_q6_avoid_holb();

	if (ipa3_q6_clean_q6_tables()) {
		IPAERR("Failed to clean Q6 tables\n");
		BUG();
	}
	if (ipa3_q6_set_ex_path_to_apps()) {
		IPAERR("Failed to redirect exceptions to APPS\n");
		BUG();
	}
	/* Remove delay from Q6 PRODs to avoid pending descriptors
	  * on pipe reset procedure
	  */
	ipa3_q6_pipe_delay(false);

	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
	IPADBG_LOW("Exit with success\n");
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

	IPADBG_LOW("ENTER\n");

	if (!ipa3_ctx->uc_ctx.uc_loaded) {
		IPAERR("uC is not loaded. Skipping\n");
		return;
	}

	IPA_ACTIVE_CLIENTS_INC_SIMPLE();

	/* Handle the issue where SUSPEND was removed for some reason */
	ipa3_q6_avoid_holb();
	ipa3_halt_q6_cons_gsi_channels();

	for (client_idx = 0; client_idx < IPA_CLIENT_MAX; client_idx++)
		if (IPA_CLIENT_IS_Q6_PROD(client_idx)) {
			ep_idx = ipa3_get_ep_mapping(client_idx);
			if (ep_idx == -1)
				continue;

			if (ipa3_uc_is_gsi_channel_empty(client_idx)) {
				IPAERR("fail to validate Q6 ch emptiness %d\n",
					client_idx);
				BUG();
				return;
			}
		}

	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
	IPADBG_LOW("Exit with success\n");
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
		ipahal_get_reg_n_ofst(IPA_SRAM_DIRECT_ACCESS_n,
			ipa3_ctx->smem_restricted_bytes / 4);

	ipa_sram_mmio = ioremap(phys_addr, ipa3_ctx->smem_sz);
	if (!ipa_sram_mmio) {
		IPAERR("fail to ioremap IPA SRAM\n");
		return -ENOMEM;
	}

	/* Consult with ipa_i.h on the location of the CANARY values */
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(v4_flt_hash_ofst) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(v4_flt_hash_ofst));
	ipa3_sram_set_canary(ipa_sram_mmio,
		IPA_MEM_PART(v4_flt_nhash_ofst) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(v4_flt_nhash_ofst));
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(v6_flt_hash_ofst) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(v6_flt_hash_ofst));
	ipa3_sram_set_canary(ipa_sram_mmio,
		IPA_MEM_PART(v6_flt_nhash_ofst) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(v6_flt_nhash_ofst));
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(v4_rt_hash_ofst) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(v4_rt_hash_ofst));
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(v4_rt_nhash_ofst) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(v4_rt_nhash_ofst));
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(v6_rt_hash_ofst) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(v6_rt_hash_ofst));
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(v6_rt_nhash_ofst) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(v6_rt_nhash_ofst));
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(modem_hdr_ofst) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(modem_hdr_ofst));
	ipa3_sram_set_canary(ipa_sram_mmio,
		IPA_MEM_PART(modem_hdr_proc_ctx_ofst) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio,
		IPA_MEM_PART(modem_hdr_proc_ctx_ofst));
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(modem_ofst) - 4);
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(modem_ofst));
	ipa3_sram_set_canary(ipa_sram_mmio, IPA_MEM_PART(uc_event_ring_ofst));

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
	struct ipahal_imm_cmd_hdr_init_local cmd = {0};
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	struct ipahal_imm_cmd_dma_shared_mem dma_cmd = { 0 };

	mem.size = IPA_MEM_PART(modem_hdr_size) + IPA_MEM_PART(apps_hdr_size);
	mem.base = dma_alloc_coherent(ipa3_ctx->pdev, mem.size, &mem.phys_base,
		GFP_KERNEL);
	if (!mem.base) {
		IPAERR("fail to alloc DMA buff of size %d\n", mem.size);
		return -ENOMEM;
	}
	memset(mem.base, 0, mem.size);

	cmd.hdr_table_addr = mem.phys_base;
	cmd.size_hdr_table = mem.size;
	cmd.hdr_addr = ipa3_ctx->smem_restricted_bytes +
		IPA_MEM_PART(modem_hdr_ofst);
	cmd_pyld = ipahal_construct_imm_cmd(
		IPA_IMM_CMD_HDR_INIT_LOCAL, &cmd, false);
	if (!cmd_pyld) {
		IPAERR("fail to construct hdr_init_local imm cmd\n");
		dma_free_coherent(ipa3_ctx->pdev,
			mem.size, mem.base,
			mem.phys_base);
		return -EFAULT;
	}
	desc.opcode = cmd_pyld->opcode;
	desc.type = IPA_IMM_CMD_DESC;
	desc.pyld = cmd_pyld->data;
	desc.len = cmd_pyld->len;
	IPA_DUMP_BUFF(mem.base, mem.phys_base, mem.size);

	if (ipa3_send_cmd(1, &desc)) {
		IPAERR("fail to send immediate command\n");
		ipahal_destroy_imm_cmd(cmd_pyld);
		dma_free_coherent(ipa3_ctx->pdev,
			mem.size, mem.base,
			mem.phys_base);
		return -EFAULT;
	}

	ipahal_destroy_imm_cmd(cmd_pyld);
	dma_free_coherent(ipa3_ctx->pdev, mem.size, mem.base, mem.phys_base);

	mem.size = IPA_MEM_PART(modem_hdr_proc_ctx_size) +
		IPA_MEM_PART(apps_hdr_proc_ctx_size);
	mem.base = dma_alloc_coherent(ipa3_ctx->pdev, mem.size, &mem.phys_base,
		GFP_KERNEL);
	if (!mem.base) {
		IPAERR("fail to alloc DMA buff of size %d\n", mem.size);
		return -ENOMEM;
	}
	memset(mem.base, 0, mem.size);
	memset(&desc, 0, sizeof(desc));

	dma_cmd.is_read = false;
	dma_cmd.skip_pipeline_clear = false;
	dma_cmd.pipeline_clear_options = IPAHAL_HPS_CLEAR;
	dma_cmd.system_addr = mem.phys_base;
	dma_cmd.local_addr = ipa3_ctx->smem_restricted_bytes +
		IPA_MEM_PART(modem_hdr_proc_ctx_ofst);
	dma_cmd.size = mem.size;
	cmd_pyld = ipahal_construct_imm_cmd(
		IPA_IMM_CMD_DMA_SHARED_MEM, &dma_cmd, false);
	if (!cmd_pyld) {
		IPAERR("fail to construct dma_shared_mem imm\n");
		dma_free_coherent(ipa3_ctx->pdev,
			mem.size, mem.base,
			mem.phys_base);
		return -EFAULT;
	}
	desc.opcode = cmd_pyld->opcode;
	desc.pyld = cmd_pyld->data;
	desc.len = cmd_pyld->len;
	desc.type = IPA_IMM_CMD_DESC;
	IPA_DUMP_BUFF(mem.base, mem.phys_base, mem.size);

	if (ipa3_send_cmd(1, &desc)) {
		IPAERR("fail to send immediate command\n");
		ipahal_destroy_imm_cmd(cmd_pyld);
		dma_free_coherent(ipa3_ctx->pdev,
			mem.size,
			mem.base,
			mem.phys_base);
		return -EFAULT;
	}
	ipahal_destroy_imm_cmd(cmd_pyld);

	ipahal_write_reg(IPA_LOCAL_PKT_PROC_CNTXT_BASE, dma_cmd.local_addr);

	dma_free_coherent(ipa3_ctx->pdev, mem.size, mem.base, mem.phys_base);

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
        struct ipahal_imm_cmd_ip_v4_routing_init v4_cmd;
        struct ipahal_imm_cmd_pyld *cmd_pyld;
        int i;
        int rc = 0;

        for (i = IPA_MEM_PART(v4_modem_rt_index_lo);
                i <= IPA_MEM_PART(v4_modem_rt_index_hi);
                i++)
                ipa3_ctx->rt_idx_bitmap[IPA_IP_v4] |= (1 << i);
        IPADBG("v4 rt bitmap 0x%lx\n", ipa3_ctx->rt_idx_bitmap[IPA_IP_v4]);

        rc = ipahal_rt_generate_empty_img(IPA_MEM_PART(v4_rt_num_index),
                IPA_MEM_PART(v4_rt_hash_size), IPA_MEM_PART(v4_rt_nhash_size),
                &mem, false);
        if (rc) {
                IPAERR("fail generate empty v4 rt img\n");
                return rc;
        }

        v4_cmd.hash_rules_addr = mem.phys_base;
        v4_cmd.hash_rules_size = mem.size;
        v4_cmd.hash_local_addr = ipa3_ctx->smem_restricted_bytes +
                IPA_MEM_PART(v4_rt_hash_ofst);
        v4_cmd.nhash_rules_addr = mem.phys_base;
        v4_cmd.nhash_rules_size = mem.size;
        v4_cmd.nhash_local_addr = ipa3_ctx->smem_restricted_bytes +
                IPA_MEM_PART(v4_rt_nhash_ofst);
        IPADBG("putting hashable routing IPv4 rules to phys 0x%x\n",
                                v4_cmd.hash_local_addr);
        IPADBG("putting non-hashable routing IPv4 rules to phys 0x%x\n",
                                v4_cmd.nhash_local_addr);
        cmd_pyld = ipahal_construct_imm_cmd(
                IPA_IMM_CMD_IP_V4_ROUTING_INIT, &v4_cmd, false);
        if (!cmd_pyld) {
                IPAERR("fail construct ip_v4_rt_init imm cmd\n");
                rc = -EPERM;
                goto free_mem;
        }

        desc.opcode = cmd_pyld->opcode;
        desc.type = IPA_IMM_CMD_DESC;
        desc.pyld = cmd_pyld->data;
        desc.len = cmd_pyld->len;
        IPA_DUMP_BUFF(mem.base, mem.phys_base, mem.size);

        if (ipa3_send_cmd(1, &desc)) {
                IPAERR("fail to send immediate command\n");
                rc = -EFAULT;
        }

        ipahal_destroy_imm_cmd(cmd_pyld);

free_mem:
        ipahal_free_dma_mem(&mem);
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
        struct ipahal_imm_cmd_ip_v6_routing_init v6_cmd;
        struct ipahal_imm_cmd_pyld *cmd_pyld;
        int i;
        int rc = 0;

        for (i = IPA_MEM_PART(v6_modem_rt_index_lo);
                i <= IPA_MEM_PART(v6_modem_rt_index_hi);
                i++)
                ipa3_ctx->rt_idx_bitmap[IPA_IP_v6] |= (1 << i);
        IPADBG("v6 rt bitmap 0x%lx\n", ipa3_ctx->rt_idx_bitmap[IPA_IP_v6]);

        rc = ipahal_rt_generate_empty_img(IPA_MEM_PART(v6_rt_num_index),
                IPA_MEM_PART(v6_rt_hash_size), IPA_MEM_PART(v6_rt_nhash_size),
                &mem, false);
        if (rc) {
                IPAERR("fail generate empty v6 rt img\n");
                return rc;
        }

        v6_cmd.hash_rules_addr = mem.phys_base;
        v6_cmd.hash_rules_size = mem.size;
        v6_cmd.hash_local_addr = ipa3_ctx->smem_restricted_bytes +
                IPA_MEM_PART(v6_rt_hash_ofst);
        v6_cmd.nhash_rules_addr = mem.phys_base;
        v6_cmd.nhash_rules_size = mem.size;
        v6_cmd.nhash_local_addr = ipa3_ctx->smem_restricted_bytes +
                IPA_MEM_PART(v6_rt_nhash_ofst);
        IPADBG("putting hashable routing IPv6 rules to phys 0x%x\n",
                                v6_cmd.hash_local_addr);
        IPADBG("putting non-hashable routing IPv6 rules to phys 0x%x\n",
                                v6_cmd.nhash_local_addr);
        cmd_pyld = ipahal_construct_imm_cmd(
                IPA_IMM_CMD_IP_V6_ROUTING_INIT, &v6_cmd, false);
        if (!cmd_pyld) {
                IPAERR("fail construct ip_v6_rt_init imm cmd\n");
                rc = -EPERM;
                goto free_mem;
        }

        desc.opcode = cmd_pyld->opcode;
        desc.type = IPA_IMM_CMD_DESC;
        desc.pyld = cmd_pyld->data;
        desc.len = cmd_pyld->len;
        IPA_DUMP_BUFF(mem.base, mem.phys_base, mem.size);

        if (ipa3_send_cmd(1, &desc)) {
                IPAERR("fail to send immediate command\n");
                rc = -EFAULT;
        }

        ipahal_destroy_imm_cmd(cmd_pyld);

free_mem:
        ipahal_free_dma_mem(&mem);
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
                IPA_MEM_PART(v4_flt_hash_size),
                IPA_MEM_PART(v4_flt_nhash_size), ipa3_ctx->ep_flt_bitmap,
                &mem, false);
        if (rc) {
                IPAERR("fail generate empty v4 flt img\n");
                return rc;
        }

        v4_cmd.hash_rules_addr = mem.phys_base;
        v4_cmd.hash_rules_size = mem.size;
        v4_cmd.hash_local_addr = ipa3_ctx->smem_restricted_bytes +
                IPA_MEM_PART(v4_flt_hash_ofst);
        v4_cmd.nhash_rules_addr = mem.phys_base;
        v4_cmd.nhash_rules_size = mem.size;
        v4_cmd.nhash_local_addr = ipa3_ctx->smem_restricted_bytes +
                IPA_MEM_PART(v4_flt_nhash_ofst);
        IPADBG("putting hashable filtering IPv4 rules to phys 0x%x\n",
                                v4_cmd.hash_local_addr);
        IPADBG("putting non-hashable filtering IPv4 rules to phys 0x%x\n",
                                v4_cmd.nhash_local_addr);
        cmd_pyld = ipahal_construct_imm_cmd(
                IPA_IMM_CMD_IP_V4_FILTER_INIT, &v4_cmd, false);
        if (!cmd_pyld) {
                IPAERR("fail construct ip_v4_flt_init imm cmd\n");
                rc = -EPERM;
                goto free_mem;
        }

        desc.opcode = cmd_pyld->opcode;
        desc.type = IPA_IMM_CMD_DESC;
        desc.pyld = cmd_pyld->data;
        desc.len = cmd_pyld->len;
        IPA_DUMP_BUFF(mem.base, mem.phys_base, mem.size);

        if (ipa3_send_cmd(1, &desc)) {
                IPAERR("fail to send immediate command\n");
                rc = -EFAULT;
        }

        ipahal_destroy_imm_cmd(cmd_pyld);

free_mem:
        ipahal_free_dma_mem(&mem);
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
                IPA_MEM_PART(v6_flt_hash_size),
                IPA_MEM_PART(v6_flt_nhash_size), ipa3_ctx->ep_flt_bitmap,
                &mem, false);
        if (rc) {
                IPAERR("fail generate empty v6 flt img\n");
                return rc;
        }

        v6_cmd.hash_rules_addr = mem.phys_base;
        v6_cmd.hash_rules_size = mem.size;
        v6_cmd.hash_local_addr = ipa3_ctx->smem_restricted_bytes +
                IPA_MEM_PART(v6_flt_hash_ofst);
        v6_cmd.nhash_rules_addr = mem.phys_base;
        v6_cmd.nhash_rules_size = mem.size;
        v6_cmd.nhash_local_addr = ipa3_ctx->smem_restricted_bytes +
                IPA_MEM_PART(v6_flt_nhash_ofst);
        IPADBG("putting hashable filtering IPv6 rules to phys 0x%x\n",
                                v6_cmd.hash_local_addr);
        IPADBG("putting non-hashable filtering IPv6 rules to phys 0x%x\n",
                                v6_cmd.nhash_local_addr);

        cmd_pyld = ipahal_construct_imm_cmd(
                IPA_IMM_CMD_IP_V6_FILTER_INIT, &v6_cmd, false);
        if (!cmd_pyld) {
                IPAERR("fail construct ip_v6_flt_init imm cmd\n");
                rc = -EPERM;
                goto free_mem;
        }

        desc.opcode = cmd_pyld->opcode;
        desc.type = IPA_IMM_CMD_DESC;
        desc.pyld = cmd_pyld->data;
        desc.len = cmd_pyld->len;
        IPA_DUMP_BUFF(mem.base, mem.phys_base, mem.size);

        if (ipa3_send_cmd(1, &desc)) {
                IPAERR("fail to send immediate command\n");
                rc = -EFAULT;
        }

        ipahal_destroy_imm_cmd(cmd_pyld);

free_mem:
        ipahal_free_dma_mem(&mem);
        return rc;
}


static int ipa3_setup_flt_hash_tuple(void)
{
	int pipe_idx;
	struct ipahal_reg_hash_tuple tuple;

	memset(&tuple, 0, sizeof(struct ipahal_reg_hash_tuple));

	for (pipe_idx = 0; pipe_idx < ipa3_ctx->ipa_num_pipes ; pipe_idx++) {
		if (!ipa_is_ep_support_flt(pipe_idx))
			continue;

		if (ipa_is_modem_pipe(pipe_idx))
			continue;

		if (ipa3_set_flt_tuple_mask(pipe_idx, &tuple)) {
		IPAERR("failed to setup pipe %d flt tuple\n", pipe_idx);
		return -EFAULT;
        }
	}

	return 0;
}

static int ipa3_setup_rt_hash_tuple(void)
{
	int tbl_idx;
	struct ipahal_reg_hash_tuple tuple;

	memset(&tuple, 0, sizeof(struct ipahal_reg_hash_tuple));

	for (tbl_idx = 0;
		tbl_idx < max(IPA_MEM_PART(v6_rt_num_index),
		IPA_MEM_PART(v4_rt_num_index));
		tbl_idx++) {

		if (tbl_idx >= IPA_MEM_PART(v4_modem_rt_index_lo) &&
			tbl_idx <= IPA_MEM_PART(v4_modem_rt_index_hi))
			continue;

		if (tbl_idx >= IPA_MEM_PART(v6_modem_rt_index_lo) &&
			tbl_idx <= IPA_MEM_PART(v6_modem_rt_index_hi))
			continue;

		if (ipa3_set_rt_tuple_mask(tbl_idx, &tuple)) {
			IPAERR("failed to setup tbl %d rt tuple\n", tbl_idx);
			return -EFAULT;
		}
	}

	return 0;
}

static int ipa3_setup_apps_pipes(void)
{
	struct ipa_sys_connect_params sys_in;
	int result = 0;

	if (ipa3_ctx->gsi_ch20_wa) {
		IPADBG("Allocating GSI physical channel 20\n");
		result = ipa_gsi_ch20_wa();
		if (result) {
			IPAERR("ipa_gsi_ch20_wa failed %d\n", result);
			goto fail_ch20_wa;
		}
	}

	/* allocate the common PROD event ring */
	if (ipa3_alloc_common_event_ring()) {
		IPAERR("ipa3_alloc_common_event_ring failed.\n");
		result = -EPERM;
		goto fail_ch20_wa;
	}

	/* CMD OUT (AP->IPA) */
	memset(&sys_in, 0, sizeof(struct ipa_sys_connect_params));
	sys_in.client = IPA_CLIENT_APPS_CMD_PROD;
	sys_in.desc_fifo_sz = IPA_SYS_DESC_FIFO_SZ;
	sys_in.ipa_ep_cfg.mode.mode = IPA_DMA;
	sys_in.ipa_ep_cfg.mode.dst = IPA_CLIENT_APPS_LAN_CONS;
	if (ipa3_setup_sys_pipe(&sys_in, &ipa3_ctx->clnt_hdl_cmd)) {
		IPAERR(":setup sys pipe (APPS_CMD_PROD) failed.\n");
		result = -EPERM;
		goto fail_ch20_wa;
	}
	IPADBG("Apps to IPA cmd pipe is connected\n");

	ipa3_ctx->ctrl->ipa_init_sram();
	IPADBG("SRAM initialized\n");

	ipa3_ctx->ctrl->ipa_init_hdr();
	IPADBG("HDR initialized\n");

	ipa3_ctx->ctrl->ipa_init_rt4();
        IPADBG("V4 RT initialized\n");

        ipa3_ctx->ctrl->ipa_init_rt6();
        IPADBG("V6 RT initialized\n");

        ipa3_ctx->ctrl->ipa_init_flt4();
        IPADBG("V4 FLT initialized\n");

        ipa3_ctx->ctrl->ipa_init_flt6();
        IPADBG("V6 FLT initialized\n");

	if (ipa3_setup_flt_hash_tuple()) {
		IPAERR(":fail to configure flt hash tuple\n");
		result = -EPERM;
		goto fail_flt_hash_tuple;
	}
	IPADBG("flt hash tuple is configured\n");

	if (ipa3_setup_rt_hash_tuple()) {
		IPAERR(":fail to configure rt hash tuple\n");
		result = -EPERM;
		goto fail_flt_hash_tuple;
	}
	IPADBG("rt hash tuple is configured\n");

	#if 0
	if (ipa3_setup_exception_path()) {
		IPAERR(":fail to setup excp path\n");
		result = -EPERM;
		goto fail_flt_hash_tuple;
	}
	IPADBG("Exception path was successfully set");

	if (ipa3_setup_dflt_rt_tables()) {
                IPAERR(":fail to setup dflt routes\n");
                result = -EPERM;
                goto fail_flt_hash_tuple;
    }
        IPADBG("default routing was set\n");
	#endif

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

	/**
	 * ipa_lan_rx_cb() intended to notify the source EP about packet
	 * being received on the LAN_CONS via calling the source EP call-back.
	 * There could be a race condition with calling this call-back. Other
	 * thread may nullify it - e.g. on EP disconnect.
	 * This lock intended to protect the access to the source EP call-back
	 */
	spin_lock_init(&ipa3_ctx->disconnect_lock);
	if (ipa3_setup_sys_pipe(&sys_in, &ipa3_ctx->clnt_hdl_data_in)) {
		IPAERR(":setup sys pipe (LAN_CONS) failed.\n");
		result = -EPERM;
		goto fail_flt_hash_tuple;
	}

	return 0;

fail_flt_hash_tuple:
	#if 0
	if (ipa3_ctx->excp_hdr_hdl)
		__ipa3_del_hdr(ipa3_ctx->excp_hdr_hdl, false);
	#endif
	ipa3_teardown_sys_pipe(ipa3_ctx->clnt_hdl_cmd);
fail_ch20_wa:
	return result;
}

static int ipa3_get_clks(struct device *dev)
{
	if (ipa3_res.use_bw_vote) {
		IPADBG("Vote IPA clock by bw voting via bus scaling driver\n");
		ipa3_clk = NULL;
		return 0;
	}

	ipa3_clk = clk_get(dev, "core_clk");
	if (IS_ERR(ipa3_clk)) {
		if (ipa3_clk != ERR_PTR(-EPROBE_DEFER))
			IPAERR("fail to get ipa clk\n");
		return PTR_ERR(ipa3_clk);
	}
	return 0;
}

/**
 * _ipa_enable_clks_v3_0() - Enable IPA clocks.
 */
void _ipa_enable_clks_v3_0(void)
{
	IPADBG_LOW("curr_ipa_clk_rate=%d", ipa3_ctx->curr_ipa_clk_rate);
	if (ipa3_clk) {
		IPADBG_LOW("enabling gcc_ipa_clk\n");
		clk_prepare(ipa3_clk);
		clk_enable(ipa3_clk);
		clk_set_rate(ipa3_clk, ipa3_ctx->curr_ipa_clk_rate);
	}

	ipa3_uc_notify_clk_state(true);
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

	IPADBG("curr %d idx %d\n", ipa3_ctx->curr_ipa_clk_rate, idx);

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
	IPADBG("enabling IPA clocks and bus voting\n");

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
	ipa3_uc_notify_clk_state(false);
	if (ipa3_clk) {
		IPADBG_LOW("disabling gcc_ipa_clk\n");
		clk_disable_unprepare(ipa3_clk);
	}
}

/**
* ipa3_disable_clks() - Turn off IPA clocks
*
* Return codes:
* None
*/
void ipa3_disable_clks(void)
{
	IPADBG("disabling IPA clocks and bus voting\n");

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

	IPADBG("starting TAG process\n");
	/* close aggregation frames on all pipes */
	res = ipa3_tag_aggr_force_close(-1);
	if (res)
		IPAERR("ipa3_tag_aggr_force_close failed %d\n", res);
	IPA_ACTIVE_CLIENTS_DEC_SPECIAL("TAG_PROCESS");

	IPADBG("TAG process done\n");
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
void ipa3_active_clients_log_mod(struct ipa_active_client_logging_info *id,
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
		hentry = NULL;
		hentry = kzalloc(sizeof(
				struct ipa3_active_client_htable_entry),
				int_ctx ? GFP_ATOMIC : GFP_KERNEL);
		if (hentry == NULL) {
			IPAERR("failed allocating active clients hash entry");
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
		nanosec_rem = do_div(t, 1000000000) / 1000;
		snprintf(temp_str, IPA3_ACTIVE_CLIENTS_LOG_LINE_LEN,
				inc ? "[%5lu.%06lu] ^ %s, %s: %d" :
						"[%5lu.%06lu] v %s, %s: %d",
				(unsigned long)t, nanosec_rem,
				id->id_string, id->file, id->line);
		ipa3_active_clients_log_insert(temp_str);
	}
	spin_unlock_irqrestore(&ipa3_ctx->ipa3_active_clients_logging.lock,
		flags);
}

void ipa3_active_clients_log_dec(struct ipa_active_client_logging_info *id,
		bool int_ctx)
{
	ipa3_active_clients_log_mod(id, false, int_ctx);
}

void ipa3_active_clients_log_inc(struct ipa_active_client_logging_info *id,
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
		IPADBG_LOW("active clients = %d\n",
			atomic_read(&ipa3_ctx->ipa3_active_clients.cnt));
		return;
	}

	mutex_lock(&ipa3_ctx->ipa3_active_clients.mutex);

	/* somebody might voted to clocks meanwhile */
	ret = atomic_inc_not_zero(&ipa3_ctx->ipa3_active_clients.cnt);
	if (ret) {
		mutex_unlock(&ipa3_ctx->ipa3_active_clients.mutex);
		IPADBG_LOW("active clients = %d\n",
			atomic_read(&ipa3_ctx->ipa3_active_clients.cnt));
		return;
	}

	ipa3_enable_clks();
	atomic_inc(&ipa3_ctx->ipa3_active_clients.cnt);
	IPADBG_LOW("active clients = %d\n",
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
		IPADBG_LOW("active clients = %d\n",
			atomic_read(&ipa3_ctx->ipa3_active_clients.cnt));
		return 0;
	}

	return -EPERM;
}

static void __ipa3_dec_client_disable_clks(void)
{
	int ret;

	if (!atomic_read(&ipa3_ctx->ipa3_active_clients.cnt)) {
		IPAERR("trying to disable clocks with refcnt is 0!\n");
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
	IPADBG_LOW("active clients = %d\n",
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
		IPADBG_LOW("active clients = %d\n",
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
	IPADBG_LOW("active wakelock ref cnt = %d\n",
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
	IPADBG_LOW("active wakelock ref cnt = %d\n",
		ipa3_ctx->wakelock_ref_cnt.cnt);
	if (ipa3_ctx->wakelock_ref_cnt.cnt == 0)
		__pm_relax(&ipa3_ctx->w_lock);
	spin_unlock_irqrestore(&ipa3_ctx->wakelock_ref_cnt.spinlock, flags);
}

int ipa3_set_required_perf_profile(enum ipa_voltage_level floor_voltage,
				  u32 bandwidth_mbps)
{
	enum ipa_voltage_level needed_voltage;
	u32 clk_rate;

	IPADBG_LOW("floor_voltage=%d, bandwidth_mbps=%u",
					floor_voltage, bandwidth_mbps);

	if (floor_voltage < IPA_VOLTAGE_UNSPECIFIED ||
		floor_voltage >= IPA_VOLTAGE_MAX) {
		IPAERR("bad voltage\n");
		return -EINVAL;
	}

	if (ipa3_ctx->enable_clock_scaling) {
		IPADBG_LOW("Clock scaling is enabled\n");
		if (bandwidth_mbps >=
			ipa3_ctx->ctrl->clock_scaling_bw_threshold_turbo)
			needed_voltage = IPA_VOLTAGE_TURBO;
		else if (bandwidth_mbps >=
			ipa3_ctx->ctrl->clock_scaling_bw_threshold_nominal)
			needed_voltage = IPA_VOLTAGE_NOMINAL;
		else
			needed_voltage = IPA_VOLTAGE_SVS;
	} else {
		IPADBG_LOW("Clock scaling is disabled\n");
		needed_voltage = IPA_VOLTAGE_NOMINAL;
	}

	needed_voltage = max(needed_voltage, floor_voltage);
	switch (needed_voltage) {
	case IPA_VOLTAGE_SVS:
		clk_rate = ipa3_ctx->ctrl->ipa_clk_rate_svs;
		break;
	case IPA_VOLTAGE_NOMINAL:
		clk_rate = ipa3_ctx->ctrl->ipa_clk_rate_nominal;
		break;
	case IPA_VOLTAGE_TURBO:
		clk_rate = ipa3_ctx->ctrl->ipa_clk_rate_turbo;
		break;
	default:
		IPAERR("bad voltage\n");
		WARN_ON(1);
		return -EFAULT;
	}

	if (clk_rate == ipa3_ctx->curr_ipa_clk_rate) {
		IPADBG_LOW("Same voltage\n");
		return 0;
	}

	/* Hold the mutex to avoid race conditions with ipa3_enable_clocks() */
	mutex_lock(&ipa3_ctx->ipa3_active_clients.mutex);
	ipa3_ctx->curr_ipa_clk_rate = clk_rate;
	IPADBG_LOW("setting clock rate to %u\n", ipa3_ctx->curr_ipa_clk_rate);
	if (atomic_read(&ipa3_ctx->ipa3_active_clients.cnt) > 0) {
		if (ipa3_clk)
			clk_set_rate(ipa3_clk, ipa3_ctx->curr_ipa_clk_rate);
		if (msm_bus_scale_client_update_request(ipa3_ctx->ipa_bus_hdl,
				ipa3_get_bus_vote()))
			WARN_ON(1);
	} else {
		IPADBG_LOW("clocks are gated, not setting rate\n");
	}
	mutex_unlock(&ipa3_ctx->ipa3_active_clients.mutex);
	IPADBG_LOW("Done\n");

	return 0;
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

	IPADBG("interrupt=%d, interrupt_data=%u\n",
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
					IPADBG_LOW("Pipes un-suspended.\n");
					IPADBG_LOW("Enter poll mode.\n");
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
* ipa3_restore_suspend_handler() - restores the original suspend IRQ handler
* as it was registered in the IPA init sequence.
* Return codes:
* 0: success
* -EPERM: failed to remove current handler or failed to add original handler
*/
int ipa3_restore_suspend_handler(void)
{
	int result = 0;

	result  = ipa3_remove_interrupt_handler(IPA_TX_SUSPEND_IRQ);
	if (result) {
		IPAERR("remove handler for suspend interrupt failed\n");
		return -EPERM;
	}

	result = ipa3_add_interrupt_handler(IPA_TX_SUSPEND_IRQ,
			ipa3_suspend_handler, false, NULL);
	if (result) {
		IPAERR("register handler for suspend interrupt failed\n");
		result = -EPERM;
	}

	IPADBG("suspend handler successfully restored\n");

	return result;
}

/**
 * ipa3_init_interrupts() - Register to IPA IRQs
 *
 * Return codes: 0 in success, negative in failure
 *
 */
int ipa3_init_interrupts(void)
{
	int result;

	/*register IPA IRQ handler*/
	result = ipa3_interrupts_init(ipa3_res.ipa_irq, 0,
			master_dev);
	if (result) {
		IPAERR("ipa interrupts initialization failed\n");
		return -ENODEV;
	}

	/*add handler for suspend interrupt*/
	result = ipa3_add_interrupt_handler(IPA_TX_SUSPEND_IRQ,
			ipa3_suspend_handler, false, NULL);
	if (result) {
		IPAERR("register handler for suspend interrupt failed\n");
		result = -ENODEV;
		goto fail_add_interrupt_handler;
	}

	return 0;

fail_add_interrupt_handler:
	free_irq(ipa3_res.ipa_irq, master_dev);
	return result;
}

static void ipa3_freeze_clock_vote_and_notify_modem(void)
{
	int res;
	struct ipa_active_client_logging_info log_info;

	if (ipa3_ctx->smp2p_info.res_sent)
		return;

	if (ipa3_ctx->smp2p_info.out_base_id == 0) {
		IPAERR("smp2p out gpio not assigned\n");
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
	IPADBG("IPA clocks are %s\n",
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

	IPADBG("Calling uC panic handler\n");
	res = ipa3_uc_panic_notifier(this, event, ptr);
	if (res)
		IPAERR("uC panic handler failed %d\n", res);

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

static void ipa3_trigger_ipa_ready_cbs(void)
{
	struct ipa3_ready_cb_info *info;

	mutex_lock(&ipa3_ctx->lock);

	/* Call all the CBs */
	list_for_each_entry(info, &ipa3_ctx->ipa_ready_cb_list, link)
		if (info->ready_cb)
			info->ready_cb(info->user_data);

	mutex_unlock(&ipa3_ctx->lock);
}

static void ipa3_uc_is_loaded(void)
{
	IPADBG("\n");
	complete_all(&ipa3_ctx->uc_loaded_completion_obj);
}

/**
 * ipa3_post_init() - Initialize the IPA Driver (Part II).
 * This part contains all initialization which requires interaction with
 * IPA HW (via GSI).
 *
 * @resource_p:	contain platform specific values from DST file
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
static int ipa3_post_init(const struct ipa3_plat_drv_res *resource_p,
			  struct device *ipa_dev)
{
	int result;
	struct gsi_per_props gsi_props;
	struct ipa3_uc_hdlrs uc_hdlrs = { 0 };
	struct idr *idr;

	if (ipa3_ctx == NULL) {
		IPADBG("IPA driver haven't initialized\n");
		return -ENXIO;
	}

	/* Prevent consequent calls from trying to load the FW again. */
	if (ipa3_ctx->ipa_initialization_complete)
		return 0;

	/*
	 * indication whether working in MHI config or non MHI config is given
	 * in ipa3_write which is launched before ipa3_post_init. i.e. from
	 * this point it is safe to use ipa3_ep_mapping array and the correct
	 * entry will be returned from ipa3_get_hw_type_index()
	 */
	ipa_init_ep_flt_bitmap();
	IPADBG("EP with flt support bitmap 0x%x (%u pipes)\n",
		ipa3_ctx->ep_flt_bitmap, ipa3_ctx->ep_flt_num);

	/* Assign resource limitation to each group */
	ipa3_set_resorce_groups_min_max_limits();
	idr = &(ipa3_ctx->flt_rule_ids[IPA_IP_v4]);
	idr_init(idr);
	idr = &(ipa3_ctx->flt_rule_ids[IPA_IP_v6]);
	idr_init(idr);

	if (!ipa3_ctx->apply_rg10_wa) {
		result = ipa3_init_interrupts();
		if (result) {
			IPAERR("ipa initialization of interrupts failed\n");
			result = -ENODEV;
			goto fail_register_device;
		}
	} else {
		IPADBG("Initialization of ipa interrupts skipped\n");
	}

	memset(&gsi_props, 0, sizeof(gsi_props));
	gsi_props.ee = resource_p->ee;
	gsi_props.irq = resource_p->gsi_irq;
	gsi_props.phys_addr = resource_p->gsi_mem_base;
	gsi_props.size = resource_p->gsi_mem_size;
	gsi_props.notify_cb = ipa_gsi_notify_cb;

	ipa3_ctx->gsi_dev_hdl = gsi_register_device(&gsi_props);
	if (IS_ERR(ipa3_ctx->gsi_dev_hdl)) {
		IPAERR(":gsi register error - %ld\n",
				PTR_ERR(ipa3_ctx->gsi_dev_hdl));
		result = -ENODEV;
		goto fail_register_device;
	}
	IPADBG("IPA gsi is registered\n");

	/* setup the AP-IPA pipes */
	if (ipa3_setup_apps_pipes()) {
		IPAERR(":failed to setup IPA-Apps pipes\n");
		result = -ENODEV;
		goto fail_setup_apps_pipes;
	}
	IPADBG("IPA GPI pipes were connected\n");

	ipa3_debugfs_init();

	result = ipa3_uc_interface_init();
	if (result)
		IPAERR(":ipa Uc interface init failed (%d)\n", -result);
	else
		IPADBG(":ipa Uc interface init ok\n");

	uc_hdlrs.ipa_uc_loaded_hdlr = ipa3_uc_is_loaded;
	ipa3_uc_register_handlers(IPA_HW_FEATURE_COMMON, &uc_hdlrs);

	ipa3_register_panic_hdlr();

	ipa3_ctx->q6_proxy_clk_vote_valid = true;

	mutex_lock(&ipa3_ctx->lock);
	ipa3_ctx->ipa_initialization_complete = true;
	mutex_unlock(&ipa3_ctx->lock);


	ipa3_trigger_ipa_ready_cbs();
	complete_all(&ipa3_ctx->init_completion_obj);
	pr_info("IPA driver initialization was successful.\n");

	return 0;

fail_setup_apps_pipes:
	gsi_deregister_device(ipa3_ctx->gsi_dev_hdl);
fail_register_device:
	return result;
}

static void ipa3_post_init_wq(struct work_struct *work)
{
	ipa3_post_init(&ipa3_res, ipa3_ctx->dev);
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

	IPADBG("PIL FW loading process initiated\n");

	subsystem_get_retval = subsystem_get(IPA_SUBSYSTEM_NAME);
	if (IS_ERR_OR_NULL(subsystem_get_retval)) {
		IPAERR("Unable to trigger PIL process for FW loading\n");
		return -EINVAL;
	}

	IPADBG("PIL FW loading process is complete\n");
	return 0;
}

static int ipa3_open(struct inode *inode, struct file *filp)
{
        struct ipa3_context *ctx = NULL;

        IPADBG_LOW("ENTER\n");

        ctx = container_of(inode->i_cdev, struct ipa3_context, cdev);
        filp->private_data = ctx;
        return 0;
}

static ssize_t ipa3_write(struct file *file, const char __user *buf,
                          size_t count, loff_t *ppos)
{
	unsigned long missing;
	int result = -EINVAL;

	char dbg_buff[16] = { 0 };

	if (sizeof(dbg_buff) < count + 1) {
			IPAERR("ipalite: %s - dbg_buff 16, count = %ld\n",
					__func__, count);
			return -EFAULT;
	}

	missing = copy_from_user(dbg_buff, buf, count);
	if (missing) {
		IPAERR("Unable to copy data from user\n");
		return -EFAULT;
	}

	/* Prevent consequent calls from trying to load the FW again. */
	if (ipa3_is_ready())
		return count;

	IPA_ACTIVE_CLIENTS_INC_SIMPLE();

	result = ipa3_pil_load_ipa_fws();

	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();

	if (result) {
		IPAERR("IPA FW loading process has failed\n");
		return result;
	}

	queue_work(ipa3_ctx->transport_power_mgmt_wq,
		&ipa3_post_init_work);
	pr_info("IPA FW loaded successfully\n");
	return count;
}

static int ipa3_alloc_pkt_init(void)
{
	struct ipa_mem_buffer mem;
	struct ipahal_imm_cmd_pyld *cmd_pyld;
	struct ipahal_imm_cmd_ip_packet_init cmd = {0};
	int i;

	cmd_pyld = ipahal_construct_imm_cmd(IPA_IMM_CMD_IP_PACKET_INIT,
		&cmd, false);
	if (!cmd_pyld) {
		IPAERR("failed to construct IMM cmd\n");
		return -ENOMEM;
	}
	ipa3_ctx->pkt_init_imm_opcode = cmd_pyld->opcode;

	mem.size = cmd_pyld->len * ipa3_ctx->ipa_num_pipes;
	mem.base = dma_alloc_coherent(ipa3_ctx->pdev, mem.size,
		&mem.phys_base, GFP_KERNEL);
	if (!mem.base) {
		IPAERR("failed to alloc DMA buff of size %d\n", mem.size);
		ipahal_destroy_imm_cmd(cmd_pyld);
		return -ENOMEM;
	}
	ipahal_destroy_imm_cmd(cmd_pyld);

	memset(mem.base, 0, mem.size);
	for (i = 0; i < ipa3_ctx->ipa_num_pipes; i++) {
		cmd.destination_pipe_index = i;
		cmd_pyld = ipahal_construct_imm_cmd(IPA_IMM_CMD_IP_PACKET_INIT,
			&cmd, false);
		if (!cmd_pyld) {
			IPAERR("failed to construct IMM cmd\n");
			dma_free_coherent(ipa3_ctx->pdev,
				mem.size,
				mem.base,
				mem.phys_base);
			return -ENOMEM;
		}
		memcpy(mem.base + i * cmd_pyld->len, cmd_pyld->data,
			cmd_pyld->len);
		ipa3_ctx->pkt_init_imm[i] = mem.phys_base + i * cmd_pyld->len;
		ipahal_destroy_imm_cmd(cmd_pyld);
	}

	return 0;
}

/**
* ipa3_pre_init() - Initialize the IPA Driver.
* This part contains all initialization which doesn't require IPA HW, such
* as structure allocations and initializations, register writes, etc.
*
* @resource_p:	contain platform specific values from DST file
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
static int ipa3_pre_init(const struct ipa3_plat_drv_res *resource_p,
		struct device *ipa_dev)
{
	int result = 0;
	int i;
	struct ipa_active_client_logging_info log_info;

	IPADBG("IPA Driver initialization started\n");

	ipa3_ctx = kzalloc(sizeof(*ipa3_ctx), GFP_KERNEL);
	if (!ipa3_ctx) {
		IPAERR(":kzalloc err.\n");
		result = -ENOMEM;
		goto fail_mem_ctx;
	}

	ipa3_ctx->logbuf = ipc_log_context_create(IPA_IPC_LOG_PAGES, "ipa", 0);
	if (ipa3_ctx->logbuf == NULL)
		IPAERR("failed to create IPC log, continue...\n");

	ipa3_ctx->pdev = ipa_dev;
	ipa3_ctx->uc_pdev = ipa_dev;
	ipa3_ctx->smmu_present = smmu_info.present;
	if (!ipa3_ctx->smmu_present)
		ipa3_ctx->smmu_s1_bypass = true;
	else
		ipa3_ctx->smmu_s1_bypass = smmu_info.s1_bypass;
	ipa3_ctx->ipa_wrapper_base = resource_p->ipa_mem_base;
	ipa3_ctx->ipa_wrapper_size = resource_p->ipa_mem_size;
	ipa3_ctx->wan_rx_ring_size = resource_p->wan_rx_ring_size;
	ipa3_ctx->lan_rx_ring_size = resource_p->lan_rx_ring_size;
	ipa3_ctx->skip_uc_pipe_reset = resource_p->skip_uc_pipe_reset;
	ipa3_ctx->ee = resource_p->ee;
	ipa3_ctx->apply_rg10_wa = resource_p->apply_rg10_wa;
	ipa3_ctx->gsi_ch20_wa = resource_p->gsi_ch20_wa;
	ipa3_ctx->ipa3_active_clients_logging.log_rdy = false;
	if (resource_p->ipa_tz_unlock_reg) {
		ipa3_ctx->ipa_tz_unlock_reg_num =
			resource_p->ipa_tz_unlock_reg_num;
		ipa3_ctx->ipa_tz_unlock_reg = kcalloc(
			ipa3_ctx->ipa_tz_unlock_reg_num,
			sizeof(*ipa3_ctx->ipa_tz_unlock_reg),
			GFP_KERNEL);
		if (ipa3_ctx->ipa_tz_unlock_reg == NULL) {
			result = -ENOMEM;
			goto fail_tz_unlock_reg;
		}
		for (i = 0; i < ipa3_ctx->ipa_tz_unlock_reg_num; i++) {
			ipa3_ctx->ipa_tz_unlock_reg[i].reg_addr =
				resource_p->ipa_tz_unlock_reg[i].reg_addr;
			ipa3_ctx->ipa_tz_unlock_reg[i].size =
				resource_p->ipa_tz_unlock_reg[i].size;
		}
	}

	/* default aggregation parameters */
	ipa3_ctx->aggregation_type = IPA_MBIM_16;
	ipa3_ctx->aggregation_byte_limit = 1;
	ipa3_ctx->aggregation_time_limit = 0;

	ipa3_ctx->ctrl = kzalloc(sizeof(*ipa3_ctx->ctrl), GFP_KERNEL);
	if (!ipa3_ctx->ctrl) {
		IPAERR("memory allocation error for ctrl\n");
		result = -ENOMEM;
		goto fail_mem_ctrl;
	}
	result = ipa3_controller_static_bind(ipa3_ctx->ctrl);
	if (result) {
		IPAERR("fail to static bind IPA ctrl.\n");
		result = -EFAULT;
		goto fail_bind;
	}

	result = ipa3_init_mem_partition(master_dev->of_node);
	if (result) {
		IPAERR(":ipa3_init_mem_partition failed!\n");
		result = -ENODEV;
		goto fail_init_mem_partition;
	}

	if (ipa3_bus_scale_table) {
		IPADBG("Use bus scaling info from device tree #usecases=%d\n",
			ipa3_bus_scale_table->num_usecases);
		ipa3_ctx->ctrl->msm_bus_data_ptr = ipa3_bus_scale_table;
	}

	/* get BUS handle */
	ipa3_ctx->ipa_bus_hdl =
		msm_bus_scale_register_client(
			ipa3_ctx->ctrl->msm_bus_data_ptr);
	if (!ipa3_ctx->ipa_bus_hdl) {
		IPAERR("fail to register with bus mgr!\n");
		result = -ENODEV;
		goto fail_bus_reg;
	}

	/* get IPA clocks */
	result = ipa3_get_clks(master_dev);
	if (result)
		goto fail_clk;

	/* init active_clients_log after getting ipa-clk */
	if (ipa3_active_clients_log_init())
		goto fail_init_active_client;

	/* Enable ipa3_ctx->enable_clock_scaling */
	ipa3_ctx->enable_clock_scaling = 1;
	ipa3_ctx->curr_ipa_clk_rate = ipa3_ctx->ctrl->ipa_clk_rate_turbo;

	/* enable IPA clocks explicitly to allow the initialization */
	ipa3_enable_clks();

	/* setup IPA register access */
	IPADBG("Mapping 0x%x\n", resource_p->ipa_mem_base +
		ipa3_ctx->ctrl->ipa_reg_base_ofst);
	ipa3_ctx->mmio = ioremap(resource_p->ipa_mem_base +
			ipa3_ctx->ctrl->ipa_reg_base_ofst,
			resource_p->ipa_mem_size);
	if (!ipa3_ctx->mmio) {
		IPAERR(":ipa-base ioremap err.\n");
		result = -EFAULT;
		goto fail_remap;
	}

	if (ipahal_init(IPA_HW_v3_5_1, ipa3_ctx->mmio, ipa3_ctx->pdev)) {
		IPAERR("fail to init ipahal\n");
		result = -EFAULT;
		goto fail_ipahal;
	}

	result = ipa3_init_hw();
	if (result) {
		IPAERR(":error initializing HW.\n");
		result = -ENODEV;
		goto fail_init_hw;
	}

	IPADBG("IPA HW initialization sequence completed");

	ipa3_ctx->ipa_num_pipes = ipa3_get_num_pipes();
	if (ipa3_ctx->ipa_num_pipes > IPA3_MAX_NUM_PIPES) {
		IPAERR("IPA has more pipes then supported! has %d, max %d\n",
			ipa3_ctx->ipa_num_pipes, IPA3_MAX_NUM_PIPES);
		result = -ENODEV;
		goto fail_init_hw;
	}

	ipa3_ctx->ctrl->ipa_sram_read_settings();
	IPADBG("SRAM, size: 0x%x, restricted bytes: 0x%x\n",
		ipa3_ctx->smem_sz, ipa3_ctx->smem_restricted_bytes);

	IPADBG("hdr_lcl=%u ip4_rt_hash=%u ip4_rt_nonhash=%u\n",
		ipa3_ctx->hdr_tbl_lcl, ipa3_ctx->ip4_rt_tbl_hash_lcl,
		ipa3_ctx->ip4_rt_tbl_nhash_lcl);

	IPADBG("ip6_rt_hash=%u ip6_rt_nonhash=%u\n",
		ipa3_ctx->ip6_rt_tbl_hash_lcl, ipa3_ctx->ip6_rt_tbl_nhash_lcl);

	IPADBG("ip4_flt_hash=%u ip4_flt_nonhash=%u\n",
		ipa3_ctx->ip4_flt_tbl_hash_lcl,
		ipa3_ctx->ip4_flt_tbl_nhash_lcl);

	IPADBG("ip6_flt_hash=%u ip6_flt_nonhash=%u\n",
		ipa3_ctx->ip6_flt_tbl_hash_lcl,
		ipa3_ctx->ip6_flt_tbl_nhash_lcl);

	if (ipa3_ctx->smem_reqd_sz > ipa3_ctx->smem_sz) {
		IPAERR("SW expect more core memory, needed %d, avail %d\n",
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
		IPAERR("failed to create power mgmt wq\n");
		result = -ENOMEM;
		goto fail_init_hw;
	}

	ipa3_ctx->transport_power_mgmt_wq =
		create_singlethread_workqueue("transport_power_mgmt");
	if (!ipa3_ctx->transport_power_mgmt_wq) {
		IPAERR("failed to create transport power mgmt wq\n");
		result = -ENOMEM;
		goto fail_create_transport_wq;
	}

	mutex_init(&ipa3_ctx->transport_pm.transport_pm_mutex);

	/* init the lookaside cache */

	ipa3_ctx->hdr_proc_ctx_offset_cache =
		kmem_cache_create("IPA_HDR_PROC_CTX_OFFSET",
		sizeof(struct ipa3_hdr_proc_ctx_offset_entry), 0, 0, NULL);
	if (!ipa3_ctx->hdr_proc_ctx_offset_cache) {
		IPAERR(":ipa hdr proc ctx off cache create failed\n");
		result = -ENOMEM;
		goto fail_hdr_proc_ctx_offset_cache;
	}

	ipa3_ctx->tx_pkt_wrapper_cache =
	   kmem_cache_create("IPA_TX_PKT_WRAPPER",
			   sizeof(struct ipa3_tx_pkt_wrapper), 0, 0, NULL);
	if (!ipa3_ctx->tx_pkt_wrapper_cache) {
		IPAERR(":ipa tx pkt wrapper cache create failed\n");
		result = -ENOMEM;
		goto fail_tx_pkt_wrapper_cache;
	}
	ipa3_ctx->rx_pkt_wrapper_cache =
	   kmem_cache_create("IPA_RX_PKT_WRAPPER",
			   sizeof(struct ipa3_rx_pkt_wrapper), 0, 0, NULL);
	if (!ipa3_ctx->rx_pkt_wrapper_cache) {
		IPAERR(":ipa rx pkt wrapper cache create failed\n");
		result = -ENOMEM;
		goto fail_rx_pkt_wrapper_cache;
	}

	/* allocate memory for DMA_TASK workaround */
	result = ipa3_allocate_dma_task_for_gsi();
	if (result) {
		IPAERR("failed to allocate dma task\n");
		goto fail_dma_task;
	}

	/* init the various list heads */
	INIT_LIST_HEAD(&ipa3_ctx->hdr_tbl.head_hdr_entry_list);
	for (i = 0; i < IPA_HDR_BIN_MAX; i++) {
		INIT_LIST_HEAD(&ipa3_ctx->hdr_tbl.head_offset_list[i]);
		INIT_LIST_HEAD(&ipa3_ctx->hdr_tbl.head_free_offset_list[i]);
	}
	INIT_LIST_HEAD(&ipa3_ctx->hdr_proc_ctx_tbl.head_proc_ctx_entry_list);
	for (i = 0; i < IPA_HDR_PROC_CTX_BIN_MAX; i++) {
		INIT_LIST_HEAD(&ipa3_ctx->hdr_proc_ctx_tbl.head_offset_list[i]);
		INIT_LIST_HEAD(&ipa3_ctx->
				hdr_proc_ctx_tbl.head_free_offset_list[i]);
	}

	INIT_LIST_HEAD(&ipa3_ctx->intf_list);
	INIT_LIST_HEAD(&ipa3_ctx->msg_list);
	INIT_LIST_HEAD(&ipa3_ctx->pull_msg_list);
	init_waitqueue_head(&ipa3_ctx->msg_waitq);
	mutex_init(&ipa3_ctx->msg_lock);

	mutex_init(&ipa3_ctx->lock);

	idr_init(&ipa3_ctx->ipa_idr);
	spin_lock_init(&ipa3_ctx->idr_lock);

	ipa3_ctx->class = class_create(THIS_MODULE, DRV_NAME);

	result = alloc_chrdev_region(&ipa3_ctx->dev_num, 0, 1, DRV_NAME);
	if (result) {
		IPAERR("alloc_chrdev_region err.\n");
		result = -ENODEV;
		goto fail_alloc_chrdev_region;
	}

	ipa3_ctx->dev = device_create(ipa3_ctx->class, NULL, ipa3_ctx->dev_num,
			ipa3_ctx, DRV_NAME);
	if (IS_ERR(ipa3_ctx->dev)) {
		IPAERR(":device_create err.\n");
		result = -ENODEV;
		goto fail_device_create;
	}

	/* Create a wakeup source. */
	wakeup_source_init(&ipa3_ctx->w_lock, "IPA_WS");
	spin_lock_init(&ipa3_ctx->wakelock_ref_cnt.spinlock);

	result = ipa3_alloc_pkt_init();
	if (result) {
		IPAERR("Failed to alloc pkt_init payload\n");
		result = -ENODEV;
		goto fail_create_apps_resource;
	}

	ipa3_enable_dcd();

	INIT_LIST_HEAD(&ipa3_ctx->ipa_ready_cb_list);

	init_completion(&ipa3_ctx->init_completion_obj);
	init_completion(&ipa3_ctx->uc_loaded_completion_obj);

	cdev_init(&ipa3_ctx->cdev, &ipa3_drv_fops);
	ipa3_ctx->cdev.owner = THIS_MODULE;
	ipa3_ctx->cdev.ops = &ipa3_drv_fops;  /* from LDD3 */

	result = cdev_add(&ipa3_ctx->cdev, ipa3_ctx->dev_num, 1);
	if (result) {
		IPAERR(":cdev_add err=%d\n", -result);
		result = -ENODEV;
		goto fail_cdev_add;
	}
	IPADBG("ipa cdev added successful. major:%d minor:%d\n",
			MAJOR(ipa3_ctx->dev_num),
			MINOR(ipa3_ctx->dev_num));

	return 0;

fail_cdev_add:
fail_create_apps_resource:
	device_destroy(ipa3_ctx->class, ipa3_ctx->dev_num);
fail_device_create:
	unregister_chrdev_region(ipa3_ctx->dev_num, 1);
fail_alloc_chrdev_region:
	ipa3_free_dma_task_for_gsi();
fail_dma_task:
	idr_destroy(&ipa3_ctx->ipa_idr);
fail_rx_pkt_wrapper_cache:
	kmem_cache_destroy(ipa3_ctx->rx_pkt_wrapper_cache);
fail_tx_pkt_wrapper_cache:
	kmem_cache_destroy(ipa3_ctx->tx_pkt_wrapper_cache);
fail_hdr_proc_ctx_offset_cache:
	kmem_cache_destroy(ipa3_ctx->hdr_proc_ctx_offset_cache);
fail_create_transport_wq:
	destroy_workqueue(ipa3_ctx->power_mgmt_wq);
fail_init_hw:
	ipahal_destroy();
fail_ipahal:
	iounmap(ipa3_ctx->mmio);
fail_remap:
	ipa3_disable_clks();
	ipa3_active_clients_log_destroy();
fail_init_active_client:
	if (ipa3_clk)
		clk_put(ipa3_clk);
	ipa3_clk = NULL;
fail_clk:
	msm_bus_scale_unregister_client(ipa3_ctx->ipa_bus_hdl);
fail_bus_reg:
	if (ipa3_bus_scale_table) {
		msm_bus_cl_clear_pdata(ipa3_bus_scale_table);
		ipa3_bus_scale_table = NULL;
	}
fail_init_mem_partition:
fail_bind:
	kfree(ipa3_ctx->ctrl);
fail_mem_ctrl:
	kfree(ipa3_ctx->ipa_tz_unlock_reg);
fail_tz_unlock_reg:
	if (ipa3_ctx->logbuf)
		ipc_log_context_destroy(ipa3_ctx->logbuf);
	kfree(ipa3_ctx);
	ipa3_ctx = NULL;
fail_mem_ctx:
	return result;
}

static int get_ipa_dts_configuration(struct platform_device *pdev,
		struct ipa3_plat_drv_res *ipa_drv_res)
{
	int i, result, pos;
	struct resource *resource;
	u32 *ipa_tz_unlock_reg;
	int elem_num;
	u32 ipa_hw_type = 0;

	/* initialize ipa3_res */
	ipa_drv_res->use_bw_vote = false;
	ipa_drv_res->wan_rx_ring_size = IPA_GENERIC_RX_POOL_SZ;
	ipa_drv_res->lan_rx_ring_size = IPA_GENERIC_RX_POOL_SZ;
	ipa_drv_res->apply_rg10_wa = false;
	ipa_drv_res->gsi_ch20_wa = false;
	ipa_drv_res->ipa_tz_unlock_reg_num = 0;
	ipa_drv_res->ipa_tz_unlock_reg = NULL;

	/* Get IPA HW Version */
	result = of_property_read_u32(pdev->dev.of_node, "qcom,ipa-hw-ver",
					&ipa_hw_type);
	if (result) {
		IPAERR(":get resource failed for ipa-hw-ver!\n");
		return -ENODEV;
	}
	IPADBG(": ipa_hw_type = %d", ipa_hw_type);

	if (ipa_hw_type != IPA_HW_v3_5_1) {
		IPAERR(":only IPA version 3.5.1 supported!\n");
		return -ENODEV;
	}

	/* Get IPA WAN / LAN RX pool size */
	result = of_property_read_u32(pdev->dev.of_node,
			"qcom,wan-rx-ring-size",
			&ipa_drv_res->wan_rx_ring_size);
	if (result)
		IPADBG("using default for wan-rx-ring-size = %u\n",
				ipa_drv_res->wan_rx_ring_size);
	else
		IPADBG(": found ipa_drv_res->wan-rx-ring-size = %u",
				ipa_drv_res->wan_rx_ring_size);

	result = of_property_read_u32(pdev->dev.of_node,
			"qcom,lan-rx-ring-size",
			&ipa_drv_res->lan_rx_ring_size);
	if (result)
		IPADBG("using default for lan-rx-ring-size = %u\n",
			ipa_drv_res->lan_rx_ring_size);
	else
		IPADBG(": found ipa_drv_res->lan-rx-ring-size = %u",
			ipa_drv_res->lan_rx_ring_size);

	ipa_drv_res->use_bw_vote =
			of_property_read_bool(pdev->dev.of_node,
			"qcom,bandwidth-vote-for-ipa");
	IPADBG(": use_bw_vote = %s\n",
			ipa_drv_res->use_bw_vote
			? "True" : "False");

	ipa_drv_res->skip_uc_pipe_reset =
		of_property_read_bool(pdev->dev.of_node,
		"qcom,skip-uc-pipe-reset");
	IPADBG(": skip uC pipe reset = %s\n",
		ipa_drv_res->skip_uc_pipe_reset
		? "True" : "False");

	/* Get IPA wrapper address */
	resource = platform_get_resource_byname(pdev, IORESOURCE_MEM,
			"ipa-base");
	if (!resource) {
		IPAERR(":get resource failed for ipa-base!\n");
		return -ENODEV;
	}
	ipa_drv_res->ipa_mem_base = resource->start;
	ipa_drv_res->ipa_mem_size = resource_size(resource);
	IPADBG(": ipa-base = 0x%x, size = 0x%x\n",
			ipa_drv_res->ipa_mem_base,
			ipa_drv_res->ipa_mem_size);

	smmu_info.ipa_base = ipa_drv_res->ipa_mem_base;
	smmu_info.ipa_size = ipa_drv_res->ipa_mem_size;

	/* Get IPA GSI address */
	resource = platform_get_resource_byname(pdev, IORESOURCE_MEM,
			"gsi-base");
	if (!resource) {
		IPAERR(":get resource failed for gsi-base!\n");
		return -ENODEV;
	}
	ipa_drv_res->gsi_mem_base = resource->start;
	ipa_drv_res->gsi_mem_size = resource_size(resource);
	IPADBG(": gsi-base = 0x%x, size = 0x%x\n",
			ipa_drv_res->gsi_mem_base,
			ipa_drv_res->gsi_mem_size);

	/* Get IPA GSI IRQ number */
	resource = platform_get_resource_byname(pdev, IORESOURCE_IRQ,
			"gsi-irq");
	if (!resource) {
		IPAERR(":get resource failed for gsi-irq!\n");
		return -ENODEV;
	}
	ipa_drv_res->gsi_irq = resource->start;
	IPADBG(": gsi-irq = %d\n", ipa_drv_res->gsi_irq);

	/* Get IPA IRQ number */
	resource = platform_get_resource_byname(pdev, IORESOURCE_IRQ,
			"ipa-irq");
	if (!resource) {
		IPAERR(":get resource failed for ipa-irq!\n");
		return -ENODEV;
	}
	ipa_drv_res->ipa_irq = resource->start;
	IPADBG(":ipa-irq = %d\n", ipa_drv_res->ipa_irq);

	result = of_property_read_u32(pdev->dev.of_node, "qcom,ee",
			&ipa_drv_res->ee);
	if (result)
		ipa_drv_res->ee = 0;

	ipa_drv_res->apply_rg10_wa =
		of_property_read_bool(pdev->dev.of_node,
		"qcom,use-rg10-limitation-mitigation");
	IPADBG(": Use Register Group 10 limitation mitigation = %s\n",
		ipa_drv_res->apply_rg10_wa
		? "True" : "False");

	ipa_drv_res->gsi_ch20_wa =
		of_property_read_bool(pdev->dev.of_node,
		"qcom,do-not-use-ch-gsi-20");
	IPADBG(": GSI CH 20 WA is = %s\n",
		ipa_drv_res->apply_rg10_wa
		? "Needed" : "Not needed");

	elem_num = of_property_count_elems_of_size(pdev->dev.of_node,
		"qcom,ipa-tz-unlock-reg", sizeof(u32));

	if (elem_num > 0 && elem_num % 2 == 0) {
		ipa_drv_res->ipa_tz_unlock_reg_num = elem_num / 2;

		ipa_tz_unlock_reg = kcalloc(elem_num, sizeof(u32), GFP_KERNEL);
		if (ipa_tz_unlock_reg == NULL)
			return -ENOMEM;

		ipa_drv_res->ipa_tz_unlock_reg = kcalloc(
			ipa_drv_res->ipa_tz_unlock_reg_num,
			sizeof(*ipa_drv_res->ipa_tz_unlock_reg),
			GFP_KERNEL);
		if (ipa_drv_res->ipa_tz_unlock_reg == NULL) {
			kfree(ipa_tz_unlock_reg);
			return -ENOMEM;
		}

		if (of_property_read_u32_array(pdev->dev.of_node,
			"qcom,ipa-tz-unlock-reg", ipa_tz_unlock_reg,
			elem_num)) {
			IPAERR("failed to read register addresses\n");
			kfree(ipa_tz_unlock_reg);
			kfree(ipa_drv_res->ipa_tz_unlock_reg);
			return -EFAULT;
		}

		pos = 0;
		for (i = 0; i < ipa_drv_res->ipa_tz_unlock_reg_num; i++) {
			ipa_drv_res->ipa_tz_unlock_reg[i].reg_addr =
				ipa_tz_unlock_reg[pos++];
			ipa_drv_res->ipa_tz_unlock_reg[i].size =
				ipa_tz_unlock_reg[pos++];
			IPADBG("tz unlock reg %d: addr 0x%pa size %d\n", i,
				&ipa_drv_res->ipa_tz_unlock_reg[i].reg_addr,
				ipa_drv_res->ipa_tz_unlock_reg[i].size);
		}
		kfree(ipa_tz_unlock_reg);
	}
	return 0;
}

static int ipa_smmu_uc_cb_probe(struct device *dev)
{
	struct ipa_smmu_cb_ctx *cb = ipa3_get_uc_smmu_ctx();
	int atomic_ctx = 1;
	int bypass = 1;
	int fast = 1;
	int ret;
	u32 iova_ap_mapping[2];

	IPADBG("UC CB PROBE sub pdev=%p\n", dev);

	ret = of_property_read_u32_array(dev->of_node, "qcom,iova-mapping",
			iova_ap_mapping, 2);
	if (ret) {
		IPAERR("Fail to read UC start/size iova addresses\n");
		return ret;
	}
	cb->va_start = iova_ap_mapping[0];
	cb->va_size = iova_ap_mapping[1];
	cb->va_end = cb->va_start + cb->va_size;
	IPADBG("UC va_start=0x%x va_sise=0x%x\n", cb->va_start, cb->va_size);

	if (dma_set_mask(dev, DMA_BIT_MASK(64)) ||
			dma_set_coherent_mask(dev, DMA_BIT_MASK(64))) {
		IPAERR("DMA set 64bit mask failed\n");
		return -EOPNOTSUPP;
	}
	IPADBG("UC CB PROBE=%p create IOMMU mapping\n", dev);

	cb->dev = dev;
	cb->mapping = arm_iommu_create_mapping(dev->bus,
			cb->va_start, cb->va_size);
	if (IS_ERR_OR_NULL(cb->mapping)) {
		IPADBG("Fail to create mapping\n");
		/* assume this failure is because iommu driver is not ready */
		return -EPROBE_DEFER;
	}
	IPADBG("SMMU mapping created\n");
	cb->valid = true;

	IPADBG("UC CB PROBE sub pdev=%p set attribute\n", dev);
	if (smmu_info.s1_bypass) {
		if (iommu_domain_set_attr(cb->mapping->domain,
				DOMAIN_ATTR_S1_BYPASS,
				&bypass)) {
			IPAERR("couldn't set bypass\n");
			arm_iommu_release_mapping(cb->mapping);
			cb->valid = false;
			return -EIO;
		}
		IPADBG("SMMU S1 BYPASS\n");
	} else {
		if (iommu_domain_set_attr(cb->mapping->domain,
				DOMAIN_ATTR_ATOMIC,
				&atomic_ctx)) {
			IPAERR("couldn't set domain as atomic\n");
			arm_iommu_release_mapping(cb->mapping);
			cb->valid = false;
			return -EIO;
		}
		IPADBG("SMMU atomic set\n");

		if (smmu_info.fast_map) {
			if (iommu_domain_set_attr(cb->mapping->domain,
					DOMAIN_ATTR_FAST,
					&fast)) {
				IPAERR("couldn't set fast map\n");
				arm_iommu_release_mapping(cb->mapping);
				cb->valid = false;
				return -EIO;
			}
			IPADBG("SMMU fast map set\n");
		}
	}

	IPADBG("UC CB PROBE sub pdev=%p attaching IOMMU device\n", dev);
	ret = arm_iommu_attach_device(cb->dev, cb->mapping);
	if (ret) {
		IPAERR("could not attach device ret=%d\n", ret);
		arm_iommu_release_mapping(cb->mapping);
		cb->valid = false;
		return ret;
	}

	cb->next_addr = cb->va_end;
	ipa3_ctx->uc_pdev = dev;

	return 0;
}

static int ipa_smmu_ap_cb_probe(struct device *dev)
{
	struct ipa_smmu_cb_ctx *cb = ipa3_get_smmu_ctx();
	int result;
	int atomic_ctx = 1;
	int fast = 1;
	int bypass = 1;
	u32 iova_ap_mapping[2];
	u32 add_map_size;
	const u32 *add_map;
	void *smem_addr;
	int i;

	IPADBG("AP CB probe: sub pdev=%p\n", dev);

	result = of_property_read_u32_array(dev->of_node, "qcom,iova-mapping",
		iova_ap_mapping, 2);
	if (result) {
		IPAERR("Fail to read AP start/size iova addresses\n");
		return result;
	}
	cb->va_start = iova_ap_mapping[0];
	cb->va_size = iova_ap_mapping[1];
	cb->va_end = cb->va_start + cb->va_size;
	IPADBG("AP va_start=0x%x va_sise=0x%x\n", cb->va_start, cb->va_size);

	if (dma_set_mask(dev, DMA_BIT_MASK(64)) ||
			dma_set_coherent_mask(dev, DMA_BIT_MASK(64))) {
		IPAERR("DMA set 64bit mask failed\n");
		return -EOPNOTSUPP;
	}

	cb->dev = dev;
	cb->mapping = arm_iommu_create_mapping(dev->bus,
					cb->va_start, cb->va_size);
	if (IS_ERR_OR_NULL(cb->mapping)) {
		IPADBG("Fail to create mapping\n");
		/* assume this failure is because iommu driver is not ready */
		return -EPROBE_DEFER;
	}
	IPADBG("SMMU mapping created\n");
	cb->valid = true;

	if (smmu_info.s1_bypass) {
		if (iommu_domain_set_attr(cb->mapping->domain,
				DOMAIN_ATTR_S1_BYPASS,
				&bypass)) {
			IPAERR("couldn't set bypass\n");
			arm_iommu_release_mapping(cb->mapping);
			cb->valid = false;
			return -EIO;
		}
		IPADBG("SMMU S1 BYPASS\n");
	} else {
		if (iommu_domain_set_attr(cb->mapping->domain,
				DOMAIN_ATTR_ATOMIC,
				&atomic_ctx)) {
			IPAERR("couldn't set domain as atomic\n");
			arm_iommu_release_mapping(cb->mapping);
			cb->valid = false;
			return -EIO;
		}
		IPADBG("SMMU atomic set\n");

		if (iommu_domain_set_attr(cb->mapping->domain,
				DOMAIN_ATTR_FAST,
				&fast)) {
			IPAERR("couldn't set fast map\n");
			arm_iommu_release_mapping(cb->mapping);
			cb->valid = false;
			return -EIO;
		}
		IPADBG("SMMU fast map set\n");
	}

	result = arm_iommu_attach_device(cb->dev, cb->mapping);
	if (result) {
		IPAERR("couldn't attach to IOMMU ret=%d\n", result);
		cb->valid = false;
		return result;
	}

	add_map = of_get_property(dev->of_node,
		"qcom,additional-mapping", &add_map_size);
	if (add_map) {
		/* mapping size is an array of 3-tuple of u32 */
		if (add_map_size % (3 * sizeof(u32))) {
			IPAERR("wrong additional mapping format\n");
			cb->valid = false;
			return -EFAULT;
		}

		/* iterate of each entry of the additional mapping array */
		for (i = 0; i < add_map_size / sizeof(u32); i += 3) {
			u32 iova = be32_to_cpu(add_map[i]);
			u32 pa = be32_to_cpu(add_map[i + 1]);
			u32 size = be32_to_cpu(add_map[i + 2]);
			unsigned long iova_p;
			phys_addr_t pa_p;
			u32 size_p;

			IPA_SMMU_ROUND_TO_PAGE(iova, pa, size,
				iova_p, pa_p, size_p);
			IPADBG("mapping 0x%lx to 0x%pa size %d\n",
				iova_p, &pa_p, size_p);
			ipa3_iommu_map(cb->mapping->domain,
				iova_p, pa_p, size_p,
				IOMMU_READ | IOMMU_WRITE | IOMMU_MMIO);
		}
	}

	/* map SMEM memory for IPA table accesses */
	smem_addr = smem_alloc(SMEM_IPA_FILTER_TABLE, IPA_SMEM_SIZE,
		SMEM_MODEM, 0);
	if (smem_addr) {
		phys_addr_t iova = smem_virt_to_phys(smem_addr);
		phys_addr_t pa = iova;
		unsigned long iova_p;
		phys_addr_t pa_p;
		u32 size_p;

		IPA_SMMU_ROUND_TO_PAGE(iova, pa, IPA_SMEM_SIZE,
			iova_p, pa_p, size_p);
		IPADBG("mapping 0x%lx to 0x%pa size %d\n",
			iova_p, &pa_p, size_p);
		ipa3_iommu_map(cb->mapping->domain,
			iova_p, pa_p, size_p,
			IOMMU_READ | IOMMU_WRITE | IOMMU_MMIO);
	}


	smmu_info.present = true;

	if (!ipa3_bus_scale_table)
		ipa3_bus_scale_table = msm_bus_cl_get_pdata(ipa3_pdev);

	/* Proceed to real initialization */
	result = ipa3_pre_init(&ipa3_res, dev);
	if (result) {
		IPAERR("ipa_init failed\n");
		arm_iommu_detach_device(cb->dev);
		arm_iommu_release_mapping(cb->mapping);
		cb->valid = false;
		return result;
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

	if (ipa3_ctx == NULL) {
		IPAERR("ipa3_ctx was not initialized\n");
		return -EPROBE_DEFER;
	}
	IPADBG("node->name=%s\n", node->name);
	if (strcmp("qcom,smp2pgpio_map_ipa_1_out", node->name) == 0) {
		res = of_get_gpio(node, 0);
		if (res < 0) {
			IPADBG("of_get_gpio returned %d\n", res);
			return res;
		}

		ipa3_ctx->smp2p_info.out_base_id = res;
		IPADBG("smp2p out_base_id=%d\n",
			ipa3_ctx->smp2p_info.out_base_id);
	} else if (strcmp("qcom,smp2pgpio_map_ipa_1_in", node->name) == 0) {
		int irq;

		res = of_get_gpio(node, 0);
		if (res < 0) {
			IPADBG("of_get_gpio returned %d\n", res);
			return res;
		}

		ipa3_ctx->smp2p_info.in_base_id = res;
		IPADBG("smp2p in_base_id=%d\n",
			ipa3_ctx->smp2p_info.in_base_id);

		/* register for modem clk query */
		irq = gpio_to_irq(ipa3_ctx->smp2p_info.in_base_id +
			IPA_GPIO_IN_QUERY_CLK_IDX);
		if (irq < 0) {
			IPAERR("gpio_to_irq failed %d\n", irq);
			return -ENODEV;
		}
		IPADBG("smp2p irq#=%d\n", irq);
		res = request_irq(irq,
			(irq_handler_t)ipa3_smp2p_modem_clk_query_isr,
			IRQF_TRIGGER_RISING, "ipa_smp2p_clk_vote", dev);
		if (res) {
			IPAERR("fail to register smp2p irq=%d\n", irq);
			return -ENODEV;
		}
		res = enable_irq_wake(ipa3_ctx->smp2p_info.in_base_id +
			IPA_GPIO_IN_QUERY_CLK_IDX);
		if (res)
			IPAERR("failed to enable irq wake\n");
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
	int result;
	struct device *dev = &pdev_p->dev;

	IPADBG("IPA driver probing started\n");
	IPADBG("dev->of_node->name = %s\n", dev->of_node->name);

	if (of_device_is_compatible(dev->of_node, "qcom,ipa-smmu-ap-cb"))
		return ipa_smmu_ap_cb_probe(dev);

	if (of_device_is_compatible(dev->of_node, "qcom,ipa-smmu-uc-cb"))
		return ipa_smmu_uc_cb_probe(dev);

	if (of_device_is_compatible(dev->of_node,
	    "qcom,smp2pgpio-map-ipa-1-in"))
		return ipa3_smp2p_probe(dev);

	if (of_device_is_compatible(dev->of_node,
	    "qcom,smp2pgpio-map-ipa-1-out"))
		return ipa3_smp2p_probe(dev);

	result = msm_gsi_init(pdev_p);
	if (result) {
		pr_err("ipa: error initializing gsi driver.\n");
		return result;
	}

	master_dev = dev;
	if (!ipa3_pdev)
		ipa3_pdev = pdev_p;

	result = get_ipa_dts_configuration(pdev_p, &ipa3_res);
	if (result) {
		IPAERR("IPA dts parsing failed\n");
		return result;
	}

	/* The SDM845 has an SMMU, and uses the ARM SMMU driver */
	if (of_property_read_bool(pdev_p->dev.of_node, "qcom,smmu-s1-bypass"))
		smmu_info.s1_bypass = true;
	if (of_property_read_bool(pdev_p->dev.of_node, "qcom,smmu-fast-map"))
		smmu_info.fast_map = true;
	pr_info("IPA smmu_info.s1_bypass=%d smmu_info.fast_map=%d\n",
		smmu_info.s1_bypass, smmu_info.fast_map);

	result = of_platform_populate(pdev_p->dev.of_node,
		ipa_plat_drv_match, NULL, &pdev_p->dev);
	if (result) {
		IPAERR("failed to populate platform\n");
		return result;
	}

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

	IPADBG("Enter...\n");

	/* In case there is a tx/rx handler in polling mode fail to suspend */
	for (i = 0; i < ipa3_ctx->ipa_num_pipes; i++) {
		if (ipa3_ctx->ep[i].sys &&
			atomic_read(&ipa3_ctx->ep[i].sys->curr_polling_state)) {
			IPAERR("EP %d is in polling state, do not suspend\n",
				i);
			return -EAGAIN;
		}
	}

	/*
	 * Release transport IPA resource without waiting for inactivity timer
	 */
	atomic_set(&ipa3_ctx->transport_pm.eot_activity, 0);
	//ipa3_disable_clks();
	IPADBG("Exit\n");

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

struct ipa3_context *ipa3_get_ctx(void)
{
	return ipa3_ctx;
}

static void ipa_gsi_notify_cb(struct gsi_per_notify *notify)
{
	switch (notify->evt_id) {
	case GSI_PER_EVT_GLOB_ERROR:
		IPAERR("Got GSI_PER_EVT_GLOB_ERROR\n");
		IPAERR("Err_desc = 0x%04x\n", notify->data.err_desc);
		break;
	case GSI_PER_EVT_GLOB_GP1:
		IPAERR("Got GSI_PER_EVT_GLOB_GP1\n");
		BUG();
		break;
	case GSI_PER_EVT_GLOB_GP2:
		IPAERR("Got GSI_PER_EVT_GLOB_GP2\n");
		BUG();
		break;
	case GSI_PER_EVT_GLOB_GP3:
		IPAERR("Got GSI_PER_EVT_GLOB_GP3\n");
		BUG();
		break;
	case GSI_PER_EVT_GENERAL_BREAK_POINT:
		IPAERR("Got GSI_PER_EVT_GENERAL_BREAK_POINT\n");
		break;
	case GSI_PER_EVT_GENERAL_BUS_ERROR:
		IPAERR("Got GSI_PER_EVT_GENERAL_BUS_ERROR\n");
		BUG();
		break;
	case GSI_PER_EVT_GENERAL_CMD_FIFO_OVERFLOW:
		IPAERR("Got GSI_PER_EVT_GENERAL_CMD_FIFO_OVERFLOW\n");
		BUG();
		break;
	case GSI_PER_EVT_GENERAL_MCS_STACK_OVERFLOW:
		IPAERR("Got GSI_PER_EVT_GENERAL_MCS_STACK_OVERFLOW\n");
		BUG();
		break;
	default:
		IPAERR("Received unexpected evt: %d\n",
			notify->evt_id);
		BUG();
	}
}

int ipa3_register_ipa_ready_cb(void (*ipa_ready_cb)(void *), void *user_data)
{
	struct ipa3_ready_cb_info *cb_info = NULL;

	/* check ipa3_ctx existed or not */
	if (!ipa3_ctx) {
		IPADBG("IPA driver has't initialized\n");
		return -ENXIO;
	}
	mutex_lock(&ipa3_ctx->lock);
	if (ipa3_ctx->ipa_initialization_complete) {
		mutex_unlock(&ipa3_ctx->lock);
		IPADBG("IPA driver finished initialization already\n");
		return -EEXIST;
	}

	cb_info = kmalloc(sizeof(struct ipa3_ready_cb_info), GFP_KERNEL);
	if (!cb_info) {
		mutex_unlock(&ipa3_ctx->lock);
		return -ENOMEM;
	}

	cb_info->ready_cb = ipa_ready_cb;
	cb_info->user_data = user_data;

	list_add_tail(&cb_info->link, &ipa3_ctx->ipa_ready_cb_list);
	mutex_unlock(&ipa3_ctx->lock);

	return 0;
}

int ipa3_iommu_map(struct iommu_domain *domain,
	unsigned long iova, phys_addr_t paddr, size_t size, int prot)
{
	struct ipa_smmu_cb_ctx *ap_cb = ipa3_get_smmu_ctx();
	struct ipa_smmu_cb_ctx *uc_cb = ipa3_get_uc_smmu_ctx();

	IPADBG("domain =0x%p iova 0x%lx\n", domain, iova);
	IPADBG("paddr =0x%pa size 0x%x\n", &paddr, (u32)size);

	/* make sure no overlapping */
	if (domain == ipa3_get_smmu_domain()) {
		if (iova >= ap_cb->va_start && iova < ap_cb->va_end) {
			IPAERR("iommu AP overlap addr 0x%lx\n", iova);
			ipa_assert();
			return -EFAULT;
		}
	} else if (domain == ipa3_get_uc_smmu_domain()) {
		if (iova >= uc_cb->va_start && iova < uc_cb->va_end) {
			IPAERR("iommu uC overlap addr 0x%lx\n", iova);
			ipa_assert();
			return -EFAULT;
		}
	} else {
		IPAERR("Unexpected domain 0x%p\n", domain);
		ipa_assert();
		return -EFAULT;
	}

	return iommu_map(domain, iova, paddr, size, prot);
}

static int ipa3_q6_clean_q6_flt_tbls(enum ipa_ip_type ip,
        enum ipa_rule_type rlt)
{
        struct ipa3_desc *desc;
        struct ipahal_imm_cmd_dma_shared_mem cmd = {0};
        struct ipahal_imm_cmd_pyld **cmd_pyld;
        int retval = 0;
        int pipe_idx;
        int flt_idx = 0;
        int num_cmds = 0;
        int index;
        u32 lcl_addr_mem_part;
        u32 lcl_hdr_sz;
        struct ipa_mem_buffer mem;

        IPADBG("Entry\n");

        if ((ip >= IPA_IP_MAX) || (rlt >= IPA_RULE_TYPE_MAX)) {
                IPAERR("Input Err: ip=%d ; rlt=%d\n", ip, rlt);
                return -EINVAL;
        }

        /* Up to filtering pipes we have filtering tables */
        desc = kcalloc(ipa3_ctx->ep_flt_num, sizeof(struct ipa3_desc),
                GFP_KERNEL);
        if (!desc) {
                IPAERR("failed to allocate memory\n");
                return -ENOMEM;
        }

        cmd_pyld = kcalloc(ipa3_ctx->ep_flt_num,
                sizeof(struct ipahal_imm_cmd_pyld *), GFP_KERNEL);
        if (!cmd_pyld) {
                IPAERR("failed to allocate memory\n");
                retval = -ENOMEM;
                goto free_desc;
        }

        if (ip == IPA_IP_v4) {
                if (rlt == IPA_RULE_HASHABLE) {
                        lcl_addr_mem_part = IPA_MEM_PART(v4_flt_hash_ofst);
                        lcl_hdr_sz = IPA_MEM_PART(v4_flt_hash_size);
                } else {
                        lcl_addr_mem_part = IPA_MEM_PART(v4_flt_nhash_ofst);
                        lcl_hdr_sz = IPA_MEM_PART(v4_flt_nhash_size);
                }
        } else {
                if (rlt == IPA_RULE_HASHABLE) {
                        lcl_addr_mem_part = IPA_MEM_PART(v6_flt_hash_ofst);
                        lcl_hdr_sz = IPA_MEM_PART(v6_flt_hash_size);
                } else {
                        lcl_addr_mem_part = IPA_MEM_PART(v6_flt_nhash_ofst);
                        lcl_hdr_sz = IPA_MEM_PART(v6_flt_nhash_size);
                }
        }

        retval = ipahal_flt_generate_empty_img(1, lcl_hdr_sz, lcl_hdr_sz,
                0, &mem, true);
        if (retval) {
                IPAERR("failed to generate flt single tbl empty img\n");
                goto free_cmd_pyld;
        }

        for (pipe_idx = 0; pipe_idx < ipa3_ctx->ipa_num_pipes; pipe_idx++) {
                if (!ipa_is_ep_support_flt(pipe_idx))
                        continue;

                /*
                 * Iterating over all the filtering pipes which are either
                 * invalid but connected or connected but not configured by AP.
                 */
		if (!ipa3_ctx->ep[pipe_idx].valid ||
                    ipa3_ctx->ep[pipe_idx].skip_ep_cfg) {

                        cmd.is_read = false;
                        cmd.skip_pipeline_clear = false;
                        cmd.pipeline_clear_options = IPAHAL_HPS_CLEAR;
                        cmd.size = mem.size;
                        cmd.system_addr = mem.phys_base;
                        cmd.local_addr =
                                ipa3_ctx->smem_restricted_bytes +
                                lcl_addr_mem_part +
                                ipahal_get_hw_tbl_hdr_width() +
                                flt_idx * ipahal_get_hw_tbl_hdr_width();
                        cmd_pyld[num_cmds] = ipahal_construct_imm_cmd(
                                IPA_IMM_CMD_DMA_SHARED_MEM, &cmd, false);
                        if (!cmd_pyld[num_cmds]) {
                                IPAERR("fail construct dma_shared_mem cmd\n");
                                retval = -ENOMEM;
                                goto free_empty_img;
                        }
                        desc[num_cmds].opcode = cmd_pyld[num_cmds]->opcode;
                        desc[num_cmds].pyld = cmd_pyld[num_cmds]->data;
                        desc[num_cmds].len = cmd_pyld[num_cmds]->len;
                        desc[num_cmds].type = IPA_IMM_CMD_DESC;
                        num_cmds++;
                }

                flt_idx++;
        }

        IPADBG("Sending %d descriptors for flt tbl clearing\n", num_cmds);
        retval = ipa3_send_cmd(num_cmds, desc);
        if (retval) {
                IPAERR("failed to send immediate command (err %d)\n", retval);
                retval = -EFAULT;
        }

free_empty_img:
        ipahal_free_dma_mem(&mem);
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
        struct ipahal_imm_cmd_dma_shared_mem cmd = {0};
        struct ipahal_imm_cmd_pyld *cmd_pyld = NULL;
        int retval = 0;
        u32 modem_rt_index_lo;
        u32 modem_rt_index_hi;
        u32 lcl_addr_mem_part;
        u32 lcl_hdr_sz;
        struct ipa_mem_buffer mem;

        IPADBG("Entry\n");

        if ((ip >= IPA_IP_MAX) || (rlt >= IPA_RULE_TYPE_MAX)) {
                IPAERR("Input Err: ip=%d ; rlt=%d\n", ip, rlt);
                return -EINVAL;
        }

        if (ip == IPA_IP_v4) {
                modem_rt_index_lo = IPA_MEM_PART(v4_modem_rt_index_lo);
                modem_rt_index_hi = IPA_MEM_PART(v4_modem_rt_index_hi);
                if (rlt == IPA_RULE_HASHABLE) {
                        lcl_addr_mem_part = IPA_MEM_PART(v4_rt_hash_ofst);
                        lcl_hdr_sz =  IPA_MEM_PART(v4_flt_hash_size);
                } else {
                        lcl_addr_mem_part = IPA_MEM_PART(v4_rt_nhash_ofst);
                        lcl_hdr_sz = IPA_MEM_PART(v4_flt_nhash_size);
                }
        } else {
                modem_rt_index_lo = IPA_MEM_PART(v6_modem_rt_index_lo);
                modem_rt_index_hi = IPA_MEM_PART(v6_modem_rt_index_hi);
                if (rlt == IPA_RULE_HASHABLE) {
                        lcl_addr_mem_part = IPA_MEM_PART(v6_rt_hash_ofst);
                        lcl_hdr_sz =  IPA_MEM_PART(v6_flt_hash_size);
                } else {
                        lcl_addr_mem_part = IPA_MEM_PART(v6_rt_nhash_ofst);
                        lcl_hdr_sz = IPA_MEM_PART(v6_flt_nhash_size);
                }
        }

        retval = ipahal_rt_generate_empty_img(
                modem_rt_index_hi - modem_rt_index_lo + 1,
                lcl_hdr_sz, lcl_hdr_sz, &mem, true);
        if (retval) {
                IPAERR("fail generate empty rt img\n");
                return -ENOMEM;
        }

        desc = kzalloc(sizeof(struct ipa3_desc), GFP_KERNEL);
        if (!desc) {
                IPAERR("failed to allocate memory\n");
                goto free_empty_img;
        }

        cmd.is_read = false;
        cmd.skip_pipeline_clear = false;
        cmd.pipeline_clear_options = IPAHAL_HPS_CLEAR;
        cmd.size = mem.size;
        cmd.system_addr =  mem.phys_base;
        cmd.local_addr = ipa3_ctx->smem_restricted_bytes +
                lcl_addr_mem_part +
                modem_rt_index_lo * ipahal_get_hw_tbl_hdr_width();
        cmd_pyld = ipahal_construct_imm_cmd(
                        IPA_IMM_CMD_DMA_SHARED_MEM, &cmd, false);
        if (!cmd_pyld) {
                IPAERR("failed to construct dma_shared_mem imm cmd\n");
                retval = -ENOMEM;
                goto free_desc;
        }
	desc->opcode = cmd_pyld->opcode;
        desc->pyld = cmd_pyld->data;
        desc->len = cmd_pyld->len;
        desc->type = IPA_IMM_CMD_DESC;

        IPADBG("Sending 1 descriptor for rt tbl clearing\n");
        retval = ipa3_send_cmd(1, desc);
        if (retval) {
                IPAERR("failed to send immediate command (err %d)\n", retval);
                retval = -EFAULT;
        }

        ipahal_destroy_imm_cmd(cmd_pyld);
free_desc:
        kfree(desc);
free_empty_img:
        ipahal_free_dma_mem(&mem);
        return retval;
}


static int ipa3_q6_clean_q6_tables(void)
{
        struct ipa3_desc *desc;
        struct ipahal_imm_cmd_pyld *cmd_pyld = NULL;
        struct ipahal_imm_cmd_register_write reg_write_cmd = {0};
        int retval;
        struct ipahal_reg_fltrt_hash_flush flush;
        struct ipahal_reg_valmask valmask;

        IPADBG("Entry\n");


        if (ipa3_q6_clean_q6_flt_tbls(IPA_IP_v4, IPA_RULE_HASHABLE)) {
                IPAERR("failed to clean q6 flt tbls (v4/hashable)\n");
                return -EFAULT;
        }
        if (ipa3_q6_clean_q6_flt_tbls(IPA_IP_v6, IPA_RULE_HASHABLE)) {
                IPAERR("failed to clean q6 flt tbls (v6/hashable)\n");
                return -EFAULT;
        }
        if (ipa3_q6_clean_q6_flt_tbls(IPA_IP_v4, IPA_RULE_NON_HASHABLE)) {
                IPAERR("failed to clean q6 flt tbls (v4/non-hashable)\n");
                return -EFAULT;
        }
        if (ipa3_q6_clean_q6_flt_tbls(IPA_IP_v6, IPA_RULE_NON_HASHABLE)) {
                IPAERR("failed to clean q6 flt tbls (v6/non-hashable)\n");
                return -EFAULT;
        }

        if (ipa3_q6_clean_q6_rt_tbls(IPA_IP_v4, IPA_RULE_HASHABLE)) {
                IPAERR("failed to clean q6 rt tbls (v4/hashable)\n");
                return -EFAULT;
        }
        if (ipa3_q6_clean_q6_rt_tbls(IPA_IP_v6, IPA_RULE_HASHABLE)) {
                IPAERR("failed to clean q6 rt tbls (v6/hashable)\n");
                return -EFAULT;
        }
        if (ipa3_q6_clean_q6_rt_tbls(IPA_IP_v4, IPA_RULE_NON_HASHABLE)) {
                IPAERR("failed to clean q6 rt tbls (v4/non-hashable)\n");
                return -EFAULT;
        }
        if (ipa3_q6_clean_q6_rt_tbls(IPA_IP_v6, IPA_RULE_NON_HASHABLE)) {
                IPAERR("failed to clean q6 rt tbls (v6/non-hashable)\n");
                return -EFAULT;
        }

        /* Flush rules cache */
        desc = kzalloc(sizeof(struct ipa3_desc), GFP_KERNEL);
        if (!desc) {
                IPAERR("failed to allocate memory\n");
                return -ENOMEM;
        }

        flush.v4_flt = true;
        flush.v4_rt = true;
        flush.v6_flt = true;
        flush.v6_rt = true;
        ipahal_get_fltrt_hash_flush_valmask(&flush, &valmask);
        reg_write_cmd.skip_pipeline_clear = false;
        reg_write_cmd.pipeline_clear_options = IPAHAL_HPS_CLEAR;
        reg_write_cmd.offset = ipahal_get_reg_ofst(IPA_FILT_ROUT_HASH_FLUSH);
        reg_write_cmd.value = valmask.val;
        reg_write_cmd.value_mask = valmask.mask;
        cmd_pyld = ipahal_construct_imm_cmd(IPA_IMM_CMD_REGISTER_WRITE,
                &reg_write_cmd, false);
        if (!cmd_pyld) {
                IPAERR("fail construct register_write imm cmd\n");
                retval = -EFAULT;
                goto bail_desc;
        }

        desc->opcode = cmd_pyld->opcode;
		desc->pyld = cmd_pyld->data;
        desc->len = cmd_pyld->len;
        desc->type = IPA_IMM_CMD_DESC;

        IPADBG("Sending 1 descriptor for tbls flush\n");
        retval = ipa3_send_cmd(1, desc);
        if (retval) {
                IPAERR("failed to send immediate command (err %d)\n", retval);
                retval = -EFAULT;
        }

        ipahal_destroy_imm_cmd(cmd_pyld);

bail_desc:
        kfree(desc);
        IPADBG("Done - retval = %d\n", retval);
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
	pr_debug("IPA module init\n");

	/* Register as a platform device driver */
	return platform_driver_register(&ipa_plat_drv);
}
subsys_initcall(ipa_module_init);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("IPA HW device driver");
