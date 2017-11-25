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

#ifdef CONFIG_DEBUG_FS

#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/stringify.h>
#include "ipa_i.h"

#define IPA_MAX_MSG_LEN 4096
#define IPA_DBG_ACTIVE_CLIENT_BUF_SIZE ((IPA3_ACTIVE_CLIENTS_LOG_LINE_LEN \
	* IPA3_ACTIVE_CLIENTS_LOG_BUFFER_SIZE_LINES) + IPA_MAX_MSG_LEN)

#define IPA_DUMP_STATUS_FIELD(f) \
	pr_err(#f "=0x%x\n", status->f)

const char *ipa3_event_name[] = {
	__stringify(IPA_SSR_BEFORE_SHUTDOWN),
	__stringify(IPA_SSR_AFTER_POWERUP)
};

static struct dentry *dfile_gen_reg;
static struct dentry *dfile_ep_reg;
static struct dentry *dfile_keep_awake;
static struct dentry *dfile_ep_holb;
static struct dentry *dfile_stats;
static struct dentry *dfile_dbg_cnt;
static struct dentry *dfile_msg;
static struct dentry *dfile_status_stats;
static struct dentry *dfile_active_clients;
static char dbg_buff[IPA_MAX_MSG_LEN];
static char *active_clients_buf;

static s8 ep_reg_idx;
static void *ipa_ipc_low_buff;


static ssize_t ipa3_read_gen_reg(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	int nbytes;
	struct ipahal_reg_shared_mem_size smem_sz;

	memset(&smem_sz, 0, sizeof(smem_sz));

	IPA_ACTIVE_CLIENTS_INC_SIMPLE();

	ipahal_read_reg_fields(IPA_SHARED_MEM_SIZE, &smem_sz);
	nbytes = scnprintf(dbg_buff, IPA_MAX_MSG_LEN,
			"IPA_VERSION=0x%x\n"
			"IPA_COMP_HW_VERSION=0x%x\n"
			"IPA_ROUTE=0x%x\n"
			"IPA_SHARED_MEM_RESTRICTED=0x%x\n"
			"IPA_SHARED_MEM_SIZE=0x%x\n",
			ipahal_read_reg(IPA_VERSION),
			ipahal_read_reg(IPA_COMP_HW_VERSION),
			ipahal_read_reg(IPA_ROUTE),
			smem_sz.shared_mem_baddr,
			smem_sz.shared_mem_sz);

	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();

	return simple_read_from_buffer(ubuf, count, ppos, dbg_buff, nbytes);
}

static ssize_t ipa3_write_ep_holb(struct file *file,
		const char __user *buf, size_t count, loff_t *ppos)
{
	struct ipa_ep_cfg_holb holb;
	u32 en;
	u32 tmr_val;
	u32 ep_idx;
	unsigned long missing;
	char *sptr, *token;

	if (sizeof(dbg_buff) < count + 1)
		return -EFAULT;

	missing = copy_from_user(dbg_buff, buf, count);
	if (missing)
		return -EFAULT;

	dbg_buff[count] = '\0';

	sptr = dbg_buff;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &ep_idx))
		return -EINVAL;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &en))
		return -EINVAL;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &tmr_val))
		return -EINVAL;

	holb.en = en;
	holb.tmr_val = tmr_val;

	ipa3_cfg_ep_holb(ep_idx, &holb);

	return count;
}

static ssize_t ipa3_write_ep_reg(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	unsigned long missing;
	s8 option = 0;

	if (sizeof(dbg_buff) < count + 1)
		return -EFAULT;

	missing = copy_from_user(dbg_buff, buf, count);
	if (missing)
		return -EFAULT;

	dbg_buff[count] = '\0';
	if (kstrtos8(dbg_buff, 0, &option))
		return -EFAULT;

	if (option >= ipa3_ctx->ipa_num_pipes) {
		IPAERR("bad pipe specified %u\n", option);
		return count;
	}

	ep_reg_idx = option;

	return count;
}

/**
 * _ipa_read_ep_reg_v3_0() - Reads and prints endpoint configuration registers
 *
 * Returns the number of characters printed
 */
int _ipa_read_ep_reg_v3_0(char *buf, int max_len, int pipe)
{
	return scnprintf(
		dbg_buff, IPA_MAX_MSG_LEN,
		"IPA_ENDP_INIT_NAT_%u=0x%x\n"
		"IPA_ENDP_INIT_HDR_%u=0x%x\n"
		"IPA_ENDP_INIT_HDR_EXT_%u=0x%x\n"
		"IPA_ENDP_INIT_MODE_%u=0x%x\n"
		"IPA_ENDP_INIT_AGGR_%u=0x%x\n"
		"IPA_ENDP_INIT_ROUTE_%u=0x%x\n"
		"IPA_ENDP_INIT_CTRL_%u=0x%x\n"
		"IPA_ENDP_INIT_HOL_EN_%u=0x%x\n"
		"IPA_ENDP_INIT_HOL_TIMER_%u=0x%x\n"
		"IPA_ENDP_INIT_DEAGGR_%u=0x%x\n"
		"IPA_ENDP_INIT_CFG_%u=0x%x\n",
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_NAT_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_HDR_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_HDR_EXT_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_MODE_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_AGGR_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_ROUTE_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_CTRL_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_HOL_BLOCK_EN_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_HOL_BLOCK_TIMER_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_DEAGGR_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_CFG_n, pipe));
}

/**
 * _ipa_read_ep_reg_v4_0() - Reads and prints endpoint configuration registers
 *
 * Returns the number of characters printed
 * Removed IPA_ENDP_INIT_ROUTE_n from v3
 */
int _ipa_read_ep_reg_v4_0(char *buf, int max_len, int pipe)
{
	return scnprintf(
		dbg_buff, IPA_MAX_MSG_LEN,
		"IPA_ENDP_INIT_NAT_%u=0x%x\n"
		"IPA_ENDP_INIT_CONN_TRACK_n%u=0x%x\n"
		"IPA_ENDP_INIT_HDR_%u=0x%x\n"
		"IPA_ENDP_INIT_HDR_EXT_%u=0x%x\n"
		"IPA_ENDP_INIT_MODE_%u=0x%x\n"
		"IPA_ENDP_INIT_AGGR_%u=0x%x\n"
		"IPA_ENDP_INIT_CTRL_%u=0x%x\n"
		"IPA_ENDP_INIT_HOL_EN_%u=0x%x\n"
		"IPA_ENDP_INIT_HOL_TIMER_%u=0x%x\n"
		"IPA_ENDP_INIT_DEAGGR_%u=0x%x\n"
		"IPA_ENDP_INIT_CFG_%u=0x%x\n",
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_NAT_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_CONN_TRACK_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_HDR_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_HDR_EXT_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_MODE_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_AGGR_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_CTRL_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_HOL_BLOCK_EN_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_HOL_BLOCK_TIMER_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_DEAGGR_n, pipe),
		pipe, ipahal_read_reg_n(IPA_ENDP_INIT_CFG_n, pipe));
}

static ssize_t ipa3_read_ep_reg(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	int nbytes;
	int i;
	int start_idx;
	int end_idx;
	int size = 0;
	int ret;
	loff_t pos;

	/* negative ep_reg_idx means all registers */
	if (ep_reg_idx < 0) {
		start_idx = 0;
		end_idx = ipa3_ctx->ipa_num_pipes;
	} else {
		start_idx = ep_reg_idx;
		end_idx = start_idx + 1;
	}
	pos = *ppos;
	IPA_ACTIVE_CLIENTS_INC_SIMPLE();
	for (i = start_idx; i < end_idx; i++) {

		nbytes = ipa3_ctx->ctrl->ipa3_read_ep_reg(dbg_buff,
				IPA_MAX_MSG_LEN, i);

		*ppos = pos;
		ret = simple_read_from_buffer(ubuf, count, ppos, dbg_buff,
					      nbytes);
		if (ret < 0) {
			IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
			return ret;
		}

		size += ret;
		ubuf += nbytes;
		count -= nbytes;
	}
	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();

	*ppos = pos + size;
	return size;
}

static ssize_t ipa3_write_keep_awake(struct file *file, const char __user *buf,
	size_t count, loff_t *ppos)
{
	unsigned long missing;
	s8 option = 0;

	if (sizeof(dbg_buff) < count + 1)
		return -EFAULT;

	missing = copy_from_user(dbg_buff, buf, count);
	if (missing)
		return -EFAULT;

	dbg_buff[count] = '\0';
	if (kstrtos8(dbg_buff, 0, &option))
		return -EFAULT;

	if (option == 1)
		IPA_ACTIVE_CLIENTS_INC_SIMPLE();
	else if (option == 0)
		IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
	else
		return -EFAULT;

	return count;
}

static ssize_t ipa3_read_keep_awake(struct file *file, char __user *ubuf,
	size_t count, loff_t *ppos)
{
	int nbytes;

	mutex_lock(&ipa3_ctx->ipa3_active_clients.mutex);
	if (atomic_read(&ipa3_ctx->ipa3_active_clients.cnt))
		nbytes = scnprintf(dbg_buff, IPA_MAX_MSG_LEN,
				"IPA APPS power state is ON\n");
	else
		nbytes = scnprintf(dbg_buff, IPA_MAX_MSG_LEN,
				"IPA APPS power state is OFF\n");
	mutex_unlock(&ipa3_ctx->ipa3_active_clients.mutex);

	return simple_read_from_buffer(ubuf, count, ppos, dbg_buff, nbytes);
}

static ssize_t ipa3_read_stats(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	int nbytes;
	int i;
	int cnt = 0;
	uint connect = 0;

	for (i = 0; i < ipa3_ctx->ipa_num_pipes; i++)
		connect |= (ipa3_ctx->ep[i].valid << i);

	nbytes = scnprintf(dbg_buff, IPA_MAX_MSG_LEN,
		"sw_tx=%u\n"
		"hw_tx=%u\n"
		"tx_non_linear=%u\n"
		"tx_compl=%u\n"
		"wan_rx=%u\n"
		"stat_compl=%u\n"
		"lan_aggr_close=%u\n"
		"wan_aggr_close=%u\n"
		"act_clnt=%u\n"
		"con_clnt_bmap=0x%x\n"
		"wan_rx_empty=%u\n"
		"wan_repl_rx_empty=%u\n"
		"lan_rx_empty=%u\n"
		"lan_repl_rx_empty=%u\n"
		"flow_enable=%u\n"
		"flow_disable=%u\n",
		ipa3_ctx->stats.tx_sw_pkts,
		ipa3_ctx->stats.tx_hw_pkts,
		ipa3_ctx->stats.tx_non_linear,
		ipa3_ctx->stats.tx_pkts_compl,
		ipa3_ctx->stats.rx_pkts,
		ipa3_ctx->stats.stat_compl,
		ipa3_ctx->stats.aggr_close,
		ipa3_ctx->stats.wan_aggr_close,
		atomic_read(&ipa3_ctx->ipa3_active_clients.cnt),
		connect,
		ipa3_ctx->stats.wan_rx_empty,
		ipa3_ctx->stats.wan_repl_rx_empty,
		ipa3_ctx->stats.lan_rx_empty,
		ipa3_ctx->stats.lan_repl_rx_empty,
		ipa3_ctx->stats.flow_enable,
		ipa3_ctx->stats.flow_disable);
	cnt += nbytes;

	for (i = 0; i < IPAHAL_PKT_STATUS_EXCEPTION_MAX; i++) {
		nbytes = scnprintf(dbg_buff + cnt,
			IPA_MAX_MSG_LEN - cnt,
			"lan_rx_excp[%u:%20s]=%u\n", i,
			ipahal_pkt_status_exception_str(i),
			ipa3_ctx->stats.rx_excp_pkts[i]);
		cnt += nbytes;
	}

	return simple_read_from_buffer(ubuf, count, ppos, dbg_buff, cnt);
}

static ssize_t ipa3_write_dbg_cnt(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	unsigned long missing;
	u32 option = 0;
	struct ipahal_reg_debug_cnt_ctrl dbg_cnt_ctrl;

	if (ipa3_ctx->ipa_hw_type >= IPA_HW_v4_0) {
		IPAERR("IPA_DEBUG_CNT_CTRL is not supported in IPA 4.0\n");
		return -EPERM;
	}

	if (sizeof(dbg_buff) < count + 1)
		return -EFAULT;

	missing = copy_from_user(dbg_buff, buf, count);
	if (missing)
		return -EFAULT;

	dbg_buff[count] = '\0';
	if (kstrtou32(dbg_buff, 0, &option))
		return -EFAULT;

	memset(&dbg_cnt_ctrl, 0, sizeof(dbg_cnt_ctrl));
	dbg_cnt_ctrl.type = DBG_CNT_TYPE_GENERAL;
	dbg_cnt_ctrl.product = true;
	dbg_cnt_ctrl.src_pipe = 0xff;
	dbg_cnt_ctrl.rule_idx_pipe_rule = false;
	dbg_cnt_ctrl.rule_idx = 0;
	if (option == 1)
		dbg_cnt_ctrl.en = true;
	else
		dbg_cnt_ctrl.en = false;

	IPA_ACTIVE_CLIENTS_INC_SIMPLE();
	ipahal_write_reg_n_fields(IPA_DEBUG_CNT_CTRL_n, 0, &dbg_cnt_ctrl);
	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();

	return count;
}

static ssize_t ipa3_read_dbg_cnt(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	int nbytes;
	u32 regval;

	if (ipa3_ctx->ipa_hw_type >= IPA_HW_v4_0) {
		IPAERR("IPA_DEBUG_CNT_REG is not supported in IPA 4.0\n");
		return -EPERM;
	}

	IPA_ACTIVE_CLIENTS_INC_SIMPLE();
	regval =
		ipahal_read_reg_n(IPA_DEBUG_CNT_REG_n, 0);
	nbytes = scnprintf(dbg_buff, IPA_MAX_MSG_LEN,
			"IPA_DEBUG_CNT_REG_0=0x%x\n", regval);
	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();

	return simple_read_from_buffer(ubuf, count, ppos, dbg_buff, nbytes);
}

static ssize_t ipa3_read_msg(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	int nbytes;
	int cnt = 0;
	int i;
	for (i = 0; i < IPA_EVENT_MAX_NUM; i++) {
		nbytes = scnprintf(dbg_buff + cnt, IPA_MAX_MSG_LEN - cnt,
				"msg[%u:%27s] W:%u R:%u\n", i,
				ipa3_event_name[i],
				ipa3_ctx->stats.msg_w[i],
				ipa3_ctx->stats.msg_r[i]);
		cnt += nbytes;
	}

	return simple_read_from_buffer(ubuf, count, ppos, dbg_buff, cnt);
}

static void ipa_dump_status(struct ipahal_pkt_status *status)
{
	IPA_DUMP_STATUS_FIELD(status_opcode);
	IPA_DUMP_STATUS_FIELD(exception);
	IPA_DUMP_STATUS_FIELD(status_mask);
	IPA_DUMP_STATUS_FIELD(pkt_len);
	IPA_DUMP_STATUS_FIELD(endp_src_idx);
	IPA_DUMP_STATUS_FIELD(endp_dest_idx);
	IPA_DUMP_STATUS_FIELD(metadata);
	IPA_DUMP_STATUS_FIELD(ucp);
	pr_err("tag = 0x%llx\n", (u64)status->tag_info & 0xFFFFFFFFFFFF);
	IPA_DUMP_STATUS_FIELD(seq_num);
	IPA_DUMP_STATUS_FIELD(time_of_day_ctr);
	IPA_DUMP_STATUS_FIELD(hdr_local);
	IPA_DUMP_STATUS_FIELD(hdr_offset);
	IPA_DUMP_STATUS_FIELD(frag_hit);
	IPA_DUMP_STATUS_FIELD(frag_rule);
}

static ssize_t ipa_status_stats_read(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	struct ipa3_status_stats *stats;
	int i, j;

	stats = kzalloc(sizeof(*stats), GFP_KERNEL);
	if (!stats)
		return -EFAULT;

	for (i = 0; i < ipa3_ctx->ipa_num_pipes; i++) {
		if (!ipa3_ctx->ep[i].sys || !ipa3_ctx->ep[i].sys->status_stat)
			continue;

		memcpy(stats, ipa3_ctx->ep[i].sys->status_stat, sizeof(*stats));
		pr_err("Statuses for pipe %d\n", i);
		for (j = 0; j < IPA_MAX_STATUS_STAT_NUM; j++) {
			pr_err("curr=%d\n", stats->curr);
			ipa_dump_status(&stats->status[stats->curr]);
			pr_err("\n\n\n");
			stats->curr = (stats->curr + 1) %
				IPA_MAX_STATUS_STAT_NUM;
		}
	}

	kfree(stats);
	return 0;
}

static ssize_t ipa3_print_active_clients_log(struct file *file,
		char __user *ubuf, size_t count, loff_t *ppos)
{
	int cnt;
	int table_size;

	if (active_clients_buf == NULL) {
		IPAERR("Active Clients buffer is not allocated");
		return 0;
	}
	memset(active_clients_buf, 0, IPA_DBG_ACTIVE_CLIENT_BUF_SIZE);
	mutex_lock(&ipa3_ctx->ipa3_active_clients.mutex);
	cnt = ipa3_active_clients_log_print_buffer(active_clients_buf,
			IPA_DBG_ACTIVE_CLIENT_BUF_SIZE - IPA_MAX_MSG_LEN);
	table_size = ipa3_active_clients_log_print_table(active_clients_buf
			+ cnt, IPA_MAX_MSG_LEN);
	mutex_unlock(&ipa3_ctx->ipa3_active_clients.mutex);

	return simple_read_from_buffer(ubuf, count, ppos,
			active_clients_buf, cnt + table_size);
}

static ssize_t ipa3_clear_active_clients_log(struct file *file,
		const char __user *ubuf, size_t count, loff_t *ppos)
{
	unsigned long missing;
		s8 option = 0;

	if (sizeof(dbg_buff) < count + 1)
		return -EFAULT;

	missing = copy_from_user(dbg_buff, ubuf, count);
	if (missing)
		return -EFAULT;

	dbg_buff[count] = '\0';
	if (kstrtos8(dbg_buff, 0, &option))
		return -EFAULT;

	ipa3_active_clients_log_clear();

	return count;
}

static ssize_t ipa3_enable_ipc_low(struct file *file,
	const char __user *ubuf, size_t count, loff_t *ppos)
{
	unsigned long missing;
	s8 option = 0;

	if (sizeof(dbg_buff) < count + 1)
		return -EFAULT;

	missing = copy_from_user(dbg_buff, ubuf, count);
	if (missing)
		return -EFAULT;

	dbg_buff[count] = '\0';
	if (kstrtos8(dbg_buff, 0, &option))
		return -EFAULT;

	mutex_lock(&ipa3_ctx->lock);
	if (option) {
		if (!ipa_ipc_low_buff) {
			ipa_ipc_low_buff =
				ipc_log_context_create(IPA_IPC_LOG_PAGES,
					"ipa_low", 0);
		}
			if (ipa_ipc_low_buff == NULL)
				IPAERR("failed to get logbuf_low\n");
		ipa3_ctx->logbuf_low = ipa_ipc_low_buff;
	} else {
		ipa3_ctx->logbuf_low = NULL;
	}
	mutex_unlock(&ipa3_ctx->lock);

	return count;
}

const struct file_operations ipa3_gen_reg_ops = {
	.read = ipa3_read_gen_reg,
};

const struct file_operations ipa3_ep_reg_ops = {
	.read = ipa3_read_ep_reg,
	.write = ipa3_write_ep_reg,
};

const struct file_operations ipa3_keep_awake_ops = {
	.read = ipa3_read_keep_awake,
	.write = ipa3_write_keep_awake,
};

const struct file_operations ipa3_ep_holb_ops = {
	.write = ipa3_write_ep_holb,
};

const struct file_operations ipa3_stats_ops = {
	.read = ipa3_read_stats,
};

const struct file_operations ipa3_msg_ops = {
	.read = ipa3_read_msg,
};

const struct file_operations ipa3_dbg_cnt_ops = {
	.read = ipa3_read_dbg_cnt,
	.write = ipa3_write_dbg_cnt,
};

const struct file_operations ipa3_status_stats_ops = {
	.read = ipa_status_stats_read,
};

const struct file_operations ipa3_active_clients = {
	.read = ipa3_print_active_clients_log,
	.write = ipa3_clear_active_clients_log,
};

const struct file_operations ipa3_ipc_low_ops = {
	.write = ipa3_enable_ipc_low,
};

void ipa3_debugfs_init(void)
{
	static struct dentry *ipa_dir;
	const mode_t read_only_mode = S_IRUSR | S_IRGRP | S_IROTH;
	const mode_t read_write_mode = S_IRUSR | S_IRGRP | S_IROTH |
			S_IWUSR | S_IWGRP;
	const mode_t write_only_mode = S_IWUSR | S_IWGRP;
	struct dentry *file;

	ipa_dir = debugfs_create_dir("ipa", 0);
	if (IS_ERR(ipa_dir)) {
		IPAERR("fail to create folder in debug_fs.\n");
		return;
	}

	file = debugfs_create_u32("hw_type", read_only_mode,
			ipa_dir, &ipa3_ctx->ipa_hw_type);
	if (!file) {
		IPAERR("could not create hw_type file\n");
		goto fail;
	}

	dfile_gen_reg = debugfs_create_file("gen_reg",
			read_only_mode, ipa_dir, 0,
			&ipa3_gen_reg_ops);
	if (IS_ERR_OR_NULL(dfile_gen_reg)) {
		IPAERR("fail to create file for debug_fs gen_reg\n");
		goto fail;
	}

	dfile_active_clients = debugfs_create_file("active_clients",
			read_write_mode, ipa_dir, 0, &ipa3_active_clients);
	if (IS_ERR_OR_NULL(dfile_active_clients)) {
		IPAERR("fail to create file for debug_fs active_clients\n");
		goto fail;
	}

	dfile_ep_reg = debugfs_create_file("ep_reg",
			read_write_mode, ipa_dir, 0,
			&ipa3_ep_reg_ops);
	if (IS_ERR_OR_NULL(dfile_ep_reg)) {
		IPAERR("fail to create file for debug_fs ep_reg\n");
		goto fail;
	}

	dfile_keep_awake = debugfs_create_file("keep_awake", read_write_mode,
			ipa_dir, 0, &ipa3_keep_awake_ops);
	if (IS_ERR_OR_NULL(dfile_keep_awake)) {
		IPAERR("fail to create file for debug_fs dfile_keep_awake\n");
		goto fail;
	}

	dfile_ep_holb = debugfs_create_file("holb", write_only_mode,
			ipa_dir,
			0, &ipa3_ep_holb_ops);
	if (IS_ERR_OR_NULL(dfile_ep_holb)) {
		IPAERR("fail to create file for debug_fs dfile_ep_hol_en\n");
		goto fail;
	}


	dfile_stats = debugfs_create_file("stats", read_only_mode,
			ipa_dir, 0,
			&ipa3_stats_ops);
	if (IS_ERR_OR_NULL(dfile_stats)) {
		IPAERR("fail to create file for debug_fs stats\n");
		goto fail;
	}

	dfile_dbg_cnt = debugfs_create_file("dbg_cnt",
			read_write_mode, ipa_dir, 0,
			&ipa3_dbg_cnt_ops);
	if (IS_ERR_OR_NULL(dfile_dbg_cnt)) {
		IPAERR("fail to create file for debug_fs dbg_cnt\n");
		goto fail;
	}

	dfile_msg = debugfs_create_file("msg", read_only_mode,
			ipa_dir, 0,
			&ipa3_msg_ops);
	if (IS_ERR_OR_NULL(dfile_msg)) {
		IPAERR("fail to create file for debug_fs msg\n");
		goto fail;
	}

	dfile_status_stats = debugfs_create_file("status_stats",
			read_only_mode, ipa_dir, 0, &ipa3_status_stats_ops);
	if (IS_ERR_OR_NULL(dfile_status_stats)) {
		IPAERR("fail to create file for debug_fs status_stats\n");
		goto fail;
	}

	file = debugfs_create_u32("enable_clock_scaling", read_write_mode,
		ipa_dir, &ipa3_ctx->enable_clock_scaling);
	if (!file) {
		IPAERR("could not create enable_clock_scaling file\n");
		goto fail;
	}

	file = debugfs_create_u32("clock_scaling_bw_threshold_nominal_mbps",
		read_write_mode, ipa_dir,
		&ipa3_ctx->ctrl->clock_scaling_bw_threshold_nominal);
	if (!file) {
		IPAERR("could not create bw_threshold_nominal_mbps\n");
		goto fail;
	}

	file = debugfs_create_u32("clock_scaling_bw_threshold_turbo_mbps",
		read_write_mode, ipa_dir,
		&ipa3_ctx->ctrl->clock_scaling_bw_threshold_turbo);
	if (!file) {
		IPAERR("could not create bw_threshold_turbo_mbps\n");
		goto fail;
	}

	file = debugfs_create_file("enable_low_prio_print", write_only_mode,
		ipa_dir, 0, &ipa3_ipc_low_ops);
	if (IS_ERR_OR_NULL(file)) {
		IPAERR("could not create enable_low_prio_print file\n");
		goto fail;
	}

	active_clients_buf = kzalloc(IPA_DBG_ACTIVE_CLIENT_BUF_SIZE,
			GFP_KERNEL);
	if (!active_clients_buf)
		IPAERR("fail to allocate active clients memory buffer");

	return;
fail:
	debugfs_remove_recursive(ipa_dir);
}

#else /* !CONFIG_DEBUG_FS */
void ipa3_debugfs_init(void) {}
#endif
