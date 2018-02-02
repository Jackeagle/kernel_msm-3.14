/* Copyright (c) 2015-2017, The Linux Foundation. All rights reserved.
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
#ifdef CONFIG_DEBUG_FS

#define pr_fmt(fmt)	"%s:%d " fmt, __func__, __LINE__

#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/dma-mapping.h>
#include <linux/random.h>
#include <linux/uaccess.h>
#include "gsi_reg.h"
#include "gsi.h"

static char dbg_buff[4096];

static void gsi_wq_print_dp_stats(struct work_struct *work);
static DECLARE_DELAYED_WORK(gsi_print_dp_stats_work, gsi_wq_print_dp_stats);
static void gsi_wq_update_dp_stats(struct work_struct *work);
static DECLARE_DELAYED_WORK(gsi_update_dp_stats_work, gsi_wq_update_dp_stats);

static ssize_t gsi_dump_evt(struct file *file,
		const char __user *buf, size_t count, loff_t *ppos)
{
	u32 arg1;
	u32 arg2;
	unsigned long missing;
	char *sptr, *token;
	uint32_t val;
	struct gsi_evt_ctx *ctx;
	u32 i;

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
	if (kstrtou32(token, 0, &arg1))
		return -EINVAL;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &arg2))
		return -EINVAL;

	pr_debug("arg1=%u arg2=%u\n", arg1, arg2);

	if (arg1 >= gsi_ctx->max_ev) {
		pr_err("invalid evt ring id %u\n", arg1);
		return -EFAULT;
	}

	val = gsi_readl(GSI_EE_n_EV_CH_k_CNTXT_0_OFFS(arg1, gsi_ctx->ee));
	pr_err("EV%2d CTX0  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_EV_CH_k_CNTXT_1_OFFS(arg1, gsi_ctx->ee));
	pr_err("EV%2d CTX1  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_EV_CH_k_CNTXT_2_OFFS(arg1, gsi_ctx->ee));
	pr_err("EV%2d CTX2  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_EV_CH_k_CNTXT_3_OFFS(arg1, gsi_ctx->ee));
	pr_err("EV%2d CTX3  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_EV_CH_k_CNTXT_4_OFFS(arg1, gsi_ctx->ee));
	pr_err("EV%2d CTX4  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_EV_CH_k_CNTXT_5_OFFS(arg1, gsi_ctx->ee));
	pr_err("EV%2d CTX5  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_EV_CH_k_CNTXT_6_OFFS(arg1, gsi_ctx->ee));
	pr_err("EV%2d CTX6  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_EV_CH_k_CNTXT_7_OFFS(arg1, gsi_ctx->ee));
	pr_err("EV%2d CTX7  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_EV_CH_k_CNTXT_8_OFFS(arg1, gsi_ctx->ee));
	pr_err("EV%2d CTX8  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_EV_CH_k_CNTXT_9_OFFS(arg1, gsi_ctx->ee));
	pr_err("EV%2d CTX9  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_EV_CH_k_CNTXT_10_OFFS(arg1, gsi_ctx->ee));
	pr_err("EV%2d CTX10 0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_EV_CH_k_CNTXT_11_OFFS(arg1, gsi_ctx->ee));
	pr_err("EV%2d CTX11 0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_EV_CH_k_CNTXT_12_OFFS(arg1, gsi_ctx->ee));
	pr_err("EV%2d CTX12 0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_EV_CH_k_CNTXT_13_OFFS(arg1, gsi_ctx->ee));
	pr_err("EV%2d CTX13 0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_EV_CH_k_SCRATCH_0_OFFS(arg1, gsi_ctx->ee));
	pr_err("EV%2d SCR0  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_EV_CH_k_SCRATCH_1_OFFS(arg1, gsi_ctx->ee));
	pr_err("EV%2d SCR1  0x%x\n", arg1, val);

	if (arg2) {
		ctx = &gsi_ctx->evtr[arg1];

		if (ctx->mem.base) {
			for (i = 0; i < ctx->mem.size / 16; i++)
				pr_err("EV%2d (0x%08llx) %08x %08x %08x %08x\n",
				arg1, ctx->mem.phys_base + i * 16,
				*(u32 *)((u8 *)ctx->mem.base +
					i * 16 + 0),
				*(u32 *)((u8 *)ctx->mem.base +
					i * 16 + 4),
				*(u32 *)((u8 *)ctx->mem.base +
					i * 16 + 8),
				*(u32 *)((u8 *)ctx->mem.base +
					i * 16 + 12));
		} else {
			pr_err("No VA supplied for event ring id %u\n", arg1);
		}
	}

	return count;
}

static ssize_t gsi_dump_ch(struct file *file,
		const char __user *buf, size_t count, loff_t *ppos)
{
	u32 arg1;
	u32 arg2;
	unsigned long missing;
	char *sptr, *token;
	uint32_t val;
	struct gsi_chan_ctx *ctx;
	u32 i;

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
	if (kstrtou32(token, 0, &arg1))
		return -EINVAL;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &arg2))
		return -EINVAL;

	pr_debug("arg1=%u arg2=%u\n", arg1, arg2);

	if (arg1 >= gsi_ctx->max_ch) {
		pr_err("invalid chan id %u\n", arg1);
		return -EFAULT;
	}

	val = gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_0_OFFS(arg1, gsi_ctx->ee));
	pr_err("CH%2d CTX0  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_1_OFFS(arg1, gsi_ctx->ee));
	pr_err("CH%2d CTX1  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_2_OFFS(arg1, gsi_ctx->ee));
	pr_err("CH%2d CTX2  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_3_OFFS(arg1, gsi_ctx->ee));
	pr_err("CH%2d CTX3  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_4_OFFS(arg1, gsi_ctx->ee));
	pr_err("CH%2d CTX4  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_5_OFFS(arg1, gsi_ctx->ee));
	pr_err("CH%2d CTX5  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_6_OFFS(arg1, gsi_ctx->ee));
	pr_err("CH%2d CTX6  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_7_OFFS(arg1, gsi_ctx->ee));
	pr_err("CH%2d CTX7  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_GSI_CH_k_RE_FETCH_READ_PTR_OFFS(arg1,
			gsi_ctx->ee));
	pr_err("CH%2d REFRP 0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_GSI_CH_k_RE_FETCH_WRITE_PTR_OFFS(arg1,
			gsi_ctx->ee));
	pr_err("CH%2d REFWP 0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_GSI_CH_k_QOS_OFFS(arg1, gsi_ctx->ee));
	pr_err("CH%2d QOS   0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_GSI_CH_k_SCRATCH_0_OFFS(arg1, gsi_ctx->ee));
	pr_err("CH%2d SCR0  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_GSI_CH_k_SCRATCH_1_OFFS(arg1, gsi_ctx->ee));
	pr_err("CH%2d SCR1  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_GSI_CH_k_SCRATCH_2_OFFS(arg1, gsi_ctx->ee));
	pr_err("CH%2d SCR2  0x%x\n", arg1, val);
	val = gsi_readl(GSI_EE_n_GSI_CH_k_SCRATCH_3_OFFS(arg1, gsi_ctx->ee));
	pr_err("CH%2d SCR3  0x%x\n", arg1, val);

	if (arg2) {
		ctx = &gsi_ctx->chan[arg1];

		if (ctx->props.mem.base) {
			for (i = 0; i < ctx->props.mem.size / 16; i++)
				pr_err("CH%2d (0x%08llx) %08x %08x %08x %08x\n",
				arg1, ctx->props.mem.phys_base + i * 16,
				*(u32 *)((u8 *)ctx->props.mem.base +
					i * 16 + 0),
				*(u32 *)((u8 *)ctx->props.mem.base +
					i * 16 + 4),
				*(u32 *)((u8 *)ctx->props.mem.base +
					i * 16 + 8),
				*(u32 *)((u8 *)ctx->props.mem.base +
					i * 16 + 12));
		} else {
			pr_err("No VA supplied for chan id %u\n", arg1);
		}
	}

	return count;
}

static ssize_t gsi_dump_ee(struct file *file,
		const char __user *buf, size_t count, loff_t *ppos)
{
	uint32_t val;

	val = gsi_readl(GSI_GSI_MANAGER_EE_QOS_n_OFFS(gsi_ctx->ee));
	pr_err("EE%2d QOS 0x%x\n", gsi_ctx->ee, val);
	val = gsi_readl(GSI_EE_n_GSI_STATUS_OFFS(gsi_ctx->ee));
	pr_err("EE%2d STATUS 0x%x\n", gsi_ctx->ee, val);

	/* SDM845 uses GSI hardware version 1.3.0 */
	val = gsi_readl(GSI_V1_3_EE_n_GSI_HW_PARAM_0_OFFS(gsi_ctx->ee));
	pr_err("EE%2d HW_PARAM_0 0x%x\n", gsi_ctx->ee, val);
	val = gsi_readl(GSI_V1_3_EE_n_GSI_HW_PARAM_1_OFFS(gsi_ctx->ee));
	pr_err("EE%2d HW_PARAM_1 0x%x\n", gsi_ctx->ee, val);
	val = gsi_readl(GSI_V1_3_EE_n_GSI_HW_PARAM_2_OFFS(gsi_ctx->ee));
	pr_err("EE%2d HW_PARAM_2 0x%x\n", gsi_ctx->ee, val);

	val = gsi_readl(GSI_EE_n_GSI_SW_VERSION_OFFS(gsi_ctx->ee));
	pr_err("EE%2d SW_VERSION 0x%x\n", gsi_ctx->ee, val);
	val = gsi_readl(GSI_EE_n_GSI_MCS_CODE_VER_OFFS(gsi_ctx->ee));
	pr_err("EE%2d MCS_CODE_VER 0x%x\n", gsi_ctx->ee, val);
	val = gsi_readl(GSI_EE_n_CNTXT_TYPE_IRQ_MSK_OFFS(gsi_ctx->ee));
	pr_err("EE%2d TYPE_IRQ_MSK 0x%x\n", gsi_ctx->ee, val);
	val = gsi_readl(GSI_EE_n_CNTXT_SRC_GSI_CH_IRQ_MSK_OFFS(gsi_ctx->ee));
	pr_err("EE%2d CH_IRQ_MSK 0x%x\n", gsi_ctx->ee, val);
	val = gsi_readl(GSI_EE_n_CNTXT_SRC_EV_CH_IRQ_MSK_OFFS(gsi_ctx->ee));
	pr_err("EE%2d EV_IRQ_MSK 0x%x\n", gsi_ctx->ee, val);
	val = gsi_readl(GSI_EE_n_CNTXT_SRC_IEOB_IRQ_MSK_OFFS(gsi_ctx->ee));
	pr_err("EE%2d IEOB_IRQ_MSK 0x%x\n", gsi_ctx->ee, val);
	val = gsi_readl(GSI_EE_n_CNTXT_GLOB_IRQ_EN_OFFS(gsi_ctx->ee));
	pr_err("EE%2d GLOB_IRQ_EN 0x%x\n", gsi_ctx->ee, val);
	val = gsi_readl(GSI_EE_n_CNTXT_GSI_IRQ_EN_OFFS(gsi_ctx->ee));
	pr_err("EE%2d GSI_IRQ_EN 0x%x\n", gsi_ctx->ee, val);
	val = gsi_readl(GSI_EE_n_CNTXT_INTSET_OFFS(gsi_ctx->ee));
	pr_err("EE%2d INTSET 0x%x\n", gsi_ctx->ee, val);
	val = gsi_readl(GSI_EE_n_CNTXT_MSI_BASE_LSB_OFFS(gsi_ctx->ee));
	pr_err("EE%2d MSI_BASE_LSB 0x%x\n", gsi_ctx->ee, val);
	val = gsi_readl(GSI_EE_n_CNTXT_MSI_BASE_MSB_OFFS(gsi_ctx->ee));
	pr_err("EE%2d MSI_BASE_MSB 0x%x\n", gsi_ctx->ee, val);
	val = gsi_readl(GSI_EE_n_CNTXT_INT_VEC_OFFS(gsi_ctx->ee));
	pr_err("EE%2d INT_VEC 0x%x\n", gsi_ctx->ee, val);
	val = gsi_readl(GSI_EE_n_CNTXT_SCRATCH_0_OFFS(gsi_ctx->ee));
	pr_err("EE%2d SCR0 0x%x\n", gsi_ctx->ee, val);
	val = gsi_readl(GSI_EE_n_CNTXT_SCRATCH_1_OFFS(gsi_ctx->ee));
	pr_err("EE%2d SCR1 0x%x\n", gsi_ctx->ee, val);

	return count;
}

static ssize_t gsi_dump_map(struct file *file,
		const char __user *buf, size_t count, loff_t *ppos)
{
	struct gsi_chan_ctx *ctx;
	uint32_t val1;
	uint32_t val2;
	int i;

	pr_err("EVT bitmap 0x%lx\n", gsi_ctx->evt_bmap);
	for (i = 0; i < gsi_ctx->max_ch; i++) {
		ctx = &gsi_ctx->chan[i];

		if (ctx->allocated) {
			pr_err("VIRT CH%2d -> VIRT EV%2d\n", ctx->props.ch_id,
				ctx->evtr ? ctx->evtr->id : GSI_NO_EVT_ERINDEX);
			val1 = gsi_readl(GSI_GSI_DEBUG_EE_n_CH_k_VP_TABLE_OFFS(i,
					gsi_ctx->ee));
			pr_err("VIRT CH%2d -> PHYS CH%2d\n", ctx->props.ch_id,
				val1 &
				GSI_GSI_DEBUG_EE_n_CH_k_VP_TABLE_PHY_CH_BMSK);
			if (ctx->evtr) {
				val2 = gsi_readl(GSI_GSI_DEBUG_EE_n_EV_k_VP_TABLE_OFFS(
					ctx->evtr->id, gsi_ctx->ee));
				pr_err("VRT EV%2d -> PHYS EV%2d\n", ctx->evtr->id,
				val2 &
				GSI_GSI_DEBUG_EE_n_CH_k_VP_TABLE_PHY_CH_BMSK);
			}
			pr_err("\n");
		}
	}

	return count;
}

static void gsi_dump_ch_stats(struct gsi_chan_ctx *ctx)
{
	if (!ctx->allocated)
		return;

	printk(KERN_ERR "CH%2d:\n", ctx->props.ch_id);
	printk(KERN_ERR "queued=%lu compl=%lu\n",
		ctx->stats.queued,
		ctx->stats.completed);
	printk(KERN_ERR "cb->poll=%lu poll->cb=%lu\n",
		ctx->stats.callback_to_poll,
		ctx->stats.poll_to_callback);
	printk(KERN_ERR "invalid_tre_error=%lu\n",
		ctx->stats.invalid_tre_error);
	printk(KERN_ERR "poll_ok=%lu poll_empty=%lu\n",
		ctx->stats.poll_ok, ctx->stats.poll_empty);
	if (ctx->evtr)
		printk(KERN_ERR "compl_evt=%lu\n",
			ctx->evtr->stats.completed);

	printk(KERN_ERR "ch_below_lo=%lu\n", ctx->stats.dp.ch_below_lo);
	printk(KERN_ERR "ch_below_hi=%lu\n", ctx->stats.dp.ch_below_hi);
	printk(KERN_ERR "ch_above_hi=%lu\n", ctx->stats.dp.ch_above_hi);
	printk(KERN_ERR "time_empty=%lums\n", ctx->stats.dp.empty_time);
	printk(KERN_ERR "\n");
}

static ssize_t gsi_dump_stats(struct file *file,
		const char __user *buf, size_t count, loff_t *ppos)
{
	int ch_id;
	int min, max;

	if (sizeof(dbg_buff) < count + 1)
		goto error;

	if (copy_from_user(dbg_buff, buf, count))
		goto error;

	dbg_buff[count] = '\0';

	if (kstrtos32(dbg_buff, 0, &ch_id))
		goto error;

	if (ch_id == -1) {
		min = 0;
		max = gsi_ctx->max_ch;
	} else if (ch_id < 0 || ch_id >= gsi_ctx->max_ch ||
		   !gsi_ctx->chan[ch_id].allocated) {
		goto error;
	} else {
		min = ch_id;
		max = ch_id + 1;
	}

	for (ch_id = min; ch_id < max; ch_id++)
		gsi_dump_ch_stats(&gsi_ctx->chan[ch_id]);

	return count;
error:
	pr_err("Usage: echo ch_id > stats. Use -1 for all\n");
	return -EFAULT;
}

static int gsi_dbg_create_stats_wq(void)
{
	gsi_ctx->dp_stat_wq =
		create_singlethread_workqueue("gsi_stat");
	if (!gsi_ctx->dp_stat_wq) {
		pr_err("failed create workqueue\n");
		return -ENOMEM;
	}

	return 0;
}

static void gsi_dbg_destroy_stats_wq(void)
{
	cancel_delayed_work_sync(&gsi_update_dp_stats_work);
	cancel_delayed_work_sync(&gsi_print_dp_stats_work);
	flush_workqueue(gsi_ctx->dp_stat_wq);
	destroy_workqueue(gsi_ctx->dp_stat_wq);
	gsi_ctx->dp_stat_wq = NULL;
}

static ssize_t gsi_enable_dp_stats(struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
	int ch_id;
	bool enable;
	int ret;

	if (sizeof(dbg_buff) < count + 1)
		goto error;

	if (copy_from_user(dbg_buff, buf, count))
		goto error;

	dbg_buff[count] = '\0';

	if (dbg_buff[0] != '+' && dbg_buff[0] != '-')
		goto error;

	enable = (dbg_buff[0] == '+');

	if (kstrtos32(dbg_buff + 1, 0, &ch_id))
		goto error;

	if (ch_id < 0 || ch_id >= gsi_ctx->max_ch ||
	    !gsi_ctx->chan[ch_id].allocated) {
		goto error;
	}

	if (gsi_ctx->chan[ch_id].enable_dp_stats == enable) {
		pr_err("ch_%d: already enabled/disabled\n", ch_id);
		return -EFAULT;
	}
	gsi_ctx->chan[ch_id].enable_dp_stats = enable;

	if (enable)
		gsi_ctx->num_ch_dp_stats++;
	else
		gsi_ctx->num_ch_dp_stats--;

	if (enable) {
		if (gsi_ctx->num_ch_dp_stats == 1) {
			ret = gsi_dbg_create_stats_wq();
			if (ret)
				return ret;
		}
		cancel_delayed_work_sync(&gsi_update_dp_stats_work);
		queue_delayed_work(gsi_ctx->dp_stat_wq,
			&gsi_update_dp_stats_work, msecs_to_jiffies(10));
	} else if (!enable && gsi_ctx->num_ch_dp_stats == 0) {
		gsi_dbg_destroy_stats_wq();
	}

	return count;
error:
	pr_err("Usage: echo [+-]ch_id > enable_dp_stats\n");
	return -EFAULT;
}

static ssize_t gsi_set_max_elem_dp_stats(struct file *file,
		const char __user *buf, size_t count, loff_t *ppos)
{
	u32 ch_id;
	u32 max_elem;
	unsigned long missing;
	char *sptr, *token;


	if (sizeof(dbg_buff) < count + 1)
		goto error;

	missing = copy_from_user(dbg_buff, buf, count);
	if (missing)
		goto error;

	dbg_buff[count] = '\0';

	sptr = dbg_buff;

	token = strsep(&sptr, " ");
	if (!token) {
		pr_err("\n");
		goto error;
	}

	if (kstrtou32(token, 0, &ch_id)) {
		pr_err("\n");
		goto error;
	}

	token = strsep(&sptr, " ");
	if (!token) {
		/* get */
		if (kstrtou32(dbg_buff, 0, &ch_id))
			goto error;
		if (ch_id >= gsi_ctx->max_ch)
			goto error;
		printk(KERN_ERR "ch %d: max_re_expected=%d\n", ch_id,
			gsi_ctx->chan[ch_id].props.max_re_expected);
		return count;
	}
	if (kstrtou32(token, 0, &max_elem)) {
		pr_err("\n");
		goto error;
	}

	pr_debug("ch_id=%u max_elem=%u\n", ch_id, max_elem);

	if (ch_id >= gsi_ctx->max_ch) {
		pr_err("invalid chan id %u\n", ch_id);
		goto error;
	}

	gsi_ctx->chan[ch_id].props.max_re_expected = max_elem;

	return count;

error:
	pr_err("Usage: (set) echo <ch_id> <max_elem> > max_elem_dp_stats\n");
	pr_err("Usage: (get) echo <ch_id> > max_elem_dp_stats\n");
	return -EFAULT;
}

static void gsi_wq_print_dp_stats(struct work_struct *work)
{
	int ch_id;

	for (ch_id = 0; ch_id < gsi_ctx->max_ch; ch_id++) {
		if (gsi_ctx->chan[ch_id].print_dp_stats)
			gsi_dump_ch_stats(&gsi_ctx->chan[ch_id]);
	}

	queue_delayed_work(gsi_ctx->dp_stat_wq, &gsi_print_dp_stats_work,
		msecs_to_jiffies(1000));
}

static void gsi_dbg_update_ch_dp_stats(struct gsi_chan_ctx *ctx)
{
	uint16_t start_hw;
	uint16_t end_hw;
	uint64_t rp_hw;
	uint64_t wp_hw;
	int ee = gsi_ctx->ee;
	uint16_t used_hw;

	rp_hw = gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_4_OFFS(ctx->props.ch_id, ee));
	rp_hw |= ((uint64_t)gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_5_OFFS(ctx->props.ch_id, ee)))
		<< 32;

	wp_hw = gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_6_OFFS(ctx->props.ch_id, ee));
	wp_hw |= ((uint64_t)gsi_readl(GSI_EE_n_GSI_CH_k_CNTXT_7_OFFS(ctx->props.ch_id, ee)))
		<< 32;

	start_hw = gsi_find_idx_from_addr(&ctx->ring, rp_hw);
	end_hw = gsi_find_idx_from_addr(&ctx->ring, wp_hw);

	if (end_hw >= start_hw)
		used_hw = end_hw - start_hw;
	else
		used_hw = ctx->ring.max_num_elem + 1 - (start_hw - end_hw);

	pr_debug("ch %d used %d\n", ctx->props.ch_id, used_hw);
	gsi_update_ch_dp_stats(ctx, used_hw);
}

static void gsi_wq_update_dp_stats(struct work_struct *work)
{
	int ch_id;

	for (ch_id = 0; ch_id < gsi_ctx->max_ch; ch_id++) {
		if (gsi_ctx->chan[ch_id].allocated &&
		    gsi_ctx->chan[ch_id].enable_dp_stats)
			gsi_dbg_update_ch_dp_stats(&gsi_ctx->chan[ch_id]);
	}

	queue_delayed_work(gsi_ctx->dp_stat_wq, &gsi_update_dp_stats_work,
		msecs_to_jiffies(10));
}


static ssize_t gsi_rst_stats(struct file *file,
		const char __user *buf, size_t count, loff_t *ppos)
{
	int ch_id;
	int min, max;

	if (sizeof(dbg_buff) < count + 1)
		goto error;

	if (copy_from_user(dbg_buff, buf, count))
		goto error;

	dbg_buff[count] = '\0';

	if (kstrtos32(dbg_buff, 0, &ch_id))
		goto error;

	if (ch_id == -1) {
		min = 0;
		max = gsi_ctx->max_ch;
	} else if (ch_id < 0 || ch_id >= gsi_ctx->max_ch ||
		   !gsi_ctx->chan[ch_id].allocated) {
		goto error;
	} else {
		min = ch_id;
		max = ch_id + 1;
	}

	for (ch_id = min; ch_id < max; ch_id++)
		memset(&gsi_ctx->chan[ch_id].stats, 0,
			sizeof(gsi_ctx->chan[ch_id].stats));

	return count;
error:
	pr_err("Usage: echo ch_id > rst_stats. Use -1 for all\n");
	return -EFAULT;
}

static ssize_t gsi_print_dp_stats(struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
	int ch_id;
	bool enable;
	int ret;

	if (sizeof(dbg_buff) < count + 1)
		goto error;

	if (copy_from_user(dbg_buff, buf, count))
		goto error;

	dbg_buff[count] = '\0';

	if (dbg_buff[0] != '+' && dbg_buff[0] != '-')
		goto error;

	enable = (dbg_buff[0] == '+');

	if (kstrtos32(dbg_buff + 1, 0, &ch_id))
		goto error;

	if (ch_id < 0 || ch_id >= gsi_ctx->max_ch ||
	    !gsi_ctx->chan[ch_id].allocated) {
		goto error;
	}

	if (gsi_ctx->chan[ch_id].print_dp_stats == enable) {
		pr_err("ch_%d: already enabled/disabled\n", ch_id);
		return -EFAULT;
	}
	gsi_ctx->chan[ch_id].print_dp_stats = enable;

	if (enable)
		gsi_ctx->num_ch_dp_stats++;
	else
		gsi_ctx->num_ch_dp_stats--;

	if (enable) {
		if (gsi_ctx->num_ch_dp_stats == 1) {
			ret = gsi_dbg_create_stats_wq();
			if (ret)
				return ret;
		}
		cancel_delayed_work_sync(&gsi_print_dp_stats_work);
		queue_delayed_work(gsi_ctx->dp_stat_wq,
			&gsi_print_dp_stats_work, msecs_to_jiffies(10));
	} else if (!enable && gsi_ctx->num_ch_dp_stats == 0) {
		gsi_dbg_destroy_stats_wq();
	}

	return count;
error:
	pr_err("Usage: echo [+-]ch_id > print_dp_stats\n");
	return -EFAULT;
}

const struct file_operations gsi_ev_dump_ops = {
	.write = gsi_dump_evt,
};

const struct file_operations gsi_ch_dump_ops = {
	.write = gsi_dump_ch,
};

const struct file_operations gsi_ee_dump_ops = {
	.write = gsi_dump_ee,
};

const struct file_operations gsi_map_ops = {
	.write = gsi_dump_map,
};

const struct file_operations gsi_stats_ops = {
	.write = gsi_dump_stats,
};

const struct file_operations gsi_enable_dp_stats_ops = {
	.write = gsi_enable_dp_stats,
};

const struct file_operations gsi_max_elem_dp_stats_ops = {
	.write = gsi_set_max_elem_dp_stats,
};

const struct file_operations gsi_rst_stats_ops = {
	.write = gsi_rst_stats,
};

const struct file_operations gsi_print_dp_stats_ops = {
	.write = gsi_print_dp_stats,
};

void gsi_debugfs_init(void)
{
	struct dentry *gsi_dir;
	struct dentry *dfile;
	const mode_t read_only_mode = S_IRUSR | S_IRGRP | S_IROTH;
	const mode_t write_only_mode = S_IWUSR | S_IWGRP;

	pr_err("%s - \n", __func__);

	gsi_dir = debugfs_create_dir("gsi", NULL);
	if (IS_ERR(gsi_dir))
		goto fail;

	dfile = debugfs_create_file("ev_dump", write_only_mode,
			gsi_dir, NULL, &gsi_ev_dump_ops);
	if (IS_ERR_OR_NULL(dfile))
		goto fail;

	dfile = debugfs_create_file("ch_dump", write_only_mode,
			gsi_dir, NULL, &gsi_ch_dump_ops);
	if (IS_ERR_OR_NULL(dfile))
		goto fail;

	dfile = debugfs_create_file("ee_dump", read_only_mode,
			gsi_dir, NULL, &gsi_ee_dump_ops);
	if (IS_ERR_OR_NULL(dfile))
		goto fail;

	dfile = debugfs_create_file("map", read_only_mode, gsi_dir,
			NULL, &gsi_map_ops);
	if (IS_ERR_OR_NULL(dfile))
		goto fail;

	dfile = debugfs_create_file("stats", write_only_mode,
			gsi_dir, NULL, &gsi_stats_ops);
	if (IS_ERR_OR_NULL(dfile))
		goto fail;

	dfile = debugfs_create_file("enable_dp_stats",
			write_only_mode, gsi_dir,
			NULL, &gsi_enable_dp_stats_ops);
	if (IS_ERR_OR_NULL(dfile))
		goto fail;

	dfile = debugfs_create_file("max_elem_dp_stats", write_only_mode,
		gsi_dir, NULL, &gsi_max_elem_dp_stats_ops);
	if (IS_ERR_OR_NULL(dfile))
		goto fail;

	dfile = debugfs_create_file("rst_stats", write_only_mode,
		gsi_dir, NULL, &gsi_rst_stats_ops);
	if (IS_ERR_OR_NULL(dfile))
		goto fail;

	dfile = debugfs_create_file("print_dp_stats",
		write_only_mode, gsi_dir, NULL, &gsi_print_dp_stats_ops);
	if (IS_ERR_OR_NULL(dfile))
		goto fail;

	pr_err("%s - complete\n", __func__);

	return;
fail:
	pr_err("error while creating gsi debugfs hierarchy\n");
	debugfs_remove_recursive(gsi_dir);
}
#else
void gsi_debugfs_init(void)
{
}
#endif
