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

static ssize_t gsi_dump_ee(struct file *file,
		const char __user *buf, size_t count, loff_t *ppos)
{
	uint32_t val;

	val = gsi_readl(GSI_MANAGER_EE_QOS_n_OFFS(gsi_ctx->ee));
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
				ctx->evtr->id);
			val1 = gsi_readl(GSI_DEBUG_EE_n_CH_k_VP_TABLE_OFFS(i,
					gsi_ctx->ee));
			pr_err("VIRT CH%2d -> PHYS CH%2d\n", ctx->props.ch_id,
				val1 & PHY_CH_BMSK);
			val2 = gsi_readl(GSI_DEBUG_EE_n_EV_k_VP_TABLE_OFFS(
				ctx->evtr->id, gsi_ctx->ee));
			pr_err("VRT EV%2d -> PHYS EV%2d\n",
					ctx->evtr->id,
			val2 & PHY_CH_BMSK);
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

const struct file_operations gsi_ee_dump_ops = {
	.write = gsi_dump_ee,
};

const struct file_operations gsi_map_ops = {
	.write = gsi_dump_map,
};

const struct file_operations gsi_stats_ops = {
	.write = gsi_dump_stats,
};

const struct file_operations gsi_max_elem_dp_stats_ops = {
	.write = gsi_set_max_elem_dp_stats,
};

const struct file_operations gsi_rst_stats_ops = {
	.write = gsi_rst_stats,
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

	dfile = debugfs_create_file("max_elem_dp_stats", write_only_mode,
		gsi_dir, NULL, &gsi_max_elem_dp_stats_ops);
	if (IS_ERR_OR_NULL(dfile))
		goto fail;

	dfile = debugfs_create_file("rst_stats", write_only_mode,
		gsi_dir, NULL, &gsi_rst_stats_ops);
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
