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

const struct file_operations gsi_stats_ops = {
	.write = gsi_dump_stats,
};

void gsi_debugfs_init(void)
{
	struct dentry *gsi_dir;
	struct dentry *dfile;
	const mode_t write_only_mode = S_IWUSR | S_IWGRP;

	pr_err("%s - \n", __func__);

	gsi_dir = debugfs_create_dir("gsi", NULL);
	if (IS_ERR(gsi_dir))
		goto fail;

	dfile = debugfs_create_file("stats", write_only_mode,
			gsi_dir, NULL, &gsi_stats_ops);
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
