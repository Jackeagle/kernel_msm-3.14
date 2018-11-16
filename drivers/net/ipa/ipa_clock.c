// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */

#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/clk.h>
#include <linux/device.h>
#include <linux/interconnect.h>
#include <linux/workqueue.h>

#include "ipa_clock.h"

#define	IPA_CORE_CLOCK_RATE		(75UL * 1000 * 1000)	/* Hz */

/* Interconnect path bandwidths (each times 1000 bytes per second) */
#define IPA_MEMORY_AVG			(80 * 1000)	/* 80 MBps */
#define IPA_MEMORY_PEAK			(600 * 1000)

#define IPA_IMEM_AVG			(80 * 1000)
#define IPA_IMEM_PEAK			(350 * 1000)

#define IPA_CONFIG_AVG			(40 * 1000)
#define IPA_CONFIG_PEAK			(40 * 1000)

static int ipa_interconnect_init(struct ipa_context *ipa)
{
	struct device *dev = &ipa->pdev->dev;
	struct icc_path *path;

	path = of_icc_get(dev, "memory");
	if (IS_ERR(path))
		goto err_return;
	ipa->memory_path = path;

	path = of_icc_get(dev, "imem");
	if (IS_ERR(path))
		goto err_memory_path_put;
	ipa->imem_path = path;

	path = of_icc_get(dev, "config");
	if (IS_ERR(path))
		goto err_imem_path_put;
	ipa->config_path = path;

	return 0;

err_imem_path_put:
	icc_put(ipa->imem_path);
	ipa->imem_path = NULL;
err_memory_path_put:
	icc_put(ipa->memory_path);
	ipa->memory_path = NULL;
err_return:

	return PTR_ERR(path);
}

static void ipa_interconnect_exit(struct ipa_context *ipa)
{
	icc_put(ipa->config_path);
	ipa->config_path = NULL;

	icc_put(ipa->imem_path);
	ipa->imem_path = NULL;

	icc_put(ipa->memory_path);
	ipa->memory_path = NULL;
}

/* Currently we only use bandwidth level, so just "enable" interconnects */
static int ipa_interconnect_enable(struct ipa_context *ipa)
{
	int ret;

	ret = icc_set(ipa->memory_path, IPA_MEMORY_AVG, IPA_MEMORY_PEAK);
	if (ret)
		return ret;

	ret = icc_set(ipa->imem_path, IPA_IMEM_AVG, IPA_IMEM_PEAK);
	if (ret)
		goto err_disable_memory_path;

	ret = icc_set(ipa->config_path, IPA_CONFIG_AVG, IPA_CONFIG_PEAK);
	if (!ret)
		return 0;	/* Success */

	(void)icc_set(ipa->imem_path, 0, 0);
err_disable_memory_path:
	(void)icc_set(ipa->memory_path, 0, 0);

	return ret;
}

/* To disable an interconnect, we just its bandwidth to 0 */
static int ipa_interconnect_disable(struct ipa_context *ipa)
{
	int ret;

	ret = icc_set(ipa->memory_path, 0, 0);
	if (ret)
		return ret;

	ret = icc_set(ipa->imem_path, 0, 0);
	if (ret)
		goto err_reenable_memory_path;

	ret = icc_set(ipa->config_path, 0, 0);
	if (!ret)
		return 0;	/* Success */

	/* Re-enable things in the event of an error */
	(void)icc_set(ipa->imem_path, IPA_IMEM_AVG, IPA_IMEM_PEAK);
err_reenable_memory_path:
	(void)icc_set(ipa->memory_path, IPA_MEMORY_AVG, IPA_MEMORY_PEAK);

	return ret;
}

/**
 * ipa_clock_enable() - Turn on IPA clocks
 */
static int ipa_clock_enable(struct ipa_context *ipa)
{
	int ret;

	ret = ipa_interconnect_enable(ipa);
	if (ret)
		return ret;

	ret = clk_prepare_enable(ipa->core_clock);
	if (ret)
		ipa_interconnect_disable(ipa);

	return ret;
}

/**
 * ipa_clock_disable() - Turn off IPA clocks
 */
static void ipa_clock_disable(struct ipa_context *ipa)
{
	clk_disable_unprepare(ipa->core_clock);
	(void)ipa_interconnect_disable(ipa);
}

/* Add an IPA client under protection of the mutex.  This is called
 * for the first client, but a race could mean another caller gets
 * the first reference.  When the first reference is taken, IPA
 * clocks are enabled endpoints are resumed.  A positive reference count
 * means the endpoints are active; this doesn't set the first reference
 * until after this is complete (and the mutex, not the atomic
 * count, is what protects this).
 */
static void ipa_clock_get_first(struct ipa_context *ipa)
{
	mutex_lock(&ipa->clock_mutex);

	/* A reference might have been added before we got the mutex. */
	if (atomic_inc_return(&ipa->clock_count) == 1) {
		(void)ipa_clock_enable(ipa);
		ipa_ep_resume_all(ipa);
	}

	mutex_unlock(&ipa->clock_mutex);
}

/* Add an IPA client, but only if the reference count is already
 * non-zero.  (This is used to avoid blocking.)  Returns true if the
 * additional reference was added successfully, or false otherwise.
 */
bool ipa_clock_get_additional(struct ipa_context *ipa)
{
	return !!atomic_inc_not_zero(&ipa->clock_count);
}

/* Add an IPA client.  If this is not the first client, the
 * reference count is updated and return is immediate.  Otherwise
 * ipa_clock_get_first() will safely add the first client, enabling
 * clocks and setting up (resuming) endpoints before returning.
 */
void ipa_clock_get(struct ipa_context *ipa)
{
	if (!ipa_clock_get_additional(ipa))
		ipa_clock_get_first(ipa);
}

/* Decrement the active clients reference count, and if the result
 * is 0, suspend the endpoints and disable clocks.
 *
 * This function runs in work queue context, scheduled to run whenever
 * the last reference would be dropped in ipa_clock_put_final().
 */
static void ipa_clock_put_final(struct work_struct *work)
{
	struct ipa_context *ipa;

	ipa = container_of(work, struct ipa_context, clock_work);

	mutex_lock(&ipa->clock_mutex);

	/* A reference might have been removed before we got the mutex. */
	if (!atomic_dec_return(&ipa->clock_count)) {
		ipa_ep_suspend_all(ipa);
		ipa_clock_disable(ipa);
	}

	mutex_unlock(&ipa->clock_mutex);
}

/* Attempt to remove an IPA clock reference.  If this represents
 * the last reference arrange for ipa_clock_put_final() to be
 * called in workqueue context to drop the last reference under
 * protection of the mutex.
 */
void ipa_clock_put(struct ipa_context *ipa)
{
	if (!atomic_add_unless(&ipa->clock_count, -1, 1))
		queue_work(ipa->clock_wq, &ipa->clock_work);
}

/** ipa_clock_proxy_put() - called to remove IPA clock proxy vote
 *
 * Return value: none
 */
void ipa_clock_proxy_put(struct ipa_context *ipa)
{
	if (ipa->proxy_held) {
		ipa_clock_put(ipa);
		ipa->proxy_held = false;
	}
}

/** ipa_clock_proxy_get() - called to add IPA clock proxy vote
 *
 * Return value: none
 */
void ipa_clock_proxy_get(struct ipa_context *ipa)
{
	if (!ipa->proxy_held) {
		ipa_clock_get(ipa);
		ipa->proxy_held = true;
	}
}

int ipa_clock_init(struct ipa_context *ipa)
{
	struct device *dev = &ipa->pdev->dev;
	struct clk *clk;
	int ret;

	clk = clk_get(dev, "core");
	if (IS_ERR(clk))
		return PTR_ERR(clk);
	ipa->core_clock = clk;

	ret = clk_set_rate(clk, IPA_CORE_CLOCK_RATE);
	if (ret)
		goto err_clk_put;

	ret = ipa_interconnect_init(ipa);
	if (ret)
		goto err_clk_put;

	ipa->clock_wq = create_singlethread_workqueue("ipa_clock");
	if (!ipa->clock_wq)
		goto err_interconnect_exit;

	INIT_WORK(&ipa->clock_work, ipa_clock_put_final);
	mutex_init(&ipa->clock_mutex);
	atomic_set(&ipa->clock_count, 1);

	return 0;

err_interconnect_exit:
	ret = -ENOMEM;
	ipa_interconnect_exit(ipa);
err_clk_put:
	ipa->core_clock = NULL;
	clk_put(clk);

	return ret;
}

void ipa_clock_exit(struct ipa_context *ipa)
{
	atomic_set(&ipa->clock_count, 0);
	mutex_destroy(&ipa->clock_mutex);
	cancel_work_sync(&ipa->clock_work);
	memset(&ipa->clock_work, 0, sizeof(ipa->clock_work));
	destroy_workqueue(ipa->clock_wq);
	ipa->clock_wq = NULL;
	ipa_interconnect_exit(ipa);
	clk_put(ipa->core_clock);
	ipa->core_clock = NULL;
}
