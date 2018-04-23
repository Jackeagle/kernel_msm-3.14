/* Copyright (c) 2015-2018, The Linux Foundation. All rights reserved.
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

#define pr_fmt(fmt)	"[drm:%s:%d] " fmt, __func__, __LINE__

#include <linux/irqdomain.h>
#include <linux/irq.h>
#include <linux/kthread.h>

#include "dpu_irq.h"
#include "dpu_core_irq.h"

static uint32_t g_dpu_irq_status;

irqreturn_t dpu_irq(struct msm_kms *kms)
{
	struct dpu_kms *dpu_kms = to_dpu_kms(kms);
	u32 interrupts;

	dpu_kms->hw_intr->ops.get_interrupt_sources(dpu_kms->hw_intr,
			&interrupts);

	/* store irq status in case of irq-storm debugging */
	g_dpu_irq_status = interrupts;

	/*
	 * Taking care of MDP interrupt
	 */
	if (interrupts & IRQ_SOURCE_MDP) {
		interrupts &= ~IRQ_SOURCE_MDP;
		dpu_core_irq(dpu_kms);
	}

	/*
	 * Routing all other interrupts to external drivers
	 */
	while (interrupts) {
		irq_hw_number_t hwirq = fls(interrupts) - 1;
		unsigned int mapping;
		int rc;

		mapping = irq_find_mapping(dpu_kms->irq_controller.domain,
				hwirq);
		if (mapping == 0) {
			DPU_EVT32(hwirq, DPU_EVTLOG_ERROR);
			goto error;
		}

		rc = generic_handle_irq(mapping);
		if (rc < 0) {
			DPU_EVT32(hwirq, mapping, rc, DPU_EVTLOG_ERROR);
			goto error;
		}

		interrupts &= ~(1 << hwirq);
	}

	return IRQ_HANDLED;

error:
	/* bad situation, inform irq system, it may disable overall MDSS irq */
	return IRQ_NONE;
}

void dpu_irq_preinstall(struct msm_kms *kms)
{
	struct dpu_kms *dpu_kms = to_dpu_kms(kms);

	if (!dpu_kms->dev || !dpu_kms->dev->dev) {
		pr_err("invalid device handles\n");
		return;
	}

	dpu_core_irq_preinstall(dpu_kms);
}

int dpu_irq_postinstall(struct msm_kms *kms)
{
	struct dpu_kms *dpu_kms = to_dpu_kms(kms);
	int rc;

	if (!kms) {
		DPU_ERROR("invalid parameters\n");
		return -EINVAL;
	}

	rc = dpu_core_irq_postinstall(dpu_kms);

	return rc;
}

void dpu_irq_uninstall(struct msm_kms *kms)
{
	struct dpu_kms *dpu_kms = to_dpu_kms(kms);

	if (!kms) {
		DPU_ERROR("invalid parameters\n");
		return;
	}

	dpu_core_irq_uninstall(dpu_kms);
	dpu_core_irq_domain_fini(dpu_kms);
}
