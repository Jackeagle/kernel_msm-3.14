// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2014-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */

/*
 * DOC: IPA Interrupts
 *
 * The IPA has an interrupt line distinct from the interrupt used
 * by the GSI code.  Whereas GSI interrupts are generally related
 * to channel events (like transfer completions), IPA interrupts are
 * related to other events related to the IPA.  Some of the IPA
 * interrupts come from a microcontroller embedded in the IPA.
 * Each IPA interrupt type can be both masked and acknowledged
 * independent of the others,
 *
 * So two of the IPA interrupts are initiated by the microcontroller.
 * A third can be generated to signal the need for a wakeup/resume
 * when the IPA has been suspended.  The modem can cause this event
 * to occur (for example, for an incoming call).  There are other IPA
 * events defined, but at this time only these three are supported.
 */

#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>

#include "ipa_i.h"
#include "ipa_clock.h"
#include "ipa_reg.h"

static const int ipa_irq_mapping[] = {
	[IPA_INVALID_IRQ]		= -1,
	[IPA_UC_IRQ_0]			= 2,
	[IPA_UC_IRQ_1]			= 3,
	[IPA_TX_SUSPEND_IRQ]		= 14,
};

/* Workaround disables TX_SUSPEND interrupt for this long */
#define DISABLE_TX_SUSPEND_INTR_DELAY	msecs_to_jiffies(5)

/* Disable the IPA TX_SUSPEND interrupt, and arrange for it to be
 * re-enabled again in 5 milliseconds.
 *
 * This is part of a hardware bug workaround.
 */
static void ipa_tx_suspend_interrupt_wa(struct ipa_context *ipa)
{
	u32 val;

	val = ipa_read_reg_n(IPA_IRQ_EN_EE_N, IPA_EE_AP);
	val &= ~BIT(ipa_irq_mapping[IPA_TX_SUSPEND_IRQ]);
	ipa_write_reg_n(IPA_IRQ_EN_EE_N, IPA_EE_AP, val);

	queue_delayed_work(ipa->interrupt_wq, &ipa->tx_suspend_work,
			   DISABLE_TX_SUSPEND_INTR_DELAY);
}

static void ipa_handle_interrupt(struct ipa_context *ipa, u32 ipa_irq)
{
	struct ipa_interrupt_info *intr_info;
	u32 endpoints = 0;	/* Only TX_SUSPEND uses its interrupt_data */

	intr_info = &ipa->interrupt_info[ipa_irq];
	if (!intr_info->handler)
		return;

	if (intr_info->interrupt == IPA_TX_SUSPEND_IRQ) {
		/* Disable the suspend interrupt temporarily */
		ipa_tx_suspend_interrupt_wa(ipa);

		/* Get and clear mask of endpoints signaling TX_SUSPEND */
		endpoints = ipa_read_reg_n(IPA_IRQ_SUSPEND_INFO_EE_N,
					   IPA_EE_AP);
		ipa_write_reg_n(IPA_SUSPEND_IRQ_CLR_EE_N, IPA_EE_AP, endpoints);
	}

	intr_info->handler(intr_info->interrupt, endpoints);
}

static inline bool is_uc_irq(struct ipa_context *ipa, u32 ipa_irq)
{
	enum ipa_irq_type interrupt = ipa->interrupt_info[ipa_irq].interrupt;

	return interrupt == IPA_UC_IRQ_0 || interrupt == IPA_UC_IRQ_1;
}

static void ipa_process_interrupts(struct ipa_context *ipa)
{
	while (true) {
		u32 ipa_intr_mask;
		u32 imask;	/* one set bit */

		/* Determine which interrupts have fired, then examine only
		 * those that are enabled.  Note that a suspend interrupt
		 * bug forces us to re-read the enabled mask every time to
		 * avoid an endless loop.
		 */
		ipa_intr_mask = ipa_read_reg_n(IPA_IRQ_STTS_EE_N, IPA_EE_AP);
		ipa_intr_mask &= ipa_read_reg_n(IPA_IRQ_EN_EE_N, IPA_EE_AP);

		if (!ipa_intr_mask)
			break;

		do {
			u32 i = (u32)__ffs(ipa_intr_mask);
			bool uc_irq = is_uc_irq(ipa, i);

			imask = BIT(i);

			/* Clear uC interrupt before processing to avoid
			 * clearing unhandled interrupts
			 */
			if (uc_irq)
				ipa_write_reg_n(IPA_IRQ_CLR_EE_N, IPA_EE_AP,
						imask);

			ipa_handle_interrupt(ipa, i);

			/* Clear non-uC interrupt after processing
			 * to avoid clearing interrupt data
			 */
			if (!uc_irq)
				ipa_write_reg_n(IPA_IRQ_CLR_EE_N, IPA_EE_AP,
						imask);
		} while ((ipa_intr_mask ^= imask));
	}
}

static void ipa_interrupt_work_func(struct work_struct *work)
{
	struct ipa_context *ipa;

	ipa = container_of(work, struct ipa_context, interrupt_work);

	ipa_clock_get(ipa);

	ipa_process_interrupts(ipa);

	ipa_clock_put(ipa);
}

static irqreturn_t ipa_isr(int irq, void *dev_id)
{
	struct ipa_context *ipa = dev_id;

	/* Schedule handling (if not already scheduled) */
	queue_work(ipa->interrupt_wq, &ipa->interrupt_work);

	return IRQ_HANDLED;
}

/* Re-enable the IPA TX_SUSPEND interrupt after having been disabled
 * for a moment by ipa_tx_suspend_interrupt_wa().  This is part of a
 * workaround for a hardware bug.
 */
static void enable_tx_suspend_work_func(struct work_struct *work)
{
	struct ipa_context *ipa;
	u32 val;

	ipa = container_of(work, struct ipa_context, tx_suspend_work.work);

	ipa_clock_get(ipa);

	val = ipa_read_reg_n(IPA_IRQ_EN_EE_N, IPA_EE_AP);
	val |= BIT(ipa_irq_mapping[IPA_TX_SUSPEND_IRQ]);
	ipa_write_reg_n(IPA_IRQ_EN_EE_N, IPA_EE_AP, val);

	ipa_process_interrupts(ipa);

	ipa_clock_put(ipa);
}

/* Register SUSPEND_IRQ_EN_EE_N_ADDR for L2 interrupt. */
static void tx_suspend_enable(void)
{
	enum ipa_client_type client;
	u32 val = ~0;

	/* Compute the mask to use (bits set for all non-modem endpoints) */
	for (client = 0; client < IPA_CLIENT_MAX; client++)
		if (ipa_modem_consumer(client) || ipa_modem_producer(client))
			val &= ~BIT(ipa_client_ep_id(client));

	ipa_write_reg_n(IPA_SUSPEND_IRQ_EN_EE_N, IPA_EE_AP, val);
}

/* Unregister SUSPEND_IRQ_EN_EE_N_ADDR for L2 interrupt. */
static void tx_suspend_disable(void)
{
	ipa_write_reg_n(IPA_SUSPEND_IRQ_EN_EE_N, IPA_EE_AP, 0);
}

/**
 * ipa_add_interrupt_handler() - Adds handler for an IPA interrupt
 * @interrupt:		IPA interrupt type
 * @handler:		The handler for that interrupt
 *
 * Adds handler to an IPA interrupt type and enable it.  IPA interrupt
 * handlers are allowed to block (they aren't run in interrupt context).
 */
void ipa_add_interrupt_handler(struct ipa_context *ipa,
			       enum ipa_irq_type interrupt,
			       ipa_irq_handler_t handler)
{
	u32 ipa_irq = ipa_irq_mapping[interrupt];
	struct ipa_interrupt_info *intr_info;
	u32 val;

	intr_info = &ipa->interrupt_info[ipa_irq];
	intr_info->handler = handler;
	intr_info->interrupt = interrupt;

	/* Enable the IPA interrupt */
	val = ipa_read_reg_n(IPA_IRQ_EN_EE_N, IPA_EE_AP);
	val |= BIT(ipa_irq);
	ipa_write_reg_n(IPA_IRQ_EN_EE_N, IPA_EE_AP, val);

	if (interrupt == IPA_TX_SUSPEND_IRQ)
		tx_suspend_enable();
}

/**
 * ipa_remove_interrupt_handler() - Removes handler for an IPA interrupt type
 * @interrupt:		IPA interrupt type
 *
 * Remove an IPA interrupt handler and disable it.
 */
void ipa_remove_interrupt_handler(struct ipa_context *ipa,
				  enum ipa_irq_type interrupt)
{
	u32 ipa_irq = ipa_irq_mapping[interrupt];
	struct ipa_interrupt_info *intr_info;
	u32 val;

	intr_info = &ipa->interrupt_info[ipa_irq];
	intr_info->handler = NULL;
	intr_info->interrupt = IPA_INVALID_IRQ;

	if (interrupt == IPA_TX_SUSPEND_IRQ)
		tx_suspend_disable();

	/* Disable the interrupt */
	val = ipa_read_reg_n(IPA_IRQ_EN_EE_N, IPA_EE_AP);
	val &= ~BIT(ipa_irq);
	ipa_write_reg_n(IPA_IRQ_EN_EE_N, IPA_EE_AP, val);
}

/**
 * ipa_interrupts_init() - Initialize the IPA interrupts framework
 */
int ipa_interrupt_init(struct ipa_context *ipa)
{
	int ret;

	ret = platform_get_irq_byname(ipa->pdev, "ipa");
	if (ret < 0)
		return ret;
	ipa->irq = ret;

	ret = request_irq(ipa->irq, ipa_isr, IRQF_TRIGGER_RISING, "ipa", ipa);
	if (ret)
		goto err_clear_irq;

	INIT_WORK(&ipa->interrupt_work, ipa_interrupt_work_func);
	INIT_DELAYED_WORK(&ipa->tx_suspend_work, enable_tx_suspend_work_func);
	ipa->interrupt_wq = alloc_ordered_workqueue("ipa_interrupt_wq", 0);
	if (ipa->interrupt_wq)
		return 0;	/* Success */
	ret = -ENOMEM;

	free_irq(ipa->irq, ipa);
err_clear_irq:
	ipa->irq = 0;

	return ret;
}

void ipa_interrupt_exit(struct ipa_context *ipa)
{
	free_irq(ipa->irq, ipa);
	ipa->irq = 0;
	cancel_delayed_work_sync(&ipa->tx_suspend_work);
	memset(&ipa->tx_suspend_work, 0, sizeof(ipa->tx_suspend_work));
	cancel_work_sync(&ipa->interrupt_work);
	memset(&ipa->interrupt_work, 0, sizeof(ipa->interrupt_work));
	destroy_workqueue(ipa->interrupt_wq);
	ipa->interrupt_wq = NULL;
}

/**
 * ipa_suspend_active_aggr_wa() - Emulate suspend interrupt
 * @ep_id:	Endpoint on which to emulate a suspend
 *
 *  Emulate suspend IRQ to unsuspend a client suspended with an open
 *  aggregation frame.  This is to work around a hardware issue
 *  where an IRQ is not generated as it should be when this occurs.
 */
void ipa_suspend_active_aggr_wa(struct ipa_context *ipa, u32 ep_id)
{
	struct ipa_reg_aggr_force_close force_close;
	struct ipa_interrupt_info *intr_info;
	u32 clnt_mask;
	u32 ipa_irq;

	ipa_irq = ipa_irq_mapping[IPA_TX_SUSPEND_IRQ];
	intr_info = &ipa->interrupt_info[ipa_irq];
	clnt_mask = BIT(ep_id);

	/* Nothing to do if the endpoint doesn't have aggregation open */
	if (!(ipa_read_reg(IPA_STATE_AGGR_ACTIVE) & clnt_mask))
		return;

	/* Force close aggregation */
	ipa_reg_aggr_force_close(&force_close, clnt_mask);
	ipa_write_reg_fields(IPA_AGGR_FORCE_CLOSE, &force_close);

	/* Simulate suspend IRQ */
	ipa_assert(!in_interrupt());
	if (intr_info->handler)
		intr_info->handler(intr_info->interrupt, clnt_mask);
}
