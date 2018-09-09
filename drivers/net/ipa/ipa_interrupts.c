// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2014-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#define pr_fmt(fmt)    "ipa %s:%d " fmt, __func__, __LINE__

/* The IPA supports generating an interrupt on a number of events
 * using a single IRQ.  When the IPA IRQ fires, an IPA interrupt
 * status register indicates which IPA interrupt events are being
 * signaled.  Each IPA interrupt is acknowledged by writing its bit
 * to an interrupt clear register.  Finally, another register is
 * used to mask (or rather, enable) particular IPA interrupts.
 */

#include <linux/interrupt.h>
#include "ipa_i.h"

struct ipa_interrupt_info {
	ipa_irq_handler_t handler;
	enum ipa_irq_type interrupt;
};

#define IPA_IRQ_NUM_MAX	32	/* Number of IRQ bits in IPA interrupt mask */
static struct ipa_interrupt_info ipa_interrupt_info[IPA_IRQ_NUM_MAX];

static struct workqueue_struct *ipa_interrupt_wq;

static void enable_tx_suspend_work_func(struct work_struct *work);
static DECLARE_DELAYED_WORK(tx_suspend_work, enable_tx_suspend_work_func);

static const int ipa_irq_mapping[] = {
	[IPA_INVALID_IRQ]		= -1,
	[IPA_UC_IRQ_0]			= 2,
	[IPA_UC_IRQ_1]			= 3,
	[IPA_TX_SUSPEND_IRQ]		= 14,
};

/* IPA interrupt handlers are called in contexts that can block */
static void ipa_interrupt_work_func(struct work_struct *work);
static DECLARE_WORK(ipa_interrupt_work, ipa_interrupt_work_func);

/* Workaround disables TX_SUSPEND interrupt for this long */
#define DISABLE_TX_SUSPEND_INTR_DELAY	msecs_to_jiffies(5)

/* Disable the IPA TX_SUSPEND interrupt, and arrange for it to be
 * re-enabled again in 5 milliseconds.
 *
 * This is part of a hardware bug workaround.
 */
static void ipa_tx_suspend_interrupt_wa(void)
{
	u32 val;

	val = ipa_read_reg_n(IPA_IRQ_EN_EE_N, IPA_EE_AP);
	val &= ~BIT(ipa_irq_mapping[IPA_TX_SUSPEND_IRQ]);
	ipa_write_reg_n(IPA_IRQ_EN_EE_N, IPA_EE_AP, val);

	queue_delayed_work(ipa_interrupt_wq, &tx_suspend_work,
			   DISABLE_TX_SUSPEND_INTR_DELAY);
}

static void ipa_handle_interrupt(int irq_num)
{
	struct ipa_interrupt_info *intr_info = &ipa_interrupt_info[irq_num];
	u32 endpoints = 0;	/* Only TX_SUSPEND uses its interrupt_data */

	if (!intr_info->handler)
		return;

	if (intr_info->interrupt == IPA_TX_SUSPEND_IRQ) {
		/* Disable the suspend interrupt temporarily */
		ipa_tx_suspend_interrupt_wa();

		/* Get and clear mask of endpoints signaling TX_SUSPEND */
		endpoints = ipa_read_reg_n(IPA_IRQ_SUSPEND_INFO_EE_N,
					   IPA_EE_AP);
		ipa_write_reg_n(IPA_SUSPEND_IRQ_CLR_EE_N, IPA_EE_AP, endpoints);
	}

	intr_info->handler(intr_info->interrupt, endpoints);
}

static inline bool is_uc_irq(int irq_num)
{
	enum ipa_irq_type interrupt = ipa_interrupt_info[irq_num].interrupt;

	return interrupt != IPA_UC_IRQ_0 && interrupt != IPA_UC_IRQ_1;
}

static void ipa_process_interrupts(void)
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
			int i = __ffs(ipa_intr_mask);
			bool uc_irq = is_uc_irq(i);

			imask = BIT(i);

			/* Clear uC interrupt before processing to avoid
			 * clearing unhandled interrupts
			 */
			if (uc_irq)
				ipa_write_reg_n(IPA_IRQ_CLR_EE_N, IPA_EE_AP,
						imask);

			ipa_handle_interrupt(i);

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
	ipa_client_add();

	ipa_process_interrupts();

	ipa_client_remove();
}

static irqreturn_t ipa_isr(int irq, void *ctxt)
{
	/* Schedule handling (if not already scheduled) */
	queue_work(ipa_interrupt_wq, &ipa_interrupt_work);

	return IRQ_HANDLED;
}

/* Re-enable the IPA TX_SUSPEND interrupt after having been disabled
 * for a moment by ipa_tx_suspend_interrupt_wa().  This is part of a
 * workaround for a hardware bug.
 */
static void enable_tx_suspend_work_func(struct work_struct *work)
{
	u32 val;

	ipa_client_add();

	val = ipa_read_reg_n(IPA_IRQ_EN_EE_N, IPA_EE_AP);
	val |= BIT(ipa_irq_mapping[IPA_TX_SUSPEND_IRQ]);
	ipa_write_reg_n(IPA_IRQ_EN_EE_N, IPA_EE_AP, val);

	ipa_process_interrupts();

	ipa_client_remove();
}

/* Register SUSPEND_IRQ_EN_EE_N_ADDR for L2 interrupt. */
static void tx_suspend_enable(void)
{
	enum ipa_client_type client;
	u32 val = ~0;

	/* Compute the mask to use (bits set for all non-modem endpoints) */
	for (client = 0; client < IPA_CLIENT_MAX; client++)
		if (ipa_modem_consumer(client) || ipa_modem_producer(client))
			val &= ~BIT(ipa_get_ep_mapping(client));

	ipa_write_reg_n(IPA_SUSPEND_IRQ_EN_EE_N, IPA_EE_AP, val);
}

/* Unregister SUSPEND_IRQ_EN_EE_N_ADDR for L2 interrupt. */
static void tx_suspend_disable(void)
{
	ipa_write_reg_n(IPA_SUSPEND_IRQ_EN_EE_N, IPA_EE_AP, 0);
}

/** ipa_add_interrupt_handler() - Adds handler for an IPA interrupt
 * @interrupt:		IPA interrupt type
 * @handler:		The handler for that interrupt
 *
 * Adds handler to an IPA interrupt type and enable it.  IPA interrupt
 * handlers are allowed to block (they aren't run in interrupt context).
 */
void ipa_add_interrupt_handler(enum ipa_irq_type interrupt,
			       ipa_irq_handler_t handler)
{
	int irq_num = ipa_irq_mapping[interrupt];
	struct ipa_interrupt_info *intr_info = &ipa_interrupt_info[irq_num];
	u32 val;

	intr_info->handler = handler;
	intr_info->interrupt = interrupt;

	/* Enable the IPA interrupt */
	val = ipa_read_reg_n(IPA_IRQ_EN_EE_N, IPA_EE_AP);
	val |= BIT(irq_num);
	ipa_write_reg_n(IPA_IRQ_EN_EE_N, IPA_EE_AP, val);

	if (interrupt == IPA_TX_SUSPEND_IRQ)
		tx_suspend_enable();
}

/** ipa_remove_interrupt_handler() - Removes handler for an IPA interrupt type
 * @interrupt:		IPA interrupt type
 *
 * Remove an IPA interrupt handler and disable it.
 */
void ipa_remove_interrupt_handler(enum ipa_irq_type interrupt)
{
	int irq_num = ipa_irq_mapping[interrupt];
	struct ipa_interrupt_info *intr_info = &ipa_interrupt_info[irq_num];
	u32 val;

	intr_info->handler = NULL;
	intr_info->interrupt = IPA_INVALID_IRQ;

	if (interrupt == IPA_TX_SUSPEND_IRQ)
		tx_suspend_disable();

	/* Disable the interrupt */
	val = ipa_read_reg_n(IPA_IRQ_EN_EE_N, IPA_EE_AP);
	val &= ~BIT(irq_num);
	ipa_write_reg_n(IPA_IRQ_EN_EE_N, IPA_EE_AP, val);
}

/** ipa_interrupts_init() - Initialize the IPA interrupts framework */
int ipa_interrupts_init(void)
{
	int ret;

	ret = request_irq(ipa_ctx->ipa_irq, ipa_isr, IRQF_TRIGGER_RISING,
			  "ipa", ipa_ctx->dev);
	if (ret)
		return ret;

	ipa_interrupt_wq = alloc_ordered_workqueue("ipa_interrupt_wq", 0);
	if (ipa_interrupt_wq)
		return 0;

	free_irq(ipa_ctx->ipa_irq, ipa_ctx->dev);

	return -ENOMEM;
}

/** ipa_suspend_active_aggr_wa() - Emulate suspend IRQ
 * @clnt_hndl:		suspended client handle, IRQ is emulated for this pipe
 *
 *  Emulate suspend IRQ to unsuspend client which was suspended with an open
 *  aggregation frame in order to bypass HW bug of IRQ not generated when
 *  endpoint is suspended during an open aggregation.
 */
void ipa_suspend_active_aggr_wa(u32 clnt_hdl)
{
	struct ipa_reg_aggr_force_close force_close;
	int irq_num = ipa_irq_mapping[IPA_TX_SUSPEND_IRQ];
	struct ipa_interrupt_info *intr_info = &ipa_interrupt_info[irq_num];
	u32 clnt_mask = BIT(clnt_hdl);

	/* Nothing to do if the endpoint doesn't have aggregation open */
	if (!(ipa_read_reg(IPA_STATE_AGGR_ACTIVE) & clnt_mask))
		return;

	/* Force close aggregation */
	force_close.pipe_bitmap = clnt_mask;
	ipa_write_reg_fields(IPA_AGGR_FORCE_CLOSE, &force_close);

	/* Simulate suspend IRQ */
	ipa_assert(!in_interrupt());
	if (intr_info->handler)
		intr_info->handler(intr_info->interrupt, clnt_mask);
}
