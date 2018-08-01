// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2014-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#define pr_fmt(fmt)    "ipa %s:%d " fmt, __func__, __LINE__

#include <linux/interrupt.h>
#include "ipa_i.h"

/* Workaround disables TX_SUSPEND interrupt for this long */
#define DIS_TX_SUSPEND_INTR_DELAY	msecs_to_jiffies(5)

struct ipa_interrupt_info {
	ipa_irq_handler_t handler;
	enum ipa_irq_type interrupt;
};

#define IPA_IRQ_NUM_MAX 32	/* Number of IRQ bits in IPA interrupt mask */
static struct ipa_interrupt_info ipa_interrupt_info[IPA_IRQ_NUM_MAX];

static struct workqueue_struct *ipa_interrupt_wq;

static void enable_tx_suspend_work_func(struct work_struct *work);
static DECLARE_DELAYED_WORK(tx_suspend_work, enable_tx_suspend_work_func);
static spinlock_t suspend_wa_lock;

static const int ipa_irq_mapping[] = {
	[IPA_INVALID_IRQ]			= -1,
	[IPA_UC_IRQ_0]				= 2,
	[IPA_UC_IRQ_1]				= 3,
	[IPA_TX_SUSPEND_IRQ]			= 14,
};

/* IPA interrupt handlers are called in contexts that can block */
static void ipa_interrupt_work_func(struct work_struct *work);
static DECLARE_WORK(ipa_interrupt_work, ipa_interrupt_work_func);

/* Disable the IPA TX_SUSPEND interrupt, and arrange for it to be
 * re-enabled again in 5 milliseconds.
 *
 * This is part of a hardware bug workaround.
 */
static void ipa_tx_suspend_interrupt_wa(void)
{
	u32 val;

	ipa_debug_low("briefly disabling TX_SUSPEND interrupt\n");

	val = ipahal_read_reg_n(IPA_IRQ_EN_EE_n, IPA_EE_AP);
	val &= ~BIT(ipa_irq_mapping[IPA_TX_SUSPEND_IRQ]);
	ipahal_write_reg_n(IPA_IRQ_EN_EE_n, IPA_EE_AP, val);

	queue_delayed_work(ipa_interrupt_wq, &tx_suspend_work,
			   DIS_TX_SUSPEND_INTR_DELAY);
}

static void ipa_handle_interrupt(int irq_num)
{
	struct ipa_interrupt_info *intr_info = &ipa_interrupt_info[irq_num];
	u32 endpoints = 0;	/* Only TX_SUSPEND uses its interrupt_data */

	if (!intr_info->handler)
		return;

	if (intr_info->interrupt == IPA_TX_SUSPEND_IRQ) {
		/* Implement a workaround for a hardware problem */
		ipa_tx_suspend_interrupt_wa();

		/* Get and clear mask of endpoints signaling TX_SUSPEND */
		endpoints = ipahal_read_reg_n(IPA_IRQ_SUSPEND_INFO_EE_n,
					      IPA_EE_AP);
		ipahal_write_reg_n(IPA_SUSPEND_IRQ_CLR_EE_n, IPA_EE_AP,
				   endpoints);
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
	unsigned long flags;

	ipa_debug_low("Enter\n");

	spin_lock_irqsave(&suspend_wa_lock, flags);

	while (true) {
		u32 ipa_intr_mask;
		u32 imask;	/* one set bit */

		/*
		 * Determine which interrupts have fired, then examine only
		 * those that are enabled.  Note that a suspend interrupt
		 * bug forces us to re-read the enabled mask every time to
		 * avoid an endless loop.
		 */
		ipa_intr_mask = ipahal_read_reg_n(IPA_IRQ_STTS_EE_n, IPA_EE_AP);
		ipa_intr_mask &= ipahal_read_reg_n(IPA_IRQ_EN_EE_n, IPA_EE_AP);

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
				ipahal_write_reg_n(IPA_IRQ_CLR_EE_n, IPA_EE_AP,
						   imask);

			/* Handle the interrupt with spin_lock unlocked to
			 * avoid calling client in atomic context.  Mutual
			 * exclusion still preserved as the read/clr is done
			 * with spin_lock locked.
			 */
			spin_unlock_irqrestore(&suspend_wa_lock, flags);

			ipa_handle_interrupt(i);

			spin_lock_irqsave(&suspend_wa_lock, flags);

			/* Clear non uC interrupt after processing
			 * to avoid clearing interrupt data
			 * */
			if (!uc_irq)
				ipahal_write_reg_n(IPA_IRQ_CLR_EE_n, IPA_EE_AP,
						   imask);
		} while ((ipa_intr_mask ^= imask));
	}

	spin_unlock_irqrestore(&suspend_wa_lock, flags);
	ipa_debug_low("Exit\n");
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
 * for a moment by ipa_tx_suspend_interrupt_wa().  This ex
 *
 * This is part of a hardware bug workaround.
 */
static void enable_tx_suspend_work_func(struct work_struct *work)
{
	u32 val;

	ipa_client_add();

	val = ipahal_read_reg_n(IPA_IRQ_EN_EE_n, IPA_EE_AP);
	val |= BIT(ipa_irq_mapping[IPA_TX_SUSPEND_IRQ]);
	ipahal_write_reg_n(IPA_IRQ_EN_EE_n, IPA_EE_AP, val);

	ipa_process_interrupts();

	ipa_client_remove();
}

/* Register SUSPEND_IRQ_EN_EE_N_ADDR for L2 interrupt.
 * Note the following must not be executed for IPA hardware
 * versions prior to 3.1.
 */
static void tx_suspend_enable(void)
{
	enum ipa_client_type client;
	u32 val = ~0;

	/* Compute the mask to use (bits set for all non-modem endpoints) */
	for (client = 0; client < IPA_CLIENT_MAX; client++)
		if (ipa_modem_consumer(client) || ipa_modem_producer(client))
			val &= ~BIT(ipa_get_ep_mapping(client));

	ipahal_write_reg_n(IPA_SUSPEND_IRQ_EN_EE_n, IPA_EE_AP, val);
}

/* Unregister SUSPEND_IRQ_EN_EE_N_ADDR for L2 interrupt.
 * Note the following must not be executed for IPA hardware
 * versions prior to 3.1.
 */
static void tx_suspend_disable(void)
{
	ipahal_write_reg_n(IPA_SUSPEND_IRQ_EN_EE_n, IPA_EE_AP, 0);
}

/** ipa_add_interrupt_handler() - Adds handler to an interrupt type
 * @interrupt:		Interrupt type
 * @handler:		The handler to be added
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

	ipa_debug("%s: interrupt_enum %d irq_num %d\n", __func__,
		  interrupt, irq_num);

	intr_info->handler = handler;
	intr_info->interrupt = interrupt;

	val = ipahal_read_reg_n(IPA_IRQ_EN_EE_n, IPA_EE_AP);
	ipa_debug("read IPA_IRQ_EN_EE_n register. reg = %d\n", val);
	val |= BIT(irq_num);
	ipahal_write_reg_n(IPA_IRQ_EN_EE_n, IPA_EE_AP, val);
	ipa_debug("wrote IPA_IRQ_EN_EE_n register. reg = %d\n", val);

	if (interrupt == IPA_TX_SUSPEND_IRQ)
		tx_suspend_enable();
}

/** ipa_remove_interrupt_handler() - Removes handler to an interrupt type
 * @interrupt:		Interrupt type
 *
 * Removes the handler and disable the specific bit in IRQ_EN register
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

	val = ipahal_read_reg_n(IPA_IRQ_EN_EE_n, IPA_EE_AP);
	val &= ~BIT(irq_num);
	ipahal_write_reg_n(IPA_IRQ_EN_EE_n, IPA_EE_AP, val);
}

/** ipa_interrupts_init() - Initialize the IPA interrupts framework
 * @ipa_irq:	The interrupt number to allocate
 * @ipa_dev:	The basic device structure representing the IPA driver
 *
 * - Initialize the ipa_interrupt_info array
 * - Clear interrupts status
 * - Register the ipa interrupt handler - ipa_isr
 * - Enable apps processor wakeup by IPA interrupts
 */
int ipa_interrupts_init(u32 ipa_irq, struct device *ipa_dev)
{
	int ret;

	ipa_interrupt_wq = create_singlethread_workqueue("ipa_interrupt_wq");
	if (!ipa_interrupt_wq)
		return -ENOMEM;

	ret = request_irq(ipa_irq, ipa_isr, IRQF_TRIGGER_RISING, "ipa",
			  ipa_dev);
	if (ret) {
		destroy_workqueue(ipa_interrupt_wq);
		ipa_interrupt_wq = NULL;
		return ret;
	}

	spin_lock_init(&suspend_wa_lock);

	return 0;
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
	int irq_num = ipa_irq_mapping[IPA_TX_SUSPEND_IRQ];
	struct ipa_interrupt_info *intr_info = &ipa_interrupt_info[irq_num];
	u32 clnt_mask = BIT(clnt_hdl);

	/* Nothing to do if the endpoint doesn't have aggregation open */
	if (!(ipahal_read_reg(IPA_STATE_AGGR_ACTIVE) & clnt_mask))
		return;

	/* Force close aggregation */
	ipahal_write_reg(IPA_AGGR_FORCE_CLOSE, clnt_mask);

	/* Simulate suspend IRQ */
	ipa_assert(!in_interrupt());
	if (intr_info->handler)
		intr_info->handler(intr_info->interrupt, clnt_mask);
}
