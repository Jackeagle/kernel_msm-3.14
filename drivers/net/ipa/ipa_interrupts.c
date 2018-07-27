// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2014-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#define pr_fmt(fmt)    "ipa %s:%d " fmt, __func__, __LINE__

#include <linux/interrupt.h>
#include "ipa_i.h"

#define DIS_SUSPEND_INTERRUPT_TIMEOUT 5		/* msec */
#define IPA_IRQ_NUM_MAX 32

struct ipa_interrupt_info {
	ipa_irq_handler_t handler;
	enum ipa_irq_type interrupt;
	bool deferred_flag;
};

struct ipa_interrupt_work_wrap {
	struct work_struct interrupt_work;
	ipa_irq_handler_t handler;
	enum ipa_irq_type interrupt;
	void *interrupt_data;
};

static struct ipa_interrupt_info ipa_interrupt_to_cb[IPA_IRQ_NUM_MAX];
static struct workqueue_struct *ipa_interrupt_wq;

static void ipa_tx_suspend_interrupt_wa(void);
static void ipa_enable_tx_suspend_wa(struct work_struct *work);
static DECLARE_DELAYED_WORK(dwork_en_suspend_int, ipa_enable_tx_suspend_wa);
static spinlock_t suspend_wa_lock;
static void ipa_process_interrupts(bool isr_context);

/* Unsupported interrupt types have value -1 in this table */
static const int ipa_irq_mapping[IPA_IRQ_MAX] = {
	[IPA_UC_TX_CMD_Q_NOT_FULL_IRQ]		= -1,
	[IPA_UC_TO_PROC_ACK_Q_NOT_FULL_IRQ]	= -1,
	[IPA_BAD_SNOC_ACCESS_IRQ]		= 0,
	[IPA_EOT_COAL_IRQ]			= -1,
	[IPA_UC_IRQ_0]				= 2,
	[IPA_UC_IRQ_1]				= 3,
	[IPA_UC_IRQ_2]				= 4,
	[IPA_UC_IRQ_3]				= 5,
	[IPA_UC_IN_Q_NOT_EMPTY_IRQ]		= 6,
	[IPA_UC_RX_CMD_Q_NOT_FULL_IRQ]		= 7,
	[IPA_PROC_TO_UC_ACK_Q_NOT_EMPTY_IRQ]	= 8,
	[IPA_RX_ERR_IRQ]			= 9,
	[IPA_DEAGGR_ERR_IRQ]			= 10,
	[IPA_TX_ERR_IRQ]			= 11,
	[IPA_STEP_MODE_IRQ]			= 12,
	[IPA_PROC_ERR_IRQ]			= 13,
	[IPA_TX_SUSPEND_IRQ]			= 14,
	[IPA_TX_HOLB_DROP_IRQ]			= 15,
	[IPA_GSI_IDLE_IRQ]			= 16,
};

static void ipa_interrupt_defer(struct work_struct *work);
static DECLARE_WORK(ipa_interrupt_defer_work, ipa_interrupt_defer);

static void ipa_deferred_interrupt_work(struct work_struct *work)
{
	struct ipa_interrupt_work_wrap *work_data =
			container_of(work, struct ipa_interrupt_work_wrap,
				     interrupt_work);
	ipa_debug("call handler from workq...\n");
	work_data->handler(work_data->interrupt, work_data->interrupt_data);
	kfree(work_data->interrupt_data);
	kfree(work_data);
}

static bool ipa_is_valid_ep(u32 ep_suspend_data)
{
	while (ep_suspend_data) {
		int i = __ffs(ep_suspend_data);

		if (ipa_ctx->ep[i].valid)
			return true;

		ep_suspend_data ^= BIT(i);
	}

	return false;
}

static void ipa_handle_interrupt(int irq_num, bool isr_context)
{
	struct ipa_interrupt_info *interrupt_info;
	struct ipa_interrupt_work_wrap *work_data;
	u32 suspend_data;
	struct ipa_tx_suspend_irq_data *interrupt_data = NULL;

	interrupt_info = &ipa_interrupt_to_cb[irq_num];
	if (!interrupt_info->handler) {
		ipa_err("A callback function wasn't set for interrupt num %d\n",
			irq_num);
		return;
	}

	switch (interrupt_info->interrupt) {
	case IPA_TX_SUSPEND_IRQ:
		ipa_debug_low("processing TX_SUSPEND interrupt work-around\n");
		ipa_tx_suspend_interrupt_wa();
		suspend_data = ipahal_read_reg_n(IPA_IRQ_SUSPEND_INFO_EE_n,
						 IPA_EE_AP);
		ipa_debug_low("get interrupt %d\n", suspend_data);

		/* Clear L2 interrupts status.  Note the following
		 * must not be executed for IPA hardware versions
		 * prior to 3.1.
		 */
		ipahal_write_reg_n(IPA_SUSPEND_IRQ_CLR_EE_n,
				   IPA_EE_AP, suspend_data);
		if (!ipa_is_valid_ep(suspend_data))
			return;

		interrupt_data = kzalloc(sizeof(*interrupt_data), GFP_ATOMIC);
		if (!interrupt_data) {
			ipa_err("failed allocating interrupt_data\n");
			return;
		}
		interrupt_data->endpoints = suspend_data;
		break;
	case IPA_UC_IRQ_0:
		break;
	default:
		break;
	}

	/* Force defer processing if in ISR context. */
	if (interrupt_info->deferred_flag || isr_context) {
		work_data = kzalloc(sizeof(*work_data), GFP_ATOMIC);
		if (!work_data) {
			kfree(interrupt_data);
			return;
		}
		INIT_WORK(&work_data->interrupt_work,
			  ipa_deferred_interrupt_work);
		work_data->handler = interrupt_info->handler;
		work_data->interrupt = interrupt_info->interrupt;
		work_data->interrupt_data = interrupt_data;
		queue_work(ipa_interrupt_wq, &work_data->interrupt_work);

	} else {
		interrupt_info->handler(interrupt_info->interrupt,
				        interrupt_data);
		kfree(interrupt_data);
	}
}

static void ipa_enable_tx_suspend_wa(struct work_struct *work)
{
	u32 en;
	u32 suspend_bmask;
	int irq_num;

	ipa_debug_low("Enter\n");

	irq_num = ipa_irq_mapping[IPA_TX_SUSPEND_IRQ];
	ipa_assert(irq_num != -1);

	/* make sure ipa hw is clocked on*/
	ipa_client_add(__func__, false);

	en = ipahal_read_reg_n(IPA_IRQ_EN_EE_n, IPA_EE_AP);
	suspend_bmask = BIT(irq_num);
	/*enable  TX_SUSPEND_IRQ*/
	en |= suspend_bmask;
	ipa_debug("enable TX_SUSPEND_IRQ, IPA_IRQ_EN_EE reg, write val = %u\n"
		, en);
	ipahal_write_reg_n(IPA_IRQ_EN_EE_n, IPA_EE_AP, en);
	ipa_process_interrupts(false);
	ipa_client_remove(__func__, false);

	ipa_debug_low("Exit\n");
}

static void ipa_tx_suspend_interrupt_wa(void)
{
	u32 val;
	u32 suspend_bmask;
	int irq_num;

	ipa_debug_low("Enter\n");
	irq_num = ipa_irq_mapping[IPA_TX_SUSPEND_IRQ];
	ipa_assert(irq_num != -1);

	/*disable TX_SUSPEND_IRQ*/
	val = ipahal_read_reg_n(IPA_IRQ_EN_EE_n, IPA_EE_AP);
	suspend_bmask = BIT(irq_num);
	val &= ~suspend_bmask;
	ipa_debug("Disable TX_SUSPEND_IRQ write %u to IPA_IRQ_EN_EE\n", val);
	ipahal_write_reg_n(IPA_IRQ_EN_EE_n, IPA_EE_AP, val);

	ipa_debug_low("processing suspend interrupt WA delayed work\n");
	queue_delayed_work(ipa_interrupt_wq, &dwork_en_suspend_int,
			   msecs_to_jiffies(DIS_SUSPEND_INTERRUPT_TIMEOUT));

	ipa_debug_low("Exit\n");
}

static inline bool is_uc_irq(int irq_num)
{
	return ipa_interrupt_to_cb[irq_num].interrupt >= IPA_UC_IRQ_0 &&
		ipa_interrupt_to_cb[irq_num].interrupt <= IPA_UC_IRQ_3;
}

static void ipa_process_interrupts(bool isr_context)
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

			ipa_handle_interrupt(i, isr_context);

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

static void ipa_interrupt_defer(struct work_struct *work)
{
	ipa_debug("processing interrupts in wq\n");
	ipa_client_add(__func__, false);
	ipa_process_interrupts(false);
	ipa_client_remove(__func__, false);
	ipa_debug("Done\n");
}

static irqreturn_t ipa_isr(int irq, void *ctxt)
{
	ipa_debug_low("Enter\n");
	/* defer interrupt handling in case IPA is not clocked on */
	if (!ipa_client_add_additional(__func__, false)) {
		ipa_debug("defer interrupt processing\n");
		queue_work(ipa_ctx->power_mgmt_wq, &ipa_interrupt_defer_work);
		return IRQ_HANDLED;
	}

	ipa_process_interrupts(true);
	ipa_debug_low("Exit\n");

	ipa_client_remove(__func__, false);

	return IRQ_HANDLED;
}

/** ipa_add_interrupt_handler() - Adds handler to an interrupt type
 * @interrupt:		Interrupt type
 * @handler:		The handler to be added
 * @deferred_flag:	whether the handler processing should be deferred in
 *			a workqueue
 *
 * Adds handler to an interrupt type and enable the specific bit
 * in IRQ_EN register, associated interrupt in IRQ_STTS register will be enabled
 */
void ipa_add_interrupt_handler(enum ipa_irq_type interrupt,
			      ipa_irq_handler_t handler, bool deferred_flag)
{
	int irq_num = ipa_irq_mapping[interrupt];
	struct ipa_interrupt_info *interrupt_info;
	int client_idx;
	u32 val;

	ipa_debug("%s: interrupt_enum %d irq_num %d\n", __func__,
		  interrupt, irq_num);

	ipa_assert(irq_num >= 0);

	interrupt_info = &ipa_interrupt_to_cb[irq_num];
	interrupt_info->deferred_flag = deferred_flag;
	interrupt_info->handler = handler;
	interrupt_info->interrupt = interrupt;

	val = ipahal_read_reg_n(IPA_IRQ_EN_EE_n, IPA_EE_AP);
	ipa_debug("read IPA_IRQ_EN_EE_n register. reg = %d\n", val);
	val |= BIT(irq_num);
	ipahal_write_reg_n(IPA_IRQ_EN_EE_n, IPA_EE_AP, val);
	ipa_debug("wrote IPA_IRQ_EN_EE_n register. reg = %d\n", val);

	if (interrupt != IPA_TX_SUSPEND_IRQ)
		return;

	/* Register SUSPEND_IRQ_EN_EE_N_ADDR for L2 interrupt.
	 * Note the following must not be executed for IPA hardware
	 * versions prior to 3.1.
	 */
	val = ~0;
	for (client_idx = 0; client_idx < IPA_CLIENT_MAX; client_idx++)
		if (ipa_modem_consumer(client_idx) ||
				ipa_modem_producer(client_idx)) {
			u32 ep_idx = ipa_get_ep_mapping(client_idx);

			ipa_debug("modem ep_idx(%u) client_idx = %d\n",
					ep_idx, client_idx);

			val &= ~BIT(ep_idx);
		}

	ipahal_write_reg_n(IPA_SUSPEND_IRQ_EN_EE_n, IPA_EE_AP, val);
	ipa_debug("wrote IPA_SUSPEND_IRQ_EN_EE_n reg = %d\n", val);
}

/** ipa_remove_interrupt_handler() - Removes handler to an interrupt type
 * @interrupt:		Interrupt type
 *
 * Removes the handler and disable the specific bit in IRQ_EN register
 */
void ipa_remove_interrupt_handler(enum ipa_irq_type interrupt)
{
	int irq_num = ipa_irq_mapping[interrupt];
	struct ipa_interrupt_info *interrupt_info;
	u32 val;

	interrupt_info = &ipa_interrupt_to_cb[irq_num];
	interrupt_info->deferred_flag = false;
	interrupt_info->handler = NULL;
	interrupt_info->interrupt = -1;

	/* Unregister SUSPEND_IRQ_EN_EE_N_ADDR for L2 interrupt.
	 * Note the following must not be executed for IPA hardware
	 * versions prior to 3.1.
	 */
	if (interrupt == IPA_TX_SUSPEND_IRQ) {
		ipahal_write_reg_n(IPA_SUSPEND_IRQ_EN_EE_n, IPA_EE_AP, 0);
		ipa_debug("wrote IPA_SUSPEND_IRQ_EN_EE_n reg = %d\n", 0);
	}

	val = ipahal_read_reg_n(IPA_IRQ_EN_EE_n, IPA_EE_AP);
	val &= ~BIT(irq_num);
	ipahal_write_reg_n(IPA_IRQ_EN_EE_n, IPA_EE_AP, val);
}

/** ipa_interrupts_init() - Initialize the IPA interrupts framework
 * @ipa_irq:	The interrupt number to allocate
 * @ipa_dev:	The basic device structure representing the IPA driver
 *
 * - Initialize the ipa_interrupt_to_cb array
 * - Clear interrupts status
 * - Register the ipa interrupt handler - ipa_isr
 * - Enable apps processor wakeup by IPA interrupts
 */
int ipa_interrupts_init(u32 ipa_irq, struct device *ipa_dev)
{
	int idx;
	int res = 0;

	for (idx = 0; idx < IPA_IRQ_NUM_MAX; idx++) {
		ipa_interrupt_to_cb[idx].deferred_flag = false;
		ipa_interrupt_to_cb[idx].handler = NULL;
		ipa_interrupt_to_cb[idx].interrupt = -1;
	}

	ipa_interrupt_wq = create_singlethread_workqueue("ipa_interrupt_wq");
	if (!ipa_interrupt_wq) {
		ipa_err("workqueue creation failed\n");
		return -ENOMEM;
	}

	res = request_irq(ipa_irq, ipa_isr, IRQF_TRIGGER_RISING, "ipa",
			  ipa_dev);
	if (res) {
		ipa_err("fail to register IPA IRQ handler irq=%d\n", ipa_irq);
		return -ENODEV;
	}
	ipa_debug("IPA IRQ handler irq=%d registered\n", ipa_irq);

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
	struct ipa_interrupt_info *interrupt_info;
	struct ipa_interrupt_work_wrap *work_data;
	struct ipa_tx_suspend_irq_data *interrupt_data;
	int irq_num;
	int aggr_active_bitmap = ipahal_read_reg(IPA_STATE_AGGR_ACTIVE);

	if (aggr_active_bitmap & BIT(clnt_hdl)) {
		/* force close aggregation */
		ipahal_write_reg(IPA_AGGR_FORCE_CLOSE, BIT(clnt_hdl));

		/* simulate suspend IRQ */
		irq_num = ipa_irq_mapping[IPA_TX_SUSPEND_IRQ];
		interrupt_info = &ipa_interrupt_to_cb[irq_num];
		if (!interrupt_info->handler) {
			ipa_err("no CB function for IPA_TX_SUSPEND_IRQ!\n");
			return;
		}
		interrupt_data = kzalloc(sizeof(*interrupt_data), GFP_ATOMIC);
		if (!interrupt_data) {
			ipa_err("failed allocating interrupt_data\n");
			return;
		}
		interrupt_data->endpoints = BIT(clnt_hdl);

		work_data = kzalloc(sizeof(*work_data), GFP_ATOMIC);
		if (!work_data)
			goto fail_alloc_work;

		INIT_WORK(&work_data->interrupt_work,
			  ipa_deferred_interrupt_work);
		work_data->handler = interrupt_info->handler;
		work_data->interrupt = IPA_TX_SUSPEND_IRQ;
		work_data->interrupt_data = interrupt_data;
		queue_work(ipa_interrupt_wq, &work_data->interrupt_work);
		return;
fail_alloc_work:
		kfree(interrupt_data);
	}
}
