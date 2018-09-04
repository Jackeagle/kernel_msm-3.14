// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#define pr_fmt(fmt)    "ipa %s:%d " fmt, __func__, __LINE__

#include <linux/delay.h>
#include "ipa_i.h"

/* Supports hardware interface version 0x2000 */

#define IPA_RAM_UC_SMEM_SIZE 128
#define IPA_PKT_FLUSH_TO_US 100
#define IPA_UC_POLL_SLEEP_USEC 100
#define IPA_UC_POLL_MAX_RETRY 10000

/** enum ipa_cpu_2_hw_commands - Values that represent the commands from the CPU
 * IPA_CPU_2_HW_CMD_ERR_FATAL : CPU instructs HW to perform error fatal
 *				handling.
 * IPA_CPU_2_HW_CMD_CLK_GATE : CPU instructs HW to goto Clock Gated state.
 * IPA_CPU_2_HW_CMD_CLK_UNGATE : CPU instructs HW to goto Clock Ungated state.
 * IPA_CPU_2_HW_CMD_CH_EMPTY : Command to check for GSI channel emptiness.
 */
enum ipa_cpu_2_hw_commands {
	IPA_CPU_2_HW_CMD_ERR_FATAL		   =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 4),
	IPA_CPU_2_HW_CMD_CH_EMPTY		   =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 10),
};

/** enum ipa_hw_2_cpu_responses -  Values that represent common HW responses
 *  to CPU commands.
 * @IPA_HW_2_CPU_RESPONSE_INIT_COMPLETED : HW shall send this command once
 *  boot sequence is completed and HW is ready to serve commands from CPU
 * @IPA_HW_2_CPU_RESPONSE_CMD_COMPLETED: Response to CPU commands
 */
enum ipa_hw_2_cpu_responses {
	IPA_HW_2_CPU_RESPONSE_INIT_COMPLETED =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 1),
	IPA_HW_2_CPU_RESPONSE_CMD_COMPLETED  =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 2),
};

/** union ipa_hw_error_event_data - HW->CPU Common Events
 * @error_type : Entered when a system error is detected by the HW. Type of
 * error is specified by IPA_HW_ERRORS
 * @reserved : Reserved
 */
union ipa_hw_error_event_data {
	u8 error_type;
	u32 raw32b;
} __packed;

/** union ipa_hw_cpu_cmd_completed_response_data - Structure holding the
 * parameters for IPA_HW_2_CPU_RESPONSE_CMD_COMPLETED response.
 * @original_cmd_op : The original command opcode
 * @status : 0 for success indication, otherwise failure
 * @reserved : Reserved
 *
 * Parameters are sent as 32b immediate parameters.
 */
union ipa_hw_cpu_cmd_completed_response_data {
	struct ipa_hw_cpu_cmd_completed_response_params {
		u8 original_cmd_op;
		u8 status;
	} params;
	u32 raw32b;
} __packed;

struct ipa_uc_ctx ipa_uc_ctx;

/** ipa_uc_loaded() - tell whether the microcontroller has been loaded
 *
 * Returns true if the microcontroller is loaded, false otherwise
 */
bool ipa_uc_loaded(void)
{
	return ipa_uc_ctx.uc_loaded;
}

static void
ipa_uc_event_handler(enum ipa_irq_type interrupt, u32 interrupt_data)
{
	struct ipa_hw_shared_mem_common_mapping *mmio;
	union ipa_hw_error_event_data evt;
	u8 event_op;

	ipa_client_add();

	mmio = ipa_uc_ctx.uc_sram_mmio;
	event_op = mmio->event_op;
	evt.raw32b = mmio->event_params;

	/* General handling */
	if (event_op == IPA_HW_2_CPU_EVENT_ERROR) {
		ipa_err("uC error type 0x%02x timestamp 0x%08x\n",
			evt.error_type, ipahal_read_reg(IPA_TAG_TIMER));
		ipa_bug();
	} else {
		ipa_debug("unsupported uC evt opcode=%u\n", event_op);
	}

	ipa_client_remove();
}

static void
ipa_uc_response_hdlr(enum ipa_irq_type interrupt, u32 interrupt_data)
{
	union ipa_hw_cpu_cmd_completed_response_data uc_rsp;
	struct ipa_hw_shared_mem_common_mapping *mmio;
	u8 response_op;

	ipa_client_add();

	mmio = ipa_uc_ctx.uc_sram_mmio;
	response_op = mmio->response_op;

	/* An INIT_COMPLETED response message is sent to the AP by
	 * the microcontroller when it is operational.  Other than
	 * this, the AP should only receive responses from the
	 * microntroller when it has sent it a request message.
	 */
	if (response_op == IPA_HW_2_CPU_RESPONSE_INIT_COMPLETED) {
		/* The proxy vote is held until uC is loaded to ensure that
		 * IPA_HW_2_CPU_RESPONSE_INIT_COMPLETED is received.
		 */
		ipa_proxy_clk_unvote();
		ipa_uc_ctx.uc_loaded = true;
	} else if (response_op == IPA_HW_2_CPU_RESPONSE_CMD_COMPLETED) {
		uc_rsp.raw32b = mmio->response_params;
		ipa_err("uC cmd response opcode=%u status=%u\n",
			  uc_rsp.params.original_cmd_op, uc_rsp.params.status);
	} else {
		ipa_err("Unsupported uC rsp opcode = %u\n", response_op);
	}

	ipa_client_remove();
}

/* Send a command to the microcontroller */
static void send_uc_command(struct ipa_uc_ctx *uc_ctx, u32 cmd, u32 opcode)
{
	struct ipa_hw_shared_mem_common_mapping *mmio = uc_ctx->uc_sram_mmio;

	mmio->cmd_op = opcode;
	mmio->cmd_params = cmd;
	mmio->cmd_params_hi = 0;
	mmio->response_op = 0;
	mmio->response_params = 0;

	wmb();	/* ensure write to shared memory is done before triggering uc */

	ipahal_write_reg_n(IPA_IRQ_EE_UC_N, IPA_EE_AP, 0x1);
}

/** ipa_uc_init() - Initialize the microcontroller
 *
 * Returns pointer to microcontroller context on success, NULL otherwise
 */
struct ipa_uc_ctx *ipa_uc_init(phys_addr_t phys_addr)
{

	phys_addr += ipahal_reg_n_offset(IPA_SRAM_DIRECT_ACCESS_N, 0);
	ipa_uc_ctx.uc_sram_mmio = ioremap(phys_addr, IPA_RAM_UC_SMEM_SIZE);
	if (!ipa_uc_ctx.uc_sram_mmio)
		return NULL;

	ipa_add_interrupt_handler(IPA_UC_IRQ_0, ipa_uc_event_handler);
	ipa_add_interrupt_handler(IPA_UC_IRQ_1, ipa_uc_response_hdlr);

	return &ipa_uc_ctx;
}

void ipa_uc_panic_notifier(void)
{
	if (!ipa_uc_ctx.uc_loaded)
		return;

	if (!ipa_client_add_additional())
		return;

	send_uc_command(&ipa_uc_ctx, 0, IPA_CPU_2_HW_CMD_ERR_FATAL);

	/* give uc enough time to save state */
	udelay(IPA_PKT_FLUSH_TO_US);

	ipa_client_remove();
}
