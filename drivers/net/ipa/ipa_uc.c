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

/*
 * The IPA has an embedded microcontroller that is capable of doing
 * more general-purpose processing, for example for handling certain
 * exceptional conditions.  When it has completed its boot sequence
 * it signals the AP with an interrupt.  At this time we don't use
 * any of the microcontroller capabilities, but we do handle the
 * "ready" interrupt.  We also notify it (by sending it a special
 * command) in the event of a crash.
 *
 * A 128 byte block of structured memory within the IPA SRAM is used
 * to communicate between the AP and the microcontroller embedded in
 * the IPA.
 *
 * To send a command to the microcontroller, the AP fills in the
 * command opcode and command parameter fields in this area, then
 * writes a register to signal to the microcontroller the command is
 * available.  When the microcontroller has executed the command, it
 * writes response data to this shared area, then issues a response
 * interrupt (micrcontroller IRQ 1) to the AP.  The response
 * includes a "response operation" that indicates the completion,
 * along with a "response parameter" which encodes the original
 * command and the command's status (result).
 *
 * The shared area is also used to communicate events asynchronously
 * from the microcontroller to the AP.  Events are signaled using
 * the event interrupt (micrcontroller IRQ 0).  The microcontroller
 * fills in an "event operation" and "event parameter" before
 * triggering the interrupt.
 *
 * Some additional information is also found in this shared area,
 * but is currently unused by the IPA driver.
 *
 * All other space in the shared area is reserved, and must not be
 * read or written by the AP.
 */

/** struct ipa_uc_shared_area - AP/microcontroller shared memory area
 *
 * @cmd_op: ipa_cpu_2_hw_command opcode (AP->microcontroller)
 * @cmd_params: low 32 bits of command parameter (AP->microcontroller)
 * @cmd_params_hi: high 32 bits of command parameter (AP->microcontroller)
 *
 * @response_op: ipa_hw_2_cpu_response response opcode (microcontroller->AP)
 * @response_params: response parameter (microcontroller->AP)
 *
 * @event_op: ipa_hw_2_cpu_events event opcode (microcontroller->AP)
 * @event_params: event parameter (microcontroller->AP)
 *
 * @first_error_address: address of first error-source on SNOC
 * @hw_state: state of hardware (including error type information)
 * @warning_counter: counter of non-fatal hardware errors
 * @interface_version: hardware-reported interface version
 */
struct ipa_uc_shared_area {
	u32 cmd_op		: 8;	/* followed by 3 reserved bytes */
	u32 cmd_params;
	u32 cmd_params_hi;
	u32 response_op		: 8;	/* followed by 3 reserved bytes */
	u32 response_params;
	u32 event_op		: 8;	/* followed by 3 reserved bytes */
	u32 event_params;
	u32 first_error_address;
	u32 hw_state		: 8,
	    warning_counter	: 8,
	    reserved		: 16;
	u32 interface_version	: 16;	/* followed by 2 reserved bytes */
};

/** struct ipa_uc_ctx - IPA microcontroller context
 *
 * @uc_loaded: whether microcontroller has been loaded
 * @shared: pointer to AP/microcontroller shared memory area
 */
struct ipa_uc_ctx {
	bool uc_loaded;
	struct ipa_uc_shared_area *shared;
} ipa_uc_ctx;

#define FEATURE_ENUM_VAL(feature, opcode) ((feature << 5) | opcode)

/** enum ipa_hw_features - Values that represent the features supported
 * in IPA HW
 * @IPA_HW_FEATURE_COMMON : Feature related to common operation of IPA HW
 *
 */
enum ipa_hw_features {
	IPA_HW_FEATURE_COMMON		=	0x0,
};

/** enum ipa_hw_2_cpu_events - Values that represent HW event to be sent to CPU.
 * @IPA_HW_2_CPU_EVENT_NO_OP : No event present
 * @IPA_HW_2_CPU_EVENT_ERROR : Event specify a system error is detected by the
 *  device
 * @IPA_HW_2_CPU_EVENT_LOG_INFO : Event providing logging specific information
 */
enum ipa_hw_2_cpu_events {
	IPA_HW_2_CPU_EVENT_NO_OP     =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 0),
	IPA_HW_2_CPU_EVENT_ERROR     =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 1),
	IPA_HW_2_CPU_EVENT_LOG_INFO  =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 2),
};

/** enum ipa_hw_errors - Common error types.
 * @IPA_HW_ERROR_NONE : No error persists
 * @IPA_HW_INVALID_DOORBELL_ERROR : Invalid data read from doorbell
 * @IPA_HW_DMA_ERROR : Unexpected DMA error
 * @IPA_HW_FATAL_SYSTEM_ERROR : HW has crashed and requires reset.
 * @IPA_HW_INVALID_OPCODE : Invalid opcode sent
 * @IPA_HW_INVALID_PARAMS : Invalid params for the requested command
 * @IPA_HW_CH_NOT_EMPTY_FAILURE : GSI channel emptiness validation failed
 */
enum ipa_hw_errors {
	IPA_HW_ERROR_NONE	       =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 0),
	IPA_HW_INVALID_DOORBELL_ERROR  =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 1),
	IPA_HW_DMA_ERROR	       =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 2),
	IPA_HW_FATAL_SYSTEM_ERROR      =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 3),
	IPA_HW_INVALID_OPCODE	       =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 4),
	IPA_HW_INVALID_PARAMS	     =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 5),
	IPA_HW_CONS_DISABLE_CMD_GSI_STOP_FAILURE =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 6),
	IPA_HW_PROD_DISABLE_CMD_GSI_STOP_FAILURE =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 7),
	IPA_HW_CH_NOT_EMPTY_FAILURE =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 8)
};

/** enum ipa_cpu_2_hw_command - commands from the AP to the microcontroller
 *
 * @IPA_CPU_2_HW_CMD_ERR_FATAL: notify of AP system crash
 */
enum ipa_cpu_2_hw_command {
	IPA_CPU_2_HW_CMD_ERR_FATAL		   =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 4),
};

/** enum ipa_hw_2_cpu_response - common hardware response codes
 *
 * @IPA_HW_2_CPU_RESPONSE_INIT_COMPLETED: microcontroller ready
 * @IPA_HW_2_CPU_RESPONSE_CMD_COMPLETED: AP issued command has completed
 */
enum ipa_hw_2_cpu_responses {
	IPA_HW_2_CPU_RESPONSE_INIT_COMPLETED =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 1),
	IPA_HW_2_CPU_RESPONSE_CMD_COMPLETED  =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 2),
};

/** union ipa_hw_error_event_data - microcontroller->AP event data
 *
 * @error_type: ipa_hw_errors error type value
 * @raw32b: 32-bit register value (used when reading)
 */
union ipa_hw_error_event_data {
	u8 error_type;
	u32 raw32b;
} __packed;

/** union ipa_hw_cpu_cmd_completed_response_data - response to AP command
 *
 * @original_cmd_op: the AP issued command this is responding to
 * @status: 0 for success indication, otherwise failure
 * @raw32b: 32-bit register value (used when reading)
 */
union ipa_hw_cpu_cmd_completed_response_data {
	struct ipa_hw_cpu_cmd_completed_response_params {
		u8 original_cmd_op;
		u8 status;
	} params;
	u32 raw32b;
} __packed;

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
	struct ipa_uc_shared_area *shared = ipa_uc_ctx.shared;
	union ipa_hw_error_event_data evt;
	u8 event_op;

	ipa_client_add();

	event_op = shared->event_op;
	evt.raw32b = shared->event_params;

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
	struct ipa_uc_shared_area *shared = ipa_uc_ctx.shared;
	u8 response_op;

	ipa_client_add();

	shared = ipa_uc_ctx.shared;
	response_op = shared->response_op;

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
		uc_rsp.raw32b = shared->response_params;
		ipa_err("uC cmd response opcode=%u status=%u\n",
			  uc_rsp.params.original_cmd_op, uc_rsp.params.status);
	} else {
		ipa_err("Unsupported uC rsp opcode = %u\n", response_op);
	}

	ipa_client_remove();
}

/* Send a command to the microcontroller */
static void send_uc_command(u32 cmd, u32 opcode)
{
	struct ipa_uc_shared_area *shared = ipa_uc_ctx.shared;

	shared->cmd_op = opcode;
	shared->cmd_params = cmd;
	shared->cmd_params_hi = 0;
	shared->response_op = 0;
	shared->response_params = 0;

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
	ipa_uc_ctx.shared = ioremap(phys_addr, IPA_RAM_UC_SMEM_SIZE);
	if (!ipa_uc_ctx.shared)
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

	send_uc_command(0, IPA_CPU_2_HW_CMD_ERR_FATAL);

	/* give uc enough time to save state */
	udelay(IPA_PKT_FLUSH_TO_US);

	ipa_client_remove();
}
