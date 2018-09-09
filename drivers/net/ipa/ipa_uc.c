// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#define pr_fmt(fmt)    "ipa %s:%d " fmt, __func__, __LINE__

#include <linux/delay.h>
#include "ipa_i.h"

/* Supports hardware interface version 0x2000 */

#define IPA_RAM_UC_SMEM_SIZE	128	/* Size of shared memory area */

/* Delay to allow a the microcontroller to save state when crashing */
#define IPA_SEND_DELAY		100	/* microseconds */

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
 * @command: command code (AP->microcontroller)
 * @command_param: low 32 bits of command parameter (AP->microcontroller)
 * @command_param_hi: high 32 bits of command parameter (AP->microcontroller)
 *
 * @response: response code (microcontroller->AP)
 * @response_param: response parameter (microcontroller->AP)
 *
 * @event: event code (microcontroller->AP)
 * @event_param: event parameter (microcontroller->AP)
 *
 * @first_error_address: address of first error-source on SNOC
 * @hw_state: state of hardware (including error type information)
 * @warning_counter: counter of non-fatal hardware errors
 * @interface_version: hardware-reported interface version
 */
struct ipa_uc_shared_area {
	u32 command		: 8;	/* enum ipa_uc_command */
	/* 3 reserved bytes */
	u32 command_param;
	u32 command_param_hi;

	u32 response		: 8; 	/* enum ipa_uc_response */
	/* 3 reserved bytes */
	u32 response_param;

	u32 event		: 8;	/* enum ipa_uc_event */
	/* 3 reserved bytes */
	u32 event_param;

	u32 first_error_address;
	u32 hw_state		: 8,
	    warning_counter	: 8,
	    reserved		: 16;
	u32 interface_version	: 16;
	/* 2 reserved bytes */
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

/*
 * Microcontroller event codes, error codes, commands, and responses
 * to commands all encode both a "code" and a "feature" in their
 * 8-bit numeric value.  The top 3 bits represent the feature, and
 * the bottom 5 bits represent the code.  A "common" feature uses
 * feature code 0, and at this time we only deal with common
 * features.  Because of this we can just ignore the feature bits
 * and define the values of symbols in  the following enumerated
 * types by just their code values.
 */

/** enum ipa_uc_event - common cpu events (microcontroller->AP)
 *
 * @IPA_UC_EVENT_NO_OP: no event present
 * @IPA_UC_EVENT_ERROR: system error has been detected
 * @IPA_UC_EVENT_LOG_INFO: logging information available
 */
enum ipa_uc_event {
	IPA_UC_EVENT_NO_OP     = 0,
	IPA_UC_EVENT_ERROR     = 1,
	IPA_UC_EVENT_LOG_INFO  = 2,
};

/** enum ipa_uc_error - common error types (microcontroller->AP)
 *
 * @IPA_UC_ERROR_NONE: no error
 * @IPA_UC_ERROR_INVALID_DOORBELL: invalid data read from doorbell
 * @IPA_UC_ERROR_DMA: unexpected DMA error
 * @IPA_UC_ERROR_FATAL_SYSTEM: microcontroller has crashed and requires reset
 * @IPA_UC_ERROR_INVALID_OPCODE: invalid opcode sent
 * @IPA_UC_ERROR_INVALID_PARAMS: invalid params for the requested command
 * @IPA_UC_ERROR_CONS_DISABLE_CMD_GSI_STOP: consumer pipe stop failure
 * @IPA_UC_ERROR_PROD_DISABLE_CMD_GSI_STOP: producer pipe stop failure
 * @IPA_UC_ERROR_CH_NOT_EMPTY: micrcontroller GSI channel is not empty
 */
enum ipa_uc_error {
	IPA_UC_ERROR_NONE			= 0,
	IPA_UC_ERROR_INVALID_DOORBELL		= 1,
	IPA_UC_ERROR_DMA			= 2,
	IPA_UC_ERROR_FATAL_SYSTEM		= 3,
	IPA_UC_ERROR_INVALID_OPCODE		= 4,
	IPA_UC_ERROR_INVALID_PARAMS		= 5,
	IPA_UC_ERROR_CONS_DISABLE_CMD_GSI_STOP	= 6,
	IPA_UC_ERROR_PROD_DISABLE_CMD_GSI_STOP	= 7,
	IPA_UC_ERROR_CH_NOT_EMPTY		= 8,
};

/** enum ipa_uc_command - commands from the AP to the microcontroller
 *
 * @IPA_UC_COMMAND_NO_OP: no operation
 * @IPA_UC_COMMAND_UPDATE_FLAGS: request to re-read configuration flags
 * @IPA_UC_COMMAND_DEBUG_RUN_TEST: request to run hardware test
 * @IPA_UC_COMMAND_DEBUG_GET_INFO: request to read internal debug information
 * @IPA_UC_COMMAND_ERR_FATAL: AP system crash notification
 * @IPA_UC_COMMAND_CLK_GATE: request hardware to enter clock gated state
 * @IPA_UC_COMMAND_CLK_UNGATE: request hardware to enter clock ungated state
 * @IPA_UC_COMMAND_MEMCPY: request hardware to perform memcpy
 * @IPA_UC_COMMAND_RESET_PIPE: request pipe reset
 * @IPA_UC_COMMAND_REG_WRITE: request a register be written
 * @IPA_UC_COMMAND_GSI_CH_EMPTY: request to determine whether channel is empty
 */
enum ipa_uc_command {
	IPA_UC_COMMAND_NO_OP		= 0,
	IPA_UC_COMMAND_UPDATE_FLAGS	= 1,
	IPA_UC_COMMAND_DEBUG_RUN_TEST	= 2,
	IPA_UC_COMMAND_DEBUG_GET_INFO	= 3,
	IPA_UC_COMMAND_ERR_FATAL	= 4,
	IPA_UC_COMMAND_CLK_GATE		= 5,
	IPA_UC_COMMAND_CLK_UNGATE	= 6,
	IPA_UC_COMMAND_MEMCPY		= 7,
	IPA_UC_COMMAND_RESET_PIPE	= 8,
	IPA_UC_COMMAND_REG_WRITE	= 9,
	IPA_UC_COMMAND_GSI_CH_EMPTY	= 10,
};

/** enum ipa_uc_response - common hardware response codes
 *
 * @IPA_UC_RESPONSE_NO_OP: no operation
 * @IPA_UC_RESPONSE_INIT_COMPLETED: microcontroller ready
 * @IPA_UC_RESPONSE_CMD_COMPLETED: AP-issued command has completed
 * @IPA_UC_RESPONSE_DEBUG_GET_INFO: get debug info
 */
enum ipa_uc_response {
	IPA_UC_RESPONSE_NO_OP		= 0,
	IPA_UC_RESPONSE_INIT_COMPLETED	= 1,
	IPA_UC_RESPONSE_CMD_COMPLETED	= 2,
	IPA_UC_RESPONSE_DEBUG_GET_INFO	= 3,
};

/** union ipa_uc_event_data - microcontroller->AP event data
 *
 * @error_type: ipa_uc_error error type value
 * @raw32b: 32-bit register value (used when reading)
 */
union ipa_uc_event_data {
	u8 error_type;	/* enum ipa_uc_error */
	u32 raw32b;
} __packed;

/** union ipa_uc_response_data - response to AP command
 *
 * @command: the AP issued command this is responding to
 * @status: 0 for success indication, otherwise failure
 * @raw32b: 32-bit register value (used when reading)
 */
union ipa_uc_response_data {
	struct ipa_uc_response_param {
		u8 command;	/* enum ipa_uc_command */
		u8 status;	/* enum ipa_uc_error */
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
	union ipa_uc_event_data event_param;
	u8 event;

	ipa_client_add();

	event = shared->event;
	event_param.raw32b = shared->event_param;

	/* General handling */
	if (event == IPA_UC_EVENT_ERROR) {
		ipa_err("uC error type 0x%02x timestamp 0x%08x\n",
			event_param.error_type, ipa_read_reg(IPA_TAG_TIMER));
		ipa_bug();
	} else {
		ipa_debug("unsupported uC event opcode=%u\n", event);
	}

	ipa_client_remove();
}

static void
ipa_uc_response_hdlr(enum ipa_irq_type interrupt, u32 interrupt_data)
{
	struct ipa_uc_shared_area *shared = ipa_uc_ctx.shared;
	union ipa_uc_response_data response_data;
	u8 response;

	ipa_client_add();

	response = shared->response;

	/* An INIT_COMPLETED response message is sent to the AP by
	 * the microcontroller when it is operational.  Other than
	 * this, the AP should only receive responses from the
	 * microntroller when it has sent it a request message.
	 */
	if (response == IPA_UC_RESPONSE_INIT_COMPLETED) {
		/* The proxy vote is held until uC is loaded to ensure that
		 * IPA_HW_2_CPU_RESPONSE_INIT_COMPLETED is received.
		 */
		ipa_proxy_clk_unvote();
		ipa_uc_ctx.uc_loaded = true;
	} else if (response == IPA_UC_RESPONSE_CMD_COMPLETED) {
		response_data.raw32b = shared->response_param;
		ipa_err("uC command response code %u status %u\n",
			response_data.params.command,
			response_data.params.status);
	} else {
		ipa_err("Unsupported uC rsp opcode = %u\n", response);
	}

	ipa_client_remove();
}

/** ipa_uc_init() - Initialize the microcontroller
 *
 * Returns pointer to microcontroller context on success, NULL otherwise
 */
struct ipa_uc_ctx *ipa_uc_init(phys_addr_t phys_addr)
{

	phys_addr += ipa_reg_n_offset(IPA_SRAM_DIRECT_ACCESS_N, 0);
	ipa_uc_ctx.shared = ioremap(phys_addr, IPA_RAM_UC_SMEM_SIZE);
	if (!ipa_uc_ctx.shared)
		return NULL;

	ipa_add_interrupt_handler(IPA_UC_IRQ_0, ipa_uc_event_handler);
	ipa_add_interrupt_handler(IPA_UC_IRQ_1, ipa_uc_response_hdlr);

	return &ipa_uc_ctx;
}

/* Send a command to the microcontroller */
static void send_uc_command(u32 command, u32 command_param)
{
	struct ipa_uc_shared_area *shared = ipa_uc_ctx.shared;

	shared->command = command;
	shared->command_param = command_param;
	shared->command_param_hi = 0;
	shared->response = 0;
	shared->response_param = 0;

	wmb();	/* ensure write to shared memory is done before triggering uc */

	ipa_write_reg_n(IPA_IRQ_EE_UC_N, IPA_EE_AP, 0x1);
}

void ipa_uc_panic_notifier(void)
{
	if (!ipa_uc_ctx.uc_loaded)
		return;

	if (!ipa_client_add_additional())
		return;

	send_uc_command(IPA_UC_COMMAND_ERR_FATAL, 0);

	/* give uc enough time to save state */
	udelay(IPA_SEND_DELAY);

	ipa_client_remove();
}
