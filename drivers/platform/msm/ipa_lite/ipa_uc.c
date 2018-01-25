/* Copyright (c) 2012-2017, The Linux Foundation. All rights reserved.
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

#define pr_fmt(fmt)    "ipa %s:%d " fmt, __func__, __LINE__

#include <linux/delay.h>
#include "ipa_i.h"

/* Supports hardware interface version 0x2000 */

#define IPA_RAM_UC_SMEM_SIZE 128
#define IPA_PKT_FLUSH_TO_US 100
#define IPA_UC_POLL_SLEEP_USEC 100
#define IPA_UC_POLL_MAX_RETRY 10000

/**
 * enum ipa3_cpu_2_hw_commands - Values that represent the commands from the CPU
 * IPA_CPU_2_HW_CMD_ERR_FATAL : CPU instructs HW to perform error fatal
 *                              handling.
 * IPA_CPU_2_HW_CMD_CLK_GATE : CPU instructs HW to goto Clock Gated state.
 * IPA_CPU_2_HW_CMD_CLK_UNGATE : CPU instructs HW to goto Clock Ungated state.
 * IPA_CPU_2_HW_CMD_GSI_CH_EMPTY : Command to check for GSI channel emptiness.
 */
enum ipa3_cpu_2_hw_commands {
	IPA_CPU_2_HW_CMD_ERR_FATAL                 =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 4),
	IPA_CPU_2_HW_CMD_GSI_CH_EMPTY              =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 10),
};

/**
 * enum ipa3_hw_2_cpu_responses -  Values that represent common HW responses
 *  to CPU commands.
 * @IPA_HW_2_CPU_RESPONSE_INIT_COMPLETED : HW shall send this command once
 *  boot sequence is completed and HW is ready to serve commands from CPU
 * @IPA_HW_2_CPU_RESPONSE_CMD_COMPLETED: Response to CPU commands
 */
enum ipa3_hw_2_cpu_responses {
	IPA_HW_2_CPU_RESPONSE_INIT_COMPLETED =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 1),
	IPA_HW_2_CPU_RESPONSE_CMD_COMPLETED  =
		FEATURE_ENUM_VAL(IPA_HW_FEATURE_COMMON, 2),
};

/**
 * union IpaHwCpuCmdCompletedResponseData_t - Structure holding the parameters
 * for IPA_HW_2_CPU_RESPONSE_CMD_COMPLETED response.
 * @originalCmdOp : The original command opcode
 * @status : 0 for success indication, otherwise failure
 * @reserved : Reserved
 *
 * Parameters are sent as 32b immediate parameters.
 */
union IpaHwCpuCmdCompletedResponseData_t {
	struct IpaHwCpuCmdCompletedResponseParams_t {
		u32 originalCmdOp:8;
		u32 status:8;
		u32 reserved:16;
	} __packed params;
	u32 raw32b;
} __packed;

/**
 * union IpaHwChkChEmptyCmdData_t -  Structure holding the parameters for
 *  IPA_CPU_2_HW_CMD_GSI_CH_EMPTY command. Parameters are sent as 32b
 *  immediate parameters.
 * @ee_n : EE owner of the channel
 * @vir_ch_id : GSI virtual channel ID of the channel to checked of emptiness
 * @reserved_02_04 : Reserved
 */
union IpaHwChkChEmptyCmdData_t {
	struct IpaHwChkChEmptyCmdParams_t {
		u8 ee_n;
		u8 vir_ch_id;
		u16 reserved_02_04;
	} __packed params;
	u32 raw32b;
} __packed;

const char *ipa_hw_error_str(enum ipa_hw_errors err_type)
{
	const char *str;

	switch (err_type) {
	case IPA_HW_ERROR_NONE:
		str = "IPA_HW_ERROR_NONE";
		break;
	case IPA_HW_INVALID_DOORBELL_ERROR:
		str = "IPA_HW_INVALID_DOORBELL_ERROR";
		break;
	case IPA_HW_DMA_ERROR:
		str = "IPA_HW_DMA_ERROR";
		break;
	case IPA_HW_FATAL_SYSTEM_ERROR:
		str = "IPA_HW_FATAL_SYSTEM_ERROR";
		break;
	case IPA_HW_INVALID_OPCODE:
		str = "IPA_HW_INVALID_OPCODE";
		break;
	case IPA_HW_INVALID_PARAMS:
		str = "IPA_HW_INVALID_PARAMS";
		break;
	case IPA_HW_CONS_DISABLE_CMD_GSI_STOP_FAILURE:
		str = "IPA_HW_CONS_DISABLE_CMD_GSI_STOP_FAILURE";
		break;
	case IPA_HW_PROD_DISABLE_CMD_GSI_STOP_FAILURE:
		str = "IPA_HW_PROD_DISABLE_CMD_GSI_STOP_FAILURE";
		break;
	case IPA_HW_GSI_CH_NOT_EMPTY_FAILURE:
		str = "IPA_HW_GSI_CH_NOT_EMPTY_FAILURE";
		break;
	default:
		str = "INVALID ipa_hw_errors type";
	}

	return str;
}

static void ipa3_log_evt_hdlr(void)
{
	if (!ipa3_ctx->uc_ctx.uc_event_top_ofst) {
		ipa3_ctx->uc_ctx.uc_event_top_ofst =
			ipa3_ctx->uc_ctx.uc_sram_mmio->eventParams;
		if (ipa3_ctx->uc_ctx.uc_event_top_ofst +
			sizeof(struct IpaHwEventLogInfoData_t) >=
			ipa3_ctx->ctrl->ipa_reg_base_ofst +
			ipahal_reg_n_offset(IPA_SRAM_DIRECT_ACCESS_n, 0) +
			ipa3_ctx->smem_sz) {
			ipa_err("uc_top 0x%x outside SRAM\n",
				ipa3_ctx->uc_ctx.uc_event_top_ofst);
			goto bad_uc_top_ofst;
		}

		ipa3_ctx->uc_ctx.uc_event_top_mmio = ioremap(
			ipa3_ctx->ipa_wrapper_base +
			ipa3_ctx->uc_ctx.uc_event_top_ofst,
			sizeof(struct IpaHwEventLogInfoData_t));
		if (!ipa3_ctx->uc_ctx.uc_event_top_mmio) {
			ipa_err("fail to ioremap uc top\n");
			goto bad_uc_top_ofst;
		}
	} else {

		if (ipa3_ctx->uc_ctx.uc_sram_mmio->eventParams !=
			ipa3_ctx->uc_ctx.uc_event_top_ofst) {
			ipa_err("uc top ofst changed new=%u cur=%u\n",
				ipa3_ctx->uc_ctx.uc_sram_mmio->
				eventParams,
				ipa3_ctx->uc_ctx.uc_event_top_ofst);
		}
	}

	return;

bad_uc_top_ofst:
	ipa3_ctx->uc_ctx.uc_event_top_ofst = 0;
}

/**
 * ipa3_uc_state_check() - Check the status of the uC interface
 *
 * Return value: 0 if the uC is loaded, interface is initialized
 *               and there was no recent failure in one of the commands.
 *               A negative value is returned otherwise.
 */
static int ipa3_uc_state_check(void)
{
	if (!ipa3_ctx->uc_ctx.uc_inited) {
		ipa_err("uC interface not initialized\n");
		return -EFAULT;
	}

	if (!ipa3_ctx->uc_ctx.uc_loaded) {
		ipa_err("uC is not loaded\n");
		return -EFAULT;
	}

	if (ipa3_ctx->uc_ctx.uc_failed) {
		ipa_err("uC has failed its last command\n");
		return -EFAULT;
	}

	return 0;
}

/**
 * ipa3_uc_loaded_check() - Check the uC has been loaded
 *
 * Return value: 1 if the uC is loaded, 0 otherwise
 */
int ipa3_uc_loaded_check(void)
{
	return ipa3_ctx->uc_ctx.uc_loaded;
}
EXPORT_SYMBOL(ipa3_uc_loaded_check);

static void ipa3_uc_event_handler(enum ipa_irq_type interrupt,
				 void *private_data,
				 void *interrupt_data)
{
	union IpaHwErrorEventData_t evt;
	u8 feature;

	WARN_ON(private_data != ipa3_ctx);

	IPA_ACTIVE_CLIENTS_INC_SIMPLE();

	ipa_debug("uC evt opcode=%u\n",
		ipa3_ctx->uc_ctx.uc_sram_mmio->eventOp);


	feature = EXTRACT_UC_FEATURE(ipa3_ctx->uc_ctx.uc_sram_mmio->eventOp);

	if (0 > feature || IPA_HW_FEATURE_MAX <= feature) {
		ipa_err("Invalid feature %u for event %u\n",
			feature, ipa3_ctx->uc_ctx.uc_sram_mmio->eventOp);
		IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
		return;
	}

	/* General handling */
	if (ipa3_ctx->uc_ctx.uc_sram_mmio->eventOp ==
	    IPA_HW_2_CPU_EVENT_ERROR) {
		evt.raw32b = ipa3_ctx->uc_ctx.uc_sram_mmio->eventParams;
		ipa_err("uC Error, evt errorType = %s\n",
			ipa_hw_error_str(evt.params.errorType));
		ipa3_ctx->uc_ctx.uc_failed = true;
		ipa3_ctx->uc_ctx.uc_error_type = evt.params.errorType;
		ipa3_ctx->uc_ctx.uc_error_timestamp =
			ipahal_read_reg(IPA_TAG_TIMER);
		BUG();
	} else if (ipa3_ctx->uc_ctx.uc_sram_mmio->eventOp ==
		IPA_HW_2_CPU_EVENT_LOG_INFO) {
		ipa_debug("uC evt log info ofst=0x%x\n",
			ipa3_ctx->uc_ctx.uc_sram_mmio->eventParams);
		ipa3_log_evt_hdlr();
	} else {
		ipa_debug("unsupported uC evt opcode=%u\n",
				ipa3_ctx->uc_ctx.uc_sram_mmio->eventOp);
	}
	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();

}

int ipa3_uc_panic_notifier(struct notifier_block *this,
		unsigned long event, void *ptr)
{
	int result = 0;
	struct ipa_active_client_logging_info log_info;

	ipa_debug("this=%p evt=%lu ptr=%p\n", this, event, ptr);

	result = ipa3_uc_state_check();
	if (result)
		goto fail;

	IPA_ACTIVE_CLIENTS_PREP_SIMPLE(log_info);
	if (ipa3_inc_client_enable_clks_no_block(&log_info))
		goto fail;

	ipa3_ctx->uc_ctx.uc_sram_mmio->cmdOp =
		IPA_CPU_2_HW_CMD_ERR_FATAL;
	ipa3_ctx->uc_ctx.pending_cmd = ipa3_ctx->uc_ctx.uc_sram_mmio->cmdOp;
	/* ensure write to shared memory is done before triggering uc */
	wmb();

	ipahal_write_reg_n(IPA_IRQ_EE_UC_n, 0, 0x1);

	/* give uc enough time to save state */
	udelay(IPA_PKT_FLUSH_TO_US);

	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
	ipa_debug("err_fatal issued\n");

fail:
	return NOTIFY_DONE;
}

static void ipa3_uc_response_hdlr(enum ipa_irq_type interrupt,
				void *private_data,
				void *interrupt_data)
{
	union IpaHwCpuCmdCompletedResponseData_t uc_rsp;
	u8 feature;

	WARN_ON(private_data != ipa3_ctx);
	IPA_ACTIVE_CLIENTS_INC_SIMPLE();
	ipa_debug("uC rsp opcode=%u\n",
			ipa3_ctx->uc_ctx.uc_sram_mmio->responseOp);

	feature = EXTRACT_UC_FEATURE(ipa3_ctx->uc_ctx.uc_sram_mmio->responseOp);

	if (0 > feature || IPA_HW_FEATURE_MAX <= feature) {
		ipa_err("Invalid feature %u for event %u\n",
			feature, ipa3_ctx->uc_ctx.uc_sram_mmio->eventOp);
		IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
		return;
	}

	/* General handling */
	if (ipa3_ctx->uc_ctx.uc_sram_mmio->responseOp ==
			IPA_HW_2_CPU_RESPONSE_INIT_COMPLETED) {
		ipa3_ctx->uc_ctx.uc_loaded = true;

		ipa_debug("IPA uC loaded\n");
		/*
		 * The proxy vote is held until uC is loaded to ensure that
		 * IPA_HW_2_CPU_RESPONSE_INIT_COMPLETED is received.
		 */
		ipa3_proxy_clk_unvote();
	} else if (ipa3_ctx->uc_ctx.uc_sram_mmio->responseOp ==
		   IPA_HW_2_CPU_RESPONSE_CMD_COMPLETED) {
		uc_rsp.raw32b = ipa3_ctx->uc_ctx.uc_sram_mmio->responseParams;
		ipa_debug("uC cmd response opcode=%u status=%u\n",
		       uc_rsp.params.originalCmdOp,
		       uc_rsp.params.status);
		if (uc_rsp.params.originalCmdOp ==
		    ipa3_ctx->uc_ctx.pending_cmd) {
			ipa3_ctx->uc_ctx.uc_status = uc_rsp.params.status;
			complete_all(&ipa3_ctx->uc_ctx.uc_completion);
		} else {
			ipa_err("Expected cmd=%u rcvd cmd=%u\n",
			       ipa3_ctx->uc_ctx.pending_cmd,
			       uc_rsp.params.originalCmdOp);
		}
	} else {
		ipa_err("Unsupported uC rsp opcode = %u\n",
		       ipa3_ctx->uc_ctx.uc_sram_mmio->responseOp);
	}
	IPA_ACTIVE_CLIENTS_DEC_SIMPLE();
}

/**
 * ipa3_uc_send_cmd() - Send a command to the uC
 *
 * Note1: This function sends command with 32bit parameter and do not
 *	use the higher 32bit of the command parameter (set to zero).
 *
 * Note2: In case the operation times out (No response from the uC) or
 *       polling maximal amount of retries has reached, the logic
 *       considers it as an invalid state of the uC/IPA, and
 *       issues a kernel panic.
 *
 * Returns: 0 on success.
 *          -EINVAL in case of invalid input.
 *          -EBADF in case uC interface is not initialized /
 *                 or the uC has failed previously.
 *          -EFAULT in case the received status doesn't match
 *                  the expected.
 */
static int ipa3_uc_send_cmd(u32 cmd, u32 opcode, unsigned long timeout_jiffies)
{
	struct ipa3_uc_ctx *uc_ctx = &ipa3_ctx->uc_ctx;
	struct IpaHwSharedMemCommonMapping_t *mmio = uc_ctx->uc_sram_mmio;
	int retries = 0;

send_cmd_lock:
	mutex_lock(&uc_ctx->uc_lock);

	if (ipa3_uc_state_check()) {
		ipa_debug("uC send command aborted\n");
		mutex_unlock(&uc_ctx->uc_lock);
		return -EBADF;
	}
send_cmd:
	init_completion(&uc_ctx->uc_completion);

	uc_ctx->pending_cmd = opcode;
	uc_ctx->uc_status = 0;

	mmio->cmdOp = opcode;
	mmio->cmdParams = cmd;
	mmio->cmdParams_hi = 0;
	mmio->responseOp = 0;
	mmio->responseParams = 0;

	/* ensure write to shared memory is done before triggering uc */
	wmb();

	ipahal_write_reg_n(IPA_IRQ_EE_UC_n, 0, 0x1);

	if (wait_for_completion_timeout(&uc_ctx->uc_completion,
		timeout_jiffies) == 0) {
		ipa_err("uC timed out\n");
		if (uc_ctx->uc_failed)
			ipa_err("uC reported on Error, errorType = %s\n",
				ipa_hw_error_str(uc_ctx->uc_error_type));
		mutex_unlock(&uc_ctx->uc_lock);
		BUG();
		return -EFAULT;
	}

	if (uc_ctx->uc_status) {
		if (uc_ctx->uc_status ==
		    IPA_HW_PROD_DISABLE_CMD_GSI_STOP_FAILURE ||
		    uc_ctx->uc_status ==
		    IPA_HW_CONS_DISABLE_CMD_GSI_STOP_FAILURE) {
			retries++;
			if (retries == IPA_GSI_CHANNEL_STOP_MAX_RETRY) {
				ipa_err("Failed after %d tries\n", retries);
				mutex_unlock(&uc_ctx->uc_lock);
				BUG();
				return -EFAULT;
			}
			mutex_unlock(&uc_ctx->uc_lock);
			if (uc_ctx->uc_status ==
			    IPA_HW_PROD_DISABLE_CMD_GSI_STOP_FAILURE)
				ipa3_inject_dma_task_for_gsi();
			/* sleep for short period to flush IPA */
			usleep_range(IPA_GSI_CHANNEL_STOP_SLEEP_MIN_USEC,
				IPA_GSI_CHANNEL_STOP_SLEEP_MAX_USEC);
			goto send_cmd_lock;
		}

		if (uc_ctx->uc_status == IPA_HW_GSI_CH_NOT_EMPTY_FAILURE) {
			retries++;
			if (retries >= IPA_GSI_CHANNEL_EMPTY_MAX_RETRY) {
				ipa_err("Failed after %d tries\n", retries);
				mutex_unlock(&uc_ctx->uc_lock);
				return -EFAULT;
			}
			usleep_range(IPA_GSI_CHANNEL_EMPTY_SLEEP_MIN_USEC,
				IPA_GSI_CHANNEL_EMPTY_SLEEP_MAX_USEC);
			goto send_cmd;
		}

		ipa_err("Received status %u\n", uc_ctx->uc_status);
		mutex_unlock(&uc_ctx->uc_lock);
		return -EFAULT;
	}

	mutex_unlock(&uc_ctx->uc_lock);

	ipa_debug("uC cmd %u send succeeded\n", opcode);

	return 0;
}

/**
 * ipa3_uc_interface_init() - Initialize the interface with the uC
 *
 * Return value: 0 on success, negative value otherwise
 */
int ipa3_uc_interface_init(void)
{
	int result;
	unsigned long phys_addr;

	if (ipa3_ctx->uc_ctx.uc_inited) {
		ipa_debug("uC interface already initialized\n");
		return 0;
	}

	mutex_init(&ipa3_ctx->uc_ctx.uc_lock);

	phys_addr = ipa3_ctx->ipa_wrapper_base +
		ipa3_ctx->ctrl->ipa_reg_base_ofst +
		ipahal_reg_n_offset(IPA_SRAM_DIRECT_ACCESS_n, 0);
	ipa3_ctx->uc_ctx.uc_sram_mmio = ioremap(phys_addr,
					       IPA_RAM_UC_SMEM_SIZE);
	if (!ipa3_ctx->uc_ctx.uc_sram_mmio) {
		ipa_err("Fail to ioremap IPA uC SRAM\n");
		result = -ENOMEM;
		goto remap_fail;
	}

	result = ipa3_add_interrupt_handler(IPA_UC_IRQ_0,
		ipa3_uc_event_handler, true,
		ipa3_ctx);
	if (result) {
		ipa_err("Fail to register for UC_IRQ0 rsp interrupt\n");
		result = -EFAULT;
		goto irq_fail0;
	}

	result = ipa3_add_interrupt_handler(IPA_UC_IRQ_1,
		ipa3_uc_response_hdlr, true,
		ipa3_ctx);
	if (result) {
		ipa_err("fail to register for UC_IRQ1 rsp interrupt\n");
		result = -EFAULT;
		goto irq_fail1;
	}

	ipa3_ctx->uc_ctx.uc_inited = true;

	ipa_debug("IPA uC interface is initialized\n");
	return 0;

irq_fail1:
	ipa3_remove_interrupt_handler(IPA_UC_IRQ_0);
irq_fail0:
	iounmap(ipa3_ctx->uc_ctx.uc_sram_mmio);
remap_fail:
	return result;
}

int ipa3_uc_is_gsi_channel_empty(enum ipa_client_type ipa_client)
{
	const struct ipa_gsi_ep_config *gsi_ep_info;
	union IpaHwChkChEmptyCmdData_t cmd;
	int ret;

	gsi_ep_info = ipa3_get_gsi_ep_info(ipa_client);
	if (!gsi_ep_info) {
		ipa_err("Failed getting GSI EP info for client=%d\n",
		       ipa_client);
		return 0;
	}

	if (ipa3_uc_state_check()) {
		ipa_debug("uC cannot be used to validate ch emptiness clnt=%d\n"
			, ipa_client);
		return 0;
	}

	cmd.params.ee_n = gsi_ep_info->ee;
	cmd.params.vir_ch_id = gsi_ep_info->ipa_gsi_chan_num;

	ipa_debug("uC emptiness check for IPA GSI Channel %d\n",
	       gsi_ep_info->ipa_gsi_chan_num);

	ret = ipa3_uc_send_cmd(cmd.raw32b, IPA_CPU_2_HW_CMD_GSI_CH_EMPTY, 10*HZ);

	return ret;
}
