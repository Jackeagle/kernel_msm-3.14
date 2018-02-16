/* Copyright (c) 2013-2017, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt)    "ipa-wan %s:%d " fmt, __func__, __LINE__

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/qmi_encdec.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <soc/qcom/subsystem_restart.h>
#include <linux/ipc_logging.h>
#include <linux/vmalloc.h>

#include "ipa_qmi_service.h"

#define IPA_Q6_SVC_VERS 1
#define IPA_A5_SVC_VERS 1
#define Q6_QMI_COMPLETION_TIMEOUT (60*HZ)

#define IPA_A5_SERVICE_SVC_ID 0x31
#define IPA_A5_SERVICE_INS_ID 1
#define IPA_Q6_SERVICE_SVC_ID 0x31
#define IPA_Q6_SERVICE_INS_ID 2

#define QMI_SEND_STATS_REQ_TIMEOUT_MS 5000
#define QMI_SEND_REQ_TIMEOUT_MS 60000

#define QMI_IPA_FORCE_CLEAR_DATAPATH_TIMEOUT_MS 1000

static struct qmi_handle *ipa3_svc_handle;
static void ipa3_a5_svc_recv_msg(struct work_struct *work);
static DECLARE_WORK(work_recv_msg, ipa3_a5_svc_recv_msg);
static struct workqueue_struct *ipa_svc_workqueue;
static struct workqueue_struct *ipa_clnt_req_workqueue;
static struct workqueue_struct *ipa_clnt_resp_workqueue;
static void *curr_conn;
static bool ipa3_qmi_modem_init_fin, ipa3_qmi_indication_fin;
static struct work_struct ipa3_qmi_service_init_work;
static uint32_t ipa_wan_platform;
static bool workqueues_stopped;
static bool ipa3_modem_init_cmplt;
static bool first_time_handshake;

/* QMI A5 service */

static struct msg_desc ipa3_install_fltr_rule_req_desc = {
	.max_msg_len = QMI_IPA_INSTALL_FILTER_RULE_REQ_MAX_MSG_LEN_V01,
	.msg_id = QMI_IPA_INSTALL_FILTER_RULE_REQ_V01,
	.ei_array = ipa3_install_fltr_rule_req_msg_data_v01_ei,
};

static struct msg_desc ipa3_indication_reg_req_desc = {
	.max_msg_len = QMI_IPA_INDICATION_REGISTER_REQ_MAX_MSG_LEN_V01,
	.msg_id = QMI_IPA_INDICATION_REGISTER_REQ_V01,
	.ei_array = ipa3_indication_reg_req_msg_data_v01_ei,
};
static struct msg_desc ipa3_indication_reg_resp_desc = {
	.max_msg_len = QMI_IPA_INDICATION_REGISTER_RESP_MAX_MSG_LEN_V01,
	.msg_id = QMI_IPA_INDICATION_REGISTER_RESP_V01,
	.ei_array = ipa3_indication_reg_resp_msg_data_v01_ei,
};
static struct msg_desc ipa3_master_driver_complete_indication_desc = {
	.max_msg_len = QMI_IPA_MASTER_DRIVER_INIT_COMPLETE_IND_MAX_MSG_LEN_V01,
	.msg_id = QMI_IPA_MASTER_DRIVER_INIT_COMPLETE_IND_V01,
	.ei_array = ipa3_master_driver_init_complt_ind_msg_data_v01_ei,
};

static struct msg_desc ipa3_config_req_desc = {
	.max_msg_len = QMI_IPA_CONFIG_REQ_MAX_MSG_LEN_V01,
	.msg_id = QMI_IPA_CONFIG_REQ_V01,
	.ei_array = ipa3_config_req_msg_data_v01_ei,
};

static struct msg_desc ipa3_install_fltr_rule_resp_desc = {
	.max_msg_len = QMI_IPA_INSTALL_FILTER_RULE_RESP_MAX_MSG_LEN_V01,
	.msg_id = QMI_IPA_INSTALL_FILTER_RULE_RESP_V01,
	.ei_array = ipa3_install_fltr_rule_resp_msg_data_v01_ei,
};

static struct msg_desc ipa3_init_modem_driver_cmplt_req_desc = {
	.max_msg_len = QMI_IPA_INIT_MODEM_DRIVER_CMPLT_REQ_MAX_MSG_LEN_V01,
	.msg_id = QMI_IPA_INIT_MODEM_DRIVER_CMPLT_REQ_V01,
	.ei_array = ipa3_init_modem_driver_cmplt_req_msg_data_v01_ei,
};

static struct msg_desc ipa3_init_modem_driver_cmplt_resp_desc = {
	.max_msg_len = QMI_IPA_INIT_MODEM_DRIVER_CMPLT_RESP_MAX_MSG_LEN_V01,
	.msg_id = QMI_IPA_INIT_MODEM_DRIVER_CMPLT_RESP_V01,
	.ei_array = ipa3_init_modem_driver_cmplt_resp_msg_data_v01_ei,
};

/*
 * The AP and modem synchronize by performing a handshake operation
 * over QMI.  It involves both sides initiating a request/response
 * transaction, followed the AP sending an indication to the modem.
 *
 * The AP is considered the master, and must tell the modem about
 * some of the operational parameters they must agree on (such as
 * the way shared IPA memory is laid out).  This information is
 * contained in an "init modem driver" request sent to the modem.
 * The modem uses this information for initialization, and once
 * it's done it sends its response (normally indicating success).
 *
 * The modem, meanwhile, is able to perform some initialization
 * before it receives the information from the "init modem driver"
 * request, and will send an "indication register" request to the
 * AP once it is prepared to receive indications from the AP.  When
 * this is received, the AP sends a response indicating success.
 *
 * The above two request/response transactions can occur in any
 * order.  Regardless, once both have completed successfully, the AP
 * sends a "master driver complete" indication to the modem, which
 * completes the handshake.
 */
static int ipa3_qmi_send_handshake_complete_indication(void)
{
	struct msg_desc *desc = &ipa3_master_driver_complete_indication_desc;
	struct ipa_master_driver_init_complt_ind_msg_v01 ind;
	size_t size = sizeof(ind);

	ipa_debug("send indication to modem\n");

	memset(&ind, 0, size);
	ind.master_driver_init_status.result = IPA_QMI_RESULT_SUCCESS_V01;

	return qmi_send_ind(ipa3_svc_handle, curr_conn, desc, &ind, size);
}

static int ipa3_send_resp_from_cb(void *req_h, struct msg_desc *resp_desc,
			  void *resp, size_t resp_size)
{
	return qmi_send_resp_from_cb(ipa3_svc_handle, curr_conn, req_h,
			resp_desc, resp, (unsigned int)resp_size);
}

static int ipa3_handle_indication_req(void *req_h, void *req)
{
	struct msg_desc *desc = &ipa3_indication_reg_resp_desc;
	struct ipa_indication_reg_resp_msg_v01 resp;
	size_t size = sizeof(resp);
	int rc;

	ipa_debug("Received INDICATION Request\n");

	memset(&resp, 0, size);
	resp.resp.result = IPA_QMI_RESULT_SUCCESS_V01;

	rc = ipa3_send_resp_from_cb(req_h, desc, &resp, size);

	ipa3_qmi_indication_fin = true;

	/* check if need sending indication to modem */
	if (ipa3_qmi_modem_init_fin)
		rc = ipa3_qmi_send_handshake_complete_indication();
	else
		ipa_err("not send indication\n");

	return rc;
}

static int ipa3_handle_config_req(void *req_h, void *req)
{
	struct msg_desc *desc = &ipa3_config_req_desc;
	struct ipa_config_resp_msg_v01 resp;
	size_t size = sizeof(resp);
	int rc;

	ipa_debug("Received QMI_IPA_CONFIG_REQ_V01\n");

	memset(&resp, 0, size);
	resp.resp.result = IPA_QMI_RESULT_SUCCESS_V01;

	rc = ipa3_send_resp_from_cb(req_h, desc, &resp, size);

	ipa_debug("Sent QMI_IPA_CONFIG_RESP_V01\n");

	return rc;
}
static int ipa3_install_filter_rule_req(void *req_h, void *req)
{
	struct msg_desc *desc = &ipa3_install_fltr_rule_resp_desc;
	struct ipa_install_fltr_rule_resp_msg_v01 resp;
	size_t size = sizeof(resp);
	int rc;

	ipa_debug("Received QMI_IPA_INSTALL_FILTER_RULE_REQ_V01\n");

	memset(&resp, 0, size);
	resp.resp.result = IPA_QMI_RESULT_SUCCESS_V01;

	rc = ipa3_send_resp_from_cb(req_h, desc, &resp, size);

	ipa_debug("Sent QMI_IPA_INSTALL_FILTER_RULE_RESP_V01\n");

	return rc;
}

static int ipa3_handle_modem_init_cmplt_req(void *req_h, void *req)
{
	struct msg_desc *desc = &ipa3_init_modem_driver_cmplt_resp_desc;
	struct ipa_init_modem_driver_cmplt_resp_msg_v01 resp;
	size_t size = sizeof(resp);
	int rc;

	ipa_debug("Received QMI_IPA_INIT_MODEM_DRIVER_CMPLT_REQ_V01\n");

	ipa3_modem_init_cmplt = true;

	memset(&resp, 0, size);
	resp.resp.result = IPA_QMI_RESULT_SUCCESS_V01;

	rc = ipa3_send_resp_from_cb(req_h, desc, &resp, size);

	ipa_debug("Sent QMI_IPA_INIT_MODEM_DRIVER_CMPLT_RESP_V01\n");

	return rc;
}

static int ipa3_a5_svc_connect_cb(struct qmi_handle *handle, void *conn_h)
{
	if (curr_conn)
		return -ECONNREFUSED;

	curr_conn = conn_h;

	return 0;
}

static int ipa3_a5_svc_disconnect_cb(struct qmi_handle *handle, void *conn_h)
{
	if (curr_conn != conn_h)
		return -EINVAL;

	curr_conn = NULL;

	return 0;
}

static int ipa3_a5_svc_req_desc_cb(unsigned int msg_id,
				struct msg_desc **req_desc)
{
	int rc;

	switch (msg_id) {
	case QMI_IPA_INDICATION_REGISTER_REQ_V01:
		*req_desc = &ipa3_indication_reg_req_desc;
		rc = sizeof(struct ipa_indication_reg_req_msg_v01);
		break;
	case QMI_IPA_INSTALL_FILTER_RULE_REQ_V01:
		*req_desc = &ipa3_install_fltr_rule_req_desc;
		rc = sizeof(struct ipa_install_fltr_rule_req_msg_v01);
		break;
	case QMI_IPA_CONFIG_REQ_V01:
		*req_desc = &ipa3_config_req_desc;
		rc = sizeof(struct ipa_config_req_msg_v01);
		break;
	case QMI_IPA_INIT_MODEM_DRIVER_CMPLT_REQ_V01:
		*req_desc = &ipa3_init_modem_driver_cmplt_req_desc;
		rc = sizeof(struct ipa_init_modem_driver_cmplt_req_msg_v01);
		break;
	default:
		rc = -ENOTSUPP;
		break;
	}
	return rc;
}

static int ipa3_a5_svc_req_cb(struct qmi_handle *handle, void *conn_h,
			void *req_h, unsigned int msg_id, void *req)
{
	int rc;

	if (curr_conn != conn_h)
		return -EINVAL;

	switch (msg_id) {
	case QMI_IPA_INDICATION_REGISTER_REQ_V01:
		rc = ipa3_handle_indication_req(req_h, req);
		break;
	case QMI_IPA_CONFIG_REQ_V01:
		rc = ipa3_handle_config_req(req_h, req);
		break;
	case QMI_IPA_INSTALL_FILTER_RULE_REQ_V01:
		rc = ipa3_install_filter_rule_req(req_h, req);
		break;
	case QMI_IPA_INIT_MODEM_DRIVER_CMPLT_REQ_V01:
		rc = ipa3_handle_modem_init_cmplt_req(req_h, req);
		break;
	default:
		rc = -ENOTSUPP;
		break;
	}
	return rc;
}

static void ipa3_a5_svc_recv_msg(struct work_struct *work)
{
	int rc;

	do {
		ipa_debug_low("Notified about a Receive Event");
		rc = qmi_recv_msg(ipa3_svc_handle);
	} while (rc == 0);
	if (rc != -ENOMSG)
		ipa_err("Error receiving message\n");
}

static void qmi_ipa_a5_svc_ntfy(struct qmi_handle *handle,
		enum qmi_event_type event, void *priv)
{
	if (event != QMI_RECV_MSG)
		return;		/* Silently ignore unsupported events */

	if (workqueues_stopped)
		return;

	queue_work(ipa_svc_workqueue, &work_recv_msg);
}

static struct qmi_svc_ops_options ipa3_a5_svc_ops_options = {
	.version = 1,
	.service_id = IPA_A5_SERVICE_SVC_ID,
	.service_vers = IPA_A5_SVC_VERS,
	.service_ins = IPA_A5_SERVICE_INS_ID,
	.connect_cb = ipa3_a5_svc_connect_cb,
	.disconnect_cb = ipa3_a5_svc_disconnect_cb,
	.req_desc_cb = ipa3_a5_svc_req_desc_cb,
	.req_cb = ipa3_a5_svc_req_cb,
};

/****************************************************/
/*		   QMI A5 client ->Q6		    */
/****************************************************/
static void ipa3_q6_clnt_recv_msg(struct work_struct *work);
static DECLARE_WORK(ipa3_work_recv_msg_client, ipa3_q6_clnt_recv_msg);
static void ipa3_q6_clnt_svc_arrive(struct work_struct *work);
static DECLARE_WORK(ipa3_work_svc_arrive, ipa3_q6_clnt_svc_arrive);
static void ipa3_q6_clnt_svc_exit(struct work_struct *work);
static DECLARE_WORK(ipa3_work_svc_exit, ipa3_q6_clnt_svc_exit);
/* Test client port for IPC Router */
static struct qmi_handle *ipa_q6_clnt;
static int ipa_q6_clnt_reset;

static void
init_modem_driver_req_msg_dump(struct ipa_init_modem_driver_req_msg_v01 *req)
{
#define DUMP(field)	ipa_debug(#field " %d\n", req->field)
	DUMP(platform_type);
	DUMP(hdr_tbl_info.modem_offset_start);
	DUMP(hdr_tbl_info.modem_offset_end);
	DUMP(v4_route_tbl_info.route_tbl_start_addr);
	DUMP(v4_route_tbl_info.num_indices);
	DUMP(v6_route_tbl_info.route_tbl_start_addr);
	DUMP(v6_route_tbl_info.num_indices);
	DUMP(v4_filter_tbl_start_addr);
	DUMP(v6_filter_tbl_start_addr);
	DUMP(modem_mem_info.block_start_addr);
	DUMP(modem_mem_info.size);
	DUMP(ctrl_comm_dest_end_pt);
	DUMP(is_ssr_bootup);
	DUMP(v4_hash_route_tbl_info.route_tbl_start_addr);
	DUMP(v4_hash_route_tbl_info.num_indices);
	DUMP(v6_hash_route_tbl_info.route_tbl_start_addr);
	DUMP(v6_hash_route_tbl_info.num_indices);
	DUMP(v4_hash_filter_tbl_start_addr);
	DUMP(v6_hash_filter_tbl_start_addr);
#undef DUMP
}

static int ipa3_qmi_init_modem_send_sync_msg(void)
{
	struct ipa_init_modem_driver_req_msg_v01 req;
	struct ipa_init_modem_driver_resp_msg_v01 resp;
	struct msg_desc req_desc, resp_desc;
	u32 offset;
	int rc;
	u16 restricted_bytes = ipa3_get_smem_restr_bytes();

	if (unlikely(!ipa_q6_clnt))
		return -ETIMEDOUT;

	memset(&req, 0, sizeof(struct ipa_init_modem_driver_req_msg_v01));
	memset(&resp, 0, sizeof(struct ipa_init_modem_driver_resp_msg_v01));

	req.platform_type_valid = true;
	req.platform_type = ipa_wan_platform;

	if (ipa3_mem(MODEM_HDR_SIZE)) {
		req.hdr_tbl_info_valid = true;
		offset = restricted_bytes + ipa3_mem(MODEM_HDR_OFST);
		req.hdr_tbl_info.modem_offset_start = offset;
		req.hdr_tbl_info.modem_offset_end =
			offset + ipa3_mem(MODEM_HDR_SIZE) - 1;
	}

	req.v4_route_tbl_info_valid = true;
	offset = restricted_bytes + ipa3_mem(V4_RT_NHASH_OFST);
	req.v4_route_tbl_info.route_tbl_start_addr = offset;
	req.v4_route_tbl_info.num_indices = ipa3_mem(V4_MODEM_RT_INDEX_HI);

	req.v6_route_tbl_info_valid = true;
	offset = restricted_bytes + ipa3_mem(V6_RT_NHASH_OFST);
	req.v6_route_tbl_info.route_tbl_start_addr = offset;
	req.v6_route_tbl_info.num_indices = ipa3_mem(V6_MODEM_RT_INDEX_HI);

	req.v4_filter_tbl_start_addr_valid = true;
	offset = restricted_bytes + ipa3_mem(V4_FLT_NHASH_OFST);
	req.v4_filter_tbl_start_addr = offset;

	req.v6_filter_tbl_start_addr_valid = true;
	offset = restricted_bytes + ipa3_mem(V6_FLT_NHASH_OFST);
	req.v6_filter_tbl_start_addr = offset;

	if (ipa3_mem(MODEM_SIZE)) {
		req.modem_mem_info_valid = true;
		offset = restricted_bytes + ipa3_mem(MODEM_OFST);
		req.modem_mem_info.block_start_addr = offset;
		req.modem_mem_info.size = ipa3_mem(MODEM_SIZE);
	}

	req.ctrl_comm_dest_end_pt_valid = true;
	req.ctrl_comm_dest_end_pt =
		ipa3_get_ep_mapping(IPA_CLIENT_APPS_WAN_CONS);

	if (ipa3_mem(MODEM_HDR_PROC_CTX_SIZE)) {
		req.hdr_proc_ctx_tbl_info_valid = true;
		offset = restricted_bytes + ipa3_mem(MODEM_HDR_PROC_CTX_OFST);
		req.hdr_proc_ctx_tbl_info.modem_offset_start = offset;
		req.hdr_proc_ctx_tbl_info.modem_offset_end =
			offset + ipa3_mem(MODEM_HDR_PROC_CTX_SIZE) - 1;
	}

	if (ipa3_mem(MODEM_COMP_DECOMP_SIZE)) {
		req.zip_tbl_info_valid = true;
		offset = restricted_bytes + ipa3_mem(MODEM_COMP_DECOMP_OFST);
		req.zip_tbl_info.modem_offset_start = offset;
		req.zip_tbl_info.modem_offset_end =
			offset + ipa3_mem(MODEM_COMP_DECOMP_SIZE) - 1;
	}

	req.v4_hash_route_tbl_info_valid = true;
	offset = restricted_bytes + ipa3_mem(V4_RT_HASH_OFST);
	req.v4_hash_route_tbl_info.route_tbl_start_addr = offset;
	req.v4_hash_route_tbl_info.num_indices = ipa3_mem(V4_MODEM_RT_INDEX_HI);

	req.v6_hash_route_tbl_info_valid = true;
	offset = restricted_bytes + ipa3_mem(V6_RT_HASH_OFST);
	req.v6_hash_route_tbl_info.route_tbl_start_addr = offset;
	req.v6_hash_route_tbl_info.num_indices = ipa3_mem(V6_MODEM_RT_INDEX_HI);

	req.v4_hash_filter_tbl_start_addr_valid = true;
	offset = restricted_bytes + ipa3_mem(V4_FLT_HASH_OFST);
	req.v4_hash_filter_tbl_start_addr = offset;

	req.v6_hash_filter_tbl_start_addr_valid = true;
	offset = restricted_bytes + ipa3_mem(V6_FLT_HASH_OFST);
	req.v6_hash_filter_tbl_start_addr = offset;

	/* Distinguish between first time and SSR boot */
	if (ipa3_uc_loaded_check()) {
		req.is_ssr_bootup_valid = true;
		req.is_ssr_bootup = 1;	/* Not first time */
	}

	init_modem_driver_req_msg_dump(&req);

	req_desc.max_msg_len = QMI_IPA_INIT_MODEM_DRIVER_REQ_MAX_MSG_LEN_V01;
	req_desc.msg_id = QMI_IPA_INIT_MODEM_DRIVER_REQ_V01;
	req_desc.ei_array = ipa3_init_modem_driver_req_msg_data_v01_ei;

	resp_desc.max_msg_len = QMI_IPA_INIT_MODEM_DRIVER_RESP_MAX_MSG_LEN_V01;
	resp_desc.msg_id = QMI_IPA_INIT_MODEM_DRIVER_RESP_V01;
	resp_desc.ei_array = ipa3_init_modem_driver_resp_msg_data_v01_ei;

	ipa_info("Sending QMI_IPA_INIT_MODEM_DRIVER_REQ_V01\n");
	rc = qmi_send_req_wait(ipa_q6_clnt, &req_desc, &req, sizeof(req),
			&resp_desc, &resp, sizeof(resp),
			QMI_SEND_REQ_TIMEOUT_MS);
	ipa_info("QMI_IPA_INIT_MODEM_DRIVER_REQ_V01 response received\n");

	if (rc) {
		if (rc == -ETIMEDOUT && ipa3_rmnet_ctx.ipa_rmnet_ssr)
			ipa_err("Timeout on qmi INIT_MODEM_DRIVER\n");
		else
			ipa_err("Error %d on qmi INIT_MODEM_DRIVER\n", rc);
		return rc;
	}

	if (resp.resp.result == IPA_QMI_RESULT_SUCCESS_V01)
		ipa_debug_low("Received init_modem_driver successfully\n");
	else if (ipa3_rmnet_ctx.ipa_rmnet_ssr)
		ipa_err("Got bad response %d on init_modem_driver\n",
				resp.resp.result);
	return 0;
}

static void ipa3_q6_clnt_recv_msg(struct work_struct *work)
{
	int rc;

	do {
		ipa_debug_low("Notified about a Receive Event");
		rc = qmi_recv_msg(ipa_q6_clnt);
	} while (rc == 0);
	if (rc != -ENOMSG)
		ipa_err("Error receiving message\n");
}

static void ipa3_q6_clnt_notify(struct qmi_handle *handle,
			     enum qmi_event_type event, void *notify_priv)
{
	if (event != QMI_RECV_MSG)
		return;		/* Silently ignore unsupported events */

	ipa_debug_low("client qmi recv message called");
	if (workqueues_stopped)
		return;

	queue_work(ipa_clnt_resp_workqueue, &ipa3_work_recv_msg_client);
}

static void ipa3_q6_clnt_svc_arrive(struct work_struct *work)
{
	int rc;

	/* Create a Local client port for QMI communication */
	ipa_q6_clnt = qmi_handle_create(ipa3_q6_clnt_notify, NULL);
	if (!ipa_q6_clnt) {
		ipa_err("QMI client handle alloc failed\n");
		return;
	}

	ipa_debug("Lookup server name, get client-hdl(%p)\n",
		ipa_q6_clnt);
	rc = qmi_connect_to_service(ipa_q6_clnt,
			IPA_Q6_SERVICE_SVC_ID,
			IPA_Q6_SVC_VERS,
			IPA_Q6_SERVICE_INS_ID);
	if (rc < 0) {
		ipa_err("Server not found\n");
		qmi_handle_destroy(ipa_q6_clnt);
		ipa_q6_clnt = NULL;
		return;
	}

	ipa_q6_clnt_reset = 0;
	ipa_debug("Q6 QMI service available now\n");
	/* Initialize modem IPA-driver */
	ipa_debug("send ipa3_qmi_init_modem_send_sync_msg to modem\n");
	rc = ipa3_qmi_init_modem_send_sync_msg();
	ipa_bug_on(rc && rc != -ENETRESET && rc == -ENODEV);
	if (rc) {
		ipa_err("qmi_init_modem_send_sync_msg failed due to SSR!\n");
		/* Cleanup will take place when ipa3_wwan_remove is called */
		return;
	}
	ipa3_qmi_modem_init_fin = true;

	/* In cold-bootup, first_time_handshake = false */
	ipa3_q6_handshake_complete(first_time_handshake);
	first_time_handshake = true;
	ipa_debug("complete, ipa3_qmi_modem_init_fin : %d\n",
		ipa3_qmi_modem_init_fin);

	if (ipa3_qmi_indication_fin)
		(void)ipa3_qmi_send_handshake_complete_indication();
	else
		ipa_err("not send indication\n");
}


static void ipa3_q6_clnt_svc_exit(struct work_struct *work)
{
	qmi_handle_destroy(ipa_q6_clnt);
	ipa_q6_clnt_reset = 1;
	ipa_q6_clnt = NULL;
}


static int ipa3_q6_clnt_svc_event_notify(struct notifier_block *this,
				      unsigned long code,
				      void *_cmd)
{
	if (workqueues_stopped)
		return 0;

	ipa_debug("event %ld\n", code);
	if (code == QMI_SERVER_ARRIVE)
		queue_work(ipa_clnt_req_workqueue, &ipa3_work_svc_arrive);
	else if (code == QMI_SERVER_EXIT)
		queue_work(ipa_clnt_req_workqueue, &ipa3_work_svc_exit);

	return 0;
}

static struct notifier_block ipa3_q6_clnt_nb = {
	.notifier_call = ipa3_q6_clnt_svc_event_notify,
};

static void ipa3_qmi_service_init_worker(struct work_struct *work)
{
	int rc;

	/* Initialize QMI-service*/
	ipa_debug("IPA A7 QMI init OK :>>>>\n");

	ipa_svc_workqueue = create_singlethread_workqueue("ipa_A7_svc");
	if (!ipa_svc_workqueue) {
		ipa_err("Creating ipa_A7_svc workqueue failed\n");
		return;
	}

	ipa3_svc_handle = qmi_handle_create(qmi_ipa_a5_svc_ntfy, NULL);
	if (!ipa3_svc_handle) {
		ipa_err("Creating ipa_A7_svc qmi handle failed\n");
		goto destroy_ipa_A7_svc_wq;
	}

	/*
	 * Setting the current connection to NULL, as due to a race between
	 * server and client clean-up in SSR, the disconnect_cb might not
	 * have necessarily been called
	 */
	curr_conn = NULL;

	rc = qmi_svc_register(ipa3_svc_handle, &ipa3_a5_svc_ops_options);
	if (rc < 0) {
		ipa_err("Registering ipa_a5 svc failed %d\n",
				rc);
		goto destroy_qmi_handle;
	}

	/* Initialize QMI-client */

	ipa_clnt_req_workqueue = create_singlethread_workqueue("clnt_req");
	if (!ipa_clnt_req_workqueue) {
		ipa_err("Creating clnt_req workqueue failed\n");
		goto deregister_qmi_srv;
	}

	ipa_clnt_resp_workqueue = create_singlethread_workqueue("clnt_resp");
	if (!ipa_clnt_resp_workqueue) {
		ipa_err("Creating clnt_resp workqueue failed\n");
		goto destroy_clnt_req_wq;
	}

	rc = qmi_svc_event_notifier_register(IPA_Q6_SERVICE_SVC_ID,
				IPA_Q6_SVC_VERS,
				IPA_Q6_SERVICE_INS_ID, &ipa3_q6_clnt_nb);
	if (rc < 0) {
		ipa_err("notifier register failed\n");
		goto destroy_clnt_resp_wq;
	}

	/* get Q6 service and start send modem-initial to Q6 */
	ipa_debug("wait service available\n");
	return;

destroy_clnt_resp_wq:
	destroy_workqueue(ipa_clnt_resp_workqueue);
	ipa_clnt_resp_workqueue = NULL;
destroy_clnt_req_wq:
	destroy_workqueue(ipa_clnt_req_workqueue);
	ipa_clnt_req_workqueue = NULL;
deregister_qmi_srv:
	qmi_svc_unregister(ipa3_svc_handle);
destroy_qmi_handle:
	qmi_handle_destroy(ipa3_svc_handle);
	ipa3_svc_handle = NULL;
destroy_ipa_A7_svc_wq:
	destroy_workqueue(ipa_svc_workqueue);
	ipa_svc_workqueue = NULL;
}

int ipa3_qmi_service_init(uint32_t wan_platform_type)
{
	ipa_wan_platform = wan_platform_type;
	ipa3_qmi_modem_init_fin = false;
	ipa3_qmi_indication_fin = false;
	ipa3_modem_init_cmplt = false;
	workqueues_stopped = false;

	if (!ipa3_svc_handle) {
		INIT_WORK(&ipa3_qmi_service_init_work,
			ipa3_qmi_service_init_worker);
		schedule_work(&ipa3_qmi_service_init_work);
	}
	return 0;
}

void ipa3_qmi_service_exit(void)
{
	int ret = 0;

	workqueues_stopped = true;

	/* qmi-service */
	if (ipa3_svc_handle) {
		ret = qmi_svc_unregister(ipa3_svc_handle);
		if (ret < 0)
			ipa_err("unregister qmi handle %p failed, ret=%d\n",
			ipa3_svc_handle, ret);
	}
	if (ipa_svc_workqueue) {
		flush_workqueue(ipa_svc_workqueue);
		destroy_workqueue(ipa_svc_workqueue);
		ipa_svc_workqueue = NULL;
	}

	if (ipa3_svc_handle) {
		ret = qmi_handle_destroy(ipa3_svc_handle);
		if (ret < 0)
			ipa_err("Error destroying qmi handle %p, ret=%d\n",
			ipa3_svc_handle, ret);
	}

	/* qmi-client */

	/* Unregister from events */
	ret = qmi_svc_event_notifier_unregister(IPA_Q6_SERVICE_SVC_ID,
				IPA_Q6_SVC_VERS,
				IPA_Q6_SERVICE_INS_ID, &ipa3_q6_clnt_nb);
	if (ret < 0)
		ipa_err(
		"Error qmi_svc_event_notifier_unregister service %d, ret=%d\n",
		IPA_Q6_SERVICE_SVC_ID, ret);

	/* Release client handle */
	ipa3_q6_clnt_svc_exit(0);

	if (ipa_clnt_req_workqueue) {
		destroy_workqueue(ipa_clnt_req_workqueue);
		ipa_clnt_req_workqueue = NULL;
	}
	if (ipa_clnt_resp_workqueue) {
		destroy_workqueue(ipa_clnt_resp_workqueue);
		ipa_clnt_resp_workqueue = NULL;
	}

	ipa3_svc_handle = NULL;
	ipa3_qmi_modem_init_fin = false;
	ipa3_qmi_indication_fin = false;
	ipa3_modem_init_cmplt = false;
}

void ipa3_qmi_stop_workqueues(void)
{
	ipa_debug("Stopping all QMI workqueues\n");

	/* Stopping all workqueues so new work won't be scheduled */
	workqueues_stopped = true;

	/* Making sure that the current scheduled work won't be executed */
	cancel_work(&work_recv_msg);
	cancel_work(&ipa3_work_recv_msg_client);
	cancel_work(&ipa3_work_svc_arrive);
	cancel_work(&ipa3_work_svc_exit);
}
