/* Copyright (c) 2013-2017, The Linux Foundation. All rights reserved.
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

#ifndef IPA_QMI_SERVICE_H
#define IPA_QMI_SERVICE_H

#include <linux/ipc_logging.h>
#include "ipa_qmi_service_v01.h"
#include <soc/qcom/msm_qmi_interface.h>
#include "ipa_i.h"

/**
 * name of the DL wwan default routing tables for v4 and v6
 */
#define IPA_A7_QMAP_HDR_NAME "ipa_qmap_hdr"
#define IPA_DFLT_WAN_RT_TBL_NAME "ipa_dflt_wan_rt"
#define MAX_NUM_Q6_RULE 35
#define MAX_NUM_QMI_RULE_CACHE 10
#define DEV_NAME "ipa-wan"
#define SUBSYS_MODEM "modem"

/* User space may not have this defined. */
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif


struct ipa3_rmnet_mux_val {
	uint32_t  mux_id;
	int8_t    vchannel_name[IFNAMSIZ];
	bool mux_channel_set;
	bool ul_flt_reg;
	bool mux_hdr_set;
	uint32_t  hdr_hdl;
};

extern struct elem_info ipa3_init_modem_driver_req_msg_data_v01_ei[];
extern struct elem_info ipa3_init_modem_driver_resp_msg_data_v01_ei[];
extern struct elem_info ipa3_indication_reg_req_msg_data_v01_ei[];
extern struct elem_info ipa3_indication_reg_resp_msg_data_v01_ei[];
extern struct elem_info ipa3_master_driver_init_complt_ind_msg_data_v01_ei[];
extern struct elem_info ipa3_install_fltr_rule_req_msg_data_v01_ei[];
extern struct elem_info ipa3_install_fltr_rule_resp_msg_data_v01_ei[];
extern struct elem_info ipa3_fltr_installed_notif_req_msg_data_v01_ei[];
extern struct elem_info ipa3_fltr_installed_notif_resp_msg_data_v01_ei[];
extern struct elem_info ipa3_enable_force_clear_datapath_req_msg_data_v01_ei[];
extern struct elem_info ipa3_enable_force_clear_datapath_resp_msg_data_v01_ei[];
extern struct elem_info ipa3_disable_force_clear_datapath_req_msg_data_v01_ei[];
extern struct elem_info
	ipa3_disable_force_clear_datapath_resp_msg_data_v01_ei[];
extern struct elem_info ipa3_config_req_msg_data_v01_ei[];
extern struct elem_info ipa3_config_resp_msg_data_v01_ei[];
extern struct elem_info ipa3_get_data_stats_req_msg_data_v01_ei[];
extern struct elem_info ipa3_get_data_stats_resp_msg_data_v01_ei[];
extern struct elem_info ipa3_get_apn_data_stats_req_msg_data_v01_ei[];
extern struct elem_info ipa3_get_apn_data_stats_resp_msg_data_v01_ei[];
extern struct elem_info ipa3_init_modem_driver_cmplt_req_msg_data_v01_ei[];
extern struct elem_info ipa3_init_modem_driver_cmplt_resp_msg_data_v01_ei[];

/**
 * struct ipa3_rmnet_context - IPA rmnet context
 * @ipa_rmnet_ssr: support modem SSR
 * @polling_interval: Requested interval for polling tethered statistics
 * @metered_mux_id: The mux ID on which quota has been set
 */
struct ipa3_rmnet_context {
	bool ipa_rmnet_ssr;
	u64 polling_interval;
	u32 metered_mux_id;
};

extern struct ipa3_rmnet_context ipa3_rmnet_ctx;

int ipa3_qmi_service_init(uint32_t wan_platform_type);

void ipa3_qmi_service_exit(void);

int ipa3_qmi_enable_force_clear_datapath_send(
	struct ipa_enable_force_clear_datapath_req_msg_v01 *req);

int ipa3_qmi_disable_force_clear_datapath_send(
	struct ipa_disable_force_clear_datapath_req_msg_v01 *req);

void ipa3_qmi_stop_workqueues(void);

void ipa3_q6_handshake_complete(bool ssr_bootup);

#endif /* IPA_QMI_SERVICE_H */
