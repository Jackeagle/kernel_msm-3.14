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

#ifndef IPA_QMI_SERVICE_H
#define IPA_QMI_SERVICE_H

#include <linux/ipc_logging.h>
#include "ipa_qmi_service_v01.h"
#include <soc/qcom/msm_qmi_interface.h>
#include "ipa_i.h"

/**
 * name of the DL wwan default routing tables for v4 and v6
 */
#define DEV_NAME "ipa-wan"
#define SUBSYS_MODEM "modem"

/* User space may not have this defined. */
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif


struct ipa3_rmnet_mux_val {
	uint32_t  mux_id;
	int8_t	  vchannel_name[IFNAMSIZ];
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
extern struct elem_info ipa3_config_req_msg_data_v01_ei[];
extern struct elem_info ipa3_config_resp_msg_data_v01_ei[];
extern struct elem_info ipa3_init_modem_driver_cmplt_req_msg_data_v01_ei[];
extern struct elem_info ipa3_init_modem_driver_cmplt_resp_msg_data_v01_ei[];

int ipa3_qmi_service_init(uint32_t wan_platform_type);

void ipa3_qmi_service_exit(void);

void ipa3_qmi_stop_workqueues(void);

void ipa3_q6_handshake_complete(bool ssr_bootup);

#endif /* IPA_QMI_SERVICE_H */
