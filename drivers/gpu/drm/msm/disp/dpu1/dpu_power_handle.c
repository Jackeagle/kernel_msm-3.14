/* Copyright (c) 2014-2018, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#define pr_fmt(fmt)	"[drm:%s:%d]: " fmt, __func__, __LINE__

#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/string.h>
#include <linux/of_address.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/of_platform.h>

#include "dpu_power_handle.h"
#include "dpu_trace.h"

#ifdef CONFIG_QCOM_BUS_SCALING
#include <linux/msm-bus.h>
#include <linux/msm-bus-board.h>

#define DPU_BUS_VECTOR_ENTRY(src_val, dst_val, ab_val, ib_val) \
	{                                                          \
		.src = src_val,                                        \
		.dst = dst_val,                                        \
		.ab = (ab_val),                                        \
		.ib = (ib_val),                                        \
	}

static struct msm_bus_vectors dpu_reg_bus_vectors[] = {
	DPU_BUS_VECTOR_ENTRY(MSM_BUS_MASTER_FIRST,
			     MSM_BUS_SLAVE_DISPLAY_CFG, 0, 0),
	DPU_BUS_VECTOR_ENTRY(MSM_BUS_MASTER_FIRST,
			     MSM_BUS_SLAVE_DISPLAY_CFG, 0, 76800000),
	DPU_BUS_VECTOR_ENTRY(MSM_BUS_MASTER_FIRST,
			     MSM_BUS_SLAVE_DISPLAY_CFG, 0, 150000000),
	DPU_BUS_VECTOR_ENTRY(MSM_BUS_MASTER_FIRST,
			     MSM_BUS_SLAVE_DISPLAY_CFG, 0, 300000000),
};

static struct msm_bus_paths dpu_reg_bus_usecases[] = { {
		.num_paths = 1,
		.vectors = &dpu_reg_bus_vectors[0],
}, {
		.num_paths = 1,
		.vectors = &dpu_reg_bus_vectors[1],
}, {
		.num_paths = 1,
		.vectors = &dpu_reg_bus_vectors[2],
}, {
		.num_paths = 1,
		.vectors = &dpu_reg_bus_vectors[3],
} };

static struct msm_bus_scale_pdata dpu_reg_bus_scale_table = {
	.usecase = dpu_reg_bus_usecases,
	.num_usecases = ARRAY_SIZE(dpu_reg_bus_usecases),
	.name = "mdss_reg",
};

static struct msm_bus_vectors dpu_data_bus_vectors[] = {
	DPU_BUS_VECTOR_ENTRY(MSM_BUS_MASTER_MDP_PORT0,
			     MSM_BUS_SLAVE_MNOC_HF_MEM_NOC, 0, 0),
	DPU_BUS_VECTOR_ENTRY(MSM_BUS_MASTER_MDP_PORT1,
			     MSM_BUS_SLAVE_MNOC_HF_MEM_NOC, 0, 0),
	DPU_BUS_VECTOR_ENTRY(MSM_BUS_MASTER_MDP_PORT0,
			     MSM_BUS_SLAVE_MNOC_HF_MEM_NOC, 0, 6400000000),
	DPU_BUS_VECTOR_ENTRY(MSM_BUS_MASTER_MDP_PORT1,
			     MSM_BUS_SLAVE_MNOC_HF_MEM_NOC, 0, 6400000000),
	DPU_BUS_VECTOR_ENTRY(MSM_BUS_MASTER_MDP_PORT0,
			     MSM_BUS_SLAVE_MNOC_HF_MEM_NOC, 0, 6400000000),
	DPU_BUS_VECTOR_ENTRY(MSM_BUS_MASTER_MDP_PORT1,
			     MSM_BUS_SLAVE_MNOC_HF_MEM_NOC, 0, 6400000000),
};

static struct msm_bus_paths dpu_data_bus_usecases[] = { {
		.num_paths = 2,
		.vectors = &dpu_data_bus_vectors[0],
}, {
		.num_paths = 2,
		.vectors = &dpu_data_bus_vectors[2],
}, {
		.num_paths = 2,
		.vectors = &dpu_data_bus_vectors[4],
} };

static struct msm_bus_scale_pdata dpu_data_bus_scale_table = {
	.usecase = dpu_data_bus_usecases,
	.num_usecases = ARRAY_SIZE(dpu_data_bus_usecases),
	.name = "mdss_mnoc",
};

static struct msm_bus_vectors dpu_llcc_bus_vectors[] = {
	DPU_BUS_VECTOR_ENTRY(MSM_BUS_MASTER_MNOC_HF_MEM_NOC,
			     MSM_BUS_SLAVE_LLCC, 0, 0),
	DPU_BUS_VECTOR_ENTRY(MSM_BUS_MASTER_MNOC_HF_MEM_NOC,
			     MSM_BUS_SLAVE_LLCC, 0, 6400000000),
	DPU_BUS_VECTOR_ENTRY(MSM_BUS_MASTER_MNOC_HF_MEM_NOC,
			     MSM_BUS_SLAVE_LLCC, 0, 6400000000),
};

static struct msm_bus_paths dpu_llcc_bus_usecases[] = { {
		.num_paths = 1,
		.vectors = &dpu_llcc_bus_vectors[0],
}, {
		.num_paths = 1,
		.vectors = &dpu_llcc_bus_vectors[1],
}, {
		.num_paths = 1,
		.vectors = &dpu_llcc_bus_vectors[2],
} };
static struct msm_bus_scale_pdata dpu_llcc_bus_scale_table = {
	.usecase = dpu_llcc_bus_usecases,
	.num_usecases = ARRAY_SIZE(dpu_llcc_bus_usecases),
	.name = "mdss_llcc",
};

static struct msm_bus_vectors dpu_ebi_bus_vectors[] = {
	DPU_BUS_VECTOR_ENTRY(MSM_BUS_MASTER_LLCC,
			     MSM_BUS_SLAVE_EBI_CH0, 0, 0),
	DPU_BUS_VECTOR_ENTRY(MSM_BUS_MASTER_LLCC,
			     MSM_BUS_SLAVE_EBI_CH0, 0, 6400000000),
	DPU_BUS_VECTOR_ENTRY(MSM_BUS_MASTER_LLCC,
			     MSM_BUS_SLAVE_EBI_CH0, 0, 6400000000),
};

static struct msm_bus_paths dpu_ebi_bus_usecases[] = { {
		.num_paths = 1,
		.vectors = &dpu_ebi_bus_vectors[0],
}, {
		.num_paths = 1,
		.vectors = &dpu_ebi_bus_vectors[1],
}, {
		.num_paths = 1,
		.vectors = &dpu_ebi_bus_vectors[2],
} };
static struct msm_bus_scale_pdata dpu_ebi_bus_scale_table = {
	.usecase = dpu_ebi_bus_usecases,
	.num_usecases = ARRAY_SIZE(dpu_ebi_bus_usecases),
	.name = "mdss_ebi",
};
#endif

static const char *data_bus_name[DPU_POWER_HANDLE_DBUS_ID_MAX] = {
	[DPU_POWER_HANDLE_DBUS_ID_MNOC] = "qcom,dpu-data-bus",
	[DPU_POWER_HANDLE_DBUS_ID_LLCC] = "qcom,dpu-llcc-bus",
	[DPU_POWER_HANDLE_DBUS_ID_EBI] = "qcom,dpu-ebi-bus",
};

const char *dpu_power_handle_get_dbus_name(u32 bus_id)
{
	if (bus_id < DPU_POWER_HANDLE_DBUS_ID_MAX)
		return data_bus_name[bus_id];

	return NULL;
}

static void dpu_power_event_trigger_locked(struct dpu_power_handle *phandle,
		u32 event_type)
{
	struct dpu_power_event *event;

	list_for_each_entry(event, &phandle->event_list, list) {
		if (event->event_type & event_type)
			event->cb_fnc(event_type, event->usr);
	}
}

struct dpu_power_client *dpu_power_client_create(
	struct dpu_power_handle *phandle, char *client_name)
{
	struct dpu_power_client *client;
	static u32 id;

	if (!client_name || !phandle) {
		pr_err("client name is null or invalid power data\n");
		return ERR_PTR(-EINVAL);
	}

	client = kzalloc(sizeof(struct dpu_power_client), GFP_KERNEL);
	if (!client)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&phandle->phandle_lock);
	strlcpy(client->name, client_name, MAX_CLIENT_NAME_LEN);
	client->usecase_ndx = VOTE_INDEX_DISABLE;
	client->id = id;
	client->active = true;
	pr_debug("client %s created:%pK id :%d\n", client_name,
		client, id);
	id++;
	list_add(&client->list, &phandle->power_client_clist);
	mutex_unlock(&phandle->phandle_lock);

	return client;
}

void dpu_power_client_destroy(struct dpu_power_handle *phandle,
	struct dpu_power_client *client)
{
	if (!client  || !phandle) {
		pr_err("reg bus vote: invalid client handle\n");
	} else if (!client->active) {
		pr_err("dpu power deinit already done\n");
		kfree(client);
	} else {
		pr_debug("bus vote client %s destroyed:%pK id:%u\n",
			client->name, client, client->id);
		mutex_lock(&phandle->phandle_lock);
		list_del_init(&client->list);
		mutex_unlock(&phandle->phandle_lock);
		kfree(client);
	}
}

#ifdef CONFIG_QCOM_BUS_SCALING

#define MAX_AXI_PORT_COUNT 3

static int _dpu_power_data_bus_set_quota(
		struct dpu_power_data_bus_handle *pdbus,
		u64 ab_quota_rt, u64 ab_quota_nrt,
		u64 ib_quota_rt, u64 ib_quota_nrt)
{
	int new_uc_idx;
	u64 ab_quota[MAX_AXI_PORT_COUNT] = {0, 0};
	u64 ib_quota[MAX_AXI_PORT_COUNT] = {0, 0};
	int rc;

	if (pdbus->data_bus_hdl < 1) {
		pr_err("invalid bus handle %d\n", pdbus->data_bus_hdl);
		return -EINVAL;
	}

	pdbus->ab_rt = ab_quota_rt;
	pdbus->ib_rt = ib_quota_rt;
	pdbus->ab_nrt = ab_quota_nrt;
	pdbus->ib_nrt = ib_quota_nrt;

	if (pdbus->enable) {
		ab_quota_rt = max_t(u64, ab_quota_rt,
				DPU_POWER_HANDLE_ENABLE_BUS_AB_QUOTA);
		ib_quota_rt = max_t(u64, ib_quota_rt,
				DPU_POWER_HANDLE_ENABLE_BUS_IB_QUOTA);
		ab_quota_nrt = max_t(u64, ab_quota_nrt,
				DPU_POWER_HANDLE_ENABLE_BUS_AB_QUOTA);
		ib_quota_nrt = max_t(u64, ib_quota_nrt,
				DPU_POWER_HANDLE_ENABLE_BUS_IB_QUOTA);
	} else {
		ab_quota_rt = min_t(u64, ab_quota_rt,
				DPU_POWER_HANDLE_DISABLE_BUS_AB_QUOTA);
		ib_quota_rt = min_t(u64, ib_quota_rt,
				DPU_POWER_HANDLE_DISABLE_BUS_IB_QUOTA);
		ab_quota_nrt = min_t(u64, ab_quota_nrt,
				DPU_POWER_HANDLE_DISABLE_BUS_AB_QUOTA);
		ib_quota_nrt = min_t(u64, ib_quota_nrt,
				DPU_POWER_HANDLE_DISABLE_BUS_IB_QUOTA);
	}

	if (!ab_quota_rt && !ab_quota_nrt && !ib_quota_rt && !ib_quota_nrt)  {
		new_uc_idx = 0;
	} else {
		int i;
		struct msm_bus_vectors *vect = NULL;
		struct msm_bus_scale_pdata *bw_table =
			pdbus->data_bus_scale_table;
		u32 nrt_axi_port_cnt = pdbus->nrt_axi_port_cnt;
		u32 total_axi_port_cnt = pdbus->axi_port_cnt;
		u32 rt_axi_port_cnt = total_axi_port_cnt - nrt_axi_port_cnt;

		if (!bw_table || !total_axi_port_cnt ||
		    total_axi_port_cnt > MAX_AXI_PORT_COUNT) {
			pr_err("invalid input\n");
			return -EINVAL;
		}

		if (pdbus->bus_channels) {
			ib_quota_rt = div_u64(ib_quota_rt,
						pdbus->bus_channels);
			ib_quota_nrt = div_u64(ib_quota_nrt,
						pdbus->bus_channels);
		}

		if (nrt_axi_port_cnt) {

			ab_quota_rt = div_u64(ab_quota_rt, rt_axi_port_cnt);
			ab_quota_nrt = div_u64(ab_quota_nrt, nrt_axi_port_cnt);

			for (i = 0; i < total_axi_port_cnt; i++) {
				if (i < rt_axi_port_cnt) {
					ab_quota[i] = ab_quota_rt;
					ib_quota[i] = ib_quota_rt;
				} else {
					ab_quota[i] = ab_quota_nrt;
					ib_quota[i] = ib_quota_nrt;
				}
			}
		} else {
			ab_quota[0] = div_u64(ab_quota_rt + ab_quota_nrt,
					total_axi_port_cnt);
			ib_quota[0] = ib_quota_rt + ib_quota_nrt;

			for (i = 1; i < total_axi_port_cnt; i++) {
				ab_quota[i] = ab_quota[0];
				ib_quota[i] = ib_quota[0];
			}
		}

		new_uc_idx = (pdbus->curr_bw_uc_idx %
			(bw_table->num_usecases - 1)) + 1;

		for (i = 0; i < total_axi_port_cnt; i++) {
			vect = &bw_table->usecase[new_uc_idx].vectors[i];
			vect->ab = ab_quota[i];
			vect->ib = ib_quota[i];

			pr_debug(
				"%s uc_idx=%d %s path idx=%d ab=%llu ib=%llu\n",
				bw_table->name,
				new_uc_idx, (i < rt_axi_port_cnt) ? "rt" : "nrt"
				, i, vect->ab, vect->ib);
		}
	}
	pdbus->curr_bw_uc_idx = new_uc_idx;
	pdbus->ao_bw_uc_idx = new_uc_idx;

	DPU_ATRACE_BEGIN("msm_bus_scale_req");
	rc = msm_bus_scale_client_update_request(pdbus->data_bus_hdl,
			new_uc_idx);
	DPU_ATRACE_END("msm_bus_scale_req");

	return rc;
}

int dpu_power_data_bus_set_quota(struct dpu_power_handle *phandle,
		struct dpu_power_client *pclient,
		int bus_client, u32 bus_id,
		u64 ab_quota, u64 ib_quota)
{
	int rc = 0;
	int i;
	u64 total_ab_rt = 0, total_ib_rt = 0;
	u64 total_ab_nrt = 0, total_ib_nrt = 0;
	struct dpu_power_client *client;

	if (!phandle || !pclient ||
			bus_client >= DPU_POWER_HANDLE_DATA_BUS_CLIENT_MAX ||
			bus_id >= DPU_POWER_HANDLE_DBUS_ID_MAX) {
		pr_err("invalid parameters\n");
		return -EINVAL;
	}

	mutex_lock(&phandle->phandle_lock);

	pclient->ab[bus_client] = ab_quota;
	pclient->ib[bus_client] = ib_quota;
	trace_dpu_perf_update_bus(bus_client, ab_quota, ib_quota);

	list_for_each_entry(client, &phandle->power_client_clist, list) {
		for (i = 0; i < DPU_POWER_HANDLE_DATA_BUS_CLIENT_MAX; i++) {
			if (i == DPU_POWER_HANDLE_DATA_BUS_CLIENT_NRT) {
				total_ab_nrt += client->ab[i];
				total_ib_nrt += client->ib[i];
			} else {
				total_ab_rt += client->ab[i];
				total_ib_rt = max(total_ib_rt, client->ib[i]);
			}
		}
	}

	if (phandle->data_bus_handle[bus_id].data_bus_hdl)
		rc = _dpu_power_data_bus_set_quota(
			&phandle->data_bus_handle[bus_id],
			total_ab_rt, total_ab_nrt,
			total_ib_rt, total_ib_nrt);

	mutex_unlock(&phandle->phandle_lock);

	return rc;
}

static void dpu_power_data_bus_unregister(
		struct dpu_power_data_bus_handle *pdbus)
{
	if (pdbus->data_bus_hdl) {
		msm_bus_scale_unregister_client(pdbus->data_bus_hdl);
		pdbus->data_bus_hdl = 0;
	}
}

static int dpu_power_data_bus_register(struct dpu_power_handle *phandle,
		int index)
{
	struct dpu_power_data_bus_handle *pdbus = &phandle->data_bus_handle[index];

	pdbus->bus_channels = 2;
	pdbus->nrt_axi_port_cnt = 0;
	pdbus->axi_port_cnt = 1;

	switch (index) {
	case DPU_POWER_HANDLE_DBUS_ID_MNOC:
		pdbus->data_bus_scale_table = &dpu_data_bus_scale_table;
		pdbus->axi_port_cnt = 2;
		break;
	case DPU_POWER_HANDLE_DBUS_ID_LLCC:
		pdbus->data_bus_scale_table = &dpu_llcc_bus_scale_table;
		break;
	case DPU_POWER_HANDLE_DBUS_ID_EBI:
		pdbus->data_bus_scale_table = &dpu_ebi_bus_scale_table;
		break;
	default:
		pr_err("invalid data_bus type: %d", index);
		return -EINVAL;
	}

	pdbus->data_bus_hdl = msm_bus_scale_register_client(
			pdbus->data_bus_scale_table);
	if (!pdbus->data_bus_hdl) {
		pr_err("data_bus_client register failed\n");
		return -EINVAL;
	}
	pr_debug("register %s data_bus_hdl=%x\n", data_bus_name[index],
			pdbus->data_bus_hdl);

	return 0;
}

static int dpu_power_reg_bus_register(struct dpu_power_handle *phandle)
{
	phandle->reg_bus_hdl = msm_bus_scale_register_client(
			&dpu_reg_bus_scale_table);
	if (!phandle->reg_bus_hdl) {
		pr_err("reg_bus_client register failed\n");
		return -EINVAL;
	}
	pr_debug("register reg_bus_hdl=%x\n", phandle->reg_bus_hdl);

	return 0;
}

static void dpu_power_reg_bus_unregister(u32 reg_bus_hdl)
{
	if (reg_bus_hdl)
		msm_bus_scale_unregister_client(reg_bus_hdl);
}

int dpu_power_data_bus_state_update(struct dpu_power_handle *phandle,
							bool enable)
{
	int i;

	if (!phandle) {
		pr_err("invalid param\n");
		return -EINVAL;
	}

	for (i = DPU_POWER_HANDLE_DBUS_ID_MNOC;
			i < DPU_POWER_HANDLE_DBUS_ID_MAX; i++)
		phandle->data_bus_handle[i].enable = enable;

	return 0;
}

static int dpu_power_data_bus_update(struct dpu_power_data_bus_handle *pdbus,
							bool enable)
{
	int rc = 0;

	pdbus->enable = enable;

	if (pdbus->data_bus_hdl)
		rc = _dpu_power_data_bus_set_quota(pdbus, pdbus->ab_rt,
				pdbus->ab_nrt, pdbus->ib_rt, pdbus->ib_nrt);

	if (rc)
		pr_err("failed to set data bus vote rc=%d enable:%d\n",
							rc, enable);

	return rc;
}

static int dpu_power_reg_bus_update(u32 reg_bus_hdl, u32 usecase_ndx)
{
	int rc = 0;

	if (reg_bus_hdl)
		rc = msm_bus_scale_client_update_request(reg_bus_hdl,
								usecase_ndx);
	if (rc)
		pr_err("failed to set reg bus vote rc=%d\n", rc);

	return rc;
}
#else
static int dpu_power_data_bus_register(struct dpu_power_handle *phandle,
		int index)
{
	return 0;
}

static void dpu_power_data_bus_unregister(
		struct dpu_power_data_bus_handle *pdbus)
{
}

int dpu_power_data_bus_set_quota(struct dpu_power_handle *phandle,
		struct dpu_power_client *pclient,
		int bus_client, u32 bus_id,
		u64 ab_quota, u64 ib_quota)
{
	return 0;
}

static int dpu_power_reg_bus_register(struct dpu_power_handle *phandle)
{
	return 0;
}

static void dpu_power_reg_bus_unregister(u32 reg_bus_hdl)
{
}

static int dpu_power_reg_bus_update(u32 reg_bus_hdl, u32 usecase_ndx)
{
	return 0;
}

static int dpu_power_data_bus_update(struct dpu_power_data_bus_handle *pdbus,
							bool enable)
{
	return 0;
}

int dpu_power_data_bus_state_update(struct dpu_power_handle *phandle,
							bool enable)
{
	return 0;
}
#endif

int dpu_power_resource_init(struct platform_device *pdev,
	struct dpu_power_handle *phandle)
{
	int rc = 0, i;

	phandle->dev = &pdev->dev;

	rc = dpu_power_reg_bus_register(phandle);
	if (rc) {
		pr_err("register bus parse failed rc=%d\n", rc);
		return rc;
	}

	for (i = DPU_POWER_HANDLE_DBUS_ID_MNOC;
			i < DPU_POWER_HANDLE_DBUS_ID_MAX; i++) {
		rc = dpu_power_data_bus_register(phandle, i);
		if (rc) {
			pr_err("register data bus parse failed id=%d rc=%d\n",
					i, rc);
			goto data_bus_err;
		}
	}

	INIT_LIST_HEAD(&phandle->power_client_clist);
	INIT_LIST_HEAD(&phandle->event_list);

	mutex_init(&phandle->phandle_lock);

	return rc;

data_bus_err:
	for (i--; i >= 0; i--)
		dpu_power_data_bus_unregister(&phandle->data_bus_handle[i]);
	dpu_power_reg_bus_unregister(phandle->reg_bus_hdl);
	return rc;
}

void dpu_power_resource_deinit(struct platform_device *pdev,
	struct dpu_power_handle *phandle)
{
	struct dpu_power_client *curr_client, *next_client;
	struct dpu_power_event *curr_event, *next_event;
	int i;

	if (!phandle || !pdev) {
		pr_err("invalid input param\n");
		return;
	}

	mutex_lock(&phandle->phandle_lock);
	list_for_each_entry_safe(curr_client, next_client,
			&phandle->power_client_clist, list) {
		pr_err("cliend:%s-%d still registered with refcount:%d\n",
				curr_client->name, curr_client->id,
				curr_client->refcount);
		curr_client->active = false;
		list_del(&curr_client->list);
	}

	list_for_each_entry_safe(curr_event, next_event,
			&phandle->event_list, list) {
		pr_err("event:%d, client:%s still registered\n",
				curr_event->event_type,
				curr_event->client_name);
		curr_event->active = false;
		list_del(&curr_event->list);
	}
	mutex_unlock(&phandle->phandle_lock);

	for (i = 0; i < DPU_POWER_HANDLE_DBUS_ID_MAX; i++)
		dpu_power_data_bus_unregister(&phandle->data_bus_handle[i]);

	dpu_power_reg_bus_unregister(phandle->reg_bus_hdl);
}

int dpu_power_resource_enable(struct dpu_power_handle *phandle,
	struct dpu_power_client *pclient, bool enable)
{
	int rc = 0, i;
	bool changed = false;
	u32 max_usecase_ndx = VOTE_INDEX_DISABLE, prev_usecase_ndx;
	struct dpu_power_client *client;

	if (!phandle || !pclient) {
		pr_err("invalid input argument\n");
		return -EINVAL;
	}

	mutex_lock(&phandle->phandle_lock);
	if (enable)
		pclient->refcount++;
	else if (pclient->refcount)
		pclient->refcount--;

	if (pclient->refcount)
		pclient->usecase_ndx = VOTE_INDEX_LOW;
	else
		pclient->usecase_ndx = VOTE_INDEX_DISABLE;

	list_for_each_entry(client, &phandle->power_client_clist, list) {
		if (client->usecase_ndx < VOTE_INDEX_MAX &&
		    client->usecase_ndx > max_usecase_ndx)
			max_usecase_ndx = client->usecase_ndx;
	}

	if (phandle->current_usecase_ndx != max_usecase_ndx) {
		changed = true;
		prev_usecase_ndx = phandle->current_usecase_ndx;
		phandle->current_usecase_ndx = max_usecase_ndx;
	}

	pr_debug("%pS: changed=%d current idx=%d request client %s id:%u enable:%d refcount:%d\n",
		__builtin_return_address(0), changed, max_usecase_ndx,
		pclient->name, pclient->id, enable, pclient->refcount);

	if (!changed)
		goto end;

	if (enable) {
		dpu_power_event_trigger_locked(phandle,
				DPU_POWER_EVENT_PRE_ENABLE);

		for (i = 0; i < DPU_POWER_HANDLE_DBUS_ID_MAX; i++) {
			rc = dpu_power_data_bus_update(
					&phandle->data_bus_handle[i], enable);
			if (rc) {
				pr_err("failed to set data bus vote id=%d rc=%d\n",
						i, rc);
				goto data_bus_hdl_err;
			}
		}

		rc = dpu_power_reg_bus_update(phandle->reg_bus_hdl,
							max_usecase_ndx);
		if (rc) {
			pr_err("failed to set reg bus vote rc=%d\n", rc);
			goto reg_bus_hdl_err;
		}

		dpu_power_event_trigger_locked(phandle,
				DPU_POWER_EVENT_POST_ENABLE);

	} else {
		dpu_power_event_trigger_locked(phandle,
				DPU_POWER_EVENT_PRE_DISABLE);

		dpu_power_reg_bus_update(phandle->reg_bus_hdl,
							max_usecase_ndx);

		for (i = 0 ; i < DPU_POWER_HANDLE_DBUS_ID_MAX; i++)
			dpu_power_data_bus_update(&phandle->data_bus_handle[i],
					enable);

		dpu_power_event_trigger_locked(phandle,
				DPU_POWER_EVENT_POST_DISABLE);
	}

end:
	mutex_unlock(&phandle->phandle_lock);
	return rc;

reg_bus_hdl_err:
	for (i = 0 ; i < DPU_POWER_HANDLE_DBUS_ID_MAX; i++)
		dpu_power_data_bus_update(&phandle->data_bus_handle[i], 0);
data_bus_hdl_err:
	phandle->current_usecase_ndx = prev_usecase_ndx;
	mutex_unlock(&phandle->phandle_lock);
	return rc;
}

struct dpu_power_event *dpu_power_handle_register_event(
		struct dpu_power_handle *phandle,
		u32 event_type, void (*cb_fnc)(u32 event_type, void *usr),
		void *usr, char *client_name)
{
	struct dpu_power_event *event;

	if (!phandle) {
		pr_err("invalid power handle\n");
		return ERR_PTR(-EINVAL);
	} else if (!cb_fnc || !event_type) {
		pr_err("no callback fnc or event type\n");
		return ERR_PTR(-EINVAL);
	}

	event = kzalloc(sizeof(struct dpu_power_event), GFP_KERNEL);
	if (!event)
		return ERR_PTR(-ENOMEM);

	event->event_type = event_type;
	event->cb_fnc = cb_fnc;
	event->usr = usr;
	strlcpy(event->client_name, client_name, MAX_CLIENT_NAME_LEN);
	event->active = true;

	mutex_lock(&phandle->phandle_lock);
	list_add(&event->list, &phandle->event_list);
	mutex_unlock(&phandle->phandle_lock);

	return event;
}

void dpu_power_handle_unregister_event(
		struct dpu_power_handle *phandle,
		struct dpu_power_event *event)
{
	if (!phandle || !event) {
		pr_err("invalid phandle or event\n");
	} else if (!event->active) {
		pr_err("power handle deinit already done\n");
		kfree(event);
	} else {
		mutex_lock(&phandle->phandle_lock);
		list_del_init(&event->list);
		mutex_unlock(&phandle->phandle_lock);
		kfree(event);
	}
}
