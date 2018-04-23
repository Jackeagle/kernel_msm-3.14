/*
 * Copyright (c) 2014-2018 The Linux Foundation. All rights reserved.
 * Copyright (C) 2013 Red Hat
 * Author: Rob Clark <robdclark@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define pr_fmt(fmt)	"[drm:%s:%d] " fmt, __func__, __LINE__
#include <linux/sort.h>
#include <linux/debugfs.h>
#include <linux/ktime.h>
#include <uapi/drm/dpu_drm.h>
#include <drm/drm_mode.h>
#include <drm/drm_crtc.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_flip_work.h>

#include "dpu_kms.h"
#include "dpu_hw_lm.h"
#include "dpu_hw_ctl.h"
#include "dpu_crtc.h"
#include "dpu_plane.h"
#include "dpu_color_processing.h"
#include "dpu_encoder.h"
#include "dpu_vbif.h"
#include "dpu_power_handle.h"
#include "dpu_core_perf.h"
#include "dpu_trace.h"

/* layer mixer index on dpu_crtc */
#define LEFT_MIXER 0
#define RIGHT_MIXER 1

#define MISR_BUFF_SIZE			256

static inline struct dpu_kms *_dpu_crtc_get_kms(struct drm_crtc *crtc)
{
	struct msm_drm_private *priv;

	if (!crtc || !crtc->dev || !crtc->dev->dev_private) {
		DPU_ERROR("invalid crtc\n");
		return NULL;
	}
	priv = crtc->dev->dev_private;
	if (!priv || !priv->kms) {
		DPU_ERROR("invalid kms\n");
		return NULL;
	}

	return to_dpu_kms(priv->kms);
}

static inline int _dpu_crtc_power_enable(struct dpu_crtc *dpu_crtc, bool enable)
{
	struct drm_crtc *crtc;
	struct msm_drm_private *priv;
	struct dpu_kms *dpu_kms;

	if (!dpu_crtc) {
		DPU_ERROR("invalid dpu crtc\n");
		return -EINVAL;
	}

	crtc = &dpu_crtc->base;
	if (!crtc->dev || !crtc->dev->dev_private) {
		DPU_ERROR("invalid drm device\n");
		return -EINVAL;
	}

	priv = crtc->dev->dev_private;
	if (!priv->kms) {
		DPU_ERROR("invalid kms\n");
		return -EINVAL;
	}

	dpu_kms = to_dpu_kms(priv->kms);

	return dpu_power_resource_enable(&priv->phandle, dpu_kms->core_client,
									enable);
}

/**
 * _dpu_crtc_rp_to_crtc - get crtc from resource pool object
 * @rp: Pointer to resource pool
 * return: Pointer to drm crtc if success; null otherwise
 */
static struct drm_crtc *_dpu_crtc_rp_to_crtc(struct dpu_crtc_respool *rp)
{
	if (!rp)
		return NULL;

	return container_of(rp, struct dpu_crtc_state, rp)->base.crtc;
}

/**
 * _dpu_crtc_rp_reclaim - reclaim unused, or all if forced, resources in pool
 * @rp: Pointer to resource pool
 * @force: True to reclaim all resources; otherwise, reclaim only unused ones
 * return: None
 */
static void _dpu_crtc_rp_reclaim(struct dpu_crtc_respool *rp, bool force)
{
	struct dpu_crtc_res *res, *next;
	struct drm_crtc *crtc;

	crtc = _dpu_crtc_rp_to_crtc(rp);
	if (!crtc) {
		DPU_ERROR("invalid crtc\n");
		return;
	}

	DPU_DEBUG("crtc%d.%u %s\n", crtc->base.id, rp->sequence_id,
			force ? "destroy" : "free_unused");

	list_for_each_entry_safe(res, next, &rp->res_list, list) {
		if (!force && !(res->flags & DPU_CRTC_RES_FLAG_FREE))
			continue;
		DPU_DEBUG("crtc%d.%u reclaim res:0x%x/0x%llx/%pK/%d\n",
				crtc->base.id, rp->sequence_id,
				res->type, res->tag, res->val,
				atomic_read(&res->refcount));
		list_del(&res->list);
		if (res->ops.put)
			res->ops.put(res->val);
		kfree(res);
	}
}

/**
 * _dpu_crtc_rp_free_unused - free unused resource in pool
 * @rp: Pointer to resource pool
 * return: none
 */
static void _dpu_crtc_rp_free_unused(struct dpu_crtc_respool *rp)
{
	mutex_lock(rp->rp_lock);
	_dpu_crtc_rp_reclaim(rp, false);
	mutex_unlock(rp->rp_lock);
}

/**
 * _dpu_crtc_rp_destroy - destroy resource pool
 * @rp: Pointer to resource pool
 * return: None
 */
static void _dpu_crtc_rp_destroy(struct dpu_crtc_respool *rp)
{
	mutex_lock(rp->rp_lock);
	list_del_init(&rp->rp_list);
	_dpu_crtc_rp_reclaim(rp, true);
	mutex_unlock(rp->rp_lock);
}

/**
 * _dpu_crtc_hw_blk_get - get callback for hardware block
 * @val: Resource handle
 * @type: Resource type
 * @tag: Search tag for given resource
 * return: Resource handle
 */
static void *_dpu_crtc_hw_blk_get(void *val, u32 type, u64 tag)
{
	DPU_DEBUG("res:%d/0x%llx/%pK\n", type, tag, val);
	return dpu_hw_blk_get(val, type, tag);
}

/**
 * _dpu_crtc_hw_blk_put - put callback for hardware block
 * @val: Resource handle
 * return: None
 */
static void _dpu_crtc_hw_blk_put(void *val)
{
	DPU_DEBUG("res://%pK\n", val);
	dpu_hw_blk_put(val);
}

/**
 * _dpu_crtc_rp_duplicate - duplicate resource pool and reset reference count
 * @rp: Pointer to original resource pool
 * @dup_rp: Pointer to duplicated resource pool
 * return: None
 */
static void _dpu_crtc_rp_duplicate(struct dpu_crtc_respool *rp,
		struct dpu_crtc_respool *dup_rp)
{
	struct dpu_crtc_res *res, *dup_res;
	struct drm_crtc *crtc;

	if (!rp || !dup_rp || !rp->rp_head) {
		DPU_ERROR("invalid resource pool\n");
		return;
	}

	crtc = _dpu_crtc_rp_to_crtc(rp);
	if (!crtc) {
		DPU_ERROR("invalid crtc\n");
		return;
	}

	DPU_DEBUG("crtc%d.%u duplicate\n", crtc->base.id, rp->sequence_id);

	mutex_lock(rp->rp_lock);
	dup_rp->sequence_id = rp->sequence_id + 1;
	INIT_LIST_HEAD(&dup_rp->res_list);
	dup_rp->ops = rp->ops;
	list_for_each_entry(res, &rp->res_list, list) {
		dup_res = kzalloc(sizeof(struct dpu_crtc_res), GFP_KERNEL);
		if (!dup_res) {
			mutex_unlock(rp->rp_lock);
			return;
		}
		INIT_LIST_HEAD(&dup_res->list);
		atomic_set(&dup_res->refcount, 0);
		dup_res->type = res->type;
		dup_res->tag = res->tag;
		dup_res->val = res->val;
		dup_res->ops = res->ops;
		dup_res->flags = DPU_CRTC_RES_FLAG_FREE;
		DPU_DEBUG("crtc%d.%u dup res:0x%x/0x%llx/%pK/%d\n",
				crtc->base.id, dup_rp->sequence_id,
				dup_res->type, dup_res->tag, dup_res->val,
				atomic_read(&dup_res->refcount));
		list_add_tail(&dup_res->list, &dup_rp->res_list);
		if (dup_res->ops.get)
			dup_res->ops.get(dup_res->val, 0, -1);
	}

	dup_rp->rp_lock = rp->rp_lock;
	dup_rp->rp_head = rp->rp_head;
	INIT_LIST_HEAD(&dup_rp->rp_list);
	list_add_tail(&dup_rp->rp_list, rp->rp_head);
	mutex_unlock(rp->rp_lock);
}

/**
 * _dpu_crtc_rp_reset - reset resource pool after allocation
 * @rp: Pointer to original resource pool
 * @rp_lock: Pointer to serialization resource pool lock
 * @rp_head: Pointer to crtc resource pool head
 * return: None
 */
static void _dpu_crtc_rp_reset(struct dpu_crtc_respool *rp,
		struct mutex *rp_lock, struct list_head *rp_head)
{
	if (!rp || !rp_lock || !rp_head) {
		DPU_ERROR("invalid resource pool\n");
		return;
	}

	mutex_lock(rp_lock);
	rp->rp_lock = rp_lock;
	rp->rp_head = rp_head;
	INIT_LIST_HEAD(&rp->rp_list);
	rp->sequence_id = 0;
	INIT_LIST_HEAD(&rp->res_list);
	rp->ops.get = _dpu_crtc_hw_blk_get;
	rp->ops.put = _dpu_crtc_hw_blk_put;
	list_add_tail(&rp->rp_list, rp->rp_head);
	mutex_unlock(rp_lock);
}

/**
 * _dpu_crtc_rp_add_no_lock - add given resource to resource pool without lock
 * @rp: Pointer to original resource pool
 * @type: Resource type
 * @tag: Search tag for given resource
 * @val: Resource handle
 * @ops: Resource callback operations
 * return: 0 if success; error code otherwise
 */
static int _dpu_crtc_rp_add_no_lock(struct dpu_crtc_respool *rp, u32 type,
		u64 tag, void *val, struct dpu_crtc_res_ops *ops)
{
	struct dpu_crtc_res *res;
	struct drm_crtc *crtc;

	if (!rp || !ops) {
		DPU_ERROR("invalid resource pool/ops\n");
		return -EINVAL;
	}

	crtc = _dpu_crtc_rp_to_crtc(rp);
	if (!crtc) {
		DPU_ERROR("invalid crtc\n");
		return -EINVAL;
	}

	list_for_each_entry(res, &rp->res_list, list) {
		if (res->type != type || res->tag != tag)
			continue;
		DPU_ERROR("crtc%d.%u already exist res:0x%x/0x%llx/%pK/%d\n",
				crtc->base.id, rp->sequence_id,
				res->type, res->tag, res->val,
				atomic_read(&res->refcount));
		return -EEXIST;
	}
	res = kzalloc(sizeof(struct dpu_crtc_res), GFP_KERNEL);
	if (!res)
		return -ENOMEM;
	INIT_LIST_HEAD(&res->list);
	atomic_set(&res->refcount, 1);
	res->type = type;
	res->tag = tag;
	res->val = val;
	res->ops = *ops;
	list_add_tail(&res->list, &rp->res_list);
	DPU_DEBUG("crtc%d.%u added res:0x%x/0x%llx\n",
			crtc->base.id, rp->sequence_id, type, tag);
	return 0;
}

/**
 * _dpu_crtc_rp_add - add given resource to resource pool
 * @rp: Pointer to original resource pool
 * @type: Resource type
 * @tag: Search tag for given resource
 * @val: Resource handle
 * @ops: Resource callback operations
 * return: 0 if success; error code otherwise
 */
static int _dpu_crtc_rp_add(struct dpu_crtc_respool *rp, u32 type, u64 tag,
		void *val, struct dpu_crtc_res_ops *ops)
{
	int rc;

	if (!rp) {
		DPU_ERROR("invalid resource pool\n");
		return -EINVAL;
	}

	mutex_lock(rp->rp_lock);
	rc = _dpu_crtc_rp_add_no_lock(rp, type, tag, val, ops);
	mutex_unlock(rp->rp_lock);
	return rc;
}

/**
 * _dpu_crtc_rp_get - lookup the resource from given resource pool and obtain
 *	if available; otherwise, obtain resource from global pool
 * @rp: Pointer to original resource pool
 * @type: Resource type
 * @tag:  Search tag for given resource
 * return: Resource handle if success; pointer error or null otherwise
 */
static void *_dpu_crtc_rp_get(struct dpu_crtc_respool *rp, u32 type, u64 tag)
{
	struct dpu_crtc_respool *old_rp;
	struct dpu_crtc_res *res;
	void *val = NULL;
	int rc;
	struct drm_crtc *crtc;

	if (!rp) {
		DPU_ERROR("invalid resource pool\n");
		return NULL;
	}

	crtc = _dpu_crtc_rp_to_crtc(rp);
	if (!crtc) {
		DPU_ERROR("invalid crtc\n");
		return NULL;
	}

	mutex_lock(rp->rp_lock);
	list_for_each_entry(res, &rp->res_list, list) {
		if (res->type != type || res->tag != tag)
			continue;
		DPU_DEBUG("crtc%d.%u found res:0x%x/0x%llx/%pK/%d\n",
				crtc->base.id, rp->sequence_id,
				res->type, res->tag, res->val,
				atomic_read(&res->refcount));
		atomic_inc(&res->refcount);
		res->flags &= ~DPU_CRTC_RES_FLAG_FREE;
		mutex_unlock(rp->rp_lock);
		return res->val;
	}
	list_for_each_entry(res, &rp->res_list, list) {
		if (res->type != type || !(res->flags & DPU_CRTC_RES_FLAG_FREE))
			continue;
		DPU_DEBUG("crtc%d.%u retag res:0x%x/0x%llx/%pK/%d\n",
				crtc->base.id, rp->sequence_id,
				res->type, res->tag, res->val,
				atomic_read(&res->refcount));
		atomic_inc(&res->refcount);
		res->tag = tag;
		res->flags &= ~DPU_CRTC_RES_FLAG_FREE;
		mutex_unlock(rp->rp_lock);
		return res->val;
	}
	/* not in this rp, try to grab from global pool */
	if (rp->ops.get)
		val = rp->ops.get(NULL, type, -1);
	if (!IS_ERR_OR_NULL(val))
		goto add_res;
	/*
	 * Search older resource pools for hw blk with matching type,
	 * necessary when resource is being used by this object,
	 * but in previous states not yet cleaned up.
	 *
	 * This enables searching of all resources currently owned
	 * by this crtc even though the resource might not be used
	 * in the current atomic state. This allows those resources
	 * to be re-acquired by the new atomic state immediately
	 * without waiting for the resources to be fully released.
	 */
	else if (IS_ERR_OR_NULL(val) && (type < DPU_HW_BLK_MAX)) {
		list_for_each_entry(old_rp, rp->rp_head, rp_list) {
			if (old_rp == rp)
				continue;

			list_for_each_entry(res, &old_rp->res_list, list) {
				if (res->type != type)
					continue;
				DPU_DEBUG(
					"crtc%d.%u found res:0x%x//%pK/ in crtc%d.%d\n",
						crtc->base.id,
						rp->sequence_id,
						res->type, res->val,
						crtc->base.id,
						old_rp->sequence_id);
				DPU_EVT32_VERBOSE(crtc->base.id,
						rp->sequence_id,
						res->type, res->val,
						crtc->base.id,
						old_rp->sequence_id);
				if (res->ops.get)
					res->ops.get(res->val, 0, -1);
				val = res->val;
				break;
			}

			if (!IS_ERR_OR_NULL(val))
				break;
		}
	}
	if (IS_ERR_OR_NULL(val)) {
		DPU_DEBUG("crtc%d.%u failed to get res:0x%x//\n",
				crtc->base.id, rp->sequence_id, type);
		mutex_unlock(rp->rp_lock);
		return NULL;
	}
add_res:
	rc = _dpu_crtc_rp_add_no_lock(rp, type, tag, val, &rp->ops);
	if (rc) {
		DPU_ERROR("crtc%d.%u failed to add res:0x%x/0x%llx\n",
				crtc->base.id, rp->sequence_id, type, tag);
		if (rp->ops.put)
			rp->ops.put(val);
		val = NULL;
	}
	mutex_unlock(rp->rp_lock);
	return val;
}

/**
 * _dpu_crtc_rp_put - return given resource to resource pool
 * @rp: Pointer to original resource pool
 * @type: Resource type
 * @tag: Search tag for given resource
 * return: None
 */
static void _dpu_crtc_rp_put(struct dpu_crtc_respool *rp, u32 type, u64 tag)
{
	struct dpu_crtc_res *res, *next;
	struct drm_crtc *crtc;

	if (!rp) {
		DPU_ERROR("invalid resource pool\n");
		return;
	}

	crtc = _dpu_crtc_rp_to_crtc(rp);
	if (!crtc) {
		DPU_ERROR("invalid crtc\n");
		return;
	}

	mutex_lock(rp->rp_lock);
	list_for_each_entry_safe(res, next, &rp->res_list, list) {
		if (res->type != type || res->tag != tag)
			continue;
		DPU_DEBUG("crtc%d.%u found res:0x%x/0x%llx/%pK/%d\n",
				crtc->base.id, rp->sequence_id,
				res->type, res->tag, res->val,
				atomic_read(&res->refcount));
		if (res->flags & DPU_CRTC_RES_FLAG_FREE)
			DPU_ERROR(
				"crtc%d.%u already free res:0x%x/0x%llx/%pK/%d\n",
					crtc->base.id, rp->sequence_id,
					res->type, res->tag, res->val,
					atomic_read(&res->refcount));
		else if (atomic_dec_return(&res->refcount) == 0)
			res->flags |= DPU_CRTC_RES_FLAG_FREE;

		mutex_unlock(rp->rp_lock);
		return;
	}
	DPU_ERROR("crtc%d.%u not found res:0x%x/0x%llx\n",
			crtc->base.id, rp->sequence_id, type, tag);
	mutex_unlock(rp->rp_lock);
}

int dpu_crtc_res_add(struct drm_crtc_state *state, u32 type, u64 tag,
		void *val, struct dpu_crtc_res_ops *ops)
{
	struct dpu_crtc_respool *rp;

	if (!state) {
		DPU_ERROR("invalid parameters\n");
		return -EINVAL;
	}

	rp = &to_dpu_crtc_state(state)->rp;
	return _dpu_crtc_rp_add(rp, type, tag, val, ops);
}

void *dpu_crtc_res_get(struct drm_crtc_state *state, u32 type, u64 tag)
{
	struct dpu_crtc_respool *rp;
	void *val;

	if (!state) {
		DPU_ERROR("invalid parameters\n");
		return NULL;
	}

	rp = &to_dpu_crtc_state(state)->rp;
	val = _dpu_crtc_rp_get(rp, type, tag);
	if (IS_ERR(val)) {
		DPU_ERROR("failed to get res type:0x%x:0x%llx\n",
				type, tag);
		return NULL;
	}

	return val;
}

void dpu_crtc_res_put(struct drm_crtc_state *state, u32 type, u64 tag)
{
	struct dpu_crtc_respool *rp;

	if (!state) {
		DPU_ERROR("invalid parameters\n");
		return;
	}

	rp = &to_dpu_crtc_state(state)->rp;
	_dpu_crtc_rp_put(rp, type, tag);
}

static void _dpu_crtc_deinit_events(struct dpu_crtc *dpu_crtc)
{
	if (!dpu_crtc)
		return;
}

/**
 * dpu_crtc_destroy_dest_scaler - free memory allocated for scaler lut
 * @dpu_crtc: Pointer to dpu crtc
 */
static void _dpu_crtc_destroy_dest_scaler(struct dpu_crtc *dpu_crtc)
{
	if (!dpu_crtc)
		return;

	kfree(dpu_crtc->scl3_lut_cfg);
}

static void dpu_crtc_destroy(struct drm_crtc *crtc)
{
	struct dpu_crtc *dpu_crtc = to_dpu_crtc(crtc);

	DPU_DEBUG("\n");

	if (!crtc)
		return;

	if (dpu_crtc->blob_info)
		drm_property_blob_put(dpu_crtc->blob_info);
	msm_property_destroy(&dpu_crtc->property_info);
	dpu_cp_crtc_destroy_properties(crtc);
	_dpu_crtc_destroy_dest_scaler(dpu_crtc);

	_dpu_crtc_deinit_events(dpu_crtc);

	drm_crtc_cleanup(crtc);
	mutex_destroy(&dpu_crtc->crtc_lock);
	kfree(dpu_crtc);
}

static bool dpu_crtc_mode_fixup(struct drm_crtc *crtc,
		const struct drm_display_mode *mode,
		struct drm_display_mode *adjusted_mode)
{
	DPU_DEBUG("\n");

	if ((msm_is_mode_seamless(adjusted_mode) ||
			msm_is_mode_seamless_vrr(adjusted_mode)) &&
		(!crtc->enabled)) {
		DPU_ERROR("crtc state prevents seamless transition\n");
		return false;
	}

	return true;
}

static void _dpu_crtc_setup_blend_cfg(struct dpu_crtc_mixer *mixer,
	struct dpu_plane_state *pstate, struct dpu_format *format)
{
	uint32_t blend_op, fg_alpha, bg_alpha;
	uint32_t blend_type;
	struct dpu_hw_mixer *lm = mixer->hw_lm;

	/* default to opaque blending */
	fg_alpha = dpu_plane_get_property(pstate, PLANE_PROP_ALPHA);
	bg_alpha = 0xFF - fg_alpha;
	blend_op = DPU_BLEND_FG_ALPHA_FG_CONST | DPU_BLEND_BG_ALPHA_BG_CONST;
	blend_type = dpu_plane_get_property(pstate, PLANE_PROP_BLEND_OP);

	DPU_DEBUG("blend type:0x%x blend alpha:0x%x\n", blend_type, fg_alpha);

	switch (blend_type) {

	case DPU_DRM_BLEND_OP_OPAQUE:
		blend_op = DPU_BLEND_FG_ALPHA_FG_CONST |
			DPU_BLEND_BG_ALPHA_BG_CONST;
		break;

	case DPU_DRM_BLEND_OP_PREMULTIPLIED:
		if (format->alpha_enable) {
			blend_op = DPU_BLEND_FG_ALPHA_FG_CONST |
				DPU_BLEND_BG_ALPHA_FG_PIXEL;
			if (fg_alpha != 0xff) {
				bg_alpha = fg_alpha;
				blend_op |= DPU_BLEND_BG_MOD_ALPHA |
					DPU_BLEND_BG_INV_MOD_ALPHA;
			} else {
				blend_op |= DPU_BLEND_BG_INV_ALPHA;
			}
		}
		break;

	case DPU_DRM_BLEND_OP_COVERAGE:
		if (format->alpha_enable) {
			blend_op = DPU_BLEND_FG_ALPHA_FG_PIXEL |
				DPU_BLEND_BG_ALPHA_FG_PIXEL;
			if (fg_alpha != 0xff) {
				bg_alpha = fg_alpha;
				blend_op |= DPU_BLEND_FG_MOD_ALPHA |
					DPU_BLEND_FG_INV_MOD_ALPHA |
					DPU_BLEND_BG_MOD_ALPHA |
					DPU_BLEND_BG_INV_MOD_ALPHA;
			} else {
				blend_op |= DPU_BLEND_BG_INV_ALPHA;
			}
		}
		break;
	default:
		/* do nothing */
		break;
	}

	lm->ops.setup_blend_config(lm, pstate->stage, fg_alpha,
						bg_alpha, blend_op);
	DPU_DEBUG(
		"format: %4.4s, alpha_enable %u fg alpha:0x%x bg alpha:0x%x blend_op:0x%x\n",
		(char *) &format->base.pixel_format,
		format->alpha_enable, fg_alpha, bg_alpha, blend_op);
}

static void _dpu_crtc_setup_dim_layer_cfg(struct drm_crtc *crtc,
		struct dpu_crtc *dpu_crtc, struct dpu_crtc_mixer *mixer,
		struct dpu_hw_dim_layer *dim_layer)
{
	struct dpu_crtc_state *cstate;
	struct dpu_hw_mixer *lm;
	struct dpu_hw_dim_layer split_dim_layer;
	int i;

	if (!dim_layer->rect.w || !dim_layer->rect.h) {
		DPU_DEBUG("empty dim_layer\n");
		return;
	}

	cstate = to_dpu_crtc_state(crtc->state);

	DPU_DEBUG("dim_layer - flags:%d, stage:%d\n",
			dim_layer->flags, dim_layer->stage);

	split_dim_layer.stage = dim_layer->stage;
	split_dim_layer.color_fill = dim_layer->color_fill;

	/*
	 * traverse through the layer mixers attached to crtc and find the
	 * intersecting dim layer rect in each LM and program accordingly.
	 */
	for (i = 0; i < dpu_crtc->num_mixers; i++) {
		split_dim_layer.flags = dim_layer->flags;

		dpu_kms_rect_intersect(&cstate->lm_bounds[i], &dim_layer->rect,
					&split_dim_layer.rect);
		if (dpu_kms_rect_is_null(&split_dim_layer.rect)) {
			/*
			 * no extra programming required for non-intersecting
			 * layer mixers with INCLUSIVE dim layer
			 */
			if (split_dim_layer.flags & DPU_DRM_DIM_LAYER_INCLUSIVE)
				continue;

			/*
			 * program the other non-intersecting layer mixers with
			 * INCLUSIVE dim layer of full size for uniformity
			 * with EXCLUSIVE dim layer config.
			 */
			split_dim_layer.flags &= ~DPU_DRM_DIM_LAYER_EXCLUSIVE;
			split_dim_layer.flags |= DPU_DRM_DIM_LAYER_INCLUSIVE;
			memcpy(&split_dim_layer.rect, &cstate->lm_bounds[i],
					sizeof(split_dim_layer.rect));

		} else {
			split_dim_layer.rect.x =
					split_dim_layer.rect.x -
						cstate->lm_bounds[i].x;
		}

		DPU_DEBUG("split_dim_layer - LM:%d, rect:{%d,%d,%d,%d}}\n",
			i, split_dim_layer.rect.x, split_dim_layer.rect.y,
			split_dim_layer.rect.w, split_dim_layer.rect.h);

		lm = mixer[i].hw_lm;
		mixer[i].mixer_op_mode |= 1 << split_dim_layer.stage;
		lm->ops.setup_dim_layer(lm, &split_dim_layer);
	}
}

static void _dpu_crtc_program_lm_output_roi(struct drm_crtc *crtc)
{
	struct dpu_crtc *dpu_crtc;
	struct dpu_crtc_state *crtc_state;
	int lm_idx, lm_horiz_position;

	dpu_crtc = to_dpu_crtc(crtc);
	crtc_state = to_dpu_crtc_state(crtc->state);

	lm_horiz_position = 0;
	for (lm_idx = 0; lm_idx < dpu_crtc->num_mixers; lm_idx++) {
		const struct dpu_rect *lm_roi = &crtc_state->lm_bounds[lm_idx];
		struct dpu_hw_mixer *hw_lm = dpu_crtc->mixers[lm_idx].hw_lm;
		struct dpu_hw_mixer_cfg cfg;

		if (dpu_kms_rect_is_null(lm_roi))
			continue;

		cfg.out_width = lm_roi->w;
		cfg.out_height = lm_roi->h;
		cfg.right_mixer = lm_horiz_position++;
		cfg.flags = 0;
		hw_lm->ops.setup_mixer_out(hw_lm, &cfg);
	}
}

static void _dpu_crtc_blend_setup_mixer(struct drm_crtc *crtc,
	struct dpu_crtc *dpu_crtc, struct dpu_crtc_mixer *mixer)
{
	struct drm_plane *plane;
	struct drm_framebuffer *fb;
	struct drm_plane_state *state;
	struct dpu_crtc_state *cstate;
	struct dpu_plane_state *pstate = NULL;
	struct dpu_format *format;
	struct dpu_hw_ctl *ctl;
	struct dpu_hw_mixer *lm;
	struct dpu_hw_stage_cfg *stage_cfg;
	struct dpu_rect plane_crtc_roi;

	u32 flush_mask;
	uint32_t stage_idx, lm_idx;
	int zpos_cnt[DPU_STAGE_MAX + 1] = { 0 };
	int i;
	bool bg_alpha_enable = false;

	if (!dpu_crtc || !mixer) {
		DPU_ERROR("invalid dpu_crtc or mixer\n");
		return;
	}

	ctl = mixer->hw_ctl;
	lm = mixer->hw_lm;
	stage_cfg = &dpu_crtc->stage_cfg;
	cstate = to_dpu_crtc_state(crtc->state);

	drm_atomic_crtc_for_each_plane(plane, crtc) {
		state = plane->state;
		if (!state)
			continue;

		plane_crtc_roi.x = state->crtc_x;
		plane_crtc_roi.y = state->crtc_y;
		plane_crtc_roi.w = state->crtc_w;
		plane_crtc_roi.h = state->crtc_h;

		pstate = to_dpu_plane_state(state);
		fb = state->fb;

		dpu_plane_get_ctl_flush(plane, ctl, &flush_mask);

		DPU_DEBUG("crtc %d stage:%d - plane %d sspp %d fb %d\n",
				crtc->base.id,
				pstate->stage,
				plane->base.id,
				dpu_plane_pipe(plane) - SSPP_VIG0,
				state->fb ? state->fb->base.id : -1);

		format = to_dpu_format(msm_framebuffer_format(pstate->base.fb));
		if (!format) {
			DPU_ERROR("invalid format\n");
			return;
		}

		if (pstate->stage == DPU_STAGE_BASE && format->alpha_enable)
			bg_alpha_enable = true;

		DPU_EVT32(DRMID(crtc), DRMID(plane),
				state->fb ? state->fb->base.id : -1,
				state->src_x >> 16, state->src_y >> 16,
				state->src_w >> 16, state->src_h >> 16,
				state->crtc_x, state->crtc_y,
				state->crtc_w, state->crtc_h);

		stage_idx = zpos_cnt[pstate->stage]++;
		stage_cfg->stage[pstate->stage][stage_idx] =
					dpu_plane_pipe(plane);
		stage_cfg->multirect_index[pstate->stage][stage_idx] =
					pstate->multirect_index;

		DPU_EVT32(DRMID(crtc), DRMID(plane), stage_idx,
			dpu_plane_pipe(plane) - SSPP_VIG0, pstate->stage,
			pstate->multirect_index, pstate->multirect_mode,
			format->base.pixel_format, fb ? fb->modifier : 0);

		/* blend config update */
		for (lm_idx = 0; lm_idx < dpu_crtc->num_mixers; lm_idx++) {
			_dpu_crtc_setup_blend_cfg(mixer + lm_idx, pstate,
								format);
			mixer[lm_idx].flush_mask |= flush_mask;

			if (bg_alpha_enable && !format->alpha_enable)
				mixer[lm_idx].mixer_op_mode = 0;
			else
				mixer[lm_idx].mixer_op_mode |=
						1 << pstate->stage;
		}
	}

	if (lm && lm->ops.setup_dim_layer) {
		cstate = to_dpu_crtc_state(crtc->state);
		for (i = 0; i < cstate->num_dim_layers; i++)
			_dpu_crtc_setup_dim_layer_cfg(crtc, dpu_crtc,
					mixer, &cstate->dim_layer[i]);
	}

	 _dpu_crtc_program_lm_output_roi(crtc);
}

/**
 * _dpu_crtc_blend_setup - configure crtc mixers
 * @crtc: Pointer to drm crtc structure
 */
static void _dpu_crtc_blend_setup(struct drm_crtc *crtc)
{
	struct dpu_crtc *dpu_crtc;
	struct dpu_crtc_state *dpu_crtc_state;
	struct dpu_crtc_mixer *mixer;
	struct dpu_hw_ctl *ctl;
	struct dpu_hw_mixer *lm;

	int i;

	if (!crtc)
		return;

	dpu_crtc = to_dpu_crtc(crtc);
	dpu_crtc_state = to_dpu_crtc_state(crtc->state);
	mixer = dpu_crtc->mixers;

	DPU_DEBUG("%s\n", dpu_crtc->name);

	if (dpu_crtc->num_mixers > CRTC_DUAL_MIXERS) {
		DPU_ERROR("invalid number mixers: %d\n", dpu_crtc->num_mixers);
		return;
	}

	for (i = 0; i < dpu_crtc->num_mixers; i++) {
		if (!mixer[i].hw_lm || !mixer[i].hw_ctl) {
			DPU_ERROR("invalid lm or ctl assigned to mixer\n");
			return;
		}
		mixer[i].mixer_op_mode = 0;
		mixer[i].flush_mask = 0;
		if (mixer[i].hw_ctl->ops.clear_all_blendstages)
			mixer[i].hw_ctl->ops.clear_all_blendstages(
					mixer[i].hw_ctl);

		/* clear dim_layer settings */
		lm = mixer[i].hw_lm;
		if (lm->ops.clear_dim_layer)
			lm->ops.clear_dim_layer(lm);
	}

	/* initialize stage cfg */
	memset(&dpu_crtc->stage_cfg, 0, sizeof(struct dpu_hw_stage_cfg));

	_dpu_crtc_blend_setup_mixer(crtc, dpu_crtc, mixer);

	for (i = 0; i < dpu_crtc->num_mixers; i++) {
		ctl = mixer[i].hw_ctl;
		lm = mixer[i].hw_lm;

		lm->ops.setup_alpha_out(lm, mixer[i].mixer_op_mode);

		mixer[i].flush_mask |= ctl->ops.get_bitmask_mixer(ctl,
			mixer[i].hw_lm->idx);

		/* stage config flush mask */
		ctl->ops.update_pending_flush(ctl, mixer[i].flush_mask);

		DPU_DEBUG("lm %d, op_mode 0x%X, ctl %d, flush mask 0x%x\n",
			mixer[i].hw_lm->idx - LM_0,
			mixer[i].mixer_op_mode,
			ctl->idx - CTL_0,
			mixer[i].flush_mask);

		ctl->ops.setup_blendstage(ctl, mixer[i].hw_lm->idx,
			&dpu_crtc->stage_cfg);
	}
}

/**
 * _dpu_crtc_setup_scaler3_lut - Set up scaler lut
 * LUTs are configured only once during boot
 * @dpu_crtc: Pointer to dpu crtc
 * @cstate: Pointer to dpu crtc state
 */
static int _dpu_crtc_set_dest_scaler_lut(struct dpu_crtc *dpu_crtc,
		struct dpu_crtc_state *cstate, uint32_t lut_idx)
{
	struct dpu_hw_scaler3_lut_cfg *cfg;
	u32 *lut_data = NULL;
	size_t len = 0;
	int ret = 0;

	if (!dpu_crtc || !cstate || !dpu_crtc->scl3_lut_cfg) {
		DPU_ERROR("invalid args\n");
		return -EINVAL;
	}

	if (dpu_crtc->scl3_lut_cfg->is_configured) {
		DPU_DEBUG("lut already configured\n");
		return 0;
	}

	lut_data = msm_property_get_blob(&dpu_crtc->property_info,
			&cstate->property_state, &len, lut_idx);
	if (!lut_data || !len) {
		DPU_ERROR("lut(%d): no data, len(%zu)\n", lut_idx, len);
		return -ENODATA;
	}

	cfg = dpu_crtc->scl3_lut_cfg;

	switch (lut_idx) {
	case CRTC_PROP_DEST_SCALER_LUT_ED:
		cfg->dir_lut = lut_data;
		cfg->dir_len = len;
		break;
	case CRTC_PROP_DEST_SCALER_LUT_CIR:
		cfg->cir_lut = lut_data;
		cfg->cir_len = len;
		break;
	case CRTC_PROP_DEST_SCALER_LUT_SEP:
		cfg->sep_lut = lut_data;
		cfg->sep_len = len;
		break;
	default:
		ret = -EINVAL;
		DPU_ERROR("invalid LUT index = %d", lut_idx);
		break;
	}

	if (cfg->dir_lut && cfg->cir_lut && cfg->sep_lut)
		cfg->is_configured = true;

	return ret;
}

/**
 * _dpu_crtc_dest_scaler_setup - Set up dest scaler block
 * @crtc: Pointer to drm crtc
 */
static void _dpu_crtc_dest_scaler_setup(struct drm_crtc *crtc)
{
	struct dpu_crtc *dpu_crtc;
	struct dpu_crtc_state *cstate;
	struct dpu_hw_mixer *hw_lm;
	struct dpu_hw_ctl *hw_ctl;
	struct dpu_hw_ds *hw_ds;
	struct dpu_hw_ds_cfg *cfg;
	struct dpu_kms *kms;
	u32 flush_mask = 0, op_mode = 0;
	u32 lm_idx = 0, num_mixers = 0;
	int i, count = 0;

	if (!crtc)
		return;

	dpu_crtc   = to_dpu_crtc(crtc);
	cstate = to_dpu_crtc_state(crtc->state);
	kms    = _dpu_crtc_get_kms(crtc);
	num_mixers = dpu_crtc->num_mixers;

	DPU_DEBUG("crtc%d\n", crtc->base.id);

	if (!cstate->ds_dirty) {
		DPU_DEBUG("no change in settings, skip commit\n");
	} else if (!kms || !kms->catalog) {
		DPU_ERROR("invalid parameters\n");
	} else if (!kms->catalog->mdp[0].has_dest_scaler) {
		DPU_DEBUG("dest scaler feature not supported\n");
	} else if (num_mixers > CRTC_DUAL_MIXERS) {
		DPU_ERROR("invalid number mixers: %d\n", num_mixers);
	} else if (!dpu_crtc->scl3_lut_cfg->is_configured) {
		DPU_DEBUG("no LUT data available\n");
	} else {
		count = cstate->num_ds_enabled ? cstate->num_ds : num_mixers;

		for (i = 0; i < count; i++) {
			cfg = &cstate->ds_cfg[i];

			if (!cfg->flags)
				continue;

			lm_idx = cfg->ndx;
			hw_lm  = dpu_crtc->mixers[lm_idx].hw_lm;
			hw_ctl = dpu_crtc->mixers[lm_idx].hw_ctl;
			hw_ds  = dpu_crtc->mixers[lm_idx].hw_ds;

			/* Setup op mode - Dual/single */
			if (cfg->flags & DPU_DRM_DESTSCALER_ENABLE)
				op_mode |= BIT(hw_ds->idx - DS_0);

			if ((i == count-1) && hw_ds->ops.setup_opmode) {
				op_mode |= (cstate->num_ds_enabled ==
					CRTC_DUAL_MIXERS) ?
					DPU_DS_OP_MODE_DUAL : 0;
				hw_ds->ops.setup_opmode(hw_ds, op_mode);
				DPU_EVT32(DRMID(crtc), op_mode);
			}

			/* Setup scaler */
			if ((cfg->flags & DPU_DRM_DESTSCALER_SCALE_UPDATE) ||
				(cfg->flags &
					DPU_DRM_DESTSCALER_ENHANCER_UPDATE)) {
				if (hw_ds->ops.setup_scaler)
					hw_ds->ops.setup_scaler(hw_ds,
							cfg->scl3_cfg,
							dpu_crtc->scl3_lut_cfg);

				/**
				 * Clear the flags as the block doesn't have to
				 * be programmed in each commit if no updates
				 */
				cfg->flags &= ~DPU_DRM_DESTSCALER_SCALE_UPDATE;
				cfg->flags &=
					~DPU_DRM_DESTSCALER_ENHANCER_UPDATE;
			}

			/*
			 * Dest scaler shares the flush bit of the LM in control
			 */
			if (cfg->set_lm_flush && hw_lm && hw_ctl &&
				hw_ctl->ops.get_bitmask_mixer) {
				flush_mask = hw_ctl->ops.get_bitmask_mixer(
						hw_ctl, hw_lm->idx);
				DPU_DEBUG("Set lm[%d] flush = %d",
					hw_lm->idx, flush_mask);
				hw_ctl->ops.update_pending_flush(hw_ctl,
								flush_mask);
			}
			cfg->set_lm_flush = false;
		}
		cstate->ds_dirty = false;
	}
}

/**
 *  _dpu_crtc_complete_flip - signal pending page_flip events
 * Any pending vblank events are added to the vblank_event_list
 * so that the next vblank interrupt shall signal them.
 * However PAGE_FLIP events are not handled through the vblank_event_list.
 * This API signals any pending PAGE_FLIP events requested through
 * DRM_IOCTL_MODE_PAGE_FLIP and are cached in the dpu_crtc->event.
 * if file!=NULL, this is preclose potential cancel-flip path
 * @crtc: Pointer to drm crtc structure
 * @file: Pointer to drm file
 */
static void _dpu_crtc_complete_flip(struct drm_crtc *crtc,
		struct drm_file *file)
{
	struct dpu_crtc *dpu_crtc = to_dpu_crtc(crtc);
	struct drm_device *dev = crtc->dev;
	struct drm_pending_vblank_event *event;
	unsigned long flags;

	spin_lock_irqsave(&dev->event_lock, flags);
	event = dpu_crtc->event;
	if (event) {
		/* if regular vblank case (!file) or if cancel-flip from
		 * preclose on file that requested flip, then send the
		 * event:
		 */
		if (!file || (event->base.file_priv == file)) {
			dpu_crtc->event = NULL;
			DRM_DEBUG_VBL("%s: send event: %pK\n",
						dpu_crtc->name, event);
			DPU_EVT32_VERBOSE(DRMID(crtc));
			drm_crtc_send_vblank_event(crtc, event);
		}
	}
	spin_unlock_irqrestore(&dev->event_lock, flags);
}

enum dpu_intf_mode dpu_crtc_get_intf_mode(struct drm_crtc *crtc)
{
	struct drm_encoder *encoder;

	if (!crtc || !crtc->dev) {
		DPU_ERROR("invalid crtc\n");
		return INTF_MODE_NONE;
	}

	drm_for_each_encoder(encoder, crtc->dev)
		if (encoder->crtc == crtc)
			return dpu_encoder_get_intf_mode(encoder);

	return INTF_MODE_NONE;
}

static void dpu_crtc_vblank_cb(void *data)
{
	struct drm_crtc *crtc = (struct drm_crtc *)data;
	struct dpu_crtc *dpu_crtc = to_dpu_crtc(crtc);

	/* keep statistics on vblank callback - with auto reset via debugfs */
	if (ktime_compare(dpu_crtc->vblank_cb_time, ktime_set(0, 0)) == 0)
		dpu_crtc->vblank_cb_time = ktime_get();
	else
		dpu_crtc->vblank_cb_count++;
	_dpu_crtc_complete_flip(crtc, NULL);
	drm_crtc_handle_vblank(crtc);
	DRM_DEBUG_VBL("crtc%d\n", crtc->base.id);
	DPU_EVT32_VERBOSE(DRMID(crtc));
}

/* _dpu_crtc_idle_notify - signal idle timeout to client */
static void _dpu_crtc_idle_notify(struct dpu_crtc *dpu_crtc)
{
	struct drm_crtc *crtc;
	struct drm_event event;
	int ret = 0;

	if (!dpu_crtc) {
		DPU_ERROR("invalid dpu crtc\n");
		return;
	}

	crtc = &dpu_crtc->base;
	event.type = DRM_EVENT_IDLE_NOTIFY;
	event.length = sizeof(u32);
	msm_mode_object_event_notify(&crtc->base, crtc->dev, &event,
								(u8 *)&ret);

	DPU_DEBUG("crtc:%d idle timeout notified\n", crtc->base.id);
}

/*
 * dpu_crtc_handle_event - crtc frame event handle.
 * This API must manage only non-IRQ context events.
 */
static bool _dpu_crtc_handle_event(struct dpu_crtc *dpu_crtc, u32 event)
{
	bool event_processed = false;

	/**
	 * idle events are originated from commit thread and can be processed
	 * in same context
	 */
	if (event & DPU_ENCODER_FRAME_EVENT_IDLE) {
		_dpu_crtc_idle_notify(dpu_crtc);
		event_processed = true;
	}

	return event_processed;
}

static void dpu_crtc_frame_event_work(struct kthread_work *work)
{
	struct msm_drm_private *priv;
	struct dpu_crtc_frame_event *fevent;
	struct drm_crtc *crtc;
	struct dpu_crtc *dpu_crtc;
	struct dpu_kms *dpu_kms;
	unsigned long flags;
	bool frame_done = false;

	if (!work) {
		DPU_ERROR("invalid work handle\n");
		return;
	}

	fevent = container_of(work, struct dpu_crtc_frame_event, work);
	if (!fevent->crtc || !fevent->crtc->state) {
		DPU_ERROR("invalid crtc\n");
		return;
	}

	crtc = fevent->crtc;
	dpu_crtc = to_dpu_crtc(crtc);

	dpu_kms = _dpu_crtc_get_kms(crtc);
	if (!dpu_kms) {
		DPU_ERROR("invalid kms handle\n");
		return;
	}
	priv = dpu_kms->dev->dev_private;
	DPU_ATRACE_BEGIN("crtc_frame_event");

	DPU_DEBUG("crtc%d event:%u ts:%lld\n", crtc->base.id, fevent->event,
			ktime_to_ns(fevent->ts));

	DPU_EVT32_VERBOSE(DRMID(crtc), fevent->event, DPU_EVTLOG_FUNC_ENTRY);

	if (fevent->event & (DPU_ENCODER_FRAME_EVENT_DONE
				| DPU_ENCODER_FRAME_EVENT_ERROR
				| DPU_ENCODER_FRAME_EVENT_PANEL_DEAD)) {

		if (atomic_read(&dpu_crtc->frame_pending) < 1) {
			/* this should not happen */
			DPU_ERROR("crtc%d ts:%lld invalid frame_pending:%d\n",
					crtc->base.id,
					ktime_to_ns(fevent->ts),
					atomic_read(&dpu_crtc->frame_pending));
			DPU_EVT32(DRMID(crtc), fevent->event,
							DPU_EVTLOG_FUNC_CASE1);
		} else if (atomic_dec_return(&dpu_crtc->frame_pending) == 0) {
			/* release bandwidth and other resources */
			DPU_DEBUG("crtc%d ts:%lld last pending\n",
					crtc->base.id,
					ktime_to_ns(fevent->ts));
			DPU_EVT32(DRMID(crtc), fevent->event,
							DPU_EVTLOG_FUNC_CASE2);
			dpu_core_perf_crtc_release_bw(crtc);
		} else {
			DPU_EVT32_VERBOSE(DRMID(crtc), fevent->event,
							DPU_EVTLOG_FUNC_CASE3);
		}

		if (fevent->event & DPU_ENCODER_FRAME_EVENT_DONE)
			dpu_core_perf_crtc_update(crtc, 0, false);

		if (fevent->event & (DPU_ENCODER_FRAME_EVENT_DONE
					| DPU_ENCODER_FRAME_EVENT_ERROR))
			frame_done = true;
	}

	if (fevent->event & DPU_ENCODER_FRAME_EVENT_PANEL_DEAD)
		DPU_ERROR("crtc%d ts:%lld received panel dead event\n",
				crtc->base.id, ktime_to_ns(fevent->ts));

	if (frame_done)
		complete_all(&dpu_crtc->frame_done_comp);

	spin_lock_irqsave(&dpu_crtc->spin_lock, flags);
	list_add_tail(&fevent->list, &dpu_crtc->frame_event_list);
	spin_unlock_irqrestore(&dpu_crtc->spin_lock, flags);
	DPU_ATRACE_END("crtc_frame_event");
}

/*
 * dpu_crtc_frame_event_cb - crtc frame event callback API. CRTC module
 * registers this API to encoder for all frame event callbacks like
 * frame_error, frame_done, idle_timeout, etc. Encoder may call different events
 * from different context - IRQ, user thread, commit_thread, etc. Each event
 * should be carefully reviewed and should be processed in proper task context
 * to avoid schedulin delay or properly manage the irq context's bottom half
 * processing.
 */
static void dpu_crtc_frame_event_cb(void *data, u32 event)
{
	struct drm_crtc *crtc = (struct drm_crtc *)data;
	struct dpu_crtc *dpu_crtc;
	struct msm_drm_private *priv;
	struct dpu_crtc_frame_event *fevent;
	unsigned long flags;
	u32 crtc_id;
	bool event_processed = false;

	if (!crtc || !crtc->dev || !crtc->dev->dev_private) {
		DPU_ERROR("invalid parameters\n");
		return;
	}
	dpu_crtc = to_dpu_crtc(crtc);
	priv = crtc->dev->dev_private;
	crtc_id = drm_crtc_index(crtc);

	DPU_DEBUG("crtc%d\n", crtc->base.id);
	DPU_EVT32_VERBOSE(DRMID(crtc), event);

	/* try to process the event in caller context */
	event_processed = _dpu_crtc_handle_event(dpu_crtc, event);
	if (event_processed)
		return;

	spin_lock_irqsave(&dpu_crtc->spin_lock, flags);
	fevent = list_first_entry_or_null(&dpu_crtc->frame_event_list,
			struct dpu_crtc_frame_event, list);
	if (fevent)
		list_del_init(&fevent->list);
	spin_unlock_irqrestore(&dpu_crtc->spin_lock, flags);

	if (!fevent) {
		DPU_ERROR("crtc%d event %d overflow\n",
				crtc->base.id, event);
		DPU_EVT32(DRMID(crtc), event);
		return;
	}

	fevent->event = event;
	fevent->crtc = crtc;
	fevent->ts = ktime_get();
	kthread_queue_work(&priv->event_thread[crtc_id].worker, &fevent->work);
}

void dpu_crtc_complete_commit(struct drm_crtc *crtc,
		struct drm_crtc_state *old_state)
{
	if (!crtc || !crtc->state) {
		DPU_ERROR("invalid crtc\n");
		return;
	}
	DPU_EVT32_VERBOSE(DRMID(crtc));
}

/* _dpu_crtc_set_idle_timeout - update idle timeout wait duration */
static void _dpu_crtc_set_idle_timeout(struct drm_crtc *crtc, u64 val)
{
	struct drm_encoder *encoder;

	if (!crtc) {
		DPU_ERROR("invalid crtc\n");
		return;
	}

	drm_for_each_encoder(encoder, crtc->dev) {
		if (encoder->crtc != crtc)
			continue;

		dpu_encoder_set_idle_timeout(encoder, (u32) val);
	}
}

/**
 * _dpu_crtc_set_dim_layer_v1 - copy dim layer settings from userspace
 * @cstate:      Pointer to dpu crtc state
 * @user_ptr:    User ptr for dpu_drm_dim_layer_v1 struct
 */
static void _dpu_crtc_set_dim_layer_v1(struct dpu_crtc_state *cstate,
		void __user *usr_ptr)
{
	struct dpu_drm_dim_layer_v1 dim_layer_v1;
	struct dpu_drm_dim_layer_cfg *user_cfg;
	struct dpu_hw_dim_layer *dim_layer;
	u32 count, i;

	if (!cstate) {
		DPU_ERROR("invalid cstate\n");
		return;
	}
	dim_layer = cstate->dim_layer;

	if (!usr_ptr) {
		DPU_DEBUG("dim_layer data removed\n");
		return;
	}

	if (copy_from_user(&dim_layer_v1, usr_ptr, sizeof(dim_layer_v1))) {
		DPU_ERROR("failed to copy dim_layer data\n");
		return;
	}

	count = dim_layer_v1.num_layers;
	if (count > DPU_MAX_DIM_LAYERS) {
		DPU_ERROR("invalid number of dim_layers:%d", count);
		return;
	}

	/* populate from user space */
	cstate->num_dim_layers = count;
	for (i = 0; i < count; i++) {
		user_cfg = &dim_layer_v1.layer_cfg[i];

		dim_layer[i].flags = user_cfg->flags;
		dim_layer[i].stage = user_cfg->stage + DPU_STAGE_0;

		dim_layer[i].rect.x = user_cfg->rect.x1;
		dim_layer[i].rect.y = user_cfg->rect.y1;
		dim_layer[i].rect.w = user_cfg->rect.x2 - user_cfg->rect.x1;
		dim_layer[i].rect.h = user_cfg->rect.y2 - user_cfg->rect.y1;

		dim_layer[i].color_fill = (struct dpu_mdss_color) {
				user_cfg->color_fill.color_0,
				user_cfg->color_fill.color_1,
				user_cfg->color_fill.color_2,
				user_cfg->color_fill.color_3,
		};

		DPU_DEBUG("dim_layer[%d] - flags:%d, stage:%d\n",
				i, dim_layer[i].flags, dim_layer[i].stage);
		DPU_DEBUG(" rect:{%d,%d,%d,%d}, color:{%d,%d,%d,%d}\n",
				dim_layer[i].rect.x, dim_layer[i].rect.y,
				dim_layer[i].rect.w, dim_layer[i].rect.h,
				dim_layer[i].color_fill.color_0,
				dim_layer[i].color_fill.color_1,
				dim_layer[i].color_fill.color_2,
				dim_layer[i].color_fill.color_3);
	}
}

/**
 * _dpu_crtc_dest_scaler_init - allocate memory for scaler lut
 * @dpu_crtc    :  Pointer to dpu crtc
 * @catalog :  Pointer to mdss catalog info
 */
static void _dpu_crtc_dest_scaler_init(struct dpu_crtc *dpu_crtc,
				struct dpu_mdss_cfg *catalog)
{
	if (!dpu_crtc || !catalog)
		return;

	if (!catalog->mdp[0].has_dest_scaler) {
		DPU_DEBUG("dest scaler feature not supported\n");
		return;
	}

	dpu_crtc->scl3_lut_cfg = kzalloc(sizeof(struct dpu_hw_scaler3_lut_cfg),
				GFP_KERNEL);
	if (!dpu_crtc->scl3_lut_cfg)
		DPU_ERROR("failed to create scale LUT for dest scaler");
}

/**
 * _dpu_crtc_set_dest_scaler - copy dest scaler settings from userspace
 * @dpu_crtc   :  Pointer to dpu crtc
 * @cstate :  Pointer to dpu crtc state
 * @usr_ptr:  User ptr for dpu_drm_dest_scaler_data struct
 */
static int _dpu_crtc_set_dest_scaler(struct dpu_crtc *dpu_crtc,
				struct dpu_crtc_state *cstate,
				void __user *usr_ptr)
{
	struct dpu_drm_dest_scaler_data ds_data;
	struct dpu_drm_dest_scaler_cfg *ds_cfg_usr;
	struct dpu_drm_scaler_v2 scaler_v2;
	void __user *scaler_v2_usr;
	int i, count, ret = 0;

	if (!dpu_crtc || !cstate) {
		DPU_ERROR("invalid dpu_crtc/state\n");
		return -EINVAL;
	}

	DPU_DEBUG("crtc %s\n", dpu_crtc->name);

	cstate->num_ds = 0;
	cstate->ds_dirty = false;
	if (!usr_ptr) {
		DPU_DEBUG("ds data removed\n");
		return 0;
	}

	if (copy_from_user(&ds_data, usr_ptr, sizeof(ds_data))) {
		DPU_ERROR("failed to copy dest scaler data from user\n");
		return -EINVAL;
	}

	count = ds_data.num_dest_scaler;
	if (!dpu_crtc->num_mixers || count > dpu_crtc->num_mixers ||
		(count && (count != dpu_crtc->num_mixers) &&
		!(ds_data.ds_cfg[0].flags & DPU_DRM_DESTSCALER_PU_ENABLE))) {
		DPU_ERROR("invalid config:num ds(%d), mixers(%d),flags(%d)\n",
			count, dpu_crtc->num_mixers, ds_data.ds_cfg[0].flags);
		return -EINVAL;
	}

	/* Populate from user space */
	for (i = 0; i < count; i++) {
		ds_cfg_usr = &ds_data.ds_cfg[i];

		cstate->ds_cfg[i].ndx = ds_cfg_usr->index;
		cstate->ds_cfg[i].flags = ds_cfg_usr->flags;
		cstate->ds_cfg[i].lm_width = ds_cfg_usr->lm_width;
		cstate->ds_cfg[i].lm_height = ds_cfg_usr->lm_height;
		cstate->ds_cfg[i].scl3_cfg = NULL;

		if (ds_cfg_usr->scaler_cfg) {
			scaler_v2_usr =
			(void __user *)((uintptr_t)ds_cfg_usr->scaler_cfg);

			memset(&scaler_v2, 0, sizeof(scaler_v2));

			cstate->ds_cfg[i].scl3_cfg =
				kzalloc(sizeof(struct dpu_hw_scaler3_cfg),
					GFP_KERNEL);

			if (!cstate->ds_cfg[i].scl3_cfg) {
				ret = -ENOMEM;
				goto err;
			}

			if (copy_from_user(&scaler_v2, scaler_v2_usr,
					sizeof(scaler_v2))) {
				DPU_ERROR("scale data:copy from user failed\n");
				ret = -EINVAL;
				goto err;
			}

			dpu_set_scaler_v2(cstate->ds_cfg[i].scl3_cfg,
					&scaler_v2);

			DPU_DEBUG("en(%d)dir(%d)de(%d) src(%dx%d) dst(%dx%d)\n",
				scaler_v2.enable, scaler_v2.dir_en,
				scaler_v2.de.enable, scaler_v2.src_width[0],
				scaler_v2.src_height[0], scaler_v2.dst_width,
				scaler_v2.dst_height);
			DPU_EVT32_VERBOSE(DRMID(&dpu_crtc->base),
				scaler_v2.enable, scaler_v2.dir_en,
				scaler_v2.de.enable, scaler_v2.src_width[0],
				scaler_v2.src_height[0], scaler_v2.dst_width,
				scaler_v2.dst_height);
		}

		DPU_DEBUG("ds cfg[%d]-ndx(%d) flags(%d) lm(%dx%d)\n",
			i, ds_cfg_usr->index, ds_cfg_usr->flags,
			ds_cfg_usr->lm_width, ds_cfg_usr->lm_height);
		DPU_EVT32_VERBOSE(DRMID(&dpu_crtc->base), i, ds_cfg_usr->index,
			ds_cfg_usr->flags, ds_cfg_usr->lm_width,
			ds_cfg_usr->lm_height);
	}

	cstate->num_ds = count;
	cstate->ds_dirty = true;
	return 0;

err:
	for (; i >= 0; i--)
		kfree(cstate->ds_cfg[i].scl3_cfg);

	return ret;
}

/**
 * _dpu_crtc_check_dest_scaler_data - validate the dest scaler data
 * @crtc  :  Pointer to drm crtc
 * @state :  Pointer to drm crtc state
 */
static int _dpu_crtc_check_dest_scaler_data(struct drm_crtc *crtc,
				struct drm_crtc_state *state)
{
	struct dpu_crtc *dpu_crtc;
	struct dpu_crtc_state *cstate;
	struct drm_display_mode *mode;
	struct dpu_kms *kms;
	struct dpu_hw_ds *hw_ds;
	struct dpu_hw_ds_cfg *cfg;
	u32 i, ret = 0, lm_idx;
	u32 num_ds_enable = 0;
	u32 max_in_width = 0, max_out_width = 0;
	u32 prev_lm_width = 0, prev_lm_height = 0;

	if (!crtc || !state)
		return -EINVAL;

	dpu_crtc = to_dpu_crtc(crtc);
	cstate = to_dpu_crtc_state(state);
	kms = _dpu_crtc_get_kms(crtc);
	mode = &state->adjusted_mode;

	DPU_DEBUG("crtc%d\n", crtc->base.id);

	if (!cstate->ds_dirty && !cstate->num_ds_enabled) {
		DPU_DEBUG("dest scaler property not set, skip validation\n");
		return 0;
	}

	if (!kms || !kms->catalog) {
		DPU_ERROR("invalid parameters\n");
		return -EINVAL;
	}

	if (!kms->catalog->mdp[0].has_dest_scaler) {
		DPU_DEBUG("dest scaler feature not supported\n");
		return 0;
	}

	if (!dpu_crtc->num_mixers) {
		DPU_ERROR("mixers not allocated\n");
		return -EINVAL;
	}

	/**
	 * Check if sufficient hw resources are
	 * available as per target caps & topology
	 */
	if (dpu_crtc->num_mixers > CRTC_DUAL_MIXERS) {
		DPU_ERROR("invalid config: mixers(%d) max(%d)\n",
			dpu_crtc->num_mixers, CRTC_DUAL_MIXERS);
		ret = -EINVAL;
		goto err;
	}

	for (i = 0; i < dpu_crtc->num_mixers; i++) {
		if (!dpu_crtc->mixers[i].hw_lm || !dpu_crtc->mixers[i].hw_ds) {
			DPU_ERROR("insufficient HW resources allocated\n");
			ret = -EINVAL;
			goto err;
		}
	}

	/**
	 * Check if DS needs to be enabled or disabled
	 * In case of enable, validate the data
	 */
	if (!cstate->ds_dirty || !cstate->num_ds ||
		!(cstate->ds_cfg[0].flags & DPU_DRM_DESTSCALER_ENABLE)) {
		DPU_DEBUG("disable dest scaler,dirty(%d)num(%d)flags(%d)\n",
			cstate->ds_dirty, cstate->num_ds,
			cstate->ds_cfg[0].flags);
		goto disable;
	}

	/**
	 * No of dest scalers shouldn't exceed hw ds block count and
	 * also, match the num of mixers unless it is partial update
	 * left only/right only use case - currently PU + DS is not supported
	 */
	if (cstate->num_ds > kms->catalog->ds_count ||
		((cstate->num_ds != dpu_crtc->num_mixers) &&
		!(cstate->ds_cfg[0].flags & DPU_DRM_DESTSCALER_PU_ENABLE))) {
		DPU_ERROR("invalid cfg: num_ds(%d), hw_ds_cnt(%d) flags(%d)\n",
			cstate->num_ds, kms->catalog->ds_count,
			cstate->ds_cfg[0].flags);
		ret = -EINVAL;
		goto err;
	}

	/* Validate the DS data */
	for (i = 0; i < cstate->num_ds; i++) {
		cfg = &cstate->ds_cfg[i];
		lm_idx = cfg->ndx;

		/**
		 * Validate against topology
		 * No of dest scalers should match the num of mixers
		 * unless it is partial update left only/right only use case
		 */
		if (lm_idx >= dpu_crtc->num_mixers || (i != lm_idx &&
			!(cfg->flags & DPU_DRM_DESTSCALER_PU_ENABLE))) {
			DPU_ERROR("invalid user data(%d):idx(%d), flags(%d)\n",
				i, lm_idx, cfg->flags);
			ret = -EINVAL;
			goto err;
		}

		hw_ds = dpu_crtc->mixers[lm_idx].hw_ds;

		if (!max_in_width && !max_out_width) {
			max_in_width = hw_ds->scl->top->maxinputwidth;
			max_out_width = hw_ds->scl->top->maxoutputwidth;

			if (cstate->num_ds == CRTC_DUAL_MIXERS)
				max_in_width -= DPU_DS_OVERFETCH_SIZE;

			DPU_DEBUG("max DS width [%d,%d] for num_ds = %d\n",
				max_in_width, max_out_width, cstate->num_ds);
		}

		/* Check LM width and height */
		if (cfg->lm_width > (mode->hdisplay/dpu_crtc->num_mixers) ||
			cfg->lm_height > mode->vdisplay ||
			!cfg->lm_width || !cfg->lm_height) {
			DPU_ERROR("invalid lm size[%d,%d] display [%d,%d]\n",
				cfg->lm_width,
				cfg->lm_height,
				mode->hdisplay/dpu_crtc->num_mixers,
				mode->vdisplay);
			ret = -E2BIG;
			goto err;
		}

		if (!prev_lm_width && !prev_lm_height) {
			prev_lm_width = cfg->lm_width;
			prev_lm_height = cfg->lm_height;
		} else {
			if (cfg->lm_width != prev_lm_width ||
				cfg->lm_height != prev_lm_height) {
				DPU_ERROR("lm size:left[%d,%d], right[%d %d]\n",
					cfg->lm_width, cfg->lm_height,
					prev_lm_width, prev_lm_height);
				ret = -EINVAL;
				goto err;
			}
		}

		/* Check scaler data */
		if (cfg->flags & DPU_DRM_DESTSCALER_SCALE_UPDATE ||
			cfg->flags & DPU_DRM_DESTSCALER_ENHANCER_UPDATE) {
			if (!cfg->scl3_cfg) {
				ret = -EINVAL;
				DPU_ERROR("null scale data\n");
				goto err;
			}
			if (cfg->scl3_cfg->src_width[0] > max_in_width ||
				cfg->scl3_cfg->dst_width > max_out_width ||
				!cfg->scl3_cfg->src_width[0] ||
				!cfg->scl3_cfg->dst_width) {
				DPU_ERROR("scale width(%d %d) for ds-%d:\n",
					cfg->scl3_cfg->src_width[0],
					cfg->scl3_cfg->dst_width,
					hw_ds->idx - DS_0);
				DPU_ERROR("scale_en = %d, DE_en =%d\n",
					cfg->scl3_cfg->enable,
					cfg->scl3_cfg->de.enable);

				cfg->flags &=
					~DPU_DRM_DESTSCALER_SCALE_UPDATE;
				cfg->flags &=
					~DPU_DRM_DESTSCALER_ENHANCER_UPDATE;

				ret = -EINVAL;
				goto err;
			}
		}

		if (cfg->flags & DPU_DRM_DESTSCALER_ENABLE)
			num_ds_enable++;

		/**
		 * Validation successful, indicator for flush to be issued
		 */
		cfg->set_lm_flush = true;

		DPU_DEBUG("ds[%d]: flags = 0x%X\n",
			hw_ds->idx - DS_0, cfg->flags);
	}

disable:
	DPU_DEBUG("dest scaler enable status, old = %d, new = %d",
		cstate->num_ds_enabled, num_ds_enable);
	DPU_EVT32(DRMID(crtc), cstate->num_ds_enabled, num_ds_enable,
		cstate->ds_dirty);

	if (cstate->num_ds_enabled != num_ds_enable) {
		/* Disabling destination scaler */
		if (!num_ds_enable) {
			for (i = 0; i < dpu_crtc->num_mixers; i++) {
				cfg = &cstate->ds_cfg[i];
				cfg->ndx = i;
				/* Update scaler settings in disable case */
				cfg->flags = DPU_DRM_DESTSCALER_SCALE_UPDATE;
				cfg->scl3_cfg->enable = 0;
				cfg->scl3_cfg->de.enable = 0;
				cfg->set_lm_flush = true;
			}
		}
		cstate->num_ds_enabled = num_ds_enable;
		cstate->ds_dirty = true;
	}

	return 0;

err:
	cstate->ds_dirty = false;
	return ret;
}

static void _dpu_crtc_setup_mixer_for_encoder(
		struct drm_crtc *crtc,
		struct drm_encoder *enc)
{
	struct dpu_crtc *dpu_crtc = to_dpu_crtc(crtc);
	struct dpu_kms *dpu_kms = _dpu_crtc_get_kms(crtc);
	struct dpu_rm *rm = &dpu_kms->rm;
	struct dpu_crtc_mixer *mixer;
	struct dpu_hw_ctl *last_valid_ctl = NULL;
	int i;
	struct dpu_rm_hw_iter lm_iter, ctl_iter, dspp_iter, ds_iter;

	dpu_rm_init_hw_iter(&lm_iter, enc->base.id, DPU_HW_BLK_LM);
	dpu_rm_init_hw_iter(&ctl_iter, enc->base.id, DPU_HW_BLK_CTL);
	dpu_rm_init_hw_iter(&dspp_iter, enc->base.id, DPU_HW_BLK_DSPP);
	dpu_rm_init_hw_iter(&ds_iter, enc->base.id, DPU_HW_BLK_DS);

	/* Set up all the mixers and ctls reserved by this encoder */
	for (i = dpu_crtc->num_mixers; i < ARRAY_SIZE(dpu_crtc->mixers); i++) {
		mixer = &dpu_crtc->mixers[i];

		if (!dpu_rm_get_hw(rm, &lm_iter))
			break;
		mixer->hw_lm = (struct dpu_hw_mixer *)lm_iter.hw;

		/* CTL may be <= LMs, if <, multiple LMs controlled by 1 CTL */
		if (!dpu_rm_get_hw(rm, &ctl_iter)) {
			DPU_DEBUG("no ctl assigned to lm %d, using previous\n",
					mixer->hw_lm->idx - LM_0);
			mixer->hw_ctl = last_valid_ctl;
		} else {
			mixer->hw_ctl = (struct dpu_hw_ctl *)ctl_iter.hw;
			last_valid_ctl = mixer->hw_ctl;
		}

		/* Shouldn't happen, mixers are always >= ctls */
		if (!mixer->hw_ctl) {
			DPU_ERROR("no valid ctls found for lm %d\n",
					mixer->hw_lm->idx - LM_0);
			return;
		}

		/* Dspp may be null */
		(void) dpu_rm_get_hw(rm, &dspp_iter);
		mixer->hw_dspp = (struct dpu_hw_dspp *)dspp_iter.hw;

		/* DS may be null */
		(void) dpu_rm_get_hw(rm, &ds_iter);
		mixer->hw_ds = (struct dpu_hw_ds *)ds_iter.hw;

		mixer->encoder = enc;

		dpu_crtc->num_mixers++;
		DPU_DEBUG("setup mixer %d: lm %d\n",
				i, mixer->hw_lm->idx - LM_0);
		DPU_DEBUG("setup mixer %d: ctl %d\n",
				i, mixer->hw_ctl->idx - CTL_0);
		if (mixer->hw_ds)
			DPU_DEBUG("setup mixer %d: ds %d\n",
				i, mixer->hw_ds->idx - DS_0);
	}
}

static void _dpu_crtc_setup_mixers(struct drm_crtc *crtc)
{
	struct dpu_crtc *dpu_crtc = to_dpu_crtc(crtc);
	struct drm_encoder *enc;

	dpu_crtc->num_mixers = 0;
	dpu_crtc->mixers_swapped = false;
	memset(dpu_crtc->mixers, 0, sizeof(dpu_crtc->mixers));

	mutex_lock(&dpu_crtc->crtc_lock);
	/* Check for mixers on all encoders attached to this crtc */
	list_for_each_entry(enc, &crtc->dev->mode_config.encoder_list, head) {
		if (enc->crtc != crtc)
			continue;

		_dpu_crtc_setup_mixer_for_encoder(crtc, enc);
	}

	mutex_unlock(&dpu_crtc->crtc_lock);
}

static void _dpu_crtc_setup_lm_bounds(struct drm_crtc *crtc,
		struct drm_crtc_state *state)
{
	struct dpu_crtc *dpu_crtc;
	struct dpu_crtc_state *cstate;
	struct drm_display_mode *adj_mode;
	u32 crtc_split_width;
	int i;

	if (!crtc || !state) {
		DPU_ERROR("invalid args\n");
		return;
	}

	dpu_crtc = to_dpu_crtc(crtc);
	cstate = to_dpu_crtc_state(state);

	adj_mode = &state->adjusted_mode;
	crtc_split_width = dpu_crtc_get_mixer_width(dpu_crtc, cstate, adj_mode);

	for (i = 0; i < dpu_crtc->num_mixers; i++) {
		cstate->lm_bounds[i].x = crtc_split_width * i;
		cstate->lm_bounds[i].y = 0;
		cstate->lm_bounds[i].w = crtc_split_width;
		cstate->lm_bounds[i].h =
			dpu_crtc_get_mixer_height(dpu_crtc, cstate, adj_mode);
		DPU_EVT32_VERBOSE(DRMID(crtc), i,
				cstate->lm_bounds[i].x, cstate->lm_bounds[i].y,
				cstate->lm_bounds[i].w, cstate->lm_bounds[i].h);
	}

	drm_mode_debug_printmodeline(adj_mode);
}

static void dpu_crtc_atomic_begin(struct drm_crtc *crtc,
		struct drm_crtc_state *old_state)
{
	struct dpu_crtc *dpu_crtc;
	struct drm_encoder *encoder;
	struct drm_device *dev;
	unsigned long flags;
	struct dpu_crtc_smmu_state_data *smmu_state;

	if (!crtc) {
		DPU_ERROR("invalid crtc\n");
		return;
	}

	if (!crtc->state->enable) {
		DPU_DEBUG("crtc%d -> enable %d, skip atomic_begin\n",
				crtc->base.id, crtc->state->enable);
		return;
	}

	DPU_DEBUG("crtc%d\n", crtc->base.id);

	dpu_crtc = to_dpu_crtc(crtc);
	dev = crtc->dev;
	smmu_state = &dpu_crtc->smmu_state;

	if (!dpu_crtc->num_mixers) {
		_dpu_crtc_setup_mixers(crtc);
		_dpu_crtc_setup_lm_bounds(crtc, crtc->state);
	}

	if (dpu_crtc->event) {
		WARN_ON(dpu_crtc->event);
	} else {
		spin_lock_irqsave(&dev->event_lock, flags);
		dpu_crtc->event = crtc->state->event;
		crtc->state->event = NULL;
		spin_unlock_irqrestore(&dev->event_lock, flags);
	}

	list_for_each_entry(encoder, &dev->mode_config.encoder_list, head) {
		if (encoder->crtc != crtc)
			continue;

		/* encoder will trigger pending mask now */
		dpu_encoder_trigger_kickoff_pending(encoder);
	}

	/*
	 * If no mixers have been allocated in dpu_crtc_atomic_check(),
	 * it means we are trying to flush a CRTC whose state is disabled:
	 * nothing else needs to be done.
	 */
	if (unlikely(!dpu_crtc->num_mixers))
		return;

	_dpu_crtc_blend_setup(crtc);
	_dpu_crtc_dest_scaler_setup(crtc);

	/*
	 * Since CP properties use AXI buffer to program the
	 * HW, check if context bank is in attached
	 * state,
	 * apply color processing properties only if
	 * smmu state is attached,
	 */
	if ((smmu_state->state != DETACHED) &&
			(smmu_state->state != DETACH_ALL_REQ))
		dpu_cp_crtc_apply_properties(crtc);

	/*
	 * PP_DONE irq is only used by command mode for now.
	 * It is better to request pending before FLUSH and START trigger
	 * to make sure no pp_done irq missed.
	 * This is safe because no pp_done will happen before SW trigger
	 * in command mode.
	 */
}

static void dpu_crtc_atomic_flush(struct drm_crtc *crtc,
		struct drm_crtc_state *old_crtc_state)
{
	struct dpu_crtc *dpu_crtc;
	struct drm_device *dev;
	struct drm_plane *plane;
	struct msm_drm_private *priv;
	struct msm_drm_thread *event_thread;
	unsigned long flags;
	struct dpu_crtc_state *cstate;

	if (!crtc || !crtc->dev || !crtc->dev->dev_private) {
		DPU_ERROR("invalid crtc\n");
		return;
	}

	if (!crtc->state->enable) {
		DPU_DEBUG("crtc%d -> enable %d, skip atomic_flush\n",
				crtc->base.id, crtc->state->enable);
		return;
	}

	DPU_DEBUG("crtc%d\n", crtc->base.id);

	dpu_crtc = to_dpu_crtc(crtc);
	cstate = to_dpu_crtc_state(crtc->state);
	dev = crtc->dev;
	priv = dev->dev_private;

	if (crtc->index >= ARRAY_SIZE(priv->event_thread)) {
		DPU_ERROR("invalid crtc index[%d]\n", crtc->index);
		return;
	}

	event_thread = &priv->event_thread[crtc->index];

	if (dpu_crtc->event) {
		DPU_DEBUG("already received dpu_crtc->event\n");
	} else {
		spin_lock_irqsave(&dev->event_lock, flags);
		dpu_crtc->event = crtc->state->event;
		crtc->state->event = NULL;
		spin_unlock_irqrestore(&dev->event_lock, flags);
	}

	/*
	 * If no mixers has been allocated in dpu_crtc_atomic_check(),
	 * it means we are trying to flush a CRTC whose state is disabled:
	 * nothing else needs to be done.
	 */
	if (unlikely(!dpu_crtc->num_mixers))
		return;

	/*
	 * For planes without commit update, drm framework will not add
	 * those planes to current state since hardware update is not
	 * required. However, if those planes were power collapsed since
	 * last commit cycle, driver has to restore the hardware state
	 * of those planes explicitly here prior to plane flush.
	 */
	drm_atomic_crtc_for_each_plane(plane, crtc)
		dpu_plane_restore(plane);

	/* update performance setting before crtc kickoff */
	dpu_core_perf_crtc_update(crtc, 1, false);

	/*
	 * Final plane updates: Give each plane a chance to complete all
	 *                      required writes/flushing before crtc's "flush
	 *                      everything" call below.
	 */
	drm_atomic_crtc_for_each_plane(plane, crtc) {
		if (dpu_crtc->smmu_state.transition_error)
			dpu_plane_set_error(plane, true);
		dpu_plane_flush(plane);
	}

	/* Kickoff will be scheduled by outer layer */
}

/**
 * dpu_crtc_destroy_state - state destroy hook
 * @crtc: drm CRTC
 * @state: CRTC state object to release
 */
static void dpu_crtc_destroy_state(struct drm_crtc *crtc,
		struct drm_crtc_state *state)
{
	struct dpu_crtc *dpu_crtc;
	struct dpu_crtc_state *cstate;

	if (!crtc || !state) {
		DPU_ERROR("invalid argument(s)\n");
		return;
	}

	dpu_crtc = to_dpu_crtc(crtc);
	cstate = to_dpu_crtc_state(state);

	DPU_DEBUG("crtc%d\n", crtc->base.id);

	_dpu_crtc_rp_destroy(&cstate->rp);

	__drm_atomic_helper_crtc_destroy_state(state);

	/* destroy value helper */
	msm_property_destroy_state(&dpu_crtc->property_info, cstate,
			&cstate->property_state);
}

static int _dpu_crtc_wait_for_frame_done(struct drm_crtc *crtc)
{
	struct dpu_crtc *dpu_crtc;
	int ret, rc = 0;

	if (!crtc) {
		DPU_ERROR("invalid argument\n");
		return -EINVAL;
	}
	dpu_crtc = to_dpu_crtc(crtc);

	if (!atomic_read(&dpu_crtc->frame_pending)) {
		DPU_DEBUG("no frames pending\n");
		return 0;
	}

	DPU_EVT32_VERBOSE(DRMID(crtc), DPU_EVTLOG_FUNC_ENTRY);
	ret = wait_for_completion_timeout(&dpu_crtc->frame_done_comp,
			msecs_to_jiffies(DPU_FRAME_DONE_TIMEOUT));
	if (!ret) {
		DPU_ERROR("frame done completion wait timed out, ret:%d\n",
				ret);
		DPU_EVT32(DRMID(crtc), DPU_EVTLOG_FATAL);
		rc = -ETIMEDOUT;
	}
	DPU_EVT32_VERBOSE(DRMID(crtc), DPU_EVTLOG_FUNC_EXIT);

	return rc;
}

void dpu_crtc_commit_kickoff(struct drm_crtc *crtc)
{
	struct drm_encoder *encoder;
	struct drm_device *dev;
	struct dpu_crtc *dpu_crtc;
	struct msm_drm_private *priv;
	struct dpu_kms *dpu_kms;
	struct dpu_crtc_state *cstate;
	int ret;

	if (!crtc) {
		DPU_ERROR("invalid argument\n");
		return;
	}
	dev = crtc->dev;
	dpu_crtc = to_dpu_crtc(crtc);
	dpu_kms = _dpu_crtc_get_kms(crtc);

	if (!dpu_kms || !dpu_kms->dev || !dpu_kms->dev->dev_private) {
		DPU_ERROR("invalid argument\n");
		return;
	}

	priv = dpu_kms->dev->dev_private;
	cstate = to_dpu_crtc_state(crtc->state);

	/*
	 * If no mixers has been allocated in dpu_crtc_atomic_check(),
	 * it means we are trying to start a CRTC whose state is disabled:
	 * nothing else needs to be done.
	 */
	if (unlikely(!dpu_crtc->num_mixers))
		return;

	DPU_ATRACE_BEGIN("crtc_commit");

	list_for_each_entry(encoder, &dev->mode_config.encoder_list, head) {
		struct dpu_encoder_kickoff_params params = { 0 };

		if (encoder->crtc != crtc)
			continue;

		/*
		 * Encoder will flush/start now, unless it has a tx pending.
		 * If so, it may delay and flush at an irq event (e.g. ppdone)
		 */
		dpu_encoder_prepare_for_kickoff(encoder, &params);
	}

	/* wait for frame_event_done completion */
	DPU_ATRACE_BEGIN("wait_for_frame_done_event");
	ret = _dpu_crtc_wait_for_frame_done(crtc);
	DPU_ATRACE_END("wait_for_frame_done_event");
	if (ret) {
		DPU_ERROR("crtc%d wait for frame done failed;frame_pending%d\n",
				crtc->base.id,
				atomic_read(&dpu_crtc->frame_pending));
		goto end;
	}

	if (atomic_inc_return(&dpu_crtc->frame_pending) == 1) {
		/* acquire bandwidth and other resources */
		DPU_DEBUG("crtc%d first commit\n", crtc->base.id);
	} else
		DPU_DEBUG("crtc%d commit\n", crtc->base.id);

	dpu_crtc->play_count++;

	dpu_vbif_clear_errors(dpu_kms);

	list_for_each_entry(encoder, &dev->mode_config.encoder_list, head) {
		if (encoder->crtc != crtc)
			continue;

		dpu_encoder_kickoff(encoder);
	}

end:
	reinit_completion(&dpu_crtc->frame_done_comp);
	DPU_ATRACE_END("crtc_commit");
}

/**
 * _dpu_crtc_vblank_enable_no_lock - update power resource and vblank request
 * @dpu_crtc: Pointer to dpu crtc structure
 * @enable: Whether to enable/disable vblanks
 *
 * @Return: error code
 */
static int _dpu_crtc_vblank_enable_no_lock(
		struct dpu_crtc *dpu_crtc, bool enable)
{
	struct drm_device *dev;
	struct drm_crtc *crtc;
	struct drm_encoder *enc;

	if (!dpu_crtc) {
		DPU_ERROR("invalid crtc\n");
		return -EINVAL;
	}

	crtc = &dpu_crtc->base;
	dev = crtc->dev;

	if (enable) {
		int ret;

		/* drop lock since power crtc cb may try to re-acquire lock */
		mutex_unlock(&dpu_crtc->crtc_lock);
		pm_runtime_get_sync(dev->dev);
		ret = _dpu_crtc_power_enable(dpu_crtc, true);
		mutex_lock(&dpu_crtc->crtc_lock);
		if (ret)
			return ret;

		list_for_each_entry(enc, &dev->mode_config.encoder_list, head) {
			if (enc->crtc != crtc)
				continue;

			DPU_EVT32(DRMID(&dpu_crtc->base), DRMID(enc), enable,
					dpu_crtc->enabled,
					dpu_crtc->suspend,
					dpu_crtc->vblank_requested);

			dpu_encoder_register_vblank_callback(enc,
					dpu_crtc_vblank_cb, (void *)crtc);
		}
	} else {
		list_for_each_entry(enc, &dev->mode_config.encoder_list, head) {
			if (enc->crtc != crtc)
				continue;

			DPU_EVT32(DRMID(&dpu_crtc->base), DRMID(enc), enable,
					dpu_crtc->enabled,
					dpu_crtc->suspend,
					dpu_crtc->vblank_requested);

			dpu_encoder_register_vblank_callback(enc, NULL, NULL);
		}

		/* drop lock since power crtc cb may try to re-acquire lock */
		mutex_unlock(&dpu_crtc->crtc_lock);
		_dpu_crtc_power_enable(dpu_crtc, false);
		mutex_lock(&dpu_crtc->crtc_lock);
	}

	return 0;
}

/**
 * _dpu_crtc_set_suspend - notify crtc of suspend enable/disable
 * @crtc: Pointer to drm crtc object
 * @enable: true to enable suspend, false to indicate resume
 */
static void _dpu_crtc_set_suspend(struct drm_crtc *crtc, bool enable)
{
	struct dpu_crtc *dpu_crtc;
	struct msm_drm_private *priv;
	struct dpu_kms *dpu_kms;
	int ret = 0;

	if (!crtc || !crtc->dev || !crtc->dev->dev_private) {
		DPU_ERROR("invalid crtc\n");
		return;
	}
	dpu_crtc = to_dpu_crtc(crtc);
	priv = crtc->dev->dev_private;

	if (!priv->kms) {
		DPU_ERROR("invalid crtc kms\n");
		return;
	}
	dpu_kms = to_dpu_kms(priv->kms);

	DPU_DEBUG("crtc%d suspend = %d\n", crtc->base.id, enable);
	DPU_EVT32_VERBOSE(DRMID(crtc), enable);

	mutex_lock(&dpu_crtc->crtc_lock);

	/*
	 * If the vblank is enabled, release a power reference on suspend
	 * and take it back during resume (if it is still enabled).
	 */
	DPU_EVT32(DRMID(&dpu_crtc->base), enable, dpu_crtc->enabled,
			dpu_crtc->suspend, dpu_crtc->vblank_requested);
	if (dpu_crtc->suspend == enable)
		DPU_DEBUG("crtc%d suspend already set to %d, ignoring update\n",
				crtc->base.id, enable);
	else if (dpu_crtc->enabled && dpu_crtc->vblank_requested) {
		ret = _dpu_crtc_vblank_enable_no_lock(dpu_crtc, !enable);
		if (ret)
			DPU_ERROR("%s vblank enable failed: %d\n",
					dpu_crtc->name, ret);
	}

	dpu_crtc->suspend = enable;
	mutex_unlock(&dpu_crtc->crtc_lock);
}

/**
 * dpu_crtc_duplicate_state - state duplicate hook
 * @crtc: Pointer to drm crtc structure
 * @Returns: Pointer to new drm_crtc_state structure
 */
static struct drm_crtc_state *dpu_crtc_duplicate_state(struct drm_crtc *crtc)
{
	struct dpu_crtc *dpu_crtc;
	struct dpu_crtc_state *cstate, *old_cstate;

	if (!crtc || !crtc->state) {
		DPU_ERROR("invalid argument(s)\n");
		return NULL;
	}

	dpu_crtc = to_dpu_crtc(crtc);
	old_cstate = to_dpu_crtc_state(crtc->state);
	cstate = msm_property_alloc_state(&dpu_crtc->property_info);
	if (!cstate) {
		DPU_ERROR("failed to allocate state\n");
		return NULL;
	}

	/* duplicate value helper */
	msm_property_duplicate_state(&dpu_crtc->property_info,
			old_cstate, cstate,
			&cstate->property_state, cstate->property_values);

	/* duplicate base helper */
	__drm_atomic_helper_crtc_duplicate_state(crtc, &cstate->base);

	_dpu_crtc_rp_duplicate(&old_cstate->rp, &cstate->rp);

	return &cstate->base;
}

/**
 * dpu_crtc_reset - reset hook for CRTCs
 * Resets the atomic state for @crtc by freeing the state pointer (which might
 * be NULL, e.g. at driver load time) and allocating a new empty state object.
 * @crtc: Pointer to drm crtc structure
 */
static void dpu_crtc_reset(struct drm_crtc *crtc)
{
	struct dpu_crtc *dpu_crtc;
	struct dpu_crtc_state *cstate;

	if (!crtc) {
		DPU_ERROR("invalid crtc\n");
		return;
	}

	/* revert suspend actions, if necessary */
	if (dpu_kms_is_suspend_state(crtc->dev))
		_dpu_crtc_set_suspend(crtc, false);

	/* remove previous state, if present */
	if (crtc->state) {
		dpu_crtc_destroy_state(crtc, crtc->state);
		crtc->state = 0;
	}

	dpu_crtc = to_dpu_crtc(crtc);
	cstate = msm_property_alloc_state(&dpu_crtc->property_info);
	if (!cstate) {
		DPU_ERROR("failed to allocate state\n");
		return;
	}

	/* reset value helper */
	msm_property_reset_state(&dpu_crtc->property_info, cstate,
			&cstate->property_state,
			cstate->property_values);

	_dpu_crtc_rp_reset(&cstate->rp, &dpu_crtc->rp_lock,
			&dpu_crtc->rp_head);

	cstate->base.crtc = crtc;
	crtc->state = &cstate->base;
}

static void dpu_crtc_handle_power_event(u32 event_type, void *arg)
{
	struct drm_crtc *crtc = arg;
	struct dpu_crtc *dpu_crtc;
	struct drm_plane *plane;
	struct drm_encoder *encoder;
	struct dpu_crtc_mixer *m;
	u32 i, misr_status;

	if (!crtc) {
		DPU_ERROR("invalid crtc\n");
		return;
	}
	dpu_crtc = to_dpu_crtc(crtc);

	mutex_lock(&dpu_crtc->crtc_lock);

	DPU_EVT32(DRMID(crtc), event_type);

	switch (event_type) {
	case DPU_POWER_EVENT_POST_ENABLE:
		/* restore encoder; crtc will be programmed during commit */
		drm_for_each_encoder(encoder, crtc->dev) {
			if (encoder->crtc != crtc)
				continue;

			dpu_encoder_virt_restore(encoder);
		}

		dpu_cp_crtc_post_ipc(crtc);

		for (i = 0; i < dpu_crtc->num_mixers; ++i) {
			m = &dpu_crtc->mixers[i];
			if (!m->hw_lm || !m->hw_lm->ops.setup_misr ||
					!dpu_crtc->misr_enable)
				continue;

			m->hw_lm->ops.setup_misr(m->hw_lm, true,
					dpu_crtc->misr_frame_count);
		}
		break;
	case DPU_POWER_EVENT_PRE_DISABLE:
		for (i = 0; i < dpu_crtc->num_mixers; ++i) {
			m = &dpu_crtc->mixers[i];
			if (!m->hw_lm || !m->hw_lm->ops.collect_misr ||
					!dpu_crtc->misr_enable)
				continue;

			misr_status = m->hw_lm->ops.collect_misr(m->hw_lm);
			dpu_crtc->misr_data[i] = misr_status ? misr_status :
							dpu_crtc->misr_data[i];
		}

		dpu_cp_crtc_pre_ipc(crtc);
		break;
	case DPU_POWER_EVENT_POST_DISABLE:
		/*
		 * set revalidate flag in planes, so it will be re-programmed
		 * in the next frame update
		 */
		drm_atomic_crtc_for_each_plane(plane, crtc)
			dpu_plane_set_revalidate(plane, true);

		dpu_cp_crtc_suspend(crtc);
		break;
	default:
		DPU_DEBUG("event:%d not handled\n", event_type);
		break;
	}

	mutex_unlock(&dpu_crtc->crtc_lock);
}

static void dpu_crtc_disable(struct drm_crtc *crtc)
{
	struct dpu_crtc *dpu_crtc;
	struct dpu_crtc_state *cstate;
	struct drm_display_mode *mode;
	struct drm_encoder *encoder;
	struct msm_drm_private *priv;
	struct drm_event event;
	u32 power_on;
	int ret;

	if (!crtc || !crtc->dev || !crtc->dev->dev_private || !crtc->state) {
		DPU_ERROR("invalid crtc\n");
		return;
	}
	dpu_crtc = to_dpu_crtc(crtc);
	cstate = to_dpu_crtc_state(crtc->state);
	mode = &cstate->base.adjusted_mode;
	priv = crtc->dev->dev_private;

	if (msm_is_mode_seamless(mode) || msm_is_mode_seamless_vrr(mode) ||
	    msm_is_mode_seamless_dms(mode)) {
		DPU_DEBUG("Seamless mode is being applied, skip disable\n");
		return;
	}

	DPU_DEBUG("crtc%d\n", crtc->base.id);

	if (dpu_kms_is_suspend_state(crtc->dev))
		_dpu_crtc_set_suspend(crtc, true);

	mutex_lock(&dpu_crtc->crtc_lock);
	DPU_EVT32_VERBOSE(DRMID(crtc));

	/* update color processing on suspend */
	event.type = DRM_EVENT_CRTC_POWER;
	event.length = sizeof(u32);
	dpu_cp_crtc_suspend(crtc);
	power_on = 0;
	msm_mode_object_event_notify(&crtc->base, crtc->dev, &event,
			(u8 *)&power_on);

	/* wait for frame_event_done completion */
	if (_dpu_crtc_wait_for_frame_done(crtc))
		DPU_ERROR("crtc%d wait for frame done failed;frame_pending%d\n",
				crtc->base.id,
				atomic_read(&dpu_crtc->frame_pending));

	DPU_EVT32(DRMID(crtc), dpu_crtc->enabled, dpu_crtc->suspend,
			dpu_crtc->vblank_requested);
	if (dpu_crtc->enabled && !dpu_crtc->suspend &&
			dpu_crtc->vblank_requested) {
		ret = _dpu_crtc_vblank_enable_no_lock(dpu_crtc, false);
		if (ret)
			DPU_ERROR("%s vblank enable failed: %d\n",
					dpu_crtc->name, ret);
	}
	dpu_crtc->enabled = false;

	if (atomic_read(&dpu_crtc->frame_pending)) {
		DPU_EVT32(DRMID(crtc), atomic_read(&dpu_crtc->frame_pending),
							DPU_EVTLOG_FUNC_CASE2);
		dpu_core_perf_crtc_release_bw(crtc);
		atomic_set(&dpu_crtc->frame_pending, 0);
	}

	dpu_core_perf_crtc_update(crtc, 0, true);

	drm_for_each_encoder(encoder, crtc->dev) {
		if (encoder->crtc != crtc)
			continue;
		dpu_encoder_register_frame_event_callback(encoder, NULL, NULL);
	}

	if (dpu_crtc->power_event)
		dpu_power_handle_unregister_event(&priv->phandle,
				dpu_crtc->power_event);


	memset(dpu_crtc->mixers, 0, sizeof(dpu_crtc->mixers));
	dpu_crtc->num_mixers = 0;
	dpu_crtc->mixers_swapped = false;

	/* disable clk & bw control until clk & bw properties are set */
	cstate->bw_control = false;
	cstate->bw_split_vote = false;
	pm_runtime_put_sync(crtc->dev->dev);

	mutex_unlock(&dpu_crtc->crtc_lock);
}

static void dpu_crtc_enable(struct drm_crtc *crtc,
		struct drm_crtc_state *old_crtc_state)
{
	struct dpu_crtc *dpu_crtc;
	struct drm_encoder *encoder;
	struct msm_drm_private *priv;
	struct drm_event event;
	u32 power_on;
	int ret;

	if (!crtc || !crtc->dev || !crtc->dev->dev_private) {
		DPU_ERROR("invalid crtc\n");
		return;
	}
	priv = crtc->dev->dev_private;

	DPU_DEBUG("crtc%d\n", crtc->base.id);
	DPU_EVT32_VERBOSE(DRMID(crtc));
	dpu_crtc = to_dpu_crtc(crtc);

	if (msm_is_mode_seamless(&crtc->state->adjusted_mode) ||
	    msm_is_mode_seamless_vrr(&crtc->state->adjusted_mode)) {
		DPU_DEBUG("Skipping crtc enable, seamless mode\n");
		return;
	}

	pm_runtime_get_sync(crtc->dev->dev);

	drm_for_each_encoder(encoder, crtc->dev) {
		if (encoder->crtc != crtc)
			continue;
		dpu_encoder_register_frame_event_callback(encoder,
				dpu_crtc_frame_event_cb, (void *)crtc);
	}

	mutex_lock(&dpu_crtc->crtc_lock);
	DPU_EVT32(DRMID(crtc), dpu_crtc->enabled, dpu_crtc->suspend,
			dpu_crtc->vblank_requested);
	if (!dpu_crtc->enabled && !dpu_crtc->suspend &&
			dpu_crtc->vblank_requested) {
		ret = _dpu_crtc_vblank_enable_no_lock(dpu_crtc, true);
		if (ret)
			DPU_ERROR("%s vblank enable failed: %d\n",
					dpu_crtc->name, ret);
	}
	dpu_crtc->enabled = true;

	/* update color processing on resume */
	event.type = DRM_EVENT_CRTC_POWER;
	event.length = sizeof(u32);
	dpu_cp_crtc_resume(crtc);
	power_on = 1;
	msm_mode_object_event_notify(&crtc->base, crtc->dev, &event,
			(u8 *)&power_on);

	mutex_unlock(&dpu_crtc->crtc_lock);

	dpu_crtc->power_event = dpu_power_handle_register_event(
		&priv->phandle,
		DPU_POWER_EVENT_POST_ENABLE | DPU_POWER_EVENT_POST_DISABLE |
		DPU_POWER_EVENT_PRE_DISABLE,
		dpu_crtc_handle_power_event, crtc, dpu_crtc->name);

	if (msm_needs_vblank_pre_modeset(&crtc->state->adjusted_mode))
		drm_crtc_wait_one_vblank(crtc);
}

struct plane_state {
	struct dpu_plane_state *dpu_pstate;
	const struct drm_plane_state *drm_pstate;
	int stage;
	u32 pipe_id;
};

static int pstate_cmp(const void *a, const void *b)
{
	struct plane_state *pa = (struct plane_state *)a;
	struct plane_state *pb = (struct plane_state *)b;
	int rc = 0;
	int pa_zpos, pb_zpos;

	pa_zpos = dpu_plane_get_property(pa->dpu_pstate, PLANE_PROP_ZPOS);
	pb_zpos = dpu_plane_get_property(pb->dpu_pstate, PLANE_PROP_ZPOS);

	if (pa_zpos != pb_zpos)
		rc = pa_zpos - pb_zpos;
	else
		rc = pa->drm_pstate->crtc_x - pb->drm_pstate->crtc_x;

	return rc;
}

static int _dpu_crtc_excl_rect_overlap_check(struct plane_state pstates[],
	int cnt, int curr_cnt, struct dpu_rect *excl_rect, int z_pos)
{
	struct dpu_rect dst_rect, intersect;
	int i, rc = -EINVAL;
	const struct drm_plane_state *pstate;

	/* start checking from next plane */
	for (i = curr_cnt; i < cnt; i++) {
		pstate = pstates[i].drm_pstate;
		POPULATE_RECT(&dst_rect, pstate->crtc_x, pstate->crtc_y,
				pstate->crtc_w, pstate->crtc_h, false);
		dpu_kms_rect_intersect(&dst_rect, excl_rect, &intersect);

		if (intersect.w == excl_rect->w && intersect.h == excl_rect->h
				/* next plane may be on same z-order */
				&& z_pos != pstates[i].stage) {
			rc = 0;
			goto end;
		}
	}

	DPU_ERROR("excl rect does not find top overlapping rect\n");
end:
	return rc;
}

/* no input validation - caller API has all the checks */
static int _dpu_crtc_excl_dim_layer_check(struct drm_crtc_state *state,
		struct plane_state pstates[], int cnt)
{
	struct dpu_crtc_state *cstate = to_dpu_crtc_state(state);
	struct drm_display_mode *mode = &state->adjusted_mode;
	const struct drm_plane_state *pstate;
	struct dpu_plane_state *dpu_pstate;
	int rc = 0, i;

	/* Check dim layer rect bounds and stage */
	for (i = 0; i < cstate->num_dim_layers; i++) {
		if ((CHECK_LAYER_BOUNDS(cstate->dim_layer[i].rect.y,
			cstate->dim_layer[i].rect.h, mode->vdisplay)) ||
		    (CHECK_LAYER_BOUNDS(cstate->dim_layer[i].rect.x,
			cstate->dim_layer[i].rect.w, mode->hdisplay)) ||
		    (cstate->dim_layer[i].stage >= DPU_STAGE_MAX) ||
		    (!cstate->dim_layer[i].rect.w) ||
		    (!cstate->dim_layer[i].rect.h)) {
			DPU_ERROR("invalid dim_layer:{%d,%d,%d,%d}, stage:%d\n",
					cstate->dim_layer[i].rect.x,
					cstate->dim_layer[i].rect.y,
					cstate->dim_layer[i].rect.w,
					cstate->dim_layer[i].rect.h,
					cstate->dim_layer[i].stage);
			DPU_ERROR("display: %dx%d\n", mode->hdisplay,
					mode->vdisplay);
			rc = -E2BIG;
			goto end;
		}
	}

	/* this is traversing on sorted z-order pstates */
	for (i = 0; i < cnt; i++) {
		pstate = pstates[i].drm_pstate;
		dpu_pstate = to_dpu_plane_state(pstate);
		if (dpu_pstate->excl_rect.w && dpu_pstate->excl_rect.h) {
			/* check overlap on all top z-order */
			rc = _dpu_crtc_excl_rect_overlap_check(pstates, cnt,
			     i + 1, &dpu_pstate->excl_rect, pstates[i].stage);
			if (rc)
				goto end;
		}
	}

end:
	return rc;
}

static int dpu_crtc_atomic_check(struct drm_crtc *crtc,
		struct drm_crtc_state *state)
{
	struct dpu_crtc *dpu_crtc;
	struct plane_state pstates[DPU_STAGE_MAX * 4];
	struct dpu_crtc_state *cstate;

	const struct drm_plane_state *pstate;
	struct drm_plane *plane;
	struct drm_display_mode *mode;

	int cnt = 0, rc = 0, mixer_width, i, z_pos;

	struct dpu_multirect_plane_states multirect_plane[DPU_STAGE_MAX * 2];
	int multirect_count = 0;
	const struct drm_plane_state *pipe_staged[SSPP_MAX];
	int left_zpos_cnt = 0, right_zpos_cnt = 0;

	if (!crtc) {
		DPU_ERROR("invalid crtc\n");
		return -EINVAL;
	}

	dpu_crtc = to_dpu_crtc(crtc);
	cstate = to_dpu_crtc_state(state);

	if (!state->enable || !state->active) {
		DPU_DEBUG("crtc%d -> enable %d, active %d, skip atomic_check\n",
				crtc->base.id, state->enable, state->active);
		goto end;
	}

	mode = &state->adjusted_mode;
	DPU_DEBUG("%s: check", dpu_crtc->name);

	/* force a full mode set if active state changed */
	if (state->active_changed)
		state->mode_changed = true;

	memset(pipe_staged, 0, sizeof(pipe_staged));

	rc = _dpu_crtc_check_dest_scaler_data(crtc, state);
	if (rc) {
		DPU_ERROR("crtc%d failed dest scaler check %d\n",
			crtc->base.id, rc);
		goto end;
	}

	mixer_width = dpu_crtc_get_mixer_width(dpu_crtc, cstate, mode);

	_dpu_crtc_setup_lm_bounds(crtc, state);

	 /* get plane state for all drm planes associated with crtc state */
	drm_atomic_crtc_state_for_each_plane_state(plane, pstate, state) {
		if (IS_ERR_OR_NULL(pstate)) {
			rc = PTR_ERR(pstate);
			DPU_ERROR("%s: failed to get plane%d state, %d\n",
					dpu_crtc->name, plane->base.id, rc);
			goto end;
		}
		if (cnt >= ARRAY_SIZE(pstates))
			continue;

		pstates[cnt].dpu_pstate = to_dpu_plane_state(pstate);
		pstates[cnt].drm_pstate = pstate;
		pstates[cnt].stage = dpu_plane_get_property(
				pstates[cnt].dpu_pstate, PLANE_PROP_ZPOS);
		pstates[cnt].pipe_id = dpu_plane_pipe(plane);

		/* check dim layer stage with every plane */
		for (i = 0; i < cstate->num_dim_layers; i++) {
			if (cstate->dim_layer[i].stage
					== (pstates[cnt].stage + DPU_STAGE_0)) {
				DPU_ERROR(
					"plane:%d/dim_layer:%i-same stage:%d\n",
					plane->base.id, i,
					cstate->dim_layer[i].stage);
				rc = -EINVAL;
				goto end;
			}
		}

		if (pipe_staged[pstates[cnt].pipe_id]) {
			multirect_plane[multirect_count].r0 =
				pipe_staged[pstates[cnt].pipe_id];
			multirect_plane[multirect_count].r1 = pstate;
			multirect_count++;

			pipe_staged[pstates[cnt].pipe_id] = NULL;
		} else {
			pipe_staged[pstates[cnt].pipe_id] = pstate;
		}

		cnt++;

		if (CHECK_LAYER_BOUNDS(pstate->crtc_y, pstate->crtc_h,
				mode->vdisplay) ||
		    CHECK_LAYER_BOUNDS(pstate->crtc_x, pstate->crtc_w,
				mode->hdisplay)) {
			DPU_ERROR("invalid vertical/horizontal destination\n");
			DPU_ERROR("y:%d h:%d vdisp:%d x:%d w:%d hdisp:%d\n",
				pstate->crtc_y, pstate->crtc_h, mode->vdisplay,
				pstate->crtc_x, pstate->crtc_w, mode->hdisplay);
			rc = -E2BIG;
			goto end;
		}
	}

	for (i = 1; i < SSPP_MAX; i++) {
		if (pipe_staged[i]) {
			dpu_plane_clear_multirect(pipe_staged[i]);

			if (is_dpu_plane_virtual(pipe_staged[i]->plane)) {
				DPU_ERROR(
					"r1 only virt plane:%d not supported\n",
					pipe_staged[i]->plane->base.id);
				rc  = -EINVAL;
				goto end;
			}
		}
	}

	/* assign mixer stages based on sorted zpos property */
	sort(pstates, cnt, sizeof(pstates[0]), pstate_cmp, NULL);

	rc = _dpu_crtc_excl_dim_layer_check(state, pstates, cnt);
	if (rc)
		goto end;

	if (!dpu_is_custom_client()) {
		int stage_old = pstates[0].stage;

		z_pos = 0;
		for (i = 0; i < cnt; i++) {
			if (stage_old != pstates[i].stage)
				++z_pos;
			stage_old = pstates[i].stage;
			pstates[i].stage = z_pos;
		}
	}

	z_pos = -1;
	for (i = 0; i < cnt; i++) {
		/* reset counts at every new blend stage */
		if (pstates[i].stage != z_pos) {
			left_zpos_cnt = 0;
			right_zpos_cnt = 0;
			z_pos = pstates[i].stage;
		}

		/* verify z_pos setting before using it */
		if (z_pos >= DPU_STAGE_MAX - DPU_STAGE_0) {
			DPU_ERROR("> %d plane stages assigned\n",
					DPU_STAGE_MAX - DPU_STAGE_0);
			rc = -EINVAL;
			goto end;
		} else if (pstates[i].drm_pstate->crtc_x < mixer_width) {
			if (left_zpos_cnt == 2) {
				DPU_ERROR("> 2 planes @ stage %d on left\n",
					z_pos);
				rc = -EINVAL;
				goto end;
			}
			left_zpos_cnt++;

		} else {
			if (right_zpos_cnt == 2) {
				DPU_ERROR("> 2 planes @ stage %d on right\n",
					z_pos);
				rc = -EINVAL;
				goto end;
			}
			right_zpos_cnt++;
		}

		pstates[i].dpu_pstate->stage = z_pos + DPU_STAGE_0;
		DPU_DEBUG("%s: zpos %d", dpu_crtc->name, z_pos);
	}

	for (i = 0; i < multirect_count; i++) {
		if (dpu_plane_validate_multirect_v2(&multirect_plane[i])) {
			DPU_ERROR(
			"multirect validation failed for planes (%d - %d)\n",
					multirect_plane[i].r0->plane->base.id,
					multirect_plane[i].r1->plane->base.id);
			rc = -EINVAL;
			goto end;
		}
	}

	rc = dpu_core_perf_crtc_check(crtc, state);
	if (rc) {
		DPU_ERROR("crtc%d failed performance check %d\n",
				crtc->base.id, rc);
		goto end;
	}

	/* validate source split:
	 * use pstates sorted by stage to check planes on same stage
	 * we assume that all pipes are in source split so its valid to compare
	 * without taking into account left/right mixer placement
	 */
	for (i = 1; i < cnt; i++) {
		struct plane_state *prv_pstate, *cur_pstate;
		struct dpu_rect left_rect, right_rect;
		int32_t left_pid, right_pid;
		int32_t stage;

		prv_pstate = &pstates[i - 1];
		cur_pstate = &pstates[i];
		if (prv_pstate->stage != cur_pstate->stage)
			continue;

		stage = cur_pstate->stage;

		left_pid = prv_pstate->dpu_pstate->base.plane->base.id;
		POPULATE_RECT(&left_rect, prv_pstate->drm_pstate->crtc_x,
			prv_pstate->drm_pstate->crtc_y,
			prv_pstate->drm_pstate->crtc_w,
			prv_pstate->drm_pstate->crtc_h, false);

		right_pid = cur_pstate->dpu_pstate->base.plane->base.id;
		POPULATE_RECT(&right_rect, cur_pstate->drm_pstate->crtc_x,
			cur_pstate->drm_pstate->crtc_y,
			cur_pstate->drm_pstate->crtc_w,
			cur_pstate->drm_pstate->crtc_h, false);

		if (right_rect.x < left_rect.x) {
			swap(left_pid, right_pid);
			swap(left_rect, right_rect);
		}

		/**
		 * - planes are enumerated in pipe-priority order such that
		 *   planes with lower drm_id must be left-most in a shared
		 *   blend-stage when using source split.
		 * - planes in source split must be contiguous in width
		 * - planes in source split must have same dest yoff and height
		 */
		if (right_pid < left_pid) {
			DPU_ERROR(
				"invalid src split cfg. priority mismatch. stage: %d left: %d right: %d\n",
				stage, left_pid, right_pid);
			rc = -EINVAL;
			goto end;
		} else if (right_rect.x != (left_rect.x + left_rect.w)) {
			DPU_ERROR(
				"non-contiguous coordinates for src split. stage: %d left: %d - %d right: %d - %d\n",
				stage, left_rect.x, left_rect.w,
				right_rect.x, right_rect.w);
			rc = -EINVAL;
			goto end;
		} else if ((left_rect.y != right_rect.y) ||
				(left_rect.h != right_rect.h)) {
			DPU_ERROR(
				"source split at stage: %d. invalid yoff/height: l_y: %d r_y: %d l_h: %d r_h: %d\n",
				stage, left_rect.y, right_rect.y,
				left_rect.h, right_rect.h);
			rc = -EINVAL;
			goto end;
		}
	}

end:
	_dpu_crtc_rp_free_unused(&cstate->rp);
	return rc;
}

int dpu_crtc_vblank(struct drm_crtc *crtc, bool en)
{
	struct dpu_crtc *dpu_crtc;
	int ret;

	if (!crtc) {
		DPU_ERROR("invalid crtc\n");
		return -EINVAL;
	}
	dpu_crtc = to_dpu_crtc(crtc);

	mutex_lock(&dpu_crtc->crtc_lock);
	DPU_EVT32(DRMID(&dpu_crtc->base), en, dpu_crtc->enabled,
			dpu_crtc->suspend, dpu_crtc->vblank_requested);
	if (dpu_crtc->enabled && !dpu_crtc->suspend) {
		ret = _dpu_crtc_vblank_enable_no_lock(dpu_crtc, en);
		if (ret)
			DPU_ERROR("%s vblank enable failed: %d\n",
					dpu_crtc->name, ret);
	}
	dpu_crtc->vblank_requested = en;
	mutex_unlock(&dpu_crtc->crtc_lock);

	return 0;
}

void dpu_crtc_cancel_pending_flip(struct drm_crtc *crtc, struct drm_file *file)
{
	struct dpu_crtc *dpu_crtc = to_dpu_crtc(crtc);

	DPU_DEBUG("%s: cancel: %p\n", dpu_crtc->name, file);
	_dpu_crtc_complete_flip(crtc, file);
}

/**
 * dpu_crtc_install_properties - install all drm properties for crtc
 * @crtc: Pointer to drm crtc structure
 */
static void dpu_crtc_install_properties(struct drm_crtc *crtc,
				struct dpu_mdss_cfg *catalog)
{
	struct dpu_crtc *dpu_crtc;
	struct drm_device *dev;
	struct dpu_kms_info *info;
	struct dpu_kms *dpu_kms;

	DPU_DEBUG("\n");

	if (!crtc || !catalog) {
		DPU_ERROR("invalid crtc or catalog\n");
		return;
	}

	dpu_crtc = to_dpu_crtc(crtc);
	dev = crtc->dev;
	dpu_kms = _dpu_crtc_get_kms(crtc);

	if (!dpu_kms) {
		DPU_ERROR("invalid argument\n");
		return;
	}

	info = kzalloc(sizeof(struct dpu_kms_info), GFP_KERNEL);
	if (!info) {
		DPU_ERROR("failed to allocate info memory\n");
		return;
	}

	/* range properties */
	msm_property_install_range(&dpu_crtc->property_info,
			"core_clk", 0x0, 0, U64_MAX,
			dpu_kms->perf.max_core_clk_rate,
			CRTC_PROP_CORE_CLK);
	msm_property_install_range(&dpu_crtc->property_info,
			"core_ab", 0x0, 0, U64_MAX,
			catalog->perf.max_bw_high * 1000ULL,
			CRTC_PROP_CORE_AB);
	msm_property_install_range(&dpu_crtc->property_info,
			"core_ib", 0x0, 0, U64_MAX,
			catalog->perf.max_bw_high * 1000ULL,
			CRTC_PROP_CORE_IB);
	msm_property_install_range(&dpu_crtc->property_info,
			"llcc_ab", 0x0, 0, U64_MAX,
			catalog->perf.max_bw_high * 1000ULL,
			CRTC_PROP_LLCC_AB);
	msm_property_install_range(&dpu_crtc->property_info,
			"llcc_ib", 0x0, 0, U64_MAX,
			catalog->perf.max_bw_high * 1000ULL,
			CRTC_PROP_LLCC_IB);
	msm_property_install_range(&dpu_crtc->property_info,
			"dram_ab", 0x0, 0, U64_MAX,
			catalog->perf.max_bw_high * 1000ULL,
			CRTC_PROP_DRAM_AB);
	msm_property_install_range(&dpu_crtc->property_info,
			"dram_ib", 0x0, 0, U64_MAX,
			catalog->perf.max_bw_high * 1000ULL,
			CRTC_PROP_DRAM_IB);

	msm_property_install_range(&dpu_crtc->property_info,
		"idle_timeout", IDLE_TIMEOUT, 0, U64_MAX, 0,
		CRTC_PROP_IDLE_TIMEOUT);

	msm_property_install_blob(&dpu_crtc->property_info, "capabilities",
		DRM_MODE_PROP_IMMUTABLE, CRTC_PROP_INFO);

	dpu_kms_info_reset(info);

	if (catalog->caps->has_dim_layer) {
		msm_property_install_volatile_range(&dpu_crtc->property_info,
			"dim_layer_v1", 0x0, 0, ~0, 0, CRTC_PROP_DIM_LAYER_V1);
		dpu_kms_info_add_keyint(info, "dim_layer_v1_max_layers",
				DPU_MAX_DIM_LAYERS);
	}

	dpu_kms_info_add_keyint(info, "hw_version", catalog->hwversion);
	dpu_kms_info_add_keyint(info, "max_linewidth",
			catalog->caps->max_mixer_width);
	dpu_kms_info_add_keyint(info, "max_blendstages",
			catalog->caps->max_mixer_blendstages);
	if (catalog->caps->qseed_type == DPU_SSPP_SCALER_QSEED2)
		dpu_kms_info_add_keystr(info, "qseed_type", "qseed2");
	if (catalog->caps->qseed_type == DPU_SSPP_SCALER_QSEED3)
		dpu_kms_info_add_keystr(info, "qseed_type", "qseed3");

	if (dpu_is_custom_client()) {
		if (catalog->caps->smart_dma_rev == DPU_SSPP_SMART_DMA_V1)
			dpu_kms_info_add_keystr(info,
					"smart_dma_rev", "smart_dma_v1");
		if (catalog->caps->smart_dma_rev == DPU_SSPP_SMART_DMA_V2)
			dpu_kms_info_add_keystr(info,
					"smart_dma_rev", "smart_dma_v2");
	}

	if (catalog->mdp[0].has_dest_scaler) {
		dpu_kms_info_add_keyint(info, "has_dest_scaler",
				catalog->mdp[0].has_dest_scaler);
		dpu_kms_info_add_keyint(info, "dest_scaler_count",
					catalog->ds_count);

		if (catalog->ds[0].top) {
			dpu_kms_info_add_keyint(info,
					"max_dest_scaler_input_width",
					catalog->ds[0].top->maxinputwidth);
			dpu_kms_info_add_keyint(info,
					"max_dest_scaler_output_width",
					catalog->ds[0].top->maxinputwidth);
			dpu_kms_info_add_keyint(info, "max_dest_scale_up",
					catalog->ds[0].top->maxupscale);
		}

		if (catalog->ds[0].features & BIT(DPU_SSPP_SCALER_QSEED3)) {
			msm_property_install_volatile_range(
					&dpu_crtc->property_info, "dest_scaler",
					0x0, 0, ~0, 0, CRTC_PROP_DEST_SCALER);
			msm_property_install_blob(&dpu_crtc->property_info,
					"ds_lut_ed", 0,
					CRTC_PROP_DEST_SCALER_LUT_ED);
			msm_property_install_blob(&dpu_crtc->property_info,
					"ds_lut_cir", 0,
					CRTC_PROP_DEST_SCALER_LUT_CIR);
			msm_property_install_blob(&dpu_crtc->property_info,
					"ds_lut_sep", 0,
					CRTC_PROP_DEST_SCALER_LUT_SEP);
		}
	}

	dpu_kms_info_add_keyint(info, "has_src_split",
				catalog->caps->has_src_split);
	if (catalog->perf.max_bw_low)
		dpu_kms_info_add_keyint(info, "max_bandwidth_low",
				catalog->perf.max_bw_low * 1000LL);
	if (catalog->perf.max_bw_high)
		dpu_kms_info_add_keyint(info, "max_bandwidth_high",
				catalog->perf.max_bw_high * 1000LL);
	if (catalog->perf.min_core_ib)
		dpu_kms_info_add_keyint(info, "min_core_ib",
				catalog->perf.min_core_ib * 1000LL);
	if (catalog->perf.min_llcc_ib)
		dpu_kms_info_add_keyint(info, "min_llcc_ib",
				catalog->perf.min_llcc_ib * 1000LL);
	if (catalog->perf.min_dram_ib)
		dpu_kms_info_add_keyint(info, "min_dram_ib",
				catalog->perf.min_dram_ib * 1000LL);
	if (dpu_kms->perf.max_core_clk_rate)
		dpu_kms_info_add_keyint(info, "max_mdp_clk",
				dpu_kms->perf.max_core_clk_rate);
	dpu_kms_info_add_keystr(info, "core_ib_ff",
			catalog->perf.core_ib_ff);
	dpu_kms_info_add_keystr(info, "core_clk_ff",
			catalog->perf.core_clk_ff);
	dpu_kms_info_add_keystr(info, "comp_ratio_rt",
			catalog->perf.comp_ratio_rt);
	dpu_kms_info_add_keystr(info, "comp_ratio_nrt",
			catalog->perf.comp_ratio_nrt);
	dpu_kms_info_add_keyint(info, "dest_scale_prefill_lines",
			catalog->perf.dest_scale_prefill_lines);
	dpu_kms_info_add_keyint(info, "undersized_prefill_lines",
			catalog->perf.undersized_prefill_lines);
	dpu_kms_info_add_keyint(info, "macrotile_prefill_lines",
			catalog->perf.macrotile_prefill_lines);
	dpu_kms_info_add_keyint(info, "yuv_nv12_prefill_lines",
			catalog->perf.yuv_nv12_prefill_lines);
	dpu_kms_info_add_keyint(info, "linear_prefill_lines",
			catalog->perf.linear_prefill_lines);
	dpu_kms_info_add_keyint(info, "downscaling_prefill_lines",
			catalog->perf.downscaling_prefill_lines);
	dpu_kms_info_add_keyint(info, "xtra_prefill_lines",
			catalog->perf.xtra_prefill_lines);
	dpu_kms_info_add_keyint(info, "amortizable_threshold",
			catalog->perf.amortizable_threshold);
	dpu_kms_info_add_keyint(info, "min_prefill_lines",
			catalog->perf.min_prefill_lines);

	msm_property_set_blob(&dpu_crtc->property_info, &dpu_crtc->blob_info,
			info->data, DPU_KMS_INFO_DATALEN(info), CRTC_PROP_INFO);

	kfree(info);
}

/**
 * dpu_crtc_atomic_set_property - atomically set a crtc drm property
 * @crtc: Pointer to drm crtc structure
 * @state: Pointer to drm crtc state structure
 * @property: Pointer to targeted drm property
 * @val: Updated property value
 * @Returns: Zero on success
 */
static int dpu_crtc_atomic_set_property(struct drm_crtc *crtc,
		struct drm_crtc_state *state,
		struct drm_property *property,
		uint64_t val)
{
	struct dpu_crtc *dpu_crtc;
	struct dpu_crtc_state *cstate;
	int idx, ret = -EINVAL;

	if (!crtc || !state || !property) {
		DPU_ERROR("invalid argument(s)\n");
	} else {
		dpu_crtc = to_dpu_crtc(crtc);
		cstate = to_dpu_crtc_state(state);
		ret = msm_property_atomic_set(&dpu_crtc->property_info,
				&cstate->property_state, property, val);
		if (!ret) {
			idx = msm_property_index(&dpu_crtc->property_info,
					property);
			switch (idx) {
			case CRTC_PROP_DIM_LAYER_V1:
				_dpu_crtc_set_dim_layer_v1(cstate,
							u64_to_user_ptr(val));
				break;
			case CRTC_PROP_DEST_SCALER:
				ret = _dpu_crtc_set_dest_scaler(dpu_crtc,
						cstate, u64_to_user_ptr(val));
				break;
			case CRTC_PROP_DEST_SCALER_LUT_ED:
			case CRTC_PROP_DEST_SCALER_LUT_CIR:
			case CRTC_PROP_DEST_SCALER_LUT_SEP:
				ret = _dpu_crtc_set_dest_scaler_lut(dpu_crtc,
								cstate, idx);
				break;
			case CRTC_PROP_CORE_CLK:
			case CRTC_PROP_CORE_AB:
			case CRTC_PROP_CORE_IB:
				cstate->bw_control = true;
				break;
			case CRTC_PROP_LLCC_AB:
			case CRTC_PROP_LLCC_IB:
			case CRTC_PROP_DRAM_AB:
			case CRTC_PROP_DRAM_IB:
				cstate->bw_control = true;
				cstate->bw_split_vote = true;
				break;
			case CRTC_PROP_IDLE_TIMEOUT:
				_dpu_crtc_set_idle_timeout(crtc, val);
			default:
				/* nothing to do */
				break;
			}
		} else {
			ret = dpu_cp_crtc_set_property(crtc,
					property, val);
		}
		if (ret)
			DRM_ERROR("failed to set the property\n");

		DPU_DEBUG("crtc%d %s[%d] <= 0x%llx ret=%d\n", crtc->base.id,
				property->name, property->base.id, val, ret);
	}

	return ret;
}

/**
 * dpu_crtc_set_property - set a crtc drm property
 * @crtc: Pointer to drm crtc structure
 * @property: Pointer to targeted drm property
 * @val: Updated property value
 * @Returns: Zero on success
 */
static int dpu_crtc_set_property(struct drm_crtc *crtc,
		struct drm_property *property, uint64_t val)
{
	DPU_DEBUG("\n");

	return dpu_crtc_atomic_set_property(crtc, crtc->state, property, val);
}

/**
 * dpu_crtc_atomic_get_property - retrieve a crtc drm property
 * @crtc: Pointer to drm crtc structure
 * @state: Pointer to drm crtc state structure
 * @property: Pointer to targeted drm property
 * @val: Pointer to variable for receiving property value
 * @Returns: Zero on success
 */
static int dpu_crtc_atomic_get_property(struct drm_crtc *crtc,
		const struct drm_crtc_state *state,
		struct drm_property *property,
		uint64_t *val)
{
	struct dpu_crtc *dpu_crtc;
	struct dpu_crtc_state *cstate;
	struct drm_encoder *encoder;
	int i, ret = -EINVAL;
	bool is_cmd = true;

	if (!crtc || !state) {
		DPU_ERROR("invalid argument(s)\n");
	} else {
		dpu_crtc = to_dpu_crtc(crtc);
		cstate = to_dpu_crtc_state(state);

		/**
		 * set the cmd flag only when all the encoders attached
		 * to the crtc are in cmd mode. Consider all other cases
		 * as video mode.
		 */
		drm_for_each_encoder(encoder, crtc->dev) {
			if (encoder->crtc == crtc)
				is_cmd = dpu_encoder_check_mode(encoder,
						MSM_DISPLAY_CAP_CMD_MODE);
		}

		i = msm_property_index(&dpu_crtc->property_info, property);
		ret = msm_property_atomic_get(&dpu_crtc->property_info,
				&cstate->property_state,
				property, val);
		if (ret)
			ret = dpu_cp_crtc_get_property(crtc,
				property, val);
		if (ret)
			DRM_ERROR("get property failed\n");
	}
	return ret;
}

#ifdef CONFIG_DEBUG_FS
static int _dpu_debugfs_status_show(struct seq_file *s, void *data)
{
	struct dpu_crtc *dpu_crtc;
	struct dpu_plane_state *pstate = NULL;
	struct dpu_crtc_mixer *m;

	struct drm_crtc *crtc;
	struct drm_plane *plane;
	struct drm_display_mode *mode;
	struct drm_framebuffer *fb;
	struct drm_plane_state *state;
	struct dpu_crtc_state *cstate;

	int i, out_width;

	if (!s || !s->private)
		return -EINVAL;

	dpu_crtc = s->private;
	crtc = &dpu_crtc->base;
	cstate = to_dpu_crtc_state(crtc->state);

	mutex_lock(&dpu_crtc->crtc_lock);
	mode = &crtc->state->adjusted_mode;
	out_width = dpu_crtc_get_mixer_width(dpu_crtc, cstate, mode);

	seq_printf(s, "crtc:%d width:%d height:%d\n", crtc->base.id,
				mode->hdisplay, mode->vdisplay);

	seq_puts(s, "\n");

	for (i = 0; i < dpu_crtc->num_mixers; ++i) {
		m = &dpu_crtc->mixers[i];
		if (!m->hw_lm)
			seq_printf(s, "\tmixer[%d] has no lm\n", i);
		else if (!m->hw_ctl)
			seq_printf(s, "\tmixer[%d] has no ctl\n", i);
		else
			seq_printf(s, "\tmixer:%d ctl:%d width:%d height:%d\n",
				m->hw_lm->idx - LM_0, m->hw_ctl->idx - CTL_0,
				out_width, mode->vdisplay);
	}

	seq_puts(s, "\n");

	for (i = 0; i < cstate->num_dim_layers; i++) {
		struct dpu_hw_dim_layer *dim_layer = &cstate->dim_layer[i];

		seq_printf(s, "\tdim_layer:%d] stage:%d flags:%d\n",
				i, dim_layer->stage, dim_layer->flags);
		seq_printf(s, "\tdst_x:%d dst_y:%d dst_w:%d dst_h:%d\n",
				dim_layer->rect.x, dim_layer->rect.y,
				dim_layer->rect.w, dim_layer->rect.h);
		seq_printf(s,
			"\tcolor_0:%d color_1:%d color_2:%d color_3:%d\n",
				dim_layer->color_fill.color_0,
				dim_layer->color_fill.color_1,
				dim_layer->color_fill.color_2,
				dim_layer->color_fill.color_3);
		seq_puts(s, "\n");
	}

	drm_atomic_crtc_for_each_plane(plane, crtc) {
		pstate = to_dpu_plane_state(plane->state);
		state = plane->state;

		if (!pstate || !state)
			continue;

		seq_printf(s, "\tplane:%u stage:%d\n", plane->base.id,
			pstate->stage);

		if (plane->state->fb) {
			fb = plane->state->fb;

			seq_printf(s, "\tfb:%d image format:%4.4s wxh:%ux%u ",
				fb->base.id, (char *) &fb->format->format,
				fb->width, fb->height);
			for (i = 0; i < ARRAY_SIZE(fb->format->cpp); ++i)
				seq_printf(s, "cpp[%d]:%u ",
						i, fb->format->cpp[i]);
			seq_puts(s, "\n\t");

			seq_printf(s, "modifier:%8llu ", fb->modifier);
			seq_puts(s, "\n");

			seq_puts(s, "\t");
			for (i = 0; i < ARRAY_SIZE(fb->pitches); i++)
				seq_printf(s, "pitches[%d]:%8u ", i,
							fb->pitches[i]);
			seq_puts(s, "\n");

			seq_puts(s, "\t");
			for (i = 0; i < ARRAY_SIZE(fb->offsets); i++)
				seq_printf(s, "offsets[%d]:%8u ", i,
							fb->offsets[i]);
			seq_puts(s, "\n");
		}

		seq_printf(s, "\tsrc_x:%4d src_y:%4d src_w:%4d src_h:%4d\n",
			state->src_x, state->src_y, state->src_w, state->src_h);

		seq_printf(s, "\tdst x:%4d dst_y:%4d dst_w:%4d dst_h:%4d\n",
			state->crtc_x, state->crtc_y, state->crtc_w,
			state->crtc_h);
		seq_printf(s, "\tmultirect: mode: %d index: %d\n",
			pstate->multirect_mode, pstate->multirect_index);

		seq_printf(s, "\texcl_rect: x:%4d y:%4d w:%4d h:%4d\n",
			pstate->excl_rect.x, pstate->excl_rect.y,
			pstate->excl_rect.w, pstate->excl_rect.h);

		seq_puts(s, "\n");
	}
	if (dpu_crtc->vblank_cb_count) {
		ktime_t diff = ktime_sub(ktime_get(), dpu_crtc->vblank_cb_time);
		s64 diff_ms = ktime_to_ms(diff);
		s64 fps = diff_ms ? div_s64(
				dpu_crtc->vblank_cb_count * 1000, diff_ms) : 0;

		seq_printf(s,
			"vblank fps:%lld count:%u total:%llums total_framecount:%llu\n",
				fps, dpu_crtc->vblank_cb_count,
				ktime_to_ms(diff), dpu_crtc->play_count);

		/* reset time & count for next measurement */
		dpu_crtc->vblank_cb_count = 0;
		dpu_crtc->vblank_cb_time = ktime_set(0, 0);
	}

	seq_printf(s, "vblank_enable:%d\n", dpu_crtc->vblank_requested);

	mutex_unlock(&dpu_crtc->crtc_lock);

	return 0;
}

static int _dpu_debugfs_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, _dpu_debugfs_status_show, inode->i_private);
}

static ssize_t _dpu_crtc_misr_setup(struct file *file,
		const char __user *user_buf, size_t count, loff_t *ppos)
{
	struct dpu_crtc *dpu_crtc;
	struct dpu_crtc_mixer *m;
	int i = 0, rc;
	char buf[MISR_BUFF_SIZE + 1];
	u32 frame_count, enable;
	size_t buff_copy;

	if (!file || !file->private_data)
		return -EINVAL;

	dpu_crtc = file->private_data;
	buff_copy = min_t(size_t, count, MISR_BUFF_SIZE);
	if (copy_from_user(buf, user_buf, buff_copy)) {
		DPU_ERROR("buffer copy failed\n");
		return -EINVAL;
	}

	buf[buff_copy] = 0; /* end of string */

	if (sscanf(buf, "%u %u", &enable, &frame_count) != 2)
		return -EINVAL;

	rc = _dpu_crtc_power_enable(dpu_crtc, true);
	if (rc)
		return rc;

	mutex_lock(&dpu_crtc->crtc_lock);
	dpu_crtc->misr_enable = enable;
	dpu_crtc->misr_frame_count = frame_count;
	for (i = 0; i < dpu_crtc->num_mixers; ++i) {
		dpu_crtc->misr_data[i] = 0;
		m = &dpu_crtc->mixers[i];
		if (!m->hw_lm || !m->hw_lm->ops.setup_misr)
			continue;

		m->hw_lm->ops.setup_misr(m->hw_lm, enable, frame_count);
	}
	mutex_unlock(&dpu_crtc->crtc_lock);
	_dpu_crtc_power_enable(dpu_crtc, false);

	return count;
}

static ssize_t _dpu_crtc_misr_read(struct file *file,
		char __user *user_buff, size_t count, loff_t *ppos)
{
	struct dpu_crtc *dpu_crtc;
	struct dpu_crtc_mixer *m;
	int i = 0, rc;
	u32 misr_status;
	ssize_t len = 0;
	char buf[MISR_BUFF_SIZE + 1] = {'\0'};

	if (*ppos)
		return 0;

	if (!file || !file->private_data)
		return -EINVAL;

	dpu_crtc = file->private_data;
	rc = _dpu_crtc_power_enable(dpu_crtc, true);
	if (rc)
		return rc;

	mutex_lock(&dpu_crtc->crtc_lock);
	if (!dpu_crtc->misr_enable) {
		len += snprintf(buf + len, MISR_BUFF_SIZE - len,
			"disabled\n");
		goto buff_check;
	}

	for (i = 0; i < dpu_crtc->num_mixers; ++i) {
		m = &dpu_crtc->mixers[i];
		if (!m->hw_lm || !m->hw_lm->ops.collect_misr)
			continue;

		misr_status = m->hw_lm->ops.collect_misr(m->hw_lm);
		dpu_crtc->misr_data[i] = misr_status ? misr_status :
							dpu_crtc->misr_data[i];
		len += snprintf(buf + len, MISR_BUFF_SIZE - len, "lm idx:%d\n",
					m->hw_lm->idx - LM_0);
		len += snprintf(buf + len, MISR_BUFF_SIZE - len, "0x%x\n",
							dpu_crtc->misr_data[i]);
	}

buff_check:
	if (count <= len) {
		len = 0;
		goto end;
	}

	if (copy_to_user(user_buff, buf, len)) {
		len = -EFAULT;
		goto end;
	}

	*ppos += len;   /* increase offset */

end:
	mutex_unlock(&dpu_crtc->crtc_lock);
	_dpu_crtc_power_enable(dpu_crtc, false);
	return len;
}

#define DEFINE_DPU_DEBUGFS_SEQ_FOPS(__prefix)                          \
static int __prefix ## _open(struct inode *inode, struct file *file)	\
{									\
	return single_open(file, __prefix ## _show, inode->i_private);	\
}									\
static const struct file_operations __prefix ## _fops = {		\
	.owner = THIS_MODULE,						\
	.open = __prefix ## _open,					\
	.release = single_release,					\
	.read = seq_read,						\
	.llseek = seq_lseek,						\
}

static int dpu_crtc_debugfs_state_show(struct seq_file *s, void *v)
{
	struct drm_crtc *crtc = (struct drm_crtc *) s->private;
	struct dpu_crtc *dpu_crtc = to_dpu_crtc(crtc);
	struct dpu_crtc_state *cstate = to_dpu_crtc_state(crtc->state);
	struct dpu_crtc_res *res;
	struct dpu_crtc_respool *rp;
	int i;

	seq_printf(s, "num_connectors: %d\n", cstate->num_connectors);
	seq_printf(s, "client type: %d\n", dpu_crtc_get_client_type(crtc));
	seq_printf(s, "intf_mode: %d\n", dpu_crtc_get_intf_mode(crtc));
	seq_printf(s, "core_clk_rate: %llu\n",
			dpu_crtc->cur_perf.core_clk_rate);
	for (i = DPU_POWER_HANDLE_DBUS_ID_MNOC;
			i < DPU_POWER_HANDLE_DBUS_ID_MAX; i++) {
		seq_printf(s, "bw_ctl[%s]: %llu\n",
				dpu_power_handle_get_dbus_name(i),
				dpu_crtc->cur_perf.bw_ctl[i]);
		seq_printf(s, "max_per_pipe_ib[%s]: %llu\n",
				dpu_power_handle_get_dbus_name(i),
				dpu_crtc->cur_perf.max_per_pipe_ib[i]);
	}

	mutex_lock(&dpu_crtc->rp_lock);
	list_for_each_entry(rp, &dpu_crtc->rp_head, rp_list) {
		seq_printf(s, "rp.%d: ", rp->sequence_id);
		list_for_each_entry(res, &rp->res_list, list)
			seq_printf(s, "0x%x/0x%llx/%pK/%d ",
					res->type, res->tag, res->val,
					atomic_read(&res->refcount));
		seq_puts(s, "\n");
	}
	mutex_unlock(&dpu_crtc->rp_lock);

	return 0;
}
DEFINE_DPU_DEBUGFS_SEQ_FOPS(dpu_crtc_debugfs_state);

static int _dpu_crtc_init_debugfs(struct drm_crtc *crtc)
{
	struct dpu_crtc *dpu_crtc;
	struct dpu_kms *dpu_kms;

	static const struct file_operations debugfs_status_fops = {
		.open =		_dpu_debugfs_status_open,
		.read =		seq_read,
		.llseek =	seq_lseek,
		.release =	single_release,
	};
	static const struct file_operations debugfs_misr_fops = {
		.open =		simple_open,
		.read =		_dpu_crtc_misr_read,
		.write =	_dpu_crtc_misr_setup,
	};

	if (!crtc)
		return -EINVAL;
	dpu_crtc = to_dpu_crtc(crtc);

	dpu_kms = _dpu_crtc_get_kms(crtc);
	if (!dpu_kms)
		return -EINVAL;

	dpu_crtc->debugfs_root = debugfs_create_dir(dpu_crtc->name,
			crtc->dev->primary->debugfs_root);
	if (!dpu_crtc->debugfs_root)
		return -ENOMEM;

	/* don't error check these */
	debugfs_create_file("status", 0400,
			dpu_crtc->debugfs_root,
			dpu_crtc, &debugfs_status_fops);
	debugfs_create_file("state", 0600,
			dpu_crtc->debugfs_root,
			&dpu_crtc->base,
			&dpu_crtc_debugfs_state_fops);
	debugfs_create_file("misr_data", 0600, dpu_crtc->debugfs_root,
					dpu_crtc, &debugfs_misr_fops);

	return 0;
}

static void _dpu_crtc_destroy_debugfs(struct drm_crtc *crtc)
{
	struct dpu_crtc *dpu_crtc;

	if (!crtc)
		return;
	dpu_crtc = to_dpu_crtc(crtc);
	debugfs_remove_recursive(dpu_crtc->debugfs_root);
}
#else
static int _dpu_crtc_init_debugfs(struct drm_crtc *crtc)
{
	return 0;
}

static void _dpu_crtc_destroy_debugfs(struct drm_crtc *crtc)
{
}
#endif /* CONFIG_DEBUG_FS */

static int dpu_crtc_late_register(struct drm_crtc *crtc)
{
	return _dpu_crtc_init_debugfs(crtc);
}

static void dpu_crtc_early_unregister(struct drm_crtc *crtc)
{
	_dpu_crtc_destroy_debugfs(crtc);
}

static const struct drm_crtc_funcs dpu_crtc_funcs = {
	.set_config = drm_atomic_helper_set_config,
	.destroy = dpu_crtc_destroy,
	.page_flip = drm_atomic_helper_page_flip,
	.set_property = dpu_crtc_set_property,
	.atomic_set_property = dpu_crtc_atomic_set_property,
	.atomic_get_property = dpu_crtc_atomic_get_property,
	.reset = dpu_crtc_reset,
	.atomic_duplicate_state = dpu_crtc_duplicate_state,
	.atomic_destroy_state = dpu_crtc_destroy_state,
	.late_register = dpu_crtc_late_register,
	.early_unregister = dpu_crtc_early_unregister,
};

static const struct drm_crtc_helper_funcs dpu_crtc_helper_funcs = {
	.mode_fixup = dpu_crtc_mode_fixup,
	.disable = dpu_crtc_disable,
	.atomic_enable = dpu_crtc_enable,
	.atomic_check = dpu_crtc_atomic_check,
	.atomic_begin = dpu_crtc_atomic_begin,
	.atomic_flush = dpu_crtc_atomic_flush,
};

static void _dpu_crtc_event_cb(struct kthread_work *work)
{
	struct dpu_crtc_event *event;
	struct dpu_crtc *dpu_crtc;
	unsigned long irq_flags;

	if (!work) {
		DPU_ERROR("invalid work item\n");
		return;
	}

	event = container_of(work, struct dpu_crtc_event, kt_work);

	/* set dpu_crtc to NULL for static work structures */
	dpu_crtc = event->dpu_crtc;
	if (!dpu_crtc)
		return;

	if (event->cb_func)
		event->cb_func(&dpu_crtc->base, event->usr);

	spin_lock_irqsave(&dpu_crtc->event_lock, irq_flags);
	list_add_tail(&event->list, &dpu_crtc->event_free_list);
	spin_unlock_irqrestore(&dpu_crtc->event_lock, irq_flags);
}

int dpu_crtc_event_queue(struct drm_crtc *crtc,
		void (*func)(struct drm_crtc *crtc, void *usr), void *usr)
{
	unsigned long irq_flags;
	struct dpu_crtc *dpu_crtc;
	struct msm_drm_private *priv;
	struct dpu_crtc_event *event = NULL;
	u32 crtc_id;

	if (!crtc || !crtc->dev || !crtc->dev->dev_private || !func) {
		DPU_ERROR("invalid parameters\n");
		return -EINVAL;
	}
	dpu_crtc = to_dpu_crtc(crtc);
	priv = crtc->dev->dev_private;
	crtc_id = drm_crtc_index(crtc);

	/*
	 * Obtain an event struct from the private cache. This event
	 * queue may be called from ISR contexts, so use a private
	 * cache to avoid calling any memory allocation functions.
	 */
	spin_lock_irqsave(&dpu_crtc->event_lock, irq_flags);
	if (!list_empty(&dpu_crtc->event_free_list)) {
		event = list_first_entry(&dpu_crtc->event_free_list,
				struct dpu_crtc_event, list);
		list_del_init(&event->list);
	}
	spin_unlock_irqrestore(&dpu_crtc->event_lock, irq_flags);

	if (!event)
		return -ENOMEM;

	/* populate event node */
	event->dpu_crtc = dpu_crtc;
	event->cb_func = func;
	event->usr = usr;

	/* queue new event request */
	kthread_init_work(&event->kt_work, _dpu_crtc_event_cb);
	kthread_queue_work(&priv->event_thread[crtc_id].worker,
			&event->kt_work);

	return 0;
}

static int _dpu_crtc_init_events(struct dpu_crtc *dpu_crtc)
{
	int i, rc = 0;

	if (!dpu_crtc) {
		DPU_ERROR("invalid crtc\n");
		return -EINVAL;
	}

	spin_lock_init(&dpu_crtc->event_lock);

	INIT_LIST_HEAD(&dpu_crtc->event_free_list);
	for (i = 0; i < DPU_CRTC_MAX_EVENT_COUNT; ++i)
		list_add_tail(&dpu_crtc->event_cache[i].list,
				&dpu_crtc->event_free_list);

	return rc;
}

/* initialize crtc */
struct drm_crtc *dpu_crtc_init(struct drm_device *dev, struct drm_plane *plane)
{
	struct drm_crtc *crtc = NULL;
	struct dpu_crtc *dpu_crtc = NULL;
	struct msm_drm_private *priv = NULL;
	struct dpu_kms *kms = NULL;
	int i, rc;

	priv = dev->dev_private;
	kms = to_dpu_kms(priv->kms);

	dpu_crtc = kzalloc(sizeof(*dpu_crtc), GFP_KERNEL);
	if (!dpu_crtc)
		return ERR_PTR(-ENOMEM);

	crtc = &dpu_crtc->base;
	crtc->dev = dev;

	mutex_init(&dpu_crtc->crtc_lock);
	spin_lock_init(&dpu_crtc->spin_lock);
	atomic_set(&dpu_crtc->frame_pending, 0);

	mutex_init(&dpu_crtc->rp_lock);
	INIT_LIST_HEAD(&dpu_crtc->rp_head);

	init_completion(&dpu_crtc->frame_done_comp);

	INIT_LIST_HEAD(&dpu_crtc->frame_event_list);

	for (i = 0; i < ARRAY_SIZE(dpu_crtc->frame_events); i++) {
		INIT_LIST_HEAD(&dpu_crtc->frame_events[i].list);
		list_add(&dpu_crtc->frame_events[i].list,
				&dpu_crtc->frame_event_list);
		kthread_init_work(&dpu_crtc->frame_events[i].work,
				dpu_crtc_frame_event_work);
	}

	drm_crtc_init_with_planes(dev, crtc, plane, NULL, &dpu_crtc_funcs,
				NULL);

	drm_crtc_helper_add(crtc, &dpu_crtc_helper_funcs);
	plane->crtc = crtc;

	/* save user friendly CRTC name for later */
	snprintf(dpu_crtc->name, DPU_CRTC_NAME_SIZE, "crtc%u", crtc->base.id);

	/* initialize event handling */
	rc = _dpu_crtc_init_events(dpu_crtc);
	if (rc) {
		drm_crtc_cleanup(crtc);
		kfree(dpu_crtc);
		return ERR_PTR(rc);
	}

	/* create CRTC properties */
	msm_property_init(&dpu_crtc->property_info, &crtc->base, dev,
			priv->crtc_property, dpu_crtc->property_data,
			CRTC_PROP_COUNT, CRTC_PROP_BLOBCOUNT,
			sizeof(struct dpu_crtc_state));

	dpu_crtc_install_properties(crtc, kms->catalog);

	/* Init dest scaler */
	_dpu_crtc_dest_scaler_init(dpu_crtc, kms->catalog);

	/* Install color processing properties */
	dpu_cp_crtc_init(crtc);
	dpu_cp_crtc_install_properties(crtc);

	DPU_DEBUG("%s: successfully initialized crtc\n", dpu_crtc->name);
	return crtc;
}
