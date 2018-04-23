/*
 * Copyright (c) 2014-2018, The Linux Foundation. All rights reserved.
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

#include <drm/drm_crtc.h>
#include <linux/debugfs.h>
#include <linux/of_irq.h>
#include <linux/dma-buf.h>

#include "msm_drv.h"
#include "msm_mmu.h"
#include "msm_gem.h"

#include "dpu_kms.h"
#include "dpu_core_irq.h"
#include "dpu_formats.h"
#include "dpu_hw_vbif.h"
#include "dpu_vbif.h"
#include "dpu_encoder.h"
#include "dpu_plane.h"
#include "dpu_crtc.h"
#include "dpu_reg_dma.h"

#define CREATE_TRACE_POINTS
#include "dpu_trace.h"

static const char * const iommu_ports[] = {
		"mdp_0",
};

/**
 * Controls size of event log buffer. Specified as a power of 2.
 */
#define DPU_EVTLOG_SIZE	1024

/*
 * To enable overall DRM driver logging
 * # echo 0x2 > /sys/module/drm/parameters/debug
 *
 * To enable DRM driver h/w logging
 * # echo <mask> > /sys/kernel/debug/dri/0/debug/hw_log_mask
 *
 * See dpu_hw_mdss.h for h/w logging mask definitions (search for DPU_DBG_MASK_)
 */
#define DPU_DEBUGFS_DIR "msm_dpu"
#define DPU_DEBUGFS_HWMASKNAME "hw_log_mask"

/**
 * dpucustom - enable certain driver customizations for dpu clients
 *	Enabling this modifies the standard DRM behavior slightly and assumes
 *	that the clients have specific knowledge about the modifications that
 *	are involved, so don't enable this unless you know what you're doing.
 *
 *	Parts of the driver that are affected by this setting may be located by
 *	searching for invocations of the 'dpu_is_custom_client()' function.
 *
 *	This is disabled by default.
 */
static bool dpucustom;
module_param(dpucustom, bool, 0400);
MODULE_PARM_DESC(dpucustom, "Enable customizations for dpu clients");

static int dpu_kms_hw_init(struct msm_kms *kms);
static int _dpu_kms_mmu_destroy(struct dpu_kms *dpu_kms);
bool dpu_is_custom_client(void)
{
	return dpucustom;
}

#ifdef CONFIG_DEBUG_FS
static int _dpu_danger_signal_status(struct seq_file *s,
		bool danger_status)
{
	struct dpu_kms *kms = (struct dpu_kms *)s->private;
	struct msm_drm_private *priv;
	struct dpu_danger_safe_status status;
	int i;

	if (!kms || !kms->dev || !kms->dev->dev_private || !kms->hw_mdp) {
		DPU_ERROR("invalid arg(s)\n");
		return 0;
	}

	priv = kms->dev->dev_private;
	memset(&status, 0, sizeof(struct dpu_danger_safe_status));

	pm_runtime_get_sync(kms->dev->dev);
	dpu_power_resource_enable(&priv->phandle, kms->core_client, true);
	if (danger_status) {
		seq_puts(s, "\nDanger signal status:\n");
		if (kms->hw_mdp->ops.get_danger_status)
			kms->hw_mdp->ops.get_danger_status(kms->hw_mdp,
					&status);
	} else {
		seq_puts(s, "\nSafe signal status:\n");
		if (kms->hw_mdp->ops.get_danger_status)
			kms->hw_mdp->ops.get_danger_status(kms->hw_mdp,
					&status);
	}
	dpu_power_resource_enable(&priv->phandle, kms->core_client, false);
	pm_runtime_put_sync(kms->dev->dev);

	seq_printf(s, "MDP     :  0x%x\n", status.mdp);

	for (i = SSPP_VIG0; i < SSPP_MAX; i++)
		seq_printf(s, "SSPP%d   :  0x%x  \t", i - SSPP_VIG0,
				status.sspp[i]);
	seq_puts(s, "\n");

	for (i = WB_0; i < WB_MAX; i++)
		seq_printf(s, "WB%d     :  0x%x  \t", i - WB_0,
				status.wb[i]);
	seq_puts(s, "\n");

	return 0;
}

#define DEFINE_DPU_DEBUGFS_SEQ_FOPS(__prefix)				\
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

static int dpu_debugfs_danger_stats_show(struct seq_file *s, void *v)
{
	return _dpu_danger_signal_status(s, true);
}
DEFINE_DPU_DEBUGFS_SEQ_FOPS(dpu_debugfs_danger_stats);

static int dpu_debugfs_safe_stats_show(struct seq_file *s, void *v)
{
	return _dpu_danger_signal_status(s, false);
}
DEFINE_DPU_DEBUGFS_SEQ_FOPS(dpu_debugfs_safe_stats);

static void dpu_debugfs_danger_destroy(struct dpu_kms *dpu_kms)
{
	debugfs_remove_recursive(dpu_kms->debugfs_danger);
	dpu_kms->debugfs_danger = NULL;
}

static int dpu_debugfs_danger_init(struct dpu_kms *dpu_kms,
		struct dentry *parent)
{
	dpu_kms->debugfs_danger = debugfs_create_dir("danger",
			parent);
	if (!dpu_kms->debugfs_danger) {
		DPU_ERROR("failed to create danger debugfs\n");
		return -EINVAL;
	}

	debugfs_create_file("danger_status", 0600, dpu_kms->debugfs_danger,
			dpu_kms, &dpu_debugfs_danger_stats_fops);
	debugfs_create_file("safe_status", 0600, dpu_kms->debugfs_danger,
			dpu_kms, &dpu_debugfs_safe_stats_fops);

	return 0;
}

static int _dpu_debugfs_show_regset32(struct seq_file *s, void *data)
{
	struct dpu_debugfs_regset32 *regset;
	struct dpu_kms *dpu_kms;
	struct drm_device *dev;
	struct msm_drm_private *priv;
	void __iomem *base;
	uint32_t i, addr;

	if (!s || !s->private)
		return 0;

	regset = s->private;

	dpu_kms = regset->dpu_kms;
	if (!dpu_kms || !dpu_kms->mmio)
		return 0;

	dev = dpu_kms->dev;
	if (!dev)
		return 0;

	priv = dev->dev_private;
	if (!priv)
		return 0;

	base = dpu_kms->mmio + regset->offset;

	/* insert padding spaces, if needed */
	if (regset->offset & 0xF) {
		seq_printf(s, "[%x]", regset->offset & ~0xF);
		for (i = 0; i < (regset->offset & 0xF); i += 4)
			seq_puts(s, "         ");
	}

	if (dpu_power_resource_enable(&priv->phandle,
				dpu_kms->core_client, true)) {
		seq_puts(s, "failed to enable dpu clocks\n");
		return 0;
	}

	/* main register output */
	for (i = 0; i < regset->blk_len; i += 4) {
		addr = regset->offset + i;
		if ((addr & 0xF) == 0x0)
			seq_printf(s, i ? "\n[%x]" : "[%x]", addr);
		seq_printf(s, " %08x", readl_relaxed(base + i));
	}
	seq_puts(s, "\n");
	dpu_power_resource_enable(&priv->phandle, dpu_kms->core_client, false);

	return 0;
}

static int dpu_debugfs_open_regset32(struct inode *inode,
		struct file *file)
{
	return single_open(file, _dpu_debugfs_show_regset32, inode->i_private);
}

static const struct file_operations dpu_fops_regset32 = {
	.open =		dpu_debugfs_open_regset32,
	.read =		seq_read,
	.llseek =	seq_lseek,
	.release =	single_release,
};

void dpu_debugfs_setup_regset32(struct dpu_debugfs_regset32 *regset,
		uint32_t offset, uint32_t length, struct dpu_kms *dpu_kms)
{
	if (regset) {
		regset->offset = offset;
		regset->blk_len = length;
		regset->dpu_kms = dpu_kms;
	}
}

void *dpu_debugfs_create_regset32(const char *name, umode_t mode,
		void *parent, struct dpu_debugfs_regset32 *regset)
{
	if (!name || !regset || !regset->dpu_kms || !regset->blk_len)
		return NULL;

	/* make sure offset is a multiple of 4 */
	regset->offset = round_down(regset->offset, 4);

	return debugfs_create_file(name, mode, parent,
			regset, &dpu_fops_regset32);
}

void *dpu_debugfs_get_root(struct dpu_kms *dpu_kms)
{
	struct msm_drm_private *priv;

	if (!dpu_kms || !dpu_kms->dev || !dpu_kms->dev->dev_private)
		return NULL;

	priv = dpu_kms->dev->dev_private;
	return priv->debug_root;
}

static int _dpu_debugfs_init(struct dpu_kms *dpu_kms)
{
	void *p;
	int rc;
	void *debugfs_root;

	p = dpu_hw_util_get_log_mask_ptr();

	if (!dpu_kms || !p)
		return -EINVAL;

	debugfs_root = dpu_debugfs_get_root(dpu_kms);
	if (!debugfs_root)
		return -EINVAL;

	/* allow debugfs_root to be NULL */
	debugfs_create_x32(DPU_DEBUGFS_HWMASKNAME, 0600, debugfs_root, p);

	(void) dpu_debugfs_danger_init(dpu_kms, debugfs_root);
	(void) dpu_debugfs_vbif_init(dpu_kms, debugfs_root);
	(void) dpu_debugfs_core_irq_init(dpu_kms, debugfs_root);

	rc = dpu_core_perf_debugfs_init(&dpu_kms->perf, debugfs_root);
	if (rc) {
		DPU_ERROR("failed to init perf %d\n", rc);
		return rc;
	}

	return 0;
}

static void _dpu_debugfs_destroy(struct dpu_kms *dpu_kms)
{
	/* don't need to NULL check debugfs_root */
	if (dpu_kms) {
		dpu_debugfs_vbif_destroy(dpu_kms);
		dpu_debugfs_danger_destroy(dpu_kms);
		dpu_debugfs_core_irq_destroy(dpu_kms);
	}
}
#else
static int _dpu_debugfs_init(struct dpu_kms *dpu_kms)
{
	return 0;
}

static void _dpu_debugfs_destroy(struct dpu_kms *dpu_kms)
{
}
#endif

static int dpu_kms_enable_vblank(struct msm_kms *kms, struct drm_crtc *crtc)
{
	int ret;

	pm_runtime_get_sync(crtc->dev->dev);
	ret = dpu_crtc_vblank(crtc, true);
	pm_runtime_put_sync(crtc->dev->dev);

	return ret;
}

static void dpu_kms_disable_vblank(struct msm_kms *kms, struct drm_crtc *crtc)
{
	pm_runtime_get_sync(crtc->dev->dev);
	dpu_crtc_vblank(crtc, false);
	pm_runtime_put_sync(crtc->dev->dev);
}

static void dpu_kms_wait_for_frame_transfer_complete(struct msm_kms *kms,
		struct drm_crtc *crtc)
{
	struct drm_encoder *encoder;
	struct drm_device *dev;
	int ret;

	if (!kms || !crtc || !crtc->state || !crtc->dev) {
		DPU_ERROR("invalid params\n");
		return;
	}

	if (!crtc->state->enable) {
		DPU_DEBUG("[crtc:%d] not enable\n", crtc->base.id);
		return;
	}

	if (!crtc->state->active) {
		DPU_DEBUG("[crtc:%d] not active\n", crtc->base.id);
		return;
	}

	dev = crtc->dev;

	list_for_each_entry(encoder, &dev->mode_config.encoder_list, head) {
		if (encoder->crtc != crtc)
			continue;
		/*
		 * Video Mode - Wait for VSYNC
		 * Cmd Mode   - Wait for PP_DONE. Will be no-op if transfer is
		 *              complete
		 */
		DPU_EVT32_VERBOSE(DRMID(crtc));
		ret = dpu_encoder_wait_for_event(encoder, MSM_ENC_TX_COMPLETE);
		if (ret && ret != -EWOULDBLOCK) {
			DPU_ERROR(
			"[crtc: %d][enc: %d] wait for commit done returned %d\n",
			crtc->base.id, encoder->base.id, ret);
			break;
		}
	}
}

static void dpu_kms_prepare_commit(struct msm_kms *kms,
		struct drm_atomic_state *state)
{
	struct dpu_kms *dpu_kms;
	struct msm_drm_private *priv;
	struct drm_device *dev;
	struct drm_encoder *encoder;

	if (!kms)
		return;
	dpu_kms = to_dpu_kms(kms);
	dev = dpu_kms->dev;

	if (!dev || !dev->dev_private)
		return;
	priv = dev->dev_private;
	pm_runtime_get_sync(dev->dev);
	dpu_power_resource_enable(&priv->phandle, dpu_kms->core_client, true);

	list_for_each_entry(encoder, &dev->mode_config.encoder_list, head)
		if (encoder->crtc != NULL)
			dpu_encoder_prepare_commit(encoder);
}

/*
 * Override the encoder enable since we need to setup the inline rotator and do
 * some crtc magic before enabling any bridge that might be present.
 */
void dpu_kms_encoder_enable(struct drm_encoder *encoder)
{
	const struct drm_encoder_helper_funcs *funcs = encoder->helper_private;
	struct drm_crtc *crtc = encoder->crtc;

	/* Forward this enable call to the commit hook */
	if (funcs && funcs->commit)
		funcs->commit(encoder);

	if (crtc && crtc->state->active) {
		DPU_EVT32(DRMID(crtc));
		dpu_crtc_commit_kickoff(crtc);
	}
}

static void dpu_kms_commit(struct msm_kms *kms, struct drm_atomic_state *state)
{
	struct drm_crtc *crtc;
	struct drm_crtc_state *crtc_state;
	int i;

	for_each_new_crtc_in_state(state, crtc, crtc_state, i) {
		/* If modeset is required, kickoff is run in encoder_enable */
		if (drm_atomic_crtc_needs_modeset(crtc_state))
			continue;

		if (crtc->state->active) {
			DPU_EVT32(DRMID(crtc));
			dpu_crtc_commit_kickoff(crtc);
		}
	}
}

static void dpu_kms_complete_commit(struct msm_kms *kms,
		struct drm_atomic_state *old_state)
{
	struct dpu_kms *dpu_kms;
	struct msm_drm_private *priv;
	struct drm_crtc *crtc;
	struct drm_crtc_state *old_crtc_state;
	int i;

	if (!kms || !old_state)
		return;
	dpu_kms = to_dpu_kms(kms);

	if (!dpu_kms->dev || !dpu_kms->dev->dev_private)
		return;
	priv = dpu_kms->dev->dev_private;

	for_each_old_crtc_in_state(old_state, crtc, old_crtc_state, i)
		dpu_crtc_complete_commit(crtc, old_crtc_state);

	dpu_power_resource_enable(&priv->phandle, dpu_kms->core_client, false);
	pm_runtime_put_sync(dpu_kms->dev->dev);

	DPU_EVT32_VERBOSE(DPU_EVTLOG_FUNC_EXIT);
}

static void dpu_kms_wait_for_commit_done(struct msm_kms *kms,
		struct drm_crtc *crtc)
{
	struct drm_encoder *encoder;
	struct drm_device *dev;
	int ret;

	if (!kms || !crtc || !crtc->state) {
		DPU_ERROR("invalid params\n");
		return;
	}

	dev = crtc->dev;

	if (!crtc->state->enable) {
		DPU_DEBUG("[crtc:%d] not enable\n", crtc->base.id);
		return;
	}

	if (!crtc->state->active) {
		DPU_DEBUG("[crtc:%d] not active\n", crtc->base.id);
		return;
	}

	ret = drm_crtc_vblank_get(crtc);
	if (ret)
		return;
	list_for_each_entry(encoder, &dev->mode_config.encoder_list, head) {
		if (encoder->crtc != crtc)
			continue;
		/*
		 * Wait for post-flush if necessary to delay before
		 * plane_cleanup. For example, wait for vsync in case of video
		 * mode panels. This may be a no-op for command mode panels.
		 */
		DPU_EVT32_VERBOSE(DRMID(crtc));
		ret = dpu_encoder_wait_for_event(encoder, MSM_ENC_COMMIT_DONE);
		if (ret && ret != -EWOULDBLOCK) {
			DPU_ERROR("wait for commit done returned %d\n", ret);
			break;
		}
	}

	drm_crtc_vblank_put(crtc);
}

static void _dpu_kms_initialize_dsi(struct drm_device *dev,
				    struct msm_drm_private *priv,
				    struct dpu_kms *dpu_kms)
{
	struct drm_encoder *encoder = NULL;
	int i, rc;

	/*TODO: Support two independent DSI connectors */
	encoder = dpu_encoder_init(dev, DRM_MODE_CONNECTOR_DSI);
	if (IS_ERR_OR_NULL(encoder)) {
		DPU_ERROR("encoder init failed for dsi display\n");
		return;
	}

	priv->encoders[priv->num_encoders++] = encoder;

	for (i = 0; i < ARRAY_SIZE(priv->dsi); i++) {
		if (!priv->dsi[i]) {
			DPU_DEBUG("invalid msm_dsi for ctrl %d\n", i);
			return;
		}

		rc = msm_dsi_modeset_init(priv->dsi[i], dev, encoder);
		if (rc) {
			DPU_ERROR("modeset_init failed for dsi[%d], rc = %d\n",
				i, rc);
			continue;
		}
	}
}

/**
 * _dpu_kms_setup_displays - create encoders, bridges and connectors
 *                           for underlying displays
 * @dev:        Pointer to drm device structure
 * @priv:       Pointer to private drm device data
 * @dpu_kms:    Pointer to dpu kms structure
 * Returns:     Zero on success
 */
static void _dpu_kms_setup_displays(struct drm_device *dev,
				    struct msm_drm_private *priv,
				    struct dpu_kms *dpu_kms)
{
	_dpu_kms_initialize_dsi(dev, priv, dpu_kms);

	/**
	 * Extend this function to initialize other
	 * types of displays
	 */
}

static void _dpu_kms_drm_obj_destroy(struct dpu_kms *dpu_kms)
{
	struct msm_drm_private *priv;
	int i;

	if (!dpu_kms) {
		DPU_ERROR("invalid dpu_kms\n");
		return;
	} else if (!dpu_kms->dev) {
		DPU_ERROR("invalid dev\n");
		return;
	} else if (!dpu_kms->dev->dev_private) {
		DPU_ERROR("invalid dev_private\n");
		return;
	}
	priv = dpu_kms->dev->dev_private;

	for (i = 0; i < priv->num_crtcs; i++)
		priv->crtcs[i]->funcs->destroy(priv->crtcs[i]);
	priv->num_crtcs = 0;

	for (i = 0; i < priv->num_planes; i++)
		priv->planes[i]->funcs->destroy(priv->planes[i]);
	priv->num_planes = 0;

	for (i = 0; i < priv->num_connectors; i++)
		priv->connectors[i]->funcs->destroy(priv->connectors[i]);
	priv->num_connectors = 0;

	for (i = 0; i < priv->num_encoders; i++)
		priv->encoders[i]->funcs->destroy(priv->encoders[i]);
	priv->num_encoders = 0;
}

static int _dpu_kms_drm_obj_init(struct dpu_kms *dpu_kms)
{
	struct drm_device *dev;
	struct drm_plane *primary_planes[MAX_PLANES], *plane;
	struct drm_crtc *crtc;

	struct msm_drm_private *priv;
	struct dpu_mdss_cfg *catalog;

	int primary_planes_idx = 0, i, ret;
	int max_crtc_count;

	u32 sspp_id[MAX_PLANES];
	u32 master_plane_id[MAX_PLANES];
	u32 num_virt_planes = 0;

	if (!dpu_kms || !dpu_kms->dev || !dpu_kms->dev->dev) {
		DPU_ERROR("invalid dpu_kms\n");
		return -EINVAL;
	}

	dev = dpu_kms->dev;
	priv = dev->dev_private;
	catalog = dpu_kms->catalog;

	ret = dpu_core_irq_domain_add(dpu_kms);
	if (ret)
		goto fail_irq;

	/*
	 * Create encoder and query display drivers to create
	 * bridges and connectors
	 */
	_dpu_kms_setup_displays(dev, priv, dpu_kms);

	max_crtc_count = min(catalog->mixer_count, priv->num_encoders);

	/* Create the planes */
	for (i = 0; i < catalog->sspp_count; i++) {
		bool primary = true;

		if (catalog->sspp[i].features & BIT(DPU_SSPP_CURSOR)
			|| primary_planes_idx >= max_crtc_count)
			primary = false;

		plane = dpu_plane_init(dev, catalog->sspp[i].id, primary,
				(1UL << max_crtc_count) - 1, 0);
		if (IS_ERR(plane)) {
			DPU_ERROR("dpu_plane_init failed\n");
			ret = PTR_ERR(plane);
			goto fail;
		}
		priv->planes[priv->num_planes++] = plane;

		if (primary)
			primary_planes[primary_planes_idx++] = plane;

		if (dpu_hw_sspp_multirect_enabled(&catalog->sspp[i]) &&
			dpu_is_custom_client()) {
			int priority =
				catalog->sspp[i].sblk->smart_dma_priority;
			sspp_id[priority - 1] = catalog->sspp[i].id;
			master_plane_id[priority - 1] = plane->base.id;
			num_virt_planes++;
		}
	}

	/* Initialize smart DMA virtual planes */
	for (i = 0; i < num_virt_planes; i++) {
		plane = dpu_plane_init(dev, sspp_id[i], false,
			(1UL << max_crtc_count) - 1, master_plane_id[i]);
		if (IS_ERR(plane)) {
			DPU_ERROR("dpu_plane for virtual SSPP init failed\n");
			ret = PTR_ERR(plane);
			goto fail;
		}
		priv->planes[priv->num_planes++] = plane;
	}

	max_crtc_count = min(max_crtc_count, primary_planes_idx);

	/* Create one CRTC per encoder */
	for (i = 0; i < max_crtc_count; i++) {
		crtc = dpu_crtc_init(dev, primary_planes[i]);
		if (IS_ERR(crtc)) {
			ret = PTR_ERR(crtc);
			goto fail;
		}
		priv->crtcs[priv->num_crtcs++] = crtc;
	}

	if (dpu_is_custom_client()) {
		/* All CRTCs are compatible with all planes */
		for (i = 0; i < priv->num_planes; i++)
			priv->planes[i]->possible_crtcs =
				(1 << priv->num_crtcs) - 1;
	}

	/* All CRTCs are compatible with all encoders */
	for (i = 0; i < priv->num_encoders; i++)
		priv->encoders[i]->possible_crtcs = (1 << priv->num_crtcs) - 1;

	return 0;
fail:
	_dpu_kms_drm_obj_destroy(dpu_kms);
fail_irq:
	dpu_core_irq_domain_fini(dpu_kms);
	return ret;
}

/**
 * struct dpu_kms_fbo_fb - framebuffer creation list
 * @list: list of framebuffer attached to framebuffer object
 * @fb: Pointer to framebuffer attached to framebuffer object
 */
struct dpu_kms_fbo_fb {
	struct list_head list;
	struct drm_framebuffer *fb;
};

struct drm_framebuffer *dpu_kms_fbo_create_fb(struct drm_device *dev,
		struct dpu_kms_fbo *fbo)
{
	struct drm_framebuffer *fb = NULL;
	struct dpu_kms_fbo_fb *fbo_fb;
	struct drm_mode_fb_cmd2 mode_cmd = {0};
	u32 base_offset = 0;
	int i, ret;

	if (!dev) {
		DPU_ERROR("invalid drm device node\n");
		return NULL;
	}

	fbo_fb = kzalloc(sizeof(struct dpu_kms_fbo_fb), GFP_KERNEL);
	if (!fbo_fb)
		return NULL;

	mode_cmd.pixel_format = fbo->pixel_format;
	mode_cmd.width = fbo->width;
	mode_cmd.height = fbo->height;
	mode_cmd.flags = fbo->flags;

	for (i = 0; i < fbo->nplane; i++) {
		mode_cmd.offsets[i] = base_offset;
		mode_cmd.pitches[i] = fbo->layout.plane_pitch[i];
		mode_cmd.modifier[i] = fbo->modifier[i];
		base_offset += fbo->layout.plane_size[i];
		DPU_DEBUG("offset[%d]:%x\n", i, mode_cmd.offsets[i]);
	}

	fb = msm_framebuffer_init(dev, &mode_cmd, fbo->bo);
	if (IS_ERR(fb)) {
		ret = PTR_ERR(fb);
		fb = NULL;
		DPU_ERROR("failed to allocate fb %d\n", ret);
		goto fail;
	}

	/* need to take one reference for gem object */
	for (i = 0; i < fbo->nplane; i++)
		drm_gem_object_get(fbo->bo[i]);

	DPU_DEBUG("register private fb:%d\n", fb->base.id);

	INIT_LIST_HEAD(&fbo_fb->list);
	fbo_fb->fb = fb;
	drm_framebuffer_get(fbo_fb->fb);
	list_add_tail(&fbo_fb->list, &fbo->fb_list);

	return fb;

fail:
	kfree(fbo_fb);
	return NULL;
}

static void dpu_kms_fbo_destroy(struct dpu_kms_fbo *fbo)
{
	struct msm_drm_private *priv;
	struct dpu_kms *dpu_kms;
	struct drm_device *dev;
	struct dpu_kms_fbo_fb *curr, *next;
	int i;

	if (!fbo) {
		DPU_ERROR("invalid drm device node\n");
		return;
	}
	dev = fbo->dev;

	if (!dev || !dev->dev_private) {
		DPU_ERROR("invalid drm device node\n");
		return;
	}
	priv = dev->dev_private;

	if (!priv->kms) {
		DPU_ERROR("invalid kms handle\n");
		return;
	}
	dpu_kms = to_dpu_kms(priv->kms);

	DPU_DEBUG("%dx%d@%c%c%c%c/%llx/%x\n", fbo->width, fbo->height,
			fbo->pixel_format >> 0, fbo->pixel_format >> 8,
			fbo->pixel_format >> 16, fbo->pixel_format >> 24,
			fbo->modifier[0], fbo->flags);

	list_for_each_entry_safe(curr, next, &fbo->fb_list, list) {
		DPU_DEBUG("unregister private fb:%d\n", curr->fb->base.id);
		drm_framebuffer_unregister_private(curr->fb);
		drm_framebuffer_put(curr->fb);
		list_del(&curr->list);
		kfree(curr);
	}

	for (i = 0; i < fbo->layout.num_planes; i++) {
		if (fbo->bo[i]) {
			mutex_lock(&dev->struct_mutex);
			drm_gem_object_put(fbo->bo[i]);
			mutex_unlock(&dev->struct_mutex);
			fbo->bo[i] = NULL;
		}
	}

	if (fbo->dma_buf) {
		dma_buf_put(fbo->dma_buf);
		fbo->dma_buf = NULL;
	}


	if (dpu_kms->iclient && fbo->ihandle) {
#ifdef CONFIG_ION
		ion_free(dpu_kms->iclient, fbo->ihandle);
#endif
		fbo->ihandle = NULL;
	}
}

#ifdef CONFIG_ION
static void dpu_kms_set_gem_flags(struct msm_gem_object *msm_obj,
		uint32_t flags)
{
	if (msm_obj)
		msm_obj->flags |= flags;
}
#endif

struct dpu_kms_fbo *dpu_kms_fbo_alloc(struct drm_device *dev, u32 width,
		u32 height, u32 pixel_format, u64 modifier[4], u32 flags)
{
	struct msm_drm_private *priv;
	struct dpu_kms *dpu_kms;
	struct dpu_kms_fbo *fbo;
	int i, ret;

	if (!dev || !dev->dev_private) {
		DPU_ERROR("invalid drm device node\n");
		return NULL;
	}
	priv = dev->dev_private;

	if (!priv->kms) {
		DPU_ERROR("invalid kms handle\n");
		return NULL;
	}
	dpu_kms = to_dpu_kms(priv->kms);

	DPU_DEBUG("%dx%d@%c%c%c%c/%llx/%x\n", width, height,
			pixel_format >> 0, pixel_format >> 8,
			pixel_format >> 16, pixel_format >> 24,
			modifier[0], flags);

	fbo = kzalloc(sizeof(struct dpu_kms_fbo), GFP_KERNEL);
	if (!fbo)
		return NULL;

	atomic_set(&fbo->refcount, 0);
	INIT_LIST_HEAD(&fbo->fb_list);
	fbo->dev = dev;
	fbo->width = width;
	fbo->height = height;
	fbo->pixel_format = pixel_format;
	fbo->flags = flags;
	for (i = 0; i < ARRAY_SIZE(fbo->modifier); i++)
		fbo->modifier[i] = modifier[i];
	fbo->nplane = drm_format_num_planes(fbo->pixel_format);
	fbo->fmt = dpu_get_dpu_format_ext(fbo->pixel_format, fbo->modifier[0]);
	if (!fbo->fmt) {
		ret = -EINVAL;
		DPU_ERROR("failed to find pixel format\n");
		goto done;
	}

	ret = dpu_format_get_plane_sizes(fbo->fmt, fbo->width, fbo->height,
			&fbo->layout, fbo->layout.plane_pitch);
	if (ret) {
		DPU_ERROR("failed to get plane sizes\n");
		goto done;
	}

	/* allocate backing buffer object */
	if (dpu_kms->iclient) {
#ifdef CONFIG_ION
		u32 heap_id = ION_HEAP(ION_SYSTEM_HEAP_ID);

		fbo->ihandle = ion_alloc(dpu_kms->iclient,
				fbo->layout.total_size, SZ_4K, heap_id, 0);
		if (IS_ERR_OR_NULL(fbo->ihandle)) {
			DPU_ERROR("failed to alloc ion memory\n");
			ret = PTR_ERR(fbo->ihandle);
			fbo->ihandle = NULL;
			goto done;
		}

		fbo->dma_buf = ion_share_dma_buf(dpu_kms->iclient,
				fbo->ihandle);
		if (IS_ERR(fbo->dma_buf)) {
			DPU_ERROR("failed to share ion memory\n");
			ret = -ENOMEM;
			fbo->dma_buf = NULL;
			goto done;
		}

		fbo->bo[0] = dev->driver->gem_prime_import(dev,
				fbo->dma_buf);
		if (IS_ERR(fbo->bo[0])) {
			DPU_ERROR("failed to import ion memory\n");
			ret = PTR_ERR(fbo->bo[0]);
			fbo->bo[0] = NULL;
			goto done;
		}

		/* insert extra bo flags */
		dpu_kms_set_gem_flags(to_msm_bo(fbo->bo[0]), MSM_BO_KEEPATTRS);
#endif
	} else {
		fbo->bo[0] = msm_gem_new(dev, fbo->layout.total_size,
				MSM_BO_SCANOUT | MSM_BO_WC | MSM_BO_KEEPATTRS);
		if (IS_ERR(fbo->bo[0])) {
			DPU_ERROR("failed to new gem buffer\n");
			ret = PTR_ERR(fbo->bo[0]);
			fbo->bo[0] = NULL;
			goto done;
		}
	}

	mutex_lock(&dev->struct_mutex);
	for (i = 1; i < fbo->layout.num_planes; i++) {
		fbo->bo[i] = fbo->bo[0];
		drm_gem_object_get(fbo->bo[i]);
	}
	mutex_unlock(&dev->struct_mutex);

done:
	if (ret) {
		dpu_kms_fbo_destroy(fbo);
		kfree(fbo);
		fbo = NULL;
	} else {
		dpu_kms_fbo_reference(fbo);
	}

	return fbo;
}

int dpu_kms_fbo_reference(struct dpu_kms_fbo *fbo)
{
	if (!fbo) {
		DPU_ERROR("invalid parameters\n");
		return -EINVAL;
	}

	DPU_DEBUG("%pS refcount:%d\n", __builtin_return_address(0),
			atomic_read(&fbo->refcount));

	atomic_inc(&fbo->refcount);

	return 0;
}

void dpu_kms_fbo_unreference(struct dpu_kms_fbo *fbo)
{
	if (!fbo) {
		DPU_ERROR("invalid parameters\n");
		return;
	}

	DPU_DEBUG("%pS refcount:%d\n", __builtin_return_address(0),
			atomic_read(&fbo->refcount));

	if (!atomic_read(&fbo->refcount)) {
		DPU_ERROR("invalid refcount\n");
		return;
	} else if (atomic_dec_return(&fbo->refcount) == 0) {
		dpu_kms_fbo_destroy(fbo);
	}
}

static int dpu_kms_postinit(struct msm_kms *kms)
{
	struct dpu_kms *dpu_kms = to_dpu_kms(kms);
	struct drm_device *dev;
	int rc;

	if (!dpu_kms || !dpu_kms->dev || !dpu_kms->dev->dev) {
		DPU_ERROR("invalid dpu_kms\n");
		return -EINVAL;
	}

	dev = dpu_kms->dev;

	rc = _dpu_debugfs_init(dpu_kms);
	if (rc)
		DPU_ERROR("dpu_debugfs init failed: %d\n", rc);

	return rc;
}

static long dpu_kms_round_pixclk(struct msm_kms *kms, unsigned long rate,
		struct drm_encoder *encoder)
{
	return rate;
}

static void _dpu_kms_hw_destroy(struct dpu_kms *dpu_kms,
		struct platform_device *pdev)
{
	struct drm_device *dev;
	struct msm_drm_private *priv;
	int i;

	if (!dpu_kms || !pdev)
		return;

	dev = dpu_kms->dev;
	if (!dev)
		return;

	priv = dev->dev_private;
	if (!priv)
		return;

	if (dpu_kms->hw_intr)
		dpu_hw_intr_destroy(dpu_kms->hw_intr);
	dpu_kms->hw_intr = NULL;

	if (dpu_kms->power_event)
		dpu_power_handle_unregister_event(
				&priv->phandle, dpu_kms->power_event);

	/* safe to call these more than once during shutdown */
	_dpu_debugfs_destroy(dpu_kms);
	_dpu_kms_mmu_destroy(dpu_kms);


	if (dpu_kms->iclient) {
#ifdef CONFIG_ION
		ion_client_destroy(dpu_kms->iclient);
#endif
		dpu_kms->iclient = NULL;
	}


	if (dpu_kms->catalog) {
		for (i = 0; i < dpu_kms->catalog->vbif_count; i++) {
			u32 vbif_idx = dpu_kms->catalog->vbif[i].id;

			if ((vbif_idx < VBIF_MAX) && dpu_kms->hw_vbif[vbif_idx])
				dpu_hw_vbif_destroy(dpu_kms->hw_vbif[vbif_idx]);
		}
	}

	if (dpu_kms->rm_init)
		dpu_rm_destroy(&dpu_kms->rm);
	dpu_kms->rm_init = false;

	if (dpu_kms->catalog)
		dpu_hw_catalog_deinit(dpu_kms->catalog);
	dpu_kms->catalog = NULL;

	if (dpu_kms->core_client)
		dpu_power_client_destroy(&priv->phandle, dpu_kms->core_client);
	dpu_kms->core_client = NULL;

	if (dpu_kms->vbif[VBIF_NRT])
		msm_iounmap(pdev, dpu_kms->vbif[VBIF_NRT]);
	dpu_kms->vbif[VBIF_NRT] = NULL;

	if (dpu_kms->vbif[VBIF_RT])
		msm_iounmap(pdev, dpu_kms->vbif[VBIF_RT]);
	dpu_kms->vbif[VBIF_RT] = NULL;

	if (dpu_kms->mmio)
		msm_iounmap(pdev, dpu_kms->mmio);
	dpu_kms->mmio = NULL;

	dpu_reg_dma_deinit();
}

int dpu_kms_mmu_detach(struct dpu_kms *dpu_kms, bool secure_only)
{
	int i;

	if (!dpu_kms)
		return -EINVAL;

	for (i = 0; i < MSM_SMMU_DOMAIN_MAX; i++) {
		struct msm_mmu *mmu;
		struct msm_gem_address_space *aspace = dpu_kms->aspace[i];

		if (!aspace)
			continue;

		mmu = dpu_kms->aspace[i]->mmu;

		if (secure_only &&
			!aspace->mmu->funcs->is_domain_secure(mmu))
			continue;

		/* cleanup aspace before detaching */
		msm_gem_aspace_domain_attach_detach_update(aspace, true);

		DPU_DEBUG("Detaching domain:%d\n", i);
		aspace->mmu->funcs->detach(mmu, (const char **)iommu_ports,
			ARRAY_SIZE(iommu_ports));

		aspace->domain_attached = false;
	}

	return 0;
}

int dpu_kms_mmu_attach(struct dpu_kms *dpu_kms, bool secure_only)
{
	int i;

	if (!dpu_kms)
		return -EINVAL;

	for (i = 0; i < MSM_SMMU_DOMAIN_MAX; i++) {
		struct msm_mmu *mmu;
		struct msm_gem_address_space *aspace = dpu_kms->aspace[i];

		if (!aspace)
			continue;

		mmu = dpu_kms->aspace[i]->mmu;

		if (secure_only &&
			!aspace->mmu->funcs->is_domain_secure(mmu))
			continue;

		DPU_DEBUG("Attaching domain:%d\n", i);
		aspace->mmu->funcs->attach(mmu, (const char **)iommu_ports,
			ARRAY_SIZE(iommu_ports));

		msm_gem_aspace_domain_attach_detach_update(aspace, false);
		aspace->domain_attached = true;
	}

	return 0;
}

static void dpu_kms_destroy(struct msm_kms *kms)
{
	struct dpu_kms *dpu_kms;
	struct drm_device *dev;
	struct platform_device *platformdev;

	if (!kms) {
		DPU_ERROR("invalid kms\n");
		return;
	}

	dpu_kms = to_dpu_kms(kms);
	dev = dpu_kms->dev;
	if (!dev) {
		DPU_ERROR("invalid device\n");
		return;
	}

	platformdev = to_platform_device(dev->dev);
	if (!platformdev) {
		DPU_ERROR("invalid platform device\n");
		return;
	}

	_dpu_kms_hw_destroy(dpu_kms, platformdev);
	kfree(dpu_kms);
}

static void dpu_kms_preclose(struct msm_kms *kms, struct drm_file *file)
{
	struct dpu_kms *dpu_kms = to_dpu_kms(kms);
	struct drm_device *dev = dpu_kms->dev;
	struct msm_drm_private *priv = dev->dev_private;
	unsigned int i;

	for (i = 0; i < priv->num_crtcs; i++)
		dpu_crtc_cancel_pending_flip(priv->crtcs[i], file);
}

static int dpu_kms_atomic_check(struct msm_kms *kms,
		struct drm_atomic_state *state)
{
	struct dpu_kms *dpu_kms;
	struct drm_device *dev;
	int ret;

	if (!kms || !state)
		return -EINVAL;

	dpu_kms = to_dpu_kms(kms);
	dev = dpu_kms->dev;

	if (dpu_kms_is_suspend_blocked(dev)) {
		DPU_DEBUG("suspended, skip atomic_check\n");
		return -EBUSY;
	}

	ret = drm_atomic_helper_check(dev, state);
	if (ret)
		return ret;

	return 0;
}

static struct msm_gem_address_space*
_dpu_kms_get_address_space(struct msm_kms *kms,
		unsigned int domain)
{
	struct dpu_kms *dpu_kms;

	if (!kms) {
		DPU_ERROR("invalid kms\n");
		return  NULL;
	}

	dpu_kms = to_dpu_kms(kms);
	if (!dpu_kms) {
		DPU_ERROR("invalid dpu_kms\n");
		return NULL;
	}

	if (domain >= MSM_SMMU_DOMAIN_MAX)
		return NULL;

	return (dpu_kms->aspace[domain] &&
			dpu_kms->aspace[domain]->domain_attached) ?
		dpu_kms->aspace[domain] : NULL;
}

static int dpu_kms_pm_suspend(struct device *dev)
{
	struct drm_device *ddev;
	struct drm_modeset_acquire_ctx ctx;
	struct drm_atomic_state *state;
	struct dpu_kms *dpu_kms;
	int ret = 0, num_crtcs = 0;

	if (!dev)
		return -EINVAL;

	ddev = dev_get_drvdata(dev);
	if (!ddev || !ddev_to_msm_kms(ddev))
		return -EINVAL;

	dpu_kms = to_dpu_kms(ddev_to_msm_kms(ddev));
	DPU_EVT32(0);

	/* disable hot-plug polling */
	drm_kms_helper_poll_disable(ddev);

	/* acquire modeset lock(s) */
	drm_modeset_acquire_init(&ctx, 0);

retry:
	ret = drm_modeset_lock_all_ctx(ddev, &ctx);
	if (ret)
		goto unlock;

	/* save current state for resume */
	if (dpu_kms->suspend_state)
		drm_atomic_state_put(dpu_kms->suspend_state);
	dpu_kms->suspend_state = drm_atomic_helper_duplicate_state(ddev, &ctx);
	if (IS_ERR_OR_NULL(dpu_kms->suspend_state)) {
		DRM_ERROR("failed to back up suspend state\n");
		dpu_kms->suspend_state = NULL;
		goto unlock;
	}

	/* create atomic state to disable all CRTCs */
	state = drm_atomic_state_alloc(ddev);
	if (IS_ERR_OR_NULL(state)) {
		DRM_ERROR("failed to allocate crtc disable state\n");
		goto unlock;
	}

	state->acquire_ctx = &ctx;

	/* check for nothing to do */
	if (num_crtcs == 0) {
		DRM_DEBUG("all crtcs are already in the off state\n");
		drm_atomic_state_put(state);
		goto suspended;
	}

	/* commit the "disable all" state */
	ret = drm_atomic_commit(state);
	if (ret < 0) {
		DRM_ERROR("failed to disable crtcs, %d\n", ret);
		drm_atomic_state_put(state);
		goto unlock;
	}

suspended:
	dpu_kms->suspend_block = true;

unlock:
	if (ret == -EDEADLK) {
		drm_modeset_backoff(&ctx);
		goto retry;
	}
	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);

	return 0;
}

static int dpu_kms_pm_resume(struct device *dev)
{
	struct drm_device *ddev;
	struct dpu_kms *dpu_kms;
	int ret;

	if (!dev)
		return -EINVAL;

	ddev = dev_get_drvdata(dev);
	if (!ddev || !ddev_to_msm_kms(ddev))
		return -EINVAL;

	dpu_kms = to_dpu_kms(ddev_to_msm_kms(ddev));

	DPU_EVT32(dpu_kms->suspend_state != NULL);

	drm_mode_config_reset(ddev);

	drm_modeset_lock_all(ddev);

	dpu_kms->suspend_block = false;

	if (dpu_kms->suspend_state) {
		dpu_kms->suspend_state->acquire_ctx =
			ddev->mode_config.acquire_ctx;
		ret = drm_atomic_commit(dpu_kms->suspend_state);
		if (ret < 0) {
			DRM_ERROR("failed to restore state, %d\n", ret);
			drm_atomic_state_put(dpu_kms->suspend_state);
		}
		dpu_kms->suspend_state = NULL;
	}
	drm_modeset_unlock_all(ddev);

	/* enable hot-plug polling */
	drm_kms_helper_poll_enable(ddev);

	return 0;
}

void _dpu_kms_set_encoder_mode(struct msm_kms *kms,
				 struct drm_encoder *encoder,
				 bool cmd_mode)
{
	struct msm_display_info info;
	struct msm_drm_private *priv = encoder->dev->dev_private;
	int i, rc = 0;

	memset(&info, 0, sizeof(info));

	info.intf_type = encoder->encoder_type;
	info.capabilities = cmd_mode ? MSM_DISPLAY_CAP_CMD_MODE :
			MSM_DISPLAY_CAP_VID_MODE;

	/* TODO: No support for DSI swap */
	for (i = 0; i < ARRAY_SIZE(priv->dsi); i++) {
		if (priv->dsi[i]) {
			info.h_tile_instance[info.num_of_h_tiles] = i;
			info.num_of_h_tiles++;
		}
	}

	rc = dpu_encoder_setup(encoder->dev, encoder, &info);
	if (rc)
		DPU_ERROR("failed to setup DPU encoder %d: rc:%d\n",
			encoder->base.id, rc);
}

static const struct msm_kms_funcs kms_funcs = {
	.hw_init         = dpu_kms_hw_init,
	.postinit        = dpu_kms_postinit,
	.irq_preinstall  = dpu_irq_preinstall,
	.irq_postinstall = dpu_irq_postinstall,
	.irq_uninstall   = dpu_irq_uninstall,
	.irq             = dpu_irq,
	.preclose        = dpu_kms_preclose,
	.prepare_commit  = dpu_kms_prepare_commit,
	.commit          = dpu_kms_commit,
	.complete_commit = dpu_kms_complete_commit,
	.wait_for_crtc_commit_done = dpu_kms_wait_for_commit_done,
	.wait_for_tx_complete = dpu_kms_wait_for_frame_transfer_complete,
	.enable_vblank   = dpu_kms_enable_vblank,
	.disable_vblank  = dpu_kms_disable_vblank,
	.check_modified_format = dpu_format_check_modified_format,
	.atomic_check = dpu_kms_atomic_check,
	.get_format      = dpu_get_msm_format,
	.round_pixclk    = dpu_kms_round_pixclk,
	.pm_suspend      = dpu_kms_pm_suspend,
	.pm_resume       = dpu_kms_pm_resume,
	.destroy         = dpu_kms_destroy,
	.get_address_space = _dpu_kms_get_address_space,
	.set_encoder_mode = _dpu_kms_set_encoder_mode,
};

/* the caller api needs to turn on clock before calling it */
static inline void _dpu_kms_core_hw_rev_init(struct dpu_kms *dpu_kms)
{
	dpu_kms->core_rev = readl_relaxed(dpu_kms->mmio + 0x0);
}

static int _dpu_kms_mmu_destroy(struct dpu_kms *dpu_kms)
{
	struct msm_mmu *mmu;
	int i;

	for (i = ARRAY_SIZE(dpu_kms->aspace) - 1; i >= 0; i--) {
		if (!dpu_kms->aspace[i])
			continue;

		mmu = dpu_kms->aspace[i]->mmu;

		mmu->funcs->detach(mmu, (const char **)iommu_ports,
				ARRAY_SIZE(iommu_ports));
		msm_gem_address_space_put(dpu_kms->aspace[i]);

		dpu_kms->aspace[i] = NULL;
	}

	return 0;
}

static int _dpu_kms_mmu_init(struct dpu_kms *dpu_kms)
{
	int ret;

#ifdef CONFIG_QCOM_SMMU
	struct msm_mmu *mmu;
	int i;

	for (i = 0; i < MSM_SMMU_DOMAIN_MAX; i++) {
		struct msm_gem_address_space *aspace;

		mmu = msm_smmu_new(dpu_kms->dev->dev, i);
		if (IS_ERR(mmu)) {
			ret = PTR_ERR(mmu);
			DPU_DEBUG("failed to init iommu id %d: rc:%d\n",
								i, ret);
			continue;
		}

		aspace = msm_gem_smmu_address_space_create(dpu_kms->dev,
			mmu, "dpu");
		if (IS_ERR(aspace)) {
			ret = PTR_ERR(aspace);
			mmu->funcs->destroy(mmu);
			goto fail;
		}

		dpu_kms->aspace[i] = aspace;

		ret = mmu->funcs->attach(mmu, (const char **)iommu_ports,
				ARRAY_SIZE(iommu_ports));
		if (ret) {
			DPU_ERROR("failed to attach iommu %d: %d\n", i, ret);
			msm_gem_address_space_put(aspace);
			goto fail;
		}
		aspace->domain_attached = true;
	}
#else
	struct iommu_domain *domain;
	struct msm_gem_address_space *aspace;

	domain = iommu_get_domain_for_dev(dpu_kms->dev->dev);
	if (!domain) {
		DPU_ERROR("failed to get iommu domain for DPU\n");
		return PTR_ERR(domain);
	}

	domain->geometry.aperture_start = 0x1000;
	domain->geometry.aperture_end = 0xffffffff;

	aspace = msm_gem_address_space_create(dpu_kms->dev->dev,
		domain, "dpu");
	if (IS_ERR(aspace)) {
		ret = PTR_ERR(aspace);
		goto fail;
	}

	ret = aspace->mmu->funcs->attach(aspace->mmu,
				(const char **)iommu_ports,
				ARRAY_SIZE(iommu_ports));
	if (ret) {
		DPU_ERROR("failed to attach iommu %d\n", ret);
		msm_gem_address_space_put(aspace);
		goto fail;
	}

	aspace->domain_attached = true;
	dpu_kms->aspace[0] = aspace;
#endif
	return 0;
fail:
	_dpu_kms_mmu_destroy(dpu_kms);

	return ret;
}

static void dpu_kms_handle_power_event(u32 event_type, void *usr)
{
	struct dpu_kms *dpu_kms = usr;

	if (!dpu_kms)
		return;

	if (event_type == DPU_POWER_EVENT_POST_ENABLE)
		dpu_vbif_init_memtypes(dpu_kms);
}

static int dpu_kms_hw_init(struct msm_kms *kms)
{
	struct dpu_kms *dpu_kms;
	struct drm_device *dev;
	struct msm_drm_private *priv;
	struct platform_device *platformdev;
	int i, rc = -EINVAL;

	if (!kms) {
		DPU_ERROR("invalid kms\n");
		goto end;
	}

	dpu_kms = to_dpu_kms(kms);
	dev = dpu_kms->dev;
	if (!dev) {
		DPU_ERROR("invalid device\n");
		goto end;
	}

	platformdev = to_platform_device(dev->dev);
	if (!platformdev) {
		DPU_ERROR("invalid platform device\n");
		goto end;
		}

	priv = dev->dev_private;
	if (!priv) {
		DPU_ERROR("invalid private data\n");
		goto end;
	}

	dpu_kms->mmio = msm_ioremap(platformdev, "mdp_phys", "mdp_phys");
	if (IS_ERR(dpu_kms->mmio)) {
		rc = PTR_ERR(dpu_kms->mmio);
		DPU_ERROR("mdp register memory map failed: %d\n", rc);
		dpu_kms->mmio = NULL;
		goto error;
	}
	DRM_INFO("mapped mdp address space @%p\n", dpu_kms->mmio);
	dpu_kms->mmio_len = msm_iomap_size(platformdev, "mdp_phys");

	rc = dpu_dbg_reg_register_base(DPU_DBG_NAME, dpu_kms->mmio,
			dpu_kms->mmio_len);
	if (rc)
		DPU_ERROR("dbg base register kms failed: %d\n", rc);

	dpu_kms->vbif[VBIF_RT] = msm_ioremap(platformdev, "vbif_phys",
								"vbif_phys");
	if (IS_ERR(dpu_kms->vbif[VBIF_RT])) {
		rc = PTR_ERR(dpu_kms->vbif[VBIF_RT]);
		DPU_ERROR("vbif register memory map failed: %d\n", rc);
		dpu_kms->vbif[VBIF_RT] = NULL;
		goto error;
	}
	dpu_kms->vbif_len[VBIF_RT] = msm_iomap_size(platformdev,
								"vbif_phys");
	rc = dpu_dbg_reg_register_base("vbif_rt", dpu_kms->vbif[VBIF_RT],
				dpu_kms->vbif_len[VBIF_RT]);
	if (rc)
		DPU_ERROR("dbg base register vbif_rt failed: %d\n", rc);

	dpu_kms->vbif[VBIF_NRT] = msm_ioremap(platformdev, "vbif_nrt_phys",
								"vbif_nrt_phys");
	if (IS_ERR(dpu_kms->vbif[VBIF_NRT])) {
		dpu_kms->vbif[VBIF_NRT] = NULL;
		DPU_DEBUG("VBIF NRT is not defined");
	} else {
		dpu_kms->vbif_len[VBIF_NRT] = msm_iomap_size(platformdev,
							"vbif_nrt_phys");
		rc = dpu_dbg_reg_register_base("vbif_nrt",
				dpu_kms->vbif[VBIF_NRT],
				dpu_kms->vbif_len[VBIF_NRT]);
		if (rc)
			DPU_ERROR("dbg base register vbif_nrt failed: %d\n",
					rc);
	}

#ifdef CONFIG_CHROME_REGDMA
	dpu_kms->reg_dma = msm_ioremap(platformdev, "regdma_phys",
								"regdma_phys");
	if (IS_ERR(dpu_kms->reg_dma)) {
		dpu_kms->reg_dma = NULL;
		DPU_DEBUG("REG_DMA is not defined");
	} else {
		dpu_kms->reg_dma_len = msm_iomap_size(platformdev,
								"regdma_phys");
		rc =  dpu_dbg_reg_register_base("reg_dma",
				dpu_kms->reg_dma,
				dpu_kms->reg_dma_len);
		if (rc)
			DPU_ERROR("dbg base register reg_dma failed: %d\n",
					rc);
	}
#endif

	dpu_kms->core_client = dpu_power_client_create(&priv->phandle, "core");
	if (IS_ERR_OR_NULL(dpu_kms->core_client)) {
		rc = PTR_ERR(dpu_kms->core_client);
		if (!dpu_kms->core_client)
			rc = -EINVAL;
		DPU_ERROR("dpu power client create failed: %d\n", rc);
		dpu_kms->core_client = NULL;
		goto error;
	}
	pm_runtime_get_sync(dev->dev);
	rc = dpu_power_resource_enable(&priv->phandle, dpu_kms->core_client,
		true);
	if (rc) {
		DPU_ERROR("resource enable failed: %d\n", rc);
		goto error;
	}

	_dpu_kms_core_hw_rev_init(dpu_kms);

	pr_info("dpu hardware revision:0x%x\n", dpu_kms->core_rev);

	dpu_kms->catalog = dpu_hw_catalog_init(dpu_kms->core_rev);
	if (IS_ERR_OR_NULL(dpu_kms->catalog)) {
		rc = PTR_ERR(dpu_kms->catalog);
		if (!dpu_kms->catalog)
			rc = -EINVAL;
		DPU_ERROR("catalog init failed: %d\n", rc);
		dpu_kms->catalog = NULL;
		goto power_error;
	}

	dpu_dbg_init_dbg_buses(dpu_kms->core_rev);

	/*
	 * Now we need to read the HW catalog and initialize resources such as
	 * clocks, regulators, GDSC/MMAGIC, ioremap the register ranges etc
	 */
	rc = _dpu_kms_mmu_init(dpu_kms);
	if (rc) {
		DPU_ERROR("dpu_kms_mmu_init failed: %d\n", rc);
		goto power_error;
	}

	if (dpu_kms->aspace[0])
		kms->aspace = dpu_kms->aspace[0];

#ifdef CONFIG_CHROME_REGDMA
	/* Initialize reg dma block which is a singleton */
	rc = dpu_reg_dma_init(dpu_kms->reg_dma, dpu_kms->catalog,
			dpu_kms->dev);
	if (rc) {
		DPU_ERROR("failed: reg dma init failed\n");
		goto power_error;
	}
#endif

	rc = dpu_rm_init(&dpu_kms->rm, dpu_kms->catalog, dpu_kms->mmio,
			dpu_kms->dev);
	if (rc) {
		DPU_ERROR("rm init failed: %d\n", rc);
		goto power_error;
	}

	dpu_kms->rm_init = true;

	dpu_kms->hw_mdp = dpu_rm_get_mdp(&dpu_kms->rm);
	if (IS_ERR_OR_NULL(dpu_kms->hw_mdp)) {
		rc = PTR_ERR(dpu_kms->hw_mdp);
		if (!dpu_kms->hw_mdp)
			rc = -EINVAL;
		DPU_ERROR("failed to get hw_mdp: %d\n", rc);
		dpu_kms->hw_mdp = NULL;
		goto power_error;
	}

	for (i = 0; i < dpu_kms->catalog->vbif_count; i++) {
		u32 vbif_idx = dpu_kms->catalog->vbif[i].id;

		dpu_kms->hw_vbif[i] = dpu_hw_vbif_init(vbif_idx,
				dpu_kms->vbif[vbif_idx], dpu_kms->catalog);
		if (IS_ERR_OR_NULL(dpu_kms->hw_vbif[vbif_idx])) {
			rc = PTR_ERR(dpu_kms->hw_vbif[vbif_idx]);
			if (!dpu_kms->hw_vbif[vbif_idx])
				rc = -EINVAL;
			DPU_ERROR("failed to init vbif %d: %d\n", vbif_idx, rc);
			dpu_kms->hw_vbif[vbif_idx] = NULL;
			goto power_error;
		}
	}

#ifdef CONFIG_ION
	dpu_kms->iclient = msm_ion_client_create(dev->unique);
	if (IS_ERR(dpu_kms->iclient)) {
		rc = PTR_ERR(dpu_kms->iclient);
		DPU_DEBUG("msm_ion_client not available: %d\n", rc);
		dpu_kms->iclient = NULL;
	}
#else
	dpu_kms->iclient = NULL;
#endif

	rc = dpu_core_perf_init(&dpu_kms->perf, dev, dpu_kms->catalog,
			&priv->phandle, priv->pclient, "core_clk");
	if (rc) {
		DPU_ERROR("failed to init perf %d\n", rc);
		goto perf_err;
	}

	dpu_kms->hw_intr = dpu_hw_intr_init(dpu_kms->mmio, dpu_kms->catalog);
	if (IS_ERR_OR_NULL(dpu_kms->hw_intr)) {
		rc = PTR_ERR(dpu_kms->hw_intr);
		DPU_ERROR("hw_intr init failed: %d\n", rc);
		dpu_kms->hw_intr = NULL;
		goto hw_intr_init_err;
	}

	/*
	 * _dpu_kms_drm_obj_init should create the DRM related objects
	 * i.e. CRTCs, planes, encoders, connectors and so forth
	 */
	rc = _dpu_kms_drm_obj_init(dpu_kms);
	if (rc) {
		DPU_ERROR("modeset init failed: %d\n", rc);
		goto drm_obj_init_err;
	}

	dev->mode_config.min_width = 0;
	dev->mode_config.min_height = 0;

	/*
	 * max crtc width is equal to the max mixer width * 2 and max height is
	 * is 4K
	 */
	dev->mode_config.max_width =
			dpu_kms->catalog->caps->max_mixer_width * 2;
	dev->mode_config.max_height = 4096;

	/*
	 * Support format modifiers for compression etc.
	 */
	dev->mode_config.allow_fb_modifiers = true;

	/*
	 * Handle (re)initializations during power enable
	 */
	dpu_kms_handle_power_event(DPU_POWER_EVENT_POST_ENABLE, dpu_kms);
	dpu_kms->power_event = dpu_power_handle_register_event(&priv->phandle,
			DPU_POWER_EVENT_POST_ENABLE,
			dpu_kms_handle_power_event, dpu_kms, "kms");

	dpu_power_resource_enable(&priv->phandle, dpu_kms->core_client, false);
	pm_runtime_put_sync(dev->dev);

	return 0;

drm_obj_init_err:
	dpu_core_perf_destroy(&dpu_kms->perf);
hw_intr_init_err:
perf_err:
power_error:
	dpu_power_resource_enable(&priv->phandle, dpu_kms->core_client, false);
	pm_runtime_put_sync(dev->dev);
error:
	_dpu_kms_hw_destroy(dpu_kms, platformdev);
end:
	return rc;
}

struct msm_kms *dpu_kms_init(struct drm_device *dev)
{
	struct platform_device *pdev = to_platform_device(dev->dev);
	struct msm_drm_private *priv;
	struct dpu_kms *dpu_kms;
	int irq;

	if (!dev || !dev->dev_private) {
		DPU_ERROR("drm device node invalid\n");
		return ERR_PTR(-EINVAL);
	}

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		DPU_ERROR("failed to get irq: %d\n", irq);
		return ERR_PTR(irq);
	}

	priv = dev->dev_private;

	dpu_kms = kzalloc(sizeof(*dpu_kms), GFP_KERNEL);
	if (!dpu_kms) {
		DPU_ERROR("failed to allocate dpu kms\n");
		return ERR_PTR(-ENOMEM);
	}

	msm_kms_init(&dpu_kms->base, &kms_funcs);
	dpu_kms->dev = dev;
	dpu_kms->base.irq = irq;

	return &dpu_kms->base;
}

