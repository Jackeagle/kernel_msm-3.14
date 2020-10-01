// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2018-2020, The Linux Foundation. All rights reserved.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/of_clk.h>
#include <linux/clk-provider.h>
#include <sound/soc.h>
#include <sound/soc-dapm.h>
#include <linux/of_platform.h>
#include <sound/tlv.h>
#include <linux/pinctrl/consumer.h>

#include "lpass-wsa-macro.h"

#define AUTO_SUSPEND_DELAY  50 /* delay in msec */
#define WSA_MACRO_MAX_OFFSET 0x1000

#define WSA_MACRO_RX_RATES (SNDRV_PCM_RATE_8000 | SNDRV_PCM_RATE_16000 |\
			SNDRV_PCM_RATE_32000 | SNDRV_PCM_RATE_48000 |\
			SNDRV_PCM_RATE_96000 | SNDRV_PCM_RATE_192000)
#define WSA_MACRO_RX_MIX_RATES (SNDRV_PCM_RATE_48000 |\
			SNDRV_PCM_RATE_96000 | SNDRV_PCM_RATE_192000)
#define WSA_MACRO_RX_FORMATS (SNDRV_PCM_FMTBIT_S16_LE |\
		SNDRV_PCM_FMTBIT_S24_LE |\
		SNDRV_PCM_FMTBIT_S24_3LE | SNDRV_PCM_FMTBIT_S32_LE)

#define WSA_MACRO_ECHO_RATES (SNDRV_PCM_RATE_8000 | SNDRV_PCM_RATE_16000 |\
			SNDRV_PCM_RATE_48000)
#define WSA_MACRO_ECHO_FORMATS (SNDRV_PCM_FMTBIT_S16_LE |\
		SNDRV_PCM_FMTBIT_S24_LE |\
		SNDRV_PCM_FMTBIT_S24_3LE)

#define NUM_INTERPOLATORS 2

#define WSA_MACRO_MUX_INP_SHFT 0x3
#define WSA_MACRO_MUX_INP_MASK1 0x07
#define WSA_MACRO_MUX_INP_MASK2 0x38
#define WSA_MACRO_MUX_CFG_OFFSET 0x8
#define WSA_MACRO_MUX_CFG1_OFFSET 0x4
#define WSA_MACRO_RX_COMP_OFFSET 0x40
#define WSA_MACRO_RX_SOFTCLIP_OFFSET 0x40
#define WSA_MACRO_RX_PATH_OFFSET 0x80
#define WSA_MACRO_RX_PATH_CFG3_OFFSET 0x10
#define WSA_MACRO_RX_PATH_DSMDEM_OFFSET 0x4C
#define WSA_MACRO_FS_RATE_MASK 0x0F
#define WSA_MACRO_EC_MIX_TX0_MASK 0x03
#define WSA_MACRO_EC_MIX_TX1_MASK 0x18

#define WSA_MACRO_MAX_DMA_CH_PER_PORT 0x2

enum {
	WSA_MACRO_RX0 = 0,
	WSA_MACRO_RX1,
	WSA_MACRO_RX_MIX,
	WSA_MACRO_RX_MIX0 = WSA_MACRO_RX_MIX,
	WSA_MACRO_RX_MIX1,
	WSA_MACRO_RX_MAX,
};

enum {
	WSA_MACRO_TX0 = 0,
	WSA_MACRO_TX1,
	WSA_MACRO_TX_MAX,
};

enum {
	WSA_MACRO_EC0_MUX = 0,
	WSA_MACRO_EC1_MUX,
	WSA_MACRO_EC_MUX_MAX,
};

enum {
	WSA_MACRO_COMP1, /* SPK_L */
	WSA_MACRO_COMP2, /* SPK_R */
	WSA_MACRO_COMP_MAX
};

enum {
	WSA_MACRO_SOFTCLIP0, /* RX0 */
	WSA_MACRO_SOFTCLIP1, /* RX1 */
	WSA_MACRO_SOFTCLIP_MAX
};

enum {
	INTn_1_INP_SEL_ZERO = 0,
	INTn_1_INP_SEL_RX0,
	INTn_1_INP_SEL_RX1,
	INTn_1_INP_SEL_RX2,
	INTn_1_INP_SEL_RX3,
	INTn_1_INP_SEL_DEC0,
	INTn_1_INP_SEL_DEC1,
};

enum {
	INTn_2_INP_SEL_ZERO = 0,
	INTn_2_INP_SEL_RX0,
	INTn_2_INP_SEL_RX1,
	INTn_2_INP_SEL_RX2,
	INTn_2_INP_SEL_RX3,
};

struct interp_sample_rate {
	int sample_rate;
	int rate_val;
};

/*
 * Structure used to update codec
 * register defaults after reset
 */
struct wsa_macro_reg_mask_val {
	u16 reg;
	u8 mask;
	u8 val;
};

static struct interp_sample_rate int_prim_sample_rate_val[] = {
	{8000, 0x0},	/* 8K */
	{16000, 0x1},	/* 16K */
	{24000, -EINVAL},/* 24K */
	{32000, 0x3},	/* 32K */
	{48000, 0x4},	/* 48K */
	{96000, 0x5},	/* 96K */
	{192000, 0x6},	/* 192K */
	{384000, 0x7},	/* 384K */
	{44100, 0x8}, /* 44.1K */
};

static struct interp_sample_rate int_mix_sample_rate_val[] = {
	{48000, 0x4},	/* 48K */
	{96000, 0x5},	/* 96K */
	{192000, 0x6},	/* 192K */
};

#define WSA_MACRO_SWR_STRING_LEN 80

/* Hold instance to soundwire platform device */
struct wsa_macro_swr_ctrl_data {
	struct platform_device *wsa_swr_pdev;
};

enum {
	WSA_MACRO_AIF_INVALID = 0,
	WSA_MACRO_AIF1_PB,
	WSA_MACRO_AIF_MIX1_PB,
	WSA_MACRO_AIF_VI,
	WSA_MACRO_AIF_ECHO,
	WSA_MACRO_MAX_DAIS,
};

#define WSA_MACRO_CHILD_DEVICES_MAX 3

struct wsa_macro_priv {
	struct device *dev;
	int comp_enabled[WSA_MACRO_COMP_MAX];
	int ec_hq[WSA_MACRO_RX1 + 1];
	u16 prim_int_users[WSA_MACRO_RX1 + 1];
	u16 wsa_mclk_users;
	bool dapm_mclk_enable;
	bool reset_swr;
	unsigned int vi_feed_value;
	struct mutex mclk_lock;
	int rx_0_count;
	int rx_1_count;
	unsigned long active_ch_mask[WSA_MACRO_MAX_DAIS];
	unsigned long active_ch_cnt[WSA_MACRO_MAX_DAIS];
	int rx_port_value[WSA_MACRO_RX_MAX];
	int ear_spkr_gain;
	int spkr_gain_offset;
	int spkr_mode;
	int is_softclip_on[WSA_MACRO_SOFTCLIP_MAX];
	int softclip_clk_users[WSA_MACRO_SOFTCLIP_MAX];
	int wsa_digital_mute_status[WSA_MACRO_RX_MAX];

	struct regmap *regmap;
//	struct regmap *va_regmap;
	struct clk *hw_vote;
	struct clk *dcodec_vote;
	struct clk *clk;
	struct clk *npl_clk;
	struct clk_hw hw;
};
#define to_wsa_macro(_hw) container_of(_hw, struct wsa_macro_priv, hw)

static int wsa_macro_config_ear_spkr_gain(struct snd_soc_component *component,
					struct wsa_macro_priv *wsa_priv,
					int event, int gain_reg);
static struct snd_soc_dai_driver wsa_macro_dai[];
static const DECLARE_TLV_DB_SCALE(digital_gain, 0, 1, 0);

static const char *const rx_text[] = {
	"ZERO", "RX0", "RX1", "RX_MIX0", "RX_MIX1", "DEC0", "DEC1"
};

static const char *const rx_mix_text[] = {
	"ZERO", "RX0", "RX1", "RX_MIX0", "RX_MIX1"
};

static const char *const rx_mix_ec_text[] = {
	"ZERO", "RX_MIX_TX0", "RX_MIX_TX1"
};

static const char *const rx_mux_text[] = {
	"ZERO", "AIF1_PB", "AIF_MIX1_PB"
};

static const char *const rx_sidetone_mix_text[] = {
	"ZERO", "SRC0"
};

static const char * const wsa_macro_ear_spkr_pa_gain_text[] = {
	"G_DEFAULT", "G_0_DB", "G_1_DB", "G_2_DB", "G_3_DB",
	"G_4_DB", "G_5_DB", "G_6_DB"
};

static const char * const wsa_macro_speaker_boost_stage_text[] = {
	"NO_MAX_STATE", "MAX_STATE_1", "MAX_STATE_2"
};

static const char * const wsa_macro_vbat_bcl_gsm_mode_text[] = {
	"OFF", "ON"
};

static const struct snd_kcontrol_new wsa_int0_vbat_mix_switch[] = {
	SOC_DAPM_SINGLE("WSA RX0 VBAT Enable", SND_SOC_NOPM, 0, 1, 0)
};

static const struct snd_kcontrol_new wsa_int1_vbat_mix_switch[] = {
	SOC_DAPM_SINGLE("WSA RX1 VBAT Enable", SND_SOC_NOPM, 0, 1, 0)
};

static SOC_ENUM_SINGLE_EXT_DECL(wsa_macro_ear_spkr_pa_gain_enum,
				wsa_macro_ear_spkr_pa_gain_text);
static SOC_ENUM_SINGLE_EXT_DECL(wsa_macro_spkr_boost_stage_enum,
			wsa_macro_speaker_boost_stage_text);
static SOC_ENUM_SINGLE_EXT_DECL(wsa_macro_vbat_bcl_gsm_mode_enum,
			wsa_macro_vbat_bcl_gsm_mode_text);

/* RX INT0 */
static const struct soc_enum rx0_prim_inp0_chain_enum =
	SOC_ENUM_SINGLE(CDC_WSA_RX_INP_MUX_RX_INT0_CFG0,
		0, 7, rx_text);

static const struct soc_enum rx0_prim_inp1_chain_enum =
	SOC_ENUM_SINGLE(CDC_WSA_RX_INP_MUX_RX_INT0_CFG0,
		3, 7, rx_text);

static const struct soc_enum rx0_prim_inp2_chain_enum =
	SOC_ENUM_SINGLE(CDC_WSA_RX_INP_MUX_RX_INT0_CFG1,
		3, 7, rx_text);

static const struct soc_enum rx0_mix_chain_enum =
	SOC_ENUM_SINGLE(CDC_WSA_RX_INP_MUX_RX_INT0_CFG1,
		0, 5, rx_mix_text);

static const struct soc_enum rx0_sidetone_mix_enum =
	SOC_ENUM_SINGLE(SND_SOC_NOPM, 0, 2, rx_sidetone_mix_text);

static const struct snd_kcontrol_new rx0_prim_inp0_mux =
	SOC_DAPM_ENUM("WSA_RX0 INP0 Mux", rx0_prim_inp0_chain_enum);

static const struct snd_kcontrol_new rx0_prim_inp1_mux =
	SOC_DAPM_ENUM("WSA_RX0 INP1 Mux", rx0_prim_inp1_chain_enum);

static const struct snd_kcontrol_new rx0_prim_inp2_mux =
	SOC_DAPM_ENUM("WSA_RX0 INP2 Mux", rx0_prim_inp2_chain_enum);

static const struct snd_kcontrol_new rx0_mix_mux =
	SOC_DAPM_ENUM("WSA_RX0 MIX Mux", rx0_mix_chain_enum);

static const struct snd_kcontrol_new rx0_sidetone_mix_mux =
	SOC_DAPM_ENUM("WSA_RX0 SIDETONE MIX Mux", rx0_sidetone_mix_enum);

/* RX INT1 */
static const struct soc_enum rx1_prim_inp0_chain_enum =
	SOC_ENUM_SINGLE(CDC_WSA_RX_INP_MUX_RX_INT1_CFG0,
		0, 7, rx_text);

static const struct soc_enum rx1_prim_inp1_chain_enum =
	SOC_ENUM_SINGLE(CDC_WSA_RX_INP_MUX_RX_INT1_CFG0,
		3, 7, rx_text);

static const struct soc_enum rx1_prim_inp2_chain_enum =
	SOC_ENUM_SINGLE(CDC_WSA_RX_INP_MUX_RX_INT1_CFG1,
		3, 7, rx_text);

static const struct soc_enum rx1_mix_chain_enum =
	SOC_ENUM_SINGLE(CDC_WSA_RX_INP_MUX_RX_INT1_CFG1,
		0, 5, rx_mix_text);

static const struct snd_kcontrol_new rx1_prim_inp0_mux =
	SOC_DAPM_ENUM("WSA_RX1 INP0 Mux", rx1_prim_inp0_chain_enum);

static const struct snd_kcontrol_new rx1_prim_inp1_mux =
	SOC_DAPM_ENUM("WSA_RX1 INP1 Mux", rx1_prim_inp1_chain_enum);

static const struct snd_kcontrol_new rx1_prim_inp2_mux =
	SOC_DAPM_ENUM("WSA_RX1 INP2 Mux", rx1_prim_inp2_chain_enum);

static const struct snd_kcontrol_new rx1_mix_mux =
	SOC_DAPM_ENUM("WSA_RX1 MIX Mux", rx1_mix_chain_enum);

static const struct soc_enum rx_mix_ec0_enum =
	SOC_ENUM_SINGLE(CDC_WSA_RX_INP_MUX_RX_MIX_CFG0,
		0, 3, rx_mix_ec_text);

static const struct soc_enum rx_mix_ec1_enum =
	SOC_ENUM_SINGLE(CDC_WSA_RX_INP_MUX_RX_MIX_CFG0,
		3, 3, rx_mix_ec_text);

static const struct snd_kcontrol_new rx_mix_ec0_mux =
	SOC_DAPM_ENUM("WSA RX_MIX EC0_Mux", rx_mix_ec0_enum);

static const struct snd_kcontrol_new rx_mix_ec1_mux =
	SOC_DAPM_ENUM("WSA RX_MIX EC1_Mux", rx_mix_ec1_enum);

static const struct wsa_macro_reg_mask_val wsa_macro_spkr_default[] = {
	{CDC_WSA_COMPANDER0_CTL3, 0x80, 0x80},
	{CDC_WSA_COMPANDER1_CTL3, 0x80, 0x80},
	{CDC_WSA_COMPANDER0_CTL7, 0x01, 0x01},
	{CDC_WSA_COMPANDER1_CTL7, 0x01, 0x01},
	{CDC_WSA_BOOST0_BOOST_CTL, 0x7C, 0x58},
	{CDC_WSA_BOOST1_BOOST_CTL, 0x7C, 0x58},
};

static const struct wsa_macro_reg_mask_val wsa_macro_spkr_mode1[] = {
	{CDC_WSA_COMPANDER0_CTL3, 0x80, 0x00},
	{CDC_WSA_COMPANDER1_CTL3, 0x80, 0x00},
	{CDC_WSA_COMPANDER0_CTL7, 0x01, 0x00},
	{CDC_WSA_COMPANDER1_CTL7, 0x01, 0x00},
	{CDC_WSA_BOOST0_BOOST_CTL, 0x7C, 0x44},
	{CDC_WSA_BOOST1_BOOST_CTL, 0x7C, 0x44},
};

/**
 * wsa_macro_set_spkr_mode - Configures speaker compander and smartboost
 * settings based on speaker mode.
 *
 * @component: codec instance
 * @mode: Indicates speaker configuration mode.
 *
 * Returns 0 on success or -EINVAL on error.
 */
int wsa_macro_set_spkr_mode(struct snd_soc_component *component, int mode)
{
	int i;
	const struct wsa_macro_reg_mask_val *regs;
	int size;
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	switch (mode) {
	case WSA_MACRO_SPKR_MODE_1:
		regs = wsa_macro_spkr_mode1;
		size = ARRAY_SIZE(wsa_macro_spkr_mode1);
		break;
	default:
		regs = wsa_macro_spkr_default;
		size = ARRAY_SIZE(wsa_macro_spkr_default);
		break;
	}

	wsa_priv->spkr_mode = mode;
	for (i = 0; i < size; i++)
		snd_soc_component_update_bits(component, regs[i].reg,
				    regs[i].mask, regs[i].val);
	return 0;
}
EXPORT_SYMBOL(wsa_macro_set_spkr_mode);

static int wsa_macro_set_prim_interpolator_rate(struct snd_soc_dai *dai,
					    u8 int_prim_fs_rate_reg_val,
					    u32 sample_rate)
{
	u8 int_1_mix1_inp;
	u32 j, port;
	u16 int_mux_cfg0, int_mux_cfg1;
	u16 int_fs_reg;
	u8 int_mux_cfg0_val, int_mux_cfg1_val;
	u8 inp0_sel, inp1_sel, inp2_sel;
	struct snd_soc_component *component = dai->component;
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	for_each_set_bit(port, &wsa_priv->active_ch_mask[dai->id],
			 WSA_MACRO_RX_MAX) {
		int_1_mix1_inp = port;
		if ((int_1_mix1_inp < WSA_MACRO_RX0) ||
			(int_1_mix1_inp > WSA_MACRO_RX_MIX1)) {
			dev_err(component->dev,
				"%s: Invalid RX port, Dai ID is %d\n",
				__func__, dai->id);
			return -EINVAL;
		}

		int_mux_cfg0 = CDC_WSA_RX_INP_MUX_RX_INT0_CFG0;

		/*
		 * Loop through all interpolator MUX inputs and find out
		 * to which interpolator input, the cdc_dma rx port
		 * is connected
		 */
		for (j = 0; j < NUM_INTERPOLATORS; j++) {
			int_mux_cfg1 = int_mux_cfg0 + WSA_MACRO_MUX_CFG1_OFFSET;

			int_mux_cfg0_val = snd_soc_component_read(component,
							int_mux_cfg0);
			int_mux_cfg1_val = snd_soc_component_read(component,
							int_mux_cfg1);
			inp0_sel = int_mux_cfg0_val & WSA_MACRO_MUX_INP_MASK1;
			inp1_sel = (int_mux_cfg0_val >>
					WSA_MACRO_MUX_INP_SHFT) &
					WSA_MACRO_MUX_INP_MASK1;
			inp2_sel = (int_mux_cfg1_val >>
					WSA_MACRO_MUX_INP_SHFT) &
					WSA_MACRO_MUX_INP_MASK1;
			if ((inp0_sel == int_1_mix1_inp + INTn_1_INP_SEL_RX0) ||
			    (inp1_sel == int_1_mix1_inp + INTn_1_INP_SEL_RX0) ||
			    (inp2_sel == int_1_mix1_inp + INTn_1_INP_SEL_RX0)) {
				int_fs_reg = CDC_WSA_RX0_RX_PATH_CTL +
					     WSA_MACRO_RX_PATH_OFFSET * j;
				dev_dbg(component->dev,
					"%s: AIF_PB DAI(%d) connected to INT%u_1\n",
					__func__, dai->id, j);
				dev_dbg(component->dev,
					"%s: set INT%u_1 sample rate to %u\n",
					__func__, j, sample_rate);
				/* sample_rate is in Hz */
				snd_soc_component_update_bits(component,
						int_fs_reg,
						WSA_MACRO_FS_RATE_MASK,
						int_prim_fs_rate_reg_val);
			}
			int_mux_cfg0 += WSA_MACRO_MUX_CFG_OFFSET;
		}
	}

	return 0;
}

static int wsa_macro_set_mix_interpolator_rate(struct snd_soc_dai *dai,
					u8 int_mix_fs_rate_reg_val,
					u32 sample_rate)
{
	u8 int_2_inp;
	u32 j, port;
	u16 int_mux_cfg1, int_fs_reg;
	u8 int_mux_cfg1_val;
	struct snd_soc_component *component = dai->component;
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	for_each_set_bit(port, &wsa_priv->active_ch_mask[dai->id],
			 WSA_MACRO_RX_MAX) {
		int_2_inp = port;
		if ((int_2_inp < WSA_MACRO_RX0) ||
			(int_2_inp > WSA_MACRO_RX_MIX1)) {
			dev_err(component->dev,
				"%s: Invalid RX port, Dai ID is %d\n",
				__func__, dai->id);
			return -EINVAL;
		}

		int_mux_cfg1 = CDC_WSA_RX_INP_MUX_RX_INT0_CFG1;
		for (j = 0; j < NUM_INTERPOLATORS; j++) {
			int_mux_cfg1_val = snd_soc_component_read(component,
							int_mux_cfg1) &
							WSA_MACRO_MUX_INP_MASK1;
			if (int_mux_cfg1_val == int_2_inp +
							INTn_2_INP_SEL_RX0) {
				int_fs_reg =
					CDC_WSA_RX0_RX_PATH_MIX_CTL +
					WSA_MACRO_RX_PATH_OFFSET * j;

				dev_dbg(component->dev,
					"%s: AIF_PB DAI(%d) connected to INT%u_2\n",
					__func__, dai->id, j);
				dev_dbg(component->dev,
					"%s: set INT%u_2 sample rate to %u\n",
					__func__, j, sample_rate);
				snd_soc_component_update_bits(component,
						int_fs_reg,
						WSA_MACRO_FS_RATE_MASK,
						int_mix_fs_rate_reg_val);
			}
			int_mux_cfg1 += WSA_MACRO_MUX_CFG_OFFSET;
		}
	}
	return 0;
}

static int wsa_macro_set_interpolator_rate(struct snd_soc_dai *dai,
				       u32 sample_rate)
{
	int rate_val = 0;
	int i, ret;

	/* set mixing path rate */
	for (i = 0; i < ARRAY_SIZE(int_mix_sample_rate_val); i++) {
		if (sample_rate ==
				int_mix_sample_rate_val[i].sample_rate) {
			rate_val =
				int_mix_sample_rate_val[i].rate_val;
			break;
		}
	}
	if ((i == ARRAY_SIZE(int_mix_sample_rate_val)) ||
			(rate_val < 0))
		goto prim_rate;
	ret = wsa_macro_set_mix_interpolator_rate(dai,
			(u8) rate_val, sample_rate);
prim_rate:
	/* set primary path sample rate */
	for (i = 0; i < ARRAY_SIZE(int_prim_sample_rate_val); i++) {
		if (sample_rate ==
				int_prim_sample_rate_val[i].sample_rate) {
			rate_val =
				int_prim_sample_rate_val[i].rate_val;
			break;
		}
	}
	if ((i == ARRAY_SIZE(int_prim_sample_rate_val)) ||
			(rate_val < 0))
		return -EINVAL;
	ret = wsa_macro_set_prim_interpolator_rate(dai,
			(u8) rate_val, sample_rate);
	return ret;
}

static int wsa_macro_hw_params(struct snd_pcm_substream *substream,
			       struct snd_pcm_hw_params *params,
			       struct snd_soc_dai *dai)
{
	struct snd_soc_component *component = dai->component;
	int ret;

	dev_dbg(component->dev,
		"%s: dai_name = %s DAI-ID %x rate %d num_ch %d\n", __func__,
		 dai->name, dai->id, params_rate(params),
		 params_channels(params));

	switch (substream->stream) {
	case SNDRV_PCM_STREAM_PLAYBACK:
		ret = wsa_macro_set_interpolator_rate(dai, params_rate(params));
		if (ret) {
			dev_err(component->dev,
				"%s: cannot set sample rate: %u\n",
				__func__, params_rate(params));
			return ret;
		}
		break;
	case SNDRV_PCM_STREAM_CAPTURE:
	default:
		break;
	}
	return 0;
}

static int wsa_macro_get_channel_map(struct snd_soc_dai *dai,
				unsigned int *tx_num, unsigned int *tx_slot,
				unsigned int *rx_num, unsigned int *rx_slot)
{
	struct snd_soc_component *component = dai->component;
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);
	u16 val = 0, mask = 0, cnt = 0, temp = 0;

	wsa_priv = dev_get_drvdata(component->dev);
	if (!wsa_priv)
		return -EINVAL;

	switch (dai->id) {
	case WSA_MACRO_AIF_VI:
		*tx_slot = wsa_priv->active_ch_mask[dai->id];
		*tx_num = wsa_priv->active_ch_cnt[dai->id];
		break;
	case WSA_MACRO_AIF1_PB:
	case WSA_MACRO_AIF_MIX1_PB:
		for_each_set_bit(temp, &wsa_priv->active_ch_mask[dai->id],
					WSA_MACRO_RX_MAX) {
			mask |= (1 << temp);
			if (++cnt == WSA_MACRO_MAX_DMA_CH_PER_PORT)
				break;
		}
		if (mask & 0x0C)
			mask = mask >> 0x2;
		*rx_slot = mask;
		*rx_num = cnt;
		break;
	case WSA_MACRO_AIF_ECHO:
		val = snd_soc_component_read(component,
			CDC_WSA_RX_INP_MUX_RX_MIX_CFG0);
		if (val & WSA_MACRO_EC_MIX_TX1_MASK) {
			mask |= 0x2;
			cnt++;
		}
		if (val & WSA_MACRO_EC_MIX_TX0_MASK) {
			mask |= 0x1;
			cnt++;
		}
		*tx_slot = mask;
		*tx_num = cnt;
		break;
	default:
		dev_err(component->dev, "%s: Invalid AIF\n", __func__);
		break;
	}
	return 0;
}

static int wsa_macro_digital_mute(struct snd_soc_dai *dai, int mute, int stream)
{
	struct snd_soc_component *component = dai->component;
	uint16_t j = 0, reg = 0, mix_reg = 0, dsm_reg = 0;
	u16 int_mux_cfg0 = 0, int_mux_cfg1 = 0;
	u8 int_mux_cfg0_val = 0, int_mux_cfg1_val = 0;

	if (mute)
		return 0;

	switch (dai->id) {
	case WSA_MACRO_AIF1_PB:
	case WSA_MACRO_AIF_MIX1_PB:
	for (j = 0; j < NUM_INTERPOLATORS; j++) {
		reg = CDC_WSA_RX0_RX_PATH_CTL +
				(j * WSA_MACRO_RX_PATH_OFFSET);
		mix_reg = CDC_WSA_RX0_RX_PATH_MIX_CTL +
				(j * WSA_MACRO_RX_PATH_OFFSET);
		dsm_reg = CDC_WSA_RX0_RX_PATH_CTL +
				(j * WSA_MACRO_RX_PATH_OFFSET) +
				WSA_MACRO_RX_PATH_DSMDEM_OFFSET;
		int_mux_cfg0 = CDC_WSA_RX_INP_MUX_RX_INT0_CFG0 + j * 8;
		int_mux_cfg1 = int_mux_cfg0 + 4;
		int_mux_cfg0_val = snd_soc_component_read(component,
							int_mux_cfg0);
		int_mux_cfg1_val = snd_soc_component_read(component,
							int_mux_cfg1);
		if (snd_soc_component_read(component, dsm_reg) & 0x01) {
			if (int_mux_cfg0_val || (int_mux_cfg1_val & 0x38))
				snd_soc_component_update_bits(component, reg,
							0x20, 0x20);
			if (int_mux_cfg1_val & 0x07) {
				snd_soc_component_update_bits(component, reg,
							0x20, 0x20);
				snd_soc_component_update_bits(component,
						mix_reg, 0x20, 0x20);
			}
		}
	}
		break;
	default:
		break;
	}
	return 0;
}

static struct snd_soc_dai_ops wsa_macro_dai_ops = {
	.hw_params = wsa_macro_hw_params,
	.get_channel_map = wsa_macro_get_channel_map,
	.mute_stream = wsa_macro_digital_mute,
};

static struct snd_soc_dai_driver wsa_macro_dai[] = {
	{
		.name = "wsa_macro_rx1",
		.id = WSA_MACRO_AIF1_PB,
		.playback = {
			.stream_name = "WSA_AIF1 Playback",
			.rates = WSA_MACRO_RX_RATES,
			.formats = WSA_MACRO_RX_FORMATS,
			.rate_max = 384000,
			.rate_min = 8000,
			.channels_min = 1,
			.channels_max = 2,
		},
		.ops = &wsa_macro_dai_ops,
	},
	{
		.name = "wsa_macro_rx_mix",
		.id = WSA_MACRO_AIF_MIX1_PB,
		.playback = {
			.stream_name = "WSA_AIF_MIX1 Playback",
			.rates = WSA_MACRO_RX_MIX_RATES,
			.formats = WSA_MACRO_RX_FORMATS,
			.rate_max = 192000,
			.rate_min = 48000,
			.channels_min = 1,
			.channels_max = 2,
		},
		.ops = &wsa_macro_dai_ops,
	},
	{
		.name = "wsa_macro_vifeedback",
		.id = WSA_MACRO_AIF_VI,
		.capture = {
			.stream_name = "WSA_AIF_VI Capture",
			.rates = SNDRV_PCM_RATE_8000 | SNDRV_PCM_RATE_48000,
			.formats = WSA_MACRO_RX_FORMATS,
			.rate_max = 48000,
			.rate_min = 8000,
			.channels_min = 1,
			.channels_max = 4,
		},
		.ops = &wsa_macro_dai_ops,
	},
	{
		.name = "wsa_macro_echo",
		.id = WSA_MACRO_AIF_ECHO,
		.capture = {
			.stream_name = "WSA_AIF_ECHO Capture",
			.rates = WSA_MACRO_ECHO_RATES,
			.formats = WSA_MACRO_ECHO_FORMATS,
			.rate_max = 48000,
			.rate_min = 8000,
			.channels_min = 1,
			.channels_max = 2,
		},
		.ops = &wsa_macro_dai_ops,
	},
};

static int wsa_clk_rsc_fs_gen_request(struct wsa_macro_priv *wsa_priv)
{
#if 0
	struct regmap *regmap = wsa_priv->va_regmap;

	regmap_update_bits(regmap, 0x0, 0x1, 0x1);
	regmap_update_bits(regmap, 0x4, 0x1, 0x1);
	regmap_update_bits(regmap, 0x80, 0x2, 0x2);
#endif
	return 0;
}

static int wsa_macro_mclk_enable(struct wsa_macro_priv *wsa_priv,
				 bool mclk_enable, bool dapm)
{
	struct regmap *regmap = wsa_priv->regmap;
	int ret = 0;

	if (regmap == NULL) {
		dev_err(wsa_priv->dev, "%s: regmap is NULL\n", __func__);
		return -EINVAL;
	}

	dev_err(wsa_priv->dev, "%s: mclk_enable = %u, dapm = %d clk_users= %d\n",
		__func__, mclk_enable, dapm, wsa_priv->wsa_mclk_users);

	mutex_lock(&wsa_priv->mclk_lock);
	if (mclk_enable) {
		if (wsa_priv->wsa_mclk_users == 0) {
			wsa_clk_rsc_fs_gen_request(wsa_priv);
			regcache_mark_dirty(regmap);
			regcache_sync_region(regmap,
					WSA_START_OFFSET,
					WSA_MAX_OFFSET);
			/* 9.6MHz MCLK, set value 0x00 if other frequency */
			regmap_update_bits(regmap,
				CDC_WSA_TOP_FREQ_MCLK, 0x01, 0x01);
			regmap_update_bits(regmap,
				CDC_WSA_CLK_RST_CTRL_MCLK_CONTROL,
				0x01, 0x01);
			regmap_update_bits(regmap,
				CDC_WSA_CLK_RST_CTRL_FS_CNT_CONTROL,
				0x01, 0x01);
		}
		wsa_priv->wsa_mclk_users++;
	} else {
		if (wsa_priv->wsa_mclk_users <= 0) {
			dev_err(wsa_priv->dev, "%s: clock already disabled\n",
			__func__);
			wsa_priv->wsa_mclk_users = 0;
			goto exit;
		}
		wsa_priv->wsa_mclk_users--;
		if (wsa_priv->wsa_mclk_users == 0) {
			regmap_update_bits(regmap,
				CDC_WSA_CLK_RST_CTRL_FS_CNT_CONTROL,
				0x01, 0x00);
			regmap_update_bits(regmap,
				CDC_WSA_CLK_RST_CTRL_MCLK_CONTROL,
				0x01, 0x00);

			//FIXME CLK UNPREPARE HERE>
		}
	}
exit:
	mutex_unlock(&wsa_priv->mclk_lock);
	return ret;
}

static int wsa_macro_mclk_event(struct snd_soc_dapm_widget *w,
			       struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_component *component =
				snd_soc_dapm_to_component(w->dapm);
	int ret = 0;
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	dev_dbg(component->dev, "%s: event = %d\n", __func__, event);
	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		ret = wsa_macro_mclk_enable(wsa_priv, 1, true);
		if (ret)
			wsa_priv->dapm_mclk_enable = false;
		else
			wsa_priv->dapm_mclk_enable = true;
		break;
	case SND_SOC_DAPM_POST_PMD:
		if (wsa_priv->dapm_mclk_enable)
			wsa_macro_mclk_enable(wsa_priv, 0, true);
		break;
	default:
		dev_err(wsa_priv->dev,
			"%s: invalid DAPM event %d\n", __func__, event);
		ret = -EINVAL;
	}
	return ret;
}

static int wsa_macro_enable_vi_feedback(struct snd_soc_dapm_widget *w,
					struct snd_kcontrol *kcontrol,
					int event)
{
	struct snd_soc_component *component =
			snd_soc_dapm_to_component(w->dapm);
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	switch (event) {
	case SND_SOC_DAPM_POST_PMU:
		if (test_bit(WSA_MACRO_TX0,
			&wsa_priv->active_ch_mask[WSA_MACRO_AIF_VI])) {
			dev_dbg(component->dev, "%s: spkr1 enabled\n", __func__);
			/* Enable V&I sensing */
			snd_soc_component_update_bits(component,
				CDC_WSA_TX0_SPKR_PROT_PATH_CTL,
				0x20, 0x20);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX1_SPKR_PROT_PATH_CTL,
				0x20, 0x20);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX0_SPKR_PROT_PATH_CTL,
				0x0F, 0x00);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX1_SPKR_PROT_PATH_CTL,
				0x0F, 0x00);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX0_SPKR_PROT_PATH_CTL,
				0x10, 0x10);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX1_SPKR_PROT_PATH_CTL,
				0x10, 0x10);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX0_SPKR_PROT_PATH_CTL,
				0x20, 0x00);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX1_SPKR_PROT_PATH_CTL,
				0x20, 0x00);
		}
		if (test_bit(WSA_MACRO_TX1,
			&wsa_priv->active_ch_mask[WSA_MACRO_AIF_VI])) {
			dev_dbg(component->dev, "%s: spkr2 enabled\n", __func__);
			/* Enable V&I sensing */
			snd_soc_component_update_bits(component,
				CDC_WSA_TX2_SPKR_PROT_PATH_CTL,
				0x20, 0x20);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX3_SPKR_PROT_PATH_CTL,
				0x20, 0x20);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX2_SPKR_PROT_PATH_CTL,
				0x0F, 0x00);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX3_SPKR_PROT_PATH_CTL,
				0x0F, 0x00);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX2_SPKR_PROT_PATH_CTL,
				0x10, 0x10);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX3_SPKR_PROT_PATH_CTL,
				0x10, 0x10);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX2_SPKR_PROT_PATH_CTL,
				0x20, 0x00);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX3_SPKR_PROT_PATH_CTL,
				0x20, 0x00);
		}
		break;
	case SND_SOC_DAPM_POST_PMD:
		if (test_bit(WSA_MACRO_TX0,
			&wsa_priv->active_ch_mask[WSA_MACRO_AIF_VI])) {
			/* Disable V&I sensing */
			snd_soc_component_update_bits(component,
				CDC_WSA_TX0_SPKR_PROT_PATH_CTL,
				0x20, 0x20);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX1_SPKR_PROT_PATH_CTL,
				0x20, 0x20);
			dev_dbg(component->dev, "%s: spkr1 disabled\n", __func__);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX0_SPKR_PROT_PATH_CTL,
				0x10, 0x00);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX1_SPKR_PROT_PATH_CTL,
				0x10, 0x00);
		}
		if (test_bit(WSA_MACRO_TX1,
			&wsa_priv->active_ch_mask[WSA_MACRO_AIF_VI])) {
			/* Disable V&I sensing */
			dev_dbg(component->dev, "%s: spkr2 disabled\n", __func__);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX2_SPKR_PROT_PATH_CTL,
				0x20, 0x20);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX3_SPKR_PROT_PATH_CTL,
				0x20, 0x20);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX2_SPKR_PROT_PATH_CTL,
				0x10, 0x00);
			snd_soc_component_update_bits(component,
				CDC_WSA_TX3_SPKR_PROT_PATH_CTL,
				0x10, 0x00);
		}
		break;
	}

	return 0;
}

static int wsa_macro_enable_mix_path(struct snd_soc_dapm_widget *w,
		struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_component *component =
				snd_soc_dapm_to_component(w->dapm);
	u16 gain_reg;
	int offset_val = 0;
	int val = 0;

	dev_dbg(component->dev, "%s %d %s\n", __func__, event, w->name);

	switch (w->reg) {
	case CDC_WSA_RX0_RX_PATH_MIX_CTL:
		gain_reg = CDC_WSA_RX0_RX_VOL_MIX_CTL;
		break;
	case CDC_WSA_RX1_RX_PATH_MIX_CTL:
		gain_reg = CDC_WSA_RX1_RX_VOL_MIX_CTL;
		break;
	default:
		dev_err(component->dev, "%s: No gain register avail for %s\n",
			__func__, w->name);
		return 0;
	}

	switch (event) {
	case SND_SOC_DAPM_POST_PMU:
		val = snd_soc_component_read(component, gain_reg);
		val += offset_val;
		snd_soc_component_write(component, gain_reg, val);
		break;
	case SND_SOC_DAPM_POST_PMD:
		snd_soc_component_update_bits(component,
					w->reg, 0x20, 0x00);
		break;
	}

	return 0;
}

static void wsa_macro_hd2_control(struct snd_soc_component *component,
				  u16 reg, int event)
{
	u16 hd2_scale_reg;
	u16 hd2_enable_reg = 0;

	if (reg == CDC_WSA_RX0_RX_PATH_CTL) {
		hd2_scale_reg = CDC_WSA_RX0_RX_PATH_SEC3;
		hd2_enable_reg = CDC_WSA_RX0_RX_PATH_CFG0;
	}
	if (reg == CDC_WSA_RX1_RX_PATH_CTL) {
		hd2_scale_reg = CDC_WSA_RX1_RX_PATH_SEC3;
		hd2_enable_reg = CDC_WSA_RX1_RX_PATH_CFG0;
	}

	if (hd2_enable_reg && SND_SOC_DAPM_EVENT_ON(event)) {
		snd_soc_component_update_bits(component, hd2_scale_reg,
						0x3C, 0x10);
		snd_soc_component_update_bits(component, hd2_scale_reg,
						0x03, 0x01);
		snd_soc_component_update_bits(component, hd2_enable_reg,
						0x04, 0x04);
	}

	if (hd2_enable_reg && SND_SOC_DAPM_EVENT_OFF(event)) {
		snd_soc_component_update_bits(component, hd2_enable_reg,
						0x04, 0x00);
		snd_soc_component_update_bits(component, hd2_scale_reg,
						0x03, 0x00);
		snd_soc_component_update_bits(component, hd2_scale_reg,
						0x3C, 0x00);
	}
}

static int wsa_macro_enable_swr(struct snd_soc_dapm_widget *w,
		struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_component *component =
				snd_soc_dapm_to_component(w->dapm);
	int ch_cnt;
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		if (!(strnstr(w->name, "RX0", sizeof("WSA_RX0"))) &&
		    !wsa_priv->rx_0_count)
			wsa_priv->rx_0_count++;
		if (!(strnstr(w->name, "RX1", sizeof("WSA_RX1"))) &&
		    !wsa_priv->rx_1_count)
			wsa_priv->rx_1_count++;
		ch_cnt = wsa_priv->rx_0_count + wsa_priv->rx_1_count;

		break;
	case SND_SOC_DAPM_POST_PMD:
		if (!(strnstr(w->name, "RX0", sizeof("WSA_RX0"))) &&
		    wsa_priv->rx_0_count)
			wsa_priv->rx_0_count--;
		if (!(strnstr(w->name, "RX1", sizeof("WSA_RX1"))) &&
		    wsa_priv->rx_1_count)
			wsa_priv->rx_1_count--;
		ch_cnt = wsa_priv->rx_0_count + wsa_priv->rx_1_count;

		break;
	}
	dev_dbg(wsa_priv->dev, "%s: current swr ch cnt: %d\n",
		__func__, wsa_priv->rx_0_count + wsa_priv->rx_1_count);

	return 0;
}

static int wsa_macro_config_compander(struct snd_soc_component *component,
				int comp, int event)
{
	u16 comp_ctl0_reg, rx_path_cfg0_reg;
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	dev_dbg(component->dev, "%s: event %d compander %d, enabled %d\n",
		__func__, event, comp + 1, wsa_priv->comp_enabled[comp]);

	if (!wsa_priv->comp_enabled[comp])
		return 0;

	comp_ctl0_reg = CDC_WSA_COMPANDER0_CTL0 +
					(comp * WSA_MACRO_RX_COMP_OFFSET);
	rx_path_cfg0_reg = CDC_WSA_RX0_RX_PATH_CFG0 +
					(comp * WSA_MACRO_RX_PATH_OFFSET);

	if (SND_SOC_DAPM_EVENT_ON(event)) {
		/* Enable Compander Clock */
		snd_soc_component_update_bits(component, comp_ctl0_reg,
						0x01, 0x01);
		snd_soc_component_update_bits(component, comp_ctl0_reg,
						0x02, 0x02);
		snd_soc_component_update_bits(component, comp_ctl0_reg,
						0x02, 0x00);
		snd_soc_component_update_bits(component, rx_path_cfg0_reg,
						0x02, 0x02);
	}

	if (SND_SOC_DAPM_EVENT_OFF(event)) {
		snd_soc_component_update_bits(component, comp_ctl0_reg,
						0x04, 0x04);
		snd_soc_component_update_bits(component, rx_path_cfg0_reg,
						0x02, 0x00);
		snd_soc_component_update_bits(component, comp_ctl0_reg,
						0x02, 0x02);
		snd_soc_component_update_bits(component, comp_ctl0_reg,
						0x02, 0x00);
		snd_soc_component_update_bits(component, comp_ctl0_reg,
						0x01, 0x00);
		snd_soc_component_update_bits(component, comp_ctl0_reg,
						0x04, 0x00);
	}

	return 0;
}

static void wsa_macro_enable_softclip_clk(struct snd_soc_component *component,
					 struct wsa_macro_priv *wsa_priv,
					 int path,
					 bool enable)
{
	u16 softclip_clk_reg = CDC_WSA_SOFTCLIP0_CRC +
			(path * WSA_MACRO_RX_SOFTCLIP_OFFSET);
	u8 softclip_mux_mask = (1 << path);
	u8 softclip_mux_value = (1 << path);

	dev_dbg(component->dev, "%s: path %d, enable %d\n",
		__func__, path, enable);
	if (enable) {
		if (wsa_priv->softclip_clk_users[path] == 0) {
			snd_soc_component_update_bits(component,
				softclip_clk_reg, 0x01, 0x01);
			snd_soc_component_update_bits(component,
				CDC_WSA_RX_INP_MUX_SOFTCLIP_CFG0,
				softclip_mux_mask, softclip_mux_value);
		}
		wsa_priv->softclip_clk_users[path]++;
	} else {
		wsa_priv->softclip_clk_users[path]--;
		if (wsa_priv->softclip_clk_users[path] == 0) {
			snd_soc_component_update_bits(component,
				softclip_clk_reg, 0x01, 0x00);
			snd_soc_component_update_bits(component,
				CDC_WSA_RX_INP_MUX_SOFTCLIP_CFG0,
				softclip_mux_mask, 0x00);
		}
	}
}

static int wsa_macro_config_softclip(struct snd_soc_component *component,
				int path, int event)
{
	u16 softclip_ctrl_reg = 0;
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);
	int softclip_path = 0;

	if (path == WSA_MACRO_COMP1)
		softclip_path = WSA_MACRO_SOFTCLIP0;
	else if (path == WSA_MACRO_COMP2)
		softclip_path = WSA_MACRO_SOFTCLIP1;

	dev_dbg(component->dev, "%s: event %d path %d, enabled %d\n",
		__func__, event, softclip_path,
		wsa_priv->is_softclip_on[softclip_path]);

	if (!wsa_priv->is_softclip_on[softclip_path])
		return 0;

	softclip_ctrl_reg = CDC_WSA_SOFTCLIP0_SOFTCLIP_CTRL +
				(softclip_path * WSA_MACRO_RX_SOFTCLIP_OFFSET);

	if (SND_SOC_DAPM_EVENT_ON(event)) {
		/* Enable Softclip clock and mux */
		wsa_macro_enable_softclip_clk(component, wsa_priv,
				softclip_path, true);
		/* Enable Softclip control */
		snd_soc_component_update_bits(component, softclip_ctrl_reg,
				0x01, 0x01);
	}

	if (SND_SOC_DAPM_EVENT_OFF(event)) {
		snd_soc_component_update_bits(component, softclip_ctrl_reg,
				0x01, 0x00);
		wsa_macro_enable_softclip_clk(component, wsa_priv,
				softclip_path, false);
	}

	return 0;
}

static bool wsa_macro_adie_lb(struct snd_soc_component *component,
			      int interp_idx)
{
	u16 int_mux_cfg0 = 0, int_mux_cfg1 = 0;
	u8 int_mux_cfg0_val = 0, int_mux_cfg1_val = 0;
	u8 int_n_inp0 = 0, int_n_inp1 = 0, int_n_inp2 = 0;

	int_mux_cfg0 = CDC_WSA_RX_INP_MUX_RX_INT0_CFG0 + interp_idx * 8;
	int_mux_cfg1 = int_mux_cfg0 + 4;
	int_mux_cfg0_val = snd_soc_component_read(component, int_mux_cfg0);
	int_mux_cfg1_val = snd_soc_component_read(component, int_mux_cfg1);

	int_n_inp0 = int_mux_cfg0_val & 0x0F;
	if (int_n_inp0 == INTn_1_INP_SEL_DEC0 ||
		int_n_inp0 == INTn_1_INP_SEL_DEC1)
		return true;

	int_n_inp1 = int_mux_cfg0_val >> 4;
	if (int_n_inp1 == INTn_1_INP_SEL_DEC0 ||
		int_n_inp1 == INTn_1_INP_SEL_DEC1)
		return true;

	int_n_inp2 = int_mux_cfg1_val >> 4;
	if (int_n_inp2 == INTn_1_INP_SEL_DEC0 ||
		int_n_inp2 == INTn_1_INP_SEL_DEC1)
		return true;

	return false;
}

static int wsa_macro_enable_main_path(struct snd_soc_dapm_widget *w,
				      struct snd_kcontrol *kcontrol,
				      int event)
{
	struct snd_soc_component *component =
				snd_soc_dapm_to_component(w->dapm);
	u16 reg = 0;


	reg = CDC_WSA_RX0_RX_PATH_CTL +
			WSA_MACRO_RX_PATH_OFFSET * w->shift;
	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		if (wsa_macro_adie_lb(component, w->shift)) {
			snd_soc_component_update_bits(component,
						reg, 0x20, 0x20);
		}
		break;
	default:
		break;
	}
	return 0;
}

static int wsa_macro_interp_get_primary_reg(u16 reg, u16 *ind)
{
	u16 prim_int_reg = 0;

	switch (reg) {
	case CDC_WSA_RX0_RX_PATH_CTL:
	case CDC_WSA_RX0_RX_PATH_MIX_CTL:
		prim_int_reg = CDC_WSA_RX0_RX_PATH_CTL;
		*ind = 0;
		break;
	case CDC_WSA_RX1_RX_PATH_CTL:
	case CDC_WSA_RX1_RX_PATH_MIX_CTL:
		prim_int_reg = CDC_WSA_RX1_RX_PATH_CTL;
		*ind = 1;
		break;
	}

	return prim_int_reg;
}

static int wsa_macro_enable_prim_interpolator(
				struct snd_soc_component *component,
				u16 reg, int event)
{
	u16 prim_int_reg;
	u16 ind = 0;
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	prim_int_reg = wsa_macro_interp_get_primary_reg(reg, &ind);

	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		wsa_priv->prim_int_users[ind]++;
		if (wsa_priv->prim_int_users[ind] == 1) {
			snd_soc_component_update_bits(component,
				prim_int_reg + WSA_MACRO_RX_PATH_CFG3_OFFSET,
				0x03, 0x03);
			snd_soc_component_update_bits(component, prim_int_reg,
					    0x10, 0x10);
			wsa_macro_hd2_control(component, prim_int_reg, event);
			snd_soc_component_update_bits(component,
				prim_int_reg + WSA_MACRO_RX_PATH_DSMDEM_OFFSET,
				0x1, 0x1);
		}
		if ((reg != prim_int_reg) &&
		    ((snd_soc_component_read(
				component, prim_int_reg)) & 0x10))
			snd_soc_component_update_bits(component, reg,
					0x10, 0x10);
		break;
	case SND_SOC_DAPM_POST_PMD:
		wsa_priv->prim_int_users[ind]--;
		if (wsa_priv->prim_int_users[ind] == 0) {
			snd_soc_component_update_bits(component, prim_int_reg,
					1 << 0x5, 0 << 0x5);
			snd_soc_component_update_bits(component,
				prim_int_reg + WSA_MACRO_RX_PATH_DSMDEM_OFFSET,
				0x1, 0x0);
			snd_soc_component_update_bits(component, prim_int_reg,
					0x40, 0x40);
			snd_soc_component_update_bits(component, prim_int_reg,
					0x40, 0x00);
			wsa_macro_hd2_control(component, prim_int_reg, event);
		}
		break;
	}

	dev_dbg(component->dev, "%s: primary interpolator: INT%d, users: %d\n",
		__func__, ind, wsa_priv->prim_int_users[ind]);
	return 0;
}

static int wsa_macro_enable_interpolator(struct snd_soc_dapm_widget *w,
					 struct snd_kcontrol *kcontrol,
					 int event)
{
	struct snd_soc_component *component =
			snd_soc_dapm_to_component(w->dapm);
	u16 gain_reg;
	u16 reg;
	int val;
	int offset_val = 0;
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	dev_dbg(component->dev, "%s %d %s\n", __func__, event, w->name);

	if (!(strcmp(w->name, "WSA_RX INT0 INTERP"))) {
		reg = CDC_WSA_RX0_RX_PATH_CTL;
		gain_reg = CDC_WSA_RX0_RX_VOL_CTL;
	} else if (!(strcmp(w->name, "WSA_RX INT1 INTERP"))) {
		reg = CDC_WSA_RX1_RX_PATH_CTL;
		gain_reg = CDC_WSA_RX1_RX_VOL_CTL;
	} else {
		dev_err(component->dev, "%s: Interpolator reg not found\n",
			__func__);
		return -EINVAL;
	}

	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		/* Reset if needed */
		wsa_macro_enable_prim_interpolator(component, reg, event);
		break;
	case SND_SOC_DAPM_POST_PMU:
		wsa_macro_config_compander(component, w->shift, event);
		wsa_macro_config_softclip(component, w->shift, event);
		/* apply gain after int clk is enabled */
		if ((wsa_priv->spkr_gain_offset ==
			WSA_MACRO_GAIN_OFFSET_M1P5_DB) &&
		    (wsa_priv->comp_enabled[WSA_MACRO_COMP1] ||
		     wsa_priv->comp_enabled[WSA_MACRO_COMP2]) &&
		    (gain_reg == CDC_WSA_RX0_RX_VOL_CTL ||
		     gain_reg == CDC_WSA_RX1_RX_VOL_CTL)) {
			snd_soc_component_update_bits(component,
					CDC_WSA_RX0_RX_PATH_SEC1,
					0x01, 0x01);
			snd_soc_component_update_bits(component,
					CDC_WSA_RX0_RX_PATH_MIX_SEC0,
					0x01, 0x01);
			snd_soc_component_update_bits(component,
					CDC_WSA_RX1_RX_PATH_SEC1,
					0x01, 0x01);
			snd_soc_component_update_bits(component,
					CDC_WSA_RX1_RX_PATH_MIX_SEC0,
					0x01, 0x01);
			offset_val = -2;
		}
		val = snd_soc_component_read(component, gain_reg);
		val += offset_val;
		snd_soc_component_write(component, gain_reg, val);
		wsa_macro_config_ear_spkr_gain(component, wsa_priv,
						event, gain_reg);
		break;
	case SND_SOC_DAPM_POST_PMD:
		wsa_macro_config_compander(component, w->shift, event);
		wsa_macro_config_softclip(component, w->shift, event);
		wsa_macro_enable_prim_interpolator(component, reg, event);
		if ((wsa_priv->spkr_gain_offset ==
			WSA_MACRO_GAIN_OFFSET_M1P5_DB) &&
		    (wsa_priv->comp_enabled[WSA_MACRO_COMP1] ||
		     wsa_priv->comp_enabled[WSA_MACRO_COMP2]) &&
		    (gain_reg == CDC_WSA_RX0_RX_VOL_CTL ||
		     gain_reg == CDC_WSA_RX1_RX_VOL_CTL)) {
			snd_soc_component_update_bits(component,
					CDC_WSA_RX0_RX_PATH_SEC1,
					0x01, 0x00);
			snd_soc_component_update_bits(component,
					CDC_WSA_RX0_RX_PATH_MIX_SEC0,
					0x01, 0x00);
			snd_soc_component_update_bits(component,
					CDC_WSA_RX1_RX_PATH_SEC1,
					0x01, 0x00);
			snd_soc_component_update_bits(component,
					CDC_WSA_RX1_RX_PATH_MIX_SEC0,
					0x01, 0x00);
			offset_val = 2;
			val = snd_soc_component_read(component, gain_reg);
			val += offset_val;
			snd_soc_component_write(component, gain_reg, val);
		}
		wsa_macro_config_ear_spkr_gain(component, wsa_priv,
						event, gain_reg);
		break;
	}

	return 0;
}

static int wsa_macro_config_ear_spkr_gain(struct snd_soc_component *component,
					struct wsa_macro_priv *wsa_priv,
					int event, int gain_reg)
{
	int comp_gain_offset, val;

	switch (wsa_priv->spkr_mode) {
	/* Compander gain in WSA_MACRO_SPKR_MODE1 case is 12 dB */
	case WSA_MACRO_SPKR_MODE_1:
		comp_gain_offset = -12;
		break;
	/* Default case compander gain is 15 dB */
	default:
		comp_gain_offset = -15;
		break;
	}

	switch (event) {
	case SND_SOC_DAPM_POST_PMU:
		/* Apply ear spkr gain only if compander is enabled */
		if (wsa_priv->comp_enabled[WSA_MACRO_COMP1] &&
		    (gain_reg == CDC_WSA_RX0_RX_VOL_CTL) &&
		    (wsa_priv->ear_spkr_gain != 0)) {
			/* For example, val is -8(-12+5-1) for 4dB of gain */
			val = comp_gain_offset + wsa_priv->ear_spkr_gain - 1;
			snd_soc_component_write(component, gain_reg, val);

			dev_dbg(wsa_priv->dev, "%s: RX0 Volume %d dB\n",
				__func__, val);
		}
		break;
	case SND_SOC_DAPM_POST_PMD:
		/*
		 * Reset RX0 volume to 0 dB if compander is enabled and
		 * ear_spkr_gain is non-zero.
		 */
		if (wsa_priv->comp_enabled[WSA_MACRO_COMP1] &&
		    (gain_reg == CDC_WSA_RX0_RX_VOL_CTL) &&
		    (wsa_priv->ear_spkr_gain != 0)) {
			snd_soc_component_write(component, gain_reg, 0x0);

			dev_dbg(wsa_priv->dev, "%s: Reset RX0 Volume to 0 dB\n",
				__func__);
		}
		break;
	}

	return 0;
}

static int wsa_macro_spk_boost_event(struct snd_soc_dapm_widget *w,
				     struct snd_kcontrol *kcontrol,
				     int event)
{
	struct snd_soc_component *component =
				snd_soc_dapm_to_component(w->dapm);
	u16 boost_path_ctl, boost_path_cfg1;
	u16 reg, reg_mix;

	dev_dbg(component->dev, "%s %s %d\n", __func__, w->name, event);

	if (!strcmp(w->name, "WSA_RX INT0 CHAIN")) {
		boost_path_ctl = CDC_WSA_BOOST0_BOOST_PATH_CTL;
		boost_path_cfg1 = CDC_WSA_RX0_RX_PATH_CFG1;
		reg = CDC_WSA_RX0_RX_PATH_CTL;
		reg_mix = CDC_WSA_RX0_RX_PATH_MIX_CTL;
	} else if (!strcmp(w->name, "WSA_RX INT1 CHAIN")) {
		boost_path_ctl = CDC_WSA_BOOST1_BOOST_PATH_CTL;
		boost_path_cfg1 = CDC_WSA_RX1_RX_PATH_CFG1;
		reg = CDC_WSA_RX1_RX_PATH_CTL;
		reg_mix = CDC_WSA_RX1_RX_PATH_MIX_CTL;
	} else {
		dev_err(component->dev, "%s: unknown widget: %s\n",
			__func__, w->name);
		return -EINVAL;
	}

	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		snd_soc_component_update_bits(component, boost_path_cfg1,
						0x01, 0x01);
		snd_soc_component_update_bits(component, boost_path_ctl,
						0x10, 0x10);
		if ((snd_soc_component_read(component, reg_mix)) & 0x10)
			snd_soc_component_update_bits(component, reg_mix,
						0x10, 0x00);
		break;
	case SND_SOC_DAPM_POST_PMU:
		snd_soc_component_update_bits(component, reg, 0x10, 0x00);
		break;
	case SND_SOC_DAPM_POST_PMD:
		snd_soc_component_update_bits(component, boost_path_ctl,
						0x10, 0x00);
		snd_soc_component_update_bits(component, boost_path_cfg1,
						0x01, 0x00);
		break;
	}

	return 0;
}


static int wsa_macro_enable_vbat(struct snd_soc_dapm_widget *w,
				 struct snd_kcontrol *kcontrol,
				 int event)
{
	struct snd_soc_component *component =
			snd_soc_dapm_to_component(w->dapm);
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);
	u16 vbat_path_cfg = 0;
	int softclip_path = 0;

	dev_dbg(component->dev, "%s %s %d\n", __func__, w->name, event);
	if (!strcmp(w->name, "WSA_RX INT0 VBAT")) {
		vbat_path_cfg = CDC_WSA_RX0_RX_PATH_CFG1;
		softclip_path = WSA_MACRO_SOFTCLIP0;
	} else if (!strcmp(w->name, "WSA_RX INT1 VBAT")) {
		vbat_path_cfg = CDC_WSA_RX1_RX_PATH_CFG1;
		softclip_path = WSA_MACRO_SOFTCLIP1;
	}

	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		/* Enable clock for VBAT block */
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_PATH_CTL, 0x10, 0x10);
		/* Enable VBAT block */
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_CFG, 0x01, 0x01);
		/* Update interpolator with 384K path */
		snd_soc_component_update_bits(component, vbat_path_cfg,
			0x80, 0x80);
		/* Use attenuation mode */
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_CFG, 0x02, 0x00);
		/*
		 * BCL block needs softclip clock and mux config to be enabled
		 */
		wsa_macro_enable_softclip_clk(component, wsa_priv,
					softclip_path, true);
		/* Enable VBAT at channel level */
		snd_soc_component_update_bits(component, vbat_path_cfg,
				0x02, 0x02);
		/* Set the ATTK1 gain */
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD1,
			0xFF, 0xFF);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD2,
			0xFF, 0x03);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD3,
			0xFF, 0x00);
		/* Set the ATTK2 gain */
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD4,
			0xFF, 0xFF);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD5,
			0xFF, 0x03);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD6,
			0xFF, 0x00);
		/* Set the ATTK3 gain */
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD7,
			0xFF, 0xFF);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD8,
			0xFF, 0x03);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD9,
			0xFF, 0x00);
		break;

	case SND_SOC_DAPM_POST_PMD:
		snd_soc_component_update_bits(component, vbat_path_cfg,
			0x80, 0x00);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_CFG,
			0x02, 0x02);
		snd_soc_component_update_bits(component, vbat_path_cfg,
			0x02, 0x00);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD1,
			0xFF, 0x00);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD2,
			0xFF, 0x00);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD3,
			0xFF, 0x00);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD4,
			0xFF, 0x00);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD5,
			0xFF, 0x00);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD6,
			0xFF, 0x00);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD7,
			0xFF, 0x00);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD8,
			0xFF, 0x00);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_BCL_GAIN_UPD9,
			0xFF, 0x00);
		wsa_macro_enable_softclip_clk(component, wsa_priv,
			softclip_path, false);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_CFG, 0x01, 0x00);
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_PATH_CTL, 0x10, 0x00);
		break;
	default:
		dev_err(component->dev, "%s: Invalid event %d\n", __func__, event);
		break;
	}
	return 0;
}

static int wsa_macro_enable_echo(struct snd_soc_dapm_widget *w,
				 struct snd_kcontrol *kcontrol,
				 int event)
{
	struct snd_soc_component *component =
				snd_soc_dapm_to_component(w->dapm);
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);
	u16 val, ec_tx = 0, ec_hq_reg;

	dev_dbg(component->dev, "%s %d %s\n", __func__, event, w->name);

	val = snd_soc_component_read(component,
				CDC_WSA_RX_INP_MUX_RX_MIX_CFG0);
	if (!(strcmp(w->name, "WSA RX_MIX EC0_MUX")))
		ec_tx = (val & 0x07) - 1;
	else
		ec_tx = ((val & 0x38) >> 0x3) - 1;

	if (ec_tx < 0 || ec_tx >= (WSA_MACRO_RX1 + 1)) {
		dev_err(component->dev, "%s: EC mix control not set correctly\n",
			__func__);
		return -EINVAL;
	}
	if (wsa_priv->ec_hq[ec_tx]) {
		snd_soc_component_update_bits(component,
				CDC_WSA_RX_INP_MUX_RX_MIX_CFG0,
				0x1 << ec_tx, 0x1 << ec_tx);
		ec_hq_reg = CDC_WSA_EC_HQ0_EC_REF_HQ_PATH_CTL +
							0x40 * ec_tx;
		snd_soc_component_update_bits(component, ec_hq_reg, 0x01, 0x01);
		ec_hq_reg = CDC_WSA_EC_HQ0_EC_REF_HQ_CFG0 +
							0x40 * ec_tx;
		/* default set to 48k */
		snd_soc_component_update_bits(component, ec_hq_reg, 0x1E, 0x08);
	}

	return 0;
}

static int wsa_macro_get_ec_hq(struct snd_kcontrol *kcontrol,
			       struct snd_ctl_elem_value *ucontrol)
{

	struct snd_soc_component *component =
				snd_soc_kcontrol_component(kcontrol);
	int ec_tx = ((struct soc_mixer_control *)
		    kcontrol->private_value)->shift;
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	ucontrol->value.integer.value[0] = wsa_priv->ec_hq[ec_tx];
	return 0;
}

static int wsa_macro_set_ec_hq(struct snd_kcontrol *kcontrol,
			       struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component =
				snd_soc_kcontrol_component(kcontrol);
	int ec_tx = ((struct soc_mixer_control *)
		    kcontrol->private_value)->shift;
	int value = ucontrol->value.integer.value[0];
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	dev_dbg(component->dev, "%s: enable current %d, new %d\n",
		__func__, wsa_priv->ec_hq[ec_tx], value);
	wsa_priv->ec_hq[ec_tx] = value;

	return 0;
}

static int wsa_macro_get_rx_mute_status(struct snd_kcontrol *kcontrol,
			       struct snd_ctl_elem_value *ucontrol)
{

	struct snd_soc_component *component =
				snd_soc_kcontrol_component(kcontrol);
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);
	int wsa_rx_shift = ((struct soc_mixer_control *)
		       kcontrol->private_value)->shift;

	ucontrol->value.integer.value[0] =
		wsa_priv->wsa_digital_mute_status[wsa_rx_shift];
	return 0;
}

static int wsa_macro_set_rx_mute_status(struct snd_kcontrol *kcontrol,
			       struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component =
				snd_soc_kcontrol_component(kcontrol);
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);
	int value = ucontrol->value.integer.value[0];
	int wsa_rx_shift = ((struct soc_mixer_control *)
			kcontrol->private_value)->shift;


	switch (wsa_rx_shift) {
	case 0:
		snd_soc_component_update_bits(component,
				CDC_WSA_RX0_RX_PATH_CTL,
				0x10, value << 4);
		break;
	case 1:
		snd_soc_component_update_bits(component,
				CDC_WSA_RX1_RX_PATH_CTL,
				0x10, value << 4);
		break;
	case 2:
		snd_soc_component_update_bits(component,
				CDC_WSA_RX0_RX_PATH_MIX_CTL,
				0x10, value << 4);
		break;
	case 3:
		snd_soc_component_update_bits(component,
				CDC_WSA_RX1_RX_PATH_MIX_CTL,
				0x10, value << 4);
		break;
	default:
		pr_err("%s: invalid argument rx_shift = %d\n", __func__,
			wsa_rx_shift);
		return -EINVAL;
	}

	dev_dbg(component->dev, "%s: WSA Digital Mute RX %d Enable %d\n",
		__func__, wsa_rx_shift, value);
	wsa_priv->wsa_digital_mute_status[wsa_rx_shift] = value;
	return 0;
}

static int wsa_macro_get_compander(struct snd_kcontrol *kcontrol,
			       struct snd_ctl_elem_value *ucontrol)
{

	struct snd_soc_component *component =
				snd_soc_kcontrol_component(kcontrol);
	int comp = ((struct soc_mixer_control *)
		    kcontrol->private_value)->shift;
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	ucontrol->value.integer.value[0] = wsa_priv->comp_enabled[comp];
	return 0;
}

static int wsa_macro_set_compander(struct snd_kcontrol *kcontrol,
			       struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component =
				snd_soc_kcontrol_component(kcontrol);
	int comp = ((struct soc_mixer_control *)
		    kcontrol->private_value)->shift;
	int value = ucontrol->value.integer.value[0];
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);


	dev_dbg(component->dev, "%s: Compander %d enable current %d, new %d\n",
		__func__, comp + 1, wsa_priv->comp_enabled[comp], value);
	wsa_priv->comp_enabled[comp] = value;

	return 0;
}

static int wsa_macro_ear_spkr_pa_gain_get(struct snd_kcontrol *kcontrol,
					struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component =
				snd_soc_kcontrol_component(kcontrol);
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	ucontrol->value.integer.value[0] = wsa_priv->ear_spkr_gain;

	dev_dbg(component->dev, "%s: ucontrol->value.integer.value[0] = %ld\n",
		__func__, ucontrol->value.integer.value[0]);

	return 0;
}

static int wsa_macro_ear_spkr_pa_gain_put(struct snd_kcontrol *kcontrol,
					struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component =
				snd_soc_kcontrol_component(kcontrol);
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	wsa_priv->ear_spkr_gain =  ucontrol->value.integer.value[0];

	dev_dbg(component->dev, "%s: gain = %d\n", __func__,
		wsa_priv->ear_spkr_gain);

	return 0;
}

static int wsa_macro_spkr_left_boost_stage_get(struct snd_kcontrol *kcontrol,
			struct snd_ctl_elem_value *ucontrol)
{
	u8 bst_state_max = 0;
	struct snd_soc_component *component =
				snd_soc_kcontrol_component(kcontrol);

	bst_state_max = snd_soc_component_read(component,
				CDC_WSA_BOOST0_BOOST_CTL);
	bst_state_max = (bst_state_max & 0x0c) >> 2;
	ucontrol->value.integer.value[0] = bst_state_max;
	dev_dbg(component->dev, "%s: ucontrol->value.integer.value[0]  = %ld\n",
		__func__, ucontrol->value.integer.value[0]);

	return 0;
}

static int wsa_macro_spkr_left_boost_stage_put(struct snd_kcontrol *kcontrol,
			struct snd_ctl_elem_value *ucontrol)
{
	u8 bst_state_max;
	struct snd_soc_component *component =
				snd_soc_kcontrol_component(kcontrol);

	dev_dbg(component->dev, "%s: ucontrol->value.integer.value[0]  = %ld\n",
		__func__, ucontrol->value.integer.value[0]);
	bst_state_max =  ucontrol->value.integer.value[0] << 2;
	/* wsa does not need to limit the boost levels */

	return 0;
}

static int wsa_macro_spkr_right_boost_stage_get(struct snd_kcontrol *kcontrol,
			struct snd_ctl_elem_value *ucontrol)
{
	u8 bst_state_max = 0;
	struct snd_soc_component *component =
				snd_soc_kcontrol_component(kcontrol);

	bst_state_max = snd_soc_component_read(component,
				CDC_WSA_BOOST1_BOOST_CTL);
	bst_state_max = (bst_state_max & 0x0c) >> 2;
	ucontrol->value.integer.value[0] = bst_state_max;
	dev_dbg(component->dev, "%s: ucontrol->value.integer.value[0]  = %ld\n",
		__func__, ucontrol->value.integer.value[0]);

	return 0;
}

static int wsa_macro_spkr_right_boost_stage_put(struct snd_kcontrol *kcontrol,
					struct snd_ctl_elem_value *ucontrol)
{
	u8 bst_state_max;
	struct snd_soc_component *component =
				snd_soc_kcontrol_component(kcontrol);

	dev_dbg(component->dev, "%s: ucontrol->value.integer.value[0]  = %ld\n",
		__func__, ucontrol->value.integer.value[0]);
	bst_state_max =  ucontrol->value.integer.value[0] << 2;
	/* wsa does not need to limit the boost levels */

	return 0;
}

static int wsa_macro_rx_mux_get(struct snd_kcontrol *kcontrol,
			  struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_dapm_widget *widget =
		snd_soc_dapm_kcontrol_widget(kcontrol);
	struct snd_soc_component *component =
				snd_soc_dapm_to_component(widget->dapm);
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	ucontrol->value.integer.value[0] =
			wsa_priv->rx_port_value[widget->shift];
	return 0;
}

static int wsa_macro_rx_mux_put(struct snd_kcontrol *kcontrol,
			  struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_dapm_widget *widget =
		snd_soc_dapm_kcontrol_widget(kcontrol);
	struct snd_soc_component *component =
				snd_soc_dapm_to_component(widget->dapm);
	struct soc_enum *e = (struct soc_enum *)kcontrol->private_value;
	struct snd_soc_dapm_update *update = NULL;
	u32 rx_port_value = ucontrol->value.integer.value[0];
	u32 bit_input = 0;
	u32 aif_rst;
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	aif_rst = wsa_priv->rx_port_value[widget->shift];
	if (!rx_port_value) {
		if (aif_rst == 0) {
			dev_err(component->dev, "%s: AIF reset already\n", __func__);
			return 0;
		}
		if (aif_rst >= WSA_MACRO_RX_MAX) {
			dev_err(component->dev, "%s: Invalid AIF reset\n", __func__);
			return 0;
		}
	}
	wsa_priv->rx_port_value[widget->shift] = rx_port_value;

	bit_input = widget->shift;

	dev_dbg(component->dev,
		"%s: mux input: %d, mux output: %d, bit: %d\n",
		__func__, rx_port_value, widget->shift, bit_input);

	switch (rx_port_value) {
	case 0:
		if (wsa_priv->active_ch_cnt[aif_rst]) {
			clear_bit(bit_input,
				  &wsa_priv->active_ch_mask[aif_rst]);
			wsa_priv->active_ch_cnt[aif_rst]--;
		}
		break;
	case 1:
	case 2:
		set_bit(bit_input,
			&wsa_priv->active_ch_mask[rx_port_value]);
		wsa_priv->active_ch_cnt[rx_port_value]++;
		break;
	default:
		dev_err(component->dev,
			"%s: Invalid AIF_ID for WSA RX MUX %d\n",
			__func__, rx_port_value);
		return -EINVAL;
	}

	snd_soc_dapm_mux_update_power(widget->dapm, kcontrol,
					rx_port_value, e, update);
	return 0;
}

static int wsa_macro_vbat_bcl_gsm_mode_func_get(struct snd_kcontrol *kcontrol,
					struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component =
			snd_soc_kcontrol_component(kcontrol);

	ucontrol->value.integer.value[0] =
	    ((snd_soc_component_read(
		component, CDC_WSA_VBAT_BCL_VBAT_CFG) & 0x04) ?
	    1 : 0);

	dev_dbg(component->dev, "%s: value: %lu\n", __func__,
		ucontrol->value.integer.value[0]);

	return 0;
}

static int wsa_macro_vbat_bcl_gsm_mode_func_put(struct snd_kcontrol *kcontrol,
					struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component =
			snd_soc_kcontrol_component(kcontrol);

	dev_dbg(component->dev, "%s: value: %lu\n", __func__,
		ucontrol->value.integer.value[0]);

	/* Set Vbat register configuration for GSM mode bit based on value */
	if (ucontrol->value.integer.value[0])
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_CFG,
			0x04, 0x04);
	else
		snd_soc_component_update_bits(component,
			CDC_WSA_VBAT_BCL_VBAT_CFG,
			0x04, 0x00);

	return 0;
}

static int wsa_macro_soft_clip_enable_get(struct snd_kcontrol *kcontrol,
					  struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component =
			snd_soc_kcontrol_component(kcontrol);
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);
	int path = ((struct soc_mixer_control *)
		    kcontrol->private_value)->shift;


	ucontrol->value.integer.value[0] = wsa_priv->is_softclip_on[path];

	dev_dbg(component->dev, "%s: ucontrol->value.integer.value[0] = %ld\n",
		__func__, ucontrol->value.integer.value[0]);

	return 0;
}

static int wsa_macro_soft_clip_enable_put(struct snd_kcontrol *kcontrol,
					  struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component =
			snd_soc_kcontrol_component(kcontrol);
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);
	int path = ((struct soc_mixer_control *)
		    kcontrol->private_value)->shift;

	wsa_priv->is_softclip_on[path] =  ucontrol->value.integer.value[0];

	dev_dbg(component->dev, "%s: soft clip enable for %d: %d\n", __func__,
		path, wsa_priv->is_softclip_on[path]);

	return 0;
}

static const struct snd_kcontrol_new wsa_macro_snd_controls[] = {
	SOC_ENUM_EXT("EAR SPKR PA Gain", wsa_macro_ear_spkr_pa_gain_enum,
		     wsa_macro_ear_spkr_pa_gain_get,
		     wsa_macro_ear_spkr_pa_gain_put),
	SOC_ENUM_EXT("SPKR Left Boost Max State",
		wsa_macro_spkr_boost_stage_enum,
		wsa_macro_spkr_left_boost_stage_get,
		wsa_macro_spkr_left_boost_stage_put),
	SOC_ENUM_EXT("SPKR Right Boost Max State",
		wsa_macro_spkr_boost_stage_enum,
		wsa_macro_spkr_right_boost_stage_get,
		wsa_macro_spkr_right_boost_stage_put),
	SOC_ENUM_EXT("GSM mode Enable", wsa_macro_vbat_bcl_gsm_mode_enum,
		     wsa_macro_vbat_bcl_gsm_mode_func_get,
		     wsa_macro_vbat_bcl_gsm_mode_func_put),
	SOC_SINGLE_EXT("WSA_Softclip0 Enable", SND_SOC_NOPM,
			WSA_MACRO_SOFTCLIP0, 1, 0,
			wsa_macro_soft_clip_enable_get,
			wsa_macro_soft_clip_enable_put),
	SOC_SINGLE_EXT("WSA_Softclip1 Enable", SND_SOC_NOPM,
			WSA_MACRO_SOFTCLIP1, 1, 0,
			wsa_macro_soft_clip_enable_get,
			wsa_macro_soft_clip_enable_put),
	SOC_SINGLE_S8_TLV("WSA_RX0 Digital Volume",
			  CDC_WSA_RX0_RX_VOL_CTL,
			  -84, 40, digital_gain),
	SOC_SINGLE_S8_TLV("WSA_RX1 Digital Volume",
			  CDC_WSA_RX1_RX_VOL_CTL,
			  -84, 40, digital_gain),
	SOC_SINGLE_EXT("WSA_RX0 Digital Mute", SND_SOC_NOPM, WSA_MACRO_RX0, 1,
			0, wsa_macro_get_rx_mute_status,
			wsa_macro_set_rx_mute_status),
	SOC_SINGLE_EXT("WSA_RX1 Digital Mute", SND_SOC_NOPM, WSA_MACRO_RX1, 1,
			0, wsa_macro_get_rx_mute_status,
			wsa_macro_set_rx_mute_status),
	SOC_SINGLE_EXT("WSA_RX0_MIX Digital Mute", SND_SOC_NOPM,
			WSA_MACRO_RX_MIX0, 1, 0, wsa_macro_get_rx_mute_status,
			wsa_macro_set_rx_mute_status),
	SOC_SINGLE_EXT("WSA_RX1_MIX Digital Mute", SND_SOC_NOPM,
			WSA_MACRO_RX_MIX1, 1, 0, wsa_macro_get_rx_mute_status,
			wsa_macro_set_rx_mute_status),
	SOC_SINGLE_EXT("WSA_COMP1 Switch", SND_SOC_NOPM, WSA_MACRO_COMP1, 1, 0,
		wsa_macro_get_compander, wsa_macro_set_compander),
	SOC_SINGLE_EXT("WSA_COMP2 Switch", SND_SOC_NOPM, WSA_MACRO_COMP2, 1, 0,
		wsa_macro_get_compander, wsa_macro_set_compander),
	SOC_SINGLE_EXT("WSA_RX0 EC_HQ Switch", SND_SOC_NOPM, WSA_MACRO_RX0,
			1, 0, wsa_macro_get_ec_hq, wsa_macro_set_ec_hq),
	SOC_SINGLE_EXT("WSA_RX1 EC_HQ Switch", SND_SOC_NOPM, WSA_MACRO_RX1,
			1, 0, wsa_macro_get_ec_hq, wsa_macro_set_ec_hq),
};

static const struct soc_enum rx_mux_enum =
	SOC_ENUM_SINGLE_EXT(ARRAY_SIZE(rx_mux_text), rx_mux_text);

static const struct snd_kcontrol_new rx_mux[WSA_MACRO_RX_MAX] = {
	SOC_DAPM_ENUM_EXT("WSA RX0 Mux", rx_mux_enum,
			  wsa_macro_rx_mux_get, wsa_macro_rx_mux_put),
	SOC_DAPM_ENUM_EXT("WSA RX1 Mux", rx_mux_enum,
			  wsa_macro_rx_mux_get, wsa_macro_rx_mux_put),
	SOC_DAPM_ENUM_EXT("WSA RX_MIX0 Mux", rx_mux_enum,
			  wsa_macro_rx_mux_get, wsa_macro_rx_mux_put),
	SOC_DAPM_ENUM_EXT("WSA RX_MIX1 Mux", rx_mux_enum,
			  wsa_macro_rx_mux_get, wsa_macro_rx_mux_put),
};

static int wsa_macro_vi_feed_mixer_get(struct snd_kcontrol *kcontrol,
				   struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_dapm_widget *widget =
		snd_soc_dapm_kcontrol_widget(kcontrol);
	struct snd_soc_component *component =
				snd_soc_dapm_to_component(widget->dapm);
	struct soc_mixer_control *mixer =
		((struct soc_mixer_control *)kcontrol->private_value);
	u32 dai_id = widget->shift;
	u32 spk_tx_id = mixer->shift;
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	if (test_bit(spk_tx_id, &wsa_priv->active_ch_mask[dai_id]))
		ucontrol->value.integer.value[0] = 1;
	else
		ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int wsa_macro_vi_feed_mixer_put(struct snd_kcontrol *kcontrol,
				   struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_dapm_widget *widget =
		snd_soc_dapm_kcontrol_widget(kcontrol);
	struct snd_soc_component *component =
				snd_soc_dapm_to_component(widget->dapm);
	struct soc_mixer_control *mixer =
		((struct soc_mixer_control *)kcontrol->private_value);
	u32 spk_tx_id = mixer->shift;
	u32 enable = ucontrol->value.integer.value[0];
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(component);

	wsa_priv->vi_feed_value = ucontrol->value.integer.value[0];

	if (enable) {
		if (spk_tx_id == WSA_MACRO_TX0 &&
			!test_bit(WSA_MACRO_TX0,
				&wsa_priv->active_ch_mask[WSA_MACRO_AIF_VI])) {
			set_bit(WSA_MACRO_TX0,
				&wsa_priv->active_ch_mask[WSA_MACRO_AIF_VI]);
			wsa_priv->active_ch_cnt[WSA_MACRO_AIF_VI]++;
		}
		if (spk_tx_id == WSA_MACRO_TX1 &&
			!test_bit(WSA_MACRO_TX1,
				&wsa_priv->active_ch_mask[WSA_MACRO_AIF_VI])) {
			set_bit(WSA_MACRO_TX1,
				&wsa_priv->active_ch_mask[WSA_MACRO_AIF_VI]);
			wsa_priv->active_ch_cnt[WSA_MACRO_AIF_VI]++;
		}
	} else {
		if (spk_tx_id == WSA_MACRO_TX0 &&
			test_bit(WSA_MACRO_TX0,
				&wsa_priv->active_ch_mask[WSA_MACRO_AIF_VI])) {
			clear_bit(WSA_MACRO_TX0,
				&wsa_priv->active_ch_mask[WSA_MACRO_AIF_VI]);
			wsa_priv->active_ch_cnt[WSA_MACRO_AIF_VI]--;
		}
		if (spk_tx_id == WSA_MACRO_TX1 &&
			test_bit(WSA_MACRO_TX1,
				&wsa_priv->active_ch_mask[WSA_MACRO_AIF_VI])) {
			clear_bit(WSA_MACRO_TX1,
				&wsa_priv->active_ch_mask[WSA_MACRO_AIF_VI]);
			wsa_priv->active_ch_cnt[WSA_MACRO_AIF_VI]--;
		}
	}
	snd_soc_dapm_mixer_update_power(widget->dapm, kcontrol, enable, NULL);

	return 0;
}

static const struct snd_kcontrol_new aif_vi_mixer[] = {
	SOC_SINGLE_EXT("WSA_SPKR_VI_1", SND_SOC_NOPM, WSA_MACRO_TX0, 1, 0,
			wsa_macro_vi_feed_mixer_get,
			wsa_macro_vi_feed_mixer_put),
	SOC_SINGLE_EXT("WSA_SPKR_VI_2", SND_SOC_NOPM, WSA_MACRO_TX1, 1, 0,
			wsa_macro_vi_feed_mixer_get,
			wsa_macro_vi_feed_mixer_put),
};

static const struct snd_soc_dapm_widget wsa_macro_dapm_widgets[] = {
	SND_SOC_DAPM_AIF_IN("WSA AIF1 PB", "WSA_AIF1 Playback", 0,
		SND_SOC_NOPM, 0, 0),

	SND_SOC_DAPM_AIF_IN("WSA AIF_MIX1 PB", "WSA_AIF_MIX1 Playback", 0,
		SND_SOC_NOPM, 0, 0),

	SND_SOC_DAPM_AIF_OUT_E("WSA AIF_VI", "WSA_AIF_VI Capture", 0,
		SND_SOC_NOPM, WSA_MACRO_AIF_VI, 0,
		wsa_macro_enable_vi_feedback,
		SND_SOC_DAPM_POST_PMU | SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_AIF_OUT("WSA AIF_ECHO", "WSA_AIF_ECHO Capture", 0,
		SND_SOC_NOPM, 0, 0),

	SND_SOC_DAPM_MIXER("WSA_AIF_VI Mixer", SND_SOC_NOPM, WSA_MACRO_AIF_VI,
		0, aif_vi_mixer, ARRAY_SIZE(aif_vi_mixer)),
	SND_SOC_DAPM_MUX_E("WSA RX_MIX EC0_MUX", SND_SOC_NOPM,
			WSA_MACRO_EC0_MUX, 0,
			&rx_mix_ec0_mux, wsa_macro_enable_echo,
			SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MUX_E("WSA RX_MIX EC1_MUX", SND_SOC_NOPM,
			WSA_MACRO_EC1_MUX, 0,
			&rx_mix_ec1_mux, wsa_macro_enable_echo,
			SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_MUX("WSA RX0 MUX", SND_SOC_NOPM, WSA_MACRO_RX0, 0,
				&rx_mux[WSA_MACRO_RX0]),
	SND_SOC_DAPM_MUX("WSA RX1 MUX", SND_SOC_NOPM, WSA_MACRO_RX1, 0,
				&rx_mux[WSA_MACRO_RX1]),
	SND_SOC_DAPM_MUX("WSA RX_MIX0 MUX", SND_SOC_NOPM, WSA_MACRO_RX_MIX0, 0,
				&rx_mux[WSA_MACRO_RX_MIX0]),
	SND_SOC_DAPM_MUX("WSA RX_MIX1 MUX", SND_SOC_NOPM, WSA_MACRO_RX_MIX1, 0,
				&rx_mux[WSA_MACRO_RX_MIX1]),

	SND_SOC_DAPM_MIXER("WSA RX0", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("WSA RX1", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("WSA RX_MIX0", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("WSA RX_MIX1", SND_SOC_NOPM, 0, 0, NULL, 0),

	SND_SOC_DAPM_MUX_E("WSA_RX0 INP0", SND_SOC_NOPM, 0, 0,
		&rx0_prim_inp0_mux, wsa_macro_enable_swr,
		SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MUX_E("WSA_RX0 INP1", SND_SOC_NOPM, 0, 0,
		&rx0_prim_inp1_mux, wsa_macro_enable_swr,
		SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MUX_E("WSA_RX0 INP2", SND_SOC_NOPM, 0, 0,
		&rx0_prim_inp2_mux, wsa_macro_enable_swr,
		SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MUX_E("WSA_RX0 MIX INP", CDC_WSA_RX0_RX_PATH_MIX_CTL,
		0, 0, &rx0_mix_mux, wsa_macro_enable_mix_path,
		SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MUX_E("WSA_RX1 INP0", SND_SOC_NOPM, 0, 0,
		&rx1_prim_inp0_mux, wsa_macro_enable_swr,
		SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MUX_E("WSA_RX1 INP1", SND_SOC_NOPM, 0, 0,
		&rx1_prim_inp1_mux, wsa_macro_enable_swr,
		SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MUX_E("WSA_RX1 INP2", SND_SOC_NOPM, 0, 0,
		&rx1_prim_inp2_mux, wsa_macro_enable_swr,
		SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MUX_E("WSA_RX1 MIX INP", CDC_WSA_RX1_RX_PATH_MIX_CTL,
		0, 0, &rx1_mix_mux, wsa_macro_enable_mix_path,
		SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MIXER_E("WSA_RX INT0 MIX", SND_SOC_NOPM,
			0, 0, NULL, 0, wsa_macro_enable_main_path,
			SND_SOC_DAPM_PRE_PMU),
	SND_SOC_DAPM_MIXER_E("WSA_RX INT1 MIX", SND_SOC_NOPM,
			1, 0, NULL, 0, wsa_macro_enable_main_path,
			SND_SOC_DAPM_PRE_PMU),
	SND_SOC_DAPM_MIXER("WSA_RX INT0 SEC MIX", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("WSA_RX INT1 SEC MIX", SND_SOC_NOPM, 0, 0, NULL, 0),

	SND_SOC_DAPM_MUX_E("WSA_RX0 INT0 SIDETONE MIX",
			   CDC_WSA_RX0_RX_PATH_CFG1, 4, 0,
			   &rx0_sidetone_mix_mux, wsa_macro_enable_swr,
			  SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_INPUT("WSA SRC0_INP"),

	SND_SOC_DAPM_INPUT("WSA_TX DEC0_INP"),
	SND_SOC_DAPM_INPUT("WSA_TX DEC1_INP"),

	SND_SOC_DAPM_MIXER_E("WSA_RX INT0 INTERP", SND_SOC_NOPM,
		WSA_MACRO_COMP1, 0, NULL, 0, wsa_macro_enable_interpolator,
		SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU |
		SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MIXER_E("WSA_RX INT1 INTERP", SND_SOC_NOPM,
		WSA_MACRO_COMP2, 0, NULL, 0, wsa_macro_enable_interpolator,
		SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU |
		SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_MIXER_E("WSA_RX INT0 CHAIN", SND_SOC_NOPM, 0, 0,
		NULL, 0, wsa_macro_spk_boost_event,
		SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU |
		SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MIXER_E("WSA_RX INT1 CHAIN", SND_SOC_NOPM, 0, 0,
		NULL, 0, wsa_macro_spk_boost_event,
		SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMU |
		SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_MIXER_E("WSA_RX INT0 VBAT", SND_SOC_NOPM,
		0, 0, wsa_int0_vbat_mix_switch,
		ARRAY_SIZE(wsa_int0_vbat_mix_switch),
		wsa_macro_enable_vbat,
		SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MIXER_E("WSA_RX INT1 VBAT", SND_SOC_NOPM,
		0, 0, wsa_int1_vbat_mix_switch,
		ARRAY_SIZE(wsa_int1_vbat_mix_switch),
		wsa_macro_enable_vbat,
		SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_INPUT("VIINPUT_WSA"),

	SND_SOC_DAPM_OUTPUT("WSA_SPK1 OUT"),
	SND_SOC_DAPM_OUTPUT("WSA_SPK2 OUT"),

	SND_SOC_DAPM_SUPPLY_S("WSA_MCLK", 0, SND_SOC_NOPM, 0, 0,
	wsa_macro_mclk_event, SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
};

static const struct snd_soc_dapm_route wsa_audio_map[] = {
	/* VI Feedback */
	{"WSA_AIF_VI Mixer", "WSA_SPKR_VI_1", "VIINPUT_WSA"},
	{"WSA_AIF_VI Mixer", "WSA_SPKR_VI_2", "VIINPUT_WSA"},
	{"WSA AIF_VI", NULL, "WSA_AIF_VI Mixer"},
	{"WSA AIF_VI", NULL, "WSA_MCLK"},

	{"WSA RX_MIX EC0_MUX", "RX_MIX_TX0", "WSA_RX INT0 SEC MIX"},
	{"WSA RX_MIX EC1_MUX", "RX_MIX_TX0", "WSA_RX INT0 SEC MIX"},
	{"WSA RX_MIX EC0_MUX", "RX_MIX_TX1", "WSA_RX INT1 SEC MIX"},
	{"WSA RX_MIX EC1_MUX", "RX_MIX_TX1", "WSA_RX INT1 SEC MIX"},
	{"WSA AIF_ECHO", NULL, "WSA RX_MIX EC0_MUX"},
	{"WSA AIF_ECHO", NULL, "WSA RX_MIX EC1_MUX"},
	{"WSA AIF_ECHO", NULL, "WSA_MCLK"},

	{"WSA AIF1 PB", NULL, "WSA_MCLK"},
	{"WSA AIF_MIX1 PB", NULL, "WSA_MCLK"},

	{"WSA RX0 MUX", "AIF1_PB", "WSA AIF1 PB"},
	{"WSA RX1 MUX", "AIF1_PB", "WSA AIF1 PB"},
	{"WSA RX_MIX0 MUX", "AIF1_PB", "WSA AIF1 PB"},
	{"WSA RX_MIX1 MUX", "AIF1_PB", "WSA AIF1 PB"},

	{"WSA RX0 MUX", "AIF_MIX1_PB", "WSA AIF_MIX1 PB"},
	{"WSA RX1 MUX", "AIF_MIX1_PB", "WSA AIF_MIX1 PB"},
	{"WSA RX_MIX0 MUX", "AIF_MIX1_PB", "WSA AIF_MIX1 PB"},
	{"WSA RX_MIX1 MUX", "AIF_MIX1_PB", "WSA AIF_MIX1 PB"},

	{"WSA RX0", NULL, "WSA RX0 MUX"},
	{"WSA RX1", NULL, "WSA RX1 MUX"},
	{"WSA RX_MIX0", NULL, "WSA RX_MIX0 MUX"},
	{"WSA RX_MIX1", NULL, "WSA RX_MIX1 MUX"},

	{"WSA_RX0 INP0", "RX0", "WSA RX0"},
	{"WSA_RX0 INP0", "RX1", "WSA RX1"},
	{"WSA_RX0 INP0", "RX_MIX0", "WSA RX_MIX0"},
	{"WSA_RX0 INP0", "RX_MIX1", "WSA RX_MIX1"},
	{"WSA_RX0 INP0", "DEC0", "WSA_TX DEC0_INP"},
	{"WSA_RX0 INP0", "DEC1", "WSA_TX DEC1_INP"},
	{"WSA_RX INT0 MIX", NULL, "WSA_RX0 INP0"},

	{"WSA_RX0 INP1", "RX0", "WSA RX0"},
	{"WSA_RX0 INP1", "RX1", "WSA RX1"},
	{"WSA_RX0 INP1", "RX_MIX0", "WSA RX_MIX0"},
	{"WSA_RX0 INP1", "RX_MIX1", "WSA RX_MIX1"},
	{"WSA_RX0 INP1", "DEC0", "WSA_TX DEC0_INP"},
	{"WSA_RX0 INP1", "DEC1", "WSA_TX DEC1_INP"},
	{"WSA_RX INT0 MIX", NULL, "WSA_RX0 INP1"},

	{"WSA_RX0 INP2", "RX0", "WSA RX0"},
	{"WSA_RX0 INP2", "RX1", "WSA RX1"},
	{"WSA_RX0 INP2", "RX_MIX0", "WSA RX_MIX0"},
	{"WSA_RX0 INP2", "RX_MIX1", "WSA RX_MIX1"},
	{"WSA_RX0 INP2", "DEC0", "WSA_TX DEC0_INP"},
	{"WSA_RX0 INP2", "DEC1", "WSA_TX DEC1_INP"},
	{"WSA_RX INT0 MIX", NULL, "WSA_RX0 INP2"},

	{"WSA_RX0 MIX INP", "RX0", "WSA RX0"},
	{"WSA_RX0 MIX INP", "RX1", "WSA RX1"},
	{"WSA_RX0 MIX INP", "RX_MIX0", "WSA RX_MIX0"},
	{"WSA_RX0 MIX INP", "RX_MIX1", "WSA RX_MIX1"},
	{"WSA_RX INT0 SEC MIX", NULL, "WSA_RX0 MIX INP"},

	{"WSA_RX INT0 SEC MIX", NULL, "WSA_RX INT0 MIX"},
	{"WSA_RX INT0 INTERP", NULL, "WSA_RX INT0 SEC MIX"},
	{"WSA_RX0 INT0 SIDETONE MIX", "SRC0", "WSA SRC0_INP"},
	{"WSA_RX INT0 INTERP", NULL, "WSA_RX0 INT0 SIDETONE MIX"},
	{"WSA_RX INT0 CHAIN", NULL, "WSA_RX INT0 INTERP"},

	{"WSA_RX INT0 VBAT", "WSA RX0 VBAT Enable", "WSA_RX INT0 INTERP"},
	{"WSA_RX INT0 CHAIN", NULL, "WSA_RX INT0 VBAT"},

	{"WSA_SPK1 OUT", NULL, "WSA_RX INT0 CHAIN"},
	{"WSA_SPK1 OUT", NULL, "WSA_MCLK"},

	{"WSA_RX1 INP0", "RX0", "WSA RX0"},
	{"WSA_RX1 INP0", "RX1", "WSA RX1"},
	{"WSA_RX1 INP0", "RX_MIX0", "WSA RX_MIX0"},
	{"WSA_RX1 INP0", "RX_MIX1", "WSA RX_MIX1"},
	{"WSA_RX1 INP0", "DEC0", "WSA_TX DEC0_INP"},
	{"WSA_RX1 INP0", "DEC1", "WSA_TX DEC1_INP"},
	{"WSA_RX INT1 MIX", NULL, "WSA_RX1 INP0"},

	{"WSA_RX1 INP1", "RX0", "WSA RX0"},
	{"WSA_RX1 INP1", "RX1", "WSA RX1"},
	{"WSA_RX1 INP1", "RX_MIX0", "WSA RX_MIX0"},
	{"WSA_RX1 INP1", "RX_MIX1", "WSA RX_MIX1"},
	{"WSA_RX1 INP1", "DEC0", "WSA_TX DEC0_INP"},
	{"WSA_RX1 INP1", "DEC1", "WSA_TX DEC1_INP"},
	{"WSA_RX INT1 MIX", NULL, "WSA_RX1 INP1"},

	{"WSA_RX1 INP2", "RX0", "WSA RX0"},
	{"WSA_RX1 INP2", "RX1", "WSA RX1"},
	{"WSA_RX1 INP2", "RX_MIX0", "WSA RX_MIX0"},
	{"WSA_RX1 INP2", "RX_MIX1", "WSA RX_MIX1"},
	{"WSA_RX1 INP2", "DEC0", "WSA_TX DEC0_INP"},
	{"WSA_RX1 INP2", "DEC1", "WSA_TX DEC1_INP"},
	{"WSA_RX INT1 MIX", NULL, "WSA_RX1 INP2"},

	{"WSA_RX1 MIX INP", "RX0", "WSA RX0"},
	{"WSA_RX1 MIX INP", "RX1", "WSA RX1"},
	{"WSA_RX1 MIX INP", "RX_MIX0", "WSA RX_MIX0"},
	{"WSA_RX1 MIX INP", "RX_MIX1", "WSA RX_MIX1"},
	{"WSA_RX INT1 SEC MIX", NULL, "WSA_RX1 MIX INP"},

	{"WSA_RX INT1 SEC MIX", NULL, "WSA_RX INT1 MIX"},
	{"WSA_RX INT1 INTERP", NULL, "WSA_RX INT1 SEC MIX"},

	{"WSA_RX INT1 VBAT", "WSA RX1 VBAT Enable", "WSA_RX INT1 INTERP"},
	{"WSA_RX INT1 CHAIN", NULL, "WSA_RX INT1 VBAT"},

	{"WSA_RX INT1 CHAIN", NULL, "WSA_RX INT1 INTERP"},
	{"WSA_SPK2 OUT", NULL, "WSA_RX INT1 CHAIN"},
	{"WSA_SPK2 OUT", NULL, "WSA_MCLK"},
};

static int wsa_swrm_clock(struct wsa_macro_priv *wsa_priv, bool enable)
{
	struct regmap *regmap = wsa_priv->regmap;
	int ret = 0;

	if (enable) {
		ret = wsa_macro_mclk_enable(wsa_priv, 1, true);
		if (ret < 0) {
			dev_err_ratelimited(wsa_priv->dev,
				"%s: wsa request clock enable failed\n",
				__func__);
			return ret;
		}

		if (wsa_priv->reset_swr)
			regmap_update_bits(regmap,
				CDC_WSA_CLK_RST_CTRL_SWR_CONTROL,
				0x02, 0x02);
		regmap_update_bits(regmap,
			CDC_WSA_CLK_RST_CTRL_SWR_CONTROL,
			0x01, 0x01);

		if (wsa_priv->reset_swr)
			regmap_update_bits(regmap,
				CDC_WSA_CLK_RST_CTRL_SWR_CONTROL,
				0x02, 0x00);
		wsa_priv->reset_swr = false;
	} else {
		regmap_update_bits(regmap,
			CDC_WSA_CLK_RST_CTRL_SWR_CONTROL,
			0x01, 0x00);
		wsa_macro_mclk_enable(wsa_priv, 0, true);
	}

	return ret;
}

static int wsa_macro_component_probe(struct snd_soc_component *comp)
{
	struct wsa_macro_priv *wsa_priv = snd_soc_component_get_drvdata(comp);
	int i;

	snd_soc_component_init_regmap(comp, wsa_priv->regmap);


	wsa_priv->spkr_gain_offset = WSA_MACRO_GAIN_OFFSET_M1P5_DB;//WSA_MACRO_GAIN_OFFSET_0_DB;



//	for (i = 0; i < ARRAY_SIZE(wsa_macro_reg_init); i++)
//		snd_soc_component_update_bits(component,
//				wsa_macro_reg_init[i].reg,
//				wsa_macro_reg_init[i].mask,
//				wsa_macro_reg_init[i].val);

	snd_soc_component_update_bits(comp, CDC_WSA_BOOST0_BOOST_CFG1,
					0x3F, 0x12);
	snd_soc_component_update_bits(comp, CDC_WSA_BOOST0_BOOST_CFG2,
					0x1C, 0x08);
	snd_soc_component_update_bits(comp, CDC_WSA_COMPANDER0_CTL7,
					0x1E, 0x18);
	snd_soc_component_update_bits(comp, CDC_WSA_BOOST1_BOOST_CFG1,
					0x3F, 0x12);
	snd_soc_component_update_bits(comp, CDC_WSA_BOOST1_BOOST_CFG2,
					0x1C, 0x08);
	snd_soc_component_update_bits(comp, CDC_WSA_COMPANDER1_CTL7,
					0x1E, 0x18);
	snd_soc_component_update_bits(comp, CDC_WSA_BOOST0_BOOST_CTL,
					0x70, 0x58);
	snd_soc_component_update_bits(comp, CDC_WSA_BOOST1_BOOST_CTL,
					0x70, 0x58);
	snd_soc_component_update_bits(comp, CDC_WSA_RX0_RX_PATH_CFG1,
					0x08, 0x08);
	snd_soc_component_update_bits(comp, CDC_WSA_RX1_RX_PATH_CFG1,
					0x08, 0x08);
	snd_soc_component_update_bits(comp, CDC_WSA_TOP_TOP_CFG1,
					0x02, 0x02);
	snd_soc_component_update_bits(comp, CDC_WSA_TOP_TOP_CFG1,
					0x01, 0x01);
	snd_soc_component_update_bits(comp, CDC_WSA_TX0_SPKR_PROT_PATH_CFG0,
					0x01, 0x01);
	snd_soc_component_update_bits(comp, CDC_WSA_TX1_SPKR_PROT_PATH_CFG0,
					0x01, 0x01);
	snd_soc_component_update_bits(comp, CDC_WSA_TX2_SPKR_PROT_PATH_CFG0,
					0x01, 0x01);
	snd_soc_component_update_bits(comp, CDC_WSA_TX3_SPKR_PROT_PATH_CFG0,
					0x01, 0x01);
	snd_soc_component_update_bits(comp, CDC_WSA_COMPANDER0_CTL3,
					0x80, 0x80);
	snd_soc_component_update_bits(comp, CDC_WSA_COMPANDER1_CTL3,
					0x80, 0x80);
	snd_soc_component_update_bits(comp, CDC_WSA_COMPANDER0_CTL7,
					0x01, 0x01);
	snd_soc_component_update_bits(comp, CDC_WSA_COMPANDER1_CTL7,
					0x01, 0x01);
	snd_soc_component_update_bits(comp, CDC_WSA_RX0_RX_PATH_CFG0,
					0x01, 0x01);
	snd_soc_component_update_bits(comp, CDC_WSA_RX1_RX_PATH_CFG0,
					0x01, 0x01);
	snd_soc_component_update_bits(comp, CDC_WSA_RX0_RX_PATH_MIX_CFG,
					0x01, 0x01);
	snd_soc_component_update_bits(comp, CDC_WSA_RX1_RX_PATH_MIX_CFG,
					0x01, 0x01);

	wsa_macro_set_spkr_mode(comp, 1);

	return 0;
}

static int swclk_gate_enable(struct clk_hw *hw)
{
	return wsa_swrm_clock(to_wsa_macro(hw), true);
}

static void swclk_gate_disable(struct clk_hw *hw)
{
	wsa_swrm_clock(to_wsa_macro(hw), false);
}

static int swclk_gate_is_enabled(struct clk_hw *hw)
{
	struct wsa_macro_priv *wsa = to_wsa_macro(hw);
	int ret, val;

	regmap_read(wsa->regmap, CDC_WSA_CLK_RST_CTRL_SWR_CONTROL, &val);
	ret = val & BIT(0);

	return ret;
}

static unsigned long swclk_recalc_rate(struct clk_hw *hw,
				       unsigned long parent_rate)
{
	return parent_rate / 2;
}

static const struct clk_ops swclk_gate_ops = {
	.prepare = swclk_gate_enable,
	.unprepare = swclk_gate_disable,
	.is_enabled = swclk_gate_is_enabled,
	.recalc_rate = swclk_recalc_rate,

};

static struct clk *wsa_macro_register_mclk_output(struct wsa_macro_priv *wsa)
{
	struct clk *parent = wsa->npl_clk;
	struct device *dev = wsa->dev;
	struct device_node *np = dev->of_node;
	const char *parent_clk_name = NULL;
	const char *clk_name = "mclk";
	struct clk_hw *hw;
	struct clk_init_data init;
	int rate;
	int ret;

	if (of_property_read_u32(np, "clock-frequency", &rate))
		return NULL;

	parent_clk_name = __clk_get_name(parent);

	of_property_read_string(np, "clock-output-names", &clk_name);

	init.name = clk_name;
	init.ops = &swclk_gate_ops;
	init.flags = 0;
	init.parent_names = &parent_clk_name;
	init.num_parents = 1;
	wsa->hw.init = &init;
	hw = &wsa->hw;
	ret = clk_hw_register(wsa->dev, hw);
	if (ret)
		return ERR_PTR(ret);

	of_clk_add_provider(np, of_clk_src_simple_get, hw->clk);

	return NULL;
}

static const struct snd_soc_component_driver wsa_macro_component_drv = {
	.name = "WSA MACRO",
	.probe = wsa_macro_component_probe,
	.controls = wsa_macro_snd_controls,
	.num_controls = ARRAY_SIZE(wsa_macro_snd_controls),
	.dapm_widgets = wsa_macro_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(wsa_macro_dapm_widgets),
	.dapm_routes = wsa_audio_map,
	.num_dapm_routes = ARRAY_SIZE(wsa_audio_map),
};

const struct regmap_config wsa_va_regmap_config = {
	.name = "va_macro",
	.reg_bits = 16,
	.val_bits = 32, /* 8 but with 32 bit read/write */
	.reg_stride = 4,
	.cache_type = REGCACHE_FLAT,
	.max_register = WSA_MAX_OFFSET,
};

static int wsa_macro_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct wsa_macro_priv *wsa_priv;
	struct resource *res;
	struct clk *c;
	int ret;

	wsa_priv = devm_kzalloc(dev, sizeof(struct wsa_macro_priv),
				GFP_KERNEL);
	if (!wsa_priv)
		return -ENOMEM;

	wsa_priv->hw_vote = devm_clk_get(dev, "macro");
	if (IS_ERR(wsa_priv->hw_vote))
		return PTR_ERR(wsa_priv->hw_vote);

	wsa_priv->dcodec_vote = devm_clk_get(dev, "dcodec");
	if (IS_ERR(wsa_priv->dcodec_vote))
		return PTR_ERR(wsa_priv->dcodec_vote);

	clk_prepare_enable(wsa_priv->hw_vote);
	clk_prepare_enable(wsa_priv->dcodec_vote);

	wsa_priv->clk = devm_clk_get(dev, "mclk");
	if (IS_ERR(wsa_priv->clk))
		return PTR_ERR(wsa_priv->clk);

	wsa_priv->npl_clk = devm_clk_get(dev, "npl");
	if (IS_ERR(wsa_priv->npl_clk))
		return PTR_ERR(wsa_priv->npl_clk);

	clk_set_rate(wsa_priv->clk, 19200000);

	clk_set_rate(wsa_priv->npl_clk, 19200000);

	c = devm_clk_get(dev, "va");
	if (IS_ERR(c))
		return PTR_ERR(c);
	clk_set_rate(c, 19200000);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	wsa_priv->regmap = devm_regmap_init_mmio(dev,
						 devm_ioremap_resource(dev, res),
						 &wsa_regmap_config);

//	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
//	wsa_priv->va_regmap = devm_regmap_init_mmio(dev,
//						 devm_ioremap_resource(dev, res),
//						 &wsa_va_regmap_config);

	dev_set_drvdata(dev, wsa_priv);
	mutex_init(&wsa_priv->mclk_lock);

	wsa_priv->reset_swr = true;
	wsa_priv->dev = dev;

	clk_prepare_enable(wsa_priv->clk);
	clk_prepare_enable(wsa_priv->npl_clk);
	clk_prepare_enable(c);

	wsa_macro_register_mclk_output(wsa_priv);

	ret = devm_snd_soc_register_component(dev,
					      &wsa_macro_component_drv,
					       wsa_macro_dai,
					       ARRAY_SIZE(wsa_macro_dai));
	if (ret)
		return ret;

	return of_platform_populate(dev->of_node, NULL, NULL, dev);
}

static int wsa_macro_remove(struct platform_device *pdev)
{
	struct wsa_macro_priv *wsa_priv;

	wsa_priv = dev_get_drvdata(&pdev->dev);

	if (!wsa_priv)
		return -EINVAL;

	mutex_destroy(&wsa_priv->mclk_lock);
	return 0;
}

static const struct of_device_id wsa_macro_dt_match[] = {
	{.compatible = "qcom,sm8250-lpass-wsa-macro"},
	{}
};
MODULE_DEVICE_TABLE(of, wsa_macro_dt_match);

static struct platform_driver wsa_macro_driver = {
	.driver = {
		.name = "wsa_macro",
		.owner = THIS_MODULE,
		.of_match_table = wsa_macro_dt_match,
	},
	.probe = wsa_macro_probe,
	.remove = wsa_macro_remove,
};

module_platform_driver(wsa_macro_driver);
MODULE_DESCRIPTION("WSA macro driver");
MODULE_LICENSE("GPL v2");
