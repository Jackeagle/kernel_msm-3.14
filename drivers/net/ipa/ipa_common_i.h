// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#ifndef _IPA_COMMON_I_H_
#define _IPA_COMMON_I_H_

#include <linux/slab.h>

#include "ipa_reg.h"

/** enum ipa_irq_type - IPA Interrupt Type
 * Used to register handlers for IPA interrupts
 *
 * Below enum is a logical mapping and not the actual interrupt bit in HW
 */
enum ipa_irq_type {
	IPA_INVALID_IRQ = 0,
	IPA_UC_IRQ_0,
	IPA_UC_IRQ_1,
	IPA_TX_SUSPEND_IRQ,
	IPA_IRQ_MAX
};

/** enum ipa_client_type - names for the various IPA "clients"
 * these are from the perspective of the clients, for e.g.
 * HSIC1_PROD means HSIC client is the producer and IPA is the
 * consumer.
 * PROD clients are always even, and CONS clients are always odd.
 * Add new clients in the end of the list and update IPA_CLIENT_MAX
 */
enum ipa_client_type {
	IPA_CLIENT_HSIC1_PROD                   = 0,
	IPA_CLIENT_HSIC1_CONS                   = 1,

	IPA_CLIENT_HSIC2_PROD                   = 2,
	IPA_CLIENT_HSIC2_CONS                   = 3,

	IPA_CLIENT_HSIC3_PROD                   = 4,
	IPA_CLIENT_HSIC3_CONS                   = 5,

	IPA_CLIENT_HSIC4_PROD                   = 6,
	IPA_CLIENT_HSIC4_CONS                   = 7,

	IPA_CLIENT_HSIC5_PROD                   = 8,
	IPA_CLIENT_HSIC5_CONS                   = 9,

	IPA_CLIENT_WLAN1_PROD                   = 10,
	IPA_CLIENT_WLAN1_CONS                   = 11,

	IPA_CLIENT_A5_WLAN_AMPDU_PROD           = 12,
	IPA_CLIENT_WLAN2_CONS                   = 13,

	/* RESERVERD PROD                       = 14, */
	IPA_CLIENT_WLAN3_CONS                   = 15,

	/* RESERVERD PROD                       = 16, */
	IPA_CLIENT_WLAN4_CONS                   = 17,

	IPA_CLIENT_USB_PROD                     = 18,
	IPA_CLIENT_USB_CONS                     = 19,

	IPA_CLIENT_USB2_PROD                    = 20,
	IPA_CLIENT_USB2_CONS                    = 21,

	IPA_CLIENT_USB3_PROD                    = 22,
	IPA_CLIENT_USB3_CONS                    = 23,

	IPA_CLIENT_USB4_PROD                    = 24,
	IPA_CLIENT_USB4_CONS                    = 25,

	IPA_CLIENT_UC_USB_PROD                  = 26,
	IPA_CLIENT_USB_DPL_CONS                 = 27,

	IPA_CLIENT_A2_EMBEDDED_PROD		= 28,
	IPA_CLIENT_A2_EMBEDDED_CONS		= 29,

	IPA_CLIENT_A2_TETHERED_PROD             = 30,
	IPA_CLIENT_A2_TETHERED_CONS             = 31,

	IPA_CLIENT_APPS_LAN_PROD		= 32,
	IPA_CLIENT_APPS_LAN_CONS		= 33,

	IPA_CLIENT_APPS_WAN_PROD		= 34,
	IPA_CLIENT_APPS_LAN_WAN_PROD = IPA_CLIENT_APPS_WAN_PROD,
	IPA_CLIENT_APPS_WAN_CONS		= 35,

	IPA_CLIENT_APPS_CMD_PROD		= 36,
	IPA_CLIENT_A5_LAN_WAN_CONS		= 37,

	IPA_CLIENT_ODU_PROD                     = 38,
	IPA_CLIENT_ODU_EMB_CONS                 = 39,

	/* RESERVERD PROD                       = 40, */
	IPA_CLIENT_ODU_TETH_CONS                = 41,

	IPA_CLIENT_MHI_PROD                     = 42,
	IPA_CLIENT_MHI_CONS                     = 43,

	IPA_CLIENT_MEMCPY_DMA_SYNC_PROD		= 44,
	IPA_CLIENT_MEMCPY_DMA_SYNC_CONS		= 45,

	IPA_CLIENT_MEMCPY_DMA_ASYNC_PROD	= 46,
	IPA_CLIENT_MEMCPY_DMA_ASYNC_CONS	= 47,

	IPA_CLIENT_ETHERNET_PROD                = 48,
	IPA_CLIENT_ETHERNET_CONS                = 49,

	IPA_CLIENT_Q6_LAN_PROD			= 50,
	IPA_CLIENT_Q6_LAN_CONS			= 51,

	IPA_CLIENT_Q6_WAN_PROD			= 52,
	IPA_CLIENT_Q6_WAN_CONS			= 53,

	IPA_CLIENT_Q6_CMD_PROD			= 54,
	IPA_CLIENT_Q6_DUN_CONS			= 55,

	IPA_CLIENT_Q6_DECOMP_PROD		= 56,
	IPA_CLIENT_Q6_DECOMP_CONS		= 57,

	IPA_CLIENT_Q6_DECOMP2_PROD		= 58,
	IPA_CLIENT_Q6_DECOMP2_CONS		= 59,

	/* RESERVERD PROD			= 60, */
	IPA_CLIENT_Q6_LTE_WIFI_AGGR_CONS	= 61,

	IPA_CLIENT_TEST_PROD                    = 62,
	IPA_CLIENT_TEST_CONS                    = 63,

	IPA_CLIENT_TEST1_PROD                   = 64,
	IPA_CLIENT_TEST1_CONS                   = 65,

	IPA_CLIENT_TEST2_PROD                   = 66,
	IPA_CLIENT_TEST2_CONS                   = 67,

	IPA_CLIENT_TEST3_PROD                   = 68,
	IPA_CLIENT_TEST3_CONS                   = 69,

	IPA_CLIENT_TEST4_PROD                   = 70,
	IPA_CLIENT_TEST4_CONS                   = 71,

	/* RESERVERD PROD			= 72, */
	IPA_CLIENT_DUMMY_CONS			= 73,

	IPA_CLIENT_MAX,
};

static inline bool ipa_producer(enum ipa_client_type client)
{
	return !((u32)client & 1);	/* Even numbers are producers */
}

static inline bool ipa_consumer(enum ipa_client_type client)
{
	return !ipa_producer(client);
}

/* Note a client must have a valid entry in the ipa_ep_configuration[]
 * array to be are considered a modem consumer or producer client.
 */
static inline bool ipa_modem_consumer(enum ipa_client_type client)
{
	return client == IPA_CLIENT_Q6_LAN_CONS ||
		client == IPA_CLIENT_Q6_WAN_CONS;
}

static inline bool ipa_modem_producer(enum ipa_client_type client)
{
	return client == IPA_CLIENT_Q6_LAN_PROD ||
		client == IPA_CLIENT_Q6_WAN_PROD ||
		client == IPA_CLIENT_Q6_CMD_PROD;
}

static inline bool ipa_ap_consumer(enum ipa_client_type client)
{
	return client == IPA_CLIENT_APPS_LAN_CONS ||
		client == IPA_CLIENT_APPS_WAN_CONS;
}

struct ipa_active_client_logging_info {
	const char *id_string;
	const char *file;
	int line;
};

/** enum ipa_dp_evt_type - type of event client callback is
 * invoked for on data path
 * @IPA_RECEIVE: data is struct sk_buff
 * @IPA_WRITE_DONE: data is struct sk_buff
 */
enum ipa_dp_evt_type {
	IPA_RECEIVE,
	IPA_WRITE_DONE,
	IPA_CLIENT_START_POLL,
	IPA_CLIENT_COMP_NAPI,
};

#define IPA_GENERIC_AGGR_BYTE_LIMIT	6
#define IPA_GENERIC_AGGR_TIME_LIMIT	1
#define IPA_GENERIC_AGGR_PKT_LIMIT	0

/** enum hdr_total_len_or_pad_type - type of value held by TOTAL_LEN_OR_PAD
 * field in header configuration register.
 * @IPA_HDR_PAD: field is used as padding length
 * @IPA_HDR_TOTAL_LEN: field is used as total length
 */
enum hdr_total_len_or_pad_type {
	IPA_HDR_PAD		= 0,
	IPA_HDR_TOTAL_LEN	= 1,
};

/** max size of the name of the resource (routing table, header) */
#define IPA_RESOURCE_NAME_MAX	32

#define ipa_debug(fmt, args...) \
		pr_debug(fmt, ## args)

#define ipa_debug_low(fmt, args...) \
		pr_debug(fmt, ## args)

#define ipa_err(fmt, args...) \
		pr_err(fmt, ## args)

#define ipa_info(fmt, args...) \
		pr_info(fmt, ## args)

#define ipa_bug() \
	do {								\
		ipa_err("an unrecoverable error has occurred\n");	\
		BUG();							\
	} while (0)

#define ipa_bug_on(condition)						\
	do {								\
		if (unlikely(condition)) {				\
			ipa_err("ipa_bug_on(%s) failed!\n", #condition); \
			ipa_bug();					\
		}							\
	} while (0)

#ifdef CONFIG_IPA_ASSERT

/* Communicate a condition assumed by the code.  This is intended as
 * an informative statement about something that should always be true.
 *
 * N.B.:  Conditions asserted must not incorporate code with side-effects
 *	  that are necessary for correct execution.  And an assertion
 *	  failure should not be expected to force a crash (because all
 *	  assertion code is optionally compiled out).
 */
#define ipa_assert(cond) \
	do {								\
		if (unlikely(!(cond))) {				\
			ipa_err("ipa_assert(%s) failed!\n", #cond);	\
			ipa_bug();					\
		}							\
	} while (0)
#else	/* !CONFIG_IPA_ASSERT */

#define ipa_assert(expr)	((void)0)

#endif	/* !CONFIG_IPA_ASSERT */

#endif /* _IPA_COMMON_I_H_ */
