// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#ifndef _IPA_CLOCK_H_
#define _IPA_CLOCK_H_

#include "ipa_i.h"	/* ipa_context */

/**
 * DOC: IPA Clocking
 *
 * This module implements clocking as it relates to IPA.
 */

int ipa_clock_init(struct ipa_context *ipa);
void ipa_clock_exit(struct ipa_context *ipa);

void ipa_clock_get(void);
bool ipa_clock_get_additional(void);
void ipa_clock_put(void);

void ipa_clock_proxy_put(void);
void ipa_clock_proxy_get(void);

#endif /* _IPA_CLOCK_H_ */
