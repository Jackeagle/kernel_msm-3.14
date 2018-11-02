// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#ifndef _RMNET_CONFIG_H_
#define _RMNET_CONFIG_H_

#include <linux/types.h>

/* XXX We want to use struct rmnet_map_header, but that's currently defined in
 * XXX     drivers/net/ethernet/qualcomm/rmnet/rmnet_map.h
 * XXX We also want to use RMNET_MAP_GET_CD_BIT(Y), defined in the same file.
 */
struct rmnet_map_header_s {
#ifndef RMNET_USE_BIG_ENDIAN_STRUCTS
	u8	pad_len		: 6,
		reserved_bit	: 1,
		cd_bit		: 1;
#else
	u8	cd_bit		: 1,
		reserved_bit	: 1,
		pad_len		: 6;
#endif /* RMNET_USE_BIG_ENDIAN_STRUCTS */
	u8	mux_id;
	u16	pkt_len;
}  __aligned(1);

#define RMNET_MAP_GET_CD_BIT(Y) (((struct rmnet_map_header_s *)Y->data)->cd_bit)

#endif /* _RMNET_CONFIG_H_ */
