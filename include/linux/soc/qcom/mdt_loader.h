/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __QCOM_MDT_LOADER_H__
#define __QCOM_MDT_LOADER_H__

#include <linux/types.h>

#define QCOM_MDT_TYPE_MASK	(7 << 24)
#define QCOM_MDT_TYPE_HASH	(2 << 24)
#define QCOM_MDT_RELOCATABLE	BIT(27)
#define QCOM_MDT_IMAGE_ID_WCNSS 0
#define QCOM_MDT_IMAGE_ID_MODEM 1
#define QCOM_MDT_IMAGE_ID_VENUS 2


struct qcom_mdt_image_info {
	char name[8];
	__le64 start;
	__le32 size;
} __attribute__((__packed__));

struct device;
struct firmware;

bool is_timeout_disabled(void);
int qcom_mdt_write_image_info(struct device *dev,
		struct qcom_mdt_image_info *info,
		unsigned int qcom_mdt_image_id);
ssize_t qcom_mdt_get_size(const struct firmware *fw);
int qcom_mdt_load(struct device *dev, const struct firmware *fw,
		  const char *fw_name, int pas_id, void *mem_region,
		  phys_addr_t mem_phys, size_t mem_size,
		  phys_addr_t *reloc_base);

#endif
