// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#ifndef _IPAHAL_H_
#define _IPAHAL_H_

#include <linux/types.h>

#include "ipa_dma.h"

/* The IPA implements offloaded packet filtering and routing
 * capabilities.  This is managed by programming tables of rules
 * that define the processing that should be performed by the IPA
 * and the conditions under which they should be applied.  Each
 * route or filter table entry is a DMA address that refers to the
 * routing or filtering rule.
 *
 * Values could differ for different versions of IPA hardware.
 * These values are for v3.5.1, found in the SDM845.
 */
#define IPA_HW_TBL_SYSADDR_ALIGN	128
#define IPA_TABLE_ENTRY_SIZE		sizeof(u64)
#define IPA_FILTER_SIZE			8
#define IPA_ROUTE_SIZE			8

/**
 * ipahal_dma_shared_mem_write_pyld() - Write to shared memory command payload
 *
 * Return a pointer to the payload for a DMA shared memory write immediate
 * command, or null if one can't be allocated.  Result is dynamically
 * allocated, and caller must ensure it gets released by providing it to
 * ipahal_destroy_imm_cmd() when it is no longer needed.
 *
 * Return:	 Pointer to the immediate command payload, or NULL
 */
void *ipahal_dma_shared_mem_write_pyld(struct ipa_dma_mem *mem, u32 offset);

/**
 * ipahal_hdr_init_local_pyld() - Header initialization command payload
 * mem:		DMA buffer containing data for initialization
 * offset:	Where in location IPA local memory to write
 *
 * Return a pointer to the payload for a header init local immediate
 * command, or null if one can't be allocated.  Caller must ensure result
 * gets released by providing it to ipahal_destroy_imm_cmd().
 *
 * Return:	 Pointer to the immediate command payload, or NULL
 */
void *ipahal_hdr_init_local_pyld(struct ipa_dma_mem *mem, u32 offset);

/**
 * ipa_ip_fltrt_init_pyld() - IP filter/routing table initialization payload
 * mem:		The IPv4 or IPv6 routing or filter table data to be written
 * hash_offset:	The location in IPA memory for a hashed table
 * nhash_offset: The location in IPA memory for a non-hashed table
 *
 * Common function used for initializing the payload for an IPv4 or
 * IPv6 filtering or routing init immediate command.  Caller must
 * ensure result gets released by providing it to ipahal_destroy_imm_cmd().
 *
 * Return:	 Pointer to the immediate command payload, or NULL
 */
void *ipa_imm_ip_fltrt_init_pyld(dma_addr_t phys, size_t size, u32 hash_offset,
				 u32 nhash_offset);

/**
 * ipahal_dma_task_32b_addr_pyld() - 32-bit DMA task command payload
 * mem:		DMA memory involved in the task
 *
 * Return a pointer to the payload for DMA task 32-bit address immediate
 * command, or null if one can't be allocated.  Caller must ensure result
 * gets released by providing it to ipahal_destroy_imm_cmd().
 */
void *ipahal_dma_task_32b_addr_pyld(struct ipa_dma_mem *mem);

/**
 * ipahal_payload_free() - Release an allocated immediate command payload
 * @payload:	Payload to be released
 */
void ipahal_payload_free(void *payload);

/**
 * enum ipahal_pkt_status_opcode - Packet Status Opcode
 * @IPAHAL_STATUS_OPCODE_PACKET_2ND_PASS: Packet Status generated as part of
 *  IPA second processing pass for a packet (i.e. IPA XLAT processing for
 *  the translated packet).
 *
 *  The values assigned here are assumed by ipa_pkt_status_parse()
 *  to match values returned in the status_opcode field of a
 *  ipa_pkt_status_hw structure inserted by the IPA in received
 *  buffer.
 */
enum ipahal_pkt_status_opcode {
	IPAHAL_PKT_STATUS_OPCODE_PACKET			= 0x01,
	IPAHAL_PKT_STATUS_OPCODE_NEW_FRAG_RULE		= 0x02,
	IPAHAL_PKT_STATUS_OPCODE_DROPPED_PACKET		= 0x04,
	IPAHAL_PKT_STATUS_OPCODE_SUSPENDED_PACKET	= 0x08,
	IPAHAL_PKT_STATUS_OPCODE_LOG			= 0x10,
	IPAHAL_PKT_STATUS_OPCODE_DCMP			= 0x20,
	IPAHAL_PKT_STATUS_OPCODE_PACKET_2ND_PASS	= 0x40,
};

/**
 * enum ipahal_pkt_status_exception - Packet Status exception type
 * @IPAHAL_PKT_STATUS_EXCEPTION_PACKET_LENGTH: formerly IHL exception.
 *
 * Note: IPTYPE, PACKET_LENGTH and PACKET_THRESHOLD exceptions means that
 *  partial / no IP processing took place and corresponding Status Mask
 *  fields should be ignored. Flt and rt info is not valid.
 *
 * NOTE:: Any change to this enum, need to change to
 *	ipahal_pkt_status_exception_to_str array as well.
 */
enum ipahal_pkt_status_exception {
	IPAHAL_PKT_STATUS_EXCEPTION_NONE = 0,
	IPAHAL_PKT_STATUS_EXCEPTION_DEAGGR,
	IPAHAL_PKT_STATUS_EXCEPTION_IPTYPE,
	IPAHAL_PKT_STATUS_EXCEPTION_PACKET_LENGTH,
	IPAHAL_PKT_STATUS_EXCEPTION_PACKET_THRESHOLD,
	IPAHAL_PKT_STATUS_EXCEPTION_FRAG_RULE_MISS,
	IPAHAL_PKT_STATUS_EXCEPTION_SW_FILT,
	/* NAT and IPv6CT have the same value at HW.
	 * NAT for IPv4 and IPv6CT for IPv6 exceptions
	 */
	IPAHAL_PKT_STATUS_EXCEPTION_NAT,
	IPAHAL_PKT_STATUS_EXCEPTION_IPV6CT,
	IPAHAL_PKT_STATUS_EXCEPTION_MAX,
};

/**
 * enum ipahal_pkt_status_mask - Packet Status bitmask values of
 *  the contained flags. This bitmask indicates flags on the properties of
 *  the packet as well as IPA processing it may had.
 * @TAG_VALID: Flag specifying if TAG and TAG info valid?
 * @CKSUM_PROCESS: CSUM block processing flag: Was pkt processed by csum block?
 *  If so, csum trailer exists
 */
enum ipahal_pkt_status_mask {
	/* Other values are defined but are not specifically handled yet. */
	IPAHAL_PKT_STATUS_MASK_CKSUM_PROCESS	= 0x0100,
};

/**
 * struct ipahal_pkt_status - IPA status packet abstracted payload.
 * @status_opcode: The type of status (Opcode).
 * @exception: The first exception that took place.
 *  In case of exception, endp_src_idx and pkt_len are always valid.
 * @status_mask: Bit mask for flags on several properties on the packet
 *  and processing it may passed at IPA.
 * @pkt_len: Pkt pyld len including hdr and retained hdr if used. Does
 *  not include padding or checksum trailer len.
 * @endp_src_idx: Source end point index.
 * @endp_dest_idx: Destination end point index.
 *  Not valid in case of exception
 * @metadata: meta data value used by packet
 * @rt_miss: Routing miss flag: Was their a routing rule miss?
 *
 * This structure describes the status packet fields for the following
 * status values: IPA_STATUS_PACKET, IPA_STATUS_DROPPED_PACKET,
 * IPA_STATUS_SUSPENDED_PACKET.  Other status types have different status
 * packet structure.  Note that the hardware supplies additional status
 * information that is currently unused.
 */
struct ipahal_pkt_status {
	enum ipahal_pkt_status_opcode status_opcode;
	enum ipahal_pkt_status_exception exception;
	enum ipahal_pkt_status_mask status_mask;
	u32 pkt_len;
	u8 endp_src_idx;
	u8 endp_dest_idx;
	u32 metadata;
	bool rt_miss;
};

/**
 * ipahal_pkt_status_get_size() - Get size of a hardware packet status
 */
u32 ipahal_pkt_status_get_size(void);

/* ipahal_pkt_status_parse() - Parse packet status payload
 * @unparsed_status:	Packet status read from hardware
 * @status:		Buffer to hold parsed status information
 */
void ipahal_pkt_status_parse(const void *unparsed_status,
			     struct ipahal_pkt_status *status);

/* Does the given ID represent rule miss? */
bool ipahal_is_rule_miss_id(u32 id);

void ipa_route_table_init(u32 route_count, struct ipa_dma_mem *mem);
void ipa_filter_table_init(u32 filter_count, u32 filter_bitmap,
			   struct ipa_dma_mem *mem);

#endif /* _IPAHAL_H_ */
