// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#ifndef _IPAHAL_H_
#define _IPAHAL_H_
#include <linux/if_ether.h>
#include "ipa_common_i.h"

/* The IPA implements offloaded packet filtering and routing
 * capabilities.  This is managed by programming IPA-resident
 * tables of rules that define the processing that should be
 * performed by the IPA and the conditions under which they
 * should be applied.  Aspects of these rules are constrained
 * by things like table entry sizes and alignment requirements;
 * all of these are in units of bytes.  These definitions are
 * subject to some constraints:
 * - IPA_HW_TBL_WIDTH must be non-zero
 * - IPA_HW_TBL_SYSADDR_ALIGN must be a non-zero power of 2
 * - IPA_HW_TBL_HDR_WIDTH must be non-zero
 *
 * Values could differ for different versions of IPA hardware.
 * These values are for v3.5.1, found in the SDM845.
 */
#define IPA_HW_TBL_WIDTH		8
#define IPA_HW_TBL_SYSADDR_ALIGN	128
#define IPA_HW_TBL_HDR_WIDTH		8

/* Immediate commands abstracted structures */

/* struct ipahal_imm_cmd_pyld - Immediate cmd payload information
 * @len: length of the buffer
 * @opcode: opcode of the immediate command
 * The immediate command type-specific payload implicitly follows these
 * common fields
 */
struct ipahal_imm_cmd_pyld {
	u16 len;
	u16 opcode;
};

/* Return the address of type-specific data portion of an immediate
 * command payload.
 */
static inline void *ipahal_imm_cmd_pyld_data(struct ipahal_imm_cmd_pyld *pyld)
{
	return pyld + 1;
}

/* Immediate command Function APIs */

/* Return a pointer to the payload for a DMA shared memory write immediate
 * command, or null if one can't be allocated.  Result is dynamically
 * allocated, and caller must ensure it gets released by providing it to
 * ipahal_destroy_imm_cmd() when it is no longer needed.
 *
 * mem		a DMA buffer containing data to be written (up to 2KB)
 * offset	is where to write in IPA local memory
 */
struct ipahal_imm_cmd_pyld *ipahal_dma_shared_mem_write_pyld(
				struct ipa_dma_mem *mem, u32 offset);

/* Return a pointer to the payload for a header init local immediate
 * command, or null if one can't be allocated.  Caller must ensure result
 * gets released by providing it to ipahal_destroy_imm_cmd().
 *
 * mem		a DMA buffer containing data to be written (up to 2KB)
 * offset	is the location IPA local memory to write
 */
struct ipahal_imm_cmd_pyld *ipahal_hdr_init_local_pyld(
				struct ipa_dma_mem *mem, u32 offset);

/* Return a pointer to the payload for an IPv4 routing init immediate
 * command, or null if one can't be allocated.  Caller must ensure result
 * gets released by providing it to ipahal_destroy_imm_cmd().
 *
 * mem		contains the IPv4 routing table data to be written
 * hash_offset	is the locatin in IPA memory for hashed routing table
 * nhash_offset	is the locatin in IPA memory for non-hashed routing table
 */
struct ipahal_imm_cmd_pyld *ipahal_ip_v4_routing_init_pyld(
				struct ipa_dma_mem *mem,
				u32 hash_offset, u32 nhash_offset);

/* Return a pointer to the payload for an IPv6 routing init immediate
 * command, or null if one can't be allocated.  Caller must ensure result
 * gets released by providing it to ipahal_destroy_imm_cmd().
 *
 * mem		contains the IPv6 routing table data to be written
 * hash_offset	is the locatin in IPA memory for hashed routing table
 * nhash_offset	is the locatin in IPA memory for non-hashed routing table
 */
struct ipahal_imm_cmd_pyld *ipahal_ip_v6_routing_init_pyld(
				struct ipa_dma_mem *mem,
				u32 hash_offset, u32 nhash_offset);

/* Return a pointer to the payload for an IPv4 filter init immediate
 * command, or null if one can't be allocated.  Caller must ensure result
 * gets released by providing it to ipahal_destroy_imm_cmd().
 *
 * mem		contains the IPv4 filter table data to be written
 * hash_offset	is the locatin in IPA memory for hashed routing table
 * nhash_offset	is the locatin in IPA memory for non-hashed routing table
 */
struct ipahal_imm_cmd_pyld *ipahal_ip_v4_filter_init_pyld(
				struct ipa_dma_mem *mem,
				u32 hash_offset, u32 nhash_offset);

/* Return a pointer to the payload for an IPv6 filter init immediate
 * command, or null if one can't be allocated.  Caller must ensure result
 * gets released by providing it to ipahal_destroy_imm_cmd().
 *
 * mem		contains the IPv6 filter table data to be written
 * hash_offset	is the locatin in IPA memory for hashed routing table
 * nhash_offset	is the locatin in IPA memory for non-hashed routing table
 */
struct ipahal_imm_cmd_pyld *ipahal_ip_v6_filter_init_pyld(
				struct ipa_dma_mem *mem,
				u32 hash_offset, u32 nhash_offset);

/* Return a pointer to the payload for DMA task 32-bit address immediate
 * command, or null if one can't be allocated.  Caller must ensure result
 * gets released by providing it to ipahal_destroy_imm_cmd().
 *
 * mem is the dat to transfer (it will be discarded)
 */
struct ipahal_imm_cmd_pyld *ipahal_dma_task_32b_addr_pyld(
				struct ipa_dma_mem *mem);

/* ipahal_destroy_imm_cmd() - Destroy/Release bulk that was built
 *  by the construction functions
 */
static inline void ipahal_destroy_imm_cmd(struct ipahal_imm_cmd_pyld *pyld)
{
	kfree(pyld);
}

/* IPA Status packet Structures and Function APIs */

/* enum ipahal_pkt_status_opcode - Packet Status Opcode
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

/* enum ipahal_pkt_status_exception - Packet Status exception type
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

/* enum ipahal_pkt_status_mask - Packet Status bitmask values of
 *  the contained flags. This bitmask indicates flags on the properties of
 *  the packet as well as IPA processing it may had.
 * @TAG_VALID: Flag specifying if TAG and TAG info valid?
 * @CKSUM_PROCESS: CSUM block processing flag: Was pkt processed by csum block?
 *  If so, csum trailer exists
 */
enum ipahal_pkt_status_mask {
	/* Other values are defined but are not specifically handed yet. */
	IPAHAL_PKT_STATUS_MASK_TAG_VALID	= 0x0010,
	IPAHAL_PKT_STATUS_MASK_CKSUM_PROCESS	= 0x0100,
};

/* enum ipahal_pkt_status_nat_type - Type of NAT
 *
 *  The values assigned here are assumed by ipa_pkt_status_parse() to
 *  match values returned in the nat_type field of a ipa_pkt_status_hw
 *  structure inserted by the IPA in received buffer.
 */
enum ipahal_pkt_status_nat_type {
	IPAHAL_PKT_STATUS_NAT_NONE	= 0,
	IPAHAL_PKT_STATUS_NAT_SRC	= 1,
	IPAHAL_PKT_STATUS_NAT_DST	= 2,
};

/* struct ipahal_pkt_status - IPA status packet abstracted payload.
 *  This structure describes the status packet fields for the
 *   following statuses: IPA_STATUS_PACKET, IPA_STATUS_DROPPED_PACKET,
 *   IPA_STATUS_SUSPENDED_PACKET.
 *  Other statuses types has different status packet structure.
 * @status_opcode: The Type of the status (Opcode).
 * @exception: The first exception that took place.
 *  In case of exception, src endp and pkt len are always valid.
 * @status_mask: Bit mask for flags on several properties on the packet
 *  and processing it may passed at IPA. See enum ipahal_pkt_status_mask
 * @pkt_len: Pkt pyld len including hdr and retained hdr if used. Does
 *  not include padding or checksum trailer len.
 * @endp_src_idx: Source end point index.
 * @endp_dest_idx: Destination end point index.
 *  Not valid in case of exception
 * @metadata: meta data value used by packet
 * @flt_local: Filter table location flag: Does matching flt rule belongs to
 *  flt tbl that resides in lcl memory? (if not, then system mem)
 * @flt_hash: Filter hash hit flag: Does matching flt rule was in hash tbl?
 * @flt_global: Global filter rule flag: Does matching flt rule belongs to
 *  the global flt tbl? (if not, then the per endp tables)
 * @flt_ret_hdr: Retain header in filter rule flag: Does matching flt rule
 *  specifies to retain header?
 * @flt_miss: Filtering miss flag: Was their a filtering rule miss?
 *   In case of miss, all flt info to be ignored
 * @flt_rule_id: The ID of the matching filter rule (if no miss).
 *  This info can be combined with endp_src_idx to locate the exact rule.
 * @rt_local: Route table location flag: Does matching rt rule belongs to
 *  rt tbl that resides in lcl memory? (if not, then system mem)
 * @rt_hash: Route hash hit flag: Does matching rt rule was in hash tbl?
 * @ucp: UC Processing flag
 * @rt_tbl_idx: Index of rt tbl that contains the rule on which was a match
 * @rt_miss: Routing miss flag: Was their a routing rule miss?
 * @rt_rule_id: The ID of the matching rt rule. (if no miss). This info
 *  can be combined with rt_tbl_idx to locate the exact rule.
 * @nat_hit: NAT hit flag: Was their NAT hit?
 * @nat_entry_idx: Index of the NAT entry used of NAT processing
 * @nat_type: Defines the type of the NAT operation:
 * @tag_info: S/W defined value provided via immediate command
 * @seq_num: Per source endp unique packet sequence number
 * @time_of_day_ctr: running counter from IPA clock
 * @hdr_local: Header table location flag: In header insertion, was the header
 *  taken from the table resides in local memory? (If no, then system mem)
 * @hdr_offset: Offset of used header in the header table
 * @frag_hit: Frag hit flag: Was their frag rule hit in H/W frag table?
 * @frag_rule: Frag rule index in H/W frag table in case of frag hit
 */
struct ipahal_pkt_status {
	enum ipahal_pkt_status_opcode status_opcode;
	enum ipahal_pkt_status_exception exception;
	u32 status_mask;
	u32 pkt_len;
	u8 endp_src_idx;
	u8 endp_dest_idx;
	u32 metadata;
	bool flt_local;
	bool flt_hash;
	bool flt_global;
	bool flt_ret_hdr;
	bool flt_miss;
	u16 flt_rule_id;
	bool rt_local;
	bool rt_hash;
	bool ucp;
	u8 rt_tbl_idx;
	bool rt_miss;
	u16 rt_rule_id;
	bool nat_hit;
	u16 nat_entry_idx;
	enum ipahal_pkt_status_nat_type nat_type;
	u64 tag_info;
	u8 seq_num;
	u32 time_of_day_ctr;
	bool hdr_local;
	u16 hdr_offset;
	bool frag_hit;
	u8 frag_rule;
};

/* ipahal_pkt_status_get_size() - Get H/W size of packet status
 */
u32 ipahal_pkt_status_get_size(void);

/* ipahal_pkt_status_parse() - Parse Packet Status payload to abstracted form
 * @unparsed_status: Pointer to H/W format of the packet status as read from H/W
 * @status: Pointer to pre-allocated buffer where the parsed info will be stored
 */
void ipahal_pkt_status_parse(const void *unparsed_status,
			     struct ipahal_pkt_status *status);

int ipahal_init(void);
void ipahal_exit(void);

/* Does the given ID represents rule miss? */
bool ipahal_is_rule_miss_id(u32 id);

int ipahal_rt_generate_empty_img(u32 route_count, struct ipa_dma_mem *mem);
int ipahal_flt_generate_empty_img(u64 ep_bitmap, struct ipa_dma_mem *mem);

/* ipahal_free_empty_img() - free empty filter or route image
 */
void ipahal_free_empty_img(struct ipa_dma_mem *mem);

#endif /* _IPAHAL_H_ */
