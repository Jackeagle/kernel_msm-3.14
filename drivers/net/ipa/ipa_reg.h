// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018 Linaro Ltd.
 */
#ifndef _IPA_REG_H_
#define _IPA_REG_H_

/* The IPA code abstracts the details of its 32-bit registers, allowing access
 * to them to be done generically.  The original motivation for this was that
 * the field width and/or position for values stored in some registers differed
 * for different versions of IPA hardware.  Abstracting access this way allows
 * code that uses such registers to be simpler, describing how register fields
 * are used without proliferating special-case code that is dependent on
 * hardware version.
 *
 * Each IPA register has a name, which is one of the values in the "ipa_reg"
 * enumerated type (e.g., IPA_ENABLED_PIPES).  The offset (memory address) of
 * the register having a given name is maintained internal to the "ipa_reg"
 * module.
 *
 * For simple registers that hold a single 32-bit value, two functions provide
 * access to the register:
 *	u32 ipa_read_reg(enum ipa_reg reg);
 *	void ipa_write_reg(enum ipa_reg reg, u32 val);
 *
 * Some registers are "N-parameterized."  This means there is a set of
 * registers having identical format, and each is accessed by supplying
 * the "N" value to select which register is intended.  The names for
 * N-parameterized registers have an "_N" suffix (e.g. IPA_IRQ_STTS_EE_N).
 * Details of computing the offset for such registers are maintained internal
 * to the "ipa_reg" module.  For simple registers holding a single 32-bit
 * value, these functions provide access to N-parameterized registers:
 *	u32 ipa_read_reg_n(enum ipa_reg reg, u32 n);
 *	void ipa_write_reg_n(enum ipa_reg reg, u32 n, u32 val);
 *
 * Some registers contain fields less than 32 bits wide (call these "field
 * registers").  For each such register a "field structure" is defined to
 * represent the values of the individual fields within the register.  The
 * name of the structure matches the name of the register (in lower case).
 * For example, the individual fields in the IPA_ROUTE register are represented
 * by the field structure named ipa_reg_route.
 *
 * The position and width of fields within a register are defined (in
 * "ipa_reg.c") using field masks, and the names of the members in the field
 * structure associated with such registers match the names of the bit masks
 * that define the fields.  (E.g., ipa_reg_route->route_dis is used to
 * represent the field defined by the ROUTE_DIS field mask.)
 *
 * "Field registers" are accessed using these functions:
 *	void ipa_read_reg_fields(enum ipa_reg reg, void *fields);
 *	void ipa_write_reg_fields(enum ipa_reg reg, const void *fields);
 * The "fields" parameter in both cases is the address of the "field structure"
 * associated with the register being accessed.  When reading, the structure is
 * filled by ipa_read_reg_fields() with values found in the register's
 * fields.  (All fields will be filled; there is no need for the caller to
 * initialize the passed-in structure before the call.)  When writing, the
 * caller initializes the structure with all values that should be written to
 * the fields in the register.
 *
 * "Field registers" can also be N-parameterized, in which case they are
 * accessed using these functions:
 *	void ipa_read_reg_n_fields(enum ipa_reg reg, u32 n, void *fields);
 *	void ipa_write_reg_n_fields(enum ipa_reg reg, u32 n,
 *				    const void *fields);
 */

/* Register names */
enum ipa_reg {
	IPA_ROUTE,
	IPA_IRQ_STTS_EE_N,
	IPA_IRQ_EN_EE_N,
	IPA_IRQ_CLR_EE_N,
	IPA_IRQ_SUSPEND_INFO_EE_N,
	IPA_SUSPEND_IRQ_EN_EE_N,
	IPA_SUSPEND_IRQ_CLR_EE_N,
	IPA_BCR,
	IPA_ENABLED_PIPES,
	IPA_TAG_TIMER,
	IPA_STATE_AGGR_ACTIVE,
	IPA_ENDP_INIT_HDR_N,
	IPA_ENDP_INIT_HDR_EXT_N,
	IPA_ENDP_INIT_AGGR_N,
	IPA_AGGR_FORCE_CLOSE,
	IPA_ENDP_INIT_MODE_N,
	IPA_ENDP_INIT_CTRL_N,
	IPA_ENDP_INIT_DEAGGR_N,
	IPA_ENDP_INIT_SEQ_N,
	IPA_ENDP_INIT_CFG_N,
	IPA_IRQ_EE_UC_N,
	IPA_ENDP_INIT_HDR_METADATA_MASK_N,
	IPA_SHARED_MEM_SIZE,
	IPA_SRAM_DIRECT_ACCESS_N,
	IPA_LOCAL_PKT_PROC_CNTXT_BASE,
	IPA_ENDP_STATUS_N,
	IPA_ENDP_FILTER_ROUTER_HSH_CFG_N,
	IPA_SRC_RSRC_GRP_01_RSRC_TYPE_N,
	IPA_SRC_RSRC_GRP_23_RSRC_TYPE_N,
	IPA_DST_RSRC_GRP_01_RSRC_TYPE_N,
	IPA_DST_RSRC_GRP_23_RSRC_TYPE_N,
	IPA_QSB_MAX_WRITES,
	IPA_QSB_MAX_READS,
	IPA_IDLE_INDICATION_CFG,
};

/* struct ipa_reg_route - IPA_ROUTE field structure
 *
 * @route_dis: route disable
 * @route_def_pipe: route default pipe
 * @route_def_hdr_table: route default header table
 * @route_def_hdr_ofst: route default header offset table
 * @route_frag_def_pipe: Default pipe to route fragmented exception
 *    packets and frag new rule statues, if source pipe does not have
 *    a notification status pipe defined.
 * @route_def_retain_hdr: default value of retain header. It is used
 *    when no rule was hit
 */
struct ipa_reg_route {
	u32 route_dis;
	u32 route_def_pipe;
	u32 route_def_hdr_table;
	u32 route_def_hdr_ofst;
	u32 route_frag_def_pipe;
	u32 route_def_retain_hdr;
};

/* ipa_reg_endp_init_hdr - ENDP_INIT_HDR_N field structure
 *
 * @hdr_len:
 * @hdr_ofst_metadata_valid:
 * @hdr_ofst_metadata:
 * @hdr_additional_const_len:
 * @hdr_ofst_pkt_size_valid:
 * @hdr_ofst_pkt_size:
 * @hdr_a5_mux:
 * @hdr_len_inc_deagg_hdr:
 * @hdr_metadata_reg_valid:
*/
struct ipa_reg_endp_init_hdr {
	u32 hdr_len;
	u32 hdr_ofst_metadata_valid;
	u32 hdr_ofst_metadata;
	u32 hdr_additional_const_len;
	u32 hdr_ofst_pkt_size_valid;
	u32 hdr_ofst_pkt_size;
	u32 hdr_a5_mux;
	u32 hdr_len_inc_deagg_hdr;
	u32 hdr_metadata_reg_valid;
};

/* ipa_reg_endp_init_hdr_ext - IPA_ENDP_INIT_HDR_EXT_N field structure
 *
 * @hdr_endianness:
 * @hdr_total_len_or_pad_valid:
 * @hdr_total_len_or_pad:
 * @hdr_payload_len_inc_padding:
 * @hdr_total_len_or_pad_offset:
 * @hdr_pad_to_alignment:
 */
struct ipa_reg_endp_init_hdr_ext {
	u32 hdr_endianness;		/* 0 = little endian; 1 = big endian */
	u32 hdr_total_len_or_pad_valid;
	u32 hdr_total_len_or_pad;	/* 0 = pad; 1 = total_len */
	u32 hdr_payload_len_inc_padding;
	u32 hdr_total_len_or_pad_offset;
	u32 hdr_pad_to_alignment;
};

/** enum ipa_aggr_en - aggregation setting type in IPA end-point */
enum ipa_aggr_en {
	IPA_BYPASS_AGGR		= 0,
	IPA_ENABLE_AGGR		= 1,
	IPA_ENABLE_DEAGGR	= 2,
};

/** enum ipa_aggr_type - type of aggregation in IPA end-point */
enum ipa_aggr_type {
	IPA_MBIM_16 = 0,
	IPA_HDLC    = 1,
	IPA_TLP	    = 2,
	IPA_RNDIS   = 3,
	IPA_GENERIC = 4,
	IPA_QCMAP   = 6,
};

#define IPA_AGGR_TIME_LIMIT_DEFAULT	1	/* XXX units? */

/** struct ipa_reg_endp_init_aggr - IPA_ENDP_INIT_AGGR_N field structure
 *
 * @aggr_en: bypass aggregation, enable aggregation, or deaggregation
 *	     (enum ipa_aggr_en)
 * @aggr_type: type of aggregation (enum ipa_aggr_type aggr)
 * @aggr_byte_limit: aggregated byte limit in KB, or no limit if 0
 *		     (producer pipes only)
 * @aggr_time_limit: time limit before close of aggregation, or
 *		     aggregation disabled if 0 (producer pipes only)
 * @aggr_pkt_limit: packet limit before closing aggregation, or no
 *		    limit if 0 (producer pipes only) XXX units
 * @aggr_sw_eof_active: whether EOF closes aggregation--in addition to
 *			hardware aggregation configuration (producer
 *			pipes configured for generic aggregation only)
 * @aggr_force_close: whether to force a close XXX verify/when
 * @aggr_hard_byte_limit_en: whether aggregation frames close *before*
 * 			     byte count has crossed limit, rather than
 * 			     after XXX producer only?
 */
struct ipa_reg_endp_init_aggr {
	u32 aggr_en;		/* enum ipa_aggr_en */
	u32 aggr_type;		/* enum ipa_aggr_type */
	u32 aggr_byte_limit;
	u32 aggr_time_limit;
	u32 aggr_pkt_limit;
	u32 aggr_sw_eof_active;
	u32 aggr_force_close;
	u32 aggr_hard_byte_limit_en;
};

/* struct ipa_aggr_force_close - IPA_AGGR_FORCE_CLOSE field structure
 *
 * @pipe_bitmap: bitmap of pipes on which aggregation should be closed
 */
struct ipa_reg_aggr_force_close {
	u32 pipe_bitmap;
};

/** enum ipa_mode - mode setting type in IPA end-point
 * @BASIC: basic mode
 * @ENABLE_FRAMING_HDLC: not currently supported
 * @ENABLE_DEFRAMING_HDLC: not currently supported
 * @DMA: all data arriving IPA will not go through IPA logic blocks, this
 *  allows IPA to work as DMA for specific pipes.
 */
enum ipa_mode {
	IPA_BASIC			= 0,
	IPA_ENABLE_FRAMING_HDLC		= 1,
	IPA_ENABLE_DEFRAMING_HDLC	= 2,
	IPA_DMA				= 3,
};

/* struct ipa_reg_endp_init_mode - IPA_ENDP_INIT_MODE_N field structure
 *
 * @mode: endpoint mode setting (enum ipa_mode_type)
 * @dst_pipe_index: This parameter specifies destination output-pipe-packets
 *	will be routed to. Valid for DMA mode only and for Input
 *	Pipes only (IPA Consumer)
 * @byte_threshold:
 * @pipe_replication_en:
 * @pad_en:
 * @hdr_ftch_disable:
 */
struct ipa_reg_endp_init_mode {
	u32 mode;		/* enum ipa_mode */
	u32 dest_pipe_index;
	u32 byte_threshold;
	u32 pipe_replication_en;
	u32 pad_en;
	u32 hdr_ftch_disable;
};

/* struct ipa_ep_init_ctrl - IPA_ENDP_INIT_CTRL_N field structure
 *
 * @ipa_ep_suspend: 0 - ENDP is enabled, 1 - ENDP is suspended (disabled).
 *			Valid for PROD Endpoints
 * @ipa_ep_delay:   0 - ENDP is free-running, 1 - ENDP is delayed.
 *			SW controls the data flow of an endpoint usind this bit.
 *			Valid for CONS Endpoints
 */
struct ipa_reg_endp_init_ctrl {
	u32 endp_suspend;
	u32 endp_delay;
};

/** struct ipa_reg_endp_init_deaggr - IPA_ENDP_INIT_DEAGGR_N field structure
 *
 * @deaggr_hdr_len:
 * @packet_offset_valid:
 * @packet_offset_location:
 * @max_packet_len:
 */
struct ipa_reg_endp_init_deaggr {
	u32 deaggr_hdr_len;
	u32 packet_offset_valid;
	u32 packet_offset_location;
	u32 max_packet_len;
};

/* HPS, DPS sequencers types */
enum ipa_seq_type {
	IPA_SEQ_DMA_ONLY			= 0x00,
	/* Packet Processing + no decipher + uCP (for Ethernet Bridging) */
	IPA_SEQ_PKT_PROCESS_NO_DEC_UCP		= 0x02,
	/* 2 Packet Processing pass + no decipher + uCP */
	IPA_SEQ_2ND_PKT_PROCESS_PASS_NO_DEC_UCP	= 0x04,
	/* DMA + DECIPHER/CIPHER */
	IPA_SEQ_DMA_DEC				= 0x11,
	/* COMP/DECOMP */
	IPA_SEQ_DMA_COMP_DECOMP			= 0x20,
	/* Invalid sequencer type */
	IPA_SEQ_INVALID				= 0xff,
};

/** struct ipa_ep_init_seq - IPA_ENDP_INIT_SEQ_N field structure
 *
 * @hps_seq_type: type of HPS sequencer (enum ipa_hps_dps_sequencer_type)
 */
struct ipa_reg_endp_init_seq {
	u32 hps_seq_type;
	u32 dps_seq_type;
	u32 hps_rep_seq_type;
	u32 dps_rep_seq_type;
};

/** enum ipa_cs_offload_en - checksum offload setting */
enum ipa_cs_offload_en {
	IPA_CS_OFFLOAD_NONE	= 0,
	IPA_CS_OFFLOAD_UL	= 1,
	IPA_CS_OFFLOAD_DL	= 2,
	IPA_CS_RSVD
};

/** struct ipa_reg_endp_init_cfg - IPA_ENDP_INIT_CFG_N field structure
 *
 * @frag_offload_en:
 * @cs_offload_en: type of offloading (enum ipa_cs_offload)
 * @cs_metadata_hdr_offset: offload (in 4-byte words) within header
 * where 4-byte checksum metadata begins.  Valid only for consumer
 * pipes.
 * @cs_gen_qmb_master_sel:
 */
struct ipa_reg_endp_init_cfg {
	u32 frag_offload_en;
	u32 cs_offload_en;		/* enum ipa_cs_offload_en */
	u32 cs_metadata_hdr_offset;
	u32 cs_gen_qmb_master_sel;
};

/** struct ipa_reg_endp_init_hdr_metadata_mask -
 *	IPA_ENDP_INIT_HDR_METADATA_MASK_N field structure
 *
 * @metadata_mask: mask specifying metadata bits to write
 *
 *  Valid for producer pipes only.
 */
struct ipa_reg_endp_init_hdr_metadata_mask {
	u32 metadata_mask;
};

/* struct ipa_reg_shared_mem_size - SHARED_MEM_SIZE field structure
 *
 * @shared_mem_size: Available size [in 8Bytes] of SW partition within
 *	IPA shared memory.
 * @shared_mem_baddr: Offset of SW partition within IPA
 *	shared memory[in 8Bytes]. To get absolute address of SW partition,
 *	add this offset to IPA_SRAM_DIRECT_ACCESS_N baddr.
 */
struct ipa_reg_shared_mem_size {
	u32 shared_mem_size;
	u32 shared_mem_baddr;
};

/* struct ipa_reg_endp_status - IPA_ENDP_STATUS_N field structure
 *
 * @status_en: Determines if end point supports Status Indications. SW should
 *	set this bit in order to enable Statuses. Output Pipe - send
 *	Status indications only if bit is set. Input Pipe - forward Status
 *	indication to STATUS_ENDP only if bit is set. Valid for Input
 *	and Output Pipes (IPA Consumer and Producer)
 * @status_endp: Statuses generated for this endpoint will be forwarded to the
 *	specified Status End Point. Status endpoint needs to be
 *	configured with STATUS_EN=1 Valid only for Input Pipes (IPA
 *	Consumer)
 * @status_location: Location of PKT-STATUS on destination pipe.
 *	If set to 0 (default), PKT-STATUS will be appended before the packet
 *	for this endpoint. If set to 1, PKT-STATUS will be appended after the
 *	packet for this endpoint. Valid only for Output Pipes (IPA Producer)
 * @status_pkt_suppress:
 */
struct ipa_reg_endp_status {
	u32 status_en;
	u32 status_endp;
	u32 status_location;
	u32 status_pkt_suppress;
};

/* struct ipa_hash_tuple - structure used to group filter and route fields in
 *			   struct ipa_ep_filter_router_hsh_cfg
 *
 * Each field is a Boolean value, indicating whether that particular value
 * should be used for filtering or routing.
 *
 * @src_id: pipe number for flt, table index for rt
 * @src_ip_addr: IP source address
 * @dst_ip_addr: IP destination address
 * @src_port: L4 source port
 * @dst_port: L4 destination port
 * @protocol: IP protocol field
 * @meta_data: packet meta-data
 */
struct ipa_reg_hash_tuple {
	u32 src_id;	/* pipe number in flt, table index in rt */
	u32 src_ip;
	u32 dst_ip;
	u32 src_port;
	u32 dst_port;
	u32 protocol;
	u32 metadata;
};

/* struct ipa_ep_filter_router_hsh_cfg - IPA_ENDP_FILTER_ROUTER_HSH_CFG_N
 * 					 field structure
 *
 * @flt: Hash tuple info for filtering
 * @undefined1:
 * @rt: Hash tuple info for routing
 * @undefined2:
 * @undefinedX: Undefined/Unused bit fields set of the register
 */
struct ipa_ep_filter_router_hsh_cfg {
	struct ipa_reg_hash_tuple flt;
	u32 undefined1;
	struct ipa_reg_hash_tuple rt;
	u32 undefined2;
};

/* struct ipa_reg_rsrc_grp_cfg - IPA_{SRC,DST}_RSRC_GRP_{02}{13}Y_RSRC_TYPE_N
 * 				 field structure
 *
 * This field structure is used for accessing the following registers:
 *	IPA_SRC_RSRC_GRP_01_RSRC_TYPE_N IPA_SRC_RSRC_GRP_23_RSRC_TYPE_N
 *	IPA_DST_RSRC_GRP_01_RSRC_TYPE_N IPA_DST_RSRC_GRP_23_RSRC_TYPE_N
 *
 * @x_min - first group min value
 * @x_max - first group max value
 * @y_min - second group min value
 * @y_max - second group max value
 */
struct ipa_reg_rsrc_grp_cfg {
	u32 x_min;
	u32 x_max;
	u32 y_min;
	u32 y_max;
};

/* struct ipa_reg_qsb_max_writes - IPA_QSB_MAX_WRITES field register
 *
 * @qmb_0_max_writes: Max number of outstanding writes for GEN_QMB_0
 * @qmb_1_max_writes: Max number of outstanding writes for GEN_QMB_1
 */
struct ipa_reg_qsb_max_writes {
	u32 qmb_0_max_writes;
	u32 qmb_1_max_writes;
};

/* struct ipa_reg_qsb_max_reads - IPA_QSB_MAX_READS field register
 *
 * @qmb_0_max_reads: Max number of outstanding reads for GEN_QMB_0
 * @qmb_1_max_reads: Max number of outstanding reads for GEN_QMB_1
 */
struct ipa_reg_qsb_max_reads {
	u32 qmb_0_max_reads;
	u32 qmb_1_max_reads;
};

/* struct ipa_reg_idle_indication_cfg - IPA_IDLE_INDICATION_CFG field register
 *
 * @const_non_idle_enable: enable the asserting of the IDLE value and DCD
 * @enter_idle_debounce_thresh:	 configure the debounce threshold
 */
struct ipa_reg_idle_indication_cfg {
	u32 enter_idle_debounce_thresh;
	u32 const_non_idle_enable;
};

/* Initialize the IPA register subsystem */
void ipa_reg_init(void __iomem *base);
void ipa_reg_exit(void);

void ipa_reg_endp_init_hdr_cons(struct ipa_reg_endp_init_hdr *init_hdr,
				u32 header_size, u32 metadata_offset,
				u32 length_offset);
void ipa_reg_endp_init_hdr_prod(struct ipa_reg_endp_init_hdr *init_hdr,
				u32 header_size, u32 metadata_offset,
				u32 length_offset);
void ipa_reg_endp_init_hdr_ext_cons(struct ipa_reg_endp_init_hdr_ext *hdr_ext,
				    u32 pad_align, bool pad_included);
void ipa_reg_endp_init_hdr_ext_prod(struct ipa_reg_endp_init_hdr_ext *hdr_ext,
				    u32 pad_align);
void ipa_reg_endp_init_aggr_cons(struct ipa_reg_endp_init_aggr *init_aggr,
				 u32 byte_limit, u32 packet_limit,
				 bool close_on_eof);
void ipa_reg_endp_init_aggr_prod(struct ipa_reg_endp_init_aggr *init_aggr,
				 enum ipa_aggr_en aggr_en,
				 enum ipa_aggr_type aggr_type);
void ipa_reg_endp_init_mode_cons(struct ipa_reg_endp_init_mode *init_mode);
void ipa_reg_endp_init_mode_prod(struct ipa_reg_endp_init_mode *init_mode,
				 enum ipa_mode mode, u32 dest_endp);
void ipa_reg_endp_init_cfg_cons(struct ipa_reg_endp_init_cfg *init_cfg,
				enum ipa_cs_offload_en offload_type);
void ipa_reg_endp_init_cfg_prod(struct ipa_reg_endp_init_cfg *init_cfg,
				enum ipa_cs_offload_en offload_type,
				u32 metadata_offset);
void ipa_reg_endp_init_deaggr_cons(
		struct ipa_reg_endp_init_deaggr *init_deaggr);
void ipa_reg_endp_init_deaggr_prod(
		struct ipa_reg_endp_init_deaggr *init_deaggr);
void ipa_reg_endp_init_seq_cons(struct ipa_reg_endp_init_seq *init_seq);
void ipa_reg_endp_init_seq_prod(struct ipa_reg_endp_init_seq *init_seq,
				enum ipa_seq_type seq_type);
void ipa_reg_endp_init_hdr_metadata_mask_cons(
		struct ipa_reg_endp_init_hdr_metadata_mask *metadata_mask,
		u32 mask);
void ipa_reg_endp_init_hdr_metadata_mask_prod(
		struct ipa_reg_endp_init_hdr_metadata_mask *metadata_mask);
void ipa_reg_endp_status_cons(struct ipa_reg_endp_status *endp_status,
			      bool enable);
void ipa_reg_endp_status_prod(struct ipa_reg_endp_status *endp_status,
			      bool enable, u32 endp);

/* Get the offset of an n-parameterized register */
u32 ipa_reg_n_offset(enum ipa_reg reg, u32 n);

/* Get the offset of a register */
static inline u32 ipa_reg_offset(enum ipa_reg reg)
{
	return ipa_reg_n_offset(reg, 0);
}

/* ipa_read_reg_n() - Get the raw value of n-parameterized register */
u32 ipa_read_reg_n(enum ipa_reg reg, u32 n);

/* ipa_write_reg_n() - Write a raw value to an n-param register */
void ipa_write_reg_n(enum ipa_reg reg, u32 n, u32 val);

/* ipa_read_reg_n_fields() - Get the parsed value of an n-param register */
void ipa_read_reg_n_fields(enum ipa_reg reg, u32 n, void *fields);

/* ipa_write_reg_n_fields() - Write a parsed value to an n-param register */
void ipa_write_reg_n_fields(enum ipa_reg reg, u32 n, const void *fields);

/* ipa_read_reg() - Get the raw value from a register */
static inline u32 ipa_read_reg(enum ipa_reg reg)
{
	return ipa_read_reg_n(reg, 0);
}

/* ipa_write_reg() - Write a raw value to a register*/
static inline void ipa_write_reg(enum ipa_reg reg, u32 val)
{
	ipa_write_reg_n(reg, 0, val);
}

/* ipa_read_reg_fields() - Get the parsed value of a register */
static inline void ipa_read_reg_fields(enum ipa_reg reg, void *fields)
{
	ipa_read_reg_n_fields(reg, 0, fields);
}

/* ipa_write_reg_fields() - Write a parsed value to a register */
static inline void ipa_write_reg_fields(enum ipa_reg reg, const void *fields)
{
	ipa_write_reg_n_fields(reg, 0, fields);
}

u32 ipa_reg_aggr_max_byte_limit(void);
u32 ipa_reg_aggr_max_packet_limit(void);

#endif /* _IPA_REG_H_ */
