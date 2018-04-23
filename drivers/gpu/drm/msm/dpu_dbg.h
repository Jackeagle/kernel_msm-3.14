/* Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef DPU_DBG_H_
#define DPU_DBG_H_

#include <stdarg.h>
#include <linux/debugfs.h>
#include <linux/list.h>

#define DPU_EVTLOG_DATA_LIMITER	(-1)
#define DPU_EVTLOG_FUNC_ENTRY	0x1111
#define DPU_EVTLOG_FUNC_EXIT	0x2222
#define DPU_EVTLOG_FUNC_CASE1	0x3333
#define DPU_EVTLOG_FUNC_CASE2	0x4444
#define DPU_EVTLOG_FUNC_CASE3	0x5555
#define DPU_EVTLOG_FUNC_CASE4	0x6666
#define DPU_EVTLOG_FUNC_CASE5	0x7777
#define DPU_EVTLOG_FUNC_CASE6	0x8888
#define DPU_EVTLOG_FUNC_CASE7	0x9999
#define DPU_EVTLOG_FUNC_CASE8	0xaaaa
#define DPU_EVTLOG_FUNC_CASE9	0xbbbb
#define DPU_EVTLOG_FUNC_CASE10	0xcccc
#define DPU_EVTLOG_PANIC	0xdead
#define DPU_EVTLOG_FATAL	0xbad
#define DPU_EVTLOG_ERROR	0xebad

#define DPU_DBG_DUMP_DATA_LIMITER (NULL)

enum dpu_dbg_evtlog_flag {
	DPU_EVTLOG_CRITICAL = BIT(0),
	DPU_EVTLOG_IRQ = BIT(1),
	DPU_EVTLOG_VERBOSE = BIT(2),
	DPU_EVTLOG_ALWAYS = -1
};

enum dpu_dbg_dump_flag {
	DPU_DBG_DUMP_IN_LOG = BIT(0),
	DPU_DBG_DUMP_IN_MEM = BIT(1),
};

#ifdef CONFIG_DRM_DPU_EVTLOG_DEBUG
#define DPU_EVTLOG_DEFAULT_ENABLE (DPU_EVTLOG_CRITICAL | DPU_EVTLOG_IRQ)
#else
#define DPU_EVTLOG_DEFAULT_ENABLE 0
#endif

/*
 * evtlog will print this number of entries when it is called through
 * sysfs node or panic. This prevents kernel log from evtlog message
 * flood.
 */
#define DPU_EVTLOG_PRINT_ENTRY	256

/*
 * evtlog keeps this number of entries in memory for debug purpose. This
 * number must be greater than print entry to prevent out of bound evtlog
 * entry array access.
 */
#define DPU_EVTLOG_ENTRY	(DPU_EVTLOG_PRINT_ENTRY * 4)
#define DPU_EVTLOG_MAX_DATA 15
#define DPU_EVTLOG_BUF_MAX 512
#define DPU_EVTLOG_BUF_ALIGN 32

struct dpu_dbg_power_ctrl {
	void *handle;
	void *client;
	int (*enable_fn)(void *handle, void *client, bool enable);
};

struct dpu_dbg_evtlog_log {
	s64 time;
	const char *name;
	int line;
	u32 data[DPU_EVTLOG_MAX_DATA];
	u32 data_cnt;
	int pid;
};

/**
 * @filter_list: Linked list of currently active filter strings
 */
struct dpu_dbg_evtlog {
	struct dpu_dbg_evtlog_log logs[DPU_EVTLOG_ENTRY];
	u32 first;
	u32 last;
	u32 curr;
	u32 next;
	u32 enable;
	spinlock_t spin_lock;
	struct list_head filter_list;
};

extern struct dpu_dbg_evtlog *dpu_dbg_base_evtlog;

/**
 * DPU_EVT32 - Write a list of 32bit values to the event log, default area
 * ... - variable arguments
 */
#define DPU_EVT32(...) dpu_evtlog_log(dpu_dbg_base_evtlog, __func__, \
		__LINE__, DPU_EVTLOG_ALWAYS, ##__VA_ARGS__, \
		DPU_EVTLOG_DATA_LIMITER)

/**
 * DPU_EVT32_VERBOSE - Write a list of 32bit values for verbose event logging
 * ... - variable arguments
 */
#define DPU_EVT32_VERBOSE(...) dpu_evtlog_log(dpu_dbg_base_evtlog, __func__, \
		__LINE__, DPU_EVTLOG_VERBOSE, ##__VA_ARGS__, \
		DPU_EVTLOG_DATA_LIMITER)

/**
 * DPU_EVT32_IRQ - Write a list of 32bit values to the event log, IRQ area
 * ... - variable arguments
 */
#define DPU_EVT32_IRQ(...) dpu_evtlog_log(dpu_dbg_base_evtlog, __func__, \
		__LINE__, DPU_EVTLOG_IRQ, ##__VA_ARGS__, \
		DPU_EVTLOG_DATA_LIMITER)

/**
 * DPU_DBG_DUMP - trigger dumping of all dpu_dbg facilities
 * @va_args:	list of named register dump ranges and regions to dump, as
 *		registered previously through dpu_dbg_reg_register_base and
 *		dpu_dbg_reg_register_dump_range.
 *		Including the special name "panic" will trigger a panic after
 *		the dumping work has completed.
 */
#define DPU_DBG_DUMP(...) dpu_dbg_dump(false, __func__, ##__VA_ARGS__, \
		DPU_DBG_DUMP_DATA_LIMITER)

/**
 * DPU_DBG_DUMP_WQ - trigger dumping of all dpu_dbg facilities, queuing the work
 * @va_args:	list of named register dump ranges and regions to dump, as
 *		registered previously through dpu_dbg_reg_register_base and
 *		dpu_dbg_reg_register_dump_range.
 *		Including the special name "panic" will trigger a panic after
 *		the dumping work has completed.
 */
#define DPU_DBG_DUMP_WQ(...) dpu_dbg_dump(true, __func__, ##__VA_ARGS__, \
		DPU_DBG_DUMP_DATA_LIMITER)

#if defined(CONFIG_DEBUG_FS)

/**
 * dpu_evtlog_init - allocate a new event log object
 * Returns:	evtlog or -ERROR
 */
struct dpu_dbg_evtlog *dpu_evtlog_init(void);

/**
 * dpu_evtlog_destroy - destroy previously allocated event log
 * @evtlog:	pointer to evtlog
 * Returns:	none
 */
void dpu_evtlog_destroy(struct dpu_dbg_evtlog *evtlog);

/**
 * dpu_evtlog_log - log an entry into the event log.
 *	log collection may be enabled/disabled entirely via debugfs
 *	log area collection may be filtered by user provided flags via debugfs.
 * @evtlog:	pointer to evtlog
 * @name:	function name of call site
 * @line:	line number of call site
 * @flag:	log area filter flag checked against user's debugfs request
 * Returns:	none
 */
void dpu_evtlog_log(struct dpu_dbg_evtlog *evtlog, const char *name, int line,
		int flag, ...);

/**
 * dpu_evtlog_dump_all - print all entries in event log to kernel log
 * @evtlog:	pointer to evtlog
 * Returns:	none
 */
void dpu_evtlog_dump_all(struct dpu_dbg_evtlog *evtlog);

/**
 * dpu_evtlog_is_enabled - check whether log collection is enabled for given
 *	event log and log area flag
 * @evtlog:	pointer to evtlog
 * @flag:	log area filter flag
 * Returns:	none
 */
bool dpu_evtlog_is_enabled(struct dpu_dbg_evtlog *evtlog, u32 flag);

/**
 * dpu_evtlog_dump_to_buffer - print content of event log to the given buffer
 * @evtlog:		pointer to evtlog
 * @evtlog_buf:		target buffer to print into
 * @evtlog_buf_size:	size of target buffer
 * Returns:		number of bytes written to buffer
 */
ssize_t dpu_evtlog_dump_to_buffer(struct dpu_dbg_evtlog *evtlog,
		char *evtlog_buf, ssize_t evtlog_buf_size);

/**
 * dpu_dbg_init_dbg_buses - initialize debug bus dumping support for the chipset
 * @hwversion:		Chipset revision
 */
void dpu_dbg_init_dbg_buses(u32 hwversion);

/**
 * dpu_dbg_init - initialize global dpu debug facilities: evtlog, regdump
 * @dev:		device handle
 * @power_ctrl:		power control callback structure for enabling clocks
 *			during register dumping
 * Returns:		0 or -ERROR
 */
int dpu_dbg_init(struct device *dev, struct dpu_dbg_power_ctrl *power_ctrl);

/**
 * dpu_dbg_debugfs_register - register entries at the given debugfs dir
 * @debugfs_root:	debugfs root in which to create dpu debug entries
 * Returns:	0 or -ERROR
 */
int dpu_dbg_debugfs_register(struct dentry *debugfs_root);

/**
 * dpu_dbg_destroy - destroy the global dpu debug facilities
 * Returns:	none
 */
void dpu_dbg_destroy(void);

/**
 * dpu_dbg_dump - trigger dumping of all dpu_dbg facilities
 * @queue_work:	whether to queue the dumping work to the work_struct
 * @name:	string indicating origin of dump
 * @va_args:	list of named register dump ranges and regions to dump, as
 *		registered previously through dpu_dbg_reg_register_base and
 *		dpu_dbg_reg_register_dump_range.
 *		Including the special name "panic" will trigger a panic after
 *		the dumping work has completed.
 * Returns:	none
 */
void dpu_dbg_dump(bool queue_work, const char *name, ...);

/**
 * dpu_dbg_reg_register_base - register a hw register address section for later
 *	dumping. call this before calling dpu_dbg_reg_register_dump_range
 *	to be able to specify sub-ranges within the base hw range.
 * @name:	name of base region
 * @base:	base pointer of region
 * @max_offset:	length of region
 * Returns:	0 or -ERROR
 */
int dpu_dbg_reg_register_base(const char *name, void __iomem *base,
		size_t max_offset);

/**
 * dpu_dbg_reg_register_cb - register a hw register callback for later
 *	dumping.
 * @name:	name of base region
 * @cb:		callback of external region
 * @cb_ptr:	private pointer of external region
 * Returns:	0 or -ERROR
 */
int dpu_dbg_reg_register_cb(const char *name, void (*cb)(void *), void *ptr);

/**
 * dpu_dbg_reg_unregister_cb - register a hw unregister callback for later
 *	dumping.
 * @name:	name of base region
 * @cb:		callback of external region
 * @cb_ptr:	private pointer of external region
 * Returns:	None
 */
void dpu_dbg_reg_unregister_cb(const char *name, void (*cb)(void *), void *ptr);

/**
 * dpu_dbg_reg_register_dump_range - register a hw register sub-region for
 *	later register dumping associated with base specified by
 *	dpu_dbg_reg_register_base
 * @base_name:		name of base region
 * @range_name:		name of sub-range within base region
 * @offset_start:	sub-range's start offset from base's base pointer
 * @offset_end:		sub-range's end offset from base's base pointer
 * @xin_id:		xin id
 * Returns:		none
 */
void dpu_dbg_reg_register_dump_range(const char *base_name,
		const char *range_name, u32 offset_start, u32 offset_end,
		uint32_t xin_id);

/**
 * dpu_dbg_set_dpu_top_offset - set the target specific offset from mdss base
 *	address of the top registers. Used for accessing debug bus controls.
 * @blk_off: offset from mdss base of the top block
 */
void dpu_dbg_set_dpu_top_offset(u32 blk_off);

/**
 * dpu_evtlog_set_filter - update evtlog filtering
 * @evtlog:	pointer to evtlog
 * @filter:     pointer to optional function name filter, set to NULL to disable
 */
void dpu_evtlog_set_filter(struct dpu_dbg_evtlog *evtlog, char *filter);

/**
 * dpu_evtlog_get_filter - query configured evtlog filters
 * @evtlog:	pointer to evtlog
 * @index:	filter index to retrieve
 * @buf:	pointer to output filter buffer
 * @bufsz:	size of output filter buffer
 * Returns:	zero if a filter string was returned
 */
int dpu_evtlog_get_filter(struct dpu_dbg_evtlog *evtlog, int index,
		char *buf, size_t bufsz);

/**
 * dsi_ctrl_debug_dump - dump dsi debug dump status
 */
#if defined(CONFIG_DRM_MSM_DSI_STAGING)
void dsi_ctrl_debug_dump(void);
#else
static inline void dsi_ctrl_debug_dump(void) {}
#endif

#else
static inline struct dpu_dbg_evtlog *dpu_evtlog_init(void)
{
	return NULL;
}

static inline void dpu_evtlog_destroy(struct dpu_dbg_evtlog *evtlog)
{
}

static inline void dpu_evtlog_log(struct dpu_dbg_evtlog *evtlog,
		const char *name, int line, int flag, ...)
{
}

static inline void dpu_evtlog_dump_all(struct dpu_dbg_evtlog *evtlog)
{
}

static inline bool dpu_evtlog_is_enabled(struct dpu_dbg_evtlog *evtlog,
		u32 flag)
{
	return false;
}

static inline ssize_t dpu_evtlog_dump_to_buffer(struct dpu_dbg_evtlog *evtlog,
		char *evtlog_buf, ssize_t evtlog_buf_size)
{
	return 0;
}

static inline void dpu_dbg_init_dbg_buses(u32 hwversion)
{
}

static inline int dpu_dbg_init(struct device *dev,
		struct dpu_dbg_power_ctrl *power_ctrl)
{
	return 0;
}

static inline int dpu_dbg_debugfs_register(struct dentry *debugfs_root)
{
	return 0;
}

static inline void dpu_dbg_destroy(void)
{
}

static inline void dpu_dbg_dump(bool queue_work, const char *name, ...)
{
}

static inline int dpu_dbg_reg_register_base(const char *name,
		void __iomem *base, size_t max_offset)
{
	return 0;
}

static inline void dpu_dbg_reg_register_dump_range(const char *base_name,
		const char *range_name, u32 offset_start, u32 offset_end,
		uint32_t xin_id)
{
}

void dpu_dbg_set_dpu_top_offset(u32 blk_off)
{
}

static inline void dpu_evtlog_set_filter(
		struct dpu_dbg_evtlog *evtlog, char *filter)
{
}

static inline int dpu_evtlog_get_filter(struct dpu_dbg_evtlog *evtlog,
		int index, char *buf, size_t bufsz)
{
	return -EINVAL;
}

static inline void dsi_ctrl_debug_dump(void)
{
}

#endif /* defined(CONFIG_DEBUG_FS) */


#endif /* DPU_DBG_H_ */
