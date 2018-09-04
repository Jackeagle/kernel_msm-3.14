// SPDX-License-Identifier: GPL-2.0

/* Copyright (C) 2018 Linaro Ltd. */

#ifndef _FIELD_MASK_H_
#define _FIELD_MASK_H_

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/log2.h>
#include <linux/build_bug.h>

/* A field_mask is a bitmask that defines both the width and
 * position of a field within in a 32-bit register.  Set bits in a
 * field_mask define which bits are considered part of a field.  At
 * least one bit must be set, and all set bits in a field_mask must
 * be contiguous.
 *
 * The "width" of a field (1-32) can be determined by counting the number
 * of 1 bits in its field_mask.  The "shift" for a field (i.e. the position
 * of its rightmost set bit, 0-31) is the same as the number of low-order
 * 0 bits in the field_mask.
 *
 * For constant field_mask, these values can be computed at compile time.
 */
static __always_inline u32 __field_mask_check(u32 field_mask)
{
	/* BUILD_BUG_ON(!__builtin_constant_p(field_mask)); */
	BUILD_BUG_ON(!field_mask);
	if (field_mask == ~0)
		return ~0;	/* Valid, but won't pass next test */

	BUILD_BUG_ON(!is_power_of_2((field_mask >> __ffs(field_mask)) + 1));

	return field_mask;
}

/* Compute the number of set bits in the field mask */
static __always_inline u32 field_width(u32 field_mask)
{
	return hweight32(__field_mask_check(field_mask));
}

/* Compute the position of the rightmost set bit in the field mask */
static __always_inline u32 field_shift(u32 field_mask)
{
	return __ffs(__field_mask_check(field_mask));
}

/* Generate a field value--the given value shifted into the field's position */
static __always_inline u32 field_gen(u32 val, u32 field_mask)
{
	u32 shift = field_shift(field_mask);

	WARN_ON(val > field_mask >> shift);

	return val << shift & field_mask;
}

/* Extract the value of a field from the given register */
static __always_inline u32 field_val(u32 reg, u32 field_mask)
{
	return (reg & field_mask) >> field_shift(field_mask);
}

/* Return the maximum representable value for a field with the given mask */
static __always_inline u32 field_max(u32 field_mask)
{
	return field_mask >> field_shift(field_mask);
}

#endif /* _FIELD_MASK_H_ */
