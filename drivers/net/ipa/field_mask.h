// SPDX-License-Identifier: GPL-2.0

/* Copyright (C) 2018 Linaro Ltd. */

#ifndef _FIELD_MASK_H_
#define _FIELD_MASK_H_

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/log2.h>
#include <linux/build_bug.h>

/**
 * DOC: Overview
 *
 * A "field_mask" is a bitmask that defines both the width and position of
 * a field within in a 32-bit register.  Set bits in a field_mask define
 * which bits within a register are included in the field.  At least one
 * bit must be set, and all set bits in a field_mask must be contiguous.
 *
 * The "width" of a field (1-32) is determined by counting the number of
 * set bits in its field_mask.  The "shift" for a field (i.e. the position
 * of its rightmost set bit, 0-31) is the number of low-order clear bits
 * in the field_mask.
 *
 * For constant field_mask, these values can be computed at compile time.
 */

/**
 * __field_mask_check() -  Validate a field_mask value (used internally).
 * @field_mask: Field mask whose value is checked.
 *
 * A field mask must be non-zero, and it must contain a single span of
 * contiguous set bits.  If these properties aren't satisfied, this
 * function produces a compile-time error.
 *
 * Return: The (valid) @field_mask value.
 */
static __always_inline u32 __field_mask_check(u32 field_mask)
{
	/* BUILD_BUG_ON(!__builtin_constant_p(field_mask)); */
	BUILD_BUG_ON(!field_mask);
	if (!~field_mask)
		return ~0;	/* Valid, but won't pass next test */

	BUILD_BUG_ON(!is_power_of_2((field_mask >> __ffs(field_mask)) + 1));

	return field_mask;
}

/**
 * field_width() - Compute the number of set bits in the field mask.
 * @field_mask: Field mask whose width is returned.
 *
 * Return: The width of the supplied field mask (1-32).
 */
static __always_inline u32 field_width(u32 field_mask)
{
	return hweight32(__field_mask_check(field_mask));
}

/**
 * field_shift() - Compute position of the rightmost set bit in a field mask.
 * @field_mask: Field mask whose shift value is returned.
 *
 * Return: The shift value for the supplied field mask (0-31).
 */
static __always_inline u32 field_shift(u32 field_mask)
{
	return __ffs(__field_mask_check(field_mask));
}

/**
 * field_gen() - Generate a register value holding a value in a field
 * @val: The value to be held in the field defined by @field_mask.
 * @field_mask: Field mask that defines the position and width of the field.
 *
 * Return: The supplied @value, shifted into the field's position.
 */
static __always_inline u32 field_gen(u32 val, u32 field_mask)
{
	u32 shift = field_shift(field_mask);

	WARN_ON(val > field_mask >> shift);

	return val << shift & field_mask;
}

/**
 * field_val() - Extract the value in a field from the given register value.
 * @reg: The register value from which a field's value should be extracted
 * @field_mask: Field mask that defines the position and width of the field.
 *
 * Return: The field value extracted from the register.
 */
static __always_inline u32 field_val(u32 reg, u32 field_mask)
{
	return (reg & field_mask) >> field_shift(field_mask);
}

/**
 * field_max() - Return the maximum value representable in a field.
 * @field_mask: Field mask that defines the position and width of the field.
 *
 * Return: The maximum field value.
 */
static __always_inline u32 field_max(u32 field_mask)
{
	return field_mask >> field_shift(field_mask);
}

#endif /* _FIELD_MASK_H_ */
