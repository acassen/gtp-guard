/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of gtp-guard is to provide robust and secure
 *              extensions to GTP protocol (GPRS Tunneling Procol). GTP is
 *              widely used for data-plane in mobile core-network. gtp-guard
 *              implements a set of 3 main frameworks:
 *              A Proxy feature for data-plane tweaking, a Routing facility
 *              to inter-connect and a Firewall feature for filtering,
 *              rewriting and redirecting.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2023-2024 Alexandre Cassen, <acassen@gmail.com>
 */

#pragma once

#include "config.h"

#include <limits.h>
#include <stdbool.h>

/* Defines */
#define BIT_PER_LONG	(CHAR_BIT * sizeof(unsigned long))
#define BIT_MASK(idx)	(1UL << ((idx) % BIT_PER_LONG))
#define BIT_WORD(idx)	((idx) / BIT_PER_LONG)

/* Helpers */
static inline void __set_bit(unsigned idx, unsigned long *bmap)
{
	*bmap |= BIT_MASK(idx);
}

static inline void __clear_bit(unsigned idx, unsigned long *bmap)
{
	*bmap &= ~BIT_MASK(idx);
}

static inline bool __test_bit(unsigned idx, const unsigned long *bmap)
{
	return !!(*bmap & BIT_MASK(idx));
}

static inline bool __test_and_set_bit(unsigned idx, unsigned long *bmap)
{
	if (__test_bit(idx, bmap))
		return true;

	__set_bit(idx, bmap);

	return false;
}

static inline bool __test_and_clear_bit(unsigned idx, unsigned long *bmap)
{
	if (!__test_bit(idx, bmap))
		return false;

	__clear_bit(idx, bmap);

	return true;
}

static inline void __set_bit_array(unsigned idx, unsigned long bmap[])
{
	bmap[BIT_WORD(idx)] |= BIT_MASK(idx);
}

static inline void __clear_bit_array(unsigned idx, unsigned long bmap[])
{
	bmap[BIT_WORD(idx)] &= ~BIT_MASK(idx);
}

static inline bool __test_bit_array(unsigned idx, const unsigned long bmap[])
{
	return !!(bmap[BIT_WORD(idx)] & BIT_MASK(idx));
}

static inline bool __test_and_set_bit_array(unsigned idx, unsigned long bmap[])
{
	if (__test_bit_array(idx, bmap))
		return true;

	__set_bit_array(idx, bmap);

	return false;
}

/* Bits */
enum global_bits {
	LOG_CONSOLE_BIT,
	NO_SYSLOG_BIT,
	DONT_FORK_BIT,
	DUMP_CONF_BIT,
	LOG_DETAIL_BIT,
	LOG_EXTRA_DETAIL_BIT,
	DONT_RESPAWN_BIT,
#ifdef _MEM_CHECK_
	MEM_CHECK_BIT,
#ifdef _MEM_ERR_DEBUG_
	MEM_ERR_DETECT_BIT,
#endif
#ifdef _MEM_CHECK_LOG_
	MEM_CHECK_LOG_BIT,
#endif
#endif
	CONFIG_TEST_BIT,
};
