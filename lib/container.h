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

#if defined _HAVE_FUNCTION_ATTRIBUTE_ERROR_ && (!defined _HAVE_WARNING_NESTED_EXTERNS_ || defined _HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_)

/* Copied from linux kernel 5.15 source include/linux/{build_bug,compiler_types,compiler_attributes}.h */

#define __compiletime_error(message) __attribute__((error(message)))

# define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
		RELAX_NESTED_EXTERNS_START				\
		RELAX_REDUNDANT_DECLS_START				\
		extern void prefix ## suffix(void) __compiletime_error(msg); \
		if (!(condition))					\
			prefix ## suffix();				\
		RELAX_REDUNDANT_DECLS_END				\
		RELAX_NESTED_EXTERNS_END				\
	} while (0)


#define _compiletime_assert(condition, msg, prefix, suffix) \
	__compiletime_assert(condition, msg, prefix, suffix)

#define compiletime_assert(condition, msg) \
	_compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)

#define BUILD_BUG_ON_MSG(cond, msg) compiletime_assert(!(cond), msg)

#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))

#else
#define BUILD_BUG_ON_MSG(conf, msg)	do {} while (0)
#endif


/* Copied from linux kernel 5.15 source include/linux/{kernel.h,stddef.h} */

#ifndef offsetof
# define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

/*
 * container_of - cast a member of a structure out to the containing structure
 *
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */

#ifndef container_of
# define container_of(ptr, type, member) ({				\
	BUILD_BUG_ON_MSG(!__same_type(*(ptr), ((type *)0)->member) &&	\
			!__same_type(*(ptr), void),			\
			"pointer type mismatch in container_of()");	\
	typeof( ((type *)0)->member ) *__mptr = (ptr); 			\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#ifndef container_of_const
# define container_of_const(ptr, type, member) ({			\
	BUILD_BUG_ON_MSG(!__same_type(*(ptr), ((type *)0)->member) &&	\
			!__same_type(*(ptr), void),			\
			"pointer type mismatch in container_of()");	\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);  		\
	(type *)( (const char *)__mptr - offsetof(type,member) );})
#endif
