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

#ifdef __GNUC__
#include <features.h>
#endif

/* musl does not define __GNUC_PREREQ, so create a dummy definition */
#ifndef __GNUC_PREREQ
#define __GNUC_PREREQ(maj, min) 0
#endif

/* GCC allows pragmas in functions, and diagnostic push/pop from version 4.6.0 */

/* See https://clang.llvm.org/docs/DiagnosticsReference.html for clang diagnostics
 * See https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html for GCC warnings
*/

#ifdef _HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_
#define RELAX_END \
_Pragma("GCC diagnostic pop")
#else
#define RELAX_END
#endif

#if defined _HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_ && defined _HAVE_WARNING_STACK_PROTECTOR_
#define RELAX_STACK_PROTECTOR_START \
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic ignored \"-Wstack-protector\"")
#define RELAX_STACK_PROTECTOR_END RELAX_END
#else
#define RELAX_STACK_PROTECTOR_START
#define RELAX_STACK_PROTECTOR_END
#endif

#if __GNUC__ && !__GNUC_PREREQ(8,0) && defined _HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_ && defined _HAVE_WARNING_STRICT_OVERFLOW_
#ifdef _HAVE_PRAGMA_WARN_STRICT_OVERFLOW_1_
#define RELAX_STRICT_OVERFLOW_START \
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic warning \"-Wstrict-overflow=1\"")
#else
#define RELAX_STRICT_OVERFLOW_START \
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic warning \"-Wstrict-overflow\"")
#endif
#define RELAX_STRICT_OVERFLOW_END RELAX_END
#else
#define RELAX_STRICT_OVERFLOW_START
#define RELAX_STRICT_OVERFLOW_END
#endif

#if defined _HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_ && defined _HAVE_WARNING_CAST_QUAL_
#define RELAX_CAST_QUAL_START \
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic ignored \"-Wcast-qual\"")
#define RELAX_CAST_QUAL_END RELAX_END
#else
#define RELAX_CAST_QUAL_START
#define RELAX_CAST_QUAL_END
#endif

#if defined _HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_ && defined _HAVE_WARNING_SUGGEST_ATTRIBUTE_CONST_START_
#define RELAX_SUGGEST_ATTRIBUTE_CONST_START \
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic ignored \"-Wsuggest-attribute=const\"")
#define RELAX_SUGGEST_ATTRIBUTE_CONST_END RELAX_END
#else
#define RELAX_SUGGEST_ATTRIBUTE_CONST_START
#define RELAX_SUGGEST_ATTRIBUTE_CONST_END
#endif

#if defined _HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_ && defined _HAVE_WARNING_STRINGOP_OVERFLOW_
#define RELAX_STRINGOP_OVERFLOW \
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic ignored \"-Wstringop-overflow\"")
#define RELAX_STRINGOP_OVERFLOW_END RELAX_END
#else
#define RELAX_STRINGOP_OVERFLOW
#define RELAX_STRINGOP_OVERFLOW_END
#endif

#if defined _HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_ && defined _HAVE_WARNING_NESTED_EXTERNS_
# define RELAX_NESTED_EXTERNS_START \
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic ignored \"-Wnested-externs\"")
#define RELAX_NESTED_EXTERNS_END RELAX_END
#else
#define RELAX_NESTED_EXTERNS_START
#define RELAX_NESTED_EXTERNS_END
#endif

#if defined _HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_ && defined _HAVE_WARNING_REDUNDANT_DECLS_
#define RELAX_REDUNDANT_DECLS_START \
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic ignored \"-Wredundant-decls\"")
#define RELAX_REDUNDANT_DECLS_END RELAX_END
#else
#define RELAX_REDUNDANT_DECLS_START
#define RELAX_REDUNDANT_DECLS_END
#endif
