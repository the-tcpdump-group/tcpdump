/*
 * Copyright (c) 1992, 1993, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * For 8-bit values; needed to fetch a one-byte value.  Byte order
 * isn't relevant, and alignment isn't an issue.
 */
#define EXTRACT_U_1(p)	(*(p))
#define EXTRACT_S_1(p)	((int8_t)(*(p)))

/*
 * Inline functions or macros to extract possibly-unaligned big-endian
 * integral values.
 */
#include "funcattrs.h"

/*
 * If we have versions of GCC or Clang that support an __attribute__
 * to say "if we're building with unsigned behavior sanitization,
 * don't complain about undefined behavior in this function", we
 * label these functions with that attribute - we *know* it's undefined
 * in the C standard, but we *also* know it does what we want with
 * the ISA we're targeting and the compiler we're using.
 *
 * For GCC 4.9.0 and later, we use __attribute__((no_sanitize_undefined));
 * pre-5.0 GCC doesn't have __has_attribute, and I'm not sure whether
 * GCC or Clang first had __attribute__((no_sanitize(XXX)).
 *
 * For Clang, we check for __attribute__((no_sanitize(XXX)) with
 * __has_attribute, as there are versions of Clang that support
 * __attribute__((no_sanitize("undefined")) but don't support
 * __attribute__((no_sanitize_undefined)).
 *
 * We define this here, rather than in funcattrs.h, because we
 * only want it used here, we don't want it to be broadly used.
 * (Any printer will get this defined, but this should at least
 * make it harder for people to find.)
 */
#if defined(__GNUC__) && ((__GNUC__ * 100 + __GNUC_MINOR__) >= 409)
#define UNALIGNED_OK	__attribute__((no_sanitize_undefined))
#elif __has_attribute(no_sanitize)
#define UNALIGNED_OK	__attribute__((no_sanitize("undefined")))
#else
#define UNALIGNED_OK
#endif

#if (defined(__i386__) || defined(_M_IX86) || defined(__X86__) || defined(__x86_64__) || defined(_M_X64)) || \
    (defined(__arm__) || defined(_M_ARM) || defined(__aarch64__)) || \
    (defined(__m68k__) && (!defined(__mc68000__) && !defined(__mc68010__))) || \
    (defined(__ppc__) || defined(__ppc64__) || defined(_M_PPC) || defined(_ARCH_PPC) || defined(_ARCH_PPC64)) || \
    (defined(__s390__) || defined(__s390x__) || defined(__zarch__))
/*
 * The processor natively handles unaligned loads, so we can just
 * cast the pointer and fetch through it.
 *
 * XXX - are those all the x86 tests we need?
 * XXX - do we need to worry about ARMv1 through ARMv5, which didn't
 * support unaligned loads, and, if so, do we need to worry about all
 * of them, or just some of them, e.g. ARMv5?
 * XXX - are those the only 68k tests we need not to generated
 * unaligned accesses if the target is the 68000 or 68010?
 * XXX - are there any tests we don't need, because some definitions are for
 * compilers that also predefine the GCC symbols?
 * XXX - do we need to test for both 32-bit and 64-bit versions of those
 * architectures in all cases?
 */
static inline uint16_t UNALIGNED_OK
EXTRACT_BE_U_2(const void *p)
{
	return ((uint16_t)ntohs(*(const uint16_t *)(p)));
}

static inline int16_t UNALIGNED_OK
EXTRACT_BE_S_2(const void *p)
{
	return ((int16_t)ntohs(*(const int16_t *)(p)));
}

static inline uint32_t UNALIGNED_OK
EXTRACT_BE_U_4(const void *p)
{
	return ((uint32_t)ntohl(*(const uint32_t *)(p)));
}

static inline int32_t UNALIGNED_OK
EXTRACT_BE_S_4(const void *p)
{
	return ((int32_t)ntohl(*(const int32_t *)(p)));
}

static inline uint64_t UNALIGNED_OK
EXTRACT_BE_U_8(const void *p)
{
	return ((uint64_t)(((uint64_t)ntohl(*((const uint32_t *)(p) + 0))) << 32 |
		((uint64_t)ntohl(*((const uint32_t *)(p) + 1))) << 0));

}

static inline int64_t UNALIGNED_OK
EXTRACT_BE_S_8(const void *p)
{
	return ((int64_t)(((int64_t)ntohl(*((const uint32_t *)(p) + 0))) << 32 |
		((uint64_t)ntohl(*((const uint32_t *)(p) + 1))) << 0));

}
#elif defined(__GNUC__) && defined(HAVE___ATTRIBUTE__) && \
    (defined(__alpha) || defined(__alpha__) || \
     defined(__mips) || defined(__mips__))
/*
 * This is MIPS or Alpha, which don't natively handle unaligned loads,
 * but which have instructions that can help when doing unaligned
 * loads, and this is a GCC-compatible compiler and we have __attribute__,
 * which we assume that mean we have __attribute__((packed)), which
 * we can use to convince the compiler to generate those instructions.
 *
 * Declare packed structures containing a uint16_t and a uint32_t,
 * cast the pointer to point to one of those, and fetch through it;
 * the GCC manual doesn't appear to explicitly say that
 * __attribute__((packed)) causes the compiler to generate unaligned-safe
 * code, but it apppears to do so.
 *
 * We do this in case the compiler can generate code using those
 * instructions to do an unaligned load and pass stuff to "ntohs()" or
 * "ntohl()", which might be better than than the code to fetch the
 * bytes one at a time and assemble them.  (That might not be the
 * case on a little-endian platform, such as DEC's MIPS machines and
 * Alpha machines, where "ntohs()" and "ntohl()" might not be done
 * inline.)
 *
 * We do this only for specific architectures because, for example,
 * at least some versions of GCC, when compiling for 64-bit SPARC,
 * generate code that assumes alignment if we do this.
 *
 * XXX - add other architectures and compilers as possible and
 * appropriate.
 *
 * HP's C compiler, indicated by __HP_cc being defined, supports
 * "#pragma unaligned N" in version A.05.50 and later, where "N"
 * specifies a number of bytes at which the typedef on the next
 * line is aligned, e.g.
 *
 *	#pragma unalign 1
 *	typedef uint16_t unaligned_uint16_t;
 *
 * to define unaligned_uint16_t as a 16-bit unaligned data type.
 * This could be presumably used, in sufficiently recent versions of
 * the compiler, with macros similar to those below.  This would be
 * useful only if that compiler could generate better code for PA-RISC
 * or Itanium than would be generated by a bunch of shifts-and-ORs.
 *
 * DEC C, indicated by __DECC being defined, has, at least on Alpha,
 * an __unaligned qualifier that can be applied to pointers to get the
 * compiler to generate code that does unaligned loads and stores when
 * dereferencing the pointer in question.
 *
 * XXX - what if the native C compiler doesn't support
 * __attribute__((packed))?  How can we get it to generate unaligned
 * accesses for *specific* items?
 */
typedef struct {
	uint16_t	val;
} __attribute__((packed)) unaligned_uint16_t;

typedef struct {
	int16_t		val;
} __attribute__((packed)) unaligned_int16_t;

typedef struct {
	uint32_t	val;
} __attribute__((packed)) unaligned_uint32_t;

typedef struct {
	int32_t		val;
} __attribute__((packed)) unaligned_int32_t;

UNALIGNED_OK static inline uint16_t
EXTRACT_BE_U_2(const void *p)
{
	return ((uint16_t)ntohs(((const unaligned_uint16_t *)(p))->val));
}

UNALIGNED_OK static inline int16_t
EXTRACT_BE_S_2(const void *p)
{
	return ((int16_t)ntohs(((const unaligned_int16_t *)(p))->val));
}

UNALIGNED_OK static inline uint32_t
EXTRACT_BE_U_4(const void *p)
{
	return ((uint32_t)ntohl(((const unaligned_uint32_t *)(p))->val));
}

UNALIGNED_OK static inline int32_t
EXTRACT_BE_S_4(const void *p)
{
	return ((int32_t)ntohl(((const unaligned_int32_t *)(p))->val));
}

UNALIGNED_OK static inline uint64_t
EXTRACT_BE_U_8(const void *p)
{
	return ((uint64_t)(((uint64_t)ntohl(((const unaligned_uint32_t *)(p) + 0)->val)) << 32 |
		((uint64_t)ntohl(((const unaligned_uint32_t *)(p) + 1)->val)) << 0));
}

UNALIGNED_OK static inline int64_t
EXTRACT_BE_S_8(const void *p)
{
	return ((int64_t)(((uint64_t)ntohl(((const unaligned_uint32_t *)(p) + 0)->val)) << 32 |
		((uint64_t)ntohl(((const unaligned_uint32_t *)(p) + 1)->val)) << 0));
}
#else
/*
 * This architecture doesn't natively support unaligned loads, and either
 * this isn't a GCC-compatible compiler, we don't have __attribute__,
 * or we do but we don't know of any better way with this instruction
 * set to do unaligned loads, so do unaligned loads of big-endian
 * quantities the hard way - fetch the bytes one at a time and
 * assemble them.
 */
#define EXTRACT_BE_U_2(p) \
	((uint16_t)(((uint16_t)(*((const uint8_t *)(p) + 0)) << 8) | \
	            ((uint16_t)(*((const uint8_t *)(p) + 1)) << 0)))
#define EXTRACT_BE_S_2(p) \
	((int16_t)(((uint16_t)(*((const uint8_t *)(p) + 0)) << 8) | \
	           ((uint16_t)(*((const uint8_t *)(p) + 1)) << 0)))
#define EXTRACT_BE_U_4(p) \
	((uint32_t)(((uint32_t)(*((const uint8_t *)(p) + 0)) << 24) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 1)) << 16) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 2)) << 8) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 3)) << 0)))
#define EXTRACT_BE_S_4(p) \
	((int32_t)(((uint32_t)(*((const uint8_t *)(p) + 0)) << 24) | \
	           ((uint32_t)(*((const uint8_t *)(p) + 1)) << 16) | \
	           ((uint32_t)(*((const uint8_t *)(p) + 2)) << 8) | \
	           ((uint32_t)(*((const uint8_t *)(p) + 3)) << 0)))
#define EXTRACT_BE_U_8(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 56) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 1)) << 48) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 2)) << 40) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 3)) << 32) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 4)) << 24) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 5)) << 16) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 6)) << 8) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 7)) << 0)))
#define EXTRACT_BE_S_8(p) \
	((int64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 56) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 1)) << 48) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 2)) << 40) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 3)) << 32) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 4)) << 24) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 5)) << 16) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 6)) << 8) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 7)) << 0)))
#endif /* unaligned access checks */

#define EXTRACT_BE_U_3(p) \
	((uint32_t)(((uint32_t)(*((const uint8_t *)(p) + 0)) << 16) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 2)) << 0)))

#define EXTRACT_BE_S_3(p) \
	(((*((const uint8_t *)(p) + 0)) & 0x80) ? \
	  ((int32_t)(((uint32_t)(*((const uint8_t *)(p) + 0)) << 16) | \
	             ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	             ((uint32_t)(*((const uint8_t *)(p) + 2)) << 0))) : \
	  ((int32_t)(0xFF000000U | \
	             ((uint32_t)(*((const uint8_t *)(p) + 0)) << 16) | \
	             ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	             ((uint32_t)(*((const uint8_t *)(p) + 2)) << 0))))

#define EXTRACT_BE_U_5(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 32) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 1)) << 24) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 3)) << 8) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 4)) << 0)))

#define EXTRACT_BE_S_5(p) \
	(((*((const uint8_t *)(p) + 0)) & 0x80) ? \
	  ((int64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 32) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 1)) << 24) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 3)) << 8) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 4)) << 0))) : \
	  ((int64_t)(INT64_T_CONSTANT(0xFFFFFF0000000000U) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 0)) << 32) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 1)) << 24) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 3)) << 8) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 4)) << 0))))

#define EXTRACT_BE_U_6(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 40) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 1)) << 32) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 2)) << 24) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 3)) << 16) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 4)) << 8) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 5)) << 0)))

#define EXTRACT_BE_S_6(p) \
	(((*((const uint8_t *)(p) + 0)) & 0x80) ? \
	  ((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 40) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 1)) << 32) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 2)) << 24) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 3)) << 16) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 4)) << 8) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 5)) << 0))) : \
	  ((int64_t)(INT64_T_CONSTANT(0xFFFFFFFF00000000U) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 0)) << 40) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 1)) << 32) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 2)) << 24) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 3)) << 16) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 4)) << 8) | \
	              ((uint64_t)(*((const uint8_t *)(p) + 5)) << 0))))

#define EXTRACT_BE_U_7(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 48) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 1)) << 40) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 2)) << 32) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 3)) << 24) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 4)) << 16) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 5)) << 8) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 6)) << 0)))

#define EXTRACT_BE_S_7(p) \
	(((*((const uint8_t *)(p) + 0)) & 0x80) ? \
	  ((int64_t)(((uint64_t)(*((const uint8_t *)(p) + 0)) << 48) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 1)) << 40) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 2)) << 32) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 3)) << 24) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 4)) << 16) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 5)) << 8) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 6)) << 0))) : \
	    ((int64_t)(INT64_T_CONSTANT(0xFFFFFFFFFF000000U) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 0)) << 48) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 1)) << 40) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 2)) << 32) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 3)) << 24) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 4)) << 16) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 5)) << 8) | \
	             ((uint64_t)(*((const uint8_t *)(p) + 6)) << 0))))

/*
 * Macros to extract possibly-unaligned little-endian integral values.
 * XXX - do loads on little-endian machines that support unaligned loads?
 */
#define EXTRACT_LE_U_2(p) \
	((uint16_t)(((uint16_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	            ((uint16_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_S_2(p) \
	((int16_t)(((uint16_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	           ((uint16_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_U_4(p) \
	((uint32_t)(((uint32_t)(*((const uint8_t *)(p) + 3)) << 24) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_S_4(p) \
	((int32_t)(((uint32_t)(*((const uint8_t *)(p) + 3)) << 24) | \
	           ((uint32_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	           ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	           ((uint32_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_U_3(p) \
	((uint32_t)(((uint32_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_S_3(p) \
	((int32_t)(((uint32_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	           ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	           ((uint32_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_U_8(p) \
	((uint64_t)(((uint64_t)(*((const uint8_t *)(p) + 7)) << 56) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 6)) << 48) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 5)) << 40) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 4)) << 32) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 3)) << 24) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	            ((uint64_t)(*((const uint8_t *)(p) + 0)) << 0)))
#define EXTRACT_LE_S_8(p) \
	((int64_t)(((uint64_t)(*((const uint8_t *)(p) + 7)) << 56) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 6)) << 48) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 5)) << 40) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 4)) << 32) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 3)) << 24) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 2)) << 16) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	           ((uint64_t)(*((const uint8_t *)(p) + 0)) << 0)))

/*
 * Macros to check the presence of the values in question.
 */
#define ND_TTEST_1(p) ND_TTEST2(*(p), 1)
#define ND_TCHECK_1(p) ND_TCHECK2(*(p), 1)

#define ND_TTEST_2(p) ND_TTEST2(*(p), 2)
#define ND_TCHECK_2(p) ND_TCHECK2(*(p), 2)

#define ND_TTEST_3(p) ND_TTEST2(*(p), 3)
#define ND_TCHECK_3(p) ND_TCHECK2(*(p), 3)

#define ND_TTEST_4(p) ND_TTEST2(*(p), 4)
#define ND_TCHECK_4(p) ND_TCHECK2(*(p), 4)

#define ND_TTEST_5(p) ND_TTEST2(*(p), 5)
#define ND_TCHECK_5(p) ND_TCHECK2(*(p), 5)

#define ND_TTEST_6(p) ND_TTEST2(*(p), 6)
#define ND_TCHECK_6(p) ND_TCHECK2(*(p), 6)

#define ND_TTEST_7(p) ND_TTEST2(*(p), 7)
#define ND_TCHECK_7(p) ND_TCHECK2(*(p), 7)

#define ND_TTEST_8(p) ND_TTEST2(*(p), 8)
#define ND_TCHECK_8(p) ND_TCHECK2(*(p), 8)

#define ND_TTEST_16(p) ND_TTEST2(*(p), 16)
#define ND_TCHECK_16(p) ND_TCHECK2(*(p), 16)
