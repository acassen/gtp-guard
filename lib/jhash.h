/*
 * Soft:        Jenkins hash support
 *
 * Author:      Bob Jenkins, <bob_jenkins@burtleburtle.net
 *
 * Copyright (C) 1996 Bob Jenkins, <bob_jenkins@burtleburtle.net>
 */

#ifndef _JHASH_H
#define _JHASH_H

/* Global helpers */
typedef uint32_t ub4;
typedef uint8_t ub1;

#define jhashsize(n) ((ub4)1<<(n))
#define jhashmask(n) (jhashsize(n)-1)

/* NOTE: Arguments are modified. */
#define __jhash_mix(a, b, c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

/* The golden ration: an arbitrary value */
#define JHASH_GOLDEN_RATIO	0x9e3779b9

/* The most generic version, hashes an arbitrary sequence
 * of bytes.  No alignment or length assumptions are made about
 * the input key.
 */
static inline ub4
jhash(register ub1 *k, register ub4 length, register ub4 initval)
{
	register ub4 a, b, c, len;

	len = length;
	a = b = JHASH_GOLDEN_RATIO;
	c = initval;

	while (len >= 12) {
		a += (k[0] + ((ub4) k[1] << 8) + ((ub4) k[2] << 16) +
		      ((ub4) k[3] << 24));
		b += (k[4] + ((ub4) k[5] << 8) + ((ub4) k[6] << 16) +
		      ((ub4) k[7] << 24));
		c += (k[8] + ((ub4) k[9] << 8) + ((ub4) k[10] << 16) +
		      ((ub4) k[11] << 24));

		__jhash_mix(a, b, c);

		k += 12;
		len -= 12;
	}

	c += length;
	switch (len) {
	case 11:
		c += ((ub4) k[10] << 24);
	case 10:
		c += ((ub4) k[9] << 16);
	case 9:
		c += ((ub4) k[8] << 8);
	case 8:
		b += ((ub4) k[7] << 24);
	case 7:
		b += ((ub4) k[6] << 16);
	case 6:
		b += ((ub4) k[5] << 8);
	case 5:
		b += k[4];
	case 4:
		a += ((ub4) k[3] << 24);
	case 3:
		a += ((ub4) k[2] << 16);
	case 2:
		a += ((ub4) k[1] << 8);
	case 1:
		a += k[0];
	};

	__jhash_mix(a, b, c);

	return c;
}

/* A special optimized version that handles 1 or more of ub4s.
 * The length parameter here is the number of ub4s in the key.
 */
static inline ub4
jhash2(register ub4 *k, register ub4 length, register ub4 initval)
{
	register ub4 a, b, c, len;

	a = b = JHASH_GOLDEN_RATIO;
	c = initval;
	len = length;

	while (len >= 3) {
		a += k[0];
		b += k[1];
		c += k[2];
		__jhash_mix(a, b, c);
		k += 3;
		len -= 3;
	}

	c += length * 4;

	switch (len) {
	case 2:
		b += k[1];
	case 1:
		a += k[0];
	};

	__jhash_mix(a, b, c);

	return c;
}

/* A special ultra-optimized versions that knows they are hashing exactly
 * 3, 2 or 1 word(s).
 *
 * NOTE: In partilar the "c += length; __jhash_mix(a,b,c);" normally
 *       done at the end is not done here.
 */
static inline ub4
jhash_3words(register ub4 a, register ub4 b,
	     register ub4 c, register ub4 initval)
{
	a += JHASH_GOLDEN_RATIO;
	b += JHASH_GOLDEN_RATIO;
	c += initval;

	__jhash_mix(a, b, c);

	return c;
}

static inline ub4
jhash_2words(register ub4 a, register ub4 b, register ub4 initval)
{
	return jhash_3words(a, b, 0, initval);
}

static inline ub4
jhash_1word(register ub4 a, register ub4 initval)
{
	return jhash_3words(a, 0, 0, initval);
}

/* One-At-A-Time string hashing */
static inline ub4
jhash_oaat(register ub1 *k, size_t s)
{
	register ub4 hash = JHASH_GOLDEN_RATIO;
	const ub1 *cp;
	int i = 0;

	for (cp = k; *cp && i < s; cp++, i++) {
		hash += *cp;
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return hash;
}

#endif
