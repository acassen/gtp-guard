/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <linux/bpf.h>

/*********************************/
/* compiler stuff */

#ifndef likely
# define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
# define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* always_inline is a wish: compiler may not follow it */
#undef __always_inline
#define __always_inline		inline __attribute__((always_inline))



/*********************************/
/* l2 stuff */

struct vlan_hdr {
	__be16		vlan_tci;
	__be16		next_proto;
};


/*********************************/
/* ip stuff */


#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */


typedef __u32 v4addr_t;

union v6addr
{
	struct {
		__u32 p1;
		__u32 p2;
		__u32 p3;
		__u32 p4;
	};
	struct {
		__u64 d1;
		__u64 d2;
	};
	__u8 addr[16];
} __attribute__((packed));

union v4v6addr
{
	struct {
		v4addr_t	ip4;
		__u32		pad[3];
	};
	union v6addr		ip6;
} __attribute__((packed));


/*********************************/
/* gre stuff */

/* GRE Version field */
# define GRE_VERSION_1701	0x00
# define GRE_VERSION_PPTP	0x01

# define GRE_VERSION(gre)	((gre)->version & 0x07)

/* GRE Protocol field */
# define GRE_PROTOCOL_PPTP	0x880B

/* GRE Flags */
# define GRE_FLAG_C		0x80
# define GRE_FLAG_R		0x40
# define GRE_FLAG_K		0x20
# define GRE_FLAG_S		0x10
# define GRE_FLAG_A		0x80	/* in field 'version' */

struct gre_hdr
{
	__u8 flags;
	__u8 version;
	__u16 proto;
} __attribute__((packed));


/*********************************/
/* checksum helpers */

static __always_inline __u32
csum_add(__u32 csum, __u32 addend)
{
	csum += addend;
	return csum + (csum < addend);
}

static __always_inline __u32
csum_diff32(__u32 csum, __u32 from, __u32 to)
{
	return csum_add(csum, csum_add(~from, to));
}

static __always_inline __u32
csum_diff16(__u32 csum, __u16 from, __u16 to)
{
	return csum + (~from & 0xffff) + to;
}

static __always_inline __u16
csum_replace(__u16 old_csum, __u32 diff)
{
	__u32 csum = csum_add(diff, ~old_csum & 0xffff);
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__u16)~csum;
}


/*********************************/
/* ipfrag */

union ipfrag_key
{
	__u8	family;

	struct {
		__u8		family;
		__u8		proto;
		__u16		packet_id;
		__u32		src;		/* net order */
		__u32		dst;		/* net order */
		__u32		pad[7];
	} v4;

	struct {
		__u8		family;
		__u8		proto;
		__u8		pad[2];
		__u32		packet_id;
		union v6addr	src;
		union v6addr	dst;
	} v6;

	struct {
		__u32		data[10];
	} _u4;

} __attribute__((aligned(4))) __attribute__((packed));

#define IPFRAG_FL_RULE_SET	0x01

struct ipfrag_rule
{
	struct bpf_timer timer;
	__u8 flags;
};

/*********************************/


/* Program statistics */
enum pkt_stats_type {
	PKT_STAT_FRAG_FWD = 0,
	PKT_STAT_FRAG_REORDER,
	PKT_STAT_FRAG_NOMATCH_DROP,
	PKT_STAT_MAX,
};

