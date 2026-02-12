/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>


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
#define __no_inline		__attribute__((noinline))

#ifndef min
# define min(x,y) ((x)<(y) ? x : y)
#endif


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

union v6addr
{
	struct {
		__u64 d1;
		__u64 d2;
	};
	__u32 addr4[4];
	__u8 addr[16];
} __attribute__((packed));

union v4v6addr
{
	struct {
		__be32		ip4;
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

/* modified GRE header for PPTP
 * may have more field wrt flags. */
struct gre_hdr_pptp
{
	__u8 flags;		/* bitfield */
	__u8 version;		/* should be GRE_VERSION_PPTP */
	__u16 protocol;		/* should be GRE_PROTOCOL_PPTP */
	__u16 payload_len;	/* size of ppp payload, not inc. gre header */
	__u16 call_id;		/* peer's call_id for this session */
} __attribute__((packed));


/*********************************/
/* gtp-u stuff */

/* fixme: duplicate with gtp.h */
#ifndef GTPU_ECHO_REQ_TYPE
struct gtphdr {
	__u8		flags;
	__u8		type;
	__be16		length;
	__be32		teid;
} __attribute__ ((__packed__));
#define GTPU_TPDU		0xff
#define GTPU_FLAGS		0x30
#define GTPU_PORT		2152
#define GTPC_PORT		2123
#define GTPU_ECHO_REQ_TYPE	1
#endif

/*********************************/
/* checksum helpers */

#ifdef EBPF_SRC

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
	return csum_add(csum, (~from & 0xffff) + to);
}

static __always_inline __u16
csum_replace(__u16 old_csum, __u32 diff)
{
	__u32 csum = csum_add(diff, ~old_csum & 0xffff);
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__u16)~csum;
}

static __always_inline __u16
csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum>>16) + (csum & 0xffff);
	sum += (sum>>16);
	return ~sum;
}

static __always_inline void
csum_ipv4(void *data_start, int data_size, __u32 *csum)
{
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = csum_fold_helper(*csum);
}

#endif /* EBPF_SRC */

/*********************************/
/* ipfrag */

struct ip4_frag_key {
	__u32		saddr;
	__u32		daddr;
	__u16		id;
	__u8		protocol;
	__u8		pad;
} __attribute__((packed));

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
/* ipv6 */

#define IPV6_MAX_HEADERS	4

#ifdef EBPF_SRC
/* from netinet/in.h */
# define IN6_IS_ADDR_LINKLOCAL(a)				    \
 	(((a)->s6_addr32[0] & __constant_htonl(0xffc00000)) ==	    \
	 __constant_htonl(0xfe800000))

struct ipv6_frag_hdr
{
	__u8 nexthdr;
	__u8 hdrlen;
	__be16 frag_off;
	__be32 id;
} __attribute__((packed));


static __always_inline void *
ipv6_skip_exthdr(struct ipv6hdr *ip6h, void *data_end, __u8 *out_nh)
{
	struct ipv6_opt_hdr *opthdr;
	struct ipv6_frag_hdr *fraghdr;
	__u8 nh = ip6h->nexthdr;
	void *data = ip6h + 1;
	int i;

#pragma unroll
	for (i = 0; i < IPV6_MAX_HEADERS; i++) {
		switch (nh) {
		case IPPROTO_NONE:
			return NULL;

		case IPPROTO_FRAGMENT:
			if (data + sizeof (*fraghdr) > data_end)
				return NULL;
			fraghdr = data;
			data = fraghdr + 1;
			nh = fraghdr->nexthdr;
			break;

		case IPPROTO_ROUTING:
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
			if (data + sizeof (*opthdr) > data_end)
				return NULL;
			opthdr = data;
			data += 8 + opthdr->hdrlen * 8;
			nh = opthdr->nexthdr;
			break;

		default:
			*out_nh = nh;
			return data;
		}
	}

	return NULL;
}

#endif



/*********************************/


/* Program statistics */
enum pkt_stats_type {
	PKT_STAT_FRAG_FWD = 0,
	PKT_STAT_FRAG_REORDER,
	PKT_STAT_FRAG_NOMATCH_DROP,
	PKT_STAT_MAX,
};

