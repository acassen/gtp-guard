/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <stdbool.h>
#include <netinet/in.h>
#include <linux/if_packet.h>

#ifdef __cplusplus
extern "C" {
#endif

union addr
{
	sa_family_t family;
	struct sockaddr sa;
	struct sockaddr_in sin;		/* AF_INET */
	struct sockaddr_in6 sin6;	/* AF_INET6 */
	struct sockaddr_ll sll;		/* AF_PACKET */
	struct sockaddr_storage ss;
};

static void addr_zero(union addr *a);
socklen_t addr_len(const union addr *a);
void addr_copy(union addr *dst, const union addr *src);
int addr_cmp(const union addr *la, const union addr *ra);
int addr_cmp_ip(const union addr *la, const union addr *ra);
int addr_cmp_port(const union addr *la, const union addr *ra);
uint16_t addr_get_port(const union addr *a);
void addr_set_port(union addr *a, uint16_t port);
bool addr_is_unicast(const union addr *a);
char *addr_stringify(const union addr *a, char *buf, size_t buf_size);
char *addr_stringify_ip(const union addr *a, char *buf, size_t buf_size);
char *addr_stringify_port(const union addr *a, char *buf, size_t buf_size);
int addr_parse(char *paddr, union addr *a);
int addr_parse_const(const char *paddr, union addr *a);
int addr_parse_ip(const char *paddr, union addr *a, uint32_t *out_netmask,
		  uint64_t *out_count, bool first_ip);
int addr_parse_iface(const char *iface_name, union addr *a);


static inline void
addr_zero(union addr *a)
{
	a->sa.sa_family = AF_UNSPEC;
}

#ifdef __cplusplus
} // extern "C"
#endif
