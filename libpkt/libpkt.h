/*
 * Copyright (c) 2016 Internet Initiative Japan, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _LIBPKT_H_
#define _LIBPKT_H_

#include <sys/param.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#ifdef __NetBSD__
#include <net/if_ether.h>
#elif defined(__OpenBSD__)
#include <netinet/if_ether.h>
#elif defined(__FreeBSD__)
#include <net/ethernet.h>
#define ether_addr_octet octet
#endif
#include <stdio.h>

#define LIBPKT_PKTBUFSIZE	2048


/* ethernet arp packet */
struct arppkt {
	struct ether_header eheader;
	struct {
		uint16_t ar_hrd;			/* +0x00 */
		uint16_t ar_pro;			/* +0x02 */
		uint8_t ar_hln;				/* +0x04 */
		uint8_t ar_pln;				/* +0x05 */
		uint16_t ar_op;				/* +0x06 */
		uint8_t ar_sha[ETHER_ADDR_LEN];		/* +0x08 */
		struct in_addr ar_spa;			/* +0x0e */
		uint8_t ar_tha[ETHER_ADDR_LEN];		/* +0x12 */
		struct in_addr ar_tpa;			/* +0x18 */
							/* +0x1c */
	} __packed arp;
} __packed;

struct ndpkt {
	struct ether_header eheader;
	struct ip6_hdr ip6;
	union {
		struct icmp6_hdr nd_icmp6;
		struct nd_neighbor_solicit nd_solicit;
		struct nd_neighbor_advert nd_advert;
	} nd;
#define nd_solicit	nd.nd_solicit
#define nd_advert	nd.nd_advert
#define nd_icmp6	nd.nd_icmp6
	uint8_t opt[8];
} __packed;

static inline unsigned int align(unsigned int n, unsigned int a)
{
	return (n + a - 1) & (-a);
}

static inline unsigned int
reduce1(uint32_t sum)
{
	if (sum == 0)
		return 0xffff;

	sum = ((sum >> 16) & 0xffff) + (sum & 0xffff);
	sum &= 0xffff;
	if (sum == 0)
		sum++;
	return sum;
}

/* cksum.c */
unsigned int in4_cksum(struct in_addr, struct in_addr, int, char *, unsigned int);
unsigned int in6_cksum(struct in6_addr *, struct in6_addr *, int, char *, unsigned int);
unsigned int in_cksum(unsigned int, char *, unsigned int);

/* etherpkt.c */
int ethpkt_template(char *, unsigned int);
int ethpkt_type(char *, u_short);
int ethpkt_src(char *, u_char *);
int ethpkt_dst(char *, u_char *);

/* ip4pkt.c */
int ip4pkt_arpparse(char *, int *, struct ether_addr *, in_addr_t *);
int ip4pkt_arpquery(char *, const struct ether_addr *, in_addr_t, in_addr_t);
int ip4pkt_arpreply(char *, const char *, u_char *, in_addr_t, in_addr_t);
int ip4pkt_icmp_template(char *, unsigned int);
int ip4pkt_icmp_echoreply(char *, const char *, unsigned int);
int ip4pkt_icmp_type(char *, int);
int ip4pkt_udp_template(char *, unsigned int);
int ip4pkt_tcp_template(char *, unsigned int);
int ip4pkt_length(char *, unsigned int);
int ip4pkt_off(char *, uint16_t);
int ip4pkt_id(char *, uint16_t);
int ip4pkt_ttl(char *, unsigned int);
int ip4pkt_src(char *, in_addr_t);
int ip4pkt_dst(char *, in_addr_t);
int ip4pkt_srcport(char *, uint16_t);
int ip4pkt_dstport(char *, uint16_t);
int ip4pkt_payload(char *, char *, unsigned int);

int ip4pkt_icmptype(char *, uint8_t);
int ip4pkt_icmpcode(char *, uint8_t);
int ip4pkt_icmpid(char *, uint16_t);
int ip4pkt_icmpseq(char *, uint16_t);

int ip4pkt_tcpseq(char *, uint32_t);
int ip4pkt_tcpack(char *, uint32_t);
int ip4pkt_tcpflags(char *, int);
int ip4pkt_tcpwin(char *, uint16_t);
int ip4pkt_tcpurp(char *, uint16_t);

int ip4pkt_writedata(char *, unsigned int, char *, unsigned int);
int ip4pkt_readdata(char *, unsigned int, char *, unsigned int);
char *ip4pkt_getptr(char *, unsigned int);

int ip4pkt_test_cksum(char *, unsigned int);

/* ip6pkt.c */
int ip6pkt_neighbor_parse(char *, int *, struct ether_addr *, struct in6_addr *);
int ip6pkt_neighbor_solicit(char *, const struct ether_addr *, struct in6_addr *, struct in6_addr *);
int ip6pkt_neighbor_solicit_reply(char *, const char *, u_char *, struct in6_addr *);
int ip6pkt_icmp6_template(char *, unsigned int);
int ip6pkt_icmp6_echoreply(char *, const char *, unsigned int);
int ip6pkt_icmp6_type(char *, unsigned int);
int ip6pkt_udp_template(char *, unsigned int);
int ip6pkt_tcp_template(char *, unsigned int);
int ip6pkt_length(char *, unsigned int);
int ip6pkt_off(char *, uint16_t);
int ip6pkt_flowinfo(char *, uint32_t);
int ip6pkt_ttl(char *, int);
int ip6pkt_src(char *, const struct in6_addr *);
int ip6pkt_dst(char *, const struct in6_addr *);
int ip6pkt_srcport(char *, uint16_t);
int ip6pkt_dstport(char *, uint16_t);
int ip6pkt_payload(char *, char *, unsigned int);

int ip6pkt_icmptype(char *, uint8_t);
int ip6pkt_icmpcode(char *, uint8_t);
int ip6pkt_icmpid(char *, uint16_t);
int ip6pkt_icmpseq(char *, uint16_t);

int ip6pkt_tcpseq(char *, uint32_t);
int ip6pkt_tcpack(char *, uint32_t);
int ip6pkt_tcpflags(char *, int);
int ip6pkt_tcpwin(char *, uint16_t);
int ip6pkt_tcpurp(char *, uint16_t);

int ip6pkt_writedata(char *, unsigned int, char *, unsigned int);
int ip6pkt_readdata(char *, unsigned int, char *, unsigned int);
char *ip6pkt_getptr(char *, unsigned int);

int ip6pkt_test_cksum(char *, unsigned int);


/* debug */
int fdumpstr(FILE *, const char *, size_t);
int dumpstr(const char *, size_t);

/* tcpdump file output utility */
int tcpdumpfile_open(const char *);
ssize_t tcpdumpfile_output(int, char *, int);
void tcpdumpfile_close(int);

#endif /* _LIBPKT_H_ */
