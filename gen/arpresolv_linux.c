/*
 * Copyright (c) 2013 Ryo Shimizu <ryo@nerv.org>
 * Copyright (c) 2021 Ryota Ozaki <ozaki.ryota@gmail.com>
 * All rights reserved.
 *
 * This file is based on arpresolve.c.
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
#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <linux/sysctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/icmp6.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>
#include <err.h>
#include <bsd/sys/time.h>
#include <time.h>

#include "libpkt/libpkt.h"
#include "arpresolv.h"


static int afpkt_read_and_exec(int (*)(void *, unsigned char *, int, const char *), void *, int, const char *, unsigned char *, int);

static void arpquery(int, const char *, struct ether_addr *, struct in_addr *, struct in_addr *);
static void ndsolicit(int, const char *, struct ether_addr *, struct in6_addr *, struct in6_addr *);
static int afpkt_open(const char *, int, unsigned int *, int);
static void afpkt_close(int);
static int getifinfo(const char *, int *, uint8_t *);


struct recvarp_arg {
	struct in_addr src;
	struct ether_addr src_eaddr;
};

struct recvnd_arg {
	struct in6_addr src;
	struct ether_addr src_eaddr;
};

#define BUFSIZE	(1024 * 4)
static unsigned char buf[BUFSIZE];
static unsigned int buflen = BUFSIZE;

#ifdef DEBUG
static int
usage(void)
{
	fprintf(stderr, "usage: arpresolv <interface> <ipv4address>\n");
	fprintf(stderr, "usage: ndresolv <interface> <ipv6address>\n");
	return 99;
}

static int
getaddr(const char *ifname, const struct in_addr *dstaddr, struct in_addr *srcaddr)
{
	int rc;
	struct ifaddrs *ifa0, *ifa;
	struct in_addr src, mask;
	struct in_addr curmask;

	curmask.s_addr = 0;
	src.s_addr = 0;

	rc = getifaddrs(&ifa0);
	ifa = ifa0;
	for (; ifa != NULL; ifa = ifa->ifa_next) {
		if ((strcmp(ifa->ifa_name, ifname) == 0) &&
		    (ifa->ifa_addr->sa_family == AF_INET)) {

			if (src.s_addr == 0)
				src = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;

			/* lookup addr with netmask */
			if (dstaddr != NULL) {
				mask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;
				if ((ntohl(mask.s_addr) > ntohl(curmask.s_addr)) &&
				    ((((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr & mask.s_addr) ==
				    (dstaddr->s_addr & mask.s_addr))) {
					src = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
					curmask = mask;
				}
			}
		}
	}

	if (ifa0 != NULL)
		freeifaddrs(ifa0);

	*srcaddr = src;

	return (src.s_addr == 0);
}

static inline int
ip6_iszero(struct in6_addr *addr)
{
	int i;
	for (i = 0; i < 16; i++) {
		if (addr->s6_addr[0] != 0)
			return 0;
	}
	return 1;
}

static int
getaddr6(const char *ifname, const struct in6_addr *dstaddr, struct in6_addr *srcaddr)
{
	int rc;
	struct ifaddrs *ifa0, *ifa;
	struct in6_addr src;

	memset(&src, 0, sizeof(src));

	rc = getifaddrs(&ifa0);
	ifa = ifa0;
	for (; ifa != NULL; ifa = ifa->ifa_next) {
		if ((strcmp(ifa->ifa_name, ifname) == 0) &&
		    (ifa->ifa_addr->sa_family == AF_INET6)) {

			if (ip6_iszero(&src))
				src = ((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;

			/* lookup address that has same prefix */
			if (dstaddr != NULL) {
				if (memcmp(&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, dstaddr, 8) == 0) {
					memcpy(&src, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, 16);
				}
			}
		}
	}

	if (ifa0 != NULL)
		freeifaddrs(ifa0);

	*srcaddr = src;

	return ip6_iszero(&src);
}

int
main(int argc, char *argv[])
{
	int rc;
	char *ifname;
	struct in_addr src, dst;
	struct in6_addr src6, dst6;
	struct ether_addr *eth;
	char buf[INET6_ADDRSTRLEN];

	if (argc != 3)
		return usage();

	ifname = argv[1];
	if (inet_pton(AF_INET, argv[2], &dst) == 1) {
		rc = getaddr(ifname, &dst, &src);
		if (rc != 0) {
			fprintf(stderr, "%s: %s: source address is unknown\n",
			    ifname, inet_ntoa(dst));
			return 3;
		}
		eth = arpresolv(ifname, &src, &dst);
	} else if (inet_pton(AF_INET6, argv[2], &dst6) == 1) {
		rc = getaddr6(ifname, &dst6, &src6);
		if (rc != 0) {
			fprintf(stderr, "%s: %s: source address is unknown\n",
			    ifname, inet_ntop(AF_INET6, &dst6, buf, sizeof(buf)));
			return 3;
		}
		eth = ndpresolv(ifname, &src6, &dst6);
	} else {
		printf("%s: invalid host\n", argv[2]);
		return 2;
	}

	if (eth != NULL) {
		printf("%s\n", ether_ntoa(eth));
		return 0;
	}
	return 1;
}
#endif

static int
recv_arpreply(void *arg, unsigned char *buf, int buflen, const char *ifname)
{
	struct ether_arp *arp;
	struct recvarp_arg *recvarparg;

#ifdef DEBUG
	fprintf(stderr, "recv_arpreply: %s\n", ifname);
	dumpstr((const char *)buf, buflen, 0);
#endif

	recvarparg = (struct recvarp_arg *)arg;
	arp = (struct ether_arp *)buf;

	if (memcmp(arp->arp_spa, &recvarparg->src, sizeof(arp->arp_spa)) != 0)
		return 0;

	memcpy(&recvarparg->src_eaddr, (struct ether_addr *)(arp->arp_sha), sizeof(struct ether_addr));

	return 1;
}

static int
recv_nd(void *arg, unsigned char *buf, int buflen, const char *ifname)
{
	struct recvnd_arg *recvndarg;
	struct icmp6_hdr *icmp6;
	struct nd_neighbor_advert *na;
	struct ether_addr *eaddr;
	struct ip6_hdr *ip6;

#ifdef DEBUG
	fprintf(stderr, "recv_nd: %s\n", ifname);
	dumpstr((const char *)buf, buflen, 0);
#endif

	recvndarg = (struct recvnd_arg *)arg;

	ip6 = (struct ip6_hdr *)buf;
	if (ip6->ip6_nxt != IPPROTO_ICMPV6)
		return 0;

	icmp6 = (struct icmp6_hdr *)(buf + sizeof(struct ip6_hdr));
	if (icmp6->icmp6_type != ND_NEIGHBOR_ADVERT)
		return 0;

	na = (struct nd_neighbor_advert *)icmp6;
	eaddr = (struct ether_addr *)((char *)na + sizeof(*na) + 2);
	memcpy(&recvndarg->src_eaddr, eaddr, sizeof(struct ether_addr));

	return 1;
}

struct ether_addr *
arpresolv(const char *ifname, struct in_addr *src, struct in_addr *dst)
{
	fd_set rfd;
	struct timespec end, lim, now;
	struct timeval tlim;
	struct ether_addr macaddr;
	struct ether_addr *found;
	int fd, rc, mtu, nretry;

	found = NULL;

	fd = afpkt_open(ifname, 0, &buflen, ETH_P_ARP);
	if (fd < 0) {
		warn("open: %s", ifname);
		return NULL;
	}

	rc = getifinfo(ifname, &mtu, macaddr.ether_addr_octet);
	if (rc != 0) {
		warn("%s", ifname);
		goto close_exit;
	}

	for (nretry = 3; nretry > 0; nretry--) {
		arpquery(fd, ifname, &macaddr, src, dst);

		lim.tv_sec = 1;
		lim.tv_nsec = 0;
		clock_gettime(CLOCK_MONOTONIC, &end);

		timespecadd(&lim, &end, &end);

		for (;;) {
			clock_gettime(CLOCK_MONOTONIC, &now);
			timespecsub(&end, &now, &lim);
			if (lim.tv_sec < 0)
				break;

			TIMESPEC_TO_TIMEVAL(&tlim, &lim);

			FD_ZERO(&rfd);
			FD_SET(fd, &rfd);
			rc = select(fd + 1, &rfd, NULL, NULL, &tlim);
			if (rc < 0) {
				err(1, "select");
				break;
			}

			if (rc == 0) {
				char buf[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, dst, buf, sizeof(buf));
				fprintf(stderr, "%s: %s: arp timeout\n", ifname, buf);
				break;
			}
			if (FD_ISSET(fd, &rfd)) {
				static struct recvarp_arg arg;
				memset(&arg, 0, sizeof(arg));
				arg.src = *dst;

				rc = afpkt_read_and_exec(recv_arpreply, (void *)&arg, fd, ifname, buf, buflen);
				if (rc != 0) {
					found = &arg.src_eaddr;
					break;
				}
			}
		}
		if (found != NULL)
			break;
	}

close_exit:
	afpkt_close(fd);

	return found;
}

struct ether_addr *
ndpresolv(const char *ifname, struct in6_addr *src, struct in6_addr *dst)
{
	fd_set rfd;
	struct timespec end, lim, now;
	struct timeval tlim;
	struct ether_addr macaddr;
	struct ether_addr *found;
	int fd, rc, mtu, nretry;

	found = NULL;

	fd = afpkt_open(ifname, 0, &buflen, ETH_P_IPV6);
	if (fd < 0) {
		warn("open: %s", ifname);
		return NULL;
	}

	rc = getifinfo(ifname, &mtu, macaddr.ether_addr_octet);
	if (rc != 0) {
		warn("%s", ifname);
		goto close_exit;
	}

	for (nretry = 3; nretry > 0; nretry--) {
		ndsolicit(fd, ifname, &macaddr, src, dst);

		lim.tv_sec = 1;
		lim.tv_nsec = 0;
		clock_gettime(CLOCK_MONOTONIC, &end);

		timespecadd(&lim, &end, &end);

		for (;;) {
			clock_gettime(CLOCK_MONOTONIC, &now);
			timespecsub(&end, &now, &lim);
			if (lim.tv_sec < 0)
				break;

			TIMESPEC_TO_TIMEVAL(&tlim, &lim);

			FD_ZERO(&rfd);
			FD_SET(fd, &rfd);
			rc = select(fd + 1, &rfd, NULL, NULL, &tlim);
			if (rc < 0) {
				err(1, "select");
				break;
			}

			if (rc == 0) {
				char buf[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, dst, buf, sizeof(buf));
				fprintf(stderr, "%s: [%s]: neighbor solicit timeout\n", ifname, buf);
				break;
			}
			if (FD_ISSET(fd, &rfd)) {
				static struct recvnd_arg arg;
				memset(&arg, 0, sizeof(arg));
				arg.src = *dst;

				rc = afpkt_read_and_exec(recv_nd, (void *)&arg, fd, ifname, buf, buflen);
				if (rc != 0) {
					found = &arg.src_eaddr;
					break;
				}
			}
		}
		if (found != NULL)
			break;
	}

close_exit:
	afpkt_close(fd);

	return found;
}

static int
afpkt_open(const char *ifname, int promisc, unsigned int *buflen, int proto)
{
	int fd, rc;
	struct sockaddr_ll sall;

	fd = socket(AF_PACKET, SOCK_DGRAM, htons(proto));
	if (fd < 0)
		return fd;

	memset(&sall, 0, sizeof(sall));
	sall.sll_family = AF_PACKET;
	sall.sll_protocol = htons(proto);
	sall.sll_ifindex = if_nametoindex(ifname);

	rc = bind(fd, (struct sockaddr*)&sall, sizeof(sall));
	if (rc < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static void
afpkt_close(int fd)
{
	close(fd);
}

static int
getifinfo(const char *ifname, int *mtu, uint8_t *hwaddr)
{
	int rc;
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(s.ifr_name, ifname);
	rc = ioctl(fd, SIOCGIFHWADDR, &s);
	close(fd);
	if (rc < 0)
		return -1;
	memcpy(hwaddr, s.ifr_addr.sa_data, ETH_ALEN);
	return 0;
}

static void
arpquery(int fd, const char *ifname, struct ether_addr *sha, struct in_addr *src, struct in_addr *dst)
{
	struct sockaddr_ll sall;
	struct ether_arp arp;
	int rc;

	memset(&sall, 0, sizeof(sall));
	sall.sll_family = AF_PACKET;
	sall.sll_protocol = htons(ETH_P_ARP);
	sall.sll_ifindex = if_nametoindex(ifname);
	sall.sll_halen = ETHER_ADDR_LEN;
	memset(&sall.sll_addr, 0xff, ETHER_ADDR_LEN);

	memset(&arp, 0, sizeof(arp));
	arp.arp_hrd = htons(ARPHRD_ETHER);
	arp.arp_pro = htons(ETHERTYPE_IP);
	arp.arp_hln = ETHER_ADDR_LEN;
	arp.arp_pln = sizeof(struct in_addr);
	arp.arp_op  = htons(ARPOP_REQUEST);
	memcpy(arp.arp_sha, sha, ETHER_ADDR_LEN);
	memcpy(arp.arp_spa, src, sizeof(*src));
	memcpy(arp.arp_tpa, dst, sizeof(*dst));

	rc = sendto(fd, (char *)&arp, sizeof(arp), 0, (struct sockaddr *)&sall, sizeof(sall));
	if (rc < 0)
		warn("sendto");
}

static void
ndsolicit(int fd, const char *ifname, struct ether_addr *sha, struct in6_addr *src, struct in6_addr *dst)
{
	struct sockaddr_ll sall;
	char pktbuf[LIBPKT_PKTBUFSIZE];
	char *pkt;
	unsigned int pktlen;
	int rc;

	memset(&sall, 0, sizeof(sall));
	sall.sll_family = AF_PACKET;
	sall.sll_protocol = htons(ETH_P_IPV6);
	sall.sll_ifindex = if_nametoindex(ifname);
	sall.sll_halen = ETHER_ADDR_LEN;
	memset(&sall.sll_addr, 0xff, ETHER_ADDR_LEN);

	pktlen = ip6pkt_neighbor_solicit(pktbuf, sha, src, dst);
	pkt = pktbuf + sizeof(struct ether_header);
	pktlen -= sizeof(struct ether_header);

#ifdef DEBUG
	fprintf(stderr, "send nd-solicit on %s\n", ifname);
	dumpstr((const char *)pktbuf, pktlen, 0);
#endif

	rc = sendto(fd, pkt, pktlen, 0, (struct sockaddr *)&sall, sizeof(sall));
	if (rc < 0)
		warn("sendto");
}

static int
afpkt_read_and_exec(int (*recvcallback)(void *, unsigned char *, int, const char *),
    void *callbackarg, int fd, const char *ifname,
    unsigned char *buf, int buflen)
{
	ssize_t rc, len;

	rc = recvfrom(fd, buf, buflen, 0, NULL, NULL);
	if (rc == 0) {
		fprintf(stderr, "read: bpf: no data\n");
		return -1;
	} else if (rc < 0) {
		warn("read");
		return -1;
	} else {
		len = rc;
		rc = recvcallback(callbackarg, buf, len, ifname);
	}

	return rc;
}
