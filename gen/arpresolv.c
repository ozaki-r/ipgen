/*
 * Copyright (c) 2013 Ryo Shimizu <ryo@nerv.org>
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
#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/if_arp.h>
#ifdef __FreeBSD__
#include <net/ethernet.h>
#else
#include <net/if_ether.h>
#endif
#include <net/bpf.h>
#include <net/route.h>
#include <netinet/in.h>
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

#include "arpresolv.h"

#undef DEBUG

#ifdef DEBUG
static void dumpstr(const uint8_t *, size_t);
#endif

static int bpfread_and_exec(int (*)(void *, unsigned char *, int, const char *), void *, int, const char *, unsigned char *, int);

static int bpfslot(void);
static void arpquery(int, const char *, struct ether_addr *, struct in_addr *, struct in_addr *);
static int bpfopen(const char *, int, unsigned int *);
static void bpfclose(int);
static int bpf_arpfilter(int);
static int getifinfo(const char *, int *, uint8_t *);


/* for compatibility */
#ifdef __FreeBSD__
#define ether_addr_octet octet
#endif

#define TIMESPECADD(tsp, usp, vsp)					\
	do {								\
		(vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec >= 1000000000L) {			\
			(vsp)->tv_sec++;				\
			(vsp)->tv_nsec -= 1000000000L;			\
		}							\
	} while (/* CONSTCOND */ 0)
#define TIMESPECSUB(tsp, usp, vsp)                                      \
	do {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
		}							\
	} while (/* CONSTCOND */ 0)

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

struct recvarp_arg {
	struct in_addr src;
	struct ether_addr src_eaddr;
};

struct bpf_insn arp_reply_filter[] = {
	/* check ethertype */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, ETHER_ADDR_LEN * 2),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_ARP, 0, 5),

	/* check ar_hrd == ARPHDR_ETHER && ar_pro == ETHERTYPE_IP */
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ETHER_HDR_LEN),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
	    (ARPHRD_ETHER << 16) + ETHERTYPE_IP, 0, 3),
	/* check ar_hln, ar_pln, ar_op */
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ETHER_HDR_LEN + 4),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
	    (ETHER_ADDR_LEN << 24) + (sizeof(struct in_addr) << 16) +
	    ARPOP_REPLY, 0, 1),

	BPF_STMT(BPF_RET + BPF_K, -1),	/* return -1 */
	BPF_STMT(BPF_RET + BPF_K, 0),	/* return 0 */
};

#define BPFBUFSIZE	(1024 * 4)
unsigned char bpfbuf[BPFBUFSIZE];
unsigned int bpfbuflen = BPFBUFSIZE;

#if 0
static int
usage(void)
{
	fprintf(stderr, "usage: arpresolv <interface> <ipv4addr>\n");
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

			/* find addr with netmask */
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

int
main(int argc, char *argv[])
{
	int rc;
	char *ifname;
	struct in_addr src, dst;
	struct ether_addr *eth;

	if (argc != 3)
		return usage();

	ifname = argv[1];
	if (inet_aton(argv[2], &dst) == 0) {
		printf("%s: invalid host\n", argv[2]);
		return 2;
	}

	rc = getaddr(ifname, &dst, &src);
	if (rc != 0) {
		fprintf(stderr, "%s: %s: source address is unknown\n",
		    ifname, inet_ntoa(dst));
		return 3;
	}

	eth = arpresolv(ifname, &src, &dst);
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
	struct arppkt *arppkt;
	struct recvarp_arg *recvarparg;

#ifdef DEBUG
	fprintf(stderr, "recv_arpreply: %s\n", ifname);
	dumpstr((uint8_t *)buf, buflen);
#endif

	recvarparg = (struct recvarp_arg *)arg;
	arppkt = (struct arppkt *)buf;

	if (arppkt->arp.ar_spa.s_addr != recvarparg->src.s_addr)
		return 0;

	memcpy(&recvarparg->src_eaddr, (struct ether_addr *)(arppkt->arp.ar_sha), sizeof(struct ether_addr));

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

	fd = bpfopen(ifname, 0, &bpfbuflen);
	if (fd < 0) {
		warn("open: %s", ifname);
		return NULL;
	}

	bpf_arpfilter(fd);

	rc = getifinfo(ifname, &mtu, macaddr.ether_addr_octet);
	if (rc != 0) {
		warn("%s", ifname);
		return NULL;
	}

	for (nretry = 3; nretry > 0; nretry--) {
		arpquery(fd, ifname, &macaddr, src, dst);

		lim.tv_sec = 1;
		lim.tv_nsec = 0;
		clock_gettime(CLOCK_MONOTONIC, &end);

		TIMESPECADD(&lim, &end, &end);

		for (;;) {
			clock_gettime(CLOCK_MONOTONIC, &now);
			TIMESPECSUB(&end, &now, &lim);
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
				fprintf(stderr, "arp timeout\n");
				break;
			}
			if (FD_ISSET(fd, &rfd)) {
				static struct recvarp_arg arg;
				memset(&arg, 0, sizeof(arg));
				arg.src = *dst;

				rc = bpfread_and_exec(recv_arpreply, (void *)&arg, fd, ifname, bpfbuf, bpfbuflen);
				if (rc != 0) {
					found = &arg.src_eaddr;
					break;
				}
			}
		}
		if (found != NULL)
			break;
	}

	bpfclose(fd);

	return found;
}

static int
bpfslot()
{
	int fd, i;

#ifdef _PATH_BPF
	fd = open(_PATH_BPF, O_RDWR);
#else
	char devbpf[PATH_MAX + 1];

	memset(devbpf, 0, sizeof(devbpf));
	i = 0;
	do {
		snprintf(devbpf, sizeof(devbpf), "/dev/bpf%d", i++);
		fd = open(devbpf, O_RDWR);
	} while ((fd < 0) && (errno == EBUSY));
#endif

	return fd;
}

static int
bpf_arpfilter(int fd)
{
	struct bpf_program bpfprog;
	int rc;

	memset(&bpfprog, 0, sizeof(bpfprog));
#ifdef nitems
	bpfprog.bf_len = nitems(arp_reply_filter);
#else
	bpfprog.bf_len = __arraycount(arp_reply_filter);
#endif

	bpfprog.bf_insns = arp_reply_filter;
	rc = ioctl(fd, BIOCSETF, &bpfprog);
	if (rc != 0)
		warn("ioctl: BIOCSETF");

	return rc;
}

static int
bpfopen(const char *ifname, int promisc, unsigned int *buflen)
{
	int fd, flag, rc;
	struct ifreq ifr;
	struct bpf_version bv;

	rc = 0;
	fd = bpfslot();
	if (fd < 0) {
		warn("open: bpf");
		rc = -1;
		goto bpfopen_err;
	}

	if (ioctl(fd, BIOCVERSION, (caddr_t)&bv) < 0) {
		warn("ioctl: BIOCVERSION");
		rc = -1;
		goto bpfopen_err;
	}

	if (bv.bv_major != BPF_MAJOR_VERSION ||
	    bv.bv_minor < BPF_MINOR_VERSION) {
		fprintf(stderr, "kernel bpf filter out of date");
		rc = -1;
		goto bpfopen_err;
	}

	memset(&ifr, 0, sizeof(ifr));
	if (ifname != NULL) {
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
			warn("ioctl: %s: BIOCSETIF", ifname);
			rc = -2;
			goto bpfopen_warn;
		}
	}

	flag = 1;
	ioctl(fd, BIOCIMMEDIATE, &flag);

	if (promisc) {
		if (ioctl(fd, BIOCPROMISC, 0) != 0) {
			warn("ioctl: BIOCPROMISC: %s", ifname);
		}
	}

	ioctl(fd, BIOCSBLEN, buflen);
	ioctl(fd, BIOCGBLEN, buflen);	/* return value for caller */

	return fd;

 bpfopen_warn:
 bpfopen_err:
	if (fd >= 0)
		close(fd);

	return rc;
}

static void
bpfclose(int fd)
{
	close(fd);
}

static int
getifinfo(const char *ifname, int *mtu, uint8_t *hwaddr)
{
	int mib[6] = {
		CTL_NET,
		AF_ROUTE,
		0,
		AF_LINK,
		NET_RT_IFLIST,
		0
	};
	uint8_t *buf, *end, *msghdr;
	struct if_msghdr *ifm;
	struct if_data *ifd = NULL;
	struct sockaddr_dl *sdl;
	size_t len;
	int rc;

	rc = -1;
	buf = NULL;
	if (sysctl(mib, 6, NULL, &len, NULL, 0) == -1) {
		fprintf(stderr, "sysctl: %s: cannot get iflist size",
		    strerror(errno));
		goto getifinfo_done;
	}
	if ((buf = malloc(len)) == NULL) {
		fprintf(stderr, "cannot allocate memory");
		goto getifinfo_done;
	}
	if (sysctl(mib, 6, buf, &len, NULL, 0) == -1) {
		fprintf(stderr, "sysctl: %s: cannot get iflist",
		    strerror(errno));
		goto getifinfo_done;
	}

	end = buf + len;
	for (msghdr = buf; msghdr < end; msghdr += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)msghdr;
		if (ifm->ifm_type == RTM_IFINFO) {
			sdl = (struct sockaddr_dl *)(ifm + 1);

			if (sdl->sdl_type != IFT_ETHER)
				continue;
			if (strncmp(&sdl->sdl_data[0], ifname, sdl->sdl_nlen)
			    != 0)
				continue;


			ifd = &ifm->ifm_data;
			if (mtu != NULL)
				*mtu = ifd->ifi_mtu;
			memcpy(hwaddr, LLADDR(sdl), ETHER_ADDR_LEN);
			rc = 0;
			break;
		}
	}
	if (rc != 0)
		fprintf(stderr,
		    "%s: Not a ethernet interface or no such interface",
		    ifname);

 getifinfo_done:
	if (buf != NULL)
		free(buf);

	return rc;
}

#ifdef DEBUG
static void
dumpstr(const uint8_t *str, size_t len)
{
	const unsigned char *p = (const unsigned char*)str;
	size_t i = len;
	char ascii[17];
	char *ap = ascii;

	while (i > 0) {
		unsigned char c;

		if (((len - i) & 15) == 0) {
			printf("%08x:", (unsigned int)(len - i));
			ap = ascii;
		}

		c = p[len - i];
		fprintf(stderr, " %02x", c);
		i--;

		*ap++ = isprint(c) ? c : '.';

		if (((len - i) & 15) == 0) {
			*ap = '\0';
			fprintf(stderr, "  %s\n", ascii);
		}
	}
	*ap = '\0';

	if (len & 0xf) {
		const char *whitesp =
		 /* "00 01 02 03 04 05 06 07:08 09 0A 0B 0C 0D 0E 0F " */
		    "                                                ";
		i = len % 16;
		fprintf(stderr, "%s  %s\n", whitesp + (i * 3), ascii);
	}
}
#endif /* DEBUG */

static void
arpquery(int fd, const char *ifname, struct ether_addr *sha, struct in_addr *src, struct in_addr *dst)
{
	struct arppkt aquery;
	static const uint8_t eth_broadcast[ETHER_ADDR_LEN] =
	    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	/* build arp reply packet */
	memset(&aquery, 0, sizeof(aquery));
	memcpy(&aquery.eheader.ether_dhost, eth_broadcast, ETHER_ADDR_LEN);
	memcpy(&aquery.eheader.ether_shost, sha->ether_addr_octet,
	    ETHER_ADDR_LEN);
	aquery.eheader.ether_type = htons(ETHERTYPE_ARP);
	aquery.arp.ar_hrd = htons(ARPHRD_ETHER);
	aquery.arp.ar_pro = htons(ETHERTYPE_IP);
	aquery.arp.ar_hln = ETHER_ADDR_LEN;
	aquery.arp.ar_pln = sizeof(struct in_addr);
	aquery.arp.ar_op = htons(ARPOP_REQUEST);
	memcpy(&aquery.arp.ar_sha, sha->ether_addr_octet,
	    ETHER_ADDR_LEN);
	memcpy(&aquery.arp.ar_spa, src, sizeof(struct in_addr));
	memcpy(&aquery.arp.ar_sha, sha->ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(&aquery.arp.ar_tpa, dst, sizeof(struct in_addr));

#ifdef DEBUG
	fprintf(stderr, "send arp-query on %s\n", ifname);
	dumpstr((uint8_t *)&aquery, sizeof(aquery));
#endif

	/* send an arp-query via bpf */
	write(fd, &aquery, sizeof(aquery));
}

static int
bpfread_and_exec(int (*recvcallback)(void *, unsigned char *, int, const char *),
    void *callbackarg, int fd, const char *ifname,
    unsigned char *buf, int buflen)
{
	ssize_t rc;

	rc = read(fd, buf, buflen);
	if (rc == 0) {
		fprintf(stderr, "read: bpf: no data\n");
		return -1;
	} else if (rc < 0) {
		warn("read");
		return -1;
	} else {
		uint8_t *p = buf;
		uint8_t *end = p + rc;

		rc = 0;
		while (p < end) {
			unsigned int perpacketsize =
			    ((struct bpf_hdr*)p)->bh_hdrlen +
			    ((struct bpf_hdr*)p)->bh_caplen;

			rc = recvcallback(callbackarg,
			    ((uint8_t *)p + ((struct bpf_hdr*)p)->bh_hdrlen),
			    ((struct bpf_hdr*)p)->bh_datalen, ifname);

			if (rc != 0)
				break;

			p += BPF_WORDALIGN(perpacketsize);
		}
	}

	return rc;
}
