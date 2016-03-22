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
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "util.h"

char *
ip6_sprintf(struct in6_addr *addr)
{
	static char buf[8][INET6_ADDRSTRLEN];
	static int i;
	char *p = buf[i++ & 7];

	inet_ntop(AF_INET6, addr, p, sizeof(buf[0]));
	return p;
}

char *
ip4_sprintf(struct in_addr *addr)
{
	static char buf[8][INET_ADDRSTRLEN];
	static int i;
	char *p = buf[i++ & 7];

	inet_ntop(AF_INET, addr, p, sizeof(buf[0]));
	return p;
}

void
prefix2in6addr(int prefix, struct in6_addr *addr)
{
	if (prefix > 128)
		prefix = 128;

	if (prefix < 128)
		memset(&addr->s6_addr[prefix / 8], 0, 16 - (prefix / 8));
	if (prefix >= 8)
		memset(addr, 0xff, prefix / 8);
	if (prefix < 128)
		addr->s6_addr[prefix / 8] = 0xff << (8 - (prefix & 7));
}

unsigned int
in6addr2prefix(struct in6_addr *addr)
{
	unsigned int prefix;
	int i;

	for (prefix = 0; prefix < 128; prefix += 8) {
		if (addr->s6_addr[prefix / 8] != 0xff) {
			for (i = 0; i < 8; i++) {
				if ((addr->s6_addr[prefix / 8] & (0x80 >> i)) != 0) {
					prefix += i;
					break;
				}
			}
			break;
		}
	}

	return prefix;
}

int
ipv6_iszero(struct in6_addr *addr)
{
	int i;

	for (i = 0; i < 16; i++) {
		if (addr->s6_addr[i] != 0)
			return 0;
	}
	return 1;
}

int
ipv4_iszero(struct in_addr *addr)
{
	if (addr->s_addr == 0)
		return 1;

	return 0;
}

int
ipv6_not(struct in6_addr *src, struct in6_addr *dst)
{
	int i;

	for (i = 0; i < 16; i++)
		dst->s6_addr[i] = ~src->s6_addr[i];

	return 0;
}

int
ipv6_and(struct in6_addr *a, struct in6_addr *b, struct in6_addr *dst)
{
	int i;

	for (i = 0; i < 16; i++)
		dst->s6_addr[i] = a->s6_addr[i] & b->s6_addr[i];

	return 0;
}

int
ipv6_or(struct in6_addr *a, struct in6_addr *b, struct in6_addr *dst)
{
	int i;

	for (i = 0; i < 16; i++)
		dst->s6_addr[i] = a->s6_addr[i] | b->s6_addr[i];

	return 0;
}

void
chop(char *p)
{
	char c;

	for (c = '\0'; *p != '\0'; c = *p++)
		;
	if (c == '\n')
		*--p = '\0';
}

int
interface_is_active(const char *ifname)
{
	FILE *fp;
	char buf[256], *p;
	int active;

	active = 0;
	snprintf(buf, sizeof(buf), "ifconfig %s", ifname);

#define IFCONFIG_STATUS	"\tstatus: "
	fp = popen(buf, "r");
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		chop(buf);
		p = strstr(buf, IFCONFIG_STATUS);
		if (p != NULL) {
			p += strlen(IFCONFIG_STATUS);
			if (strcmp(p, "active") == 0) {
				active = 1;
				break;
			}
		}
	}
	pclose(fp);

	return active;
}

struct in_addr *
getifipaddr(const char *ifname, struct in_addr *addr, struct in_addr *netmask)
{
	struct ifaddrs *ifap, *ifa;
	const struct sockaddr_in *sin;
	int found = 0;

	if (getifaddrs(&ifap) != 0)
		return NULL;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) != 0)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET) {
			sin = (const struct sockaddr_in *)ifa->ifa_addr;
			*addr = sin->sin_addr;
			*netmask = ((const struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;
			found = 1;
			break;
		}
	}

	freeifaddrs(ifap);
	return found ? (struct in_addr *)addr : NULL;
}

struct in6_addr *
getifip6addr(const char *ifname, struct in6_addr *addr, struct in6_addr *netmask)
{
	struct ifaddrs *ifap, *ifa;
	const struct sockaddr_in6 *sin6;
	int found = 0;

	if (getifaddrs(&ifap) != 0)
		return NULL;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) != 0)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET6) {
			sin6 = (const struct sockaddr_in6 *)ifa->ifa_addr;
			*addr = sin6->sin6_addr;
			*netmask = ((const struct sockaddr_in6 *)ifa->ifa_netmask)->sin6_addr;
			found = 1;
			break;
		}
	}

	freeifaddrs(ifap);
	return found ? (struct in6_addr *)addr : NULL;
}

uint8_t *
getiflinkaddr(const char *ifname, struct ether_addr *addr)
{
	struct ifaddrs *ifap, *ifa;
	const struct sockaddr_dl *sdl;
	int found = 0;

	if (getifaddrs(&ifap) != 0)
		return NULL;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) != 0)
			continue;

		if (ifa->ifa_addr->sa_family == AF_LINK) {
			sdl = (const struct sockaddr_dl *) ifa->ifa_addr;
			if ((sdl->sdl_type == IFT_ETHER) &&
			    (sdl->sdl_alen == ETHER_ADDR_LEN)) {

				memcpy(addr, (struct ether_addr *)LLADDR(sdl), ETHER_ADDR_LEN);
				found = 1;
				break;
			}
		}
	}

	freeifaddrs(ifap);
	return found ? (uint8_t *)addr : NULL;
}

int
listentcp(in_addr_t addr, uint16_t port)
{
	int s, on, rc;
	struct sockaddr_in sin;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		warn("socket");
		return -1;
	}
	on = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on));
	setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on));

	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = addr;

	rc = bind(s, (struct sockaddr *)&sin, sin.sin_len);
	if (rc < 0) {
		warn("bind");
		close(s);
		return -1;
	}
	rc = listen(s, 5);
	if (rc < 0) {
		warn("listen");
		close(s);
		return -1;
	}

	return s;
}
