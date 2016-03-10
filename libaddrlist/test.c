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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libaddrlist.h"

struct in_addr
ip(const char *addr)
{
	struct in_addr in;

	in.s_addr = inet_addr(addr);

	return in;
}


int
main(int argc, char *argv[])
{
	struct addresslist *adrlist;
	struct in_addr in;
	char buf1[128], buf2[128];
	int i;

	printf("============================================================\n");
	printf("create\n");
	adrlist = addresslist_new();
	addresslist_dump(adrlist);

	printf("============================================================\n");
	printf("set\n");

#if 0
	addresslist_exclude_daddr(adrlist, ip("172.16.0.1"));
	addresslist_exclude_daddr(adrlist, ip("172.16.0.255"));

	addresslist_append(adrlist,
	    IPPROTO_TCP,
	    ip("192.168.0.1"), ip("192.168.0.1"),
	    ip("172.16.0.1"), ip("172.16.0.255"),
	    9, 9,
	    9, 9);
	addresslist_dump(adrlist);
#endif

	addresslist_append(adrlist,
	    IPPROTO_UDP,
	    ip("1.2.3.4"), ip("1.2.3.5"),
	    ip("9.9.9.9"), ip("9.9.9.9"),
	    5, 10,
	    9, 10);
	addresslist_dump(adrlist);

#if 0
	addresslist_append(adrlist,
	    IPPROTO_TCP,
	    ip("1.2.3.4"), ip("1.2.3.4"),
	    ip("10.0.0.1"), ip("10.0.0.10"),
	    9, 9,
	    1024, 1030);
	addresslist_dump(adrlist);


#endif

	addresslist_rebuild(adrlist);
	addresslist_dump(adrlist);

	for (i = 0; i < adrlist->ntuple; i++) {
		const struct address_tuple *tuple;

		tuple = addresslist_get_tuple_next(adrlist);
		inet_ntop(AF_INET, &tuple->saddr, buf1, sizeof(buf1));
		inet_ntop(AF_INET, &tuple->daddr, buf2, sizeof(buf2));
		printf("%d: %d %s:%d %s:%d\n", i, tuple->proto, buf1, tuple->sport, buf2, tuple->dport);
	}


	return 0;
}
