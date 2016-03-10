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
#ifndef _LIBADDR_H_
#define _LIBADDR_H_

struct address {
	uint8_t af;
	union {
		struct in_addr addr4;
		struct in6_addr addr6;
	} a;
};

struct addresslist {
	unsigned int ntuple;
	unsigned int curtuple;
	int sorted;
	unsigned int tuple_limit;

	unsigned int exclude_saddr_num;
	unsigned int exclude_daddr_num;
	struct address *exclude_saddr;
	struct address *exclude_daddr;

	struct address_tuple *tuple;
};

struct address_tuple {
	struct address saddr, daddr;
	uint16_t sport, dport;
	uint16_t proto;
} __packed;

struct addresslist *addresslist_new(void);
void addresslist_delete(struct addresslist *);

int addresslist_exclude_saddr(struct addresslist *, struct in_addr);
int addresslist_exclude_daddr(struct addresslist *, struct in_addr);
int addresslist_append(struct addresslist *, uint8_t, struct in_addr, struct in_addr, struct in_addr, struct in_addr, uint16_t, uint16_t, uint16_t, uint16_t);

int addresslist_exclude_saddr6(struct addresslist *, struct in6_addr *);
int addresslist_exclude_daddr6(struct addresslist *, struct in6_addr *);
int addresslist_append6(struct addresslist *, uint8_t, struct in6_addr *, struct in6_addr *, struct in6_addr *, struct in6_addr *, uint16_t, uint16_t, uint16_t, uint16_t);

int addresslist_rebuild(struct addresslist *);
void addresslist_setlimit(struct addresslist *, unsigned int);
unsigned int addresslist_get_tuplenum(struct addresslist *);
void addresslist_set_current_tupleid(struct addresslist *, unsigned int);
unsigned int addresslist_get_current_tupleid(struct addresslist *);
const struct address_tuple *addresslist_get_current_tuple(struct addresslist *);
const struct address_tuple *addresslist_get_tuple_next(struct addresslist *);
int addresslist_tuple2id(struct addresslist *, struct address_tuple *);

int addresslist_include_af(struct addresslist *, int);

void addresslist_dump(struct addresslist *);

#endif /* _LIBADDR_H_ */
