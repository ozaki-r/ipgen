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
#ifndef _PBUF_H_
#define _PBUF_H_

#include <sys/queue.h>

struct pbuf {
	TAILQ_ENTRY(pbuf) list;
	unsigned int len;
	char data[2048];
};

TAILQ_HEAD(pbufq_head, pbuf);
struct pbufq {
	struct pbufq_head q;
	unsigned int n;
};

struct pbuf *pbuf_alloc(unsigned int);
int pbuf_free(struct pbuf *);

int pbufq_init(struct pbufq *);
int pbufq_enqueue(struct pbufq *, struct pbuf *);
struct pbuf *pbufq_dequeue(struct pbufq *);
struct pbuf *pbufq_poll(struct pbufq *);
unsigned int pbufq_nqueued(struct pbufq *);

void pbuf_debug(void);	/* for debug */

#endif /* _PBUF_H_ */
