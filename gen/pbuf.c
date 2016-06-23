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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "pbuf.h"

#undef PBUFDEBUG

#ifdef PBUFDEBUG
static struct {
	unsigned long alloc;
	unsigned long free;
	unsigned long allocated;
} stat;
#endif

void
pbuf_debug(void)
{
#ifdef PBUFDEBUG
	fprintf(stderr, "pbuf alloc     = %llu\n", (unsigned long long)stat.alloc);
	fprintf(stderr, "pbuf free      = %llu\n", (unsigned long long)stat.free);
	fprintf(stderr, "pbuf allocated = %llu\n", (unsigned long long)stat.allocated);
#endif /* PBUFDEBUG */
}

struct pbuf *
pbuf_alloc(unsigned int len)
{
	struct pbuf *p;

	p = malloc(sizeof(struct pbuf));

	if (p != NULL) {
#ifdef PBUFDEBUG
		stat.alloc++;
		stat.allocated++;
#endif /* PBUFDEBUG */

		p->len = len;
	}
	return p;
}

int
pbuf_free(struct pbuf *p)
{
	free(p);

#ifdef PBUFDEBUG
	stat.free++;
	stat.allocated--;
#endif /* PBUFDEBUG */

	return 0;
}

int
pbufq_init(struct pbufq *pbufq)
{
	pthread_mutex_init(&pbufq->mtx, NULL);
	TAILQ_INIT(&pbufq->q);
	pbufq->n = 0;
	return 0;
}

int
pbufq_enqueue(struct pbufq *pbufq, struct pbuf *p)
{
	pthread_mutex_lock(&pbufq->mtx);
	TAILQ_INSERT_TAIL(&pbufq->q, p, list);
	pbufq->n++;
	pthread_mutex_unlock(&pbufq->mtx);
	return 0;
}

unsigned int
pbufq_nqueued(struct pbufq *pbufq)
{
	return pbufq->n;
}

struct pbuf *
pbufq_dequeue(struct pbufq *pbufq)
{
	struct pbuf *p;

	pthread_mutex_lock(&pbufq->mtx);
	p = TAILQ_FIRST(&pbufq->q);
	if (p != NULL) {
		TAILQ_REMOVE(&pbufq->q, p, list);
		pbufq->n--;
	}
	pthread_mutex_unlock(&pbufq->mtx);
	return p;
}

struct pbuf *
pbufq_poll(struct pbufq *pbufq)
{
	return TAILQ_FIRST(&pbufq->q);
}
