/*
 * Copyright (c) 2021 Ryota Ozaki <ozaki.ryota@gmail.com>
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
#ifndef _AF_XDP_H_
#define _AF_XDP_H_

struct ax_socket;
struct ax_desc
{
	int			fd;
	struct ax_socket	*axs;
};

struct ax_rx_handle
{
	uint32_t	rring_idx;	/* Index in the Rx ring */
	uint32_t	fring_idx;	/* Index in the Fill ring */
	unsigned int	npkts;
};

static inline void
ax_rx_handle_advance(struct ax_rx_handle *handle)
{
	handle->rring_idx++;
	handle->fring_idx++;
}

static inline int
ax_get_fd(struct ax_desc *ax_desc)
{
	return ax_desc->fd;
}

struct ax_desc *
	ax_open(const char *);
void	ax_close(struct ax_desc *);

unsigned int
	ax_wait_for_packets(struct ax_desc *, struct ax_rx_handle *);
char *
	ax_get_rx_buf(struct ax_desc *, uint32_t *, struct ax_rx_handle *);
void	ax_complete_rx(struct ax_desc *, unsigned int);

uint32_t
	ax_prepare_tx(struct ax_desc *, unsigned int *);
char *
	ax_get_tx_buf(struct ax_desc *, uint32_t **, uint32_t, int);
void	ax_complete_tx(struct ax_desc *, unsigned int);

#endif /* _AF_XDP_H_ */
