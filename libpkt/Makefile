.include <bsd.own.mk>

CFLAGS+=	-Wall
LIB=	pkt
INTERNALLIB=

SRCS+=	dumpstr.c
SRCS+=	etherpkt.c
SRCS+=	ip4pkt.c
SRCS+=	ip6pkt.c
SRCS+=	utils.c

# x86
CFLAGS+=-DUSE_CPU_IN_CKSUM

SRCS+=	in_cksum.c
SRCS+=	cpu_in_cksum.S

CFLAGS+=	-Wno-address-of-packed-member

test: libpkt.a
	cc test.c libpkt.a && ./a.out | tcpdump -vvvv -n -s0 -X -r -

.include <bsd.lib.mk>


