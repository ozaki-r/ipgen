.include <bsd.own.mk>

CFLAGS+=	-Wall
LIB=	addrlist
INTERNALLIB=

SRCS+=	addresses.c

test: libaddrlist.a
	cc test.c libaddrlist.a && ./a.out

.include <bsd.lib.mk>

