.include <bsd.own.mk>
.include <../Makefile.inc>

OS!=		uname -s
.if ${OS} != "Linux"
DESTDIR=	${PREFIX}/bin
.endif

PROG=		ipgen
SRCS=		gen.c util.c webserv.c pbuf.c sequencecheck.c seqtable.c item.c genscript.c flowparse.c pktgen_item.c
CFLAGS+=	-I.. -I/usr/local/include -g -Wall -DHTDOCS=\"${PREFIX}/share/ipgen/htdocs\"
DPADD=		
LDADD=		-L../libpkt -lpkt -L../libaddrlist -L/usr/local/lib -laddrlist -lpthread -lc -lcurses -levent -lmd
MK_MAN=		no

.if ${OS} == "Linux"
LDADD+=		-lbsd -lcrypto -lbpf
CFLAGS+=	-DUSE_AF_XDP
SRCS+=		arpresolv_linux.c af_xdp.c
.else
CFLAGS+=	-DIPG_HACK -DUSE_NETMAP
SRCS+=		arpresolv.c
.endif

.include <bsd.prog.mk>

pktgen_item.c: pktgen.layout
	perl layout_generator pktgen.layout

