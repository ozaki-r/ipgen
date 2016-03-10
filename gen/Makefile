.include <bsd.own.mk>
.include <../Makefile.inc>

DESTDIR=	${PREFIX}/bin

PROG=		ipgen
SRCS=		gen.c util.c webserv.c pbuf.c arpresolv.c sequencecheck.c item.c genscript.c flowparse.c pktgen_item.c
CFLAGS+=	-I.. -I/usr/local/include -g -Wall -DIPG_HACK -DHTDOCS=\"${PREFIX}/share/ipgen/htdocs\"
DPADD=		
LDADD=		-L../libpkt -lpkt -L../libaddrlist -L/usr/local/lib -laddrlist -lpthread -lc -lcurses -levent
MK_MAN=		no

.include <bsd.prog.mk>

pktgen_item.c: pktgen.layout
	perl layout_generator pktgen.layout

