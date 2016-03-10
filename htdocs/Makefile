.include <../Makefile.inc>

FILES=	default.css		\
	index.html		\
	pktgen.js		\
	dygraph-combined.js	\
	jquery-1.11.1.min.js

all:
clean:
cleandir:
depend:

install:
	install -o root -g wheel -m 444 -d ${PREFIX}/share/ipgen/htdocs
	install -o root -g wheel -m 444 ${FILES} ${PREFIX}/share/ipgen/htdocs
