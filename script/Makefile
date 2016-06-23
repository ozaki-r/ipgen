.include <../Makefile.inc>

FILES=	pktsize46.script	\
	pktsize66.script	\
	pktsize100.script	\
	pktsize200.script	\
	pktsize300.script	\
	pktsize400.script	\
	pktsize500.script	\
	pktsize600.script	\
	pktsize700.script	\
	pktsize800.script	\
	pktsize900.script	\
	pktsize1000.script	\
	pktsize1100.script	\
	pktsize1200.script	\
	pktsize1280.script	\
	pktsize1300.script	\
	pktsize1400.script	\
	pktsize1500.script	\
	pktsizeAll.script

all:
clean:
cleandir:
depend:

install:
	install -o root -g wheel -m 555 log2graph ${PREFIX}/bin/ipgen_log2graph
	install -o root -g wheel -m 444 -d ${PREFIX}/share/ipgen/script
	install -o root -g wheel -m 444 ${FILES} ${PREFIX}/share/ipgen/script
