![screenshot](https://github.com/iij/ipgen/wiki/img/screenshot.png)

ipgen
=====
ipgen is an Interactive Packet Generator with netmap


usage
=====
- setup FreeBSD and config kernel with NETMAP (add "device netmap" to conf/GENERIC).
- perl and libevent are required to compile.
-- git clone git@github.com:iij/ipgen.git
-- cd ipgen
-- make depend && make && make install
-- run ipgen


Presentation materials
======================
ipgen: Interactive Packet Generator for performance measurement
- in english https://github.com/iij/ipgen/wiki/materials/ipgen.pdf
- in japanese https://github.com/iij/ipgen/wiki/materials/ipgen_ja.pdf


Bootable USB Image
==================
- http://www.nerv.org/~ryo/ipgen/ipgen-freebsd11.0current-amd64-bootable-2G.img.gz (FreeBSD/amd64 11.0-current)

```sh
# wget http://www.nerv.org/~ryo/ipgen/ipgen-freebsd11.0current-amd64-bootable-2G.img.gz
# gzip -d ipgen-freebsd11.0current-amd64-bootable-2G.img.gz
# dd if=ipgen-freebsd11.0current-amd64-bootable-2G.img of=/dev/da0
```
