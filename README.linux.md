
# ipgen on Linux

`ipgen` was initially implemented with `netmap` on FreeBSD,
then ported to Linux.
On Linux ipgen employs `AF_XDP` instead of netmap.

## Supported distributions

ipgen with AF_XDP is developed and tested on Ubuntu 21.04.
It should work on recent Fedora Linux too with some minor tweaks.

## Build

```
apt install bmake libbsd-dev clang libssl-dev libevent-dev libbpf-dev
git clone https://github.com/iij/ipgen.git
cd ipgen
env CC=clang bmake -m /usr/share/bmake/mk-netbsd
```

## Caveat

ipgen with AF_XDP uses only the 1st hardware queue on a netowrk
adapter, so if the network adapter uses multiple hardware queues
ipgen with AF_XDP doesn't work correctly.

You can check if your network adapter, say `eth0`, uses
multiple queues by `ethtool -l eth0`.
If so you can change the number of using queues to just one by:

```
ethtool -L eth0 combined 1
```
