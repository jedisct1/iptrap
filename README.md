[![Build Status](https://travis-ci.org/jedisct1/iptrap.png?branch=master)](https://travis-ci.org/jedisct1/iptrap?branch=master)

IPtrap 2
========

A fast, stateless TCP sinkhole, implemented in Rust. Performs TCP handshakes
on all ports and logs the initial payload.

See [A sinkhole that never clogs](https://blog.opendns.com/2014/02/28/dns-sinkhole/)
for an introduction.

Dependencies:

- libpcap-dev
- libzmq3-dev or libzmq4-dev
- rust-nightly

Compilation:

    git submodule update --init --recursive
    cargo build --release

Usage
-----

IPTrap implements its own TCP/IP stack, and the network interface it
is listening on shouldn't have any IP address configured for the kernel.

However, IPTrap doesn't respond to ARP requests: a tool such as `fakearpd` can
be used for that purpose.

    iptrap <device> <local ip address> <uid> <gid>
    
Starts the sinkhole. Although it requires root privileges in order to
directly open the network interface, it also requires a non-root uid
to drop its privileges as soon as possible.

IPTrap listens to all TCP ports, with the exception of port 22.

The sinkhole logs are available as JSON data on a ZeroMQ PUB socket on
port 9922.
