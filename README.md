[![Build Status](https://travis-ci.org/jedisct1/iptrap.png?branch=master)](https://travis-ci.org/jedisct1/iptrap?branch=master)

IPtrap 2
========

Source code of the OpenDNS sinkhole, implemented in Rust.

See [A sinkhole that never clogs](http://labs.opendns.com/2014/02/28/dns-sinkhole/)
for an introduction.

Dependencies:

- libpcap-dev
- libzmq3-dev
- rust-nightly

Compilation:

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

IPTrap listens to all TCP ports, with the exception of ports 22 and 3702.

The sinkhole logs are available as JSON data on a ZeroMQ PUB socket on
port 9922. As a faster and binary-safe alternative to JSON, the
`capnproto` branch makes the log available using Cap'n Proto instead.


