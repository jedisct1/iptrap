# IPTrap 2

A fast, stateless TCP sinkhole implemented in Rust. Performs TCP handshakes on all ports and logs the initial payload.

Uses SYN cookies to remain completely stateless - no per-connection memory is allocated, making it immune to SYN flood attacks.

## Dependencies

- libpcap-dev
- libzmq3-dev or libzmq4-dev
- Rust

## Building

```sh
git submodule update --init --recursive
cargo build --release
```

The binary will be at `target/release/iptrap`.

## Usage

```sh
iptrap <device> <local ip address> <uid> <gid>
```

IPTrap implements its own TCP/IP stack. The network interface must not have a kernel IP address configured.

IPTrap does not respond to ARP requests. Use a tool like `fakearpd` for that purpose.

Requires root privileges to open the network interface, but immediately drops to the specified uid/gid.

### Excluded Ports

- Port 22 (SSH)
- Port 9922 (ZeroMQ output)

### Output

Logs are published as JSON on a ZeroMQ PUB socket on port 9922.

Example output:

```json
{"ts":1703698800,"ip_src":"192.168.1.100","dport":80,"payload":"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"}
```

Subscribe with any ZeroMQ SUB client:

```sh
# Using Python
python3 -c "import zmq; ctx=zmq.Context(); s=ctx.socket(zmq.SUB); s.connect('tcp://127.0.0.1:9922'); s.setsockopt_string(zmq.SUBSCRIBE,''); print(s.recv_string())"
```
