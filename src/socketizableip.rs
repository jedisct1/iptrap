
use std::io::net::ip::{IpAddr, Ipv4Addr};

pub trait SocketizableIp {
    fn to_vec(&self) -> Result<~[u8], ~str>;
}

impl SocketizableIp for IpAddr {
    fn to_vec(&self) -> Result<~[u8], ~str> {
        match *self {
            Ipv4Addr(a, b, c, d) => Ok(~[a, b, c, d]),
            _ => Err(~"Unsupported IP address")
        }
    }
}
