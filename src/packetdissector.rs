
extern mod std;

use std::cast::transmute;
use std::mem::size_of;
use std::mem::{to_be16, from_be16};
use std::ptr;
use std::vec;

pub static ETHERTYPE_IP: u16 = 0x0800;
pub static IPPROTO_TCP: u8 = 6;
pub static TH_SYN: u8 = 0x02;
pub static TH_ACK: u8 = 0x10;
pub static TH_PUSH: u8 = 0x08;

#[packed]
pub struct EtherHeader {
    ether_dhost: [u8, ..6],
    ether_shost: [u8, ..6],
    ether_type: u16
}

#[packed]
pub struct IpHeader {
    ip_vhl: u8,
    ip_tos: u8,
    ip_len: u16,
    ip_id: u16,
    ip_off: u16,
    ip_ttl: u8,
    ip_p: u8,
    ip_sum: u16,
    ip_src: [u8, ..4],
    ip_dst: [u8, ..4]
}

#[packed]
pub struct TcpHeader {
    th_sport: u16,
    th_dport: u16,
    th_seq: u32,
    th_ack: u32,
    th_off_x2: u8,
    th_flags: u8,
    th_win: u16,
    th_sum: u16,
    th_urp: u16
}

pub struct PacketDissectorFilter {
    local_ip: ~[u8]
}

pub struct PacketDissector {
    ll_data: ~[u8],
    etherhdr_ptr: *EtherHeader,
    iphdr_ptr: *IpHeader,
    tcphdr_ptr: *TcpHeader,
    tcp_data: ~[u8]
}

impl PacketDissector {
    pub fn new(filter: &PacketDissectorFilter,
               ll_data: ~[u8]) -> Result<PacketDissector, ~str> {
        let ll_data_len = ll_data.len();
        if ll_data_len < size_of::<EtherHeader>() {
            return Err(~"Short ethernet frame");
        }
        let etherhdr_ptr: *EtherHeader = unsafe {
            transmute(ll_data.as_ptr())
        };
        let ref etherhdr = unsafe { *etherhdr_ptr };
        
        if etherhdr.ether_type != to_be16(ETHERTYPE_IP as i16) as u16 {
            return Err(~"Unsupported type of ethernet frame");
        }

        let iphdr_offset: uint = size_of::<EtherHeader>();
        if ll_data_len - iphdr_offset < size_of::<IpHeader>() {
            return Err(~"Short IP packet")
        }
        let iphdr_ptr: *IpHeader = unsafe {
            transmute(ptr::offset(ll_data.as_ptr(), iphdr_offset as int))
        };
        let ref iphdr: IpHeader = unsafe { *iphdr_ptr };
        let iphdr_len = (iphdr.ip_vhl & 0xf) as uint * 4u;
        if iphdr_len < size_of::<IpHeader>() ||
            ll_data_len - iphdr_offset < iphdr_len {
            return Err(~"Short IP packet")
        }
        let ip_version = (iphdr.ip_vhl >> 4) & 0xf;
        if ip_version != 4 {
            return Err(~"Unsupported IP version");
        }
        if iphdr.ip_p != IPPROTO_TCP {
            return Err(~"Unsupported IP protocol");
        }
        if filter.local_ip.ne(&iphdr.ip_dst.into_owned()) {
            return Err(~"Packet destination is not the local IP");
        }
        let tcphdr_offset = iphdr_offset + iphdr_len;
        if ll_data_len - tcphdr_offset < size_of::<TcpHeader>() {
            return Err(~"Short TCP packet");
        }
        let tcphdr_ptr: *TcpHeader = unsafe {
            transmute(ptr::offset(ll_data.as_ptr(), tcphdr_offset as int))
        };
        let ref tcphdr: TcpHeader = unsafe { *tcphdr_ptr };        
        let tcphdr_data_offset = ((tcphdr.th_off_x2 >> 4) & 0xf) as uint * 4u;
        if tcphdr_data_offset < size_of::<TcpHeader>() {
            return Err(~"Short TCP data offset");
        }
        if ll_data_len - tcphdr_offset < tcphdr_data_offset {
            return Err(~"Truncated TCP packet - no data");
        }
        let tcp_data_offset = tcphdr_offset + tcphdr_data_offset;

        let ip_len = from_be16(iphdr.ip_len as i16) as uint;
        if ip_len < tcp_data_offset - tcp_data_offset {
            return Err(~"Truncated TCP packet - truncated data");
        }
        let real_tcp_data_len = ip_len - iphdr_len - tcphdr_data_offset;
        let max_tcp_data_len = ll_data_len - tcp_data_offset;
        let tcp_data_len = std::cmp::min(real_tcp_data_len, max_tcp_data_len);
        let tcp_data_ptr = unsafe {
            ptr::offset(ll_data.as_ptr(), tcp_data_offset as int)
        };
        let tcp_data = unsafe { vec::from_buf(tcp_data_ptr, tcp_data_len) };

        Ok(PacketDissector {
                ll_data: ll_data,
                etherhdr_ptr: etherhdr_ptr,
                iphdr_ptr: iphdr_ptr,
                tcphdr_ptr: tcphdr_ptr,
                tcp_data: tcp_data
            })
    }    
}
