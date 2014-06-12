
extern crate std;

use std::c_vec::CVec;
use std::mem::size_of;
use std::mem::{to_be16, from_be16};

pub static ETHERTYPE_IP: u16 = 0x0800;
pub static IPPROTO_TCP: u8 = 6;
pub static TH_SYN: u8 = 0x02;
pub static TH_RST: u8 = 0x04;
pub static TH_ACK: u8 = 0x10;
pub static TH_PUSH: u8 = 0x08;

#[packed]
pub struct EtherHeader {
    pub ether_dhost: [u8, ..6],
    pub ether_shost: [u8, ..6],
    pub ether_type: u16
}

#[packed]
pub struct IpHeader {
    pub ip_vhl: u8,
    pub ip_tos: u8,
    pub ip_len: u16,
    pub ip_id: u16,
    pub ip_off: u16,
    pub ip_ttl: u8,
    pub ip_p: u8,
    pub ip_sum: u16,
    pub ip_src: [u8, ..4],
    pub ip_dst: [u8, ..4]
}

#[packed]
pub struct TcpHeader {
    pub th_sport: u16,
    pub th_dport: u16,
    pub th_seq: u32,
    pub th_ack: u32,
    pub th_off_x2: u8,
    pub th_flags: u8,
    pub th_win: u16,
    pub th_sum: u16,
    pub th_urp: u16
}

pub struct PacketDissectorFilter {
    local_ip: Vec<u8>
}

impl PacketDissectorFilter {
    pub fn new(local_ip: Vec<u8>) -> PacketDissectorFilter {
        PacketDissectorFilter {
            local_ip: local_ip
        }
    }
}

pub struct PacketDissector {
    pub ll_data: CVec<u8>,
    pub etherhdr_ptr: *EtherHeader,
    pub iphdr_ptr: *IpHeader,
    pub tcphdr_ptr: *TcpHeader,
    pub tcp_data: CVec<u8>
}

impl PacketDissector {
    pub fn new(filter: &PacketDissectorFilter,
               ll_data: CVec<u8>) -> Result<PacketDissector, &str> {
        let ll_data_len = ll_data.len();
        if ll_data_len < size_of::<EtherHeader>() {
            return Err("Short ethernet frame");
        }
        let ll_data_ptr = ll_data.as_slice().as_ptr();
        let etherhdr_ptr: *EtherHeader = ll_data_ptr as *EtherHeader;
        let ref etherhdr = unsafe { *etherhdr_ptr };
        if etherhdr.ether_type != to_be16(ETHERTYPE_IP) {
            return Err("Unsupported type of ethernet frame");
        }
        let iphdr_offset: uint = size_of::<EtherHeader>();
        if ll_data_len - iphdr_offset < size_of::<IpHeader>() {
            return Err("Short IP packet")
        }
        let iphdr_ptr: *IpHeader = unsafe {
            ll_data_ptr.offset(iphdr_offset as int) as *IpHeader
        };
        let ref iphdr: IpHeader = unsafe { *iphdr_ptr };
        let iphdr_len = (iphdr.ip_vhl & 0xf) as uint * 4u;
        if iphdr_len < size_of::<IpHeader>() ||
            ll_data_len - iphdr_offset < iphdr_len {
            return Err("Short IP packet")
        }
        let ip_version = (iphdr.ip_vhl >> 4) & 0xf;
        if ip_version != 4 {
            return Err("Unsupported IP version");
        }
        if iphdr.ip_p != IPPROTO_TCP {
            return Err("Unsupported IP protocol");
        }
        if filter.local_ip.ne(&iphdr.ip_dst.into_owned()) {
            return Err("Packet destination is not the local IP");
        }
        let tcphdr_offset = iphdr_offset + iphdr_len;
        if ll_data_len - tcphdr_offset < size_of::<TcpHeader>() {
            return Err("Short TCP packet");
        }
        let tcphdr_ptr: *TcpHeader = unsafe {
            ll_data_ptr.offset(tcphdr_offset as int) as *TcpHeader
        };
        let ref tcphdr: TcpHeader = unsafe { *tcphdr_ptr };        
        let tcphdr_data_offset = ((tcphdr.th_off_x2 >> 4) & 0xf) as uint * 4u;
        if tcphdr_data_offset < size_of::<TcpHeader>() {
            return Err("Short TCP data offset");
        }
        if ll_data_len - tcphdr_offset < tcphdr_data_offset {
            return Err("Truncated TCP packet - no data");
        }
        let tcp_data_offset = tcphdr_offset + tcphdr_data_offset;

        let ip_len = from_be16(iphdr.ip_len) as uint;
        if ip_len < tcp_data_offset - tcp_data_offset {
            return Err("Truncated TCP packet - truncated data");
        }
        let real_tcp_data_len = ip_len - iphdr_len - tcphdr_data_offset;
        let max_tcp_data_len = ll_data_len - tcp_data_offset;
        let tcp_data_len = std::cmp::min(real_tcp_data_len, max_tcp_data_len);
        let tcp_data_ptr = unsafe {
            ll_data_ptr.offset(tcp_data_offset as int)
        };
        let tcp_data = unsafe {
            CVec::new(tcp_data_ptr as *mut u8, tcp_data_len)
        };
        Ok(PacketDissector {
                ll_data: ll_data,
                etherhdr_ptr: etherhdr_ptr,
                iphdr_ptr: iphdr_ptr,
                tcphdr_ptr: tcphdr_ptr,
                tcp_data: tcp_data
            })
    }    
}
