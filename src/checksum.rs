
use packetdissector::{IpHeader, TcpHeader};
use std::iter;
use std::num::Int;
use std::mem::size_of_val;

pub fn ip_header(iphdr: &mut IpHeader) {
    let iphdr_len = size_of_val(iphdr);
    let iphdr_ptr: *const u8 = iphdr as *mut IpHeader as *const u8;
    let iphdr_v = unsafe { Vec::from_raw_buf(iphdr_ptr as *mut u8, iphdr_len) };
    let mut sum: u64 = iter::range_step(0u, iphdr_len, 2u).
        fold(0u64, |sum, i|
             sum + (((*iphdr_v.get(i).unwrap() as u16) << 8) |
                    *iphdr_v.get(i + 1).unwrap() as u16) as u64);
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let iphdr: &mut IpHeader = unsafe { &mut *(iphdr_ptr as *mut IpHeader) };
    iphdr.ip_sum = (!(sum as u16)).to_be();
}

pub fn tcp_header(iphdr: &IpHeader, tcphdr: &mut TcpHeader) {
    let tcphdr_len = ((tcphdr.th_off_x2 >> 4) & 0xf) as uint * 4;
    assert!(tcphdr_len >= size_of_val(tcphdr));
    let mut sum0: u64;
    sum0  = tcphdr_len as u64;
    sum0 += iphdr.ip_p as u64;
    sum0 += ((iphdr.ip_src[0] as u16) << 8 | iphdr.ip_src[1] as u16) as u64;
    sum0 += ((iphdr.ip_src[2] as u16) << 8 | iphdr.ip_src[3] as u16) as u64;
    sum0 += ((iphdr.ip_dst[0] as u16) << 8 | iphdr.ip_dst[1] as u16) as u64;
    sum0 += ((iphdr.ip_dst[2] as u16) << 8 | iphdr.ip_dst[3] as u16) as u64;
    let tcphdr_ptr: *const u8 = tcphdr as *mut TcpHeader as *const u8;
    let tcphdr_v = unsafe {
        Vec::from_raw_buf(tcphdr_ptr as *mut u8, tcphdr_len)
    };
    let mut sum: u64 = iter::range_step(0u, tcphdr_len, 2u).
        fold(sum0, |sum, i|
             sum + (((*tcphdr_v.get(i).unwrap() as u16) << 8) |
                    *tcphdr_v.get(i + 1).unwrap() as u16) as u64);
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let tcphdr: &mut TcpHeader = unsafe { &mut *(tcphdr_ptr as *mut TcpHeader) };
    tcphdr.th_sum = (!(sum as u16)).to_be();
}
