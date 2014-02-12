
use packetdissector::{EtherHeader, IpHeader, TcpHeader};
use packetdissector::{ETHERTYPE_IP, IPPROTO_TCP};
use std::mem::to_be16;
use std::mem::size_of;
use std::rand;

#[packed]
pub struct EmptyTcpPacket {
    etherhdr: EtherHeader,
    iphdr: IpHeader,
    tcphdr: TcpHeader,
    tcpoptions: [u8, ..4]
}

impl EmptyTcpPacket {
    pub fn new() -> EmptyTcpPacket {
        let etherhdr = EtherHeader {
            ether_dhost: [0u8, ..6],
            ether_shost: [0u8, ..6],
            ether_type: to_be16(ETHERTYPE_IP as i16) as u16
        };
        let tcpoptions = [ 0x2u8, 0x4u8, 0x5u8, 0xb4u8 ];
        let iphdr = IpHeader {
            ip_vhl: (4u8 << 4) | (size_of::<IpHeader>() as u8 / 4u8),
            ip_tos: 0u8,
            ip_len: to_be16((size_of::<IpHeader>() +
                             size_of::<TcpHeader>() +
                             tcpoptions.len()) as i16) as u16,
            ip_id: rand::random(),
            ip_off: 0u16,
            ip_ttl: 42u8,
            ip_p: IPPROTO_TCP,
            ip_sum: 0u16,
            ip_src: [0u8, ..4],
            ip_dst: [0u8, ..4]
        };
        assert!(tcpoptions.len() % 4 == 0);
        let tcphdr = TcpHeader {
            th_sport: 0u16,
            th_dport: 0u16,
            th_seq: 0u32,
            th_ack: 0u32,
            th_off_x2: ((size_of::<TcpHeader>() +
                         tcpoptions.len()) / 4) as u8 << 4,
            th_flags: 0u8,
            th_win: 65535u16,
            th_sum: 0u16,
            th_urp: 0u16
        };
        EmptyTcpPacket {
            etherhdr: etherhdr,
            iphdr: iphdr,
            tcphdr: tcphdr,
            tcpoptions: tcpoptions
        }
    }
}
