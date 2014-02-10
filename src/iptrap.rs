
#[warn(non_camel_case_types,
       non_uppercase_statics,
       unnecessary_qualification,
       managed_heap_memory)];

extern mod extra;
extern mod iptrap;

use extra::time;
use iptrap::ETHERTYPE_IP;
use iptrap::EmptyTcpPacket;
use iptrap::socketizableip::SocketizableIp;
use iptrap::{EtherHeader, IpHeader, TcpHeader};
use iptrap::{PacketDissector, PacketDissectorFilter};
use iptrap::{Pcap, PcapPacket, DataLinkTypeEthernet};
use iptrap::{TH_SYN, TH_ACK, TH_PUSH};
use iptrap::{checksum, cookie};
use std::cast::transmute;
use std::io::net::ip::IpAddr;
use std::mem::size_of_val;
use std::mem::{to_be16, from_be16, to_be32, from_be32};
use std::{os, rand, vec};

fn send_tcp_synack(sk: cookie::SipHashKey, pcap: &Pcap,
                   dissector: PacketDissector, uts: u64) {
    let ref s_etherhdr: EtherHeader = unsafe { *dissector.etherhdr_ptr };
    assert!(s_etherhdr.ether_type == to_be16(ETHERTYPE_IP as i16) as u16);
    let ref s_iphdr: IpHeader = unsafe { *dissector.iphdr_ptr };
    let ref s_tcphdr: TcpHeader = unsafe { *dissector.tcphdr_ptr };

    let mut sa_packet: EmptyTcpPacket = EmptyTcpPacket::new();
    sa_packet.etherhdr.ether_shost = s_etherhdr.ether_dhost;
    sa_packet.etherhdr.ether_dhost = s_etherhdr.ether_shost;
    sa_packet.iphdr.ip_src = s_iphdr.ip_dst;
    sa_packet.iphdr.ip_dst = s_iphdr.ip_src;
    checksum::ip_header(&mut sa_packet.iphdr);

    sa_packet.tcphdr.th_sport = s_tcphdr.th_dport;
    sa_packet.tcphdr.th_dport = s_tcphdr.th_sport;
    sa_packet.tcphdr.th_ack = to_be32(
        (from_be32(s_tcphdr.th_seq as i32) as u32 + 1u32) as i32) as u32;
    sa_packet.tcphdr.th_flags = TH_SYN | TH_ACK;
    sa_packet.tcphdr.th_seq =
        cookie::tcp(sa_packet.iphdr.ip_src, sa_packet.iphdr.ip_dst,
                    sa_packet.tcphdr.th_sport, sa_packet.tcphdr.th_dport,
                    s_iphdr.ip_id, sk, uts);
    checksum::tcp_header(&sa_packet.iphdr, &mut sa_packet.tcphdr);

    let sa_packet_v = unsafe { vec::from_buf(transmute(&sa_packet),
                                             size_of_val(&sa_packet)) };
    pcap.send_packet(sa_packet_v);
}

fn log_tcp_ack(sk: cookie::SipHashKey, dissector: PacketDissector, uts: u64) {
    let ref s_iphdr: IpHeader = unsafe { *dissector.iphdr_ptr };
    let ref s_tcphdr: TcpHeader = unsafe { *dissector.tcphdr_ptr };
    let wanted_ip_id = to_be16(
        (from_be16(s_iphdr.ip_id as i16) as u16 - 2u16) as i16) as u16;
    let ack_cookie = cookie::tcp(s_iphdr.ip_dst, s_iphdr.ip_src,
                                 s_tcphdr.th_dport, s_tcphdr.th_sport,
                                 wanted_ip_id, sk, uts);
    let wanted_cookie = to_be32((from_be32(ack_cookie as i32) as u32
                                 + 1u32) as i32) as u32;
    if s_tcphdr.th_ack != wanted_cookie {
        let uts_alt = uts - 0x1000000000;
        let ack_cookie_alt = cookie::tcp(s_iphdr.ip_dst, s_iphdr.ip_src,
                                         s_tcphdr.th_dport, s_tcphdr.th_sport,
                                         wanted_ip_id, sk, uts_alt);
        let wanted_cookie_alt = to_be32((from_be32(ack_cookie_alt as i32) as u32
                                         + 1u32) as i32) as u32;
        if s_tcphdr.th_ack != wanted_cookie_alt {
            return;
        }
    }
    println!("cookie");
}

fn usage() {
    println!("Usage: iptrap <device> <local ip address>");
}

fn main() {
    let args = os::args();
    if args.len() != 3 {
        return usage();
    }
    let local_ip = match from_str::<IpAddr>(args[2]) {
        Some(local_ip) => local_ip,
        None => { return usage(); }
    }.to_vec().unwrap();
    let pcap = Pcap::open_live(args[1]).unwrap();
    match pcap.data_link_type() {
        DataLinkTypeEthernet => (),
        _ => fail!("Unsupported data link type")
    }
    let sk = cookie::SipHashKey {
        k1: rand::random(),
        k2: rand::random()
    };
    let filter = PacketDissectorFilter {
        local_ip: local_ip
    };
    let mut pkt_opt: Option<PcapPacket>;
    while { pkt_opt = pcap.next_packet();
            pkt_opt.is_some() } {
        let pkt = pkt_opt.unwrap();
        let dissector = match PacketDissector::new(&filter, pkt.ll_data) {
            Ok(dissector) => dissector,
            Err(err) => {
                debug!("dissector: {}", err);
                continue;
            }
        };
        let uts = time::precise_time_ns() & 0x1000000000;
        let th_flags = unsafe { *dissector.tcphdr_ptr }.th_flags;
        if th_flags == TH_SYN {
            send_tcp_synack(sk, &pcap, dissector, uts);
        } else if (th_flags & (TH_PUSH | TH_ACK)) == (TH_PUSH | TH_ACK) &&
            (th_flags & TH_SYN) == 0 {
            log_tcp_ack(sk, dissector, uts);
        }
    }
}
