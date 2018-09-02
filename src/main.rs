#![warn(
    non_camel_case_types,
    non_upper_case_globals,
    unused_qualifications
)]
#[macro_use]
extern crate log;

extern crate iptrap;
extern crate rustc_serialize;
extern crate time;
extern crate zmq;

use iptrap::privilegesdrop;
use iptrap::strsliceescape::StrSliceEscape;
use iptrap::EmptyTcpPacket;
use iptrap::ETHERTYPE_IP;
use iptrap::{checksum, cookie};
use iptrap::{DataLinkType, Pcap, PcapPacket};
use iptrap::{EtherHeader, IpHeader, TcpHeader};
use iptrap::{PacketDissector, PacketDissectorFilter};
use iptrap::{TH_ACK, TH_RST, TH_SYN};
use rustc_serialize::json::{Json, ToJson};
use std::collections::HashMap;
use std::env;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicBool, ATOMIC_BOOL_INIT};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;

static STREAM_PORT: u16 = 9922;
static SSH_PORT: u16 = 22;

fn send_tcp_synack(
    sk: cookie::SipHashKey,
    chan: &Sender<EmptyTcpPacket>,
    dissector: &PacketDissector,
    ts: u64,
) {
    let s_etherhdr: &EtherHeader = &unsafe { *dissector.etherhdr_ptr };
    assert!(s_etherhdr.ether_type == ETHERTYPE_IP.to_be());
    let s_iphdr: &IpHeader = &unsafe { *dissector.iphdr_ptr };
    let s_tcphdr: &TcpHeader = &unsafe { *dissector.tcphdr_ptr };

    let mut sa_packet: EmptyTcpPacket = EmptyTcpPacket::new();
    sa_packet.etherhdr.ether_shost = s_etherhdr.ether_dhost;
    sa_packet.etherhdr.ether_dhost = s_etherhdr.ether_shost;
    sa_packet.iphdr.ip_src = s_iphdr.ip_dst;
    sa_packet.iphdr.ip_dst = s_iphdr.ip_src;
    checksum::ip_header(&mut sa_packet.iphdr);

    sa_packet.tcphdr.th_sport = s_tcphdr.th_dport;
    sa_packet.tcphdr.th_dport = s_tcphdr.th_sport;
    sa_packet.tcphdr.th_flags = TH_SYN | TH_ACK;
    sa_packet.tcphdr.th_ack = (u32::from_be(s_tcphdr.th_seq) + 1u32).to_be();
    sa_packet.tcphdr.th_seq = cookie::tcp(
        sa_packet.iphdr.ip_src,
        sa_packet.iphdr.ip_dst,
        sa_packet.tcphdr.th_sport,
        sa_packet.tcphdr.th_dport,
        sk,
        ts,
    );
    checksum::tcp_header(&sa_packet.iphdr, &mut sa_packet.tcphdr);

    let _ = chan.send(sa_packet);
}

fn send_tcp_rst(chan: &Sender<EmptyTcpPacket>, dissector: &PacketDissector) {
    let s_etherhdr: &EtherHeader = &unsafe { *dissector.etherhdr_ptr };
    assert!(s_etherhdr.ether_type == ETHERTYPE_IP.to_be());
    let s_iphdr: &IpHeader = &unsafe { *dissector.iphdr_ptr };
    let s_tcphdr: &TcpHeader = &unsafe { *dissector.tcphdr_ptr };
    let mut rst_packet: EmptyTcpPacket = EmptyTcpPacket::new();
    rst_packet.etherhdr.ether_shost = s_etherhdr.ether_dhost;
    rst_packet.etherhdr.ether_dhost = s_etherhdr.ether_shost;
    rst_packet.iphdr.ip_src = s_iphdr.ip_dst;
    rst_packet.iphdr.ip_dst = s_iphdr.ip_src;
    checksum::ip_header(&mut rst_packet.iphdr);

    rst_packet.tcphdr.th_sport = s_tcphdr.th_dport;
    rst_packet.tcphdr.th_dport = s_tcphdr.th_sport;
    rst_packet.tcphdr.th_ack = s_tcphdr.th_seq;
    rst_packet.tcphdr.th_seq = s_tcphdr.th_ack;
    rst_packet.tcphdr.th_flags = TH_RST | TH_ACK;
    checksum::tcp_header(&rst_packet.iphdr, &mut rst_packet.tcphdr);

    let _ = chan.send(rst_packet);
}

fn log_tcp_ack(
    zmq_ctx: &mut zmq::Socket,
    sk: cookie::SipHashKey,
    dissector: &PacketDissector,
    ts: u64,
) -> bool {
    if dissector.tcp_data.len() <= 0 {
        return false;
    }
    let s_iphdr: &IpHeader = &unsafe { *dissector.iphdr_ptr };
    let s_tcphdr: &TcpHeader = &unsafe { *dissector.tcphdr_ptr };
    let ack_cookie = cookie::tcp(
        s_iphdr.ip_dst,
        s_iphdr.ip_src,
        s_tcphdr.th_dport,
        s_tcphdr.th_sport,
        sk,
        ts,
    );
    let wanted_cookie = (u32::from_be(ack_cookie) + 1u32).to_be();
    if s_tcphdr.th_ack != wanted_cookie {
        let ts_alt = ts - 0x40;
        let ack_cookie_alt = cookie::tcp(
            s_iphdr.ip_dst,
            s_iphdr.ip_src,
            s_tcphdr.th_dport,
            s_tcphdr.th_sport,
            sk,
            ts_alt,
        );
        let wanted_cookie_alt = (u32::from_be(ack_cookie_alt) + 1u32).to_be();
        if s_tcphdr.th_ack != wanted_cookie_alt {
            return false;
        }
    }
    let tcp_data_str = String::from_utf8_lossy(&dissector.tcp_data).into_owned();
    let ip_src = s_iphdr.ip_src;
    let dport = u16::from_be(s_tcphdr.th_dport);
    let mut record: HashMap<String, Json> = HashMap::with_capacity(4);
    record.insert("ts".to_owned(), Json::U64(ts));
    record.insert(
        "ip_src".to_owned(),
        Json::String(format!("{}.{}.{}.{}", ip_src[0], ip_src[1], ip_src[2], ip_src[3]).to_owned()),
    );
    record.insert("dport".to_owned(), Json::U64(dport as u64));
    record.insert(
        "payload".to_owned(),
        Json::String(tcp_data_str.escape_default_except_lf().to_owned()),
    );
    let json = record.to_json().to_string();
    let _ = zmq_ctx.send(json.as_bytes(), 0);
    info!("{}", json);
    true
}

fn usage() {
    println!("Usage: iptrap <device> <local ip address> <uid> <gid>");
}

#[allow(unreachable_code, deprecated)]
fn spawn_time_updater(time_needs_update: &'static AtomicBool) {
    thread::spawn(move || {
        loop {
            time_needs_update.store(true, Relaxed);
            thread::sleep_ms(10 * 1000);
        }
        ()
    });
}

fn packet_should_be_bypassed(dissector: &PacketDissector) -> bool {
    let th_dport = unsafe { *dissector.tcphdr_ptr }.th_dport;
    th_dport == STREAM_PORT.to_be() || th_dport == SSH_PORT.to_be()
}

#[allow(unreachable_code)]
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        return usage();
    }
    let local_addr: Ipv4Addr = match args[2].parse() {
        Ok(local_ip) => local_ip,
        Err(_) => {
            return usage();
        }
    };
    let local_ip = local_addr.octets().to_vec();
    let pcap = Pcap::open_live(&args[1]).unwrap();
    privilegesdrop::switch_user(args[3].parse().ok(), args[4].parse().ok());
    match pcap.data_link_type() {
        DataLinkType::Ethernet => (),
        _ => panic!("Unsupported data link type"),
    }
    let sk = cookie::SipHashKey::new();
    let filter = PacketDissectorFilter::new(local_ip);
    let pcap_arc = Arc::new(pcap);
    let (packetwriter_chan, packetwriter_port): (
        Sender<EmptyTcpPacket>,
        Receiver<EmptyTcpPacket>,
    ) = channel();
    let pcap_arc0 = pcap_arc.clone();
    thread::spawn(move || {
        loop {
            let pkt = packetwriter_port.recv().unwrap();
            let _ = pcap_arc0.send_packet(&pkt);
        }
        ()
    });
    let zmq_ctx = zmq::Context::new();
    let mut zmq_socket = zmq_ctx.socket(zmq::SocketType::PUB).unwrap();
    let _ = zmq_socket.set_linger(1);
    let _ = zmq_socket.bind(&format!("tcp://0.0.0.0:{}", STREAM_PORT));
    static TIME_NEEDS_UPDATE: AtomicBool = ATOMIC_BOOL_INIT;
    spawn_time_updater(&TIME_NEEDS_UPDATE);
    let mut ts = time::get_time().sec as u64 & !0x3f;
    let mut pkt_opt: Option<PcapPacket>;
    while {
        pkt_opt = pcap_arc.next_packet();
        pkt_opt.is_some()
    } {
        let pkt = pkt_opt.unwrap();
        let dissector = match PacketDissector::new(&filter, pkt.ll_data) {
            Ok(dissector) => dissector,
            Err(_) => {
                continue;
            }
        };
        if packet_should_be_bypassed(&dissector) {
            continue;
        }
        if TIME_NEEDS_UPDATE.load(Relaxed) != false {
            TIME_NEEDS_UPDATE.store(false, Relaxed);
            ts = time::get_time().sec as u64 & !0x3f;
        }
        let th_flags = unsafe { *dissector.tcphdr_ptr }.th_flags;
        if th_flags == TH_SYN {
            send_tcp_synack(sk, &packetwriter_chan, &dissector, ts);
        } else if (th_flags & TH_ACK) == TH_ACK
            && (th_flags & TH_SYN) == 0
            && log_tcp_ack(&mut zmq_socket, sk, &dissector, ts)
        {
            send_tcp_rst(&packetwriter_chan, &dissector);
        }
    }
}
