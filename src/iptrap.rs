
#![warn(non_camel_case_types,
        non_uppercase_statics,
        unnecessary_qualification,
        managed_heap_memory)]

#![feature(phase)]
#[phase(plugin, link)] extern crate log;

extern crate iptrap;
extern crate libc;
extern crate serialize;
extern crate sync;
extern crate time;

use iptrap::ETHERTYPE_IP;
use iptrap::EmptyTcpPacket;
use iptrap::privilegesdrop;
use iptrap::strsliceescape::StrSliceEscape;
use iptrap::{EtherHeader, IpHeader, TcpHeader};
use iptrap::{PacketDissector, PacketDissectorFilter};
use iptrap::{Pcap, PcapPacket, DataLinkTypeEthernet};
use iptrap::{TH_SYN, TH_ACK, TH_RST};
use iptrap::{checksum, cookie};
use serialize::json::ToJson;
use serialize::json;
use std::collections::HashMap;
use std::io::net::ip::{IpAddr, Ipv4Addr};
use std::sync::atomics::{AtomicBool, Relaxed, INIT_ATOMIC_BOOL};
use std::os;

pub mod zmq;

static STREAM_PORT: u16 = 9922;
static SSH_PORT: u16 = 22;
static WSD_PORT: u16 = 3702;

fn send_tcp_synack(sk: cookie::SipHashKey, chan: &Sender<EmptyTcpPacket>,
                   dissector: &PacketDissector, ts: u64) {
    let ref s_etherhdr: EtherHeader = unsafe { *dissector.etherhdr_ptr };
    assert!(s_etherhdr.ether_type == ETHERTYPE_IP.to_be());
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
    sa_packet.tcphdr.th_flags = TH_SYN | TH_ACK;
    sa_packet.tcphdr.th_ack = (Int::from_be(s_tcphdr.th_seq) + 1u32).to_be();
    sa_packet.tcphdr.th_seq =
        cookie::tcp(sa_packet.iphdr.ip_src, sa_packet.iphdr.ip_dst,
                    sa_packet.tcphdr.th_sport, sa_packet.tcphdr.th_dport,
                    sk, ts);
    checksum::tcp_header(&sa_packet.iphdr, &mut sa_packet.tcphdr);

    chan.send(sa_packet);
}

fn send_tcp_rst(chan: &Sender<EmptyTcpPacket>, dissector: &PacketDissector) {
    let ref s_etherhdr: EtherHeader = unsafe { *dissector.etherhdr_ptr };
    assert!(s_etherhdr.ether_type == ETHERTYPE_IP.to_be());
    let ref s_iphdr: IpHeader = unsafe { *dissector.iphdr_ptr };
    let ref s_tcphdr: TcpHeader = unsafe { *dissector.tcphdr_ptr };
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

    chan.send(rst_packet);
}

fn log_tcp_ack(zmq_ctx: &mut zmq::Socket, sk: cookie::SipHashKey,
               dissector: &PacketDissector, ts: u64) -> bool {
    if dissector.tcp_data.len() <= 0 {
        return false;
    }
    let ref s_iphdr: IpHeader = unsafe { *dissector.iphdr_ptr };
    let ref s_tcphdr: TcpHeader = unsafe { *dissector.tcphdr_ptr };
    let ack_cookie = cookie::tcp(s_iphdr.ip_dst, s_iphdr.ip_src,
                                 s_tcphdr.th_dport, s_tcphdr.th_sport,
                                 sk, ts);
    let wanted_cookie = (Int::from_be(ack_cookie) + 1u32).to_be();
    if s_tcphdr.th_ack != wanted_cookie {
        let ts_alt = ts - 0x40;
        let ack_cookie_alt = cookie::tcp(s_iphdr.ip_dst, s_iphdr.ip_src,
                                         s_tcphdr.th_dport, s_tcphdr.th_sport,
                                         sk, ts_alt);
        let wanted_cookie_alt = (Int::from_be(ack_cookie_alt) + 1u32).to_be();
        if s_tcphdr.th_ack != wanted_cookie_alt {
            return false;
        }
    }
    let tcp_data_str =
        std::str::from_utf8_lossy(dissector.tcp_data.as_slice()).into_string();
    let ip_src = s_iphdr.ip_src;
    let dport = Int::from_be(s_tcphdr.th_dport);
    let mut record: HashMap<String, json::Json> = HashMap::with_capacity(4);
    record.insert("ts".to_string(), json::Number(ts as f64));
    record.insert("ip_src".to_string(), json::String(format!("{}.{}.{}.{}",
                                                            ip_src[0], ip_src[1],
                                                            ip_src[2], ip_src[3]).to_string()));
    record.insert("dport".to_string(), json::Number(dport as f64));
    record.insert("payload".to_string(), json::String(tcp_data_str.escape_default_except_lf().to_string()));
    let json = record.to_json().to_string();
    let _ = zmq_ctx.send(json.as_bytes(), 0);
    info!("{}", json);
    true
}

fn usage() {
    println!("Usage: iptrap <device> <local ip address> <uid> <gid>");
}

fn spawn_time_updater(time_needs_update: &'static mut AtomicBool) {
    spawn(proc() {
            loop {
                time_needs_update.store(true, Relaxed);
                std::io::timer::sleep(10 * 1_000);
            }
        });
}

fn packet_should_be_bypassed(dissector: &PacketDissector) -> bool {
    let th_dport = unsafe { *dissector.tcphdr_ptr }.th_dport;
    th_dport == STREAM_PORT.to_be() || th_dport == SSH_PORT.to_be() ||
    th_dport == WSD_PORT.to_be()
}

fn main() {
    let args = os::args();
    if args.len() != 5 {
        return usage();
    }
    let local_addr = match from_str::<IpAddr>(args.get(2).as_slice()) {
        Some(local_ip) => local_ip,
        None => { return usage(); }
    };
    let local_ip = match local_addr {
        Ipv4Addr(a, b, c, d) => vec!(a, b, c, d),
        _ => fail!("Only IPv4 is supported for now")
    };
    let pcap = Pcap::open_live(args.get(1).as_slice()).unwrap();
    privilegesdrop::switch_user(from_str(args.get(3).as_slice()), from_str(args.get(4).as_slice()));
    match pcap.data_link_type() {
        DataLinkTypeEthernet => (),
        _ => fail!("Unsupported data link type")
    }
    let sk = cookie::SipHashKey::new();
    let filter = PacketDissectorFilter::new(local_ip);
    let pcap_arc = sync::Arc::new(pcap);
    let (packetwriter_chan, packetwriter_port):
        (Sender<EmptyTcpPacket>, Receiver<EmptyTcpPacket>) = channel();
    let pcap_arc0 = pcap_arc.clone();
    spawn(proc() {
            loop {
                let pkt = packetwriter_port.recv();
                let _ = pcap_arc0.send_packet(&pkt);
            }
        });
    let mut zmq_ctx = zmq::Context::new();
    let mut zmq_socket = zmq_ctx.socket(zmq::PUB).unwrap();
    let _ = zmq_socket.set_linger(1);
    let _ = zmq_socket.bind(format!("tcp://0.0.0.0:{}", STREAM_PORT).as_slice());
    static mut time_needs_update: AtomicBool = INIT_ATOMIC_BOOL;
    unsafe { spawn_time_updater(&mut time_needs_update) };
    let mut ts = time::get_time().sec as u64 & !0x3f;
    let mut pkt_opt: Option<PcapPacket>;
    while { pkt_opt = pcap_arc.next_packet();
            pkt_opt.is_some() } {
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
        if unsafe { time_needs_update.load(Relaxed) } != false {
            unsafe { time_needs_update.store(false, Relaxed) };
            ts = time::get_time().sec as u64 & !0x3f;
        }
        let th_flags = unsafe { *dissector.tcphdr_ptr }.th_flags;
        if th_flags == TH_SYN {
            send_tcp_synack(sk, &packetwriter_chan, &dissector, ts);
        } else if (th_flags & TH_ACK) == TH_ACK && (th_flags & TH_SYN) == 0 {
            if log_tcp_ack(&mut zmq_socket, sk, &dissector, ts) {
                send_tcp_rst(&packetwriter_chan, &dissector);
            }
        }
    }
}
