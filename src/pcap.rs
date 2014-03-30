
#![allow(visible_private_types)]

use std::c_vec::CVec;
use std::libc::types::os::common::posix01::timeval;
use std::libc::{c_void, c_char, c_int};
use std::ptr;
use std::str::raw::from_c_str;

pub static PCAP_ERRBUF_SIZE: uint = 256;

type Pcap_ = * mut c_void;

struct PacketHeader {
    ts: timeval,
    caplen: u32,
    len: u32,
    comment: [u8, ..256]
}

pub struct PcapPacket {
    ll_data: CVec<u8>
}

pub struct Pcap {
    pcap_: Pcap_ 
}

pub enum DataLinkType {
    DataLinkTypeNull = 0,
    DataLinkTypeEthernet = 1
}

#[link(name = "pcap")]
extern {
    pub fn pcap_open_live(device: *c_char, snaplen: c_int, promisc: c_int,
                          to_ms: c_int, errbuf: *mut c_char) -> Pcap_;

    pub fn pcap_close(pcap: Pcap_);

    pub fn pcap_datalink(pcap: Pcap_) -> c_int;

    pub fn pcap_next_ex(pcap: Pcap_, pkthdr: * mut *PacketHeader,
                        ll_data: *mut *u8) -> c_int;

    pub fn pcap_sendpacket(pcap: Pcap_, ll_data: *u8, len: c_int) -> c_int;
}

impl Pcap {
    pub fn open_live(device: ~str) -> Result<Pcap, ~str> {
        let mut errbuf: Vec<c_char> = Vec::with_capacity(PCAP_ERRBUF_SIZE);
        let device = unsafe { device.to_c_str().unwrap() };
        let pcap = unsafe { pcap_open_live(device, 65536, 1,
                                           500, errbuf.as_mut_ptr()) };
        if pcap.is_null() {            
            return Err(unsafe { from_c_str(errbuf.as_ptr()) });
        }
        Ok(Pcap {
            pcap_: pcap
        })
    }

    pub fn data_link_type(&self) -> DataLinkType {
        match unsafe { pcap_datalink(self.pcap_) } {
            0 => DataLinkTypeNull,
            1 => DataLinkTypeEthernet,
            _ => fail!("Unsupported data link type")
        }        
    }

    pub fn next_packet(&self) -> Option<PcapPacket> {
        let mut packet_header_pnt: *PacketHeader = ptr::null();
        let mut ll_data_pnt: *u8 = ptr::null();
        match unsafe { pcap_next_ex(self.pcap_,
                                    &mut packet_header_pnt,
                                    &mut ll_data_pnt) } {
            0 => self.next_packet(),
            1 => {
                let packet_header = unsafe { *packet_header_pnt };
                let ll_data_len = packet_header.caplen as uint;
                let ll_data = unsafe {
                    CVec::new(ll_data_pnt as *mut u8, ll_data_len)
                };
                Some(PcapPacket {
                        ll_data: ll_data
                    })
            },
            _ => None
        }
    }

    pub fn send_packet(&self, ll_data: CVec<u8>) {
        unsafe {
            pcap_sendpacket(self.pcap_,
                            ll_data.as_slice().as_ptr(),
                            ll_data.len() as c_int);
        }
    }
}

impl Drop for Pcap {
    fn drop(&mut self) {
        unsafe { pcap_close(self.pcap_) };
    }
}
