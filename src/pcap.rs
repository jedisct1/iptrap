use super::libc::{c_char, c_int, c_void, timeval};

use std::ffi;
use std::mem;
use std::ptr;
use std::slice;
use std::str;

pub const PCAP_ERRBUF_SIZE: usize = 256;

pub type Pcap_ = *mut c_void;

#[allow(dead_code)]
#[repr(C)]
#[derive(Copy)]
pub struct PacketHeader {
    ts: timeval,
    caplen: u32,
    len: u32,
    comment: [u8; 256],
}

impl Clone for PacketHeader {
    fn clone(&self) -> PacketHeader {
        *self
    }
}

pub struct PcapPacket {
    pub ll_data: Vec<u8>,
}

unsafe impl Send for Pcap {}
unsafe impl Sync for Pcap {}

pub struct Pcap {
    pcap_: Pcap_,
}

pub enum DataLinkType {
    Null = 0,
    Ethernet = 1,
}

#[link(name = "pcap")]
extern "C" {
    pub fn pcap_open_live(
        device: *const c_char,
        snaplen: c_int,
        promisc: c_int,
        to_ms: c_int,
        errbuf: *mut c_char,
    ) -> Pcap_;

    pub fn pcap_close(pcap: Pcap_);

    pub fn pcap_datalink(pcap: Pcap_) -> c_int;

    pub fn pcap_next_ex(
        pcap: Pcap_,
        pkthdr: *mut *const PacketHeader,
        ll_data: *mut *const u8,
    ) -> c_int;

    pub fn pcap_sendpacket(pcap: Pcap_, ll_data: *const u8, len: c_int) -> c_int;
}

impl Pcap {
    pub fn open_live(device: &str) -> Result<Pcap, String> {
        let errbuf = [0; PCAP_ERRBUF_SIZE].as_mut_ptr();
        let device = ffi::CString::new(device.as_bytes()).unwrap();
        let pcap = unsafe { pcap_open_live(device.as_ptr(), 65536, 1, 500, errbuf) };
        if pcap.is_null() {
            return Err(
                unsafe { str::from_utf8(ffi::CStr::from_ptr(errbuf).to_bytes()).unwrap() }
                    .to_owned(),
            );
        }
        Ok(Pcap { pcap_: pcap })
    }

    pub fn data_link_type(&self) -> DataLinkType {
        match unsafe { pcap_datalink(self.pcap_) } {
            0 => DataLinkType::Null,
            1 => DataLinkType::Ethernet,
            _ => panic!("Unsupported data link type"),
        }
    }

    pub fn next_packet(&self) -> Option<PcapPacket> {
        let mut packet_header_pnt: *const PacketHeader = ptr::null();
        let mut ll_data_pnt: *const u8 = ptr::null();
        match unsafe { pcap_next_ex(self.pcap_, &mut packet_header_pnt, &mut ll_data_pnt) } {
            0 => self.next_packet(),
            1 => {
                let packet_header = unsafe { *packet_header_pnt };
                let ll_data_len = packet_header.caplen as usize;
                let ll_data =
                    unsafe { slice::from_raw_parts(ll_data_pnt as *mut u8, ll_data_len) }.to_vec();
                Some(PcapPacket { ll_data: ll_data })
            }
            _ => None,
        }
    }

    pub fn send_packet<T: Copy>(&self, data: &T) -> Result<(), &str> {
        let ll_data = data as *const T as *const u8;
        let ll_data_len = mem::size_of_val(data);
        match unsafe { pcap_sendpacket(self.pcap_, ll_data, ll_data_len as i32) } {
            0 => Ok(()),
            _ => Err("Unable to send packet"),
        }
    }
}

impl Drop for Pcap {
    fn drop(&mut self) {
        unsafe { pcap_close(self.pcap_) };
    }
}
