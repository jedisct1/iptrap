
use std::hash::{Hash, Hasher, SipHasher};
use std::rand;

pub struct SipHashKey {
    k1: u64,
    k2: u64
}

impl Copy for SipHashKey { }

impl SipHashKey {
    pub fn new() -> SipHashKey {
        SipHashKey {
            k1: rand::random(),
            k2: rand::random()
        }
    }
}

#[allow(unused_must_use)]
pub fn tcp(ip_src: [u8; 4], ip_dst: [u8; 4], th_sport: u16, th_dport: u16,
           sk: SipHashKey, uts: u64) -> u32 {
    let sip = &mut SipHasher::new_with_keys(sk.k1, sk.k2);
    ip_src.hash(sip);
    ip_dst.hash(sip);
    th_sport.hash(sip);
    th_dport.hash(sip);
    uts.hash(sip);
    sip.finish() as u32
}
