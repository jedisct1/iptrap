
use std::hash::sip;
use std::hash::Hash;
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

#[deriving(Hash)]
struct CookieInput {
    ip_src: [u8, ..4],
    ip_dst: [u8, ..4],
    th_sport: u16,
    th_dport: u16,
    uts: u64
}

#[allow(unused_must_use)]
pub fn tcp(ip_src: [u8, ..4], ip_dst: [u8, ..4], th_sport: u16, th_dport: u16,
           sk: SipHashKey, uts: u64) -> u32 {
    let input = CookieInput {
        ip_src: ip_src,
        ip_dst: ip_dst,
        th_sport: th_sport,
        th_dport: th_dport,
        uts: uts
    };
    sip::hash_with_keys(sk.k1, sk.k2, &input) as u32
}
