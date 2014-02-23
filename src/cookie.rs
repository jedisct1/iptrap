
use std::hash::sip;
use std::hash::Hash;

pub struct SipHashKey {
    k1: u64,
    k2: u64
}

#[deriving(Hash)]
struct CookieInput<'s> {
    ip_src: &'s [u8],
    ip_dst: &'s [u8],
    th_sport: u16,
    th_dport: u16,
    uts: u64
}

#[allow(unused_must_use)]
pub fn tcp(ip_src: &[u8], ip_dst: &[u8], th_sport: u16, th_dport: u16,
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
