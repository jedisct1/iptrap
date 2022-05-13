use std::hash::{Hash, Hasher};

use rand;
use siphasher;

use self::siphasher::sip::SipHasher13;

#[derive(Copy, Clone)]
pub struct SipHashKey {
    k1: u64,
    k2: u64,
}

impl SipHashKey {
    pub fn new() -> SipHashKey {
        SipHashKey {
            k1: rand::random(),
            k2: rand::random(),
        }
    }
}

#[derive(Hash)]
struct CookieInput {
    ip_src: [u8; 4],
    ip_dst: [u8; 4],
    th_sport: u16,
    th_dport: u16,
    uts: u64,
}

#[allow(unused_must_use)]
pub fn tcp(
    ip_src: [u8; 4],
    ip_dst: [u8; 4],
    th_sport: u16,
    th_dport: u16,
    sk: SipHashKey,
    uts: u64,
) -> u32 {
    let input = CookieInput {
        ip_src,
        ip_dst,
        th_sport,
        th_dport,
        uts,
    };
    let sip = &mut SipHasher13::new_with_keys(sk.k1, sk.k2);
    input.hash(sip);
    sip.finish() as u32
}
