
use std::hash::sip::SipState;

pub struct SipHashKey {
    k1: u64,
    k2: u64
}

#[allow(unused_must_use)]
pub fn tcp(ip_src: &[u8], ip_dst: &[u8], th_sport: u16, th_dport: u16,
           sk: SipHashKey, uts: u64) -> u32 {
    let mut hash = SipState::new(sk.k1, sk.k2);
    hash.write(ip_src);
    hash.write(ip_dst);
    hash.write_le_u16(th_sport);
    hash.write_le_u16(th_dport);
    hash.write_le_u64(uts);
    hash.result() as u32
}
