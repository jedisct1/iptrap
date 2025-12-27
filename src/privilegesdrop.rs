use libc::{c_int, c_void, gid_t, setgid, setuid, uid_t};
use std::ptr;

pub fn switch_user(uid: Option<uid_t>, gid: Option<gid_t>) {
    if let Some(gid) = gid {
        if unsafe { setgid(gid) } != 0 {
            panic!("setgid()");
        }
    }
    if let Some(uid) = uid {
        extern "C" {
            fn setgroups(ngroups: c_int, ptr: *const c_void) -> c_int;
        }
        let _ = unsafe { setgroups(0, ptr::null::<c_void>()) };
        if unsafe { setuid(uid) } != 0 {
            panic!("setuid()");
        }
    }
}
