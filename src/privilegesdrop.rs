
use ::libc::{uid_t, gid_t, c_int, c_void, setgid, setuid};

pub fn switch_user(uid: Option<uid_t>, gid: Option<gid_t>) {
    match gid {
        Some(gid) => {
            if unsafe { setgid(gid) } != 0 {
                panic!("setgid()");
            }
        }
        None => (),
    }
    match uid {
        Some(uid) => {
            extern "C" {
                fn setgroups(ngroups: c_int, ptr: *const c_void) -> c_int;
            }
            let _ = unsafe { setgroups(0, 0 as *const c_void) };
            if unsafe { setuid(uid) } != 0 {
                panic!("setuid()");
            }
        }
        None => (),
    }
}
