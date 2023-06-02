use ::libc;
extern "C" {
    fn clock_gettime(__clock_id: i32, __tp: * mut crate::src::lib::file::timespec) -> i32;
    fn gettimeofday(__tv: * mut crate::src::lib::openldap::timeval, __tz: * mut core::ffi::c_void) -> i32;
}
pub type __time_t = i64;
pub type __suseconds_t = i64;
pub type __clockid_t = i32;
pub type __syscall_slong_t = i64;
pub type clockid_t = i32;
// #[derive(Copy, Clone)]

pub type timeval = crate::src::lib::openldap::timeval;
// #[derive(Copy, Clone)]

pub type timespec = crate::src::lib::file::timespec;
#[no_mangle]
pub unsafe extern "C" fn tvnow() -> crate::src::lib::openldap::timeval {
    let mut now: crate::src::lib::openldap::timeval = timeval { tv_sec: 0, tv_usec: 0 };
    let mut tsnow: crate::src::lib::file::timespec = timespec { tv_sec: 0, tv_nsec: 0 };
    if 0 as i32 == clock_gettime(1 as i32, &mut tsnow) {
        now.tv_sec = tsnow.tv_sec;
        now
            .tv_usec = (tsnow.tv_nsec / 1000 as i32 as i64)
            as i32 as __suseconds_t;
    } else {
        gettimeofday(&mut now, 0 as *mut libc::c_void);
    }
    return now;
}
#[no_mangle]
pub extern "C" fn tvdiff(mut newer: crate::src::lib::openldap::timeval, mut older: crate::src::lib::openldap::timeval) -> i64 {
    return (newer.tv_sec - older.tv_sec) * 1000 as i32 as i64
        + (newer.tv_usec - older.tv_usec) / 1000 as i32 as i64;
}
use crate::laertes_rt::*;
