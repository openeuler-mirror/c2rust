use ::libc;
extern "C" {
    fn clock_gettime(__clock_id: clockid_t, __tp: *mut timespec) -> i32;
    fn gettimeofday(__tv: *mut timeval, __tz: *mut libc::c_void) -> i32;
}
pub type __time_t = crate::src::lib::http2::__time_t;
pub type __suseconds_t = crate::src::lib::openldap::__suseconds_t;
pub type __clockid_t = crate::src::lib::timeval::__clockid_t;
pub type __syscall_slong_t = crate::src::lib::file::__syscall_slong_t;
pub type clockid_t = crate::src::lib::timeval::clockid_t;
// #[derive(Copy, Clone)]

pub type timeval = crate::src::lib::openldap::timeval;
// #[derive(Copy, Clone)]

pub type timespec = crate::src::lib::file::timespec;
#[no_mangle]
pub unsafe extern "C" fn tvnow() -> timeval {
    let mut now: timeval = timeval { tv_sec: 0, tv_usec: 0 };
    let mut tsnow: timespec = timespec { tv_sec: 0, tv_nsec: 0 };
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
pub extern "C" fn tvdiff(mut newer: timeval, mut older: timeval) -> i64 {
    return (newer.tv_sec - older.tv_sec) * 1000 as i32 as i64
        + (newer.tv_usec - older.tv_usec) / 1000 as i32 as i64;
}
