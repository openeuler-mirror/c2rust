use ::libc;
extern "C" {
    fn clock_gettime(__clock_id: clockid_t, __tp: *mut timespec) -> libc::c_int;
    fn gettimeofday(__tv: *mut timeval, __tz: *mut libc::c_void) -> libc::c_int;
}
pub type __time_t = libc::c_long;
pub type __suseconds_t = libc::c_long;
pub type __clockid_t = libc::c_int;
pub type __syscall_slong_t = libc::c_long;
pub type clockid_t = __clockid_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timeval {
    pub tv_sec: __time_t,
    pub tv_usec: __suseconds_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
#[no_mangle]
pub unsafe extern "C" fn tvnow() -> timeval {
    let mut now: timeval = timeval { tv_sec: 0, tv_usec: 0 };
    let mut tsnow: timespec = timespec { tv_sec: 0, tv_nsec: 0 };
    if 0 as libc::c_int == clock_gettime(1 as libc::c_int, &mut tsnow) {
        now.tv_sec = tsnow.tv_sec;
        now
            .tv_usec = (tsnow.tv_nsec / 1000 as libc::c_int as libc::c_long)
            as libc::c_int as __suseconds_t;
    } else {
        gettimeofday(&mut now, 0 as *mut libc::c_void);
    }
    return now;
}
#[no_mangle]
pub unsafe extern "C" fn tvdiff(mut newer: timeval, mut older: timeval) -> libc::c_long {
    return (newer.tv_sec - older.tv_sec) * 1000 as libc::c_int as libc::c_long
        + (newer.tv_usec - older.tv_usec) / 1000 as libc::c_int as libc::c_long;
}
