use :: libc;
extern "C" {
    fn clock_gettime(__clock_id: clockid_t, __tp: *mut timespec) -> i32;
    fn gettimeofday(__tv: *mut timeval, __tz: *mut libc::c_void) -> i32;
}
pub type __time_t = i64;
pub type __suseconds_t = i64;
pub type __clockid_t = i32;
pub type __syscall_slong_t = i64;
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
pub extern "C" fn tvnow() -> timeval {
    let mut now: timeval = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut tsnow: timespec = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if 0 as i32 == (unsafe { clock_gettime(1 as i32, &mut tsnow) }) {
        now.tv_sec = tsnow.tv_sec;
        now.tv_usec = (tsnow.tv_nsec / 1000 as i32 as i64) as i32 as __suseconds_t;
    } else {
        (unsafe { gettimeofday(&mut now, 0 as *mut libc::c_void) });
    }
    return now;
}
#[no_mangle]
pub extern "C" fn tvdiff(mut newer: timeval, mut older: timeval) -> i64 {
    return (newer.tv_sec - older.tv_sec) * 1000 as i32 as i64
        + (newer.tv_usec - older.tv_usec) / 1000 as i32 as i64;
}
