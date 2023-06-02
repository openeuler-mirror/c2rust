use ::libc;
extern "C" {
    fn clock_gettime(__clock_id: clockid_t, __tp: *mut timespec) -> i32;
    fn gettimeofday(__tv: *mut timeval, __tz: *mut libc::c_void) -> i32;
}
pub type __time_t = crate::src::lib::http2::__time_t;
pub type __suseconds_t = crate::src::lib::openldap::__suseconds_t;
pub type __clockid_t = i32;
pub type __syscall_slong_t = crate::src::lib::file::__syscall_slong_t;
pub type clockid_t = __clockid_t;
pub type time_t = crate::src::lib::http2::time_t;
// #[derive(Copy, Clone)]

pub type timeval = crate::src::lib::openldap::timeval;
// #[derive(Copy, Clone)]

pub type timespec = crate::src::lib::file::timespec;
pub type curl_off_t = crate::src::lib::http2::curl_off_t;
pub type timediff_t = crate::src::lib::http2::timediff_t;
// #[derive(Copy, Clone)]

pub type curltime = crate::src::lib::http2::curltime;
#[no_mangle]
pub unsafe extern "C" fn Curl_now() -> curltime {
    let mut now: timeval = timeval { tv_sec: 0, tv_usec: 0 };
    let mut cnow: curltime = curltime { tv_sec: 0, tv_usec: 0 };
    let mut tsnow: timespec = timespec { tv_sec: 0, tv_nsec: 0 };
    if 0 as i32 == clock_gettime(1 as i32, &mut tsnow) {
        cnow.tv_sec = tsnow.tv_sec;
        cnow
            .tv_usec = (tsnow.tv_nsec / 1000 as i32 as i64)
            as u32 as i32;
    } else {
        gettimeofday(&mut now, 0 as *mut libc::c_void);
        cnow.tv_sec = now.tv_sec;
        cnow.tv_usec = now.tv_usec as u32 as i32;
    }
    return cnow;
}
#[no_mangle]
pub extern "C" fn Curl_timediff(
    mut newer: curltime,
    mut older: curltime,
) -> timediff_t {
    let mut diff: timediff_t = newer.tv_sec - older.tv_sec;
    if diff >= 0x7fffffffffffffff as i64 / 1000 as i32 as i64 {
        return 0x7fffffffffffffff as i64
    } else {
        if diff
            <= (-(0x7fffffffffffffff as i64) - 1 as i64)
                / 1000 as i32 as i64
        {
            return -(0x7fffffffffffffff as i64) - 1 as i64;
        }
    }
    return diff * 1000 as i32 as i64
        + ((newer.tv_usec - older.tv_usec) / 1000 as i32) as i64;
}
#[no_mangle]
pub extern "C" fn Curl_timediff_us(
    mut newer: curltime,
    mut older: curltime,
) -> timediff_t {
    let mut diff: timediff_t = newer.tv_sec - older.tv_sec;
    if diff
        >= 0x7fffffffffffffff as i64 / 1000000 as i32 as i64
    {
        return 0x7fffffffffffffff as i64
    } else {
        if diff
            <= (-(0x7fffffffffffffff as i64) - 1 as i64)
                / 1000000 as i32 as i64
        {
            return -(0x7fffffffffffffff as i64) - 1 as i64;
        }
    }
    return diff * 1000000 as i32 as i64 + newer.tv_usec as i64
        - older.tv_usec as i64;
}
