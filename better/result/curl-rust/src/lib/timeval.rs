use :: libc;
extern "C" {
    fn clock_gettime(__clock_id: i32, __tp: *mut crate::src::lib::file::timespec) -> i32;
    fn gettimeofday(
        __tv: *mut crate::src::lib::openldap::timeval,
        __tz: *mut core::ffi::c_void,
    ) -> i32;
}
pub type __time_t = i64;
pub type __suseconds_t = i64;
pub type __clockid_t = i32;
pub type __syscall_slong_t = i64;
pub type clockid_t = i32;
pub type time_t = i64;
pub type timeval = crate::src::lib::openldap::timeval;
pub type timespec = crate::src::lib::file::timespec;
pub type curl_off_t = i64;
pub type timediff_t = i64;
pub type curltime = crate::src::lib::http2::curltime;
#[no_mangle]
pub extern "C" fn Curl_now() -> crate::src::lib::http2::curltime {
    let mut now: crate::src::lib::openldap::timeval = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut cnow: crate::src::lib::http2::curltime = curltime {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut tsnow: crate::src::lib::file::timespec = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if 0 as i32 == (unsafe { clock_gettime(1 as i32, &mut tsnow) }) {
        cnow.tv_sec = tsnow.tv_sec;
        cnow.tv_usec = (tsnow.tv_nsec / 1000 as i32 as i64) as u32 as i32;
    } else {
        (unsafe { gettimeofday(&mut now, 0 as *mut libc::c_void) });
        cnow.tv_sec = now.tv_sec;
        cnow.tv_usec = now.tv_usec as u32 as i32;
    }
    return cnow;
}
#[no_mangle]
pub extern "C" fn Curl_timediff(
    mut newer: crate::src::lib::http2::curltime,
    mut older: crate::src::lib::http2::curltime,
) -> i64 {
    let mut diff: i64 = newer.tv_sec - older.tv_sec;
    if diff >= 0x7fffffffffffffff as i64 / 1000 as i32 as i64 {
        return 0x7fffffffffffffff as i64;
    } else {
        if diff <= (-(0x7fffffffffffffff as i64) - 1 as i64) / 1000 as i32 as i64 {
            return -(0x7fffffffffffffff as i64) - 1 as i64;
        }
    }
    return diff * 1000 as i32 as i64 + ((newer.tv_usec - older.tv_usec) / 1000 as i32) as i64;
}
#[no_mangle]
pub extern "C" fn Curl_timediff_us(
    mut newer: crate::src::lib::http2::curltime,
    mut older: crate::src::lib::http2::curltime,
) -> i64 {
    let mut diff: i64 = newer.tv_sec - older.tv_sec;
    if diff >= 0x7fffffffffffffff as i64 / 1000000 as i32 as i64 {
        return 0x7fffffffffffffff as i64;
    } else {
        if diff <= (-(0x7fffffffffffffff as i64) - 1 as i64) / 1000000 as i32 as i64 {
            return -(0x7fffffffffffffff as i64) - 1 as i64;
        }
    }
    return diff * 1000000 as i32 as i64 + newer.tv_usec as i64 - older.tv_usec as i64;
}

