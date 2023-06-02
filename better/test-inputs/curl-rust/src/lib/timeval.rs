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
pub type time_t = __time_t;
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
pub type curl_off_t = libc::c_long;
pub type timediff_t = curl_off_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curltime {
    pub tv_sec: time_t,
    pub tv_usec: libc::c_int,
}
#[no_mangle]
pub unsafe extern "C" fn Curl_now() -> curltime {
    let mut now: timeval = timeval { tv_sec: 0, tv_usec: 0 };
    let mut cnow: curltime = curltime { tv_sec: 0, tv_usec: 0 };
    let mut tsnow: timespec = timespec { tv_sec: 0, tv_nsec: 0 };
    if 0 as libc::c_int == clock_gettime(1 as libc::c_int, &mut tsnow) {
        cnow.tv_sec = tsnow.tv_sec;
        cnow
            .tv_usec = (tsnow.tv_nsec / 1000 as libc::c_int as libc::c_long)
            as libc::c_uint as libc::c_int;
    } else {
        gettimeofday(&mut now, 0 as *mut libc::c_void);
        cnow.tv_sec = now.tv_sec;
        cnow.tv_usec = now.tv_usec as libc::c_uint as libc::c_int;
    }
    return cnow;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_timediff(
    mut newer: curltime,
    mut older: curltime,
) -> timediff_t {
    let mut diff: timediff_t = newer.tv_sec - older.tv_sec;
    if diff >= 0x7fffffffffffffff as libc::c_long / 1000 as libc::c_int as libc::c_long {
        return 0x7fffffffffffffff as libc::c_long
    } else {
        if diff
            <= (-(0x7fffffffffffffff as libc::c_long) - 1 as libc::c_long)
                / 1000 as libc::c_int as libc::c_long
        {
            return -(0x7fffffffffffffff as libc::c_long) - 1 as libc::c_long;
        }
    }
    return diff * 1000 as libc::c_int as libc::c_long
        + ((newer.tv_usec - older.tv_usec) / 1000 as libc::c_int) as libc::c_long;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_timediff_us(
    mut newer: curltime,
    mut older: curltime,
) -> timediff_t {
    let mut diff: timediff_t = newer.tv_sec - older.tv_sec;
    if diff
        >= 0x7fffffffffffffff as libc::c_long / 1000000 as libc::c_int as libc::c_long
    {
        return 0x7fffffffffffffff as libc::c_long
    } else {
        if diff
            <= (-(0x7fffffffffffffff as libc::c_long) - 1 as libc::c_long)
                / 1000000 as libc::c_int as libc::c_long
        {
            return -(0x7fffffffffffffff as libc::c_long) - 1 as libc::c_long;
        }
    }
    return diff * 1000000 as libc::c_int as libc::c_long + newer.tv_usec as libc::c_long
        - older.tv_usec as libc::c_long;
}
