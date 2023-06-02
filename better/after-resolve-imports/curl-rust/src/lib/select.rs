use ::libc;
extern "C" {
    fn __errno_location() -> *mut i32;
    fn poll(__fds: *mut pollfd, __nfds: nfds_t, __timeout: i32) -> i32;
}
pub type curl_off_t = crate::src::lib::altsvc::curl_off_t;
pub type timediff_t = crate::src::lib::altsvc::timediff_t;
pub type curl_socket_t = crate::src::lib::altsvc::curl_socket_t;
pub type nfds_t = u64;
// #[derive(Copy, Clone)]

pub type pollfd = crate::src::lib::multi::pollfd;
#[no_mangle]
pub unsafe extern "C" fn Curl_wait_ms(mut timeout_ms: timediff_t) -> i32 {
    let mut r: i32 = 0 as i32;
    if timeout_ms == 0 {
        return 0 as i32;
    }
    if timeout_ms < 0 as i32 as i64 {
        *__errno_location() = 22 as i32;
        return -(1 as i32);
    }
    if timeout_ms > 2147483647 as i32 as i64 {
        timeout_ms = 2147483647 as i32 as timediff_t;
    }
    r = poll(0 as *mut pollfd, 0 as i32 as nfds_t, timeout_ms as i32);
    if r != 0 {
        r = -(1 as i32);
    }
    return r;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_socket_check(
    mut readfd0: curl_socket_t,
    mut readfd1: curl_socket_t,
    mut writefd: curl_socket_t,
    mut timeout_ms: timediff_t,
) -> i32 {
    let mut pfd: [pollfd; 3] = [pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    }; 3];
    let mut num: i32 = 0;
    let mut r: i32 = 0;
    if readfd0 == -(1 as i32) && readfd1 == -(1 as i32)
        && writefd == -(1 as i32)
    {
        return Curl_wait_ms(timeout_ms);
    }
    num = 0 as i32;
    if readfd0 != -(1 as i32) {
        pfd[num as usize].fd = readfd0;
        pfd[num as usize]
            .events = (0x40 as i32 | 0x1 as i32 | 0x80 as i32
            | 0x2 as i32) as i16;
        pfd[num as usize].revents = 0 as i32 as i16;
        num += 1;
    }
    if readfd1 != -(1 as i32) {
        pfd[num as usize].fd = readfd1;
        pfd[num as usize]
            .events = (0x40 as i32 | 0x1 as i32 | 0x80 as i32
            | 0x2 as i32) as i16;
        pfd[num as usize].revents = 0 as i32 as i16;
        num += 1;
    }
    if writefd != -(1 as i32) {
        pfd[num as usize].fd = writefd;
        pfd[num as usize]
            .events = (0x100 as i32 | 0x4 as i32 | 0x2 as i32)
            as i16;
        pfd[num as usize].revents = 0 as i32 as i16;
        num += 1;
    }
    r = Curl_poll(pfd.as_mut_ptr(), num as u32, timeout_ms);
    if r <= 0 as i32 {
        return r;
    }
    r = 0 as i32;
    num = 0 as i32;
    if readfd0 != -(1 as i32) {
        if pfd[num as usize].revents as i32
            & (0x40 as i32 | 0x1 as i32 | 0x8 as i32
                | 0x10 as i32) != 0
        {
            r |= 0x1 as i32;
        }
        if pfd[num as usize].revents as i32
            & (0x80 as i32 | 0x2 as i32 | 0x20 as i32) != 0
        {
            r |= 0x4 as i32;
        }
        num += 1;
    }
    if readfd1 != -(1 as i32) {
        if pfd[num as usize].revents as i32
            & (0x40 as i32 | 0x1 as i32 | 0x8 as i32
                | 0x10 as i32) != 0
        {
            r |= (0x4 as i32) << 1 as i32;
        }
        if pfd[num as usize].revents as i32
            & (0x80 as i32 | 0x2 as i32 | 0x20 as i32) != 0
        {
            r |= 0x4 as i32;
        }
        num += 1;
    }
    if writefd != -(1 as i32) {
        if pfd[num as usize].revents as i32
            & (0x100 as i32 | 0x4 as i32) != 0
        {
            r |= 0x2 as i32;
        }
        if pfd[num as usize].revents as i32
            & (0x8 as i32 | 0x10 as i32 | 0x2 as i32
                | 0x20 as i32) != 0
        {
            r |= 0x4 as i32;
        }
    }
    return r;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_poll(
    mut ufds: *mut pollfd,
    mut nfds: u32,
    mut timeout_ms: timediff_t,
) -> i32 {
    let mut pending_ms: i32 = 0;
    let mut fds_none: bool = 1 as i32 != 0;
    let mut i: u32 = 0;
    let mut r: i32 = 0;
    if !ufds.is_null() {
        i = 0 as i32 as u32;
        while i < nfds {
            if (*ufds.offset(i as isize)).fd != -(1 as i32) {
                fds_none = 0 as i32 != 0;
                break;
            } else {
                i = i.wrapping_add(1);
            }
        }
    }
    if fds_none {
        return Curl_wait_ms(timeout_ms);
    }
    if timeout_ms > 2147483647 as i32 as i64 {
        timeout_ms = 2147483647 as i32 as timediff_t;
    }
    if timeout_ms > 0 as i32 as i64 {
        pending_ms = timeout_ms as i32;
    } else if timeout_ms < 0 as i32 as i64 {
        pending_ms = -(1 as i32);
    } else {
        pending_ms = 0 as i32;
    }
    r = poll(ufds, nfds as nfds_t, pending_ms);
    if r <= 0 as i32 {
        return r;
    }
    i = 0 as i32 as u32;
    while i < nfds {
        if !((*ufds.offset(i as isize)).fd == -(1 as i32)) {
            if (*ufds.offset(i as isize)).revents as i32 & 0x10 as i32
                != 0
            {
                let fresh0 = &mut ((*ufds.offset(i as isize)).revents);
                *fresh0 = (*fresh0 as i32 | 0x1 as i32) as i16;
            }
            if (*ufds.offset(i as isize)).revents as i32 & 0x8 as i32
                != 0
            {
                let fresh1 = &mut ((*ufds.offset(i as isize)).revents);
                *fresh1 = (*fresh1 as i32
                    | (0x1 as i32 | 0x4 as i32)) as i16;
            }
        }
        i = i.wrapping_add(1);
    }
    return r;
}
