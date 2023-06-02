use ::libc;
extern "C" {
    fn __errno_location() -> *mut libc::c_int;
    fn poll(__fds: *mut pollfd, __nfds: nfds_t, __timeout: libc::c_int) -> libc::c_int;
}
pub type curl_off_t = libc::c_long;
pub type timediff_t = curl_off_t;
pub type curl_socket_t = libc::c_int;
pub type nfds_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pollfd {
    pub fd: libc::c_int,
    pub events: libc::c_short,
    pub revents: libc::c_short,
}
#[no_mangle]
pub unsafe extern "C" fn Curl_wait_ms(mut timeout_ms: timediff_t) -> libc::c_int {
    let mut r: libc::c_int = 0 as libc::c_int;
    if timeout_ms == 0 {
        return 0 as libc::c_int;
    }
    if timeout_ms < 0 as libc::c_int as libc::c_long {
        *__errno_location() = 22 as libc::c_int;
        return -(1 as libc::c_int);
    }
    if timeout_ms > 2147483647 as libc::c_int as libc::c_long {
        timeout_ms = 2147483647 as libc::c_int as timediff_t;
    }
    r = poll(0 as *mut pollfd, 0 as libc::c_int as nfds_t, timeout_ms as libc::c_int);
    if r != 0 {
        r = -(1 as libc::c_int);
    }
    return r;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_socket_check(
    mut readfd0: curl_socket_t,
    mut readfd1: curl_socket_t,
    mut writefd: curl_socket_t,
    mut timeout_ms: timediff_t,
) -> libc::c_int {
    let mut pfd: [pollfd; 3] = [pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    }; 3];
    let mut num: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    if readfd0 == -(1 as libc::c_int) && readfd1 == -(1 as libc::c_int)
        && writefd == -(1 as libc::c_int)
    {
        return Curl_wait_ms(timeout_ms);
    }
    num = 0 as libc::c_int;
    if readfd0 != -(1 as libc::c_int) {
        pfd[num as usize].fd = readfd0;
        pfd[num as usize]
            .events = (0x40 as libc::c_int | 0x1 as libc::c_int | 0x80 as libc::c_int
            | 0x2 as libc::c_int) as libc::c_short;
        pfd[num as usize].revents = 0 as libc::c_int as libc::c_short;
        num += 1;
    }
    if readfd1 != -(1 as libc::c_int) {
        pfd[num as usize].fd = readfd1;
        pfd[num as usize]
            .events = (0x40 as libc::c_int | 0x1 as libc::c_int | 0x80 as libc::c_int
            | 0x2 as libc::c_int) as libc::c_short;
        pfd[num as usize].revents = 0 as libc::c_int as libc::c_short;
        num += 1;
    }
    if writefd != -(1 as libc::c_int) {
        pfd[num as usize].fd = writefd;
        pfd[num as usize]
            .events = (0x100 as libc::c_int | 0x4 as libc::c_int | 0x2 as libc::c_int)
            as libc::c_short;
        pfd[num as usize].revents = 0 as libc::c_int as libc::c_short;
        num += 1;
    }
    r = Curl_poll(pfd.as_mut_ptr(), num as libc::c_uint, timeout_ms);
    if r <= 0 as libc::c_int {
        return r;
    }
    r = 0 as libc::c_int;
    num = 0 as libc::c_int;
    if readfd0 != -(1 as libc::c_int) {
        if pfd[num as usize].revents as libc::c_int
            & (0x40 as libc::c_int | 0x1 as libc::c_int | 0x8 as libc::c_int
                | 0x10 as libc::c_int) != 0
        {
            r |= 0x1 as libc::c_int;
        }
        if pfd[num as usize].revents as libc::c_int
            & (0x80 as libc::c_int | 0x2 as libc::c_int | 0x20 as libc::c_int) != 0
        {
            r |= 0x4 as libc::c_int;
        }
        num += 1;
    }
    if readfd1 != -(1 as libc::c_int) {
        if pfd[num as usize].revents as libc::c_int
            & (0x40 as libc::c_int | 0x1 as libc::c_int | 0x8 as libc::c_int
                | 0x10 as libc::c_int) != 0
        {
            r |= (0x4 as libc::c_int) << 1 as libc::c_int;
        }
        if pfd[num as usize].revents as libc::c_int
            & (0x80 as libc::c_int | 0x2 as libc::c_int | 0x20 as libc::c_int) != 0
        {
            r |= 0x4 as libc::c_int;
        }
        num += 1;
    }
    if writefd != -(1 as libc::c_int) {
        if pfd[num as usize].revents as libc::c_int
            & (0x100 as libc::c_int | 0x4 as libc::c_int) != 0
        {
            r |= 0x2 as libc::c_int;
        }
        if pfd[num as usize].revents as libc::c_int
            & (0x8 as libc::c_int | 0x10 as libc::c_int | 0x2 as libc::c_int
                | 0x20 as libc::c_int) != 0
        {
            r |= 0x4 as libc::c_int;
        }
    }
    return r;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_poll(
    mut ufds: *mut pollfd,
    mut nfds: libc::c_uint,
    mut timeout_ms: timediff_t,
) -> libc::c_int {
    let mut pending_ms: libc::c_int = 0;
    let mut fds_none: bool = 1 as libc::c_int != 0;
    let mut i: libc::c_uint = 0;
    let mut r: libc::c_int = 0;
    if !ufds.is_null() {
        i = 0 as libc::c_int as libc::c_uint;
        while i < nfds {
            if (*ufds.offset(i as isize)).fd != -(1 as libc::c_int) {
                fds_none = 0 as libc::c_int != 0;
                break;
            } else {
                i = i.wrapping_add(1);
            }
        }
    }
    if fds_none {
        return Curl_wait_ms(timeout_ms);
    }
    if timeout_ms > 2147483647 as libc::c_int as libc::c_long {
        timeout_ms = 2147483647 as libc::c_int as timediff_t;
    }
    if timeout_ms > 0 as libc::c_int as libc::c_long {
        pending_ms = timeout_ms as libc::c_int;
    } else if timeout_ms < 0 as libc::c_int as libc::c_long {
        pending_ms = -(1 as libc::c_int);
    } else {
        pending_ms = 0 as libc::c_int;
    }
    r = poll(ufds, nfds as nfds_t, pending_ms);
    if r <= 0 as libc::c_int {
        return r;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while i < nfds {
        if !((*ufds.offset(i as isize)).fd == -(1 as libc::c_int)) {
            if (*ufds.offset(i as isize)).revents as libc::c_int & 0x10 as libc::c_int
                != 0
            {
                let ref mut fresh0 = (*ufds.offset(i as isize)).revents;
                *fresh0 = (*fresh0 as libc::c_int | 0x1 as libc::c_int) as libc::c_short;
            }
            if (*ufds.offset(i as isize)).revents as libc::c_int & 0x8 as libc::c_int
                != 0
            {
                let ref mut fresh1 = (*ufds.offset(i as isize)).revents;
                *fresh1 = (*fresh1 as libc::c_int
                    | (0x1 as libc::c_int | 0x4 as libc::c_int)) as libc::c_short;
            }
        }
        i = i.wrapping_add(1);
    }
    return r;
}
