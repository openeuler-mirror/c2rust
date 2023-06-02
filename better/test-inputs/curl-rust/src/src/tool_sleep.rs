use ::libc;
extern "C" {
    fn poll(__fds: *mut pollfd, __nfds: nfds_t, __timeout: libc::c_int) -> libc::c_int;
}
pub type nfds_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pollfd {
    pub fd: libc::c_int,
    pub events: libc::c_short,
    pub revents: libc::c_short,
}
#[no_mangle]
pub unsafe extern "C" fn tool_go_sleep(mut ms: libc::c_long) {
    poll(0 as *mut pollfd, 0 as libc::c_int as nfds_t, ms as libc::c_int);
}
