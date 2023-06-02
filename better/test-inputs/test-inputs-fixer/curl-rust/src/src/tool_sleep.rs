
extern "C" {
    fn poll(__fds: *mut pollfd, __nfds: nfds_t, __timeout: i32) -> i32;
}
pub type nfds_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pollfd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}
#[no_mangle]
pub extern "C" fn tool_go_sleep(mut ms: i64) {
    (unsafe { poll(0 as *mut pollfd, 0 as i32 as nfds_t, ms as i32) });
}
