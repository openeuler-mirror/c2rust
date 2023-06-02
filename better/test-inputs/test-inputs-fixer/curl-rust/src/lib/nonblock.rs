
extern "C" {
    fn fcntl(__fd: i32, __cmd: i32, _: ...) -> i32;
}
pub type curl_socket_t = i32;
#[no_mangle]
pub extern "C" fn curlx_nonblock(mut sockfd: curl_socket_t, mut nonblock: i32) -> i32 {
    let mut flags: i32 = 0;
    flags = unsafe { fcntl(sockfd, 3 as i32, 0 as i32) };
    if nonblock != 0 {
        return unsafe { fcntl(sockfd, 4 as i32, flags | 0o4000 as i32) };
    }
    return unsafe { fcntl(sockfd, 4 as i32, flags & !(0o4000 as i32)) };
}
