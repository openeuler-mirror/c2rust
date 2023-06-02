use ::libc;
extern "C" {
    fn fcntl(__fd: libc::c_int, __cmd: libc::c_int, _: ...) -> libc::c_int;
}
pub type curl_socket_t = libc::c_int;
#[no_mangle]
pub unsafe extern "C" fn curlx_nonblock(
    mut sockfd: curl_socket_t,
    mut nonblock: libc::c_int,
) -> libc::c_int {
    let mut flags: libc::c_int = 0;
    flags = fcntl(sockfd, 3 as libc::c_int, 0 as libc::c_int);
    if nonblock != 0 {
        return fcntl(sockfd, 4 as libc::c_int, flags | 0o4000 as libc::c_int);
    }
    return fcntl(sockfd, 4 as libc::c_int, flags & !(0o4000 as libc::c_int));
}
