use ::libc;
extern "C" {
    fn rename(__old: *const libc::c_char, __new: *const libc::c_char) -> libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_rename(
    mut oldpath: *const libc::c_char,
    mut newpath: *const libc::c_char,
) -> libc::c_int {
    if rename(oldpath, newpath) != 0 {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
