use ::libc;
#[no_mangle]
pub unsafe extern "C" fn json_c_version() -> *const libc::c_char {
    return b"0.16.99\0" as *const u8 as *const libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn json_c_version_num() -> libc::c_int {
    return (0 as libc::c_int) << 16 as libc::c_int
        | (16 as libc::c_int) << 8 as libc::c_int | 99 as libc::c_int;
}
