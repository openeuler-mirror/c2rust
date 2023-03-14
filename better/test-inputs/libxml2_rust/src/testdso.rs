use ::libc;
extern "C" {
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn hello_world() -> libc::c_int {
    printf(b"Success!\n\0" as *const u8 as *const libc::c_char);
    return 0 as libc::c_int;
}
