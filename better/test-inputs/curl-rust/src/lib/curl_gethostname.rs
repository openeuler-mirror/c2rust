use ::libc;
extern "C" {
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn gethostname(__name: *mut libc::c_char, __len: size_t) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
#[no_mangle]
pub unsafe extern "C" fn Curl_gethostname(
    name: *mut libc::c_char,
    mut namelen: size_t,
) -> libc::c_int {
    let mut err: libc::c_int = 0;
    let mut dot: *mut libc::c_char = 0 as *mut libc::c_char;
    *name.offset(0 as libc::c_int as isize) = '\u{0}' as i32 as libc::c_char;
    err = gethostname(name, namelen);
    *name
        .offset(
            namelen.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
        ) = '\u{0}' as i32 as libc::c_char;
    if err != 0 {
        return err;
    }
    dot = strchr(name, '.' as i32);
    if !dot.is_null() {
        *dot = '\u{0}' as i32 as libc::c_char;
    }
    return 0 as libc::c_int;
}
