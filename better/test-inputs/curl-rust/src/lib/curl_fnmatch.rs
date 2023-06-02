use ::libc;
extern "C" {
    fn fnmatch(
        __pattern: *const libc::c_char,
        __name: *const libc::c_char,
        __flags: libc::c_int,
    ) -> libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_fnmatch(
    mut ptr: *mut libc::c_void,
    mut pattern: *const libc::c_char,
    mut string: *const libc::c_char,
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    if pattern.is_null() || string.is_null() {
        return 2 as libc::c_int;
    }
    rc = fnmatch(pattern, string, 0 as libc::c_int);
    match rc {
        0 => return 0 as libc::c_int,
        1 => return 1 as libc::c_int,
        _ => return 2 as libc::c_int,
    };
}
