use ::libc;
extern "C" {
    fn strpbrk(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn curl_maprintf(format: *const libc::c_char, _: ...) -> *mut libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_auth_build_spn(
    mut service: *const libc::c_char,
    mut host: *const libc::c_char,
    mut realm: *const libc::c_char,
) -> *mut libc::c_char {
    let mut spn: *mut libc::c_char = 0 as *mut libc::c_char;
    if !host.is_null() && !realm.is_null() {
        spn = curl_maprintf(
            b"%s/%s@%s\0" as *const u8 as *const libc::c_char,
            service,
            host,
            realm,
        );
    } else if !host.is_null() {
        spn = curl_maprintf(
            b"%s/%s\0" as *const u8 as *const libc::c_char,
            service,
            host,
        );
    } else if !realm.is_null() {
        spn = curl_maprintf(
            b"%s@%s\0" as *const u8 as *const libc::c_char,
            service,
            realm,
        );
    }
    return spn;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_auth_user_contains_domain(
    mut user: *const libc::c_char,
) -> bool {
    let mut valid: bool = 0 as libc::c_int != 0;
    if !user.is_null() && *user as libc::c_int != 0 {
        let mut p: *mut libc::c_char = strpbrk(
            user,
            b"\\/@\0" as *const u8 as *const libc::c_char,
        );
        valid = if !p.is_null() && p > user as *mut libc::c_char
            && p
                < user.offset(strlen(user) as isize).offset(-(1 as libc::c_int as isize))
                    as *mut libc::c_char
        {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        } != 0;
    }
    return valid;
}
