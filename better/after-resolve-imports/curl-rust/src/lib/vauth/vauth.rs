use ::libc;
extern "C" {
    fn strpbrk(_: *const i8, _: *const i8) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    
}
pub use crate::src::lib::mprintf::curl_maprintf;
#[no_mangle]
pub unsafe extern "C" fn Curl_auth_build_spn(
    mut service: *const i8,
    mut host: *const i8,
    mut realm: *const i8,
) -> *mut i8 {
    let mut spn: *mut i8 = 0 as *mut i8;
    if !host.is_null() && !realm.is_null() {
        spn = curl_maprintf(
            b"%s/%s@%s\0" as *const u8 as *const i8,
            service,
            host,
            realm,
        );
    } else if !host.is_null() {
        spn = curl_maprintf(
            b"%s/%s\0" as *const u8 as *const i8,
            service,
            host,
        );
    } else if !realm.is_null() {
        spn = curl_maprintf(
            b"%s@%s\0" as *const u8 as *const i8,
            service,
            realm,
        );
    }
    return spn;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_auth_user_contains_domain(
    mut user: *const i8,
) -> bool {
    let mut valid: bool = 0 as i32 != 0;
    if !user.is_null() && *user as i32 != 0 {
        let mut p: *mut i8 = strpbrk(
            user,
            b"\\/@\0" as *const u8 as *const i8,
        );
        valid = if !p.is_null() && p > user as *mut i8
            && p
                < user.offset(strlen(user) as isize).offset(-(1 as i32 as isize))
                    as *mut i8
        {
            1 as i32
        } else {
            0 as i32
        } != 0;
    }
    return valid;
}
