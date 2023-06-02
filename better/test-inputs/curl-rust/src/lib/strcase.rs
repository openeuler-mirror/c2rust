use ::libc;
pub type size_t = libc::c_ulong;
#[no_mangle]
pub unsafe extern "C" fn Curl_raw_toupper(mut in_0: libc::c_char) -> libc::c_char {
    if in_0 as libc::c_int >= 'a' as i32 && in_0 as libc::c_int <= 'z' as i32 {
        return ('A' as i32 + in_0 as libc::c_int - 'a' as i32) as libc::c_char;
    }
    return in_0;
}
unsafe extern "C" fn raw_tolower(mut in_0: libc::c_char) -> libc::c_char {
    if in_0 as libc::c_int >= 'A' as i32 && in_0 as libc::c_int <= 'Z' as i32 {
        return ('a' as i32 + in_0 as libc::c_int - 'A' as i32) as libc::c_char;
    }
    return in_0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_strcasecompare(
    mut first: *const libc::c_char,
    mut second: *const libc::c_char,
) -> libc::c_int {
    while *first as libc::c_int != 0 && *second as libc::c_int != 0 {
        if Curl_raw_toupper(*first) as libc::c_int
            != Curl_raw_toupper(*second) as libc::c_int
        {
            break;
        }
        first = first.offset(1);
        second = second.offset(1);
    }
    return (Curl_raw_toupper(*first) as libc::c_int
        == Curl_raw_toupper(*second) as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_safe_strcasecompare(
    mut first: *const libc::c_char,
    mut second: *const libc::c_char,
) -> libc::c_int {
    if !first.is_null() && !second.is_null() {
        return Curl_strcasecompare(first, second);
    }
    return (first.is_null() && second.is_null()) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_strncasecompare(
    mut first: *const libc::c_char,
    mut second: *const libc::c_char,
    mut max: size_t,
) -> libc::c_int {
    while *first as libc::c_int != 0 && *second as libc::c_int != 0 && max != 0 {
        if Curl_raw_toupper(*first) as libc::c_int
            != Curl_raw_toupper(*second) as libc::c_int
        {
            break;
        }
        max = max.wrapping_sub(1);
        first = first.offset(1);
        second = second.offset(1);
    }
    if 0 as libc::c_int as libc::c_ulong == max {
        return 1 as libc::c_int;
    }
    return (Curl_raw_toupper(*first) as libc::c_int
        == Curl_raw_toupper(*second) as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_strntoupper(
    mut dest: *mut libc::c_char,
    mut src: *const libc::c_char,
    mut n: size_t,
) {
    if n < 1 as libc::c_int as libc::c_ulong {
        return;
    }
    loop {
        let fresh0 = dest;
        dest = dest.offset(1);
        *fresh0 = Curl_raw_toupper(*src);
        let fresh1 = src;
        src = src.offset(1);
        if !(*fresh1 as libc::c_int != 0
            && {
                n = n.wrapping_sub(1);
                n != 0
            })
        {
            break;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn Curl_strntolower(
    mut dest: *mut libc::c_char,
    mut src: *const libc::c_char,
    mut n: size_t,
) {
    if n < 1 as libc::c_int as libc::c_ulong {
        return;
    }
    loop {
        let fresh2 = dest;
        dest = dest.offset(1);
        *fresh2 = raw_tolower(*src);
        let fresh3 = src;
        src = src.offset(1);
        if !(*fresh3 as libc::c_int != 0
            && {
                n = n.wrapping_sub(1);
                n != 0
            })
        {
            break;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn curl_strequal(
    mut first: *const libc::c_char,
    mut second: *const libc::c_char,
) -> libc::c_int {
    return Curl_strcasecompare(first, second);
}
#[no_mangle]
pub unsafe extern "C" fn curl_strnequal(
    mut first: *const libc::c_char,
    mut second: *const libc::c_char,
    mut max: size_t,
) -> libc::c_int {
    return Curl_strncasecompare(first, second, max);
}
