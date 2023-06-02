use ::libc;
pub type size_t = u64;
#[no_mangle]
pub extern "C" fn Curl_raw_toupper(mut in_0: i8) -> i8 {
    if in_0 as i32 >= 'a' as i32 && in_0 as i32 <= 'z' as i32 {
        return ('A' as i32 + in_0 as i32 - 'a' as i32) as i8;
    }
    return in_0;
}
 extern "C" fn raw_tolower(mut in_0: i8) -> i8 {
    if in_0 as i32 >= 'A' as i32 && in_0 as i32 <= 'Z' as i32 {
        return ('a' as i32 + in_0 as i32 - 'A' as i32) as i8;
    }
    return in_0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_strcasecompare(
    mut first: * const i8,
    mut second: * const i8,
) -> i32 {
    while *first as i32 != 0 && *second as i32 != 0 {
        if Curl_raw_toupper(*first) as i32
            != Curl_raw_toupper(*second) as i32
        {
            break;
        }
        first = first.offset(1);
        second = second.offset(1);
    }
    return (Curl_raw_toupper(*first) as i32
        == Curl_raw_toupper(*second) as i32) as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_safe_strcasecompare(
    mut first: * const i8,
    mut second: * const i8,
) -> i32 {
    if !first.is_null() && !second.is_null() {
        return Curl_strcasecompare(first, second);
    }
    return (first.is_null() && second.is_null()) as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_strncasecompare(
    mut first: * const i8,
    mut second: * const i8,
    mut max: u64,
) -> i32 {
    while *first as i32 != 0 && *second as i32 != 0 && max != 0 {
        if Curl_raw_toupper(*first) as i32
            != Curl_raw_toupper(*second) as i32
        {
            break;
        }
        max = max.wrapping_sub(1);
        first = first.offset(1);
        second = second.offset(1);
    }
    if 0 as i32 as u64 == max {
        return 1 as i32;
    }
    return (Curl_raw_toupper(*first) as i32
        == Curl_raw_toupper(*second) as i32) as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_strntoupper(
    mut dest: * mut i8,
    mut src: * const i8,
    mut n: u64,
) {
    if n < 1 as i32 as u64 {
        return;
    }
    loop {
        let mut fresh0 = dest;
        dest = dest.offset(1);
        *fresh0 = Curl_raw_toupper(*src);
        let mut fresh1 = src;
        src = src.offset(1);
        if !(*fresh1 as i32 != 0
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
    mut dest: * mut i8,
    mut src: * const i8,
    mut n: u64,
) {
    if n < 1 as i32 as u64 {
        return;
    }
    loop {
        let mut fresh2 = dest;
        dest = dest.offset(1);
        *fresh2 = raw_tolower(*src);
        let mut fresh3 = src;
        src = src.offset(1);
        if !(*fresh3 as i32 != 0
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
    mut first: * const i8,
    mut second: * const i8,
) -> i32 {
    return Curl_strcasecompare(first, second);
}
#[no_mangle]
pub unsafe extern "C" fn curl_strnequal(
    mut first: * const i8,
    mut second: * const i8,
    mut max: u64,
) -> i32 {
    return Curl_strncasecompare(first, second, max);
}
use crate::laertes_rt::*;
