use ::libc;
static mut ascii: [libc::c_uchar; 128] = [
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int | (1 as libc::c_int) << 3 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int | (1 as libc::c_int) << 3 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int | (1 as libc::c_int) << 3 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int | (1 as libc::c_int) << 3 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int | (1 as libc::c_int) << 3 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 3 as libc::c_int | (1 as libc::c_int) << 7 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int | (1 as libc::c_int) << 6 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int | (1 as libc::c_int) << 6 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int | (1 as libc::c_int) << 6 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int | (1 as libc::c_int) << 6 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int | (1 as libc::c_int) << 6 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int | (1 as libc::c_int) << 6 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int | (1 as libc::c_int) << 6 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int | (1 as libc::c_int) << 6 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int | (1 as libc::c_int) << 6 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int | (1 as libc::c_int) << 6 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int | (1 as libc::c_int) << 6 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int | (1 as libc::c_int) << 6 as libc::c_int)
        as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uchar,
    ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uchar,
];
#[no_mangle]
pub unsafe extern "C" fn Curl_isspace(mut c: libc::c_int) -> libc::c_int {
    if c < 0 as libc::c_int || c >= 0x80 as libc::c_int {
        return 0 as libc::c_int;
    }
    return ascii[c as usize] as libc::c_int & (1 as libc::c_int) << 3 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_isdigit(mut c: libc::c_int) -> libc::c_int {
    if c < 0 as libc::c_int || c >= 0x80 as libc::c_int {
        return 0 as libc::c_int;
    }
    return ascii[c as usize] as libc::c_int & (1 as libc::c_int) << 2 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_isalnum(mut c: libc::c_int) -> libc::c_int {
    if c < 0 as libc::c_int || c >= 0x80 as libc::c_int {
        return 0 as libc::c_int;
    }
    return ascii[c as usize] as libc::c_int
        & ((1 as libc::c_int) << 2 as libc::c_int
            | (1 as libc::c_int) << 0 as libc::c_int
            | (1 as libc::c_int) << 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_isxdigit(mut c: libc::c_int) -> libc::c_int {
    if c < 0 as libc::c_int || c >= 0x80 as libc::c_int {
        return 0 as libc::c_int;
    }
    return ascii[c as usize] as libc::c_int
        & ((1 as libc::c_int) << 2 as libc::c_int
            | (1 as libc::c_int) << 6 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_isgraph(mut c: libc::c_int) -> libc::c_int {
    if c < 0 as libc::c_int || c >= 0x80 as libc::c_int || c == ' ' as i32 {
        return 0 as libc::c_int;
    }
    return ascii[c as usize] as libc::c_int
        & ((1 as libc::c_int) << 2 as libc::c_int
            | (1 as libc::c_int) << 6 as libc::c_int
            | (1 as libc::c_int) << 0 as libc::c_int
            | (1 as libc::c_int) << 1 as libc::c_int
            | (1 as libc::c_int) << 4 as libc::c_int
            | (1 as libc::c_int) << 3 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_isprint(mut c: libc::c_int) -> libc::c_int {
    if c < 0 as libc::c_int || c >= 0x80 as libc::c_int {
        return 0 as libc::c_int;
    }
    return ascii[c as usize] as libc::c_int
        & ((1 as libc::c_int) << 2 as libc::c_int
            | (1 as libc::c_int) << 6 as libc::c_int
            | (1 as libc::c_int) << 0 as libc::c_int
            | (1 as libc::c_int) << 1 as libc::c_int
            | (1 as libc::c_int) << 4 as libc::c_int
            | (1 as libc::c_int) << 3 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_isalpha(mut c: libc::c_int) -> libc::c_int {
    if c < 0 as libc::c_int || c >= 0x80 as libc::c_int {
        return 0 as libc::c_int;
    }
    return ascii[c as usize] as libc::c_int
        & ((1 as libc::c_int) << 0 as libc::c_int
            | (1 as libc::c_int) << 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_isupper(mut c: libc::c_int) -> libc::c_int {
    if c < 0 as libc::c_int || c >= 0x80 as libc::c_int {
        return 0 as libc::c_int;
    }
    return ascii[c as usize] as libc::c_int & (1 as libc::c_int) << 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_islower(mut c: libc::c_int) -> libc::c_int {
    if c < 0 as libc::c_int || c >= 0x80 as libc::c_int {
        return 0 as libc::c_int;
    }
    return ascii[c as usize] as libc::c_int & (1 as libc::c_int) << 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_iscntrl(mut c: libc::c_int) -> libc::c_int {
    if c < 0 as libc::c_int || c >= 0x80 as libc::c_int {
        return 0 as libc::c_int;
    }
    return ascii[c as usize] as libc::c_int & (1 as libc::c_int) << 5 as libc::c_int;
}
