use ::libc;
static mut ascii: [u8; 128] = [
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32 | (1 as i32) << 3 as i32)
        as u8,
    ((1 as i32) << 5 as i32 | (1 as i32) << 3 as i32)
        as u8,
    ((1 as i32) << 5 as i32 | (1 as i32) << 3 as i32)
        as u8,
    ((1 as i32) << 5 as i32 | (1 as i32) << 3 as i32)
        as u8,
    ((1 as i32) << 5 as i32 | (1 as i32) << 3 as i32)
        as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
    ((1 as i32) << 3 as i32 | (1 as i32) << 7 as i32)
        as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 2 as i32) as u8,
    ((1 as i32) << 2 as i32) as u8,
    ((1 as i32) << 2 as i32) as u8,
    ((1 as i32) << 2 as i32) as u8,
    ((1 as i32) << 2 as i32) as u8,
    ((1 as i32) << 2 as i32) as u8,
    ((1 as i32) << 2 as i32) as u8,
    ((1 as i32) << 2 as i32) as u8,
    ((1 as i32) << 2 as i32) as u8,
    ((1 as i32) << 2 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 0 as i32 | (1 as i32) << 6 as i32)
        as u8,
    ((1 as i32) << 0 as i32 | (1 as i32) << 6 as i32)
        as u8,
    ((1 as i32) << 0 as i32 | (1 as i32) << 6 as i32)
        as u8,
    ((1 as i32) << 0 as i32 | (1 as i32) << 6 as i32)
        as u8,
    ((1 as i32) << 0 as i32 | (1 as i32) << 6 as i32)
        as u8,
    ((1 as i32) << 0 as i32 | (1 as i32) << 6 as i32)
        as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 0 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 1 as i32 | (1 as i32) << 6 as i32)
        as u8,
    ((1 as i32) << 1 as i32 | (1 as i32) << 6 as i32)
        as u8,
    ((1 as i32) << 1 as i32 | (1 as i32) << 6 as i32)
        as u8,
    ((1 as i32) << 1 as i32 | (1 as i32) << 6 as i32)
        as u8,
    ((1 as i32) << 1 as i32 | (1 as i32) << 6 as i32)
        as u8,
    ((1 as i32) << 1 as i32 | (1 as i32) << 6 as i32)
        as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 1 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 4 as i32) as u8,
    ((1 as i32) << 5 as i32) as u8,
];
#[no_mangle]
pub unsafe extern "C" fn Curl_isspace(mut c: i32) -> i32 {
    if c < 0 as i32 || c >= 0x80 as i32 {
        return 0 as i32;
    }
    return ascii[c as usize] as i32 & (1 as i32) << 3 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_isdigit(mut c: i32) -> i32 {
    if c < 0 as i32 || c >= 0x80 as i32 {
        return 0 as i32;
    }
    return ascii[c as usize] as i32 & (1 as i32) << 2 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_isalnum(mut c: i32) -> i32 {
    if c < 0 as i32 || c >= 0x80 as i32 {
        return 0 as i32;
    }
    return ascii[c as usize] as i32
        & ((1 as i32) << 2 as i32
            | (1 as i32) << 0 as i32
            | (1 as i32) << 1 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_isxdigit(mut c: i32) -> i32 {
    if c < 0 as i32 || c >= 0x80 as i32 {
        return 0 as i32;
    }
    return ascii[c as usize] as i32
        & ((1 as i32) << 2 as i32
            | (1 as i32) << 6 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_isgraph(mut c: i32) -> i32 {
    if c < 0 as i32 || c >= 0x80 as i32 || c == ' ' as i32 {
        return 0 as i32;
    }
    return ascii[c as usize] as i32
        & ((1 as i32) << 2 as i32
            | (1 as i32) << 6 as i32
            | (1 as i32) << 0 as i32
            | (1 as i32) << 1 as i32
            | (1 as i32) << 4 as i32
            | (1 as i32) << 3 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_isprint(mut c: i32) -> i32 {
    if c < 0 as i32 || c >= 0x80 as i32 {
        return 0 as i32;
    }
    return ascii[c as usize] as i32
        & ((1 as i32) << 2 as i32
            | (1 as i32) << 6 as i32
            | (1 as i32) << 0 as i32
            | (1 as i32) << 1 as i32
            | (1 as i32) << 4 as i32
            | (1 as i32) << 3 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_isalpha(mut c: i32) -> i32 {
    if c < 0 as i32 || c >= 0x80 as i32 {
        return 0 as i32;
    }
    return ascii[c as usize] as i32
        & ((1 as i32) << 0 as i32
            | (1 as i32) << 1 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_isupper(mut c: i32) -> i32 {
    if c < 0 as i32 || c >= 0x80 as i32 {
        return 0 as i32;
    }
    return ascii[c as usize] as i32 & (1 as i32) << 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_islower(mut c: i32) -> i32 {
    if c < 0 as i32 || c >= 0x80 as i32 {
        return 0 as i32;
    }
    return ascii[c as usize] as i32 & (1 as i32) << 1 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_iscntrl(mut c: i32) -> i32 {
    if c < 0 as i32 || c >= 0x80 as i32 {
        return 0 as i32;
    }
    return ascii[c as usize] as i32 & (1 as i32) << 5 as i32;
}
use crate::laertes_rt::*;
