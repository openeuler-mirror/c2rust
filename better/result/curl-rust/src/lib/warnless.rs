
pub type __ssize_t = i64;
pub type ssize_t = i64;
pub type size_t = u64;
pub type curl_off_t = i64;
#[no_mangle]
pub extern "C" fn curlx_ultous(mut ulnum: u64) -> u16 {
    return (ulnum & !(0 as i32) as u16 as u64) as u16;
}
#[no_mangle]
pub extern "C" fn curlx_ultouc(mut ulnum: u64) -> u8 {
    return (ulnum & !(0 as i32) as u8 as u64) as u8;
}
#[no_mangle]
pub extern "C" fn curlx_uztoso(mut uznum: u64) -> i64 {
    return (uznum & !(0 as i32) as u64 >> 1 as i32) as curl_off_t;
}
#[no_mangle]
pub extern "C" fn curlx_uztosi(mut uznum: u64) -> i32 {
    return (uznum & (!(0 as i32) as u32 >> 1 as i32) as size_t) as i32;
}
#[no_mangle]
pub extern "C" fn curlx_uztoul(mut uznum: u64) -> u64 {
    return uznum & !(0 as i32) as u64;
}
#[no_mangle]
pub extern "C" fn curlx_uztoui(mut uznum: u64) -> u32 {
    return (uznum & !(0 as i32) as u32 as size_t) as u32;
}
#[no_mangle]
pub extern "C" fn curlx_sltosi(mut slnum: i64) -> i32 {
    return (slnum & (!(0 as i32) as u32 >> 1 as i32) as i64) as i32;
}
#[no_mangle]
pub extern "C" fn curlx_sltoui(mut slnum: i64) -> u32 {
    return (slnum & !(0 as i32) as u32 as i64) as u32;
}
#[no_mangle]
pub extern "C" fn curlx_sltous(mut slnum: i64) -> u16 {
    return (slnum & !(0 as i32) as u16 as i64) as u16;
}
#[no_mangle]
pub extern "C" fn curlx_uztosz(mut uznum: u64) -> i64 {
    return (uznum & !(0 as i32) as size_t >> 1 as i32) as ssize_t;
}
#[no_mangle]
pub extern "C" fn curlx_sotouz(mut sonum: i64) -> u64 {
    return (sonum & !(0 as i32) as size_t as curl_off_t) as size_t;
}
#[no_mangle]
pub extern "C" fn curlx_sztosi(mut sznum: i64) -> i32 {
    return (sznum & (!(0 as i32) as u32 >> 1 as i32) as ssize_t) as i32;
}
#[no_mangle]
pub extern "C" fn curlx_uitous(mut uinum: u32) -> u16 {
    return (uinum & !(0 as i32) as u16 as u32) as u16;
}
#[no_mangle]
pub extern "C" fn curlx_sitouz(mut sinum: i32) -> u64 {
    return sinum as size_t;
}

