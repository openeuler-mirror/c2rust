use ::libc;
#[no_mangle]
pub unsafe extern "C" fn Curl_read16_le(
    mut buf: * const u8,
) -> u16 {
    return (*buf.offset(0 as i32 as isize) as u16 as i32
        | (*buf.offset(1 as i32 as isize) as u16 as i32)
            << 8 as i32) as u16;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_read32_le(mut buf: * const u8) -> u32 {
    return *buf.offset(0 as i32 as isize) as u32
        | (*buf.offset(1 as i32 as isize) as u32) << 8 as i32
        | (*buf.offset(2 as i32 as isize) as u32) << 16 as i32
        | (*buf.offset(3 as i32 as isize) as u32) << 24 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_read16_be(
    mut buf: * const u8,
) -> u16 {
    return ((*buf.offset(0 as i32 as isize) as u16 as i32)
        << 8 as i32
        | *buf.offset(1 as i32 as isize) as u16 as i32)
        as u16;
}
use crate::laertes_rt::*;
