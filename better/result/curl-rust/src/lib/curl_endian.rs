
#[no_mangle]
pub extern "C" fn Curl_read16_le(mut buf: *const u8) -> u16 {
    return ((unsafe { *buf.offset(0 as i32 as isize) }) as u16 as i32
        | ((unsafe { *buf.offset(1 as i32 as isize) }) as u16 as i32) << 8 as i32) as u16;
}
#[no_mangle]
pub extern "C" fn Curl_read32_le(mut buf: *const u8) -> u32 {
    return (unsafe { *buf.offset(0 as i32 as isize) }) as u32
        | ((unsafe { *buf.offset(1 as i32 as isize) }) as u32) << 8 as i32
        | ((unsafe { *buf.offset(2 as i32 as isize) }) as u32) << 16 as i32
        | ((unsafe { *buf.offset(3 as i32 as isize) }) as u32) << 24 as i32;
}
#[no_mangle]
pub extern "C" fn Curl_read16_be(mut buf: *const u8) -> u16 {
    return (((unsafe { *buf.offset(0 as i32 as isize) }) as u16 as i32) << 8 as i32
        | (unsafe { *buf.offset(1 as i32 as isize) }) as u16 as i32) as u16;
}

