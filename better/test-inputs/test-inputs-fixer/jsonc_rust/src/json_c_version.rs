
#[no_mangle]
pub extern "C" fn json_c_version() -> *const i8 {
    return b"0.16.99\0" as *const u8 as *const i8;
}
#[no_mangle]
pub extern "C" fn json_c_version_num() -> i32 {
    return (0 as i32) << 16 as i32 | (16 as i32) << 8 as i32 | 99 as i32;
}
