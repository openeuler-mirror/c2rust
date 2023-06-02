
extern "C" {
    fn rename(__old: *const i8, __new: *const i8) -> i32;
}
#[no_mangle]
pub extern "C" fn Curl_rename(mut oldpath: *const i8, mut newpath: *const i8) -> i32 {
    if (unsafe { rename(oldpath, newpath) }) != 0 {
        return 1 as i32;
    }
    return 0 as i32;
}
