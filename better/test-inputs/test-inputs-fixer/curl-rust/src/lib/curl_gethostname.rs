
extern "C" {
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn gethostname(__name: *mut i8, __len: size_t) -> i32;
}
pub type size_t = u64;
#[no_mangle]
pub extern "C" fn Curl_gethostname(name: *mut i8, mut namelen: size_t) -> i32 {
    let mut err: i32 = 0;
    let mut dot: *mut i8 = 0 as *mut i8;
    (unsafe { *name.offset(0 as i32 as isize) = '\u{0}' as i32 as i8 });
    err = unsafe { gethostname(name, namelen) };
    (unsafe { *name.offset(namelen.wrapping_sub(1 as i32 as u64) as isize) = '\u{0}' as i32 as i8 });
    if err != 0 {
        return err;
    }
    dot = unsafe { strchr(name, '.' as i32) };
    if !dot.is_null() {
        (unsafe { *dot = '\u{0}' as i32 as i8 });
    }
    return 0 as i32;
}
