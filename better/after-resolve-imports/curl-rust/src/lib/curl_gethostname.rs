use ::libc;
extern "C" {
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn gethostname(__name: *mut i8, __len: size_t) -> i32;
}
pub type size_t = crate::src::lib::altsvc::size_t;
#[no_mangle]
pub unsafe extern "C" fn Curl_gethostname(
    name: *mut i8,
    mut namelen: size_t,
) -> i32 {
    let mut err: i32 = 0;
    let mut dot: *mut i8 = 0 as *mut i8;
    *name.offset(0 as i32 as isize) = '\u{0}' as i32 as i8;
    err = gethostname(name, namelen);
    *name
        .offset(
            namelen.wrapping_sub(1 as i32 as u64) as isize,
        ) = '\u{0}' as i32 as i8;
    if err != 0 {
        return err;
    }
    dot = strchr(name, '.' as i32);
    if !dot.is_null() {
        *dot = '\u{0}' as i32 as i8;
    }
    return 0 as i32;
}
