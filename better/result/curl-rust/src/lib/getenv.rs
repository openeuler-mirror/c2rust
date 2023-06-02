
extern "C" {
    fn getenv(__name: *const i8) -> *mut i8;
}
pub use crate::src::lib::easy::Curl_cstrdup;
pub type curl_strdup_callback<'a1, 'a2> =
    Option<unsafe extern "C" fn(_: Option<&'a1 i8>) -> Option<&'a2 mut i8>>;
extern "C" fn GetEnv(mut variable: *const i8) -> *mut i8 {
    let mut env: *mut i8 = unsafe { getenv(variable) };
    return if !env.is_null() && (unsafe { *env.offset(0 as i32 as isize) }) as i32 != 0 {
        unsafe { Curl_cstrdup.expect("non-null function pointer")(env) }
    } else {
        0 as *mut i8
    };
}
#[no_mangle]
pub extern "C" fn curl_getenv(mut v: *const i8) -> *mut i8 {
    return GetEnv(v);
}

