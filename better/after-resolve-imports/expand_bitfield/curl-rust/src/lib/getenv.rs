use ::libc;
extern "C" {
    fn getenv(__name: *const i8) -> *mut i8;
    
}
pub use crate::src::lib::easy::Curl_cstrdup;
pub type curl_strdup_callback = crate::src::lib::altsvc::curl_strdup_callback;
unsafe extern "C" fn GetEnv(mut variable: *const i8) -> *mut i8 {
    let mut env: *mut i8 = getenv(variable);
    return if !env.is_null()
        && *env.offset(0 as i32 as isize) as i32 != 0
    {
        Curl_cstrdup.expect("non-null function pointer")(env)
    } else {
        0 as *mut i8
    };
}
#[no_mangle]
pub unsafe extern "C" fn curl_getenv(mut v: *const i8) -> *mut i8 {
    return GetEnv(v);
}
