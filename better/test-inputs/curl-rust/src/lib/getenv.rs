use ::libc;
extern "C" {
    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    static mut Curl_cstrdup: curl_strdup_callback;
}
pub type curl_strdup_callback = Option::<
    unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
>;
unsafe extern "C" fn GetEnv(mut variable: *const libc::c_char) -> *mut libc::c_char {
    let mut env: *mut libc::c_char = getenv(variable);
    return if !env.is_null()
        && *env.offset(0 as libc::c_int as isize) as libc::c_int != 0
    {
        Curl_cstrdup.expect("non-null function pointer")(env)
    } else {
        0 as *mut libc::c_char
    };
}
#[no_mangle]
pub unsafe extern "C" fn curl_getenv(mut v: *const libc::c_char) -> *mut libc::c_char {
    return GetEnv(v);
}
