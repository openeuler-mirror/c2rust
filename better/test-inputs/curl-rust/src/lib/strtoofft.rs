use ::libc;
extern "C" {
    fn __errno_location() -> *mut libc::c_int;
    fn Curl_isspace(c: libc::c_int) -> libc::c_int;
    fn strtol(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_long;
}
pub type curl_off_t = libc::c_long;
pub type CURLofft = libc::c_uint;
pub const CURL_OFFT_INVAL: CURLofft = 2;
pub const CURL_OFFT_FLOW: CURLofft = 1;
pub const CURL_OFFT_OK: CURLofft = 0;
#[no_mangle]
pub unsafe extern "C" fn curlx_strtoofft(
    mut str: *const libc::c_char,
    mut endp: *mut *mut libc::c_char,
    mut base: libc::c_int,
    mut num: *mut curl_off_t,
) -> CURLofft {
    let mut end: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut number: curl_off_t = 0;
    *__errno_location() = 0 as libc::c_int;
    *num = 0 as libc::c_int as curl_off_t;
    while *str as libc::c_int != 0
        && Curl_isspace(*str as libc::c_uchar as libc::c_int) != 0
    {
        str = str.offset(1);
    }
    if '-' as i32 == *str as libc::c_int {
        if !endp.is_null() {
            *endp = str as *mut libc::c_char;
        }
        return CURL_OFFT_INVAL;
    }
    number = strtol(str, &mut end, base);
    if !endp.is_null() {
        *endp = end;
    }
    if *__errno_location() == 34 as libc::c_int {
        return CURL_OFFT_FLOW
    } else {
        if str == end as *const libc::c_char {
            return CURL_OFFT_INVAL;
        }
    }
    *num = number;
    return CURL_OFFT_OK;
}
