
extern "C" {
    fn __errno_location() -> *mut i32;
    fn Curl_isspace(c: i32) -> i32;
    fn strtol(_: *const i8, _: *mut *mut i8, _: i32) -> i64;
}
pub type curl_off_t = i64;
pub type CURLofft = u32;
pub const CURL_OFFT_INVAL: CURLofft = 2;
pub const CURL_OFFT_FLOW: CURLofft = 1;
pub const CURL_OFFT_OK: CURLofft = 0;
#[no_mangle]
pub extern "C" fn curlx_strtoofft(
    mut str: *const i8,
    mut endp: *mut *mut i8,
    mut base: i32,
    mut num: *mut curl_off_t,
) -> CURLofft {
    let mut end: *mut i8 = 0 as *mut i8;
    let mut number: curl_off_t = 0;
    (unsafe { *__errno_location() = 0 as i32 });
    (unsafe { *num = 0 as i32 as curl_off_t });
    while (unsafe { *str }) as i32 != 0 && (unsafe { Curl_isspace(*str as u8 as i32) }) != 0 {
        str = unsafe { str.offset(1) };
    }
    if '-' as i32 == (unsafe { *str }) as i32 {
        if !endp.is_null() {
            (unsafe { *endp = str as *mut i8 });
        }
        return CURL_OFFT_INVAL;
    }
    number = unsafe { strtol(str, &mut end, base) };
    if !endp.is_null() {
        (unsafe { *endp = end });
    }
    if (unsafe { *__errno_location() }) == 34 as i32 {
        return CURL_OFFT_FLOW;
    } else {
        if str == end as *const i8 {
            return CURL_OFFT_INVAL;
        }
    }
    (unsafe { *num = number });
    return CURL_OFFT_OK;
}
