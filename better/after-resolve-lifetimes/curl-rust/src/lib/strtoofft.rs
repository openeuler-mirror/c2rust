use ::libc;
extern "C" {
    fn __errno_location() -> * mut i32;
    
    fn strtol(
        _: * const i8,
        _: * mut * mut i8,
        _: i32,
    ) -> i64;
}
pub use crate::src::lib::curl_ctype::Curl_isspace;
pub type curl_off_t = i64;
pub type CURLofft = u32;
pub const CURL_OFFT_INVAL: CURLofft = 2;
pub const CURL_OFFT_FLOW: CURLofft = 1;
pub const CURL_OFFT_OK: CURLofft = 0;
#[no_mangle]
pub unsafe extern "C" fn curlx_strtoofft<'a1, 'a2>(
    mut str: * const i8,
    mut endp: Option<&'a1 mut * mut i8>,
    mut base: i32,
    mut num: Option<&'a2 mut i64>,
) -> u32 {
    let mut end: * mut i8 = 0 as *mut i8;
    let mut number: i64 = 0;
    *__errno_location() = 0 as i32;
    *(borrow_mut(&mut num)).unwrap() = 0 as i32 as curl_off_t;
    while *str as i32 != 0
        && Curl_isspace(*str as u8 as i32) != 0
    {
        str = str.offset(1);
    }
    if '-' as i32 == *str as i32 {
        if !borrow(& endp).is_none() {
            *(borrow_mut(&mut endp)).unwrap() = str as *mut i8;
        }
        return CURL_OFFT_INVAL;
    }
    number = strtol(str, &mut end, base);
    if !borrow(& endp).is_none() {
        *(borrow_mut(&mut endp)).unwrap() = end;
    }
    if *__errno_location() == 34 as i32 {
        return CURL_OFFT_FLOW
    } else {
        if str == end as *const i8 {
            return CURL_OFFT_INVAL;
        }
    }
    *(borrow_mut(&mut num)).unwrap() = number;
    return CURL_OFFT_OK;
}
use crate::laertes_rt::*;
