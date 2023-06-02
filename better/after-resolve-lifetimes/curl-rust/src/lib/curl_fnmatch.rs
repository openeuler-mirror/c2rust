use ::libc;
extern "C" {
    fn fnmatch(
        __pattern: * const i8,
        __name: * const i8,
        __flags: i32,
    ) -> i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_fnmatch(
    mut ptr: * mut core::ffi::c_void,
    mut pattern: * const i8,
    mut string: * const i8,
) -> i32 {
    let mut rc: i32 = 0;
    if pattern.is_null() || string.is_null() {
        return 2 as i32;
    }
    rc = fnmatch(pattern, string, 0 as i32);
    match rc {
        0 => return 0 as i32,
        1 => return 1 as i32,
        _ => return 2 as i32,
    };
}
use crate::laertes_rt::*;
