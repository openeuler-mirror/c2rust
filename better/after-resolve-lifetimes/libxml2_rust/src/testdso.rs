use ::libc;
extern "C" {
    fn printf(_: * const i8, _: ...) -> i32;
}
#[no_mangle]
pub unsafe extern "C" fn hello_world() -> i32 {
    printf(b"Success!\n\0" as *const u8 as *const i8);
    return 0 as i32;
}
use crate::laertes_rt::*;
