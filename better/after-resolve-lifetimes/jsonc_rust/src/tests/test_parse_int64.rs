use ::libc;
extern "C" {
    fn printf(_: * const i8, _: ...) -> i32;
    fn strcpy(_: * mut i8, _: * const i8) -> * mut i8;
    
    
}
pub use crate::src::json_util::json_parse_int64;
pub use crate::src::json_util::json_parse_uint64;
pub type __int64_t = i64;
pub type __uint64_t = u64;
pub type int64_t = i64;
pub type uint64_t = u64;
#[no_mangle]
pub unsafe extern "C" fn checkit(mut buf: * const i8) {
    let mut cint64: i64 = -(666 as i32) as int64_t;
    let mut retval: i32 = json_parse_int64(buf, Some(&mut cint64));
    printf(
        b"buf=%s parseit=%d, value=%ld \n\0" as *const u8 as *const i8,
        buf,
        retval,
        cint64,
    );
}
#[no_mangle]
pub unsafe extern "C" fn checkit_uint(mut buf: * const i8) {
    let mut cuint64: u64 = 666 as i32 as uint64_t;
    let mut retval: i32 = json_parse_uint64(buf, Some(&mut cuint64));
    printf(
        b"buf=%s parseit=%d, value=%lu \n\0" as *const u8 as *const i8,
        buf,
        retval,
        cuint64,
    );
}
unsafe fn main_0(
    mut argc: i32,
    mut argv: * mut * mut i8,
) -> i32 {
    let mut buf: [i8; 100] = [0; 100];
    printf(
        b"==========json_parse_int64() test===========\n\0" as *const u8
            as *const i8,
    );
    checkit(b"x\0" as *const u8 as *const i8);
    checkit(b"0\0" as *const u8 as *const i8);
    checkit(b"-0\0" as *const u8 as *const i8);
    checkit(b"00000000\0" as *const u8 as *const i8);
    checkit(b"-00000000\0" as *const u8 as *const i8);
    checkit(b"1\0" as *const u8 as *const i8);
    strcpy(buf.as_mut_ptr(), b"2147483647\0" as *const u8 as *const i8);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"-1\0" as *const u8 as *const i8);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"   -1\0" as *const u8 as *const i8);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"00001234\0" as *const u8 as *const i8);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"0001234x\0" as *const u8 as *const i8);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"-00001234\0" as *const u8 as *const i8);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"-00001234x\0" as *const u8 as *const i8);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"4294967295\0" as *const u8 as *const i8);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"4294967296\0" as *const u8 as *const i8);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"21474836470\0" as *const u8 as *const i8);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"31474836470\0" as *const u8 as *const i8);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"-2147483647\0" as *const u8 as *const i8);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"-2147483648\0" as *const u8 as *const i8);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"-2147483649\0" as *const u8 as *const i8);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"-21474836480\0" as *const u8 as *const i8);
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"9223372036854775806\0" as *const u8 as *const i8,
    );
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"9223372036854775807\0" as *const u8 as *const i8,
    );
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"9223372036854775808\0" as *const u8 as *const i8,
    );
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"-9223372036854775808\0" as *const u8 as *const i8,
    );
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"-9223372036854775809\0" as *const u8 as *const i8,
    );
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"18446744073709551614\0" as *const u8 as *const i8,
    );
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"18446744073709551615\0" as *const u8 as *const i8,
    );
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"18446744073709551616\0" as *const u8 as *const i8,
    );
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"-18446744073709551616\0" as *const u8 as *const i8,
    );
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"123\0" as *const u8 as *const i8);
    checkit(buf.as_mut_ptr());
    printf(
        b"\n==========json_parse_uint64() test===========\n\0" as *const u8
            as *const i8,
    );
    checkit_uint(b"x\0" as *const u8 as *const i8);
    checkit_uint(b"0\0" as *const u8 as *const i8);
    checkit_uint(b"-0\0" as *const u8 as *const i8);
    checkit_uint(b"00000000\0" as *const u8 as *const i8);
    checkit_uint(b"-00000000\0" as *const u8 as *const i8);
    checkit_uint(b"1\0" as *const u8 as *const i8);
    strcpy(buf.as_mut_ptr(), b"2147483647\0" as *const u8 as *const i8);
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"-1\0" as *const u8 as *const i8);
    checkit_uint(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"-9223372036854775808\0" as *const u8 as *const i8,
    );
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"   1\0" as *const u8 as *const i8);
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"00001234\0" as *const u8 as *const i8);
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"0001234x\0" as *const u8 as *const i8);
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"4294967295\0" as *const u8 as *const i8);
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"4294967296\0" as *const u8 as *const i8);
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"21474836470\0" as *const u8 as *const i8);
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"31474836470\0" as *const u8 as *const i8);
    checkit_uint(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"9223372036854775806\0" as *const u8 as *const i8,
    );
    checkit_uint(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"9223372036854775807\0" as *const u8 as *const i8,
    );
    checkit_uint(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"9223372036854775808\0" as *const u8 as *const i8,
    );
    checkit_uint(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"18446744073709551614\0" as *const u8 as *const i8,
    );
    checkit_uint(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"18446744073709551615\0" as *const u8 as *const i8,
    );
    checkit_uint(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"18446744073709551616\0" as *const u8 as *const i8,
    );
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"123\0" as *const u8 as *const i8);
    checkit_uint(buf.as_mut_ptr());
    return 0 as i32;
}
pub fn main() {
    let mut args: Vec::<*mut i8> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::std::ptr::null_mut());
    unsafe {
        ::std::process::exit(
            main_0(
                (args.len() - 1) as i32,
                args.as_mut_ptr() as *mut *mut i8,
            ) as i32,
        )
    }
}
use crate::laertes_rt::*;
