use ::libc;
extern "C" {
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn strcpy(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    
    
}
pub use crate::json_util::json_parse_int64;
pub use crate::json_util::json_parse_uint64;
pub use crate::json_object::__int64_t;
pub use crate::json_object::__uint64_t;
pub use crate::json_object::int64_t;
pub use crate::json_object::uint64_t;
#[no_mangle]
pub unsafe extern "C" fn checkit(mut buf: *const libc::c_char) {
    let mut cint64: int64_t = -(666 as libc::c_int) as int64_t;
    let mut retval: libc::c_int = json_parse_int64(buf, &mut cint64);
    printf(
        b"buf=%s parseit=%d, value=%ld \n\0" as *const u8 as *const libc::c_char,
        buf,
        retval,
        cint64,
    );
}
#[no_mangle]
pub unsafe extern "C" fn checkit_uint(mut buf: *const libc::c_char) {
    let mut cuint64: uint64_t = 666 as libc::c_int as uint64_t;
    let mut retval: libc::c_int = json_parse_uint64(buf, &mut cuint64);
    printf(
        b"buf=%s parseit=%d, value=%lu \n\0" as *const u8 as *const libc::c_char,
        buf,
        retval,
        cuint64,
    );
}
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut buf: [libc::c_char; 100] = [0; 100];
    printf(
        b"==========json_parse_int64() test===========\n\0" as *const u8
            as *const libc::c_char,
    );
    checkit(b"x\0" as *const u8 as *const libc::c_char);
    checkit(b"0\0" as *const u8 as *const libc::c_char);
    checkit(b"-0\0" as *const u8 as *const libc::c_char);
    checkit(b"00000000\0" as *const u8 as *const libc::c_char);
    checkit(b"-00000000\0" as *const u8 as *const libc::c_char);
    checkit(b"1\0" as *const u8 as *const libc::c_char);
    strcpy(buf.as_mut_ptr(), b"2147483647\0" as *const u8 as *const libc::c_char);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"-1\0" as *const u8 as *const libc::c_char);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"   -1\0" as *const u8 as *const libc::c_char);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"00001234\0" as *const u8 as *const libc::c_char);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"0001234x\0" as *const u8 as *const libc::c_char);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"-00001234\0" as *const u8 as *const libc::c_char);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"-00001234x\0" as *const u8 as *const libc::c_char);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"4294967295\0" as *const u8 as *const libc::c_char);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"4294967296\0" as *const u8 as *const libc::c_char);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"21474836470\0" as *const u8 as *const libc::c_char);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"31474836470\0" as *const u8 as *const libc::c_char);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"-2147483647\0" as *const u8 as *const libc::c_char);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"-2147483648\0" as *const u8 as *const libc::c_char);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"-2147483649\0" as *const u8 as *const libc::c_char);
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"-21474836480\0" as *const u8 as *const libc::c_char);
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"9223372036854775806\0" as *const u8 as *const libc::c_char,
    );
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"9223372036854775807\0" as *const u8 as *const libc::c_char,
    );
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"9223372036854775808\0" as *const u8 as *const libc::c_char,
    );
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"-9223372036854775808\0" as *const u8 as *const libc::c_char,
    );
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"-9223372036854775809\0" as *const u8 as *const libc::c_char,
    );
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"18446744073709551614\0" as *const u8 as *const libc::c_char,
    );
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"18446744073709551615\0" as *const u8 as *const libc::c_char,
    );
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"18446744073709551616\0" as *const u8 as *const libc::c_char,
    );
    checkit(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"-18446744073709551616\0" as *const u8 as *const libc::c_char,
    );
    checkit(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"123\0" as *const u8 as *const libc::c_char);
    checkit(buf.as_mut_ptr());
    printf(
        b"\n==========json_parse_uint64() test===========\n\0" as *const u8
            as *const libc::c_char,
    );
    checkit_uint(b"x\0" as *const u8 as *const libc::c_char);
    checkit_uint(b"0\0" as *const u8 as *const libc::c_char);
    checkit_uint(b"-0\0" as *const u8 as *const libc::c_char);
    checkit_uint(b"00000000\0" as *const u8 as *const libc::c_char);
    checkit_uint(b"-00000000\0" as *const u8 as *const libc::c_char);
    checkit_uint(b"1\0" as *const u8 as *const libc::c_char);
    strcpy(buf.as_mut_ptr(), b"2147483647\0" as *const u8 as *const libc::c_char);
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"-1\0" as *const u8 as *const libc::c_char);
    checkit_uint(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"-9223372036854775808\0" as *const u8 as *const libc::c_char,
    );
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"   1\0" as *const u8 as *const libc::c_char);
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"00001234\0" as *const u8 as *const libc::c_char);
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"0001234x\0" as *const u8 as *const libc::c_char);
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"4294967295\0" as *const u8 as *const libc::c_char);
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"4294967296\0" as *const u8 as *const libc::c_char);
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"21474836470\0" as *const u8 as *const libc::c_char);
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"31474836470\0" as *const u8 as *const libc::c_char);
    checkit_uint(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"9223372036854775806\0" as *const u8 as *const libc::c_char,
    );
    checkit_uint(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"9223372036854775807\0" as *const u8 as *const libc::c_char,
    );
    checkit_uint(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"9223372036854775808\0" as *const u8 as *const libc::c_char,
    );
    checkit_uint(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"18446744073709551614\0" as *const u8 as *const libc::c_char,
    );
    checkit_uint(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"18446744073709551615\0" as *const u8 as *const libc::c_char,
    );
    checkit_uint(buf.as_mut_ptr());
    strcpy(
        buf.as_mut_ptr(),
        b"18446744073709551616\0" as *const u8 as *const libc::c_char,
    );
    checkit_uint(buf.as_mut_ptr());
    strcpy(buf.as_mut_ptr(), b"123\0" as *const u8 as *const libc::c_char);
    checkit_uint(buf.as_mut_ptr());
    return 0 as libc::c_int;
}
pub fn main() {
    let mut args: Vec::<*mut libc::c_char> = Vec::new();
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
                (args.len() - 1) as libc::c_int,
                args.as_mut_ptr() as *mut *mut libc::c_char,
            ) as i32,
        )
    }
}
