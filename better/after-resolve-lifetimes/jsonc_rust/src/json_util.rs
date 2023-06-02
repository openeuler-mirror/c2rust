use ::libc;
extern "C" {
    
    
    
    
    
    
    fn __errno_location() -> * mut i32;
    fn strlen(_: * const i8) -> u64;
    fn vsnprintf(
        _: * mut i8,
        _: u64,
        _: * const i8,
        _: core::ffi::VaList,
    ) -> i32;
    fn strtod(_: * const i8, _: * mut * mut i8) -> f64;
    fn strtoll(
        _: * const i8,
        _: * mut * mut i8,
        _: i32,
    ) -> i64;
    fn strtoull(
        _: * const i8,
        _: * mut * mut i8,
        _: i32,
    ) -> u64;
    fn open(__file: * const i8, __oflag: i32, _: ...) -> i32;
    fn close(__fd: i32) -> i32;
    fn read(__fd: i32, __buf: * mut core::ffi::c_void, __nbytes: u64) -> i64;
    fn write(__fd: i32, __buf: * const core::ffi::c_void, __n: u64) -> i64;
    
    
    
    
    
}
pub use crate::src::json_object::json_object_to_json_string_ext;
pub use crate::src::json_tokener::json_tokener_error_desc;
pub use crate::src::json_tokener::json_tokener_free;
pub use crate::src::json_tokener::json_tokener_get_error;
pub use crate::src::json_tokener::json_tokener_new_ex;
pub use crate::src::json_tokener::json_tokener_parse_ex;
pub use crate::src::printbuf::printbuf_free;
pub use crate::src::printbuf::printbuf_memappend;
pub use crate::src::printbuf::printbuf_new;
pub use crate::src::strerror_override::_json_c_strerror;
pub use crate::src::json_object::json_object;
pub type __builtin_va_list = [crate::src::debug::__va_list_tag; 1];
// #[derive(Copy, Clone)]

pub type __va_list_tag = crate::src::debug::__va_list_tag;
pub type __int64_t = i64;
pub type __uint64_t = u64;
pub type __ssize_t = i64;
pub type int64_t = i64;
pub type uint64_t = u64;
// #[derive(Copy, Clone)]

pub type printbuf = crate::src::apps::json_parse::printbuf;
pub type json_type = u32;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
pub type size_t = u64;
pub type va_list = [crate::src::debug::__va_list_tag; 1];
pub type ssize_t = i64;
pub type json_tokener_error = u32;
pub const json_tokener_error_size: json_tokener_error = 15;
pub const json_tokener_error_parse_utf8_string: json_tokener_error = 14;
pub const json_tokener_error_parse_comment: json_tokener_error = 13;
pub const json_tokener_error_parse_string: json_tokener_error = 12;
pub const json_tokener_error_parse_object_value_sep: json_tokener_error = 11;
pub const json_tokener_error_parse_object_key_sep: json_tokener_error = 10;
pub const json_tokener_error_parse_object_key_name: json_tokener_error = 9;
pub const json_tokener_error_parse_array: json_tokener_error = 8;
pub const json_tokener_error_parse_number: json_tokener_error = 7;
pub const json_tokener_error_parse_boolean: json_tokener_error = 6;
pub const json_tokener_error_parse_null: json_tokener_error = 5;
pub const json_tokener_error_parse_unexpected: json_tokener_error = 4;
pub const json_tokener_error_parse_eof: json_tokener_error = 3;
pub const json_tokener_error_depth: json_tokener_error = 2;
pub const json_tokener_continue: json_tokener_error = 1;
pub const json_tokener_success: json_tokener_error = 0;
pub type json_tokener_state = u32;
pub const json_tokener_state_inf: json_tokener_state = 26;
pub const json_tokener_state_object_field_start_after_sep: json_tokener_state = 25;
pub const json_tokener_state_array_after_sep: json_tokener_state = 24;
pub const json_tokener_state_object_sep: json_tokener_state = 23;
pub const json_tokener_state_object_value_add: json_tokener_state = 22;
pub const json_tokener_state_object_value: json_tokener_state = 21;
pub const json_tokener_state_object_field_end: json_tokener_state = 20;
pub const json_tokener_state_object_field: json_tokener_state = 19;
pub const json_tokener_state_object_field_start: json_tokener_state = 18;
pub const json_tokener_state_array_sep: json_tokener_state = 17;
pub const json_tokener_state_array_add: json_tokener_state = 16;
pub const json_tokener_state_array: json_tokener_state = 15;
pub const json_tokener_state_number: json_tokener_state = 14;
pub const json_tokener_state_boolean: json_tokener_state = 13;
pub const json_tokener_state_escape_unicode_need_u: json_tokener_state = 12;
pub const json_tokener_state_escape_unicode_need_escape: json_tokener_state = 11;
pub const json_tokener_state_escape_unicode: json_tokener_state = 10;
pub const json_tokener_state_string_escape: json_tokener_state = 9;
pub const json_tokener_state_string: json_tokener_state = 8;
pub const json_tokener_state_comment_end: json_tokener_state = 7;
pub const json_tokener_state_comment_eol: json_tokener_state = 6;
pub const json_tokener_state_comment: json_tokener_state = 5;
pub const json_tokener_state_comment_start: json_tokener_state = 4;
pub const json_tokener_state_null: json_tokener_state = 3;
pub const json_tokener_state_finish: json_tokener_state = 2;
pub const json_tokener_state_start: json_tokener_state = 1;
pub const json_tokener_state_eatws: json_tokener_state = 0;
// #[derive(Copy, Clone)]

pub type json_tokener_srec<'a> = crate::src::apps::json_parse::json_tokener_srec<'a>;
// #[derive(Copy, Clone)]

pub type json_tokener<'a> = crate::src::apps::json_parse::json_tokener<'a>;
static mut _last_err: [i8; 256] = unsafe {
    *core::intrinsics::transmute::<&'_ [u8; 256], &'_ mut [i8; 256]>(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    )
};
#[no_mangle]
pub unsafe extern "C" fn json_util_get_last_err() -> * const i8 {
    if _last_err[0 as i32 as usize] as i32 == '\u{0}' as i32 {
        return 0 as *const i8;
    }
    return _last_err.as_mut_ptr();
}
#[no_mangle]
pub unsafe extern "C" fn _json_c_set_last_err(
    mut err_fmt: * const i8,
    mut args: ...
) {
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    vsnprintf(
        _last_err.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 256]>() as u64,
        err_fmt,
        ap.as_va_list(),
    );
}
#[no_mangle]
pub unsafe extern "C" fn json_object_from_fd(mut fd: i32) -> * mut crate::src::json_object::json_object {
    return json_object_from_fd_ex(fd, -(1 as i32));
}
#[no_mangle]
pub unsafe extern "C" fn json_object_from_fd_ex(
    mut fd: i32,
    mut in_depth: i32,
) -> * mut crate::src::json_object::json_object {
    let mut pb: * mut crate::src::apps::json_parse::printbuf = 0 as *mut printbuf;
    let mut obj: * mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut buf: [i8; 4096] = [0; 4096];
    let mut ret: i64 = 0;
    let mut depth: i32 = 32 as i32;
    let mut tok: * mut crate::src::apps::json_parse::json_tokener<'_> = 0 as *mut json_tokener;
    pb = printbuf_new();
    if pb.is_null() {
        _json_c_set_last_err(
            b"json_object_from_fd_ex: printbuf_new failed\n\0" as *const u8
                as *const i8,
        );
        return 0 as *mut json_object;
    }
    if in_depth != -(1 as i32) {
        depth = in_depth;
    }
    tok = json_tokener_new_ex(depth);
    if tok.is_null() {
        _json_c_set_last_err(
            b"json_object_from_fd_ex: unable to allocate json_tokener(depth=%d): %s\n\0"
                as *const u8 as *const i8,
            depth,
            _json_c_strerror(*__errno_location()),
        );
        printbuf_free(pb);
        return 0 as *mut json_object;
    }
    loop {
        ret = read(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            ::std::mem::size_of::<[i8; 4096]>() as u64,
        );
        if !(ret > 0 as i32 as i64) {
            break;
        }
        if printbuf_memappend(pb, buf.as_mut_ptr(), ret as i32)
            < 0 as i32
        {
            _json_c_set_last_err(
                b"json_object_from_fd_ex: failed to printbuf_memappend after reading %d+%d bytes: %s\0"
                    as *const u8 as *const i8,
                (*pb).bpos,
                ret as i32,
                _json_c_strerror(*__errno_location()),
            );
            json_tokener_free(tok);
            printbuf_free(pb);
            return 0 as *mut json_object;
        }
    }
    if ret < 0 as i32 as i64 {
        _json_c_set_last_err(
            b"json_object_from_fd_ex: error reading fd %d: %s\n\0" as *const u8
                as *const i8,
            fd,
            _json_c_strerror(*__errno_location()),
        );
        json_tokener_free(tok);
        printbuf_free(pb);
        return 0 as *mut json_object;
    }
    obj = json_tokener_parse_ex(tok, (*pb).buf, (*pb).bpos);
    if obj.is_null() {
        _json_c_set_last_err(
            b"json_tokener_parse_ex failed: %s\n\0" as *const u8 as *const i8,
            json_tokener_error_desc(json_tokener_get_error(tok)),
        );
    }
    json_tokener_free(tok);
    printbuf_free(pb);
    return obj;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_from_file(
    mut filename: * const i8,
) -> * mut crate::src::json_object::json_object {
    let mut obj: * mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut fd: i32 = 0;
    fd = open(filename, 0 as i32);
    if fd < 0 as i32 {
        _json_c_set_last_err(
            b"json_object_from_file: error opening file %s: %s\n\0" as *const u8
                as *const i8,
            filename,
            _json_c_strerror(*__errno_location()),
        );
        return 0 as *mut json_object;
    }
    obj = json_object_from_fd(fd);
    close(fd);
    return obj;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_to_file_ext(
    mut filename: * const i8,
    mut obj: * mut crate::src::json_object::json_object,
    mut flags: i32,
) -> i32 {
    let mut fd: i32 = 0;
    let mut ret: i32 = 0;
    let mut saved_errno: i32 = 0;
    if obj.is_null() {
        _json_c_set_last_err(
            b"json_object_to_file_ext: object is null\n\0" as *const u8
                as *const i8,
        );
        return -(1 as i32);
    }
    fd = open(
        filename,
        0o1 as i32 | 0o1000 as i32 | 0o100 as i32,
        0o644 as i32,
    );
    if fd < 0 as i32 {
        _json_c_set_last_err(
            b"json_object_to_file_ext: error opening file %s: %s\n\0" as *const u8
                as *const i8,
            filename,
            _json_c_strerror(*__errno_location()),
        );
        return -(1 as i32);
    }
    ret = _json_object_to_fd(fd, obj, flags, filename);
    saved_errno = *__errno_location();
    close(fd);
    *__errno_location() = saved_errno;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_to_fd(
    mut fd: i32,
    mut obj: * mut crate::src::json_object::json_object,
    mut flags: i32,
) -> i32 {
    if obj.is_null() {
        _json_c_set_last_err(
            b"json_object_to_fd: object is null\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    return _json_object_to_fd(fd, obj, flags, 0 as *const i8);
}
unsafe extern "C" fn _json_object_to_fd(
    mut fd: i32,
    mut obj: * mut crate::src::json_object::json_object,
    mut flags: i32,
    mut filename: * const i8,
) -> i32 {
    let mut ret: i64 = 0;
    let mut json_str: * const i8 = 0 as *const i8;
    let mut wpos: u64 = 0;
    let mut wsize: u64 = 0;
    filename = if !filename.is_null() {
        filename
    } else {
        b"(fd)\0" as *const u8 as *const i8
    };
    json_str = json_object_to_json_string_ext(obj, flags);
    if json_str.is_null() {
        return -(1 as i32);
    }
    wsize = strlen(json_str);
    wpos = 0 as i32 as size_t;
    while wpos < wsize {
        ret = write(
            fd,
            json_str.offset(wpos as isize) as *const libc::c_void,
            wsize.wrapping_sub(wpos),
        );
        if ret < 0 as i32 as i64 {
            _json_c_set_last_err(
                b"json_object_to_fd: error writing file %s: %s\n\0" as *const u8
                    as *const i8,
                filename,
                _json_c_strerror(*__errno_location()),
            );
            return -(1 as i32);
        }
        wpos = (wpos as u64).wrapping_add(ret as size_t) as size_t as size_t;
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_to_file(
    mut filename: * const i8,
    mut obj: * mut crate::src::json_object::json_object,
) -> i32 {
    return json_object_to_file_ext(filename, obj, 0 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn json_parse_double<'a1>(
    mut buf: * const i8,
    mut retval: Option<&'a1 mut f64>,
) -> i32 {
    let mut end: * mut i8 = 0 as *mut i8;
    *(borrow_mut(&mut retval)).unwrap() = strtod(buf, &mut end);
    return if end == buf as *mut i8 {
        1 as i32
    } else {
        0 as i32
    };
}
#[no_mangle]
pub unsafe extern "C" fn json_parse_int64<'a1>(
    mut buf: * const i8,
    mut retval: Option<&'a1 mut i64>,
) -> i32 {
    let mut end: * mut i8 = 0 as *mut i8;
    let mut val: i64 = 0;
    *__errno_location() = 0 as i32;
    val = strtoll(buf, &mut end, 10 as i32) as int64_t;
    if end != buf as *mut i8 {
        *(borrow_mut(&mut retval)).unwrap() = val;
    }
    if val == 0 as i32 as i64 && *__errno_location() != 0 as i32
        || end == buf as *mut i8
    {
        *__errno_location() = 22 as i32;
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn json_parse_uint64<'a1>(
    mut buf: * const i8,
    mut retval: Option<&'a1 mut u64>,
) -> i32 {
    let mut end: * mut i8 = 0 as *mut i8;
    let mut val: u64 = 0;
    *__errno_location() = 0 as i32;
    while *buf as i32 == ' ' as i32 {
        buf = buf.offset(1);
    }
    if *buf as i32 == '-' as i32 {
        return 1 as i32;
    }
    val = strtoull(buf, &mut end, 10 as i32) as uint64_t;
    if end != buf as *mut i8 {
        *(borrow_mut(&mut retval)).unwrap() = val;
    }
    if val == 0 as i32 as u64
        && *__errno_location() != 0 as i32 || end == buf as *mut i8
    {
        *__errno_location() = 22 as i32;
        return 1 as i32;
    }
    return 0 as i32;
}
static mut json_type_name: [* const i8; 7] = [
    b"null\0" as *const u8 as *const i8,
    b"boolean\0" as *const u8 as *const i8,
    b"double\0" as *const u8 as *const i8,
    b"int\0" as *const u8 as *const i8,
    b"object\0" as *const u8 as *const i8,
    b"array\0" as *const u8 as *const i8,
    b"string\0" as *const u8 as *const i8,
];
#[no_mangle]
pub unsafe extern "C" fn json_type_to_name(
    mut o_type: u32,
) -> * const i8 {
    let mut o_type_int: i32 = o_type as i32;
    if o_type_int < 0 as i32
        || o_type_int
            >= (::std::mem::size_of::<[*const i8; 7]>() as u64)
                .wrapping_div(
                    ::std::mem::size_of::<*const i8>() as u64,
                ) as i32
    {
        _json_c_set_last_err(
            b"json_type_to_name: type %d is out of range [0,%u]\n\0" as *const u8
                as *const i8,
            o_type as u32,
            (::std::mem::size_of::<[*const i8; 7]>() as u64)
                .wrapping_div(
                    ::std::mem::size_of::<*const i8>() as u64,
                ) as u32,
        );
        return 0 as *const i8;
    }
    return json_type_name[o_type as usize];
}
use crate::laertes_rt::*;
