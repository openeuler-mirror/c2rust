use ::libc;
extern "C" {
    
    
    
    
    
    
    fn __errno_location() -> *mut libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::std::ffi::VaList,
    ) -> libc::c_int;
    fn strtod(_: *const libc::c_char, _: *mut *mut libc::c_char) -> libc::c_double;
    fn strtoll(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_longlong;
    fn strtoull(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_ulonglong;
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...) -> libc::c_int;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    
    
    
    
    
}
pub use crate::json_object::json_object;
pub use crate::json_object::json_object_to_json_string_ext;
pub use crate::json_tokener::json_tokener_error_desc;
pub use crate::json_tokener::json_tokener_free;
pub use crate::json_tokener::json_tokener_get_error;
pub use crate::json_tokener::json_tokener_new_ex;
pub use crate::json_tokener::json_tokener_parse_ex;
pub use crate::printbuf::printbuf_free;
pub use crate::printbuf::printbuf_memappend;
pub use crate::printbuf::printbuf_new;
pub use crate::strerror_override::_json_c_strerror;
pub use crate::debug::__builtin_va_list;
// #[derive(Copy, Clone)]

pub use crate::debug::__va_list_tag;
pub use crate::json_object::__int64_t;
pub use crate::json_object::__uint64_t;
pub use crate::apps::json_parse::__ssize_t;
pub use crate::json_object::int64_t;
pub use crate::json_object::uint64_t;
// #[derive(Copy, Clone)]

pub use crate::apps::json_parse::printbuf;
pub use crate::json_object::json_type;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
pub use crate::apps::json_parse::size_t;
pub use crate::debug::va_list;
pub use crate::apps::json_parse::ssize_t;
pub use crate::apps::json_parse::json_tokener_error;
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
pub use crate::apps::json_parse::json_tokener_state;
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

pub use crate::apps::json_parse::json_tokener_srec;
// #[derive(Copy, Clone)]

pub use crate::apps::json_parse::json_tokener;
static mut _last_err: [libc::c_char; 256] = unsafe {
    *::std::mem::transmute::<
        &[u8; 256],
        &mut [libc::c_char; 256],
    >(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    )
};
#[no_mangle]
pub unsafe extern "C" fn json_util_get_last_err() -> *const libc::c_char {
    if _last_err[0 as libc::c_int as usize] as libc::c_int == '\u{0}' as i32 {
        return 0 as *const libc::c_char;
    }
    return _last_err.as_mut_ptr();
}
#[no_mangle]
pub unsafe extern "C" fn _json_c_set_last_err(
    mut err_fmt: *const libc::c_char,
    mut args: ...
) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    vsnprintf(
        _last_err.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
        err_fmt,
        ap.as_va_list(),
    );
}
#[no_mangle]
pub unsafe extern "C" fn json_object_from_fd(mut fd: libc::c_int) -> *mut json_object {
    return json_object_from_fd_ex(fd, -(1 as libc::c_int));
}
#[no_mangle]
pub unsafe extern "C" fn json_object_from_fd_ex(
    mut fd: libc::c_int,
    mut in_depth: libc::c_int,
) -> *mut json_object {
    let mut pb: *mut printbuf = 0 as *mut printbuf;
    let mut obj: *mut json_object = 0 as *mut json_object;
    let mut buf: [libc::c_char; 4096] = [0; 4096];
    let mut ret: ssize_t = 0;
    let mut depth: libc::c_int = 32 as libc::c_int;
    let mut tok: *mut json_tokener = 0 as *mut json_tokener;
    pb = printbuf_new();
    if pb.is_null() {
        _json_c_set_last_err(
            b"json_object_from_fd_ex: printbuf_new failed\n\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as *mut json_object;
    }
    if in_depth != -(1 as libc::c_int) {
        depth = in_depth;
    }
    tok = json_tokener_new_ex(depth);
    if tok.is_null() {
        _json_c_set_last_err(
            b"json_object_from_fd_ex: unable to allocate json_tokener(depth=%d): %s\n\0"
                as *const u8 as *const libc::c_char,
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
            ::std::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
        );
        if !(ret > 0 as libc::c_int as libc::c_long) {
            break;
        }
        if printbuf_memappend(pb, buf.as_mut_ptr(), ret as libc::c_int)
            < 0 as libc::c_int
        {
            _json_c_set_last_err(
                b"json_object_from_fd_ex: failed to printbuf_memappend after reading %d+%d bytes: %s\0"
                    as *const u8 as *const libc::c_char,
                (*pb).bpos,
                ret as libc::c_int,
                _json_c_strerror(*__errno_location()),
            );
            json_tokener_free(tok);
            printbuf_free(pb);
            return 0 as *mut json_object;
        }
    }
    if ret < 0 as libc::c_int as libc::c_long {
        _json_c_set_last_err(
            b"json_object_from_fd_ex: error reading fd %d: %s\n\0" as *const u8
                as *const libc::c_char,
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
            b"json_tokener_parse_ex failed: %s\n\0" as *const u8 as *const libc::c_char,
            json_tokener_error_desc(json_tokener_get_error(tok)),
        );
    }
    json_tokener_free(tok);
    printbuf_free(pb);
    return obj;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_from_file(
    mut filename: *const libc::c_char,
) -> *mut json_object {
    let mut obj: *mut json_object = 0 as *mut json_object;
    let mut fd: libc::c_int = 0;
    fd = open(filename, 0 as libc::c_int);
    if fd < 0 as libc::c_int {
        _json_c_set_last_err(
            b"json_object_from_file: error opening file %s: %s\n\0" as *const u8
                as *const libc::c_char,
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
    mut filename: *const libc::c_char,
    mut obj: *mut json_object,
    mut flags: libc::c_int,
) -> libc::c_int {
    let mut fd: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut saved_errno: libc::c_int = 0;
    if obj.is_null() {
        _json_c_set_last_err(
            b"json_object_to_file_ext: object is null\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    fd = open(
        filename,
        0o1 as libc::c_int | 0o1000 as libc::c_int | 0o100 as libc::c_int,
        0o644 as libc::c_int,
    );
    if fd < 0 as libc::c_int {
        _json_c_set_last_err(
            b"json_object_to_file_ext: error opening file %s: %s\n\0" as *const u8
                as *const libc::c_char,
            filename,
            _json_c_strerror(*__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    ret = _json_object_to_fd(fd, obj, flags, filename);
    saved_errno = *__errno_location();
    close(fd);
    *__errno_location() = saved_errno;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_to_fd(
    mut fd: libc::c_int,
    mut obj: *mut json_object,
    mut flags: libc::c_int,
) -> libc::c_int {
    if obj.is_null() {
        _json_c_set_last_err(
            b"json_object_to_fd: object is null\n\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    return _json_object_to_fd(fd, obj, flags, 0 as *const libc::c_char);
}
unsafe extern "C" fn _json_object_to_fd(
    mut fd: libc::c_int,
    mut obj: *mut json_object,
    mut flags: libc::c_int,
    mut filename: *const libc::c_char,
) -> libc::c_int {
    let mut ret: ssize_t = 0;
    let mut json_str: *const libc::c_char = 0 as *const libc::c_char;
    let mut wpos: size_t = 0;
    let mut wsize: size_t = 0;
    filename = if !filename.is_null() {
        filename
    } else {
        b"(fd)\0" as *const u8 as *const libc::c_char
    };
    json_str = json_object_to_json_string_ext(obj, flags);
    if json_str.is_null() {
        return -(1 as libc::c_int);
    }
    wsize = strlen(json_str);
    wpos = 0 as libc::c_int as size_t;
    while wpos < wsize {
        ret = write(
            fd,
            json_str.offset(wpos as isize) as *const libc::c_void,
            wsize.wrapping_sub(wpos),
        );
        if ret < 0 as libc::c_int as libc::c_long {
            _json_c_set_last_err(
                b"json_object_to_fd: error writing file %s: %s\n\0" as *const u8
                    as *const libc::c_char,
                filename,
                _json_c_strerror(*__errno_location()),
            );
            return -(1 as libc::c_int);
        }
        wpos = (wpos as libc::c_ulong).wrapping_add(ret as size_t) as size_t as size_t;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_to_file(
    mut filename: *const libc::c_char,
    mut obj: *mut json_object,
) -> libc::c_int {
    return json_object_to_file_ext(filename, obj, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn json_parse_double(
    mut buf: *const libc::c_char,
    mut retval: *mut libc::c_double,
) -> libc::c_int {
    let mut end: *mut libc::c_char = 0 as *mut libc::c_char;
    *retval = strtod(buf, &mut end);
    return if end == buf as *mut libc::c_char {
        1 as libc::c_int
    } else {
        0 as libc::c_int
    };
}
#[no_mangle]
pub unsafe extern "C" fn json_parse_int64(
    mut buf: *const libc::c_char,
    mut retval: *mut int64_t,
) -> libc::c_int {
    let mut end: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut val: int64_t = 0;
    *__errno_location() = 0 as libc::c_int;
    val = strtoll(buf, &mut end, 10 as libc::c_int) as int64_t;
    if end != buf as *mut libc::c_char {
        *retval = val;
    }
    if val == 0 as libc::c_int as libc::c_long && *__errno_location() != 0 as libc::c_int
        || end == buf as *mut libc::c_char
    {
        *__errno_location() = 22 as libc::c_int;
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn json_parse_uint64(
    mut buf: *const libc::c_char,
    mut retval: *mut uint64_t,
) -> libc::c_int {
    let mut end: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut val: uint64_t = 0;
    *__errno_location() = 0 as libc::c_int;
    while *buf as libc::c_int == ' ' as i32 {
        buf = buf.offset(1);
    }
    if *buf as libc::c_int == '-' as i32 {
        return 1 as libc::c_int;
    }
    val = strtoull(buf, &mut end, 10 as libc::c_int) as uint64_t;
    if end != buf as *mut libc::c_char {
        *retval = val;
    }
    if val == 0 as libc::c_int as libc::c_ulong
        && *__errno_location() != 0 as libc::c_int || end == buf as *mut libc::c_char
    {
        *__errno_location() = 22 as libc::c_int;
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
static mut json_type_name: [*const libc::c_char; 7] = [
    b"null\0" as *const u8 as *const libc::c_char,
    b"boolean\0" as *const u8 as *const libc::c_char,
    b"double\0" as *const u8 as *const libc::c_char,
    b"int\0" as *const u8 as *const libc::c_char,
    b"object\0" as *const u8 as *const libc::c_char,
    b"array\0" as *const u8 as *const libc::c_char,
    b"string\0" as *const u8 as *const libc::c_char,
];
#[no_mangle]
pub unsafe extern "C" fn json_type_to_name(
    mut o_type: json_type,
) -> *const libc::c_char {
    let mut o_type_int: libc::c_int = o_type as libc::c_int;
    if o_type_int < 0 as libc::c_int
        || o_type_int
            >= (::std::mem::size_of::<[*const libc::c_char; 7]>() as libc::c_ulong)
                .wrapping_div(
                    ::std::mem::size_of::<*const libc::c_char>() as libc::c_ulong,
                ) as libc::c_int
    {
        _json_c_set_last_err(
            b"json_type_to_name: type %d is out of range [0,%u]\n\0" as *const u8
                as *const libc::c_char,
            o_type as libc::c_uint,
            (::std::mem::size_of::<[*const libc::c_char; 7]>() as libc::c_ulong)
                .wrapping_div(
                    ::std::mem::size_of::<*const libc::c_char>() as libc::c_ulong,
                ) as libc::c_uint,
        );
        return 0 as *const libc::c_char;
    }
    return json_type_name[o_type as usize];
}
