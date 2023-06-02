use :: libc;
extern "C" {
    pub type json_object;
    fn printbuf_new() -> *mut printbuf;
    fn printbuf_memappend(p: *mut printbuf, buf: *const i8, size: i32) -> i32;
    fn printbuf_free(p: *mut printbuf);
    fn json_object_to_json_string_ext(obj: *mut json_object, flags: i32) -> *const i8;
    fn _json_c_strerror(errno_in: i32) -> *mut i8;
    fn __errno_location() -> *mut i32;
    fn strlen(_: *const i8) -> u64;
    fn vsnprintf(_: *mut i8, _: u64, _: *const i8, _: ::std::ffi::VaList) -> i32;
    fn strtod(_: *const i8, _: *mut *mut i8) -> f64;
    fn strtoll(_: *const i8, _: *mut *mut i8, _: i32) -> i64;
    fn strtoull(_: *const i8, _: *mut *mut i8, _: i32) -> u64;
    fn open(__file: *const i8, __oflag: i32, _: ...) -> i32;
    fn close(__fd: i32) -> i32;
    fn read(__fd: i32, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: i32, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn json_tokener_error_desc(jerr: json_tokener_error) -> *const i8;
    fn json_tokener_get_error(tok: *mut json_tokener) -> json_tokener_error;
    fn json_tokener_new_ex(depth: i32) -> *mut json_tokener;
    fn json_tokener_free(tok: *mut json_tokener);
    fn json_tokener_parse_ex(tok: *mut json_tokener, str: *const i8, len: i32) -> *mut json_object;
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: u32,
    pub fp_offset: u32,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type __int64_t = i64;
pub type __uint64_t = u64;
pub type __ssize_t = i64;
pub type int64_t = __int64_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct printbuf {
    pub buf: *mut i8,
    pub bpos: i32,
    pub size: i32,
}
pub type json_type = u32;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
pub type size_t = u64;
pub type va_list = __builtin_va_list;
pub type ssize_t = __ssize_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_tokener_srec {
    pub state: json_tokener_state,
    pub saved_state: json_tokener_state,
    pub obj: *mut json_object,
    pub current: *mut json_object,
    pub obj_field_name: *mut i8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_tokener {
    pub str_0: *mut i8,
    pub pb: *mut printbuf,
    pub max_depth: i32,
    pub depth: i32,
    pub is_double: i32,
    pub st_pos: i32,
    pub char_offset: i32,
    pub err: json_tokener_error,
    pub ucs_char: u32,
    pub high_surrogate: u32,
    pub quote_char: i8,
    pub stack: *mut json_tokener_srec,
    pub flags: i32,
}
static mut _last_err: [i8; 256] = unsafe {
    * :: std :: mem :: transmute :: < & [u8 ; 256] , & mut [i8 ; 256] , > (b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" ,)
};
#[no_mangle]
pub extern "C" fn json_util_get_last_err() -> *const i8 {
    if (unsafe { _last_err[0 as i32 as usize] }) as i32 == '\u{0}' as i32 {
        return 0 as *const i8;
    }
    return unsafe { _last_err.as_mut_ptr() };
}
#[no_mangle]
pub unsafe extern "C" fn _json_c_set_last_err(mut err_fmt: *const i8, mut args: ...) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    vsnprintf(
        _last_err.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 256]>() as u64,
        err_fmt,
        ap.as_va_list(),
    );
}
#[no_mangle]
pub extern "C" fn json_object_from_fd(mut fd: i32) -> *mut json_object {
    return json_object_from_fd_ex(fd, -(1 as i32));
}
#[no_mangle]
pub extern "C" fn json_object_from_fd_ex(mut fd: i32, mut in_depth: i32) -> *mut json_object {
    let mut pb: *mut printbuf = 0 as *mut printbuf;
    let mut obj: *mut json_object = 0 as *mut json_object;
    let mut buf: [i8; 4096] = [0; 4096];
    let mut ret: ssize_t = 0;
    let mut depth: i32 = 32 as i32;
    let mut tok: *mut json_tokener = 0 as *mut json_tokener;
    pb = unsafe { printbuf_new() };
    if pb.is_null() {
        (unsafe { _json_c_set_last_err(
            b"json_object_from_fd_ex: printbuf_new failed\n\0" as *const u8 as *const i8,
        ) });
        return 0 as *mut json_object;
    }
    if in_depth != -(1 as i32) {
        depth = in_depth;
    }
    tok = unsafe { json_tokener_new_ex(depth) };
    if tok.is_null() {
        (unsafe { _json_c_set_last_err(
            b"json_object_from_fd_ex: unable to allocate json_tokener(depth=%d): %s\n\0"
                as *const u8 as *const i8,
            depth,
            _json_c_strerror(*__errno_location()),
        ) });
        (unsafe { printbuf_free(pb) });
        return 0 as *mut json_object;
    }
    loop {
        ret = unsafe { read(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            ::std::mem::size_of::<[i8; 4096]>() as u64,
        ) };
        if !(ret > 0 as i32 as i64) {
            break;
        }
        if (unsafe { printbuf_memappend(pb, buf.as_mut_ptr(), ret as i32) }) < 0 as i32 {
            (unsafe { _json_c_set_last_err (b"json_object_from_fd_ex: failed to printbuf_memappend after reading %d+%d bytes: %s\0" as * const u8 as * const i8 , (* pb) . bpos , ret as i32 , _json_c_strerror (* __errno_location ()) ,) }) ;
            (unsafe { json_tokener_free(tok) });
            (unsafe { printbuf_free(pb) });
            return 0 as *mut json_object;
        }
    }
    if ret < 0 as i32 as i64 {
        (unsafe { _json_c_set_last_err(
            b"json_object_from_fd_ex: error reading fd %d: %s\n\0" as *const u8 as *const i8,
            fd,
            _json_c_strerror(*__errno_location()),
        ) });
        (unsafe { json_tokener_free(tok) });
        (unsafe { printbuf_free(pb) });
        return 0 as *mut json_object;
    }
    obj = unsafe { json_tokener_parse_ex(tok, (*pb).buf, (*pb).bpos) };
    if obj.is_null() {
        (unsafe { _json_c_set_last_err(
            b"json_tokener_parse_ex failed: %s\n\0" as *const u8 as *const i8,
            json_tokener_error_desc(json_tokener_get_error(tok)),
        ) });
    }
    (unsafe { json_tokener_free(tok) });
    (unsafe { printbuf_free(pb) });
    return obj;
}
#[no_mangle]
pub extern "C" fn json_object_from_file(mut filename: *const i8) -> *mut json_object {
    let mut obj: *mut json_object = 0 as *mut json_object;
    let mut fd: i32 = 0;
    fd = unsafe { open(filename, 0 as i32) };
    if fd < 0 as i32 {
        (unsafe { _json_c_set_last_err(
            b"json_object_from_file: error opening file %s: %s\n\0" as *const u8 as *const i8,
            filename,
            _json_c_strerror(*__errno_location()),
        ) });
        return 0 as *mut json_object;
    }
    obj = json_object_from_fd(fd);
    (unsafe { close(fd) });
    return obj;
}
#[no_mangle]
pub extern "C" fn json_object_to_file_ext(
    mut filename: *const i8,
    mut obj: *mut json_object,
    mut flags: i32,
) -> i32 {
    let mut fd: i32 = 0;
    let mut ret: i32 = 0;
    let mut saved_errno: i32 = 0;
    if obj.is_null() {
        (unsafe { _json_c_set_last_err(
            b"json_object_to_file_ext: object is null\n\0" as *const u8 as *const i8,
        ) });
        return -(1 as i32);
    }
    fd = unsafe { open(
        filename,
        0o1 as i32 | 0o1000 as i32 | 0o100 as i32,
        0o644 as i32,
    ) };
    if fd < 0 as i32 {
        (unsafe { _json_c_set_last_err(
            b"json_object_to_file_ext: error opening file %s: %s\n\0" as *const u8 as *const i8,
            filename,
            _json_c_strerror(*__errno_location()),
        ) });
        return -(1 as i32);
    }
    ret = _json_object_to_fd(fd, obj, flags, filename);
    saved_errno = unsafe { *__errno_location() };
    (unsafe { close(fd) });
    (unsafe { *__errno_location() = saved_errno });
    return ret;
}
#[no_mangle]
pub extern "C" fn json_object_to_fd(mut fd: i32, mut obj: *mut json_object, mut flags: i32) -> i32 {
    if obj.is_null() {
        (unsafe { _json_c_set_last_err(b"json_object_to_fd: object is null\n\0" as *const u8 as *const i8) });
        return -(1 as i32);
    }
    return _json_object_to_fd(fd, obj, flags, 0 as *const i8);
}
extern "C" fn _json_object_to_fd(
    mut fd: i32,
    mut obj: *mut json_object,
    mut flags: i32,
    mut filename: *const i8,
) -> i32 {
    let mut ret: ssize_t = 0;
    let mut json_str: *const i8 = 0 as *const i8;
    let mut wpos: size_t = 0;
    let mut wsize: size_t = 0;
    filename = if !filename.is_null() {
        filename
    } else {
        b"(fd)\0" as *const u8 as *const i8
    };
    json_str = unsafe { json_object_to_json_string_ext(obj, flags) };
    if json_str.is_null() {
        return -(1 as i32);
    }
    wsize = unsafe { strlen(json_str) };
    wpos = 0 as i32 as size_t;
    while wpos < wsize {
        ret = unsafe { write(
            fd,
            json_str.offset(wpos as isize) as *const libc::c_void,
            wsize.wrapping_sub(wpos),
        ) };
        if ret < 0 as i32 as i64 {
            (unsafe { _json_c_set_last_err(
                b"json_object_to_fd: error writing file %s: %s\n\0" as *const u8 as *const i8,
                filename,
                _json_c_strerror(*__errno_location()),
            ) });
            return -(1 as i32);
        }
        wpos = (wpos as u64).wrapping_add(ret as size_t) as size_t as size_t;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn json_object_to_file(mut filename: *const i8, mut obj: *mut json_object) -> i32 {
    return json_object_to_file_ext(filename, obj, 0 as i32);
}
#[no_mangle]
pub extern "C" fn json_parse_double(mut buf: *const i8, mut retval: *mut f64) -> i32 {
    let mut end: *mut i8 = 0 as *mut i8;
    (unsafe { *retval = strtod(buf, &mut end) });
    return if end == buf as *mut i8 {
        1 as i32
    } else {
        0 as i32
    };
}
#[no_mangle]
pub extern "C" fn json_parse_int64(mut buf: *const i8, mut retval: *mut int64_t) -> i32 {
    let mut end: *mut i8 = 0 as *mut i8;
    let mut val: int64_t = 0;
    (unsafe { *__errno_location() = 0 as i32 });
    val = (unsafe { strtoll(buf, &mut end, 10 as i32) }) as int64_t;
    if end != buf as *mut i8 {
        (unsafe { *retval = val });
    }
    if val == 0 as i32 as i64 && (unsafe { *__errno_location() }) != 0 as i32 || end == buf as *mut i8 {
        (unsafe { *__errno_location() = 22 as i32 });
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn json_parse_uint64(mut buf: *const i8, mut retval: *mut uint64_t) -> i32 {
    let mut end: *mut i8 = 0 as *mut i8;
    let mut val: uint64_t = 0;
    (unsafe { *__errno_location() = 0 as i32 });
    while (unsafe { *buf }) as i32 == ' ' as i32 {
        buf = unsafe { buf.offset(1) };
    }
    if (unsafe { *buf }) as i32 == '-' as i32 {
        return 1 as i32;
    }
    val = (unsafe { strtoull(buf, &mut end, 10 as i32) }) as uint64_t;
    if end != buf as *mut i8 {
        (unsafe { *retval = val });
    }
    if val == 0 as i32 as u64 && (unsafe { *__errno_location() }) != 0 as i32 || end == buf as *mut i8 {
        (unsafe { *__errno_location() = 22 as i32 });
        return 1 as i32;
    }
    return 0 as i32;
}
static mut json_type_name: [*const i8; 7] = [
    b"null\0" as *const u8 as *const i8,
    b"boolean\0" as *const u8 as *const i8,
    b"double\0" as *const u8 as *const i8,
    b"int\0" as *const u8 as *const i8,
    b"object\0" as *const u8 as *const i8,
    b"array\0" as *const u8 as *const i8,
    b"string\0" as *const u8 as *const i8,
];
#[no_mangle]
pub extern "C" fn json_type_to_name(mut o_type: json_type) -> *const i8 {
    let mut o_type_int: i32 = o_type as i32;
    if o_type_int < 0 as i32
        || o_type_int
            >= (::std::mem::size_of::<[*const i8; 7]>() as u64)
                .wrapping_div(::std::mem::size_of::<*const i8>() as u64) as i32
    {
        (unsafe { _json_c_set_last_err(
            b"json_type_to_name: type %d is out of range [0,%u]\n\0" as *const u8 as *const i8,
            o_type as u32,
            (::std::mem::size_of::<[*const i8; 7]>() as u64)
                .wrapping_div(::std::mem::size_of::<*const i8>() as u64) as u32,
        ) });
        return 0 as *const i8;
    }
    return unsafe { json_type_name[o_type as usize] };
}
