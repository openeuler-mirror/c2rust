use :: libc;
extern "C" {
    fn __assert_fail(
        __assertion: *const i8,
        __file: *const i8,
        __line: u32,
        __function: *const i8,
    ) -> !;
    fn __errno_location() -> *mut i32;
    fn open(__file: *const i8, __oflag: i32, _: ...) -> i32;
    static mut optind: i32;
    fn getopt(___argc: i32, ___argv: *const *mut i8, __shortopts: *const i8) -> i32;
    static mut stdout: *mut crate::src::apps::json_parse::_IO_FILE;
    static mut stderr: *mut crate::src::apps::json_parse::_IO_FILE;
    fn fflush(__stream: *mut crate::src::apps::json_parse::_IO_FILE) -> i32;
    fn fprintf(_: *mut crate::src::apps::json_parse::_IO_FILE, _: *const i8, _: ...) -> i32;
    fn printf(_: *const i8, _: ...) -> i32;
    fn exit(_: i32) -> !;
    fn memset(_: *mut core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn strerror(_: i32) -> *mut i8;
    fn read(__fd: i32, __buf: *mut core::ffi::c_void, __nbytes: u64) -> i64;
    fn getrusage(__who: i32, __usage: *mut crate::src::apps::json_parse::rusage) -> i32;
}
pub use crate::src::{
    debug::_IO_wide_data,
    json_object::{
        _IO_codecvt, json_object, json_object_put, json_object_to_json_string,
        json_object_to_json_string_ext,
    },
    json_tokener::{
        json_tokener_error_desc, json_tokener_free, json_tokener_get_error, json_tokener_new_ex,
        json_tokener_parse_ex, json_tokener_set_flags,
    },
    json_visit::_IO_marker,
};
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __time_t = i64;
pub type __suseconds_t = i64;
pub type __ssize_t = i64;
pub type __syscall_slong_t = i64;
pub type size_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: i32,
    pub _IO_read_ptr: *mut i8,
    pub _IO_read_end: *mut i8,
    pub _IO_read_base: *mut i8,
    pub _IO_write_base: *mut i8,
    pub _IO_write_ptr: *mut i8,
    pub _IO_write_end: *mut i8,
    pub _IO_buf_base: *mut i8,
    pub _IO_buf_end: *mut i8,
    pub _IO_save_base: *mut i8,
    pub _IO_backup_base: *mut i8,
    pub _IO_save_end: *mut i8,
    pub _markers: *mut crate::src::json_visit::_IO_marker,
    pub _chain: *mut crate::src::apps::json_parse::_IO_FILE,
    pub _fileno: i32,
    pub _flags2: i32,
    pub _old_offset: i64,
    pub _cur_column: u16,
    pub _vtable_offset: i8,
    pub _shortbuf: [i8; 1],
    pub _lock: *mut core::ffi::c_void,
    pub _offset: i64,
    pub _codecvt: *mut crate::src::json_object::_IO_codecvt,
    pub _wide_data: *mut crate::src::debug::_IO_wide_data,
    pub _freeres_list: *mut crate::src::apps::json_parse::_IO_FILE,
    pub _freeres_buf: *mut core::ffi::c_void,
    pub __pad5: u64,
    pub _mode: i32,
    pub _unused2: [i8; 20],
}
impl _IO_FILE {
    pub const fn new() -> Self {
        _IO_FILE {
            _flags: 0,
            _IO_read_ptr: (0 as *mut i8),
            _IO_read_end: (0 as *mut i8),
            _IO_read_base: (0 as *mut i8),
            _IO_write_base: (0 as *mut i8),
            _IO_write_ptr: (0 as *mut i8),
            _IO_write_end: (0 as *mut i8),
            _IO_buf_base: (0 as *mut i8),
            _IO_buf_end: (0 as *mut i8),
            _IO_save_base: (0 as *mut i8),
            _IO_backup_base: (0 as *mut i8),
            _IO_save_end: (0 as *mut i8),
            _markers: (0 as *mut crate::src::json_visit::_IO_marker),
            _chain: (0 as *mut crate::src::apps::json_parse::_IO_FILE),
            _fileno: 0,
            _flags2: 0,
            _old_offset: 0,
            _cur_column: 0,
            _vtable_offset: 0,
            _shortbuf: [0],
            _lock: (0 as *mut core::ffi::c_void),
            _offset: 0,
            _codecvt: (0 as *mut crate::src::json_object::_IO_codecvt),
            _wide_data: (0 as *mut crate::src::debug::_IO_wide_data),
            _freeres_list: (0 as *mut crate::src::apps::json_parse::_IO_FILE),
            _freeres_buf: (0 as *mut core::ffi::c_void),
            __pad5: 0,
            _mode: 0,
            _unused2: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }
}
impl std::default::Default for _IO_FILE {
    fn default() -> Self {
        _IO_FILE::new()
    }
}
pub type _IO_lock_t = ();
pub type FILE = crate::src::apps::json_parse::_IO_FILE;
pub type ssize_t = i64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}
impl timeval {
    pub const fn new() -> Self {
        timeval {
            tv_sec: 0,
            tv_usec: 0,
        }
    }
}
impl std::default::Default for timeval {
    fn default() -> Self {
        timeval::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct printbuf {
    pub buf: *mut i8,
    pub bpos: i32,
    pub size: i32,
}
impl printbuf {
    pub const fn new() -> Self {
        printbuf {
            buf: (0 as *mut i8),
            bpos: 0,
            size: 0,
        }
    }
}
impl std::default::Default for printbuf {
    fn default() -> Self {
        printbuf::new()
    }
}
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
#[repr(C)]
pub struct json_tokener_srec<'a> {
    pub state: u32,
    pub saved_state: u32,
    pub obj: Option<&'a mut crate::src::json_object::json_object>,
    pub current: *mut crate::src::json_object::json_object,
    pub obj_field_name: *mut i8,
}
impl<'a> json_tokener_srec<'a> {
    pub const fn new() -> Self {
        json_tokener_srec {
            state: 0,
            saved_state: 0,
            obj: None,
            current: (0 as *mut crate::src::json_object::json_object),
            obj_field_name: (0 as *mut i8),
        }
    }
}
impl<'a> std::default::Default for json_tokener_srec<'a> {
    fn default() -> Self {
        json_tokener_srec::new()
    }
}
#[repr(C)]
pub struct json_tokener<'a> {
    pub str_0: Option<&'a mut i8>,
    pub pb: *mut crate::src::apps::json_parse::printbuf,
    pub max_depth: i32,
    pub depth: i32,
    pub is_double: i32,
    pub st_pos: i32,
    pub char_offset: i32,
    pub err: u32,
    pub ucs_char: u32,
    pub high_surrogate: u32,
    pub quote_char: i8,
    pub stack: *mut crate::src::apps::json_parse::json_tokener_srec<'a>,
    pub flags: i32,
}
impl<'a> json_tokener<'a> {
    pub const fn new() -> Self {
        json_tokener {
            str_0: None,
            pb: (0 as *mut crate::src::apps::json_parse::printbuf),
            max_depth: 0,
            depth: 0,
            is_double: 0,
            st_pos: 0,
            char_offset: 0,
            err: 0,
            ucs_char: 0,
            high_surrogate: 0,
            quote_char: 0,
            stack: (0 as *mut crate::src::apps::json_parse::json_tokener_srec<'a>),
            flags: 0,
        }
    }
}
impl<'a> std::default::Default for json_tokener<'a> {
    fn default() -> Self {
        json_tokener::new()
    }
}
pub type __rusage_who = i32;
pub const RUSAGE_THREAD: __rusage_who = 1;
pub const RUSAGE_CHILDREN: __rusage_who = -1;
pub const RUSAGE_SELF: __rusage_who = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rusage {
    pub ru_utime: crate::src::apps::json_parse::timeval,
    pub ru_stime: crate::src::apps::json_parse::timeval,
    pub c2rust_unnamed: crate::src::apps::json_parse::C2RustUnnamed_12,
    pub c2rust_unnamed_0: crate::src::apps::json_parse::C2RustUnnamed_11,
    pub c2rust_unnamed_1: crate::src::apps::json_parse::C2RustUnnamed_10,
    pub c2rust_unnamed_2: crate::src::apps::json_parse::C2RustUnnamed_9,
    pub c2rust_unnamed_3: crate::src::apps::json_parse::C2RustUnnamed_8,
    pub c2rust_unnamed_4: crate::src::apps::json_parse::C2RustUnnamed_7,
    pub c2rust_unnamed_5: crate::src::apps::json_parse::C2RustUnnamed_6,
    pub c2rust_unnamed_6: crate::src::apps::json_parse::C2RustUnnamed_5,
    pub c2rust_unnamed_7: crate::src::apps::json_parse::C2RustUnnamed_4,
    pub c2rust_unnamed_8: crate::src::apps::json_parse::C2RustUnnamed_3,
    pub c2rust_unnamed_9: crate::src::apps::json_parse::C2RustUnnamed_2,
    pub c2rust_unnamed_10: crate::src::apps::json_parse::C2RustUnnamed_1,
    pub c2rust_unnamed_11: crate::src::apps::json_parse::C2RustUnnamed_0,
    pub c2rust_unnamed_12: crate::src::apps::json_parse::C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub ru_nivcsw: i64,
    pub __ru_nivcsw_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub ru_nvcsw: i64,
    pub __ru_nvcsw_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub ru_nsignals: i64,
    pub __ru_nsignals_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_2 {
    pub ru_msgrcv: i64,
    pub __ru_msgrcv_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_3 {
    pub ru_msgsnd: i64,
    pub __ru_msgsnd_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_4 {
    pub ru_oublock: i64,
    pub __ru_oublock_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_5 {
    pub ru_inblock: i64,
    pub __ru_inblock_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_6 {
    pub ru_nswap: i64,
    pub __ru_nswap_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_7 {
    pub ru_majflt: i64,
    pub __ru_majflt_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_8 {
    pub ru_minflt: i64,
    pub __ru_minflt_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_9 {
    pub ru_isrss: i64,
    pub __ru_isrss_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_10 {
    pub ru_idrss: i64,
    pub __ru_idrss_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_11 {
    pub ru_ixrss: i64,
    pub __ru_ixrss_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_12 {
    pub ru_maxrss: i64,
    pub __ru_maxrss_word: __syscall_slong_t,
}
pub type __rusage_who_t = i32;
static mut formatted_output: i32 = 0 as i32;
static mut show_output: i32 = 1 as i32;
static mut strict_mode: i32 = 0 as i32;
static mut fname: *const i8 = 0 as *const i8;
extern "C" fn showmem() {
    let mut rusage: crate::src::apps::json_parse::rusage = rusage {
        ru_utime: timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        ru_stime: timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        c2rust_unnamed: C2RustUnnamed_12 { ru_maxrss: 0 },
        c2rust_unnamed_0: C2RustUnnamed_11 { ru_ixrss: 0 },
        c2rust_unnamed_1: C2RustUnnamed_10 { ru_idrss: 0 },
        c2rust_unnamed_2: C2RustUnnamed_9 { ru_isrss: 0 },
        c2rust_unnamed_3: C2RustUnnamed_8 { ru_minflt: 0 },
        c2rust_unnamed_4: C2RustUnnamed_7 { ru_majflt: 0 },
        c2rust_unnamed_5: C2RustUnnamed_6 { ru_nswap: 0 },
        c2rust_unnamed_6: C2RustUnnamed_5 { ru_inblock: 0 },
        c2rust_unnamed_7: C2RustUnnamed_4 { ru_oublock: 0 },
        c2rust_unnamed_8: C2RustUnnamed_3 { ru_msgsnd: 0 },
        c2rust_unnamed_9: C2RustUnnamed_2 { ru_msgrcv: 0 },
        c2rust_unnamed_10: C2RustUnnamed_1 { ru_nsignals: 0 },
        c2rust_unnamed_11: C2RustUnnamed_0 { ru_nvcsw: 0 },
        c2rust_unnamed_12: C2RustUnnamed { ru_nivcsw: 0 },
    };
    (unsafe { memset(
        &mut rusage as *mut rusage as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<rusage>() as u64,
    ) });
    (unsafe { getrusage(RUSAGE_SELF, &mut rusage) });
    (unsafe { printf(
        b"maxrss: %ld KB\n\0" as *const u8 as *const i8,
        rusage.c2rust_unnamed.ru_maxrss,
    ) });
}
extern "C" fn parseit(
    mut fd: i32,
    mut callback: Option<unsafe extern "C" fn(_: *mut crate::src::json_object::json_object) -> i32>,
) -> i32 {
    let mut obj: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut buf: [i8; 32768] = [0; 32768];
    let mut ret: i64 = 0;
    let mut depth: i32 = 32 as i32;
    let mut tok: *mut crate::src::apps::json_parse::json_tokener<'_> = 0 as *mut json_tokener;
    tok = json_tokener_new_ex(depth);
    if tok.is_null() {
        (unsafe { fprintf(
            stderr,
            b"unable to allocate json_tokener: %s\n\0" as *const u8 as *const i8,
            strerror(*__errno_location()),
        ) });
        return 1 as i32;
    }
    json_tokener_set_flags(tok, 0x1 as i32 | 0x2 as i32);
    let mut total_read: u64 = 0 as i32 as size_t;
    loop {
        ret = unsafe { read(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            ::std::mem::size_of::<[i8; 32768]>() as u64,
        ) };
        if !(ret > 0 as i32 as i64) {
            break;
        }
        let mut retu: u64 = ret as size_t;
        total_read = (total_read as u64).wrapping_add(retu) as size_t as size_t;
        let mut start_pos: u64 = 0 as i32 as size_t;
        while start_pos != retu {
            obj = json_tokener_parse_ex(
                tok,
                unsafe { &mut *buf.as_mut_ptr().offset(start_pos as isize) },
                retu.wrapping_sub(start_pos) as i32,
            );
            let mut jerr: u32 = json_tokener_get_error(tok);
            let mut parse_end: u64 = (unsafe { (*tok).char_offset }) as size_t;
            if obj.is_null() && jerr as u32 != json_tokener_continue as i32 as u32 {
                let mut aterr: *const i8 = if start_pos.wrapping_add(parse_end)
                    < ::std::mem::size_of::<[i8; 32768]>() as u64 as i32 as u64
                {
                    (unsafe { &mut *buf
                        .as_mut_ptr()
                        .offset(start_pos.wrapping_add(parse_end) as isize) })
                        as *mut i8 as *const i8
                } else {
                    b"\0" as *const u8 as *const i8
                };
                (unsafe { fflush(stdout) });
                let mut fail_offset: u64 = total_read
                    .wrapping_sub(retu)
                    .wrapping_add(start_pos)
                    .wrapping_add(parse_end);
                (unsafe { fprintf(
                    stderr,
                    b"Failed at offset %lu: %s %c\n\0" as *const u8 as *const i8,
                    fail_offset,
                    json_tokener_error_desc(jerr),
                    *aterr.offset(0 as i32 as isize) as i32,
                ) });
                json_tokener_free(tok);
                return 1 as i32;
            }
            if !obj.is_null() {
                let mut cb_ret: i32 = unsafe { callback.expect("non-null function pointer")(obj) };
                json_object_put(obj);
                if cb_ret != 0 as i32 {
                    json_tokener_free(tok);
                    return 1 as i32;
                }
            }
            start_pos =
                (start_pos as u64).wrapping_add((unsafe { (*tok).char_offset }) as u64) as size_t as size_t;
            if start_pos <= retu {
            } else {
                (unsafe { __assert_fail(
                    b"start_pos <= retu\0" as *const u8 as *const i8,
                    b"/home/xial/json-c/apps/json_parse.c\0" as *const u8 as *const i8,
                    119 as i32 as u32,
                    (*core::intrinsics::transmute::<&'_ [u8; 48], &'_ [i8; 48]>(
                        b"int parseit(int, int (*)(struct json_object *))\0",
                    ))
                    .as_ptr(),
                ) });
            }
        }
    }
    if ret < 0 as i32 as i64 {
        (unsafe { fprintf(
            stderr,
            b"error reading fd %d: %s\n\0" as *const u8 as *const i8,
            fd,
            strerror(*__errno_location()),
        ) });
    }
    json_tokener_free(tok);
    return 0 as i32;
}
extern "C" fn showobj(mut new_obj: *mut crate::src::json_object::json_object) -> i32 {
    if new_obj.is_null() {
        (unsafe { fprintf(
            stderr,
            b"%s: Failed to parse\n\0" as *const u8 as *const i8,
            fname,
        ) });
        return 1 as i32;
    }
    (unsafe { printf(
        b"Successfully parsed object from %s\n\0" as *const u8 as *const i8,
        fname,
    ) });
    if (unsafe { show_output }) != 0 {
        let mut output: *const i8 = 0 as *const i8;
        if (unsafe { formatted_output }) != 0 {
            output = json_object_to_json_string(new_obj);
        } else {
            output = json_object_to_json_string_ext(new_obj, (1 as i32) << 1 as i32);
        }
        (unsafe { printf(b"%s\n\0" as *const u8 as *const i8, output) });
    }
    showmem();
    return 0 as i32;
}
#[cold]
extern "C" fn usage(mut argv0: *const i8, mut exitval: i32, mut errmsg: *const i8) -> ! {
    let mut fp: *mut crate::src::apps::json_parse::_IO_FILE = unsafe { stdout };
    if exitval != 0 as i32 {
        fp = unsafe { stderr };
    }
    if !errmsg.is_null() {
        (unsafe { fprintf(fp, b"ERROR: %s\n\n\0" as *const u8 as *const i8, errmsg) });
    }
    (unsafe { fprintf(
        fp,
        b"Usage: %s [-f] [-n] [-s]\n\0" as *const u8 as *const i8,
        argv0,
    ) });
    (unsafe { fprintf(
        fp,
        b"  -f - Format the output with JSON_C_TO_STRING_PRETTY\n\0" as *const u8 as *const i8,
    ) });
    (unsafe { fprintf(fp, b"  -n - No output\n\0" as *const u8 as *const i8) });
    (unsafe { fprintf(
        fp,
        b"  -s - Parse in strict mode, flags:\n\0" as *const u8 as *const i8,
    ) });
    (unsafe { fprintf(
        fp,
        b"       JSON_TOKENER_STRICT|JSON_TOKENER_ALLOW_TRAILING_CHARS\n\0" as *const u8
            as *const i8,
    ) });
    (unsafe { fprintf(
        fp,
        b"\nWARNING WARNING WARNING\n\0" as *const u8 as *const i8,
    ) });
    (unsafe { fprintf(
        fp,
        b"This is a prototype, it may change or be removed at any time!\n\0" as *const u8
            as *const i8,
    ) });
    (unsafe { exit(exitval) });
}
fn main_0(mut argc: i32, mut argv: *mut *mut i8) -> i32 {
    let mut opt: i32 = 0;
    loop {
        opt = unsafe { getopt(argc, argv, b"fhns\0" as *const u8 as *const i8) };
        if !(opt != -(1 as i32)) {
            break;
        }
        match opt {
            102 => {
                (unsafe { formatted_output = 1 as i32 });
            },
            110 => {
                (unsafe { show_output = 0 as i32 });
            },
            115 => {
                (unsafe { strict_mode = 1 as i32 });
            },
            104 => {
                usage(unsafe { *argv.offset(0 as i32 as isize) }, 0 as i32, 0 as *const i8);
            },
            _ => {
                usage(
                    unsafe { *argv.offset(0 as i32 as isize) },
                    1 as i32,
                    b"Unknown arguments\0" as *const u8 as *const i8,
                );
            },
        }
    }
    if (unsafe { optind }) >= argc {
        usage(
            unsafe { *argv.offset(0 as i32 as isize) },
            1 as i32,
            b"Expected argument after options\0" as *const u8 as *const i8,
        );
    }
    (unsafe { fname = *argv.offset(optind as isize) });
    let mut fd: i32 = unsafe { open(*argv.offset(optind as isize), 0 as i32, 0 as i32) };
    showmem();
    if parseit(fd, Some(showobj)) != 0 as i32 {
        (unsafe { exit(1 as i32) });
    }
    showmem();
    (unsafe { exit(0 as i32) });
}
pub fn main() {
    let mut args: Vec<*mut i8> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::std::ptr::null_mut());
     {
        ::std::process::exit(
            main_0((args.len() - 1) as i32, args.as_mut_ptr() as *mut *mut i8) as i32,
        )
    }
}

