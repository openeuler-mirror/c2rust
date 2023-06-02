use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type json_object;
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
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn fflush(__stream: *mut FILE) -> i32;
    fn fprintf(_: *mut FILE, _: *const i8, _: ...) -> i32;
    fn printf(_: *const i8, _: ...) -> i32;
    fn exit(_: i32) -> !;
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn strerror(_: i32) -> *mut i8;
    fn read(__fd: i32, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn json_object_put(obj: *mut json_object) -> i32;
    fn json_object_to_json_string(obj: *mut json_object) -> *const i8;
    fn json_object_to_json_string_ext(obj: *mut json_object, flags: i32) -> *const i8;
    fn json_tokener_error_desc(jerr: json_tokener_error) -> *const i8;
    fn json_tokener_get_error(tok: *mut json_tokener) -> json_tokener_error;
    fn json_tokener_new_ex(depth: i32) -> *mut json_tokener;
    fn json_tokener_free(tok: *mut json_tokener);
    fn json_tokener_set_flags(tok: *mut json_tokener, flags: i32);
    fn json_tokener_parse_ex(tok: *mut json_tokener, str: *const i8, len: i32) -> *mut json_object;
    fn getrusage(__who: __rusage_who_t, __usage: *mut rusage) -> i32;
}
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
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: i32,
    pub _flags2: i32,
    pub _old_offset: __off_t,
    pub _cur_column: u16,
    pub _vtable_offset: i8,
    pub _shortbuf: [i8; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: i32,
    pub _unused2: [i8; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type ssize_t = __ssize_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timeval {
    pub tv_sec: __time_t,
    pub tv_usec: __suseconds_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct printbuf {
    pub buf: *mut i8,
    pub bpos: i32,
    pub size: i32,
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
pub type __rusage_who = i32;
pub const RUSAGE_THREAD: __rusage_who = 1;
pub const RUSAGE_CHILDREN: __rusage_who = -1;
pub const RUSAGE_SELF: __rusage_who = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rusage {
    pub ru_utime: timeval,
    pub ru_stime: timeval,
    pub c2rust_unnamed: C2RustUnnamed_12,
    pub c2rust_unnamed_0: C2RustUnnamed_11,
    pub c2rust_unnamed_1: C2RustUnnamed_10,
    pub c2rust_unnamed_2: C2RustUnnamed_9,
    pub c2rust_unnamed_3: C2RustUnnamed_8,
    pub c2rust_unnamed_4: C2RustUnnamed_7,
    pub c2rust_unnamed_5: C2RustUnnamed_6,
    pub c2rust_unnamed_6: C2RustUnnamed_5,
    pub c2rust_unnamed_7: C2RustUnnamed_4,
    pub c2rust_unnamed_8: C2RustUnnamed_3,
    pub c2rust_unnamed_9: C2RustUnnamed_2,
    pub c2rust_unnamed_10: C2RustUnnamed_1,
    pub c2rust_unnamed_11: C2RustUnnamed_0,
    pub c2rust_unnamed_12: C2RustUnnamed,
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
pub type __rusage_who_t = __rusage_who;
static mut formatted_output: i32 = 0 as i32;
static mut show_output: i32 = 1 as i32;
static mut strict_mode: i32 = 0 as i32;
static mut fname: *const i8 = 0 as *const i8;
extern "C" fn showmem() {
    let mut rusage: rusage = rusage {
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
    mut callback: Option<unsafe extern "C" fn(*mut json_object) -> i32>,
) -> i32 {
    let mut obj: *mut json_object = 0 as *mut json_object;
    let mut buf: [i8; 32768] = [0; 32768];
    let mut ret: ssize_t = 0;
    let mut depth: i32 = 32 as i32;
    let mut tok: *mut json_tokener = 0 as *mut json_tokener;
    tok = unsafe { json_tokener_new_ex(depth) };
    if tok.is_null() {
        (unsafe { fprintf(
            stderr,
            b"unable to allocate json_tokener: %s\n\0" as *const u8 as *const i8,
            strerror(*__errno_location()),
        ) });
        return 1 as i32;
    }
    (unsafe { json_tokener_set_flags(tok, 0x1 as i32 | 0x2 as i32) });
    let mut total_read: size_t = 0 as i32 as size_t;
    loop {
        ret = unsafe { read(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            ::std::mem::size_of::<[i8; 32768]>() as u64,
        ) };
        if !(ret > 0 as i32 as i64) {
            break;
        }
        let mut retu: size_t = ret as size_t;
        total_read = (total_read as u64).wrapping_add(retu) as size_t as size_t;
        let mut start_pos: size_t = 0 as i32 as size_t;
        while start_pos != retu {
            obj = unsafe { json_tokener_parse_ex(
                tok,
                &mut *buf.as_mut_ptr().offset(start_pos as isize),
                retu.wrapping_sub(start_pos) as i32,
            ) };
            let mut jerr: json_tokener_error = unsafe { json_tokener_get_error(tok) };
            let mut parse_end: size_t = (unsafe { (*tok).char_offset }) as size_t;
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
                let mut fail_offset: size_t = total_read
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
                (unsafe { json_tokener_free(tok) });
                return 1 as i32;
            }
            if !obj.is_null() {
                let mut cb_ret: i32 = unsafe { callback.expect("non-null function pointer")(obj) };
                (unsafe { json_object_put(obj) });
                if cb_ret != 0 as i32 {
                    (unsafe { json_tokener_free(tok) });
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
                    (*::std::mem::transmute::<&[u8; 48], &[i8; 48]>(
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
    (unsafe { json_tokener_free(tok) });
    return 0 as i32;
}
extern "C" fn showobj(mut new_obj: *mut json_object) -> i32 {
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
            output = unsafe { json_object_to_json_string(new_obj) };
        } else {
            output = unsafe { json_object_to_json_string_ext(new_obj, (1 as i32) << 1 as i32) };
        }
        (unsafe { printf(b"%s\n\0" as *const u8 as *const i8, output) });
    }
    showmem();
    return 0 as i32;
}
#[cold]
extern "C" fn usage(mut argv0: *const i8, mut exitval: i32, mut errmsg: *const i8) -> ! {
    let mut fp: *mut FILE = unsafe { stdout };
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
            }
            110 => {
                (unsafe { show_output = 0 as i32 });
            }
            115 => {
                (unsafe { strict_mode = 1 as i32 });
            }
            104 => {
                usage(unsafe { *argv.offset(0 as i32 as isize) }, 0 as i32, 0 as *const i8);
            }
            _ => {
                usage(
                    unsafe { *argv.offset(0 as i32 as isize) },
                    1 as i32,
                    b"Unknown arguments\0" as *const u8 as *const i8,
                );
            }
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
    if parseit(
        fd,
        Some(showobj as unsafe extern "C" fn(*mut json_object) -> i32),
    ) != 0 as i32
    {
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
