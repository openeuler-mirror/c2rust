use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn __errno_location() -> *mut libc::c_int;
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...) -> libc::c_int;
    static mut optind: libc::c_int;
    fn getopt(
        ___argc: libc::c_int,
        ___argv: *const *mut libc::c_char,
        __shortopts: *const libc::c_char,
    ) -> libc::c_int;
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn exit(_: libc::c_int) -> !;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    
    
    
    
    
    
    
    
    
    fn getrusage(__who: __rusage_who_t, __usage: *mut rusage) -> libc::c_int;
}
pub use crate::json_object::json_object_put;
pub use crate::json_object::json_object_to_json_string;
pub use crate::json_object::json_object_to_json_string_ext;
pub use crate::json_tokener::json_tokener_error_desc;
pub use crate::json_tokener::json_tokener_free;
pub use crate::json_tokener::json_tokener_get_error;
pub use crate::json_tokener::json_tokener_new_ex;
pub use crate::json_tokener::json_tokener_parse_ex;
pub use crate::json_tokener::json_tokener_set_flags;
pub use crate::json_object::json_object;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __suseconds_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
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
    pub buf: *mut libc::c_char,
    pub bpos: libc::c_int,
    pub size: libc::c_int,
}
pub type json_tokener_error = libc::c_uint;
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
pub type json_tokener_state = libc::c_uint;
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
    pub obj_field_name: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_tokener {
    pub str_0: *mut libc::c_char,
    pub pb: *mut printbuf,
    pub max_depth: libc::c_int,
    pub depth: libc::c_int,
    pub is_double: libc::c_int,
    pub st_pos: libc::c_int,
    pub char_offset: libc::c_int,
    pub err: json_tokener_error,
    pub ucs_char: libc::c_uint,
    pub high_surrogate: libc::c_uint,
    pub quote_char: libc::c_char,
    pub stack: *mut json_tokener_srec,
    pub flags: libc::c_int,
}
pub type __rusage_who = libc::c_int;
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
    pub ru_nivcsw: libc::c_long,
    pub __ru_nivcsw_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub ru_nvcsw: libc::c_long,
    pub __ru_nvcsw_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub ru_nsignals: libc::c_long,
    pub __ru_nsignals_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_2 {
    pub ru_msgrcv: libc::c_long,
    pub __ru_msgrcv_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_3 {
    pub ru_msgsnd: libc::c_long,
    pub __ru_msgsnd_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_4 {
    pub ru_oublock: libc::c_long,
    pub __ru_oublock_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_5 {
    pub ru_inblock: libc::c_long,
    pub __ru_inblock_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_6 {
    pub ru_nswap: libc::c_long,
    pub __ru_nswap_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_7 {
    pub ru_majflt: libc::c_long,
    pub __ru_majflt_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_8 {
    pub ru_minflt: libc::c_long,
    pub __ru_minflt_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_9 {
    pub ru_isrss: libc::c_long,
    pub __ru_isrss_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_10 {
    pub ru_idrss: libc::c_long,
    pub __ru_idrss_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_11 {
    pub ru_ixrss: libc::c_long,
    pub __ru_ixrss_word: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_12 {
    pub ru_maxrss: libc::c_long,
    pub __ru_maxrss_word: __syscall_slong_t,
}
pub type __rusage_who_t = __rusage_who;
static mut formatted_output: libc::c_int = 0 as libc::c_int;
static mut show_output: libc::c_int = 1 as libc::c_int;
static mut strict_mode: libc::c_int = 0 as libc::c_int;
static mut fname: *const libc::c_char = 0 as *const libc::c_char;
unsafe extern "C" fn showmem() {
    let mut rusage: rusage = rusage {
        ru_utime: timeval { tv_sec: 0, tv_usec: 0 },
        ru_stime: timeval { tv_sec: 0, tv_usec: 0 },
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
    memset(
        &mut rusage as *mut rusage as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<rusage>() as libc::c_ulong,
    );
    getrusage(RUSAGE_SELF, &mut rusage);
    printf(
        b"maxrss: %ld KB\n\0" as *const u8 as *const libc::c_char,
        rusage.c2rust_unnamed.ru_maxrss,
    );
}
unsafe extern "C" fn parseit(
    mut fd: libc::c_int,
    mut callback: Option::<unsafe extern "C" fn(*mut json_object) -> libc::c_int>,
) -> libc::c_int {
    let mut obj: *mut json_object = 0 as *mut json_object;
    let mut buf: [libc::c_char; 32768] = [0; 32768];
    let mut ret: ssize_t = 0;
    let mut depth: libc::c_int = 32 as libc::c_int;
    let mut tok: *mut json_tokener = 0 as *mut json_tokener;
    tok = json_tokener_new_ex(depth);
    if tok.is_null() {
        fprintf(
            stderr,
            b"unable to allocate json_tokener: %s\n\0" as *const u8
                as *const libc::c_char,
            strerror(*__errno_location()),
        );
        return 1 as libc::c_int;
    }
    json_tokener_set_flags(tok, 0x1 as libc::c_int | 0x2 as libc::c_int);
    let mut total_read: size_t = 0 as libc::c_int as size_t;
    loop {
        ret = read(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            ::std::mem::size_of::<[libc::c_char; 32768]>() as libc::c_ulong,
        );
        if !(ret > 0 as libc::c_int as libc::c_long) {
            break;
        }
        let mut retu: size_t = ret as size_t;
        total_read = (total_read as libc::c_ulong).wrapping_add(retu) as size_t
            as size_t;
        let mut start_pos: size_t = 0 as libc::c_int as size_t;
        while start_pos != retu {
            obj = json_tokener_parse_ex(
                tok,
                &mut *buf.as_mut_ptr().offset(start_pos as isize),
                retu.wrapping_sub(start_pos) as libc::c_int,
            );
            let mut jerr: json_tokener_error = json_tokener_get_error(tok);
            let mut parse_end: size_t = (*tok).char_offset as size_t;
            if obj.is_null()
                && jerr as libc::c_uint
                    != json_tokener_continue as libc::c_int as libc::c_uint
            {
                let mut aterr: *const libc::c_char = if start_pos.wrapping_add(parse_end)
                    < ::std::mem::size_of::<[libc::c_char; 32768]>() as libc::c_ulong
                        as libc::c_int as libc::c_ulong
                {
                    &mut *buf
                        .as_mut_ptr()
                        .offset(start_pos.wrapping_add(parse_end) as isize)
                        as *mut libc::c_char as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                };
                fflush(stdout);
                let mut fail_offset: size_t = total_read
                    .wrapping_sub(retu)
                    .wrapping_add(start_pos)
                    .wrapping_add(parse_end);
                fprintf(
                    stderr,
                    b"Failed at offset %lu: %s %c\n\0" as *const u8
                        as *const libc::c_char,
                    fail_offset,
                    json_tokener_error_desc(jerr),
                    *aterr.offset(0 as libc::c_int as isize) as libc::c_int,
                );
                json_tokener_free(tok);
                return 1 as libc::c_int;
            }
            if !obj.is_null() {
                let mut cb_ret: libc::c_int = callback
                    .expect("non-null function pointer")(obj);
                json_object_put(obj);
                if cb_ret != 0 as libc::c_int {
                    json_tokener_free(tok);
                    return 1 as libc::c_int;
                }
            }
            start_pos = (start_pos as libc::c_ulong)
                .wrapping_add((*tok).char_offset as libc::c_ulong) as size_t as size_t;
            if start_pos <= retu {} else {
                __assert_fail(
                    b"start_pos <= retu\0" as *const u8 as *const libc::c_char,
                    b"/home/xial/json-c/apps/json_parse.c\0" as *const u8
                        as *const libc::c_char,
                    119 as libc::c_int as libc::c_uint,
                    (*::std::mem::transmute::<
                        &[u8; 48],
                        &[libc::c_char; 48],
                    >(b"int parseit(int, int (*)(struct json_object *))\0"))
                        .as_ptr(),
                );
            }
        }
    }
    if ret < 0 as libc::c_int as libc::c_long {
        fprintf(
            stderr,
            b"error reading fd %d: %s\n\0" as *const u8 as *const libc::c_char,
            fd,
            strerror(*__errno_location()),
        );
    }
    json_tokener_free(tok);
    return 0 as libc::c_int;
}
unsafe extern "C" fn showobj(mut new_obj: *mut json_object) -> libc::c_int {
    if new_obj.is_null() {
        fprintf(
            stderr,
            b"%s: Failed to parse\n\0" as *const u8 as *const libc::c_char,
            fname,
        );
        return 1 as libc::c_int;
    }
    printf(
        b"Successfully parsed object from %s\n\0" as *const u8 as *const libc::c_char,
        fname,
    );
    if show_output != 0 {
        let mut output: *const libc::c_char = 0 as *const libc::c_char;
        if formatted_output != 0 {
            output = json_object_to_json_string(new_obj);
        } else {
            output = json_object_to_json_string_ext(
                new_obj,
                (1 as libc::c_int) << 1 as libc::c_int,
            );
        }
        printf(b"%s\n\0" as *const u8 as *const libc::c_char, output);
    }
    showmem();
    return 0 as libc::c_int;
}
#[cold]
unsafe extern "C" fn usage(
    mut argv0: *const libc::c_char,
    mut exitval: libc::c_int,
    mut errmsg: *const libc::c_char,
) -> ! {
    let mut fp: *mut FILE = stdout;
    if exitval != 0 as libc::c_int {
        fp = stderr;
    }
    if !errmsg.is_null() {
        fprintf(fp, b"ERROR: %s\n\n\0" as *const u8 as *const libc::c_char, errmsg);
    }
    fprintf(
        fp,
        b"Usage: %s [-f] [-n] [-s]\n\0" as *const u8 as *const libc::c_char,
        argv0,
    );
    fprintf(
        fp,
        b"  -f - Format the output with JSON_C_TO_STRING_PRETTY\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(fp, b"  -n - No output\n\0" as *const u8 as *const libc::c_char);
    fprintf(
        fp,
        b"  -s - Parse in strict mode, flags:\n\0" as *const u8 as *const libc::c_char,
    );
    fprintf(
        fp,
        b"       JSON_TOKENER_STRICT|JSON_TOKENER_ALLOW_TRAILING_CHARS\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(fp, b"\nWARNING WARNING WARNING\n\0" as *const u8 as *const libc::c_char);
    fprintf(
        fp,
        b"This is a prototype, it may change or be removed at any time!\n\0" as *const u8
            as *const libc::c_char,
    );
    exit(exitval);
}
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut opt: libc::c_int = 0;
    loop {
        opt = getopt(argc, argv, b"fhns\0" as *const u8 as *const libc::c_char);
        if !(opt != -(1 as libc::c_int)) {
            break;
        }
        match opt {
            102 => {
                formatted_output = 1 as libc::c_int;
            }
            110 => {
                show_output = 0 as libc::c_int;
            }
            115 => {
                strict_mode = 1 as libc::c_int;
            }
            104 => {
                usage(
                    *argv.offset(0 as libc::c_int as isize),
                    0 as libc::c_int,
                    0 as *const libc::c_char,
                );
            }
            _ => {
                usage(
                    *argv.offset(0 as libc::c_int as isize),
                    1 as libc::c_int,
                    b"Unknown arguments\0" as *const u8 as *const libc::c_char,
                );
            }
        }
    }
    if optind >= argc {
        usage(
            *argv.offset(0 as libc::c_int as isize),
            1 as libc::c_int,
            b"Expected argument after options\0" as *const u8 as *const libc::c_char,
        );
    }
    fname = *argv.offset(optind as isize);
    let mut fd: libc::c_int = open(
        *argv.offset(optind as isize),
        0 as libc::c_int,
        0 as libc::c_int,
    );
    showmem();
    if parseit(
        fd,
        Some(showobj as unsafe extern "C" fn(*mut json_object) -> libc::c_int),
    ) != 0 as libc::c_int
    {
        exit(1 as libc::c_int);
    }
    showmem();
    exit(0 as libc::c_int);
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
