use :: libc;
extern "C" {
    pub type json_object;
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn json_object_put(obj: *mut json_object) -> i32;
    fn json_object_to_json_string(obj: *mut json_object) -> *const i8;
    fn __errno_location() -> *mut i32;
    fn _json_c_strerror(errno_in: i32) -> *mut i8;
    fn strncmp(_: *const i8, _: *const i8, _: u64) -> i32;
    fn open(__file: *const i8, __oflag: i32, _: ...) -> i32;
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn fflush(__stream: *mut FILE) -> i32;
    fn fprintf(_: *mut FILE, _: *const i8, _: ...) -> i32;
    fn printf(_: *const i8, _: ...) -> i32;
    fn snprintf(_: *mut i8, _: u64, _: *const i8, _: ...) -> i32;
    fn putchar(__c: i32) -> i32;
    fn puts(__s: *const i8) -> i32;
    fn malloc(_: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn exit(_: i32) -> !;
    fn lseek(__fd: i32, __offset: __off_t, __whence: i32) -> __off_t;
    fn close(__fd: i32) -> i32;
    fn read(__fd: i32, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn dup2(__fd: i32, __fd2: i32) -> i32;
    fn __assert_fail(
        __assertion: *const i8,
        __file: *const i8,
        __line: u32,
        __function: *const i8,
    ) -> !;
    fn fstat(__fd: i32, __buf: *mut stat) -> i32;
    fn json_c_version() -> *const i8;
    fn json_c_version_num() -> i32;
    fn json_tokener_parse(str: *const i8) -> *mut json_object;
    fn json_object_from_file(filename: *const i8) -> *mut json_object;
    fn json_object_from_fd_ex(fd: i32, depth: i32) -> *mut json_object;
    fn json_object_from_fd(fd: i32) -> *mut json_object;
    fn json_object_to_file(filename: *const i8, obj: *mut json_object) -> i32;
    fn json_object_to_file_ext(filename: *const i8, obj: *mut json_object, flags: i32) -> i32;
    fn json_object_to_fd(fd: i32, obj: *mut json_object, flags: i32) -> i32;
    fn json_util_get_last_err() -> *const i8;
}
pub type __dev_t = u64;
pub type __uid_t = u32;
pub type __gid_t = u32;
pub type __ino_t = u64;
pub type __mode_t = u32;
pub type __nlink_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __time_t = i64;
pub type __blksize_t = i64;
pub type __blkcnt_t = i64;
pub type __ssize_t = i64;
pub type __syscall_slong_t = i64;
pub type size_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stat {
    pub st_dev: __dev_t,
    pub st_ino: __ino_t,
    pub st_nlink: __nlink_t,
    pub st_mode: __mode_t,
    pub st_uid: __uid_t,
    pub st_gid: __gid_t,
    pub __pad0: i32,
    pub st_rdev: __dev_t,
    pub st_size: __off_t,
    pub st_blksize: __blksize_t,
    pub st_blocks: __blkcnt_t,
    pub st_atim: timespec,
    pub st_mtim: timespec,
    pub st_ctim: timespec,
    pub __glibc_reserved: [__syscall_slong_t; 3],
}
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
extern "C" fn test_write_to_file() {
    let mut jso: *mut json_object = 0 as *mut json_object;
    jso = unsafe { json_tokener_parse (b"{\"foo\":1234,\"foo1\":\"abcdefghijklmnopqrstuvwxyz\",\"foo2\":\"abcdefghijklmnopqrstuvwxyz\",\"foo3\":\"abcdefghijklmnopqrstuvwxyz\",\"foo4\":\"abcdefghijklmnopqrstuvwxyz\",\"foo5\":\"abcdefghijklmnopqrstuvwxyz\",\"foo6\":\"abcdefghijklmnopqrstuvwxyz\",\"foo7\":\"abcdefghijklmnopqrstuvwxyz\",\"foo8\":\"abcdefghijklmnopqrstuvwxyz\",\"foo9\":\"abcdefghijklmnopqrstuvwxyz\"}\0" as * const u8 as * const i8 ,) } ;
    let mut outfile: *const i8 = b"json.out\0" as *const u8 as *const i8;
    let mut rv: i32 = unsafe { json_object_to_file(outfile, jso) };
    (unsafe { printf(
        b"%s: json_object_to_file(%s, jso)=%d\n\0" as *const u8 as *const i8,
        if rv == 0 as i32 {
            b"OK\0" as *const u8 as *const i8
        } else {
            b"FAIL\0" as *const u8 as *const i8
        },
        outfile,
        rv,
    ) });
    if rv == 0 as i32 {
        stat_and_cat(outfile);
    }
    (unsafe { putchar('\n' as i32) });
    let mut outfile2: *const i8 = b"json2.out\0" as *const u8 as *const i8;
    rv = unsafe { json_object_to_file_ext(outfile2, jso, (1 as i32) << 1 as i32) };
    (unsafe { printf(
        b"%s: json_object_to_file_ext(%s, jso, JSON_C_TO_STRING_PRETTY)=%d\n\0" as *const u8
            as *const i8,
        if rv == 0 as i32 {
            b"OK\0" as *const u8 as *const i8
        } else {
            b"FAIL\0" as *const u8 as *const i8
        },
        outfile2,
        rv,
    ) });
    if rv == 0 as i32 {
        stat_and_cat(outfile2);
    }
    let mut outfile3: *const i8 = b"json3.out\0" as *const u8 as *const i8;
    let mut d: i32 = unsafe { open(outfile3, 0o1 as i32 | 0o100 as i32, 0o600 as i32) };
    if d < 0 as i32 {
        (unsafe { printf(
            b"FAIL: unable to open %s %s\n\0" as *const u8 as *const i8,
            outfile3,
            _json_c_strerror(*__errno_location()),
        ) });
        return;
    }
    rv = unsafe { json_object_to_fd(d, jso, (1 as i32) << 1 as i32) };
    (unsafe { printf(
        b"%s: json_object_to_fd(%s, jso, JSON_C_TO_STRING_PRETTY)=%d\n\0" as *const u8 as *const i8,
        if rv == 0 as i32 {
            b"OK\0" as *const u8 as *const i8
        } else {
            b"FAIL\0" as *const u8 as *const i8
        },
        outfile3,
        rv,
    ) });
    rv = unsafe { json_object_to_fd(d, jso, 0 as i32) };
    (unsafe { printf(
        b"%s: json_object_to_fd(%s, jso, JSON_C_TO_STRING_PLAIN)=%d\n\0" as *const u8 as *const i8,
        if rv == 0 as i32 {
            b"OK\0" as *const u8 as *const i8
        } else {
            b"FAIL\0" as *const u8 as *const i8
        },
        outfile3,
        rv,
    ) });
    (unsafe { close(d) });
    if rv == 0 as i32 {
        stat_and_cat(outfile3);
    }
    (unsafe { json_object_put(jso) });
}
extern "C" fn stat_and_cat(mut file: *const i8) {
    let mut sb: stat = stat {
        st_dev: 0,
        st_ino: 0,
        st_nlink: 0,
        st_mode: 0,
        st_uid: 0,
        st_gid: 0,
        __pad0: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 0,
        st_blocks: 0,
        st_atim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_mtim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_ctim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        __glibc_reserved: [0; 3],
    };
    let mut d: i32 = unsafe { open(file, 0 as i32) };
    if d < 0 as i32 {
        (unsafe { printf(
            b"FAIL: unable to open %s: %s\n\0" as *const u8 as *const i8,
            file,
            _json_c_strerror(*__errno_location()),
        ) });
        return;
    }
    if (unsafe { fstat(d, &mut sb) }) < 0 as i32 {
        (unsafe { printf(
            b"FAIL: unable to stat %s: %s\n\0" as *const u8 as *const i8,
            file,
            _json_c_strerror(*__errno_location()),
        ) });
        (unsafe { close(d) });
        return;
    }
    let mut buf: *mut i8 = (unsafe { malloc((sb.st_size + 1 as i32 as i64) as u64) }) as *mut i8;
    if buf.is_null() {
        (unsafe { printf(b"FAIL: unable to allocate memory\n\0" as *const u8 as *const i8) });
        (unsafe { close(d) });
        return;
    }
    if (unsafe { read(d, buf as *mut libc::c_void, sb.st_size as size_t) }) < sb.st_size {
        (unsafe { printf(
            b"FAIL: unable to read all of %s: %s\n\0" as *const u8 as *const i8,
            file,
            _json_c_strerror(*__errno_location()),
        ) });
        (unsafe { free(buf as *mut libc::c_void) });
        (unsafe { close(d) });
        return;
    }
    (unsafe { *buf.offset(sb.st_size as isize) = '\u{0}' as i32 as i8 });
    (unsafe { printf(
        b"file[%s], size=%d, contents=%s\n\0" as *const u8 as *const i8,
        file,
        sb.st_size as i32,
        buf,
    ) });
    (unsafe { free(buf as *mut libc::c_void) });
    (unsafe { close(d) });
}
fn main_0(mut argc: i32, mut argv: *mut *mut i8) -> i32 {
    let mut testdir: *const i8 = 0 as *const i8;
    if argc < 2 as i32 {
        (unsafe { fprintf(
            stderr,
            b"Usage: %s <testdir>\n  <testdir> is the location of input files\n\0" as *const u8
                as *const i8,
            *argv.offset(0 as i32 as isize),
        ) });
        return 1 as i32;
    }
    testdir = unsafe { *argv.offset(1 as i32 as isize) };
    if (unsafe { strncmp(
        json_c_version(),
        b"0.16.99\0" as *const u8 as *const i8,
        ::std::mem::size_of::<[i8; 8]>() as u64,
    ) }) != 0
    {
        (unsafe { printf(
            b"FAIL: Output from json_c_version(): %s does not match %s\0" as *const u8 as *const i8,
            json_c_version(),
            b"0.16.99\0" as *const u8 as *const i8,
        ) });
        return 1 as i32;
    }
    if (unsafe { json_c_version_num() }) != (0 as i32) << 16 as i32 | (16 as i32) << 8 as i32 | 99 as i32 {
        (unsafe { printf(
            b"FAIL: Output from json_c_version_num(): %d does not match %d\0" as *const u8
                as *const i8,
            json_c_version_num(),
            (0 as i32) << 16 as i32 | (16 as i32) << 8 as i32 | 99 as i32,
        ) });
        return 1 as i32;
    }
    test_read_valid_with_fd(testdir);
    test_read_valid_nested_with_fd(testdir);
    test_read_nonexistant();
    test_read_closed();
    test_write_to_file();
    test_read_fd_equal(testdir);
    return 0 as i32;
}
extern "C" fn test_read_valid_with_fd(mut testdir: *const i8) {
    let mut filename: [i8; 4096] = [0; 4096];
    (unsafe { snprintf(
        filename.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 4096]>() as u64,
        b"%s/valid.json\0" as *const u8 as *const i8,
        testdir,
    ) });
    let mut d: i32 = unsafe { open(filename.as_mut_ptr(), 0 as i32) };
    if d < 0 as i32 {
        (unsafe { fprintf(
            stderr,
            b"FAIL: unable to open %s: %s\n\0" as *const u8 as *const i8,
            filename.as_mut_ptr(),
            _json_c_strerror(*__errno_location()),
        ) });
        (unsafe { exit(1 as i32) });
    }
    let mut jso: *mut json_object = unsafe { json_object_from_fd(d) };
    if !jso.is_null() {
        (unsafe { printf(
            b"OK: json_object_from_fd(valid.json)=%s\n\0" as *const u8 as *const i8,
            json_object_to_json_string(jso),
        ) });
        (unsafe { json_object_put(jso) });
    } else {
        (unsafe { fprintf(
            stderr,
            b"FAIL: unable to parse contents of %s: %s\n\0" as *const u8 as *const i8,
            filename.as_mut_ptr(),
            json_util_get_last_err(),
        ) });
    }
    (unsafe { close(d) });
}
extern "C" fn test_read_valid_nested_with_fd(mut testdir: *const i8) {
    let mut filename: [i8; 4096] = [0; 4096];
    (unsafe { snprintf(
        filename.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 4096]>() as u64,
        b"%s/valid_nested.json\0" as *const u8 as *const i8,
        testdir,
    ) });
    let mut d: i32 = unsafe { open(filename.as_mut_ptr(), 0 as i32) };
    if d < 0 as i32 {
        (unsafe { fprintf(
            stderr,
            b"FAIL: unable to open %s: %s\n\0" as *const u8 as *const i8,
            filename.as_mut_ptr(),
            _json_c_strerror(*__errno_location()),
        ) });
        (unsafe { exit(1 as i32) });
    }
    if (unsafe { json_object_from_fd_ex(d, -(2 as i32)) }).is_null() {
    } else {
        (unsafe { __assert_fail(
            b"NULL == json_object_from_fd_ex(d, -2)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_util_file.c\0" as *const u8 as *const i8,
            205 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 50], &[i8; 50]>(
                b"void test_read_valid_nested_with_fd(const char *)\0",
            ))
            .as_ptr(),
        ) });
    }
    let mut jso: *mut json_object = unsafe { json_object_from_fd_ex(d, 20 as i32) };
    if !jso.is_null() {
        (unsafe { printf(
            b"OK: json_object_from_fd_ex(valid_nested.json, 20)=%s\n\0" as *const u8 as *const i8,
            json_object_to_json_string(jso),
        ) });
        (unsafe { json_object_put(jso) });
    } else {
        (unsafe { fprintf(
            stderr,
            b"FAIL: unable to parse contents of %s: %s\n\0" as *const u8 as *const i8,
            filename.as_mut_ptr(),
            json_util_get_last_err(),
        ) });
    }
    (unsafe { lseek(d, 0 as i32 as __off_t, 0 as i32) });
    jso = unsafe { json_object_from_fd_ex(d, 3 as i32) };
    if !jso.is_null() {
        (unsafe { printf(
            b"FAIL: json_object_from_fd_ex(%s, 3)=%s\n\0" as *const u8 as *const i8,
            filename.as_mut_ptr(),
            json_object_to_json_string(jso),
        ) });
        (unsafe { json_object_put(jso) });
    } else {
        (unsafe { printf (b"OK: correctly unable to parse contents of valid_nested.json with low max depth: %s\n\0" as * const u8 as * const i8 , json_util_get_last_err () ,) }) ;
    }
    (unsafe { close(d) });
}
extern "C" fn test_read_nonexistant() {
    let mut filename: *const i8 = b"./not_present.json\0" as *const u8 as *const i8;
    let mut jso: *mut json_object = unsafe { json_object_from_file(filename) };
    if !jso.is_null() {
        (unsafe { printf(
            b"FAIL: json_object_from_file(%s) returned %p when NULL expected\n\0" as *const u8
                as *const i8,
            filename,
            jso as *mut libc::c_void,
        ) });
        (unsafe { json_object_put(jso) });
    } else {
        (unsafe { printf(
            b"OK: json_object_from_file(%s) correctly returned NULL: %s\n\0" as *const u8
                as *const i8,
            filename,
            json_util_get_last_err(),
        ) });
    };
}
extern "C" fn test_read_closed() {
    let mut d: i32 = unsafe { open(b"/dev/null\0" as *const u8 as *const i8, 0 as i32) };
    if d < 0 as i32 {
        (unsafe { puts(b"FAIL: unable to open\0" as *const u8 as *const i8) });
    }
    let mut fixed_d: i32 = 10 as i32;
    if (unsafe { dup2(d, fixed_d) }) < 0 as i32 {
        (unsafe { printf(
            b"FAIL: unable to dup to fd %d\0" as *const u8 as *const i8,
            fixed_d,
        ) });
    }
    (unsafe { close(d) });
    (unsafe { close(fixed_d) });
    let mut jso: *mut json_object = unsafe { json_object_from_fd(fixed_d) };
    if !jso.is_null() {
        (unsafe { printf(
            b"FAIL: read from closed fd returning non-NULL: %p\n\0" as *const u8 as *const i8,
            jso as *mut libc::c_void,
        ) });
        (unsafe { fflush(stdout) });
        (unsafe { printf(
            b"  jso=%s\n\0" as *const u8 as *const i8,
            json_object_to_json_string(jso),
        ) });
        (unsafe { json_object_put(jso) });
        return;
    }
    (unsafe { printf(
        b"OK: json_object_from_fd(closed_fd), expecting NULL, EBADF, got:NULL, %s\n\0" as *const u8
            as *const i8,
        json_util_get_last_err(),
    ) });
}
extern "C" fn test_read_fd_equal(mut testdir: *const i8) {
    let mut filename: [i8; 4096] = [0; 4096];
    (unsafe { snprintf(
        filename.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 4096]>() as u64,
        b"%s/valid_nested.json\0" as *const u8 as *const i8,
        testdir,
    ) });
    let mut jso: *mut json_object = unsafe { json_object_from_file(filename.as_mut_ptr()) };
    let mut d: i32 = unsafe { open(filename.as_mut_ptr(), 0 as i32) };
    if d < 0 as i32 {
        (unsafe { fprintf(
            stderr,
            b"FAIL: unable to open %s: %s\n\0" as *const u8 as *const i8,
            filename.as_mut_ptr(),
            _json_c_strerror(*__errno_location()),
        ) });
        (unsafe { exit(1 as i32) });
    }
    let mut new_jso: *mut json_object = unsafe { json_object_from_fd(d) };
    (unsafe { close(d) });
    (unsafe { printf(
        b"OK: json_object_from_file(valid.json)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(jso),
    ) });
    (unsafe { printf(
        b"OK: json_object_from_fd(valid.json)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(new_jso),
    ) });
    (unsafe { json_object_put(jso) });
    (unsafe { json_object_put(new_jso) });
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
