use ::libc;
extern "C" {
    pub type json_object;
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn json_object_put(obj: *mut json_object) -> libc::c_int;
    fn json_object_to_json_string(obj: *mut json_object) -> *const libc::c_char;
    fn __errno_location() -> *mut libc::c_int;
    fn _json_c_strerror(errno_in: libc::c_int) -> *mut libc::c_char;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...) -> libc::c_int;
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn putchar(__c: libc::c_int) -> libc::c_int;
    fn puts(__s: *const libc::c_char) -> libc::c_int;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn exit(_: libc::c_int) -> !;
    fn lseek(__fd: libc::c_int, __offset: __off_t, __whence: libc::c_int) -> __off_t;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn dup2(__fd: libc::c_int, __fd2: libc::c_int) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn fstat(__fd: libc::c_int, __buf: *mut stat) -> libc::c_int;
    fn json_c_version() -> *const libc::c_char;
    fn json_c_version_num() -> libc::c_int;
    fn json_tokener_parse(str: *const libc::c_char) -> *mut json_object;
    fn json_object_from_file(filename: *const libc::c_char) -> *mut json_object;
    fn json_object_from_fd_ex(fd: libc::c_int, depth: libc::c_int) -> *mut json_object;
    fn json_object_from_fd(fd: libc::c_int) -> *mut json_object;
    fn json_object_to_file(
        filename: *const libc::c_char,
        obj: *mut json_object,
    ) -> libc::c_int;
    fn json_object_to_file_ext(
        filename: *const libc::c_char,
        obj: *mut json_object,
        flags: libc::c_int,
    ) -> libc::c_int;
    fn json_object_to_fd(
        fd: libc::c_int,
        obj: *mut json_object,
        flags: libc::c_int,
    ) -> libc::c_int;
    fn json_util_get_last_err() -> *const libc::c_char;
}
pub type __dev_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __ino_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type size_t = libc::c_ulong;
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
    pub __pad0: libc::c_int,
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
unsafe extern "C" fn test_write_to_file() {
    let mut jso: *mut json_object = 0 as *mut json_object;
    jso = json_tokener_parse(
        b"{\"foo\":1234,\"foo1\":\"abcdefghijklmnopqrstuvwxyz\",\"foo2\":\"abcdefghijklmnopqrstuvwxyz\",\"foo3\":\"abcdefghijklmnopqrstuvwxyz\",\"foo4\":\"abcdefghijklmnopqrstuvwxyz\",\"foo5\":\"abcdefghijklmnopqrstuvwxyz\",\"foo6\":\"abcdefghijklmnopqrstuvwxyz\",\"foo7\":\"abcdefghijklmnopqrstuvwxyz\",\"foo8\":\"abcdefghijklmnopqrstuvwxyz\",\"foo9\":\"abcdefghijklmnopqrstuvwxyz\"}\0"
            as *const u8 as *const libc::c_char,
    );
    let mut outfile: *const libc::c_char = b"json.out\0" as *const u8
        as *const libc::c_char;
    let mut rv: libc::c_int = json_object_to_file(outfile, jso);
    printf(
        b"%s: json_object_to_file(%s, jso)=%d\n\0" as *const u8 as *const libc::c_char,
        if rv == 0 as libc::c_int {
            b"OK\0" as *const u8 as *const libc::c_char
        } else {
            b"FAIL\0" as *const u8 as *const libc::c_char
        },
        outfile,
        rv,
    );
    if rv == 0 as libc::c_int {
        stat_and_cat(outfile);
    }
    putchar('\n' as i32);
    let mut outfile2: *const libc::c_char = b"json2.out\0" as *const u8
        as *const libc::c_char;
    rv = json_object_to_file_ext(outfile2, jso, (1 as libc::c_int) << 1 as libc::c_int);
    printf(
        b"%s: json_object_to_file_ext(%s, jso, JSON_C_TO_STRING_PRETTY)=%d\n\0"
            as *const u8 as *const libc::c_char,
        if rv == 0 as libc::c_int {
            b"OK\0" as *const u8 as *const libc::c_char
        } else {
            b"FAIL\0" as *const u8 as *const libc::c_char
        },
        outfile2,
        rv,
    );
    if rv == 0 as libc::c_int {
        stat_and_cat(outfile2);
    }
    let mut outfile3: *const libc::c_char = b"json3.out\0" as *const u8
        as *const libc::c_char;
    let mut d: libc::c_int = open(
        outfile3,
        0o1 as libc::c_int | 0o100 as libc::c_int,
        0o600 as libc::c_int,
    );
    if d < 0 as libc::c_int {
        printf(
            b"FAIL: unable to open %s %s\n\0" as *const u8 as *const libc::c_char,
            outfile3,
            _json_c_strerror(*__errno_location()),
        );
        return;
    }
    rv = json_object_to_fd(d, jso, (1 as libc::c_int) << 1 as libc::c_int);
    printf(
        b"%s: json_object_to_fd(%s, jso, JSON_C_TO_STRING_PRETTY)=%d\n\0" as *const u8
            as *const libc::c_char,
        if rv == 0 as libc::c_int {
            b"OK\0" as *const u8 as *const libc::c_char
        } else {
            b"FAIL\0" as *const u8 as *const libc::c_char
        },
        outfile3,
        rv,
    );
    rv = json_object_to_fd(d, jso, 0 as libc::c_int);
    printf(
        b"%s: json_object_to_fd(%s, jso, JSON_C_TO_STRING_PLAIN)=%d\n\0" as *const u8
            as *const libc::c_char,
        if rv == 0 as libc::c_int {
            b"OK\0" as *const u8 as *const libc::c_char
        } else {
            b"FAIL\0" as *const u8 as *const libc::c_char
        },
        outfile3,
        rv,
    );
    close(d);
    if rv == 0 as libc::c_int {
        stat_and_cat(outfile3);
    }
    json_object_put(jso);
}
unsafe extern "C" fn stat_and_cat(mut file: *const libc::c_char) {
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
        st_atim: timespec { tv_sec: 0, tv_nsec: 0 },
        st_mtim: timespec { tv_sec: 0, tv_nsec: 0 },
        st_ctim: timespec { tv_sec: 0, tv_nsec: 0 },
        __glibc_reserved: [0; 3],
    };
    let mut d: libc::c_int = open(file, 0 as libc::c_int);
    if d < 0 as libc::c_int {
        printf(
            b"FAIL: unable to open %s: %s\n\0" as *const u8 as *const libc::c_char,
            file,
            _json_c_strerror(*__errno_location()),
        );
        return;
    }
    if fstat(d, &mut sb) < 0 as libc::c_int {
        printf(
            b"FAIL: unable to stat %s: %s\n\0" as *const u8 as *const libc::c_char,
            file,
            _json_c_strerror(*__errno_location()),
        );
        close(d);
        return;
    }
    let mut buf: *mut libc::c_char = malloc(
        (sb.st_size + 1 as libc::c_int as libc::c_long) as libc::c_ulong,
    ) as *mut libc::c_char;
    if buf.is_null() {
        printf(
            b"FAIL: unable to allocate memory\n\0" as *const u8 as *const libc::c_char,
        );
        close(d);
        return;
    }
    if read(d, buf as *mut libc::c_void, sb.st_size as size_t) < sb.st_size {
        printf(
            b"FAIL: unable to read all of %s: %s\n\0" as *const u8
                as *const libc::c_char,
            file,
            _json_c_strerror(*__errno_location()),
        );
        free(buf as *mut libc::c_void);
        close(d);
        return;
    }
    *buf.offset(sb.st_size as isize) = '\u{0}' as i32 as libc::c_char;
    printf(
        b"file[%s], size=%d, contents=%s\n\0" as *const u8 as *const libc::c_char,
        file,
        sb.st_size as libc::c_int,
        buf,
    );
    free(buf as *mut libc::c_void);
    close(d);
}
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut testdir: *const libc::c_char = 0 as *const libc::c_char;
    if argc < 2 as libc::c_int {
        fprintf(
            stderr,
            b"Usage: %s <testdir>\n  <testdir> is the location of input files\n\0"
                as *const u8 as *const libc::c_char,
            *argv.offset(0 as libc::c_int as isize),
        );
        return 1 as libc::c_int;
    }
    testdir = *argv.offset(1 as libc::c_int as isize);
    if strncmp(
        json_c_version(),
        b"0.16.99\0" as *const u8 as *const libc::c_char,
        ::std::mem::size_of::<[libc::c_char; 8]>() as libc::c_ulong,
    ) != 0
    {
        printf(
            b"FAIL: Output from json_c_version(): %s does not match %s\0" as *const u8
                as *const libc::c_char,
            json_c_version(),
            b"0.16.99\0" as *const u8 as *const libc::c_char,
        );
        return 1 as libc::c_int;
    }
    if json_c_version_num()
        != (0 as libc::c_int) << 16 as libc::c_int
            | (16 as libc::c_int) << 8 as libc::c_int | 99 as libc::c_int
    {
        printf(
            b"FAIL: Output from json_c_version_num(): %d does not match %d\0"
                as *const u8 as *const libc::c_char,
            json_c_version_num(),
            (0 as libc::c_int) << 16 as libc::c_int
                | (16 as libc::c_int) << 8 as libc::c_int | 99 as libc::c_int,
        );
        return 1 as libc::c_int;
    }
    test_read_valid_with_fd(testdir);
    test_read_valid_nested_with_fd(testdir);
    test_read_nonexistant();
    test_read_closed();
    test_write_to_file();
    test_read_fd_equal(testdir);
    return 0 as libc::c_int;
}
unsafe extern "C" fn test_read_valid_with_fd(mut testdir: *const libc::c_char) {
    let mut filename: [libc::c_char; 4096] = [0; 4096];
    snprintf(
        filename.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
        b"%s/valid.json\0" as *const u8 as *const libc::c_char,
        testdir,
    );
    let mut d: libc::c_int = open(filename.as_mut_ptr(), 0 as libc::c_int);
    if d < 0 as libc::c_int {
        fprintf(
            stderr,
            b"FAIL: unable to open %s: %s\n\0" as *const u8 as *const libc::c_char,
            filename.as_mut_ptr(),
            _json_c_strerror(*__errno_location()),
        );
        exit(1 as libc::c_int);
    }
    let mut jso: *mut json_object = json_object_from_fd(d);
    if !jso.is_null() {
        printf(
            b"OK: json_object_from_fd(valid.json)=%s\n\0" as *const u8
                as *const libc::c_char,
            json_object_to_json_string(jso),
        );
        json_object_put(jso);
    } else {
        fprintf(
            stderr,
            b"FAIL: unable to parse contents of %s: %s\n\0" as *const u8
                as *const libc::c_char,
            filename.as_mut_ptr(),
            json_util_get_last_err(),
        );
    }
    close(d);
}
unsafe extern "C" fn test_read_valid_nested_with_fd(mut testdir: *const libc::c_char) {
    let mut filename: [libc::c_char; 4096] = [0; 4096];
    snprintf(
        filename.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
        b"%s/valid_nested.json\0" as *const u8 as *const libc::c_char,
        testdir,
    );
    let mut d: libc::c_int = open(filename.as_mut_ptr(), 0 as libc::c_int);
    if d < 0 as libc::c_int {
        fprintf(
            stderr,
            b"FAIL: unable to open %s: %s\n\0" as *const u8 as *const libc::c_char,
            filename.as_mut_ptr(),
            _json_c_strerror(*__errno_location()),
        );
        exit(1 as libc::c_int);
    }
    if (json_object_from_fd_ex(d, -(2 as libc::c_int))).is_null() {} else {
        __assert_fail(
            b"NULL == json_object_from_fd_ex(d, -2)\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_util_file.c\0" as *const u8
                as *const libc::c_char,
            205 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 50],
                &[libc::c_char; 50],
            >(b"void test_read_valid_nested_with_fd(const char *)\0"))
                .as_ptr(),
        );
    }
    let mut jso: *mut json_object = json_object_from_fd_ex(d, 20 as libc::c_int);
    if !jso.is_null() {
        printf(
            b"OK: json_object_from_fd_ex(valid_nested.json, 20)=%s\n\0" as *const u8
                as *const libc::c_char,
            json_object_to_json_string(jso),
        );
        json_object_put(jso);
    } else {
        fprintf(
            stderr,
            b"FAIL: unable to parse contents of %s: %s\n\0" as *const u8
                as *const libc::c_char,
            filename.as_mut_ptr(),
            json_util_get_last_err(),
        );
    }
    lseek(d, 0 as libc::c_int as __off_t, 0 as libc::c_int);
    jso = json_object_from_fd_ex(d, 3 as libc::c_int);
    if !jso.is_null() {
        printf(
            b"FAIL: json_object_from_fd_ex(%s, 3)=%s\n\0" as *const u8
                as *const libc::c_char,
            filename.as_mut_ptr(),
            json_object_to_json_string(jso),
        );
        json_object_put(jso);
    } else {
        printf(
            b"OK: correctly unable to parse contents of valid_nested.json with low max depth: %s\n\0"
                as *const u8 as *const libc::c_char,
            json_util_get_last_err(),
        );
    }
    close(d);
}
unsafe extern "C" fn test_read_nonexistant() {
    let mut filename: *const libc::c_char = b"./not_present.json\0" as *const u8
        as *const libc::c_char;
    let mut jso: *mut json_object = json_object_from_file(filename);
    if !jso.is_null() {
        printf(
            b"FAIL: json_object_from_file(%s) returned %p when NULL expected\n\0"
                as *const u8 as *const libc::c_char,
            filename,
            jso as *mut libc::c_void,
        );
        json_object_put(jso);
    } else {
        printf(
            b"OK: json_object_from_file(%s) correctly returned NULL: %s\n\0" as *const u8
                as *const libc::c_char,
            filename,
            json_util_get_last_err(),
        );
    };
}
unsafe extern "C" fn test_read_closed() {
    let mut d: libc::c_int = open(
        b"/dev/null\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    if d < 0 as libc::c_int {
        puts(b"FAIL: unable to open\0" as *const u8 as *const libc::c_char);
    }
    let mut fixed_d: libc::c_int = 10 as libc::c_int;
    if dup2(d, fixed_d) < 0 as libc::c_int {
        printf(
            b"FAIL: unable to dup to fd %d\0" as *const u8 as *const libc::c_char,
            fixed_d,
        );
    }
    close(d);
    close(fixed_d);
    let mut jso: *mut json_object = json_object_from_fd(fixed_d);
    if !jso.is_null() {
        printf(
            b"FAIL: read from closed fd returning non-NULL: %p\n\0" as *const u8
                as *const libc::c_char,
            jso as *mut libc::c_void,
        );
        fflush(stdout);
        printf(
            b"  jso=%s\n\0" as *const u8 as *const libc::c_char,
            json_object_to_json_string(jso),
        );
        json_object_put(jso);
        return;
    }
    printf(
        b"OK: json_object_from_fd(closed_fd), expecting NULL, EBADF, got:NULL, %s\n\0"
            as *const u8 as *const libc::c_char,
        json_util_get_last_err(),
    );
}
unsafe extern "C" fn test_read_fd_equal(mut testdir: *const libc::c_char) {
    let mut filename: [libc::c_char; 4096] = [0; 4096];
    snprintf(
        filename.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
        b"%s/valid_nested.json\0" as *const u8 as *const libc::c_char,
        testdir,
    );
    let mut jso: *mut json_object = json_object_from_file(filename.as_mut_ptr());
    let mut d: libc::c_int = open(filename.as_mut_ptr(), 0 as libc::c_int);
    if d < 0 as libc::c_int {
        fprintf(
            stderr,
            b"FAIL: unable to open %s: %s\n\0" as *const u8 as *const libc::c_char,
            filename.as_mut_ptr(),
            _json_c_strerror(*__errno_location()),
        );
        exit(1 as libc::c_int);
    }
    let mut new_jso: *mut json_object = json_object_from_fd(d);
    close(d);
    printf(
        b"OK: json_object_from_file(valid.json)=%s\n\0" as *const u8
            as *const libc::c_char,
        json_object_to_json_string(jso),
    );
    printf(
        b"OK: json_object_from_fd(valid.json)=%s\n\0" as *const u8
            as *const libc::c_char,
        json_object_to_json_string(new_jso),
    );
    json_object_put(jso);
    json_object_put(new_jso);
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
