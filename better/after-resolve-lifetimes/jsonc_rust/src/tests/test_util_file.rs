use ::libc;
extern "C" {
    
    
    
    
    
    
    fn __errno_location() -> * mut i32;
    
    fn strncmp(
        _: * const i8,
        _: * const i8,
        _: u64,
    ) -> i32;
    fn open(__file: * const i8, __oflag: i32, _: ...) -> i32;
    static mut stdout: * mut crate::src::apps::json_parse::_IO_FILE;
    static mut stderr: * mut crate::src::apps::json_parse::_IO_FILE;
    fn fflush(__stream: * mut crate::src::apps::json_parse::_IO_FILE) -> i32;
    fn fprintf(_: * mut crate::src::apps::json_parse::_IO_FILE, _: * const i8, _: ...) -> i32;
    fn printf(_: * const i8, _: ...) -> i32;
    fn snprintf(
        _: * mut i8,
        _: u64,
        _: * const i8,
        _: ...
    ) -> i32;
    fn putchar(__c: i32) -> i32;
    fn puts(__s: * const i8) -> i32;
    fn malloc(_: u64) -> * mut core::ffi::c_void;
    fn free(__ptr: * mut core::ffi::c_void);
    fn exit(_: i32) -> !;
    fn lseek(__fd: i32, __offset: i64, __whence: i32) -> i64;
    fn close(__fd: i32) -> i32;
    fn read(__fd: i32, __buf: * mut core::ffi::c_void, __nbytes: u64) -> i64;
    fn dup2(__fd: i32, __fd2: i32) -> i32;
    fn __assert_fail(
        __assertion: * const i8,
        __file: * const i8,
        __line: u32,
        __function: * const i8,
    ) -> !;
    fn fstat(__fd: i32, __buf: * mut crate::src::random_seed::stat) -> i32;
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::json_c_version::json_c_version;
pub use crate::src::json_c_version::json_c_version_num;
pub use crate::src::json_object::json_object_put;
pub use crate::src::json_object::json_object_to_json_string;
pub use crate::src::json_tokener::json_tokener_parse;
pub use crate::src::json_util::json_object_from_fd;
pub use crate::src::json_util::json_object_from_fd_ex;
pub use crate::src::json_util::json_object_from_file;
pub use crate::src::json_util::json_object_to_fd;
pub use crate::src::json_util::json_object_to_file;
pub use crate::src::json_util::json_object_to_file_ext;
pub use crate::src::json_util::json_util_get_last_err;
pub use crate::src::strerror_override::_json_c_strerror;
pub use crate::src::json_object::json_object;
pub use crate::src::debug::_IO_wide_data;
pub use crate::src::json_object::_IO_codecvt;
pub use crate::src::json_visit::_IO_marker;
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
// #[derive(Copy, Clone)]

pub type timespec = crate::src::random_seed::timespec;
// #[derive(Copy, Clone)]

pub type stat = crate::src::random_seed::stat;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::apps::json_parse::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::apps::json_parse::_IO_FILE;
pub type ssize_t = i64;
unsafe extern "C" fn test_write_to_file() {
    let mut jso: * mut crate::src::json_object::json_object = 0 as *mut json_object;
    jso = json_tokener_parse(
        b"{\"foo\":1234,\"foo1\":\"abcdefghijklmnopqrstuvwxyz\",\"foo2\":\"abcdefghijklmnopqrstuvwxyz\",\"foo3\":\"abcdefghijklmnopqrstuvwxyz\",\"foo4\":\"abcdefghijklmnopqrstuvwxyz\",\"foo5\":\"abcdefghijklmnopqrstuvwxyz\",\"foo6\":\"abcdefghijklmnopqrstuvwxyz\",\"foo7\":\"abcdefghijklmnopqrstuvwxyz\",\"foo8\":\"abcdefghijklmnopqrstuvwxyz\",\"foo9\":\"abcdefghijklmnopqrstuvwxyz\"}\0"
            as *const u8 as *const i8,
    );
    let mut outfile: * const i8 = b"json.out\0" as *const u8
        as *const i8;
    let mut rv: i32 = json_object_to_file(outfile, jso);
    printf(
        b"%s: json_object_to_file(%s, jso)=%d\n\0" as *const u8 as *const i8,
        if rv == 0 as i32 {
            b"OK\0" as *const u8 as *const i8
        } else {
            b"FAIL\0" as *const u8 as *const i8
        },
        outfile,
        rv,
    );
    if rv == 0 as i32 {
        stat_and_cat(outfile);
    }
    putchar('\n' as i32);
    let mut outfile2: * const i8 = b"json2.out\0" as *const u8
        as *const i8;
    rv = json_object_to_file_ext(outfile2, jso, (1 as i32) << 1 as i32);
    printf(
        b"%s: json_object_to_file_ext(%s, jso, JSON_C_TO_STRING_PRETTY)=%d\n\0"
            as *const u8 as *const i8,
        if rv == 0 as i32 {
            b"OK\0" as *const u8 as *const i8
        } else {
            b"FAIL\0" as *const u8 as *const i8
        },
        outfile2,
        rv,
    );
    if rv == 0 as i32 {
        stat_and_cat(outfile2);
    }
    let mut outfile3: * const i8 = b"json3.out\0" as *const u8
        as *const i8;
    let mut d: i32 = open(
        outfile3,
        0o1 as i32 | 0o100 as i32,
        0o600 as i32,
    );
    if d < 0 as i32 {
        printf(
            b"FAIL: unable to open %s %s\n\0" as *const u8 as *const i8,
            outfile3,
            _json_c_strerror(*__errno_location()),
        );
        return;
    }
    rv = json_object_to_fd(d, jso, (1 as i32) << 1 as i32);
    printf(
        b"%s: json_object_to_fd(%s, jso, JSON_C_TO_STRING_PRETTY)=%d\n\0" as *const u8
            as *const i8,
        if rv == 0 as i32 {
            b"OK\0" as *const u8 as *const i8
        } else {
            b"FAIL\0" as *const u8 as *const i8
        },
        outfile3,
        rv,
    );
    rv = json_object_to_fd(d, jso, 0 as i32);
    printf(
        b"%s: json_object_to_fd(%s, jso, JSON_C_TO_STRING_PLAIN)=%d\n\0" as *const u8
            as *const i8,
        if rv == 0 as i32 {
            b"OK\0" as *const u8 as *const i8
        } else {
            b"FAIL\0" as *const u8 as *const i8
        },
        outfile3,
        rv,
    );
    close(d);
    if rv == 0 as i32 {
        stat_and_cat(outfile3);
    }
    json_object_put(jso);
}
unsafe extern "C" fn stat_and_cat(mut file: * const i8) {
    let mut sb: crate::src::random_seed::stat = stat {
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
    let mut d: i32 = open(file, 0 as i32);
    if d < 0 as i32 {
        printf(
            b"FAIL: unable to open %s: %s\n\0" as *const u8 as *const i8,
            file,
            _json_c_strerror(*__errno_location()),
        );
        return;
    }
    if fstat(d, &mut sb) < 0 as i32 {
        printf(
            b"FAIL: unable to stat %s: %s\n\0" as *const u8 as *const i8,
            file,
            _json_c_strerror(*__errno_location()),
        );
        close(d);
        return;
    }
    let mut buf: * mut i8 = malloc(
        (sb.st_size + 1 as i32 as i64) as u64,
    ) as *mut i8;
    if buf.is_null() {
        printf(
            b"FAIL: unable to allocate memory\n\0" as *const u8 as *const i8,
        );
        close(d);
        return;
    }
    if read(d, buf as *mut libc::c_void, sb.st_size as size_t) < sb.st_size {
        printf(
            b"FAIL: unable to read all of %s: %s\n\0" as *const u8
                as *const i8,
            file,
            _json_c_strerror(*__errno_location()),
        );
        free(buf as *mut libc::c_void);
        close(d);
        return;
    }
    *buf.offset(sb.st_size as isize) = '\u{0}' as i32 as i8;
    printf(
        b"file[%s], size=%d, contents=%s\n\0" as *const u8 as *const i8,
        file,
        sb.st_size as i32,
        buf,
    );
    free(buf as *mut libc::c_void);
    close(d);
}
unsafe fn main_0(
    mut argc: i32,
    mut argv: * mut * mut i8,
) -> i32 {
    let mut testdir: * const i8 = 0 as *const i8;
    if argc < 2 as i32 {
        fprintf(
            stderr,
            b"Usage: %s <testdir>\n  <testdir> is the location of input files\n\0"
                as *const u8 as *const i8,
            *argv.offset(0 as i32 as isize),
        );
        return 1 as i32;
    }
    testdir = *argv.offset(1 as i32 as isize);
    if strncmp(
        json_c_version(),
        b"0.16.99\0" as *const u8 as *const i8,
        ::std::mem::size_of::<[i8; 8]>() as u64,
    ) != 0
    {
        printf(
            b"FAIL: Output from json_c_version(): %s does not match %s\0" as *const u8
                as *const i8,
            json_c_version(),
            b"0.16.99\0" as *const u8 as *const i8,
        );
        return 1 as i32;
    }
    if json_c_version_num()
        != (0 as i32) << 16 as i32
            | (16 as i32) << 8 as i32 | 99 as i32
    {
        printf(
            b"FAIL: Output from json_c_version_num(): %d does not match %d\0"
                as *const u8 as *const i8,
            json_c_version_num(),
            (0 as i32) << 16 as i32
                | (16 as i32) << 8 as i32 | 99 as i32,
        );
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
unsafe extern "C" fn test_read_valid_with_fd(mut testdir: * const i8) {
    let mut filename: [i8; 4096] = [0; 4096];
    snprintf(
        filename.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 4096]>() as u64,
        b"%s/valid.json\0" as *const u8 as *const i8,
        testdir,
    );
    let mut d: i32 = open(filename.as_mut_ptr(), 0 as i32);
    if d < 0 as i32 {
        fprintf(
            stderr,
            b"FAIL: unable to open %s: %s\n\0" as *const u8 as *const i8,
            filename.as_mut_ptr(),
            _json_c_strerror(*__errno_location()),
        );
        exit(1 as i32);
    }
    let mut jso: * mut crate::src::json_object::json_object = json_object_from_fd(d);
    if !jso.is_null() {
        printf(
            b"OK: json_object_from_fd(valid.json)=%s\n\0" as *const u8
                as *const i8,
            json_object_to_json_string(jso),
        );
        json_object_put(jso);
    } else {
        fprintf(
            stderr,
            b"FAIL: unable to parse contents of %s: %s\n\0" as *const u8
                as *const i8,
            filename.as_mut_ptr(),
            json_util_get_last_err(),
        );
    }
    close(d);
}
unsafe extern "C" fn test_read_valid_nested_with_fd(mut testdir: * const i8) {
    let mut filename: [i8; 4096] = [0; 4096];
    snprintf(
        filename.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 4096]>() as u64,
        b"%s/valid_nested.json\0" as *const u8 as *const i8,
        testdir,
    );
    let mut d: i32 = open(filename.as_mut_ptr(), 0 as i32);
    if d < 0 as i32 {
        fprintf(
            stderr,
            b"FAIL: unable to open %s: %s\n\0" as *const u8 as *const i8,
            filename.as_mut_ptr(),
            _json_c_strerror(*__errno_location()),
        );
        exit(1 as i32);
    }
    if (json_object_from_fd_ex(d, -(2 as i32))).is_null() {} else {
        __assert_fail(
            b"NULL == json_object_from_fd_ex(d, -2)\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_util_file.c\0" as *const u8
                as *const i8,
            205 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 50], &'_ [i8; 50]>(b"void test_read_valid_nested_with_fd(const char *)\0"))
                .as_ptr(),
        );
    }
    let mut jso: * mut crate::src::json_object::json_object = json_object_from_fd_ex(d, 20 as i32);
    if !jso.is_null() {
        printf(
            b"OK: json_object_from_fd_ex(valid_nested.json, 20)=%s\n\0" as *const u8
                as *const i8,
            json_object_to_json_string(jso),
        );
        json_object_put(jso);
    } else {
        fprintf(
            stderr,
            b"FAIL: unable to parse contents of %s: %s\n\0" as *const u8
                as *const i8,
            filename.as_mut_ptr(),
            json_util_get_last_err(),
        );
    }
    lseek(d, 0 as i32 as __off_t, 0 as i32);
    jso = json_object_from_fd_ex(d, 3 as i32);
    if !jso.is_null() {
        printf(
            b"FAIL: json_object_from_fd_ex(%s, 3)=%s\n\0" as *const u8
                as *const i8,
            filename.as_mut_ptr(),
            json_object_to_json_string(jso),
        );
        json_object_put(jso);
    } else {
        printf(
            b"OK: correctly unable to parse contents of valid_nested.json with low max depth: %s\n\0"
                as *const u8 as *const i8,
            json_util_get_last_err(),
        );
    }
    close(d);
}
unsafe extern "C" fn test_read_nonexistant() {
    let mut filename: * const i8 = b"./not_present.json\0" as *const u8
        as *const i8;
    let mut jso: * mut crate::src::json_object::json_object = json_object_from_file(filename);
    if !jso.is_null() {
        printf(
            b"FAIL: json_object_from_file(%s) returned %p when NULL expected\n\0"
                as *const u8 as *const i8,
            filename,
            jso as *mut libc::c_void,
        );
        json_object_put(jso);
    } else {
        printf(
            b"OK: json_object_from_file(%s) correctly returned NULL: %s\n\0" as *const u8
                as *const i8,
            filename,
            json_util_get_last_err(),
        );
    };
}
unsafe extern "C" fn test_read_closed() {
    let mut d: i32 = open(
        b"/dev/null\0" as *const u8 as *const i8,
        0 as i32,
    );
    if d < 0 as i32 {
        puts(b"FAIL: unable to open\0" as *const u8 as *const i8);
    }
    let mut fixed_d: i32 = 10 as i32;
    if dup2(d, fixed_d) < 0 as i32 {
        printf(
            b"FAIL: unable to dup to fd %d\0" as *const u8 as *const i8,
            fixed_d,
        );
    }
    close(d);
    close(fixed_d);
    let mut jso: * mut crate::src::json_object::json_object = json_object_from_fd(fixed_d);
    if !jso.is_null() {
        printf(
            b"FAIL: read from closed fd returning non-NULL: %p\n\0" as *const u8
                as *const i8,
            jso as *mut libc::c_void,
        );
        fflush(stdout);
        printf(
            b"  jso=%s\n\0" as *const u8 as *const i8,
            json_object_to_json_string(jso),
        );
        json_object_put(jso);
        return;
    }
    printf(
        b"OK: json_object_from_fd(closed_fd), expecting NULL, EBADF, got:NULL, %s\n\0"
            as *const u8 as *const i8,
        json_util_get_last_err(),
    );
}
unsafe extern "C" fn test_read_fd_equal(mut testdir: * const i8) {
    let mut filename: [i8; 4096] = [0; 4096];
    snprintf(
        filename.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 4096]>() as u64,
        b"%s/valid_nested.json\0" as *const u8 as *const i8,
        testdir,
    );
    let mut jso: * mut crate::src::json_object::json_object = json_object_from_file(filename.as_mut_ptr());
    let mut d: i32 = open(filename.as_mut_ptr(), 0 as i32);
    if d < 0 as i32 {
        fprintf(
            stderr,
            b"FAIL: unable to open %s: %s\n\0" as *const u8 as *const i8,
            filename.as_mut_ptr(),
            _json_c_strerror(*__errno_location()),
        );
        exit(1 as i32);
    }
    let mut new_jso: * mut crate::src::json_object::json_object = json_object_from_fd(d);
    close(d);
    printf(
        b"OK: json_object_from_file(valid.json)=%s\n\0" as *const u8
            as *const i8,
        json_object_to_json_string(jso),
    );
    printf(
        b"OK: json_object_from_fd(valid.json)=%s\n\0" as *const u8
            as *const i8,
        json_object_to_json_string(new_jso),
    );
    json_object_put(jso);
    json_object_put(new_jso);
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
