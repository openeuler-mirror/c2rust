use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    
    fn __errno_location() -> *mut libc::c_int;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn getrandom(
        __buffer: *mut libc::c_void,
        __length: size_t,
        __flags: libc::c_uint,
    ) -> ssize_t;
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...) -> libc::c_int;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn stat(__file: *const libc::c_char, __buf: *mut stat) -> libc::c_int;
    fn time(__timer: *mut time_t) -> time_t;
}
pub use crate::strerror_override::_json_c_strerror;
pub type time_t = __time_t;
pub use crate::apps::json_parse::__time_t;
pub use crate::apps::json_parse::FILE;
// #[derive(Copy, Clone)]

pub use crate::apps::json_parse::_IO_FILE;
pub use crate::apps::json_parse::size_t;
pub use crate::apps::json_parse::__off64_t;
pub use crate::apps::json_parse::_IO_lock_t;
pub use crate::apps::json_parse::__off_t;
pub use crate::apps::json_parse::ssize_t;
pub use crate::apps::json_parse::__ssize_t;
pub type __mode_t = libc::c_uint;
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
pub use crate::apps::json_parse::__syscall_slong_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
pub type __blkcnt_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __dev_t = libc::c_ulong;
pub type __gid_t = libc::c_uint;
pub type __uid_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __ino_t = libc::c_ulong;
unsafe extern "C" fn get_getrandom_seed(mut seed: *mut libc::c_int) -> libc::c_int {
    let mut ret: ssize_t = 0;
    loop {
        ret = getrandom(
            seed as *mut libc::c_void,
            ::std::mem::size_of::<libc::c_int>() as libc::c_ulong,
            0x1 as libc::c_int as libc::c_uint,
        );
        if !(ret == -(1 as libc::c_int) as libc::c_long
            && *__errno_location() == 4 as libc::c_int)
        {
            break;
        }
    }
    if ret == -(1 as libc::c_int) as libc::c_long {
        if *__errno_location() == 38 as libc::c_int {
            return -(1 as libc::c_int);
        }
        if *__errno_location() == 11 as libc::c_int {
            return -(1 as libc::c_int);
        }
        fprintf(
            stderr,
            b"error from getrandom(): %s\0" as *const u8 as *const libc::c_char,
            _json_c_strerror(*__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if ret as libc::c_ulong != ::std::mem::size_of::<libc::c_int>() as libc::c_ulong {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
static mut dev_random_file: *const libc::c_char = b"/dev/urandom\0" as *const u8
    as *const libc::c_char;
unsafe extern "C" fn get_dev_random_seed(mut seed: *mut libc::c_int) -> libc::c_int {
    let mut buf: stat = stat {
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
    if stat(dev_random_file, &mut buf) != 0 {
        return -(1 as libc::c_int);
    }
    if buf.st_mode & 0o20000 as libc::c_int as libc::c_uint
        == 0 as libc::c_int as libc::c_uint
    {
        return -(1 as libc::c_int);
    }
    let mut fd: libc::c_int = open(dev_random_file, 0 as libc::c_int);
    if fd < 0 as libc::c_int {
        fprintf(
            stderr,
            b"error opening %s: %s\0" as *const u8 as *const libc::c_char,
            dev_random_file,
            _json_c_strerror(*__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    let mut nread: ssize_t = read(
        fd,
        seed as *mut libc::c_void,
        ::std::mem::size_of::<libc::c_int>() as libc::c_ulong,
    );
    close(fd);
    if nread as libc::c_ulong != ::std::mem::size_of::<libc::c_int>() as libc::c_ulong {
        fprintf(
            stderr,
            b"error short read %s: %s\0" as *const u8 as *const libc::c_char,
            dev_random_file,
            _json_c_strerror(*__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn get_time_seed() -> libc::c_int {
    return (time(0 as *mut time_t) as libc::c_uint)
        .wrapping_mul(433494437 as libc::c_int as libc::c_uint) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn json_c_get_random_seed() -> libc::c_int {
    let mut seed: libc::c_int = 0 as libc::c_int;
    if get_getrandom_seed(&mut seed) == 0 as libc::c_int {
        return seed;
    }
    let mut seed_0: libc::c_int = 0 as libc::c_int;
    if get_dev_random_seed(&mut seed_0) == 0 as libc::c_int {
        return seed_0;
    }
    return get_time_seed();
}
