use :: libc;
extern "C" {
    fn __errno_location() -> *mut i32;
    static mut stderr: *mut crate::src::apps::json_parse::_IO_FILE;
    fn fprintf(_: *mut crate::src::apps::json_parse::_IO_FILE, _: *const i8, _: ...) -> i32;
    fn getrandom(__buffer: *mut core::ffi::c_void, __length: u64, __flags: u32) -> i64;
    fn open(__file: *const i8, __oflag: i32, _: ...) -> i32;
    fn close(__fd: i32) -> i32;
    fn read(__fd: i32, __buf: *mut core::ffi::c_void, __nbytes: u64) -> i64;
    fn stat(__file: *const i8, __buf: *mut crate::src::random_seed::stat) -> i32;
    fn time(__timer: *mut i64) -> i64;
}
pub use crate::src::{
    debug::_IO_wide_data, json_object::_IO_codecvt, json_visit::_IO_marker,
    strerror_override::_json_c_strerror,
};
pub type time_t = i64;
pub type __time_t = i64;
pub type FILE = crate::src::apps::json_parse::_IO_FILE;
pub type _IO_FILE = crate::src::apps::json_parse::_IO_FILE;
pub type size_t = u64;
pub type __off64_t = i64;
pub type _IO_lock_t = ();
pub type __off_t = i64;
pub type ssize_t = i64;
pub type __ssize_t = i64;
pub type __mode_t = u32;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: i32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atim: crate::src::random_seed::timespec,
    pub st_mtim: crate::src::random_seed::timespec,
    pub st_ctim: crate::src::random_seed::timespec,
    pub __glibc_reserved: [i64; 3],
}
impl stat {
    pub const fn new() -> Self {
        stat {
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
            st_atim: crate::src::random_seed::timespec::new(),
            st_mtim: crate::src::random_seed::timespec::new(),
            st_ctim: crate::src::random_seed::timespec::new(),
            __glibc_reserved: [0, 0, 0],
        }
    }
}
impl std::default::Default for stat {
    fn default() -> Self {
        stat::new()
    }
}
pub type __syscall_slong_t = i64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}
impl timespec {
    pub const fn new() -> Self {
        timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }
    }
}
impl std::default::Default for timespec {
    fn default() -> Self {
        timespec::new()
    }
}
pub type __blkcnt_t = i64;
pub type __blksize_t = i64;
pub type __dev_t = u64;
pub type __gid_t = u32;
pub type __uid_t = u32;
pub type __nlink_t = u64;
pub type __ino_t = u64;
extern "C" fn get_getrandom_seed(mut seed: *mut i32) -> i32 {
    let mut ret: i64 = 0;
    loop {
        ret = unsafe { getrandom(
            seed as *mut libc::c_void,
            ::std::mem::size_of::<i32>() as u64,
            0x1 as i32 as u32,
        ) };
        if !(ret == -(1 as i32) as i64 && (unsafe { *__errno_location() }) == 4 as i32) {
            break;
        }
    }
    if ret == -(1 as i32) as i64 {
        if (unsafe { *__errno_location() }) == 38 as i32 {
            return -(1 as i32);
        }
        if (unsafe { *__errno_location() }) == 11 as i32 {
            return -(1 as i32);
        }
        (unsafe { fprintf(
            stderr,
            b"error from getrandom(): %s\0" as *const u8 as *const i8,
            _json_c_strerror(*__errno_location()),
        ) });
        return -(1 as i32);
    }
    if ret as u64 != ::std::mem::size_of::<i32>() as u64 {
        return -(1 as i32);
    }
    return 0 as i32;
}
static mut dev_random_file: *const i8 = b"/dev/urandom\0" as *const u8 as *const i8;
extern "C" fn get_dev_random_seed(mut seed: *mut i32) -> i32 {
    let mut buf: crate::src::random_seed::stat = stat {
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
    if (unsafe { stat(dev_random_file, &mut buf) }) != 0 {
        return -(1 as i32);
    }
    if buf.st_mode & 0o20000 as i32 as u32 == 0 as i32 as u32 {
        return -(1 as i32);
    }
    let mut fd: i32 = unsafe { open(dev_random_file, 0 as i32) };
    if fd < 0 as i32 {
        (unsafe { fprintf(
            stderr,
            b"error opening %s: %s\0" as *const u8 as *const i8,
            dev_random_file,
            _json_c_strerror(*__errno_location()),
        ) });
        return -(1 as i32);
    }
    let mut nread: i64 = unsafe { read(
        fd,
        seed as *mut libc::c_void,
        ::std::mem::size_of::<i32>() as u64,
    ) };
    (unsafe { close(fd) });
    if nread as u64 != ::std::mem::size_of::<i32>() as u64 {
        (unsafe { fprintf(
            stderr,
            b"error short read %s: %s\0" as *const u8 as *const i8,
            dev_random_file,
            _json_c_strerror(*__errno_location()),
        ) });
        return -(1 as i32);
    }
    return 0 as i32;
}
extern "C" fn get_time_seed() -> i32 {
    return ((unsafe { time(0 as *mut time_t) }) as u32).wrapping_mul(433494437 as i32 as u32) as i32;
}
#[no_mangle]
pub extern "C" fn json_c_get_random_seed() -> i32 {
    let mut seed: i32 = 0 as i32;
    if get_getrandom_seed(&mut seed) == 0 as i32 {
        return seed;
    }
    let mut seed_0: i32 = 0 as i32;
    if get_dev_random_seed(&mut seed_0) == 0 as i32 {
        return seed_0;
    }
    return get_time_seed();
}

