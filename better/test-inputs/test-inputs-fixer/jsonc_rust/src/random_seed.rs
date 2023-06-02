use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn _json_c_strerror(errno_in: i32) -> *mut i8;
    fn __errno_location() -> *mut i32;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const i8, _: ...) -> i32;
    fn getrandom(__buffer: *mut libc::c_void, __length: size_t, __flags: u32) -> ssize_t;
    fn open(__file: *const i8, __oflag: i32, _: ...) -> i32;
    fn close(__fd: i32) -> i32;
    fn read(__fd: i32, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn stat(__file: *const i8, __buf: *mut stat) -> i32;
    fn time(__timer: *mut time_t) -> time_t;
}
pub type time_t = __time_t;
pub type __time_t = i64;
pub type FILE = _IO_FILE;
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
pub type size_t = u64;
pub type __off64_t = i64;
pub type _IO_lock_t = ();
pub type __off_t = i64;
pub type ssize_t = __ssize_t;
pub type __ssize_t = i64;
pub type __mode_t = u32;
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
pub type __syscall_slong_t = i64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
pub type __blkcnt_t = i64;
pub type __blksize_t = i64;
pub type __dev_t = u64;
pub type __gid_t = u32;
pub type __uid_t = u32;
pub type __nlink_t = u64;
pub type __ino_t = u64;
extern "C" fn get_getrandom_seed(mut seed: *mut i32) -> i32 {
    let mut ret: ssize_t = 0;
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
    let mut nread: ssize_t = unsafe { read(
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
