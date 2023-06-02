use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    static mut stderr: *mut FILE;
    fn fputs(__s: *const i8, __stream: *mut FILE) -> i32;
    fn close(__fd: i32) -> i32;
    fn read(__fd: i32, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn open(__file: *const i8, __oflag: i32, _: ...) -> i32;
    fn tcgetattr(__fd: i32, __termios_p: *mut termios) -> i32;
    fn tcsetattr(__fd: i32, __optional_actions: i32, __termios_p: *const termios) -> i32;
}
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __ssize_t = i64;
pub type ssize_t = __ssize_t;
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
pub type cc_t = u8;
pub type speed_t = u32;
pub type tcflag_t = u32;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct termios {
    pub c_iflag: tcflag_t,
    pub c_oflag: tcflag_t,
    pub c_cflag: tcflag_t,
    pub c_lflag: tcflag_t,
    pub c_line: cc_t,
    pub c_cc: [cc_t; 32],
    pub c_ispeed: speed_t,
    pub c_ospeed: speed_t,
}
extern "C" fn ttyecho(mut enable: bool, mut fd: i32) -> bool {
    static mut withecho: termios = termios {
        c_iflag: 0,
        c_oflag: 0,
        c_cflag: 0,
        c_lflag: 0,
        c_line: 0,
        c_cc: [0; 32],
        c_ispeed: 0,
        c_ospeed: 0,
    };
    static mut noecho: termios = termios {
        c_iflag: 0,
        c_oflag: 0,
        c_cflag: 0,
        c_lflag: 0,
        c_line: 0,
        c_cc: [0; 32],
        c_ispeed: 0,
        c_ospeed: 0,
    };
    if !enable {
        (unsafe { tcgetattr(fd, &mut withecho) });
        (unsafe { noecho = withecho });
        (unsafe { noecho.c_lflag &= !(0o10 as i32) as u32 });
        (unsafe { tcsetattr(fd, 0 as i32, &mut noecho) });
        return 1 as i32 != 0;
    }
    (unsafe { tcsetattr(fd, 2 as i32, &mut withecho) });
    return 1 as i32 != 0;
}
#[no_mangle]
pub extern "C" fn getpass_r(
    mut prompt: *const i8,
    mut password: *mut i8,
    mut buflen: size_t,
) -> *mut i8 {
    let mut nread: ssize_t = 0;
    let mut disabled: bool = false;
    let mut fd: i32 = unsafe { open(b"/dev/tty\0" as *const u8 as *const i8, 0 as i32) };
    if -(1 as i32) == fd {
        fd = 0 as i32;
    }
    disabled = ttyecho(0 as i32 != 0, fd);
    (unsafe { fputs(prompt, stderr) });
    nread = unsafe { read(fd, password as *mut libc::c_void, buflen) };
    if nread > 0 as i32 as i64 {
        nread -= 1;
        (unsafe { *password.offset(nread as isize) = '\u{0}' as i32 as i8 });
    } else {
        (unsafe { *password.offset(0 as i32 as isize) = '\u{0}' as i32 as i8 });
    }
    if disabled {
        (unsafe { fputs(b"\n\0" as *const u8 as *const i8, stderr) });
        ttyecho(1 as i32 != 0, fd);
    }
    if 0 as i32 != fd {
        (unsafe { close(fd) });
    }
    return password;
}
