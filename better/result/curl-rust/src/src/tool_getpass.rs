use :: libc;
extern "C" {
    static mut stderr: *mut crate::src::lib::http2::_IO_FILE;
    fn fputs(__s: *const i8, __stream: *mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn close(__fd: i32) -> i32;
    fn read(__fd: i32, __buf: *mut core::ffi::c_void, __nbytes: u64) -> i64;
    fn open(__file: *const i8, __oflag: i32, _: ...) -> i32;
    fn tcgetattr(__fd: i32, __termios_p: *mut crate::src::src::tool_getpass::termios) -> i32;
    fn tcsetattr(
        __fd: i32,
        __optional_actions: i32,
        __termios_p: *const crate::src::src::tool_getpass::termios,
    ) -> i32;
}
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __ssize_t = i64;
pub type ssize_t = i64;
pub type size_t = u64;
pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::lib::http2::_IO_FILE;
pub type cc_t = u8;
pub type speed_t = u32;
pub type tcflag_t = u32;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; 32],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}
impl termios {
    pub const fn new() -> Self {
        termios {
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: 0,
            c_lflag: 0,
            c_line: 0,
            c_cc: [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            c_ispeed: 0,
            c_ospeed: 0,
        }
    }
}
impl std::default::Default for termios {
    fn default() -> Self {
        termios::new()
    }
}
extern "C" fn ttyecho(mut enable: bool, mut fd: i32) -> bool {
    static mut withecho: crate::src::src::tool_getpass::termios = termios {
        c_iflag: 0,
        c_oflag: 0,
        c_cflag: 0,
        c_lflag: 0,
        c_line: 0,
        c_cc: [0; 32],
        c_ispeed: 0,
        c_ospeed: 0,
    };
    static mut noecho: crate::src::src::tool_getpass::termios = termios {
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
    mut buflen: u64,
) -> *mut i8 {
    let mut nread: i64 = 0;
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

