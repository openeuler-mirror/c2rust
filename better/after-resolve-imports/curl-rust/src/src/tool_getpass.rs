use ::libc;
extern "C" {
    
    
    
    static mut stderr: *mut FILE;
    fn fputs(__s: *const i8, __stream: *mut FILE) -> i32;
    fn close(__fd: i32) -> i32;
    fn read(__fd: i32, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn open(__file: *const i8, __oflag: i32, _: ...) -> i32;
    fn tcgetattr(__fd: i32, __termios_p: *mut termios) -> i32;
    fn tcsetattr(
        __fd: i32,
        __optional_actions: i32,
        __termios_p: *const termios,
    ) -> i32;
}
pub use crate::src::lib::imap::_IO_marker;
pub use crate::src::lib::speedcheck::_IO_codecvt;
pub use crate::src::lib::vtls::vtls::_IO_wide_data;
pub type __off_t = crate::src::lib::altsvc::__off_t;
pub type __off64_t = crate::src::lib::altsvc::__off64_t;
pub type __ssize_t = crate::src::lib::altsvc::__ssize_t;
pub type ssize_t = crate::src::lib::altsvc::ssize_t;
pub type size_t = crate::src::lib::altsvc::size_t;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::altsvc::_IO_FILE;
pub type _IO_lock_t = crate::src::lib::altsvc::_IO_lock_t;
pub type FILE = crate::src::lib::altsvc::FILE;
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
unsafe extern "C" fn ttyecho(mut enable: bool, mut fd: i32) -> bool {
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
        tcgetattr(fd, &mut withecho);
        noecho = withecho;
        noecho.c_lflag &= !(0o10 as i32) as u32;
        tcsetattr(fd, 0 as i32, &mut noecho);
        return 1 as i32 != 0;
    }
    tcsetattr(fd, 2 as i32, &mut withecho);
    return 1 as i32 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn getpass_r(
    mut prompt: *const i8,
    mut password: *mut i8,
    mut buflen: size_t,
) -> *mut i8 {
    let mut nread: ssize_t = 0;
    let mut disabled: bool = false;
    let mut fd: i32 = open(
        b"/dev/tty\0" as *const u8 as *const i8,
        0 as i32,
    );
    if -(1 as i32) == fd {
        fd = 0 as i32;
    }
    disabled = ttyecho(0 as i32 != 0, fd);
    fputs(prompt, stderr);
    nread = read(fd, password as *mut libc::c_void, buflen);
    if nread > 0 as i32 as i64 {
        nread -= 1;
        *password.offset(nread as isize) = '\u{0}' as i32 as i8;
    } else {
        *password.offset(0 as i32 as isize) = '\u{0}' as i32 as i8;
    }
    if disabled {
        fputs(b"\n\0" as *const u8 as *const i8, stderr);
        ttyecho(1 as i32 != 0, fd);
    }
    if 0 as i32 != fd {
        close(fd);
    }
    return password;
}
