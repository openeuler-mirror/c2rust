use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    static mut stderr: *mut FILE;
    fn fputs(__s: *const libc::c_char, __stream: *mut FILE) -> libc::c_int;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...) -> libc::c_int;
    fn tcgetattr(__fd: libc::c_int, __termios_p: *mut termios) -> libc::c_int;
    fn tcsetattr(
        __fd: libc::c_int,
        __optional_actions: libc::c_int,
        __termios_p: *const termios,
    ) -> libc::c_int;
}
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type ssize_t = __ssize_t;
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
pub type cc_t = libc::c_uchar;
pub type speed_t = libc::c_uint;
pub type tcflag_t = libc::c_uint;
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
unsafe extern "C" fn ttyecho(mut enable: bool, mut fd: libc::c_int) -> bool {
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
        noecho.c_lflag &= !(0o10 as libc::c_int) as libc::c_uint;
        tcsetattr(fd, 0 as libc::c_int, &mut noecho);
        return 1 as libc::c_int != 0;
    }
    tcsetattr(fd, 2 as libc::c_int, &mut withecho);
    return 1 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn getpass_r(
    mut prompt: *const libc::c_char,
    mut password: *mut libc::c_char,
    mut buflen: size_t,
) -> *mut libc::c_char {
    let mut nread: ssize_t = 0;
    let mut disabled: bool = false;
    let mut fd: libc::c_int = open(
        b"/dev/tty\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    if -(1 as libc::c_int) == fd {
        fd = 0 as libc::c_int;
    }
    disabled = ttyecho(0 as libc::c_int != 0, fd);
    fputs(prompt, stderr);
    nread = read(fd, password as *mut libc::c_void, buflen);
    if nread > 0 as libc::c_int as libc::c_long {
        nread -= 1;
        *password.offset(nread as isize) = '\u{0}' as i32 as libc::c_char;
    } else {
        *password.offset(0 as libc::c_int as isize) = '\u{0}' as i32 as libc::c_char;
    }
    if disabled {
        fputs(b"\n\0" as *const u8 as *const libc::c_char, stderr);
        ttyecho(1 as libc::c_int != 0, fd);
    }
    if 0 as libc::c_int != fd {
        close(fd);
    }
    return password;
}
