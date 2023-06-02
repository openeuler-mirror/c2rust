use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    static mut stderr: *mut FILE;
    fn vfprintf(_: *mut FILE, _: *const i8, _: ::std::ffi::VaList) -> i32;
    fn vprintf(_: *const i8, _: ::std::ffi::VaList) -> i32;
    fn vsyslog(__pri: i32, __fmt: *const i8, __ap: ::std::ffi::VaList);
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: u32,
    pub fp_offset: u32,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type va_list = __builtin_va_list;
pub type size_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
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
static mut _syslog: i32 = 0 as i32;
static mut _debug: i32 = 0 as i32;
#[no_mangle]
pub extern "C" fn mc_set_debug(mut debug: i32) {
    (unsafe { _debug = debug });
}
#[no_mangle]
pub extern "C" fn mc_get_debug() -> i32 {
    return unsafe { _debug };
}
#[no_mangle]
pub extern "C" fn mc_set_syslog(mut syslog: i32) {
    (unsafe { _syslog = syslog });
}
#[no_mangle]
pub unsafe extern "C" fn mc_debug(mut msg: *const i8, mut args: ...) {
    let mut ap: ::std::ffi::VaListImpl;
    if _debug != 0 {
        ap = args.clone();
        if _syslog != 0 {
            vsyslog(7 as i32, msg, ap.as_va_list());
        } else {
            vprintf(msg, ap.as_va_list());
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn mc_error(mut msg: *const i8, mut args: ...) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    if _syslog != 0 {
        vsyslog(3 as i32, msg, ap.as_va_list());
    } else {
        vfprintf(stderr, msg, ap.as_va_list());
    };
}
#[no_mangle]
pub unsafe extern "C" fn mc_info(mut msg: *const i8, mut args: ...) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    if _syslog != 0 {
        vsyslog(6 as i32, msg, ap.as_va_list());
    } else {
        vfprintf(stderr, msg, ap.as_va_list());
    };
}
