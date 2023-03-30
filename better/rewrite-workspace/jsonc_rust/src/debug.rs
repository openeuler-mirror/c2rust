use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    static mut stderr: *mut FILE;
    fn vfprintf(
        _: *mut FILE,
        _: *const libc::c_char,
        _: ::std::ffi::VaList,
    ) -> libc::c_int;
    fn vprintf(_: *const libc::c_char, _: ::std::ffi::VaList) -> libc::c_int;
    fn vsyslog(__pri: libc::c_int, __fmt: *const libc::c_char, __ap: ::std::ffi::VaList);
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: libc::c_uint,
    pub fp_offset: libc::c_uint,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type va_list = __builtin_va_list;
pub use crate::src::apps::json_parse::size_t;
pub use crate::src::apps::json_parse::__off_t;
pub use crate::src::apps::json_parse::__off64_t;
// #[derive(Copy, Clone)]

pub use crate::src::apps::json_parse::_IO_FILE;
pub use crate::src::apps::json_parse::_IO_lock_t;
pub use crate::src::apps::json_parse::FILE;
static mut _syslog: libc::c_int = 0 as libc::c_int;
static mut _debug: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub unsafe extern "C" fn mc_set_debug(mut debug: libc::c_int) {
    _debug = debug;
}
#[no_mangle]
pub unsafe extern "C" fn mc_get_debug() -> libc::c_int {
    return _debug;
}
#[no_mangle]
pub unsafe extern "C" fn mc_set_syslog(mut syslog: libc::c_int) {
    _syslog = syslog;
}
#[no_mangle]
pub unsafe extern "C" fn mc_debug(mut msg: *const libc::c_char, mut args: ...) {
    let mut ap: ::std::ffi::VaListImpl;
    if _debug != 0 {
        ap = args.clone();
        if _syslog != 0 {
            vsyslog(7 as libc::c_int, msg, ap.as_va_list());
        } else {
            vprintf(msg, ap.as_va_list());
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn mc_error(mut msg: *const libc::c_char, mut args: ...) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    if _syslog != 0 {
        vsyslog(3 as libc::c_int, msg, ap.as_va_list());
    } else {
        vfprintf(stderr, msg, ap.as_va_list());
    };
}
#[no_mangle]
pub unsafe extern "C" fn mc_info(mut msg: *const libc::c_char, mut args: ...) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    if _syslog != 0 {
        vsyslog(6 as libc::c_int, msg, ap.as_va_list());
    } else {
        vfprintf(stderr, msg, ap.as_va_list());
    };
}
