
extern "C" {
    pub type _IO_wide_data;
    static mut stderr: *mut crate::src::apps::json_parse::_IO_FILE;
    fn vfprintf(
        _: *mut crate::src::apps::json_parse::_IO_FILE,
        _: *const i8,
        _: core::ffi::VaList,
    ) -> i32;
    fn vprintf(_: *const i8, _: core::ffi::VaList) -> i32;
    fn vsyslog(__pri: i32, __fmt: *const i8, __ap: core::ffi::VaList);
}
pub use crate::src::{json_object::_IO_codecvt, json_visit::_IO_marker};
pub type __builtin_va_list = [crate::src::debug::__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: u32,
    pub fp_offset: u32,
    pub overflow_arg_area: *mut core::ffi::c_void,
    pub reg_save_area: *mut core::ffi::c_void,
}
impl __va_list_tag {
    pub const fn new() -> Self {
        __va_list_tag {
            gp_offset: 0,
            fp_offset: 0,
            overflow_arg_area: (0 as *mut core::ffi::c_void),
            reg_save_area: (0 as *mut core::ffi::c_void),
        }
    }
}
impl std::default::Default for __va_list_tag {
    fn default() -> Self {
        __va_list_tag::new()
    }
}
pub type va_list = [crate::src::debug::__va_list_tag; 1];
pub type size_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type _IO_FILE = crate::src::apps::json_parse::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::apps::json_parse::_IO_FILE;
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
    let mut ap: core::ffi::VaListImpl;
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
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    if _syslog != 0 {
        vsyslog(3 as i32, msg, ap.as_va_list());
    } else {
        vfprintf(stderr, msg, ap.as_va_list());
    };
}
#[no_mangle]
pub unsafe extern "C" fn mc_info(mut msg: *const i8, mut args: ...) {
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    if _syslog != 0 {
        vsyslog(6 as i32, msg, ap.as_va_list());
    } else {
        vfprintf(stderr, msg, ap.as_va_list());
    };
}

