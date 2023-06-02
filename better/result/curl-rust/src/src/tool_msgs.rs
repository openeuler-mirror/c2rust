use :: libc;
extern "C" {
    pub type _IO_marker;
    fn fputs(__s: *const i8, __stream: *mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn fwrite(
        _: *const core::ffi::c_void,
        _: u64,
        _: u64,
        _: *mut crate::src::lib::http2::_IO_FILE,
    ) -> u64;
    fn strlen(_: *const i8) -> u64;
}
pub use crate::src::lib::curl_ctype::Curl_isspace;
pub use crate::src::lib::escape::curl_free;
pub use crate::src::lib::http2::curl_mime;
pub use crate::src::lib::mprintf::curl_mfprintf;
pub use crate::src::lib::mprintf::curl_mvaprintf;
pub use crate::src::lib::mprintf::curl_mvfprintf;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub type __builtin_va_list = [crate::src::lib::dict::__va_list_tag; 1];
pub type __va_list_tag = crate::src::lib::dict::__va_list_tag;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type size_t = u64;
pub type curl_off_t = i64;
pub type va_list = [crate::src::lib::dict::__va_list_tag; 1];
pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::lib::http2::_IO_FILE;
pub type curl_slist = crate::src::lib::http2::curl_slist;
pub type curl_TimeCond = u32;
pub const CURL_TIMECOND_LAST: curl_TimeCond = 4;
pub const CURL_TIMECOND_LASTMOD: curl_TimeCond = 3;
pub const CURL_TIMECOND_IFUNMODSINCE: curl_TimeCond = 2;
pub const CURL_TIMECOND_IFMODSINCE: curl_TimeCond = 1;
pub const CURL_TIMECOND_NONE: curl_TimeCond = 0;
pub type OperationConfig = crate::src::src::tool_cb_dbg::OperationConfig;
pub type State = crate::src::src::tool_cb_dbg::State;
pub type URLGlob = crate::src::src::tool_cb_dbg::URLGlob;
pub type URLPattern = crate::src::src::tool_cb_dbg::URLPattern;
pub type C2RustUnnamed = crate::src::src::tool_cb_dbg::C2RustUnnamed;
pub type C2RustUnnamed_0 = crate::src::src::tool_cb_dbg::C2RustUnnamed_0;
pub type C2RustUnnamed_1 = crate::src::src::tool_cb_dbg::C2RustUnnamed_1;
pub type C2RustUnnamed_2 = crate::src::src::tool_cb_dbg::C2RustUnnamed_2;
pub type URLPatternType = u32;
pub const UPTNumRange: URLPatternType = 3;
pub const UPTCharRange: URLPatternType = 2;
pub const UPTSet: URLPatternType = 1;
pub type getout = crate::src::src::tool_cb_dbg::getout;
pub type GlobalConfig = crate::src::src::tool_cb_dbg::GlobalConfig;
pub type trace = u32;
pub const TRACE_PLAIN: trace = 3;
pub const TRACE_ASCII: trace = 2;
pub const TRACE_BIN: trace = 1;
pub const TRACE_NONE: trace = 0;
pub type curl_error = u32;
pub const ERR_LAST: curl_error = 2;
pub const ERR_BINARY_TERMINAL: curl_error = 1;
pub const ERR_NONE: curl_error = 0;
pub type HttpReq = u32;
pub const HTTPREQ_SIMPLEPOST: HttpReq = 4;
pub const HTTPREQ_MIMEPOST: HttpReq = 3;
pub const HTTPREQ_HEAD: HttpReq = 2;
pub const HTTPREQ_GET: HttpReq = 1;
pub const HTTPREQ_UNSPEC: HttpReq = 0;
pub type tool_mime = crate::src::src::tool_cb_dbg::tool_mime;
pub type toolmimekind = u32;
pub const TOOLMIME_STDINDATA: toolmimekind = 6;
pub const TOOLMIME_STDIN: toolmimekind = 5;
pub const TOOLMIME_FILEDATA: toolmimekind = 4;
pub const TOOLMIME_FILE: toolmimekind = 3;
pub const TOOLMIME_DATA: toolmimekind = 2;
pub const TOOLMIME_PARTS: toolmimekind = 1;
pub const TOOLMIME_NONE: toolmimekind = 0;
extern "C" fn voutf(
    mut config: *mut crate::src::src::tool_cb_dbg::GlobalConfig,
    mut prefix: *const i8,
    mut fmt: *const i8,
    mut ap: core::ffi::VaList,
) {
    let mut width: u64 = (79 as i32 as u64).wrapping_sub(unsafe { strlen(prefix) });
    if !(unsafe { (*config).mute }) {
        let mut len: u64 = 0;
        let mut ptr: *mut i8 = 0 as *mut i8;
        let mut print_buffer: *mut i8 = 0 as *mut i8;
        print_buffer = curl_mvaprintf(fmt, ap.as_va_list());
        if print_buffer.is_null() {
            return;
        }
        len = unsafe { strlen(print_buffer) };
        ptr = print_buffer;
        while len > 0 as i32 as u64 {
            (unsafe { fputs(prefix, (*config).errors) });
            if len > width {
                let mut cut: u64 = width.wrapping_sub(1 as i32 as u64);
                while Curl_isspace((unsafe { *ptr.offset(cut as isize) }) as u8 as i32) == 0 && cut != 0 {
                    cut = cut.wrapping_sub(1);
                }
                if 0 as i32 as u64 == cut {
                    cut = width.wrapping_sub(1 as i32 as u64);
                }
                (unsafe { fwrite(
                    ptr as *const libc::c_void,
                    cut.wrapping_add(1 as i32 as u64),
                    1 as i32 as u64,
                    (*config).errors,
                ) });
                (unsafe { fputs(b"\n\0" as *const u8 as *const i8, (*config).errors) });
                ptr = unsafe { ptr.offset(cut.wrapping_add(1 as i32 as u64) as isize) };
                len = (len as u64).wrapping_sub(cut.wrapping_add(1 as i32 as u64)) as size_t
                    as size_t;
            } else {
                (unsafe { fputs(ptr, (*config).errors) });
                len = 0 as i32 as size_t;
            }
        }
        curl_free(print_buffer as *mut libc::c_void);
    }
}
#[no_mangle]
pub unsafe extern "C" fn notef(
    mut config: *mut crate::src::src::tool_cb_dbg::GlobalConfig,
    mut fmt: *const i8,
    mut args: ...
) {
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    if (*config).tracetype as u64 != 0 {
        voutf(
            config,
            b"Note: \0" as *const u8 as *const i8,
            fmt,
            ap.as_va_list(),
        );
    }
}
#[no_mangle]
pub unsafe extern "C" fn warnf(
    mut config: *mut crate::src::src::tool_cb_dbg::GlobalConfig,
    mut fmt: *const i8,
    mut args: ...
) {
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    voutf(
        config,
        b"Warning: \0" as *const u8 as *const i8,
        fmt,
        ap.as_va_list(),
    );
}
#[no_mangle]
pub unsafe extern "C" fn helpf(
    mut errors: *mut crate::src::lib::http2::_IO_FILE,
    mut fmt: *const i8,
    mut args: ...
) {
    if !fmt.is_null() {
        let mut ap: core::ffi::VaListImpl;
        ap = args.clone();
        fputs(b"curl: \0" as *const u8 as *const i8, errors);
        curl_mvfprintf(errors, fmt, ap.as_va_list());
    }
    curl_mfprintf(
        errors,
        b"curl: try 'curl --help' or 'curl --manual' for more information\n\0" as *const u8
            as *const i8,
    );
}
#[no_mangle]
pub unsafe extern "C" fn errorf(
    mut config: *mut crate::src::src::tool_cb_dbg::GlobalConfig,
    mut fmt: *const i8,
    mut args: ...
) {
    if !(*config).mute {
        let mut ap: core::ffi::VaListImpl;
        ap = args.clone();
        voutf(
            config,
            b"curl: \0" as *const u8 as *const i8,
            fmt,
            ap.as_va_list(),
        );
    }
}

