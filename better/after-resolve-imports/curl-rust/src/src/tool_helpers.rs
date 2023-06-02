use ::libc;
extern "C" {
    
    
    
    
    
    
    
}
pub use crate::src::lib::strcase::curl_strequal;
pub use crate::src::src::tool_msgs::notef;
pub use crate::src::src::tool_msgs::warnf;
pub use crate::src::lib::altsvc::curl_mime;
pub use crate::src::lib::imap::_IO_marker;
pub use crate::src::lib::speedcheck::_IO_codecvt;
pub use crate::src::lib::vtls::vtls::_IO_wide_data;
pub type __off_t = crate::src::lib::altsvc::__off_t;
pub type __off64_t = crate::src::lib::altsvc::__off64_t;
pub type size_t = crate::src::lib::altsvc::size_t;
pub type curl_off_t = crate::src::lib::altsvc::curl_off_t;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::altsvc::_IO_FILE;
pub type _IO_lock_t = crate::src::lib::altsvc::_IO_lock_t;
pub type FILE = crate::src::lib::altsvc::FILE;
// #[derive(Copy, Clone)]

pub type curl_slist = crate::src::lib::altsvc::curl_slist;
pub type curl_TimeCond = crate::src::lib::altsvc::curl_TimeCond;
pub const CURL_TIMECOND_LAST: curl_TimeCond = 4;
pub const CURL_TIMECOND_LASTMOD: curl_TimeCond = 3;
pub const CURL_TIMECOND_IFUNMODSINCE: curl_TimeCond = 2;
pub const CURL_TIMECOND_IFMODSINCE: curl_TimeCond = 1;
pub const CURL_TIMECOND_NONE: curl_TimeCond = 0;
// #[derive(Copy, Clone)]

pub type OperationConfig = crate::src::src::tool_cb_dbg::OperationConfig;
// #[derive(Copy, Clone)]

pub type State = crate::src::src::tool_cb_dbg::State;
// #[derive(Copy, Clone)]

pub type URLGlob = crate::src::src::tool_cb_dbg::URLGlob;
// #[derive(Copy, Clone)]

pub type URLPattern = crate::src::src::tool_cb_dbg::URLPattern;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed = crate::src::src::tool_cb_dbg::C2RustUnnamed;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_0 = crate::src::src::tool_cb_dbg::C2RustUnnamed_0;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_1 = crate::src::src::tool_cb_dbg::C2RustUnnamed_1;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_2 = crate::src::src::tool_cb_dbg::C2RustUnnamed_2;
pub type URLPatternType = crate::src::src::tool_cb_dbg::URLPatternType;
pub const UPTNumRange: URLPatternType = 3;
pub const UPTCharRange: URLPatternType = 2;
pub const UPTSet: URLPatternType = 1;
// #[derive(Copy, Clone)]

pub type getout = crate::src::src::tool_cb_dbg::getout;
// #[derive(Copy, Clone)]

pub type GlobalConfig = crate::src::src::tool_cb_dbg::GlobalConfig;
pub type trace = crate::src::src::tool_cb_dbg::trace;
pub const TRACE_PLAIN: trace = 3;
pub const TRACE_ASCII: trace = 2;
pub const TRACE_BIN: trace = 1;
pub const TRACE_NONE: trace = 0;
pub type curl_error = crate::src::src::tool_cb_dbg::curl_error;
pub const ERR_LAST: curl_error = 2;
pub const ERR_BINARY_TERMINAL: curl_error = 1;
pub const ERR_NONE: curl_error = 0;
pub type HttpReq = crate::src::src::tool_cb_dbg::HttpReq;
pub const HTTPREQ_SIMPLEPOST: HttpReq = 4;
pub const HTTPREQ_MIMEPOST: HttpReq = 3;
pub const HTTPREQ_HEAD: HttpReq = 2;
pub const HTTPREQ_GET: HttpReq = 1;
pub const HTTPREQ_UNSPEC: HttpReq = 0;
// #[derive(Copy, Clone)]

pub type tool_mime = crate::src::src::tool_cb_dbg::tool_mime;
pub type toolmimekind = crate::src::src::tool_cb_dbg::toolmimekind;
pub const TOOLMIME_STDINDATA: toolmimekind = 6;
pub const TOOLMIME_STDIN: toolmimekind = 5;
pub const TOOLMIME_FILEDATA: toolmimekind = 4;
pub const TOOLMIME_FILE: toolmimekind = 3;
pub const TOOLMIME_DATA: toolmimekind = 2;
pub const TOOLMIME_PARTS: toolmimekind = 1;
pub const TOOLMIME_NONE: toolmimekind = 0;
pub type ParameterError = crate::src::src::tool_formparse::ParameterError;
pub const PARAM_LAST: ParameterError = 21;
pub const PARAM_CONTDISP_RESUME_FROM: ParameterError = 20;
pub const PARAM_CONTDISP_SHOW_HEADER: ParameterError = 19;
pub const PARAM_NO_NOT_BOOLEAN: ParameterError = 18;
pub const PARAM_NUMBER_TOO_LARGE: ParameterError = 17;
pub const PARAM_NO_PREFIX: ParameterError = 16;
pub const PARAM_NEXT_OPERATION: ParameterError = 15;
pub const PARAM_NO_MEM: ParameterError = 14;
pub const PARAM_LIBCURL_UNSUPPORTED_PROTOCOL: ParameterError = 13;
pub const PARAM_LIBCURL_DOESNT_SUPPORT: ParameterError = 12;
pub const PARAM_NEGATIVE_NUMERIC: ParameterError = 11;
pub const PARAM_BAD_NUMERIC: ParameterError = 10;
pub const PARAM_GOT_EXTRA_PARAMETER: ParameterError = 9;
pub const PARAM_ENGINES_REQUESTED: ParameterError = 8;
pub const PARAM_VERSION_INFO_REQUESTED: ParameterError = 7;
pub const PARAM_MANUAL_REQUESTED: ParameterError = 6;
pub const PARAM_HELP_REQUESTED: ParameterError = 5;
pub const PARAM_BAD_USE: ParameterError = 4;
pub const PARAM_REQUIRES_PARAMETER: ParameterError = 3;
pub const PARAM_OPTION_UNKNOWN: ParameterError = 2;
pub const PARAM_OPTION_AMBIGUOUS: ParameterError = 1;
pub const PARAM_OK: ParameterError = 0;
#[no_mangle]
pub extern "C" fn param2text(mut res: i32) -> *const i8 {
    let mut error: ParameterError = res as ParameterError;
    match error as u32 {
        9 => {
            return b"had unsupported trailing garbage\0" as *const u8
                as *const i8;
        }
        2 => return b"is unknown\0" as *const u8 as *const i8,
        1 => return b"is ambiguous\0" as *const u8 as *const i8,
        3 => return b"requires parameter\0" as *const u8 as *const i8,
        4 => return b"is badly used here\0" as *const u8 as *const i8,
        10 => {
            return b"expected a proper numerical parameter\0" as *const u8
                as *const i8;
        }
        11 => {
            return b"expected a positive numerical parameter\0" as *const u8
                as *const i8;
        }
        12 => {
            return b"the installed libcurl version doesn't support this\0" as *const u8
                as *const i8;
        }
        13 => {
            return b"a specified protocol is unsupported by libcurl\0" as *const u8
                as *const i8;
        }
        14 => return b"out of memory\0" as *const u8 as *const i8,
        16 => {
            return b"the given option can't be reversed with a --no- prefix\0"
                as *const u8 as *const i8;
        }
        17 => return b"too large number\0" as *const u8 as *const i8,
        18 => {
            return b"used '--no-' for option that isn't a boolean\0" as *const u8
                as *const i8;
        }
        19 => {
            return b"--include and --remote-header-name cannot be combined\0"
                as *const u8 as *const i8;
        }
        20 => {
            return b"--continue-at and --remote-header-name cannot be combined\0"
                as *const u8 as *const i8;
        }
        _ => return b"unknown error\0" as *const u8 as *const i8,
    };
}
#[no_mangle]
pub unsafe extern "C" fn SetHTTPrequest(
    mut config: *mut OperationConfig,
    mut req: HttpReq,
    mut store: *mut HttpReq,
) -> i32 {
    let mut reqname: [*const i8; 5] = [
        b"\0" as *const u8 as *const i8,
        b"GET (-G, --get)\0" as *const u8 as *const i8,
        b"HEAD (-I, --head)\0" as *const u8 as *const i8,
        b"multipart formpost (-F, --form)\0" as *const u8 as *const i8,
        b"POST (-d, --data)\0" as *const u8 as *const i8,
    ];
    if *store as u32 == HTTPREQ_UNSPEC as i32 as u32
        || *store as u32 == req as u32
    {
        *store = req;
        return 0 as i32;
    }
    warnf(
        (*config).global,
        b"You can only select one HTTP request method! You asked for both %s and %s.\n\0"
            as *const u8 as *const i8,
        reqname[req as usize],
        reqname[*store as usize],
    );
    return 1 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn customrequest_helper(
    mut config: *mut OperationConfig,
    mut req: HttpReq,
    mut method: *mut i8,
) {
    let mut dflt: [*const i8; 5] = [
        b"GET\0" as *const u8 as *const i8,
        b"GET\0" as *const u8 as *const i8,
        b"HEAD\0" as *const u8 as *const i8,
        b"POST\0" as *const u8 as *const i8,
        b"POST\0" as *const u8 as *const i8,
    ];
    if !method.is_null() {
        if curl_strequal(method, dflt[req as usize]) != 0 {
            notef(
                (*config).global,
                b"Unnecessary use of -X or --request, %s is already inferred.\n\0"
                    as *const u8 as *const i8,
                dflt[req as usize],
            );
        } else if curl_strequal(method, b"head\0" as *const u8 as *const i8)
                != 0
            {
            warnf(
                (*config).global,
                b"Setting custom HTTP method to HEAD with -X/--request may not work the way you want. Consider using -I/--head instead.\n\0"
                    as *const u8 as *const i8,
            );
        }
    }
}
