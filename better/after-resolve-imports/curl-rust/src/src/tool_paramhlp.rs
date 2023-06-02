use ::libc;
extern "C" {
    
    
    
    
    fn fgets(
        __s: *mut i8,
        __n: i32,
        __stream: *mut FILE,
    ) -> *mut i8;
    fn fread(
        _: *mut libc::c_void,
        _: u64,
        _: u64,
        _: *mut FILE,
    ) -> u64;
    
    
    
    fn strtod(_: *const i8, _: *mut *mut i8) -> f64;
    fn strtol(
        _: *const i8,
        _: *mut *mut i8,
        _: i32,
    ) -> i64;
    fn calloc(_: u64, _: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn memset(
        _: *mut libc::c_void,
        _: i32,
        _: u64,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strdup(_: *const i8) -> *mut i8;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strtok(_: *mut i8, _: *const i8) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn __errno_location() -> *mut i32;
    
    
    
    
    
    fn curlx_dyn_init(s: *mut dynbuf, toobig: size_t);
    fn curlx_dyn_addn(s: *mut dynbuf, mem: *const libc::c_void, len: size_t) -> CURLcode;
    fn curlx_dyn_add(s: *mut dynbuf, str: *const i8) -> CURLcode;
    fn curlx_dyn_addf(s: *mut dynbuf, fmt: *const i8, _: ...) -> CURLcode;
    fn curlx_dyn_ptr(s: *const dynbuf) -> *mut i8;
    fn curlx_dyn_len(s: *const dynbuf) -> size_t;
}
pub use crate::src::lib::curl_ctype::Curl_isalnum;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::slist::curl_slist_append;
pub use crate::src::lib::strcase::curl_strequal;
pub use crate::src::lib::version::curl_version_info;
pub use crate::src::src::tool_getpass::getpass_r;
pub use crate::src::src::tool_msgs::errorf;
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
pub type CURLcode = crate::src::lib::altsvc::CURLcode;
pub const CURL_LAST: CURLcode = 99;
pub const CURLE_SSL_CLIENTCERT: CURLcode = 98;
pub const CURLE_PROXY: CURLcode = 97;
pub const CURLE_QUIC_CONNECT_ERROR: CURLcode = 96;
pub const CURLE_HTTP3: CURLcode = 95;
pub const CURLE_AUTH_ERROR: CURLcode = 94;
pub const CURLE_RECURSIVE_API_CALL: CURLcode = 93;
pub const CURLE_HTTP2_STREAM: CURLcode = 92;
pub const CURLE_SSL_INVALIDCERTSTATUS: CURLcode = 91;
pub const CURLE_SSL_PINNEDPUBKEYNOTMATCH: CURLcode = 90;
pub const CURLE_NO_CONNECTION_AVAILABLE: CURLcode = 89;
pub const CURLE_CHUNK_FAILED: CURLcode = 88;
pub const CURLE_FTP_BAD_FILE_LIST: CURLcode = 87;
pub const CURLE_RTSP_SESSION_ERROR: CURLcode = 86;
pub const CURLE_RTSP_CSEQ_ERROR: CURLcode = 85;
pub const CURLE_FTP_PRET_FAILED: CURLcode = 84;
pub const CURLE_SSL_ISSUER_ERROR: CURLcode = 83;
pub const CURLE_SSL_CRL_BADFILE: CURLcode = 82;
pub const CURLE_AGAIN: CURLcode = 81;
pub const CURLE_SSL_SHUTDOWN_FAILED: CURLcode = 80;
pub const CURLE_SSH: CURLcode = 79;
pub const CURLE_REMOTE_FILE_NOT_FOUND: CURLcode = 78;
pub const CURLE_SSL_CACERT_BADFILE: CURLcode = 77;
pub const CURLE_CONV_REQD: CURLcode = 76;
pub const CURLE_CONV_FAILED: CURLcode = 75;
pub const CURLE_TFTP_NOSUCHUSER: CURLcode = 74;
pub const CURLE_REMOTE_FILE_EXISTS: CURLcode = 73;
pub const CURLE_TFTP_UNKNOWNID: CURLcode = 72;
pub const CURLE_TFTP_ILLEGAL: CURLcode = 71;
pub const CURLE_REMOTE_DISK_FULL: CURLcode = 70;
pub const CURLE_TFTP_PERM: CURLcode = 69;
pub const CURLE_TFTP_NOTFOUND: CURLcode = 68;
pub const CURLE_LOGIN_DENIED: CURLcode = 67;
pub const CURLE_SSL_ENGINE_INITFAILED: CURLcode = 66;
pub const CURLE_SEND_FAIL_REWIND: CURLcode = 65;
pub const CURLE_USE_SSL_FAILED: CURLcode = 64;
pub const CURLE_FILESIZE_EXCEEDED: CURLcode = 63;
pub const CURLE_LDAP_INVALID_URL: CURLcode = 62;
pub const CURLE_BAD_CONTENT_ENCODING: CURLcode = 61;
pub const CURLE_PEER_FAILED_VERIFICATION: CURLcode = 60;
pub const CURLE_SSL_CIPHER: CURLcode = 59;
pub const CURLE_SSL_CERTPROBLEM: CURLcode = 58;
pub const CURLE_OBSOLETE57: CURLcode = 57;
pub const CURLE_RECV_ERROR: CURLcode = 56;
pub const CURLE_SEND_ERROR: CURLcode = 55;
pub const CURLE_SSL_ENGINE_SETFAILED: CURLcode = 54;
pub const CURLE_SSL_ENGINE_NOTFOUND: CURLcode = 53;
pub const CURLE_GOT_NOTHING: CURLcode = 52;
pub const CURLE_OBSOLETE51: CURLcode = 51;
pub const CURLE_OBSOLETE50: CURLcode = 50;
pub const CURLE_SETOPT_OPTION_SYNTAX: CURLcode = 49;
pub const CURLE_UNKNOWN_OPTION: CURLcode = 48;
pub const CURLE_TOO_MANY_REDIRECTS: CURLcode = 47;
pub const CURLE_OBSOLETE46: CURLcode = 46;
pub const CURLE_INTERFACE_FAILED: CURLcode = 45;
pub const CURLE_OBSOLETE44: CURLcode = 44;
pub const CURLE_BAD_FUNCTION_ARGUMENT: CURLcode = 43;
pub const CURLE_ABORTED_BY_CALLBACK: CURLcode = 42;
pub const CURLE_FUNCTION_NOT_FOUND: CURLcode = 41;
pub const CURLE_OBSOLETE40: CURLcode = 40;
pub const CURLE_LDAP_SEARCH_FAILED: CURLcode = 39;
pub const CURLE_LDAP_CANNOT_BIND: CURLcode = 38;
pub const CURLE_FILE_COULDNT_READ_FILE: CURLcode = 37;
pub const CURLE_BAD_DOWNLOAD_RESUME: CURLcode = 36;
pub const CURLE_SSL_CONNECT_ERROR: CURLcode = 35;
pub const CURLE_HTTP_POST_ERROR: CURLcode = 34;
pub const CURLE_RANGE_ERROR: CURLcode = 33;
pub const CURLE_OBSOLETE32: CURLcode = 32;
pub const CURLE_FTP_COULDNT_USE_REST: CURLcode = 31;
pub const CURLE_FTP_PORT_FAILED: CURLcode = 30;
pub const CURLE_OBSOLETE29: CURLcode = 29;
pub const CURLE_OPERATION_TIMEDOUT: CURLcode = 28;
pub const CURLE_OUT_OF_MEMORY: CURLcode = 27;
pub const CURLE_READ_ERROR: CURLcode = 26;
pub const CURLE_UPLOAD_FAILED: CURLcode = 25;
pub const CURLE_OBSOLETE24: CURLcode = 24;
pub const CURLE_WRITE_ERROR: CURLcode = 23;
pub const CURLE_HTTP_RETURNED_ERROR: CURLcode = 22;
pub const CURLE_QUOTE_ERROR: CURLcode = 21;
pub const CURLE_OBSOLETE20: CURLcode = 20;
pub const CURLE_FTP_COULDNT_RETR_FILE: CURLcode = 19;
pub const CURLE_PARTIAL_FILE: CURLcode = 18;
pub const CURLE_FTP_COULDNT_SET_TYPE: CURLcode = 17;
pub const CURLE_HTTP2: CURLcode = 16;
pub const CURLE_FTP_CANT_GET_HOST: CURLcode = 15;
pub const CURLE_FTP_WEIRD_227_FORMAT: CURLcode = 14;
pub const CURLE_FTP_WEIRD_PASV_REPLY: CURLcode = 13;
pub const CURLE_FTP_ACCEPT_TIMEOUT: CURLcode = 12;
pub const CURLE_FTP_WEIRD_PASS_REPLY: CURLcode = 11;
pub const CURLE_FTP_ACCEPT_FAILED: CURLcode = 10;
pub const CURLE_REMOTE_ACCESS_DENIED: CURLcode = 9;
pub const CURLE_WEIRD_SERVER_REPLY: CURLcode = 8;
pub const CURLE_COULDNT_CONNECT: CURLcode = 7;
pub const CURLE_COULDNT_RESOLVE_HOST: CURLcode = 6;
pub const CURLE_COULDNT_RESOLVE_PROXY: CURLcode = 5;
pub const CURLE_NOT_BUILT_IN: CURLcode = 4;
pub const CURLE_URL_MALFORMAT: CURLcode = 3;
pub const CURLE_FAILED_INIT: CURLcode = 2;
pub const CURLE_UNSUPPORTED_PROTOCOL: CURLcode = 1;
pub const CURLE_OK: CURLcode = 0;
pub type C2RustUnnamed = u32;
pub const CURLFTPSSL_CCC_LAST: C2RustUnnamed = 3;
pub const CURLFTPSSL_CCC_ACTIVE: C2RustUnnamed = 2;
pub const CURLFTPSSL_CCC_PASSIVE: C2RustUnnamed = 1;
pub const CURLFTPSSL_CCC_NONE: C2RustUnnamed = 0;
pub type C2RustUnnamed_0 = u32;
pub const CURLFTPMETHOD_LAST: C2RustUnnamed_0 = 4;
pub const CURLFTPMETHOD_SINGLECWD: C2RustUnnamed_0 = 3;
pub const CURLFTPMETHOD_NOCWD: C2RustUnnamed_0 = 2;
pub const CURLFTPMETHOD_MULTICWD: C2RustUnnamed_0 = 1;
pub const CURLFTPMETHOD_DEFAULT: C2RustUnnamed_0 = 0;
pub type C2RustUnnamed_1 = u32;
pub const CURL_SSLVERSION_MAX_LAST: C2RustUnnamed_1 = 524288;
pub const CURL_SSLVERSION_MAX_TLSv1_3: C2RustUnnamed_1 = 458752;
pub const CURL_SSLVERSION_MAX_TLSv1_2: C2RustUnnamed_1 = 393216;
pub const CURL_SSLVERSION_MAX_TLSv1_1: C2RustUnnamed_1 = 327680;
pub const CURL_SSLVERSION_MAX_TLSv1_0: C2RustUnnamed_1 = 262144;
pub const CURL_SSLVERSION_MAX_DEFAULT: C2RustUnnamed_1 = 65536;
pub const CURL_SSLVERSION_MAX_NONE: C2RustUnnamed_1 = 0;
pub type curl_TimeCond = crate::src::lib::altsvc::curl_TimeCond;
pub const CURL_TIMECOND_LAST: curl_TimeCond = 4;
pub const CURL_TIMECOND_LASTMOD: curl_TimeCond = 3;
pub const CURL_TIMECOND_IFUNMODSINCE: curl_TimeCond = 2;
pub const CURL_TIMECOND_IFMODSINCE: curl_TimeCond = 1;
pub const CURL_TIMECOND_NONE: curl_TimeCond = 0;
pub type CURLversion = crate::src::lib::version::CURLversion;
pub const CURLVERSION_LAST: CURLversion = 10;
pub const CURLVERSION_TENTH: CURLversion = 9;
pub const CURLVERSION_NINTH: CURLversion = 8;
pub const CURLVERSION_EIGHTH: CURLversion = 7;
pub const CURLVERSION_SEVENTH: CURLversion = 6;
pub const CURLVERSION_SIXTH: CURLversion = 5;
pub const CURLVERSION_FIFTH: CURLversion = 4;
pub const CURLVERSION_FOURTH: CURLversion = 3;
pub const CURLVERSION_THIRD: CURLversion = 2;
pub const CURLVERSION_SECOND: CURLversion = 1;
pub const CURLVERSION_FIRST: CURLversion = 0;
// #[derive(Copy, Clone)]

pub type curl_version_info_data = crate::src::lib::version::curl_version_info_data;
// #[derive(Copy, Clone)]

pub type OperationConfig = crate::src::src::tool_cb_dbg::OperationConfig;
// #[derive(Copy, Clone)]

pub type State = crate::src::src::tool_cb_dbg::State;
// #[derive(Copy, Clone)]

pub type URLGlob = crate::src::src::tool_cb_dbg::URLGlob;
// #[derive(Copy, Clone)]

pub type URLPattern = crate::src::src::tool_cb_dbg::URLPattern;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_2 = crate::src::src::tool_cb_dbg::C2RustUnnamed;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_3 = crate::src::src::tool_cb_dbg::C2RustUnnamed_0;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_4 = crate::src::src::tool_cb_dbg::C2RustUnnamed_1;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_5 = crate::src::src::tool_cb_dbg::C2RustUnnamed_2;
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
// #[derive(Copy, Clone)]

pub type dynbuf = crate::src::lib::altsvc::dynbuf;
pub const set: e_action = 2;
pub type e_action = u32;
pub const deny: e_action = 1;
pub const allow: e_action = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sprotos {
    pub name: *const i8,
    pub bit: i64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct s_tls_max {
    pub tls_max_str: *const i8,
    pub tls_max: i64,
}
#[no_mangle]
pub unsafe extern "C" fn new_getout(mut config: *mut OperationConfig) -> *mut getout {
    let mut node: *mut getout = calloc(
        1 as i32 as u64,
        ::std::mem::size_of::<getout>() as u64,
    ) as *mut getout;
    let mut last: *mut getout = (*config).url_last;
    if !node.is_null() {
        static mut outnum: i32 = 0 as i32;
        if !last.is_null() {
            let fresh0 = &mut ((*last).next);
            *fresh0 = node;
        } else {
            let fresh1 = &mut ((*config).url_list);
            *fresh1 = node;
        }
        let fresh2 = &mut ((*config).url_last);
        *fresh2 = node;
        (*node).flags = (*config).default_node_flags;
        let fresh3 = outnum;
        outnum = outnum + 1;
        (*node).num = fresh3;
    }
    return node;
}
#[no_mangle]
pub unsafe extern "C" fn file2string(
    mut bufp: *mut *mut i8,
    mut file: *mut FILE,
) -> ParameterError {
    let mut dyn_0: dynbuf = dynbuf {
        bufr: 0 as *mut i8,
        leng: 0,
        allc: 0,
        toobig: 0,
    };
    curlx_dyn_init(
        &mut dyn_0,
        (256 as i32 * 1024 as i32 * 1024 as i32) as size_t,
    );
    if !file.is_null() {
        let mut buffer: [i8; 256] = [0; 256];
        while !(fgets(
            buffer.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 256]>() as u64 as i32,
            file,
        ))
            .is_null()
        {
            let mut ptr: *mut i8 = strchr(buffer.as_mut_ptr(), '\r' as i32);
            if !ptr.is_null() {
                *ptr = '\u{0}' as i32 as i8;
            }
            ptr = strchr(buffer.as_mut_ptr(), '\n' as i32);
            if !ptr.is_null() {
                *ptr = '\u{0}' as i32 as i8;
            }
            if curlx_dyn_add(&mut dyn_0, buffer.as_mut_ptr()) as u64 != 0 {
                return PARAM_NO_MEM;
            }
        }
    }
    *bufp = curlx_dyn_ptr(&mut dyn_0);
    return PARAM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn file2memory(
    mut bufp: *mut *mut i8,
    mut size: *mut size_t,
    mut file: *mut FILE,
) -> ParameterError {
    if !file.is_null() {
        let mut nread: size_t = 0;
        let mut dyn_0: dynbuf = dynbuf {
            bufr: 0 as *mut i8,
            leng: 0,
            allc: 0,
            toobig: 0,
        };
        curlx_dyn_init(
            &mut dyn_0,
            (1024 as i32 * 1024 as i32 * 1024 as i32) as size_t,
        );
        loop {
            let mut buffer: [i8; 4096] = [0; 4096];
            nread = fread(
                buffer.as_mut_ptr() as *mut libc::c_void,
                1 as i32 as u64,
                ::std::mem::size_of::<[i8; 4096]>() as u64,
                file,
            );
            if nread != 0 {
                if curlx_dyn_addn(
                    &mut dyn_0,
                    buffer.as_mut_ptr() as *const libc::c_void,
                    nread,
                ) as u64 != 0
                {
                    return PARAM_NO_MEM;
                }
            }
            if !(nread != 0) {
                break;
            }
        }
        *size = curlx_dyn_len(&mut dyn_0);
        *bufp = curlx_dyn_ptr(&mut dyn_0);
    } else {
        *size = 0 as i32 as size_t;
        *bufp = 0 as *mut i8;
    }
    return PARAM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn cleanarg(mut str: *mut i8) {
    if !str.is_null() {
        let mut len: size_t = strlen(str);
        memset(str as *mut libc::c_void, ' ' as i32, len);
    }
}
unsafe extern "C" fn getnum(
    mut val: *mut i64,
    mut str: *const i8,
    mut base: i32,
) -> ParameterError {
    if !str.is_null() {
        let mut endptr: *mut i8 = 0 as *mut i8;
        let mut num: i64 = 0;
        *__errno_location() = 0 as i32;
        num = strtol(str, &mut endptr, base);
        if *__errno_location() == 34 as i32 {
            return PARAM_NUMBER_TOO_LARGE;
        }
        if endptr != str as *mut i8
            && endptr == str.offset(strlen(str) as isize) as *mut i8
        {
            *val = num;
            return PARAM_OK;
        }
    }
    return PARAM_BAD_NUMERIC;
}
#[no_mangle]
pub unsafe extern "C" fn str2num(
    mut val: *mut i64,
    mut str: *const i8,
) -> ParameterError {
    return getnum(val, str, 10 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn oct2nummax(
    mut val: *mut i64,
    mut str: *const i8,
    mut max: i64,
) -> ParameterError {
    let mut result: ParameterError = getnum(val, str, 8 as i32);
    if result as u32 != PARAM_OK as i32 as u32 {
        return result
    } else {
        if *val > max {
            return PARAM_NUMBER_TOO_LARGE
        } else {
            if *val < 0 as i32 as i64 {
                return PARAM_NEGATIVE_NUMERIC;
            }
        }
    }
    return PARAM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn str2unum(
    mut val: *mut i64,
    mut str: *const i8,
) -> ParameterError {
    let mut result: ParameterError = getnum(val, str, 10 as i32);
    if result as u32 != PARAM_OK as i32 as u32 {
        return result;
    }
    if *val < 0 as i32 as i64 {
        return PARAM_NEGATIVE_NUMERIC;
    }
    return PARAM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn str2unummax(
    mut val: *mut i64,
    mut str: *const i8,
    mut max: i64,
) -> ParameterError {
    let mut result: ParameterError = str2unum(val, str);
    if result as u32 != PARAM_OK as i32 as u32 {
        return result;
    }
    if *val > max {
        return PARAM_NUMBER_TOO_LARGE;
    }
    return PARAM_OK;
}
unsafe extern "C" fn str2double(
    mut val: *mut f64,
    mut str: *const i8,
    mut max: i64,
) -> ParameterError {
    if !str.is_null() {
        let mut endptr: *mut i8 = 0 as *mut i8;
        let mut num: f64 = 0.;
        *__errno_location() = 0 as i32;
        num = strtod(str, &mut endptr);
        if *__errno_location() == 34 as i32 {
            return PARAM_NUMBER_TOO_LARGE;
        }
        if num > max as f64 {
            return PARAM_NUMBER_TOO_LARGE;
        }
        if endptr != str as *mut i8
            && endptr == str.offset(strlen(str) as isize) as *mut i8
        {
            *val = num;
            return PARAM_OK;
        }
    }
    return PARAM_BAD_NUMERIC;
}
#[no_mangle]
pub unsafe extern "C" fn str2udouble(
    mut valp: *mut f64,
    mut str: *const i8,
    mut max: i64,
) -> ParameterError {
    let mut value: f64 = 0.;
    let mut result: ParameterError = str2double(&mut value, str, max);
    if result as u32 != PARAM_OK as i32 as u32 {
        return result;
    }
    if value < 0 as i32 as f64 {
        return PARAM_NEGATIVE_NUMERIC;
    }
    *valp = value;
    return PARAM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn proto2num(
    mut config: *mut OperationConfig,
    mut val: *mut i64,
    mut str: *const i8,
) -> i64 {
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut sep: *const i8 = b",\0" as *const u8 as *const i8;
    let mut token: *mut i8 = 0 as *mut i8;
    static mut protos: [sprotos; 24] = [
        {
            let mut init = sprotos {
                name: b"all\0" as *const u8 as *const i8,
                bit: !(0 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"http\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 0 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"https\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 1 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"ftp\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 2 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"ftps\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 3 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"scp\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 4 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"sftp\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 5 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"telnet\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 6 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"ldap\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 7 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"ldaps\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 8 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"dict\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 9 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"file\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 10 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"tftp\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 11 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"imap\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 12 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"imaps\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 13 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"pop3\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 14 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"pop3s\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 15 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"smtp\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 16 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"smtps\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 17 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"rtsp\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 18 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"gopher\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 25 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"smb\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 26 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"smbs\0" as *const u8 as *const i8,
                bit: ((1 as i32) << 27 as i32) as i64,
            };
            init
        },
        {
            let mut init = sprotos {
                name: 0 as *const i8,
                bit: 0 as i32 as i64,
            };
            init
        },
    ];
    if str.is_null() {
        return 1 as i32 as i64;
    }
    buffer = strdup(str);
    if buffer.is_null() {
        return 1 as i32 as i64;
    }
    token = strtok(buffer, sep);
    while !token.is_null() {
        let mut action: e_action = allow;
        let mut pp: *const sprotos = 0 as *const sprotos;
        while Curl_isalnum(*token as u8 as i32) == 0 {
            let fresh4 = token;
            token = token.offset(1);
            match *fresh4 as i32 {
                61 => {
                    action = set;
                }
                45 => {
                    action = deny;
                }
                43 => {
                    action = allow;
                }
                _ => {
                    free(buffer as *mut libc::c_void);
                    buffer = 0 as *mut i8;
                    return 1 as i32 as i64;
                }
            }
        }
        pp = protos.as_ptr();
        while !((*pp).name).is_null() {
            if curl_strequal(token, (*pp).name) != 0 {
                match action as u32 {
                    1 => {
                        *val &= !(*pp).bit;
                    }
                    0 => {
                        *val |= (*pp).bit;
                    }
                    2 => {
                        *val = (*pp).bit;
                    }
                    _ => {}
                }
                break;
            } else {
                pp = pp.offset(1);
            }
        }
        if ((*pp).name).is_null() {
            if action as u32 == set as i32 as u32 {
                *val = 0 as i32 as i64;
            }
            warnf(
                (*config).global,
                b"unrecognized protocol '%s'\n\0" as *const u8 as *const i8,
                token,
            );
        }
        token = strtok(0 as *mut i8, sep);
    }
    free(buffer as *mut libc::c_void);
    buffer = 0 as *mut i8;
    return 0 as i32 as i64;
}
#[no_mangle]
pub unsafe extern "C" fn check_protocol(mut str: *const i8) -> i32 {
    let mut pp: *const *const i8 = 0 as *const *const i8;
    let mut curlinfo: *const curl_version_info_data = curl_version_info(
        CURLVERSION_TENTH,
    );
    if str.is_null() {
        return PARAM_REQUIRES_PARAMETER as i32;
    }
    pp = (*curlinfo).protocols;
    while !(*pp).is_null() {
        if curl_strequal(*pp, str) != 0 {
            return PARAM_OK as i32;
        }
        pp = pp.offset(1);
    }
    return PARAM_LIBCURL_UNSUPPORTED_PROTOCOL as i32;
}
#[no_mangle]
pub unsafe extern "C" fn str2offset(
    mut val: *mut curl_off_t,
    mut str: *const i8,
) -> ParameterError {
    let mut endptr: *mut i8 = 0 as *mut i8;
    if *str.offset(0 as i32 as isize) as i32 == '-' as i32 {
        return PARAM_NEGATIVE_NUMERIC;
    }
    *__errno_location() = 0 as i32;
    *val = strtol(str, &mut endptr, 0 as i32);
    if (*val == -(9223372036854775807 as i64) - 1 as i64
        || *val == 9223372036854775807 as i64)
        && *__errno_location() == 34 as i32
    {
        return PARAM_NUMBER_TOO_LARGE;
    }
    if endptr != str as *mut i8
        && endptr == str.offset(strlen(str) as isize) as *mut i8
    {
        return PARAM_OK;
    }
    return PARAM_BAD_NUMERIC;
}
unsafe extern "C" fn checkpasswd(
    mut kind: *const i8,
    i: size_t,
    last: bool,
    mut userpwd: *mut *mut i8,
) -> CURLcode {
    let mut psep: *mut i8 = 0 as *mut i8;
    let mut osep: *mut i8 = 0 as *mut i8;
    if (*userpwd).is_null() {
        return CURLE_OK;
    }
    psep = strchr(*userpwd, ':' as i32);
    osep = strchr(*userpwd, ';' as i32);
    if psep.is_null() && **userpwd as i32 != ';' as i32 {
        let mut passwd: [i8; 2048] = *::std::mem::transmute::<
            &[u8; 2048],
            &mut [i8; 2048],
        >(
            b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        );
        let mut prompt: [i8; 256] = [0; 256];
        let mut dyn_0: dynbuf = dynbuf {
            bufr: 0 as *mut i8,
            leng: 0,
            allc: 0,
            toobig: 0,
        };
        curlx_dyn_init(&mut dyn_0, (100 as i32 * 1024 as i32) as size_t);
        if !osep.is_null() {
            *osep = '\u{0}' as i32 as i8;
        }
        if i == 0 && last as i32 != 0 {
            curl_msnprintf(
                prompt.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 256]>() as u64,
                b"Enter %s password for user '%s':\0" as *const u8
                    as *const i8,
                kind,
                *userpwd,
            );
        } else {
            curl_msnprintf(
                prompt.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 256]>() as u64,
                b"Enter %s password for user '%s' on URL #%zu:\0" as *const u8
                    as *const i8,
                kind,
                *userpwd,
                i.wrapping_add(1 as i32 as u64),
            );
        }
        getpass_r(
            prompt.as_mut_ptr(),
            passwd.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 2048]>() as u64,
        );
        if !osep.is_null() {
            *osep = ';' as i32 as i8;
        }
        if curlx_dyn_addf(
            &mut dyn_0 as *mut dynbuf,
            b"%s:%s\0" as *const u8 as *const i8,
            *userpwd,
            passwd.as_mut_ptr(),
        ) as u64 != 0
        {
            return CURLE_OUT_OF_MEMORY;
        }
        free(*userpwd as *mut libc::c_void);
        *userpwd = curlx_dyn_ptr(&mut dyn_0);
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn add2list(
    mut list: *mut *mut curl_slist,
    mut ptr: *const i8,
) -> ParameterError {
    let mut newlist: *mut curl_slist = curl_slist_append(*list, ptr);
    if !newlist.is_null() {
        *list = newlist;
    } else {
        return PARAM_NO_MEM
    }
    return PARAM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn ftpfilemethod(
    mut config: *mut OperationConfig,
    mut str: *const i8,
) -> i32 {
    if curl_strequal(b"singlecwd\0" as *const u8 as *const i8, str) != 0 {
        return CURLFTPMETHOD_SINGLECWD as i32;
    }
    if curl_strequal(b"nocwd\0" as *const u8 as *const i8, str) != 0 {
        return CURLFTPMETHOD_NOCWD as i32;
    }
    if curl_strequal(b"multicwd\0" as *const u8 as *const i8, str) != 0 {
        return CURLFTPMETHOD_MULTICWD as i32;
    }
    warnf(
        (*config).global,
        b"unrecognized ftp file method '%s', using default\n\0" as *const u8
            as *const i8,
        str,
    );
    return CURLFTPMETHOD_MULTICWD as i32;
}
#[no_mangle]
pub unsafe extern "C" fn ftpcccmethod(
    mut config: *mut OperationConfig,
    mut str: *const i8,
) -> i32 {
    if curl_strequal(b"passive\0" as *const u8 as *const i8, str) != 0 {
        return CURLFTPSSL_CCC_PASSIVE as i32;
    }
    if curl_strequal(b"active\0" as *const u8 as *const i8, str) != 0 {
        return CURLFTPSSL_CCC_ACTIVE as i32;
    }
    warnf(
        (*config).global,
        b"unrecognized ftp CCC method '%s', using default\n\0" as *const u8
            as *const i8,
        str,
    );
    return CURLFTPSSL_CCC_PASSIVE as i32;
}
#[no_mangle]
pub unsafe extern "C" fn delegation(
    mut config: *mut OperationConfig,
    mut str: *const i8,
) -> i64 {
    if curl_strequal(b"none\0" as *const u8 as *const i8, str) != 0 {
        return 0 as i32 as i64;
    }
    if curl_strequal(b"policy\0" as *const u8 as *const i8, str) != 0 {
        return ((1 as i32) << 0 as i32) as i64;
    }
    if curl_strequal(b"always\0" as *const u8 as *const i8, str) != 0 {
        return ((1 as i32) << 1 as i32) as i64;
    }
    warnf(
        (*config).global,
        b"unrecognized delegation method '%s', using none\n\0" as *const u8
            as *const i8,
        str,
    );
    return 0 as i32 as i64;
}
unsafe extern "C" fn my_useragent() -> *mut i8 {
    return strdup(b"curl/7.79.1\0" as *const u8 as *const i8);
}
#[no_mangle]
pub unsafe extern "C" fn get_args(
    mut config: *mut OperationConfig,
    i: size_t,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut last: bool = if !((*config).next).is_null() {
        0 as i32
    } else {
        1 as i32
    } != 0;
    if !((*config).userpwd).is_null() && ((*config).oauth_bearer).is_null() {
        result = checkpasswd(
            b"host\0" as *const u8 as *const i8,
            i,
            last,
            &mut (*config).userpwd,
        );
        if result as u64 != 0 {
            return result;
        }
    }
    if !((*config).proxyuserpwd).is_null() {
        result = checkpasswd(
            b"proxy\0" as *const u8 as *const i8,
            i,
            last,
            &mut (*config).proxyuserpwd,
        );
        if result as u64 != 0 {
            return result;
        }
    }
    if ((*config).useragent).is_null() {
        let fresh5 = &mut ((*config).useragent);
        *fresh5 = my_useragent();
        if ((*config).useragent).is_null() {
            errorf(
                (*config).global,
                b"out of memory\n\0" as *const u8 as *const i8,
            );
            result = CURLE_OUT_OF_MEMORY;
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn str2tls_max(
    mut val: *mut i64,
    mut str: *const i8,
) -> ParameterError {
    static mut tls_max_array: [s_tls_max; 5] = [
        {
            let mut init = s_tls_max {
                tls_max_str: b"default\0" as *const u8 as *const i8,
                tls_max: CURL_SSLVERSION_MAX_DEFAULT as i32 as i64,
            };
            init
        },
        {
            let mut init = s_tls_max {
                tls_max_str: b"1.0\0" as *const u8 as *const i8,
                tls_max: CURL_SSLVERSION_MAX_TLSv1_0 as i32 as i64,
            };
            init
        },
        {
            let mut init = s_tls_max {
                tls_max_str: b"1.1\0" as *const u8 as *const i8,
                tls_max: CURL_SSLVERSION_MAX_TLSv1_1 as i32 as i64,
            };
            init
        },
        {
            let mut init = s_tls_max {
                tls_max_str: b"1.2\0" as *const u8 as *const i8,
                tls_max: CURL_SSLVERSION_MAX_TLSv1_2 as i32 as i64,
            };
            init
        },
        {
            let mut init = s_tls_max {
                tls_max_str: b"1.3\0" as *const u8 as *const i8,
                tls_max: CURL_SSLVERSION_MAX_TLSv1_3 as i32 as i64,
            };
            init
        },
    ];
    let mut i: size_t = 0 as i32 as size_t;
    if str.is_null() {
        return PARAM_REQUIRES_PARAMETER;
    }
    i = 0 as i32 as size_t;
    while i
        < (::std::mem::size_of::<[s_tls_max; 5]>() as u64)
            .wrapping_div(::std::mem::size_of::<s_tls_max>() as u64)
    {
        if strcmp(str, tls_max_array[i as usize].tls_max_str) == 0 {
            *val = tls_max_array[i as usize].tls_max;
            return PARAM_OK;
        }
        i = i.wrapping_add(1);
    }
    return PARAM_BAD_USE;
}
