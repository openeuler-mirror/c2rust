use ::libc;
extern "C" {
    
    
    
    
    static mut stderr: * mut crate::src::lib::http2::_IO_FILE;
    fn sscanf(_: * const i8, _: * const i8, _: ...) -> i32;
    
    
    
    
    
    fn strtoul(
        _: * const i8,
        _: * mut * mut i8,
        _: i32,
    ) -> u64;
    fn malloc(_: u64) -> * mut core::ffi::c_void;
    fn calloc(_: u64, _: u64) -> * mut core::ffi::c_void;
    fn realloc(_: * mut core::ffi::c_void, _: u64) -> * mut core::ffi::c_void;
    fn free(__ptr: * mut core::ffi::c_void);
    fn memcpy(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn strdup(_: * const i8) -> * mut i8;
    fn strchr(_: * const i8, _: i32) -> * mut i8;
    fn strlen(_: * const i8) -> u64;
    fn __errno_location() -> * mut i32;
    
    
    
    fn curlx_dyn_init(s: * mut crate::src::lib::http2::dynbuf, toobig: u64);
    fn curlx_dyn_free(s: * mut crate::src::lib::http2::dynbuf);
    fn curlx_dyn_addn(s: * mut crate::src::lib::http2::dynbuf, mem: * const core::ffi::c_void, len: u64) -> u32;
    fn curlx_dyn_ptr(s: * const crate::src::lib::http2::dynbuf) -> * mut i8;
}
pub use crate::src::lib::curl_ctype::Curl_isalpha;
pub use crate::src::lib::curl_ctype::Curl_isdigit;
pub use crate::src::lib::mprintf::curl_mfprintf;
pub use crate::src::lib::mprintf::curl_mprintf;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::urlapi::curl_url;
pub use crate::src::lib::urlapi::curl_url_cleanup;
pub use crate::src::lib::urlapi::curl_url_set;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type size_t = u64;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::lib::http2::_IO_FILE;
pub type CURLcode = u32;
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
pub type CURLUcode = u32;
pub const CURLUE_NO_FRAGMENT: CURLUcode = 17;
pub const CURLUE_NO_QUERY: CURLUcode = 16;
pub const CURLUE_NO_PORT: CURLUcode = 15;
pub const CURLUE_NO_HOST: CURLUcode = 14;
pub const CURLUE_NO_OPTIONS: CURLUcode = 13;
pub const CURLUE_NO_PASSWORD: CURLUcode = 12;
pub const CURLUE_NO_USER: CURLUcode = 11;
pub const CURLUE_NO_SCHEME: CURLUcode = 10;
pub const CURLUE_UNKNOWN_PART: CURLUcode = 9;
pub const CURLUE_USER_NOT_ALLOWED: CURLUcode = 8;
pub const CURLUE_OUT_OF_MEMORY: CURLUcode = 7;
pub const CURLUE_URLDECODE: CURLUcode = 6;
pub const CURLUE_UNSUPPORTED_SCHEME: CURLUcode = 5;
pub const CURLUE_BAD_PORT_NUMBER: CURLUcode = 4;
pub const CURLUE_MALFORMED_INPUT: CURLUcode = 3;
pub const CURLUE_BAD_PARTPOINTER: CURLUcode = 2;
pub const CURLUE_BAD_HANDLE: CURLUcode = 1;
pub const CURLUE_OK: CURLUcode = 0;
pub type CURLUPart = u32;
pub const CURLUPART_ZONEID: CURLUPart = 10;
pub const CURLUPART_FRAGMENT: CURLUPart = 9;
pub const CURLUPART_QUERY: CURLUPart = 8;
pub const CURLUPART_PATH: CURLUPart = 7;
pub const CURLUPART_PORT: CURLUPart = 6;
pub const CURLUPART_HOST: CURLUPart = 5;
pub const CURLUPART_OPTIONS: CURLUPart = 4;
pub const CURLUPART_PASSWORD: CURLUPart = 3;
pub const CURLUPART_USER: CURLUPart = 2;
pub const CURLUPART_SCHEME: CURLUPart = 1;
pub const CURLUPART_URL: CURLUPart = 0;
pub type CURLU = crate::src::lib::urlapi::Curl_URL;
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
pub type URLPatternType = u32;
pub const UPTNumRange: URLPatternType = 3;
pub const UPTCharRange: URLPatternType = 2;
pub const UPTSet: URLPatternType = 1;
// #[derive(Copy, Clone)]

pub type dynbuf = crate::src::lib::http2::dynbuf;
unsafe extern "C" fn glob_fixed(
    mut glob: * mut crate::src::src::tool_cb_dbg::URLGlob,
    mut fixed: * mut i8,
    mut len: u64,
) -> u32 {
    let mut pat: Option<&'_ mut crate::src::src::tool_cb_dbg::URLPattern> = Some(&mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(((*glob).pattern).as_mut().unwrap(), ((*glob).size as isize))));
    (*(borrow_mut(&mut pat)).unwrap()).type_0 = UPTSet;
    (*(borrow_mut(&mut pat)).unwrap()).content.Set.size = 1 as i32;
    (*(borrow_mut(&mut pat)).unwrap()).content.Set.ptr_s = 0 as i32;
    (*(borrow_mut(&mut pat)).unwrap()).globindex = -(1 as i32);
    let mut fresh0 = &mut ((*(borrow_mut(&mut pat)).unwrap()).content.Set.elements);
    *fresh0 = malloc(::std::mem::size_of::<*mut i8>() as u64)
        as *mut *mut i8;
    if ((*(borrow_mut(&mut pat)).unwrap()).content.Set.elements).is_null() {
        let mut fresh1 = &mut ((*glob).error);
        *fresh1 = b"out of memory\0" as *const u8 as *const i8;
        (*glob).pos = 0 as i32 as size_t;
        return CURLE_OUT_OF_MEMORY as i32 as CURLcode;
    }
    let mut fresh2 = &mut (*((*(borrow(& pat)).unwrap()).content.Set.elements)
        .offset(0 as i32 as isize));
    *fresh2 = malloc(len.wrapping_add(1 as i32 as u64))
        as *mut i8;
    if (*((*(borrow(& pat)).unwrap()).content.Set.elements).offset(0 as i32 as isize)).is_null() {
        let mut fresh3 = &mut ((*glob).error);
        *fresh3 = b"out of memory\0" as *const u8 as *const i8;
        (*glob).pos = 0 as i32 as size_t;
        return CURLE_OUT_OF_MEMORY as i32 as CURLcode;
    }
    memcpy(
        *((*(borrow(& pat)).unwrap()).content.Set.elements).offset(0 as i32 as isize)
            as *mut libc::c_void,
        fixed as *const libc::c_void,
        len,
    );
    *(*((*(borrow(& pat)).unwrap()).content.Set.elements).offset(0 as i32 as isize))
        .offset(len as isize) = 0 as i32 as i8;
    return CURLE_OK;
}
unsafe extern "C" fn multiply<'a1>(
    mut amount: Option<&'a1 mut u64>,
    mut with: i64,
) -> i32 {
    let mut sum: u64 = (*(borrow(& amount)).unwrap()).wrapping_mul(with as u64);
    if with == 0 {
        *(borrow_mut(&mut amount)).unwrap() = 0 as i32 as u64;
        return 0 as i32;
    }
    if sum.wrapping_div(with as u64) != *(borrow(& amount)).unwrap() {
        return 1 as i32;
    }
    *(borrow_mut(&mut amount)).unwrap() = sum;
    return 0 as i32;
}
unsafe extern "C" fn glob_set<'a1, 'a2, 'a3>(
    mut glob: * mut crate::src::src::tool_cb_dbg::URLGlob,
    mut patternp: Option<&'a1 mut * mut i8>,
    mut posp: Option<&'a2 mut u64>,
    mut amount: Option<&'a3 mut u64>,
    mut globindex: i32,
) -> u32 {
    let mut pat: Option<&'_ mut crate::src::src::tool_cb_dbg::URLPattern> = Option::<&'_ mut crate::src::src::tool_cb_dbg::URLPattern>::None;
    let mut done: bool = 0 as i32 != 0;
    let mut buf: * mut i8 = (*glob).glob_buffer;
    let mut pattern: * mut i8 = *(borrow_mut(&mut patternp)).unwrap();
    let mut opattern: * mut i8 = pattern;
    let mut opos: u64 = (*(borrow(& posp)).unwrap()).wrapping_sub(1 as i32 as u64);
    pat = Some(&mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(((*glob).pattern).as_mut().unwrap(), ((*glob).size as isize))));
    (*(borrow_mut(&mut pat)).unwrap()).type_0 = UPTSet;
    (*(borrow_mut(&mut pat)).unwrap()).content.Set.size = 0 as i32;
    (*(borrow_mut(&mut pat)).unwrap()).content.Set.ptr_s = 0 as i32;
    let mut fresh4 = &mut ((*(borrow_mut(&mut pat)).unwrap()).content.Set.elements);
    *fresh4 = 0 as *mut *mut i8;
    (*(borrow_mut(&mut pat)).unwrap()).globindex = globindex;
    let mut current_block_36: u64;
    while !done {
        match *pattern as i32 {
            0 => {
                let mut fresh5 = &mut ((*glob).error);
                *fresh5 = b"unmatched brace\0" as *const u8 as *const i8;
                (*glob).pos = opos;
                return CURLE_URL_MALFORMAT as i32 as CURLcode;
            }
            123 | 91 => {
                let mut fresh6 = &mut ((*glob).error);
                *fresh6 = b"nested brace\0" as *const u8 as *const i8;
                (*glob).pos = *(borrow_mut(&mut posp)).unwrap();
                return CURLE_URL_MALFORMAT as i32 as CURLcode;
            }
            125 => {
                if opattern == pattern {
                    let mut fresh7 = &mut ((*glob).error);
                    *fresh7 = b"empty string within braces\0" as *const u8
                        as *const i8;
                    (*glob).pos = *(borrow_mut(&mut posp)).unwrap();
                    return CURLE_URL_MALFORMAT as i32 as CURLcode;
                }
                if multiply(
                    borrow_mut(&mut amount),
                    ((*(borrow(& pat)).unwrap()).content.Set.size + 1 as i32) as i64,
                ) != 0
                {
                    let mut fresh8 = &mut ((*glob).error);
                    *fresh8 = b"range overflow\0" as *const u8 as *const i8;
                    (*glob).pos = 0 as i32 as size_t;
                    return CURLE_URL_MALFORMAT as i32 as CURLcode;
                }
                current_block_36 = 6366302455163204299;
            }
            44 => {
                current_block_36 = 6366302455163204299;
            }
            93 => {
                let mut fresh16 = &mut ((*glob).error);
                *fresh16 = b"unexpected close bracket\0" as *const u8
                    as *const i8;
                (*glob).pos = *(borrow_mut(&mut posp)).unwrap();
                return CURLE_URL_MALFORMAT as i32 as CURLcode;
            }
            92 => {
                if *pattern.offset(1 as i32 as isize) != 0 {
                    pattern = pattern.offset(1);
                    *(borrow_mut(&mut posp)).unwrap() = (*(borrow(& posp)).unwrap()).wrapping_add(1);
                }
                current_block_36 = 9754301318773204628;
            }
            _ => {
                current_block_36 = 9754301318773204628;
            }
        }
        match current_block_36 {
            6366302455163204299 => {
                *buf = '\u{0}' as i32 as i8;
                if !((*(borrow_mut(&mut pat)).unwrap()).content.Set.elements).is_null() {
                    let mut new_arr: * mut * mut i8 = realloc(
                        (*(borrow_mut(&mut pat)).unwrap()).content.Set.elements as *mut libc::c_void,
                        (((*(borrow(& pat)).unwrap()).content.Set.size + 1 as i32) as u64)
                            .wrapping_mul(
                                ::std::mem::size_of::<*mut i8>() as u64,
                            ),
                    ) as *mut *mut i8;
                    if new_arr.is_null() {
                        let mut fresh9 = &mut ((*glob).error);
                        *fresh9 = b"out of memory\0" as *const u8 as *const i8;
                        (*glob).pos = 0 as i32 as size_t;
                        return CURLE_OUT_OF_MEMORY as i32 as CURLcode;
                    }
                    let mut fresh10 = &mut ((*(borrow_mut(&mut pat)).unwrap()).content.Set.elements);
                    *fresh10 = new_arr;
                } else {
                    let mut fresh11 = &mut ((*(borrow_mut(&mut pat)).unwrap()).content.Set.elements);
                    *fresh11 = malloc(
                        ::std::mem::size_of::<*mut i8>() as u64,
                    ) as *mut *mut i8;
                }
                if ((*(borrow_mut(&mut pat)).unwrap()).content.Set.elements).is_null() {
                    let mut fresh12 = &mut ((*glob).error);
                    *fresh12 = b"out of memory\0" as *const u8 as *const i8;
                    (*glob).pos = 0 as i32 as size_t;
                    return CURLE_OUT_OF_MEMORY as i32 as CURLcode;
                }
                let mut fresh13 = &mut (*((*(borrow(& pat)).unwrap()).content.Set.elements)
                    .offset((*(borrow(& pat)).unwrap()).content.Set.size as isize));
                *fresh13 = strdup((*glob).glob_buffer);
                if (*((*(borrow(& pat)).unwrap()).content.Set.elements)
                    .offset((*(borrow(& pat)).unwrap()).content.Set.size as isize))
                    .is_null()
                {
                    let mut fresh14 = &mut ((*glob).error);
                    *fresh14 = b"out of memory\0" as *const u8 as *const i8;
                    (*glob).pos = 0 as i32 as size_t;
                    return CURLE_OUT_OF_MEMORY as i32 as CURLcode;
                }
                let mut fresh15 = &mut ((*(borrow_mut(&mut pat)).unwrap()).content.Set.size);
                *fresh15 += 1;
                if *pattern as i32 == '}' as i32 {
                    pattern = pattern.offset(1);
                    done = 1 as i32 != 0;
                } else {
                    buf = (*glob).glob_buffer;
                    pattern = pattern.offset(1);
                    *(borrow_mut(&mut posp)).unwrap() = (*(borrow(& posp)).unwrap()).wrapping_add(1);
                }
            }
            _ => {
                let mut fresh17 = pattern;
                pattern = pattern.offset(1);
                let mut fresh18 = buf;
                buf = buf.offset(1);
                *fresh18 = *fresh17;
                *(borrow_mut(&mut posp)).unwrap() = (*(borrow(& posp)).unwrap()).wrapping_add(1);
            }
        }
    }
    *(borrow_mut(&mut patternp)).unwrap() = pattern;
    return CURLE_OK;
}
unsafe extern "C" fn glob_range<'a1, 'a2, 'a3>(
    mut glob: * mut crate::src::src::tool_cb_dbg::URLGlob,
    mut patternp: Option<&'a1 mut * mut i8>,
    mut posp: Option<&'a2 mut u64>,
    mut amount: Option<&'a3 mut u64>,
    mut globindex: i32,
) -> u32 {
    let mut pat: Option<&'_ mut crate::src::src::tool_cb_dbg::URLPattern> = Option::<&'_ mut crate::src::src::tool_cb_dbg::URLPattern>::None;
    let mut rc: i32 = 0;
    let mut pattern: * mut i8 = *(borrow_mut(&mut patternp)).unwrap();
    let mut c: * mut i8 = 0 as *mut i8;
    pat = Some(&mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(((*glob).pattern).as_mut().unwrap(), ((*glob).size as isize))));
    (*(borrow_mut(&mut pat)).unwrap()).globindex = globindex;
    if Curl_isalpha(*pattern as u8 as i32) != 0 {
        let mut min_c: i8 = 0;
        let mut max_c: i8 = 0;
        let mut end_c: i8 = 0;
        let mut step: u64 = 1 as i32 as u64;
        (*(borrow_mut(&mut pat)).unwrap()).type_0 = UPTCharRange;
        rc = sscanf(
            pattern,
            b"%c-%c%c\0" as *const u8 as *const i8,
            &mut min_c as *mut i8,
            &mut max_c as *mut i8,
            &mut end_c as *mut i8,
        );
        if rc == 3 as i32 {
            if end_c as i32 == ':' as i32 {
                let mut endp: * mut i8 = 0 as *mut i8;
                *__errno_location() = 0 as i32;
                step = strtoul(
                    &mut *pattern.offset(4 as i32 as isize),
                    &mut endp,
                    10 as i32,
                );
                if *__errno_location() != 0
                    || &mut *pattern.offset(4 as i32 as isize)
                        as *mut i8 == endp
                    || *endp as i32 != ']' as i32
                {
                    step = 0 as i32 as u64;
                } else {
                    pattern = endp.offset(1 as i32 as isize);
                }
            } else if end_c as i32 != ']' as i32 {
                rc = 0 as i32;
            } else {
                pattern = pattern.offset(4 as i32 as isize);
            }
        }
        *(borrow_mut(&mut posp)).unwrap() = (*(borrow(& posp)).unwrap() as u64)
            .wrapping_add(
                pattern.offset_from(*(borrow(& patternp)).unwrap()) as i64 as u64,
            ) as size_t as size_t;
        if rc != 3 as i32 || step == 0
            || step > 2147483647 as i32 as u32 as u64
            || min_c as i32 == max_c as i32
                && step != 1 as i32 as u64
            || min_c as i32 != max_c as i32
                && (min_c as i32 > max_c as i32
                    || step
                        > (max_c as i32 - min_c as i32) as u32
                            as u64
                    || max_c as i32 - min_c as i32
                        > 'z' as i32 - 'a' as i32)
        {
            let mut fresh19 = &mut ((*glob).error);
            *fresh19 = b"bad range\0" as *const u8 as *const i8;
            (*glob).pos = *(borrow_mut(&mut posp)).unwrap();
            return CURLE_URL_MALFORMAT as i32 as CURLcode;
        }
        (*(borrow_mut(&mut pat)).unwrap()).content.CharRange.step = step as i32;
        let mut fresh20 = &mut ((*(borrow_mut(&mut pat)).unwrap()).content.CharRange.min_c);
        *fresh20 = min_c;
        (*(borrow_mut(&mut pat)).unwrap()).content.CharRange.ptr_c = *fresh20;
        (*(borrow_mut(&mut pat)).unwrap()).content.CharRange.max_c = max_c;
        if multiply(
            borrow_mut(&mut amount),
            (((*(borrow(& pat)).unwrap()).content.CharRange.max_c as i32
                - (*(borrow(& pat)).unwrap()).content.CharRange.min_c as i32)
                / (*(borrow(& pat)).unwrap()).content.CharRange.step + 1 as i32) as i64,
        ) != 0
        {
            let mut fresh21 = &mut ((*glob).error);
            *fresh21 = b"range overflow\0" as *const u8 as *const i8;
            (*glob).pos = *(borrow_mut(&mut posp)).unwrap();
            return CURLE_URL_MALFORMAT as i32 as CURLcode;
        }
    } else if Curl_isdigit(*pattern as u8 as i32) != 0 {
        let mut min_n: u64 = 0;
        let mut max_n: u64 = 0 as i32 as u64;
        let mut step_n: u64 = 0 as i32 as u64;
        let mut endp_0: * mut i8 = 0 as *mut i8;
        (*(borrow_mut(&mut pat)).unwrap()).type_0 = UPTNumRange;
        (*(borrow_mut(&mut pat)).unwrap()).content.NumRange.padlength = 0 as i32;
        if *pattern as i32 == '0' as i32 {
            c = pattern;
            while Curl_isdigit(*c as u8 as i32) != 0 {
                c = c.offset(1);
                let mut fresh22 = &mut ((*(borrow_mut(&mut pat)).unwrap()).content.NumRange.padlength);
                *fresh22 += 1;
            }
        }
        *__errno_location() = 0 as i32;
        min_n = strtoul(pattern, &mut endp_0, 10 as i32);
        if *__errno_location() != 0 || endp_0 == pattern {
            endp_0 = 0 as *mut i8;
        } else if *endp_0 as i32 != '-' as i32 {
            endp_0 = 0 as *mut i8;
        } else {
            pattern = endp_0.offset(1 as i32 as isize);
            while *pattern as i32 != 0
                && (*pattern as u8 as i32 == ' ' as i32
                    || *pattern as u8 as i32 == '\t' as i32)
            {
                pattern = pattern.offset(1);
            }
            if Curl_isdigit(*pattern as u8 as i32) == 0 {
                endp_0 = 0 as *mut i8;
            } else {
                *__errno_location() = 0 as i32;
                max_n = strtoul(pattern, &mut endp_0, 10 as i32);
                if *__errno_location() != 0 {
                    endp_0 = 0 as *mut i8;
                } else if *endp_0 as i32 == ':' as i32 {
                    pattern = endp_0.offset(1 as i32 as isize);
                    *__errno_location() = 0 as i32;
                    step_n = strtoul(pattern, &mut endp_0, 10 as i32);
                    if *__errno_location() != 0 {
                        endp_0 = 0 as *mut i8;
                    }
                } else {
                    step_n = 1 as i32 as u64;
                }
                if !endp_0.is_null() && *endp_0 as i32 == ']' as i32 {
                    pattern = endp_0.offset(1 as i32 as isize);
                } else {
                    endp_0 = 0 as *mut i8;
                }
            }
        }
        *(borrow_mut(&mut posp)).unwrap() = (*(borrow(& posp)).unwrap() as u64)
            .wrapping_add(
                pattern.offset_from(*(borrow(& patternp)).unwrap()) as i64 as u64,
            ) as size_t as size_t;
        if endp_0.is_null() || step_n == 0
            || min_n == max_n && step_n != 1 as i32 as u64
            || min_n != max_n && (min_n > max_n || step_n > max_n.wrapping_sub(min_n))
        {
            let mut fresh23 = &mut ((*glob).error);
            *fresh23 = b"bad range\0" as *const u8 as *const i8;
            (*glob).pos = *(borrow_mut(&mut posp)).unwrap();
            return CURLE_URL_MALFORMAT as i32 as CURLcode;
        }
        let mut fresh24 = &mut ((*(borrow_mut(&mut pat)).unwrap()).content.NumRange.min_n);
        *fresh24 = min_n;
        (*(borrow_mut(&mut pat)).unwrap()).content.NumRange.ptr_n = *fresh24;
        (*(borrow_mut(&mut pat)).unwrap()).content.NumRange.max_n = max_n;
        (*(borrow_mut(&mut pat)).unwrap()).content.NumRange.step = step_n;
        if multiply(
            borrow_mut(&mut amount),
            ((*(borrow(& pat)).unwrap()).content.NumRange.max_n)
                .wrapping_sub((*(borrow(& pat)).unwrap()).content.NumRange.min_n)
                .wrapping_div((*(borrow(& pat)).unwrap()).content.NumRange.step)
                .wrapping_add(1 as i32 as u64) as i64,
        ) != 0
        {
            let mut fresh25 = &mut ((*glob).error);
            *fresh25 = b"range overflow\0" as *const u8 as *const i8;
            (*glob).pos = *(borrow_mut(&mut posp)).unwrap();
            return CURLE_URL_MALFORMAT as i32 as CURLcode;
        }
    } else {
        let mut fresh26 = &mut ((*glob).error);
        *fresh26 = b"bad range specification\0" as *const u8 as *const i8;
        (*glob).pos = *(borrow_mut(&mut posp)).unwrap();
        return CURLE_URL_MALFORMAT as i32 as CURLcode;
    }
    *(borrow_mut(&mut patternp)).unwrap() = pattern;
    return CURLE_OK;
}
unsafe extern "C" fn peek_ipv6<'a1>(
    mut str: * const i8,
    mut skip: Option<&'a1 mut u64>,
) -> bool {
    let mut hostname: [i8; 128] = [0; 128];
    let mut u: * mut crate::src::lib::urlapi::Curl_URL = 0 as *mut CURLU;
    let mut endbr: * mut i8 = strchr(str, ']' as i32);
    let mut hlen: u64 = 0;
    let mut rc: u32 = CURLUE_OK;
    if endbr.is_null() {
        return 0 as i32 != 0;
    }
    hlen = (endbr.offset_from(str) as i64 + 1 as i32 as i64)
        as size_t;
    if hlen >= 128 as i32 as u64 {
        return 0 as i32 != 0;
    }
    u = curl_url();
    if u.is_null() {
        return 0 as i32 != 0;
    }
    memcpy(hostname.as_mut_ptr() as *mut libc::c_void, str as *const libc::c_void, hlen);
    hostname[hlen as usize] = 0 as i32 as i8;
    rc = curl_url_set(
        u,
        CURLUPART_URL,
        hostname.as_mut_ptr(),
        ((1 as i32) << 9 as i32) as u32,
    );
    curl_url_cleanup(u);
    if rc as u64 == 0 {
        *(borrow_mut(&mut skip)).unwrap() = hlen;
    }
    return if rc as u32 != 0 { 0 as i32 } else { 1 as i32 }
        != 0;
}
unsafe extern "C" fn glob_parse<'a1>(
    mut glob: * mut crate::src::src::tool_cb_dbg::URLGlob,
    mut pattern: * mut i8,
    mut pos: u64,
    mut amount: Option<&'a1 mut u64>,
) -> u32 {
    let mut res: u32 = CURLE_OK;
    let mut globindex: i32 = 0 as i32;
    *(borrow_mut(&mut amount)).unwrap() = 1 as i32 as u64;
    while *pattern as i32 != 0 && res as u64 == 0 {
        let mut buf: * mut i8 = (*glob).glob_buffer;
        let mut sublen: u64 = 0 as i32 as size_t;
        while *pattern as i32 != 0 && *pattern as i32 != '{' as i32 {
            if *pattern as i32 == '[' as i32 {
                let mut skip: u64 = 0 as i32 as size_t;
                if !peek_ipv6(pattern, Some(&mut skip))
                    && *pattern.offset(1 as i32 as isize) as i32
                        == ']' as i32
                {
                    skip = 2 as i32 as size_t;
                }
                if !(skip != 0) {
                    break;
                }
                memcpy(buf as *mut libc::c_void, pattern as *const libc::c_void, skip);
                buf = buf.offset(skip as isize);
                pattern = pattern.offset(skip as isize);
                sublen = (sublen as u64).wrapping_add(skip) as size_t
                    as size_t;
            } else {
                if *pattern as i32 == '}' as i32
                    || *pattern as i32 == ']' as i32
                {
                    let mut fresh27 = &mut ((*glob).error);
                    *fresh27 = b"unmatched close brace/bracket\0" as *const u8
                        as *const i8;
                    (*glob).pos = pos;
                    return CURLE_URL_MALFORMAT as i32 as CURLcode;
                }
                if *pattern as i32 == '\\' as i32
                    && (*pattern.offset(1 as i32 as isize) as i32
                        == '{' as i32
                        || *pattern.offset(1 as i32 as isize) as i32
                            == '[' as i32
                        || *pattern.offset(1 as i32 as isize) as i32
                            == '}' as i32
                        || *pattern.offset(1 as i32 as isize) as i32
                            == ']' as i32)
                {
                    pattern = pattern.offset(1);
                    pos = pos.wrapping_add(1);
                }
                let mut fresh28 = pattern;
                pattern = pattern.offset(1);
                let mut fresh29 = buf;
                buf = buf.offset(1);
                *fresh29 = *fresh28;
                pos = pos.wrapping_add(1);
                sublen = sublen.wrapping_add(1);
            }
        }
        if sublen != 0 {
            *buf = '\u{0}' as i32 as i8;
            res = glob_fixed(glob, (*glob).glob_buffer, sublen);
        } else {
            match *pattern as i32 {
                123 => {
                    pattern = pattern.offset(1);
                    pos = pos.wrapping_add(1);
                    let mut fresh30 = globindex;
                    globindex = globindex + 1;
                    res = glob_set(glob, Some(&mut pattern), Some(&mut pos), borrow_mut(&mut amount), fresh30);
                }
                91 => {
                    pattern = pattern.offset(1);
                    pos = pos.wrapping_add(1);
                    let mut fresh31 = globindex;
                    globindex = globindex + 1;
                    res = glob_range(glob, Some(&mut pattern), Some(&mut pos), borrow_mut(&mut amount), fresh31);
                }
                0 | _ => {}
            }
        }
        let mut fresh32 = &mut ((*glob).size);
        *fresh32 = (*fresh32).wrapping_add(1);
        if *fresh32 >= 100 as i32 as u64 {
            let mut fresh33 = &mut ((*glob).error);
            *fresh33 = b"too many globs\0" as *const u8 as *const i8;
            (*glob).pos = pos;
            return CURLE_URL_MALFORMAT as i32 as CURLcode;
        }
    }
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn glob_url<'a1, 'a2>(
    mut glob: Option<&'a1 mut * mut crate::src::src::tool_cb_dbg::URLGlob>,
    mut url: * mut i8,
    mut urlnum: Option<&'a2 mut u64>,
    mut error: * mut crate::src::lib::http2::_IO_FILE,
) -> u32 {
    let mut glob_expand: * mut crate::src::src::tool_cb_dbg::URLGlob = 0 as *mut URLGlob;
    let mut amount: u64 = 0 as i32 as u64;
    let mut glob_buffer: * mut i8 = 0 as *mut i8;
    let mut res: u32 = CURLE_OK;
    *(borrow_mut(&mut glob)).unwrap() = 0 as *mut URLGlob;
    glob_buffer = malloc((strlen(url)).wrapping_add(1 as i32 as u64))
        as *mut i8;
    if glob_buffer.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    *glob_buffer.offset(0 as i32 as isize) = 0 as i32 as i8;
    glob_expand = calloc(
        1 as i32 as u64,
        ::std::mem::size_of::<URLGlob>() as u64,
    ) as *mut URLGlob;
    if glob_expand.is_null() {
        free(glob_buffer as *mut libc::c_void);
        glob_buffer = 0 as *mut i8;
        return CURLE_OUT_OF_MEMORY;
    }
    (*glob_expand).urllen = strlen(url);
    let mut fresh34 = &mut ((*glob_expand).glob_buffer);
    *fresh34 = glob_buffer;
    res = glob_parse(glob_expand, url, 1 as i32 as size_t, Some(&mut amount));
    if res as u64 == 0 {
        *(borrow_mut(&mut urlnum)).unwrap() = amount;
    } else {
        if !error.is_null() && !((*glob_expand).error).is_null() {
            let mut text: [i8; 512] = [0; 512];
            let mut t: * const i8 = 0 as *const i8;
            if (*glob_expand).pos != 0 {
                curl_msnprintf(
                    text.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 512]>() as u64,
                    b"%s in URL position %zu:\n%s\n%*s^\0" as *const u8
                        as *const i8,
                    (*glob_expand).error,
                    (*glob_expand).pos,
                    url,
                    (*glob_expand).pos as i32 - 1 as i32,
                    b" \0" as *const u8 as *const i8,
                );
                t = text.as_mut_ptr();
            } else {
                t = (*glob_expand).error;
            }
            curl_mfprintf(
                error,
                b"curl: (%d) %s\n\0" as *const u8 as *const i8,
                res as u32,
                t,
            );
        }
        glob_cleanup(glob_expand);
        *(borrow_mut(&mut urlnum)).unwrap() = 1 as i32 as u64;
        return res;
    }
    *(borrow_mut(&mut glob)).unwrap() = glob_expand;
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn glob_cleanup(mut glob: * mut crate::src::src::tool_cb_dbg::URLGlob) {
    let mut i: u64 = 0;
    let mut elem: i32 = 0;
    if glob.is_null() {
        return;
    }
    i = 0 as i32 as size_t;
    while i < (*glob).size {
        if (*crate::__laertes_array::Get::<&_>::get_add(((*glob).pattern).as_ref().unwrap(), (i as usize))).type_0 as u32
            == UPTSet as i32 as u32
            && !((*crate::__laertes_array::Get::<&_>::get_add(((*glob).pattern).as_ref().unwrap(), (i as usize))).content.Set.elements).is_null()
        {
            elem = (*crate::__laertes_array::Get::<&_>::get_add(((*glob).pattern).as_ref().unwrap(), (i as usize))).content.Set.size - 1 as i32;
            while elem >= 0 as i32 {
                free(
                    *((*crate::__laertes_array::Get::<&_>::get_add(((*glob).pattern).as_ref().unwrap(), (i as usize))).content.Set.elements)
                        .offset(elem as isize) as *mut libc::c_void,
                );
                let mut fresh35 = &mut (*((*crate::__laertes_array::Get::<&_>::get_add(((*glob).pattern).as_ref().unwrap(), (i as usize))).content.Set.elements)
                    .offset(elem as isize));
                *fresh35 = 0 as *mut i8;
                elem -= 1;
            }
            free((*crate::__laertes_array::GetMut::<&mut _>::get_add_mut(((*glob).pattern).as_mut().unwrap(), (i as usize))).content.Set.elements as *mut libc::c_void);
            // let fresh36 = &mut ((*glob).pattern[i as usize].content.Set.elements);
            let mut fresh36 = &mut ((*crate::__laertes_array::GetMut::<&mut _>::get_add_mut(((*glob).pattern).as_mut().unwrap(), (i as usize))).content.Set.elements);
            *fresh36 = 0 as *mut *mut i8;
        }
        i = i.wrapping_add(1);
    }
    free((*glob).glob_buffer as *mut libc::c_void);
    let mut fresh37 = &mut ((*glob).glob_buffer);
    *fresh37 = 0 as *mut i8;
    free(glob as *mut libc::c_void);
    glob = 0 as *mut URLGlob;
}
#[no_mangle]
pub unsafe extern "C" fn glob_next_url<'a1>(
    mut globbed: Option<&'a1 mut * mut i8>,
    mut glob: * mut crate::src::src::tool_cb_dbg::URLGlob,
) -> u32 {
    let mut pat: * mut crate::src::src::tool_cb_dbg::URLPattern = (0 as * mut crate::src::src::tool_cb_dbg::URLPattern);
    let mut i: u64 = 0;
    let mut len: u64 = 0;
    let mut buflen: u64 = ((*glob).urllen)
        .wrapping_add(1 as i32 as u64);
    let mut buf: * mut i8 = (*glob).glob_buffer;
    *(borrow_mut(&mut globbed)).unwrap() = 0 as *mut i8;
    if (*glob).beenhere == 0 {
        (*glob).beenhere = 1 as i32 as i8;
    } else {
        let mut carry: bool = 1 as i32 != 0;
        i = 0 as i32 as size_t;
        while carry as i32 != 0 && i < (*glob).size {
            carry = 0 as i32 != 0;
            pat = &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(((*glob).pattern).as_mut().unwrap(), (((*glob).size)
                        .wrapping_sub(1 as i32 as u64)
                        .wrapping_sub(i) as isize))) as *mut URLPattern;
            match (*pat).type_0 as u32 {
                1 => {
                    if !((*pat).content.Set.elements).is_null()
                        && {
                            let mut fresh38 = &mut ((*pat).content.Set.ptr_s);
                            *fresh38 += 1;
                            *fresh38 == (*pat).content.Set.size
                        }
                    {
                        (*pat).content.Set.ptr_s = 0 as i32;
                        carry = 1 as i32 != 0;
                    }
                }
                2 => {
                    (*pat)
                        .content
                        .CharRange
                        .ptr_c = ((*pat).content.CharRange.step
                        + (*pat).content.CharRange.ptr_c as u8 as i32)
                        as i8;
                    if (*pat).content.CharRange.ptr_c as i32
                        > (*pat).content.CharRange.max_c as i32
                    {
                        (*pat).content.CharRange.ptr_c = (*pat).content.CharRange.min_c;
                        carry = 1 as i32 != 0;
                    }
                }
                3 => {
                    let mut fresh39 = &mut ((*pat).content.NumRange.ptr_n);
                    *fresh39 = (*fresh39).wrapping_add((*pat).content.NumRange.step);
                    if (*pat).content.NumRange.ptr_n > (*pat).content.NumRange.max_n {
                        (*pat).content.NumRange.ptr_n = (*pat).content.NumRange.min_n;
                        carry = 1 as i32 != 0;
                    }
                }
                _ => {
                    curl_mprintf(
                        b"internal error: invalid pattern type (%d)\n\0" as *const u8
                            as *const i8,
                        (*pat).type_0 as i32,
                    );
                    return CURLE_FAILED_INIT;
                }
            }
            i = i.wrapping_add(1);
        }
        if carry {
            return CURLE_OK;
        }
    }
    i = 0 as i32 as size_t;
    while i < (*glob).size {
        pat = &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(((*glob).pattern).as_mut().unwrap(), (i as isize))) as *mut URLPattern;
        match (*pat).type_0 as u32 {
            1 => {
                if !((*pat).content.Set.elements).is_null() {
                    curl_msnprintf(
                        buf,
                        buflen,
                        b"%s\0" as *const u8 as *const i8,
                        *((*pat).content.Set.elements)
                            .offset((*pat).content.Set.ptr_s as isize),
                    );
                    len = strlen(buf);
                    buf = buf.offset(len as isize);
                    buflen = (buflen as u64).wrapping_sub(len) as size_t
                        as size_t;
                }
            }
            2 => {
                if buflen != 0 {
                    let mut fresh40 = buf;
                    buf = buf.offset(1);
                    *fresh40 = (*pat).content.CharRange.ptr_c;
                    *buf = '\u{0}' as i32 as i8;
                    buflen = buflen.wrapping_sub(1);
                }
            }
            3 => {
                curl_msnprintf(
                    buf,
                    buflen,
                    b"%0*lu\0" as *const u8 as *const i8,
                    (*pat).content.NumRange.padlength,
                    (*pat).content.NumRange.ptr_n,
                );
                len = strlen(buf);
                buf = buf.offset(len as isize);
                buflen = (buflen as u64).wrapping_sub(len) as size_t as size_t;
            }
            _ => {
                curl_mprintf(
                    b"internal error: invalid pattern type (%d)\n\0" as *const u8
                        as *const i8,
                    (*pat).type_0 as i32,
                );
                return CURLE_FAILED_INIT;
            }
        }
        i = i.wrapping_add(1);
    }
    *(borrow_mut(&mut globbed)).unwrap() = strdup((*glob).glob_buffer);
    if (*(borrow_mut(&mut globbed)).unwrap()).is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn glob_match_url<'a1>(
    mut result: Option<&'a1 mut * mut i8>,
    mut filename: * mut i8,
    mut glob: * mut crate::src::src::tool_cb_dbg::URLGlob,
) -> u32 {
    let mut numbuf: [i8; 18] = [0; 18];
    let mut appendthis: * mut i8 = b"\0" as *const u8 as *const i8
        as *mut i8;
    let mut appendlen: u64 = 0 as i32 as size_t;
    let mut dyn_0: crate::src::lib::http2::dynbuf = dynbuf {
        bufr: 0 as *mut i8,
        leng: 0,
        allc: 0,
        toobig: 0,
    };
    *(borrow_mut(&mut result)).unwrap() = 0 as *mut i8;
    curlx_dyn_init(&mut dyn_0, (10 as i32 * 1024 as i32) as size_t);
    while *filename != 0 {
        if *filename as i32 == '#' as i32
            && Curl_isdigit(
                *filename.offset(1 as i32 as isize) as u8
                    as i32,
            ) != 0
        {
            let mut ptr: * mut i8 = filename;
            let mut num: u64 = strtoul(
                &mut *filename.offset(1 as i32 as isize),
                &mut filename,
                10 as i32,
            );
            let mut pat: Option<&'_ mut crate::src::src::tool_cb_dbg::URLPattern> = Option::<&'_ mut crate::src::src::tool_cb_dbg::URLPattern>::None;
            if num != 0 && num < (*glob).size {
                let mut i: u64 = 0;
                num = num.wrapping_sub(1);
                i = 0 as i32 as u64;
                while i < (*glob).size {
                    if (*crate::__laertes_array::Get::<&_>::get_add(((*glob).pattern).as_ref().unwrap(), (i as usize))).globindex == num as i32 {
                        pat = Some(&mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(((*glob).pattern).as_mut().unwrap(), (i as isize))));
                        break;
                    } else {
                        i = i.wrapping_add(1);
                    }
                }
            }
            if !borrow(& pat).is_none() {
                match (*(borrow(& pat)).unwrap()).type_0 as u32 {
                    1 => {
                        if !((*(borrow(& pat)).unwrap()).content.Set.elements).is_null() {
                            appendthis = *((*(borrow(& pat)).unwrap()).content.Set.elements)
                                .offset((*(borrow(& pat)).unwrap()).content.Set.ptr_s as isize);
                            appendlen = strlen(
                                *((*(borrow(& pat)).unwrap()).content.Set.elements)
                                    .offset((*(borrow(& pat)).unwrap()).content.Set.ptr_s as isize),
                            );
                        }
                    }
                    2 => {
                        numbuf[0 as i32
                            as usize] = (*(borrow_mut(&mut pat)).unwrap()).content.CharRange.ptr_c;
                        numbuf[1 as i32
                            as usize] = 0 as i32 as i8;
                        appendthis = numbuf.as_mut_ptr();
                        appendlen = 1 as i32 as size_t;
                    }
                    3 => {
                        curl_msnprintf(
                            numbuf.as_mut_ptr(),
                            ::std::mem::size_of::<[i8; 18]>() as u64,
                            b"%0*lu\0" as *const u8 as *const i8,
                            (*(borrow(& pat)).unwrap()).content.NumRange.padlength,
                            (*(borrow(& pat)).unwrap()).content.NumRange.ptr_n,
                        );
                        appendthis = numbuf.as_mut_ptr();
                        appendlen = strlen(numbuf.as_mut_ptr());
                    }
                    _ => {
                        curl_mfprintf(
                            stderr,
                            b"internal error: invalid pattern type (%d)\n\0" as *const u8
                                as *const i8,
                            (*(borrow(& pat)).unwrap()).type_0 as i32,
                        );
                        curlx_dyn_free(&mut dyn_0);
                        return CURLE_FAILED_INIT;
                    }
                }
            } else {
                filename = ptr;
                let mut fresh41 = filename;
                filename = filename.offset(1);
                appendthis = fresh41;
                appendlen = 1 as i32 as size_t;
            }
        } else {
            let mut fresh42 = filename;
            filename = filename.offset(1);
            appendthis = fresh42;
            appendlen = 1 as i32 as size_t;
        }
        if curlx_dyn_addn(&mut dyn_0, appendthis as *const libc::c_void, appendlen)
            as u64 != 0
        {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    *(borrow_mut(&mut result)).unwrap() = curlx_dyn_ptr(&mut dyn_0);
    return CURLE_OK;
}
use crate::laertes_rt::*;
