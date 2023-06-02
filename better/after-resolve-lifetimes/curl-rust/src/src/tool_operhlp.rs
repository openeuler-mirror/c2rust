use ::libc;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    fn strcmp(_: * const i8, _: * const i8) -> i32;
    fn strdup(_: * const i8) -> * mut i8;
    fn strrchr(_: * const i8, _: i32) -> * mut i8;
    fn strstr(_: * const i8, _: * const i8) -> * mut i8;
    fn strlen(_: * const i8) -> u64;
    fn free(__ptr: * mut core::ffi::c_void);
    
}
pub use crate::src::lib::easy::curl_easy_cleanup;
pub use crate::src::lib::easy::curl_easy_init;
pub use crate::src::lib::escape::curl_easy_escape;
pub use crate::src::lib::escape::curl_free;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::strcase::curl_strnequal;
pub use crate::src::lib::http2::Curl_easy;
pub use crate::src::lib::http2::curl_mime;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type size_t = u64;
pub type curl_off_t = i64;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::lib::http2::_IO_FILE;
pub type CURL = crate::src::lib::http2::Curl_easy;
// #[derive(Copy, Clone)]

pub type curl_slist = crate::src::lib::http2::curl_slist;
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
pub type curl_TimeCond = u32;
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
pub type URLPatternType = u32;
pub const UPTNumRange: URLPatternType = 3;
pub const UPTCharRange: URLPatternType = 2;
pub const UPTSet: URLPatternType = 1;
// #[derive(Copy, Clone)]

pub type getout = crate::src::src::tool_cb_dbg::getout;
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone)]

pub type tool_mime = crate::src::src::tool_cb_dbg::tool_mime;
pub type toolmimekind = u32;
pub const TOOLMIME_STDINDATA: toolmimekind = 6;
pub const TOOLMIME_STDIN: toolmimekind = 5;
pub const TOOLMIME_FILEDATA: toolmimekind = 4;
pub const TOOLMIME_FILE: toolmimekind = 3;
pub const TOOLMIME_DATA: toolmimekind = 2;
pub const TOOLMIME_PARTS: toolmimekind = 1;
pub const TOOLMIME_NONE: toolmimekind = 0;
#[no_mangle]
pub unsafe extern "C" fn clean_getout(mut config: * mut crate::src::src::tool_cb_dbg::OperationConfig) {
    if !config.is_null() {
        let mut next: * mut crate::src::src::tool_cb_dbg::getout = 0 as *mut getout;
        let mut node: * mut crate::src::src::tool_cb_dbg::getout = (*config).url_list;
        while !node.is_null() {
            next = (*node).next;
            free((*node).url as *mut libc::c_void);
            let mut fresh0 = &mut ((*node).url);
            *fresh0 = 0 as *mut i8;
            free((*node).outfile as *mut libc::c_void);
            let mut fresh1 = &mut ((*node).outfile);
            *fresh1 = 0 as *mut i8;
            free((*node).infile as *mut libc::c_void);
            let mut fresh2 = &mut ((*node).infile);
            *fresh2 = 0 as *mut i8;
            free(node as *mut libc::c_void);
            node = 0 as *mut getout;
            node = next;
        }
        let mut fresh3 = &mut ((*config).url_list);
        *fresh3 = 0 as *mut getout;
    }
}
#[no_mangle]
pub unsafe extern "C" fn output_expected(
    mut url: * const i8,
    mut uploadfile: * const i8,
) -> bool {
    if uploadfile.is_null() {
        return 1 as i32 != 0;
    }
    if curl_strnequal(
        b"http://\0" as *const u8 as *const i8,
        url,
        strlen(b"http://\0" as *const u8 as *const i8),
    ) != 0
        || curl_strnequal(
            b"https://\0" as *const u8 as *const i8,
            url,
            strlen(b"https://\0" as *const u8 as *const i8),
        ) != 0
    {
        return 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn stdin_upload(mut uploadfile: * const i8) -> bool {
    return if strcmp(uploadfile, b"-\0" as *const u8 as *const i8) == 0
        || strcmp(uploadfile, b".\0" as *const u8 as *const i8) == 0
    {
        1 as i32
    } else {
        0 as i32
    } != 0;
}
#[no_mangle]
pub unsafe extern "C" fn add_file_name_to_url(
    mut url: * mut i8,
    mut filename: * const i8,
) -> * mut i8 {
    let mut ptr: * mut i8 = strstr(
        url,
        b"://\0" as *const u8 as *const i8,
    );
    let mut curl: * mut crate::src::lib::http2::Curl_easy = curl_easy_init();
    if curl.is_null() {
        return 0 as *mut i8;
    }
    if !ptr.is_null() {
        ptr = ptr.offset(3 as i32 as isize);
    } else {
        ptr = url;
    }
    ptr = strrchr(ptr, '/' as i32);
    if ptr.is_null()
        || {
            ptr = ptr.offset(1);
            *ptr == 0
        }
    {
        let mut filep: * const i8 = strrchr(filename, '/' as i32);
        let mut file2: * mut i8 = strrchr(
            if !filep.is_null() { filep } else { filename },
            '\\' as i32,
        );
        let mut encfile: * mut i8 = 0 as *mut i8;
        if !file2.is_null() {
            filep = file2.offset(1 as i32 as isize);
        } else if !filep.is_null() {
            filep = filep.offset(1);
        } else {
            filep = filename;
        }
        encfile = curl_easy_escape(curl, filep, 0 as i32);
        if !encfile.is_null() {
            let mut urlbuffer: * mut i8 = 0 as *mut i8;
            if !ptr.is_null() {
                urlbuffer = curl_maprintf(
                    b"%s%s\0" as *const u8 as *const i8,
                    url,
                    encfile,
                );
            } else {
                urlbuffer = curl_maprintf(
                    b"%s/%s\0" as *const u8 as *const i8,
                    url,
                    encfile,
                );
            }
            curl_free(encfile as *mut libc::c_void);
            if urlbuffer.is_null() {
                url = 0 as *mut i8;
            } else {
                free(url as *mut libc::c_void);
                url = 0 as *mut i8;
                url = urlbuffer;
            }
        }
    }
    curl_easy_cleanup(curl);
    return url;
}
#[no_mangle]
pub unsafe extern "C" fn get_url_file_name<'a1>(
    mut filename: Option<&'a1 mut * mut i8>,
    mut url: * const i8,
) -> u32 {
    let mut pc: * const i8 = 0 as *const i8;
    let mut pc2: * const i8 = 0 as *const i8;
    *(borrow_mut(&mut filename)).unwrap() = 0 as *mut i8;
    pc = strstr(url, b"://\0" as *const u8 as *const i8);
    if !pc.is_null() {
        pc = pc.offset(3 as i32 as isize);
    } else {
        pc = url;
    }
    pc2 = strrchr(pc, '\\' as i32);
    pc = strrchr(pc, '/' as i32);
    if !pc2.is_null() && (pc.is_null() || pc < pc2) {
        pc = pc2;
    }
    if !pc.is_null() {
        pc = pc.offset(1);
    } else {
        pc = b"\0" as *const u8 as *const i8;
    }
    *(borrow_mut(&mut filename)).unwrap() = strdup(pc);
    if (*(borrow_mut(&mut filename)).unwrap()).is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    return CURLE_OK;
}
use crate::laertes_rt::*;
