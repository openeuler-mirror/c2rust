use ::libc;
extern "C" {
    
    
    
    
    static mut stdout: *mut FILE;
    fn fclose(__stream: *mut FILE) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut FILE;
    
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    
    
    
    
    
}
pub use crate::src::lib::escape::curl_free;
pub use crate::src::lib::mprintf::curl_mfprintf;
pub use crate::src::lib::mprintf::curl_mvaprintf;
pub use crate::src::src::slist_wc::slist_wc_append;
pub use crate::src::src::slist_wc::slist_wc_free_all;
pub use crate::src::src::tool_msgs::warnf;
pub use crate::src::lib::http2::curl_mime;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub type __builtin_va_list = crate::src::lib::dict::__builtin_va_list;
// #[derive(Copy, Clone)]

pub type __va_list_tag = crate::src::lib::dict::__va_list_tag;
pub type __off_t = crate::src::lib::http2::__off_t;
pub type __off64_t = crate::src::lib::http2::__off64_t;
pub type size_t = crate::src::lib::http2::size_t;
pub type curl_off_t = crate::src::lib::http2::curl_off_t;
pub type va_list = crate::src::lib::dict::va_list;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = crate::src::lib::http2::_IO_lock_t;
pub type FILE = crate::src::lib::http2::FILE;
// #[derive(Copy, Clone)]

pub type curl_slist = crate::src::lib::http2::curl_slist;
pub type CURLcode = crate::src::lib::http2::CURLcode;
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
pub type curl_TimeCond = crate::src::lib::http2::curl_TimeCond;
pub const CURL_TIMECOND_LAST: curl_TimeCond = 4;
pub const CURL_TIMECOND_LASTMOD: curl_TimeCond = 3;
pub const CURL_TIMECOND_IFUNMODSINCE: curl_TimeCond = 2;
pub const CURL_TIMECOND_IFMODSINCE: curl_TimeCond = 1;
pub const CURL_TIMECOND_NONE: curl_TimeCond = 0;
// #[derive(Copy, Clone)]

pub type slist_wc = crate::src::src::slist_wc::slist_wc;
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
#[no_mangle]
pub static mut easysrc_decl: *mut slist_wc = 0 as *const slist_wc as *mut slist_wc;
#[no_mangle]
pub static mut easysrc_data: *mut slist_wc = 0 as *const slist_wc as *mut slist_wc;
#[no_mangle]
pub static mut easysrc_code: *mut slist_wc = 0 as *const slist_wc as *mut slist_wc;
#[no_mangle]
pub static mut easysrc_toohard: *mut slist_wc = 0 as *const slist_wc as *mut slist_wc;
#[no_mangle]
pub static mut easysrc_clean: *mut slist_wc = 0 as *const slist_wc as *mut slist_wc;
#[no_mangle]
pub static mut easysrc_mime_count: i32 = 0 as i32;
#[no_mangle]
pub static mut easysrc_slist_count: i32 = 0 as i32;
static mut srchead: [*const i8; 11] = [
    b"/********* Sample code generated by the curl command line tool **********\0"
        as *const u8 as *const i8,
    b" * All curl_easy_setopt() options are documented at:\0" as *const u8
        as *const i8,
    b" * https://curl.se/libcurl/c/curl_easy_setopt.html\0" as *const u8
        as *const i8,
    b" ************************************************************************/\0"
        as *const u8 as *const i8,
    b"#include <curl/curl.h>\0" as *const u8 as *const i8,
    b"\0" as *const u8 as *const i8,
    b"int main(int argc, char *argv[])\0" as *const u8 as *const i8,
    b"{\0" as *const u8 as *const i8,
    b"  CURLcode ret;\0" as *const u8 as *const i8,
    b"  CURL *hnd;\0" as *const u8 as *const i8,
    0 as *const i8,
];
static mut srchard: [*const i8; 5] = [
    b"/* Here is a list of options the curl code used that cannot get generated\0"
        as *const u8 as *const i8,
    b"   as source easily. You may select to either not use them or implement\0"
        as *const u8 as *const i8,
    b"   them yourself.\0" as *const u8 as *const i8,
    b"\0" as *const u8 as *const i8,
    0 as *const i8,
];
static mut srcend: [*const i8; 5] = [
    b"\0" as *const u8 as *const i8,
    b"  return (int)ret;\0" as *const u8 as *const i8,
    b"}\0" as *const u8 as *const i8,
    b"/**** End of sample code ****/\0" as *const u8 as *const i8,
    0 as *const i8,
];
unsafe extern "C" fn easysrc_free() {
    slist_wc_free_all(easysrc_decl);
    easysrc_decl = 0 as *mut slist_wc;
    slist_wc_free_all(easysrc_data);
    easysrc_data = 0 as *mut slist_wc;
    slist_wc_free_all(easysrc_code);
    easysrc_code = 0 as *mut slist_wc;
    slist_wc_free_all(easysrc_toohard);
    easysrc_toohard = 0 as *mut slist_wc;
    slist_wc_free_all(easysrc_clean);
    easysrc_clean = 0 as *mut slist_wc;
}
#[no_mangle]
pub unsafe extern "C" fn easysrc_add(
    mut plist: *mut *mut slist_wc,
    mut line: *const i8,
) -> CURLcode {
    let mut ret: CURLcode = CURLE_OK;
    let mut list: *mut slist_wc = slist_wc_append(*plist, line);
    if list.is_null() {
        easysrc_free();
        ret = CURLE_OUT_OF_MEMORY;
    } else {
        *plist = list;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn easysrc_addf(
    mut plist: *mut *mut slist_wc,
    mut fmt: *const i8,
    mut args: ...
) -> CURLcode {
    let mut ret: CURLcode = CURLE_OK;
    let mut bufp: *mut i8 = 0 as *mut i8;
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    bufp = curl_mvaprintf(fmt, ap.as_va_list());
    if bufp.is_null() {
        ret = CURLE_OUT_OF_MEMORY;
    } else {
        ret = easysrc_add(plist, bufp);
        curl_free(bufp as *mut libc::c_void);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn easysrc_init() -> CURLcode {
    let mut ret: CURLcode = easysrc_add(
        &mut easysrc_code,
        b"hnd = curl_easy_init();\0" as *const u8 as *const i8,
    );
    if ret as u64 != 0 {
        return ret;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn easysrc_perform() -> CURLcode {
    if !easysrc_toohard.is_null() {
        let mut i: i32 = 0;
        let mut ptr: *mut curl_slist = 0 as *mut curl_slist;
        let mut c: *const i8 = 0 as *const i8;
        let mut ret: CURLcode = easysrc_add(
            &mut easysrc_code,
            b"\0" as *const u8 as *const i8,
        );
        if ret as u64 != 0 {
            return ret;
        }
        i = 0 as i32;
        loop {
            c = srchard[i as usize];
            if c.is_null() {
                break;
            }
            let mut ret_0: CURLcode = easysrc_add(&mut easysrc_code, c);
            if ret_0 as u64 != 0 {
                return ret_0;
            }
            i += 1;
        }
        if !easysrc_toohard.is_null() {
            ptr = (*easysrc_toohard).first;
            while !ptr.is_null() {
                let mut ret_1: CURLcode = easysrc_add(&mut easysrc_code, (*ptr).data);
                if ret_1 as u64 != 0 {
                    return ret_1;
                }
                ptr = (*ptr).next;
            }
        }
        let mut ret_2: CURLcode = easysrc_add(
            &mut easysrc_code,
            b"\0" as *const u8 as *const i8,
        );
        if ret_2 as u64 != 0 {
            return ret_2;
        }
        let mut ret_3: CURLcode = easysrc_add(
            &mut easysrc_code,
            b"*/\0" as *const u8 as *const i8,
        );
        if ret_3 as u64 != 0 {
            return ret_3;
        }
        slist_wc_free_all(easysrc_toohard);
        easysrc_toohard = 0 as *mut slist_wc;
    }
    let mut ret_4: CURLcode = easysrc_add(
        &mut easysrc_code,
        b"\0" as *const u8 as *const i8,
    );
    if ret_4 as u64 != 0 {
        return ret_4;
    }
    let mut ret_5: CURLcode = easysrc_add(
        &mut easysrc_code,
        b"ret = curl_easy_perform(hnd);\0" as *const u8 as *const i8,
    );
    if ret_5 as u64 != 0 {
        return ret_5;
    }
    let mut ret_6: CURLcode = easysrc_add(
        &mut easysrc_code,
        b"\0" as *const u8 as *const i8,
    );
    if ret_6 as u64 != 0 {
        return ret_6;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn easysrc_cleanup() -> CURLcode {
    let mut ret: CURLcode = easysrc_add(
        &mut easysrc_code,
        b"curl_easy_cleanup(hnd);\0" as *const u8 as *const i8,
    );
    if ret as u64 != 0 {
        return ret;
    }
    let mut ret_0: CURLcode = easysrc_add(
        &mut easysrc_code,
        b"hnd = NULL;\0" as *const u8 as *const i8,
    );
    if ret_0 as u64 != 0 {
        return ret_0;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn dumpeasysrc(mut config: *mut GlobalConfig) {
    let mut ptr: *mut curl_slist = 0 as *mut curl_slist;
    let mut o: *mut i8 = (*config).libcurl;
    let mut out: *mut FILE = 0 as *mut FILE;
    let mut fopened: bool = 0 as i32 != 0;
    if strcmp(o, b"-\0" as *const u8 as *const i8) != 0 {
        out = fopen(o, b"w\0" as *const u8 as *const i8);
        fopened = 1 as i32 != 0;
    } else {
        out = stdout;
    }
    if out.is_null() {
        warnf(
            config,
            b"Failed to open %s to write libcurl code!\n\0" as *const u8
                as *const i8,
            o,
        );
    } else {
        let mut i: i32 = 0;
        let mut c: *const i8 = 0 as *const i8;
        i = 0 as i32;
        loop {
            c = srchead[i as usize];
            if c.is_null() {
                break;
            }
            curl_mfprintf(out, b"%s\n\0" as *const u8 as *const i8, c);
            i += 1;
        }
        if !easysrc_decl.is_null() {
            ptr = (*easysrc_decl).first;
            while !ptr.is_null() {
                curl_mfprintf(
                    out,
                    b"  %s\n\0" as *const u8 as *const i8,
                    (*ptr).data,
                );
                ptr = (*ptr).next;
            }
        }
        if !easysrc_data.is_null() {
            curl_mfprintf(out, b"\n\0" as *const u8 as *const i8);
            ptr = (*easysrc_data).first;
            while !ptr.is_null() {
                curl_mfprintf(
                    out,
                    b"  %s\n\0" as *const u8 as *const i8,
                    (*ptr).data,
                );
                ptr = (*ptr).next;
            }
        }
        curl_mfprintf(out, b"\n\0" as *const u8 as *const i8);
        if !easysrc_code.is_null() {
            ptr = (*easysrc_code).first;
            while !ptr.is_null() {
                if *((*ptr).data).offset(0 as i32 as isize) != 0 {
                    curl_mfprintf(
                        out,
                        b"  %s\n\0" as *const u8 as *const i8,
                        (*ptr).data,
                    );
                } else {
                    curl_mfprintf(out, b"\n\0" as *const u8 as *const i8);
                }
                ptr = (*ptr).next;
            }
        }
        if !easysrc_clean.is_null() {
            ptr = (*easysrc_clean).first;
            while !ptr.is_null() {
                curl_mfprintf(
                    out,
                    b"  %s\n\0" as *const u8 as *const i8,
                    (*ptr).data,
                );
                ptr = (*ptr).next;
            }
        }
        i = 0 as i32;
        loop {
            c = srcend[i as usize];
            if c.is_null() {
                break;
            }
            curl_mfprintf(out, b"%s\n\0" as *const u8 as *const i8, c);
            i += 1;
        }
        if fopened {
            fclose(out);
        }
    }
    easysrc_free();
}
