use ::libc;
extern "C" {
    
    
    
    
    
    fn fputs(__s: *const i8, __stream: *mut FILE) -> i32;
    
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    
    
    
    
    
}
pub use crate::src::lib::easy::curl_easy_pause;
pub use crate::src::lib::mprintf::curl_mfprintf;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::src::tool_util::tvdiff;
pub use crate::src::src::tool_util::tvnow;
pub use crate::src::lib::http2::Curl_easy;
pub use crate::src::lib::http2::curl_mime;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub use crate::src::src::tool_operate::transfers;
pub type __off_t = crate::src::lib::http2::__off_t;
pub type __off64_t = crate::src::lib::http2::__off64_t;
pub type __time_t = crate::src::lib::http2::__time_t;
pub type __suseconds_t = crate::src::lib::openldap::__suseconds_t;
pub type time_t = crate::src::lib::http2::time_t;
pub type size_t = crate::src::lib::http2::size_t;
// #[derive(Copy, Clone)]

pub type timeval = crate::src::lib::openldap::timeval;
pub type curl_off_t = crate::src::lib::http2::curl_off_t;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = crate::src::lib::http2::_IO_lock_t;
pub type FILE = crate::src::lib::http2::FILE;
pub type CURL = crate::src::lib::http2::CURL;
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

pub type HdrCbData = crate::src::src::tool_cb_hdr::HdrCbData;
// #[derive(Copy, Clone)]

pub type OutStruct = crate::src::src::tool_cb_hdr::OutStruct;
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
// #[derive(Copy, Clone)]

pub type ProgressData = crate::src::src::tool_cb_hdr::ProgressData;
// #[derive(Copy, Clone)]

pub type InStruct = crate::src::src::tool_cb_hdr::InStruct;
// #[derive(Copy, Clone)]

pub type per_transfer = crate::src::src::tool_cb_hdr::per_transfer;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct speedcount {
    pub dl: curl_off_t,
    pub ul: curl_off_t,
    pub stamp: timeval,
}
unsafe extern "C" fn max5data(
    mut bytes: curl_off_t,
    mut max5: *mut i8,
) -> *mut i8 {
    if bytes < 100000 as i64 {
        curl_msnprintf(
            max5,
            6 as i32 as size_t,
            b"%5ld\0" as *const u8 as *const i8,
            bytes,
        );
    } else if bytes < 10000 as i64 * 1024 as i64 {
        curl_msnprintf(
            max5,
            6 as i32 as size_t,
            b"%4ldk\0" as *const u8 as *const i8,
            bytes / 1024 as i64,
        );
    } else if bytes < 100 as i64 * (1024 as i64 * 1024 as i64)
        {
        curl_msnprintf(
            max5,
            6 as i32 as size_t,
            b"%2ld.%0ldM\0" as *const u8 as *const i8,
            bytes / (1024 as i64 * 1024 as i64),
            bytes % (1024 as i64 * 1024 as i64)
                / (1024 as i64 * 1024 as i64 / 10 as i64),
        );
    } else if bytes
            < 10000 as i64 * (1024 as i64 * 1024 as i64)
        {
        curl_msnprintf(
            max5,
            6 as i32 as size_t,
            b"%4ldM\0" as *const u8 as *const i8,
            bytes / (1024 as i64 * 1024 as i64),
        );
    } else if bytes
            < 100 as i64
                * (1024 as i64 * (1024 as i64 * 1024 as i64))
        {
        curl_msnprintf(
            max5,
            6 as i32 as size_t,
            b"%2ld.%0ldG\0" as *const u8 as *const i8,
            bytes
                / (1024 as i64 * (1024 as i64 * 1024 as i64)),
            bytes
                % (1024 as i64 * (1024 as i64 * 1024 as i64))
                / (1024 as i64 * (1024 as i64 * 1024 as i64)
                    / 10 as i64),
        );
    } else if bytes
            < 10000 as i64
                * (1024 as i64 * (1024 as i64 * 1024 as i64))
        {
        curl_msnprintf(
            max5,
            6 as i32 as size_t,
            b"%4ldG\0" as *const u8 as *const i8,
            bytes
                / (1024 as i64 * (1024 as i64 * 1024 as i64)),
        );
    } else if bytes
            < 10000 as i64
                * (1024 as i64
                    * (1024 as i64
                        * (1024 as i64 * 1024 as i64)))
        {
        curl_msnprintf(
            max5,
            6 as i32 as size_t,
            b"%4ldT\0" as *const u8 as *const i8,
            bytes
                / (1024 as i64
                    * (1024 as i64
                        * (1024 as i64 * 1024 as i64))),
        );
    } else {
        curl_msnprintf(
            max5,
            6 as i32 as size_t,
            b"%4ldP\0" as *const u8 as *const i8,
            bytes
                / (1024 as i64
                    * (1024 as i64
                        * (1024 as i64
                            * (1024 as i64 * 1024 as i64)))),
        );
    }
    return max5;
}
#[no_mangle]
pub unsafe extern "C" fn xferinfo_cb(
    mut clientp: *mut libc::c_void,
    mut dltotal: curl_off_t,
    mut dlnow: curl_off_t,
    mut ultotal: curl_off_t,
    mut ulnow: curl_off_t,
) -> i32 {
    let mut per: *mut per_transfer = clientp as *mut per_transfer;
    let mut config: *mut OperationConfig = (*per).config;
    (*per).dltotal = dltotal;
    (*per).dlnow = dlnow;
    (*per).ultotal = ultotal;
    (*per).ulnow = ulnow;
    if (*per).abort {
        return 1 as i32;
    }
    if (*config).readbusy {
        (*config).readbusy = 0 as i32 != 0;
        curl_easy_pause((*per).curl, 0 as i32 | 0 as i32);
    }
    return 0 as i32;
}
unsafe extern "C" fn time2str(mut r: *mut i8, mut seconds: curl_off_t) {
    let mut h: curl_off_t = 0;
    if seconds <= 0 as i32 as i64 {
        strcpy(r, b"--:--:--\0" as *const u8 as *const i8);
        return;
    }
    h = seconds / 3600 as i64;
    if h <= 99 as i64 {
        let mut m: curl_off_t = (seconds - h * 3600 as i64)
            / 60 as i64;
        let mut s: curl_off_t = seconds - h * 3600 as i64
            - m * 60 as i64;
        curl_msnprintf(
            r,
            9 as i32 as size_t,
            b"%2ld:%02ld:%02ld\0" as *const u8 as *const i8,
            h,
            m,
            s,
        );
    } else {
        let mut d: curl_off_t = seconds / 86400 as i64;
        h = (seconds - d * 86400 as i64) / 3600 as i64;
        if d <= 999 as i64 {
            curl_msnprintf(
                r,
                9 as i32 as size_t,
                b"%3ldd %02ldh\0" as *const u8 as *const i8,
                d,
                h,
            );
        } else {
            curl_msnprintf(
                r,
                9 as i32 as size_t,
                b"%7ldd\0" as *const u8 as *const i8,
                d,
            );
        }
    };
}
static mut all_dltotal: curl_off_t = 0 as i32 as curl_off_t;
static mut all_ultotal: curl_off_t = 0 as i32 as curl_off_t;
static mut all_dlalready: curl_off_t = 0 as i32 as curl_off_t;
static mut all_ulalready: curl_off_t = 0 as i32 as curl_off_t;
#[no_mangle]
pub static mut all_xfers: curl_off_t = 0 as i32 as curl_off_t;
static mut speedindex: u32 = 0;
static mut indexwrapped: bool = false;
static mut speedstore: [speedcount; 10] = [speedcount {
    dl: 0,
    ul: 0,
    stamp: timeval { tv_sec: 0, tv_usec: 0 },
}; 10];
#[no_mangle]
pub unsafe extern "C" fn progress_meter(
    mut global: *mut GlobalConfig,
    mut start: *mut timeval,
    mut final_0: bool,
) -> bool {
    static mut stamp: timeval = timeval { tv_sec: 0, tv_usec: 0 };
    static mut header: bool = 0 as i32 != 0;
    let mut now: timeval = timeval { tv_sec: 0, tv_usec: 0 };
    let mut diff: i64 = 0;
    if (*global).noprogress {
        return 0 as i32 != 0;
    }
    now = tvnow();
    diff = tvdiff(now, stamp);
    if !header {
        header = 1 as i32 != 0;
        fputs(
            b"DL% UL%  Dled  Uled  Xfers  Live   Qd Total     Current  Left    Speed\n\0"
                as *const u8 as *const i8,
            (*global).errors,
        );
    }
    if final_0 as i32 != 0 || diff > 500 as i32 as i64 {
        let mut time_left: [i8; 10] = [0; 10];
        let mut time_total: [i8; 10] = [0; 10];
        let mut time_spent: [i8; 10] = [0; 10];
        let mut buffer: [[i8; 6]; 3] = [[0; 6]; 3];
        let mut spent: curl_off_t = tvdiff(now, *start)
            / 1000 as i32 as i64;
        let mut dlpercen: [i8; 4] = *::std::mem::transmute::<
            &[u8; 4],
            &mut [i8; 4],
        >(b"--\0\0");
        let mut ulpercen: [i8; 4] = *::std::mem::transmute::<
            &[u8; 4],
            &mut [i8; 4],
        >(b"--\0\0");
        let mut per: *mut per_transfer = 0 as *mut per_transfer;
        let mut all_dlnow: curl_off_t = 0 as i32 as curl_off_t;
        let mut all_ulnow: curl_off_t = 0 as i32 as curl_off_t;
        let mut dlknown: bool = 1 as i32 != 0;
        let mut ulknown: bool = 1 as i32 != 0;
        let mut all_running: curl_off_t = 0 as i32 as curl_off_t;
        let mut all_queued: curl_off_t = 0 as i32 as curl_off_t;
        let mut speed: curl_off_t = 0 as i32 as curl_off_t;
        let mut i: u32 = 0;
        stamp = now;
        all_dlnow += all_dlalready;
        all_ulnow += all_ulalready;
        per = transfers;
        while !per.is_null() {
            all_dlnow += (*per).dlnow;
            all_ulnow += (*per).ulnow;
            if (*per).dltotal == 0 {
                dlknown = 0 as i32 != 0;
            } else if !(*per).dltotal_added {
                all_dltotal += (*per).dltotal;
                (*per).dltotal_added = 1 as i32 != 0;
            }
            if (*per).ultotal == 0 {
                ulknown = 0 as i32 != 0;
            } else if !(*per).ultotal_added {
                all_ultotal += (*per).ultotal;
                (*per).ultotal_added = 1 as i32 != 0;
            }
            if !(*per).added {
                all_queued += 1;
            } else {
                all_running += 1;
            }
            per = (*per).next;
        }
        if dlknown as i32 != 0 && all_dltotal != 0 {
            curl_msnprintf(
                dlpercen.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 4]>() as u64,
                b"%3ld\0" as *const u8 as *const i8,
                all_dlnow * 100 as i32 as i64 / all_dltotal,
            );
        }
        if ulknown as i32 != 0 && all_ultotal != 0 {
            curl_msnprintf(
                ulpercen.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 4]>() as u64,
                b"%3ld\0" as *const u8 as *const i8,
                all_ulnow * 100 as i32 as i64 / all_ultotal,
            );
        }
        i = speedindex;
        speedstore[i as usize].dl = all_dlnow;
        speedstore[i as usize].ul = all_ulnow;
        speedstore[i as usize].stamp = now;
        speedindex = speedindex.wrapping_add(1);
        if speedindex >= 10 as i32 as u32 {
            indexwrapped = 1 as i32 != 0;
            speedindex = 0 as i32 as u32;
        }
        let mut deltams: i64 = 0;
        let mut dl: curl_off_t = 0;
        let mut ul: curl_off_t = 0;
        let mut dls: curl_off_t = 0;
        let mut uls: curl_off_t = 0;
        if indexwrapped {
            deltams = tvdiff(now, speedstore[speedindex as usize].stamp);
            dl = all_dlnow - speedstore[speedindex as usize].dl;
            ul = all_ulnow - speedstore[speedindex as usize].ul;
        } else {
            deltams = tvdiff(now, *start);
            dl = all_dlnow;
            ul = all_ulnow;
        }
        dls = (dl as f64 / (deltams as f64 / 1000.0f64))
            as curl_off_t;
        uls = (ul as f64 / (deltams as f64 / 1000.0f64))
            as curl_off_t;
        speed = if dls > uls { dls } else { uls };
        if dlknown as i32 != 0 && speed != 0 {
            let mut est: curl_off_t = all_dltotal / speed;
            let mut left: curl_off_t = (all_dltotal - all_dlnow) / speed;
            time2str(time_left.as_mut_ptr(), left);
            time2str(time_total.as_mut_ptr(), est);
        } else {
            time2str(time_left.as_mut_ptr(), 0 as i32 as curl_off_t);
            time2str(time_total.as_mut_ptr(), 0 as i32 as curl_off_t);
        }
        time2str(time_spent.as_mut_ptr(), spent);
        curl_mfprintf(
            (*global).errors,
            b"\r%-3s %-3s %s %s %5ld %5ld %5ld %s %s %s %s %5s\0" as *const u8
                as *const i8,
            dlpercen.as_mut_ptr(),
            ulpercen.as_mut_ptr(),
            max5data(all_dlnow, (buffer[0 as i32 as usize]).as_mut_ptr()),
            max5data(all_ulnow, (buffer[1 as i32 as usize]).as_mut_ptr()),
            all_xfers,
            all_running,
            all_queued,
            time_total.as_mut_ptr(),
            time_spent.as_mut_ptr(),
            time_left.as_mut_ptr(),
            max5data(speed, (buffer[2 as i32 as usize]).as_mut_ptr()),
            if final_0 as i32 != 0 {
                b"\n\0" as *const u8 as *const i8
            } else {
                b"\0" as *const u8 as *const i8
            },
        );
        return 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn progress_finalize(mut per: *mut per_transfer) {
    all_dlalready += (*per).dlnow;
    all_ulalready += (*per).ulnow;
    if !(*per).dltotal_added {
        all_dltotal += (*per).dltotal;
        (*per).dltotal_added = 1 as i32 != 0;
    }
    if !(*per).ultotal_added {
        all_ultotal += (*per).ultotal;
        (*per).ultotal_added = 1 as i32 != 0;
    }
}
