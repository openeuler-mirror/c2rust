use :: libc;
extern "C" {
    fn fflush(__stream: *mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut crate::src::lib::http2::_IO_FILE;
    fn fdopen(__fd: i32, __modes: *const i8) -> *mut crate::src::lib::http2::_IO_FILE;
    fn fwrite(
        _: *const core::ffi::c_void,
        _: u64,
        _: u64,
        _: *mut crate::src::lib::http2::_IO_FILE,
    ) -> u64;
    fn free(__ptr: *mut core::ffi::c_void);
    fn memchr(_: *const core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn strerror(_: i32) -> *mut i8;
    fn __errno_location() -> *mut i32;
    fn close(__fd: i32) -> i32;
    fn open(__file: *const i8, __oflag: i32, _: ...) -> i32;
}
pub use crate::src::lib::easy::curl_easy_pause;
pub use crate::src::lib::http2::curl_mime;
pub use crate::src::lib::http2::Curl_easy;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub use crate::src::src::tool_msgs::errorf;
pub use crate::src::src::tool_msgs::warnf;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __time_t = i64;
pub type __suseconds_t = i64;
pub type time_t = i64;
pub type size_t = u64;
pub type timeval = crate::src::lib::openldap::timeval;
pub type curl_off_t = i64;
pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::lib::http2::_IO_FILE;
pub type CURL = crate::src::lib::http2::Curl_easy;
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
pub type OutStruct = crate::src::src::tool_cb_hdr::OutStruct;
pub type InStruct = crate::src::src::tool_cb_hdr::InStruct;
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
pub type per_transfer<'a> = crate::src::src::tool_cb_hdr::per_transfer<'a>;
pub type HdrCbData<'a> = crate::src::src::tool_cb_hdr::HdrCbData<'a>;
pub type ProgressData = crate::src::src::tool_cb_hdr::ProgressData;
#[no_mangle]
pub extern "C" fn tool_create_output_file<'a1>(
    mut outs: Option<&'a1 mut crate::src::src::tool_cb_hdr::OutStruct>,
    mut config: *mut crate::src::src::tool_cb_dbg::OperationConfig,
) -> bool {
    let mut global: *mut crate::src::src::tool_cb_dbg::GlobalConfig =
        0 as *mut crate::src::src::tool_cb_dbg::GlobalConfig;
    let mut file: *mut crate::src::lib::http2::_IO_FILE = 0 as *mut FILE;
    global = unsafe { (*config).global };
    if ((*(borrow(&outs)).unwrap()).filename).is_null()
        || (unsafe { *(*(borrow(&outs)).unwrap()).filename }) == 0
    {
        (unsafe { warnf(
            global,
            b"Remote filename has no length!\n\0" as *const u8 as *const i8,
        ) });
        return 0 as i32 != 0;
    }
    if (*(borrow(&outs)).unwrap()).is_cd_filename {
        let mut fd: i32 = 0;
        let mut name: *mut i8 = (*(borrow_mut(&mut outs)).unwrap()).filename;
        let mut aname: *mut i8 = 0 as *mut i8;
        if !(unsafe { (*config).output_dir }).is_null() {
            aname = unsafe { curl_maprintf(
                b"%s/%s\0" as *const u8 as *const i8,
                (*config).output_dir,
                name,
            ) };
            if aname.is_null() {
                (unsafe { errorf(global, b"out of memory\n\0" as *const u8 as *const i8) });
                return 0 as i32 != 0;
            }
            name = aname;
        }
        fd = unsafe { open(
            name,
            0o100 as i32 | 0o1 as i32 | 0o200 as i32 | 0 as i32,
            0o400 as i32
                | 0o200 as i32
                | 0o400 as i32 >> 3 as i32
                | 0o200 as i32 >> 3 as i32
                | 0o400 as i32 >> 3 as i32 >> 3 as i32
                | 0o200 as i32 >> 3 as i32 >> 3 as i32,
        ) };
        if fd != -(1 as i32) {
            file = unsafe { fdopen(fd, b"wb\0" as *const u8 as *const i8) };
            if file.is_null() {
                (unsafe { close(fd) });
            }
        }
        (unsafe { free(aname as *mut libc::c_void) });
    } else {
        file = unsafe { fopen(
            (*(borrow(&outs)).unwrap()).filename,
            b"wb\0" as *const u8 as *const i8,
        ) };
    }
    if file.is_null() {
        (unsafe { warnf(
            global,
            b"Failed to create the file %s: %s\n\0" as *const u8 as *const i8,
            (*(borrow(&outs)).unwrap()).filename,
            strerror(*__errno_location()),
        ) });
        return 0 as i32 != 0;
    }
    (*(borrow_mut(&mut outs)).unwrap()).s_isreg = 1 as i32 != 0;
    (*(borrow_mut(&mut outs)).unwrap()).fopened = 1 as i32 != 0;
    let mut fresh0 = &mut ((*(borrow_mut(&mut outs)).unwrap()).stream);
    *fresh0 = file;
    (*(borrow_mut(&mut outs)).unwrap()).bytes = 0 as i32 as curl_off_t;
    (*(borrow_mut(&mut outs)).unwrap()).init = 0 as i32 as curl_off_t;
    return 1 as i32 != 0;
}
#[no_mangle]
pub extern "C" fn tool_write_cb(
    mut buffer: *mut i8,
    mut sz: u64,
    mut nmemb: u64,
    mut userdata: *mut core::ffi::c_void,
) -> u64 {
    let mut rc: u64 = 0;
    let mut per: *mut crate::src::src::tool_cb_hdr::per_transfer<'_> =
        userdata as *mut per_transfer;
    let mut outs: Option<&'_ mut crate::src::src::tool_cb_hdr::OutStruct> = Some(unsafe { &mut (*per).outs });
    let mut config: *mut crate::src::src::tool_cb_dbg::OperationConfig = unsafe { (*per).config };
    let mut bytes: u64 = sz.wrapping_mul(nmemb);
    let mut is_tty: bool = unsafe { (*(*config).global).isatty };
    let failure: u64 = (if bytes != 0 { 0 as i32 } else { 1 as i32 }) as size_t;
    if ((*(borrow(&outs)).unwrap()).stream).is_null()
        && !tool_create_output_file(borrow_mut(&mut outs), unsafe { (*per).config })
    {
        return failure;
    }
    if is_tty as i32 != 0
        && (*(borrow(&outs)).unwrap()).bytes < 2000 as i32 as i64
        && !(unsafe { (*config).terminal_binary_ok })
    {
        if !(unsafe { memchr(buffer as *const libc::c_void, 0 as i32, bytes) }).is_null() {
            (unsafe { warnf ((* config) . global , b"Binary output can mess up your terminal. Use \"--output -\" to tell curl to output it to your terminal anyway, or consider \"--output <FILE>\" to save to a file.\n\0" as * const u8 as * const i8 ,) }) ;
            (unsafe { (*config).synthetic_error = ERR_BINARY_TERMINAL });
            return failure;
        }
    }
    rc = unsafe { fwrite(
        buffer as *const libc::c_void,
        sz,
        nmemb,
        (*(borrow_mut(&mut outs)).unwrap()).stream,
    ) };
    if bytes == rc {
        let mut fresh1 = &mut ((*(borrow_mut(&mut outs)).unwrap()).bytes);
        *fresh1 = (*fresh1 as u64).wrapping_add(bytes) as curl_off_t as curl_off_t;
    }
    if unsafe { (*config).readbusy } {
        (unsafe { (*config).readbusy = 0 as i32 != 0 });
        curl_easy_pause(unsafe { (*per).curl }, 0 as i32 | 0 as i32);
    }
    if unsafe { (*config).nobuffer } {
        let mut res: i32 = unsafe { fflush((*(borrow_mut(&mut outs)).unwrap()).stream) };
        if res != 0 {
            return failure;
        }
    }
    return rc;
}
use crate::laertes_rt::*;
