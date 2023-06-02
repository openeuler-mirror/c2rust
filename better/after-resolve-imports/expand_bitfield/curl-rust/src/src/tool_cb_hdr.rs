use ::libc;
extern "C" {
    
    
    
    
    
    
    fn fflush(__stream: *mut FILE) -> i32;
    fn fputc(__c: i32, __stream: *mut FILE) -> i32;
    fn fwrite(
        _: *const libc::c_void,
        _: u64,
        _: u64,
        _: *mut FILE,
    ) -> u64;
    
    fn malloc(_: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> *mut libc::c_void;
    fn memmove(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> *mut libc::c_void;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> i32;
    fn memchr(
        _: *const libc::c_void,
        _: i32,
        _: u64,
    ) -> *mut libc::c_void;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strrchr(_: *const i8, _: i32) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    
    
    
    
}
pub use crate::src::lib::curl_ctype::Curl_isalpha;
pub use crate::src::lib::curl_ctype::Curl_isspace;
pub use crate::src::lib::easy::curl_easy_getinfo;
pub use crate::src::lib::mprintf::curl_mfprintf;
pub use crate::src::lib::strcase::curl_strnequal;
pub use crate::src::src::tool_cb_wrt::tool_create_output_file;
pub use crate::src::lib::http2::Curl_easy;
pub use crate::src::lib::http2::curl_mime;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub type __off_t = crate::src::lib::http2::__off_t;
pub type __off64_t = crate::src::lib::http2::__off64_t;
pub type __time_t = crate::src::lib::http2::__time_t;
pub type __suseconds_t = crate::src::lib::openldap::__suseconds_t;
pub type __ssize_t = crate::src::lib::http2::__ssize_t;
pub type ssize_t = crate::src::lib::http2::ssize_t;
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
pub type CURLINFO = crate::src::lib::easy::CURLINFO;
pub const CURLINFO_LASTONE: CURLINFO = 60;
pub const CURLINFO_REFERER: CURLINFO = 1048636;
pub const CURLINFO_PROXY_ERROR: CURLINFO = 2097211;
pub const CURLINFO_EFFECTIVE_METHOD: CURLINFO = 1048634;
pub const CURLINFO_RETRY_AFTER: CURLINFO = 6291513;
pub const CURLINFO_APPCONNECT_TIME_T: CURLINFO = 6291512;
pub const CURLINFO_REDIRECT_TIME_T: CURLINFO = 6291511;
pub const CURLINFO_STARTTRANSFER_TIME_T: CURLINFO = 6291510;
pub const CURLINFO_PRETRANSFER_TIME_T: CURLINFO = 6291509;
pub const CURLINFO_CONNECT_TIME_T: CURLINFO = 6291508;
pub const CURLINFO_NAMELOOKUP_TIME_T: CURLINFO = 6291507;
pub const CURLINFO_TOTAL_TIME_T: CURLINFO = 6291506;
pub const CURLINFO_SCHEME: CURLINFO = 1048625;
pub const CURLINFO_PROTOCOL: CURLINFO = 2097200;
pub const CURLINFO_PROXY_SSL_VERIFYRESULT: CURLINFO = 2097199;
pub const CURLINFO_HTTP_VERSION: CURLINFO = 2097198;
pub const CURLINFO_TLS_SSL_PTR: CURLINFO = 4194349;
pub const CURLINFO_ACTIVESOCKET: CURLINFO = 5242924;
pub const CURLINFO_TLS_SESSION: CURLINFO = 4194347;
pub const CURLINFO_LOCAL_PORT: CURLINFO = 2097194;
pub const CURLINFO_LOCAL_IP: CURLINFO = 1048617;
pub const CURLINFO_PRIMARY_PORT: CURLINFO = 2097192;
pub const CURLINFO_RTSP_CSEQ_RECV: CURLINFO = 2097191;
pub const CURLINFO_RTSP_SERVER_CSEQ: CURLINFO = 2097190;
pub const CURLINFO_RTSP_CLIENT_CSEQ: CURLINFO = 2097189;
pub const CURLINFO_RTSP_SESSION_ID: CURLINFO = 1048612;
pub const CURLINFO_CONDITION_UNMET: CURLINFO = 2097187;
pub const CURLINFO_CERTINFO: CURLINFO = 4194338;
pub const CURLINFO_APPCONNECT_TIME: CURLINFO = 3145761;
pub const CURLINFO_PRIMARY_IP: CURLINFO = 1048608;
pub const CURLINFO_REDIRECT_URL: CURLINFO = 1048607;
pub const CURLINFO_FTP_ENTRY_PATH: CURLINFO = 1048606;
pub const CURLINFO_LASTSOCKET: CURLINFO = 2097181;
pub const CURLINFO_COOKIELIST: CURLINFO = 4194332;
pub const CURLINFO_SSL_ENGINES: CURLINFO = 4194331;
pub const CURLINFO_NUM_CONNECTS: CURLINFO = 2097178;
pub const CURLINFO_OS_ERRNO: CURLINFO = 2097177;
pub const CURLINFO_PROXYAUTH_AVAIL: CURLINFO = 2097176;
pub const CURLINFO_HTTPAUTH_AVAIL: CURLINFO = 2097175;
pub const CURLINFO_HTTP_CONNECTCODE: CURLINFO = 2097174;
pub const CURLINFO_PRIVATE: CURLINFO = 1048597;
pub const CURLINFO_REDIRECT_COUNT: CURLINFO = 2097172;
pub const CURLINFO_REDIRECT_TIME: CURLINFO = 3145747;
pub const CURLINFO_CONTENT_TYPE: CURLINFO = 1048594;
pub const CURLINFO_STARTTRANSFER_TIME: CURLINFO = 3145745;
pub const CURLINFO_CONTENT_LENGTH_UPLOAD_T: CURLINFO = 6291472;
pub const CURLINFO_CONTENT_LENGTH_UPLOAD: CURLINFO = 3145744;
pub const CURLINFO_CONTENT_LENGTH_DOWNLOAD_T: CURLINFO = 6291471;
pub const CURLINFO_CONTENT_LENGTH_DOWNLOAD: CURLINFO = 3145743;
pub const CURLINFO_FILETIME_T: CURLINFO = 6291470;
pub const CURLINFO_FILETIME: CURLINFO = 2097166;
pub const CURLINFO_SSL_VERIFYRESULT: CURLINFO = 2097165;
pub const CURLINFO_REQUEST_SIZE: CURLINFO = 2097164;
pub const CURLINFO_HEADER_SIZE: CURLINFO = 2097163;
pub const CURLINFO_SPEED_UPLOAD_T: CURLINFO = 6291466;
pub const CURLINFO_SPEED_UPLOAD: CURLINFO = 3145738;
pub const CURLINFO_SPEED_DOWNLOAD_T: CURLINFO = 6291465;
pub const CURLINFO_SPEED_DOWNLOAD: CURLINFO = 3145737;
pub const CURLINFO_SIZE_DOWNLOAD_T: CURLINFO = 6291464;
pub const CURLINFO_SIZE_DOWNLOAD: CURLINFO = 3145736;
pub const CURLINFO_SIZE_UPLOAD_T: CURLINFO = 6291463;
pub const CURLINFO_SIZE_UPLOAD: CURLINFO = 3145735;
pub const CURLINFO_PRETRANSFER_TIME: CURLINFO = 3145734;
pub const CURLINFO_CONNECT_TIME: CURLINFO = 3145733;
pub const CURLINFO_NAMELOOKUP_TIME: CURLINFO = 3145732;
pub const CURLINFO_TOTAL_TIME: CURLINFO = 3145731;
pub const CURLINFO_RESPONSE_CODE: CURLINFO = 2097154;
pub const CURLINFO_EFFECTIVE_URL: CURLINFO = 1048577;
pub const CURLINFO_NONE: CURLINFO = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct OutStruct {
    pub filename: *mut i8,
    pub alloc_filename: bool,
    pub is_cd_filename: bool,
    pub s_isreg: bool,
    pub fopened: bool,
    pub stream: *mut FILE,
    pub bytes: curl_off_t,
    pub init: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct InStruct {
    pub fd: i32,
    pub config: *mut OperationConfig,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HdrCbData {
    pub global: *mut GlobalConfig,
    pub config: *mut OperationConfig,
    pub outs: *mut OutStruct,
    pub heads: *mut OutStruct,
    pub etag_save: *mut OutStruct,
    pub honor_cd_filename: bool,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct per_transfer {
    pub next: *mut per_transfer,
    pub prev: *mut per_transfer,
    pub config: *mut OperationConfig,
    pub curl: *mut CURL,
    pub retry_numretries: i64,
    pub retry_sleep_default: i64,
    pub retry_sleep: i64,
    pub retrystart: timeval,
    pub this_url: *mut i8,
    pub urlnum: u32,
    pub outfile: *mut i8,
    pub infdopen: bool,
    pub infd: i32,
    pub noprogress: bool,
    pub progressbar: ProgressData,
    pub outs: OutStruct,
    pub heads: OutStruct,
    pub etag_save: OutStruct,
    pub input: InStruct,
    pub hdrcbdata: HdrCbData,
    pub num_headers: i64,
    pub was_last_header_empty: bool,
    pub errorbuffer: [i8; 256],
    pub added: bool,
    pub startat: time_t,
    pub abort: bool,
    pub dltotal: curl_off_t,
    pub dlnow: curl_off_t,
    pub ultotal: curl_off_t,
    pub ulnow: curl_off_t,
    pub dltotal_added: bool,
    pub ultotal_added: bool,
    pub separator_err: *mut i8,
    pub separator: *mut i8,
    pub uploadfile: *mut i8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ProgressData {
    pub calls: i32,
    pub prev: curl_off_t,
    pub prevtime: timeval,
    pub width: i32,
    pub out: *mut FILE,
    pub initial_size: curl_off_t,
    pub tick: u32,
    pub bar: i32,
    pub barmove: i32,
}
#[no_mangle]
pub unsafe extern "C" fn tool_header_cb(
    mut ptr: *mut i8,
    mut size: size_t,
    mut nmemb: size_t,
    mut userdata: *mut libc::c_void,
) -> size_t {
    let mut per: *mut per_transfer = userdata as *mut per_transfer;
    let mut hdrcbdata: *mut HdrCbData = &mut (*per).hdrcbdata;
    let mut outs: *mut OutStruct = &mut (*per).outs;
    let mut heads: *mut OutStruct = &mut (*per).heads;
    let mut etag_save: *mut OutStruct = &mut (*per).etag_save;
    let mut str: *const i8 = ptr;
    let cb: size_t = size.wrapping_mul(nmemb);
    let mut end: *const i8 = ptr.offset(cb as isize);
    let mut protocol: i64 = 0 as i32 as i64;
    let mut failure: size_t = (if size != 0 && nmemb != 0 {
        0 as i32
    } else {
        1 as i32
    }) as size_t;
    if ((*per).config).is_null() {
        return failure;
    }
    if !((*(*per).config).headerfile).is_null() && !((*heads).stream).is_null() {
        let mut rc: size_t = fwrite(
            ptr as *const libc::c_void,
            size,
            nmemb,
            (*heads).stream,
        );
        if rc != cb {
            return rc;
        }
        fflush((*heads).stream);
    }
    if !((*(*per).config).etag_save_file).is_null() && !((*etag_save).stream).is_null() {
        if curl_strnequal(
            str,
            b"etag:\0" as *const u8 as *const i8,
            5 as i32 as size_t,
        ) != 0
        {
            let mut etag_h: *const i8 = &*str.offset(5 as i32 as isize)
                as *const i8;
            let mut eot: *const i8 = end.offset(-(1 as i32 as isize));
            if *eot as i32 == '\n' as i32 {
                while Curl_isspace(*etag_h as u8 as i32) != 0
                    && etag_h < eot
                {
                    etag_h = etag_h.offset(1);
                }
                while Curl_isspace(*eot as u8 as i32) != 0 {
                    eot = eot.offset(-1);
                }
                if eot >= etag_h {
                    let mut etag_length: size_t = (eot.offset_from(etag_h)
                        as i64 + 1 as i32 as i64) as size_t;
                    fwrite(
                        etag_h as *const libc::c_void,
                        size,
                        etag_length,
                        (*etag_save).stream,
                    );
                    fputc('\n' as i32, (*etag_save).stream);
                    fflush((*etag_save).stream);
                }
            }
        }
    }
    curl_easy_getinfo(
        (*per).curl,
        CURLINFO_PROTOCOL,
        &mut protocol as *mut i64,
    );
    if (*hdrcbdata).honor_cd_filename as i32 != 0
        && cb > 20 as i32 as u64
        && curl_strnequal(
            b"Content-disposition:\0" as *const u8 as *const i8,
            str,
            strlen(b"Content-disposition:\0" as *const u8 as *const i8),
        ) != 0
        && protocol
            & ((1 as i32) << 1 as i32
                | (1 as i32) << 0 as i32) as i64 != 0
    {
        let mut p: *const i8 = str.offset(20 as i32 as isize);
        loop {
            let mut filename: *mut i8 = 0 as *mut i8;
            let mut len: size_t = 0;
            while *p as i32 != 0 && p < end
                && Curl_isalpha(*p as u8 as i32) == 0
            {
                p = p.offset(1);
            }
            if p > end.offset(-(9 as i32 as isize)) {
                break;
            }
            if memcmp(
                p as *const libc::c_void,
                b"filename=\0" as *const u8 as *const i8
                    as *const libc::c_void,
                9 as i32 as u64,
            ) != 0
            {
                while p < end && *p as i32 != ';' as i32 {
                    p = p.offset(1);
                }
            } else {
                p = p.offset(9 as i32 as isize);
                len = (cb as ssize_t - p.offset_from(str) as i64) as size_t;
                filename = parse_filename(p, len);
                if !filename.is_null() {
                    if !((*outs).stream).is_null() {
                        free(filename as *mut libc::c_void);
                        return failure;
                    }
                    (*outs).is_cd_filename = 1 as i32 != 0;
                    (*outs).s_isreg = 1 as i32 != 0;
                    (*outs).fopened = 0 as i32 != 0;
                    let ref mut fresh0 = (*outs).filename;
                    *fresh0 = filename;
                    (*outs).alloc_filename = 1 as i32 != 0;
                    (*hdrcbdata).honor_cd_filename = 0 as i32 != 0;
                    if !tool_create_output_file(outs, (*per).config) {
                        return failure;
                    }
                }
                break;
            }
        }
        if ((*outs).stream).is_null() && !tool_create_output_file(outs, (*per).config) {
            return failure;
        }
    }
    if !((*(*hdrcbdata).config).writeout).is_null() {
        let mut value: *mut i8 = memchr(
            ptr as *const libc::c_void,
            ':' as i32,
            cb,
        ) as *mut i8;
        if !value.is_null() {
            if (*per).was_last_header_empty {
                (*per).num_headers = 0 as i32 as i64;
            }
            (*per).was_last_header_empty = 0 as i32 != 0;
            let ref mut fresh1 = (*per).num_headers;
            *fresh1 += 1;
        } else if *ptr.offset(0 as i32 as isize) as i32 == '\r' as i32
                || *ptr.offset(0 as i32 as isize) as i32 == '\n' as i32
            {
            (*per).was_last_header_empty = 1 as i32 != 0;
        }
    }
    if (*(*hdrcbdata).config).show_headers as i32 != 0
        && protocol
            & ((1 as i32) << 0 as i32
                | (1 as i32) << 1 as i32
                | (1 as i32) << 18 as i32
                | (1 as i32) << 10 as i32) as i64 != 0
    {
        let mut value_0: *mut i8 = 0 as *mut i8;
        if ((*outs).stream).is_null() && !tool_create_output_file(outs, (*per).config) {
            return failure;
        }
        if (*(*hdrcbdata).global).isatty as i32 != 0
            && (*(*hdrcbdata).global).styled_output as i32 != 0
        {
            value_0 = memchr(ptr as *const libc::c_void, ':' as i32, cb)
                as *mut i8;
        }
        if !value_0.is_null() {
            let mut namelen: size_t = value_0.offset_from(ptr) as i64 as size_t;
            curl_mfprintf(
                (*outs).stream,
                b"\x1B[1m%.*s\x1B[0m:\0" as *const u8 as *const i8,
                namelen,
                ptr,
            );
            fwrite(
                &mut *value_0.offset(1 as i32 as isize) as *mut i8
                    as *const libc::c_void,
                cb.wrapping_sub(namelen).wrapping_sub(1 as i32 as u64),
                1 as i32 as u64,
                (*outs).stream,
            );
        } else {
            fwrite(
                ptr as *const libc::c_void,
                cb,
                1 as i32 as u64,
                (*outs).stream,
            );
        }
    }
    return cb;
}
unsafe extern "C" fn parse_filename(
    mut ptr: *const i8,
    mut len: size_t,
) -> *mut i8 {
    let mut copy: *mut i8 = 0 as *mut i8;
    let mut p: *mut i8 = 0 as *mut i8;
    let mut q: *mut i8 = 0 as *mut i8;
    let mut stop: i8 = '\u{0}' as i32 as i8;
    copy = malloc(len.wrapping_add(1 as i32 as u64))
        as *mut i8;
    if copy.is_null() {
        return 0 as *mut i8;
    }
    memcpy(copy as *mut libc::c_void, ptr as *const libc::c_void, len);
    *copy.offset(len as isize) = '\u{0}' as i32 as i8;
    p = copy;
    if *p as i32 == '\'' as i32 || *p as i32 == '"' as i32 {
        stop = *p;
        p = p.offset(1);
    } else {
        stop = ';' as i32 as i8;
    }
    q = strchr(p, stop as i32);
    if !q.is_null() {
        *q = '\u{0}' as i32 as i8;
    }
    q = strrchr(p, '/' as i32);
    if !q.is_null() {
        p = q.offset(1 as i32 as isize);
        if *p == 0 {
            free(copy as *mut libc::c_void);
            copy = 0 as *mut i8;
            return 0 as *mut i8;
        }
    }
    q = strrchr(p, '\\' as i32);
    if !q.is_null() {
        p = q.offset(1 as i32 as isize);
        if *p == 0 {
            free(copy as *mut libc::c_void);
            copy = 0 as *mut i8;
            return 0 as *mut i8;
        }
    }
    q = strchr(p, '\r' as i32);
    if !q.is_null() {
        *q = '\u{0}' as i32 as i8;
    }
    q = strchr(p, '\n' as i32);
    if !q.is_null() {
        *q = '\u{0}' as i32 as i8;
    }
    if copy != p {
        memmove(
            copy as *mut libc::c_void,
            p as *const libc::c_void,
            (strlen(p)).wrapping_add(1 as i32 as u64),
        );
    }
    return copy;
}
