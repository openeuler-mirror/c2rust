use :: libc;
extern "C" {
    fn fflush(__stream: *mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn fputc(__c: i32, __stream: *mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn fwrite(
        _: *const core::ffi::c_void,
        _: u64,
        _: u64,
        _: *mut crate::src::lib::http2::_IO_FILE,
    ) -> u64;
    fn malloc(_: u64) -> *mut core::ffi::c_void;
    fn free(__ptr: *mut core::ffi::c_void);
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn memmove(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn memcmp(_: *const core::ffi::c_void, _: *const core::ffi::c_void, _: u64) -> i32;
    fn memchr(_: *const core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strrchr(_: *const i8, _: i32) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
}
pub use crate::src::lib::curl_ctype::Curl_isalpha;
pub use crate::src::lib::curl_ctype::Curl_isspace;
pub use crate::src::lib::easy::curl_easy_getinfo;
pub use crate::src::lib::http2::curl_mime;
pub use crate::src::lib::http2::Curl_easy;
pub use crate::src::lib::mprintf::curl_mfprintf;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::strcase::curl_strnequal;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_cb_wrt::tool_create_output_file;
pub use crate::src::src::tool_msgs::_IO_marker;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __time_t = i64;
pub type __suseconds_t = i64;
pub type __ssize_t = i64;
pub type ssize_t = i64;
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
pub type CURLINFO = u32;
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
    pub stream: *mut crate::src::lib::http2::_IO_FILE,
    pub bytes: i64,
    pub init: i64,
}
impl OutStruct {
    pub const fn new() -> Self {
        OutStruct {
            filename: (0 as *mut i8),
            alloc_filename: false,
            is_cd_filename: false,
            s_isreg: false,
            fopened: false,
            stream: (0 as *mut crate::src::lib::http2::_IO_FILE),
            bytes: 0,
            init: 0,
        }
    }
}
impl std::default::Default for OutStruct {
    fn default() -> Self {
        OutStruct::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct InStruct {
    pub fd: i32,
    pub config: *mut crate::src::src::tool_cb_dbg::OperationConfig,
}
impl InStruct {
    pub const fn new() -> Self {
        InStruct {
            fd: 0,
            config: (0 as *mut crate::src::src::tool_cb_dbg::OperationConfig),
        }
    }
}
impl std::default::Default for InStruct {
    fn default() -> Self {
        InStruct::new()
    }
}
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
#[repr(C)]
pub struct HdrCbData<'a> {
    pub global: *mut crate::src::src::tool_cb_dbg::GlobalConfig,
    pub config: *mut crate::src::src::tool_cb_dbg::OperationConfig,
    pub outs: Option<&'a mut crate::src::src::tool_cb_hdr::OutStruct>,
    pub heads: Option<&'a mut crate::src::src::tool_cb_hdr::OutStruct>,
    pub etag_save: Option<&'a mut crate::src::src::tool_cb_hdr::OutStruct>,
    pub honor_cd_filename: bool,
}
impl<'a> HdrCbData<'a> {
    pub const fn new() -> Self {
        HdrCbData {
            global: (0 as *mut crate::src::src::tool_cb_dbg::GlobalConfig),
            config: (0 as *mut crate::src::src::tool_cb_dbg::OperationConfig),
            outs: None,
            heads: None,
            etag_save: None,
            honor_cd_filename: false,
        }
    }
}
impl<'a> std::default::Default for HdrCbData<'a> {
    fn default() -> Self {
        HdrCbData::new()
    }
}
#[repr(C)]
pub struct per_transfer<'a> {
    pub next: *mut crate::src::src::tool_cb_hdr::per_transfer<'a>,
    pub prev: *mut crate::src::src::tool_cb_hdr::per_transfer<'a>,
    pub config: *mut crate::src::src::tool_cb_dbg::OperationConfig,
    pub curl: *mut crate::src::lib::http2::Curl_easy,
    pub retry_numretries: i64,
    pub retry_sleep_default: i64,
    pub retry_sleep: i64,
    pub retrystart: crate::src::lib::openldap::timeval,
    pub this_url: *mut i8,
    pub urlnum: u32,
    pub outfile: *mut i8,
    pub infdopen: bool,
    pub infd: i32,
    pub noprogress: bool,
    pub progressbar: crate::src::src::tool_cb_hdr::ProgressData,
    pub outs: crate::src::src::tool_cb_hdr::OutStruct,
    pub heads: crate::src::src::tool_cb_hdr::OutStruct,
    pub etag_save: crate::src::src::tool_cb_hdr::OutStruct,
    pub input: crate::src::src::tool_cb_hdr::InStruct,
    pub hdrcbdata: crate::src::src::tool_cb_hdr::HdrCbData<'a>,
    pub num_headers: i64,
    pub was_last_header_empty: bool,
    pub errorbuffer: [i8; 256],
    pub added: bool,
    pub startat: i64,
    pub abort: bool,
    pub dltotal: i64,
    pub dlnow: i64,
    pub ultotal: i64,
    pub ulnow: i64,
    pub dltotal_added: bool,
    pub ultotal_added: bool,
    pub separator_err: *mut i8,
    pub separator: *mut i8,
    pub uploadfile: *mut i8,
}
impl<'a> per_transfer<'a> {
    pub const fn new() -> Self {
        per_transfer {
            next: (0 as *mut crate::src::src::tool_cb_hdr::per_transfer<'a>),
            prev: (0 as *mut crate::src::src::tool_cb_hdr::per_transfer<'a>),
            config: (0 as *mut crate::src::src::tool_cb_dbg::OperationConfig),
            curl: (0 as *mut crate::src::lib::http2::Curl_easy),
            retry_numretries: 0,
            retry_sleep_default: 0,
            retry_sleep: 0,
            retrystart: crate::src::lib::openldap::timeval::new(),
            this_url: (0 as *mut i8),
            urlnum: 0,
            outfile: (0 as *mut i8),
            infdopen: false,
            infd: 0,
            noprogress: false,
            progressbar: crate::src::src::tool_cb_hdr::ProgressData::new(),
            outs: crate::src::src::tool_cb_hdr::OutStruct::new(),
            heads: crate::src::src::tool_cb_hdr::OutStruct::new(),
            etag_save: crate::src::src::tool_cb_hdr::OutStruct::new(),
            input: crate::src::src::tool_cb_hdr::InStruct::new(),
            hdrcbdata: crate::src::src::tool_cb_hdr::HdrCbData::new(),
            num_headers: 0,
            was_last_header_empty: false,
            errorbuffer: [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            added: false,
            startat: 0,
            abort: false,
            dltotal: 0,
            dlnow: 0,
            ultotal: 0,
            ulnow: 0,
            dltotal_added: false,
            ultotal_added: false,
            separator_err: (0 as *mut i8),
            separator: (0 as *mut i8),
            uploadfile: (0 as *mut i8),
        }
    }
}
impl<'a> std::default::Default for per_transfer<'a> {
    fn default() -> Self {
        per_transfer::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ProgressData {
    pub calls: i32,
    pub prev: i64,
    pub prevtime: crate::src::lib::openldap::timeval,
    pub width: i32,
    pub out: *mut crate::src::lib::http2::_IO_FILE,
    pub initial_size: i64,
    pub tick: u32,
    pub bar: i32,
    pub barmove: i32,
}
impl ProgressData {
    pub const fn new() -> Self {
        ProgressData {
            calls: 0,
            prev: 0,
            prevtime: crate::src::lib::openldap::timeval::new(),
            width: 0,
            out: (0 as *mut crate::src::lib::http2::_IO_FILE),
            initial_size: 0,
            tick: 0,
            bar: 0,
            barmove: 0,
        }
    }
}
impl std::default::Default for ProgressData {
    fn default() -> Self {
        ProgressData::new()
    }
}
#[no_mangle]
pub extern "C" fn tool_header_cb(
    mut ptr: *mut i8,
    mut size: u64,
    mut nmemb: u64,
    mut userdata: *mut core::ffi::c_void,
) -> u64 {
    let mut per: *mut crate::src::src::tool_cb_hdr::per_transfer<'_> =
        userdata as *mut per_transfer;
    let mut hdrcbdata: Option<&'_ mut crate::src::src::tool_cb_hdr::HdrCbData<'_>> =
        Some(unsafe { &mut (*per).hdrcbdata });
    let mut outs: Option<&'_ mut crate::src::src::tool_cb_hdr::OutStruct> = Some(unsafe { &mut (*per).outs });
    let mut heads: Option<&'_ mut crate::src::src::tool_cb_hdr::OutStruct> =
        Some(unsafe { &mut (*per).heads });
    let mut etag_save: Option<&'_ mut crate::src::src::tool_cb_hdr::OutStruct> =
        Some(unsafe { &mut (*per).etag_save });
    let mut str: *const i8 = ptr;
    let cb: u64 = size.wrapping_mul(nmemb);
    let mut end: *const i8 = unsafe { ptr.offset(cb as isize) };
    let mut protocol: i64 = 0 as i32 as i64;
    let mut failure: u64 = (if size != 0 && nmemb != 0 {
        0 as i32
    } else {
        1 as i32
    }) as size_t;
    if (unsafe { (*per).config }).is_null() {
        return failure;
    }
    if !(unsafe { (*(*per).config).headerfile }).is_null()
        && !((*(borrow_mut(&mut heads)).unwrap()).stream).is_null()
    {
        let mut rc: u64 = unsafe { fwrite(
            ptr as *const libc::c_void,
            size,
            nmemb,
            (*(borrow_mut(&mut heads)).unwrap()).stream,
        ) };
        if rc != cb {
            return rc;
        }
        (unsafe { fflush((*(borrow_mut(&mut heads)).unwrap()).stream) });
    }
    if !(unsafe { (*(*per).config).etag_save_file }).is_null()
        && !((*(borrow(&etag_save)).unwrap()).stream).is_null()
    {
        if curl_strnequal(
            str,
            b"etag:\0" as *const u8 as *const i8,
            5 as i32 as size_t,
        ) != 0
        {
            let mut etag_h: *const i8 = (unsafe { &*str.offset(5 as i32 as isize) }) as *const i8;
            let mut eot: *const i8 = unsafe { end.offset(-(1 as i32 as isize)) };
            if (unsafe { *eot }) as i32 == '\n' as i32 {
                while Curl_isspace((unsafe { *etag_h }) as u8 as i32) != 0 && etag_h < eot {
                    etag_h = unsafe { etag_h.offset(1) };
                }
                while Curl_isspace((unsafe { *eot }) as u8 as i32) != 0 {
                    eot = unsafe { eot.offset(-1) };
                }
                if eot >= etag_h {
                    let mut etag_length: u64 =
                        ((unsafe { eot.offset_from(etag_h) }) as i64 + 1 as i32 as i64) as size_t;
                    (unsafe { fwrite(
                        etag_h as *const libc::c_void,
                        size,
                        etag_length,
                        (*(borrow_mut(&mut etag_save)).unwrap()).stream,
                    ) });
                    (unsafe { fputc('\n' as i32, (*(borrow_mut(&mut etag_save)).unwrap()).stream) });
                    (unsafe { fflush((*(borrow_mut(&mut etag_save)).unwrap()).stream) });
                }
            }
        }
    }
    (unsafe { curl_easy_getinfo((*per).curl, CURLINFO_PROTOCOL, &mut protocol as *mut i64) });
    if (*(borrow(&hdrcbdata)).unwrap()).honor_cd_filename as i32 != 0
        && cb > 20 as i32 as u64
        && curl_strnequal(
            b"Content-disposition:\0" as *const u8 as *const i8,
            str,
            unsafe { strlen(b"Content-disposition:\0" as *const u8 as *const i8) },
        ) != 0
        && protocol & ((1 as i32) << 1 as i32 | (1 as i32) << 0 as i32) as i64 != 0
    {
        let mut p: *const i8 = unsafe { str.offset(20 as i32 as isize) };
        loop {
            let mut filename: *mut i8 = 0 as *mut i8;
            let mut len: u64 = 0;
            while (unsafe { *p }) as i32 != 0 && p < end && Curl_isalpha((unsafe { *p }) as u8 as i32) == 0 {
                p = unsafe { p.offset(1) };
            }
            if p > (unsafe { end.offset(-(9 as i32 as isize)) }) {
                break;
            }
            if (unsafe { memcmp(
                p as *const libc::c_void,
                b"filename=\0" as *const u8 as *const i8 as *const libc::c_void,
                9 as i32 as u64,
            ) }) != 0
            {
                while p < end && (unsafe { *p }) as i32 != ';' as i32 {
                    p = unsafe { p.offset(1) };
                }
            } else {
                p = unsafe { p.offset(9 as i32 as isize) };
                len = (cb as ssize_t - (unsafe { p.offset_from(str) }) as i64) as size_t;
                filename = parse_filename(p, len);
                if !filename.is_null() {
                    if !((*(borrow_mut(&mut outs)).unwrap()).stream).is_null() {
                        (unsafe { free(filename as *mut libc::c_void) });
                        return failure;
                    }
                    (*(borrow_mut(&mut outs)).unwrap()).is_cd_filename = 1 as i32 != 0;
                    (*(borrow_mut(&mut outs)).unwrap()).s_isreg = 1 as i32 != 0;
                    (*(borrow_mut(&mut outs)).unwrap()).fopened = 0 as i32 != 0;
                    let mut fresh0 = &mut ((*(borrow_mut(&mut outs)).unwrap()).filename);
                    *fresh0 = filename;
                    (*(borrow_mut(&mut outs)).unwrap()).alloc_filename = 1 as i32 != 0;
                    (*(borrow_mut(&mut hdrcbdata)).unwrap()).honor_cd_filename = 0 as i32 != 0;
                    if !tool_create_output_file(borrow_mut(&mut outs), unsafe { (*per).config }) {
                        return failure;
                    }
                }
                break;
            }
        }
        if ((*(borrow(&outs)).unwrap()).stream).is_null()
            && !tool_create_output_file(borrow_mut(&mut outs), unsafe { (*per).config })
        {
            return failure;
        }
    }
    if !(unsafe { (*(*(borrow(&hdrcbdata)).unwrap()).config).writeout }).is_null() {
        let mut value: *mut i8 = (unsafe { memchr(ptr as *const libc::c_void, ':' as i32, cb) }) as *mut i8;
        if !value.is_null() {
            if unsafe { (*per).was_last_header_empty } {
                (unsafe { (*per).num_headers = 0 as i32 as i64 });
            }
            (unsafe { (*per).was_last_header_empty = 0 as i32 != 0 });
            let mut fresh1 = unsafe { &mut ((*per).num_headers) };
            *fresh1 += 1;
        } else if (unsafe { *ptr.offset(0 as i32 as isize) }) as i32 == '\r' as i32
            || (unsafe { *ptr.offset(0 as i32 as isize) }) as i32 == '\n' as i32
        {
            (unsafe { (*per).was_last_header_empty = 1 as i32 != 0 });
        }
    }
    if (unsafe { (*(*(borrow(&hdrcbdata)).unwrap()).config).show_headers }) as i32 != 0
        && protocol
            & ((1 as i32) << 0 as i32
                | (1 as i32) << 1 as i32
                | (1 as i32) << 18 as i32
                | (1 as i32) << 10 as i32) as i64
            != 0
    {
        let mut value_0: *mut i8 = 0 as *mut i8;
        if ((*(borrow(&outs)).unwrap()).stream).is_null()
            && !tool_create_output_file(borrow_mut(&mut outs), unsafe { (*per).config })
        {
            return failure;
        }
        if (unsafe { (*(*(borrow(&hdrcbdata)).unwrap()).global).isatty }) as i32 != 0
            && (unsafe { (*(*(borrow(&hdrcbdata)).unwrap()).global).styled_output }) as i32 != 0
        {
            value_0 = (unsafe { memchr(ptr as *const libc::c_void, ':' as i32, cb) }) as *mut i8;
        }
        if !value_0.is_null() {
            let mut namelen: u64 = (unsafe { value_0.offset_from(ptr) }) as i64 as size_t;
            (unsafe { curl_mfprintf(
                (*(borrow_mut(&mut outs)).unwrap()).stream,
                b"\x1B[1m%.*s\x1B[0m:\0" as *const u8 as *const i8,
                namelen,
                ptr,
            ) });
            (unsafe { fwrite(
                &mut *value_0.offset(1 as i32 as isize) as *mut i8 as *const libc::c_void,
                cb.wrapping_sub(namelen).wrapping_sub(1 as i32 as u64),
                1 as i32 as u64,
                (*(borrow_mut(&mut outs)).unwrap()).stream,
            ) });
        } else {
            (unsafe { fwrite(
                ptr as *const libc::c_void,
                cb,
                1 as i32 as u64,
                (*(borrow_mut(&mut outs)).unwrap()).stream,
            ) });
        }
    }
    return cb;
}
extern "C" fn parse_filename(mut ptr: *const i8, mut len: u64) -> *mut i8 {
    let mut copy: *mut i8 = 0 as *mut i8;
    let mut p: *mut i8 = 0 as *mut i8;
    let mut q: *mut i8 = 0 as *mut i8;
    let mut stop: i8 = '\u{0}' as i32 as i8;
    copy = (unsafe { malloc(len.wrapping_add(1 as i32 as u64)) }) as *mut i8;
    if copy.is_null() {
        return 0 as *mut i8;
    }
    (unsafe { memcpy(copy as *mut libc::c_void, ptr as *const libc::c_void, len) });
    (unsafe { *copy.offset(len as isize) = '\u{0}' as i32 as i8 });
    p = copy;
    if (unsafe { *p }) as i32 == '\'' as i32 || (unsafe { *p }) as i32 == '"' as i32 {
        stop = unsafe { *p };
        p = unsafe { p.offset(1) };
    } else {
        stop = ';' as i32 as i8;
    }
    q = unsafe { strchr(p, stop as i32) };
    if !q.is_null() {
        (unsafe { *q = '\u{0}' as i32 as i8 });
    }
    q = unsafe { strrchr(p, '/' as i32) };
    if !q.is_null() {
        p = unsafe { q.offset(1 as i32 as isize) };
        if (unsafe { *p }) == 0 {
            (unsafe { free(copy as *mut libc::c_void) });
            copy = 0 as *mut i8;
            return 0 as *mut i8;
        }
    }
    q = unsafe { strrchr(p, '\\' as i32) };
    if !q.is_null() {
        p = unsafe { q.offset(1 as i32 as isize) };
        if (unsafe { *p }) == 0 {
            (unsafe { free(copy as *mut libc::c_void) });
            copy = 0 as *mut i8;
            return 0 as *mut i8;
        }
    }
    q = unsafe { strchr(p, '\r' as i32) };
    if !q.is_null() {
        (unsafe { *q = '\u{0}' as i32 as i8 });
    }
    q = unsafe { strchr(p, '\n' as i32) };
    if !q.is_null() {
        (unsafe { *q = '\u{0}' as i32 as i8 });
    }
    if copy != p {
        (unsafe { memmove(
            copy as *mut libc::c_void,
            p as *const libc::c_void,
            (strlen(p)).wrapping_add(1 as i32 as u64),
        ) });
    }
    return copy;
}
use crate::laertes_rt::*;
