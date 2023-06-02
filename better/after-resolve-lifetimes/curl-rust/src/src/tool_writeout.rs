use ::libc;
extern "C" {
    
    
    
    
    
    
    static mut stdout: * mut crate::src::lib::http2::_IO_FILE;
    static mut stderr: * mut crate::src::lib::http2::_IO_FILE;
    fn fputc(__c: i32, __stream: * mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn fputs(__s: * const i8, __stream: * mut crate::src::lib::http2::_IO_FILE) -> i32;
    
    
    fn strchr(_: * const i8, _: i32) -> * mut i8;
    
    
    
}
pub use crate::src::lib::easy::curl_easy_getinfo;
pub use crate::src::lib::mprintf::curl_mfprintf;
pub use crate::src::lib::strcase::curl_strequal;
pub use crate::src::lib::strerror::curl_easy_strerror;
pub use crate::src::src::tool_writeout_json::jsonWriteString;
pub use crate::src::src::tool_writeout_json::ourWriteOutJSON;
pub use crate::src::lib::http2::Curl_easy;
pub use crate::src::lib::http2::curl_mime;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __time_t = i64;
pub type __suseconds_t = i64;
pub type time_t = i64;
pub type size_t = u64;
// #[derive(Copy, Clone)]

pub type timeval = crate::src::lib::openldap::timeval;
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
// #[derive(Copy, Clone)]

pub type OutStruct = crate::src::src::tool_cb_hdr::OutStruct;
// #[derive(Copy, Clone)]

pub type InStruct = crate::src::src::tool_cb_hdr::InStruct;
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
// #[derive(Copy, Clone)]

pub type HdrCbData<'a> = crate::src::src::tool_cb_hdr::HdrCbData<'a>;
// #[derive(Copy, Clone)]

pub type ProgressData = crate::src::src::tool_cb_hdr::ProgressData;
// #[derive(Copy, Clone)]

pub type per_transfer<'a> = crate::src::src::tool_cb_hdr::per_transfer<'a>;
pub type writeoutid = u32;
pub const VAR_NUM_OF_VARS: writeoutid = 42;
pub const VAR_URLNUM: writeoutid = 41;
pub const VAR_TOTAL_TIME: writeoutid = 40;
pub const VAR_STDOUT: writeoutid = 39;
pub const VAR_STDERR: writeoutid = 38;
pub const VAR_STARTTRANSFER_TIME: writeoutid = 37;
pub const VAR_SSL_VERIFY_RESULT: writeoutid = 36;
pub const VAR_SPEED_UPLOAD: writeoutid = 35;
pub const VAR_SPEED_DOWNLOAD: writeoutid = 34;
pub const VAR_SIZE_UPLOAD: writeoutid = 33;
pub const VAR_SIZE_DOWNLOAD: writeoutid = 32;
pub const VAR_SCHEME: writeoutid = 31;
pub const VAR_REQUEST_SIZE: writeoutid = 30;
pub const VAR_REFERER: writeoutid = 29;
pub const VAR_REDIRECT_URL: writeoutid = 28;
pub const VAR_REDIRECT_TIME: writeoutid = 27;
pub const VAR_REDIRECT_COUNT: writeoutid = 26;
pub const VAR_PROXY_SSL_VERIFY_RESULT: writeoutid = 25;
pub const VAR_PRIMARY_PORT: writeoutid = 24;
pub const VAR_PRIMARY_IP: writeoutid = 23;
pub const VAR_PRETRANSFER_TIME: writeoutid = 22;
pub const VAR_ONERROR: writeoutid = 21;
pub const VAR_NUM_HEADERS: writeoutid = 20;
pub const VAR_NUM_CONNECTS: writeoutid = 19;
pub const VAR_NAMELOOKUP_TIME: writeoutid = 18;
pub const VAR_LOCAL_PORT: writeoutid = 17;
pub const VAR_LOCAL_IP: writeoutid = 16;
pub const VAR_JSON: writeoutid = 15;
pub const VAR_INPUT_URL: writeoutid = 14;
pub const VAR_HTTP_VERSION: writeoutid = 13;
pub const VAR_HTTP_CODE_PROXY: writeoutid = 12;
pub const VAR_HTTP_CODE: writeoutid = 11;
pub const VAR_HEADER_SIZE: writeoutid = 10;
pub const VAR_FTP_ENTRY_PATH: writeoutid = 9;
pub const VAR_EXITCODE: writeoutid = 8;
pub const VAR_ERRORMSG: writeoutid = 7;
pub const VAR_EFFECTIVE_URL: writeoutid = 6;
pub const VAR_EFFECTIVE_METHOD: writeoutid = 5;
pub const VAR_EFFECTIVE_FILENAME: writeoutid = 4;
pub const VAR_CONTENT_TYPE: writeoutid = 3;
pub const VAR_CONNECT_TIME: writeoutid = 2;
pub const VAR_APPCONNECT_TIME: writeoutid = 1;
pub const VAR_NONE: writeoutid = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct writeoutvar<'a> {
    pub name: * const i8,
    pub id: u32,
    pub ci: u32,
    pub writefunc: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::_IO_FILE,_: Option<&'a crate::src::src::tool_writeout::writeoutvar<'a>>,_: * mut crate::src::src::tool_cb_hdr::per_transfer<'a>,_: u32,_: bool,) -> i32>,
}
impl<'a> writeoutvar<'a> {
    pub const fn new() -> Self {
        writeoutvar {
        name: (0 as * const i8),
        id: 0,
        ci: 0,
        writefunc: None
        }
    }
}

impl<'a> std::default::Default for writeoutvar<'a> {
    fn default() -> Self { writeoutvar::new() }
}

static mut http_version: [* const i8; 5] = [
    b"0\0" as *const u8 as *const i8,
    b"1\0" as *const u8 as *const i8,
    b"1.1\0" as *const u8 as *const i8,
    b"2\0" as *const u8 as *const i8,
    b"3\0" as *const u8 as *const i8,
];
static mut variables: [crate::src::src::tool_writeout::writeoutvar<'static>; 43] = unsafe {
    [
        {
            let mut init = writeoutvar {
                name: b"content_type\0" as *const u8 as *const i8,
                id: VAR_CONTENT_TYPE,
                ci: CURLINFO_CONTENT_TYPE,
                writefunc: Some(
                    writeString,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"errormsg\0" as *const u8 as *const i8,
                id: VAR_ERRORMSG,
                ci: CURLINFO_NONE,
                writefunc: Some(
                    writeString,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"exitcode\0" as *const u8 as *const i8,
                id: VAR_EXITCODE,
                ci: CURLINFO_NONE,
                writefunc: Some(
                    writeLong,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"filename_effective\0" as *const u8 as *const i8,
                id: VAR_EFFECTIVE_FILENAME,
                ci: CURLINFO_NONE,
                writefunc: Some(
                    writeString,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"ftp_entry_path\0" as *const u8 as *const i8,
                id: VAR_FTP_ENTRY_PATH,
                ci: CURLINFO_FTP_ENTRY_PATH,
                writefunc: Some(
                    writeString,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"http_code\0" as *const u8 as *const i8,
                id: VAR_HTTP_CODE,
                ci: CURLINFO_RESPONSE_CODE,
                writefunc: Some(
                    writeLong,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"http_connect\0" as *const u8 as *const i8,
                id: VAR_HTTP_CODE_PROXY,
                ci: CURLINFO_HTTP_CONNECTCODE,
                writefunc: Some(
                    writeLong,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"http_version\0" as *const u8 as *const i8,
                id: VAR_HTTP_VERSION,
                ci: CURLINFO_HTTP_VERSION,
                writefunc: Some(
                    writeString,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"json\0" as *const u8 as *const i8,
                id: VAR_JSON,
                ci: CURLINFO_NONE,
                writefunc: None,
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"local_ip\0" as *const u8 as *const i8,
                id: VAR_LOCAL_IP,
                ci: CURLINFO_LOCAL_IP,
                writefunc: Some(
                    writeString,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"local_port\0" as *const u8 as *const i8,
                id: VAR_LOCAL_PORT,
                ci: CURLINFO_LOCAL_PORT,
                writefunc: Some(
                    writeLong,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"method\0" as *const u8 as *const i8,
                id: VAR_EFFECTIVE_METHOD,
                ci: CURLINFO_EFFECTIVE_METHOD,
                writefunc: Some(
                    writeString,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"num_connects\0" as *const u8 as *const i8,
                id: VAR_NUM_CONNECTS,
                ci: CURLINFO_NUM_CONNECTS,
                writefunc: Some(
                    writeLong,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"num_headers\0" as *const u8 as *const i8,
                id: VAR_NUM_HEADERS,
                ci: CURLINFO_NONE,
                writefunc: Some(
                    writeLong,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"num_redirects\0" as *const u8 as *const i8,
                id: VAR_REDIRECT_COUNT,
                ci: CURLINFO_REDIRECT_COUNT,
                writefunc: Some(
                    writeLong,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"onerror\0" as *const u8 as *const i8,
                id: VAR_ONERROR,
                ci: CURLINFO_NONE,
                writefunc: None,
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"proxy_ssl_verify_result\0" as *const u8 as *const i8,
                id: VAR_PROXY_SSL_VERIFY_RESULT,
                ci: CURLINFO_PROXY_SSL_VERIFYRESULT,
                writefunc: Some(
                    writeLong,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"redirect_url\0" as *const u8 as *const i8,
                id: VAR_REDIRECT_URL,
                ci: CURLINFO_REDIRECT_URL,
                writefunc: Some(
                    writeString,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"referer\0" as *const u8 as *const i8,
                id: VAR_REFERER,
                ci: CURLINFO_REFERER,
                writefunc: Some(
                    writeString,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"remote_ip\0" as *const u8 as *const i8,
                id: VAR_PRIMARY_IP,
                ci: CURLINFO_PRIMARY_IP,
                writefunc: Some(
                    writeString,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"remote_port\0" as *const u8 as *const i8,
                id: VAR_PRIMARY_PORT,
                ci: CURLINFO_PRIMARY_PORT,
                writefunc: Some(
                    writeLong,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"response_code\0" as *const u8 as *const i8,
                id: VAR_HTTP_CODE,
                ci: CURLINFO_RESPONSE_CODE,
                writefunc: Some(
                    writeLong,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"scheme\0" as *const u8 as *const i8,
                id: VAR_SCHEME,
                ci: CURLINFO_SCHEME,
                writefunc: Some(
                    writeString,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"size_download\0" as *const u8 as *const i8,
                id: VAR_SIZE_DOWNLOAD,
                ci: CURLINFO_SIZE_DOWNLOAD_T,
                writefunc: Some(
                    writeOffset,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"size_header\0" as *const u8 as *const i8,
                id: VAR_HEADER_SIZE,
                ci: CURLINFO_HEADER_SIZE,
                writefunc: Some(
                    writeLong,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"size_request\0" as *const u8 as *const i8,
                id: VAR_REQUEST_SIZE,
                ci: CURLINFO_REQUEST_SIZE,
                writefunc: Some(
                    writeLong,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"size_upload\0" as *const u8 as *const i8,
                id: VAR_SIZE_UPLOAD,
                ci: CURLINFO_SIZE_UPLOAD_T,
                writefunc: Some(
                    writeOffset,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"speed_download\0" as *const u8 as *const i8,
                id: VAR_SPEED_DOWNLOAD,
                ci: CURLINFO_SPEED_DOWNLOAD_T,
                writefunc: Some(
                    writeOffset,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"speed_upload\0" as *const u8 as *const i8,
                id: VAR_SPEED_UPLOAD,
                ci: CURLINFO_SPEED_UPLOAD_T,
                writefunc: Some(
                    writeOffset,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"ssl_verify_result\0" as *const u8 as *const i8,
                id: VAR_SSL_VERIFY_RESULT,
                ci: CURLINFO_SSL_VERIFYRESULT,
                writefunc: Some(
                    writeLong,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"stderr\0" as *const u8 as *const i8,
                id: VAR_STDERR,
                ci: CURLINFO_NONE,
                writefunc: None,
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"stdout\0" as *const u8 as *const i8,
                id: VAR_STDOUT,
                ci: CURLINFO_NONE,
                writefunc: None,
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"time_appconnect\0" as *const u8 as *const i8,
                id: VAR_APPCONNECT_TIME,
                ci: CURLINFO_APPCONNECT_TIME_T,
                writefunc: Some(
                    writeTime,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"time_connect\0" as *const u8 as *const i8,
                id: VAR_CONNECT_TIME,
                ci: CURLINFO_CONNECT_TIME_T,
                writefunc: Some(
                    writeTime,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"time_namelookup\0" as *const u8 as *const i8,
                id: VAR_NAMELOOKUP_TIME,
                ci: CURLINFO_NAMELOOKUP_TIME_T,
                writefunc: Some(
                    writeTime,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"time_pretransfer\0" as *const u8 as *const i8,
                id: VAR_PRETRANSFER_TIME,
                ci: CURLINFO_PRETRANSFER_TIME_T,
                writefunc: Some(
                    writeTime,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"time_redirect\0" as *const u8 as *const i8,
                id: VAR_REDIRECT_TIME,
                ci: CURLINFO_REDIRECT_TIME_T,
                writefunc: Some(
                    writeTime,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"time_starttransfer\0" as *const u8 as *const i8,
                id: VAR_STARTTRANSFER_TIME,
                ci: CURLINFO_STARTTRANSFER_TIME_T,
                writefunc: Some(
                    writeTime,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"time_total\0" as *const u8 as *const i8,
                id: VAR_TOTAL_TIME,
                ci: CURLINFO_TOTAL_TIME_T,
                writefunc: Some(
                    writeTime,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"url\0" as *const u8 as *const i8,
                id: VAR_INPUT_URL,
                ci: CURLINFO_NONE,
                writefunc: Some(
                    writeString,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"url_effective\0" as *const u8 as *const i8,
                id: VAR_EFFECTIVE_URL,
                ci: CURLINFO_EFFECTIVE_URL,
                writefunc: Some(
                    writeString,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"urlnum\0" as *const u8 as *const i8,
                id: VAR_URLNUM,
                ci: CURLINFO_NONE,
                writefunc: Some(
                    writeLong,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: 0 as *const i8,
                id: VAR_NONE,
                ci: CURLINFO_NONE,
                writefunc: None,
            };
            init
        },
    ]
};
unsafe extern "C" fn writeTime<'a1, 'a2, 'a3>(
    mut stream: * mut crate::src::lib::http2::_IO_FILE,
    mut wovar: Option<&'a1 crate::src::src::tool_writeout::writeoutvar<'a2>>,
    mut per: * mut crate::src::src::tool_cb_hdr::per_transfer<'a3>,
    mut per_result: u32,
    mut use_json: bool,
) -> i32 {
    let mut valid: bool = 0 as i32 != 0;
    let mut us: i64 = 0 as i32 as curl_off_t;
    if (*((wovar).clone()).unwrap()).ci as u64 != 0 {
        if curl_easy_getinfo((*per).curl, (*(wovar).unwrap()).ci, &mut us as *mut curl_off_t) as u64
            == 0
        {
            valid = 1 as i32 != 0;
        }
    }
    if valid {
        let mut secs: i64 = us / 1000000 as i32 as i64;
        us %= 1000000 as i32 as i64;
        if use_json {
            curl_mfprintf(
                stream,
                b"\"%s\":\0" as *const u8 as *const i8,
                (*((wovar).clone()).unwrap()).name,
            );
        }
        curl_mfprintf(
            stream,
            b"%lu.%06lu\0" as *const u8 as *const i8,
            secs,
            us,
        );
    } else if use_json {
        curl_mfprintf(
            stream,
            b"\"%s\":null\0" as *const u8 as *const i8,
            (*((wovar).clone()).unwrap()).name,
        );
    }
    return 1 as i32;
}
unsafe extern "C" fn writeString<'a1, 'a2, 'a3>(
    mut stream: * mut crate::src::lib::http2::_IO_FILE,
    mut wovar: Option<&'a1 crate::src::src::tool_writeout::writeoutvar<'a2>>,
    mut per: * mut crate::src::src::tool_cb_hdr::per_transfer<'a3>,
    mut per_result: u32,
    mut use_json: bool,
) -> i32 {
    let mut valid: bool = 0 as i32 != 0;
    let mut strinfo: * const i8 = 0 as *const i8;
    if (*((wovar).clone()).unwrap()).ci as u64 != 0 {
        if (*((wovar).clone()).unwrap()).ci as u32
            == CURLINFO_HTTP_VERSION as i32 as u32
        {
            let mut version: i64 = 0 as i32 as i64;
            if curl_easy_getinfo(
                (*per).curl,
                CURLINFO_HTTP_VERSION,
                &mut version as *mut i64,
            ) as u64 == 0 && version >= 0 as i32 as i64
                && version
                    < (::std::mem::size_of::<[*const i8; 5]>()
                        as u64)
                        .wrapping_div(
                            ::std::mem::size_of::<*const i8>() as u64,
                        ) as i64
            {
                strinfo = http_version[version as usize];
                valid = 1 as i32 != 0;
            }
        } else if curl_easy_getinfo(
                (*per).curl,
                (*(wovar).unwrap()).ci,
                &mut strinfo as *mut *const i8,
            ) as u64 == 0 && !strinfo.is_null()
            {
            valid = 1 as i32 != 0;
        }
    } else {
        match (*((wovar).clone()).unwrap()).id as u32 {
            7 => {
                if per_result as u64 != 0 {
                    strinfo = if (*per).errorbuffer[0 as i32 as usize]
                        as i32 != 0
                    {
                        ((*per).errorbuffer).as_mut_ptr() as *const i8
                    } else {
                        curl_easy_strerror(per_result)
                    };
                    valid = 1 as i32 != 0;
                }
            }
            4 => {
                if !((*per).outs.filename).is_null() {
                    strinfo = (*per).outs.filename;
                    valid = 1 as i32 != 0;
                }
            }
            14 => {
                if !((*per).this_url).is_null() {
                    strinfo = (*per).this_url;
                    valid = 1 as i32 != 0;
                }
            }
            _ => {}
        }
    }
    if valid {
        if use_json {
            curl_mfprintf(
                stream,
                b"\"%s\":\"\0" as *const u8 as *const i8,
                (*((wovar).clone()).unwrap()).name,
            );
            jsonWriteString(stream, strinfo);
            fputs(b"\"\0" as *const u8 as *const i8, stream);
        } else {
            fputs(strinfo, stream);
        }
    } else if use_json {
        curl_mfprintf(
            stream,
            b"\"%s\":null\0" as *const u8 as *const i8,
            (*((wovar).clone()).unwrap()).name,
        );
    }
    return 1 as i32;
}
unsafe extern "C" fn writeLong<'a1, 'a2, 'a3>(
    mut stream: * mut crate::src::lib::http2::_IO_FILE,
    mut wovar: Option<&'a1 crate::src::src::tool_writeout::writeoutvar<'a2>>,
    mut per: * mut crate::src::src::tool_cb_hdr::per_transfer<'a3>,
    mut per_result: u32,
    mut use_json: bool,
) -> i32 {
    let mut valid: bool = 0 as i32 != 0;
    let mut longinfo: i64 = 0 as i32 as i64;
    if (*((wovar).clone()).unwrap()).ci as u64 != 0 {
        if curl_easy_getinfo(
            (*per).curl,
            (*(wovar).unwrap()).ci,
            &mut longinfo as *mut i64,
        ) as u64 == 0
        {
            valid = 1 as i32 != 0;
        }
    } else {
        match (*((wovar).clone()).unwrap()).id as u32 {
            20 => {
                longinfo = (*per).num_headers;
                valid = 1 as i32 != 0;
            }
            8 => {
                longinfo = per_result as i64;
                valid = 1 as i32 != 0;
            }
            41 => {
                if (*per).urlnum <= 2147483647 as i32 as u32 {
                    longinfo = (*per).urlnum as i64;
                    valid = 1 as i32 != 0;
                }
            }
            _ => {}
        }
    }
    if valid {
        if use_json {
            curl_mfprintf(
                stream,
                b"\"%s\":%ld\0" as *const u8 as *const i8,
                (*((wovar).clone()).unwrap()).name,
                longinfo,
            );
        } else if (*((wovar).clone()).unwrap()).id as u32
                == VAR_HTTP_CODE as i32 as u32
                || (*((wovar).clone()).unwrap()).id as u32
                    == VAR_HTTP_CODE_PROXY as i32 as u32
            {
            curl_mfprintf(
                stream,
                b"%03ld\0" as *const u8 as *const i8,
                longinfo,
            );
        } else {
            curl_mfprintf(
                stream,
                b"%ld\0" as *const u8 as *const i8,
                longinfo,
            );
        }
    } else if use_json {
        curl_mfprintf(
            stream,
            b"\"%s\":null\0" as *const u8 as *const i8,
            (*((wovar).clone()).unwrap()).name,
        );
    }
    return 1 as i32;
}
unsafe extern "C" fn writeOffset<'a1, 'a2, 'a3>(
    mut stream: * mut crate::src::lib::http2::_IO_FILE,
    mut wovar: Option<&'a1 crate::src::src::tool_writeout::writeoutvar<'a2>>,
    mut per: * mut crate::src::src::tool_cb_hdr::per_transfer<'a3>,
    mut per_result: u32,
    mut use_json: bool,
) -> i32 {
    let mut valid: bool = 0 as i32 != 0;
    let mut offinfo: i64 = 0 as i32 as curl_off_t;
    if (*((wovar).clone()).unwrap()).ci as u64 != 0 {
        if curl_easy_getinfo((*per).curl, (*(wovar).unwrap()).ci, &mut offinfo as *mut curl_off_t)
            as u64 == 0
        {
            valid = 1 as i32 != 0;
        }
    }
    if valid {
        if use_json {
            curl_mfprintf(
                stream,
                b"\"%s\":\0" as *const u8 as *const i8,
                (*((wovar).clone()).unwrap()).name,
            );
        }
        curl_mfprintf(stream, b"%ld\0" as *const u8 as *const i8, offinfo);
    } else if use_json {
        curl_mfprintf(
            stream,
            b"\"%s\":null\0" as *const u8 as *const i8,
            (*((wovar).clone()).unwrap()).name,
        );
    }
    return 1 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn ourWriteOut<'a1>(
    mut writeinfo: * const i8,
    mut per: * mut crate::src::src::tool_cb_hdr::per_transfer<'a1>,
    mut per_result: u32,
) where 'a1: 'static {
    let mut stream: * mut crate::src::lib::http2::_IO_FILE = stdout;
    let mut ptr: * const i8 = writeinfo;
    let mut done: bool = 0 as i32 != 0;
    while !ptr.is_null() && *ptr as i32 != 0 && !done {
        if '%' as i32 == *ptr as i32
            && *ptr.offset(1 as i32 as isize) as i32 != 0
        {
            if '%' as i32 == *ptr.offset(1 as i32 as isize) as i32 {
                fputc('%' as i32, stream);
                ptr = ptr.offset(2 as i32 as isize);
            } else {
                let mut end: * mut i8 = 0 as *mut i8;
                if '{' as i32 == *ptr.offset(1 as i32 as isize) as i32 {
                    let mut keepit: i8 = 0;
                    let mut i: i32 = 0;
                    let mut match_0: bool = 0 as i32 != 0;
                    end = strchr(ptr, '}' as i32);
                    ptr = ptr.offset(2 as i32 as isize);
                    if end.is_null() {
                        fputs(b"%{\0" as *const u8 as *const i8, stream);
                    } else {
                        keepit = *end;
                        *end = 0 as i32 as i8;
                        i = 0 as i32;
                        while !(variables[i as usize].name).is_null() {
                            if curl_strequal(ptr, variables[i as usize].name) != 0 {
                                match_0 = 1 as i32 != 0;
                                match variables[i as usize].id as u32 {
                                    21 => {
                                        if per_result as u32
                                            == CURLE_OK as i32 as u32
                                        {
                                            done = 1 as i32 != 0;
                                        }
                                    }
                                    39 => {
                                        stream = stdout;
                                    }
                                    38 => {
                                        stream = stderr;
                                    }
                                    15 => {
                                        ourWriteOutJSON(
                                            stream,
                                            variables.as_ptr(),
                                            per,
                                            per_result,
                                        );
                                    }
                                    _ => {
                                        (variables[i as usize].writefunc)
                                            .expect(
                                                "non-null function pointer",
                                            )(
                                            stream,
                                            (Some(&*variables.as_ptr().offset(i as isize))).clone(),
                                            per,
                                            per_result,
                                            0 as i32 != 0,
                                        );
                                    }
                                }
                                break;
                            } else {
                                i += 1;
                            }
                        }
                        if !match_0 {
                            curl_mfprintf(
                                stderr,
                                b"curl: unknown --write-out variable: '%s'\n\0" as *const u8
                                    as *const i8,
                                ptr,
                            );
                        }
                        ptr = end.offset(1 as i32 as isize);
                        *end = keepit;
                    }
                } else {
                    fputc('%' as i32, stream);
                    fputc(*ptr.offset(1 as i32 as isize) as i32, stream);
                    ptr = ptr.offset(2 as i32 as isize);
                }
            }
        } else if '\\' as i32 == *ptr as i32
                && *ptr.offset(1 as i32 as isize) as i32 != 0
            {
            match *ptr.offset(1 as i32 as isize) as i32 {
                114 => {
                    fputc('\r' as i32, stream);
                }
                110 => {
                    fputc('\n' as i32, stream);
                }
                116 => {
                    fputc('\t' as i32, stream);
                }
                _ => {
                    fputc(*ptr as i32, stream);
                    fputc(*ptr.offset(1 as i32 as isize) as i32, stream);
                }
            }
            ptr = ptr.offset(2 as i32 as isize);
        } else {
            fputc(*ptr as i32, stream);
            ptr = ptr.offset(1);
        }
    }
}
use crate::laertes_rt::*;
