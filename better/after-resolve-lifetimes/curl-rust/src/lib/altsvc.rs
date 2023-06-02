use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn fclose(__stream: * mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn fopen(_: * const i8, _: * const i8) -> * mut crate::src::lib::http2::_IO_FILE;
    fn sscanf(_: * const i8, _: * const i8, _: ...) -> i32;
    fn fputs(__s: * const i8, __stream: * mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn time(__timer: * mut i64) -> i64;
    
    fn unlink(__name: * const i8) -> i32;
    fn strtoul(
        _: * const i8,
        _: * mut * mut i8,
        _: i32,
    ) -> u64;
    fn memcpy(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::curl_ctype::Curl_isalnum;
pub use crate::src::lib::curl_get_line::Curl_get_line;
pub use crate::src::lib::llist::Curl_llist_init;
pub use crate::src::lib::llist::Curl_llist_insert_next;
pub use crate::src::lib::llist::Curl_llist_remove;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::mprintf::curl_mfprintf;
pub use crate::src::lib::parsedate::Curl_getdate_capped;
pub use crate::src::lib::parsedate::Curl_gmtime;
pub use crate::src::lib::rand::Curl_rand_hex;
pub use crate::src::lib::rename::Curl_rename;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::warnless::curlx_ultous;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::easy::Curl_ccalloc;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_cstrdup;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
pub type __uint8_t = u8;
pub type __int32_t = i32;
pub type __uint32_t = u32;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __pid_t = i32;
pub type __time_t = i64;
pub type __ssize_t = i64;
pub type __socklen_t = u32;
pub type pid_t = i32;
pub type ssize_t = i64;
pub type time_t = i64;
pub type size_t = u64;
pub type int32_t = i32;
pub type socklen_t = u32;
pub type sa_family_t = u16;
// #[derive(Copy, Clone)]

pub type sockaddr = crate::src::lib::http2::sockaddr;
pub type curl_socklen_t = u32;
pub type curl_off_t = i64;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::lib::http2::_IO_FILE;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tm {
    pub tm_sec: i32,
    pub tm_min: i32,
    pub tm_hour: i32,
    pub tm_mday: i32,
    pub tm_mon: i32,
    pub tm_year: i32,
    pub tm_wday: i32,
    pub tm_yday: i32,
    pub tm_isdst: i32,
    pub tm_gmtoff: i64,
    pub tm_zone: * const i8,
}
impl tm {
    pub const fn new() -> Self {
        tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: (0 as * const i8)
        }
    }
}

impl std::default::Default for tm {
    fn default() -> Self { tm::new() }
}

// #[derive(Copy, Clone)]

pub type Curl_easy = crate::src::lib::http2::Curl_easy;
// #[derive(Copy, Clone)]

pub type curl_tlssessioninfo = crate::src::lib::http2::curl_tlssessioninfo;
pub type curl_sslbackend = u32;
pub const CURLSSLBACKEND_RUSTLS: curl_sslbackend = 14;
pub const CURLSSLBACKEND_BEARSSL: curl_sslbackend = 13;
pub const CURLSSLBACKEND_MESALINK: curl_sslbackend = 12;
pub const CURLSSLBACKEND_MBEDTLS: curl_sslbackend = 11;
pub const CURLSSLBACKEND_AXTLS: curl_sslbackend = 10;
pub const CURLSSLBACKEND_SECURETRANSPORT: curl_sslbackend = 9;
pub const CURLSSLBACKEND_SCHANNEL: curl_sslbackend = 8;
pub const CURLSSLBACKEND_WOLFSSL: curl_sslbackend = 7;
pub const CURLSSLBACKEND_POLARSSL: curl_sslbackend = 6;
pub const CURLSSLBACKEND_GSKIT: curl_sslbackend = 5;
pub const CURLSSLBACKEND_OBSOLETE4: curl_sslbackend = 4;
pub const CURLSSLBACKEND_NSS: curl_sslbackend = 3;
pub const CURLSSLBACKEND_GNUTLS: curl_sslbackend = 2;
pub const CURLSSLBACKEND_OPENSSL: curl_sslbackend = 1;
pub const CURLSSLBACKEND_NONE: curl_sslbackend = 0;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type PureInfo = crate::src::lib::http2::PureInfo;
pub type bit = u32;
pub type CURLproxycode = u32;
pub const CURLPX_LAST: CURLproxycode = 34;
pub const CURLPX_USER_REJECTED: CURLproxycode = 33;
pub const CURLPX_UNKNOWN_MODE: CURLproxycode = 32;
pub const CURLPX_UNKNOWN_FAIL: CURLproxycode = 31;
pub const CURLPX_SEND_REQUEST: CURLproxycode = 30;
pub const CURLPX_SEND_CONNECT: CURLproxycode = 29;
pub const CURLPX_SEND_AUTH: CURLproxycode = 28;
pub const CURLPX_RESOLVE_HOST: CURLproxycode = 27;
pub const CURLPX_REQUEST_FAILED: CURLproxycode = 26;
pub const CURLPX_REPLY_UNASSIGNED: CURLproxycode = 25;
pub const CURLPX_REPLY_TTL_EXPIRED: CURLproxycode = 24;
pub const CURLPX_REPLY_NOT_ALLOWED: CURLproxycode = 23;
pub const CURLPX_REPLY_NETWORK_UNREACHABLE: CURLproxycode = 22;
pub const CURLPX_REPLY_HOST_UNREACHABLE: CURLproxycode = 21;
pub const CURLPX_REPLY_GENERAL_SERVER_FAILURE: CURLproxycode = 20;
pub const CURLPX_REPLY_CONNECTION_REFUSED: CURLproxycode = 19;
pub const CURLPX_REPLY_COMMAND_NOT_SUPPORTED: CURLproxycode = 18;
pub const CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: CURLproxycode = 17;
pub const CURLPX_RECV_REQACK: CURLproxycode = 16;
pub const CURLPX_RECV_CONNECT: CURLproxycode = 15;
pub const CURLPX_RECV_AUTH: CURLproxycode = 14;
pub const CURLPX_RECV_ADDRESS: CURLproxycode = 13;
pub const CURLPX_NO_AUTH: CURLproxycode = 12;
pub const CURLPX_LONG_USER: CURLproxycode = 11;
pub const CURLPX_LONG_PASSWD: CURLproxycode = 10;
pub const CURLPX_LONG_HOSTNAME: CURLproxycode = 9;
pub const CURLPX_IDENTD_DIFFER: CURLproxycode = 8;
pub const CURLPX_IDENTD: CURLproxycode = 7;
pub const CURLPX_GSSAPI_PROTECTION: CURLproxycode = 6;
pub const CURLPX_GSSAPI_PERMSG: CURLproxycode = 5;
pub const CURLPX_GSSAPI: CURLproxycode = 4;
pub const CURLPX_CLOSED: CURLproxycode = 3;
pub const CURLPX_BAD_VERSION: CURLproxycode = 2;
pub const CURLPX_BAD_ADDRESS_TYPE: CURLproxycode = 1;
pub const CURLPX_OK: CURLproxycode = 0;
// #[derive(Copy, Clone)]

pub type curl_certinfo = crate::src::lib::http2::curl_certinfo;
// #[derive(Copy, Clone)]

pub type curl_slist = crate::src::lib::http2::curl_slist;
// #[derive(Copy, Clone)]

pub type WildcardData = crate::src::lib::http2::WildcardData;
pub type wildcard_dtor<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> ()>;
// #[derive(Copy, Clone)]

pub type Curl_llist = crate::src::lib::http2::Curl_llist;
pub type Curl_llist_dtor<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: Option<&'a2 mut core::ffi::c_void>,) -> ()>;
// #[derive(Copy, Clone)]

pub type Curl_llist_element = crate::src::lib::http2::Curl_llist_element;
pub type wildcard_states = u32;
pub const CURLWC_DONE: wildcard_states = 7;
pub const CURLWC_ERROR: wildcard_states = 6;
pub const CURLWC_SKIP: wildcard_states = 5;
pub const CURLWC_CLEAN: wildcard_states = 4;
pub const CURLWC_DOWNLOADING: wildcard_states = 3;
pub const CURLWC_MATCHING: wildcard_states = 2;
pub const CURLWC_INIT: wildcard_states = 1;
pub const CURLWC_CLEAR: wildcard_states = 0;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type UrlState = crate::src::lib::http2::UrlState;
// #[derive(Copy, Clone)]

pub type dynamically_allocated_data = crate::src::lib::http2::dynamically_allocated_data;
pub type trailers_state = u32;
pub const TRAILERS_DONE: trailers_state = 3;
pub const TRAILERS_SENDING: trailers_state = 2;
pub const TRAILERS_INITIALIZED: trailers_state = 1;
pub const TRAILERS_NONE: trailers_state = 0;
// #[derive(Copy, Clone)]

pub type dynbuf = crate::src::lib::http2::dynbuf;
pub type Curl_HttpReq = u32;
pub const HTTPREQ_HEAD: Curl_HttpReq = 5;
pub const HTTPREQ_PUT: Curl_HttpReq = 4;
pub const HTTPREQ_POST_MIME: Curl_HttpReq = 3;
pub const HTTPREQ_POST_FORM: Curl_HttpReq = 2;
pub const HTTPREQ_POST: Curl_HttpReq = 1;
pub const HTTPREQ_GET: Curl_HttpReq = 0;
// #[derive(Copy, Clone)]

pub type urlpieces = crate::src::lib::http2::urlpieces;
pub type CURLU = crate::src::lib::urlapi::Curl_URL;
pub type curl_read_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut i8>,_: u64,_: u64,_: Option<&'a2 mut core::ffi::c_void>,) -> u64>;
// #[derive(Copy, Clone)]

pub type time_node = crate::src::lib::http2::time_node;
pub type expire_id = u32;
pub const EXPIRE_LAST: expire_id = 13;
pub const EXPIRE_QUIC: expire_id = 12;
pub const EXPIRE_TOOFAST: expire_id = 11;
pub const EXPIRE_TIMEOUT: expire_id = 10;
pub const EXPIRE_SPEEDCHECK: expire_id = 9;
pub const EXPIRE_RUN_NOW: expire_id = 8;
pub const EXPIRE_MULTI_PENDING: expire_id = 7;
pub const EXPIRE_HAPPY_EYEBALLS: expire_id = 6;
pub const EXPIRE_HAPPY_EYEBALLS_DNS: expire_id = 5;
pub const EXPIRE_DNS_PER_NAME2: expire_id = 4;
pub const EXPIRE_DNS_PER_NAME: expire_id = 3;
pub const EXPIRE_CONNECTTIMEOUT: expire_id = 2;
pub const EXPIRE_ASYNC_NAME: expire_id = 1;
pub const EXPIRE_100_TIMEOUT: expire_id = 0;
// #[derive(Copy, Clone)]

pub type curltime = crate::src::lib::http2::curltime;
// #[derive(Copy, Clone)]

pub type Curl_tree = crate::src::lib::http2::Curl_tree;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type Curl_async = crate::src::lib::http2::Curl_async;
// #[derive(Copy, Clone)]

pub type Curl_dns_entry = crate::src::lib::http2::Curl_dns_entry;
// #[derive(Copy, Clone)]

pub type Curl_addrinfo = crate::src::lib::http2::Curl_addrinfo;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type auth = crate::src::lib::http2::auth;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type digestdata = crate::src::lib::http2::digestdata;
// #[derive(Copy, Clone)]

pub type tempbuf = crate::src::lib::http2::tempbuf;
// #[derive(Copy, Clone)]

pub type Curl_ssl_session = crate::src::lib::http2::Curl_ssl_session;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type ssl_primary_config = crate::src::lib::http2::ssl_primary_config;
// #[derive(Copy, Clone)]

pub type curl_blob = crate::src::lib::http2::curl_blob;
// #[derive(Copy, Clone)]

pub type conncache = crate::src::lib::http2::conncache;
// #[derive(Copy, Clone)]

pub type Curl_hash = crate::src::lib::http2::Curl_hash;
pub type Curl_hash_dtor<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> ()>;
pub type comp_function<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: u64,_: Option<&'a2 mut core::ffi::c_void>,_: u64,) -> u64>;
pub type hash_function<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: u64,_: u64,) -> u64>;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type Progress = crate::src::lib::http2::Progress;
pub type timediff_t = i64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct altsvcinfo {
    pub filename: * mut i8,
    pub list: crate::src::lib::http2::Curl_llist,
    pub flags: i64,
}
impl altsvcinfo {
    pub const fn new() -> Self {
        altsvcinfo {
        filename: (0 as * mut i8),
        list: crate::src::lib::http2::Curl_llist::new(),
        flags: 0
        }
    }
}

impl std::default::Default for altsvcinfo {
    fn default() -> Self { altsvcinfo::new() }
}

// #[derive(Copy, Clone)]

pub type CookieInfo = crate::src::lib::http2::CookieInfo;
// #[derive(Copy, Clone)]

pub type Cookie = crate::src::lib::http2::Cookie;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type UserDefined = crate::src::lib::http2::UserDefined;
pub type curl_trailer_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut Option<&'a2 mut crate::src::lib::http2::curl_slist>>,_: Option<&'a3 mut core::ffi::c_void>,) -> i32>;
pub type multidone_func<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: u32,) -> i32>;
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
pub type curl_resolver_start_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: Option<&'a2 mut core::ffi::c_void>,_: Option<&'a3 mut core::ffi::c_void>,) -> i32>;
// #[derive(Copy, Clone)]

pub type Curl_http2_dep = crate::src::lib::http2::Curl_http2_dep;
pub type curl_fnmatch_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: Option<&'a2 i8>,_: Option<&'a3 i8>,) -> i32>;
pub type curl_chunk_end_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> i64>;
pub type curl_chunk_bgn_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 core::ffi::c_void>,_: Option<&'a2 mut core::ffi::c_void>,_: i32,) -> i64>;
pub type Curl_RtspReq = u32;
pub const RTSPREQ_LAST: Curl_RtspReq = 12;
pub const RTSPREQ_RECEIVE: Curl_RtspReq = 11;
pub const RTSPREQ_RECORD: Curl_RtspReq = 10;
pub const RTSPREQ_SET_PARAMETER: Curl_RtspReq = 9;
pub const RTSPREQ_GET_PARAMETER: Curl_RtspReq = 8;
pub const RTSPREQ_TEARDOWN: Curl_RtspReq = 7;
pub const RTSPREQ_PAUSE: Curl_RtspReq = 6;
pub const RTSPREQ_PLAY: Curl_RtspReq = 5;
pub const RTSPREQ_SETUP: Curl_RtspReq = 4;
pub const RTSPREQ_ANNOUNCE: Curl_RtspReq = 3;
pub const RTSPREQ_DESCRIBE: Curl_RtspReq = 2;
pub const RTSPREQ_OPTIONS: Curl_RtspReq = 1;
pub const RTSPREQ_NONE: Curl_RtspReq = 0;
pub type curl_usessl = u32;
pub const CURLUSESSL_LAST: curl_usessl = 4;
pub const CURLUSESSL_ALL: curl_usessl = 3;
pub const CURLUSESSL_CONTROL: curl_usessl = 2;
pub const CURLUSESSL_TRY: curl_usessl = 1;
pub const CURLUSESSL_NONE: curl_usessl = 0;
pub type CURL_NETRC_OPTION = u32;
pub const CURL_NETRC_LAST: CURL_NETRC_OPTION = 3;
pub const CURL_NETRC_REQUIRED: CURL_NETRC_OPTION = 2;
pub const CURL_NETRC_OPTIONAL: CURL_NETRC_OPTION = 1;
pub const CURL_NETRC_IGNORED: CURL_NETRC_OPTION = 0;
pub type curl_sshkeycallback<'a1, 'a2, 'a3, 'a4> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: Option<&'a2 crate::src::lib::http2::curl_khkey>,_: Option<&'a3 crate::src::lib::http2::curl_khkey>,_: u32,_: Option<&'a4 mut core::ffi::c_void>,) -> i32>;
pub type curl_khmatch = u32;
pub const CURLKHMATCH_LAST: curl_khmatch = 3;
pub const CURLKHMATCH_MISSING: curl_khmatch = 2;
pub const CURLKHMATCH_MISMATCH: curl_khmatch = 1;
pub const CURLKHMATCH_OK: curl_khmatch = 0;
// #[derive(Copy, Clone)]

pub type curl_khkey = crate::src::lib::http2::curl_khkey;
pub type curl_khtype = u32;
pub const CURLKHTYPE_ED25519: curl_khtype = 5;
pub const CURLKHTYPE_ECDSA: curl_khtype = 4;
pub const CURLKHTYPE_DSS: curl_khtype = 3;
pub const CURLKHTYPE_RSA: curl_khtype = 2;
pub const CURLKHTYPE_RSA1: curl_khtype = 1;
pub const CURLKHTYPE_UNKNOWN: curl_khtype = 0;
pub type CURL = crate::src::lib::http2::Curl_easy;
pub type curl_ftpccc = u32;
pub const CURLFTPSSL_CCC_LAST: curl_ftpccc = 3;
pub const CURLFTPSSL_CCC_ACTIVE: curl_ftpccc = 2;
pub const CURLFTPSSL_CCC_PASSIVE: curl_ftpccc = 1;
pub const CURLFTPSSL_CCC_NONE: curl_ftpccc = 0;
pub type curl_ftpauth = u32;
pub const CURLFTPAUTH_LAST: curl_ftpauth = 3;
pub const CURLFTPAUTH_TLS: curl_ftpauth = 2;
pub const CURLFTPAUTH_SSL: curl_ftpauth = 1;
pub const CURLFTPAUTH_DEFAULT: curl_ftpauth = 0;
pub type curl_ftpfile = u32;
pub const FTPFILE_SINGLECWD: curl_ftpfile = 3;
pub const FTPFILE_NOCWD: curl_ftpfile = 2;
pub const FTPFILE_MULTICWD: curl_ftpfile = 1;
// #[derive(Copy, Clone)]

pub type ssl_general_config = crate::src::lib::http2::ssl_general_config;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type ssl_config_data = crate::src::lib::http2::ssl_config_data;
pub type CURL_TLSAUTH = u32;
pub const CURL_TLSAUTH_LAST: CURL_TLSAUTH = 2;
pub const CURL_TLSAUTH_SRP: CURL_TLSAUTH = 1;
pub const CURL_TLSAUTH_NONE: CURL_TLSAUTH = 0;
pub type curl_ssl_ctx_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: Option<&'a2 mut core::ffi::c_void>,_: Option<&'a3 mut core::ffi::c_void>,) -> u32>;
pub type curl_proxytype = u32;
pub const CURLPROXY_SOCKS5_HOSTNAME: curl_proxytype = 7;
pub const CURLPROXY_SOCKS4A: curl_proxytype = 6;
pub const CURLPROXY_SOCKS5: curl_proxytype = 5;
pub const CURLPROXY_SOCKS4: curl_proxytype = 4;
pub const CURLPROXY_HTTPS: curl_proxytype = 2;
pub const CURLPROXY_HTTP_1_0: curl_proxytype = 1;
pub const CURLPROXY_HTTP: curl_proxytype = 0;
pub type curl_TimeCond = u32;
pub const CURL_TIMECOND_LAST: curl_TimeCond = 4;
pub const CURL_TIMECOND_LASTMOD: curl_TimeCond = 3;
pub const CURL_TIMECOND_IFUNMODSINCE: curl_TimeCond = 2;
pub const CURL_TIMECOND_IFMODSINCE: curl_TimeCond = 1;
pub const CURL_TIMECOND_NONE: curl_TimeCond = 0;
// #[derive(Copy, Clone)]

pub type curl_mimepart = crate::src::lib::http2::curl_mimepart;
// #[derive(Copy, Clone)]

pub type mime_encoder_state = crate::src::lib::http2::mime_encoder_state;
// #[derive(Copy, Clone)]

pub type mime_encoder = crate::src::lib::http2::mime_encoder;
// #[derive(Copy, Clone)]

pub type mime_state = crate::src::lib::http2::mime_state;
pub type mimestate = u32;
pub const MIMESTATE_LAST: mimestate = 9;
pub const MIMESTATE_END: mimestate = 8;
pub const MIMESTATE_CONTENT: mimestate = 7;
pub const MIMESTATE_BOUNDARY2: mimestate = 6;
pub const MIMESTATE_BOUNDARY1: mimestate = 5;
pub const MIMESTATE_BODY: mimestate = 4;
pub const MIMESTATE_EOH: mimestate = 3;
pub const MIMESTATE_USERHEADERS: mimestate = 2;
pub const MIMESTATE_CURLHEADERS: mimestate = 1;
pub const MIMESTATE_BEGIN: mimestate = 0;
pub type curl_free_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> ()>;
pub type curl_seek_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: i64,_: i32,) -> i32>;
pub type mimekind = u32;
pub const MIMEKIND_LAST: mimekind = 5;
pub const MIMEKIND_MULTIPART: mimekind = 4;
pub const MIMEKIND_CALLBACK: mimekind = 3;
pub const MIMEKIND_FILE: mimekind = 2;
pub const MIMEKIND_DATA: mimekind = 1;
pub const MIMEKIND_NONE: mimekind = 0;
// #[derive(Copy, Clone)]

pub type curl_mime = crate::src::lib::http2::curl_mime;
// #[derive(Copy, Clone)]

pub type curl_httppost = crate::src::lib::http2::curl_httppost;
pub type curl_hstswrite_callback<'a1, 'a2, 'a3, 'a4> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: Option<&'a2 mut crate::src::lib::http2::curl_hstsentry>,_: Option<&'a3 mut crate::src::lib::http2::curl_index>,_: Option<&'a4 mut core::ffi::c_void>,) -> u32>;
// #[derive(Copy, Clone)]

pub type curl_index = crate::src::lib::http2::curl_index;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type curl_hstsentry = crate::src::lib::http2::curl_hstsentry;
pub type CURLSTScode = u32;
pub const CURLSTS_FAIL: CURLSTScode = 2;
pub const CURLSTS_DONE: CURLSTScode = 1;
pub const CURLSTS_OK: CURLSTScode = 0;
pub type curl_hstsread_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: Option<&'a2 mut crate::src::lib::http2::curl_hstsentry>,_: Option<&'a3 mut core::ffi::c_void>,) -> u32>;
pub type curl_conv_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut i8>,_: u64,) -> u32>;
pub type curl_closesocket_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: i32,) -> i32>;
pub type curl_socket_t = i32;
pub type curl_opensocket_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: u32,_: Option<&'a2 mut crate::src::lib::http2::curl_sockaddr>,) -> i32>;
// #[derive(Copy, Clone)]

pub type curl_sockaddr = crate::src::lib::http2::curl_sockaddr;
pub type curlsocktype = u32;
pub const CURLSOCKTYPE_LAST: curlsocktype = 2;
pub const CURLSOCKTYPE_ACCEPT: curlsocktype = 1;
pub const CURLSOCKTYPE_IPCXN: curlsocktype = 0;
pub type curl_sockopt_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: i32,_: u32,) -> i32>;
pub type curl_ioctl_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: i32,_: Option<&'a2 mut core::ffi::c_void>,) -> u32>;
pub type curlioerr = u32;
pub const CURLIOE_LAST: curlioerr = 3;
pub const CURLIOE_FAILRESTART: curlioerr = 2;
pub const CURLIOE_UNKNOWNCMD: curlioerr = 1;
pub const CURLIOE_OK: curlioerr = 0;
pub type curl_debug_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: u32,_: Option<&'a2 mut i8>,_: u64,_: Option<&'a3 mut core::ffi::c_void>,) -> i32>;
pub type curl_infotype = u32;
pub const CURLINFO_END: curl_infotype = 7;
pub const CURLINFO_SSL_DATA_OUT: curl_infotype = 6;
pub const CURLINFO_SSL_DATA_IN: curl_infotype = 5;
pub const CURLINFO_DATA_OUT: curl_infotype = 4;
pub const CURLINFO_DATA_IN: curl_infotype = 3;
pub const CURLINFO_HEADER_OUT: curl_infotype = 2;
pub const CURLINFO_HEADER_IN: curl_infotype = 1;
pub const CURLINFO_TEXT: curl_infotype = 0;
pub type curl_xferinfo_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: i64,_: i64,_: i64,_: i64,) -> i32>;
pub type curl_progress_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: f64,_: f64,_: f64,_: f64,) -> i32>;
pub type curl_write_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut i8>,_: u64,_: u64,_: Option<&'a2 mut core::ffi::c_void>,) -> u64>;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type SingleRequest = crate::src::lib::http2::SingleRequest;
// #[derive(Copy, Clone)]

pub type dohdata = crate::src::lib::http2::dohdata;
// #[derive(Copy, Clone)]

pub type dnsprobe = crate::src::lib::http2::dnsprobe;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed = crate::src::lib::http2::C2RustUnnamed;
// #[derive(Copy, Clone)]

pub type SSHPROTO = crate::src::lib::http2::SSHPROTO;
// #[derive(Copy, Clone)]

pub type SMTP = crate::src::lib::http2::SMTP;
pub type curl_pp_transfer = u32;
pub const PPTRANSFER_NONE: curl_pp_transfer = 2;
pub const PPTRANSFER_INFO: curl_pp_transfer = 1;
pub const PPTRANSFER_BODY: curl_pp_transfer = 0;
// #[derive(Copy, Clone)]

pub type RTSP = crate::src::lib::http2::RTSP;
// #[derive(Copy, Clone)]

pub type HTTP = crate::src::lib::http2::HTTP;
pub type uint8_t = u8;
pub type uint32_t = u32;
pub type C2RustUnnamed_0 = u32;
pub const HTTPSEND_BODY: C2RustUnnamed_0 = 2;
pub const HTTPSEND_REQUEST: C2RustUnnamed_0 = 1;
pub const HTTPSEND_NADA: C2RustUnnamed_0 = 0;
// #[derive(Copy, Clone)]

pub type back = crate::src::lib::http2::back;
// #[derive(Copy, Clone)]

pub type POP3 = crate::src::lib::http2::POP3;
// #[derive(Copy, Clone)]

pub type MQTT = crate::src::lib::http2::MQTT;
// #[derive(Copy, Clone)]

pub type IMAP = crate::src::lib::http2::IMAP;
// #[derive(Copy, Clone)]

pub type FTP = crate::src::lib::http2::FTP;
// #[derive(Copy, Clone)]

pub type FILEPROTO = crate::src::lib::http2::FILEPROTO;
pub type upgrade101 = u32;
pub const UPGR101_WORKING: upgrade101 = 3;
pub const UPGR101_RECEIVED: upgrade101 = 2;
pub const UPGR101_REQUESTED: upgrade101 = 1;
pub const UPGR101_INIT: upgrade101 = 0;
pub type expect100 = u32;
pub const EXP100_FAILED: expect100 = 3;
pub const EXP100_SENDING_REQUEST: expect100 = 2;
pub const EXP100_AWAITING_CONTINUE: expect100 = 1;
pub const EXP100_SEND_DATA: expect100 = 0;
pub type C2RustUnnamed_1 = u32;
pub const HEADER_ALLBAD: C2RustUnnamed_1 = 2;
pub const HEADER_PARTHEADER: C2RustUnnamed_1 = 1;
pub const HEADER_NORMAL: C2RustUnnamed_1 = 0;
// #[derive(Copy, Clone)]

pub type PslCache = crate::src::lib::http2::PslCache;
pub type psl_ctx_t = crate::src::lib::urlapi::psl_ctx_st;
// #[derive(Copy, Clone)]

pub type Curl_multi = crate::src::lib::http2::Curl_multi;
pub type curl_multi_timer_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_multi>,_: i64,_: Option<&'a2 mut core::ffi::c_void>,) -> i32>;
pub type CURLM = crate::src::lib::http2::Curl_multi;
pub type curl_push_callback<'a1, 'a2, 'a3, 'a4> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: Option<&'a2 mut crate::src::lib::http2::Curl_easy>,_: u64,_: Option<&'a3 mut crate::src::lib::http2::curl_pushheaders>,_: Option<&'a4 mut core::ffi::c_void>,) -> i32>;
pub type curl_socket_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: i32,_: i32,_: Option<&'a2 mut core::ffi::c_void>,_: Option<&'a3 mut core::ffi::c_void>,) -> i32>;
// #[derive(Copy, Clone)]

pub type Names = crate::src::lib::http2::Names;
pub type C2RustUnnamed_2 = u32;
pub const HCACHE_SHARED: C2RustUnnamed_2 = 2;
pub const HCACHE_MULTI: C2RustUnnamed_2 = 1;
pub const HCACHE_NONE: C2RustUnnamed_2 = 0;
// #[derive(Copy, Clone)]

pub type Curl_message = crate::src::lib::http2::Curl_message;
// #[derive(Copy, Clone)]

pub type CURLMsg = crate::src::lib::http2::CURLMsg;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_3 = crate::src::lib::http2::C2RustUnnamed_3;
pub type CURLMSG = u32;
pub const CURLMSG_LAST: CURLMSG = 2;
pub const CURLMSG_DONE: CURLMSG = 1;
pub const CURLMSG_NONE: CURLMSG = 0;
pub type CURLMstate = u32;
pub const MSTATE_LAST: CURLMstate = 17;
pub const MSTATE_MSGSENT: CURLMstate = 16;
pub const MSTATE_COMPLETED: CURLMstate = 15;
pub const MSTATE_DONE: CURLMstate = 14;
pub const MSTATE_RATELIMITING: CURLMstate = 13;
pub const MSTATE_PERFORMING: CURLMstate = 12;
pub const MSTATE_DID: CURLMstate = 11;
pub const MSTATE_DOING_MORE: CURLMstate = 10;
pub const MSTATE_DOING: CURLMstate = 9;
pub const MSTATE_DO: CURLMstate = 8;
pub const MSTATE_PROTOCONNECTING: CURLMstate = 7;
pub const MSTATE_PROTOCONNECT: CURLMstate = 6;
pub const MSTATE_TUNNELING: CURLMstate = 5;
pub const MSTATE_CONNECTING: CURLMstate = 4;
pub const MSTATE_RESOLVING: CURLMstate = 3;
pub const MSTATE_CONNECT: CURLMstate = 2;
pub const MSTATE_PENDING: CURLMstate = 1;
pub const MSTATE_INIT: CURLMstate = 0;
// #[derive(Copy, Clone)]

pub type connectdata = crate::src::lib::http2::connectdata;
// #[derive(Copy, Clone)]

pub type connectbundle = crate::src::lib::http2::connectbundle;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_4 = crate::src::lib::http2::C2RustUnnamed_4;
// #[derive(Copy, Clone)]

pub type mqtt_conn = crate::src::lib::http2::mqtt_conn;
pub type mqttstate = u32;
pub const MQTT_NOSTATE: mqttstate = 7;
pub const MQTT_PUB_REMAIN: mqttstate = 6;
pub const MQTT_PUBWAIT: mqttstate = 5;
pub const MQTT_SUBACK_COMING: mqttstate = 4;
pub const MQTT_SUBACK: mqttstate = 3;
pub const MQTT_CONNACK: mqttstate = 2;
pub const MQTT_REMAINING_LENGTH: mqttstate = 1;
pub const MQTT_FIRST: mqttstate = 0;
// #[derive(Copy, Clone)]

pub type smb_conn = crate::src::lib::http2::smb_conn;
pub type smb_conn_state = u32;
pub const SMB_CONNECTED: smb_conn_state = 4;
pub const SMB_SETUP: smb_conn_state = 3;
pub const SMB_NEGOTIATE: smb_conn_state = 2;
pub const SMB_CONNECTING: smb_conn_state = 1;
pub const SMB_NOT_CONNECTED: smb_conn_state = 0;
// #[derive(Copy, Clone)]

pub type rtsp_conn = crate::src::lib::http2::rtsp_conn;
// #[derive(Copy, Clone)]

pub type smtp_conn = crate::src::lib::http2::smtp_conn;
// #[derive(Copy, Clone)]

pub type SASL = crate::src::lib::http2::SASL;
pub type saslstate = u32;
pub const SASL_FINAL: saslstate = 17;
pub const SASL_CANCEL: saslstate = 16;
pub const SASL_GSASL: saslstate = 15;
pub const SASL_OAUTH2_RESP: saslstate = 14;
pub const SASL_OAUTH2: saslstate = 13;
pub const SASL_GSSAPI_NO_DATA: saslstate = 12;
pub const SASL_GSSAPI_TOKEN: saslstate = 11;
pub const SASL_GSSAPI: saslstate = 10;
pub const SASL_NTLM_TYPE2MSG: saslstate = 9;
pub const SASL_NTLM: saslstate = 8;
pub const SASL_DIGESTMD5_RESP: saslstate = 7;
pub const SASL_DIGESTMD5: saslstate = 6;
pub const SASL_CRAMMD5: saslstate = 5;
pub const SASL_EXTERNAL: saslstate = 4;
pub const SASL_LOGIN_PASSWD: saslstate = 3;
pub const SASL_LOGIN: saslstate = 2;
pub const SASL_PLAIN: saslstate = 1;
pub const SASL_STOP: saslstate = 0;
// #[derive(Copy, Clone)]

pub type SASLproto = crate::src::lib::http2::SASLproto;
pub type smtpstate = u32;
pub const SMTP_LAST: smtpstate = 13;
pub const SMTP_QUIT: smtpstate = 12;
pub const SMTP_POSTDATA: smtpstate = 11;
pub const SMTP_DATA: smtpstate = 10;
pub const SMTP_RCPT: smtpstate = 9;
pub const SMTP_MAIL: smtpstate = 8;
pub const SMTP_COMMAND: smtpstate = 7;
pub const SMTP_AUTH: smtpstate = 6;
pub const SMTP_UPGRADETLS: smtpstate = 5;
pub const SMTP_STARTTLS: smtpstate = 4;
pub const SMTP_HELO: smtpstate = 3;
pub const SMTP_EHLO: smtpstate = 2;
pub const SMTP_SERVERGREET: smtpstate = 1;
pub const SMTP_STOP: smtpstate = 0;
// #[derive(Copy, Clone)]

pub type pingpong = crate::src::lib::http2::pingpong;
// #[derive(Copy, Clone)]

pub type pop3_conn = crate::src::lib::http2::pop3_conn;
pub type pop3state = u32;
pub const POP3_LAST: pop3state = 11;
pub const POP3_QUIT: pop3state = 10;
pub const POP3_COMMAND: pop3state = 9;
pub const POP3_PASS: pop3state = 8;
pub const POP3_USER: pop3state = 7;
pub const POP3_APOP: pop3state = 6;
pub const POP3_AUTH: pop3state = 5;
pub const POP3_UPGRADETLS: pop3state = 4;
pub const POP3_STARTTLS: pop3state = 3;
pub const POP3_CAPA: pop3state = 2;
pub const POP3_SERVERGREET: pop3state = 1;
pub const POP3_STOP: pop3state = 0;
// #[derive(Copy, Clone)]

pub type imap_conn = crate::src::lib::http2::imap_conn;
pub type imapstate = u32;
pub const IMAP_LAST: imapstate = 15;
pub const IMAP_LOGOUT: imapstate = 14;
pub const IMAP_SEARCH: imapstate = 13;
pub const IMAP_APPEND_FINAL: imapstate = 12;
pub const IMAP_APPEND: imapstate = 11;
pub const IMAP_FETCH_FINAL: imapstate = 10;
pub const IMAP_FETCH: imapstate = 9;
pub const IMAP_SELECT: imapstate = 8;
pub const IMAP_LIST: imapstate = 7;
pub const IMAP_LOGIN: imapstate = 6;
pub const IMAP_AUTHENTICATE: imapstate = 5;
pub const IMAP_UPGRADETLS: imapstate = 4;
pub const IMAP_STARTTLS: imapstate = 3;
pub const IMAP_CAPABILITY: imapstate = 2;
pub const IMAP_SERVERGREET: imapstate = 1;
pub const IMAP_STOP: imapstate = 0;
// #[derive(Copy, Clone)]

pub type ssh_conn = crate::src::lib::http2::ssh_conn;
pub type sshstate = i32;
pub const SSH_LAST: sshstate = 60;
pub const SSH_QUIT: sshstate = 59;
pub const SSH_SESSION_FREE: sshstate = 58;
pub const SSH_SESSION_DISCONNECT: sshstate = 57;
pub const SSH_SCP_CHANNEL_FREE: sshstate = 56;
pub const SSH_SCP_WAIT_CLOSE: sshstate = 55;
pub const SSH_SCP_WAIT_EOF: sshstate = 54;
pub const SSH_SCP_SEND_EOF: sshstate = 53;
pub const SSH_SCP_DONE: sshstate = 52;
pub const SSH_SCP_DOWNLOAD: sshstate = 51;
pub const SSH_SCP_DOWNLOAD_INIT: sshstate = 50;
pub const SSH_SCP_UPLOAD_INIT: sshstate = 49;
pub const SSH_SCP_TRANS_INIT: sshstate = 48;
pub const SSH_SFTP_SHUTDOWN: sshstate = 47;
pub const SSH_SFTP_CLOSE: sshstate = 46;
pub const SSH_SFTP_DOWNLOAD_STAT: sshstate = 45;
pub const SSH_SFTP_DOWNLOAD_INIT: sshstate = 44;
pub const SSH_SFTP_READDIR_DONE: sshstate = 43;
pub const SSH_SFTP_READDIR_BOTTOM: sshstate = 42;
pub const SSH_SFTP_READDIR_LINK: sshstate = 41;
pub const SSH_SFTP_READDIR: sshstate = 40;
pub const SSH_SFTP_READDIR_INIT: sshstate = 39;
pub const SSH_SFTP_CREATE_DIRS_MKDIR: sshstate = 38;
pub const SSH_SFTP_CREATE_DIRS: sshstate = 37;
pub const SSH_SFTP_CREATE_DIRS_INIT: sshstate = 36;
pub const SSH_SFTP_UPLOAD_INIT: sshstate = 35;
pub const SSH_SFTP_TRANS_INIT: sshstate = 34;
pub const SSH_SFTP_FILETIME: sshstate = 33;
pub const SSH_SFTP_GETINFO: sshstate = 32;
pub const SSH_SFTP_QUOTE_STATVFS: sshstate = 31;
pub const SSH_SFTP_QUOTE_UNLINK: sshstate = 30;
pub const SSH_SFTP_QUOTE_RMDIR: sshstate = 29;
pub const SSH_SFTP_QUOTE_RENAME: sshstate = 28;
pub const SSH_SFTP_QUOTE_MKDIR: sshstate = 27;
pub const SSH_SFTP_QUOTE_SYMLINK: sshstate = 26;
pub const SSH_SFTP_QUOTE_SETSTAT: sshstate = 25;
pub const SSH_SFTP_QUOTE_STAT: sshstate = 24;
pub const SSH_SFTP_NEXT_QUOTE: sshstate = 23;
pub const SSH_SFTP_QUOTE: sshstate = 22;
pub const SSH_SFTP_POSTQUOTE_INIT: sshstate = 21;
pub const SSH_SFTP_QUOTE_INIT: sshstate = 20;
pub const SSH_SFTP_REALPATH: sshstate = 19;
pub const SSH_SFTP_INIT: sshstate = 18;
pub const SSH_AUTH_DONE: sshstate = 17;
pub const SSH_AUTH_GSSAPI: sshstate = 16;
pub const SSH_AUTH_KEY: sshstate = 15;
pub const SSH_AUTH_KEY_INIT: sshstate = 14;
pub const SSH_AUTH_HOST: sshstate = 13;
pub const SSH_AUTH_HOST_INIT: sshstate = 12;
pub const SSH_AUTH_AGENT: sshstate = 11;
pub const SSH_AUTH_AGENT_LIST: sshstate = 10;
pub const SSH_AUTH_AGENT_INIT: sshstate = 9;
pub const SSH_AUTH_PASS: sshstate = 8;
pub const SSH_AUTH_PASS_INIT: sshstate = 7;
pub const SSH_AUTH_PKEY: sshstate = 6;
pub const SSH_AUTH_PKEY_INIT: sshstate = 5;
pub const SSH_AUTHLIST: sshstate = 4;
pub const SSH_HOSTKEY: sshstate = 3;
pub const SSH_S_STARTUP: sshstate = 2;
pub const SSH_INIT: sshstate = 1;
pub const SSH_STOP: sshstate = 0;
pub const SSH_NO_STATE: sshstate = -1;
// #[derive(Copy, Clone)]

pub type http_conn = crate::src::lib::http2::http_conn;
// #[derive(Copy, Clone)]

pub type nghttp2_settings_entry = crate::src::lib::http2::nghttp2_settings_entry;
// #[derive(Copy, Clone)]

pub type h2settings = crate::src::lib::http2::h2settings;
pub type Curl_recv<'a1, 'a2, 'a3> = unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: i32,_: Option<&'a2 mut i8>,_: u64,_: Option<&'a3 mut u32>,) -> i64;
pub type Curl_send<'a1, 'a2, 'a3> = unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: i32,_: Option<&'a2 core::ffi::c_void>,_: u64,_: Option<&'a3 mut u32>,) -> i64;
// #[derive(Copy, Clone)]

pub type ftp_conn = crate::src::lib::http2::ftp_conn;
pub type ftpstate = u32;
pub const FTP_LAST: ftpstate = 35;
pub const FTP_QUIT: ftpstate = 34;
pub const FTP_STOR: ftpstate = 33;
pub const FTP_RETR: ftpstate = 32;
pub const FTP_LIST: ftpstate = 31;
pub const FTP_PASV: ftpstate = 30;
pub const FTP_PRET: ftpstate = 29;
pub const FTP_PORT: ftpstate = 28;
pub const FTP_RETR_REST: ftpstate = 27;
pub const FTP_REST: ftpstate = 26;
pub const FTP_STOR_SIZE: ftpstate = 25;
pub const FTP_RETR_SIZE: ftpstate = 24;
pub const FTP_SIZE: ftpstate = 23;
pub const FTP_STOR_TYPE: ftpstate = 22;
pub const FTP_RETR_TYPE: ftpstate = 21;
pub const FTP_LIST_TYPE: ftpstate = 20;
pub const FTP_TYPE: ftpstate = 19;
pub const FTP_MDTM: ftpstate = 18;
pub const FTP_MKD: ftpstate = 17;
pub const FTP_CWD: ftpstate = 16;
pub const FTP_POSTQUOTE: ftpstate = 15;
pub const FTP_STOR_PREQUOTE: ftpstate = 14;
pub const FTP_RETR_PREQUOTE: ftpstate = 13;
pub const FTP_QUOTE: ftpstate = 12;
pub const FTP_NAMEFMT: ftpstate = 11;
pub const FTP_SYST: ftpstate = 10;
pub const FTP_PWD: ftpstate = 9;
pub const FTP_CCC: ftpstate = 8;
pub const FTP_PROT: ftpstate = 7;
pub const FTP_PBSZ: ftpstate = 6;
pub const FTP_ACCT: ftpstate = 5;
pub const FTP_PASS: ftpstate = 4;
pub const FTP_USER: ftpstate = 3;
pub const FTP_AUTH: ftpstate = 2;
pub const FTP_WAIT220: ftpstate = 1;
pub const FTP_STOP: ftpstate = 0;
// #[derive(Copy, Clone)]

pub type ntlmdata = crate::src::lib::http2::ntlmdata;
pub type curlntlm = u32;
pub const NTLMSTATE_LAST: curlntlm = 4;
pub const NTLMSTATE_TYPE3: curlntlm = 3;
pub const NTLMSTATE_TYPE2: curlntlm = 2;
pub const NTLMSTATE_TYPE1: curlntlm = 1;
pub const NTLMSTATE_NONE: curlntlm = 0;
// #[derive(Copy, Clone)]

pub type gsasldata = crate::src::lib::http2::gsasldata;
// #[derive(Copy, Clone)]

pub type Curl_handler = crate::src::lib::http2::Curl_handler;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type ConnectBits = crate::src::lib::http2::ConnectBits;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type ssl_connect_data = crate::src::lib::http2::ssl_connect_data;
pub type ssl_connect_state = u32;
pub const ssl_connect_done: ssl_connect_state = 5;
pub const ssl_connect_3: ssl_connect_state = 4;
pub const ssl_connect_2_writing: ssl_connect_state = 3;
pub const ssl_connect_2_reading: ssl_connect_state = 2;
pub const ssl_connect_2: ssl_connect_state = 1;
pub const ssl_connect_1: ssl_connect_state = 0;
pub type ssl_connection_state = u32;
pub const ssl_connection_complete: ssl_connection_state = 2;
pub const ssl_connection_negotiating: ssl_connection_state = 1;
pub const ssl_connection_none: ssl_connection_state = 0;
// #[derive(Copy, Clone)]

pub type proxy_info = crate::src::lib::http2::proxy_info;
// #[derive(Copy, Clone)]

pub type hostname = crate::src::lib::http2::hostname;
pub type C2RustUnnamed_5 = u32;
pub const TRNSPRT_QUIC: C2RustUnnamed_5 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_5 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_5 = 3;
// #[derive(Copy, Clone)]

pub type Curl_chunker = crate::src::lib::http2::Curl_chunker;
pub type ChunkyState = u32;
pub const CHUNK_TRAILER_POSTCR: ChunkyState = 7;
pub const CHUNK_TRAILER_CR: ChunkyState = 6;
pub const CHUNK_TRAILER: ChunkyState = 5;
pub const CHUNK_STOP: ChunkyState = 4;
pub const CHUNK_POSTLF: ChunkyState = 3;
pub const CHUNK_DATA: ChunkyState = 2;
pub const CHUNK_LF: ChunkyState = 1;
pub const CHUNK_HEX: ChunkyState = 0;
// #[derive(Copy, Clone)]

pub type connstate = crate::src::lib::http2::connstate;
pub type connect_t = u32;
pub const CONNECT_DONE: connect_t = 17;
pub const CONNECT_REQ_READ_MORE: connect_t = 16;
pub const CONNECT_REQ_READ: connect_t = 15;
pub const CONNECT_REQ_SENDING: connect_t = 14;
pub const CONNECT_REQ_SEND: connect_t = 13;
pub const CONNECT_RESOLVE_REMOTE: connect_t = 12;
pub const CONNECT_RESOLVED: connect_t = 11;
pub const CONNECT_RESOLVING: connect_t = 10;
pub const CONNECT_REQ_INIT: connect_t = 9;
pub const CONNECT_AUTH_READ: connect_t = 8;
pub const CONNECT_AUTH_SEND: connect_t = 7;
pub const CONNECT_AUTH_INIT: connect_t = 6;
pub const CONNECT_GSSAPI_INIT: connect_t = 5;
pub const CONNECT_SOCKS_READ: connect_t = 4;
pub const CONNECT_SOCKS_READ_INIT: connect_t = 3;
pub const CONNECT_SOCKS_SEND: connect_t = 2;
pub const CONNECT_SOCKS_INIT: connect_t = 1;
pub const CONNECT_INIT: connect_t = 0;
pub type curl_malloc_callback<'a1> = Option<unsafe extern "C"  fn(_: u64,) -> Option<&'a1 mut core::ffi::c_void>>;
pub type curl_strdup_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 i8>,) -> Option<&'a2 mut i8>>;
pub type curl_calloc_callback<'a1> = Option<unsafe extern "C"  fn(_: u64,_: u64,) -> Option<&'a1 mut core::ffi::c_void>>;
pub type alpnid = u32;
pub const ALPN_h3: alpnid = 32;
pub const ALPN_h2: alpnid = 16;
pub const ALPN_h1: alpnid = 8;
pub const ALPN_none: alpnid = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct althost {
    pub host: * mut i8,
    pub port: u16,
    pub alpnid: u32,
}
impl althost {
    pub const fn new() -> Self {
        althost {
        host: (0 as * mut i8),
        port: 0,
        alpnid: 0
        }
    }
}

impl std::default::Default for althost {
    fn default() -> Self { althost::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct altsvc {
    pub src: crate::src::lib::altsvc::althost,
    pub dst: crate::src::lib::altsvc::althost,
    pub expires: i64,
    pub persist: bool,
    pub prio: i32,
    pub node: crate::src::lib::http2::Curl_llist_element,
}
impl altsvc {
    pub const fn new() -> Self {
        altsvc {
        src: crate::src::lib::altsvc::althost::new(),
        dst: crate::src::lib::altsvc::althost::new(),
        expires: 0,
        persist: false,
        prio: 0,
        node: crate::src::lib::http2::Curl_llist_element::new()
        }
    }
}

impl std::default::Default for altsvc {
    fn default() -> Self { altsvc::new() }
}

unsafe extern "C" fn alpn2alpnid(mut name: * mut i8) -> u32 {
    if Curl_strcasecompare(name, b"h1\0" as *const u8 as *const i8) != 0 {
        return ALPN_h1;
    }
    if Curl_strcasecompare(name, b"h2\0" as *const u8 as *const i8) != 0 {
        return ALPN_h2;
    }
    if Curl_strcasecompare(name, b"h3\0" as *const u8 as *const i8) != 0 {
        return ALPN_h3;
    }
    return ALPN_none;
}
#[no_mangle]
pub extern "C" fn Curl_alpnid2str(mut id: u32) -> * const i8 {
    match id as u32 {
        8 => return b"h1\0" as *const u8 as *const i8,
        16 => return b"h2\0" as *const u8 as *const i8,
        32 => return b"h3\0" as *const u8 as *const i8,
        _ => return b"\0" as *const u8 as *const i8,
    };
}
unsafe extern "C" fn altsvc_free(mut as_0: * mut crate::src::lib::altsvc::altsvc) {
    Curl_cfree
        .expect("non-null function pointer")((*as_0).src.host as *mut libc::c_void);
    Curl_cfree
        .expect("non-null function pointer")((*as_0).dst.host as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(as_0 as *mut libc::c_void);
}
unsafe extern "C" fn altsvc_createid(
    mut srchost: * const i8,
    mut dsthost: * const i8,
    mut srcalpnid: u32,
    mut dstalpnid: u32,
    mut srcport: u32,
    mut dstport: u32,
) -> * mut crate::src::lib::altsvc::altsvc {
    let mut as_0: * mut crate::src::lib::altsvc::altsvc = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<altsvc>() as u64, 1 as i32 as size_t)
        as *mut altsvc;
    if as_0.is_null() {
        return 0 as *mut altsvc;
    }
    let mut fresh0 = &mut ((*as_0).src.host);
    *fresh0 = Curl_cstrdup.expect("non-null function pointer")(srchost);
    if !((*as_0).src.host).is_null() {
        let mut fresh1 = &mut ((*as_0).dst.host);
        *fresh1 = Curl_cstrdup.expect("non-null function pointer")(dsthost);
        if !((*as_0).dst.host).is_null() {
            (*as_0).src.alpnid = srcalpnid;
            (*as_0).dst.alpnid = dstalpnid;
            (*as_0).src.port = curlx_ultous(srcport as u64);
            (*as_0).dst.port = curlx_ultous(dstport as u64);
            return as_0;
        }
    }
    altsvc_free(as_0);
    return 0 as *mut altsvc;
}
unsafe extern "C" fn altsvc_create(
    mut srchost: * mut i8,
    mut dsthost: * mut i8,
    mut srcalpn: * mut i8,
    mut dstalpn: * mut i8,
    mut srcport: u32,
    mut dstport: u32,
) -> * mut crate::src::lib::altsvc::altsvc {
    let mut dstalpnid: u32 = alpn2alpnid(dstalpn);
    let mut srcalpnid: u32 = alpn2alpnid(srcalpn);
    if srcalpnid as u64 == 0 || dstalpnid as u64 == 0 {
        return 0 as *mut altsvc;
    }
    return altsvc_createid(srchost, dsthost, srcalpnid, dstalpnid, srcport, dstport);
}
unsafe extern "C" fn altsvc_add(
    mut asi: * mut crate::src::lib::altsvc::altsvcinfo,
    mut line: * mut i8,
) -> u32 {
    let mut srchost: [i8; 513] = [0; 513];
    let mut dsthost: [i8; 513] = [0; 513];
    let mut srcalpn: [i8; 11] = [0; 11];
    let mut dstalpn: [i8; 11] = [0; 11];
    let mut date: [i8; 65] = [0; 65];
    let mut srcport: u32 = 0;
    let mut dstport: u32 = 0;
    let mut prio: u32 = 0;
    let mut persist: u32 = 0;
    let mut rc: i32 = 0;
    rc = sscanf(
        line,
        b"%10s %512s %u %10s %512s %u \"%64[^\"]\" %u %u\0" as *const u8
            as *const i8,
        srcalpn.as_mut_ptr(),
        srchost.as_mut_ptr(),
        &mut srcport as *mut u32,
        dstalpn.as_mut_ptr(),
        dsthost.as_mut_ptr(),
        &mut dstport as *mut u32,
        date.as_mut_ptr(),
        &mut persist as *mut u32,
        &mut prio as *mut u32,
    );
    if 9 as i32 == rc {
        let mut as_0: * mut crate::src::lib::altsvc::altsvc = 0 as *mut altsvc;
        let mut expires: i64 = Curl_getdate_capped(date.as_mut_ptr());
        as_0 = altsvc_create(
            srchost.as_mut_ptr(),
            dsthost.as_mut_ptr(),
            srcalpn.as_mut_ptr(),
            dstalpn.as_mut_ptr(),
            srcport,
            dstport,
        );
        if !as_0.is_null() {
            (*as_0).expires = expires;
            (*as_0).prio = prio as i32;
            (*as_0)
                .persist = if persist != 0 { 1 as i32 } else { 0 as i32 }
                != 0;
            Curl_llist_insert_next(
                &mut (*asi).list,
                (*asi).list.tail,
                as_0 as *const libc::c_void,
                &mut (*as_0).node,
            );
        }
    }
    return CURLE_OK;
}
unsafe extern "C" fn altsvc_load(
    mut asi: * mut crate::src::lib::altsvc::altsvcinfo,
    mut file: * const i8,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut line: * mut i8 = 0 as *mut i8;
    let mut fp: * mut crate::src::lib::http2::_IO_FILE = 0 as *mut FILE;
    Curl_cfree.expect("non-null function pointer")((*asi).filename as *mut libc::c_void);
    let mut fresh2 = &mut ((*asi).filename);
    *fresh2 = Curl_cstrdup.expect("non-null function pointer")(file);
    if ((*asi).filename).is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    fp = fopen(file, b"r\0" as *const u8 as *const i8);
    if !fp.is_null() {
        line = Curl_cmalloc
            .expect("non-null function pointer")(4095 as i32 as size_t)
            as *mut i8;
        if line.is_null() {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*asi).filename as *mut libc::c_void);
            let mut fresh3 = &mut ((*asi).filename);
            *fresh3 = 0 as *mut i8;
            Curl_cfree.expect("non-null function pointer")(line as *mut libc::c_void);
            fclose(fp);
            return CURLE_OUT_OF_MEMORY;
        } else {
            while !(Curl_get_line(line, 4095 as i32, fp)).is_null() {
                let mut lineptr: * mut i8 = line;
                while *lineptr as i32 != 0
                    && (*lineptr as u8 as i32 == ' ' as i32
                        || *lineptr as u8 as i32 == '\t' as i32)
                {
                    lineptr = lineptr.offset(1);
                }
                if *lineptr as i32 == '#' as i32 {
                    continue;
                }
                altsvc_add(asi, lineptr);
            }
            Curl_cfree.expect("non-null function pointer")(line as *mut libc::c_void);
            fclose(fp);
        }
    }
    return result;
}
unsafe extern "C" fn altsvc_out(mut as_0: * mut crate::src::lib::altsvc::altsvc, mut fp: * mut crate::src::lib::http2::_IO_FILE) -> u32 {
    let mut stamp: crate::src::lib::altsvc::tm = tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: 0 as *const i8,
    };
    let mut result: u32 = Curl_gmtime((*as_0).expires, &mut stamp);
    if result as u64 != 0 {
        return result;
    }
    curl_mfprintf(
        fp,
        b"%s %s %u %s %s %u \"%d%02d%02d %02d:%02d:%02d\" %u %d\n\0" as *const u8
            as *const i8,
        Curl_alpnid2str((*as_0).src.alpnid),
        (*as_0).src.host,
        (*as_0).src.port as i32,
        Curl_alpnid2str((*as_0).dst.alpnid),
        (*as_0).dst.host,
        (*as_0).dst.port as i32,
        stamp.tm_year + 1900 as i32,
        stamp.tm_mon + 1 as i32,
        stamp.tm_mday,
        stamp.tm_hour,
        stamp.tm_min,
        stamp.tm_sec,
        (*as_0).persist as i32,
        (*as_0).prio,
    );
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_altsvc_init() -> * mut crate::src::lib::altsvc::altsvcinfo {
    let mut asi: * mut crate::src::lib::altsvc::altsvcinfo = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(
        ::std::mem::size_of::<altsvcinfo>() as u64,
        1 as i32 as size_t,
    ) as *mut altsvcinfo;
    if asi.is_null() {
        return 0 as *mut altsvcinfo;
    }
    Curl_llist_init(Some(&mut (*asi).list), None);
    (*asi)
        .flags = ((1 as i32) << 3 as i32
        | (1 as i32) << 4 as i32) as i64;
    return asi;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_altsvc_load(
    mut asi: * mut crate::src::lib::altsvc::altsvcinfo,
    mut file: * const i8,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    result = altsvc_load(asi, file);
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_altsvc_ctrl(
    mut asi: * mut crate::src::lib::altsvc::altsvcinfo,
    ctrl: i64,
) -> u32 {
    if ctrl == 0 {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    (*asi).flags = ctrl;
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_altsvc_cleanup<'a1>(mut altsvcp: Option<&'a1 mut * mut crate::src::lib::altsvc::altsvcinfo>) {
    let mut e: * mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut n: * mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
    if !(*(borrow_mut(&mut altsvcp)).unwrap()).is_null() {
        let mut altsvc: * mut crate::src::lib::altsvc::altsvcinfo = *(borrow_mut(&mut altsvcp)).unwrap();
        e = (*altsvc).list.head;
        while !e.is_null() {
            let mut as_0: * mut crate::src::lib::altsvc::altsvc = (*e).ptr as *mut altsvc;
            n = (*e).next;
            altsvc_free(as_0);
            e = n;
        }
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*altsvc).filename as *mut libc::c_void);
        Curl_cfree.expect("non-null function pointer")(altsvc as *mut libc::c_void);
        *(borrow_mut(&mut altsvcp)).unwrap() = 0 as *mut altsvcinfo;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_altsvc_save(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut altsvc: * mut crate::src::lib::altsvc::altsvcinfo,
    mut file: * const i8,
) -> u32 {
    let mut e: * mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut n: * mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut result: u32 = CURLE_OK;
    let mut out: * mut crate::src::lib::http2::_IO_FILE = 0 as *mut FILE;
    let mut tempstore: * mut i8 = 0 as *mut i8;
    let mut randsuffix: [u8; 9] = [0; 9];
    if altsvc.is_null() {
        return CURLE_OK;
    }
    if file.is_null() && !((*altsvc).filename).is_null() {
        file = (*altsvc).filename;
    }
    if (*altsvc).flags & ((1 as i32) << 2 as i32) as i64 != 0
        || file.is_null() || *file.offset(0 as i32 as isize) == 0
    {
        return CURLE_OK;
    }
    if Curl_rand_hex(
        data,
        randsuffix.as_mut_ptr(),
        ::std::mem::size_of::<[u8; 9]>() as u64,
    ) as u64 != 0
    {
        return CURLE_FAILED_INIT;
    }
    tempstore = curl_maprintf(
        b"%s.%s.tmp\0" as *const u8 as *const i8,
        file,
        randsuffix.as_mut_ptr(),
    );
    if tempstore.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    out = fopen(tempstore, b"w\0" as *const u8 as *const i8);
    if out.is_null() {
        result = CURLE_WRITE_ERROR;
    } else {
        fputs(
            b"# Your alt-svc cache. https://curl.se/docs/alt-svc.html\n# This file was generated by libcurl! Edit at your own risk.\n\0"
                as *const u8 as *const i8,
            out,
        );
        e = (*altsvc).list.head;
        while !e.is_null() {
            let mut as_0: * mut crate::src::lib::altsvc::altsvc = (*e).ptr as *mut altsvc;
            n = (*e).next;
            result = altsvc_out(as_0, out);
            if result as u64 != 0 {
                break;
            }
            e = n;
        }
        fclose(out);
        if result as u64 == 0 && Curl_rename(tempstore, file) != 0 {
            result = CURLE_WRITE_ERROR;
        }
        if result as u64 != 0 {
            unlink(tempstore);
        }
    }
    Curl_cfree.expect("non-null function pointer")(tempstore as *mut libc::c_void);
    return result;
}
unsafe extern "C" fn getalnum<'a1>(
    mut ptr: Option<&'a1 mut * const i8>,
    mut alpnbuf: * mut i8,
    mut buflen: u64,
) -> u32 {
    let mut len: u64 = 0;
    let mut protop: * const i8 = 0 as *const i8;
    let mut p: * const i8 = *(borrow(& ptr)).unwrap();
    while *p as i32 != 0
        && (*p as u8 as i32 == ' ' as i32
            || *p as u8 as i32 == '\t' as i32)
    {
        p = p.offset(1);
    }
    protop = p;
    while *p as i32 != 0
        && !(*p as u8 as i32 == ' ' as i32
            || *p as u8 as i32 == '\t' as i32)
        && *p as i32 != ';' as i32 && *p as i32 != '=' as i32
    {
        p = p.offset(1);
    }
    len = p.offset_from(protop) as i64 as size_t;
    *(borrow_mut(&mut ptr)).unwrap() = p;
    if len == 0 || len >= buflen {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    memcpy(alpnbuf as *mut libc::c_void, protop as *const libc::c_void, len);
    *alpnbuf.offset(len as isize) = 0 as i32 as i8;
    return CURLE_OK;
}
unsafe extern "C" fn altsvc_flush(
    mut asi: * mut crate::src::lib::altsvc::altsvcinfo,
    mut srcalpnid: u32,
    mut srchost: * const i8,
    mut srcport: u16,
) {
    let mut e: * mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut n: * mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
    e = (*asi).list.head;
    while !e.is_null() {
        let mut as_0: * mut crate::src::lib::altsvc::altsvc = (*e).ptr as *mut altsvc;
        n = (*e).next;
        if srcalpnid as u32 == (*as_0).src.alpnid as u32
            && srcport as i32 == (*as_0).src.port as i32
            && Curl_strcasecompare(srchost, (*as_0).src.host) != 0
        {
            Curl_llist_remove(&mut (*asi).list, e, 0 as *mut libc::c_void);
            altsvc_free(as_0);
        }
        e = n;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_altsvc_parse(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut asi: * mut crate::src::lib::altsvc::altsvcinfo,
    mut value: * const i8,
    mut srcalpnid: u32,
    mut srchost: * const i8,
    mut srcport: u16,
) -> u32 {
    let mut p: * const i8 = value;
    let mut len: u64 = 0;
    let mut namebuf: [i8; 512] = *core::intrinsics::transmute::<&'_ [u8; 512], &'_ mut [i8; 512]>(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut alpnbuf: [i8; 10] = *core::intrinsics::transmute::<&'_ [u8; 10], &'_ mut [i8; 10]>(b"\0\0\0\0\0\0\0\0\0\0");
    let mut as_0: * mut crate::src::lib::altsvc::altsvc = 0 as *mut altsvc;
    let mut dstport: u16 = srcport;
    let mut result: u32 = getalnum(
        Some(&mut p),
        alpnbuf.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 10]>() as u64,
    );
    if result as u64 != 0 {
        Curl_infof(
            data,
            b"Excessive alt-svc header, ignoring.\0" as *const u8 as *const i8,
        );
        return CURLE_OK;
    }
    altsvc_flush(asi, srcalpnid, srchost, srcport);
    if Curl_strcasecompare(
        alpnbuf.as_mut_ptr(),
        b"clear\0" as *const u8 as *const i8,
    ) != 0
    {
        return CURLE_OK;
    }
    while *p as i32 == '=' as i32 {
        let mut dstalpnid: u32 = alpn2alpnid(alpnbuf.as_mut_ptr());
        p = p.offset(1);
        if !(*p as i32 == '"' as i32) {
            break;
        }
        let mut dsthost: * const i8 = b"\0" as *const u8 as *const i8;
        let mut value_ptr: * const i8 = 0 as *const i8;
        let mut option: [i8; 32] = [0; 32];
        let mut num: u64 = 0;
        let mut end_ptr: * mut i8 = 0 as *mut i8;
        let mut quoted: bool = 0 as i32 != 0;
        let mut maxage: i64 = (24 as i32 * 3600 as i32) as time_t;
        let mut persist: bool = 0 as i32 != 0;
        p = p.offset(1);
        if *p as i32 != ':' as i32 {
            let mut hostp: * const i8 = p;
            while *p as i32 != 0
                && (Curl_isalnum(*p as u8 as i32) != 0
                    || *p as i32 == '.' as i32
                    || *p as i32 == '-' as i32)
            {
                p = p.offset(1);
            }
            len = p.offset_from(hostp) as i64 as size_t;
            if len == 0 || len >= 512 as i32 as u64 {
                Curl_infof(
                    data,
                    b"Excessive alt-svc host name, ignoring.\0" as *const u8
                        as *const i8,
                );
                dstalpnid = ALPN_none;
            } else {
                memcpy(
                    namebuf.as_mut_ptr() as *mut libc::c_void,
                    hostp as *const libc::c_void,
                    len,
                );
                namebuf[len as usize] = 0 as i32 as i8;
                dsthost = namebuf.as_mut_ptr();
            }
        } else {
            dsthost = srchost;
        }
        if *p as i32 == ':' as i32 {
            p = p.offset(1);
            let mut port: u64 = strtoul(p, &mut end_ptr, 10 as i32);
            if port
                > (32767 as i32 * 2 as i32 + 1 as i32)
                    as u64 || end_ptr == p as *mut i8
                || *end_ptr as i32 != '"' as i32
            {
                Curl_infof(
                    data,
                    b"Unknown alt-svc port number, ignoring.\0" as *const u8
                        as *const i8,
                );
                dstalpnid = ALPN_none;
            }
            p = end_ptr;
            dstport = curlx_ultous(port);
        }
        let mut fresh4 = p;
        p = p.offset(1);
        if *fresh4 as i32 != '"' as i32 {
            break;
        }
        loop {
            while *p as u8 as i32 == ' ' as i32
                || *p as u8 as i32 == '\t' as i32
            {
                p = p.offset(1);
            }
            if *p as i32 != ';' as i32 {
                break;
            }
            p = p.offset(1);
            if *p == 0
                || (*p as i32 == '\n' as i32 || *p as i32 == '\r' as i32)
            {
                break;
            }
            result = getalnum(
                Some(&mut p),
                option.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 32]>() as u64,
            );
            if result as u64 != 0 {
                option[0 as i32 as usize] = '\u{0}' as i32 as i8;
            }
            while *p as i32 != 0
                && (*p as u8 as i32 == ' ' as i32
                    || *p as u8 as i32 == '\t' as i32)
            {
                p = p.offset(1);
            }
            if *p as i32 != '=' as i32 {
                return CURLE_OK;
            }
            p = p.offset(1);
            while *p as i32 != 0
                && (*p as u8 as i32 == ' ' as i32
                    || *p as u8 as i32 == '\t' as i32)
            {
                p = p.offset(1);
            }
            if *p == 0 {
                return CURLE_OK;
            }
            if *p as i32 == '"' as i32 {
                p = p.offset(1);
                quoted = 1 as i32 != 0;
            }
            value_ptr = p;
            if quoted {
                while *p as i32 != 0 && *p as i32 != '"' as i32 {
                    p = p.offset(1);
                }
                let mut fresh5 = p;
                p = p.offset(1);
                if *fresh5 == 0 {
                    return CURLE_OK;
                }
            } else {
                while *p as i32 != 0
                    && !(*p as u8 as i32 == ' ' as i32
                        || *p as u8 as i32 == '\t' as i32)
                    && *p as i32 != ';' as i32 && *p as i32 != ',' as i32
                {
                    p = p.offset(1);
                }
            }
            num = strtoul(value_ptr, &mut end_ptr, 10 as i32);
            if end_ptr != value_ptr as *mut i8
                && num
                    < (9223372036854775807 as i64 as u64)
                        .wrapping_mul(2 as u64)
                        .wrapping_add(1 as u64)
            {
                if Curl_strcasecompare(
                    b"ma\0" as *const u8 as *const i8,
                    option.as_mut_ptr(),
                ) != 0
                {
                    maxage = num as time_t;
                } else if Curl_strcasecompare(
                        b"persist\0" as *const u8 as *const i8,
                        option.as_mut_ptr(),
                    ) != 0 && num == 1 as i32 as u64
                    {
                    persist = 1 as i32 != 0;
                }
            }
        }
        if dstalpnid as u64 != 0 {
            as_0 = altsvc_createid(
                srchost,
                dsthost,
                srcalpnid,
                dstalpnid,
                srcport as u32,
                dstport as u32,
            );
            if !as_0.is_null() {
                (*as_0).expires = maxage + time(0 as *mut time_t);
                (*as_0).persist = persist;
                Curl_llist_insert_next(
                    &mut (*asi).list,
                    (*asi).list.tail,
                    as_0 as *const libc::c_void,
                    &mut (*as_0).node,
                );
                Curl_infof(
                    data,
                    b"Added alt-svc: %s:%d over %s\0" as *const u8
                        as *const i8,
                    dsthost,
                    dstport as i32,
                    Curl_alpnid2str(dstalpnid),
                );
            }
        } else {
            Curl_infof(
                data,
                b"Unknown alt-svc protocol \"%s\", skipping.\0" as *const u8
                    as *const i8,
                alpnbuf.as_mut_ptr(),
            );
        }
        if *p as i32 == ',' as i32 {
            p = p.offset(1);
            result = getalnum(
                Some(&mut p),
                alpnbuf.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 10]>() as u64,
            );
            if result as u64 != 0 {
                break;
            }
        }
        if !(*p as i32 != 0 && *p as i32 != ';' as i32
            && *p as i32 != '\n' as i32 && *p as i32 != '\r' as i32)
        {
            break;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_altsvc_lookup<'a1>(
    mut asi: * mut crate::src::lib::altsvc::altsvcinfo,
    mut srcalpnid: u32,
    mut srchost: * const i8,
    mut srcport: i32,
    mut dstentry: Option<&'a1 mut * mut crate::src::lib::altsvc::altsvc>,
    versions: i32,
) -> bool {
    let mut e: * mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut n: * mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut now: i64 = time(0 as *mut time_t);
    e = (*asi).list.head;
    while !e.is_null() {
        let mut as_0: * mut crate::src::lib::altsvc::altsvc = (*e).ptr as *mut altsvc;
        n = (*e).next;
        if (*as_0).expires < now {
            Curl_llist_remove(&mut (*asi).list, e, 0 as *mut libc::c_void);
            altsvc_free(as_0);
        } else if (*as_0).src.alpnid as u32 == srcalpnid as u32
                && Curl_strcasecompare((*as_0).src.host, srchost) != 0
                && (*as_0).src.port as i32 == srcport
                && versions as u32 & (*as_0).dst.alpnid as u32 != 0
            {
            *(borrow_mut(&mut dstentry)).unwrap() = as_0;
            return 1 as i32 != 0;
        }
        e = n;
    }
    return 0 as i32 != 0;
}
use crate::laertes_rt::*;
