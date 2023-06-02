use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    pub type psl_ctx_st;
    
    
    
    
    
    
    
    
    
    fn sscanf(_: * const i8, _: * const i8, _: ...) -> i32;
    
    fn strlen(_: * const i8) -> u64;
    fn memcpy(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn strcspn(_: * const i8, _: * const i8) -> u64;
    fn strncmp(
        _: * const i8,
        _: * const i8,
        _: u64,
    ) -> i32;
    fn strspn(_: * const i8, _: * const i8) -> u64;
    fn strcpy(_: * mut i8, _: * const i8) -> * mut i8;
    fn __ctype_tolower_loc() -> * mut * const i32;
    
    
    fn __errno_location() -> * mut i32;
    fn strtoul(
        _: * const i8,
        _: * mut * mut i8,
        _: i32,
    ) -> u64;
    fn strtol(
        _: * const i8,
        _: * mut * mut i8,
        _: i32,
    ) -> i64;
    
    fn strchr(_: * const i8, _: i32) -> * mut i8;
    fn strcmp(_: * const i8, _: * const i8) -> i32;
    
    
    
    fn strstr(_: * const i8, _: * const i8) -> * mut i8;
    
    fn memset(
        _: * mut core::ffi::c_void,
        _: i32,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn strrchr(_: * const i8, _: i32) -> * mut i8;
    fn inet_pton(
        __af: i32,
        __cp: * const i8,
        __buf: * mut core::ffi::c_void,
    ) -> i32;
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::curl_ctype::Curl_isalnum;
pub use crate::src::lib::curl_ctype::Curl_iscntrl;
pub use crate::src::lib::curl_ctype::Curl_isdigit;
pub use crate::src::lib::curl_ctype::Curl_isgraph;
pub use crate::src::lib::curl_ctype::Curl_isspace;
pub use crate::src::lib::curl_ctype::Curl_isupper;
pub use crate::src::lib::curl_ctype::Curl_isxdigit;
pub use crate::src::lib::dotdot::Curl_dedotdotify;
pub use crate::src::lib::escape::Curl_isunreserved;
pub use crate::src::lib::escape::Curl_urldecode;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::strcase::curl_strnequal;
pub use crate::src::lib::url::Curl_builtin_scheme;
pub use crate::src::lib::url::Curl_parse_login_details;
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::easy::Curl_ccalloc;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_cstrdup;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_URL {
    pub scheme: * mut i8,
    pub user: * mut i8,
    pub password: * mut i8,
    pub options: * mut i8,
    pub host: * mut i8,
    pub zoneid: * mut i8,
    pub port: * mut i8,
    pub path: * mut i8,
    pub query: * mut i8,
    pub fragment: * mut i8,
    pub scratch: * mut i8,
    pub temppath: * mut i8,
    pub portnum: i64,
}
impl Curl_URL {
    pub const fn new() -> Self {
        Curl_URL {
        scheme: (0 as * mut i8),
        user: (0 as * mut i8),
        password: (0 as * mut i8),
        options: (0 as * mut i8),
        host: (0 as * mut i8),
        zoneid: (0 as * mut i8),
        port: (0 as * mut i8),
        path: (0 as * mut i8),
        query: (0 as * mut i8),
        fragment: (0 as * mut i8),
        scratch: (0 as * mut i8),
        temppath: (0 as * mut i8),
        portnum: 0
        }
    }
}

impl std::default::Default for Curl_URL {
    fn default() -> Self { Curl_URL::new() }
}

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
pub type urlreject = u32;
pub const REJECT_ZERO: urlreject = 4;
pub const REJECT_CTRL: urlreject = 3;
pub const REJECT_NADA: urlreject = 2;
#[inline]
unsafe extern "C" fn tolower(mut __c: i32) -> i32 {
    return if __c >= -(128 as i32) && __c < 256 as i32 {
        *(*__ctype_tolower_loc()).offset(__c as isize)
    } else {
        __c
    };
}
unsafe extern "C" fn free_urlhandle(mut u: * mut crate::src::lib::urlapi::Curl_URL) {
    Curl_cfree.expect("non-null function pointer")((*u).scheme as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*u).user as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*u).password as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*u).options as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*u).host as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*u).zoneid as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*u).port as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*u).path as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*u).query as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*u).fragment as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*u).scratch as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*u).temppath as *mut libc::c_void);
}
unsafe extern "C" fn mv_urlhandle(mut from: * mut crate::src::lib::urlapi::Curl_URL, mut to: * mut crate::src::lib::urlapi::Curl_URL) {
    free_urlhandle(to);
    *to = *from;
    Curl_cfree.expect("non-null function pointer")(from as *mut libc::c_void);
}
unsafe extern "C" fn find_host_sep(mut url: * const i8) -> * const i8 {
    let mut sep: * const i8 = 0 as *const i8;
    let mut query: * const i8 = 0 as *const i8;
    sep = strstr(url, b"//\0" as *const u8 as *const i8);
    if sep.is_null() {
        sep = url;
    } else {
        sep = sep.offset(2 as i32 as isize);
    }
    query = strchr(sep, '?' as i32);
    sep = strchr(sep, '/' as i32);
    if sep.is_null() {
        sep = url.offset(strlen(url) as isize);
    }
    if query.is_null() {
        query = url.offset(strlen(url) as isize);
    }
    return if sep < query { sep } else { query };
}
unsafe extern "C" fn urlchar_needs_escaping(mut c: i32) -> bool {
    return !(Curl_iscntrl(c as u8 as i32) != 0
        || Curl_isspace(c as u8 as i32) != 0
        || Curl_isgraph(c as u8 as i32) != 0);
}
unsafe extern "C" fn strlen_url(
    mut url: * const i8,
    mut relative: bool,
) -> u64 {
    let mut ptr: * const u8 = 0 as *const u8;
    let mut newlen: u64 = 0 as i32 as size_t;
    let mut left: bool = 1 as i32 != 0;
    let mut host_sep: * const u8 = url as *const u8;
    if !relative {
        host_sep = find_host_sep(url) as *const u8;
    }
    ptr = url as *mut u8;
    while *ptr != 0 {
        if ptr < host_sep {
            newlen = newlen.wrapping_add(1);
        } else {
            let mut current_block_10: u64;
            match *ptr as i32 {
                63 => {
                    left = 0 as i32 != 0;
                    current_block_10 = 8167214597936611784;
                }
                32 => {
                    if left {
                        newlen = (newlen as u64)
                            .wrapping_add(3 as i32 as u64) as size_t
                            as size_t;
                    } else {
                        newlen = newlen.wrapping_add(1);
                    }
                    current_block_10 = 8457315219000651999;
                }
                _ => {
                    current_block_10 = 8167214597936611784;
                }
            }
            match current_block_10 {
                8167214597936611784 => {
                    if urlchar_needs_escaping(*ptr as i32) {
                        newlen = (newlen as u64)
                            .wrapping_add(2 as i32 as u64) as size_t
                            as size_t;
                    }
                    newlen = newlen.wrapping_add(1);
                }
                _ => {}
            }
        }
        ptr = ptr.offset(1);
    }
    return newlen;
}
unsafe extern "C" fn strcpy_url(
    mut output: * mut i8,
    mut url: * const i8,
    mut relative: bool,
) {
    let mut left: bool = 1 as i32 != 0;
    let mut iptr: * const u8 = 0 as *const u8;
    let mut optr: * mut i8 = output;
    let mut host_sep: * const u8 = url as *const u8;
    if !relative {
        host_sep = find_host_sep(url) as *const u8;
    }
    iptr = url as *mut u8;
    while *iptr != 0 {
        if iptr < host_sep {
            let mut fresh0 = optr;
            optr = optr.offset(1);
            *fresh0 = *iptr as i8;
        } else {
            let mut current_block_15: u64;
            match *iptr as i32 {
                63 => {
                    left = 0 as i32 != 0;
                    current_block_15 = 11997719445127346396;
                }
                32 => {
                    if left {
                        let mut fresh2 = optr;
                        optr = optr.offset(1);
                        *fresh2 = '%' as i32 as i8;
                        let mut fresh3 = optr;
                        optr = optr.offset(1);
                        *fresh3 = '2' as i32 as i8;
                        let mut fresh4 = optr;
                        optr = optr.offset(1);
                        *fresh4 = '0' as i32 as i8;
                    } else {
                        let mut fresh5 = optr;
                        optr = optr.offset(1);
                        *fresh5 = '+' as i32 as i8;
                    }
                    current_block_15 = 11042950489265723346;
                }
                _ => {
                    current_block_15 = 11997719445127346396;
                }
            }
            match current_block_15 {
                11997719445127346396 => {
                    if urlchar_needs_escaping(*iptr as i32) {
                        curl_msnprintf(
                            optr,
                            4 as i32 as size_t,
                            b"%%%02x\0" as *const u8 as *const i8,
                            *iptr as i32,
                        );
                        optr = optr.offset(3 as i32 as isize);
                    } else {
                        let mut fresh1 = optr;
                        optr = optr.offset(1);
                        *fresh1 = *iptr as i8;
                    }
                }
                _ => {}
            }
        }
        iptr = iptr.offset(1);
    }
    *optr = 0 as i32 as i8;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_is_absolute_url(
    mut url: * const i8,
    mut buf: * mut i8,
    mut buflen: u64,
) -> bool {
    let mut i: u64 = 0;
    i = 0 as i32 as size_t;
    while i < buflen && *url.offset(i as isize) as i32 != 0 {
        let mut s: i8 = *url.offset(i as isize);
        if s as i32 == ':' as i32
            && *url.offset(i.wrapping_add(1 as i32 as u64) as isize)
                as i32 == '/' as i32
        {
            if !buf.is_null() {
                *buf.offset(i as isize) = 0 as i32 as i8;
            }
            return 1 as i32 != 0;
        } else {
            if !(Curl_isalnum(s as u8 as i32) != 0
                || s as i32 == '+' as i32 || s as i32 == '-' as i32
                || s as i32 == '.' as i32)
            {
                break;
            }
            if !buf.is_null() {
                *buf
                    .offset(
                        i as isize,
                    ) = ({
                    let mut __res: i32 = 0;
                    if ::std::mem::size_of::<i32>() as u64
                        > 1 as i32 as u64
                    {
                        if 0 != 0 {
                            let mut __c: i32 = s as u8 as i32;
                            __res = if __c < -(128 as i32)
                                || __c > 255 as i32
                            {
                                __c
                            } else {
                                *(*__ctype_tolower_loc()).offset(__c as isize)
                            };
                        } else {
                            __res = tolower(s as u8 as i32);
                        }
                    } else {
                        __res = *(*__ctype_tolower_loc())
                            .offset(s as u8 as i32 as isize);
                    }
                    __res
                }) as i8;
            }
            i = i.wrapping_add(1);
        }
    }
    return 0 as i32 != 0;
}
unsafe extern "C" fn concat_url(
    mut base: * const i8,
    mut relurl: * const i8,
) -> * mut i8 {
    let mut newest: * mut i8 = 0 as *mut i8;
    let mut protsep: * mut i8 = 0 as *mut i8;
    let mut pathsep: * mut i8 = 0 as *mut i8;
    let mut newlen: u64 = 0;
    let mut host_changed: bool = 0 as i32 != 0;
    let mut useurl: * const i8 = relurl;
    let mut urllen: u64 = 0;
    let mut url_clone: * mut i8 = Curl_cstrdup
        .expect("non-null function pointer")(base);
    if url_clone.is_null() {
        return 0 as *mut i8;
    }
    protsep = strstr(url_clone, b"//\0" as *const u8 as *const i8);
    if protsep.is_null() {
        protsep = url_clone;
    } else {
        protsep = protsep.offset(2 as i32 as isize);
    }
    if '/' as i32 != *relurl.offset(0 as i32 as isize) as i32 {
        let mut level: i32 = 0 as i32;
        pathsep = strchr(protsep, '?' as i32);
        if !pathsep.is_null() {
            *pathsep = 0 as i32 as i8;
        }
        if *useurl.offset(0 as i32 as isize) as i32 != '?' as i32 {
            pathsep = strrchr(protsep, '/' as i32);
            if !pathsep.is_null() {
                *pathsep = 0 as i32 as i8;
            }
        }
        pathsep = strchr(protsep, '/' as i32);
        if !pathsep.is_null() {
            protsep = pathsep.offset(1 as i32 as isize);
        } else {
            protsep = 0 as *mut i8;
        }
        if *useurl.offset(0 as i32 as isize) as i32 == '.' as i32
            && *useurl.offset(1 as i32 as isize) as i32 == '/' as i32
        {
            useurl = useurl.offset(2 as i32 as isize);
        }
        while *useurl.offset(0 as i32 as isize) as i32 == '.' as i32
            && *useurl.offset(1 as i32 as isize) as i32 == '.' as i32
            && *useurl.offset(2 as i32 as isize) as i32 == '/' as i32
        {
            level += 1;
            useurl = useurl.offset(3 as i32 as isize);
        }
        if !protsep.is_null() {
            loop {
                let mut fresh6 = level;
                level = level - 1;
                if !(fresh6 != 0) {
                    break;
                }
                pathsep = strrchr(protsep, '/' as i32);
                if !pathsep.is_null() {
                    *pathsep = 0 as i32 as i8;
                } else {
                    *protsep = 0 as i32 as i8;
                    break;
                }
            }
        }
    } else if *relurl.offset(1 as i32 as isize) as i32 == '/' as i32 {
        *protsep = 0 as i32 as i8;
        useurl = &*relurl.offset(2 as i32 as isize) as *const i8;
        host_changed = 1 as i32 != 0;
    } else {
        pathsep = strchr(protsep, '/' as i32);
        if !pathsep.is_null() {
            let mut sep: * mut i8 = strchr(protsep, '?' as i32);
            if !sep.is_null() && sep < pathsep {
                pathsep = sep;
            }
            *pathsep = 0 as i32 as i8;
        } else {
            pathsep = strchr(protsep, '?' as i32);
            if !pathsep.is_null() {
                *pathsep = 0 as i32 as i8;
            }
        }
    }
    newlen = strlen_url(useurl, !host_changed);
    urllen = strlen(url_clone);
    newest = Curl_cmalloc
        .expect(
            "non-null function pointer",
        )(
        urllen
            .wrapping_add(1 as i32 as u64)
            .wrapping_add(newlen)
            .wrapping_add(1 as i32 as u64),
    ) as *mut i8;
    if newest.is_null() {
        Curl_cfree.expect("non-null function pointer")(url_clone as *mut libc::c_void);
        return 0 as *mut i8;
    }
    memcpy(newest as *mut libc::c_void, url_clone as *const libc::c_void, urllen);
    if !('/' as i32 == *useurl.offset(0 as i32 as isize) as i32
        || !protsep.is_null() && *protsep == 0
        || '?' as i32 == *useurl.offset(0 as i32 as isize) as i32)
    {
        let mut fresh7 = urllen;
        urllen = urllen.wrapping_add(1);
        *newest.offset(fresh7 as isize) = '/' as i32 as i8;
    }
    strcpy_url(&mut *newest.offset(urllen as isize), useurl, !host_changed);
    Curl_cfree.expect("non-null function pointer")(url_clone as *mut libc::c_void);
    return newest;
}
unsafe extern "C" fn parse_hostname_login<'a1>(
    mut u: * mut crate::src::lib::urlapi::Curl_URL,
    mut hostname: Option<&'a1 mut * mut i8>,
    mut flags: u32,
) -> u32 {
    let mut current_block: u64;
    let mut result: u32 = CURLUE_OK;
    let mut ccode: u32 = CURLE_OK;
    let mut userp: * mut i8 = 0 as *mut i8;
    let mut passwdp: * mut i8 = 0 as *mut i8;
    let mut optionsp: * mut i8 = 0 as *mut i8;
    let mut h: * const crate::src::lib::http2::Curl_handler = 0 as *const Curl_handler;
    let mut ptr: * mut i8 = strchr(*(borrow(& hostname)).unwrap(), '@' as i32);
    let mut login: * mut i8 = *(borrow_mut(&mut hostname)).unwrap();
    if !ptr.is_null() {
        ptr = ptr.offset(1);
        *(borrow_mut(&mut hostname)).unwrap() = ptr;
        if !((*u).scheme).is_null() {
            h = Curl_builtin_scheme((*u).scheme);
        }
        ccode = Curl_parse_login_details(
            login,
            (ptr.offset_from(login) as i64 - 1 as i32 as i64)
                as size_t,
            Some(&mut userp),
            Some(&mut passwdp),
            if !h.is_null()
                && (*h).flags & ((1 as i32) << 10 as i32) as u32
                    != 0
            {
                &mut optionsp
            } else {
                0 as *mut *mut i8
            },
        );
        if ccode as u64 != 0 {
            result = CURLUE_MALFORMED_INPUT;
        } else {
            if !userp.is_null() {
                if flags & ((1 as i32) << 5 as i32) as u32 != 0
                {
                    result = CURLUE_USER_NOT_ALLOWED;
                    current_block = 3551955217870244501;
                } else {
                    let mut fresh8 = &mut ((*u).user);
                    *fresh8 = userp;
                    current_block = 5143058163439228106;
                }
            } else {
                current_block = 5143058163439228106;
            }
            match current_block {
                3551955217870244501 => {}
                _ => {
                    if !passwdp.is_null() {
                        let mut fresh9 = &mut ((*u).password);
                        *fresh9 = passwdp;
                    }
                    if !optionsp.is_null() {
                        let mut fresh10 = &mut ((*u).options);
                        *fresh10 = optionsp;
                    }
                    return CURLUE_OK;
                }
            }
        }
    }
    Curl_cfree.expect("non-null function pointer")(userp as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(passwdp as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(optionsp as *mut libc::c_void);
    return result;
}
unsafe extern "C" fn Curl_parse_port(
    mut u: * mut crate::src::lib::urlapi::Curl_URL,
    mut hostname: * mut i8,
    mut has_scheme: bool,
) -> u32 {
    let mut portptr: * mut i8 = 0 as *mut i8;
    let mut endbracket: i8 = 0;
    let mut len: i32 = 0;
    if 1 as i32
        == sscanf(
            hostname,
            b"[%*45[0123456789abcdefABCDEF:.]%c%n\0" as *const u8 as *const i8,
            &mut endbracket as *mut i8,
            &mut len as *mut i32,
        )
    {
        if ']' as i32 == endbracket as i32 {
            portptr = &mut *hostname.offset(len as isize) as *mut i8;
        } else if '%' as i32 == endbracket as i32 {
            let mut zonelen: i32 = len;
            if 1 as i32
                == sscanf(
                    hostname.offset(zonelen as isize),
                    b"%*[^]]%c%n\0" as *const u8 as *const i8,
                    &mut endbracket as *mut i8,
                    &mut len as *mut i32,
                )
            {
                if ']' as i32 != endbracket as i32 {
                    return CURLUE_MALFORMED_INPUT;
                }
                zonelen -= 1;
                portptr = &mut *hostname
                    .offset((zonelen + len + 1 as i32) as isize)
                    as *mut i8;
            } else {
                return CURLUE_MALFORMED_INPUT
            }
        } else {
            return CURLUE_MALFORMED_INPUT
        }
        if !portptr.is_null() && *portptr as i32 != 0 {
            if *portptr as i32 != ':' as i32 {
                return CURLUE_MALFORMED_INPUT;
            }
        } else {
            portptr = 0 as *mut i8;
        }
    } else {
        portptr = strchr(hostname, ':' as i32);
    }
    if !portptr.is_null() {
        let mut rest: * mut i8 = 0 as *mut i8;
        let mut port: i64 = 0;
        let mut portbuf: [i8; 7] = [0; 7];
        if *portptr.offset(1 as i32 as isize) == 0 {
            *portptr = '\u{0}' as i32 as i8;
            return (if has_scheme as i32 != 0 {
                CURLUE_OK as i32
            } else {
                CURLUE_BAD_PORT_NUMBER as i32
            }) as CURLUcode;
        }
        if Curl_isdigit(
            *portptr.offset(1 as i32 as isize) as u8 as i32,
        ) == 0
        {
            return CURLUE_BAD_PORT_NUMBER;
        }
        port = strtol(
            portptr.offset(1 as i32 as isize),
            &mut rest,
            10 as i32,
        );
        if port <= 0 as i32 as i64
            || port > 0xffff as i32 as i64
        {
            return CURLUE_BAD_PORT_NUMBER;
        }
        if *rest.offset(0 as i32 as isize) != 0 {
            return CURLUE_BAD_PORT_NUMBER;
        }
        let mut fresh11 = portptr;
        portptr = portptr.offset(1);
        *fresh11 = '\u{0}' as i32 as i8;
        *rest = 0 as i32 as i8;
        curl_msnprintf(
            portbuf.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 7]>() as u64,
            b"%ld\0" as *const u8 as *const i8,
            port,
        );
        (*u).portnum = port;
        let mut fresh12 = &mut ((*u).port);
        *fresh12 = Curl_cstrdup
            .expect("non-null function pointer")(portbuf.as_mut_ptr());
        if ((*u).port).is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
    }
    return CURLUE_OK;
}
unsafe extern "C" fn junkscan(
    mut part: * const i8,
    mut flags: u32,
) -> bool {
    if !part.is_null() {
        static mut badbytes: [i8; 33] = [
            0x1 as i32 as i8,
            0x2 as i32 as i8,
            0x3 as i32 as i8,
            0x4 as i32 as i8,
            0x5 as i32 as i8,
            0x6 as i32 as i8,
            0x7 as i32 as i8,
            0x8 as i32 as i8,
            0x9 as i32 as i8,
            0xa as i32 as i8,
            0xb as i32 as i8,
            0xc as i32 as i8,
            0xd as i32 as i8,
            0xe as i32 as i8,
            0xf as i32 as i8,
            0x10 as i32 as i8,
            0x11 as i32 as i8,
            0x12 as i32 as i8,
            0x13 as i32 as i8,
            0x14 as i32 as i8,
            0x15 as i32 as i8,
            0x16 as i32 as i8,
            0x17 as i32 as i8,
            0x18 as i32 as i8,
            0x19 as i32 as i8,
            0x1a as i32 as i8,
            0x1b as i32 as i8,
            0x1c as i32 as i8,
            0x1d as i32 as i8,
            0x1e as i32 as i8,
            0x1f as i32 as i8,
            0x7f as i32 as i8,
            0 as i32 as i8,
        ];
        let mut n: u64 = strlen(part);
        let mut nfine: u64 = strcspn(part, badbytes.as_ptr());
        if nfine != n {
            return 1 as i32 != 0;
        }
        if flags & ((1 as i32) << 11 as i32) as u32 == 0
            && !(strchr(part, ' ' as i32)).is_null()
        {
            return 1 as i32 != 0;
        }
    }
    return 0 as i32 != 0;
}
unsafe extern "C" fn hostname_check(
    mut u: * mut crate::src::lib::urlapi::Curl_URL,
    mut hostname: * mut i8,
) -> u32 {
    let mut len: u64 = 0;
    let mut hlen: u64 = strlen(hostname);
    if *hostname.offset(0 as i32 as isize) as i32 == '[' as i32 {
        let mut dest: [i8; 16] = [0; 16];
        let mut l: * const i8 = b"0123456789abcdefABCDEF:.\0" as *const u8
            as *const i8;
        if hlen < 4 as i32 as u64 {
            return CURLUE_MALFORMED_INPUT;
        }
        hostname = hostname.offset(1);
        hlen = (hlen as u64).wrapping_sub(2 as i32 as u64)
            as size_t as size_t;
        if *hostname.offset(hlen as isize) as i32 != ']' as i32 {
            return CURLUE_MALFORMED_INPUT;
        }
        len = strspn(hostname, l);
        if hlen != len {
            hlen = len;
            if *hostname.offset(len as isize) as i32 == '%' as i32 {
                let mut zoneid: [i8; 16] = [0; 16];
                let mut i: i32 = 0 as i32;
                let mut h: * mut i8 = &mut *hostname
                    .offset(len.wrapping_add(1 as i32 as u64) as isize)
                    as *mut i8;
                if strncmp(
                    h,
                    b"25\0" as *const u8 as *const i8,
                    2 as i32 as u64,
                ) == 0 && *h.offset(2 as i32 as isize) as i32 != 0
                    && *h.offset(2 as i32 as isize) as i32 != ']' as i32
                {
                    h = h.offset(2 as i32 as isize);
                }
                while *h as i32 != 0 && *h as i32 != ']' as i32
                    && i < 15 as i32
                {
                    let mut fresh13 = h;
                    h = h.offset(1);
                    let mut fresh14 = i;
                    i = i + 1;
                    zoneid[fresh14 as usize] = *fresh13;
                }
                if i == 0 || ']' as i32 != *h as i32 {
                    return CURLUE_MALFORMED_INPUT;
                }
                zoneid[i as usize] = 0 as i32 as i8;
                let mut fresh15 = &mut ((*u).zoneid);
                *fresh15 = Curl_cstrdup
                    .expect("non-null function pointer")(zoneid.as_mut_ptr());
                if ((*u).zoneid).is_null() {
                    return CURLUE_OUT_OF_MEMORY;
                }
                *hostname.offset(len as isize) = ']' as i32 as i8;
                *hostname
                    .offset(
                        len.wrapping_add(1 as i32 as u64) as isize,
                    ) = 0 as i32 as i8;
            } else {
                return CURLUE_MALFORMED_INPUT
            }
        }
        *hostname.offset(hlen as isize) = 0 as i32 as i8;
        if 1 as i32
            != inet_pton(
                10 as i32,
                hostname,
                dest.as_mut_ptr() as *mut libc::c_void,
            )
        {
            return CURLUE_MALFORMED_INPUT;
        }
        *hostname.offset(hlen as isize) = ']' as i32 as i8;
    } else {
        len = strcspn(hostname, b" \0" as *const u8 as *const i8);
        if hlen != len {
            return CURLUE_MALFORMED_INPUT;
        }
    }
    if *hostname.offset(0 as i32 as isize) == 0 {
        return CURLUE_NO_HOST;
    }
    return CURLUE_OK;
}
unsafe extern "C" fn ipv4_normalize(
    mut hostname: * const i8,
    mut outp: * mut i8,
    mut olen: u64,
) -> bool {
    let mut done: bool = 0 as i32 != 0;
    let mut n: i32 = 0 as i32;
    let mut c: * const i8 = hostname;
    let mut parts: [u64; 4] = [
        0 as i32 as u64,
        0 as i32 as u64,
        0 as i32 as u64,
        0 as i32 as u64,
    ];
    while !done {
        let mut endp: * mut i8 = 0 as *mut i8;
        let mut l: u64 = 0;
        if (*c as i32) < '0' as i32 || *c as i32 > '9' as i32 {
            return 0 as i32 != 0;
        }
        l = strtoul(c, &mut endp, 0 as i32);
        if l
            == (9223372036854775807 as i64 as u64)
                .wrapping_mul(2 as u64)
                .wrapping_add(1 as u64)
            && *__errno_location() == 34 as i32 || endp == c as *mut i8
        {
            return 0 as i32 != 0;
        }
        if l
            > (2147483647 as i32 as u32)
                .wrapping_mul(2 as u32)
                .wrapping_add(1 as u32) as u64
        {
            return 0 as i32 != 0;
        }
        parts[n as usize] = l;
        c = endp;
        match *c as i32 {
            46 => {
                if n == 3 as i32 {
                    return 0 as i32 != 0;
                }
                n += 1;
                c = c.offset(1);
            }
            0 => {
                done = 1 as i32 != 0;
            }
            _ => return 0 as i32 != 0,
        }
    }
    match n {
        0 => {
            curl_msnprintf(
                outp,
                olen,
                b"%u.%u.%u.%u\0" as *const u8 as *const i8,
                parts[0 as i32 as usize] >> 24 as i32,
                parts[0 as i32 as usize] >> 16 as i32
                    & 0xff as i32 as u64,
                parts[0 as i32 as usize] >> 8 as i32
                    & 0xff as i32 as u64,
                parts[0 as i32 as usize] & 0xff as i32 as u64,
            );
        }
        1 => {
            if parts[0 as i32 as usize] > 0xff as i32 as u64
                || parts[1 as i32 as usize]
                    > 0xffffff as i32 as u64
            {
                return 0 as i32 != 0;
            }
            curl_msnprintf(
                outp,
                olen,
                b"%u.%u.%u.%u\0" as *const u8 as *const i8,
                parts[0 as i32 as usize],
                parts[1 as i32 as usize] >> 16 as i32
                    & 0xff as i32 as u64,
                parts[1 as i32 as usize] >> 8 as i32
                    & 0xff as i32 as u64,
                parts[1 as i32 as usize] & 0xff as i32 as u64,
            );
        }
        2 => {
            if parts[0 as i32 as usize] > 0xff as i32 as u64
                || parts[1 as i32 as usize]
                    > 0xff as i32 as u64
                || parts[2 as i32 as usize]
                    > 0xffff as i32 as u64
            {
                return 0 as i32 != 0;
            }
            curl_msnprintf(
                outp,
                olen,
                b"%u.%u.%u.%u\0" as *const u8 as *const i8,
                parts[0 as i32 as usize],
                parts[1 as i32 as usize],
                parts[2 as i32 as usize] >> 8 as i32
                    & 0xff as i32 as u64,
                parts[2 as i32 as usize] & 0xff as i32 as u64,
            );
        }
        3 => {
            if parts[0 as i32 as usize] > 0xff as i32 as u64
                || parts[1 as i32 as usize]
                    > 0xff as i32 as u64
                || parts[2 as i32 as usize]
                    > 0xff as i32 as u64
                || parts[3 as i32 as usize]
                    > 0xff as i32 as u64
            {
                return 0 as i32 != 0;
            }
            curl_msnprintf(
                outp,
                olen,
                b"%u.%u.%u.%u\0" as *const u8 as *const i8,
                parts[0 as i32 as usize],
                parts[1 as i32 as usize],
                parts[2 as i32 as usize],
                parts[3 as i32 as usize],
            );
        }
        _ => {}
    }
    return 1 as i32 != 0;
}
unsafe extern "C" fn seturl(
    mut url: * const i8,
    mut u: * mut crate::src::lib::urlapi::Curl_URL,
    mut flags: u32,
) -> u32 {
    let mut path: * mut i8 = 0 as *mut i8;
    let mut path_alloced: bool = 0 as i32 != 0;
    let mut hostname: * mut i8 = 0 as *mut i8;
    let mut query: * mut i8 = 0 as *mut i8;
    let mut fragment: * mut i8 = 0 as *mut i8;
    let mut result: u32 = CURLUE_OK;
    let mut url_has_scheme: bool = 0 as i32 != 0;
    let mut schemebuf: [i8; 41] = [0; 41];
    let mut schemep: * const i8 = 0 as *const i8;
    let mut schemelen: u64 = 0 as i32 as size_t;
    let mut urllen: u64 = 0;
    urllen = strlen(url);
    if urllen > 8000000 as i32 as u64 {
        return CURLUE_MALFORMED_INPUT;
    }
    let mut fresh16 = &mut ((*u).scratch);
    *fresh16 = Curl_cmalloc
        .expect(
            "non-null function pointer",
        )(
        urllen
            .wrapping_mul(2 as i32 as u64)
            .wrapping_add(2 as i32 as u64),
    ) as *mut i8;
    path = *fresh16;
    if path.is_null() {
        return CURLUE_OUT_OF_MEMORY;
    }
    hostname = &mut *path
        .offset(urllen.wrapping_add(1 as i32 as u64) as isize)
        as *mut i8;
    *hostname.offset(0 as i32 as isize) = 0 as i32 as i8;
    if Curl_is_absolute_url(
        url,
        schemebuf.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 41]>() as u64,
    ) {
        url_has_scheme = 1 as i32 != 0;
        schemelen = strlen(schemebuf.as_mut_ptr());
    }
    if url_has_scheme as i32 != 0
        && Curl_strcasecompare(
            schemebuf.as_mut_ptr(),
            b"file\0" as *const u8 as *const i8,
        ) != 0
    {
        strcpy(path, &*url.offset(5 as i32 as isize));
        hostname = 0 as *mut i8;
        let mut fresh17 = &mut ((*u).scheme);
        *fresh17 = Curl_cstrdup
            .expect(
                "non-null function pointer",
            )(b"file\0" as *const u8 as *const i8);
        if ((*u).scheme).is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
        if *path.offset(0 as i32 as isize) as i32 == '/' as i32
            && *path.offset(1 as i32 as isize) as i32 == '/' as i32
        {
            let mut ptr: * mut i8 = &mut *path.offset(2 as i32 as isize)
                as *mut i8;
            if *ptr.offset(0 as i32 as isize) as i32 != '/' as i32
                && !(('a' as i32 <= *ptr.offset(0 as i32 as isize) as i32
                    && *ptr.offset(0 as i32 as isize) as i32
                        <= 'z' as i32
                    || 'A' as i32
                        <= *ptr.offset(0 as i32 as isize) as i32
                        && *ptr.offset(0 as i32 as isize) as i32
                            <= 'Z' as i32)
                    && (*ptr.offset(1 as i32 as isize) as i32
                        == ':' as i32
                        || *ptr.offset(1 as i32 as isize) as i32
                            == '|' as i32)
                    && (*ptr.offset(2 as i32 as isize) as i32
                        == '/' as i32
                        || *ptr.offset(2 as i32 as isize) as i32
                            == '\\' as i32
                        || *ptr.offset(2 as i32 as isize) as i32
                            == 0 as i32))
            {
                if curl_strnequal(
                    b"localhost/\0" as *const u8 as *const i8,
                    ptr,
                    strlen(b"localhost/\0" as *const u8 as *const i8),
                ) == 0
                    && curl_strnequal(
                        b"127.0.0.1/\0" as *const u8 as *const i8,
                        ptr,
                        strlen(b"127.0.0.1/\0" as *const u8 as *const i8),
                    ) == 0
                {
                    return CURLUE_MALFORMED_INPUT;
                }
                ptr = ptr.offset(9 as i32 as isize);
            }
            path = ptr;
        }
        if '/' as i32 == *path.offset(0 as i32 as isize) as i32
            && (('a' as i32
                <= *(&mut *path.offset(1 as i32 as isize) as *mut i8)
                    .offset(0 as i32 as isize) as i32
                && *(&mut *path.offset(1 as i32 as isize) as *mut i8)
                    .offset(0 as i32 as isize) as i32 <= 'z' as i32
                || 'A' as i32
                    <= *(&mut *path.offset(1 as i32 as isize)
                        as *mut i8)
                        .offset(0 as i32 as isize) as i32
                    && *(&mut *path.offset(1 as i32 as isize)
                        as *mut i8)
                        .offset(0 as i32 as isize) as i32 <= 'Z' as i32)
                && (*(&mut *path.offset(1 as i32 as isize) as *mut i8)
                    .offset(1 as i32 as isize) as i32 == ':' as i32
                    || *(&mut *path.offset(1 as i32 as isize)
                        as *mut i8)
                        .offset(1 as i32 as isize) as i32 == '|' as i32)
                && (*(&mut *path.offset(1 as i32 as isize) as *mut i8)
                    .offset(2 as i32 as isize) as i32 == '/' as i32
                    || *(&mut *path.offset(1 as i32 as isize)
                        as *mut i8)
                        .offset(2 as i32 as isize) as i32 == '\\' as i32
                    || *(&mut *path.offset(1 as i32 as isize)
                        as *mut i8)
                        .offset(2 as i32 as isize) as i32
                        == 0 as i32))
            || ('a' as i32 <= *path.offset(0 as i32 as isize) as i32
                && *path.offset(0 as i32 as isize) as i32 <= 'z' as i32
                || 'A' as i32 <= *path.offset(0 as i32 as isize) as i32
                    && *path.offset(0 as i32 as isize) as i32
                        <= 'Z' as i32)
                && (*path.offset(1 as i32 as isize) as i32 == ':' as i32
                    || *path.offset(1 as i32 as isize) as i32
                        == '|' as i32)
                && (*path.offset(2 as i32 as isize) as i32 == '/' as i32
                    || *path.offset(2 as i32 as isize) as i32
                        == '\\' as i32
                    || *path.offset(2 as i32 as isize) as i32
                        == 0 as i32)
        {
            return CURLUE_MALFORMED_INPUT;
        }
    } else {
        let mut p: * const i8 = 0 as *const i8;
        let mut hostp: * const i8 = 0 as *const i8;
        let mut len: u64 = 0;
        *path.offset(0 as i32 as isize) = 0 as i32 as i8;
        if url_has_scheme {
            let mut i: i32 = 0 as i32;
            p = &*url
                .offset(
                    schemelen.wrapping_add(1 as i32 as u64) as isize,
                ) as *const i8;
            while !p.is_null() && *p as i32 == '/' as i32 && i < 4 as i32
            {
                p = p.offset(1);
                i += 1;
            }
            if i < 1 as i32 || i > 3 as i32 {
                return CURLUE_MALFORMED_INPUT;
            }
            schemep = schemebuf.as_mut_ptr();
            if (Curl_builtin_scheme(schemep)).is_null()
                && flags & ((1 as i32) << 3 as i32) as u32 == 0
            {
                return CURLUE_UNSUPPORTED_SCHEME;
            }
            if junkscan(schemep, flags) {
                return CURLUE_MALFORMED_INPUT;
            }
        } else {
            if flags
                & ((1 as i32) << 2 as i32
                    | (1 as i32) << 9 as i32) as u32 == 0
            {
                return CURLUE_MALFORMED_INPUT;
            }
            if flags & ((1 as i32) << 2 as i32) as u32 != 0 {
                schemep = b"https\0" as *const u8 as *const i8;
            }
            p = url;
        }
        hostp = p;
        while *p as i32 != 0
            && !(*p as i32 == '/' as i32 || *p as i32 == '?' as i32
                || *p as i32 == '#' as i32)
        {
            p = p.offset(1);
        }
        len = p.offset_from(hostp) as i64 as size_t;
        if len != 0 {
            memcpy(hostname as *mut libc::c_void, hostp as *const libc::c_void, len);
            *hostname.offset(len as isize) = 0 as i32 as i8;
        } else if flags & ((1 as i32) << 10 as i32) as u32 == 0
            {
            return CURLUE_MALFORMED_INPUT
        }
        len = strlen(p);
        memcpy(path as *mut libc::c_void, p as *const libc::c_void, len);
        *path.offset(len as isize) = 0 as i32 as i8;
        if !schemep.is_null() {
            let mut fresh18 = &mut ((*u).scheme);
            *fresh18 = Curl_cstrdup.expect("non-null function pointer")(schemep);
            if ((*u).scheme).is_null() {
                return CURLUE_OUT_OF_MEMORY;
            }
        }
    }
    if junkscan(path, flags) {
        return CURLUE_MALFORMED_INPUT;
    }
    if flags & ((1 as i32) << 7 as i32) as u32 != 0
        && *path.offset(0 as i32 as isize) as i32 != 0
    {
        let mut newp: * mut i8 = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )((strlen(path)).wrapping_mul(3 as i32 as u64))
            as *mut i8;
        if newp.is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
        path_alloced = 1 as i32 != 0;
        strcpy_url(newp, path, 1 as i32 != 0);
        path = newp;
        let mut fresh19 = &mut ((*u).temppath);
        *fresh19 = path;
    }
    fragment = strchr(path, '#' as i32);
    if !fragment.is_null() {
        let mut fresh20 = fragment;
        fragment = fragment.offset(1);
        *fresh20 = 0 as i32 as i8;
        if *fragment.offset(0 as i32 as isize) != 0 {
            let mut fresh21 = &mut ((*u).fragment);
            *fresh21 = Curl_cstrdup.expect("non-null function pointer")(fragment);
            if ((*u).fragment).is_null() {
                return CURLUE_OUT_OF_MEMORY;
            }
        }
    }
    query = strchr(path, '?' as i32);
    if !query.is_null() {
        let mut fresh22 = query;
        query = query.offset(1);
        *fresh22 = 0 as i32 as i8;
        let mut fresh23 = &mut ((*u).query);
        *fresh23 = Curl_cstrdup.expect("non-null function pointer")(query);
        if ((*u).query).is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
    }
    if *path.offset(0 as i32 as isize) == 0 {
        path = 0 as *mut i8;
    } else {
        if flags & ((1 as i32) << 4 as i32) as u32 == 0 {
            let mut newp_0: * mut i8 = Curl_dedotdotify(path);
            if newp_0.is_null() {
                return CURLUE_OUT_OF_MEMORY;
            }
            if strcmp(newp_0, path) != 0 {
                if path_alloced {
                    Curl_cfree
                        .expect(
                            "non-null function pointer",
                        )((*u).temppath as *mut libc::c_void);
                    let mut fresh24 = &mut ((*u).temppath);
                    *fresh24 = 0 as *mut i8;
                }
                path = newp_0;
                let mut fresh25 = &mut ((*u).temppath);
                *fresh25 = path;
                path_alloced = 1 as i32 != 0;
            } else {
                Curl_cfree
                    .expect("non-null function pointer")(newp_0 as *mut libc::c_void);
            }
        }
        let mut fresh26 = &mut ((*u).path);
        *fresh26 = if path_alloced as i32 != 0 {
            path
        } else {
            Curl_cstrdup.expect("non-null function pointer")(path)
        };
        if ((*u).path).is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
        let mut fresh27 = &mut ((*u).temppath);
        *fresh27 = 0 as *mut i8;
    }
    if !hostname.is_null() {
        let mut normalized_ipv4: [i8; 17] = [0; 17];
        if junkscan(hostname, flags) {
            return CURLUE_MALFORMED_INPUT;
        }
        result = parse_hostname_login(u, Some(&mut hostname), flags);
        if result as u64 != 0 {
            return result;
        }
        result = Curl_parse_port(u, hostname, url_has_scheme);
        if result as u64 != 0 {
            return result;
        }
        if !(0 as i32 as u64 == strlen(hostname)
            && flags & ((1 as i32) << 10 as i32) as u32 != 0)
        {
            result = hostname_check(u, hostname);
            if result as u64 != 0 {
                return result;
            }
        }
        if ipv4_normalize(
            hostname,
            normalized_ipv4.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 17]>() as u64,
        ) {
            let mut fresh28 = &mut ((*u).host);
            *fresh28 = Curl_cstrdup
                .expect("non-null function pointer")(normalized_ipv4.as_mut_ptr());
        } else {
            let mut fresh29 = &mut ((*u).host);
            *fresh29 = Curl_cstrdup.expect("non-null function pointer")(hostname);
        }
        if ((*u).host).is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
        if flags & ((1 as i32) << 9 as i32) as u32 != 0
            && schemep.is_null()
        {
            if curl_strnequal(
                b"ftp.\0" as *const u8 as *const i8,
                hostname,
                strlen(b"ftp.\0" as *const u8 as *const i8),
            ) != 0
            {
                schemep = b"ftp\0" as *const u8 as *const i8;
            } else if curl_strnequal(
                    b"dict.\0" as *const u8 as *const i8,
                    hostname,
                    strlen(b"dict.\0" as *const u8 as *const i8),
                ) != 0
                {
                schemep = b"dict\0" as *const u8 as *const i8;
            } else if curl_strnequal(
                    b"ldap.\0" as *const u8 as *const i8,
                    hostname,
                    strlen(b"ldap.\0" as *const u8 as *const i8),
                ) != 0
                {
                schemep = b"ldap\0" as *const u8 as *const i8;
            } else if curl_strnequal(
                    b"imap.\0" as *const u8 as *const i8,
                    hostname,
                    strlen(b"imap.\0" as *const u8 as *const i8),
                ) != 0
                {
                schemep = b"imap\0" as *const u8 as *const i8;
            } else if curl_strnequal(
                    b"smtp.\0" as *const u8 as *const i8,
                    hostname,
                    strlen(b"smtp.\0" as *const u8 as *const i8),
                ) != 0
                {
                schemep = b"smtp\0" as *const u8 as *const i8;
            } else if curl_strnequal(
                    b"pop3.\0" as *const u8 as *const i8,
                    hostname,
                    strlen(b"pop3.\0" as *const u8 as *const i8),
                ) != 0
                {
                schemep = b"pop3\0" as *const u8 as *const i8;
            } else {
                schemep = b"http\0" as *const u8 as *const i8;
            }
            let mut fresh30 = &mut ((*u).scheme);
            *fresh30 = Curl_cstrdup.expect("non-null function pointer")(schemep);
            if ((*u).scheme).is_null() {
                return CURLUE_OUT_OF_MEMORY;
            }
        }
    }
    Curl_cfree.expect("non-null function pointer")((*u).scratch as *mut libc::c_void);
    let mut fresh31 = &mut ((*u).scratch);
    *fresh31 = 0 as *mut i8;
    Curl_cfree.expect("non-null function pointer")((*u).temppath as *mut libc::c_void);
    let mut fresh32 = &mut ((*u).temppath);
    *fresh32 = 0 as *mut i8;
    return CURLUE_OK;
}
unsafe extern "C" fn parseurl(
    mut url: * const i8,
    mut u: * mut crate::src::lib::urlapi::Curl_URL,
    mut flags: u32,
) -> u32 {
    let mut result: u32 = seturl(url, u, flags);
    if result as u64 != 0 {
        free_urlhandle(u);
        memset(
            u as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<Curl_URL>() as u64,
        );
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn curl_url() -> * mut crate::src::lib::urlapi::Curl_URL {
    return Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<Curl_URL>() as u64, 1 as i32 as size_t)
        as *mut CURLU;
}
#[no_mangle]
pub unsafe extern "C" fn curl_url_cleanup(mut u: * mut crate::src::lib::urlapi::Curl_URL) {
    if !u.is_null() {
        free_urlhandle(u);
        Curl_cfree.expect("non-null function pointer")(u as *mut libc::c_void);
    }
}
#[no_mangle]
pub unsafe extern "C" fn curl_url_dup(mut in_0: * mut crate::src::lib::urlapi::Curl_URL) -> * mut crate::src::lib::urlapi::Curl_URL {
    let mut current_block: u64;
    let mut u: * mut crate::src::lib::urlapi::Curl_URL = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<Curl_URL>() as u64, 1 as i32 as size_t)
        as *mut Curl_URL;
    if !u.is_null() {
        if !((*in_0).scheme).is_null() {
            let mut fresh33 = &mut ((*u).scheme);
            *fresh33 = Curl_cstrdup.expect("non-null function pointer")((*in_0).scheme);
            if ((*u).scheme).is_null() {
                current_block = 3421950808998859186;
            } else {
                current_block = 7815301370352969686;
            }
        } else {
            current_block = 7815301370352969686;
        }
        match current_block {
            7815301370352969686 => {
                if !((*in_0).user).is_null() {
                    let mut fresh34 = &mut ((*u).user);
                    *fresh34 = Curl_cstrdup
                        .expect("non-null function pointer")((*in_0).user);
                    if ((*u).user).is_null() {
                        current_block = 3421950808998859186;
                    } else {
                        current_block = 11050875288958768710;
                    }
                } else {
                    current_block = 11050875288958768710;
                }
                match current_block {
                    3421950808998859186 => {}
                    _ => {
                        if !((*in_0).password).is_null() {
                            let mut fresh35 = &mut ((*u).password);
                            *fresh35 = Curl_cstrdup
                                .expect("non-null function pointer")((*in_0).password);
                            if ((*u).password).is_null() {
                                current_block = 3421950808998859186;
                            } else {
                                current_block = 5948590327928692120;
                            }
                        } else {
                            current_block = 5948590327928692120;
                        }
                        match current_block {
                            3421950808998859186 => {}
                            _ => {
                                if !((*in_0).options).is_null() {
                                    let mut fresh36 = &mut ((*u).options);
                                    *fresh36 = Curl_cstrdup
                                        .expect("non-null function pointer")((*in_0).options);
                                    if ((*u).options).is_null() {
                                        current_block = 3421950808998859186;
                                    } else {
                                        current_block = 10652014663920648156;
                                    }
                                } else {
                                    current_block = 10652014663920648156;
                                }
                                match current_block {
                                    3421950808998859186 => {}
                                    _ => {
                                        if !((*in_0).host).is_null() {
                                            let mut fresh37 = &mut ((*u).host);
                                            *fresh37 = Curl_cstrdup
                                                .expect("non-null function pointer")((*in_0).host);
                                            if ((*u).host).is_null() {
                                                current_block = 3421950808998859186;
                                            } else {
                                                current_block = 4775909272756257391;
                                            }
                                        } else {
                                            current_block = 4775909272756257391;
                                        }
                                        match current_block {
                                            3421950808998859186 => {}
                                            _ => {
                                                if !((*in_0).port).is_null() {
                                                    let mut fresh38 = &mut ((*u).port);
                                                    *fresh38 = Curl_cstrdup
                                                        .expect("non-null function pointer")((*in_0).port);
                                                    if ((*u).port).is_null() {
                                                        current_block = 3421950808998859186;
                                                    } else {
                                                        current_block = 11385396242402735691;
                                                    }
                                                } else {
                                                    current_block = 11385396242402735691;
                                                }
                                                match current_block {
                                                    3421950808998859186 => {}
                                                    _ => {
                                                        if !((*in_0).path).is_null() {
                                                            let mut fresh39 = &mut ((*u).path);
                                                            *fresh39 = Curl_cstrdup
                                                                .expect("non-null function pointer")((*in_0).path);
                                                            if ((*u).path).is_null() {
                                                                current_block = 3421950808998859186;
                                                            } else {
                                                                current_block = 15090052786889560393;
                                                            }
                                                        } else {
                                                            current_block = 15090052786889560393;
                                                        }
                                                        match current_block {
                                                            3421950808998859186 => {}
                                                            _ => {
                                                                if !((*in_0).query).is_null() {
                                                                    let mut fresh40 = &mut ((*u).query);
                                                                    *fresh40 = Curl_cstrdup
                                                                        .expect("non-null function pointer")((*in_0).query);
                                                                    if ((*u).query).is_null() {
                                                                        current_block = 3421950808998859186;
                                                                    } else {
                                                                        current_block = 16799951812150840583;
                                                                    }
                                                                } else {
                                                                    current_block = 16799951812150840583;
                                                                }
                                                                match current_block {
                                                                    3421950808998859186 => {}
                                                                    _ => {
                                                                        if !((*in_0).fragment).is_null() {
                                                                            let mut fresh41 = &mut ((*u).fragment);
                                                                            *fresh41 = Curl_cstrdup
                                                                                .expect("non-null function pointer")((*in_0).fragment);
                                                                            if ((*u).fragment).is_null() {
                                                                                current_block = 3421950808998859186;
                                                                            } else {
                                                                                current_block = 3689906465960840878;
                                                                            }
                                                                        } else {
                                                                            current_block = 3689906465960840878;
                                                                        }
                                                                        match current_block {
                                                                            3421950808998859186 => {}
                                                                            _ => {
                                                                                (*u).portnum = (*in_0).portnum;
                                                                                current_block = 7990025728955927862;
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        match current_block {
            7990025728955927862 => {}
            _ => {
                curl_url_cleanup(u);
                return 0 as *mut CURLU;
            }
        }
    }
    return u;
}
#[no_mangle]
pub unsafe extern "C" fn curl_url_get<'a1>(
    mut u: * mut crate::src::lib::urlapi::Curl_URL,
    mut what: u32,
    mut part: Option<&'a1 mut * mut i8>,
    mut flags: u32,
) -> u32 {
    let mut ptr: * mut i8 = 0 as *mut i8;
    let mut ifmissing: u32 = CURLUE_UNKNOWN_PART;
    let mut portbuf: [i8; 7] = [0; 7];
    let mut urldecode: bool = if flags
        & ((1 as i32) << 6 as i32) as u32 != 0
    {
        1 as i32
    } else {
        0 as i32
    } != 0;
    let mut plusdecode: bool = 0 as i32 != 0;
    if u.is_null() {
        return CURLUE_BAD_HANDLE;
    }
    if borrow(& part).is_none() {
        return CURLUE_BAD_PARTPOINTER;
    }
    *(borrow_mut(&mut part)).unwrap() = 0 as *mut i8;
    match what as u32 {
        1 => {
            ptr = (*u).scheme;
            ifmissing = CURLUE_NO_SCHEME;
            urldecode = 0 as i32 != 0;
        }
        2 => {
            ptr = (*u).user;
            ifmissing = CURLUE_NO_USER;
        }
        3 => {
            ptr = (*u).password;
            ifmissing = CURLUE_NO_PASSWORD;
        }
        4 => {
            ptr = (*u).options;
            ifmissing = CURLUE_NO_OPTIONS;
        }
        5 => {
            ptr = (*u).host;
            ifmissing = CURLUE_NO_HOST;
        }
        10 => {
            ptr = (*u).zoneid;
        }
        6 => {
            ptr = (*u).port;
            ifmissing = CURLUE_NO_PORT;
            urldecode = 0 as i32 != 0;
            if ptr.is_null()
                && flags & ((1 as i32) << 0 as i32) as u32 != 0
                && !((*u).scheme).is_null()
            {
                let mut h: * const crate::src::lib::http2::Curl_handler = Curl_builtin_scheme((*u).scheme);
                if !h.is_null() {
                    curl_msnprintf(
                        portbuf.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 7]>() as u64,
                        b"%u\0" as *const u8 as *const i8,
                        (*h).defport,
                    );
                    ptr = portbuf.as_mut_ptr();
                }
            } else if !ptr.is_null() && !((*u).scheme).is_null() {
                let mut h_0: * const crate::src::lib::http2::Curl_handler = Curl_builtin_scheme((*u).scheme);
                if !h_0.is_null() && (*h_0).defport as i64 == (*u).portnum
                    && flags & ((1 as i32) << 1 as i32) as u32
                        != 0
                {
                    ptr = 0 as *mut i8;
                }
            }
        }
        7 => {
            ptr = (*u).path;
            if ptr.is_null() {
                let mut fresh42 = &mut ((*u).path);
                *fresh42 = Curl_cstrdup
                    .expect(
                        "non-null function pointer",
                    )(b"/\0" as *const u8 as *const i8);
                ptr = *fresh42;
                if ((*u).path).is_null() {
                    return CURLUE_OUT_OF_MEMORY;
                }
            }
        }
        8 => {
            ptr = (*u).query;
            ifmissing = CURLUE_NO_QUERY;
            plusdecode = urldecode;
        }
        9 => {
            ptr = (*u).fragment;
            ifmissing = CURLUE_NO_FRAGMENT;
        }
        0 => {
            let mut url: * mut i8 = 0 as *mut i8;
            let mut scheme: * mut i8 = 0 as *mut i8;
            let mut options: * mut i8 = (*u).options;
            let mut port: * mut i8 = (*u).port;
            let mut allochost: * mut i8 = 0 as *mut i8;
            if !((*u).scheme).is_null()
                && Curl_strcasecompare(
                    b"file\0" as *const u8 as *const i8,
                    (*u).scheme,
                ) != 0
            {
                url = curl_maprintf(
                    b"file://%s%s%s\0" as *const u8 as *const i8,
                    (*u).path,
                    if !((*u).fragment).is_null() {
                        b"#\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).fragment).is_null() {
                        (*u).fragment as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                );
            } else if ((*u).host).is_null() {
                return CURLUE_NO_HOST
            } else {
                let mut h_1: * const crate::src::lib::http2::Curl_handler = 0 as *const Curl_handler;
                if !((*u).scheme).is_null() {
                    scheme = (*u).scheme;
                } else if flags
                        & ((1 as i32) << 2 as i32) as u32 != 0
                    {
                    scheme = b"https\0" as *const u8 as *const i8
                        as *mut i8;
                } else {
                    return CURLUE_NO_SCHEME
                }
                h_1 = Curl_builtin_scheme(scheme);
                if port.is_null()
                    && flags & ((1 as i32) << 0 as i32) as u32
                        != 0
                {
                    if !h_1.is_null() {
                        curl_msnprintf(
                            portbuf.as_mut_ptr(),
                            ::std::mem::size_of::<[i8; 7]>() as u64,
                            b"%u\0" as *const u8 as *const i8,
                            (*h_1).defport,
                        );
                        port = portbuf.as_mut_ptr();
                    }
                } else if !port.is_null() {
                    if !h_1.is_null() && (*h_1).defport as i64 == (*u).portnum
                        && flags
                            & ((1 as i32) << 1 as i32) as u32
                            != 0
                    {
                        port = 0 as *mut i8;
                    }
                }
                if !h_1.is_null()
                    && (*h_1).flags
                        & ((1 as i32) << 10 as i32) as u32 == 0
                {
                    options = 0 as *mut i8;
                }
                if *((*u).host).offset(0 as i32 as isize) as i32
                    == '[' as i32 && !((*u).zoneid).is_null()
                {
                    let mut hostlen: u64 = strlen((*u).host);
                    let mut alen: u64 = hostlen
                        .wrapping_add(3 as i32 as u64)
                        .wrapping_add(strlen((*u).zoneid))
                        .wrapping_add(1 as i32 as u64);
                    allochost = Curl_cmalloc.expect("non-null function pointer")(alen)
                        as *mut i8;
                    if allochost.is_null() {
                        return CURLUE_OUT_OF_MEMORY;
                    }
                    memcpy(
                        allochost as *mut libc::c_void,
                        (*u).host as *const libc::c_void,
                        hostlen.wrapping_sub(1 as i32 as u64),
                    );
                    curl_msnprintf(
                        &mut *allochost
                            .offset(
                                hostlen.wrapping_sub(1 as i32 as u64)
                                    as isize,
                            ) as *mut i8,
                        alen
                            .wrapping_sub(hostlen)
                            .wrapping_add(1 as i32 as u64),
                        b"%%25%s]\0" as *const u8 as *const i8,
                        (*u).zoneid,
                    );
                }
                url = curl_maprintf(
                    b"%s://%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\0" as *const u8
                        as *const i8,
                    scheme,
                    if !((*u).user).is_null() {
                        (*u).user as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).password).is_null() {
                        b":\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).password).is_null() {
                        (*u).password as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !options.is_null() {
                        b";\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !options.is_null() {
                        options as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).user).is_null() || !((*u).password).is_null()
                        || !options.is_null()
                    {
                        b"@\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !allochost.is_null() { allochost } else { (*u).host },
                    if !port.is_null() {
                        b":\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !port.is_null() {
                        port as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).path).is_null()
                        && *((*u).path).offset(0 as i32 as isize) as i32
                            != '/' as i32
                    {
                        b"/\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).path).is_null() {
                        (*u).path as *const i8
                    } else {
                        b"/\0" as *const u8 as *const i8
                    },
                    if !((*u).query).is_null()
                        && *((*u).query).offset(0 as i32 as isize) as i32
                            != 0
                    {
                        b"?\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).query).is_null()
                        && *((*u).query).offset(0 as i32 as isize) as i32
                            != 0
                    {
                        (*u).query as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).fragment).is_null() {
                        b"#\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).fragment).is_null() {
                        (*u).fragment as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                );
                Curl_cfree
                    .expect("non-null function pointer")(allochost as *mut libc::c_void);
            }
            if url.is_null() {
                return CURLUE_OUT_OF_MEMORY;
            }
            *(borrow_mut(&mut part)).unwrap() = url;
            return CURLUE_OK;
        }
        _ => {
            ptr = 0 as *mut i8;
        }
    }
    if !ptr.is_null() {
        *(borrow_mut(&mut part)).unwrap() = Curl_cstrdup.expect("non-null function pointer")(ptr);
        if (*(borrow_mut(&mut part)).unwrap()).is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
        if plusdecode {
            let mut plus: * mut i8 = 0 as *mut i8;
            plus = *(borrow_mut(&mut part)).unwrap();
            while *plus != 0 {
                if *plus as i32 == '+' as i32 {
                    *plus = ' ' as i32 as i8;
                }
                plus = plus.offset(1);
            }
        }
        if urldecode {
            let mut decoded: * mut i8 = 0 as *mut i8;
            let mut dlen: u64 = 0;
            let mut res: u32 = Curl_urldecode(
                0 as *mut Curl_easy,
                *(borrow(& part)).unwrap(),
                0 as i32 as size_t,
                Some(&mut decoded),
                Some(&mut dlen),
                REJECT_CTRL,
            );
            Curl_cfree.expect("non-null function pointer")(*(borrow_mut(&mut part)).unwrap() as *mut libc::c_void);
            if res as u64 != 0 {
                *(borrow_mut(&mut part)).unwrap() = 0 as *mut i8;
                return CURLUE_URLDECODE;
            }
            *(borrow_mut(&mut part)).unwrap() = decoded;
        }
        return CURLUE_OK;
    } else {
        return ifmissing
    };
}
#[no_mangle]
pub unsafe extern "C" fn curl_url_set(
    mut u: * mut crate::src::lib::urlapi::Curl_URL,
    mut what: u32,
    mut part: * const i8,
    mut flags: u32,
) -> u32 {
    let mut storep: Option<&'_ mut * mut i8> = Option::<&'_ mut * mut i8>::None;
    let mut port: i64 = 0 as i32 as i64;
    let mut urlencode: bool = if flags
        & ((1 as i32) << 7 as i32) as u32 != 0
    {
        1 as i32
    } else {
        0 as i32
    } != 0;
    let mut plusencode: bool = 0 as i32 != 0;
    let mut urlskipslash: bool = 0 as i32 != 0;
    let mut appendquery: bool = 0 as i32 != 0;
    let mut equalsencode: bool = 0 as i32 != 0;
    if u.is_null() {
        return CURLUE_BAD_HANDLE;
    }
    if part.is_null() {
        match what as u32 {
            0 => {}
            1 => {
                storep = Some(&mut (*u).scheme);
            }
            2 => {
                storep = Some(&mut (*u).user);
            }
            3 => {
                storep = Some(&mut (*u).password);
            }
            4 => {
                storep = Some(&mut (*u).options);
            }
            5 => {
                storep = Some(&mut (*u).host);
            }
            10 => {
                storep = Some(&mut (*u).zoneid);
            }
            6 => {
                (*u).portnum = 0 as i32 as i64;
                storep = Some(&mut (*u).port);
            }
            7 => {
                storep = Some(&mut (*u).path);
            }
            8 => {
                storep = Some(&mut (*u).query);
            }
            9 => {
                storep = Some(&mut (*u).fragment);
            }
            _ => return CURLUE_UNKNOWN_PART,
        }
        if !borrow(& storep).is_none() && !(*(borrow_mut(&mut storep)).unwrap()).is_null() {
            Curl_cfree.expect("non-null function pointer")(*(borrow_mut(&mut storep)).unwrap() as *mut libc::c_void);
            *(borrow_mut(&mut storep)).unwrap() = 0 as *mut i8;
        }
        return CURLUE_OK;
    }
    match what as u32 {
        1 => {
            if strlen(part) > 40 as i32 as u64 {
                return CURLUE_MALFORMED_INPUT;
            }
            if flags & ((1 as i32) << 3 as i32) as u32 == 0
                && (Curl_builtin_scheme(part)).is_null()
            {
                return CURLUE_UNSUPPORTED_SCHEME;
            }
            storep = Some(&mut (*u).scheme);
            urlencode = 0 as i32 != 0;
        }
        2 => {
            storep = Some(&mut (*u).user);
        }
        3 => {
            storep = Some(&mut (*u).password);
        }
        4 => {
            storep = Some(&mut (*u).options);
        }
        5 => {
            storep = Some(&mut (*u).host);
            Curl_cfree
                .expect("non-null function pointer")((*u).zoneid as *mut libc::c_void);
            let mut fresh43 = &mut ((*u).zoneid);
            *fresh43 = 0 as *mut i8;
        }
        10 => {
            storep = Some(&mut (*u).zoneid);
        }
        6 => {
            let mut endp: * mut i8 = 0 as *mut i8;
            urlencode = 0 as i32 != 0;
            port = strtol(part, &mut endp, 10 as i32);
            if port <= 0 as i32 as i64
                || port > 0xffff as i32 as i64
            {
                return CURLUE_BAD_PORT_NUMBER;
            }
            if *endp != 0 {
                return CURLUE_MALFORMED_INPUT;
            }
            storep = Some(&mut (*u).port);
        }
        7 => {
            urlskipslash = 1 as i32 != 0;
            storep = Some(&mut (*u).path);
        }
        8 => {
            plusencode = urlencode;
            appendquery = if flags
                & ((1 as i32) << 8 as i32) as u32 != 0
            {
                1 as i32
            } else {
                0 as i32
            } != 0;
            equalsencode = appendquery;
            storep = Some(&mut (*u).query);
        }
        9 => {
            storep = Some(&mut (*u).fragment);
        }
        0 => {
            let mut result: u32 = CURLUE_OK;
            let mut oldurl: * mut i8 = 0 as *mut i8;
            let mut redired_url: * mut i8 = 0 as *mut i8;
            let mut handle2: * mut crate::src::lib::urlapi::Curl_URL = 0 as *mut CURLU;
            if Curl_is_absolute_url(
                part,
                0 as *mut i8,
                (40 as i32 + 1 as i32) as size_t,
            ) {
                handle2 = curl_url();
                if handle2.is_null() {
                    return CURLUE_OUT_OF_MEMORY;
                }
                result = parseurl(part, handle2, flags);
                if result as u64 == 0 {
                    mv_urlhandle(handle2, u);
                } else {
                    curl_url_cleanup(handle2);
                }
                return result;
            }
            result = curl_url_get(u, CURLUPART_URL, Some(&mut oldurl), flags);
            if result as u64 != 0 {
                handle2 = curl_url();
                if handle2.is_null() {
                    return CURLUE_OUT_OF_MEMORY;
                }
                result = parseurl(part, handle2, flags);
                if result as u64 == 0 {
                    mv_urlhandle(handle2, u);
                } else {
                    curl_url_cleanup(handle2);
                }
                return result;
            }
            redired_url = concat_url(oldurl, part);
            Curl_cfree.expect("non-null function pointer")(oldurl as *mut libc::c_void);
            if redired_url.is_null() {
                return CURLUE_OUT_OF_MEMORY;
            }
            handle2 = curl_url();
            if handle2.is_null() {
                Curl_cfree
                    .expect(
                        "non-null function pointer",
                    )(redired_url as *mut libc::c_void);
                return CURLUE_OUT_OF_MEMORY;
            }
            result = parseurl(redired_url, handle2, flags);
            Curl_cfree
                .expect("non-null function pointer")(redired_url as *mut libc::c_void);
            if result as u64 == 0 {
                mv_urlhandle(handle2, u);
            } else {
                curl_url_cleanup(handle2);
            }
            return result;
        }
        _ => return CURLUE_UNKNOWN_PART,
    }
    let mut newp: * const i8 = part;
    let mut nalloc: u64 = strlen(part);
    if nalloc > 8000000 as i32 as u64 {
        return CURLUE_MALFORMED_INPUT;
    }
    if urlencode {
        let mut i: * const u8 = 0 as *const u8;
        let mut o: * mut i8 = 0 as *mut i8;
        let mut enc: * mut i8 = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )(
            nalloc
                .wrapping_mul(3 as i32 as u64)
                .wrapping_add(1 as i32 as u64),
        ) as *mut i8;
        if enc.is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
        i = part as *const u8;
        o = enc;
        while *i != 0 {
            if *i as i32 == ' ' as i32 && plusencode as i32 != 0 {
                *o = '+' as i32 as i8;
                o = o.offset(1);
            } else if Curl_isunreserved(*i) as i32 != 0
                    || *i as i32 == '/' as i32
                        && urlskipslash as i32 != 0
                    || *i as i32 == '=' as i32
                        && equalsencode as i32 != 0
                {
                if *i as i32 == '=' as i32 && equalsencode as i32 != 0 {
                    equalsencode = 0 as i32 != 0;
                }
                *o = *i as i8;
                o = o.offset(1);
            } else {
                curl_msnprintf(
                    o,
                    4 as i32 as size_t,
                    b"%%%02x\0" as *const u8 as *const i8,
                    *i as i32,
                );
                o = o.offset(3 as i32 as isize);
            }
            i = i.offset(1);
        }
        *o = 0 as i32 as i8;
        newp = enc;
    } else {
        let mut p: * mut i8 = 0 as *mut i8;
        newp = Curl_cstrdup.expect("non-null function pointer")(part);
        if newp.is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
        p = newp as *mut i8;
        while *p != 0 {
            if *p as i32 == '%' as i32
                && Curl_isxdigit(
                    *p.offset(1 as i32 as isize) as u8 as i32,
                ) != 0
                && Curl_isxdigit(
                    *p.offset(2 as i32 as isize) as u8 as i32,
                ) != 0
                && (Curl_isupper(
                    *p.offset(1 as i32 as isize) as u8 as i32,
                ) != 0
                    || Curl_isupper(
                        *p.offset(2 as i32 as isize) as u8
                            as i32,
                    ) != 0)
            {
                *p
                    .offset(
                        1 as i32 as isize,
                    ) = ({
                    let mut __res: i32 = 0;
                    if ::std::mem::size_of::<i32>() as u64
                        > 1 as i32 as u64
                    {
                        if 0 != 0 {
                            let mut __c: i32 = *p
                                .offset(1 as i32 as isize) as u8
                                as i32;
                            __res = if __c < -(128 as i32)
                                || __c > 255 as i32
                            {
                                __c
                            } else {
                                *(*__ctype_tolower_loc()).offset(__c as isize)
                            };
                        } else {
                            __res = tolower(
                                *p.offset(1 as i32 as isize) as u8
                                    as i32,
                            );
                        }
                    } else {
                        __res = *(*__ctype_tolower_loc())
                            .offset(
                                *p.offset(1 as i32 as isize) as u8
                                    as i32 as isize,
                            );
                    }
                    __res
                }) as i8;
                *p
                    .offset(
                        2 as i32 as isize,
                    ) = ({
                    let mut __res: i32 = 0;
                    if ::std::mem::size_of::<i32>() as u64
                        > 1 as i32 as u64
                    {
                        if 0 != 0 {
                            let mut __c: i32 = *p
                                .offset(2 as i32 as isize) as u8
                                as i32;
                            __res = if __c < -(128 as i32)
                                || __c > 255 as i32
                            {
                                __c
                            } else {
                                *(*__ctype_tolower_loc()).offset(__c as isize)
                            };
                        } else {
                            __res = tolower(
                                *p.offset(2 as i32 as isize) as u8
                                    as i32,
                            );
                        }
                    } else {
                        __res = *(*__ctype_tolower_loc())
                            .offset(
                                *p.offset(2 as i32 as isize) as u8
                                    as i32 as isize,
                            );
                    }
                    __res
                }) as i8;
                p = p.offset(3 as i32 as isize);
            } else {
                p = p.offset(1);
            }
        }
    }
    if appendquery {
        let mut querylen: u64 = if !((*u).query).is_null() {
            strlen((*u).query)
        } else {
            0 as i32 as u64
        };
        let mut addamperand: bool = querylen != 0
            && *((*u).query)
                .offset(
                    querylen.wrapping_sub(1 as i32 as u64) as isize,
                ) as i32 != '&' as i32;
        if querylen != 0 {
            let mut newplen: u64 = strlen(newp);
            let mut p_0: * mut i8 = Curl_cmalloc
                .expect(
                    "non-null function pointer",
                )(
                querylen
                    .wrapping_add(addamperand as u64)
                    .wrapping_add(newplen)
                    .wrapping_add(1 as i32 as u64),
            ) as *mut i8;
            if p_0.is_null() {
                Curl_cfree
                    .expect(
                        "non-null function pointer",
                    )(newp as *mut i8 as *mut libc::c_void);
                return CURLUE_OUT_OF_MEMORY;
            }
            strcpy(p_0, (*u).query);
            if addamperand {
                *p_0.offset(querylen as isize) = '&' as i32 as i8;
            }
            strcpy(
                &mut *p_0
                    .offset(
                        querylen.wrapping_add(addamperand as u64) as isize,
                    ),
                newp,
            );
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )(newp as *mut i8 as *mut libc::c_void);
            Curl_cfree.expect("non-null function pointer")(*(borrow_mut(&mut storep)).unwrap() as *mut libc::c_void);
            *(borrow_mut(&mut storep)).unwrap() = p_0;
            return CURLUE_OK;
        }
    }
    if what as u32 == CURLUPART_HOST as i32 as u32 {
        if !(0 as i32 as u64 == strlen(newp)
            && flags & ((1 as i32) << 10 as i32) as u32 != 0)
        {
            if hostname_check(u, newp as *mut i8) as u64 != 0 {
                Curl_cfree
                    .expect(
                        "non-null function pointer",
                    )(newp as *mut i8 as *mut libc::c_void);
                return CURLUE_MALFORMED_INPUT;
            }
        }
    }
    Curl_cfree.expect("non-null function pointer")(*(borrow_mut(&mut storep)).unwrap() as *mut libc::c_void);
    *(borrow_mut(&mut storep)).unwrap() = newp as *mut i8;
    if port != 0 {
        (*u).portnum = port;
    }
    return CURLUE_OK;
}
use crate::laertes_rt::*;
