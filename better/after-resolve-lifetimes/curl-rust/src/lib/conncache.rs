use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    pub type Gsasl_session;
    
    
    fn memset(
        _: * mut core::ffi::c_void,
        _: i32,
        _: u64,
    ) -> * mut core::ffi::c_void;
    
    fn strlen(_: * const i8) -> u64;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn sigaction(
        __sig: i32,
        __act: * const crate::src::lib::conncache::sigaction,
        __oact: * mut crate::src::lib::conncache::sigaction,
    ) -> i32;
    
    
    
    
    
}
pub use crate::src::lib::connect::Curl_conncontrol;
pub use crate::src::lib::easy::curl_easy_init;
pub use crate::src::lib::hash::Curl_hash_add;
pub use crate::src::lib::hash::Curl_hash_delete;
pub use crate::src::lib::hash::Curl_hash_destroy;
pub use crate::src::lib::hash::Curl_hash_init;
pub use crate::src::lib::hash::Curl_hash_next_element;
pub use crate::src::lib::hash::Curl_hash_pick;
pub use crate::src::lib::hash::Curl_hash_start_iterate;
pub use crate::src::lib::hash::Curl_hash_str;
pub use crate::src::lib::hash::Curl_str_key_compare;
pub use crate::src::lib::hostip::Curl_hostcache_clean;
pub use crate::src::lib::llist::Curl_llist_destroy;
pub use crate::src::lib::llist::Curl_llist_init;
pub use crate::src::lib::llist::Curl_llist_insert_next;
pub use crate::src::lib::llist::Curl_llist_remove;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::share::Curl_share_lock;
pub use crate::src::lib::share::Curl_share_unlock;
pub use crate::src::lib::strcase::Curl_strntolower;
pub use crate::src::lib::timeval::Curl_now;
pub use crate::src::lib::timeval::Curl_timediff;
pub use crate::src::lib::url::Curl_close;
pub use crate::src::lib::url::Curl_disconnect;
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
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
pub type __uid_t = u32;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __pid_t = i32;
pub type __clock_t = i64;
pub type __time_t = i64;
pub type __ssize_t = i64;
pub type __socklen_t = u32;
pub type pid_t = i32;
pub type ssize_t = i64;
pub type time_t = i64;
pub type size_t = u64;
pub type int32_t = i32;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __sigset_t {
    pub __val: [u64; 16],
}
impl __sigset_t {
    pub const fn new() -> Self {
        __sigset_t {
        __val: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,]
        }
    }
}

impl std::default::Default for __sigset_t {
    fn default() -> Self { __sigset_t::new() }
}

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
pub type __sigval_t = crate::src::lib::conncache::sigval;
#[derive(Copy, Clone)]
#[repr(C)]
pub union sigval {
    pub sival_int: i32,
    pub sival_ptr: *mut libc::c_void,
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

pub type Curl_share = crate::src::lib::asyn_thread::Curl_share;
pub type curl_unlock_function<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: u32,_: Option<&'a2 mut core::ffi::c_void>,) -> ()>;
pub type curl_lock_data = u32;
pub const CURL_LOCK_DATA_LAST: curl_lock_data = 7;
pub const CURL_LOCK_DATA_PSL: curl_lock_data = 6;
pub const CURL_LOCK_DATA_CONNECT: curl_lock_data = 5;
pub const CURL_LOCK_DATA_SSL_SESSION: curl_lock_data = 4;
pub const CURL_LOCK_DATA_DNS: curl_lock_data = 3;
pub const CURL_LOCK_DATA_COOKIE: curl_lock_data = 2;
pub const CURL_LOCK_DATA_SHARE: curl_lock_data = 1;
pub const CURL_LOCK_DATA_NONE: curl_lock_data = 0;
pub type curl_lock_function<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: u32,_: u32,_: Option<&'a2 mut core::ffi::c_void>,) -> ()>;
pub type curl_lock_access = u32;
pub const CURL_LOCK_ACCESS_LAST: curl_lock_access = 3;
pub const CURL_LOCK_ACCESS_SINGLE: curl_lock_access = 2;
pub const CURL_LOCK_ACCESS_SHARED: curl_lock_access = 1;
pub const CURL_LOCK_ACCESS_NONE: curl_lock_access = 0;
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
pub type CURLSHcode = u32;
pub const CURLSHE_LAST: CURLSHcode = 6;
pub const CURLSHE_NOT_BUILT_IN: CURLSHcode = 5;
pub const CURLSHE_NOMEM: CURLSHcode = 4;
pub const CURLSHE_INVALID: CURLSHcode = 3;
pub const CURLSHE_IN_USE: CURLSHcode = 2;
pub const CURLSHE_BAD_OPTION: CURLSHcode = 1;
pub const CURLSHE_OK: CURLSHcode = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_hash_element {
    pub list: crate::src::lib::http2::Curl_llist_element,
    pub ptr: * mut core::ffi::c_void,
    pub key_len: u64,
    pub key: [i8; 1],
}
impl Curl_hash_element {
    pub const fn new() -> Self {
        Curl_hash_element {
        list: crate::src::lib::http2::Curl_llist_element::new(),
        ptr: (0 as * mut core::ffi::c_void),
        key_len: 0,
        key: [0,]
        }
    }
}

impl std::default::Default for Curl_hash_element {
    fn default() -> Self { Curl_hash_element::new() }
}

// #[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_hash_iterator<'a> {
    pub hash: Option<&'a mut crate::src::lib::http2::Curl_hash>,
    pub slot_index: i32,
    pub current_element: * mut crate::src::lib::http2::Curl_llist_element,
}
impl<'a> Curl_hash_iterator<'a> {
    pub const fn new() -> Self {
        Curl_hash_iterator {
        hash: None,
        slot_index: 0,
        current_element: (0 as * mut crate::src::lib::http2::Curl_llist_element)
        }
    }
}

impl<'a> std::default::Default for Curl_hash_iterator<'a> {
    fn default() -> Self { Curl_hash_iterator::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct sigpipe_ignore {
    pub old_pipe_act: crate::src::lib::conncache::sigaction,
    pub no_signal: bool,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sigaction {
    pub __sigaction_handler: crate::src::lib::conncache::C2RustUnnamed_6,
    pub sa_mask: crate::src::lib::conncache::__sigset_t,
    pub sa_flags: i32,
    pub sa_restorer: Option<unsafe extern "C"  fn() -> ()>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_6 {
    pub sa_handler: __sighandler_t,
    pub sa_sigaction: Option::<
        unsafe extern "C" fn(i32, *mut siginfo_t, *mut libc::c_void) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct siginfo_t {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub __pad0: i32,
    pub _sifields: crate::src::lib::conncache::C2RustUnnamed_7,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_7 {
    pub _pad: [i32; 28],
    pub _kill: C2RustUnnamed_16,
    pub _timer: C2RustUnnamed_15,
    pub _rt: C2RustUnnamed_14,
    pub _sigchld: C2RustUnnamed_13,
    pub _sigfault: C2RustUnnamed_10,
    pub _sigpoll: C2RustUnnamed_9,
    pub _sigsys: C2RustUnnamed_8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_8 {
    pub _call_addr: * mut core::ffi::c_void,
    pub _syscall: i32,
    pub _arch: u32,
}
impl C2RustUnnamed_8 {
    pub const fn new() -> Self {
        C2RustUnnamed_8 {
        _call_addr: (0 as * mut core::ffi::c_void),
        _syscall: 0,
        _arch: 0
        }
    }
}

impl std::default::Default for C2RustUnnamed_8 {
    fn default() -> Self { C2RustUnnamed_8::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_9 {
    pub si_band: i64,
    pub si_fd: i32,
}
impl C2RustUnnamed_9 {
    pub const fn new() -> Self {
        C2RustUnnamed_9 {
        si_band: 0,
        si_fd: 0
        }
    }
}

impl std::default::Default for C2RustUnnamed_9 {
    fn default() -> Self { C2RustUnnamed_9::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_10 {
    pub si_addr: * mut core::ffi::c_void,
    pub si_addr_lsb: i16,
    pub _bounds: crate::src::lib::conncache::C2RustUnnamed_11,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_11 {
    pub _addr_bnd: C2RustUnnamed_12,
    pub _pkey: __uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_12 {
    pub _lower: * mut core::ffi::c_void,
    pub _upper: * mut core::ffi::c_void,
}
impl C2RustUnnamed_12 {
    pub const fn new() -> Self {
        C2RustUnnamed_12 {
        _lower: (0 as * mut core::ffi::c_void),
        _upper: (0 as * mut core::ffi::c_void)
        }
    }
}

impl std::default::Default for C2RustUnnamed_12 {
    fn default() -> Self { C2RustUnnamed_12::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_13 {
    pub si_pid: i32,
    pub si_uid: u32,
    pub si_status: i32,
    pub si_utime: i64,
    pub si_stime: i64,
}
impl C2RustUnnamed_13 {
    pub const fn new() -> Self {
        C2RustUnnamed_13 {
        si_pid: 0,
        si_uid: 0,
        si_status: 0,
        si_utime: 0,
        si_stime: 0
        }
    }
}

impl std::default::Default for C2RustUnnamed_13 {
    fn default() -> Self { C2RustUnnamed_13::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_14 {
    pub si_pid: i32,
    pub si_uid: u32,
    pub si_sigval: crate::src::lib::conncache::sigval,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_15 {
    pub si_tid: i32,
    pub si_overrun: i32,
    pub si_sigval: crate::src::lib::conncache::sigval,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_16 {
    pub si_pid: i32,
    pub si_uid: u32,
}
impl C2RustUnnamed_16 {
    pub const fn new() -> Self {
        C2RustUnnamed_16 {
        si_pid: 0,
        si_uid: 0
        }
    }
}

impl std::default::Default for C2RustUnnamed_16 {
    fn default() -> Self { C2RustUnnamed_16::new() }
}

pub type __sighandler_t = Option<unsafe extern "C"  fn(_: i32,) -> ()>;
unsafe extern "C" fn sigpipe_ignore<'a1>(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut ig: Option<&'a1 mut crate::src::lib::conncache::sigpipe_ignore>,
) {
    (*(borrow_mut(&mut ig)).unwrap()).no_signal = ((*data).set).no_signal() != 0;
    if ((*data).set).no_signal() == 0 {
        let mut action: crate::src::lib::conncache::sigaction = sigaction {
            __sigaction_handler: C2RustUnnamed_6 {
                sa_handler: None,
            },
            sa_mask: __sigset_t { __val: [0; 16] },
            sa_flags: 0,
            sa_restorer: None,
        };
        memset(
            &mut (*(borrow_mut(&mut ig)).unwrap()).old_pipe_act as *mut sigaction as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<sigaction>() as u64,
        );
        sigaction(13 as i32, 0 as *const sigaction, &mut (*(borrow_mut(&mut ig)).unwrap()).old_pipe_act);
        action = (*(borrow_mut(&mut ig)).unwrap()).old_pipe_act;
        action
            .__sigaction_handler
            .sa_handler = core::intrinsics::transmute::<isize, Option<unsafe extern "C"  fn(_: i32,) -> ()>>(1 as i32 as libc::intptr_t);
        sigaction(13 as i32, &mut action, 0 as *mut sigaction);
    }
}
unsafe extern "C" fn sigpipe_restore<'a1>(mut ig: Option<&'a1 mut crate::src::lib::conncache::sigpipe_ignore>) {
    if !(*(borrow(& ig)).unwrap()).no_signal {
        sigaction(13 as i32, &mut (*(borrow_mut(&mut ig)).unwrap()).old_pipe_act, 0 as *mut sigaction);
    }
}
unsafe extern "C" fn conn_llist_dtor(
    mut user: * mut core::ffi::c_void,
    mut element: * mut core::ffi::c_void,
) {
    let mut conn: * mut crate::src::lib::http2::connectdata = element as *mut connectdata;
    let mut fresh0 = &mut ((*conn).bundle);
    *fresh0 = 0 as *mut connectbundle;
}
unsafe extern "C" fn bundle_create<'a1>(mut bundlep: Option<&'a1 mut * mut crate::src::lib::http2::connectbundle>) -> u32 {
    *(borrow_mut(&mut bundlep)).unwrap() = Curl_cmalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<connectbundle>() as u64) as *mut connectbundle;
    if (*(borrow_mut(&mut bundlep)).unwrap()).is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    (**(borrow_mut(&mut bundlep)).unwrap()).num_connections = 0 as i32 as size_t;
    (**(borrow_mut(&mut bundlep)).unwrap()).multiuse = 0 as i32;
    Curl_llist_init(
        Some(&mut (**(borrow_mut(&mut bundlep)).unwrap()).conn_list),
        core::intrinsics::transmute::<Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut core::ffi::c_void,) -> ()>, Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut core::ffi::c_void,) -> ()>>(
            Some(
                conn_llist_dtor,
            ),
        ),
    );
    return CURLE_OK;
}
unsafe extern "C" fn bundle_destroy(mut bundle: * mut crate::src::lib::http2::connectbundle) {
    if bundle.is_null() {
        return;
    }
    Curl_llist_destroy(&mut (*bundle).conn_list, 0 as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(bundle as *mut libc::c_void);
}
unsafe extern "C" fn bundle_add_conn(
    mut bundle: * mut crate::src::lib::http2::connectbundle,
    mut conn: * mut crate::src::lib::http2::connectdata,
) {
    Curl_llist_insert_next(
        &mut (*bundle).conn_list,
        (*bundle).conn_list.tail,
        conn as *const libc::c_void,
        &mut (*conn).bundle_node,
    );
    let mut fresh1 = &mut ((*conn).bundle);
    *fresh1 = bundle;
    let mut fresh2 = &mut ((*bundle).num_connections);
    *fresh2 = (*fresh2).wrapping_add(1);
}
unsafe extern "C" fn bundle_remove_conn(
    mut bundle: * mut crate::src::lib::http2::connectbundle,
    mut conn: * mut crate::src::lib::http2::connectdata,
) -> i32 {
    let mut curr: * mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
    curr = (*bundle).conn_list.head;
    while !curr.is_null() {
        if (*curr).ptr == conn as *mut libc::c_void {
            Curl_llist_remove(&mut (*bundle).conn_list, curr, 0 as *mut libc::c_void);
            let mut fresh3 = &mut ((*bundle).num_connections);
            *fresh3 = (*fresh3).wrapping_sub(1);
            let mut fresh4 = &mut ((*conn).bundle);
            *fresh4 = 0 as *mut connectbundle;
            return 1 as i32;
        }
        curr = (*curr).next;
    }
    return 0 as i32;
}
unsafe extern "C" fn free_bundle_hash_entry(mut freethis: * mut core::ffi::c_void) {
    let mut b: * mut crate::src::lib::http2::connectbundle = freethis as *mut connectbundle;
    bundle_destroy(b);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_conncache_init(
    mut connc: * mut crate::src::lib::http2::conncache,
    mut size: i32,
) -> i32 {
    let mut rc: i32 = 0;
    let mut fresh5 = &mut ((*connc).closure_handle);
    *fresh5 = curl_easy_init();
    if ((*connc).closure_handle).is_null() {
        return 1 as i32;
    }
    rc = Curl_hash_init(
        Some(&mut (*connc).hash),
        size,
        Some(
            Curl_hash_str,
        ),
        Some(
            Curl_str_key_compare,
        ),
        Some(free_bundle_hash_entry),
    );
    if rc != 0 {
        Curl_close(Some(&mut (*connc).closure_handle));
    } else {
        let mut fresh6 = &mut ((*(*connc).closure_handle).state.conn_cache);
        *fresh6 = connc;
    }
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_conncache_destroy<'a1>(mut connc: Option<&'a1 mut crate::src::lib::http2::conncache>) {
    if !borrow(& connc).is_none() {
        Curl_hash_destroy(&mut (*(borrow_mut(&mut connc)).unwrap()).hash);
    }
}
unsafe extern "C" fn hashkey<'a1>(
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut buf: * mut i8,
    mut len: u64,
    mut hostp: Option<&'a1 mut * const i8>,
) {
    let mut hostname: * const i8 = 0 as *const i8;
    let mut port: i64 = (*conn).remote_port as i64;
    if ((*conn).bits).httpproxy() as i32 != 0
        && ((*conn).bits).tunnel_proxy() == 0
    {
        hostname = (*conn).http_proxy.host.name;
        port = (*conn).port as i64;
    } else if ((*conn).bits).conn_to_host() != 0 {
        hostname = (*conn).conn_to_host.name;
    } else {
        hostname = (*conn).host.name;
    }
    if !borrow(& hostp).is_none() {
        *(borrow_mut(&mut hostp)).unwrap() = hostname;
    }
    curl_msnprintf(
        buf,
        len,
        b"%ld%s\0" as *const u8 as *const i8,
        port,
        hostname,
    );
    Curl_strntolower(buf, buf, len);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_conncache_size(mut data: * mut crate::src::lib::http2::Curl_easy) -> u64 {
    let mut num: u64 = 0;
    if !((*data).share).is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_CONNECT, CURL_LOCK_ACCESS_SINGLE);
    }
    num = (*(*data).state.conn_cache).num_conn;
    if !((*data).share).is_null() {
        Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
    }
    return num;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_conncache_find_bundle<'a1>(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut connc: * mut crate::src::lib::http2::conncache,
    mut hostp: Option<&'a1 mut * const i8>,
) -> * mut crate::src::lib::http2::connectbundle {
    let mut bundle: * mut crate::src::lib::http2::connectbundle = 0 as *mut connectbundle;
    if !((*data).share).is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_CONNECT, CURL_LOCK_ACCESS_SINGLE);
    }
    if !connc.is_null() {
        let mut key: [i8; 128] = [0; 128];
        hashkey(
            conn,
            key.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 128]>() as u64,
            borrow_mut(&mut hostp),
        );
        bundle = Curl_hash_pick(
            &mut (*connc).hash,
            key.as_mut_ptr() as *mut libc::c_void,
            strlen(key.as_mut_ptr()),
        ) as *mut connectbundle;
    }
    return bundle;
}
unsafe extern "C" fn conncache_add_bundle(
    mut connc: * mut crate::src::lib::http2::conncache,
    mut key: * mut i8,
    mut bundle: * mut crate::src::lib::http2::connectbundle,
) -> bool {
    let mut p: * mut core::ffi::c_void = Curl_hash_add(
        &mut (*connc).hash,
        key as *mut libc::c_void,
        strlen(key),
        bundle as *mut libc::c_void,
    );
    return if !p.is_null() { 1 as i32 } else { 0 as i32 } != 0;
}
unsafe extern "C" fn conncache_remove_bundle(
    mut connc: * mut crate::src::lib::http2::conncache,
    mut bundle: * mut crate::src::lib::http2::connectbundle,
) {
    let mut iter: crate::src::lib::conncache::Curl_hash_iterator<'_> = Curl_hash_iterator {
        hash: Option::<&'_ mut crate::src::lib::http2::Curl_hash>::None,
        slot_index: 0,
        current_element: 0 as *mut Curl_llist_element,
    };
    let mut he: * mut crate::src::lib::conncache::Curl_hash_element = (0 as * mut crate::src::lib::conncache::Curl_hash_element);
    if connc.is_null() {
        return;
    }
    Curl_hash_start_iterate(Some(&mut (*connc).hash), Some(&mut iter));
    he = Curl_hash_next_element(&mut iter);
    while !he.is_null() {
        if (*he).ptr == bundle as *mut libc::c_void {
            Curl_hash_delete(
                &mut (*connc).hash,
                ((*he).key).as_mut_ptr() as *mut libc::c_void,
                (*he).key_len,
            );
            return;
        }
        he = Curl_hash_next_element(&mut iter);
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_conncache_add_conn(mut data: * mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut current_block: u64;
    let mut result: u32 = CURLE_OK;
    let mut bundle: * mut crate::src::lib::http2::connectbundle = 0 as *mut connectbundle;
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    let mut connc: * mut crate::src::lib::http2::conncache = (*data).state.conn_cache;
    bundle = Curl_conncache_find_bundle(
        data,
        conn,
        (*data).state.conn_cache,
        Option::<&'_ mut * const i8>::None,
    );
    if bundle.is_null() {
        let mut rc: i32 = 0;
        let mut key: [i8; 128] = [0; 128];
        result = bundle_create(Some(&mut bundle));
        if result as u64 != 0 {
            current_block = 10723485634627595274;
        } else {
            hashkey(
                conn,
                key.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 128]>() as u64,
                Option::<&'_ mut * const i8>::None,
            );
            rc = conncache_add_bundle((*data).state.conn_cache, key.as_mut_ptr(), bundle)
                as i32;
            if rc == 0 {
                bundle_destroy(bundle);
                result = CURLE_OUT_OF_MEMORY;
                current_block = 10723485634627595274;
            } else {
                current_block = 17407779659766490442;
            }
        }
    } else {
        current_block = 17407779659766490442;
    }
    match current_block {
        17407779659766490442 => {
            bundle_add_conn(bundle, conn);
            let mut fresh7 = &mut ((*connc).next_connection_id);
            let mut fresh8 = *fresh7;
            *fresh7 = *fresh7 + 1;
            (*conn).connection_id = fresh8;
            let mut fresh9 = &mut ((*connc).num_conn);
            *fresh9 = (*fresh9).wrapping_add(1);
        }
        _ => {}
    }
    if !((*data).share).is_null() {
        Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_conncache_remove_conn(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut lock: bool,
) {
    let mut bundle: * mut crate::src::lib::http2::connectbundle = (*conn).bundle;
    let mut connc: * mut crate::src::lib::http2::conncache = (*data).state.conn_cache;
    if !bundle.is_null() {
        if lock {
            if !((*data).share).is_null() {
                Curl_share_lock(data, CURL_LOCK_DATA_CONNECT, CURL_LOCK_ACCESS_SINGLE);
            }
        }
        bundle_remove_conn(bundle, conn);
        if (*bundle).num_connections == 0 as i32 as u64 {
            conncache_remove_bundle(connc, bundle);
        }
        let mut fresh10 = &mut ((*conn).bundle);
        *fresh10 = 0 as *mut connectbundle;
        if !connc.is_null() {
            let mut fresh11 = &mut ((*connc).num_conn);
            *fresh11 = (*fresh11).wrapping_sub(1);
        }
        if lock {
            if !((*data).share).is_null() {
                Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
            }
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_conncache_foreach(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut connc: * mut crate::src::lib::http2::conncache,
    mut param: * mut core::ffi::c_void,
    mut func: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut crate::src::lib::http2::connectdata,_: * mut core::ffi::c_void,) -> i32>,
) -> bool {
    let mut iter: crate::src::lib::conncache::Curl_hash_iterator<'_> = Curl_hash_iterator {
        hash: Option::<&'_ mut crate::src::lib::http2::Curl_hash>::None,
        slot_index: 0,
        current_element: 0 as *mut Curl_llist_element,
    };
    let mut curr: * mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut he: * mut crate::src::lib::conncache::Curl_hash_element = (0 as * mut crate::src::lib::conncache::Curl_hash_element);
    if connc.is_null() {
        return 0 as i32 != 0;
    }
    if !((*data).share).is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_CONNECT, CURL_LOCK_ACCESS_SINGLE);
    }
    Curl_hash_start_iterate(Some(&mut (*connc).hash), Some(&mut iter));
    he = Curl_hash_next_element(&mut iter);
    while !he.is_null() {
        let mut bundle: * mut crate::src::lib::http2::connectbundle = (0 as * mut crate::src::lib::http2::connectbundle);
        bundle = (*he).ptr as *mut connectbundle;
        he = Curl_hash_next_element(&mut iter);
        curr = (*bundle).conn_list.head;
        while !curr.is_null() {
            let mut conn: * mut crate::src::lib::http2::connectdata = (*curr).ptr as *mut connectdata;
            curr = (*curr).next;
            if 1 as i32
                == func.expect("non-null function pointer")(data, conn, param)
            {
                if !((*data).share).is_null() {
                    Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
                }
                return 1 as i32 != 0;
            }
        }
    }
    if !((*data).share).is_null() {
        Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
    }
    return 0 as i32 != 0;
}
unsafe extern "C" fn conncache_find_first_connection<'a1>(
    mut connc: Option<&'a1 mut crate::src::lib::http2::conncache>,
) -> * mut crate::src::lib::http2::connectdata {
    let mut iter: crate::src::lib::conncache::Curl_hash_iterator<'_> = Curl_hash_iterator {
        hash: Option::<&'_ mut crate::src::lib::http2::Curl_hash>::None,
        slot_index: 0,
        current_element: 0 as *mut Curl_llist_element,
    };
    let mut he: * mut crate::src::lib::conncache::Curl_hash_element = (0 as * mut crate::src::lib::conncache::Curl_hash_element);
    let mut bundle: * mut crate::src::lib::http2::connectbundle = (0 as * mut crate::src::lib::http2::connectbundle);
    Curl_hash_start_iterate(Some(&mut (*(borrow_mut(&mut connc)).unwrap()).hash), Some(&mut iter));
    he = Curl_hash_next_element(&mut iter);
    while !he.is_null() {
        let mut curr: * mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
        bundle = (*he).ptr as *mut connectbundle;
        curr = (*bundle).conn_list.head;
        if !curr.is_null() {
            return (*curr).ptr as *mut connectdata;
        }
        he = Curl_hash_next_element(&mut iter);
    }
    return 0 as *mut connectdata;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_conncache_return_conn(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
) -> bool {
    let mut maxconnects: u64 = (if (*(*data).multi).maxconnects
        < 0 as i32 as i64
    {
        ((*(*data).multi).num_easy * 4 as i32) as i64
    } else {
        (*(*data).multi).maxconnects
    }) as size_t;
    let mut conn_candidate: * mut crate::src::lib::http2::connectdata = 0 as *mut connectdata;
    (*conn).lastused = Curl_now();
    if maxconnects > 0 as i32 as u64
        && Curl_conncache_size(data) > maxconnects
    {
        Curl_infof(
            data,
            b"Connection cache is full, closing the oldest one\0" as *const u8
                as *const i8,
        );
        conn_candidate = Curl_conncache_extract_oldest(data);
        if !conn_candidate.is_null() {
            Curl_disconnect(data, conn_candidate, 0 as i32 != 0);
        }
    }
    return if conn_candidate == conn { 0 as i32 } else { 1 as i32 } != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_conncache_extract_bundle(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut bundle: * mut crate::src::lib::http2::connectbundle,
) -> * mut crate::src::lib::http2::connectdata {
    let mut curr: * mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut highscore: i64 = -(1 as i32) as timediff_t;
    let mut score: i64 = 0;
    let mut now: crate::src::lib::http2::curltime = curltime { tv_sec: 0, tv_usec: 0 };
    let mut conn_candidate: * mut crate::src::lib::http2::connectdata = 0 as *mut connectdata;
    let mut conn: * mut crate::src::lib::http2::connectdata = 0 as *mut connectdata;
    now = Curl_now();
    curr = (*bundle).conn_list.head;
    while !curr.is_null() {
        conn = (*curr).ptr as *mut connectdata;
        if (*conn).easyq.size == 0 {
            score = Curl_timediff(now, (*conn).lastused);
            if score > highscore {
                highscore = score;
                conn_candidate = conn;
            }
        }
        curr = (*curr).next;
    }
    if !conn_candidate.is_null() {
        bundle_remove_conn(bundle, conn_candidate);
        let mut fresh12 = &mut ((*(*data).state.conn_cache).num_conn);
        *fresh12 = (*fresh12).wrapping_sub(1);
    }
    return conn_candidate;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_conncache_extract_oldest(
    mut data: * mut crate::src::lib::http2::Curl_easy,
) -> * mut crate::src::lib::http2::connectdata {
    let mut connc: * mut crate::src::lib::http2::conncache = (*data).state.conn_cache;
    let mut iter: crate::src::lib::conncache::Curl_hash_iterator<'_> = Curl_hash_iterator {
        hash: Option::<&'_ mut crate::src::lib::http2::Curl_hash>::None,
        slot_index: 0,
        current_element: 0 as *mut Curl_llist_element,
    };
    let mut curr: * mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut he: * mut crate::src::lib::conncache::Curl_hash_element = (0 as * mut crate::src::lib::conncache::Curl_hash_element);
    let mut highscore: i64 = -(1 as i32) as timediff_t;
    let mut score: i64 = 0;
    let mut now: crate::src::lib::http2::curltime = curltime { tv_sec: 0, tv_usec: 0 };
    let mut conn_candidate: * mut crate::src::lib::http2::connectdata = 0 as *mut connectdata;
    let mut bundle: * mut crate::src::lib::http2::connectbundle = 0 as *mut connectbundle;
    let mut bundle_candidate: * mut crate::src::lib::http2::connectbundle = 0 as *mut connectbundle;
    now = Curl_now();
    if !((*data).share).is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_CONNECT, CURL_LOCK_ACCESS_SINGLE);
    }
    Curl_hash_start_iterate(Some(&mut (*connc).hash), Some(&mut iter));
    he = Curl_hash_next_element(&mut iter);
    while !he.is_null() {
        let mut conn: * mut crate::src::lib::http2::connectdata = 0 as *mut connectdata;
        bundle = (*he).ptr as *mut connectbundle;
        curr = (*bundle).conn_list.head;
        while !curr.is_null() {
            conn = (*curr).ptr as *mut connectdata;
            if (*conn).easyq.size == 0 && ((*conn).bits).close() == 0
                && ((*conn).bits).connect_only() == 0
            {
                score = Curl_timediff(now, (*conn).lastused);
                if score > highscore {
                    highscore = score;
                    conn_candidate = conn;
                    bundle_candidate = bundle;
                }
            }
            curr = (*curr).next;
        }
        he = Curl_hash_next_element(&mut iter);
    }
    if !conn_candidate.is_null() {
        bundle_remove_conn(bundle_candidate, conn_candidate);
        let mut fresh13 = &mut ((*connc).num_conn);
        *fresh13 = (*fresh13).wrapping_sub(1);
    }
    if !((*data).share).is_null() {
        Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
    }
    return conn_candidate;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_conncache_close_all_connections<'a1>(
    mut connc: Option<&'a1 mut crate::src::lib::http2::conncache>,
) {
    let mut conn: * mut crate::src::lib::http2::connectdata = 0 as *mut connectdata;
    let mut buffer: [i8; 1025] = [0; 1025];
    if ((*(borrow_mut(&mut connc)).unwrap()).closure_handle).is_null() {
        return;
    }
    let mut fresh14 = &mut ((*(*(borrow_mut(&mut connc)).unwrap()).closure_handle).state.buffer);
    *fresh14 = buffer.as_mut_ptr();
    (*(*(borrow_mut(&mut connc)).unwrap()).closure_handle).set.buffer_size = 1024 as i32 as i64;
    conn = conncache_find_first_connection(borrow_mut(&mut connc));
    while !conn.is_null() {
        let mut pipe_st: crate::src::lib::conncache::sigpipe_ignore = sigpipe_ignore {
            old_pipe_act: sigaction {
                __sigaction_handler: C2RustUnnamed_6 {
                    sa_handler: None,
                },
                sa_mask: __sigset_t { __val: [0; 16] },
                sa_flags: 0,
                sa_restorer: None,
            },
            no_signal: false,
        };
        sigpipe_ignore((*(borrow_mut(&mut connc)).unwrap()).closure_handle, Some(&mut pipe_st));
        Curl_conncontrol(conn, 1 as i32);
        Curl_conncache_remove_conn((*(borrow_mut(&mut connc)).unwrap()).closure_handle, conn, 1 as i32 != 0);
        Curl_disconnect((*(borrow_mut(&mut connc)).unwrap()).closure_handle, conn, 0 as i32 != 0);
        sigpipe_restore(Some(&mut pipe_st));
        conn = conncache_find_first_connection(borrow_mut(&mut connc));
    }
    let mut fresh15 = &mut ((*(*(borrow_mut(&mut connc)).unwrap()).closure_handle).state.buffer);
    *fresh15 = 0 as *mut i8;
    if !((*(borrow_mut(&mut connc)).unwrap()).closure_handle).is_null() {
        let mut pipe_st_0: crate::src::lib::conncache::sigpipe_ignore = sigpipe_ignore {
            old_pipe_act: sigaction {
                __sigaction_handler: C2RustUnnamed_6 {
                    sa_handler: None,
                },
                sa_mask: __sigset_t { __val: [0; 16] },
                sa_flags: 0,
                sa_restorer: None,
            },
            no_signal: false,
        };
        sigpipe_ignore((*(borrow_mut(&mut connc)).unwrap()).closure_handle, Some(&mut pipe_st_0));
        Curl_hostcache_clean(
            (*(borrow_mut(&mut connc)).unwrap()).closure_handle,
            (*(*(borrow_mut(&mut connc)).unwrap()).closure_handle).dns.hostcache,
        );
        Curl_close(Some(&mut (*(borrow_mut(&mut connc)).unwrap()).closure_handle));
        sigpipe_restore(Some(&mut pipe_st_0));
    }
}
use crate::laertes_rt::*;
