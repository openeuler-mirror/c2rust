use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn fclose(__stream: * mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn fopen(_: * const i8, _: * const i8) -> * mut crate::src::lib::http2::_IO_FILE;
    fn fread(
        _: * mut core::ffi::c_void,
        _: u64,
        _: u64,
        _: * mut crate::src::lib::http2::_IO_FILE,
    ) -> u64;
    fn fseek(
        __stream: * mut crate::src::lib::http2::_IO_FILE,
        __off: i64,
        __whence: i32,
    ) -> i32;
    fn ftell(__stream: * mut crate::src::lib::http2::_IO_FILE) -> i64;
    
    fn strcpy(_: * mut i8, _: * const i8) -> * mut i8;
    fn strncpy(
        _: * mut i8,
        _: * const i8,
        _: u64,
    ) -> * mut i8;
    
    fn memcpy(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn memset(
        _: * mut core::ffi::c_void,
        _: i32,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn memcmp(
        _: * const core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> i32;
    fn strcmp(_: * const i8, _: * const i8) -> i32;
    fn strncmp(
        _: * const i8,
        _: * const i8,
        _: u64,
    ) -> i32;
    fn strstr(_: * const i8, _: * const i8) -> * mut i8;
    fn strlen(_: * const i8) -> u64;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::base64::Curl_base64_decode;
pub use crate::src::lib::base64::Curl_base64_encode;
pub use crate::src::lib::getenv::curl_getenv;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::progress::Curl_pgrsTime;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::sendf::Curl_recv_plain;
pub use crate::src::lib::sendf::Curl_send_plain;
pub use crate::src::lib::share::Curl_share_lock;
pub use crate::src::lib::share::Curl_share_unlock;
pub use crate::src::lib::slist::Curl_slist_append_nodup;
pub use crate::src::lib::slist::curl_slist_free_all;
pub use crate::src::lib::strcase::Curl_safe_strcasecompare;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::warnless::curlx_sotouz;
pub use crate::src::lib::altsvc::altsvcinfo;
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
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::easy::Curl_ccalloc;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_cstrdup;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::lib::vtls::openssl::Curl_ssl_openssl;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
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
pub type curl_strdup_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 i8>,) -> Option<&'a2 mut i8>>;
pub type curl_calloc_callback<'a1> = Option<unsafe extern "C"  fn(_: u64,_: u64,) -> Option<&'a1 mut core::ffi::c_void>>;
pub type C2RustUnnamed_6 = u32;
pub const CURL_SSLVERSION_LAST: C2RustUnnamed_6 = 8;
pub const CURL_SSLVERSION_TLSv1_3: C2RustUnnamed_6 = 7;
pub const CURL_SSLVERSION_TLSv1_2: C2RustUnnamed_6 = 6;
pub const CURL_SSLVERSION_TLSv1_1: C2RustUnnamed_6 = 5;
pub const CURL_SSLVERSION_TLSv1_0: C2RustUnnamed_6 = 4;
pub const CURL_SSLVERSION_SSLv3: C2RustUnnamed_6 = 3;
pub const CURL_SSLVERSION_SSLv2: C2RustUnnamed_6 = 2;
pub const CURL_SSLVERSION_TLSv1: C2RustUnnamed_6 = 1;
pub const CURL_SSLVERSION_DEFAULT: C2RustUnnamed_6 = 0;
pub type C2RustUnnamed_7 = u32;
pub const CURL_SSLVERSION_MAX_LAST: C2RustUnnamed_7 = 524288;
pub const CURL_SSLVERSION_MAX_TLSv1_3: C2RustUnnamed_7 = 458752;
pub const CURL_SSLVERSION_MAX_TLSv1_2: C2RustUnnamed_7 = 393216;
pub const CURL_SSLVERSION_MAX_TLSv1_1: C2RustUnnamed_7 = 327680;
pub const CURL_SSLVERSION_MAX_TLSv1_0: C2RustUnnamed_7 = 262144;
pub const CURL_SSLVERSION_MAX_DEFAULT: C2RustUnnamed_7 = 65536;
pub const CURL_SSLVERSION_MAX_NONE: C2RustUnnamed_7 = 0;
// #[derive(Copy, Clone)]

pub type curl_ssl_backend = crate::src::lib::getinfo::curl_ssl_backend;
pub type CURLsslset = u32;
pub const CURLSSLSET_NO_BACKENDS: CURLsslset = 3;
pub const CURLSSLSET_TOO_LATE: CURLsslset = 2;
pub const CURLSSLSET_UNKNOWN_BACKEND: CURLsslset = 1;
pub const CURLSSLSET_OK: CURLsslset = 0;
// #[derive(Copy, Clone)]

pub type Curl_ssl = crate::src::lib::getinfo::Curl_ssl;
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
pub type CURLSHcode = u32;
pub const CURLSHE_LAST: CURLSHcode = 6;
pub const CURLSHE_NOT_BUILT_IN: CURLSHcode = 5;
pub const CURLSHE_NOMEM: CURLSHcode = 4;
pub const CURLSHE_INVALID: CURLSHcode = 3;
pub const CURLSHE_IN_USE: CURLSHcode = 2;
pub const CURLSHE_BAD_OPTION: CURLSHcode = 1;
pub const CURLSHE_OK: CURLSHcode = 0;
pub type timerid = u32;
pub const TIMER_LAST: timerid = 11;
pub const TIMER_REDIRECT: timerid = 10;
pub const TIMER_STARTACCEPT: timerid = 9;
pub const TIMER_POSTRANSFER: timerid = 8;
pub const TIMER_STARTTRANSFER: timerid = 7;
pub const TIMER_PRETRANSFER: timerid = 6;
pub const TIMER_APPCONNECT: timerid = 5;
pub const TIMER_CONNECT: timerid = 4;
pub const TIMER_NAMELOOKUP: timerid = 3;
pub const TIMER_STARTSINGLE: timerid = 2;
pub const TIMER_STARTOP: timerid = 1;
pub const TIMER_NONE: timerid = 0;
unsafe extern "C" fn blobdup<'a1>(
    mut dest: Option<&'a1 mut * mut crate::src::lib::http2::curl_blob>,
    mut src: * mut crate::src::lib::http2::curl_blob,
) -> u32 {
    if !src.is_null() {
        let mut d: * mut crate::src::lib::http2::curl_blob = 0 as *mut curl_blob;
        d = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )(
            (::std::mem::size_of::<curl_blob>() as u64)
                .wrapping_add((*src).len),
        ) as *mut curl_blob;
        if d.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (*d).len = (*src).len;
        (*d).flags = 1 as i32 as u32;
        let mut fresh0 = &mut ((*d).data);
        *fresh0 = (d as *mut i8)
            .offset(::std::mem::size_of::<curl_blob>() as u64 as isize)
            as *mut libc::c_void;
        memcpy((*d).data, (*src).data, (*src).len);
        *(borrow_mut(&mut dest)).unwrap() = d;
    }
    return CURLE_OK;
}
unsafe extern "C" fn blobcmp(
    mut first: * mut crate::src::lib::http2::curl_blob,
    mut second: * mut crate::src::lib::http2::curl_blob,
) -> bool {
    if first.is_null() && second.is_null() {
        return 1 as i32 != 0;
    }
    if first.is_null() || second.is_null() {
        return 0 as i32 != 0;
    }
    if (*first).len != (*second).len {
        return 0 as i32 != 0;
    }
    return memcmp((*first).data, (*second).data, (*first).len) == 0;
}
unsafe extern "C" fn safecmp(
    mut a: * mut i8,
    mut b: * mut i8,
) -> bool {
    if !a.is_null() && !b.is_null() {
        return strcmp(a, b) == 0
    } else {
        if a.is_null() && b.is_null() {
            return 1 as i32 != 0;
        }
    }
    return 0 as i32 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_config_matches<'a1>(
    mut data: * mut crate::src::lib::http2::ssl_primary_config,
    mut needle: Option<&'a1 mut crate::src::lib::http2::ssl_primary_config>,
) -> bool {
    if (*data).version == (*(borrow(& needle)).unwrap()).version
        && (*data).version_max == (*(borrow(& needle)).unwrap()).version_max
        && (*data).verifypeer() as i32 == (*(borrow(& needle)).unwrap()).verifypeer() as i32
        && (*data).verifyhost() as i32 == (*(borrow(& needle)).unwrap()).verifyhost() as i32
        && (*data).verifystatus() as i32
            == (*(borrow(& needle)).unwrap()).verifystatus() as i32
        && blobcmp((*data).cert_blob, (*(borrow_mut(&mut needle)).unwrap()).cert_blob) as i32 != 0
        && blobcmp((*data).ca_info_blob, (*(borrow_mut(&mut needle)).unwrap()).ca_info_blob) as i32 != 0
        && blobcmp((*data).issuercert_blob, (*(borrow_mut(&mut needle)).unwrap()).issuercert_blob) as i32
            != 0 && safecmp((*data).CApath, (*(borrow_mut(&mut needle)).unwrap()).CApath) as i32 != 0
        && safecmp((*data).CAfile, (*(borrow_mut(&mut needle)).unwrap()).CAfile) as i32 != 0
        && safecmp((*data).issuercert, (*(borrow_mut(&mut needle)).unwrap()).issuercert) as i32 != 0
        && safecmp((*data).clientcert, (*(borrow_mut(&mut needle)).unwrap()).clientcert) as i32 != 0
        && safecmp((*data).random_file, (*(borrow_mut(&mut needle)).unwrap()).random_file) as i32 != 0
        && safecmp((*data).egdsocket, (*(borrow_mut(&mut needle)).unwrap()).egdsocket) as i32 != 0
        && Curl_safe_strcasecompare((*data).cipher_list, (*(borrow(& needle)).unwrap()).cipher_list) != 0
        && Curl_safe_strcasecompare((*data).cipher_list13, (*(borrow(& needle)).unwrap()).cipher_list13) != 0
        && Curl_safe_strcasecompare((*data).curves, (*(borrow(& needle)).unwrap()).curves) != 0
        && Curl_safe_strcasecompare((*data).pinned_key, (*(borrow(& needle)).unwrap()).pinned_key) != 0
    {
        return 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_clone_primary_ssl_config<'a1>(
    mut source: * mut crate::src::lib::http2::ssl_primary_config,
    mut dest: Option<&'a1 mut crate::src::lib::http2::ssl_primary_config>,
) -> bool {
    (*(borrow_mut(&mut dest)).unwrap()).version = (*source).version;
    (*(borrow_mut(&mut dest)).unwrap()).version_max = (*source).version_max;
    (*(borrow_mut(&mut dest)).unwrap()).set_verifypeer((*source).verifypeer());
    (*(borrow_mut(&mut dest)).unwrap()).set_verifyhost((*source).verifyhost());
    (*(borrow_mut(&mut dest)).unwrap()).set_verifystatus((*source).verifystatus());
    (*(borrow_mut(&mut dest)).unwrap()).set_sessionid((*source).sessionid());
    if blobdup(Some(&mut (*(borrow_mut(&mut dest)).unwrap()).cert_blob), (*source).cert_blob) as u64 != 0 {
        return 0 as i32 != 0;
    }
    if blobdup(Some(&mut (*(borrow_mut(&mut dest)).unwrap()).ca_info_blob), (*source).ca_info_blob) as u64 != 0 {
        return 0 as i32 != 0;
    }
    if blobdup(Some(&mut (*(borrow_mut(&mut dest)).unwrap()).issuercert_blob), (*source).issuercert_blob) as u64 != 0 {
        return 0 as i32 != 0;
    }
    if !((*source).CApath).is_null() {
        let mut fresh1 = &mut ((*(borrow_mut(&mut dest)).unwrap()).CApath);
        *fresh1 = Curl_cstrdup.expect("non-null function pointer")((*source).CApath);
        if ((*(borrow_mut(&mut dest)).unwrap()).CApath).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let mut fresh2 = &mut ((*(borrow_mut(&mut dest)).unwrap()).CApath);
        *fresh2 = 0 as *mut i8;
    }
    if !((*source).CAfile).is_null() {
        let mut fresh3 = &mut ((*(borrow_mut(&mut dest)).unwrap()).CAfile);
        *fresh3 = Curl_cstrdup.expect("non-null function pointer")((*source).CAfile);
        if ((*(borrow_mut(&mut dest)).unwrap()).CAfile).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let mut fresh4 = &mut ((*(borrow_mut(&mut dest)).unwrap()).CAfile);
        *fresh4 = 0 as *mut i8;
    }
    if !((*source).issuercert).is_null() {
        let mut fresh5 = &mut ((*(borrow_mut(&mut dest)).unwrap()).issuercert);
        *fresh5 = Curl_cstrdup.expect("non-null function pointer")((*source).issuercert);
        if ((*(borrow_mut(&mut dest)).unwrap()).issuercert).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let mut fresh6 = &mut ((*(borrow_mut(&mut dest)).unwrap()).issuercert);
        *fresh6 = 0 as *mut i8;
    }
    if !((*source).clientcert).is_null() {
        let mut fresh7 = &mut ((*(borrow_mut(&mut dest)).unwrap()).clientcert);
        *fresh7 = Curl_cstrdup.expect("non-null function pointer")((*source).clientcert);
        if ((*(borrow_mut(&mut dest)).unwrap()).clientcert).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let mut fresh8 = &mut ((*(borrow_mut(&mut dest)).unwrap()).clientcert);
        *fresh8 = 0 as *mut i8;
    }
    if !((*source).random_file).is_null() {
        let mut fresh9 = &mut ((*(borrow_mut(&mut dest)).unwrap()).random_file);
        *fresh9 = Curl_cstrdup
            .expect("non-null function pointer")((*source).random_file);
        if ((*(borrow_mut(&mut dest)).unwrap()).random_file).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let mut fresh10 = &mut ((*(borrow_mut(&mut dest)).unwrap()).random_file);
        *fresh10 = 0 as *mut i8;
    }
    if !((*source).egdsocket).is_null() {
        let mut fresh11 = &mut ((*(borrow_mut(&mut dest)).unwrap()).egdsocket);
        *fresh11 = Curl_cstrdup.expect("non-null function pointer")((*source).egdsocket);
        if ((*(borrow_mut(&mut dest)).unwrap()).egdsocket).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let mut fresh12 = &mut ((*(borrow_mut(&mut dest)).unwrap()).egdsocket);
        *fresh12 = 0 as *mut i8;
    }
    if !((*source).cipher_list).is_null() {
        let mut fresh13 = &mut ((*(borrow_mut(&mut dest)).unwrap()).cipher_list);
        *fresh13 = Curl_cstrdup
            .expect("non-null function pointer")((*source).cipher_list);
        if ((*(borrow_mut(&mut dest)).unwrap()).cipher_list).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let mut fresh14 = &mut ((*(borrow_mut(&mut dest)).unwrap()).cipher_list);
        *fresh14 = 0 as *mut i8;
    }
    if !((*source).cipher_list13).is_null() {
        let mut fresh15 = &mut ((*(borrow_mut(&mut dest)).unwrap()).cipher_list13);
        *fresh15 = Curl_cstrdup
            .expect("non-null function pointer")((*source).cipher_list13);
        if ((*(borrow_mut(&mut dest)).unwrap()).cipher_list13).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let mut fresh16 = &mut ((*(borrow_mut(&mut dest)).unwrap()).cipher_list13);
        *fresh16 = 0 as *mut i8;
    }
    if !((*source).pinned_key).is_null() {
        let mut fresh17 = &mut ((*(borrow_mut(&mut dest)).unwrap()).pinned_key);
        *fresh17 = Curl_cstrdup
            .expect("non-null function pointer")((*source).pinned_key);
        if ((*(borrow_mut(&mut dest)).unwrap()).pinned_key).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let mut fresh18 = &mut ((*(borrow_mut(&mut dest)).unwrap()).pinned_key);
        *fresh18 = 0 as *mut i8;
    }
    if !((*source).curves).is_null() {
        let mut fresh19 = &mut ((*(borrow_mut(&mut dest)).unwrap()).curves);
        *fresh19 = Curl_cstrdup.expect("non-null function pointer")((*source).curves);
        if ((*(borrow_mut(&mut dest)).unwrap()).curves).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let mut fresh20 = &mut ((*(borrow_mut(&mut dest)).unwrap()).curves);
        *fresh20 = 0 as *mut i8;
    }
    return 1 as i32 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_free_primary_ssl_config<'a1>(
    mut sslc: Option<&'a1 mut crate::src::lib::http2::ssl_primary_config>,
) {
    Curl_cfree.expect("non-null function pointer")((*(borrow_mut(&mut sslc)).unwrap()).CApath as *mut libc::c_void);
    let mut fresh21 = &mut ((*(borrow_mut(&mut sslc)).unwrap()).CApath);
    *fresh21 = 0 as *mut i8;
    Curl_cfree.expect("non-null function pointer")((*(borrow_mut(&mut sslc)).unwrap()).CAfile as *mut libc::c_void);
    let mut fresh22 = &mut ((*(borrow_mut(&mut sslc)).unwrap()).CAfile);
    *fresh22 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*(borrow_mut(&mut sslc)).unwrap()).issuercert as *mut libc::c_void);
    let mut fresh23 = &mut ((*(borrow_mut(&mut sslc)).unwrap()).issuercert);
    *fresh23 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*(borrow_mut(&mut sslc)).unwrap()).clientcert as *mut libc::c_void);
    let mut fresh24 = &mut ((*(borrow_mut(&mut sslc)).unwrap()).clientcert);
    *fresh24 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*(borrow_mut(&mut sslc)).unwrap()).random_file as *mut libc::c_void);
    let mut fresh25 = &mut ((*(borrow_mut(&mut sslc)).unwrap()).random_file);
    *fresh25 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*(borrow_mut(&mut sslc)).unwrap()).egdsocket as *mut libc::c_void);
    let mut fresh26 = &mut ((*(borrow_mut(&mut sslc)).unwrap()).egdsocket);
    *fresh26 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*(borrow_mut(&mut sslc)).unwrap()).cipher_list as *mut libc::c_void);
    let mut fresh27 = &mut ((*(borrow_mut(&mut sslc)).unwrap()).cipher_list);
    *fresh27 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*(borrow_mut(&mut sslc)).unwrap()).cipher_list13 as *mut libc::c_void);
    let mut fresh28 = &mut ((*(borrow_mut(&mut sslc)).unwrap()).cipher_list13);
    *fresh28 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*(borrow_mut(&mut sslc)).unwrap()).pinned_key as *mut libc::c_void);
    let mut fresh29 = &mut ((*(borrow_mut(&mut sslc)).unwrap()).pinned_key);
    *fresh29 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*(borrow_mut(&mut sslc)).unwrap()).cert_blob as *mut libc::c_void);
    let mut fresh30 = &mut ((*(borrow_mut(&mut sslc)).unwrap()).cert_blob);
    *fresh30 = 0 as *mut curl_blob;
    Curl_cfree
        .expect("non-null function pointer")((*(borrow_mut(&mut sslc)).unwrap()).ca_info_blob as *mut libc::c_void);
    let mut fresh31 = &mut ((*(borrow_mut(&mut sslc)).unwrap()).ca_info_blob);
    *fresh31 = 0 as *mut curl_blob;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*(borrow_mut(&mut sslc)).unwrap()).issuercert_blob as *mut libc::c_void);
    let mut fresh32 = &mut ((*(borrow_mut(&mut sslc)).unwrap()).issuercert_blob);
    *fresh32 = 0 as *mut curl_blob;
    Curl_cfree.expect("non-null function pointer")((*(borrow_mut(&mut sslc)).unwrap()).curves as *mut libc::c_void);
    let mut fresh33 = &mut ((*(borrow_mut(&mut sslc)).unwrap()).curves);
    *fresh33 = 0 as *mut i8;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_backend() -> i32 {
    multissl_setup(0 as *const Curl_ssl);
    return (*Curl_ssl).info.id as i32;
}
static mut init_ssl: bool = 0 as i32 != 0;
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_init() -> i32 {
    if init_ssl {
        return 1 as i32;
    }
    init_ssl = 1 as i32 != 0;
    return ((*Curl_ssl).init).expect("non-null function pointer")();
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_cleanup() {
    if init_ssl {
        ((*Curl_ssl).cleanup).expect("non-null function pointer")();
        init_ssl = 0 as i32 != 0;
    }
}
unsafe extern "C" fn ssl_prefs_check(mut data: * mut crate::src::lib::http2::Curl_easy) -> bool {
    let sslver: i64 = (*data).set.ssl.primary.version;
    if sslver < 0 as i32 as i64
        || sslver >= CURL_SSLVERSION_LAST as i32 as i64
    {
        Curl_failf(
            data,
            b"Unrecognized parameter value passed via CURLOPT_SSLVERSION\0" as *const u8
                as *const i8,
        );
        return 0 as i32 != 0;
    }
    match (*data).set.ssl.primary.version_max {
        0 | 65536 => {}
        _ => {
            if ((*data).set.ssl.primary.version_max >> 16 as i32) < sslver {
                Curl_failf(
                    data,
                    b"CURL_SSLVERSION_MAX incompatible with CURL_SSLVERSION\0"
                        as *const u8 as *const i8,
                );
                return 0 as i32 != 0;
            }
        }
    }
    return 1 as i32 != 0;
}
unsafe extern "C" fn ssl_connect_init_proxy(
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut sockindex: i32,
) -> u32 {
    if ssl_connection_complete as i32 as u32
        == (*conn).ssl[sockindex as usize].state as u32
        && ((*conn).proxy_ssl[sockindex as usize]).use_0() == 0
    {
        let mut pbdata: * mut crate::src::lib::vtls::openssl::ssl_backend_data = 0 as *mut ssl_backend_data;
        if (*Curl_ssl).supports
            & ((1 as i32) << 4 as i32) as u32 == 0
        {
            return CURLE_NOT_BUILT_IN;
        }
        pbdata = (*conn).proxy_ssl[sockindex as usize].backend;
        (*conn).proxy_ssl[sockindex as usize] = (*conn).ssl[sockindex as usize];
        memset(
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize)
                as *mut ssl_connect_data as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<ssl_connect_data>() as u64,
        );
        memset(
            pbdata as *mut libc::c_void,
            0 as i32,
            (*Curl_ssl).sizeof_ssl_backend_data,
        );
        let mut fresh34 = &mut ((*conn).ssl[sockindex as usize].backend);
        *fresh34 = pbdata;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_connect(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut sockindex: i32,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    if (*conn).bits.proxy_ssl_connected[sockindex as usize] {
        result = ssl_connect_init_proxy(conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    if !ssl_prefs_check(data) {
        return CURLE_SSL_CONNECT_ERROR;
    }
    let mut fresh35 = &mut ((*conn).ssl[sockindex as usize]);
    (*fresh35).set_use_0(1 as i32 as bit);
    (*conn).ssl[sockindex as usize].state = ssl_connection_negotiating;
    result = ((*Curl_ssl).connect_blocking)
        .expect("non-null function pointer")(data, conn, sockindex);
    if result as u64 == 0 {
        Curl_pgrsTime(data, TIMER_APPCONNECT);
    } else {
        let mut fresh36 = &mut ((*conn).ssl[sockindex as usize]);
        (*fresh36).set_use_0(0 as i32 as bit);
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_connect_nonblocking(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut isproxy: bool,
    mut sockindex: i32,
    mut done: * mut bool,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    if (*conn).bits.proxy_ssl_connected[sockindex as usize] {
        result = ssl_connect_init_proxy(conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    if !ssl_prefs_check(data) {
        return CURLE_SSL_CONNECT_ERROR;
    }
    let mut fresh37 = &mut ((*conn).ssl[sockindex as usize]);
    (*fresh37).set_use_0(1 as i32 as bit);
    result = ((*Curl_ssl).connect_nonblocking)
        .expect("non-null function pointer")(data, conn, sockindex, done);
    if result as u64 != 0 {
        let mut fresh38 = &mut ((*conn).ssl[sockindex as usize]);
        (*fresh38).set_use_0(0 as i32 as bit);
    } else if *done as i32 != 0 && !isproxy {
        Curl_pgrsTime(data, TIMER_APPCONNECT);
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_sessionid_lock(mut data: * mut crate::src::lib::http2::Curl_easy) {
    if !((*data).share).is_null()
        && (*(*data).share).specifier
            & ((1 as i32) << CURL_LOCK_DATA_SSL_SESSION as i32)
                as u32 != 0
    {
        Curl_share_lock(data, CURL_LOCK_DATA_SSL_SESSION, CURL_LOCK_ACCESS_SINGLE);
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_sessionid_unlock(mut data: * mut crate::src::lib::http2::Curl_easy) {
    if !((*data).share).is_null()
        && (*(*data).share).specifier
            & ((1 as i32) << CURL_LOCK_DATA_SSL_SESSION as i32)
                as u32 != 0
    {
        Curl_share_unlock(data, CURL_LOCK_DATA_SSL_SESSION);
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_getsessionid<'a1, 'a2>(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    isProxy: bool,
    mut ssl_sessionid: Option<&'a1 mut * mut core::ffi::c_void>,
    mut idsize: Option<&'a2 mut u64>,
    mut sockindex: i32,
) -> bool {
    let mut check: Option<&'_ mut crate::src::lib::http2::Curl_ssl_session> = Option::<&'_ mut crate::src::lib::http2::Curl_ssl_session>::None;
    let mut i: u64 = 0;
    let mut general_age: Option<&'_ mut i64> = Option::<&'_ mut i64>::None;
    let mut no_match: bool = 1 as i32 != 0;
    let ssl_config: * mut crate::src::lib::http2::ssl_primary_config = if isProxy as i32 != 0 {
        &mut (*conn).proxy_ssl_config
    } else {
        &mut (*conn).ssl_config
    };
    let name: * const i8 = if isProxy as i32 != 0 {
        (*conn).http_proxy.host.name
    } else {
        (*conn).host.name
    };
    let mut port: i32 = if isProxy as i32 != 0 {
        (*conn).port
    } else {
        (*conn).remote_port
    };
    *(borrow_mut(&mut ssl_sessionid)).unwrap() = 0 as *mut libc::c_void;
    if (if CURLPROXY_HTTPS as i32 as u32
        == (*conn).http_proxy.proxytype as u32
        && ssl_connection_complete as i32 as u32
            != (*conn)
                .proxy_ssl[(if (*conn).sock[1 as i32 as usize]
                    == -(1 as i32)
                {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                .state as u32
    {
        ((*data).set.proxy_ssl.primary).sessionid() as i32
    } else {
        ((*data).set.ssl.primary).sessionid() as i32
    }) == 0 || ((*data).state.session).is_null()
    {
        return 1 as i32 != 0;
    }
    if !((*data).share).is_null()
        && (*(*data).share).specifier
            & ((1 as i32) << CURL_LOCK_DATA_SSL_SESSION as i32)
                as u32 != 0
    {
        general_age = Some(&mut (*(*data).share).sessionage);
    } else {
        general_age = Some(&mut (*data).state.sessionage);
    }
    i = 0 as i32 as size_t;
    while i < (*data).set.general_ssl.max_ssl_sessions {
        check = Some(&mut *((*data).state.session).offset(i as isize));
        if !((*(borrow(& check)).unwrap()).sessionid).is_null() {
            if Curl_strcasecompare(name, (*(borrow(& check)).unwrap()).name) != 0
                && (((*conn).bits).conn_to_host() == 0
                    && ((*(borrow(& check)).unwrap()).conn_to_host).is_null()
                    || ((*conn).bits).conn_to_host() as i32 != 0
                        && !((*(borrow(& check)).unwrap()).conn_to_host).is_null()
                        && Curl_strcasecompare(
                            (*conn).conn_to_host.name,
                            (*(borrow(& check)).unwrap()).conn_to_host,
                        ) != 0)
                && (((*conn).bits).conn_to_port() == 0
                    && (*(borrow(& check)).unwrap()).conn_to_port == -(1 as i32)
                    || ((*conn).bits).conn_to_port() as i32 != 0
                        && (*(borrow(& check)).unwrap()).conn_to_port != -(1 as i32)
                        && (*conn).conn_to_port == (*(borrow(& check)).unwrap()).conn_to_port)
                && port == (*(borrow(& check)).unwrap()).remote_port
                && Curl_strcasecompare((*(*conn).handler).scheme, (*(borrow(& check)).unwrap()).scheme) != 0
                && Curl_ssl_config_matches(ssl_config, Some(&mut (*(borrow_mut(&mut check)).unwrap()).ssl_config))
                    as i32 != 0
            {
                *(borrow_mut(&mut general_age)).unwrap() += 1;
                (*(borrow_mut(&mut check)).unwrap()).age = *(borrow_mut(&mut general_age)).unwrap();
                *(borrow_mut(&mut ssl_sessionid)).unwrap() = (*(borrow_mut(&mut check)).unwrap()).sessionid;
                if !borrow(& idsize).is_none() {
                    *(borrow_mut(&mut idsize)).unwrap() = (*(borrow_mut(&mut check)).unwrap()).idsize;
                }
                no_match = 0 as i32 != 0;
                break;
            }
        }
        i = i.wrapping_add(1);
    }
    return no_match;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_kill_session<'a1>(mut session: Option<&'a1 mut crate::src::lib::http2::Curl_ssl_session>) {
    if !((*(borrow_mut(&mut session)).unwrap()).sessionid).is_null() {
        ((*Curl_ssl).session_free)
            .expect("non-null function pointer")((*(borrow_mut(&mut session)).unwrap()).sessionid);
        let mut fresh39 = &mut ((*(borrow_mut(&mut session)).unwrap()).sessionid);
        *fresh39 = 0 as *mut libc::c_void;
        (*(borrow_mut(&mut session)).unwrap()).age = 0 as i32 as i64;
        Curl_free_primary_ssl_config(Some(&mut (*(borrow_mut(&mut session)).unwrap()).ssl_config));
        Curl_cfree
            .expect("non-null function pointer")((*(borrow_mut(&mut session)).unwrap()).name as *mut libc::c_void);
        let mut fresh40 = &mut ((*(borrow_mut(&mut session)).unwrap()).name);
        *fresh40 = 0 as *mut i8;
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*(borrow_mut(&mut session)).unwrap()).conn_to_host as *mut libc::c_void);
        let mut fresh41 = &mut ((*(borrow_mut(&mut session)).unwrap()).conn_to_host);
        *fresh41 = 0 as *mut i8;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_delsessionid(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut ssl_sessionid: * mut core::ffi::c_void,
) {
    let mut i: u64 = 0;
    i = 0 as i32 as size_t;
    while i < (*data).set.general_ssl.max_ssl_sessions {
        let mut check: Option<&'_ mut crate::src::lib::http2::Curl_ssl_session> = Some(&mut *((*data).state.session)
            .offset(i as isize));
        if (*(borrow(& check)).unwrap()).sessionid == ssl_sessionid {
            Curl_ssl_kill_session(borrow_mut(&mut check));
            break;
        } else {
            i = i.wrapping_add(1);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_addsessionid(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    isProxy: bool,
    mut ssl_sessionid: * mut core::ffi::c_void,
    mut idsize: u64,
    mut sockindex: i32,
) -> u32 {
    let mut i: u64 = 0;
    let mut store: Option<&'_ mut crate::src::lib::http2::Curl_ssl_session> = Option::<&'_ mut crate::src::lib::http2::Curl_ssl_session>::None;
    let mut oldest_age: i64 = 0;
    let mut clone_host: * mut i8 = 0 as *mut i8;
    let mut clone_conn_to_host: * mut i8 = 0 as *mut i8;
    let mut conn_to_port: i32 = 0;
    let mut general_age: Option<&'_ mut i64> = Option::<&'_ mut i64>::None;
    let ssl_config: * mut crate::src::lib::http2::ssl_primary_config = if isProxy as i32 != 0 {
        &mut (*conn).proxy_ssl_config
    } else {
        &mut (*conn).ssl_config
    };
    let mut hostname: * const i8 = if isProxy as i32 != 0 {
        (*conn).http_proxy.host.name
    } else {
        (*conn).host.name
    };
    if ((*data).state.session).is_null() {
        return CURLE_OK;
    }
    store = Some(&mut *((*data).state.session).offset(0 as i32 as isize));
    oldest_age = (*((*data).state.session).offset(0 as i32 as isize)).age;
    clone_host = Curl_cstrdup.expect("non-null function pointer")(hostname);
    if clone_host.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if ((*conn).bits).conn_to_host() != 0 {
        clone_conn_to_host = Curl_cstrdup
            .expect("non-null function pointer")((*conn).conn_to_host.name);
        if clone_conn_to_host.is_null() {
            Curl_cfree
                .expect("non-null function pointer")(clone_host as *mut libc::c_void);
            return CURLE_OUT_OF_MEMORY;
        }
    } else {
        clone_conn_to_host = 0 as *mut i8;
    }
    if ((*conn).bits).conn_to_port() != 0 {
        conn_to_port = (*conn).conn_to_port;
    } else {
        conn_to_port = -(1 as i32);
    }
    if !((*data).share).is_null()
        && (*(*data).share).specifier
            & ((1 as i32) << CURL_LOCK_DATA_SSL_SESSION as i32)
                as u32 != 0
    {
        general_age = Some(&mut (*(*data).share).sessionage);
    } else {
        general_age = Some(&mut (*data).state.sessionage);
    }
    i = 1 as i32 as size_t;
    while i < (*data).set.general_ssl.max_ssl_sessions
        && !((*((*data).state.session).offset(i as isize)).sessionid).is_null()
    {
        if (*((*data).state.session).offset(i as isize)).age < oldest_age {
            oldest_age = (*((*data).state.session).offset(i as isize)).age;
            store = Some(&mut *((*data).state.session).offset(i as isize));
        }
        i = i.wrapping_add(1);
    }
    if i == (*data).set.general_ssl.max_ssl_sessions {
        Curl_ssl_kill_session(borrow_mut(&mut store));
    } else {
        store = Some(&mut *((*data).state.session).offset(i as isize));
    }
    let mut fresh42 = &mut ((*(borrow_mut(&mut store)).unwrap()).sessionid);
    *fresh42 = ssl_sessionid;
    (*(borrow_mut(&mut store)).unwrap()).idsize = idsize;
    (*(borrow_mut(&mut store)).unwrap()).age = *(borrow_mut(&mut general_age)).unwrap();
    Curl_cfree.expect("non-null function pointer")((*(borrow_mut(&mut store)).unwrap()).name as *mut libc::c_void);
    Curl_cfree
        .expect("non-null function pointer")((*(borrow_mut(&mut store)).unwrap()).conn_to_host as *mut libc::c_void);
    let mut fresh43 = &mut ((*(borrow_mut(&mut store)).unwrap()).name);
    *fresh43 = clone_host;
    let mut fresh44 = &mut ((*(borrow_mut(&mut store)).unwrap()).conn_to_host);
    *fresh44 = clone_conn_to_host;
    (*(borrow_mut(&mut store)).unwrap()).conn_to_port = conn_to_port;
    (*(borrow_mut(&mut store)).unwrap())
        .remote_port = if isProxy as i32 != 0 {
        (*conn).port
    } else {
        (*conn).remote_port
    };
    let mut fresh45 = &mut ((*(borrow_mut(&mut store)).unwrap()).scheme);
    *fresh45 = (*(*conn).handler).scheme;
    if !Curl_clone_primary_ssl_config(ssl_config, Some(&mut (*(borrow_mut(&mut store)).unwrap()).ssl_config)) {
        Curl_free_primary_ssl_config(Some(&mut (*(borrow_mut(&mut store)).unwrap()).ssl_config));
        let mut fresh46 = &mut ((*(borrow_mut(&mut store)).unwrap()).sessionid);
        *fresh46 = 0 as *mut libc::c_void;
        Curl_cfree.expect("non-null function pointer")(clone_host as *mut libc::c_void);
        Curl_cfree
            .expect(
                "non-null function pointer",
            )(clone_conn_to_host as *mut libc::c_void);
        return CURLE_OUT_OF_MEMORY;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_associate_conn(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
) {
    if ((*Curl_ssl).associate_connection).is_some() {
        ((*Curl_ssl).associate_connection)
            .expect("non-null function pointer")(data, conn, 0 as i32);
        if (*conn).sock[1 as i32 as usize] != 0
            && ((*conn).bits).sock_accepted() as i32 != 0
        {
            ((*Curl_ssl).associate_connection)
                .expect("non-null function pointer")(data, conn, 1 as i32);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_detach_conn(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
) {
    if ((*Curl_ssl).disassociate_connection).is_some() {
        ((*Curl_ssl).disassociate_connection)
            .expect("non-null function pointer")(data, 0 as i32);
        if (*conn).sock[1 as i32 as usize] != 0
            && ((*conn).bits).sock_accepted() as i32 != 0
        {
            ((*Curl_ssl).disassociate_connection)
                .expect("non-null function pointer")(data, 1 as i32);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_close_all(mut data: * mut crate::src::lib::http2::Curl_easy) {
    if !((*data).state.session).is_null()
        && !(!((*data).share).is_null()
            && (*(*data).share).specifier
                & ((1 as i32) << CURL_LOCK_DATA_SSL_SESSION as i32)
                    as u32 != 0)
    {
        let mut i: u64 = 0;
        i = 0 as i32 as size_t;
        while i < (*data).set.general_ssl.max_ssl_sessions {
            Curl_ssl_kill_session(Some(&mut *((*data).state.session).offset(i as isize)));
            i = i.wrapping_add(1);
        }
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.session as *mut libc::c_void);
        let mut fresh47 = &mut ((*data).state.session);
        *fresh47 = 0 as *mut Curl_ssl_session;
    }
    ((*Curl_ssl).close_all).expect("non-null function pointer")(data);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_getsock(
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut socks: * mut i32,
) -> i32 {
    let mut connssl: Option<&'_ mut crate::src::lib::http2::ssl_connect_data> = Some(&mut *((*conn).ssl)
        .as_mut_ptr()
        .offset(0 as i32 as isize));
    if (*(borrow(& connssl)).unwrap()).connecting_state as u32
        == ssl_connect_2_writing as i32 as u32
    {
        *socks
            .offset(0 as i32 as isize) = (*conn).sock[0 as i32 as usize];
        return (1 as i32) << 16 as i32 + 0 as i32;
    }
    if (*(borrow(& connssl)).unwrap()).connecting_state as u32
        == ssl_connect_2_reading as i32 as u32
    {
        *socks
            .offset(0 as i32 as isize) = (*conn).sock[0 as i32 as usize];
        return (1 as i32) << 0 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_close(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut sockindex: i32,
) {
    ((*Curl_ssl).close_one).expect("non-null function pointer")(data, conn, sockindex);
    (*conn).ssl[sockindex as usize].state = ssl_connection_none;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_shutdown(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut sockindex: i32,
) -> u32 {
    if ((*Curl_ssl).shut_down).expect("non-null function pointer")(data, conn, sockindex)
        != 0
    {
        return CURLE_SSL_SHUTDOWN_FAILED;
    }
    let mut fresh48 = &mut ((*conn).ssl[sockindex as usize]);
    (*fresh48).set_use_0(0 as i32 as bit);
    (*conn).ssl[sockindex as usize].state = ssl_connection_none;
    let mut fresh49 = &mut ((*conn).recv[sockindex as usize]);
    *fresh49 = Some(
        Curl_recv_plain,
    );
    let mut fresh50 = &mut ((*conn).send[sockindex as usize]);
    *fresh50 = Some(
        Curl_send_plain,
    );
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_set_engine(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut engine: * const i8,
) -> u32 {
    return ((*Curl_ssl).set_engine).expect("non-null function pointer")(data, engine);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_set_engine_default(
    mut data: * mut crate::src::lib::http2::Curl_easy,
) -> u32 {
    return ((*Curl_ssl).set_engine_default).expect("non-null function pointer")(data);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_engines_list(
    mut data: * mut crate::src::lib::http2::Curl_easy,
) -> * mut crate::src::lib::http2::curl_slist {
    return ((*Curl_ssl).engines_list).expect("non-null function pointer")(data);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_initsessions(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut amount: u64,
) -> u32 {
    let mut session: * mut crate::src::lib::http2::Curl_ssl_session = 0 as *mut Curl_ssl_session;
    if !((*data).state.session).is_null() {
        return CURLE_OK;
    }
    session = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(amount, ::std::mem::size_of::<Curl_ssl_session>() as u64)
        as *mut Curl_ssl_session;
    if session.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    (*data).set.general_ssl.max_ssl_sessions = amount;
    let mut fresh51 = &mut ((*data).state.session);
    *fresh51 = session;
    (*data).state.sessionage = 1 as i32 as i64;
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_version(
    mut buffer: * mut i8,
    mut size: u64,
) {
    ((*Curl_ssl).version).expect("non-null function pointer")(buffer, size);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_check_cxn(mut conn: * mut crate::src::lib::http2::connectdata) -> i32 {
    return ((*Curl_ssl).check_cxn).expect("non-null function pointer")(conn);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_data_pending(
    mut conn: * const crate::src::lib::http2::connectdata,
    mut connindex: i32,
) -> bool {
    return ((*Curl_ssl).data_pending)
        .expect("non-null function pointer")(conn, connindex);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_free_certinfo(mut data: * mut crate::src::lib::http2::Curl_easy) {
    let mut ci: Option<&'_ mut crate::src::lib::http2::curl_certinfo> = Some(&mut (*data).info.certs);
    if (*(borrow(& ci)).unwrap()).num_of_certs != 0 {
        let mut i: i32 = 0;
        i = 0 as i32;
        while i < (*(borrow(& ci)).unwrap()).num_of_certs {
            curl_slist_free_all(*((*(borrow(& ci)).unwrap()).certinfo).offset(i as isize));
            let mut fresh52 = &mut (*((*(borrow(& ci)).unwrap()).certinfo).offset(i as isize));
            *fresh52 = 0 as *mut curl_slist;
            i += 1;
        }
        Curl_cfree
            .expect("non-null function pointer")((*(borrow_mut(&mut ci)).unwrap()).certinfo as *mut libc::c_void);
        let mut fresh53 = &mut ((*(borrow_mut(&mut ci)).unwrap()).certinfo);
        *fresh53 = 0 as *mut *mut curl_slist;
        (*(borrow_mut(&mut ci)).unwrap()).num_of_certs = 0 as i32;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_init_certinfo(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut num: i32,
) -> u32 {
    let mut ci: Option<&'_ mut crate::src::lib::http2::curl_certinfo> = Some(&mut (*data).info.certs);
    let mut table: * mut * mut crate::src::lib::http2::curl_slist = 0 as *mut *mut curl_slist;
    Curl_ssl_free_certinfo(data);
    table = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(num as size_t, ::std::mem::size_of::<*mut curl_slist>() as u64)
        as *mut *mut curl_slist;
    if table.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    (*(borrow_mut(&mut ci)).unwrap()).num_of_certs = num;
    let mut fresh54 = &mut ((*(borrow_mut(&mut ci)).unwrap()).certinfo);
    *fresh54 = table;
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_push_certinfo_len(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut certnum: i32,
    mut label: * const i8,
    mut value: * const i8,
    mut valuelen: u64,
) -> u32 {
    let mut ci: Option<&'_ mut crate::src::lib::http2::curl_certinfo> = Some(&mut (*data).info.certs);
    let mut output: * mut i8 = 0 as *mut i8;
    let mut nl: * mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
    let mut result: u32 = CURLE_OK;
    let mut labellen: u64 = strlen(label);
    let mut outlen: u64 = labellen
        .wrapping_add(1 as i32 as u64)
        .wrapping_add(valuelen)
        .wrapping_add(1 as i32 as u64);
    output = Curl_cmalloc.expect("non-null function pointer")(outlen)
        as *mut i8;
    if output.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    curl_msnprintf(output, outlen, b"%s:\0" as *const u8 as *const i8, label);
    memcpy(
        &mut *output
            .offset(labellen.wrapping_add(1 as i32 as u64) as isize)
            as *mut i8 as *mut libc::c_void,
        value as *const libc::c_void,
        valuelen,
    );
    *output
        .offset(
            labellen
                .wrapping_add(1 as i32 as u64)
                .wrapping_add(valuelen) as isize,
        ) = 0 as i32 as i8;
    nl = Curl_slist_append_nodup(*((*(borrow(& ci)).unwrap()).certinfo).offset(certnum as isize), output);
    if nl.is_null() {
        Curl_cfree.expect("non-null function pointer")(output as *mut libc::c_void);
        curl_slist_free_all(*((*(borrow(& ci)).unwrap()).certinfo).offset(certnum as isize));
        result = CURLE_OUT_OF_MEMORY;
    }
    let mut fresh55 = &mut (*((*(borrow(& ci)).unwrap()).certinfo).offset(certnum as isize));
    *fresh55 = nl;
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_push_certinfo(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut certnum: i32,
    mut label: * const i8,
    mut value: * const i8,
) -> u32 {
    let mut valuelen: u64 = strlen(value);
    return Curl_ssl_push_certinfo_len(data, certnum, label, value, valuelen);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_random(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut entropy: * mut u8,
    mut length: u64,
) -> u32 {
    return ((*Curl_ssl).random)
        .expect("non-null function pointer")(data, entropy, length);
}
unsafe extern "C" fn pubkey_pem_to_der<'a1, 'a2>(
    mut pem: * const i8,
    mut der: Option<&'a1 mut * mut u8>,
    mut der_len: Option<&'a2 mut u64>,
) -> u32 {
    let mut stripped_pem: * mut i8 = 0 as *mut i8;
    let mut begin_pos: * mut i8 = 0 as *mut i8;
    let mut end_pos: * mut i8 = 0 as *mut i8;
    let mut pem_count: u64 = 0;
    let mut stripped_pem_count: u64 = 0 as i32 as size_t;
    let mut pem_len: u64 = 0;
    let mut result: u32 = CURLE_OK;
    if pem.is_null() {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    begin_pos = strstr(
        pem,
        b"-----BEGIN PUBLIC KEY-----\0" as *const u8 as *const i8,
    );
    if begin_pos.is_null() {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    pem_count = begin_pos.offset_from(pem) as i64 as size_t;
    if 0 as i32 as u64 != pem_count
        && '\n' as i32
            != *pem
                .offset(
                    pem_count.wrapping_sub(1 as i32 as u64) as isize,
                ) as i32
    {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    pem_count = (pem_count as u64)
        .wrapping_add(26 as i32 as u64) as size_t as size_t;
    end_pos = strstr(
        pem.offset(pem_count as isize),
        b"\n-----END PUBLIC KEY-----\0" as *const u8 as *const i8,
    );
    if end_pos.is_null() {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    pem_len = end_pos.offset_from(pem) as i64 as size_t;
    stripped_pem = Curl_cmalloc
        .expect(
            "non-null function pointer",
        )(
        pem_len.wrapping_sub(pem_count).wrapping_add(1 as i32 as u64),
    ) as *mut i8;
    if stripped_pem.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    while pem_count < pem_len {
        if '\n' as i32 != *pem.offset(pem_count as isize) as i32
            && '\r' as i32 != *pem.offset(pem_count as isize) as i32
        {
            let mut fresh56 = stripped_pem_count;
            stripped_pem_count = stripped_pem_count.wrapping_add(1);
            *stripped_pem.offset(fresh56 as isize) = *pem.offset(pem_count as isize);
        }
        pem_count = pem_count.wrapping_add(1);
    }
    *stripped_pem.offset(stripped_pem_count as isize) = '\u{0}' as i32 as i8;
    result = Curl_base64_decode(stripped_pem, borrow_mut(&mut der), borrow_mut(&mut der_len));
    Curl_cfree.expect("non-null function pointer")(stripped_pem as *mut libc::c_void);
    stripped_pem = 0 as *mut i8;
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_pin_peer_pubkey(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut pinnedpubkey: * const i8,
    mut pubkey: * const u8,
    mut pubkeylen: u64,
) -> u32 {
    let mut fp: * mut crate::src::lib::http2::_IO_FILE = 0 as *mut FILE;
    let mut buf: * mut u8 = 0 as *mut u8;
    let mut pem_ptr: * mut u8 = 0 as *mut u8;
    let mut result: u32 = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    if pinnedpubkey.is_null() {
        return CURLE_OK;
    }
    if pubkey.is_null() || pubkeylen == 0 {
        return result;
    }
    if strncmp(
        pinnedpubkey,
        b"sha256//\0" as *const u8 as *const i8,
        8 as i32 as u64,
    ) == 0 as i32
    {
        let mut encode: u32 = CURLE_OK;
        let mut encodedlen: u64 = 0;
        let mut pinkeylen: u64 = 0;
        let mut encoded: * mut i8 = 0 as *mut i8;
        let mut pinkeycopy: * mut i8 = 0 as *mut i8;
        let mut begin_pos: * mut i8 = 0 as *mut i8;
        let mut end_pos: * mut i8 = 0 as *mut i8;
        let mut sha256sumdigest: * mut u8 = 0 as *mut u8;
        if ((*Curl_ssl).sha256sum).is_none() {
            return result;
        }
        sha256sumdigest = Curl_cmalloc
            .expect("non-null function pointer")(32 as i32 as size_t)
            as *mut u8;
        if sha256sumdigest.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        encode = ((*Curl_ssl).sha256sum)
            .expect(
                "non-null function pointer",
            )(pubkey, pubkeylen, sha256sumdigest, 32 as i32 as size_t);
        if encode as u32 != CURLE_OK as i32 as u32 {
            return encode;
        }
        encode = Curl_base64_encode(
            data,
            sha256sumdigest as *mut i8,
            32 as i32 as size_t,
            Some(&mut encoded),
            Some(&mut encodedlen),
        );
        Curl_cfree
            .expect("non-null function pointer")(sha256sumdigest as *mut libc::c_void);
        sha256sumdigest = 0 as *mut u8;
        if encode as u64 != 0 {
            return encode;
        }
        Curl_infof(
            data,
            b" public key hash: sha256//%s\0" as *const u8 as *const i8,
            encoded,
        );
        pinkeylen = (strlen(pinnedpubkey))
            .wrapping_add(1 as i32 as u64);
        pinkeycopy = Curl_cmalloc.expect("non-null function pointer")(pinkeylen)
            as *mut i8;
        if pinkeycopy.is_null() {
            Curl_cfree.expect("non-null function pointer")(encoded as *mut libc::c_void);
            encoded = 0 as *mut i8;
            return CURLE_OUT_OF_MEMORY;
        }
        memcpy(
            pinkeycopy as *mut libc::c_void,
            pinnedpubkey as *const libc::c_void,
            pinkeylen,
        );
        begin_pos = pinkeycopy;
        loop {
            end_pos = strstr(
                begin_pos,
                b";sha256//\0" as *const u8 as *const i8,
            );
            if !end_pos.is_null() {
                *end_pos
                    .offset(0 as i32 as isize) = '\u{0}' as i32 as i8;
            }
            if encodedlen == strlen(begin_pos.offset(8 as i32 as isize))
                && memcmp(
                    encoded as *const libc::c_void,
                    begin_pos.offset(8 as i32 as isize) as *const libc::c_void,
                    encodedlen,
                ) == 0
            {
                result = CURLE_OK;
                break;
            } else {
                if !end_pos.is_null() {
                    *end_pos
                        .offset(0 as i32 as isize) = ';' as i32 as i8;
                    begin_pos = strstr(
                        end_pos,
                        b"sha256//\0" as *const u8 as *const i8,
                    );
                }
                if !(!end_pos.is_null() && !begin_pos.is_null()) {
                    break;
                }
            }
        }
        Curl_cfree.expect("non-null function pointer")(encoded as *mut libc::c_void);
        encoded = 0 as *mut i8;
        Curl_cfree.expect("non-null function pointer")(pinkeycopy as *mut libc::c_void);
        pinkeycopy = 0 as *mut i8;
        return result;
    }
    fp = fopen(pinnedpubkey, b"rb\0" as *const u8 as *const i8);
    if fp.is_null() {
        return result;
    }
    let mut filesize: i64 = 0;
    let mut size: u64 = 0;
    let mut pem_len: u64 = 0;
    let mut pem_read: u32 = CURLE_OK;
    if !(fseek(fp, 0 as i32 as i64, 2 as i32) != 0) {
        filesize = ftell(fp);
        if !(fseek(fp, 0 as i32 as i64, 0 as i32) != 0) {
            if !(filesize < 0 as i32 as i64
                || filesize > 1048576 as i32 as i64)
            {
                size = curlx_sotouz(filesize);
                if !(pubkeylen > size) {
                    buf = Curl_cmalloc
                        .expect(
                            "non-null function pointer",
                        )(size.wrapping_add(1 as i32 as u64))
                        as *mut u8;
                    if !buf.is_null() {
                        if !(fread(
                            buf as *mut libc::c_void,
                            size,
                            1 as i32 as u64,
                            fp,
                        ) as i32 != 1 as i32)
                        {
                            if pubkeylen == size {
                                if memcmp(
                                    pubkey as *const libc::c_void,
                                    buf as *const libc::c_void,
                                    pubkeylen,
                                ) == 0
                                {
                                    result = CURLE_OK;
                                }
                            } else {
                                *buf
                                    .offset(size as isize) = '\u{0}' as i32 as u8;
                                pem_read = pubkey_pem_to_der(
                                    buf as *const i8,
                                    Some(&mut pem_ptr),
                                    Some(&mut pem_len),
                                );
                                if !(pem_read as u64 != 0) {
                                    if pubkeylen == pem_len
                                        && memcmp(
                                            pubkey as *const libc::c_void,
                                            pem_ptr as *const libc::c_void,
                                            pubkeylen,
                                        ) == 0
                                    {
                                        result = CURLE_OK;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Curl_cfree.expect("non-null function pointer")(buf as *mut libc::c_void);
    buf = 0 as *mut u8;
    Curl_cfree.expect("non-null function pointer")(pem_ptr as *mut libc::c_void);
    pem_ptr = 0 as *mut u8;
    fclose(fp);
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_cert_status_request() -> bool {
    return ((*Curl_ssl).cert_status_request).expect("non-null function pointer")();
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_false_start() -> bool {
    return ((*Curl_ssl).false_start).expect("non-null function pointer")();
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ssl_tls13_ciphersuites() -> bool {
    return (*Curl_ssl).supports
        & ((1 as i32) << 5 as i32) as u32 != 0;
}
#[no_mangle]
pub extern "C" fn Curl_none_init() -> i32 {
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn Curl_none_cleanup() {}
#[no_mangle]
pub extern "C" fn Curl_none_shutdown(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut sockindex: i32,
) -> i32 {
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn Curl_none_check_cxn(mut conn: * mut crate::src::lib::http2::connectdata) -> i32 {
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn Curl_none_random(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut entropy: * mut u8,
    mut length: u64,
) -> u32 {
    return CURLE_NOT_BUILT_IN;
}
#[no_mangle]
pub extern "C" fn Curl_none_close_all(mut data: * mut crate::src::lib::http2::Curl_easy) {}
#[no_mangle]
pub extern "C" fn Curl_none_session_free(mut ptr: * mut core::ffi::c_void) {}
#[no_mangle]
pub extern "C" fn Curl_none_data_pending(
    mut conn: * const crate::src::lib::http2::connectdata,
    mut connindex: i32,
) -> bool {
    return 0 as i32 != 0;
}
#[no_mangle]
pub extern "C" fn Curl_none_cert_status_request() -> bool {
    return 0 as i32 != 0;
}
#[no_mangle]
pub extern "C" fn Curl_none_set_engine(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut engine: * const i8,
) -> u32 {
    return CURLE_NOT_BUILT_IN;
}
#[no_mangle]
pub extern "C" fn Curl_none_set_engine_default(
    mut data: * mut crate::src::lib::http2::Curl_easy,
) -> u32 {
    return CURLE_NOT_BUILT_IN;
}
#[no_mangle]
pub extern "C" fn Curl_none_engines_list(
    mut data: * mut crate::src::lib::http2::Curl_easy,
) -> * mut crate::src::lib::http2::curl_slist {
    return 0 as *mut libc::c_void as *mut curl_slist;
}
#[no_mangle]
pub extern "C" fn Curl_none_false_start() -> bool {
    return 0 as i32 != 0;
}
unsafe extern "C" fn multissl_init() -> i32 {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return 1 as i32;
    }
    return ((*Curl_ssl).init).expect("non-null function pointer")();
}
unsafe extern "C" fn multissl_connect(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut sockindex: i32,
) -> u32 {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return CURLE_FAILED_INIT;
    }
    return ((*Curl_ssl).connect_blocking)
        .expect("non-null function pointer")(data, conn, sockindex);
}
unsafe extern "C" fn multissl_connect_nonblocking(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut sockindex: i32,
    mut done: * mut bool,
) -> u32 {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return CURLE_FAILED_INIT;
    }
    return ((*Curl_ssl).connect_nonblocking)
        .expect("non-null function pointer")(data, conn, sockindex, done);
}
unsafe extern "C" fn multissl_getsock(
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut socks: * mut i32,
) -> i32 {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return 0 as i32;
    }
    return ((*Curl_ssl).getsock).expect("non-null function pointer")(conn, socks);
}
unsafe extern "C" fn multissl_get_internals(
    mut connssl: * mut crate::src::lib::http2::ssl_connect_data,
    mut info: u32,
) -> * mut core::ffi::c_void {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return 0 as *mut libc::c_void;
    }
    return ((*Curl_ssl).get_internals)
        .expect("non-null function pointer")(connssl, info);
}
unsafe extern "C" fn multissl_close(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut sockindex: i32,
) {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return;
    }
    ((*Curl_ssl).close_one).expect("non-null function pointer")(data, conn, sockindex);
}
static mut Curl_ssl_multi: crate::src::lib::getinfo::Curl_ssl = unsafe {
    {
        let mut init = Curl_ssl {
            info: {
                let mut init = curl_ssl_backend {
                    id: CURLSSLBACKEND_NONE,
                    name: b"multi\0" as *const u8 as *const i8,
                };
                init
            },
            supports: 0 as i32 as u32,
            sizeof_ssl_backend_data: -(1 as i32) as size_t,
            init: Some(multissl_init),
            cleanup: Some(Curl_none_cleanup),
            version: Some(
                multissl_version,
            ),
            check_cxn: Some(
                Curl_none_check_cxn,
            ),
            shut_down: Some(
                Curl_none_shutdown,
            ),
            data_pending: Some(
                Curl_none_data_pending,
            ),
            random: Some(
                Curl_none_random,
            ),
            cert_status_request: Some(
                Curl_none_cert_status_request,
            ),
            connect_blocking: Some(
                multissl_connect,
            ),
            connect_nonblocking: Some(
                multissl_connect_nonblocking,
            ),
            getsock: Some(
                multissl_getsock,
            ),
            get_internals: Some(
                multissl_get_internals,
            ),
            close_one: Some(
                multissl_close,
            ),
            close_all: Some(
                Curl_none_close_all,
            ),
            session_free: Some(
                Curl_none_session_free,
            ),
            set_engine: Some(
                Curl_none_set_engine,
            ),
            set_engine_default: Some(
                Curl_none_set_engine_default,
            ),
            engines_list: Some(
                Curl_none_engines_list,
            ),
            false_start: Some(Curl_none_false_start),
            sha256sum: None,
            associate_connection: None,
            disassociate_connection: None,
        };
        init
    }
};
#[no_mangle]
pub static mut Curl_ssl: * const crate::src::lib::getinfo::Curl_ssl = unsafe {
    &Curl_ssl_openssl as *const Curl_ssl
};
static mut available_backends: [* const crate::src::lib::getinfo::Curl_ssl; 2] = unsafe {
    [&Curl_ssl_openssl as *const Curl_ssl, 0 as *const Curl_ssl]
};
unsafe extern "C" fn multissl_version(
    mut buffer: * mut i8,
    mut size: u64,
) -> u64 {
    static mut selected: * const crate::src::lib::getinfo::Curl_ssl = 0 as *const Curl_ssl;
    static mut backends: [i8; 200] = [0; 200];
    static mut backends_len: u64 = 0;
    let mut current: * const crate::src::lib::getinfo::Curl_ssl = 0 as *const Curl_ssl;
    current = if Curl_ssl == &Curl_ssl_multi as *const Curl_ssl {
        available_backends[0 as i32 as usize]
    } else {
        Curl_ssl
    };
    if current != selected {
        let mut p: * mut i8 = backends.as_mut_ptr();
        let mut end: * mut i8 = backends
            .as_mut_ptr()
            .offset(
                ::std::mem::size_of::<[i8; 200]>() as u64 as isize,
            );
        let mut i: i32 = 0;
        selected = current;
        backends[0 as i32 as usize] = '\u{0}' as i32 as i8;
        i = 0 as i32;
        while !(available_backends[i as usize]).is_null() {
            let mut vb: [i8; 200] = [0; 200];
            let mut paren: bool = selected != available_backends[i as usize];
            if ((*available_backends[i as usize]).version)
                .expect(
                    "non-null function pointer",
                )(
                vb.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 200]>() as u64,
            ) != 0
            {
                p = p
                    .offset(
                        curl_msnprintf(
                            p,
                            end.offset_from(p) as i64 as size_t,
                            b"%s%s%s%s\0" as *const u8 as *const i8,
                            if p != backends.as_mut_ptr() {
                                b" \0" as *const u8 as *const i8
                            } else {
                                b"\0" as *const u8 as *const i8
                            },
                            if paren as i32 != 0 {
                                b"(\0" as *const u8 as *const i8
                            } else {
                                b"\0" as *const u8 as *const i8
                            },
                            vb.as_mut_ptr(),
                            if paren as i32 != 0 {
                                b")\0" as *const u8 as *const i8
                            } else {
                                b"\0" as *const u8 as *const i8
                            },
                        ) as isize,
                    );
            }
            i += 1;
        }
        backends_len = p.offset_from(backends.as_mut_ptr()) as i64 as size_t;
    }
    if size == 0 {
        return 0 as i32 as size_t;
    }
    if size <= backends_len {
        strncpy(
            buffer,
            backends.as_mut_ptr(),
            size.wrapping_sub(1 as i32 as u64),
        );
        *buffer
            .offset(
                size.wrapping_sub(1 as i32 as u64) as isize,
            ) = '\u{0}' as i32 as i8;
        return size.wrapping_sub(1 as i32 as u64);
    }
    strcpy(buffer, backends.as_mut_ptr());
    return backends_len;
}
unsafe extern "C" fn multissl_setup(mut backend: * const crate::src::lib::getinfo::Curl_ssl) -> i32 {
    let mut env: * const i8 = 0 as *const i8;
    let mut env_tmp: * mut i8 = 0 as *mut i8;
    if Curl_ssl != &Curl_ssl_multi as *const Curl_ssl {
        return 1 as i32;
    }
    if !backend.is_null() {
        Curl_ssl = backend;
        return 0 as i32;
    }
    if (available_backends[0 as i32 as usize]).is_null() {
        return 1 as i32;
    }
    env_tmp = curl_getenv(b"CURL_SSL_BACKEND\0" as *const u8 as *const i8);
    env = env_tmp;
    if !env.is_null() {
        let mut i: i32 = 0;
        i = 0 as i32;
        while !(available_backends[i as usize]).is_null() {
            if Curl_strcasecompare(env, (*available_backends[i as usize]).info.name) != 0
            {
                Curl_ssl = available_backends[i as usize];
                Curl_cfree
                    .expect("non-null function pointer")(env_tmp as *mut libc::c_void);
                return 0 as i32;
            }
            i += 1;
        }
    }
    Curl_ssl = available_backends[0 as i32 as usize];
    Curl_cfree.expect("non-null function pointer")(env_tmp as *mut libc::c_void);
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn curl_global_sslset<'a1>(
    mut id: u32,
    mut name: * const i8,
    mut avail: Option<&'a1 mut * mut * const crate::src::lib::getinfo::curl_ssl_backend>,
) -> u32 {
    let mut i: i32 = 0;
    if !borrow(& avail).is_none() {
        *(borrow_mut(&mut avail)).unwrap() = &mut available_backends as *mut [*const Curl_ssl; 2]
            as *mut *const curl_ssl_backend;
    }
    if Curl_ssl != &Curl_ssl_multi as *const Curl_ssl {
        return (if id as u32 == (*Curl_ssl).info.id as u32
            || !name.is_null() && Curl_strcasecompare(name, (*Curl_ssl).info.name) != 0
        {
            CURLSSLSET_OK as i32
        } else {
            CURLSSLSET_UNKNOWN_BACKEND as i32
        }) as CURLsslset;
    }
    i = 0 as i32;
    while !(available_backends[i as usize]).is_null() {
        if (*available_backends[i as usize]).info.id as u32
            == id as u32
            || !name.is_null()
                && Curl_strcasecompare((*available_backends[i as usize]).info.name, name)
                    != 0
        {
            multissl_setup(available_backends[i as usize]);
            return CURLSSLSET_OK;
        }
        i += 1;
    }
    return CURLSSLSET_UNKNOWN_BACKEND;
}
use crate::laertes_rt::*;
