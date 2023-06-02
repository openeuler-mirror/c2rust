use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn send(
        __fd: i32,
        __buf: * const core::ffi::c_void,
        __n: u64,
        __flags: i32,
    ) -> i64;
    fn sscanf(_: * const i8, _: * const i8, _: ...) -> i32;
    fn fileno(__stream: * mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn read(__fd: i32, __buf: * mut core::ffi::c_void, __nbytes: u64) -> i64;
    fn __errno_location() -> * mut i32;
    
    
    fn strtol(
        _: * const i8,
        _: * mut * mut i8,
        _: i32,
    ) -> i64;
    fn strncpy(
        _: * mut i8,
        _: * const i8,
        _: u64,
    ) -> * mut i8;
    fn strlen(_: * const i8) -> u64;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::progress::Curl_pgrsSetDownloadCounter;
pub use crate::src::lib::progress::Curl_pgrsSetUploadCounter;
pub use crate::src::lib::progress::Curl_pgrsUpdate;
pub use crate::src::lib::select::Curl_poll;
pub use crate::src::lib::sendf::Curl_client_write;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::sendf::Curl_read;
pub use crate::src::lib::sendf::Curl_write;
pub use crate::src::lib::slist::curl_slist_append;
pub use crate::src::lib::slist::curl_slist_free_all;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::timeval::Curl_now;
pub use crate::src::lib::timeval::Curl_timediff;
pub use crate::src::lib::transfer::Curl_setup_transfer;
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
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::easy::Curl_ccalloc;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
pub type __uint8_t = u8;
pub type __uint16_t = u16;
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
pub type C2RustUnnamed = u32;
pub const MSG_CMSG_CLOEXEC: C2RustUnnamed = 1073741824;
pub const MSG_FASTOPEN: C2RustUnnamed = 536870912;
pub const MSG_ZEROCOPY: C2RustUnnamed = 67108864;
pub const MSG_BATCH: C2RustUnnamed = 262144;
pub const MSG_WAITFORONE: C2RustUnnamed = 65536;
pub const MSG_MORE: C2RustUnnamed = 32768;
pub const MSG_NOSIGNAL: C2RustUnnamed = 16384;
pub const MSG_ERRQUEUE: C2RustUnnamed = 8192;
pub const MSG_RST: C2RustUnnamed = 4096;
pub const MSG_CONFIRM: C2RustUnnamed = 2048;
pub const MSG_SYN: C2RustUnnamed = 1024;
pub const MSG_FIN: C2RustUnnamed = 512;
pub const MSG_WAITALL: C2RustUnnamed = 256;
pub const MSG_EOR: C2RustUnnamed = 128;
pub const MSG_DONTWAIT: C2RustUnnamed = 64;
pub const MSG_TRUNC: C2RustUnnamed = 32;
pub const MSG_PROXY: C2RustUnnamed = 16;
pub const MSG_CTRUNC: C2RustUnnamed = 8;
pub const MSG_DONTROUTE: C2RustUnnamed = 4;
pub const MSG_PEEK: C2RustUnnamed = 2;
pub const MSG_OOB: C2RustUnnamed = 1;
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

pub type C2RustUnnamed_0 = crate::src::lib::http2::C2RustUnnamed;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct TELNET {
    pub please_negotiate: i32,
    pub already_negotiated: i32,
    pub us: [i32; 256],
    pub usq: [i32; 256],
    pub us_preferred: [i32; 256],
    pub him: [i32; 256],
    pub himq: [i32; 256],
    pub him_preferred: [i32; 256],
    pub subnegotiation: [i32; 256],
    pub subopt_ttype: [i8; 32],
    pub subopt_xdisploc: [i8; 128],
    pub subopt_wsx: u16,
    pub subopt_wsy: u16,
    pub telrcv_state: u32,
    pub telnet_vars: * mut crate::src::lib::http2::curl_slist,
    pub subbuffer: [u8; 512],
    pub subpointer: * mut u8,
    pub subend: * mut u8,
}
impl TELNET {
    pub const fn new() -> Self {
        TELNET {
        please_negotiate: 0,
        already_negotiated: 0,
        us: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],
        usq: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],
        us_preferred: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],
        him: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],
        himq: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],
        him_preferred: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],
        subnegotiation: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],
        subopt_ttype: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],
        subopt_xdisploc: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],
        subopt_wsx: 0,
        subopt_wsy: 0,
        telrcv_state: 0,
        telnet_vars: (0 as * mut crate::src::lib::http2::curl_slist),
        subbuffer: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],
        subpointer: (0 as * mut u8),
        subend: (0 as * mut u8)
        }
    }
}

impl std::default::Default for TELNET {
    fn default() -> Self { TELNET::new() }
}

pub type TelnetReceive = u32;
pub const CURL_TS_SE: TelnetReceive = 8;
pub const CURL_TS_SB: TelnetReceive = 7;
pub const CURL_TS_CR: TelnetReceive = 6;
pub const CURL_TS_DONT: TelnetReceive = 5;
pub const CURL_TS_DO: TelnetReceive = 4;
pub const CURL_TS_WONT: TelnetReceive = 3;
pub const CURL_TS_WILL: TelnetReceive = 2;
pub const CURL_TS_IAC: TelnetReceive = 1;
pub const CURL_TS_DATA: TelnetReceive = 0;
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
pub type C2RustUnnamed_1 = u32;
pub const HTTPSEND_BODY: C2RustUnnamed_1 = 2;
pub const HTTPSEND_REQUEST: C2RustUnnamed_1 = 1;
pub const HTTPSEND_NADA: C2RustUnnamed_1 = 0;
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
pub type C2RustUnnamed_2 = u32;
pub const HEADER_ALLBAD: C2RustUnnamed_2 = 2;
pub const HEADER_PARTHEADER: C2RustUnnamed_2 = 1;
pub const HEADER_NORMAL: C2RustUnnamed_2 = 0;
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
pub type C2RustUnnamed_3 = u32;
pub const HCACHE_SHARED: C2RustUnnamed_3 = 2;
pub const HCACHE_MULTI: C2RustUnnamed_3 = 1;
pub const HCACHE_NONE: C2RustUnnamed_3 = 0;
// #[derive(Copy, Clone)]

pub type Curl_message = crate::src::lib::http2::Curl_message;
// #[derive(Copy, Clone)]

pub type CURLMsg = crate::src::lib::http2::CURLMsg;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_4 = crate::src::lib::http2::C2RustUnnamed_3;
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

pub type C2RustUnnamed_5 = crate::src::lib::http2::C2RustUnnamed_4;
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
pub type C2RustUnnamed_6 = u32;
pub const TRNSPRT_QUIC: C2RustUnnamed_6 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_6 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_6 = 3;
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
pub type curl_calloc_callback<'a1> = Option<unsafe extern "C"  fn(_: u64,_: u64,) -> Option<&'a1 mut core::ffi::c_void>>;
// #[derive(Copy, Clone)]

pub type pollfd = crate::src::lib::multi::pollfd;
#[inline]
 extern "C" fn __bswap_16(mut __bsx: u16) -> u16 {
    return (__bsx as i32 >> 8 as i32 & 0xff as i32
        | (__bsx as i32 & 0xff as i32) << 8 as i32)
        as __uint16_t;
}
#[inline]
unsafe extern "C" fn atoi(mut __nptr: * const i8) -> i32 {
    return strtol(
        __nptr,
        0 as *mut libc::c_void as *mut *mut i8,
        10 as i32,
    ) as i32;
}
static mut telnetoptions: [* const i8; 40] = [
    b"BINARY\0" as *const u8 as *const i8,
    b"ECHO\0" as *const u8 as *const i8,
    b"RCP\0" as *const u8 as *const i8,
    b"SUPPRESS GO AHEAD\0" as *const u8 as *const i8,
    b"NAME\0" as *const u8 as *const i8,
    b"STATUS\0" as *const u8 as *const i8,
    b"TIMING MARK\0" as *const u8 as *const i8,
    b"RCTE\0" as *const u8 as *const i8,
    b"NAOL\0" as *const u8 as *const i8,
    b"NAOP\0" as *const u8 as *const i8,
    b"NAOCRD\0" as *const u8 as *const i8,
    b"NAOHTS\0" as *const u8 as *const i8,
    b"NAOHTD\0" as *const u8 as *const i8,
    b"NAOFFD\0" as *const u8 as *const i8,
    b"NAOVTS\0" as *const u8 as *const i8,
    b"NAOVTD\0" as *const u8 as *const i8,
    b"NAOLFD\0" as *const u8 as *const i8,
    b"EXTEND ASCII\0" as *const u8 as *const i8,
    b"LOGOUT\0" as *const u8 as *const i8,
    b"BYTE MACRO\0" as *const u8 as *const i8,
    b"DE TERMINAL\0" as *const u8 as *const i8,
    b"SUPDUP\0" as *const u8 as *const i8,
    b"SUPDUP OUTPUT\0" as *const u8 as *const i8,
    b"SEND LOCATION\0" as *const u8 as *const i8,
    b"TERM TYPE\0" as *const u8 as *const i8,
    b"END OF RECORD\0" as *const u8 as *const i8,
    b"TACACS UID\0" as *const u8 as *const i8,
    b"OUTPUT MARKING\0" as *const u8 as *const i8,
    b"TTYLOC\0" as *const u8 as *const i8,
    b"3270 REGIME\0" as *const u8 as *const i8,
    b"X3 PAD\0" as *const u8 as *const i8,
    b"NAWS\0" as *const u8 as *const i8,
    b"TERM SPEED\0" as *const u8 as *const i8,
    b"LFLOW\0" as *const u8 as *const i8,
    b"LINEMODE\0" as *const u8 as *const i8,
    b"XDISPLOC\0" as *const u8 as *const i8,
    b"OLD-ENVIRON\0" as *const u8 as *const i8,
    b"AUTHENTICATION\0" as *const u8 as *const i8,
    b"ENCRYPT\0" as *const u8 as *const i8,
    b"NEW-ENVIRON\0" as *const u8 as *const i8,
];
static mut telnetcmds: [* const i8; 20] = [
    b"EOF\0" as *const u8 as *const i8,
    b"SUSP\0" as *const u8 as *const i8,
    b"ABORT\0" as *const u8 as *const i8,
    b"EOR\0" as *const u8 as *const i8,
    b"SE\0" as *const u8 as *const i8,
    b"NOP\0" as *const u8 as *const i8,
    b"DMARK\0" as *const u8 as *const i8,
    b"BRK\0" as *const u8 as *const i8,
    b"IP\0" as *const u8 as *const i8,
    b"AO\0" as *const u8 as *const i8,
    b"AYT\0" as *const u8 as *const i8,
    b"EC\0" as *const u8 as *const i8,
    b"EL\0" as *const u8 as *const i8,
    b"GA\0" as *const u8 as *const i8,
    b"SB\0" as *const u8 as *const i8,
    b"WILL\0" as *const u8 as *const i8,
    b"WONT\0" as *const u8 as *const i8,
    b"DO\0" as *const u8 as *const i8,
    b"DONT\0" as *const u8 as *const i8,
    b"IAC\0" as *const u8 as *const i8,
];
#[no_mangle]
pub static mut Curl_handler_telnet: crate::src::lib::http2::Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"TELNET\0" as *const u8 as *const i8,
            setup_connection: None,
            do_it: Some(
                telnet_do,
            ),
            done: Some(
                telnet_done,
            ),
            do_more: None,
            connect_it: None,
            connecting: None,
            doing: None,
            proto_getsock: None,
            doing_getsock: None,
            domore_getsock: None,
            perform_getsock: None,
            disconnect: None,
            readwrite: None,
            connection_check: None,
            attach: None,
            defport: 23 as i32,
            protocol: ((1 as i32) << 6 as i32) as u32,
            family: ((1 as i32) << 6 as i32) as u32,
            flags: (0 as i32 | (1 as i32) << 6 as i32)
                as u32,
        };
        init
    }
};
unsafe extern "C" fn init_telnet(mut data: * mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut tn: * mut crate::src::lib::telnet::TELNET = 0 as *mut TELNET;
    tn = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(1 as i32 as size_t, ::std::mem::size_of::<TELNET>() as u64)
        as *mut TELNET;
    if tn.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    let mut fresh0 = &mut ((*data).req.p.telnet);
    *fresh0 = tn;
    (*tn).telrcv_state = CURL_TS_DATA;
    let mut fresh1 = &mut ((*tn).subpointer);
    *fresh1 = ((*tn).subbuffer).as_mut_ptr();
    (*tn).us_preferred[3 as i32 as usize] = 1 as i32;
    (*tn).him_preferred[3 as i32 as usize] = 1 as i32;
    (*tn).us_preferred[0 as i32 as usize] = 1 as i32;
    (*tn).him_preferred[0 as i32 as usize] = 1 as i32;
    (*tn).him_preferred[1 as i32 as usize] = 1 as i32;
    (*tn).subnegotiation[31 as i32 as usize] = 1 as i32;
    return CURLE_OK;
}
unsafe extern "C" fn negotiate(mut data: * mut crate::src::lib::http2::Curl_easy) {
    let mut i: i32 = 0;
    let mut tn: * mut crate::src::lib::telnet::TELNET = (*data).req.p.telnet;
    i = 0 as i32;
    while i < 40 as i32 {
        if !(i == 1 as i32) {
            if (*tn).us_preferred[i as usize] == 1 as i32 {
                set_local_option(data, i, 1 as i32);
            }
            if (*tn).him_preferred[i as usize] == 1 as i32 {
                set_remote_option(data, i, 1 as i32);
            }
        }
        i += 1;
    }
}
unsafe extern "C" fn printoption(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut direction: * const i8,
    mut cmd: i32,
    mut option: i32,
) {
    if ((*data).set).verbose() != 0 {
        if cmd == 255 as i32 {
            if option as u32 >= 236 as i32 as u32
                && option as u32 <= 255 as i32 as u32
            {
                Curl_infof(
                    data,
                    b"%s IAC %s\0" as *const u8 as *const i8,
                    direction,
                    telnetcmds[(option - 236 as i32) as usize],
                );
            } else {
                Curl_infof(
                    data,
                    b"%s IAC %d\0" as *const u8 as *const i8,
                    direction,
                    option,
                );
            }
        } else {
            let mut fmt: * const i8 = if cmd == 251 as i32 {
                b"WILL\0" as *const u8 as *const i8
            } else if cmd == 252 as i32 {
                b"WONT\0" as *const u8 as *const i8
            } else if cmd == 253 as i32 {
                b"DO\0" as *const u8 as *const i8
            } else if cmd == 254 as i32 {
                b"DONT\0" as *const u8 as *const i8
            } else {
                0 as *const i8
            };
            if !fmt.is_null() {
                let mut opt: * const i8 = 0 as *const i8;
                if option <= 39 as i32 {
                    opt = telnetoptions[option as usize];
                } else if option == 255 as i32 {
                    opt = b"EXOPL\0" as *const u8 as *const i8;
                } else {
                    opt = 0 as *const i8;
                }
                if !opt.is_null() {
                    Curl_infof(
                        data,
                        b"%s %s %s\0" as *const u8 as *const i8,
                        direction,
                        fmt,
                        opt,
                    );
                } else {
                    Curl_infof(
                        data,
                        b"%s %s %d\0" as *const u8 as *const i8,
                        direction,
                        fmt,
                        option,
                    );
                }
            } else {
                Curl_infof(
                    data,
                    b"%s %d %d\0" as *const u8 as *const i8,
                    direction,
                    cmd,
                    option,
                );
            }
        }
    }
}
unsafe extern "C" fn send_negotiation(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut cmd: i32,
    mut option: i32,
) {
    let mut buf: [u8; 3] = [0; 3];
    let mut bytes_written: i64 = 0;
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    buf[0 as i32 as usize] = 255 as i32 as u8;
    buf[1 as i32 as usize] = cmd as u8;
    buf[2 as i32 as usize] = option as u8;
    bytes_written = send(
        (*conn).sock[0 as i32 as usize],
        buf.as_mut_ptr() as *const libc::c_void,
        3 as i32 as size_t,
        MSG_NOSIGNAL as i32,
    );
    if bytes_written < 0 as i32 as i64 {
        let mut err: i32 = *__errno_location();
        Curl_failf(
            data,
            b"Sending data failed (%d)\0" as *const u8 as *const i8,
            err,
        );
    }
    printoption(data, b"SENT\0" as *const u8 as *const i8, cmd, option);
}
unsafe extern "C" fn set_remote_option(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut option: i32,
    mut newstate: i32,
) {
    let mut tn: * mut crate::src::lib::telnet::TELNET = (*data).req.p.telnet;
    if newstate == 1 as i32 {
        match (*tn).him[option as usize] {
            0 => {
                (*tn).him[option as usize] = 2 as i32;
                send_negotiation(data, 253 as i32, option);
            }
            3 => {
                match (*tn).himq[option as usize] {
                    0 => {
                        (*tn).himq[option as usize] = 1 as i32;
                    }
                    1 | _ => {}
                }
            }
            2 => {
                match (*tn).himq[option as usize] {
                    1 => {
                        (*tn).himq[option as usize] = 0 as i32;
                    }
                    0 | _ => {}
                }
            }
            1 | _ => {}
        }
    } else {
        match (*tn).him[option as usize] {
            1 => {
                (*tn).him[option as usize] = 3 as i32;
                send_negotiation(data, 254 as i32, option);
            }
            3 => {
                match (*tn).himq[option as usize] {
                    1 => {
                        (*tn).himq[option as usize] = 0 as i32;
                    }
                    0 | _ => {}
                }
            }
            2 => {
                match (*tn).himq[option as usize] {
                    0 => {
                        (*tn).himq[option as usize] = 1 as i32;
                    }
                    1 | _ => {}
                }
            }
            0 | _ => {}
        }
    };
}
unsafe extern "C" fn rec_will(mut data: * mut crate::src::lib::http2::Curl_easy, mut option: i32) {
    let mut tn: * mut crate::src::lib::telnet::TELNET = (*data).req.p.telnet;
    match (*tn).him[option as usize] {
        0 => {
            if (*tn).him_preferred[option as usize] == 1 as i32 {
                (*tn).him[option as usize] = 1 as i32;
                send_negotiation(data, 253 as i32, option);
            } else {
                send_negotiation(data, 254 as i32, option);
            }
        }
        3 => {
            match (*tn).himq[option as usize] {
                0 => {
                    (*tn).him[option as usize] = 0 as i32;
                }
                1 => {
                    (*tn).him[option as usize] = 1 as i32;
                    (*tn).himq[option as usize] = 0 as i32;
                }
                _ => {}
            }
        }
        2 => {
            match (*tn).himq[option as usize] {
                0 => {
                    (*tn).him[option as usize] = 1 as i32;
                }
                1 => {
                    (*tn).him[option as usize] = 3 as i32;
                    (*tn).himq[option as usize] = 0 as i32;
                    send_negotiation(data, 254 as i32, option);
                }
                _ => {}
            }
        }
        1 | _ => {}
    };
}
unsafe extern "C" fn rec_wont(mut data: * mut crate::src::lib::http2::Curl_easy, mut option: i32) {
    let mut tn: * mut crate::src::lib::telnet::TELNET = (*data).req.p.telnet;
    match (*tn).him[option as usize] {
        1 => {
            (*tn).him[option as usize] = 0 as i32;
            send_negotiation(data, 254 as i32, option);
        }
        3 => {
            match (*tn).himq[option as usize] {
                0 => {
                    (*tn).him[option as usize] = 0 as i32;
                }
                1 => {
                    (*tn).him[option as usize] = 2 as i32;
                    (*tn).himq[option as usize] = 0 as i32;
                    send_negotiation(data, 253 as i32, option);
                }
                _ => {}
            }
        }
        2 => {
            match (*tn).himq[option as usize] {
                0 => {
                    (*tn).him[option as usize] = 0 as i32;
                }
                1 => {
                    (*tn).him[option as usize] = 0 as i32;
                    (*tn).himq[option as usize] = 0 as i32;
                }
                _ => {}
            }
        }
        0 | _ => {}
    };
}
unsafe extern "C" fn set_local_option(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut option: i32,
    mut newstate: i32,
) {
    let mut tn: * mut crate::src::lib::telnet::TELNET = (*data).req.p.telnet;
    if newstate == 1 as i32 {
        match (*tn).us[option as usize] {
            0 => {
                (*tn).us[option as usize] = 2 as i32;
                send_negotiation(data, 251 as i32, option);
            }
            3 => {
                match (*tn).usq[option as usize] {
                    0 => {
                        (*tn).usq[option as usize] = 1 as i32;
                    }
                    1 | _ => {}
                }
            }
            2 => {
                match (*tn).usq[option as usize] {
                    1 => {
                        (*tn).usq[option as usize] = 0 as i32;
                    }
                    0 | _ => {}
                }
            }
            1 | _ => {}
        }
    } else {
        match (*tn).us[option as usize] {
            1 => {
                (*tn).us[option as usize] = 3 as i32;
                send_negotiation(data, 252 as i32, option);
            }
            3 => {
                match (*tn).usq[option as usize] {
                    1 => {
                        (*tn).usq[option as usize] = 0 as i32;
                    }
                    0 | _ => {}
                }
            }
            2 => {
                match (*tn).usq[option as usize] {
                    0 => {
                        (*tn).usq[option as usize] = 1 as i32;
                    }
                    1 | _ => {}
                }
            }
            0 | _ => {}
        }
    };
}
unsafe extern "C" fn rec_do(mut data: * mut crate::src::lib::http2::Curl_easy, mut option: i32) {
    let mut tn: * mut crate::src::lib::telnet::TELNET = (*data).req.p.telnet;
    match (*tn).us[option as usize] {
        0 => {
            if (*tn).us_preferred[option as usize] == 1 as i32 {
                (*tn).us[option as usize] = 1 as i32;
                send_negotiation(data, 251 as i32, option);
                if (*tn).subnegotiation[option as usize] == 1 as i32 {
                    sendsuboption(data, option);
                }
            } else if (*tn).subnegotiation[option as usize] == 1 as i32 {
                (*tn).us[option as usize] = 1 as i32;
                send_negotiation(data, 251 as i32, option);
                sendsuboption(data, option);
            } else {
                send_negotiation(data, 252 as i32, option);
            }
        }
        3 => {
            match (*tn).usq[option as usize] {
                0 => {
                    (*tn).us[option as usize] = 0 as i32;
                }
                1 => {
                    (*tn).us[option as usize] = 1 as i32;
                    (*tn).usq[option as usize] = 0 as i32;
                }
                _ => {}
            }
        }
        2 => {
            match (*tn).usq[option as usize] {
                0 => {
                    (*tn).us[option as usize] = 1 as i32;
                    if (*tn).subnegotiation[option as usize] == 1 as i32 {
                        sendsuboption(data, option);
                    }
                }
                1 => {
                    (*tn).us[option as usize] = 3 as i32;
                    (*tn).himq[option as usize] = 0 as i32;
                    send_negotiation(data, 252 as i32, option);
                }
                _ => {}
            }
        }
        1 | _ => {}
    };
}
unsafe extern "C" fn rec_dont(mut data: * mut crate::src::lib::http2::Curl_easy, mut option: i32) {
    let mut tn: * mut crate::src::lib::telnet::TELNET = (*data).req.p.telnet;
    match (*tn).us[option as usize] {
        1 => {
            (*tn).us[option as usize] = 0 as i32;
            send_negotiation(data, 252 as i32, option);
        }
        3 => {
            match (*tn).usq[option as usize] {
                0 => {
                    (*tn).us[option as usize] = 0 as i32;
                }
                1 => {
                    (*tn).us[option as usize] = 2 as i32;
                    (*tn).usq[option as usize] = 0 as i32;
                    send_negotiation(data, 251 as i32, option);
                }
                _ => {}
            }
        }
        2 => {
            match (*tn).usq[option as usize] {
                0 => {
                    (*tn).us[option as usize] = 0 as i32;
                }
                1 => {
                    (*tn).us[option as usize] = 0 as i32;
                    (*tn).usq[option as usize] = 0 as i32;
                }
                _ => {}
            }
        }
        0 | _ => {}
    };
}
unsafe extern "C" fn printsub(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut direction: i32,
    mut pointer: * mut u8,
    mut length: u64,
) {
    if ((*data).set).verbose() != 0 {
        let mut i: u32 = 0 as i32 as u32;
        if direction != 0 {
            Curl_infof(
                data,
                b"%s IAC SB \0" as *const u8 as *const i8,
                if direction == '<' as i32 {
                    b"RCVD\0" as *const u8 as *const i8
                } else {
                    b"SENT\0" as *const u8 as *const i8
                },
            );
            if length >= 3 as i32 as u64 {
                let mut j: i32 = 0;
                i = *pointer
                    .offset(
                        length.wrapping_sub(2 as i32 as u64) as isize,
                    ) as u32;
                j = *pointer
                    .offset(
                        length.wrapping_sub(1 as i32 as u64) as isize,
                    ) as i32;
                if i != 255 as i32 as u32 || j != 240 as i32 {
                    Curl_infof(
                        data,
                        b"(terminated by \0" as *const u8 as *const i8,
                    );
                    if i <= 39 as i32 as u32 {
                        Curl_infof(
                            data,
                            b"%s \0" as *const u8 as *const i8,
                            telnetoptions[i as usize],
                        );
                    } else if i >= 236 as i32 as u32
                            && i <= 255 as i32 as u32
                        {
                        Curl_infof(
                            data,
                            b"%s \0" as *const u8 as *const i8,
                            telnetcmds[i.wrapping_sub(236 as i32 as u32)
                                as usize],
                        );
                    } else {
                        Curl_infof(
                            data,
                            b"%u \0" as *const u8 as *const i8,
                            i,
                        );
                    }
                    if j <= 39 as i32 {
                        Curl_infof(
                            data,
                            b"%s\0" as *const u8 as *const i8,
                            telnetoptions[j as usize],
                        );
                    } else if j as u32 >= 236 as i32 as u32
                            && j as u32 <= 255 as i32 as u32
                        {
                        Curl_infof(
                            data,
                            b"%s\0" as *const u8 as *const i8,
                            telnetcmds[(j - 236 as i32) as usize],
                        );
                    } else {
                        Curl_infof(data, b"%d\0" as *const u8 as *const i8, j);
                    }
                    Curl_infof(
                        data,
                        b", not IAC SE!) \0" as *const u8 as *const i8,
                    );
                }
            }
            length = (length as u64)
                .wrapping_sub(2 as i32 as u64) as size_t as size_t;
        }
        if length < 1 as i32 as u64 {
            Curl_infof(
                data,
                b"(Empty suboption?)\0" as *const u8 as *const i8,
            );
            return;
        }
        if *pointer.offset(0 as i32 as isize) as i32 <= 39 as i32
        {
            match *pointer.offset(0 as i32 as isize) as i32 {
                24 | 35 | 39 | 31 => {
                    Curl_infof(
                        data,
                        b"%s\0" as *const u8 as *const i8,
                        telnetoptions[*pointer.offset(0 as i32 as isize)
                            as usize],
                    );
                }
                _ => {
                    Curl_infof(
                        data,
                        b"%s (unsupported)\0" as *const u8 as *const i8,
                        telnetoptions[*pointer.offset(0 as i32 as isize)
                            as usize],
                    );
                }
            }
        } else {
            Curl_infof(
                data,
                b"%d (unknown)\0" as *const u8 as *const i8,
                *pointer.offset(i as isize) as i32,
            );
        }
        match *pointer.offset(0 as i32 as isize) as i32 {
            31 => {
                if length > 4 as i32 as u64 {
                    Curl_infof(
                        data,
                        b"Width: %d ; Height: %d\0" as *const u8 as *const i8,
                        (*pointer.offset(1 as i32 as isize) as i32)
                            << 8 as i32
                            | *pointer.offset(2 as i32 as isize) as i32,
                        (*pointer.offset(3 as i32 as isize) as i32)
                            << 8 as i32
                            | *pointer.offset(4 as i32 as isize) as i32,
                    );
                }
            }
            _ => {
                match *pointer.offset(1 as i32 as isize) as i32 {
                    0 => {
                        Curl_infof(data, b" IS\0" as *const u8 as *const i8);
                    }
                    1 => {
                        Curl_infof(data, b" SEND\0" as *const u8 as *const i8);
                    }
                    2 => {
                        Curl_infof(
                            data,
                            b" INFO/REPLY\0" as *const u8 as *const i8,
                        );
                    }
                    3 => {
                        Curl_infof(data, b" NAME\0" as *const u8 as *const i8);
                    }
                    _ => {}
                }
                match *pointer.offset(0 as i32 as isize) as i32 {
                    24 | 35 => {
                        *pointer
                            .offset(length as isize) = 0 as i32 as u8;
                        Curl_infof(
                            data,
                            b" \"%s\"\0" as *const u8 as *const i8,
                            &mut *pointer.offset(2 as i32 as isize)
                                as *mut u8,
                        );
                    }
                    39 => {
                        if *pointer.offset(1 as i32 as isize) as i32
                            == 0 as i32
                        {
                            Curl_infof(data, b" \0" as *const u8 as *const i8);
                            i = 3 as i32 as u32;
                            while (i as u64) < length {
                                match *pointer.offset(i as isize) as i32 {
                                    0 => {
                                        Curl_infof(
                                            data,
                                            b", \0" as *const u8 as *const i8,
                                        );
                                    }
                                    1 => {
                                        Curl_infof(
                                            data,
                                            b" = \0" as *const u8 as *const i8,
                                        );
                                    }
                                    _ => {
                                        Curl_infof(
                                            data,
                                            b"%c\0" as *const u8 as *const i8,
                                            *pointer.offset(i as isize) as i32,
                                        );
                                    }
                                }
                                i = i.wrapping_add(1);
                            }
                        }
                    }
                    _ => {
                        i = 2 as i32 as u32;
                        while (i as u64) < length {
                            Curl_infof(
                                data,
                                b" %.2x\0" as *const u8 as *const i8,
                                *pointer.offset(i as isize) as i32,
                            );
                            i = i.wrapping_add(1);
                        }
                    }
                }
            }
        }
    }
}
unsafe extern "C" fn check_telnet_options(mut data: * mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut head: * mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
    let mut beg: * mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
    let mut option_keyword: [i8; 128] = *core::intrinsics::transmute::<&'_ [u8; 128], &'_ mut [i8; 128]>(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut option_arg: [i8; 256] = *core::intrinsics::transmute::<&'_ [u8; 256], &'_ mut [i8; 256]>(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut tn: * mut crate::src::lib::telnet::TELNET = (*data).req.p.telnet;
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    let mut result: u32 = CURLE_OK;
    let mut binary_option: i32 = 0;
    if ((*conn).bits).user_passwd() != 0 {
        curl_msnprintf(
            option_arg.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 256]>() as u64,
            b"USER,%s\0" as *const u8 as *const i8,
            (*conn).user,
        );
        beg = curl_slist_append((*tn).telnet_vars, option_arg.as_mut_ptr());
        if beg.is_null() {
            curl_slist_free_all((*tn).telnet_vars);
            let mut fresh2 = &mut ((*tn).telnet_vars);
            *fresh2 = 0 as *mut curl_slist;
            return CURLE_OUT_OF_MEMORY;
        }
        let mut fresh3 = &mut ((*tn).telnet_vars);
        *fresh3 = beg;
        (*tn).us_preferred[39 as i32 as usize] = 1 as i32;
    }
    head = (*data).set.telnet_options;
    while !head.is_null() {
        if sscanf(
            (*head).data,
            b"%127[^= ]%*[ =]%255s\0" as *const u8 as *const i8,
            option_keyword.as_mut_ptr(),
            option_arg.as_mut_ptr(),
        ) == 2 as i32
        {
            if Curl_strcasecompare(
                option_keyword.as_mut_ptr(),
                b"TTYPE\0" as *const u8 as *const i8,
            ) != 0
            {
                strncpy(
                    ((*tn).subopt_ttype).as_mut_ptr(),
                    option_arg.as_mut_ptr(),
                    31 as i32 as u64,
                );
                (*tn)
                    .subopt_ttype[31 as i32
                    as usize] = 0 as i32 as i8;
                (*tn).us_preferred[24 as i32 as usize] = 1 as i32;
            } else if Curl_strcasecompare(
                    option_keyword.as_mut_ptr(),
                    b"XDISPLOC\0" as *const u8 as *const i8,
                ) != 0
                {
                strncpy(
                    ((*tn).subopt_xdisploc).as_mut_ptr(),
                    option_arg.as_mut_ptr(),
                    127 as i32 as u64,
                );
                (*tn)
                    .subopt_xdisploc[127 as i32
                    as usize] = 0 as i32 as i8;
                (*tn).us_preferred[35 as i32 as usize] = 1 as i32;
            } else if Curl_strcasecompare(
                    option_keyword.as_mut_ptr(),
                    b"NEW_ENV\0" as *const u8 as *const i8,
                ) != 0
                {
                beg = curl_slist_append((*tn).telnet_vars, option_arg.as_mut_ptr());
                if beg.is_null() {
                    result = CURLE_OUT_OF_MEMORY;
                    break;
                } else {
                    let mut fresh4 = &mut ((*tn).telnet_vars);
                    *fresh4 = beg;
                    (*tn).us_preferred[39 as i32 as usize] = 1 as i32;
                }
            } else if Curl_strcasecompare(
                    option_keyword.as_mut_ptr(),
                    b"WS\0" as *const u8 as *const i8,
                ) != 0
                {
                if sscanf(
                    option_arg.as_mut_ptr(),
                    b"%hu%*[xX]%hu\0" as *const u8 as *const i8,
                    &mut (*tn).subopt_wsx as *mut u16,
                    &mut (*tn).subopt_wsy as *mut u16,
                ) == 2 as i32
                {
                    (*tn).us_preferred[31 as i32 as usize] = 1 as i32;
                } else {
                    Curl_failf(
                        data,
                        b"Syntax error in telnet option: %s\0" as *const u8
                            as *const i8,
                        (*head).data,
                    );
                    result = CURLE_SETOPT_OPTION_SYNTAX;
                    break;
                }
            } else if Curl_strcasecompare(
                    option_keyword.as_mut_ptr(),
                    b"BINARY\0" as *const u8 as *const i8,
                ) != 0
                {
                binary_option = atoi(option_arg.as_mut_ptr());
                if binary_option != 1 as i32 {
                    (*tn).us_preferred[0 as i32 as usize] = 0 as i32;
                    (*tn).him_preferred[0 as i32 as usize] = 0 as i32;
                }
            } else {
                Curl_failf(
                    data,
                    b"Unknown telnet option %s\0" as *const u8 as *const i8,
                    (*head).data,
                );
                result = CURLE_UNKNOWN_OPTION;
                break;
            }
            head = (*head).next;
        } else {
            Curl_failf(
                data,
                b"Syntax error in telnet option: %s\0" as *const u8
                    as *const i8,
                (*head).data,
            );
            result = CURLE_SETOPT_OPTION_SYNTAX;
            break;
        }
    }
    if result as u64 != 0 {
        curl_slist_free_all((*tn).telnet_vars);
        let mut fresh5 = &mut ((*tn).telnet_vars);
        *fresh5 = 0 as *mut curl_slist;
    }
    return result;
}
unsafe extern "C" fn suboption(mut data: * mut crate::src::lib::http2::Curl_easy) {
    let mut v: * mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
    let mut temp: [u8; 2048] = [0; 2048];
    let mut bytes_written: i64 = 0;
    let mut len: u64 = 0;
    let mut err: i32 = 0;
    let mut varname: [i8; 128] = *core::intrinsics::transmute::<&'_ [u8; 128], &'_ mut [i8; 128]>(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut varval: [i8; 128] = *core::intrinsics::transmute::<&'_ [u8; 128], &'_ mut [i8; 128]>(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut tn: * mut crate::src::lib::telnet::TELNET = (*data).req.p.telnet;
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    printsub(
        data,
        '<' as i32,
        ((*tn).subbuffer).as_mut_ptr(),
        (((*tn).subend).offset_from((*tn).subpointer) as i64
            + 2 as i32 as i64) as size_t,
    );
    let mut fresh6 = &mut ((*tn).subpointer);
    let mut fresh7 = *fresh6;
    *fresh6 = (*fresh6).offset(1);
    match *fresh7 as i32 & 0xff as i32 {
        24 => {
            len = (strlen(((*tn).subopt_ttype).as_mut_ptr()))
                .wrapping_add(4 as i32 as u64)
                .wrapping_add(2 as i32 as u64);
            curl_msnprintf(
                temp.as_mut_ptr() as *mut i8,
                ::std::mem::size_of::<[u8; 2048]>() as u64,
                b"%c%c%c%c%s%c%c\0" as *const u8 as *const i8,
                255 as i32,
                250 as i32,
                24 as i32,
                0 as i32,
                ((*tn).subopt_ttype).as_mut_ptr(),
                255 as i32,
                240 as i32,
            );
            bytes_written = send(
                (*conn).sock[0 as i32 as usize],
                temp.as_mut_ptr() as *const libc::c_void,
                len,
                MSG_NOSIGNAL as i32,
            );
            if bytes_written < 0 as i32 as i64 {
                err = *__errno_location();
                Curl_failf(
                    data,
                    b"Sending data failed (%d)\0" as *const u8 as *const i8,
                    err,
                );
            }
            printsub(
                data,
                '>' as i32,
                &mut *temp.as_mut_ptr().offset(2 as i32 as isize),
                len.wrapping_sub(2 as i32 as u64),
            );
        }
        35 => {
            len = (strlen(((*tn).subopt_xdisploc).as_mut_ptr()))
                .wrapping_add(4 as i32 as u64)
                .wrapping_add(2 as i32 as u64);
            curl_msnprintf(
                temp.as_mut_ptr() as *mut i8,
                ::std::mem::size_of::<[u8; 2048]>() as u64,
                b"%c%c%c%c%s%c%c\0" as *const u8 as *const i8,
                255 as i32,
                250 as i32,
                35 as i32,
                0 as i32,
                ((*tn).subopt_xdisploc).as_mut_ptr(),
                255 as i32,
                240 as i32,
            );
            bytes_written = send(
                (*conn).sock[0 as i32 as usize],
                temp.as_mut_ptr() as *const libc::c_void,
                len,
                MSG_NOSIGNAL as i32,
            );
            if bytes_written < 0 as i32 as i64 {
                err = *__errno_location();
                Curl_failf(
                    data,
                    b"Sending data failed (%d)\0" as *const u8 as *const i8,
                    err,
                );
            }
            printsub(
                data,
                '>' as i32,
                &mut *temp.as_mut_ptr().offset(2 as i32 as isize),
                len.wrapping_sub(2 as i32 as u64),
            );
        }
        39 => {
            curl_msnprintf(
                temp.as_mut_ptr() as *mut i8,
                ::std::mem::size_of::<[u8; 2048]>() as u64,
                b"%c%c%c%c\0" as *const u8 as *const i8,
                255 as i32,
                250 as i32,
                39 as i32,
                0 as i32,
            );
            len = 4 as i32 as size_t;
            v = (*tn).telnet_vars;
            while !v.is_null() {
                let mut tmplen: u64 = (strlen((*v).data))
                    .wrapping_add(1 as i32 as u64);
                if len.wrapping_add(tmplen)
                    < (::std::mem::size_of::<[u8; 2048]>() as u64
                        as i32 - 6 as i32) as u64
                {
                    let mut rv: i32 = 0;
                    let mut sep: [i8; 2] = *core::intrinsics::transmute::<&'_ [u8; 2], &'_ mut [i8; 2]>(b"\0\0");
                    varval[0 as i32 as usize] = 0 as i32 as i8;
                    rv = sscanf(
                        (*v).data,
                        b"%127[^,]%1[,]%127s\0" as *const u8 as *const i8,
                        varname.as_mut_ptr(),
                        sep.as_mut_ptr(),
                        varval.as_mut_ptr(),
                    );
                    if rv == 1 as i32 {
                        len = (len as u64)
                            .wrapping_add(
                                curl_msnprintf(
                                    &mut *temp.as_mut_ptr().offset(len as isize)
                                        as *mut u8 as *mut i8,
                                    (::std::mem::size_of::<[u8; 2048]>()
                                        as u64)
                                        .wrapping_sub(len),
                                    b"%c%s\0" as *const u8 as *const i8,
                                    0 as i32,
                                    varname.as_mut_ptr(),
                                ) as u64,
                            ) as size_t as size_t;
                    } else if rv >= 2 as i32 {
                        len = (len as u64)
                            .wrapping_add(
                                curl_msnprintf(
                                    &mut *temp.as_mut_ptr().offset(len as isize)
                                        as *mut u8 as *mut i8,
                                    (::std::mem::size_of::<[u8; 2048]>()
                                        as u64)
                                        .wrapping_sub(len),
                                    b"%c%s%c%s\0" as *const u8 as *const i8,
                                    0 as i32,
                                    varname.as_mut_ptr(),
                                    1 as i32,
                                    varval.as_mut_ptr(),
                                ) as u64,
                            ) as size_t as size_t;
                    }
                }
                v = (*v).next;
            }
            curl_msnprintf(
                &mut *temp.as_mut_ptr().offset(len as isize) as *mut u8
                    as *mut i8,
                (::std::mem::size_of::<[u8; 2048]>() as u64)
                    .wrapping_sub(len),
                b"%c%c\0" as *const u8 as *const i8,
                255 as i32,
                240 as i32,
            );
            len = (len as u64).wrapping_add(2 as i32 as u64)
                as size_t as size_t;
            bytes_written = send(
                (*conn).sock[0 as i32 as usize],
                temp.as_mut_ptr() as *const libc::c_void,
                len,
                MSG_NOSIGNAL as i32,
            );
            if bytes_written < 0 as i32 as i64 {
                err = *__errno_location();
                Curl_failf(
                    data,
                    b"Sending data failed (%d)\0" as *const u8 as *const i8,
                    err,
                );
            }
            printsub(
                data,
                '>' as i32,
                &mut *temp.as_mut_ptr().offset(2 as i32 as isize),
                len.wrapping_sub(2 as i32 as u64),
            );
        }
        _ => {}
    };
}
unsafe extern "C" fn sendsuboption(mut data: * mut crate::src::lib::http2::Curl_easy, mut option: i32) {
    let mut bytes_written: i64 = 0;
    let mut err: i32 = 0;
    let mut x: u16 = 0;
    let mut y: u16 = 0;
    let mut uc1: * mut u8 = (0 as * mut u8);
    let mut uc2: * mut u8 = (0 as * mut u8);
    let mut tn: * mut crate::src::lib::telnet::TELNET = (*data).req.p.telnet;
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    match option {
        31 => {
            let mut fresh8 = &mut ((*tn).subpointer);
            *fresh8 = ((*tn).subbuffer).as_mut_ptr();
            if (*tn).subpointer
                < ((*tn).subbuffer)
                    .as_mut_ptr()
                    .offset(
                        ::std::mem::size_of::<[u8; 512]>() as u64
                            as isize,
                    )
            {
                let mut fresh9 = &mut ((*tn).subpointer);
                let mut fresh10 = *fresh9;
                *fresh9 = (*fresh9).offset(1);
                *fresh10 = 255 as i32 as u8;
            }
            if (*tn).subpointer
                < ((*tn).subbuffer)
                    .as_mut_ptr()
                    .offset(
                        ::std::mem::size_of::<[u8; 512]>() as u64
                            as isize,
                    )
            {
                let mut fresh11 = &mut ((*tn).subpointer);
                let mut fresh12 = *fresh11;
                *fresh11 = (*fresh11).offset(1);
                *fresh12 = 250 as i32 as u8;
            }
            if (*tn).subpointer
                < ((*tn).subbuffer)
                    .as_mut_ptr()
                    .offset(
                        ::std::mem::size_of::<[u8; 512]>() as u64
                            as isize,
                    )
            {
                let mut fresh13 = &mut ((*tn).subpointer);
                let mut fresh14 = *fresh13;
                *fresh13 = (*fresh13).offset(1);
                *fresh14 = 31 as i32 as u8;
            }
            x = __bswap_16((*tn).subopt_wsx);
            y = __bswap_16((*tn).subopt_wsy);
            uc1 = &mut x as *mut u16 as *mut u8;
            uc2 = &mut y as *mut u16 as *mut u8;
            if (*tn).subpointer
                < ((*tn).subbuffer)
                    .as_mut_ptr()
                    .offset(
                        ::std::mem::size_of::<[u8; 512]>() as u64
                            as isize,
                    )
            {
                let mut fresh15 = &mut ((*tn).subpointer);
                let mut fresh16 = *fresh15;
                *fresh15 = (*fresh15).offset(1);
                *fresh16 = *uc1.offset(0 as i32 as isize);
            }
            if (*tn).subpointer
                < ((*tn).subbuffer)
                    .as_mut_ptr()
                    .offset(
                        ::std::mem::size_of::<[u8; 512]>() as u64
                            as isize,
                    )
            {
                let mut fresh17 = &mut ((*tn).subpointer);
                let mut fresh18 = *fresh17;
                *fresh17 = (*fresh17).offset(1);
                *fresh18 = *uc1.offset(1 as i32 as isize);
            }
            if (*tn).subpointer
                < ((*tn).subbuffer)
                    .as_mut_ptr()
                    .offset(
                        ::std::mem::size_of::<[u8; 512]>() as u64
                            as isize,
                    )
            {
                let mut fresh19 = &mut ((*tn).subpointer);
                let mut fresh20 = *fresh19;
                *fresh19 = (*fresh19).offset(1);
                *fresh20 = *uc2.offset(0 as i32 as isize);
            }
            if (*tn).subpointer
                < ((*tn).subbuffer)
                    .as_mut_ptr()
                    .offset(
                        ::std::mem::size_of::<[u8; 512]>() as u64
                            as isize,
                    )
            {
                let mut fresh21 = &mut ((*tn).subpointer);
                let mut fresh22 = *fresh21;
                *fresh21 = (*fresh21).offset(1);
                *fresh22 = *uc2.offset(1 as i32 as isize);
            }
            if (*tn).subpointer
                < ((*tn).subbuffer)
                    .as_mut_ptr()
                    .offset(
                        ::std::mem::size_of::<[u8; 512]>() as u64
                            as isize,
                    )
            {
                let mut fresh23 = &mut ((*tn).subpointer);
                let mut fresh24 = *fresh23;
                *fresh23 = (*fresh23).offset(1);
                *fresh24 = 255 as i32 as u8;
            }
            if (*tn).subpointer
                < ((*tn).subbuffer)
                    .as_mut_ptr()
                    .offset(
                        ::std::mem::size_of::<[u8; 512]>() as u64
                            as isize,
                    )
            {
                let mut fresh25 = &mut ((*tn).subpointer);
                let mut fresh26 = *fresh25;
                *fresh25 = (*fresh25).offset(1);
                *fresh26 = 240 as i32 as u8;
            }
            let mut fresh27 = &mut ((*tn).subend);
            *fresh27 = (*tn).subpointer;
            let mut fresh28 = &mut ((*tn).subpointer);
            *fresh28 = ((*tn).subbuffer).as_mut_ptr();
            printsub(
                data,
                '>' as i32,
                ((*tn).subbuffer).as_mut_ptr().offset(2 as i32 as isize),
                (((*tn).subend).offset_from((*tn).subpointer) as i64
                    - 2 as i32 as i64) as size_t,
            );
            bytes_written = send(
                (*conn).sock[0 as i32 as usize],
                ((*tn).subbuffer).as_mut_ptr() as *const libc::c_void,
                3 as i32 as size_t,
                MSG_NOSIGNAL as i32,
            );
            if bytes_written < 0 as i32 as i64 {
                err = *__errno_location();
                Curl_failf(
                    data,
                    b"Sending data failed (%d)\0" as *const u8 as *const i8,
                    err,
                );
            }
            send_telnet_data(
                data,
                (((*tn).subbuffer).as_mut_ptr() as *mut i8)
                    .offset(3 as i32 as isize),
                4 as i32 as ssize_t,
            );
            bytes_written = send(
                (*conn).sock[0 as i32 as usize],
                ((*tn).subbuffer).as_mut_ptr().offset(7 as i32 as isize)
                    as *const libc::c_void,
                2 as i32 as size_t,
                MSG_NOSIGNAL as i32,
            );
            if bytes_written < 0 as i32 as i64 {
                err = *__errno_location();
                Curl_failf(
                    data,
                    b"Sending data failed (%d)\0" as *const u8 as *const i8,
                    err,
                );
            }
        }
        _ => {}
    };
}
unsafe extern "C" fn telrcv(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut inbuf: * const u8,
    mut count: i64,
) -> u32 {
    let mut c: u8 = 0;
    let mut result: u32 = CURLE_OK;
    let mut in_0: i32 = 0 as i32;
    let mut startwrite: i32 = -(1 as i32);
    let mut tn: * mut crate::src::lib::telnet::TELNET = (*data).req.p.telnet;
    loop {
        let mut fresh29 = count;
        count = count - 1;
        if !(fresh29 != 0) {
            break;
        }
        c = *inbuf.offset(in_0 as isize);
        let mut current_block_93: u64;
        match (*tn).telrcv_state as u32 {
            6 => {
                (*tn).telrcv_state = CURL_TS_DATA;
                if c as i32 == '\u{0}' as i32 {
                    if startwrite >= 0 as i32 {
                        result = Curl_client_write(
                            data,
                            (1 as i32) << 0 as i32,
                            &*inbuf.offset(startwrite as isize) as *const u8
                                as *mut i8,
                            (in_0 - startwrite) as size_t,
                        );
                        if result as u64 != 0 {
                            return result;
                        }
                    }
                    startwrite = -(1 as i32);
                } else if startwrite < 0 as i32 {
                    startwrite = in_0;
                }
                current_block_93 = 6733407218104445560;
            }
            0 => {
                if c as i32 == 255 as i32 {
                    (*tn).telrcv_state = CURL_TS_IAC;
                    if startwrite >= 0 as i32 {
                        result = Curl_client_write(
                            data,
                            (1 as i32) << 0 as i32,
                            &*inbuf.offset(startwrite as isize) as *const u8
                                as *mut i8,
                            (in_0 - startwrite) as size_t,
                        );
                        if result as u64 != 0 {
                            return result;
                        }
                    }
                    startwrite = -(1 as i32);
                } else {
                    if c as i32 == '\r' as i32 {
                        (*tn).telrcv_state = CURL_TS_CR;
                    }
                    if startwrite < 0 as i32 {
                        startwrite = in_0;
                    }
                }
                current_block_93 = 6733407218104445560;
            }
            1 => {
                current_block_93 = 11636175345244025579;
            }
            2 => {
                printoption(
                    data,
                    b"RCVD\0" as *const u8 as *const i8,
                    251 as i32,
                    c as i32,
                );
                (*tn).please_negotiate = 1 as i32;
                rec_will(data, c as i32);
                (*tn).telrcv_state = CURL_TS_DATA;
                current_block_93 = 6733407218104445560;
            }
            3 => {
                printoption(
                    data,
                    b"RCVD\0" as *const u8 as *const i8,
                    252 as i32,
                    c as i32,
                );
                (*tn).please_negotiate = 1 as i32;
                rec_wont(data, c as i32);
                (*tn).telrcv_state = CURL_TS_DATA;
                current_block_93 = 6733407218104445560;
            }
            4 => {
                printoption(
                    data,
                    b"RCVD\0" as *const u8 as *const i8,
                    253 as i32,
                    c as i32,
                );
                (*tn).please_negotiate = 1 as i32;
                rec_do(data, c as i32);
                (*tn).telrcv_state = CURL_TS_DATA;
                current_block_93 = 6733407218104445560;
            }
            5 => {
                printoption(
                    data,
                    b"RCVD\0" as *const u8 as *const i8,
                    254 as i32,
                    c as i32,
                );
                (*tn).please_negotiate = 1 as i32;
                rec_dont(data, c as i32);
                (*tn).telrcv_state = CURL_TS_DATA;
                current_block_93 = 6733407218104445560;
            }
            7 => {
                if c as i32 == 255 as i32 {
                    (*tn).telrcv_state = CURL_TS_SE;
                } else if (*tn).subpointer
                        < ((*tn).subbuffer)
                            .as_mut_ptr()
                            .offset(
                                ::std::mem::size_of::<[u8; 512]>()
                                    as u64 as isize,
                            )
                    {
                    let mut fresh31 = &mut ((*tn).subpointer);
                    let mut fresh32 = *fresh31;
                    *fresh31 = (*fresh31).offset(1);
                    *fresh32 = c;
                }
                current_block_93 = 6733407218104445560;
            }
            8 => {
                if c as i32 != 240 as i32 {
                    if c as i32 != 255 as i32 {
                        if (*tn).subpointer
                            < ((*tn).subbuffer)
                                .as_mut_ptr()
                                .offset(
                                    ::std::mem::size_of::<[u8; 512]>()
                                        as u64 as isize,
                                )
                        {
                            let mut fresh33 = &mut ((*tn).subpointer);
                            let mut fresh34 = *fresh33;
                            *fresh33 = (*fresh33).offset(1);
                            *fresh34 = 255 as i32 as u8;
                        }
                        if (*tn).subpointer
                            < ((*tn).subbuffer)
                                .as_mut_ptr()
                                .offset(
                                    ::std::mem::size_of::<[u8; 512]>()
                                        as u64 as isize,
                                )
                        {
                            let mut fresh35 = &mut ((*tn).subpointer);
                            let mut fresh36 = *fresh35;
                            *fresh35 = (*fresh35).offset(1);
                            *fresh36 = c;
                        }
                        let mut fresh37 = &mut ((*tn).subpointer);
                        *fresh37 = (*fresh37).offset(-(2 as i32 as isize));
                        let mut fresh38 = &mut ((*tn).subend);
                        *fresh38 = (*tn).subpointer;
                        let mut fresh39 = &mut ((*tn).subpointer);
                        *fresh39 = ((*tn).subbuffer).as_mut_ptr();
                        printoption(
                            data,
                            b"In SUBOPTION processing, RCVD\0" as *const u8
                                as *const i8,
                            255 as i32,
                            c as i32,
                        );
                        suboption(data);
                        (*tn).telrcv_state = CURL_TS_IAC;
                        current_block_93 = 11636175345244025579;
                    } else {
                        if (*tn).subpointer
                            < ((*tn).subbuffer)
                                .as_mut_ptr()
                                .offset(
                                    ::std::mem::size_of::<[u8; 512]>()
                                        as u64 as isize,
                                )
                        {
                            let mut fresh40 = &mut ((*tn).subpointer);
                            let mut fresh41 = *fresh40;
                            *fresh40 = (*fresh40).offset(1);
                            *fresh41 = c;
                        }
                        (*tn).telrcv_state = CURL_TS_SB;
                        current_block_93 = 6733407218104445560;
                    }
                } else {
                    if (*tn).subpointer
                        < ((*tn).subbuffer)
                            .as_mut_ptr()
                            .offset(
                                ::std::mem::size_of::<[u8; 512]>()
                                    as u64 as isize,
                            )
                    {
                        let mut fresh42 = &mut ((*tn).subpointer);
                        let mut fresh43 = *fresh42;
                        *fresh42 = (*fresh42).offset(1);
                        *fresh43 = 255 as i32 as u8;
                    }
                    if (*tn).subpointer
                        < ((*tn).subbuffer)
                            .as_mut_ptr()
                            .offset(
                                ::std::mem::size_of::<[u8; 512]>()
                                    as u64 as isize,
                            )
                    {
                        let mut fresh44 = &mut ((*tn).subpointer);
                        let mut fresh45 = *fresh44;
                        *fresh44 = (*fresh44).offset(1);
                        *fresh45 = 240 as i32 as u8;
                    }
                    let mut fresh46 = &mut ((*tn).subpointer);
                    *fresh46 = (*fresh46).offset(-(2 as i32 as isize));
                    let mut fresh47 = &mut ((*tn).subend);
                    *fresh47 = (*tn).subpointer;
                    let mut fresh48 = &mut ((*tn).subpointer);
                    *fresh48 = ((*tn).subbuffer).as_mut_ptr();
                    suboption(data);
                    (*tn).telrcv_state = CURL_TS_DATA;
                    current_block_93 = 6733407218104445560;
                }
            }
            _ => {
                current_block_93 = 6733407218104445560;
            }
        }
        match current_block_93 {
            11636175345244025579 => {
                match c as i32 {
                    251 => {
                        (*tn).telrcv_state = CURL_TS_WILL;
                    }
                    252 => {
                        (*tn).telrcv_state = CURL_TS_WONT;
                    }
                    253 => {
                        (*tn).telrcv_state = CURL_TS_DO;
                    }
                    254 => {
                        (*tn).telrcv_state = CURL_TS_DONT;
                    }
                    250 => {
                        let mut fresh30 = &mut ((*tn).subpointer);
                        *fresh30 = ((*tn).subbuffer).as_mut_ptr();
                        (*tn).telrcv_state = CURL_TS_SB;
                    }
                    255 => {
                        (*tn).telrcv_state = CURL_TS_DATA;
                        if startwrite < 0 as i32 {
                            startwrite = in_0;
                        }
                    }
                    242 | 241 | 249 | _ => {
                        (*tn).telrcv_state = CURL_TS_DATA;
                        printoption(
                            data,
                            b"RCVD\0" as *const u8 as *const i8,
                            255 as i32,
                            c as i32,
                        );
                    }
                }
            }
            _ => {}
        }
        in_0 += 1;
    }
    if startwrite >= 0 as i32 {
        result = Curl_client_write(
            data,
            (1 as i32) << 0 as i32,
            &*inbuf.offset(startwrite as isize) as *const u8
                as *mut i8,
            (in_0 - startwrite) as size_t,
        );
        if result as u64 != 0 {
            return result;
        }
    }
    startwrite = -(1 as i32);
    return CURLE_OK;
}
unsafe extern "C" fn send_telnet_data(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut buffer: * mut i8,
    mut nread: i64,
) -> u32 {
    let mut escapes: i64 = 0;
    let mut i: i64 = 0;
    let mut outlen: i64 = 0;
    let mut outbuf: * mut u8 = 0 as *mut u8;
    let mut result: u32 = CURLE_OK;
    let mut bytes_written: i64 = 0;
    let mut total_written: i64 = 0;
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    escapes = 0 as i32 as ssize_t;
    i = 0 as i32 as ssize_t;
    while i < nread {
        if *buffer.offset(i as isize) as u8 as i32
            == 255 as i32
        {
            escapes += 1;
        }
        i += 1;
    }
    outlen = nread + escapes;
    if outlen == nread {
        outbuf = buffer as *mut u8;
    } else {
        let mut j: i64 = 0;
        outbuf = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )((nread + escapes + 1 as i32 as i64) as size_t)
            as *mut u8;
        if outbuf.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        j = 0 as i32 as ssize_t;
        i = 0 as i32 as ssize_t;
        while i < nread {
            let mut fresh49 = j;
            j = j + 1;
            *outbuf
                .offset(fresh49 as isize) = *buffer.offset(i as isize) as u8;
            if *buffer.offset(i as isize) as u8 as i32
                == 255 as i32
            {
                let mut fresh50 = j;
                j = j + 1;
                *outbuf.offset(fresh50 as isize) = 255 as i32 as u8;
            }
            i += 1;
        }
        *outbuf.offset(j as isize) = '\u{0}' as i32 as u8;
    }
    total_written = 0 as i32 as ssize_t;
    while result as u64 == 0 && total_written < outlen {
        let mut pfd: [crate::src::lib::multi::pollfd; 1] = [pollfd {
            fd: 0,
            events: 0,
            revents: 0,
        }; 1];
        pfd[0 as i32 as usize].fd = (*conn).sock[0 as i32 as usize];
        pfd[0 as i32 as usize].events = 0x4 as i32 as i16;
        match Curl_poll(
            pfd.as_mut_ptr(),
            1 as i32 as u32,
            -(1 as i32) as timediff_t,
        ) {
            -1 | 0 => {
                result = CURLE_SEND_ERROR;
            }
            _ => {
                bytes_written = 0 as i32 as ssize_t;
                result = Curl_write(
                    data,
                    (*conn).sock[0 as i32 as usize],
                    outbuf.offset(total_written as isize) as *const libc::c_void,
                    (outlen - total_written) as size_t,
                    Some(&mut bytes_written),
                );
                total_written += bytes_written;
            }
        }
    }
    if outbuf != buffer as *mut u8 {
        Curl_cfree.expect("non-null function pointer")(outbuf as *mut libc::c_void);
    }
    return result;
}
unsafe extern "C" fn telnet_done(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut status: u32,
    mut premature: bool,
) -> u32 {
    let mut tn: * mut crate::src::lib::telnet::TELNET = (*data).req.p.telnet;
    if tn.is_null() {
        return CURLE_OK;
    }
    curl_slist_free_all((*tn).telnet_vars);
    let mut fresh51 = &mut ((*tn).telnet_vars);
    *fresh51 = 0 as *mut curl_slist;
    Curl_cfree
        .expect("non-null function pointer")((*data).req.p.telnet as *mut libc::c_void);
    let mut fresh52 = &mut ((*data).req.p.telnet);
    *fresh52 = 0 as *mut TELNET;
    return CURLE_OK;
}
unsafe extern "C" fn telnet_do(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut done: * mut bool,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    let mut sockfd: i32 = (*conn).sock[0 as i32 as usize];
    let mut interval_ms: i64 = 0;
    let mut pfd: [crate::src::lib::multi::pollfd; 2] = [pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    }; 2];
    let mut poll_cnt: i32 = 0;
    let mut total_dl: i64 = 0 as i32 as curl_off_t;
    let mut total_ul: i64 = 0 as i32 as curl_off_t;
    let mut nread: i64 = 0;
    let mut now: crate::src::lib::http2::curltime = curltime { tv_sec: 0, tv_usec: 0 };
    let mut keepon: bool = 1 as i32 != 0;
    let mut buf: * mut i8 = (*data).state.buffer;
    let mut tn: * mut crate::src::lib::telnet::TELNET = 0 as *mut TELNET;
    *done = 1 as i32 != 0;
    result = init_telnet(data);
    if result as u64 != 0 {
        return result;
    }
    tn = (*data).req.p.telnet;
    result = check_telnet_options(data);
    if result as u64 != 0 {
        return result;
    }
    pfd[0 as i32 as usize].fd = sockfd;
    pfd[0 as i32 as usize].events = 0x1 as i32 as i16;
    if ((*data).set).is_fread_set() != 0 {
        poll_cnt = 1 as i32;
        interval_ms = 100 as i32 as timediff_t;
    } else {
        pfd[1 as i32 as usize].fd = fileno((*data).state.in_0 as *mut FILE);
        pfd[1 as i32 as usize].events = 0x1 as i32 as i16;
        poll_cnt = 2 as i32;
        interval_ms = (1 as i32 * 1000 as i32) as timediff_t;
    }
    let mut current_block_54: u64;
    while keepon {
        match Curl_poll(pfd.as_mut_ptr(), poll_cnt as u32, interval_ms) {
            -1 => {
                keepon = 0 as i32 != 0;
                continue;
            }
            0 => {
                pfd[0 as i32 as usize]
                    .revents = 0 as i32 as i16;
                pfd[1 as i32 as usize]
                    .revents = 0 as i32 as i16;
            }
            _ => {}
        }
        if pfd[0 as i32 as usize].revents as i32 & 0x1 as i32
            != 0
        {
            result = Curl_read(
                data,
                sockfd,
                buf,
                (*data).set.buffer_size as size_t,
                Some(&mut nread),
            );
            if result as u32 == CURLE_AGAIN as i32 as u32 {
                current_block_54 = 15970011996474399071;
            } else if result as u64 != 0 {
                keepon = 0 as i32 != 0;
                current_block_54 = 15970011996474399071;
            } else if nread <= 0 as i32 as i64 {
                keepon = 0 as i32 != 0;
                current_block_54 = 15970011996474399071;
            } else {
                total_dl += nread;
                Curl_pgrsSetDownloadCounter(data, total_dl);
                result = telrcv(data, buf as *mut u8, nread);
                if result as u64 != 0 {
                    keepon = 0 as i32 != 0;
                    current_block_54 = 15970011996474399071;
                } else {
                    if (*tn).please_negotiate != 0 && (*tn).already_negotiated == 0 {
                        negotiate(data);
                        (*tn).already_negotiated = 1 as i32;
                    }
                    current_block_54 = 1345366029464561491;
                }
            }
        } else {
            current_block_54 = 1345366029464561491;
        }
        match current_block_54 {
            1345366029464561491 => {
                nread = 0 as i32 as ssize_t;
                if poll_cnt == 2 as i32 {
                    if pfd[1 as i32 as usize].revents as i32
                        & 0x1 as i32 != 0
                    {
                        nread = read(
                            pfd[1 as i32 as usize].fd,
                            buf as *mut libc::c_void,
                            (*data).set.buffer_size as size_t,
                        );
                    }
                    current_block_54 = 5235537862154438448;
                } else {
                    nread = ((*data).state.fread_func)
                        .expect(
                            "non-null function pointer",
                        )(
                        buf,
                        1 as i32 as size_t,
                        (*data).set.buffer_size as size_t,
                        (*data).state.in_0,
                    ) as i32 as ssize_t;
                    if nread == 0x10000000 as i32 as i64 {
                        keepon = 0 as i32 != 0;
                        current_block_54 = 15970011996474399071;
                    } else if nread == 0x10000001 as i32 as i64 {
                        current_block_54 = 15970011996474399071;
                    } else {
                        current_block_54 = 5235537862154438448;
                    }
                }
                match current_block_54 {
                    15970011996474399071 => {}
                    _ => {
                        if nread > 0 as i32 as i64 {
                            result = send_telnet_data(data, buf, nread);
                            if result as u64 != 0 {
                                keepon = 0 as i32 != 0;
                            } else {
                                total_ul += nread;
                                Curl_pgrsSetUploadCounter(data, total_ul);
                            }
                        } else if nread < 0 as i32 as i64 {
                            keepon = 0 as i32 != 0;
                        }
                    }
                }
            }
            _ => {}
        }
        if (*data).set.timeout != 0 {
            now = Curl_now();
            if Curl_timediff(now, (*conn).created) >= (*data).set.timeout {
                Curl_failf(data, b"Time-out\0" as *const u8 as *const i8);
                result = CURLE_OPERATION_TIMEDOUT;
                keepon = 0 as i32 != 0;
            }
        }
        if !(Curl_pgrsUpdate(data) != 0) {
            continue;
        }
        result = CURLE_ABORTED_BY_CALLBACK;
        break;
    }
    Curl_setup_transfer(
        data,
        -(1 as i32),
        -(1 as i32) as curl_off_t,
        0 as i32 != 0,
        -(1 as i32),
    );
    return result;
}
use crate::laertes_rt::*;
