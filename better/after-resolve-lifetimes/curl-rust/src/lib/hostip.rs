use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn socket(
        __domain: i32,
        __type: i32,
        __protocol: i32,
    ) -> i32;
    fn sscanf(_: * const i8, _: * const i8, _: ...) -> i32;
    fn time(__timer: * mut i64) -> i64;
    fn close(__fd: i32) -> i32;
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
    fn memset(
        _: * mut core::ffi::c_void,
        _: i32,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn strcpy(_: * mut i8, _: * const i8) -> * mut i8;
    fn strchr(_: * const i8, _: i32) -> * mut i8;
    fn strlen(_: * const i8) -> u64;
    fn __ctype_tolower_loc() -> * mut * const i32;
    fn inet_pton(
        __af: i32,
        __cp: * const i8,
        __buf: * mut core::ffi::c_void,
    ) -> i32;
    fn inet_ntop(
        __af: i32,
        __cp: * const core::ffi::c_void,
        __buf: * mut i8,
        __len: u32,
    ) -> * const i8;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::asyn_thread::Curl_resolver_getsock;
pub use crate::src::lib::asyn_thread::Curl_resolver_is_resolved;
pub use crate::src::lib::conncache::Curl_conncache_remove_conn;
pub use crate::src::lib::curl_addrinfo::Curl_freeaddrinfo;
pub use crate::src::lib::curl_addrinfo::Curl_ip2addr;
pub use crate::src::lib::curl_addrinfo::Curl_str2addr;
pub use crate::src::lib::doh::Curl_doh;
pub use crate::src::lib::doh::Curl_doh_is_resolved;
pub use crate::src::lib::hash::Curl_hash_add;
pub use crate::src::lib::hash::Curl_hash_clean;
pub use crate::src::lib::hash::Curl_hash_clean_with_criterium;
pub use crate::src::lib::hash::Curl_hash_delete;
pub use crate::src::lib::hash::Curl_hash_init;
pub use crate::src::lib::hash::Curl_hash_pick;
pub use crate::src::lib::hash::Curl_hash_str;
pub use crate::src::lib::hash::Curl_str_key_compare;
pub use crate::src::lib::hostasyn::Curl_getaddrinfo;
pub use crate::src::lib::hostip6::Curl_ipvalid;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::multi::Curl_detach_connnection;
pub use crate::src::lib::multi::Curl_set_in_callback;
pub use crate::src::lib::rand::Curl_rand;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::share::Curl_share_lock;
pub use crate::src::lib::share::Curl_share_unlock;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::url::Curl_disconnect;
pub use crate::src::lib::url::Curl_setup_conn;
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::http2::curl_pushheaders;
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
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::telnet::TELNET;
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
// #[derive(Copy, Clone)]

pub type __sigset_t = crate::src::lib::conncache::__sigset_t;
pub type socklen_t = u32;
pub type __socket_type = u32;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_RAW: __socket_type = 3;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;
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
pub type curl_calloc_callback<'a1> = Option<unsafe extern "C"  fn(_: u64,_: u64,) -> Option<&'a1 mut core::ffi::c_void>>;
pub type CURLSHcode = u32;
pub const CURLSHE_LAST: CURLSHcode = 6;
pub const CURLSHE_NOT_BUILT_IN: CURLSHcode = 5;
pub const CURLSHE_NOMEM: CURLSHcode = 4;
pub const CURLSHE_INVALID: CURLSHcode = 3;
pub const CURLSHE_IN_USE: CURLSHcode = 2;
pub const CURLSHE_BAD_OPTION: CURLSHcode = 1;
pub const CURLSHE_OK: CURLSHcode = 0;
pub type uint16_t = u16;
pub type in_addr_t = u32;
// #[derive(Copy, Clone)]

pub type in_addr = crate::src::lib::connect::in_addr;
pub type C2RustUnnamed_6 = u32;
pub const IPPROTO_MAX: C2RustUnnamed_6 = 256;
pub const IPPROTO_RAW: C2RustUnnamed_6 = 255;
pub const IPPROTO_MPLS: C2RustUnnamed_6 = 137;
pub const IPPROTO_UDPLITE: C2RustUnnamed_6 = 136;
pub const IPPROTO_SCTP: C2RustUnnamed_6 = 132;
pub const IPPROTO_COMP: C2RustUnnamed_6 = 108;
pub const IPPROTO_PIM: C2RustUnnamed_6 = 103;
pub const IPPROTO_ENCAP: C2RustUnnamed_6 = 98;
pub const IPPROTO_BEETPH: C2RustUnnamed_6 = 94;
pub const IPPROTO_MTP: C2RustUnnamed_6 = 92;
pub const IPPROTO_AH: C2RustUnnamed_6 = 51;
pub const IPPROTO_ESP: C2RustUnnamed_6 = 50;
pub const IPPROTO_GRE: C2RustUnnamed_6 = 47;
pub const IPPROTO_RSVP: C2RustUnnamed_6 = 46;
pub const IPPROTO_IPV6: C2RustUnnamed_6 = 41;
pub const IPPROTO_DCCP: C2RustUnnamed_6 = 33;
pub const IPPROTO_TP: C2RustUnnamed_6 = 29;
pub const IPPROTO_IDP: C2RustUnnamed_6 = 22;
pub const IPPROTO_UDP: C2RustUnnamed_6 = 17;
pub const IPPROTO_PUP: C2RustUnnamed_6 = 12;
pub const IPPROTO_EGP: C2RustUnnamed_6 = 8;
pub const IPPROTO_TCP: C2RustUnnamed_6 = 6;
pub const IPPROTO_IPIP: C2RustUnnamed_6 = 4;
pub const IPPROTO_IGMP: C2RustUnnamed_6 = 2;
pub const IPPROTO_ICMP: C2RustUnnamed_6 = 1;
pub const IPPROTO_IP: C2RustUnnamed_6 = 0;
pub type in_port_t = u16;
// #[derive(Copy, Clone)]

pub type in6_addr = crate::src::lib::connect::in6_addr;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_7 = crate::src::lib::connect::C2RustUnnamed_8;
// #[derive(Copy, Clone)]

pub type sockaddr_in = crate::src::lib::connect::sockaddr_in;
// #[derive(Copy, Clone)]

pub type sockaddr_in6 = crate::src::lib::connect::sockaddr_in6;
pub type __jmp_buf = [i64; 8];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __jmp_buf_tag {
    pub __jmpbuf: [i64; 8],
    pub __mask_was_saved: i32,
    pub __saved_mask: crate::src::lib::conncache::__sigset_t,
}
impl __jmp_buf_tag {
    pub const fn new() -> Self {
        __jmp_buf_tag {
        __jmpbuf: [0,0,0,0,0,0,0,0,],
        __mask_was_saved: 0,
        __saved_mask: crate::src::lib::conncache::__sigset_t::new()
        }
    }
}

impl std::default::Default for __jmp_buf_tag {
    fn default() -> Self { __jmp_buf_tag::new() }
}

pub type sigjmp_buf = [crate::src::lib::hostip::__jmp_buf_tag; 1];
pub type ptrdiff_t = i64;
pub type resolve_t = i32;
pub const CURLRESOLV_PENDING: resolve_t = 1;
pub const CURLRESOLV_RESOLVED: resolve_t = 0;
pub const CURLRESOLV_ERROR: resolve_t = -1;
pub const CURLRESOLV_TIMEDOUT: resolve_t = -2;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostcache_prune_data {
    pub cache_timeout: i64,
    pub now: i64,
}
impl hostcache_prune_data {
    pub const fn new() -> Self {
        hostcache_prune_data {
        cache_timeout: 0,
        now: 0
        }
    }
}

impl std::default::Default for hostcache_prune_data {
    fn default() -> Self { hostcache_prune_data::new() }
}

#[inline]
 extern "C" fn __bswap_16(mut __bsx: u16) -> u16 {
    return (__bsx as i32 >> 8 as i32 & 0xff as i32
        | (__bsx as i32 & 0xff as i32) << 8 as i32)
        as __uint16_t;
}
#[inline]
unsafe extern "C" fn tolower(mut __c: i32) -> i32 {
    return if __c >= -(128 as i32) && __c < 256 as i32 {
        *(*__ctype_tolower_loc()).offset(__c as isize)
    } else {
        __c
    };
}
#[no_mangle]
pub unsafe extern "C" fn Curl_num_addresses(
    mut addr: * const crate::src::lib::http2::Curl_addrinfo,
) -> i32 {
    let mut i: i32 = 0 as i32;
    while !addr.is_null() {
        addr = (*addr).ai_next;
        i += 1;
    }
    return i;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_printable_address(
    mut ai: * const crate::src::lib::http2::Curl_addrinfo,
    mut buf: * mut i8,
    mut bufsize: u64,
) {
    *buf.offset(0 as i32 as isize) = 0 as i32 as i8;
    match (*ai).ai_family {
        2 => {
            let mut sa4: * const crate::src::lib::connect::sockaddr_in = (*ai).ai_addr as *const libc::c_void
                as *const sockaddr_in;
            let mut ipaddr4: * const crate::src::lib::connect::in_addr = &(*sa4).sin_addr;
            inet_ntop(
                (*ai).ai_family,
                ipaddr4 as *const libc::c_void,
                buf,
                bufsize as curl_socklen_t,
            );
        }
        10 => {
            let mut sa6: * const crate::src::lib::connect::sockaddr_in6 = (*ai).ai_addr as *const libc::c_void
                as *const sockaddr_in6;
            let mut ipaddr6: * const crate::src::lib::connect::in6_addr = &(*sa6).sin6_addr;
            inet_ntop(
                (*ai).ai_family,
                ipaddr6 as *const libc::c_void,
                buf,
                bufsize as curl_socklen_t,
            );
        }
        _ => {}
    };
}
unsafe extern "C" fn create_hostcache_id(
    mut name: * const i8,
    mut port: i32,
    mut ptr: * mut i8,
    mut buflen: u64,
) {
    let mut len: u64 = strlen(name);
    if len > buflen.wrapping_sub(7 as i32 as u64) {
        len = buflen.wrapping_sub(7 as i32 as u64);
    }
    loop {
        let mut fresh0 = len;
        len = len.wrapping_sub(1);
        if !(fresh0 != 0) {
            break;
        }
        let mut fresh4 = ptr;
        ptr = ptr.offset(1);
        *fresh4 = ({
            let mut __res: i32 = 0;
            if ::std::mem::size_of::<i32>() as u64
                > 1 as i32 as u64
            {
                if 0 != 0 {
                    let mut fresh1 = name;
                    name = name.offset(1);
                    let mut __c: i32 = *fresh1 as u8 as i32;
                    __res = if __c < -(128 as i32) || __c > 255 as i32 {
                        __c
                    } else {
                        *(*__ctype_tolower_loc()).offset(__c as isize)
                    };
                } else {
                    let mut fresh2 = name;
                    name = name.offset(1);
                    __res = tolower(*fresh2 as u8 as i32);
                }
            } else {
                let mut fresh3 = name;
                name = name.offset(1);
                __res = *(*__ctype_tolower_loc())
                    .offset(*fresh3 as u8 as i32 as isize);
            }
            __res
        }) as i8;
    }
    curl_msnprintf(
        ptr,
        7 as i32 as size_t,
        b":%u\0" as *const u8 as *const i8,
        port,
    );
}
unsafe extern "C" fn hostcache_timestamp_remove(
    mut datap: * mut core::ffi::c_void,
    mut hc: * mut core::ffi::c_void,
) -> i32 {
    let mut data: * mut crate::src::lib::hostip::hostcache_prune_data = datap as *mut hostcache_prune_data;
    let mut c: * mut crate::src::lib::http2::Curl_dns_entry = hc as *mut Curl_dns_entry;
    return (0 as i32 as i64 != (*c).timestamp
        && (*data).now - (*c).timestamp >= (*data).cache_timeout) as i32;
}
unsafe extern "C" fn hostcache_prune(
    mut hostcache: * mut crate::src::lib::http2::Curl_hash,
    mut cache_timeout: i64,
    mut now: i64,
) {
    let mut user: crate::src::lib::hostip::hostcache_prune_data = hostcache_prune_data {
        cache_timeout: 0,
        now: 0,
    };
    user.cache_timeout = cache_timeout;
    user.now = now;
    Curl_hash_clean_with_criterium(
        hostcache,
        &mut user as *mut hostcache_prune_data as *mut libc::c_void,
        Some(
            hostcache_timestamp_remove,
        ),
    );
}
#[no_mangle]
pub unsafe extern "C" fn Curl_hostcache_prune(mut data: * mut crate::src::lib::http2::Curl_easy) {
    let mut now: i64 = 0;
    if (*data).set.dns_cache_timeout == -(1 as i32) as i64
        || ((*data).dns.hostcache).is_null()
    {
        return;
    }
    if !((*data).share).is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE);
    }
    time(&mut now);
    hostcache_prune((*data).dns.hostcache, (*data).set.dns_cache_timeout, now);
    if !((*data).share).is_null() {
        Curl_share_unlock(data, CURL_LOCK_DATA_DNS);
    }
}
#[no_mangle]
pub static mut curl_jmpenv: [crate::src::lib::hostip::__jmp_buf_tag; 1] = [__jmp_buf_tag {
    __jmpbuf: [0; 8],
    __mask_was_saved: 0,
    __saved_mask: __sigset_t { __val: [0; 16] },
}; 1];
unsafe extern "C" fn fetch_addr(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut hostname: * const i8,
    mut port: i32,
) -> * mut crate::src::lib::http2::Curl_dns_entry {
    let mut dns: * mut crate::src::lib::http2::Curl_dns_entry = 0 as *mut Curl_dns_entry;
    let mut entry_len: u64 = 0;
    let mut entry_id: [i8; 262] = [0; 262];
    create_hostcache_id(
        hostname,
        port,
        entry_id.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 262]>() as u64,
    );
    entry_len = strlen(entry_id.as_mut_ptr());
    dns = Curl_hash_pick(
        (*data).dns.hostcache,
        entry_id.as_mut_ptr() as *mut libc::c_void,
        entry_len.wrapping_add(1 as i32 as u64),
    ) as *mut Curl_dns_entry;
    if dns.is_null() && ((*data).state).wildcard_resolve() as i32 != 0 {
        create_hostcache_id(
            b"*\0" as *const u8 as *const i8,
            port,
            entry_id.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 262]>() as u64,
        );
        entry_len = strlen(entry_id.as_mut_ptr());
        dns = Curl_hash_pick(
            (*data).dns.hostcache,
            entry_id.as_mut_ptr() as *mut libc::c_void,
            entry_len.wrapping_add(1 as i32 as u64),
        ) as *mut Curl_dns_entry;
    }
    if !dns.is_null()
        && (*data).set.dns_cache_timeout != -(1 as i32) as i64
    {
        let mut user: crate::src::lib::hostip::hostcache_prune_data = hostcache_prune_data {
            cache_timeout: 0,
            now: 0,
        };
        time(&mut user.now);
        user.cache_timeout = (*data).set.dns_cache_timeout;
        if hostcache_timestamp_remove(
            &mut user as *mut hostcache_prune_data as *mut libc::c_void,
            dns as *mut libc::c_void,
        ) != 0
        {
            Curl_infof(
                data,
                b"Hostname in DNS cache was stale, zapped\0" as *const u8
                    as *const i8,
            );
            dns = 0 as *mut Curl_dns_entry;
            Curl_hash_delete(
                (*data).dns.hostcache,
                entry_id.as_mut_ptr() as *mut libc::c_void,
                entry_len.wrapping_add(1 as i32 as u64),
            );
        }
    }
    return dns;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_fetch_addr(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut hostname: * const i8,
    mut port: i32,
) -> * mut crate::src::lib::http2::Curl_dns_entry {
    let mut dns: * mut crate::src::lib::http2::Curl_dns_entry = 0 as *mut Curl_dns_entry;
    if !((*data).share).is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE);
    }
    dns = fetch_addr(data, hostname, port);
    if !dns.is_null() {
        let mut fresh5 = &mut ((*dns).inuse);
        *fresh5 += 1;
    }
    if !((*data).share).is_null() {
        Curl_share_unlock(data, CURL_LOCK_DATA_DNS);
    }
    return dns;
}
unsafe extern "C" fn Curl_shuffle_addr<'a1>(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut addr: Option<&'a1 mut * mut crate::src::lib::http2::Curl_addrinfo>,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let num_addrs: i32 = Curl_num_addresses(*(borrow(& addr)).unwrap());
    if num_addrs > 1 as i32 {
        let mut nodes: * mut * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut *mut Curl_addrinfo;
        Curl_infof(
            data,
            b"Shuffling %i addresses\0" as *const u8 as *const i8,
            num_addrs,
        );
        nodes = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )(
            (num_addrs as u64)
                .wrapping_mul(
                    ::std::mem::size_of::<*mut Curl_addrinfo>() as u64,
                ),
        ) as *mut *mut Curl_addrinfo;
        if !nodes.is_null() {
            let mut i: i32 = 0;
            let mut rnd: * mut u32 = 0 as *mut u32;
            let rnd_size: u64 = (num_addrs as u64)
                .wrapping_mul(::std::mem::size_of::<u32>() as u64);
            let mut fresh6 = &mut (*nodes.offset(0 as i32 as isize));
            *fresh6 = *(borrow_mut(&mut addr)).unwrap();
            i = 1 as i32;
            while i < num_addrs {
                let mut fresh7 = &mut (*nodes.offset(i as isize));
                *fresh7 = (**nodes.offset((i - 1 as i32) as isize)).ai_next;
                i += 1;
            }
            rnd = Curl_cmalloc.expect("non-null function pointer")(rnd_size)
                as *mut u32;
            if !rnd.is_null() {
                if Curl_rand(data, rnd as *mut u8, rnd_size) as u32
                    == CURLE_OK as i32 as u32
                {
                    let mut swap_tmp: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
                    i = num_addrs - 1 as i32;
                    while i > 0 as i32 {
                        swap_tmp = *nodes
                            .offset(
                                (*rnd.offset(i as isize))
                                    .wrapping_rem((i + 1 as i32) as u32)
                                    as isize,
                            );
                        let mut fresh8 = &mut (*nodes
                            .offset(
                                (*rnd.offset(i as isize))
                                    .wrapping_rem((i + 1 as i32) as u32)
                                    as isize,
                            ));
                        *fresh8 = *nodes.offset(i as isize);
                        let mut fresh9 = &mut (*nodes.offset(i as isize));
                        *fresh9 = swap_tmp;
                        i -= 1;
                    }
                    i = 1 as i32;
                    while i < num_addrs {
                        let mut fresh10 = &mut ((**nodes
                            .offset((i - 1 as i32) as isize))
                            .ai_next);
                        *fresh10 = *nodes.offset(i as isize);
                        i += 1;
                    }
                    let mut fresh11 = &mut ((**nodes
                        .offset((num_addrs - 1 as i32) as isize))
                        .ai_next);
                    *fresh11 = 0 as *mut Curl_addrinfo;
                    *(borrow_mut(&mut addr)).unwrap() = *nodes.offset(0 as i32 as isize);
                }
                Curl_cfree.expect("non-null function pointer")(rnd as *mut libc::c_void);
            } else {
                result = CURLE_OUT_OF_MEMORY;
            }
            Curl_cfree.expect("non-null function pointer")(nodes as *mut libc::c_void);
        } else {
            result = CURLE_OUT_OF_MEMORY;
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_cache_addr(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut addr: * mut crate::src::lib::http2::Curl_addrinfo,
    mut hostname: * const i8,
    mut port: i32,
) -> * mut crate::src::lib::http2::Curl_dns_entry {
    let mut entry_id: [i8; 262] = [0; 262];
    let mut entry_len: u64 = 0;
    let mut dns: * mut crate::src::lib::http2::Curl_dns_entry = 0 as *mut Curl_dns_entry;
    let mut dns2: * mut crate::src::lib::http2::Curl_dns_entry = 0 as *mut Curl_dns_entry;
    if ((*data).set).dns_shuffle_addresses() != 0 {
        let mut result: u32 = Curl_shuffle_addr(data, Some(&mut addr));
        if result as u64 != 0 {
            return 0 as *mut Curl_dns_entry;
        }
    }
    dns = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(
        1 as i32 as size_t,
        ::std::mem::size_of::<Curl_dns_entry>() as u64,
    ) as *mut Curl_dns_entry;
    if dns.is_null() {
        return 0 as *mut Curl_dns_entry;
    }
    create_hostcache_id(
        hostname,
        port,
        entry_id.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 262]>() as u64,
    );
    entry_len = strlen(entry_id.as_mut_ptr());
    (*dns).inuse = 1 as i32 as i64;
    let mut fresh12 = &mut ((*dns).addr);
    *fresh12 = addr;
    time(&mut (*dns).timestamp);
    if (*dns).timestamp == 0 as i32 as i64 {
        (*dns).timestamp = 1 as i32 as time_t;
    }
    dns2 = Curl_hash_add(
        (*data).dns.hostcache,
        entry_id.as_mut_ptr() as *mut libc::c_void,
        entry_len.wrapping_add(1 as i32 as u64),
        dns as *mut libc::c_void,
    ) as *mut Curl_dns_entry;
    if dns2.is_null() {
        Curl_cfree.expect("non-null function pointer")(dns as *mut libc::c_void);
        return 0 as *mut Curl_dns_entry;
    }
    dns = dns2;
    let mut fresh13 = &mut ((*dns).inuse);
    *fresh13 += 1;
    return dns;
}
unsafe extern "C" fn get_localhost6(mut port: i32) -> * mut crate::src::lib::http2::Curl_addrinfo {
    let mut ca: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let ss_size: u64 = ::std::mem::size_of::<sockaddr_in6>() as u64;
    let hostlen: u64 = strlen(b"localhost\0" as *const u8 as *const i8);
    let mut sa6: crate::src::lib::connect::sockaddr_in6 = sockaddr_in6 {
        sin6_family: 0,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: in6_addr {
            __in6_u: C2RustUnnamed_7 {
                __u6_addr8: [0; 16],
            },
        },
        sin6_scope_id: 0,
    };
    let mut ipv6: [u8; 16] = [0; 16];
    let mut port16: u16 = (port & 0xffff as i32) as u16;
    ca = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(
        (::std::mem::size_of::<Curl_addrinfo>() as u64)
            .wrapping_add(ss_size)
            .wrapping_add(hostlen)
            .wrapping_add(1 as i32 as u64),
        1 as i32 as size_t,
    ) as *mut Curl_addrinfo;
    if ca.is_null() {
        return 0 as *mut Curl_addrinfo;
    }
    sa6.sin6_family = 10 as i32 as sa_family_t;
    sa6.sin6_port = __bswap_16(port16);
    sa6.sin6_flowinfo = 0 as i32 as uint32_t;
    sa6.sin6_scope_id = 0 as i32 as uint32_t;
    if inet_pton(
        10 as i32,
        b"::1\0" as *const u8 as *const i8,
        ipv6.as_mut_ptr() as *mut libc::c_void,
    ) < 1 as i32
    {
        return 0 as *mut Curl_addrinfo;
    }
    memcpy(
        &mut sa6.sin6_addr as *mut in6_addr as *mut libc::c_void,
        ipv6.as_mut_ptr() as *const libc::c_void,
        ::std::mem::size_of::<[u8; 16]>() as u64,
    );
    (*ca).ai_flags = 0 as i32;
    (*ca).ai_family = 10 as i32;
    (*ca).ai_socktype = SOCK_STREAM as i32;
    (*ca).ai_protocol = IPPROTO_TCP as i32;
    (*ca).ai_addrlen = ss_size as curl_socklen_t;
    let mut fresh14 = &mut ((*ca).ai_next);
    *fresh14 = 0 as *mut Curl_addrinfo;
    let mut fresh15 = &mut ((*ca).ai_addr);
    *fresh15 = (ca as *mut i8)
        .offset(::std::mem::size_of::<Curl_addrinfo>() as u64 as isize)
        as *mut libc::c_void as *mut sockaddr;
    memcpy(
        (*ca).ai_addr as *mut libc::c_void,
        &mut sa6 as *mut sockaddr_in6 as *const libc::c_void,
        ss_size,
    );
    let mut fresh16 = &mut ((*ca).ai_canonname);
    *fresh16 = ((*ca).ai_addr as *mut i8).offset(ss_size as isize);
    strcpy((*ca).ai_canonname, b"localhost\0" as *const u8 as *const i8);
    return ca;
}
unsafe extern "C" fn get_localhost(mut port: i32) -> * mut crate::src::lib::http2::Curl_addrinfo {
    let mut ca: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let ss_size: u64 = ::std::mem::size_of::<sockaddr_in>() as u64;
    let hostlen: u64 = strlen(b"localhost\0" as *const u8 as *const i8);
    let mut sa: crate::src::lib::connect::sockaddr_in = sockaddr_in {
        sin_family: 0,
        sin_port: 0,
        sin_addr: in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let mut ipv4: u32 = 0;
    let mut port16: u16 = (port & 0xffff as i32) as u16;
    ca = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(
        (::std::mem::size_of::<Curl_addrinfo>() as u64)
            .wrapping_add(ss_size)
            .wrapping_add(hostlen)
            .wrapping_add(1 as i32 as u64),
        1 as i32 as size_t,
    ) as *mut Curl_addrinfo;
    if ca.is_null() {
        return 0 as *mut Curl_addrinfo;
    }
    memset(
        &mut sa as *mut sockaddr_in as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<sockaddr_in>() as u64,
    );
    sa.sin_family = 2 as i32 as sa_family_t;
    sa.sin_port = __bswap_16(port16);
    if inet_pton(
        2 as i32,
        b"127.0.0.1\0" as *const u8 as *const i8,
        &mut ipv4 as *mut u32 as *mut i8 as *mut libc::c_void,
    ) < 1 as i32
    {
        return 0 as *mut Curl_addrinfo;
    }
    memcpy(
        &mut sa.sin_addr as *mut in_addr as *mut libc::c_void,
        &mut ipv4 as *mut u32 as *const libc::c_void,
        ::std::mem::size_of::<u32>() as u64,
    );
    (*ca).ai_flags = 0 as i32;
    (*ca).ai_family = 2 as i32;
    (*ca).ai_socktype = SOCK_STREAM as i32;
    (*ca).ai_protocol = IPPROTO_TCP as i32;
    (*ca).ai_addrlen = ss_size as curl_socklen_t;
    let mut fresh17 = &mut ((*ca).ai_addr);
    *fresh17 = (ca as *mut i8)
        .offset(::std::mem::size_of::<Curl_addrinfo>() as u64 as isize)
        as *mut libc::c_void as *mut sockaddr;
    memcpy(
        (*ca).ai_addr as *mut libc::c_void,
        &mut sa as *mut sockaddr_in as *const libc::c_void,
        ss_size,
    );
    let mut fresh18 = &mut ((*ca).ai_canonname);
    *fresh18 = ((*ca).ai_addr as *mut i8).offset(ss_size as isize);
    strcpy((*ca).ai_canonname, b"localhost\0" as *const u8 as *const i8);
    let mut fresh19 = &mut ((*ca).ai_next);
    *fresh19 = get_localhost6(port);
    return ca;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ipv6works(mut data: * mut crate::src::lib::http2::Curl_easy) -> bool {
    if !data.is_null() {
        return (*(*data).multi).ipv6_works
    } else {
        let mut ipv6_works: i32 = -(1 as i32);
        let mut s: i32 = socket(
            10 as i32,
            SOCK_DGRAM as i32,
            0 as i32,
        );
        if s == -(1 as i32) {
            ipv6_works = 0 as i32;
        } else {
            ipv6_works = 1 as i32;
            close(s);
        }
        return if ipv6_works > 0 as i32 {
            1 as i32
        } else {
            0 as i32
        } != 0;
    };
}
#[no_mangle]
pub unsafe extern "C" fn Curl_host_is_ipnum(mut hostname: * const i8) -> bool {
    let mut in_0: crate::src::lib::connect::in_addr = in_addr { s_addr: 0 };
    let mut in6: crate::src::lib::connect::in6_addr = in6_addr {
        __in6_u: C2RustUnnamed_7 {
            __u6_addr8: [0; 16],
        },
    };
    if inet_pton(
        2 as i32,
        hostname,
        &mut in_0 as *mut in_addr as *mut libc::c_void,
    ) > 0 as i32
        || inet_pton(
            10 as i32,
            hostname,
            &mut in6 as *mut in6_addr as *mut libc::c_void,
        ) > 0 as i32
    {
        return 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_resolv<'a1>(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut hostname: * const i8,
    mut port: i32,
    mut allowDOH: bool,
    mut entry: Option<&'a1 mut * mut crate::src::lib::http2::Curl_dns_entry>,
) -> i32 {
    let mut dns: * mut crate::src::lib::http2::Curl_dns_entry = 0 as *mut Curl_dns_entry;
    let mut result: u32 = CURLE_OK;
    let mut rc: i32 = CURLRESOLV_ERROR;
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    *(borrow_mut(&mut entry)).unwrap() = 0 as *mut Curl_dns_entry;
    let mut fresh20 = &mut ((*conn).bits);
    (*fresh20).set_doh(0 as i32 as bit);
    if !((*data).share).is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE);
    }
    dns = fetch_addr(data, hostname, port);
    if !dns.is_null() {
        Curl_infof(
            data,
            b"Hostname %s was found in DNS cache\0" as *const u8 as *const i8,
            hostname,
        );
        let mut fresh21 = &mut ((*dns).inuse);
        *fresh21 += 1;
        rc = CURLRESOLV_RESOLVED;
    }
    if !((*data).share).is_null() {
        Curl_share_unlock(data, CURL_LOCK_DATA_DNS);
    }
    if dns.is_null() {
        let mut addr: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
        let mut respwait: i32 = 0 as i32;
        let mut in_0: crate::src::lib::connect::in_addr = in_addr { s_addr: 0 };
        let ipnum: bool = 0 as i32 != 0;
        if ((*data).set.resolver_start).is_some() {
            let mut st: i32 = 0;
            Curl_set_in_callback(data, 1 as i32 != 0);
            st = ((*data).set.resolver_start)
                .expect(
                    "non-null function pointer",
                )(
                (*data).state.async_0.resolver,
                0 as *mut libc::c_void,
                (*data).set.resolver_start_client,
            );
            Curl_set_in_callback(data, 0 as i32 != 0);
            if st != 0 {
                return CURLRESOLV_ERROR;
            }
        }
        if inet_pton(
            2 as i32,
            hostname,
            &mut in_0 as *mut in_addr as *mut libc::c_void,
        ) > 0 as i32
        {
            addr = Curl_ip2addr(
                2 as i32,
                &mut in_0 as *mut in_addr as *const libc::c_void,
                hostname,
                port,
            );
        }
        if addr.is_null() {
            let mut in6: crate::src::lib::connect::in6_addr = in6_addr {
                __in6_u: C2RustUnnamed_7 {
                    __u6_addr8: [0; 16],
                },
            };
            if inet_pton(
                10 as i32,
                hostname,
                &mut in6 as *mut in6_addr as *mut libc::c_void,
            ) > 0 as i32
            {
                addr = Curl_ip2addr(
                    10 as i32,
                    &mut in6 as *mut in6_addr as *const libc::c_void,
                    hostname,
                    port,
                );
            }
        }
        if addr.is_null() {
            if (*conn).ip_version as i32 == 2 as i32
                && !Curl_ipv6works(data)
            {
                return CURLRESOLV_ERROR;
            }
            if Curl_strcasecompare(
                hostname,
                b"localhost\0" as *const u8 as *const i8,
            ) != 0
            {
                addr = get_localhost(port);
            } else if allowDOH as i32 != 0
                    && ((*data).set).doh() as i32 != 0 && !ipnum
                {
                addr = Curl_doh(data, hostname, port, Some(&mut respwait));
            } else {
                if !Curl_ipvalid(data, conn) {
                    return CURLRESOLV_ERROR;
                }
                addr = Curl_getaddrinfo(data, hostname, port, Some(&mut respwait));
            }
        }
        if addr.is_null() {
            if respwait != 0 {
                result = Curl_resolv_check(data, Some(&mut dns));
                if result as u64 != 0 {
                    return CURLRESOLV_ERROR;
                }
                if !dns.is_null() {
                    rc = CURLRESOLV_RESOLVED;
                } else {
                    rc = CURLRESOLV_PENDING;
                }
            }
        } else {
            if !((*data).share).is_null() {
                Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE);
            }
            dns = Curl_cache_addr(data, addr, hostname, port);
            if !((*data).share).is_null() {
                Curl_share_unlock(data, CURL_LOCK_DATA_DNS);
            }
            if dns.is_null() {
                Curl_freeaddrinfo(addr);
            } else {
                rc = CURLRESOLV_RESOLVED;
            }
        }
    }
    *(borrow_mut(&mut entry)).unwrap() = dns;
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_resolv_timeout<'a1>(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut hostname: * const i8,
    mut port: i32,
    mut entry: Option<&'a1 mut * mut crate::src::lib::http2::Curl_dns_entry>,
    mut timeoutms: i64,
) -> i32 {
    let mut rc: i32 = CURLRESOLV_RESOLVED;
    *(borrow_mut(&mut entry)).unwrap() = 0 as *mut Curl_dns_entry;
    if timeoutms < 0 as i32 as i64 {
        return CURLRESOLV_TIMEDOUT;
    }
    rc = Curl_resolv(data, hostname, port, 1 as i32 != 0, borrow_mut(&mut entry));
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_resolv_unlock(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut dns: * mut crate::src::lib::http2::Curl_dns_entry,
) {
    if !data.is_null() && !((*data).share).is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE);
    }
    freednsentry(dns as *mut libc::c_void);
    if !data.is_null() && !((*data).share).is_null() {
        Curl_share_unlock(data, CURL_LOCK_DATA_DNS);
    }
}
unsafe extern "C" fn freednsentry(mut freethis: * mut core::ffi::c_void) {
    let mut dns: * mut crate::src::lib::http2::Curl_dns_entry = freethis as *mut Curl_dns_entry;
    let mut fresh22 = &mut ((*dns).inuse);
    *fresh22 -= 1;
    if (*dns).inuse == 0 as i32 as i64 {
        Curl_freeaddrinfo((*dns).addr);
        Curl_cfree.expect("non-null function pointer")(dns as *mut libc::c_void);
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_mk_dnscache<'a1>(mut hash: Option<&'a1 mut crate::src::lib::http2::Curl_hash>) -> i32 {
    return Curl_hash_init(
        borrow_mut(&mut hash),
        7 as i32,
        Some(
            Curl_hash_str,
        ),
        Some(
            Curl_str_key_compare,
        ),
        Some(freednsentry),
    );
}
#[no_mangle]
pub unsafe extern "C" fn Curl_hostcache_clean(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut hash: * mut crate::src::lib::http2::Curl_hash,
) {
    if !data.is_null() && !((*data).share).is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE);
    }
    Curl_hash_clean(hash);
    if !data.is_null() && !((*data).share).is_null() {
        Curl_share_unlock(data, CURL_LOCK_DATA_DNS);
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_loadhostpairs(mut data: * mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut current_block: u64;
    let mut hostp: * mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
    let mut hostname: [i8; 256] = [0; 256];
    let mut port: i32 = 0 as i32;
    let mut fresh23 = &mut ((*data).state);
    (*fresh23).set_wildcard_resolve(0 as i32 as bit);
    hostp = (*data).state.resolve;
    while !hostp.is_null() {
        let mut entry_id: [i8; 262] = [0; 262];
        if !((*hostp).data).is_null() {
            if *((*hostp).data).offset(0 as i32 as isize) as i32
                == '-' as i32
            {
                let mut entry_len: u64 = 0;
                if 2 as i32
                    != sscanf(
                        ((*hostp).data).offset(1 as i32 as isize),
                        b"%255[^:]:%d\0" as *const u8 as *const i8,
                        hostname.as_mut_ptr(),
                        &mut port as *mut i32,
                    )
                {
                    Curl_infof(
                        data,
                        b"Couldn't parse CURLOPT_RESOLVE removal entry '%s'\0"
                            as *const u8 as *const i8,
                        (*hostp).data,
                    );
                } else {
                    create_hostcache_id(
                        hostname.as_mut_ptr(),
                        port,
                        entry_id.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 262]>() as u64,
                    );
                    entry_len = strlen(entry_id.as_mut_ptr());
                    if !((*data).share).is_null() {
                        Curl_share_lock(
                            data,
                            CURL_LOCK_DATA_DNS,
                            CURL_LOCK_ACCESS_SINGLE,
                        );
                    }
                    Curl_hash_delete(
                        (*data).dns.hostcache,
                        entry_id.as_mut_ptr() as *mut libc::c_void,
                        entry_len.wrapping_add(1 as i32 as u64),
                    );
                    if !((*data).share).is_null() {
                        Curl_share_unlock(data, CURL_LOCK_DATA_DNS);
                    }
                }
            } else {
                let mut dns: * mut crate::src::lib::http2::Curl_dns_entry = 0 as *mut Curl_dns_entry;
                let mut head: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
                let mut tail: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
                let mut entry_len_0: u64 = 0;
                let mut address: [i8; 64] = [0; 64];
                let mut addresses: * mut i8 = 0 as *mut i8;
                let mut addr_begin: * mut i8 = 0 as *mut i8;
                let mut addr_end: * mut i8 = 0 as *mut i8;
                let mut port_ptr: * mut i8 = 0 as *mut i8;
                let mut end_ptr: * mut i8 = 0 as *mut i8;
                let mut permanent: bool = 1 as i32 != 0;
                let mut host_begin: * mut i8 = 0 as *mut i8;
                let mut host_end: * mut i8 = 0 as *mut i8;
                let mut tmp_port: u64 = 0;
                let mut error: bool = 1 as i32 != 0;
                host_begin = (*hostp).data;
                if *host_begin.offset(0 as i32 as isize) as i32
                    == '+' as i32
                {
                    host_begin = host_begin.offset(1);
                    permanent = 0 as i32 != 0;
                }
                host_end = strchr(host_begin, ':' as i32);
                if !(host_end.is_null()
                    || host_end.offset_from(host_begin) as i64
                        >= ::std::mem::size_of::<[i8; 256]>() as u64
                            as ptrdiff_t)
                {
                    memcpy(
                        hostname.as_mut_ptr() as *mut libc::c_void,
                        host_begin as *const libc::c_void,
                        host_end.offset_from(host_begin) as i64 as u64,
                    );
                    hostname[host_end.offset_from(host_begin) as i64
                        as usize] = '\u{0}' as i32 as i8;
                    port_ptr = host_end.offset(1 as i32 as isize);
                    tmp_port = strtoul(port_ptr, &mut end_ptr, 10 as i32);
                    if !(tmp_port
                        > (32767 as i32 * 2 as i32 + 1 as i32)
                            as u64 || end_ptr == port_ptr
                        || *end_ptr as i32 != ':' as i32)
                    {
                        port = tmp_port as i32;
                        addresses = end_ptr.offset(1 as i32 as isize);
                        loop {
                            if !(*end_ptr != 0) {
                                current_block = 15594603006322722090;
                                break;
                            }
                            let mut alen: u64 = 0;
                            let mut ai: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
                            addr_begin = end_ptr.offset(1 as i32 as isize);
                            addr_end = strchr(addr_begin, ',' as i32);
                            if addr_end.is_null() {
                                addr_end = addr_begin.offset(strlen(addr_begin) as isize);
                            }
                            end_ptr = addr_end;
                            if *addr_begin as i32 == '[' as i32 {
                                if addr_end == addr_begin
                                    || *addr_end.offset(-(1 as i32 as isize))
                                        as i32 != ']' as i32
                                {
                                    current_block = 2415380317517078313;
                                    break;
                                }
                                addr_begin = addr_begin.offset(1);
                                addr_end = addr_end.offset(-1);
                            }
                            alen = addr_end.offset_from(addr_begin) as i64
                                as size_t;
                            if alen == 0 {
                                continue;
                            }
                            if alen
                                >= ::std::mem::size_of::<[i8; 64]>()
                                    as u64
                            {
                                current_block = 2415380317517078313;
                                break;
                            }
                            memcpy(
                                address.as_mut_ptr() as *mut libc::c_void,
                                addr_begin as *const libc::c_void,
                                alen,
                            );
                            address[alen as usize] = '\u{0}' as i32 as i8;
                            ai = Curl_str2addr(address.as_mut_ptr(), port);
                            if ai.is_null() {
                                Curl_infof(
                                    data,
                                    b"Resolve address '%s' found illegal!\0" as *const u8
                                        as *const i8,
                                    address.as_mut_ptr(),
                                );
                                current_block = 2415380317517078313;
                                break;
                            } else if !tail.is_null() {
                                let mut fresh24 = &mut ((*tail).ai_next);
                                *fresh24 = ai;
                                tail = (*tail).ai_next;
                            } else {
                                tail = ai;
                                head = tail;
                            }
                        }
                        match current_block {
                            2415380317517078313 => {}
                            _ => {
                                if !head.is_null() {
                                    error = 0 as i32 != 0;
                                }
                            }
                        }
                    }
                }
                if error {
                    Curl_failf(
                        data,
                        b"Couldn't parse CURLOPT_RESOLVE entry '%s'!\0" as *const u8
                            as *const i8,
                        (*hostp).data,
                    );
                    Curl_freeaddrinfo(head);
                    return CURLE_SETOPT_OPTION_SYNTAX;
                }
                create_hostcache_id(
                    hostname.as_mut_ptr(),
                    port,
                    entry_id.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 262]>() as u64,
                );
                entry_len_0 = strlen(entry_id.as_mut_ptr());
                if !((*data).share).is_null() {
                    Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE);
                }
                dns = Curl_hash_pick(
                    (*data).dns.hostcache,
                    entry_id.as_mut_ptr() as *mut libc::c_void,
                    entry_len_0.wrapping_add(1 as i32 as u64),
                ) as *mut Curl_dns_entry;
                if !dns.is_null() {
                    Curl_infof(
                        data,
                        b"RESOLVE %s:%d is - old addresses discarded!\0" as *const u8
                            as *const i8,
                        hostname.as_mut_ptr(),
                        port,
                    );
                    Curl_hash_delete(
                        (*data).dns.hostcache,
                        entry_id.as_mut_ptr() as *mut libc::c_void,
                        entry_len_0.wrapping_add(1 as i32 as u64),
                    );
                }
                dns = Curl_cache_addr(data, head, hostname.as_mut_ptr(), port);
                if !dns.is_null() {
                    if permanent {
                        (*dns).timestamp = 0 as i32 as time_t;
                    }
                    let mut fresh25 = &mut ((*dns).inuse);
                    *fresh25 -= 1;
                }
                if !((*data).share).is_null() {
                    Curl_share_unlock(data, CURL_LOCK_DATA_DNS);
                }
                if dns.is_null() {
                    Curl_freeaddrinfo(head);
                    return CURLE_OUT_OF_MEMORY;
                }
                Curl_infof(
                    data,
                    b"Added %s:%d:%s to DNS cache%s\0" as *const u8
                        as *const i8,
                    hostname.as_mut_ptr(),
                    port,
                    addresses,
                    if permanent as i32 != 0 {
                        b"\0" as *const u8 as *const i8
                    } else {
                        b" (non-permanent)\0" as *const u8 as *const i8
                    },
                );
                if hostname[0 as i32 as usize] as i32 == '*' as i32
                    && hostname[1 as i32 as usize] as i32
                        == '\u{0}' as i32
                {
                    Curl_infof(
                        data,
                        b"RESOLVE %s:%d is wildcard, enabling wildcard checks\0"
                            as *const u8 as *const i8,
                        hostname.as_mut_ptr(),
                        port,
                    );
                    let mut fresh26 = &mut ((*data).state);
                    (*fresh26).set_wildcard_resolve(1 as i32 as bit);
                }
            }
        }
        hostp = (*hostp).next;
    }
    let mut fresh27 = &mut ((*data).state.resolve);
    *fresh27 = 0 as *mut curl_slist;
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_resolv_check<'a1>(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut dns: Option<&'a1 mut * mut crate::src::lib::http2::Curl_dns_entry>,
) -> u32 {
    if ((*(*data).conn).bits).doh() != 0 {
        return Curl_doh_is_resolved(data, borrow_mut(&mut dns));
    }
    return Curl_resolver_is_resolved(data, borrow_mut(&mut dns));
}
#[no_mangle]
pub unsafe extern "C" fn Curl_resolv_getsock(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut socks: * mut i32,
) -> i32 {
    if ((*(*data).conn).bits).doh() != 0 {
        return 0 as i32;
    }
    return Curl_resolver_getsock(data, socks);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_once_resolved<'a1>(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut protocol_done: Option<&'a1 mut bool>,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    if !((*data).state.async_0.dns).is_null() {
        let mut fresh28 = &mut ((*conn).dns_entry);
        *fresh28 = (*data).state.async_0.dns;
        let mut fresh29 = &mut ((*data).state.async_0.dns);
        *fresh29 = 0 as *mut Curl_dns_entry;
    }
    result = Curl_setup_conn(data, borrow_mut(&mut protocol_done));
    if result as u64 != 0 {
        Curl_detach_connnection(data);
        Curl_conncache_remove_conn(data, conn, 1 as i32 != 0);
        Curl_disconnect(data, conn, 1 as i32 != 0);
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_resolver_error(mut data: * mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut host_or_proxy: * const i8 = 0 as *const i8;
    let mut result: u32 = CURLE_OK;
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    if ((*conn).bits).httpproxy() != 0 {
        host_or_proxy = b"proxy\0" as *const u8 as *const i8;
        result = CURLE_COULDNT_RESOLVE_PROXY;
    } else {
        host_or_proxy = b"host\0" as *const u8 as *const i8;
        result = CURLE_COULDNT_RESOLVE_HOST;
    }
    Curl_failf(
        data,
        b"Could not resolve %s: %s\0" as *const u8 as *const i8,
        host_or_proxy,
        (*data).state.async_0.hostname,
    );
    return result;
}
use crate::laertes_rt::*;
