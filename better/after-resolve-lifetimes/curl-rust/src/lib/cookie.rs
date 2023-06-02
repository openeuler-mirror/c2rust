use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    static mut stdin: * mut crate::src::lib::http2::_IO_FILE;
    static mut stdout: * mut crate::src::lib::http2::_IO_FILE;
    fn fclose(__stream: * mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn fopen(_: * const i8, _: * const i8) -> * mut crate::src::lib::http2::_IO_FILE;
    fn sscanf(_: * const i8, _: * const i8, _: ...) -> i32;
    fn fputs(__s: * const i8, __stream: * mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn time(__timer: * mut i64) -> i64;
    fn unlink(__name: * const i8) -> i32;
    
    
    
    fn qsort(
        __base: * mut core::ffi::c_void,
        __nmemb: u64,
        __size: u64,
        __compar: Option<unsafe extern "C"  fn(_: * const core::ffi::c_void,_: * const core::ffi::c_void,) -> i32>,
    );
    fn memcpy(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn memmove(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn strcmp(_: * const i8, _: * const i8) -> i32;
    fn strncmp(
        _: * const i8,
        _: * const i8,
        _: u64,
    ) -> i32;
    fn strchr(_: * const i8, _: i32) -> * mut i8;
    fn strrchr(_: * const i8, _: i32) -> * mut i8;
    fn strtok_r(
        __s: * mut i8,
        __delim: * const i8,
        __save_ptr: * mut * mut i8,
    ) -> * mut i8;
    fn strlen(_: * const i8) -> u64;
    
    
    
    fn psl_is_cookie_domain_acceptable(
        psl: * const crate::src::lib::urlapi::psl_ctx_st,
        hostname: * const i8,
        cookie_domain: * const i8,
    ) -> i32;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::curl_get_line::Curl_get_line;
pub use crate::src::lib::curl_memrchr::Curl_memrchr;
pub use crate::src::lib::hostip::Curl_host_is_ipnum;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::mprintf::curl_mfprintf;
pub use crate::src::lib::parsedate::Curl_getdate_capped;
pub use crate::src::lib::psl::Curl_psl_release;
pub use crate::src::lib::psl::Curl_psl_use;
pub use crate::src::lib::rand::Curl_rand_hex;
pub use crate::src::lib::rename::Curl_rename;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::share::Curl_share_lock;
pub use crate::src::lib::share::Curl_share_unlock;
pub use crate::src::lib::slist::Curl_slist_append_nodup;
pub use crate::src::lib::slist::curl_slist_free_all;
pub use crate::src::lib::strcase::Curl_raw_toupper;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::strcase::Curl_strncasecompare;
pub use crate::src::lib::strcase::curl_strnequal;
pub use crate::src::lib::strerror::curl_easy_strerror;
pub use crate::src::lib::strtoofft::curlx_strtoofft;
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::content_encoding::contenc_writer;
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
pub type CURLSHcode = u32;
pub const CURLSHE_LAST: CURLSHcode = 6;
pub const CURLSHE_NOT_BUILT_IN: CURLSHcode = 5;
pub const CURLSHE_NOMEM: CURLSHcode = 4;
pub const CURLSHE_INVALID: CURLSHcode = 3;
pub const CURLSHE_IN_USE: CURLSHcode = 2;
pub const CURLSHE_BAD_OPTION: CURLSHcode = 1;
pub const CURLSHE_OK: CURLSHcode = 0;
pub type __compar_fn_t<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 core::ffi::c_void>,_: Option<&'a2 core::ffi::c_void>,) -> i32>;
pub type CURLofft = u32;
pub const CURL_OFFT_INVAL: CURLofft = 2;
pub const CURL_OFFT_FLOW: CURLofft = 1;
pub const CURL_OFFT_OK: CURLofft = 0;
pub const STRING_COOKIEJAR: dupstring = 5;
pub type dupstring = u32;
pub const STRING_LAST: dupstring = 80;
pub const STRING_AWS_SIGV4: dupstring = 79;
pub const STRING_COPYPOSTFIELDS: dupstring = 78;
pub const STRING_LASTZEROTERMINATED: dupstring = 77;
pub const STRING_SSL_EC_CURVES: dupstring = 76;
pub const STRING_DNS_LOCAL_IP6: dupstring = 75;
pub const STRING_DNS_LOCAL_IP4: dupstring = 74;
pub const STRING_DNS_INTERFACE: dupstring = 73;
pub const STRING_DNS_SERVERS: dupstring = 72;
pub const STRING_SASL_AUTHZID: dupstring = 71;
pub const STRING_HSTS: dupstring = 70;
pub const STRING_ALTSVC: dupstring = 69;
pub const STRING_DOH: dupstring = 68;
pub const STRING_TARGET: dupstring = 67;
pub const STRING_UNIX_SOCKET_PATH: dupstring = 66;
pub const STRING_BEARER: dupstring = 65;
pub const STRING_TLSAUTH_PASSWORD_PROXY: dupstring = 64;
pub const STRING_TLSAUTH_PASSWORD: dupstring = 63;
pub const STRING_TLSAUTH_USERNAME_PROXY: dupstring = 62;
pub const STRING_TLSAUTH_USERNAME: dupstring = 61;
pub const STRING_MAIL_AUTH: dupstring = 60;
pub const STRING_MAIL_FROM: dupstring = 59;
pub const STRING_SERVICE_NAME: dupstring = 58;
pub const STRING_PROXY_SERVICE_NAME: dupstring = 57;
pub const STRING_SSH_KNOWNHOSTS: dupstring = 56;
pub const STRING_SSH_HOST_PUBLIC_KEY_MD5: dupstring = 55;
pub const STRING_SSH_PUBLIC_KEY: dupstring = 54;
pub const STRING_SSH_PRIVATE_KEY: dupstring = 53;
pub const STRING_RTSP_TRANSPORT: dupstring = 52;
pub const STRING_RTSP_STREAM_URI: dupstring = 51;
pub const STRING_RTSP_SESSION_ID: dupstring = 50;
pub const STRING_NOPROXY: dupstring = 49;
pub const STRING_PROXYPASSWORD: dupstring = 48;
pub const STRING_PROXYUSERNAME: dupstring = 47;
pub const STRING_OPTIONS: dupstring = 46;
pub const STRING_PASSWORD: dupstring = 45;
pub const STRING_USERNAME: dupstring = 44;
pub const STRING_SSL_ENGINE: dupstring = 43;
pub const STRING_SSL_ISSUERCERT_PROXY: dupstring = 42;
pub const STRING_SSL_ISSUERCERT: dupstring = 41;
pub const STRING_SSL_CRLFILE_PROXY: dupstring = 40;
pub const STRING_SSL_CRLFILE: dupstring = 39;
pub const STRING_USERAGENT: dupstring = 38;
pub const STRING_SSL_RANDOM_FILE: dupstring = 37;
pub const STRING_SSL_EGDSOCKET: dupstring = 36;
pub const STRING_SSL_CIPHER13_LIST_PROXY: dupstring = 35;
pub const STRING_SSL_CIPHER13_LIST: dupstring = 34;
pub const STRING_SSL_CIPHER_LIST_PROXY: dupstring = 33;
pub const STRING_SSL_CIPHER_LIST: dupstring = 32;
pub const STRING_SSL_PINNEDPUBLICKEY_PROXY: dupstring = 31;
pub const STRING_SSL_PINNEDPUBLICKEY: dupstring = 30;
pub const STRING_SSL_CAFILE_PROXY: dupstring = 29;
pub const STRING_SSL_CAFILE: dupstring = 28;
pub const STRING_SSL_CAPATH_PROXY: dupstring = 27;
pub const STRING_SSL_CAPATH: dupstring = 26;
pub const STRING_SET_URL: dupstring = 25;
pub const STRING_SET_REFERER: dupstring = 24;
pub const STRING_SET_RANGE: dupstring = 23;
pub const STRING_PRE_PROXY: dupstring = 22;
pub const STRING_PROXY: dupstring = 21;
pub const STRING_NETRC_FILE: dupstring = 20;
pub const STRING_KRB_LEVEL: dupstring = 19;
pub const STRING_KEY_TYPE_PROXY: dupstring = 18;
pub const STRING_KEY_TYPE: dupstring = 17;
pub const STRING_KEY_PASSWD_PROXY: dupstring = 16;
pub const STRING_KEY_PASSWD: dupstring = 15;
pub const STRING_KEY_PROXY: dupstring = 14;
pub const STRING_KEY: dupstring = 13;
pub const STRING_FTPPORT: dupstring = 12;
pub const STRING_FTP_ALTERNATIVE_TO_USER: dupstring = 11;
pub const STRING_FTP_ACCOUNT: dupstring = 10;
pub const STRING_ENCODING: dupstring = 9;
pub const STRING_DEVICE: dupstring = 8;
pub const STRING_DEFAULT_PROTOCOL: dupstring = 7;
pub const STRING_CUSTOMREQUEST: dupstring = 6;
pub const STRING_COOKIE: dupstring = 4;
pub const STRING_CERT_TYPE_PROXY: dupstring = 3;
pub const STRING_CERT_TYPE: dupstring = 2;
pub const STRING_CERT_PROXY: dupstring = 1;
pub const STRING_CERT: dupstring = 0;
unsafe extern "C" fn freecookie(mut co: * mut crate::src::lib::http2::Cookie) {
    Curl_cfree.expect("non-null function pointer")((*co).expirestr as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*co).domain as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*co).path as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*co).spath as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*co).name as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*co).value as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*co).maxage as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")((*co).version as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(co as *mut libc::c_void);
}
unsafe extern "C" fn tailmatch(
    mut cooke_domain: * const i8,
    mut hostname: * const i8,
) -> bool {
    let mut cookie_domain_len: u64 = strlen(cooke_domain);
    let mut hostname_len: u64 = strlen(hostname);
    if hostname_len < cookie_domain_len {
        return 0 as i32 != 0;
    }
    if Curl_strcasecompare(
        cooke_domain,
        hostname.offset(hostname_len as isize).offset(-(cookie_domain_len as isize)),
    ) == 0
    {
        return 0 as i32 != 0;
    }
    if hostname_len == cookie_domain_len {
        return 1 as i32 != 0;
    }
    if '.' as i32
        == *hostname
            .offset(hostname_len as isize)
            .offset(-(cookie_domain_len as isize))
            .offset(-(1 as i32 as isize)) as i32
    {
        return 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
unsafe extern "C" fn pathmatch(
    mut cookie_path: * const i8,
    mut request_uri: * const i8,
) -> bool {
    let mut cookie_path_len: u64 = 0;
    let mut uri_path_len: u64 = 0;
    let mut uri_path: * mut i8 = 0 as *mut i8;
    let mut pos: * mut i8 = 0 as *mut i8;
    let mut ret: bool = 0 as i32 != 0;
    cookie_path_len = strlen(cookie_path);
    if 1 as i32 as u64 == cookie_path_len {
        return 1 as i32 != 0;
    }
    uri_path = Curl_cstrdup.expect("non-null function pointer")(request_uri);
    if uri_path.is_null() {
        return 0 as i32 != 0;
    }
    pos = strchr(uri_path, '?' as i32);
    if !pos.is_null() {
        *pos = 0 as i32 as i8;
    }
    if 0 as i32 as u64 == strlen(uri_path)
        || *uri_path.offset(0 as i32 as isize) as i32 != '/' as i32
    {
        strstore(Some(&mut uri_path), b"/\0" as *const u8 as *const i8);
        if uri_path.is_null() {
            return 0 as i32 != 0;
        }
    }
    uri_path_len = strlen(uri_path);
    if uri_path_len < cookie_path_len {
        ret = 0 as i32 != 0;
    } else if strncmp(cookie_path, uri_path, cookie_path_len) != 0 {
        ret = 0 as i32 != 0;
    } else if cookie_path_len == uri_path_len {
        ret = 1 as i32 != 0;
    } else if *uri_path.offset(cookie_path_len as isize) as i32 == '/' as i32 {
        ret = 1 as i32 != 0;
    } else {
        ret = 0 as i32 != 0;
    }
    Curl_cfree.expect("non-null function pointer")(uri_path as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn get_top_domain<'a1>(
    domain: * const i8,
    mut outlen: Option<&'a1 mut u64>,
) -> * const i8 {
    let mut len: u64 = 0 as i32 as size_t;
    let mut first: * const i8 = 0 as *const i8;
    let mut last: * const i8 = 0 as *const i8;
    if !domain.is_null() {
        len = strlen(domain);
        last = Curl_memrchr(domain as *const libc::c_void, '.' as i32, len)
            as *const i8;
        if !last.is_null() {
            first = Curl_memrchr(
                domain as *const libc::c_void,
                '.' as i32,
                last.offset_from(domain) as i64 as size_t,
            ) as *const i8;
            if !first.is_null() {
                first = first.offset(1);
                len = (len as u64)
                    .wrapping_sub(
                        first.offset_from(domain) as i64 as u64,
                    ) as size_t as size_t;
            }
        }
    }
    if !borrow(& outlen).is_none() {
        *(borrow_mut(&mut outlen)).unwrap() = len;
    }
    return if !first.is_null() { first } else { domain };
}
unsafe extern "C" fn cookie_hash_domain(
    mut domain: * const i8,
    len: u64,
) -> u64 {
    let mut end: * const i8 = domain.offset(len as isize);
    let mut h: u64 = 5381 as i32 as size_t;
    while domain < end {
        h = (h as u64).wrapping_add(h << 5 as i32) as size_t as size_t;
        let mut fresh0 = domain;
        domain = domain.offset(1);
        h ^= Curl_raw_toupper(*fresh0) as u64;
    }
    return h.wrapping_rem(256 as i32 as u64);
}
unsafe extern "C" fn cookiehash(domain: * const i8) -> u64 {
    let mut top: * const i8 = 0 as *const i8;
    let mut len: u64 = 0;
    if domain.is_null() || Curl_host_is_ipnum(domain) as i32 != 0 {
        return 0 as i32 as size_t;
    }
    top = get_top_domain(domain, Some(&mut len));
    return cookie_hash_domain(top, len);
}
unsafe extern "C" fn sanitize_cookie_path(
    mut cookie_path: * const i8,
) -> * mut i8 {
    let mut len: u64 = 0;
    let mut new_path: * mut i8 = Curl_cstrdup
        .expect("non-null function pointer")(cookie_path);
    if new_path.is_null() {
        return 0 as *mut i8;
    }
    len = strlen(new_path);
    if *new_path.offset(0 as i32 as isize) as i32 == '"' as i32 {
        memmove(
            new_path as *mut libc::c_void,
            new_path.offset(1 as i32 as isize) as *const libc::c_void,
            len,
        );
        len = len.wrapping_sub(1);
    }
    if len != 0
        && *new_path.offset(len.wrapping_sub(1 as i32 as u64) as isize)
            as i32 == '"' as i32
    {
        *new_path
            .offset(
                len.wrapping_sub(1 as i32 as u64) as isize,
            ) = 0 as i32 as i8;
        len = len.wrapping_sub(1);
    }
    if *new_path.offset(0 as i32 as isize) as i32 != '/' as i32 {
        strstore(Some(&mut new_path), b"/\0" as *const u8 as *const i8);
        return new_path;
    }
    if len != 0
        && *new_path.offset(len.wrapping_sub(1 as i32 as u64) as isize)
            as i32 == '/' as i32
    {
        *new_path
            .offset(
                len.wrapping_sub(1 as i32 as u64) as isize,
            ) = 0 as i32 as i8;
    }
    return new_path;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_cookie_loadfiles(mut data: * mut crate::src::lib::http2::Curl_easy) {
    let mut list: * mut crate::src::lib::http2::curl_slist = (*data).state.cookielist;
    if !list.is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
        while !list.is_null() {
            let mut newcookies: * mut crate::src::lib::http2::CookieInfo = Curl_cookie_init(
                data,
                (*list).data,
                (*data).cookies,
                ((*data).set).cookiesession() != 0,
            );
            if newcookies.is_null() {
                Curl_infof(
                    data,
                    b"ignoring failed cookie_init for %s\0" as *const u8
                        as *const i8,
                    (*list).data,
                );
            } else {
                let mut fresh1 = &mut ((*data).cookies);
                *fresh1 = newcookies;
            }
            list = (*list).next;
        }
        curl_slist_free_all((*data).state.cookielist);
        let mut fresh2 = &mut ((*data).state.cookielist);
        *fresh2 = 0 as *mut curl_slist;
        Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
    }
}
unsafe extern "C" fn strstore<'a1>(
    mut str: Option<&'a1 mut * mut i8>,
    mut newstr: * const i8,
) {
    Curl_cfree.expect("non-null function pointer")(*(borrow_mut(&mut str)).unwrap() as *mut libc::c_void);
    *(borrow_mut(&mut str)).unwrap() = Curl_cstrdup.expect("non-null function pointer")(newstr);
}
unsafe extern "C" fn remove_expired(mut cookies: * mut crate::src::lib::http2::CookieInfo) {
    let mut co: * mut crate::src::lib::http2::Cookie = 0 as *mut Cookie;
    let mut nx: * mut crate::src::lib::http2::Cookie = 0 as *mut Cookie;
    let mut now: i64 = time(0 as *mut time_t);
    let mut i: u32 = 0;
    if now < (*cookies).next_expiration
        && (*cookies).next_expiration != 0x7fffffffffffffff as i64
    {
        return
    } else {
        (*cookies).next_expiration = 0x7fffffffffffffff as i64;
    }
    i = 0 as i32 as u32;
    while i < 256 as i32 as u32 {
        let mut pv: * mut crate::src::lib::http2::Cookie = 0 as *mut Cookie;
        co = (*cookies).cookies[i as usize];
        while !co.is_null() {
            nx = (*co).next;
            if (*co).expires != 0 && (*co).expires < now {
                if pv.is_null() {
                    let mut fresh3 = &mut ((*cookies).cookies[i as usize]);
                    *fresh3 = (*co).next;
                } else {
                    let mut fresh4 = &mut ((*pv).next);
                    *fresh4 = (*co).next;
                }
                let mut fresh5 = &mut ((*cookies).numcookies);
                *fresh5 -= 1;
                freecookie(co);
            } else {
                if (*co).expires != 0 && (*co).expires < (*cookies).next_expiration {
                    (*cookies).next_expiration = (*co).expires;
                }
                pv = co;
            }
            co = nx;
        }
        i = i.wrapping_add(1);
    }
}
unsafe extern "C" fn bad_domain(mut domain: * const i8) -> bool {
    return (strchr(domain, '.' as i32)).is_null()
        && Curl_strcasecompare(
            domain,
            b"localhost\0" as *const u8 as *const i8,
        ) == 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_cookie_add(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut c: * mut crate::src::lib::http2::CookieInfo,
    mut httpheader: bool,
    mut noexpire: bool,
    mut lineptr: * mut i8,
    mut domain: * const i8,
    mut path: * const i8,
    mut secure: bool,
) -> * mut crate::src::lib::http2::Cookie {
    let mut clist: * mut crate::src::lib::http2::Cookie = 0 as *mut Cookie;
    let mut co: * mut crate::src::lib::http2::Cookie = 0 as *mut Cookie;
    let mut lastc: * mut crate::src::lib::http2::Cookie = 0 as *mut Cookie;
    let mut now: i64 = time(0 as *mut time_t);
    let mut replace_old: bool = 0 as i32 != 0;
    let mut badcookie: bool = 0 as i32 != 0;
    let mut myhash: u64 = 0;
    co = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(1 as i32 as size_t, ::std::mem::size_of::<Cookie>() as u64)
        as *mut Cookie;
    if co.is_null() {
        return 0 as *mut Cookie;
    }
    if httpheader {
        let mut name: [i8; 4096] = [0; 4096];
        let mut what: [i8; 4096] = [0; 4096];
        let mut ptr: * const i8 = 0 as *const i8;
        let mut semiptr: * const i8 = 0 as *const i8;
        let mut linelength: u64 = strlen(lineptr);
        if linelength > 5000 as i32 as u64 {
            Curl_cfree.expect("non-null function pointer")(co as *mut libc::c_void);
            return 0 as *mut Cookie;
        }
        semiptr = strchr(lineptr, ';' as i32);
        while *lineptr as i32 != 0
            && (*lineptr as u8 as i32 == ' ' as i32
                || *lineptr as u8 as i32 == '\t' as i32)
        {
            lineptr = lineptr.offset(1);
        }
        ptr = lineptr;
        loop {
            what[0 as i32 as usize] = 0 as i32 as i8;
            name[0 as i32 as usize] = what[0 as i32 as usize];
            if 1 as i32
                <= sscanf(
                    ptr,
                    b"%4095[^;\r\n=] =%4095[^;\r\n]\0" as *const u8
                        as *const i8,
                    name.as_mut_ptr(),
                    what.as_mut_ptr(),
                )
            {
                let mut whatptr: * const i8 = 0 as *const i8;
                let mut done: bool = 0 as i32 != 0;
                let mut sep: bool = false;
                let mut len: u64 = strlen(what.as_mut_ptr());
                let mut nlen: u64 = strlen(name.as_mut_ptr());
                let mut endofn: * const i8 = &*ptr.offset(nlen as isize)
                    as *const i8;
                if nlen >= (4096 as i32 - 1 as i32) as u64
                    || len >= (4096 as i32 - 1 as i32) as u64
                    || nlen.wrapping_add(len) > 4096 as i32 as u64
                {
                    freecookie(co);
                    Curl_infof(
                        data,
                        b"oversized cookie dropped, name/val %zu + %zu bytes\0"
                            as *const u8 as *const i8,
                        nlen,
                        len,
                    );
                    return 0 as *mut Cookie;
                }
                sep = if *endofn as i32 == '=' as i32 {
                    1 as i32
                } else {
                    0 as i32
                } != 0;
                if nlen != 0 {
                    endofn = endofn.offset(-1);
                    if *endofn as u8 as i32 == ' ' as i32
                        || *endofn as u8 as i32 == '\t' as i32
                    {
                        while *endofn as i32 != 0
                            && (*endofn as u8 as i32 == ' ' as i32
                                || *endofn as u8 as i32 == '\t' as i32)
                            && nlen != 0
                        {
                            endofn = endofn.offset(-1);
                            nlen = nlen.wrapping_sub(1);
                        }
                        name[nlen as usize] = 0 as i32 as i8;
                    }
                }
                while len != 0
                    && (what[len.wrapping_sub(1 as i32 as u64)
                        as usize] as u8 as i32 == ' ' as i32
                        || what[len.wrapping_sub(1 as i32 as u64)
                            as usize] as u8 as i32 == '\t' as i32)
                {
                    what[len.wrapping_sub(1 as i32 as u64)
                        as usize] = 0 as i32 as i8;
                    len = len.wrapping_sub(1);
                }
                whatptr = what.as_mut_ptr();
                while *whatptr as i32 != 0
                    && (*whatptr as u8 as i32 == ' ' as i32
                        || *whatptr as u8 as i32 == '\t' as i32)
                {
                    whatptr = whatptr.offset(1);
                }
                if nlen > 3 as i32 as u64
                    && name[0 as i32 as usize] as i32 == '_' as i32
                    && name[1 as i32 as usize] as i32 == '_' as i32
                {
                    if strncmp(
                        b"__Secure-\0" as *const u8 as *const i8,
                        name.as_mut_ptr(),
                        9 as i32 as u64,
                    ) == 0
                    {
                        let mut fresh6 = &mut ((*co).prefix);
                        *fresh6 = (*fresh6 as i32
                            | (1 as i32) << 0 as i32) as u8;
                    } else if strncmp(
                            b"__Host-\0" as *const u8 as *const i8,
                            name.as_mut_ptr(),
                            7 as i32 as u64,
                        ) == 0
                        {
                        let mut fresh7 = &mut ((*co).prefix);
                        *fresh7 = (*fresh7 as i32
                            | (1 as i32) << 1 as i32) as u8;
                    }
                }
                if ((*co).name).is_null() {
                    if !sep {
                        badcookie = 1 as i32 != 0;
                        break;
                    } else {
                        let mut fresh8 = &mut ((*co).name);
                        *fresh8 = Curl_cstrdup
                            .expect("non-null function pointer")(name.as_mut_ptr());
                        let mut fresh9 = &mut ((*co).value);
                        *fresh9 = Curl_cstrdup
                            .expect("non-null function pointer")(whatptr);
                        done = 1 as i32 != 0;
                        if ((*co).name).is_null() || ((*co).value).is_null() {
                            badcookie = 1 as i32 != 0;
                            break;
                        }
                    }
                } else if len == 0 {
                    done = 1 as i32 != 0;
                    if Curl_strcasecompare(
                        b"secure\0" as *const u8 as *const i8,
                        name.as_mut_ptr(),
                    ) != 0
                    {
                        if secure as i32 != 0 || !(*c).running {
                            (*co).secure = 1 as i32 != 0;
                        } else {
                            badcookie = 1 as i32 != 0;
                            break;
                        }
                    } else if Curl_strcasecompare(
                            b"httponly\0" as *const u8 as *const i8,
                            name.as_mut_ptr(),
                        ) != 0
                        {
                        (*co).httponly = 1 as i32 != 0;
                    } else if sep {
                        done = 0 as i32 != 0;
                    }
                }
                if !done {
                    if Curl_strcasecompare(
                        b"path\0" as *const u8 as *const i8,
                        name.as_mut_ptr(),
                    ) != 0
                    {
                        strstore(Some(&mut (*co).path), whatptr);
                        if ((*co).path).is_null() {
                            badcookie = 1 as i32 != 0;
                            break;
                        } else {
                            Curl_cfree
                                .expect(
                                    "non-null function pointer",
                                )((*co).spath as *mut libc::c_void);
                            let mut fresh10 = &mut ((*co).spath);
                            *fresh10 = sanitize_cookie_path((*co).path);
                            if ((*co).spath).is_null() {
                                badcookie = 1 as i32 != 0;
                                break;
                            }
                        }
                    } else if Curl_strcasecompare(
                            b"domain\0" as *const u8 as *const i8,
                            name.as_mut_ptr(),
                        ) != 0
                        {
                        let mut is_ip: bool = false;
                        if '.' as i32
                            == *whatptr.offset(0 as i32 as isize) as i32
                        {
                            whatptr = whatptr.offset(1);
                        }
                        is_ip = Curl_host_is_ipnum(
                            if !domain.is_null() { domain } else { whatptr },
                        );
                        if domain.is_null()
                            || is_ip as i32 != 0 && strcmp(whatptr, domain) == 0
                            || !is_ip && tailmatch(whatptr, domain) as i32 != 0
                        {
                            strstore(Some(&mut (*co).domain), whatptr);
                            if ((*co).domain).is_null() {
                                badcookie = 1 as i32 != 0;
                                break;
                            } else if !is_ip {
                                (*co).tailmatch = 1 as i32 != 0;
                            }
                        } else {
                            badcookie = 1 as i32 != 0;
                            Curl_infof(
                                data,
                                b"skipped cookie with bad tailmatch domain: %s\0"
                                    as *const u8 as *const i8,
                                whatptr,
                            );
                        }
                    } else if Curl_strcasecompare(
                            b"version\0" as *const u8 as *const i8,
                            name.as_mut_ptr(),
                        ) != 0
                        {
                        strstore(Some(&mut (*co).version), whatptr);
                        if ((*co).version).is_null() {
                            badcookie = 1 as i32 != 0;
                            break;
                        }
                    } else if Curl_strcasecompare(
                            b"max-age\0" as *const u8 as *const i8,
                            name.as_mut_ptr(),
                        ) != 0
                        {
                        strstore(Some(&mut (*co).maxage), whatptr);
                        if ((*co).maxage).is_null() {
                            badcookie = 1 as i32 != 0;
                            break;
                        }
                    } else if Curl_strcasecompare(
                            b"expires\0" as *const u8 as *const i8,
                            name.as_mut_ptr(),
                        ) != 0
                        {
                        strstore(Some(&mut (*co).expirestr), whatptr);
                        if ((*co).expirestr).is_null() {
                            badcookie = 1 as i32 != 0;
                            break;
                        }
                    }
                }
            }
            if semiptr.is_null() || *semiptr == 0 {
                semiptr = 0 as *const i8;
            } else {
                ptr = semiptr.offset(1 as i32 as isize);
                while *ptr as i32 != 0
                    && (*ptr as u8 as i32 == ' ' as i32
                        || *ptr as u8 as i32 == '\t' as i32)
                {
                    ptr = ptr.offset(1);
                }
                semiptr = strchr(ptr, ';' as i32);
                if semiptr.is_null() && *ptr as i32 != 0 {
                    semiptr = strchr(ptr, '\u{0}' as i32);
                }
            }
            if semiptr.is_null() {
                break;
            }
        }
        if !((*co).maxage).is_null() {
            let mut offt: u32 = CURL_OFFT_OK;
            offt = curlx_strtoofft(
                if *(*co).maxage as i32 == '"' as i32 {
                    &mut *((*co).maxage).offset(1 as i32 as isize)
                } else {
                    &mut *((*co).maxage).offset(0 as i32 as isize)
                },
                Option::<&'_ mut * mut i8>::None,
                10 as i32,
                Some(&mut (*co).expires),
            );
            if offt as u32 == CURL_OFFT_FLOW as i32 as u32 {
                (*co).expires = 0x7fffffffffffffff as i64;
            } else if offt as u64 == 0 {
                if (*co).expires == 0 {
                    (*co).expires = 1 as i32 as curl_off_t;
                } else if 0x7fffffffffffffff as i64 - now < (*co).expires {
                    (*co).expires = 0x7fffffffffffffff as i64;
                } else {
                    let mut fresh11 = &mut ((*co).expires);
                    *fresh11 += now;
                }
            }
        } else if !((*co).expirestr).is_null() {
            (*co).expires = Curl_getdate_capped((*co).expirestr);
            if (*co).expires == 0 as i32 as i64 {
                (*co).expires = 1 as i32 as curl_off_t;
            } else if (*co).expires < 0 as i32 as i64 {
                (*co).expires = 0 as i32 as curl_off_t;
            }
        }
        if !badcookie && ((*co).domain).is_null() {
            if !domain.is_null() {
                let mut fresh12 = &mut ((*co).domain);
                *fresh12 = Curl_cstrdup.expect("non-null function pointer")(domain);
                if ((*co).domain).is_null() {
                    badcookie = 1 as i32 != 0;
                }
            }
        }
        if !badcookie && ((*co).path).is_null() && !path.is_null() {
            let mut queryp: * mut i8 = strchr(path, '?' as i32);
            let mut endslash: * mut i8 = 0 as *mut i8;
            if queryp.is_null() {
                endslash = strrchr(path, '/' as i32);
            } else {
                endslash = Curl_memrchr(
                    path as *const libc::c_void,
                    '/' as i32,
                    queryp.offset_from(path) as i64 as size_t,
                ) as *mut i8;
            }
            if !endslash.is_null() {
                let mut pathlen: u64 = (endslash.offset_from(path) as i64
                    + 1 as i32 as i64) as size_t;
                let mut fresh13 = &mut ((*co).path);
                *fresh13 = Curl_cmalloc
                    .expect(
                        "non-null function pointer",
                    )(pathlen.wrapping_add(1 as i32 as u64))
                    as *mut i8;
                if !((*co).path).is_null() {
                    memcpy(
                        (*co).path as *mut libc::c_void,
                        path as *const libc::c_void,
                        pathlen,
                    );
                    *((*co).path)
                        .offset(pathlen as isize) = 0 as i32 as i8;
                    let mut fresh14 = &mut ((*co).spath);
                    *fresh14 = sanitize_cookie_path((*co).path);
                    if ((*co).spath).is_null() {
                        badcookie = 1 as i32 != 0;
                    }
                } else {
                    badcookie = 1 as i32 != 0;
                }
            }
        }
        if badcookie as i32 != 0 || ((*co).name).is_null() {
            freecookie(co);
            return 0 as *mut Cookie;
        }
    } else {
        let mut ptr_0: * mut i8 = 0 as *mut i8;
        let mut firstptr: * mut i8 = 0 as *mut i8;
        let mut tok_buf: * mut i8 = 0 as *mut i8;
        let mut fields: i32 = 0;
        if strncmp(
            lineptr,
            b"#HttpOnly_\0" as *const u8 as *const i8,
            10 as i32 as u64,
        ) == 0 as i32
        {
            lineptr = lineptr.offset(10 as i32 as isize);
            (*co).httponly = 1 as i32 != 0;
        }
        if *lineptr.offset(0 as i32 as isize) as i32 == '#' as i32 {
            Curl_cfree.expect("non-null function pointer")(co as *mut libc::c_void);
            return 0 as *mut Cookie;
        }
        ptr_0 = strchr(lineptr, '\r' as i32);
        if !ptr_0.is_null() {
            *ptr_0 = 0 as i32 as i8;
        }
        ptr_0 = strchr(lineptr, '\n' as i32);
        if !ptr_0.is_null() {
            *ptr_0 = 0 as i32 as i8;
        }
        firstptr = strtok_r(
            lineptr,
            b"\t\0" as *const u8 as *const i8,
            &mut tok_buf,
        );
        ptr_0 = firstptr;
        fields = 0 as i32;
        while !ptr_0.is_null() && !badcookie {
            let mut current_block_187: u64;
            match fields {
                0 => {
                    if *ptr_0.offset(0 as i32 as isize) as i32
                        == '.' as i32
                    {
                        ptr_0 = ptr_0.offset(1);
                    }
                    let mut fresh15 = &mut ((*co).domain);
                    *fresh15 = Curl_cstrdup.expect("non-null function pointer")(ptr_0);
                    if ((*co).domain).is_null() {
                        badcookie = 1 as i32 != 0;
                    }
                    current_block_187 = 4402115142504265260;
                }
                1 => {
                    (*co)
                        .tailmatch = if Curl_strcasecompare(
                        ptr_0,
                        b"TRUE\0" as *const u8 as *const i8,
                    ) != 0
                    {
                        1 as i32
                    } else {
                        0 as i32
                    } != 0;
                    current_block_187 = 4402115142504265260;
                }
                2 => {
                    if strcmp(b"TRUE\0" as *const u8 as *const i8, ptr_0) != 0
                        && strcmp(b"FALSE\0" as *const u8 as *const i8, ptr_0)
                            != 0
                    {
                        let mut fresh16 = &mut ((*co).path);
                        *fresh16 = Curl_cstrdup
                            .expect("non-null function pointer")(ptr_0);
                        if ((*co).path).is_null() {
                            badcookie = 1 as i32 != 0;
                        } else {
                            let mut fresh17 = &mut ((*co).spath);
                            *fresh17 = sanitize_cookie_path((*co).path);
                            if ((*co).spath).is_null() {
                                badcookie = 1 as i32 != 0;
                            }
                        }
                        current_block_187 = 4402115142504265260;
                    } else {
                        let mut fresh18 = &mut ((*co).path);
                        *fresh18 = Curl_cstrdup
                            .expect(
                                "non-null function pointer",
                            )(b"/\0" as *const u8 as *const i8);
                        if ((*co).path).is_null() {
                            badcookie = 1 as i32 != 0;
                        }
                        let mut fresh19 = &mut ((*co).spath);
                        *fresh19 = Curl_cstrdup
                            .expect(
                                "non-null function pointer",
                            )(b"/\0" as *const u8 as *const i8);
                        if ((*co).spath).is_null() {
                            badcookie = 1 as i32 != 0;
                        }
                        fields += 1;
                        current_block_187 = 15249084414975911002;
                    }
                }
                3 => {
                    current_block_187 = 15249084414975911002;
                }
                4 => {
                    if curlx_strtoofft(
                        ptr_0,
                        Option::<&'_ mut * mut i8>::None,
                        10 as i32,
                        Some(&mut (*co).expires),
                    ) as u64 != 0
                    {
                        badcookie = 1 as i32 != 0;
                    }
                    current_block_187 = 4402115142504265260;
                }
                5 => {
                    let mut fresh20 = &mut ((*co).name);
                    *fresh20 = Curl_cstrdup.expect("non-null function pointer")(ptr_0);
                    if ((*co).name).is_null() {
                        badcookie = 1 as i32 != 0;
                    } else if Curl_strncasecompare(
                            b"__Secure-\0" as *const u8 as *const i8,
                            (*co).name,
                            9 as i32 as size_t,
                        ) != 0
                        {
                        let mut fresh21 = &mut ((*co).prefix);
                        *fresh21 = (*fresh21 as i32
                            | (1 as i32) << 0 as i32) as u8;
                    } else if Curl_strncasecompare(
                            b"__Host-\0" as *const u8 as *const i8,
                            (*co).name,
                            7 as i32 as size_t,
                        ) != 0
                        {
                        let mut fresh22 = &mut ((*co).prefix);
                        *fresh22 = (*fresh22 as i32
                            | (1 as i32) << 1 as i32) as u8;
                    }
                    current_block_187 = 4402115142504265260;
                }
                6 => {
                    let mut fresh23 = &mut ((*co).value);
                    *fresh23 = Curl_cstrdup.expect("non-null function pointer")(ptr_0);
                    if ((*co).value).is_null() {
                        badcookie = 1 as i32 != 0;
                    }
                    current_block_187 = 4402115142504265260;
                }
                _ => {
                    current_block_187 = 4402115142504265260;
                }
            }
            match current_block_187 {
                15249084414975911002 => {
                    (*co).secure = 0 as i32 != 0;
                    if Curl_strcasecompare(
                        ptr_0,
                        b"TRUE\0" as *const u8 as *const i8,
                    ) != 0
                    {
                        if secure as i32 != 0 || (*c).running as i32 != 0
                        {
                            (*co).secure = 1 as i32 != 0;
                        } else {
                            badcookie = 1 as i32 != 0;
                        }
                    }
                }
                _ => {}
            }
            ptr_0 = strtok_r(
                0 as *mut i8,
                b"\t\0" as *const u8 as *const i8,
                &mut tok_buf,
            );
            fields += 1;
        }
        if 6 as i32 == fields {
            let mut fresh24 = &mut ((*co).value);
            *fresh24 = Curl_cstrdup
                .expect(
                    "non-null function pointer",
                )(b"\0" as *const u8 as *const i8);
            if ((*co).value).is_null() {
                badcookie = 1 as i32 != 0;
            } else {
                fields += 1;
            }
        }
        if !badcookie && 7 as i32 != fields {
            badcookie = 1 as i32 != 0;
        }
        if badcookie {
            freecookie(co);
            return 0 as *mut Cookie;
        }
    }
    if (*co).prefix as i32 & (1 as i32) << 0 as i32 != 0 {
        if !(*co).secure {
            freecookie(co);
            return 0 as *mut Cookie;
        }
    }
    if (*co).prefix as i32 & (1 as i32) << 1 as i32 != 0 {
        if (*co).secure as i32 != 0 && !((*co).path).is_null()
            && strcmp((*co).path, b"/\0" as *const u8 as *const i8)
                == 0 as i32 && !(*co).tailmatch
        {} else {
            freecookie(co);
            return 0 as *mut Cookie;
        }
    }
    if !(*c).running && (*c).newsession as i32 != 0 && (*co).expires == 0 {
        freecookie(co);
        return 0 as *mut Cookie;
    }
    (*co).livecookie = (*c).running;
    let mut fresh25 = &mut ((*c).lastct);
    *fresh25 += 1;
    (*co).creationtime = *fresh25;
    if !noexpire {
        remove_expired(c);
    }
    if !data.is_null()
        && (!domain.is_null() && !((*co).domain).is_null()
            && !Curl_host_is_ipnum((*co).domain))
    {
        let mut psl: * const crate::src::lib::urlapi::psl_ctx_st = Curl_psl_use(data);
        let mut acceptable: i32 = 0;
        if !psl.is_null() {
            acceptable = psl_is_cookie_domain_acceptable(psl, domain, (*co).domain);
            Curl_psl_release(data);
        } else {
            acceptable = !bad_domain(domain) as i32;
        }
        if acceptable == 0 {
            Curl_infof(
                data,
                b"cookie '%s' dropped, domain '%s' must not set cookies for '%s'\0"
                    as *const u8 as *const i8,
                (*co).name,
                domain,
                (*co).domain,
            );
            freecookie(co);
            return 0 as *mut Cookie;
        }
    }
    myhash = cookiehash((*co).domain);
    clist = (*c).cookies[myhash as usize];
    replace_old = 0 as i32 != 0;
    while !clist.is_null() {
        if Curl_strcasecompare((*clist).name, (*co).name) != 0 {
            if !((*clist).domain).is_null() && !((*co).domain).is_null() {
                if Curl_strcasecompare((*clist).domain, (*co).domain) != 0
                    && (*clist).tailmatch as i32
                        == (*co).tailmatch as i32
                {
                    replace_old = 1 as i32 != 0;
                }
            } else if ((*clist).domain).is_null() && ((*co).domain).is_null() {
                replace_old = 1 as i32 != 0;
            }
            if replace_old {
                if !((*clist).spath).is_null() && !((*co).spath).is_null() {
                    if (*clist).secure as i32 != 0 && !(*co).secure && !secure {
                        let mut cllen: u64 = 0;
                        let mut sep_0: * const i8 = 0 as *const i8;
                        sep_0 = strchr(
                            ((*clist).spath).offset(1 as i32 as isize),
                            '/' as i32,
                        );
                        if !sep_0.is_null() {
                            cllen = sep_0.offset_from((*clist).spath) as i64
                                as size_t;
                        } else {
                            cllen = strlen((*clist).spath);
                        }
                        if Curl_strncasecompare((*clist).spath, (*co).spath, cllen) != 0
                        {
                            freecookie(co);
                            return 0 as *mut Cookie;
                        }
                    } else if Curl_strcasecompare((*clist).spath, (*co).spath) != 0 {
                        replace_old = 1 as i32 != 0;
                    } else {
                        replace_old = 0 as i32 != 0;
                    }
                } else if ((*clist).spath).is_null() && ((*co).spath).is_null() {
                    replace_old = 1 as i32 != 0;
                } else {
                    replace_old = 0 as i32 != 0;
                }
            }
            if replace_old as i32 != 0 && !(*co).livecookie
                && (*clist).livecookie as i32 != 0
            {
                freecookie(co);
                return 0 as *mut Cookie;
            }
            if replace_old {
                let mut fresh26 = &mut ((*co).next);
                *fresh26 = (*clist).next;
                (*co).creationtime = (*clist).creationtime;
                Curl_cfree
                    .expect(
                        "non-null function pointer",
                    )((*clist).name as *mut libc::c_void);
                Curl_cfree
                    .expect(
                        "non-null function pointer",
                    )((*clist).value as *mut libc::c_void);
                Curl_cfree
                    .expect(
                        "non-null function pointer",
                    )((*clist).domain as *mut libc::c_void);
                Curl_cfree
                    .expect(
                        "non-null function pointer",
                    )((*clist).path as *mut libc::c_void);
                Curl_cfree
                    .expect(
                        "non-null function pointer",
                    )((*clist).spath as *mut libc::c_void);
                Curl_cfree
                    .expect(
                        "non-null function pointer",
                    )((*clist).expirestr as *mut libc::c_void);
                Curl_cfree
                    .expect(
                        "non-null function pointer",
                    )((*clist).version as *mut libc::c_void);
                Curl_cfree
                    .expect(
                        "non-null function pointer",
                    )((*clist).maxage as *mut libc::c_void);
                *clist = *co;
                Curl_cfree.expect("non-null function pointer")(co as *mut libc::c_void);
                co = clist;
                loop {
                    lastc = clist;
                    clist = (*clist).next;
                    if clist.is_null() {
                        break;
                    }
                }
                break;
            }
        }
        lastc = clist;
        clist = (*clist).next;
    }
    if (*c).running {
        Curl_infof(
            data,
            b"%s cookie %s=\"%s\" for domain %s, path %s, expire %ld\0" as *const u8
                as *const i8,
            if replace_old as i32 != 0 {
                b"Replaced\0" as *const u8 as *const i8
            } else {
                b"Added\0" as *const u8 as *const i8
            },
            (*co).name,
            (*co).value,
            (*co).domain,
            (*co).path,
            (*co).expires,
        );
    }
    if !replace_old {
        if !lastc.is_null() {
            let mut fresh27 = &mut ((*lastc).next);
            *fresh27 = co;
        } else {
            let mut fresh28 = &mut ((*c).cookies[myhash as usize]);
            *fresh28 = co;
        }
        let mut fresh29 = &mut ((*c).numcookies);
        *fresh29 += 1;
    }
    if (*co).expires != 0 && (*co).expires < (*c).next_expiration {
        (*c).next_expiration = (*co).expires;
    }
    return co;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_cookie_init(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut file: * const i8,
    mut inc: * mut crate::src::lib::http2::CookieInfo,
    mut newsession: bool,
) -> * mut crate::src::lib::http2::CookieInfo {
    let mut current_block: u64;
    let mut c: * mut crate::src::lib::http2::CookieInfo = 0 as *mut CookieInfo;
    let mut fp: * mut crate::src::lib::http2::_IO_FILE = 0 as *mut FILE;
    let mut fromfile: bool = 1 as i32 != 0;
    let mut line: * mut i8 = 0 as *mut i8;
    if inc.is_null() {
        c = Curl_ccalloc
            .expect(
                "non-null function pointer",
            )(
            1 as i32 as size_t,
            ::std::mem::size_of::<CookieInfo>() as u64,
        ) as *mut CookieInfo;
        if c.is_null() {
            return 0 as *mut CookieInfo;
        }
        let mut fresh30 = &mut ((*c).filename);
        *fresh30 = Curl_cstrdup
            .expect(
                "non-null function pointer",
            )(
            if !file.is_null() {
                file
            } else {
                b"none\0" as *const u8 as *const i8
            },
        );
        if ((*c).filename).is_null() {
            current_block = 3471203105459249385;
        } else {
            (*c).next_expiration = 0x7fffffffffffffff as i64;
            current_block = 11650488183268122163;
        }
    } else {
        c = inc;
        current_block = 11650488183268122163;
    }
    match current_block {
        11650488183268122163 => {
            (*c).running = 0 as i32 != 0;
            if !file.is_null()
                && strcmp(file, b"-\0" as *const u8 as *const i8) == 0
            {
                fp = stdin;
                fromfile = 0 as i32 != 0;
            } else if !file.is_null() && *file == 0 {
                fp = 0 as *mut FILE;
            } else {
                fp = if !file.is_null() {
                    fopen(file, b"r\0" as *const u8 as *const i8)
                } else {
                    0 as *mut FILE
                };
            }
            (*c).newsession = newsession;
            if !fp.is_null() {
                let mut lineptr: * mut i8 = 0 as *mut i8;
                let mut headerline: bool = false;
                line = Curl_cmalloc
                    .expect("non-null function pointer")(5000 as i32 as size_t)
                    as *mut i8;
                if line.is_null() {
                    current_block = 3471203105459249385;
                } else {
                    while !(Curl_get_line(line, 5000 as i32, fp)).is_null() {
                        if curl_strnequal(
                            b"Set-Cookie:\0" as *const u8 as *const i8,
                            line,
                            strlen(b"Set-Cookie:\0" as *const u8 as *const i8),
                        ) != 0
                        {
                            lineptr = &mut *line.offset(11 as i32 as isize)
                                as *mut i8;
                            headerline = 1 as i32 != 0;
                        } else {
                            lineptr = line;
                            headerline = 0 as i32 != 0;
                        }
                        while *lineptr as i32 != 0
                            && (*lineptr as u8 as i32 == ' ' as i32
                                || *lineptr as u8 as i32 == '\t' as i32)
                        {
                            lineptr = lineptr.offset(1);
                        }
                        Curl_cookie_add(
                            data,
                            c,
                            headerline,
                            1 as i32 != 0,
                            lineptr,
                            0 as *const i8,
                            0 as *const i8,
                            1 as i32 != 0,
                        );
                    }
                    Curl_cfree
                        .expect("non-null function pointer")(line as *mut libc::c_void);
                    remove_expired(c);
                    if fromfile {
                        fclose(fp);
                    }
                    current_block = 14072441030219150333;
                }
            } else {
                current_block = 14072441030219150333;
            }
            match current_block {
                3471203105459249385 => {}
                _ => {
                    (*c).running = 1 as i32 != 0;
                    if !data.is_null() {
                        let mut fresh31 = &mut ((*data).state);
                        (*fresh31).set_cookie_engine(1 as i32 as bit);
                    }
                    return c;
                }
            }
        }
        _ => {}
    }
    Curl_cfree.expect("non-null function pointer")(line as *mut libc::c_void);
    if inc.is_null() {
        Curl_cookie_cleanup(c);
    }
    if fromfile as i32 != 0 && !fp.is_null() {
        fclose(fp);
    }
    return 0 as *mut CookieInfo;
}
unsafe extern "C" fn cookie_sort(
    mut p1: * const core::ffi::c_void,
    mut p2: * const core::ffi::c_void,
) -> i32 {
    let mut c1: * mut crate::src::lib::http2::Cookie = *(p1 as *mut *mut Cookie);
    let mut c2: * mut crate::src::lib::http2::Cookie = *(p2 as *mut *mut Cookie);
    let mut l1: u64 = 0;
    let mut l2: u64 = 0;
    l1 = if !((*c1).path).is_null() {
        strlen((*c1).path)
    } else {
        0 as i32 as u64
    };
    l2 = if !((*c2).path).is_null() {
        strlen((*c2).path)
    } else {
        0 as i32 as u64
    };
    if l1 != l2 {
        return if l2 > l1 { 1 as i32 } else { -(1 as i32) };
    }
    l1 = if !((*c1).domain).is_null() {
        strlen((*c1).domain)
    } else {
        0 as i32 as u64
    };
    l2 = if !((*c2).domain).is_null() {
        strlen((*c2).domain)
    } else {
        0 as i32 as u64
    };
    if l1 != l2 {
        return if l2 > l1 { 1 as i32 } else { -(1 as i32) };
    }
    l1 = if !((*c1).name).is_null() {
        strlen((*c1).name)
    } else {
        0 as i32 as u64
    };
    l2 = if !((*c2).name).is_null() {
        strlen((*c2).name)
    } else {
        0 as i32 as u64
    };
    if l1 != l2 {
        return if l2 > l1 { 1 as i32 } else { -(1 as i32) };
    }
    return if (*c2).creationtime > (*c1).creationtime {
        1 as i32
    } else {
        -(1 as i32)
    };
}
unsafe extern "C" fn cookie_sort_ct(
    mut p1: * const core::ffi::c_void,
    mut p2: * const core::ffi::c_void,
) -> i32 {
    let mut c1: * mut crate::src::lib::http2::Cookie = *(p1 as *mut *mut Cookie);
    let mut c2: * mut crate::src::lib::http2::Cookie = *(p2 as *mut *mut Cookie);
    return if (*c2).creationtime > (*c1).creationtime {
        1 as i32
    } else {
        -(1 as i32)
    };
}
unsafe extern "C" fn dup_cookie(mut src: * mut crate::src::lib::http2::Cookie) -> * mut crate::src::lib::http2::Cookie {
    let mut current_block: u64;
    let mut d: * mut crate::src::lib::http2::Cookie = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<Cookie>() as u64, 1 as i32 as size_t)
        as *mut Cookie;
    if !d.is_null() {
        if !((*src).expirestr).is_null() {
            let mut fresh32 = &mut ((*d).expirestr);
            *fresh32 = Curl_cstrdup
                .expect("non-null function pointer")((*src).expirestr);
            if ((*d).expirestr).is_null() {
                current_block = 3152575373803700262;
            } else {
                current_block = 7815301370352969686;
            }
        } else {
            current_block = 7815301370352969686;
        }
        match current_block {
            7815301370352969686 => {
                if !((*src).domain).is_null() {
                    let mut fresh33 = &mut ((*d).domain);
                    *fresh33 = Curl_cstrdup
                        .expect("non-null function pointer")((*src).domain);
                    if ((*d).domain).is_null() {
                        current_block = 3152575373803700262;
                    } else {
                        current_block = 11050875288958768710;
                    }
                } else {
                    current_block = 11050875288958768710;
                }
                match current_block {
                    3152575373803700262 => {}
                    _ => {
                        if !((*src).path).is_null() {
                            let mut fresh34 = &mut ((*d).path);
                            *fresh34 = Curl_cstrdup
                                .expect("non-null function pointer")((*src).path);
                            if ((*d).path).is_null() {
                                current_block = 3152575373803700262;
                            } else {
                                current_block = 5948590327928692120;
                            }
                        } else {
                            current_block = 5948590327928692120;
                        }
                        match current_block {
                            3152575373803700262 => {}
                            _ => {
                                if !((*src).spath).is_null() {
                                    let mut fresh35 = &mut ((*d).spath);
                                    *fresh35 = Curl_cstrdup
                                        .expect("non-null function pointer")((*src).spath);
                                    if ((*d).spath).is_null() {
                                        current_block = 3152575373803700262;
                                    } else {
                                        current_block = 10652014663920648156;
                                    }
                                } else {
                                    current_block = 10652014663920648156;
                                }
                                match current_block {
                                    3152575373803700262 => {}
                                    _ => {
                                        if !((*src).name).is_null() {
                                            let mut fresh36 = &mut ((*d).name);
                                            *fresh36 = Curl_cstrdup
                                                .expect("non-null function pointer")((*src).name);
                                            if ((*d).name).is_null() {
                                                current_block = 3152575373803700262;
                                            } else {
                                                current_block = 4775909272756257391;
                                            }
                                        } else {
                                            current_block = 4775909272756257391;
                                        }
                                        match current_block {
                                            3152575373803700262 => {}
                                            _ => {
                                                if !((*src).value).is_null() {
                                                    let mut fresh37 = &mut ((*d).value);
                                                    *fresh37 = Curl_cstrdup
                                                        .expect("non-null function pointer")((*src).value);
                                                    if ((*d).value).is_null() {
                                                        current_block = 3152575373803700262;
                                                    } else {
                                                        current_block = 11385396242402735691;
                                                    }
                                                } else {
                                                    current_block = 11385396242402735691;
                                                }
                                                match current_block {
                                                    3152575373803700262 => {}
                                                    _ => {
                                                        if !((*src).maxage).is_null() {
                                                            let mut fresh38 = &mut ((*d).maxage);
                                                            *fresh38 = Curl_cstrdup
                                                                .expect("non-null function pointer")((*src).maxage);
                                                            if ((*d).maxage).is_null() {
                                                                current_block = 3152575373803700262;
                                                            } else {
                                                                current_block = 15090052786889560393;
                                                            }
                                                        } else {
                                                            current_block = 15090052786889560393;
                                                        }
                                                        match current_block {
                                                            3152575373803700262 => {}
                                                            _ => {
                                                                if !((*src).version).is_null() {
                                                                    let mut fresh39 = &mut ((*d).version);
                                                                    *fresh39 = Curl_cstrdup
                                                                        .expect("non-null function pointer")((*src).version);
                                                                    if ((*d).version).is_null() {
                                                                        current_block = 3152575373803700262;
                                                                    } else {
                                                                        current_block = 1356832168064818221;
                                                                    }
                                                                } else {
                                                                    current_block = 1356832168064818221;
                                                                }
                                                                match current_block {
                                                                    3152575373803700262 => {}
                                                                    _ => {
                                                                        (*d).expires = (*src).expires;
                                                                        (*d).tailmatch = (*src).tailmatch;
                                                                        (*d).secure = (*src).secure;
                                                                        (*d).livecookie = (*src).livecookie;
                                                                        (*d).httponly = (*src).httponly;
                                                                        (*d).creationtime = (*src).creationtime;
                                                                        current_block = 13678349939556791712;
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
            13678349939556791712 => {}
            _ => {
                freecookie(d);
                return 0 as *mut Cookie;
            }
        }
    }
    return d;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_cookie_getlist(
    mut c: * mut crate::src::lib::http2::CookieInfo,
    mut host: * const i8,
    mut path: * const i8,
    mut secure: bool,
) -> * mut crate::src::lib::http2::Cookie {
    let mut current_block: u64;
    let mut newco: * mut crate::src::lib::http2::Cookie = 0 as *mut Cookie;
    let mut co: * mut crate::src::lib::http2::Cookie = 0 as *mut Cookie;
    let mut mainco: * mut crate::src::lib::http2::Cookie = 0 as *mut Cookie;
    let mut matches: u64 = 0 as i32 as size_t;
    let mut is_ip: bool = false;
    let myhash: u64 = cookiehash(host);
    if c.is_null() || ((*c).cookies[myhash as usize]).is_null() {
        return 0 as *mut Cookie;
    }
    remove_expired(c);
    is_ip = Curl_host_is_ipnum(host);
    co = (*c).cookies[myhash as usize];
    loop {
        if co.is_null() {
            current_block = 4808432441040389987;
            break;
        }
        if if (*co).secure as i32 != 0 {
            secure as i32
        } else {
            1 as i32
        } != 0
        {
            if ((*co).domain).is_null()
                || (*co).tailmatch as i32 != 0 && !is_ip
                    && tailmatch((*co).domain, host) as i32 != 0
                || (!(*co).tailmatch || is_ip as i32 != 0)
                    && Curl_strcasecompare(host, (*co).domain) != 0
            {
                if ((*co).spath).is_null()
                    || pathmatch((*co).spath, path) as i32 != 0
                {
                    newco = dup_cookie(co);
                    if newco.is_null() {
                        current_block = 4964016911898087089;
                        break;
                    }
                    let mut fresh40 = &mut ((*newco).next);
                    *fresh40 = mainco;
                    mainco = newco;
                    matches = matches.wrapping_add(1);
                }
            }
        }
        co = (*co).next;
    }
    match current_block {
        4808432441040389987 => {
            if matches != 0 {
                let mut array: * mut * mut crate::src::lib::http2::Cookie = 0 as *mut *mut Cookie;
                let mut i: u64 = 0;
                array = Curl_cmalloc
                    .expect(
                        "non-null function pointer",
                    )(
                    (::std::mem::size_of::<*mut Cookie>() as u64)
                        .wrapping_mul(matches),
                ) as *mut *mut Cookie;
                if array.is_null() {
                    current_block = 4964016911898087089;
                } else {
                    co = mainco;
                    i = 0 as i32 as size_t;
                    while !co.is_null() {
                        let mut fresh41 = i;
                        i = i.wrapping_add(1);
                        let mut fresh42 = &mut (*array.offset(fresh41 as isize));
                        *fresh42 = co;
                        co = (*co).next;
                    }
                    qsort(
                        array as *mut libc::c_void,
                        matches,
                        ::std::mem::size_of::<*mut Cookie>() as u64,
                        Some(
                            cookie_sort,
                        ),
                    );
                    mainco = *array.offset(0 as i32 as isize);
                    i = 0 as i32 as size_t;
                    while i < matches.wrapping_sub(1 as i32 as u64) {
                        let mut fresh43 = &mut ((**array.offset(i as isize)).next);
                        *fresh43 = *array
                            .offset(
                                i.wrapping_add(1 as i32 as u64) as isize,
                            );
                        i = i.wrapping_add(1);
                    }
                    let mut fresh44 = &mut ((**array
                        .offset(
                            matches.wrapping_sub(1 as i32 as u64)
                                as isize,
                        ))
                        .next);
                    *fresh44 = 0 as *mut Cookie;
                    Curl_cfree
                        .expect("non-null function pointer")(array as *mut libc::c_void);
                    current_block = 7333393191927787629;
                }
            } else {
                current_block = 7333393191927787629;
            }
            match current_block {
                4964016911898087089 => {}
                _ => return mainco,
            }
        }
        _ => {}
    }
    Curl_cookie_freelist(mainco);
    return 0 as *mut Cookie;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_cookie_clearall(mut cookies: * mut crate::src::lib::http2::CookieInfo) {
    if !cookies.is_null() {
        let mut i: u32 = 0;
        i = 0 as i32 as u32;
        while i < 256 as i32 as u32 {
            Curl_cookie_freelist((*cookies).cookies[i as usize]);
            let mut fresh45 = &mut ((*cookies).cookies[i as usize]);
            *fresh45 = 0 as *mut Cookie;
            i = i.wrapping_add(1);
        }
        (*cookies).numcookies = 0 as i32 as i64;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_cookie_freelist(mut co: * mut crate::src::lib::http2::Cookie) {
    let mut next: * mut crate::src::lib::http2::Cookie = 0 as *mut Cookie;
    while !co.is_null() {
        next = (*co).next;
        freecookie(co);
        co = next;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_cookie_clearsess(mut cookies: * mut crate::src::lib::http2::CookieInfo) {
    let mut first: * mut crate::src::lib::http2::Cookie = 0 as *mut Cookie;
    let mut curr: * mut crate::src::lib::http2::Cookie = 0 as *mut Cookie;
    let mut next: * mut crate::src::lib::http2::Cookie = 0 as *mut Cookie;
    let mut prev: * mut crate::src::lib::http2::Cookie = 0 as *mut Cookie;
    let mut i: u32 = 0;
    if cookies.is_null() {
        return;
    }
    i = 0 as i32 as u32;
    while i < 256 as i32 as u32 {
        if !((*cookies).cookies[i as usize]).is_null() {
            prev = (*cookies).cookies[i as usize];
            curr = prev;
            first = curr;
            while !curr.is_null() {
                next = (*curr).next;
                if (*curr).expires == 0 {
                    if first == curr {
                        first = next;
                    }
                    if prev == curr {
                        prev = next;
                    } else {
                        let mut fresh46 = &mut ((*prev).next);
                        *fresh46 = next;
                    }
                    freecookie(curr);
                    let mut fresh47 = &mut ((*cookies).numcookies);
                    *fresh47 -= 1;
                } else {
                    prev = curr;
                }
                curr = next;
            }
            let mut fresh48 = &mut ((*cookies).cookies[i as usize]);
            *fresh48 = first;
        }
        i = i.wrapping_add(1);
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_cookie_cleanup(mut c: * mut crate::src::lib::http2::CookieInfo) {
    if !c.is_null() {
        let mut i: u32 = 0;
        Curl_cfree
            .expect("non-null function pointer")((*c).filename as *mut libc::c_void);
        i = 0 as i32 as u32;
        while i < 256 as i32 as u32 {
            Curl_cookie_freelist((*c).cookies[i as usize]);
            i = i.wrapping_add(1);
        }
        Curl_cfree.expect("non-null function pointer")(c as *mut libc::c_void);
    }
}
unsafe extern "C" fn get_netscape_format(mut co: * const crate::src::lib::http2::Cookie) -> * mut i8 {
    return curl_maprintf(
        b"%s%s%s\t%s\t%s\t%s\t%ld\t%s\t%s\0" as *const u8 as *const i8,
        if (*co).httponly as i32 != 0 {
            b"#HttpOnly_\0" as *const u8 as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        if (*co).tailmatch as i32 != 0 && !((*co).domain).is_null()
            && *((*co).domain).offset(0 as i32 as isize) as i32
                != '.' as i32
        {
            b".\0" as *const u8 as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !((*co).domain).is_null() {
            (*co).domain as *const i8
        } else {
            b"unknown\0" as *const u8 as *const i8
        },
        if (*co).tailmatch as i32 != 0 {
            b"TRUE\0" as *const u8 as *const i8
        } else {
            b"FALSE\0" as *const u8 as *const i8
        },
        if !((*co).path).is_null() {
            (*co).path as *const i8
        } else {
            b"/\0" as *const u8 as *const i8
        },
        if (*co).secure as i32 != 0 {
            b"TRUE\0" as *const u8 as *const i8
        } else {
            b"FALSE\0" as *const u8 as *const i8
        },
        (*co).expires,
        (*co).name,
        if !((*co).value).is_null() {
            (*co).value as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
    );
}
unsafe extern "C" fn cookie_output(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut c: * mut crate::src::lib::http2::CookieInfo,
    mut filename: * const i8,
) -> u32 {
    let mut current_block: u64;
    let mut co: * mut crate::src::lib::http2::Cookie = 0 as *mut Cookie;
    let mut out: * mut crate::src::lib::http2::_IO_FILE = 0 as *mut FILE;
    let mut use_stdout: bool = 0 as i32 != 0;
    let mut tempstore: * mut i8 = 0 as *mut i8;
    let mut error: u32 = CURLE_OK;
    if c.is_null() {
        return CURLE_OK;
    }
    remove_expired(c);
    if strcmp(b"-\0" as *const u8 as *const i8, filename) == 0 {
        out = stdout;
        use_stdout = 1 as i32 != 0;
        current_block = 15652330335145281839;
    } else {
        let mut randsuffix: [u8; 9] = [0; 9];
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
            filename,
            randsuffix.as_mut_ptr(),
        );
        if tempstore.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        out = fopen(tempstore, b"w\0" as *const u8 as *const i8);
        if out.is_null() {
            error = CURLE_WRITE_ERROR;
            current_block = 7867765481719854029;
        } else {
            current_block = 15652330335145281839;
        }
    }
    match current_block {
        15652330335145281839 => {
            fputs(
                b"# Netscape HTTP Cookie File\n# https://curl.se/docs/http-cookies.html\n# This file was generated by libcurl! Edit at your own risk.\n\n\0"
                    as *const u8 as *const i8,
                out,
            );
            if (*c).numcookies != 0 {
                let mut i: u32 = 0;
                let mut nvalid: u64 = 0 as i32 as size_t;
                let mut array: * mut * mut crate::src::lib::http2::Cookie = 0 as *mut *mut Cookie;
                array = Curl_ccalloc
                    .expect(
                        "non-null function pointer",
                    )(
                    1 as i32 as size_t,
                    (::std::mem::size_of::<*mut Cookie>() as u64)
                        .wrapping_mul((*c).numcookies as u64),
                ) as *mut *mut Cookie;
                if array.is_null() {
                    error = CURLE_OUT_OF_MEMORY;
                    current_block = 7867765481719854029;
                } else {
                    i = 0 as i32 as u32;
                    while i < 256 as i32 as u32 {
                        co = (*c).cookies[i as usize];
                        while !co.is_null() {
                            if !((*co).domain).is_null() {
                                let mut fresh49 = nvalid;
                                nvalid = nvalid.wrapping_add(1);
                                let mut fresh50 = &mut (*array.offset(fresh49 as isize));
                                *fresh50 = co;
                            }
                            co = (*co).next;
                        }
                        i = i.wrapping_add(1);
                    }
                    qsort(
                        array as *mut libc::c_void,
                        nvalid,
                        ::std::mem::size_of::<*mut Cookie>() as u64,
                        Some(
                            cookie_sort_ct,
                        ),
                    );
                    i = 0 as i32 as u32;
                    loop {
                        if !((i as u64) < nvalid) {
                            current_block = 18435049525520518667;
                            break;
                        }
                        let mut format_ptr: * mut i8 = get_netscape_format(
                            *array.offset(i as isize),
                        );
                        if format_ptr.is_null() {
                            Curl_cfree
                                .expect(
                                    "non-null function pointer",
                                )(array as *mut libc::c_void);
                            error = CURLE_OUT_OF_MEMORY;
                            current_block = 7867765481719854029;
                            break;
                        } else {
                            curl_mfprintf(
                                out,
                                b"%s\n\0" as *const u8 as *const i8,
                                format_ptr,
                            );
                            Curl_cfree
                                .expect(
                                    "non-null function pointer",
                                )(format_ptr as *mut libc::c_void);
                            i = i.wrapping_add(1);
                        }
                    }
                    match current_block {
                        7867765481719854029 => {}
                        _ => {
                            Curl_cfree
                                .expect(
                                    "non-null function pointer",
                                )(array as *mut libc::c_void);
                            current_block = 2543120759711851213;
                        }
                    }
                }
            } else {
                current_block = 2543120759711851213;
            }
            match current_block {
                7867765481719854029 => {}
                _ => {
                    if !use_stdout {
                        fclose(out);
                        out = 0 as *mut FILE;
                        if Curl_rename(tempstore, filename) != 0 {
                            unlink(tempstore);
                            error = CURLE_WRITE_ERROR;
                            current_block = 7867765481719854029;
                        } else {
                            current_block = 3689906465960840878;
                        }
                    } else {
                        current_block = 3689906465960840878;
                    }
                    match current_block {
                        7867765481719854029 => {}
                        _ => {
                            Curl_cfree
                                .expect(
                                    "non-null function pointer",
                                )(tempstore as *mut libc::c_void);
                            return CURLE_OK;
                        }
                    }
                }
            }
        }
        _ => {}
    }
    if !out.is_null() && !use_stdout {
        fclose(out);
    }
    Curl_cfree.expect("non-null function pointer")(tempstore as *mut libc::c_void);
    return error;
}
unsafe extern "C" fn cookie_list(mut data: * mut crate::src::lib::http2::Curl_easy) -> * mut crate::src::lib::http2::curl_slist {
    let mut list: * mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
    let mut beg: * mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
    let mut c: * mut crate::src::lib::http2::Cookie = 0 as *mut Cookie;
    let mut line: * mut i8 = 0 as *mut i8;
    let mut i: u32 = 0;
    if ((*data).cookies).is_null()
        || (*(*data).cookies).numcookies == 0 as i32 as i64
    {
        return 0 as *mut curl_slist;
    }
    i = 0 as i32 as u32;
    while i < 256 as i32 as u32 {
        c = (*(*data).cookies).cookies[i as usize];
        while !c.is_null() {
            if !((*c).domain).is_null() {
                line = get_netscape_format(c);
                if line.is_null() {
                    curl_slist_free_all(list);
                    return 0 as *mut curl_slist;
                }
                beg = Curl_slist_append_nodup(list, line);
                if beg.is_null() {
                    Curl_cfree
                        .expect("non-null function pointer")(line as *mut libc::c_void);
                    curl_slist_free_all(list);
                    return 0 as *mut curl_slist;
                }
                list = beg;
            }
            c = (*c).next;
        }
        i = i.wrapping_add(1);
    }
    return list;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_cookie_list(mut data: * mut crate::src::lib::http2::Curl_easy) -> * mut crate::src::lib::http2::curl_slist {
    let mut list: * mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
    list = cookie_list(data);
    Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
    return list;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_flush_cookies(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut cleanup: bool,
) {
    let mut res: u32 = CURLE_OK;
    if !((*data).set.str_0[STRING_COOKIEJAR as i32 as usize]).is_null() {
        if !((*data).state.cookielist).is_null() {
            Curl_cookie_loadfiles(data);
        }
        Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
        res = cookie_output(
            data,
            (*data).cookies,
            (*data).set.str_0[STRING_COOKIEJAR as i32 as usize],
        );
        if res as u64 != 0 {
            Curl_infof(
                data,
                b"WARNING: failed to save cookies in %s: %s\0" as *const u8
                    as *const i8,
                (*data).set.str_0[STRING_COOKIEJAR as i32 as usize],
                curl_easy_strerror(res),
            );
        }
    } else {
        if cleanup as i32 != 0 && !((*data).state.cookielist).is_null() {
            curl_slist_free_all((*data).state.cookielist);
            let mut fresh51 = &mut ((*data).state.cookielist);
            *fresh51 = 0 as *mut curl_slist;
        }
        Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
    }
    if cleanup as i32 != 0
        && (((*data).share).is_null() || (*data).cookies != (*(*data).share).cookies)
    {
        Curl_cookie_cleanup((*data).cookies);
        let mut fresh52 = &mut ((*data).cookies);
        *fresh52 = 0 as *mut CookieInfo;
    }
    Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
}
use crate::laertes_rt::*;
