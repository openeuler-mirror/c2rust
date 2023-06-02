use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn memcpy(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn strcpy(_: * mut i8, _: * const i8) -> * mut i8;
    fn strlen(_: * const i8) -> u64;
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::hostip::Curl_fetch_addr;
pub use crate::src::lib::hostip::Curl_printable_address;
pub use crate::src::lib::hostip::Curl_resolv;
pub use crate::src::lib::hostip::Curl_resolv_check;
pub use crate::src::lib::hostip::Curl_resolv_unlock;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::sendf::Curl_read_plain;
pub use crate::src::lib::sendf::Curl_write_plain;
pub use crate::src::lib::strerror::curl_easy_strerror;
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
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
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
pub type uint16_t = u16;
pub type in_addr_t = u32;
// #[derive(Copy, Clone)]

pub type in_addr = crate::src::lib::connect::in_addr;
pub type in_port_t = u16;
// #[derive(Copy, Clone)]

pub type in6_addr = crate::src::lib::connect::in6_addr;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_6 = crate::src::lib::connect::C2RustUnnamed_8;
// #[derive(Copy, Clone)]

pub type sockaddr_in = crate::src::lib::connect::sockaddr_in;
// #[derive(Copy, Clone)]

pub type sockaddr_in6 = crate::src::lib::connect::sockaddr_in6;
pub type resolve_t = i32;
pub const CURLRESOLV_PENDING: resolve_t = 1;
pub const CURLRESOLV_RESOLVED: resolve_t = 0;
pub const CURLRESOLV_ERROR: resolve_t = -1;
pub const CURLRESOLV_TIMEDOUT: resolve_t = -2;
unsafe extern "C" fn socksstate(mut data: * mut crate::src::lib::http2::Curl_easy, mut state: u32) {
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    let mut oldstate: u32 = (*conn).cnnct.state;
    if oldstate as u32 == state as u32 {
        return;
    }
    (*conn).cnnct.state = state;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_SOCKS_getsock(
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut sock: * mut i32,
    mut sockindex: i32,
) -> i32 {
    let mut rc: i32 = 0 as i32;
    *sock.offset(0 as i32 as isize) = (*conn).sock[sockindex as usize];
    match (*conn).cnnct.state as u32 {
        10 | 4 | 8 | 15 | 16 => {
            rc = (1 as i32) << 0 as i32;
        }
        _ => {
            rc = (1 as i32) << 16 as i32 + 0 as i32;
        }
    }
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_SOCKS4<'a1>(
    mut proxy_user: * const i8,
    mut hostname: * const i8,
    mut remote_port: i32,
    mut sockindex: i32,
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut done: Option<&'a1 mut bool>,
) -> u32 {
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    let protocol4a: bool = if (*conn).socks_proxy.proxytype as u32
        == CURLPROXY_SOCKS4A as i32 as u32
    {
        1 as i32
    } else {
        0 as i32
    } != 0;
    let mut socksreq: * mut u8 = (*data).state.buffer as *mut u8;
    let mut result: u32 = CURLE_OK;
    let mut sockfd: i32 = (*conn).sock[sockindex as usize];
    let mut sx: Option<&'_ mut crate::src::lib::http2::connstate> = Some(&mut (*conn).cnnct);
    let mut dns: * mut crate::src::lib::http2::Curl_dns_entry = 0 as *mut Curl_dns_entry;
    let mut actualread: i64 = 0;
    let mut written: i64 = 0;
    if !((*(borrow(& sx)).unwrap()).state as u32 >= CONNECT_SOCKS_INIT as i32 as u32
        && ((*(borrow(& sx)).unwrap()).state as u32) < CONNECT_DONE as i32 as u32)
        && !*(borrow(& done)).unwrap()
    {
        socksstate(data, CONNECT_SOCKS_INIT);
    }
    let mut current_block_107: u64;
    match (*(borrow(& sx)).unwrap()).state as u32 {
        1 => {
            (*conn).ip_version = 1 as i32 as u8;
            if ((*conn).bits).httpproxy() != 0 {
                Curl_infof(
                    data,
                    b"SOCKS4%s: connecting to HTTP proxy %s port %d\0" as *const u8
                        as *const i8,
                    if protocol4a as i32 != 0 {
                        b"a\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    hostname,
                    remote_port,
                );
            }
            Curl_infof(
                data,
                b"SOCKS4 communication to %s:%d\0" as *const u8 as *const i8,
                hostname,
                remote_port,
            );
            *socksreq
                .offset(0 as i32 as isize) = 4 as i32 as u8;
            *socksreq
                .offset(1 as i32 as isize) = 1 as i32 as u8;
            *socksreq
                .offset(
                    2 as i32 as isize,
                ) = (remote_port >> 8 as i32 & 0xff as i32)
                as u8;
            *socksreq
                .offset(
                    3 as i32 as isize,
                ) = (remote_port & 0xff as i32) as u8;
            if !protocol4a {
                let mut rc: i32 = Curl_resolv(
                    data,
                    hostname,
                    remote_port,
                    0 as i32 != 0,
                    Some(&mut dns),
                );
                if rc as i32 == CURLRESOLV_ERROR as i32 {
                    return CURLPX_RESOLVE_HOST
                } else {
                    if rc as i32 == CURLRESOLV_PENDING as i32 {
                        socksstate(data, CONNECT_RESOLVING);
                        Curl_infof(
                            data,
                            b"SOCKS4 non-blocking resolve of %s\0" as *const u8
                                as *const i8,
                            hostname,
                        );
                        return CURLPX_OK;
                    }
                }
                socksstate(data, CONNECT_RESOLVED);
                current_block_107 = 1526476230797115868;
            } else {
                socksstate(data, CONNECT_REQ_INIT);
                current_block_107 = 10721739657148430059;
            }
        }
        10 => {
            dns = Curl_fetch_addr(data, hostname, (*conn).port);
            if !dns.is_null() {
                let mut fresh0 = &mut ((*data).state.async_0.dns);
                *fresh0 = dns;
                let mut fresh1 = &mut ((*data).state.async_0);
                (*fresh1).set_done(1 as i32 as bit);
                Curl_infof(
                    data,
                    b"Hostname '%s' was found\0" as *const u8 as *const i8,
                    hostname,
                );
                socksstate(data, CONNECT_RESOLVED);
            } else {
                result = Curl_resolv_check(data, Some(&mut dns));
                if dns.is_null() {
                    if result as u64 != 0 {
                        return CURLPX_RESOLVE_HOST;
                    }
                    return CURLPX_OK;
                }
            }
            current_block_107 = 1526476230797115868;
        }
        11 => {
            current_block_107 = 1526476230797115868;
        }
        9 => {
            current_block_107 = 10721739657148430059;
        }
        14 => {
            current_block_107 = 4542371696367325799;
        }
        4 => {
            current_block_107 = 7725392638173102412;
        }
        _ => {
            current_block_107 = 11064061988481400464;
        }
    }
    match current_block_107 {
        1526476230797115868 => {
            let mut hp: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
            if !dns.is_null() {
                hp = (*dns).addr;
                while !hp.is_null() && (*hp).ai_family != 2 as i32 {
                    hp = (*hp).ai_next;
                }
                if !hp.is_null() {
                    let mut saddr_in: * mut crate::src::lib::connect::sockaddr_in = (0 as * mut crate::src::lib::connect::sockaddr_in);
                    let mut buf: [i8; 64] = [0; 64];
                    Curl_printable_address(
                        hp,
                        buf.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 64]>() as u64,
                    );
                    saddr_in = (*hp).ai_addr as *mut libc::c_void as *mut sockaddr_in;
                    *socksreq
                        .offset(
                            4 as i32 as isize,
                        ) = *(&mut (*saddr_in).sin_addr.s_addr as *mut in_addr_t
                        as *mut u8)
                        .offset(0 as i32 as isize);
                    *socksreq
                        .offset(
                            5 as i32 as isize,
                        ) = *(&mut (*saddr_in).sin_addr.s_addr as *mut in_addr_t
                        as *mut u8)
                        .offset(1 as i32 as isize);
                    *socksreq
                        .offset(
                            6 as i32 as isize,
                        ) = *(&mut (*saddr_in).sin_addr.s_addr as *mut in_addr_t
                        as *mut u8)
                        .offset(2 as i32 as isize);
                    *socksreq
                        .offset(
                            7 as i32 as isize,
                        ) = *(&mut (*saddr_in).sin_addr.s_addr as *mut in_addr_t
                        as *mut u8)
                        .offset(3 as i32 as isize);
                    Curl_infof(
                        data,
                        b"SOCKS4 connect to IPv4 %s (locally resolved)\0" as *const u8
                            as *const i8,
                        buf.as_mut_ptr(),
                    );
                    Curl_resolv_unlock(data, dns);
                } else {
                    Curl_failf(
                        data,
                        b"SOCKS4 connection to %s not supported\0" as *const u8
                            as *const i8,
                        hostname,
                    );
                }
            } else {
                Curl_failf(
                    data,
                    b"Failed to resolve \"%s\" for SOCKS4 connect.\0" as *const u8
                        as *const i8,
                    hostname,
                );
            }
            if hp.is_null() {
                return CURLPX_RESOLVE_HOST;
            }
            current_block_107 = 10721739657148430059;
        }
        _ => {}
    }
    match current_block_107 {
        10721739657148430059 => {
            *socksreq
                .offset(8 as i32 as isize) = 0 as i32 as u8;
            if !proxy_user.is_null() {
                let mut plen: u64 = strlen(proxy_user);
                if plen
                    >= ((*data).set.buffer_size as size_t)
                        .wrapping_sub(8 as i32 as u64)
                {
                    Curl_failf(
                        data,
                        b"Too long SOCKS proxy user name, can't use!\0" as *const u8
                            as *const i8,
                    );
                    return CURLPX_LONG_USER;
                }
                memcpy(
                    socksreq.offset(8 as i32 as isize) as *mut libc::c_void,
                    proxy_user as *const libc::c_void,
                    plen.wrapping_add(1 as i32 as u64),
                );
            }
            let mut packetsize: u64 = (9 as i32 as u64)
                .wrapping_add(
                    strlen(
                        (socksreq as *mut i8).offset(8 as i32 as isize),
                    ),
                );
            if protocol4a {
                let mut hostnamelen: u64 = 0 as i32 as size_t;
                *socksreq
                    .offset(
                        4 as i32 as isize,
                    ) = 0 as i32 as u8;
                *socksreq
                    .offset(
                        5 as i32 as isize,
                    ) = 0 as i32 as u8;
                *socksreq
                    .offset(
                        6 as i32 as isize,
                    ) = 0 as i32 as u8;
                *socksreq
                    .offset(
                        7 as i32 as isize,
                    ) = 1 as i32 as u8;
                hostnamelen = (strlen(hostname))
                    .wrapping_add(1 as i32 as u64);
                if hostnamelen <= 255 as i32 as u64 {
                    strcpy(
                        (socksreq as *mut i8).offset(packetsize as isize),
                        hostname,
                    );
                } else {
                    Curl_failf(
                        data,
                        b"SOCKS4: too long host name\0" as *const u8
                            as *const i8,
                    );
                    return CURLPX_LONG_HOSTNAME;
                }
                packetsize = (packetsize as u64).wrapping_add(hostnamelen)
                    as size_t as size_t;
            }
            let mut fresh2 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
            *fresh2 = socksreq;
            (*(borrow_mut(&mut sx)).unwrap()).outstanding = packetsize as ssize_t;
            socksstate(data, CONNECT_REQ_SENDING);
            current_block_107 = 4542371696367325799;
        }
        _ => {}
    }
    match current_block_107 {
        4542371696367325799 => {
            result = Curl_write_plain(
                data,
                sockfd,
                (*(borrow_mut(&mut sx)).unwrap()).outp as *mut i8 as *const libc::c_void,
                (*(borrow_mut(&mut sx)).unwrap()).outstanding as size_t,
                Some(&mut written),
            );
            if result as u32 != 0
                && CURLE_AGAIN as i32 as u32 != result as u32
            {
                Curl_failf(
                    data,
                    b"Failed to send SOCKS4 connect request.\0" as *const u8
                        as *const i8,
                );
                return CURLPX_SEND_CONNECT;
            }
            if written != (*(borrow(& sx)).unwrap()).outstanding {
                let mut fresh3 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outstanding);
                *fresh3 -= written;
                let mut fresh4 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
                *fresh4 = (*fresh4).offset(written as isize);
                return CURLPX_OK;
            }
            (*(borrow_mut(&mut sx)).unwrap()).outstanding = 8 as i32 as ssize_t;
            let mut fresh5 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
            *fresh5 = socksreq;
            socksstate(data, CONNECT_SOCKS_READ);
            current_block_107 = 7725392638173102412;
        }
        _ => {}
    }
    match current_block_107 {
        7725392638173102412 => {
            result = Curl_read_plain(
                sockfd,
                (*(borrow_mut(&mut sx)).unwrap()).outp as *mut i8,
                (*(borrow_mut(&mut sx)).unwrap()).outstanding as size_t,
                Some(&mut actualread),
            );
            if result as u32 != 0
                && CURLE_AGAIN as i32 as u32 != result as u32
            {
                Curl_failf(
                    data,
                    b"SOCKS4: Failed receiving connect request ack: %s\0" as *const u8
                        as *const i8,
                    curl_easy_strerror(result),
                );
                return CURLPX_RECV_CONNECT;
            } else {
                if result as u64 == 0 && actualread == 0 {
                    Curl_failf(
                        data,
                        b"connection to proxy closed\0" as *const u8
                            as *const i8,
                    );
                    return CURLPX_CLOSED;
                } else {
                    if actualread != (*(borrow(& sx)).unwrap()).outstanding {
                        let mut fresh6 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outstanding);
                        *fresh6 -= actualread;
                        let mut fresh7 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
                        *fresh7 = (*fresh7).offset(actualread as isize);
                        return CURLPX_OK;
                    }
                }
            }
            socksstate(data, CONNECT_DONE);
        }
        _ => {}
    }
    if *socksreq.offset(0 as i32 as isize) != 0 {
        Curl_failf(
            data,
            b"SOCKS4 reply has wrong version, version should be 0.\0" as *const u8
                as *const i8,
        );
        return CURLPX_BAD_VERSION;
    }
    match *socksreq.offset(1 as i32 as isize) as i32 {
        90 => {
            Curl_infof(
                data,
                b"SOCKS4%s request granted.\0" as *const u8 as *const i8,
                if protocol4a as i32 != 0 {
                    b"a\0" as *const u8 as *const i8
                } else {
                    b"\0" as *const u8 as *const i8
                },
            );
        }
        91 => {
            Curl_failf(
                data,
                b"Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d), request rejected or failed.\0"
                    as *const u8 as *const i8,
                *socksreq.offset(4 as i32 as isize) as i32,
                *socksreq.offset(5 as i32 as isize) as i32,
                *socksreq.offset(6 as i32 as isize) as i32,
                *socksreq.offset(7 as i32 as isize) as i32,
                (*socksreq.offset(2 as i32 as isize) as i32)
                    << 8 as i32
                    | *socksreq.offset(3 as i32 as isize) as i32,
                *socksreq.offset(1 as i32 as isize) as i32,
            );
            return CURLPX_REQUEST_FAILED;
        }
        92 => {
            Curl_failf(
                data,
                b"Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d), request rejected because SOCKS server cannot connect to identd on the client.\0"
                    as *const u8 as *const i8,
                *socksreq.offset(4 as i32 as isize) as i32,
                *socksreq.offset(5 as i32 as isize) as i32,
                *socksreq.offset(6 as i32 as isize) as i32,
                *socksreq.offset(7 as i32 as isize) as i32,
                (*socksreq.offset(2 as i32 as isize) as i32)
                    << 8 as i32
                    | *socksreq.offset(3 as i32 as isize) as i32,
                *socksreq.offset(1 as i32 as isize) as i32,
            );
            return CURLPX_IDENTD;
        }
        93 => {
            Curl_failf(
                data,
                b"Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d), request rejected because the client program and identd report different user-ids.\0"
                    as *const u8 as *const i8,
                *socksreq.offset(4 as i32 as isize) as i32,
                *socksreq.offset(5 as i32 as isize) as i32,
                *socksreq.offset(6 as i32 as isize) as i32,
                *socksreq.offset(7 as i32 as isize) as i32,
                (*socksreq.offset(2 as i32 as isize) as i32)
                    << 8 as i32
                    | *socksreq.offset(3 as i32 as isize) as i32,
                *socksreq.offset(1 as i32 as isize) as i32,
            );
            return CURLPX_IDENTD_DIFFER;
        }
        _ => {
            Curl_failf(
                data,
                b"Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d), Unknown.\0"
                    as *const u8 as *const i8,
                *socksreq.offset(4 as i32 as isize) as i32,
                *socksreq.offset(5 as i32 as isize) as i32,
                *socksreq.offset(6 as i32 as isize) as i32,
                *socksreq.offset(7 as i32 as isize) as i32,
                (*socksreq.offset(2 as i32 as isize) as i32)
                    << 8 as i32
                    | *socksreq.offset(3 as i32 as isize) as i32,
                *socksreq.offset(1 as i32 as isize) as i32,
            );
            return CURLPX_UNKNOWN_FAIL;
        }
    }
    *(borrow_mut(&mut done)).unwrap() = 1 as i32 != 0;
    return CURLPX_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_SOCKS5<'a1>(
    mut proxy_user: * const i8,
    mut proxy_password: * const i8,
    mut hostname: * const i8,
    mut remote_port: i32,
    mut sockindex: i32,
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut done: Option<&'a1 mut bool>,
) -> u32 {
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    let mut socksreq: * mut u8 = (*data).state.buffer as *mut u8;
    let mut dest: [i8; 256] = *core::intrinsics::transmute::<&'_ [u8; 256], &'_ mut [i8; 256]>(
        b"unknown\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut idx: i32 = 0;
    let mut actualread: i64 = 0;
    let mut written: i64 = 0;
    let mut result: u32 = CURLE_OK;
    let mut sockfd: i32 = (*conn).sock[sockindex as usize];
    let mut socks5_resolve_local: bool = if (*conn).socks_proxy.proxytype as u32
        == CURLPROXY_SOCKS5 as i32 as u32
    {
        1 as i32
    } else {
        0 as i32
    } != 0;
    let hostname_len: u64 = strlen(hostname);
    let mut len: i64 = 0 as i32 as ssize_t;
    let auth: u64 = (*data).set.socks5auth;
    let mut allow_gssapi: bool = 0 as i32 != 0;
    let mut sx: Option<&'_ mut crate::src::lib::http2::connstate> = Some(&mut (*conn).cnnct);
    let mut dns: * mut crate::src::lib::http2::Curl_dns_entry = 0 as *mut Curl_dns_entry;
    if !((*(borrow(& sx)).unwrap()).state as u32 >= CONNECT_SOCKS_INIT as i32 as u32
        && ((*(borrow(& sx)).unwrap()).state as u32) < CONNECT_DONE as i32 as u32)
        && !*(borrow(& done)).unwrap()
    {
        socksstate(data, CONNECT_SOCKS_INIT);
    }
    let mut current_block_276: u64;
    match (*(borrow(& sx)).unwrap()).state as u32 {
        1 => {
            if ((*conn).bits).httpproxy() != 0 {
                Curl_infof(
                    data,
                    b"SOCKS5: connecting to HTTP proxy %s port %d\0" as *const u8
                        as *const i8,
                    hostname,
                    remote_port,
                );
            }
            if !socks5_resolve_local
                && hostname_len > 255 as i32 as u64
            {
                Curl_infof(
                    data,
                    b"SOCKS5: server resolving disabled for hostnames of length > 255 [actual len=%zu]\0"
                        as *const u8 as *const i8,
                    hostname_len,
                );
                socks5_resolve_local = 1 as i32 != 0;
            }
            if auth
                & !((1 as i32 as u64) << 0 as i32
                    | (1 as i32 as u64) << 2 as i32) != 0
            {
                Curl_infof(
                    data,
                    b"warning: unsupported value passed to CURLOPT_SOCKS5_AUTH: %lu\0"
                        as *const u8 as *const i8,
                    auth,
                );
            }
            if auth & (1 as i32 as u64) << 0 as i32 == 0 {
                proxy_user = 0 as *const i8;
            }
            idx = 0 as i32;
            let mut fresh8 = idx;
            idx = idx + 1;
            *socksreq.offset(fresh8 as isize) = 5 as i32 as u8;
            idx += 1;
            let mut fresh9 = idx;
            idx = idx + 1;
            *socksreq.offset(fresh9 as isize) = 0 as i32 as u8;
            if allow_gssapi {
                let mut fresh10 = idx;
                idx = idx + 1;
                *socksreq.offset(fresh10 as isize) = 1 as i32 as u8;
            }
            if !proxy_user.is_null() {
                let mut fresh11 = idx;
                idx = idx + 1;
                *socksreq.offset(fresh11 as isize) = 2 as i32 as u8;
            }
            *socksreq
                .offset(
                    1 as i32 as isize,
                ) = (idx - 2 as i32) as u8;
            result = Curl_write_plain(
                data,
                sockfd,
                socksreq as *mut i8 as *const libc::c_void,
                idx as size_t,
                Some(&mut written),
            );
            if result as u32 != 0
                && CURLE_AGAIN as i32 as u32 != result as u32
            {
                Curl_failf(
                    data,
                    b"Unable to send initial SOCKS5 request.\0" as *const u8
                        as *const i8,
                );
                return CURLPX_SEND_CONNECT;
            }
            if written != idx as i64 {
                socksstate(data, CONNECT_SOCKS_SEND);
                (*(borrow_mut(&mut sx)).unwrap()).outstanding = idx as i64 - written;
                let mut fresh12 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
                *fresh12 = &mut *socksreq.offset(written as isize) as *mut u8;
                return CURLPX_OK;
            }
            socksstate(data, CONNECT_SOCKS_READ);
            current_block_276 = 3729150195017652645;
        }
        2 => {
            result = Curl_write_plain(
                data,
                sockfd,
                (*(borrow_mut(&mut sx)).unwrap()).outp as *mut i8 as *const libc::c_void,
                (*(borrow_mut(&mut sx)).unwrap()).outstanding as size_t,
                Some(&mut written),
            );
            if result as u32 != 0
                && CURLE_AGAIN as i32 as u32 != result as u32
            {
                Curl_failf(
                    data,
                    b"Unable to send initial SOCKS5 request.\0" as *const u8
                        as *const i8,
                );
                return CURLPX_SEND_CONNECT;
            }
            if written != (*(borrow(& sx)).unwrap()).outstanding {
                let mut fresh13 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outstanding);
                *fresh13 -= written;
                let mut fresh14 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
                *fresh14 = (*fresh14).offset(written as isize);
                return CURLPX_OK;
            }
            current_block_276 = 3729150195017652645;
        }
        3 => {
            current_block_276 = 3729150195017652645;
        }
        4 => {
            current_block_276 = 17113687173598995549;
        }
        6 => {
            current_block_276 = 6177381118916711871;
        }
        7 => {
            current_block_276 = 2986675497777506938;
        }
        8 => {
            current_block_276 = 5249903830285462583;
        }
        9 => {
            current_block_276 = 6765806975593869225;
        }
        10 => {
            dns = Curl_fetch_addr(data, hostname, remote_port);
            if !dns.is_null() {
                let mut fresh27 = &mut ((*data).state.async_0.dns);
                *fresh27 = dns;
                let mut fresh28 = &mut ((*data).state.async_0);
                (*fresh28).set_done(1 as i32 as bit);
                Curl_infof(
                    data,
                    b"SOCKS5: hostname '%s' found\0" as *const u8 as *const i8,
                    hostname,
                );
            }
            if dns.is_null() {
                result = Curl_resolv_check(data, Some(&mut dns));
                if dns.is_null() {
                    if result as u64 != 0 {
                        return CURLPX_RESOLVE_HOST;
                    }
                    return CURLPX_OK;
                }
            }
            current_block_276 = 6938158527927677584;
        }
        11 => {
            current_block_276 = 6938158527927677584;
        }
        12 => {
            current_block_276 = 4992401317151232712;
        }
        13 => {
            current_block_276 = 3777403817673069519;
        }
        14 => {
            current_block_276 = 1406533880978078420;
        }
        15 => {
            current_block_276 = 17002506680330119909;
        }
        16 => {
            current_block_276 = 5405868585544072297;
        }
        _ => {
            current_block_276 = 6531417090144833949;
        }
    }
    match current_block_276 {
        3729150195017652645 => {
            (*(borrow_mut(&mut sx)).unwrap()).outstanding = 2 as i32 as ssize_t;
            let mut fresh15 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
            *fresh15 = socksreq;
            current_block_276 = 17113687173598995549;
        }
        _ => {}
    }
    match current_block_276 {
        17113687173598995549 => {
            result = Curl_read_plain(
                sockfd,
                (*(borrow_mut(&mut sx)).unwrap()).outp as *mut i8,
                (*(borrow_mut(&mut sx)).unwrap()).outstanding as size_t,
                Some(&mut actualread),
            );
            if result as u32 != 0
                && CURLE_AGAIN as i32 as u32 != result as u32
            {
                Curl_failf(
                    data,
                    b"Unable to receive initial SOCKS5 response.\0" as *const u8
                        as *const i8,
                );
                return CURLPX_RECV_CONNECT;
            } else if result as u64 == 0 && actualread == 0 {
                Curl_failf(
                    data,
                    b"Connection to proxy closed\0" as *const u8 as *const i8,
                );
                return CURLPX_CLOSED;
            } else if actualread != (*(borrow(& sx)).unwrap()).outstanding {
                let mut fresh16 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outstanding);
                *fresh16 -= actualread;
                let mut fresh17 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
                *fresh17 = (*fresh17).offset(actualread as isize);
                return CURLPX_OK;
            } else if *socksreq.offset(0 as i32 as isize) as i32
                    != 5 as i32
                {
                Curl_failf(
                    data,
                    b"Received invalid version in initial SOCKS5 response.\0"
                        as *const u8 as *const i8,
                );
                return CURLPX_BAD_VERSION;
            } else if *socksreq.offset(1 as i32 as isize) as i32
                    == 0 as i32
                {
                socksstate(data, CONNECT_REQ_INIT);
                current_block_276 = 6765806975593869225;
            } else {
                if *socksreq.offset(1 as i32 as isize) as i32
                    == 2 as i32
                {
                    socksstate(data, CONNECT_AUTH_INIT);
                } else {
                    if !allow_gssapi
                        && *socksreq.offset(1 as i32 as isize) as i32
                            == 1 as i32
                    {
                        Curl_failf(
                            data,
                            b"SOCKS5 GSSAPI per-message authentication is not supported.\0"
                                as *const u8 as *const i8,
                        );
                        return CURLPX_GSSAPI_PERMSG;
                    } else {
                        if *socksreq.offset(1 as i32 as isize) as i32
                            == 255 as i32
                        {
                            Curl_failf(
                                data,
                                b"No authentication method was acceptable.\0" as *const u8
                                    as *const i8,
                            );
                            return CURLPX_NO_AUTH;
                        }
                    }
                    Curl_failf(
                        data,
                        b"Undocumented SOCKS5 mode attempted to be used by server.\0"
                            as *const u8 as *const i8,
                    );
                    return CURLPX_UNKNOWN_MODE;
                }
                current_block_276 = 6177381118916711871;
            }
        }
        _ => {}
    }
    match current_block_276 {
        6177381118916711871 => {
            let mut proxy_user_len: u64 = 0;
            let mut proxy_password_len: u64 = 0;
            if !proxy_user.is_null() && !proxy_password.is_null() {
                proxy_user_len = strlen(proxy_user);
                proxy_password_len = strlen(proxy_password);
            } else {
                proxy_user_len = 0 as i32 as size_t;
                proxy_password_len = 0 as i32 as size_t;
            }
            len = 0 as i32 as ssize_t;
            let mut fresh18 = len;
            len = len + 1;
            *socksreq.offset(fresh18 as isize) = 1 as i32 as u8;
            let mut fresh19 = len;
            len = len + 1;
            *socksreq.offset(fresh19 as isize) = proxy_user_len as u8;
            if !proxy_user.is_null() && proxy_user_len != 0 {
                if proxy_user_len >= 255 as i32 as u64 {
                    Curl_failf(
                        data,
                        b"Excessive user name length for proxy auth\0" as *const u8
                            as *const i8,
                    );
                    return CURLPX_LONG_USER;
                }
                memcpy(
                    socksreq.offset(len as isize) as *mut libc::c_void,
                    proxy_user as *const libc::c_void,
                    proxy_user_len,
                );
            }
            len = (len as u64).wrapping_add(proxy_user_len) as ssize_t
                as ssize_t;
            let mut fresh20 = len;
            len = len + 1;
            *socksreq.offset(fresh20 as isize) = proxy_password_len as u8;
            if !proxy_password.is_null() && proxy_password_len != 0 {
                if proxy_password_len > 255 as i32 as u64 {
                    Curl_failf(
                        data,
                        b"Excessive password length for proxy auth\0" as *const u8
                            as *const i8,
                    );
                    return CURLPX_LONG_PASSWD;
                }
                memcpy(
                    socksreq.offset(len as isize) as *mut libc::c_void,
                    proxy_password as *const libc::c_void,
                    proxy_password_len,
                );
            }
            len = (len as u64).wrapping_add(proxy_password_len) as ssize_t
                as ssize_t;
            socksstate(data, CONNECT_AUTH_SEND);
            (*(borrow_mut(&mut sx)).unwrap()).outstanding = len;
            let mut fresh21 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
            *fresh21 = socksreq;
            current_block_276 = 2986675497777506938;
        }
        _ => {}
    }
    match current_block_276 {
        2986675497777506938 => {
            result = Curl_write_plain(
                data,
                sockfd,
                (*(borrow_mut(&mut sx)).unwrap()).outp as *mut i8 as *const libc::c_void,
                (*(borrow_mut(&mut sx)).unwrap()).outstanding as size_t,
                Some(&mut written),
            );
            if result as u32 != 0
                && CURLE_AGAIN as i32 as u32 != result as u32
            {
                Curl_failf(
                    data,
                    b"Failed to send SOCKS5 sub-negotiation request.\0" as *const u8
                        as *const i8,
                );
                return CURLPX_SEND_AUTH;
            }
            if (*(borrow(& sx)).unwrap()).outstanding != written {
                let mut fresh22 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outstanding);
                *fresh22 -= written;
                let mut fresh23 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
                *fresh23 = (*fresh23).offset(written as isize);
                return CURLPX_OK;
            }
            let mut fresh24 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
            *fresh24 = socksreq;
            (*(borrow_mut(&mut sx)).unwrap()).outstanding = 2 as i32 as ssize_t;
            socksstate(data, CONNECT_AUTH_READ);
            current_block_276 = 5249903830285462583;
        }
        _ => {}
    }
    match current_block_276 {
        5249903830285462583 => {
            result = Curl_read_plain(
                sockfd,
                (*(borrow_mut(&mut sx)).unwrap()).outp as *mut i8,
                (*(borrow_mut(&mut sx)).unwrap()).outstanding as size_t,
                Some(&mut actualread),
            );
            if result as u32 != 0
                && CURLE_AGAIN as i32 as u32 != result as u32
            {
                Curl_failf(
                    data,
                    b"Unable to receive SOCKS5 sub-negotiation response.\0" as *const u8
                        as *const i8,
                );
                return CURLPX_RECV_AUTH;
            } else {
                if result as u64 == 0 && actualread == 0 {
                    Curl_failf(
                        data,
                        b"connection to proxy closed\0" as *const u8
                            as *const i8,
                    );
                    return CURLPX_CLOSED;
                } else {
                    if actualread != (*(borrow(& sx)).unwrap()).outstanding {
                        let mut fresh25 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outstanding);
                        *fresh25 -= actualread;
                        let mut fresh26 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
                        *fresh26 = (*fresh26).offset(actualread as isize);
                        return CURLPX_OK;
                    } else {
                        if *socksreq.offset(1 as i32 as isize) != 0 {
                            Curl_failf(
                                data,
                                b"User was rejected by the SOCKS5 server (%d %d).\0"
                                    as *const u8 as *const i8,
                                *socksreq.offset(0 as i32 as isize) as i32,
                                *socksreq.offset(1 as i32 as isize) as i32,
                            );
                            return CURLPX_USER_REJECTED;
                        }
                    }
                }
            }
            socksstate(data, CONNECT_REQ_INIT);
            current_block_276 = 6765806975593869225;
        }
        _ => {}
    }
    match current_block_276 {
        6765806975593869225 => {
            if socks5_resolve_local {
                let mut rc: i32 = Curl_resolv(
                    data,
                    hostname,
                    remote_port,
                    0 as i32 != 0,
                    Some(&mut dns),
                );
                if rc as i32 == CURLRESOLV_ERROR as i32 {
                    return CURLPX_RESOLVE_HOST;
                }
                if rc as i32 == CURLRESOLV_PENDING as i32 {
                    socksstate(data, CONNECT_RESOLVING);
                    return CURLPX_OK;
                }
                socksstate(data, CONNECT_RESOLVED);
                current_block_276 = 6938158527927677584;
            } else {
                current_block_276 = 4992401317151232712;
            }
        }
        _ => {}
    }
    match current_block_276 {
        4992401317151232712 => {
            len = 0 as i32 as ssize_t;
            let mut fresh36 = len;
            len = len + 1;
            *socksreq.offset(fresh36 as isize) = 5 as i32 as u8;
            let mut fresh37 = len;
            len = len + 1;
            *socksreq.offset(fresh37 as isize) = 1 as i32 as u8;
            let mut fresh38 = len;
            len = len + 1;
            *socksreq.offset(fresh38 as isize) = 0 as i32 as u8;
            if !socks5_resolve_local {
                let mut fresh39 = len;
                len = len + 1;
                *socksreq.offset(fresh39 as isize) = 3 as i32 as u8;
                let mut fresh40 = len;
                len = len + 1;
                *socksreq
                    .offset(
                        fresh40 as isize,
                    ) = hostname_len as i8 as u8;
                memcpy(
                    &mut *socksreq.offset(len as isize) as *mut u8
                        as *mut libc::c_void,
                    hostname as *const libc::c_void,
                    hostname_len,
                );
                len = (len as u64).wrapping_add(hostname_len) as ssize_t
                    as ssize_t;
                Curl_infof(
                    data,
                    b"SOCKS5 connect to %s:%d (remotely resolved)\0" as *const u8
                        as *const i8,
                    hostname,
                    remote_port,
                );
            }
            current_block_276 = 3777403817673069519;
        }
        6938158527927677584 => {
            let mut hp: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
            let mut destlen: u64 = 0;
            if !dns.is_null() {
                hp = (*dns).addr;
            }
            if hp.is_null() {
                Curl_failf(
                    data,
                    b"Failed to resolve \"%s\" for SOCKS5 connect.\0" as *const u8
                        as *const i8,
                    hostname,
                );
                return CURLPX_RESOLVE_HOST;
            }
            Curl_printable_address(
                hp,
                dest.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 256]>() as u64,
            );
            destlen = strlen(dest.as_mut_ptr());
            curl_msnprintf(
                dest.as_mut_ptr().offset(destlen as isize),
                (::std::mem::size_of::<[i8; 256]>() as u64)
                    .wrapping_sub(destlen),
                b":%d\0" as *const u8 as *const i8,
                remote_port,
            );
            len = 0 as i32 as ssize_t;
            let mut fresh29 = len;
            len = len + 1;
            *socksreq.offset(fresh29 as isize) = 5 as i32 as u8;
            let mut fresh30 = len;
            len = len + 1;
            *socksreq.offset(fresh30 as isize) = 1 as i32 as u8;
            let mut fresh31 = len;
            len = len + 1;
            *socksreq.offset(fresh31 as isize) = 0 as i32 as u8;
            if (*hp).ai_family == 2 as i32 {
                let mut i: i32 = 0;
                let mut saddr_in: * mut crate::src::lib::connect::sockaddr_in = (0 as * mut crate::src::lib::connect::sockaddr_in);
                let mut fresh32 = len;
                len = len + 1;
                *socksreq.offset(fresh32 as isize) = 1 as i32 as u8;
                saddr_in = (*hp).ai_addr as *mut libc::c_void as *mut sockaddr_in;
                i = 0 as i32;
                while i < 4 as i32 {
                    let mut fresh33 = len;
                    len = len + 1;
                    *socksreq
                        .offset(
                            fresh33 as isize,
                        ) = *(&mut (*saddr_in).sin_addr.s_addr as *mut in_addr_t
                        as *mut u8)
                        .offset(i as isize);
                    i += 1;
                }
                Curl_infof(
                    data,
                    b"SOCKS5 connect to IPv4 %s (locally resolved)\0" as *const u8
                        as *const i8,
                    dest.as_mut_ptr(),
                );
            } else if (*hp).ai_family == 10 as i32 {
                let mut i_0: i32 = 0;
                let mut saddr_in6: * mut crate::src::lib::connect::sockaddr_in6 = (0 as * mut crate::src::lib::connect::sockaddr_in6);
                let mut fresh34 = len;
                len = len + 1;
                *socksreq.offset(fresh34 as isize) = 4 as i32 as u8;
                saddr_in6 = (*hp).ai_addr as *mut libc::c_void as *mut sockaddr_in6;
                i_0 = 0 as i32;
                while i_0 < 16 as i32 {
                    let mut fresh35 = len;
                    len = len + 1;
                    *socksreq
                        .offset(
                            fresh35 as isize,
                        ) = *(&mut (*saddr_in6).sin6_addr.__in6_u.__u6_addr8
                        as *mut [uint8_t; 16] as *mut u8)
                        .offset(i_0 as isize);
                    i_0 += 1;
                }
                Curl_infof(
                    data,
                    b"SOCKS5 connect to IPv6 %s (locally resolved)\0" as *const u8
                        as *const i8,
                    dest.as_mut_ptr(),
                );
            } else {
                hp = 0 as *mut Curl_addrinfo;
                Curl_failf(
                    data,
                    b"SOCKS5 connection to %s not supported\0" as *const u8
                        as *const i8,
                    dest.as_mut_ptr(),
                );
            }
            Curl_resolv_unlock(data, dns);
            current_block_276 = 3777403817673069519;
        }
        _ => {}
    }
    match current_block_276 {
        3777403817673069519 => {
            let mut fresh41 = len;
            len = len + 1;
            *socksreq
                .offset(
                    fresh41 as isize,
                ) = (remote_port >> 8 as i32 & 0xff as i32)
                as u8;
            let mut fresh42 = len;
            len = len + 1;
            *socksreq
                .offset(
                    fresh42 as isize,
                ) = (remote_port & 0xff as i32) as u8;
            let mut fresh43 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
            *fresh43 = socksreq;
            (*(borrow_mut(&mut sx)).unwrap()).outstanding = len;
            socksstate(data, CONNECT_REQ_SENDING);
            current_block_276 = 1406533880978078420;
        }
        _ => {}
    }
    match current_block_276 {
        1406533880978078420 => {
            result = Curl_write_plain(
                data,
                sockfd,
                (*(borrow_mut(&mut sx)).unwrap()).outp as *mut i8 as *const libc::c_void,
                (*(borrow_mut(&mut sx)).unwrap()).outstanding as size_t,
                Some(&mut written),
            );
            if result as u32 != 0
                && CURLE_AGAIN as i32 as u32 != result as u32
            {
                Curl_failf(
                    data,
                    b"Failed to send SOCKS5 connect request.\0" as *const u8
                        as *const i8,
                );
                return CURLPX_SEND_REQUEST;
            }
            if (*(borrow(& sx)).unwrap()).outstanding != written {
                let mut fresh44 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outstanding);
                *fresh44 -= written;
                let mut fresh45 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
                *fresh45 = (*fresh45).offset(written as isize);
                return CURLPX_OK;
            }
            (*(borrow_mut(&mut sx)).unwrap()).outstanding = 10 as i32 as ssize_t;
            let mut fresh46 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
            *fresh46 = socksreq;
            socksstate(data, CONNECT_REQ_READ);
            current_block_276 = 17002506680330119909;
        }
        _ => {}
    }
    match current_block_276 {
        17002506680330119909 => {
            result = Curl_read_plain(
                sockfd,
                (*(borrow_mut(&mut sx)).unwrap()).outp as *mut i8,
                (*(borrow_mut(&mut sx)).unwrap()).outstanding as size_t,
                Some(&mut actualread),
            );
            if result as u32 != 0
                && CURLE_AGAIN as i32 as u32 != result as u32
            {
                Curl_failf(
                    data,
                    b"Failed to receive SOCKS5 connect request ack.\0" as *const u8
                        as *const i8,
                );
                return CURLPX_RECV_REQACK;
            } else {
                if result as u64 == 0 && actualread == 0 {
                    Curl_failf(
                        data,
                        b"connection to proxy closed\0" as *const u8
                            as *const i8,
                    );
                    return CURLPX_CLOSED;
                } else {
                    if actualread != (*(borrow(& sx)).unwrap()).outstanding {
                        let mut fresh47 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outstanding);
                        *fresh47 -= actualread;
                        let mut fresh48 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
                        *fresh48 = (*fresh48).offset(actualread as isize);
                        return CURLPX_OK;
                    }
                }
            }
            if *socksreq.offset(0 as i32 as isize) as i32
                != 5 as i32
            {
                Curl_failf(
                    data,
                    b"SOCKS5 reply has wrong version, version should be 5.\0"
                        as *const u8 as *const i8,
                );
                return CURLPX_BAD_VERSION;
            } else {
                if *socksreq.offset(1 as i32 as isize) != 0 {
                    let mut rc_0: u32 = CURLPX_REPLY_UNASSIGNED;
                    let mut code: i32 = *socksreq
                        .offset(1 as i32 as isize) as i32;
                    Curl_failf(
                        data,
                        b"Can't complete SOCKS5 connection to %s. (%d)\0" as *const u8
                            as *const i8,
                        hostname,
                        *socksreq.offset(1 as i32 as isize) as i32,
                    );
                    if code < 9 as i32 {
                        static mut lookup: [u32; 9] = [
                            CURLPX_OK,
                            CURLPX_REPLY_GENERAL_SERVER_FAILURE,
                            CURLPX_REPLY_NOT_ALLOWED,
                            CURLPX_REPLY_NETWORK_UNREACHABLE,
                            CURLPX_REPLY_HOST_UNREACHABLE,
                            CURLPX_REPLY_CONNECTION_REFUSED,
                            CURLPX_REPLY_TTL_EXPIRED,
                            CURLPX_REPLY_COMMAND_NOT_SUPPORTED,
                            CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
                        ];
                        rc_0 = lookup[code as usize];
                    }
                    return rc_0;
                }
            }
            if *socksreq.offset(3 as i32 as isize) as i32
                == 3 as i32
            {
                let mut addrlen: i32 = *socksreq
                    .offset(4 as i32 as isize) as i32;
                len = (5 as i32 + addrlen + 2 as i32) as ssize_t;
            } else if *socksreq.offset(3 as i32 as isize) as i32
                    == 4 as i32
                {
                len = (4 as i32 + 16 as i32 + 2 as i32)
                    as ssize_t;
            } else if *socksreq.offset(3 as i32 as isize) as i32
                    == 1 as i32
                {
                len = (4 as i32 + 4 as i32 + 2 as i32)
                    as ssize_t;
            } else {
                Curl_failf(
                    data,
                    b"SOCKS5 reply has wrong address type.\0" as *const u8
                        as *const i8,
                );
                return CURLPX_BAD_ADDRESS_TYPE;
            }
            if len > 10 as i32 as i64 {
                (*(borrow_mut(&mut sx)).unwrap()).outstanding = len - 10 as i32 as i64;
                let mut fresh49 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
                *fresh49 = &mut *socksreq.offset(10 as i32 as isize)
                    as *mut u8;
                socksstate(data, CONNECT_REQ_READ_MORE);
                current_block_276 = 5405868585544072297;
            } else {
                socksstate(data, CONNECT_DONE);
                current_block_276 = 6531417090144833949;
            }
        }
        _ => {}
    }
    match current_block_276 {
        5405868585544072297 => {
            result = Curl_read_plain(
                sockfd,
                (*(borrow_mut(&mut sx)).unwrap()).outp as *mut i8,
                (*(borrow_mut(&mut sx)).unwrap()).outstanding as size_t,
                Some(&mut actualread),
            );
            if result as u32 != 0
                && CURLE_AGAIN as i32 as u32 != result as u32
            {
                Curl_failf(
                    data,
                    b"Failed to receive SOCKS5 connect request ack.\0" as *const u8
                        as *const i8,
                );
                return CURLPX_RECV_ADDRESS;
            } else {
                if result as u64 == 0 && actualread == 0 {
                    Curl_failf(
                        data,
                        b"connection to proxy closed\0" as *const u8
                            as *const i8,
                    );
                    return CURLPX_CLOSED;
                } else {
                    if actualread != (*(borrow(& sx)).unwrap()).outstanding {
                        let mut fresh50 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outstanding);
                        *fresh50 -= actualread;
                        let mut fresh51 = &mut ((*(borrow_mut(&mut sx)).unwrap()).outp);
                        *fresh51 = (*fresh51).offset(actualread as isize);
                        return CURLPX_OK;
                    }
                }
            }
            socksstate(data, CONNECT_DONE);
        }
        _ => {}
    }
    Curl_infof(data, b"SOCKS5 request granted.\0" as *const u8 as *const i8);
    *(borrow_mut(&mut done)).unwrap() = 1 as i32 != 0;
    return CURLPX_OK;
}
use crate::laertes_rt::*;
