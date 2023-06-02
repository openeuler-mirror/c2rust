
use :: libc;
extern "C" {
    fn bind(__fd: i32, __addr: *const crate::src::lib::http2::sockaddr, __len: u32) -> i32;
    fn sendto(
        __fd: i32,
        __buf: *const core::ffi::c_void,
        __n: u64,
        __flags: i32,
        __addr: *const crate::src::lib::http2::sockaddr,
        __addr_len: u32,
    ) -> i64;
    fn recvfrom(
        __fd: i32,
        __buf: *mut core::ffi::c_void,
        __n: u64,
        __flags: i32,
        __addr: *mut crate::src::lib::http2::sockaddr,
        __addr_len: *mut u32,
    ) -> i64;
    fn time(__timer: *mut i64) -> i64;
    fn strtol(_: *const i8, _: *mut *mut i8, _: i32) -> i64;
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn memchr(_: *const core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strstr(_: *const i8, _: *const i8) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn __errno_location() -> *mut i32;
}
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::connect::Curl_conncontrol;
pub use crate::src::lib::connect::Curl_timeleft;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::easy::Curl_ccalloc;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::escape::Curl_urldecode;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::progress::Curl_pgrsDone;
pub use crate::src::lib::progress::Curl_pgrsSetDownloadCounter;
pub use crate::src::lib::progress::Curl_pgrsSetDownloadSize;
pub use crate::src::lib::progress::Curl_pgrsSetUploadCounter;
pub use crate::src::lib::progress::Curl_pgrsSetUploadSize;
pub use crate::src::lib::progress::Curl_pgrsStartNow;
pub use crate::src::lib::progress::Curl_pgrsUpdate;
pub use crate::src::lib::select::Curl_socket_check;
pub use crate::src::lib::sendf::Curl_client_write;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::speedcheck::Curl_speedcheck;
pub use crate::src::lib::strcase::curl_strnequal;
pub use crate::src::lib::strcase::Curl_raw_toupper;
pub use crate::src::lib::strerror::Curl_strerror;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::timeval::Curl_now;
pub use crate::src::lib::transfer::Curl_fillreadbuffer;
pub use crate::src::lib::transfer::Curl_setup_transfer;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
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
pub type sockaddr = crate::src::lib::http2::sockaddr;
pub type sockaddr_storage = crate::src::lib::connect::sockaddr_storage;
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
pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::lib::http2::_IO_FILE;
pub type Curl_easy = crate::src::lib::http2::Curl_easy;
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
pub type curl_certinfo = crate::src::lib::http2::curl_certinfo;
pub type curl_slist = crate::src::lib::http2::curl_slist;
pub type WildcardData = crate::src::lib::http2::WildcardData;
pub type wildcard_dtor<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>) -> ()>;
pub type Curl_llist = crate::src::lib::http2::Curl_llist;
pub type Curl_llist_dtor<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: Option<&'a2 mut core::ffi::c_void>,
    ) -> (),
>;
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
pub type UrlState = crate::src::lib::http2::UrlState;
pub type dynamically_allocated_data = crate::src::lib::http2::dynamically_allocated_data;
pub type trailers_state = u32;
pub const TRAILERS_DONE: trailers_state = 3;
pub const TRAILERS_SENDING: trailers_state = 2;
pub const TRAILERS_INITIALIZED: trailers_state = 1;
pub const TRAILERS_NONE: trailers_state = 0;
pub type dynbuf = crate::src::lib::http2::dynbuf;
pub type Curl_HttpReq = u32;
pub const HTTPREQ_HEAD: Curl_HttpReq = 5;
pub const HTTPREQ_PUT: Curl_HttpReq = 4;
pub const HTTPREQ_POST_MIME: Curl_HttpReq = 3;
pub const HTTPREQ_POST_FORM: Curl_HttpReq = 2;
pub const HTTPREQ_POST: Curl_HttpReq = 1;
pub const HTTPREQ_GET: Curl_HttpReq = 0;
pub type urlpieces = crate::src::lib::http2::urlpieces;
pub type CURLU = crate::src::lib::urlapi::Curl_URL;
pub type curl_read_callback<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut i8>,
        _: u64,
        _: u64,
        _: Option<&'a2 mut core::ffi::c_void>,
    ) -> u64,
>;
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
pub type curltime = crate::src::lib::http2::curltime;
pub type Curl_tree = crate::src::lib::http2::Curl_tree;
pub type Curl_async = crate::src::lib::http2::Curl_async;
pub type Curl_dns_entry = crate::src::lib::http2::Curl_dns_entry;
pub type Curl_addrinfo = crate::src::lib::http2::Curl_addrinfo;
pub type auth = crate::src::lib::http2::auth;
pub type digestdata = crate::src::lib::http2::digestdata;
pub type tempbuf = crate::src::lib::http2::tempbuf;
pub type Curl_ssl_session = crate::src::lib::http2::Curl_ssl_session;
pub type ssl_primary_config = crate::src::lib::http2::ssl_primary_config;
pub type curl_blob = crate::src::lib::http2::curl_blob;
pub type conncache = crate::src::lib::http2::conncache;
pub type Curl_hash = crate::src::lib::http2::Curl_hash;
pub type Curl_hash_dtor<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>) -> ()>;
pub type comp_function<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: u64,
        _: Option<&'a2 mut core::ffi::c_void>,
        _: u64,
    ) -> u64,
>;
pub type hash_function<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>, _: u64, _: u64) -> u64>;
pub type Progress = crate::src::lib::http2::Progress;
pub type timediff_t = i64;
pub type CookieInfo = crate::src::lib::http2::CookieInfo;
pub type Cookie = crate::src::lib::http2::Cookie;
pub type UserDefined = crate::src::lib::http2::UserDefined;
pub type curl_trailer_callback<'a1, 'a2, 'a3> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut Option<&'a2 mut crate::src::lib::http2::curl_slist>>,
        _: Option<&'a3 mut core::ffi::c_void>,
    ) -> i32,
>;
pub type multidone_func<'a1> = Option<
    unsafe extern "C" fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>, _: u32) -> i32,
>;
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
pub type curl_resolver_start_callback<'a1, 'a2, 'a3> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: Option<&'a2 mut core::ffi::c_void>,
        _: Option<&'a3 mut core::ffi::c_void>,
    ) -> i32,
>;
pub type Curl_http2_dep = crate::src::lib::http2::Curl_http2_dep;
pub type curl_fnmatch_callback<'a1, 'a2, 'a3> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: Option<&'a2 i8>,
        _: Option<&'a3 i8>,
    ) -> i32,
>;
pub type curl_chunk_end_callback<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>) -> i64>;
pub type curl_chunk_bgn_callback<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 core::ffi::c_void>,
        _: Option<&'a2 mut core::ffi::c_void>,
        _: i32,
    ) -> i64,
>;
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
pub type curl_sshkeycallback<'a1, 'a2, 'a3, 'a4> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: Option<&'a2 crate::src::lib::http2::curl_khkey>,
        _: Option<&'a3 crate::src::lib::http2::curl_khkey>,
        _: u32,
        _: Option<&'a4 mut core::ffi::c_void>,
    ) -> i32,
>;
pub type curl_khmatch = u32;
pub const CURLKHMATCH_LAST: curl_khmatch = 3;
pub const CURLKHMATCH_MISSING: curl_khmatch = 2;
pub const CURLKHMATCH_MISMATCH: curl_khmatch = 1;
pub const CURLKHMATCH_OK: curl_khmatch = 0;
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
pub type ssl_general_config = crate::src::lib::http2::ssl_general_config;
pub type ssl_config_data = crate::src::lib::http2::ssl_config_data;
pub type CURL_TLSAUTH = u32;
pub const CURL_TLSAUTH_LAST: CURL_TLSAUTH = 2;
pub const CURL_TLSAUTH_SRP: CURL_TLSAUTH = 1;
pub const CURL_TLSAUTH_NONE: CURL_TLSAUTH = 0;
pub type curl_ssl_ctx_callback<'a1, 'a2, 'a3> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: Option<&'a2 mut core::ffi::c_void>,
        _: Option<&'a3 mut core::ffi::c_void>,
    ) -> u32,
>;
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
pub type curl_mimepart = crate::src::lib::http2::curl_mimepart;
pub type mime_encoder_state = crate::src::lib::http2::mime_encoder_state;
pub type mime_encoder = crate::src::lib::http2::mime_encoder;
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
pub type curl_free_callback<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>) -> ()>;
pub type curl_seek_callback<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>, _: i64, _: i32) -> i32>;
pub type mimekind = u32;
pub const MIMEKIND_LAST: mimekind = 5;
pub const MIMEKIND_MULTIPART: mimekind = 4;
pub const MIMEKIND_CALLBACK: mimekind = 3;
pub const MIMEKIND_FILE: mimekind = 2;
pub const MIMEKIND_DATA: mimekind = 1;
pub const MIMEKIND_NONE: mimekind = 0;
pub type curl_mime = crate::src::lib::http2::curl_mime;
pub type curl_httppost = crate::src::lib::http2::curl_httppost;
pub type curl_hstswrite_callback<'a1, 'a2, 'a3, 'a4> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: Option<&'a2 mut crate::src::lib::http2::curl_hstsentry>,
        _: Option<&'a3 mut crate::src::lib::http2::curl_index>,
        _: Option<&'a4 mut core::ffi::c_void>,
    ) -> u32,
>;
pub type curl_index = crate::src::lib::http2::curl_index;
pub type curl_hstsentry = crate::src::lib::http2::curl_hstsentry;
pub type CURLSTScode = u32;
pub const CURLSTS_FAIL: CURLSTScode = 2;
pub const CURLSTS_DONE: CURLSTScode = 1;
pub const CURLSTS_OK: CURLSTScode = 0;
pub type curl_hstsread_callback<'a1, 'a2, 'a3> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: Option<&'a2 mut crate::src::lib::http2::curl_hstsentry>,
        _: Option<&'a3 mut core::ffi::c_void>,
    ) -> u32,
>;
pub type curl_conv_callback<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut i8>, _: u64) -> u32>;
pub type curl_closesocket_callback<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>, _: i32) -> i32>;
pub type curl_socket_t = i32;
pub type curl_opensocket_callback<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: u32,
        _: Option<&'a2 mut crate::src::lib::http2::curl_sockaddr>,
    ) -> i32,
>;
pub type curl_sockaddr = crate::src::lib::http2::curl_sockaddr;
pub type curlsocktype = u32;
pub const CURLSOCKTYPE_LAST: curlsocktype = 2;
pub const CURLSOCKTYPE_ACCEPT: curlsocktype = 1;
pub const CURLSOCKTYPE_IPCXN: curlsocktype = 0;
pub type curl_sockopt_callback<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>, _: i32, _: u32) -> i32>;
pub type curl_ioctl_callback<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: i32,
        _: Option<&'a2 mut core::ffi::c_void>,
    ) -> u32,
>;
pub type curlioerr = u32;
pub const CURLIOE_LAST: curlioerr = 3;
pub const CURLIOE_FAILRESTART: curlioerr = 2;
pub const CURLIOE_UNKNOWNCMD: curlioerr = 1;
pub const CURLIOE_OK: curlioerr = 0;
pub type curl_debug_callback<'a1, 'a2, 'a3> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: u32,
        _: Option<&'a2 mut i8>,
        _: u64,
        _: Option<&'a3 mut core::ffi::c_void>,
    ) -> i32,
>;
pub type curl_infotype = u32;
pub const CURLINFO_END: curl_infotype = 7;
pub const CURLINFO_SSL_DATA_OUT: curl_infotype = 6;
pub const CURLINFO_SSL_DATA_IN: curl_infotype = 5;
pub const CURLINFO_DATA_OUT: curl_infotype = 4;
pub const CURLINFO_DATA_IN: curl_infotype = 3;
pub const CURLINFO_HEADER_OUT: curl_infotype = 2;
pub const CURLINFO_HEADER_IN: curl_infotype = 1;
pub const CURLINFO_TEXT: curl_infotype = 0;
pub type curl_xferinfo_callback<'a1> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: i64,
        _: i64,
        _: i64,
        _: i64,
    ) -> i32,
>;
pub type curl_progress_callback<'a1> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: f64,
        _: f64,
        _: f64,
        _: f64,
    ) -> i32,
>;
pub type curl_write_callback<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut i8>,
        _: u64,
        _: u64,
        _: Option<&'a2 mut core::ffi::c_void>,
    ) -> u64,
>;
pub type SingleRequest = crate::src::lib::http2::SingleRequest;
pub type dohdata = crate::src::lib::http2::dohdata;
pub type dnsprobe = crate::src::lib::http2::dnsprobe;
pub type C2RustUnnamed_0 = crate::src::lib::http2::C2RustUnnamed;
pub type SSHPROTO = crate::src::lib::http2::SSHPROTO;
pub type SMTP = crate::src::lib::http2::SMTP;
pub type curl_pp_transfer = u32;
pub const PPTRANSFER_NONE: curl_pp_transfer = 2;
pub const PPTRANSFER_INFO: curl_pp_transfer = 1;
pub const PPTRANSFER_BODY: curl_pp_transfer = 0;
pub type RTSP = crate::src::lib::http2::RTSP;
pub type HTTP = crate::src::lib::http2::HTTP;
pub type uint8_t = u8;
pub type uint32_t = u32;
pub type C2RustUnnamed_1 = u32;
pub const HTTPSEND_BODY: C2RustUnnamed_1 = 2;
pub const HTTPSEND_REQUEST: C2RustUnnamed_1 = 1;
pub const HTTPSEND_NADA: C2RustUnnamed_1 = 0;
pub type back = crate::src::lib::http2::back;
pub type POP3 = crate::src::lib::http2::POP3;
pub type MQTT = crate::src::lib::http2::MQTT;
pub type IMAP = crate::src::lib::http2::IMAP;
pub type FTP = crate::src::lib::http2::FTP;
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
pub type PslCache = crate::src::lib::http2::PslCache;
pub type psl_ctx_t = crate::src::lib::urlapi::psl_ctx_st;
pub type Curl_multi = crate::src::lib::http2::Curl_multi;
pub type curl_multi_timer_callback<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_multi>,
        _: i64,
        _: Option<&'a2 mut core::ffi::c_void>,
    ) -> i32,
>;
pub type CURLM = crate::src::lib::http2::Curl_multi;
pub type curl_push_callback<'a1, 'a2, 'a3, 'a4> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: Option<&'a2 mut crate::src::lib::http2::Curl_easy>,
        _: u64,
        _: Option<&'a3 mut crate::src::lib::http2::curl_pushheaders>,
        _: Option<&'a4 mut core::ffi::c_void>,
    ) -> i32,
>;
pub type curl_socket_callback<'a1, 'a2, 'a3> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: i32,
        _: i32,
        _: Option<&'a2 mut core::ffi::c_void>,
        _: Option<&'a3 mut core::ffi::c_void>,
    ) -> i32,
>;
pub type Names = crate::src::lib::http2::Names;
pub type C2RustUnnamed_3 = u32;
pub const HCACHE_SHARED: C2RustUnnamed_3 = 2;
pub const HCACHE_MULTI: C2RustUnnamed_3 = 1;
pub const HCACHE_NONE: C2RustUnnamed_3 = 0;
pub type Curl_message = crate::src::lib::http2::Curl_message;
pub type CURLMsg = crate::src::lib::http2::CURLMsg;
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
pub type connectdata = crate::src::lib::http2::connectdata;
pub type connectbundle = crate::src::lib::http2::connectbundle;
pub type C2RustUnnamed_5 = crate::src::lib::http2::C2RustUnnamed_4;
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
pub type smb_conn = crate::src::lib::http2::smb_conn;
pub type smb_conn_state = u32;
pub const SMB_CONNECTED: smb_conn_state = 4;
pub const SMB_SETUP: smb_conn_state = 3;
pub const SMB_NEGOTIATE: smb_conn_state = 2;
pub const SMB_CONNECTING: smb_conn_state = 1;
pub const SMB_NOT_CONNECTED: smb_conn_state = 0;
pub type rtsp_conn = crate::src::lib::http2::rtsp_conn;
pub type smtp_conn = crate::src::lib::http2::smtp_conn;
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
pub type pingpong = crate::src::lib::http2::pingpong;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tftp_state_data {
    pub state: u32,
    pub mode: u32,
    pub error: i32,
    pub event: i32,
    pub data: *mut crate::src::lib::http2::Curl_easy,
    pub sockfd: i32,
    pub retries: i32,
    pub retry_time: i32,
    pub retry_max: i32,
    pub rx_time: i64,
    pub local_addr: crate::src::lib::connect::Curl_sockaddr_storage,
    pub remote_addr: crate::src::lib::connect::Curl_sockaddr_storage,
    pub remote_addrlen: u32,
    pub rbytes: i32,
    pub sbytes: i32,
    pub blksize: i32,
    pub requested_blksize: i32,
    pub block: u16,
    pub rpacket: crate::src::lib::tftp::tftp_packet,
    pub spacket: crate::src::lib::tftp::tftp_packet,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tftp_packet {
    pub data: *mut u8,
}
impl tftp_packet {
    pub const fn new() -> Self {
        tftp_packet {
            data: (0 as *mut u8),
        }
    }
}
impl std::default::Default for tftp_packet {
    fn default() -> Self {
        tftp_packet::new()
    }
}
pub type Curl_sockaddr_storage = crate::src::lib::connect::Curl_sockaddr_storage;
pub type C2RustUnnamed_6 = crate::src::lib::connect::C2RustUnnamed_9;
pub type sockaddr_in6 = crate::src::lib::connect::sockaddr_in6;
pub type in6_addr = crate::src::lib::connect::in6_addr;
pub type C2RustUnnamed_7 = crate::src::lib::connect::C2RustUnnamed_8;
pub type uint16_t = u16;
pub type in_port_t = u16;
pub type sockaddr_in = crate::src::lib::connect::sockaddr_in;
pub type in_addr = crate::src::lib::connect::in_addr;
pub type in_addr_t = u32;
pub type tftp_event_t = i32;
pub const TFTP_EVENT_TIMEOUT: tftp_event_t = 7;
pub const TFTP_EVENT_OACK: tftp_event_t = 6;
pub const TFTP_EVENT_ERROR: tftp_event_t = 5;
pub const TFTP_EVENT_ACK: tftp_event_t = 4;
pub const TFTP_EVENT_DATA: tftp_event_t = 3;
pub const TFTP_EVENT_WRQ: tftp_event_t = 2;
pub const TFTP_EVENT_RRQ: tftp_event_t = 1;
pub const TFTP_EVENT_INIT: tftp_event_t = 0;
pub const TFTP_EVENT_NONE: tftp_event_t = -1;
pub type tftp_error_t = i32;
pub const TFTP_ERR_NORESPONSE: tftp_error_t = -98;
pub const TFTP_ERR_TIMEOUT: tftp_error_t = -99;
pub const TFTP_ERR_NONE: tftp_error_t = -100;
pub const TFTP_ERR_NOSUCHUSER: tftp_error_t = 7;
pub const TFTP_ERR_EXISTS: tftp_error_t = 6;
pub const TFTP_ERR_UNKNOWNID: tftp_error_t = 5;
pub const TFTP_ERR_ILLEGAL: tftp_error_t = 4;
pub const TFTP_ERR_DISKFULL: tftp_error_t = 3;
pub const TFTP_ERR_PERM: tftp_error_t = 2;
pub const TFTP_ERR_NOTFOUND: tftp_error_t = 1;
pub const TFTP_ERR_UNDEF: tftp_error_t = 0;
pub type tftp_mode_t = u32;
pub const TFTP_MODE_OCTET: tftp_mode_t = 1;
pub const TFTP_MODE_NETASCII: tftp_mode_t = 0;
pub type tftp_state_t = u32;
pub const TFTP_STATE_FIN: tftp_state_t = 3;
pub const TFTP_STATE_TX: tftp_state_t = 2;
pub const TFTP_STATE_RX: tftp_state_t = 1;
pub const TFTP_STATE_START: tftp_state_t = 0;
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
pub type http_conn = crate::src::lib::http2::http_conn;
pub type nghttp2_settings_entry = crate::src::lib::http2::nghttp2_settings_entry;
pub type h2settings = crate::src::lib::http2::h2settings;
pub type Curl_recv<'a1, 'a2, 'a3> = unsafe extern "C" fn(
    _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
    _: i32,
    _: Option<&'a2 mut i8>,
    _: u64,
    _: Option<&'a3 mut u32>,
) -> i64;
pub type Curl_send<'a1, 'a2, 'a3> = unsafe extern "C" fn(
    _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
    _: i32,
    _: Option<&'a2 core::ffi::c_void>,
    _: u64,
    _: Option<&'a3 mut u32>,
) -> i64;
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
pub type ntlmdata = crate::src::lib::http2::ntlmdata;
pub type curlntlm = u32;
pub const NTLMSTATE_LAST: curlntlm = 4;
pub const NTLMSTATE_TYPE3: curlntlm = 3;
pub const NTLMSTATE_TYPE2: curlntlm = 2;
pub const NTLMSTATE_TYPE1: curlntlm = 1;
pub const NTLMSTATE_NONE: curlntlm = 0;
pub type gsasldata = crate::src::lib::http2::gsasldata;
pub type Curl_handler = crate::src::lib::http2::Curl_handler;
pub type ConnectBits = crate::src::lib::http2::ConnectBits;
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
pub type proxy_info = crate::src::lib::http2::proxy_info;
pub type hostname = crate::src::lib::http2::hostname;
pub type C2RustUnnamed_8 = u32;
pub const TRNSPRT_QUIC: C2RustUnnamed_8 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_8 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_8 = 3;
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
pub type curl_calloc_callback<'a1> =
    Option<unsafe extern "C" fn(_: u64, _: u64) -> Option<&'a1 mut core::ffi::c_void>>;
pub type urlreject = u32;
pub const REJECT_ZERO: urlreject = 4;
pub const REJECT_CTRL: urlreject = 3;
pub const REJECT_NADA: urlreject = 2;
#[no_mangle]
pub static mut Curl_handler_tftp: crate::src::lib::http2::Curl_handler =  {
    {
        let mut init = Curl_handler {
            scheme: b"TFTP\0" as *const u8 as *const i8,
            setup_connection: Some(tftp_setup_connection),
            do_it: Some(tftp_do),
            done: Some(tftp_done),
            do_more: None,
            connect_it: Some(tftp_connect),
            connecting: Some(tftp_multi_statemach),
            doing: Some(tftp_doing),
            proto_getsock: Some(tftp_getsock),
            doing_getsock: Some(tftp_getsock),
            domore_getsock: None,
            perform_getsock: None,
            disconnect: Some(tftp_disconnect),
            readwrite: None,
            connection_check: None,
            attach: None,
            defport: 69 as i32,
            protocol: ((1 as i32) << 11 as i32) as u32,
            family: ((1 as i32) << 11 as i32) as u32,
            flags: (0 as i32 | (1 as i32) << 6 as i32) as u32,
        };
        init
    }
};
extern "C" fn tftp_set_timeouts(mut state: *mut crate::src::lib::tftp::tftp_state_data) -> u32 {
    let mut maxtime: i64 = 0;
    let mut timeout: i64 = 0;
    let mut timeout_ms: i64 = 0;
    let mut start: bool = if (unsafe { (*state).state }) as u32 == TFTP_STATE_START as i32 as u32 {
        1 as i32
    } else {
        0 as i32
    } != 0;
    timeout_ms = Curl_timeleft(
        unsafe { (*state).data },
        0 as *mut crate::src::lib::http2::curltime,
        start,
    );
    if timeout_ms < 0 as i32 as i64 {
        (unsafe { Curl_failf(
            (*state).data,
            b"Connection time-out\0" as *const u8 as *const i8,
        ) });
        return CURLE_OPERATION_TIMEDOUT;
    }
    if timeout_ms > 0 as i32 as i64 {
        maxtime = (timeout_ms + 500 as i32 as i64) / 1000 as i32 as i64;
    } else {
        maxtime = 3600 as i32 as time_t;
    }
    timeout = maxtime;
    (unsafe { (*state).retry_max = timeout as i32 / 5 as i32 });
    if (unsafe { (*state).retry_max }) < 3 as i32 {
        (unsafe { (*state).retry_max = 3 as i32 });
    }
    if (unsafe { (*state).retry_max }) > 50 as i32 {
        (unsafe { (*state).retry_max = 50 as i32 });
    }
    (unsafe { (*state).retry_time = (timeout / (*state).retry_max as i64) as i32 });
    if (unsafe { (*state).retry_time }) < 1 as i32 {
        (unsafe { (*state).retry_time = 1 as i32 });
    }
    (unsafe { Curl_infof(
        (*state).data,
        b"set timeouts for state %d; Total % ld, retry %d maxtry %d\0" as *const u8 as *const i8,
        (*state).state as i32,
        timeout_ms,
        (*state).retry_time,
        (*state).retry_max,
    ) });
    (unsafe { time(&mut (*state).rx_time) });
    return CURLE_OK;
}
extern "C" fn setpacketevent<'a1>(
    mut packet: Option<&'a1 mut crate::src::lib::tftp::tftp_packet>,
    mut num: u16,
) {
    (unsafe { *((*(borrow(&packet)).unwrap()).data).offset(0 as i32 as isize) =
        (num as i32 >> 8 as i32) as u8 });
    (unsafe { *((*(borrow(&packet)).unwrap()).data).offset(1 as i32 as isize) =
        (num as i32 & 0xff as i32) as u8 });
}
extern "C" fn setpacketblock<'a1>(
    mut packet: Option<&'a1 mut crate::src::lib::tftp::tftp_packet>,
    mut num: u16,
) {
    (unsafe { *((*(borrow(&packet)).unwrap()).data).offset(2 as i32 as isize) =
        (num as i32 >> 8 as i32) as u8 });
    (unsafe { *((*(borrow(&packet)).unwrap()).data).offset(3 as i32 as isize) =
        (num as i32 & 0xff as i32) as u8 });
}
extern "C" fn getrpacketevent<'a1>(
    mut packet: Option<&'a1 crate::src::lib::tftp::tftp_packet>,
) -> u16 {
    return (((unsafe { *((*((packet).clone()).unwrap()).data).offset(0 as i32 as isize) }) as i32) << 8 as i32
        | (unsafe { *((*((packet).clone()).unwrap()).data).offset(1 as i32 as isize) }) as i32)
        as u16;
}
extern "C" fn getrpacketblock<'a1>(
    mut packet: Option<&'a1 crate::src::lib::tftp::tftp_packet>,
) -> u16 {
    return (((unsafe { *((*((packet).clone()).unwrap()).data).offset(2 as i32 as isize) }) as i32) << 8 as i32
        | (unsafe { *((*((packet).clone()).unwrap()).data).offset(3 as i32 as isize) }) as i32)
        as u16;
}
extern "C" fn tftp_strnlen(mut string: *const i8, mut maxlen: u64) -> u64 {
    let mut end: *const i8 =
        (unsafe { memchr(string as *const libc::c_void, '\u{0}' as i32, maxlen) }) as *const i8;
    return if !end.is_null() {
        (unsafe { end.offset_from(string) }) as i64 as size_t
    } else {
        maxlen
    };
}
extern "C" fn tftp_option_get<'a1, 'a2>(
    mut buf: *const i8,
    mut len: u64,
    mut option: Option<&'a1 mut *const i8>,
    mut value: Option<&'a2 mut *const i8>,
) -> *const i8 {
    let mut loc: u64 = 0;
    loc = tftp_strnlen(buf, len);
    loc = loc.wrapping_add(1);
    if loc >= len {
        return 0 as *const i8;
    }
    *(borrow_mut(&mut option)).unwrap() = buf;
    loc = (loc as u64).wrapping_add(tftp_strnlen(
        unsafe { buf.offset(loc as isize) },
        len.wrapping_sub(loc),
    )) as size_t as size_t;
    loc = loc.wrapping_add(1);
    if loc > len {
        return 0 as *const i8;
    }
    *(borrow_mut(&mut value)).unwrap() = (unsafe { &*buf
        .offset(((strlen)(*(borrow(&option)).unwrap())).wrapping_add(1 as i32 as u64) as isize) })
        as *const i8;
    return (unsafe { &*buf.offset(loc as isize) }) as *const i8;
}
extern "C" fn tftp_parse_option_ack(
    mut state: *mut crate::src::lib::tftp::tftp_state_data,
    mut ptr: *const i8,
    mut len: i32,
) -> u32 {
    let mut tmp: *const i8 = ptr;
    let mut data: *mut crate::src::lib::http2::Curl_easy = unsafe { (*state).data };
    (unsafe { (*state).blksize = 512 as i32 });
    while tmp < (unsafe { ptr.offset(len as isize) }) {
        let mut option: *const i8 = 0 as *const i8;
        let mut value: *const i8 = 0 as *const i8;
        tmp = tftp_option_get(
            tmp,
            (unsafe { ptr.offset(len as isize).offset_from(tmp) }) as i64 as size_t,
            Some(&mut option),
            Some(&mut value),
        );
        if tmp.is_null() {
            (unsafe { Curl_failf(
                data,
                b"Malformed ACK packet, rejecting\0" as *const u8 as *const i8,
            ) });
            return CURLE_TFTP_ILLEGAL;
        }
        (unsafe { Curl_infof(
            data,
            b"got option=(%s) value=(%s)\0" as *const u8 as *const i8,
            option,
            value,
        ) });
        if curl_strnequal(
            option,
            b"blksize\0" as *const u8 as *const i8,
            unsafe { strlen(option) },
        ) != 0
        {
            let mut blksize: i64 = 0;
            blksize = unsafe { strtol(value, 0 as *mut *mut i8, 10 as i32) };
            if blksize == 0 {
                (unsafe { Curl_failf(
                    data,
                    b"invalid blocksize value in OACK packet\0" as *const u8 as *const i8,
                ) });
                return CURLE_TFTP_ILLEGAL;
            }
            if blksize > 65464 as i32 as i64 {
                (unsafe { Curl_failf(
                    data,
                    b"%s (%d)\0" as *const u8 as *const i8,
                    b"blksize is larger than max supported\0" as *const u8 as *const i8,
                    65464 as i32,
                ) });
                return CURLE_TFTP_ILLEGAL;
            } else {
                if blksize < 8 as i32 as i64 {
                    (unsafe { Curl_failf(
                        data,
                        b"%s (%d)\0" as *const u8 as *const i8,
                        b"blksize is smaller than min supported\0" as *const u8 as *const i8,
                        8 as i32,
                    ) });
                    return CURLE_TFTP_ILLEGAL;
                } else {
                    if blksize > (unsafe { (*state).requested_blksize }) as i64 {
                        (unsafe { Curl_failf(
                            data,
                            b"%s (%ld)\0" as *const u8 as *const i8,
                            b"server requested blksize larger than allocated\0" as *const u8
                                as *const i8,
                            blksize,
                        ) });
                        return CURLE_TFTP_ILLEGAL;
                    }
                }
            }
            (unsafe { (*state).blksize = blksize as i32 });
            (unsafe { Curl_infof(
                data,
                b"%s (%d) %s (%d)\0" as *const u8 as *const i8,
                b"blksize parsed from OACK\0" as *const u8 as *const i8,
                (*state).blksize,
                b"requested\0" as *const u8 as *const i8,
                (*state).requested_blksize,
            ) });
        } else if curl_strnequal(option, b"tsize\0" as *const u8 as *const i8, unsafe { strlen(option) }) != 0
        {
            let mut tsize: i64 = 0 as i32 as i64;
            tsize = unsafe { strtol(value, 0 as *mut *mut i8, 10 as i32) };
            (unsafe { Curl_infof(
                data,
                b"%s (%ld)\0" as *const u8 as *const i8,
                b"tsize parsed from OACK\0" as *const u8 as *const i8,
                tsize,
            ) });
            if (unsafe { ((*data).set).upload() }) == 0 {
                if tsize == 0 {
                    (unsafe { Curl_failf(
                        data,
                        b"invalid tsize -:%s:- value in OACK packet\0" as *const u8 as *const i8,
                        value,
                    ) });
                    return CURLE_TFTP_ILLEGAL;
                }
                Curl_pgrsSetDownloadSize(data, tsize);
            }
        }
    }
    return CURLE_OK;
}
extern "C" fn tftp_option_add(
    mut state: *mut crate::src::lib::tftp::tftp_state_data,
    mut csize: *mut u64,
    mut buf: *mut i8,
    mut option: *const i8,
) -> u32 {
    if (unsafe { strlen(option) })
        .wrapping_add(unsafe { *csize })
        .wrapping_add(1 as i32 as u64)
        > (unsafe { (*state).blksize }) as size_t
    {
        return CURLE_TFTP_ILLEGAL;
    }
    (unsafe { strcpy(buf, option) });
    (unsafe { *csize = (*csize as u64).wrapping_add((strlen(option)).wrapping_add(1 as i32 as u64)) as size_t
        as size_t });
    return CURLE_OK;
}
extern "C" fn tftp_connect_for_tx(
    mut state: *mut crate::src::lib::tftp::tftp_state_data,
    mut event: i32,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut data: *mut crate::src::lib::http2::Curl_easy = unsafe { (*state).data };
    (unsafe { Curl_infof(
        data,
        b"%s\0" as *const u8 as *const i8,
        b"Connected for transmit\0" as *const u8 as *const i8,
    ) });
    (unsafe { (*state).state = TFTP_STATE_TX });
    result = tftp_set_timeouts(state);
    if result as u64 != 0 {
        return result;
    }
    return tftp_tx(state, event);
}
extern "C" fn tftp_connect_for_rx(
    mut state: *mut crate::src::lib::tftp::tftp_state_data,
    mut event: i32,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut data: *mut crate::src::lib::http2::Curl_easy = unsafe { (*state).data };
    (unsafe { Curl_infof(
        data,
        b"%s\0" as *const u8 as *const i8,
        b"Connected for receive\0" as *const u8 as *const i8,
    ) });
    (unsafe { (*state).state = TFTP_STATE_RX });
    result = tftp_set_timeouts(state);
    if result as u64 != 0 {
        return result;
    }
    return tftp_rx(state, event);
}
extern "C" fn tftp_send_first(
    mut state: *mut crate::src::lib::tftp::tftp_state_data,
    mut event: i32,
) -> u32 {
    let mut sbytes: u64 = 0;
    let mut senddata: i64 = 0;
    let mut mode: *const i8 = b"octet\0" as *const u8 as *const i8;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut data: *mut crate::src::lib::http2::Curl_easy = unsafe { (*state).data };
    let mut result: u32 = CURLE_OK;
    if (unsafe { ((*data).state).prefer_ascii() }) != 0 {
        mode = b"netascii\0" as *const u8 as *const i8;
    }
    match event as i32 {
        0 | 7 => {
            let mut fresh0 = unsafe { &mut ((*state).retries) };
            *fresh0 += 1;
            if (unsafe { (*state).retries }) > (unsafe { (*state).retry_max }) {
                (unsafe { (*state).error = TFTP_ERR_NORESPONSE });
                (unsafe { (*state).state = TFTP_STATE_FIN });
                return result;
            }
            if (unsafe { ((*data).set).upload() }) != 0 {
                setpacketevent(Some(unsafe { &mut (*state).spacket }), TFTP_EVENT_WRQ as i32 as u16);
                let mut fresh1 = unsafe { &mut ((*(*state).data).req.upload_fromhere) };
                *fresh1 = unsafe { ((*state).spacket.data as *mut i8).offset(4 as i32 as isize) };
                if (unsafe { (*data).state.infilesize }) != -(1 as i32) as i64 {
                    Curl_pgrsSetUploadSize(data, unsafe { (*data).state.infilesize });
                }
            } else {
                setpacketevent(Some(unsafe { &mut (*state).spacket }), TFTP_EVENT_RRQ as i32 as u16);
            }
            result = Curl_urldecode(
                data,
                unsafe { &mut *((*(*state).data).state.up.path).offset(1 as i32 as isize) },
                0 as i32 as size_t,
                Some(&mut filename),
                Option::<&'_ mut u64>::None,
                REJECT_ZERO,
            );
            if result as u64 != 0 {
                return result;
            }
            if (unsafe { strlen(filename) })
                > ((unsafe { (*state).blksize }) as u64)
                    .wrapping_sub(unsafe { strlen(mode) })
                    .wrapping_sub(4 as i32 as u64)
            {
                (unsafe { Curl_failf(data, b"TFTP file name too long\0" as *const u8 as *const i8) });
                (unsafe { Curl_cfree.expect("non-null function pointer")(filename as *mut libc::c_void) });
                return CURLE_TFTP_ILLEGAL;
            }
            (unsafe { curl_msnprintf(
                ((*state).spacket.data as *mut i8).offset(2 as i32 as isize),
                (*state).blksize as size_t,
                b"%s%c%s%c\0" as *const u8 as *const i8,
                filename,
                '\u{0}' as i32,
                mode,
                '\u{0}' as i32,
            ) });
            sbytes = (4 as i32 as u64)
                .wrapping_add(unsafe { strlen(filename) })
                .wrapping_add(unsafe { strlen(mode) });
            if (unsafe { ((*data).set).tftp_no_options() }) == 0 {
                let mut buf: [i8; 64] = [0; 64];
                if (unsafe { ((*data).set).upload() }) as i32 != 0
                    && (unsafe { (*data).state.infilesize }) != -(1 as i32) as i64
                {
                    (unsafe { curl_msnprintf(
                        buf.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 64]>() as u64,
                        b"%ld\0" as *const u8 as *const i8,
                        (*data).state.infilesize,
                    ) });
                } else {
                    (unsafe { strcpy(buf.as_mut_ptr(), b"0\0" as *const u8 as *const i8) });
                }
                result = tftp_option_add(
                    state,
                    &mut sbytes,
                    unsafe { ((*state).spacket.data as *mut i8).offset(sbytes as isize) },
                    b"tsize\0" as *const u8 as *const i8,
                );
                if result as u32 == CURLE_OK as i32 as u32 {
                    result = tftp_option_add(
                        state,
                        &mut sbytes,
                        unsafe { ((*state).spacket.data as *mut i8).offset(sbytes as isize) },
                        buf.as_mut_ptr(),
                    );
                }
                (unsafe { curl_msnprintf(
                    buf.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 64]>() as u64,
                    b"%d\0" as *const u8 as *const i8,
                    (*state).requested_blksize,
                ) });
                if result as u32 == CURLE_OK as i32 as u32 {
                    result = tftp_option_add(
                        state,
                        &mut sbytes,
                        unsafe { ((*state).spacket.data as *mut i8).offset(sbytes as isize) },
                        b"blksize\0" as *const u8 as *const i8,
                    );
                }
                if result as u32 == CURLE_OK as i32 as u32 {
                    result = tftp_option_add(
                        state,
                        &mut sbytes,
                        unsafe { ((*state).spacket.data as *mut i8).offset(sbytes as isize) },
                        buf.as_mut_ptr(),
                    );
                }
                (unsafe { curl_msnprintf(
                    buf.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 64]>() as u64,
                    b"%d\0" as *const u8 as *const i8,
                    (*state).retry_time,
                ) });
                if result as u32 == CURLE_OK as i32 as u32 {
                    result = tftp_option_add(
                        state,
                        &mut sbytes,
                        unsafe { ((*state).spacket.data as *mut i8).offset(sbytes as isize) },
                        b"timeout\0" as *const u8 as *const i8,
                    );
                }
                if result as u32 == CURLE_OK as i32 as u32 {
                    result = tftp_option_add(
                        state,
                        &mut sbytes,
                        unsafe { ((*state).spacket.data as *mut i8).offset(sbytes as isize) },
                        buf.as_mut_ptr(),
                    );
                }
                if result as u32 != CURLE_OK as i32 as u32 {
                    (unsafe { Curl_failf(
                        data,
                        b"TFTP buffer too small for options\0" as *const u8 as *const i8,
                    ) });
                    (unsafe { Curl_cfree.expect("non-null function pointer")(filename as *mut libc::c_void) });
                    return CURLE_TFTP_ILLEGAL;
                }
            }
            senddata = unsafe { sendto(
                (*state).sockfd,
                (*state).spacket.data as *mut libc::c_void,
                sbytes,
                0 as i32,
                (*(*(*data).conn).ip_addr).ai_addr,
                (*(*(*data).conn).ip_addr).ai_addrlen,
            ) };
            if senddata != sbytes as ssize_t {
                let mut buffer: [i8; 256] = [0; 256];
                (unsafe { Curl_failf(
                    data,
                    b"%s\0" as *const u8 as *const i8,
                    Curl_strerror(
                        *__errno_location(),
                        buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 256]>() as u64,
                    ),
                ) });
            }
            (unsafe { Curl_cfree.expect("non-null function pointer")(filename as *mut libc::c_void) });
        }
        6 => {
            if (unsafe { ((*data).set).upload() }) != 0 {
                result = tftp_connect_for_tx(state, event);
            } else {
                result = tftp_connect_for_rx(state, event);
            }
        }
        4 => {
            result = tftp_connect_for_tx(state, event);
        }
        3 => {
            result = tftp_connect_for_rx(state, event);
        }
        5 => {
            (unsafe { (*state).state = TFTP_STATE_FIN });
        }
        _ => {
            (unsafe { Curl_failf(
                (*state).data,
                b"tftp_send_first: internal error\0" as *const u8 as *const i8,
            ) });
        }
    }
    return result;
}
extern "C" fn tftp_rx(
    mut state: *mut crate::src::lib::tftp::tftp_state_data,
    mut event: i32,
) -> u32 {
    let mut sbytes: i64 = 0;
    let mut rblock: i32 = 0;
    let mut data: *mut crate::src::lib::http2::Curl_easy = unsafe { (*state).data };
    let mut buffer: [i8; 256] = [0; 256];
    let mut current_block_48: u64;
    match event as i32 {
        3 => {
            rblock = getrpacketblock(Some(unsafe { &mut (*state).rpacket })) as i32;
            if (unsafe { (*state).block }) as i32 + 1 as i32 & 0xffff as i32 == rblock {
                (unsafe { (*state).retries = 0 as i32 });
                current_block_48 = 17965632435239708295;
            } else if (unsafe { (*state).block }) as i32 == rblock {
                (unsafe { Curl_infof(
                    data,
                    b"Received last DATA packet block %d again.\0" as *const u8 as *const i8,
                    rblock,
                ) });
                current_block_48 = 17965632435239708295;
            } else {
                (unsafe { Curl_infof(
                    data,
                    b"Received unexpected DATA packet block %d, expecting block %d\0" as *const u8
                        as *const i8,
                    rblock,
                    (*state).block as i32 + 1 as i32 & 0xffff as i32,
                ) });
                current_block_48 = 1423531122933789233;
            }
            match current_block_48 {
                1423531122933789233 => {}
                _ => {
                    (unsafe { (*state).block = rblock as u16 });
                    setpacketevent(Some(unsafe { &mut (*state).spacket }), TFTP_EVENT_ACK as i32 as u16);
                    setpacketblock(Some(unsafe { &mut (*state).spacket }), unsafe { (*state).block });
                    sbytes = unsafe { sendto(
                        (*state).sockfd,
                        (*state).spacket.data as *mut libc::c_void,
                        4 as i32 as size_t,
                        MSG_NOSIGNAL as i32,
                        &mut (*state).remote_addr as *mut Curl_sockaddr_storage as *mut sockaddr,
                        (*state).remote_addrlen,
                    ) };
                    if sbytes < 0 as i32 as i64 {
                        (unsafe { Curl_failf(
                            data,
                            b"%s\0" as *const u8 as *const i8,
                            Curl_strerror(
                                *__errno_location(),
                                buffer.as_mut_ptr(),
                                ::std::mem::size_of::<[i8; 256]>() as u64,
                            ),
                        ) });
                        return CURLE_SEND_ERROR;
                    }
                    if ((unsafe { (*state).rbytes }) as i64) < (unsafe { (*state).blksize }) as ssize_t + 4 as i32 as i64 {
                        (unsafe { (*state).state = TFTP_STATE_FIN });
                    } else {
                        (unsafe { (*state).state = TFTP_STATE_RX });
                    }
                    (unsafe { time(&mut (*state).rx_time) });
                }
            }
        }
        6 => {
            (unsafe { (*state).block = 0 as i32 as u16 });
            (unsafe { (*state).retries = 0 as i32 });
            setpacketevent(Some(unsafe { &mut (*state).spacket }), TFTP_EVENT_ACK as i32 as u16);
            setpacketblock(Some(unsafe { &mut (*state).spacket }), unsafe { (*state).block });
            sbytes = unsafe { sendto(
                (*state).sockfd,
                (*state).spacket.data as *mut libc::c_void,
                4 as i32 as size_t,
                MSG_NOSIGNAL as i32,
                &mut (*state).remote_addr as *mut Curl_sockaddr_storage as *mut sockaddr,
                (*state).remote_addrlen,
            ) };
            if sbytes < 0 as i32 as i64 {
                (unsafe { Curl_failf(
                    data,
                    b"%s\0" as *const u8 as *const i8,
                    Curl_strerror(
                        *__errno_location(),
                        buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 256]>() as u64,
                    ),
                ) });
                return CURLE_SEND_ERROR;
            }
            (unsafe { (*state).state = TFTP_STATE_RX });
            (unsafe { time(&mut (*state).rx_time) });
        }
        7 => {
            let mut fresh2 = unsafe { &mut ((*state).retries) };
            *fresh2 += 1;
            (unsafe { Curl_infof(
                data,
                b"Timeout waiting for block %d ACK.  Retries = %d\0" as *const u8 as *const i8,
                (*state).block as i32 + 1 as i32 & 0xffff as i32,
                (*state).retries,
            ) });
            if (unsafe { (*state).retries }) > (unsafe { (*state).retry_max }) {
                (unsafe { (*state).error = TFTP_ERR_TIMEOUT });
                (unsafe { (*state).state = TFTP_STATE_FIN });
            } else {
                sbytes = unsafe { sendto(
                    (*state).sockfd,
                    (*state).spacket.data as *mut libc::c_void,
                    4 as i32 as size_t,
                    MSG_NOSIGNAL as i32,
                    &mut (*state).remote_addr as *mut Curl_sockaddr_storage as *mut sockaddr,
                    (*state).remote_addrlen,
                ) };
                if sbytes < 0 as i32 as i64 {
                    (unsafe { Curl_failf(
                        data,
                        b"%s\0" as *const u8 as *const i8,
                        Curl_strerror(
                            *__errno_location(),
                            buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[i8; 256]>() as u64,
                        ),
                    ) });
                    return CURLE_SEND_ERROR;
                }
            }
        }
        5 => {
            setpacketevent(Some(unsafe { &mut (*state).spacket }), TFTP_EVENT_ERROR as i32 as u16);
            setpacketblock(Some(unsafe { &mut (*state).spacket }), unsafe { (*state).block });
            (unsafe { sendto(
                (*state).sockfd,
                (*state).spacket.data as *mut libc::c_void,
                4 as i32 as size_t,
                MSG_NOSIGNAL as i32,
                &mut (*state).remote_addr as *mut Curl_sockaddr_storage as *mut sockaddr,
                (*state).remote_addrlen,
            ) });
            (unsafe { (*state).state = TFTP_STATE_FIN });
        }
        _ => {
            (unsafe { Curl_failf(
                data,
                b"%s\0" as *const u8 as *const i8,
                b"tftp_rx: internal error\0" as *const u8 as *const i8,
            ) });
            return CURLE_TFTP_ILLEGAL;
        }
    }
    return CURLE_OK;
}
extern "C" fn tftp_tx(
    mut state: *mut crate::src::lib::tftp::tftp_state_data,
    mut event: i32,
) -> u32 {
    let mut data: *mut crate::src::lib::http2::Curl_easy = unsafe { (*state).data };
    let mut sbytes: i64 = 0;
    let mut result: u32 = CURLE_OK;
    let mut k: Option<&'_ mut crate::src::lib::http2::SingleRequest> = Some(unsafe { &mut (*data).req });
    let mut cb: u64 = 0;
    let mut buffer: [i8; 256] = [0; 256];
    match event as i32 {
        4 | 6 => {
            if event as i32 == TFTP_EVENT_ACK as i32 {
                let mut rblock: i32 = getrpacketblock(Some(unsafe { &mut (*state).rpacket })) as i32;
                if rblock != (unsafe { (*state).block }) as i32
                    && !((unsafe { (*state).block }) as i32 == 0 as i32 && rblock == 65535 as i32)
                {
                    (unsafe { Curl_infof(
                        data,
                        b"Received ACK for block %d, expecting %d\0" as *const u8 as *const i8,
                        rblock,
                        (*state).block as i32,
                    ) });
                    let mut fresh3 = unsafe { &mut ((*state).retries) };
                    *fresh3 += 1;
                    if (unsafe { (*state).retries }) > (unsafe { (*state).retry_max }) {
                        (unsafe { Curl_failf(
                            data,
                            b"tftp_tx: giving up waiting for block %d ack\0" as *const u8
                                as *const i8,
                            (*state).block as i32,
                        ) });
                        result = CURLE_SEND_ERROR;
                    } else {
                        sbytes = unsafe { sendto(
                            (*state).sockfd,
                            (*state).spacket.data as *mut libc::c_void,
                            (4 as i32 + (*state).sbytes) as size_t,
                            MSG_NOSIGNAL as i32,
                            &mut (*state).remote_addr as *mut Curl_sockaddr_storage
                                as *mut sockaddr,
                            (*state).remote_addrlen,
                        ) };
                        if sbytes < 0 as i32 as i64 {
                            (unsafe { Curl_failf(
                                data,
                                b"%s\0" as *const u8 as *const i8,
                                Curl_strerror(
                                    *__errno_location(),
                                    buffer.as_mut_ptr(),
                                    ::std::mem::size_of::<[i8; 256]>() as u64,
                                ),
                            ) });
                            result = CURLE_SEND_ERROR;
                        }
                    }
                    return result;
                }
                (unsafe { time(&mut (*state).rx_time) });
                let mut fresh4 = unsafe { &mut ((*state).block) };
                *fresh4 = (*fresh4).wrapping_add(1);
            } else {
                (unsafe { (*state).block = 1 as i32 as u16 });
            }
            (unsafe { (*state).retries = 0 as i32 });
            setpacketevent(Some(unsafe { &mut (*state).spacket }), TFTP_EVENT_DATA as i32 as u16);
            setpacketblock(Some(unsafe { &mut (*state).spacket }), unsafe { (*state).block });
            if (unsafe { (*state).block }) as i32 > 1 as i32 && (unsafe { (*state).sbytes }) < (unsafe { (*state).blksize }) {
                (unsafe { (*state).state = TFTP_STATE_FIN });
                return CURLE_OK;
            }
            (unsafe { (*state).sbytes = 0 as i32 });
            let mut fresh5 = unsafe { &mut ((*(*state).data).req.upload_fromhere) };
            *fresh5 = unsafe { ((*state).spacket.data as *mut i8).offset(4 as i32 as isize) };
            loop {
                result = Curl_fillreadbuffer(
                    data,
                    ((unsafe { (*state).blksize }) - (unsafe { (*state).sbytes })) as size_t,
                    Some(&mut cb),
                );
                if result as u64 != 0 {
                    return result;
                }
                (unsafe { (*state).sbytes += cb as i32 });
                let mut fresh6 = unsafe { &mut ((*(*state).data).req.upload_fromhere) };
                *fresh6 = unsafe { (*fresh6).offset(cb as isize) };
                if !((unsafe { (*state).sbytes }) < (unsafe { (*state).blksize }) && cb != 0) {
                    break;
                }
            }
            sbytes = unsafe { sendto(
                (*state).sockfd,
                (*state).spacket.data as *mut libc::c_void,
                (4 as i32 + (*state).sbytes) as size_t,
                MSG_NOSIGNAL as i32,
                &mut (*state).remote_addr as *mut Curl_sockaddr_storage as *mut sockaddr,
                (*state).remote_addrlen,
            ) };
            if sbytes < 0 as i32 as i64 {
                (unsafe { Curl_failf(
                    data,
                    b"%s\0" as *const u8 as *const i8,
                    Curl_strerror(
                        *__errno_location(),
                        buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 256]>() as u64,
                    ),
                ) });
                return CURLE_SEND_ERROR;
            }
            let mut fresh7 = &mut ((*(borrow_mut(&mut k)).unwrap()).writebytecount);
            *fresh7 += (unsafe { (*state).sbytes }) as i64;
            Curl_pgrsSetUploadCounter(data, (*(borrow_mut(&mut k)).unwrap()).writebytecount);
        }
        7 => {
            let mut fresh8 = unsafe { &mut ((*state).retries) };
            *fresh8 += 1;
            (unsafe { Curl_infof(
                data,
                b"Timeout waiting for block %d ACK.  Retries = %d\0" as *const u8 as *const i8,
                (*state).block as i32 + 1 as i32 & 0xffff as i32,
                (*state).retries,
            ) });
            if (unsafe { (*state).retries }) > (unsafe { (*state).retry_max }) {
                (unsafe { (*state).error = TFTP_ERR_TIMEOUT });
                (unsafe { (*state).state = TFTP_STATE_FIN });
            } else {
                sbytes = unsafe { sendto(
                    (*state).sockfd,
                    (*state).spacket.data as *mut libc::c_void,
                    (4 as i32 + (*state).sbytes) as size_t,
                    MSG_NOSIGNAL as i32,
                    &mut (*state).remote_addr as *mut Curl_sockaddr_storage as *mut sockaddr,
                    (*state).remote_addrlen,
                ) };
                if sbytes < 0 as i32 as i64 {
                    (unsafe { Curl_failf(
                        data,
                        b"%s\0" as *const u8 as *const i8,
                        Curl_strerror(
                            *__errno_location(),
                            buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[i8; 256]>() as u64,
                        ),
                    ) });
                    return CURLE_SEND_ERROR;
                }
                Curl_pgrsSetUploadCounter(data, (*(borrow_mut(&mut k)).unwrap()).writebytecount);
            }
        }
        5 => {
            (unsafe { (*state).state = TFTP_STATE_FIN });
            setpacketevent(Some(unsafe { &mut (*state).spacket }), TFTP_EVENT_ERROR as i32 as u16);
            setpacketblock(Some(unsafe { &mut (*state).spacket }), unsafe { (*state).block });
            (unsafe { sendto(
                (*state).sockfd,
                (*state).spacket.data as *mut libc::c_void,
                4 as i32 as size_t,
                MSG_NOSIGNAL as i32,
                &mut (*state).remote_addr as *mut Curl_sockaddr_storage as *mut sockaddr,
                (*state).remote_addrlen,
            ) });
            (unsafe { (*state).state = TFTP_STATE_FIN });
        }
        _ => {
            (unsafe { Curl_failf(
                data,
                b"tftp_tx: internal error, event: %i\0" as *const u8 as *const i8,
                event as i32,
            ) });
        }
    }
    return result;
}
extern "C" fn tftp_translate_code(mut error: i32) -> u32 {
    let mut result: u32 = CURLE_OK;
    if error as i32 != TFTP_ERR_NONE as i32 {
        match error as i32 {
            1 => {
                result = CURLE_TFTP_NOTFOUND;
            }
            2 => {
                result = CURLE_TFTP_PERM;
            }
            3 => {
                result = CURLE_REMOTE_DISK_FULL;
            }
            0 | 4 => {
                result = CURLE_TFTP_ILLEGAL;
            }
            5 => {
                result = CURLE_TFTP_UNKNOWNID;
            }
            6 => {
                result = CURLE_REMOTE_FILE_EXISTS;
            }
            7 => {
                result = CURLE_TFTP_NOSUCHUSER;
            }
            -99 => {
                result = CURLE_OPERATION_TIMEDOUT;
            }
            -98 => {
                result = CURLE_COULDNT_CONNECT;
            }
            _ => {
                result = CURLE_ABORTED_BY_CALLBACK;
            }
        }
    } else {
        result = CURLE_OK;
    }
    return result;
}
extern "C" fn tftp_state_machine(
    mut state: *mut crate::src::lib::tftp::tftp_state_data,
    mut event: i32,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut data: *mut crate::src::lib::http2::Curl_easy = unsafe { (*state).data };
    match (unsafe { (*state).state }) as u32 {
        0 => {
            result = tftp_send_first(state, event);
        }
        1 => {
            result = tftp_rx(state, event);
        }
        2 => {
            result = tftp_tx(state, event);
        }
        3 => {
            (unsafe { Curl_infof(
                data,
                b"%s\0" as *const u8 as *const i8,
                b"TFTP finished\0" as *const u8 as *const i8,
            ) });
        }
        _ => {
            (unsafe { Curl_failf(
                data,
                b"%s\0" as *const u8 as *const i8,
                b"Internal state machine error\0" as *const u8 as *const i8,
            ) });
            result = CURLE_TFTP_ILLEGAL;
        }
    }
    return result;
}
extern "C" fn tftp_disconnect(
    mut _data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut _dead_connection: bool,
) -> u32 {
    let mut state: *mut crate::src::lib::tftp::tftp_state_data = unsafe { (*conn).proto.tftpc };
    if !state.is_null() {
        (unsafe { Curl_cfree.expect("non-null function pointer")((*state).rpacket.data as *mut libc::c_void) });
        let mut fresh9 = unsafe { &mut ((*state).rpacket.data) };
        *fresh9 = 0 as *mut u8;
        (unsafe { Curl_cfree.expect("non-null function pointer")((*state).spacket.data as *mut libc::c_void) });
        let mut fresh10 = unsafe { &mut ((*state).spacket.data) };
        *fresh10 = 0 as *mut u8;
        (unsafe { Curl_cfree.expect("non-null function pointer")(state as *mut libc::c_void) });
    }
    return CURLE_OK;
}
extern "C" fn tftp_connect(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut done: *mut bool,
) -> u32 {
    let mut state: *mut crate::src::lib::tftp::tftp_state_data = 0 as *mut tftp_state_data;
    let mut blksize: i32 = 0;
    let mut need_blksize: i32 = 0;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    blksize = 512 as i32;
    let mut fresh11 = unsafe { &mut ((*conn).proto.tftpc) };
    *fresh11 = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
        1 as i32 as size_t,
        ::std::mem::size_of::<tftp_state_data>() as u64,
    ) }) as *mut tftp_state_data;
    state = *fresh11;
    if state.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if (unsafe { (*data).set.tftp_blksize }) != 0 {
        blksize = (unsafe { (*data).set.tftp_blksize }) as i32;
        if blksize > 65464 as i32 || blksize < 8 as i32 {
            return CURLE_TFTP_ILLEGAL;
        }
    }
    need_blksize = blksize;
    if need_blksize < 512 as i32 {
        need_blksize = 512 as i32;
    }
    if (unsafe { (*state).rpacket.data }).is_null() {
        let mut fresh12 = unsafe { &mut ((*state).rpacket.data) };
        *fresh12 = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
            1 as i32 as size_t,
            (need_blksize + 2 as i32 + 2 as i32) as size_t,
        ) }) as *mut u8;
        if (unsafe { (*state).rpacket.data }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if (unsafe { (*state).spacket.data }).is_null() {
        let mut fresh13 = unsafe { &mut ((*state).spacket.data) };
        *fresh13 = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
            1 as i32 as size_t,
            (need_blksize + 2 as i32 + 2 as i32) as size_t,
        ) }) as *mut u8;
        if (unsafe { (*state).spacket.data }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    Curl_conncontrol(conn, 1 as i32);
    let mut fresh14 = unsafe { &mut ((*state).data) };
    *fresh14 = data;
    (unsafe { (*state).sockfd = (*conn).sock[0 as i32 as usize] });
    (unsafe { (*state).state = TFTP_STATE_START });
    (unsafe { (*state).error = TFTP_ERR_NONE });
    (unsafe { (*state).blksize = 512 as i32 });
    (unsafe { (*state).requested_blksize = blksize });
    (unsafe { (*(&mut (*state).local_addr as *mut Curl_sockaddr_storage as *mut sockaddr)).sa_family =
        (*(*conn).ip_addr).ai_family as sa_family_t });
    tftp_set_timeouts(state);
    if (unsafe { ((*conn).bits).bound() }) == 0 {
        let mut rc: i32 = unsafe { bind(
            (*state).sockfd,
            &mut (*state).local_addr as *mut Curl_sockaddr_storage as *mut sockaddr,
            (*(*conn).ip_addr).ai_addrlen,
        ) };
        if rc != 0 {
            let mut buffer: [i8; 256] = [0; 256];
            (unsafe { Curl_failf(
                data,
                b"bind() failed; %s\0" as *const u8 as *const i8,
                Curl_strerror(
                    *__errno_location(),
                    buffer.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 256]>() as u64,
                ),
            ) });
            return CURLE_COULDNT_CONNECT;
        }
        let mut fresh15 = unsafe { &mut ((*conn).bits) };
        (*fresh15).set_bound(1 as i32 as bit);
    }
    Curl_pgrsStartNow(data);
    (unsafe { *done = 1 as i32 != 0 });
    return CURLE_OK;
}
extern "C" fn tftp_done(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut _status: u32,
    mut _premature: bool,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut state: *mut crate::src::lib::tftp::tftp_state_data = unsafe { (*conn).proto.tftpc };
    if Curl_pgrsDone(data) != 0 {
        return CURLE_ABORTED_BY_CALLBACK;
    }
    if !state.is_null() {
        result = tftp_translate_code(unsafe { (*state).error });
    }
    return result;
}
extern "C" fn tftp_getsock(
    mut _data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut socks: *mut i32,
) -> i32 {
    (unsafe { *socks.offset(0 as i32 as isize) = (*conn).sock[0 as i32 as usize] });
    return (1 as i32) << 0 as i32;
}
extern "C" fn tftp_receive_packet(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut fromaddr: crate::src::lib::connect::Curl_sockaddr_storage = Curl_sockaddr_storage {
        buffer: C2RustUnnamed_6 {
            sa: sockaddr {
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    };
    let mut fromlen: u32 = 0;
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut state: *mut crate::src::lib::tftp::tftp_state_data = unsafe { (*conn).proto.tftpc };
    let mut k: Option<&'_ mut crate::src::lib::http2::SingleRequest> = Some(unsafe { &mut (*data).req });
    fromlen = ::std::mem::size_of::<Curl_sockaddr_storage>() as u64 as curl_socklen_t;
    (unsafe { (*state).rbytes = recvfrom(
        (*state).sockfd,
        (*state).rpacket.data as *mut libc::c_void,
        ((*state).blksize + 4 as i32) as size_t,
        0 as i32,
        &mut fromaddr as *mut Curl_sockaddr_storage as *mut sockaddr,
        &mut fromlen,
    ) as i32 });
    if (unsafe { (*state).remote_addrlen }) == 0 as i32 as u32 {
        (unsafe { memcpy(
            &mut (*state).remote_addr as *mut Curl_sockaddr_storage as *mut libc::c_void,
            &mut fromaddr as *mut Curl_sockaddr_storage as *const libc::c_void,
            fromlen as u64,
        ) });
        (unsafe { (*state).remote_addrlen = fromlen });
    }
    if (unsafe { (*state).rbytes }) < 4 as i32 {
        (unsafe { Curl_failf(
            data,
            b"Received too short packet\0" as *const u8 as *const i8,
        ) });
        (unsafe { (*state).event = TFTP_EVENT_TIMEOUT });
    } else {
        let mut event: u16 = getrpacketevent(Some(unsafe { &mut (*state).rpacket }));
        (unsafe { (*state).event = event as tftp_event_t });
        match (unsafe { (*state).event }) as i32 {
            3 => {
                if (unsafe { (*state).rbytes }) > 4 as i32
                    && (unsafe { (*state).block }) as i32 + 1 as i32 & 0xffff as i32
                        == getrpacketblock(Some(unsafe { &mut (*state).rpacket })) as i32
                {
                    result = Curl_client_write(
                        data,
                        (1 as i32) << 0 as i32,
                        unsafe { ((*state).rpacket.data as *mut i8).offset(4 as i32 as isize) },
                        ((unsafe { (*state).rbytes }) - 4 as i32) as size_t,
                    );
                    if result as u64 != 0 {
                        tftp_state_machine(state, TFTP_EVENT_ERROR);
                        return result;
                    }
                    let mut fresh16 = &mut ((*(borrow_mut(&mut k)).unwrap()).bytecount);
                    *fresh16 += ((unsafe { (*state).rbytes }) - 4 as i32) as i64;
                    Curl_pgrsSetDownloadCounter(data, (*(borrow_mut(&mut k)).unwrap()).bytecount);
                }
            }
            5 => {
                let mut error: u16 = getrpacketblock(Some(unsafe { &mut (*state).rpacket }));
                let mut str: *mut i8 = unsafe { ((*state).rpacket.data as *mut i8).offset(4 as i32 as isize) };
                let mut strn: u64 = ((unsafe { (*state).rbytes }) - 4 as i32) as size_t;
                (unsafe { (*state).error = error as tftp_error_t });
                if tftp_strnlen(str, strn) < strn {
                    (unsafe { Curl_infof(data, b"TFTP error: %s\0" as *const u8 as *const i8, str) });
                }
            }
            4 => {}
            6 => {
                result = tftp_parse_option_ack(
                    state,
                    unsafe { ((*state).rpacket.data as *const i8).offset(2 as i32 as isize) },
                    (unsafe { (*state).rbytes }) - 2 as i32,
                );
                if result as u64 != 0 {
                    return result;
                }
            }
            1 | 2 | _ => {
                (unsafe { Curl_failf(
                    data,
                    b"%s\0" as *const u8 as *const i8,
                    b"Internal error: Unexpected packet\0" as *const u8 as *const i8,
                ) });
            }
        }
        if Curl_pgrsUpdate(data) != 0 {
            tftp_state_machine(state, TFTP_EVENT_ERROR);
            return CURLE_ABORTED_BY_CALLBACK;
        }
    }
    return result;
}
extern "C" fn tftp_state_timeout<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut event: Option<&'a1 mut i32>,
) -> i64 {
    let mut current: i64 = 0;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut state: *mut crate::src::lib::tftp::tftp_state_data = unsafe { (*conn).proto.tftpc };
    let mut timeout_ms: i64 = 0;
    if !borrow(&event).is_none() {
        *(borrow_mut(&mut event)).unwrap() = TFTP_EVENT_NONE;
    }
    timeout_ms = Curl_timeleft(
        unsafe { (*state).data },
        0 as *mut crate::src::lib::http2::curltime,
        (unsafe { (*state).state }) as u32 == TFTP_STATE_START as i32 as u32,
    );
    if timeout_ms < 0 as i32 as i64 {
        (unsafe { (*state).error = TFTP_ERR_TIMEOUT });
        (unsafe { (*state).state = TFTP_STATE_FIN });
        return 0 as i32 as timediff_t;
    }
    (unsafe { time(&mut current) });
    if current > (unsafe { (*state).rx_time }) + (unsafe { (*state).retry_time }) as i64 {
        if !borrow(&event).is_none() {
            *(borrow_mut(&mut event)).unwrap() = TFTP_EVENT_TIMEOUT;
        }
        (unsafe { time(&mut (*state).rx_time) });
    }
    return timeout_ms;
}
extern "C" fn tftp_multi_statemach(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut done: *mut bool,
) -> u32 {
    let mut event: i32 = TFTP_EVENT_INIT;
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut state: *mut crate::src::lib::tftp::tftp_state_data = unsafe { (*conn).proto.tftpc };
    let mut timeout_ms: i64 = tftp_state_timeout(data, Some(&mut event));
    (unsafe { *done = 0 as i32 != 0 });
    if timeout_ms < 0 as i32 as i64 {
        (unsafe { Curl_failf(data, b"TFTP response timeout\0" as *const u8 as *const i8) });
        return CURLE_OPERATION_TIMEDOUT;
    }
    if event as i32 != TFTP_EVENT_NONE as i32 {
        result = tftp_state_machine(state, event);
        if result as u64 != 0 {
            return result;
        }
        (unsafe { *done = if (*state).state as u32 == TFTP_STATE_FIN as i32 as u32 {
            1 as i32
        } else {
            0 as i32
        } != 0 });
        if unsafe { *done } {
            Curl_setup_transfer(
                data,
                -(1 as i32),
                -(1 as i32) as curl_off_t,
                0 as i32 != 0,
                -(1 as i32),
            );
        }
    } else {
        let mut rc: i32 = Curl_socket_check(
            unsafe { (*state).sockfd },
            -(1 as i32),
            -(1 as i32),
            0 as i32 as timediff_t,
        );
        if rc == -(1 as i32) {
            let mut error: i32 = unsafe { *__errno_location() };
            let mut buffer: [i8; 256] = [0; 256];
            (unsafe { Curl_failf(
                data,
                b"%s\0" as *const u8 as *const i8,
                Curl_strerror(
                    error,
                    buffer.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 256]>() as u64,
                ),
            ) });
            (unsafe { (*state).event = TFTP_EVENT_ERROR });
        } else if rc != 0 {
            result = tftp_receive_packet(data);
            if result as u64 != 0 {
                return result;
            }
            result = tftp_state_machine(state, unsafe { (*state).event });
            if result as u64 != 0 {
                return result;
            }
            (unsafe { *done = if (*state).state as u32 == TFTP_STATE_FIN as i32 as u32 {
                1 as i32
            } else {
                0 as i32
            } != 0 });
            if unsafe { *done } {
                Curl_setup_transfer(
                    data,
                    -(1 as i32),
                    -(1 as i32) as curl_off_t,
                    0 as i32 != 0,
                    -(1 as i32),
                );
            }
        }
    }
    return result;
}
extern "C" fn tftp_doing(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut dophase_done: *mut bool,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    result = tftp_multi_statemach(data, dophase_done);
    if !(unsafe { *dophase_done }) {
        if result as u64 == 0 {
            if Curl_pgrsUpdate(data) != 0 {
                result = CURLE_ABORTED_BY_CALLBACK;
            } else {
                result = Curl_speedcheck(data, Curl_now());
            }
        }
    }
    return result;
}
extern "C" fn tftp_perform(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut dophase_done: *mut bool,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut state: *mut crate::src::lib::tftp::tftp_state_data = unsafe { (*conn).proto.tftpc };
    (unsafe { *dophase_done = 0 as i32 != 0 });
    result = tftp_state_machine(state, TFTP_EVENT_INIT);
    if (unsafe { (*state).state }) as u32 == TFTP_STATE_FIN as i32 as u32 || result as u32 != 0 {
        return result;
    }
    tftp_multi_statemach(data, dophase_done);
    (unsafe { *dophase_done });
    return result;
}
extern "C" fn tftp_do(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut done: *mut bool,
) -> u32 {
    let mut state: *mut crate::src::lib::tftp::tftp_state_data = 0 as *mut tftp_state_data;
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    (unsafe { *done = 0 as i32 != 0 });
    if (unsafe { (*conn).proto.tftpc }).is_null() {
        result = tftp_connect(data, done);
        if result as u64 != 0 {
            return result;
        }
    }
    state = unsafe { (*conn).proto.tftpc };
    if state.is_null() {
        return CURLE_TFTP_ILLEGAL;
    }
    result = tftp_perform(data, done);
    if result as u64 == 0 {
        result = tftp_translate_code(unsafe { (*state).error });
    }
    return result;
}
extern "C" fn tftp_setup_connection(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut type_0: *mut i8 = 0 as *mut i8;
    (unsafe { (*conn).transport = TRNSPRT_UDP });
    type_0 = unsafe { strstr((*data).state.up.path, b";mode=\0" as *const u8 as *const i8) };
    if type_0.is_null() {
        type_0 = unsafe { strstr((*conn).host.rawalloc, b";mode=\0" as *const u8 as *const i8) };
    }
    if !type_0.is_null() {
        let mut command: i8 = 0;
        (unsafe { *type_0 = 0 as i32 as i8 });
        command = Curl_raw_toupper(unsafe { *type_0.offset(6 as i32 as isize) });
        let mut current_block_7: u64;
        match command as i32 {
            65 | 78 => {
                let mut fresh17 = unsafe { &mut ((*data).state) };
                (*fresh17).set_prefer_ascii(1 as i32 as bit);
                current_block_7 = 1841672684692190573;
            }
            79 => {
                current_block_7 = 1069480347385033206;
            }
            73 | _ => {
                current_block_7 = 1069480347385033206;
            }
        }
        match current_block_7 {
            1069480347385033206 => {
                let mut fresh18 = unsafe { &mut ((*data).state) };
                (*fresh18).set_prefer_ascii(0 as i32 as bit);
            }
            _ => {}
        }
    }
    return CURLE_OK;
}
use crate::laertes_rt::*;
