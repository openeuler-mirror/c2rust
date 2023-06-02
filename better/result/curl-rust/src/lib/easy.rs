
use :: libc;
extern "C" {
    fn malloc(_: u64) -> *mut core::ffi::c_void;
    fn calloc(_: u64, _: u64) -> *mut core::ffi::c_void;
    fn realloc(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void;
    fn free(__ptr: *mut core::ffi::c_void);
    fn strdup(_: *const i8) -> *mut i8;
    fn memset(_: *mut core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn sigaction(
        __sig: i32,
        __act: *const crate::src::lib::conncache::sigaction,
        __oact: *mut crate::src::lib::conncache::sigaction,
    ) -> i32;
}
pub use crate::src::lib::altsvc::Curl_altsvc_cleanup;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::asyn_thread::Curl_resolver_duphandle;
pub use crate::src::lib::asyn_thread::Curl_resolver_global_cleanup;
pub use crate::src::lib::asyn_thread::Curl_resolver_global_init;
pub use crate::src::lib::conncache::Curl_conncache_foreach;
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::connect::Curl_getconnectinfo;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::cookie::Curl_cookie_init;
pub use crate::src::lib::dynbuf::Curl_dyn_free;
pub use crate::src::lib::dynbuf::Curl_dyn_init;
pub use crate::src::lib::dynbuf::Curl_dyn_len;
pub use crate::src::lib::dynbuf::Curl_dyn_ptr;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::getinfo::Curl_getinfo;
pub use crate::src::lib::getinfo::Curl_initinfo;
pub use crate::src::lib::hsts::Curl_hsts_cleanup;
pub use crate::src::lib::hsts::Curl_hsts_init;
pub use crate::src::lib::hsts::Curl_hsts_loadcb;
pub use crate::src::lib::hsts::Curl_hsts_loadfile;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::http2::Curl_http2_stream_pause;
pub use crate::src::lib::http_digest::Curl_http_auth_cleanup_digest;
pub use crate::src::lib::mime::Curl_mime_duppart;
pub use crate::src::lib::mime::Curl_mime_initpart;
pub use crate::src::lib::mime::Curl_mime_read;
pub use crate::src::lib::mime::Curl_mime_unpause;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::multi::curl_multi_add_handle;
pub use crate::src::lib::multi::curl_multi_cleanup;
pub use crate::src::lib::multi::curl_multi_info_read;
pub use crate::src::lib::multi::curl_multi_perform;
pub use crate::src::lib::multi::curl_multi_poll;
pub use crate::src::lib::multi::curl_multi_remove_handle;
pub use crate::src::lib::multi::curl_multi_setopt;
pub use crate::src::lib::multi::Curl_attach_connnection;
pub use crate::src::lib::multi::Curl_detach_connnection;
pub use crate::src::lib::multi::Curl_expire;
pub use crate::src::lib::multi::Curl_is_in_callback;
pub use crate::src::lib::multi::Curl_multi_handle;
pub use crate::src::lib::multi::Curl_update_timer;
pub use crate::src::lib::multi::Curl_updatesocket;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::sendf::Curl_client_write;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_read;
pub use crate::src::lib::sendf::Curl_write;
pub use crate::src::lib::setopt::Curl_setblobopt;
pub use crate::src::lib::setopt::Curl_setstropt;
pub use crate::src::lib::slist::curl_slist_free_all;
pub use crate::src::lib::slist::Curl_slist_duplicate;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::strdup::Curl_memdup;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::url::Curl_close;
pub use crate::src::lib::url::Curl_free_request_state;
pub use crate::src::lib::url::Curl_freeset;
pub use crate::src::lib::url::Curl_init_userdefined;
pub use crate::src::lib::url::Curl_open;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
pub use crate::src::lib::vtls::vtls::Curl_ssl_cleanup;
pub use crate::src::lib::vtls::vtls::Curl_ssl_init;
pub use crate::src::lib::vtls::vtls::Curl_ssl_set_engine;
pub use crate::src::lib::warnless::curlx_sotouz;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub type __builtin_va_list = [crate::src::lib::dict::__va_list_tag; 1];
pub type __va_list_tag = crate::src::lib::dict::__va_list_tag;
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
pub type __sigset_t = crate::src::lib::conncache::__sigset_t;
pub type socklen_t = u32;
pub type sa_family_t = u16;
pub type sockaddr = crate::src::lib::http2::sockaddr;
pub type curl_socklen_t = u32;
pub type curl_off_t = i64;
pub type va_list = [crate::src::lib::dict::__va_list_tag; 1];
pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::lib::http2::_IO_FILE;
pub type __sigval_t = crate::src::lib::conncache::sigval;
pub type sigval = crate::src::lib::conncache::sigval;
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
pub type altsvcinfo = crate::src::lib::altsvc::altsvcinfo;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hsts {
    pub list: crate::src::lib::http2::Curl_llist,
    pub filename: *mut i8,
    pub flags: u32,
}
impl hsts {
    pub const fn new() -> Self {
        hsts {
            list: crate::src::lib::http2::Curl_llist::new(),
            filename: (0 as *mut i8),
            flags: 0,
        }
    }
}
impl std::default::Default for hsts {
    fn default() -> Self {
        hsts::new()
    }
}
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
pub type C2RustUnnamed = crate::src::lib::http2::C2RustUnnamed;
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
pub type C2RustUnnamed_0 = u32;
pub const HTTPSEND_BODY: C2RustUnnamed_0 = 2;
pub const HTTPSEND_REQUEST: C2RustUnnamed_0 = 1;
pub const HTTPSEND_NADA: C2RustUnnamed_0 = 0;
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
pub type C2RustUnnamed_1 = u32;
pub const HEADER_ALLBAD: C2RustUnnamed_1 = 2;
pub const HEADER_PARTHEADER: C2RustUnnamed_1 = 1;
pub const HEADER_NORMAL: C2RustUnnamed_1 = 0;
pub type PslCache = crate::src::lib::http2::PslCache;
pub type psl_ctx_t = crate::src::lib::urlapi::psl_ctx_st;
pub type Curl_share = crate::src::lib::asyn_thread::Curl_share;
pub type curl_unlock_function<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: u32,
        _: Option<&'a2 mut core::ffi::c_void>,
    ) -> (),
>;
pub type curl_lock_data = u32;
pub const CURL_LOCK_DATA_LAST: curl_lock_data = 7;
pub const CURL_LOCK_DATA_PSL: curl_lock_data = 6;
pub const CURL_LOCK_DATA_CONNECT: curl_lock_data = 5;
pub const CURL_LOCK_DATA_SSL_SESSION: curl_lock_data = 4;
pub const CURL_LOCK_DATA_DNS: curl_lock_data = 3;
pub const CURL_LOCK_DATA_COOKIE: curl_lock_data = 2;
pub const CURL_LOCK_DATA_SHARE: curl_lock_data = 1;
pub const CURL_LOCK_DATA_NONE: curl_lock_data = 0;
pub type curl_lock_function<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: u32,
        _: u32,
        _: Option<&'a2 mut core::ffi::c_void>,
    ) -> (),
>;
pub type curl_lock_access = u32;
pub const CURL_LOCK_ACCESS_LAST: curl_lock_access = 3;
pub const CURL_LOCK_ACCESS_SINGLE: curl_lock_access = 2;
pub const CURL_LOCK_ACCESS_SHARED: curl_lock_access = 1;
pub const CURL_LOCK_ACCESS_NONE: curl_lock_access = 0;
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
pub type C2RustUnnamed_2 = u32;
pub const HCACHE_SHARED: C2RustUnnamed_2 = 2;
pub const HCACHE_MULTI: C2RustUnnamed_2 = 1;
pub const HCACHE_NONE: C2RustUnnamed_2 = 0;
pub type Curl_message = crate::src::lib::http2::Curl_message;
pub type CURLMsg = crate::src::lib::http2::CURLMsg;
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
pub type connectdata = crate::src::lib::http2::connectdata;
pub type connectbundle = crate::src::lib::http2::connectbundle;
pub type C2RustUnnamed_4 = crate::src::lib::http2::C2RustUnnamed_4;
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
pub type C2RustUnnamed_5 = u32;
pub const TRNSPRT_QUIC: C2RustUnnamed_5 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_5 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_5 = 3;
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
pub type curl_malloc_callback<'a1> =
    Option<unsafe extern "C" fn(_: u64) -> Option<&'a1 mut core::ffi::c_void>>;
pub type curl_realloc_callback<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: u64,
    ) -> Option<&'a2 mut core::ffi::c_void>,
>;
pub type curl_strdup_callback<'a1, 'a2> =
    Option<unsafe extern "C" fn(_: Option<&'a1 i8>) -> Option<&'a2 mut i8>>;
pub type curl_calloc_callback<'a1> =
    Option<unsafe extern "C" fn(_: u64, _: u64) -> Option<&'a1 mut core::ffi::c_void>>;
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
pub type sigpipe_ignore = crate::src::lib::conncache::sigpipe_ignore;
pub type sigaction = crate::src::lib::conncache::sigaction;
pub type C2RustUnnamed_6 = crate::src::lib::conncache::C2RustUnnamed_6;
pub type siginfo_t = crate::src::lib::conncache::siginfo_t;
pub type C2RustUnnamed_7 = crate::src::lib::conncache::C2RustUnnamed_7;
pub type C2RustUnnamed_8 = crate::src::lib::conncache::C2RustUnnamed_8;
pub type C2RustUnnamed_9 = crate::src::lib::conncache::C2RustUnnamed_9;
pub type C2RustUnnamed_10 = crate::src::lib::conncache::C2RustUnnamed_10;
pub type C2RustUnnamed_11 = crate::src::lib::conncache::C2RustUnnamed_11;
pub type C2RustUnnamed_12 = crate::src::lib::conncache::C2RustUnnamed_12;
pub type C2RustUnnamed_13 = crate::src::lib::conncache::C2RustUnnamed_13;
pub type C2RustUnnamed_14 = crate::src::lib::conncache::C2RustUnnamed_14;
pub type C2RustUnnamed_15 = crate::src::lib::conncache::C2RustUnnamed_15;
pub type C2RustUnnamed_16 = crate::src::lib::conncache::C2RustUnnamed_16;
pub type __sighandler_t = Option<unsafe extern "C" fn(_: i32) -> ()>;
pub type CURLMcode = i32;
pub const CURLM_LAST: CURLMcode = 11;
pub const CURLM_BAD_FUNCTION_ARGUMENT: CURLMcode = 10;
pub const CURLM_WAKEUP_FAILURE: CURLMcode = 9;
pub const CURLM_RECURSIVE_API_CALL: CURLMcode = 8;
pub const CURLM_ADDED_ALREADY: CURLMcode = 7;
pub const CURLM_UNKNOWN_OPTION: CURLMcode = 6;
pub const CURLM_BAD_SOCKET: CURLMcode = 5;
pub const CURLM_INTERNAL_ERROR: CURLMcode = 4;
pub const CURLM_OUT_OF_MEMORY: CURLMcode = 3;
pub const CURLM_BAD_EASY_HANDLE: CURLMcode = 2;
pub const CURLM_BAD_HANDLE: CURLMcode = 1;
pub const CURLM_OK: CURLMcode = 0;
pub const CURLM_CALL_MULTI_PERFORM: CURLMcode = -1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_waitfd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}
impl curl_waitfd {
    pub const fn new() -> Self {
        curl_waitfd {
            fd: 0,
            events: 0,
            revents: 0,
        }
    }
}
impl std::default::Default for curl_waitfd {
    fn default() -> Self {
        curl_waitfd::new()
    }
}
pub type CURLMoption = u32;
pub const CURLMOPT_LASTENTRY: CURLMoption = 17;
pub const CURLMOPT_MAX_CONCURRENT_STREAMS: CURLMoption = 16;
pub const CURLMOPT_PUSHDATA: CURLMoption = 10015;
pub const CURLMOPT_PUSHFUNCTION: CURLMoption = 20014;
pub const CURLMOPT_MAX_TOTAL_CONNECTIONS: CURLMoption = 13;
pub const CURLMOPT_PIPELINING_SERVER_BL: CURLMoption = 10012;
pub const CURLMOPT_PIPELINING_SITE_BL: CURLMoption = 10011;
pub const CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE: CURLMoption = 30010;
pub const CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE: CURLMoption = 30009;
pub const CURLMOPT_MAX_PIPELINE_LENGTH: CURLMoption = 8;
pub const CURLMOPT_MAX_HOST_CONNECTIONS: CURLMoption = 7;
pub const CURLMOPT_MAXCONNECTS: CURLMoption = 6;
pub const CURLMOPT_TIMERDATA: CURLMoption = 10005;
pub const CURLMOPT_TIMERFUNCTION: CURLMoption = 20004;
pub const CURLMOPT_PIPELINING: CURLMoption = 3;
pub const CURLMOPT_SOCKETDATA: CURLMoption = 10002;
pub const CURLMOPT_SOCKETFUNCTION: CURLMoption = 20001;
pub const STRING_HSTS: dupstring = 70;
pub const STRING_SSL_ENGINE: dupstring = 43;
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
pub const STRING_COOKIEJAR: dupstring = 5;
pub const STRING_COOKIE: dupstring = 4;
pub const STRING_CERT_TYPE_PROXY: dupstring = 3;
pub const STRING_CERT_TYPE: dupstring = 2;
pub const STRING_CERT_PROXY: dupstring = 1;
pub const STRING_CERT: dupstring = 0;
pub type dupblob = u32;
pub const BLOB_LAST: dupblob = 8;
pub const BLOB_CAINFO_PROXY: dupblob = 7;
pub const BLOB_CAINFO: dupblob = 6;
pub const BLOB_SSL_ISSUERCERT_PROXY: dupblob = 5;
pub const BLOB_SSL_ISSUERCERT: dupblob = 4;
pub const BLOB_KEY_PROXY: dupblob = 3;
pub const BLOB_KEY: dupblob = 2;
pub const BLOB_CERT_PROXY: dupblob = 1;
pub const BLOB_CERT: dupblob = 0;
extern "C" fn sigpipe_ignore<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut ig: Option<&'a1 mut crate::src::lib::conncache::sigpipe_ignore>,
) {
    (*(borrow_mut(&mut ig)).unwrap()).no_signal = (unsafe { ((*data).set).no_signal() }) != 0;
    if (unsafe { ((*data).set).no_signal() }) == 0 {
        let mut action: crate::src::lib::conncache::sigaction = sigaction {
            __sigaction_handler: C2RustUnnamed_6 { sa_handler: None },
            sa_mask: __sigset_t { __val: [0; 16] },
            sa_flags: 0,
            sa_restorer: None,
        };
        (unsafe { memset(
            &mut (*(borrow_mut(&mut ig)).unwrap()).old_pipe_act as *mut sigaction
                as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<sigaction>() as u64,
        ) });
        (unsafe { sigaction(
            13 as i32,
            0 as *const sigaction,
            &mut (*(borrow_mut(&mut ig)).unwrap()).old_pipe_act,
        ) });
        action = (*(borrow_mut(&mut ig)).unwrap()).old_pipe_act;
        action.__sigaction_handler.sa_handler = unsafe { core::intrinsics::transmute::<
            isize,
            Option<unsafe extern "C" fn(_: i32) -> ()>,
        >(1 as i32 as libc::intptr_t) };
        (unsafe { sigaction(13 as i32, &mut action, 0 as *mut sigaction) });
    }
}
extern "C" fn sigpipe_restore<'a1>(
    mut ig: Option<&'a1 mut crate::src::lib::conncache::sigpipe_ignore>,
) {
    if !(*(borrow(&ig)).unwrap()).no_signal {
        (unsafe { sigaction(
            13 as i32,
            &mut (*(borrow_mut(&mut ig)).unwrap()).old_pipe_act,
            0 as *mut sigaction,
        ) });
    }
}
static mut initialized: u32 = 0;
static mut init_flags: i64 = 0;
#[no_mangle]
pub static mut Curl_cmalloc: Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void> = unsafe {
    core::intrinsics::transmute::<
        Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>,
        Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>,
    >(Some(malloc))
};
#[no_mangle]
pub static mut Curl_cfree: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()> = unsafe {
    core::intrinsics::transmute::<
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>,
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>,
    >(Some(free))
};
#[no_mangle]
pub static mut Curl_crealloc: Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void,
> = unsafe {
    core::intrinsics::transmute::<
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void>,
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void>,
    >(Some(realloc))
};
#[no_mangle]
pub static mut Curl_cstrdup: Option<unsafe extern "C" fn(_: *const i8) -> *mut i8> = unsafe {
    core::intrinsics::transmute::<
        Option<unsafe extern "C" fn(_: *const i8) -> *mut i8>,
        Option<unsafe extern "C" fn(_: *const i8) -> *mut i8>,
    >(Some(strdup))
};
#[no_mangle]
pub static mut Curl_ccalloc: Option<
    unsafe extern "C" fn(_: u64, _: u64) -> *mut core::ffi::c_void,
> = unsafe {
    core::intrinsics::transmute::<
        Option<unsafe extern "C" fn(_: u64, _: u64) -> *mut core::ffi::c_void>,
        Option<unsafe extern "C" fn(_: u64, _: u64) -> *mut core::ffi::c_void>,
    >(Some(calloc))
};
extern "C" fn global_init(mut flags: i64, mut memoryfuncs: bool) -> u32 {
    let mut fresh0 = unsafe { initialized };
    (unsafe { initialized = initialized.wrapping_add(1) });
    if fresh0 != 0 {
        return CURLE_OK;
    }
    if memoryfuncs {
        (unsafe { Curl_cmalloc = core::intrinsics::transmute::<
            Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>,
            Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>,
        >(Some(malloc)) });
        (unsafe { Curl_cfree = core::intrinsics::transmute::<
            Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>,
            Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>,
        >(Some(free)) });
        (unsafe { Curl_crealloc = core::intrinsics::transmute::<
            Option<
                unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void,
            >,
            Option<
                unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void,
            >,
        >(Some(realloc)) });
        (unsafe { Curl_cstrdup = core::intrinsics::transmute::<
            Option<unsafe extern "C" fn(_: *const i8) -> *mut i8>,
            Option<unsafe extern "C" fn(_: *const i8) -> *mut i8>,
        >(Some(strdup)) });
        (unsafe { Curl_ccalloc = core::intrinsics::transmute::<
            Option<unsafe extern "C" fn(_: u64, _: u64) -> *mut core::ffi::c_void>,
            Option<unsafe extern "C" fn(_: u64, _: u64) -> *mut core::ffi::c_void>,
        >(Some(calloc)) });
    }
    if !(Curl_ssl_init() == 0) {
        if !(Curl_resolver_global_init() != 0) {
            (unsafe { init_flags = flags });
            return CURLE_OK;
        }
    }
    (unsafe { initialized = initialized.wrapping_sub(1) });
    return CURLE_FAILED_INIT;
}
#[no_mangle]
pub extern "C" fn curl_global_init(mut flags: i64) -> u32 {
    return global_init(flags, 1 as i32 != 0);
}
#[no_mangle]
pub extern "C" fn curl_global_init_mem(
    mut flags: i64,
    mut m: Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>,
    mut f: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>,
    mut r: Option<
        unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void,
    >,
    mut s: Option<unsafe extern "C" fn(_: *const i8) -> *mut i8>,
    mut c: Option<unsafe extern "C" fn(_: u64, _: u64) -> *mut core::ffi::c_void>,
) -> u32 {
    if m.is_none() || f.is_none() || r.is_none() || s.is_none() || c.is_none() {
        return CURLE_FAILED_INIT;
    }
    if (unsafe { initialized }) != 0 {
        (unsafe { initialized = initialized.wrapping_add(1) });
        return CURLE_OK;
    }
    (unsafe { Curl_cmalloc = m });
    (unsafe { Curl_cfree = f });
    (unsafe { Curl_cstrdup = s });
    (unsafe { Curl_crealloc = r });
    (unsafe { Curl_ccalloc = c });
    return global_init(flags, 0 as i32 != 0);
}
#[no_mangle]
pub extern "C" fn curl_global_cleanup() {
    if (unsafe { initialized }) == 0 {
        return;
    }
    (unsafe { initialized = initialized.wrapping_sub(1) });
    if (unsafe { initialized }) != 0 {
        return;
    }
    Curl_ssl_cleanup();
    Curl_resolver_global_cleanup();
    (unsafe { init_flags = 0 as i32 as i64 });
}
#[no_mangle]
pub extern "C" fn curl_easy_init() -> *mut crate::src::lib::http2::Curl_easy {
    let mut result: u32 = CURLE_OK;
    let mut data: *mut crate::src::lib::http2::Curl_easy = 0 as *mut Curl_easy;
    if (unsafe { initialized }) == 0 {
        result = curl_global_init(((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as i64);
        if result as u64 != 0 {
            return 0 as *mut CURL;
        }
    }
    result = Curl_open(Some(&mut data));
    if result as u64 != 0 {
        return 0 as *mut CURL;
    }
    return data;
}
extern "C" fn easy_transfer(mut multi: *mut crate::src::lib::http2::Curl_multi) -> u32 {
    let mut done: bool = 0 as i32 != 0;
    let mut mcode: i32 = CURLM_OK;
    let mut result: u32 = CURLE_OK;
    while !done && mcode as u64 == 0 {
        let mut still_running: i32 = 0 as i32;
        mcode = curl_multi_poll(
            multi,
            0 as *mut crate::src::lib::easy::curl_waitfd,
            0 as i32 as u32,
            1000 as i32,
            Option::<&'_ mut i32>::None,
        );
        if mcode as u64 == 0 {
            mcode = curl_multi_perform(multi, Some(&mut still_running));
        }
        if mcode as u64 == 0 && still_running == 0 {
            let mut rc: i32 = 0;
            let mut msg: Option<&'_ mut crate::src::lib::http2::CURLMsg> =
                curl_multi_info_read(multi, Some(&mut rc));
            if !borrow(&msg).is_none() {
                result = unsafe { (*(borrow_mut(&mut msg)).unwrap()).data.result };
                done = 1 as i32 != 0;
            }
        }
    }
    if mcode as u64 != 0 {
        result = (if mcode as i32 == CURLM_OUT_OF_MEMORY as i32 {
            CURLE_OUT_OF_MEMORY as i32
        } else {
            CURLE_BAD_FUNCTION_ARGUMENT as i32
        }) as CURLcode;
    }
    return result;
}
extern "C" fn easy_perform(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut events: bool,
) -> u32 {
    let mut multi: *mut crate::src::lib::http2::Curl_multi = 0 as *mut Curl_multi;
    let mut mcode: i32 = CURLM_OK;
    let mut result: u32 = CURLE_OK;
    let mut pipe_st: crate::src::lib::conncache::sigpipe_ignore = sigpipe_ignore {
        old_pipe_act: sigaction {
            __sigaction_handler: C2RustUnnamed_6 { sa_handler: None },
            sa_mask: __sigset_t { __val: [0; 16] },
            sa_flags: 0,
            sa_restorer: None,
        },
        no_signal: false,
    };
    if data.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if !(unsafe { (*data).set.errorbuffer }).is_null() {
        (unsafe { *((*data).set.errorbuffer).offset(0 as i32 as isize) = 0 as i32 as i8 });
    }
    if !(unsafe { (*data).multi }).is_null() {
        (unsafe { Curl_failf(
            data,
            b"easy handle already used in multi handle\0" as *const u8 as *const i8,
        ) });
        return CURLE_FAILED_INIT;
    }
    if !(unsafe { (*data).multi_easy }).is_null() {
        multi = unsafe { (*data).multi_easy };
    } else {
        multi = Curl_multi_handle(1 as i32, 3 as i32);
        if multi.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        let mut fresh1 = unsafe { &mut ((*data).multi_easy) };
        *fresh1 = multi;
    }
    if unsafe { (*multi).in_callback } {
        return CURLE_RECURSIVE_API_CALL;
    }
    (unsafe { curl_multi_setopt(multi, CURLMOPT_MAXCONNECTS, (*data).set.maxconnects) });
    mcode = curl_multi_add_handle(multi, data);
    if mcode as u64 != 0 {
        curl_multi_cleanup(multi);
        let mut fresh2 = unsafe { &mut ((*data).multi_easy) };
        *fresh2 = 0 as *mut Curl_multi;
        if mcode as i32 == CURLM_OUT_OF_MEMORY as i32 {
            return CURLE_OUT_OF_MEMORY;
        }
        return CURLE_FAILED_INIT;
    }
    sigpipe_ignore(data, Some(&mut pipe_st));
    result = (if events as i32 != 0 {
        CURLE_NOT_BUILT_IN as i32 as u32
    } else {
        easy_transfer(multi) as u32
    }) as CURLcode;
    curl_multi_remove_handle(multi, data);
    sigpipe_restore(Some(&mut pipe_st));
    return result;
}
#[no_mangle]
pub extern "C" fn curl_easy_perform(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    return easy_perform(data, 0 as i32 != 0);
}
#[no_mangle]
pub extern "C" fn curl_easy_cleanup(mut data: *mut crate::src::lib::http2::Curl_easy) {
    let mut pipe_st: crate::src::lib::conncache::sigpipe_ignore = sigpipe_ignore {
        old_pipe_act: sigaction {
            __sigaction_handler: C2RustUnnamed_6 { sa_handler: None },
            sa_mask: __sigset_t { __val: [0; 16] },
            sa_flags: 0,
            sa_restorer: None,
        },
        no_signal: false,
    };
    if data.is_null() {
        return;
    }
    sigpipe_ignore(data, Some(&mut pipe_st));
    Curl_close(Some(&mut data));
    sigpipe_restore(Some(&mut pipe_st));
}
#[no_mangle]
pub unsafe extern "C" fn curl_easy_getinfo(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut info: u32,
    mut args: ...
) -> u32 {
    let mut arg: core::ffi::VaListImpl;
    let mut paramp: *mut core::ffi::c_void = 0 as *mut libc::c_void;
    let mut result: u32 = CURLE_OK;
    arg = args.clone();
    paramp = arg.arg::<*mut libc::c_void>();
    result = Curl_getinfo(data, info, paramp);
    return result;
}
extern "C" fn dupset(
    mut dst: *mut crate::src::lib::http2::Curl_easy,
    mut src: *mut crate::src::lib::http2::Curl_easy,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut i: u32 = STRING_CERT;
    let mut j: u32 = BLOB_CERT;
    (unsafe { (*dst).set = (*src).set });
    Curl_mime_initpart(unsafe { &mut (*dst).set.mimepost }, dst);
    (unsafe { memset(
        ((*dst).set.str_0).as_mut_ptr() as *mut libc::c_void,
        0 as i32,
        (STRING_LAST as i32 as u64).wrapping_mul(::std::mem::size_of::<*mut i8>() as u64),
    ) });
    i = STRING_CERT;
    while (i as u32) < STRING_LASTZEROTERMINATED as i32 as u32 {
        result = Curl_setstropt(
            Some(unsafe { &mut *((*dst).set.str_0).as_mut_ptr().offset(i as isize) }),
            unsafe { (*src).set.str_0[i as usize] },
        );
        if result as u64 != 0 {
            return result;
        }
        i += 1;
    }
    (unsafe { memset(
        ((*dst).set.blobs).as_mut_ptr() as *mut libc::c_void,
        0 as i32,
        (BLOB_LAST as i32 as u64).wrapping_mul(::std::mem::size_of::<*mut curl_blob>() as u64),
    ) });
    j = BLOB_CERT;
    while (j as u32) < BLOB_LAST as i32 as u32 {
        result = Curl_setblobopt(
            Some(unsafe { &mut *((*dst).set.blobs).as_mut_ptr().offset(j as isize) }),
            unsafe { (*src).set.blobs[j as usize] },
        );
        if result as u64 != 0 {
            return result;
        }
        j += 1;
    }
    i = STRING_COPYPOSTFIELDS;
    if (unsafe { (*src).set.postfieldsize }) != 0 && !(unsafe { (*src).set.str_0[i as usize] }).is_null() {
        let mut fresh3 = unsafe { &mut ((*dst).set.str_0[i as usize]) };
        *fresh3 = Curl_memdup(
            (unsafe { (*src).set.str_0[i as usize] }) as *const libc::c_void,
            curlx_sotouz(unsafe { (*src).set.postfieldsize }),
        ) as *mut i8;
        if (unsafe { (*dst).set.str_0[i as usize] }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        let mut fresh4 = unsafe { &mut ((*dst).set.postfields) };
        *fresh4 = (unsafe { (*dst).set.str_0[i as usize] }) as *mut libc::c_void;
    }
    result = Curl_mime_duppart(unsafe { &mut (*dst).set.mimepost }, unsafe { &mut (*src).set.mimepost });
    if !(unsafe { (*src).set.resolve }).is_null() {
        let mut fresh5 = unsafe { &mut ((*dst).state.resolve) };
        *fresh5 = unsafe { (*dst).set.resolve };
    }
    return result;
}
#[no_mangle]
pub extern "C" fn curl_easy_duphandle(
    mut data: *mut crate::src::lib::http2::Curl_easy,
) -> *mut crate::src::lib::http2::Curl_easy {
    let mut current_block: u64;
    let mut outcurl: *mut crate::src::lib::http2::Curl_easy = (unsafe { Curl_ccalloc
        .expect("non-null function pointer")(
        1 as i32 as size_t,
        ::std::mem::size_of::<Curl_easy>() as u64,
    ) }) as *mut Curl_easy;
    if !outcurl.is_null() {
        (unsafe { (*outcurl).set.buffer_size = (*data).set.buffer_size });
        if !(dupset(outcurl, data) as u64 != 0) {
            Curl_dyn_init(
                unsafe { &mut (*outcurl).state.headerb },
                (100 as i32 * 1024 as i32) as size_t,
            );
            let mut fresh6 = unsafe { &mut ((*outcurl).state.conn_cache) };
            *fresh6 = 0 as *mut conncache;
            (unsafe { (*outcurl).state.lastconnect_id = -(1 as i32) as i64 });
            (unsafe { (*outcurl).progress.flags = (*data).progress.flags });
            let mut fresh7 = unsafe { &mut ((*outcurl).progress) };
            (*fresh7).set_callback(unsafe { ((*data).progress).callback() });
            if !(unsafe { (*data).cookies }).is_null() {
                let mut fresh8 = unsafe { &mut ((*outcurl).cookies) };
                *fresh8 = Curl_cookie_init(
                    data,
                    unsafe { (*(*data).cookies).filename },
                    unsafe { (*outcurl).cookies },
                    (unsafe { ((*data).set).cookiesession() }) != 0,
                );
                if (unsafe { (*outcurl).cookies }).is_null() {
                    current_block = 12715656406826180841;
                } else {
                    current_block = 17965632435239708295;
                }
            } else {
                current_block = 17965632435239708295;
            }
            match current_block {
                12715656406826180841 => {}
                _ => {
                    if !(unsafe { (*data).state.cookielist }).is_null() {
                        let mut fresh9 = unsafe { &mut ((*outcurl).state.cookielist) };
                        *fresh9 = Curl_slist_duplicate(unsafe { (*data).state.cookielist });
                        if (unsafe { (*outcurl).state.cookielist }).is_null() {
                            current_block = 12715656406826180841;
                        } else {
                            current_block = 8236137900636309791;
                        }
                    } else {
                        current_block = 8236137900636309791;
                    }
                    match current_block {
                        12715656406826180841 => {}
                        _ => {
                            if !(unsafe { (*data).state.url }).is_null() {
                                let mut fresh10 = unsafe { &mut ((*outcurl).state.url) };
                                *fresh10 = unsafe { Curl_cstrdup.expect("non-null function pointer")(
                                    (*data).state.url,
                                ) };
                                if (unsafe { (*outcurl).state.url }).is_null() {
                                    current_block = 12715656406826180841;
                                } else {
                                    let mut fresh11 = unsafe { &mut ((*outcurl).state) };
                                    (*fresh11).set_url_alloc(1 as i32 as bit);
                                    current_block = 13242334135786603907;
                                }
                            } else {
                                current_block = 13242334135786603907;
                            }
                            match current_block {
                                12715656406826180841 => {}
                                _ => {
                                    if !(unsafe { (*data).state.referer }).is_null() {
                                        let mut fresh12 = unsafe { &mut ((*outcurl).state.referer) };
                                        *fresh12 = unsafe { Curl_cstrdup.expect("non-null function pointer")(
                                            (*data).state.referer,
                                        ) };
                                        if (unsafe { (*outcurl).state.referer }).is_null() {
                                            current_block = 12715656406826180841;
                                        } else {
                                            let mut fresh13 = unsafe { &mut ((*outcurl).state) };
                                            (*fresh13).set_referer_alloc(1 as i32 as bit);
                                            current_block = 11298138898191919651;
                                        }
                                    } else {
                                        current_block = 11298138898191919651;
                                    }
                                    match current_block {
                                        12715656406826180841 => {}
                                        _ => {
                                            if !(unsafe { (*outcurl).set.str_0
                                                [STRING_SSL_ENGINE as i32 as usize] })
                                                .is_null()
                                            {
                                                if Curl_ssl_set_engine(
                                                    outcurl,
                                                    unsafe { (*outcurl).set.str_0
                                                        [STRING_SSL_ENGINE as i32 as usize] },
                                                )
                                                    as u64
                                                    != 0
                                                {
                                                    current_block = 12715656406826180841;
                                                } else {
                                                    current_block = 4068382217303356765;
                                                }
                                            } else {
                                                current_block = 4068382217303356765;
                                            }
                                            match current_block {
                                                12715656406826180841 => {}
                                                _ => {
                                                    if !(unsafe { (*data).hsts }).is_null() {
                                                        let mut fresh14 = unsafe { &mut ((*outcurl).hsts) };
                                                        *fresh14 = Curl_hsts_init();
                                                        if (unsafe { (*outcurl).hsts }).is_null() {
                                                            current_block = 12715656406826180841;
                                                        } else {
                                                            if !(unsafe { (*outcurl).set.str_0
                                                                [STRING_HSTS as i32 as usize] })
                                                                .is_null()
                                                            {
                                                                Curl_hsts_loadfile(
                                                                    outcurl,
                                                                    unsafe { (*outcurl).hsts },
                                                                    unsafe { (*outcurl).set.str_0[STRING_HSTS
                                                                        as i32
                                                                        as usize] },
                                                                );
                                                            }
                                                            Curl_hsts_loadcb(
                                                                outcurl,
                                                                unsafe { (*outcurl).hsts },
                                                            );
                                                            current_block = 18377268871191777778;
                                                        }
                                                    } else {
                                                        current_block = 18377268871191777778;
                                                    }
                                                    match current_block {
                                                        12715656406826180841 => {}
                                                        _ => {
                                                            if !(Curl_resolver_duphandle(
                                                                outcurl,
                                                                Some(
                                                                    unsafe { &mut (*outcurl)
                                                                        .state
                                                                        .async_0
                                                                        .resolver },
                                                                ),
                                                                unsafe { (*data).state.async_0.resolver },
                                                            )
                                                                as u64
                                                                != 0)
                                                            {
                                                                Curl_initinfo(outcurl);
                                                                (unsafe { (*outcurl).magic =
                                                                    0xc0dedbad as u32 });
                                                                return outcurl;
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
    if !outcurl.is_null() {
        curl_slist_free_all(unsafe { (*outcurl).state.cookielist });
        let mut fresh15 = unsafe { &mut ((*outcurl).state.cookielist) };
        *fresh15 = 0 as *mut curl_slist;
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            (*outcurl).state.buffer as *mut libc::c_void,
        ) });
        let mut fresh16 = unsafe { &mut ((*outcurl).state.buffer) };
        *fresh16 = 0 as *mut i8;
        Curl_dyn_free(unsafe { &mut (*outcurl).state.headerb });
        (unsafe { Curl_cfree.expect("non-null function pointer")((*outcurl).state.url as *mut libc::c_void) });
        let mut fresh17 = unsafe { &mut ((*outcurl).state.url) };
        *fresh17 = 0 as *mut i8;
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            (*outcurl).state.referer as *mut libc::c_void,
        ) });
        let mut fresh18 = unsafe { &mut ((*outcurl).state.referer) };
        *fresh18 = 0 as *mut i8;
        Curl_altsvc_cleanup(Some(unsafe { &mut (*outcurl).asi }));
        Curl_hsts_cleanup(Some(unsafe { &mut (*outcurl).hsts }));
        Curl_freeset(outcurl);
        (unsafe { Curl_cfree.expect("non-null function pointer")(outcurl as *mut libc::c_void) });
    }
    return 0 as *mut CURL;
}
#[no_mangle]
pub extern "C" fn curl_easy_reset(mut data: *mut crate::src::lib::http2::Curl_easy) {
    Curl_free_request_state(data);
    Curl_freeset(data);
    (unsafe { memset(
        &mut (*data).set as *mut UserDefined as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<UserDefined>() as u64,
    ) });
    Curl_init_userdefined(data);
    (unsafe { memset(
        &mut (*data).progress as *mut Progress as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<Progress>() as u64,
    ) });
    Curl_initinfo(data);
    (unsafe { (*data).progress.flags |= (1 as i32) << 4 as i32 });
    (unsafe { (*data).state.current_speed = -(1 as i32) as curl_off_t });
    (unsafe { (*data).state.retrycount = 0 as i32 });
    (unsafe { memset(
        &mut (*data).state.authhost as *mut auth as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<auth>() as u64,
    ) });
    (unsafe { memset(
        &mut (*data).state.authproxy as *mut auth as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<auth>() as u64,
    ) });
    Curl_http_auth_cleanup_digest(data);
}
#[no_mangle]
pub extern "C" fn curl_easy_pause(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut action: i32,
) -> u32 {
    let mut k: Option<&'_ mut crate::src::lib::http2::SingleRequest> =
        Option::<&'_ mut crate::src::lib::http2::SingleRequest>::None;
    let mut result: u32 = CURLE_OK;
    let mut oldstate: i32 = 0;
    let mut newstate: i32 = 0;
    if !(!data.is_null() && (unsafe { (*data).magic }) == 0xc0dedbad as u32) || (unsafe { (*data).conn }).is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    k = Some(unsafe { &mut (*data).req });
    oldstate = (*(borrow(&k)).unwrap()).keepon & ((1 as i32) << 4 as i32 | (1 as i32) << 5 as i32);
    newstate = (*(borrow(&k)).unwrap()).keepon & !((1 as i32) << 4 as i32 | (1 as i32) << 5 as i32)
        | (if action & (1 as i32) << 0 as i32 != 0 {
            (1 as i32) << 4 as i32
        } else {
            0 as i32
        })
        | (if action & (1 as i32) << 2 as i32 != 0 {
            (1 as i32) << 5 as i32
        } else {
            0 as i32
        });
    if newstate & ((1 as i32) << 4 as i32 | (1 as i32) << 5 as i32) == oldstate {
        return CURLE_OK;
    }
    if (*(borrow(&k)).unwrap()).keepon & !newstate & (1 as i32) << 5 as i32 != 0
        && ((unsafe { (*data).mstate }) as u32 == MSTATE_PERFORMING as i32 as u32
            || (unsafe { (*data).mstate }) as u32 == MSTATE_RATELIMITING as i32 as u32)
        && (unsafe { (*data).state.fread_func }).map(|f| f as usize)
            == (unsafe { core::intrinsics::transmute::<
                Option<
                    unsafe extern "C" fn(
                        _: *mut i8,
                        _: u64,
                        _: u64,
                        _: *mut core::ffi::c_void,
                    ) -> u64,
                >,
                Option<
                    unsafe extern "C" fn(
                        _: *mut i8,
                        _: u64,
                        _: u64,
                        _: *mut core::ffi::c_void,
                    ) -> u64,
                >,
            >(Some(Curl_mime_read)) })
            .map(|f| f as usize)
    {
        Curl_mime_unpause((unsafe { (*data).state.in_0 }) as *mut curl_mimepart);
    }
    (*(borrow_mut(&mut k)).unwrap()).keepon = newstate;
    if newstate & (1 as i32) << 4 as i32 == 0 {
        Curl_http2_stream_pause(data, 0 as i32 != 0);
        if (unsafe { (*data).state.tempcount }) != 0 {
            let mut i: u32 = 0;
            let mut count: u32 = unsafe { (*data).state.tempcount };
            let mut writebuf: Option<
                crate::__laertes_array::CustomSlice<
                    'static,
                    crate::src::lib::http2::tempbuf,
                    [crate::src::lib::http2::tempbuf; 3],
                >,
            > = Some(crate::__laertes_array::CustomSlice::new(
                [tempbuf {
                    b: dynbuf {
                        bufr: 0 as *mut i8,
                        leng: 0,
                        allc: 0,
                        toobig: 0,
                    },
                    type_0: 0,
                }; 3],
            ));
            i = 0 as i32 as u32;
            while i < (unsafe { (*data).state.tempcount }) {
                (*crate::__laertes_array::GetMut::<&mut _>::get_add_mut(
                    (writebuf).as_mut().unwrap(),
                    i as usize,
                )) = unsafe { (*data).state.tempwrite[i as usize] };
                Curl_dyn_init(
                    unsafe { &mut (*((*data).state.tempwrite).as_mut_ptr().offset(i as isize)).b },
                    (64 as i32 * 1024 as i32 * 1024 as i32) as size_t,
                );
                i = i.wrapping_add(1);
            }
            (unsafe { (*data).state.tempcount = 0 as i32 as u32 });
            i = 0 as i32 as u32;
            while i < count {
                if result as u64 == 0 {
                    result = Curl_client_write(
                        data,
                        (*crate::__laertes_array::Get::<&_>::get_add(
                            (writebuf).as_ref().unwrap(),
                            i as usize,
                        ))
                        .type_0,
                        Curl_dyn_ptr(
                            &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                                writebuf.as_mut().unwrap(),
                                i as isize,
                            ))
                            .b,
                        ),
                        Curl_dyn_len(
                            &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                                writebuf.as_mut().unwrap(),
                                i as isize,
                            ))
                            .b,
                        ),
                    );
                }
                Curl_dyn_free(
                    &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                        writebuf.as_mut().unwrap(),
                        i as isize,
                    ))
                    .b,
                );
                i = i.wrapping_add(1);
            }
            if result as u64 != 0 {
                return result;
            }
        }
    }
    if newstate & ((1 as i32) << 4 as i32 | (1 as i32) << 5 as i32)
        != (1 as i32) << 4 as i32 | (1 as i32) << 5 as i32
    {
        Curl_expire(data, 0 as i32 as timediff_t, EXPIRE_RUN_NOW);
        (unsafe { (*data).state.keeps_speed.tv_sec = 0 as i32 as time_t });
        if (unsafe { (*data).state.tempcount }) == 0 {
            (unsafe { (*(*data).conn).cselect_bits = 0x1 as i32 | 0x2 as i32 });
        }
        if !(unsafe { (*data).multi }).is_null() {
            Curl_update_timer(unsafe { (*data).multi });
        }
    }
    if (unsafe { ((*data).state).done() }) == 0 {
        Curl_updatesocket(data);
    }
    return result;
}
extern "C" fn easy_connection<'a1, 'a2>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut sfd: Option<&'a1 mut i32>,
    mut connp: Option<&'a2 mut *mut crate::src::lib::http2::connectdata>,
) -> u32 {
    if data.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if (unsafe { ((*data).set).connect_only() }) == 0 {
        (unsafe { Curl_failf(
            data,
            b"CONNECT_ONLY is required!\0" as *const u8 as *const i8,
        ) });
        return CURLE_UNSUPPORTED_PROTOCOL;
    }
    *(borrow_mut(&mut sfd)).unwrap() = Curl_getconnectinfo(data, borrow_mut(&mut connp));
    if *(borrow(&sfd)).unwrap() == -(1 as i32) {
        (unsafe { Curl_failf(
            data,
            b"Failed to get recent socket\0" as *const u8 as *const i8,
        ) });
        return CURLE_UNSUPPORTED_PROTOCOL;
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn curl_easy_recv<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut buffer: *mut core::ffi::c_void,
    mut buflen: u64,
    mut n: Option<&'a1 mut u64>,
) -> u32 {
    let mut sfd: i32 = 0;
    let mut result: u32 = CURLE_OK;
    let mut n1: i64 = 0;
    let mut c: *mut crate::src::lib::http2::connectdata = 0 as *mut connectdata;
    if Curl_is_in_callback(data) {
        return CURLE_RECURSIVE_API_CALL;
    }
    result = easy_connection(data, Some(&mut sfd), Some(&mut c));
    if result as u64 != 0 {
        return result;
    }
    if (unsafe { (*data).conn }).is_null() {
        Curl_attach_connnection(data, c);
    }
    *(borrow_mut(&mut n)).unwrap() = 0 as i32 as size_t;
    result = Curl_read(data, sfd, buffer as *mut i8, buflen, Some(&mut n1));
    if result as u64 != 0 {
        return result;
    }
    *(borrow_mut(&mut n)).unwrap() = n1 as size_t;
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn curl_easy_send<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut buffer: *const core::ffi::c_void,
    mut buflen: u64,
    mut n: Option<&'a1 mut u64>,
) -> u32 {
    let mut sfd: i32 = 0;
    let mut result: u32 = CURLE_OK;
    let mut n1: i64 = 0;
    let mut c: *mut crate::src::lib::http2::connectdata = 0 as *mut connectdata;
    let mut pipe_st: crate::src::lib::conncache::sigpipe_ignore = sigpipe_ignore {
        old_pipe_act: sigaction {
            __sigaction_handler: C2RustUnnamed_6 { sa_handler: None },
            sa_mask: __sigset_t { __val: [0; 16] },
            sa_flags: 0,
            sa_restorer: None,
        },
        no_signal: false,
    };
    if Curl_is_in_callback(data) {
        return CURLE_RECURSIVE_API_CALL;
    }
    result = easy_connection(data, Some(&mut sfd), Some(&mut c));
    if result as u64 != 0 {
        return result;
    }
    if (unsafe { (*data).conn }).is_null() {
        Curl_attach_connnection(data, c);
    }
    *(borrow_mut(&mut n)).unwrap() = 0 as i32 as size_t;
    sigpipe_ignore(data, Some(&mut pipe_st));
    result = Curl_write(data, sfd, buffer, buflen, Some(&mut n1));
    sigpipe_restore(Some(&mut pipe_st));
    if n1 == -(1 as i32) as i64 {
        return CURLE_SEND_ERROR;
    }
    if result as u64 == 0 && n1 == 0 {
        return CURLE_AGAIN;
    }
    *(borrow_mut(&mut n)).unwrap() = n1 as size_t;
    return result;
}
extern "C" fn conn_upkeep(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut _param: *mut core::ffi::c_void,
) -> i32 {
    if unsafe { ((*(*conn).handler).connection_check).is_some() } {
        Curl_attach_connnection(data, conn);
        (unsafe { ((*(*conn).handler).connection_check).expect("non-null function pointer")(
            data,
            conn,
            ((1 as i32) << 1 as i32) as u32,
        ) });
        Curl_detach_connnection(data);
    }
    return 0 as i32;
}
extern "C" fn upkeep(
    mut conn_cache: *mut crate::src::lib::http2::conncache,
    mut data: *mut core::ffi::c_void,
) -> u32 {
    Curl_conncache_foreach(data as *mut Curl_easy, conn_cache, data, Some(conn_upkeep));
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn curl_easy_upkeep(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    if !(!data.is_null() && (unsafe { (*data).magic }) == 0xc0dedbad as u32) {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if !(unsafe { (*data).multi_easy }).is_null() {
        return upkeep(
            unsafe { &mut (*(*data).multi_easy).conn_cache },
            data as *mut libc::c_void,
        );
    } else {
        return CURLE_OK;
    };
}
use crate::laertes_rt::*;
