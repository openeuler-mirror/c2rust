use :: c2rust_bitfields;
use :: libc;
extern "C" {
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strncpy(_: *mut i8, _: *const i8, _: u64) -> *mut i8;
    fn strncmp(_: *const i8, _: *const i8, _: u64) -> i32;
    fn bind(__fd: i32, __addr: *const crate::src::lib::http2::sockaddr, __len: u32) -> i32;
    fn getsockname(
        __fd: i32,
        __addr: *mut crate::src::lib::http2::sockaddr,
        __len: *mut u32,
    ) -> i32;
    fn listen(__fd: i32, __n: i32) -> i32;
    fn accept(
        __fd: i32,
        __addr: *mut crate::src::lib::http2::sockaddr,
        __addr_len: *mut u32,
    ) -> i32;
    fn sscanf(_: *const i8, _: *const i8, _: ...) -> i32;
    fn strtol(_: *const i8, _: *mut *mut i8, _: i32) -> i64;
    fn strtoul(_: *const i8, _: *mut *mut i8, _: i32) -> u64;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strrchr(_: *const i8, _: i32) -> *mut i8;
    fn strstr(_: *const i8, _: *const i8) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn __errno_location() -> *mut i32;
    fn inet_pton(__af: i32, __cp: *const i8, __buf: *mut core::ffi::c_void) -> i32;
    fn inet_ntop(
        __af: i32,
        __cp: *const core::ffi::c_void,
        __buf: *mut i8,
        __len: u32,
    ) -> *const i8;
}
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::asyn_thread::Curl_resolver_wait_resolv;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::connect::Curl_closesocket;
pub use crate::src::lib::connect::Curl_conn_data_pending;
pub use crate::src::lib::connect::Curl_conncontrol;
pub use crate::src::lib::connect::Curl_connecthost;
pub use crate::src::lib::connect::Curl_conninfo_remote;
pub use crate::src::lib::connect::Curl_is_connected;
pub use crate::src::lib::connect::Curl_socket;
pub use crate::src::lib::connect::Curl_timeleft;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::curl_ctype::Curl_isdigit;
pub use crate::src::lib::curl_range::Curl_range;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::easy::Curl_ccalloc;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_cstrdup;
pub use crate::src::lib::escape::Curl_urldecode;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::ftplistparser::ftp_parselist_data;
pub use crate::src::lib::ftplistparser::Curl_ftp_parselist;
pub use crate::src::lib::ftplistparser::Curl_ftp_parselist_data_alloc;
pub use crate::src::lib::ftplistparser::Curl_ftp_parselist_data_free;
pub use crate::src::lib::ftplistparser::Curl_ftp_parselist_geterror;
pub use crate::src::lib::hostip::Curl_printable_address;
pub use crate::src::lib::hostip::Curl_resolv;
pub use crate::src::lib::hostip::Curl_resolv_unlock;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::http_proxy::Curl_connect_ongoing;
pub use crate::src::lib::http_proxy::Curl_proxyCONNECT;
pub use crate::src::lib::http_proxy::Curl_proxy_connect;
pub use crate::src::lib::if2ip::Curl_if2ip;
pub use crate::src::lib::if2ip::Curl_ipv6_scope;
pub use crate::src::lib::llist::Curl_llist_remove;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::multi::Curl_expire;
pub use crate::src::lib::multi::Curl_set_in_callback;
pub use crate::src::lib::nonblock::curlx_nonblock;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::parsedate::Curl_getdate_capped;
pub use crate::src::lib::parsedate::Curl_gmtime;
pub use crate::src::lib::parsedate::Curl_month;
pub use crate::src::lib::parsedate::Curl_wkday;
pub use crate::src::lib::pingpong::Curl_pp_disconnect;
pub use crate::src::lib::pingpong::Curl_pp_flushsend;
pub use crate::src::lib::pingpong::Curl_pp_getsock;
pub use crate::src::lib::pingpong::Curl_pp_init;
pub use crate::src::lib::pingpong::Curl_pp_readresp;
pub use crate::src::lib::pingpong::Curl_pp_sendf;
pub use crate::src::lib::pingpong::Curl_pp_setup;
pub use crate::src::lib::pingpong::Curl_pp_state_timeout;
pub use crate::src::lib::pingpong::Curl_pp_statemach;
pub use crate::src::lib::progress::Curl_pgrsSetDownloadCounter;
pub use crate::src::lib::progress::Curl_pgrsSetDownloadSize;
pub use crate::src::lib::progress::Curl_pgrsSetUploadCounter;
pub use crate::src::lib::progress::Curl_pgrsSetUploadSize;
pub use crate::src::lib::progress::Curl_pgrsTime;
pub use crate::src::lib::progress::Curl_pgrsUpdate;
pub use crate::src::lib::select::Curl_socket_check;
pub use crate::src::lib::sendf::Curl_client_write;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::socks::Curl_SOCKS_getsock;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::strcase::Curl_raw_toupper;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::strerror::curl_easy_strerror;
pub use crate::src::lib::strerror::Curl_strerror;
pub use crate::src::lib::strtoofft::curlx_strtoofft;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::timeval::Curl_now;
pub use crate::src::lib::timeval::Curl_timediff;
pub use crate::src::lib::transfer::Curl_setup_transfer;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
pub use crate::src::lib::vtls::vtls::Curl_ssl_close;
pub use crate::src::lib::vtls::vtls::Curl_ssl_connect;
pub use crate::src::lib::vtls::vtls::Curl_ssl_shutdown;
pub use crate::src::lib::warnless::curlx_sltosi;
pub use crate::src::lib::warnless::curlx_sotouz;
pub use crate::src::lib::warnless::curlx_ultous;
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
pub type curl_socklen_t = u32;
pub type curl_off_t = i64;
pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::lib::http2::_IO_FILE;
pub type tm = crate::src::lib::altsvc::tm;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct http_connect_state {
    pub http_proxy: crate::src::lib::http2::HTTP,
    pub prot_save: *mut crate::src::lib::http2::HTTP,
    pub rcvbuf: crate::src::lib::http2::dynbuf,
    pub req: crate::src::lib::http2::dynbuf,
    pub nsend: u64,
    pub keepon: u32,
    pub cl: i64,
    pub tunnel_state: u32,
    pub chunked_encoding_close_connection: [u8; 1],
    pub c2rust_padding: [u8; 3],
}
impl http_connect_state {
    pub const fn new() -> Self {
        http_connect_state {
            http_proxy: crate::src::lib::http2::HTTP::new(),
            prot_save: (0 as *mut crate::src::lib::http2::HTTP),
            rcvbuf: crate::src::lib::http2::dynbuf::new(),
            req: crate::src::lib::http2::dynbuf::new(),
            nsend: 0,
            keepon: 0,
            cl: 0,
            tunnel_state: 0,
            chunked_encoding_close_connection: [0],
            c2rust_padding: [0, 0, 0],
        }
    }
}
impl std::default::Default for http_connect_state {
    fn default() -> Self {
        http_connect_state::new()
    }
}
impl http_connect_state {
    #[doc = " This method allows you to write to a bitfield with a value"]
    pub fn set_chunked_encoding(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.chunked_encoding_close_connection;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    #[doc = " This method allows you to read from a bitfield to a value"]
    pub fn chunked_encoding(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.chunked_encoding_close_connection;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    #[doc = " This method allows you to write to a bitfield with a value"]
    pub fn set_close_connection(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.chunked_encoding_close_connection;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    #[doc = " This method allows you to read from a bitfield to a value"]
    pub fn close_connection(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.chunked_encoding_close_connection;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
}
pub type C2RustUnnamed_4 = u32;
pub const TUNNEL_EXIT: C2RustUnnamed_4 = 3;
pub const TUNNEL_COMPLETE: C2RustUnnamed_4 = 2;
pub const TUNNEL_CONNECT: C2RustUnnamed_4 = 1;
pub const TUNNEL_INIT: C2RustUnnamed_4 = 0;
pub type keeponval = u32;
pub const KEEPON_IGNORE: keeponval = 2;
pub const KEEPON_CONNECT: keeponval = 1;
pub const KEEPON_DONE: keeponval = 0;
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
pub type C2RustUnnamed_6 = u32;
pub const TRNSPRT_QUIC: C2RustUnnamed_6 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_6 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_6 = 3;
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
pub type curlfiletype = u32;
pub const CURLFILETYPE_UNKNOWN: curlfiletype = 8;
pub const CURLFILETYPE_DOOR: curlfiletype = 7;
pub const CURLFILETYPE_SOCKET: curlfiletype = 6;
pub const CURLFILETYPE_NAMEDPIPE: curlfiletype = 5;
pub const CURLFILETYPE_DEVICE_CHAR: curlfiletype = 4;
pub const CURLFILETYPE_DEVICE_BLOCK: curlfiletype = 3;
pub const CURLFILETYPE_SYMLINK: curlfiletype = 2;
pub const CURLFILETYPE_DIRECTORY: curlfiletype = 1;
pub const CURLFILETYPE_FILE: curlfiletype = 0;
pub type curl_fileinfo = crate::src::lib::fileinfo::curl_fileinfo;
pub type C2RustUnnamed_7 = crate::src::lib::fileinfo::C2RustUnnamed;
pub type curl_malloc_callback<'a1> =
    Option<unsafe extern "C" fn(_: u64) -> Option<&'a1 mut core::ffi::c_void>>;
pub type curl_strdup_callback<'a1, 'a2> =
    Option<unsafe extern "C" fn(_: Option<&'a1 i8>) -> Option<&'a2 mut i8>>;
pub type curl_calloc_callback<'a1> =
    Option<unsafe extern "C" fn(_: u64, _: u64) -> Option<&'a1 mut core::ffi::c_void>>;
pub type uint16_t = u16;
pub type in_addr_t = u32;
pub type in_addr = crate::src::lib::connect::in_addr;
pub type in_port_t = u16;
pub type in6_addr = crate::src::lib::connect::in6_addr;
pub type C2RustUnnamed_8 = crate::src::lib::connect::C2RustUnnamed_8;
pub type sockaddr_in = crate::src::lib::connect::sockaddr_in;
pub type sockaddr_in6 = crate::src::lib::connect::sockaddr_in6;
pub type resolve_t = i32;
pub const CURLRESOLV_PENDING: resolve_t = 1;
pub const CURLRESOLV_RESOLVED: resolve_t = 0;
pub const CURLRESOLV_ERROR: resolve_t = -1;
pub const CURLRESOLV_TIMEDOUT: resolve_t = -2;
pub const STRING_CUSTOMREQUEST: dupstring = 6;
pub type ftpport = u32;
pub const DONE: ftpport = 2;
pub const PORT: ftpport = 1;
pub const EPRT: ftpport = 0;
pub type Curl_sockaddr_storage = crate::src::lib::connect::Curl_sockaddr_storage;
pub type C2RustUnnamed_9 = crate::src::lib::connect::C2RustUnnamed_9;
pub type Curl_sockaddr_ex = crate::src::lib::connect::Curl_sockaddr_ex;
pub type C2RustUnnamed_10 = crate::src::lib::connect::C2RustUnnamed_10;
pub const IF2IP_FOUND: if2ip_result_t = 2;
pub const IF2IP_AF_NOT_SUPPORTED: if2ip_result_t = 1;
pub const IF2IP_NOT_FOUND: if2ip_result_t = 0;
pub type if2ip_result_t = u32;
pub const STRING_FTPPORT: dupstring = 12;
pub type urlreject = u32;
pub const REJECT_ZERO: urlreject = 4;
pub const REJECT_CTRL: urlreject = 3;
pub const REJECT_NADA: urlreject = 2;
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
pub type CURLofft = u32;
pub const CURL_OFFT_INVAL: CURLofft = 2;
pub const CURL_OFFT_FLOW: CURLofft = 1;
pub const CURL_OFFT_OK: CURLofft = 0;
pub const STRING_FTP_ALTERNATIVE_TO_USER: dupstring = 11;
pub const STRING_FTP_ACCOUNT: dupstring = 10;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ftp_wc {
    pub parser: *mut crate::src::lib::ftplistparser::ftp_parselist_data,
    pub backup: crate::src::lib::ftp::C2RustUnnamed_11,
}
impl ftp_wc {
    pub const fn new() -> Self {
        ftp_wc {
            parser: (0 as *mut crate::src::lib::ftplistparser::ftp_parselist_data),
            backup: crate::src::lib::ftp::C2RustUnnamed_11::new(),
        }
    }
}
impl std::default::Default for ftp_wc {
    fn default() -> Self {
        ftp_wc::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_11 {
    pub write_function:
        Option<unsafe extern "C" fn(_: *mut i8, _: u64, _: u64, _: *mut core::ffi::c_void) -> u64>,
    pub file_descriptor: *mut crate::src::lib::http2::_IO_FILE,
}
impl C2RustUnnamed_11 {
    pub const fn new() -> Self {
        C2RustUnnamed_11 {
            write_function: None,
            file_descriptor: (0 as *mut crate::src::lib::http2::_IO_FILE),
        }
    }
}
impl std::default::Default for C2RustUnnamed_11 {
    fn default() -> Self {
        C2RustUnnamed_11::new()
    }
}
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
pub const STRING_ENCODING: dupstring = 9;
pub const STRING_DEVICE: dupstring = 8;
pub const STRING_DEFAULT_PROTOCOL: dupstring = 7;
pub const STRING_COOKIEJAR: dupstring = 5;
pub const STRING_COOKIE: dupstring = 4;
pub const STRING_CERT_TYPE_PROXY: dupstring = 3;
pub const STRING_CERT_TYPE: dupstring = 2;
pub const STRING_CERT_PROXY: dupstring = 1;
pub const STRING_CERT: dupstring = 0;
#[inline]
extern "C" fn __bswap_16(mut __bsx: u16) -> u16 {
    return (__bsx as i32 >> 8 as i32 & 0xff as i32 | (__bsx as i32 & 0xff as i32) << 8 as i32)
        as __uint16_t;
}
#[no_mangle]
pub static mut Curl_handler_ftp: crate::src::lib::http2::Curl_handler =  {
    {
        let mut init = Curl_handler {
            scheme: b"FTP\0" as *const u8 as *const i8,
            setup_connection: Some(ftp_setup_connection),
            do_it: Some(ftp_do),
            done: Some(ftp_done),
            do_more: Some(ftp_do_more),
            connect_it: Some(ftp_connect),
            connecting: Some(ftp_multi_statemach),
            doing: Some(ftp_doing),
            proto_getsock: Some(ftp_getsock),
            doing_getsock: Some(ftp_getsock),
            domore_getsock: Some(ftp_domore_getsock),
            perform_getsock: None,
            disconnect: Some(ftp_disconnect),
            readwrite: None,
            connection_check: None,
            attach: None,
            defport: 21 as i32,
            protocol: ((1 as i32) << 2 as i32) as u32,
            family: ((1 as i32) << 2 as i32) as u32,
            flags: ((1 as i32) << 1 as i32
                | (1 as i32) << 2 as i32
                | (1 as i32) << 5 as i32
                | (1 as i32) << 6 as i32
                | (1 as i32) << 11 as i32
                | (1 as i32) << 12 as i32) as u32,
        };
        init
    }
};
#[no_mangle]
pub static mut Curl_handler_ftps: crate::src::lib::http2::Curl_handler =  {
    {
        let mut init = Curl_handler {
            scheme: b"FTPS\0" as *const u8 as *const i8,
            setup_connection: Some(ftp_setup_connection),
            do_it: Some(ftp_do),
            done: Some(ftp_done),
            do_more: Some(ftp_do_more),
            connect_it: Some(ftp_connect),
            connecting: Some(ftp_multi_statemach),
            doing: Some(ftp_doing),
            proto_getsock: Some(ftp_getsock),
            doing_getsock: Some(ftp_getsock),
            domore_getsock: Some(ftp_domore_getsock),
            perform_getsock: None,
            disconnect: Some(ftp_disconnect),
            readwrite: None,
            connection_check: None,
            attach: None,
            defport: 990 as i32,
            protocol: ((1 as i32) << 3 as i32) as u32,
            family: ((1 as i32) << 2 as i32) as u32,
            flags: ((1 as i32) << 0 as i32
                | (1 as i32) << 1 as i32
                | (1 as i32) << 2 as i32
                | (1 as i32) << 5 as i32
                | (1 as i32) << 6 as i32
                | (1 as i32) << 12 as i32) as u32,
        };
        init
    }
};
extern "C" fn close_secondarysocket(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) {
    if -(1 as i32) != (unsafe { (*conn).sock[1 as i32 as usize] }) {
        Curl_closesocket(data, conn, unsafe { (*conn).sock[1 as i32 as usize] });
        (unsafe { (*conn).sock[1 as i32 as usize] = -(1 as i32) });
    }
    (unsafe { (*conn).bits.tcpconnect[1 as i32 as usize] = 0 as i32 != 0 });
    (unsafe { (*conn).bits.proxy_ssl_connected[1 as i32 as usize] = 0 as i32 != 0 });
}
extern "C" fn freedirs(mut ftpc: *mut crate::src::lib::http2::ftp_conn) {
    if !(unsafe { (*ftpc).dirs }).is_null() {
        let mut i: i32 = 0;
        i = 0 as i32;
        while i < (unsafe { (*ftpc).dirdepth }) {
            (unsafe { Curl_cfree.expect("non-null function pointer")(
                *((*ftpc).dirs).offset(i as isize) as *mut libc::c_void
            ) });
            let mut fresh0 = unsafe { &mut (*((*ftpc).dirs).offset(i as isize)) };
            *fresh0 = 0 as *mut i8;
            i += 1;
        }
        (unsafe { Curl_cfree.expect("non-null function pointer")((*ftpc).dirs as *mut libc::c_void) });
        let mut fresh1 = unsafe { &mut ((*ftpc).dirs) };
        *fresh1 = 0 as *mut *mut i8;
        (unsafe { (*ftpc).dirdepth = 0 as i32 });
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")((*ftpc).file as *mut libc::c_void) });
    let mut fresh2 = unsafe { &mut ((*ftpc).file) };
    *fresh2 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*ftpc).newhost as *mut libc::c_void) });
    let mut fresh3 = unsafe { &mut ((*ftpc).newhost) };
    *fresh3 = 0 as *mut i8;
}
extern "C" fn AcceptServerConnect(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut sock: i32 = unsafe { (*conn).sock[1 as i32 as usize] };
    let mut s: i32 = -(1 as i32);
    let mut add: crate::src::lib::connect::Curl_sockaddr_storage = Curl_sockaddr_storage {
        buffer: C2RustUnnamed_9 {
            sa: sockaddr {
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    };
    let mut size: u32 = ::std::mem::size_of::<Curl_sockaddr_storage>() as u64 as curl_socklen_t;
    if 0 as i32
        == (unsafe { getsockname(
            sock,
            &mut add as *mut Curl_sockaddr_storage as *mut sockaddr,
            &mut size,
        ) })
    {
        size = ::std::mem::size_of::<Curl_sockaddr_storage>() as u64 as curl_socklen_t;
        s = unsafe { accept(
            sock,
            &mut add as *mut Curl_sockaddr_storage as *mut sockaddr,
            &mut size,
        ) };
    }
    Curl_closesocket(data, conn, sock);
    if -(1 as i32) == s {
        (unsafe { Curl_failf(
            data,
            b"Error accept()ing server connect\0" as *const u8 as *const i8,
        ) });
        return CURLE_FTP_PORT_FAILED;
    }
    (unsafe { Curl_infof(
        data,
        b"Connection accepted from server\0" as *const u8 as *const i8,
    ) });
    let mut fresh4 = unsafe { &mut ((*conn).bits) };
    (*fresh4).set_do_more(0 as i32 as bit);
    (unsafe { (*conn).sock[1 as i32 as usize] = s });
    curlx_nonblock(s, 1 as i32);
    let mut fresh5 = unsafe { &mut ((*conn).bits) };
    (*fresh5).set_sock_accepted(1 as i32 as bit);
    if unsafe { ((*data).set.fsockopt).is_some() } {
        let mut error: i32 = 0 as i32;
        Curl_set_in_callback(data, 1 as i32 != 0);
        error = unsafe { ((*data).set.fsockopt).expect("non-null function pointer")(
            (*data).set.sockopt_client,
            s,
            CURLSOCKTYPE_ACCEPT,
        ) };
        Curl_set_in_callback(data, 0 as i32 != 0);
        if error != 0 {
            close_secondarysocket(data, conn);
            return CURLE_ABORTED_BY_CALLBACK;
        }
    }
    return CURLE_OK;
}
extern "C" fn ftp_timeleft_accept(mut data: *mut crate::src::lib::http2::Curl_easy) -> i64 {
    let mut timeout_ms: i64 = 60000 as i32 as timediff_t;
    let mut other: i64 = 0;
    let mut now: crate::src::lib::http2::curltime = curltime {
        tv_sec: 0,
        tv_usec: 0,
    };
    if (unsafe { (*data).set.accepttimeout }) > 0 as i32 as i64 {
        timeout_ms = unsafe { (*data).set.accepttimeout };
    }
    now = Curl_now();
    other = Curl_timeleft(data, &mut now, 0 as i32 != 0);
    if other != 0 && other < timeout_ms {
        timeout_ms = other;
    } else {
        timeout_ms -= Curl_timediff(now, unsafe { (*data).progress.t_acceptdata });
        if timeout_ms == 0 {
            return -(1 as i32) as timediff_t;
        }
    }
    return timeout_ms;
}
extern "C" fn ReceivedServerConnect<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut received: Option<&'a1 mut bool>,
) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ctrl_sock: i32 = unsafe { (*conn).sock[0 as i32 as usize] };
    let mut data_sock: i32 = unsafe { (*conn).sock[1 as i32 as usize] };
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    let mut pp: Option<&'_ mut crate::src::lib::http2::pingpong> =
        Some(&mut (*(borrow_mut(&mut ftpc)).unwrap()).pp);
    let mut result: i32 = 0;
    let mut timeout_ms: i64 = 0;
    let mut nread: i64 = 0;
    let mut ftpcode: i32 = 0;
    *(borrow_mut(&mut received)).unwrap() = 0 as i32 != 0;
    timeout_ms = ftp_timeleft_accept(data);
    (unsafe { Curl_infof(
        data,
        b"Checking for server connect\0" as *const u8 as *const i8,
    ) });
    if timeout_ms < 0 as i32 as i64 {
        (unsafe { Curl_failf(
            data,
            b"Accept timeout occurred while waiting server connect\0" as *const u8 as *const i8,
        ) });
        return CURLE_FTP_ACCEPT_TIMEOUT;
    }
    if (*(borrow(&pp)).unwrap()).cache_size != 0
        && !((*(borrow(&pp)).unwrap()).cache).is_null()
        && (unsafe { *((*(borrow(&pp)).unwrap()).cache).offset(0 as i32 as isize) }) as i32 > '3' as i32
    {
        (unsafe { Curl_infof(
            data,
            b"There is negative response in cache while serv connect\0" as *const u8 as *const i8,
        ) });
        Curl_GetFTPResponse(data, Some(&mut nread), &mut ftpcode);
        return CURLE_FTP_ACCEPT_FAILED;
    }
    result = Curl_socket_check(ctrl_sock, data_sock, -(1 as i32), 0 as i32 as timediff_t);
    match result {
        -1 => {
            (unsafe { Curl_failf(
                data,
                b"Error while waiting for server connect\0" as *const u8 as *const i8,
            ) });
            return CURLE_FTP_ACCEPT_FAILED;
        }
        0 => {}
        _ => {
            if result & (0x4 as i32) << 1 as i32 != 0 {
                (unsafe { Curl_infof(
                    data,
                    b"Ready to accept data connection from server\0" as *const u8 as *const i8,
                ) });
                *(borrow_mut(&mut received)).unwrap() = 1 as i32 != 0;
            } else if result & 0x1 as i32 != 0 {
                (unsafe { Curl_infof(
                    data,
                    b"Ctrl conn has data while waiting for data conn\0" as *const u8 as *const i8,
                ) });
                Curl_GetFTPResponse(data, Some(&mut nread), &mut ftpcode);
                if ftpcode / 100 as i32 > 3 as i32 {
                    return CURLE_FTP_ACCEPT_FAILED;
                }
                return CURLE_WEIRD_SERVER_REPLY;
            }
        }
    }
    return CURLE_OK;
}
extern "C" fn InitiateTransfer(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    if (unsafe { ((*conn).bits).ftp_use_data_ssl() }) != 0 {
        (unsafe { Curl_infof(
            data,
            b"Doing the SSL/TLS handshake on the data stream\0" as *const u8 as *const i8,
        ) });
        result = Curl_ssl_connect(data, conn, 1 as i32);
        if result as u64 != 0 {
            return result;
        }
    }
    if (unsafe { (*conn).proto.ftpc.state_saved }) as u32 == FTP_STOR as i32 as u32 {
        Curl_pgrsSetUploadSize(data, unsafe { (*data).state.infilesize });
        Curl_setup_transfer(
            data,
            -(1 as i32),
            -(1 as i32) as curl_off_t,
            0 as i32 != 0,
            1 as i32,
        );
    } else {
        Curl_setup_transfer(
            data,
            1 as i32,
            unsafe { (*conn).proto.ftpc.retr_size_saved },
            0 as i32 != 0,
            -(1 as i32),
        );
    }
    (unsafe { (*conn).proto.ftpc.pp.pending_resp = 1 as i32 != 0 });
    _state(data, FTP_STOP);
    return CURLE_OK;
}
extern "C" fn AllowServerConnect<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut connected: Option<&'a1 mut bool>,
) -> u32 {
    let mut timeout_ms: i64 = 0;
    let mut result: u32 = CURLE_OK;
    *(borrow_mut(&mut connected)).unwrap() = 0 as i32 != 0;
    (unsafe { Curl_infof(
        data,
        b"Preparing for accepting server on data port\0" as *const u8 as *const i8,
    ) });
    Curl_pgrsTime(data, TIMER_STARTACCEPT);
    timeout_ms = ftp_timeleft_accept(data);
    if timeout_ms < 0 as i32 as i64 {
        (unsafe { Curl_failf(
            data,
            b"Accept timeout occurred while waiting server connect\0" as *const u8 as *const i8,
        ) });
        return CURLE_FTP_ACCEPT_TIMEOUT;
    }
    result = ReceivedServerConnect(data, borrow_mut(&mut connected));
    if result as u64 != 0 {
        return result;
    }
    if *(borrow(&connected)).unwrap() {
        result = AcceptServerConnect(data);
        if result as u64 != 0 {
            return result;
        }
        result = InitiateTransfer(data);
        if result as u64 != 0 {
            return result;
        }
    } else if *(borrow(&connected)).unwrap() as i32 == 0 as i32 {
        Curl_expire(
            data,
            if (unsafe { (*data).set.accepttimeout }) > 0 as i32 as i64 {
                unsafe { (*data).set.accepttimeout }
            } else {
                60000 as i32 as i64
            },
            EXPIRE_100_TIMEOUT,
        );
    }
    return result;
}
extern "C" fn ftp_endofresp(
    mut _data: *mut crate::src::lib::http2::Curl_easy,
    mut _conn: *mut crate::src::lib::http2::connectdata,
    mut line: *mut i8,
    mut len: u64,
    mut code: *mut i32,
) -> bool {
    if len > 3 as i32 as u64
        && (Curl_isdigit((unsafe { *line.offset(0 as i32 as isize) }) as u8 as i32) != 0
            && Curl_isdigit((unsafe { *line.offset(1 as i32 as isize) }) as u8 as i32) != 0
            && Curl_isdigit((unsafe { *line.offset(2 as i32 as isize) }) as u8 as i32) != 0
            && ' ' as i32 == (unsafe { *line.offset(3 as i32 as isize) }) as i32)
    {
        (unsafe { *code = curlx_sltosi(strtol(line, 0 as *mut *mut i8, 10 as i32)) });
        return 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
extern "C" fn ftp_readresp<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut sockfd: i32,
    mut pp: *mut crate::src::lib::http2::pingpong,
    mut ftpcode: *mut i32,
    mut size: Option<&'a1 mut u64>,
) -> u32 {
    let mut code: i32 = 0;
    let mut result: u32 = Curl_pp_readresp(data, sockfd, pp, &mut code, borrow_mut(&mut size));
    (unsafe { (*data).info.httpcode = code });
    if !ftpcode.is_null() {
        (unsafe { *ftpcode = code });
    }
    if 421 as i32 == code {
        (unsafe { Curl_infof(data, b"We got a 421 - timeout!\0" as *const u8 as *const i8) });
        _state(data, FTP_STOP);
        return CURLE_OPERATION_TIMEDOUT;
    }
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_GetFTPResponse<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut nreadp: Option<&'a1 mut i64>,
    mut ftpcode: *mut i32,
) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut sockfd: i32 = unsafe { (*conn).sock[0 as i32 as usize] };
    let mut result: u32 = CURLE_OK;
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    let mut pp: *mut crate::src::lib::http2::pingpong = &mut (*(borrow_mut(&mut ftpc)).unwrap()).pp;
    let mut nread: u64 = 0;
    let mut cache_skip: i32 = 0 as i32;
    let mut value_to_be_ignored: i32 = 0 as i32;
    if !ftpcode.is_null() {
        (unsafe { *ftpcode = 0 as i32 });
    } else {
        ftpcode = &mut value_to_be_ignored;
    }
    *(borrow_mut(&mut nreadp)).unwrap() = 0 as i32 as ssize_t;
    let mut current_block_20: u64;
    while (unsafe { *ftpcode }) == 0 && result as u64 == 0 {
        let mut timeout: i64 = Curl_pp_state_timeout(data, pp, 0 as i32 != 0);
        let mut interval_ms: i64 = 0;
        if timeout <= 0 as i32 as i64 {
            (unsafe { Curl_failf(data, b"FTP response timeout\0" as *const u8 as *const i8) });
            return CURLE_OPERATION_TIMEDOUT;
        }
        interval_ms = 1000 as i32 as timediff_t;
        if timeout < interval_ms {
            interval_ms = timeout;
        }
        if !(!(unsafe { (*pp).cache }).is_null() && cache_skip < 2 as i32) {
            if !Curl_conn_data_pending(conn, 0 as i32) {
                match Curl_socket_check(sockfd, -(1 as i32), -(1 as i32), interval_ms) {
                    -1 => {
                        current_block_20 = 5150713838310018186;
                        match current_block_20 {
                            5150713838310018186 => {
                                (unsafe { Curl_failf(
                                    data,
                                    b"FTP response aborted due to select/poll error: %d\0"
                                        as *const u8
                                        as *const i8,
                                    *__errno_location(),
                                ) });
                                return CURLE_RECV_ERROR;
                            }
                            _ => {
                                if Curl_pgrsUpdate(data) != 0 {
                                    return CURLE_ABORTED_BY_CALLBACK;
                                }
                                continue;
                            }
                        }
                    }
                    0 => {
                        current_block_20 = 7791345847782151099;
                        match current_block_20 {
                            5150713838310018186 => {
                                (unsafe { Curl_failf(
                                    data,
                                    b"FTP response aborted due to select/poll error: %d\0"
                                        as *const u8
                                        as *const i8,
                                    *__errno_location(),
                                ) });
                                return CURLE_RECV_ERROR;
                            }
                            _ => {
                                if Curl_pgrsUpdate(data) != 0 {
                                    return CURLE_ABORTED_BY_CALLBACK;
                                }
                                continue;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        result = ftp_readresp(data, sockfd, pp, ftpcode, Some(&mut nread));
        if result as u64 != 0 {
            break;
        }
        if nread == 0 && !(unsafe { (*pp).cache }).is_null() {
            cache_skip += 1;
        } else {
            cache_skip = 0 as i32;
        }
        *(borrow_mut(&mut nreadp)).unwrap() =
            (*(borrow(&nreadp)).unwrap() as u64).wrapping_add(nread) as ssize_t as ssize_t;
    }
    (unsafe { (*pp).pending_resp = 0 as i32 != 0 });
    return result;
}
extern "C" fn _state(mut data: *mut crate::src::lib::http2::Curl_easy, mut newstate: u32) {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    (*(borrow_mut(&mut ftpc)).unwrap()).state = newstate;
}
extern "C" fn ftp_state_user(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut result: u32 = unsafe { Curl_pp_sendf(
        data,
        Some(&mut (*conn).proto.ftpc.pp),
        b"USER %s\0" as *const u8 as *const i8,
        if !((*conn).user).is_null() {
            (*conn).user as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
    ) };
    if result as u64 == 0 {
        _state(data, FTP_USER);
        let mut fresh6 = unsafe { &mut ((*data).state) };
        (*fresh6).set_ftp_trying_alternative(0 as i32 as bit);
    }
    return result;
}
extern "C" fn ftp_state_pwd(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut result: u32 = unsafe { Curl_pp_sendf(
        data,
        Some(&mut (*conn).proto.ftpc.pp),
        b"%s\0" as *const u8 as *const i8,
        b"PWD\0" as *const u8 as *const i8,
    ) };
    if result as u64 == 0 {
        _state(data, FTP_PWD);
    }
    return result;
}
extern "C" fn ftp_getsock(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut socks: *mut i32,
) -> i32 {
    return Curl_pp_getsock(data, Some(unsafe { &mut (*conn).proto.ftpc.pp }), socks);
}
extern "C" fn ftp_domore_getsock(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut socks: *mut i32,
) -> i32 {
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    if (unsafe { (*conn).cnnct.state }) as u32 >= CONNECT_SOCKS_INIT as i32 as u32
        && ((unsafe { (*conn).cnnct.state }) as u32) < CONNECT_DONE as i32 as u32
    {
        return Curl_SOCKS_getsock(conn, socks, 1 as i32);
    }
    if FTP_STOP as i32 as u32 == (*(borrow(&ftpc)).unwrap()).state as u32 {
        let mut bits: i32 = (1 as i32) << 0 as i32;
        let mut any: bool = 0 as i32 != 0;
        (unsafe { *socks.offset(0 as i32 as isize) = (*conn).sock[0 as i32 as usize] });
        if (unsafe { ((*data).set).ftp_use_port() }) == 0 {
            let mut s: i32 = 0;
            let mut i: i32 = 0;
            s = 1 as i32;
            i = 0 as i32;
            while i < 2 as i32 {
                if (unsafe { (*conn).tempsock[i as usize] }) != -(1 as i32) {
                    (unsafe { *socks.offset(s as isize) = (*conn).tempsock[i as usize] });
                    let mut fresh7 = s;
                    s = s + 1;
                    bits |= (1 as i32) << 16 as i32 + fresh7;
                    any = 1 as i32 != 0;
                }
                i += 1;
            }
        }
        if !any {
            (unsafe { *socks.offset(1 as i32 as isize) = (*conn).sock[1 as i32 as usize] });
            bits |= (1 as i32) << 16 as i32 + 1 as i32 | (1 as i32) << 1 as i32;
        }
        return bits;
    }
    return Curl_pp_getsock(data, Some(unsafe { &mut (*conn).proto.ftpc.pp }), socks);
}
extern "C" fn ftp_state_cwd(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut ftpc: *mut crate::src::lib::http2::ftp_conn = unsafe { &mut (*conn).proto.ftpc };
    if unsafe { (*ftpc).cwddone } {
        result = ftp_state_mdtm(data);
    } else {
        (unsafe { (*ftpc).count2 = 0 as i32 });
        (unsafe { (*ftpc).count3 = if (*data).set.ftp_create_missing_dirs == 2 as i32 {
            1 as i32
        } else {
            0 as i32
        } });
        if (unsafe { ((*conn).bits).reuse() }) as i32 != 0
            && !(unsafe { (*ftpc).entrypath }).is_null()
            && !((unsafe { (*ftpc).dirdepth }) != 0
                && (unsafe { *(*((*ftpc).dirs).offset(0 as i32 as isize)).offset(0 as i32 as isize) }) as i32
                    == '/' as i32)
        {
            (unsafe { (*ftpc).cwdcount = 0 as i32 });
            result = unsafe { Curl_pp_sendf(
                data,
                Some(&mut (*ftpc).pp),
                b"CWD %s\0" as *const u8 as *const i8,
                (*ftpc).entrypath,
            ) };
            if result as u64 == 0 {
                _state(data, FTP_CWD);
            }
        } else if (unsafe { (*ftpc).dirdepth }) != 0 {
            (unsafe { (*ftpc).cwdcount = 1 as i32 });
            result = unsafe { Curl_pp_sendf(
                data,
                Some(&mut (*ftpc).pp),
                b"CWD %s\0" as *const u8 as *const i8,
                *((*ftpc).dirs).offset(((*ftpc).cwdcount - 1 as i32) as isize),
            ) };
            if result as u64 == 0 {
                _state(data, FTP_CWD);
            }
        } else {
            result = ftp_state_mdtm(data);
        }
    }
    return result;
}
extern "C" fn ftp_state_use_port(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut fcmd: u32,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    let mut portsock: i32 = -(1 as i32);
    let mut myhost : [i8 ; 47] = * (unsafe { core :: intrinsics :: transmute :: < & '_ [u8 ; 47] , & '_ mut [i8 ; 47] > (b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" ,) }) ;
    let mut ss: crate::src::lib::connect::Curl_sockaddr_storage = Curl_sockaddr_storage {
        buffer: C2RustUnnamed_9 {
            sa: sockaddr {
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    };
    let mut res: *mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut ai: *mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut sslen: u32 = 0;
    let mut hbuf: [i8; 1025] = [0; 1025];
    let mut sa: *mut crate::src::lib::http2::sockaddr =
        &mut ss as *mut Curl_sockaddr_storage as *mut sockaddr;
    let sa4: *mut crate::src::lib::connect::sockaddr_in =
        sa as *mut libc::c_void as *mut sockaddr_in;
    let sa6: *mut crate::src::lib::connect::sockaddr_in6 =
        sa as *mut libc::c_void as *mut sockaddr_in6;
    static mut mode: [[i8; 5]; 2] = unsafe {
        [
            *core::intrinsics::transmute::<&'_ [u8; 5], &'_ [i8; 5]>(b"EPRT\0"),
            *core::intrinsics::transmute::<&'_ [u8; 5], &'_ [i8; 5]>(b"PORT\0"),
        ]
    };
    let mut rc: i32 = CURLRESOLV_RESOLVED;
    let mut error: i32 = 0;
    let mut host: *mut i8 = 0 as *mut i8;
    let mut string_ftpport: *mut i8 = unsafe { (*data).set.str_0[STRING_FTPPORT as i32 as usize] };
    let mut h: *mut crate::src::lib::http2::Curl_dns_entry = 0 as *mut Curl_dns_entry;
    let mut port_min: u16 = 0 as i32 as u16;
    let mut port_max: u16 = 0 as i32 as u16;
    let mut port: u16 = 0;
    let mut possibly_non_local: bool = 1 as i32 != 0;
    let mut buffer: [i8; 256] = [0; 256];
    let mut addr: *mut i8 = 0 as *mut i8;
    if !(unsafe { (*data).set.str_0[STRING_FTPPORT as i32 as usize] }).is_null()
        && (unsafe { strlen((*data).set.str_0[STRING_FTPPORT as i32 as usize]) }) > 1 as i32 as u64
    {
        let mut addrlen: u64 = if 46 as i32 as u64 > (unsafe { strlen(string_ftpport) }) {
            46 as i32 as u64
        } else {
            unsafe { strlen(string_ftpport) }
        };
        let mut ip_start: *mut i8 = string_ftpport;
        let mut ip_end: *mut i8 = 0 as *mut i8;
        let mut port_start: *mut i8 = 0 as *mut i8;
        let mut port_sep: *mut i8 = 0 as *mut i8;
        addr = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
            addrlen.wrapping_add(1 as i32 as u64),
            1 as i32 as size_t,
        ) }) as *mut i8;
        if addr.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if (unsafe { *string_ftpport }) as i32 == '[' as i32 {
            ip_start = unsafe { string_ftpport.offset(1 as i32 as isize) };
            ip_end = unsafe { strchr(string_ftpport, ']' as i32) };
            if !ip_end.is_null() {
                (unsafe { strncpy(addr, ip_start, ip_end.offset_from(ip_start) as i64 as u64) });
            }
        } else if (unsafe { *string_ftpport }) as i32 == ':' as i32 {
            ip_end = string_ftpport;
        } else {
            ip_end = unsafe { strchr(string_ftpport, ':' as i32) };
            if !ip_end.is_null() {
                if (unsafe { inet_pton(10 as i32, string_ftpport, sa6 as *mut libc::c_void) }) == 1 as i32 {
                    port_max = 0 as i32 as u16;
                    port_min = port_max;
                    (unsafe { strcpy(addr, string_ftpport) });
                    ip_end = 0 as *mut i8;
                } else {
                    (unsafe { strncpy(
                        addr,
                        string_ftpport,
                        ip_end.offset_from(ip_start) as i64 as u64,
                    ) });
                }
            } else {
                (unsafe { strcpy(addr, string_ftpport) });
            }
        }
        if !ip_end.is_null() {
            port_start = unsafe { strchr(ip_end, ':' as i32) };
            if !port_start.is_null() {
                port_min = curlx_ultous(unsafe { strtoul(
                    port_start.offset(1 as i32 as isize),
                    0 as *mut *mut i8,
                    10 as i32,
                ) });
                port_sep = unsafe { strchr(port_start, '-' as i32) };
                if !port_sep.is_null() {
                    port_max = curlx_ultous(unsafe { strtoul(
                        port_sep.offset(1 as i32 as isize),
                        0 as *mut *mut i8,
                        10 as i32,
                    ) });
                } else {
                    port_max = port_min;
                }
            }
        }
        if port_min as i32 > port_max as i32 {
            port_max = 0 as i32 as u16;
            port_min = port_max;
        }
        if (unsafe { *addr }) as i32 != '\u{0}' as i32 {
            match Curl_if2ip(
                unsafe { (*(*conn).ip_addr).ai_family },
                Curl_ipv6_scope(unsafe { (*(*conn).ip_addr).ai_addr }),
                unsafe { (*conn).scope_id },
                addr,
                hbuf.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 1025]>() as u64 as i32,
            ) as u32
            {
                0 => {
                    host = addr;
                }
                1 => return CURLE_FTP_PORT_FAILED,
                2 => {
                    host = hbuf.as_mut_ptr();
                }
                _ => {}
            }
        } else {
            host = 0 as *mut i8;
        }
    }
    if host.is_null() {
        let mut r: *const i8 = 0 as *const i8;
        sslen = ::std::mem::size_of::<Curl_sockaddr_storage>() as u64 as curl_socklen_t;
        if (unsafe { getsockname((*conn).sock[0 as i32 as usize], sa, &mut sslen) }) != 0 {
            (unsafe { Curl_failf(
                data,
                b"getsockname() failed: %s\0" as *const u8 as *const i8,
                Curl_strerror(
                    *__errno_location(),
                    buffer.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 256]>() as u64,
                ),
            ) });
            (unsafe { Curl_cfree.expect("non-null function pointer")(addr as *mut libc::c_void) });
            return CURLE_FTP_PORT_FAILED;
        }
        match (unsafe { (*sa).sa_family }) as i32 {
            10 => {
                r = unsafe { inet_ntop(
                    (*sa).sa_family as i32,
                    &mut (*sa6).sin6_addr as *mut in6_addr as *const libc::c_void,
                    hbuf.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 1025]>() as u64 as curl_socklen_t,
                ) };
            }
            _ => {
                r = unsafe { inet_ntop(
                    (*sa).sa_family as i32,
                    &mut (*sa4).sin_addr as *mut in_addr as *const libc::c_void,
                    hbuf.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 1025]>() as u64 as curl_socklen_t,
                ) };
            }
        }
        if r.is_null() {
            return CURLE_FTP_PORT_FAILED;
        }
        host = hbuf.as_mut_ptr();
        possibly_non_local = 0 as i32 != 0;
    }
    rc = Curl_resolv(data, host, 0 as i32, 0 as i32 != 0, Some(&mut h));
    if rc as i32 == CURLRESOLV_PENDING as i32 {
        Curl_resolver_wait_resolv(data, Some(&mut h));
    }
    if !h.is_null() {
        res = unsafe { (*h).addr };
        Curl_resolv_unlock(data, h);
    } else {
        res = 0 as *mut Curl_addrinfo;
    }
    if res.is_null() {
        (unsafe { Curl_failf(
            data,
            b"failed to resolve the address provided to PORT: %s\0" as *const u8 as *const i8,
            host,
        ) });
        (unsafe { Curl_cfree.expect("non-null function pointer")(addr as *mut libc::c_void) });
        return CURLE_FTP_PORT_FAILED;
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")(addr as *mut libc::c_void) });
    host = 0 as *mut i8;
    portsock = -(1 as i32);
    error = 0 as i32;
    ai = res;
    while !ai.is_null() {
        result = Curl_socket(data, ai, 0 as *mut Curl_sockaddr_ex, Some(&mut portsock));
        if !(result as u64 != 0) {
            break;
        }
        error = unsafe { *__errno_location() };
        ai = unsafe { (*ai).ai_next };
    }
    if ai.is_null() {
        (unsafe { Curl_failf(
            data,
            b"socket failure: %s\0" as *const u8 as *const i8,
            Curl_strerror(
                error,
                buffer.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 256]>() as u64,
            ),
        ) });
        return CURLE_FTP_PORT_FAILED;
    }
    (unsafe { memcpy(
        sa as *mut libc::c_void,
        (*ai).ai_addr as *const libc::c_void,
        (*ai).ai_addrlen as u64,
    ) });
    sslen = unsafe { (*ai).ai_addrlen };
    port = port_min;
    while port as i32 <= port_max as i32 {
        if (unsafe { (*sa).sa_family }) as i32 == 2 as i32 {
            (unsafe { (*sa4).sin_port = __bswap_16(port) });
        } else {
            (unsafe { (*sa6).sin6_port = __bswap_16(port) });
        }
        if !((unsafe { bind(portsock, sa, sslen) }) != 0) {
            break;
        }
        error = unsafe { *__errno_location() };
        if possibly_non_local as i32 != 0 && error == 99 as i32 {
            (unsafe { Curl_infof(
                data,
                b"bind(port=%hu) on non-local address failed: %s\0" as *const u8 as *const i8,
                port as i32,
                Curl_strerror(
                    error,
                    buffer.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 256]>() as u64,
                ),
            ) });
            sslen = ::std::mem::size_of::<Curl_sockaddr_storage>() as u64 as curl_socklen_t;
            if (unsafe { getsockname((*conn).sock[0 as i32 as usize], sa, &mut sslen) }) != 0 {
                (unsafe { Curl_failf(
                    data,
                    b"getsockname() failed: %s\0" as *const u8 as *const i8,
                    Curl_strerror(
                        *__errno_location(),
                        buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 256]>() as u64,
                    ),
                ) });
                Curl_closesocket(data, conn, portsock);
                return CURLE_FTP_PORT_FAILED;
            }
            port = port_min;
            possibly_non_local = 0 as i32 != 0;
        } else {
            if error != 98 as i32 && error != 13 as i32 {
                (unsafe { Curl_failf(
                    data,
                    b"bind(port=%hu) failed: %s\0" as *const u8 as *const i8,
                    port as i32,
                    Curl_strerror(
                        error,
                        buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 256]>() as u64,
                    ),
                ) });
                Curl_closesocket(data, conn, portsock);
                return CURLE_FTP_PORT_FAILED;
            }
            port = port.wrapping_add(1);
        }
    }
    if port as i32 > port_max as i32 {
        (unsafe { Curl_failf(
            data,
            b"bind() failed, we ran out of ports!\0" as *const u8 as *const i8,
        ) });
        Curl_closesocket(data, conn, portsock);
        return CURLE_FTP_PORT_FAILED;
    }
    sslen = ::std::mem::size_of::<Curl_sockaddr_storage>() as u64 as curl_socklen_t;
    if (unsafe { getsockname(portsock, sa, &mut sslen) }) != 0 {
        (unsafe { Curl_failf(
            data,
            b"getsockname() failed: %s\0" as *const u8 as *const i8,
            Curl_strerror(
                *__errno_location(),
                buffer.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 256]>() as u64,
            ),
        ) });
        Curl_closesocket(data, conn, portsock);
        return CURLE_FTP_PORT_FAILED;
    }
    if (unsafe { listen(portsock, 1 as i32) }) != 0 {
        (unsafe { Curl_failf(
            data,
            b"socket failure: %s\0" as *const u8 as *const i8,
            Curl_strerror(
                *__errno_location(),
                buffer.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 256]>() as u64,
            ),
        ) });
        Curl_closesocket(data, conn, portsock);
        return CURLE_FTP_PORT_FAILED;
    }
    Curl_printable_address(
        ai,
        myhost.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 47]>() as u64,
    );
    if (unsafe { ((*conn).bits).ftp_use_eprt() }) == 0 && (unsafe { ((*conn).bits).ipv6() }) as i32 != 0 {
        let mut fresh8 = unsafe { &mut ((*conn).bits) };
        (*fresh8).set_ftp_use_eprt(1 as i32 as bit);
    }
    let mut current_block_152: u64;
    while fcmd as u32 != DONE as i32 as u32 {
        if !((unsafe { ((*conn).bits).ftp_use_eprt() }) == 0 && EPRT as i32 as u32 == fcmd as u32) {
            if !(PORT as i32 as u32 == fcmd as u32 && (unsafe { (*sa).sa_family }) as i32 != 2 as i32) {
                match (unsafe { (*sa).sa_family }) as i32 {
                    2 => {
                        current_block_152 = 8167214597936611784;
                        match current_block_152 {
                            11945233418868655198 => {
                                port = __bswap_16(unsafe { (*sa6).sin6_port });
                            }
                            _ => {
                                port = __bswap_16(unsafe { (*sa4).sin_port });
                            }
                        }
                        if EPRT as i32 as u32 == fcmd as u32 {
                            result = unsafe { Curl_pp_sendf(
                                data,
                                Some(&mut (*(borrow_mut(&mut ftpc)).unwrap()).pp),
                                b"%s |%d|%s|%hu|\0" as *const u8 as *const i8,
                                (mode[fcmd as usize]).as_ptr(),
                                if (*sa).sa_family as i32 == 2 as i32 {
                                    1 as i32
                                } else {
                                    2 as i32
                                },
                                myhost.as_mut_ptr(),
                                port as i32,
                            ) };
                            if result as u64 != 0 {
                                (unsafe { Curl_failf(
                                    data,
                                    b"Failure sending EPRT command: %s\0" as *const u8 as *const i8,
                                    curl_easy_strerror(result),
                                ) });
                                Curl_closesocket(data, conn, portsock);
                                (*(borrow_mut(&mut ftpc)).unwrap()).count1 = PORT as i32;
                                _state(data, FTP_STOP);
                                return result;
                            }
                            break;
                        } else if PORT as i32 as u32 == fcmd as u32 {
                            let mut target: [i8; 67] = [0; 67];
                            let mut source: *mut i8 = myhost.as_mut_ptr();
                            let mut dest: *mut i8 = target.as_mut_ptr();
                            while !source.is_null() && (unsafe { *source }) as i32 != 0 {
                                if (unsafe { *source }) as i32 == '.' as i32 {
                                    (unsafe { *dest = ',' as i32 as i8 });
                                } else {
                                    (unsafe { *dest = *source });
                                }
                                dest = unsafe { dest.offset(1) };
                                source = unsafe { source.offset(1) };
                            }
                            (unsafe { *dest = 0 as i32 as i8 });
                            (unsafe { curl_msnprintf(
                                dest,
                                20 as i32 as size_t,
                                b",%d,%d\0" as *const u8 as *const i8,
                                port as i32 >> 8 as i32,
                                port as i32 & 0xff as i32,
                            ) });
                            result = unsafe { Curl_pp_sendf(
                                data,
                                Some(&mut (*(borrow_mut(&mut ftpc)).unwrap()).pp),
                                b"%s %s\0" as *const u8 as *const i8,
                                (mode[fcmd as usize]).as_ptr(),
                                target.as_mut_ptr(),
                            ) };
                            if result as u64 != 0 {
                                (unsafe { Curl_failf(
                                    data,
                                    b"Failure sending PORT command: %s\0" as *const u8 as *const i8,
                                    curl_easy_strerror(result),
                                ) });
                                Curl_closesocket(data, conn, portsock);
                                _state(data, FTP_STOP);
                                return result;
                            }
                            break;
                        }
                    }
                    10 => {
                        current_block_152 = 11945233418868655198;
                        match current_block_152 {
                            11945233418868655198 => {
                                port = __bswap_16(unsafe { (*sa6).sin6_port });
                            }
                            _ => {
                                port = __bswap_16(unsafe { (*sa4).sin_port });
                            }
                        }
                        if EPRT as i32 as u32 == fcmd as u32 {
                            result = unsafe { Curl_pp_sendf(
                                data,
                                Some(&mut (*(borrow_mut(&mut ftpc)).unwrap()).pp),
                                b"%s |%d|%s|%hu|\0" as *const u8 as *const i8,
                                (mode[fcmd as usize]).as_ptr(),
                                if (*sa).sa_family as i32 == 2 as i32 {
                                    1 as i32
                                } else {
                                    2 as i32
                                },
                                myhost.as_mut_ptr(),
                                port as i32,
                            ) };
                            if result as u64 != 0 {
                                (unsafe { Curl_failf(
                                    data,
                                    b"Failure sending EPRT command: %s\0" as *const u8 as *const i8,
                                    curl_easy_strerror(result),
                                ) });
                                Curl_closesocket(data, conn, portsock);
                                (*(borrow_mut(&mut ftpc)).unwrap()).count1 = PORT as i32;
                                _state(data, FTP_STOP);
                                return result;
                            }
                            break;
                        } else if PORT as i32 as u32 == fcmd as u32 {
                            let mut target: [i8; 67] = [0; 67];
                            let mut source: *mut i8 = myhost.as_mut_ptr();
                            let mut dest: *mut i8 = target.as_mut_ptr();
                            while !source.is_null() && (unsafe { *source }) as i32 != 0 {
                                if (unsafe { *source }) as i32 == '.' as i32 {
                                    (unsafe { *dest = ',' as i32 as i8 });
                                } else {
                                    (unsafe { *dest = *source });
                                }
                                dest = unsafe { dest.offset(1) };
                                source = unsafe { source.offset(1) };
                            }
                            (unsafe { *dest = 0 as i32 as i8 });
                            (unsafe { curl_msnprintf(
                                dest,
                                20 as i32 as size_t,
                                b",%d,%d\0" as *const u8 as *const i8,
                                port as i32 >> 8 as i32,
                                port as i32 & 0xff as i32,
                            ) });
                            result = unsafe { Curl_pp_sendf(
                                data,
                                Some(&mut (*(borrow_mut(&mut ftpc)).unwrap()).pp),
                                b"%s %s\0" as *const u8 as *const i8,
                                (mode[fcmd as usize]).as_ptr(),
                                target.as_mut_ptr(),
                            ) };
                            if result as u64 != 0 {
                                (unsafe { Curl_failf(
                                    data,
                                    b"Failure sending PORT command: %s\0" as *const u8 as *const i8,
                                    curl_easy_strerror(result),
                                ) });
                                Curl_closesocket(data, conn, portsock);
                                _state(data, FTP_STOP);
                                return result;
                            }
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
        fcmd += 1;
    }
    (*(borrow_mut(&mut ftpc)).unwrap()).count1 = fcmd as i32;
    close_secondarysocket(data, conn);
    (unsafe { (*conn).sock[1 as i32 as usize] = portsock });
    (unsafe { (*conn).bits.tcpconnect[1 as i32 as usize] = 1 as i32 != 0 });
    _state(data, FTP_PORT);
    return result;
}
extern "C" fn ftp_state_use_pasv(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    let mut result: u32 = CURLE_OK;
    static mut mode: [[i8; 5]; 2] = unsafe {
        [
            *core::intrinsics::transmute::<&'_ [u8; 5], &'_ [i8; 5]>(b"EPSV\0"),
            *core::intrinsics::transmute::<&'_ [u8; 5], &'_ [i8; 5]>(b"PASV\0"),
        ]
    };
    let mut modeoff: i32 = 0;
    if (unsafe { ((*conn).bits).ftp_use_epsv() }) == 0 && (unsafe { ((*conn).bits).ipv6() }) as i32 != 0 {
        let mut fresh9 = unsafe { &mut ((*conn).bits) };
        (*fresh9).set_ftp_use_epsv(1 as i32 as bit);
    }
    modeoff = if (unsafe { ((*conn).bits).ftp_use_epsv() }) as i32 != 0 {
        0 as i32
    } else {
        1 as i32
    };
    result = unsafe { Curl_pp_sendf(
        data,
        Some(&mut (*(borrow_mut(&mut ftpc)).unwrap()).pp),
        b"%s\0" as *const u8 as *const i8,
        (mode[modeoff as usize]).as_ptr(),
    ) };
    if result as u64 == 0 {
        (*(borrow_mut(&mut ftpc)).unwrap()).count1 = modeoff;
        _state(data, FTP_PASV);
        (unsafe { Curl_infof(
            data,
            b"Connect data stream passively\0" as *const u8 as *const i8,
        ) });
    }
    return result;
}
extern "C" fn ftp_state_prepare_transfer(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut ftp: *mut crate::src::lib::http2::FTP = unsafe { (*data).req.p.ftp };
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    if (unsafe { (*ftp).transfer }) as u32 != PPTRANSFER_BODY as i32 as u32 {
        _state(data, FTP_RETR_PREQUOTE);
        result = ftp_state_quote(data, 1 as i32 != 0, FTP_RETR_PREQUOTE);
    } else if (unsafe { ((*data).set).ftp_use_port() }) != 0 {
        result = ftp_state_use_port(data, EPRT);
    } else if (unsafe { ((*data).set).ftp_use_pret() }) != 0 {
        let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> =
            Some(unsafe { &mut (*conn).proto.ftpc });
        if (unsafe { (*conn).proto.ftpc.file }).is_null() {
            result = unsafe { Curl_pp_sendf(
                data,
                Some(&mut (*(borrow_mut(&mut ftpc)).unwrap()).pp),
                b"PRET %s\0" as *const u8 as *const i8,
                if !((*data).set.str_0[STRING_CUSTOMREQUEST as i32 as usize]).is_null() {
                    (*data).set.str_0[STRING_CUSTOMREQUEST as i32 as usize] as *const i8
                } else if ((*data).state).list_only() as i32 != 0 {
                    b"NLST\0" as *const u8 as *const i8
                } else {
                    b"LIST\0" as *const u8 as *const i8
                },
            ) };
        } else if (unsafe { ((*data).set).upload() }) != 0 {
            result = unsafe { Curl_pp_sendf(
                data,
                Some(&mut (*(borrow_mut(&mut ftpc)).unwrap()).pp),
                b"PRET STOR %s\0" as *const u8 as *const i8,
                (*conn).proto.ftpc.file,
            ) };
        } else {
            result = unsafe { Curl_pp_sendf(
                data,
                Some(&mut (*(borrow_mut(&mut ftpc)).unwrap()).pp),
                b"PRET RETR %s\0" as *const u8 as *const i8,
                (*conn).proto.ftpc.file,
            ) };
        }
        if result as u64 == 0 {
            _state(data, FTP_PRET);
        }
    } else {
        result = ftp_state_use_pasv(data, conn);
    }
    return result;
}
extern "C" fn ftp_state_rest(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut ftp: *mut crate::src::lib::http2::FTP = unsafe { (*data).req.p.ftp };
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    if (unsafe { (*ftp).transfer }) as u32 != PPTRANSFER_BODY as i32 as u32
        && !((*(borrow(&ftpc)).unwrap()).file).is_null()
    {
        result = unsafe { Curl_pp_sendf(
            data,
            Some(&mut (*(borrow_mut(&mut ftpc)).unwrap()).pp),
            b"REST %d\0" as *const u8 as *const i8,
            0 as i32,
        ) };
        if result as u64 == 0 {
            _state(data, FTP_REST);
        }
    } else {
        result = ftp_state_prepare_transfer(data);
    }
    return result;
}
extern "C" fn ftp_state_size(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut ftp: *mut crate::src::lib::http2::FTP = unsafe { (*data).req.p.ftp };
    let mut ftpc: *mut crate::src::lib::http2::ftp_conn = unsafe { &mut (*conn).proto.ftpc };
    if (unsafe { (*ftp).transfer }) as u32 == PPTRANSFER_INFO as i32 as u32 && !(unsafe { (*ftpc).file }).is_null() {
        result = unsafe { Curl_pp_sendf(
            data,
            Some(&mut (*ftpc).pp),
            b"SIZE %s\0" as *const u8 as *const i8,
            (*ftpc).file,
        ) };
        if result as u64 == 0 {
            _state(data, FTP_SIZE);
        }
    } else {
        result = ftp_state_rest(data, conn);
    }
    return result;
}
extern "C" fn ftp_state_list(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut ftp: *mut crate::src::lib::http2::FTP = unsafe { (*data).req.p.ftp };
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut lstArg: *mut i8 = 0 as *mut i8;
    let mut cmd: *mut i8 = 0 as *mut i8;
    if (unsafe { (*data).set.ftp_filemethod }) as u32 == FTPFILE_NOCWD as i32 as u32 && !(unsafe { (*ftp).path }).is_null()
    {
        let mut slashPos: *const i8 = 0 as *const i8;
        let mut rawPath: *mut i8 = 0 as *mut i8;
        result = Curl_urldecode(
            data,
            unsafe { (*ftp).path },
            0 as i32 as size_t,
            Some(&mut rawPath),
            Option::<&'_ mut u64>::None,
            REJECT_CTRL,
        );
        if result as u64 != 0 {
            return result;
        }
        slashPos = unsafe { strrchr(rawPath, '/' as i32) };
        if !slashPos.is_null() {
            let mut n: u64 = (unsafe { slashPos.offset_from(rawPath) }) as i64 as size_t;
            if n == 0 as i32 as u64 {
                n = n.wrapping_add(1);
            }
            lstArg = rawPath;
            (unsafe { *lstArg.offset(n as isize) = '\u{0}' as i32 as i8 });
        } else {
            (unsafe { Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void) });
        }
    }
    cmd = unsafe { curl_maprintf(
        b"%s%s%s\0" as *const u8 as *const i8,
        if !((*data).set.str_0[STRING_CUSTOMREQUEST as i32 as usize]).is_null() {
            (*data).set.str_0[STRING_CUSTOMREQUEST as i32 as usize] as *const i8
        } else if ((*data).state).list_only() as i32 != 0 {
            b"NLST\0" as *const u8 as *const i8
        } else {
            b"LIST\0" as *const u8 as *const i8
        },
        if !lstArg.is_null() {
            b" \0" as *const u8 as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !lstArg.is_null() {
            lstArg as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
    ) };
    (unsafe { Curl_cfree.expect("non-null function pointer")(lstArg as *mut libc::c_void) });
    if cmd.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    result = unsafe { Curl_pp_sendf(
        data,
        Some(&mut (*conn).proto.ftpc.pp),
        b"%s\0" as *const u8 as *const i8,
        cmd,
    ) };
    (unsafe { Curl_cfree.expect("non-null function pointer")(cmd as *mut libc::c_void) });
    if result as u64 == 0 {
        _state(data, FTP_LIST);
    }
    return result;
}
extern "C" fn ftp_state_retr_prequote(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    return ftp_state_quote(data, 1 as i32 != 0, FTP_RETR_PREQUOTE);
}
extern "C" fn ftp_state_stor_prequote(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    return ftp_state_quote(data, 1 as i32 != 0, FTP_STOR_PREQUOTE);
}
extern "C" fn ftp_state_type(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut ftp: *mut crate::src::lib::http2::FTP = unsafe { (*data).req.p.ftp };
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    if (unsafe { ((*data).set).opt_no_body() }) as i32 != 0
        && !((*(borrow(&ftpc)).unwrap()).file).is_null()
        && ftp_need_type(conn, (unsafe { ((*data).state).prefer_ascii() }) != 0) != 0
    {
        (unsafe { (*ftp).transfer = PPTRANSFER_INFO });
        result = ftp_nb_type(data, conn, (unsafe { ((*data).state).prefer_ascii() }) != 0, FTP_TYPE);
        if result as u64 != 0 {
            return result;
        }
    } else {
        result = ftp_state_size(data, conn);
    }
    return result;
}
extern "C" fn ftp_state_mdtm(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftpc: *mut crate::src::lib::http2::ftp_conn = unsafe { &mut (*conn).proto.ftpc };
    if ((unsafe { ((*data).set).get_filetime() }) as i32 != 0 || (unsafe { (*data).set.timecondition }) as u32 != 0)
        && !(unsafe { (*ftpc).file }).is_null()
    {
        result = unsafe { Curl_pp_sendf(
            data,
            Some(&mut (*ftpc).pp),
            b"MDTM %s\0" as *const u8 as *const i8,
            (*ftpc).file,
        ) };
        if result as u64 == 0 {
            _state(data, FTP_MDTM);
        }
    } else {
        result = ftp_state_type(data);
    }
    return result;
}
extern "C" fn ftp_state_ul_setup(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut sizechecked: bool,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftp: *mut crate::src::lib::http2::FTP = unsafe { (*data).req.p.ftp };
    let mut ftpc: *mut crate::src::lib::http2::ftp_conn = unsafe { &mut (*conn).proto.ftpc };
    let mut append: bool = (unsafe { ((*data).set).remote_append() }) != 0;
    if (unsafe { (*data).state.resume_from }) != 0 && !sizechecked
        || (unsafe { (*data).state.resume_from }) > 0 as i32 as i64 && sizechecked as i32 != 0
    {
        let mut seekerr: i32 = 0 as i32;
        if (unsafe { (*data).state.resume_from }) < 0 as i32 as i64 {
            result = unsafe { Curl_pp_sendf(
                data,
                Some(&mut (*ftpc).pp),
                b"SIZE %s\0" as *const u8 as *const i8,
                (*ftpc).file,
            ) };
            if result as u64 == 0 {
                _state(data, FTP_STOR_SIZE);
            }
            return result;
        }
        append = 1 as i32 != 0;
        if unsafe { ((*conn).seek_func).is_some() } {
            Curl_set_in_callback(data, 1 as i32 != 0);
            seekerr = unsafe { ((*conn).seek_func).expect("non-null function pointer")(
                (*conn).seek_client,
                (*data).state.resume_from,
                0 as i32,
            ) };
            Curl_set_in_callback(data, 0 as i32 != 0);
        }
        if seekerr != 0 as i32 {
            let mut passed: i64 = 0 as i32 as curl_off_t;
            if seekerr != 2 as i32 {
                (unsafe { Curl_failf(data, b"Could not seek stream\0" as *const u8 as *const i8) });
                return CURLE_FTP_COULDNT_USE_REST;
            }
            loop {
                let mut readthisamountnow: u64 =
                    if (unsafe { (*data).state.resume_from }) - passed > (unsafe { (*data).set.buffer_size }) {
                        (unsafe { (*data).set.buffer_size }) as size_t
                    } else {
                        curlx_sotouz((unsafe { (*data).state.resume_from }) - passed)
                    };
                let mut actuallyread: u64 = unsafe { ((*data).state.fread_func)
                    .expect("non-null function pointer")(
                    (*data).state.buffer,
                    1 as i32 as size_t,
                    readthisamountnow,
                    (*data).state.in_0,
                ) };
                passed = (passed as u64).wrapping_add(actuallyread) as curl_off_t as curl_off_t;
                if actuallyread == 0 as i32 as u64 || actuallyread > readthisamountnow {
                    (unsafe { Curl_failf(data, b"Failed to read data\0" as *const u8 as *const i8) });
                    return CURLE_FTP_COULDNT_USE_REST;
                }
                if !(passed < (unsafe { (*data).state.resume_from })) {
                    break;
                }
            }
        }
        if (unsafe { (*data).state.infilesize }) > 0 as i32 as i64 {
            let mut fresh10 = unsafe { &mut ((*data).state.infilesize) };
            *fresh10 -= unsafe { (*data).state.resume_from };
            if (unsafe { (*data).state.infilesize }) <= 0 as i32 as i64 {
                (unsafe { Curl_infof(
                    data,
                    b"File already completely uploaded\0" as *const u8 as *const i8,
                ) });
                Curl_setup_transfer(
                    data,
                    -(1 as i32),
                    -(1 as i32) as curl_off_t,
                    0 as i32 != 0,
                    -(1 as i32),
                );
                (unsafe { (*ftp).transfer = PPTRANSFER_NONE });
                _state(data, FTP_STOP);
                return CURLE_OK;
            }
        }
    }
    result = unsafe { Curl_pp_sendf(
        data,
        Some(&mut (*ftpc).pp),
        if append as i32 != 0 {
            b"APPE %s\0" as *const u8 as *const i8
        } else {
            b"STOR %s\0" as *const u8 as *const i8
        },
        (*ftpc).file,
    ) };
    if result as u64 == 0 {
        _state(data, FTP_STOR);
    }
    return result;
}
extern "C" fn ftp_state_quote(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut init: bool,
    mut instate: u32,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut ftp: *mut crate::src::lib::http2::FTP = unsafe { (*data).req.p.ftp };
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftpc: *mut crate::src::lib::http2::ftp_conn = unsafe { &mut (*conn).proto.ftpc };
    let mut quote: bool = 0 as i32 != 0;
    let mut item: *mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
    match instate as u32 {
        13 | 14 => {
            item = unsafe { (*data).set.prequote };
        }
        15 => {
            item = unsafe { (*data).set.postquote };
        }
        12 | _ => {
            item = unsafe { (*data).set.quote };
        }
    }
    if init {
        (unsafe { (*ftpc).count1 = 0 as i32 });
    } else {
        let mut fresh11 = unsafe { &mut ((*ftpc).count1) };
        *fresh11 += 1;
    }
    if !item.is_null() {
        let mut i: i32 = 0 as i32;
        while i < (unsafe { (*ftpc).count1 }) && !item.is_null() {
            item = unsafe { (*item).next };
            i += 1;
        }
        if !item.is_null() {
            let mut cmd: *mut i8 = unsafe { (*item).data };
            if (unsafe { *cmd.offset(0 as i32 as isize) }) as i32 == '*' as i32 {
                cmd = unsafe { cmd.offset(1) };
                (unsafe { (*ftpc).count2 = 1 as i32 });
            } else {
                (unsafe { (*ftpc).count2 = 0 as i32 });
            }
            result = unsafe { Curl_pp_sendf(
                data,
                Some(&mut (*ftpc).pp),
                b"%s\0" as *const u8 as *const i8,
                cmd,
            ) };
            if result as u64 != 0 {
                return result;
            }
            _state(data, instate);
            quote = 1 as i32 != 0;
        }
    }
    if !quote {
        match instate as u32 {
            13 => {
                if (unsafe { (*ftp).transfer }) as u32 != PPTRANSFER_BODY as i32 as u32 {
                    _state(data, FTP_STOP);
                } else if (unsafe { (*ftpc).known_filesize }) != -(1 as i32) as i64 {
                    Curl_pgrsSetDownloadSize(data, unsafe { (*ftpc).known_filesize });
                    result = ftp_state_retr(data, unsafe { (*ftpc).known_filesize });
                } else if (unsafe { ((*data).set).ignorecl() }) as i32 != 0
                    || (unsafe { ((*data).state).prefer_ascii() }) as i32 != 0
                {
                    result = unsafe { Curl_pp_sendf(
                        data,
                        Some(&mut (*ftpc).pp),
                        b"RETR %s\0" as *const u8 as *const i8,
                        (*ftpc).file,
                    ) };
                    if result as u64 == 0 {
                        _state(data, FTP_RETR);
                    }
                } else {
                    result = unsafe { Curl_pp_sendf(
                        data,
                        Some(&mut (*ftpc).pp),
                        b"SIZE %s\0" as *const u8 as *const i8,
                        (*ftpc).file,
                    ) };
                    if result as u64 == 0 {
                        _state(data, FTP_RETR_SIZE);
                    }
                }
            }
            14 => {
                result = ftp_state_ul_setup(data, 0 as i32 != 0);
            }
            15 => {}
            12 | _ => {
                result = ftp_state_cwd(data, conn);
            }
        }
    }
    return result;
}
extern "C" fn ftp_epsv_disable(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    if (unsafe { ((*conn).bits).ipv6() }) as i32 != 0
        && !((unsafe { ((*conn).bits).tunnel_proxy() }) as i32 != 0 || (unsafe { ((*conn).bits).socksproxy() }) as i32 != 0)
    {
        (unsafe { Curl_failf(
            data,
            b"Failed EPSV attempt, exiting\0" as *const u8 as *const i8,
        ) });
        return CURLE_WEIRD_SERVER_REPLY;
    }
    (unsafe { Curl_infof(
        data,
        b"Failed EPSV attempt. Disabling EPSV\0" as *const u8 as *const i8,
    ) });
    let mut fresh12 = unsafe { &mut ((*conn).bits) };
    (*fresh12).set_ftp_use_epsv(0 as i32 as bit);
    let mut fresh13 = unsafe { &mut ((*data).state) };
    (*fresh13).set_errorbuf(0 as i32 as bit);
    result = unsafe { Curl_pp_sendf(
        data,
        Some(&mut (*conn).proto.ftpc.pp),
        b"%s\0" as *const u8 as *const i8,
        b"PASV\0" as *const u8 as *const i8,
    ) };
    if result as u64 == 0 {
        let mut fresh14 = unsafe { &mut ((*conn).proto.ftpc.count1) };
        *fresh14 += 1;
        _state(data, FTP_PASV);
    }
    return result;
}
extern "C" fn control_address(mut conn: *mut crate::src::lib::http2::connectdata) -> *mut i8 {
    if (unsafe { ((*conn).bits).tunnel_proxy() }) as i32 != 0 || (unsafe { ((*conn).bits).socksproxy() }) as i32 != 0 {
        return unsafe { (*conn).host.name };
    }
    return unsafe { ((*conn).primary_ip).as_mut_ptr() };
}
extern "C" fn ftp_state_pasv_resp(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut ftpcode: i32,
) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    let mut result: u32 = CURLE_OK;
    let mut addr: *mut crate::src::lib::http2::Curl_dns_entry = 0 as *mut Curl_dns_entry;
    let mut rc: i32 = CURLRESOLV_RESOLVED;
    let mut connectport: u16 = 0;
    let mut str: *mut i8 = (unsafe { &mut *((*data).state.buffer).offset(4 as i32 as isize) }) as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut ftpc)).unwrap()).newhost as *mut libc::c_void,
    ) });
    let mut fresh15 = &mut ((*(borrow_mut(&mut ftpc)).unwrap()).newhost);
    *fresh15 = 0 as *mut i8;
    if (*(borrow(&ftpc)).unwrap()).count1 == 0 as i32 && ftpcode == 229 as i32 {
        let mut ptr: *mut i8 = unsafe { strchr(str, '(' as i32) };
        if !ptr.is_null() {
            let mut num: u32 = 0;
            let mut separator: Option<crate::__laertes_array::CustomSlice<'static, i8, [i8; 4]>> =
                Some(crate::__laertes_array::CustomSlice::new([0; 4]));
            ptr = unsafe { ptr.offset(1) };
            if 5 as i32
                == (unsafe { sscanf(
                    ptr,
                    b"%c%c%c%u%c\0" as *const u8 as *const i8,
                    &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                        separator.as_mut().unwrap(),
                        0 as i32 as isize,
                    )) as *mut i8,
                    &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                        separator.as_mut().unwrap(),
                        1 as i32 as isize,
                    )) as *mut i8,
                    &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                        separator.as_mut().unwrap(),
                        2 as i32 as isize,
                    )) as *mut i8,
                    &mut num as *mut u32,
                    &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                        separator.as_mut().unwrap(),
                        3 as i32 as isize,
                    )) as *mut i8,
                ) })
            {
                let sep1: i8 = *crate::__laertes_array::Get::<&_>::get_add(
                    (separator).as_ref().unwrap(),
                    0 as i32 as usize,
                );
                let mut i: i32 = 0;
                i = 1 as i32;
                while i < 4 as i32 {
                    if (*crate::__laertes_array::Get::<&_>::get_add(
                        (separator).as_ref().unwrap(),
                        i as usize,
                    )) as i32
                        != sep1 as i32
                    {
                        ptr = 0 as *mut i8;
                        break;
                    } else {
                        i += 1;
                    }
                }
                if num > 0xffff as i32 as u32 {
                    (unsafe { Curl_failf(
                        data,
                        b"Illegal port number in EPSV reply\0" as *const u8 as *const i8,
                    ) });
                    return CURLE_FTP_WEIRD_PASV_REPLY;
                }
                if !ptr.is_null() {
                    (*(borrow_mut(&mut ftpc)).unwrap()).newport =
                        (num & 0xffff as i32 as u32) as u16;
                    let mut fresh16 = &mut ((*(borrow_mut(&mut ftpc)).unwrap()).newhost);
                    *fresh16 =
                        unsafe { Curl_cstrdup.expect("non-null function pointer")(control_address(conn)) };
                    if ((*(borrow(&ftpc)).unwrap()).newhost).is_null() {
                        return CURLE_OUT_OF_MEMORY;
                    }
                }
            } else {
                ptr = 0 as *mut i8;
            }
        }
        if ptr.is_null() {
            (unsafe { Curl_failf(
                data,
                b"Weirdly formatted EPSV reply\0" as *const u8 as *const i8,
            ) });
            return CURLE_FTP_WEIRD_PASV_REPLY;
        }
    } else if (*(borrow(&ftpc)).unwrap()).count1 == 1 as i32 && ftpcode == 227 as i32 {
        let mut ip: Option<crate::__laertes_array::CustomSlice<'static, u32, [u32; 4]>> =
            Some(crate::__laertes_array::CustomSlice::new([
                0 as i32 as u32,
                0 as i32 as u32,
                0 as i32 as u32,
                0 as i32 as u32,
            ]));
        let mut port: Option<crate::__laertes_array::CustomSlice<'static, u32, [u32; 2]>> =
            Some(crate::__laertes_array::CustomSlice::new([
                0 as i32 as u32,
                0 as i32 as u32,
            ]));
        while (unsafe { *str }) != 0 {
            if 6 as i32
                == (unsafe { sscanf(
                    str,
                    b"%u,%u,%u,%u,%u,%u\0" as *const u8 as *const i8,
                    &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                        ip.as_mut().unwrap(),
                        0 as i32 as isize,
                    )) as *mut u32,
                    &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                        ip.as_mut().unwrap(),
                        1 as i32 as isize,
                    )) as *mut u32,
                    &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                        ip.as_mut().unwrap(),
                        2 as i32 as isize,
                    )) as *mut u32,
                    &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                        ip.as_mut().unwrap(),
                        3 as i32 as isize,
                    )) as *mut u32,
                    &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                        port.as_mut().unwrap(),
                        0 as i32 as isize,
                    )) as *mut u32,
                    &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                        port.as_mut().unwrap(),
                        1 as i32 as isize,
                    )) as *mut u32,
                ) })
            {
                break;
            }
            str = unsafe { str.offset(1) };
        }
        if (unsafe { *str }) == 0
            || (*crate::__laertes_array::Get::<&_>::get_add(
                (ip).as_ref().unwrap(),
                0 as i32 as usize,
            )) > 255 as i32 as u32
            || (*crate::__laertes_array::Get::<&_>::get_add(
                (ip).as_ref().unwrap(),
                1 as i32 as usize,
            )) > 255 as i32 as u32
            || (*crate::__laertes_array::Get::<&_>::get_add(
                (ip).as_ref().unwrap(),
                2 as i32 as usize,
            )) > 255 as i32 as u32
            || (*crate::__laertes_array::Get::<&_>::get_add(
                (ip).as_ref().unwrap(),
                3 as i32 as usize,
            )) > 255 as i32 as u32
            || (*crate::__laertes_array::Get::<&_>::get_add(
                (port).as_ref().unwrap(),
                0 as i32 as usize,
            )) > 255 as i32 as u32
            || (*crate::__laertes_array::Get::<&_>::get_add(
                (port).as_ref().unwrap(),
                1 as i32 as usize,
            )) > 255 as i32 as u32
        {
            (unsafe { Curl_failf(
                data,
                b"Couldn't interpret the 227-response\0" as *const u8 as *const i8,
            ) });
            return CURLE_FTP_WEIRD_227_FORMAT;
        }
        if (unsafe { ((*data).set).ftp_skip_ip() }) != 0 {
            (unsafe { Curl_infof(
                data,
                b"Skip %u.%u.%u.%u for data connection, re-use %s instead\0" as *const u8
                    as *const i8,
                *crate::__laertes_array::Get::<&_>::get_add(
                    (ip).as_ref().unwrap(),
                    0 as i32 as usize,
                ),
                *crate::__laertes_array::Get::<&_>::get_add(
                    (ip).as_ref().unwrap(),
                    1 as i32 as usize,
                ),
                *crate::__laertes_array::Get::<&_>::get_add(
                    (ip).as_ref().unwrap(),
                    2 as i32 as usize,
                ),
                *crate::__laertes_array::Get::<&_>::get_add(
                    (ip).as_ref().unwrap(),
                    3 as i32 as usize,
                ),
                (*conn).host.name,
            ) });
            let mut fresh17 = &mut ((*(borrow_mut(&mut ftpc)).unwrap()).newhost);
            *fresh17 = unsafe { Curl_cstrdup.expect("non-null function pointer")(control_address(conn)) };
        } else {
            let mut fresh18 = &mut ((*(borrow_mut(&mut ftpc)).unwrap()).newhost);
            *fresh18 = unsafe { curl_maprintf(
                b"%u.%u.%u.%u\0" as *const u8 as *const i8,
                *crate::__laertes_array::Get::<&_>::get_add(
                    (ip).as_ref().unwrap(),
                    0 as i32 as usize,
                ),
                *crate::__laertes_array::Get::<&_>::get_add(
                    (ip).as_ref().unwrap(),
                    1 as i32 as usize,
                ),
                *crate::__laertes_array::Get::<&_>::get_add(
                    (ip).as_ref().unwrap(),
                    2 as i32 as usize,
                ),
                *crate::__laertes_array::Get::<&_>::get_add(
                    (ip).as_ref().unwrap(),
                    3 as i32 as usize,
                ),
            ) };
        }
        if ((*(borrow_mut(&mut ftpc)).unwrap()).newhost).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (*(borrow_mut(&mut ftpc)).unwrap()).newport =
            (((*crate::__laertes_array::Get::<&_>::get_add(
                (port).as_ref().unwrap(),
                0 as i32 as usize,
            )) << 8 as i32)
                .wrapping_add(
                    *crate::__laertes_array::Get::<&_>::get_add(
                        (port).as_ref().unwrap(),
                        1 as i32 as usize,
                    ),
                )
                & 0xffff as i32 as u32) as u16;
    } else if (*(borrow(&ftpc)).unwrap()).count1 == 0 as i32 {
        return ftp_epsv_disable(data, conn);
    } else {
        (unsafe { Curl_failf(
            data,
            b"Bad PASV/EPSV response: %03d\0" as *const u8 as *const i8,
            ftpcode,
        ) });
        return CURLE_FTP_WEIRD_PASV_REPLY;
    }
    if (unsafe { ((*conn).bits).proxy() }) != 0 {
        let host_name: *const i8 = if (unsafe { ((*conn).bits).socksproxy() }) as i32 != 0 {
            unsafe { (*conn).socks_proxy.host.name }
        } else {
            unsafe { (*conn).http_proxy.host.name }
        };
        rc = Curl_resolv(
            data,
            host_name,
            unsafe { (*conn).port },
            0 as i32 != 0,
            Some(&mut addr),
        );
        if rc as i32 == CURLRESOLV_PENDING as i32 {
            Curl_resolver_wait_resolv(data, Some(&mut addr));
        }
        connectport = (unsafe { (*conn).port }) as u16;
        if addr.is_null() {
            (unsafe { Curl_failf(
                data,
                b"Can't resolve proxy host %s:%hu\0" as *const u8 as *const i8,
                host_name,
                connectport as i32,
            ) });
            return CURLE_COULDNT_RESOLVE_PROXY;
        }
    } else {
        if (unsafe { ((*conn).bits).tcp_fastopen() }) as i32 != 0
            && (unsafe { ((*conn).bits).reuse() }) == 0
            && (unsafe { *((*(borrow(&ftpc)).unwrap()).newhost).offset(0 as i32 as isize) }) == 0
        {
            Curl_conninfo_remote(data, conn, unsafe { (*conn).sock[0 as i32 as usize] });
            (unsafe { Curl_cfree.expect("non-null function pointer")(
                (*(borrow_mut(&mut ftpc)).unwrap()).newhost as *mut libc::c_void,
            ) });
            let mut fresh19 = &mut ((*(borrow_mut(&mut ftpc)).unwrap()).newhost);
            *fresh19 = 0 as *mut i8;
            let mut fresh20 = &mut ((*(borrow_mut(&mut ftpc)).unwrap()).newhost);
            *fresh20 = unsafe { Curl_cstrdup.expect("non-null function pointer")(control_address(conn)) };
            if ((*(borrow(&ftpc)).unwrap()).newhost).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        }
        rc = Curl_resolv(
            data,
            (*(borrow(&ftpc)).unwrap()).newhost,
            (*(borrow_mut(&mut ftpc)).unwrap()).newport as i32,
            0 as i32 != 0,
            Some(&mut addr),
        );
        if rc as i32 == CURLRESOLV_PENDING as i32 {
            Curl_resolver_wait_resolv(data, Some(&mut addr));
        }
        connectport = (*(borrow_mut(&mut ftpc)).unwrap()).newport;
        if addr.is_null() {
            (unsafe { Curl_failf(
                data,
                b"Can't resolve new host %s:%hu\0" as *const u8 as *const i8,
                (*(borrow(&ftpc)).unwrap()).newhost,
                connectport as i32,
            ) });
            return CURLE_FTP_CANT_GET_HOST;
        }
    }
    (unsafe { (*conn).bits.tcpconnect[1 as i32 as usize] = 0 as i32 != 0 });
    result = Curl_connecthost(data, conn, addr);
    if result as u64 != 0 {
        Curl_resolv_unlock(data, addr);
        if (*(borrow(&ftpc)).unwrap()).count1 == 0 as i32 && ftpcode == 229 as i32 {
            return ftp_epsv_disable(data, conn);
        }
        return result;
    }
    if (unsafe { ((*data).set).verbose() }) != 0 {
        ftp_pasv_verbose(
            data,
            unsafe { (*addr).addr },
            (*(borrow_mut(&mut ftpc)).unwrap()).newhost,
            connectport as i32,
        );
    }
    Curl_resolv_unlock(data, addr);
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).secondaryhostname as *mut libc::c_void) });
    let mut fresh21 = unsafe { &mut ((*conn).secondaryhostname) };
    *fresh21 = 0 as *mut i8;
    (unsafe { (*conn).secondary_port = (*(borrow_mut(&mut ftpc)).unwrap()).newport });
    let mut fresh22 = unsafe { &mut ((*conn).secondaryhostname) };
    *fresh22 =
        unsafe { Curl_cstrdup.expect("non-null function pointer")((*(borrow(&ftpc)).unwrap()).newhost) };
    if (unsafe { (*conn).secondaryhostname }).is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    let mut fresh23 = unsafe { &mut ((*conn).bits) };
    (*fresh23).set_do_more(1 as i32 as bit);
    _state(data, FTP_STOP);
    return result;
}
extern "C" fn ftp_state_port_resp(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut ftpcode: i32,
) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    let mut fcmd: u32 = (*(borrow_mut(&mut ftpc)).unwrap()).count1 as ftpport;
    let mut result: u32 = CURLE_OK;
    if ftpcode / 100 as i32 != 2 as i32 {
        if EPRT as i32 as u32 == fcmd as u32 {
            (unsafe { Curl_infof(data, b"disabling EPRT usage\0" as *const u8 as *const i8) });
            let mut fresh24 = unsafe { &mut ((*conn).bits) };
            (*fresh24).set_ftp_use_eprt(0 as i32 as bit);
        }
        fcmd += 1;
        if fcmd as u32 == DONE as i32 as u32 {
            (unsafe { Curl_failf(data, b"Failed to do PORT\0" as *const u8 as *const i8) });
            result = CURLE_FTP_PORT_FAILED;
        } else {
            result = ftp_state_use_port(data, fcmd);
        }
    } else {
        (unsafe { Curl_infof(
            data,
            b"Connect data stream actively\0" as *const u8 as *const i8,
        ) });
        _state(data, FTP_STOP);
        result = ftp_dophase_done(data, 0 as i32 != 0);
    }
    return result;
}
extern "C" fn ftp_state_mdtm_resp(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut ftpcode: i32,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut ftp: *mut crate::src::lib::http2::FTP = unsafe { (*data).req.p.ftp };
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    match ftpcode {
        213 => {
            let mut year: i32 = 0;
            let mut month: i32 = 0;
            let mut day: i32 = 0;
            let mut hour: i32 = 0;
            let mut minute: i32 = 0;
            let mut second: i32 = 0;
            if 6 as i32
                == (unsafe { sscanf(
                    &mut *((*data).state.buffer).offset(4 as i32 as isize) as *mut i8,
                    b"%04d%02d%02d%02d%02d%02d\0" as *const u8 as *const i8,
                    &mut year as *mut i32,
                    &mut month as *mut i32,
                    &mut day as *mut i32,
                    &mut hour as *mut i32,
                    &mut minute as *mut i32,
                    &mut second as *mut i32,
                ) })
            {
                let mut timebuf: [i8; 24] = [0; 24];
                (unsafe { curl_msnprintf(
                    timebuf.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 24]>() as u64,
                    b"%04d%02d%02d %02d:%02d:%02d GMT\0" as *const u8 as *const i8,
                    year,
                    month,
                    day,
                    hour,
                    minute,
                    second,
                ) });
                (unsafe { (*data).info.filetime = Curl_getdate_capped(timebuf.as_mut_ptr()) });
            }
            if (unsafe { ((*data).set).opt_no_body() }) as i32 != 0
                && !((*(borrow(&ftpc)).unwrap()).file).is_null()
                && (unsafe { ((*data).set).get_filetime() }) as i32 != 0
                && (unsafe { (*data).info.filetime }) >= 0 as i32 as i64
            {
                let mut headerbuf: [i8; 128] = [0; 128];
                let mut headerbuflen: i32 = 0;
                let mut filetime: i64 = unsafe { (*data).info.filetime };
                let mut buffer: crate::src::lib::altsvc::tm = tm {
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
                let mut tm: *const crate::src::lib::altsvc::tm = &mut buffer;
                result = Curl_gmtime(filetime, &mut buffer);
                if result as u64 != 0 {
                    return result;
                }
                headerbuflen = unsafe { curl_msnprintf(
                    headerbuf.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 128]>() as u64,
                    b"Last-Modified: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n\0" as *const u8
                        as *const i8,
                    Curl_wkday[(if (*tm).tm_wday != 0 {
                        (*tm).tm_wday - 1 as i32
                    } else {
                        6 as i32
                    }) as usize],
                    (*tm).tm_mday,
                    Curl_month[(*tm).tm_mon as usize],
                    (*tm).tm_year + 1900 as i32,
                    (*tm).tm_hour,
                    (*tm).tm_min,
                    (*tm).tm_sec,
                ) };
                result = Curl_client_write(
                    data,
                    (1 as i32) << 0 as i32 | (1 as i32) << 1 as i32,
                    headerbuf.as_mut_ptr(),
                    headerbuflen as size_t,
                );
                if result as u64 != 0 {
                    return result;
                }
            }
        }
        550 => {
            (unsafe { Curl_failf(
                data,
                b"Given file does not exist\0" as *const u8 as *const i8,
            ) });
            result = CURLE_REMOTE_FILE_NOT_FOUND;
        }
        _ => {
            (unsafe { Curl_infof(
                data,
                b"unsupported MDTM reply format\0" as *const u8 as *const i8,
            ) });
        }
    }
    if (unsafe { (*data).set.timecondition }) as u64 != 0 {
        if (unsafe { (*data).info.filetime }) > 0 as i32 as i64 && (unsafe { (*data).set.timevalue }) > 0 as i32 as i64 {
            match (unsafe { (*data).set.timecondition }) as u32 {
                2 => {
                    if (unsafe { (*data).info.filetime }) > (unsafe { (*data).set.timevalue }) {
                        (unsafe { Curl_infof(
                            data,
                            b"The requested document is not old enough\0" as *const u8 as *const i8,
                        ) });
                        (unsafe { (*ftp).transfer = PPTRANSFER_NONE });
                        let mut fresh26 = unsafe { &mut ((*data).info) };
                        (*fresh26).set_timecond(1 as i32 as bit);
                        _state(data, FTP_STOP);
                        return CURLE_OK;
                    }
                }
                1 | _ => {
                    if (unsafe { (*data).info.filetime }) <= (unsafe { (*data).set.timevalue }) {
                        (unsafe { Curl_infof(
                            data,
                            b"The requested document is not new enough\0" as *const u8 as *const i8,
                        ) });
                        (unsafe { (*ftp).transfer = PPTRANSFER_NONE });
                        let mut fresh25 = unsafe { &mut ((*data).info) };
                        (*fresh25).set_timecond(1 as i32 as bit);
                        _state(data, FTP_STOP);
                        return CURLE_OK;
                    }
                }
            }
        } else {
            (unsafe { Curl_infof(
                data,
                b"Skipping time comparison\0" as *const u8 as *const i8,
            ) });
        }
    }
    if result as u64 == 0 {
        result = ftp_state_type(data);
    }
    return result;
}
extern "C" fn ftp_state_type_resp(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut ftpcode: i32,
    mut instate: u32,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    if ftpcode / 100 as i32 != 2 as i32 {
        (unsafe { Curl_failf(
            data,
            b"Couldn't set desired mode\0" as *const u8 as *const i8,
        ) });
        return CURLE_FTP_COULDNT_SET_TYPE;
    }
    if ftpcode != 200 as i32 {
        (unsafe { Curl_infof(
            data,
            b"Got a %03d response code instead of the assumed 200\0" as *const u8 as *const i8,
            ftpcode,
        ) });
    }
    if instate as u32 == FTP_TYPE as i32 as u32 {
        result = ftp_state_size(data, conn);
    } else if instate as u32 == FTP_LIST_TYPE as i32 as u32 {
        result = ftp_state_list(data);
    } else if instate as u32 == FTP_RETR_TYPE as i32 as u32 {
        result = ftp_state_retr_prequote(data);
    } else if instate as u32 == FTP_STOR_TYPE as i32 as u32 {
        result = ftp_state_stor_prequote(data);
    }
    return result;
}
extern "C" fn ftp_state_retr(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut filesize: i64,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut ftp: *mut crate::src::lib::http2::FTP = unsafe { (*data).req.p.ftp };
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftpc: *mut crate::src::lib::http2::ftp_conn = unsafe { &mut (*conn).proto.ftpc };
    if (unsafe { (*data).set.max_filesize }) != 0 && filesize > (unsafe { (*data).set.max_filesize }) {
        (unsafe { Curl_failf(
            data,
            b"Maximum file size exceeded\0" as *const u8 as *const i8,
        ) });
        return CURLE_FILESIZE_EXCEEDED;
    }
    (unsafe { (*ftp).downloadsize = filesize });
    if (unsafe { (*data).state.resume_from }) != 0 {
        if filesize == -(1 as i32) as i64 {
            (unsafe { Curl_infof(
                data,
                b"ftp server doesn't support SIZE\0" as *const u8 as *const i8,
            ) });
        } else if (unsafe { (*data).state.resume_from }) < 0 as i32 as i64 {
            if filesize < -(unsafe { (*data).state.resume_from }) {
                (unsafe { Curl_failf(
                    data,
                    b"Offset (%ld) was beyond file size (%ld)\0" as *const u8 as *const i8,
                    (*data).state.resume_from,
                    filesize,
                ) });
                return CURLE_BAD_DOWNLOAD_RESUME;
            }
            (unsafe { (*ftp).downloadsize = -(*data).state.resume_from });
            (unsafe { (*data).state.resume_from = filesize - (*ftp).downloadsize });
        } else {
            if filesize < (unsafe { (*data).state.resume_from }) {
                (unsafe { Curl_failf(
                    data,
                    b"Offset (%ld) was beyond file size (%ld)\0" as *const u8 as *const i8,
                    (*data).state.resume_from,
                    filesize,
                ) });
                return CURLE_BAD_DOWNLOAD_RESUME;
            }
            (unsafe { (*ftp).downloadsize = filesize - (*data).state.resume_from });
        }
        if (unsafe { (*ftp).downloadsize }) == 0 as i32 as i64 {
            Curl_setup_transfer(
                data,
                -(1 as i32),
                -(1 as i32) as curl_off_t,
                0 as i32 != 0,
                -(1 as i32),
            );
            (unsafe { Curl_infof(
                data,
                b"File already completely downloaded\0" as *const u8 as *const i8,
            ) });
            (unsafe { (*ftp).transfer = PPTRANSFER_NONE });
            _state(data, FTP_STOP);
            return CURLE_OK;
        }
        (unsafe { Curl_infof(
            data,
            b"Instructs server to resume from offset %ld\0" as *const u8 as *const i8,
            (*data).state.resume_from,
        ) });
        result = unsafe { Curl_pp_sendf(
            data,
            Some(&mut (*ftpc).pp),
            b"REST %ld\0" as *const u8 as *const i8,
            (*data).state.resume_from,
        ) };
        if result as u64 == 0 {
            _state(data, FTP_RETR_REST);
        }
    } else {
        result = unsafe { Curl_pp_sendf(
            data,
            Some(&mut (*ftpc).pp),
            b"RETR %s\0" as *const u8 as *const i8,
            (*ftpc).file,
        ) };
        if result as u64 == 0 {
            _state(data, FTP_RETR);
        }
    }
    return result;
}
extern "C" fn ftp_state_size_resp(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut ftpcode: i32,
    mut instate: u32,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut filesize: i64 = -(1 as i32) as curl_off_t;
    let mut buf: *mut i8 = unsafe { (*data).state.buffer };
    if ftpcode == 213 as i32 {
        let mut start: *mut i8 = (unsafe { &mut *buf.offset(4 as i32 as isize) }) as *mut i8;
        let mut fdigit: *mut i8 = unsafe { strchr(start, '\r' as i32) };
        if !fdigit.is_null() {
            loop {
                fdigit = unsafe { fdigit.offset(-1) };
                if !(Curl_isdigit((unsafe { *fdigit }) as u8 as i32) != 0 && fdigit > start) {
                    break;
                }
            }
            if Curl_isdigit((unsafe { *fdigit }) as u8 as i32) == 0 {
                fdigit = unsafe { fdigit.offset(1) };
            }
        } else {
            fdigit = start;
        }
        curlx_strtoofft(
            fdigit,
            Option::<&'_ mut *mut i8>::None,
            0 as i32,
            Some(&mut filesize),
        );
    } else if ftpcode == 550 as i32 {
        if instate as u32 != FTP_STOR_SIZE as i32 as u32 {
            (unsafe { Curl_failf(data, b"The file does not exist\0" as *const u8 as *const i8) });
            return CURLE_REMOTE_FILE_NOT_FOUND;
        }
    }
    if instate as u32 == FTP_SIZE as i32 as u32 {
        if -(1 as i32) as i64 != filesize {
            let mut clbuf: [i8; 128] = [0; 128];
            let mut clbuflen: i32 = unsafe { curl_msnprintf(
                clbuf.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 128]>() as u64,
                b"Content-Length: %ld\r\n\0" as *const u8 as *const i8,
                filesize,
            ) };
            result = Curl_client_write(
                data,
                (1 as i32) << 0 as i32 | (1 as i32) << 1 as i32,
                clbuf.as_mut_ptr(),
                clbuflen as size_t,
            );
            if result as u64 != 0 {
                return result;
            }
        }
        Curl_pgrsSetDownloadSize(data, filesize);
        result = ftp_state_rest(data, unsafe { (*data).conn });
    } else if instate as u32 == FTP_RETR_SIZE as i32 as u32 {
        Curl_pgrsSetDownloadSize(data, filesize);
        result = ftp_state_retr(data, filesize);
    } else if instate as u32 == FTP_STOR_SIZE as i32 as u32 {
        (unsafe { (*data).state.resume_from = filesize });
        result = ftp_state_ul_setup(data, 1 as i32 != 0);
    }
    return result;
}
extern "C" fn ftp_state_rest_resp(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut ftpcode: i32,
    mut instate: u32,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut ftpc: *mut crate::src::lib::http2::ftp_conn = unsafe { &mut (*conn).proto.ftpc };
    match instate as u32 {
        27 => {
            if ftpcode != 350 as i32 {
                (unsafe { Curl_failf(data, b"Couldn't use REST\0" as *const u8 as *const i8) });
                result = CURLE_FTP_COULDNT_USE_REST;
            } else {
                result = unsafe { Curl_pp_sendf(
                    data,
                    Some(&mut (*ftpc).pp),
                    b"RETR %s\0" as *const u8 as *const i8,
                    (*ftpc).file,
                ) };
                if result as u64 == 0 {
                    _state(data, FTP_RETR);
                }
            }
        }
        26 | _ => {
            if ftpcode == 350 as i32 {
                let mut buffer: [i8; 24] = *(unsafe { core::intrinsics::transmute::<
                    &'_ [u8; 24],
                    &'_ mut [i8; 24],
                >(b"Accept-ranges: bytes\r\n\0\0") });
                result = Curl_client_write(
                    data,
                    (1 as i32) << 0 as i32 | (1 as i32) << 1 as i32,
                    buffer.as_mut_ptr(),
                    unsafe { strlen(buffer.as_mut_ptr()) },
                );
                if result as u64 != 0 {
                    return result;
                }
            }
            result = ftp_state_prepare_transfer(data);
        }
    }
    return result;
}
extern "C" fn ftp_state_stor_resp(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut ftpcode: i32,
    mut instate: u32,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    if ftpcode >= 400 as i32 {
        (unsafe { Curl_failf(
            data,
            b"Failed FTP upload: %0d\0" as *const u8 as *const i8,
            ftpcode,
        ) });
        _state(data, FTP_STOP);
        return CURLE_UPLOAD_FAILED;
    }
    (unsafe { (*conn).proto.ftpc.state_saved = instate });
    if (unsafe { ((*data).set).ftp_use_port() }) != 0 {
        let mut connected: bool = false;
        _state(data, FTP_STOP);
        result = AllowServerConnect(data, Some(&mut connected));
        if result as u64 != 0 {
            return result;
        }
        if !connected {
            let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> =
                Some(unsafe { &mut (*conn).proto.ftpc });
            (unsafe { Curl_infof(
                data,
                b"Data conn was not available immediately\0" as *const u8 as *const i8,
            ) });
            (*(borrow_mut(&mut ftpc)).unwrap()).wait_data_conn = 1 as i32 != 0;
        }
        return CURLE_OK;
    }
    return InitiateTransfer(data);
}
extern "C" fn ftp_state_get_resp(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut ftpcode: i32,
    mut instate: u32,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut ftp: *mut crate::src::lib::http2::FTP = unsafe { (*data).req.p.ftp };
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    if ftpcode == 150 as i32 || ftpcode == 125 as i32 {
        let mut size: i64 = -(1 as i32) as curl_off_t;
        if instate as u32 != FTP_LIST as i32 as u32
            && (unsafe { ((*data).state).prefer_ascii() }) == 0
            && (unsafe { (*ftp).downloadsize }) < 1 as i32 as i64
        {
            let mut bytes: *mut i8 = 0 as *mut i8;
            let mut buf: *mut i8 = unsafe { (*data).state.buffer };
            bytes = unsafe { strstr(buf, b" bytes\0" as *const u8 as *const i8) };
            if !bytes.is_null() {
                bytes = unsafe { bytes.offset(-1) };
                let mut in_0: i64 = (unsafe { bytes.offset_from(buf) }) as i64;
                loop {
                    in_0 -= 1;
                    if !(in_0 != 0) {
                        break;
                    }
                    if '(' as i32 == (unsafe { *bytes }) as i32 {
                        break;
                    }
                    if Curl_isdigit((unsafe { *bytes }) as u8 as i32) == 0 {
                        bytes = 0 as *mut i8;
                        break;
                    } else {
                        bytes = unsafe { bytes.offset(-1) };
                    }
                }
                if !bytes.is_null() {
                    bytes = unsafe { bytes.offset(1) };
                    curlx_strtoofft(
                        bytes,
                        Option::<&'_ mut *mut i8>::None,
                        0 as i32,
                        Some(&mut size),
                    );
                }
            }
        } else if (unsafe { (*ftp).downloadsize }) > -(1 as i32) as i64 {
            size = unsafe { (*ftp).downloadsize };
        }
        if size > (unsafe { (*data).req.maxdownload }) && (unsafe { (*data).req.maxdownload }) > 0 as i32 as i64 {
            let mut fresh27 = unsafe { &mut ((*data).req.size) };
            *fresh27 = unsafe { (*data).req.maxdownload };
            size = *fresh27;
        } else if instate as u32 != FTP_LIST as i32 as u32
            && (unsafe { ((*data).state).prefer_ascii() }) as i32 != 0
        {
            size = -(1 as i32) as curl_off_t;
        }
        (unsafe { Curl_infof(
            data,
            b"Maxdownload = %ld\0" as *const u8 as *const i8,
            (*data).req.maxdownload,
        ) });
        if instate as u32 != FTP_LIST as i32 as u32 {
            (unsafe { Curl_infof(
                data,
                b"Getting file with size: %ld\0" as *const u8 as *const i8,
                size,
            ) });
        }
        (unsafe { (*conn).proto.ftpc.state_saved = instate });
        (unsafe { (*conn).proto.ftpc.retr_size_saved = size });
        if (unsafe { ((*data).set).ftp_use_port() }) != 0 {
            let mut connected: bool = false;
            result = AllowServerConnect(data, Some(&mut connected));
            if result as u64 != 0 {
                return result;
            }
            if !connected {
                let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> =
                    Some(unsafe { &mut (*conn).proto.ftpc });
                (unsafe { Curl_infof(
                    data,
                    b"Data conn was not available immediately\0" as *const u8 as *const i8,
                ) });
                _state(data, FTP_STOP);
                (*(borrow_mut(&mut ftpc)).unwrap()).wait_data_conn = 1 as i32 != 0;
            }
        } else {
            return InitiateTransfer(data);
        }
    } else if instate as u32 == FTP_LIST as i32 as u32 && ftpcode == 450 as i32 {
        (unsafe { (*ftp).transfer = PPTRANSFER_NONE });
        _state(data, FTP_STOP);
    } else {
        (unsafe { Curl_failf(
            data,
            b"RETR response: %03d\0" as *const u8 as *const i8,
            ftpcode,
        ) });
        return (if instate as u32 == FTP_RETR as i32 as u32 && ftpcode == 550 as i32 {
            CURLE_REMOTE_FILE_NOT_FOUND as i32
        } else {
            CURLE_FTP_COULDNT_RETR_FILE as i32
        }) as CURLcode;
    }
    return result;
}
extern "C" fn ftp_state_loggedin(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    if (unsafe { ((*conn).bits).ftp_use_control_ssl() }) != 0 {
        result = unsafe { Curl_pp_sendf(
            data,
            Some(&mut (*conn).proto.ftpc.pp),
            b"PBSZ %d\0" as *const u8 as *const i8,
            0 as i32,
        ) };
        if result as u64 == 0 {
            _state(data, FTP_PBSZ);
        }
    } else {
        result = ftp_state_pwd(data, conn);
    }
    return result;
}
extern "C" fn ftp_state_user_resp(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut ftpcode: i32,
    mut _instate: u32,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    if ftpcode == 331 as i32 && (*(borrow(&ftpc)).unwrap()).state as u32 == FTP_USER as i32 as u32 {
        result = unsafe { Curl_pp_sendf(
            data,
            Some(&mut (*(borrow_mut(&mut ftpc)).unwrap()).pp),
            b"PASS %s\0" as *const u8 as *const i8,
            if !((*conn).passwd).is_null() {
                (*conn).passwd as *const i8
            } else {
                b"\0" as *const u8 as *const i8
            },
        ) };
        if result as u64 == 0 {
            _state(data, FTP_PASS);
        }
    } else if ftpcode / 100 as i32 == 2 as i32 {
        result = ftp_state_loggedin(data);
    } else if ftpcode == 332 as i32 {
        if !(unsafe { (*data).set.str_0[STRING_FTP_ACCOUNT as i32 as usize] }).is_null() {
            result = unsafe { Curl_pp_sendf(
                data,
                Some(&mut (*(borrow_mut(&mut ftpc)).unwrap()).pp),
                b"ACCT %s\0" as *const u8 as *const i8,
                (*data).set.str_0[STRING_FTP_ACCOUNT as i32 as usize],
            ) };
            if result as u64 == 0 {
                _state(data, FTP_ACCT);
            }
        } else {
            (unsafe { Curl_failf(
                data,
                b"ACCT requested but none available\0" as *const u8 as *const i8,
            ) });
            result = CURLE_LOGIN_DENIED;
        }
    } else if !(unsafe { (*data).set.str_0[STRING_FTP_ALTERNATIVE_TO_USER as i32 as usize] }).is_null()
        && (unsafe { ((*data).state).ftp_trying_alternative() }) == 0
    {
        result = unsafe { Curl_pp_sendf(
            data,
            Some(&mut (*(borrow_mut(&mut ftpc)).unwrap()).pp),
            b"%s\0" as *const u8 as *const i8,
            (*data).set.str_0[STRING_FTP_ALTERNATIVE_TO_USER as i32 as usize],
        ) };
        if result as u64 == 0 {
            let mut fresh28 = unsafe { &mut ((*data).state) };
            (*fresh28).set_ftp_trying_alternative(1 as i32 as bit);
            _state(data, FTP_USER);
        }
    } else {
        (unsafe { Curl_failf(
            data,
            b"Access denied: %03d\0" as *const u8 as *const i8,
            ftpcode,
        ) });
        result = CURLE_LOGIN_DENIED;
    }
    return result;
}
extern "C" fn ftp_state_acct_resp(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut ftpcode: i32,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    if ftpcode != 230 as i32 {
        (unsafe { Curl_failf(
            data,
            b"ACCT rejected by server: %03d\0" as *const u8 as *const i8,
            ftpcode,
        ) });
        result = CURLE_FTP_WEIRD_PASS_REPLY;
    } else {
        result = ftp_state_loggedin(data);
    }
    return result;
}
extern "C" fn ftp_statemachine(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut sock: i32 = unsafe { (*conn).sock[0 as i32 as usize] };
    let mut ftpcode: i32 = 0;
    let mut ftpc: *mut crate::src::lib::http2::ftp_conn = unsafe { &mut (*conn).proto.ftpc };
    let mut pp: *mut crate::src::lib::http2::pingpong = unsafe { &mut (*ftpc).pp };
    static mut ftpauth: [[i8; 4]; 2] = unsafe {
        [
            *core::intrinsics::transmute::<&'_ [u8; 4], &'_ [i8; 4]>(b"SSL\0"),
            *core::intrinsics::transmute::<&'_ [u8; 4], &'_ [i8; 4]>(b"TLS\0"),
        ]
    };
    let mut nread: u64 = 0 as i32 as size_t;
    if (unsafe { (*pp).sendleft }) != 0 {
        return Curl_pp_flushsend(data, pp);
    }
    result = ftp_readresp(data, sock, pp, &mut ftpcode, Some(&mut nread));
    if result as u64 != 0 {
        return result;
    }
    if ftpcode != 0 {
        let mut current_block_187: u64;
        match (unsafe { (*ftpc).state }) as u32 {
            1 => {
                if ftpcode == 230 as i32 {
                    if (unsafe { (*data).set.use_ssl }) as u32 <= CURLUSESSL_TRY as i32 as u32
                        || (unsafe { ((*conn).bits).ftp_use_control_ssl() }) as i32 != 0
                    {
                        return ftp_state_user_resp(data, ftpcode, unsafe { (*ftpc).state });
                    }
                } else if ftpcode != 220 as i32 {
                    (unsafe { Curl_failf(
                        data,
                        b"Got a %03d ftp-server response when 220 was expected\0" as *const u8
                            as *const i8,
                        ftpcode,
                    ) });
                    return CURLE_WEIRD_SERVER_REPLY;
                }
                if (unsafe { (*data).set.use_ssl }) as u32 != 0 && (unsafe { ((*conn).bits).ftp_use_control_ssl() }) == 0 {
                    (unsafe { (*ftpc).count3 = 0 as i32 });
                    match (unsafe { (*data).set.ftpsslauth }) as u32 {
                        0 | 1 => {
                            (unsafe { (*ftpc).count2 = 1 as i32 });
                            (unsafe { (*ftpc).count1 = 0 as i32 });
                        }
                        2 => {
                            (unsafe { (*ftpc).count2 = -(1 as i32) });
                            (unsafe { (*ftpc).count1 = 1 as i32 });
                        }
                        _ => {
                            (unsafe { Curl_failf(
                                data,
                                b"unsupported parameter to CURLOPT_FTPSSLAUTH: %d\0" as *const u8
                                    as *const i8,
                                (*data).set.ftpsslauth as i32,
                            ) });
                            return CURLE_UNKNOWN_OPTION;
                        }
                    }
                    result = unsafe { Curl_pp_sendf(
                        data,
                        Some(&mut (*ftpc).pp),
                        b"AUTH %s\0" as *const u8 as *const i8,
                        (ftpauth[(*ftpc).count1 as usize]).as_ptr(),
                    ) };
                    if result as u64 == 0 {
                        _state(data, FTP_AUTH);
                    }
                } else {
                    result = ftp_state_user(data, conn);
                }
            }
            2 => {
                if (unsafe { (*pp).cache_size }) != 0 {
                    return CURLE_WEIRD_SERVER_REPLY;
                }
                if ftpcode == 234 as i32 || ftpcode == 334 as i32 {
                    result = Curl_ssl_connect(data, conn, 0 as i32);
                    if result as u64 == 0 {
                        let mut fresh29 = unsafe { &mut ((*conn).bits) };
                        (*fresh29).set_ftp_use_data_ssl(0 as i32 as bit);
                        let mut fresh30 = unsafe { &mut ((*conn).bits) };
                        (*fresh30).set_ftp_use_control_ssl(1 as i32 as bit);
                        result = ftp_state_user(data, conn);
                    }
                } else if (unsafe { (*ftpc).count3 }) < 1 as i32 {
                    let mut fresh31 = unsafe { &mut ((*ftpc).count3) };
                    *fresh31 += 1;
                    (unsafe { (*ftpc).count1 += (*ftpc).count2 });
                    result = unsafe { Curl_pp_sendf(
                        data,
                        Some(&mut (*ftpc).pp),
                        b"AUTH %s\0" as *const u8 as *const i8,
                        (ftpauth[(*ftpc).count1 as usize]).as_ptr(),
                    ) };
                } else if (unsafe { (*data).set.use_ssl }) as u32 > CURLUSESSL_TRY as i32 as u32 {
                    result = CURLE_USE_SSL_FAILED;
                } else {
                    result = ftp_state_user(data, conn);
                }
            }
            3 | 4 => {
                result = ftp_state_user_resp(data, ftpcode, unsafe { (*ftpc).state });
            }
            5 => {
                result = ftp_state_acct_resp(data, ftpcode);
            }
            6 => {
                result = unsafe { Curl_pp_sendf(
                    data,
                    Some(&mut (*ftpc).pp),
                    b"PROT %c\0" as *const u8 as *const i8,
                    if (*data).set.use_ssl as u32 == CURLUSESSL_CONTROL as i32 as u32 {
                        'C' as i32
                    } else {
                        'P' as i32
                    },
                ) };
                if result as u64 == 0 {
                    _state(data, FTP_PROT);
                }
            }
            7 => {
                if ftpcode / 100 as i32 == 2 as i32 {
                    let mut fresh32 = unsafe { &mut ((*conn).bits) };
                    (*fresh32).set_ftp_use_data_ssl(
                        (if (unsafe { (*data).set.use_ssl }) as u32 != CURLUSESSL_CONTROL as i32 as u32 {
                            1 as i32
                        } else {
                            0 as i32
                        }) as bit,
                    );
                } else if (unsafe { (*data).set.use_ssl }) as u32 > CURLUSESSL_CONTROL as i32 as u32 {
                    return CURLE_USE_SSL_FAILED;
                }
                if (unsafe { (*data).set.ftp_ccc }) as u64 != 0 {
                    result = unsafe { Curl_pp_sendf(
                        data,
                        Some(&mut (*ftpc).pp),
                        b"%s\0" as *const u8 as *const i8,
                        b"CCC\0" as *const u8 as *const i8,
                    ) };
                    if result as u64 == 0 {
                        _state(data, FTP_CCC);
                    }
                } else {
                    result = ftp_state_pwd(data, conn);
                }
            }
            8 => {
                if ftpcode < 500 as i32 {
                    result = Curl_ssl_shutdown(data, conn, 0 as i32);
                    if result as u64 != 0 {
                        (unsafe { Curl_failf(
                            data,
                            b"Failed to clear the command channel (CCC)\0" as *const u8
                                as *const i8,
                        ) });
                    }
                }
                if result as u64 == 0 {
                    result = ftp_state_pwd(data, conn);
                }
            }
            9 => {
                if ftpcode == 257 as i32 {
                    let mut ptr: *mut i8 =
                        (unsafe { &mut *((*data).state.buffer).offset(4 as i32 as isize) }) as *mut i8;
                    let buf_size: u64 = (unsafe { (*data).set.buffer_size }) as size_t;
                    let mut dir: *mut i8 = 0 as *mut i8;
                    let mut entry_extracted: bool = 0 as i32 != 0;
                    dir = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
                        nread.wrapping_add(1 as i32 as u64),
                    ) }) as *mut i8;
                    if dir.is_null() {
                        return CURLE_OUT_OF_MEMORY;
                    }
                    while ptr < (unsafe { &mut *((*data).state.buffer).offset(buf_size as isize) }) as *mut i8
                        && (unsafe { *ptr }) as i32 != '\n' as i32
                        && (unsafe { *ptr }) as i32 != '\u{0}' as i32
                        && (unsafe { *ptr }) as i32 != '"' as i32
                    {
                        ptr = unsafe { ptr.offset(1) };
                    }
                    if '"' as i32 == (unsafe { *ptr }) as i32 {
                        let mut store: *mut i8 = 0 as *mut i8;
                        ptr = unsafe { ptr.offset(1) };
                        store = dir;
                        while (unsafe { *ptr }) != 0 {
                            if '"' as i32 == (unsafe { *ptr }) as i32 {
                                if '"' as i32 == (unsafe { *ptr.offset(1 as i32 as isize) }) as i32 {
                                    (unsafe { *store = *ptr.offset(1 as i32 as isize) });
                                    ptr = unsafe { ptr.offset(1) };
                                } else {
                                    entry_extracted = 1 as i32 != 0;
                                    break;
                                }
                            } else {
                                (unsafe { *store = *ptr });
                            }
                            store = unsafe { store.offset(1) };
                            ptr = unsafe { ptr.offset(1) };
                        }
                        (unsafe { *store = '\u{0}' as i32 as i8 });
                    }
                    if entry_extracted {
                        if (unsafe { (*ftpc).server_os }).is_null()
                            && (unsafe { *dir.offset(0 as i32 as isize) }) as i32 != '/' as i32
                        {
                            result = unsafe { Curl_pp_sendf(
                                data,
                                Some(&mut (*ftpc).pp),
                                b"%s\0" as *const u8 as *const i8,
                                b"SYST\0" as *const u8 as *const i8,
                            ) };
                            if result as u64 != 0 {
                                (unsafe { Curl_cfree.expect("non-null function pointer")(
                                    dir as *mut libc::c_void,
                                ) });
                                return result;
                            }
                            (unsafe { Curl_cfree.expect("non-null function pointer")(
                                (*ftpc).entrypath as *mut libc::c_void,
                            ) });
                            let mut fresh33 = unsafe { &mut ((*ftpc).entrypath) };
                            *fresh33 = 0 as *mut i8;
                            let mut fresh34 = unsafe { &mut ((*ftpc).entrypath) };
                            *fresh34 = dir;
                            (unsafe { Curl_infof(
                                data,
                                b"Entry path is '%s'\0" as *const u8 as *const i8,
                                (*ftpc).entrypath,
                            ) });
                            let mut fresh35 = unsafe { &mut ((*data).state.most_recent_ftp_entrypath) };
                            *fresh35 = unsafe { (*ftpc).entrypath };
                            _state(data, FTP_SYST);
                            current_block_187 = 10490607306284298299;
                        } else {
                            (unsafe { Curl_cfree.expect("non-null function pointer")(
                                (*ftpc).entrypath as *mut libc::c_void,
                            ) });
                            let mut fresh36 = unsafe { &mut ((*ftpc).entrypath) };
                            *fresh36 = 0 as *mut i8;
                            let mut fresh37 = unsafe { &mut ((*ftpc).entrypath) };
                            *fresh37 = dir;
                            (unsafe { Curl_infof(
                                data,
                                b"Entry path is '%s'\0" as *const u8 as *const i8,
                                (*ftpc).entrypath,
                            ) });
                            let mut fresh38 = unsafe { &mut ((*data).state.most_recent_ftp_entrypath) };
                            *fresh38 = unsafe { (*ftpc).entrypath };
                            current_block_187 = 17917672080766325409;
                        }
                    } else {
                        (unsafe { Curl_cfree.expect("non-null function pointer")(dir as *mut libc::c_void) });
                        (unsafe { Curl_infof(
                            data,
                            b"Failed to figure out path\0" as *const u8 as *const i8,
                        ) });
                        current_block_187 = 17917672080766325409;
                    }
                } else {
                    current_block_187 = 17917672080766325409;
                }
                match current_block_187 {
                    10490607306284298299 => {}
                    _ => {
                        _state(data, FTP_STOP);
                    }
                }
            }
            10 => {
                if ftpcode == 215 as i32 {
                    let mut ptr_0: *mut i8 =
                        (unsafe { &mut *((*data).state.buffer).offset(4 as i32 as isize) }) as *mut i8;
                    let mut os: *mut i8 = 0 as *mut i8;
                    let mut store_0: *mut i8 = 0 as *mut i8;
                    os = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
                        nread.wrapping_add(1 as i32 as u64),
                    ) }) as *mut i8;
                    if os.is_null() {
                        return CURLE_OUT_OF_MEMORY;
                    }
                    while (unsafe { *ptr_0 }) as i32 == ' ' as i32 {
                        ptr_0 = unsafe { ptr_0.offset(1) };
                    }
                    store_0 = os;
                    while (unsafe { *ptr_0 }) as i32 != 0 && (unsafe { *ptr_0 }) as i32 != ' ' as i32 {
                        let mut fresh39 = ptr_0;
                        ptr_0 = unsafe { ptr_0.offset(1) };
                        let mut fresh40 = store_0;
                        store_0 = unsafe { store_0.offset(1) };
                        (unsafe { *fresh40 = *fresh39 });
                    }
                    (unsafe { *store_0 = '\u{0}' as i32 as i8 });
                    if Curl_strcasecompare(os, b"OS/400\0" as *const u8 as *const i8) != 0 {
                        result = unsafe { Curl_pp_sendf(
                            data,
                            Some(&mut (*ftpc).pp),
                            b"%s\0" as *const u8 as *const i8,
                            b"SITE NAMEFMT 1\0" as *const u8 as *const i8,
                        ) };
                        if result as u64 != 0 {
                            (unsafe { Curl_cfree.expect("non-null function pointer")(os as *mut libc::c_void) });
                            return result;
                        }
                        (unsafe { Curl_cfree.expect("non-null function pointer")(
                            (*ftpc).server_os as *mut libc::c_void,
                        ) });
                        let mut fresh41 = unsafe { &mut ((*ftpc).server_os) };
                        *fresh41 = 0 as *mut i8;
                        let mut fresh42 = unsafe { &mut ((*ftpc).server_os) };
                        *fresh42 = os;
                        _state(data, FTP_NAMEFMT);
                        current_block_187 = 10490607306284298299;
                    } else {
                        (unsafe { Curl_cfree.expect("non-null function pointer")(
                            (*ftpc).server_os as *mut libc::c_void,
                        ) });
                        let mut fresh43 = unsafe { &mut ((*ftpc).server_os) };
                        *fresh43 = 0 as *mut i8;
                        let mut fresh44 = unsafe { &mut ((*ftpc).server_os) };
                        *fresh44 = os;
                        current_block_187 = 6938158527927677584;
                    }
                } else {
                    current_block_187 = 6938158527927677584;
                }
                match current_block_187 {
                    10490607306284298299 => {}
                    _ => {
                        _state(data, FTP_STOP);
                    }
                }
            }
            11 => {
                if ftpcode == 250 as i32 {
                    ftp_state_pwd(data, conn);
                } else {
                    _state(data, FTP_STOP);
                }
            }
            12 | 15 | 13 | 14 => {
                if ftpcode >= 400 as i32 && (unsafe { (*ftpc).count2 }) == 0 {
                    (unsafe { Curl_failf(
                        data,
                        b"QUOT command failed with %03d\0" as *const u8 as *const i8,
                        ftpcode,
                    ) });
                    result = CURLE_QUOTE_ERROR;
                } else {
                    result = ftp_state_quote(data, 0 as i32 != 0, unsafe { (*ftpc).state });
                }
            }
            16 => {
                if ftpcode / 100 as i32 != 2 as i32 {
                    if (unsafe { (*data).set.ftp_create_missing_dirs }) != 0
                        && (unsafe { (*ftpc).cwdcount }) != 0
                        && (unsafe { (*ftpc).count2 }) == 0
                    {
                        let mut fresh45 = unsafe { &mut ((*ftpc).count2) };
                        *fresh45 += 1;
                        result = unsafe { Curl_pp_sendf(
                            data,
                            Some(&mut (*ftpc).pp),
                            b"MKD %s\0" as *const u8 as *const i8,
                            *((*ftpc).dirs).offset(((*ftpc).cwdcount - 1 as i32) as isize),
                        ) };
                        if result as u64 == 0 {
                            _state(data, FTP_MKD);
                        }
                    } else {
                        (unsafe { Curl_failf(
                            data,
                            b"Server denied you to change to the given directory\0" as *const u8
                                as *const i8,
                        ) });
                        (unsafe { (*ftpc).cwdfail = 1 as i32 != 0 });
                        result = CURLE_REMOTE_ACCESS_DENIED;
                    }
                } else {
                    (unsafe { (*ftpc).count2 = 0 as i32 });
                    let mut fresh46 = unsafe { &mut ((*ftpc).cwdcount) };
                    *fresh46 += 1;
                    if *fresh46 <= (unsafe { (*ftpc).dirdepth }) {
                        result = unsafe { Curl_pp_sendf(
                            data,
                            Some(&mut (*ftpc).pp),
                            b"CWD %s\0" as *const u8 as *const i8,
                            *((*ftpc).dirs).offset(((*ftpc).cwdcount - 1 as i32) as isize),
                        ) };
                    } else {
                        result = ftp_state_mdtm(data);
                    }
                }
            }
            17 => {
                if ftpcode / 100 as i32 != 2 as i32 && {
                    let mut fresh47 = unsafe { &mut ((*ftpc).count3) };
                    let mut fresh48 = *fresh47;
                    *fresh47 = *fresh47 - 1;
                    fresh48 == 0
                } {
                    (unsafe { Curl_failf(
                        data,
                        b"Failed to MKD dir: %03d\0" as *const u8 as *const i8,
                        ftpcode,
                    ) });
                    result = CURLE_REMOTE_ACCESS_DENIED;
                } else {
                    _state(data, FTP_CWD);
                    result = unsafe { Curl_pp_sendf(
                        data,
                        Some(&mut (*ftpc).pp),
                        b"CWD %s\0" as *const u8 as *const i8,
                        *((*ftpc).dirs).offset(((*ftpc).cwdcount - 1 as i32) as isize),
                    ) };
                }
            }
            18 => {
                result = ftp_state_mdtm_resp(data, ftpcode);
            }
            19 | 20 | 21 | 22 => {
                result = ftp_state_type_resp(data, ftpcode, unsafe { (*ftpc).state });
            }
            23 | 24 | 25 => {
                result = ftp_state_size_resp(data, ftpcode, unsafe { (*ftpc).state });
            }
            26 | 27 => {
                result = ftp_state_rest_resp(data, conn, ftpcode, unsafe { (*ftpc).state });
            }
            29 => {
                if ftpcode != 200 as i32 {
                    (unsafe { Curl_failf(
                        data,
                        b"PRET command not accepted: %03d\0" as *const u8 as *const i8,
                        ftpcode,
                    ) });
                    return CURLE_FTP_PRET_FAILED;
                }
                result = ftp_state_use_pasv(data, conn);
            }
            30 => {
                result = ftp_state_pasv_resp(data, ftpcode);
            }
            28 => {
                result = ftp_state_port_resp(data, ftpcode);
            }
            31 | 32 => {
                result = ftp_state_get_resp(data, ftpcode, unsafe { (*ftpc).state });
            }
            33 => {
                result = ftp_state_stor_resp(data, ftpcode, unsafe { (*ftpc).state });
            }
            34 | _ => {
                _state(data, FTP_STOP);
            }
        }
    }
    return result;
}
extern "C" fn ftp_multi_statemach(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut done: *mut bool,
) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    let mut result: u32 = Curl_pp_statemach(
        data,
        &mut (*(borrow_mut(&mut ftpc)).unwrap()).pp,
        0 as i32 != 0,
        0 as i32 != 0,
    );
    (unsafe { *done = if (*(borrow(&ftpc)).unwrap()).state as u32 == FTP_STOP as i32 as u32 {
        1 as i32
    } else {
        0 as i32
    } != 0 });
    return result;
}
extern "C" fn ftp_block_statemach(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut ftpc: *mut crate::src::lib::http2::ftp_conn = unsafe { &mut (*conn).proto.ftpc };
    let mut pp: *mut crate::src::lib::http2::pingpong = unsafe { &mut (*ftpc).pp };
    let mut result: u32 = CURLE_OK;
    while (unsafe { (*ftpc).state }) as u32 != FTP_STOP as i32 as u32 {
        result = Curl_pp_statemach(data, pp, 1 as i32 != 0, 1 as i32 != 0);
        if result as u64 != 0 {
            break;
        }
    }
    return result;
}
extern "C" fn ftp_connect(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut done: *mut bool,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    let mut pp: Option<&'_ mut crate::src::lib::http2::pingpong> =
        Some(&mut (*(borrow_mut(&mut ftpc)).unwrap()).pp);
    (unsafe { *done = 0 as i32 != 0 });
    Curl_conncontrol(conn, 0 as i32);
    (*(borrow_mut(&mut pp)).unwrap()).response_time = (120 as i32 * 1000 as i32) as timediff_t;
    let mut fresh49 = &mut ((*(borrow_mut(&mut pp)).unwrap()).statemachine);
    *fresh49 = Some(ftp_statemachine);
    let mut fresh50 = &mut ((*(borrow_mut(&mut pp)).unwrap()).endofresp);
    *fresh50 = Some(ftp_endofresp);
    if (unsafe { (*(*conn).handler).flags }) & ((1 as i32) << 0 as i32) as u32 != 0 {
        result = Curl_ssl_connect(data, conn, 0 as i32);
        if result as u64 != 0 {
            return result;
        }
        let mut fresh51 = unsafe { &mut ((*conn).bits) };
        (*fresh51).set_ftp_use_control_ssl(1 as i32 as bit);
    }
    Curl_pp_setup(borrow_mut(&mut pp));
    Curl_pp_init(data, borrow_mut(&mut pp));
    _state(data, FTP_WAIT220);
    result = ftp_multi_statemach(data, done);
    return result;
}
extern "C" fn ftp_done(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut status: u32,
    mut premature: bool,
) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftp: *mut crate::src::lib::http2::FTP = unsafe { (*data).req.p.ftp };
    let mut ftpc: *mut crate::src::lib::http2::ftp_conn = unsafe { &mut (*conn).proto.ftpc };
    let mut pp: Option<&'_ mut crate::src::lib::http2::pingpong> = Some(unsafe { &mut (*ftpc).pp });
    let mut nread: i64 = 0;
    let mut ftpcode: i32 = 0;
    let mut result: u32 = CURLE_OK;
    let mut rawPath: *mut i8 = 0 as *mut i8;
    let mut pathLen: u64 = 0 as i32 as size_t;
    if ftp.is_null() {
        return CURLE_OK;
    }
    let mut current_block_5: u64;
    match status as u32 {
        23 => {
            current_block_5 = 6900697668027202712;
        }
        36 | 13 | 30 | 10 | 12 | 17 | 19 | 18 | 25 | 9 | 63 | 78 | 0 => {
            current_block_5 = 6900697668027202712;
        }
        _ => {
            current_block_5 = 7085979425372231744;
        }
    }
    match current_block_5 {
        6900697668027202712 => {
            if !premature {
                current_block_5 = 6057473163062296781;
            } else {
                current_block_5 = 7085979425372231744;
            }
        }
        _ => {}
    }
    match current_block_5 {
        7085979425372231744 => {
            (unsafe { (*ftpc).ctl_valid = 0 as i32 != 0 });
            (unsafe { (*ftpc).cwdfail = 1 as i32 != 0 });
            Curl_conncontrol(conn, 1 as i32);
            result = status;
        }
        _ => {}
    }
    if (unsafe { ((*data).state).wildcardmatch() }) != 0 {
        if (unsafe { ((*data).set.chunk_end).is_some() }) && !(unsafe { (*ftpc).file }).is_null() {
            Curl_set_in_callback(data, 1 as i32 != 0);
            (unsafe { ((*data).set.chunk_end).expect("non-null function pointer")((*data).wildcard.customptr) });
            Curl_set_in_callback(data, 0 as i32 != 0);
        }
        (unsafe { (*ftpc).known_filesize = -(1 as i32) as curl_off_t });
    }
    if result as u64 == 0 {
        result = Curl_urldecode(
            data,
            unsafe { (*ftp).path },
            0 as i32 as size_t,
            Some(&mut rawPath),
            Some(&mut pathLen),
            REJECT_CTRL,
        );
    }
    if result as u64 != 0 {
        (unsafe { (*ftpc).ctl_valid = 0 as i32 != 0 });
        Curl_conncontrol(conn, 1 as i32);
        (unsafe { Curl_cfree.expect("non-null function pointer")((*ftpc).prevpath as *mut libc::c_void) });
        let mut fresh52 = unsafe { &mut ((*ftpc).prevpath) };
        *fresh52 = 0 as *mut i8;
    } else {
        if (unsafe { (*data).set.ftp_filemethod }) as u32 == FTPFILE_NOCWD as i32 as u32
            && (unsafe { *rawPath.offset(0 as i32 as isize) }) as i32 == '/' as i32
        {
            (unsafe { Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void) });
        } else {
            (unsafe { Curl_cfree.expect("non-null function pointer")((*ftpc).prevpath as *mut libc::c_void) });
            if !(unsafe { (*ftpc).cwdfail }) {
                if (unsafe { (*data).set.ftp_filemethod }) as u32 == FTPFILE_NOCWD as i32 as u32 {
                    pathLen = 0 as i32 as size_t;
                } else {
                    pathLen = (pathLen as u64).wrapping_sub(if !(unsafe { (*ftpc).file }).is_null() {
                        unsafe { strlen((*ftpc).file) }
                    } else {
                        0 as i32 as u64
                    }) as size_t as size_t;
                }
                (unsafe { *rawPath.offset(pathLen as isize) = '\u{0}' as i32 as i8 });
                let mut fresh53 = unsafe { &mut ((*ftpc).prevpath) };
                *fresh53 = rawPath;
            } else {
                (unsafe { Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void) });
                let mut fresh54 = unsafe { &mut ((*ftpc).prevpath) };
                *fresh54 = 0 as *mut i8;
            }
        }
        if !(unsafe { (*ftpc).prevpath }).is_null() {
            (unsafe { Curl_infof(
                data,
                b"Remembering we are in dir \"%s\"\0" as *const u8 as *const i8,
                (*ftpc).prevpath,
            ) });
        }
    }
    freedirs(ftpc);
    if (unsafe { (*conn).sock[1 as i32 as usize] }) != -(1 as i32) {
        if result as u64 == 0
            && (unsafe { (*ftpc).dont_check }) as i32 != 0
            && (unsafe { (*data).req.maxdownload }) > 0 as i32 as i64
        {
            result = unsafe { Curl_pp_sendf(
                data,
                borrow_mut(&mut pp),
                b"%s\0" as *const u8 as *const i8,
                b"ABOR\0" as *const u8 as *const i8,
            ) };
            if result as u64 != 0 {
                (unsafe { Curl_failf(
                    data,
                    b"Failure sending ABOR command: %s\0" as *const u8 as *const i8,
                    curl_easy_strerror(result),
                ) });
                (unsafe { (*ftpc).ctl_valid = 0 as i32 != 0 });
                Curl_conncontrol(conn, 1 as i32);
            }
        }
        if (unsafe { ((*conn).ssl[1 as i32 as usize]).use_0() }) != 0 {
            Curl_ssl_close(data, conn, 1 as i32);
        }
        close_secondarysocket(data, conn);
    }
    if result as u64 == 0
        && (unsafe { (*ftp).transfer }) as u32 == PPTRANSFER_BODY as i32 as u32
        && (unsafe { (*ftpc).ctl_valid }) as i32 != 0
        && (*(borrow(&pp)).unwrap()).pending_resp as i32 != 0
        && !premature
    {
        let mut old_time: i64 = (*(borrow_mut(&mut pp)).unwrap()).response_time;
        (*(borrow_mut(&mut pp)).unwrap()).response_time = (60 as i32 * 1000 as i32) as timediff_t;
        (*(borrow_mut(&mut pp)).unwrap()).response = Curl_now();
        result = Curl_GetFTPResponse(data, Some(&mut nread), &mut ftpcode);
        (*(borrow_mut(&mut pp)).unwrap()).response_time = old_time;
        if nread == 0 && CURLE_OPERATION_TIMEDOUT as i32 as u32 == result as u32 {
            (unsafe { Curl_failf(
                data,
                b"control connection looks dead\0" as *const u8 as *const i8,
            ) });
            (unsafe { (*ftpc).ctl_valid = 0 as i32 != 0 });
            Curl_conncontrol(conn, 1 as i32);
        }
        if result as u64 != 0 {
            (unsafe { Curl_cfree.expect("non-null function pointer")((*ftp).pathalloc as *mut libc::c_void) });
            let mut fresh55 = unsafe { &mut ((*ftp).pathalloc) };
            *fresh55 = 0 as *mut i8;
            return result;
        }
        if (unsafe { (*ftpc).dont_check }) as i32 != 0 && (unsafe { (*data).req.maxdownload }) > 0 as i32 as i64 {
            (unsafe { Curl_infof(
                data,
                b"partial download completed, closing connection\0" as *const u8 as *const i8,
            ) });
            Curl_conncontrol(conn, 1 as i32);
            return result;
        }
        if !(unsafe { (*ftpc).dont_check }) {
            match ftpcode {
                226 | 250 => {}
                552 => {
                    (unsafe { Curl_failf(
                        data,
                        b"Exceeded storage allocation\0" as *const u8 as *const i8,
                    ) });
                    result = CURLE_REMOTE_DISK_FULL;
                }
                _ => {
                    (unsafe { Curl_failf(
                        data,
                        b"server did not report OK, got %d\0" as *const u8 as *const i8,
                        ftpcode,
                    ) });
                    result = CURLE_PARTIAL_FILE;
                }
            }
        }
    }
    if !(result as u32 != 0 || premature as i32 != 0) {
        if (unsafe { ((*data).set).upload() }) != 0 {
            if -(1 as i32) as i64 != (unsafe { (*data).state.infilesize })
                && (unsafe { (*data).state.infilesize }) != (unsafe { (*data).req.writebytecount })
                && (unsafe { ((*data).set).crlf() }) == 0
                && (unsafe { (*ftp).transfer }) as u32 == PPTRANSFER_BODY as i32 as u32
            {
                (unsafe { Curl_failf(
                    data,
                    b"Uploaded unaligned file size (%ld out of %ld bytes)\0" as *const u8
                        as *const i8,
                    (*data).req.bytecount,
                    (*data).state.infilesize,
                ) });
                result = CURLE_PARTIAL_FILE;
            }
        } else if -(1 as i32) as i64 != (unsafe { (*data).req.size })
            && (unsafe { (*data).req.size }) != (unsafe { (*data).req.bytecount })
            && (unsafe { (*data).req.size }) + (unsafe { (*data).state.crlf_conversions }) != (unsafe { (*data).req.bytecount })
            && (unsafe { (*data).req.maxdownload }) != (unsafe { (*data).req.bytecount })
        {
            (unsafe { Curl_failf(
                data,
                b"Received only partial file: %ld bytes\0" as *const u8 as *const i8,
                (*data).req.bytecount,
            ) });
            result = CURLE_PARTIAL_FILE;
        } else if !(unsafe { (*ftpc).dont_check })
            && (unsafe { (*data).req.bytecount }) == 0
            && (unsafe { (*data).req.size }) > 0 as i32 as i64
        {
            (unsafe { Curl_failf(data, b"No data was received!\0" as *const u8 as *const i8) });
            result = CURLE_FTP_COULDNT_RETR_FILE;
        }
    }
    (unsafe { (*ftp).transfer = PPTRANSFER_BODY });
    (unsafe { (*ftpc).dont_check = 0 as i32 != 0 });
    if status as u64 == 0 && result as u64 == 0 && !premature && !(unsafe { (*data).set.postquote }).is_null()
    {
        result = ftp_sendquote(data, conn, unsafe { (*data).set.postquote });
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")((*ftp).pathalloc as *mut libc::c_void) });
    let mut fresh56 = unsafe { &mut ((*ftp).pathalloc) };
    *fresh56 = 0 as *mut i8;
    return result;
}
extern "C" fn ftp_sendquote(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut quote: *mut crate::src::lib::http2::curl_slist,
) -> u32 {
    let mut item: *mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
    let mut ftpc: *mut crate::src::lib::http2::ftp_conn = unsafe { &mut (*conn).proto.ftpc };
    let mut pp: Option<&'_ mut crate::src::lib::http2::pingpong> = Some(unsafe { &mut (*ftpc).pp });
    item = quote;
    while !item.is_null() {
        if !(unsafe { (*item).data }).is_null() {
            let mut nread: i64 = 0;
            let mut cmd: *mut i8 = unsafe { (*item).data };
            let mut acceptfail: bool = 0 as i32 != 0;
            let mut result: u32 = CURLE_OK;
            let mut ftpcode: i32 = 0 as i32;
            if (unsafe { *cmd.offset(0 as i32 as isize) }) as i32 == '*' as i32 {
                cmd = unsafe { cmd.offset(1) };
                acceptfail = 1 as i32 != 0;
            }
            result = unsafe { Curl_pp_sendf(
                data,
                Some(&mut (*ftpc).pp),
                b"%s\0" as *const u8 as *const i8,
                cmd,
            ) };
            if result as u64 == 0 {
                (*(borrow_mut(&mut pp)).unwrap()).response = Curl_now();
                result = Curl_GetFTPResponse(data, Some(&mut nread), &mut ftpcode);
            }
            if result as u64 != 0 {
                return result;
            }
            if !acceptfail && ftpcode >= 400 as i32 {
                (unsafe { Curl_failf(
                    data,
                    b"QUOT string not accepted: %s\0" as *const u8 as *const i8,
                    cmd,
                ) });
                return CURLE_QUOTE_ERROR;
            }
        }
        item = unsafe { (*item).next };
    }
    return CURLE_OK;
}
extern "C" fn ftp_need_type(
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut ascii_wanted: bool,
) -> i32 {
    return ((unsafe { (*conn).proto.ftpc.transfertype }) as i32
        != (if ascii_wanted as i32 != 0 {
            'A' as i32
        } else {
            'I' as i32
        })) as i32;
}
extern "C" fn ftp_nb_type(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut ascii: bool,
    mut newstate: u32,
) -> u32 {
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    let mut result: u32 = CURLE_OK;
    let mut want: i8 = (if ascii as i32 != 0 {
        'A' as i32
    } else {
        'I' as i32
    }) as i8;
    if (*(borrow(&ftpc)).unwrap()).transfertype as i32 == want as i32 {
        _state(data, newstate);
        return ftp_state_type_resp(data, 200 as i32, newstate);
    }
    result = unsafe { Curl_pp_sendf(
        data,
        Some(&mut (*(borrow_mut(&mut ftpc)).unwrap()).pp),
        b"TYPE %c\0" as *const u8 as *const i8,
        want as i32,
    ) };
    if result as u64 == 0 {
        _state(data, newstate);
        (*(borrow_mut(&mut ftpc)).unwrap()).transfertype = want;
    }
    return result;
}
extern "C" fn ftp_pasv_verbose(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut ai: *mut crate::src::lib::http2::Curl_addrinfo,
    mut newhost: *mut i8,
    mut port: i32,
) {
    let mut buf: [i8; 256] = [0; 256];
    Curl_printable_address(
        ai,
        buf.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 256]>() as u64,
    );
    (unsafe { Curl_infof(
        data,
        b"Connecting to %s (%s) port %d\0" as *const u8 as *const i8,
        newhost,
        buf.as_mut_ptr(),
        port,
    ) });
}
extern "C" fn ftp_do_more(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut completep: *mut i32,
) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    let mut result: u32 = CURLE_OK;
    let mut connected: bool = 0 as i32 != 0;
    let mut complete: bool = 0 as i32 != 0;
    let mut ftp: *mut crate::src::lib::http2::FTP = unsafe { (*data).req.p.ftp };
    if !(unsafe { (*conn).bits.tcpconnect[1 as i32 as usize] }) {
        if Curl_connect_ongoing(conn) {
            result = Curl_proxyCONNECT(data, 1 as i32, 0 as *const i8, 0 as i32);
            return result;
        }
        result = Curl_is_connected(data, conn, 1 as i32, Some(&mut connected));
        if connected {
        } else {
            if result as u32 != 0 && (*(borrow(&ftpc)).unwrap()).count1 == 0 as i32 {
                (unsafe { *completep = -(1 as i32) });
                return ftp_epsv_disable(data, conn);
            }
            return result;
        }
    }
    result = Curl_proxy_connect(data, 1 as i32);
    if result as u64 != 0 {
        return result;
    }
    if (unsafe { (*conn).http_proxy.proxytype }) as u32 == CURLPROXY_HTTPS as i32 as u32
        && !(unsafe { (*conn).bits.proxy_ssl_connected[1 as i32 as usize] })
    {
        return result;
    }
    if (unsafe { ((*conn).bits).tunnel_proxy() }) as i32 != 0
        && (unsafe { ((*conn).bits).httpproxy() }) as i32 != 0
        && Curl_connect_ongoing(conn) as i32 != 0
    {
        return result;
    }
    if (*(borrow(&ftpc)).unwrap()).state as u64 != 0 {
        result = ftp_multi_statemach(data, &mut complete);
        (unsafe { *completep = complete as i32 });
        if result as u32 != 0 || !(*(borrow(&ftpc)).unwrap()).wait_data_conn {
            return result;
        }
        (unsafe { *completep = 0 as i32 });
    }
    if (unsafe { (*ftp).transfer }) as u32 <= PPTRANSFER_INFO as i32 as u32 {
        if (*(borrow(&ftpc)).unwrap()).wait_data_conn as i32 == 1 as i32 {
            let mut serv_conned: bool = false;
            result = ReceivedServerConnect(data, Some(&mut serv_conned));
            if result as u64 != 0 {
                return result;
            }
            if serv_conned {
                result = AcceptServerConnect(data);
                (*(borrow_mut(&mut ftpc)).unwrap()).wait_data_conn = 0 as i32 != 0;
                if result as u64 == 0 {
                    result = InitiateTransfer(data);
                }
                if result as u64 != 0 {
                    return result;
                }
                (unsafe { *completep = 1 as i32 });
            }
        } else if (unsafe { ((*data).set).upload() }) != 0 {
            result = ftp_nb_type(
                data,
                conn,
                (unsafe { ((*data).state).prefer_ascii() }) != 0,
                FTP_STOR_TYPE,
            );
            if result as u64 != 0 {
                return result;
            }
            result = ftp_multi_statemach(data, &mut complete);
            if (*(borrow(&ftpc)).unwrap()).wait_data_conn {
                (unsafe { *completep = 0 as i32 });
            } else {
                (unsafe { *completep = complete as i32 });
            }
        } else {
            (unsafe { (*ftp).downloadsize = -(1 as i32) as curl_off_t });
            result = Curl_range(data);
            if result as u32 == CURLE_OK as i32 as u32 && (unsafe { (*data).req.maxdownload }) >= 0 as i32 as i64
            {
                (*(borrow_mut(&mut ftpc)).unwrap()).dont_check = 1 as i32 != 0;
            }
            if !(result as u64 != 0) {
                if (unsafe { ((*data).state).list_only() }) as i32 != 0
                    || ((*(borrow(&ftpc)).unwrap()).file).is_null()
                {
                    if (unsafe { (*ftp).transfer }) as u32 == PPTRANSFER_BODY as i32 as u32 {
                        result = ftp_nb_type(data, conn, 1 as i32 != 0, FTP_LIST_TYPE);
                        if result as u64 != 0 {
                            return result;
                        }
                    }
                } else {
                    result = ftp_nb_type(
                        data,
                        conn,
                        (unsafe { ((*data).state).prefer_ascii() }) != 0,
                        FTP_RETR_TYPE,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                }
            }
            result = ftp_multi_statemach(data, &mut complete);
            (unsafe { *completep = complete as i32 });
        }
        return result;
    }
    Curl_setup_transfer(
        data,
        -(1 as i32),
        -(1 as i32) as curl_off_t,
        0 as i32 != 0,
        -(1 as i32),
    );
    if !(*(borrow(&ftpc)).unwrap()).wait_data_conn {
        (unsafe { *completep = 1 as i32 });
    }
    return result;
}
extern "C" fn ftp_perform<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut connected: Option<&'a1 mut bool>,
    mut dophase_done: *mut bool,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    if (unsafe { ((*data).set).opt_no_body() }) != 0 {
        let mut ftp: *mut crate::src::lib::http2::FTP = unsafe { (*data).req.p.ftp };
        (unsafe { (*ftp).transfer = PPTRANSFER_INFO });
    }
    (unsafe { *dophase_done = 0 as i32 != 0 });
    result = ftp_state_quote(data, 1 as i32 != 0, FTP_QUOTE);
    if result as u64 != 0 {
        return result;
    }
    result = ftp_multi_statemach(data, dophase_done);
    *(borrow_mut(&mut connected)).unwrap() = unsafe { (*conn).bits.tcpconnect[1 as i32 as usize] };
    (unsafe { Curl_infof(
        data,
        b"ftp_perform ends with SECONDARY: %d\0" as *const u8 as *const i8,
        *(borrow(&connected)).unwrap() as i32,
    ) });
    (unsafe { *dophase_done });
    return result;
}
extern "C" fn wc_data_dtor(mut ptr: *mut core::ffi::c_void) {
    let mut ftpwc: *mut crate::src::lib::ftp::ftp_wc = ptr as *mut ftp_wc;
    if !ftpwc.is_null() && !(unsafe { (*ftpwc).parser }).is_null() {
        Curl_ftp_parselist_data_free(Some(unsafe { &mut (*ftpwc).parser }));
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")(ftpwc as *mut libc::c_void) });
}
extern "C" fn init_wc_data(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut last_slash: *mut i8 = 0 as *mut i8;
    let mut ftp: *mut crate::src::lib::http2::FTP = unsafe { (*data).req.p.ftp };
    let mut path: *mut i8 = unsafe { (*ftp).path };
    let mut wildcard: Option<&'_ mut crate::src::lib::http2::WildcardData> =
        Some(unsafe { &mut (*data).wildcard });
    let mut result: u32 = CURLE_OK;
    let mut ftpwc: *mut crate::src::lib::ftp::ftp_wc = 0 as *mut ftp_wc;
    last_slash = unsafe { strrchr((*ftp).path, '/' as i32) };
    if !last_slash.is_null() {
        last_slash = unsafe { last_slash.offset(1) };
        if (unsafe { *last_slash.offset(0 as i32 as isize) }) as i32 == '\u{0}' as i32 {
            (*(borrow_mut(&mut wildcard)).unwrap()).state = CURLWC_CLEAN;
            result = ftp_parse_url_path(data);
            return result;
        }
        let mut fresh57 = &mut ((*(borrow_mut(&mut wildcard)).unwrap()).pattern);
        *fresh57 = unsafe { Curl_cstrdup.expect("non-null function pointer")(last_slash) };
        if ((*(borrow_mut(&mut wildcard)).unwrap()).pattern).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (unsafe { *last_slash.offset(0 as i32 as isize) = '\u{0}' as i32 as i8 });
    } else if (unsafe { *path.offset(0 as i32 as isize) }) != 0 {
        let mut fresh58 = &mut ((*(borrow_mut(&mut wildcard)).unwrap()).pattern);
        *fresh58 = unsafe { Curl_cstrdup.expect("non-null function pointer")(path) };
        if ((*(borrow_mut(&mut wildcard)).unwrap()).pattern).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (unsafe { *path.offset(0 as i32 as isize) = '\u{0}' as i32 as i8 });
    } else {
        (*(borrow_mut(&mut wildcard)).unwrap()).state = CURLWC_CLEAN;
        result = ftp_parse_url_path(data);
        return result;
    }
    ftpwc = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
        1 as i32 as size_t,
        ::std::mem::size_of::<ftp_wc>() as u64,
    ) }) as *mut ftp_wc;
    if ftpwc.is_null() {
        result = CURLE_OUT_OF_MEMORY;
    } else {
        let mut fresh59 = unsafe { &mut ((*ftpwc).parser) };
        *fresh59 = Curl_ftp_parselist_data_alloc();
        if (unsafe { (*ftpwc).parser }).is_null() {
            result = CURLE_OUT_OF_MEMORY;
        } else {
            let mut fresh60 = &mut ((*(borrow_mut(&mut wildcard)).unwrap()).protdata);
            *fresh60 = ftpwc as *mut libc::c_void;
            let mut fresh61 = &mut ((*(borrow_mut(&mut wildcard)).unwrap()).dtor);
            *fresh61 = Some(wc_data_dtor);
            if (unsafe { (*data).set.ftp_filemethod }) as u32 == FTPFILE_NOCWD as i32 as u32 {
                (unsafe { (*data).set.ftp_filemethod = FTPFILE_MULTICWD });
            }
            result = ftp_parse_url_path(data);
            if !(result as u64 != 0) {
                let mut fresh62 = &mut ((*(borrow_mut(&mut wildcard)).unwrap()).path);
                *fresh62 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*ftp).path) };
                if ((*(borrow(&wildcard)).unwrap()).path).is_null() {
                    result = CURLE_OUT_OF_MEMORY;
                } else {
                    let mut fresh63 = unsafe { &mut ((*ftpwc).backup.write_function) };
                    *fresh63 = unsafe { (*data).set.fwrite_func };
                    let mut fresh64 = unsafe { &mut ((*data).set.fwrite_func) };
                    *fresh64 = Some(Curl_ftp_parselist);
                    let mut fresh65 = unsafe { &mut ((*ftpwc).backup.file_descriptor) };
                    *fresh65 = (unsafe { (*data).set.out }) as *mut FILE;
                    let mut fresh66 = unsafe { &mut ((*data).set.out) };
                    *fresh66 = data as *mut libc::c_void;
                    (unsafe { Curl_infof(
                        data,
                        b"Wildcard - Parsing started\0" as *const u8 as *const i8,
                    ) });
                    return CURLE_OK;
                }
            }
        }
    }
    if !ftpwc.is_null() {
        Curl_ftp_parselist_data_free(Some(unsafe { &mut (*ftpwc).parser }));
        (unsafe { Curl_cfree.expect("non-null function pointer")(ftpwc as *mut libc::c_void) });
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut wildcard)).unwrap()).pattern as *mut libc::c_void,
    ) });
    let mut fresh67 = &mut ((*(borrow_mut(&mut wildcard)).unwrap()).pattern);
    *fresh67 = 0 as *mut i8;
    let mut fresh68 = &mut ((*(borrow_mut(&mut wildcard)).unwrap()).dtor);
    *fresh68 = None;
    let mut fresh69 = &mut ((*(borrow_mut(&mut wildcard)).unwrap()).protdata);
    *fresh69 = 0 as *mut libc::c_void;
    return result;
}
extern "C" fn wc_statemach(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let wildcard: *mut crate::src::lib::http2::WildcardData = unsafe { &mut (*data).wildcard };
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut result: u32 = CURLE_OK;
    let mut current_block_53: u64;
    loop {
        match (unsafe { (*wildcard).state }) as u32 {
            1 => {
                result = init_wc_data(data);
                if (unsafe { (*wildcard).state }) as u32 == CURLWC_CLEAN as i32 as u32 {
                    return result;
                }
                (unsafe { (*wildcard).state = (if result as u32 != 0 {
                    CURLWC_ERROR as i32
                } else {
                    CURLWC_MATCHING as i32
                }) as wildcard_states });
                return result;
            }
            2 => {
                let mut ftpwc: *mut crate::src::lib::ftp::ftp_wc =
                    (unsafe { (*wildcard).protdata }) as *mut ftp_wc;
                let mut fresh70 = unsafe { &mut ((*data).set.fwrite_func) };
                *fresh70 = unsafe { (*ftpwc).backup.write_function };
                let mut fresh71 = unsafe { &mut ((*data).set.out) };
                *fresh71 = (unsafe { (*ftpwc).backup.file_descriptor }) as *mut libc::c_void;
                let mut fresh72 = unsafe { &mut ((*ftpwc).backup.write_function) };
                *fresh72 = None;
                let mut fresh73 = unsafe { &mut ((*ftpwc).backup.file_descriptor) };
                *fresh73 = 0 as *mut FILE;
                (unsafe { (*wildcard).state = CURLWC_DOWNLOADING });
                if Curl_ftp_parselist_geterror(unsafe { (*ftpwc).parser }) as u64 != 0 {
                    (unsafe { (*wildcard).state = CURLWC_CLEAN });
                } else if (unsafe { (*wildcard).filelist.size }) == 0 as i32 as u64 {
                    (unsafe { (*wildcard).state = CURLWC_CLEAN });
                    return CURLE_REMOTE_FILE_NOT_FOUND;
                }
            }
            3 => {
                let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> =
                    Some(unsafe { &mut (*conn).proto.ftpc });
                let mut finfo: *mut crate::src::lib::fileinfo::curl_fileinfo =
                    (unsafe { (*(*wildcard).filelist.head).ptr }) as *mut curl_fileinfo;
                let mut ftp: *mut crate::src::lib::http2::FTP = unsafe { (*data).req.p.ftp };
                let mut tmp_path: *mut i8 = unsafe { curl_maprintf(
                    b"%s%s\0" as *const u8 as *const i8,
                    (*wildcard).path,
                    (*finfo).filename,
                ) };
                if tmp_path.is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
                (unsafe { Curl_cfree.expect("non-null function pointer")(
                    (*ftp).pathalloc as *mut libc::c_void,
                ) });
                let mut fresh74 = unsafe { &mut ((*ftp).path) };
                *fresh74 = tmp_path;
                let mut fresh75 = unsafe { &mut ((*ftp).pathalloc) };
                *fresh75 = *fresh74;
                (unsafe { Curl_infof(
                    data,
                    b"Wildcard - START of \"%s\"\0" as *const u8 as *const i8,
                    (*finfo).filename,
                ) });
                if unsafe { ((*data).set.chunk_bgn).is_some() } {
                    let mut userresponse: i64 = 0;
                    Curl_set_in_callback(data, 1 as i32 != 0);
                    userresponse = unsafe { ((*data).set.chunk_bgn).expect("non-null function pointer")(
                        finfo as *const libc::c_void,
                        (*wildcard).customptr,
                        (*wildcard).filelist.size as i32,
                    ) };
                    Curl_set_in_callback(data, 0 as i32 != 0);
                    match userresponse {
                        2 => {
                            current_block_53 = 12241815505008426805;
                            match current_block_53 {
                                15782252138314684429 => return CURLE_CHUNK_FAILED,
                                _ => {
                                    (unsafe { Curl_infof(
                                        data,
                                        b"Wildcard - \"%s\" skipped by user\0" as *const u8
                                            as *const i8,
                                        (*finfo).filename,
                                    ) });
                                    (unsafe { (*wildcard).state = CURLWC_SKIP });
                                    continue;
                                }
                            }
                        }
                        1 => {
                            current_block_53 = 15782252138314684429;
                            match current_block_53 {
                                15782252138314684429 => return CURLE_CHUNK_FAILED,
                                _ => {
                                    (unsafe { Curl_infof(
                                        data,
                                        b"Wildcard - \"%s\" skipped by user\0" as *const u8
                                            as *const i8,
                                        (*finfo).filename,
                                    ) });
                                    (unsafe { (*wildcard).state = CURLWC_SKIP });
                                    continue;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if (unsafe { (*finfo).filetype }) as u32 != CURLFILETYPE_FILE as i32 as u32 {
                    (unsafe { (*wildcard).state = CURLWC_SKIP });
                } else {
                    if (unsafe { (*finfo).flags }) & ((1 as i32) << 6 as i32) as u32 != 0 {
                        (*(borrow_mut(&mut ftpc)).unwrap()).known_filesize = unsafe { (*finfo).size };
                    }
                    result = ftp_parse_url_path(data);
                    if result as u64 != 0 {
                        return result;
                    }
                    Curl_llist_remove(
                        unsafe { &mut (*wildcard).filelist },
                        unsafe { (*wildcard).filelist.head },
                        0 as *mut libc::c_void,
                    );
                    if (unsafe { (*wildcard).filelist.size }) == 0 as i32 as u64 {
                        (unsafe { (*wildcard).state = CURLWC_CLEAN });
                        return CURLE_OK;
                    }
                    return result;
                }
            }
            5 => {
                if unsafe { ((*data).set.chunk_end).is_some() } {
                    Curl_set_in_callback(data, 1 as i32 != 0);
                    (unsafe { ((*data).set.chunk_end).expect("non-null function pointer")(
                        (*data).wildcard.customptr,
                    ) });
                    Curl_set_in_callback(data, 0 as i32 != 0);
                }
                Curl_llist_remove(
                    unsafe { &mut (*wildcard).filelist },
                    unsafe { (*wildcard).filelist.head },
                    0 as *mut libc::c_void,
                );
                (unsafe { (*wildcard).state = (if (*wildcard).filelist.size == 0 as i32 as u64 {
                    CURLWC_CLEAN as i32
                } else {
                    CURLWC_DOWNLOADING as i32
                }) as wildcard_states });
            }
            4 => {
                let mut ftpwc_0: *mut crate::src::lib::ftp::ftp_wc =
                    (unsafe { (*wildcard).protdata }) as *mut ftp_wc;
                result = CURLE_OK;
                if !ftpwc_0.is_null() {
                    result = Curl_ftp_parselist_geterror(unsafe { (*ftpwc_0).parser });
                }
                (unsafe { (*wildcard).state = (if result as u32 != 0 {
                    CURLWC_ERROR as i32
                } else {
                    CURLWC_DONE as i32
                }) as wildcard_states });
                return result;
            }
            7 | 6 | 0 => {
                if unsafe { ((*wildcard).dtor).is_some() } {
                    (unsafe { ((*wildcard).dtor).expect("non-null function pointer")((*wildcard).protdata) });
                }
                return result;
            }
            _ => {}
        }
    }
}
extern "C" fn ftp_do(mut data: *mut crate::src::lib::http2::Curl_easy, mut done: *mut bool) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    (unsafe { *done = 0 as i32 != 0 });
    (*(borrow_mut(&mut ftpc)).unwrap()).wait_data_conn = 0 as i32 != 0;
    if (unsafe { ((*data).state).wildcardmatch() }) != 0 {
        result = wc_statemach(data);
        if (unsafe { (*data).wildcard.state }) as u32 == CURLWC_SKIP as i32 as u32
            || (unsafe { (*data).wildcard.state }) as u32 == CURLWC_DONE as i32 as u32
        {
            return CURLE_OK;
        }
        if result as u64 != 0 {
            return result;
        }
    } else {
        result = ftp_parse_url_path(data);
        if result as u64 != 0 {
            return result;
        }
    }
    result = ftp_regular_transfer(data, done);
    return result;
}
extern "C" fn ftp_quit(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    if unsafe { (*conn).proto.ftpc.ctl_valid } {
        result = unsafe { Curl_pp_sendf(
            data,
            Some(&mut (*conn).proto.ftpc.pp),
            b"%s\0" as *const u8 as *const i8,
            b"QUIT\0" as *const u8 as *const i8,
        ) };
        if result as u64 != 0 {
            (unsafe { Curl_failf(
                data,
                b"Failure sending QUIT command: %s\0" as *const u8 as *const i8,
                curl_easy_strerror(result),
            ) });
            (unsafe { (*conn).proto.ftpc.ctl_valid = 0 as i32 != 0 });
            Curl_conncontrol(conn, 1 as i32);
            _state(data, FTP_STOP);
            return result;
        }
        _state(data, FTP_QUIT);
        result = ftp_block_statemach(data, conn);
    }
    return result;
}
extern "C" fn ftp_disconnect(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut dead_connection: bool,
) -> u32 {
    let mut ftpc: *mut crate::src::lib::http2::ftp_conn = unsafe { &mut (*conn).proto.ftpc };
    let mut pp: Option<&'_ mut crate::src::lib::http2::pingpong> = Some(unsafe { &mut (*ftpc).pp });
    if dead_connection {
        (unsafe { (*ftpc).ctl_valid = 0 as i32 != 0 });
    }
    ftp_quit(data, conn);
    if !(unsafe { (*ftpc).entrypath }).is_null() {
        if (unsafe { (*data).state.most_recent_ftp_entrypath }) == (unsafe { (*ftpc).entrypath }) {
            let mut fresh76 = unsafe { &mut ((*data).state.most_recent_ftp_entrypath) };
            *fresh76 = 0 as *mut i8;
        }
        (unsafe { Curl_cfree.expect("non-null function pointer")((*ftpc).entrypath as *mut libc::c_void) });
        let mut fresh77 = unsafe { &mut ((*ftpc).entrypath) };
        *fresh77 = 0 as *mut i8;
    }
    freedirs(ftpc);
    (unsafe { Curl_cfree.expect("non-null function pointer")((*ftpc).prevpath as *mut libc::c_void) });
    let mut fresh78 = unsafe { &mut ((*ftpc).prevpath) };
    *fresh78 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*ftpc).server_os as *mut libc::c_void) });
    let mut fresh79 = unsafe { &mut ((*ftpc).server_os) };
    *fresh79 = 0 as *mut i8;
    Curl_pp_disconnect(borrow_mut(&mut pp));
    return CURLE_OK;
}
extern "C" fn ftp_parse_url_path(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut ftp: *mut crate::src::lib::http2::FTP = unsafe { (*data).req.p.ftp };
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    let mut slashPos: *const i8 = 0 as *const i8;
    let mut fileName: *const i8 = 0 as *const i8;
    let mut result: u32 = CURLE_OK;
    let mut rawPath: *mut i8 = 0 as *mut i8;
    let mut pathLen: u64 = 0 as i32 as size_t;
    (*(borrow_mut(&mut ftpc)).unwrap()).ctl_valid = 0 as i32 != 0;
    (*(borrow_mut(&mut ftpc)).unwrap()).cwdfail = 0 as i32 != 0;
    result = Curl_urldecode(
        data,
        unsafe { (*ftp).path },
        0 as i32 as size_t,
        Some(&mut rawPath),
        Some(&mut pathLen),
        REJECT_CTRL,
    );
    if result as u64 != 0 {
        return result;
    }
    match (unsafe { (*data).set.ftp_filemethod }) as u32 {
        2 => {
            if pathLen > 0 as i32 as u64
                && (unsafe { *rawPath.offset(pathLen.wrapping_sub(1 as i32 as u64) as isize) }) as i32
                    != '/' as i32
            {
                fileName = rawPath;
            }
        }
        3 => {
            slashPos = unsafe { strrchr(rawPath, '/' as i32) };
            if !slashPos.is_null() {
                let mut dirlen: u64 = (unsafe { slashPos.offset_from(rawPath) }) as i64 as size_t;
                if dirlen == 0 as i32 as u64 {
                    dirlen = dirlen.wrapping_add(1);
                }
                let mut fresh80 = &mut ((*(borrow_mut(&mut ftpc)).unwrap()).dirs);
                *fresh80 = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
                    1 as i32 as size_t,
                    ::std::mem::size_of::<*mut i8>() as u64,
                ) }) as *mut *mut i8;
                if ((*(borrow_mut(&mut ftpc)).unwrap()).dirs).is_null() {
                    (unsafe { Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void) });
                    return CURLE_OUT_OF_MEMORY;
                }
                let mut fresh81 =
                    unsafe { &mut (*((*(borrow(&ftpc)).unwrap()).dirs).offset(0 as i32 as isize)) };
                *fresh81 = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
                    1 as i32 as size_t,
                    dirlen.wrapping_add(1 as i32 as u64),
                ) }) as *mut i8;
                if (unsafe { *((*(borrow(&ftpc)).unwrap()).dirs).offset(0 as i32 as isize) }).is_null() {
                    (unsafe { Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void) });
                    return CURLE_OUT_OF_MEMORY;
                }
                (unsafe { strncpy(
                    *((*(borrow(&ftpc)).unwrap()).dirs).offset(0 as i32 as isize),
                    rawPath,
                    dirlen,
                ) });
                (*(borrow_mut(&mut ftpc)).unwrap()).dirdepth = 1 as i32;
                fileName = unsafe { slashPos.offset(1 as i32 as isize) };
            } else {
                fileName = rawPath;
            }
        }
        1 | _ => {
            let mut curPos: *const i8 = rawPath;
            let mut dirAlloc: i32 = 0 as i32;
            let mut str: *const i8 = rawPath;
            while (unsafe { *str }) as i32 != 0 as i32 {
                if (unsafe { *str }) as i32 == '/' as i32 {
                    dirAlloc += 1;
                }
                str = unsafe { str.offset(1) };
            }
            if dirAlloc > 0 as i32 {
                let mut fresh82 = &mut ((*(borrow_mut(&mut ftpc)).unwrap()).dirs);
                *fresh82 = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
                    dirAlloc as size_t,
                    ::std::mem::size_of::<*mut i8>() as u64,
                ) }) as *mut *mut i8;
                if ((*(borrow_mut(&mut ftpc)).unwrap()).dirs).is_null() {
                    (unsafe { Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void) });
                    return CURLE_OUT_OF_MEMORY;
                }
                loop {
                    slashPos = unsafe { strchr(curPos, '/' as i32) };
                    if slashPos.is_null() {
                        break;
                    }
                    let mut compLen: u64 = (unsafe { slashPos.offset_from(curPos) }) as i64 as size_t;
                    if compLen == 0 as i32 as u64
                        && (*(borrow(&ftpc)).unwrap()).dirdepth == 0 as i32
                    {
                        compLen = compLen.wrapping_add(1);
                    }
                    if compLen > 0 as i32 as u64 {
                        let mut comp: *mut i8 = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
                            1 as i32 as size_t,
                            compLen.wrapping_add(1 as i32 as u64),
                        ) }) as *mut i8;
                        if comp.is_null() {
                            (unsafe { Curl_cfree.expect("non-null function pointer")(
                                rawPath as *mut libc::c_void,
                            ) });
                            return CURLE_OUT_OF_MEMORY;
                        }
                        (unsafe { strncpy(comp, curPos, compLen) });
                        let mut fresh83 = &mut ((*(borrow_mut(&mut ftpc)).unwrap()).dirdepth);
                        let mut fresh84 = *fresh83;
                        *fresh83 = *fresh83 + 1;
                        let mut fresh85 =
                            unsafe { &mut (*((*(borrow(&ftpc)).unwrap()).dirs).offset(fresh84 as isize)) };
                        *fresh85 = comp;
                    }
                    curPos = unsafe { slashPos.offset(1 as i32 as isize) };
                }
            }
            fileName = curPos;
        }
    }
    if !fileName.is_null() && (unsafe { *fileName }) as i32 != 0 {
        let mut fresh86 = &mut ((*(borrow_mut(&mut ftpc)).unwrap()).file);
        *fresh86 = unsafe { Curl_cstrdup.expect("non-null function pointer")(fileName) };
    } else {
        let mut fresh87 = &mut ((*(borrow_mut(&mut ftpc)).unwrap()).file);
        *fresh87 = 0 as *mut i8;
    }
    if (unsafe { ((*data).set).upload() }) as i32 != 0
        && ((*(borrow(&ftpc)).unwrap()).file).is_null()
        && (unsafe { (*ftp).transfer }) as u32 == PPTRANSFER_BODY as i32 as u32
    {
        (unsafe { Curl_failf(
            data,
            b"Uploading to a URL without a file name!\0" as *const u8 as *const i8,
        ) });
        (unsafe { Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void) });
        return CURLE_URL_MALFORMAT;
    }
    (*(borrow_mut(&mut ftpc)).unwrap()).cwddone = 0 as i32 != 0;
    if (unsafe { (*data).set.ftp_filemethod }) as u32 == FTPFILE_NOCWD as i32 as u32
        && (unsafe { *rawPath.offset(0 as i32 as isize) }) as i32 == '/' as i32
    {
        (*(borrow_mut(&mut ftpc)).unwrap()).cwddone = 1 as i32 != 0;
    } else {
        let mut oldPath: *const i8 = if (unsafe { ((*conn).bits).reuse() }) as i32 != 0 {
            (*(borrow(&ftpc)).unwrap()).prevpath as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        };
        if !oldPath.is_null() {
            let mut n: u64 = pathLen;
            if (unsafe { (*data).set.ftp_filemethod }) as u32 == FTPFILE_NOCWD as i32 as u32 {
                n = 0 as i32 as size_t;
            } else {
                n = (n as u64).wrapping_sub(if !((*(borrow(&ftpc)).unwrap()).file).is_null() {
                    unsafe { strlen((*(borrow(&ftpc)).unwrap()).file) }
                } else {
                    0 as i32 as u64
                }) as size_t as size_t;
            }
            if (unsafe { strlen(oldPath) }) == n && (unsafe { strncmp(rawPath, oldPath, n) }) == 0 {
                (unsafe { Curl_infof(
                    data,
                    b"Request has same path as previous transfer\0" as *const u8 as *const i8,
                ) });
                (*(borrow_mut(&mut ftpc)).unwrap()).cwddone = 1 as i32 != 0;
            }
        }
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void) });
    return CURLE_OK;
}
extern "C" fn ftp_dophase_done(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut connected: bool,
) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftp: *mut crate::src::lib::http2::FTP = unsafe { (*data).req.p.ftp };
    let mut ftpc: Option<&'_ mut crate::src::lib::http2::ftp_conn> = Some(unsafe { &mut (*conn).proto.ftpc });
    if connected {
        let mut completed: i32 = 0;
        let mut result: u32 = ftp_do_more(data, &mut completed);
        if result as u64 != 0 {
            close_secondarysocket(data, conn);
            return result;
        }
    }
    if (unsafe { (*ftp).transfer }) as u32 != PPTRANSFER_BODY as i32 as u32 {
        Curl_setup_transfer(
            data,
            -(1 as i32),
            -(1 as i32) as curl_off_t,
            0 as i32 != 0,
            -(1 as i32),
        );
    } else if !connected {
        let mut fresh88 = unsafe { &mut ((*conn).bits) };
        (*fresh88).set_do_more(1 as i32 as bit);
    }
    (*(borrow_mut(&mut ftpc)).unwrap()).ctl_valid = 1 as i32 != 0;
    return CURLE_OK;
}
extern "C" fn ftp_doing(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut dophase_done: *mut bool,
) -> u32 {
    let mut result: u32 = ftp_multi_statemach(data, dophase_done);
    if !(result as u64 != 0) {
        if unsafe { *dophase_done } {
            result = ftp_dophase_done(data, 0 as i32 != 0);
        }
    }
    return result;
}
extern "C" fn ftp_regular_transfer(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut dophase_done: *mut bool,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut connected: bool = 0 as i32 != 0;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut ftpc: *mut crate::src::lib::http2::ftp_conn = unsafe { &mut (*conn).proto.ftpc };
    (unsafe { (*data).req.size = -(1 as i32) as curl_off_t });
    Curl_pgrsSetUploadCounter(data, 0 as i32 as curl_off_t);
    Curl_pgrsSetDownloadCounter(data, 0 as i32 as curl_off_t);
    Curl_pgrsSetUploadSize(data, -(1 as i32) as curl_off_t);
    Curl_pgrsSetDownloadSize(data, -(1 as i32) as curl_off_t);
    (unsafe { (*ftpc).ctl_valid = 1 as i32 != 0 });
    result = ftp_perform(data, Some(&mut connected), dophase_done);
    if result as u64 == 0 {
        if !(unsafe { *dophase_done }) {
            return CURLE_OK;
        }
        result = ftp_dophase_done(data, connected);
        if result as u64 != 0 {
            return result;
        }
    } else {
        freedirs(ftpc);
    }
    return result;
}
extern "C" fn ftp_setup_connection(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut type_0: *mut i8 = 0 as *mut i8;
    let mut ftp: *mut crate::src::lib::http2::FTP = 0 as *mut crate::src::lib::http2::FTP;
    ftp = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<FTP>() as u64,
        1 as i32 as size_t,
    ) }) as *mut FTP;
    let mut fresh89 = unsafe { &mut ((*data).req.p.ftp) };
    *fresh89 = ftp;
    if ftp.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    let mut fresh90 = unsafe { &mut ((*ftp).path) };
    *fresh90 = (unsafe { &mut *((*data).state.up.path).offset(1 as i32 as isize) }) as *mut i8;
    type_0 = unsafe { strstr((*ftp).path, b";type=\0" as *const u8 as *const i8) };
    if type_0.is_null() {
        type_0 = unsafe { strstr((*conn).host.rawalloc, b";type=\0" as *const u8 as *const i8) };
    }
    if !type_0.is_null() {
        let mut command: i8 = 0;
        (unsafe { *type_0 = 0 as i32 as i8 });
        command = Curl_raw_toupper(unsafe { *type_0.offset(6 as i32 as isize) });
        match command as i32 {
            65 => {
                let mut fresh91 = unsafe { &mut ((*data).state) };
                (*fresh91).set_prefer_ascii(1 as i32 as bit);
            }
            68 => {
                let mut fresh92 = unsafe { &mut ((*data).state) };
                (*fresh92).set_list_only(1 as i32 as bit);
            }
            73 | _ => {
                let mut fresh93 = unsafe { &mut ((*data).state) };
                (*fresh93).set_prefer_ascii(0 as i32 as bit);
            }
        }
    }
    (unsafe { (*ftp).transfer = PPTRANSFER_BODY });
    (unsafe { (*ftp).downloadsize = 0 as i32 as curl_off_t });
    (unsafe { (*conn).proto.ftpc.known_filesize = -(1 as i32) as curl_off_t });
    return CURLE_OK;
}
use crate::laertes_rt::*;
