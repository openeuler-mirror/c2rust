
use :: libc;
extern "C" {
    static mut stdin: *mut crate::src::lib::http2::_IO_FILE;
    static mut stdout: *mut crate::src::lib::http2::_IO_FILE;
    static mut stderr: *mut crate::src::lib::http2::_IO_FILE;
    fn __errno_location() -> *mut i32;
    fn strtol(_: *const i8, _: *mut *mut i8, _: i32) -> i64;
    fn strtoul(_: *const i8, _: *mut *mut i8, _: i32) -> u64;
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn memset(_: *mut core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strncmp(_: *const i8, _: *const i8, _: u64) -> i32;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn __ctype_tolower_loc() -> *mut *const i32;
    fn fread(
        _: *mut core::ffi::c_void,
        _: u64,
        _: u64,
        _: *mut crate::src::lib::http2::_IO_FILE,
    ) -> u64;
    fn fwrite(
        _: *const core::ffi::c_void,
        _: u64,
        _: u64,
        _: *mut crate::src::lib::http2::_IO_FILE,
    ) -> u64;
    fn if_nametoindex(__ifname: *const i8) -> u32;
    static mut Curl_ssl: *const crate::src::lib::getinfo::Curl_ssl;
}
pub use crate::src::lib::altsvc::Curl_alpnid2str;
pub use crate::src::lib::altsvc::Curl_altsvc_cleanup;
pub use crate::src::lib::altsvc::Curl_altsvc_lookup;
pub use crate::src::lib::altsvc::Curl_altsvc_save;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::asyn_thread::Curl_resolver_cancel;
pub use crate::src::lib::asyn_thread::Curl_resolver_cleanup;
pub use crate::src::lib::asyn_thread::Curl_resolver_init;
pub use crate::src::lib::conncache::Curl_conncache_add_conn;
pub use crate::src::lib::conncache::Curl_conncache_extract_bundle;
pub use crate::src::lib::conncache::Curl_conncache_extract_oldest;
pub use crate::src::lib::conncache::Curl_conncache_find_bundle;
pub use crate::src::lib::conncache::Curl_conncache_foreach;
pub use crate::src::lib::conncache::Curl_conncache_remove_conn;
pub use crate::src::lib::conncache::Curl_conncache_size;
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::connect::Curl_closesocket;
pub use crate::src::lib::connect::Curl_conncontrol;
pub use crate::src::lib::connect::Curl_connecthost;
pub use crate::src::lib::connect::Curl_conninfo_local;
pub use crate::src::lib::connect::Curl_persistconninfo;
pub use crate::src::lib::connect::Curl_timeleft;
pub use crate::src::lib::connect::Curl_updateconninfo;
pub use crate::src::lib::cookie::Curl_flush_cookies;
pub use crate::src::lib::curl_addrinfo::Curl_unix2addr;
pub use crate::src::lib::curl_ctype::Curl_isalpha;
pub use crate::src::lib::curl_ctype::Curl_isxdigit;
pub use crate::src::lib::dict::Curl_handler_dict;
pub use crate::src::lib::dynbuf::Curl_dyn_free;
pub use crate::src::lib::dynbuf::Curl_dyn_init;
pub use crate::src::lib::easy::Curl_ccalloc;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_cstrdup;
pub use crate::src::lib::escape::Curl_urldecode;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::file::Curl_handler_file;
pub use crate::src::lib::ftp::Curl_handler_ftp;
pub use crate::src::lib::ftp::Curl_handler_ftps;
pub use crate::src::lib::getenv::curl_getenv;
pub use crate::src::lib::getinfo::Curl_initinfo;
pub use crate::src::lib::gopher::Curl_handler_gopher;
pub use crate::src::lib::gopher::Curl_handler_gophers;
pub use crate::src::lib::hostip::Curl_resolv_timeout;
pub use crate::src::lib::hostip::Curl_resolv_unlock;
pub use crate::src::lib::hsts::Curl_hsts;
pub use crate::src::lib::hsts::Curl_hsts_cleanup;
pub use crate::src::lib::hsts::Curl_hsts_save;
pub use crate::src::lib::http::Curl_handler_http;
pub use crate::src::lib::http::Curl_handler_https;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::http2::Curl_http2_cleanup_dependencies;
pub use crate::src::lib::http2::Curl_http2_init_userset;
pub use crate::src::lib::http_digest::Curl_http_auth_cleanup_digest;
pub use crate::src::lib::http_ntlm::Curl_http_auth_cleanup_ntlm;
pub use crate::src::lib::imap::Curl_handler_imap;
pub use crate::src::lib::imap::Curl_handler_imaps;
pub use crate::src::lib::llist::Curl_llist_destroy;
pub use crate::src::lib::llist::Curl_llist_init;
pub use crate::src::lib::mime::Curl_mime_cleanpart;
pub use crate::src::lib::mime::Curl_mime_initpart;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::mqtt::Curl_handler_mqtt;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::multi::curl_multi_cleanup;
pub use crate::src::lib::multi::curl_multi_remove_handle;
pub use crate::src::lib::multi::Curl_attach_connnection;
pub use crate::src::lib::multi::Curl_detach_connnection;
pub use crate::src::lib::multi::Curl_expire_clear;
pub use crate::src::lib::multi::Curl_multi_max_concurrent_streams;
pub use crate::src::lib::multi::Curl_multi_max_host_connections;
pub use crate::src::lib::multi::Curl_multi_max_total_connections;
pub use crate::src::lib::multi::Curl_multiplex_wanted;
pub use crate::src::lib::multi::Curl_preconnect;
pub use crate::src::lib::netrc::Curl_parsenetrc;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::openldap::Curl_handler_ldap;
pub use crate::src::lib::openldap::Curl_handler_ldaps;
pub use crate::src::lib::pop3::Curl_handler_pop3;
pub use crate::src::lib::pop3::Curl_handler_pop3s;
pub use crate::src::lib::progress::Curl_pgrsSetDownloadCounter;
pub use crate::src::lib::progress::Curl_pgrsSetUploadCounter;
pub use crate::src::lib::progress::Curl_pgrsTime;
pub use crate::src::lib::rtsp::Curl_handler_rtsp;
pub use crate::src::lib::select::Curl_socket_check;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::sendf::Curl_recv_plain;
pub use crate::src::lib::sendf::Curl_send_plain;
pub use crate::src::lib::setopt::Curl_setstropt;
pub use crate::src::lib::share::Curl_share_lock;
pub use crate::src::lib::share::Curl_share_unlock;
pub use crate::src::lib::slist::curl_slist_free_all;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::smb::Curl_handler_smb;
pub use crate::src::lib::smb::Curl_handler_smbs;
pub use crate::src::lib::smtp::Curl_handler_smtp;
pub use crate::src::lib::smtp::Curl_handler_smtps;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::speedcheck::Curl_speedinit;
pub use crate::src::lib::strcase::Curl_safe_strcasecompare;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::strcase::Curl_strncasecompare;
pub use crate::src::lib::strcase::Curl_strntoupper;
pub use crate::src::lib::strerror::Curl_strerror;
pub use crate::src::lib::telnet::Curl_handler_telnet;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::tftp::Curl_handler_tftp;
pub use crate::src::lib::timeval::Curl_now;
pub use crate::src::lib::timeval::Curl_timediff;
pub use crate::src::lib::transfer::Curl_setup_transfer;
pub use crate::src::lib::urlapi::curl_url;
pub use crate::src::lib::urlapi::curl_url_cleanup;
pub use crate::src::lib::urlapi::curl_url_dup;
pub use crate::src::lib::urlapi::curl_url_get;
pub use crate::src::lib::urlapi::curl_url_set;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::urlapi::Curl_is_absolute_url;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
pub use crate::src::lib::vtls::vtls::Curl_clone_primary_ssl_config;
pub use crate::src::lib::vtls::vtls::Curl_free_primary_ssl_config;
pub use crate::src::lib::vtls::vtls::Curl_ssl_backend;
pub use crate::src::lib::vtls::vtls::Curl_ssl_close;
pub use crate::src::lib::vtls::vtls::Curl_ssl_close_all;
pub use crate::src::lib::vtls::vtls::Curl_ssl_config_matches;
pub use crate::src::lib::vtls::vtls::Curl_ssl_free_certinfo;
pub use crate::src::lib::warnless::curlx_ultous;
pub use crate::src::lib::wildcard::Curl_wildcard_dtor;
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
pub type sockaddr = crate::src::lib::http2::sockaddr;
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
pub type altsvcinfo = crate::src::lib::altsvc::altsvcinfo;
pub type hsts = crate::src::lib::easy::hsts;
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
pub type contenc_writer = crate::src::lib::content_encoding::contenc_writer;
pub type content_encoding = crate::src::lib::content_encoding::content_encoding;
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
pub type http_connect_state = crate::src::lib::ftp::http_connect_state;
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
pub type curl_malloc_callback<'a1> =
    Option<unsafe extern "C" fn(_: u64) -> Option<&'a1 mut core::ffi::c_void>>;
pub type curl_strdup_callback<'a1, 'a2> =
    Option<unsafe extern "C" fn(_: Option<&'a1 i8>) -> Option<&'a2 mut i8>>;
pub type curl_calloc_callback<'a1> =
    Option<unsafe extern "C" fn(_: u64, _: u64) -> Option<&'a1 mut core::ffi::c_void>>;
pub type C2RustUnnamed_7 = u32;
pub const CURL_HTTP_VERSION_LAST: C2RustUnnamed_7 = 31;
pub const CURL_HTTP_VERSION_3: C2RustUnnamed_7 = 30;
pub const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: C2RustUnnamed_7 = 5;
pub const CURL_HTTP_VERSION_2TLS: C2RustUnnamed_7 = 4;
pub const CURL_HTTP_VERSION_2_0: C2RustUnnamed_7 = 3;
pub const CURL_HTTP_VERSION_1_1: C2RustUnnamed_7 = 2;
pub const CURL_HTTP_VERSION_1_0: C2RustUnnamed_7 = 1;
pub const CURL_HTTP_VERSION_NONE: C2RustUnnamed_7 = 0;
pub type curl_ssl_backend = crate::src::lib::getinfo::curl_ssl_backend;
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
pub type resolve_t = i32;
pub const CURLRESOLV_PENDING: resolve_t = 1;
pub const CURLRESOLV_RESOLVED: resolve_t = 0;
pub const CURLRESOLV_ERROR: resolve_t = -1;
pub const CURLRESOLV_TIMEDOUT: resolve_t = -2;
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
pub type Curl_ssl = crate::src::lib::getinfo::Curl_ssl;
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
pub type urlreject = u32;
pub const REJECT_ZERO: urlreject = 4;
pub const REJECT_CTRL: urlreject = 3;
pub const REJECT_NADA: urlreject = 2;
pub type stsentry = crate::src::lib::hsts::stsentry;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct prunedead {
    pub data: *mut crate::src::lib::http2::Curl_easy,
    pub extracted: *mut crate::src::lib::http2::connectdata,
}
impl prunedead {
    pub const fn new() -> Self {
        prunedead {
            data: (0 as *mut crate::src::lib::http2::Curl_easy),
            extracted: (0 as *mut crate::src::lib::http2::connectdata),
        }
    }
}
impl std::default::Default for prunedead {
    fn default() -> Self {
        prunedead::new()
    }
}
pub const ALPN_h3: alpnid = 32;
pub const ALPN_h2: alpnid = 16;
pub const ALPN_h1: alpnid = 8;
pub type alpnid = u32;
pub const ALPN_none: alpnid = 0;
pub type althost = crate::src::lib::altsvc::althost;
pub type altsvc = crate::src::lib::altsvc::altsvc;
#[inline]
extern "C" fn tolower(mut __c: i32) -> i32 {
    return if __c >= -(128 as i32) && __c < 256 as i32 {
        unsafe { *(*__ctype_tolower_loc()).offset(__c as isize) }
    } else {
        __c
    };
}
extern "C" fn get_protocol_family(mut h: *const crate::src::lib::http2::Curl_handler) -> u32 {
    return unsafe { (*h).family };
}
static mut protocols: [*const crate::src::lib::http2::Curl_handler; 23] = unsafe {
    [
        &Curl_handler_https as *const Curl_handler,
        &Curl_handler_http as *const Curl_handler,
        &Curl_handler_ftp as *const Curl_handler,
        &Curl_handler_ftps as *const Curl_handler,
        &Curl_handler_file as *const Curl_handler,
        &Curl_handler_smtp as *const Curl_handler,
        &Curl_handler_smtps as *const Curl_handler,
        &Curl_handler_ldap as *const Curl_handler,
        &Curl_handler_ldaps as *const Curl_handler,
        &Curl_handler_imap as *const Curl_handler,
        &Curl_handler_imaps as *const Curl_handler,
        &Curl_handler_telnet as *const Curl_handler,
        &Curl_handler_tftp as *const Curl_handler,
        &Curl_handler_pop3 as *const Curl_handler,
        &Curl_handler_pop3s as *const Curl_handler,
        &Curl_handler_smb as *const Curl_handler,
        &Curl_handler_smbs as *const Curl_handler,
        &Curl_handler_rtsp as *const Curl_handler,
        &Curl_handler_mqtt as *const Curl_handler,
        &Curl_handler_gopher as *const Curl_handler,
        &Curl_handler_gophers as *const Curl_handler,
        &Curl_handler_dict as *const Curl_handler,
        0 as *const libc::c_void as *mut libc::c_void as *mut Curl_handler as *const Curl_handler,
    ]
};
static mut Curl_handler_dummy: crate::src::lib::http2::Curl_handler = {
    let mut init = Curl_handler {
        scheme: b"<no protocol>\0" as *const u8 as *const i8,
        setup_connection: None,
        do_it: None,
        done: None,
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
        defport: 0 as i32,
        protocol: 0 as i32 as u32,
        family: 0 as i32 as u32,
        flags: 0 as i32 as u32,
    };
    init
};
#[no_mangle]
pub extern "C" fn Curl_freeset(mut data: *mut crate::src::lib::http2::Curl_easy) {
    let mut i: u32 = STRING_CERT;
    let mut j: u32 = BLOB_CERT;
    i = STRING_CERT;
    while (i as u32) < STRING_LAST as i32 as u32 {
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            (*data).set.str_0[i as usize] as *mut libc::c_void,
        ) });
        let mut fresh0 = unsafe { &mut ((*data).set.str_0[i as usize]) };
        *fresh0 = 0 as *mut i8;
        i += 1;
    }
    j = BLOB_CERT;
    while (j as u32) < BLOB_LAST as i32 as u32 {
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            (*data).set.blobs[j as usize] as *mut libc::c_void,
        ) });
        let mut fresh1 = unsafe { &mut ((*data).set.blobs[j as usize]) };
        *fresh1 = 0 as *mut curl_blob;
        j += 1;
    }
    if (unsafe { ((*data).state).referer_alloc() }) != 0 {
        (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.referer as *mut libc::c_void) });
        let mut fresh2 = unsafe { &mut ((*data).state.referer) };
        *fresh2 = 0 as *mut i8;
        let mut fresh3 = unsafe { &mut ((*data).state) };
        (*fresh3).set_referer_alloc(0 as i32 as bit);
    }
    let mut fresh4 = unsafe { &mut ((*data).state.referer) };
    *fresh4 = 0 as *mut i8;
    if (unsafe { ((*data).state).url_alloc() }) != 0 {
        (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.url as *mut libc::c_void) });
        let mut fresh5 = unsafe { &mut ((*data).state.url) };
        *fresh5 = 0 as *mut i8;
        let mut fresh6 = unsafe { &mut ((*data).state) };
        (*fresh6).set_url_alloc(0 as i32 as bit);
    }
    let mut fresh7 = unsafe { &mut ((*data).state.url) };
    *fresh7 = 0 as *mut i8;
    Curl_mime_cleanpart(unsafe { &mut (*data).set.mimepost });
}
extern "C" fn up_free(mut data: *mut crate::src::lib::http2::Curl_easy) {
    let mut up: Option<&'_ mut crate::src::lib::http2::urlpieces> = Some(unsafe { &mut (*data).state.up });
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut up)).unwrap()).scheme as *mut libc::c_void,
    ) });
    let mut fresh8 = &mut ((*(borrow_mut(&mut up)).unwrap()).scheme);
    *fresh8 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut up)).unwrap()).hostname as *mut libc::c_void,
    ) });
    let mut fresh9 = &mut ((*(borrow_mut(&mut up)).unwrap()).hostname);
    *fresh9 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut up)).unwrap()).port as *mut libc::c_void,
    ) });
    let mut fresh10 = &mut ((*(borrow_mut(&mut up)).unwrap()).port);
    *fresh10 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut up)).unwrap()).user as *mut libc::c_void,
    ) });
    let mut fresh11 = &mut ((*(borrow_mut(&mut up)).unwrap()).user);
    *fresh11 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut up)).unwrap()).password as *mut libc::c_void,
    ) });
    let mut fresh12 = &mut ((*(borrow_mut(&mut up)).unwrap()).password);
    *fresh12 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut up)).unwrap()).options as *mut libc::c_void,
    ) });
    let mut fresh13 = &mut ((*(borrow_mut(&mut up)).unwrap()).options);
    *fresh13 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut up)).unwrap()).path as *mut libc::c_void,
    ) });
    let mut fresh14 = &mut ((*(borrow_mut(&mut up)).unwrap()).path);
    *fresh14 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut up)).unwrap()).query as *mut libc::c_void,
    ) });
    let mut fresh15 = &mut ((*(borrow_mut(&mut up)).unwrap()).query);
    *fresh15 = 0 as *mut i8;
    curl_url_cleanup(unsafe { (*data).state.uh });
    let mut fresh16 = unsafe { &mut ((*data).state.uh) };
    *fresh16 = 0 as *mut CURLU;
}
#[no_mangle]
pub extern "C" fn Curl_close<'a1>(
    mut datap: Option<&'a1 mut *mut crate::src::lib::http2::Curl_easy>,
) -> u32 {
    let mut m: *mut crate::src::lib::http2::Curl_multi = 0 as *mut Curl_multi;
    let mut data: *mut crate::src::lib::http2::Curl_easy = 0 as *mut Curl_easy;
    if borrow(&datap).is_none() || (*(borrow_mut(&mut datap)).unwrap()).is_null() {
        return CURLE_OK;
    }
    data = *(borrow_mut(&mut datap)).unwrap();
    *(borrow_mut(&mut datap)).unwrap() = 0 as *mut Curl_easy;
    Curl_expire_clear(data);
    Curl_detach_connnection(data);
    m = unsafe { (*data).multi };
    if !m.is_null() {
        curl_multi_remove_handle(unsafe { (*data).multi }, data);
    }
    if !(unsafe { (*data).multi_easy }).is_null() {
        curl_multi_cleanup(unsafe { (*data).multi_easy });
        let mut fresh17 = unsafe { &mut ((*data).multi_easy) };
        *fresh17 = 0 as *mut Curl_multi;
    }
    Curl_llist_destroy(unsafe { &mut (*data).state.timeoutlist }, 0 as *mut libc::c_void);
    (unsafe { (*data).magic = 0 as i32 as u32 });
    if (unsafe { ((*data).state).rangestringalloc() }) != 0 {
        (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.range as *mut libc::c_void) });
    }
    Curl_free_request_state(data);
    Curl_ssl_close_all(data);
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.first_host as *mut libc::c_void) });
    let mut fresh18 = unsafe { &mut ((*data).state.first_host) };
    *fresh18 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.scratch as *mut libc::c_void) });
    let mut fresh19 = unsafe { &mut ((*data).state.scratch) };
    *fresh19 = 0 as *mut i8;
    Curl_ssl_free_certinfo(data);
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).req.newurl as *mut libc::c_void) });
    let mut fresh20 = unsafe { &mut ((*data).req.newurl) };
    *fresh20 = 0 as *mut i8;
    if (unsafe { ((*data).state).referer_alloc() }) != 0 {
        (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.referer as *mut libc::c_void) });
        let mut fresh21 = unsafe { &mut ((*data).state.referer) };
        *fresh21 = 0 as *mut i8;
        let mut fresh22 = unsafe { &mut ((*data).state) };
        (*fresh22).set_referer_alloc(0 as i32 as bit);
    }
    let mut fresh23 = unsafe { &mut ((*data).state.referer) };
    *fresh23 = 0 as *mut i8;
    up_free(data);
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.buffer as *mut libc::c_void) });
    let mut fresh24 = unsafe { &mut ((*data).state.buffer) };
    *fresh24 = 0 as *mut i8;
    Curl_dyn_free(unsafe { &mut (*data).state.headerb });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.ulbuf as *mut libc::c_void) });
    let mut fresh25 = unsafe { &mut ((*data).state.ulbuf) };
    *fresh25 = 0 as *mut i8;
    Curl_flush_cookies(data, 1 as i32 != 0);
    Curl_altsvc_save(
        data,
        unsafe { (*data).asi },
        unsafe { (*data).set.str_0[STRING_ALTSVC as i32 as usize] },
    );
    Curl_altsvc_cleanup(Some(unsafe { &mut (*data).asi }));
    Curl_hsts_save(
        data,
        unsafe { (*data).hsts },
        unsafe { (*data).set.str_0[STRING_HSTS as i32 as usize] },
    );
    Curl_hsts_cleanup(Some(unsafe { &mut (*data).hsts }));
    Curl_http_auth_cleanup_digest(data);
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).info.contenttype as *mut libc::c_void) });
    let mut fresh26 = unsafe { &mut ((*data).info.contenttype) };
    *fresh26 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).info.wouldredirect as *mut libc::c_void) });
    let mut fresh27 = unsafe { &mut ((*data).info.wouldredirect) };
    *fresh27 = 0 as *mut i8;
    Curl_resolver_cleanup(unsafe { (*data).state.async_0.resolver });
    Curl_http2_cleanup_dependencies(data);
    if !(unsafe { (*data).share }).is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE);
        let mut fresh28 = unsafe { &mut ((*(*data).share).dirty) };
        (unsafe { ::std::ptr::write_volatile(
            fresh28,
            (::std::ptr::read_volatile::<u32>(fresh28 as *const u32)).wrapping_sub(1),
        ) });
        Curl_share_unlock(data, CURL_LOCK_DATA_SHARE);
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*data).state.aptr.proxyuserpwd as *mut libc::c_void,
    ) });
    let mut fresh29 = unsafe { &mut ((*data).state.aptr.proxyuserpwd) };
    *fresh29 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.aptr.uagent as *mut libc::c_void) });
    let mut fresh30 = unsafe { &mut ((*data).state.aptr.uagent) };
    *fresh30 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.aptr.userpwd as *mut libc::c_void) });
    let mut fresh31 = unsafe { &mut ((*data).state.aptr.userpwd) };
    *fresh31 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*data).state.aptr.accept_encoding as *mut libc::c_void,
    ) });
    let mut fresh32 = unsafe { &mut ((*data).state.aptr.accept_encoding) };
    *fresh32 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.aptr.te as *mut libc::c_void) });
    let mut fresh33 = unsafe { &mut ((*data).state.aptr.te) };
    *fresh33 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*data).state.aptr.rangeline as *mut libc::c_void,
    ) });
    let mut fresh34 = unsafe { &mut ((*data).state.aptr.rangeline) };
    *fresh34 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.aptr.ref_0 as *mut libc::c_void) });
    let mut fresh35 = unsafe { &mut ((*data).state.aptr.ref_0) };
    *fresh35 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.aptr.host as *mut libc::c_void) });
    let mut fresh36 = unsafe { &mut ((*data).state.aptr.host) };
    *fresh36 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*data).state.aptr.cookiehost as *mut libc::c_void,
    ) });
    let mut fresh37 = unsafe { &mut ((*data).state.aptr.cookiehost) };
    *fresh37 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*data).state.aptr.rtsp_transport as *mut libc::c_void,
    ) });
    let mut fresh38 = unsafe { &mut ((*data).state.aptr.rtsp_transport) };
    *fresh38 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.aptr.user as *mut libc::c_void) });
    let mut fresh39 = unsafe { &mut ((*data).state.aptr.user) };
    *fresh39 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.aptr.passwd as *mut libc::c_void) });
    let mut fresh40 = unsafe { &mut ((*data).state.aptr.passwd) };
    *fresh40 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*data).state.aptr.proxyuser as *mut libc::c_void,
    ) });
    let mut fresh41 = unsafe { &mut ((*data).state.aptr.proxyuser) };
    *fresh41 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*data).state.aptr.proxypasswd as *mut libc::c_void,
    ) });
    let mut fresh42 = unsafe { &mut ((*data).state.aptr.proxypasswd) };
    *fresh42 = 0 as *mut i8;
    if !(unsafe { (*data).req.doh }).is_null() {
        Curl_dyn_free(
            unsafe { &mut (*((*(*data).req.doh).probe)
                .as_mut_ptr()
                .offset(0 as i32 as isize))
            .serverdoh },
        );
        Curl_dyn_free(
            unsafe { &mut (*((*(*data).req.doh).probe)
                .as_mut_ptr()
                .offset(1 as i32 as isize))
            .serverdoh },
        );
        curl_slist_free_all(unsafe { (*(*data).req.doh).headers });
        (unsafe { Curl_cfree.expect("non-null function pointer")((*data).req.doh as *mut libc::c_void) });
        let mut fresh43 = unsafe { &mut ((*data).req.doh) };
        *fresh43 = 0 as *mut dohdata;
    }
    Curl_wildcard_dtor(Some(unsafe { &mut (*data).wildcard }));
    Curl_freeset(data);
    (unsafe { Curl_cfree.expect("non-null function pointer")(data as *mut libc::c_void) });
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_init_userdefined(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut set: Option<&'_ mut crate::src::lib::http2::UserDefined> = Some(unsafe { &mut (*data).set });
    let mut result: u32 = CURLE_OK;
    let mut fresh44 = &mut ((*(borrow_mut(&mut set)).unwrap()).out);
    *fresh44 = (unsafe { stdout }) as *mut libc::c_void;
    let mut fresh45 = &mut ((*(borrow_mut(&mut set)).unwrap()).in_set);
    *fresh45 = (unsafe { stdin }) as *mut libc::c_void;
    let mut fresh46 = &mut ((*(borrow_mut(&mut set)).unwrap()).err);
    *fresh46 = unsafe { stderr };
    let mut fresh47 = &mut ((*(borrow_mut(&mut set)).unwrap()).fwrite_func);
    *fresh47 = unsafe { core::intrinsics::transmute::<
        Option<
            unsafe extern "C" fn(
                _: *const core::ffi::c_void,
                _: u64,
                _: u64,
                _: *mut crate::src::lib::http2::_IO_FILE,
            ) -> u64,
        >,
        Option<unsafe extern "C" fn(_: *mut i8, _: u64, _: u64, _: *mut core::ffi::c_void) -> u64>,
    >(Some(fwrite)) };
    let mut fresh48 = &mut ((*(borrow_mut(&mut set)).unwrap()).fread_func_set);
    *fresh48 = unsafe { core::intrinsics::transmute::<
        Option<
            unsafe extern "C" fn(
                _: *mut core::ffi::c_void,
                _: u64,
                _: u64,
                _: *mut crate::src::lib::http2::_IO_FILE,
            ) -> u64,
        >,
        Option<unsafe extern "C" fn(_: *mut i8, _: u64, _: u64, _: *mut core::ffi::c_void) -> u64>,
    >(Some(fread)) };
    (*(borrow_mut(&mut set)).unwrap()).set_is_fread_set(0 as i32 as bit);
    (*(borrow_mut(&mut set)).unwrap()).set_is_fwrite_set(0 as i32 as bit);
    let mut fresh49 = &mut ((*(borrow_mut(&mut set)).unwrap()).seek_func);
    *fresh49 = None;
    let mut fresh50 = &mut ((*(borrow_mut(&mut set)).unwrap()).seek_client);
    *fresh50 = 0 as *mut libc::c_void;
    let mut fresh51 = &mut ((*(borrow_mut(&mut set)).unwrap()).convfromnetwork);
    *fresh51 = None;
    let mut fresh52 = &mut ((*(borrow_mut(&mut set)).unwrap()).convtonetwork);
    *fresh52 = None;
    let mut fresh53 = &mut ((*(borrow_mut(&mut set)).unwrap()).convfromutf8);
    *fresh53 = None;
    (*(borrow_mut(&mut set)).unwrap()).filesize = -(1 as i32) as curl_off_t;
    (*(borrow_mut(&mut set)).unwrap()).postfieldsize = -(1 as i32) as curl_off_t;
    (*(borrow_mut(&mut set)).unwrap()).maxredirs = -(1 as i32) as i64;
    (*(borrow_mut(&mut set)).unwrap()).method = HTTPREQ_GET;
    (*(borrow_mut(&mut set)).unwrap()).rtspreq = RTSPREQ_OPTIONS;
    (*(borrow_mut(&mut set)).unwrap()).set_ftp_use_epsv(1 as i32 as bit);
    (*(borrow_mut(&mut set)).unwrap()).set_ftp_use_eprt(1 as i32 as bit);
    (*(borrow_mut(&mut set)).unwrap()).set_ftp_use_pret(0 as i32 as bit);
    (*(borrow_mut(&mut set)).unwrap()).ftp_filemethod = FTPFILE_MULTICWD;
    (*(borrow_mut(&mut set)).unwrap()).set_ftp_skip_ip(1 as i32 as bit);
    (*(borrow_mut(&mut set)).unwrap()).dns_cache_timeout = 60 as i32 as i64;
    (*(borrow_mut(&mut set)).unwrap())
        .general_ssl
        .max_ssl_sessions = 5 as i32 as size_t;
    (*(borrow_mut(&mut set)).unwrap()).proxyport = 0 as i32 as i64;
    (*(borrow_mut(&mut set)).unwrap()).proxytype = CURLPROXY_HTTP;
    (*(borrow_mut(&mut set)).unwrap()).httpauth = (1 as i32 as u64) << 0 as i32;
    (*(borrow_mut(&mut set)).unwrap()).proxyauth = (1 as i32 as u64) << 0 as i32;
    (*(borrow_mut(&mut set)).unwrap()).socks5auth =
        (1 as i32 as u64) << 0 as i32 | (1 as i32 as u64) << 2 as i32;
    (*(borrow_mut(&mut set)).unwrap()).set_hide_progress(1 as i32 as bit);
    Curl_mime_initpart(&mut (*(borrow_mut(&mut set)).unwrap()).mimepost, data);
    (*(borrow_mut(&mut set)).unwrap()).set_doh_verifyhost(1 as i32 as bit);
    (*(borrow_mut(&mut set)).unwrap()).set_doh_verifypeer(1 as i32 as bit);
    let mut fresh54 = &mut ((*(borrow_mut(&mut set)).unwrap()).ssl.primary);
    (*fresh54).set_verifypeer(1 as i32 as bit);
    let mut fresh55 = &mut ((*(borrow_mut(&mut set)).unwrap()).ssl.primary);
    (*fresh55).set_verifyhost(1 as i32 as bit);
    (*(borrow_mut(&mut set)).unwrap()).ssl.authtype = CURL_TLSAUTH_NONE;
    (*(borrow_mut(&mut set)).unwrap()).ssh_auth_types = !(0 as i32) as i64;
    let mut fresh56 = &mut ((*(borrow_mut(&mut set)).unwrap()).ssl.primary);
    (*fresh56).set_sessionid(1 as i32 as bit);
    (*(borrow_mut(&mut set)).unwrap()).proxy_ssl = (*(borrow_mut(&mut set)).unwrap()).ssl;
    (*(borrow_mut(&mut set)).unwrap()).new_file_perms = 0o644 as i32 as i64;
    (*(borrow_mut(&mut set)).unwrap()).new_directory_perms = 0o755 as i32 as i64;
    (*(borrow_mut(&mut set)).unwrap()).allowed_protocols = !(0 as i32) as i64;
    (*(borrow_mut(&mut set)).unwrap()).redir_protocols = ((1 as i32) << 0 as i32
        | (1 as i32) << 1 as i32
        | (1 as i32) << 2 as i32
        | (1 as i32) << 3 as i32) as i64;
    if Curl_ssl_backend() != CURLSSLBACKEND_SCHANNEL as i32 {
        result = Curl_setstropt(
            Some(
                unsafe { &mut *((*(borrow_mut(&mut set)).unwrap()).str_0)
                    .as_mut_ptr()
                    .offset(STRING_SSL_CAFILE as i32 as isize) },
            ),
            b"/etc/ssl/certs/ca-certificates.crt\0" as *const u8 as *const i8,
        );
        if result as u64 != 0 {
            return result;
        }
        result = Curl_setstropt(
            Some(
                unsafe { &mut *((*(borrow_mut(&mut set)).unwrap()).str_0)
                    .as_mut_ptr()
                    .offset(STRING_SSL_CAFILE_PROXY as i32 as isize) },
            ),
            b"/etc/ssl/certs/ca-certificates.crt\0" as *const u8 as *const i8,
        );
        if result as u64 != 0 {
            return result;
        }
    }
    (*(borrow_mut(&mut set)).unwrap()).set_wildcard_enabled(0 as i32 as bit);
    let mut fresh57 = &mut ((*(borrow_mut(&mut set)).unwrap()).chunk_bgn);
    *fresh57 = None;
    let mut fresh58 = &mut ((*(borrow_mut(&mut set)).unwrap()).chunk_end);
    *fresh58 = None;
    (*(borrow_mut(&mut set)).unwrap()).set_tcp_keepalive(0 as i32 as bit);
    (*(borrow_mut(&mut set)).unwrap()).tcp_keepintvl = 60 as i32 as i64;
    (*(borrow_mut(&mut set)).unwrap()).tcp_keepidle = 60 as i32 as i64;
    (*(borrow_mut(&mut set)).unwrap()).set_tcp_fastopen(0 as i32 as bit);
    (*(borrow_mut(&mut set)).unwrap()).set_tcp_nodelay(1 as i32 as bit);
    (*(borrow_mut(&mut set)).unwrap()).set_ssl_enable_npn(1 as i32 as bit);
    (*(borrow_mut(&mut set)).unwrap()).set_ssl_enable_alpn(1 as i32 as bit);
    (*(borrow_mut(&mut set)).unwrap()).expect_100_timeout = 1000 as i64;
    (*(borrow_mut(&mut set)).unwrap()).set_sep_headers(1 as i32 as bit);
    (*(borrow_mut(&mut set)).unwrap()).buffer_size = 16384 as i32 as i64;
    (*(borrow_mut(&mut set)).unwrap()).upload_buffer_size = 65536 as i32 as u32;
    (*(borrow_mut(&mut set)).unwrap()).happy_eyeballs_timeout = 200 as i64;
    let mut fresh59 = &mut ((*(borrow_mut(&mut set)).unwrap()).fnmatch);
    *fresh59 = None;
    (*(borrow_mut(&mut set)).unwrap()).upkeep_interval_ms = 60000 as i64;
    (*(borrow_mut(&mut set)).unwrap()).maxconnects = 5 as i32 as size_t;
    (*(borrow_mut(&mut set)).unwrap()).maxage_conn = 118 as i32 as i64;
    (*(borrow_mut(&mut set)).unwrap()).set_http09_allowed(0 as i32 as bit);
    (*(borrow_mut(&mut set)).unwrap()).httpwant = CURL_HTTP_VERSION_2TLS as i32 as u8;
    Curl_http2_init_userset(borrow_mut(&mut set));
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_open<'a1>(
    mut curl: Option<&'a1 mut *mut crate::src::lib::http2::Curl_easy>,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut data: *mut crate::src::lib::http2::Curl_easy = 0 as *mut Curl_easy;
    data = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
        1 as i32 as size_t,
        ::std::mem::size_of::<Curl_easy>() as u64,
    ) }) as *mut Curl_easy;
    if data.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    (unsafe { (*data).magic = 0xc0dedbad as u32 });
    result = Curl_resolver_init(data, Some(unsafe { &mut (*data).state.async_0.resolver }));
    if result as u64 != 0 {
        (unsafe { Curl_cfree.expect("non-null function pointer")(data as *mut libc::c_void) });
        return result;
    }
    result = Curl_init_userdefined(data);
    if result as u64 == 0 {
        Curl_dyn_init(
            unsafe { &mut (*data).state.headerb },
            (100 as i32 * 1024 as i32) as size_t,
        );
        Curl_initinfo(data);
        (unsafe { (*data).state.lastconnect_id = -(1 as i32) as i64 });
        (unsafe { (*data).progress.flags |= (1 as i32) << 4 as i32 });
        (unsafe { (*data).state.current_speed = -(1 as i32) as curl_off_t });
    }
    if result as u64 != 0 {
        Curl_resolver_cleanup(unsafe { (*data).state.async_0.resolver });
        Curl_dyn_free(unsafe { &mut (*data).state.headerb });
        Curl_freeset(data);
        (unsafe { Curl_cfree.expect("non-null function pointer")(data as *mut libc::c_void) });
        data = 0 as *mut Curl_easy;
    } else {
        *(borrow_mut(&mut curl)).unwrap() = data;
    }
    return result;
}
extern "C" fn conn_shutdown(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) {
    (unsafe { Curl_infof(
        data,
        b"Closing connection %ld\0" as *const u8 as *const i8,
        (*conn).connection_id,
    ) });
    if !(unsafe { (*conn).connect_state }).is_null() && !(unsafe { (*(*conn).connect_state).prot_save }).is_null() {
        let mut fresh60 = unsafe { &mut ((*data).req.p.http) };
        *fresh60 = 0 as *mut HTTP;
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            (*(*conn).connect_state).prot_save as *mut libc::c_void,
        ) });
        let mut fresh61 = unsafe { &mut ((*(*conn).connect_state).prot_save) };
        *fresh61 = 0 as *mut HTTP;
    }
    Curl_resolver_cancel(data);
    Curl_ssl_close(data, conn, 0 as i32);
    Curl_ssl_close(data, conn, 1 as i32);
    if -(1 as i32) != (unsafe { (*conn).sock[1 as i32 as usize] }) {
        Curl_closesocket(data, conn, unsafe { (*conn).sock[1 as i32 as usize] });
    }
    if -(1 as i32) != (unsafe { (*conn).sock[0 as i32 as usize] }) {
        Curl_closesocket(data, conn, unsafe { (*conn).sock[0 as i32 as usize] });
    }
    if -(1 as i32) != (unsafe { (*conn).tempsock[0 as i32 as usize] }) {
        Curl_closesocket(data, conn, unsafe { (*conn).tempsock[0 as i32 as usize] });
    }
    if -(1 as i32) != (unsafe { (*conn).tempsock[1 as i32 as usize] }) {
        Curl_closesocket(data, conn, unsafe { (*conn).tempsock[1 as i32 as usize] });
    }
}
extern "C" fn conn_free(mut conn: *mut crate::src::lib::http2::connectdata) {
    Curl_free_idnconverted_hostname(Some(unsafe { &mut (*conn).host }));
    Curl_free_idnconverted_hostname(Some(unsafe { &mut (*conn).conn_to_host }));
    Curl_free_idnconverted_hostname(Some(unsafe { &mut (*conn).http_proxy.host }));
    Curl_free_idnconverted_hostname(Some(unsafe { &mut (*conn).socks_proxy.host }));
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).http_proxy.user as *mut libc::c_void) });
    let mut fresh62 = unsafe { &mut ((*conn).http_proxy.user) };
    *fresh62 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).socks_proxy.user as *mut libc::c_void) });
    let mut fresh63 = unsafe { &mut ((*conn).socks_proxy.user) };
    *fresh63 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).http_proxy.passwd as *mut libc::c_void) });
    let mut fresh64 = unsafe { &mut ((*conn).http_proxy.passwd) };
    *fresh64 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).socks_proxy.passwd as *mut libc::c_void) });
    let mut fresh65 = unsafe { &mut ((*conn).socks_proxy.passwd) };
    *fresh65 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*conn).http_proxy.host.rawalloc as *mut libc::c_void,
    ) });
    let mut fresh66 = unsafe { &mut ((*conn).http_proxy.host.rawalloc) };
    *fresh66 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*conn).socks_proxy.host.rawalloc as *mut libc::c_void,
    ) });
    let mut fresh67 = unsafe { &mut ((*conn).socks_proxy.host.rawalloc) };
    *fresh67 = 0 as *mut i8;
    Curl_free_primary_ssl_config(Some(unsafe { &mut (*conn).proxy_ssl_config }));
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).user as *mut libc::c_void) });
    let mut fresh68 = unsafe { &mut ((*conn).user) };
    *fresh68 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).passwd as *mut libc::c_void) });
    let mut fresh69 = unsafe { &mut ((*conn).passwd) };
    *fresh69 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).sasl_authzid as *mut libc::c_void) });
    let mut fresh70 = unsafe { &mut ((*conn).sasl_authzid) };
    *fresh70 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).options as *mut libc::c_void) });
    let mut fresh71 = unsafe { &mut ((*conn).options) };
    *fresh71 = 0 as *mut i8;
    Curl_dyn_free(unsafe { &mut (*conn).trailer });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).host.rawalloc as *mut libc::c_void) });
    let mut fresh72 = unsafe { &mut ((*conn).host.rawalloc) };
    *fresh72 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*conn).conn_to_host.rawalloc as *mut libc::c_void,
    ) });
    let mut fresh73 = unsafe { &mut ((*conn).conn_to_host.rawalloc) };
    *fresh73 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).hostname_resolve as *mut libc::c_void) });
    let mut fresh74 = unsafe { &mut ((*conn).hostname_resolve) };
    *fresh74 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).secondaryhostname as *mut libc::c_void) });
    let mut fresh75 = unsafe { &mut ((*conn).secondaryhostname) };
    *fresh75 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).connect_state as *mut libc::c_void) });
    let mut fresh76 = unsafe { &mut ((*conn).connect_state) };
    *fresh76 = 0 as *mut http_connect_state;
    Curl_llist_destroy(unsafe { &mut (*conn).easyq }, 0 as *mut libc::c_void);
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).localdev as *mut libc::c_void) });
    let mut fresh77 = unsafe { &mut ((*conn).localdev) };
    *fresh77 = 0 as *mut i8;
    Curl_free_primary_ssl_config(Some(unsafe { &mut (*conn).ssl_config }));
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).unix_domain_socket as *mut libc::c_void) });
    let mut fresh78 = unsafe { &mut ((*conn).unix_domain_socket) };
    *fresh78 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).ssl_extra) });
    let mut fresh79 = unsafe { &mut ((*conn).ssl_extra) };
    *fresh79 = 0 as *mut libc::c_void;
    (unsafe { Curl_cfree.expect("non-null function pointer")(conn as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn Curl_disconnect(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut dead_connection: bool,
) -> u32 {
    if (unsafe { (*conn).easyq.size }) != 0 && !dead_connection {
        return CURLE_OK;
    }
    if !(unsafe { (*conn).dns_entry }).is_null() {
        Curl_resolv_unlock(data, unsafe { (*conn).dns_entry });
        let mut fresh80 = unsafe { &mut ((*conn).dns_entry) };
        *fresh80 = 0 as *mut Curl_dns_entry;
    }
    Curl_http_auth_cleanup_ntlm(conn);
    if (unsafe { ((*conn).bits).connect_only() }) != 0 {
        dead_connection = 1 as i32 != 0;
    }
    Curl_attach_connnection(data, conn);
    if unsafe { ((*(*conn).handler).disconnect).is_some() } {
        (unsafe { ((*(*conn).handler).disconnect).expect("non-null function pointer")(
            data,
            conn,
            dead_connection,
        ) });
    }
    conn_shutdown(data, conn);
    Curl_detach_connnection(data);
    conn_free(conn);
    return CURLE_OK;
}
extern "C" fn SocketIsDead(mut sock: i32) -> bool {
    let mut sval: i32 = 0;
    let mut ret_val: bool = 1 as i32 != 0;
    sval = Curl_socket_check(sock, -(1 as i32), -(1 as i32), 0 as i32 as timediff_t);
    if sval == 0 as i32 {
        ret_val = 0 as i32 != 0;
    }
    return ret_val;
}
extern "C" fn IsMultiplexingPossible(
    mut handle: *const crate::src::lib::http2::Curl_easy,
    mut conn: *const crate::src::lib::http2::connectdata,
) -> i32 {
    let mut avail: i32 = 0 as i32;
    if (unsafe { (*(*conn).handler).protocol }) & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32 != 0
        && ((unsafe { ((*conn).bits).protoconnstart() }) == 0 || (unsafe { ((*conn).bits).close() }) == 0)
    {
        if Curl_multiplex_wanted(unsafe { (*handle).multi }) as i32 != 0
            && (unsafe { (*handle).state.httpwant }) as i32 >= CURL_HTTP_VERSION_2_0 as i32
        {
            avail = (avail as i64 | 2 as i64) as i32;
        }
    }
    return avail;
}
extern "C" fn proxy_info_matches<'a1, 'a2>(
    mut data: Option<&'a1 crate::src::lib::http2::proxy_info>,
    mut needle: Option<&'a2 crate::src::lib::http2::proxy_info>,
) -> bool {
    if (*((data).clone()).unwrap()).proxytype as u32
        == (*((needle).clone()).unwrap()).proxytype as u32
        && (*((data).clone()).unwrap()).port == (*((needle).clone()).unwrap()).port
        && Curl_safe_strcasecompare(
            (*((data).clone()).unwrap()).host.name,
            (*((needle).clone()).unwrap()).host.name,
        ) != 0
    {
        return 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
extern "C" fn socks_proxy_info_matches<'a1, 'a2>(
    mut data: Option<&'a1 crate::src::lib::http2::proxy_info>,
    mut needle: Option<&'a2 crate::src::lib::http2::proxy_info>,
) -> bool {
    if !proxy_info_matches((data).clone(), (needle).clone()) {
        return 0 as i32 != 0;
    }
    if ((*(data).unwrap()).user).is_null() as i32 != ((*(needle).unwrap()).user).is_null() as i32 {
        return 0 as i32 != 0;
    }
    if !((*((data).clone()).unwrap()).user).is_null()
        && !((*((needle).clone()).unwrap()).user).is_null()
        && (unsafe { strcmp(
            (*((data).clone()).unwrap()).user,
            (*((needle).clone()).unwrap()).user,
        ) }) != 0 as i32
    {
        return 0 as i32 != 0;
    }
    if ((*(data).unwrap()).passwd).is_null() as i32
        != ((*(needle).unwrap()).passwd).is_null() as i32
    {
        return 0 as i32 != 0;
    }
    if !((*((data).clone()).unwrap()).passwd).is_null()
        && !((*((needle).clone()).unwrap()).passwd).is_null()
        && (unsafe { strcmp(
            (*((data).clone()).unwrap()).passwd,
            (*((needle).clone()).unwrap()).passwd,
        ) }) != 0 as i32
    {
        return 0 as i32 != 0;
    }
    return 1 as i32 != 0;
}
extern "C" fn conn_maxage(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut now: crate::src::lib::http2::curltime,
) -> bool {
    let mut idletime: i64 = Curl_timediff(now, unsafe { (*conn).lastused });
    idletime /= 1000 as i32 as i64;
    if idletime > (unsafe { (*data).set.maxage_conn }) {
        (unsafe { Curl_infof(
            data,
            b"Too old connection (%ld seconds), disconnect it\0" as *const u8 as *const i8,
            idletime,
        ) });
        return 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
extern "C" fn extract_if_dead(
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut data: *mut crate::src::lib::http2::Curl_easy,
) -> bool {
    if (unsafe { (*conn).easyq.size }) == 0 {
        let mut dead: bool = false;
        let mut now: crate::src::lib::http2::curltime = Curl_now();
        if conn_maxage(data, conn, now) {
            dead = 1 as i32 != 0;
        } else if unsafe { ((*(*conn).handler).connection_check).is_some() } {
            let mut state: u32 = 0;
            Curl_attach_connnection(data, conn);
            state = unsafe { ((*(*conn).handler).connection_check).expect("non-null function pointer")(
                data,
                conn,
                ((1 as i32) << 0 as i32) as u32,
            ) };
            dead = state & ((1 as i32) << 0 as i32) as u32 != 0;
            Curl_detach_connnection(data);
        } else {
            dead = SocketIsDead(unsafe { (*conn).sock[0 as i32 as usize] });
        }
        if dead {
            (unsafe { Curl_infof(
                data,
                b"Connection %ld seems to be dead!\0" as *const u8 as *const i8,
                (*conn).connection_id,
            ) });
            Curl_conncache_remove_conn(data, conn, 0 as i32 != 0);
            return 1 as i32 != 0;
        }
    }
    return 0 as i32 != 0;
}
extern "C" fn call_extract_if_dead(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut param: *mut core::ffi::c_void,
) -> i32 {
    let mut p: *mut crate::src::lib::url::prunedead = param as *mut prunedead;
    if extract_if_dead(conn, data) {
        let mut fresh81 = unsafe { &mut ((*p).extracted) };
        *fresh81 = conn;
        return 1 as i32;
    }
    return 0 as i32;
}
extern "C" fn prune_dead_connections(mut data: *mut crate::src::lib::http2::Curl_easy) {
    let mut now: crate::src::lib::http2::curltime = Curl_now();
    let mut elapsed: i64 = 0;
    if !(unsafe { (*data).share }).is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_CONNECT, CURL_LOCK_ACCESS_SINGLE);
    }
    elapsed = Curl_timediff(now, unsafe { (*(*data).state.conn_cache).last_cleanup });
    if !(unsafe { (*data).share }).is_null() {
        Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
    }
    if elapsed >= 1000 as i64 {
        let mut prune: crate::src::lib::url::prunedead = prunedead {
            data: 0 as *mut Curl_easy,
            extracted: 0 as *mut connectdata,
        };
        prune.data = data;
        prune.extracted = 0 as *mut connectdata;
        while Curl_conncache_foreach(
            data,
            unsafe { (*data).state.conn_cache },
            &mut prune as *mut prunedead as *mut libc::c_void,
            Some(call_extract_if_dead),
        ) {
            Curl_conncache_remove_conn(data, prune.extracted, 1 as i32 != 0);
            Curl_disconnect(data, prune.extracted, 1 as i32 != 0);
        }
        if !(unsafe { (*data).share }).is_null() {
            Curl_share_lock(data, CURL_LOCK_DATA_CONNECT, CURL_LOCK_ACCESS_SINGLE);
        }
        (unsafe { (*(*data).state.conn_cache).last_cleanup = now });
        if !(unsafe { (*data).share }).is_null() {
            Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
        }
    }
}
extern "C" fn ConnectionExists<'a1, 'a2, 'a3>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut needle: *mut crate::src::lib::http2::connectdata,
    mut usethis: Option<&'a1 mut *mut crate::src::lib::http2::connectdata>,
    mut force_reuse: Option<&'a2 mut bool>,
    mut waitpipe: Option<&'a3 mut bool>,
) -> bool {
    let mut check: *mut crate::src::lib::http2::connectdata = 0 as *mut connectdata;
    let mut chosen: *mut crate::src::lib::http2::connectdata = 0 as *mut connectdata;
    let mut foundPendingCandidate: bool = 0 as i32 != 0;
    let mut canmultiplex: bool = IsMultiplexingPossible(data, needle) != 0;
    let mut bundle: *mut crate::src::lib::http2::connectbundle = 0 as *mut connectbundle;
    let mut hostbundle: *const i8 = 0 as *const i8;
    let mut wantNTLMhttp: bool = (unsafe { (*data).state.authhost.want })
        & ((1 as i32 as u64) << 3 as i32 | (1 as i32 as u64) << 5 as i32)
        != 0
        && (unsafe { (*(*needle).handler).protocol }) & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32
            != 0;
    let mut wantProxyNTLMhttp: bool = (unsafe { ((*needle).bits).proxy_user_passwd() }) as i32 != 0
        && ((unsafe { (*data).state.authproxy.want })
            & ((1 as i32 as u64) << 3 as i32 | (1 as i32 as u64) << 5 as i32)
            != 0
            && (unsafe { (*(*needle).handler).protocol })
                & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32
                != 0);
    *(borrow_mut(&mut force_reuse)).unwrap() = 0 as i32 != 0;
    *(borrow_mut(&mut waitpipe)).unwrap() = 0 as i32 != 0;
    bundle = Curl_conncache_find_bundle(
        data,
        needle,
        unsafe { (*data).state.conn_cache },
        Some(&mut hostbundle),
    );
    if !bundle.is_null() {
        let mut curr: *mut crate::src::lib::http2::Curl_llist_element =
            0 as *mut Curl_llist_element;
        (unsafe { Curl_infof(
            data,
            b"Found bundle for host %s: %p [%s]\0" as *const u8 as *const i8,
            hostbundle,
            bundle as *mut libc::c_void,
            if (*bundle).multiuse == 2 as i32 {
                b"can multiplex\0" as *const u8 as *const i8
            } else {
                b"serially\0" as *const u8 as *const i8
            },
        ) });
        if canmultiplex {
            if (unsafe { (*bundle).multiuse }) == 0 as i32 {
                if (unsafe { ((*data).set).pipewait() }) != 0 {
                    (unsafe { Curl_infof(
                        data,
                        b"Server doesn't support multiplex yet, wait\0" as *const u8 as *const i8,
                    ) });
                    *(borrow_mut(&mut waitpipe)).unwrap() = 1 as i32 != 0;
                    if !(unsafe { (*data).share }).is_null() {
                        Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
                    }
                    return 0 as i32 != 0;
                }
                (unsafe { Curl_infof(
                    data,
                    b"Server doesn't support multiplex (yet)\0" as *const u8 as *const i8,
                ) });
                canmultiplex = 0 as i32 != 0;
            }
            if (unsafe { (*bundle).multiuse }) == 2 as i32 && !Curl_multiplex_wanted(unsafe { (*data).multi }) {
                (unsafe { Curl_infof(
                    data,
                    b"Could multiplex, but not asked to!\0" as *const u8 as *const i8,
                ) });
                canmultiplex = 0 as i32 != 0;
            }
            if (unsafe { (*bundle).multiuse }) == -(1 as i32) {
                (unsafe { Curl_infof(
                    data,
                    b"Can not multiplex, even if we wanted to!\0" as *const u8 as *const i8,
                ) });
                canmultiplex = 0 as i32 != 0;
            }
        }
        curr = unsafe { (*bundle).conn_list.head };
        while !curr.is_null() {
            let mut match_0: bool = 0 as i32 != 0;
            let mut multiplexed: u64 = 0 as i32 as size_t;
            check = (unsafe { (*curr).ptr }) as *mut connectdata;
            curr = unsafe { (*curr).next };
            if !((unsafe { ((*check).bits).connect_only() }) as i32 != 0 || (unsafe { ((*check).bits).close() }) as i32 != 0)
            {
                if extract_if_dead(check, data) {
                    Curl_disconnect(data, check, 1 as i32 != 0);
                } else if !((unsafe { (*data).set.ipver }) as i32 != 0 as i32
                    && (unsafe { (*data).set.ipver }) as i32 != (unsafe { (*check).ip_version }) as i32)
                {
                    if (unsafe { (*bundle).multiuse }) == 2 as i32 {
                        multiplexed = unsafe { (*check).easyq.size };
                    }
                    if !canmultiplex {
                        if multiplexed != 0 {
                            continue;
                        } else if (unsafe { (*check).primary_ip[0 as i32 as usize] }) == 0 {
                            (unsafe { Curl_infof(
                                data,
                                b"Connection #%ld is still name resolving, can't reuse\0"
                                    as *const u8 as *const i8,
                                (*check).connection_id,
                            ) });
                            continue;
                        } else if (unsafe { (*check).sock[0 as i32 as usize] }) == -(1 as i32) {
                            foundPendingCandidate = 1 as i32 != 0;
                            (unsafe { Curl_infof(
                                data,
                                b"Connection #%ld isn't open enough, can't reuse\0" as *const u8
                                    as *const i8,
                                (*check).connection_id,
                            ) });
                            continue;
                        }
                    }
                    if !(unsafe { (*needle).unix_domain_socket }).is_null() {
                        if (unsafe { (*check).unix_domain_socket }).is_null() {
                            continue;
                        }
                        if (unsafe { strcmp((*needle).unix_domain_socket, (*check).unix_domain_socket) }) != 0 {
                            continue;
                        }
                        if (unsafe { ((*needle).bits).abstract_unix_socket() }) as i32
                            != (unsafe { ((*check).bits).abstract_unix_socket() }) as i32
                        {
                            continue;
                        }
                    } else if !(unsafe { (*check).unix_domain_socket }).is_null() {
                        continue;
                    }
                    if (unsafe { (*(*needle).handler).flags }) & ((1 as i32) << 0 as i32) as u32
                        != (unsafe { (*(*check).handler).flags }) & ((1 as i32) << 0 as i32) as u32
                    {
                        if get_protocol_family(unsafe { (*check).handler }) != (unsafe { (*(*needle).handler).protocol })
                            || (unsafe { ((*check).bits).tls_upgraded() }) == 0
                        {
                            continue;
                        }
                    }
                    if (unsafe { ((*needle).bits).httpproxy() }) as i32 != (unsafe { ((*check).bits).httpproxy() }) as i32
                        || (unsafe { ((*needle).bits).socksproxy() }) as i32
                            != (unsafe { ((*check).bits).socksproxy() }) as i32
                    {
                        continue;
                    }
                    if (unsafe { ((*needle).bits).socksproxy() }) as i32 != 0
                        && !socks_proxy_info_matches(
                            Some(unsafe { &mut (*needle).socks_proxy }),
                            Some(unsafe { &mut (*check).socks_proxy }),
                        )
                    {
                        continue;
                    }
                    if !((unsafe { ((*needle).bits).conn_to_host() }) as i32
                        != (unsafe { ((*check).bits).conn_to_host() }) as i32)
                    {
                        if !((unsafe { ((*needle).bits).conn_to_port() }) as i32
                            != (unsafe { ((*check).bits).conn_to_port() }) as i32)
                        {
                            if (unsafe { ((*needle).bits).httpproxy() }) != 0 {
                                if !proxy_info_matches(
                                    Some(unsafe { &mut (*needle).http_proxy }),
                                    Some(unsafe { &mut (*check).http_proxy }),
                                ) {
                                    continue;
                                }
                                if (unsafe { ((*needle).bits).tunnel_proxy() }) as i32
                                    != (unsafe { ((*check).bits).tunnel_proxy() }) as i32
                                {
                                    continue;
                                }
                                if (unsafe { (*needle).http_proxy.proxytype }) as u32
                                    == CURLPROXY_HTTPS as i32 as u32
                                {
                                    if (unsafe { (*(*needle).handler).flags }) & ((1 as i32) << 0 as i32) as u32
                                        != 0
                                    {
                                        if !Curl_ssl_config_matches(
                                            unsafe { &mut (*needle).proxy_ssl_config },
                                            Some(unsafe { &mut (*check).proxy_ssl_config }),
                                        ) {
                                            continue;
                                        }
                                        if (unsafe { (*check).proxy_ssl[0 as i32 as usize].state }) as u32
                                            != ssl_connection_complete as i32 as u32
                                        {
                                            continue;
                                        }
                                    } else {
                                        if !Curl_ssl_config_matches(
                                            unsafe { &mut (*needle).ssl_config },
                                            Some(unsafe { &mut (*check).ssl_config }),
                                        ) {
                                            continue;
                                        }
                                        if (unsafe { (*check).ssl[0 as i32 as usize].state }) as u32
                                            != ssl_connection_complete as i32 as u32
                                        {
                                            continue;
                                        }
                                    }
                                }
                            }
                            if !(!canmultiplex && (unsafe { (*check).easyq.size }) != 0) {
                                if (unsafe { (*check).easyq.size }) != 0 {
                                    let mut e: *mut crate::src::lib::http2::Curl_llist_element =
                                        unsafe { (*check).easyq.head };
                                    let mut entry: *mut crate::src::lib::http2::Curl_easy =
                                        (unsafe { (*e).ptr }) as *mut Curl_easy;
                                    if (unsafe { (*entry).multi }) != (unsafe { (*data).multi }) {
                                        continue;
                                    }
                                }
                                if !(unsafe { (*needle).localdev }).is_null()
                                    || (unsafe { (*needle).localport }) as i32 != 0
                                {
                                    if (unsafe { (*check).localport }) as i32 != (unsafe { (*needle).localport }) as i32
                                        || (unsafe { (*check).localportrange }) != (unsafe { (*needle).localportrange })
                                        || !(unsafe { (*needle).localdev }).is_null()
                                            && ((unsafe { (*check).localdev }).is_null()
                                                || (unsafe { strcmp((*check).localdev, (*needle).localdev) })
                                                    != 0)
                                    {
                                        continue;
                                    }
                                }
                                if (unsafe { (*(*needle).handler).flags }) & ((1 as i32) << 7 as i32) as u32 == 0
                                {
                                    if (unsafe { strcmp((*needle).user, (*check).user) }) != 0
                                        || (unsafe { strcmp((*needle).passwd, (*check).passwd) }) != 0
                                    {
                                        continue;
                                    }
                                }
                                if (unsafe { (*(*needle).handler).protocol })
                                    & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32
                                    != 0
                                    && (unsafe { (*check).httpversion }) as i32 >= 20 as i32
                                    && ((unsafe { (*data).state.httpwant }) as i32)
                                        < CURL_HTTP_VERSION_2_0 as i32
                                {
                                    continue;
                                }
                                if (unsafe { (*(*needle).handler).flags }) & ((1 as i32) << 0 as i32) as u32 != 0
                                    || (unsafe { ((*needle).bits).httpproxy() }) == 0
                                    || (unsafe { ((*needle).bits).tunnel_proxy() }) as i32 != 0
                                {
                                    if (Curl_strcasecompare(
                                        unsafe { (*(*needle).handler).scheme },
                                        unsafe { (*(*check).handler).scheme },
                                    ) != 0
                                        || get_protocol_family(unsafe { (*check).handler })
                                            == (unsafe { (*(*needle).handler).protocol })
                                            && (unsafe { ((*check).bits).tls_upgraded() }) as i32 != 0)
                                        && ((unsafe { ((*needle).bits).conn_to_host() }) == 0
                                            || Curl_strcasecompare(
                                                unsafe { (*needle).conn_to_host.name },
                                                unsafe { (*check).conn_to_host.name },
                                            ) != 0)
                                        && ((unsafe { ((*needle).bits).conn_to_port() }) == 0
                                            || (unsafe { (*needle).conn_to_port }) == (unsafe { (*check).conn_to_port }))
                                        && Curl_strcasecompare(
                                            unsafe { (*needle).host.name },
                                            unsafe { (*check).host.name },
                                        ) != 0
                                        && (unsafe { (*needle).remote_port }) == (unsafe { (*check).remote_port })
                                    {
                                        if (unsafe { (*(*needle).handler).flags })
                                            & ((1 as i32) << 0 as i32) as u32
                                            != 0
                                        {
                                            if !Curl_ssl_config_matches(
                                                unsafe { &mut (*needle).ssl_config },
                                                Some(unsafe { &mut (*check).ssl_config }),
                                            ) {
                                                continue;
                                            }
                                            if (unsafe { (*check).ssl[0 as i32 as usize].state }) as u32
                                                != ssl_connection_complete as i32 as u32
                                            {
                                                foundPendingCandidate = 1 as i32 != 0;
                                                continue;
                                            }
                                        }
                                        match_0 = 1 as i32 != 0;
                                    }
                                } else {
                                    match_0 = 1 as i32 != 0;
                                }
                                if !match_0 {
                                    continue;
                                }
                                if wantNTLMhttp {
                                    if (unsafe { strcmp((*needle).user, (*check).user) }) != 0
                                        || (unsafe { strcmp((*needle).passwd, (*check).passwd) }) != 0
                                    {
                                        if (unsafe { (*check).http_ntlm_state }) as u32
                                            == NTLMSTATE_NONE as i32 as u32
                                        {
                                            chosen = check;
                                        }
                                        continue;
                                    }
                                } else if (unsafe { (*check).http_ntlm_state }) as u32
                                    != NTLMSTATE_NONE as i32 as u32
                                {
                                    continue;
                                }
                                if wantProxyNTLMhttp {
                                    if (unsafe { (*check).http_proxy.user }).is_null()
                                        || (unsafe { (*check).http_proxy.passwd }).is_null()
                                    {
                                        continue;
                                    }
                                    if (unsafe { strcmp((*needle).http_proxy.user, (*check).http_proxy.user) })
                                        != 0
                                        || (unsafe { strcmp(
                                            (*needle).http_proxy.passwd,
                                            (*check).http_proxy.passwd,
                                        ) }) != 0
                                    {
                                        continue;
                                    }
                                } else if (unsafe { (*check).proxy_ntlm_state }) as u32
                                    != NTLMSTATE_NONE as i32 as u32
                                {
                                    continue;
                                }
                                if wantNTLMhttp as i32 != 0 || wantProxyNTLMhttp as i32 != 0 {
                                    chosen = check;
                                    if !(wantNTLMhttp as i32 != 0
                                        && (unsafe { (*check).http_ntlm_state }) as u32
                                            != NTLMSTATE_NONE as i32 as u32
                                        || wantProxyNTLMhttp as i32 != 0
                                            && (unsafe { (*check).proxy_ntlm_state }) as u32
                                                != NTLMSTATE_NONE as i32 as u32)
                                    {
                                        continue;
                                    }
                                    *(borrow_mut(&mut force_reuse)).unwrap() = 1 as i32 != 0;
                                    break;
                                } else if canmultiplex {
                                    if multiplexed == 0 {
                                        chosen = check;
                                        break;
                                    } else {
                                        if (unsafe { ((*check).bits).multiplex() }) != 0 {
                                            let mut httpc: Option<
                                                &'_ mut crate::src::lib::http2::http_conn,
                                            > = Some(unsafe { &mut (*check).proto.httpc });
                                            if multiplexed
                                                >= (*(borrow(&httpc)).unwrap())
                                                    .settings
                                                    .max_concurrent_streams
                                                    as u64
                                            {
                                                (unsafe { Curl_infof(
                                                    data,
                                                    b"MAX_CONCURRENT_STREAMS reached, skip (%zu)\0"
                                                        as *const u8
                                                        as *const i8,
                                                    multiplexed,
                                                ) });
                                                continue;
                                            } else if multiplexed
                                                >= Curl_multi_max_concurrent_streams(unsafe { (*data).multi })
                                                    as u64
                                            {
                                                (unsafe { Curl_infof (data , b"client side MAX_CONCURRENT_STREAMS reached, skip (%zu)\0" as * const u8 as * const i8 , multiplexed ,) }) ;
                                                continue;
                                            }
                                        }
                                        chosen = check;
                                        (unsafe { Curl_infof(
                                            data,
                                            b"Multiplexed connection found!\0" as *const u8
                                                as *const i8,
                                        ) });
                                        break;
                                    }
                                } else {
                                    chosen = check;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if !chosen.is_null() {
        Curl_attach_connnection(data, chosen);
        if !(unsafe { (*data).share }).is_null() {
            Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
        }
        *(borrow_mut(&mut usethis)).unwrap() = chosen;
        return 1 as i32 != 0;
    }
    if !(unsafe { (*data).share }).is_null() {
        Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
    }
    if foundPendingCandidate as i32 != 0 && (unsafe { ((*data).set).pipewait() }) as i32 != 0 {
        (unsafe { Curl_infof(
            data,
            b"Found pending candidate for reuse and CURLOPT_PIPEWAIT is set\0" as *const u8
                as *const i8,
        ) });
        *(borrow_mut(&mut waitpipe)).unwrap() = 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
#[no_mangle]
pub extern "C" fn Curl_verboseconnect(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) {
    if (unsafe { ((*data).set).verbose() }) != 0 {
        (unsafe { Curl_infof(
            data,
            b"Connected to %s (%s) port %u (#%ld)\0" as *const u8 as *const i8,
            if ((*conn).bits).socksproxy() as i32 != 0 {
                (*conn).socks_proxy.host.dispname
            } else if ((*conn).bits).httpproxy() as i32 != 0 {
                (*conn).http_proxy.host.dispname
            } else if ((*conn).bits).conn_to_host() as i32 != 0 {
                (*conn).conn_to_host.dispname
            } else {
                (*conn).host.dispname
            },
            ((*conn).primary_ip).as_mut_ptr(),
            (*conn).port,
            (*conn).connection_id,
        ) });
    }
}
#[no_mangle]
pub extern "C" fn Curl_is_ASCII_name(mut hostname: *const i8) -> bool {
    let mut ch: *const u8 = hostname as *const u8;
    if hostname.is_null() {
        return 1 as i32 != 0;
    }
    while (unsafe { *ch }) != 0 {
        let mut fresh82 = ch;
        ch = unsafe { ch.offset(1) };
        if (unsafe { *fresh82 }) as i32 & 0x80 as i32 != 0 {
            return 0 as i32 != 0;
        }
    }
    return 1 as i32 != 0;
}
extern "C" fn strip_trailing_dot<'a1>(mut host: Option<&'a1 mut crate::src::lib::http2::hostname>) {
    let mut len: u64 = 0;
    if borrow(&host).is_none() || ((*(borrow_mut(&mut host)).unwrap()).name).is_null() {
        return;
    }
    len = unsafe { strlen((*(borrow(&host)).unwrap()).name) };
    if len != 0
        && (unsafe { *((*(borrow(&host)).unwrap()).name).offset(len.wrapping_sub(1 as i32 as u64) as isize) })
            as i32
            == '.' as i32
    {
        (unsafe { *((*(borrow(&host)).unwrap()).name).offset(len.wrapping_sub(1 as i32 as u64) as isize) =
            0 as i32 as i8 });
    }
}
#[no_mangle]
pub extern "C" fn Curl_idnconvert_hostname(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut host: *mut crate::src::lib::http2::hostname,
) -> u32 {
    let mut fresh83 = unsafe { &mut ((*host).dispname) };
    *fresh83 = unsafe { (*host).name };
    if !Curl_is_ASCII_name(unsafe { (*host).name }) {
        (unsafe { Curl_infof(
            data,
            b"IDN support not present, can't parse Unicode domains\0" as *const u8 as *const i8,
        ) });
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_free_idnconverted_hostname<'a1>(
    mut _host: Option<&'a1 mut crate::src::lib::http2::hostname>,
) {
}
extern "C" fn allocate_conn(
    mut data: *mut crate::src::lib::http2::Curl_easy,
) -> *mut crate::src::lib::http2::connectdata {
    let mut conn: *mut crate::src::lib::http2::connectdata = (unsafe { Curl_ccalloc
        .expect("non-null function pointer")(
        1 as i32 as size_t,
        ::std::mem::size_of::<connectdata>() as u64,
    ) }) as *mut connectdata;
    if conn.is_null() {
        return 0 as *mut connectdata;
    }
    let mut sslsize: u64 = unsafe { (*Curl_ssl).sizeof_ssl_backend_data };
    let mut ssl: *mut i8 =
        (unsafe { Curl_ccalloc.expect("non-null function pointer")(4 as i32 as size_t, sslsize) }) as *mut i8;
    if ssl.is_null() {
        (unsafe { Curl_cfree.expect("non-null function pointer")(conn as *mut libc::c_void) });
        return 0 as *mut connectdata;
    }
    let mut fresh84 = unsafe { &mut ((*conn).ssl_extra) };
    *fresh84 = ssl as *mut libc::c_void;
    let mut fresh85 = unsafe { &mut ((*conn).ssl[0 as i32 as usize].backend) };
    *fresh85 = ssl as *mut libc::c_void as *mut ssl_backend_data;
    let mut fresh86 = unsafe { &mut ((*conn).ssl[1 as i32 as usize].backend) };
    *fresh86 = (unsafe { ssl.offset(sslsize as isize) }) as *mut libc::c_void as *mut ssl_backend_data;
    let mut fresh87 = unsafe { &mut ((*conn).proxy_ssl[0 as i32 as usize].backend) };
    *fresh87 = (unsafe { ssl.offset((2 as i32 as u64).wrapping_mul(sslsize) as isize) }) as *mut libc::c_void
        as *mut ssl_backend_data;
    let mut fresh88 = unsafe { &mut ((*conn).proxy_ssl[1 as i32 as usize].backend) };
    *fresh88 = (unsafe { ssl.offset((3 as i32 as u64).wrapping_mul(sslsize) as isize) }) as *mut libc::c_void
        as *mut ssl_backend_data;
    let mut fresh89 = unsafe { &mut ((*conn).handler) };
    *fresh89 = unsafe { &Curl_handler_dummy };
    (unsafe { (*conn).sock[0 as i32 as usize] = -(1 as i32) });
    (unsafe { (*conn).sock[1 as i32 as usize] = -(1 as i32) });
    (unsafe { (*conn).tempsock[0 as i32 as usize] = -(1 as i32) });
    (unsafe { (*conn).tempsock[1 as i32 as usize] = -(1 as i32) });
    (unsafe { (*conn).connection_id = -(1 as i32) as i64 });
    (unsafe { (*conn).port = -(1 as i32) });
    (unsafe { (*conn).remote_port = -(1 as i32) });
    Curl_conncontrol(conn, 1 as i32);
    (unsafe { (*conn).created = Curl_now() });
    (unsafe { (*conn).keepalive = Curl_now() });
    (unsafe { (*conn).http_proxy.proxytype = (*data).set.proxytype });
    (unsafe { (*conn).socks_proxy.proxytype = CURLPROXY_SOCKS4 });
    let mut fresh90 = unsafe { &mut ((*conn).bits) };
    (*fresh90).set_proxy(
        (if !(unsafe { (*data).set.str_0[STRING_PROXY as i32 as usize] }).is_null()
            && (unsafe { *(*data).set.str_0[STRING_PROXY as i32 as usize] }) as i32 != 0
        {
            1 as i32
        } else {
            0 as i32
        }) as bit,
    );
    let mut fresh91 = unsafe { &mut ((*conn).bits) };
    (*fresh91).set_httpproxy(
        (if (unsafe { ((*conn).bits).proxy() }) as i32 != 0
            && ((unsafe { (*conn).http_proxy.proxytype }) as u32 == CURLPROXY_HTTP as i32 as u32
                || (unsafe { (*conn).http_proxy.proxytype }) as u32 == CURLPROXY_HTTP_1_0 as i32 as u32
                || (unsafe { (*conn).http_proxy.proxytype }) as u32 == CURLPROXY_HTTPS as i32 as u32)
        {
            1 as i32
        } else {
            0 as i32
        }) as bit,
    );
    let mut fresh92 = unsafe { &mut ((*conn).bits) };
    (*fresh92).set_socksproxy(
        (if (unsafe { ((*conn).bits).proxy() }) as i32 != 0 && (unsafe { ((*conn).bits).httpproxy() }) == 0 {
            1 as i32
        } else {
            0 as i32
        }) as bit,
    );
    if !(unsafe { (*data).set.str_0[STRING_PRE_PROXY as i32 as usize] }).is_null()
        && (unsafe { *(*data).set.str_0[STRING_PRE_PROXY as i32 as usize] }) as i32 != 0
    {
        let mut fresh93 = unsafe { &mut ((*conn).bits) };
        (*fresh93).set_proxy(1 as i32 as bit);
        let mut fresh94 = unsafe { &mut ((*conn).bits) };
        (*fresh94).set_socksproxy(1 as i32 as bit);
    }
    let mut fresh95 = unsafe { &mut ((*conn).bits) };
    (*fresh95).set_proxy_user_passwd(
        (if !(unsafe { (*data).state.aptr.proxyuser }).is_null() {
            1 as i32
        } else {
            0 as i32
        }) as bit,
    );
    let mut fresh96 = unsafe { &mut ((*conn).bits) };
    (*fresh96).set_tunnel_proxy(unsafe { ((*data).set).tunnel_thru_httpproxy() });
    let mut fresh97 = unsafe { &mut ((*conn).bits) };
    (*fresh97).set_user_passwd(
        (if !(unsafe { (*data).state.aptr.user }).is_null() {
            1 as i32
        } else {
            0 as i32
        }) as bit,
    );
    let mut fresh98 = unsafe { &mut ((*conn).bits) };
    (*fresh98).set_ftp_use_epsv(unsafe { ((*data).set).ftp_use_epsv() });
    let mut fresh99 = unsafe { &mut ((*conn).bits) };
    (*fresh99).set_ftp_use_eprt(unsafe { ((*data).set).ftp_use_eprt() });
    let mut fresh100 = unsafe { &mut ((*conn).ssl_config) };
    (*fresh100).set_verifystatus(unsafe { ((*data).set.ssl.primary).verifystatus() });
    let mut fresh101 = unsafe { &mut ((*conn).ssl_config) };
    (*fresh101).set_verifypeer(unsafe { ((*data).set.ssl.primary).verifypeer() });
    let mut fresh102 = unsafe { &mut ((*conn).ssl_config) };
    (*fresh102).set_verifyhost(unsafe { ((*data).set.ssl.primary).verifyhost() });
    let mut fresh103 = unsafe { &mut ((*conn).proxy_ssl_config) };
    (*fresh103).set_verifystatus(unsafe { ((*data).set.proxy_ssl.primary).verifystatus() });
    let mut fresh104 = unsafe { &mut ((*conn).proxy_ssl_config) };
    (*fresh104).set_verifypeer(unsafe { ((*data).set.proxy_ssl.primary).verifypeer() });
    let mut fresh105 = unsafe { &mut ((*conn).proxy_ssl_config) };
    (*fresh105).set_verifyhost(unsafe { ((*data).set.proxy_ssl.primary).verifyhost() });
    (unsafe { (*conn).ip_version = (*data).set.ipver });
    let mut fresh106 = unsafe { &mut ((*conn).bits) };
    (*fresh106).set_connect_only(unsafe { ((*data).set).connect_only() });
    (unsafe { (*conn).transport = TRNSPRT_TCP });
    (unsafe { (*conn).ntlm.ntlm_auth_hlpr_socket = -(1 as i32) });
    (unsafe { (*conn).proxyntlm.ntlm_auth_hlpr_socket = -(1 as i32) });
    Curl_llist_init(Some(unsafe { &mut (*conn).easyq }), None);
    if !(unsafe { (*data).set.str_0[STRING_DEVICE as i32 as usize] }).is_null() {
        let mut fresh107 = unsafe { &mut ((*conn).localdev) };
        *fresh107 = unsafe { Curl_cstrdup.expect("non-null function pointer")(
            (*data).set.str_0[STRING_DEVICE as i32 as usize],
        ) };
        if (unsafe { (*conn).localdev }).is_null() {
            Curl_llist_destroy(unsafe { &mut (*conn).easyq }, 0 as *mut libc::c_void);
            (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).localdev as *mut libc::c_void) });
            (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).ssl_extra) });
            (unsafe { Curl_cfree.expect("non-null function pointer")(conn as *mut libc::c_void) });
            return 0 as *mut connectdata;
        }
    }
    (unsafe { (*conn).localportrange = (*data).set.localportrange });
    (unsafe { (*conn).localport = (*data).set.localport });
    let mut fresh108 = unsafe { &mut ((*conn).fclosesocket) };
    *fresh108 = unsafe { (*data).set.fclosesocket };
    let mut fresh109 = unsafe { &mut ((*conn).closesocket_client) };
    *fresh109 = unsafe { (*data).set.closesocket_client };
    (unsafe { (*conn).lastused = Curl_now() });
    return conn;
}
#[no_mangle]
pub extern "C" fn Curl_builtin_scheme(
    mut scheme: *const i8,
) -> *const crate::src::lib::http2::Curl_handler {
    let mut pp: *const *const crate::src::lib::http2::Curl_handler =
        0 as *const *const crate::src::lib::http2::Curl_handler;
    let mut p: *const crate::src::lib::http2::Curl_handler = 0 as *const Curl_handler;
    pp = unsafe { protocols.as_ptr() };
    loop {
        p = unsafe { *pp };
        if p.is_null() {
            break;
        }
        if Curl_strcasecompare(unsafe { (*p).scheme }, scheme) != 0 {
            return p;
        }
        pp = unsafe { pp.offset(1) };
    }
    return 0 as *const Curl_handler;
}
extern "C" fn findprotocol(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut protostr: *const i8,
) -> u32 {
    let mut p: *const crate::src::lib::http2::Curl_handler = Curl_builtin_scheme(protostr);
    if !p.is_null() && (unsafe { (*data).set.allowed_protocols }) & (unsafe { (*p).protocol }) as i64 != 0 {
        if (unsafe { ((*data).state).this_is_a_follow() }) as i32 != 0
            && (unsafe { (*data).set.redir_protocols }) & (unsafe { (*p).protocol }) as i64 == 0
        {
        } else {
            let mut fresh110 = unsafe { &mut ((*conn).given) };
            *fresh110 = p;
            let mut fresh111 = unsafe { &mut ((*conn).handler) };
            *fresh111 = *fresh110;
            return CURLE_OK;
        }
    }
    (unsafe { Curl_failf(
        data,
        b"Protocol \"%s\" not supported or disabled in libcurl\0" as *const u8 as *const i8,
        protostr,
    ) });
    return CURLE_UNSUPPORTED_PROTOCOL;
}
#[no_mangle]
pub extern "C" fn Curl_uc_to_curlcode(mut uc: u32) -> u32 {
    match uc as u32 {
        5 => return CURLE_UNSUPPORTED_PROTOCOL,
        7 => return CURLE_OUT_OF_MEMORY,
        8 => return CURLE_LOGIN_DENIED,
        _ => return CURLE_URL_MALFORMAT,
    };
}
extern "C" fn zonefrom_url(
    mut uh: *mut crate::src::lib::urlapi::Curl_URL,
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) {
    let mut zoneid: *mut i8 = 0 as *mut i8;
    let mut uc: u32 = curl_url_get(uh, CURLUPART_ZONEID, Some(&mut zoneid), 0 as i32 as u32);
    if uc as u64 == 0 && !zoneid.is_null() {
        let mut endp: *mut i8 = 0 as *mut i8;
        let mut scope: u64 = unsafe { strtoul(zoneid, &mut endp, 10 as i32) };
        if (unsafe { *endp }) == 0
            && scope
                < (2147483647 as i32 as u32)
                    .wrapping_mul(2 as u32)
                    .wrapping_add(1 as u32) as u64
        {
            (unsafe { (*conn).scope_id = scope as u32 });
        } else {
            let mut scopeidx: u32 = 0 as i32 as u32;
            scopeidx = unsafe { if_nametoindex(zoneid) };
            if scopeidx == 0 {
                let mut buffer: [i8; 256] = [0; 256];
                (unsafe { Curl_infof(
                    data,
                    b"Invalid zoneid: %s; %s\0" as *const u8 as *const i8,
                    zoneid,
                    Curl_strerror(
                        *__errno_location(),
                        buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 256]>() as u64,
                    ),
                ) });
            } else {
                (unsafe { (*conn).scope_id = scopeidx });
            }
        }
        (unsafe { Curl_cfree.expect("non-null function pointer")(zoneid as *mut libc::c_void) });
    }
}
extern "C" fn parseurlandfillconn(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut uh: *mut crate::src::lib::urlapi::Curl_URL = 0 as *mut CURLU;
    let mut uc: u32 = CURLUE_OK;
    let mut hostname: *mut i8 = 0 as *mut i8;
    let mut use_set_uh: bool =
        !(unsafe { (*data).set.uh }).is_null() && (unsafe { ((*data).state).this_is_a_follow() }) == 0;
    up_free(data);
    if use_set_uh {
        let mut fresh112 = unsafe { &mut ((*data).state.uh) };
        *fresh112 = curl_url_dup(unsafe { (*data).set.uh });
        uh = *fresh112;
    } else {
        let mut fresh113 = unsafe { &mut ((*data).state.uh) };
        *fresh113 = curl_url();
        uh = *fresh113;
    }
    if uh.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if !(unsafe { (*data).set.str_0[STRING_DEFAULT_PROTOCOL as i32 as usize] }).is_null()
        && !Curl_is_absolute_url(unsafe { (*data).state.url }, 0 as *mut i8, 40 as i32 as size_t)
    {
        let mut url: *mut i8 = unsafe { curl_maprintf(
            b"%s://%s\0" as *const u8 as *const i8,
            (*data).set.str_0[STRING_DEFAULT_PROTOCOL as i32 as usize],
            (*data).state.url,
        ) };
        if url.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if (unsafe { ((*data).state).url_alloc() }) != 0 {
            (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.url as *mut libc::c_void) });
        }
        let mut fresh114 = unsafe { &mut ((*data).state.url) };
        *fresh114 = url;
        let mut fresh115 = unsafe { &mut ((*data).state) };
        (*fresh115).set_url_alloc(1 as i32 as bit);
    }
    if !use_set_uh {
        let mut newurl: *mut i8 = 0 as *mut i8;
        uc = curl_url_set(
            uh,
            CURLUPART_URL,
            unsafe { (*data).state.url },
            ((1 as i32) << 9 as i32
                | (1 as i32) << 3 as i32
                | (if (unsafe { ((*data).set).disallow_username_in_url() }) as i32 != 0 {
                    (1 as i32) << 5 as i32
                } else {
                    0 as i32
                })
                | (if (unsafe { ((*data).set).path_as_is() }) as i32 != 0 {
                    (1 as i32) << 4 as i32
                } else {
                    0 as i32
                })) as u32,
        );
        if uc as u64 != 0 {
            return Curl_uc_to_curlcode(uc);
        }
        uc = curl_url_get(uh, CURLUPART_URL, Some(&mut newurl), 0 as i32 as u32);
        if uc as u64 != 0 {
            return Curl_uc_to_curlcode(uc);
        }
        if (unsafe { ((*data).state).url_alloc() }) != 0 {
            (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.url as *mut libc::c_void) });
        }
        let mut fresh116 = unsafe { &mut ((*data).state.url) };
        *fresh116 = newurl;
        let mut fresh117 = unsafe { &mut ((*data).state) };
        (*fresh117).set_url_alloc(1 as i32 as bit);
    }
    uc = curl_url_get(
        uh,
        CURLUPART_SCHEME,
        Some(unsafe { &mut (*data).state.up.scheme }),
        0 as i32 as u32,
    );
    if uc as u64 != 0 {
        return Curl_uc_to_curlcode(uc);
    }
    uc = curl_url_get(
        uh,
        CURLUPART_HOST,
        Some(unsafe { &mut (*data).state.up.hostname }),
        0 as i32 as u32,
    );
    if uc as u64 != 0 {
        if Curl_strcasecompare(b"file\0" as *const u8 as *const i8, unsafe { (*data).state.up.scheme }) == 0 {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if !(unsafe { (*data).hsts }).is_null()
        && Curl_strcasecompare(b"http\0" as *const u8 as *const i8, unsafe { (*data).state.up.scheme }) != 0
    {
        if !(Curl_hsts(unsafe { (*data).hsts }, unsafe { (*data).state.up.hostname }, 1 as i32 != 0)).is_null() {
            let mut url_0: *mut i8 = 0 as *mut i8;
            (unsafe { Curl_cfree.expect("non-null function pointer")(
                (*data).state.up.scheme as *mut libc::c_void,
            ) });
            let mut fresh118 = unsafe { &mut ((*data).state.up.scheme) };
            *fresh118 = 0 as *mut i8;
            uc = curl_url_set(
                uh,
                CURLUPART_SCHEME,
                b"https\0" as *const u8 as *const i8,
                0 as i32 as u32,
            );
            if uc as u64 != 0 {
                return Curl_uc_to_curlcode(uc);
            }
            if (unsafe { ((*data).state).url_alloc() }) != 0 {
                (unsafe { Curl_cfree.expect("non-null function pointer")(
                    (*data).state.url as *mut libc::c_void,
                ) });
                let mut fresh119 = unsafe { &mut ((*data).state.url) };
                *fresh119 = 0 as *mut i8;
            }
            uc = curl_url_get(uh, CURLUPART_URL, Some(&mut url_0), 0 as i32 as u32);
            if uc as u64 != 0 {
                return Curl_uc_to_curlcode(uc);
            }
            uc = curl_url_get(
                uh,
                CURLUPART_SCHEME,
                Some(unsafe { &mut (*data).state.up.scheme }),
                0 as i32 as u32,
            );
            if uc as u64 != 0 {
                (unsafe { Curl_cfree.expect("non-null function pointer")(url_0 as *mut libc::c_void) });
                return Curl_uc_to_curlcode(uc);
            }
            let mut fresh120 = unsafe { &mut ((*data).state.url) };
            *fresh120 = url_0;
            let mut fresh121 = unsafe { &mut ((*data).state) };
            (*fresh121).set_url_alloc(1 as i32 as bit);
            (unsafe { Curl_infof(
                data,
                b"Switched from HTTP to HTTPS due to HSTS => %s\0" as *const u8 as *const i8,
                (*data).state.url,
            ) });
        }
    }
    result = findprotocol(data, conn, unsafe { (*data).state.up.scheme });
    if result as u64 != 0 {
        return result;
    }
    if (unsafe { (*data).state.aptr.user }).is_null() {
        uc = curl_url_get(
            uh,
            CURLUPART_USER,
            Some(unsafe { &mut (*data).state.up.user }),
            0 as i32 as u32,
        );
        if uc as u64 == 0 {
            let mut decoded: *mut i8 = 0 as *mut i8;
            result = Curl_urldecode(
                0 as *mut Curl_easy,
                unsafe { (*data).state.up.user },
                0 as i32 as size_t,
                Some(&mut decoded),
                Option::<&'_ mut u64>::None,
                (if (unsafe { (*(*conn).handler).flags }) & ((1 as i32) << 13 as i32) as u32 != 0 {
                    REJECT_ZERO as i32
                } else {
                    REJECT_CTRL as i32
                }) as urlreject,
            );
            if result as u64 != 0 {
                return result;
            }
            let mut fresh122 = unsafe { &mut ((*conn).user) };
            *fresh122 = decoded;
            let mut fresh123 = unsafe { &mut ((*conn).bits) };
            (*fresh123).set_user_passwd(1 as i32 as bit);
            result = Curl_setstropt(Some(unsafe { &mut (*data).state.aptr.user }), decoded);
            if result as u64 != 0 {
                return result;
            }
        } else if uc as u32 != CURLUE_NO_USER as i32 as u32 {
            return Curl_uc_to_curlcode(uc);
        }
    }
    if (unsafe { (*data).state.aptr.passwd }).is_null() {
        uc = curl_url_get(
            uh,
            CURLUPART_PASSWORD,
            Some(unsafe { &mut (*data).state.up.password }),
            0 as i32 as u32,
        );
        if uc as u64 == 0 {
            let mut decoded_0: *mut i8 = 0 as *mut i8;
            result = Curl_urldecode(
                0 as *mut Curl_easy,
                unsafe { (*data).state.up.password },
                0 as i32 as size_t,
                Some(&mut decoded_0),
                Option::<&'_ mut u64>::None,
                (if (unsafe { (*(*conn).handler).flags }) & ((1 as i32) << 13 as i32) as u32 != 0 {
                    REJECT_ZERO as i32
                } else {
                    REJECT_CTRL as i32
                }) as urlreject,
            );
            if result as u64 != 0 {
                return result;
            }
            let mut fresh124 = unsafe { &mut ((*conn).passwd) };
            *fresh124 = decoded_0;
            let mut fresh125 = unsafe { &mut ((*conn).bits) };
            (*fresh125).set_user_passwd(1 as i32 as bit);
            result = Curl_setstropt(Some(unsafe { &mut (*data).state.aptr.passwd }), decoded_0);
            if result as u64 != 0 {
                return result;
            }
        } else if uc as u32 != CURLUE_NO_PASSWORD as i32 as u32 {
            return Curl_uc_to_curlcode(uc);
        }
    }
    uc = curl_url_get(
        uh,
        CURLUPART_OPTIONS,
        Some(unsafe { &mut (*data).state.up.options }),
        ((1 as i32) << 6 as i32) as u32,
    );
    if uc as u64 == 0 {
        let mut fresh126 = unsafe { &mut ((*conn).options) };
        *fresh126 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*data).state.up.options) };
        if (unsafe { (*conn).options }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    } else if uc as u32 != CURLUE_NO_OPTIONS as i32 as u32 {
        return Curl_uc_to_curlcode(uc);
    }
    uc = curl_url_get(
        uh,
        CURLUPART_PATH,
        Some(unsafe { &mut (*data).state.up.path }),
        0 as i32 as u32,
    );
    if uc as u64 != 0 {
        return Curl_uc_to_curlcode(uc);
    }
    uc = curl_url_get(
        uh,
        CURLUPART_PORT,
        Some(unsafe { &mut (*data).state.up.port }),
        ((1 as i32) << 0 as i32) as u32,
    );
    if uc as u64 != 0 {
        if Curl_strcasecompare(b"file\0" as *const u8 as *const i8, unsafe { (*data).state.up.scheme }) == 0 {
            return CURLE_OUT_OF_MEMORY;
        }
    } else {
        let mut port: u64 = unsafe { strtoul((*data).state.up.port, 0 as *mut *mut i8, 10 as i32) };
        let mut fresh127 = unsafe { &mut ((*conn).remote_port) };
        *fresh127 = if (unsafe { (*data).set.use_port }) != 0 && (unsafe { ((*data).state).allow_port() }) as i32 != 0 {
            (unsafe { (*data).set.use_port }) as i32
        } else {
            curlx_ultous(port) as i32
        };
        (unsafe { (*conn).port = *fresh127 });
    }
    curl_url_get(
        uh,
        CURLUPART_QUERY,
        Some(unsafe { &mut (*data).state.up.query }),
        0 as i32 as u32,
    );
    hostname = unsafe { (*data).state.up.hostname };
    if !hostname.is_null() && (unsafe { *hostname.offset(0 as i32 as isize) }) as i32 == '[' as i32 {
        let mut hlen: u64 = 0;
        let mut fresh128 = unsafe { &mut ((*conn).bits) };
        (*fresh128).set_ipv6_ip(1 as i32 as bit);
        hostname = unsafe { hostname.offset(1) };
        hlen = unsafe { strlen(hostname) };
        (unsafe { *hostname.offset(hlen.wrapping_sub(1 as i32 as u64) as isize) = 0 as i32 as i8 });
        zonefrom_url(uh, data, conn);
    }
    let mut fresh129 = unsafe { &mut ((*conn).host.rawalloc) };
    *fresh129 = unsafe { Curl_cstrdup.expect("non-null function pointer")(if !hostname.is_null() {
        hostname as *const i8
    } else {
        b"\0" as *const u8 as *const i8
    }) };
    if (unsafe { (*conn).host.rawalloc }).is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    let mut fresh130 = unsafe { &mut ((*conn).host.name) };
    *fresh130 = unsafe { (*conn).host.rawalloc };
    if (unsafe { (*data).set.scope_id }) != 0 {
        (unsafe { (*conn).scope_id = (*data).set.scope_id });
    }
    return CURLE_OK;
}
extern "C" fn setup_range(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut s: *mut crate::src::lib::http2::UrlState = unsafe { &mut (*data).state };
    (unsafe { (*s).resume_from = (*data).set.set_resume_from });
    if (unsafe { (*s).resume_from }) != 0 || !(unsafe { (*data).set.str_0[STRING_SET_RANGE as i32 as usize] }).is_null() {
        if (unsafe { (*s).rangestringalloc() }) != 0 {
            (unsafe { Curl_cfree.expect("non-null function pointer")((*s).range as *mut libc::c_void) });
        }
        if (unsafe { (*s).resume_from }) != 0 {
            let mut fresh131 = unsafe { &mut ((*s).range) };
            *fresh131 = unsafe { curl_maprintf(b"%ld-\0" as *const u8 as *const i8, (*s).resume_from) };
        } else {
            let mut fresh132 = unsafe { &mut ((*s).range) };
            *fresh132 = unsafe { Curl_cstrdup.expect("non-null function pointer")(
                (*data).set.str_0[STRING_SET_RANGE as i32 as usize],
            ) };
        }
        (unsafe { (*s).set_rangestringalloc(
            (if !((*s).range).is_null() {
                1 as i32
            } else {
                0 as i32
            }) as bit,
        ) });
        if (unsafe { (*s).range }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (unsafe { (*s).set_use_range(1 as i32 as bit) });
    } else {
        (unsafe { (*s).set_use_range(0 as i32 as bit) });
    }
    return CURLE_OK;
}
extern "C" fn setup_connection_internals(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut p: *const crate::src::lib::http2::Curl_handler = 0 as *const Curl_handler;
    let mut result: u32 = CURLE_OK;
    p = unsafe { (*conn).handler };
    if unsafe { ((*p).setup_connection).is_some() } {
        result = unsafe { (Some(((*p).setup_connection).expect("non-null function pointer")))
            .expect("non-null function pointer")(data, conn) };
        if result as u64 != 0 {
            return result;
        }
        p = unsafe { (*conn).handler };
    }
    if (unsafe { (*conn).port }) < 0 as i32 {
        (unsafe { (*conn).port = (*p).defport });
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_free_request_state(mut data: *mut crate::src::lib::http2::Curl_easy) {
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).req.p.http as *mut libc::c_void) });
    let mut fresh133 = unsafe { &mut ((*data).req.p.http) };
    *fresh133 = 0 as *mut HTTP;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).req.newurl as *mut libc::c_void) });
    let mut fresh134 = unsafe { &mut ((*data).req.newurl) };
    *fresh134 = 0 as *mut i8;
    if !(unsafe { (*data).req.doh }).is_null() {
        Curl_close(Some(
            unsafe { &mut (*((*(*data).req.doh).probe)
                .as_mut_ptr()
                .offset(0 as i32 as isize))
            .easy },
        ));
        Curl_close(Some(
            unsafe { &mut (*((*(*data).req.doh).probe)
                .as_mut_ptr()
                .offset(1 as i32 as isize))
            .easy },
        ));
    }
}
extern "C" fn check_noproxy(mut name: *const i8, mut no_proxy: *const i8) -> bool {
    if !no_proxy.is_null() && (unsafe { *no_proxy.offset(0 as i32 as isize) }) as i32 != 0 {
        let mut tok_start: u64 = 0;
        let mut tok_end: u64 = 0;
        let mut separator: *const i8 = b", \0" as *const u8 as *const i8;
        let mut no_proxy_len: u64 = 0;
        let mut namelen: u64 = 0;
        let mut endptr: *mut i8 = 0 as *mut i8;
        if Curl_strcasecompare(b"*\0" as *const u8 as *const i8, no_proxy) != 0 {
            return 1 as i32 != 0;
        }
        no_proxy_len = unsafe { strlen(no_proxy) };
        if (unsafe { *name.offset(0 as i32 as isize) }) as i32 == '[' as i32 {
            endptr = unsafe { strchr(name, ']' as i32) };
            if endptr.is_null() {
                return 0 as i32 != 0;
            }
            name = unsafe { name.offset(1) };
            namelen = (unsafe { endptr.offset_from(name) }) as i64 as size_t;
        } else {
            namelen = unsafe { strlen(name) };
        }
        tok_start = 0 as i32 as size_t;
        while tok_start < no_proxy_len {
            while tok_start < no_proxy_len
                && !(unsafe { strchr(separator, *no_proxy.offset(tok_start as isize) as i32) }).is_null()
            {
                tok_start = tok_start.wrapping_add(1);
            }
            if tok_start == no_proxy_len {
                break;
            }
            tok_end = tok_start;
            while tok_end < no_proxy_len
                && (unsafe { strchr(separator, *no_proxy.offset(tok_end as isize) as i32) }).is_null()
            {
                tok_end = tok_end.wrapping_add(1);
            }
            if (unsafe { *no_proxy.offset(tok_start as isize) }) as i32 == '.' as i32 {
                tok_start = tok_start.wrapping_add(1);
            }
            if tok_end.wrapping_sub(tok_start) <= namelen {
                let mut checkn: *const i8 = unsafe { name
                    .offset(namelen as isize)
                    .offset(-(tok_end.wrapping_sub(tok_start) as isize)) };
                if Curl_strncasecompare(
                    unsafe { no_proxy.offset(tok_start as isize) },
                    checkn,
                    tok_end.wrapping_sub(tok_start),
                ) != 0
                {
                    if tok_end.wrapping_sub(tok_start) == namelen
                        || (unsafe { *checkn.offset(-(1 as i32 as isize)) }) as i32 == '.' as i32
                    {
                        return 1 as i32 != 0;
                    }
                }
            }
            tok_start = tok_end.wrapping_add(1 as i32 as u64);
        }
    }
    return 0 as i32 != 0;
}
extern "C" fn detect_proxy(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> *mut i8 {
    let mut proxy: *mut i8 = 0 as *mut i8;
    let mut proxy_env: [i8; 128] = [0; 128];
    let mut protop: *const i8 = unsafe { (*(*conn).handler).scheme };
    let mut envp: *mut i8 = proxy_env.as_mut_ptr();
    let mut prox: *mut i8 = 0 as *mut i8;
    while (unsafe { *protop }) != 0 {
        let mut fresh138 = envp;
        envp = unsafe { envp.offset(1) };
        (unsafe { *fresh138 = ({
            let mut __res: i32 = 0;
            if ::std::mem::size_of::<i32>() as u64 > 1 as i32 as u64 {
                if 0 != 0 {
                    let mut fresh135 = protop;
                    protop = protop.offset(1);
                    let mut __c: i32 = *fresh135 as i32;
                    __res = if __c < -(128 as i32) || __c > 255 as i32 {
                        __c
                    } else {
                        *(*__ctype_tolower_loc()).offset(__c as isize)
                    };
                } else {
                    let mut fresh136 = protop;
                    protop = protop.offset(1);
                    __res = tolower(*fresh136 as i32);
                }
            } else {
                let mut fresh137 = protop;
                protop = protop.offset(1);
                __res = *(*__ctype_tolower_loc()).offset(*fresh137 as i32 as isize);
            }
            __res
        }) as i8 });
    }
    (unsafe { strcpy(envp, b"_proxy\0" as *const u8 as *const i8) });
    prox = curl_getenv(proxy_env.as_mut_ptr());
    if prox.is_null()
        && Curl_strcasecompare(
            b"http_proxy\0" as *const u8 as *const i8,
            proxy_env.as_mut_ptr(),
        ) == 0
    {
        Curl_strntoupper(
            proxy_env.as_mut_ptr(),
            proxy_env.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 128]>() as u64,
        );
        prox = curl_getenv(proxy_env.as_mut_ptr());
    }
    envp = proxy_env.as_mut_ptr();
    if !prox.is_null() {
        proxy = prox;
    } else {
        envp = b"all_proxy\0" as *const u8 as *const i8 as *mut i8;
        proxy = curl_getenv(envp);
        if proxy.is_null() {
            envp = b"ALL_PROXY\0" as *const u8 as *const i8 as *mut i8;
            proxy = curl_getenv(envp);
        }
    }
    if !proxy.is_null() {
        (unsafe { Curl_infof(
            data,
            b"Uses proxy env variable %s == '%s'\0" as *const u8 as *const i8,
            envp,
            proxy,
        ) });
    }
    return proxy;
}
extern "C" fn parse_proxy(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut proxy: *mut i8,
    mut proxytype: u32,
) -> u32 {
    let mut current_block: u64;
    let mut portptr: *mut i8 = 0 as *mut i8;
    let mut port: i32 = -(1 as i32);
    let mut proxyuser: *mut i8 = 0 as *mut i8;
    let mut proxypasswd: *mut i8 = 0 as *mut i8;
    let mut host: *mut i8 = 0 as *mut i8;
    let mut sockstype: bool = false;
    let mut uc: u32 = CURLUE_OK;
    let mut proxyinfo: *mut crate::src::lib::http2::proxy_info = 0 as *mut proxy_info;
    let mut uhp: *mut crate::src::lib::urlapi::Curl_URL = curl_url();
    let mut result: u32 = CURLE_OK;
    let mut scheme: *mut i8 = 0 as *mut i8;
    uc = curl_url_set(
        uhp,
        CURLUPART_URL,
        proxy,
        ((1 as i32) << 3 as i32 | (1 as i32) << 9 as i32) as u32,
    );
    if uc as u64 == 0 {
        uc = curl_url_get(uhp, CURLUPART_SCHEME, Some(&mut scheme), 0 as i32 as u32);
        if uc as u64 != 0 {
            result = CURLE_OUT_OF_MEMORY;
        } else {
            if Curl_strcasecompare(b"https\0" as *const u8 as *const i8, scheme) != 0 {
                proxytype = CURLPROXY_HTTPS;
                current_block = 15125582407903384992;
            } else if Curl_strcasecompare(b"socks5h\0" as *const u8 as *const i8, scheme) != 0 {
                proxytype = CURLPROXY_SOCKS5_HOSTNAME;
                current_block = 15125582407903384992;
            } else if Curl_strcasecompare(b"socks5\0" as *const u8 as *const i8, scheme) != 0 {
                proxytype = CURLPROXY_SOCKS5;
                current_block = 15125582407903384992;
            } else if Curl_strcasecompare(b"socks4a\0" as *const u8 as *const i8, scheme) != 0 {
                proxytype = CURLPROXY_SOCKS4A;
                current_block = 15125582407903384992;
            } else if Curl_strcasecompare(b"socks4\0" as *const u8 as *const i8, scheme) != 0
                || Curl_strcasecompare(b"socks\0" as *const u8 as *const i8, scheme) != 0
            {
                proxytype = CURLPROXY_SOCKS4;
                current_block = 15125582407903384992;
            } else if Curl_strcasecompare(b"http\0" as *const u8 as *const i8, scheme) != 0 {
                current_block = 15125582407903384992;
            } else {
                (unsafe { Curl_failf(
                    data,
                    b"Unsupported proxy scheme for '%s'\0" as *const u8 as *const i8,
                    proxy,
                ) });
                result = CURLE_COULDNT_CONNECT;
                current_block = 467357264955599708;
            }
            match current_block {
                467357264955599708 => {}
                _ => {
                    if (unsafe { (*Curl_ssl).supports }) & ((1 as i32) << 4 as i32) as u32 == 0 {
                        if proxytype as u32 == CURLPROXY_HTTPS as i32 as u32 {
                            (unsafe { Curl_failf (data , b"Unsupported proxy '%s', libcurl is built without the HTTPS-proxy support.\0" as * const u8 as * const i8 , proxy ,) }) ;
                            result = CURLE_NOT_BUILT_IN;
                            current_block = 467357264955599708;
                        } else {
                            current_block = 2569451025026770673;
                        }
                    } else {
                        current_block = 2569451025026770673;
                    }
                    match current_block {
                        467357264955599708 => {}
                        _ => {
                            sockstype = proxytype as u32 == CURLPROXY_SOCKS5_HOSTNAME as i32 as u32
                                || proxytype as u32 == CURLPROXY_SOCKS5 as i32 as u32
                                || proxytype as u32 == CURLPROXY_SOCKS4A as i32 as u32
                                || proxytype as u32 == CURLPROXY_SOCKS4 as i32 as u32;
                            proxyinfo = if sockstype as i32 != 0 {
                                unsafe { &mut (*conn).socks_proxy }
                            } else {
                                unsafe { &mut (*conn).http_proxy }
                            };
                            (unsafe { (*proxyinfo).proxytype = proxytype });
                            uc = curl_url_get(
                                uhp,
                                CURLUPART_USER,
                                Some(&mut proxyuser),
                                ((1 as i32) << 6 as i32) as u32,
                            );
                            if !(uc as u32 != 0 && uc as u32 != CURLUE_NO_USER as i32 as u32) {
                                uc = curl_url_get(
                                    uhp,
                                    CURLUPART_PASSWORD,
                                    Some(&mut proxypasswd),
                                    ((1 as i32) << 6 as i32) as u32,
                                );
                                if !(uc as u32 != 0
                                    && uc as u32 != CURLUE_NO_PASSWORD as i32 as u32)
                                {
                                    if !proxyuser.is_null() || !proxypasswd.is_null() {
                                        (unsafe { Curl_cfree.expect("non-null function pointer")(
                                            (*proxyinfo).user as *mut libc::c_void,
                                        ) });
                                        let mut fresh139 = unsafe { &mut ((*proxyinfo).user) };
                                        *fresh139 = 0 as *mut i8;
                                        let mut fresh140 = unsafe { &mut ((*proxyinfo).user) };
                                        *fresh140 = proxyuser;
                                        result = Curl_setstropt(
                                            Some(unsafe { &mut (*data).state.aptr.proxyuser }),
                                            proxyuser,
                                        );
                                        proxyuser = 0 as *mut i8;
                                        if result as u64 != 0 {
                                            current_block = 467357264955599708;
                                        } else {
                                            (unsafe { Curl_cfree.expect("non-null function pointer")(
                                                (*proxyinfo).passwd as *mut libc::c_void,
                                            ) });
                                            let mut fresh141 = unsafe { &mut ((*proxyinfo).passwd) };
                                            *fresh141 = 0 as *mut i8;
                                            if proxypasswd.is_null() {
                                                proxypasswd = unsafe { Curl_cstrdup
                                                    .expect("non-null function pointer")(
                                                    b"\0" as *const u8 as *const i8,
                                                ) };
                                                if proxypasswd.is_null() {
                                                    result = CURLE_OUT_OF_MEMORY;
                                                    current_block = 467357264955599708;
                                                } else {
                                                    current_block = 1854459640724737493;
                                                }
                                            } else {
                                                current_block = 1854459640724737493;
                                            }
                                            match current_block {
                                                467357264955599708 => {}
                                                _ => {
                                                    let mut fresh142 = unsafe { &mut ((*proxyinfo).passwd) };
                                                    *fresh142 = proxypasswd;
                                                    result = Curl_setstropt(
                                                        Some(unsafe { &mut (*data).state.aptr.proxypasswd }),
                                                        proxypasswd,
                                                    );
                                                    proxypasswd = 0 as *mut i8;
                                                    if result as u64 != 0 {
                                                        current_block = 467357264955599708;
                                                    } else {
                                                        let mut fresh143 = unsafe { &mut ((*conn).bits) };
                                                        (*fresh143)
                                                            .set_proxy_user_passwd(1 as i32 as bit);
                                                        current_block = 11441799814184323368;
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        current_block = 11441799814184323368;
                                    }
                                    match current_block {
                                        467357264955599708 => {}
                                        _ => {
                                            curl_url_get(
                                                uhp,
                                                CURLUPART_PORT,
                                                Some(&mut portptr),
                                                0 as i32 as u32,
                                            );
                                            if !portptr.is_null() {
                                                port = (unsafe { strtol(portptr, 0 as *mut *mut i8, 10 as i32) })
                                                    as i32;
                                                (unsafe { Curl_cfree.expect("non-null function pointer")(
                                                    portptr as *mut libc::c_void,
                                                ) });
                                            } else if (unsafe { (*data).set.proxyport }) != 0 {
                                                port = (unsafe { (*data).set.proxyport }) as i32;
                                            } else if proxytype as u32
                                                == CURLPROXY_HTTPS as i32 as u32
                                            {
                                                port = 443 as i32;
                                            } else {
                                                port = 1080 as i32;
                                            }
                                            if port >= 0 as i32 {
                                                (unsafe { (*proxyinfo).port = port as i64 });
                                                if (unsafe { (*conn).port }) < 0 as i32
                                                    || sockstype as i32 != 0
                                                    || (unsafe { (*conn).socks_proxy.host.rawalloc }).is_null()
                                                {
                                                    (unsafe { (*conn).port = port });
                                                }
                                            }
                                            uc = curl_url_get(
                                                uhp,
                                                CURLUPART_HOST,
                                                Some(&mut host),
                                                ((1 as i32) << 6 as i32) as u32,
                                            );
                                            if uc as u64 != 0 {
                                                result = CURLE_OUT_OF_MEMORY;
                                            } else {
                                                (unsafe { Curl_cfree.expect("non-null function pointer")(
                                                    (*proxyinfo).host.rawalloc as *mut libc::c_void,
                                                ) });
                                                let mut fresh144 =
                                                    unsafe { &mut ((*proxyinfo).host.rawalloc) };
                                                *fresh144 = 0 as *mut i8;
                                                let mut fresh145 =
                                                    unsafe { &mut ((*proxyinfo).host.rawalloc) };
                                                *fresh145 = host;
                                                if (unsafe { *host.offset(0 as i32 as isize) }) as i32
                                                    == '[' as i32
                                                {
                                                    let mut len: u64 = unsafe { strlen(host) };
                                                    (unsafe { *host.offset(
                                                        len.wrapping_sub(1 as i32 as u64) as isize,
                                                    ) = 0 as i32 as i8 });
                                                    host = unsafe { host.offset(1) };
                                                    zonefrom_url(uhp, data, conn);
                                                }
                                                let mut fresh146 = unsafe { &mut ((*proxyinfo).host.name) };
                                                *fresh146 = host;
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
    } else {
        (unsafe { Curl_failf(
            data,
            b"Unsupported proxy syntax in '%s'\0" as *const u8 as *const i8,
            proxy,
        ) });
        result = CURLE_COULDNT_RESOLVE_PROXY;
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")(proxyuser as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")(proxypasswd as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")(scheme as *mut libc::c_void) });
    curl_url_cleanup(uhp);
    return result;
}
extern "C" fn parse_proxy_auth(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut proxyuser: *const i8 = if !(unsafe { (*data).state.aptr.proxyuser }).is_null() {
        (unsafe { (*data).state.aptr.proxyuser }) as *const i8
    } else {
        b"\0" as *const u8 as *const i8
    };
    let mut proxypasswd: *const i8 = if !(unsafe { (*data).state.aptr.proxypasswd }).is_null() {
        (unsafe { (*data).state.aptr.proxypasswd }) as *const i8
    } else {
        b"\0" as *const u8 as *const i8
    };
    let mut result: u32 = CURLE_OK;
    if !proxyuser.is_null() {
        result = Curl_urldecode(
            data,
            proxyuser,
            0 as i32 as size_t,
            Some(unsafe { &mut (*conn).http_proxy.user }),
            Option::<&'_ mut u64>::None,
            REJECT_ZERO,
        );
        if result as u64 == 0 {
            result = Curl_setstropt(
                Some(unsafe { &mut (*data).state.aptr.proxyuser }),
                unsafe { (*conn).http_proxy.user },
            );
        }
    }
    if result as u64 == 0 && !proxypasswd.is_null() {
        result = Curl_urldecode(
            data,
            proxypasswd,
            0 as i32 as size_t,
            Some(unsafe { &mut (*conn).http_proxy.passwd }),
            Option::<&'_ mut u64>::None,
            REJECT_ZERO,
        );
        if result as u64 == 0 {
            result = Curl_setstropt(
                Some(unsafe { &mut (*data).state.aptr.proxypasswd }),
                unsafe { (*conn).http_proxy.passwd },
            );
        }
    }
    return result;
}
extern "C" fn create_conn_helper_init_proxy(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut current_block: u64;
    let mut proxy: *mut i8 = 0 as *mut i8;
    let mut socksproxy: *mut i8 = 0 as *mut i8;
    let mut no_proxy: *mut i8 = 0 as *mut i8;
    let mut result: u32 = CURLE_OK;
    if (unsafe { ((*conn).bits).proxy_user_passwd() }) != 0 {
        result = parse_proxy_auth(data, conn);
        if result as u64 != 0 {
            current_block = 5128804967847913759;
        } else {
            current_block = 6873731126896040597;
        }
    } else {
        current_block = 6873731126896040597;
    }
    match current_block {
        6873731126896040597 => {
            if !(unsafe { (*data).set.str_0[STRING_PROXY as i32 as usize] }).is_null() {
                proxy = unsafe { Curl_cstrdup.expect("non-null function pointer")(
                    (*data).set.str_0[STRING_PROXY as i32 as usize],
                ) };
                if proxy.is_null() {
                    (unsafe { Curl_failf(data, b"memory shortage\0" as *const u8 as *const i8) });
                    result = CURLE_OUT_OF_MEMORY;
                    current_block = 5128804967847913759;
                } else {
                    current_block = 2968425633554183086;
                }
            } else {
                current_block = 2968425633554183086;
            }
            match current_block {
                5128804967847913759 => {}
                _ => {
                    if !(unsafe { (*data).set.str_0[STRING_PRE_PROXY as i32 as usize] }).is_null() {
                        socksproxy = unsafe { Curl_cstrdup.expect("non-null function pointer")(
                            (*data).set.str_0[STRING_PRE_PROXY as i32 as usize],
                        ) };
                        if socksproxy.is_null() {
                            (unsafe { Curl_failf(data, b"memory shortage\0" as *const u8 as *const i8) });
                            result = CURLE_OUT_OF_MEMORY;
                            current_block = 5128804967847913759;
                        } else {
                            current_block = 15652330335145281839;
                        }
                    } else {
                        current_block = 15652330335145281839;
                    }
                    match current_block {
                        5128804967847913759 => {}
                        _ => {
                            if (unsafe { (*data).set.str_0[STRING_NOPROXY as i32 as usize] }).is_null() {
                                let mut p: *const i8 = b"no_proxy\0" as *const u8 as *const i8;
                                no_proxy = curl_getenv(p);
                                if no_proxy.is_null() {
                                    p = b"NO_PROXY\0" as *const u8 as *const i8;
                                    no_proxy = curl_getenv(p);
                                }
                                if !no_proxy.is_null() {
                                    (unsafe { Curl_infof(
                                        data,
                                        b"Uses proxy env variable %s == '%s'\0" as *const u8
                                            as *const i8,
                                        p,
                                        no_proxy,
                                    ) });
                                }
                            }
                            if check_noproxy(
                                unsafe { (*conn).host.name },
                                if !(unsafe { (*data).set.str_0[STRING_NOPROXY as i32 as usize] }).is_null() {
                                    unsafe { (*data).set.str_0[STRING_NOPROXY as i32 as usize] }
                                } else {
                                    no_proxy
                                },
                            ) {
                                (unsafe { Curl_cfree.expect("non-null function pointer")(
                                    proxy as *mut libc::c_void,
                                ) });
                                proxy = 0 as *mut i8;
                                (unsafe { Curl_cfree.expect("non-null function pointer")(
                                    socksproxy as *mut libc::c_void,
                                ) });
                                socksproxy = 0 as *mut i8;
                            } else if proxy.is_null() && socksproxy.is_null() {
                                proxy = detect_proxy(data, conn);
                            }
                            (unsafe { Curl_cfree.expect("non-null function pointer")(
                                no_proxy as *mut libc::c_void,
                            ) });
                            no_proxy = 0 as *mut i8;
                            if !proxy.is_null() && !(unsafe { (*conn).unix_domain_socket }).is_null() {
                                (unsafe { Curl_cfree.expect("non-null function pointer")(
                                    proxy as *mut libc::c_void,
                                ) });
                                proxy = 0 as *mut i8;
                            }
                            if !proxy.is_null()
                                && ((unsafe { *proxy }) == 0
                                    || (unsafe { (*(*conn).handler).flags }) & ((1 as i32) << 4 as i32) as u32
                                        != 0)
                            {
                                (unsafe { Curl_cfree.expect("non-null function pointer")(
                                    proxy as *mut libc::c_void,
                                ) });
                                proxy = 0 as *mut i8;
                            }
                            if !socksproxy.is_null()
                                && ((unsafe { *socksproxy }) == 0
                                    || (unsafe { (*(*conn).handler).flags }) & ((1 as i32) << 4 as i32) as u32
                                        != 0)
                            {
                                (unsafe { Curl_cfree.expect("non-null function pointer")(
                                    socksproxy as *mut libc::c_void,
                                ) });
                                socksproxy = 0 as *mut i8;
                            }
                            if !proxy.is_null() || !socksproxy.is_null() {
                                if !proxy.is_null() {
                                    result = parse_proxy(
                                        data,
                                        conn,
                                        proxy,
                                        unsafe { (*conn).http_proxy.proxytype },
                                    );
                                    (unsafe { Curl_cfree.expect("non-null function pointer")(
                                        proxy as *mut libc::c_void,
                                    ) });
                                    proxy = 0 as *mut i8;
                                    if result as u64 != 0 {
                                        current_block = 5128804967847913759;
                                    } else {
                                        current_block = 2706659501864706830;
                                    }
                                } else {
                                    current_block = 2706659501864706830;
                                }
                                match current_block {
                                    5128804967847913759 => {}
                                    _ => {
                                        if !socksproxy.is_null() {
                                            result = parse_proxy(
                                                data,
                                                conn,
                                                socksproxy,
                                                unsafe { (*conn).socks_proxy.proxytype },
                                            );
                                            (unsafe { Curl_cfree.expect("non-null function pointer")(
                                                socksproxy as *mut libc::c_void,
                                            ) });
                                            socksproxy = 0 as *mut i8;
                                            if result as u64 != 0 {
                                                current_block = 5128804967847913759;
                                            } else {
                                                current_block = 10853015579903106591;
                                            }
                                        } else {
                                            current_block = 10853015579903106591;
                                        }
                                        match current_block {
                                            5128804967847913759 => {}
                                            _ => {
                                                if !(unsafe { (*conn).http_proxy.host.rawalloc }).is_null() {
                                                    if (unsafe { (*(*conn).handler).protocol })
                                                        & ((1 as i32) << 0 as i32
                                                            | (1 as i32) << 1 as i32)
                                                            as u32
                                                        == 0
                                                    {
                                                        if (unsafe { (*(*conn).handler).flags })
                                                            & ((1 as i32) << 11 as i32) as u32
                                                            != 0
                                                            && (unsafe { ((*conn).bits).tunnel_proxy() }) == 0
                                                        {
                                                            let mut fresh147 =
                                                                unsafe { &mut ((*conn).handler) };
                                                            *fresh147 = unsafe { &Curl_handler_http };
                                                        } else {
                                                            let mut fresh148 = unsafe { &mut ((*conn).bits) };
                                                            (*fresh148)
                                                                .set_tunnel_proxy(1 as i32 as bit);
                                                        }
                                                    }
                                                    let mut fresh149 = unsafe { &mut ((*conn).bits) };
                                                    (*fresh149).set_httpproxy(1 as i32 as bit);
                                                } else {
                                                    let mut fresh150 = unsafe { &mut ((*conn).bits) };
                                                    (*fresh150).set_httpproxy(0 as i32 as bit);
                                                    let mut fresh151 = unsafe { &mut ((*conn).bits) };
                                                    (*fresh151).set_tunnel_proxy(0 as i32 as bit);
                                                }
                                                if !(unsafe { (*conn).socks_proxy.host.rawalloc }).is_null() {
                                                    if (unsafe { (*conn).http_proxy.host.rawalloc }).is_null()
                                                    {
                                                        if (unsafe { (*conn).socks_proxy.user }).is_null() {
                                                            let mut fresh152 =
                                                                unsafe { &mut ((*conn).socks_proxy.user) };
                                                            *fresh152 = unsafe { (*conn).http_proxy.user };
                                                            let mut fresh153 =
                                                                unsafe { &mut ((*conn).http_proxy.user) };
                                                            *fresh153 = 0 as *mut i8;
                                                            (unsafe { Curl_cfree.expect(
                                                                "non-null function pointer",
                                                            )(
                                                                (*conn).socks_proxy.passwd
                                                                    as *mut libc::c_void,
                                                            ) });
                                                            let mut fresh154 =
                                                                unsafe { &mut ((*conn).socks_proxy.passwd) };
                                                            *fresh154 = 0 as *mut i8;
                                                            let mut fresh155 =
                                                                unsafe { &mut ((*conn).socks_proxy.passwd) };
                                                            *fresh155 = unsafe { (*conn).http_proxy.passwd };
                                                            let mut fresh156 =
                                                                unsafe { &mut ((*conn).http_proxy.passwd) };
                                                            *fresh156 = 0 as *mut i8;
                                                        }
                                                    }
                                                    let mut fresh157 = unsafe { &mut ((*conn).bits) };
                                                    (*fresh157).set_socksproxy(1 as i32 as bit);
                                                } else {
                                                    let mut fresh158 = unsafe { &mut ((*conn).bits) };
                                                    (*fresh158).set_socksproxy(0 as i32 as bit);
                                                }
                                                current_block = 16463303006880176998;
                                            }
                                        }
                                    }
                                }
                            } else {
                                let mut fresh159 = unsafe { &mut ((*conn).bits) };
                                (*fresh159).set_socksproxy(0 as i32 as bit);
                                let mut fresh160 = unsafe { &mut ((*conn).bits) };
                                (*fresh160).set_httpproxy(0 as i32 as bit);
                                current_block = 16463303006880176998;
                            }
                            match current_block {
                                5128804967847913759 => {}
                                _ => {
                                    let mut fresh161 = unsafe { &mut ((*conn).bits) };
                                    (*fresh161).set_proxy(
                                        ((unsafe { ((*conn).bits).httpproxy() }) as i32 != 0
                                            || (unsafe { ((*conn).bits).socksproxy() }) as i32 != 0)
                                            as i32 as bit,
                                    );
                                    if (unsafe { ((*conn).bits).proxy() }) == 0 {
                                        let mut fresh162 = unsafe { &mut ((*conn).bits) };
                                        (*fresh162).set_proxy(0 as i32 as bit);
                                        let mut fresh163 = unsafe { &mut ((*conn).bits) };
                                        (*fresh163).set_httpproxy(0 as i32 as bit);
                                        let mut fresh164 = unsafe { &mut ((*conn).bits) };
                                        (*fresh164).set_socksproxy(0 as i32 as bit);
                                        let mut fresh165 = unsafe { &mut ((*conn).bits) };
                                        (*fresh165).set_proxy_user_passwd(0 as i32 as bit);
                                        let mut fresh166 = unsafe { &mut ((*conn).bits) };
                                        (*fresh166).set_tunnel_proxy(0 as i32 as bit);
                                        (unsafe { (*conn).http_proxy.proxytype = CURLPROXY_HTTP });
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
    (unsafe { Curl_cfree.expect("non-null function pointer")(socksproxy as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")(proxy as *mut libc::c_void) });
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_parse_login_details<'a1, 'a2>(
    mut login: *const i8,
    len: u64,
    mut userp: Option<&'a1 mut *mut i8>,
    mut passwdp: Option<&'a2 mut *mut i8>,
    mut optionsp: *mut *mut i8,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut ubuf: *mut i8 = 0 as *mut i8;
    let mut pbuf: *mut i8 = 0 as *mut i8;
    let mut obuf: *mut i8 = 0 as *mut i8;
    let mut psep: *const i8 = 0 as *const i8;
    let mut osep: *const i8 = 0 as *const i8;
    let mut ulen: u64 = 0;
    let mut plen: u64 = 0;
    let mut olen: u64 = 0;
    let mut llen: u64 = unsafe { strlen(login) };
    if llen > 8000000 as i32 as u64 {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if !borrow(&passwdp).is_none() {
        psep = unsafe { strchr(login, ':' as i32) };
        if psep >= (unsafe { login.offset(len as isize) }) {
            psep = 0 as *const i8;
        }
    }
    if !optionsp.is_null() {
        osep = unsafe { strchr(login, ';' as i32) };
        if osep >= (unsafe { login.offset(len as isize) }) {
            osep = 0 as *const i8;
        }
    }
    ulen = if !psep.is_null() {
        (if !osep.is_null() && psep > osep {
            (unsafe { osep.offset_from(login) }) as i64
        } else {
            (unsafe { psep.offset_from(login) }) as i64
        }) as size_t
    } else if !osep.is_null() {
        (unsafe { osep.offset_from(login) }) as i64 as size_t
    } else {
        len
    };
    plen = if !psep.is_null() {
        (if !osep.is_null() && osep > psep {
            (unsafe { osep.offset_from(psep) }) as i64 as size_t
        } else {
            (unsafe { login.offset(len as isize).offset_from(psep) }) as i64 as size_t
        })
        .wrapping_sub(1 as i32 as u64)
    } else {
        0 as i32 as u64
    };
    olen = if !osep.is_null() {
        (if !psep.is_null() && psep > osep {
            (unsafe { psep.offset_from(osep) }) as i64 as size_t
        } else {
            (unsafe { login.offset(len as isize).offset_from(osep) }) as i64 as size_t
        })
        .wrapping_sub(1 as i32 as u64)
    } else {
        0 as i32 as u64
    };
    if !borrow(&userp).is_none() && ulen != 0 {
        ubuf = (unsafe { Curl_cmalloc.expect("non-null function pointer")(ulen.wrapping_add(1 as i32 as u64)) })
            as *mut i8;
        if ubuf.is_null() {
            result = CURLE_OUT_OF_MEMORY;
        }
    }
    if result as u64 == 0 && !borrow(&passwdp).is_none() && plen != 0 {
        pbuf = (unsafe { Curl_cmalloc.expect("non-null function pointer")(plen.wrapping_add(1 as i32 as u64)) })
            as *mut i8;
        if pbuf.is_null() {
            (unsafe { Curl_cfree.expect("non-null function pointer")(ubuf as *mut libc::c_void) });
            result = CURLE_OUT_OF_MEMORY;
        }
    }
    if result as u64 == 0 && !optionsp.is_null() && olen != 0 {
        obuf = (unsafe { Curl_cmalloc.expect("non-null function pointer")(olen.wrapping_add(1 as i32 as u64)) })
            as *mut i8;
        if obuf.is_null() {
            (unsafe { Curl_cfree.expect("non-null function pointer")(pbuf as *mut libc::c_void) });
            (unsafe { Curl_cfree.expect("non-null function pointer")(ubuf as *mut libc::c_void) });
            result = CURLE_OUT_OF_MEMORY;
        }
    }
    if result as u64 == 0 {
        if !ubuf.is_null() {
            (unsafe { memcpy(
                ubuf as *mut libc::c_void,
                login as *const libc::c_void,
                ulen,
            ) });
            (unsafe { *ubuf.offset(ulen as isize) = '\u{0}' as i32 as i8 });
            (unsafe { Curl_cfree.expect("non-null function pointer")(
                *(borrow_mut(&mut userp)).unwrap() as *mut libc::c_void
            ) });
            *(borrow_mut(&mut userp)).unwrap() = 0 as *mut i8;
            *(borrow_mut(&mut userp)).unwrap() = ubuf;
        }
        if !pbuf.is_null() {
            (unsafe { memcpy(
                pbuf as *mut libc::c_void,
                psep.offset(1 as i32 as isize) as *const libc::c_void,
                plen,
            ) });
            (unsafe { *pbuf.offset(plen as isize) = '\u{0}' as i32 as i8 });
            (unsafe { Curl_cfree.expect("non-null function pointer")(
                *(borrow_mut(&mut passwdp)).unwrap() as *mut libc::c_void
            ) });
            *(borrow_mut(&mut passwdp)).unwrap() = 0 as *mut i8;
            *(borrow_mut(&mut passwdp)).unwrap() = pbuf;
        }
        if !obuf.is_null() {
            (unsafe { memcpy(
                obuf as *mut libc::c_void,
                osep.offset(1 as i32 as isize) as *const libc::c_void,
                olen,
            ) });
            (unsafe { *obuf.offset(olen as isize) = '\u{0}' as i32 as i8 });
            (unsafe { Curl_cfree.expect("non-null function pointer")(*optionsp as *mut libc::c_void) });
            (unsafe { *optionsp = 0 as *mut i8 });
            (unsafe { *optionsp = obuf });
        }
    }
    return result;
}
extern "C" fn parse_remote_port(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    if (unsafe { (*data).set.use_port }) != 0 && (unsafe { ((*data).state).allow_port() }) as i32 != 0 {
        let mut portbuf: [i8; 16] = [0; 16];
        let mut uc: u32 = CURLUE_OK;
        (unsafe { (*conn).remote_port = (*data).set.use_port as u16 as i32 });
        (unsafe { curl_msnprintf(
            portbuf.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 16]>() as u64,
            b"%d\0" as *const u8 as *const i8,
            (*conn).remote_port,
        ) });
        uc = curl_url_set(
            unsafe { (*data).state.uh },
            CURLUPART_PORT,
            portbuf.as_mut_ptr(),
            0 as i32 as u32,
        );
        if uc as u64 != 0 {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
extern "C" fn override_login(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut uc: u32 = CURLUE_OK;
    let mut userp: Option<&'_ mut *mut i8> = Some(unsafe { &mut (*conn).user });
    let mut passwdp: Option<&'_ mut *mut i8> = Some(unsafe { &mut (*conn).passwd });
    let mut optionsp: Option<&'_ mut *mut i8> = Some(unsafe { &mut (*conn).options });
    if (unsafe { (*data).set.use_netrc }) as u32 == CURL_NETRC_REQUIRED as i32 as u32
        && (unsafe { ((*conn).bits).user_passwd() }) as i32 != 0
    {
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            *(borrow_mut(&mut userp)).unwrap() as *mut libc::c_void
        ) });
        *(borrow_mut(&mut userp)).unwrap() = 0 as *mut i8;
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            *(borrow_mut(&mut passwdp)).unwrap() as *mut libc::c_void
        ) });
        *(borrow_mut(&mut passwdp)).unwrap() = 0 as *mut i8;
        let mut fresh167 = unsafe { &mut ((*conn).bits) };
        (*fresh167).set_user_passwd(0 as i32 as bit);
    }
    if !(unsafe { (*data).set.str_0[STRING_OPTIONS as i32 as usize] }).is_null() {
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            *(borrow_mut(&mut optionsp)).unwrap() as *mut libc::c_void
        ) });
        *(borrow_mut(&mut optionsp)).unwrap() = unsafe { Curl_cstrdup.expect("non-null function pointer")(
            (*data).set.str_0[STRING_OPTIONS as i32 as usize],
        ) };
        if (*(borrow_mut(&mut optionsp)).unwrap()).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    let mut fresh168 = unsafe { &mut ((*conn).bits) };
    (*fresh168).set_netrc(0 as i32 as bit);
    if (unsafe { (*data).set.use_netrc }) as u32 != 0
        && (unsafe { (*data).set.str_0[STRING_USERNAME as i32 as usize] }).is_null()
    {
        let mut netrc_user_changed: bool = 0 as i32 != 0;
        let mut netrc_passwd_changed: bool = 0 as i32 != 0;
        let mut ret: i32 = 0;
        ret = Curl_parsenetrc(
            unsafe { (*conn).host.name },
            borrow_mut(&mut userp),
            borrow_mut(&mut passwdp),
            Some(&mut netrc_user_changed),
            Some(&mut netrc_passwd_changed),
            unsafe { (*data).set.str_0[STRING_NETRC_FILE as i32 as usize] },
        );
        if ret > 0 as i32 {
            (unsafe { Curl_infof(
                data,
                b"Couldn't find host %s in the %s file; using defaults\0" as *const u8 as *const i8,
                (*conn).host.name,
                (*data).set.str_0[STRING_NETRC_FILE as i32 as usize],
            ) });
        } else if ret < 0 as i32 {
            return CURLE_OUT_OF_MEMORY;
        } else {
            let mut fresh169 = unsafe { &mut ((*conn).bits) };
            (*fresh169).set_netrc(1 as i32 as bit);
            let mut fresh170 = unsafe { &mut ((*conn).bits) };
            (*fresh170).set_user_passwd(1 as i32 as bit);
        }
    }
    if !(*(borrow(&userp)).unwrap()).is_null() {
        let mut result: u32 = Curl_setstropt(
            Some(unsafe { &mut (*data).state.aptr.user }),
            *(borrow(&userp)).unwrap(),
        );
        if result as u64 != 0 {
            return result;
        }
    }
    if !(unsafe { (*data).state.aptr.user }).is_null() {
        uc = curl_url_set(
            unsafe { (*data).state.uh },
            CURLUPART_USER,
            unsafe { (*data).state.aptr.user },
            ((1 as i32) << 7 as i32) as u32,
        );
        if uc as u64 != 0 {
            return Curl_uc_to_curlcode(uc);
        }
        if (*(borrow_mut(&mut userp)).unwrap()).is_null() {
            *(borrow_mut(&mut userp)).unwrap() =
                unsafe { Curl_cstrdup.expect("non-null function pointer")((*data).state.aptr.user) };
            if (*(borrow_mut(&mut userp)).unwrap()).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        }
    }
    if !(*(borrow(&passwdp)).unwrap()).is_null() {
        let mut result_0: u32 = Curl_setstropt(
            Some(unsafe { &mut (*data).state.aptr.passwd }),
            *(borrow(&passwdp)).unwrap(),
        );
        if result_0 as u64 != 0 {
            return result_0;
        }
    }
    if !(unsafe { (*data).state.aptr.passwd }).is_null() {
        uc = curl_url_set(
            unsafe { (*data).state.uh },
            CURLUPART_PASSWORD,
            unsafe { (*data).state.aptr.passwd },
            ((1 as i32) << 7 as i32) as u32,
        );
        if uc as u64 != 0 {
            return Curl_uc_to_curlcode(uc);
        }
        if (*(borrow_mut(&mut passwdp)).unwrap()).is_null() {
            *(borrow_mut(&mut passwdp)).unwrap() =
                unsafe { Curl_cstrdup.expect("non-null function pointer")((*data).state.aptr.passwd) };
            if (*(borrow_mut(&mut passwdp)).unwrap()).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        }
    }
    return CURLE_OK;
}
extern "C" fn set_login(mut conn: *mut crate::src::lib::http2::connectdata) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut setuser: *const i8 = b"anonymous\0" as *const u8 as *const i8;
    let mut setpasswd: *const i8 = b"ftp@example.com\0" as *const u8 as *const i8;
    if !((unsafe { (*(*conn).handler).flags }) & ((1 as i32) << 5 as i32) as u32 != 0
        && (unsafe { ((*conn).bits).user_passwd() }) == 0)
    {
        setuser = b"\0" as *const u8 as *const i8;
        setpasswd = b"\0" as *const u8 as *const i8;
    }
    if (unsafe { (*conn).user }).is_null() {
        let mut fresh171 = unsafe { &mut ((*conn).user) };
        *fresh171 = unsafe { Curl_cstrdup.expect("non-null function pointer")(setuser) };
        if (unsafe { (*conn).user }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if (unsafe { (*conn).passwd }).is_null() {
        let mut fresh172 = unsafe { &mut ((*conn).passwd) };
        *fresh172 = unsafe { Curl_cstrdup.expect("non-null function pointer")(setpasswd) };
        if (unsafe { (*conn).passwd }).is_null() {
            result = CURLE_OUT_OF_MEMORY;
        }
    }
    return result;
}
extern "C" fn parse_connect_to_host_port<'a1, 'a2>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut host: *const i8,
    mut hostname_result: Option<&'a1 mut *mut i8>,
    mut port_result: Option<&'a2 mut i32>,
) -> u32 {
    let mut current_block: u64;
    let mut host_dup: *mut i8 = 0 as *mut i8;
    let mut hostptr: *mut i8 = 0 as *mut i8;
    let mut host_portno: *mut i8 = 0 as *mut i8;
    let mut portptr: *mut i8 = 0 as *mut i8;
    let mut port: i32 = -(1 as i32);
    let mut result: u32 = CURLE_OK;
    *(borrow_mut(&mut hostname_result)).unwrap() = 0 as *mut i8;
    *(borrow_mut(&mut port_result)).unwrap() = -(1 as i32);
    if host.is_null() || (unsafe { *host }) == 0 {
        return CURLE_OK;
    }
    host_dup = unsafe { Curl_cstrdup.expect("non-null function pointer")(host) };
    if host_dup.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    hostptr = host_dup;
    portptr = hostptr;
    if (unsafe { *hostptr }) as i32 == '[' as i32 {
        hostptr = unsafe { hostptr.offset(1) };
        let mut ptr: *mut i8 = hostptr;
        while (unsafe { *ptr }) as i32 != 0
            && (Curl_isxdigit((unsafe { *ptr }) as u8 as i32) != 0
                || (unsafe { *ptr }) as i32 == ':' as i32
                || (unsafe { *ptr }) as i32 == '.' as i32)
        {
            ptr = unsafe { ptr.offset(1) };
        }
        if (unsafe { *ptr }) as i32 == '%' as i32 {
            if (unsafe { strncmp(b"%25\0" as *const u8 as *const i8, ptr, 3 as i32 as u64) }) != 0 {
                (unsafe { Curl_infof(
                    data,
                    b"Please URL encode %% as %%25, see RFC 6874.\0" as *const u8 as *const i8,
                ) });
            }
            ptr = unsafe { ptr.offset(1) };
            while (unsafe { *ptr }) as i32 != 0
                && (Curl_isalpha((unsafe { *ptr }) as u8 as i32) != 0
                    || Curl_isxdigit((unsafe { *ptr }) as u8 as i32) != 0
                    || (unsafe { *ptr }) as i32 == '-' as i32
                    || (unsafe { *ptr }) as i32 == '.' as i32
                    || (unsafe { *ptr }) as i32 == '_' as i32
                    || (unsafe { *ptr }) as i32 == '~' as i32)
            {
                ptr = unsafe { ptr.offset(1) };
            }
        }
        if (unsafe { *ptr }) as i32 == ']' as i32 {
            let mut fresh173 = ptr;
            ptr = unsafe { ptr.offset(1) };
            (unsafe { *fresh173 = '\u{0}' as i32 as i8 });
        } else {
            (unsafe { Curl_infof(
                data,
                b"Invalid IPv6 address format\0" as *const u8 as *const i8,
            ) });
        }
        portptr = ptr;
    }
    host_portno = unsafe { strchr(portptr, ':' as i32) };
    if !host_portno.is_null() {
        let mut endp: *mut i8 = 0 as *mut i8;
        (unsafe { *host_portno = '\u{0}' as i32 as i8 });
        host_portno = unsafe { host_portno.offset(1) };
        if (unsafe { *host_portno }) != 0 {
            let mut portparse: i64 = unsafe { strtol(host_portno, &mut endp, 10 as i32) };
            if !endp.is_null() && (unsafe { *endp }) as i32 != 0
                || portparse < 0 as i32 as i64
                || portparse > 65535 as i32 as i64
            {
                (unsafe { Curl_failf(
                    data,
                    b"No valid port number in connect to host string (%s)\0" as *const u8
                        as *const i8,
                    host_portno,
                ) });
                result = CURLE_SETOPT_OPTION_SYNTAX;
                current_block = 1356886395307775006;
            } else {
                port = portparse as i32;
                current_block = 10692455896603418738;
            }
        } else {
            current_block = 10692455896603418738;
        }
    } else {
        current_block = 10692455896603418738;
    }
    match current_block {
        10692455896603418738 => {
            if !hostptr.is_null() {
                *(borrow_mut(&mut hostname_result)).unwrap() =
                    unsafe { Curl_cstrdup.expect("non-null function pointer")(hostptr) };
                if (*(borrow_mut(&mut hostname_result)).unwrap()).is_null() {
                    result = CURLE_OUT_OF_MEMORY;
                    current_block = 1356886395307775006;
                } else {
                    current_block = 572715077006366937;
                }
            } else {
                current_block = 572715077006366937;
            }
            match current_block {
                1356886395307775006 => {}
                _ => {
                    *(borrow_mut(&mut port_result)).unwrap() = port;
                }
            }
        }
        _ => {}
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")(host_dup as *mut libc::c_void) });
    return result;
}
extern "C" fn parse_connect_to_string<'a1, 'a2>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut conn_to_host: *const i8,
    mut host_result: Option<&'a1 mut *mut i8>,
    mut port_result: Option<&'a2 mut i32>,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut ptr: *const i8 = conn_to_host;
    let mut host_match: i32 = 0 as i32;
    let mut port_match: i32 = 0 as i32;
    *(borrow_mut(&mut host_result)).unwrap() = 0 as *mut i8;
    *(borrow_mut(&mut port_result)).unwrap() = -(1 as i32);
    if (unsafe { *ptr }) as i32 == ':' as i32 {
        host_match = 1 as i32;
        ptr = unsafe { ptr.offset(1) };
    } else {
        let mut hostname_to_match_len: u64 = 0;
        let mut hostname_to_match: *mut i8 = unsafe { curl_maprintf(
            b"%s%s%s\0" as *const u8 as *const i8,
            if ((*conn).bits).ipv6_ip() as i32 != 0 {
                b"[\0" as *const u8 as *const i8
            } else {
                b"\0" as *const u8 as *const i8
            },
            (*conn).host.name,
            if ((*conn).bits).ipv6_ip() as i32 != 0 {
                b"]\0" as *const u8 as *const i8
            } else {
                b"\0" as *const u8 as *const i8
            },
        ) };
        if hostname_to_match.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        hostname_to_match_len = unsafe { strlen(hostname_to_match) };
        host_match = Curl_strncasecompare(ptr, hostname_to_match, hostname_to_match_len);
        (unsafe { Curl_cfree.expect("non-null function pointer")(hostname_to_match as *mut libc::c_void) });
        ptr = unsafe { ptr.offset(hostname_to_match_len as isize) };
        host_match = (host_match != 0 && (unsafe { *ptr }) as i32 == ':' as i32) as i32;
        ptr = unsafe { ptr.offset(1) };
    }
    if host_match != 0 {
        if (unsafe { *ptr }) as i32 == ':' as i32 {
            port_match = 1 as i32;
            ptr = unsafe { ptr.offset(1) };
        } else {
            let mut ptr_next: *mut i8 = unsafe { strchr(ptr, ':' as i32) };
            if !ptr_next.is_null() {
                let mut endp: *mut i8 = 0 as *mut i8;
                let mut port_to_match: i64 = unsafe { strtol(ptr, &mut endp, 10 as i32) };
                if endp == ptr_next && port_to_match == (unsafe { (*conn).remote_port }) as i64 {
                    port_match = 1 as i32;
                    ptr = unsafe { ptr_next.offset(1 as i32 as isize) };
                }
            }
        }
    }
    if host_match != 0 && port_match != 0 {
        result = parse_connect_to_host_port(
            data,
            ptr,
            borrow_mut(&mut host_result),
            borrow_mut(&mut port_result),
        );
    }
    return result;
}
extern "C" fn parse_connect_to_slist(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut conn_to_host: *mut crate::src::lib::http2::curl_slist,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut host: *mut i8 = 0 as *mut i8;
    let mut port: i32 = -(1 as i32);
    while !conn_to_host.is_null() && host.is_null() && port == -(1 as i32) {
        result = parse_connect_to_string(
            data,
            conn,
            unsafe { (*conn_to_host).data },
            Some(&mut host),
            Some(&mut port),
        );
        if result as u64 != 0 {
            return result;
        }
        if !host.is_null() && (unsafe { *host }) as i32 != 0 {
            let mut fresh174 = unsafe { &mut ((*conn).conn_to_host.rawalloc) };
            *fresh174 = host;
            let mut fresh175 = unsafe { &mut ((*conn).conn_to_host.name) };
            *fresh175 = host;
            let mut fresh176 = unsafe { &mut ((*conn).bits) };
            (*fresh176).set_conn_to_host(1 as i32 as bit);
            (unsafe { Curl_infof(
                data,
                b"Connecting to hostname: %s\0" as *const u8 as *const i8,
                host,
            ) });
        } else {
            let mut fresh177 = unsafe { &mut ((*conn).bits) };
            (*fresh177).set_conn_to_host(0 as i32 as bit);
            (unsafe { Curl_cfree.expect("non-null function pointer")(host as *mut libc::c_void) });
            host = 0 as *mut i8;
        }
        if port >= 0 as i32 {
            (unsafe { (*conn).conn_to_port = port });
            let mut fresh178 = unsafe { &mut ((*conn).bits) };
            (*fresh178).set_conn_to_port(1 as i32 as bit);
            (unsafe { Curl_infof(
                data,
                b"Connecting to port: %d\0" as *const u8 as *const i8,
                port,
            ) });
        } else {
            let mut fresh179 = unsafe { &mut ((*conn).bits) };
            (*fresh179).set_conn_to_port(0 as i32 as bit);
            port = -(1 as i32);
        }
        conn_to_host = unsafe { (*conn_to_host).next };
    }
    if !(unsafe { (*data).asi }).is_null()
        && host.is_null()
        && port == -(1 as i32)
        && ((unsafe { (*(*conn).handler).protocol }) == ((1 as i32) << 1 as i32) as u32 || 0 as i32 != 0)
    {
        let mut srcalpnid: u32 = ALPN_none;
        let mut hit: bool = false;
        let mut as_0: *mut crate::src::lib::altsvc::altsvc = 0 as *mut altsvc;
        let allowed_versions: i32 =
            ((ALPN_h1 as i32 | ALPN_h2 as i32) as i64 & (unsafe { (*(*data).asi).flags })) as i32;
        host = unsafe { (*conn).host.rawalloc };
        srcalpnid = ALPN_h2;
        hit = Curl_altsvc_lookup(
            unsafe { (*data).asi },
            srcalpnid,
            host,
            unsafe { (*conn).remote_port },
            Some(&mut as_0),
            allowed_versions,
        );
        if !hit {
            srcalpnid = ALPN_h1;
            hit = Curl_altsvc_lookup(
                unsafe { (*data).asi },
                srcalpnid,
                host,
                unsafe { (*conn).remote_port },
                Some(&mut as_0),
                allowed_versions,
            );
        }
        if hit {
            let mut hostd: *mut i8 =
                unsafe { Curl_cstrdup.expect("non-null function pointer")((*as_0).dst.host) };
            if hostd.is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            let mut fresh180 = unsafe { &mut ((*conn).conn_to_host.rawalloc) };
            *fresh180 = hostd;
            let mut fresh181 = unsafe { &mut ((*conn).conn_to_host.name) };
            *fresh181 = hostd;
            let mut fresh182 = unsafe { &mut ((*conn).bits) };
            (*fresh182).set_conn_to_host(1 as i32 as bit);
            (unsafe { (*conn).conn_to_port = (*as_0).dst.port as i32 });
            let mut fresh183 = unsafe { &mut ((*conn).bits) };
            (*fresh183).set_conn_to_port(1 as i32 as bit);
            let mut fresh184 = unsafe { &mut ((*conn).bits) };
            (*fresh184).set_altused(1 as i32 as bit);
            (unsafe { Curl_infof(
                data,
                b"Alt-svc connecting from [%s]%s:%d to [%s]%s:%d\0" as *const u8 as *const i8,
                Curl_alpnid2str(srcalpnid),
                host,
                (*conn).remote_port,
                Curl_alpnid2str((*as_0).dst.alpnid),
                hostd,
                (*as_0).dst.port as i32,
            ) });
            if srcalpnid as u32 != (unsafe { (*as_0).dst.alpnid }) as u32 {
                match (unsafe { (*as_0).dst.alpnid }) as u32 {
                    8 => {
                        (unsafe { (*conn).httpversion = 11 as i32 as u8 });
                    }
                    16 => {
                        (unsafe { (*conn).httpversion = 20 as i32 as u8 });
                    }
                    32 => {
                        (unsafe { (*conn).transport = TRNSPRT_QUIC });
                        (unsafe { (*conn).httpversion = 30 as i32 as u8 });
                    }
                    _ => {}
                }
            }
        }
    }
    return result;
}
extern "C" fn resolve_server<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut async_0: Option<&'a1 mut bool>,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut timeout_ms: i64 = Curl_timeleft(
        data,
        0 as *mut crate::src::lib::http2::curltime,
        1 as i32 != 0,
    );
    if (unsafe { ((*conn).bits).reuse() }) != 0 {
        *(borrow_mut(&mut async_0)).unwrap() = 0 as i32 != 0;
    } else {
        let mut rc: i32 = 0;
        let mut hostaddr: *mut crate::src::lib::http2::Curl_dns_entry = 0 as *mut Curl_dns_entry;
        if !(unsafe { (*conn).unix_domain_socket }).is_null() {
            let mut path: *const i8 = unsafe { (*conn).unix_domain_socket };
            hostaddr = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
                1 as i32 as size_t,
                ::std::mem::size_of::<Curl_dns_entry>() as u64,
            ) }) as *mut Curl_dns_entry;
            if hostaddr.is_null() {
                result = CURLE_OUT_OF_MEMORY;
            } else {
                let mut longpath: bool = 0 as i32 != 0;
                let mut fresh185 = unsafe { &mut ((*hostaddr).addr) };
                *fresh185 = Curl_unix2addr(
                    path,
                    Some(&mut longpath),
                    (unsafe { ((*conn).bits).abstract_unix_socket() }) != 0,
                );
                if !(unsafe { (*hostaddr).addr }).is_null() {
                    let mut fresh186 = unsafe { &mut ((*hostaddr).inuse) };
                    *fresh186 += 1;
                } else {
                    if longpath {
                        (unsafe { Curl_failf(
                            data,
                            b"Unix socket path too long: '%s'\0" as *const u8 as *const i8,
                            path,
                        ) });
                        result = CURLE_COULDNT_RESOLVE_HOST;
                    } else {
                        result = CURLE_OUT_OF_MEMORY;
                    }
                    (unsafe { Curl_cfree.expect("non-null function pointer")(hostaddr as *mut libc::c_void) });
                    hostaddr = 0 as *mut Curl_dns_entry;
                }
            }
        } else if (unsafe { ((*conn).bits).proxy() }) == 0 {
            let mut connhost: Option<&'_ mut crate::src::lib::http2::hostname> =
                Option::<&'_ mut crate::src::lib::http2::hostname>::None;
            if (unsafe { ((*conn).bits).conn_to_host() }) != 0 {
                connhost = Some(unsafe { &mut (*conn).conn_to_host });
            } else {
                connhost = Some(unsafe { &mut (*conn).host });
            }
            if (unsafe { ((*conn).bits).conn_to_port() }) != 0 {
                (unsafe { (*conn).port = (*conn).conn_to_port });
            } else {
                (unsafe { (*conn).port = (*conn).remote_port });
            }
            let mut fresh187 = unsafe { &mut ((*conn).hostname_resolve) };
            *fresh187 = unsafe { Curl_cstrdup.expect("non-null function pointer")(
                (*(borrow(&connhost)).unwrap()).name,
            ) };
            if (unsafe { (*conn).hostname_resolve }).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            rc = Curl_resolv_timeout(
                data,
                unsafe { (*conn).hostname_resolve },
                unsafe { (*conn).port },
                Some(&mut hostaddr),
                timeout_ms,
            ) as i32;
            if rc == CURLRESOLV_PENDING as i32 {
                *(borrow_mut(&mut async_0)).unwrap() = 1 as i32 != 0;
            } else if rc == CURLRESOLV_TIMEDOUT as i32 {
                (unsafe { Curl_failf(
                    data,
                    b"Failed to resolve host '%s' with timeout after %ld ms\0" as *const u8
                        as *const i8,
                    (*(borrow(&connhost)).unwrap()).dispname,
                    Curl_timediff(Curl_now(), (*data).progress.t_startsingle),
                ) });
                result = CURLE_OPERATION_TIMEDOUT;
            } else if hostaddr.is_null() {
                (unsafe { Curl_failf(
                    data,
                    b"Could not resolve host: %s\0" as *const u8 as *const i8,
                    (*(borrow(&connhost)).unwrap()).dispname,
                ) });
                result = CURLE_COULDNT_RESOLVE_HOST;
            }
        } else {
            let host: *mut crate::src::lib::http2::hostname =
                if (unsafe { ((*conn).bits).socksproxy() }) as i32 != 0 {
                    unsafe { &mut (*conn).socks_proxy.host }
                } else {
                    unsafe { &mut (*conn).http_proxy.host }
                };
            let mut fresh188 = unsafe { &mut ((*conn).hostname_resolve) };
            *fresh188 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*host).name) };
            if (unsafe { (*conn).hostname_resolve }).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            rc = Curl_resolv_timeout(
                data,
                unsafe { (*conn).hostname_resolve },
                unsafe { (*conn).port },
                Some(&mut hostaddr),
                timeout_ms,
            ) as i32;
            if rc == CURLRESOLV_PENDING as i32 {
                *(borrow_mut(&mut async_0)).unwrap() = 1 as i32 != 0;
            } else if rc == CURLRESOLV_TIMEDOUT as i32 {
                result = CURLE_OPERATION_TIMEDOUT;
            } else if hostaddr.is_null() {
                (unsafe { Curl_failf(
                    data,
                    b"Couldn't resolve proxy '%s'\0" as *const u8 as *const i8,
                    (*host).dispname,
                ) });
                result = CURLE_COULDNT_RESOLVE_PROXY;
            }
        }
        let mut fresh189 = unsafe { &mut ((*conn).dns_entry) };
        *fresh189 = hostaddr;
    }
    return result;
}
extern "C" fn reuse_conn(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut old_conn: *mut crate::src::lib::http2::connectdata,
    mut conn: *mut crate::src::lib::http2::connectdata,
) {
    let mut local_ip : [i8 ; 46] = * (unsafe { core :: intrinsics :: transmute :: < & '_ [u8 ; 46] , & '_ mut [i8 ; 46] > (b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" ,) }) ;
    let mut local_port: i32 = -(1 as i32);
    Curl_free_idnconverted_hostname(Some(unsafe { &mut (*old_conn).http_proxy.host }));
    Curl_free_idnconverted_hostname(Some(unsafe { &mut (*old_conn).socks_proxy.host }));
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*old_conn).http_proxy.host.rawalloc as *mut libc::c_void,
    ) });
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*old_conn).socks_proxy.host.rawalloc as *mut libc::c_void,
    ) });
    Curl_free_primary_ssl_config(Some(unsafe { &mut (*old_conn).proxy_ssl_config }));
    Curl_free_primary_ssl_config(Some(unsafe { &mut (*old_conn).ssl_config }));
    let mut fresh190 = unsafe { &mut ((*conn).bits) };
    (*fresh190).set_user_passwd(unsafe { ((*old_conn).bits).user_passwd() });
    if (unsafe { ((*conn).bits).user_passwd() }) != 0 {
        (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).user as *mut libc::c_void) });
        let mut fresh191 = unsafe { &mut ((*conn).user) };
        *fresh191 = 0 as *mut i8;
        (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).passwd as *mut libc::c_void) });
        let mut fresh192 = unsafe { &mut ((*conn).passwd) };
        *fresh192 = 0 as *mut i8;
        let mut fresh193 = unsafe { &mut ((*conn).user) };
        *fresh193 = unsafe { (*old_conn).user };
        let mut fresh194 = unsafe { &mut ((*conn).passwd) };
        *fresh194 = unsafe { (*old_conn).passwd };
        let mut fresh195 = unsafe { &mut ((*old_conn).user) };
        *fresh195 = 0 as *mut i8;
        let mut fresh196 = unsafe { &mut ((*old_conn).passwd) };
        *fresh196 = 0 as *mut i8;
    }
    let mut fresh197 = unsafe { &mut ((*conn).bits) };
    (*fresh197).set_proxy_user_passwd(unsafe { ((*old_conn).bits).proxy_user_passwd() });
    if (unsafe { ((*conn).bits).proxy_user_passwd() }) != 0 {
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            (*conn).http_proxy.user as *mut libc::c_void,
        ) });
        let mut fresh198 = unsafe { &mut ((*conn).http_proxy.user) };
        *fresh198 = 0 as *mut i8;
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            (*conn).socks_proxy.user as *mut libc::c_void,
        ) });
        let mut fresh199 = unsafe { &mut ((*conn).socks_proxy.user) };
        *fresh199 = 0 as *mut i8;
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            (*conn).http_proxy.passwd as *mut libc::c_void,
        ) });
        let mut fresh200 = unsafe { &mut ((*conn).http_proxy.passwd) };
        *fresh200 = 0 as *mut i8;
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            (*conn).socks_proxy.passwd as *mut libc::c_void,
        ) });
        let mut fresh201 = unsafe { &mut ((*conn).socks_proxy.passwd) };
        *fresh201 = 0 as *mut i8;
        let mut fresh202 = unsafe { &mut ((*conn).http_proxy.user) };
        *fresh202 = unsafe { (*old_conn).http_proxy.user };
        let mut fresh203 = unsafe { &mut ((*conn).socks_proxy.user) };
        *fresh203 = unsafe { (*old_conn).socks_proxy.user };
        let mut fresh204 = unsafe { &mut ((*conn).http_proxy.passwd) };
        *fresh204 = unsafe { (*old_conn).http_proxy.passwd };
        let mut fresh205 = unsafe { &mut ((*conn).socks_proxy.passwd) };
        *fresh205 = unsafe { (*old_conn).socks_proxy.passwd };
        let mut fresh206 = unsafe { &mut ((*old_conn).http_proxy.user) };
        *fresh206 = 0 as *mut i8;
        let mut fresh207 = unsafe { &mut ((*old_conn).socks_proxy.user) };
        *fresh207 = 0 as *mut i8;
        let mut fresh208 = unsafe { &mut ((*old_conn).http_proxy.passwd) };
        *fresh208 = 0 as *mut i8;
        let mut fresh209 = unsafe { &mut ((*old_conn).socks_proxy.passwd) };
        *fresh209 = 0 as *mut i8;
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*old_conn).http_proxy.user as *mut libc::c_void,
    ) });
    let mut fresh210 = unsafe { &mut ((*old_conn).http_proxy.user) };
    *fresh210 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*old_conn).socks_proxy.user as *mut libc::c_void,
    ) });
    let mut fresh211 = unsafe { &mut ((*old_conn).socks_proxy.user) };
    *fresh211 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*old_conn).http_proxy.passwd as *mut libc::c_void,
    ) });
    let mut fresh212 = unsafe { &mut ((*old_conn).http_proxy.passwd) };
    *fresh212 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*old_conn).socks_proxy.passwd as *mut libc::c_void,
    ) });
    let mut fresh213 = unsafe { &mut ((*old_conn).socks_proxy.passwd) };
    *fresh213 = 0 as *mut i8;
    Curl_free_idnconverted_hostname(Some(unsafe { &mut (*conn).host }));
    Curl_free_idnconverted_hostname(Some(unsafe { &mut (*conn).conn_to_host }));
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).host.rawalloc as *mut libc::c_void) });
    let mut fresh214 = unsafe { &mut ((*conn).host.rawalloc) };
    *fresh214 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*conn).conn_to_host.rawalloc as *mut libc::c_void,
    ) });
    let mut fresh215 = unsafe { &mut ((*conn).conn_to_host.rawalloc) };
    *fresh215 = 0 as *mut i8;
    (unsafe { (*conn).host = (*old_conn).host });
    (unsafe { (*conn).conn_to_host = (*old_conn).conn_to_host });
    (unsafe { (*conn).conn_to_port = (*old_conn).conn_to_port });
    (unsafe { (*conn).remote_port = (*old_conn).remote_port });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*conn).hostname_resolve as *mut libc::c_void) });
    let mut fresh216 = unsafe { &mut ((*conn).hostname_resolve) };
    *fresh216 = 0 as *mut i8;
    let mut fresh217 = unsafe { &mut ((*conn).hostname_resolve) };
    *fresh217 = unsafe { (*old_conn).hostname_resolve };
    let mut fresh218 = unsafe { &mut ((*old_conn).hostname_resolve) };
    *fresh218 = 0 as *mut i8;
    if (unsafe { (*conn).transport }) as u32 == TRNSPRT_TCP as i32 as u32 {
        Curl_conninfo_local(
            data,
            unsafe { (*conn).sock[0 as i32 as usize] },
            local_ip.as_mut_ptr(),
            Some(&mut local_port),
        );
    }
    Curl_persistconninfo(data, conn, local_ip.as_mut_ptr(), local_port);
    let mut fresh219 = unsafe { &mut ((*conn).bits) };
    (*fresh219).set_reuse(1 as i32 as bit);
    (unsafe { Curl_cfree.expect("non-null function pointer")((*old_conn).user as *mut libc::c_void) });
    let mut fresh220 = unsafe { &mut ((*old_conn).user) };
    *fresh220 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*old_conn).passwd as *mut libc::c_void) });
    let mut fresh221 = unsafe { &mut ((*old_conn).passwd) };
    *fresh221 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*old_conn).options as *mut libc::c_void) });
    let mut fresh222 = unsafe { &mut ((*old_conn).options) };
    *fresh222 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*old_conn).localdev as *mut libc::c_void) });
    let mut fresh223 = unsafe { &mut ((*old_conn).localdev) };
    *fresh223 = 0 as *mut i8;
    Curl_llist_destroy(unsafe { &mut (*old_conn).easyq }, 0 as *mut libc::c_void);
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*old_conn).unix_domain_socket as *mut libc::c_void,
    ) });
    let mut fresh224 = unsafe { &mut ((*old_conn).unix_domain_socket) };
    *fresh224 = 0 as *mut i8;
}
extern "C" fn create_conn<'a1, 'a2>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut in_connect: Option<&'a1 mut *mut crate::src::lib::http2::connectdata>,
    mut async_0: Option<&'a2 mut bool>,
) -> u32 {
    let mut current_block: u64;
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = 0 as *mut connectdata;
    let mut conn_temp: *mut crate::src::lib::http2::connectdata = 0 as *mut connectdata;
    let mut reuse: bool = false;
    let mut connections_available: bool = 1 as i32 != 0;
    let mut force_reuse: bool = 0 as i32 != 0;
    let mut waitpipe: bool = 0 as i32 != 0;
    let mut max_host_connections: u64 = Curl_multi_max_host_connections(unsafe { (*data).multi });
    let mut max_total_connections: u64 = Curl_multi_max_total_connections(unsafe { (*data).multi });
    *(borrow_mut(&mut async_0)).unwrap() = 0 as i32 != 0;
    *(borrow_mut(&mut in_connect)).unwrap() = 0 as *mut connectdata;
    if (unsafe { (*data).state.url }).is_null() {
        result = CURLE_URL_MALFORMAT;
    } else {
        conn = allocate_conn(data);
        if conn.is_null() {
            result = CURLE_OUT_OF_MEMORY;
        } else {
            *(borrow_mut(&mut in_connect)).unwrap() = conn;
            result = parseurlandfillconn(data, conn);
            if !(result as u64 != 0) {
                if !(unsafe { (*data).set.str_0[STRING_SASL_AUTHZID as i32 as usize] }).is_null() {
                    let mut fresh225 = unsafe { &mut ((*conn).sasl_authzid) };
                    *fresh225 = unsafe { Curl_cstrdup.expect("non-null function pointer")(
                        (*data).set.str_0[STRING_SASL_AUTHZID as i32 as usize],
                    ) };
                    if (unsafe { (*conn).sasl_authzid }).is_null() {
                        result = CURLE_OUT_OF_MEMORY;
                        current_block = 4631372686411729056;
                    } else {
                        current_block = 11584701595673473500;
                    }
                } else {
                    current_block = 11584701595673473500;
                }
                match current_block {
                    4631372686411729056 => {}
                    _ => {
                        if !(unsafe { (*data).set.str_0[STRING_UNIX_SOCKET_PATH as i32 as usize] }).is_null() {
                            let mut fresh226 = unsafe { &mut ((*conn).unix_domain_socket) };
                            *fresh226 = unsafe { Curl_cstrdup.expect("non-null function pointer")(
                                (*data).set.str_0[STRING_UNIX_SOCKET_PATH as i32 as usize],
                            ) };
                            if (unsafe { (*conn).unix_domain_socket }).is_null() {
                                result = CURLE_OUT_OF_MEMORY;
                                current_block = 4631372686411729056;
                            } else {
                                let mut fresh227 = unsafe { &mut ((*conn).bits) };
                                (*fresh227)
                                    .set_abstract_unix_socket(unsafe { ((*data).set).abstract_unix_socket() });
                                current_block = 4068382217303356765;
                            }
                        } else {
                            current_block = 4068382217303356765;
                        }
                        match current_block {
                            4631372686411729056 => {}
                            _ => {
                                result = create_conn_helper_init_proxy(data, conn);
                                if !(result as u64 != 0) {
                                    if (unsafe { (*(*conn).given).flags }) & ((1 as i32) << 0 as i32) as u32 != 0
                                        && (unsafe { ((*conn).bits).httpproxy() }) as i32 != 0
                                    {
                                        let mut fresh228 = unsafe { &mut ((*conn).bits) };
                                        (*fresh228).set_tunnel_proxy(1 as i32 as bit);
                                    }
                                    result = parse_remote_port(data, conn);
                                    if !(result as u64 != 0) {
                                        result = override_login(data, conn);
                                        if !(result as u64 != 0) {
                                            result = set_login(conn);
                                            if !(result as u64 != 0) {
                                                result = parse_connect_to_slist(
                                                    data,
                                                    conn,
                                                    unsafe { (*data).set.connect_to },
                                                );
                                                if !(result as u64 != 0) {
                                                    result = Curl_idnconvert_hostname(
                                                        data,
                                                        unsafe { &mut (*conn).host },
                                                    );
                                                    if !(result as u64 != 0) {
                                                        if (unsafe { ((*conn).bits).conn_to_host() }) != 0 {
                                                            result = Curl_idnconvert_hostname(
                                                                data,
                                                                unsafe { &mut (*conn).conn_to_host },
                                                            );
                                                            if result as u64 != 0 {
                                                                current_block = 4631372686411729056;
                                                            } else {
                                                                current_block = 721385680381463314;
                                                            }
                                                        } else {
                                                            current_block = 721385680381463314;
                                                        }
                                                        match current_block {
                                                            4631372686411729056 => {}
                                                            _ => {
                                                                if (unsafe { ((*conn).bits).httpproxy() }) != 0 {
                                                                    result =
                                                                        Curl_idnconvert_hostname(
                                                                            data,
                                                                            unsafe { &mut (*conn)
                                                                                .http_proxy
                                                                                .host },
                                                                        );
                                                                    if result as u64 != 0 {
                                                                        current_block =
                                                                            4631372686411729056;
                                                                    } else {
                                                                        current_block =
                                                                            14775119014532381840;
                                                                    }
                                                                } else {
                                                                    current_block =
                                                                        14775119014532381840;
                                                                }
                                                                match current_block {
                                                                    4631372686411729056 => {}
                                                                    _ => {
                                                                        if (unsafe { ((*conn).bits)
                                                                            .socksproxy() })
                                                                            != 0
                                                                        {
                                                                            result = Curl_idnconvert_hostname (data , unsafe { & mut (* conn) . socks_proxy . host } ,) ;
                                                                            if result as u64 != 0 {
                                                                                current_block = 4631372686411729056 ;
                                                                            } else {
                                                                                current_block = 5141539773904409130 ;
                                                                            }
                                                                        } else {
                                                                            current_block =
                                                                                5141539773904409130;
                                                                        }
                                                                        match current_block {
                                                                            4631372686411729056 => {
                                                                            }
                                                                            _ => {
                                                                                if (unsafe { ((* conn) . bits) . conn_to_host () }) as i32 != 0 && Curl_strcasecompare (unsafe { (* conn) . conn_to_host . name } , unsafe { (* conn) . host . name } ,) != 0 { let mut fresh229 = unsafe { & mut ((* conn) . bits) } ; (* fresh229) . set_conn_to_host (0 as i32 as bit) ; }
                                                                                if (unsafe { ((* conn) . bits) . conn_to_port () }) as i32 != 0 && (unsafe { (* conn) . conn_to_port }) == (unsafe { (* conn) . remote_port }) { let mut fresh230 = unsafe { & mut ((* conn) . bits) } ; (* fresh230) . set_conn_to_port (0 as i32 as bit) ; }
                                                                                if ((unsafe { ((* conn) . bits) . conn_to_host () }) as i32 != 0 || (unsafe { ((* conn) . bits) . conn_to_port () }) as i32 != 0) && (unsafe { ((* conn) . bits) . httpproxy () }) as i32 != 0 { let mut fresh231 = unsafe { & mut ((* conn) . bits) } ; (* fresh231) . set_tunnel_proxy (1 as i32 as bit) ; }
                                                                                result = setup_connection_internals (data , conn) ;
                                                                                if !(result as u64
                                                                                    != 0)
                                                                                {
                                                                                    let mut fresh232 = unsafe { & mut ((* conn) . recv [0 as i32 as usize]) } ;
                                                                                    * fresh232 = Some (Curl_recv_plain ,) ;
                                                                                    let mut fresh233 = unsafe { & mut ((* conn) . send [0 as i32 as usize]) } ;
                                                                                    * fresh233 = Some (Curl_send_plain ,) ;
                                                                                    let mut fresh234 = unsafe { & mut ((* conn) . recv [1 as i32 as usize]) } ;
                                                                                    * fresh234 = Some (Curl_recv_plain ,) ;
                                                                                    let mut fresh235 = unsafe { & mut ((* conn) . send [1 as i32 as usize]) } ;
                                                                                    * fresh235 = Some (Curl_send_plain ,) ;
                                                                                    let mut fresh236 = unsafe { & mut ((* conn) . bits) } ;
                                                                                    (* fresh236) . set_tcp_fastopen (unsafe { ((* data) . set) . tcp_fastopen () }) ;
                                                                                    if (unsafe { (* (* conn) . handler) . flags }) & ((1 as i32) << 4 as i32) as u32 != 0 { let mut done : bool = false ; Curl_persistconninfo (data , conn , 0 as * mut i8 , - (1 as i32) ,) ; result = unsafe { ((* (* conn) . handler) . connect_it) . expect ("non-null function pointer") (data , & mut done) } ; if result as u64 == 0 { (unsafe { (* conn) . bits . tcpconnect [0 as i32 as usize] = 1 as i32 != 0 }) ; Curl_attach_connnection (data , conn) ; result = Curl_conncache_add_conn (data) ; if result as u64 != 0 { current_block = 4631372686411729056 ; } else { result = setup_range (data) ; if result as u64 != 0 { (unsafe { ((* (* conn) . handler) . done) . expect ("non-null function pointer" ,) (data , result , 0 as i32 != 0) }) ; current_block = 4631372686411729056 ; } else { Curl_setup_transfer (data , - (1 as i32) , - (1 as i32) as curl_off_t , 0 as i32 != 0 , - (1 as i32) ,) ; current_block = 17019156190352891614 ; } } } else { current_block = 17019156190352891614 ; } match current_block { 4631372686411729056 => { } _ => { Curl_init_do (data , conn) ; } } } else { let mut fresh237 = unsafe { & mut ((* data) . set . ssl . primary . CApath) } ; * fresh237 = unsafe { (* data) . set . str_0 [STRING_SSL_CAPATH as i32 as usize] } ; let mut fresh238 = unsafe { & mut ((* data) . set . ssl . primary . CAfile) } ; * fresh238 = unsafe { (* data) . set . str_0 [STRING_SSL_CAFILE as i32 as usize] } ; let mut fresh239 = unsafe { & mut ((* data) . set . ssl . primary . issuercert) } ; * fresh239 = unsafe { (* data) . set . str_0 [STRING_SSL_ISSUERCERT as i32 as usize] } ; let mut fresh240 = unsafe { & mut ((* data) . set . ssl . primary . issuercert_blob) } ; * fresh240 = unsafe { (* data) . set . blobs [BLOB_SSL_ISSUERCERT as i32 as usize] } ; let mut fresh241 = unsafe { & mut ((* data) . set . ssl . primary . random_file) } ; * fresh241 = unsafe { (* data) . set . str_0 [STRING_SSL_RANDOM_FILE as i32 as usize] } ; let mut fresh242 = unsafe { & mut ((* data) . set . ssl . primary . egdsocket) } ; * fresh242 = unsafe { (* data) . set . str_0 [STRING_SSL_EGDSOCKET as i32 as usize] } ; let mut fresh243 = unsafe { & mut ((* data) . set . ssl . primary . cipher_list) } ; * fresh243 = unsafe { (* data) . set . str_0 [STRING_SSL_CIPHER_LIST as i32 as usize] } ; let mut fresh244 = unsafe { & mut ((* data) . set . ssl . primary . cipher_list13) } ; * fresh244 = unsafe { (* data) . set . str_0 [STRING_SSL_CIPHER13_LIST as i32 as usize] } ; let mut fresh245 = unsafe { & mut ((* data) . set . ssl . primary . pinned_key) } ; * fresh245 = unsafe { (* data) . set . str_0 [STRING_SSL_PINNEDPUBLICKEY as i32 as usize] } ; let mut fresh246 = unsafe { & mut ((* data) . set . ssl . primary . cert_blob) } ; * fresh246 = unsafe { (* data) . set . blobs [BLOB_CERT as i32 as usize] } ; let mut fresh247 = unsafe { & mut ((* data) . set . ssl . primary . ca_info_blob) } ; * fresh247 = unsafe { (* data) . set . blobs [BLOB_CAINFO as i32 as usize] } ; let mut fresh248 = unsafe { & mut ((* data) . set . ssl . primary . curves) } ; * fresh248 = unsafe { (* data) . set . str_0 [STRING_SSL_EC_CURVES as i32 as usize] } ; let mut fresh249 = unsafe { & mut ((* data) . set . proxy_ssl . primary . CApath) } ; * fresh249 = unsafe { (* data) . set . str_0 [STRING_SSL_CAPATH_PROXY as i32 as usize] } ; let mut fresh250 = unsafe { & mut ((* data) . set . proxy_ssl . primary . CAfile) } ; * fresh250 = unsafe { (* data) . set . str_0 [STRING_SSL_CAFILE_PROXY as i32 as usize] } ; let mut fresh251 = unsafe { & mut ((* data) . set . proxy_ssl . primary . random_file) } ; * fresh251 = unsafe { (* data) . set . str_0 [STRING_SSL_RANDOM_FILE as i32 as usize] } ; let mut fresh252 = unsafe { & mut ((* data) . set . proxy_ssl . primary . egdsocket) } ; * fresh252 = unsafe { (* data) . set . str_0 [STRING_SSL_EGDSOCKET as i32 as usize] } ; let mut fresh253 = unsafe { & mut ((* data) . set . proxy_ssl . primary . cipher_list) } ; * fresh253 = unsafe { (* data) . set . str_0 [STRING_SSL_CIPHER_LIST_PROXY as i32 as usize] } ; let mut fresh254 = unsafe { & mut ((* data) . set . proxy_ssl . primary . cipher_list13) } ; * fresh254 = unsafe { (* data) . set . str_0 [STRING_SSL_CIPHER13_LIST_PROXY as i32 as usize] } ; let mut fresh255 = unsafe { & mut ((* data) . set . proxy_ssl . primary . pinned_key) } ; * fresh255 = unsafe { (* data) . set . str_0 [STRING_SSL_PINNEDPUBLICKEY_PROXY as i32 as usize] } ; let mut fresh256 = unsafe { & mut ((* data) . set . proxy_ssl . primary . cert_blob) } ; * fresh256 = unsafe { (* data) . set . blobs [BLOB_CERT_PROXY as i32 as usize] } ; let mut fresh257 = unsafe { & mut ((* data) . set . proxy_ssl . primary . ca_info_blob) } ; * fresh257 = unsafe { (* data) . set . blobs [BLOB_CAINFO_PROXY as i32 as usize] } ; let mut fresh258 = unsafe { & mut ((* data) . set . proxy_ssl . primary . issuercert) } ; * fresh258 = unsafe { (* data) . set . str_0 [STRING_SSL_ISSUERCERT_PROXY as i32 as usize] } ; let mut fresh259 = unsafe { & mut ((* data) . set . proxy_ssl . primary . issuercert_blob) } ; * fresh259 = unsafe { (* data) . set . blobs [BLOB_SSL_ISSUERCERT_PROXY as i32 as usize] } ; let mut fresh260 = unsafe { & mut ((* data) . set . proxy_ssl . CRLfile) } ; * fresh260 = unsafe { (* data) . set . str_0 [STRING_SSL_CRLFILE_PROXY as i32 as usize] } ; let mut fresh261 = unsafe { & mut ((* data) . set . proxy_ssl . cert_type) } ; * fresh261 = unsafe { (* data) . set . str_0 [STRING_CERT_TYPE_PROXY as i32 as usize] } ; let mut fresh262 = unsafe { & mut ((* data) . set . proxy_ssl . key) } ; * fresh262 = unsafe { (* data) . set . str_0 [STRING_KEY_PROXY as i32 as usize] } ; let mut fresh263 = unsafe { & mut ((* data) . set . proxy_ssl . key_type) } ; * fresh263 = unsafe { (* data) . set . str_0 [STRING_KEY_TYPE_PROXY as i32 as usize] } ; let mut fresh264 = unsafe { & mut ((* data) . set . proxy_ssl . key_passwd) } ; * fresh264 = unsafe { (* data) . set . str_0 [STRING_KEY_PASSWD_PROXY as i32 as usize] } ; let mut fresh265 = unsafe { & mut ((* data) . set . proxy_ssl . primary . clientcert) } ; * fresh265 = unsafe { (* data) . set . str_0 [STRING_CERT_PROXY as i32 as usize] } ; let mut fresh266 = unsafe { & mut ((* data) . set . proxy_ssl . key_blob) } ; * fresh266 = unsafe { (* data) . set . blobs [BLOB_KEY_PROXY as i32 as usize] } ; let mut fresh267 = unsafe { & mut ((* data) . set . ssl . CRLfile) } ; * fresh267 = unsafe { (* data) . set . str_0 [STRING_SSL_CRLFILE as i32 as usize] } ; let mut fresh268 = unsafe { & mut ((* data) . set . ssl . cert_type) } ; * fresh268 = unsafe { (* data) . set . str_0 [STRING_CERT_TYPE as i32 as usize] } ; let mut fresh269 = unsafe { & mut ((* data) . set . ssl . key) } ; * fresh269 = unsafe { (* data) . set . str_0 [STRING_KEY as i32 as usize] } ; let mut fresh270 = unsafe { & mut ((* data) . set . ssl . key_type) } ; * fresh270 = unsafe { (* data) . set . str_0 [STRING_KEY_TYPE as i32 as usize] } ; let mut fresh271 = unsafe { & mut ((* data) . set . ssl . key_passwd) } ; * fresh271 = unsafe { (* data) . set . str_0 [STRING_KEY_PASSWD as i32 as usize] } ; let mut fresh272 = unsafe { & mut ((* data) . set . ssl . primary . clientcert) } ; * fresh272 = unsafe { (* data) . set . str_0 [STRING_CERT as i32 as usize] } ; let mut fresh273 = unsafe { & mut ((* data) . set . ssl . username) } ; * fresh273 = unsafe { (* data) . set . str_0 [STRING_TLSAUTH_USERNAME as i32 as usize] } ; let mut fresh274 = unsafe { & mut ((* data) . set . ssl . password) } ; * fresh274 = unsafe { (* data) . set . str_0 [STRING_TLSAUTH_PASSWORD as i32 as usize] } ; let mut fresh275 = unsafe { & mut ((* data) . set . proxy_ssl . username) } ; * fresh275 = unsafe { (* data) . set . str_0 [STRING_TLSAUTH_USERNAME_PROXY as i32 as usize] } ; let mut fresh276 = unsafe { & mut ((* data) . set . proxy_ssl . password) } ; * fresh276 = unsafe { (* data) . set . str_0 [STRING_TLSAUTH_PASSWORD_PROXY as i32 as usize] } ; let mut fresh277 = unsafe { & mut ((* data) . set . ssl . key_blob) } ; * fresh277 = unsafe { (* data) . set . blobs [BLOB_KEY as i32 as usize] } ; if ! Curl_clone_primary_ssl_config (unsafe { & mut (* data) . set . ssl . primary } , Some (unsafe { & mut (* conn) . ssl_config }) ,) { result = CURLE_OUT_OF_MEMORY ; } else if ! Curl_clone_primary_ssl_config (unsafe { & mut (* data) . set . proxy_ssl . primary } , Some (unsafe { & mut (* conn) . proxy_ssl_config }) ,) { result = CURLE_OUT_OF_MEMORY ; } else { prune_dead_connections (data) ; if (unsafe { ((* data) . set) . reuse_fresh () }) as i32 != 0 && (unsafe { ((* data) . state) . this_is_a_follow () }) == 0 || (unsafe { ((* data) . set) . connect_only () }) as i32 != 0 { reuse = 0 as i32 != 0 ; } else { reuse = ConnectionExists (data , conn , Some (& mut conn_temp) , Some (& mut force_reuse) , Some (& mut waitpipe) ,) ; } if reuse { reuse_conn (data , conn , conn_temp) ; (unsafe { Curl_cfree . expect ("non-null function pointer") ((* conn) . ssl_extra) }) ; (unsafe { Curl_cfree . expect ("non-null function pointer" ,) (conn as * mut libc :: c_void) }) ; conn = conn_temp ; * (borrow_mut (& mut in_connect)) . unwrap () = conn ; (unsafe { Curl_infof (data , b"Re-using existing connection! (#%ld) with %s %s\0" as * const u8 as * const i8 , (* conn) . connection_id , if ((* conn) . bits) . proxy () as i32 != 0 { b"proxy\0" as * const u8 as * const i8 } else { b"host\0" as * const u8 as * const i8 } , if ! ((* conn) . socks_proxy . host . name) . is_null () { (* conn) . socks_proxy . host . dispname } else if ! ((* conn) . http_proxy . host . name) . is_null () { (* conn) . http_proxy . host . dispname } else { (* conn) . host . dispname } ,) }) ; current_block = 2182835884935087477 ; } else { if (unsafe { (* (* conn) . handler) . flags }) & ((1 as i32) << 8 as i32) as u32 != 0 { if (unsafe { ((* data) . set) . ssl_enable_alpn () }) != 0 { let mut fresh278 = unsafe { & mut ((* conn) . bits) } ; (* fresh278) . set_tls_enable_alpn (1 as i32 as bit) ; } if (unsafe { ((* data) . set) . ssl_enable_npn () }) != 0 { let mut fresh279 = unsafe { & mut ((* conn) . bits) } ; (* fresh279) . set_tls_enable_npn (1 as i32 as bit) ; } } if waitpipe { connections_available = 0 as i32 != 0 ; } else { let mut bundlehost : * const i8 = 0 as * const i8 ; let mut bundle : * mut crate :: src :: lib :: http2 :: connectbundle = Curl_conncache_find_bundle (data , conn , unsafe { (* data) . state . conn_cache } , Some (& mut bundlehost) ,) ; if max_host_connections > 0 as i32 as u64 && ! bundle . is_null () && (unsafe { (* bundle) . num_connections }) >= max_host_connections { let mut conn_candidate : * mut crate :: src :: lib :: http2 :: connectdata = 0 as * mut connectdata ; conn_candidate = Curl_conncache_extract_bundle (data , bundle ,) ; if ! (unsafe { (* data) . share }) . is_null () { Curl_share_unlock (data , CURL_LOCK_DATA_CONNECT) ; } if ! conn_candidate . is_null () { Curl_disconnect (data , conn_candidate , 0 as i32 != 0 ,) ; } else { (unsafe { Curl_infof (data , b"No more connections allowed to host %s: %zu\0" as * const u8 as * const i8 , bundlehost , max_host_connections ,) }) ; connections_available = 0 as i32 != 0 ; } } else if ! (unsafe { (* data) . share }) . is_null () { Curl_share_unlock (data , CURL_LOCK_DATA_CONNECT) ; } } if connections_available as i32 != 0 && max_total_connections > 0 as i32 as u64 && Curl_conncache_size (data) >= max_total_connections { let mut conn_candidate_0 : * mut crate :: src :: lib :: http2 :: connectdata = 0 as * mut connectdata ; conn_candidate_0 = Curl_conncache_extract_oldest (data) ; if ! conn_candidate_0 . is_null () { Curl_disconnect (data , conn_candidate_0 , 0 as i32 != 0 ,) ; } else { (unsafe { Curl_infof (data , b"No connections available in cache\0" as * const u8 as * const i8 ,) }) ; connections_available = 0 as i32 != 0 ; } } if ! connections_available { (unsafe { Curl_infof (data , b"No connections available.\0" as * const u8 as * const i8 ,) }) ; conn_free (conn) ; * (borrow_mut (& mut in_connect)) . unwrap () = 0 as * mut connectdata ; result = CURLE_NO_CONNECTION_AVAILABLE ; current_block = 4631372686411729056 ; } else { Curl_attach_connnection (data , conn) ; result = Curl_conncache_add_conn (data) ; if result as u64 != 0 { current_block = 4631372686411729056 ; } else { if (unsafe { (* data) . state . authhost . picked }) & ((1 as i32 as u64) << 3 as i32 | (1 as i32 as u64) << 5 as i32) != 0 && (unsafe { ((* data) . state . authhost) . done () }) as i32 != 0 { (unsafe { Curl_infof (data , b"NTLM picked AND auth done set, clear picked!\0" as * const u8 as * const i8 ,) }) ; (unsafe { (* data) . state . authhost . picked = 0 as i32 as u64 }) ; let mut fresh280 = unsafe { & mut ((* data) . state . authhost) } ; (* fresh280) . set_done (0 as i32 as bit) ; } if (unsafe { (* data) . state . authproxy . picked }) & ((1 as i32 as u64) << 3 as i32 | (1 as i32 as u64) << 5 as i32) != 0 && (unsafe { ((* data) . state . authproxy) . done () }) as i32 != 0 { (unsafe { Curl_infof (data , b"NTLM-proxy picked AND auth done set, clear picked!\0" as * const u8 as * const i8 ,) }) ; (unsafe { (* data) . state . authproxy . picked = 0 as i32 as u64 }) ; let mut fresh281 = unsafe { & mut ((* data) . state . authproxy) } ; (* fresh281) . set_done (0 as i32 as bit) ; } current_block = 2182835884935087477 ; } } } match current_block { 4631372686411729056 => { } _ => { Curl_init_do (data , conn) ; result = setup_range (data) ; if ! (result as u64 != 0) { let mut fresh282 = unsafe { & mut ((* conn) . seek_func) } ; * fresh282 = unsafe { (* data) . set . seek_func } ; let mut fresh283 = unsafe { & mut ((* conn) . seek_client) } ; * fresh283 = unsafe { (* data) . set . seek_client } ; result = resolve_server (data , conn , borrow_mut (& mut async_0)) ; strip_trailing_dot (Some (unsafe { & mut (* conn) . host })) ; if (unsafe { ((* conn) . bits) . httpproxy () }) != 0 { strip_trailing_dot (Some (unsafe { & mut (* conn) . http_proxy . host })) ; } if (unsafe { ((* conn) . bits) . socksproxy () }) != 0 { strip_trailing_dot (Some (unsafe { & mut (* conn) . socks_proxy . host })) ; } if (unsafe { ((* conn) . bits) . conn_to_host () }) != 0 { strip_trailing_dot (Some (unsafe { & mut (* conn) . conn_to_host })) ; } } } } } }
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
            }
        }
    }
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_setup_conn<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut protocol_done: Option<&'a1 mut bool>,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    Curl_pgrsTime(data, TIMER_NAMELOOKUP);
    if (unsafe { (*(*conn).handler).flags }) & ((1 as i32) << 4 as i32) as u32 != 0 {
        *(borrow_mut(&mut protocol_done)).unwrap() = 1 as i32 != 0;
        return result;
    }
    *(borrow_mut(&mut protocol_done)).unwrap() = 0 as i32 != 0;
    let mut fresh284 = unsafe { &mut ((*conn).bits) };
    (*fresh284).set_proxy_connect_closed(0 as i32 as bit);
    (unsafe { (*data).state.crlf_conversions = 0 as i32 as curl_off_t });
    (unsafe { (*conn).now = Curl_now() });
    if -(1 as i32) == (unsafe { (*conn).sock[0 as i32 as usize] }) {
        (unsafe { (*conn).bits.tcpconnect[0 as i32 as usize] = 0 as i32 != 0 });
        result = Curl_connecthost(data, conn, unsafe { (*conn).dns_entry });
        if result as u64 != 0 {
            return result;
        }
    } else {
        Curl_pgrsTime(data, TIMER_CONNECT);
        if (unsafe { ((*conn).ssl[0 as i32 as usize]).use_0() }) as i32 != 0
            || (unsafe { (*(*conn).handler).protocol })
                & ((1 as i32) << 4 as i32 | (1 as i32) << 5 as i32) as u32
                != 0
        {
            Curl_pgrsTime(data, TIMER_APPCONNECT);
        }
        (unsafe { (*conn).bits.tcpconnect[0 as i32 as usize] = 1 as i32 != 0 });
        *(borrow_mut(&mut protocol_done)).unwrap() = 1 as i32 != 0;
        Curl_updateconninfo(data, conn, unsafe { (*conn).sock[0 as i32 as usize] });
        Curl_verboseconnect(data, conn);
    }
    (unsafe { (*conn).now = Curl_now() });
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_connect<'a1, 'a2>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut asyncp: Option<&'a1 mut bool>,
    mut protocol_done: Option<&'a2 mut bool>,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: *mut crate::src::lib::http2::connectdata = 0 as *mut connectdata;
    *(borrow_mut(&mut asyncp)).unwrap() = 0 as i32 != 0;
    Curl_free_request_state(data);
    (unsafe { memset(
        &mut (*data).req as *mut SingleRequest as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<SingleRequest>() as u64,
    ) });
    (unsafe { (*data).req.maxdownload = -(1 as i32) as curl_off_t });
    result = create_conn(data, Some(&mut conn), borrow_mut(&mut asyncp));
    if result as u64 == 0 {
        if (unsafe { (*conn).easyq.size }) > 1 as i32 as u64 {
            *(borrow_mut(&mut protocol_done)).unwrap() = 1 as i32 != 0;
        } else if !*(borrow(&asyncp)).unwrap() {
            result = Curl_setup_conn(data, borrow_mut(&mut protocol_done));
        }
    }
    if result as u32 == CURLE_NO_CONNECTION_AVAILABLE as i32 as u32 {
        return result;
    } else {
        if result as u32 != 0 && !conn.is_null() {
            Curl_detach_connnection(data);
            Curl_conncache_remove_conn(data, conn, 1 as i32 != 0);
            Curl_disconnect(data, conn, 1 as i32 != 0);
        }
    }
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_init_do(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut k: Option<&'_ mut crate::src::lib::http2::SingleRequest> = Some(unsafe { &mut (*data).req });
    let mut result: u32 = Curl_preconnect(data);
    if result as u64 != 0 {
        return result;
    }
    if !conn.is_null() {
        let mut fresh285 = unsafe { &mut ((*conn).bits) };
        (*fresh285).set_do_more(0 as i32 as bit);
        if (unsafe { ((*data).state).wildcardmatch() }) as i32 != 0
            && (unsafe { (*(*conn).handler).flags }) & ((1 as i32) << 12 as i32) as u32 == 0
        {
            let mut fresh286 = unsafe { &mut ((*data).state) };
            (*fresh286).set_wildcardmatch(0 as i32 as bit);
        }
    }
    let mut fresh287 = unsafe { &mut ((*data).state) };
    (*fresh287).set_done(0 as i32 as bit);
    let mut fresh288 = unsafe { &mut ((*data).state) };
    (*fresh288).set_expect100header(0 as i32 as bit);
    if (unsafe { ((*data).set).opt_no_body() }) != 0 {
        (unsafe { (*data).state.httpreq = HTTPREQ_HEAD });
    }
    (*(borrow_mut(&mut k)).unwrap()).start = Curl_now();
    (*(borrow_mut(&mut k)).unwrap()).now = (*(borrow_mut(&mut k)).unwrap()).start;
    (*(borrow_mut(&mut k)).unwrap()).set_header(1 as i32 as bit);
    (*(borrow_mut(&mut k)).unwrap()).bytecount = 0 as i32 as curl_off_t;
    (*(borrow_mut(&mut k)).unwrap()).set_ignorebody(0 as i32 as bit);
    Curl_speedinit(data);
    Curl_pgrsSetUploadCounter(data, 0 as i32 as curl_off_t);
    Curl_pgrsSetDownloadCounter(data, 0 as i32 as curl_off_t);
    return CURLE_OK;
}
use crate::laertes_rt::*;
