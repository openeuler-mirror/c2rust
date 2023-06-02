use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    static mut stdin: *mut FILE;
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    
    
    fn __errno_location() -> *mut i32;
    
    
    
    
    
    
    
    
    
    fn strtol(
        _: *const i8,
        _: *mut *mut i8,
        _: i32,
    ) -> i64;
    fn strtoul(
        _: *const i8,
        _: *mut *mut i8,
        _: i32,
    ) -> u64;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: i32,
        _: u64,
    ) -> *mut libc::c_void;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strncmp(
        _: *const i8,
        _: *const i8,
        _: u64,
    ) -> i32;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn __ctype_tolower_loc() -> *mut *const __int32_t;
    fn fread(
        _: *mut libc::c_void,
        _: u64,
        _: u64,
        _: *mut FILE,
    ) -> u64;
    fn fwrite(
        _: *const libc::c_void,
        _: u64,
        _: u64,
        _: *mut FILE,
    ) -> u64;
    fn if_nametoindex(__ifname: *const i8) -> u32;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    static mut Curl_ssl: *const Curl_ssl;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::altsvc::Curl_alpnid2str;
pub use crate::src::lib::altsvc::Curl_altsvc_cleanup;
pub use crate::src::lib::altsvc::Curl_altsvc_lookup;
pub use crate::src::lib::altsvc::Curl_altsvc_save;
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
pub use crate::src::lib::dynbuf::Curl_dyn_free;
pub use crate::src::lib::dynbuf::Curl_dyn_init;
pub use crate::src::lib::escape::Curl_urldecode;
pub use crate::src::lib::getenv::curl_getenv;
pub use crate::src::lib::getinfo::Curl_initinfo;
pub use crate::src::lib::hostip::Curl_resolv_timeout;
pub use crate::src::lib::hostip::Curl_resolv_unlock;
pub use crate::src::lib::hsts::Curl_hsts;
pub use crate::src::lib::hsts::Curl_hsts_cleanup;
pub use crate::src::lib::hsts::Curl_hsts_save;
pub use crate::src::lib::http2::Curl_http2_cleanup_dependencies;
pub use crate::src::lib::http2::Curl_http2_init_userset;
pub use crate::src::lib::http_digest::Curl_http_auth_cleanup_digest;
pub use crate::src::lib::http_ntlm::Curl_http_auth_cleanup_ntlm;
pub use crate::src::lib::llist::Curl_llist_destroy;
pub use crate::src::lib::llist::Curl_llist_init;
pub use crate::src::lib::mime::Curl_mime_cleanpart;
pub use crate::src::lib::mime::Curl_mime_initpart;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::multi::Curl_attach_connnection;
pub use crate::src::lib::multi::Curl_detach_connnection;
pub use crate::src::lib::multi::Curl_expire_clear;
pub use crate::src::lib::multi::Curl_multi_max_concurrent_streams;
pub use crate::src::lib::multi::Curl_multi_max_host_connections;
pub use crate::src::lib::multi::Curl_multi_max_total_connections;
pub use crate::src::lib::multi::Curl_multiplex_wanted;
pub use crate::src::lib::multi::Curl_preconnect;
pub use crate::src::lib::multi::curl_multi_cleanup;
pub use crate::src::lib::multi::curl_multi_remove_handle;
pub use crate::src::lib::netrc::Curl_parsenetrc;
pub use crate::src::lib::progress::Curl_pgrsSetDownloadCounter;
pub use crate::src::lib::progress::Curl_pgrsSetUploadCounter;
pub use crate::src::lib::progress::Curl_pgrsTime;
pub use crate::src::lib::select::Curl_socket_check;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::sendf::Curl_recv_plain;
pub use crate::src::lib::sendf::Curl_send_plain;
pub use crate::src::lib::setopt::Curl_setstropt;
pub use crate::src::lib::share::Curl_share_lock;
pub use crate::src::lib::share::Curl_share_unlock;
pub use crate::src::lib::slist::curl_slist_free_all;
pub use crate::src::lib::speedcheck::Curl_speedinit;
pub use crate::src::lib::strcase::Curl_safe_strcasecompare;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::strcase::Curl_strncasecompare;
pub use crate::src::lib::strcase::Curl_strntoupper;
pub use crate::src::lib::strerror::Curl_strerror;
pub use crate::src::lib::timeval::Curl_now;
pub use crate::src::lib::timeval::Curl_timediff;
pub use crate::src::lib::transfer::Curl_setup_transfer;
pub use crate::src::lib::urlapi::Curl_is_absolute_url;
pub use crate::src::lib::urlapi::curl_url;
pub use crate::src::lib::urlapi::curl_url_cleanup;
pub use crate::src::lib::urlapi::curl_url_dup;
pub use crate::src::lib::urlapi::curl_url_get;
pub use crate::src::lib::urlapi::curl_url_set;
pub use crate::src::lib::vtls::vtls::Curl_clone_primary_ssl_config;
pub use crate::src::lib::vtls::vtls::Curl_free_primary_ssl_config;
pub use crate::src::lib::vtls::vtls::Curl_ssl_backend;
pub use crate::src::lib::vtls::vtls::Curl_ssl_close;
pub use crate::src::lib::vtls::vtls::Curl_ssl_close_all;
pub use crate::src::lib::vtls::vtls::Curl_ssl_config_matches;
pub use crate::src::lib::vtls::vtls::Curl_ssl_free_certinfo;
pub use crate::src::lib::warnless::curlx_ultous;
pub use crate::src::lib::wildcard::Curl_wildcard_dtor;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::altsvc::Gsasl;
pub use crate::src::lib::dict::Curl_handler_dict;
pub use crate::src::lib::easy::Curl_ccalloc;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_cstrdup;
pub use crate::src::lib::file::Curl_handler_file;
pub use crate::src::lib::ftp::Curl_handler_ftp;
pub use crate::src::lib::ftp::Curl_handler_ftps;
pub use crate::src::lib::gopher::Curl_handler_gopher;
pub use crate::src::lib::gopher::Curl_handler_gophers;
pub use crate::src::lib::hostip6::psl_ctx_st;
pub use crate::src::lib::http::Curl_handler_http;
pub use crate::src::lib::http::Curl_handler_https;
pub use crate::src::lib::imap::Curl_handler_imap;
pub use crate::src::lib::imap::Curl_handler_imaps;
pub use crate::src::lib::imap::_IO_marker;
pub use crate::src::lib::mqtt::Curl_handler_mqtt;
pub use crate::src::lib::openldap::Curl_handler_ldap;
pub use crate::src::lib::openldap::Curl_handler_ldaps;
pub use crate::src::lib::pop3::Curl_handler_pop3;
pub use crate::src::lib::pop3::Curl_handler_pop3s;
pub use crate::src::lib::rtsp::Curl_handler_rtsp;
pub use crate::src::lib::smb::Curl_handler_smb;
pub use crate::src::lib::smb::Curl_handler_smbs;
pub use crate::src::lib::smtp::Curl_handler_smtp;
pub use crate::src::lib::smtp::Curl_handler_smtps;
pub use crate::src::lib::speedcheck::_IO_codecvt;
pub use crate::src::lib::telnet::Curl_handler_telnet;
pub use crate::src::lib::tftp::Curl_handler_tftp;
pub use crate::src::lib::urlapi::Gsasl_session;
pub use crate::src::lib::version::nghttp2_session;
pub use crate::src::lib::vtls::vtls::_IO_wide_data;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
pub type __uint8_t = crate::src::lib::altsvc::__uint8_t;
pub type __int32_t = crate::src::lib::altsvc::__int32_t;
pub type __uint32_t = crate::src::lib::altsvc::__uint32_t;
pub type __off_t = crate::src::lib::altsvc::__off_t;
pub type __off64_t = crate::src::lib::altsvc::__off64_t;
pub type __pid_t = crate::src::lib::altsvc::__pid_t;
pub type __time_t = crate::src::lib::altsvc::__time_t;
pub type __ssize_t = crate::src::lib::altsvc::__ssize_t;
pub type __socklen_t = crate::src::lib::altsvc::__socklen_t;
pub type pid_t = crate::src::lib::altsvc::pid_t;
pub type ssize_t = crate::src::lib::altsvc::ssize_t;
pub type time_t = crate::src::lib::altsvc::time_t;
pub type size_t = crate::src::lib::altsvc::size_t;
pub type int32_t = crate::src::lib::altsvc::int32_t;
pub type socklen_t = crate::src::lib::altsvc::socklen_t;
pub type sa_family_t = crate::src::lib::altsvc::sa_family_t;
// #[derive(Copy, Clone)]

pub type sockaddr = crate::src::lib::altsvc::sockaddr;
pub type curl_socklen_t = crate::src::lib::altsvc::curl_socklen_t;
pub type curl_off_t = crate::src::lib::altsvc::curl_off_t;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::altsvc::_IO_FILE;
pub type _IO_lock_t = crate::src::lib::altsvc::_IO_lock_t;
pub type FILE = crate::src::lib::altsvc::FILE;
// #[derive(Copy, Clone)]

pub type Curl_easy = crate::src::lib::altsvc::Curl_easy;
// #[derive(Copy, Clone)]

pub type curl_tlssessioninfo = crate::src::lib::altsvc::curl_tlssessioninfo;
pub type curl_sslbackend = crate::src::lib::altsvc::curl_sslbackend;
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

pub type PureInfo = crate::src::lib::altsvc::PureInfo;
pub type bit = crate::src::lib::altsvc::bit;
pub type CURLproxycode = crate::src::lib::altsvc::CURLproxycode;
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

pub type curl_certinfo = crate::src::lib::altsvc::curl_certinfo;
// #[derive(Copy, Clone)]

pub type curl_slist = crate::src::lib::altsvc::curl_slist;
// #[derive(Copy, Clone)]

pub type WildcardData = crate::src::lib::altsvc::WildcardData;
pub type wildcard_dtor = crate::src::lib::altsvc::wildcard_dtor;
// #[derive(Copy, Clone)]

pub type Curl_llist = crate::src::lib::altsvc::Curl_llist;
pub type Curl_llist_dtor = crate::src::lib::altsvc::Curl_llist_dtor;
// #[derive(Copy, Clone)]

pub type Curl_llist_element = crate::src::lib::altsvc::Curl_llist_element;
pub type wildcard_states = crate::src::lib::altsvc::wildcard_states;
pub const CURLWC_DONE: wildcard_states = 7;
pub const CURLWC_ERROR: wildcard_states = 6;
pub const CURLWC_SKIP: wildcard_states = 5;
pub const CURLWC_CLEAN: wildcard_states = 4;
pub const CURLWC_DOWNLOADING: wildcard_states = 3;
pub const CURLWC_MATCHING: wildcard_states = 2;
pub const CURLWC_INIT: wildcard_states = 1;
pub const CURLWC_CLEAR: wildcard_states = 0;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type UrlState = crate::src::lib::altsvc::UrlState;
// #[derive(Copy, Clone)]

pub type dynamically_allocated_data = crate::src::lib::altsvc::dynamically_allocated_data;
pub type trailers_state = crate::src::lib::altsvc::trailers_state;
pub const TRAILERS_DONE: trailers_state = 3;
pub const TRAILERS_SENDING: trailers_state = 2;
pub const TRAILERS_INITIALIZED: trailers_state = 1;
pub const TRAILERS_NONE: trailers_state = 0;
// #[derive(Copy, Clone)]

pub type dynbuf = crate::src::lib::altsvc::dynbuf;
pub type Curl_HttpReq = crate::src::lib::altsvc::Curl_HttpReq;
pub const HTTPREQ_HEAD: Curl_HttpReq = 5;
pub const HTTPREQ_PUT: Curl_HttpReq = 4;
pub const HTTPREQ_POST_MIME: Curl_HttpReq = 3;
pub const HTTPREQ_POST_FORM: Curl_HttpReq = 2;
pub const HTTPREQ_POST: Curl_HttpReq = 1;
pub const HTTPREQ_GET: Curl_HttpReq = 0;
// #[derive(Copy, Clone)]

pub type urlpieces = crate::src::lib::altsvc::urlpieces;
pub type CURLU = crate::src::lib::altsvc::CURLU;
pub type curl_read_callback = crate::src::lib::altsvc::curl_read_callback;
// #[derive(Copy, Clone)]

pub type time_node = crate::src::lib::altsvc::time_node;
pub type expire_id = crate::src::lib::altsvc::expire_id;
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

pub type curltime = crate::src::lib::altsvc::curltime;
// #[derive(Copy, Clone)]

pub type Curl_tree = crate::src::lib::altsvc::Curl_tree;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type Curl_async = crate::src::lib::altsvc::Curl_async;
// #[derive(Copy, Clone)]

pub type Curl_dns_entry = crate::src::lib::altsvc::Curl_dns_entry;
// #[derive(Copy, Clone)]

pub type Curl_addrinfo = crate::src::lib::altsvc::Curl_addrinfo;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type auth = crate::src::lib::altsvc::auth;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type digestdata = crate::src::lib::altsvc::digestdata;
// #[derive(Copy, Clone)]

pub type tempbuf = crate::src::lib::altsvc::tempbuf;
// #[derive(Copy, Clone)]

pub type Curl_ssl_session = crate::src::lib::altsvc::Curl_ssl_session;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type ssl_primary_config = crate::src::lib::altsvc::ssl_primary_config;
// #[derive(Copy, Clone)]

pub type curl_blob = crate::src::lib::altsvc::curl_blob;
// #[derive(Copy, Clone)]

pub type conncache = crate::src::lib::altsvc::conncache;
// #[derive(Copy, Clone)]

pub type Curl_hash = crate::src::lib::altsvc::Curl_hash;
pub type Curl_hash_dtor = crate::src::lib::altsvc::Curl_hash_dtor;
pub type comp_function = crate::src::lib::altsvc::comp_function;
pub type hash_function = crate::src::lib::altsvc::hash_function;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type Progress = crate::src::lib::altsvc::Progress;
pub type timediff_t = crate::src::lib::altsvc::timediff_t;
// #[derive(Copy, Clone)]

pub type altsvcinfo = crate::src::lib::altsvc::altsvcinfo;
// #[derive(Copy, Clone)]

pub type hsts = crate::src::lib::easy::hsts;
// #[derive(Copy, Clone)]

pub type CookieInfo = crate::src::lib::altsvc::CookieInfo;
// #[derive(Copy, Clone)]

pub type Cookie = crate::src::lib::altsvc::Cookie;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type UserDefined = crate::src::lib::altsvc::UserDefined;
pub type curl_trailer_callback = crate::src::lib::altsvc::curl_trailer_callback;
pub type multidone_func = crate::src::lib::altsvc::multidone_func;
pub type CURLcode = crate::src::lib::altsvc::CURLcode;
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
pub type curl_resolver_start_callback = crate::src::lib::altsvc::curl_resolver_start_callback;
// #[derive(Copy, Clone)]

pub type Curl_http2_dep = crate::src::lib::altsvc::Curl_http2_dep;
pub type curl_fnmatch_callback = crate::src::lib::altsvc::curl_fnmatch_callback;
pub type curl_chunk_end_callback = crate::src::lib::altsvc::curl_chunk_end_callback;
pub type curl_chunk_bgn_callback = crate::src::lib::altsvc::curl_chunk_bgn_callback;
pub type Curl_RtspReq = crate::src::lib::altsvc::Curl_RtspReq;
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
pub type curl_usessl = crate::src::lib::altsvc::curl_usessl;
pub const CURLUSESSL_LAST: curl_usessl = 4;
pub const CURLUSESSL_ALL: curl_usessl = 3;
pub const CURLUSESSL_CONTROL: curl_usessl = 2;
pub const CURLUSESSL_TRY: curl_usessl = 1;
pub const CURLUSESSL_NONE: curl_usessl = 0;
pub type CURL_NETRC_OPTION = crate::src::lib::altsvc::CURL_NETRC_OPTION;
pub const CURL_NETRC_LAST: CURL_NETRC_OPTION = 3;
pub const CURL_NETRC_REQUIRED: CURL_NETRC_OPTION = 2;
pub const CURL_NETRC_OPTIONAL: CURL_NETRC_OPTION = 1;
pub const CURL_NETRC_IGNORED: CURL_NETRC_OPTION = 0;
pub type curl_sshkeycallback = crate::src::lib::altsvc::curl_sshkeycallback;
pub type curl_khmatch = crate::src::lib::altsvc::curl_khmatch;
pub const CURLKHMATCH_LAST: curl_khmatch = 3;
pub const CURLKHMATCH_MISSING: curl_khmatch = 2;
pub const CURLKHMATCH_MISMATCH: curl_khmatch = 1;
pub const CURLKHMATCH_OK: curl_khmatch = 0;
// #[derive(Copy, Clone)]

pub type curl_khkey = crate::src::lib::altsvc::curl_khkey;
pub type curl_khtype = crate::src::lib::altsvc::curl_khtype;
pub const CURLKHTYPE_ED25519: curl_khtype = 5;
pub const CURLKHTYPE_ECDSA: curl_khtype = 4;
pub const CURLKHTYPE_DSS: curl_khtype = 3;
pub const CURLKHTYPE_RSA: curl_khtype = 2;
pub const CURLKHTYPE_RSA1: curl_khtype = 1;
pub const CURLKHTYPE_UNKNOWN: curl_khtype = 0;
pub type CURL = crate::src::lib::altsvc::CURL;
pub type curl_ftpccc = crate::src::lib::altsvc::curl_ftpccc;
pub const CURLFTPSSL_CCC_LAST: curl_ftpccc = 3;
pub const CURLFTPSSL_CCC_ACTIVE: curl_ftpccc = 2;
pub const CURLFTPSSL_CCC_PASSIVE: curl_ftpccc = 1;
pub const CURLFTPSSL_CCC_NONE: curl_ftpccc = 0;
pub type curl_ftpauth = crate::src::lib::altsvc::curl_ftpauth;
pub const CURLFTPAUTH_LAST: curl_ftpauth = 3;
pub const CURLFTPAUTH_TLS: curl_ftpauth = 2;
pub const CURLFTPAUTH_SSL: curl_ftpauth = 1;
pub const CURLFTPAUTH_DEFAULT: curl_ftpauth = 0;
pub type curl_ftpfile = crate::src::lib::altsvc::curl_ftpfile;
pub const FTPFILE_SINGLECWD: curl_ftpfile = 3;
pub const FTPFILE_NOCWD: curl_ftpfile = 2;
pub const FTPFILE_MULTICWD: curl_ftpfile = 1;
// #[derive(Copy, Clone)]

pub type ssl_general_config = crate::src::lib::altsvc::ssl_general_config;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type ssl_config_data = crate::src::lib::altsvc::ssl_config_data;
pub type CURL_TLSAUTH = crate::src::lib::altsvc::CURL_TLSAUTH;
pub const CURL_TLSAUTH_LAST: CURL_TLSAUTH = 2;
pub const CURL_TLSAUTH_SRP: CURL_TLSAUTH = 1;
pub const CURL_TLSAUTH_NONE: CURL_TLSAUTH = 0;
pub type curl_ssl_ctx_callback = crate::src::lib::altsvc::curl_ssl_ctx_callback;
pub type curl_proxytype = crate::src::lib::altsvc::curl_proxytype;
pub const CURLPROXY_SOCKS5_HOSTNAME: curl_proxytype = 7;
pub const CURLPROXY_SOCKS4A: curl_proxytype = 6;
pub const CURLPROXY_SOCKS5: curl_proxytype = 5;
pub const CURLPROXY_SOCKS4: curl_proxytype = 4;
pub const CURLPROXY_HTTPS: curl_proxytype = 2;
pub const CURLPROXY_HTTP_1_0: curl_proxytype = 1;
pub const CURLPROXY_HTTP: curl_proxytype = 0;
pub type curl_TimeCond = crate::src::lib::altsvc::curl_TimeCond;
pub const CURL_TIMECOND_LAST: curl_TimeCond = 4;
pub const CURL_TIMECOND_LASTMOD: curl_TimeCond = 3;
pub const CURL_TIMECOND_IFUNMODSINCE: curl_TimeCond = 2;
pub const CURL_TIMECOND_IFMODSINCE: curl_TimeCond = 1;
pub const CURL_TIMECOND_NONE: curl_TimeCond = 0;
// #[derive(Copy, Clone)]

pub type curl_mimepart = crate::src::lib::altsvc::curl_mimepart;
// #[derive(Copy, Clone)]

pub type mime_encoder_state = crate::src::lib::altsvc::mime_encoder_state;
// #[derive(Copy, Clone)]

pub type mime_encoder = crate::src::lib::altsvc::mime_encoder;
// #[derive(Copy, Clone)]

pub type mime_state = crate::src::lib::altsvc::mime_state;
pub type mimestate = crate::src::lib::altsvc::mimestate;
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
pub type curl_free_callback = crate::src::lib::altsvc::curl_free_callback;
pub type curl_seek_callback = crate::src::lib::altsvc::curl_seek_callback;
pub type mimekind = crate::src::lib::altsvc::mimekind;
pub const MIMEKIND_LAST: mimekind = 5;
pub const MIMEKIND_MULTIPART: mimekind = 4;
pub const MIMEKIND_CALLBACK: mimekind = 3;
pub const MIMEKIND_FILE: mimekind = 2;
pub const MIMEKIND_DATA: mimekind = 1;
pub const MIMEKIND_NONE: mimekind = 0;
// #[derive(Copy, Clone)]

pub type curl_mime = crate::src::lib::altsvc::curl_mime;
// #[derive(Copy, Clone)]

pub type curl_httppost = crate::src::lib::altsvc::curl_httppost;
pub type curl_hstswrite_callback = crate::src::lib::altsvc::curl_hstswrite_callback;
// #[derive(Copy, Clone)]

pub type curl_index = crate::src::lib::altsvc::curl_index;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type curl_hstsentry = crate::src::lib::altsvc::curl_hstsentry;
pub type CURLSTScode = crate::src::lib::altsvc::CURLSTScode;
pub const CURLSTS_FAIL: CURLSTScode = 2;
pub const CURLSTS_DONE: CURLSTScode = 1;
pub const CURLSTS_OK: CURLSTScode = 0;
pub type curl_hstsread_callback = crate::src::lib::altsvc::curl_hstsread_callback;
pub type curl_conv_callback = crate::src::lib::altsvc::curl_conv_callback;
pub type curl_closesocket_callback = crate::src::lib::altsvc::curl_closesocket_callback;
pub type curl_socket_t = crate::src::lib::altsvc::curl_socket_t;
pub type curl_opensocket_callback = crate::src::lib::altsvc::curl_opensocket_callback;
// #[derive(Copy, Clone)]

pub type curl_sockaddr = crate::src::lib::altsvc::curl_sockaddr;
pub type curlsocktype = crate::src::lib::altsvc::curlsocktype;
pub const CURLSOCKTYPE_LAST: curlsocktype = 2;
pub const CURLSOCKTYPE_ACCEPT: curlsocktype = 1;
pub const CURLSOCKTYPE_IPCXN: curlsocktype = 0;
pub type curl_sockopt_callback = crate::src::lib::altsvc::curl_sockopt_callback;
pub type curl_ioctl_callback = crate::src::lib::altsvc::curl_ioctl_callback;
pub type curlioerr = crate::src::lib::altsvc::curlioerr;
pub const CURLIOE_LAST: curlioerr = 3;
pub const CURLIOE_FAILRESTART: curlioerr = 2;
pub const CURLIOE_UNKNOWNCMD: curlioerr = 1;
pub const CURLIOE_OK: curlioerr = 0;
pub type curl_debug_callback = crate::src::lib::altsvc::curl_debug_callback;
pub type curl_infotype = crate::src::lib::altsvc::curl_infotype;
pub const CURLINFO_END: curl_infotype = 7;
pub const CURLINFO_SSL_DATA_OUT: curl_infotype = 6;
pub const CURLINFO_SSL_DATA_IN: curl_infotype = 5;
pub const CURLINFO_DATA_OUT: curl_infotype = 4;
pub const CURLINFO_DATA_IN: curl_infotype = 3;
pub const CURLINFO_HEADER_OUT: curl_infotype = 2;
pub const CURLINFO_HEADER_IN: curl_infotype = 1;
pub const CURLINFO_TEXT: curl_infotype = 0;
pub type curl_xferinfo_callback = crate::src::lib::altsvc::curl_xferinfo_callback;
pub type curl_progress_callback = crate::src::lib::altsvc::curl_progress_callback;
pub type curl_write_callback = crate::src::lib::altsvc::curl_write_callback;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type SingleRequest = crate::src::lib::altsvc::SingleRequest;
// #[derive(Copy, Clone)]

pub type dohdata = crate::src::lib::altsvc::dohdata;
// #[derive(Copy, Clone)]

pub type dnsprobe = crate::src::lib::altsvc::dnsprobe;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed = crate::src::lib::altsvc::C2RustUnnamed;
// #[derive(Copy, Clone)]

pub type SSHPROTO = crate::src::lib::altsvc::SSHPROTO;
// #[derive(Copy, Clone)]

pub type SMTP = crate::src::lib::altsvc::SMTP;
pub type curl_pp_transfer = crate::src::lib::altsvc::curl_pp_transfer;
pub const PPTRANSFER_NONE: curl_pp_transfer = 2;
pub const PPTRANSFER_INFO: curl_pp_transfer = 1;
pub const PPTRANSFER_BODY: curl_pp_transfer = 0;
// #[derive(Copy, Clone)]

pub type RTSP = crate::src::lib::altsvc::RTSP;
// #[derive(Copy, Clone)]

pub type HTTP = crate::src::lib::altsvc::HTTP;
pub type uint8_t = crate::src::lib::altsvc::uint8_t;
pub type uint32_t = crate::src::lib::altsvc::uint32_t;
pub type C2RustUnnamed_0 = u32;
pub const HTTPSEND_BODY: C2RustUnnamed_0 = 2;
pub const HTTPSEND_REQUEST: C2RustUnnamed_0 = 1;
pub const HTTPSEND_NADA: C2RustUnnamed_0 = 0;
// #[derive(Copy, Clone)]

pub type back = crate::src::lib::altsvc::back;
// #[derive(Copy, Clone)]

pub type POP3 = crate::src::lib::altsvc::POP3;
// #[derive(Copy, Clone)]

pub type MQTT = crate::src::lib::altsvc::MQTT;
// #[derive(Copy, Clone)]

pub type IMAP = crate::src::lib::altsvc::IMAP;
// #[derive(Copy, Clone)]

pub type FTP = crate::src::lib::altsvc::FTP;
// #[derive(Copy, Clone)]

pub type FILEPROTO = crate::src::lib::altsvc::FILEPROTO;
// #[derive(Copy, Clone)]

pub type contenc_writer = crate::src::lib::content_encoding::contenc_writer;
// #[derive(Copy, Clone)]

pub type content_encoding = crate::src::lib::content_encoding::content_encoding;
pub type upgrade101 = crate::src::lib::altsvc::upgrade101;
pub const UPGR101_WORKING: upgrade101 = 3;
pub const UPGR101_RECEIVED: upgrade101 = 2;
pub const UPGR101_REQUESTED: upgrade101 = 1;
pub const UPGR101_INIT: upgrade101 = 0;
pub type expect100 = crate::src::lib::altsvc::expect100;
pub const EXP100_FAILED: expect100 = 3;
pub const EXP100_SENDING_REQUEST: expect100 = 2;
pub const EXP100_AWAITING_CONTINUE: expect100 = 1;
pub const EXP100_SEND_DATA: expect100 = 0;
pub type C2RustUnnamed_1 = u32;
pub const HEADER_ALLBAD: C2RustUnnamed_1 = 2;
pub const HEADER_PARTHEADER: C2RustUnnamed_1 = 1;
pub const HEADER_NORMAL: C2RustUnnamed_1 = 0;
// #[derive(Copy, Clone)]

pub type PslCache = crate::src::lib::altsvc::PslCache;
pub type psl_ctx_t = crate::src::lib::altsvc::psl_ctx_t;
// #[derive(Copy, Clone)]

pub type Curl_share = crate::src::lib::asyn_thread::Curl_share;
pub type curl_unlock_function = crate::src::lib::asyn_thread::curl_unlock_function;
pub type curl_lock_data = crate::src::lib::asyn_thread::curl_lock_data;
pub const CURL_LOCK_DATA_LAST: curl_lock_data = 7;
pub const CURL_LOCK_DATA_PSL: curl_lock_data = 6;
pub const CURL_LOCK_DATA_CONNECT: curl_lock_data = 5;
pub const CURL_LOCK_DATA_SSL_SESSION: curl_lock_data = 4;
pub const CURL_LOCK_DATA_DNS: curl_lock_data = 3;
pub const CURL_LOCK_DATA_COOKIE: curl_lock_data = 2;
pub const CURL_LOCK_DATA_SHARE: curl_lock_data = 1;
pub const CURL_LOCK_DATA_NONE: curl_lock_data = 0;
pub type curl_lock_function = crate::src::lib::asyn_thread::curl_lock_function;
pub type curl_lock_access = crate::src::lib::asyn_thread::curl_lock_access;
pub const CURL_LOCK_ACCESS_LAST: curl_lock_access = 3;
pub const CURL_LOCK_ACCESS_SINGLE: curl_lock_access = 2;
pub const CURL_LOCK_ACCESS_SHARED: curl_lock_access = 1;
pub const CURL_LOCK_ACCESS_NONE: curl_lock_access = 0;
// #[derive(Copy, Clone)]

pub type Curl_multi = crate::src::lib::altsvc::Curl_multi;
pub type curl_multi_timer_callback = crate::src::lib::altsvc::curl_multi_timer_callback;
pub type CURLM = crate::src::lib::altsvc::CURLM;
pub type curl_push_callback = crate::src::lib::altsvc::curl_push_callback;
pub type curl_socket_callback = crate::src::lib::altsvc::curl_socket_callback;
// #[derive(Copy, Clone)]

pub type Names = crate::src::lib::altsvc::Names;
pub type C2RustUnnamed_2 = u32;
pub const HCACHE_SHARED: C2RustUnnamed_2 = 2;
pub const HCACHE_MULTI: C2RustUnnamed_2 = 1;
pub const HCACHE_NONE: C2RustUnnamed_2 = 0;
// #[derive(Copy, Clone)]

pub type Curl_message = crate::src::lib::altsvc::Curl_message;
// #[derive(Copy, Clone)]

pub type CURLMsg = crate::src::lib::altsvc::CURLMsg;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_3 = crate::src::lib::altsvc::C2RustUnnamed_3;
pub type CURLMSG = crate::src::lib::altsvc::CURLMSG;
pub const CURLMSG_LAST: CURLMSG = 2;
pub const CURLMSG_DONE: CURLMSG = 1;
pub const CURLMSG_NONE: CURLMSG = 0;
pub type CURLMstate = crate::src::lib::altsvc::CURLMstate;
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

pub type connectdata = crate::src::lib::altsvc::connectdata;
// #[derive(Copy, Clone)]

pub type connectbundle = crate::src::lib::altsvc::connectbundle;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type http_connect_state = crate::src::lib::ftp::http_connect_state;
pub type C2RustUnnamed_4 = u32;
pub const TUNNEL_EXIT: C2RustUnnamed_4 = 3;
pub const TUNNEL_COMPLETE: C2RustUnnamed_4 = 2;
pub const TUNNEL_CONNECT: C2RustUnnamed_4 = 1;
pub const TUNNEL_INIT: C2RustUnnamed_4 = 0;
pub type keeponval = crate::src::lib::ftp::keeponval;
pub const KEEPON_IGNORE: keeponval = 2;
pub const KEEPON_CONNECT: keeponval = 1;
pub const KEEPON_DONE: keeponval = 0;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_5 = crate::src::lib::altsvc::C2RustUnnamed_4;
// #[derive(Copy, Clone)]

pub type mqtt_conn = crate::src::lib::altsvc::mqtt_conn;
pub type mqttstate = crate::src::lib::altsvc::mqttstate;
pub const MQTT_NOSTATE: mqttstate = 7;
pub const MQTT_PUB_REMAIN: mqttstate = 6;
pub const MQTT_PUBWAIT: mqttstate = 5;
pub const MQTT_SUBACK_COMING: mqttstate = 4;
pub const MQTT_SUBACK: mqttstate = 3;
pub const MQTT_CONNACK: mqttstate = 2;
pub const MQTT_REMAINING_LENGTH: mqttstate = 1;
pub const MQTT_FIRST: mqttstate = 0;
// #[derive(Copy, Clone)]

pub type smb_conn = crate::src::lib::altsvc::smb_conn;
pub type smb_conn_state = crate::src::lib::altsvc::smb_conn_state;
pub const SMB_CONNECTED: smb_conn_state = 4;
pub const SMB_SETUP: smb_conn_state = 3;
pub const SMB_NEGOTIATE: smb_conn_state = 2;
pub const SMB_CONNECTING: smb_conn_state = 1;
pub const SMB_NOT_CONNECTED: smb_conn_state = 0;
// #[derive(Copy, Clone)]

pub type rtsp_conn = crate::src::lib::altsvc::rtsp_conn;
// #[derive(Copy, Clone)]

pub type smtp_conn = crate::src::lib::altsvc::smtp_conn;
// #[derive(Copy, Clone)]

pub type SASL = crate::src::lib::altsvc::SASL;
pub type saslstate = crate::src::lib::altsvc::saslstate;
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

pub type SASLproto = crate::src::lib::altsvc::SASLproto;
pub type smtpstate = crate::src::lib::altsvc::smtpstate;
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

pub type pingpong = crate::src::lib::altsvc::pingpong;
// #[derive(Copy, Clone)]

pub type pop3_conn = crate::src::lib::altsvc::pop3_conn;
pub type pop3state = crate::src::lib::altsvc::pop3state;
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

pub type imap_conn = crate::src::lib::altsvc::imap_conn;
pub type imapstate = crate::src::lib::altsvc::imapstate;
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

pub type ssh_conn = crate::src::lib::altsvc::ssh_conn;
pub type sshstate = crate::src::lib::altsvc::sshstate;
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

pub type http_conn = crate::src::lib::altsvc::http_conn;
// #[derive(Copy, Clone)]

pub type nghttp2_settings_entry = crate::src::lib::altsvc::nghttp2_settings_entry;
// #[derive(Copy, Clone)]

pub type h2settings = crate::src::lib::altsvc::h2settings;
pub type Curl_recv = crate::src::lib::altsvc::Curl_recv;
pub type Curl_send = crate::src::lib::altsvc::Curl_send;
// #[derive(Copy, Clone)]

pub type ftp_conn = crate::src::lib::altsvc::ftp_conn;
pub type ftpstate = crate::src::lib::altsvc::ftpstate;
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

pub type ntlmdata = crate::src::lib::altsvc::ntlmdata;
pub type curlntlm = crate::src::lib::altsvc::curlntlm;
pub const NTLMSTATE_LAST: curlntlm = 4;
pub const NTLMSTATE_TYPE3: curlntlm = 3;
pub const NTLMSTATE_TYPE2: curlntlm = 2;
pub const NTLMSTATE_TYPE1: curlntlm = 1;
pub const NTLMSTATE_NONE: curlntlm = 0;
// #[derive(Copy, Clone)]

pub type gsasldata = crate::src::lib::altsvc::gsasldata;
// #[derive(Copy, Clone)]

pub type Curl_handler = crate::src::lib::altsvc::Curl_handler;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type ConnectBits = crate::src::lib::altsvc::ConnectBits;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type ssl_connect_data = crate::src::lib::altsvc::ssl_connect_data;
pub type ssl_connect_state = crate::src::lib::altsvc::ssl_connect_state;
pub const ssl_connect_done: ssl_connect_state = 5;
pub const ssl_connect_3: ssl_connect_state = 4;
pub const ssl_connect_2_writing: ssl_connect_state = 3;
pub const ssl_connect_2_reading: ssl_connect_state = 2;
pub const ssl_connect_2: ssl_connect_state = 1;
pub const ssl_connect_1: ssl_connect_state = 0;
pub type ssl_connection_state = crate::src::lib::altsvc::ssl_connection_state;
pub const ssl_connection_complete: ssl_connection_state = 2;
pub const ssl_connection_negotiating: ssl_connection_state = 1;
pub const ssl_connection_none: ssl_connection_state = 0;
// #[derive(Copy, Clone)]

pub type proxy_info = crate::src::lib::altsvc::proxy_info;
// #[derive(Copy, Clone)]

pub type hostname = crate::src::lib::altsvc::hostname;
pub type C2RustUnnamed_6 = u32;
pub const TRNSPRT_QUIC: C2RustUnnamed_6 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_6 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_6 = 3;
// #[derive(Copy, Clone)]

pub type Curl_chunker = crate::src::lib::altsvc::Curl_chunker;
pub type ChunkyState = crate::src::lib::altsvc::ChunkyState;
pub const CHUNK_TRAILER_POSTCR: ChunkyState = 7;
pub const CHUNK_TRAILER_CR: ChunkyState = 6;
pub const CHUNK_TRAILER: ChunkyState = 5;
pub const CHUNK_STOP: ChunkyState = 4;
pub const CHUNK_POSTLF: ChunkyState = 3;
pub const CHUNK_DATA: ChunkyState = 2;
pub const CHUNK_LF: ChunkyState = 1;
pub const CHUNK_HEX: ChunkyState = 0;
// #[derive(Copy, Clone)]

pub type connstate = crate::src::lib::altsvc::connstate;
pub type connect_t = crate::src::lib::altsvc::connect_t;
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
pub type curl_malloc_callback = crate::src::lib::altsvc::curl_malloc_callback;
pub type curl_strdup_callback = crate::src::lib::altsvc::curl_strdup_callback;
pub type curl_calloc_callback = crate::src::lib::altsvc::curl_calloc_callback;
pub type C2RustUnnamed_7 = u32;
pub const CURL_HTTP_VERSION_LAST: C2RustUnnamed_7 = 31;
pub const CURL_HTTP_VERSION_3: C2RustUnnamed_7 = 30;
pub const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: C2RustUnnamed_7 = 5;
pub const CURL_HTTP_VERSION_2TLS: C2RustUnnamed_7 = 4;
pub const CURL_HTTP_VERSION_2_0: C2RustUnnamed_7 = 3;
pub const CURL_HTTP_VERSION_1_1: C2RustUnnamed_7 = 2;
pub const CURL_HTTP_VERSION_1_0: C2RustUnnamed_7 = 1;
pub const CURL_HTTP_VERSION_NONE: C2RustUnnamed_7 = 0;
// #[derive(Copy, Clone)]

pub type curl_ssl_backend = crate::src::lib::getinfo::curl_ssl_backend;
pub type CURLINFO = crate::src::lib::easy::CURLINFO;
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
pub type CURLSHcode = crate::src::lib::conncache::CURLSHcode;
pub const CURLSHE_LAST: CURLSHcode = 6;
pub const CURLSHE_NOT_BUILT_IN: CURLSHcode = 5;
pub const CURLSHE_NOMEM: CURLSHcode = 4;
pub const CURLSHE_INVALID: CURLSHcode = 3;
pub const CURLSHE_IN_USE: CURLSHcode = 2;
pub const CURLSHE_BAD_OPTION: CURLSHcode = 1;
pub const CURLSHE_OK: CURLSHcode = 0;
pub type CURLMcode = crate::src::lib::doh::CURLMcode;
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
pub type CURLUcode = crate::src::lib::http::CURLUcode;
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
pub type CURLUPart = crate::src::lib::http::CURLUPart;
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
pub type resolve_t = crate::src::lib::connect::resolve_t;
pub const CURLRESOLV_PENDING: resolve_t = 1;
pub const CURLRESOLV_RESOLVED: resolve_t = 0;
pub const CURLRESOLV_ERROR: resolve_t = -1;
pub const CURLRESOLV_TIMEDOUT: resolve_t = -2;
pub type dupstring = crate::src::lib::connect::dupstring;
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
pub type dupblob = crate::src::lib::doh::dupblob;
pub const BLOB_LAST: dupblob = 8;
pub const BLOB_CAINFO_PROXY: dupblob = 7;
pub const BLOB_CAINFO: dupblob = 6;
pub const BLOB_SSL_ISSUERCERT_PROXY: dupblob = 5;
pub const BLOB_SSL_ISSUERCERT: dupblob = 4;
pub const BLOB_KEY_PROXY: dupblob = 3;
pub const BLOB_KEY: dupblob = 2;
pub const BLOB_CERT_PROXY: dupblob = 1;
pub const BLOB_CERT: dupblob = 0;
// #[derive(Copy, Clone)]

pub type Curl_ssl = crate::src::lib::getinfo::Curl_ssl;
pub type timerid = crate::src::lib::connect::timerid;
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
pub type urlreject = crate::src::lib::dict::urlreject;
pub const REJECT_ZERO: urlreject = 4;
pub const REJECT_CTRL: urlreject = 3;
pub const REJECT_NADA: urlreject = 2;
// #[derive(Copy, Clone)]

pub type stsentry = crate::src::lib::hsts::stsentry;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct prunedead {
    pub data: *mut Curl_easy,
    pub extracted: *mut connectdata,
}
pub const ALPN_h3: alpnid = 32;
pub const ALPN_h2: alpnid = 16;
pub const ALPN_h1: alpnid = 8;
pub type alpnid = crate::src::lib::altsvc::alpnid;
pub const ALPN_none: alpnid = 0;
// #[derive(Copy, Clone)]

pub type althost = crate::src::lib::altsvc::althost;
// #[derive(Copy, Clone)]

pub type altsvc = crate::src::lib::altsvc::altsvc;
#[inline]
unsafe extern "C" fn tolower(mut __c: i32) -> i32 {
    return if __c >= -(128 as i32) && __c < 256 as i32 {
        *(*__ctype_tolower_loc()).offset(__c as isize)
    } else {
        __c
    };
}
unsafe extern "C" fn get_protocol_family(mut h: *const Curl_handler) -> u32 {
    return (*h).family;
}
static mut protocols: [*const Curl_handler; 23] = unsafe {
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
        0 as *const libc::c_void as *mut libc::c_void as *mut Curl_handler
            as *const Curl_handler,
    ]
};
static mut Curl_handler_dummy: Curl_handler = {
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
pub unsafe extern "C" fn Curl_freeset(mut data: *mut Curl_easy) {
    let mut i: dupstring = STRING_CERT;
    let mut j: dupblob = BLOB_CERT;
    i = STRING_CERT;
    while (i as u32) < STRING_LAST as i32 as u32 {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).set.str_0[i as usize] as *mut libc::c_void);
        let fresh0 = &mut ((*data).set.str_0[i as usize]);
        *fresh0 = 0 as *mut i8;
        i += 1;
    }
    j = BLOB_CERT;
    while (j as u32) < BLOB_LAST as i32 as u32 {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).set.blobs[j as usize] as *mut libc::c_void);
        let fresh1 = &mut ((*data).set.blobs[j as usize]);
        *fresh1 = 0 as *mut curl_blob;
        j += 1;
    }
    if ((*data).state).referer_alloc() != 0 {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.referer as *mut libc::c_void);
        let fresh2 = &mut ((*data).state.referer);
        *fresh2 = 0 as *mut i8;
        let fresh3 = &mut ((*data).state);
        (*fresh3).set_referer_alloc(0 as i32 as bit);
    }
    let fresh4 = &mut ((*data).state.referer);
    *fresh4 = 0 as *mut i8;
    if ((*data).state).url_alloc() != 0 {
        Curl_cfree
            .expect("non-null function pointer")((*data).state.url as *mut libc::c_void);
        let fresh5 = &mut ((*data).state.url);
        *fresh5 = 0 as *mut i8;
        let fresh6 = &mut ((*data).state);
        (*fresh6).set_url_alloc(0 as i32 as bit);
    }
    let fresh7 = &mut ((*data).state.url);
    *fresh7 = 0 as *mut i8;
    Curl_mime_cleanpart(&mut (*data).set.mimepost);
}
unsafe extern "C" fn up_free(mut data: *mut Curl_easy) {
    let mut up: *mut urlpieces = &mut (*data).state.up;
    Curl_cfree.expect("non-null function pointer")((*up).scheme as *mut libc::c_void);
    let fresh8 = &mut ((*up).scheme);
    *fresh8 = 0 as *mut i8;
    Curl_cfree.expect("non-null function pointer")((*up).hostname as *mut libc::c_void);
    let fresh9 = &mut ((*up).hostname);
    *fresh9 = 0 as *mut i8;
    Curl_cfree.expect("non-null function pointer")((*up).port as *mut libc::c_void);
    let fresh10 = &mut ((*up).port);
    *fresh10 = 0 as *mut i8;
    Curl_cfree.expect("non-null function pointer")((*up).user as *mut libc::c_void);
    let fresh11 = &mut ((*up).user);
    *fresh11 = 0 as *mut i8;
    Curl_cfree.expect("non-null function pointer")((*up).password as *mut libc::c_void);
    let fresh12 = &mut ((*up).password);
    *fresh12 = 0 as *mut i8;
    Curl_cfree.expect("non-null function pointer")((*up).options as *mut libc::c_void);
    let fresh13 = &mut ((*up).options);
    *fresh13 = 0 as *mut i8;
    Curl_cfree.expect("non-null function pointer")((*up).path as *mut libc::c_void);
    let fresh14 = &mut ((*up).path);
    *fresh14 = 0 as *mut i8;
    Curl_cfree.expect("non-null function pointer")((*up).query as *mut libc::c_void);
    let fresh15 = &mut ((*up).query);
    *fresh15 = 0 as *mut i8;
    curl_url_cleanup((*data).state.uh);
    let fresh16 = &mut ((*data).state.uh);
    *fresh16 = 0 as *mut CURLU;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_close(mut datap: *mut *mut Curl_easy) -> CURLcode {
    let mut m: *mut Curl_multi = 0 as *mut Curl_multi;
    let mut data: *mut Curl_easy = 0 as *mut Curl_easy;
    if datap.is_null() || (*datap).is_null() {
        return CURLE_OK;
    }
    data = *datap;
    *datap = 0 as *mut Curl_easy;
    Curl_expire_clear(data);
    Curl_detach_connnection(data);
    m = (*data).multi;
    if !m.is_null() {
        curl_multi_remove_handle((*data).multi, data);
    }
    if !((*data).multi_easy).is_null() {
        curl_multi_cleanup((*data).multi_easy);
        let fresh17 = &mut ((*data).multi_easy);
        *fresh17 = 0 as *mut Curl_multi;
    }
    Curl_llist_destroy(&mut (*data).state.timeoutlist, 0 as *mut libc::c_void);
    (*data).magic = 0 as i32 as u32;
    if ((*data).state).rangestringalloc() != 0 {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.range as *mut libc::c_void);
    }
    Curl_free_request_state(data);
    Curl_ssl_close_all(data);
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.first_host as *mut libc::c_void);
    let fresh18 = &mut ((*data).state.first_host);
    *fresh18 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*data).state.scratch as *mut libc::c_void);
    let fresh19 = &mut ((*data).state.scratch);
    *fresh19 = 0 as *mut i8;
    Curl_ssl_free_certinfo(data);
    Curl_cfree
        .expect("non-null function pointer")((*data).req.newurl as *mut libc::c_void);
    let fresh20 = &mut ((*data).req.newurl);
    *fresh20 = 0 as *mut i8;
    if ((*data).state).referer_alloc() != 0 {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.referer as *mut libc::c_void);
        let fresh21 = &mut ((*data).state.referer);
        *fresh21 = 0 as *mut i8;
        let fresh22 = &mut ((*data).state);
        (*fresh22).set_referer_alloc(0 as i32 as bit);
    }
    let fresh23 = &mut ((*data).state.referer);
    *fresh23 = 0 as *mut i8;
    up_free(data);
    Curl_cfree
        .expect("non-null function pointer")((*data).state.buffer as *mut libc::c_void);
    let fresh24 = &mut ((*data).state.buffer);
    *fresh24 = 0 as *mut i8;
    Curl_dyn_free(&mut (*data).state.headerb);
    Curl_cfree
        .expect("non-null function pointer")((*data).state.ulbuf as *mut libc::c_void);
    let fresh25 = &mut ((*data).state.ulbuf);
    *fresh25 = 0 as *mut i8;
    Curl_flush_cookies(data, 1 as i32 != 0);
    Curl_altsvc_save(
        data,
        (*data).asi,
        (*data).set.str_0[STRING_ALTSVC as i32 as usize],
    );
    Curl_altsvc_cleanup(&mut (*data).asi);
    Curl_hsts_save(
        data,
        (*data).hsts,
        (*data).set.str_0[STRING_HSTS as i32 as usize],
    );
    Curl_hsts_cleanup(&mut (*data).hsts);
    Curl_http_auth_cleanup_digest(data);
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).info.contenttype as *mut libc::c_void);
    let fresh26 = &mut ((*data).info.contenttype);
    *fresh26 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).info.wouldredirect as *mut libc::c_void);
    let fresh27 = &mut ((*data).info.wouldredirect);
    *fresh27 = 0 as *mut i8;
    Curl_resolver_cleanup((*data).state.async_0.resolver);
    Curl_http2_cleanup_dependencies(data);
    if !((*data).share).is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE);
        let fresh28 = &mut ((*(*data).share).dirty);
        ::std::ptr::write_volatile(
            fresh28,
            (::std::ptr::read_volatile::<u32>(fresh28 as *const u32))
                .wrapping_sub(1),
        );
        Curl_share_unlock(data, CURL_LOCK_DATA_SHARE);
    }
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.proxyuserpwd as *mut libc::c_void);
    let fresh29 = &mut ((*data).state.aptr.proxyuserpwd);
    *fresh29 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.uagent as *mut libc::c_void);
    let fresh30 = &mut ((*data).state.aptr.uagent);
    *fresh30 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.userpwd as *mut libc::c_void);
    let fresh31 = &mut ((*data).state.aptr.userpwd);
    *fresh31 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.accept_encoding as *mut libc::c_void);
    let fresh32 = &mut ((*data).state.aptr.accept_encoding);
    *fresh32 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*data).state.aptr.te as *mut libc::c_void);
    let fresh33 = &mut ((*data).state.aptr.te);
    *fresh33 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.rangeline as *mut libc::c_void);
    let fresh34 = &mut ((*data).state.aptr.rangeline);
    *fresh34 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.ref_0 as *mut libc::c_void);
    let fresh35 = &mut ((*data).state.aptr.ref_0);
    *fresh35 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.host as *mut libc::c_void);
    let fresh36 = &mut ((*data).state.aptr.host);
    *fresh36 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.cookiehost as *mut libc::c_void);
    let fresh37 = &mut ((*data).state.aptr.cookiehost);
    *fresh37 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.rtsp_transport as *mut libc::c_void);
    let fresh38 = &mut ((*data).state.aptr.rtsp_transport);
    *fresh38 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.user as *mut libc::c_void);
    let fresh39 = &mut ((*data).state.aptr.user);
    *fresh39 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.passwd as *mut libc::c_void);
    let fresh40 = &mut ((*data).state.aptr.passwd);
    *fresh40 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.proxyuser as *mut libc::c_void);
    let fresh41 = &mut ((*data).state.aptr.proxyuser);
    *fresh41 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.proxypasswd as *mut libc::c_void);
    let fresh42 = &mut ((*data).state.aptr.proxypasswd);
    *fresh42 = 0 as *mut i8;
    if !((*data).req.doh).is_null() {
        Curl_dyn_free(
            &mut (*((*(*data).req.doh).probe)
                .as_mut_ptr()
                .offset(0 as i32 as isize))
                .serverdoh,
        );
        Curl_dyn_free(
            &mut (*((*(*data).req.doh).probe)
                .as_mut_ptr()
                .offset(1 as i32 as isize))
                .serverdoh,
        );
        curl_slist_free_all((*(*data).req.doh).headers);
        Curl_cfree
            .expect("non-null function pointer")((*data).req.doh as *mut libc::c_void);
        let fresh43 = &mut ((*data).req.doh);
        *fresh43 = 0 as *mut dohdata;
    }
    Curl_wildcard_dtor(&mut (*data).wildcard);
    Curl_freeset(data);
    Curl_cfree.expect("non-null function pointer")(data as *mut libc::c_void);
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_init_userdefined(mut data: *mut Curl_easy) -> CURLcode {
    let mut set: *mut UserDefined = &mut (*data).set;
    let mut result: CURLcode = CURLE_OK;
    let fresh44 = &mut ((*set).out);
    *fresh44 = stdout as *mut libc::c_void;
    let fresh45 = &mut ((*set).in_set);
    *fresh45 = stdin as *mut libc::c_void;
    let fresh46 = &mut ((*set).err);
    *fresh46 = stderr;
    let fresh47 = &mut ((*set).fwrite_func);
    *fresh47 = ::std::mem::transmute::<
        Option::<
            unsafe extern "C" fn(
                *const libc::c_void,
                u64,
                u64,
                *mut FILE,
            ) -> u64,
        >,
        curl_write_callback,
    >(
        Some(
            fwrite
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    u64,
                    u64,
                    *mut FILE,
                ) -> u64,
        ),
    );
    let fresh48 = &mut ((*set).fread_func_set);
    *fresh48 = ::std::mem::transmute::<
        Option::<
            unsafe extern "C" fn(
                *mut libc::c_void,
                u64,
                u64,
                *mut FILE,
            ) -> u64,
        >,
        curl_read_callback,
    >(
        Some(
            fread
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    u64,
                    u64,
                    *mut FILE,
                ) -> u64,
        ),
    );
    (*set).set_is_fread_set(0 as i32 as bit);
    (*set).set_is_fwrite_set(0 as i32 as bit);
    let fresh49 = &mut ((*set).seek_func);
    *fresh49 = None;
    let fresh50 = &mut ((*set).seek_client);
    *fresh50 = 0 as *mut libc::c_void;
    let fresh51 = &mut ((*set).convfromnetwork);
    *fresh51 = None;
    let fresh52 = &mut ((*set).convtonetwork);
    *fresh52 = None;
    let fresh53 = &mut ((*set).convfromutf8);
    *fresh53 = None;
    (*set).filesize = -(1 as i32) as curl_off_t;
    (*set).postfieldsize = -(1 as i32) as curl_off_t;
    (*set).maxredirs = -(1 as i32) as i64;
    (*set).method = HTTPREQ_GET;
    (*set).rtspreq = RTSPREQ_OPTIONS;
    (*set).set_ftp_use_epsv(1 as i32 as bit);
    (*set).set_ftp_use_eprt(1 as i32 as bit);
    (*set).set_ftp_use_pret(0 as i32 as bit);
    (*set).ftp_filemethod = FTPFILE_MULTICWD;
    (*set).set_ftp_skip_ip(1 as i32 as bit);
    (*set).dns_cache_timeout = 60 as i32 as i64;
    (*set).general_ssl.max_ssl_sessions = 5 as i32 as size_t;
    (*set).proxyport = 0 as i32 as i64;
    (*set).proxytype = CURLPROXY_HTTP;
    (*set).httpauth = (1 as i32 as u64) << 0 as i32;
    (*set).proxyauth = (1 as i32 as u64) << 0 as i32;
    (*set)
        .socks5auth = (1 as i32 as u64) << 0 as i32
        | (1 as i32 as u64) << 2 as i32;
    (*set).set_hide_progress(1 as i32 as bit);
    Curl_mime_initpart(&mut (*set).mimepost, data);
    (*set).set_doh_verifyhost(1 as i32 as bit);
    (*set).set_doh_verifypeer(1 as i32 as bit);
    let fresh54 = &mut ((*set).ssl.primary);
    (*fresh54).set_verifypeer(1 as i32 as bit);
    let fresh55 = &mut ((*set).ssl.primary);
    (*fresh55).set_verifyhost(1 as i32 as bit);
    (*set).ssl.authtype = CURL_TLSAUTH_NONE;
    (*set).ssh_auth_types = !(0 as i32) as i64;
    let fresh56 = &mut ((*set).ssl.primary);
    (*fresh56).set_sessionid(1 as i32 as bit);
    (*set).proxy_ssl = (*set).ssl;
    (*set).new_file_perms = 0o644 as i32 as i64;
    (*set).new_directory_perms = 0o755 as i32 as i64;
    (*set).allowed_protocols = !(0 as i32) as i64;
    (*set)
        .redir_protocols = ((1 as i32) << 0 as i32
        | (1 as i32) << 1 as i32 | (1 as i32) << 2 as i32
        | (1 as i32) << 3 as i32) as i64;
    if Curl_ssl_backend() != CURLSSLBACKEND_SCHANNEL as i32 {
        result = Curl_setstropt(
            &mut *((*set).str_0)
                .as_mut_ptr()
                .offset(STRING_SSL_CAFILE as i32 as isize),
            b"/etc/ssl/certs/ca-certificates.crt\0" as *const u8 as *const i8,
        );
        if result as u64 != 0 {
            return result;
        }
        result = Curl_setstropt(
            &mut *((*set).str_0)
                .as_mut_ptr()
                .offset(STRING_SSL_CAFILE_PROXY as i32 as isize),
            b"/etc/ssl/certs/ca-certificates.crt\0" as *const u8 as *const i8,
        );
        if result as u64 != 0 {
            return result;
        }
    }
    (*set).set_wildcard_enabled(0 as i32 as bit);
    let fresh57 = &mut ((*set).chunk_bgn);
    *fresh57 = None;
    let fresh58 = &mut ((*set).chunk_end);
    *fresh58 = None;
    (*set).set_tcp_keepalive(0 as i32 as bit);
    (*set).tcp_keepintvl = 60 as i32 as i64;
    (*set).tcp_keepidle = 60 as i32 as i64;
    (*set).set_tcp_fastopen(0 as i32 as bit);
    (*set).set_tcp_nodelay(1 as i32 as bit);
    (*set).set_ssl_enable_npn(1 as i32 as bit);
    (*set).set_ssl_enable_alpn(1 as i32 as bit);
    (*set).expect_100_timeout = 1000 as i64;
    (*set).set_sep_headers(1 as i32 as bit);
    (*set).buffer_size = 16384 as i32 as i64;
    (*set).upload_buffer_size = 65536 as i32 as u32;
    (*set).happy_eyeballs_timeout = 200 as i64;
    let fresh59 = &mut ((*set).fnmatch);
    *fresh59 = None;
    (*set).upkeep_interval_ms = 60000 as i64;
    (*set).maxconnects = 5 as i32 as size_t;
    (*set).maxage_conn = 118 as i32 as i64;
    (*set).set_http09_allowed(0 as i32 as bit);
    (*set).httpwant = CURL_HTTP_VERSION_2TLS as i32 as u8;
    Curl_http2_init_userset(set);
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_open(mut curl: *mut *mut Curl_easy) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut data: *mut Curl_easy = 0 as *mut Curl_easy;
    data = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(
        1 as i32 as size_t,
        ::std::mem::size_of::<Curl_easy>() as u64,
    ) as *mut Curl_easy;
    if data.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    (*data).magic = 0xc0dedbad as u32;
    result = Curl_resolver_init(data, &mut (*data).state.async_0.resolver);
    if result as u64 != 0 {
        Curl_cfree.expect("non-null function pointer")(data as *mut libc::c_void);
        return result;
    }
    result = Curl_init_userdefined(data);
    if result as u64 == 0 {
        Curl_dyn_init(
            &mut (*data).state.headerb,
            (100 as i32 * 1024 as i32) as size_t,
        );
        Curl_initinfo(data);
        (*data).state.lastconnect_id = -(1 as i32) as i64;
        (*data).progress.flags |= (1 as i32) << 4 as i32;
        (*data).state.current_speed = -(1 as i32) as curl_off_t;
    }
    if result as u64 != 0 {
        Curl_resolver_cleanup((*data).state.async_0.resolver);
        Curl_dyn_free(&mut (*data).state.headerb);
        Curl_freeset(data);
        Curl_cfree.expect("non-null function pointer")(data as *mut libc::c_void);
        data = 0 as *mut Curl_easy;
    } else {
        *curl = data;
    }
    return result;
}
unsafe extern "C" fn conn_shutdown(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) {
    Curl_infof(
        data,
        b"Closing connection %ld\0" as *const u8 as *const i8,
        (*conn).connection_id,
    );
    if !((*conn).connect_state).is_null()
        && !((*(*conn).connect_state).prot_save).is_null()
    {
        let fresh60 = &mut ((*data).req.p.http);
        *fresh60 = 0 as *mut HTTP;
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*(*conn).connect_state).prot_save as *mut libc::c_void);
        let fresh61 = &mut ((*(*conn).connect_state).prot_save);
        *fresh61 = 0 as *mut HTTP;
    }
    Curl_resolver_cancel(data);
    Curl_ssl_close(data, conn, 0 as i32);
    Curl_ssl_close(data, conn, 1 as i32);
    if -(1 as i32) != (*conn).sock[1 as i32 as usize] {
        Curl_closesocket(data, conn, (*conn).sock[1 as i32 as usize]);
    }
    if -(1 as i32) != (*conn).sock[0 as i32 as usize] {
        Curl_closesocket(data, conn, (*conn).sock[0 as i32 as usize]);
    }
    if -(1 as i32) != (*conn).tempsock[0 as i32 as usize] {
        Curl_closesocket(data, conn, (*conn).tempsock[0 as i32 as usize]);
    }
    if -(1 as i32) != (*conn).tempsock[1 as i32 as usize] {
        Curl_closesocket(data, conn, (*conn).tempsock[1 as i32 as usize]);
    }
}
unsafe extern "C" fn conn_free(mut conn: *mut connectdata) {
    Curl_free_idnconverted_hostname(&mut (*conn).host);
    Curl_free_idnconverted_hostname(&mut (*conn).conn_to_host);
    Curl_free_idnconverted_hostname(&mut (*conn).http_proxy.host);
    Curl_free_idnconverted_hostname(&mut (*conn).socks_proxy.host);
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).http_proxy.user as *mut libc::c_void);
    let fresh62 = &mut ((*conn).http_proxy.user);
    *fresh62 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).socks_proxy.user as *mut libc::c_void);
    let fresh63 = &mut ((*conn).socks_proxy.user);
    *fresh63 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).http_proxy.passwd as *mut libc::c_void);
    let fresh64 = &mut ((*conn).http_proxy.passwd);
    *fresh64 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).socks_proxy.passwd as *mut libc::c_void);
    let fresh65 = &mut ((*conn).socks_proxy.passwd);
    *fresh65 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).http_proxy.host.rawalloc as *mut libc::c_void);
    let fresh66 = &mut ((*conn).http_proxy.host.rawalloc);
    *fresh66 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).socks_proxy.host.rawalloc as *mut libc::c_void);
    let fresh67 = &mut ((*conn).socks_proxy.host.rawalloc);
    *fresh67 = 0 as *mut i8;
    Curl_free_primary_ssl_config(&mut (*conn).proxy_ssl_config);
    Curl_cfree.expect("non-null function pointer")((*conn).user as *mut libc::c_void);
    let fresh68 = &mut ((*conn).user);
    *fresh68 = 0 as *mut i8;
    Curl_cfree.expect("non-null function pointer")((*conn).passwd as *mut libc::c_void);
    let fresh69 = &mut ((*conn).passwd);
    *fresh69 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*conn).sasl_authzid as *mut libc::c_void);
    let fresh70 = &mut ((*conn).sasl_authzid);
    *fresh70 = 0 as *mut i8;
    Curl_cfree.expect("non-null function pointer")((*conn).options as *mut libc::c_void);
    let fresh71 = &mut ((*conn).options);
    *fresh71 = 0 as *mut i8;
    Curl_dyn_free(&mut (*conn).trailer);
    Curl_cfree
        .expect("non-null function pointer")((*conn).host.rawalloc as *mut libc::c_void);
    let fresh72 = &mut ((*conn).host.rawalloc);
    *fresh72 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).conn_to_host.rawalloc as *mut libc::c_void);
    let fresh73 = &mut ((*conn).conn_to_host.rawalloc);
    *fresh73 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).hostname_resolve as *mut libc::c_void);
    let fresh74 = &mut ((*conn).hostname_resolve);
    *fresh74 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).secondaryhostname as *mut libc::c_void);
    let fresh75 = &mut ((*conn).secondaryhostname);
    *fresh75 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*conn).connect_state as *mut libc::c_void);
    let fresh76 = &mut ((*conn).connect_state);
    *fresh76 = 0 as *mut http_connect_state;
    Curl_llist_destroy(&mut (*conn).easyq, 0 as *mut libc::c_void);
    Curl_cfree
        .expect("non-null function pointer")((*conn).localdev as *mut libc::c_void);
    let fresh77 = &mut ((*conn).localdev);
    *fresh77 = 0 as *mut i8;
    Curl_free_primary_ssl_config(&mut (*conn).ssl_config);
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).unix_domain_socket as *mut libc::c_void);
    let fresh78 = &mut ((*conn).unix_domain_socket);
    *fresh78 = 0 as *mut i8;
    Curl_cfree.expect("non-null function pointer")((*conn).ssl_extra);
    let fresh79 = &mut ((*conn).ssl_extra);
    *fresh79 = 0 as *mut libc::c_void;
    Curl_cfree.expect("non-null function pointer")(conn as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_disconnect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut dead_connection: bool,
) -> CURLcode {
    if (*conn).easyq.size != 0 && !dead_connection {
        return CURLE_OK;
    }
    if !((*conn).dns_entry).is_null() {
        Curl_resolv_unlock(data, (*conn).dns_entry);
        let fresh80 = &mut ((*conn).dns_entry);
        *fresh80 = 0 as *mut Curl_dns_entry;
    }
    Curl_http_auth_cleanup_ntlm(conn);
    if ((*conn).bits).connect_only() != 0 {
        dead_connection = 1 as i32 != 0;
    }
    Curl_attach_connnection(data, conn);
    if ((*(*conn).handler).disconnect).is_some() {
        ((*(*conn).handler).disconnect)
            .expect("non-null function pointer")(data, conn, dead_connection);
    }
    conn_shutdown(data, conn);
    Curl_detach_connnection(data);
    conn_free(conn);
    return CURLE_OK;
}
unsafe extern "C" fn SocketIsDead(mut sock: curl_socket_t) -> bool {
    let mut sval: i32 = 0;
    let mut ret_val: bool = 1 as i32 != 0;
    sval = Curl_socket_check(
        sock,
        -(1 as i32),
        -(1 as i32),
        0 as i32 as timediff_t,
    );
    if sval == 0 as i32 {
        ret_val = 0 as i32 != 0;
    }
    return ret_val;
}
unsafe extern "C" fn IsMultiplexingPossible(
    mut handle: *const Curl_easy,
    mut conn: *const connectdata,
) -> i32 {
    let mut avail: i32 = 0 as i32;
    if (*(*conn).handler).protocol
        & ((1 as i32) << 0 as i32
            | (1 as i32) << 1 as i32) as u32 != 0
        && (((*conn).bits).protoconnstart() == 0 || ((*conn).bits).close() == 0)
    {
        if Curl_multiplex_wanted((*handle).multi) as i32 != 0
            && (*handle).state.httpwant as i32
                >= CURL_HTTP_VERSION_2_0 as i32
        {
            avail = (avail as i64 | 2 as i64) as i32;
        }
    }
    return avail;
}
unsafe extern "C" fn proxy_info_matches(
    mut data: *const proxy_info,
    mut needle: *const proxy_info,
) -> bool {
    if (*data).proxytype as u32 == (*needle).proxytype as u32
        && (*data).port == (*needle).port
        && Curl_safe_strcasecompare((*data).host.name, (*needle).host.name) != 0
    {
        return 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
unsafe extern "C" fn socks_proxy_info_matches(
    mut data: *const proxy_info,
    mut needle: *const proxy_info,
) -> bool {
    if !proxy_info_matches(data, needle) {
        return 0 as i32 != 0;
    }
    if ((*data).user).is_null() as i32
        != ((*needle).user).is_null() as i32
    {
        return 0 as i32 != 0;
    }
    if !((*data).user).is_null() && !((*needle).user).is_null()
        && strcmp((*data).user, (*needle).user) != 0 as i32
    {
        return 0 as i32 != 0;
    }
    if ((*data).passwd).is_null() as i32
        != ((*needle).passwd).is_null() as i32
    {
        return 0 as i32 != 0;
    }
    if !((*data).passwd).is_null() && !((*needle).passwd).is_null()
        && strcmp((*data).passwd, (*needle).passwd) != 0 as i32
    {
        return 0 as i32 != 0;
    }
    return 1 as i32 != 0;
}
unsafe extern "C" fn conn_maxage(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut now: curltime,
) -> bool {
    let mut idletime: timediff_t = Curl_timediff(now, (*conn).lastused);
    idletime /= 1000 as i32 as i64;
    if idletime > (*data).set.maxage_conn {
        Curl_infof(
            data,
            b"Too old connection (%ld seconds), disconnect it\0" as *const u8
                as *const i8,
            idletime,
        );
        return 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
unsafe extern "C" fn extract_if_dead(
    mut conn: *mut connectdata,
    mut data: *mut Curl_easy,
) -> bool {
    if (*conn).easyq.size == 0 {
        let mut dead: bool = false;
        let mut now: curltime = Curl_now();
        if conn_maxage(data, conn, now) {
            dead = 1 as i32 != 0;
        } else if ((*(*conn).handler).connection_check).is_some() {
            let mut state: u32 = 0;
            Curl_attach_connnection(data, conn);
            state = ((*(*conn).handler).connection_check)
                .expect(
                    "non-null function pointer",
                )(data, conn, ((1 as i32) << 0 as i32) as u32);
            dead = state & ((1 as i32) << 0 as i32) as u32 != 0;
            Curl_detach_connnection(data);
        } else {
            dead = SocketIsDead((*conn).sock[0 as i32 as usize]);
        }
        if dead {
            Curl_infof(
                data,
                b"Connection %ld seems to be dead!\0" as *const u8
                    as *const i8,
                (*conn).connection_id,
            );
            Curl_conncache_remove_conn(data, conn, 0 as i32 != 0);
            return 1 as i32 != 0;
        }
    }
    return 0 as i32 != 0;
}
unsafe extern "C" fn call_extract_if_dead(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut param: *mut libc::c_void,
) -> i32 {
    let mut p: *mut prunedead = param as *mut prunedead;
    if extract_if_dead(conn, data) {
        let fresh81 = &mut ((*p).extracted);
        *fresh81 = conn;
        return 1 as i32;
    }
    return 0 as i32;
}
unsafe extern "C" fn prune_dead_connections(mut data: *mut Curl_easy) {
    let mut now: curltime = Curl_now();
    let mut elapsed: timediff_t = 0;
    if !((*data).share).is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_CONNECT, CURL_LOCK_ACCESS_SINGLE);
    }
    elapsed = Curl_timediff(now, (*(*data).state.conn_cache).last_cleanup);
    if !((*data).share).is_null() {
        Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
    }
    if elapsed >= 1000 as i64 {
        let mut prune: prunedead = prunedead {
            data: 0 as *mut Curl_easy,
            extracted: 0 as *mut connectdata,
        };
        prune.data = data;
        prune.extracted = 0 as *mut connectdata;
        while Curl_conncache_foreach(
            data,
            (*data).state.conn_cache,
            &mut prune as *mut prunedead as *mut libc::c_void,
            Some(
                call_extract_if_dead
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut libc::c_void,
                    ) -> i32,
            ),
        ) {
            Curl_conncache_remove_conn(data, prune.extracted, 1 as i32 != 0);
            Curl_disconnect(data, prune.extracted, 1 as i32 != 0);
        }
        if !((*data).share).is_null() {
            Curl_share_lock(data, CURL_LOCK_DATA_CONNECT, CURL_LOCK_ACCESS_SINGLE);
        }
        (*(*data).state.conn_cache).last_cleanup = now;
        if !((*data).share).is_null() {
            Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
        }
    }
}
unsafe extern "C" fn ConnectionExists(
    mut data: *mut Curl_easy,
    mut needle: *mut connectdata,
    mut usethis: *mut *mut connectdata,
    mut force_reuse: *mut bool,
    mut waitpipe: *mut bool,
) -> bool {
    let mut check: *mut connectdata = 0 as *mut connectdata;
    let mut chosen: *mut connectdata = 0 as *mut connectdata;
    let mut foundPendingCandidate: bool = 0 as i32 != 0;
    let mut canmultiplex: bool = IsMultiplexingPossible(data, needle) != 0;
    let mut bundle: *mut connectbundle = 0 as *mut connectbundle;
    let mut hostbundle: *const i8 = 0 as *const i8;
    let mut wantNTLMhttp: bool = (*data).state.authhost.want
        & ((1 as i32 as u64) << 3 as i32
            | (1 as i32 as u64) << 5 as i32) != 0
        && (*(*needle).handler).protocol
            & ((1 as i32) << 0 as i32
                | (1 as i32) << 1 as i32) as u32 != 0;
    let mut wantProxyNTLMhttp: bool = ((*needle).bits).proxy_user_passwd() as i32
        != 0
        && ((*data).state.authproxy.want
            & ((1 as i32 as u64) << 3 as i32
                | (1 as i32 as u64) << 5 as i32) != 0
            && (*(*needle).handler).protocol
                & ((1 as i32) << 0 as i32
                    | (1 as i32) << 1 as i32) as u32 != 0);
    *force_reuse = 0 as i32 != 0;
    *waitpipe = 0 as i32 != 0;
    bundle = Curl_conncache_find_bundle(
        data,
        needle,
        (*data).state.conn_cache,
        &mut hostbundle,
    );
    if !bundle.is_null() {
        let mut curr: *mut Curl_llist_element = 0 as *mut Curl_llist_element;
        Curl_infof(
            data,
            b"Found bundle for host %s: %p [%s]\0" as *const u8 as *const i8,
            hostbundle,
            bundle as *mut libc::c_void,
            if (*bundle).multiuse == 2 as i32 {
                b"can multiplex\0" as *const u8 as *const i8
            } else {
                b"serially\0" as *const u8 as *const i8
            },
        );
        if canmultiplex {
            if (*bundle).multiuse == 0 as i32 {
                if ((*data).set).pipewait() != 0 {
                    Curl_infof(
                        data,
                        b"Server doesn't support multiplex yet, wait\0" as *const u8
                            as *const i8,
                    );
                    *waitpipe = 1 as i32 != 0;
                    if !((*data).share).is_null() {
                        Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
                    }
                    return 0 as i32 != 0;
                }
                Curl_infof(
                    data,
                    b"Server doesn't support multiplex (yet)\0" as *const u8
                        as *const i8,
                );
                canmultiplex = 0 as i32 != 0;
            }
            if (*bundle).multiuse == 2 as i32
                && !Curl_multiplex_wanted((*data).multi)
            {
                Curl_infof(
                    data,
                    b"Could multiplex, but not asked to!\0" as *const u8
                        as *const i8,
                );
                canmultiplex = 0 as i32 != 0;
            }
            if (*bundle).multiuse == -(1 as i32) {
                Curl_infof(
                    data,
                    b"Can not multiplex, even if we wanted to!\0" as *const u8
                        as *const i8,
                );
                canmultiplex = 0 as i32 != 0;
            }
        }
        curr = (*bundle).conn_list.head;
        while !curr.is_null() {
            let mut match_0: bool = 0 as i32 != 0;
            let mut multiplexed: size_t = 0 as i32 as size_t;
            check = (*curr).ptr as *mut connectdata;
            curr = (*curr).next;
            if !(((*check).bits).connect_only() as i32 != 0
                || ((*check).bits).close() as i32 != 0)
            {
                if extract_if_dead(check, data) {
                    Curl_disconnect(data, check, 1 as i32 != 0);
                } else if !((*data).set.ipver as i32 != 0 as i32
                        && (*data).set.ipver as i32
                            != (*check).ip_version as i32)
                    {
                    if (*bundle).multiuse == 2 as i32 {
                        multiplexed = (*check).easyq.size;
                    }
                    if !canmultiplex {
                        if multiplexed != 0 {
                            continue;
                        } else if (*check).primary_ip[0 as i32 as usize] == 0 {
                            Curl_infof(
                                data,
                                b"Connection #%ld is still name resolving, can't reuse\0"
                                    as *const u8 as *const i8,
                                (*check).connection_id,
                            );
                            continue;
                        } else if (*check).sock[0 as i32 as usize]
                                == -(1 as i32)
                            {
                            foundPendingCandidate = 1 as i32 != 0;
                            Curl_infof(
                                data,
                                b"Connection #%ld isn't open enough, can't reuse\0"
                                    as *const u8 as *const i8,
                                (*check).connection_id,
                            );
                            continue;
                        }
                    }
                    if !((*needle).unix_domain_socket).is_null() {
                        if ((*check).unix_domain_socket).is_null() {
                            continue;
                        }
                        if strcmp(
                            (*needle).unix_domain_socket,
                            (*check).unix_domain_socket,
                        ) != 0
                        {
                            continue;
                        }
                        if ((*needle).bits).abstract_unix_socket() as i32
                            != ((*check).bits).abstract_unix_socket() as i32
                        {
                            continue;
                        }
                    } else if !((*check).unix_domain_socket).is_null() {
                        continue;
                    }
                    if (*(*needle).handler).flags
                        & ((1 as i32) << 0 as i32) as u32
                        != (*(*check).handler).flags
                            & ((1 as i32) << 0 as i32) as u32
                    {
                        if get_protocol_family((*check).handler)
                            != (*(*needle).handler).protocol
                            || ((*check).bits).tls_upgraded() == 0
                        {
                            continue;
                        }
                    }
                    if ((*needle).bits).httpproxy() as i32
                        != ((*check).bits).httpproxy() as i32
                        || ((*needle).bits).socksproxy() as i32
                            != ((*check).bits).socksproxy() as i32
                    {
                        continue;
                    }
                    if ((*needle).bits).socksproxy() as i32 != 0
                        && !socks_proxy_info_matches(
                            &mut (*needle).socks_proxy,
                            &mut (*check).socks_proxy,
                        )
                    {
                        continue;
                    }
                    if !(((*needle).bits).conn_to_host() as i32
                        != ((*check).bits).conn_to_host() as i32)
                    {
                        if !(((*needle).bits).conn_to_port() as i32
                            != ((*check).bits).conn_to_port() as i32)
                        {
                            if ((*needle).bits).httpproxy() != 0 {
                                if !proxy_info_matches(
                                    &mut (*needle).http_proxy,
                                    &mut (*check).http_proxy,
                                ) {
                                    continue;
                                }
                                if ((*needle).bits).tunnel_proxy() as i32
                                    != ((*check).bits).tunnel_proxy() as i32
                                {
                                    continue;
                                }
                                if (*needle).http_proxy.proxytype as u32
                                    == CURLPROXY_HTTPS as i32 as u32
                                {
                                    if (*(*needle).handler).flags
                                        & ((1 as i32) << 0 as i32) as u32
                                        != 0
                                    {
                                        if !Curl_ssl_config_matches(
                                            &mut (*needle).proxy_ssl_config,
                                            &mut (*check).proxy_ssl_config,
                                        ) {
                                            continue;
                                        }
                                        if (*check).proxy_ssl[0 as i32 as usize].state
                                            as u32
                                            != ssl_connection_complete as i32 as u32
                                        {
                                            continue;
                                        }
                                    } else {
                                        if !Curl_ssl_config_matches(
                                            &mut (*needle).ssl_config,
                                            &mut (*check).ssl_config,
                                        ) {
                                            continue;
                                        }
                                        if (*check).ssl[0 as i32 as usize].state
                                            as u32
                                            != ssl_connection_complete as i32 as u32
                                        {
                                            continue;
                                        }
                                    }
                                }
                            }
                            if !(!canmultiplex && (*check).easyq.size != 0) {
                                if (*check).easyq.size != 0 {
                                    let mut e: *mut Curl_llist_element = (*check).easyq.head;
                                    let mut entry: *mut Curl_easy = (*e).ptr as *mut Curl_easy;
                                    if (*entry).multi != (*data).multi {
                                        continue;
                                    }
                                }
                                if !((*needle).localdev).is_null()
                                    || (*needle).localport as i32 != 0
                                {
                                    if (*check).localport as i32
                                        != (*needle).localport as i32
                                        || (*check).localportrange != (*needle).localportrange
                                        || !((*needle).localdev).is_null()
                                            && (((*check).localdev).is_null()
                                                || strcmp((*check).localdev, (*needle).localdev) != 0)
                                    {
                                        continue;
                                    }
                                }
                                if (*(*needle).handler).flags
                                    & ((1 as i32) << 7 as i32) as u32
                                    == 0
                                {
                                    if strcmp((*needle).user, (*check).user) != 0
                                        || strcmp((*needle).passwd, (*check).passwd) != 0
                                    {
                                        continue;
                                    }
                                }
                                if (*(*needle).handler).protocol
                                    & ((1 as i32) << 0 as i32
                                        | (1 as i32) << 1 as i32) as u32
                                    != 0
                                    && (*check).httpversion as i32 >= 20 as i32
                                    && ((*data).state.httpwant as i32)
                                        < CURL_HTTP_VERSION_2_0 as i32
                                {
                                    continue;
                                }
                                if (*(*needle).handler).flags
                                    & ((1 as i32) << 0 as i32) as u32
                                    != 0 || ((*needle).bits).httpproxy() == 0
                                    || ((*needle).bits).tunnel_proxy() as i32 != 0
                                {
                                    if (Curl_strcasecompare(
                                        (*(*needle).handler).scheme,
                                        (*(*check).handler).scheme,
                                    ) != 0
                                        || get_protocol_family((*check).handler)
                                            == (*(*needle).handler).protocol
                                            && ((*check).bits).tls_upgraded() as i32 != 0)
                                        && (((*needle).bits).conn_to_host() == 0
                                            || Curl_strcasecompare(
                                                (*needle).conn_to_host.name,
                                                (*check).conn_to_host.name,
                                            ) != 0)
                                        && (((*needle).bits).conn_to_port() == 0
                                            || (*needle).conn_to_port == (*check).conn_to_port)
                                        && Curl_strcasecompare(
                                            (*needle).host.name,
                                            (*check).host.name,
                                        ) != 0 && (*needle).remote_port == (*check).remote_port
                                    {
                                        if (*(*needle).handler).flags
                                            & ((1 as i32) << 0 as i32) as u32
                                            != 0
                                        {
                                            if !Curl_ssl_config_matches(
                                                &mut (*needle).ssl_config,
                                                &mut (*check).ssl_config,
                                            ) {
                                                continue;
                                            }
                                            if (*check).ssl[0 as i32 as usize].state
                                                as u32
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
                                    if strcmp((*needle).user, (*check).user) != 0
                                        || strcmp((*needle).passwd, (*check).passwd) != 0
                                    {
                                        if (*check).http_ntlm_state as u32
                                            == NTLMSTATE_NONE as i32 as u32
                                        {
                                            chosen = check;
                                        }
                                        continue;
                                    }
                                } else if (*check).http_ntlm_state as u32
                                        != NTLMSTATE_NONE as i32 as u32
                                    {
                                    continue;
                                }
                                if wantProxyNTLMhttp {
                                    if ((*check).http_proxy.user).is_null()
                                        || ((*check).http_proxy.passwd).is_null()
                                    {
                                        continue;
                                    }
                                    if strcmp(
                                        (*needle).http_proxy.user,
                                        (*check).http_proxy.user,
                                    ) != 0
                                        || strcmp(
                                            (*needle).http_proxy.passwd,
                                            (*check).http_proxy.passwd,
                                        ) != 0
                                    {
                                        continue;
                                    }
                                } else if (*check).proxy_ntlm_state as u32
                                        != NTLMSTATE_NONE as i32 as u32
                                    {
                                    continue;
                                }
                                if wantNTLMhttp as i32 != 0
                                    || wantProxyNTLMhttp as i32 != 0
                                {
                                    chosen = check;
                                    if !(wantNTLMhttp as i32 != 0
                                        && (*check).http_ntlm_state as u32
                                            != NTLMSTATE_NONE as i32 as u32
                                        || wantProxyNTLMhttp as i32 != 0
                                            && (*check).proxy_ntlm_state as u32
                                                != NTLMSTATE_NONE as i32 as u32)
                                    {
                                        continue;
                                    }
                                    *force_reuse = 1 as i32 != 0;
                                    break;
                                } else if canmultiplex {
                                    if multiplexed == 0 {
                                        chosen = check;
                                        break;
                                    } else {
                                        if ((*check).bits).multiplex() != 0 {
                                            let mut httpc: *mut http_conn = &mut (*check).proto.httpc;
                                            if multiplexed
                                                >= (*httpc).settings.max_concurrent_streams as u64
                                            {
                                                Curl_infof(
                                                    data,
                                                    b"MAX_CONCURRENT_STREAMS reached, skip (%zu)\0" as *const u8
                                                        as *const i8,
                                                    multiplexed,
                                                );
                                                continue;
                                            } else if multiplexed
                                                    >= Curl_multi_max_concurrent_streams((*data).multi)
                                                        as u64
                                                {
                                                Curl_infof(
                                                    data,
                                                    b"client side MAX_CONCURRENT_STREAMS reached, skip (%zu)\0"
                                                        as *const u8 as *const i8,
                                                    multiplexed,
                                                );
                                                continue;
                                            }
                                        }
                                        chosen = check;
                                        Curl_infof(
                                            data,
                                            b"Multiplexed connection found!\0" as *const u8
                                                as *const i8,
                                        );
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
        if !((*data).share).is_null() {
            Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
        }
        *usethis = chosen;
        return 1 as i32 != 0;
    }
    if !((*data).share).is_null() {
        Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
    }
    if foundPendingCandidate as i32 != 0
        && ((*data).set).pipewait() as i32 != 0
    {
        Curl_infof(
            data,
            b"Found pending candidate for reuse and CURLOPT_PIPEWAIT is set\0"
                as *const u8 as *const i8,
        );
        *waitpipe = 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_verboseconnect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) {
    if ((*data).set).verbose() != 0 {
        Curl_infof(
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
        );
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_is_ASCII_name(mut hostname: *const i8) -> bool {
    let mut ch: *const u8 = hostname as *const u8;
    if hostname.is_null() {
        return 1 as i32 != 0;
    }
    while *ch != 0 {
        let fresh82 = ch;
        ch = ch.offset(1);
        if *fresh82 as i32 & 0x80 as i32 != 0 {
            return 0 as i32 != 0;
        }
    }
    return 1 as i32 != 0;
}
unsafe extern "C" fn strip_trailing_dot(mut host: *mut hostname) {
    let mut len: size_t = 0;
    if host.is_null() || ((*host).name).is_null() {
        return;
    }
    len = strlen((*host).name);
    if len != 0
        && *((*host).name)
            .offset(len.wrapping_sub(1 as i32 as u64) as isize)
            as i32 == '.' as i32
    {
        *((*host).name)
            .offset(
                len.wrapping_sub(1 as i32 as u64) as isize,
            ) = 0 as i32 as i8;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_idnconvert_hostname(
    mut data: *mut Curl_easy,
    mut host: *mut hostname,
) -> CURLcode {
    let fresh83 = &mut ((*host).dispname);
    *fresh83 = (*host).name;
    if !Curl_is_ASCII_name((*host).name) {
        Curl_infof(
            data,
            b"IDN support not present, can't parse Unicode domains\0" as *const u8
                as *const i8,
        );
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_free_idnconverted_hostname(mut host: *mut hostname) {}
unsafe extern "C" fn allocate_conn(mut data: *mut Curl_easy) -> *mut connectdata {
    let mut conn: *mut connectdata = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(
        1 as i32 as size_t,
        ::std::mem::size_of::<connectdata>() as u64,
    ) as *mut connectdata;
    if conn.is_null() {
        return 0 as *mut connectdata;
    }
    let mut sslsize: size_t = (*Curl_ssl).sizeof_ssl_backend_data;
    let mut ssl: *mut i8 = Curl_ccalloc
        .expect("non-null function pointer")(4 as i32 as size_t, sslsize)
        as *mut i8;
    if ssl.is_null() {
        Curl_cfree.expect("non-null function pointer")(conn as *mut libc::c_void);
        return 0 as *mut connectdata;
    }
    let fresh84 = &mut ((*conn).ssl_extra);
    *fresh84 = ssl as *mut libc::c_void;
    let fresh85 = &mut ((*conn).ssl[0 as i32 as usize].backend);
    *fresh85 = ssl as *mut libc::c_void as *mut ssl_backend_data;
    let fresh86 = &mut ((*conn).ssl[1 as i32 as usize].backend);
    *fresh86 = ssl.offset(sslsize as isize) as *mut libc::c_void
        as *mut ssl_backend_data;
    let fresh87 = &mut ((*conn).proxy_ssl[0 as i32 as usize].backend);
    *fresh87 = ssl
        .offset((2 as i32 as u64).wrapping_mul(sslsize) as isize)
        as *mut libc::c_void as *mut ssl_backend_data;
    let fresh88 = &mut ((*conn).proxy_ssl[1 as i32 as usize].backend);
    *fresh88 = ssl
        .offset((3 as i32 as u64).wrapping_mul(sslsize) as isize)
        as *mut libc::c_void as *mut ssl_backend_data;
    let fresh89 = &mut ((*conn).handler);
    *fresh89 = &Curl_handler_dummy;
    (*conn).sock[0 as i32 as usize] = -(1 as i32);
    (*conn).sock[1 as i32 as usize] = -(1 as i32);
    (*conn).tempsock[0 as i32 as usize] = -(1 as i32);
    (*conn).tempsock[1 as i32 as usize] = -(1 as i32);
    (*conn).connection_id = -(1 as i32) as i64;
    (*conn).port = -(1 as i32);
    (*conn).remote_port = -(1 as i32);
    Curl_conncontrol(conn, 1 as i32);
    (*conn).created = Curl_now();
    (*conn).keepalive = Curl_now();
    (*conn).http_proxy.proxytype = (*data).set.proxytype;
    (*conn).socks_proxy.proxytype = CURLPROXY_SOCKS4;
    let fresh90 = &mut ((*conn).bits);
    (*fresh90)
        .set_proxy(
            (if !((*data).set.str_0[STRING_PROXY as i32 as usize]).is_null()
                && *(*data).set.str_0[STRING_PROXY as i32 as usize]
                    as i32 != 0
            {
                1 as i32
            } else {
                0 as i32
            }) as bit,
        );
    let fresh91 = &mut ((*conn).bits);
    (*fresh91)
        .set_httpproxy(
            (if ((*conn).bits).proxy() as i32 != 0
                && ((*conn).http_proxy.proxytype as u32
                    == CURLPROXY_HTTP as i32 as u32
                    || (*conn).http_proxy.proxytype as u32
                        == CURLPROXY_HTTP_1_0 as i32 as u32
                    || (*conn).http_proxy.proxytype as u32
                        == CURLPROXY_HTTPS as i32 as u32)
            {
                1 as i32
            } else {
                0 as i32
            }) as bit,
        );
    let fresh92 = &mut ((*conn).bits);
    (*fresh92)
        .set_socksproxy(
            (if ((*conn).bits).proxy() as i32 != 0
                && ((*conn).bits).httpproxy() == 0
            {
                1 as i32
            } else {
                0 as i32
            }) as bit,
        );
    if !((*data).set.str_0[STRING_PRE_PROXY as i32 as usize]).is_null()
        && *(*data).set.str_0[STRING_PRE_PROXY as i32 as usize] as i32
            != 0
    {
        let fresh93 = &mut ((*conn).bits);
        (*fresh93).set_proxy(1 as i32 as bit);
        let fresh94 = &mut ((*conn).bits);
        (*fresh94).set_socksproxy(1 as i32 as bit);
    }
    let fresh95 = &mut ((*conn).bits);
    (*fresh95)
        .set_proxy_user_passwd(
            (if !((*data).state.aptr.proxyuser).is_null() {
                1 as i32
            } else {
                0 as i32
            }) as bit,
        );
    let fresh96 = &mut ((*conn).bits);
    (*fresh96).set_tunnel_proxy(((*data).set).tunnel_thru_httpproxy());
    let fresh97 = &mut ((*conn).bits);
    (*fresh97)
        .set_user_passwd(
            (if !((*data).state.aptr.user).is_null() {
                1 as i32
            } else {
                0 as i32
            }) as bit,
        );
    let fresh98 = &mut ((*conn).bits);
    (*fresh98).set_ftp_use_epsv(((*data).set).ftp_use_epsv());
    let fresh99 = &mut ((*conn).bits);
    (*fresh99).set_ftp_use_eprt(((*data).set).ftp_use_eprt());
    let fresh100 = &mut ((*conn).ssl_config);
    (*fresh100).set_verifystatus(((*data).set.ssl.primary).verifystatus());
    let fresh101 = &mut ((*conn).ssl_config);
    (*fresh101).set_verifypeer(((*data).set.ssl.primary).verifypeer());
    let fresh102 = &mut ((*conn).ssl_config);
    (*fresh102).set_verifyhost(((*data).set.ssl.primary).verifyhost());
    let fresh103 = &mut ((*conn).proxy_ssl_config);
    (*fresh103).set_verifystatus(((*data).set.proxy_ssl.primary).verifystatus());
    let fresh104 = &mut ((*conn).proxy_ssl_config);
    (*fresh104).set_verifypeer(((*data).set.proxy_ssl.primary).verifypeer());
    let fresh105 = &mut ((*conn).proxy_ssl_config);
    (*fresh105).set_verifyhost(((*data).set.proxy_ssl.primary).verifyhost());
    (*conn).ip_version = (*data).set.ipver;
    let fresh106 = &mut ((*conn).bits);
    (*fresh106).set_connect_only(((*data).set).connect_only());
    (*conn).transport = TRNSPRT_TCP;
    (*conn).ntlm.ntlm_auth_hlpr_socket = -(1 as i32);
    (*conn).proxyntlm.ntlm_auth_hlpr_socket = -(1 as i32);
    Curl_llist_init(&mut (*conn).easyq, None);
    if !((*data).set.str_0[STRING_DEVICE as i32 as usize]).is_null() {
        let fresh107 = &mut ((*conn).localdev);
        *fresh107 = Curl_cstrdup
            .expect(
                "non-null function pointer",
            )((*data).set.str_0[STRING_DEVICE as i32 as usize]);
        if ((*conn).localdev).is_null() {
            Curl_llist_destroy(&mut (*conn).easyq, 0 as *mut libc::c_void);
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*conn).localdev as *mut libc::c_void);
            Curl_cfree.expect("non-null function pointer")((*conn).ssl_extra);
            Curl_cfree.expect("non-null function pointer")(conn as *mut libc::c_void);
            return 0 as *mut connectdata;
        }
    }
    (*conn).localportrange = (*data).set.localportrange;
    (*conn).localport = (*data).set.localport;
    let fresh108 = &mut ((*conn).fclosesocket);
    *fresh108 = (*data).set.fclosesocket;
    let fresh109 = &mut ((*conn).closesocket_client);
    *fresh109 = (*data).set.closesocket_client;
    (*conn).lastused = Curl_now();
    return conn;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_builtin_scheme(
    mut scheme: *const i8,
) -> *const Curl_handler {
    let mut pp: *const *const Curl_handler = 0 as *const *const Curl_handler;
    let mut p: *const Curl_handler = 0 as *const Curl_handler;
    pp = protocols.as_ptr();
    loop {
        p = *pp;
        if p.is_null() {
            break;
        }
        if Curl_strcasecompare((*p).scheme, scheme) != 0 {
            return p;
        }
        pp = pp.offset(1);
    }
    return 0 as *const Curl_handler;
}
unsafe extern "C" fn findprotocol(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut protostr: *const i8,
) -> CURLcode {
    let mut p: *const Curl_handler = Curl_builtin_scheme(protostr);
    if !p.is_null() && (*data).set.allowed_protocols & (*p).protocol as i64 != 0
    {
        if ((*data).state).this_is_a_follow() as i32 != 0
            && (*data).set.redir_protocols & (*p).protocol as i64 == 0
        {} else {
            let fresh110 = &mut ((*conn).given);
            *fresh110 = p;
            let fresh111 = &mut ((*conn).handler);
            *fresh111 = *fresh110;
            return CURLE_OK;
        }
    }
    Curl_failf(
        data,
        b"Protocol \"%s\" not supported or disabled in libcurl\0" as *const u8
            as *const i8,
        protostr,
    );
    return CURLE_UNSUPPORTED_PROTOCOL;
}
#[no_mangle]
pub extern "C" fn Curl_uc_to_curlcode(mut uc: CURLUcode) -> CURLcode {
    match uc as u32 {
        5 => return CURLE_UNSUPPORTED_PROTOCOL,
        7 => return CURLE_OUT_OF_MEMORY,
        8 => return CURLE_LOGIN_DENIED,
        _ => return CURLE_URL_MALFORMAT,
    };
}
unsafe extern "C" fn zonefrom_url(
    mut uh: *mut CURLU,
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) {
    let mut zoneid: *mut i8 = 0 as *mut i8;
    let mut uc: CURLUcode = curl_url_get(
        uh,
        CURLUPART_ZONEID,
        &mut zoneid,
        0 as i32 as u32,
    );
    if uc as u64 == 0 && !zoneid.is_null() {
        let mut endp: *mut i8 = 0 as *mut i8;
        let mut scope: u64 = strtoul(zoneid, &mut endp, 10 as i32);
        if *endp == 0
            && scope
                < (2147483647 as i32 as u32)
                    .wrapping_mul(2 as u32)
                    .wrapping_add(1 as u32) as u64
        {
            (*conn).scope_id = scope as u32;
        } else {
            let mut scopeidx: u32 = 0 as i32 as u32;
            scopeidx = if_nametoindex(zoneid);
            if scopeidx == 0 {
                let mut buffer: [i8; 256] = [0; 256];
                Curl_infof(
                    data,
                    b"Invalid zoneid: %s; %s\0" as *const u8 as *const i8,
                    zoneid,
                    Curl_strerror(
                        *__errno_location(),
                        buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 256]>() as u64,
                    ),
                );
            } else {
                (*conn).scope_id = scopeidx;
            }
        }
        Curl_cfree.expect("non-null function pointer")(zoneid as *mut libc::c_void);
    }
}
unsafe extern "C" fn parseurlandfillconn(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut uh: *mut CURLU = 0 as *mut CURLU;
    let mut uc: CURLUcode = CURLUE_OK;
    let mut hostname: *mut i8 = 0 as *mut i8;
    let mut use_set_uh: bool = !((*data).set.uh).is_null()
        && ((*data).state).this_is_a_follow() == 0;
    up_free(data);
    if use_set_uh {
        let fresh112 = &mut ((*data).state.uh);
        *fresh112 = curl_url_dup((*data).set.uh);
        uh = *fresh112;
    } else {
        let fresh113 = &mut ((*data).state.uh);
        *fresh113 = curl_url();
        uh = *fresh113;
    }
    if uh.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if !((*data).set.str_0[STRING_DEFAULT_PROTOCOL as i32 as usize]).is_null()
        && !Curl_is_absolute_url(
            (*data).state.url,
            0 as *mut i8,
            40 as i32 as size_t,
        )
    {
        let mut url: *mut i8 = curl_maprintf(
            b"%s://%s\0" as *const u8 as *const i8,
            (*data).set.str_0[STRING_DEFAULT_PROTOCOL as i32 as usize],
            (*data).state.url,
        );
        if url.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if ((*data).state).url_alloc() != 0 {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).state.url as *mut libc::c_void);
        }
        let fresh114 = &mut ((*data).state.url);
        *fresh114 = url;
        let fresh115 = &mut ((*data).state);
        (*fresh115).set_url_alloc(1 as i32 as bit);
    }
    if !use_set_uh {
        let mut newurl: *mut i8 = 0 as *mut i8;
        uc = curl_url_set(
            uh,
            CURLUPART_URL,
            (*data).state.url,
            ((1 as i32) << 9 as i32
                | (1 as i32) << 3 as i32
                | (if ((*data).set).disallow_username_in_url() as i32 != 0 {
                    (1 as i32) << 5 as i32
                } else {
                    0 as i32
                })
                | (if ((*data).set).path_as_is() as i32 != 0 {
                    (1 as i32) << 4 as i32
                } else {
                    0 as i32
                })) as u32,
        );
        if uc as u64 != 0 {
            return Curl_uc_to_curlcode(uc);
        }
        uc = curl_url_get(
            uh,
            CURLUPART_URL,
            &mut newurl,
            0 as i32 as u32,
        );
        if uc as u64 != 0 {
            return Curl_uc_to_curlcode(uc);
        }
        if ((*data).state).url_alloc() != 0 {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).state.url as *mut libc::c_void);
        }
        let fresh116 = &mut ((*data).state.url);
        *fresh116 = newurl;
        let fresh117 = &mut ((*data).state);
        (*fresh117).set_url_alloc(1 as i32 as bit);
    }
    uc = curl_url_get(
        uh,
        CURLUPART_SCHEME,
        &mut (*data).state.up.scheme,
        0 as i32 as u32,
    );
    if uc as u64 != 0 {
        return Curl_uc_to_curlcode(uc);
    }
    uc = curl_url_get(
        uh,
        CURLUPART_HOST,
        &mut (*data).state.up.hostname,
        0 as i32 as u32,
    );
    if uc as u64 != 0 {
        if Curl_strcasecompare(
            b"file\0" as *const u8 as *const i8,
            (*data).state.up.scheme,
        ) == 0
        {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if !((*data).hsts).is_null()
        && Curl_strcasecompare(
            b"http\0" as *const u8 as *const i8,
            (*data).state.up.scheme,
        ) != 0
    {
        if !(Curl_hsts((*data).hsts, (*data).state.up.hostname, 1 as i32 != 0))
            .is_null()
        {
            let mut url_0: *mut i8 = 0 as *mut i8;
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).state.up.scheme as *mut libc::c_void);
            let fresh118 = &mut ((*data).state.up.scheme);
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
            if ((*data).state).url_alloc() != 0 {
                Curl_cfree
                    .expect(
                        "non-null function pointer",
                    )((*data).state.url as *mut libc::c_void);
                let fresh119 = &mut ((*data).state.url);
                *fresh119 = 0 as *mut i8;
            }
            uc = curl_url_get(
                uh,
                CURLUPART_URL,
                &mut url_0,
                0 as i32 as u32,
            );
            if uc as u64 != 0 {
                return Curl_uc_to_curlcode(uc);
            }
            uc = curl_url_get(
                uh,
                CURLUPART_SCHEME,
                &mut (*data).state.up.scheme,
                0 as i32 as u32,
            );
            if uc as u64 != 0 {
                Curl_cfree
                    .expect("non-null function pointer")(url_0 as *mut libc::c_void);
                return Curl_uc_to_curlcode(uc);
            }
            let fresh120 = &mut ((*data).state.url);
            *fresh120 = url_0;
            let fresh121 = &mut ((*data).state);
            (*fresh121).set_url_alloc(1 as i32 as bit);
            Curl_infof(
                data,
                b"Switched from HTTP to HTTPS due to HSTS => %s\0" as *const u8
                    as *const i8,
                (*data).state.url,
            );
        }
    }
    result = findprotocol(data, conn, (*data).state.up.scheme);
    if result as u64 != 0 {
        return result;
    }
    if ((*data).state.aptr.user).is_null() {
        uc = curl_url_get(
            uh,
            CURLUPART_USER,
            &mut (*data).state.up.user,
            0 as i32 as u32,
        );
        if uc as u64 == 0 {
            let mut decoded: *mut i8 = 0 as *mut i8;
            result = Curl_urldecode(
                0 as *mut Curl_easy,
                (*data).state.up.user,
                0 as i32 as size_t,
                &mut decoded,
                0 as *mut size_t,
                (if (*(*conn).handler).flags
                    & ((1 as i32) << 13 as i32) as u32 != 0
                {
                    REJECT_ZERO as i32
                } else {
                    REJECT_CTRL as i32
                }) as urlreject,
            );
            if result as u64 != 0 {
                return result;
            }
            let fresh122 = &mut ((*conn).user);
            *fresh122 = decoded;
            let fresh123 = &mut ((*conn).bits);
            (*fresh123).set_user_passwd(1 as i32 as bit);
            result = Curl_setstropt(&mut (*data).state.aptr.user, decoded);
            if result as u64 != 0 {
                return result;
            }
        } else if uc as u32 != CURLUE_NO_USER as i32 as u32 {
            return Curl_uc_to_curlcode(uc)
        }
    }
    if ((*data).state.aptr.passwd).is_null() {
        uc = curl_url_get(
            uh,
            CURLUPART_PASSWORD,
            &mut (*data).state.up.password,
            0 as i32 as u32,
        );
        if uc as u64 == 0 {
            let mut decoded_0: *mut i8 = 0 as *mut i8;
            result = Curl_urldecode(
                0 as *mut Curl_easy,
                (*data).state.up.password,
                0 as i32 as size_t,
                &mut decoded_0,
                0 as *mut size_t,
                (if (*(*conn).handler).flags
                    & ((1 as i32) << 13 as i32) as u32 != 0
                {
                    REJECT_ZERO as i32
                } else {
                    REJECT_CTRL as i32
                }) as urlreject,
            );
            if result as u64 != 0 {
                return result;
            }
            let fresh124 = &mut ((*conn).passwd);
            *fresh124 = decoded_0;
            let fresh125 = &mut ((*conn).bits);
            (*fresh125).set_user_passwd(1 as i32 as bit);
            result = Curl_setstropt(&mut (*data).state.aptr.passwd, decoded_0);
            if result as u64 != 0 {
                return result;
            }
        } else if uc as u32 != CURLUE_NO_PASSWORD as i32 as u32
            {
            return Curl_uc_to_curlcode(uc)
        }
    }
    uc = curl_url_get(
        uh,
        CURLUPART_OPTIONS,
        &mut (*data).state.up.options,
        ((1 as i32) << 6 as i32) as u32,
    );
    if uc as u64 == 0 {
        let fresh126 = &mut ((*conn).options);
        *fresh126 = Curl_cstrdup
            .expect("non-null function pointer")((*data).state.up.options);
        if ((*conn).options).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    } else if uc as u32 != CURLUE_NO_OPTIONS as i32 as u32 {
        return Curl_uc_to_curlcode(uc)
    }
    uc = curl_url_get(
        uh,
        CURLUPART_PATH,
        &mut (*data).state.up.path,
        0 as i32 as u32,
    );
    if uc as u64 != 0 {
        return Curl_uc_to_curlcode(uc);
    }
    uc = curl_url_get(
        uh,
        CURLUPART_PORT,
        &mut (*data).state.up.port,
        ((1 as i32) << 0 as i32) as u32,
    );
    if uc as u64 != 0 {
        if Curl_strcasecompare(
            b"file\0" as *const u8 as *const i8,
            (*data).state.up.scheme,
        ) == 0
        {
            return CURLE_OUT_OF_MEMORY;
        }
    } else {
        let mut port: u64 = strtoul(
            (*data).state.up.port,
            0 as *mut *mut i8,
            10 as i32,
        );
        let fresh127 = &mut ((*conn).remote_port);
        *fresh127 = if (*data).set.use_port != 0
            && ((*data).state).allow_port() as i32 != 0
        {
            (*data).set.use_port as i32
        } else {
            curlx_ultous(port) as i32
        };
        (*conn).port = *fresh127;
    }
    curl_url_get(
        uh,
        CURLUPART_QUERY,
        &mut (*data).state.up.query,
        0 as i32 as u32,
    );
    hostname = (*data).state.up.hostname;
    if !hostname.is_null()
        && *hostname.offset(0 as i32 as isize) as i32 == '[' as i32
    {
        let mut hlen: size_t = 0;
        let fresh128 = &mut ((*conn).bits);
        (*fresh128).set_ipv6_ip(1 as i32 as bit);
        hostname = hostname.offset(1);
        hlen = strlen(hostname);
        *hostname
            .offset(
                hlen.wrapping_sub(1 as i32 as u64) as isize,
            ) = 0 as i32 as i8;
        zonefrom_url(uh, data, conn);
    }
    let fresh129 = &mut ((*conn).host.rawalloc);
    *fresh129 = Curl_cstrdup
        .expect(
            "non-null function pointer",
        )(
        if !hostname.is_null() {
            hostname as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
    );
    if ((*conn).host.rawalloc).is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    let fresh130 = &mut ((*conn).host.name);
    *fresh130 = (*conn).host.rawalloc;
    if (*data).set.scope_id != 0 {
        (*conn).scope_id = (*data).set.scope_id;
    }
    return CURLE_OK;
}
unsafe extern "C" fn setup_range(mut data: *mut Curl_easy) -> CURLcode {
    let mut s: *mut UrlState = &mut (*data).state;
    (*s).resume_from = (*data).set.set_resume_from;
    if (*s).resume_from != 0
        || !((*data).set.str_0[STRING_SET_RANGE as i32 as usize]).is_null()
    {
        if (*s).rangestringalloc() != 0 {
            Curl_cfree
                .expect("non-null function pointer")((*s).range as *mut libc::c_void);
        }
        if (*s).resume_from != 0 {
            let fresh131 = &mut ((*s).range);
            *fresh131 = curl_maprintf(
                b"%ld-\0" as *const u8 as *const i8,
                (*s).resume_from,
            );
        } else {
            let fresh132 = &mut ((*s).range);
            *fresh132 = Curl_cstrdup
                .expect(
                    "non-null function pointer",
                )((*data).set.str_0[STRING_SET_RANGE as i32 as usize]);
        }
        (*s)
            .set_rangestringalloc(
                (if !((*s).range).is_null() {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        if ((*s).range).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (*s).set_use_range(1 as i32 as bit);
    } else {
        (*s).set_use_range(0 as i32 as bit);
    }
    return CURLE_OK;
}
unsafe extern "C" fn setup_connection_internals(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut p: *const Curl_handler = 0 as *const Curl_handler;
    let mut result: CURLcode = CURLE_OK;
    p = (*conn).handler;
    if ((*p).setup_connection).is_some() {
        result = (Some(((*p).setup_connection).expect("non-null function pointer")))
            .expect("non-null function pointer")(data, conn);
        if result as u64 != 0 {
            return result;
        }
        p = (*conn).handler;
    }
    if (*conn).port < 0 as i32 {
        (*conn).port = (*p).defport;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_free_request_state(mut data: *mut Curl_easy) {
    Curl_cfree
        .expect("non-null function pointer")((*data).req.p.http as *mut libc::c_void);
    let fresh133 = &mut ((*data).req.p.http);
    *fresh133 = 0 as *mut HTTP;
    Curl_cfree
        .expect("non-null function pointer")((*data).req.newurl as *mut libc::c_void);
    let fresh134 = &mut ((*data).req.newurl);
    *fresh134 = 0 as *mut i8;
    if !((*data).req.doh).is_null() {
        Curl_close(
            &mut (*((*(*data).req.doh).probe)
                .as_mut_ptr()
                .offset(0 as i32 as isize))
                .easy,
        );
        Curl_close(
            &mut (*((*(*data).req.doh).probe)
                .as_mut_ptr()
                .offset(1 as i32 as isize))
                .easy,
        );
    }
}
unsafe extern "C" fn check_noproxy(
    mut name: *const i8,
    mut no_proxy: *const i8,
) -> bool {
    if !no_proxy.is_null()
        && *no_proxy.offset(0 as i32 as isize) as i32 != 0
    {
        let mut tok_start: size_t = 0;
        let mut tok_end: size_t = 0;
        let mut separator: *const i8 = b", \0" as *const u8
            as *const i8;
        let mut no_proxy_len: size_t = 0;
        let mut namelen: size_t = 0;
        let mut endptr: *mut i8 = 0 as *mut i8;
        if Curl_strcasecompare(b"*\0" as *const u8 as *const i8, no_proxy) != 0
        {
            return 1 as i32 != 0;
        }
        no_proxy_len = strlen(no_proxy);
        if *name.offset(0 as i32 as isize) as i32 == '[' as i32 {
            endptr = strchr(name, ']' as i32);
            if endptr.is_null() {
                return 0 as i32 != 0;
            }
            name = name.offset(1);
            namelen = endptr.offset_from(name) as i64 as size_t;
        } else {
            namelen = strlen(name);
        }
        tok_start = 0 as i32 as size_t;
        while tok_start < no_proxy_len {
            while tok_start < no_proxy_len
                && !(strchr(
                    separator,
                    *no_proxy.offset(tok_start as isize) as i32,
                ))
                    .is_null()
            {
                tok_start = tok_start.wrapping_add(1);
            }
            if tok_start == no_proxy_len {
                break;
            }
            tok_end = tok_start;
            while tok_end < no_proxy_len
                && (strchr(separator, *no_proxy.offset(tok_end as isize) as i32))
                    .is_null()
            {
                tok_end = tok_end.wrapping_add(1);
            }
            if *no_proxy.offset(tok_start as isize) as i32 == '.' as i32 {
                tok_start = tok_start.wrapping_add(1);
            }
            if tok_end.wrapping_sub(tok_start) <= namelen {
                let mut checkn: *const i8 = name
                    .offset(namelen as isize)
                    .offset(-(tok_end.wrapping_sub(tok_start) as isize));
                if Curl_strncasecompare(
                    no_proxy.offset(tok_start as isize),
                    checkn,
                    tok_end.wrapping_sub(tok_start),
                ) != 0
                {
                    if tok_end.wrapping_sub(tok_start) == namelen
                        || *checkn.offset(-(1 as i32 as isize)) as i32
                            == '.' as i32
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
unsafe extern "C" fn detect_proxy(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> *mut i8 {
    let mut proxy: *mut i8 = 0 as *mut i8;
    let mut proxy_env: [i8; 128] = [0; 128];
    let mut protop: *const i8 = (*(*conn).handler).scheme;
    let mut envp: *mut i8 = proxy_env.as_mut_ptr();
    let mut prox: *mut i8 = 0 as *mut i8;
    while *protop != 0 {
        let fresh138 = envp;
        envp = envp.offset(1);
        *fresh138 = ({
            let mut __res: i32 = 0;
            if ::std::mem::size_of::<i32>() as u64
                > 1 as i32 as u64
            {
                if 0 != 0 {
                    let fresh135 = protop;
                    protop = protop.offset(1);
                    let mut __c: i32 = *fresh135 as i32;
                    __res = if __c < -(128 as i32) || __c > 255 as i32 {
                        __c
                    } else {
                        *(*__ctype_tolower_loc()).offset(__c as isize)
                    };
                } else {
                    let fresh136 = protop;
                    protop = protop.offset(1);
                    __res = tolower(*fresh136 as i32);
                }
            } else {
                let fresh137 = protop;
                protop = protop.offset(1);
                __res = *(*__ctype_tolower_loc())
                    .offset(*fresh137 as i32 as isize);
            }
            __res
        }) as i8;
    }
    strcpy(envp, b"_proxy\0" as *const u8 as *const i8);
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
            envp = b"ALL_PROXY\0" as *const u8 as *const i8
                as *mut i8;
            proxy = curl_getenv(envp);
        }
    }
    if !proxy.is_null() {
        Curl_infof(
            data,
            b"Uses proxy env variable %s == '%s'\0" as *const u8 as *const i8,
            envp,
            proxy,
        );
    }
    return proxy;
}
unsafe extern "C" fn parse_proxy(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut proxy: *mut i8,
    mut proxytype: curl_proxytype,
) -> CURLcode {
    let mut current_block: u64;
    let mut portptr: *mut i8 = 0 as *mut i8;
    let mut port: i32 = -(1 as i32);
    let mut proxyuser: *mut i8 = 0 as *mut i8;
    let mut proxypasswd: *mut i8 = 0 as *mut i8;
    let mut host: *mut i8 = 0 as *mut i8;
    let mut sockstype: bool = false;
    let mut uc: CURLUcode = CURLUE_OK;
    let mut proxyinfo: *mut proxy_info = 0 as *mut proxy_info;
    let mut uhp: *mut CURLU = curl_url();
    let mut result: CURLcode = CURLE_OK;
    let mut scheme: *mut i8 = 0 as *mut i8;
    uc = curl_url_set(
        uhp,
        CURLUPART_URL,
        proxy,
        ((1 as i32) << 3 as i32 | (1 as i32) << 9 as i32)
            as u32,
    );
    if uc as u64 == 0 {
        uc = curl_url_get(
            uhp,
            CURLUPART_SCHEME,
            &mut scheme,
            0 as i32 as u32,
        );
        if uc as u64 != 0 {
            result = CURLE_OUT_OF_MEMORY;
        } else {
            if Curl_strcasecompare(
                b"https\0" as *const u8 as *const i8,
                scheme,
            ) != 0
            {
                proxytype = CURLPROXY_HTTPS;
                current_block = 15125582407903384992;
            } else if Curl_strcasecompare(
                    b"socks5h\0" as *const u8 as *const i8,
                    scheme,
                ) != 0
                {
                proxytype = CURLPROXY_SOCKS5_HOSTNAME;
                current_block = 15125582407903384992;
            } else if Curl_strcasecompare(
                    b"socks5\0" as *const u8 as *const i8,
                    scheme,
                ) != 0
                {
                proxytype = CURLPROXY_SOCKS5;
                current_block = 15125582407903384992;
            } else if Curl_strcasecompare(
                    b"socks4a\0" as *const u8 as *const i8,
                    scheme,
                ) != 0
                {
                proxytype = CURLPROXY_SOCKS4A;
                current_block = 15125582407903384992;
            } else if Curl_strcasecompare(
                    b"socks4\0" as *const u8 as *const i8,
                    scheme,
                ) != 0
                    || Curl_strcasecompare(
                        b"socks\0" as *const u8 as *const i8,
                        scheme,
                    ) != 0
                {
                proxytype = CURLPROXY_SOCKS4;
                current_block = 15125582407903384992;
            } else if Curl_strcasecompare(
                    b"http\0" as *const u8 as *const i8,
                    scheme,
                ) != 0
                {
                current_block = 15125582407903384992;
            } else {
                Curl_failf(
                    data,
                    b"Unsupported proxy scheme for '%s'\0" as *const u8
                        as *const i8,
                    proxy,
                );
                result = CURLE_COULDNT_CONNECT;
                current_block = 467357264955599708;
            }
            match current_block {
                467357264955599708 => {}
                _ => {
                    if (*Curl_ssl).supports
                        & ((1 as i32) << 4 as i32) as u32 == 0
                    {
                        if proxytype as u32
                            == CURLPROXY_HTTPS as i32 as u32
                        {
                            Curl_failf(
                                data,
                                b"Unsupported proxy '%s', libcurl is built without the HTTPS-proxy support.\0"
                                    as *const u8 as *const i8,
                                proxy,
                            );
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
                            sockstype = proxytype as u32
                                == CURLPROXY_SOCKS5_HOSTNAME as i32 as u32
                                || proxytype as u32
                                    == CURLPROXY_SOCKS5 as i32 as u32
                                || proxytype as u32
                                    == CURLPROXY_SOCKS4A as i32 as u32
                                || proxytype as u32
                                    == CURLPROXY_SOCKS4 as i32 as u32;
                            proxyinfo = if sockstype as i32 != 0 {
                                &mut (*conn).socks_proxy
                            } else {
                                &mut (*conn).http_proxy
                            };
                            (*proxyinfo).proxytype = proxytype;
                            uc = curl_url_get(
                                uhp,
                                CURLUPART_USER,
                                &mut proxyuser,
                                ((1 as i32) << 6 as i32) as u32,
                            );
                            if !(uc as u32 != 0
                                && uc as u32
                                    != CURLUE_NO_USER as i32 as u32)
                            {
                                uc = curl_url_get(
                                    uhp,
                                    CURLUPART_PASSWORD,
                                    &mut proxypasswd,
                                    ((1 as i32) << 6 as i32) as u32,
                                );
                                if !(uc as u32 != 0
                                    && uc as u32
                                        != CURLUE_NO_PASSWORD as i32 as u32)
                                {
                                    if !proxyuser.is_null() || !proxypasswd.is_null() {
                                        Curl_cfree
                                            .expect(
                                                "non-null function pointer",
                                            )((*proxyinfo).user as *mut libc::c_void);
                                        let fresh139 = &mut ((*proxyinfo).user);
                                        *fresh139 = 0 as *mut i8;
                                        let fresh140 = &mut ((*proxyinfo).user);
                                        *fresh140 = proxyuser;
                                        result = Curl_setstropt(
                                            &mut (*data).state.aptr.proxyuser,
                                            proxyuser,
                                        );
                                        proxyuser = 0 as *mut i8;
                                        if result as u64 != 0 {
                                            current_block = 467357264955599708;
                                        } else {
                                            Curl_cfree
                                                .expect(
                                                    "non-null function pointer",
                                                )((*proxyinfo).passwd as *mut libc::c_void);
                                            let fresh141 = &mut ((*proxyinfo).passwd);
                                            *fresh141 = 0 as *mut i8;
                                            if proxypasswd.is_null() {
                                                proxypasswd = Curl_cstrdup
                                                    .expect(
                                                        "non-null function pointer",
                                                    )(b"\0" as *const u8 as *const i8);
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
                                                    let fresh142 = &mut ((*proxyinfo).passwd);
                                                    *fresh142 = proxypasswd;
                                                    result = Curl_setstropt(
                                                        &mut (*data).state.aptr.proxypasswd,
                                                        proxypasswd,
                                                    );
                                                    proxypasswd = 0 as *mut i8;
                                                    if result as u64 != 0 {
                                                        current_block = 467357264955599708;
                                                    } else {
                                                        let fresh143 = &mut ((*conn).bits);
                                                        (*fresh143).set_proxy_user_passwd(1 as i32 as bit);
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
                                                &mut portptr,
                                                0 as i32 as u32,
                                            );
                                            if !portptr.is_null() {
                                                port = strtol(
                                                    portptr,
                                                    0 as *mut *mut i8,
                                                    10 as i32,
                                                ) as i32;
                                                Curl_cfree
                                                    .expect(
                                                        "non-null function pointer",
                                                    )(portptr as *mut libc::c_void);
                                            } else if (*data).set.proxyport != 0 {
                                                port = (*data).set.proxyport as i32;
                                            } else if proxytype as u32
                                                    == CURLPROXY_HTTPS as i32 as u32
                                                {
                                                port = 443 as i32;
                                            } else {
                                                port = 1080 as i32;
                                            }
                                            if port >= 0 as i32 {
                                                (*proxyinfo).port = port as i64;
                                                if (*conn).port < 0 as i32
                                                    || sockstype as i32 != 0
                                                    || ((*conn).socks_proxy.host.rawalloc).is_null()
                                                {
                                                    (*conn).port = port;
                                                }
                                            }
                                            uc = curl_url_get(
                                                uhp,
                                                CURLUPART_HOST,
                                                &mut host,
                                                ((1 as i32) << 6 as i32) as u32,
                                            );
                                            if uc as u64 != 0 {
                                                result = CURLE_OUT_OF_MEMORY;
                                            } else {
                                                Curl_cfree
                                                    .expect(
                                                        "non-null function pointer",
                                                    )((*proxyinfo).host.rawalloc as *mut libc::c_void);
                                                let fresh144 = &mut ((*proxyinfo).host.rawalloc);
                                                *fresh144 = 0 as *mut i8;
                                                let fresh145 = &mut ((*proxyinfo).host.rawalloc);
                                                *fresh145 = host;
                                                if *host.offset(0 as i32 as isize) as i32
                                                    == '[' as i32
                                                {
                                                    let mut len: size_t = strlen(host);
                                                    *host
                                                        .offset(
                                                            len.wrapping_sub(1 as i32 as u64) as isize,
                                                        ) = 0 as i32 as i8;
                                                    host = host.offset(1);
                                                    zonefrom_url(uhp, data, conn);
                                                }
                                                let fresh146 = &mut ((*proxyinfo).host.name);
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
        Curl_failf(
            data,
            b"Unsupported proxy syntax in '%s'\0" as *const u8 as *const i8,
            proxy,
        );
        result = CURLE_COULDNT_RESOLVE_PROXY;
    }
    Curl_cfree.expect("non-null function pointer")(proxyuser as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(proxypasswd as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(scheme as *mut libc::c_void);
    curl_url_cleanup(uhp);
    return result;
}
unsafe extern "C" fn parse_proxy_auth(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut proxyuser: *const i8 = if !((*data).state.aptr.proxyuser).is_null()
    {
        (*data).state.aptr.proxyuser as *const i8
    } else {
        b"\0" as *const u8 as *const i8
    };
    let mut proxypasswd: *const i8 = if !((*data).state.aptr.proxypasswd)
        .is_null()
    {
        (*data).state.aptr.proxypasswd as *const i8
    } else {
        b"\0" as *const u8 as *const i8
    };
    let mut result: CURLcode = CURLE_OK;
    if !proxyuser.is_null() {
        result = Curl_urldecode(
            data,
            proxyuser,
            0 as i32 as size_t,
            &mut (*conn).http_proxy.user,
            0 as *mut size_t,
            REJECT_ZERO,
        );
        if result as u64 == 0 {
            result = Curl_setstropt(
                &mut (*data).state.aptr.proxyuser,
                (*conn).http_proxy.user,
            );
        }
    }
    if result as u64 == 0 && !proxypasswd.is_null() {
        result = Curl_urldecode(
            data,
            proxypasswd,
            0 as i32 as size_t,
            &mut (*conn).http_proxy.passwd,
            0 as *mut size_t,
            REJECT_ZERO,
        );
        if result as u64 == 0 {
            result = Curl_setstropt(
                &mut (*data).state.aptr.proxypasswd,
                (*conn).http_proxy.passwd,
            );
        }
    }
    return result;
}
unsafe extern "C" fn create_conn_helper_init_proxy(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut current_block: u64;
    let mut proxy: *mut i8 = 0 as *mut i8;
    let mut socksproxy: *mut i8 = 0 as *mut i8;
    let mut no_proxy: *mut i8 = 0 as *mut i8;
    let mut result: CURLcode = CURLE_OK;
    if ((*conn).bits).proxy_user_passwd() != 0 {
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
            if !((*data).set.str_0[STRING_PROXY as i32 as usize]).is_null() {
                proxy = Curl_cstrdup
                    .expect(
                        "non-null function pointer",
                    )((*data).set.str_0[STRING_PROXY as i32 as usize]);
                if proxy.is_null() {
                    Curl_failf(
                        data,
                        b"memory shortage\0" as *const u8 as *const i8,
                    );
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
                    if !((*data).set.str_0[STRING_PRE_PROXY as i32 as usize])
                        .is_null()
                    {
                        socksproxy = Curl_cstrdup
                            .expect(
                                "non-null function pointer",
                            )(
                            (*data).set.str_0[STRING_PRE_PROXY as i32 as usize],
                        );
                        if socksproxy.is_null() {
                            Curl_failf(
                                data,
                                b"memory shortage\0" as *const u8 as *const i8,
                            );
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
                            if ((*data)
                                .set
                                .str_0[STRING_NOPROXY as i32 as usize])
                                .is_null()
                            {
                                let mut p: *const i8 = b"no_proxy\0" as *const u8
                                    as *const i8;
                                no_proxy = curl_getenv(p);
                                if no_proxy.is_null() {
                                    p = b"NO_PROXY\0" as *const u8 as *const i8;
                                    no_proxy = curl_getenv(p);
                                }
                                if !no_proxy.is_null() {
                                    Curl_infof(
                                        data,
                                        b"Uses proxy env variable %s == '%s'\0" as *const u8
                                            as *const i8,
                                        p,
                                        no_proxy,
                                    );
                                }
                            }
                            if check_noproxy(
                                (*conn).host.name,
                                if !((*data)
                                    .set
                                    .str_0[STRING_NOPROXY as i32 as usize])
                                    .is_null()
                                {
                                    (*data).set.str_0[STRING_NOPROXY as i32 as usize]
                                } else {
                                    no_proxy
                                },
                            ) {
                                Curl_cfree
                                    .expect(
                                        "non-null function pointer",
                                    )(proxy as *mut libc::c_void);
                                proxy = 0 as *mut i8;
                                Curl_cfree
                                    .expect(
                                        "non-null function pointer",
                                    )(socksproxy as *mut libc::c_void);
                                socksproxy = 0 as *mut i8;
                            } else if proxy.is_null() && socksproxy.is_null() {
                                proxy = detect_proxy(data, conn);
                            }
                            Curl_cfree
                                .expect(
                                    "non-null function pointer",
                                )(no_proxy as *mut libc::c_void);
                            no_proxy = 0 as *mut i8;
                            if !proxy.is_null()
                                && !((*conn).unix_domain_socket).is_null()
                            {
                                Curl_cfree
                                    .expect(
                                        "non-null function pointer",
                                    )(proxy as *mut libc::c_void);
                                proxy = 0 as *mut i8;
                            }
                            if !proxy.is_null()
                                && (*proxy == 0
                                    || (*(*conn).handler).flags
                                        & ((1 as i32) << 4 as i32) as u32
                                        != 0)
                            {
                                Curl_cfree
                                    .expect(
                                        "non-null function pointer",
                                    )(proxy as *mut libc::c_void);
                                proxy = 0 as *mut i8;
                            }
                            if !socksproxy.is_null()
                                && (*socksproxy == 0
                                    || (*(*conn).handler).flags
                                        & ((1 as i32) << 4 as i32) as u32
                                        != 0)
                            {
                                Curl_cfree
                                    .expect(
                                        "non-null function pointer",
                                    )(socksproxy as *mut libc::c_void);
                                socksproxy = 0 as *mut i8;
                            }
                            if !proxy.is_null() || !socksproxy.is_null() {
                                if !proxy.is_null() {
                                    result = parse_proxy(
                                        data,
                                        conn,
                                        proxy,
                                        (*conn).http_proxy.proxytype,
                                    );
                                    Curl_cfree
                                        .expect(
                                            "non-null function pointer",
                                        )(proxy as *mut libc::c_void);
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
                                                (*conn).socks_proxy.proxytype,
                                            );
                                            Curl_cfree
                                                .expect(
                                                    "non-null function pointer",
                                                )(socksproxy as *mut libc::c_void);
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
                                                if !((*conn).http_proxy.host.rawalloc).is_null() {
                                                    if (*(*conn).handler).protocol
                                                        & ((1 as i32) << 0 as i32
                                                            | (1 as i32) << 1 as i32) as u32
                                                        == 0
                                                    {
                                                        if (*(*conn).handler).flags
                                                            & ((1 as i32) << 11 as i32) as u32
                                                            != 0 && ((*conn).bits).tunnel_proxy() == 0
                                                        {
                                                            let fresh147 = &mut ((*conn).handler);
                                                            *fresh147 = &Curl_handler_http;
                                                        } else {
                                                            let fresh148 = &mut ((*conn).bits);
                                                            (*fresh148).set_tunnel_proxy(1 as i32 as bit);
                                                        }
                                                    }
                                                    let fresh149 = &mut ((*conn).bits);
                                                    (*fresh149).set_httpproxy(1 as i32 as bit);
                                                } else {
                                                    let fresh150 = &mut ((*conn).bits);
                                                    (*fresh150).set_httpproxy(0 as i32 as bit);
                                                    let fresh151 = &mut ((*conn).bits);
                                                    (*fresh151).set_tunnel_proxy(0 as i32 as bit);
                                                }
                                                if !((*conn).socks_proxy.host.rawalloc).is_null() {
                                                    if ((*conn).http_proxy.host.rawalloc).is_null() {
                                                        if ((*conn).socks_proxy.user).is_null() {
                                                            let fresh152 = &mut ((*conn).socks_proxy.user);
                                                            *fresh152 = (*conn).http_proxy.user;
                                                            let fresh153 = &mut ((*conn).http_proxy.user);
                                                            *fresh153 = 0 as *mut i8;
                                                            Curl_cfree
                                                                .expect(
                                                                    "non-null function pointer",
                                                                )((*conn).socks_proxy.passwd as *mut libc::c_void);
                                                            let fresh154 = &mut ((*conn).socks_proxy.passwd);
                                                            *fresh154 = 0 as *mut i8;
                                                            let fresh155 = &mut ((*conn).socks_proxy.passwd);
                                                            *fresh155 = (*conn).http_proxy.passwd;
                                                            let fresh156 = &mut ((*conn).http_proxy.passwd);
                                                            *fresh156 = 0 as *mut i8;
                                                        }
                                                    }
                                                    let fresh157 = &mut ((*conn).bits);
                                                    (*fresh157).set_socksproxy(1 as i32 as bit);
                                                } else {
                                                    let fresh158 = &mut ((*conn).bits);
                                                    (*fresh158).set_socksproxy(0 as i32 as bit);
                                                }
                                                current_block = 16463303006880176998;
                                            }
                                        }
                                    }
                                }
                            } else {
                                let fresh159 = &mut ((*conn).bits);
                                (*fresh159).set_socksproxy(0 as i32 as bit);
                                let fresh160 = &mut ((*conn).bits);
                                (*fresh160).set_httpproxy(0 as i32 as bit);
                                current_block = 16463303006880176998;
                            }
                            match current_block {
                                5128804967847913759 => {}
                                _ => {
                                    let fresh161 = &mut ((*conn).bits);
                                    (*fresh161)
                                        .set_proxy(
                                            (((*conn).bits).httpproxy() as i32 != 0
                                                || ((*conn).bits).socksproxy() as i32 != 0)
                                                as i32 as bit,
                                        );
                                    if ((*conn).bits).proxy() == 0 {
                                        let fresh162 = &mut ((*conn).bits);
                                        (*fresh162).set_proxy(0 as i32 as bit);
                                        let fresh163 = &mut ((*conn).bits);
                                        (*fresh163).set_httpproxy(0 as i32 as bit);
                                        let fresh164 = &mut ((*conn).bits);
                                        (*fresh164).set_socksproxy(0 as i32 as bit);
                                        let fresh165 = &mut ((*conn).bits);
                                        (*fresh165).set_proxy_user_passwd(0 as i32 as bit);
                                        let fresh166 = &mut ((*conn).bits);
                                        (*fresh166).set_tunnel_proxy(0 as i32 as bit);
                                        (*conn).http_proxy.proxytype = CURLPROXY_HTTP;
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
    Curl_cfree.expect("non-null function pointer")(socksproxy as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(proxy as *mut libc::c_void);
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_parse_login_details(
    mut login: *const i8,
    len: size_t,
    mut userp: *mut *mut i8,
    mut passwdp: *mut *mut i8,
    mut optionsp: *mut *mut i8,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ubuf: *mut i8 = 0 as *mut i8;
    let mut pbuf: *mut i8 = 0 as *mut i8;
    let mut obuf: *mut i8 = 0 as *mut i8;
    let mut psep: *const i8 = 0 as *const i8;
    let mut osep: *const i8 = 0 as *const i8;
    let mut ulen: size_t = 0;
    let mut plen: size_t = 0;
    let mut olen: size_t = 0;
    let mut llen: size_t = strlen(login);
    if llen > 8000000 as i32 as u64 {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if !passwdp.is_null() {
        psep = strchr(login, ':' as i32);
        if psep >= login.offset(len as isize) {
            psep = 0 as *const i8;
        }
    }
    if !optionsp.is_null() {
        osep = strchr(login, ';' as i32);
        if osep >= login.offset(len as isize) {
            osep = 0 as *const i8;
        }
    }
    ulen = if !psep.is_null() {
        (if !osep.is_null() && psep > osep {
            osep.offset_from(login) as i64
        } else {
            psep.offset_from(login) as i64
        }) as size_t
    } else if !osep.is_null() {
        osep.offset_from(login) as i64 as size_t
    } else {
        len
    };
    plen = if !psep.is_null() {
        (if !osep.is_null() && osep > psep {
            osep.offset_from(psep) as i64 as size_t
        } else {
            login.offset(len as isize).offset_from(psep) as i64 as size_t
        })
            .wrapping_sub(1 as i32 as u64)
    } else {
        0 as i32 as u64
    };
    olen = if !osep.is_null() {
        (if !psep.is_null() && psep > osep {
            psep.offset_from(osep) as i64 as size_t
        } else {
            login.offset(len as isize).offset_from(osep) as i64 as size_t
        })
            .wrapping_sub(1 as i32 as u64)
    } else {
        0 as i32 as u64
    };
    if !userp.is_null() && ulen != 0 {
        ubuf = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )(ulen.wrapping_add(1 as i32 as u64)) as *mut i8;
        if ubuf.is_null() {
            result = CURLE_OUT_OF_MEMORY;
        }
    }
    if result as u64 == 0 && !passwdp.is_null() && plen != 0 {
        pbuf = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )(plen.wrapping_add(1 as i32 as u64)) as *mut i8;
        if pbuf.is_null() {
            Curl_cfree.expect("non-null function pointer")(ubuf as *mut libc::c_void);
            result = CURLE_OUT_OF_MEMORY;
        }
    }
    if result as u64 == 0 && !optionsp.is_null() && olen != 0 {
        obuf = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )(olen.wrapping_add(1 as i32 as u64)) as *mut i8;
        if obuf.is_null() {
            Curl_cfree.expect("non-null function pointer")(pbuf as *mut libc::c_void);
            Curl_cfree.expect("non-null function pointer")(ubuf as *mut libc::c_void);
            result = CURLE_OUT_OF_MEMORY;
        }
    }
    if result as u64 == 0 {
        if !ubuf.is_null() {
            memcpy(ubuf as *mut libc::c_void, login as *const libc::c_void, ulen);
            *ubuf.offset(ulen as isize) = '\u{0}' as i32 as i8;
            Curl_cfree.expect("non-null function pointer")(*userp as *mut libc::c_void);
            *userp = 0 as *mut i8;
            *userp = ubuf;
        }
        if !pbuf.is_null() {
            memcpy(
                pbuf as *mut libc::c_void,
                psep.offset(1 as i32 as isize) as *const libc::c_void,
                plen,
            );
            *pbuf.offset(plen as isize) = '\u{0}' as i32 as i8;
            Curl_cfree
                .expect("non-null function pointer")(*passwdp as *mut libc::c_void);
            *passwdp = 0 as *mut i8;
            *passwdp = pbuf;
        }
        if !obuf.is_null() {
            memcpy(
                obuf as *mut libc::c_void,
                osep.offset(1 as i32 as isize) as *const libc::c_void,
                olen,
            );
            *obuf.offset(olen as isize) = '\u{0}' as i32 as i8;
            Curl_cfree
                .expect("non-null function pointer")(*optionsp as *mut libc::c_void);
            *optionsp = 0 as *mut i8;
            *optionsp = obuf;
        }
    }
    return result;
}
unsafe extern "C" fn parse_remote_port(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    if (*data).set.use_port != 0 && ((*data).state).allow_port() as i32 != 0 {
        let mut portbuf: [i8; 16] = [0; 16];
        let mut uc: CURLUcode = CURLUE_OK;
        (*conn).remote_port = (*data).set.use_port as u16 as i32;
        curl_msnprintf(
            portbuf.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 16]>() as u64,
            b"%d\0" as *const u8 as *const i8,
            (*conn).remote_port,
        );
        uc = curl_url_set(
            (*data).state.uh,
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
unsafe extern "C" fn override_login(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut uc: CURLUcode = CURLUE_OK;
    let mut userp: *mut *mut i8 = &mut (*conn).user;
    let mut passwdp: *mut *mut i8 = &mut (*conn).passwd;
    let mut optionsp: *mut *mut i8 = &mut (*conn).options;
    if (*data).set.use_netrc as u32
        == CURL_NETRC_REQUIRED as i32 as u32
        && ((*conn).bits).user_passwd() as i32 != 0
    {
        Curl_cfree.expect("non-null function pointer")(*userp as *mut libc::c_void);
        *userp = 0 as *mut i8;
        Curl_cfree.expect("non-null function pointer")(*passwdp as *mut libc::c_void);
        *passwdp = 0 as *mut i8;
        let fresh167 = &mut ((*conn).bits);
        (*fresh167).set_user_passwd(0 as i32 as bit);
    }
    if !((*data).set.str_0[STRING_OPTIONS as i32 as usize]).is_null() {
        Curl_cfree.expect("non-null function pointer")(*optionsp as *mut libc::c_void);
        *optionsp = Curl_cstrdup
            .expect(
                "non-null function pointer",
            )((*data).set.str_0[STRING_OPTIONS as i32 as usize]);
        if (*optionsp).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    let fresh168 = &mut ((*conn).bits);
    (*fresh168).set_netrc(0 as i32 as bit);
    if (*data).set.use_netrc as u32 != 0
        && ((*data).set.str_0[STRING_USERNAME as i32 as usize]).is_null()
    {
        let mut netrc_user_changed: bool = 0 as i32 != 0;
        let mut netrc_passwd_changed: bool = 0 as i32 != 0;
        let mut ret: i32 = 0;
        ret = Curl_parsenetrc(
            (*conn).host.name,
            userp,
            passwdp,
            &mut netrc_user_changed,
            &mut netrc_passwd_changed,
            (*data).set.str_0[STRING_NETRC_FILE as i32 as usize],
        );
        if ret > 0 as i32 {
            Curl_infof(
                data,
                b"Couldn't find host %s in the %s file; using defaults\0" as *const u8
                    as *const i8,
                (*conn).host.name,
                (*data).set.str_0[STRING_NETRC_FILE as i32 as usize],
            );
        } else if ret < 0 as i32 {
            return CURLE_OUT_OF_MEMORY
        } else {
            let fresh169 = &mut ((*conn).bits);
            (*fresh169).set_netrc(1 as i32 as bit);
            let fresh170 = &mut ((*conn).bits);
            (*fresh170).set_user_passwd(1 as i32 as bit);
        }
    }
    if !(*userp).is_null() {
        let mut result: CURLcode = Curl_setstropt(&mut (*data).state.aptr.user, *userp);
        if result as u64 != 0 {
            return result;
        }
    }
    if !((*data).state.aptr.user).is_null() {
        uc = curl_url_set(
            (*data).state.uh,
            CURLUPART_USER,
            (*data).state.aptr.user,
            ((1 as i32) << 7 as i32) as u32,
        );
        if uc as u64 != 0 {
            return Curl_uc_to_curlcode(uc);
        }
        if (*userp).is_null() {
            *userp = Curl_cstrdup
                .expect("non-null function pointer")((*data).state.aptr.user);
            if (*userp).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        }
    }
    if !(*passwdp).is_null() {
        let mut result_0: CURLcode = Curl_setstropt(
            &mut (*data).state.aptr.passwd,
            *passwdp,
        );
        if result_0 as u64 != 0 {
            return result_0;
        }
    }
    if !((*data).state.aptr.passwd).is_null() {
        uc = curl_url_set(
            (*data).state.uh,
            CURLUPART_PASSWORD,
            (*data).state.aptr.passwd,
            ((1 as i32) << 7 as i32) as u32,
        );
        if uc as u64 != 0 {
            return Curl_uc_to_curlcode(uc);
        }
        if (*passwdp).is_null() {
            *passwdp = Curl_cstrdup
                .expect("non-null function pointer")((*data).state.aptr.passwd);
            if (*passwdp).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        }
    }
    return CURLE_OK;
}
unsafe extern "C" fn set_login(mut conn: *mut connectdata) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut setuser: *const i8 = b"anonymous\0" as *const u8
        as *const i8;
    let mut setpasswd: *const i8 = b"ftp@example.com\0" as *const u8
        as *const i8;
    if !((*(*conn).handler).flags
        & ((1 as i32) << 5 as i32) as u32 != 0
        && ((*conn).bits).user_passwd() == 0)
    {
        setuser = b"\0" as *const u8 as *const i8;
        setpasswd = b"\0" as *const u8 as *const i8;
    }
    if ((*conn).user).is_null() {
        let fresh171 = &mut ((*conn).user);
        *fresh171 = Curl_cstrdup.expect("non-null function pointer")(setuser);
        if ((*conn).user).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if ((*conn).passwd).is_null() {
        let fresh172 = &mut ((*conn).passwd);
        *fresh172 = Curl_cstrdup.expect("non-null function pointer")(setpasswd);
        if ((*conn).passwd).is_null() {
            result = CURLE_OUT_OF_MEMORY;
        }
    }
    return result;
}
unsafe extern "C" fn parse_connect_to_host_port(
    mut data: *mut Curl_easy,
    mut host: *const i8,
    mut hostname_result: *mut *mut i8,
    mut port_result: *mut i32,
) -> CURLcode {
    let mut current_block: u64;
    let mut host_dup: *mut i8 = 0 as *mut i8;
    let mut hostptr: *mut i8 = 0 as *mut i8;
    let mut host_portno: *mut i8 = 0 as *mut i8;
    let mut portptr: *mut i8 = 0 as *mut i8;
    let mut port: i32 = -(1 as i32);
    let mut result: CURLcode = CURLE_OK;
    *hostname_result = 0 as *mut i8;
    *port_result = -(1 as i32);
    if host.is_null() || *host == 0 {
        return CURLE_OK;
    }
    host_dup = Curl_cstrdup.expect("non-null function pointer")(host);
    if host_dup.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    hostptr = host_dup;
    portptr = hostptr;
    if *hostptr as i32 == '[' as i32 {
        hostptr = hostptr.offset(1);
        let mut ptr: *mut i8 = hostptr;
        while *ptr as i32 != 0
            && (Curl_isxdigit(*ptr as u8 as i32) != 0
                || *ptr as i32 == ':' as i32
                || *ptr as i32 == '.' as i32)
        {
            ptr = ptr.offset(1);
        }
        if *ptr as i32 == '%' as i32 {
            if strncmp(
                b"%25\0" as *const u8 as *const i8,
                ptr,
                3 as i32 as u64,
            ) != 0
            {
                Curl_infof(
                    data,
                    b"Please URL encode %% as %%25, see RFC 6874.\0" as *const u8
                        as *const i8,
                );
            }
            ptr = ptr.offset(1);
            while *ptr as i32 != 0
                && (Curl_isalpha(*ptr as u8 as i32) != 0
                    || Curl_isxdigit(*ptr as u8 as i32) != 0
                    || *ptr as i32 == '-' as i32
                    || *ptr as i32 == '.' as i32
                    || *ptr as i32 == '_' as i32
                    || *ptr as i32 == '~' as i32)
            {
                ptr = ptr.offset(1);
            }
        }
        if *ptr as i32 == ']' as i32 {
            let fresh173 = ptr;
            ptr = ptr.offset(1);
            *fresh173 = '\u{0}' as i32 as i8;
        } else {
            Curl_infof(
                data,
                b"Invalid IPv6 address format\0" as *const u8 as *const i8,
            );
        }
        portptr = ptr;
    }
    host_portno = strchr(portptr, ':' as i32);
    if !host_portno.is_null() {
        let mut endp: *mut i8 = 0 as *mut i8;
        *host_portno = '\u{0}' as i32 as i8;
        host_portno = host_portno.offset(1);
        if *host_portno != 0 {
            let mut portparse: i64 = strtol(
                host_portno,
                &mut endp,
                10 as i32,
            );
            if !endp.is_null() && *endp as i32 != 0
                || portparse < 0 as i32 as i64
                || portparse > 65535 as i32 as i64
            {
                Curl_failf(
                    data,
                    b"No valid port number in connect to host string (%s)\0" as *const u8
                        as *const i8,
                    host_portno,
                );
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
                *hostname_result = Curl_cstrdup
                    .expect("non-null function pointer")(hostptr);
                if (*hostname_result).is_null() {
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
                    *port_result = port;
                }
            }
        }
        _ => {}
    }
    Curl_cfree.expect("non-null function pointer")(host_dup as *mut libc::c_void);
    return result;
}
unsafe extern "C" fn parse_connect_to_string(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut conn_to_host: *const i8,
    mut host_result: *mut *mut i8,
    mut port_result: *mut i32,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ptr: *const i8 = conn_to_host;
    let mut host_match: i32 = 0 as i32;
    let mut port_match: i32 = 0 as i32;
    *host_result = 0 as *mut i8;
    *port_result = -(1 as i32);
    if *ptr as i32 == ':' as i32 {
        host_match = 1 as i32;
        ptr = ptr.offset(1);
    } else {
        let mut hostname_to_match_len: size_t = 0;
        let mut hostname_to_match: *mut i8 = curl_maprintf(
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
        );
        if hostname_to_match.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        hostname_to_match_len = strlen(hostname_to_match);
        host_match = Curl_strncasecompare(ptr, hostname_to_match, hostname_to_match_len);
        Curl_cfree
            .expect("non-null function pointer")(hostname_to_match as *mut libc::c_void);
        ptr = ptr.offset(hostname_to_match_len as isize);
        host_match = (host_match != 0 && *ptr as i32 == ':' as i32)
            as i32;
        ptr = ptr.offset(1);
    }
    if host_match != 0 {
        if *ptr as i32 == ':' as i32 {
            port_match = 1 as i32;
            ptr = ptr.offset(1);
        } else {
            let mut ptr_next: *mut i8 = strchr(ptr, ':' as i32);
            if !ptr_next.is_null() {
                let mut endp: *mut i8 = 0 as *mut i8;
                let mut port_to_match: i64 = strtol(
                    ptr,
                    &mut endp,
                    10 as i32,
                );
                if endp == ptr_next
                    && port_to_match == (*conn).remote_port as i64
                {
                    port_match = 1 as i32;
                    ptr = ptr_next.offset(1 as i32 as isize);
                }
            }
        }
    }
    if host_match != 0 && port_match != 0 {
        result = parse_connect_to_host_port(data, ptr, host_result, port_result);
    }
    return result;
}
unsafe extern "C" fn parse_connect_to_slist(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut conn_to_host: *mut curl_slist,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut host: *mut i8 = 0 as *mut i8;
    let mut port: i32 = -(1 as i32);
    while !conn_to_host.is_null() && host.is_null() && port == -(1 as i32) {
        result = parse_connect_to_string(
            data,
            conn,
            (*conn_to_host).data,
            &mut host,
            &mut port,
        );
        if result as u64 != 0 {
            return result;
        }
        if !host.is_null() && *host as i32 != 0 {
            let fresh174 = &mut ((*conn).conn_to_host.rawalloc);
            *fresh174 = host;
            let fresh175 = &mut ((*conn).conn_to_host.name);
            *fresh175 = host;
            let fresh176 = &mut ((*conn).bits);
            (*fresh176).set_conn_to_host(1 as i32 as bit);
            Curl_infof(
                data,
                b"Connecting to hostname: %s\0" as *const u8 as *const i8,
                host,
            );
        } else {
            let fresh177 = &mut ((*conn).bits);
            (*fresh177).set_conn_to_host(0 as i32 as bit);
            Curl_cfree.expect("non-null function pointer")(host as *mut libc::c_void);
            host = 0 as *mut i8;
        }
        if port >= 0 as i32 {
            (*conn).conn_to_port = port;
            let fresh178 = &mut ((*conn).bits);
            (*fresh178).set_conn_to_port(1 as i32 as bit);
            Curl_infof(
                data,
                b"Connecting to port: %d\0" as *const u8 as *const i8,
                port,
            );
        } else {
            let fresh179 = &mut ((*conn).bits);
            (*fresh179).set_conn_to_port(0 as i32 as bit);
            port = -(1 as i32);
        }
        conn_to_host = (*conn_to_host).next;
    }
    if !((*data).asi).is_null() && host.is_null() && port == -(1 as i32)
        && ((*(*conn).handler).protocol
            == ((1 as i32) << 1 as i32) as u32
            || 0 as i32 != 0)
    {
        let mut srcalpnid: alpnid = ALPN_none;
        let mut hit: bool = false;
        let mut as_0: *mut altsvc = 0 as *mut altsvc;
        let allowed_versions: i32 = ((ALPN_h1 as i32
            | ALPN_h2 as i32) as i64 & (*(*data).asi).flags)
            as i32;
        host = (*conn).host.rawalloc;
        srcalpnid = ALPN_h2;
        hit = Curl_altsvc_lookup(
            (*data).asi,
            srcalpnid,
            host,
            (*conn).remote_port,
            &mut as_0,
            allowed_versions,
        );
        if !hit {
            srcalpnid = ALPN_h1;
            hit = Curl_altsvc_lookup(
                (*data).asi,
                srcalpnid,
                host,
                (*conn).remote_port,
                &mut as_0,
                allowed_versions,
            );
        }
        if hit {
            let mut hostd: *mut i8 = Curl_cstrdup
                .expect("non-null function pointer")((*as_0).dst.host);
            if hostd.is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            let fresh180 = &mut ((*conn).conn_to_host.rawalloc);
            *fresh180 = hostd;
            let fresh181 = &mut ((*conn).conn_to_host.name);
            *fresh181 = hostd;
            let fresh182 = &mut ((*conn).bits);
            (*fresh182).set_conn_to_host(1 as i32 as bit);
            (*conn).conn_to_port = (*as_0).dst.port as i32;
            let fresh183 = &mut ((*conn).bits);
            (*fresh183).set_conn_to_port(1 as i32 as bit);
            let fresh184 = &mut ((*conn).bits);
            (*fresh184).set_altused(1 as i32 as bit);
            Curl_infof(
                data,
                b"Alt-svc connecting from [%s]%s:%d to [%s]%s:%d\0" as *const u8
                    as *const i8,
                Curl_alpnid2str(srcalpnid),
                host,
                (*conn).remote_port,
                Curl_alpnid2str((*as_0).dst.alpnid),
                hostd,
                (*as_0).dst.port as i32,
            );
            if srcalpnid as u32 != (*as_0).dst.alpnid as u32 {
                match (*as_0).dst.alpnid as u32 {
                    8 => {
                        (*conn).httpversion = 11 as i32 as u8;
                    }
                    16 => {
                        (*conn).httpversion = 20 as i32 as u8;
                    }
                    32 => {
                        (*conn).transport = TRNSPRT_QUIC;
                        (*conn).httpversion = 30 as i32 as u8;
                    }
                    _ => {}
                }
            }
        }
    }
    return result;
}
unsafe extern "C" fn resolve_server(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut async_0: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut timeout_ms: timediff_t = Curl_timeleft(
        data,
        0 as *mut curltime,
        1 as i32 != 0,
    );
    if ((*conn).bits).reuse() != 0 {
        *async_0 = 0 as i32 != 0;
    } else {
        let mut rc: i32 = 0;
        let mut hostaddr: *mut Curl_dns_entry = 0 as *mut Curl_dns_entry;
        if !((*conn).unix_domain_socket).is_null() {
            let mut path: *const i8 = (*conn).unix_domain_socket;
            hostaddr = Curl_ccalloc
                .expect(
                    "non-null function pointer",
                )(
                1 as i32 as size_t,
                ::std::mem::size_of::<Curl_dns_entry>() as u64,
            ) as *mut Curl_dns_entry;
            if hostaddr.is_null() {
                result = CURLE_OUT_OF_MEMORY;
            } else {
                let mut longpath: bool = 0 as i32 != 0;
                let fresh185 = &mut ((*hostaddr).addr);
                *fresh185 = Curl_unix2addr(
                    path,
                    &mut longpath,
                    ((*conn).bits).abstract_unix_socket() != 0,
                );
                if !((*hostaddr).addr).is_null() {
                    let fresh186 = &mut ((*hostaddr).inuse);
                    *fresh186 += 1;
                } else {
                    if longpath {
                        Curl_failf(
                            data,
                            b"Unix socket path too long: '%s'\0" as *const u8
                                as *const i8,
                            path,
                        );
                        result = CURLE_COULDNT_RESOLVE_HOST;
                    } else {
                        result = CURLE_OUT_OF_MEMORY;
                    }
                    Curl_cfree
                        .expect(
                            "non-null function pointer",
                        )(hostaddr as *mut libc::c_void);
                    hostaddr = 0 as *mut Curl_dns_entry;
                }
            }
        } else if ((*conn).bits).proxy() == 0 {
            let mut connhost: *mut hostname = 0 as *mut hostname;
            if ((*conn).bits).conn_to_host() != 0 {
                connhost = &mut (*conn).conn_to_host;
            } else {
                connhost = &mut (*conn).host;
            }
            if ((*conn).bits).conn_to_port() != 0 {
                (*conn).port = (*conn).conn_to_port;
            } else {
                (*conn).port = (*conn).remote_port;
            }
            let fresh187 = &mut ((*conn).hostname_resolve);
            *fresh187 = Curl_cstrdup
                .expect("non-null function pointer")((*connhost).name);
            if ((*conn).hostname_resolve).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            rc = Curl_resolv_timeout(
                data,
                (*conn).hostname_resolve,
                (*conn).port,
                &mut hostaddr,
                timeout_ms,
            ) as i32;
            if rc == CURLRESOLV_PENDING as i32 {
                *async_0 = 1 as i32 != 0;
            } else if rc == CURLRESOLV_TIMEDOUT as i32 {
                Curl_failf(
                    data,
                    b"Failed to resolve host '%s' with timeout after %ld ms\0"
                        as *const u8 as *const i8,
                    (*connhost).dispname,
                    Curl_timediff(Curl_now(), (*data).progress.t_startsingle),
                );
                result = CURLE_OPERATION_TIMEDOUT;
            } else if hostaddr.is_null() {
                Curl_failf(
                    data,
                    b"Could not resolve host: %s\0" as *const u8 as *const i8,
                    (*connhost).dispname,
                );
                result = CURLE_COULDNT_RESOLVE_HOST;
            }
        } else {
            let host: *mut hostname = if ((*conn).bits).socksproxy() as i32 != 0
            {
                &mut (*conn).socks_proxy.host
            } else {
                &mut (*conn).http_proxy.host
            };
            let fresh188 = &mut ((*conn).hostname_resolve);
            *fresh188 = Curl_cstrdup.expect("non-null function pointer")((*host).name);
            if ((*conn).hostname_resolve).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            rc = Curl_resolv_timeout(
                data,
                (*conn).hostname_resolve,
                (*conn).port,
                &mut hostaddr,
                timeout_ms,
            ) as i32;
            if rc == CURLRESOLV_PENDING as i32 {
                *async_0 = 1 as i32 != 0;
            } else if rc == CURLRESOLV_TIMEDOUT as i32 {
                result = CURLE_OPERATION_TIMEDOUT;
            } else if hostaddr.is_null() {
                Curl_failf(
                    data,
                    b"Couldn't resolve proxy '%s'\0" as *const u8 as *const i8,
                    (*host).dispname,
                );
                result = CURLE_COULDNT_RESOLVE_PROXY;
            }
        }
        let fresh189 = &mut ((*conn).dns_entry);
        *fresh189 = hostaddr;
    }
    return result;
}
unsafe extern "C" fn reuse_conn(
    mut data: *mut Curl_easy,
    mut old_conn: *mut connectdata,
    mut conn: *mut connectdata,
) {
    let mut local_ip: [i8; 46] = *::std::mem::transmute::<
        &[u8; 46],
        &mut [i8; 46],
    >(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut local_port: i32 = -(1 as i32);
    Curl_free_idnconverted_hostname(&mut (*old_conn).http_proxy.host);
    Curl_free_idnconverted_hostname(&mut (*old_conn).socks_proxy.host);
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*old_conn).http_proxy.host.rawalloc as *mut libc::c_void);
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*old_conn).socks_proxy.host.rawalloc as *mut libc::c_void);
    Curl_free_primary_ssl_config(&mut (*old_conn).proxy_ssl_config);
    Curl_free_primary_ssl_config(&mut (*old_conn).ssl_config);
    let fresh190 = &mut ((*conn).bits);
    (*fresh190).set_user_passwd(((*old_conn).bits).user_passwd());
    if ((*conn).bits).user_passwd() != 0 {
        Curl_cfree
            .expect("non-null function pointer")((*conn).user as *mut libc::c_void);
        let fresh191 = &mut ((*conn).user);
        *fresh191 = 0 as *mut i8;
        Curl_cfree
            .expect("non-null function pointer")((*conn).passwd as *mut libc::c_void);
        let fresh192 = &mut ((*conn).passwd);
        *fresh192 = 0 as *mut i8;
        let fresh193 = &mut ((*conn).user);
        *fresh193 = (*old_conn).user;
        let fresh194 = &mut ((*conn).passwd);
        *fresh194 = (*old_conn).passwd;
        let fresh195 = &mut ((*old_conn).user);
        *fresh195 = 0 as *mut i8;
        let fresh196 = &mut ((*old_conn).passwd);
        *fresh196 = 0 as *mut i8;
    }
    let fresh197 = &mut ((*conn).bits);
    (*fresh197).set_proxy_user_passwd(((*old_conn).bits).proxy_user_passwd());
    if ((*conn).bits).proxy_user_passwd() != 0 {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*conn).http_proxy.user as *mut libc::c_void);
        let fresh198 = &mut ((*conn).http_proxy.user);
        *fresh198 = 0 as *mut i8;
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*conn).socks_proxy.user as *mut libc::c_void);
        let fresh199 = &mut ((*conn).socks_proxy.user);
        *fresh199 = 0 as *mut i8;
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*conn).http_proxy.passwd as *mut libc::c_void);
        let fresh200 = &mut ((*conn).http_proxy.passwd);
        *fresh200 = 0 as *mut i8;
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*conn).socks_proxy.passwd as *mut libc::c_void);
        let fresh201 = &mut ((*conn).socks_proxy.passwd);
        *fresh201 = 0 as *mut i8;
        let fresh202 = &mut ((*conn).http_proxy.user);
        *fresh202 = (*old_conn).http_proxy.user;
        let fresh203 = &mut ((*conn).socks_proxy.user);
        *fresh203 = (*old_conn).socks_proxy.user;
        let fresh204 = &mut ((*conn).http_proxy.passwd);
        *fresh204 = (*old_conn).http_proxy.passwd;
        let fresh205 = &mut ((*conn).socks_proxy.passwd);
        *fresh205 = (*old_conn).socks_proxy.passwd;
        let fresh206 = &mut ((*old_conn).http_proxy.user);
        *fresh206 = 0 as *mut i8;
        let fresh207 = &mut ((*old_conn).socks_proxy.user);
        *fresh207 = 0 as *mut i8;
        let fresh208 = &mut ((*old_conn).http_proxy.passwd);
        *fresh208 = 0 as *mut i8;
        let fresh209 = &mut ((*old_conn).socks_proxy.passwd);
        *fresh209 = 0 as *mut i8;
    }
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*old_conn).http_proxy.user as *mut libc::c_void);
    let fresh210 = &mut ((*old_conn).http_proxy.user);
    *fresh210 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*old_conn).socks_proxy.user as *mut libc::c_void);
    let fresh211 = &mut ((*old_conn).socks_proxy.user);
    *fresh211 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*old_conn).http_proxy.passwd as *mut libc::c_void);
    let fresh212 = &mut ((*old_conn).http_proxy.passwd);
    *fresh212 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*old_conn).socks_proxy.passwd as *mut libc::c_void);
    let fresh213 = &mut ((*old_conn).socks_proxy.passwd);
    *fresh213 = 0 as *mut i8;
    Curl_free_idnconverted_hostname(&mut (*conn).host);
    Curl_free_idnconverted_hostname(&mut (*conn).conn_to_host);
    Curl_cfree
        .expect("non-null function pointer")((*conn).host.rawalloc as *mut libc::c_void);
    let fresh214 = &mut ((*conn).host.rawalloc);
    *fresh214 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).conn_to_host.rawalloc as *mut libc::c_void);
    let fresh215 = &mut ((*conn).conn_to_host.rawalloc);
    *fresh215 = 0 as *mut i8;
    (*conn).host = (*old_conn).host;
    (*conn).conn_to_host = (*old_conn).conn_to_host;
    (*conn).conn_to_port = (*old_conn).conn_to_port;
    (*conn).remote_port = (*old_conn).remote_port;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).hostname_resolve as *mut libc::c_void);
    let fresh216 = &mut ((*conn).hostname_resolve);
    *fresh216 = 0 as *mut i8;
    let fresh217 = &mut ((*conn).hostname_resolve);
    *fresh217 = (*old_conn).hostname_resolve;
    let fresh218 = &mut ((*old_conn).hostname_resolve);
    *fresh218 = 0 as *mut i8;
    if (*conn).transport as u32 == TRNSPRT_TCP as i32 as u32 {
        Curl_conninfo_local(
            data,
            (*conn).sock[0 as i32 as usize],
            local_ip.as_mut_ptr(),
            &mut local_port,
        );
    }
    Curl_persistconninfo(data, conn, local_ip.as_mut_ptr(), local_port);
    let fresh219 = &mut ((*conn).bits);
    (*fresh219).set_reuse(1 as i32 as bit);
    Curl_cfree
        .expect("non-null function pointer")((*old_conn).user as *mut libc::c_void);
    let fresh220 = &mut ((*old_conn).user);
    *fresh220 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*old_conn).passwd as *mut libc::c_void);
    let fresh221 = &mut ((*old_conn).passwd);
    *fresh221 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*old_conn).options as *mut libc::c_void);
    let fresh222 = &mut ((*old_conn).options);
    *fresh222 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*old_conn).localdev as *mut libc::c_void);
    let fresh223 = &mut ((*old_conn).localdev);
    *fresh223 = 0 as *mut i8;
    Curl_llist_destroy(&mut (*old_conn).easyq, 0 as *mut libc::c_void);
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*old_conn).unix_domain_socket as *mut libc::c_void);
    let fresh224 = &mut ((*old_conn).unix_domain_socket);
    *fresh224 = 0 as *mut i8;
}
unsafe extern "C" fn create_conn(
    mut data: *mut Curl_easy,
    mut in_connect: *mut *mut connectdata,
    mut async_0: *mut bool,
) -> CURLcode {
    let mut current_block: u64;
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = 0 as *mut connectdata;
    let mut conn_temp: *mut connectdata = 0 as *mut connectdata;
    let mut reuse: bool = false;
    let mut connections_available: bool = 1 as i32 != 0;
    let mut force_reuse: bool = 0 as i32 != 0;
    let mut waitpipe: bool = 0 as i32 != 0;
    let mut max_host_connections: size_t = Curl_multi_max_host_connections(
        (*data).multi,
    );
    let mut max_total_connections: size_t = Curl_multi_max_total_connections(
        (*data).multi,
    );
    *async_0 = 0 as i32 != 0;
    *in_connect = 0 as *mut connectdata;
    if ((*data).state.url).is_null() {
        result = CURLE_URL_MALFORMAT;
    } else {
        conn = allocate_conn(data);
        if conn.is_null() {
            result = CURLE_OUT_OF_MEMORY;
        } else {
            *in_connect = conn;
            result = parseurlandfillconn(data, conn);
            if !(result as u64 != 0) {
                if !((*data).set.str_0[STRING_SASL_AUTHZID as i32 as usize])
                    .is_null()
                {
                    let fresh225 = &mut ((*conn).sasl_authzid);
                    *fresh225 = Curl_cstrdup
                        .expect(
                            "non-null function pointer",
                        )(
                        (*data).set.str_0[STRING_SASL_AUTHZID as i32 as usize],
                    );
                    if ((*conn).sasl_authzid).is_null() {
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
                        if !((*data)
                            .set
                            .str_0[STRING_UNIX_SOCKET_PATH as i32 as usize])
                            .is_null()
                        {
                            let fresh226 = &mut ((*conn).unix_domain_socket);
                            *fresh226 = Curl_cstrdup
                                .expect(
                                    "non-null function pointer",
                                )(
                                (*data)
                                    .set
                                    .str_0[STRING_UNIX_SOCKET_PATH as i32 as usize],
                            );
                            if ((*conn).unix_domain_socket).is_null() {
                                result = CURLE_OUT_OF_MEMORY;
                                current_block = 4631372686411729056;
                            } else {
                                let fresh227 = &mut ((*conn).bits);
                                (*fresh227)
                                    .set_abstract_unix_socket(
                                        ((*data).set).abstract_unix_socket(),
                                    );
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
                                    if (*(*conn).given).flags
                                        & ((1 as i32) << 0 as i32) as u32
                                        != 0 && ((*conn).bits).httpproxy() as i32 != 0
                                    {
                                        let fresh228 = &mut ((*conn).bits);
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
                                                    (*data).set.connect_to,
                                                );
                                                if !(result as u64 != 0) {
                                                    result = Curl_idnconvert_hostname(data, &mut (*conn).host);
                                                    if !(result as u64 != 0) {
                                                        if ((*conn).bits).conn_to_host() != 0 {
                                                            result = Curl_idnconvert_hostname(
                                                                data,
                                                                &mut (*conn).conn_to_host,
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
                                                                if ((*conn).bits).httpproxy() != 0 {
                                                                    result = Curl_idnconvert_hostname(
                                                                        data,
                                                                        &mut (*conn).http_proxy.host,
                                                                    );
                                                                    if result as u64 != 0 {
                                                                        current_block = 4631372686411729056;
                                                                    } else {
                                                                        current_block = 14775119014532381840;
                                                                    }
                                                                } else {
                                                                    current_block = 14775119014532381840;
                                                                }
                                                                match current_block {
                                                                    4631372686411729056 => {}
                                                                    _ => {
                                                                        if ((*conn).bits).socksproxy() != 0 {
                                                                            result = Curl_idnconvert_hostname(
                                                                                data,
                                                                                &mut (*conn).socks_proxy.host,
                                                                            );
                                                                            if result as u64 != 0 {
                                                                                current_block = 4631372686411729056;
                                                                            } else {
                                                                                current_block = 5141539773904409130;
                                                                            }
                                                                        } else {
                                                                            current_block = 5141539773904409130;
                                                                        }
                                                                        match current_block {
                                                                            4631372686411729056 => {}
                                                                            _ => {
                                                                                if ((*conn).bits).conn_to_host() as i32 != 0
                                                                                    && Curl_strcasecompare(
                                                                                        (*conn).conn_to_host.name,
                                                                                        (*conn).host.name,
                                                                                    ) != 0
                                                                                {
                                                                                    let fresh229 = &mut ((*conn).bits);
                                                                                    (*fresh229).set_conn_to_host(0 as i32 as bit);
                                                                                }
                                                                                if ((*conn).bits).conn_to_port() as i32 != 0
                                                                                    && (*conn).conn_to_port == (*conn).remote_port
                                                                                {
                                                                                    let fresh230 = &mut ((*conn).bits);
                                                                                    (*fresh230).set_conn_to_port(0 as i32 as bit);
                                                                                }
                                                                                if (((*conn).bits).conn_to_host() as i32 != 0
                                                                                    || ((*conn).bits).conn_to_port() as i32 != 0)
                                                                                    && ((*conn).bits).httpproxy() as i32 != 0
                                                                                {
                                                                                    let fresh231 = &mut ((*conn).bits);
                                                                                    (*fresh231).set_tunnel_proxy(1 as i32 as bit);
                                                                                }
                                                                                result = setup_connection_internals(data, conn);
                                                                                if !(result as u64 != 0) {
                                                                                    let fresh232 = &mut ((*conn)
                                                                                        .recv[0 as i32 as usize]);
                                                                                    *fresh232 = Some(
                                                                                        Curl_recv_plain
                                                                                            as unsafe extern "C" fn(
                                                                                                *mut Curl_easy,
                                                                                                i32,
                                                                                                *mut i8,
                                                                                                size_t,
                                                                                                *mut CURLcode,
                                                                                            ) -> ssize_t,
                                                                                    );
                                                                                    let fresh233 = &mut ((*conn)
                                                                                        .send[0 as i32 as usize]);
                                                                                    *fresh233 = Some(
                                                                                        Curl_send_plain
                                                                                            as unsafe extern "C" fn(
                                                                                                *mut Curl_easy,
                                                                                                i32,
                                                                                                *const libc::c_void,
                                                                                                size_t,
                                                                                                *mut CURLcode,
                                                                                            ) -> ssize_t,
                                                                                    );
                                                                                    let fresh234 = &mut ((*conn)
                                                                                        .recv[1 as i32 as usize]);
                                                                                    *fresh234 = Some(
                                                                                        Curl_recv_plain
                                                                                            as unsafe extern "C" fn(
                                                                                                *mut Curl_easy,
                                                                                                i32,
                                                                                                *mut i8,
                                                                                                size_t,
                                                                                                *mut CURLcode,
                                                                                            ) -> ssize_t,
                                                                                    );
                                                                                    let fresh235 = &mut ((*conn)
                                                                                        .send[1 as i32 as usize]);
                                                                                    *fresh235 = Some(
                                                                                        Curl_send_plain
                                                                                            as unsafe extern "C" fn(
                                                                                                *mut Curl_easy,
                                                                                                i32,
                                                                                                *const libc::c_void,
                                                                                                size_t,
                                                                                                *mut CURLcode,
                                                                                            ) -> ssize_t,
                                                                                    );
                                                                                    let fresh236 = &mut ((*conn).bits);
                                                                                    (*fresh236).set_tcp_fastopen(((*data).set).tcp_fastopen());
                                                                                    if (*(*conn).handler).flags
                                                                                        & ((1 as i32) << 4 as i32) as u32
                                                                                        != 0
                                                                                    {
                                                                                        let mut done: bool = false;
                                                                                        Curl_persistconninfo(
                                                                                            data,
                                                                                            conn,
                                                                                            0 as *mut i8,
                                                                                            -(1 as i32),
                                                                                        );
                                                                                        result = ((*(*conn).handler).connect_it)
                                                                                            .expect("non-null function pointer")(data, &mut done);
                                                                                        if result as u64 == 0 {
                                                                                            (*conn)
                                                                                                .bits
                                                                                                .tcpconnect[0 as i32
                                                                                                as usize] = 1 as i32 != 0;
                                                                                            Curl_attach_connnection(data, conn);
                                                                                            result = Curl_conncache_add_conn(data);
                                                                                            if result as u64 != 0 {
                                                                                                current_block = 4631372686411729056;
                                                                                            } else {
                                                                                                result = setup_range(data);
                                                                                                if result as u64 != 0 {
                                                                                                    ((*(*conn).handler).done)
                                                                                                        .expect(
                                                                                                            "non-null function pointer",
                                                                                                        )(data, result, 0 as i32 != 0);
                                                                                                    current_block = 4631372686411729056;
                                                                                                } else {
                                                                                                    Curl_setup_transfer(
                                                                                                        data,
                                                                                                        -(1 as i32),
                                                                                                        -(1 as i32) as curl_off_t,
                                                                                                        0 as i32 != 0,
                                                                                                        -(1 as i32),
                                                                                                    );
                                                                                                    current_block = 17019156190352891614;
                                                                                                }
                                                                                            }
                                                                                        } else {
                                                                                            current_block = 17019156190352891614;
                                                                                        }
                                                                                        match current_block {
                                                                                            4631372686411729056 => {}
                                                                                            _ => {
                                                                                                Curl_init_do(data, conn);
                                                                                            }
                                                                                        }
                                                                                    } else {
                                                                                        let fresh237 = &mut ((*data).set.ssl.primary.CApath);
                                                                                        *fresh237 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CAPATH as i32 as usize];
                                                                                        let fresh238 = &mut ((*data).set.ssl.primary.CAfile);
                                                                                        *fresh238 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CAFILE as i32 as usize];
                                                                                        let fresh239 = &mut ((*data).set.ssl.primary.issuercert);
                                                                                        *fresh239 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_ISSUERCERT as i32 as usize];
                                                                                        let fresh240 = &mut ((*data)
                                                                                            .set
                                                                                            .ssl
                                                                                            .primary
                                                                                            .issuercert_blob);
                                                                                        *fresh240 = (*data)
                                                                                            .set
                                                                                            .blobs[BLOB_SSL_ISSUERCERT as i32 as usize];
                                                                                        let fresh241 = &mut ((*data).set.ssl.primary.random_file);
                                                                                        *fresh241 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_RANDOM_FILE as i32 as usize];
                                                                                        let fresh242 = &mut ((*data).set.ssl.primary.egdsocket);
                                                                                        *fresh242 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_EGDSOCKET as i32 as usize];
                                                                                        let fresh243 = &mut ((*data).set.ssl.primary.cipher_list);
                                                                                        *fresh243 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CIPHER_LIST as i32 as usize];
                                                                                        let fresh244 = &mut ((*data)
                                                                                            .set
                                                                                            .ssl
                                                                                            .primary
                                                                                            .cipher_list13);
                                                                                        *fresh244 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CIPHER13_LIST as i32 as usize];
                                                                                        let fresh245 = &mut ((*data).set.ssl.primary.pinned_key);
                                                                                        *fresh245 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_PINNEDPUBLICKEY as i32 as usize];
                                                                                        let fresh246 = &mut ((*data).set.ssl.primary.cert_blob);
                                                                                        *fresh246 = (*data)
                                                                                            .set
                                                                                            .blobs[BLOB_CERT as i32 as usize];
                                                                                        let fresh247 = &mut ((*data).set.ssl.primary.ca_info_blob);
                                                                                        *fresh247 = (*data)
                                                                                            .set
                                                                                            .blobs[BLOB_CAINFO as i32 as usize];
                                                                                        let fresh248 = &mut ((*data).set.ssl.primary.curves);
                                                                                        *fresh248 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_EC_CURVES as i32 as usize];
                                                                                        let fresh249 = &mut ((*data).set.proxy_ssl.primary.CApath);
                                                                                        *fresh249 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CAPATH_PROXY as i32 as usize];
                                                                                        let fresh250 = &mut ((*data).set.proxy_ssl.primary.CAfile);
                                                                                        *fresh250 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CAFILE_PROXY as i32 as usize];
                                                                                        let fresh251 = &mut ((*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .random_file);
                                                                                        *fresh251 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_RANDOM_FILE as i32 as usize];
                                                                                        let fresh252 = &mut ((*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .egdsocket);
                                                                                        *fresh252 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_EGDSOCKET as i32 as usize];
                                                                                        let fresh253 = &mut ((*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .cipher_list);
                                                                                        *fresh253 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CIPHER_LIST_PROXY as i32
                                                                                            as usize];
                                                                                        let fresh254 = &mut ((*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .cipher_list13);
                                                                                        *fresh254 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CIPHER13_LIST_PROXY as i32
                                                                                            as usize];
                                                                                        let fresh255 = &mut ((*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .pinned_key);
                                                                                        *fresh255 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_PINNEDPUBLICKEY_PROXY as i32
                                                                                            as usize];
                                                                                        let fresh256 = &mut ((*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .cert_blob);
                                                                                        *fresh256 = (*data)
                                                                                            .set
                                                                                            .blobs[BLOB_CERT_PROXY as i32 as usize];
                                                                                        let fresh257 = &mut ((*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .ca_info_blob);
                                                                                        *fresh257 = (*data)
                                                                                            .set
                                                                                            .blobs[BLOB_CAINFO_PROXY as i32 as usize];
                                                                                        let fresh258 = &mut ((*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .issuercert);
                                                                                        *fresh258 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_ISSUERCERT_PROXY as i32 as usize];
                                                                                        let fresh259 = &mut ((*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .issuercert_blob);
                                                                                        *fresh259 = (*data)
                                                                                            .set
                                                                                            .blobs[BLOB_SSL_ISSUERCERT_PROXY as i32 as usize];
                                                                                        let fresh260 = &mut ((*data).set.proxy_ssl.CRLfile);
                                                                                        *fresh260 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CRLFILE_PROXY as i32 as usize];
                                                                                        let fresh261 = &mut ((*data).set.proxy_ssl.cert_type);
                                                                                        *fresh261 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_CERT_TYPE_PROXY as i32 as usize];
                                                                                        let fresh262 = &mut ((*data).set.proxy_ssl.key);
                                                                                        *fresh262 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_KEY_PROXY as i32 as usize];
                                                                                        let fresh263 = &mut ((*data).set.proxy_ssl.key_type);
                                                                                        *fresh263 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_KEY_TYPE_PROXY as i32 as usize];
                                                                                        let fresh264 = &mut ((*data).set.proxy_ssl.key_passwd);
                                                                                        *fresh264 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_KEY_PASSWD_PROXY as i32 as usize];
                                                                                        let fresh265 = &mut ((*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .clientcert);
                                                                                        *fresh265 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_CERT_PROXY as i32 as usize];
                                                                                        let fresh266 = &mut ((*data).set.proxy_ssl.key_blob);
                                                                                        *fresh266 = (*data)
                                                                                            .set
                                                                                            .blobs[BLOB_KEY_PROXY as i32 as usize];
                                                                                        let fresh267 = &mut ((*data).set.ssl.CRLfile);
                                                                                        *fresh267 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CRLFILE as i32 as usize];
                                                                                        let fresh268 = &mut ((*data).set.ssl.cert_type);
                                                                                        *fresh268 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_CERT_TYPE as i32 as usize];
                                                                                        let fresh269 = &mut ((*data).set.ssl.key);
                                                                                        *fresh269 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_KEY as i32 as usize];
                                                                                        let fresh270 = &mut ((*data).set.ssl.key_type);
                                                                                        *fresh270 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_KEY_TYPE as i32 as usize];
                                                                                        let fresh271 = &mut ((*data).set.ssl.key_passwd);
                                                                                        *fresh271 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_KEY_PASSWD as i32 as usize];
                                                                                        let fresh272 = &mut ((*data).set.ssl.primary.clientcert);
                                                                                        *fresh272 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_CERT as i32 as usize];
                                                                                        let fresh273 = &mut ((*data).set.ssl.username);
                                                                                        *fresh273 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_TLSAUTH_USERNAME as i32 as usize];
                                                                                        let fresh274 = &mut ((*data).set.ssl.password);
                                                                                        *fresh274 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_TLSAUTH_PASSWORD as i32 as usize];
                                                                                        let fresh275 = &mut ((*data).set.proxy_ssl.username);
                                                                                        *fresh275 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_TLSAUTH_USERNAME_PROXY as i32
                                                                                            as usize];
                                                                                        let fresh276 = &mut ((*data).set.proxy_ssl.password);
                                                                                        *fresh276 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_TLSAUTH_PASSWORD_PROXY as i32
                                                                                            as usize];
                                                                                        let fresh277 = &mut ((*data).set.ssl.key_blob);
                                                                                        *fresh277 = (*data)
                                                                                            .set
                                                                                            .blobs[BLOB_KEY as i32 as usize];
                                                                                        if !Curl_clone_primary_ssl_config(
                                                                                            &mut (*data).set.ssl.primary,
                                                                                            &mut (*conn).ssl_config,
                                                                                        ) {
                                                                                            result = CURLE_OUT_OF_MEMORY;
                                                                                        } else if !Curl_clone_primary_ssl_config(
                                                                                                &mut (*data).set.proxy_ssl.primary,
                                                                                                &mut (*conn).proxy_ssl_config,
                                                                                            ) {
                                                                                            result = CURLE_OUT_OF_MEMORY;
                                                                                        } else {
                                                                                            prune_dead_connections(data);
                                                                                            if ((*data).set).reuse_fresh() as i32 != 0
                                                                                                && ((*data).state).this_is_a_follow() == 0
                                                                                                || ((*data).set).connect_only() as i32 != 0
                                                                                            {
                                                                                                reuse = 0 as i32 != 0;
                                                                                            } else {
                                                                                                reuse = ConnectionExists(
                                                                                                    data,
                                                                                                    conn,
                                                                                                    &mut conn_temp,
                                                                                                    &mut force_reuse,
                                                                                                    &mut waitpipe,
                                                                                                );
                                                                                            }
                                                                                            if reuse {
                                                                                                reuse_conn(data, conn, conn_temp);
                                                                                                Curl_cfree
                                                                                                    .expect("non-null function pointer")((*conn).ssl_extra);
                                                                                                Curl_cfree
                                                                                                    .expect(
                                                                                                        "non-null function pointer",
                                                                                                    )(conn as *mut libc::c_void);
                                                                                                conn = conn_temp;
                                                                                                *in_connect = conn;
                                                                                                Curl_infof(
                                                                                                    data,
                                                                                                    b"Re-using existing connection! (#%ld) with %s %s\0"
                                                                                                        as *const u8 as *const i8,
                                                                                                    (*conn).connection_id,
                                                                                                    if ((*conn).bits).proxy() as i32 != 0 {
                                                                                                        b"proxy\0" as *const u8 as *const i8
                                                                                                    } else {
                                                                                                        b"host\0" as *const u8 as *const i8
                                                                                                    },
                                                                                                    if !((*conn).socks_proxy.host.name).is_null() {
                                                                                                        (*conn).socks_proxy.host.dispname
                                                                                                    } else if !((*conn).http_proxy.host.name).is_null() {
                                                                                                        (*conn).http_proxy.host.dispname
                                                                                                    } else {
                                                                                                        (*conn).host.dispname
                                                                                                    },
                                                                                                );
                                                                                                current_block = 2182835884935087477;
                                                                                            } else {
                                                                                                if (*(*conn).handler).flags
                                                                                                    & ((1 as i32) << 8 as i32) as u32
                                                                                                    != 0
                                                                                                {
                                                                                                    if ((*data).set).ssl_enable_alpn() != 0 {
                                                                                                        let fresh278 = &mut ((*conn).bits);
                                                                                                        (*fresh278).set_tls_enable_alpn(1 as i32 as bit);
                                                                                                    }
                                                                                                    if ((*data).set).ssl_enable_npn() != 0 {
                                                                                                        let fresh279 = &mut ((*conn).bits);
                                                                                                        (*fresh279).set_tls_enable_npn(1 as i32 as bit);
                                                                                                    }
                                                                                                }
                                                                                                if waitpipe {
                                                                                                    connections_available = 0 as i32 != 0;
                                                                                                } else {
                                                                                                    let mut bundlehost: *const i8 = 0
                                                                                                        as *const i8;
                                                                                                    let mut bundle: *mut connectbundle = Curl_conncache_find_bundle(
                                                                                                        data,
                                                                                                        conn,
                                                                                                        (*data).state.conn_cache,
                                                                                                        &mut bundlehost,
                                                                                                    );
                                                                                                    if max_host_connections > 0 as i32 as u64
                                                                                                        && !bundle.is_null()
                                                                                                        && (*bundle).num_connections >= max_host_connections
                                                                                                    {
                                                                                                        let mut conn_candidate: *mut connectdata = 0
                                                                                                            as *mut connectdata;
                                                                                                        conn_candidate = Curl_conncache_extract_bundle(
                                                                                                            data,
                                                                                                            bundle,
                                                                                                        );
                                                                                                        if !((*data).share).is_null() {
                                                                                                            Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
                                                                                                        }
                                                                                                        if !conn_candidate.is_null() {
                                                                                                            Curl_disconnect(
                                                                                                                data,
                                                                                                                conn_candidate,
                                                                                                                0 as i32 != 0,
                                                                                                            );
                                                                                                        } else {
                                                                                                            Curl_infof(
                                                                                                                data,
                                                                                                                b"No more connections allowed to host %s: %zu\0"
                                                                                                                    as *const u8 as *const i8,
                                                                                                                bundlehost,
                                                                                                                max_host_connections,
                                                                                                            );
                                                                                                            connections_available = 0 as i32 != 0;
                                                                                                        }
                                                                                                    } else if !((*data).share).is_null() {
                                                                                                        Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
                                                                                                    }
                                                                                                }
                                                                                                if connections_available as i32 != 0
                                                                                                    && max_total_connections > 0 as i32 as u64
                                                                                                    && Curl_conncache_size(data) >= max_total_connections
                                                                                                {
                                                                                                    let mut conn_candidate_0: *mut connectdata = 0
                                                                                                        as *mut connectdata;
                                                                                                    conn_candidate_0 = Curl_conncache_extract_oldest(data);
                                                                                                    if !conn_candidate_0.is_null() {
                                                                                                        Curl_disconnect(
                                                                                                            data,
                                                                                                            conn_candidate_0,
                                                                                                            0 as i32 != 0,
                                                                                                        );
                                                                                                    } else {
                                                                                                        Curl_infof(
                                                                                                            data,
                                                                                                            b"No connections available in cache\0" as *const u8
                                                                                                                as *const i8,
                                                                                                        );
                                                                                                        connections_available = 0 as i32 != 0;
                                                                                                    }
                                                                                                }
                                                                                                if !connections_available {
                                                                                                    Curl_infof(
                                                                                                        data,
                                                                                                        b"No connections available.\0" as *const u8
                                                                                                            as *const i8,
                                                                                                    );
                                                                                                    conn_free(conn);
                                                                                                    *in_connect = 0 as *mut connectdata;
                                                                                                    result = CURLE_NO_CONNECTION_AVAILABLE;
                                                                                                    current_block = 4631372686411729056;
                                                                                                } else {
                                                                                                    Curl_attach_connnection(data, conn);
                                                                                                    result = Curl_conncache_add_conn(data);
                                                                                                    if result as u64 != 0 {
                                                                                                        current_block = 4631372686411729056;
                                                                                                    } else {
                                                                                                        if (*data).state.authhost.picked
                                                                                                            & ((1 as i32 as u64) << 3 as i32
                                                                                                                | (1 as i32 as u64) << 5 as i32)
                                                                                                            != 0 && ((*data).state.authhost).done() as i32 != 0
                                                                                                        {
                                                                                                            Curl_infof(
                                                                                                                data,
                                                                                                                b"NTLM picked AND auth done set, clear picked!\0"
                                                                                                                    as *const u8 as *const i8,
                                                                                                            );
                                                                                                            (*data)
                                                                                                                .state
                                                                                                                .authhost
                                                                                                                .picked = 0 as i32 as u64;
                                                                                                            let fresh280 = &mut ((*data).state.authhost);
                                                                                                            (*fresh280).set_done(0 as i32 as bit);
                                                                                                        }
                                                                                                        if (*data).state.authproxy.picked
                                                                                                            & ((1 as i32 as u64) << 3 as i32
                                                                                                                | (1 as i32 as u64) << 5 as i32)
                                                                                                            != 0 && ((*data).state.authproxy).done() as i32 != 0
                                                                                                        {
                                                                                                            Curl_infof(
                                                                                                                data,
                                                                                                                b"NTLM-proxy picked AND auth done set, clear picked!\0"
                                                                                                                    as *const u8 as *const i8,
                                                                                                            );
                                                                                                            (*data)
                                                                                                                .state
                                                                                                                .authproxy
                                                                                                                .picked = 0 as i32 as u64;
                                                                                                            let fresh281 = &mut ((*data).state.authproxy);
                                                                                                            (*fresh281).set_done(0 as i32 as bit);
                                                                                                        }
                                                                                                        current_block = 2182835884935087477;
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                            match current_block {
                                                                                                4631372686411729056 => {}
                                                                                                _ => {
                                                                                                    Curl_init_do(data, conn);
                                                                                                    result = setup_range(data);
                                                                                                    if !(result as u64 != 0) {
                                                                                                        let fresh282 = &mut ((*conn).seek_func);
                                                                                                        *fresh282 = (*data).set.seek_func;
                                                                                                        let fresh283 = &mut ((*conn).seek_client);
                                                                                                        *fresh283 = (*data).set.seek_client;
                                                                                                        result = resolve_server(data, conn, async_0);
                                                                                                        strip_trailing_dot(&mut (*conn).host);
                                                                                                        if ((*conn).bits).httpproxy() != 0 {
                                                                                                            strip_trailing_dot(&mut (*conn).http_proxy.host);
                                                                                                        }
                                                                                                        if ((*conn).bits).socksproxy() != 0 {
                                                                                                            strip_trailing_dot(&mut (*conn).socks_proxy.host);
                                                                                                        }
                                                                                                        if ((*conn).bits).conn_to_host() != 0 {
                                                                                                            strip_trailing_dot(&mut (*conn).conn_to_host);
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
                        }
                    }
                }
            }
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_setup_conn(
    mut data: *mut Curl_easy,
    mut protocol_done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    Curl_pgrsTime(data, TIMER_NAMELOOKUP);
    if (*(*conn).handler).flags
        & ((1 as i32) << 4 as i32) as u32 != 0
    {
        *protocol_done = 1 as i32 != 0;
        return result;
    }
    *protocol_done = 0 as i32 != 0;
    let fresh284 = &mut ((*conn).bits);
    (*fresh284).set_proxy_connect_closed(0 as i32 as bit);
    (*data).state.crlf_conversions = 0 as i32 as curl_off_t;
    (*conn).now = Curl_now();
    if -(1 as i32) == (*conn).sock[0 as i32 as usize] {
        (*conn).bits.tcpconnect[0 as i32 as usize] = 0 as i32 != 0;
        result = Curl_connecthost(data, conn, (*conn).dns_entry);
        if result as u64 != 0 {
            return result;
        }
    } else {
        Curl_pgrsTime(data, TIMER_CONNECT);
        if ((*conn).ssl[0 as i32 as usize]).use_0() as i32 != 0
            || (*(*conn).handler).protocol
                & ((1 as i32) << 4 as i32
                    | (1 as i32) << 5 as i32) as u32 != 0
        {
            Curl_pgrsTime(data, TIMER_APPCONNECT);
        }
        (*conn).bits.tcpconnect[0 as i32 as usize] = 1 as i32 != 0;
        *protocol_done = 1 as i32 != 0;
        Curl_updateconninfo(data, conn, (*conn).sock[0 as i32 as usize]);
        Curl_verboseconnect(data, conn);
    }
    (*conn).now = Curl_now();
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_connect(
    mut data: *mut Curl_easy,
    mut asyncp: *mut bool,
    mut protocol_done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = 0 as *mut connectdata;
    *asyncp = 0 as i32 != 0;
    Curl_free_request_state(data);
    memset(
        &mut (*data).req as *mut SingleRequest as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<SingleRequest>() as u64,
    );
    (*data).req.maxdownload = -(1 as i32) as curl_off_t;
    result = create_conn(data, &mut conn, asyncp);
    if result as u64 == 0 {
        if (*conn).easyq.size > 1 as i32 as u64 {
            *protocol_done = 1 as i32 != 0;
        } else if !*asyncp {
            result = Curl_setup_conn(data, protocol_done);
        }
    }
    if result as u32
        == CURLE_NO_CONNECTION_AVAILABLE as i32 as u32
    {
        return result
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
pub unsafe extern "C" fn Curl_init_do(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut k: *mut SingleRequest = &mut (*data).req;
    let mut result: CURLcode = Curl_preconnect(data);
    if result as u64 != 0 {
        return result;
    }
    if !conn.is_null() {
        let fresh285 = &mut ((*conn).bits);
        (*fresh285).set_do_more(0 as i32 as bit);
        if ((*data).state).wildcardmatch() as i32 != 0
            && (*(*conn).handler).flags
                & ((1 as i32) << 12 as i32) as u32 == 0
        {
            let fresh286 = &mut ((*data).state);
            (*fresh286).set_wildcardmatch(0 as i32 as bit);
        }
    }
    let fresh287 = &mut ((*data).state);
    (*fresh287).set_done(0 as i32 as bit);
    let fresh288 = &mut ((*data).state);
    (*fresh288).set_expect100header(0 as i32 as bit);
    if ((*data).set).opt_no_body() != 0 {
        (*data).state.httpreq = HTTPREQ_HEAD;
    }
    (*k).start = Curl_now();
    (*k).now = (*k).start;
    (*k).set_header(1 as i32 as bit);
    (*k).bytecount = 0 as i32 as curl_off_t;
    (*k).set_ignorebody(0 as i32 as bit);
    Curl_speedinit(data);
    Curl_pgrsSetUploadCounter(data, 0 as i32 as curl_off_t);
    Curl_pgrsSetDownloadCounter(data, 0 as i32 as curl_off_t);
    return CURLE_OK;
}
