use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn socketpair(
        __domain: i32,
        __type: i32,
        __protocol: i32,
        __fds: *mut i32,
    ) -> i32;
    fn send(
        __fd: i32,
        __buf: *const libc::c_void,
        __n: size_t,
        __flags: i32,
    ) -> ssize_t;
    fn recv(
        __fd: i32,
        __buf: *mut libc::c_void,
        __n: size_t,
        __flags: i32,
    ) -> ssize_t;
    fn close(__fd: i32) -> i32;
    fn memset(
        _: *mut libc::c_void,
        _: i32,
        _: u64,
    ) -> *mut libc::c_void;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> *mut libc::c_void;
    fn __errno_location() -> *mut i32;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn sigaction(
        __sig: i32,
        __act: *const sigaction,
        __oact: *mut sigaction,
    ) -> i32;
    static mut Curl_ssl: *const Curl_ssl;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::asyn_thread::Curl_resolver_kill;
pub use crate::src::lib::conncache::Curl_conncache_close_all_connections;
pub use crate::src::lib::conncache::Curl_conncache_destroy;
pub use crate::src::lib::conncache::Curl_conncache_foreach;
pub use crate::src::lib::conncache::Curl_conncache_init;
pub use crate::src::lib::conncache::Curl_conncache_remove_conn;
pub use crate::src::lib::conncache::Curl_conncache_return_conn;
pub use crate::src::lib::connect::Curl_conncontrol;
pub use crate::src::lib::connect::Curl_is_connected;
pub use crate::src::lib::connect::Curl_timeleft;
pub use crate::src::lib::dynbuf::Curl_dyn_free;
pub use crate::src::lib::hash::Curl_hash_add;
pub use crate::src::lib::hash::Curl_hash_delete;
pub use crate::src::lib::hash::Curl_hash_destroy;
pub use crate::src::lib::hash::Curl_hash_init;
pub use crate::src::lib::hash::Curl_hash_next_element;
pub use crate::src::lib::hash::Curl_hash_pick;
pub use crate::src::lib::hash::Curl_hash_start_iterate;
pub use crate::src::lib::hostip::Curl_fetch_addr;
pub use crate::src::lib::hostip::Curl_hostcache_clean;
pub use crate::src::lib::hostip::Curl_hostcache_prune;
pub use crate::src::lib::hostip::Curl_ipv6works;
pub use crate::src::lib::hostip::Curl_mk_dnscache;
pub use crate::src::lib::hostip::Curl_once_resolved;
pub use crate::src::lib::hostip::Curl_resolv_check;
pub use crate::src::lib::hostip::Curl_resolv_getsock;
pub use crate::src::lib::hostip::Curl_resolv_unlock;
pub use crate::src::lib::http2::Curl_h2_http_1_1_error;
pub use crate::src::lib::http::Curl_http_connect;
pub use crate::src::lib::http_proxy::Curl_connect_complete;
pub use crate::src::lib::http_proxy::Curl_connect_free;
pub use crate::src::lib::http_proxy::Curl_connect_getsock;
pub use crate::src::lib::http_proxy::Curl_connect_ongoing;
pub use crate::src::lib::http_proxy::Curl_proxy_connect;
pub use crate::src::lib::llist::Curl_llist_count;
pub use crate::src::lib::llist::Curl_llist_destroy;
pub use crate::src::lib::llist::Curl_llist_init;
pub use crate::src::lib::llist::Curl_llist_insert_next;
pub use crate::src::lib::llist::Curl_llist_remove;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::nonblock::curlx_nonblock;
pub use crate::src::lib::progress::Curl_pgrsDone;
pub use crate::src::lib::progress::Curl_pgrsLimitWaitTime;
pub use crate::src::lib::progress::Curl_pgrsTime;
pub use crate::src::lib::progress::Curl_pgrsUpdate;
pub use crate::src::lib::progress::Curl_ratelimit;
pub use crate::src::lib::psl::Curl_psl_destroy;
pub use crate::src::lib::select::Curl_poll;
pub use crate::src::lib::select::Curl_wait_ms;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::share::Curl_share_lock;
pub use crate::src::lib::share::Curl_share_unlock;
pub use crate::src::lib::socks::Curl_SOCKS_getsock;
pub use crate::src::lib::speedcheck::Curl_speedcheck;
pub use crate::src::lib::splay::Curl_splay;
pub use crate::src::lib::splay::Curl_splaygetbest;
pub use crate::src::lib::splay::Curl_splayinsert;
pub use crate::src::lib::splay::Curl_splayremove;
pub use crate::src::lib::timeval::Curl_now;
pub use crate::src::lib::timeval::Curl_timediff;
pub use crate::src::lib::transfer::Curl_follow;
pub use crate::src::lib::transfer::Curl_init_CONNECT;
pub use crate::src::lib::transfer::Curl_posttransfer;
pub use crate::src::lib::transfer::Curl_pretransfer;
pub use crate::src::lib::transfer::Curl_readwrite;
pub use crate::src::lib::transfer::Curl_retry_request;
pub use crate::src::lib::transfer::Curl_single_getsock;
pub use crate::src::lib::url::Curl_connect;
pub use crate::src::lib::url::Curl_disconnect;
pub use crate::src::lib::url::Curl_free_request_state;
pub use crate::src::lib::url::Curl_init_do;
pub use crate::src::lib::vtls::vtls::Curl_ssl_associate_conn;
pub use crate::src::lib::vtls::vtls::Curl_ssl_detach_conn;
pub use crate::src::lib::warnless::curlx_sltoui;
pub use crate::src::lib::warnless::curlx_uztosi;
pub use crate::src::lib::wildcard::Curl_wildcard_dtor;
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::altsvc::Gsasl;
pub use crate::src::lib::easy::Curl_ccalloc;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_cstrdup;
pub use crate::src::lib::hostip6::psl_ctx_st;
pub use crate::src::lib::imap::_IO_marker;
pub use crate::src::lib::speedcheck::_IO_codecvt;
pub use crate::src::lib::urlapi::Gsasl_session;
pub use crate::src::lib::version::nghttp2_session;
pub use crate::src::lib::vtls::vtls::_IO_wide_data;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
pub type __builtin_va_list = crate::src::lib::dict::__builtin_va_list;
// #[derive(Copy, Clone)]

pub type __va_list_tag = crate::src::lib::dict::__va_list_tag;
pub type __uint8_t = crate::src::lib::altsvc::__uint8_t;
pub type __int32_t = crate::src::lib::altsvc::__int32_t;
pub type __uint32_t = crate::src::lib::altsvc::__uint32_t;
pub type __uid_t = crate::src::lib::conncache::__uid_t;
pub type __off_t = crate::src::lib::altsvc::__off_t;
pub type __off64_t = crate::src::lib::altsvc::__off64_t;
pub type __pid_t = crate::src::lib::altsvc::__pid_t;
pub type __clock_t = crate::src::lib::conncache::__clock_t;
pub type __time_t = crate::src::lib::altsvc::__time_t;
pub type __ssize_t = crate::src::lib::altsvc::__ssize_t;
pub type __socklen_t = crate::src::lib::altsvc::__socklen_t;
pub type pid_t = crate::src::lib::altsvc::pid_t;
pub type ssize_t = crate::src::lib::altsvc::ssize_t;
pub type time_t = crate::src::lib::altsvc::time_t;
pub type size_t = crate::src::lib::altsvc::size_t;
pub type int32_t = crate::src::lib::altsvc::int32_t;
// #[derive(Copy, Clone)]

pub type __sigset_t = crate::src::lib::conncache::__sigset_t;
pub type __fd_mask = i64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct fd_set {
    pub __fds_bits: [__fd_mask; 16],
}
pub type socklen_t = crate::src::lib::altsvc::socklen_t;
pub type __socket_type = crate::src::lib::asyn_thread::__socket_type;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_RAW: __socket_type = 3;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;
pub type sa_family_t = crate::src::lib::altsvc::sa_family_t;
// #[derive(Copy, Clone)]

pub type sockaddr = crate::src::lib::altsvc::sockaddr;
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
pub type curl_socklen_t = crate::src::lib::altsvc::curl_socklen_t;
pub type curl_off_t = crate::src::lib::altsvc::curl_off_t;
pub type va_list = crate::src::lib::dict::va_list;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::altsvc::_IO_FILE;
pub type _IO_lock_t = crate::src::lib::altsvc::_IO_lock_t;
pub type FILE = crate::src::lib::altsvc::FILE;
pub type __sigval_t = crate::src::lib::conncache::__sigval_t;
// #[derive(Copy, Clone)]

pub type sigval = crate::src::lib::conncache::sigval;
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

pub type C2RustUnnamed_0 = crate::src::lib::altsvc::C2RustUnnamed;
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
pub type C2RustUnnamed_1 = u32;
pub const HTTPSEND_BODY: C2RustUnnamed_1 = 2;
pub const HTTPSEND_REQUEST: C2RustUnnamed_1 = 1;
pub const HTTPSEND_NADA: C2RustUnnamed_1 = 0;
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
pub type C2RustUnnamed_2 = u32;
pub const HEADER_ALLBAD: C2RustUnnamed_2 = 2;
pub const HEADER_PARTHEADER: C2RustUnnamed_2 = 1;
pub const HEADER_NORMAL: C2RustUnnamed_2 = 0;
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
pub type C2RustUnnamed_3 = u32;
pub const HCACHE_SHARED: C2RustUnnamed_3 = 2;
pub const HCACHE_MULTI: C2RustUnnamed_3 = 1;
pub const HCACHE_NONE: C2RustUnnamed_3 = 0;
// #[derive(Copy, Clone)]

pub type Curl_message = crate::src::lib::altsvc::Curl_message;
// #[derive(Copy, Clone)]

pub type CURLMsg = crate::src::lib::altsvc::CURLMsg;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_4 = crate::src::lib::altsvc::C2RustUnnamed_3;
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
pub type C2RustUnnamed_5 = u32;
pub const TUNNEL_EXIT: C2RustUnnamed_5 = 3;
pub const TUNNEL_COMPLETE: C2RustUnnamed_5 = 2;
pub const TUNNEL_CONNECT: C2RustUnnamed_5 = 1;
pub const TUNNEL_INIT: C2RustUnnamed_5 = 0;
pub type keeponval = crate::src::lib::ftp::keeponval;
pub const KEEPON_IGNORE: keeponval = 2;
pub const KEEPON_CONNECT: keeponval = 1;
pub const KEEPON_DONE: keeponval = 0;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_6 = crate::src::lib::altsvc::C2RustUnnamed_4;
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
pub type C2RustUnnamed_7 = u32;
pub const TRNSPRT_QUIC: C2RustUnnamed_7 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_7 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_7 = 3;
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
pub type C2RustUnnamed_8 = u32;
pub const CURL_HTTP_VERSION_LAST: C2RustUnnamed_8 = 31;
pub const CURL_HTTP_VERSION_3: C2RustUnnamed_8 = 30;
pub const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: C2RustUnnamed_8 = 5;
pub const CURL_HTTP_VERSION_2TLS: C2RustUnnamed_8 = 4;
pub const CURL_HTTP_VERSION_2_0: C2RustUnnamed_8 = 3;
pub const CURL_HTTP_VERSION_1_1: C2RustUnnamed_8 = 2;
pub const CURL_HTTP_VERSION_1_0: C2RustUnnamed_8 = 1;
pub const CURL_HTTP_VERSION_NONE: C2RustUnnamed_8 = 0;
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
// #[derive(Copy, Clone)]

pub type curl_waitfd = crate::src::lib::easy::curl_waitfd;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_sh_entry {
    pub transfers: Curl_hash,
    pub action: u32,
    pub users: u32,
    pub socketp: *mut libc::c_void,
    pub readers: u32,
    pub writers: u32,
}
pub type init_multistate_func = Option::<unsafe extern "C" fn(*mut Curl_easy) -> ()>;
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
// #[derive(Copy, Clone)]

pub type Curl_ssl = crate::src::lib::getinfo::Curl_ssl;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pollfd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}
// #[derive(Copy, Clone)]

pub type sigpipe_ignore = crate::src::lib::conncache::sigpipe_ignore;
// #[derive(Copy, Clone)]

pub type sigaction = crate::src::lib::conncache::sigaction;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_9 = crate::src::lib::conncache::C2RustUnnamed_6;
// #[derive(Copy, Clone)]

pub type siginfo_t = crate::src::lib::conncache::siginfo_t;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_10 = crate::src::lib::conncache::C2RustUnnamed_7;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_11 = crate::src::lib::conncache::C2RustUnnamed_8;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_12 = crate::src::lib::conncache::C2RustUnnamed_9;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_13 = crate::src::lib::conncache::C2RustUnnamed_10;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_14 = crate::src::lib::conncache::C2RustUnnamed_11;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_15 = crate::src::lib::conncache::C2RustUnnamed_12;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_16 = crate::src::lib::conncache::C2RustUnnamed_13;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_17 = crate::src::lib::conncache::C2RustUnnamed_14;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_18 = crate::src::lib::conncache::C2RustUnnamed_15;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_19 = crate::src::lib::conncache::C2RustUnnamed_16;
pub type __sighandler_t = crate::src::lib::conncache::__sighandler_t;
pub type followtype = u32;
pub const FOLLOW_REDIR: followtype = 3;
pub const FOLLOW_RETRY: followtype = 2;
pub const FOLLOW_FAKE: followtype = 1;
pub const FOLLOW_NONE: followtype = 0;
// #[derive(Copy, Clone)]

pub type Curl_hash_element = crate::src::lib::conncache::Curl_hash_element;
// #[derive(Copy, Clone)]

pub type Curl_hash_iterator = crate::src::lib::conncache::Curl_hash_iterator;
pub type CURLMoption = crate::src::lib::easy::CURLMoption;
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
unsafe extern "C" fn sigpipe_restore(mut ig: *mut sigpipe_ignore) {
    if !(*ig).no_signal {
        sigaction(13 as i32, &mut (*ig).old_pipe_act, 0 as *mut sigaction);
    }
}
unsafe extern "C" fn sigpipe_ignore(
    mut data: *mut Curl_easy,
    mut ig: *mut sigpipe_ignore,
) {
    (*ig).no_signal = ((*data).set).no_signal() != 0;
    if ((*data).set).no_signal() == 0 {
        let mut action: sigaction = sigaction {
            __sigaction_handler: C2RustUnnamed_9 {
                sa_handler: None,
            },
            sa_mask: __sigset_t { __val: [0; 16] },
            sa_flags: 0,
            sa_restorer: None,
        };
        memset(
            &mut (*ig).old_pipe_act as *mut sigaction as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<sigaction>() as u64,
        );
        sigaction(13 as i32, 0 as *const sigaction, &mut (*ig).old_pipe_act);
        action = (*ig).old_pipe_act;
        action
            .__sigaction_handler
            .sa_handler = ::std::mem::transmute::<
            libc::intptr_t,
            __sighandler_t,
        >(1 as i32 as libc::intptr_t);
        sigaction(13 as i32, &mut action, 0 as *mut sigaction);
    }
}
unsafe extern "C" fn before_perform(mut data: *mut Curl_easy) {
    let fresh0 = &mut ((*data).req);
    (*fresh0).set_chunk(0 as i32 as bit);
    Curl_pgrsTime(data, TIMER_PRETRANSFER);
}
unsafe extern "C" fn init_completed(mut data: *mut Curl_easy) {
    Curl_detach_connnection(data);
    Curl_expire_clear(data);
}
unsafe extern "C" fn mstate(mut data: *mut Curl_easy, mut state: CURLMstate) {
    let mut oldstate: CURLMstate = (*data).mstate;
    static mut finit: [init_multistate_func; 17] = unsafe {
        [
            None,
            None,
            Some(Curl_init_CONNECT as unsafe extern "C" fn(*mut Curl_easy) -> ()),
            None,
            None,
            None,
            None,
            None,
            Some(Curl_connect_free as unsafe extern "C" fn(*mut Curl_easy) -> ()),
            None,
            None,
            Some(before_perform as unsafe extern "C" fn(*mut Curl_easy) -> ()),
            None,
            None,
            None,
            Some(init_completed as unsafe extern "C" fn(*mut Curl_easy) -> ()),
            None,
        ]
    };
    if oldstate as u32 == state as u32 {
        return;
    }
    (*data).mstate = state;
    if state as u32 == MSTATE_COMPLETED as i32 as u32 {
        let fresh1 = &mut ((*(*data).multi).num_alive);
        *fresh1 -= 1;
    }
    if (finit[state as usize]).is_some() {
        (finit[state as usize]).expect("non-null function pointer")(data);
    }
}
unsafe extern "C" fn sh_getentry(
    mut sh: *mut Curl_hash,
    mut s: curl_socket_t,
) -> *mut Curl_sh_entry {
    if s != -(1 as i32) {
        return Curl_hash_pick(
            sh,
            &mut s as *mut curl_socket_t as *mut i8 as *mut libc::c_void,
            ::std::mem::size_of::<curl_socket_t>() as u64,
        ) as *mut Curl_sh_entry;
    }
    return 0 as *mut Curl_sh_entry;
}
unsafe extern "C" fn trhash(
    mut key: *mut libc::c_void,
    mut key_length: size_t,
    mut slots_num: size_t,
) -> size_t {
    let mut keyval: size_t = *(key as *mut *mut Curl_easy) as size_t;
    return keyval.wrapping_rem(slots_num);
}
unsafe extern "C" fn trhash_compare(
    mut k1: *mut libc::c_void,
    mut k1_len: size_t,
    mut k2: *mut libc::c_void,
    mut k2_len: size_t,
) -> size_t {
    return (*(k1 as *mut *mut Curl_easy) == *(k2 as *mut *mut Curl_easy)) as i32
        as size_t;
}
 extern "C" fn trhash_dtor(mut nada: *mut libc::c_void) {}
unsafe extern "C" fn sh_addentry(
    mut sh: *mut Curl_hash,
    mut s: curl_socket_t,
) -> *mut Curl_sh_entry {
    let mut there: *mut Curl_sh_entry = sh_getentry(sh, s);
    let mut check: *mut Curl_sh_entry = 0 as *mut Curl_sh_entry;
    if !there.is_null() {
        return there;
    }
    check = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(
        1 as i32 as size_t,
        ::std::mem::size_of::<Curl_sh_entry>() as u64,
    ) as *mut Curl_sh_entry;
    if check.is_null() {
        return 0 as *mut Curl_sh_entry;
    }
    if Curl_hash_init(
        &mut (*check).transfers,
        13 as i32,
        Some(
            trhash as unsafe extern "C" fn(*mut libc::c_void, size_t, size_t) -> size_t,
        ),
        Some(
            trhash_compare
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    size_t,
                    *mut libc::c_void,
                    size_t,
                ) -> size_t,
        ),
        Some(trhash_dtor as unsafe extern "C" fn(*mut libc::c_void) -> ()),
    ) != 0
    {
        Curl_cfree.expect("non-null function pointer")(check as *mut libc::c_void);
        return 0 as *mut Curl_sh_entry;
    }
    if (Curl_hash_add(
        sh,
        &mut s as *mut curl_socket_t as *mut i8 as *mut libc::c_void,
        ::std::mem::size_of::<curl_socket_t>() as u64,
        check as *mut libc::c_void,
    ))
        .is_null()
    {
        Curl_hash_destroy(&mut (*check).transfers);
        Curl_cfree.expect("non-null function pointer")(check as *mut libc::c_void);
        return 0 as *mut Curl_sh_entry;
    }
    return check;
}
unsafe extern "C" fn sh_delentry(
    mut entry: *mut Curl_sh_entry,
    mut sh: *mut Curl_hash,
    mut s: curl_socket_t,
) {
    Curl_hash_destroy(&mut (*entry).transfers);
    Curl_hash_delete(
        sh,
        &mut s as *mut curl_socket_t as *mut i8 as *mut libc::c_void,
        ::std::mem::size_of::<curl_socket_t>() as u64,
    );
}
unsafe extern "C" fn sh_freeentry(mut freethis: *mut libc::c_void) {
    let mut p: *mut Curl_sh_entry = freethis as *mut Curl_sh_entry;
    Curl_cfree.expect("non-null function pointer")(p as *mut libc::c_void);
}
unsafe extern "C" fn fd_key_compare(
    mut k1: *mut libc::c_void,
    mut k1_len: size_t,
    mut k2: *mut libc::c_void,
    mut k2_len: size_t,
) -> size_t {
    return (*(k1 as *mut curl_socket_t) == *(k2 as *mut curl_socket_t)) as i32
        as size_t;
}
unsafe extern "C" fn hash_fd(
    mut key: *mut libc::c_void,
    mut key_length: size_t,
    mut slots_num: size_t,
) -> size_t {
    let mut fd: curl_socket_t = *(key as *mut curl_socket_t);
    return (fd as u64).wrapping_rem(slots_num);
}
unsafe extern "C" fn sh_init(
    mut hash: *mut Curl_hash,
    mut hashsize: i32,
) -> i32 {
    return Curl_hash_init(
        hash,
        hashsize,
        Some(
            hash_fd as unsafe extern "C" fn(*mut libc::c_void, size_t, size_t) -> size_t,
        ),
        Some(
            fd_key_compare
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    size_t,
                    *mut libc::c_void,
                    size_t,
                ) -> size_t,
        ),
        Some(sh_freeentry as unsafe extern "C" fn(*mut libc::c_void) -> ()),
    );
}
unsafe extern "C" fn multi_addmsg(
    mut multi: *mut Curl_multi,
    mut msg: *mut Curl_message,
) -> CURLMcode {
    Curl_llist_insert_next(
        &mut (*multi).msglist,
        (*multi).msglist.tail,
        msg as *const libc::c_void,
        &mut (*msg).list,
    );
    return CURLM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_multi_handle(
    mut hashsize: i32,
    mut chashsize: i32,
) -> *mut Curl_multi {
    let mut multi: *mut Curl_multi = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(
        1 as i32 as size_t,
        ::std::mem::size_of::<Curl_multi>() as u64,
    ) as *mut Curl_multi;
    if multi.is_null() {
        return 0 as *mut Curl_multi;
    }
    (*multi).magic = 0xbab1e as i32 as u32;
    if !(Curl_mk_dnscache(&mut (*multi).hostcache) != 0) {
        if !(sh_init(&mut (*multi).sockhash, hashsize) != 0) {
            if !(Curl_conncache_init(&mut (*multi).conn_cache, chashsize) != 0) {
                Curl_llist_init(&mut (*multi).msglist, None);
                Curl_llist_init(&mut (*multi).pending, None);
                (*multi).multiplexing = 1 as i32 != 0;
                (*multi).maxconnects = -(1 as i32) as i64;
                (*multi).max_concurrent_streams = 100 as i32 as u32;
                (*multi).ipv6_works = Curl_ipv6works(0 as *mut Curl_easy);
                if socketpair(
                    1 as i32,
                    SOCK_STREAM as i32,
                    0 as i32,
                    ((*multi).wakeup_pair).as_mut_ptr(),
                ) < 0 as i32
                {
                    (*multi)
                        .wakeup_pair[0 as i32 as usize] = -(1 as i32);
                    (*multi)
                        .wakeup_pair[1 as i32 as usize] = -(1 as i32);
                } else if curlx_nonblock(
                        (*multi).wakeup_pair[0 as i32 as usize],
                        1 as i32,
                    ) < 0 as i32
                        || curlx_nonblock(
                            (*multi).wakeup_pair[1 as i32 as usize],
                            1 as i32,
                        ) < 0 as i32
                    {
                    close((*multi).wakeup_pair[0 as i32 as usize]);
                    close((*multi).wakeup_pair[1 as i32 as usize]);
                    (*multi)
                        .wakeup_pair[0 as i32 as usize] = -(1 as i32);
                    (*multi)
                        .wakeup_pair[1 as i32 as usize] = -(1 as i32);
                }
                return multi;
            }
        }
    }
    Curl_hash_destroy(&mut (*multi).sockhash);
    Curl_hash_destroy(&mut (*multi).hostcache);
    Curl_conncache_destroy(&mut (*multi).conn_cache);
    Curl_llist_destroy(&mut (*multi).msglist, 0 as *mut libc::c_void);
    Curl_llist_destroy(&mut (*multi).pending, 0 as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(multi as *mut libc::c_void);
    return 0 as *mut Curl_multi;
}
#[no_mangle]
pub unsafe extern "C" fn curl_multi_init() -> *mut CURLM {
    return Curl_multi_handle(911 as i32, 97 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn curl_multi_add_handle(
    mut multi: *mut Curl_multi,
    mut data: *mut Curl_easy,
) -> CURLMcode {
    if !(!multi.is_null() && (*multi).magic == 0xbab1e as i32 as u32) {
        return CURLM_BAD_HANDLE;
    }
    if !(!data.is_null() && (*data).magic == 0xc0dedbad as u32) {
        return CURLM_BAD_EASY_HANDLE;
    }
    if !((*data).multi).is_null() {
        return CURLM_ADDED_ALREADY;
    }
    if (*multi).in_callback {
        return CURLM_RECURSIVE_API_CALL;
    }
    Curl_llist_init(&mut (*data).state.timeoutlist, None);
    if !((*data).set.errorbuffer).is_null() {
        *((*data).set.errorbuffer)
            .offset(0 as i32 as isize) = 0 as i32 as i8;
    }
    mstate(data, MSTATE_INIT);
    if ((*data).dns.hostcache).is_null()
        || (*data).dns.hostcachetype as u32
            == HCACHE_NONE as i32 as u32
    {
        let fresh2 = &mut ((*data).dns.hostcache);
        *fresh2 = &mut (*multi).hostcache;
        (*data).dns.hostcachetype = HCACHE_MULTI;
    }
    if !((*data).share).is_null()
        && (*(*data).share).specifier
            & ((1 as i32) << CURL_LOCK_DATA_CONNECT as i32)
                as u32 != 0
    {
        let fresh3 = &mut ((*data).state.conn_cache);
        *fresh3 = &mut (*(*data).share).conn_cache;
    } else {
        let fresh4 = &mut ((*data).state.conn_cache);
        *fresh4 = &mut (*multi).conn_cache;
    }
    (*data).state.lastconnect_id = -(1 as i32) as i64;
    if !((*data).share).is_null()
        && (*(*data).share).specifier
            & ((1 as i32) << CURL_LOCK_DATA_PSL as i32) as u32
            != 0
    {
        let fresh5 = &mut ((*data).psl);
        *fresh5 = &mut (*(*data).share).psl;
    } else {
        let fresh6 = &mut ((*data).psl);
        *fresh6 = &mut (*multi).psl;
    }
    let fresh7 = &mut ((*data).next);
    *fresh7 = 0 as *mut Curl_easy;
    if !((*multi).easyp).is_null() {
        let mut last: *mut Curl_easy = (*multi).easylp;
        let fresh8 = &mut ((*last).next);
        *fresh8 = data;
        let fresh9 = &mut ((*data).prev);
        *fresh9 = last;
        let fresh10 = &mut ((*multi).easylp);
        *fresh10 = data;
    } else {
        let fresh11 = &mut ((*data).prev);
        *fresh11 = 0 as *mut Curl_easy;
        let fresh12 = &mut ((*multi).easyp);
        *fresh12 = data;
        let fresh13 = &mut ((*multi).easylp);
        *fresh13 = *fresh12;
    }
    let fresh14 = &mut ((*data).multi);
    *fresh14 = multi;
    Curl_expire(data, 0 as i32 as timediff_t, EXPIRE_RUN_NOW);
    let fresh15 = &mut ((*multi).num_easy);
    *fresh15 += 1;
    let fresh16 = &mut ((*multi).num_alive);
    *fresh16 += 1;
    memset(
        &mut (*multi).timer_lastcall as *mut curltime as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<curltime>() as u64,
    );
    if !((*data).share).is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_CONNECT, CURL_LOCK_ACCESS_SINGLE);
    }
    (*(*(*data).state.conn_cache).closure_handle).set.timeout = (*data).set.timeout;
    (*(*(*data).state.conn_cache).closure_handle)
        .set
        .server_response_timeout = (*data).set.server_response_timeout;
    let fresh17 = &mut ((*(*(*data).state.conn_cache).closure_handle).set);
    (*fresh17).set_no_signal(((*data).set).no_signal());
    if !((*data).share).is_null() {
        Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
    }
    Curl_update_timer(multi);
    return CURLM_OK;
}
unsafe extern "C" fn multi_done(
    mut data: *mut Curl_easy,
    mut status: CURLcode,
    mut premature: bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut i: u32 = 0;
    if ((*data).state).done() != 0 {
        return CURLE_OK;
    }
    Curl_resolver_kill(data);
    Curl_cfree
        .expect("non-null function pointer")((*data).req.newurl as *mut libc::c_void);
    let fresh18 = &mut ((*data).req.newurl);
    *fresh18 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*data).req.location as *mut libc::c_void);
    let fresh19 = &mut ((*data).req.location);
    *fresh19 = 0 as *mut i8;
    match status as u32 {
        42 | 26 | 23 => {
            premature = 1 as i32 != 0;
        }
        _ => {}
    }
    if ((*(*conn).handler).done).is_some() {
        result = ((*(*conn).handler).done)
            .expect("non-null function pointer")(data, status, premature);
    } else {
        result = status;
    }
    if CURLE_ABORTED_BY_CALLBACK as i32 as u32 != result as u32
    {
        let mut rc: CURLcode = Curl_pgrsDone(data) as CURLcode;
        if result as u64 == 0 && rc as u32 != 0 {
            result = CURLE_ABORTED_BY_CALLBACK;
        }
    }
    process_pending_handles((*data).multi);
    if !((*data).share).is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_CONNECT, CURL_LOCK_ACCESS_SINGLE);
    }
    Curl_detach_connnection(data);
    if (*conn).easyq.size != 0 {
        if !((*data).share).is_null() {
            Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
        }
        return CURLE_OK;
    }
    let fresh20 = &mut ((*data).state);
    (*fresh20).set_done(1 as i32 as bit);
    if !((*conn).dns_entry).is_null() {
        Curl_resolv_unlock(data, (*conn).dns_entry);
        let fresh21 = &mut ((*conn).dns_entry);
        *fresh21 = 0 as *mut Curl_dns_entry;
    }
    Curl_hostcache_prune(data);
    Curl_cfree
        .expect("non-null function pointer")((*data).state.ulbuf as *mut libc::c_void);
    let fresh22 = &mut ((*data).state.ulbuf);
    *fresh22 = 0 as *mut i8;
    i = 0 as i32 as u32;
    while i < (*data).state.tempcount {
        Curl_dyn_free(
            &mut (*((*data).state.tempwrite).as_mut_ptr().offset(i as isize)).b,
        );
        i = i.wrapping_add(1);
    }
    (*data).state.tempcount = 0 as i32 as u32;
    if ((*data).set).reuse_forbid() as i32 != 0
        && !((*conn).http_ntlm_state as u32
            == NTLMSTATE_TYPE2 as i32 as u32
            || (*conn).proxy_ntlm_state as u32
                == NTLMSTATE_TYPE2 as i32 as u32)
        || ((*conn).bits).close() as i32 != 0
        || premature as i32 != 0
            && (*(*conn).handler).flags
                & ((1 as i32) << 9 as i32) as u32 == 0
    {
        let mut res2: CURLcode = CURLE_OK;
        Curl_conncontrol(conn, 1 as i32);
        Curl_conncache_remove_conn(data, conn, 0 as i32 != 0);
        if !((*data).share).is_null() {
            Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
        }
        res2 = Curl_disconnect(data, conn, premature);
        if result as u64 == 0 && res2 as u32 != 0 {
            result = res2;
        }
    } else {
        let mut buffer: [i8; 256] = [0; 256];
        let mut host: *const i8 = if ((*conn).bits).socksproxy() as i32
            != 0
        {
            (*conn).socks_proxy.host.dispname
        } else if ((*conn).bits).httpproxy() as i32 != 0 {
            (*conn).http_proxy.host.dispname
        } else if ((*conn).bits).conn_to_host() as i32 != 0 {
            (*conn).conn_to_host.dispname
        } else {
            (*conn).host.dispname
        };
        curl_msnprintf(
            buffer.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 256]>() as u64,
            b"Connection #%ld to host %s left intact\0" as *const u8
                as *const i8,
            (*conn).connection_id,
            host,
        );
        if !((*data).share).is_null() {
            Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
        }
        if Curl_conncache_return_conn(data, conn) {
            (*data).state.lastconnect_id = (*conn).connection_id;
            Curl_infof(
                data,
                b"%s\0" as *const u8 as *const i8,
                buffer.as_mut_ptr(),
            );
        } else {
            (*data).state.lastconnect_id = -(1 as i32) as i64;
        }
    }
    Curl_cfree
        .expect("non-null function pointer")((*data).state.buffer as *mut libc::c_void);
    let fresh23 = &mut ((*data).state.buffer);
    *fresh23 = 0 as *mut i8;
    Curl_free_request_state(data);
    return result;
}
unsafe extern "C" fn close_connect_only(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut param: *mut libc::c_void,
) -> i32 {
    if (*data).state.lastconnect_id != (*conn).connection_id {
        return 0 as i32;
    }
    if ((*conn).bits).connect_only() == 0 {
        return 1 as i32;
    }
    Curl_conncontrol(conn, 1 as i32);
    return 1 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn curl_multi_remove_handle(
    mut multi: *mut Curl_multi,
    mut data: *mut Curl_easy,
) -> CURLMcode {
    let mut easy: *mut Curl_easy = data;
    let mut premature: bool = false;
    let mut e: *mut Curl_llist_element = 0 as *mut Curl_llist_element;
    if !(!multi.is_null() && (*multi).magic == 0xbab1e as i32 as u32) {
        return CURLM_BAD_HANDLE;
    }
    if !(!data.is_null() && (*data).magic == 0xc0dedbad as u32) {
        return CURLM_BAD_EASY_HANDLE;
    }
    if ((*data).multi).is_null() {
        return CURLM_OK;
    }
    if (*data).multi != multi {
        return CURLM_BAD_EASY_HANDLE;
    }
    if (*multi).in_callback {
        return CURLM_RECURSIVE_API_CALL;
    }
    premature = if ((*data).mstate as u32)
        < MSTATE_COMPLETED as i32 as u32
    {
        1 as i32
    } else {
        0 as i32
    } != 0;
    if premature {
        let fresh24 = &mut ((*multi).num_alive);
        *fresh24 -= 1;
    }
    if !((*data).conn).is_null()
        && (*data).mstate as u32 > MSTATE_DO as i32 as u32
        && ((*data).mstate as u32)
            < MSTATE_COMPLETED as i32 as u32
    {
        Curl_conncontrol((*data).conn, 2 as i32);
    }
    if !((*data).conn).is_null() {
        multi_done(data, (*data).result, premature);
    }
    Curl_expire_clear(data);
    if !((*data).connect_queue.ptr).is_null() {
        Curl_llist_remove(
            &mut (*multi).pending,
            &mut (*data).connect_queue,
            0 as *mut libc::c_void,
        );
    }
    if (*data).dns.hostcachetype as u32
        == HCACHE_MULTI as i32 as u32
    {
        let fresh25 = &mut ((*data).dns.hostcache);
        *fresh25 = 0 as *mut Curl_hash;
        (*data).dns.hostcachetype = HCACHE_NONE;
    }
    Curl_wildcard_dtor(&mut (*data).wildcard);
    Curl_llist_destroy(&mut (*data).state.timeoutlist, 0 as *mut libc::c_void);
    (*data).mstate = MSTATE_COMPLETED;
    singlesocket(multi, easy);
    Curl_detach_connnection(data);
    if (*data).state.lastconnect_id != -(1 as i32) as i64 {
        Curl_conncache_foreach(
            data,
            (*data).state.conn_cache,
            0 as *mut libc::c_void,
            Some(
                close_connect_only
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut libc::c_void,
                    ) -> i32,
            ),
        );
    }
    if (*data).psl == &mut (*multi).psl as *mut PslCache {
        let fresh26 = &mut ((*data).psl);
        *fresh26 = 0 as *mut PslCache;
    }
    let fresh27 = &mut ((*data).state.conn_cache);
    *fresh27 = 0 as *mut conncache;
    let fresh28 = &mut ((*data).multi);
    *fresh28 = 0 as *mut Curl_multi;
    e = (*multi).msglist.head;
    while !e.is_null() {
        let mut msg: *mut Curl_message = (*e).ptr as *mut Curl_message;
        if (*msg).extmsg.easy_handle == easy {
            Curl_llist_remove(&mut (*multi).msglist, e, 0 as *mut libc::c_void);
            break;
        } else {
            e = (*e).next;
        }
    }
    e = (*multi).pending.head;
    while !e.is_null() {
        let mut curr_data: *mut Curl_easy = (*e).ptr as *mut Curl_easy;
        if curr_data == data {
            Curl_llist_remove(&mut (*multi).pending, e, 0 as *mut libc::c_void);
            break;
        } else {
            e = (*e).next;
        }
    }
    if !((*data).prev).is_null() {
        let fresh29 = &mut ((*(*data).prev).next);
        *fresh29 = (*data).next;
    } else {
        let fresh30 = &mut ((*multi).easyp);
        *fresh30 = (*data).next;
    }
    if !((*data).next).is_null() {
        let fresh31 = &mut ((*(*data).next).prev);
        *fresh31 = (*data).prev;
    } else {
        let fresh32 = &mut ((*multi).easylp);
        *fresh32 = (*data).prev;
    }
    let fresh33 = &mut ((*multi).num_easy);
    *fresh33 -= 1;
    process_pending_handles(multi);
    Curl_update_timer(multi);
    return CURLM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_multiplex_wanted(mut multi: *const Curl_multi) -> bool {
    return !multi.is_null() && (*multi).multiplexing as i32 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_detach_connnection(mut data: *mut Curl_easy) {
    let mut conn: *mut connectdata = (*data).conn;
    if !conn.is_null() {
        Curl_llist_remove(
            &mut (*conn).easyq,
            &mut (*data).conn_queue,
            0 as *mut libc::c_void,
        );
        Curl_ssl_detach_conn(data, conn);
    }
    let fresh34 = &mut ((*data).conn);
    *fresh34 = 0 as *mut connectdata;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_attach_connnection(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) {
    let fresh35 = &mut ((*data).conn);
    *fresh35 = conn;
    Curl_llist_insert_next(
        &mut (*conn).easyq,
        (*conn).easyq.tail,
        data as *const libc::c_void,
        &mut (*data).conn_queue,
    );
    if ((*(*conn).handler).attach).is_some() {
        ((*(*conn).handler).attach).expect("non-null function pointer")(data, conn);
    }
    Curl_ssl_associate_conn(data, conn);
}
unsafe extern "C" fn waitconnect_getsock(
    mut conn: *mut connectdata,
    mut sock: *mut curl_socket_t,
) -> i32 {
    let mut i: i32 = 0;
    let mut s: i32 = 0 as i32;
    let mut rc: i32 = 0 as i32;
    if (*conn).http_proxy.proxytype as u32
        == CURLPROXY_HTTPS as i32 as u32
        && !(*conn).bits.proxy_ssl_connected[0 as i32 as usize]
    {
        return ((*Curl_ssl).getsock).expect("non-null function pointer")(conn, sock);
    }
    if (*conn).cnnct.state as u32
        >= CONNECT_SOCKS_INIT as i32 as u32
        && ((*conn).cnnct.state as u32)
            < CONNECT_DONE as i32 as u32
    {
        return Curl_SOCKS_getsock(conn, sock, 0 as i32);
    }
    i = 0 as i32;
    while i < 2 as i32 {
        if (*conn).tempsock[i as usize] != -(1 as i32) {
            *sock.offset(s as isize) = (*conn).tempsock[i as usize];
            rc |= (1 as i32) << 16 as i32 + s;
            s += 1;
        }
        i += 1;
    }
    return rc;
}
unsafe extern "C" fn waitproxyconnect_getsock(
    mut conn: *mut connectdata,
    mut sock: *mut curl_socket_t,
) -> i32 {
    *sock.offset(0 as i32 as isize) = (*conn).sock[0 as i32 as usize];
    if !((*conn).connect_state).is_null() {
        return Curl_connect_getsock(conn);
    }
    return (1 as i32) << 16 as i32 + 0 as i32;
}
unsafe extern "C" fn domore_getsock(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> i32 {
    if !conn.is_null() && ((*(*conn).handler).domore_getsock).is_some() {
        return ((*(*conn).handler).domore_getsock)
            .expect("non-null function pointer")(data, conn, socks);
    }
    return 0 as i32;
}
unsafe extern "C" fn doing_getsock(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> i32 {
    if !conn.is_null() && ((*(*conn).handler).doing_getsock).is_some() {
        return ((*(*conn).handler).doing_getsock)
            .expect("non-null function pointer")(data, conn, socks);
    }
    return 0 as i32;
}
unsafe extern "C" fn protocol_getsock(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> i32 {
    if ((*(*conn).handler).proto_getsock).is_some() {
        return ((*(*conn).handler).proto_getsock)
            .expect("non-null function pointer")(data, conn, socks);
    }
    *socks.offset(0 as i32 as isize) = (*conn).sock[0 as i32 as usize];
    return (1 as i32) << 0 as i32
        | (1 as i32) << 16 as i32 + 0 as i32;
}
unsafe extern "C" fn multi_getsock(
    mut data: *mut Curl_easy,
    mut socks: *mut curl_socket_t,
) -> i32 {
    let mut conn: *mut connectdata = (*data).conn;
    if conn.is_null() {
        return 0 as i32;
    }
    match (*data).mstate as u32 {
        3 => return Curl_resolv_getsock(data, socks),
        7 | 6 => return protocol_getsock(data, conn, socks),
        8 | 9 => return doing_getsock(data, conn, socks),
        5 => return waitproxyconnect_getsock(conn, socks),
        4 => return waitconnect_getsock(conn, socks),
        10 => return domore_getsock(data, conn, socks),
        11 | 12 => return Curl_single_getsock(data, conn, socks),
        _ => return 0 as i32,
    };
}
#[no_mangle]
pub unsafe extern "C" fn curl_multi_fdset(
    mut multi: *mut Curl_multi,
    mut read_fd_set: *mut fd_set,
    mut write_fd_set: *mut fd_set,
    mut exc_fd_set: *mut fd_set,
    mut max_fd: *mut i32,
) -> CURLMcode {
    let mut data: *mut Curl_easy = 0 as *mut Curl_easy;
    let mut this_max_fd: i32 = -(1 as i32);
    let mut sockbunch: [curl_socket_t; 5] = [0; 5];
    let mut i: i32 = 0;
    if !(!multi.is_null() && (*multi).magic == 0xbab1e as i32 as u32) {
        return CURLM_BAD_HANDLE;
    }
    if (*multi).in_callback {
        return CURLM_RECURSIVE_API_CALL;
    }
    data = (*multi).easyp;
    while !data.is_null() {
        let mut bitmap: i32 = 0;
        bitmap = multi_getsock(data, sockbunch.as_mut_ptr());
        let mut current_block_13: u64;
        i = 0 as i32;
        while i < 5 as i32 {
            let mut s: curl_socket_t = -(1 as i32);
            if bitmap & (1 as i32) << i != 0
                && sockbunch[i as usize] >= 0 as i32
            {
                if !(sockbunch[i as usize] < 1024 as i32) {
                    current_block_13 = 13109137661213826276;
                } else {
                    let fresh36 = &mut ((*read_fd_set)
                        .__fds_bits[(sockbunch[i as usize]
                        / (8 as i32
                            * ::std::mem::size_of::<__fd_mask>() as u64
                                as i32)) as usize]);
                    *fresh36
                        |= ((1 as u64)
                            << sockbunch[i as usize]
                                % (8 as i32
                                    * ::std::mem::size_of::<__fd_mask>() as u64
                                        as i32)) as __fd_mask;
                    s = sockbunch[i as usize];
                    current_block_13 = 12039483399334584727;
                }
            } else {
                current_block_13 = 12039483399334584727;
            }
            match current_block_13 {
                12039483399334584727 => {
                    if bitmap & (1 as i32) << 16 as i32 + i != 0
                        && sockbunch[i as usize] >= 0 as i32
                    {
                        if !(sockbunch[i as usize] < 1024 as i32) {
                            current_block_13 = 13109137661213826276;
                        } else {
                            let fresh37 = &mut ((*write_fd_set)
                                .__fds_bits[(sockbunch[i as usize]
                                / (8 as i32
                                    * ::std::mem::size_of::<__fd_mask>() as u64
                                        as i32)) as usize]);
                            *fresh37
                                |= ((1 as u64)
                                    << sockbunch[i as usize]
                                        % (8 as i32
                                            * ::std::mem::size_of::<__fd_mask>() as u64
                                                as i32)) as __fd_mask;
                            s = sockbunch[i as usize];
                            current_block_13 = 12147880666119273379;
                        }
                    } else {
                        current_block_13 = 12147880666119273379;
                    }
                    match current_block_13 {
                        13109137661213826276 => {}
                        _ => {
                            if s == -(1 as i32) {
                                break;
                            }
                            if s > this_max_fd {
                                this_max_fd = s;
                            }
                        }
                    }
                }
                _ => {}
            }
            i += 1;
        }
        data = (*data).next;
    }
    *max_fd = this_max_fd;
    return CURLM_OK;
}
unsafe extern "C" fn multi_wait(
    mut multi: *mut Curl_multi,
    mut extra_fds: *mut curl_waitfd,
    mut extra_nfds: u32,
    mut timeout_ms: i32,
    mut ret: *mut i32,
    mut extrawait: bool,
    mut use_wakeup: bool,
) -> CURLMcode {
    let mut data: *mut Curl_easy = 0 as *mut Curl_easy;
    let mut sockbunch: [curl_socket_t; 5] = [0; 5];
    let mut bitmap: i32 = 0;
    let mut i: u32 = 0;
    let mut nfds: u32 = 0 as i32 as u32;
    let mut curlfds: u32 = 0;
    let mut timeout_internal: i64 = 0;
    let mut retcode: i32 = 0 as i32;
    let mut a_few_on_stack: [pollfd; 10] = [pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    }; 10];
    let mut ufds: *mut pollfd = &mut *a_few_on_stack
        .as_mut_ptr()
        .offset(0 as i32 as isize) as *mut pollfd;
    let mut ufds_malloc: bool = 0 as i32 != 0;
    if !(!multi.is_null() && (*multi).magic == 0xbab1e as i32 as u32) {
        return CURLM_BAD_HANDLE;
    }
    if (*multi).in_callback {
        return CURLM_RECURSIVE_API_CALL;
    }
    if timeout_ms < 0 as i32 {
        return CURLM_BAD_FUNCTION_ARGUMENT;
    }
    data = (*multi).easyp;
    while !data.is_null() {
        bitmap = multi_getsock(data, sockbunch.as_mut_ptr());
        i = 0 as i32 as u32;
        while i < 5 as i32 as u32 {
            let mut s: curl_socket_t = -(1 as i32);
            if bitmap & (1 as i32) << i != 0
                && sockbunch[i as usize] >= 0 as i32
            {
                nfds = nfds.wrapping_add(1);
                s = sockbunch[i as usize];
            }
            if bitmap
                & (1 as i32)
                    << (16 as i32 as u32).wrapping_add(i) != 0
                && sockbunch[i as usize] >= 0 as i32
            {
                nfds = nfds.wrapping_add(1);
                s = sockbunch[i as usize];
            }
            if s == -(1 as i32) {
                break;
            }
            i = i.wrapping_add(1);
        }
        data = (*data).next;
    }
    multi_timeout(multi, &mut timeout_internal);
    if timeout_internal >= 0 as i32 as i64
        && timeout_internal < timeout_ms as i64
    {
        timeout_ms = timeout_internal as i32;
    }
    curlfds = nfds;
    nfds = nfds.wrapping_add(extra_nfds);
    if use_wakeup as i32 != 0
        && (*multi).wakeup_pair[0 as i32 as usize] != -(1 as i32)
    {
        nfds = nfds.wrapping_add(1);
    }
    if nfds > 10 as i32 as u32 {
        ufds = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )(
            (nfds as u64)
                .wrapping_mul(::std::mem::size_of::<pollfd>() as u64),
        ) as *mut pollfd;
        if ufds.is_null() {
            return CURLM_OUT_OF_MEMORY;
        }
        ufds_malloc = 1 as i32 != 0;
    }
    nfds = 0 as i32 as u32;
    if curlfds != 0 {
        data = (*multi).easyp;
        while !data.is_null() {
            bitmap = multi_getsock(data, sockbunch.as_mut_ptr());
            i = 0 as i32 as u32;
            while i < 5 as i32 as u32 {
                let mut s_0: curl_socket_t = -(1 as i32);
                if bitmap & (1 as i32) << i != 0
                    && sockbunch[i as usize] >= 0 as i32
                {
                    s_0 = sockbunch[i as usize];
                    (*ufds.offset(nfds as isize)).fd = s_0;
                    (*ufds.offset(nfds as isize))
                        .events = 0x1 as i32 as i16;
                    nfds = nfds.wrapping_add(1);
                }
                if bitmap
                    & (1 as i32)
                        << (16 as i32 as u32).wrapping_add(i) != 0
                    && sockbunch[i as usize] >= 0 as i32
                {
                    s_0 = sockbunch[i as usize];
                    (*ufds.offset(nfds as isize)).fd = s_0;
                    (*ufds.offset(nfds as isize))
                        .events = 0x4 as i32 as i16;
                    nfds = nfds.wrapping_add(1);
                }
                if s_0 == -(1 as i32) {
                    break;
                }
                i = i.wrapping_add(1);
            }
            data = (*data).next;
        }
    }
    i = 0 as i32 as u32;
    while i < extra_nfds {
        (*ufds.offset(nfds as isize)).fd = (*extra_fds.offset(i as isize)).fd;
        (*ufds.offset(nfds as isize)).events = 0 as i32 as i16;
        if (*extra_fds.offset(i as isize)).events as i32 & 0x1 as i32
            != 0
        {
            let fresh38 = &mut ((*ufds.offset(nfds as isize)).events);
            *fresh38 = (*fresh38 as i32 | 0x1 as i32) as i16;
        }
        if (*extra_fds.offset(i as isize)).events as i32 & 0x2 as i32
            != 0
        {
            let fresh39 = &mut ((*ufds.offset(nfds as isize)).events);
            *fresh39 = (*fresh39 as i32 | 0x2 as i32) as i16;
        }
        if (*extra_fds.offset(i as isize)).events as i32 & 0x4 as i32
            != 0
        {
            let fresh40 = &mut ((*ufds.offset(nfds as isize)).events);
            *fresh40 = (*fresh40 as i32 | 0x4 as i32) as i16;
        }
        nfds = nfds.wrapping_add(1);
        i = i.wrapping_add(1);
    }
    if use_wakeup as i32 != 0
        && (*multi).wakeup_pair[0 as i32 as usize] != -(1 as i32)
    {
        (*ufds.offset(nfds as isize))
            .fd = (*multi).wakeup_pair[0 as i32 as usize];
        (*ufds.offset(nfds as isize)).events = 0x1 as i32 as i16;
        nfds = nfds.wrapping_add(1);
    }
    if nfds != 0 {
        let mut pollrc: i32 = 0;
        pollrc = Curl_poll(ufds, nfds, timeout_ms as timediff_t);
        if pollrc > 0 as i32 {
            retcode = pollrc;
            i = 0 as i32 as u32;
            while i < extra_nfds {
                let mut r: u32 = (*ufds
                    .offset(curlfds.wrapping_add(i) as isize))
                    .revents as u32;
                let mut mask: u16 = 0 as i32 as u16;
                if r & 0x1 as i32 as u32 != 0 {
                    mask = (mask as i32 | 0x1 as i32) as u16;
                }
                if r & 0x4 as i32 as u32 != 0 {
                    mask = (mask as i32 | 0x4 as i32) as u16;
                }
                if r & 0x2 as i32 as u32 != 0 {
                    mask = (mask as i32 | 0x2 as i32) as u16;
                }
                (*extra_fds.offset(i as isize)).revents = mask as i16;
                i = i.wrapping_add(1);
            }
            if use_wakeup as i32 != 0
                && (*multi).wakeup_pair[0 as i32 as usize] != -(1 as i32)
            {
                if (*ufds.offset(curlfds.wrapping_add(extra_nfds) as isize)).revents
                    as i32 & 0x1 as i32 != 0
                {
                    let mut buf: [i8; 64] = [0; 64];
                    let mut nread: ssize_t = 0;
                    loop {
                        nread = recv(
                            (*multi).wakeup_pair[0 as i32 as usize],
                            buf.as_mut_ptr() as *mut libc::c_void,
                            ::std::mem::size_of::<[i8; 64]>() as u64,
                            0 as i32,
                        );
                        if !(nread <= 0 as i32 as i64) {
                            continue;
                        }
                        if !(nread < 0 as i32 as i64
                            && 4 as i32 == *__errno_location())
                        {
                            break;
                        }
                    }
                    retcode -= 1;
                }
            }
        }
    }
    if ufds_malloc {
        Curl_cfree.expect("non-null function pointer")(ufds as *mut libc::c_void);
    }
    if !ret.is_null() {
        *ret = retcode;
    }
    if extrawait as i32 != 0 && nfds == 0 {
        let mut sleep_ms: i64 = 0 as i32 as i64;
        if curl_multi_timeout(multi, &mut sleep_ms) as u64 == 0 && sleep_ms != 0 {
            if sleep_ms > timeout_ms as i64 {
                sleep_ms = timeout_ms as i64;
            } else if sleep_ms < 0 as i32 as i64 {
                sleep_ms = timeout_ms as i64;
            }
            Curl_wait_ms(sleep_ms);
        }
    }
    return CURLM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn curl_multi_wait(
    mut multi: *mut Curl_multi,
    mut extra_fds: *mut curl_waitfd,
    mut extra_nfds: u32,
    mut timeout_ms: i32,
    mut ret: *mut i32,
) -> CURLMcode {
    return multi_wait(
        multi,
        extra_fds,
        extra_nfds,
        timeout_ms,
        ret,
        0 as i32 != 0,
        0 as i32 != 0,
    );
}
#[no_mangle]
pub unsafe extern "C" fn curl_multi_poll(
    mut multi: *mut Curl_multi,
    mut extra_fds: *mut curl_waitfd,
    mut extra_nfds: u32,
    mut timeout_ms: i32,
    mut ret: *mut i32,
) -> CURLMcode {
    return multi_wait(
        multi,
        extra_fds,
        extra_nfds,
        timeout_ms,
        ret,
        1 as i32 != 0,
        1 as i32 != 0,
    );
}
#[no_mangle]
pub unsafe extern "C" fn curl_multi_wakeup(mut multi: *mut Curl_multi) -> CURLMcode {
    if !(!multi.is_null() && (*multi).magic == 0xbab1e as i32 as u32) {
        return CURLM_BAD_HANDLE;
    }
    if (*multi).wakeup_pair[1 as i32 as usize] != -(1 as i32) {
        let mut buf: [i8; 1] = [0; 1];
        buf[0 as i32 as usize] = 1 as i32 as i8;
        loop {
            if send(
                (*multi).wakeup_pair[1 as i32 as usize],
                buf.as_mut_ptr() as *const libc::c_void,
                ::std::mem::size_of::<[i8; 1]>() as u64,
                MSG_NOSIGNAL as i32,
            ) < 0 as i32 as i64
            {
                let mut err: i32 = *__errno_location();
                let mut return_success: i32 = 0;
                if 4 as i32 == err {
                    continue;
                }
                return_success = (11 as i32 == err || 11 as i32 == err)
                    as i32;
                if return_success == 0 {
                    return CURLM_WAKEUP_FAILURE;
                }
            }
            return CURLM_OK;
        }
    }
    return CURLM_WAKEUP_FAILURE;
}
unsafe extern "C" fn multi_ischanged(
    mut multi: *mut Curl_multi,
    mut clear: bool,
) -> bool {
    let mut retval: bool = (*multi).recheckstate;
    if clear {
        (*multi).recheckstate = 0 as i32 != 0;
    }
    return retval;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_multi_add_perform(
    mut multi: *mut Curl_multi,
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLMcode {
    let mut rc: CURLMcode = CURLM_OK;
    if (*multi).in_callback {
        return CURLM_RECURSIVE_API_CALL;
    }
    rc = curl_multi_add_handle(multi, data);
    if rc as u64 == 0 {
        let mut k: *mut SingleRequest = &mut (*data).req;
        Curl_init_do(data, 0 as *mut connectdata);
        mstate(data, MSTATE_PERFORMING);
        Curl_attach_connnection(data, conn);
        (*k).keepon |= (1 as i32) << 0 as i32;
    }
    return rc;
}
unsafe extern "C" fn multi_do(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    if ((*(*conn).handler).do_it).is_some() {
        result = ((*(*conn).handler).do_it)
            .expect("non-null function pointer")(data, done);
    }
    return result;
}
unsafe extern "C" fn multi_do_more(
    mut data: *mut Curl_easy,
    mut complete: *mut i32,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    *complete = 0 as i32;
    if ((*(*conn).handler).do_more).is_some() {
        result = ((*(*conn).handler).do_more)
            .expect("non-null function pointer")(data, complete);
    }
    return result;
}
unsafe extern "C" fn multi_handle_timeout(
    mut data: *mut Curl_easy,
    mut now: *mut curltime,
    mut stream_error: *mut bool,
    mut result: *mut CURLcode,
    mut connect_timeout: bool,
) -> bool {
    let mut timeout_ms: timediff_t = 0;
    timeout_ms = Curl_timeleft(data, now, connect_timeout);
    if timeout_ms < 0 as i32 as i64 {
        if (*data).mstate as u32
            == MSTATE_RESOLVING as i32 as u32
        {
            Curl_failf(
                data,
                b"Resolving timed out after %ld milliseconds\0" as *const u8
                    as *const i8,
                Curl_timediff(*now, (*data).progress.t_startsingle),
            );
        } else if (*data).mstate as u32
                == MSTATE_CONNECTING as i32 as u32
            {
            Curl_failf(
                data,
                b"Connection timed out after %ld milliseconds\0" as *const u8
                    as *const i8,
                Curl_timediff(*now, (*data).progress.t_startsingle),
            );
        } else {
            let mut k: *mut SingleRequest = &mut (*data).req;
            if (*k).size != -(1 as i32) as i64 {
                Curl_failf(
                    data,
                    b"Operation timed out after %ld milliseconds with %ld out of %ld bytes received\0"
                        as *const u8 as *const i8,
                    Curl_timediff(*now, (*data).progress.t_startsingle),
                    (*k).bytecount,
                    (*k).size,
                );
            } else {
                Curl_failf(
                    data,
                    b"Operation timed out after %ld milliseconds with %ld bytes received\0"
                        as *const u8 as *const i8,
                    Curl_timediff(*now, (*data).progress.t_startsingle),
                    (*k).bytecount,
                );
            }
        }
        if (*data).mstate as u32 > MSTATE_DO as i32 as u32 {
            Curl_conncontrol((*data).conn, 2 as i32);
            *stream_error = 1 as i32 != 0;
        }
        *result = CURLE_OPERATION_TIMEDOUT;
        multi_done(data, *result, 1 as i32 != 0);
    }
    return timeout_ms < 0 as i32 as i64;
}
unsafe extern "C" fn protocol_connecting(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    if !conn.is_null() && ((*(*conn).handler).connecting).is_some() {
        *done = 0 as i32 != 0;
        result = ((*(*conn).handler).connecting)
            .expect("non-null function pointer")(data, done);
    } else {
        *done = 1 as i32 != 0;
    }
    return result;
}
unsafe extern "C" fn protocol_doing(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    if !conn.is_null() && ((*(*conn).handler).doing).is_some() {
        *done = 0 as i32 != 0;
        result = ((*(*conn).handler).doing)
            .expect("non-null function pointer")(data, done);
    } else {
        *done = 1 as i32 != 0;
    }
    return result;
}
unsafe extern "C" fn protocol_connect(
    mut data: *mut Curl_easy,
    mut protocol_done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    *protocol_done = 0 as i32 != 0;
    if (*conn).bits.tcpconnect[0 as i32 as usize] as i32 != 0
        && ((*conn).bits).protoconnstart() as i32 != 0
    {
        if ((*(*conn).handler).connecting).is_none() {
            *protocol_done = 1 as i32 != 0;
        }
        return CURLE_OK;
    }
    if ((*conn).bits).protoconnstart() == 0 {
        result = Curl_proxy_connect(data, 0 as i32);
        if result as u64 != 0 {
            return result;
        }
        if (*conn).http_proxy.proxytype as u32
            == CURLPROXY_HTTPS as i32 as u32
            && !(*conn).bits.proxy_ssl_connected[0 as i32 as usize]
        {
            return CURLE_OK;
        }
        if ((*conn).bits).tunnel_proxy() as i32 != 0
            && ((*conn).bits).httpproxy() as i32 != 0
            && Curl_connect_ongoing(conn) as i32 != 0
        {
            return CURLE_OK;
        }
        if ((*(*conn).handler).connect_it).is_some() {
            result = ((*(*conn).handler).connect_it)
                .expect("non-null function pointer")(data, protocol_done);
        } else {
            *protocol_done = 1 as i32 != 0;
        }
        if result as u64 == 0 {
            let fresh41 = &mut ((*conn).bits);
            (*fresh41).set_protoconnstart(1 as i32 as bit);
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_preconnect(mut data: *mut Curl_easy) -> CURLcode {
    if ((*data).state.buffer).is_null() {
        let fresh42 = &mut ((*data).state.buffer);
        *fresh42 = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )(((*data).set.buffer_size + 1 as i32 as i64) as size_t)
            as *mut i8;
        if ((*data).state.buffer).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
unsafe extern "C" fn multi_runsingle(
    mut multi: *mut Curl_multi,
    mut nowp: *mut curltime,
    mut data: *mut Curl_easy,
) -> CURLMcode {
    let mut msg: *mut Curl_message = 0 as *mut Curl_message;
    let mut connected: bool = false;
    let mut async_0: bool = false;
    let mut protocol_connected: bool = 0 as i32 != 0;
    let mut dophase_done: bool = 0 as i32 != 0;
    let mut done: bool = 0 as i32 != 0;
    let mut rc: CURLMcode = CURLM_OK;
    let mut result: CURLcode = CURLE_OK;
    let mut recv_timeout_ms: timediff_t = 0;
    let mut send_timeout_ms: timediff_t = 0;
    let mut control: i32 = 0;
    if !(!data.is_null() && (*data).magic == 0xc0dedbad as u32) {
        return CURLM_BAD_EASY_HANDLE;
    }
    loop {
        let mut current_block_373: u64;
        let mut stream_error: bool = 0 as i32 != 0;
        rc = CURLM_OK;
        if multi_ischanged(multi, 1 as i32 != 0) {
            process_pending_handles(multi);
        }
        if (*data).mstate as u32 > MSTATE_CONNECT as i32 as u32
            && ((*data).mstate as u32)
                < MSTATE_COMPLETED as i32 as u32
        {
            if ((*data).conn).is_null() {
                return CURLM_INTERNAL_ERROR;
            }
        }
        if !((*data).conn).is_null()
            && (*data).mstate as u32
                >= MSTATE_CONNECT as i32 as u32
            && ((*data).mstate as u32)
                < MSTATE_COMPLETED as i32 as u32
        {
            if multi_handle_timeout(
                data,
                nowp,
                &mut stream_error,
                &mut result,
                0 as i32 != 0,
            ) {
                current_block_373 = 18267909660717707325;
            } else {
                current_block_373 = 17478428563724192186;
            }
        } else {
            current_block_373 = 17478428563724192186;
        }
        match current_block_373 {
            17478428563724192186 => {
                let mut current_block_332: u64;
                match (*data).mstate as u32 {
                    0 => {
                        result = Curl_pretransfer(data);
                        if result as u64 == 0 {
                            mstate(data, MSTATE_CONNECT);
                            *nowp = Curl_pgrsTime(data, TIMER_STARTOP);
                            rc = CURLM_CALL_MULTI_PERFORM;
                        }
                    }
                    2 => {
                        result = Curl_preconnect(data);
                        if !(result as u64 != 0) {
                            *nowp = Curl_pgrsTime(data, TIMER_STARTSINGLE);
                            if (*data).set.timeout != 0 {
                                Curl_expire(data, (*data).set.timeout, EXPIRE_TIMEOUT);
                            }
                            if (*data).set.connecttimeout != 0 {
                                Curl_expire(
                                    data,
                                    (*data).set.connecttimeout,
                                    EXPIRE_CONNECTTIMEOUT,
                                );
                            }
                            result = Curl_connect(
                                data,
                                &mut async_0,
                                &mut protocol_connected,
                            );
                            if CURLE_NO_CONNECTION_AVAILABLE as i32
                                as u32 == result as u32
                            {
                                mstate(data, MSTATE_PENDING);
                                Curl_llist_insert_next(
                                    &mut (*multi).pending,
                                    (*multi).pending.tail,
                                    data as *const libc::c_void,
                                    &mut (*data).connect_queue,
                                );
                                result = CURLE_OK;
                            } else {
                                if ((*data).state).previouslypending() != 0 {
                                    Curl_infof(
                                        data,
                                        b"Transfer was pending, now try another\0" as *const u8
                                            as *const i8,
                                    );
                                    process_pending_handles((*data).multi);
                                }
                                if result as u64 == 0 {
                                    if async_0 {
                                        mstate(data, MSTATE_RESOLVING);
                                    } else {
                                        rc = CURLM_CALL_MULTI_PERFORM;
                                        if protocol_connected {
                                            mstate(data, MSTATE_DO);
                                        } else if Curl_connect_ongoing((*data).conn) {
                                            mstate(data, MSTATE_TUNNELING);
                                        } else {
                                            mstate(data, MSTATE_CONNECTING);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    3 => {
                        let mut dns: *mut Curl_dns_entry = 0 as *mut Curl_dns_entry;
                        let mut conn: *mut connectdata = (*data).conn;
                        let mut hostname: *const i8 = 0 as *const i8;
                        if ((*conn).bits).httpproxy() != 0 {
                            hostname = (*conn).http_proxy.host.name;
                        } else if ((*conn).bits).conn_to_host() != 0 {
                            hostname = (*conn).conn_to_host.name;
                        } else {
                            hostname = (*conn).host.name;
                        }
                        dns = Curl_fetch_addr(data, hostname, (*conn).port);
                        if !dns.is_null() {
                            let fresh43 = &mut ((*data).state.async_0.dns);
                            *fresh43 = dns;
                            let fresh44 = &mut ((*data).state.async_0);
                            (*fresh44).set_done(1 as i32 as bit);
                            result = CURLE_OK;
                            Curl_infof(
                                data,
                                b"Hostname '%s' was found in DNS cache\0" as *const u8
                                    as *const i8,
                                hostname,
                            );
                        }
                        if dns.is_null() {
                            result = Curl_resolv_check(data, &mut dns);
                        }
                        singlesocket(multi, data);
                        if !dns.is_null() {
                            result = Curl_once_resolved(data, &mut protocol_connected);
                            if result as u64 != 0 {
                                let fresh45 = &mut ((*data).conn);
                                *fresh45 = 0 as *mut connectdata;
                            } else {
                                rc = CURLM_CALL_MULTI_PERFORM;
                                if protocol_connected {
                                    mstate(data, MSTATE_DO);
                                } else if Curl_connect_ongoing((*data).conn) {
                                    mstate(data, MSTATE_TUNNELING);
                                } else {
                                    mstate(data, MSTATE_CONNECTING);
                                }
                            }
                        }
                        if result as u64 != 0 {
                            stream_error = 1 as i32 != 0;
                        }
                    }
                    5 => {
                        result = Curl_http_connect(data, &mut protocol_connected);
                        if ((*(*data).conn).bits).proxy_connect_closed() != 0 {
                            rc = CURLM_CALL_MULTI_PERFORM;
                            result = CURLE_OK;
                            multi_done(data, CURLE_OK, 0 as i32 != 0);
                            mstate(data, MSTATE_CONNECT);
                        } else if result as u64 == 0 {
                            if ((*(*data).conn).http_proxy.proxytype as u32
                                != CURLPROXY_HTTPS as i32 as u32
                                || (*(*data).conn)
                                    .bits
                                    .proxy_ssl_connected[0 as i32 as usize]
                                    as i32 != 0)
                                && Curl_connect_complete((*data).conn) as i32 != 0
                            {
                                rc = CURLM_CALL_MULTI_PERFORM;
                                mstate(data, MSTATE_PROTOCONNECT);
                            }
                        } else {
                            stream_error = 1 as i32 != 0;
                        }
                    }
                    4 => {
                        result = Curl_is_connected(
                            data,
                            (*data).conn,
                            0 as i32,
                            &mut connected,
                        );
                        if connected as i32 != 0 && result as u64 == 0 {
                            if (*(*data).conn).http_proxy.proxytype as u32
                                == CURLPROXY_HTTPS as i32 as u32
                                && !(*(*data).conn)
                                    .bits
                                    .proxy_ssl_connected[0 as i32 as usize]
                                || Curl_connect_ongoing((*data).conn) as i32 != 0
                            {
                                mstate(data, MSTATE_TUNNELING);
                            } else {
                                rc = CURLM_CALL_MULTI_PERFORM;
                                mstate(
                                    data,
                                    (if ((*(*data).conn).bits).tunnel_proxy() as i32
                                        != 0
                                    {
                                        MSTATE_TUNNELING as i32
                                    } else {
                                        MSTATE_PROTOCONNECT as i32
                                    }) as CURLMstate,
                                );
                            }
                        } else if result as u64 != 0 {
                            Curl_posttransfer(data);
                            multi_done(data, result, 1 as i32 != 0);
                            stream_error = 1 as i32 != 0;
                        }
                    }
                    6 => {
                        result = protocol_connect(data, &mut protocol_connected);
                        if result as u64 == 0 && !protocol_connected {
                            mstate(data, MSTATE_PROTOCONNECTING);
                        } else if result as u64 == 0 {
                            mstate(data, MSTATE_DO);
                            rc = CURLM_CALL_MULTI_PERFORM;
                        } else {
                            Curl_posttransfer(data);
                            multi_done(data, result, 1 as i32 != 0);
                            stream_error = 1 as i32 != 0;
                        }
                    }
                    7 => {
                        result = protocol_connecting(data, &mut protocol_connected);
                        if result as u64 == 0 && protocol_connected as i32 != 0 {
                            mstate(data, MSTATE_DO);
                            rc = CURLM_CALL_MULTI_PERFORM;
                        } else if result as u64 != 0 {
                            Curl_posttransfer(data);
                            multi_done(data, result, 1 as i32 != 0);
                            stream_error = 1 as i32 != 0;
                        }
                    }
                    8 => {
                        if ((*data).set).connect_only() != 0 {
                            Curl_conncontrol((*data).conn, 0 as i32);
                            mstate(data, MSTATE_DONE);
                            result = CURLE_OK;
                            rc = CURLM_CALL_MULTI_PERFORM;
                        } else {
                            result = multi_do(data, &mut dophase_done);
                            if result as u64 == 0 {
                                if !dophase_done {
                                    if ((*data).state).wildcardmatch() != 0 {
                                        let mut wc: *mut WildcardData = &mut (*data).wildcard;
                                        if (*wc).state as u32
                                            == CURLWC_DONE as i32 as u32
                                            || (*wc).state as u32
                                                == CURLWC_SKIP as i32 as u32
                                        {
                                            multi_done(data, CURLE_OK, 0 as i32 != 0);
                                            mstate(
                                                data,
                                                (if !((*data).conn).is_null() {
                                                    MSTATE_DONE as i32
                                                } else {
                                                    MSTATE_COMPLETED as i32
                                                }) as CURLMstate,
                                            );
                                            rc = CURLM_CALL_MULTI_PERFORM;
                                            current_block_332 = 14851975181745310361;
                                        } else {
                                            current_block_332 = 10784681114964964746;
                                        }
                                    } else {
                                        current_block_332 = 10784681114964964746;
                                    }
                                    match current_block_332 {
                                        14851975181745310361 => {}
                                        _ => {
                                            mstate(data, MSTATE_DOING);
                                            rc = CURLM_OK;
                                        }
                                    }
                                } else if ((*(*data).conn).bits).do_more() != 0 {
                                    mstate(data, MSTATE_DOING_MORE);
                                    rc = CURLM_OK;
                                } else {
                                    mstate(data, MSTATE_DID);
                                    rc = CURLM_CALL_MULTI_PERFORM;
                                }
                            } else if CURLE_SEND_ERROR as i32 as u32
                                    == result as u32
                                    && ((*(*data).conn).bits).reuse() as i32 != 0
                                {
                                let mut newurl: *mut i8 = 0 as *mut i8;
                                let mut follow: followtype = FOLLOW_NONE;
                                let mut drc: CURLcode = CURLE_OK;
                                drc = Curl_retry_request(data, &mut newurl);
                                if drc as u64 != 0 {
                                    result = drc;
                                    stream_error = 1 as i32 != 0;
                                }
                                Curl_posttransfer(data);
                                drc = multi_done(data, result, 0 as i32 != 0);
                                if !newurl.is_null() {
                                    if drc as u64 == 0
                                        || drc as u32
                                            == CURLE_SEND_ERROR as i32 as u32
                                    {
                                        follow = FOLLOW_RETRY;
                                        drc = Curl_follow(data, newurl, follow);
                                        if drc as u64 == 0 {
                                            mstate(data, MSTATE_CONNECT);
                                            rc = CURLM_CALL_MULTI_PERFORM;
                                            result = CURLE_OK;
                                        } else {
                                            result = drc;
                                        }
                                    } else {
                                        result = drc;
                                    }
                                } else {
                                    stream_error = 1 as i32 != 0;
                                }
                                Curl_cfree
                                    .expect(
                                        "non-null function pointer",
                                    )(newurl as *mut libc::c_void);
                            } else {
                                Curl_posttransfer(data);
                                if !((*data).conn).is_null() {
                                    multi_done(data, result, 0 as i32 != 0);
                                }
                                stream_error = 1 as i32 != 0;
                            }
                        }
                    }
                    9 => {
                        result = protocol_doing(data, &mut dophase_done);
                        if result as u64 == 0 {
                            if dophase_done {
                                mstate(
                                    data,
                                    (if ((*(*data).conn).bits).do_more() as i32 != 0 {
                                        MSTATE_DOING_MORE as i32
                                    } else {
                                        MSTATE_DID as i32
                                    }) as CURLMstate,
                                );
                                rc = CURLM_CALL_MULTI_PERFORM;
                            }
                        } else {
                            Curl_posttransfer(data);
                            multi_done(data, result, 0 as i32 != 0);
                            stream_error = 1 as i32 != 0;
                        }
                    }
                    10 => {
                        result = multi_do_more(data, &mut control);
                        if result as u64 == 0 {
                            if control != 0 {
                                mstate(
                                    data,
                                    (if control == 1 as i32 {
                                        MSTATE_DID as i32
                                    } else {
                                        MSTATE_DOING as i32
                                    }) as CURLMstate,
                                );
                                rc = CURLM_CALL_MULTI_PERFORM;
                            } else {
                                rc = CURLM_OK;
                            }
                        } else {
                            Curl_posttransfer(data);
                            multi_done(data, result, 0 as i32 != 0);
                            stream_error = 1 as i32 != 0;
                        }
                    }
                    11 => {
                        if ((*(*data).conn).bits).multiplex() != 0 {
                            process_pending_handles(multi);
                        }
                        if (*(*data).conn).sockfd != -(1 as i32)
                            || (*(*data).conn).writesockfd != -(1 as i32)
                        {
                            mstate(data, MSTATE_PERFORMING);
                        } else {
                            if ((*data).state).wildcardmatch() as i32 != 0
                                && (*(*(*data).conn).handler).flags
                                    & ((1 as i32) << 12 as i32) as u32
                                    == 0 as i32 as u32
                            {
                                (*data).wildcard.state = CURLWC_DONE;
                            }
                            mstate(data, MSTATE_DONE);
                        }
                        rc = CURLM_CALL_MULTI_PERFORM;
                    }
                    13 => {
                        if Curl_pgrsUpdate(data) != 0 {
                            result = CURLE_ABORTED_BY_CALLBACK;
                        } else {
                            result = Curl_speedcheck(data, *nowp);
                        }
                        if result as u64 != 0 {
                            if (*(*(*data).conn).handler).flags
                                & ((1 as i32) << 1 as i32) as u32
                                == 0
                                && result as u32
                                    != CURLE_HTTP2_STREAM as i32 as u32
                            {
                                Curl_conncontrol((*data).conn, 2 as i32);
                            }
                            Curl_posttransfer(data);
                            multi_done(data, result, 1 as i32 != 0);
                        } else {
                            send_timeout_ms = 0 as i32 as timediff_t;
                            if (*data).set.max_send_speed != 0 {
                                send_timeout_ms = Curl_pgrsLimitWaitTime(
                                    (*data).progress.uploaded,
                                    (*data).progress.ul_limit_size,
                                    (*data).set.max_send_speed,
                                    (*data).progress.ul_limit_start,
                                    *nowp,
                                );
                            }
                            recv_timeout_ms = 0 as i32 as timediff_t;
                            if (*data).set.max_recv_speed != 0 {
                                recv_timeout_ms = Curl_pgrsLimitWaitTime(
                                    (*data).progress.downloaded,
                                    (*data).progress.dl_limit_size,
                                    (*data).set.max_recv_speed,
                                    (*data).progress.dl_limit_start,
                                    *nowp,
                                );
                            }
                            if send_timeout_ms == 0 && recv_timeout_ms == 0 {
                                mstate(data, MSTATE_PERFORMING);
                                Curl_ratelimit(data, *nowp);
                            } else if send_timeout_ms >= recv_timeout_ms {
                                Curl_expire(data, send_timeout_ms, EXPIRE_TOOFAST);
                            } else {
                                Curl_expire(data, recv_timeout_ms, EXPIRE_TOOFAST);
                            }
                        }
                    }
                    12 => {
                        let mut newurl_0: *mut i8 = 0 as *mut i8;
                        let mut retry: bool = 0 as i32 != 0;
                        let mut comeback: bool = 0 as i32 != 0;
                        send_timeout_ms = 0 as i32 as timediff_t;
                        if (*data).set.max_send_speed != 0 {
                            send_timeout_ms = Curl_pgrsLimitWaitTime(
                                (*data).progress.uploaded,
                                (*data).progress.ul_limit_size,
                                (*data).set.max_send_speed,
                                (*data).progress.ul_limit_start,
                                *nowp,
                            );
                        }
                        recv_timeout_ms = 0 as i32 as timediff_t;
                        if (*data).set.max_recv_speed != 0 {
                            recv_timeout_ms = Curl_pgrsLimitWaitTime(
                                (*data).progress.downloaded,
                                (*data).progress.dl_limit_size,
                                (*data).set.max_recv_speed,
                                (*data).progress.dl_limit_start,
                                *nowp,
                            );
                        }
                        if send_timeout_ms != 0 || recv_timeout_ms != 0 {
                            Curl_ratelimit(data, *nowp);
                            mstate(data, MSTATE_RATELIMITING);
                            if send_timeout_ms >= recv_timeout_ms {
                                Curl_expire(data, send_timeout_ms, EXPIRE_TOOFAST);
                            } else {
                                Curl_expire(data, recv_timeout_ms, EXPIRE_TOOFAST);
                            }
                        } else {
                            result = Curl_readwrite(
                                (*data).conn,
                                data,
                                &mut done,
                                &mut comeback,
                            );
                            if done as i32 != 0
                                || result as u32
                                    == CURLE_RECV_ERROR as i32 as u32
                            {
                                let mut ret: CURLcode = Curl_retry_request(
                                    data,
                                    &mut newurl_0,
                                );
                                if ret as u64 == 0 {
                                    retry = if !newurl_0.is_null() {
                                        1 as i32
                                    } else {
                                        0 as i32
                                    } != 0;
                                } else if result as u64 == 0 {
                                    result = ret;
                                }
                                if retry {
                                    result = CURLE_OK;
                                    done = 1 as i32 != 0;
                                }
                            } else if CURLE_HTTP2_STREAM as i32 as u32
                                    == result as u32
                                    && Curl_h2_http_1_1_error(data) as i32 != 0
                                {
                                let mut ret_0: CURLcode = Curl_retry_request(
                                    data,
                                    &mut newurl_0,
                                );
                                if ret_0 as u64 == 0 {
                                    Curl_infof(
                                        data,
                                        b"Downgrades to HTTP/1.1!\0" as *const u8
                                            as *const i8,
                                    );
                                    Curl_conncontrol((*data).conn, 2 as i32);
                                    (*data)
                                        .state
                                        .httpwant = CURL_HTTP_VERSION_1_1 as i32
                                        as u8;
                                    let fresh46 = &mut ((*data).state);
                                    (*fresh46).set_errorbuf(0 as i32 as bit);
                                    if newurl_0.is_null() {
                                        newurl_0 = Curl_cstrdup
                                            .expect("non-null function pointer")((*data).state.url);
                                    }
                                    retry = 1 as i32 != 0;
                                    result = CURLE_OK;
                                    done = 1 as i32 != 0;
                                } else {
                                    result = ret_0;
                                }
                            }
                            if result as u64 != 0 {
                                if (*(*(*data).conn).handler).flags
                                    & ((1 as i32) << 1 as i32) as u32
                                    == 0
                                    && result as u32
                                        != CURLE_HTTP2_STREAM as i32 as u32
                                {
                                    Curl_conncontrol((*data).conn, 2 as i32);
                                }
                                Curl_posttransfer(data);
                                multi_done(data, result, 1 as i32 != 0);
                            } else if done {
                                Curl_posttransfer(data);
                                if !((*data).req.newurl).is_null()
                                    || retry as i32 != 0
                                {
                                    let mut follow_0: followtype = FOLLOW_NONE;
                                    if !retry {
                                        Curl_cfree
                                            .expect(
                                                "non-null function pointer",
                                            )(newurl_0 as *mut libc::c_void);
                                        newurl_0 = (*data).req.newurl;
                                        let fresh47 = &mut ((*data).req.newurl);
                                        *fresh47 = 0 as *mut i8;
                                        follow_0 = FOLLOW_REDIR;
                                    } else {
                                        follow_0 = FOLLOW_RETRY;
                                    }
                                    multi_done(data, CURLE_OK, 0 as i32 != 0);
                                    result = Curl_follow(data, newurl_0, follow_0);
                                    if result as u64 == 0 {
                                        mstate(data, MSTATE_CONNECT);
                                        rc = CURLM_CALL_MULTI_PERFORM;
                                    }
                                    Curl_cfree
                                        .expect(
                                            "non-null function pointer",
                                        )(newurl_0 as *mut libc::c_void);
                                } else {
                                    if !((*data).req.location).is_null() {
                                        Curl_cfree
                                            .expect(
                                                "non-null function pointer",
                                            )(newurl_0 as *mut libc::c_void);
                                        newurl_0 = (*data).req.location;
                                        let fresh48 = &mut ((*data).req.location);
                                        *fresh48 = 0 as *mut i8;
                                        result = Curl_follow(data, newurl_0, FOLLOW_FAKE);
                                        Curl_cfree
                                            .expect(
                                                "non-null function pointer",
                                            )(newurl_0 as *mut libc::c_void);
                                        if result as u64 != 0 {
                                            stream_error = 1 as i32 != 0;
                                            result = multi_done(data, result, 1 as i32 != 0);
                                        }
                                    }
                                    if result as u64 == 0 {
                                        mstate(data, MSTATE_DONE);
                                        rc = CURLM_CALL_MULTI_PERFORM;
                                    }
                                }
                            } else if comeback {
                                Curl_expire(
                                    data,
                                    0 as i32 as timediff_t,
                                    EXPIRE_RUN_NOW,
                                );
                                rc = CURLM_OK;
                            }
                        }
                    }
                    14 => {
                        rc = CURLM_CALL_MULTI_PERFORM;
                        if !((*data).conn).is_null() {
                            let mut res: CURLcode = CURLE_OK;
                            if ((*(*data).conn).bits).multiplex() != 0 {
                                process_pending_handles(multi);
                            }
                            res = multi_done(data, result, 0 as i32 != 0);
                            if result as u64 == 0 {
                                result = res;
                            }
                        }
                        if ((*data).state).wildcardmatch() != 0 {
                            if (*data).wildcard.state as u32
                                != CURLWC_DONE as i32 as u32
                            {
                                mstate(data, MSTATE_INIT);
                                current_block_332 = 14851975181745310361;
                            } else {
                                current_block_332 = 5537925605363743233;
                            }
                        } else {
                            current_block_332 = 5537925605363743233;
                        }
                        match current_block_332 {
                            14851975181745310361 => {}
                            _ => {
                                mstate(data, MSTATE_COMPLETED);
                            }
                        }
                    }
                    1 | 15 => {}
                    16 => {
                        (*data).result = result;
                        return CURLM_OK;
                    }
                    _ => return CURLM_INTERNAL_ERROR,
                }
                if !((*data).conn).is_null()
                    && (*data).mstate as u32
                        >= MSTATE_CONNECT as i32 as u32
                    && ((*data).mstate as u32)
                        < MSTATE_DO as i32 as u32
                    && rc as i32 != CURLM_CALL_MULTI_PERFORM as i32
                    && !multi_ischanged(multi, 0 as i32 != 0)
                {
                    multi_handle_timeout(
                        data,
                        nowp,
                        &mut stream_error,
                        &mut result,
                        1 as i32 != 0,
                    );
                }
            }
            _ => {}
        }
        if ((*data).mstate as u32)
            < MSTATE_COMPLETED as i32 as u32
        {
            if result as u64 != 0 {
                process_pending_handles(multi);
                if !((*data).conn).is_null() {
                    if stream_error {
                        let mut dead_connection: bool = result as u32
                            == CURLE_OPERATION_TIMEDOUT as i32 as u32;
                        let mut conn_0: *mut connectdata = (*data).conn;
                        Curl_detach_connnection(data);
                        Curl_conncache_remove_conn(data, conn_0, 1 as i32 != 0);
                        Curl_disconnect(data, conn_0, dead_connection);
                    }
                } else if (*data).mstate as u32
                        == MSTATE_CONNECT as i32 as u32
                    {
                    Curl_posttransfer(data);
                }
                mstate(data, MSTATE_COMPLETED);
                rc = CURLM_CALL_MULTI_PERFORM;
            } else if !((*data).conn).is_null() && Curl_pgrsUpdate(data) != 0 {
                result = CURLE_ABORTED_BY_CALLBACK;
                Curl_conncontrol((*data).conn, 2 as i32);
                mstate(
                    data,
                    (if ((*data).mstate as u32)
                        < MSTATE_DONE as i32 as u32
                    {
                        MSTATE_DONE as i32
                    } else {
                        MSTATE_COMPLETED as i32
                    }) as CURLMstate,
                );
                rc = CURLM_CALL_MULTI_PERFORM;
            }
        }
        if MSTATE_COMPLETED as i32 as u32
            == (*data).mstate as u32
        {
            if ((*data).set.fmultidone).is_some() {
                ((*data).set.fmultidone)
                    .expect("non-null function pointer")(data, result);
            } else {
                msg = &mut (*data).msg;
                (*msg).extmsg.msg = CURLMSG_DONE;
                let fresh49 = &mut ((*msg).extmsg.easy_handle);
                *fresh49 = data;
                (*msg).extmsg.data.result = result;
                rc = multi_addmsg(multi, msg);
            }
            mstate(data, MSTATE_MSGSENT);
        }
        if !(rc as i32 == CURLM_CALL_MULTI_PERFORM as i32
            || multi_ischanged(multi, 0 as i32 != 0) as i32 != 0)
        {
            break;
        }
    }
    (*data).result = result;
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn curl_multi_perform(
    mut multi: *mut Curl_multi,
    mut running_handles: *mut i32,
) -> CURLMcode {
    let mut data: *mut Curl_easy = 0 as *mut Curl_easy;
    let mut returncode: CURLMcode = CURLM_OK;
    let mut t: *mut Curl_tree = 0 as *mut Curl_tree;
    let mut now: curltime = Curl_now();
    if !(!multi.is_null() && (*multi).magic == 0xbab1e as i32 as u32) {
        return CURLM_BAD_HANDLE;
    }
    if (*multi).in_callback {
        return CURLM_RECURSIVE_API_CALL;
    }
    data = (*multi).easyp;
    while !data.is_null() {
        let mut result: CURLMcode = CURLM_OK;
        let mut pipe_st: sigpipe_ignore = sigpipe_ignore {
            old_pipe_act: sigaction {
                __sigaction_handler: C2RustUnnamed_9 {
                    sa_handler: None,
                },
                sa_mask: __sigset_t { __val: [0; 16] },
                sa_flags: 0,
                sa_restorer: None,
            },
            no_signal: false,
        };
        sigpipe_ignore(data, &mut pipe_st);
        result = multi_runsingle(multi, &mut now, data);
        sigpipe_restore(&mut pipe_st);
        if result as u64 != 0 {
            returncode = result;
        }
        data = (*data).next;
    }
    loop {
        let fresh50 = &mut ((*multi).timetree);
        *fresh50 = Curl_splaygetbest(now, (*multi).timetree, &mut t);
        if !t.is_null() {
            add_next_timeout(now, multi, (*t).payload as *mut Curl_easy);
        }
        if t.is_null() {
            break;
        }
    }
    *running_handles = (*multi).num_alive;
    if CURLM_OK as i32 >= returncode as i32 {
        Curl_update_timer(multi);
    }
    return returncode;
}
#[no_mangle]
pub unsafe extern "C" fn curl_multi_cleanup(mut multi: *mut Curl_multi) -> CURLMcode {
    let mut data: *mut Curl_easy = 0 as *mut Curl_easy;
    let mut nextdata: *mut Curl_easy = 0 as *mut Curl_easy;
    if !multi.is_null() && (*multi).magic == 0xbab1e as i32 as u32 {
        if (*multi).in_callback {
            return CURLM_RECURSIVE_API_CALL;
        }
        (*multi).magic = 0 as i32 as u32;
        data = (*multi).easyp;
        while !data.is_null() {
            nextdata = (*data).next;
            if ((*data).state).done() == 0 && !((*data).conn).is_null() {
                multi_done(data, CURLE_OK, 1 as i32 != 0);
            }
            if (*data).dns.hostcachetype as u32
                == HCACHE_MULTI as i32 as u32
            {
                Curl_hostcache_clean(data, (*data).dns.hostcache);
                let fresh51 = &mut ((*data).dns.hostcache);
                *fresh51 = 0 as *mut Curl_hash;
                (*data).dns.hostcachetype = HCACHE_NONE;
            }
            let fresh52 = &mut ((*data).state.conn_cache);
            *fresh52 = 0 as *mut conncache;
            let fresh53 = &mut ((*data).multi);
            *fresh53 = 0 as *mut Curl_multi;
            if (*data).psl == &mut (*multi).psl as *mut PslCache {
                let fresh54 = &mut ((*data).psl);
                *fresh54 = 0 as *mut PslCache;
            }
            data = nextdata;
        }
        Curl_conncache_close_all_connections(&mut (*multi).conn_cache);
        Curl_hash_destroy(&mut (*multi).sockhash);
        Curl_conncache_destroy(&mut (*multi).conn_cache);
        Curl_llist_destroy(&mut (*multi).msglist, 0 as *mut libc::c_void);
        Curl_llist_destroy(&mut (*multi).pending, 0 as *mut libc::c_void);
        Curl_hash_destroy(&mut (*multi).hostcache);
        Curl_psl_destroy(&mut (*multi).psl);
        close((*multi).wakeup_pair[0 as i32 as usize]);
        close((*multi).wakeup_pair[1 as i32 as usize]);
        Curl_cfree.expect("non-null function pointer")(multi as *mut libc::c_void);
        return CURLM_OK;
    }
    return CURLM_BAD_HANDLE;
}
#[no_mangle]
pub unsafe extern "C" fn curl_multi_info_read(
    mut multi: *mut Curl_multi,
    mut msgs_in_queue: *mut i32,
) -> *mut CURLMsg {
    let mut msg: *mut Curl_message = 0 as *mut Curl_message;
    *msgs_in_queue = 0 as i32;
    if !multi.is_null() && (*multi).magic == 0xbab1e as i32 as u32
        && !(*multi).in_callback && Curl_llist_count(&mut (*multi).msglist) != 0
    {
        let mut e: *mut Curl_llist_element = 0 as *mut Curl_llist_element;
        e = (*multi).msglist.head;
        msg = (*e).ptr as *mut Curl_message;
        Curl_llist_remove(&mut (*multi).msglist, e, 0 as *mut libc::c_void);
        *msgs_in_queue = curlx_uztosi(Curl_llist_count(&mut (*multi).msglist));
        return &mut (*msg).extmsg;
    }
    return 0 as *mut CURLMsg;
}
unsafe extern "C" fn singlesocket(
    mut multi: *mut Curl_multi,
    mut data: *mut Curl_easy,
) -> CURLMcode {
    let mut socks: [curl_socket_t; 5] = [0; 5];
    let mut i: i32 = 0;
    let mut entry: *mut Curl_sh_entry = 0 as *mut Curl_sh_entry;
    let mut s: curl_socket_t = 0;
    let mut num: i32 = 0;
    let mut curraction: u32 = 0;
    let mut actions: [u8; 5] = [0; 5];
    i = 0 as i32;
    while i < 5 as i32 {
        socks[i as usize] = -(1 as i32);
        i += 1;
    }
    curraction = multi_getsock(data, socks.as_mut_ptr()) as u32;
    i = 0 as i32;
    while i < 5 as i32
        && curraction
            & ((1 as i32) << i | (1 as i32) << 16 as i32 + i)
                as u32 != 0
    {
        let mut action: u8 = 0 as i32 as u8;
        let mut prevaction: u8 = 0 as i32 as u8;
        let mut comboaction: i32 = 0;
        let mut sincebefore: bool = 0 as i32 != 0;
        s = socks[i as usize];
        entry = sh_getentry(&mut (*multi).sockhash, s);
        if curraction & ((1 as i32) << i) as u32 != 0 {
            action = (action as i32 | 1 as i32) as u8;
        }
        if curraction & ((1 as i32) << 16 as i32 + i) as u32
            != 0
        {
            action = (action as i32 | 2 as i32) as u8;
        }
        actions[i as usize] = action;
        if !entry.is_null() {
            let mut j: i32 = 0;
            j = 0 as i32;
            while j < (*data).numsocks {
                if s == (*data).sockets[j as usize] {
                    prevaction = (*data).actions[j as usize];
                    sincebefore = 1 as i32 != 0;
                    break;
                } else {
                    j += 1;
                }
            }
        } else {
            entry = sh_addentry(&mut (*multi).sockhash, s);
            if entry.is_null() {
                return CURLM_OUT_OF_MEMORY;
            }
        }
        if sincebefore as i32 != 0
            && prevaction as i32 != action as i32
        {
            if prevaction as i32 & 1 as i32 != 0 {
                let fresh55 = &mut ((*entry).readers);
                *fresh55 = (*fresh55).wrapping_sub(1);
            }
            if prevaction as i32 & 2 as i32 != 0 {
                let fresh56 = &mut ((*entry).writers);
                *fresh56 = (*fresh56).wrapping_sub(1);
            }
            if action as i32 & 1 as i32 != 0 {
                let fresh57 = &mut ((*entry).readers);
                *fresh57 = (*fresh57).wrapping_add(1);
            }
            if action as i32 & 2 as i32 != 0 {
                let fresh58 = &mut ((*entry).writers);
                *fresh58 = (*fresh58).wrapping_add(1);
            }
        } else if !sincebefore {
            let fresh59 = &mut ((*entry).users);
            *fresh59 = (*fresh59).wrapping_add(1);
            if action as i32 & 1 as i32 != 0 {
                let fresh60 = &mut ((*entry).readers);
                *fresh60 = (*fresh60).wrapping_add(1);
            }
            if action as i32 & 2 as i32 != 0 {
                let fresh61 = &mut ((*entry).writers);
                *fresh61 = (*fresh61).wrapping_add(1);
            }
            if (Curl_hash_add(
                &mut (*entry).transfers,
                &mut data as *mut *mut Curl_easy as *mut i8
                    as *mut libc::c_void,
                ::std::mem::size_of::<*mut Curl_easy>() as u64,
                data as *mut libc::c_void,
            ))
                .is_null()
            {
                return CURLM_OUT_OF_MEMORY;
            }
        }
        comboaction = (if (*entry).writers != 0 {
            2 as i32
        } else {
            0 as i32
        }) | (if (*entry).readers != 0 { 1 as i32 } else { 0 as i32 });
        if !(sincebefore as i32 != 0
            && (*entry).action as i32 == comboaction)
        {
            if ((*multi).socket_cb).is_some() {
                ((*multi).socket_cb)
                    .expect(
                        "non-null function pointer",
                    )(data, s, comboaction, (*multi).socket_userp, (*entry).socketp);
            }
            (*entry).action = comboaction as u32;
        }
        i += 1;
    }
    num = i;
    i = 0 as i32;
    while i < (*data).numsocks {
        let mut j_0: i32 = 0;
        let mut stillused: bool = 0 as i32 != 0;
        s = (*data).sockets[i as usize];
        j_0 = 0 as i32;
        while j_0 < num {
            if s == socks[j_0 as usize] {
                stillused = 1 as i32 != 0;
                break;
            } else {
                j_0 += 1;
            }
        }
        if !stillused {
            entry = sh_getentry(&mut (*multi).sockhash, s);
            if !entry.is_null() {
                let mut oldactions: u8 = (*data).actions[i as usize];
                let fresh62 = &mut ((*entry).users);
                *fresh62 = (*fresh62).wrapping_sub(1);
                if oldactions as i32 & 2 as i32 != 0 {
                    let fresh63 = &mut ((*entry).writers);
                    *fresh63 = (*fresh63).wrapping_sub(1);
                }
                if oldactions as i32 & 1 as i32 != 0 {
                    let fresh64 = &mut ((*entry).readers);
                    *fresh64 = (*fresh64).wrapping_sub(1);
                }
                if (*entry).users == 0 {
                    if ((*multi).socket_cb).is_some() {
                        ((*multi).socket_cb)
                            .expect(
                                "non-null function pointer",
                            )(
                            data,
                            s,
                            4 as i32,
                            (*multi).socket_userp,
                            (*entry).socketp,
                        );
                    }
                    sh_delentry(entry, &mut (*multi).sockhash, s);
                } else {
                    Curl_hash_delete(
                        &mut (*entry).transfers,
                        &mut data as *mut *mut Curl_easy as *mut i8
                            as *mut libc::c_void,
                        ::std::mem::size_of::<*mut Curl_easy>() as u64,
                    ) != 0;
                }
            }
        }
        i += 1;
    }
    memcpy(
        ((*data).sockets).as_mut_ptr() as *mut libc::c_void,
        socks.as_mut_ptr() as *const libc::c_void,
        (num as u64)
            .wrapping_mul(::std::mem::size_of::<curl_socket_t>() as u64),
    );
    memcpy(
        ((*data).actions).as_mut_ptr() as *mut libc::c_void,
        actions.as_mut_ptr() as *const libc::c_void,
        (num as u64)
            .wrapping_mul(::std::mem::size_of::<i8>() as u64),
    );
    (*data).numsocks = num;
    return CURLM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_updatesocket(mut data: *mut Curl_easy) {
    singlesocket((*data).multi, data);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_multi_closed(
    mut data: *mut Curl_easy,
    mut s: curl_socket_t,
) {
    if !data.is_null() {
        let mut multi: *mut Curl_multi = (*data).multi;
        if !multi.is_null() {
            let mut entry: *mut Curl_sh_entry = sh_getentry(&mut (*multi).sockhash, s);
            if !entry.is_null() {
                if ((*multi).socket_cb).is_some() {
                    ((*multi).socket_cb)
                        .expect(
                            "non-null function pointer",
                        )(
                        data,
                        s,
                        4 as i32,
                        (*multi).socket_userp,
                        (*entry).socketp,
                    );
                }
                sh_delentry(entry, &mut (*multi).sockhash, s);
            }
        }
    }
}
unsafe extern "C" fn add_next_timeout(
    mut now: curltime,
    mut multi: *mut Curl_multi,
    mut d: *mut Curl_easy,
) -> CURLMcode {
    let mut tv: *mut curltime = &mut (*d).state.expiretime;
    let mut list: *mut Curl_llist = &mut (*d).state.timeoutlist;
    let mut e: *mut Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut node: *mut time_node = 0 as *mut time_node;
    e = (*list).head;
    while !e.is_null() {
        let mut n: *mut Curl_llist_element = (*e).next;
        let mut diff: timediff_t = 0;
        node = (*e).ptr as *mut time_node;
        diff = Curl_timediff((*node).time, now);
        if !(diff <= 0 as i32 as i64) {
            break;
        }
        Curl_llist_remove(list, e, 0 as *mut libc::c_void);
        e = n;
    }
    e = (*list).head;
    if e.is_null() {
        (*tv).tv_sec = 0 as i32 as time_t;
        (*tv).tv_usec = 0 as i32;
    } else {
        memcpy(
            tv as *mut libc::c_void,
            &mut (*node).time as *mut curltime as *const libc::c_void,
            ::std::mem::size_of::<curltime>() as u64,
        );
        let fresh65 = &mut ((*multi).timetree);
        *fresh65 = Curl_splayinsert(*tv, (*multi).timetree, &mut (*d).state.timenode);
    }
    return CURLM_OK;
}
unsafe extern "C" fn multi_socket(
    mut multi: *mut Curl_multi,
    mut checkall: bool,
    mut s: curl_socket_t,
    mut ev_bitmask: i32,
    mut running_handles: *mut i32,
) -> CURLMcode {
    let mut result: CURLMcode = CURLM_OK;
    let mut data: *mut Curl_easy = 0 as *mut Curl_easy;
    let mut t: *mut Curl_tree = 0 as *mut Curl_tree;
    let mut now: curltime = Curl_now();
    if checkall {
        result = curl_multi_perform(multi, running_handles);
        if result as i32 != CURLM_BAD_HANDLE as i32 {
            data = (*multi).easyp;
            while !data.is_null() && result as u64 == 0 {
                result = singlesocket(multi, data);
                data = (*data).next;
            }
        }
        return result;
    }
    if s != -(1 as i32) {
        let mut entry: *mut Curl_sh_entry = sh_getentry(&mut (*multi).sockhash, s);
        if !entry.is_null() {
            let mut iter: Curl_hash_iterator = Curl_hash_iterator {
                hash: 0 as *mut Curl_hash,
                slot_index: 0,
                current_element: 0 as *mut Curl_llist_element,
            };
            let mut he: *mut Curl_hash_element = 0 as *mut Curl_hash_element;
            Curl_hash_start_iterate(&mut (*entry).transfers, &mut iter);
            he = Curl_hash_next_element(&mut iter);
            while !he.is_null() {
                data = (*he).ptr as *mut Curl_easy;
                if !((*data).conn).is_null()
                    && (*(*(*data).conn).handler).flags
                        & ((1 as i32) << 3 as i32) as u32 == 0
                {
                    (*(*data).conn).cselect_bits = ev_bitmask;
                }
                Curl_expire(data, 0 as i32 as timediff_t, EXPIRE_RUN_NOW);
                he = Curl_hash_next_element(&mut iter);
            }
            data = 0 as *mut Curl_easy;
            now = Curl_now();
        }
    } else {
        memset(
            &mut (*multi).timer_lastcall as *mut curltime as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<curltime>() as u64,
        );
    }
    loop {
        if !data.is_null() {
            let mut pipe_st: sigpipe_ignore = sigpipe_ignore {
                old_pipe_act: sigaction {
                    __sigaction_handler: C2RustUnnamed_9 {
                        sa_handler: None,
                    },
                    sa_mask: __sigset_t { __val: [0; 16] },
                    sa_flags: 0,
                    sa_restorer: None,
                },
                no_signal: false,
            };
            sigpipe_ignore(data, &mut pipe_st);
            result = multi_runsingle(multi, &mut now, data);
            sigpipe_restore(&mut pipe_st);
            if CURLM_OK as i32 >= result as i32 {
                result = singlesocket(multi, data);
                if result as u64 != 0 {
                    return result;
                }
            }
        }
        let fresh66 = &mut ((*multi).timetree);
        *fresh66 = Curl_splaygetbest(now, (*multi).timetree, &mut t);
        if !t.is_null() {
            data = (*t).payload as *mut Curl_easy;
            add_next_timeout(now, multi, (*t).payload as *mut Curl_easy);
        }
        if t.is_null() {
            break;
        }
    }
    *running_handles = (*multi).num_alive;
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn curl_multi_setopt(
    mut multi: *mut Curl_multi,
    mut option: CURLMoption,
    mut args: ...
) -> CURLMcode {
    let mut res: CURLMcode = CURLM_OK;
    let mut param: ::std::ffi::VaListImpl;
    if !(!multi.is_null() && (*multi).magic == 0xbab1e as i32 as u32) {
        return CURLM_BAD_HANDLE;
    }
    if (*multi).in_callback {
        return CURLM_RECURSIVE_API_CALL;
    }
    param = args.clone();
    match option as u32 {
        20001 => {
            let fresh67 = &mut ((*multi).socket_cb);
            *fresh67 = ::std::mem::transmute(
                param
                    .arg::<
                    *mut unsafe extern "C" fn(
                        *mut CURL,
                        curl_socket_t,
                        i32,
                        *mut libc::c_void,
                        *mut libc::c_void,
                    ) -> i32,
                >(),
            );
        }
        10002 => {
            let fresh68 = &mut ((*multi).socket_userp);
            *fresh68 = param.arg::<*mut libc::c_void>();
        }
        20014 => {
            let fresh69 = &mut ((*multi).push_cb);
            *fresh69 = ::std::mem::transmute(
                param
                    .arg::<
                    *mut unsafe extern "C" fn(
                        *mut CURL,
                        *mut CURL,
                        size_t,
                        *mut curl_pushheaders,
                        *mut libc::c_void,
                    ) -> i32,
                >(),
            );
        }
        10015 => {
            let fresh70 = &mut ((*multi).push_userp);
            *fresh70 = param.arg::<*mut libc::c_void>();
        }
        3 => {
            (*multi).multiplexing = param.arg::<i64>() & 2 as i64 != 0;
        }
        20004 => {
            let fresh71 = &mut ((*multi).timer_cb);
            *fresh71 = ::std::mem::transmute(
                param
                    .arg::<
                    *mut unsafe extern "C" fn(
                        *mut CURLM,
                        i64,
                        *mut libc::c_void,
                    ) -> i32,
                >(),
            );
        }
        10005 => {
            let fresh72 = &mut ((*multi).timer_userp);
            *fresh72 = param.arg::<*mut libc::c_void>();
        }
        6 => {
            (*multi).maxconnects = param.arg::<i64>();
        }
        7 => {
            (*multi).max_host_connections = param.arg::<i64>();
        }
        13 => {
            (*multi).max_total_connections = param.arg::<i64>();
        }
        8 | 30009 | 30010 | 10011 | 10012 => {}
        16 => {
            let mut streams: i64 = param.arg::<i64>();
            if streams < 1 as i32 as i64 {
                streams = 100 as i32 as i64;
            }
            (*multi).max_concurrent_streams = curlx_sltoui(streams);
        }
        _ => {
            res = CURLM_UNKNOWN_OPTION;
        }
    }
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn curl_multi_socket(
    mut multi: *mut Curl_multi,
    mut s: curl_socket_t,
    mut running_handles: *mut i32,
) -> CURLMcode {
    let mut result: CURLMcode = CURLM_OK;
    if (*multi).in_callback {
        return CURLM_RECURSIVE_API_CALL;
    }
    result = multi_socket(
        multi,
        0 as i32 != 0,
        s,
        0 as i32,
        running_handles,
    );
    if CURLM_OK as i32 >= result as i32 {
        Curl_update_timer(multi);
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn curl_multi_socket_action(
    mut multi: *mut Curl_multi,
    mut s: curl_socket_t,
    mut ev_bitmask: i32,
    mut running_handles: *mut i32,
) -> CURLMcode {
    let mut result: CURLMcode = CURLM_OK;
    if (*multi).in_callback {
        return CURLM_RECURSIVE_API_CALL;
    }
    result = multi_socket(multi, 0 as i32 != 0, s, ev_bitmask, running_handles);
    if CURLM_OK as i32 >= result as i32 {
        Curl_update_timer(multi);
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn curl_multi_socket_all(
    mut multi: *mut Curl_multi,
    mut running_handles: *mut i32,
) -> CURLMcode {
    let mut result: CURLMcode = CURLM_OK;
    if (*multi).in_callback {
        return CURLM_RECURSIVE_API_CALL;
    }
    result = multi_socket(
        multi,
        1 as i32 != 0,
        -(1 as i32),
        0 as i32,
        running_handles,
    );
    if CURLM_OK as i32 >= result as i32 {
        Curl_update_timer(multi);
    }
    return result;
}
unsafe extern "C" fn multi_timeout(
    mut multi: *mut Curl_multi,
    mut timeout_ms: *mut i64,
) -> CURLMcode {
    static mut tv_zero: curltime = {
        let mut init = curltime {
            tv_sec: 0 as i32 as time_t,
            tv_usec: 0 as i32,
        };
        init
    };
    if !((*multi).timetree).is_null() {
        let mut now: curltime = Curl_now();
        let fresh73 = &mut ((*multi).timetree);
        *fresh73 = Curl_splay(tv_zero, (*multi).timetree);
        if (if (*(*multi).timetree).key.tv_sec < now.tv_sec {
            -(1 as i32)
        } else {
            (if (*(*multi).timetree).key.tv_sec > now.tv_sec {
                1 as i32
            } else {
                (if (*(*multi).timetree).key.tv_usec < now.tv_usec {
                    -(1 as i32)
                } else {
                    (if (*(*multi).timetree).key.tv_usec > now.tv_usec {
                        1 as i32
                    } else {
                        0 as i32
                    })
                })
            })
        }) > 0 as i32
        {
            let mut diff: timediff_t = Curl_timediff((*(*multi).timetree).key, now);
            if diff <= 0 as i32 as i64 {
                *timeout_ms = 1 as i32 as i64;
            } else {
                *timeout_ms = diff;
            }
        } else {
            *timeout_ms = 0 as i32 as i64;
        }
    } else {
        *timeout_ms = -(1 as i32) as i64;
    }
    return CURLM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn curl_multi_timeout(
    mut multi: *mut Curl_multi,
    mut timeout_ms: *mut i64,
) -> CURLMcode {
    if !(!multi.is_null() && (*multi).magic == 0xbab1e as i32 as u32) {
        return CURLM_BAD_HANDLE;
    }
    if (*multi).in_callback {
        return CURLM_RECURSIVE_API_CALL;
    }
    return multi_timeout(multi, timeout_ms);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_update_timer(mut multi: *mut Curl_multi) {
    let mut timeout_ms: i64 = 0;
    if ((*multi).timer_cb).is_none() {
        return;
    }
    if multi_timeout(multi, &mut timeout_ms) as u64 != 0 {
        return;
    }
    if timeout_ms < 0 as i32 as i64 {
        static mut none: curltime = {
            let mut init = curltime {
                tv_sec: 0 as i32 as time_t,
                tv_usec: 0 as i32,
            };
            init
        };
        if if none.tv_sec < (*multi).timer_lastcall.tv_sec {
            -(1 as i32)
        } else if none.tv_sec > (*multi).timer_lastcall.tv_sec {
            1 as i32
        } else if none.tv_usec < (*multi).timer_lastcall.tv_usec {
            -(1 as i32)
        } else if none.tv_usec > (*multi).timer_lastcall.tv_usec {
            1 as i32
        } else {
            0 as i32
        } != 0
        {
            (*multi).timer_lastcall = none;
            ((*multi).timer_cb)
                .expect(
                    "non-null function pointer",
                )(multi, -(1 as i32) as i64, (*multi).timer_userp);
            return;
        }
        return;
    }
    if (if (*(*multi).timetree).key.tv_sec < (*multi).timer_lastcall.tv_sec {
        -(1 as i32)
    } else {
        (if (*(*multi).timetree).key.tv_sec > (*multi).timer_lastcall.tv_sec {
            1 as i32
        } else {
            (if (*(*multi).timetree).key.tv_usec < (*multi).timer_lastcall.tv_usec {
                -(1 as i32)
            } else {
                (if (*(*multi).timetree).key.tv_usec > (*multi).timer_lastcall.tv_usec {
                    1 as i32
                } else {
                    0 as i32
                })
            })
        })
    }) == 0 as i32
    {
        return;
    }
    (*multi).timer_lastcall = (*(*multi).timetree).key;
    ((*multi).timer_cb)
        .expect("non-null function pointer")(multi, timeout_ms, (*multi).timer_userp);
}
unsafe extern "C" fn multi_deltimeout(mut data: *mut Curl_easy, mut eid: expire_id) {
    let mut e: *mut Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut timeoutlist: *mut Curl_llist = &mut (*data).state.timeoutlist;
    e = (*timeoutlist).head;
    while !e.is_null() {
        let mut n: *mut time_node = (*e).ptr as *mut time_node;
        if (*n).eid as u32 == eid as u32 {
            Curl_llist_remove(timeoutlist, e, 0 as *mut libc::c_void);
            return;
        }
        e = (*e).next;
    }
}
unsafe extern "C" fn multi_addtimeout(
    mut data: *mut Curl_easy,
    mut stamp: *mut curltime,
    mut eid: expire_id,
) -> CURLMcode {
    let mut e: *mut Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut node: *mut time_node = 0 as *mut time_node;
    let mut prev: *mut Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut n: size_t = 0;
    let mut timeoutlist: *mut Curl_llist = &mut (*data).state.timeoutlist;
    node = &mut *((*data).state.expires).as_mut_ptr().offset(eid as isize)
        as *mut time_node;
    memcpy(
        &mut (*node).time as *mut curltime as *mut libc::c_void,
        stamp as *const libc::c_void,
        ::std::mem::size_of::<curltime>() as u64,
    );
    (*node).eid = eid;
    n = Curl_llist_count(timeoutlist);
    if n != 0 {
        e = (*timeoutlist).head;
        while !e.is_null() {
            let mut check: *mut time_node = (*e).ptr as *mut time_node;
            let mut diff: timediff_t = Curl_timediff((*check).time, (*node).time);
            if diff > 0 as i32 as i64 {
                break;
            }
            prev = e;
            e = (*e).next;
        }
    }
    Curl_llist_insert_next(
        timeoutlist,
        prev,
        node as *const libc::c_void,
        &mut (*node).list,
    );
    return CURLM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_expire(
    mut data: *mut Curl_easy,
    mut milli: timediff_t,
    mut id: expire_id,
) {
    let mut multi: *mut Curl_multi = (*data).multi;
    let mut nowp: *mut curltime = &mut (*data).state.expiretime;
    let mut set: curltime = curltime { tv_sec: 0, tv_usec: 0 };
    if multi.is_null() {
        return;
    }
    set = Curl_now();
    set.tv_sec += milli / 1000 as i32 as i64;
    set
        .tv_usec = (set.tv_usec as u32)
        .wrapping_add(
            ((milli % 1000 as i32 as i64) as u32)
                .wrapping_mul(1000 as i32 as u32),
        ) as i32 as i32;
    if set.tv_usec >= 1000000 as i32 {
        set.tv_sec += 1;
        set.tv_usec -= 1000000 as i32;
    }
    multi_deltimeout(data, id);
    multi_addtimeout(data, &mut set, id);
    if (*nowp).tv_sec != 0 || (*nowp).tv_usec != 0 {
        let mut diff: timediff_t = Curl_timediff(set, *nowp);
        let mut rc: i32 = 0;
        if diff > 0 as i32 as i64 {
            return;
        }
        rc = Curl_splayremove(
            (*multi).timetree,
            &mut (*data).state.timenode,
            &mut (*multi).timetree,
        );
        if rc != 0 {
            Curl_infof(
                data,
                b"Internal error removing splay node = %d\0" as *const u8
                    as *const i8,
                rc,
            );
        }
    }
    *nowp = set;
    let fresh74 = &mut ((*data).state.timenode.payload);
    *fresh74 = data as *mut libc::c_void;
    let fresh75 = &mut ((*multi).timetree);
    *fresh75 = Curl_splayinsert(*nowp, (*multi).timetree, &mut (*data).state.timenode);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_expire_done(mut data: *mut Curl_easy, mut id: expire_id) {
    multi_deltimeout(data, id);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_expire_clear(mut data: *mut Curl_easy) {
    let mut multi: *mut Curl_multi = (*data).multi;
    let mut nowp: *mut curltime = &mut (*data).state.expiretime;
    if multi.is_null() {
        return;
    }
    if (*nowp).tv_sec != 0 || (*nowp).tv_usec != 0 {
        let mut list: *mut Curl_llist = &mut (*data).state.timeoutlist;
        let mut rc: i32 = 0;
        rc = Curl_splayremove(
            (*multi).timetree,
            &mut (*data).state.timenode,
            &mut (*multi).timetree,
        );
        if rc != 0 {
            Curl_infof(
                data,
                b"Internal error clearing splay node = %d\0" as *const u8
                    as *const i8,
                rc,
            );
        }
        while (*list).size > 0 as i32 as u64 {
            Curl_llist_remove(list, (*list).tail, 0 as *mut libc::c_void);
        }
        (*nowp).tv_sec = 0 as i32 as time_t;
        (*nowp).tv_usec = 0 as i32;
    }
}
#[no_mangle]
pub unsafe extern "C" fn curl_multi_assign(
    mut multi: *mut Curl_multi,
    mut s: curl_socket_t,
    mut hashp: *mut libc::c_void,
) -> CURLMcode {
    let mut there: *mut Curl_sh_entry = 0 as *mut Curl_sh_entry;
    if (*multi).in_callback {
        return CURLM_RECURSIVE_API_CALL;
    }
    there = sh_getentry(&mut (*multi).sockhash, s);
    if there.is_null() {
        return CURLM_BAD_SOCKET;
    }
    let fresh76 = &mut ((*there).socketp);
    *fresh76 = hashp;
    return CURLM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_multi_max_host_connections(
    mut multi: *mut Curl_multi,
) -> size_t {
    return (if !multi.is_null() {
        (*multi).max_host_connections
    } else {
        0 as i32 as i64
    }) as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_multi_max_total_connections(
    mut multi: *mut Curl_multi,
) -> size_t {
    return (if !multi.is_null() {
        (*multi).max_total_connections
    } else {
        0 as i32 as i64
    }) as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_multiuse_state(
    mut data: *mut Curl_easy,
    mut bundlestate: i32,
) {
    let mut conn: *mut connectdata = 0 as *mut connectdata;
    conn = (*data).conn;
    (*(*conn).bundle).multiuse = bundlestate;
    process_pending_handles((*data).multi);
}
unsafe extern "C" fn process_pending_handles(mut multi: *mut Curl_multi) {
    let mut e: *mut Curl_llist_element = (*multi).pending.head;
    if !e.is_null() {
        let mut data: *mut Curl_easy = (*e).ptr as *mut Curl_easy;
        mstate(data, MSTATE_CONNECT);
        Curl_llist_remove(&mut (*multi).pending, e, 0 as *mut libc::c_void);
        Curl_expire(data, 0 as i32 as timediff_t, EXPIRE_RUN_NOW);
        let fresh77 = &mut ((*data).state);
        (*fresh77).set_previouslypending(1 as i32 as bit);
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_set_in_callback(
    mut data: *mut Curl_easy,
    mut value: bool,
) {
    if !data.is_null() {
        if !((*data).multi_easy).is_null() {
            (*(*data).multi_easy).in_callback = value;
        } else if !((*data).multi).is_null() {
            (*(*data).multi).in_callback = value;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_is_in_callback(mut easy: *mut Curl_easy) -> bool {
    return !((*easy).multi).is_null() && (*(*easy).multi).in_callback as i32 != 0
        || !((*easy).multi_easy).is_null()
            && (*(*easy).multi_easy).in_callback as i32 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_multi_max_concurrent_streams(
    mut multi: *mut Curl_multi,
) -> u32 {
    return (*multi).max_concurrent_streams;
}
