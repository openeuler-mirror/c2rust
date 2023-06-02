use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    static mut stderr: *mut FILE;
    
    
    
    
    
    
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
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::base64::Curl_base64url_encode;
pub use crate::src::lib::connect::Curl_timeleft;
pub use crate::src::lib::curl_addrinfo::Curl_freeaddrinfo;
pub use crate::src::lib::dynbuf::Curl_dyn_add;
pub use crate::src::lib::dynbuf::Curl_dyn_addn;
pub use crate::src::lib::dynbuf::Curl_dyn_free;
pub use crate::src::lib::dynbuf::Curl_dyn_init;
pub use crate::src::lib::dynbuf::Curl_dyn_len;
pub use crate::src::lib::dynbuf::Curl_dyn_ptr;
pub use crate::src::lib::dynbuf::Curl_dyn_uptr;
pub use crate::src::lib::hostip::Curl_cache_addr;
pub use crate::src::lib::hostip::Curl_ipv6works;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::multi::Curl_expire;
pub use crate::src::lib::multi::curl_multi_add_handle;
pub use crate::src::lib::multi::curl_multi_remove_handle;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::setopt::curl_easy_setopt;
pub use crate::src::lib::share::Curl_share_lock;
pub use crate::src::lib::share::Curl_share_unlock;
pub use crate::src::lib::slist::curl_slist_append;
pub use crate::src::lib::slist::curl_slist_free_all;
pub use crate::src::lib::strerror::curl_easy_strerror;
pub use crate::src::lib::url::Curl_close;
pub use crate::src::lib::url::Curl_open;
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::altsvc::Gsasl;
pub use crate::src::lib::easy::Curl_ccalloc;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::hostip6::psl_ctx_st;
pub use crate::src::lib::imap::_IO_marker;
pub use crate::src::lib::speedcheck::_IO_codecvt;
pub use crate::src::lib::urlapi::Gsasl_session;
pub use crate::src::lib::version::nghttp2_session;
pub use crate::src::lib::vtls::vtls::_IO_wide_data;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
pub type __uint8_t = crate::src::lib::altsvc::__uint8_t;
pub type __uint16_t = crate::src::lib::connect::__uint16_t;
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
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_4 = crate::src::lib::altsvc::C2RustUnnamed_4;
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
pub type C2RustUnnamed_5 = u32;
pub const TRNSPRT_QUIC: C2RustUnnamed_5 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_5 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_5 = 3;
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
pub type curl_calloc_callback = crate::src::lib::altsvc::curl_calloc_callback;
pub type CURLoption = u32;
pub const CURLOPT_LASTENTRY: CURLoption = 40311;
pub const CURLOPT_PROXY_CAINFO_BLOB: CURLoption = 40310;
pub const CURLOPT_CAINFO_BLOB: CURLoption = 40309;
pub const CURLOPT_DOH_SSL_VERIFYSTATUS: CURLoption = 308;
pub const CURLOPT_DOH_SSL_VERIFYHOST: CURLoption = 307;
pub const CURLOPT_DOH_SSL_VERIFYPEER: CURLoption = 306;
pub const CURLOPT_AWS_SIGV4: CURLoption = 10305;
pub const CURLOPT_HSTSWRITEDATA: CURLoption = 10304;
pub const CURLOPT_HSTSWRITEFUNCTION: CURLoption = 20303;
pub const CURLOPT_HSTSREADDATA: CURLoption = 10302;
pub const CURLOPT_HSTSREADFUNCTION: CURLoption = 20301;
pub const CURLOPT_HSTS: CURLoption = 10300;
pub const CURLOPT_HSTS_CTRL: CURLoption = 299;
pub const CURLOPT_SSL_EC_CURVES: CURLoption = 10298;
pub const CURLOPT_PROXY_ISSUERCERT_BLOB: CURLoption = 40297;
pub const CURLOPT_PROXY_ISSUERCERT: CURLoption = 10296;
pub const CURLOPT_ISSUERCERT_BLOB: CURLoption = 40295;
pub const CURLOPT_PROXY_SSLKEY_BLOB: CURLoption = 40294;
pub const CURLOPT_PROXY_SSLCERT_BLOB: CURLoption = 40293;
pub const CURLOPT_SSLKEY_BLOB: CURLoption = 40292;
pub const CURLOPT_SSLCERT_BLOB: CURLoption = 40291;
pub const CURLOPT_MAIL_RCPT_ALLLOWFAILS: CURLoption = 290;
pub const CURLOPT_SASL_AUTHZID: CURLoption = 10289;
pub const CURLOPT_MAXAGE_CONN: CURLoption = 288;
pub const CURLOPT_ALTSVC: CURLoption = 10287;
pub const CURLOPT_ALTSVC_CTRL: CURLoption = 286;
pub const CURLOPT_HTTP09_ALLOWED: CURLoption = 285;
pub const CURLOPT_TRAILERDATA: CURLoption = 10284;
pub const CURLOPT_TRAILERFUNCTION: CURLoption = 20283;
pub const CURLOPT_CURLU: CURLoption = 10282;
pub const CURLOPT_UPKEEP_INTERVAL_MS: CURLoption = 281;
pub const CURLOPT_UPLOAD_BUFFERSIZE: CURLoption = 280;
pub const CURLOPT_DOH_URL: CURLoption = 10279;
pub const CURLOPT_DISALLOW_USERNAME_IN_URL: CURLoption = 278;
pub const CURLOPT_PROXY_TLS13_CIPHERS: CURLoption = 10277;
pub const CURLOPT_TLS13_CIPHERS: CURLoption = 10276;
pub const CURLOPT_DNS_SHUFFLE_ADDRESSES: CURLoption = 275;
pub const CURLOPT_HAPROXYPROTOCOL: CURLoption = 274;
pub const CURLOPT_RESOLVER_START_DATA: CURLoption = 10273;
pub const CURLOPT_RESOLVER_START_FUNCTION: CURLoption = 20272;
pub const CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS: CURLoption = 271;
pub const CURLOPT_TIMEVALUE_LARGE: CURLoption = 30270;
pub const CURLOPT_MIMEPOST: CURLoption = 10269;
pub const CURLOPT_SSH_COMPRESSION: CURLoption = 268;
pub const CURLOPT_SOCKS5_AUTH: CURLoption = 267;
pub const CURLOPT_REQUEST_TARGET: CURLoption = 10266;
pub const CURLOPT_SUPPRESS_CONNECT_HEADERS: CURLoption = 265;
pub const CURLOPT_ABSTRACT_UNIX_SOCKET: CURLoption = 10264;
pub const CURLOPT_PROXY_PINNEDPUBLICKEY: CURLoption = 10263;
pub const CURLOPT_PRE_PROXY: CURLoption = 10262;
pub const CURLOPT_PROXY_SSL_OPTIONS: CURLoption = 261;
pub const CURLOPT_PROXY_CRLFILE: CURLoption = 10260;
pub const CURLOPT_PROXY_SSL_CIPHER_LIST: CURLoption = 10259;
pub const CURLOPT_PROXY_KEYPASSWD: CURLoption = 10258;
pub const CURLOPT_PROXY_SSLKEYTYPE: CURLoption = 10257;
pub const CURLOPT_PROXY_SSLKEY: CURLoption = 10256;
pub const CURLOPT_PROXY_SSLCERTTYPE: CURLoption = 10255;
pub const CURLOPT_PROXY_SSLCERT: CURLoption = 10254;
pub const CURLOPT_PROXY_TLSAUTH_TYPE: CURLoption = 10253;
pub const CURLOPT_PROXY_TLSAUTH_PASSWORD: CURLoption = 10252;
pub const CURLOPT_PROXY_TLSAUTH_USERNAME: CURLoption = 10251;
pub const CURLOPT_PROXY_SSLVERSION: CURLoption = 250;
pub const CURLOPT_PROXY_SSL_VERIFYHOST: CURLoption = 249;
pub const CURLOPT_PROXY_SSL_VERIFYPEER: CURLoption = 248;
pub const CURLOPT_PROXY_CAPATH: CURLoption = 10247;
pub const CURLOPT_PROXY_CAINFO: CURLoption = 10246;
pub const CURLOPT_KEEP_SENDING_ON_ERROR: CURLoption = 245;
pub const CURLOPT_TCP_FASTOPEN: CURLoption = 244;
pub const CURLOPT_CONNECT_TO: CURLoption = 10243;
pub const CURLOPT_TFTP_NO_OPTIONS: CURLoption = 242;
pub const CURLOPT_STREAM_DEPENDS_E: CURLoption = 10241;
pub const CURLOPT_STREAM_DEPENDS: CURLoption = 10240;
pub const CURLOPT_STREAM_WEIGHT: CURLoption = 239;
pub const CURLOPT_DEFAULT_PROTOCOL: CURLoption = 10238;
pub const CURLOPT_PIPEWAIT: CURLoption = 237;
pub const CURLOPT_SERVICE_NAME: CURLoption = 10236;
pub const CURLOPT_PROXY_SERVICE_NAME: CURLoption = 10235;
pub const CURLOPT_PATH_AS_IS: CURLoption = 234;
pub const CURLOPT_SSL_FALSESTART: CURLoption = 233;
pub const CURLOPT_SSL_VERIFYSTATUS: CURLoption = 232;
pub const CURLOPT_UNIX_SOCKET_PATH: CURLoption = 10231;
pub const CURLOPT_PINNEDPUBLICKEY: CURLoption = 10230;
pub const CURLOPT_HEADEROPT: CURLoption = 229;
pub const CURLOPT_PROXYHEADER: CURLoption = 10228;
pub const CURLOPT_EXPECT_100_TIMEOUT_MS: CURLoption = 227;
pub const CURLOPT_SSL_ENABLE_ALPN: CURLoption = 226;
pub const CURLOPT_SSL_ENABLE_NPN: CURLoption = 225;
pub const CURLOPT_LOGIN_OPTIONS: CURLoption = 10224;
pub const CURLOPT_DNS_LOCAL_IP6: CURLoption = 10223;
pub const CURLOPT_DNS_LOCAL_IP4: CURLoption = 10222;
pub const CURLOPT_DNS_INTERFACE: CURLoption = 10221;
pub const CURLOPT_XOAUTH2_BEARER: CURLoption = 10220;
pub const CURLOPT_XFERINFOFUNCTION: CURLoption = 20219;
pub const CURLOPT_SASL_IR: CURLoption = 218;
pub const CURLOPT_MAIL_AUTH: CURLoption = 10217;
pub const CURLOPT_SSL_OPTIONS: CURLoption = 216;
pub const CURLOPT_TCP_KEEPINTVL: CURLoption = 215;
pub const CURLOPT_TCP_KEEPIDLE: CURLoption = 214;
pub const CURLOPT_TCP_KEEPALIVE: CURLoption = 213;
pub const CURLOPT_ACCEPTTIMEOUT_MS: CURLoption = 212;
pub const CURLOPT_DNS_SERVERS: CURLoption = 10211;
pub const CURLOPT_GSSAPI_DELEGATION: CURLoption = 210;
pub const CURLOPT_CLOSESOCKETDATA: CURLoption = 10209;
pub const CURLOPT_CLOSESOCKETFUNCTION: CURLoption = 20208;
pub const CURLOPT_TRANSFER_ENCODING: CURLoption = 207;
pub const CURLOPT_TLSAUTH_TYPE: CURLoption = 10206;
pub const CURLOPT_TLSAUTH_PASSWORD: CURLoption = 10205;
pub const CURLOPT_TLSAUTH_USERNAME: CURLoption = 10204;
pub const CURLOPT_RESOLVE: CURLoption = 10203;
pub const CURLOPT_FNMATCH_DATA: CURLoption = 10202;
pub const CURLOPT_CHUNK_DATA: CURLoption = 10201;
pub const CURLOPT_FNMATCH_FUNCTION: CURLoption = 20200;
pub const CURLOPT_CHUNK_END_FUNCTION: CURLoption = 20199;
pub const CURLOPT_CHUNK_BGN_FUNCTION: CURLoption = 20198;
pub const CURLOPT_WILDCARDMATCH: CURLoption = 197;
pub const CURLOPT_INTERLEAVEFUNCTION: CURLoption = 20196;
pub const CURLOPT_INTERLEAVEDATA: CURLoption = 10195;
pub const CURLOPT_RTSP_SERVER_CSEQ: CURLoption = 194;
pub const CURLOPT_RTSP_CLIENT_CSEQ: CURLoption = 193;
pub const CURLOPT_RTSP_TRANSPORT: CURLoption = 10192;
pub const CURLOPT_RTSP_STREAM_URI: CURLoption = 10191;
pub const CURLOPT_RTSP_SESSION_ID: CURLoption = 10190;
pub const CURLOPT_RTSP_REQUEST: CURLoption = 189;
pub const CURLOPT_FTP_USE_PRET: CURLoption = 188;
pub const CURLOPT_MAIL_RCPT: CURLoption = 10187;
pub const CURLOPT_MAIL_FROM: CURLoption = 10186;
pub const CURLOPT_SSH_KEYDATA: CURLoption = 10185;
pub const CURLOPT_SSH_KEYFUNCTION: CURLoption = 20184;
pub const CURLOPT_SSH_KNOWNHOSTS: CURLoption = 10183;
pub const CURLOPT_REDIR_PROTOCOLS: CURLoption = 182;
pub const CURLOPT_PROTOCOLS: CURLoption = 181;
pub const CURLOPT_SOCKS5_GSSAPI_NEC: CURLoption = 180;
pub const CURLOPT_SOCKS5_GSSAPI_SERVICE: CURLoption = 10179;
pub const CURLOPT_TFTP_BLKSIZE: CURLoption = 178;
pub const CURLOPT_NOPROXY: CURLoption = 10177;
pub const CURLOPT_PROXYPASSWORD: CURLoption = 10176;
pub const CURLOPT_PROXYUSERNAME: CURLoption = 10175;
pub const CURLOPT_PASSWORD: CURLoption = 10174;
pub const CURLOPT_USERNAME: CURLoption = 10173;
pub const CURLOPT_CERTINFO: CURLoption = 172;
pub const CURLOPT_ADDRESS_SCOPE: CURLoption = 171;
pub const CURLOPT_ISSUERCERT: CURLoption = 10170;
pub const CURLOPT_CRLFILE: CURLoption = 10169;
pub const CURLOPT_SEEKDATA: CURLoption = 10168;
pub const CURLOPT_SEEKFUNCTION: CURLoption = 20167;
pub const CURLOPT_PROXY_TRANSFER_MODE: CURLoption = 166;
pub const CURLOPT_COPYPOSTFIELDS: CURLoption = 10165;
pub const CURLOPT_OPENSOCKETDATA: CURLoption = 10164;
pub const CURLOPT_OPENSOCKETFUNCTION: CURLoption = 20163;
pub const CURLOPT_SSH_HOST_PUBLIC_KEY_MD5: CURLoption = 10162;
pub const CURLOPT_POSTREDIR: CURLoption = 161;
pub const CURLOPT_NEW_DIRECTORY_PERMS: CURLoption = 160;
pub const CURLOPT_NEW_FILE_PERMS: CURLoption = 159;
pub const CURLOPT_HTTP_CONTENT_DECODING: CURLoption = 158;
pub const CURLOPT_HTTP_TRANSFER_DECODING: CURLoption = 157;
pub const CURLOPT_CONNECTTIMEOUT_MS: CURLoption = 156;
pub const CURLOPT_TIMEOUT_MS: CURLoption = 155;
pub const CURLOPT_FTP_SSL_CCC: CURLoption = 154;
pub const CURLOPT_SSH_PRIVATE_KEYFILE: CURLoption = 10153;
pub const CURLOPT_SSH_PUBLIC_KEYFILE: CURLoption = 10152;
pub const CURLOPT_SSH_AUTH_TYPES: CURLoption = 151;
pub const CURLOPT_SSL_SESSIONID_CACHE: CURLoption = 150;
pub const CURLOPT_SOCKOPTDATA: CURLoption = 10149;
pub const CURLOPT_SOCKOPTFUNCTION: CURLoption = 20148;
pub const CURLOPT_FTP_ALTERNATIVE_TO_USER: CURLoption = 10147;
pub const CURLOPT_MAX_RECV_SPEED_LARGE: CURLoption = 30146;
pub const CURLOPT_MAX_SEND_SPEED_LARGE: CURLoption = 30145;
pub const CURLOPT_CONV_FROM_UTF8_FUNCTION: CURLoption = 20144;
pub const CURLOPT_CONV_TO_NETWORK_FUNCTION: CURLoption = 20143;
pub const CURLOPT_CONV_FROM_NETWORK_FUNCTION: CURLoption = 20142;
pub const CURLOPT_CONNECT_ONLY: CURLoption = 141;
pub const CURLOPT_LOCALPORTRANGE: CURLoption = 140;
pub const CURLOPT_LOCALPORT: CURLoption = 139;
pub const CURLOPT_FTP_FILEMETHOD: CURLoption = 138;
pub const CURLOPT_FTP_SKIP_PASV_IP: CURLoption = 137;
pub const CURLOPT_IGNORE_CONTENT_LENGTH: CURLoption = 136;
pub const CURLOPT_COOKIELIST: CURLoption = 10135;
pub const CURLOPT_FTP_ACCOUNT: CURLoption = 10134;
pub const CURLOPT_IOCTLDATA: CURLoption = 10131;
pub const CURLOPT_IOCTLFUNCTION: CURLoption = 20130;
pub const CURLOPT_FTPSSLAUTH: CURLoption = 129;
pub const CURLOPT_TCP_NODELAY: CURLoption = 121;
pub const CURLOPT_POSTFIELDSIZE_LARGE: CURLoption = 30120;
pub const CURLOPT_USE_SSL: CURLoption = 119;
pub const CURLOPT_NETRC_FILE: CURLoption = 10118;
pub const CURLOPT_MAXFILESIZE_LARGE: CURLoption = 30117;
pub const CURLOPT_RESUME_FROM_LARGE: CURLoption = 30116;
pub const CURLOPT_INFILESIZE_LARGE: CURLoption = 30115;
pub const CURLOPT_MAXFILESIZE: CURLoption = 114;
pub const CURLOPT_IPRESOLVE: CURLoption = 113;
pub const CURLOPT_FTP_RESPONSE_TIMEOUT: CURLoption = 112;
pub const CURLOPT_PROXYAUTH: CURLoption = 111;
pub const CURLOPT_FTP_CREATE_MISSING_DIRS: CURLoption = 110;
pub const CURLOPT_SSL_CTX_DATA: CURLoption = 10109;
pub const CURLOPT_SSL_CTX_FUNCTION: CURLoption = 20108;
pub const CURLOPT_HTTPAUTH: CURLoption = 107;
pub const CURLOPT_FTP_USE_EPRT: CURLoption = 106;
pub const CURLOPT_UNRESTRICTED_AUTH: CURLoption = 105;
pub const CURLOPT_HTTP200ALIASES: CURLoption = 10104;
pub const CURLOPT_PRIVATE: CURLoption = 10103;
pub const CURLOPT_ACCEPT_ENCODING: CURLoption = 10102;
pub const CURLOPT_PROXYTYPE: CURLoption = 101;
pub const CURLOPT_SHARE: CURLoption = 10100;
pub const CURLOPT_NOSIGNAL: CURLoption = 99;
pub const CURLOPT_BUFFERSIZE: CURLoption = 98;
pub const CURLOPT_CAPATH: CURLoption = 10097;
pub const CURLOPT_COOKIESESSION: CURLoption = 96;
pub const CURLOPT_DEBUGDATA: CURLoption = 10095;
pub const CURLOPT_DEBUGFUNCTION: CURLoption = 20094;
pub const CURLOPT_PREQUOTE: CURLoption = 10093;
pub const CURLOPT_DNS_CACHE_TIMEOUT: CURLoption = 92;
pub const CURLOPT_DNS_USE_GLOBAL_CACHE: CURLoption = 91;
pub const CURLOPT_SSLENGINE_DEFAULT: CURLoption = 90;
pub const CURLOPT_SSLENGINE: CURLoption = 10089;
pub const CURLOPT_SSLKEYTYPE: CURLoption = 10088;
pub const CURLOPT_SSLKEY: CURLoption = 10087;
pub const CURLOPT_SSLCERTTYPE: CURLoption = 10086;
pub const CURLOPT_FTP_USE_EPSV: CURLoption = 85;
pub const CURLOPT_HTTP_VERSION: CURLoption = 84;
pub const CURLOPT_SSL_CIPHER_LIST: CURLoption = 10083;
pub const CURLOPT_COOKIEJAR: CURLoption = 10082;
pub const CURLOPT_SSL_VERIFYHOST: CURLoption = 81;
pub const CURLOPT_HTTPGET: CURLoption = 80;
pub const CURLOPT_HEADERFUNCTION: CURLoption = 20079;
pub const CURLOPT_CONNECTTIMEOUT: CURLoption = 78;
pub const CURLOPT_EGDSOCKET: CURLoption = 10077;
pub const CURLOPT_RANDOM_FILE: CURLoption = 10076;
pub const CURLOPT_FORBID_REUSE: CURLoption = 75;
pub const CURLOPT_FRESH_CONNECT: CURLoption = 74;
pub const CURLOPT_OBSOLETE72: CURLoption = 72;
pub const CURLOPT_MAXCONNECTS: CURLoption = 71;
pub const CURLOPT_TELNETOPTIONS: CURLoption = 10070;
pub const CURLOPT_FILETIME: CURLoption = 69;
pub const CURLOPT_MAXREDIRS: CURLoption = 68;
pub const CURLOPT_CAINFO: CURLoption = 10065;
pub const CURLOPT_SSL_VERIFYPEER: CURLoption = 64;
pub const CURLOPT_KRBLEVEL: CURLoption = 10063;
pub const CURLOPT_INTERFACE: CURLoption = 10062;
pub const CURLOPT_HTTPPROXYTUNNEL: CURLoption = 61;
pub const CURLOPT_POSTFIELDSIZE: CURLoption = 60;
pub const CURLOPT_PROXYPORT: CURLoption = 59;
pub const CURLOPT_AUTOREFERER: CURLoption = 58;
pub const CURLOPT_XFERINFODATA: CURLoption = 10057;
pub const CURLOPT_PROGRESSFUNCTION: CURLoption = 20056;
pub const CURLOPT_PUT: CURLoption = 54;
pub const CURLOPT_TRANSFERTEXT: CURLoption = 53;
pub const CURLOPT_FOLLOWLOCATION: CURLoption = 52;
pub const CURLOPT_NETRC: CURLoption = 51;
pub const CURLOPT_APPEND: CURLoption = 50;
pub const CURLOPT_DIRLISTONLY: CURLoption = 48;
pub const CURLOPT_POST: CURLoption = 47;
pub const CURLOPT_UPLOAD: CURLoption = 46;
pub const CURLOPT_FAILONERROR: CURLoption = 45;
pub const CURLOPT_NOBODY: CURLoption = 44;
pub const CURLOPT_NOPROGRESS: CURLoption = 43;
pub const CURLOPT_HEADER: CURLoption = 42;
pub const CURLOPT_VERBOSE: CURLoption = 41;
pub const CURLOPT_OBSOLETE40: CURLoption = 10040;
pub const CURLOPT_POSTQUOTE: CURLoption = 10039;
pub const CURLOPT_STDERR: CURLoption = 10037;
pub const CURLOPT_CUSTOMREQUEST: CURLoption = 10036;
pub const CURLOPT_TIMEVALUE: CURLoption = 34;
pub const CURLOPT_TIMECONDITION: CURLoption = 33;
pub const CURLOPT_SSLVERSION: CURLoption = 32;
pub const CURLOPT_COOKIEFILE: CURLoption = 10031;
pub const CURLOPT_HEADERDATA: CURLoption = 10029;
pub const CURLOPT_QUOTE: CURLoption = 10028;
pub const CURLOPT_CRLF: CURLoption = 27;
pub const CURLOPT_KEYPASSWD: CURLoption = 10026;
pub const CURLOPT_SSLCERT: CURLoption = 10025;
pub const CURLOPT_HTTPPOST: CURLoption = 10024;
pub const CURLOPT_HTTPHEADER: CURLoption = 10023;
pub const CURLOPT_COOKIE: CURLoption = 10022;
pub const CURLOPT_RESUME_FROM: CURLoption = 21;
pub const CURLOPT_LOW_SPEED_TIME: CURLoption = 20;
pub const CURLOPT_LOW_SPEED_LIMIT: CURLoption = 19;
pub const CURLOPT_USERAGENT: CURLoption = 10018;
pub const CURLOPT_FTPPORT: CURLoption = 10017;
pub const CURLOPT_REFERER: CURLoption = 10016;
pub const CURLOPT_POSTFIELDS: CURLoption = 10015;
pub const CURLOPT_INFILESIZE: CURLoption = 14;
pub const CURLOPT_TIMEOUT: CURLoption = 13;
pub const CURLOPT_READFUNCTION: CURLoption = 20012;
pub const CURLOPT_WRITEFUNCTION: CURLoption = 20011;
pub const CURLOPT_ERRORBUFFER: CURLoption = 10010;
pub const CURLOPT_READDATA: CURLoption = 10009;
pub const CURLOPT_RANGE: CURLoption = 10007;
pub const CURLOPT_PROXYUSERPWD: CURLoption = 10006;
pub const CURLOPT_USERPWD: CURLoption = 10005;
pub const CURLOPT_PROXY: CURLoption = 10004;
pub const CURLOPT_PORT: CURLoption = 3;
pub const CURLOPT_URL: CURLoption = 10002;
pub const CURLOPT_WRITEDATA: CURLoption = 10001;
pub type C2RustUnnamed_6 = u32;
pub const CURL_HTTP_VERSION_LAST: C2RustUnnamed_6 = 31;
pub const CURL_HTTP_VERSION_3: C2RustUnnamed_6 = 30;
pub const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: C2RustUnnamed_6 = 5;
pub const CURL_HTTP_VERSION_2TLS: C2RustUnnamed_6 = 4;
pub const CURL_HTTP_VERSION_2_0: C2RustUnnamed_6 = 3;
pub const CURL_HTTP_VERSION_1_1: C2RustUnnamed_6 = 2;
pub const CURL_HTTP_VERSION_1_0: C2RustUnnamed_6 = 1;
pub const CURL_HTTP_VERSION_NONE: C2RustUnnamed_6 = 0;
pub type CURLSHcode = crate::src::lib::conncache::CURLSHcode;
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
pub type uint16_t = crate::src::lib::connect::uint16_t;
pub type in_addr_t = crate::src::lib::connect::in_addr_t;
// #[derive(Copy, Clone)]

pub type in_addr = crate::src::lib::connect::in_addr;
pub type in_port_t = crate::src::lib::connect::in_port_t;
// #[derive(Copy, Clone)]

pub type in6_addr = crate::src::lib::connect::in6_addr;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_7 = crate::src::lib::connect::C2RustUnnamed_8;
// #[derive(Copy, Clone)]

pub type sockaddr_in = crate::src::lib::connect::sockaddr_in;
// #[derive(Copy, Clone)]

pub type sockaddr_in6 = crate::src::lib::connect::sockaddr_in6;
pub type doh_slots = u32;
pub const DOH_PROBE_SLOTS: doh_slots = 2;
pub const DOH_PROBE_SLOT_IPADDR_V6: doh_slots = 1;
pub const DOH_PROBE_SLOT_IPADDR_V4: doh_slots = 0;
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
pub type DNStype = u32;
pub const DNS_TYPE_DNAME: DNStype = 39;
pub const DNS_TYPE_AAAA: DNStype = 28;
pub const DNS_TYPE_CNAME: DNStype = 5;
pub const DNS_TYPE_NS: DNStype = 2;
pub const DNS_TYPE_A: DNStype = 1;
pub type DOHcode = u32;
pub const DOH_DNS_NAME_TOO_LONG: DOHcode = 13;
pub const DOH_DNS_BAD_ID: DOHcode = 12;
pub const DOH_NO_CONTENT: DOHcode = 11;
pub const DOH_DNS_UNEXPECTED_CLASS: DOHcode = 10;
pub const DOH_DNS_UNEXPECTED_TYPE: DOHcode = 9;
pub const DOH_DNS_BAD_RCODE: DOHcode = 8;
pub const DOH_DNS_MALFORMAT: DOHcode = 7;
pub const DOH_DNS_RDATA_LEN: DOHcode = 6;
pub const DOH_OUT_OF_MEM: DOHcode = 5;
pub const DOH_TOO_SMALL_BUFFER: DOHcode = 4;
pub const DOH_DNS_LABEL_LOOP: DOHcode = 3;
pub const DOH_DNS_OUT_OF_RANGE: DOHcode = 2;
pub const DOH_DNS_BAD_LABEL: DOHcode = 1;
pub const DOH_OK: DOHcode = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dohentry {
    pub cname: [dynbuf; 4],
    pub addr: [dohaddr; 24],
    pub numaddr: i32,
    pub ttl: u32,
    pub numcname: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dohaddr {
    pub type_0: i32,
    pub ip: C2RustUnnamed_8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_8 {
    pub v4: [u8; 4],
    pub v6: [u8; 16],
}
#[inline]
 extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as i32 >> 8 as i32 & 0xff as i32
        | (__bsx as i32 & 0xff as i32) << 8 as i32)
        as __uint16_t;
}
static mut errors: [*const i8; 14] = [
    b"\0" as *const u8 as *const i8,
    b"Bad label\0" as *const u8 as *const i8,
    b"Out of range\0" as *const u8 as *const i8,
    b"Label loop\0" as *const u8 as *const i8,
    b"Too small\0" as *const u8 as *const i8,
    b"Out of memory\0" as *const u8 as *const i8,
    b"RDATA length\0" as *const u8 as *const i8,
    b"Malformat\0" as *const u8 as *const i8,
    b"Bad RCODE\0" as *const u8 as *const i8,
    b"Unexpected TYPE\0" as *const u8 as *const i8,
    b"Unexpected CLASS\0" as *const u8 as *const i8,
    b"No content\0" as *const u8 as *const i8,
    b"Bad ID\0" as *const u8 as *const i8,
    b"Name too long\0" as *const u8 as *const i8,
];
unsafe extern "C" fn doh_strerror(mut code: DOHcode) -> *const i8 {
    if code as u32 >= DOH_OK as i32 as u32
        && code as u32 <= DOH_DNS_NAME_TOO_LONG as i32 as u32
    {
        return errors[code as usize];
    }
    return b"bad error code\0" as *const u8 as *const i8;
}
unsafe extern "C" fn doh_encode(
    mut host: *const i8,
    mut dnstype: DNStype,
    mut dnsp: *mut u8,
    mut len: size_t,
    mut olen: *mut size_t,
) -> DOHcode {
    let hostlen: size_t = strlen(host);
    let mut orig: *mut u8 = dnsp;
    let mut hostp: *const i8 = host;
    let mut expected_len: size_t = 0;
    expected_len = ((12 as i32 + 1 as i32) as u64)
        .wrapping_add(hostlen)
        .wrapping_add(4 as i32 as u64);
    if *host.offset(hostlen.wrapping_sub(1 as i32 as u64) as isize)
        as i32 != '.' as i32
    {
        expected_len = expected_len.wrapping_add(1);
    }
    if expected_len > (256 as i32 + 16 as i32) as u64 {
        return DOH_DNS_NAME_TOO_LONG;
    }
    if len < expected_len {
        return DOH_TOO_SMALL_BUFFER;
    }
    let fresh0 = dnsp;
    dnsp = dnsp.offset(1);
    *fresh0 = 0 as i32 as u8;
    let fresh1 = dnsp;
    dnsp = dnsp.offset(1);
    *fresh1 = 0 as i32 as u8;
    let fresh2 = dnsp;
    dnsp = dnsp.offset(1);
    *fresh2 = 0x1 as i32 as u8;
    let fresh3 = dnsp;
    dnsp = dnsp.offset(1);
    *fresh3 = '\u{0}' as i32 as u8;
    let fresh4 = dnsp;
    dnsp = dnsp.offset(1);
    *fresh4 = '\u{0}' as i32 as u8;
    let fresh5 = dnsp;
    dnsp = dnsp.offset(1);
    *fresh5 = 1 as i32 as u8;
    let fresh6 = dnsp;
    dnsp = dnsp.offset(1);
    *fresh6 = '\u{0}' as i32 as u8;
    let fresh7 = dnsp;
    dnsp = dnsp.offset(1);
    *fresh7 = '\u{0}' as i32 as u8;
    let fresh8 = dnsp;
    dnsp = dnsp.offset(1);
    *fresh8 = '\u{0}' as i32 as u8;
    let fresh9 = dnsp;
    dnsp = dnsp.offset(1);
    *fresh9 = '\u{0}' as i32 as u8;
    let fresh10 = dnsp;
    dnsp = dnsp.offset(1);
    *fresh10 = '\u{0}' as i32 as u8;
    let fresh11 = dnsp;
    dnsp = dnsp.offset(1);
    *fresh11 = '\u{0}' as i32 as u8;
    while *hostp != 0 {
        let mut labellen: size_t = 0;
        let mut dot: *mut i8 = strchr(hostp, '.' as i32);
        if !dot.is_null() {
            labellen = dot.offset_from(hostp) as i64 as size_t;
        } else {
            labellen = strlen(hostp);
        }
        if labellen > 63 as i32 as u64 || labellen == 0 {
            *olen = 0 as i32 as size_t;
            return DOH_DNS_BAD_LABEL;
        }
        let fresh12 = dnsp;
        dnsp = dnsp.offset(1);
        *fresh12 = labellen as u8;
        memcpy(dnsp as *mut libc::c_void, hostp as *const libc::c_void, labellen);
        dnsp = dnsp.offset(labellen as isize);
        hostp = hostp.offset(labellen as isize);
        if !dot.is_null() {
            hostp = hostp.offset(1);
        }
    }
    let fresh13 = dnsp;
    dnsp = dnsp.offset(1);
    *fresh13 = 0 as i32 as u8;
    let fresh14 = dnsp;
    dnsp = dnsp.offset(1);
    *fresh14 = (255 as i32 as u32
        & dnstype as u32 >> 8 as i32) as u8;
    let fresh15 = dnsp;
    dnsp = dnsp.offset(1);
    *fresh15 = (255 as i32 as u32 & dnstype as u32)
        as u8;
    let fresh16 = dnsp;
    dnsp = dnsp.offset(1);
    *fresh16 = '\u{0}' as i32 as u8;
    let fresh17 = dnsp;
    dnsp = dnsp.offset(1);
    *fresh17 = 0x1 as i32 as u8;
    *olen = dnsp.offset_from(orig) as i64 as size_t;
    return DOH_OK;
}
unsafe extern "C" fn doh_write_cb(
    mut contents: *const libc::c_void,
    mut size: size_t,
    mut nmemb: size_t,
    mut userp: *mut libc::c_void,
) -> size_t {
    let mut realsize: size_t = size.wrapping_mul(nmemb);
    let mut mem: *mut dynbuf = userp as *mut dynbuf;
    if Curl_dyn_addn(mem, contents, realsize) as u64 != 0 {
        return 0 as i32 as size_t;
    }
    return realsize;
}
unsafe extern "C" fn doh_done(
    mut doh: *mut Curl_easy,
    mut result: CURLcode,
) -> i32 {
    let mut data: *mut Curl_easy = (*doh).set.dohfor;
    let mut dohp: *mut dohdata = (*data).req.doh;
    let fresh18 = &mut ((*dohp).pending);
    *fresh18 = (*fresh18).wrapping_sub(1);
    Curl_infof(
        data,
        b"a DoH request is completed, %u to go\0" as *const u8 as *const i8,
        (*dohp).pending,
    );
    if result as u64 != 0 {
        Curl_infof(
            data,
            b"DoH request %s\0" as *const u8 as *const i8,
            curl_easy_strerror(result),
        );
    }
    if (*dohp).pending == 0 {
        curl_slist_free_all((*dohp).headers);
        let fresh19 = &mut ((*dohp).headers);
        *fresh19 = 0 as *mut curl_slist;
        Curl_expire(data, 0 as i32 as timediff_t, EXPIRE_RUN_NOW);
    }
    return 0 as i32;
}
unsafe extern "C" fn dohprobe(
    mut data: *mut Curl_easy,
    mut p: *mut dnsprobe,
    mut dnstype: DNStype,
    mut host: *const i8,
    mut url: *const i8,
    mut multi: *mut CURLM,
    mut headers: *mut curl_slist,
) -> CURLcode {
    let mut current_block: u64;
    let mut doh: *mut Curl_easy = 0 as *mut Curl_easy;
    let mut nurl: *mut i8 = 0 as *mut i8;
    let mut result: CURLcode = CURLE_OK;
    let mut timeout_ms: timediff_t = 0;
    let mut d: DOHcode = doh_encode(
        host,
        dnstype,
        ((*p).dohbuffer).as_mut_ptr(),
        ::std::mem::size_of::<[u8; 512]>() as u64,
        &mut (*p).dohlen,
    );
    if d as u64 != 0 {
        Curl_failf(
            data,
            b"Failed to encode DoH packet [%d]\0" as *const u8 as *const i8,
            d as u32,
        );
        return CURLE_OUT_OF_MEMORY;
    }
    (*p).dnstype = dnstype as i32;
    Curl_dyn_init(&mut (*p).serverdoh, 3000 as i32 as size_t);
    if ((*data).set).doh_get() != 0 {
        let mut b64: *mut i8 = 0 as *mut i8;
        let mut b64len: size_t = 0;
        result = Curl_base64url_encode(
            data,
            ((*p).dohbuffer).as_mut_ptr() as *mut i8,
            (*p).dohlen,
            &mut b64,
            &mut b64len,
        );
        if result as u64 != 0 {
            current_block = 17522434821883794170;
        } else {
            nurl = curl_maprintf(
                b"%s?dns=%s\0" as *const u8 as *const i8,
                url,
                b64,
            );
            Curl_cfree.expect("non-null function pointer")(b64 as *mut libc::c_void);
            if nurl.is_null() {
                result = CURLE_OUT_OF_MEMORY;
                current_block = 17522434821883794170;
            } else {
                url = nurl;
                current_block = 15652330335145281839;
            }
        }
    } else {
        current_block = 15652330335145281839;
    }
    match current_block {
        15652330335145281839 => {
            timeout_ms = Curl_timeleft(data, 0 as *mut curltime, 1 as i32 != 0);
            if timeout_ms <= 0 as i32 as i64 {
                result = CURLE_OPERATION_TIMEDOUT;
            } else {
                result = Curl_open(&mut doh);
                if result as u64 == 0 {
                    let mut resp: *mut dynbuf = &mut (*p).serverdoh;
                    result = curl_easy_setopt(doh, CURLOPT_URL, url);
                    if !(result as u32 != 0
                        && result as u32
                            != CURLE_NOT_BUILT_IN as i32 as u32
                        && result as u32
                            != CURLE_UNKNOWN_OPTION as i32 as u32)
                    {
                        result = curl_easy_setopt(
                            doh,
                            CURLOPT_WRITEFUNCTION,
                            Some(
                                doh_write_cb
                                    as unsafe extern "C" fn(
                                        *const libc::c_void,
                                        size_t,
                                        size_t,
                                        *mut libc::c_void,
                                    ) -> size_t,
                            ),
                        );
                        if !(result as u32 != 0
                            && result as u32
                                != CURLE_NOT_BUILT_IN as i32 as u32
                            && result as u32
                                != CURLE_UNKNOWN_OPTION as i32 as u32)
                        {
                            result = curl_easy_setopt(doh, CURLOPT_WRITEDATA, resp);
                            if !(result as u32 != 0
                                && result as u32
                                    != CURLE_NOT_BUILT_IN as i32 as u32
                                && result as u32
                                    != CURLE_UNKNOWN_OPTION as i32 as u32)
                            {
                                if ((*data).set).doh_get() == 0 {
                                    result = curl_easy_setopt(
                                        doh,
                                        CURLOPT_POSTFIELDS,
                                        ((*p).dohbuffer).as_mut_ptr(),
                                    );
                                    if result as u32 != 0
                                        && result as u32
                                            != CURLE_NOT_BUILT_IN as i32 as u32
                                        && result as u32
                                            != CURLE_UNKNOWN_OPTION as i32 as u32
                                    {
                                        current_block = 17522434821883794170;
                                    } else {
                                        result = curl_easy_setopt(
                                            doh,
                                            CURLOPT_POSTFIELDSIZE,
                                            (*p).dohlen as i64,
                                        );
                                        if result as u32 != 0
                                            && result as u32
                                                != CURLE_NOT_BUILT_IN as i32 as u32
                                            && result as u32
                                                != CURLE_UNKNOWN_OPTION as i32 as u32
                                        {
                                            current_block = 17522434821883794170;
                                        } else {
                                            current_block = 15004371738079956865;
                                        }
                                    }
                                } else {
                                    current_block = 15004371738079956865;
                                }
                                match current_block {
                                    17522434821883794170 => {}
                                    _ => {
                                        result = curl_easy_setopt(doh, CURLOPT_HTTPHEADER, headers);
                                        if !(result as u32 != 0
                                            && result as u32
                                                != CURLE_NOT_BUILT_IN as i32 as u32
                                            && result as u32
                                                != CURLE_UNKNOWN_OPTION as i32 as u32)
                                        {
                                            result = curl_easy_setopt(
                                                doh,
                                                CURLOPT_HTTP_VERSION,
                                                CURL_HTTP_VERSION_2TLS as i32,
                                            );
                                            if !(result as u32 != 0
                                                && result as u32
                                                    != CURLE_NOT_BUILT_IN as i32 as u32
                                                && result as u32
                                                    != CURLE_UNKNOWN_OPTION as i32 as u32)
                                            {
                                                result = curl_easy_setopt(
                                                    doh,
                                                    CURLOPT_PROTOCOLS,
                                                    (1 as i32) << 1 as i32,
                                                );
                                                if !(result as u32 != 0
                                                    && result as u32
                                                        != CURLE_NOT_BUILT_IN as i32 as u32
                                                    && result as u32
                                                        != CURLE_UNKNOWN_OPTION as i32 as u32)
                                                {
                                                    result = curl_easy_setopt(
                                                        doh,
                                                        CURLOPT_TIMEOUT_MS,
                                                        timeout_ms,
                                                    );
                                                    if !(result as u32 != 0
                                                        && result as u32
                                                            != CURLE_NOT_BUILT_IN as i32 as u32
                                                        && result as u32
                                                            != CURLE_UNKNOWN_OPTION as i32 as u32)
                                                    {
                                                        result = curl_easy_setopt(
                                                            doh,
                                                            CURLOPT_SHARE,
                                                            (*data).share,
                                                        );
                                                        if !(result as u32 != 0
                                                            && result as u32
                                                                != CURLE_NOT_BUILT_IN as i32 as u32
                                                            && result as u32
                                                                != CURLE_UNKNOWN_OPTION as i32 as u32)
                                                        {
                                                            if !((*data).set.err).is_null() && (*data).set.err != stderr
                                                            {
                                                                result = curl_easy_setopt(
                                                                    doh,
                                                                    CURLOPT_STDERR,
                                                                    (*data).set.err,
                                                                );
                                                                if result as u32 != 0
                                                                    && result as u32
                                                                        != CURLE_NOT_BUILT_IN as i32 as u32
                                                                    && result as u32
                                                                        != CURLE_UNKNOWN_OPTION as i32 as u32
                                                                {
                                                                    current_block = 17522434821883794170;
                                                                } else {
                                                                    current_block = 2631791190359682872;
                                                                }
                                                            } else {
                                                                current_block = 2631791190359682872;
                                                            }
                                                            match current_block {
                                                                17522434821883794170 => {}
                                                                _ => {
                                                                    if ((*data).set).verbose() != 0 {
                                                                        result = curl_easy_setopt(
                                                                            doh,
                                                                            CURLOPT_VERBOSE,
                                                                            1 as i64,
                                                                        );
                                                                        if result as u32 != 0
                                                                            && result as u32
                                                                                != CURLE_NOT_BUILT_IN as i32 as u32
                                                                            && result as u32
                                                                                != CURLE_UNKNOWN_OPTION as i32 as u32
                                                                        {
                                                                            current_block = 17522434821883794170;
                                                                        } else {
                                                                            current_block = 14298507163138330979;
                                                                        }
                                                                    } else {
                                                                        current_block = 14298507163138330979;
                                                                    }
                                                                    match current_block {
                                                                        17522434821883794170 => {}
                                                                        _ => {
                                                                            if ((*data).set).no_signal() != 0 {
                                                                                result = curl_easy_setopt(
                                                                                    doh,
                                                                                    CURLOPT_NOSIGNAL,
                                                                                    1 as i64,
                                                                                );
                                                                                if result as u32 != 0
                                                                                    && result as u32
                                                                                        != CURLE_NOT_BUILT_IN as i32 as u32
                                                                                    && result as u32
                                                                                        != CURLE_UNKNOWN_OPTION as i32 as u32
                                                                                {
                                                                                    current_block = 17522434821883794170;
                                                                                } else {
                                                                                    current_block = 5793491756164225964;
                                                                                }
                                                                            } else {
                                                                                current_block = 5793491756164225964;
                                                                            }
                                                                            match current_block {
                                                                                17522434821883794170 => {}
                                                                                _ => {
                                                                                    result = curl_easy_setopt(
                                                                                        doh,
                                                                                        CURLOPT_SSL_VERIFYHOST,
                                                                                        if ((*data).set).doh_verifyhost() as i32 != 0 {
                                                                                            2 as i64
                                                                                        } else {
                                                                                            0 as i64
                                                                                        },
                                                                                    );
                                                                                    if !(result as u32 != 0
                                                                                        && result as u32
                                                                                            != CURLE_NOT_BUILT_IN as i32 as u32
                                                                                        && result as u32
                                                                                            != CURLE_UNKNOWN_OPTION as i32 as u32)
                                                                                    {
                                                                                        result = curl_easy_setopt(
                                                                                            doh,
                                                                                            CURLOPT_SSL_VERIFYPEER,
                                                                                            if ((*data).set).doh_verifypeer() as i32 != 0 {
                                                                                                1 as i64
                                                                                            } else {
                                                                                                0 as i64
                                                                                            },
                                                                                        );
                                                                                        if !(result as u32 != 0
                                                                                            && result as u32
                                                                                                != CURLE_NOT_BUILT_IN as i32 as u32
                                                                                            && result as u32
                                                                                                != CURLE_UNKNOWN_OPTION as i32 as u32)
                                                                                        {
                                                                                            result = curl_easy_setopt(
                                                                                                doh,
                                                                                                CURLOPT_SSL_VERIFYSTATUS,
                                                                                                if ((*data).set).doh_verifystatus() as i32 != 0 {
                                                                                                    1 as i64
                                                                                                } else {
                                                                                                    0 as i64
                                                                                                },
                                                                                            );
                                                                                            if !(result as u32 != 0
                                                                                                && result as u32
                                                                                                    != CURLE_NOT_BUILT_IN as i32 as u32
                                                                                                && result as u32
                                                                                                    != CURLE_UNKNOWN_OPTION as i32 as u32)
                                                                                            {
                                                                                                if ((*data).set.ssl).falsestart() != 0 {
                                                                                                    result = curl_easy_setopt(
                                                                                                        doh,
                                                                                                        CURLOPT_SSL_FALSESTART,
                                                                                                        1 as i64,
                                                                                                    );
                                                                                                    if result as u32 != 0
                                                                                                        && result as u32
                                                                                                            != CURLE_NOT_BUILT_IN as i32 as u32
                                                                                                        && result as u32
                                                                                                            != CURLE_UNKNOWN_OPTION as i32 as u32
                                                                                                    {
                                                                                                        current_block = 17522434821883794170;
                                                                                                    } else {
                                                                                                        current_block = 2616667235040759262;
                                                                                                    }
                                                                                                } else {
                                                                                                    current_block = 2616667235040759262;
                                                                                                }
                                                                                                match current_block {
                                                                                                    17522434821883794170 => {}
                                                                                                    _ => {
                                                                                                        if !((*data)
                                                                                                            .set
                                                                                                            .str_0[STRING_SSL_CAFILE as i32 as usize])
                                                                                                            .is_null()
                                                                                                        {
                                                                                                            result = curl_easy_setopt(
                                                                                                                doh,
                                                                                                                CURLOPT_CAINFO,
                                                                                                                (*data).set.str_0[STRING_SSL_CAFILE as i32 as usize],
                                                                                                            );
                                                                                                            if result as u32 != 0
                                                                                                                && result as u32
                                                                                                                    != CURLE_NOT_BUILT_IN as i32 as u32
                                                                                                                && result as u32
                                                                                                                    != CURLE_UNKNOWN_OPTION as i32 as u32
                                                                                                            {
                                                                                                                current_block = 17522434821883794170;
                                                                                                            } else {
                                                                                                                current_block = 12369290732426379360;
                                                                                                            }
                                                                                                        } else {
                                                                                                            current_block = 12369290732426379360;
                                                                                                        }
                                                                                                        match current_block {
                                                                                                            17522434821883794170 => {}
                                                                                                            _ => {
                                                                                                                if !((*data).set.blobs[BLOB_CAINFO as i32 as usize])
                                                                                                                    .is_null()
                                                                                                                {
                                                                                                                    result = curl_easy_setopt(
                                                                                                                        doh,
                                                                                                                        CURLOPT_CAINFO_BLOB,
                                                                                                                        (*data).set.blobs[BLOB_CAINFO as i32 as usize],
                                                                                                                    );
                                                                                                                    if result as u32 != 0
                                                                                                                        && result as u32
                                                                                                                            != CURLE_NOT_BUILT_IN as i32 as u32
                                                                                                                        && result as u32
                                                                                                                            != CURLE_UNKNOWN_OPTION as i32 as u32
                                                                                                                    {
                                                                                                                        current_block = 17522434821883794170;
                                                                                                                    } else {
                                                                                                                        current_block = 14116432890150942211;
                                                                                                                    }
                                                                                                                } else {
                                                                                                                    current_block = 14116432890150942211;
                                                                                                                }
                                                                                                                match current_block {
                                                                                                                    17522434821883794170 => {}
                                                                                                                    _ => {
                                                                                                                        if !((*data)
                                                                                                                            .set
                                                                                                                            .str_0[STRING_SSL_CAPATH as i32 as usize])
                                                                                                                            .is_null()
                                                                                                                        {
                                                                                                                            result = curl_easy_setopt(
                                                                                                                                doh,
                                                                                                                                CURLOPT_CAPATH,
                                                                                                                                (*data).set.str_0[STRING_SSL_CAPATH as i32 as usize],
                                                                                                                            );
                                                                                                                            if result as u32 != 0
                                                                                                                                && result as u32
                                                                                                                                    != CURLE_NOT_BUILT_IN as i32 as u32
                                                                                                                                && result as u32
                                                                                                                                    != CURLE_UNKNOWN_OPTION as i32 as u32
                                                                                                                            {
                                                                                                                                current_block = 17522434821883794170;
                                                                                                                            } else {
                                                                                                                                current_block = 2432552683059077439;
                                                                                                                            }
                                                                                                                        } else {
                                                                                                                            current_block = 2432552683059077439;
                                                                                                                        }
                                                                                                                        match current_block {
                                                                                                                            17522434821883794170 => {}
                                                                                                                            _ => {
                                                                                                                                if !((*data)
                                                                                                                                    .set
                                                                                                                                    .str_0[STRING_SSL_CRLFILE as i32 as usize])
                                                                                                                                    .is_null()
                                                                                                                                {
                                                                                                                                    result = curl_easy_setopt(
                                                                                                                                        doh,
                                                                                                                                        CURLOPT_CRLFILE,
                                                                                                                                        (*data)
                                                                                                                                            .set
                                                                                                                                            .str_0[STRING_SSL_CRLFILE as i32 as usize],
                                                                                                                                    );
                                                                                                                                    if result as u32 != 0
                                                                                                                                        && result as u32
                                                                                                                                            != CURLE_NOT_BUILT_IN as i32 as u32
                                                                                                                                        && result as u32
                                                                                                                                            != CURLE_UNKNOWN_OPTION as i32 as u32
                                                                                                                                    {
                                                                                                                                        current_block = 17522434821883794170;
                                                                                                                                    } else {
                                                                                                                                        current_block = 6478348674394853609;
                                                                                                                                    }
                                                                                                                                } else {
                                                                                                                                    current_block = 6478348674394853609;
                                                                                                                                }
                                                                                                                                match current_block {
                                                                                                                                    17522434821883794170 => {}
                                                                                                                                    _ => {
                                                                                                                                        if ((*data).set.ssl).certinfo() != 0 {
                                                                                                                                            result = curl_easy_setopt(
                                                                                                                                                doh,
                                                                                                                                                CURLOPT_CERTINFO,
                                                                                                                                                1 as i64,
                                                                                                                                            );
                                                                                                                                            if result as u32 != 0
                                                                                                                                                && result as u32
                                                                                                                                                    != CURLE_NOT_BUILT_IN as i32 as u32
                                                                                                                                                && result as u32
                                                                                                                                                    != CURLE_UNKNOWN_OPTION as i32 as u32
                                                                                                                                            {
                                                                                                                                                current_block = 17522434821883794170;
                                                                                                                                            } else {
                                                                                                                                                current_block = 8533724845731836612;
                                                                                                                                            }
                                                                                                                                        } else {
                                                                                                                                            current_block = 8533724845731836612;
                                                                                                                                        }
                                                                                                                                        match current_block {
                                                                                                                                            17522434821883794170 => {}
                                                                                                                                            _ => {
                                                                                                                                                if !((*data)
                                                                                                                                                    .set
                                                                                                                                                    .str_0[STRING_SSL_RANDOM_FILE as i32 as usize])
                                                                                                                                                    .is_null()
                                                                                                                                                {
                                                                                                                                                    result = curl_easy_setopt(
                                                                                                                                                        doh,
                                                                                                                                                        CURLOPT_RANDOM_FILE,
                                                                                                                                                        (*data)
                                                                                                                                                            .set
                                                                                                                                                            .str_0[STRING_SSL_RANDOM_FILE as i32 as usize],
                                                                                                                                                    );
                                                                                                                                                    if result as u32 != 0
                                                                                                                                                        && result as u32
                                                                                                                                                            != CURLE_NOT_BUILT_IN as i32 as u32
                                                                                                                                                        && result as u32
                                                                                                                                                            != CURLE_UNKNOWN_OPTION as i32 as u32
                                                                                                                                                    {
                                                                                                                                                        current_block = 17522434821883794170;
                                                                                                                                                    } else {
                                                                                                                                                        current_block = 2627991079881472758;
                                                                                                                                                    }
                                                                                                                                                } else {
                                                                                                                                                    current_block = 2627991079881472758;
                                                                                                                                                }
                                                                                                                                                match current_block {
                                                                                                                                                    17522434821883794170 => {}
                                                                                                                                                    _ => {
                                                                                                                                                        if !((*data)
                                                                                                                                                            .set
                                                                                                                                                            .str_0[STRING_SSL_EGDSOCKET as i32 as usize])
                                                                                                                                                            .is_null()
                                                                                                                                                        {
                                                                                                                                                            result = curl_easy_setopt(
                                                                                                                                                                doh,
                                                                                                                                                                CURLOPT_EGDSOCKET,
                                                                                                                                                                (*data)
                                                                                                                                                                    .set
                                                                                                                                                                    .str_0[STRING_SSL_EGDSOCKET as i32 as usize],
                                                                                                                                                            );
                                                                                                                                                            if result as u32 != 0
                                                                                                                                                                && result as u32
                                                                                                                                                                    != CURLE_NOT_BUILT_IN as i32 as u32
                                                                                                                                                                && result as u32
                                                                                                                                                                    != CURLE_UNKNOWN_OPTION as i32 as u32
                                                                                                                                                            {
                                                                                                                                                                current_block = 17522434821883794170;
                                                                                                                                                            } else {
                                                                                                                                                                current_block = 13932507243822716336;
                                                                                                                                                            }
                                                                                                                                                        } else {
                                                                                                                                                            current_block = 13932507243822716336;
                                                                                                                                                        }
                                                                                                                                                        match current_block {
                                                                                                                                                            17522434821883794170 => {}
                                                                                                                                                            _ => {
                                                                                                                                                                if ((*data).set.ssl.fsslctx).is_some() {
                                                                                                                                                                    result = curl_easy_setopt(
                                                                                                                                                                        doh,
                                                                                                                                                                        CURLOPT_SSL_CTX_FUNCTION,
                                                                                                                                                                        (*data).set.ssl.fsslctx,
                                                                                                                                                                    );
                                                                                                                                                                    if result as u32 != 0
                                                                                                                                                                        && result as u32
                                                                                                                                                                            != CURLE_NOT_BUILT_IN as i32 as u32
                                                                                                                                                                        && result as u32
                                                                                                                                                                            != CURLE_UNKNOWN_OPTION as i32 as u32
                                                                                                                                                                    {
                                                                                                                                                                        current_block = 17522434821883794170;
                                                                                                                                                                    } else {
                                                                                                                                                                        current_block = 10256747982273457880;
                                                                                                                                                                    }
                                                                                                                                                                } else {
                                                                                                                                                                    current_block = 10256747982273457880;
                                                                                                                                                                }
                                                                                                                                                                match current_block {
                                                                                                                                                                    17522434821883794170 => {}
                                                                                                                                                                    _ => {
                                                                                                                                                                        if !((*data).set.ssl.fsslctxp).is_null() {
                                                                                                                                                                            result = curl_easy_setopt(
                                                                                                                                                                                doh,
                                                                                                                                                                                CURLOPT_SSL_CTX_DATA,
                                                                                                                                                                                (*data).set.ssl.fsslctxp,
                                                                                                                                                                            );
                                                                                                                                                                            if result as u32 != 0
                                                                                                                                                                                && result as u32
                                                                                                                                                                                    != CURLE_NOT_BUILT_IN as i32 as u32
                                                                                                                                                                                && result as u32
                                                                                                                                                                                    != CURLE_UNKNOWN_OPTION as i32 as u32
                                                                                                                                                                            {
                                                                                                                                                                                current_block = 17522434821883794170;
                                                                                                                                                                            } else {
                                                                                                                                                                                current_block = 15650704408606443395;
                                                                                                                                                                            }
                                                                                                                                                                        } else {
                                                                                                                                                                            current_block = 15650704408606443395;
                                                                                                                                                                        }
                                                                                                                                                                        match current_block {
                                                                                                                                                                            17522434821883794170 => {}
                                                                                                                                                                            _ => {
                                                                                                                                                                                if !((*data)
                                                                                                                                                                                    .set
                                                                                                                                                                                    .str_0[STRING_SSL_EC_CURVES as i32 as usize])
                                                                                                                                                                                    .is_null()
                                                                                                                                                                                {
                                                                                                                                                                                    result = curl_easy_setopt(
                                                                                                                                                                                        doh,
                                                                                                                                                                                        CURLOPT_SSL_EC_CURVES,
                                                                                                                                                                                        (*data)
                                                                                                                                                                                            .set
                                                                                                                                                                                            .str_0[STRING_SSL_EC_CURVES as i32 as usize],
                                                                                                                                                                                    );
                                                                                                                                                                                    if result as u32 != 0
                                                                                                                                                                                        && result as u32
                                                                                                                                                                                            != CURLE_NOT_BUILT_IN as i32 as u32
                                                                                                                                                                                        && result as u32
                                                                                                                                                                                            != CURLE_UNKNOWN_OPTION as i32 as u32
                                                                                                                                                                                    {
                                                                                                                                                                                        current_block = 17522434821883794170;
                                                                                                                                                                                    } else {
                                                                                                                                                                                        current_block = 5151888778912688305;
                                                                                                                                                                                    }
                                                                                                                                                                                } else {
                                                                                                                                                                                    current_block = 5151888778912688305;
                                                                                                                                                                                }
                                                                                                                                                                                match current_block {
                                                                                                                                                                                    17522434821883794170 => {}
                                                                                                                                                                                    _ => {
                                                                                                                                                                                        let mut mask: i64 = ((if ((*data).set.ssl)
                                                                                                                                                                                            .enable_beast() as i32 != 0
                                                                                                                                                                                        {
                                                                                                                                                                                            (1 as i32) << 0 as i32
                                                                                                                                                                                        } else {
                                                                                                                                                                                            0 as i32
                                                                                                                                                                                        })
                                                                                                                                                                                            | (if ((*data).set.ssl).no_revoke() as i32 != 0 {
                                                                                                                                                                                                (1 as i32) << 1 as i32
                                                                                                                                                                                            } else {
                                                                                                                                                                                                0 as i32
                                                                                                                                                                                            })
                                                                                                                                                                                            | (if ((*data).set.ssl).no_partialchain() as i32
                                                                                                                                                                                                != 0
                                                                                                                                                                                            {
                                                                                                                                                                                                (1 as i32) << 2 as i32
                                                                                                                                                                                            } else {
                                                                                                                                                                                                0 as i32
                                                                                                                                                                                            })
                                                                                                                                                                                            | (if ((*data).set.ssl).revoke_best_effort() as i32
                                                                                                                                                                                                != 0
                                                                                                                                                                                            {
                                                                                                                                                                                                (1 as i32) << 3 as i32
                                                                                                                                                                                            } else {
                                                                                                                                                                                                0 as i32
                                                                                                                                                                                            })
                                                                                                                                                                                            | (if ((*data).set.ssl).native_ca_store() as i32
                                                                                                                                                                                                != 0
                                                                                                                                                                                            {
                                                                                                                                                                                                (1 as i32) << 4 as i32
                                                                                                                                                                                            } else {
                                                                                                                                                                                                0 as i32
                                                                                                                                                                                            })
                                                                                                                                                                                            | (if ((*data).set.ssl).auto_client_cert() as i32
                                                                                                                                                                                                != 0
                                                                                                                                                                                            {
                                                                                                                                                                                                (1 as i32) << 5 as i32
                                                                                                                                                                                            } else {
                                                                                                                                                                                                0 as i32
                                                                                                                                                                                            })) as i64;
                                                                                                                                                                                        curl_easy_setopt(doh, CURLOPT_SSL_OPTIONS, mask);
                                                                                                                                                                                        let fresh20 = &mut ((*doh).set.fmultidone);
                                                                                                                                                                                        *fresh20 = Some(
                                                                                                                                                                                            doh_done
                                                                                                                                                                                                as unsafe extern "C" fn(
                                                                                                                                                                                                    *mut Curl_easy,
                                                                                                                                                                                                    CURLcode,
                                                                                                                                                                                                ) -> i32,
                                                                                                                                                                                        );
                                                                                                                                                                                        let fresh21 = &mut ((*doh).set.dohfor);
                                                                                                                                                                                        *fresh21 = data;
                                                                                                                                                                                        let fresh22 = &mut ((*p).easy);
                                                                                                                                                                                        *fresh22 = doh;
                                                                                                                                                                                        if !(curl_multi_add_handle(multi, doh) as u64 != 0) {
                                                                                                                                                                                            Curl_cfree
                                                                                                                                                                                                .expect(
                                                                                                                                                                                                    "non-null function pointer",
                                                                                                                                                                                                )(nurl as *mut libc::c_void);
                                                                                                                                                                                            return CURLE_OK;
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
        _ => {}
    }
    Curl_cfree.expect("non-null function pointer")(nurl as *mut libc::c_void);
    Curl_close(&mut doh);
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_doh(
    mut data: *mut Curl_easy,
    mut hostname: *const i8,
    mut port: i32,
    mut waitp: *mut i32,
) -> *mut Curl_addrinfo {
    let mut current_block: u64;
    let mut result: CURLcode = CURLE_OK;
    let mut slot: i32 = 0;
    let mut dohp: *mut dohdata = 0 as *mut dohdata;
    let mut conn: *mut connectdata = (*data).conn;
    *waitp = 1 as i32;
    let fresh23 = &mut ((*data).req.doh);
    *fresh23 = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<dohdata>() as u64, 1 as i32 as size_t)
        as *mut dohdata;
    dohp = *fresh23;
    if dohp.is_null() {
        return 0 as *mut Curl_addrinfo;
    }
    let fresh24 = &mut ((*conn).bits);
    (*fresh24).set_doh(1 as i32 as bit);
    let fresh25 = &mut ((*dohp).host);
    *fresh25 = hostname;
    (*dohp).port = port;
    let fresh26 = &mut ((*dohp).headers);
    *fresh26 = curl_slist_append(
        0 as *mut curl_slist,
        b"Content-Type: application/dns-message\0" as *const u8 as *const i8,
    );
    if !((*dohp).headers).is_null() {
        result = dohprobe(
            data,
            &mut *((*dohp).probe)
                .as_mut_ptr()
                .offset(DOH_PROBE_SLOT_IPADDR_V4 as i32 as isize),
            DNS_TYPE_A,
            hostname,
            (*data).set.str_0[STRING_DOH as i32 as usize],
            (*data).multi,
            (*dohp).headers,
        );
        if !(result as u64 != 0) {
            let fresh27 = &mut ((*dohp).pending);
            *fresh27 = (*fresh27).wrapping_add(1);
            if Curl_ipv6works(data) {
                result = dohprobe(
                    data,
                    &mut *((*dohp).probe)
                        .as_mut_ptr()
                        .offset(DOH_PROBE_SLOT_IPADDR_V6 as i32 as isize),
                    DNS_TYPE_AAAA,
                    hostname,
                    (*data).set.str_0[STRING_DOH as i32 as usize],
                    (*data).multi,
                    (*dohp).headers,
                );
                if result as u64 != 0 {
                    current_block = 17163311106766648981;
                } else {
                    let fresh28 = &mut ((*dohp).pending);
                    *fresh28 = (*fresh28).wrapping_add(1);
                    current_block = 14401909646449704462;
                }
            } else {
                current_block = 14401909646449704462;
            }
            match current_block {
                17163311106766648981 => {}
                _ => return 0 as *mut Curl_addrinfo,
            }
        }
    }
    curl_slist_free_all((*dohp).headers);
    let fresh29 = &mut ((*(*data).req.doh).headers);
    *fresh29 = 0 as *mut curl_slist;
    slot = 0 as i32;
    while slot < DOH_PROBE_SLOTS as i32 {
        Curl_close(&mut (*((*dohp).probe).as_mut_ptr().offset(slot as isize)).easy);
        slot += 1;
    }
    Curl_cfree.expect("non-null function pointer")((*data).req.doh as *mut libc::c_void);
    let fresh30 = &mut ((*data).req.doh);
    *fresh30 = 0 as *mut dohdata;
    return 0 as *mut Curl_addrinfo;
}
unsafe extern "C" fn skipqname(
    mut doh: *const u8,
    mut dohlen: size_t,
    mut indexp: *mut u32,
) -> DOHcode {
    let mut length: u8 = 0;
    loop {
        if dohlen
            < (*indexp).wrapping_add(1 as i32 as u32) as u64
        {
            return DOH_DNS_OUT_OF_RANGE;
        }
        length = *doh.offset(*indexp as isize);
        if length as i32 & 0xc0 as i32 == 0xc0 as i32 {
            if dohlen
                < (*indexp).wrapping_add(2 as i32 as u32)
                    as u64
            {
                return DOH_DNS_OUT_OF_RANGE;
            }
            *indexp = (*indexp).wrapping_add(2 as i32 as u32);
            break;
        } else {
            if length as i32 & 0xc0 as i32 != 0 {
                return DOH_DNS_BAD_LABEL;
            }
            if dohlen
                < (*indexp)
                    .wrapping_add(1 as i32 as u32)
                    .wrapping_add(length as u32) as u64
            {
                return DOH_DNS_OUT_OF_RANGE;
            }
            *indexp = (*indexp)
                .wrapping_add(
                    (1 as i32 + length as i32) as u32,
                );
            if !(length != 0) {
                break;
            }
        }
    }
    return DOH_OK;
}
unsafe extern "C" fn get16bit(
    mut doh: *const u8,
    mut index: i32,
) -> u16 {
    return ((*doh.offset(index as isize) as i32) << 8 as i32
        | *doh.offset((index + 1 as i32) as isize) as i32)
        as u16;
}
unsafe extern "C" fn get32bit(
    mut doh: *const u8,
    mut index: i32,
) -> u32 {
    doh = doh.offset(index as isize);
    return (*doh.offset(0 as i32 as isize) as u32) << 24 as i32
        | ((*doh.offset(1 as i32 as isize) as i32) << 16 as i32)
            as u32
        | ((*doh.offset(2 as i32 as isize) as i32) << 8 as i32)
            as u32 | *doh.offset(3 as i32 as isize) as u32;
}
unsafe extern "C" fn store_a(
    mut doh: *const u8,
    mut index: i32,
    mut d: *mut dohentry,
) -> DOHcode {
    if (*d).numaddr < 24 as i32 {
        let mut a: *mut dohaddr = &mut *((*d).addr)
            .as_mut_ptr()
            .offset((*d).numaddr as isize) as *mut dohaddr;
        (*a).type_0 = DNS_TYPE_A as i32;
        memcpy(
            &mut (*a).ip.v4 as *mut [u8; 4] as *mut libc::c_void,
            &*doh.offset(index as isize) as *const u8 as *const libc::c_void,
            4 as i32 as u64,
        );
        let fresh31 = &mut ((*d).numaddr);
        *fresh31 += 1;
    }
    return DOH_OK;
}
unsafe extern "C" fn store_aaaa(
    mut doh: *const u8,
    mut index: i32,
    mut d: *mut dohentry,
) -> DOHcode {
    if (*d).numaddr < 24 as i32 {
        let mut a: *mut dohaddr = &mut *((*d).addr)
            .as_mut_ptr()
            .offset((*d).numaddr as isize) as *mut dohaddr;
        (*a).type_0 = DNS_TYPE_AAAA as i32;
        memcpy(
            &mut (*a).ip.v6 as *mut [u8; 16] as *mut libc::c_void,
            &*doh.offset(index as isize) as *const u8 as *const libc::c_void,
            16 as i32 as u64,
        );
        let fresh32 = &mut ((*d).numaddr);
        *fresh32 += 1;
    }
    return DOH_OK;
}
unsafe extern "C" fn store_cname(
    mut doh: *const u8,
    mut dohlen: size_t,
    mut index: u32,
    mut d: *mut dohentry,
) -> DOHcode {
    let mut c: *mut dynbuf = 0 as *mut dynbuf;
    let mut loop_0: u32 = 128 as i32 as u32;
    let mut length: u8 = 0;
    if (*d).numcname == 4 as i32 {
        return DOH_OK;
    }
    let fresh33 = &mut ((*d).numcname);
    let fresh34 = *fresh33;
    *fresh33 = *fresh33 + 1;
    c = &mut *((*d).cname).as_mut_ptr().offset(fresh34 as isize) as *mut dynbuf;
    loop {
        if index as u64 >= dohlen {
            return DOH_DNS_OUT_OF_RANGE;
        }
        length = *doh.offset(index as isize);
        if length as i32 & 0xc0 as i32 == 0xc0 as i32 {
            let mut newpos: i32 = 0;
            if index.wrapping_add(1 as i32 as u32) as u64
                >= dohlen
            {
                return DOH_DNS_OUT_OF_RANGE;
            }
            newpos = (length as i32 & 0x3f as i32) << 8 as i32
                | *doh
                    .offset(
                        index.wrapping_add(1 as i32 as u32) as isize,
                    ) as i32;
            index = newpos as u32;
        } else {
            if length as i32 & 0xc0 as i32 != 0 {
                return DOH_DNS_BAD_LABEL
            } else {
                index = index.wrapping_add(1);
            }
            if length != 0 {
                if Curl_dyn_len(c) != 0 {
                    if Curl_dyn_add(c, b".\0" as *const u8 as *const i8) as u64
                        != 0
                    {
                        return DOH_OUT_OF_MEM;
                    }
                }
                if index.wrapping_add(length as u32) as u64 > dohlen {
                    return DOH_DNS_BAD_LABEL;
                }
                if Curl_dyn_addn(
                    c,
                    &*doh.offset(index as isize) as *const u8
                        as *const libc::c_void,
                    length as size_t,
                ) as u64 != 0
                {
                    return DOH_OUT_OF_MEM;
                }
                index = index.wrapping_add(length as u32);
            }
        }
        if !(length as i32 != 0
            && {
                loop_0 = loop_0.wrapping_sub(1);
                loop_0 != 0
            })
        {
            break;
        }
    }
    if loop_0 == 0 {
        return DOH_DNS_LABEL_LOOP;
    }
    return DOH_OK;
}
unsafe extern "C" fn rdata(
    mut doh: *const u8,
    mut dohlen: size_t,
    mut rdlength: u16,
    mut type_0: u16,
    mut index: i32,
    mut d: *mut dohentry,
) -> DOHcode {
    let mut rc: DOHcode = DOH_OK;
    match type_0 as i32 {
        1 => {
            if rdlength as i32 != 4 as i32 {
                return DOH_DNS_RDATA_LEN;
            }
            rc = store_a(doh, index, d);
            if rc as u64 != 0 {
                return rc;
            }
        }
        28 => {
            if rdlength as i32 != 16 as i32 {
                return DOH_DNS_RDATA_LEN;
            }
            rc = store_aaaa(doh, index, d);
            if rc as u64 != 0 {
                return rc;
            }
        }
        5 => {
            rc = store_cname(doh, dohlen, index as u32, d);
            if rc as u64 != 0 {
                return rc;
            }
        }
        39 => {}
        _ => {}
    }
    return DOH_OK;
}
unsafe extern "C" fn de_init(mut de: *mut dohentry) {
    let mut i: i32 = 0;
    memset(
        de as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<dohentry>() as u64,
    );
    (*de).ttl = 2147483647 as i32 as u32;
    i = 0 as i32;
    while i < 4 as i32 {
        Curl_dyn_init(
            &mut *((*de).cname).as_mut_ptr().offset(i as isize),
            256 as i32 as size_t,
        );
        i += 1;
    }
}
unsafe extern "C" fn doh_decode(
    mut doh: *const u8,
    mut dohlen: size_t,
    mut dnstype: DNStype,
    mut d: *mut dohentry,
) -> DOHcode {
    let mut rcode: u8 = 0;
    let mut qdcount: u16 = 0;
    let mut ancount: u16 = 0;
    let mut type_0: u16 = 0 as i32 as u16;
    let mut rdlength: u16 = 0;
    let mut nscount: u16 = 0;
    let mut arcount: u16 = 0;
    let mut index: u32 = 12 as i32 as u32;
    let mut rc: DOHcode = DOH_OK;
    if dohlen < 12 as i32 as u64 {
        return DOH_TOO_SMALL_BUFFER;
    }
    if doh.is_null() || *doh.offset(0 as i32 as isize) as i32 != 0
        || *doh.offset(1 as i32 as isize) as i32 != 0
    {
        return DOH_DNS_BAD_ID;
    }
    rcode = (*doh.offset(3 as i32 as isize) as i32 & 0xf as i32)
        as u8;
    if rcode != 0 {
        return DOH_DNS_BAD_RCODE;
    }
    qdcount = get16bit(doh, 4 as i32);
    while qdcount != 0 {
        rc = skipqname(doh, dohlen, &mut index);
        if rc as u64 != 0 {
            return rc;
        }
        if dohlen < index.wrapping_add(4 as i32 as u32) as u64
        {
            return DOH_DNS_OUT_OF_RANGE;
        }
        index = index.wrapping_add(4 as i32 as u32);
        qdcount = qdcount.wrapping_sub(1);
    }
    ancount = get16bit(doh, 6 as i32);
    while ancount != 0 {
        let mut class: u16 = 0;
        let mut ttl: u32 = 0;
        rc = skipqname(doh, dohlen, &mut index);
        if rc as u64 != 0 {
            return rc;
        }
        if dohlen < index.wrapping_add(2 as i32 as u32) as u64
        {
            return DOH_DNS_OUT_OF_RANGE;
        }
        type_0 = get16bit(doh, index as i32);
        if type_0 as i32 != DNS_TYPE_CNAME as i32
            && type_0 as i32 != DNS_TYPE_DNAME as i32
            && type_0 as u32 != dnstype as u32
        {
            return DOH_DNS_UNEXPECTED_TYPE;
        }
        index = index.wrapping_add(2 as i32 as u32);
        if dohlen < index.wrapping_add(2 as i32 as u32) as u64
        {
            return DOH_DNS_OUT_OF_RANGE;
        }
        class = get16bit(doh, index as i32);
        if 0x1 as i32 != class as i32 {
            return DOH_DNS_UNEXPECTED_CLASS;
        }
        index = index.wrapping_add(2 as i32 as u32);
        if dohlen < index.wrapping_add(4 as i32 as u32) as u64
        {
            return DOH_DNS_OUT_OF_RANGE;
        }
        ttl = get32bit(doh, index as i32);
        if ttl < (*d).ttl {
            (*d).ttl = ttl;
        }
        index = index.wrapping_add(4 as i32 as u32);
        if dohlen < index.wrapping_add(2 as i32 as u32) as u64
        {
            return DOH_DNS_OUT_OF_RANGE;
        }
        rdlength = get16bit(doh, index as i32);
        index = index.wrapping_add(2 as i32 as u32);
        if dohlen < index.wrapping_add(rdlength as u32) as u64 {
            return DOH_DNS_OUT_OF_RANGE;
        }
        rc = rdata(doh, dohlen, rdlength, type_0, index as i32, d);
        if rc as u64 != 0 {
            return rc;
        }
        index = index.wrapping_add(rdlength as u32);
        ancount = ancount.wrapping_sub(1);
    }
    nscount = get16bit(doh, 8 as i32);
    while nscount != 0 {
        rc = skipqname(doh, dohlen, &mut index);
        if rc as u64 != 0 {
            return rc;
        }
        if dohlen < index.wrapping_add(8 as i32 as u32) as u64
        {
            return DOH_DNS_OUT_OF_RANGE;
        }
        index = index
            .wrapping_add(
                (2 as i32 + 2 as i32 + 4 as i32) as u32,
            );
        if dohlen < index.wrapping_add(2 as i32 as u32) as u64
        {
            return DOH_DNS_OUT_OF_RANGE;
        }
        rdlength = get16bit(doh, index as i32);
        index = index.wrapping_add(2 as i32 as u32);
        if dohlen < index.wrapping_add(rdlength as u32) as u64 {
            return DOH_DNS_OUT_OF_RANGE;
        }
        index = index.wrapping_add(rdlength as u32);
        nscount = nscount.wrapping_sub(1);
    }
    arcount = get16bit(doh, 10 as i32);
    while arcount != 0 {
        rc = skipqname(doh, dohlen, &mut index);
        if rc as u64 != 0 {
            return rc;
        }
        if dohlen < index.wrapping_add(8 as i32 as u32) as u64
        {
            return DOH_DNS_OUT_OF_RANGE;
        }
        index = index
            .wrapping_add(
                (2 as i32 + 2 as i32 + 4 as i32) as u32,
            );
        if dohlen < index.wrapping_add(2 as i32 as u32) as u64
        {
            return DOH_DNS_OUT_OF_RANGE;
        }
        rdlength = get16bit(doh, index as i32);
        index = index.wrapping_add(2 as i32 as u32);
        if dohlen < index.wrapping_add(rdlength as u32) as u64 {
            return DOH_DNS_OUT_OF_RANGE;
        }
        index = index.wrapping_add(rdlength as u32);
        arcount = arcount.wrapping_sub(1);
    }
    if index as u64 != dohlen {
        return DOH_DNS_MALFORMAT;
    }
    if type_0 as i32 != DNS_TYPE_NS as i32 && (*d).numcname == 0
        && (*d).numaddr == 0
    {
        return DOH_NO_CONTENT;
    }
    return DOH_OK;
}
unsafe extern "C" fn showdoh(mut data: *mut Curl_easy, mut d: *const dohentry) {
    let mut i: i32 = 0;
    Curl_infof(data, b"TTL: %u seconds\0" as *const u8 as *const i8, (*d).ttl);
    i = 0 as i32;
    while i < (*d).numaddr {
        let mut a: *const dohaddr = &*((*d).addr).as_ptr().offset(i as isize)
            as *const dohaddr;
        if (*a).type_0 == DNS_TYPE_A as i32 {
            Curl_infof(
                data,
                b"DoH A: %u.%u.%u.%u\0" as *const u8 as *const i8,
                (*a).ip.v4[0 as i32 as usize] as i32,
                (*a).ip.v4[1 as i32 as usize] as i32,
                (*a).ip.v4[2 as i32 as usize] as i32,
                (*a).ip.v4[3 as i32 as usize] as i32,
            );
        } else if (*a).type_0 == DNS_TYPE_AAAA as i32 {
            let mut j: i32 = 0;
            let mut buffer: [i8; 128] = [0; 128];
            let mut ptr: *mut i8 = 0 as *mut i8;
            let mut len: size_t = 0;
            curl_msnprintf(
                buffer.as_mut_ptr(),
                128 as i32 as size_t,
                b"DoH AAAA: \0" as *const u8 as *const i8,
            );
            ptr = &mut *buffer.as_mut_ptr().offset(10 as i32 as isize)
                as *mut i8;
            len = 118 as i32 as size_t;
            j = 0 as i32;
            while j < 16 as i32 {
                let mut l: size_t = 0;
                curl_msnprintf(
                    ptr,
                    len,
                    b"%s%02x%02x\0" as *const u8 as *const i8,
                    if j != 0 {
                        b":\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    (*d).addr[i as usize].ip.v6[j as usize] as i32,
                    (*d).addr[i as usize].ip.v6[(j + 1 as i32) as usize]
                        as i32,
                );
                l = strlen(ptr);
                len = (len as u64).wrapping_sub(l) as size_t as size_t;
                ptr = ptr.offset(l as isize);
                j += 2 as i32;
            }
            Curl_infof(
                data,
                b"%s\0" as *const u8 as *const i8,
                buffer.as_mut_ptr(),
            );
        }
        i += 1;
    }
    i = 0 as i32;
    while i < (*d).numcname {
        Curl_infof(
            data,
            b"CNAME: %s\0" as *const u8 as *const i8,
            Curl_dyn_ptr(&*((*d).cname).as_ptr().offset(i as isize)),
        );
        i += 1;
    }
}
unsafe extern "C" fn doh2ai(
    mut de: *const dohentry,
    mut hostname: *const i8,
    mut port: i32,
) -> *mut Curl_addrinfo {
    let mut ai: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut prevai: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut firstai: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut addr: *mut sockaddr_in = 0 as *mut sockaddr_in;
    let mut addr6: *mut sockaddr_in6 = 0 as *mut sockaddr_in6;
    let mut result: CURLcode = CURLE_OK;
    let mut i: i32 = 0;
    let mut hostlen: size_t = (strlen(hostname))
        .wrapping_add(1 as i32 as u64);
    if de.is_null() {
        return 0 as *mut Curl_addrinfo;
    }
    i = 0 as i32;
    while i < (*de).numaddr {
        let mut ss_size: size_t = 0;
        let mut addrtype: sa_family_t = 0;
        if (*de).addr[i as usize].type_0 == DNS_TYPE_AAAA as i32 {
            ss_size = ::std::mem::size_of::<sockaddr_in6>() as u64;
            addrtype = 10 as i32 as sa_family_t;
        } else {
            ss_size = ::std::mem::size_of::<sockaddr_in>() as u64;
            addrtype = 2 as i32 as sa_family_t;
        }
        ai = Curl_ccalloc
            .expect(
                "non-null function pointer",
            )(
            1 as i32 as size_t,
            (::std::mem::size_of::<Curl_addrinfo>() as u64)
                .wrapping_add(ss_size)
                .wrapping_add(hostlen),
        ) as *mut Curl_addrinfo;
        if ai.is_null() {
            result = CURLE_OUT_OF_MEMORY;
            break;
        } else {
            let fresh35 = &mut ((*ai).ai_addr);
            *fresh35 = (ai as *mut i8)
                .offset(::std::mem::size_of::<Curl_addrinfo>() as u64 as isize)
                as *mut libc::c_void as *mut sockaddr;
            let fresh36 = &mut ((*ai).ai_canonname);
            *fresh36 = ((*ai).ai_addr as *mut i8).offset(ss_size as isize)
                as *mut libc::c_void as *mut i8;
            memcpy(
                (*ai).ai_canonname as *mut libc::c_void,
                hostname as *const libc::c_void,
                hostlen,
            );
            if firstai.is_null() {
                firstai = ai;
            }
            if !prevai.is_null() {
                let fresh37 = &mut ((*prevai).ai_next);
                *fresh37 = ai;
            }
            (*ai).ai_family = addrtype as i32;
            (*ai).ai_socktype = SOCK_STREAM as i32;
            (*ai).ai_addrlen = ss_size as curl_socklen_t;
            match (*ai).ai_family {
                2 => {
                    addr = (*ai).ai_addr as *mut libc::c_void as *mut sockaddr_in;
                    memcpy(
                        &mut (*addr).sin_addr as *mut in_addr as *mut libc::c_void,
                        &(*((*de).addr).as_ptr().offset(i as isize)).ip.v4
                            as *const [u8; 4] as *const libc::c_void,
                        ::std::mem::size_of::<in_addr>() as u64,
                    );
                    (*addr).sin_family = addrtype;
                    (*addr).sin_port = __bswap_16(port as u16);
                }
                10 => {
                    addr6 = (*ai).ai_addr as *mut libc::c_void as *mut sockaddr_in6;
                    memcpy(
                        &mut (*addr6).sin6_addr as *mut in6_addr as *mut libc::c_void,
                        &(*((*de).addr).as_ptr().offset(i as isize)).ip.v6
                            as *const [u8; 16] as *const libc::c_void,
                        ::std::mem::size_of::<in6_addr>() as u64,
                    );
                    (*addr6).sin6_family = addrtype;
                    (*addr6).sin6_port = __bswap_16(port as u16);
                }
                _ => {}
            }
            prevai = ai;
            i += 1;
        }
    }
    if result as u64 != 0 {
        Curl_freeaddrinfo(firstai);
        firstai = 0 as *mut Curl_addrinfo;
    }
    return firstai;
}
 extern "C" fn type2name(mut dnstype: DNStype) -> *const i8 {
    return if dnstype as u32 == DNS_TYPE_A as i32 as u32 {
        b"A\0" as *const u8 as *const i8
    } else {
        b"AAAA\0" as *const u8 as *const i8
    };
}
unsafe extern "C" fn de_cleanup(mut d: *mut dohentry) {
    let mut i: i32 = 0 as i32;
    i = 0 as i32;
    while i < (*d).numcname {
        Curl_dyn_free(&mut *((*d).cname).as_mut_ptr().offset(i as isize));
        i += 1;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_doh_is_resolved(
    mut data: *mut Curl_easy,
    mut dnsp: *mut *mut Curl_dns_entry,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut dohp: *mut dohdata = (*data).req.doh;
    *dnsp = 0 as *mut Curl_dns_entry;
    if dohp.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if ((*dohp).probe[DOH_PROBE_SLOT_IPADDR_V4 as i32 as usize].easy).is_null()
        && ((*dohp).probe[DOH_PROBE_SLOT_IPADDR_V6 as i32 as usize].easy)
            .is_null()
    {
        Curl_failf(
            data,
            b"Could not DoH-resolve: %s\0" as *const u8 as *const i8,
            (*data).state.async_0.hostname,
        );
        return (if ((*(*data).conn).bits).proxy() as i32 != 0 {
            CURLE_COULDNT_RESOLVE_PROXY as i32
        } else {
            CURLE_COULDNT_RESOLVE_HOST as i32
        }) as CURLcode;
    } else {
        if (*dohp).pending == 0 {
            let mut rc: [DOHcode; 2] = [DOH_OK, DOH_OK];
            let mut de: dohentry = dohentry {
                cname: [dynbuf {
                    bufr: 0 as *mut i8,
                    leng: 0,
                    allc: 0,
                    toobig: 0,
                }; 4],
                addr: [dohaddr {
                    type_0: 0,
                    ip: C2RustUnnamed_8 { v4: [0; 4] },
                }; 24],
                numaddr: 0,
                ttl: 0,
                numcname: 0,
            };
            let mut slot: i32 = 0;
            slot = 0 as i32;
            while slot < DOH_PROBE_SLOTS as i32 {
                curl_multi_remove_handle(
                    (*data).multi,
                    (*dohp).probe[slot as usize].easy,
                );
                Curl_close(
                    &mut (*((*dohp).probe).as_mut_ptr().offset(slot as isize)).easy,
                );
                slot += 1;
            }
            de_init(&mut de);
            slot = 0 as i32;
            while slot < DOH_PROBE_SLOTS as i32 {
                let mut p: *mut dnsprobe = &mut *((*dohp).probe)
                    .as_mut_ptr()
                    .offset(slot as isize) as *mut dnsprobe;
                if !((*p).dnstype == 0) {
                    rc[slot
                        as usize] = doh_decode(
                        Curl_dyn_uptr(&mut (*p).serverdoh),
                        Curl_dyn_len(&mut (*p).serverdoh),
                        (*p).dnstype as DNStype,
                        &mut de,
                    );
                    Curl_dyn_free(&mut (*p).serverdoh);
                    if rc[slot as usize] as u64 != 0 {
                        Curl_infof(
                            data,
                            b"DoH: %s type %s for %s\0" as *const u8
                                as *const i8,
                            doh_strerror(rc[slot as usize]),
                            type2name((*p).dnstype as DNStype),
                            (*dohp).host,
                        );
                    }
                }
                slot += 1;
            }
            result = CURLE_COULDNT_RESOLVE_HOST;
            if rc[DOH_PROBE_SLOT_IPADDR_V4 as i32 as usize] as u64 == 0
                || rc[DOH_PROBE_SLOT_IPADDR_V6 as i32 as usize] as u64 == 0
            {
                let mut dns: *mut Curl_dns_entry = 0 as *mut Curl_dns_entry;
                let mut ai: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
                Curl_infof(
                    data,
                    b"DoH Host name: %s\0" as *const u8 as *const i8,
                    (*dohp).host,
                );
                showdoh(data, &mut de);
                ai = doh2ai(&mut de, (*dohp).host, (*dohp).port);
                if ai.is_null() {
                    de_cleanup(&mut de);
                    return CURLE_OUT_OF_MEMORY;
                }
                if !((*data).share).is_null() {
                    Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE);
                }
                dns = Curl_cache_addr(data, ai, (*dohp).host, (*dohp).port);
                if !((*data).share).is_null() {
                    Curl_share_unlock(data, CURL_LOCK_DATA_DNS);
                }
                if dns.is_null() {
                    Curl_freeaddrinfo(ai);
                } else {
                    let fresh38 = &mut ((*data).state.async_0.dns);
                    *fresh38 = dns;
                    *dnsp = dns;
                    result = CURLE_OK;
                }
            }
            de_cleanup(&mut de);
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).req.doh as *mut libc::c_void);
            let fresh39 = &mut ((*data).req.doh);
            *fresh39 = 0 as *mut dohdata;
            return result;
        }
    }
    return CURLE_OK;
}
