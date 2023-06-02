use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn socket(
        __domain: i32,
        __type: i32,
        __protocol: i32,
    ) -> i32;
    fn bind(__fd: i32, __addr: *const sockaddr, __len: socklen_t) -> i32;
    fn getsockname(
        __fd: i32,
        __addr: *mut sockaddr,
        __len: *mut socklen_t,
    ) -> i32;
    fn connect(
        __fd: i32,
        __addr: *const sockaddr,
        __len: socklen_t,
    ) -> i32;
    fn getpeername(
        __fd: i32,
        __addr: *mut sockaddr,
        __len: *mut socklen_t,
    ) -> i32;
    fn recv(
        __fd: i32,
        __buf: *mut libc::c_void,
        __n: size_t,
        __flags: i32,
    ) -> ssize_t;
    fn getsockopt(
        __fd: i32,
        __level: i32,
        __optname: i32,
        __optval: *mut libc::c_void,
        __optlen: *mut socklen_t,
    ) -> i32;
    fn setsockopt(
        __fd: i32,
        __level: i32,
        __optname: i32,
        __optval: *const libc::c_void,
        __optlen: socklen_t,
    ) -> i32;
    fn close(__fd: i32) -> i32;
    fn __errno_location() -> *mut i32;
    fn strtol(
        _: *const i8,
        _: *mut *mut i8,
        _: i32,
    ) -> i64;
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
    fn strncmp(
        _: *const i8,
        _: *const i8,
        _: u64,
    ) -> i32;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn inet_pton(
        __af: i32,
        __cp: *const i8,
        __buf: *mut libc::c_void,
    ) -> i32;
    fn inet_ntop(
        __af: i32,
        __cp: *const libc::c_void,
        __buf: *mut i8,
        __len: socklen_t,
    ) -> *const i8;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::asyn_thread::Curl_resolver_wait_resolv;
pub use crate::src::lib::conncache::Curl_conncache_foreach;
pub use crate::src::lib::hostip::Curl_num_addresses;
pub use crate::src::lib::hostip::Curl_printable_address;
pub use crate::src::lib::hostip::Curl_resolv;
pub use crate::src::lib::hostip::Curl_resolv_unlock;
pub use crate::src::lib::if2ip::Curl_if2ip;
pub use crate::src::lib::if2ip::Curl_ipv6_scope;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::multi::Curl_expire;
pub use crate::src::lib::multi::Curl_multi_closed;
pub use crate::src::lib::multi::Curl_set_in_callback;
pub use crate::src::lib::nonblock::curlx_nonblock;
pub use crate::src::lib::progress::Curl_pgrsTime;
pub use crate::src::lib::select::Curl_socket_check;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::sendf::Curl_recv_has_postponed_data;
pub use crate::src::lib::socks::Curl_SOCKS4;
pub use crate::src::lib::socks::Curl_SOCKS5;
pub use crate::src::lib::strerror::Curl_strerror;
pub use crate::src::lib::timeval::Curl_now;
pub use crate::src::lib::timeval::Curl_timediff;
pub use crate::src::lib::url::Curl_verboseconnect;
pub use crate::src::lib::vtls::vtls::Curl_ssl_check_cxn;
pub use crate::src::lib::vtls::vtls::Curl_ssl_data_pending;
pub use crate::src::lib::warnless::curlx_sltosi;
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
pub type __uint8_t = crate::src::lib::http2::__uint8_t;
pub type __uint16_t = u16;
pub type __int32_t = crate::src::lib::http2::__int32_t;
pub type __uint32_t = crate::src::lib::http2::__uint32_t;
pub type __off_t = crate::src::lib::http2::__off_t;
pub type __off64_t = crate::src::lib::http2::__off64_t;
pub type __pid_t = crate::src::lib::http2::__pid_t;
pub type __time_t = crate::src::lib::http2::__time_t;
pub type __ssize_t = crate::src::lib::http2::__ssize_t;
pub type __socklen_t = crate::src::lib::http2::__socklen_t;
pub type pid_t = crate::src::lib::http2::pid_t;
pub type ssize_t = crate::src::lib::http2::ssize_t;
pub type time_t = crate::src::lib::http2::time_t;
pub type size_t = crate::src::lib::http2::size_t;
pub type int32_t = crate::src::lib::http2::int32_t;
pub type socklen_t = crate::src::lib::http2::socklen_t;
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
pub type sa_family_t = crate::src::lib::http2::sa_family_t;
// #[derive(Copy, Clone)]

pub type sockaddr = crate::src::lib::http2::sockaddr;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_padding: [i8; 118],
    pub __ss_align: u64,
}
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
pub type curl_socklen_t = crate::src::lib::http2::curl_socklen_t;
pub type curl_off_t = crate::src::lib::http2::curl_off_t;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = crate::src::lib::http2::_IO_lock_t;
pub type FILE = crate::src::lib::http2::FILE;
// #[derive(Copy, Clone)]

pub type Curl_easy = crate::src::lib::http2::Curl_easy;
// #[derive(Copy, Clone)]

pub type curl_tlssessioninfo = crate::src::lib::http2::curl_tlssessioninfo;
pub type curl_sslbackend = crate::src::lib::http2::curl_sslbackend;
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
pub type bit = crate::src::lib::http2::bit;
pub type CURLproxycode = crate::src::lib::http2::CURLproxycode;
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
pub type wildcard_dtor = crate::src::lib::http2::wildcard_dtor;
// #[derive(Copy, Clone)]

pub type Curl_llist = crate::src::lib::http2::Curl_llist;
pub type Curl_llist_dtor = crate::src::lib::http2::Curl_llist_dtor;
// #[derive(Copy, Clone)]

pub type Curl_llist_element = crate::src::lib::http2::Curl_llist_element;
pub type wildcard_states = crate::src::lib::http2::wildcard_states;
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
pub type trailers_state = crate::src::lib::http2::trailers_state;
pub const TRAILERS_DONE: trailers_state = 3;
pub const TRAILERS_SENDING: trailers_state = 2;
pub const TRAILERS_INITIALIZED: trailers_state = 1;
pub const TRAILERS_NONE: trailers_state = 0;
// #[derive(Copy, Clone)]

pub type dynbuf = crate::src::lib::http2::dynbuf;
pub type Curl_HttpReq = crate::src::lib::http2::Curl_HttpReq;
pub const HTTPREQ_HEAD: Curl_HttpReq = 5;
pub const HTTPREQ_PUT: Curl_HttpReq = 4;
pub const HTTPREQ_POST_MIME: Curl_HttpReq = 3;
pub const HTTPREQ_POST_FORM: Curl_HttpReq = 2;
pub const HTTPREQ_POST: Curl_HttpReq = 1;
pub const HTTPREQ_GET: Curl_HttpReq = 0;
// #[derive(Copy, Clone)]

pub type urlpieces = crate::src::lib::http2::urlpieces;
pub type CURLU = crate::src::lib::http2::CURLU;
pub type curl_read_callback = crate::src::lib::http2::curl_read_callback;
// #[derive(Copy, Clone)]

pub type time_node = crate::src::lib::http2::time_node;
pub type expire_id = crate::src::lib::http2::expire_id;
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
pub type Curl_hash_dtor = crate::src::lib::http2::Curl_hash_dtor;
pub type comp_function = crate::src::lib::http2::comp_function;
pub type hash_function = crate::src::lib::http2::hash_function;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type Progress = crate::src::lib::http2::Progress;
pub type timediff_t = crate::src::lib::http2::timediff_t;
// #[derive(Copy, Clone)]

pub type CookieInfo = crate::src::lib::http2::CookieInfo;
// #[derive(Copy, Clone)]

pub type Cookie = crate::src::lib::http2::Cookie;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type UserDefined = crate::src::lib::http2::UserDefined;
pub type curl_trailer_callback = crate::src::lib::http2::curl_trailer_callback;
pub type multidone_func = crate::src::lib::http2::multidone_func;
pub type CURLcode = crate::src::lib::http2::CURLcode;
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
pub type curl_resolver_start_callback = crate::src::lib::http2::curl_resolver_start_callback;
// #[derive(Copy, Clone)]

pub type Curl_http2_dep = crate::src::lib::http2::Curl_http2_dep;
pub type curl_fnmatch_callback = crate::src::lib::http2::curl_fnmatch_callback;
pub type curl_chunk_end_callback = crate::src::lib::http2::curl_chunk_end_callback;
pub type curl_chunk_bgn_callback = crate::src::lib::http2::curl_chunk_bgn_callback;
pub type Curl_RtspReq = crate::src::lib::http2::Curl_RtspReq;
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
pub type curl_usessl = crate::src::lib::http2::curl_usessl;
pub const CURLUSESSL_LAST: curl_usessl = 4;
pub const CURLUSESSL_ALL: curl_usessl = 3;
pub const CURLUSESSL_CONTROL: curl_usessl = 2;
pub const CURLUSESSL_TRY: curl_usessl = 1;
pub const CURLUSESSL_NONE: curl_usessl = 0;
pub type CURL_NETRC_OPTION = crate::src::lib::http2::CURL_NETRC_OPTION;
pub const CURL_NETRC_LAST: CURL_NETRC_OPTION = 3;
pub const CURL_NETRC_REQUIRED: CURL_NETRC_OPTION = 2;
pub const CURL_NETRC_OPTIONAL: CURL_NETRC_OPTION = 1;
pub const CURL_NETRC_IGNORED: CURL_NETRC_OPTION = 0;
pub type curl_sshkeycallback = crate::src::lib::http2::curl_sshkeycallback;
pub type curl_khmatch = crate::src::lib::http2::curl_khmatch;
pub const CURLKHMATCH_LAST: curl_khmatch = 3;
pub const CURLKHMATCH_MISSING: curl_khmatch = 2;
pub const CURLKHMATCH_MISMATCH: curl_khmatch = 1;
pub const CURLKHMATCH_OK: curl_khmatch = 0;
// #[derive(Copy, Clone)]

pub type curl_khkey = crate::src::lib::http2::curl_khkey;
pub type curl_khtype = crate::src::lib::http2::curl_khtype;
pub const CURLKHTYPE_ED25519: curl_khtype = 5;
pub const CURLKHTYPE_ECDSA: curl_khtype = 4;
pub const CURLKHTYPE_DSS: curl_khtype = 3;
pub const CURLKHTYPE_RSA: curl_khtype = 2;
pub const CURLKHTYPE_RSA1: curl_khtype = 1;
pub const CURLKHTYPE_UNKNOWN: curl_khtype = 0;
pub type CURL = crate::src::lib::http2::CURL;
pub type curl_ftpccc = crate::src::lib::http2::curl_ftpccc;
pub const CURLFTPSSL_CCC_LAST: curl_ftpccc = 3;
pub const CURLFTPSSL_CCC_ACTIVE: curl_ftpccc = 2;
pub const CURLFTPSSL_CCC_PASSIVE: curl_ftpccc = 1;
pub const CURLFTPSSL_CCC_NONE: curl_ftpccc = 0;
pub type curl_ftpauth = crate::src::lib::http2::curl_ftpauth;
pub const CURLFTPAUTH_LAST: curl_ftpauth = 3;
pub const CURLFTPAUTH_TLS: curl_ftpauth = 2;
pub const CURLFTPAUTH_SSL: curl_ftpauth = 1;
pub const CURLFTPAUTH_DEFAULT: curl_ftpauth = 0;
pub type curl_ftpfile = crate::src::lib::http2::curl_ftpfile;
pub const FTPFILE_SINGLECWD: curl_ftpfile = 3;
pub const FTPFILE_NOCWD: curl_ftpfile = 2;
pub const FTPFILE_MULTICWD: curl_ftpfile = 1;
// #[derive(Copy, Clone)]

pub type ssl_general_config = crate::src::lib::http2::ssl_general_config;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type ssl_config_data = crate::src::lib::http2::ssl_config_data;
pub type CURL_TLSAUTH = crate::src::lib::http2::CURL_TLSAUTH;
pub const CURL_TLSAUTH_LAST: CURL_TLSAUTH = 2;
pub const CURL_TLSAUTH_SRP: CURL_TLSAUTH = 1;
pub const CURL_TLSAUTH_NONE: CURL_TLSAUTH = 0;
pub type curl_ssl_ctx_callback = crate::src::lib::http2::curl_ssl_ctx_callback;
pub type curl_proxytype = crate::src::lib::http2::curl_proxytype;
pub const CURLPROXY_SOCKS5_HOSTNAME: curl_proxytype = 7;
pub const CURLPROXY_SOCKS4A: curl_proxytype = 6;
pub const CURLPROXY_SOCKS5: curl_proxytype = 5;
pub const CURLPROXY_SOCKS4: curl_proxytype = 4;
pub const CURLPROXY_HTTPS: curl_proxytype = 2;
pub const CURLPROXY_HTTP_1_0: curl_proxytype = 1;
pub const CURLPROXY_HTTP: curl_proxytype = 0;
pub type curl_TimeCond = crate::src::lib::http2::curl_TimeCond;
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
pub type mimestate = crate::src::lib::http2::mimestate;
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
pub type curl_free_callback = crate::src::lib::http2::curl_free_callback;
pub type curl_seek_callback = crate::src::lib::http2::curl_seek_callback;
pub type mimekind = crate::src::lib::http2::mimekind;
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
pub type curl_hstswrite_callback = crate::src::lib::http2::curl_hstswrite_callback;
// #[derive(Copy, Clone)]

pub type curl_index = crate::src::lib::http2::curl_index;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type curl_hstsentry = crate::src::lib::http2::curl_hstsentry;
pub type CURLSTScode = crate::src::lib::http2::CURLSTScode;
pub const CURLSTS_FAIL: CURLSTScode = 2;
pub const CURLSTS_DONE: CURLSTScode = 1;
pub const CURLSTS_OK: CURLSTScode = 0;
pub type curl_hstsread_callback = crate::src::lib::http2::curl_hstsread_callback;
pub type curl_conv_callback = crate::src::lib::http2::curl_conv_callback;
pub type curl_closesocket_callback = crate::src::lib::http2::curl_closesocket_callback;
pub type curl_socket_t = crate::src::lib::http2::curl_socket_t;
pub type curl_opensocket_callback = crate::src::lib::http2::curl_opensocket_callback;
// #[derive(Copy, Clone)]

pub type curl_sockaddr = crate::src::lib::http2::curl_sockaddr;
pub type curlsocktype = crate::src::lib::http2::curlsocktype;
pub const CURLSOCKTYPE_LAST: curlsocktype = 2;
pub const CURLSOCKTYPE_ACCEPT: curlsocktype = 1;
pub const CURLSOCKTYPE_IPCXN: curlsocktype = 0;
pub type curl_sockopt_callback = crate::src::lib::http2::curl_sockopt_callback;
pub type curl_ioctl_callback = crate::src::lib::http2::curl_ioctl_callback;
pub type curlioerr = crate::src::lib::http2::curlioerr;
pub const CURLIOE_LAST: curlioerr = 3;
pub const CURLIOE_FAILRESTART: curlioerr = 2;
pub const CURLIOE_UNKNOWNCMD: curlioerr = 1;
pub const CURLIOE_OK: curlioerr = 0;
pub type curl_debug_callback = crate::src::lib::http2::curl_debug_callback;
pub type curl_infotype = crate::src::lib::http2::curl_infotype;
pub const CURLINFO_END: curl_infotype = 7;
pub const CURLINFO_SSL_DATA_OUT: curl_infotype = 6;
pub const CURLINFO_SSL_DATA_IN: curl_infotype = 5;
pub const CURLINFO_DATA_OUT: curl_infotype = 4;
pub const CURLINFO_DATA_IN: curl_infotype = 3;
pub const CURLINFO_HEADER_OUT: curl_infotype = 2;
pub const CURLINFO_HEADER_IN: curl_infotype = 1;
pub const CURLINFO_TEXT: curl_infotype = 0;
pub type curl_xferinfo_callback = crate::src::lib::http2::curl_xferinfo_callback;
pub type curl_progress_callback = crate::src::lib::http2::curl_progress_callback;
pub type curl_write_callback = crate::src::lib::http2::curl_write_callback;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type SingleRequest = crate::src::lib::http2::SingleRequest;
// #[derive(Copy, Clone)]

pub type dohdata = crate::src::lib::http2::dohdata;
// #[derive(Copy, Clone)]

pub type dnsprobe = crate::src::lib::http2::dnsprobe;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_0 = crate::src::lib::http2::C2RustUnnamed;
// #[derive(Copy, Clone)]

pub type SSHPROTO = crate::src::lib::http2::SSHPROTO;
// #[derive(Copy, Clone)]

pub type SMTP = crate::src::lib::http2::SMTP;
pub type curl_pp_transfer = crate::src::lib::http2::curl_pp_transfer;
pub const PPTRANSFER_NONE: curl_pp_transfer = 2;
pub const PPTRANSFER_INFO: curl_pp_transfer = 1;
pub const PPTRANSFER_BODY: curl_pp_transfer = 0;
// #[derive(Copy, Clone)]

pub type RTSP = crate::src::lib::http2::RTSP;
// #[derive(Copy, Clone)]

pub type HTTP = crate::src::lib::http2::HTTP;
pub type uint8_t = crate::src::lib::http2::uint8_t;
pub type uint32_t = crate::src::lib::http2::uint32_t;
pub type C2RustUnnamed_1 = u32;
pub const HTTPSEND_BODY: C2RustUnnamed_1 = 2;
pub const HTTPSEND_REQUEST: C2RustUnnamed_1 = 1;
pub const HTTPSEND_NADA: C2RustUnnamed_1 = 0;
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
pub type upgrade101 = crate::src::lib::http2::upgrade101;
pub const UPGR101_WORKING: upgrade101 = 3;
pub const UPGR101_RECEIVED: upgrade101 = 2;
pub const UPGR101_REQUESTED: upgrade101 = 1;
pub const UPGR101_INIT: upgrade101 = 0;
pub type expect100 = crate::src::lib::http2::expect100;
pub const EXP100_FAILED: expect100 = 3;
pub const EXP100_SENDING_REQUEST: expect100 = 2;
pub const EXP100_AWAITING_CONTINUE: expect100 = 1;
pub const EXP100_SEND_DATA: expect100 = 0;
pub type C2RustUnnamed_2 = u32;
pub const HEADER_ALLBAD: C2RustUnnamed_2 = 2;
pub const HEADER_PARTHEADER: C2RustUnnamed_2 = 1;
pub const HEADER_NORMAL: C2RustUnnamed_2 = 0;
// #[derive(Copy, Clone)]

pub type PslCache = crate::src::lib::http2::PslCache;
pub type psl_ctx_t = crate::src::lib::http2::psl_ctx_t;
// #[derive(Copy, Clone)]

pub type Curl_multi = crate::src::lib::http2::Curl_multi;
pub type curl_multi_timer_callback = crate::src::lib::http2::curl_multi_timer_callback;
pub type CURLM = crate::src::lib::http2::CURLM;
pub type curl_push_callback = crate::src::lib::http2::curl_push_callback;
pub type curl_socket_callback = crate::src::lib::http2::curl_socket_callback;
// #[derive(Copy, Clone)]

pub type Names = crate::src::lib::http2::Names;
pub type C2RustUnnamed_3 = u32;
pub const HCACHE_SHARED: C2RustUnnamed_3 = 2;
pub const HCACHE_MULTI: C2RustUnnamed_3 = 1;
pub const HCACHE_NONE: C2RustUnnamed_3 = 0;
// #[derive(Copy, Clone)]

pub type Curl_message = crate::src::lib::http2::Curl_message;
// #[derive(Copy, Clone)]

pub type CURLMsg = crate::src::lib::http2::CURLMsg;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_4 = crate::src::lib::http2::C2RustUnnamed_3;
pub type CURLMSG = crate::src::lib::http2::CURLMSG;
pub const CURLMSG_LAST: CURLMSG = 2;
pub const CURLMSG_DONE: CURLMSG = 1;
pub const CURLMSG_NONE: CURLMSG = 0;
pub type CURLMstate = crate::src::lib::http2::CURLMstate;
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

pub type C2RustUnnamed_5 = crate::src::lib::http2::C2RustUnnamed_4;
// #[derive(Copy, Clone)]

pub type mqtt_conn = crate::src::lib::http2::mqtt_conn;
pub type mqttstate = crate::src::lib::http2::mqttstate;
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
pub type smb_conn_state = crate::src::lib::http2::smb_conn_state;
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
pub type saslstate = crate::src::lib::http2::saslstate;
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
pub type smtpstate = crate::src::lib::http2::smtpstate;
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
pub type pop3state = crate::src::lib::http2::pop3state;
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
pub type imapstate = crate::src::lib::http2::imapstate;
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
pub type sshstate = crate::src::lib::http2::sshstate;
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
pub type Curl_recv = crate::src::lib::http2::Curl_recv;
pub type Curl_send = crate::src::lib::http2::Curl_send;
// #[derive(Copy, Clone)]

pub type ftp_conn = crate::src::lib::http2::ftp_conn;
pub type ftpstate = crate::src::lib::http2::ftpstate;
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
pub type curlntlm = crate::src::lib::http2::curlntlm;
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
pub type ssl_connect_state = crate::src::lib::http2::ssl_connect_state;
pub const ssl_connect_done: ssl_connect_state = 5;
pub const ssl_connect_3: ssl_connect_state = 4;
pub const ssl_connect_2_writing: ssl_connect_state = 3;
pub const ssl_connect_2_reading: ssl_connect_state = 2;
pub const ssl_connect_2: ssl_connect_state = 1;
pub const ssl_connect_1: ssl_connect_state = 0;
pub type ssl_connection_state = crate::src::lib::http2::ssl_connection_state;
pub const ssl_connection_complete: ssl_connection_state = 2;
pub const ssl_connection_negotiating: ssl_connection_state = 1;
pub const ssl_connection_none: ssl_connection_state = 0;
// #[derive(Copy, Clone)]

pub type proxy_info = crate::src::lib::http2::proxy_info;
// #[derive(Copy, Clone)]

pub type hostname = crate::src::lib::http2::hostname;
pub type C2RustUnnamed_6 = u32;
pub const TRNSPRT_QUIC: C2RustUnnamed_6 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_6 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_6 = 3;
// #[derive(Copy, Clone)]

pub type Curl_chunker = crate::src::lib::http2::Curl_chunker;
pub type ChunkyState = crate::src::lib::http2::ChunkyState;
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
pub type connect_t = crate::src::lib::http2::connect_t;
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
pub type uint16_t = __uint16_t;
pub type in_addr_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type C2RustUnnamed_7 = u32;
pub const IPPROTO_MAX: C2RustUnnamed_7 = 256;
pub const IPPROTO_RAW: C2RustUnnamed_7 = 255;
pub const IPPROTO_MPLS: C2RustUnnamed_7 = 137;
pub const IPPROTO_UDPLITE: C2RustUnnamed_7 = 136;
pub const IPPROTO_SCTP: C2RustUnnamed_7 = 132;
pub const IPPROTO_COMP: C2RustUnnamed_7 = 108;
pub const IPPROTO_PIM: C2RustUnnamed_7 = 103;
pub const IPPROTO_ENCAP: C2RustUnnamed_7 = 98;
pub const IPPROTO_BEETPH: C2RustUnnamed_7 = 94;
pub const IPPROTO_MTP: C2RustUnnamed_7 = 92;
pub const IPPROTO_AH: C2RustUnnamed_7 = 51;
pub const IPPROTO_ESP: C2RustUnnamed_7 = 50;
pub const IPPROTO_GRE: C2RustUnnamed_7 = 47;
pub const IPPROTO_RSVP: C2RustUnnamed_7 = 46;
pub const IPPROTO_IPV6: C2RustUnnamed_7 = 41;
pub const IPPROTO_DCCP: C2RustUnnamed_7 = 33;
pub const IPPROTO_TP: C2RustUnnamed_7 = 29;
pub const IPPROTO_IDP: C2RustUnnamed_7 = 22;
pub const IPPROTO_UDP: C2RustUnnamed_7 = 17;
pub const IPPROTO_PUP: C2RustUnnamed_7 = 12;
pub const IPPROTO_EGP: C2RustUnnamed_7 = 8;
pub const IPPROTO_TCP: C2RustUnnamed_7 = 6;
pub const IPPROTO_IPIP: C2RustUnnamed_7 = 4;
pub const IPPROTO_IGMP: C2RustUnnamed_7 = 2;
pub const IPPROTO_ICMP: C2RustUnnamed_7 = 1;
pub const IPPROTO_IP: C2RustUnnamed_7 = 0;
pub type in_port_t = uint16_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in6_addr {
    pub __in6_u: C2RustUnnamed_8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_8 {
    pub __u6_addr8: [uint8_t; 16],
    pub __u6_addr16: [uint16_t; 8],
    pub __u6_addr32: [uint32_t; 4],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [u8; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: uint32_t,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_un {
    pub sun_family: sa_family_t,
    pub sun_path: [i8; 108],
}
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
pub type if2ip_result_t = u32;
pub const IF2IP_FOUND: if2ip_result_t = 2;
pub const IF2IP_AF_NOT_SUPPORTED: if2ip_result_t = 1;
pub const IF2IP_NOT_FOUND: if2ip_result_t = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_sockaddr_storage {
    pub buffer: C2RustUnnamed_9,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_9 {
    pub sa: sockaddr,
    pub sa_in: sockaddr_in,
    pub sa_in6: sockaddr_in6,
    pub sa_stor: sockaddr_storage,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_sockaddr_ex {
    pub family: i32,
    pub socktype: i32,
    pub protocol: i32,
    pub addrlen: u32,
    pub _sa_ex_u: C2RustUnnamed_10,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_10 {
    pub addr: sockaddr,
    pub buff: Curl_sockaddr_storage,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct connfind {
    pub id_tofind: i64,
    pub found: *mut connectdata,
}
#[inline]
 extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as i32 >> 8 as i32 & 0xff as i32
        | (__bsx as i32 & 0xff as i32) << 8 as i32)
        as __uint16_t;
}
#[inline]
unsafe extern "C" fn atoi(mut __nptr: *const i8) -> i32 {
    return strtol(
        __nptr,
        0 as *mut libc::c_void as *mut *mut i8,
        10 as i32,
    ) as i32;
}
unsafe extern "C" fn tcpkeepalive(mut data: *mut Curl_easy, mut sockfd: curl_socket_t) {
    let mut optval: i32 = if ((*data).set).tcp_keepalive() as i32 != 0 {
        1 as i32
    } else {
        0 as i32
    };
    if setsockopt(
        sockfd,
        1 as i32,
        9 as i32,
        &mut optval as *mut i32 as *mut libc::c_void,
        ::std::mem::size_of::<i32>() as u64 as socklen_t,
    ) < 0 as i32
    {
        Curl_infof(
            data,
            b"Failed to set SO_KEEPALIVE on fd %d\0" as *const u8 as *const i8,
            sockfd,
        );
    } else {
        optval = curlx_sltosi((*data).set.tcp_keepidle);
        if setsockopt(
            sockfd,
            IPPROTO_TCP as i32,
            4 as i32,
            &mut optval as *mut i32 as *mut libc::c_void,
            ::std::mem::size_of::<i32>() as u64 as socklen_t,
        ) < 0 as i32
        {
            Curl_infof(
                data,
                b"Failed to set TCP_KEEPIDLE on fd %d\0" as *const u8
                    as *const i8,
                sockfd,
            );
        }
        optval = curlx_sltosi((*data).set.tcp_keepintvl);
        if setsockopt(
            sockfd,
            IPPROTO_TCP as i32,
            5 as i32,
            &mut optval as *mut i32 as *mut libc::c_void,
            ::std::mem::size_of::<i32>() as u64 as socklen_t,
        ) < 0 as i32
        {
            Curl_infof(
                data,
                b"Failed to set TCP_KEEPINTVL on fd %d\0" as *const u8
                    as *const i8,
                sockfd,
            );
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn Curl_timeleft(
    mut data: *mut Curl_easy,
    mut nowp: *mut curltime,
    mut duringconnect: bool,
) -> timediff_t {
    let mut timeout_set: u32 = 0 as i32 as u32;
    let mut connect_timeout_ms: timediff_t = 0 as i32 as timediff_t;
    let mut maxtime_timeout_ms: timediff_t = 0 as i32 as timediff_t;
    let mut timeout_ms: timediff_t = 0 as i32 as timediff_t;
    let mut now: curltime = curltime { tv_sec: 0, tv_usec: 0 };
    if (*data).set.timeout > 0 as i32 as i64 {
        timeout_set = 2 as i32 as u32;
        maxtime_timeout_ms = (*data).set.timeout;
    }
    if duringconnect {
        timeout_set |= 1 as i32 as u32;
        connect_timeout_ms = if (*data).set.connecttimeout
            > 0 as i32 as i64
        {
            (*data).set.connecttimeout
        } else {
            300000 as i32 as i64
        };
    }
    if timeout_set == 0 {
        return 0 as i32 as timediff_t;
    }
    if nowp.is_null() {
        now = Curl_now();
        nowp = &mut now;
    }
    if timeout_set & 2 as i32 as u32 != 0 {
        maxtime_timeout_ms -= Curl_timediff(*nowp, (*data).progress.t_startop);
        timeout_ms = maxtime_timeout_ms;
    }
    if timeout_set & 1 as i32 as u32 != 0 {
        connect_timeout_ms -= Curl_timediff(*nowp, (*data).progress.t_startsingle);
        if timeout_set & 2 as i32 as u32 == 0
            || connect_timeout_ms < maxtime_timeout_ms
        {
            timeout_ms = connect_timeout_ms;
        }
    }
    if timeout_ms == 0 {
        return -(1 as i32) as timediff_t;
    }
    return timeout_ms;
}
unsafe extern "C" fn bindlocal(
    mut data: *mut Curl_easy,
    mut sockfd: curl_socket_t,
    mut af: i32,
    mut scope: u32,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut sa: Curl_sockaddr_storage = Curl_sockaddr_storage {
        buffer: C2RustUnnamed_9 {
            sa: sockaddr {
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    };
    let mut sock: *mut sockaddr = &mut sa as *mut Curl_sockaddr_storage as *mut sockaddr;
    let mut sizeof_sa: curl_socklen_t = 0 as i32 as curl_socklen_t;
    let mut si4: *mut sockaddr_in = &mut sa as *mut Curl_sockaddr_storage
        as *mut sockaddr_in;
    let mut si6: *mut sockaddr_in6 = &mut sa as *mut Curl_sockaddr_storage
        as *mut sockaddr_in6;
    let mut h: *mut Curl_dns_entry = 0 as *mut Curl_dns_entry;
    let mut port: u16 = (*data).set.localport;
    let mut portnum: i32 = (*data).set.localportrange;
    let mut dev: *const i8 = (*data)
        .set
        .str_0[STRING_DEVICE as i32 as usize];
    let mut error: i32 = 0;
    let mut on: i32 = 1 as i32;
    if dev.is_null() && port == 0 {
        return CURLE_OK;
    }
    memset(
        &mut sa as *mut Curl_sockaddr_storage as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<Curl_sockaddr_storage>() as u64,
    );
    if !dev.is_null() && strlen(dev) < 255 as i32 as u64 {
        let mut myhost: [i8; 256] = *::std::mem::transmute::<
            &[u8; 256],
            &mut [i8; 256],
        >(
            b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        );
        let mut done: i32 = 0 as i32;
        let mut is_interface: bool = 0 as i32 != 0;
        let mut is_host: bool = 0 as i32 != 0;
        static mut if_prefix: *const i8 = b"if!\0" as *const u8
            as *const i8;
        static mut host_prefix: *const i8 = b"host!\0" as *const u8
            as *const i8;
        if strncmp(if_prefix, dev, strlen(if_prefix)) == 0 as i32 {
            dev = dev.offset(strlen(if_prefix) as isize);
            is_interface = 1 as i32 != 0;
        } else if strncmp(host_prefix, dev, strlen(host_prefix)) == 0 as i32 {
            dev = dev.offset(strlen(host_prefix) as isize);
            is_host = 1 as i32 != 0;
        }
        if !is_host {
            if setsockopt(
                sockfd,
                1 as i32,
                25 as i32,
                dev as *const libc::c_void,
                (strlen(dev) as curl_socklen_t)
                    .wrapping_add(1 as i32 as u32),
            ) == 0 as i32
            {
                return CURLE_OK;
            }
            match Curl_if2ip(
                af,
                scope,
                (*conn).scope_id,
                dev,
                myhost.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 256]>() as u64
                    as i32,
            ) as u32
            {
                0 => {
                    if is_interface {
                        Curl_failf(
                            data,
                            b"Couldn't bind to interface '%s'\0" as *const u8
                                as *const i8,
                            dev,
                        );
                        return CURLE_INTERFACE_FAILED;
                    }
                }
                1 => return CURLE_UNSUPPORTED_PROTOCOL,
                2 => {
                    is_interface = 1 as i32 != 0;
                    Curl_infof(
                        data,
                        b"Local Interface %s is ip %s using address family %i\0"
                            as *const u8 as *const i8,
                        dev,
                        myhost.as_mut_ptr(),
                        af,
                    );
                    done = 1 as i32;
                }
                _ => {}
            }
        }
        if !is_interface {
            let mut ipver: u8 = (*conn).ip_version;
            let mut rc: i32 = 0;
            if af == 2 as i32 {
                (*conn).ip_version = 1 as i32 as u8;
            } else if af == 10 as i32 {
                (*conn).ip_version = 2 as i32 as u8;
            }
            rc = Curl_resolv(data, dev, 0 as i32, 0 as i32 != 0, &mut h)
                as i32;
            if rc == CURLRESOLV_PENDING as i32 {
                Curl_resolver_wait_resolv(data, &mut h);
            }
            (*conn).ip_version = ipver;
            if !h.is_null() {
                Curl_printable_address(
                    (*h).addr,
                    myhost.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 256]>() as u64,
                );
                Curl_infof(
                    data,
                    b"Name '%s' family %i resolved to '%s' family %i\0" as *const u8
                        as *const i8,
                    dev,
                    af,
                    myhost.as_mut_ptr(),
                    (*(*h).addr).ai_family,
                );
                Curl_resolv_unlock(data, h);
                if af != (*(*h).addr).ai_family {
                    return CURLE_UNSUPPORTED_PROTOCOL;
                }
                done = 1 as i32;
            } else {
                done = -(1 as i32);
            }
        }
        if done > 0 as i32 {
            if af == 10 as i32 {
                let mut scope_ptr: *mut i8 = strchr(
                    myhost.as_mut_ptr(),
                    '%' as i32,
                );
                if !scope_ptr.is_null() {
                    let fresh0 = scope_ptr;
                    scope_ptr = scope_ptr.offset(1);
                    *fresh0 = 0 as i32 as i8;
                }
                if inet_pton(
                    10 as i32,
                    myhost.as_mut_ptr(),
                    &mut (*si6).sin6_addr as *mut in6_addr as *mut libc::c_void,
                ) > 0 as i32
                {
                    (*si6).sin6_family = 10 as i32 as sa_family_t;
                    (*si6).sin6_port = __bswap_16(port);
                    if !scope_ptr.is_null() {
                        (*si6).sin6_scope_id = atoi(scope_ptr) as uint32_t;
                    }
                }
                sizeof_sa = ::std::mem::size_of::<sockaddr_in6>() as u64
                    as curl_socklen_t;
            } else if af == 2 as i32
                    && inet_pton(
                        2 as i32,
                        myhost.as_mut_ptr(),
                        &mut (*si4).sin_addr as *mut in_addr as *mut libc::c_void,
                    ) > 0 as i32
                {
                (*si4).sin_family = 2 as i32 as sa_family_t;
                (*si4).sin_port = __bswap_16(port);
                sizeof_sa = ::std::mem::size_of::<sockaddr_in>() as u64
                    as curl_socklen_t;
            }
        }
        if done < 1 as i32 {
            let ref mut fresh1 = (*data).state;
            (*fresh1).set_errorbuf(0 as i32 as bit);
            Curl_failf(
                data,
                b"Couldn't bind to '%s'\0" as *const u8 as *const i8,
                dev,
            );
            return CURLE_INTERFACE_FAILED;
        }
    } else if af == 10 as i32 {
        (*si6).sin6_family = 10 as i32 as sa_family_t;
        (*si6).sin6_port = __bswap_16(port);
        sizeof_sa = ::std::mem::size_of::<sockaddr_in6>() as u64
            as curl_socklen_t;
    } else if af == 2 as i32 {
        (*si4).sin_family = 2 as i32 as sa_family_t;
        (*si4).sin_port = __bswap_16(port);
        sizeof_sa = ::std::mem::size_of::<sockaddr_in>() as u64
            as curl_socklen_t;
    }
    setsockopt(
        sockfd,
        0 as i32,
        24 as i32,
        &mut on as *mut i32 as *const libc::c_void,
        ::std::mem::size_of::<i32>() as u64 as socklen_t,
    );
    loop {
        if bind(sockfd, sock, sizeof_sa) >= 0 as i32 {
            let mut add: Curl_sockaddr_storage = Curl_sockaddr_storage {
                buffer: C2RustUnnamed_9 {
                    sa: sockaddr {
                        sa_family: 0,
                        sa_data: [0; 14],
                    },
                },
            };
            let mut size: curl_socklen_t = ::std::mem::size_of::<Curl_sockaddr_storage>()
                as u64 as curl_socklen_t;
            memset(
                &mut add as *mut Curl_sockaddr_storage as *mut libc::c_void,
                0 as i32,
                ::std::mem::size_of::<Curl_sockaddr_storage>() as u64,
            );
            if getsockname(
                sockfd,
                &mut add as *mut Curl_sockaddr_storage as *mut sockaddr,
                &mut size,
            ) < 0 as i32
            {
                let mut buffer: [i8; 256] = [0; 256];
                error = *__errno_location();
                (*data).state.os_errno = error;
                Curl_failf(
                    data,
                    b"getsockname() failed with errno %d: %s\0" as *const u8
                        as *const i8,
                    error,
                    Curl_strerror(
                        error,
                        buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 256]>() as u64,
                    ),
                );
                return CURLE_INTERFACE_FAILED;
            }
            Curl_infof(
                data,
                b"Local port: %hu\0" as *const u8 as *const i8,
                port as i32,
            );
            let ref mut fresh2 = (*conn).bits;
            (*fresh2).set_bound(1 as i32 as bit);
            return CURLE_OK;
        }
        portnum -= 1;
        if !(portnum > 0 as i32) {
            break;
        }
        Curl_infof(
            data,
            b"Bind to local port %hu failed, trying next\0" as *const u8
                as *const i8,
            port as i32,
        );
        port = port.wrapping_add(1);
        if (*sock).sa_family as i32 == 2 as i32 {
            (*si4).sin_port = __bswap_16(port);
        } else {
            (*si6).sin6_port = __bswap_16(port);
        }
    }
    let mut buffer_0: [i8; 256] = [0; 256];
    error = *__errno_location();
    (*data).state.os_errno = error;
    Curl_failf(
        data,
        b"bind failed with errno %d: %s\0" as *const u8 as *const i8,
        error,
        Curl_strerror(
            error,
            buffer_0.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 256]>() as u64,
        ),
    );
    return CURLE_INTERFACE_FAILED;
}
unsafe extern "C" fn verifyconnect(
    mut sockfd: curl_socket_t,
    mut error: *mut i32,
) -> bool {
    let mut rc: bool = 1 as i32 != 0;
    let mut err: i32 = 0 as i32;
    let mut errSize: curl_socklen_t = ::std::mem::size_of::<i32>()
        as u64 as curl_socklen_t;
    if 0 as i32
        != getsockopt(
            sockfd,
            1 as i32,
            4 as i32,
            &mut err as *mut i32 as *mut libc::c_void,
            &mut errSize,
        )
    {
        err = *__errno_location();
    }
    if 0 as i32 == err || 106 as i32 == err {
        rc = 1 as i32 != 0;
    } else {
        rc = 0 as i32 != 0;
    }
    if !error.is_null() {
        *error = err;
    }
    return rc;
}
unsafe extern "C" fn ainext(
    mut conn: *mut connectdata,
    mut tempindex: i32,
    mut next: bool,
) -> *mut Curl_addrinfo {
    let mut ai: *mut Curl_addrinfo = (*conn).tempaddr[tempindex as usize];
    if !ai.is_null() && next as i32 != 0 {
        ai = (*ai).ai_next;
    }
    while !ai.is_null() && (*ai).ai_family != (*conn).tempfamily[tempindex as usize] {
        ai = (*ai).ai_next;
    }
    let ref mut fresh3 = (*conn).tempaddr[tempindex as usize];
    *fresh3 = ai;
    return ai;
}
unsafe extern "C" fn trynextip(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
    mut tempindex: i32,
) -> CURLcode {
    let mut result: CURLcode = CURLE_COULDNT_CONNECT;
    let mut fd_to_close: curl_socket_t = (*conn).tempsock[tempindex as usize];
    (*conn).tempsock[tempindex as usize] = -(1 as i32);
    if sockindex == 0 as i32 {
        let mut ai: *mut Curl_addrinfo = (*conn).tempaddr[tempindex as usize];
        while !ai.is_null() {
            result = singleipconnect(data, conn, ai, tempindex);
            if !(result as u32
                == CURLE_COULDNT_CONNECT as i32 as u32)
            {
                break;
            }
            ai = ainext(conn, tempindex, 1 as i32 != 0);
        }
    }
    if fd_to_close != -(1 as i32) {
        Curl_closesocket(data, conn, fd_to_close);
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_persistconninfo(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut local_ip: *mut i8,
    mut local_port: i32,
) {
    memcpy(
        ((*data).info.conn_primary_ip).as_mut_ptr() as *mut libc::c_void,
        ((*conn).primary_ip).as_mut_ptr() as *const libc::c_void,
        ::std::mem::size_of::<[i8; 46]>() as u64,
    );
    if !local_ip.is_null()
        && *local_ip.offset(0 as i32 as isize) as i32 != 0
    {
        memcpy(
            ((*data).info.conn_local_ip).as_mut_ptr() as *mut libc::c_void,
            local_ip as *const libc::c_void,
            ::std::mem::size_of::<[i8; 46]>() as u64,
        );
    } else {
        (*data)
            .info
            .conn_local_ip[0 as i32 as usize] = 0 as i32 as i8;
    }
    let ref mut fresh4 = (*data).info.conn_scheme;
    *fresh4 = (*(*conn).handler).scheme;
    (*data).info.conn_protocol = (*(*conn).handler).protocol;
    (*data).info.conn_primary_port = (*conn).port;
    (*data).info.conn_local_port = local_port;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_addr2string(
    mut sa: *mut sockaddr,
    mut salen: curl_socklen_t,
    mut addr: *mut i8,
    mut port: *mut i32,
) -> bool {
    let mut si: *mut sockaddr_in = 0 as *mut sockaddr_in;
    let mut si6: *mut sockaddr_in6 = 0 as *mut sockaddr_in6;
    let mut su: *mut sockaddr_un = 0 as *mut sockaddr_un;
    match (*sa).sa_family as i32 {
        2 => {
            si = sa as *mut libc::c_void as *mut sockaddr_in;
            if !(inet_ntop(
                (*sa).sa_family as i32,
                &mut (*si).sin_addr as *mut in_addr as *const libc::c_void,
                addr,
                ::std::mem::size_of::<[i8; 46]>() as u64
                    as curl_socklen_t,
            ))
                .is_null()
            {
                let mut us_port: u16 = __bswap_16((*si).sin_port);
                *port = us_port as i32;
                return 1 as i32 != 0;
            }
        }
        10 => {
            si6 = sa as *mut libc::c_void as *mut sockaddr_in6;
            if !(inet_ntop(
                (*sa).sa_family as i32,
                &mut (*si6).sin6_addr as *mut in6_addr as *const libc::c_void,
                addr,
                ::std::mem::size_of::<[i8; 46]>() as u64
                    as curl_socklen_t,
            ))
                .is_null()
            {
                let mut us_port_0: u16 = __bswap_16((*si6).sin6_port);
                *port = us_port_0 as i32;
                return 1 as i32 != 0;
            }
        }
        1 => {
            if salen
                > ::std::mem::size_of::<sa_family_t>() as u64 as curl_socklen_t
            {
                su = sa as *mut sockaddr_un;
                curl_msnprintf(
                    addr,
                    ::std::mem::size_of::<[i8; 46]>() as u64,
                    b"%s\0" as *const u8 as *const i8,
                    ((*su).sun_path).as_mut_ptr(),
                );
            } else {
                *addr
                    .offset(
                        0 as i32 as isize,
                    ) = 0 as i32 as i8;
            }
            *port = 0 as i32;
            return 1 as i32 != 0;
        }
        _ => {}
    }
    *addr.offset(0 as i32 as isize) = '\u{0}' as i32 as i8;
    *port = 0 as i32;
    *__errno_location() = 97 as i32;
    return 0 as i32 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_conninfo_remote(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockfd: curl_socket_t,
) {
    let mut buffer: [i8; 256] = [0; 256];
    let mut ssrem: Curl_sockaddr_storage = Curl_sockaddr_storage {
        buffer: C2RustUnnamed_9 {
            sa: sockaddr {
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    };
    let mut plen: curl_socklen_t = 0;
    let mut port: i32 = 0;
    plen = ::std::mem::size_of::<Curl_sockaddr_storage>() as u64
        as curl_socklen_t;
    memset(
        &mut ssrem as *mut Curl_sockaddr_storage as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<Curl_sockaddr_storage>() as u64,
    );
    if getpeername(
        sockfd,
        &mut ssrem as *mut Curl_sockaddr_storage as *mut sockaddr,
        &mut plen,
    ) != 0
    {
        let mut error: i32 = *__errno_location();
        Curl_failf(
            data,
            b"getpeername() failed with errno %d: %s\0" as *const u8
                as *const i8,
            error,
            Curl_strerror(
                error,
                buffer.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 256]>() as u64,
            ),
        );
        return;
    }
    if !Curl_addr2string(
        &mut ssrem as *mut Curl_sockaddr_storage as *mut sockaddr,
        plen,
        ((*conn).primary_ip).as_mut_ptr(),
        &mut port,
    ) {
        Curl_failf(
            data,
            b"ssrem inet_ntop() failed with errno %d: %s\0" as *const u8
                as *const i8,
            *__errno_location(),
            Curl_strerror(
                *__errno_location(),
                buffer.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 256]>() as u64,
            ),
        );
        return;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_conninfo_local(
    mut data: *mut Curl_easy,
    mut sockfd: curl_socket_t,
    mut local_ip: *mut i8,
    mut local_port: *mut i32,
) {
    let mut buffer: [i8; 256] = [0; 256];
    let mut ssloc: Curl_sockaddr_storage = Curl_sockaddr_storage {
        buffer: C2RustUnnamed_9 {
            sa: sockaddr {
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    };
    let mut slen: curl_socklen_t = 0;
    slen = ::std::mem::size_of::<Curl_sockaddr_storage>() as u64
        as curl_socklen_t;
    memset(
        &mut ssloc as *mut Curl_sockaddr_storage as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<Curl_sockaddr_storage>() as u64,
    );
    if getsockname(
        sockfd,
        &mut ssloc as *mut Curl_sockaddr_storage as *mut sockaddr,
        &mut slen,
    ) != 0
    {
        let mut error: i32 = *__errno_location();
        Curl_failf(
            data,
            b"getsockname() failed with errno %d: %s\0" as *const u8
                as *const i8,
            error,
            Curl_strerror(
                error,
                buffer.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 256]>() as u64,
            ),
        );
        return;
    }
    if !Curl_addr2string(
        &mut ssloc as *mut Curl_sockaddr_storage as *mut sockaddr,
        slen,
        local_ip,
        local_port,
    ) {
        Curl_failf(
            data,
            b"ssloc inet_ntop() failed with errno %d: %s\0" as *const u8
                as *const i8,
            *__errno_location(),
            Curl_strerror(
                *__errno_location(),
                buffer.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 256]>() as u64,
            ),
        );
        return;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_updateconninfo(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockfd: curl_socket_t,
) {
    let mut local_ip: [i8; 46] = *::std::mem::transmute::<
        &[u8; 46],
        &mut [i8; 46],
    >(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut local_port: i32 = -(1 as i32);
    if (*conn).transport as u32 == TRNSPRT_TCP as i32 as u32 {
        if ((*conn).bits).reuse() == 0 && ((*conn).bits).tcp_fastopen() == 0 {
            Curl_conninfo_remote(data, conn, sockfd);
        }
        Curl_conninfo_local(data, sockfd, local_ip.as_mut_ptr(), &mut local_port);
    }
    Curl_persistconninfo(data, conn, local_ip.as_mut_ptr(), local_port);
}
unsafe extern "C" fn connect_SOCKS(
    mut data: *mut Curl_easy,
    mut sockindex: i32,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut pxresult: CURLproxycode = CURLPX_OK;
    let mut conn: *mut connectdata = (*data).conn;
    if ((*conn).bits).socksproxy() != 0 {
        let host: *const i8 = if ((*conn).bits).httpproxy() as i32 != 0
        {
            (*conn).http_proxy.host.name
        } else if ((*conn).bits).conn_to_host() as i32 != 0 {
            (*conn).conn_to_host.name
        } else if sockindex == 1 as i32 {
            (*conn).secondaryhostname
        } else {
            (*conn).host.name
        };
        let port: i32 = if ((*conn).bits).httpproxy() as i32 != 0 {
            (*conn).http_proxy.port as i32
        } else if sockindex == 1 as i32 {
            (*conn).secondary_port as i32
        } else if ((*conn).bits).conn_to_port() as i32 != 0 {
            (*conn).conn_to_port
        } else {
            (*conn).remote_port
        };
        match (*conn).socks_proxy.proxytype as u32 {
            5 | 7 => {
                pxresult = Curl_SOCKS5(
                    (*conn).socks_proxy.user,
                    (*conn).socks_proxy.passwd,
                    host,
                    port,
                    sockindex,
                    data,
                    done,
                );
            }
            4 | 6 => {
                pxresult = Curl_SOCKS4(
                    (*conn).socks_proxy.user,
                    host,
                    port,
                    sockindex,
                    data,
                    done,
                );
            }
            _ => {
                Curl_failf(
                    data,
                    b"unknown proxytype option given\0" as *const u8
                        as *const i8,
                );
                result = CURLE_COULDNT_CONNECT;
            }
        }
        if pxresult as u64 != 0 {
            result = CURLE_PROXY;
            (*data).info.pxcode = pxresult;
        }
    } else {
        *done = 1 as i32 != 0;
    }
    return result;
}
unsafe extern "C" fn post_SOCKS(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
    mut connected: *mut bool,
) {
    (*conn).bits.tcpconnect[sockindex as usize] = 1 as i32 != 0;
    *connected = 1 as i32 != 0;
    if sockindex == 0 as i32 {
        Curl_pgrsTime(data, TIMER_CONNECT);
    }
    Curl_updateconninfo(data, conn, (*conn).sock[sockindex as usize]);
    Curl_verboseconnect(data, conn);
    let ref mut fresh5 = (*data).info.numconnects;
    *fresh5 += 1;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_is_connected(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
    mut connected: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut allow: timediff_t = 0;
    let mut error: i32 = 0 as i32;
    let mut now: curltime = curltime { tv_sec: 0, tv_usec: 0 };
    let mut rc: i32 = 0 as i32;
    let mut i: u32 = 0;
    *connected = 0 as i32 != 0;
    if (*conn).bits.tcpconnect[sockindex as usize] {
        *connected = 1 as i32 != 0;
        return CURLE_OK;
    }
    now = Curl_now();
    if (*conn).cnnct.state as u32
        >= CONNECT_SOCKS_INIT as i32 as u32
        && ((*conn).cnnct.state as u32)
            < CONNECT_DONE as i32 as u32
    {
        result = connect_SOCKS(data, sockindex, connected);
        if result as u64 == 0 && *connected as i32 != 0 {
            post_SOCKS(data, conn, sockindex, connected);
        }
        return result;
    }
    i = 0 as i32 as u32;
    while i < 2 as i32 as u32 {
        let other: i32 = (i ^ 1 as i32 as u32) as i32;
        if !((*conn).tempsock[i as usize] == -(1 as i32)) {
            error = 0 as i32;
            rc = Curl_socket_check(
                -(1 as i32),
                -(1 as i32),
                (*conn).tempsock[i as usize],
                0 as i32 as timediff_t,
            );
            if rc == 0 as i32 {
                if Curl_timediff(now, (*conn).connecttime)
                    >= (*conn).timeoutms_per_addr[i as usize]
                {
                    Curl_infof(
                        data,
                        b"After %ldms connect time, move on!\0" as *const u8
                            as *const i8,
                        (*conn).timeoutms_per_addr[i as usize],
                    );
                    error = 110 as i32;
                }
                if i == 0 as i32 as u32
                    && ((*conn).bits).parallel_connect() == 0
                    && Curl_timediff(now, (*conn).connecttime)
                        >= (*data).set.happy_eyeballs_timeout
                {
                    let ref mut fresh6 = (*conn).bits;
                    (*fresh6).set_parallel_connect(1 as i32 as bit);
                    trynextip(data, conn, sockindex, 1 as i32);
                }
            } else if rc == 0x2 as i32
                    || ((*conn).bits).tcp_fastopen() as i32 != 0
                {
                if verifyconnect((*conn).tempsock[i as usize], &mut error) {
                    (*conn).sock[sockindex as usize] = (*conn).tempsock[i as usize];
                    let ref mut fresh7 = (*conn).ip_addr;
                    *fresh7 = (*conn).tempaddr[i as usize];
                    (*conn).tempsock[i as usize] = -(1 as i32);
                    let ref mut fresh8 = (*conn).bits;
                    (*fresh8)
                        .set_ipv6(
                            (if (*(*conn).ip_addr).ai_family == 10 as i32 {
                                1 as i32
                            } else {
                                0 as i32
                            }) as bit,
                        );
                    if (*conn).tempsock[other as usize] != -(1 as i32) {
                        Curl_closesocket(data, conn, (*conn).tempsock[other as usize]);
                        (*conn).tempsock[other as usize] = -(1 as i32);
                    }
                    result = connect_SOCKS(data, sockindex, connected);
                    if result as u32 != 0 || !*connected {
                        return result;
                    }
                    post_SOCKS(data, conn, sockindex, connected);
                    return CURLE_OK;
                }
            } else if rc & 0x4 as i32 != 0 {
                verifyconnect((*conn).tempsock[i as usize], &mut error);
            }
            if error != 0 {
                (*data).state.os_errno = error;
                *__errno_location() = error;
                if !((*conn).tempaddr[i as usize]).is_null() {
                    let mut status: CURLcode = CURLE_OK;
                    let mut ipaddress: [i8; 46] = [0; 46];
                    let mut buffer: [i8; 256] = [0; 256];
                    Curl_printable_address(
                        (*conn).tempaddr[i as usize],
                        ipaddress.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 46]>() as u64,
                    );
                    Curl_infof(
                        data,
                        b"connect to %s port %u failed: %s\0" as *const u8
                            as *const i8,
                        ipaddress.as_mut_ptr(),
                        (*conn).port,
                        Curl_strerror(
                            error,
                            buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[i8; 256]>() as u64,
                        ),
                    );
                    allow = Curl_timeleft(data, &mut now, 1 as i32 != 0);
                    (*conn)
                        .timeoutms_per_addr[i
                        as usize] = if ((*(*conn).tempaddr[i as usize]).ai_next)
                        .is_null()
                    {
                        allow
                    } else {
                        allow / 2 as i32 as i64
                    };
                    ainext(conn, i as i32, 1 as i32 != 0);
                    status = trynextip(data, conn, sockindex, i as i32);
                    if status as u32
                        != CURLE_COULDNT_CONNECT as i32 as u32
                        || (*conn).tempsock[other as usize] == -(1 as i32)
                    {
                        result = status;
                    }
                }
            }
        }
        i = i.wrapping_add(1);
    }
    allow = Curl_timeleft(data, &mut now, 1 as i32 != 0);
    if allow < 0 as i32 as i64 {
        Curl_failf(
            data,
            b"Connection timeout after %ld ms\0" as *const u8 as *const i8,
            Curl_timediff(now, (*data).progress.t_startsingle),
        );
        return CURLE_OPERATION_TIMEDOUT;
    }
    if result as u32 != 0
        && (*conn).tempsock[0 as i32 as usize] == -(1 as i32)
        && (*conn).tempsock[1 as i32 as usize] == -(1 as i32)
    {
        let mut hostname: *const i8 = 0 as *const i8;
        let mut buffer_0: [i8; 256] = [0; 256];
        result = trynextip(data, conn, sockindex, 1 as i32);
        if result as u64 == 0 {
            return result;
        }
        if ((*conn).bits).socksproxy() != 0 {
            hostname = (*conn).socks_proxy.host.name;
        } else if ((*conn).bits).httpproxy() != 0 {
            hostname = (*conn).http_proxy.host.name;
        } else if ((*conn).bits).conn_to_host() != 0 {
            hostname = (*conn).conn_to_host.name;
        } else {
            hostname = (*conn).host.name;
        }
        Curl_failf(
            data,
            b"Failed to connect to %s port %u after %ld ms: %s\0" as *const u8
                as *const i8,
            hostname,
            (*conn).port,
            Curl_timediff(now, (*data).progress.t_startsingle),
            Curl_strerror(
                error,
                buffer_0.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 256]>() as u64,
            ),
        );
        if 110 as i32 == (*data).state.os_errno {
            result = CURLE_OPERATION_TIMEDOUT;
        }
    } else {
        result = CURLE_OK;
    }
    return result;
}
unsafe extern "C" fn tcpnodelay(mut data: *mut Curl_easy, mut sockfd: curl_socket_t) {
    let mut onoff: curl_socklen_t = 1 as i32 as curl_socklen_t;
    let mut level: i32 = IPPROTO_TCP as i32;
    let mut buffer: [i8; 256] = [0; 256];
    if setsockopt(
        sockfd,
        level,
        1 as i32,
        &mut onoff as *mut curl_socklen_t as *mut libc::c_void,
        ::std::mem::size_of::<curl_socklen_t>() as u64 as socklen_t,
    ) < 0 as i32
    {
        Curl_infof(
            data,
            b"Could not set TCP_NODELAY: %s\0" as *const u8 as *const i8,
            Curl_strerror(
                *__errno_location(),
                buffer.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 256]>() as u64,
            ),
        );
    }
}
unsafe extern "C" fn singleipconnect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut ai: *const Curl_addrinfo,
    mut tempindex: i32,
) -> CURLcode {
    let mut addr: Curl_sockaddr_ex = Curl_sockaddr_ex {
        family: 0,
        socktype: 0,
        protocol: 0,
        addrlen: 0,
        _sa_ex_u: C2RustUnnamed_10 {
            addr: sockaddr {
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    };
    let mut rc: i32 = -(1 as i32);
    let mut error: i32 = 0 as i32;
    let mut isconnected: bool = 0 as i32 != 0;
    let mut sockfd: curl_socket_t = 0;
    let mut result: CURLcode = CURLE_OK;
    let mut ipaddress: [i8; 46] = [0; 46];
    let mut port: i32 = 0;
    let mut is_tcp: bool = false;
    let mut optval: i32 = 1 as i32;
    let mut buffer: [i8; 256] = [0; 256];
    let mut sockp: *mut curl_socket_t = &mut *((*conn).tempsock)
        .as_mut_ptr()
        .offset(tempindex as isize) as *mut curl_socket_t;
    *sockp = -(1 as i32);
    result = Curl_socket(data, ai, &mut addr, &mut sockfd);
    if result as u64 != 0 {
        return result;
    }
    if !Curl_addr2string(
        &mut addr._sa_ex_u.addr as *mut sockaddr,
        addr.addrlen,
        ipaddress.as_mut_ptr(),
        &mut port,
    ) {
        Curl_failf(
            data,
            b"sa_addr inet_ntop() failed with errno %d: %s\0" as *const u8
                as *const i8,
            *__errno_location(),
            Curl_strerror(
                *__errno_location(),
                buffer.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 256]>() as u64,
            ),
        );
        Curl_closesocket(data, conn, sockfd);
        return CURLE_OK;
    }
    Curl_infof(
        data,
        b"  Trying %s:%d...\0" as *const u8 as *const i8,
        ipaddress.as_mut_ptr(),
        port,
    );
    is_tcp = (addr.family == 2 as i32 || addr.family == 10 as i32)
        && addr.socktype == SOCK_STREAM as i32;
    if is_tcp as i32 != 0 && ((*data).set).tcp_nodelay() as i32 != 0 {
        tcpnodelay(data, sockfd);
    }
    if is_tcp as i32 != 0 && ((*data).set).tcp_keepalive() as i32 != 0 {
        tcpkeepalive(data, sockfd);
    }
    if ((*data).set.fsockopt).is_some() {
        Curl_set_in_callback(data, 1 as i32 != 0);
        error = ((*data).set.fsockopt)
            .expect(
                "non-null function pointer",
            )((*data).set.sockopt_client, sockfd, CURLSOCKTYPE_IPCXN);
        Curl_set_in_callback(data, 0 as i32 != 0);
        if error == 2 as i32 {
            isconnected = 1 as i32 != 0;
        } else if error != 0 {
            Curl_closesocket(data, conn, sockfd);
            return CURLE_ABORTED_BY_CALLBACK;
        }
    }
    if addr.family == 2 as i32 || addr.family == 10 as i32 {
        result = bindlocal(
            data,
            sockfd,
            addr.family,
            Curl_ipv6_scope(&mut addr._sa_ex_u.addr as *mut sockaddr),
        );
        if result as u64 != 0 {
            Curl_closesocket(data, conn, sockfd);
            if result as u32
                == CURLE_UNSUPPORTED_PROTOCOL as i32 as u32
            {
                return CURLE_COULDNT_CONNECT;
            }
            return result;
        }
    }
    curlx_nonblock(sockfd, 1 as i32);
    (*conn).connecttime = Curl_now();
    if (*conn).num_addr > 1 as i32 {
        Curl_expire(
            data,
            (*conn).timeoutms_per_addr[0 as i32 as usize],
            EXPIRE_DNS_PER_NAME,
        );
        Curl_expire(
            data,
            (*conn).timeoutms_per_addr[1 as i32 as usize],
            EXPIRE_DNS_PER_NAME2,
        );
    }
    if !isconnected
        && (*conn).transport as u32
            != TRNSPRT_UDP as i32 as u32
    {
        if ((*conn).bits).tcp_fastopen() != 0 {
            if setsockopt(
                sockfd,
                IPPROTO_TCP as i32,
                30 as i32,
                &mut optval as *mut i32 as *mut libc::c_void,
                ::std::mem::size_of::<i32>() as u64 as socklen_t,
            ) < 0 as i32
            {
                Curl_infof(
                    data,
                    b"Failed to enable TCP Fast Open on fd %d\0" as *const u8
                        as *const i8,
                    sockfd,
                );
            }
            rc = connect(sockfd, &mut addr._sa_ex_u.addr, addr.addrlen);
        } else {
            rc = connect(sockfd, &mut addr._sa_ex_u.addr, addr.addrlen);
        }
        if -(1 as i32) == rc {
            error = *__errno_location();
        }
    } else {
        *sockp = sockfd;
        return CURLE_OK;
    }
    if -(1 as i32) == rc {
        match error {
            115 | 11 => {
                result = CURLE_OK;
            }
            _ => {
                Curl_infof(
                    data,
                    b"Immediate connect fail for %s: %s\0" as *const u8
                        as *const i8,
                    ipaddress.as_mut_ptr(),
                    Curl_strerror(
                        error,
                        buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 256]>() as u64,
                    ),
                );
                (*data).state.os_errno = error;
                Curl_closesocket(data, conn, sockfd);
                result = CURLE_COULDNT_CONNECT;
            }
        }
    }
    if result as u64 == 0 {
        *sockp = sockfd;
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_connecthost(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut remotehost: *const Curl_dns_entry,
) -> CURLcode {
    let mut result: CURLcode = CURLE_COULDNT_CONNECT;
    let mut i: i32 = 0;
    let mut timeout_ms: timediff_t = Curl_timeleft(
        data,
        0 as *mut curltime,
        1 as i32 != 0,
    );
    if timeout_ms < 0 as i32 as i64 {
        Curl_failf(data, b"Connection time-out\0" as *const u8 as *const i8);
        return CURLE_OPERATION_TIMEDOUT;
    }
    (*conn).num_addr = Curl_num_addresses((*remotehost).addr);
    let ref mut fresh9 = (*conn).tempaddr[1 as i32 as usize];
    *fresh9 = (*remotehost).addr;
    let ref mut fresh10 = (*conn).tempaddr[0 as i32 as usize];
    *fresh10 = *fresh9;
    let ref mut fresh11 = (*conn).tempsock[1 as i32 as usize];
    *fresh11 = -(1 as i32);
    (*conn).tempsock[0 as i32 as usize] = *fresh11;
    (*conn)
        .timeoutms_per_addr[0 as i32
        as usize] = if ((*(*conn).tempaddr[0 as i32 as usize]).ai_next).is_null()
    {
        timeout_ms
    } else {
        timeout_ms / 2 as i32 as i64
    };
    (*conn)
        .timeoutms_per_addr[1 as i32
        as usize] = if ((*(*conn).tempaddr[1 as i32 as usize]).ai_next).is_null()
    {
        timeout_ms
    } else {
        timeout_ms / 2 as i32 as i64
    };
    if (*conn).ip_version as i32 == 0 as i32 {
        (*conn)
            .tempfamily[0 as i32
            as usize] = if !((*conn).tempaddr[0 as i32 as usize]).is_null() {
            (*(*conn).tempaddr[0 as i32 as usize]).ai_family
        } else {
            0 as i32
        };
        (*conn)
            .tempfamily[1 as i32
            as usize] = if (*conn).tempfamily[0 as i32 as usize]
            == 10 as i32
        {
            2 as i32
        } else {
            10 as i32
        };
    } else {
        (*conn)
            .tempfamily[0 as i32
            as usize] = if (*conn).ip_version as i32 == 1 as i32 {
            2 as i32
        } else {
            10 as i32
        };
        (*conn).tempfamily[1 as i32 as usize] = 0 as i32;
        ainext(conn, 0 as i32, 0 as i32 != 0);
    }
    ainext(conn, 1 as i32, 0 as i32 != 0);
    i = 0 as i32;
    while i < 2 as i32 && result as u32 != 0 {
        while !((*conn).tempaddr[i as usize]).is_null() {
            result = singleipconnect(data, conn, (*conn).tempaddr[i as usize], i);
            if result as u64 == 0 {
                break;
            }
            ainext(conn, i, 1 as i32 != 0);
        }
        i += 1;
    }
    if result as u64 != 0 {
        return result;
    }
    Curl_expire(data, (*data).set.happy_eyeballs_timeout, EXPIRE_HAPPY_EYEBALLS);
    return CURLE_OK;
}
unsafe extern "C" fn conn_is_conn(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut param: *mut libc::c_void,
) -> i32 {
    let mut f: *mut connfind = param as *mut connfind;
    if (*conn).connection_id == (*f).id_tofind {
        let ref mut fresh12 = (*f).found;
        *fresh12 = conn;
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_getconnectinfo(
    mut data: *mut Curl_easy,
    mut connp: *mut *mut connectdata,
) -> curl_socket_t {
    if (*data).state.lastconnect_id != -(1 as i32) as i64
        && (!((*data).multi_easy).is_null() || !((*data).multi).is_null())
    {
        let mut c: *mut connectdata = 0 as *mut connectdata;
        let mut find: connfind = connfind {
            id_tofind: 0,
            found: 0 as *mut connectdata,
        };
        find.id_tofind = (*data).state.lastconnect_id;
        find.found = 0 as *mut connectdata;
        Curl_conncache_foreach(
            data,
            if !((*data).multi_easy).is_null() {
                &mut (*(*data).multi_easy).conn_cache
            } else {
                &mut (*(*data).multi).conn_cache
            },
            &mut find as *mut connfind as *mut libc::c_void,
            Some(
                conn_is_conn
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut libc::c_void,
                    ) -> i32,
            ),
        );
        if (find.found).is_null() {
            (*data).state.lastconnect_id = -(1 as i32) as i64;
            return -(1 as i32);
        }
        c = find.found;
        if !connp.is_null() {
            *connp = c;
        }
        return (*c).sock[0 as i32 as usize];
    }
    return -(1 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_connalive(mut conn: *mut connectdata) -> bool {
    if ((*conn).ssl[0 as i32 as usize]).use_0() != 0 {
        if Curl_ssl_check_cxn(conn) == 0 {
            return 0 as i32 != 0;
        }
    } else if (*conn).sock[0 as i32 as usize] == -(1 as i32) {
        return 0 as i32 != 0
    } else {
        let mut buf: i8 = 0;
        if recv(
            (*conn).sock[0 as i32 as usize],
            &mut buf as *mut i8 as *mut libc::c_void,
            1 as i32 as size_t,
            MSG_PEEK as i32,
        ) == 0 as i32 as i64
        {
            return 0 as i32 != 0;
        }
    }
    return 1 as i32 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_closesocket(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sock: curl_socket_t,
) -> i32 {
    if !conn.is_null() && ((*conn).fclosesocket).is_some() {
        if sock == (*conn).sock[1 as i32 as usize]
            && ((*conn).bits).sock_accepted() as i32 != 0
        {
            let ref mut fresh13 = (*conn).bits;
            (*fresh13).set_sock_accepted(0 as i32 as bit);
        } else {
            let mut rc: i32 = 0;
            Curl_multi_closed(data, sock);
            Curl_set_in_callback(data, 1 as i32 != 0);
            rc = ((*conn).fclosesocket)
                .expect("non-null function pointer")((*conn).closesocket_client, sock);
            Curl_set_in_callback(data, 0 as i32 != 0);
            return rc;
        }
    }
    if !conn.is_null() {
        Curl_multi_closed(data, sock);
    }
    close(sock);
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_socket(
    mut data: *mut Curl_easy,
    mut ai: *const Curl_addrinfo,
    mut addr: *mut Curl_sockaddr_ex,
    mut sockfd: *mut curl_socket_t,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut dummy: Curl_sockaddr_ex = Curl_sockaddr_ex {
        family: 0,
        socktype: 0,
        protocol: 0,
        addrlen: 0,
        _sa_ex_u: C2RustUnnamed_10 {
            addr: sockaddr {
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    };
    if addr.is_null() {
        addr = &mut dummy;
    }
    (*addr).family = (*ai).ai_family;
    (*addr)
        .socktype = if (*conn).transport as u32
        == TRNSPRT_TCP as i32 as u32
    {
        SOCK_STREAM as i32
    } else {
        SOCK_DGRAM as i32
    };
    (*addr)
        .protocol = if (*conn).transport as u32
        != TRNSPRT_TCP as i32 as u32
    {
        IPPROTO_UDP as i32
    } else {
        (*ai).ai_protocol
    };
    (*addr).addrlen = (*ai).ai_addrlen;
    if (*addr).addrlen as u64
        > ::std::mem::size_of::<Curl_sockaddr_storage>() as u64
    {
        (*addr)
            .addrlen = ::std::mem::size_of::<Curl_sockaddr_storage>() as u64
            as u32;
    }
    memcpy(
        &mut (*addr)._sa_ex_u.addr as *mut sockaddr as *mut libc::c_void,
        (*ai).ai_addr as *const libc::c_void,
        (*addr).addrlen as u64,
    );
    if ((*data).set.fopensocket).is_some() {
        Curl_set_in_callback(data, 1 as i32 != 0);
        *sockfd = ((*data).set.fopensocket)
            .expect(
                "non-null function pointer",
            )(
            (*data).set.opensocket_client,
            CURLSOCKTYPE_IPCXN,
            addr as *mut curl_sockaddr,
        );
        Curl_set_in_callback(data, 0 as i32 != 0);
    } else {
        *sockfd = socket((*addr).family, (*addr).socktype, (*addr).protocol);
    }
    if *sockfd == -(1 as i32) {
        return CURLE_COULDNT_CONNECT;
    }
    if (*conn).transport as u32 == TRNSPRT_QUIC as i32 as u32 {
        curlx_nonblock(*sockfd, 1 as i32);
    }
    if (*conn).scope_id != 0 && (*addr).family == 10 as i32 {
        let sa6: *mut sockaddr_in6 = &mut (*addr)._sa_ex_u.addr as *mut sockaddr
            as *mut libc::c_void as *mut sockaddr_in6;
        (*sa6).sin6_scope_id = (*conn).scope_id;
    }
    if (*addr).socktype == SOCK_DGRAM as i32 {
        let mut one: i32 = 1 as i32;
        match (*addr).family {
            2 => {
                setsockopt(
                    *sockfd,
                    0 as i32,
                    11 as i32,
                    &mut one as *mut i32 as *const libc::c_void,
                    ::std::mem::size_of::<i32>() as u64 as socklen_t,
                );
            }
            10 => {
                setsockopt(
                    *sockfd,
                    41 as i32,
                    25 as i32,
                    &mut one as *mut i32 as *const libc::c_void,
                    ::std::mem::size_of::<i32>() as u64 as socklen_t,
                );
            }
            _ => {}
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_conncontrol(
    mut conn: *mut connectdata,
    mut ctrl: i32,
) {
    let mut closeit: bool = false;
    closeit = ctrl == 1 as i32
        || ctrl == 2 as i32
            && (*(*conn).handler).flags
                & ((1 as i32) << 9 as i32) as u32 == 0;
    if !(ctrl == 2 as i32
        && (*(*conn).handler).flags
            & ((1 as i32) << 9 as i32) as u32 != 0)
    {
        if closeit as bit != ((*conn).bits).close() {
            let ref mut fresh14 = (*conn).bits;
            (*fresh14).set_close(closeit as bit);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_conn_data_pending(
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> bool {
    let mut readable: i32 = 0;
    if Curl_ssl_data_pending(conn, sockindex) as i32 != 0
        || Curl_recv_has_postponed_data(conn, sockindex) as i32 != 0
    {
        return 1 as i32 != 0;
    }
    readable = Curl_socket_check(
        (*conn).sock[sockindex as usize],
        -(1 as i32),
        -(1 as i32),
        0 as i32 as timediff_t,
    );
    return readable > 0 as i32 && readable & 0x1 as i32 != 0;
}
