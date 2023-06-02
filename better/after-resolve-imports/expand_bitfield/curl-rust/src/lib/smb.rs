use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn getpid() -> __pid_t;
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
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::connect::Curl_conncontrol;
pub use crate::src::lib::curl_endian::Curl_read16_be;
pub use crate::src::lib::curl_endian::Curl_read16_le;
pub use crate::src::lib::curl_ntlm_core::Curl_ntlm_core_lm_resp;
pub use crate::src::lib::curl_ntlm_core::Curl_ntlm_core_mk_lm_hash;
pub use crate::src::lib::curl_ntlm_core::Curl_ntlm_core_mk_nt_hash;
pub use crate::src::lib::escape::Curl_urldecode;
pub use crate::src::lib::progress::Curl_pgrsSetDownloadCounter;
pub use crate::src::lib::progress::Curl_pgrsSetDownloadSize;
pub use crate::src::lib::progress::Curl_pgrsSetUploadCounter;
pub use crate::src::lib::progress::Curl_pgrsSetUploadSize;
pub use crate::src::lib::sendf::Curl_client_write;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_read;
pub use crate::src::lib::sendf::Curl_write;
pub use crate::src::lib::transfer::Curl_fillreadbuffer;
pub use crate::src::lib::transfer::Curl_get_upload_buffer;
pub use crate::src::lib::vtls::vtls::Curl_ssl_connect_nonblocking;
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
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
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
pub type __uint8_t = crate::src::lib::http2::__uint8_t;
pub type __uint16_t = crate::src::lib::connect::__uint16_t;
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
pub type sa_family_t = crate::src::lib::http2::sa_family_t;
// #[derive(Copy, Clone)]

pub type sockaddr = crate::src::lib::http2::sockaddr;
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

pub type C2RustUnnamed = crate::src::lib::http2::C2RustUnnamed;
// #[derive(Copy, Clone)]

pub type SSHPROTO = crate::src::lib::http2::SSHPROTO;
// #[derive(Copy, Clone)]

pub type SMTP = crate::src::lib::http2::SMTP;
pub type curl_pp_transfer = crate::src::lib::http2::curl_pp_transfer;
pub const PPTRANSFER_NONE: curl_pp_transfer = 2;
pub const PPTRANSFER_INFO: curl_pp_transfer = 1;
pub const PPTRANSFER_BODY: curl_pp_transfer = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct smb_request {
    pub state: smb_req_state,
    pub path: *mut i8,
    pub tid: u16,
    pub fid: u16,
    pub result: CURLcode,
}
pub type smb_req_state = u32;
pub const SMB_DONE: smb_req_state = 7;
pub const SMB_TREE_DISCONNECT: smb_req_state = 6;
pub const SMB_CLOSE: smb_req_state = 5;
pub const SMB_UPLOAD: smb_req_state = 4;
pub const SMB_DOWNLOAD: smb_req_state = 3;
pub const SMB_OPEN: smb_req_state = 2;
pub const SMB_TREE_CONNECT: smb_req_state = 1;
pub const SMB_REQUESTING: smb_req_state = 0;
// #[derive(Copy, Clone)]

pub type RTSP = crate::src::lib::http2::RTSP;
// #[derive(Copy, Clone)]

pub type HTTP = crate::src::lib::http2::HTTP;
pub type uint8_t = crate::src::lib::http2::uint8_t;
pub type uint32_t = crate::src::lib::http2::uint32_t;
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
pub type C2RustUnnamed_1 = u32;
pub const HEADER_ALLBAD: C2RustUnnamed_1 = 2;
pub const HEADER_PARTHEADER: C2RustUnnamed_1 = 1;
pub const HEADER_NORMAL: C2RustUnnamed_1 = 0;
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

pub type C2RustUnnamed_4 = crate::src::lib::http2::C2RustUnnamed_4;
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
pub type C2RustUnnamed_5 = u32;
pub const TRNSPRT_QUIC: C2RustUnnamed_5 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_5 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_5 = 3;
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
pub type curl_malloc_callback = crate::src::lib::http2::curl_malloc_callback;
pub type curl_strdup_callback = crate::src::lib::altsvc::curl_strdup_callback;
pub type curl_calloc_callback = crate::src::lib::http2::curl_calloc_callback;
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_header {
    pub nbt_type: u8,
    pub nbt_flags: u8,
    pub nbt_length: u16,
    pub magic: [u8; 4],
    pub command: u8,
    pub status: u32,
    pub flags: u8,
    pub flags2: u16,
    pub pid_high: u16,
    pub signature: [u8; 8],
    pub pad: u16,
    pub tid: u16,
    pub pid: u16,
    pub uid: u16,
    pub mid: u16,
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_negotiate_response {
    pub h: smb_header,
    pub word_count: u8,
    pub dialect_index: u16,
    pub security_mode: u8,
    pub max_mpx_count: u16,
    pub max_number_vcs: u16,
    pub max_buffer_size: u32,
    pub max_raw_size: u32,
    pub session_key: u32,
    pub capabilities: u32,
    pub system_time_low: u32,
    pub system_time_high: u32,
    pub server_time_zone: u16,
    pub encryption_key_length: u8,
    pub byte_count: u16,
    pub bytes: [i8; 1],
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct andx {
    pub command: u8,
    pub pad: u8,
    pub offset: u16,
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_setup {
    pub word_count: u8,
    pub andx: andx,
    pub max_buffer_size: u16,
    pub max_mpx_count: u16,
    pub vc_number: u16,
    pub session_key: u32,
    pub lengths: [u16; 2],
    pub pad: u32,
    pub capabilities: u32,
    pub byte_count: u16,
    pub bytes: [i8; 1024],
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_tree_connect {
    pub word_count: u8,
    pub andx: andx,
    pub flags: u16,
    pub pw_len: u16,
    pub byte_count: u16,
    pub bytes: [i8; 1024],
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_nt_create {
    pub word_count: u8,
    pub andx: andx,
    pub pad: u8,
    pub name_length: u16,
    pub flags: u32,
    pub root_fid: u32,
    pub access: u32,
    pub allocation_size: curl_off_t,
    pub ext_file_attributes: u32,
    pub share_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub impersonation_level: u32,
    pub security_flags: u8,
    pub byte_count: u16,
    pub bytes: [i8; 1024],
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_nt_create_response {
    pub h: smb_header,
    pub word_count: u8,
    pub andx: andx,
    pub op_lock_level: u8,
    pub fid: u16,
    pub create_disposition: u32,
    pub create_time: curl_off_t,
    pub last_access_time: curl_off_t,
    pub last_write_time: curl_off_t,
    pub last_change_time: curl_off_t,
    pub ext_file_attributes: u32,
    pub allocation_size: curl_off_t,
    pub end_of_file: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_read {
    pub word_count: u8,
    pub andx: andx,
    pub fid: u16,
    pub offset: u32,
    pub max_bytes: u16,
    pub min_bytes: u16,
    pub timeout: u32,
    pub remaining: u16,
    pub offset_high: u32,
    pub byte_count: u16,
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_write {
    pub h: smb_header,
    pub word_count: u8,
    pub andx: andx,
    pub fid: u16,
    pub offset: u32,
    pub timeout: u32,
    pub write_mode: u16,
    pub remaining: u16,
    pub pad: u16,
    pub data_length: u16,
    pub data_offset: u16,
    pub offset_high: u32,
    pub byte_count: u16,
    pub pad2: u8,
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_close {
    pub word_count: u8,
    pub fid: u16,
    pub last_mtime: u32,
    pub byte_count: u16,
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_tree_disconnect {
    pub word_count: u8,
    pub byte_count: u16,
}
pub type urlreject = crate::src::lib::dict::urlreject;
pub const REJECT_ZERO: urlreject = 4;
pub const REJECT_CTRL: urlreject = 3;
pub const REJECT_NADA: urlreject = 2;
#[inline]
 extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as i32 >> 8 as i32 & 0xff as i32
        | (__bsx as i32 & 0xff as i32) << 8 as i32)
        as __uint16_t;
}
#[no_mangle]
pub static mut Curl_handler_smb: Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"SMB\0" as *const u8 as *const i8,
            setup_connection: Some(
                smb_setup_connection
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
            ),
            do_it: Some(
                smb_do as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            done: Some(
                smb_done
                    as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
            ),
            do_more: None,
            connect_it: Some(
                smb_connect
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            connecting: Some(
                smb_connection_state
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            doing: Some(
                smb_request_state
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            proto_getsock: Some(
                smb_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            doing_getsock: Some(
                smb_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            domore_getsock: None,
            perform_getsock: None,
            disconnect: Some(
                smb_disconnect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        bool,
                    ) -> CURLcode,
            ),
            readwrite: None,
            connection_check: None,
            attach: None,
            defport: 445 as i32,
            protocol: ((1 as i32) << 26 as i32) as u32,
            family: ((1 as i32) << 26 as i32) as u32,
            flags: 0 as i32 as u32,
        };
        init
    }
};
#[no_mangle]
pub static mut Curl_handler_smbs: Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"SMBS\0" as *const u8 as *const i8,
            setup_connection: Some(
                smb_setup_connection
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
            ),
            do_it: Some(
                smb_do as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            done: Some(
                smb_done
                    as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
            ),
            do_more: None,
            connect_it: Some(
                smb_connect
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            connecting: Some(
                smb_connection_state
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            doing: Some(
                smb_request_state
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            proto_getsock: Some(
                smb_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            doing_getsock: Some(
                smb_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            domore_getsock: None,
            perform_getsock: None,
            disconnect: Some(
                smb_disconnect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        bool,
                    ) -> CURLcode,
            ),
            readwrite: None,
            connection_check: None,
            attach: None,
            defport: 445 as i32,
            protocol: ((1 as i32) << 27 as i32) as u32,
            family: ((1 as i32) << 26 as i32) as u32,
            flags: ((1 as i32) << 0 as i32) as u32,
        };
        init
    }
};
unsafe extern "C" fn conn_state(mut data: *mut Curl_easy, mut newstate: smb_conn_state) {
    let mut smbc: *mut smb_conn = &mut (*(*data).conn).proto.smbc;
    (*smbc).state = newstate;
}
unsafe extern "C" fn request_state(
    mut data: *mut Curl_easy,
    mut newstate: smb_req_state,
) {
    let mut req: *mut smb_request = (*data).req.p.smb;
    (*req).state = newstate;
}
unsafe extern "C" fn smb_setup_connection(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut req: *mut smb_request = 0 as *mut smb_request;
    req = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(
        1 as i32 as size_t,
        ::std::mem::size_of::<smb_request>() as u64,
    ) as *mut smb_request;
    let ref mut fresh0 = (*data).req.p.smb;
    *fresh0 = req;
    if req.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    return smb_parse_url_path(data, conn);
}
unsafe extern "C" fn smb_connect(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut smbc: *mut smb_conn = &mut (*conn).proto.smbc;
    let mut slash: *mut i8 = 0 as *mut i8;
    if ((*conn).bits).user_passwd() == 0 {
        return CURLE_LOGIN_DENIED;
    }
    (*smbc).state = SMB_CONNECTING;
    let ref mut fresh1 = (*smbc).recv_buf;
    *fresh1 = Curl_cmalloc
        .expect(
            "non-null function pointer",
        )((0x8000 as i32 + 0x1000 as i32) as size_t)
        as *mut i8;
    if ((*smbc).recv_buf).is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    Curl_conncontrol(conn, 0 as i32);
    slash = strchr((*conn).user, '/' as i32);
    if slash.is_null() {
        slash = strchr((*conn).user, '\\' as i32);
    }
    if !slash.is_null() {
        let ref mut fresh2 = (*smbc).user;
        *fresh2 = slash.offset(1 as i32 as isize);
        let ref mut fresh3 = (*smbc).domain;
        *fresh3 = Curl_cstrdup.expect("non-null function pointer")((*conn).user);
        if ((*smbc).domain).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        *((*smbc).domain)
            .offset(
                slash.offset_from((*conn).user) as i64 as isize,
            ) = 0 as i32 as i8;
    } else {
        let ref mut fresh4 = (*smbc).user;
        *fresh4 = (*conn).user;
        let ref mut fresh5 = (*smbc).domain;
        *fresh5 = Curl_cstrdup.expect("non-null function pointer")((*conn).host.name);
        if ((*smbc).domain).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
unsafe extern "C" fn smb_recv_message(
    mut data: *mut Curl_easy,
    mut msg: *mut *mut libc::c_void,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut smbc: *mut smb_conn = &mut (*conn).proto.smbc;
    let mut buf: *mut i8 = (*smbc).recv_buf;
    let mut bytes_read: ssize_t = 0;
    let mut nbt_size: size_t = 0;
    let mut msg_size: size_t = 0;
    let mut len: size_t = ((0x8000 as i32 + 0x1000 as i32)
        as u64)
        .wrapping_sub((*smbc).got);
    let mut result: CURLcode = CURLE_OK;
    result = Curl_read(
        data,
        0 as i32,
        buf.offset((*smbc).got as isize),
        len,
        &mut bytes_read,
    );
    if result as u64 != 0 {
        return result;
    }
    if bytes_read == 0 {
        return CURLE_OK;
    }
    let ref mut fresh6 = (*smbc).got;
    *fresh6 = (*fresh6 as u64).wrapping_add(bytes_read as u64)
        as size_t as size_t;
    if (*smbc).got < ::std::mem::size_of::<u32>() as u64 {
        return CURLE_OK;
    }
    nbt_size = (Curl_read16_be(
        buf.offset(::std::mem::size_of::<u16>() as u64 as isize)
            as *const u8,
    ) as u64)
        .wrapping_add(::std::mem::size_of::<u32>() as u64);
    if (*smbc).got < nbt_size {
        return CURLE_OK;
    }
    msg_size = ::std::mem::size_of::<smb_header>() as u64;
    if nbt_size >= msg_size.wrapping_add(1 as i32 as u64) {
        msg_size = (msg_size as u64)
            .wrapping_add(
                (1 as i32 as u64)
                    .wrapping_add(
                        (*buf.offset(msg_size as isize) as u8
                            as u64)
                            .wrapping_mul(
                                ::std::mem::size_of::<u16>() as u64,
                            ),
                    ),
            ) as size_t as size_t;
        if nbt_size
            >= msg_size
                .wrapping_add(::std::mem::size_of::<u16>() as u64)
        {
            msg_size = (msg_size as u64)
                .wrapping_add(
                    (::std::mem::size_of::<u16>() as u64)
                        .wrapping_add(
                            Curl_read16_le(
                                &mut *buf.offset(msg_size as isize) as *mut i8
                                    as *const u8,
                            ) as u64,
                        ),
                ) as size_t as size_t;
            if nbt_size < msg_size {
                return CURLE_READ_ERROR;
            }
        }
    }
    *msg = buf as *mut libc::c_void;
    return CURLE_OK;
}
unsafe extern "C" fn smb_pop_message(mut conn: *mut connectdata) {
    let mut smbc: *mut smb_conn = &mut (*conn).proto.smbc;
    (*smbc).got = 0 as i32 as size_t;
}
unsafe extern "C" fn smb_format_message(
    mut data: *mut Curl_easy,
    mut h: *mut smb_header,
    mut cmd: u8,
    mut len: size_t,
) {
    let mut conn: *mut connectdata = (*data).conn;
    let mut smbc: *mut smb_conn = &mut (*conn).proto.smbc;
    let mut req: *mut smb_request = (*data).req.p.smb;
    let mut pid: u32 = 0;
    memset(
        h as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<smb_header>() as u64,
    );
    (*h)
        .nbt_length = __bswap_16(
        (::std::mem::size_of::<smb_header>() as u64)
            .wrapping_sub(::std::mem::size_of::<u32>() as u64)
            .wrapping_add(len) as u16,
    );
    memcpy(
        ((*h).magic).as_mut_ptr() as *mut i8 as *mut libc::c_void,
        b"\xFFSMB\0" as *const u8 as *const i8 as *const libc::c_void,
        4 as i32 as u64,
    );
    (*h).command = cmd;
    (*h).flags = (0x10 as i32 | 0x8 as i32) as u8;
    (*h).flags2 = (0x40 as i32 | 0x1 as i32) as u16;
    (*h).uid = (*smbc).uid;
    (*h).tid = (*req).tid;
    pid = getpid() as u32;
    (*h).pid_high = (pid >> 16 as i32) as u16;
    (*h).pid = pid as u16;
}
unsafe extern "C" fn smb_send(
    mut data: *mut Curl_easy,
    mut len: ssize_t,
    mut upload_size: size_t,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut smbc: *mut smb_conn = &mut (*conn).proto.smbc;
    let mut bytes_written: ssize_t = 0;
    let mut result: CURLcode = CURLE_OK;
    result = Curl_write(
        data,
        0 as i32,
        (*data).state.ulbuf as *const libc::c_void,
        len as size_t,
        &mut bytes_written,
    );
    if result as u64 != 0 {
        return result;
    }
    if bytes_written != len {
        (*smbc).send_size = len as size_t;
        (*smbc).sent = bytes_written as size_t;
    }
    (*smbc).upload_size = upload_size;
    return CURLE_OK;
}
unsafe extern "C" fn smb_flush(mut data: *mut Curl_easy) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut smbc: *mut smb_conn = &mut (*conn).proto.smbc;
    let mut bytes_written: ssize_t = 0;
    let mut len: ssize_t = ((*smbc).send_size).wrapping_sub((*smbc).sent) as ssize_t;
    let mut result: CURLcode = CURLE_OK;
    if (*smbc).send_size == 0 {
        return CURLE_OK;
    }
    result = Curl_write(
        data,
        0 as i32,
        ((*data).state.ulbuf).offset((*smbc).sent as isize) as *const libc::c_void,
        len as size_t,
        &mut bytes_written,
    );
    if result as u64 != 0 {
        return result;
    }
    if bytes_written != len {
        let ref mut fresh7 = (*smbc).sent;
        *fresh7 = (*fresh7 as u64).wrapping_add(bytes_written as u64)
            as size_t as size_t;
    } else {
        (*smbc).send_size = 0 as i32 as size_t;
    }
    return CURLE_OK;
}
unsafe extern "C" fn smb_send_message(
    mut data: *mut Curl_easy,
    mut cmd: u8,
    mut msg: *const libc::c_void,
    mut msg_len: size_t,
) -> CURLcode {
    let mut result: CURLcode = Curl_get_upload_buffer(data);
    if result as u64 != 0 {
        return result;
    }
    smb_format_message(data, (*data).state.ulbuf as *mut smb_header, cmd, msg_len);
    memcpy(
        ((*data).state.ulbuf)
            .offset(::std::mem::size_of::<smb_header>() as u64 as isize)
            as *mut libc::c_void,
        msg,
        msg_len,
    );
    return smb_send(
        data,
        (::std::mem::size_of::<smb_header>() as u64).wrapping_add(msg_len)
            as ssize_t,
        0 as i32 as size_t,
    );
}
unsafe extern "C" fn smb_send_negotiate(mut data: *mut Curl_easy) -> CURLcode {
    let mut msg: *const i8 = b"\0\x0C\0\x02NT LM 0.12\0" as *const u8
        as *const i8;
    return smb_send_message(
        data,
        0x72 as i32 as u8,
        msg as *const libc::c_void,
        15 as i32 as size_t,
    );
}
unsafe extern "C" fn smb_send_setup(mut data: *mut Curl_easy) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut smbc: *mut smb_conn = &mut (*conn).proto.smbc;
    let mut msg: smb_setup = smb_setup {
        word_count: 0,
        andx: andx {
            command: 0,
            pad: 0,
            offset: 0,
        },
        max_buffer_size: 0,
        max_mpx_count: 0,
        vc_number: 0,
        session_key: 0,
        lengths: [0; 2],
        pad: 0,
        capabilities: 0,
        byte_count: 0,
        bytes: [0; 1024],
    };
    let mut p: *mut i8 = (msg.bytes).as_mut_ptr();
    let mut lm_hash: [u8; 21] = [0; 21];
    let mut lm: [u8; 24] = [0; 24];
    let mut nt_hash: [u8; 21] = [0; 21];
    let mut nt: [u8; 24] = [0; 24];
    let mut byte_count: size_t = (::std::mem::size_of::<[u8; 24]>()
        as u64)
        .wrapping_add(::std::mem::size_of::<[u8; 24]>() as u64);
    byte_count = (byte_count as u64)
        .wrapping_add((strlen((*smbc).user)).wrapping_add(strlen((*smbc).domain)))
        as size_t as size_t;
    byte_count = (byte_count as u64)
        .wrapping_add(
            (strlen(b"x86_64-pc-linux-gnu\0" as *const u8 as *const i8))
                .wrapping_add(strlen(b"curl\0" as *const u8 as *const i8))
                .wrapping_add(4 as i32 as u64),
        ) as size_t as size_t;
    if byte_count > ::std::mem::size_of::<[i8; 1024]>() as u64 {
        return CURLE_FILESIZE_EXCEEDED;
    }
    Curl_ntlm_core_mk_lm_hash(data, (*conn).passwd, lm_hash.as_mut_ptr());
    Curl_ntlm_core_lm_resp(
        lm_hash.as_mut_ptr(),
        ((*smbc).challenge).as_mut_ptr(),
        lm.as_mut_ptr(),
    );
    Curl_ntlm_core_mk_nt_hash(data, (*conn).passwd, nt_hash.as_mut_ptr());
    Curl_ntlm_core_lm_resp(
        nt_hash.as_mut_ptr(),
        ((*smbc).challenge).as_mut_ptr(),
        nt.as_mut_ptr(),
    );
    memset(
        &mut msg as *mut smb_setup as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<smb_setup>() as u64,
    );
    msg.word_count = 0xd as i32 as u8;
    msg.andx.command = 0xff as i32 as u8;
    msg
        .max_buffer_size = (0x8000 as i32 + 0x1000 as i32)
        as u16;
    msg.max_mpx_count = 1 as i32 as u16;
    msg.vc_number = 1 as i32 as u16;
    msg.session_key = (*smbc).session_key;
    msg.capabilities = 0x8 as i32 as u32;
    msg
        .lengths[0 as i32
        as usize] = ::std::mem::size_of::<[u8; 24]>() as u64
        as u16;
    msg
        .lengths[1 as i32
        as usize] = ::std::mem::size_of::<[u8; 24]>() as u64
        as u16;
    memcpy(
        p as *mut libc::c_void,
        lm.as_mut_ptr() as *const libc::c_void,
        ::std::mem::size_of::<[u8; 24]>() as u64,
    );
    p = p.offset(::std::mem::size_of::<[u8; 24]>() as u64 as isize);
    memcpy(
        p as *mut libc::c_void,
        nt.as_mut_ptr() as *const libc::c_void,
        ::std::mem::size_of::<[u8; 24]>() as u64,
    );
    p = p.offset(::std::mem::size_of::<[u8; 24]>() as u64 as isize);
    strcpy(p, (*smbc).user);
    p = p
        .offset(
            (strlen((*smbc).user)).wrapping_add(1 as i32 as u64)
                as isize,
        );
    strcpy(p, (*smbc).domain);
    p = p
        .offset(
            (strlen((*smbc).domain)).wrapping_add(1 as i32 as u64)
                as isize,
        );
    strcpy(p, b"x86_64-pc-linux-gnu\0" as *const u8 as *const i8);
    p = p
        .offset(
            (strlen(b"x86_64-pc-linux-gnu\0" as *const u8 as *const i8))
                .wrapping_add(1 as i32 as u64) as isize,
        );
    strcpy(p, b"curl\0" as *const u8 as *const i8);
    p = p
        .offset(
            (strlen(b"curl\0" as *const u8 as *const i8))
                .wrapping_add(1 as i32 as u64) as isize,
        );
    byte_count = p.offset_from((msg.bytes).as_mut_ptr()) as i64 as size_t;
    msg.byte_count = byte_count as u16;
    return smb_send_message(
        data,
        0x73 as i32 as u8,
        &mut msg as *mut smb_setup as *const libc::c_void,
        (::std::mem::size_of::<smb_setup>() as u64)
            .wrapping_sub(::std::mem::size_of::<[i8; 1024]>() as u64)
            .wrapping_add(byte_count),
    );
}
unsafe extern "C" fn smb_send_tree_connect(mut data: *mut Curl_easy) -> CURLcode {
    let mut msg: smb_tree_connect = smb_tree_connect {
        word_count: 0,
        andx: andx {
            command: 0,
            pad: 0,
            offset: 0,
        },
        flags: 0,
        pw_len: 0,
        byte_count: 0,
        bytes: [0; 1024],
    };
    let mut conn: *mut connectdata = (*data).conn;
    let mut smbc: *mut smb_conn = &mut (*conn).proto.smbc;
    let mut p: *mut i8 = (msg.bytes).as_mut_ptr();
    let mut byte_count: size_t = (strlen((*conn).host.name))
        .wrapping_add(strlen((*smbc).share));
    byte_count = (byte_count as u64)
        .wrapping_add(
            (strlen(b"?????\0" as *const u8 as *const i8))
                .wrapping_add(5 as i32 as u64),
        ) as size_t as size_t;
    if byte_count > ::std::mem::size_of::<[i8; 1024]>() as u64 {
        return CURLE_FILESIZE_EXCEEDED;
    }
    memset(
        &mut msg as *mut smb_tree_connect as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<smb_tree_connect>() as u64,
    );
    msg.word_count = 0x4 as i32 as u8;
    msg.andx.command = 0xff as i32 as u8;
    msg.pw_len = 0 as i32 as u16;
    strcpy(p, b"\\\\\0" as *const u8 as *const i8);
    p = p.offset(strlen(b"\\\\\0" as *const u8 as *const i8) as isize);
    strcpy(p, (*conn).host.name);
    p = p.offset(strlen((*conn).host.name) as isize);
    strcpy(p, b"\\\0" as *const u8 as *const i8);
    p = p.offset(strlen(b"\\\0" as *const u8 as *const i8) as isize);
    strcpy(p, (*smbc).share);
    p = p
        .offset(
            (strlen((*smbc).share)).wrapping_add(1 as i32 as u64)
                as isize,
        );
    strcpy(p, b"?????\0" as *const u8 as *const i8);
    p = p
        .offset(
            (strlen(b"?????\0" as *const u8 as *const i8))
                .wrapping_add(1 as i32 as u64) as isize,
        );
    byte_count = p.offset_from((msg.bytes).as_mut_ptr()) as i64 as size_t;
    msg.byte_count = byte_count as u16;
    return smb_send_message(
        data,
        0x75 as i32 as u8,
        &mut msg as *mut smb_tree_connect as *const libc::c_void,
        (::std::mem::size_of::<smb_tree_connect>() as u64)
            .wrapping_sub(::std::mem::size_of::<[i8; 1024]>() as u64)
            .wrapping_add(byte_count),
    );
}
unsafe extern "C" fn smb_send_open(mut data: *mut Curl_easy) -> CURLcode {
    let mut req: *mut smb_request = (*data).req.p.smb;
    let mut msg: smb_nt_create = smb_nt_create {
        word_count: 0,
        andx: andx {
            command: 0,
            pad: 0,
            offset: 0,
        },
        pad: 0,
        name_length: 0,
        flags: 0,
        root_fid: 0,
        access: 0,
        allocation_size: 0,
        ext_file_attributes: 0,
        share_access: 0,
        create_disposition: 0,
        create_options: 0,
        impersonation_level: 0,
        security_flags: 0,
        byte_count: 0,
        bytes: [0; 1024],
    };
    let mut byte_count: size_t = 0;
    if (strlen((*req).path)).wrapping_add(1 as i32 as u64)
        > ::std::mem::size_of::<[i8; 1024]>() as u64
    {
        return CURLE_FILESIZE_EXCEEDED;
    }
    memset(
        &mut msg as *mut smb_nt_create as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<smb_nt_create>() as u64,
    );
    msg.word_count = 0x18 as i32 as u8;
    msg.andx.command = 0xff as i32 as u8;
    byte_count = strlen((*req).path);
    msg.name_length = byte_count as u16;
    msg.share_access = 0x7 as i32 as u32;
    if ((*data).set).upload() != 0 {
        msg
            .access = 0x80000000 as u32
            | 0x40000000 as i32 as u32;
        msg.create_disposition = 0x5 as i32 as u32;
    } else {
        msg.access = 0x80000000 as u32;
        msg.create_disposition = 0x1 as i32 as u32;
    }
    byte_count = byte_count.wrapping_add(1);
    msg.byte_count = byte_count as u16;
    strcpy((msg.bytes).as_mut_ptr(), (*req).path);
    return smb_send_message(
        data,
        0xa2 as i32 as u8,
        &mut msg as *mut smb_nt_create as *const libc::c_void,
        (::std::mem::size_of::<smb_nt_create>() as u64)
            .wrapping_sub(::std::mem::size_of::<[i8; 1024]>() as u64)
            .wrapping_add(byte_count),
    );
}
unsafe extern "C" fn smb_send_close(mut data: *mut Curl_easy) -> CURLcode {
    let mut req: *mut smb_request = (*data).req.p.smb;
    let mut msg: smb_close = smb_close {
        word_count: 0,
        fid: 0,
        last_mtime: 0,
        byte_count: 0,
    };
    memset(
        &mut msg as *mut smb_close as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<smb_close>() as u64,
    );
    msg.word_count = 0x3 as i32 as u8;
    msg.fid = (*req).fid;
    return smb_send_message(
        data,
        0x4 as i32 as u8,
        &mut msg as *mut smb_close as *const libc::c_void,
        ::std::mem::size_of::<smb_close>() as u64,
    );
}
unsafe extern "C" fn smb_send_tree_disconnect(mut data: *mut Curl_easy) -> CURLcode {
    let mut msg: smb_tree_disconnect = smb_tree_disconnect {
        word_count: 0,
        byte_count: 0,
    };
    memset(
        &mut msg as *mut smb_tree_disconnect as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<smb_tree_disconnect>() as u64,
    );
    return smb_send_message(
        data,
        0x71 as i32 as u8,
        &mut msg as *mut smb_tree_disconnect as *const libc::c_void,
        ::std::mem::size_of::<smb_tree_disconnect>() as u64,
    );
}
unsafe extern "C" fn smb_send_read(mut data: *mut Curl_easy) -> CURLcode {
    let mut req: *mut smb_request = (*data).req.p.smb;
    let mut offset: curl_off_t = (*data).req.offset;
    let mut msg: smb_read = smb_read {
        word_count: 0,
        andx: andx {
            command: 0,
            pad: 0,
            offset: 0,
        },
        fid: 0,
        offset: 0,
        max_bytes: 0,
        min_bytes: 0,
        timeout: 0,
        remaining: 0,
        offset_high: 0,
        byte_count: 0,
    };
    memset(
        &mut msg as *mut smb_read as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<smb_read>() as u64,
    );
    msg.word_count = 0xc as i32 as u8;
    msg.andx.command = 0xff as i32 as u8;
    msg.fid = (*req).fid;
    msg.offset = offset as u32;
    msg.offset_high = (offset >> 32 as i32) as u32;
    msg.min_bytes = 0x8000 as i32 as u16;
    msg.max_bytes = 0x8000 as i32 as u16;
    return smb_send_message(
        data,
        0x2e as i32 as u8,
        &mut msg as *mut smb_read as *const libc::c_void,
        ::std::mem::size_of::<smb_read>() as u64,
    );
}
unsafe extern "C" fn smb_send_write(mut data: *mut Curl_easy) -> CURLcode {
    let mut msg: *mut smb_write = 0 as *mut smb_write;
    let mut req: *mut smb_request = (*data).req.p.smb;
    let mut offset: curl_off_t = (*data).req.offset;
    let mut upload_size: curl_off_t = (*data).req.size - (*data).req.bytecount;
    let mut result: CURLcode = Curl_get_upload_buffer(data);
    if result as u64 != 0 {
        return result;
    }
    msg = (*data).state.ulbuf as *mut smb_write;
    if upload_size >= (0x8000 as i32 - 1 as i32) as i64 {
        upload_size = (0x8000 as i32 - 1 as i32) as curl_off_t;
    }
    memset(
        msg as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<smb_write>() as u64,
    );
    (*msg).word_count = 0xe as i32 as u8;
    (*msg).andx.command = 0xff as i32 as u8;
    (*msg).fid = (*req).fid;
    (*msg).offset = offset as u32;
    (*msg).offset_high = (offset >> 32 as i32) as u32;
    (*msg).data_length = upload_size as u16;
    (*msg)
        .data_offset = (::std::mem::size_of::<smb_write>() as u64)
        .wrapping_sub(::std::mem::size_of::<u32>() as u64)
        as u16;
    (*msg)
        .byte_count = (upload_size + 1 as i32 as i64) as u16;
    smb_format_message(
        data,
        &mut (*msg).h,
        0x2f as i32 as u8,
        (::std::mem::size_of::<smb_write>() as u64)
            .wrapping_sub(::std::mem::size_of::<smb_header>() as u64)
            .wrapping_add(upload_size as size_t),
    );
    return smb_send(
        data,
        ::std::mem::size_of::<smb_write>() as u64 as ssize_t,
        upload_size as size_t,
    );
}
unsafe extern "C" fn smb_send_and_recv(
    mut data: *mut Curl_easy,
    mut msg: *mut *mut libc::c_void,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut smbc: *mut smb_conn = &mut (*conn).proto.smbc;
    let mut result: CURLcode = CURLE_OK;
    *msg = 0 as *mut libc::c_void;
    if (*smbc).send_size == 0 && (*smbc).upload_size != 0 {
        let mut nread: size_t = if (*smbc).upload_size
            > (*data).set.upload_buffer_size as size_t
        {
            (*data).set.upload_buffer_size as size_t
        } else {
            (*smbc).upload_size
        };
        let ref mut fresh8 = (*data).req.upload_fromhere;
        *fresh8 = (*data).state.ulbuf;
        result = Curl_fillreadbuffer(data, nread, &mut nread);
        if result as u32 != 0
            && result as u32 != CURLE_AGAIN as i32 as u32
        {
            return result;
        }
        if nread == 0 {
            return CURLE_OK;
        }
        let ref mut fresh9 = (*smbc).upload_size;
        *fresh9 = (*fresh9 as u64).wrapping_sub(nread) as size_t as size_t;
        (*smbc).send_size = nread;
        (*smbc).sent = 0 as i32 as size_t;
    }
    if (*smbc).send_size != 0 {
        result = smb_flush(data);
        if result as u64 != 0 {
            return result;
        }
    }
    if (*smbc).send_size != 0 || (*smbc).upload_size != 0 {
        return CURLE_AGAIN;
    }
    return smb_recv_message(data, msg);
}
unsafe extern "C" fn smb_connection_state(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut smbc: *mut smb_conn = &mut (*conn).proto.smbc;
    let mut nrsp: *mut smb_negotiate_response = 0 as *mut smb_negotiate_response;
    let mut h: *mut smb_header = 0 as *mut smb_header;
    let mut result: CURLcode = CURLE_OK;
    let mut msg: *mut libc::c_void = 0 as *mut libc::c_void;
    if (*smbc).state as u32 == SMB_CONNECTING as i32 as u32 {
        if (*(*conn).handler).flags
            & ((1 as i32) << 0 as i32) as u32 != 0
        {
            let mut ssl_done: bool = 0 as i32 != 0;
            result = Curl_ssl_connect_nonblocking(
                data,
                conn,
                0 as i32 != 0,
                0 as i32,
                &mut ssl_done,
            );
            if result as u32 != 0
                && result as u32 != CURLE_AGAIN as i32 as u32
            {
                return result;
            }
            if !ssl_done {
                return CURLE_OK;
            }
        }
        result = smb_send_negotiate(data);
        if result as u64 != 0 {
            Curl_conncontrol(conn, 1 as i32);
            return result;
        }
        conn_state(data, SMB_NEGOTIATE);
    }
    result = smb_send_and_recv(data, &mut msg);
    if result as u32 != 0
        && result as u32 != CURLE_AGAIN as i32 as u32
    {
        Curl_conncontrol(conn, 1 as i32);
        return result;
    }
    if msg.is_null() {
        return CURLE_OK;
    }
    h = msg as *mut smb_header;
    match (*smbc).state as u32 {
        2 => {
            if (*smbc).got
                < (::std::mem::size_of::<smb_negotiate_response>() as u64)
                    .wrapping_add(
                        ::std::mem::size_of::<[u8; 8]>() as u64,
                    )
                    .wrapping_sub(1 as i32 as u64) || (*h).status != 0
            {
                Curl_conncontrol(conn, 1 as i32);
                return CURLE_COULDNT_CONNECT;
            }
            nrsp = msg as *mut smb_negotiate_response;
            memcpy(
                ((*smbc).challenge).as_mut_ptr() as *mut libc::c_void,
                ((*nrsp).bytes).as_mut_ptr() as *const libc::c_void,
                ::std::mem::size_of::<[u8; 8]>() as u64,
            );
            (*smbc).session_key = (*nrsp).session_key;
            result = smb_send_setup(data);
            if result as u64 != 0 {
                Curl_conncontrol(conn, 1 as i32);
                return result;
            }
            conn_state(data, SMB_SETUP);
        }
        3 => {
            if (*h).status != 0 {
                Curl_conncontrol(conn, 1 as i32);
                return CURLE_LOGIN_DENIED;
            }
            (*smbc).uid = (*h).uid;
            conn_state(data, SMB_CONNECTED);
            *done = 1 as i32 != 0;
        }
        _ => {
            smb_pop_message(conn);
            return CURLE_OK;
        }
    }
    smb_pop_message(conn);
    return CURLE_OK;
}
unsafe extern "C" fn get_posix_time(mut out: *mut time_t, mut timestamp: curl_off_t) {
    timestamp -= 116444736000000000 as i64;
    timestamp /= 10000000 as i32 as i64;
    *out = timestamp;
}
unsafe extern "C" fn smb_request_state(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut req: *mut smb_request = (*data).req.p.smb;
    let mut h: *mut smb_header = 0 as *mut smb_header;
    let mut smbc: *mut smb_conn = &mut (*conn).proto.smbc;
    let mut next_state: smb_req_state = SMB_DONE;
    let mut len: u16 = 0;
    let mut off: u16 = 0;
    let mut result: CURLcode = CURLE_OK;
    let mut msg: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut smb_m: *const smb_nt_create_response = 0 as *const smb_nt_create_response;
    if (*req).state as u32 == SMB_REQUESTING as i32 as u32 {
        result = smb_send_tree_connect(data);
        if result as u64 != 0 {
            Curl_conncontrol(conn, 1 as i32);
            return result;
        }
        request_state(data, SMB_TREE_CONNECT);
    }
    result = smb_send_and_recv(data, &mut msg);
    if result as u32 != 0
        && result as u32 != CURLE_AGAIN as i32 as u32
    {
        Curl_conncontrol(conn, 1 as i32);
        return result;
    }
    if msg.is_null() {
        return CURLE_OK;
    }
    h = msg as *mut smb_header;
    let mut current_block_72: u64;
    match (*req).state as u32 {
        1 => {
            if (*h).status != 0 {
                (*req).result = CURLE_REMOTE_FILE_NOT_FOUND;
                if (*h).status == 0x50001 as i32 as u32 {
                    (*req).result = CURLE_REMOTE_ACCESS_DENIED;
                }
            } else {
                (*req).tid = (*h).tid;
                next_state = SMB_OPEN;
            }
        }
        2 => {
            if (*h).status != 0
                || (*smbc).got
                    < ::std::mem::size_of::<smb_nt_create_response>() as u64
            {
                (*req).result = CURLE_REMOTE_FILE_NOT_FOUND;
                if (*h).status == 0x50001 as i32 as u32 {
                    (*req).result = CURLE_REMOTE_ACCESS_DENIED;
                }
                next_state = SMB_TREE_DISCONNECT;
            } else {
                smb_m = msg as *const smb_nt_create_response;
                (*req).fid = (*smb_m).fid;
                (*data).req.offset = 0 as i32 as curl_off_t;
                if ((*data).set).upload() != 0 {
                    (*data).req.size = (*data).state.infilesize;
                    Curl_pgrsSetUploadSize(data, (*data).req.size);
                    next_state = SMB_UPLOAD;
                } else {
                    smb_m = msg as *const smb_nt_create_response;
                    (*data).req.size = (*smb_m).end_of_file;
                    if (*data).req.size < 0 as i32 as i64 {
                        (*req).result = CURLE_WEIRD_SERVER_REPLY;
                        next_state = SMB_CLOSE;
                    } else {
                        Curl_pgrsSetDownloadSize(data, (*data).req.size);
                        if ((*data).set).get_filetime() != 0 {
                            get_posix_time(
                                &mut (*data).info.filetime,
                                (*smb_m).last_change_time,
                            );
                        }
                        next_state = SMB_DOWNLOAD;
                    }
                }
            }
        }
        3 => {
            if (*h).status != 0
                || (*smbc).got
                    < (::std::mem::size_of::<smb_header>() as u64)
                        .wrapping_add(14 as i32 as u64)
            {
                (*req).result = CURLE_RECV_ERROR;
                next_state = SMB_CLOSE;
            } else {
                len = Curl_read16_le(
                    (msg as *const u8)
                        .offset(
                            ::std::mem::size_of::<smb_header>() as u64 as isize,
                        )
                        .offset(11 as i32 as isize),
                );
                off = Curl_read16_le(
                    (msg as *const u8)
                        .offset(
                            ::std::mem::size_of::<smb_header>() as u64 as isize,
                        )
                        .offset(13 as i32 as isize),
                );
                if len as i32 > 0 as i32 {
                    if (off as u64)
                        .wrapping_add(
                            ::std::mem::size_of::<u32>() as u64,
                        )
                        .wrapping_add(len as u64) > (*smbc).got
                    {
                        Curl_failf(
                            data,
                            b"Invalid input packet\0" as *const u8 as *const i8,
                        );
                        result = CURLE_RECV_ERROR;
                    } else {
                        result = Curl_client_write(
                            data,
                            (1 as i32) << 0 as i32,
                            (msg as *mut i8)
                                .offset(off as i32 as isize)
                                .offset(
                                    ::std::mem::size_of::<u32>() as u64
                                        as isize,
                                ),
                            len as size_t,
                        );
                    }
                    if result as u64 != 0 {
                        (*req).result = result;
                        next_state = SMB_CLOSE;
                        current_block_72 = 8716029205547827362;
                    } else {
                        current_block_72 = 1134115459065347084;
                    }
                } else {
                    current_block_72 = 1134115459065347084;
                }
                match current_block_72 {
                    8716029205547827362 => {}
                    _ => {
                        let ref mut fresh10 = (*data).req.bytecount;
                        *fresh10 += len as i64;
                        let ref mut fresh11 = (*data).req.offset;
                        *fresh11 += len as i64;
                        Curl_pgrsSetDownloadCounter(data, (*data).req.bytecount);
                        next_state = (if (len as i32) < 0x8000 as i32 {
                            SMB_CLOSE as i32
                        } else {
                            SMB_DOWNLOAD as i32
                        }) as smb_req_state;
                    }
                }
            }
        }
        4 => {
            if (*h).status != 0
                || (*smbc).got
                    < (::std::mem::size_of::<smb_header>() as u64)
                        .wrapping_add(6 as i32 as u64)
            {
                (*req).result = CURLE_UPLOAD_FAILED;
                next_state = SMB_CLOSE;
            } else {
                len = Curl_read16_le(
                    (msg as *const u8)
                        .offset(
                            ::std::mem::size_of::<smb_header>() as u64 as isize,
                        )
                        .offset(5 as i32 as isize),
                );
                let ref mut fresh12 = (*data).req.bytecount;
                *fresh12 += len as i64;
                let ref mut fresh13 = (*data).req.offset;
                *fresh13 += len as i64;
                Curl_pgrsSetUploadCounter(data, (*data).req.bytecount);
                if (*data).req.bytecount >= (*data).req.size {
                    next_state = SMB_CLOSE;
                } else {
                    next_state = SMB_UPLOAD;
                }
            }
        }
        5 => {
            next_state = SMB_TREE_DISCONNECT;
        }
        6 => {
            next_state = SMB_DONE;
        }
        _ => {
            smb_pop_message(conn);
            return CURLE_OK;
        }
    }
    smb_pop_message(conn);
    match next_state as u32 {
        2 => {
            result = smb_send_open(data);
        }
        3 => {
            result = smb_send_read(data);
        }
        4 => {
            result = smb_send_write(data);
        }
        5 => {
            result = smb_send_close(data);
        }
        6 => {
            result = smb_send_tree_disconnect(data);
        }
        7 => {
            result = (*req).result;
            *done = 1 as i32 != 0;
        }
        _ => {}
    }
    if result as u64 != 0 {
        Curl_conncontrol(conn, 1 as i32);
        return result;
    }
    request_state(data, next_state);
    return CURLE_OK;
}
unsafe extern "C" fn smb_done(
    mut data: *mut Curl_easy,
    mut status: CURLcode,
    mut premature: bool,
) -> CURLcode {
    Curl_cfree
        .expect("non-null function pointer")((*data).req.p.smb as *mut libc::c_void);
    let ref mut fresh14 = (*data).req.p.smb;
    *fresh14 = 0 as *mut smb_request;
    return status;
}
unsafe extern "C" fn smb_disconnect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut dead: bool,
) -> CURLcode {
    let mut smbc: *mut smb_conn = &mut (*conn).proto.smbc;
    Curl_cfree.expect("non-null function pointer")((*smbc).share as *mut libc::c_void);
    let ref mut fresh15 = (*smbc).share;
    *fresh15 = 0 as *mut i8;
    Curl_cfree.expect("non-null function pointer")((*smbc).domain as *mut libc::c_void);
    let ref mut fresh16 = (*smbc).domain;
    *fresh16 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*smbc).recv_buf as *mut libc::c_void);
    let ref mut fresh17 = (*smbc).recv_buf;
    *fresh17 = 0 as *mut i8;
    return CURLE_OK;
}
unsafe extern "C" fn smb_getsock(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> i32 {
    *socks.offset(0 as i32 as isize) = (*conn).sock[0 as i32 as usize];
    return (1 as i32) << 0 as i32
        | (1 as i32) << 16 as i32 + 0 as i32;
}
unsafe extern "C" fn smb_do(mut data: *mut Curl_easy, mut done: *mut bool) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut smbc: *mut smb_conn = &mut (*conn).proto.smbc;
    *done = 0 as i32 != 0;
    if !((*smbc).share).is_null() {
        return CURLE_OK;
    }
    return CURLE_URL_MALFORMAT;
}
unsafe extern "C" fn smb_parse_url_path(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut req: *mut smb_request = (*data).req.p.smb;
    let mut smbc: *mut smb_conn = &mut (*conn).proto.smbc;
    let mut path: *mut i8 = 0 as *mut i8;
    let mut slash: *mut i8 = 0 as *mut i8;
    let mut result: CURLcode = Curl_urldecode(
        data,
        (*data).state.up.path,
        0 as i32 as size_t,
        &mut path,
        0 as *mut size_t,
        REJECT_CTRL,
    );
    if result as u64 != 0 {
        return result;
    }
    let ref mut fresh18 = (*smbc).share;
    *fresh18 = Curl_cstrdup
        .expect(
            "non-null function pointer",
        )(
        if *path as i32 == '/' as i32 || *path as i32 == '\\' as i32 {
            path.offset(1 as i32 as isize)
        } else {
            path
        },
    );
    Curl_cfree.expect("non-null function pointer")(path as *mut libc::c_void);
    if ((*smbc).share).is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    slash = strchr((*smbc).share, '/' as i32);
    if slash.is_null() {
        slash = strchr((*smbc).share, '\\' as i32);
    }
    if slash.is_null() {
        Curl_cfree
            .expect("non-null function pointer")((*smbc).share as *mut libc::c_void);
        let ref mut fresh19 = (*smbc).share;
        *fresh19 = 0 as *mut i8;
        return CURLE_URL_MALFORMAT;
    }
    let fresh20 = slash;
    slash = slash.offset(1);
    *fresh20 = 0 as i32 as i8;
    let ref mut fresh21 = (*req).path;
    *fresh21 = slash;
    while *slash != 0 {
        if *slash as i32 == '/' as i32 {
            *slash = '\\' as i32 as i8;
        }
        slash = slash.offset(1);
    }
    return CURLE_OK;
}
