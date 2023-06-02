use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    pub type internal_state;
    
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> *mut libc::c_void;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strlen(_: *const i8) -> u64;
    
    fn zlibVersion() -> *const i8;
    fn inflate(strm: z_streamp, flush: i32) -> i32;
    fn inflateEnd(strm: z_streamp) -> i32;
    fn inflateInit_(
        strm: z_streamp,
        version: *const i8,
        stream_size: i32,
    ) -> i32;
    fn inflateInit2_(
        strm: z_streamp,
        windowBits: i32,
        version: *const i8,
        stream_size: i32,
    ) -> i32;
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::curl_ctype::Curl_isspace;
pub use crate::src::lib::http_chunks::Curl_httpchunk_init;
pub use crate::src::lib::sendf::Curl_client_write;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::strcase::Curl_strncasecompare;
pub use crate::src::lib::strdup::Curl_saferealloc;
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::http2::curl_pushheaders;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct contenc_writer {
    pub handler: *const content_encoding,
    pub downstream: *mut contenc_writer,
    pub params: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct content_encoding {
    pub name: *const i8,
    pub alias: *const i8,
    pub init_writer: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer) -> CURLcode,
    >,
    pub unencode_write: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut contenc_writer,
            *const i8,
            size_t,
        ) -> CURLcode,
    >,
    pub close_writer: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer) -> (),
    >,
    pub paramsize: size_t,
}
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
pub type Byte = u8;
pub type uInt = u32;
pub type uLong = u64;
pub type Bytef = Byte;
pub type voidpf = *mut libc::c_void;
pub type alloc_func = Option::<unsafe extern "C" fn(voidpf, uInt, uInt) -> voidpf>;
pub type free_func = Option::<unsafe extern "C" fn(voidpf, voidpf) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct z_stream_s {
    pub next_in: *mut Bytef,
    pub avail_in: uInt,
    pub total_in: uLong,
    pub next_out: *mut Bytef,
    pub avail_out: uInt,
    pub total_out: uLong,
    pub msg: *mut i8,
    pub state: *mut internal_state,
    pub zalloc: alloc_func,
    pub zfree: free_func,
    pub opaque: voidpf,
    pub data_type: i32,
    pub adler: uLong,
    pub reserved: uLong,
}
pub type z_stream = z_stream_s;
pub type z_streamp = *mut z_stream;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct zlib_params {
    pub zlib_init: zlibInitState,
    pub trailerlen: uInt,
    pub z: z_stream,
}
pub type zlibInitState = u32;
pub const ZLIB_INIT_GZIP: zlibInitState = 6;
pub const ZLIB_GZIP_INFLATING: zlibInitState = 5;
pub const ZLIB_GZIP_HEADER: zlibInitState = 4;
pub const ZLIB_EXTERNAL_TRAILER: zlibInitState = 3;
pub const ZLIB_INFLATING: zlibInitState = 2;
pub const ZLIB_INIT: zlibInitState = 1;
pub const ZLIB_UNINIT: zlibInitState = 0;
pub const GZIP_BAD: C2RustUnnamed_6 = 1;
pub const GZIP_UNDERFLOW: C2RustUnnamed_6 = 2;
pub const GZIP_OK: C2RustUnnamed_6 = 0;
pub type C2RustUnnamed_6 = u32;
unsafe extern "C" fn zalloc_cb(
    mut opaque: voidpf,
    mut items: u32,
    mut size: u32,
) -> voidpf {
    return Curl_ccalloc
        .expect("non-null function pointer")(items as size_t, size as size_t);
}
unsafe extern "C" fn zfree_cb(mut opaque: voidpf, mut ptr: voidpf) {
    Curl_cfree.expect("non-null function pointer")(ptr);
}
unsafe extern "C" fn process_zlib_error(
    mut data: *mut Curl_easy,
    mut z: *mut z_stream,
) -> CURLcode {
    if !((*z).msg).is_null() {
        Curl_failf(
            data,
            b"Error while processing content unencoding: %s\0" as *const u8
                as *const i8,
            (*z).msg,
        );
    } else {
        Curl_failf(
            data,
            b"Error while processing content unencoding: Unknown failure within decompression software.\0"
                as *const u8 as *const i8,
        );
    }
    return CURLE_BAD_CONTENT_ENCODING;
}
unsafe extern "C" fn exit_zlib(
    mut data: *mut Curl_easy,
    mut z: *mut z_stream,
    mut zlib_init: *mut zlibInitState,
    mut result: CURLcode,
) -> CURLcode {
    if *zlib_init as u32 == ZLIB_GZIP_HEADER as i32 as u32 {
        Curl_cfree
            .expect("non-null function pointer")((*z).next_in as *mut libc::c_void);
        let ref mut fresh0 = (*z).next_in;
        *fresh0 = 0 as *mut Bytef;
    }
    if *zlib_init as u32 != ZLIB_UNINIT as i32 as u32 {
        if inflateEnd(z) != 0 as i32
            && result as u32 == CURLE_OK as i32 as u32
        {
            result = process_zlib_error(data, z);
        }
        *zlib_init = ZLIB_UNINIT;
    }
    return result;
}
unsafe extern "C" fn process_trailer(
    mut data: *mut Curl_easy,
    mut zp: *mut zlib_params,
) -> CURLcode {
    let mut z: *mut z_stream = &mut (*zp).z;
    let mut result: CURLcode = CURLE_OK;
    let mut len: uInt = if (*z).avail_in < (*zp).trailerlen {
        (*z).avail_in
    } else {
        (*zp).trailerlen
    };
    let ref mut fresh1 = (*zp).trailerlen;
    *fresh1 = (*fresh1 as u32).wrapping_sub(len) as uInt as uInt;
    let ref mut fresh2 = (*z).avail_in;
    *fresh2 = (*fresh2 as u32).wrapping_sub(len) as uInt as uInt;
    let ref mut fresh3 = (*z).next_in;
    *fresh3 = (*fresh3).offset(len as isize);
    if (*z).avail_in != 0 {
        result = CURLE_WRITE_ERROR;
    }
    if result as u32 != 0 || (*zp).trailerlen == 0 {
        result = exit_zlib(data, z, &mut (*zp).zlib_init, result);
    } else {
        (*zp).zlib_init = ZLIB_EXTERNAL_TRAILER;
    }
    return result;
}
unsafe extern "C" fn inflate_stream(
    mut data: *mut Curl_easy,
    mut writer: *mut contenc_writer,
    mut started: zlibInitState,
) -> CURLcode {
    let mut zp: *mut zlib_params = &mut (*writer).params as *mut *mut libc::c_void
        as *mut zlib_params;
    let mut z: *mut z_stream = &mut (*zp).z;
    let mut nread: uInt = (*z).avail_in;
    let mut orig_in: *mut Bytef = (*z).next_in;
    let mut done: bool = 0 as i32 != 0;
    let mut result: CURLcode = CURLE_OK;
    let mut decomp: *mut i8 = 0 as *mut i8;
    if (*zp).zlib_init as u32 != ZLIB_INIT as i32 as u32
        && (*zp).zlib_init as u32
            != ZLIB_INFLATING as i32 as u32
        && (*zp).zlib_init as u32
            != ZLIB_INIT_GZIP as i32 as u32
        && (*zp).zlib_init as u32
            != ZLIB_GZIP_INFLATING as i32 as u32
    {
        return exit_zlib(data, z, &mut (*zp).zlib_init, CURLE_WRITE_ERROR);
    }
    decomp = Curl_cmalloc
        .expect("non-null function pointer")(16384 as i32 as size_t)
        as *mut i8;
    if decomp.is_null() {
        return exit_zlib(data, z, &mut (*zp).zlib_init, CURLE_OUT_OF_MEMORY);
    }
    while !done {
        let mut status: i32 = 0;
        done = 1 as i32 != 0;
        let ref mut fresh4 = (*z).next_out;
        *fresh4 = decomp as *mut Bytef;
        (*z).avail_out = 16384 as i32 as uInt;
        status = inflate(z, 5 as i32);
        if (*z).avail_out != 16384 as i32 as u32 {
            if status == 0 as i32 || status == 1 as i32 {
                (*zp).zlib_init = started;
                result = Curl_unencode_write(
                    data,
                    (*writer).downstream,
                    decomp,
                    (16384 as i32 as u32).wrapping_sub((*z).avail_out)
                        as size_t,
                );
                if result as u64 != 0 {
                    exit_zlib(data, z, &mut (*zp).zlib_init, result);
                    break;
                }
            }
        }
        let mut current_block_21: u64;
        match status {
            0 => {
                done = 0 as i32 != 0;
                current_block_21 = 10692455896603418738;
            }
            -5 => {
                current_block_21 = 10692455896603418738;
            }
            1 => {
                result = process_trailer(data, zp);
                current_block_21 = 10692455896603418738;
            }
            -3 => {
                if (*zp).zlib_init as u32
                    == ZLIB_INIT as i32 as u32
                {
                    inflateEnd(z);
                    if inflateInit2_(
                        z,
                        -(15 as i32),
                        b"1.2.11\0" as *const u8 as *const i8,
                        ::std::mem::size_of::<z_stream>() as u64 as i32,
                    ) == 0 as i32
                    {
                        let ref mut fresh5 = (*z).next_in;
                        *fresh5 = orig_in;
                        (*z).avail_in = nread;
                        (*zp).zlib_init = ZLIB_INFLATING;
                        (*zp).trailerlen = 4 as i32 as uInt;
                        done = 0 as i32 != 0;
                        current_block_21 = 10692455896603418738;
                    } else {
                        (*zp).zlib_init = ZLIB_UNINIT;
                        current_block_21 = 13757731702203840573;
                    }
                } else {
                    current_block_21 = 13757731702203840573;
                }
            }
            _ => {
                current_block_21 = 13757731702203840573;
            }
        }
        match current_block_21 {
            13757731702203840573 => {
                result = exit_zlib(
                    data,
                    z,
                    &mut (*zp).zlib_init,
                    process_zlib_error(data, z),
                );
            }
            _ => {}
        }
    }
    Curl_cfree.expect("non-null function pointer")(decomp as *mut libc::c_void);
    if nread != 0
        && (*zp).zlib_init as u32 == ZLIB_INIT as i32 as u32
    {
        (*zp).zlib_init = started;
    }
    return result;
}
unsafe extern "C" fn deflate_init_writer(
    mut data: *mut Curl_easy,
    mut writer: *mut contenc_writer,
) -> CURLcode {
    let mut zp: *mut zlib_params = &mut (*writer).params as *mut *mut libc::c_void
        as *mut zlib_params;
    let mut z: *mut z_stream = &mut (*zp).z;
    if ((*writer).downstream).is_null() {
        return CURLE_WRITE_ERROR;
    }
    let ref mut fresh6 = (*z).zalloc;
    *fresh6 = ::std::mem::transmute::<
        Option::<unsafe extern "C" fn(voidpf, u32, u32) -> voidpf>,
        alloc_func,
    >(
        Some(
            zalloc_cb
                as unsafe extern "C" fn(voidpf, u32, u32) -> voidpf,
        ),
    );
    let ref mut fresh7 = (*z).zfree;
    *fresh7 = ::std::mem::transmute::<
        Option::<unsafe extern "C" fn(voidpf, voidpf) -> ()>,
        free_func,
    >(Some(zfree_cb as unsafe extern "C" fn(voidpf, voidpf) -> ()));
    if inflateInit_(
        z,
        b"1.2.11\0" as *const u8 as *const i8,
        ::std::mem::size_of::<z_stream>() as u64 as i32,
    ) != 0 as i32
    {
        return process_zlib_error(data, z);
    }
    (*zp).zlib_init = ZLIB_INIT;
    return CURLE_OK;
}
unsafe extern "C" fn deflate_unencode_write(
    mut data: *mut Curl_easy,
    mut writer: *mut contenc_writer,
    mut buf: *const i8,
    mut nbytes: size_t,
) -> CURLcode {
    let mut zp: *mut zlib_params = &mut (*writer).params as *mut *mut libc::c_void
        as *mut zlib_params;
    let mut z: *mut z_stream = &mut (*zp).z;
    let ref mut fresh8 = (*z).next_in;
    *fresh8 = buf as *mut Bytef;
    (*z).avail_in = nbytes as uInt;
    if (*zp).zlib_init as u32
        == ZLIB_EXTERNAL_TRAILER as i32 as u32
    {
        return process_trailer(data, zp);
    }
    return inflate_stream(data, writer, ZLIB_INFLATING);
}
unsafe extern "C" fn deflate_close_writer(
    mut data: *mut Curl_easy,
    mut writer: *mut contenc_writer,
) {
    let mut zp: *mut zlib_params = &mut (*writer).params as *mut *mut libc::c_void
        as *mut zlib_params;
    let mut z: *mut z_stream = &mut (*zp).z;
    exit_zlib(data, z, &mut (*zp).zlib_init, CURLE_OK);
}
static mut deflate_encoding: content_encoding = unsafe {
    {
        let mut init = content_encoding {
            name: b"deflate\0" as *const u8 as *const i8,
            alias: 0 as *const i8,
            init_writer: Some(
                deflate_init_writer
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut contenc_writer,
                    ) -> CURLcode,
            ),
            unencode_write: Some(
                deflate_unencode_write
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut contenc_writer,
                        *const i8,
                        size_t,
                    ) -> CURLcode,
            ),
            close_writer: Some(
                deflate_close_writer
                    as unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer) -> (),
            ),
            paramsize: ::std::mem::size_of::<zlib_params>() as u64,
        };
        init
    }
};
unsafe extern "C" fn gzip_init_writer(
    mut data: *mut Curl_easy,
    mut writer: *mut contenc_writer,
) -> CURLcode {
    let mut zp: *mut zlib_params = &mut (*writer).params as *mut *mut libc::c_void
        as *mut zlib_params;
    let mut z: *mut z_stream = &mut (*zp).z;
    if ((*writer).downstream).is_null() {
        return CURLE_WRITE_ERROR;
    }
    let ref mut fresh9 = (*z).zalloc;
    *fresh9 = ::std::mem::transmute::<
        Option::<unsafe extern "C" fn(voidpf, u32, u32) -> voidpf>,
        alloc_func,
    >(
        Some(
            zalloc_cb
                as unsafe extern "C" fn(voidpf, u32, u32) -> voidpf,
        ),
    );
    let ref mut fresh10 = (*z).zfree;
    *fresh10 = ::std::mem::transmute::<
        Option::<unsafe extern "C" fn(voidpf, voidpf) -> ()>,
        free_func,
    >(Some(zfree_cb as unsafe extern "C" fn(voidpf, voidpf) -> ()));
    if strcmp(zlibVersion(), b"1.2.0.4\0" as *const u8 as *const i8)
        >= 0 as i32
    {
        if inflateInit2_(
            z,
            15 as i32 + 32 as i32,
            b"1.2.11\0" as *const u8 as *const i8,
            ::std::mem::size_of::<z_stream>() as u64 as i32,
        ) != 0 as i32
        {
            return process_zlib_error(data, z);
        }
        (*zp).zlib_init = ZLIB_INIT_GZIP;
    } else {
        if inflateInit2_(
            z,
            -(15 as i32),
            b"1.2.11\0" as *const u8 as *const i8,
            ::std::mem::size_of::<z_stream>() as u64 as i32,
        ) != 0 as i32
        {
            return process_zlib_error(data, z);
        }
        (*zp).trailerlen = 8 as i32 as uInt;
        (*zp).zlib_init = ZLIB_INIT;
    }
    return CURLE_OK;
}
unsafe extern "C" fn check_gzip_header(
    mut data: *const u8,
    mut len: ssize_t,
    mut headerlen: *mut ssize_t,
) -> C2RustUnnamed_6 {
    let mut method: i32 = 0;
    let mut flags: i32 = 0;
    let totallen: ssize_t = len;
    if len < 10 as i32 as i64 {
        return GZIP_UNDERFLOW;
    }
    if *data.offset(0 as i32 as isize) as i32 != 0x1f as i32
        || *data.offset(1 as i32 as isize) as i32 != 0x8b as i32
    {
        return GZIP_BAD;
    }
    method = *data.offset(2 as i32 as isize) as i32;
    flags = *data.offset(3 as i32 as isize) as i32;
    if method != 8 as i32 || flags & 0xe0 as i32 != 0 as i32 {
        return GZIP_BAD;
    }
    len -= 10 as i32 as i64;
    data = data.offset(10 as i32 as isize);
    if flags & 0x4 as i32 != 0 {
        let mut extra_len: ssize_t = 0;
        if len < 2 as i32 as i64 {
            return GZIP_UNDERFLOW;
        }
        extra_len = ((*data.offset(1 as i32 as isize) as i32)
            << 8 as i32 | *data.offset(0 as i32 as isize) as i32)
            as ssize_t;
        if len < extra_len + 2 as i32 as i64 {
            return GZIP_UNDERFLOW;
        }
        len -= extra_len + 2 as i32 as i64;
        data = data.offset((extra_len + 2 as i32 as i64) as isize);
    }
    if flags & 0x8 as i32 != 0 {
        while len != 0 && *data as i32 != 0 {
            len -= 1;
            data = data.offset(1);
        }
        if len == 0 || *data as i32 != 0 {
            return GZIP_UNDERFLOW;
        }
        len -= 1;
        data = data.offset(1);
    }
    if flags & 0x10 as i32 != 0 {
        while len != 0 && *data as i32 != 0 {
            len -= 1;
            data = data.offset(1);
        }
        if len == 0 || *data as i32 != 0 {
            return GZIP_UNDERFLOW;
        }
        len -= 1;
    }
    if flags & 0x2 as i32 != 0 {
        if len < 2 as i32 as i64 {
            return GZIP_UNDERFLOW;
        }
        len -= 2 as i32 as i64;
    }
    *headerlen = totallen - len;
    return GZIP_OK;
}
unsafe extern "C" fn gzip_unencode_write(
    mut data: *mut Curl_easy,
    mut writer: *mut contenc_writer,
    mut buf: *const i8,
    mut nbytes: size_t,
) -> CURLcode {
    let mut zp: *mut zlib_params = &mut (*writer).params as *mut *mut libc::c_void
        as *mut zlib_params;
    let mut z: *mut z_stream = &mut (*zp).z;
    if (*zp).zlib_init as u32 == ZLIB_INIT_GZIP as i32 as u32 {
        let ref mut fresh11 = (*z).next_in;
        *fresh11 = buf as *mut Bytef;
        (*z).avail_in = nbytes as uInt;
        return inflate_stream(data, writer, ZLIB_INIT_GZIP);
    }
    match (*zp).zlib_init as u32 {
        1 => {
            let mut hlen: ssize_t = 0;
            match check_gzip_header(
                buf as *mut u8,
                nbytes as ssize_t,
                &mut hlen,
            ) as u32
            {
                0 => {
                    let ref mut fresh12 = (*z).next_in;
                    *fresh12 = (buf as *mut Bytef).offset(hlen as isize);
                    (*z).avail_in = nbytes.wrapping_sub(hlen as u64) as uInt;
                    (*zp).zlib_init = ZLIB_GZIP_INFLATING;
                }
                2 => {
                    (*z).avail_in = nbytes as uInt;
                    let ref mut fresh13 = (*z).next_in;
                    *fresh13 = Curl_cmalloc
                        .expect("non-null function pointer")((*z).avail_in as size_t)
                        as *mut Bytef;
                    if ((*z).next_in).is_null() {
                        return exit_zlib(
                            data,
                            z,
                            &mut (*zp).zlib_init,
                            CURLE_OUT_OF_MEMORY,
                        );
                    }
                    memcpy(
                        (*z).next_in as *mut libc::c_void,
                        buf as *const libc::c_void,
                        (*z).avail_in as u64,
                    );
                    (*zp).zlib_init = ZLIB_GZIP_HEADER;
                    return CURLE_OK;
                }
                1 | _ => {
                    return exit_zlib(
                        data,
                        z,
                        &mut (*zp).zlib_init,
                        process_zlib_error(data, z),
                    );
                }
            }
        }
        4 => {
            let mut hlen_0: ssize_t = 0;
            let ref mut fresh14 = (*z).avail_in;
            *fresh14 = (*fresh14 as u32).wrapping_add(nbytes as uInt) as uInt
                as uInt;
            let ref mut fresh15 = (*z).next_in;
            *fresh15 = Curl_saferealloc(
                (*z).next_in as *mut libc::c_void,
                (*z).avail_in as size_t,
            ) as *mut Bytef;
            if ((*z).next_in).is_null() {
                return exit_zlib(data, z, &mut (*zp).zlib_init, CURLE_OUT_OF_MEMORY);
            }
            memcpy(
                ((*z).next_in).offset((*z).avail_in as isize).offset(-(nbytes as isize))
                    as *mut libc::c_void,
                buf as *const libc::c_void,
                nbytes,
            );
            match check_gzip_header((*z).next_in, (*z).avail_in as ssize_t, &mut hlen_0)
                as u32
            {
                0 => {
                    Curl_cfree
                        .expect(
                            "non-null function pointer",
                        )((*z).next_in as *mut libc::c_void);
                    let ref mut fresh16 = (*z).next_in;
                    *fresh16 = (buf as *mut Bytef)
                        .offset(hlen_0 as isize)
                        .offset(nbytes as isize)
                        .offset(-((*z).avail_in as isize));
                    (*z).avail_in = ((*z).avail_in as i64 - hlen_0) as uInt;
                    (*zp).zlib_init = ZLIB_GZIP_INFLATING;
                }
                2 => return CURLE_OK,
                1 | _ => {
                    return exit_zlib(
                        data,
                        z,
                        &mut (*zp).zlib_init,
                        process_zlib_error(data, z),
                    );
                }
            }
        }
        3 => {
            let ref mut fresh17 = (*z).next_in;
            *fresh17 = buf as *mut Bytef;
            (*z).avail_in = nbytes as uInt;
            return process_trailer(data, zp);
        }
        5 | _ => {
            let ref mut fresh18 = (*z).next_in;
            *fresh18 = buf as *mut Bytef;
            (*z).avail_in = nbytes as uInt;
        }
    }
    if (*z).avail_in == 0 as i32 as u32 {
        return CURLE_OK;
    }
    return inflate_stream(data, writer, ZLIB_GZIP_INFLATING);
}
unsafe extern "C" fn gzip_close_writer(
    mut data: *mut Curl_easy,
    mut writer: *mut contenc_writer,
) {
    let mut zp: *mut zlib_params = &mut (*writer).params as *mut *mut libc::c_void
        as *mut zlib_params;
    let mut z: *mut z_stream = &mut (*zp).z;
    exit_zlib(data, z, &mut (*zp).zlib_init, CURLE_OK);
}
static mut gzip_encoding: content_encoding = unsafe {
    {
        let mut init = content_encoding {
            name: b"gzip\0" as *const u8 as *const i8,
            alias: b"x-gzip\0" as *const u8 as *const i8,
            init_writer: Some(
                gzip_init_writer
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut contenc_writer,
                    ) -> CURLcode,
            ),
            unencode_write: Some(
                gzip_unencode_write
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut contenc_writer,
                        *const i8,
                        size_t,
                    ) -> CURLcode,
            ),
            close_writer: Some(
                gzip_close_writer
                    as unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer) -> (),
            ),
            paramsize: ::std::mem::size_of::<zlib_params>() as u64,
        };
        init
    }
};
unsafe extern "C" fn identity_init_writer(
    mut data: *mut Curl_easy,
    mut writer: *mut contenc_writer,
) -> CURLcode {
    return (if !((*writer).downstream).is_null() {
        CURLE_OK as i32
    } else {
        CURLE_WRITE_ERROR as i32
    }) as CURLcode;
}
unsafe extern "C" fn identity_unencode_write(
    mut data: *mut Curl_easy,
    mut writer: *mut contenc_writer,
    mut buf: *const i8,
    mut nbytes: size_t,
) -> CURLcode {
    return Curl_unencode_write(data, (*writer).downstream, buf, nbytes);
}
 extern "C" fn identity_close_writer(
    mut data: *mut Curl_easy,
    mut writer: *mut contenc_writer,
) {}
static mut identity_encoding: content_encoding = unsafe {
    {
        let mut init = content_encoding {
            name: b"identity\0" as *const u8 as *const i8,
            alias: b"none\0" as *const u8 as *const i8,
            init_writer: Some(
                identity_init_writer
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut contenc_writer,
                    ) -> CURLcode,
            ),
            unencode_write: Some(
                identity_unencode_write
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut contenc_writer,
                        *const i8,
                        size_t,
                    ) -> CURLcode,
            ),
            close_writer: Some(
                identity_close_writer
                    as unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer) -> (),
            ),
            paramsize: 0 as i32 as size_t,
        };
        init
    }
};
static mut encodings: [*const content_encoding; 4] = unsafe {
    [
        &identity_encoding as *const content_encoding,
        &deflate_encoding as *const content_encoding,
        &gzip_encoding as *const content_encoding,
        0 as *const content_encoding,
    ]
};
#[no_mangle]
pub unsafe extern "C" fn Curl_all_content_encodings() -> *mut i8 {
    let mut len: size_t = 0 as i32 as size_t;
    let mut cep: *const *const content_encoding = 0 as *const *const content_encoding;
    let mut ce: *const content_encoding = 0 as *const content_encoding;
    let mut ace: *mut i8 = 0 as *mut i8;
    cep = encodings.as_ptr();
    while !(*cep).is_null() {
        ce = *cep;
        if Curl_strcasecompare(
            (*ce).name,
            b"identity\0" as *const u8 as *const i8,
        ) == 0
        {
            len = (len as u64)
                .wrapping_add(
                    (strlen((*ce).name)).wrapping_add(2 as i32 as u64),
                ) as size_t as size_t;
        }
        cep = cep.offset(1);
    }
    if len == 0 {
        return Curl_cstrdup
            .expect(
                "non-null function pointer",
            )(b"identity\0" as *const u8 as *const i8);
    }
    ace = Curl_cmalloc.expect("non-null function pointer")(len) as *mut i8;
    if !ace.is_null() {
        let mut p: *mut i8 = ace;
        cep = encodings.as_ptr();
        while !(*cep).is_null() {
            ce = *cep;
            if Curl_strcasecompare(
                (*ce).name,
                b"identity\0" as *const u8 as *const i8,
            ) == 0
            {
                strcpy(p, (*ce).name);
                p = p.offset(strlen(p) as isize);
                let fresh19 = p;
                p = p.offset(1);
                *fresh19 = ',' as i32 as i8;
                let fresh20 = p;
                p = p.offset(1);
                *fresh20 = ' ' as i32 as i8;
            }
            cep = cep.offset(1);
        }
        *p.offset(-(2 as i32) as isize) = '\u{0}' as i32 as i8;
    }
    return ace;
}
unsafe extern "C" fn client_init_writer(
    mut data: *mut Curl_easy,
    mut writer: *mut contenc_writer,
) -> CURLcode {
    return (if !((*writer).downstream).is_null() {
        CURLE_WRITE_ERROR as i32
    } else {
        CURLE_OK as i32
    }) as CURLcode;
}
unsafe extern "C" fn client_unencode_write(
    mut data: *mut Curl_easy,
    mut writer: *mut contenc_writer,
    mut buf: *const i8,
    mut nbytes: size_t,
) -> CURLcode {
    let mut k: *mut SingleRequest = &mut (*data).req;
    if nbytes == 0 || (*k).ignorebody() as i32 != 0 {
        return CURLE_OK;
    }
    return Curl_client_write(
        data,
        (1 as i32) << 0 as i32,
        buf as *mut i8,
        nbytes,
    );
}
 extern "C" fn client_close_writer(
    mut data: *mut Curl_easy,
    mut writer: *mut contenc_writer,
) {}
static mut client_encoding: content_encoding = unsafe {
    {
        let mut init = content_encoding {
            name: 0 as *const i8,
            alias: 0 as *const i8,
            init_writer: Some(
                client_init_writer
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut contenc_writer,
                    ) -> CURLcode,
            ),
            unencode_write: Some(
                client_unencode_write
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut contenc_writer,
                        *const i8,
                        size_t,
                    ) -> CURLcode,
            ),
            close_writer: Some(
                client_close_writer
                    as unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer) -> (),
            ),
            paramsize: 0 as i32 as size_t,
        };
        init
    }
};
unsafe extern "C" fn error_init_writer(
    mut data: *mut Curl_easy,
    mut writer: *mut contenc_writer,
) -> CURLcode {
    return (if !((*writer).downstream).is_null() {
        CURLE_OK as i32
    } else {
        CURLE_WRITE_ERROR as i32
    }) as CURLcode;
}
unsafe extern "C" fn error_unencode_write(
    mut data: *mut Curl_easy,
    mut writer: *mut contenc_writer,
    mut buf: *const i8,
    mut nbytes: size_t,
) -> CURLcode {
    let mut all: *mut i8 = Curl_all_content_encodings();
    if all.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    Curl_failf(
        data,
        b"Unrecognized content encoding type. libcurl understands %s content encodings.\0"
            as *const u8 as *const i8,
        all,
    );
    Curl_cfree.expect("non-null function pointer")(all as *mut libc::c_void);
    return CURLE_BAD_CONTENT_ENCODING;
}
 extern "C" fn error_close_writer(
    mut data: *mut Curl_easy,
    mut writer: *mut contenc_writer,
) {}
static mut error_encoding: content_encoding = unsafe {
    {
        let mut init = content_encoding {
            name: 0 as *const i8,
            alias: 0 as *const i8,
            init_writer: Some(
                error_init_writer
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut contenc_writer,
                    ) -> CURLcode,
            ),
            unencode_write: Some(
                error_unencode_write
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut contenc_writer,
                        *const i8,
                        size_t,
                    ) -> CURLcode,
            ),
            close_writer: Some(
                error_close_writer
                    as unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer) -> (),
            ),
            paramsize: 0 as i32 as size_t,
        };
        init
    }
};
unsafe extern "C" fn new_unencoding_writer(
    mut data: *mut Curl_easy,
    mut handler: *const content_encoding,
    mut downstream: *mut contenc_writer,
) -> *mut contenc_writer {
    let mut sz: size_t = (16 as u64).wrapping_add((*handler).paramsize);
    let mut writer: *mut contenc_writer = Curl_ccalloc
        .expect("non-null function pointer")(1 as i32 as size_t, sz)
        as *mut contenc_writer;
    if !writer.is_null() {
        let ref mut fresh21 = (*writer).handler;
        *fresh21 = handler;
        let ref mut fresh22 = (*writer).downstream;
        *fresh22 = downstream;
        if ((*handler).init_writer).expect("non-null function pointer")(data, writer)
            as u64 != 0
        {
            Curl_cfree.expect("non-null function pointer")(writer as *mut libc::c_void);
            writer = 0 as *mut contenc_writer;
        }
    }
    return writer;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_unencode_write(
    mut data: *mut Curl_easy,
    mut writer: *mut contenc_writer,
    mut buf: *const i8,
    mut nbytes: size_t,
) -> CURLcode {
    if nbytes == 0 {
        return CURLE_OK;
    }
    return ((*(*writer).handler).unencode_write)
        .expect("non-null function pointer")(data, writer, buf, nbytes);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_unencode_cleanup(mut data: *mut Curl_easy) {
    let mut k: *mut SingleRequest = &mut (*data).req;
    let mut writer: *mut contenc_writer = (*k).writer_stack;
    while !writer.is_null() {
        let ref mut fresh23 = (*k).writer_stack;
        *fresh23 = (*writer).downstream;
        ((*(*writer).handler).close_writer)
            .expect("non-null function pointer")(data, writer);
        Curl_cfree.expect("non-null function pointer")(writer as *mut libc::c_void);
        writer = (*k).writer_stack;
    }
}
unsafe extern "C" fn find_encoding(
    mut name: *const i8,
    mut len: size_t,
) -> *const content_encoding {
    let mut cep: *const *const content_encoding = 0 as *const *const content_encoding;
    cep = encodings.as_ptr();
    while !(*cep).is_null() {
        let mut ce: *const content_encoding = *cep;
        if Curl_strncasecompare(name, (*ce).name, len) != 0
            && *((*ce).name).offset(len as isize) == 0
            || !((*ce).alias).is_null()
                && Curl_strncasecompare(name, (*ce).alias, len) != 0
                && *((*ce).alias).offset(len as isize) == 0
        {
            return ce;
        }
        cep = cep.offset(1);
    }
    return 0 as *const content_encoding;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_build_unencoding_stack(
    mut data: *mut Curl_easy,
    mut enclist: *const i8,
    mut maybechunked: i32,
) -> CURLcode {
    let mut k: *mut SingleRequest = &mut (*data).req;
    loop {
        let mut name: *const i8 = 0 as *const i8;
        let mut namelen: size_t = 0;
        while Curl_isspace(*enclist as u8 as i32) != 0
            || *enclist as i32 == ',' as i32
        {
            enclist = enclist.offset(1);
        }
        name = enclist;
        namelen = 0 as i32 as size_t;
        while *enclist as i32 != 0 && *enclist as i32 != ',' as i32 {
            if Curl_isspace(*enclist as u8 as i32) == 0 {
                namelen = (enclist.offset_from(name) as i64
                    + 1 as i32 as i64) as size_t;
            }
            enclist = enclist.offset(1);
        }
        if maybechunked != 0 && namelen == 7 as i32 as u64
            && Curl_strncasecompare(
                name,
                b"chunked\0" as *const u8 as *const i8,
                7 as i32 as size_t,
            ) != 0
        {
            (*k).set_chunk(1 as i32 as bit);
            Curl_httpchunk_init(data);
        } else if namelen != 0 {
            let mut encoding: *const content_encoding = find_encoding(name, namelen);
            let mut writer: *mut contenc_writer = 0 as *mut contenc_writer;
            if ((*k).writer_stack).is_null() {
                let ref mut fresh24 = (*k).writer_stack;
                *fresh24 = new_unencoding_writer(
                    data,
                    &client_encoding,
                    0 as *mut contenc_writer,
                );
                if ((*k).writer_stack).is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
            }
            if encoding.is_null() {
                encoding = &error_encoding;
            }
            writer = new_unencoding_writer(data, encoding, (*k).writer_stack);
            if writer.is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            let ref mut fresh25 = (*k).writer_stack;
            *fresh25 = writer;
        }
        if !(*enclist != 0) {
            break;
        }
    }
    return CURLE_OK;
}
