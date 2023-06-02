use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn strlen(_: *const i8) -> u64;
    fn strtok_r(
        __s: *mut i8,
        __delim: *const i8,
        __save_ptr: *mut *mut i8,
    ) -> *mut i8;
    fn strstr(_: *const i8, _: *const i8) -> *mut i8;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::base64::Curl_base64_encode;
pub use crate::src::lib::bufref::Curl_bufref_len;
pub use crate::src::lib::bufref::Curl_bufref_ptr;
pub use crate::src::lib::bufref::Curl_bufref_set;
pub use crate::src::lib::curl_ctype::Curl_isspace;
pub use crate::src::lib::escape::curl_free;
pub use crate::src::lib::md5::Curl_MD5_final;
pub use crate::src::lib::md5::Curl_MD5_init;
pub use crate::src::lib::md5::Curl_MD5_update;
pub use crate::src::lib::md5::Curl_md5it;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::rand::Curl_rand_hex;
pub use crate::src::lib::sha256::Curl_sha256it;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::vauth::vauth::Curl_auth_build_spn;
pub use crate::src::lib::warnless::curlx_uztoui;
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::altsvc::Gsasl;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_cstrdup;
pub use crate::src::lib::hostip6::psl_ctx_st;
pub use crate::src::lib::imap::_IO_marker;
pub use crate::src::lib::md5::Curl_DIGEST_MD5;
pub use crate::src::lib::speedcheck::_IO_codecvt;
pub use crate::src::lib::urlapi::Gsasl_session;
pub use crate::src::lib::version::nghttp2_session;
pub use crate::src::lib::vtls::vtls::_IO_wide_data;
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
pub type curl_malloc_callback = crate::src::lib::altsvc::curl_malloc_callback;
pub type curl_strdup_callback = crate::src::lib::altsvc::curl_strdup_callback;
// #[derive(Copy, Clone)]

pub type bufref = crate::src::lib::bufref::bufref;
// #[derive(Copy, Clone)]

pub type MD5_context = crate::src::lib::md5::MD5_context;
// #[derive(Copy, Clone)]

pub type MD5_params = crate::src::lib::md5::MD5_params;
pub type Curl_MD5_final_func = crate::src::lib::md5::Curl_MD5_final_func;
pub type Curl_MD5_update_func = crate::src::lib::md5::Curl_MD5_update_func;
pub type Curl_MD5_init_func = crate::src::lib::md5::Curl_MD5_init_func;
pub const CURLDIGESTALGO_SHA512_256SESS: C2RustUnnamed_6 = 5;
pub const CURLDIGESTALGO_SHA512_256: C2RustUnnamed_6 = 4;
pub const CURLDIGESTALGO_SHA256SESS: C2RustUnnamed_6 = 3;
pub const CURLDIGESTALGO_SHA256: C2RustUnnamed_6 = 2;
pub const CURLDIGESTALGO_MD5: C2RustUnnamed_6 = 0;
pub const CURLDIGESTALGO_MD5SESS: C2RustUnnamed_6 = 1;
pub type C2RustUnnamed_6 = u32;
#[no_mangle]
pub unsafe extern "C" fn Curl_auth_digest_get_pair(
    mut str: *const i8,
    mut value: *mut i8,
    mut content: *mut i8,
    mut endptr: *mut *const i8,
) -> bool {
    let mut c: i32 = 0;
    let mut starts_with_quote: bool = 0 as i32 != 0;
    let mut escape: bool = 0 as i32 != 0;
    c = 256 as i32 - 1 as i32;
    while *str as i32 != 0 && *str as i32 != '=' as i32
        && {
            let fresh0 = c;
            c = c - 1;
            fresh0 != 0
        }
    {
        let fresh1 = str;
        str = str.offset(1);
        let fresh2 = value;
        value = value.offset(1);
        *fresh2 = *fresh1;
    }
    *value = 0 as i32 as i8;
    let fresh3 = str;
    str = str.offset(1);
    if '=' as i32 != *fresh3 as i32 {
        return 0 as i32 != 0;
    }
    if '"' as i32 == *str as i32 {
        str = str.offset(1);
        starts_with_quote = 1 as i32 != 0;
    }
    let mut current_block_17: u64;
    c = 1024 as i32 - 1 as i32;
    while *str as i32 != 0
        && {
            let fresh4 = c;
            c = c - 1;
            fresh4 != 0
        }
    {
        match *str as i32 {
            92 => {
                if !escape {
                    escape = 1 as i32 != 0;
                    let fresh5 = content;
                    content = content.offset(1);
                    *fresh5 = '\\' as i32 as i8;
                    current_block_17 = 2968425633554183086;
                } else {
                    current_block_17 = 15125582407903384992;
                }
            }
            44 => {
                if !starts_with_quote {
                    c = 0 as i32;
                    current_block_17 = 2968425633554183086;
                } else {
                    current_block_17 = 15125582407903384992;
                }
            }
            13 | 10 => {
                c = 0 as i32;
                current_block_17 = 2968425633554183086;
            }
            34 => {
                if !escape && starts_with_quote as i32 != 0 {
                    c = 0 as i32;
                    current_block_17 = 2968425633554183086;
                } else {
                    current_block_17 = 15125582407903384992;
                }
            }
            _ => {
                current_block_17 = 15125582407903384992;
            }
        }
        match current_block_17 {
            15125582407903384992 => {
                escape = 0 as i32 != 0;
                let fresh6 = content;
                content = content.offset(1);
                *fresh6 = *str;
            }
            _ => {}
        }
        str = str.offset(1);
    }
    *content = 0 as i32 as i8;
    *endptr = str;
    return 1 as i32 != 0;
}
unsafe extern "C" fn auth_digest_md5_to_ascii(
    mut source: *mut u8,
    mut dest: *mut u8,
) {
    let mut i: i32 = 0;
    i = 0 as i32;
    while i < 16 as i32 {
        curl_msnprintf(
            &mut *dest.offset((i * 2 as i32) as isize) as *mut u8
                as *mut i8,
            3 as i32 as size_t,
            b"%02x\0" as *const u8 as *const i8,
            *source.offset(i as isize) as i32,
        );
        i += 1;
    }
}
unsafe extern "C" fn auth_digest_sha256_to_ascii(
    mut source: *mut u8,
    mut dest: *mut u8,
) {
    let mut i: i32 = 0;
    i = 0 as i32;
    while i < 32 as i32 {
        curl_msnprintf(
            &mut *dest.offset((i * 2 as i32) as isize) as *mut u8
                as *mut i8,
            3 as i32 as size_t,
            b"%02x\0" as *const u8 as *const i8,
            *source.offset(i as isize) as i32,
        );
        i += 1;
    }
}
unsafe extern "C" fn auth_digest_string_quoted(
    mut source: *const i8,
) -> *mut i8 {
    let mut dest: *mut i8 = 0 as *mut i8;
    let mut s: *const i8 = source;
    let mut n: size_t = 1 as i32 as size_t;
    while *s != 0 {
        n = n.wrapping_add(1);
        if *s as i32 == '"' as i32 || *s as i32 == '\\' as i32 {
            n = n.wrapping_add(1);
        }
        s = s.offset(1);
    }
    dest = Curl_cmalloc.expect("non-null function pointer")(n) as *mut i8;
    if !dest.is_null() {
        let mut d: *mut i8 = dest;
        s = source;
        while *s != 0 {
            if *s as i32 == '"' as i32 || *s as i32 == '\\' as i32 {
                let fresh7 = d;
                d = d.offset(1);
                *fresh7 = '\\' as i32 as i8;
            }
            let fresh8 = s;
            s = s.offset(1);
            let fresh9 = d;
            d = d.offset(1);
            *fresh9 = *fresh8;
        }
        *d = 0 as i32 as i8;
    }
    return dest;
}
unsafe extern "C" fn auth_digest_get_key_value(
    mut chlg: *const i8,
    mut key: *const i8,
    mut value: *mut i8,
    mut max_val_len: size_t,
    mut end_char: i8,
) -> bool {
    let mut find_pos: *mut i8 = 0 as *mut i8;
    let mut i: size_t = 0;
    find_pos = strstr(chlg, key);
    if find_pos.is_null() {
        return 0 as i32 != 0;
    }
    find_pos = find_pos.offset(strlen(key) as isize);
    i = 0 as i32 as size_t;
    while *find_pos as i32 != 0
        && *find_pos as i32 != end_char as i32
        && i < max_val_len.wrapping_sub(1 as i32 as u64)
    {
        let fresh10 = find_pos;
        find_pos = find_pos.offset(1);
        *value.offset(i as isize) = *fresh10;
        i = i.wrapping_add(1);
    }
    *value.offset(i as isize) = '\u{0}' as i32 as i8;
    return 1 as i32 != 0;
}
unsafe extern "C" fn auth_digest_get_qop_values(
    mut options: *const i8,
    mut value: *mut i32,
) -> CURLcode {
    let mut tmp: *mut i8 = 0 as *mut i8;
    let mut token: *mut i8 = 0 as *mut i8;
    let mut tok_buf: *mut i8 = 0 as *mut i8;
    *value = 0 as i32;
    tmp = Curl_cstrdup.expect("non-null function pointer")(options);
    if tmp.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    token = strtok_r(tmp, b",\0" as *const u8 as *const i8, &mut tok_buf);
    while !token.is_null() {
        if Curl_strcasecompare(token, b"auth\0" as *const u8 as *const i8) != 0
        {
            *value |= (1 as i32) << 0 as i32;
        } else if Curl_strcasecompare(
                token,
                b"auth-int\0" as *const u8 as *const i8,
            ) != 0
            {
            *value |= (1 as i32) << 1 as i32;
        } else if Curl_strcasecompare(
                token,
                b"auth-conf\0" as *const u8 as *const i8,
            ) != 0
            {
            *value |= (1 as i32) << 2 as i32;
        }
        token = strtok_r(
            0 as *mut i8,
            b",\0" as *const u8 as *const i8,
            &mut tok_buf,
        );
    }
    Curl_cfree.expect("non-null function pointer")(tmp as *mut libc::c_void);
    return CURLE_OK;
}
unsafe extern "C" fn auth_decode_digest_md5_message(
    mut chlgref: *const bufref,
    mut nonce: *mut i8,
    mut nlen: size_t,
    mut realm: *mut i8,
    mut rlen: size_t,
    mut alg: *mut i8,
    mut alen: size_t,
    mut qop: *mut i8,
    mut qlen: size_t,
) -> CURLcode {
    let mut chlg: *const i8 = Curl_bufref_ptr(chlgref) as *const i8;
    if Curl_bufref_len(chlgref) == 0 {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    if !auth_digest_get_key_value(
        chlg,
        b"nonce=\"\0" as *const u8 as *const i8,
        nonce,
        nlen,
        '"' as i32 as i8,
    ) {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    if !auth_digest_get_key_value(
        chlg,
        b"realm=\"\0" as *const u8 as *const i8,
        realm,
        rlen,
        '"' as i32 as i8,
    ) {
        strcpy(realm, b"\0" as *const u8 as *const i8);
    }
    if !auth_digest_get_key_value(
        chlg,
        b"algorithm=\0" as *const u8 as *const i8,
        alg,
        alen,
        ',' as i32 as i8,
    ) {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    if !auth_digest_get_key_value(
        chlg,
        b"qop=\"\0" as *const u8 as *const i8,
        qop,
        qlen,
        '"' as i32 as i8,
    ) {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_auth_is_digest_supported() -> bool {
    return 1 as i32 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_auth_create_digest_md5_message(
    mut data: *mut Curl_easy,
    mut chlg: *const bufref,
    mut userp: *const i8,
    mut passwdp: *const i8,
    mut service: *const i8,
    mut out: *mut bufref,
) -> CURLcode {
    let mut i: size_t = 0;
    let mut ctxt: *mut MD5_context = 0 as *mut MD5_context;
    let mut response: *mut i8 = 0 as *mut i8;
    let mut digest: [u8; 16] = [0; 16];
    let mut HA1_hex: [i8; 33] = [0; 33];
    let mut HA2_hex: [i8; 33] = [0; 33];
    let mut resp_hash_hex: [i8; 33] = [0; 33];
    let mut nonce: [i8; 64] = [0; 64];
    let mut realm: [i8; 128] = [0; 128];
    let mut algorithm: [i8; 64] = [0; 64];
    let mut qop_options: [i8; 64] = [0; 64];
    let mut qop_values: i32 = 0;
    let mut cnonce: [i8; 33] = [0; 33];
    let mut nonceCount: [i8; 9] = *::std::mem::transmute::<
        &[u8; 9],
        &mut [i8; 9],
    >(b"00000001\0");
    let mut method: [i8; 13] = *::std::mem::transmute::<
        &[u8; 13],
        &mut [i8; 13],
    >(b"AUTHENTICATE\0");
    let mut qop: [i8; 5] = *::std::mem::transmute::<
        &[u8; 5],
        &mut [i8; 5],
    >(b"auth\0");
    let mut spn: *mut i8 = 0 as *mut i8;
    let mut result: CURLcode = auth_decode_digest_md5_message(
        chlg,
        nonce.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 64]>() as u64,
        realm.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 128]>() as u64,
        algorithm.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 64]>() as u64,
        qop_options.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 64]>() as u64,
    );
    if result as u64 != 0 {
        return result;
    }
    if strcmp(algorithm.as_mut_ptr(), b"md5-sess\0" as *const u8 as *const i8)
        != 0 as i32
    {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    result = auth_digest_get_qop_values(qop_options.as_mut_ptr(), &mut qop_values);
    if result as u64 != 0 {
        return result;
    }
    if qop_values & (1 as i32) << 0 as i32 == 0 {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    result = Curl_rand_hex(
        data,
        cnonce.as_mut_ptr() as *mut u8,
        ::std::mem::size_of::<[i8; 33]>() as u64,
    );
    if result as u64 != 0 {
        return result;
    }
    ctxt = Curl_MD5_init(Curl_DIGEST_MD5.as_ptr());
    if ctxt.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    Curl_MD5_update(ctxt, userp as *const u8, curlx_uztoui(strlen(userp)));
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(
        ctxt,
        realm.as_mut_ptr() as *const u8,
        curlx_uztoui(strlen(realm.as_mut_ptr())),
    );
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(
        ctxt,
        passwdp as *const u8,
        curlx_uztoui(strlen(passwdp)),
    );
    Curl_MD5_final(ctxt, digest.as_mut_ptr());
    ctxt = Curl_MD5_init(Curl_DIGEST_MD5.as_ptr());
    if ctxt.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    Curl_MD5_update(
        ctxt,
        digest.as_mut_ptr() as *const u8,
        16 as i32 as u32,
    );
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(
        ctxt,
        nonce.as_mut_ptr() as *const u8,
        curlx_uztoui(strlen(nonce.as_mut_ptr())),
    );
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(
        ctxt,
        cnonce.as_mut_ptr() as *const u8,
        curlx_uztoui(strlen(cnonce.as_mut_ptr())),
    );
    Curl_MD5_final(ctxt, digest.as_mut_ptr());
    i = 0 as i32 as size_t;
    while i < 16 as i32 as u64 {
        curl_msnprintf(
            &mut *HA1_hex
                .as_mut_ptr()
                .offset((2 as i32 as u64).wrapping_mul(i) as isize)
                as *mut i8,
            3 as i32 as size_t,
            b"%02x\0" as *const u8 as *const i8,
            digest[i as usize] as i32,
        );
        i = i.wrapping_add(1);
    }
    spn = Curl_auth_build_spn(service, realm.as_mut_ptr(), 0 as *const i8);
    if spn.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    ctxt = Curl_MD5_init(Curl_DIGEST_MD5.as_ptr());
    if ctxt.is_null() {
        Curl_cfree.expect("non-null function pointer")(spn as *mut libc::c_void);
        return CURLE_OUT_OF_MEMORY;
    }
    Curl_MD5_update(
        ctxt,
        method.as_mut_ptr() as *const u8,
        curlx_uztoui(strlen(method.as_mut_ptr())),
    );
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(ctxt, spn as *const u8, curlx_uztoui(strlen(spn)));
    Curl_MD5_final(ctxt, digest.as_mut_ptr());
    i = 0 as i32 as size_t;
    while i < 16 as i32 as u64 {
        curl_msnprintf(
            &mut *HA2_hex
                .as_mut_ptr()
                .offset((2 as i32 as u64).wrapping_mul(i) as isize)
                as *mut i8,
            3 as i32 as size_t,
            b"%02x\0" as *const u8 as *const i8,
            digest[i as usize] as i32,
        );
        i = i.wrapping_add(1);
    }
    ctxt = Curl_MD5_init(Curl_DIGEST_MD5.as_ptr());
    if ctxt.is_null() {
        Curl_cfree.expect("non-null function pointer")(spn as *mut libc::c_void);
        return CURLE_OUT_OF_MEMORY;
    }
    Curl_MD5_update(
        ctxt,
        HA1_hex.as_mut_ptr() as *const u8,
        (2 as i32 * 16 as i32) as u32,
    );
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(
        ctxt,
        nonce.as_mut_ptr() as *const u8,
        curlx_uztoui(strlen(nonce.as_mut_ptr())),
    );
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(
        ctxt,
        nonceCount.as_mut_ptr() as *const u8,
        curlx_uztoui(strlen(nonceCount.as_mut_ptr())),
    );
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(
        ctxt,
        cnonce.as_mut_ptr() as *const u8,
        curlx_uztoui(strlen(cnonce.as_mut_ptr())),
    );
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(
        ctxt,
        qop.as_mut_ptr() as *const u8,
        curlx_uztoui(strlen(qop.as_mut_ptr())),
    );
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(
        ctxt,
        HA2_hex.as_mut_ptr() as *const u8,
        (2 as i32 * 16 as i32) as u32,
    );
    Curl_MD5_final(ctxt, digest.as_mut_ptr());
    i = 0 as i32 as size_t;
    while i < 16 as i32 as u64 {
        curl_msnprintf(
            &mut *resp_hash_hex
                .as_mut_ptr()
                .offset((2 as i32 as u64).wrapping_mul(i) as isize)
                as *mut i8,
            3 as i32 as size_t,
            b"%02x\0" as *const u8 as *const i8,
            digest[i as usize] as i32,
        );
        i = i.wrapping_add(1);
    }
    response = curl_maprintf(
        b"username=\"%s\",realm=\"%s\",nonce=\"%s\",cnonce=\"%s\",nc=\"%s\",digest-uri=\"%s\",response=%s,qop=%s\0"
            as *const u8 as *const i8,
        userp,
        realm.as_mut_ptr(),
        nonce.as_mut_ptr(),
        cnonce.as_mut_ptr(),
        nonceCount.as_mut_ptr(),
        spn,
        resp_hash_hex.as_mut_ptr(),
        qop.as_mut_ptr(),
    );
    Curl_cfree.expect("non-null function pointer")(spn as *mut libc::c_void);
    if response.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    Curl_bufref_set(
        out,
        response as *const libc::c_void,
        strlen(response),
        Some(curl_free as unsafe extern "C" fn(*mut libc::c_void) -> ()),
    );
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_auth_decode_digest_http_message(
    mut chlg: *const i8,
    mut digest: *mut digestdata,
) -> CURLcode {
    let mut before: bool = 0 as i32 != 0;
    let mut foundAuth: bool = 0 as i32 != 0;
    let mut foundAuthInt: bool = 0 as i32 != 0;
    let mut token: *mut i8 = 0 as *mut i8;
    let mut tmp: *mut i8 = 0 as *mut i8;
    if !((*digest).nonce).is_null() {
        before = 1 as i32 != 0;
    }
    Curl_auth_digest_cleanup(digest);
    loop {
        let mut value: [i8; 256] = [0; 256];
        let mut content: [i8; 1024] = [0; 1024];
        while *chlg as i32 != 0
            && Curl_isspace(*chlg as u8 as i32) != 0
        {
            chlg = chlg.offset(1);
        }
        if !Curl_auth_digest_get_pair(
            chlg,
            value.as_mut_ptr(),
            content.as_mut_ptr(),
            &mut chlg,
        ) {
            break;
        }
        if Curl_strcasecompare(
            value.as_mut_ptr(),
            b"nonce\0" as *const u8 as *const i8,
        ) != 0
        {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*digest).nonce as *mut libc::c_void);
            let fresh11 = &mut ((*digest).nonce);
            *fresh11 = Curl_cstrdup
                .expect("non-null function pointer")(content.as_mut_ptr());
            if ((*digest).nonce).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        } else if Curl_strcasecompare(
                value.as_mut_ptr(),
                b"stale\0" as *const u8 as *const i8,
            ) != 0
            {
            if Curl_strcasecompare(
                content.as_mut_ptr(),
                b"true\0" as *const u8 as *const i8,
            ) != 0
            {
                (*digest).set_stale(1 as i32 as bit);
                (*digest).nc = 1 as i32;
            }
        } else if Curl_strcasecompare(
                value.as_mut_ptr(),
                b"realm\0" as *const u8 as *const i8,
            ) != 0
            {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*digest).realm as *mut libc::c_void);
            let fresh12 = &mut ((*digest).realm);
            *fresh12 = Curl_cstrdup
                .expect("non-null function pointer")(content.as_mut_ptr());
            if ((*digest).realm).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        } else if Curl_strcasecompare(
                value.as_mut_ptr(),
                b"opaque\0" as *const u8 as *const i8,
            ) != 0
            {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*digest).opaque as *mut libc::c_void);
            let fresh13 = &mut ((*digest).opaque);
            *fresh13 = Curl_cstrdup
                .expect("non-null function pointer")(content.as_mut_ptr());
            if ((*digest).opaque).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        } else if Curl_strcasecompare(
                value.as_mut_ptr(),
                b"qop\0" as *const u8 as *const i8,
            ) != 0
            {
            let mut tok_buf: *mut i8 = 0 as *mut i8;
            tmp = Curl_cstrdup.expect("non-null function pointer")(content.as_mut_ptr());
            if tmp.is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            token = strtok_r(
                tmp,
                b",\0" as *const u8 as *const i8,
                &mut tok_buf,
            );
            while !token.is_null() {
                if Curl_strcasecompare(
                    token,
                    b"auth\0" as *const u8 as *const i8,
                ) != 0
                {
                    foundAuth = 1 as i32 != 0;
                } else if Curl_strcasecompare(
                        token,
                        b"auth-int\0" as *const u8 as *const i8,
                    ) != 0
                    {
                    foundAuthInt = 1 as i32 != 0;
                }
                token = strtok_r(
                    0 as *mut i8,
                    b",\0" as *const u8 as *const i8,
                    &mut tok_buf,
                );
            }
            Curl_cfree.expect("non-null function pointer")(tmp as *mut libc::c_void);
            if foundAuth {
                Curl_cfree
                    .expect(
                        "non-null function pointer",
                    )((*digest).qop as *mut libc::c_void);
                let fresh14 = &mut ((*digest).qop);
                *fresh14 = Curl_cstrdup
                    .expect(
                        "non-null function pointer",
                    )(b"auth\0" as *const u8 as *const i8);
                if ((*digest).qop).is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
            } else if foundAuthInt {
                Curl_cfree
                    .expect(
                        "non-null function pointer",
                    )((*digest).qop as *mut libc::c_void);
                let fresh15 = &mut ((*digest).qop);
                *fresh15 = Curl_cstrdup
                    .expect(
                        "non-null function pointer",
                    )(b"auth-int\0" as *const u8 as *const i8);
                if ((*digest).qop).is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
            }
        } else if Curl_strcasecompare(
                value.as_mut_ptr(),
                b"algorithm\0" as *const u8 as *const i8,
            ) != 0
            {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*digest).algorithm as *mut libc::c_void);
            let fresh16 = &mut ((*digest).algorithm);
            *fresh16 = Curl_cstrdup
                .expect("non-null function pointer")(content.as_mut_ptr());
            if ((*digest).algorithm).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            if Curl_strcasecompare(
                content.as_mut_ptr(),
                b"MD5-sess\0" as *const u8 as *const i8,
            ) != 0
            {
                (*digest).algo = CURLDIGESTALGO_MD5SESS as i32;
            } else if Curl_strcasecompare(
                    content.as_mut_ptr(),
                    b"MD5\0" as *const u8 as *const i8,
                ) != 0
                {
                (*digest).algo = CURLDIGESTALGO_MD5 as i32;
            } else if Curl_strcasecompare(
                    content.as_mut_ptr(),
                    b"SHA-256\0" as *const u8 as *const i8,
                ) != 0
                {
                (*digest).algo = CURLDIGESTALGO_SHA256 as i32;
            } else if Curl_strcasecompare(
                    content.as_mut_ptr(),
                    b"SHA-256-SESS\0" as *const u8 as *const i8,
                ) != 0
                {
                (*digest).algo = CURLDIGESTALGO_SHA256SESS as i32;
            } else if Curl_strcasecompare(
                    content.as_mut_ptr(),
                    b"SHA-512-256\0" as *const u8 as *const i8,
                ) != 0
                {
                (*digest).algo = CURLDIGESTALGO_SHA512_256 as i32;
            } else if Curl_strcasecompare(
                    content.as_mut_ptr(),
                    b"SHA-512-256-SESS\0" as *const u8 as *const i8,
                ) != 0
                {
                (*digest).algo = CURLDIGESTALGO_SHA512_256SESS as i32;
            } else {
                return CURLE_BAD_CONTENT_ENCODING
            }
        } else if Curl_strcasecompare(
                value.as_mut_ptr(),
                b"userhash\0" as *const u8 as *const i8,
            ) != 0
            {
            if Curl_strcasecompare(
                content.as_mut_ptr(),
                b"true\0" as *const u8 as *const i8,
            ) != 0
            {
                (*digest).set_userhash(1 as i32 as bit);
            }
        }
        while *chlg as i32 != 0
            && Curl_isspace(*chlg as u8 as i32) != 0
        {
            chlg = chlg.offset(1);
        }
        if ',' as i32 == *chlg as i32 {
            chlg = chlg.offset(1);
        }
    }
    if before as i32 != 0 && (*digest).stale() == 0 {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    if ((*digest).nonce).is_null() {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    return CURLE_OK;
}
unsafe extern "C" fn auth_create_digest_http_message(
    mut data: *mut Curl_easy,
    mut userp: *const i8,
    mut passwdp: *const i8,
    mut request: *const u8,
    mut uripath: *const u8,
    mut digest: *mut digestdata,
    mut outptr: *mut *mut i8,
    mut outlen: *mut size_t,
    mut convert_to_ascii: Option::<
        unsafe extern "C" fn(*mut u8, *mut u8) -> (),
    >,
    mut hash: Option::<
        unsafe extern "C" fn(*mut u8, *const u8, size_t) -> (),
    >,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut hashbuf: [u8; 32] = [0; 32];
    let mut request_digest: [u8; 65] = [0; 65];
    let mut ha1: [u8; 65] = [0; 65];
    let mut ha2: [u8; 65] = [0; 65];
    let mut userh: [i8; 65] = [0; 65];
    let mut cnonce: *mut i8 = 0 as *mut i8;
    let mut cnonce_sz: size_t = 0 as i32 as size_t;
    let mut userp_quoted: *mut i8 = 0 as *mut i8;
    let mut response: *mut i8 = 0 as *mut i8;
    let mut hashthis: *mut i8 = 0 as *mut i8;
    let mut tmp: *mut i8 = 0 as *mut i8;
    if (*digest).nc == 0 {
        (*digest).nc = 1 as i32;
    }
    if ((*digest).cnonce).is_null() {
        let mut cnoncebuf: [i8; 33] = [0; 33];
        result = Curl_rand_hex(
            data,
            cnoncebuf.as_mut_ptr() as *mut u8,
            ::std::mem::size_of::<[i8; 33]>() as u64,
        );
        if result as u64 != 0 {
            return result;
        }
        result = Curl_base64_encode(
            data,
            cnoncebuf.as_mut_ptr(),
            strlen(cnoncebuf.as_mut_ptr()),
            &mut cnonce,
            &mut cnonce_sz,
        );
        if result as u64 != 0 {
            return result;
        }
        let fresh17 = &mut ((*digest).cnonce);
        *fresh17 = cnonce;
    }
    if (*digest).userhash() != 0 {
        hashthis = curl_maprintf(
            b"%s:%s\0" as *const u8 as *const i8,
            userp,
            (*digest).realm,
        );
        if hashthis.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        result = CURLE_OK as i32 as CURLcode;
        if result as u64 != 0 {
            Curl_cfree
                .expect("non-null function pointer")(hashthis as *mut libc::c_void);
            return result;
        }
        hash
            .expect(
                "non-null function pointer",
            )(hashbuf.as_mut_ptr(), hashthis as *mut u8, strlen(hashthis));
        Curl_cfree.expect("non-null function pointer")(hashthis as *mut libc::c_void);
        convert_to_ascii
            .expect(
                "non-null function pointer",
            )(hashbuf.as_mut_ptr(), userh.as_mut_ptr() as *mut u8);
    }
    hashthis = curl_maprintf(
        b"%s:%s:%s\0" as *const u8 as *const i8,
        if (*digest).userhash() as i32 != 0 {
            userh.as_mut_ptr() as *const i8
        } else {
            userp
        },
        (*digest).realm,
        passwdp,
    );
    if hashthis.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    result = CURLE_OK as i32 as CURLcode;
    if result as u64 != 0 {
        Curl_cfree.expect("non-null function pointer")(hashthis as *mut libc::c_void);
        return result;
    }
    hash
        .expect(
            "non-null function pointer",
        )(hashbuf.as_mut_ptr(), hashthis as *mut u8, strlen(hashthis));
    Curl_cfree.expect("non-null function pointer")(hashthis as *mut libc::c_void);
    convert_to_ascii
        .expect("non-null function pointer")(hashbuf.as_mut_ptr(), ha1.as_mut_ptr());
    if (*digest).algo == CURLDIGESTALGO_MD5SESS as i32
        || (*digest).algo == CURLDIGESTALGO_SHA256SESS as i32
        || (*digest).algo == CURLDIGESTALGO_SHA512_256SESS as i32
    {
        tmp = curl_maprintf(
            b"%s:%s:%s\0" as *const u8 as *const i8,
            ha1.as_mut_ptr(),
            (*digest).nonce,
            (*digest).cnonce,
        );
        if tmp.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        result = CURLE_OK as i32 as CURLcode;
        if result as u64 != 0 {
            Curl_cfree.expect("non-null function pointer")(tmp as *mut libc::c_void);
            return result;
        }
        hash
            .expect(
                "non-null function pointer",
            )(hashbuf.as_mut_ptr(), tmp as *mut u8, strlen(tmp));
        Curl_cfree.expect("non-null function pointer")(tmp as *mut libc::c_void);
        convert_to_ascii
            .expect("non-null function pointer")(hashbuf.as_mut_ptr(), ha1.as_mut_ptr());
    }
    hashthis = curl_maprintf(
        b"%s:%s\0" as *const u8 as *const i8,
        request,
        uripath,
    );
    if hashthis.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if !((*digest).qop).is_null()
        && Curl_strcasecompare(
            (*digest).qop,
            b"auth-int\0" as *const u8 as *const i8,
        ) != 0
    {
        let mut hashed: [i8; 65] = [0; 65];
        let mut hashthis2: *mut i8 = 0 as *mut i8;
        hash
            .expect(
                "non-null function pointer",
            )(
            hashbuf.as_mut_ptr(),
            b"\0" as *const u8 as *const i8 as *const u8,
            0 as i32 as size_t,
        );
        convert_to_ascii
            .expect(
                "non-null function pointer",
            )(hashbuf.as_mut_ptr(), hashed.as_mut_ptr() as *mut u8);
        hashthis2 = curl_maprintf(
            b"%s:%s\0" as *const u8 as *const i8,
            hashthis,
            hashed.as_mut_ptr(),
        );
        Curl_cfree.expect("non-null function pointer")(hashthis as *mut libc::c_void);
        hashthis = hashthis2;
    }
    if hashthis.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    result = CURLE_OK as i32 as CURLcode;
    if result as u64 != 0 {
        Curl_cfree.expect("non-null function pointer")(hashthis as *mut libc::c_void);
        return result;
    }
    hash
        .expect(
            "non-null function pointer",
        )(hashbuf.as_mut_ptr(), hashthis as *mut u8, strlen(hashthis));
    Curl_cfree.expect("non-null function pointer")(hashthis as *mut libc::c_void);
    convert_to_ascii
        .expect("non-null function pointer")(hashbuf.as_mut_ptr(), ha2.as_mut_ptr());
    if !((*digest).qop).is_null() {
        hashthis = curl_maprintf(
            b"%s:%s:%08x:%s:%s:%s\0" as *const u8 as *const i8,
            ha1.as_mut_ptr(),
            (*digest).nonce,
            (*digest).nc,
            (*digest).cnonce,
            (*digest).qop,
            ha2.as_mut_ptr(),
        );
    } else {
        hashthis = curl_maprintf(
            b"%s:%s:%s\0" as *const u8 as *const i8,
            ha1.as_mut_ptr(),
            (*digest).nonce,
            ha2.as_mut_ptr(),
        );
    }
    if hashthis.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    result = CURLE_OK as i32 as CURLcode;
    if result as u64 != 0 {
        Curl_cfree.expect("non-null function pointer")(hashthis as *mut libc::c_void);
        return result;
    }
    hash
        .expect(
            "non-null function pointer",
        )(hashbuf.as_mut_ptr(), hashthis as *mut u8, strlen(hashthis));
    Curl_cfree.expect("non-null function pointer")(hashthis as *mut libc::c_void);
    convert_to_ascii
        .expect(
            "non-null function pointer",
        )(hashbuf.as_mut_ptr(), request_digest.as_mut_ptr());
    userp_quoted = auth_digest_string_quoted(
        if (*digest).userhash() as i32 != 0 {
            userh.as_mut_ptr() as *const i8
        } else {
            userp
        },
    );
    if userp_quoted.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if !((*digest).qop).is_null() {
        response = curl_maprintf(
            b"username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", cnonce=\"%s\", nc=%08x, qop=%s, response=\"%s\"\0"
                as *const u8 as *const i8,
            userp_quoted,
            (*digest).realm,
            (*digest).nonce,
            uripath,
            (*digest).cnonce,
            (*digest).nc,
            (*digest).qop,
            request_digest.as_mut_ptr(),
        );
        if Curl_strcasecompare(
            (*digest).qop,
            b"auth\0" as *const u8 as *const i8,
        ) != 0
        {
            let fresh18 = &mut ((*digest).nc);
            *fresh18 += 1;
        }
    } else {
        response = curl_maprintf(
            b"username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"\0"
                as *const u8 as *const i8,
            userp_quoted,
            (*digest).realm,
            (*digest).nonce,
            uripath,
            request_digest.as_mut_ptr(),
        );
    }
    Curl_cfree.expect("non-null function pointer")(userp_quoted as *mut libc::c_void);
    if response.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if !((*digest).opaque).is_null() {
        tmp = curl_maprintf(
            b"%s, opaque=\"%s\"\0" as *const u8 as *const i8,
            response,
            (*digest).opaque,
        );
        Curl_cfree.expect("non-null function pointer")(response as *mut libc::c_void);
        if tmp.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        response = tmp;
    }
    if !((*digest).algorithm).is_null() {
        tmp = curl_maprintf(
            b"%s, algorithm=%s\0" as *const u8 as *const i8,
            response,
            (*digest).algorithm,
        );
        Curl_cfree.expect("non-null function pointer")(response as *mut libc::c_void);
        if tmp.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        response = tmp;
    }
    if (*digest).userhash() != 0 {
        tmp = curl_maprintf(
            b"%s, userhash=true\0" as *const u8 as *const i8,
            response,
        );
        Curl_cfree.expect("non-null function pointer")(response as *mut libc::c_void);
        if tmp.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        response = tmp;
    }
    *outptr = response;
    *outlen = strlen(response);
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_auth_create_digest_http_message(
    mut data: *mut Curl_easy,
    mut userp: *const i8,
    mut passwdp: *const i8,
    mut request: *const u8,
    mut uripath: *const u8,
    mut digest: *mut digestdata,
    mut outptr: *mut *mut i8,
    mut outlen: *mut size_t,
) -> CURLcode {
    match (*digest).algo {
        0 | 1 => {
            return auth_create_digest_http_message(
                data,
                userp,
                passwdp,
                request,
                uripath,
                digest,
                outptr,
                outlen,
                Some(
                    auth_digest_md5_to_ascii
                        as unsafe extern "C" fn(
                            *mut u8,
                            *mut u8,
                        ) -> (),
                ),
                Some(
                    Curl_md5it
                        as unsafe extern "C" fn(
                            *mut u8,
                            *const u8,
                            size_t,
                        ) -> (),
                ),
            );
        }
        2 | 3 | 4 | 5 => {
            return auth_create_digest_http_message(
                data,
                userp,
                passwdp,
                request,
                uripath,
                digest,
                outptr,
                outlen,
                Some(
                    auth_digest_sha256_to_ascii
                        as unsafe extern "C" fn(
                            *mut u8,
                            *mut u8,
                        ) -> (),
                ),
                Some(
                    Curl_sha256it
                        as unsafe extern "C" fn(
                            *mut u8,
                            *const u8,
                            size_t,
                        ) -> (),
                ),
            );
        }
        _ => return CURLE_UNSUPPORTED_PROTOCOL,
    };
}
#[no_mangle]
pub unsafe extern "C" fn Curl_auth_digest_cleanup(mut digest: *mut digestdata) {
    Curl_cfree.expect("non-null function pointer")((*digest).nonce as *mut libc::c_void);
    let fresh19 = &mut ((*digest).nonce);
    *fresh19 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*digest).cnonce as *mut libc::c_void);
    let fresh20 = &mut ((*digest).cnonce);
    *fresh20 = 0 as *mut i8;
    Curl_cfree.expect("non-null function pointer")((*digest).realm as *mut libc::c_void);
    let fresh21 = &mut ((*digest).realm);
    *fresh21 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*digest).opaque as *mut libc::c_void);
    let fresh22 = &mut ((*digest).opaque);
    *fresh22 = 0 as *mut i8;
    Curl_cfree.expect("non-null function pointer")((*digest).qop as *mut libc::c_void);
    let fresh23 = &mut ((*digest).qop);
    *fresh23 = 0 as *mut i8;
    Curl_cfree
        .expect("non-null function pointer")((*digest).algorithm as *mut libc::c_void);
    let fresh24 = &mut ((*digest).algorithm);
    *fresh24 = 0 as *mut i8;
    (*digest).nc = 0 as i32;
    (*digest).algo = CURLDIGESTALGO_MD5 as i32;
    (*digest).set_stale(0 as i32 as bit);
    (*digest).set_userhash(0 as i32 as bit);
}
