use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
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
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> i32;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strpbrk(_: *const i8, _: *const i8) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::connect::Curl_conncontrol;
pub use crate::src::lib::curl_ctype::Curl_isdigit;
pub use crate::src::lib::curl_gethostname::Curl_gethostname;
pub use crate::src::lib::curl_sasl::Curl_sasl_can_authenticate;
pub use crate::src::lib::curl_sasl::Curl_sasl_cleanup;
pub use crate::src::lib::curl_sasl::Curl_sasl_continue;
pub use crate::src::lib::curl_sasl::Curl_sasl_decode_mech;
pub use crate::src::lib::curl_sasl::Curl_sasl_init;
pub use crate::src::lib::curl_sasl::Curl_sasl_parse_url_auth_option;
pub use crate::src::lib::curl_sasl::Curl_sasl_start;
pub use crate::src::lib::escape::Curl_urldecode;
pub use crate::src::lib::mime::Curl_mime_add_header;
pub use crate::src::lib::mime::Curl_mime_prepare_headers;
pub use crate::src::lib::mime::Curl_mime_read;
pub use crate::src::lib::mime::Curl_mime_rewind;
pub use crate::src::lib::mime::Curl_mime_size;
pub use crate::src::lib::mime::curl_mime_headers;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::pingpong::Curl_pp_disconnect;
pub use crate::src::lib::pingpong::Curl_pp_flushsend;
pub use crate::src::lib::pingpong::Curl_pp_getsock;
pub use crate::src::lib::pingpong::Curl_pp_init;
pub use crate::src::lib::pingpong::Curl_pp_moredata;
pub use crate::src::lib::pingpong::Curl_pp_readresp;
pub use crate::src::lib::pingpong::Curl_pp_sendf;
pub use crate::src::lib::pingpong::Curl_pp_setup;
pub use crate::src::lib::pingpong::Curl_pp_statemach;
pub use crate::src::lib::progress::Curl_pgrsSetDownloadCounter;
pub use crate::src::lib::progress::Curl_pgrsSetDownloadSize;
pub use crate::src::lib::progress::Curl_pgrsSetUploadCounter;
pub use crate::src::lib::progress::Curl_pgrsSetUploadSize;
pub use crate::src::lib::sendf::Curl_client_write;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::sendf::Curl_write;
pub use crate::src::lib::strcase::Curl_strncasecompare;
pub use crate::src::lib::timeval::Curl_now;
pub use crate::src::lib::transfer::Curl_checkheaders;
pub use crate::src::lib::transfer::Curl_setup_transfer;
pub use crate::src::lib::url::Curl_free_idnconverted_hostname;
pub use crate::src::lib::url::Curl_idnconvert_hostname;
pub use crate::src::lib::url::Curl_is_ASCII_name;
pub use crate::src::lib::vtls::vtls::Curl_ssl_connect_nonblocking;
pub use crate::src::lib::warnless::curlx_sltosi;
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
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
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
pub type curl_calloc_callback = crate::src::lib::altsvc::curl_calloc_callback;
pub type mimestrategy = crate::src::lib::formdata::mimestrategy;
pub const MIMESTRATEGY_LAST: mimestrategy = 2;
pub const MIMESTRATEGY_FORM: mimestrategy = 1;
pub const MIMESTRATEGY_MAIL: mimestrategy = 0;
pub type saslprogress = crate::src::lib::curl_sasl::saslprogress;
pub const SASL_DONE: saslprogress = 2;
pub const SASL_INPROGRESS: saslprogress = 1;
pub const SASL_IDLE: saslprogress = 0;
pub type urlreject = crate::src::lib::dict::urlreject;
pub const REJECT_ZERO: urlreject = 4;
pub const REJECT_CTRL: urlreject = 3;
pub const REJECT_NADA: urlreject = 2;
pub const STRING_MAIL_AUTH: dupstring = 60;
pub const STRING_MAIL_FROM: dupstring = 59;
pub const STRING_CUSTOMREQUEST: dupstring = 6;
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
pub const STRING_COOKIEJAR: dupstring = 5;
pub const STRING_COOKIE: dupstring = 4;
pub const STRING_CERT_TYPE_PROXY: dupstring = 3;
pub const STRING_CERT_TYPE: dupstring = 2;
pub const STRING_CERT_PROXY: dupstring = 1;
pub const STRING_CERT: dupstring = 0;
#[no_mangle]
pub static mut Curl_handler_smtp: Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"SMTP\0" as *const u8 as *const i8,
            setup_connection: Some(
                smtp_setup_connection
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
            ),
            do_it: Some(
                smtp_do as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            done: Some(
                smtp_done
                    as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
            ),
            do_more: None,
            connect_it: Some(
                smtp_connect
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            connecting: Some(
                smtp_multi_statemach
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            doing: Some(
                smtp_doing as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            proto_getsock: Some(
                smtp_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            doing_getsock: Some(
                smtp_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            domore_getsock: None,
            perform_getsock: None,
            disconnect: Some(
                smtp_disconnect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        bool,
                    ) -> CURLcode,
            ),
            readwrite: None,
            connection_check: None,
            attach: None,
            defport: 25 as i32,
            protocol: ((1 as i32) << 16 as i32) as u32,
            family: ((1 as i32) << 16 as i32) as u32,
            flags: ((1 as i32) << 2 as i32
                | (1 as i32) << 6 as i32
                | (1 as i32) << 10 as i32) as u32,
        };
        init
    }
};
#[no_mangle]
pub static mut Curl_handler_smtps: Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"SMTPS\0" as *const u8 as *const i8,
            setup_connection: Some(
                smtp_setup_connection
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
            ),
            do_it: Some(
                smtp_do as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            done: Some(
                smtp_done
                    as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
            ),
            do_more: None,
            connect_it: Some(
                smtp_connect
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            connecting: Some(
                smtp_multi_statemach
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            doing: Some(
                smtp_doing as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            proto_getsock: Some(
                smtp_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            doing_getsock: Some(
                smtp_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            domore_getsock: None,
            perform_getsock: None,
            disconnect: Some(
                smtp_disconnect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        bool,
                    ) -> CURLcode,
            ),
            readwrite: None,
            connection_check: None,
            attach: None,
            defport: 465 as i32,
            protocol: ((1 as i32) << 17 as i32) as u32,
            family: ((1 as i32) << 16 as i32) as u32,
            flags: ((1 as i32) << 2 as i32
                | (1 as i32) << 0 as i32
                | (1 as i32) << 6 as i32
                | (1 as i32) << 10 as i32) as u32,
        };
        init
    }
};
static mut saslsmtp: SASLproto = unsafe {
    {
        let mut init = SASLproto {
            service: b"smtp\0" as *const u8 as *const i8,
            contcode: 334 as i32,
            finalcode: 235 as i32,
            maxirlen: (512 as i32 - 8 as i32) as size_t,
            sendauth: Some(
                smtp_perform_auth
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *const i8,
                        *const i8,
                    ) -> CURLcode,
            ),
            sendcont: Some(
                smtp_continue_auth
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *const i8,
                    ) -> CURLcode,
            ),
            getmessage: Some(
                smtp_get_message
                    as unsafe extern "C" fn(
                        *mut i8,
                        *mut *mut i8,
                    ) -> (),
            ),
        };
        init
    }
};
unsafe extern "C" fn smtp_to_smtps(mut conn: *mut connectdata) {
    let fresh0 = &mut ((*conn).handler);
    *fresh0 = &Curl_handler_smtps;
    let fresh1 = &mut ((*conn).bits);
    (*fresh1).set_tls_upgraded(1 as i32 as bit);
}
unsafe extern "C" fn smtp_endofresp(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut line: *mut i8,
    mut len: size_t,
    mut resp: *mut i32,
) -> bool {
    let mut smtpc: *mut smtp_conn = &mut (*conn).proto.smtpc;
    let mut result: bool = 0 as i32 != 0;
    if len < 4 as i32 as u64
        || Curl_isdigit(
            *line.offset(0 as i32 as isize) as u8 as i32,
        ) == 0
        || Curl_isdigit(
            *line.offset(1 as i32 as isize) as u8 as i32,
        ) == 0
        || Curl_isdigit(
            *line.offset(2 as i32 as isize) as u8 as i32,
        ) == 0
    {
        return 0 as i32 != 0;
    }
    if *line.offset(3 as i32 as isize) as i32 == ' ' as i32
        || len == 5 as i32 as u64
    {
        let mut tmpline: [i8; 6] = [0; 6];
        result = 1 as i32 != 0;
        memset(
            tmpline.as_mut_ptr() as *mut libc::c_void,
            '\u{0}' as i32,
            ::std::mem::size_of::<[i8; 6]>() as u64,
        );
        memcpy(
            tmpline.as_mut_ptr() as *mut libc::c_void,
            line as *const libc::c_void,
            (if len == 5 as i32 as u64 {
                5 as i32
            } else {
                3 as i32
            }) as u64,
        );
        *resp = curlx_sltosi(
            strtol(tmpline.as_mut_ptr(), 0 as *mut *mut i8, 10 as i32),
        );
        if *resp == 1 as i32 {
            *resp = 0 as i32;
        }
    } else if *line.offset(3 as i32 as isize) as i32 == '-' as i32
            && ((*smtpc).state as u32
                == SMTP_EHLO as i32 as u32
                || (*smtpc).state as u32
                    == SMTP_COMMAND as i32 as u32)
        {
        result = 1 as i32 != 0;
        *resp = 1 as i32;
    }
    return result;
}
unsafe extern "C" fn smtp_get_message(
    mut buffer: *mut i8,
    mut outptr: *mut *mut i8,
) {
    let mut len: size_t = strlen(buffer);
    let mut message: *mut i8 = 0 as *mut i8;
    if len > 4 as i32 as u64 {
        len = (len as u64).wrapping_sub(4 as i32 as u64)
            as size_t as size_t;
        message = buffer.offset(4 as i32 as isize);
        while *message as i32 == ' ' as i32
            || *message as i32 == '\t' as i32
        {
            message = message.offset(1);
            len = len.wrapping_sub(1);
        }
        loop {
            let fresh2 = len;
            len = len.wrapping_sub(1);
            if !(fresh2 != 0) {
                break;
            }
            if *message.offset(len as isize) as i32 != '\r' as i32
                && *message.offset(len as isize) as i32 != '\n' as i32
                && *message.offset(len as isize) as i32 != ' ' as i32
                && *message.offset(len as isize) as i32 != '\t' as i32
            {
                break;
            }
        }
        len = len.wrapping_add(1);
        if len != 0 {
            *message.offset(len as isize) = '\u{0}' as i32 as i8;
        }
    } else {
        message = &mut *buffer.offset(len as isize) as *mut i8;
    }
    *outptr = message;
}
unsafe extern "C" fn state(mut data: *mut Curl_easy, mut newstate: smtpstate) {
    let mut smtpc: *mut smtp_conn = &mut (*(*data).conn).proto.smtpc;
    (*smtpc).state = newstate;
}
unsafe extern "C" fn smtp_perform_ehlo(mut data: *mut Curl_easy) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut smtpc: *mut smtp_conn = &mut (*conn).proto.smtpc;
    (*smtpc).sasl.authmechs = 0 as i32 as u16;
    (*smtpc).sasl.authused = 0 as i32 as u16;
    (*smtpc).tls_supported = 0 as i32 != 0;
    (*smtpc).auth_supported = 0 as i32 != 0;
    result = Curl_pp_sendf(
        data,
        &mut (*smtpc).pp as *mut pingpong,
        b"EHLO %s\0" as *const u8 as *const i8,
        (*smtpc).domain,
    );
    if result as u64 == 0 {
        state(data, SMTP_EHLO);
    }
    return result;
}
unsafe extern "C" fn smtp_perform_helo(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut smtpc: *mut smtp_conn = &mut (*conn).proto.smtpc;
    (*smtpc).sasl.authused = 0 as i32 as u16;
    result = Curl_pp_sendf(
        data,
        &mut (*smtpc).pp as *mut pingpong,
        b"HELO %s\0" as *const u8 as *const i8,
        (*smtpc).domain,
    );
    if result as u64 == 0 {
        state(data, SMTP_HELO);
    }
    return result;
}
unsafe extern "C" fn smtp_perform_starttls(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = Curl_pp_sendf(
        data,
        &mut (*conn).proto.smtpc.pp as *mut pingpong,
        b"%s\0" as *const u8 as *const i8,
        b"STARTTLS\0" as *const u8 as *const i8,
    );
    if result as u64 == 0 {
        state(data, SMTP_STARTTLS);
    }
    return result;
}
unsafe extern "C" fn smtp_perform_upgrade_tls(mut data: *mut Curl_easy) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut smtpc: *mut smtp_conn = &mut (*conn).proto.smtpc;
    let mut result: CURLcode = Curl_ssl_connect_nonblocking(
        data,
        conn,
        0 as i32 != 0,
        0 as i32,
        &mut (*smtpc).ssldone,
    );
    if result as u64 == 0 {
        if (*smtpc).state as u32
            != SMTP_UPGRADETLS as i32 as u32
        {
            state(data, SMTP_UPGRADETLS);
        }
        if (*smtpc).ssldone {
            smtp_to_smtps(conn);
            result = smtp_perform_ehlo(data);
        }
    }
    return result;
}
unsafe extern "C" fn smtp_perform_auth(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut mech: *const i8,
    mut initresp: *const i8,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut smtpc: *mut smtp_conn = &mut (*conn).proto.smtpc;
    if !initresp.is_null() {
        result = Curl_pp_sendf(
            data,
            &mut (*smtpc).pp as *mut pingpong,
            b"AUTH %s %s\0" as *const u8 as *const i8,
            mech,
            initresp,
        );
    } else {
        result = Curl_pp_sendf(
            data,
            &mut (*smtpc).pp as *mut pingpong,
            b"AUTH %s\0" as *const u8 as *const i8,
            mech,
        );
    }
    return result;
}
unsafe extern "C" fn smtp_continue_auth(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut resp: *const i8,
) -> CURLcode {
    let mut smtpc: *mut smtp_conn = &mut (*conn).proto.smtpc;
    return Curl_pp_sendf(
        data,
        &mut (*smtpc).pp as *mut pingpong,
        b"%s\0" as *const u8 as *const i8,
        resp,
    );
}
unsafe extern "C" fn smtp_perform_authentication(mut data: *mut Curl_easy) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut smtpc: *mut smtp_conn = &mut (*conn).proto.smtpc;
    let mut progress: saslprogress = SASL_IDLE;
    if !(*smtpc).auth_supported || !Curl_sasl_can_authenticate(&mut (*smtpc).sasl, conn)
    {
        state(data, SMTP_STOP);
        return result;
    }
    result = Curl_sasl_start(
        &mut (*smtpc).sasl,
        data,
        conn,
        0 as i32 != 0,
        &mut progress,
    );
    if result as u64 == 0 {
        if progress as u32 == SASL_INPROGRESS as i32 as u32 {
            state(data, SMTP_AUTH);
        } else {
            Curl_infof(
                data,
                b"No known authentication mechanisms supported!\0" as *const u8
                    as *const i8,
            );
            result = CURLE_LOGIN_DENIED;
        }
    }
    return result;
}
unsafe extern "C" fn smtp_perform_command(mut data: *mut Curl_easy) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut smtp: *mut SMTP = (*data).req.p.smtp;
    if !((*smtp).rcpt).is_null() {
        let mut utf8: bool = 0 as i32 != 0;
        if ((*smtp).custom).is_null()
            || *((*smtp).custom).offset(0 as i32 as isize) == 0
        {
            let mut address: *mut i8 = 0 as *mut i8;
            let mut host: hostname = {
                let mut init = hostname {
                    rawalloc: 0 as *mut i8,
                    encalloc: 0 as *mut i8,
                    name: 0 as *mut i8,
                    dispname: 0 as *const i8,
                };
                init
            };
            result = smtp_parse_address(
                data,
                (*(*smtp).rcpt).data,
                &mut address,
                &mut host,
            );
            if result as u64 != 0 {
                return result;
            }
            utf8 = (*conn).proto.smtpc.utf8_supported as i32 != 0
                && (!(host.encalloc).is_null() || !Curl_is_ASCII_name(address)
                    || !Curl_is_ASCII_name(host.name));
            result = Curl_pp_sendf(
                data,
                &mut (*conn).proto.smtpc.pp as *mut pingpong,
                b"VRFY %s%s%s%s\0" as *const u8 as *const i8,
                address,
                if !(host.name).is_null() {
                    b"@\0" as *const u8 as *const i8
                } else {
                    b"\0" as *const u8 as *const i8
                },
                if !(host.name).is_null() {
                    host.name as *const i8
                } else {
                    b"\0" as *const u8 as *const i8
                },
                if utf8 as i32 != 0 {
                    b" SMTPUTF8\0" as *const u8 as *const i8
                } else {
                    b"\0" as *const u8 as *const i8
                },
            );
            Curl_free_idnconverted_hostname(&mut host);
            Curl_cfree.expect("non-null function pointer")(address as *mut libc::c_void);
        } else {
            utf8 = (*conn).proto.smtpc.utf8_supported as i32 != 0
                && strcmp((*smtp).custom, b"EXPN\0" as *const u8 as *const i8)
                    == 0;
            result = Curl_pp_sendf(
                data,
                &mut (*conn).proto.smtpc.pp as *mut pingpong,
                b"%s %s%s\0" as *const u8 as *const i8,
                (*smtp).custom,
                (*(*smtp).rcpt).data,
                if utf8 as i32 != 0 {
                    b" SMTPUTF8\0" as *const u8 as *const i8
                } else {
                    b"\0" as *const u8 as *const i8
                },
            );
        }
    } else {
        result = Curl_pp_sendf(
            data,
            &mut (*conn).proto.smtpc.pp as *mut pingpong,
            b"%s\0" as *const u8 as *const i8,
            if !((*smtp).custom).is_null()
                && *((*smtp).custom).offset(0 as i32 as isize) as i32
                    != '\u{0}' as i32
            {
                (*smtp).custom as *const i8
            } else {
                b"HELP\0" as *const u8 as *const i8
            },
        );
    }
    if result as u64 == 0 {
        state(data, SMTP_COMMAND);
    }
    return result;
}
unsafe extern "C" fn smtp_perform_mail(mut data: *mut Curl_easy) -> CURLcode {
    let mut from: *mut i8 = 0 as *mut i8;
    let mut auth: *mut i8 = 0 as *mut i8;
    let mut size: *mut i8 = 0 as *mut i8;
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut utf8: bool = 0 as i32 != 0;
    if !((*data).set.str_0[STRING_MAIL_FROM as i32 as usize]).is_null() {
        let mut address: *mut i8 = 0 as *mut i8;
        let mut host: hostname = {
            let mut init = hostname {
                rawalloc: 0 as *mut i8,
                encalloc: 0 as *mut i8,
                name: 0 as *mut i8,
                dispname: 0 as *const i8,
            };
            init
        };
        result = smtp_parse_address(
            data,
            (*data).set.str_0[STRING_MAIL_FROM as i32 as usize],
            &mut address,
            &mut host,
        );
        if result as u64 != 0 {
            return result;
        }
        utf8 = (*conn).proto.smtpc.utf8_supported as i32 != 0
            && (!(host.encalloc).is_null() || !Curl_is_ASCII_name(address)
                || !Curl_is_ASCII_name(host.name));
        if !(host.name).is_null() {
            from = curl_maprintf(
                b"<%s@%s>\0" as *const u8 as *const i8,
                address,
                host.name,
            );
            Curl_free_idnconverted_hostname(&mut host);
        } else {
            from = curl_maprintf(b"<%s>\0" as *const u8 as *const i8, address);
        }
        Curl_cfree.expect("non-null function pointer")(address as *mut libc::c_void);
    } else {
        from = Curl_cstrdup
            .expect(
                "non-null function pointer",
            )(b"<>\0" as *const u8 as *const i8);
    }
    if from.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if !((*data).set.str_0[STRING_MAIL_AUTH as i32 as usize]).is_null()
        && (*conn).proto.smtpc.sasl.authused as i32 != 0
    {
        if *((*data).set.str_0[STRING_MAIL_AUTH as i32 as usize])
            .offset(0 as i32 as isize) as i32 != '\u{0}' as i32
        {
            let mut address_0: *mut i8 = 0 as *mut i8;
            let mut host_0: hostname = {
                let mut init = hostname {
                    rawalloc: 0 as *mut i8,
                    encalloc: 0 as *mut i8,
                    name: 0 as *mut i8,
                    dispname: 0 as *const i8,
                };
                init
            };
            result = smtp_parse_address(
                data,
                (*data).set.str_0[STRING_MAIL_AUTH as i32 as usize],
                &mut address_0,
                &mut host_0,
            );
            if result as u64 != 0 {
                Curl_cfree
                    .expect("non-null function pointer")(from as *mut libc::c_void);
                return result;
            }
            if !utf8 && (*conn).proto.smtpc.utf8_supported as i32 != 0
                && (!(host_0.encalloc).is_null() || !Curl_is_ASCII_name(address_0)
                    || !Curl_is_ASCII_name(host_0.name))
            {
                utf8 = 1 as i32 != 0;
            }
            if !(host_0.name).is_null() {
                auth = curl_maprintf(
                    b"<%s@%s>\0" as *const u8 as *const i8,
                    address_0,
                    host_0.name,
                );
                Curl_free_idnconverted_hostname(&mut host_0);
            } else {
                auth = curl_maprintf(
                    b"<%s>\0" as *const u8 as *const i8,
                    address_0,
                );
            }
            Curl_cfree
                .expect("non-null function pointer")(address_0 as *mut libc::c_void);
        } else {
            auth = Curl_cstrdup
                .expect(
                    "non-null function pointer",
                )(b"<>\0" as *const u8 as *const i8);
        }
        if auth.is_null() {
            Curl_cfree.expect("non-null function pointer")(from as *mut libc::c_void);
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if (*data).set.mimepost.kind as u32
        != MIMEKIND_NONE as i32 as u32
    {
        (*data).set.mimepost.flags
            &= !((1 as i32) << 1 as i32) as u32;
        curl_mime_headers(
            &mut (*data).set.mimepost,
            (*data).set.headers,
            0 as i32,
        );
        result = Curl_mime_prepare_headers(
            &mut (*data).set.mimepost,
            0 as *const i8,
            0 as *const i8,
            MIMESTRATEGY_MAIL,
        );
        if result as u64 == 0 {
            if (Curl_checkheaders(
                data,
                b"Mime-Version\0" as *const u8 as *const i8,
            ))
                .is_null()
            {
                result = Curl_mime_add_header(
                    &mut (*data).set.mimepost.curlheaders as *mut *mut curl_slist,
                    b"Mime-Version: 1.0\0" as *const u8 as *const i8,
                );
            }
        }
        if result as u64 == 0 {
            result = Curl_mime_rewind(&mut (*data).set.mimepost);
        }
        if result as u64 != 0 {
            Curl_cfree.expect("non-null function pointer")(from as *mut libc::c_void);
            Curl_cfree.expect("non-null function pointer")(auth as *mut libc::c_void);
            return result;
        }
        (*data).state.infilesize = Curl_mime_size(&mut (*data).set.mimepost);
        let fresh3 = &mut ((*data).state.fread_func);
        *fresh3 = ::std::mem::transmute::<
            Option::<
                unsafe extern "C" fn(
                    *mut i8,
                    size_t,
                    size_t,
                    *mut libc::c_void,
                ) -> size_t,
            >,
            curl_read_callback,
        >(
            Some(
                Curl_mime_read
                    as unsafe extern "C" fn(
                        *mut i8,
                        size_t,
                        size_t,
                        *mut libc::c_void,
                    ) -> size_t,
            ),
        );
        let fresh4 = &mut ((*data).state.in_0);
        *fresh4 = &mut (*data).set.mimepost as *mut curl_mimepart as *mut libc::c_void;
    }
    if (*conn).proto.smtpc.size_supported as i32 != 0
        && (*data).state.infilesize > 0 as i32 as i64
    {
        size = curl_maprintf(
            b"%ld\0" as *const u8 as *const i8,
            (*data).state.infilesize,
        );
        if size.is_null() {
            Curl_cfree.expect("non-null function pointer")(from as *mut libc::c_void);
            Curl_cfree.expect("non-null function pointer")(auth as *mut libc::c_void);
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if (*conn).proto.smtpc.utf8_supported as i32 != 0 && !utf8 {
        let mut smtp: *mut SMTP = (*data).req.p.smtp;
        let mut rcpt: *mut curl_slist = (*smtp).rcpt;
        while !rcpt.is_null() && !utf8 {
            if !Curl_is_ASCII_name((*rcpt).data) {
                utf8 = 1 as i32 != 0;
            }
            rcpt = (*rcpt).next;
        }
    }
    result = Curl_pp_sendf(
        data,
        &mut (*conn).proto.smtpc.pp as *mut pingpong,
        b"MAIL FROM:%s%s%s%s%s%s\0" as *const u8 as *const i8,
        from,
        if !auth.is_null() {
            b" AUTH=\0" as *const u8 as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !auth.is_null() {
            auth as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !size.is_null() {
            b" SIZE=\0" as *const u8 as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !size.is_null() {
            size as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        if utf8 as i32 != 0 {
            b" SMTPUTF8\0" as *const u8 as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
    );
    Curl_cfree.expect("non-null function pointer")(from as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(auth as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(size as *mut libc::c_void);
    if result as u64 == 0 {
        state(data, SMTP_MAIL);
    }
    return result;
}
unsafe extern "C" fn smtp_perform_rcpt_to(mut data: *mut Curl_easy) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut smtp: *mut SMTP = (*data).req.p.smtp;
    let mut address: *mut i8 = 0 as *mut i8;
    let mut host: hostname = {
        let mut init = hostname {
            rawalloc: 0 as *mut i8,
            encalloc: 0 as *mut i8,
            name: 0 as *mut i8,
            dispname: 0 as *const i8,
        };
        init
    };
    result = smtp_parse_address(data, (*(*smtp).rcpt).data, &mut address, &mut host);
    if result as u64 != 0 {
        return result;
    }
    if !(host.name).is_null() {
        result = Curl_pp_sendf(
            data,
            &mut (*conn).proto.smtpc.pp as *mut pingpong,
            b"RCPT TO:<%s@%s>\0" as *const u8 as *const i8,
            address,
            host.name,
        );
    } else {
        result = Curl_pp_sendf(
            data,
            &mut (*conn).proto.smtpc.pp as *mut pingpong,
            b"RCPT TO:<%s>\0" as *const u8 as *const i8,
            address,
        );
    }
    Curl_free_idnconverted_hostname(&mut host);
    Curl_cfree.expect("non-null function pointer")(address as *mut libc::c_void);
    if result as u64 == 0 {
        state(data, SMTP_RCPT);
    }
    return result;
}
unsafe extern "C" fn smtp_perform_quit(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = Curl_pp_sendf(
        data,
        &mut (*conn).proto.smtpc.pp as *mut pingpong,
        b"%s\0" as *const u8 as *const i8,
        b"QUIT\0" as *const u8 as *const i8,
    );
    if result as u64 == 0 {
        state(data, SMTP_QUIT);
    }
    return result;
}
unsafe extern "C" fn smtp_state_servergreet_resp(
    mut data: *mut Curl_easy,
    mut smtpcode: i32,
    mut instate: smtpstate,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    if smtpcode / 100 as i32 != 2 as i32 {
        Curl_failf(
            data,
            b"Got unexpected smtp-server response: %d\0" as *const u8
                as *const i8,
            smtpcode,
        );
        result = CURLE_WEIRD_SERVER_REPLY;
    } else {
        result = smtp_perform_ehlo(data);
    }
    return result;
}
unsafe extern "C" fn smtp_state_starttls_resp(
    mut data: *mut Curl_easy,
    mut smtpcode: i32,
    mut instate: smtpstate,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    if (*(*data).conn).proto.smtpc.pp.cache_size != 0 {
        return CURLE_WEIRD_SERVER_REPLY;
    }
    if smtpcode != 220 as i32 {
        if (*data).set.use_ssl as u32
            != CURLUSESSL_TRY as i32 as u32
        {
            Curl_failf(
                data,
                b"STARTTLS denied, code %d\0" as *const u8 as *const i8,
                smtpcode,
            );
            result = CURLE_USE_SSL_FAILED;
        } else {
            result = smtp_perform_authentication(data);
        }
    } else {
        result = smtp_perform_upgrade_tls(data);
    }
    return result;
}
unsafe extern "C" fn smtp_state_ehlo_resp(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut smtpcode: i32,
    mut instate: smtpstate,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut smtpc: *mut smtp_conn = &mut (*conn).proto.smtpc;
    let mut line: *const i8 = (*data).state.buffer;
    let mut len: size_t = strlen(line);
    if smtpcode / 100 as i32 != 2 as i32 && smtpcode != 1 as i32
    {
        if (*data).set.use_ssl as u32
            <= CURLUSESSL_TRY as i32 as u32
            || ((*conn).ssl[0 as i32 as usize]).use_0() as i32 != 0
        {
            result = smtp_perform_helo(data, conn);
        } else {
            Curl_failf(
                data,
                b"Remote access denied: %d\0" as *const u8 as *const i8,
                smtpcode,
            );
            result = CURLE_REMOTE_ACCESS_DENIED;
        }
    } else if len >= 4 as i32 as u64 {
        line = line.offset(4 as i32 as isize);
        len = (len as u64).wrapping_sub(4 as i32 as u64)
            as size_t as size_t;
        if len >= 8 as i32 as u64
            && memcmp(
                line as *const libc::c_void,
                b"STARTTLS\0" as *const u8 as *const i8 as *const libc::c_void,
                8 as i32 as u64,
            ) == 0
        {
            (*smtpc).tls_supported = 1 as i32 != 0;
        } else if len >= 4 as i32 as u64
                && memcmp(
                    line as *const libc::c_void,
                    b"SIZE\0" as *const u8 as *const i8 as *const libc::c_void,
                    4 as i32 as u64,
                ) == 0
            {
            (*smtpc).size_supported = 1 as i32 != 0;
        } else if len >= 8 as i32 as u64
                && memcmp(
                    line as *const libc::c_void,
                    b"SMTPUTF8\0" as *const u8 as *const i8
                        as *const libc::c_void,
                    8 as i32 as u64,
                ) == 0
            {
            (*smtpc).utf8_supported = 1 as i32 != 0;
        } else if len >= 5 as i32 as u64
                && memcmp(
                    line as *const libc::c_void,
                    b"AUTH \0" as *const u8 as *const i8
                        as *const libc::c_void,
                    5 as i32 as u64,
                ) == 0
            {
            (*smtpc).auth_supported = 1 as i32 != 0;
            line = line.offset(5 as i32 as isize);
            len = (len as u64).wrapping_sub(5 as i32 as u64)
                as size_t as size_t;
            loop {
                let mut llen: size_t = 0;
                let mut wordlen: size_t = 0;
                let mut mechbit: u16 = 0;
                while len != 0
                    && (*line as i32 == ' ' as i32
                        || *line as i32 == '\t' as i32
                        || *line as i32 == '\r' as i32
                        || *line as i32 == '\n' as i32)
                {
                    line = line.offset(1);
                    len = len.wrapping_sub(1);
                }
                if len == 0 {
                    break;
                }
                wordlen = 0 as i32 as size_t;
                while wordlen < len
                    && *line.offset(wordlen as isize) as i32 != ' ' as i32
                    && *line.offset(wordlen as isize) as i32 != '\t' as i32
                    && *line.offset(wordlen as isize) as i32 != '\r' as i32
                    && *line.offset(wordlen as isize) as i32 != '\n' as i32
                {
                    wordlen = wordlen.wrapping_add(1);
                }
                mechbit = Curl_sasl_decode_mech(line, wordlen, &mut llen);
                if mechbit as i32 != 0 && llen == wordlen {
                    let fresh5 = &mut ((*smtpc).sasl.authmechs);
                    *fresh5 = (*fresh5 as i32 | mechbit as i32)
                        as u16;
                }
                line = line.offset(wordlen as isize);
                len = (len as u64).wrapping_sub(wordlen) as size_t as size_t;
            }
        }
        if smtpcode != 1 as i32 {
            if (*data).set.use_ssl as u32 != 0
                && ((*conn).ssl[0 as i32 as usize]).use_0() == 0
            {
                if (*smtpc).tls_supported {
                    result = smtp_perform_starttls(data, conn);
                } else if (*data).set.use_ssl as u32
                        == CURLUSESSL_TRY as i32 as u32
                    {
                    result = smtp_perform_authentication(data);
                } else {
                    Curl_failf(
                        data,
                        b"STARTTLS not supported.\0" as *const u8 as *const i8,
                    );
                    result = CURLE_USE_SSL_FAILED;
                }
            } else {
                result = smtp_perform_authentication(data);
            }
        }
    } else {
        Curl_failf(
            data,
            b"Unexpectedly short EHLO response\0" as *const u8 as *const i8,
        );
        result = CURLE_WEIRD_SERVER_REPLY;
    }
    return result;
}
unsafe extern "C" fn smtp_state_helo_resp(
    mut data: *mut Curl_easy,
    mut smtpcode: i32,
    mut instate: smtpstate,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    if smtpcode / 100 as i32 != 2 as i32 {
        Curl_failf(
            data,
            b"Remote access denied: %d\0" as *const u8 as *const i8,
            smtpcode,
        );
        result = CURLE_REMOTE_ACCESS_DENIED;
    } else {
        state(data, SMTP_STOP);
    }
    return result;
}
unsafe extern "C" fn smtp_state_auth_resp(
    mut data: *mut Curl_easy,
    mut smtpcode: i32,
    mut instate: smtpstate,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut smtpc: *mut smtp_conn = &mut (*conn).proto.smtpc;
    let mut progress: saslprogress = SASL_IDLE;
    result = Curl_sasl_continue(&mut (*smtpc).sasl, data, conn, smtpcode, &mut progress);
    if result as u64 == 0 {
        match progress as u32 {
            2 => {
                state(data, SMTP_STOP);
            }
            0 => {
                Curl_failf(
                    data,
                    b"Authentication cancelled\0" as *const u8 as *const i8,
                );
                result = CURLE_LOGIN_DENIED;
            }
            _ => {}
        }
    }
    return result;
}
unsafe extern "C" fn smtp_state_command_resp(
    mut data: *mut Curl_easy,
    mut smtpcode: i32,
    mut instate: smtpstate,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut smtp: *mut SMTP = (*data).req.p.smtp;
    let mut line: *mut i8 = (*data).state.buffer;
    let mut len: size_t = strlen(line);
    if !((*smtp).rcpt).is_null() && smtpcode / 100 as i32 != 2 as i32
        && smtpcode != 553 as i32 && smtpcode != 1 as i32
        || ((*smtp).rcpt).is_null() && smtpcode / 100 as i32 != 2 as i32
            && smtpcode != 1 as i32
    {
        Curl_failf(
            data,
            b"Command failed: %d\0" as *const u8 as *const i8,
            smtpcode,
        );
        result = CURLE_RECV_ERROR;
    } else {
        if ((*data).set).opt_no_body() == 0 {
            *line.offset(len as isize) = '\n' as i32 as i8;
            result = Curl_client_write(
                data,
                (1 as i32) << 0 as i32,
                line,
                len.wrapping_add(1 as i32 as u64),
            );
            *line.offset(len as isize) = '\u{0}' as i32 as i8;
        }
        if smtpcode != 1 as i32 {
            if !((*smtp).rcpt).is_null() {
                let fresh6 = &mut ((*smtp).rcpt);
                *fresh6 = (*(*smtp).rcpt).next;
                if !((*smtp).rcpt).is_null() {
                    result = smtp_perform_command(data);
                } else {
                    state(data, SMTP_STOP);
                }
            } else {
                state(data, SMTP_STOP);
            }
        }
    }
    return result;
}
unsafe extern "C" fn smtp_state_mail_resp(
    mut data: *mut Curl_easy,
    mut smtpcode: i32,
    mut instate: smtpstate,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    if smtpcode / 100 as i32 != 2 as i32 {
        Curl_failf(
            data,
            b"MAIL failed: %d\0" as *const u8 as *const i8,
            smtpcode,
        );
        result = CURLE_SEND_ERROR;
    } else {
        result = smtp_perform_rcpt_to(data);
    }
    return result;
}
unsafe extern "C" fn smtp_state_rcpt_resp(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut smtpcode: i32,
    mut instate: smtpstate,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut smtp: *mut SMTP = (*data).req.p.smtp;
    let mut is_smtp_err: bool = 0 as i32 != 0;
    let mut is_smtp_blocking_err: bool = 0 as i32 != 0;
    is_smtp_err = if smtpcode / 100 as i32 != 2 as i32 {
        1 as i32
    } else {
        0 as i32
    } != 0;
    is_smtp_blocking_err = if is_smtp_err as i32 != 0
        && ((*data).set).mail_rcpt_allowfails() == 0
    {
        1 as i32
    } else {
        0 as i32
    } != 0;
    if is_smtp_err {
        (*smtp).rcpt_last_error = smtpcode;
        if is_smtp_blocking_err {
            Curl_failf(
                data,
                b"RCPT failed: %d\0" as *const u8 as *const i8,
                smtpcode,
            );
            result = CURLE_SEND_ERROR;
        }
    } else {
        (*smtp).rcpt_had_ok = 1 as i32 != 0;
    }
    if !is_smtp_blocking_err {
        let fresh7 = &mut ((*smtp).rcpt);
        *fresh7 = (*(*smtp).rcpt).next;
        if !((*smtp).rcpt).is_null() {
            result = smtp_perform_rcpt_to(data);
        } else if !(*smtp).rcpt_had_ok {
            Curl_failf(
                data,
                b"RCPT failed: %d (last error)\0" as *const u8 as *const i8,
                (*smtp).rcpt_last_error,
            );
            result = CURLE_SEND_ERROR;
        } else {
            result = Curl_pp_sendf(
                data,
                &mut (*conn).proto.smtpc.pp as *mut pingpong,
                b"%s\0" as *const u8 as *const i8,
                b"DATA\0" as *const u8 as *const i8,
            );
            if result as u64 == 0 {
                state(data, SMTP_DATA);
            }
        }
    }
    return result;
}
unsafe extern "C" fn smtp_state_data_resp(
    mut data: *mut Curl_easy,
    mut smtpcode: i32,
    mut instate: smtpstate,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    if smtpcode != 354 as i32 {
        Curl_failf(
            data,
            b"DATA failed: %d\0" as *const u8 as *const i8,
            smtpcode,
        );
        result = CURLE_SEND_ERROR;
    } else {
        Curl_pgrsSetUploadSize(data, (*data).state.infilesize);
        Curl_setup_transfer(
            data,
            -(1 as i32),
            -(1 as i32) as curl_off_t,
            0 as i32 != 0,
            0 as i32,
        );
        state(data, SMTP_STOP);
    }
    return result;
}
unsafe extern "C" fn smtp_state_postdata_resp(
    mut data: *mut Curl_easy,
    mut smtpcode: i32,
    mut instate: smtpstate,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    if smtpcode != 250 as i32 {
        result = CURLE_RECV_ERROR;
    }
    state(data, SMTP_STOP);
    return result;
}
unsafe extern "C" fn smtp_statemachine(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut sock: curl_socket_t = (*conn).sock[0 as i32 as usize];
    let mut smtpcode: i32 = 0;
    let mut smtpc: *mut smtp_conn = &mut (*conn).proto.smtpc;
    let mut pp: *mut pingpong = &mut (*smtpc).pp;
    let mut nread: size_t = 0 as i32 as size_t;
    if (*smtpc).state as u32 == SMTP_UPGRADETLS as i32 as u32 {
        return smtp_perform_upgrade_tls(data);
    }
    if (*pp).sendleft != 0 {
        return Curl_pp_flushsend(data, pp);
    }
    loop {
        result = Curl_pp_readresp(data, sock, pp, &mut smtpcode, &mut nread);
        if result as u64 != 0 {
            return result;
        }
        if (*smtpc).state as u32 != SMTP_QUIT as i32 as u32
            && smtpcode != 1 as i32
        {
            (*data).info.httpcode = smtpcode;
        }
        if smtpcode == 0 {
            break;
        }
        match (*smtpc).state as u32 {
            1 => {
                result = smtp_state_servergreet_resp(data, smtpcode, (*smtpc).state);
            }
            2 => {
                result = smtp_state_ehlo_resp(data, conn, smtpcode, (*smtpc).state);
            }
            3 => {
                result = smtp_state_helo_resp(data, smtpcode, (*smtpc).state);
            }
            4 => {
                result = smtp_state_starttls_resp(data, smtpcode, (*smtpc).state);
            }
            6 => {
                result = smtp_state_auth_resp(data, smtpcode, (*smtpc).state);
            }
            7 => {
                result = smtp_state_command_resp(data, smtpcode, (*smtpc).state);
            }
            8 => {
                result = smtp_state_mail_resp(data, smtpcode, (*smtpc).state);
            }
            9 => {
                result = smtp_state_rcpt_resp(data, conn, smtpcode, (*smtpc).state);
            }
            10 => {
                result = smtp_state_data_resp(data, smtpcode, (*smtpc).state);
            }
            11 => {
                result = smtp_state_postdata_resp(data, smtpcode, (*smtpc).state);
            }
            12 | _ => {
                state(data, SMTP_STOP);
            }
        }
        if !(result as u64 == 0
            && (*smtpc).state as u32 != SMTP_STOP as i32 as u32
            && Curl_pp_moredata(pp) as i32 != 0)
        {
            break;
        }
    }
    return result;
}
unsafe extern "C" fn smtp_multi_statemach(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut smtpc: *mut smtp_conn = &mut (*conn).proto.smtpc;
    if (*(*conn).handler).flags
        & ((1 as i32) << 0 as i32) as u32 != 0
        && !(*smtpc).ssldone
    {
        result = Curl_ssl_connect_nonblocking(
            data,
            conn,
            0 as i32 != 0,
            0 as i32,
            &mut (*smtpc).ssldone,
        );
        if result as u32 != 0 || !(*smtpc).ssldone {
            return result;
        }
    }
    result = Curl_pp_statemach(
        data,
        &mut (*smtpc).pp,
        0 as i32 != 0,
        0 as i32 != 0,
    );
    *done = if (*smtpc).state as u32 == SMTP_STOP as i32 as u32
    {
        1 as i32
    } else {
        0 as i32
    } != 0;
    return result;
}
unsafe extern "C" fn smtp_block_statemach(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut disconnecting: bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut smtpc: *mut smtp_conn = &mut (*conn).proto.smtpc;
    while (*smtpc).state as u32 != SMTP_STOP as i32 as u32
        && result as u64 == 0
    {
        result = Curl_pp_statemach(
            data,
            &mut (*smtpc).pp,
            1 as i32 != 0,
            disconnecting,
        );
    }
    return result;
}
unsafe extern "C" fn smtp_init(mut data: *mut Curl_easy) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut smtp: *mut SMTP = 0 as *mut SMTP;
    let fresh8 = &mut ((*data).req.p.smtp);
    *fresh8 = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<SMTP>() as u64, 1 as i32 as size_t)
        as *mut SMTP;
    smtp = *fresh8;
    if smtp.is_null() {
        result = CURLE_OUT_OF_MEMORY;
    }
    return result;
}
unsafe extern "C" fn smtp_getsock(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> i32 {
    return Curl_pp_getsock(data, &mut (*conn).proto.smtpc.pp, socks);
}
unsafe extern "C" fn smtp_connect(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut smtpc: *mut smtp_conn = &mut (*conn).proto.smtpc;
    let mut pp: *mut pingpong = &mut (*smtpc).pp;
    *done = 0 as i32 != 0;
    Curl_conncontrol(conn, 0 as i32);
    (*pp).response_time = (120 as i32 * 1000 as i32) as timediff_t;
    let fresh9 = &mut ((*pp).statemachine);
    *fresh9 = Some(
        smtp_statemachine
            as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
    );
    let fresh10 = &mut ((*pp).endofresp);
    *fresh10 = Some(
        smtp_endofresp
            as unsafe extern "C" fn(
                *mut Curl_easy,
                *mut connectdata,
                *mut i8,
                size_t,
                *mut i32,
            ) -> bool,
    );
    Curl_sasl_init(&mut (*smtpc).sasl, &saslsmtp);
    Curl_pp_setup(pp);
    Curl_pp_init(data, pp);
    result = smtp_parse_url_options(conn);
    if result as u64 != 0 {
        return result;
    }
    result = smtp_parse_url_path(data);
    if result as u64 != 0 {
        return result;
    }
    state(data, SMTP_SERVERGREET);
    result = smtp_multi_statemach(data, done);
    return result;
}
unsafe extern "C" fn smtp_done(
    mut data: *mut Curl_easy,
    mut status: CURLcode,
    mut premature: bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut smtp: *mut SMTP = (*data).req.p.smtp;
    let mut pp: *mut pingpong = &mut (*conn).proto.smtpc.pp;
    let mut eob: *mut i8 = 0 as *mut i8;
    let mut len: ssize_t = 0;
    let mut bytes_written: ssize_t = 0;
    if smtp.is_null() {
        return CURLE_OK;
    }
    Curl_cfree.expect("non-null function pointer")((*smtp).custom as *mut libc::c_void);
    let fresh11 = &mut ((*smtp).custom);
    *fresh11 = 0 as *mut i8;
    if status as u64 != 0 {
        Curl_conncontrol(conn, 1 as i32);
        result = status;
    } else if ((*data).set).connect_only() == 0 && !((*data).set.mail_rcpt).is_null()
            && (((*data).set).upload() as i32 != 0
                || (*data).set.mimepost.kind as u32 != 0)
        {
        if (*smtp).trailing_crlf as i32 != 0 || (*data).state.infilesize == 0 {
            eob = Curl_cstrdup
                .expect(
                    "non-null function pointer",
                )(
                &*(b"\r\n.\r\n\0" as *const u8 as *const i8)
                    .offset(2 as i32 as isize),
            );
            len = (5 as i32 - 2 as i32) as ssize_t;
        } else {
            eob = Curl_cstrdup
                .expect(
                    "non-null function pointer",
                )(b"\r\n.\r\n\0" as *const u8 as *const i8);
            len = 5 as i32 as ssize_t;
        }
        if eob.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        result = Curl_write(
            data,
            (*conn).writesockfd,
            eob as *const libc::c_void,
            len as size_t,
            &mut bytes_written,
        );
        if result as u64 != 0 {
            Curl_cfree.expect("non-null function pointer")(eob as *mut libc::c_void);
            return result;
        }
        if bytes_written != len {
            let fresh12 = &mut ((*pp).sendthis);
            *fresh12 = eob;
            (*pp).sendsize = len as size_t;
            (*pp).sendleft = (len - bytes_written) as size_t;
        } else {
            (*pp).response = Curl_now();
            Curl_cfree.expect("non-null function pointer")(eob as *mut libc::c_void);
        }
        state(data, SMTP_POSTDATA);
        result = smtp_block_statemach(data, conn, 0 as i32 != 0);
    }
    (*smtp).transfer = PPTRANSFER_BODY;
    return result;
}
unsafe extern "C" fn smtp_perform(
    mut data: *mut Curl_easy,
    mut connected: *mut bool,
    mut dophase_done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut smtp: *mut SMTP = (*data).req.p.smtp;
    if ((*data).set).opt_no_body() != 0 {
        (*smtp).transfer = PPTRANSFER_INFO;
    }
    *dophase_done = 0 as i32 != 0;
    let fresh13 = &mut ((*smtp).rcpt);
    *fresh13 = (*data).set.mail_rcpt;
    (*smtp).rcpt_had_ok = 0 as i32 != 0;
    (*smtp).rcpt_last_error = 0 as i32;
    (*smtp).trailing_crlf = 1 as i32 != 0;
    (*smtp).eob = 2 as i32 as size_t;
    if (((*data).set).upload() as i32 != 0
        || (*data).set.mimepost.kind as u32 != 0)
        && !((*data).set.mail_rcpt).is_null()
    {
        result = smtp_perform_mail(data);
    } else {
        result = smtp_perform_command(data);
    }
    if result as u64 != 0 {
        return result;
    }
    result = smtp_multi_statemach(data, dophase_done);
    *connected = (*conn).bits.tcpconnect[0 as i32 as usize];
    *dophase_done;
    return result;
}
unsafe extern "C" fn smtp_do(mut data: *mut Curl_easy, mut done: *mut bool) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    *done = 0 as i32 != 0;
    result = smtp_parse_custom_request(data);
    if result as u64 != 0 {
        return result;
    }
    result = smtp_regular_transfer(data, done);
    return result;
}
unsafe extern "C" fn smtp_disconnect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut dead_connection: bool,
) -> CURLcode {
    let mut smtpc: *mut smtp_conn = &mut (*conn).proto.smtpc;
    if !dead_connection && ((*conn).bits).protoconnstart() as i32 != 0 {
        if smtp_perform_quit(data, conn) as u64 == 0 {
            smtp_block_statemach(data, conn, 1 as i32 != 0);
        }
    }
    Curl_pp_disconnect(&mut (*smtpc).pp);
    Curl_sasl_cleanup(conn, (*smtpc).sasl.authused as u32);
    Curl_cfree.expect("non-null function pointer")((*smtpc).domain as *mut libc::c_void);
    let fresh14 = &mut ((*smtpc).domain);
    *fresh14 = 0 as *mut i8;
    return CURLE_OK;
}
unsafe extern "C" fn smtp_dophase_done(
    mut data: *mut Curl_easy,
    mut connected: bool,
) -> CURLcode {
    let mut smtp: *mut SMTP = (*data).req.p.smtp;
    if (*smtp).transfer as u32 != PPTRANSFER_BODY as i32 as u32
    {
        Curl_setup_transfer(
            data,
            -(1 as i32),
            -(1 as i32) as curl_off_t,
            0 as i32 != 0,
            -(1 as i32),
        );
    }
    return CURLE_OK;
}
unsafe extern "C" fn smtp_doing(
    mut data: *mut Curl_easy,
    mut dophase_done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = smtp_multi_statemach(data, dophase_done);
    if !(result as u64 != 0) {
        if *dophase_done {
            result = smtp_dophase_done(data, 0 as i32 != 0);
        }
    }
    return result;
}
unsafe extern "C" fn smtp_regular_transfer(
    mut data: *mut Curl_easy,
    mut dophase_done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut connected: bool = 0 as i32 != 0;
    (*data).req.size = -(1 as i32) as curl_off_t;
    Curl_pgrsSetUploadCounter(data, 0 as i32 as curl_off_t);
    Curl_pgrsSetDownloadCounter(data, 0 as i32 as curl_off_t);
    Curl_pgrsSetUploadSize(data, -(1 as i32) as curl_off_t);
    Curl_pgrsSetDownloadSize(data, -(1 as i32) as curl_off_t);
    result = smtp_perform(data, &mut connected, dophase_done);
    if result as u64 == 0 && *dophase_done as i32 != 0 {
        result = smtp_dophase_done(data, connected);
    }
    return result;
}
unsafe extern "C" fn smtp_setup_connection(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let fresh15 = &mut ((*conn).bits);
    (*fresh15).set_tls_upgraded(0 as i32 as bit);
    result = smtp_init(data);
    if result as u64 != 0 {
        return result;
    }
    return CURLE_OK;
}
unsafe extern "C" fn smtp_parse_url_options(mut conn: *mut connectdata) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut smtpc: *mut smtp_conn = &mut (*conn).proto.smtpc;
    let mut ptr: *const i8 = (*conn).options;
    (*smtpc).sasl.resetprefs = 1 as i32 != 0;
    while result as u64 == 0 && !ptr.is_null() && *ptr as i32 != 0 {
        let mut key: *const i8 = ptr;
        let mut value: *const i8 = 0 as *const i8;
        while *ptr as i32 != 0 && *ptr as i32 != '=' as i32 {
            ptr = ptr.offset(1);
        }
        value = ptr.offset(1 as i32 as isize);
        while *ptr as i32 != 0 && *ptr as i32 != ';' as i32 {
            ptr = ptr.offset(1);
        }
        if Curl_strncasecompare(
            key,
            b"AUTH=\0" as *const u8 as *const i8,
            5 as i32 as size_t,
        ) != 0
        {
            result = Curl_sasl_parse_url_auth_option(
                &mut (*smtpc).sasl,
                value,
                ptr.offset_from(value) as i64 as size_t,
            );
        } else {
            result = CURLE_URL_MALFORMAT;
        }
        if *ptr as i32 == ';' as i32 {
            ptr = ptr.offset(1);
        }
    }
    return result;
}
unsafe extern "C" fn smtp_parse_url_path(mut data: *mut Curl_easy) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut smtpc: *mut smtp_conn = &mut (*conn).proto.smtpc;
    let mut path: *const i8 = &mut *((*data).state.up.path)
        .offset(1 as i32 as isize) as *mut i8;
    let mut localhost: [i8; 1025] = [0; 1025];
    if *path == 0 {
        if Curl_gethostname(
            localhost.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 1025]>() as u64,
        ) == 0
        {
            path = localhost.as_mut_ptr();
        } else {
            path = b"localhost\0" as *const u8 as *const i8;
        }
    }
    return Curl_urldecode(
        data,
        path,
        0 as i32 as size_t,
        &mut (*smtpc).domain,
        0 as *mut size_t,
        REJECT_CTRL,
    );
}
unsafe extern "C" fn smtp_parse_custom_request(mut data: *mut Curl_easy) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut smtp: *mut SMTP = (*data).req.p.smtp;
    let mut custom: *const i8 = (*data)
        .set
        .str_0[STRING_CUSTOMREQUEST as i32 as usize];
    if !custom.is_null() {
        result = Curl_urldecode(
            data,
            custom,
            0 as i32 as size_t,
            &mut (*smtp).custom,
            0 as *mut size_t,
            REJECT_CTRL,
        );
    }
    return result;
}
unsafe extern "C" fn smtp_parse_address(
    mut data: *mut Curl_easy,
    mut fqma: *const i8,
    mut address: *mut *mut i8,
    mut host: *mut hostname,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut length: size_t = 0;
    let mut dup: *mut i8 = Curl_cstrdup
        .expect(
            "non-null function pointer",
        )(
        if *fqma.offset(0 as i32 as isize) as i32 == '<' as i32 {
            fqma.offset(1 as i32 as isize)
        } else {
            fqma
        },
    );
    if dup.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    length = strlen(dup);
    if length != 0 {
        if *dup.offset(length.wrapping_sub(1 as i32 as u64) as isize)
            as i32 == '>' as i32
        {
            *dup
                .offset(
                    length.wrapping_sub(1 as i32 as u64) as isize,
                ) = '\u{0}' as i32 as i8;
        }
    }
    let fresh16 = &mut ((*host).name);
    *fresh16 = strpbrk(dup, b"@\0" as *const u8 as *const i8);
    if !((*host).name).is_null() {
        *(*host).name = '\u{0}' as i32 as i8;
        let fresh17 = &mut ((*host).name);
        *fresh17 = ((*host).name).offset(1 as i32 as isize);
        Curl_idnconvert_hostname(data, host);
    }
    *address = dup;
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_smtp_escape_eob(
    mut data: *mut Curl_easy,
    nread: ssize_t,
) -> CURLcode {
    let mut i: ssize_t = 0;
    let mut si: ssize_t = 0;
    let mut smtp: *mut SMTP = (*data).req.p.smtp;
    let mut scratch: *mut i8 = (*data).state.scratch;
    let mut newscratch: *mut i8 = 0 as *mut i8;
    let mut oldscratch: *mut i8 = 0 as *mut i8;
    let mut eob_sent: size_t = 0;
    if scratch.is_null() || ((*data).set).crlf() as i32 != 0 {
        oldscratch = scratch;
        newscratch = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )(
            (2 as i32 as u32)
                .wrapping_mul((*data).set.upload_buffer_size) as size_t,
        ) as *mut i8;
        scratch = newscratch;
        if newscratch.is_null() {
            Curl_failf(
                data,
                b"Failed to alloc scratch buffer!\0" as *const u8 as *const i8,
            );
            return CURLE_OUT_OF_MEMORY;
        }
    }
    eob_sent = (*smtp).eob;
    i = 0 as i32 as ssize_t;
    si = 0 as i32 as ssize_t;
    while i < nread {
        if (*::std::mem::transmute::<
            &[u8; 6],
            &[i8; 6],
        >(b"\r\n.\r\n\0"))[(*smtp).eob as usize] as i32
            == *((*data).req.upload_fromhere).offset(i as isize) as i32
        {
            let fresh18 = &mut ((*smtp).eob);
            *fresh18 = (*fresh18).wrapping_add(1);
            if 2 as i32 as u64 == (*smtp).eob
                || 5 as i32 as u64 == (*smtp).eob
            {
                (*smtp).trailing_crlf = 1 as i32 != 0;
            } else {
                (*smtp).trailing_crlf = 0 as i32 != 0;
            }
        } else if (*smtp).eob != 0 {
            memcpy(
                &mut *scratch.offset(si as isize) as *mut i8
                    as *mut libc::c_void,
                &*(b"\r\n.\r\n\0" as *const u8 as *const i8)
                    .offset(eob_sent as isize) as *const i8
                    as *const libc::c_void,
                ((*smtp).eob).wrapping_sub(eob_sent),
            );
            si = (si as u64).wrapping_add(((*smtp).eob).wrapping_sub(eob_sent))
                as ssize_t as ssize_t;
            if (*::std::mem::transmute::<
                &[u8; 6],
                &[i8; 6],
            >(b"\r\n.\r\n\0"))[0 as i32 as usize] as i32
                == *((*data).req.upload_fromhere).offset(i as isize) as i32
            {
                (*smtp).eob = 1 as i32 as size_t;
            } else {
                (*smtp).eob = 0 as i32 as size_t;
            }
            eob_sent = 0 as i32 as size_t;
            (*smtp).trailing_crlf = 0 as i32 != 0;
        }
        if 3 as i32 as u64 == (*smtp).eob {
            memcpy(
                &mut *scratch.offset(si as isize) as *mut i8
                    as *mut libc::c_void,
                &*(b"\r\n..\0" as *const u8 as *const i8)
                    .offset(eob_sent as isize) as *const i8
                    as *const libc::c_void,
                (4 as i32 as u64).wrapping_sub(eob_sent),
            );
            si = (si as u64)
                .wrapping_add((4 as i32 as u64).wrapping_sub(eob_sent))
                as ssize_t as ssize_t;
            (*smtp).eob = 0 as i32 as size_t;
            eob_sent = 0 as i32 as size_t;
        } else if (*smtp).eob == 0 {
            let fresh19 = si;
            si = si + 1;
            *scratch
                .offset(
                    fresh19 as isize,
                ) = *((*data).req.upload_fromhere).offset(i as isize);
        }
        i += 1;
    }
    if ((*smtp).eob).wrapping_sub(eob_sent) != 0 {
        memcpy(
            &mut *scratch.offset(si as isize) as *mut i8 as *mut libc::c_void,
            &*(b"\r\n.\r\n\0" as *const u8 as *const i8)
                .offset(eob_sent as isize) as *const i8 as *const libc::c_void,
            ((*smtp).eob).wrapping_sub(eob_sent),
        );
        si = (si as u64).wrapping_add(((*smtp).eob).wrapping_sub(eob_sent))
            as ssize_t as ssize_t;
    }
    if si != nread {
        let fresh20 = &mut ((*data).req.upload_fromhere);
        *fresh20 = scratch;
        let fresh21 = &mut ((*data).state.scratch);
        *fresh21 = scratch;
        Curl_cfree.expect("non-null function pointer")(oldscratch as *mut libc::c_void);
        (*data).req.upload_present = si;
    } else {
        Curl_cfree.expect("non-null function pointer")(newscratch as *mut libc::c_void);
    }
    return CURLE_OK;
}
