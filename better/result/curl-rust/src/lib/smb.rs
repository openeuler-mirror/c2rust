
use :: libc;
extern "C" {
    fn getpid() -> i32;
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn memset(_: *mut core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
}
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::connect::Curl_conncontrol;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::curl_endian::Curl_read16_be;
pub use crate::src::lib::curl_endian::Curl_read16_le;
pub use crate::src::lib::curl_ntlm_core::Curl_ntlm_core_lm_resp;
pub use crate::src::lib::curl_ntlm_core::Curl_ntlm_core_mk_lm_hash;
pub use crate::src::lib::curl_ntlm_core::Curl_ntlm_core_mk_nt_hash;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::easy::Curl_ccalloc;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_cstrdup;
pub use crate::src::lib::escape::Curl_urldecode;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::progress::Curl_pgrsSetDownloadCounter;
pub use crate::src::lib::progress::Curl_pgrsSetDownloadSize;
pub use crate::src::lib::progress::Curl_pgrsSetUploadCounter;
pub use crate::src::lib::progress::Curl_pgrsSetUploadSize;
pub use crate::src::lib::sendf::Curl_client_write;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_read;
pub use crate::src::lib::sendf::Curl_write;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::transfer::Curl_fillreadbuffer;
pub use crate::src::lib::transfer::Curl_get_upload_buffer;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
pub use crate::src::lib::vtls::vtls::Curl_ssl_connect_nonblocking;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct smb_request {
    pub state: u32,
    pub path: *mut i8,
    pub tid: u16,
    pub fid: u16,
    pub result: u32,
}
impl smb_request {
    pub const fn new() -> Self {
        smb_request {
            state: 0,
            path: (0 as *mut i8),
            tid: 0,
            fid: 0,
            result: 0,
        }
    }
}
impl std::default::Default for smb_request {
    fn default() -> Self {
        smb_request::new()
    }
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
pub type C2RustUnnamed_4 = crate::src::lib::http2::C2RustUnnamed_4;
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
pub type C2RustUnnamed_5 = u32;
pub const TRNSPRT_QUIC: C2RustUnnamed_5 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_5 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_5 = 3;
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
impl smb_header {
    pub const fn new() -> Self {
        smb_header {
            nbt_type: 0,
            nbt_flags: 0,
            nbt_length: 0,
            magic: [0, 0, 0, 0],
            command: 0,
            status: 0,
            flags: 0,
            flags2: 0,
            pid_high: 0,
            signature: [0, 0, 0, 0, 0, 0, 0, 0],
            pad: 0,
            tid: 0,
            pid: 0,
            uid: 0,
            mid: 0,
        }
    }
}
impl std::default::Default for smb_header {
    fn default() -> Self {
        smb_header::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_negotiate_response {
    pub h: crate::src::lib::smb::smb_header,
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
impl smb_negotiate_response {
    pub const fn new() -> Self {
        smb_negotiate_response {
            h: crate::src::lib::smb::smb_header::new(),
            word_count: 0,
            dialect_index: 0,
            security_mode: 0,
            max_mpx_count: 0,
            max_number_vcs: 0,
            max_buffer_size: 0,
            max_raw_size: 0,
            session_key: 0,
            capabilities: 0,
            system_time_low: 0,
            system_time_high: 0,
            server_time_zone: 0,
            encryption_key_length: 0,
            byte_count: 0,
            bytes: [0],
        }
    }
}
impl std::default::Default for smb_negotiate_response {
    fn default() -> Self {
        smb_negotiate_response::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct andx {
    pub command: u8,
    pub pad: u8,
    pub offset: u16,
}
impl andx {
    pub const fn new() -> Self {
        andx {
            command: 0,
            pad: 0,
            offset: 0,
        }
    }
}
impl std::default::Default for andx {
    fn default() -> Self {
        andx::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_setup {
    pub word_count: u8,
    pub andx: crate::src::lib::smb::andx,
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
impl smb_setup {
    pub const fn new() -> Self {
        smb_setup {
            word_count: 0,
            andx: crate::src::lib::smb::andx::new(),
            max_buffer_size: 0,
            max_mpx_count: 0,
            vc_number: 0,
            session_key: 0,
            lengths: [0, 0],
            pad: 0,
            capabilities: 0,
            byte_count: 0,
            bytes: [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        }
    }
}
impl std::default::Default for smb_setup {
    fn default() -> Self {
        smb_setup::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_tree_connect {
    pub word_count: u8,
    pub andx: crate::src::lib::smb::andx,
    pub flags: u16,
    pub pw_len: u16,
    pub byte_count: u16,
    pub bytes: [i8; 1024],
}
impl smb_tree_connect {
    pub const fn new() -> Self {
        smb_tree_connect {
            word_count: 0,
            andx: crate::src::lib::smb::andx::new(),
            flags: 0,
            pw_len: 0,
            byte_count: 0,
            bytes: [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        }
    }
}
impl std::default::Default for smb_tree_connect {
    fn default() -> Self {
        smb_tree_connect::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_nt_create {
    pub word_count: u8,
    pub andx: crate::src::lib::smb::andx,
    pub pad: u8,
    pub name_length: u16,
    pub flags: u32,
    pub root_fid: u32,
    pub access: u32,
    pub allocation_size: i64,
    pub ext_file_attributes: u32,
    pub share_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub impersonation_level: u32,
    pub security_flags: u8,
    pub byte_count: u16,
    pub bytes: [i8; 1024],
}
impl smb_nt_create {
    pub const fn new() -> Self {
        smb_nt_create {
            word_count: 0,
            andx: crate::src::lib::smb::andx::new(),
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
            bytes: [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        }
    }
}
impl std::default::Default for smb_nt_create {
    fn default() -> Self {
        smb_nt_create::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_nt_create_response {
    pub h: crate::src::lib::smb::smb_header,
    pub word_count: u8,
    pub andx: crate::src::lib::smb::andx,
    pub op_lock_level: u8,
    pub fid: u16,
    pub create_disposition: u32,
    pub create_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub last_change_time: i64,
    pub ext_file_attributes: u32,
    pub allocation_size: i64,
    pub end_of_file: i64,
}
impl smb_nt_create_response {
    pub const fn new() -> Self {
        smb_nt_create_response {
            h: crate::src::lib::smb::smb_header::new(),
            word_count: 0,
            andx: crate::src::lib::smb::andx::new(),
            op_lock_level: 0,
            fid: 0,
            create_disposition: 0,
            create_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            last_change_time: 0,
            ext_file_attributes: 0,
            allocation_size: 0,
            end_of_file: 0,
        }
    }
}
impl std::default::Default for smb_nt_create_response {
    fn default() -> Self {
        smb_nt_create_response::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_read {
    pub word_count: u8,
    pub andx: crate::src::lib::smb::andx,
    pub fid: u16,
    pub offset: u32,
    pub max_bytes: u16,
    pub min_bytes: u16,
    pub timeout: u32,
    pub remaining: u16,
    pub offset_high: u32,
    pub byte_count: u16,
}
impl smb_read {
    pub const fn new() -> Self {
        smb_read {
            word_count: 0,
            andx: crate::src::lib::smb::andx::new(),
            fid: 0,
            offset: 0,
            max_bytes: 0,
            min_bytes: 0,
            timeout: 0,
            remaining: 0,
            offset_high: 0,
            byte_count: 0,
        }
    }
}
impl std::default::Default for smb_read {
    fn default() -> Self {
        smb_read::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_write {
    pub h: crate::src::lib::smb::smb_header,
    pub word_count: u8,
    pub andx: crate::src::lib::smb::andx,
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
impl smb_write {
    pub const fn new() -> Self {
        smb_write {
            h: crate::src::lib::smb::smb_header::new(),
            word_count: 0,
            andx: crate::src::lib::smb::andx::new(),
            fid: 0,
            offset: 0,
            timeout: 0,
            write_mode: 0,
            remaining: 0,
            pad: 0,
            data_length: 0,
            data_offset: 0,
            offset_high: 0,
            byte_count: 0,
            pad2: 0,
        }
    }
}
impl std::default::Default for smb_write {
    fn default() -> Self {
        smb_write::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_close {
    pub word_count: u8,
    pub fid: u16,
    pub last_mtime: u32,
    pub byte_count: u16,
}
impl smb_close {
    pub const fn new() -> Self {
        smb_close {
            word_count: 0,
            fid: 0,
            last_mtime: 0,
            byte_count: 0,
        }
    }
}
impl std::default::Default for smb_close {
    fn default() -> Self {
        smb_close::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct smb_tree_disconnect {
    pub word_count: u8,
    pub byte_count: u16,
}
impl smb_tree_disconnect {
    pub const fn new() -> Self {
        smb_tree_disconnect {
            word_count: 0,
            byte_count: 0,
        }
    }
}
impl std::default::Default for smb_tree_disconnect {
    fn default() -> Self {
        smb_tree_disconnect::new()
    }
}
pub type urlreject = u32;
pub const REJECT_ZERO: urlreject = 4;
pub const REJECT_CTRL: urlreject = 3;
pub const REJECT_NADA: urlreject = 2;
#[inline]
extern "C" fn __bswap_16(mut __bsx: u16) -> u16 {
    return (__bsx as i32 >> 8 as i32 & 0xff as i32 | (__bsx as i32 & 0xff as i32) << 8 as i32)
        as __uint16_t;
}
#[no_mangle]
pub static mut Curl_handler_smb: crate::src::lib::http2::Curl_handler =  {
    {
        let mut init = Curl_handler {
            scheme: b"SMB\0" as *const u8 as *const i8,
            setup_connection: Some(smb_setup_connection),
            do_it: Some(smb_do),
            done: Some(smb_done),
            do_more: None,
            connect_it: Some(smb_connect),
            connecting: Some(smb_connection_state),
            doing: Some(smb_request_state),
            proto_getsock: Some(smb_getsock),
            doing_getsock: Some(smb_getsock),
            domore_getsock: None,
            perform_getsock: None,
            disconnect: Some(smb_disconnect),
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
pub static mut Curl_handler_smbs: crate::src::lib::http2::Curl_handler =  {
    {
        let mut init = Curl_handler {
            scheme: b"SMBS\0" as *const u8 as *const i8,
            setup_connection: Some(smb_setup_connection),
            do_it: Some(smb_do),
            done: Some(smb_done),
            do_more: None,
            connect_it: Some(smb_connect),
            connecting: Some(smb_connection_state),
            doing: Some(smb_request_state),
            proto_getsock: Some(smb_getsock),
            doing_getsock: Some(smb_getsock),
            domore_getsock: None,
            perform_getsock: None,
            disconnect: Some(smb_disconnect),
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
extern "C" fn conn_state(mut data: *mut crate::src::lib::http2::Curl_easy, mut newstate: u32) {
    let mut smbc: Option<&'_ mut crate::src::lib::http2::smb_conn> =
        Some(unsafe { &mut (*(*data).conn).proto.smbc });
    (*(borrow_mut(&mut smbc)).unwrap()).state = newstate;
}
extern "C" fn request_state(mut data: *mut crate::src::lib::http2::Curl_easy, mut newstate: u32) {
    let mut req: *mut crate::src::lib::smb::smb_request = unsafe { (*data).req.p.smb };
    (unsafe { (*req).state = newstate });
}
extern "C" fn smb_setup_connection(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut req: *mut crate::src::lib::smb::smb_request = 0 as *mut smb_request;
    req = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
        1 as i32 as size_t,
        ::std::mem::size_of::<smb_request>() as u64,
    ) }) as *mut smb_request;
    let mut fresh0 = unsafe { &mut ((*data).req.p.smb) };
    *fresh0 = req;
    if req.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    return smb_parse_url_path(data, conn);
}
extern "C" fn smb_connect(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut _done: *mut bool,
) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut smbc: Option<&'_ mut crate::src::lib::http2::smb_conn> = Some(unsafe { &mut (*conn).proto.smbc });
    let mut slash: *mut i8 = 0 as *mut i8;
    if (unsafe { ((*conn).bits).user_passwd() }) == 0 {
        return CURLE_LOGIN_DENIED;
    }
    (*(borrow_mut(&mut smbc)).unwrap()).state = SMB_CONNECTING;
    let mut fresh1 = &mut ((*(borrow_mut(&mut smbc)).unwrap()).recv_buf);
    *fresh1 =
        (unsafe { Curl_cmalloc.expect("non-null function pointer")((0x8000 as i32 + 0x1000 as i32) as size_t) })
            as *mut i8;
    if ((*(borrow_mut(&mut smbc)).unwrap()).recv_buf).is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    Curl_conncontrol(conn, 0 as i32);
    slash = unsafe { strchr((*conn).user, '/' as i32) };
    if slash.is_null() {
        slash = unsafe { strchr((*conn).user, '\\' as i32) };
    }
    if !slash.is_null() {
        let mut fresh2 = &mut ((*(borrow_mut(&mut smbc)).unwrap()).user);
        *fresh2 = unsafe { slash.offset(1 as i32 as isize) };
        let mut fresh3 = &mut ((*(borrow_mut(&mut smbc)).unwrap()).domain);
        *fresh3 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*conn).user) };
        if ((*(borrow_mut(&mut smbc)).unwrap()).domain).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (unsafe { *((*(borrow(&smbc)).unwrap()).domain)
            .offset(slash.offset_from((*conn).user) as i64 as isize) = 0 as i32 as i8 });
    } else {
        let mut fresh4 = &mut ((*(borrow_mut(&mut smbc)).unwrap()).user);
        *fresh4 = unsafe { (*conn).user };
        let mut fresh5 = &mut ((*(borrow_mut(&mut smbc)).unwrap()).domain);
        *fresh5 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*conn).host.name) };
        if ((*(borrow_mut(&mut smbc)).unwrap()).domain).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
extern "C" fn smb_recv_message<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut msg: Option<&'a1 mut *mut core::ffi::c_void>,
) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut smbc: Option<&'_ mut crate::src::lib::http2::smb_conn> = Some(unsafe { &mut (*conn).proto.smbc });
    let mut buf: *mut i8 = (*(borrow_mut(&mut smbc)).unwrap()).recv_buf;
    let mut bytes_read: i64 = 0;
    let mut nbt_size: u64 = 0;
    let mut msg_size: u64 = 0;
    let mut len: u64 =
        ((0x8000 as i32 + 0x1000 as i32) as u64).wrapping_sub((*(borrow(&smbc)).unwrap()).got);
    let mut result: u32 = CURLE_OK;
    result = Curl_read(
        data,
        0 as i32,
        unsafe { buf.offset((*(borrow(&smbc)).unwrap()).got as isize) },
        len,
        Some(&mut bytes_read),
    );
    if result as u64 != 0 {
        return result;
    }
    if bytes_read == 0 {
        return CURLE_OK;
    }
    let mut fresh6 = &mut ((*(borrow_mut(&mut smbc)).unwrap()).got);
    *fresh6 = (*fresh6 as u64).wrapping_add(bytes_read as u64) as size_t as size_t;
    if (*(borrow(&smbc)).unwrap()).got < ::std::mem::size_of::<u32>() as u64 {
        return CURLE_OK;
    }
    nbt_size =
        (Curl_read16_be((unsafe { buf.offset(::std::mem::size_of::<u16>() as u64 as isize) }) as *const u8)
            as u64)
            .wrapping_add(::std::mem::size_of::<u32>() as u64);
    if (*(borrow(&smbc)).unwrap()).got < nbt_size {
        return CURLE_OK;
    }
    msg_size = ::std::mem::size_of::<smb_header>() as u64;
    if nbt_size >= msg_size.wrapping_add(1 as i32 as u64) {
        msg_size = (msg_size as u64).wrapping_add(
            (1 as i32 as u64).wrapping_add(
                ((unsafe { *buf.offset(msg_size as isize) }) as u8 as u64)
                    .wrapping_mul(::std::mem::size_of::<u16>() as u64),
            ),
        ) as size_t as size_t;
        if nbt_size >= msg_size.wrapping_add(::std::mem::size_of::<u16>() as u64) {
            msg_size = (msg_size as u64).wrapping_add(
                (::std::mem::size_of::<u16>() as u64).wrapping_add(Curl_read16_le(
                    (unsafe { &mut *buf.offset(msg_size as isize) }) as *mut i8 as *const u8,
                ) as u64),
            ) as size_t as size_t;
            if nbt_size < msg_size {
                return CURLE_READ_ERROR;
            }
        }
    }
    *(borrow_mut(&mut msg)).unwrap() = buf as *mut libc::c_void;
    return CURLE_OK;
}
extern "C" fn smb_pop_message(mut conn: *mut crate::src::lib::http2::connectdata) {
    let mut smbc: Option<&'_ mut crate::src::lib::http2::smb_conn> = Some(unsafe { &mut (*conn).proto.smbc });
    (*(borrow_mut(&mut smbc)).unwrap()).got = 0 as i32 as size_t;
}
extern "C" fn smb_format_message(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut h: *mut crate::src::lib::smb::smb_header,
    mut cmd: u8,
    mut len: u64,
) {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut smbc: Option<&'_ mut crate::src::lib::http2::smb_conn> = Some(unsafe { &mut (*conn).proto.smbc });
    let mut req: *mut crate::src::lib::smb::smb_request = unsafe { (*data).req.p.smb };
    let mut pid: u32 = 0;
    (unsafe { memset(
        h as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<smb_header>() as u64,
    ) });
    (unsafe { (*h).nbt_length = __bswap_16(
        (::std::mem::size_of::<smb_header>() as u64)
            .wrapping_sub(::std::mem::size_of::<u32>() as u64)
            .wrapping_add(len) as u16,
    ) });
    (unsafe { memcpy(
        ((*h).magic).as_mut_ptr() as *mut i8 as *mut libc::c_void,
        b"\xFFSMB\0" as *const u8 as *const i8 as *const libc::c_void,
        4 as i32 as u64,
    ) });
    (unsafe { (*h).command = cmd });
    (unsafe { (*h).flags = (0x10 as i32 | 0x8 as i32) as u8 });
    (unsafe { (*h).flags2 = (0x40 as i32 | 0x1 as i32) as u16 });
    (unsafe { (*h).uid = (*(borrow_mut(&mut smbc)).unwrap()).uid });
    (unsafe { (*h).tid = (*req).tid });
    pid = (unsafe { getpid() }) as u32;
    (unsafe { (*h).pid_high = (pid >> 16 as i32) as u16 });
    (unsafe { (*h).pid = pid as u16 });
}
extern "C" fn smb_send(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut len: i64,
    mut upload_size: u64,
) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut smbc: Option<&'_ mut crate::src::lib::http2::smb_conn> = Some(unsafe { &mut (*conn).proto.smbc });
    let mut bytes_written: i64 = 0;
    let mut result: u32 = CURLE_OK;
    result = Curl_write(
        data,
        0 as i32,
        (unsafe { (*data).state.ulbuf }) as *const libc::c_void,
        len as size_t,
        Some(&mut bytes_written),
    );
    if result as u64 != 0 {
        return result;
    }
    if bytes_written != len {
        (*(borrow_mut(&mut smbc)).unwrap()).send_size = len as size_t;
        (*(borrow_mut(&mut smbc)).unwrap()).sent = bytes_written as size_t;
    }
    (*(borrow_mut(&mut smbc)).unwrap()).upload_size = upload_size;
    return CURLE_OK;
}
extern "C" fn smb_flush(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut smbc: Option<&'_ mut crate::src::lib::http2::smb_conn> = Some(unsafe { &mut (*conn).proto.smbc });
    let mut bytes_written: i64 = 0;
    let mut len: i64 = ((*(borrow(&smbc)).unwrap()).send_size)
        .wrapping_sub((*(borrow(&smbc)).unwrap()).sent) as ssize_t;
    let mut result: u32 = CURLE_OK;
    if (*(borrow(&smbc)).unwrap()).send_size == 0 {
        return CURLE_OK;
    }
    result = Curl_write(
        data,
        0 as i32,
        (unsafe { ((*data).state.ulbuf).offset((*(borrow(&smbc)).unwrap()).sent as isize) })
            as *const libc::c_void,
        len as size_t,
        Some(&mut bytes_written),
    );
    if result as u64 != 0 {
        return result;
    }
    if bytes_written != len {
        let mut fresh7 = &mut ((*(borrow_mut(&mut smbc)).unwrap()).sent);
        *fresh7 = (*fresh7 as u64).wrapping_add(bytes_written as u64) as size_t as size_t;
    } else {
        (*(borrow_mut(&mut smbc)).unwrap()).send_size = 0 as i32 as size_t;
    }
    return CURLE_OK;
}
extern "C" fn smb_send_message(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut cmd: u8,
    mut msg: *const core::ffi::c_void,
    mut msg_len: u64,
) -> u32 {
    let mut result: u32 = Curl_get_upload_buffer(data);
    if result as u64 != 0 {
        return result;
    }
    smb_format_message(data, (unsafe { (*data).state.ulbuf }) as *mut smb_header, cmd, msg_len);
    (unsafe { memcpy(
        ((*data).state.ulbuf).offset(::std::mem::size_of::<smb_header>() as u64 as isize)
            as *mut libc::c_void,
        msg,
        msg_len,
    ) });
    return smb_send(
        data,
        (::std::mem::size_of::<smb_header>() as u64).wrapping_add(msg_len) as ssize_t,
        0 as i32 as size_t,
    );
}
extern "C" fn smb_send_negotiate(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut msg: *const i8 = b"\0\x0C\0\x02NT LM 0.12\0" as *const u8 as *const i8;
    return smb_send_message(
        data,
        0x72 as i32 as u8,
        msg as *const libc::c_void,
        15 as i32 as size_t,
    );
}
extern "C" fn smb_send_setup(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut smbc: Option<&'_ mut crate::src::lib::http2::smb_conn> = Some(unsafe { &mut (*conn).proto.smbc });
    let mut msg: crate::src::lib::smb::smb_setup = smb_setup {
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
    let mut byte_count: u64 = (::std::mem::size_of::<[u8; 24]>() as u64)
        .wrapping_add(::std::mem::size_of::<[u8; 24]>() as u64);
    byte_count = (byte_count as u64).wrapping_add(
        (unsafe { strlen((*(borrow(&smbc)).unwrap()).user) })
            .wrapping_add(unsafe { strlen((*(borrow(&smbc)).unwrap()).domain) }),
    ) as size_t as size_t;
    byte_count = (byte_count as u64).wrapping_add(
        (unsafe { strlen(b"x86_64-pc-linux-gnu\0" as *const u8 as *const i8) })
            .wrapping_add(unsafe { strlen(b"curl\0" as *const u8 as *const i8) })
            .wrapping_add(4 as i32 as u64),
    ) as size_t as size_t;
    if byte_count > ::std::mem::size_of::<[i8; 1024]>() as u64 {
        return CURLE_FILESIZE_EXCEEDED;
    }
    Curl_ntlm_core_mk_lm_hash(data, unsafe { (*conn).passwd }, lm_hash.as_mut_ptr());
    Curl_ntlm_core_lm_resp(
        lm_hash.as_mut_ptr(),
        ((*(borrow_mut(&mut smbc)).unwrap()).challenge).as_mut_ptr(),
        lm.as_mut_ptr(),
    );
    Curl_ntlm_core_mk_nt_hash(data, unsafe { (*conn).passwd }, nt_hash.as_mut_ptr());
    Curl_ntlm_core_lm_resp(
        nt_hash.as_mut_ptr(),
        ((*(borrow_mut(&mut smbc)).unwrap()).challenge).as_mut_ptr(),
        nt.as_mut_ptr(),
    );
    (unsafe { memset(
        &mut msg as *mut smb_setup as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<smb_setup>() as u64,
    ) });
    msg.word_count = 0xd as i32 as u8;
    msg.andx.command = 0xff as i32 as u8;
    msg.max_buffer_size = (0x8000 as i32 + 0x1000 as i32) as u16;
    msg.max_mpx_count = 1 as i32 as u16;
    msg.vc_number = 1 as i32 as u16;
    msg.session_key = (*(borrow_mut(&mut smbc)).unwrap()).session_key;
    msg.capabilities = 0x8 as i32 as u32;
    msg.lengths[0 as i32 as usize] = ::std::mem::size_of::<[u8; 24]>() as u64 as u16;
    msg.lengths[1 as i32 as usize] = ::std::mem::size_of::<[u8; 24]>() as u64 as u16;
    (unsafe { memcpy(
        p as *mut libc::c_void,
        lm.as_mut_ptr() as *const libc::c_void,
        ::std::mem::size_of::<[u8; 24]>() as u64,
    ) });
    p = unsafe { p.offset(::std::mem::size_of::<[u8; 24]>() as u64 as isize) };
    (unsafe { memcpy(
        p as *mut libc::c_void,
        nt.as_mut_ptr() as *const libc::c_void,
        ::std::mem::size_of::<[u8; 24]>() as u64,
    ) });
    p = unsafe { p.offset(::std::mem::size_of::<[u8; 24]>() as u64 as isize) };
    (unsafe { strcpy(p, (*(borrow(&smbc)).unwrap()).user) });
    p = unsafe { p.offset((strlen((*(borrow(&smbc)).unwrap()).user)).wrapping_add(1 as i32 as u64) as isize) };
    (unsafe { strcpy(p, (*(borrow(&smbc)).unwrap()).domain) });
    p = unsafe { p.offset(
        (strlen((*(borrow(&smbc)).unwrap()).domain)).wrapping_add(1 as i32 as u64) as isize,
    ) };
    (unsafe { strcpy(p, b"x86_64-pc-linux-gnu\0" as *const u8 as *const i8) });
    p = unsafe { p.offset(
        (strlen(b"x86_64-pc-linux-gnu\0" as *const u8 as *const i8)).wrapping_add(1 as i32 as u64)
            as isize,
    ) };
    (unsafe { strcpy(p, b"curl\0" as *const u8 as *const i8) });
    p = unsafe { p.offset(
        (strlen(b"curl\0" as *const u8 as *const i8)).wrapping_add(1 as i32 as u64) as isize,
    ) };
    byte_count = (unsafe { p.offset_from((msg.bytes).as_mut_ptr()) }) as i64 as size_t;
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
extern "C" fn smb_send_tree_connect(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut msg: crate::src::lib::smb::smb_tree_connect = smb_tree_connect {
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
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut smbc: Option<&'_ mut crate::src::lib::http2::smb_conn> = Some(unsafe { &mut (*conn).proto.smbc });
    let mut p: *mut i8 = (msg.bytes).as_mut_ptr();
    let mut byte_count: u64 =
        (unsafe { strlen((*conn).host.name) }).wrapping_add(unsafe { strlen((*(borrow(&smbc)).unwrap()).share) });
    byte_count = (byte_count as u64)
        .wrapping_add((unsafe { strlen(b"?????\0" as *const u8 as *const i8) }).wrapping_add(5 as i32 as u64))
        as size_t as size_t;
    if byte_count > ::std::mem::size_of::<[i8; 1024]>() as u64 {
        return CURLE_FILESIZE_EXCEEDED;
    }
    (unsafe { memset(
        &mut msg as *mut smb_tree_connect as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<smb_tree_connect>() as u64,
    ) });
    msg.word_count = 0x4 as i32 as u8;
    msg.andx.command = 0xff as i32 as u8;
    msg.pw_len = 0 as i32 as u16;
    (unsafe { strcpy(p, b"\\\\\0" as *const u8 as *const i8) });
    p = unsafe { p.offset(strlen(b"\\\\\0" as *const u8 as *const i8) as isize) };
    (unsafe { strcpy(p, (*conn).host.name) });
    p = unsafe { p.offset(strlen((*conn).host.name) as isize) };
    (unsafe { strcpy(p, b"\\\0" as *const u8 as *const i8) });
    p = unsafe { p.offset(strlen(b"\\\0" as *const u8 as *const i8) as isize) };
    (unsafe { strcpy(p, (*(borrow(&smbc)).unwrap()).share) });
    p = unsafe { p
        .offset((strlen((*(borrow(&smbc)).unwrap()).share)).wrapping_add(1 as i32 as u64) as isize) };
    (unsafe { strcpy(p, b"?????\0" as *const u8 as *const i8) });
    p = unsafe { p.offset(
        (strlen(b"?????\0" as *const u8 as *const i8)).wrapping_add(1 as i32 as u64) as isize,
    ) };
    byte_count = (unsafe { p.offset_from((msg.bytes).as_mut_ptr()) }) as i64 as size_t;
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
extern "C" fn smb_send_open(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut req: *mut crate::src::lib::smb::smb_request = unsafe { (*data).req.p.smb };
    let mut msg: crate::src::lib::smb::smb_nt_create = smb_nt_create {
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
    let mut byte_count: u64 = 0;
    if (unsafe { strlen((*req).path) }).wrapping_add(1 as i32 as u64)
        > ::std::mem::size_of::<[i8; 1024]>() as u64
    {
        return CURLE_FILESIZE_EXCEEDED;
    }
    (unsafe { memset(
        &mut msg as *mut smb_nt_create as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<smb_nt_create>() as u64,
    ) });
    msg.word_count = 0x18 as i32 as u8;
    msg.andx.command = 0xff as i32 as u8;
    byte_count = unsafe { strlen((*req).path) };
    msg.name_length = byte_count as u16;
    msg.share_access = 0x7 as i32 as u32;
    if (unsafe { ((*data).set).upload() }) != 0 {
        msg.access = 0x80000000 as u32 | 0x40000000 as i32 as u32;
        msg.create_disposition = 0x5 as i32 as u32;
    } else {
        msg.access = 0x80000000 as u32;
        msg.create_disposition = 0x1 as i32 as u32;
    }
    byte_count = byte_count.wrapping_add(1);
    msg.byte_count = byte_count as u16;
    (unsafe { strcpy((msg.bytes).as_mut_ptr(), (*req).path) });
    return smb_send_message(
        data,
        0xa2 as i32 as u8,
        &mut msg as *mut smb_nt_create as *const libc::c_void,
        (::std::mem::size_of::<smb_nt_create>() as u64)
            .wrapping_sub(::std::mem::size_of::<[i8; 1024]>() as u64)
            .wrapping_add(byte_count),
    );
}
extern "C" fn smb_send_close(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut req: *mut crate::src::lib::smb::smb_request = unsafe { (*data).req.p.smb };
    let mut msg: crate::src::lib::smb::smb_close = smb_close {
        word_count: 0,
        fid: 0,
        last_mtime: 0,
        byte_count: 0,
    };
    (unsafe { memset(
        &mut msg as *mut smb_close as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<smb_close>() as u64,
    ) });
    msg.word_count = 0x3 as i32 as u8;
    msg.fid = unsafe { (*req).fid };
    return smb_send_message(
        data,
        0x4 as i32 as u8,
        &mut msg as *mut smb_close as *const libc::c_void,
        ::std::mem::size_of::<smb_close>() as u64,
    );
}
extern "C" fn smb_send_tree_disconnect(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut msg: crate::src::lib::smb::smb_tree_disconnect = smb_tree_disconnect {
        word_count: 0,
        byte_count: 0,
    };
    (unsafe { memset(
        &mut msg as *mut smb_tree_disconnect as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<smb_tree_disconnect>() as u64,
    ) });
    return smb_send_message(
        data,
        0x71 as i32 as u8,
        &mut msg as *mut smb_tree_disconnect as *const libc::c_void,
        ::std::mem::size_of::<smb_tree_disconnect>() as u64,
    );
}
extern "C" fn smb_send_read(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut req: *mut crate::src::lib::smb::smb_request = unsafe { (*data).req.p.smb };
    let mut offset: i64 = unsafe { (*data).req.offset };
    let mut msg: crate::src::lib::smb::smb_read = smb_read {
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
    (unsafe { memset(
        &mut msg as *mut smb_read as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<smb_read>() as u64,
    ) });
    msg.word_count = 0xc as i32 as u8;
    msg.andx.command = 0xff as i32 as u8;
    msg.fid = unsafe { (*req).fid };
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
extern "C" fn smb_send_write(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut msg: *mut crate::src::lib::smb::smb_write = 0 as *mut smb_write;
    let mut req: *mut crate::src::lib::smb::smb_request = unsafe { (*data).req.p.smb };
    let mut offset: i64 = unsafe { (*data).req.offset };
    let mut upload_size: i64 = (unsafe { (*data).req.size }) - (unsafe { (*data).req.bytecount });
    let mut result: u32 = Curl_get_upload_buffer(data);
    if result as u64 != 0 {
        return result;
    }
    msg = (unsafe { (*data).state.ulbuf }) as *mut smb_write;
    if upload_size >= (0x8000 as i32 - 1 as i32) as i64 {
        upload_size = (0x8000 as i32 - 1 as i32) as curl_off_t;
    }
    (unsafe { memset(
        msg as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<smb_write>() as u64,
    ) });
    (unsafe { (*msg).word_count = 0xe as i32 as u8 });
    (unsafe { (*msg).andx.command = 0xff as i32 as u8 });
    (unsafe { (*msg).fid = (*req).fid });
    (unsafe { (*msg).offset = offset as u32 });
    (unsafe { (*msg).offset_high = (offset >> 32 as i32) as u32 });
    (unsafe { (*msg).data_length = upload_size as u16 });
    (unsafe { (*msg).data_offset = (::std::mem::size_of::<smb_write>() as u64)
        .wrapping_sub(::std::mem::size_of::<u32>() as u64) as u16 });
    (unsafe { (*msg).byte_count = (upload_size + 1 as i32 as i64) as u16 });
    smb_format_message(
        data,
        unsafe { &mut (*msg).h },
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
extern "C" fn smb_send_and_recv<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut msg: Option<&'a1 mut *mut core::ffi::c_void>,
) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut smbc: Option<&'_ mut crate::src::lib::http2::smb_conn> = Some(unsafe { &mut (*conn).proto.smbc });
    let mut result: u32 = CURLE_OK;
    *(borrow_mut(&mut msg)).unwrap() = 0 as *mut libc::c_void;
    if (*(borrow(&smbc)).unwrap()).send_size == 0 && (*(borrow(&smbc)).unwrap()).upload_size != 0 {
        let mut nread: u64 =
            if (*(borrow(&smbc)).unwrap()).upload_size > (unsafe { (*data).set.upload_buffer_size }) as size_t {
                (unsafe { (*data).set.upload_buffer_size }) as size_t
            } else {
                (*(borrow_mut(&mut smbc)).unwrap()).upload_size
            };
        let mut fresh8 = unsafe { &mut ((*data).req.upload_fromhere) };
        *fresh8 = unsafe { (*data).state.ulbuf };
        result = Curl_fillreadbuffer(data, nread, Some(&mut nread));
        if result as u32 != 0 && result as u32 != CURLE_AGAIN as i32 as u32 {
            return result;
        }
        if nread == 0 {
            return CURLE_OK;
        }
        let mut fresh9 = &mut ((*(borrow_mut(&mut smbc)).unwrap()).upload_size);
        *fresh9 = (*fresh9 as u64).wrapping_sub(nread) as size_t as size_t;
        (*(borrow_mut(&mut smbc)).unwrap()).send_size = nread;
        (*(borrow_mut(&mut smbc)).unwrap()).sent = 0 as i32 as size_t;
    }
    if (*(borrow(&smbc)).unwrap()).send_size != 0 {
        result = smb_flush(data);
        if result as u64 != 0 {
            return result;
        }
    }
    if (*(borrow(&smbc)).unwrap()).send_size != 0 || (*(borrow(&smbc)).unwrap()).upload_size != 0 {
        return CURLE_AGAIN;
    }
    return smb_recv_message(data, borrow_mut(&mut msg));
}
extern "C" fn smb_connection_state(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut done: *mut bool,
) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut smbc: Option<&'_ mut crate::src::lib::http2::smb_conn> = Some(unsafe { &mut (*conn).proto.smbc });
    let mut nrsp: *mut crate::src::lib::smb::smb_negotiate_response =
        0 as *mut crate::src::lib::smb::smb_negotiate_response;
    let mut h: *mut crate::src::lib::smb::smb_header = 0 as *mut crate::src::lib::smb::smb_header;
    let mut result: u32 = CURLE_OK;
    let mut msg: *mut core::ffi::c_void = 0 as *mut libc::c_void;
    if (*(borrow(&smbc)).unwrap()).state as u32 == SMB_CONNECTING as i32 as u32 {
        if (unsafe { (*(*conn).handler).flags }) & ((1 as i32) << 0 as i32) as u32 != 0 {
            let mut ssl_done: bool = 0 as i32 != 0;
            result =
                Curl_ssl_connect_nonblocking(data, conn, 0 as i32 != 0, 0 as i32, &mut ssl_done);
            if result as u32 != 0 && result as u32 != CURLE_AGAIN as i32 as u32 {
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
    result = smb_send_and_recv(data, Some(&mut msg));
    if result as u32 != 0 && result as u32 != CURLE_AGAIN as i32 as u32 {
        Curl_conncontrol(conn, 1 as i32);
        return result;
    }
    if msg.is_null() {
        return CURLE_OK;
    }
    h = msg as *mut smb_header;
    match (*(borrow(&smbc)).unwrap()).state as u32 {
        2 => {
            if (*(borrow(&smbc)).unwrap()).got
                < (::std::mem::size_of::<smb_negotiate_response>() as u64)
                    .wrapping_add(::std::mem::size_of::<[u8; 8]>() as u64)
                    .wrapping_sub(1 as i32 as u64)
                || (unsafe { (*h).status }) != 0
            {
                Curl_conncontrol(conn, 1 as i32);
                return CURLE_COULDNT_CONNECT;
            }
            nrsp = msg as *mut smb_negotiate_response;
            (unsafe { memcpy(
                ((*(borrow_mut(&mut smbc)).unwrap()).challenge).as_mut_ptr() as *mut libc::c_void,
                ((*nrsp).bytes).as_mut_ptr() as *const libc::c_void,
                ::std::mem::size_of::<[u8; 8]>() as u64,
            ) });
            (*(borrow_mut(&mut smbc)).unwrap()).session_key = unsafe { (*nrsp).session_key };
            result = smb_send_setup(data);
            if result as u64 != 0 {
                Curl_conncontrol(conn, 1 as i32);
                return result;
            }
            conn_state(data, SMB_SETUP);
        }
        3 => {
            if (unsafe { (*h).status }) != 0 {
                Curl_conncontrol(conn, 1 as i32);
                return CURLE_LOGIN_DENIED;
            }
            (*(borrow_mut(&mut smbc)).unwrap()).uid = unsafe { (*h).uid };
            conn_state(data, SMB_CONNECTED);
            (unsafe { *done = 1 as i32 != 0 });
        }
        _ => {
            smb_pop_message(conn);
            return CURLE_OK;
        }
    }
    smb_pop_message(conn);
    return CURLE_OK;
}
extern "C" fn get_posix_time<'a1>(mut out: Option<&'a1 mut i64>, mut timestamp: i64) {
    timestamp -= 116444736000000000 as i64;
    timestamp /= 10000000 as i32 as i64;
    *(borrow_mut(&mut out)).unwrap() = timestamp;
}
extern "C" fn smb_request_state(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut done: *mut bool,
) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut req: *mut crate::src::lib::smb::smb_request = unsafe { (*data).req.p.smb };
    let mut h: *mut crate::src::lib::smb::smb_header = 0 as *mut crate::src::lib::smb::smb_header;
    let mut smbc: Option<&'_ mut crate::src::lib::http2::smb_conn> = Some(unsafe { &mut (*conn).proto.smbc });
    let mut next_state: u32 = SMB_DONE;
    let mut len: u16 = 0;
    let mut off: u16 = 0;
    let mut result: u32 = CURLE_OK;
    let mut msg: *mut core::ffi::c_void = 0 as *mut libc::c_void;
    let mut smb_m: *const crate::src::lib::smb::smb_nt_create_response =
        0 as *const crate::src::lib::smb::smb_nt_create_response;
    if (unsafe { (*req).state }) as u32 == SMB_REQUESTING as i32 as u32 {
        result = smb_send_tree_connect(data);
        if result as u64 != 0 {
            Curl_conncontrol(conn, 1 as i32);
            return result;
        }
        request_state(data, SMB_TREE_CONNECT);
    }
    result = smb_send_and_recv(data, Some(&mut msg));
    if result as u32 != 0 && result as u32 != CURLE_AGAIN as i32 as u32 {
        Curl_conncontrol(conn, 1 as i32);
        return result;
    }
    if msg.is_null() {
        return CURLE_OK;
    }
    h = msg as *mut smb_header;
    let mut current_block_72: u64;
    match (unsafe { (*req).state }) as u32 {
        1 => {
            if (unsafe { (*h).status }) != 0 {
                (unsafe { (*req).result = CURLE_REMOTE_FILE_NOT_FOUND });
                if (unsafe { (*h).status }) == 0x50001 as i32 as u32 {
                    (unsafe { (*req).result = CURLE_REMOTE_ACCESS_DENIED });
                }
            } else {
                (unsafe { (*req).tid = (*h).tid });
                next_state = SMB_OPEN;
            }
        }
        2 => {
            if (unsafe { (*h).status }) != 0
                || (*(borrow(&smbc)).unwrap()).got
                    < ::std::mem::size_of::<smb_nt_create_response>() as u64
            {
                (unsafe { (*req).result = CURLE_REMOTE_FILE_NOT_FOUND });
                if (unsafe { (*h).status }) == 0x50001 as i32 as u32 {
                    (unsafe { (*req).result = CURLE_REMOTE_ACCESS_DENIED });
                }
                next_state = SMB_TREE_DISCONNECT;
            } else {
                smb_m = msg as *const smb_nt_create_response;
                (unsafe { (*req).fid = (*smb_m).fid });
                (unsafe { (*data).req.offset = 0 as i32 as curl_off_t });
                if (unsafe { ((*data).set).upload() }) != 0 {
                    (unsafe { (*data).req.size = (*data).state.infilesize });
                    Curl_pgrsSetUploadSize(data, unsafe { (*data).req.size });
                    next_state = SMB_UPLOAD;
                } else {
                    smb_m = msg as *const smb_nt_create_response;
                    (unsafe { (*data).req.size = (*smb_m).end_of_file });
                    if (unsafe { (*data).req.size }) < 0 as i32 as i64 {
                        (unsafe { (*req).result = CURLE_WEIRD_SERVER_REPLY });
                        next_state = SMB_CLOSE;
                    } else {
                        Curl_pgrsSetDownloadSize(data, unsafe { (*data).req.size });
                        if (unsafe { ((*data).set).get_filetime() }) != 0 {
                            get_posix_time(
                                Some(unsafe { &mut (*data).info.filetime }),
                                unsafe { (*smb_m).last_change_time },
                            );
                        }
                        next_state = SMB_DOWNLOAD;
                    }
                }
            }
        }
        3 => {
            if (unsafe { (*h).status }) != 0
                || (*(borrow(&smbc)).unwrap()).got
                    < (::std::mem::size_of::<smb_header>() as u64).wrapping_add(14 as i32 as u64)
            {
                (unsafe { (*req).result = CURLE_RECV_ERROR });
                next_state = SMB_CLOSE;
            } else {
                len = Curl_read16_le(
                    unsafe { (msg as *const u8)
                        .offset(::std::mem::size_of::<smb_header>() as u64 as isize)
                        .offset(11 as i32 as isize) },
                );
                off = Curl_read16_le(
                    unsafe { (msg as *const u8)
                        .offset(::std::mem::size_of::<smb_header>() as u64 as isize)
                        .offset(13 as i32 as isize) },
                );
                if len as i32 > 0 as i32 {
                    if (off as u64)
                        .wrapping_add(::std::mem::size_of::<u32>() as u64)
                        .wrapping_add(len as u64)
                        > (*(borrow(&smbc)).unwrap()).got
                    {
                        (unsafe { Curl_failf(data, b"Invalid input packet\0" as *const u8 as *const i8) });
                        result = CURLE_RECV_ERROR;
                    } else {
                        result = Curl_client_write(
                            data,
                            (1 as i32) << 0 as i32,
                            unsafe { (msg as *mut i8)
                                .offset(off as i32 as isize)
                                .offset(::std::mem::size_of::<u32>() as u64 as isize) },
                            len as size_t,
                        );
                    }
                    if result as u64 != 0 {
                        (unsafe { (*req).result = result });
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
                        let mut fresh10 = unsafe { &mut ((*data).req.bytecount) };
                        *fresh10 += len as i64;
                        let mut fresh11 = unsafe { &mut ((*data).req.offset) };
                        *fresh11 += len as i64;
                        Curl_pgrsSetDownloadCounter(data, unsafe { (*data).req.bytecount });
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
            if (unsafe { (*h).status }) != 0
                || (*(borrow(&smbc)).unwrap()).got
                    < (::std::mem::size_of::<smb_header>() as u64).wrapping_add(6 as i32 as u64)
            {
                (unsafe { (*req).result = CURLE_UPLOAD_FAILED });
                next_state = SMB_CLOSE;
            } else {
                len = Curl_read16_le(
                    unsafe { (msg as *const u8)
                        .offset(::std::mem::size_of::<smb_header>() as u64 as isize)
                        .offset(5 as i32 as isize) },
                );
                let mut fresh12 = unsafe { &mut ((*data).req.bytecount) };
                *fresh12 += len as i64;
                let mut fresh13 = unsafe { &mut ((*data).req.offset) };
                *fresh13 += len as i64;
                Curl_pgrsSetUploadCounter(data, unsafe { (*data).req.bytecount });
                if (unsafe { (*data).req.bytecount }) >= (unsafe { (*data).req.size }) {
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
            result = unsafe { (*req).result };
            (unsafe { *done = 1 as i32 != 0 });
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
extern "C" fn smb_done(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut status: u32,
    mut _premature: bool,
) -> u32 {
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).req.p.smb as *mut libc::c_void) });
    let mut fresh14 = unsafe { &mut ((*data).req.p.smb) };
    *fresh14 = 0 as *mut smb_request;
    return status;
}
extern "C" fn smb_disconnect(
    mut _data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut _dead: bool,
) -> u32 {
    let mut smbc: Option<&'_ mut crate::src::lib::http2::smb_conn> = Some(unsafe { &mut (*conn).proto.smbc });
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut smbc)).unwrap()).share as *mut libc::c_void,
    ) });
    let mut fresh15 = &mut ((*(borrow_mut(&mut smbc)).unwrap()).share);
    *fresh15 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut smbc)).unwrap()).domain as *mut libc::c_void,
    ) });
    let mut fresh16 = &mut ((*(borrow_mut(&mut smbc)).unwrap()).domain);
    *fresh16 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut smbc)).unwrap()).recv_buf as *mut libc::c_void,
    ) });
    let mut fresh17 = &mut ((*(borrow_mut(&mut smbc)).unwrap()).recv_buf);
    *fresh17 = 0 as *mut i8;
    return CURLE_OK;
}
extern "C" fn smb_getsock(
    mut _data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut socks: *mut i32,
) -> i32 {
    (unsafe { *socks.offset(0 as i32 as isize) = (*conn).sock[0 as i32 as usize] });
    return (1 as i32) << 0 as i32 | (1 as i32) << 16 as i32 + 0 as i32;
}
extern "C" fn smb_do(mut data: *mut crate::src::lib::http2::Curl_easy, mut done: *mut bool) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut smbc: Option<&'_ mut crate::src::lib::http2::smb_conn> = Some(unsafe { &mut (*conn).proto.smbc });
    (unsafe { *done = 0 as i32 != 0 });
    if !((*(borrow_mut(&mut smbc)).unwrap()).share).is_null() {
        return CURLE_OK;
    }
    return CURLE_URL_MALFORMAT;
}
extern "C" fn smb_parse_url_path(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut req: *mut crate::src::lib::smb::smb_request = unsafe { (*data).req.p.smb };
    let mut smbc: Option<&'_ mut crate::src::lib::http2::smb_conn> = Some(unsafe { &mut (*conn).proto.smbc });
    let mut path: *mut i8 = 0 as *mut i8;
    let mut slash: *mut i8 = 0 as *mut i8;
    let mut result: u32 = Curl_urldecode(
        data,
        unsafe { (*data).state.up.path },
        0 as i32 as size_t,
        Some(&mut path),
        Option::<&'_ mut u64>::None,
        REJECT_CTRL,
    );
    if result as u64 != 0 {
        return result;
    }
    let mut fresh18 = &mut ((*(borrow_mut(&mut smbc)).unwrap()).share);
    *fresh18 = unsafe { Curl_cstrdup.expect("non-null function pointer")(
        if *path as i32 == '/' as i32 || *path as i32 == '\\' as i32 {
            path.offset(1 as i32 as isize)
        } else {
            path
        },
    ) };
    (unsafe { Curl_cfree.expect("non-null function pointer")(path as *mut libc::c_void) });
    if ((*(borrow_mut(&mut smbc)).unwrap()).share).is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    slash = unsafe { strchr((*(borrow(&smbc)).unwrap()).share, '/' as i32) };
    if slash.is_null() {
        slash = unsafe { strchr((*(borrow(&smbc)).unwrap()).share, '\\' as i32) };
    }
    if slash.is_null() {
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            (*(borrow_mut(&mut smbc)).unwrap()).share as *mut libc::c_void,
        ) });
        let mut fresh19 = &mut ((*(borrow_mut(&mut smbc)).unwrap()).share);
        *fresh19 = 0 as *mut i8;
        return CURLE_URL_MALFORMAT;
    }
    let mut fresh20 = slash;
    slash = unsafe { slash.offset(1) };
    (unsafe { *fresh20 = 0 as i32 as i8 });
    let mut fresh21 = unsafe { &mut ((*req).path) };
    *fresh21 = slash;
    while (unsafe { *slash }) != 0 {
        if (unsafe { *slash }) as i32 == '/' as i32 {
            (unsafe { *slash = '\\' as i32 as i8 });
        }
        slash = unsafe { slash.offset(1) };
    }
    return CURLE_OK;
}
use crate::laertes_rt::*;
