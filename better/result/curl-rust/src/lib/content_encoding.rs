
use :: libc;
extern "C" {
    pub type internal_state;
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strlen(_: *const i8) -> u64;
    fn zlibVersion() -> *const i8;
    fn inflate(strm: *mut crate::src::lib::content_encoding::z_stream_s, flush: i32) -> i32;
    fn inflateEnd(strm: *mut crate::src::lib::content_encoding::z_stream_s) -> i32;
    fn inflateInit_(
        strm: *mut crate::src::lib::content_encoding::z_stream_s,
        version: *const i8,
        stream_size: i32,
    ) -> i32;
    fn inflateInit2_(
        strm: *mut crate::src::lib::content_encoding::z_stream_s,
        windowBits: i32,
        version: *const i8,
        stream_size: i32,
    ) -> i32;
}
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::curl_ctype::Curl_isspace;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::easy::Curl_ccalloc;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_cstrdup;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::http_chunks::Curl_httpchunk_init;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::sendf::Curl_client_write;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::strcase::Curl_strncasecompare;
pub use crate::src::lib::strdup::Curl_saferealloc;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct contenc_writer {
    pub handler: *const crate::src::lib::content_encoding::content_encoding,
    pub downstream: *mut crate::src::lib::content_encoding::contenc_writer,
    pub params: *mut core::ffi::c_void,
}
impl contenc_writer {
    pub const fn new() -> Self {
        contenc_writer {
            handler: (0 as *const crate::src::lib::content_encoding::content_encoding),
            downstream: (0 as *mut crate::src::lib::content_encoding::contenc_writer),
            params: (0 as *mut core::ffi::c_void),
        }
    }
}
impl std::default::Default for contenc_writer {
    fn default() -> Self {
        contenc_writer::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct content_encoding {
    pub name: *const i8,
    pub alias: *const i8,
    pub init_writer: Option<
        unsafe extern "C" fn(
            _: *mut crate::src::lib::http2::Curl_easy,
            _: *mut crate::src::lib::content_encoding::contenc_writer,
        ) -> u32,
    >,
    pub unencode_write: Option<
        unsafe extern "C" fn(
            _: *mut crate::src::lib::http2::Curl_easy,
            _: *mut crate::src::lib::content_encoding::contenc_writer,
            _: *const i8,
            _: u64,
        ) -> u32,
    >,
    pub close_writer: Option<
        unsafe extern "C" fn(
            _: *mut crate::src::lib::http2::Curl_easy,
            _: *mut crate::src::lib::content_encoding::contenc_writer,
        ) -> (),
    >,
    pub paramsize: u64,
}
impl content_encoding {
    pub const fn new() -> Self {
        content_encoding {
            name: (0 as *const i8),
            alias: (0 as *const i8),
            init_writer: None,
            unencode_write: None,
            close_writer: None,
            paramsize: 0,
        }
    }
}
impl std::default::Default for content_encoding {
    fn default() -> Self {
        content_encoding::new()
    }
}
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
pub type Byte = u8;
pub type uInt = u32;
pub type uLong = u64;
pub type Bytef = u8;
pub type voidpf = *mut core::ffi::c_void;
pub type alloc_func<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: u32,
        _: u32,
    ) -> Option<&'a2 mut core::ffi::c_void>,
>;
pub type free_func<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: Option<&'a2 mut core::ffi::c_void>,
    ) -> (),
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct z_stream_s {
    pub next_in: *mut u8,
    pub avail_in: u32,
    pub total_in: u64,
    pub next_out: *mut u8,
    pub avail_out: u32,
    pub total_out: u64,
    pub msg: *mut i8,
    pub state: *mut crate::src::lib::content_encoding::internal_state,
    pub zalloc: Option<
        unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u32, _: u32) -> *mut core::ffi::c_void,
    >,
    pub zfree:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut core::ffi::c_void) -> ()>,
    pub opaque: *mut core::ffi::c_void,
    pub data_type: i32,
    pub adler: u64,
    pub reserved: u64,
}
impl z_stream_s {
    pub const fn new() -> Self {
        z_stream_s {
            next_in: (0 as *mut u8),
            avail_in: 0,
            total_in: 0,
            next_out: (0 as *mut u8),
            avail_out: 0,
            total_out: 0,
            msg: (0 as *mut i8),
            state: (0 as *mut crate::src::lib::content_encoding::internal_state),
            zalloc: None,
            zfree: None,
            opaque: (0 as *mut core::ffi::c_void),
            data_type: 0,
            adler: 0,
            reserved: 0,
        }
    }
}
impl std::default::Default for z_stream_s {
    fn default() -> Self {
        z_stream_s::new()
    }
}
pub type z_stream = crate::src::lib::content_encoding::z_stream_s;
pub type z_streamp = *mut crate::src::lib::content_encoding::z_stream_s;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct zlib_params {
    pub zlib_init: u32,
    pub trailerlen: u32,
    pub z: crate::src::lib::content_encoding::z_stream_s,
}
impl zlib_params {
    pub const fn new() -> Self {
        zlib_params {
            zlib_init: 0,
            trailerlen: 0,
            z: crate::src::lib::content_encoding::z_stream_s::new(),
        }
    }
}
impl std::default::Default for zlib_params {
    fn default() -> Self {
        zlib_params::new()
    }
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
extern "C" fn zalloc_cb(
    mut _opaque: *mut core::ffi::c_void,
    mut items: u32,
    mut size: u32,
) -> *mut core::ffi::c_void {
    return unsafe { Curl_ccalloc.expect("non-null function pointer")(items as size_t, size as size_t) };
}
extern "C" fn zfree_cb(mut _opaque: *mut core::ffi::c_void, mut ptr: *mut core::ffi::c_void) {
    (unsafe { Curl_cfree.expect("non-null function pointer")(ptr) });
}
extern "C" fn process_zlib_error(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut z: *mut crate::src::lib::content_encoding::z_stream_s,
) -> u32 {
    if !(unsafe { (*z).msg }).is_null() {
        (unsafe { Curl_failf(
            data,
            b"Error while processing content unencoding: %s\0" as *const u8 as *const i8,
            (*z).msg,
        ) });
    } else {
        (unsafe { Curl_failf (data , b"Error while processing content unencoding: Unknown failure within decompression software.\0" as * const u8 as * const i8 ,) }) ;
    }
    return CURLE_BAD_CONTENT_ENCODING;
}
extern "C" fn exit_zlib<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut z: *mut crate::src::lib::content_encoding::z_stream_s,
    mut zlib_init: Option<&'a1 mut u32>,
    mut result: u32,
) -> u32 {
    if *(borrow(&zlib_init)).unwrap() as u32 == ZLIB_GZIP_HEADER as i32 as u32 {
        (unsafe { Curl_cfree.expect("non-null function pointer")((*z).next_in as *mut libc::c_void) });
        let mut fresh0 = unsafe { &mut ((*z).next_in) };
        *fresh0 = 0 as *mut Bytef;
    }
    if *(borrow(&zlib_init)).unwrap() as u32 != ZLIB_UNINIT as i32 as u32 {
        if (unsafe { inflateEnd(z) }) != 0 as i32 && result as u32 == CURLE_OK as i32 as u32 {
            result = process_zlib_error(data, z);
        }
        *(borrow_mut(&mut zlib_init)).unwrap() = ZLIB_UNINIT;
    }
    return result;
}
extern "C" fn process_trailer(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut zp: *mut crate::src::lib::content_encoding::zlib_params,
) -> u32 {
    let mut z: *mut crate::src::lib::content_encoding::z_stream_s = unsafe { &mut (*zp).z };
    let mut result: u32 = CURLE_OK;
    let mut len: u32 = if (unsafe { (*z).avail_in }) < (unsafe { (*zp).trailerlen }) {
        unsafe { (*z).avail_in }
    } else {
        unsafe { (*zp).trailerlen }
    };
    let mut fresh1 = unsafe { &mut ((*zp).trailerlen) };
    *fresh1 = (*fresh1 as u32).wrapping_sub(len) as uInt as uInt;
    let mut fresh2 = unsafe { &mut ((*z).avail_in) };
    *fresh2 = (*fresh2 as u32).wrapping_sub(len) as uInt as uInt;
    let mut fresh3 = unsafe { &mut ((*z).next_in) };
    *fresh3 = unsafe { (*fresh3).offset(len as isize) };
    if (unsafe { (*z).avail_in }) != 0 {
        result = CURLE_WRITE_ERROR;
    }
    if result as u32 != 0 || (unsafe { (*zp).trailerlen }) == 0 {
        result = exit_zlib(data, z, Some(unsafe { &mut (*zp).zlib_init }), result);
    } else {
        (unsafe { (*zp).zlib_init = ZLIB_EXTERNAL_TRAILER });
    }
    return result;
}
extern "C" fn inflate_stream(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut writer: *mut crate::src::lib::content_encoding::contenc_writer,
    mut started: u32,
) -> u32 {
    let mut zp: *mut crate::src::lib::content_encoding::zlib_params =
        (unsafe { &mut (*writer).params }) as *mut *mut libc::c_void as *mut zlib_params;
    let mut z: *mut crate::src::lib::content_encoding::z_stream_s = unsafe { &mut (*zp).z };
    let mut nread: u32 = unsafe { (*z).avail_in };
    let mut orig_in: *mut u8 = unsafe { (*z).next_in };
    let mut done: bool = 0 as i32 != 0;
    let mut result: u32 = CURLE_OK;
    let mut decomp: *mut i8 = 0 as *mut i8;
    if (unsafe { (*zp).zlib_init }) as u32 != ZLIB_INIT as i32 as u32
        && (unsafe { (*zp).zlib_init }) as u32 != ZLIB_INFLATING as i32 as u32
        && (unsafe { (*zp).zlib_init }) as u32 != ZLIB_INIT_GZIP as i32 as u32
        && (unsafe { (*zp).zlib_init }) as u32 != ZLIB_GZIP_INFLATING as i32 as u32
    {
        return exit_zlib(data, z, Some(unsafe { &mut (*zp).zlib_init }), CURLE_WRITE_ERROR);
    }
    decomp = (unsafe { Curl_cmalloc.expect("non-null function pointer")(16384 as i32 as size_t) }) as *mut i8;
    if decomp.is_null() {
        return exit_zlib(data, z, Some(unsafe { &mut (*zp).zlib_init }), CURLE_OUT_OF_MEMORY);
    }
    while !done {
        let mut status: i32 = 0;
        done = 1 as i32 != 0;
        let mut fresh4 = unsafe { &mut ((*z).next_out) };
        *fresh4 = decomp as *mut Bytef;
        (unsafe { (*z).avail_out = 16384 as i32 as uInt });
        status = unsafe { inflate(z, 5 as i32) };
        if (unsafe { (*z).avail_out }) != 16384 as i32 as u32 {
            if status == 0 as i32 || status == 1 as i32 {
                (unsafe { (*zp).zlib_init = started });
                result = Curl_unencode_write(
                    data,
                    unsafe { (*writer).downstream },
                    decomp,
                    (16384 as i32 as u32).wrapping_sub(unsafe { (*z).avail_out }) as size_t,
                );
                if result as u64 != 0 {
                    exit_zlib(data, z, Some(unsafe { &mut (*zp).zlib_init }), result);
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
                if (unsafe { (*zp).zlib_init }) as u32 == ZLIB_INIT as i32 as u32 {
                    (unsafe { inflateEnd(z) });
                    if (unsafe { inflateInit2_(
                        z,
                        -(15 as i32),
                        b"1.2.11\0" as *const u8 as *const i8,
                        ::std::mem::size_of::<z_stream>() as u64 as i32,
                    ) }) == 0 as i32
                    {
                        let mut fresh5 = unsafe { &mut ((*z).next_in) };
                        *fresh5 = orig_in;
                        (unsafe { (*z).avail_in = nread });
                        (unsafe { (*zp).zlib_init = ZLIB_INFLATING });
                        (unsafe { (*zp).trailerlen = 4 as i32 as uInt });
                        done = 0 as i32 != 0;
                        current_block_21 = 10692455896603418738;
                    } else {
                        (unsafe { (*zp).zlib_init = ZLIB_UNINIT });
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
                    Some(unsafe { &mut (*zp).zlib_init }),
                    process_zlib_error(data, z),
                );
            }
            _ => {}
        }
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")(decomp as *mut libc::c_void) });
    if nread != 0 && (unsafe { (*zp).zlib_init }) as u32 == ZLIB_INIT as i32 as u32 {
        (unsafe { (*zp).zlib_init = started });
    }
    return result;
}
extern "C" fn deflate_init_writer(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut writer: *mut crate::src::lib::content_encoding::contenc_writer,
) -> u32 {
    let mut zp: *mut crate::src::lib::content_encoding::zlib_params =
        (unsafe { &mut (*writer).params }) as *mut *mut libc::c_void as *mut zlib_params;
    let mut z: *mut crate::src::lib::content_encoding::z_stream_s = unsafe { &mut (*zp).z };
    if (unsafe { (*writer).downstream }).is_null() {
        return CURLE_WRITE_ERROR;
    }
    let mut fresh6 = unsafe { &mut ((*z).zalloc) };
    *fresh6 = unsafe { core::intrinsics::transmute::<
        Option<
            unsafe extern "C" fn(
                _: *mut core::ffi::c_void,
                _: u32,
                _: u32,
            ) -> *mut core::ffi::c_void,
        >,
        Option<
            unsafe extern "C" fn(
                _: *mut core::ffi::c_void,
                _: u32,
                _: u32,
            ) -> *mut core::ffi::c_void,
        >,
    >(Some(zalloc_cb)) };
    let mut fresh7 = unsafe { &mut ((*z).zfree) };
    *fresh7 = unsafe { core::intrinsics::transmute::<
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut core::ffi::c_void) -> ()>,
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut core::ffi::c_void) -> ()>,
    >(Some(zfree_cb)) };
    if (unsafe { inflateInit_(
        z,
        b"1.2.11\0" as *const u8 as *const i8,
        ::std::mem::size_of::<z_stream>() as u64 as i32,
    ) }) != 0 as i32
    {
        return process_zlib_error(data, z);
    }
    (unsafe { (*zp).zlib_init = ZLIB_INIT });
    return CURLE_OK;
}
extern "C" fn deflate_unencode_write(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut writer: *mut crate::src::lib::content_encoding::contenc_writer,
    mut buf: *const i8,
    mut nbytes: u64,
) -> u32 {
    let mut zp: *mut crate::src::lib::content_encoding::zlib_params =
        (unsafe { &mut (*writer).params }) as *mut *mut libc::c_void as *mut zlib_params;
    let mut z: Option<&'_ mut crate::src::lib::content_encoding::z_stream_s> = Some(unsafe { &mut (*zp).z });
    let mut fresh8 = &mut ((*(borrow_mut(&mut z)).unwrap()).next_in);
    *fresh8 = buf as *mut Bytef;
    (*(borrow_mut(&mut z)).unwrap()).avail_in = nbytes as uInt;
    if (unsafe { (*zp).zlib_init }) as u32 == ZLIB_EXTERNAL_TRAILER as i32 as u32 {
        return process_trailer(data, zp);
    }
    return inflate_stream(data, writer, ZLIB_INFLATING);
}
extern "C" fn deflate_close_writer(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut writer: *mut crate::src::lib::content_encoding::contenc_writer,
) {
    let mut zp: *mut crate::src::lib::content_encoding::zlib_params =
        (unsafe { &mut (*writer).params }) as *mut *mut libc::c_void as *mut zlib_params;
    let mut z: *mut crate::src::lib::content_encoding::z_stream_s = unsafe { &mut (*zp).z };
    exit_zlib(data, z, Some(unsafe { &mut (*zp).zlib_init }), CURLE_OK);
}
static mut deflate_encoding: crate::src::lib::content_encoding::content_encoding =  {
    {
        let mut init = content_encoding {
            name: b"deflate\0" as *const u8 as *const i8,
            alias: 0 as *const i8,
            init_writer: Some(deflate_init_writer),
            unencode_write: Some(deflate_unencode_write),
            close_writer: Some(deflate_close_writer),
            paramsize: ::std::mem::size_of::<zlib_params>() as u64,
        };
        init
    }
};
extern "C" fn gzip_init_writer(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut writer: *mut crate::src::lib::content_encoding::contenc_writer,
) -> u32 {
    let mut zp: *mut crate::src::lib::content_encoding::zlib_params =
        (unsafe { &mut (*writer).params }) as *mut *mut libc::c_void as *mut zlib_params;
    let mut z: *mut crate::src::lib::content_encoding::z_stream_s = unsafe { &mut (*zp).z };
    if (unsafe { (*writer).downstream }).is_null() {
        return CURLE_WRITE_ERROR;
    }
    let mut fresh9 = unsafe { &mut ((*z).zalloc) };
    *fresh9 = unsafe { core::intrinsics::transmute::<
        Option<
            unsafe extern "C" fn(
                _: *mut core::ffi::c_void,
                _: u32,
                _: u32,
            ) -> *mut core::ffi::c_void,
        >,
        Option<
            unsafe extern "C" fn(
                _: *mut core::ffi::c_void,
                _: u32,
                _: u32,
            ) -> *mut core::ffi::c_void,
        >,
    >(Some(zalloc_cb)) };
    let mut fresh10 = unsafe { &mut ((*z).zfree) };
    *fresh10 = unsafe { core::intrinsics::transmute::<
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut core::ffi::c_void) -> ()>,
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut core::ffi::c_void) -> ()>,
    >(Some(zfree_cb)) };
    if (unsafe { strcmp(zlibVersion(), b"1.2.0.4\0" as *const u8 as *const i8) }) >= 0 as i32 {
        if (unsafe { inflateInit2_(
            z,
            15 as i32 + 32 as i32,
            b"1.2.11\0" as *const u8 as *const i8,
            ::std::mem::size_of::<z_stream>() as u64 as i32,
        ) }) != 0 as i32
        {
            return process_zlib_error(data, z);
        }
        (unsafe { (*zp).zlib_init = ZLIB_INIT_GZIP });
    } else {
        if (unsafe { inflateInit2_(
            z,
            -(15 as i32),
            b"1.2.11\0" as *const u8 as *const i8,
            ::std::mem::size_of::<z_stream>() as u64 as i32,
        ) }) != 0 as i32
        {
            return process_zlib_error(data, z);
        }
        (unsafe { (*zp).trailerlen = 8 as i32 as uInt });
        (unsafe { (*zp).zlib_init = ZLIB_INIT });
    }
    return CURLE_OK;
}
extern "C" fn check_gzip_header<'a1>(
    mut data: *const u8,
    mut len: i64,
    mut headerlen: Option<&'a1 mut i64>,
) -> u32 {
    let mut method: i32 = 0;
    let mut flags: i32 = 0;
    let totallen: i64 = len;
    if len < 10 as i32 as i64 {
        return GZIP_UNDERFLOW;
    }
    if (unsafe { *data.offset(0 as i32 as isize) }) as i32 != 0x1f as i32
        || (unsafe { *data.offset(1 as i32 as isize) }) as i32 != 0x8b as i32
    {
        return GZIP_BAD;
    }
    method = (unsafe { *data.offset(2 as i32 as isize) }) as i32;
    flags = (unsafe { *data.offset(3 as i32 as isize) }) as i32;
    if method != 8 as i32 || flags & 0xe0 as i32 != 0 as i32 {
        return GZIP_BAD;
    }
    len -= 10 as i32 as i64;
    data = unsafe { data.offset(10 as i32 as isize) };
    if flags & 0x4 as i32 != 0 {
        let mut extra_len: i64 = 0;
        if len < 2 as i32 as i64 {
            return GZIP_UNDERFLOW;
        }
        extra_len = (((unsafe { *data.offset(1 as i32 as isize) }) as i32) << 8 as i32
            | (unsafe { *data.offset(0 as i32 as isize) }) as i32) as ssize_t;
        if len < extra_len + 2 as i32 as i64 {
            return GZIP_UNDERFLOW;
        }
        len -= extra_len + 2 as i32 as i64;
        data = unsafe { data.offset((extra_len + 2 as i32 as i64) as isize) };
    }
    if flags & 0x8 as i32 != 0 {
        while len != 0 && (unsafe { *data }) as i32 != 0 {
            len -= 1;
            data = unsafe { data.offset(1) };
        }
        if len == 0 || (unsafe { *data }) as i32 != 0 {
            return GZIP_UNDERFLOW;
        }
        len -= 1;
        data = unsafe { data.offset(1) };
    }
    if flags & 0x10 as i32 != 0 {
        while len != 0 && (unsafe { *data }) as i32 != 0 {
            len -= 1;
            data = unsafe { data.offset(1) };
        }
        if len == 0 || (unsafe { *data }) as i32 != 0 {
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
    *(borrow_mut(&mut headerlen)).unwrap() = totallen - len;
    return GZIP_OK;
}
extern "C" fn gzip_unencode_write(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut writer: *mut crate::src::lib::content_encoding::contenc_writer,
    mut buf: *const i8,
    mut nbytes: u64,
) -> u32 {
    let mut zp: *mut crate::src::lib::content_encoding::zlib_params =
        (unsafe { &mut (*writer).params }) as *mut *mut libc::c_void as *mut zlib_params;
    let mut z: *mut crate::src::lib::content_encoding::z_stream_s = unsafe { &mut (*zp).z };
    if (unsafe { (*zp).zlib_init }) as u32 == ZLIB_INIT_GZIP as i32 as u32 {
        let mut fresh11 = unsafe { &mut ((*z).next_in) };
        *fresh11 = buf as *mut Bytef;
        (unsafe { (*z).avail_in = nbytes as uInt });
        return inflate_stream(data, writer, ZLIB_INIT_GZIP);
    }
    match (unsafe { (*zp).zlib_init }) as u32 {
        1 => {
            let mut hlen: i64 = 0;
            match check_gzip_header(buf as *mut u8, nbytes as ssize_t, Some(&mut hlen)) as u32 {
                0 => {
                    let mut fresh12 = unsafe { &mut ((*z).next_in) };
                    *fresh12 = unsafe { (buf as *mut Bytef).offset(hlen as isize) };
                    (unsafe { (*z).avail_in = nbytes.wrapping_sub(hlen as u64) as uInt });
                    (unsafe { (*zp).zlib_init = ZLIB_GZIP_INFLATING });
                }
                2 => {
                    (unsafe { (*z).avail_in = nbytes as uInt });
                    let mut fresh13 = unsafe { &mut ((*z).next_in) };
                    *fresh13 =
                        (unsafe { Curl_cmalloc.expect("non-null function pointer")((*z).avail_in as size_t) })
                            as *mut Bytef;
                    if (unsafe { (*z).next_in }).is_null() {
                        return exit_zlib(data, z, Some(unsafe { &mut (*zp).zlib_init }), CURLE_OUT_OF_MEMORY);
                    }
                    (unsafe { memcpy(
                        (*z).next_in as *mut libc::c_void,
                        buf as *const libc::c_void,
                        (*z).avail_in as u64,
                    ) });
                    (unsafe { (*zp).zlib_init = ZLIB_GZIP_HEADER });
                    return CURLE_OK;
                }
                1 | _ => {
                    return exit_zlib(
                        data,
                        z,
                        Some(unsafe { &mut (*zp).zlib_init }),
                        process_zlib_error(data, z),
                    );
                }
            }
        }
        4 => {
            let mut hlen_0: i64 = 0;
            let mut fresh14 = unsafe { &mut ((*z).avail_in) };
            *fresh14 = (*fresh14 as u32).wrapping_add(nbytes as uInt) as uInt as uInt;
            let mut fresh15 = unsafe { &mut ((*z).next_in) };
            *fresh15 = Curl_saferealloc((unsafe { (*z).next_in }) as *mut libc::c_void, (unsafe { (*z).avail_in }) as size_t)
                as *mut Bytef;
            if (unsafe { (*z).next_in }).is_null() {
                return exit_zlib(data, z, Some(unsafe { &mut (*zp).zlib_init }), CURLE_OUT_OF_MEMORY);
            }
            (unsafe { memcpy(
                ((*z).next_in)
                    .offset((*z).avail_in as isize)
                    .offset(-(nbytes as isize)) as *mut libc::c_void,
                buf as *const libc::c_void,
                nbytes,
            ) });
            match check_gzip_header(unsafe { (*z).next_in }, (unsafe { (*z).avail_in }) as ssize_t, Some(&mut hlen_0))
                as u32
            {
                0 => {
                    (unsafe { Curl_cfree.expect("non-null function pointer")(
                        (*z).next_in as *mut libc::c_void,
                    ) });
                    let mut fresh16 = unsafe { &mut ((*z).next_in) };
                    *fresh16 = unsafe { (buf as *mut Bytef)
                        .offset(hlen_0 as isize)
                        .offset(nbytes as isize)
                        .offset(-((*z).avail_in as isize)) };
                    (unsafe { (*z).avail_in = ((*z).avail_in as i64 - hlen_0) as uInt });
                    (unsafe { (*zp).zlib_init = ZLIB_GZIP_INFLATING });
                }
                2 => return CURLE_OK,
                1 | _ => {
                    return exit_zlib(
                        data,
                        z,
                        Some(unsafe { &mut (*zp).zlib_init }),
                        process_zlib_error(data, z),
                    );
                }
            }
        }
        3 => {
            let mut fresh17 = unsafe { &mut ((*z).next_in) };
            *fresh17 = buf as *mut Bytef;
            (unsafe { (*z).avail_in = nbytes as uInt });
            return process_trailer(data, zp);
        }
        5 | _ => {
            let mut fresh18 = unsafe { &mut ((*z).next_in) };
            *fresh18 = buf as *mut Bytef;
            (unsafe { (*z).avail_in = nbytes as uInt });
        }
    }
    if (unsafe { (*z).avail_in }) == 0 as i32 as u32 {
        return CURLE_OK;
    }
    return inflate_stream(data, writer, ZLIB_GZIP_INFLATING);
}
extern "C" fn gzip_close_writer(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut writer: *mut crate::src::lib::content_encoding::contenc_writer,
) {
    let mut zp: *mut crate::src::lib::content_encoding::zlib_params =
        (unsafe { &mut (*writer).params }) as *mut *mut libc::c_void as *mut zlib_params;
    let mut z: *mut crate::src::lib::content_encoding::z_stream_s = unsafe { &mut (*zp).z };
    exit_zlib(data, z, Some(unsafe { &mut (*zp).zlib_init }), CURLE_OK);
}
static mut gzip_encoding: crate::src::lib::content_encoding::content_encoding =  {
    {
        let mut init = content_encoding {
            name: b"gzip\0" as *const u8 as *const i8,
            alias: b"x-gzip\0" as *const u8 as *const i8,
            init_writer: Some(gzip_init_writer),
            unencode_write: Some(gzip_unencode_write),
            close_writer: Some(gzip_close_writer),
            paramsize: ::std::mem::size_of::<zlib_params>() as u64,
        };
        init
    }
};
extern "C" fn identity_init_writer(
    mut _data: *mut crate::src::lib::http2::Curl_easy,
    mut writer: *mut crate::src::lib::content_encoding::contenc_writer,
) -> u32 {
    return (if !(unsafe { (*writer).downstream }).is_null() {
        CURLE_OK as i32
    } else {
        CURLE_WRITE_ERROR as i32
    }) as CURLcode;
}
extern "C" fn identity_unencode_write(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut writer: *mut crate::src::lib::content_encoding::contenc_writer,
    mut buf: *const i8,
    mut nbytes: u64,
) -> u32 {
    return Curl_unencode_write(data, unsafe { (*writer).downstream }, buf, nbytes);
}
extern "C" fn identity_close_writer(
    mut _data: *mut crate::src::lib::http2::Curl_easy,
    mut _writer: *mut crate::src::lib::content_encoding::contenc_writer,
) {
}
static mut identity_encoding: crate::src::lib::content_encoding::content_encoding =  {
    {
        let mut init = content_encoding {
            name: b"identity\0" as *const u8 as *const i8,
            alias: b"none\0" as *const u8 as *const i8,
            init_writer: Some(identity_init_writer),
            unencode_write: Some(identity_unencode_write),
            close_writer: Some(identity_close_writer),
            paramsize: 0 as i32 as size_t,
        };
        init
    }
};
static mut encodings: [*const crate::src::lib::content_encoding::content_encoding; 4] = unsafe {
    [
        &identity_encoding as *const content_encoding,
        &deflate_encoding as *const content_encoding,
        &gzip_encoding as *const content_encoding,
        0 as *const content_encoding,
    ]
};
#[no_mangle]
pub extern "C" fn Curl_all_content_encodings() -> *mut i8 {
    let mut len: u64 = 0 as i32 as size_t;
    let mut cep: *const *const crate::src::lib::content_encoding::content_encoding =
        0 as *const *const crate::src::lib::content_encoding::content_encoding;
    let mut ce: *const crate::src::lib::content_encoding::content_encoding =
        0 as *const content_encoding;
    let mut ace: *mut i8 = 0 as *mut i8;
    cep = unsafe { encodings.as_ptr() };
    while !(unsafe { *cep }).is_null() {
        ce = unsafe { *cep };
        if Curl_strcasecompare(unsafe { (*ce).name }, b"identity\0" as *const u8 as *const i8) == 0 {
            len = (len as u64).wrapping_add((unsafe { strlen((*ce).name) }).wrapping_add(2 as i32 as u64))
                as size_t as size_t;
        }
        cep = unsafe { cep.offset(1) };
    }
    if len == 0 {
        return unsafe { Curl_cstrdup.expect("non-null function pointer")(
            b"identity\0" as *const u8 as *const i8,
        ) };
    }
    ace = (unsafe { Curl_cmalloc.expect("non-null function pointer")(len) }) as *mut i8;
    if !ace.is_null() {
        let mut p: *mut i8 = ace;
        cep = unsafe { encodings.as_ptr() };
        while !(unsafe { *cep }).is_null() {
            ce = unsafe { *cep };
            if Curl_strcasecompare(unsafe { (*ce).name }, b"identity\0" as *const u8 as *const i8) == 0 {
                (unsafe { strcpy(p, (*ce).name) });
                p = unsafe { p.offset(strlen(p) as isize) };
                let mut fresh19 = p;
                p = unsafe { p.offset(1) };
                (unsafe { *fresh19 = ',' as i32 as i8 });
                let mut fresh20 = p;
                p = unsafe { p.offset(1) };
                (unsafe { *fresh20 = ' ' as i32 as i8 });
            }
            cep = unsafe { cep.offset(1) };
        }
        (unsafe { *p.offset(-(2 as i32) as isize) = '\u{0}' as i32 as i8 });
    }
    return ace;
}
extern "C" fn client_init_writer(
    mut _data: *mut crate::src::lib::http2::Curl_easy,
    mut writer: *mut crate::src::lib::content_encoding::contenc_writer,
) -> u32 {
    return (if !(unsafe { (*writer).downstream }).is_null() {
        CURLE_WRITE_ERROR as i32
    } else {
        CURLE_OK as i32
    }) as CURLcode;
}
extern "C" fn client_unencode_write(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut _writer: *mut crate::src::lib::content_encoding::contenc_writer,
    mut buf: *const i8,
    mut nbytes: u64,
) -> u32 {
    let mut k: Option<&'_ mut crate::src::lib::http2::SingleRequest> = Some(unsafe { &mut (*data).req });
    if nbytes == 0 || (*(borrow(&k)).unwrap()).ignorebody() as i32 != 0 {
        return CURLE_OK;
    }
    return Curl_client_write(data, (1 as i32) << 0 as i32, buf as *mut i8, nbytes);
}
extern "C" fn client_close_writer(
    mut _data: *mut crate::src::lib::http2::Curl_easy,
    mut _writer: *mut crate::src::lib::content_encoding::contenc_writer,
) {
}
static mut client_encoding: crate::src::lib::content_encoding::content_encoding =  {
    {
        let mut init = content_encoding {
            name: 0 as *const i8,
            alias: 0 as *const i8,
            init_writer: Some(client_init_writer),
            unencode_write: Some(client_unencode_write),
            close_writer: Some(client_close_writer),
            paramsize: 0 as i32 as size_t,
        };
        init
    }
};
extern "C" fn error_init_writer(
    mut _data: *mut crate::src::lib::http2::Curl_easy,
    mut writer: *mut crate::src::lib::content_encoding::contenc_writer,
) -> u32 {
    return (if !(unsafe { (*writer).downstream }).is_null() {
        CURLE_OK as i32
    } else {
        CURLE_WRITE_ERROR as i32
    }) as CURLcode;
}
extern "C" fn error_unencode_write(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut _writer: *mut crate::src::lib::content_encoding::contenc_writer,
    mut _buf: *const i8,
    mut _nbytes: u64,
) -> u32 {
    let mut all: *mut i8 = Curl_all_content_encodings();
    if all.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    (unsafe { Curl_failf(
        data,
        b"Unrecognized content encoding type. libcurl understands %s content encodings.\0"
            as *const u8 as *const i8,
        all,
    ) });
    (unsafe { Curl_cfree.expect("non-null function pointer")(all as *mut libc::c_void) });
    return CURLE_BAD_CONTENT_ENCODING;
}
extern "C" fn error_close_writer(
    mut _data: *mut crate::src::lib::http2::Curl_easy,
    mut _writer: *mut crate::src::lib::content_encoding::contenc_writer,
) {
}
static mut error_encoding: crate::src::lib::content_encoding::content_encoding =  {
    {
        let mut init = content_encoding {
            name: 0 as *const i8,
            alias: 0 as *const i8,
            init_writer: Some(error_init_writer),
            unencode_write: Some(error_unencode_write),
            close_writer: Some(error_close_writer),
            paramsize: 0 as i32 as size_t,
        };
        init
    }
};
extern "C" fn new_unencoding_writer(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut handler: *const crate::src::lib::content_encoding::content_encoding,
    mut downstream: *mut crate::src::lib::content_encoding::contenc_writer,
) -> *mut crate::src::lib::content_encoding::contenc_writer {
    let mut sz: u64 = (16 as u64).wrapping_add(unsafe { (*handler).paramsize });
    let mut writer: *mut crate::src::lib::content_encoding::contenc_writer =
        (unsafe { Curl_ccalloc.expect("non-null function pointer")(1 as i32 as size_t, sz) })
            as *mut contenc_writer;
    if !writer.is_null() {
        let mut fresh21 = unsafe { &mut ((*writer).handler) };
        *fresh21 = handler;
        let mut fresh22 = unsafe { &mut ((*writer).downstream) };
        *fresh22 = downstream;
        if (unsafe { ((*handler).init_writer).expect("non-null function pointer")(data, writer) }) as u64 != 0 {
            (unsafe { Curl_cfree.expect("non-null function pointer")(writer as *mut libc::c_void) });
            writer = 0 as *mut contenc_writer;
        }
    }
    return writer;
}
#[no_mangle]
pub extern "C" fn Curl_unencode_write(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut writer: *mut crate::src::lib::content_encoding::contenc_writer,
    mut buf: *const i8,
    mut nbytes: u64,
) -> u32 {
    if nbytes == 0 {
        return CURLE_OK;
    }
    return unsafe { ((*(*writer).handler).unencode_write).expect("non-null function pointer")(
        data, writer, buf, nbytes,
    ) };
}
#[no_mangle]
pub extern "C" fn Curl_unencode_cleanup(mut data: *mut crate::src::lib::http2::Curl_easy) {
    let mut k: Option<&'_ mut crate::src::lib::http2::SingleRequest> = Some(unsafe { &mut (*data).req });
    let mut writer: *mut crate::src::lib::content_encoding::contenc_writer =
        (*(borrow_mut(&mut k)).unwrap()).writer_stack;
    while !writer.is_null() {
        let mut fresh23 = &mut ((*(borrow_mut(&mut k)).unwrap()).writer_stack);
        *fresh23 = unsafe { (*writer).downstream };
        (unsafe { ((*(*writer).handler).close_writer).expect("non-null function pointer")(data, writer) });
        (unsafe { Curl_cfree.expect("non-null function pointer")(writer as *mut libc::c_void) });
        writer = (*(borrow_mut(&mut k)).unwrap()).writer_stack;
    }
}
extern "C" fn find_encoding(
    mut name: *const i8,
    mut len: u64,
) -> *const crate::src::lib::content_encoding::content_encoding {
    let mut cep: *const *const crate::src::lib::content_encoding::content_encoding =
        0 as *const *const crate::src::lib::content_encoding::content_encoding;
    cep = unsafe { encodings.as_ptr() };
    while !(unsafe { *cep }).is_null() {
        let mut ce: *const crate::src::lib::content_encoding::content_encoding = unsafe { *cep };
        if Curl_strncasecompare(name, unsafe { (*ce).name }, len) != 0
            && (unsafe { *((*ce).name).offset(len as isize) }) == 0
            || !(unsafe { (*ce).alias }).is_null()
                && Curl_strncasecompare(name, unsafe { (*ce).alias }, len) != 0
                && (unsafe { *((*ce).alias).offset(len as isize) }) == 0
        {
            return ce;
        }
        cep = unsafe { cep.offset(1) };
    }
    return 0 as *const content_encoding;
}
#[no_mangle]
pub extern "C" fn Curl_build_unencoding_stack(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut enclist: *const i8,
    mut maybechunked: i32,
) -> u32 {
    let mut k: Option<&'_ mut crate::src::lib::http2::SingleRequest> = Some(unsafe { &mut (*data).req });
    loop {
        let mut name: *const i8 = 0 as *const i8;
        let mut namelen: u64 = 0;
        while Curl_isspace((unsafe { *enclist }) as u8 as i32) != 0 || (unsafe { *enclist }) as i32 == ',' as i32 {
            enclist = unsafe { enclist.offset(1) };
        }
        name = enclist;
        namelen = 0 as i32 as size_t;
        while (unsafe { *enclist }) as i32 != 0 && (unsafe { *enclist }) as i32 != ',' as i32 {
            if Curl_isspace((unsafe { *enclist }) as u8 as i32) == 0 {
                namelen = ((unsafe { enclist.offset_from(name) }) as i64 + 1 as i32 as i64) as size_t;
            }
            enclist = unsafe { enclist.offset(1) };
        }
        if maybechunked != 0
            && namelen == 7 as i32 as u64
            && Curl_strncasecompare(
                name,
                b"chunked\0" as *const u8 as *const i8,
                7 as i32 as size_t,
            ) != 0
        {
            (*(borrow_mut(&mut k)).unwrap()).set_chunk(1 as i32 as bit);
            Curl_httpchunk_init(data);
        } else if namelen != 0 {
            let mut encoding: *const crate::src::lib::content_encoding::content_encoding =
                find_encoding(name, namelen);
            let mut writer: *mut crate::src::lib::content_encoding::contenc_writer =
                0 as *mut contenc_writer;
            if ((*(borrow_mut(&mut k)).unwrap()).writer_stack).is_null() {
                let mut fresh24 = &mut ((*(borrow_mut(&mut k)).unwrap()).writer_stack);
                *fresh24 = new_unencoding_writer(data, unsafe { &client_encoding }, 0 as *mut contenc_writer);
                if ((*(borrow_mut(&mut k)).unwrap()).writer_stack).is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
            }
            if encoding.is_null() {
                encoding = unsafe { &error_encoding };
            }
            writer = new_unencoding_writer(
                data,
                encoding,
                (*(borrow_mut(&mut k)).unwrap()).writer_stack,
            );
            if writer.is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            let mut fresh25 = &mut ((*(borrow_mut(&mut k)).unwrap()).writer_stack);
            *fresh25 = writer;
        }
        if !((unsafe { *enclist }) != 0) {
            break;
        }
    }
    return CURLE_OK;
}
use crate::laertes_rt::*;
