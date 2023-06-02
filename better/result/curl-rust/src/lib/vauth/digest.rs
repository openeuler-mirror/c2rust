
use :: libc;
extern "C" {
    fn strlen(_: *const i8) -> u64;
    fn strtok_r(__s: *mut i8, __delim: *const i8, __save_ptr: *mut *mut i8) -> *mut i8;
    fn strstr(_: *const i8, _: *const i8) -> *mut i8;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
}
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::base64::Curl_base64_encode;
pub use crate::src::lib::bufref::Curl_bufref_len;
pub use crate::src::lib::bufref::Curl_bufref_ptr;
pub use crate::src::lib::bufref::Curl_bufref_set;
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::curl_ctype::Curl_isspace;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_cstrdup;
pub use crate::src::lib::escape::curl_free;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::md5::Curl_DIGEST_MD5;
pub use crate::src::lib::md5::Curl_MD5_final;
pub use crate::src::lib::md5::Curl_MD5_init;
pub use crate::src::lib::md5::Curl_MD5_update;
pub use crate::src::lib::md5::Curl_md5it;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::rand::Curl_rand_hex;
pub use crate::src::lib::sha256::Curl_sha256it;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::vauth::vauth::Curl_auth_build_spn;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
pub use crate::src::lib::warnless::curlx_uztoui;
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
pub type bufref = crate::src::lib::bufref::bufref;
pub type MD5_context = crate::src::lib::md5::MD5_context;
pub type MD5_params = crate::src::lib::md5::MD5_params;
pub type Curl_MD5_final_func<'a1, 'a2> = Option<
    unsafe extern "C" fn(_: Option<&'a1 mut u8>, _: Option<&'a2 mut core::ffi::c_void>) -> (),
>;
pub type Curl_MD5_update_func<'a1, 'a2> = Option<
    unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>, _: Option<&'a2 u8>, _: u32) -> (),
>;
pub type Curl_MD5_init_func<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>) -> ()>;
pub const CURLDIGESTALGO_SHA512_256SESS: C2RustUnnamed_6 = 5;
pub const CURLDIGESTALGO_SHA512_256: C2RustUnnamed_6 = 4;
pub const CURLDIGESTALGO_SHA256SESS: C2RustUnnamed_6 = 3;
pub const CURLDIGESTALGO_SHA256: C2RustUnnamed_6 = 2;
pub const CURLDIGESTALGO_MD5: C2RustUnnamed_6 = 0;
pub const CURLDIGESTALGO_MD5SESS: C2RustUnnamed_6 = 1;
pub type C2RustUnnamed_6 = u32;
#[no_mangle]
pub extern "C" fn Curl_auth_digest_get_pair<'a1>(
    mut str: *const i8,
    mut value: *mut i8,
    mut content: *mut i8,
    mut endptr: Option<&'a1 mut *const i8>,
) -> bool {
    let mut c: i32 = 0;
    let mut starts_with_quote: bool = 0 as i32 != 0;
    let mut escape: bool = 0 as i32 != 0;
    c = 256 as i32 - 1 as i32;
    while (unsafe { *str }) as i32 != 0 && (unsafe { *str }) as i32 != '=' as i32 && {
        let mut fresh0 = c;
        c = c - 1;
        fresh0 != 0
    } {
        let mut fresh1 = str;
        str = unsafe { str.offset(1) };
        let mut fresh2 = value;
        value = unsafe { value.offset(1) };
        (unsafe { *fresh2 = *fresh1 });
    }
    (unsafe { *value = 0 as i32 as i8 });
    let mut fresh3 = str;
    str = unsafe { str.offset(1) };
    if '=' as i32 != (unsafe { *fresh3 }) as i32 {
        return 0 as i32 != 0;
    }
    if '"' as i32 == (unsafe { *str }) as i32 {
        str = unsafe { str.offset(1) };
        starts_with_quote = 1 as i32 != 0;
    }
    let mut current_block_17: u64;
    c = 1024 as i32 - 1 as i32;
    while (unsafe { *str }) as i32 != 0 && {
        let mut fresh4 = c;
        c = c - 1;
        fresh4 != 0
    } {
        match (unsafe { *str }) as i32 {
            92 => {
                if !escape {
                    escape = 1 as i32 != 0;
                    let mut fresh5 = content;
                    content = unsafe { content.offset(1) };
                    (unsafe { *fresh5 = '\\' as i32 as i8 });
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
                let mut fresh6 = content;
                content = unsafe { content.offset(1) };
                (unsafe { *fresh6 = *str });
            }
            _ => {}
        }
        str = unsafe { str.offset(1) };
    }
    (unsafe { *content = 0 as i32 as i8 });
    *(borrow_mut(&mut endptr)).unwrap() = str;
    return 1 as i32 != 0;
}
extern "C" fn auth_digest_md5_to_ascii(mut source: *mut u8, mut dest: *mut u8) {
    let mut i: i32 = 0;
    i = 0 as i32;
    while i < 16 as i32 {
        (unsafe { curl_msnprintf(
            &mut *dest.offset((i * 2 as i32) as isize) as *mut u8 as *mut i8,
            3 as i32 as size_t,
            b"%02x\0" as *const u8 as *const i8,
            *source.offset(i as isize) as i32,
        ) });
        i += 1;
    }
}
extern "C" fn auth_digest_sha256_to_ascii(mut source: *mut u8, mut dest: *mut u8) {
    let mut i: i32 = 0;
    i = 0 as i32;
    while i < 32 as i32 {
        (unsafe { curl_msnprintf(
            &mut *dest.offset((i * 2 as i32) as isize) as *mut u8 as *mut i8,
            3 as i32 as size_t,
            b"%02x\0" as *const u8 as *const i8,
            *source.offset(i as isize) as i32,
        ) });
        i += 1;
    }
}
extern "C" fn auth_digest_string_quoted(mut source: *const i8) -> *mut i8 {
    let mut dest: *mut i8 = 0 as *mut i8;
    let mut s: *const i8 = source;
    let mut n: u64 = 1 as i32 as size_t;
    while (unsafe { *s }) != 0 {
        n = n.wrapping_add(1);
        if (unsafe { *s }) as i32 == '"' as i32 || (unsafe { *s }) as i32 == '\\' as i32 {
            n = n.wrapping_add(1);
        }
        s = unsafe { s.offset(1) };
    }
    dest = (unsafe { Curl_cmalloc.expect("non-null function pointer")(n) }) as *mut i8;
    if !dest.is_null() {
        let mut d: *mut i8 = dest;
        s = source;
        while (unsafe { *s }) != 0 {
            if (unsafe { *s }) as i32 == '"' as i32 || (unsafe { *s }) as i32 == '\\' as i32 {
                let mut fresh7 = d;
                d = unsafe { d.offset(1) };
                (unsafe { *fresh7 = '\\' as i32 as i8 });
            }
            let mut fresh8 = s;
            s = unsafe { s.offset(1) };
            let mut fresh9 = d;
            d = unsafe { d.offset(1) };
            (unsafe { *fresh9 = *fresh8 });
        }
        (unsafe { *d = 0 as i32 as i8 });
    }
    return dest;
}
extern "C" fn auth_digest_get_key_value(
    mut chlg: *const i8,
    mut key: *const i8,
    mut value: *mut i8,
    mut max_val_len: u64,
    mut end_char: i8,
) -> bool {
    let mut find_pos: *mut i8 = 0 as *mut i8;
    let mut i: u64 = 0;
    find_pos = unsafe { strstr(chlg, key) };
    if find_pos.is_null() {
        return 0 as i32 != 0;
    }
    find_pos = unsafe { find_pos.offset(strlen(key) as isize) };
    i = 0 as i32 as size_t;
    while (unsafe { *find_pos }) as i32 != 0
        && (unsafe { *find_pos }) as i32 != end_char as i32
        && i < max_val_len.wrapping_sub(1 as i32 as u64)
    {
        let mut fresh10 = find_pos;
        find_pos = unsafe { find_pos.offset(1) };
        (unsafe { *value.offset(i as isize) = *fresh10 });
        i = i.wrapping_add(1);
    }
    (unsafe { *value.offset(i as isize) = '\u{0}' as i32 as i8 });
    return 1 as i32 != 0;
}
extern "C" fn auth_digest_get_qop_values<'a1>(
    mut options: *const i8,
    mut value: Option<&'a1 mut i32>,
) -> u32 {
    let mut tmp: *mut i8 = 0 as *mut i8;
    let mut token: *mut i8 = 0 as *mut i8;
    let mut tok_buf: *mut i8 = 0 as *mut i8;
    *(borrow_mut(&mut value)).unwrap() = 0 as i32;
    tmp = unsafe { Curl_cstrdup.expect("non-null function pointer")(options) };
    if tmp.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    token = unsafe { strtok_r(tmp, b",\0" as *const u8 as *const i8, &mut tok_buf) };
    while !token.is_null() {
        if Curl_strcasecompare(token, b"auth\0" as *const u8 as *const i8) != 0 {
            *(borrow_mut(&mut value)).unwrap() |= (1 as i32) << 0 as i32;
        } else if Curl_strcasecompare(token, b"auth-int\0" as *const u8 as *const i8) != 0 {
            *(borrow_mut(&mut value)).unwrap() |= (1 as i32) << 1 as i32;
        } else if Curl_strcasecompare(token, b"auth-conf\0" as *const u8 as *const i8) != 0 {
            *(borrow_mut(&mut value)).unwrap() |= (1 as i32) << 2 as i32;
        }
        token = unsafe { strtok_r(0 as *mut i8, b",\0" as *const u8 as *const i8, &mut tok_buf) };
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")(tmp as *mut libc::c_void) });
    return CURLE_OK;
}
extern "C" fn auth_decode_digest_md5_message<'a1>(
    mut chlgref: Option<&'a1 crate::src::lib::bufref::bufref>,
    mut nonce: *mut i8,
    mut nlen: u64,
    mut realm: *mut i8,
    mut rlen: u64,
    mut alg: *mut i8,
    mut alen: u64,
    mut qop: *mut i8,
    mut qlen: u64,
) -> u32 {
    let mut chlg: *const i8 = Curl_bufref_ptr((chlgref).clone()) as *const i8;
    if Curl_bufref_len((chlgref).clone()) == 0 {
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
        (unsafe { strcpy(realm, b"\0" as *const u8 as *const i8) });
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
pub extern "C" fn Curl_auth_create_digest_md5_message<'a1, 'a2>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut chlg: Option<&'a1 crate::src::lib::bufref::bufref>,
    mut userp: *const i8,
    mut passwdp: *const i8,
    mut service: *const i8,
    mut out: Option<&'a2 mut crate::src::lib::bufref::bufref>,
) -> u32 {
    let mut i: u64 = 0;
    let mut ctxt: *mut crate::src::lib::md5::MD5_context = 0 as *mut MD5_context;
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
    let mut nonceCount: [i8; 9] =
        *(unsafe { core::intrinsics::transmute::<&'_ [u8; 9], &'_ mut [i8; 9]>(b"00000001\0") });
    let mut method: [i8; 13] =
        *(unsafe { core::intrinsics::transmute::<&'_ [u8; 13], &'_ mut [i8; 13]>(b"AUTHENTICATE\0") });
    let mut qop: [i8; 5] = *(unsafe { core::intrinsics::transmute::<&'_ [u8; 5], &'_ mut [i8; 5]>(b"auth\0") });
    let mut spn: *mut i8 = 0 as *mut i8;
    let mut result: u32 = auth_decode_digest_md5_message(
        (chlg).clone(),
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
    if (unsafe { strcmp(
        algorithm.as_mut_ptr(),
        b"md5-sess\0" as *const u8 as *const i8,
    ) }) != 0 as i32
    {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    result = auth_digest_get_qop_values(qop_options.as_mut_ptr(), Some(&mut qop_values));
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
    ctxt = Curl_MD5_init(unsafe { Curl_DIGEST_MD5.as_ptr() });
    if ctxt.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    Curl_MD5_update(ctxt, userp as *const u8, curlx_uztoui(unsafe { strlen(userp) }));
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(
        ctxt,
        realm.as_mut_ptr() as *const u8,
        curlx_uztoui(unsafe { strlen(realm.as_mut_ptr()) }),
    );
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(ctxt, passwdp as *const u8, curlx_uztoui(unsafe { strlen(passwdp) }));
    Curl_MD5_final(ctxt, digest.as_mut_ptr());
    ctxt = Curl_MD5_init(unsafe { Curl_DIGEST_MD5.as_ptr() });
    if ctxt.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    Curl_MD5_update(ctxt, digest.as_mut_ptr() as *const u8, 16 as i32 as u32);
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(
        ctxt,
        nonce.as_mut_ptr() as *const u8,
        curlx_uztoui(unsafe { strlen(nonce.as_mut_ptr()) }),
    );
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(
        ctxt,
        cnonce.as_mut_ptr() as *const u8,
        curlx_uztoui(unsafe { strlen(cnonce.as_mut_ptr()) }),
    );
    Curl_MD5_final(ctxt, digest.as_mut_ptr());
    i = 0 as i32 as size_t;
    while i < 16 as i32 as u64 {
        (unsafe { curl_msnprintf(
            &mut *HA1_hex
                .as_mut_ptr()
                .offset((2 as i32 as u64).wrapping_mul(i) as isize) as *mut i8,
            3 as i32 as size_t,
            b"%02x\0" as *const u8 as *const i8,
            digest[i as usize] as i32,
        ) });
        i = i.wrapping_add(1);
    }
    spn = Curl_auth_build_spn(service, realm.as_mut_ptr(), 0 as *const i8);
    if spn.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    ctxt = Curl_MD5_init(unsafe { Curl_DIGEST_MD5.as_ptr() });
    if ctxt.is_null() {
        (unsafe { Curl_cfree.expect("non-null function pointer")(spn as *mut libc::c_void) });
        return CURLE_OUT_OF_MEMORY;
    }
    Curl_MD5_update(
        ctxt,
        method.as_mut_ptr() as *const u8,
        curlx_uztoui(unsafe { strlen(method.as_mut_ptr()) }),
    );
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(ctxt, spn as *const u8, curlx_uztoui(unsafe { strlen(spn) }));
    Curl_MD5_final(ctxt, digest.as_mut_ptr());
    i = 0 as i32 as size_t;
    while i < 16 as i32 as u64 {
        (unsafe { curl_msnprintf(
            &mut *HA2_hex
                .as_mut_ptr()
                .offset((2 as i32 as u64).wrapping_mul(i) as isize) as *mut i8,
            3 as i32 as size_t,
            b"%02x\0" as *const u8 as *const i8,
            digest[i as usize] as i32,
        ) });
        i = i.wrapping_add(1);
    }
    ctxt = Curl_MD5_init(unsafe { Curl_DIGEST_MD5.as_ptr() });
    if ctxt.is_null() {
        (unsafe { Curl_cfree.expect("non-null function pointer")(spn as *mut libc::c_void) });
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
        curlx_uztoui(unsafe { strlen(nonce.as_mut_ptr()) }),
    );
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(
        ctxt,
        nonceCount.as_mut_ptr() as *const u8,
        curlx_uztoui(unsafe { strlen(nonceCount.as_mut_ptr()) }),
    );
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(
        ctxt,
        cnonce.as_mut_ptr() as *const u8,
        curlx_uztoui(unsafe { strlen(cnonce.as_mut_ptr()) }),
    );
    Curl_MD5_update(
        ctxt,
        b":\0" as *const u8 as *const i8 as *const u8,
        1 as i32 as u32,
    );
    Curl_MD5_update(
        ctxt,
        qop.as_mut_ptr() as *const u8,
        curlx_uztoui(unsafe { strlen(qop.as_mut_ptr()) }),
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
        (unsafe { curl_msnprintf(
            &mut *resp_hash_hex
                .as_mut_ptr()
                .offset((2 as i32 as u64).wrapping_mul(i) as isize) as *mut i8,
            3 as i32 as size_t,
            b"%02x\0" as *const u8 as *const i8,
            digest[i as usize] as i32,
        ) });
        i = i.wrapping_add(1);
    }
    response = unsafe { curl_maprintf (b"username=\"%s\",realm=\"%s\",nonce=\"%s\",cnonce=\"%s\",nc=\"%s\",digest-uri=\"%s\",response=%s,qop=%s\0" as * const u8 as * const i8 , userp , realm . as_mut_ptr () , nonce . as_mut_ptr () , cnonce . as_mut_ptr () , nonceCount . as_mut_ptr () , spn , resp_hash_hex . as_mut_ptr () , qop . as_mut_ptr () ,) } ;
    (unsafe { Curl_cfree.expect("non-null function pointer")(spn as *mut libc::c_void) });
    if response.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    Curl_bufref_set(
        borrow_mut(&mut out),
        response as *const libc::c_void,
        unsafe { strlen(response) },
        Some(curl_free),
    );
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_auth_decode_digest_http_message<'a1>(
    mut chlg: *const i8,
    mut digest: Option<&'a1 mut crate::src::lib::http2::digestdata>,
) -> u32 {
    let mut before: bool = 0 as i32 != 0;
    let mut foundAuth: bool = 0 as i32 != 0;
    let mut foundAuthInt: bool = 0 as i32 != 0;
    let mut token: *mut i8 = 0 as *mut i8;
    let mut tmp: *mut i8 = 0 as *mut i8;
    if !((*(borrow_mut(&mut digest)).unwrap()).nonce).is_null() {
        before = 1 as i32 != 0;
    }
    Curl_auth_digest_cleanup(borrow_mut(&mut digest));
    loop {
        let mut value: [i8; 256] = [0; 256];
        let mut content: [i8; 1024] = [0; 1024];
        while (unsafe { *chlg }) as i32 != 0 && Curl_isspace((unsafe { *chlg }) as u8 as i32) != 0 {
            chlg = unsafe { chlg.offset(1) };
        }
        if !Curl_auth_digest_get_pair(
            chlg,
            value.as_mut_ptr(),
            content.as_mut_ptr(),
            Some(&mut chlg),
        ) {
            break;
        }
        if Curl_strcasecompare(value.as_mut_ptr(), b"nonce\0" as *const u8 as *const i8) != 0 {
            (unsafe { Curl_cfree.expect("non-null function pointer")(
                (*(borrow_mut(&mut digest)).unwrap()).nonce as *mut libc::c_void,
            ) });
            let mut fresh11 = &mut ((*(borrow_mut(&mut digest)).unwrap()).nonce);
            *fresh11 = unsafe { Curl_cstrdup.expect("non-null function pointer")(content.as_mut_ptr()) };
            if ((*(borrow(&digest)).unwrap()).nonce).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        } else if Curl_strcasecompare(value.as_mut_ptr(), b"stale\0" as *const u8 as *const i8) != 0
        {
            if Curl_strcasecompare(content.as_mut_ptr(), b"true\0" as *const u8 as *const i8) != 0 {
                (*(borrow_mut(&mut digest)).unwrap()).set_stale(1 as i32 as bit);
                (*(borrow_mut(&mut digest)).unwrap()).nc = 1 as i32;
            }
        } else if Curl_strcasecompare(value.as_mut_ptr(), b"realm\0" as *const u8 as *const i8) != 0
        {
            (unsafe { Curl_cfree.expect("non-null function pointer")(
                (*(borrow_mut(&mut digest)).unwrap()).realm as *mut libc::c_void,
            ) });
            let mut fresh12 = &mut ((*(borrow_mut(&mut digest)).unwrap()).realm);
            *fresh12 = unsafe { Curl_cstrdup.expect("non-null function pointer")(content.as_mut_ptr()) };
            if ((*(borrow(&digest)).unwrap()).realm).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        } else if Curl_strcasecompare(value.as_mut_ptr(), b"opaque\0" as *const u8 as *const i8)
            != 0
        {
            (unsafe { Curl_cfree.expect("non-null function pointer")(
                (*(borrow_mut(&mut digest)).unwrap()).opaque as *mut libc::c_void,
            ) });
            let mut fresh13 = &mut ((*(borrow_mut(&mut digest)).unwrap()).opaque);
            *fresh13 = unsafe { Curl_cstrdup.expect("non-null function pointer")(content.as_mut_ptr()) };
            if ((*(borrow(&digest)).unwrap()).opaque).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        } else if Curl_strcasecompare(value.as_mut_ptr(), b"qop\0" as *const u8 as *const i8) != 0 {
            let mut tok_buf: *mut i8 = 0 as *mut i8;
            tmp = unsafe { Curl_cstrdup.expect("non-null function pointer")(content.as_mut_ptr()) };
            if tmp.is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            token = unsafe { strtok_r(tmp, b",\0" as *const u8 as *const i8, &mut tok_buf) };
            while !token.is_null() {
                if Curl_strcasecompare(token, b"auth\0" as *const u8 as *const i8) != 0 {
                    foundAuth = 1 as i32 != 0;
                } else if Curl_strcasecompare(token, b"auth-int\0" as *const u8 as *const i8) != 0 {
                    foundAuthInt = 1 as i32 != 0;
                }
                token = unsafe { strtok_r(0 as *mut i8, b",\0" as *const u8 as *const i8, &mut tok_buf) };
            }
            (unsafe { Curl_cfree.expect("non-null function pointer")(tmp as *mut libc::c_void) });
            if foundAuth {
                (unsafe { Curl_cfree.expect("non-null function pointer")(
                    (*(borrow_mut(&mut digest)).unwrap()).qop as *mut libc::c_void,
                ) });
                let mut fresh14 = &mut ((*(borrow_mut(&mut digest)).unwrap()).qop);
                *fresh14 = unsafe { Curl_cstrdup.expect("non-null function pointer")(
                    b"auth\0" as *const u8 as *const i8,
                ) };
                if ((*(borrow(&digest)).unwrap()).qop).is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
            } else if foundAuthInt {
                (unsafe { Curl_cfree.expect("non-null function pointer")(
                    (*(borrow_mut(&mut digest)).unwrap()).qop as *mut libc::c_void,
                ) });
                let mut fresh15 = &mut ((*(borrow_mut(&mut digest)).unwrap()).qop);
                *fresh15 = unsafe { Curl_cstrdup.expect("non-null function pointer")(
                    b"auth-int\0" as *const u8 as *const i8,
                ) };
                if ((*(borrow(&digest)).unwrap()).qop).is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
            }
        } else if Curl_strcasecompare(value.as_mut_ptr(), b"algorithm\0" as *const u8 as *const i8)
            != 0
        {
            (unsafe { Curl_cfree.expect("non-null function pointer")(
                (*(borrow_mut(&mut digest)).unwrap()).algorithm as *mut libc::c_void,
            ) });
            let mut fresh16 = &mut ((*(borrow_mut(&mut digest)).unwrap()).algorithm);
            *fresh16 = unsafe { Curl_cstrdup.expect("non-null function pointer")(content.as_mut_ptr()) };
            if ((*(borrow_mut(&mut digest)).unwrap()).algorithm).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            if Curl_strcasecompare(
                content.as_mut_ptr(),
                b"MD5-sess\0" as *const u8 as *const i8,
            ) != 0
            {
                (*(borrow_mut(&mut digest)).unwrap()).algo = CURLDIGESTALGO_MD5SESS as i32;
            } else if Curl_strcasecompare(content.as_mut_ptr(), b"MD5\0" as *const u8 as *const i8)
                != 0
            {
                (*(borrow_mut(&mut digest)).unwrap()).algo = CURLDIGESTALGO_MD5 as i32;
            } else if Curl_strcasecompare(
                content.as_mut_ptr(),
                b"SHA-256\0" as *const u8 as *const i8,
            ) != 0
            {
                (*(borrow_mut(&mut digest)).unwrap()).algo = CURLDIGESTALGO_SHA256 as i32;
            } else if Curl_strcasecompare(
                content.as_mut_ptr(),
                b"SHA-256-SESS\0" as *const u8 as *const i8,
            ) != 0
            {
                (*(borrow_mut(&mut digest)).unwrap()).algo = CURLDIGESTALGO_SHA256SESS as i32;
            } else if Curl_strcasecompare(
                content.as_mut_ptr(),
                b"SHA-512-256\0" as *const u8 as *const i8,
            ) != 0
            {
                (*(borrow_mut(&mut digest)).unwrap()).algo = CURLDIGESTALGO_SHA512_256 as i32;
            } else if Curl_strcasecompare(
                content.as_mut_ptr(),
                b"SHA-512-256-SESS\0" as *const u8 as *const i8,
            ) != 0
            {
                (*(borrow_mut(&mut digest)).unwrap()).algo = CURLDIGESTALGO_SHA512_256SESS as i32;
            } else {
                return CURLE_BAD_CONTENT_ENCODING;
            }
        } else if Curl_strcasecompare(value.as_mut_ptr(), b"userhash\0" as *const u8 as *const i8)
            != 0
        {
            if Curl_strcasecompare(content.as_mut_ptr(), b"true\0" as *const u8 as *const i8) != 0 {
                (*(borrow_mut(&mut digest)).unwrap()).set_userhash(1 as i32 as bit);
            }
        }
        while (unsafe { *chlg }) as i32 != 0 && Curl_isspace((unsafe { *chlg }) as u8 as i32) != 0 {
            chlg = unsafe { chlg.offset(1) };
        }
        if ',' as i32 == (unsafe { *chlg }) as i32 {
            chlg = unsafe { chlg.offset(1) };
        }
    }
    if before as i32 != 0 && (*(borrow(&digest)).unwrap()).stale() == 0 {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    if ((*(borrow_mut(&mut digest)).unwrap()).nonce).is_null() {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    return CURLE_OK;
}
extern "C" fn auth_create_digest_http_message<'a1, 'a2, 'a3>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut userp: *const i8,
    mut passwdp: *const i8,
    mut request: *const u8,
    mut uripath: *const u8,
    mut digest: Option<&'a1 mut crate::src::lib::http2::digestdata>,
    mut outptr: Option<&'a2 mut *mut i8>,
    mut outlen: Option<&'a3 mut u64>,
    mut convert_to_ascii: Option<unsafe extern "C" fn(_: *mut u8, _: *mut u8) -> ()>,
    mut hash: Option<unsafe extern "C" fn(_: *mut u8, _: *const u8, _: u64) -> ()>,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut hashbuf: [u8; 32] = [0; 32];
    let mut request_digest: [u8; 65] = [0; 65];
    let mut ha1: [u8; 65] = [0; 65];
    let mut ha2: [u8; 65] = [0; 65];
    let mut userh: [i8; 65] = [0; 65];
    let mut cnonce: *mut i8 = 0 as *mut i8;
    let mut cnonce_sz: u64 = 0 as i32 as size_t;
    let mut userp_quoted: *mut i8 = 0 as *mut i8;
    let mut response: *mut i8 = 0 as *mut i8;
    let mut hashthis: *mut i8 = 0 as *mut i8;
    let mut tmp: *mut i8 = 0 as *mut i8;
    if (*(borrow(&digest)).unwrap()).nc == 0 {
        (*(borrow_mut(&mut digest)).unwrap()).nc = 1 as i32;
    }
    if ((*(borrow_mut(&mut digest)).unwrap()).cnonce).is_null() {
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
            unsafe { strlen(cnoncebuf.as_mut_ptr()) },
            Some(&mut cnonce),
            Some(&mut cnonce_sz),
        );
        if result as u64 != 0 {
            return result;
        }
        let mut fresh17 = &mut ((*(borrow_mut(&mut digest)).unwrap()).cnonce);
        *fresh17 = cnonce;
    }
    if (*(borrow(&digest)).unwrap()).userhash() != 0 {
        hashthis = unsafe { curl_maprintf(
            b"%s:%s\0" as *const u8 as *const i8,
            userp,
            (*(borrow(&digest)).unwrap()).realm,
        ) };
        if hashthis.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        result = CURLE_OK as i32 as CURLcode;
        if result as u64 != 0 {
            (unsafe { Curl_cfree.expect("non-null function pointer")(hashthis as *mut libc::c_void) });
            return result;
        }
        (unsafe { hash.expect("non-null function pointer")(
            hashbuf.as_mut_ptr(),
            hashthis as *mut u8,
            strlen(hashthis),
        ) });
        (unsafe { Curl_cfree.expect("non-null function pointer")(hashthis as *mut libc::c_void) });
        (unsafe { convert_to_ascii.expect("non-null function pointer")(
            hashbuf.as_mut_ptr(),
            userh.as_mut_ptr() as *mut u8,
        ) });
    }
    hashthis = unsafe { curl_maprintf(
        b"%s:%s:%s\0" as *const u8 as *const i8,
        if (*(borrow(&digest)).unwrap()).userhash() as i32 != 0 {
            userh.as_mut_ptr() as *const i8
        } else {
            userp
        },
        (*(borrow(&digest)).unwrap()).realm,
        passwdp,
    ) };
    if hashthis.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    result = CURLE_OK as i32 as CURLcode;
    if result as u64 != 0 {
        (unsafe { Curl_cfree.expect("non-null function pointer")(hashthis as *mut libc::c_void) });
        return result;
    }
    (unsafe { hash.expect("non-null function pointer")(
        hashbuf.as_mut_ptr(),
        hashthis as *mut u8,
        strlen(hashthis),
    ) });
    (unsafe { Curl_cfree.expect("non-null function pointer")(hashthis as *mut libc::c_void) });
    (unsafe { convert_to_ascii.expect("non-null function pointer")(hashbuf.as_mut_ptr(), ha1.as_mut_ptr()) });
    if (*(borrow(&digest)).unwrap()).algo == CURLDIGESTALGO_MD5SESS as i32
        || (*(borrow(&digest)).unwrap()).algo == CURLDIGESTALGO_SHA256SESS as i32
        || (*(borrow(&digest)).unwrap()).algo == CURLDIGESTALGO_SHA512_256SESS as i32
    {
        tmp = unsafe { curl_maprintf(
            b"%s:%s:%s\0" as *const u8 as *const i8,
            ha1.as_mut_ptr(),
            (*(borrow(&digest)).unwrap()).nonce,
            (*(borrow(&digest)).unwrap()).cnonce,
        ) };
        if tmp.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        result = CURLE_OK as i32 as CURLcode;
        if result as u64 != 0 {
            (unsafe { Curl_cfree.expect("non-null function pointer")(tmp as *mut libc::c_void) });
            return result;
        }
        (unsafe { hash.expect("non-null function pointer")(hashbuf.as_mut_ptr(), tmp as *mut u8, strlen(tmp)) });
        (unsafe { Curl_cfree.expect("non-null function pointer")(tmp as *mut libc::c_void) });
        (unsafe { convert_to_ascii.expect("non-null function pointer")(
            hashbuf.as_mut_ptr(),
            ha1.as_mut_ptr(),
        ) });
    }
    hashthis = unsafe { curl_maprintf(b"%s:%s\0" as *const u8 as *const i8, request, uripath) };
    if hashthis.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if !((*(borrow(&digest)).unwrap()).qop).is_null()
        && Curl_strcasecompare(
            (*(borrow(&digest)).unwrap()).qop,
            b"auth-int\0" as *const u8 as *const i8,
        ) != 0
    {
        let mut hashed: [i8; 65] = [0; 65];
        let mut hashthis2: *mut i8 = 0 as *mut i8;
        (unsafe { hash.expect("non-null function pointer")(
            hashbuf.as_mut_ptr(),
            b"\0" as *const u8 as *const i8 as *const u8,
            0 as i32 as size_t,
        ) });
        (unsafe { convert_to_ascii.expect("non-null function pointer")(
            hashbuf.as_mut_ptr(),
            hashed.as_mut_ptr() as *mut u8,
        ) });
        hashthis2 = unsafe { curl_maprintf(
            b"%s:%s\0" as *const u8 as *const i8,
            hashthis,
            hashed.as_mut_ptr(),
        ) };
        (unsafe { Curl_cfree.expect("non-null function pointer")(hashthis as *mut libc::c_void) });
        hashthis = hashthis2;
    }
    if hashthis.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    result = CURLE_OK as i32 as CURLcode;
    if result as u64 != 0 {
        (unsafe { Curl_cfree.expect("non-null function pointer")(hashthis as *mut libc::c_void) });
        return result;
    }
    (unsafe { hash.expect("non-null function pointer")(
        hashbuf.as_mut_ptr(),
        hashthis as *mut u8,
        strlen(hashthis),
    ) });
    (unsafe { Curl_cfree.expect("non-null function pointer")(hashthis as *mut libc::c_void) });
    (unsafe { convert_to_ascii.expect("non-null function pointer")(hashbuf.as_mut_ptr(), ha2.as_mut_ptr()) });
    if !((*(borrow_mut(&mut digest)).unwrap()).qop).is_null() {
        hashthis = unsafe { curl_maprintf(
            b"%s:%s:%08x:%s:%s:%s\0" as *const u8 as *const i8,
            ha1.as_mut_ptr(),
            (*(borrow(&digest)).unwrap()).nonce,
            (*(borrow(&digest)).unwrap()).nc,
            (*(borrow(&digest)).unwrap()).cnonce,
            (*(borrow(&digest)).unwrap()).qop,
            ha2.as_mut_ptr(),
        ) };
    } else {
        hashthis = unsafe { curl_maprintf(
            b"%s:%s:%s\0" as *const u8 as *const i8,
            ha1.as_mut_ptr(),
            (*(borrow(&digest)).unwrap()).nonce,
            ha2.as_mut_ptr(),
        ) };
    }
    if hashthis.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    result = CURLE_OK as i32 as CURLcode;
    if result as u64 != 0 {
        (unsafe { Curl_cfree.expect("non-null function pointer")(hashthis as *mut libc::c_void) });
        return result;
    }
    (unsafe { hash.expect("non-null function pointer")(
        hashbuf.as_mut_ptr(),
        hashthis as *mut u8,
        strlen(hashthis),
    ) });
    (unsafe { Curl_cfree.expect("non-null function pointer")(hashthis as *mut libc::c_void) });
    (unsafe { convert_to_ascii.expect("non-null function pointer")(
        hashbuf.as_mut_ptr(),
        request_digest.as_mut_ptr(),
    ) });
    userp_quoted =
        auth_digest_string_quoted(if (*(borrow(&digest)).unwrap()).userhash() as i32 != 0 {
            userh.as_mut_ptr() as *const i8
        } else {
            userp
        });
    if userp_quoted.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if !((*(borrow(&digest)).unwrap()).qop).is_null() {
        response = unsafe { curl_maprintf (b"username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", cnonce=\"%s\", nc=%08x, qop=%s, response=\"%s\"\0" as * const u8 as * const i8 , userp_quoted , (* (borrow (& digest)) . unwrap ()) . realm , (* (borrow (& digest)) . unwrap ()) . nonce , uripath , (* (borrow (& digest)) . unwrap ()) . cnonce , (* (borrow (& digest)) . unwrap ()) . nc , (* (borrow (& digest)) . unwrap ()) . qop , request_digest . as_mut_ptr () ,) } ;
        if Curl_strcasecompare(
            (*(borrow(&digest)).unwrap()).qop,
            b"auth\0" as *const u8 as *const i8,
        ) != 0
        {
            let mut fresh18 = &mut ((*(borrow_mut(&mut digest)).unwrap()).nc);
            *fresh18 += 1;
        }
    } else {
        response = unsafe { curl_maprintf(
            b"username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"\0"
                as *const u8 as *const i8,
            userp_quoted,
            (*(borrow(&digest)).unwrap()).realm,
            (*(borrow(&digest)).unwrap()).nonce,
            uripath,
            request_digest.as_mut_ptr(),
        ) };
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")(userp_quoted as *mut libc::c_void) });
    if response.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if !((*(borrow_mut(&mut digest)).unwrap()).opaque).is_null() {
        tmp = unsafe { curl_maprintf(
            b"%s, opaque=\"%s\"\0" as *const u8 as *const i8,
            response,
            (*(borrow(&digest)).unwrap()).opaque,
        ) };
        (unsafe { Curl_cfree.expect("non-null function pointer")(response as *mut libc::c_void) });
        if tmp.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        response = tmp;
    }
    if !((*(borrow_mut(&mut digest)).unwrap()).algorithm).is_null() {
        tmp = unsafe { curl_maprintf(
            b"%s, algorithm=%s\0" as *const u8 as *const i8,
            response,
            (*(borrow(&digest)).unwrap()).algorithm,
        ) };
        (unsafe { Curl_cfree.expect("non-null function pointer")(response as *mut libc::c_void) });
        if tmp.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        response = tmp;
    }
    if (*(borrow(&digest)).unwrap()).userhash() != 0 {
        tmp = unsafe { curl_maprintf(b"%s, userhash=true\0" as *const u8 as *const i8, response) };
        (unsafe { Curl_cfree.expect("non-null function pointer")(response as *mut libc::c_void) });
        if tmp.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        response = tmp;
    }
    *(borrow_mut(&mut outptr)).unwrap() = response;
    *(borrow_mut(&mut outlen)).unwrap() = unsafe { strlen(response) };
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_auth_create_digest_http_message<'a1, 'a2, 'a3>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut userp: *const i8,
    mut passwdp: *const i8,
    mut request: *const u8,
    mut uripath: *const u8,
    mut digest: Option<&'a1 mut crate::src::lib::http2::digestdata>,
    mut outptr: Option<&'a2 mut *mut i8>,
    mut outlen: Option<&'a3 mut u64>,
) -> u32 {
    match (*(borrow(&digest)).unwrap()).algo {
        0 | 1 => {
            return auth_create_digest_http_message(
                data,
                userp,
                passwdp,
                request,
                uripath,
                borrow_mut(&mut digest),
                borrow_mut(&mut outptr),
                borrow_mut(&mut outlen),
                Some(auth_digest_md5_to_ascii),
                Some(Curl_md5it),
            );
        }
        2 | 3 | 4 | 5 => {
            return auth_create_digest_http_message(
                data,
                userp,
                passwdp,
                request,
                uripath,
                borrow_mut(&mut digest),
                borrow_mut(&mut outptr),
                borrow_mut(&mut outlen),
                Some(auth_digest_sha256_to_ascii),
                Some(Curl_sha256it),
            );
        }
        _ => return CURLE_UNSUPPORTED_PROTOCOL,
    };
}
#[no_mangle]
pub extern "C" fn Curl_auth_digest_cleanup<'a1>(
    mut digest: Option<&'a1 mut crate::src::lib::http2::digestdata>,
) {
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut digest)).unwrap()).nonce as *mut libc::c_void,
    ) });
    let mut fresh19 = &mut ((*(borrow_mut(&mut digest)).unwrap()).nonce);
    *fresh19 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut digest)).unwrap()).cnonce as *mut libc::c_void,
    ) });
    let mut fresh20 = &mut ((*(borrow_mut(&mut digest)).unwrap()).cnonce);
    *fresh20 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut digest)).unwrap()).realm as *mut libc::c_void,
    ) });
    let mut fresh21 = &mut ((*(borrow_mut(&mut digest)).unwrap()).realm);
    *fresh21 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut digest)).unwrap()).opaque as *mut libc::c_void,
    ) });
    let mut fresh22 = &mut ((*(borrow_mut(&mut digest)).unwrap()).opaque);
    *fresh22 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut digest)).unwrap()).qop as *mut libc::c_void,
    ) });
    let mut fresh23 = &mut ((*(borrow_mut(&mut digest)).unwrap()).qop);
    *fresh23 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(borrow_mut(&mut digest)).unwrap()).algorithm as *mut libc::c_void,
    ) });
    let mut fresh24 = &mut ((*(borrow_mut(&mut digest)).unwrap()).algorithm);
    *fresh24 = 0 as *mut i8;
    (*(borrow_mut(&mut digest)).unwrap()).nc = 0 as i32;
    (*(borrow_mut(&mut digest)).unwrap()).algo = CURLDIGESTALGO_MD5 as i32;
    (*(borrow_mut(&mut digest)).unwrap()).set_stale(0 as i32 as bit);
    (*(borrow_mut(&mut digest)).unwrap()).set_userhash(0 as i32 as bit);
}
use crate::laertes_rt::*;
