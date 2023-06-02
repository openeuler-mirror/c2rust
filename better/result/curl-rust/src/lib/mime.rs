
use :: libc;
extern "C" {
    fn memmove(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn fclose(__stream: *mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut crate::src::lib::http2::_IO_FILE;
    fn fread(
        _: *mut core::ffi::c_void,
        _: u64,
        _: u64,
        _: *mut crate::src::lib::http2::_IO_FILE,
    ) -> u64;
    fn fseek(__stream: *mut crate::src::lib::http2::_IO_FILE, __off: i64, __whence: i32) -> i32;
    fn feof(__stream: *mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn access(__name: *const i8, __type: i32) -> i32;
    fn __xstat(
        __ver: i32,
        __filename: *const i8,
        __stat_buf: *mut crate::src::lib::file::stat,
    ) -> i32;
    fn memset(_: *mut core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn __xpg_basename(__path: *mut i8) -> *mut i8;
}
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_cstrdup;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::mprintf::curl_mvaprintf;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::rand::Curl_rand_hex;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::slist::curl_slist_free_all;
pub use crate::src::lib::slist::Curl_slist_append_nodup;
pub use crate::src::lib::slist::Curl_slist_duplicate;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::strcase::curl_strequal;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::strcase::Curl_strncasecompare;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
pub use crate::src::lib::warnless::curlx_sotouz;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub type __builtin_va_list = [crate::src::lib::dict::__va_list_tag; 1];
pub type __va_list_tag = crate::src::lib::dict::__va_list_tag;
pub type __uint8_t = u8;
pub type __int32_t = i32;
pub type __uint32_t = u32;
pub type __dev_t = u64;
pub type __uid_t = u32;
pub type __gid_t = u32;
pub type __ino_t = u64;
pub type __mode_t = u32;
pub type __nlink_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __pid_t = i32;
pub type __time_t = i64;
pub type __blksize_t = i64;
pub type __blkcnt_t = i64;
pub type __ssize_t = i64;
pub type __syscall_slong_t = i64;
pub type __socklen_t = u32;
pub type pid_t = i32;
pub type ssize_t = i64;
pub type time_t = i64;
pub type size_t = u64;
pub type int32_t = i32;
pub type timespec = crate::src::lib::file::timespec;
pub type socklen_t = u32;
pub type sa_family_t = u16;
pub type sockaddr = crate::src::lib::http2::sockaddr;
pub type curl_socklen_t = u32;
pub type curl_off_t = i64;
pub type va_list = [crate::src::lib::dict::__va_list_tag; 1];
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
pub type stat = crate::src::lib::file::stat;
pub type mimestrategy = u32;
pub const MIMESTRATEGY_LAST: mimestrategy = 2;
pub const MIMESTRATEGY_FORM: mimestrategy = 1;
pub const MIMESTRATEGY_MAIL: mimestrategy = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ContentType {
    pub extension: *const i8,
    pub type_0: *const i8,
}
impl ContentType {
    pub const fn new() -> Self {
        ContentType {
            extension: (0 as *const i8),
            type_0: (0 as *const i8),
        }
    }
}
impl std::default::Default for ContentType {
    fn default() -> Self {
        ContentType::new()
    }
}
#[inline]
extern "C" fn stat(mut __path: *const i8, mut __statbuf: *mut crate::src::lib::file::stat) -> i32 {
    return unsafe { __xstat(1 as i32, __path, __statbuf) };
}
static mut encoders: [crate::src::lib::http2::mime_encoder; 6] =  {
    [
        {
            let mut init = mime_encoder {
                name: b"binary\0" as *const u8 as *const i8,
                encodefunc: Some(encoder_nop_read),
                sizefunc: Some(encoder_nop_size),
            };
            init
        },
        {
            let mut init = mime_encoder {
                name: b"8bit\0" as *const u8 as *const i8,
                encodefunc: Some(encoder_nop_read),
                sizefunc: Some(encoder_nop_size),
            };
            init
        },
        {
            let mut init = mime_encoder {
                name: b"7bit\0" as *const u8 as *const i8,
                encodefunc: Some(encoder_7bit_read),
                sizefunc: Some(encoder_nop_size),
            };
            init
        },
        {
            let mut init = mime_encoder {
                name: b"base64\0" as *const u8 as *const i8,
                encodefunc: Some(encoder_base64_read),
                sizefunc: Some(encoder_base64_size),
            };
            init
        },
        {
            let mut init = mime_encoder {
                name: b"quoted-printable\0" as *const u8 as *const i8,
                encodefunc: Some(encoder_qp_read),
                sizefunc: Some(encoder_qp_size),
            };
            init
        },
        {
            let mut init = mime_encoder {
                name: 0 as *const i8,
                encodefunc: None,
                sizefunc: None,
            };
            init
        },
    ]
};
static mut base64: [i8; 65] = unsafe {
    *core::intrinsics::transmute::<&'_ [u8; 65], &'_ [i8; 65]>(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\0",
    )
};
static mut qp_class: [u8; 256] = [
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    2 as i32 as u8,
    4 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    3 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    2 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    0 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    1 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
];
static mut aschex: [i8; 17] =
    unsafe { *core::intrinsics::transmute::<&'_ [u8; 17], &'_ [i8; 17]>(b"0123456789ABCDEF\0") };
extern "C" fn mimesetstate<'a1>(
    mut state: Option<&'a1 mut crate::src::lib::http2::mime_state>,
    mut tok: u32,
    mut ptr: *mut core::ffi::c_void,
) {
    (*(borrow_mut(&mut state)).unwrap()).state = tok;
    let mut fresh0 = &mut ((*(borrow_mut(&mut state)).unwrap()).ptr);
    *fresh0 = ptr;
    (*(borrow_mut(&mut state)).unwrap()).offset = 0 as i32 as curl_off_t;
}
extern "C" fn escape_string(mut src: *const i8) -> *mut i8 {
    let mut bytecount: u64 = 0 as i32 as size_t;
    let mut i: u64 = 0;
    let mut dst: *mut i8 = 0 as *mut i8;
    i = 0 as i32 as size_t;
    while (unsafe { *src.offset(i as isize) }) != 0 {
        if (unsafe { *src.offset(i as isize) }) as i32 == '"' as i32
            || (unsafe { *src.offset(i as isize) }) as i32 == '\\' as i32
        {
            bytecount = bytecount.wrapping_add(1);
        }
        i = i.wrapping_add(1);
    }
    bytecount = (bytecount as u64).wrapping_add(i) as size_t as size_t;
    dst = (unsafe { Curl_cmalloc.expect("non-null function pointer")(bytecount.wrapping_add(1 as i32 as u64)) })
        as *mut i8;
    if dst.is_null() {
        return 0 as *mut i8;
    }
    i = 0 as i32 as size_t;
    while (unsafe { *src }) != 0 {
        if (unsafe { *src }) as i32 == '"' as i32 || (unsafe { *src }) as i32 == '\\' as i32 {
            let mut fresh1 = i;
            i = i.wrapping_add(1);
            (unsafe { *dst.offset(fresh1 as isize) = '\\' as i32 as i8 });
        }
        let mut fresh2 = i;
        i = i.wrapping_add(1);
        (unsafe { *dst.offset(fresh2 as isize) = *src });
        src = unsafe { src.offset(1) };
    }
    (unsafe { *dst.offset(i as isize) = '\u{0}' as i32 as i8 });
    return dst;
}
extern "C" fn match_header(
    mut hdr: *mut crate::src::lib::http2::curl_slist,
    mut lbl: *const i8,
    mut len: u64,
) -> *mut i8 {
    let mut value: *mut i8 = 0 as *mut i8;
    if Curl_strncasecompare(unsafe { (*hdr).data }, lbl, len) != 0
        && (unsafe { *((*hdr).data).offset(len as isize) }) as i32 == ':' as i32
    {
        value = unsafe { ((*hdr).data).offset(len as isize).offset(1 as i32 as isize) };
        while (unsafe { *value }) as i32 == ' ' as i32 {
            value = unsafe { value.offset(1) };
        }
    }
    return value;
}
extern "C" fn search_header(
    mut hdrlist: *mut crate::src::lib::http2::curl_slist,
    mut hdr: *const i8,
) -> *mut i8 {
    let mut len: u64 = unsafe { strlen(hdr) };
    let mut value: *mut i8 = 0 as *mut i8;
    while value.is_null() && !hdrlist.is_null() {
        value = match_header(hdrlist, hdr, len);
        hdrlist = unsafe { (*hdrlist).next };
    }
    return value;
}
extern "C" fn strippath(mut fullfile: *const i8) -> *mut i8 {
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut base: *mut i8 = 0 as *mut i8;
    filename = unsafe { Curl_cstrdup.expect("non-null function pointer")(fullfile) };
    if filename.is_null() {
        return 0 as *mut i8;
    }
    base = unsafe { Curl_cstrdup.expect("non-null function pointer")(__xpg_basename(filename)) };
    (unsafe { Curl_cfree.expect("non-null function pointer")(filename as *mut libc::c_void) });
    return base;
}
extern "C" fn cleanup_encoder_state<'a1>(
    mut p: Option<&'a1 mut crate::src::lib::http2::mime_encoder_state>,
) {
    (*(borrow_mut(&mut p)).unwrap()).pos = 0 as i32 as size_t;
    (*(borrow_mut(&mut p)).unwrap()).bufbeg = 0 as i32 as size_t;
    (*(borrow_mut(&mut p)).unwrap()).bufend = 0 as i32 as size_t;
}
extern "C" fn encoder_nop_read(
    mut buffer: *mut i8,
    mut size: u64,
    mut _ateof: bool,
    mut part: *mut crate::src::lib::http2::curl_mimepart,
) -> u64 {
    let mut st: Option<&'_ mut crate::src::lib::http2::mime_encoder_state> =
        Some(unsafe { &mut (*part).encstate });
    let mut insize: u64 =
        ((*(borrow(&st)).unwrap()).bufend).wrapping_sub((*(borrow(&st)).unwrap()).bufbeg);
    if size == 0 {
        return -(2 as i32) as size_t;
    }
    if size > insize {
        size = insize;
    }
    if size != 0 {
        (unsafe { memcpy(
            buffer as *mut libc::c_void,
            ((*(borrow_mut(&mut st)).unwrap()).buf)
                .as_mut_ptr()
                .offset((*(borrow(&st)).unwrap()).bufbeg as isize)
                as *const libc::c_void,
            size,
        ) });
    }
    let mut fresh3 = &mut ((*(borrow_mut(&mut st)).unwrap()).bufbeg);
    *fresh3 = (*fresh3 as u64).wrapping_add(size) as size_t as size_t;
    return size;
}
extern "C" fn encoder_nop_size(mut part: *mut crate::src::lib::http2::curl_mimepart) -> i64 {
    return unsafe { (*part).datasize };
}
extern "C" fn encoder_7bit_read(
    mut buffer: *mut i8,
    mut size: u64,
    mut _ateof: bool,
    mut part: *mut crate::src::lib::http2::curl_mimepart,
) -> u64 {
    let mut st: *mut crate::src::lib::http2::mime_encoder_state = unsafe { &mut (*part).encstate };
    let mut cursize: u64 = (unsafe { (*st).bufend }).wrapping_sub(unsafe { (*st).bufbeg });
    if size == 0 {
        return -(2 as i32) as size_t;
    }
    if size > cursize {
        size = cursize;
    }
    cursize = 0 as i32 as size_t;
    while cursize < size {
        (unsafe { *buffer = (*st).buf[(*st).bufbeg as usize] });
        let mut fresh4 = buffer;
        buffer = unsafe { buffer.offset(1) };
        if (unsafe { *fresh4 }) as i32 & 0x80 as i32 != 0 {
            return if cursize != 0 {
                cursize
            } else {
                -(1 as i32) as size_t
            };
        }
        let mut fresh5 = unsafe { &mut ((*st).bufbeg) };
        *fresh5 = (*fresh5).wrapping_add(1);
        cursize = cursize.wrapping_add(1);
    }
    return cursize;
}
extern "C" fn encoder_base64_read(
    mut buffer: *mut i8,
    mut size: u64,
    mut ateof: bool,
    mut part: *mut crate::src::lib::http2::curl_mimepart,
) -> u64 {
    let mut st: Option<&'_ mut crate::src::lib::http2::mime_encoder_state> =
        Some(unsafe { &mut (*part).encstate });
    let mut cursize: u64 = 0 as i32 as size_t;
    let mut i: i32 = 0;
    let mut ptr: *mut i8 = buffer;
    while (*(borrow(&st)).unwrap()).bufbeg < (*(borrow(&st)).unwrap()).bufend {
        if (*(borrow(&st)).unwrap()).pos > (76 as i32 - 4 as i32) as u64 {
            if size < 2 as i32 as u64 {
                if cursize == 0 {
                    return -(2 as i32) as size_t;
                }
                break;
            } else {
                let mut fresh6 = ptr;
                ptr = unsafe { ptr.offset(1) };
                (unsafe { *fresh6 = '\r' as i32 as i8 });
                let mut fresh7 = ptr;
                ptr = unsafe { ptr.offset(1) };
                (unsafe { *fresh7 = '\n' as i32 as i8 });
                (*(borrow_mut(&mut st)).unwrap()).pos = 0 as i32 as size_t;
                cursize = (cursize as u64).wrapping_add(2 as i32 as u64) as size_t as size_t;
                size = (size as u64).wrapping_sub(2 as i32 as u64) as size_t as size_t;
            }
        }
        if size < 4 as i32 as u64 {
            if cursize == 0 {
                return -(2 as i32) as size_t;
            }
            break;
        } else {
            if ((*(borrow(&st)).unwrap()).bufend).wrapping_sub((*(borrow(&st)).unwrap()).bufbeg)
                < 3 as i32 as u64
            {
                break;
            }
            let mut fresh8 = &mut ((*(borrow_mut(&mut st)).unwrap()).bufbeg);
            let mut fresh9 = *fresh8;
            *fresh8 = (*fresh8).wrapping_add(1);
            i = (*(borrow(&st)).unwrap()).buf[fresh9 as usize] as i32 & 0xff as i32;
            let mut fresh10 = &mut ((*(borrow_mut(&mut st)).unwrap()).bufbeg);
            let mut fresh11 = *fresh10;
            *fresh10 = (*fresh10).wrapping_add(1);
            i = i << 8 as i32
                | (*(borrow(&st)).unwrap()).buf[fresh11 as usize] as i32 & 0xff as i32;
            let mut fresh12 = &mut ((*(borrow_mut(&mut st)).unwrap()).bufbeg);
            let mut fresh13 = *fresh12;
            *fresh12 = (*fresh12).wrapping_add(1);
            i = i << 8 as i32
                | (*(borrow(&st)).unwrap()).buf[fresh13 as usize] as i32 & 0xff as i32;
            let mut fresh14 = ptr;
            ptr = unsafe { ptr.offset(1) };
            (unsafe { *fresh14 = base64[(i >> 18 as i32 & 0x3f as i32) as usize] });
            let mut fresh15 = ptr;
            ptr = unsafe { ptr.offset(1) };
            (unsafe { *fresh15 = base64[(i >> 12 as i32 & 0x3f as i32) as usize] });
            let mut fresh16 = ptr;
            ptr = unsafe { ptr.offset(1) };
            (unsafe { *fresh16 = base64[(i >> 6 as i32 & 0x3f as i32) as usize] });
            let mut fresh17 = ptr;
            ptr = unsafe { ptr.offset(1) };
            (unsafe { *fresh17 = base64[(i & 0x3f as i32) as usize] });
            cursize = (cursize as u64).wrapping_add(4 as i32 as u64) as size_t as size_t;
            let mut fresh18 = &mut ((*(borrow_mut(&mut st)).unwrap()).pos);
            *fresh18 = (*fresh18 as u64).wrapping_add(4 as i32 as u64) as size_t as size_t;
            size = (size as u64).wrapping_sub(4 as i32 as u64) as size_t as size_t;
        }
    }
    if ateof {
        if size < 4 as i32 as u64 {
            if cursize == 0 {
                return -(2 as i32) as size_t;
            }
        } else {
            let mut fresh19 = unsafe { &mut (*ptr.offset(3 as i32 as isize)) };
            *fresh19 = '=' as i32 as i8;
            (unsafe { *ptr.offset(2 as i32 as isize) = *fresh19 });
            i = 0 as i32;
            let mut current_block_34: u64;
            match ((*(borrow(&st)).unwrap()).bufend).wrapping_sub((*(borrow(&st)).unwrap()).bufbeg)
            {
                2 => {
                    i = ((*(borrow(&st)).unwrap()).buf
                        [((*(borrow(&st)).unwrap()).bufbeg).wrapping_add(1 as i32 as u64) as usize]
                        as i32
                        & 0xff as i32)
                        << 8 as i32;
                    current_block_34 = 5305163020872709587;
                }
                1 => {
                    current_block_34 = 5305163020872709587;
                }
                _ => {
                    current_block_34 = 3222590281903869779;
                }
            }
            match current_block_34 {
                5305163020872709587 => {
                    i |= ((*(borrow(&st)).unwrap()).buf[(*(borrow(&st)).unwrap()).bufbeg as usize]
                        as i32
                        & 0xff as i32)
                        << 16 as i32;
                    (unsafe { *ptr.offset(0 as i32 as isize) =
                        base64[(i >> 18 as i32 & 0x3f as i32) as usize] });
                    (unsafe { *ptr.offset(1 as i32 as isize) =
                        base64[(i >> 12 as i32 & 0x3f as i32) as usize] });
                    let mut fresh20 = &mut ((*(borrow_mut(&mut st)).unwrap()).bufbeg);
                    *fresh20 = (*fresh20).wrapping_add(1);
                    if *fresh20 != (*(borrow(&st)).unwrap()).bufend {
                        (unsafe { *ptr.offset(2 as i32 as isize) =
                            base64[(i >> 6 as i32 & 0x3f as i32) as usize] });
                        let mut fresh21 = &mut ((*(borrow_mut(&mut st)).unwrap()).bufbeg);
                        *fresh21 = (*fresh21).wrapping_add(1);
                    }
                    cursize = (cursize as u64).wrapping_add(4 as i32 as u64) as size_t as size_t;
                    let mut fresh22 = &mut ((*(borrow_mut(&mut st)).unwrap()).pos);
                    *fresh22 = (*fresh22 as u64).wrapping_add(4 as i32 as u64) as size_t as size_t;
                }
                _ => {}
            }
        }
    }
    return cursize;
}
extern "C" fn encoder_base64_size(mut part: *mut crate::src::lib::http2::curl_mimepart) -> i64 {
    let mut size: i64 = unsafe { (*part).datasize };
    if size <= 0 as i32 as i64 {
        return size;
    }
    size = 4 as i32 as i64 * (1 as i32 as i64 + (size - 1 as i32 as i64) / 3 as i32 as i64);
    return size + 2 as i32 as i64 * ((size - 1 as i32 as i64) / 76 as i32 as i64);
}
extern "C" fn qp_lookahead_eol(
    mut st: *mut crate::src::lib::http2::mime_encoder_state,
    mut ateof: i32,
    mut n: u64,
) -> i32 {
    n = (n as u64).wrapping_add(unsafe { (*st).bufbeg }) as size_t as size_t;
    if n >= (unsafe { (*st).bufend }) && ateof != 0 {
        return 1 as i32;
    }
    if n.wrapping_add(2 as i32 as u64) > (unsafe { (*st).bufend }) {
        return if ateof != 0 { 0 as i32 } else { -(1 as i32) };
    }
    if (unsafe { qp_class[((*st).buf[n as usize] as i32 & 0xff as i32) as usize] }) as i32 == 3 as i32
        && (unsafe { qp_class
            [((*st).buf[n.wrapping_add(1 as i32 as u64) as usize] as i32 & 0xff as i32) as usize] })
            as i32
            == 4 as i32
    {
        return 1 as i32;
    }
    return 0 as i32;
}
extern "C" fn encoder_qp_read(
    mut buffer: *mut i8,
    mut size: u64,
    mut ateof: bool,
    mut part: *mut crate::src::lib::http2::curl_mimepart,
) -> u64 {
    let mut st: *mut crate::src::lib::http2::mime_encoder_state = unsafe { &mut (*part).encstate };
    let mut ptr: *mut i8 = buffer;
    let mut cursize: u64 = 0 as i32 as size_t;
    let mut softlinebreak: i32 = 0;
    let mut buf: [i8; 4] = [0; 4];
    while (unsafe { (*st).bufbeg }) < (unsafe { (*st).bufend }) {
        let mut len: u64 = 1 as i32 as size_t;
        let mut consumed: u64 = 1 as i32 as size_t;
        let mut i: i32 = (unsafe { (*st).buf[(*st).bufbeg as usize] }) as i32;
        buf[0 as i32 as usize] = i as i8;
        buf[1 as i32 as usize] = unsafe { aschex[(i >> 4 as i32 & 0xf as i32) as usize] };
        buf[2 as i32 as usize] = unsafe { aschex[(i & 0xf as i32) as usize] };
        match (unsafe { qp_class[((*st).buf[(*st).bufbeg as usize] as i32 & 0xff as i32) as usize] }) as i32 {
            1 => {}
            2 => match qp_lookahead_eol(st, ateof as i32, 1 as i32 as size_t) {
                -1 => return cursize,
                0 => {}
                _ => {
                    buf[0 as i32 as usize] = '=' as i32 as i8;
                    len = 3 as i32 as size_t;
                }
            },
            3 => match qp_lookahead_eol(st, ateof as i32, 0 as i32 as size_t) {
                -1 => return cursize,
                1 => {
                    let mut fresh23 = len;
                    len = len.wrapping_add(1);
                    buf[fresh23 as usize] = '\n' as i32 as i8;
                    consumed = 2 as i32 as size_t;
                }
                _ => {
                    buf[0 as i32 as usize] = '=' as i32 as i8;
                    len = 3 as i32 as size_t;
                }
            },
            _ => {
                buf[0 as i32 as usize] = '=' as i32 as i8;
                len = 3 as i32 as size_t;
            }
        }
        if buf[len.wrapping_sub(1 as i32 as u64) as usize] as i32 != '\n' as i32 {
            softlinebreak = ((unsafe { (*st).pos }).wrapping_add(len) > 76 as i32 as u64) as i32;
            if softlinebreak == 0 && (unsafe { (*st).pos }).wrapping_add(len) == 76 as i32 as u64 {
                match qp_lookahead_eol(st, ateof as i32, consumed) {
                    -1 => return cursize,
                    0 => {
                        softlinebreak = 1 as i32;
                    }
                    _ => {}
                }
            }
            if softlinebreak != 0 {
                (unsafe { strcpy(buf.as_mut_ptr(), b"=\r\n\0" as *const u8 as *const i8) });
                len = 3 as i32 as size_t;
                consumed = 0 as i32 as size_t;
            }
        }
        if len > size {
            if cursize == 0 {
                return -(2 as i32) as size_t;
            }
            break;
        } else {
            (unsafe { memcpy(
                ptr as *mut libc::c_void,
                buf.as_mut_ptr() as *const libc::c_void,
                len,
            ) });
            cursize = (cursize as u64).wrapping_add(len) as size_t as size_t;
            ptr = unsafe { ptr.offset(len as isize) };
            size = (size as u64).wrapping_sub(len) as size_t as size_t;
            let mut fresh24 = unsafe { &mut ((*st).pos) };
            *fresh24 = (*fresh24 as u64).wrapping_add(len) as size_t as size_t;
            if buf[len.wrapping_sub(1 as i32 as u64) as usize] as i32 == '\n' as i32 {
                (unsafe { (*st).pos = 0 as i32 as size_t });
            }
            let mut fresh25 = unsafe { &mut ((*st).bufbeg) };
            *fresh25 = (*fresh25 as u64).wrapping_add(consumed) as size_t as size_t;
        }
    }
    return cursize;
}
extern "C" fn encoder_qp_size(mut part: *mut crate::src::lib::http2::curl_mimepart) -> i64 {
    return (if (unsafe { (*part).datasize }) != 0 {
        -(1 as i32)
    } else {
        0 as i32
    }) as curl_off_t;
}
extern "C" fn mime_mem_read(
    mut buffer: *mut i8,
    mut _size: u64,
    mut nitems: u64,
    mut instream: *mut core::ffi::c_void,
) -> u64 {
    let mut part: *mut crate::src::lib::http2::curl_mimepart = instream as *mut curl_mimepart;
    let mut sz: u64 = curlx_sotouz((unsafe { (*part).datasize }) - (unsafe { (*part).state.offset }));
    if nitems == 0 {
        return -(2 as i32) as size_t;
    }
    if sz > nitems {
        sz = nitems;
    }
    if sz != 0 {
        (unsafe { memcpy(
            buffer as *mut libc::c_void,
            ((*part).data).offset(curlx_sotouz((*part).state.offset) as isize)
                as *const libc::c_void,
            sz,
        ) });
    }
    return sz;
}
extern "C" fn mime_mem_seek(
    mut instream: *mut core::ffi::c_void,
    mut offset: i64,
    mut whence: i32,
) -> i32 {
    let mut part: *mut crate::src::lib::http2::curl_mimepart = instream as *mut curl_mimepart;
    match whence {
        1 => {
            offset += unsafe { (*part).state.offset };
        }
        2 => {
            offset += unsafe { (*part).datasize };
        }
        _ => {}
    }
    if offset < 0 as i32 as i64 || offset > (unsafe { (*part).datasize }) {
        return 1 as i32;
    }
    (unsafe { (*part).state.offset = offset });
    return 0 as i32;
}
extern "C" fn mime_mem_free(mut ptr: *mut core::ffi::c_void) {
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*(ptr as *mut curl_mimepart)).data as *mut libc::c_void,
    ) });
    let mut fresh26 = unsafe { &mut ((*(ptr as *mut curl_mimepart)).data) };
    *fresh26 = 0 as *mut i8;
}
extern "C" fn mime_open_file(mut part: *mut crate::src::lib::http2::curl_mimepart) -> i32 {
    if !(unsafe { (*part).fp }).is_null() {
        return 0 as i32;
    }
    let mut fresh27 = unsafe { &mut ((*part).fp) };
    *fresh27 = unsafe { fopen((*part).data, b"rb\0" as *const u8 as *const i8) };
    return if !(unsafe { (*part).fp }).is_null() {
        0 as i32
    } else {
        -(1 as i32)
    };
}
extern "C" fn mime_file_read(
    mut buffer: *mut i8,
    mut size: u64,
    mut nitems: u64,
    mut instream: *mut core::ffi::c_void,
) -> u64 {
    let mut part: *mut crate::src::lib::http2::curl_mimepart = instream as *mut curl_mimepart;
    if nitems == 0 {
        return -(2 as i32) as size_t;
    }
    if mime_open_file(part) != 0 {
        return -(1 as i32) as size_t;
    }
    return unsafe { fread(buffer as *mut libc::c_void, size, nitems, (*part).fp) };
}
extern "C" fn mime_file_seek(
    mut instream: *mut core::ffi::c_void,
    mut offset: i64,
    mut whence: i32,
) -> i32 {
    let mut part: *mut crate::src::lib::http2::curl_mimepart = instream as *mut curl_mimepart;
    if whence == 0 as i32 && offset == 0 && (unsafe { (*part).fp }).is_null() {
        return 0 as i32;
    }
    if mime_open_file(part) != 0 {
        return 1 as i32;
    }
    return if (unsafe { fseek((*part).fp, offset, whence) }) != 0 {
        2 as i32
    } else {
        0 as i32
    };
}
extern "C" fn mime_file_free(mut ptr: *mut core::ffi::c_void) {
    let mut part: *mut crate::src::lib::http2::curl_mimepart = ptr as *mut curl_mimepart;
    if !(unsafe { (*part).fp }).is_null() {
        (unsafe { fclose((*part).fp) });
        let mut fresh28 = unsafe { &mut ((*part).fp) };
        *fresh28 = 0 as *mut FILE;
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")((*part).data as *mut libc::c_void) });
    let mut fresh29 = unsafe { &mut ((*part).data) };
    *fresh29 = 0 as *mut i8;
    let mut fresh30 = unsafe { &mut ((*part).data) };
    *fresh30 = 0 as *mut i8;
}
extern "C" fn readback_bytes<'a1>(
    mut state: Option<&'a1 mut crate::src::lib::http2::mime_state>,
    mut buffer: *mut i8,
    mut bufsize: u64,
    mut bytes: *const i8,
    mut numbytes: u64,
    mut trail: *const i8,
) -> u64 {
    let mut sz: u64 = 0;
    let mut offset: u64 = curlx_sotouz((*(borrow_mut(&mut state)).unwrap()).offset);
    if numbytes > offset {
        sz = numbytes.wrapping_sub(offset);
        bytes = unsafe { bytes.offset(offset as isize) };
    } else {
        let mut tsz: u64 = unsafe { strlen(trail) };
        sz = offset.wrapping_sub(numbytes);
        if sz >= tsz {
            return 0 as i32 as size_t;
        }
        bytes = unsafe { trail.offset(sz as isize) };
        sz = tsz.wrapping_sub(sz);
    }
    if sz > bufsize {
        sz = bufsize;
    }
    (unsafe { memcpy(
        buffer as *mut libc::c_void,
        bytes as *const libc::c_void,
        sz,
    ) });
    let mut fresh31 = &mut ((*(borrow_mut(&mut state)).unwrap()).offset);
    *fresh31 = (*fresh31 as u64).wrapping_add(sz) as curl_off_t as curl_off_t;
    return sz;
}
extern "C" fn read_part_content<'a1>(
    mut part: *mut crate::src::lib::http2::curl_mimepart,
    mut buffer: *mut i8,
    mut bufsize: u64,
    mut hasread: Option<&'a1 mut bool>,
) -> u64 {
    let mut sz: u64 = 0 as i32 as size_t;
    match unsafe { (*part).lastreadstatus } {
        0 | 268435456 | 268435457 | 18446744073709551615 => return unsafe { (*part).lastreadstatus },
        _ => {}
    }
    if !((unsafe { (*part).datasize }) != -(1 as i32) as curl_off_t && (unsafe { (*part).state.offset }) >= (unsafe { (*part).datasize }))
    {
        let mut current_block_11: u64;
        match (unsafe { (*part).kind }) as u32 {
            4 => {
                sz = mime_subparts_read(
                    buffer,
                    1 as i32 as size_t,
                    bufsize,
                    unsafe { (*part).arg },
                    borrow_mut(&mut hasread),
                );
                current_block_11 = 5689001924483802034;
            }
            2 => {
                if !(unsafe { (*part).fp }).is_null() && (unsafe { feof((*part).fp) }) != 0 {
                    current_block_11 = 5689001924483802034;
                } else {
                    current_block_11 = 18189631580737178625;
                }
            }
            _ => {
                current_block_11 = 18189631580737178625;
            }
        }
        match current_block_11 {
            18189631580737178625 => {
                if unsafe { ((*part).readfunc).is_some() } {
                    if (unsafe { (*part).flags }) & ((1 as i32) << 2 as i32) as u32 == 0 {
                        if *(borrow(&hasread)).unwrap() {
                            return -(2 as i32) as size_t;
                        }
                        *(borrow_mut(&mut hasread)).unwrap() = 1 as i32 != 0;
                    }
                    sz = unsafe { ((*part).readfunc).expect("non-null function pointer")(
                        buffer,
                        1 as i32 as size_t,
                        bufsize,
                        (*part).arg,
                    ) };
                }
            }
            _ => {}
        }
    }
    match sz {
        18446744073709551614 => {}
        0 | 268435456 | 268435457 | 18446744073709551615 => {
            (unsafe { (*part).lastreadstatus = sz });
        }
        _ => {
            let mut fresh32 = unsafe { &mut ((*part).state.offset) };
            *fresh32 = (*fresh32 as u64).wrapping_add(sz) as curl_off_t as curl_off_t;
            (unsafe { (*part).lastreadstatus = sz });
        }
    }
    return sz;
}
extern "C" fn read_encoded_part_content<'a1>(
    mut part: *mut crate::src::lib::http2::curl_mimepart,
    mut buffer: *mut i8,
    mut bufsize: u64,
    mut hasread: Option<&'a1 mut bool>,
) -> u64 {
    let mut st: Option<&'_ mut crate::src::lib::http2::mime_encoder_state> =
        Some(unsafe { &mut (*part).encstate });
    let mut cursize: u64 = 0 as i32 as size_t;
    let mut sz: u64 = 0;
    let mut ateof: bool = 0 as i32 != 0;
    loop {
        if (*(borrow(&st)).unwrap()).bufbeg < (*(borrow(&st)).unwrap()).bufend || ateof as i32 != 0
        {
            sz = unsafe { ((*(*part).encoder).encodefunc).expect("non-null function pointer")(
                buffer, bufsize, ateof, part,
            ) };
            match sz {
                0 => {
                    if ateof {
                        return cursize;
                    }
                }
                18446744073709551615 | 18446744073709551614 => {
                    return if cursize != 0 { cursize } else { sz };
                }
                _ => {
                    cursize = (cursize as u64).wrapping_add(sz) as size_t as size_t;
                    buffer = unsafe { buffer.offset(sz as isize) };
                    bufsize = (bufsize as u64).wrapping_sub(sz) as size_t as size_t;
                    continue;
                }
            }
        }
        if (*(borrow(&st)).unwrap()).bufbeg != 0 {
            let mut len: u64 =
                ((*(borrow(&st)).unwrap()).bufend).wrapping_sub((*(borrow(&st)).unwrap()).bufbeg);
            if len != 0 {
                (unsafe { memmove(
                    ((*(borrow_mut(&mut st)).unwrap()).buf).as_mut_ptr() as *mut libc::c_void,
                    ((*(borrow_mut(&mut st)).unwrap()).buf)
                        .as_mut_ptr()
                        .offset((*(borrow(&st)).unwrap()).bufbeg as isize)
                        as *const libc::c_void,
                    len,
                ) });
            }
            (*(borrow_mut(&mut st)).unwrap()).bufbeg = 0 as i32 as size_t;
            (*(borrow_mut(&mut st)).unwrap()).bufend = len;
        }
        if (*(borrow(&st)).unwrap()).bufend >= ::std::mem::size_of::<[i8; 256]>() as u64 {
            return if cursize != 0 {
                cursize
            } else {
                -(1 as i32) as size_t
            };
        }
        sz = read_part_content(
            part,
            unsafe { ((*(borrow_mut(&mut st)).unwrap()).buf)
                .as_mut_ptr()
                .offset((*(borrow(&st)).unwrap()).bufend as isize) },
            (::std::mem::size_of::<[i8; 256]>() as u64)
                .wrapping_sub((*(borrow(&st)).unwrap()).bufend),
            borrow_mut(&mut hasread),
        );
        match sz {
            0 => {
                ateof = 1 as i32 != 0;
            }
            268435456 | 268435457 | 18446744073709551615 | 18446744073709551614 => {
                return if cursize != 0 { cursize } else { sz };
            }
            _ => {
                let mut fresh33 = &mut ((*(borrow_mut(&mut st)).unwrap()).bufend);
                *fresh33 = (*fresh33 as u64).wrapping_add(sz) as size_t as size_t;
            }
        }
    }
}
extern "C" fn readback_part<'a1>(
    mut part: *mut crate::src::lib::http2::curl_mimepart,
    mut buffer: *mut i8,
    mut bufsize: u64,
    mut hasread: Option<&'a1 mut bool>,
) -> u64 {
    let mut cursize: u64 = 0 as i32 as size_t;
    while bufsize != 0 {
        let mut sz: u64 = 0 as i32 as size_t;
        let mut hdr: *mut crate::src::lib::http2::curl_slist = (unsafe { (*part).state.ptr }) as *mut curl_slist;
        let mut current_block_24: u64;
        match (unsafe { (*part).state.state }) as u32 {
            0 => {
                mimesetstate(
                    Some(unsafe { &mut (*part).state }),
                    (if (unsafe { (*part).flags }) & ((1 as i32) << 1 as i32) as u32 != 0 {
                        MIMESTATE_BODY as i32
                    } else {
                        MIMESTATE_CURLHEADERS as i32
                    }) as mimestate,
                    (unsafe { (*part).curlheaders }) as *mut libc::c_void,
                );
                current_block_24 = 7828949454673616476;
            }
            2 => {
                if hdr.is_null() {
                    mimesetstate(
                        Some(unsafe { &mut (*part).state }),
                        MIMESTATE_EOH,
                        0 as *mut libc::c_void,
                    );
                    current_block_24 = 7828949454673616476;
                } else if !(match_header(
                    hdr,
                    b"Content-Type\0" as *const u8 as *const i8,
                    12 as i32 as size_t,
                ))
                .is_null()
                {
                    mimesetstate(
                        Some(unsafe { &mut (*part).state }),
                        MIMESTATE_USERHEADERS,
                        (unsafe { (*hdr).next }) as *mut libc::c_void,
                    );
                    current_block_24 = 7828949454673616476;
                } else {
                    current_block_24 = 14063703041815494542;
                }
            }
            1 => {
                current_block_24 = 14063703041815494542;
            }
            3 => {
                sz = readback_bytes(
                    Some(unsafe { &mut (*part).state }),
                    buffer,
                    bufsize,
                    b"\r\n\0" as *const u8 as *const i8,
                    2 as i32 as size_t,
                    b"\0" as *const u8 as *const i8,
                );
                if sz == 0 {
                    mimesetstate(
                        Some(unsafe { &mut (*part).state }),
                        MIMESTATE_BODY,
                        0 as *mut libc::c_void,
                    );
                }
                current_block_24 = 7828949454673616476;
            }
            4 => {
                cleanup_encoder_state(Some(unsafe { &mut (*part).encstate }));
                mimesetstate(
                    Some(unsafe { &mut (*part).state }),
                    MIMESTATE_CONTENT,
                    0 as *mut libc::c_void,
                );
                current_block_24 = 7828949454673616476;
            }
            7 => {
                if !(unsafe { (*part).encoder }).is_null() {
                    sz = read_encoded_part_content(part, buffer, bufsize, borrow_mut(&mut hasread));
                } else {
                    sz = read_part_content(part, buffer, bufsize, borrow_mut(&mut hasread));
                }
                's_167: {
                    match sz {
                        0 => {
                            mimesetstate(
                                Some(unsafe { &mut (*part).state }),
                                MIMESTATE_END,
                                0 as *mut libc::c_void,
                            );
                            if (unsafe { (*part).kind }) as u32 == MIMEKIND_FILE as i32 as u32
                                && !(unsafe { (*part).fp }).is_null()
                            {
                                (unsafe { fclose((*part).fp) });
                                let mut fresh34 = unsafe { &mut ((*part).fp) };
                                *fresh34 = 0 as *mut FILE;
                            }
                        }
                        268435456 | 268435457 | 18446744073709551615 | 18446744073709551614 => {}
                        _ => {
                            break 's_167;
                        }
                    }
                    return if cursize != 0 { cursize } else { sz };
                }
                current_block_24 = 7828949454673616476;
            }
            8 => return cursize,
            _ => {
                current_block_24 = 7828949454673616476;
            }
        }
        match current_block_24 {
            14063703041815494542 => {
                if hdr.is_null() {
                    mimesetstate(
                        Some(unsafe { &mut (*part).state }),
                        MIMESTATE_USERHEADERS,
                        (unsafe { (*part).userheaders }) as *mut libc::c_void,
                    );
                } else {
                    sz = readback_bytes(
                        Some(unsafe { &mut (*part).state }),
                        buffer,
                        bufsize,
                        unsafe { (*hdr).data },
                        unsafe { strlen((*hdr).data) },
                        b"\r\n\0" as *const u8 as *const i8,
                    );
                    if sz == 0 {
                        mimesetstate(
                            Some(unsafe { &mut (*part).state }),
                            unsafe { (*part).state.state },
                            (unsafe { (*hdr).next }) as *mut libc::c_void,
                        );
                    }
                }
            }
            _ => {}
        }
        cursize = (cursize as u64).wrapping_add(sz) as size_t as size_t;
        buffer = unsafe { buffer.offset(sz as isize) };
        bufsize = (bufsize as u64).wrapping_sub(sz) as size_t as size_t;
    }
    return cursize;
}
extern "C" fn mime_subparts_read<'a1>(
    mut buffer: *mut i8,
    mut _size: u64,
    mut nitems: u64,
    mut instream: *mut core::ffi::c_void,
    mut hasread: Option<&'a1 mut bool>,
) -> u64 {
    let mut mime: *mut crate::src::lib::http2::curl_mime = instream as *mut curl_mime;
    let mut cursize: u64 = 0 as i32 as size_t;
    while nitems != 0 {
        let mut sz: u64 = 0 as i32 as size_t;
        let mut part: *mut crate::src::lib::http2::curl_mimepart =
            (unsafe { (*mime).state.ptr }) as *mut curl_mimepart;
        match (unsafe { (*mime).state.state }) as u32 {
            0 | 4 => {
                mimesetstate(
                    Some(unsafe { &mut (*mime).state }),
                    MIMESTATE_BOUNDARY1,
                    (unsafe { (*mime).firstpart }) as *mut libc::c_void,
                );
                let mut fresh35 = unsafe { &mut ((*mime).state.offset) };
                *fresh35 += 2 as i32 as i64;
            }
            5 => {
                sz = readback_bytes(
                    Some(unsafe { &mut (*mime).state }),
                    buffer,
                    nitems,
                    b"\r\n--\0" as *const u8 as *const i8,
                    4 as i32 as size_t,
                    b"\0" as *const u8 as *const i8,
                );
                if sz == 0 {
                    mimesetstate(
                        Some(unsafe { &mut (*mime).state }),
                        MIMESTATE_BOUNDARY2,
                        part as *mut libc::c_void,
                    );
                }
            }
            6 => {
                sz = readback_bytes(
                    Some(unsafe { &mut (*mime).state }),
                    buffer,
                    nitems,
                    unsafe { ((*mime).boundary).as_mut_ptr() },
                    unsafe { strlen(((*mime).boundary).as_mut_ptr()) },
                    if !part.is_null() {
                        b"\r\n\0" as *const u8 as *const i8
                    } else {
                        b"--\r\n\0" as *const u8 as *const i8
                    },
                );
                if sz == 0 {
                    mimesetstate(
                        Some(unsafe { &mut (*mime).state }),
                        MIMESTATE_CONTENT,
                        part as *mut libc::c_void,
                    );
                }
            }
            7 => {
                if part.is_null() {
                    mimesetstate(
                        Some(unsafe { &mut (*mime).state }),
                        MIMESTATE_END,
                        0 as *mut libc::c_void,
                    );
                } else {
                    sz = readback_part(part, buffer, nitems, borrow_mut(&mut hasread));
                    match sz {
                        268435456 | 268435457 | 18446744073709551615 | 18446744073709551614 => {
                            return if cursize != 0 { cursize } else { sz };
                        }
                        0 => {
                            mimesetstate(
                                Some(unsafe { &mut (*mime).state }),
                                MIMESTATE_BOUNDARY1,
                                (unsafe { (*part).nextpart }) as *mut libc::c_void,
                            );
                        }
                        _ => {}
                    }
                }
            }
            8 => return cursize,
            _ => {}
        }
        cursize = (cursize as u64).wrapping_add(sz) as size_t as size_t;
        buffer = unsafe { buffer.offset(sz as isize) };
        nitems = (nitems as u64).wrapping_sub(sz) as size_t as size_t;
    }
    return cursize;
}
extern "C" fn mime_part_rewind(mut part: *mut crate::src::lib::http2::curl_mimepart) -> i32 {
    let mut res: i32 = 0 as i32;
    let mut targetstate: u32 = MIMESTATE_BEGIN;
    if (unsafe { (*part).flags }) & ((1 as i32) << 1 as i32) as u32 != 0 {
        targetstate = MIMESTATE_BODY;
    }
    cleanup_encoder_state(Some(unsafe { &mut (*part).encstate }));
    if (unsafe { (*part).state.state }) as u32 > targetstate as u32 {
        res = 2 as i32;
        if unsafe { ((*part).seekfunc).is_some() } {
            res = unsafe { ((*part).seekfunc).expect("non-null function pointer")(
                (*part).arg,
                0 as i32 as curl_off_t,
                0 as i32,
            ) };
            match res {
                0 | 1 | 2 => {}
                -1 => {
                    res = 2 as i32;
                }
                _ => {
                    res = 1 as i32;
                }
            }
        }
    }
    if res == 0 as i32 {
        mimesetstate(
            Some(unsafe { &mut (*part).state }),
            targetstate,
            0 as *mut libc::c_void,
        );
    }
    (unsafe { (*part).lastreadstatus = 1 as i32 as size_t });
    return res;
}
extern "C" fn mime_subparts_seek(
    mut instream: *mut core::ffi::c_void,
    mut offset: i64,
    mut whence: i32,
) -> i32 {
    let mut mime: *mut crate::src::lib::http2::curl_mime = instream as *mut curl_mime;
    let mut part: *mut crate::src::lib::http2::curl_mimepart = 0 as *mut curl_mimepart;
    let mut result: i32 = 0 as i32;
    if whence != 0 as i32 || offset != 0 {
        return 2 as i32;
    }
    if (unsafe { (*mime).state.state }) as u32 == MIMESTATE_BEGIN as i32 as u32 {
        return 0 as i32;
    }
    part = unsafe { (*mime).firstpart };
    while !part.is_null() {
        let mut res: i32 = mime_part_rewind(part);
        if res != 0 as i32 {
            result = res;
        }
        part = unsafe { (*part).nextpart };
    }
    if result == 0 as i32 {
        mimesetstate(
            Some(unsafe { &mut (*mime).state }),
            MIMESTATE_BEGIN,
            0 as *mut libc::c_void,
        );
    }
    return result;
}
extern "C" fn cleanup_part_content(mut part: *mut crate::src::lib::http2::curl_mimepart) {
    if unsafe { ((*part).freefunc).is_some() } {
        (unsafe { ((*part).freefunc).expect("non-null function pointer")((*part).arg) });
    }
    let mut fresh36 = unsafe { &mut ((*part).readfunc) };
    *fresh36 = None;
    let mut fresh37 = unsafe { &mut ((*part).seekfunc) };
    *fresh37 = None;
    let mut fresh38 = unsafe { &mut ((*part).freefunc) };
    *fresh38 = None;
    let mut fresh39 = unsafe { &mut ((*part).arg) };
    *fresh39 = part as *mut libc::c_void;
    let mut fresh40 = unsafe { &mut ((*part).data) };
    *fresh40 = 0 as *mut i8;
    let mut fresh41 = unsafe { &mut ((*part).fp) };
    *fresh41 = 0 as *mut FILE;
    (unsafe { (*part).datasize = 0 as i32 as curl_off_t });
    cleanup_encoder_state(Some(unsafe { &mut (*part).encstate }));
    (unsafe { (*part).kind = MIMEKIND_NONE });
    (unsafe { (*part).flags &= !((1 as i32) << 2 as i32) as u32 });
    (unsafe { (*part).lastreadstatus = 1 as i32 as size_t });
    (unsafe { (*part).state.state = MIMESTATE_BEGIN });
}
extern "C" fn mime_subparts_free(mut ptr: *mut core::ffi::c_void) {
    let mut mime: *mut crate::src::lib::http2::curl_mime = ptr as *mut curl_mime;
    if !mime.is_null() && !(unsafe { (*mime).parent }).is_null() {
        let mut fresh42 = unsafe { &mut ((*(*mime).parent).freefunc) };
        *fresh42 = None;
        cleanup_part_content(unsafe { (*mime).parent });
    }
    curl_mime_free(mime);
}
extern "C" fn mime_subparts_unbind(mut ptr: *mut core::ffi::c_void) {
    let mut mime: *mut crate::src::lib::http2::curl_mime = ptr as *mut curl_mime;
    if !mime.is_null() && !(unsafe { (*mime).parent }).is_null() {
        let mut fresh43 = unsafe { &mut ((*(*mime).parent).freefunc) };
        *fresh43 = None;
        cleanup_part_content(unsafe { (*mime).parent });
        let mut fresh44 = unsafe { &mut ((*mime).parent) };
        *fresh44 = 0 as *mut curl_mimepart;
    }
}
#[no_mangle]
pub extern "C" fn Curl_mime_cleanpart(mut part: *mut crate::src::lib::http2::curl_mimepart) {
    cleanup_part_content(part);
    curl_slist_free_all(unsafe { (*part).curlheaders });
    if (unsafe { (*part).flags }) & ((1 as i32) << 0 as i32) as u32 != 0 {
        curl_slist_free_all(unsafe { (*part).userheaders });
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")((*part).mimetype as *mut libc::c_void) });
    let mut fresh45 = unsafe { &mut ((*part).mimetype) };
    *fresh45 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*part).name as *mut libc::c_void) });
    let mut fresh46 = unsafe { &mut ((*part).name) };
    *fresh46 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*part).filename as *mut libc::c_void) });
    let mut fresh47 = unsafe { &mut ((*part).filename) };
    *fresh47 = 0 as *mut i8;
    Curl_mime_initpart(part, unsafe { (*part).easy });
}
#[no_mangle]
pub extern "C" fn curl_mime_free(mut mime: *mut crate::src::lib::http2::curl_mime) {
    let mut part: *mut crate::src::lib::http2::curl_mimepart = 0 as *mut curl_mimepart;
    if !mime.is_null() {
        mime_subparts_unbind(mime as *mut libc::c_void);
        while !(unsafe { (*mime).firstpart }).is_null() {
            part = unsafe { (*mime).firstpart };
            let mut fresh48 = unsafe { &mut ((*mime).firstpart) };
            *fresh48 = unsafe { (*part).nextpart };
            Curl_mime_cleanpart(part);
            (unsafe { Curl_cfree.expect("non-null function pointer")(part as *mut libc::c_void) });
        }
        (unsafe { Curl_cfree.expect("non-null function pointer")(mime as *mut libc::c_void) });
    }
}
#[no_mangle]
pub extern "C" fn Curl_mime_duppart(
    mut dst: *mut crate::src::lib::http2::curl_mimepart,
    mut src: *const crate::src::lib::http2::curl_mimepart,
) -> u32 {
    let mut mime: *mut crate::src::lib::http2::curl_mime = 0 as *mut curl_mime;
    let mut d: *mut crate::src::lib::http2::curl_mimepart = 0 as *mut curl_mimepart;
    let mut s: *const crate::src::lib::http2::curl_mimepart = 0 as *const curl_mimepart;
    let mut res: u32 = CURLE_OK;
    match (unsafe { (*src).kind }) as u32 {
        0 => {}
        1 => {
            res = curl_mime_data(dst, unsafe { (*src).data }, (unsafe { (*src).datasize }) as size_t);
        }
        2 => {
            res = curl_mime_filedata(dst, unsafe { (*src).data });
            if res as u32 == CURLE_READ_ERROR as i32 as u32 {
                res = CURLE_OK;
            }
        }
        3 => {
            res = curl_mime_data_cb(
                dst,
                unsafe { (*src).datasize },
                unsafe { (*src).readfunc },
                unsafe { (*src).seekfunc },
                unsafe { (*src).freefunc },
                unsafe { (*src).arg },
            );
        }
        4 => {
            mime = curl_mime_init(unsafe { (*dst).easy });
            res = (if !mime.is_null() {
                curl_mime_subparts(dst, mime) as u32
            } else {
                CURLE_OUT_OF_MEMORY as i32 as u32
            }) as CURLcode;
            s = unsafe { (*((*src).arg as *mut curl_mime)).firstpart };
            while res as u64 == 0 && !s.is_null() {
                d = curl_mime_addpart(mime);
                res = (if !d.is_null() {
                    Curl_mime_duppart(d, s) as u32
                } else {
                    CURLE_OUT_OF_MEMORY as i32 as u32
                }) as CURLcode;
                s = unsafe { (*s).nextpart };
            }
        }
        _ => {
            res = CURLE_BAD_FUNCTION_ARGUMENT;
        }
    }
    if res as u64 == 0 && !(unsafe { (*src).userheaders }).is_null() {
        let mut hdrs: *mut crate::src::lib::http2::curl_slist =
            Curl_slist_duplicate(unsafe { (*src).userheaders });
        if hdrs.is_null() {
            res = CURLE_OUT_OF_MEMORY;
        } else {
            res = curl_mime_headers(dst, hdrs, 1 as i32);
            if res as u64 != 0 {
                curl_slist_free_all(hdrs);
            }
        }
    }
    if res as u64 == 0 {
        let mut fresh49 = unsafe { &mut ((*dst).encoder) };
        *fresh49 = unsafe { (*src).encoder };
        res = curl_mime_type(dst, unsafe { (*src).mimetype });
    }
    if res as u64 == 0 {
        res = curl_mime_name(dst, unsafe { (*src).name });
    }
    if res as u64 == 0 {
        res = curl_mime_filename(dst, unsafe { (*src).filename });
    }
    if res as u64 != 0 {
        Curl_mime_cleanpart(dst);
    }
    return res;
}
#[no_mangle]
pub extern "C" fn curl_mime_init(
    mut easy: *mut crate::src::lib::http2::Curl_easy,
) -> *mut crate::src::lib::http2::curl_mime {
    let mut mime: *mut crate::src::lib::http2::curl_mime = 0 as *mut curl_mime;
    mime =
        (unsafe { Curl_cmalloc.expect("non-null function pointer")(::std::mem::size_of::<curl_mime>() as u64) })
            as *mut curl_mime;
    if !mime.is_null() {
        let mut fresh50 = unsafe { &mut ((*mime).easy) };
        *fresh50 = easy;
        let mut fresh51 = unsafe { &mut ((*mime).parent) };
        *fresh51 = 0 as *mut curl_mimepart;
        let mut fresh52 = unsafe { &mut ((*mime).firstpart) };
        *fresh52 = 0 as *mut curl_mimepart;
        let mut fresh53 = unsafe { &mut ((*mime).lastpart) };
        *fresh53 = 0 as *mut curl_mimepart;
        (unsafe { memset(
            ((*mime).boundary).as_mut_ptr() as *mut libc::c_void,
            '-' as i32,
            24 as i32 as u64,
        ) });
        if Curl_rand_hex(
            easy,
            (unsafe { &mut *((*mime).boundary).as_mut_ptr().offset(24 as i32 as isize) }) as *mut i8 as *mut u8,
            (16 as i32 + 1 as i32) as size_t,
        ) as u64
            != 0
        {
            (unsafe { Curl_cfree.expect("non-null function pointer")(mime as *mut libc::c_void) });
            return 0 as *mut curl_mime;
        }
        mimesetstate(
            Some(unsafe { &mut (*mime).state }),
            MIMESTATE_BEGIN,
            0 as *mut libc::c_void,
        );
    }
    return mime;
}
#[no_mangle]
pub extern "C" fn Curl_mime_initpart(
    mut part: *mut crate::src::lib::http2::curl_mimepart,
    mut easy: *mut crate::src::lib::http2::Curl_easy,
) {
    (unsafe { memset(
        part as *mut i8 as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<curl_mimepart>() as u64,
    ) });
    let mut fresh54 = unsafe { &mut ((*part).easy) };
    *fresh54 = easy;
    (unsafe { (*part).lastreadstatus = 1 as i32 as size_t });
    mimesetstate(
        Some(unsafe { &mut (*part).state }),
        MIMESTATE_BEGIN,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub extern "C" fn curl_mime_addpart(
    mut mime: *mut crate::src::lib::http2::curl_mime,
) -> *mut crate::src::lib::http2::curl_mimepart {
    let mut part: *mut crate::src::lib::http2::curl_mimepart = 0 as *mut curl_mimepart;
    if mime.is_null() {
        return 0 as *mut curl_mimepart;
    }
    part = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<curl_mimepart>() as u64
    ) }) as *mut curl_mimepart;
    if !part.is_null() {
        Curl_mime_initpart(part, unsafe { (*mime).easy });
        let mut fresh55 = unsafe { &mut ((*part).parent) };
        *fresh55 = mime;
        if !(unsafe { (*mime).lastpart }).is_null() {
            let mut fresh56 = unsafe { &mut ((*(*mime).lastpart).nextpart) };
            *fresh56 = part;
        } else {
            let mut fresh57 = unsafe { &mut ((*mime).firstpart) };
            *fresh57 = part;
        }
        let mut fresh58 = unsafe { &mut ((*mime).lastpart) };
        *fresh58 = part;
    }
    return part;
}
#[no_mangle]
pub extern "C" fn curl_mime_name(
    mut part: *mut crate::src::lib::http2::curl_mimepart,
    mut name: *const i8,
) -> u32 {
    if part.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")((*part).name as *mut libc::c_void) });
    let mut fresh59 = unsafe { &mut ((*part).name) };
    *fresh59 = 0 as *mut i8;
    let mut fresh60 = unsafe { &mut ((*part).name) };
    *fresh60 = 0 as *mut i8;
    if !name.is_null() {
        let mut fresh61 = unsafe { &mut ((*part).name) };
        *fresh61 = unsafe { Curl_cstrdup.expect("non-null function pointer")(name) };
        if (unsafe { (*part).name }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn curl_mime_filename(
    mut part: *mut crate::src::lib::http2::curl_mimepart,
    mut filename: *const i8,
) -> u32 {
    if part.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")((*part).filename as *mut libc::c_void) });
    let mut fresh62 = unsafe { &mut ((*part).filename) };
    *fresh62 = 0 as *mut i8;
    let mut fresh63 = unsafe { &mut ((*part).filename) };
    *fresh63 = 0 as *mut i8;
    if !filename.is_null() {
        let mut fresh64 = unsafe { &mut ((*part).filename) };
        *fresh64 = unsafe { Curl_cstrdup.expect("non-null function pointer")(filename) };
        if (unsafe { (*part).filename }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn curl_mime_data(
    mut part: *mut crate::src::lib::http2::curl_mimepart,
    mut data: *const i8,
    mut datasize: u64,
) -> u32 {
    if part.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    cleanup_part_content(part);
    if !data.is_null() {
        if datasize == -(1 as i32) as size_t {
            datasize = unsafe { strlen(data) };
        }
        let mut fresh65 = unsafe { &mut ((*part).data) };
        *fresh65 = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
            datasize.wrapping_add(1 as i32 as u64),
        ) }) as *mut i8;
        if (unsafe { (*part).data }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (unsafe { (*part).datasize = datasize as curl_off_t });
        if datasize != 0 {
            (unsafe { memcpy(
                (*part).data as *mut libc::c_void,
                data as *const libc::c_void,
                datasize,
            ) });
        }
        (unsafe { *((*part).data).offset(datasize as isize) = '\u{0}' as i32 as i8 });
        let mut fresh66 = unsafe { &mut ((*part).readfunc) };
        *fresh66 = Some(mime_mem_read);
        let mut fresh67 = unsafe { &mut ((*part).seekfunc) };
        *fresh67 = Some(mime_mem_seek);
        let mut fresh68 = unsafe { &mut ((*part).freefunc) };
        *fresh68 = Some(mime_mem_free);
        (unsafe { (*part).flags |= ((1 as i32) << 2 as i32) as u32 });
        (unsafe { (*part).kind = MIMEKIND_DATA });
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn curl_mime_filedata(
    mut part: *mut crate::src::lib::http2::curl_mimepart,
    mut filename: *const i8,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    if part.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    cleanup_part_content(part);
    if !filename.is_null() {
        let mut base: *mut i8 = 0 as *mut i8;
        let mut sbuf: crate::src::lib::file::stat = stat {
            st_dev: 0,
            st_ino: 0,
            st_nlink: 0,
            st_mode: 0,
            st_uid: 0,
            st_gid: 0,
            __pad0: 0,
            st_rdev: 0,
            st_size: 0,
            st_blksize: 0,
            st_blocks: 0,
            st_atim: timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            st_mtim: timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            st_ctim: timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            __glibc_reserved: [0; 3],
        };
        if stat(filename, &mut sbuf) != 0 || (unsafe { access(filename, 4 as i32) }) != 0 {
            result = CURLE_READ_ERROR;
        }
        let mut fresh69 = unsafe { &mut ((*part).data) };
        *fresh69 = unsafe { Curl_cstrdup.expect("non-null function pointer")(filename) };
        if (unsafe { (*part).data }).is_null() {
            result = CURLE_OUT_OF_MEMORY;
        }
        (unsafe { (*part).datasize = -(1 as i32) as curl_off_t });
        if result as u64 == 0 && sbuf.st_mode & 0o170000 as i32 as u32 == 0o100000 as i32 as u32 {
            (unsafe { (*part).datasize = sbuf.st_size });
            let mut fresh70 = unsafe { &mut ((*part).seekfunc) };
            *fresh70 = Some(mime_file_seek);
        }
        let mut fresh71 = unsafe { &mut ((*part).readfunc) };
        *fresh71 = Some(mime_file_read);
        let mut fresh72 = unsafe { &mut ((*part).freefunc) };
        *fresh72 = Some(mime_file_free);
        (unsafe { (*part).kind = MIMEKIND_FILE });
        base = strippath(filename);
        if base.is_null() {
            result = CURLE_OUT_OF_MEMORY;
        } else {
            let mut res: u32 = curl_mime_filename(part, base);
            if res as u64 != 0 {
                result = res;
            }
            (unsafe { Curl_cfree.expect("non-null function pointer")(base as *mut libc::c_void) });
        }
    }
    return result;
}
#[no_mangle]
pub extern "C" fn curl_mime_type(
    mut part: *mut crate::src::lib::http2::curl_mimepart,
    mut mimetype: *const i8,
) -> u32 {
    if part.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")((*part).mimetype as *mut libc::c_void) });
    let mut fresh73 = unsafe { &mut ((*part).mimetype) };
    *fresh73 = 0 as *mut i8;
    let mut fresh74 = unsafe { &mut ((*part).mimetype) };
    *fresh74 = 0 as *mut i8;
    if !mimetype.is_null() {
        let mut fresh75 = unsafe { &mut ((*part).mimetype) };
        *fresh75 = unsafe { Curl_cstrdup.expect("non-null function pointer")(mimetype) };
        if (unsafe { (*part).mimetype }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn curl_mime_encoder(
    mut part: *mut crate::src::lib::http2::curl_mimepart,
    mut encoding: *const i8,
) -> u32 {
    let mut result: u32 = CURLE_BAD_FUNCTION_ARGUMENT;
    let mut mep: *const crate::src::lib::http2::mime_encoder = 0 as *const mime_encoder;
    if part.is_null() {
        return result;
    }
    let mut fresh76 = unsafe { &mut ((*part).encoder) };
    *fresh76 = 0 as *const mime_encoder;
    if encoding.is_null() {
        return CURLE_OK;
    }
    mep = unsafe { encoders.as_ptr() };
    while !(unsafe { (*mep).name }).is_null() {
        if Curl_strcasecompare(encoding, unsafe { (*mep).name }) != 0 {
            let mut fresh77 = unsafe { &mut ((*part).encoder) };
            *fresh77 = mep;
            result = CURLE_OK;
        }
        mep = unsafe { mep.offset(1) };
    }
    return result;
}
#[no_mangle]
pub extern "C" fn curl_mime_headers(
    mut part: *mut crate::src::lib::http2::curl_mimepart,
    mut headers: *mut crate::src::lib::http2::curl_slist,
    mut take_ownership: i32,
) -> u32 {
    if part.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if (unsafe { (*part).flags }) & ((1 as i32) << 0 as i32) as u32 != 0 {
        if (unsafe { (*part).userheaders }) != headers {
            curl_slist_free_all(unsafe { (*part).userheaders });
        }
        (unsafe { (*part).flags &= !((1 as i32) << 0 as i32) as u32 });
    }
    let mut fresh78 = unsafe { &mut ((*part).userheaders) };
    *fresh78 = headers;
    if !headers.is_null() && take_ownership != 0 {
        (unsafe { (*part).flags |= ((1 as i32) << 0 as i32) as u32 });
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn curl_mime_data_cb(
    mut part: *mut crate::src::lib::http2::curl_mimepart,
    mut datasize: i64,
    mut readfunc: Option<
        unsafe extern "C" fn(_: *mut i8, _: u64, _: u64, _: *mut core::ffi::c_void) -> u64,
    >,
    mut seekfunc: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: i64, _: i32) -> i32>,
    mut freefunc: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>,
    mut arg: *mut core::ffi::c_void,
) -> u32 {
    if part.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    cleanup_part_content(part);
    if readfunc.is_some() {
        let mut fresh79 = unsafe { &mut ((*part).readfunc) };
        *fresh79 = readfunc;
        let mut fresh80 = unsafe { &mut ((*part).seekfunc) };
        *fresh80 = seekfunc;
        let mut fresh81 = unsafe { &mut ((*part).freefunc) };
        *fresh81 = freefunc;
        let mut fresh82 = unsafe { &mut ((*part).arg) };
        *fresh82 = arg;
        (unsafe { (*part).datasize = datasize });
        (unsafe { (*part).kind = MIMEKIND_CALLBACK });
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_mime_set_subparts(
    mut part: *mut crate::src::lib::http2::curl_mimepart,
    mut subparts: *mut crate::src::lib::http2::curl_mime,
    mut take_ownership: i32,
) -> u32 {
    let mut root: *mut crate::src::lib::http2::curl_mime = 0 as *mut curl_mime;
    if part.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if (unsafe { (*part).kind }) as u32 == MIMEKIND_MULTIPART as i32 as u32
        && (unsafe { (*part).arg }) == subparts as *mut libc::c_void
    {
        return CURLE_OK;
    }
    cleanup_part_content(part);
    if !subparts.is_null() {
        if !(unsafe { (*part).easy }).is_null()
            && !(unsafe { (*subparts).easy }).is_null()
            && (unsafe { (*part).easy }) != (unsafe { (*subparts).easy })
        {
            return CURLE_BAD_FUNCTION_ARGUMENT;
        }
        if !(unsafe { (*subparts).parent }).is_null() {
            return CURLE_BAD_FUNCTION_ARGUMENT;
        }
        root = unsafe { (*part).parent };
        if !root.is_null() {
            while !(unsafe { (*root).parent }).is_null() && !(unsafe { (*(*root).parent).parent }).is_null() {
                root = unsafe { (*(*root).parent).parent };
            }
            if subparts == root {
                if !(unsafe { (*part).easy }).is_null() {
                    (unsafe { Curl_failf(
                        (*part).easy,
                        b"Can't add itself as a subpart!\0" as *const u8 as *const i8,
                    ) });
                }
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
        }
        let mut fresh83 = unsafe { &mut ((*subparts).parent) };
        *fresh83 = part;
        let mut fresh84 = unsafe { &mut ((*part).seekfunc) };
        *fresh84 = Some(mime_subparts_seek);
        let mut fresh85 = unsafe { &mut ((*part).freefunc) };
        *fresh85 = if take_ownership != 0 {
            Some(mime_subparts_free)
        } else {
            Some(mime_subparts_unbind)
        };
        let mut fresh86 = unsafe { &mut ((*part).arg) };
        *fresh86 = subparts as *mut libc::c_void;
        (unsafe { (*part).datasize = -(1 as i32) as curl_off_t });
        (unsafe { (*part).kind = MIMEKIND_MULTIPART });
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn curl_mime_subparts(
    mut part: *mut crate::src::lib::http2::curl_mimepart,
    mut subparts: *mut crate::src::lib::http2::curl_mime,
) -> u32 {
    return Curl_mime_set_subparts(part, subparts, 1 as i32);
}
#[no_mangle]
pub extern "C" fn Curl_mime_read(
    mut buffer: *mut i8,
    mut _size: u64,
    mut nitems: u64,
    mut instream: *mut core::ffi::c_void,
) -> u64 {
    let mut part: *mut crate::src::lib::http2::curl_mimepart = instream as *mut curl_mimepart;
    let mut ret: u64 = 0;
    let mut hasread: bool = false;
    loop {
        hasread = 0 as i32 != 0;
        ret = readback_part(part, buffer, nitems, Some(&mut hasread));
        if !(ret == -(2 as i32) as size_t) {
            break;
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn Curl_mime_rewind(mut part: *mut crate::src::lib::http2::curl_mimepart) -> u32 {
    return (if mime_part_rewind(part) == 0 as i32 {
        CURLE_OK as i32
    } else {
        CURLE_SEND_FAIL_REWIND as i32
    }) as CURLcode;
}
extern "C" fn slist_size(
    mut s: *mut crate::src::lib::http2::curl_slist,
    mut overhead: u64,
    mut skip: *const i8,
) -> u64 {
    let mut size: u64 = 0 as i32 as size_t;
    let mut skiplen: u64 = if !skip.is_null() {
        unsafe { strlen(skip) }
    } else {
        0 as i32 as u64
    };
    while !s.is_null() {
        if skip.is_null() || (match_header(s, skip, skiplen)).is_null() {
            size = (size as u64).wrapping_add((unsafe { strlen((*s).data) }).wrapping_add(overhead)) as size_t
                as size_t;
        }
        s = unsafe { (*s).next };
    }
    return size;
}
extern "C" fn multipart_size(mut mime: *mut crate::src::lib::http2::curl_mime) -> i64 {
    let mut size: i64 = 0;
    let mut boundarysize: u64 = 0;
    let mut part: *mut crate::src::lib::http2::curl_mimepart = 0 as *mut curl_mimepart;
    if mime.is_null() {
        return 0 as i32 as curl_off_t;
    }
    boundarysize = (4 as i32 as u64)
        .wrapping_add(unsafe { strlen(((*mime).boundary).as_mut_ptr()) })
        .wrapping_add(2 as i32 as u64);
    size = boundarysize as curl_off_t;
    part = unsafe { (*mime).firstpart };
    while !part.is_null() {
        let mut sz: i64 = Curl_mime_size(part);
        if sz < 0 as i32 as i64 {
            size = sz;
        }
        if size >= 0 as i32 as i64 {
            size = (size as u64).wrapping_add(boundarysize.wrapping_add(sz as u64)) as curl_off_t
                as curl_off_t;
        }
        part = unsafe { (*part).nextpart };
    }
    return size;
}
#[no_mangle]
pub extern "C" fn Curl_mime_size(mut part: *mut crate::src::lib::http2::curl_mimepart) -> i64 {
    let mut size: i64 = 0;
    if (unsafe { (*part).kind }) as u32 == MIMEKIND_MULTIPART as i32 as u32 {
        (unsafe { (*part).datasize = multipart_size((*part).arg as *mut curl_mime) });
    }
    size = unsafe { (*part).datasize };
    if !(unsafe { (*part).encoder }).is_null() {
        size = unsafe { ((*(*part).encoder).sizefunc).expect("non-null function pointer")(part) };
    }
    if size >= 0 as i32 as i64 && (unsafe { (*part).flags }) & ((1 as i32) << 1 as i32) as u32 == 0 {
        size = (size as u64).wrapping_add(slist_size(
            unsafe { (*part).curlheaders },
            2 as i32 as size_t,
            0 as *const i8,
        )) as curl_off_t as curl_off_t;
        size = (size as u64).wrapping_add(slist_size(
            unsafe { (*part).userheaders },
            2 as i32 as size_t,
            b"Content-Type\0" as *const u8 as *const i8,
        )) as curl_off_t as curl_off_t;
        size += 2 as i32 as i64;
    }
    return size;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_mime_add_header<'a1>(
    mut slp: Option<&'a1 mut *mut crate::src::lib::http2::curl_slist>,
    mut fmt: *const i8,
    mut args: ...
) -> u32 {
    let mut hdr: *mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
    let mut s: *mut i8 = 0 as *mut i8;
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    s = curl_mvaprintf(fmt, ap.as_va_list());
    if !s.is_null() {
        hdr = Curl_slist_append_nodup(*(borrow_mut(&mut slp)).unwrap(), s);
        if !hdr.is_null() {
            *(borrow_mut(&mut slp)).unwrap() = hdr;
        } else {
            Curl_cfree.expect("non-null function pointer")(s as *mut libc::c_void);
        }
    }
    return (if !hdr.is_null() {
        CURLE_OK as i32
    } else {
        CURLE_OUT_OF_MEMORY as i32
    }) as CURLcode;
}
extern "C" fn add_content_type<'a1>(
    mut slp: Option<&'a1 mut *mut crate::src::lib::http2::curl_slist>,
    mut type_0: *const i8,
    mut boundary: *const i8,
) -> u32 {
    return unsafe { Curl_mime_add_header(
        borrow_mut(&mut slp),
        b"Content-Type: %s%s%s\0" as *const u8 as *const i8,
        type_0,
        if !boundary.is_null() {
            b"; boundary=\0" as *const u8 as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !boundary.is_null() {
            boundary
        } else {
            b"\0" as *const u8 as *const i8
        },
    ) };
}
#[no_mangle]
pub extern "C" fn Curl_mime_contenttype(mut filename: *const i8) -> *const i8 {
    static mut ctts: [crate::src::lib::mime::ContentType; 10] = [
        {
            let mut init = ContentType {
                extension: b".gif\0" as *const u8 as *const i8,
                type_0: b"image/gif\0" as *const u8 as *const i8,
            };
            init
        },
        {
            let mut init = ContentType {
                extension: b".jpg\0" as *const u8 as *const i8,
                type_0: b"image/jpeg\0" as *const u8 as *const i8,
            };
            init
        },
        {
            let mut init = ContentType {
                extension: b".jpeg\0" as *const u8 as *const i8,
                type_0: b"image/jpeg\0" as *const u8 as *const i8,
            };
            init
        },
        {
            let mut init = ContentType {
                extension: b".png\0" as *const u8 as *const i8,
                type_0: b"image/png\0" as *const u8 as *const i8,
            };
            init
        },
        {
            let mut init = ContentType {
                extension: b".svg\0" as *const u8 as *const i8,
                type_0: b"image/svg+xml\0" as *const u8 as *const i8,
            };
            init
        },
        {
            let mut init = ContentType {
                extension: b".txt\0" as *const u8 as *const i8,
                type_0: b"text/plain\0" as *const u8 as *const i8,
            };
            init
        },
        {
            let mut init = ContentType {
                extension: b".htm\0" as *const u8 as *const i8,
                type_0: b"text/html\0" as *const u8 as *const i8,
            };
            init
        },
        {
            let mut init = ContentType {
                extension: b".html\0" as *const u8 as *const i8,
                type_0: b"text/html\0" as *const u8 as *const i8,
            };
            init
        },
        {
            let mut init = ContentType {
                extension: b".pdf\0" as *const u8 as *const i8,
                type_0: b"application/pdf\0" as *const u8 as *const i8,
            };
            init
        },
        {
            let mut init = ContentType {
                extension: b".xml\0" as *const u8 as *const i8,
                type_0: b"application/xml\0" as *const u8 as *const i8,
            };
            init
        },
    ];
    if !filename.is_null() {
        let mut len1: u64 = unsafe { strlen(filename) };
        let mut nameend: *const i8 = unsafe { filename.offset(len1 as isize) };
        let mut i: u32 = 0;
        i = 0 as i32 as u32;
        while (i as u64)
            < (::std::mem::size_of::<[ContentType; 10]>() as u64)
                .wrapping_div(::std::mem::size_of::<ContentType>() as u64)
        {
            let mut len2: u64 = unsafe { strlen(ctts[i as usize].extension) };
            if len1 >= len2
                && Curl_strcasecompare(unsafe { nameend.offset(-(len2 as isize)) }, unsafe { ctts[i as usize].extension })
                    != 0
            {
                return unsafe { ctts[i as usize].type_0 };
            }
            i = i.wrapping_add(1);
        }
    }
    return 0 as *const i8;
}
extern "C" fn content_type_match(mut contenttype: *const i8, mut target: *const i8) -> bool {
    let mut len: u64 = unsafe { strlen(target) };
    if !contenttype.is_null() && Curl_strncasecompare(contenttype, target, len) != 0 {
        match (unsafe { *contenttype.offset(len as isize) }) as i32 {
            0 | 9 | 13 | 10 | 32 | 59 => return 1 as i32 != 0,
            _ => {}
        }
    }
    return 0 as i32 != 0;
}
#[no_mangle]
pub extern "C" fn Curl_mime_prepare_headers(
    mut part: *mut crate::src::lib::http2::curl_mimepart,
    mut contenttype: *const i8,
    mut disposition: *const i8,
    mut strategy: u32,
) -> u32 {
    let mut mime: *mut crate::src::lib::http2::curl_mime =
        0 as *mut crate::src::lib::http2::curl_mime;
    let mut boundary: *const i8 = 0 as *const i8;
    let mut customct: *mut i8 = 0 as *mut i8;
    let mut cte: *const i8 = 0 as *const i8;
    let mut ret: u32 = CURLE_OK;
    curl_slist_free_all(unsafe { (*part).curlheaders });
    let mut fresh87 = unsafe { &mut ((*part).curlheaders) };
    *fresh87 = 0 as *mut curl_slist;
    if (unsafe { (*part).state.state }) as u32 == MIMESTATE_CURLHEADERS as i32 as u32 {
        mimesetstate(
            Some(unsafe { &mut (*part).state }),
            MIMESTATE_CURLHEADERS,
            0 as *mut libc::c_void,
        );
    }
    customct = unsafe { (*part).mimetype };
    if customct.is_null() {
        customct = search_header(
            unsafe { (*part).userheaders },
            b"Content-Type\0" as *const u8 as *const i8,
        );
    }
    if !customct.is_null() {
        contenttype = customct;
    }
    if contenttype.is_null() {
        match (unsafe { (*part).kind }) as u32 {
            4 => {
                contenttype = b"multipart/mixed\0" as *const u8 as *const i8;
            }
            2 => {
                contenttype = Curl_mime_contenttype(unsafe { (*part).filename });
                if contenttype.is_null() {
                    contenttype = Curl_mime_contenttype(unsafe { (*part).data });
                }
                if contenttype.is_null() && !(unsafe { (*part).filename }).is_null() {
                    contenttype = b"application/octet-stream\0" as *const u8 as *const i8;
                }
            }
            _ => {
                contenttype = Curl_mime_contenttype(unsafe { (*part).filename });
            }
        }
    }
    if (unsafe { (*part).kind }) as u32 == MIMEKIND_MULTIPART as i32 as u32 {
        mime = (unsafe { (*part).arg }) as *mut curl_mime;
        if !mime.is_null() {
            boundary = unsafe { ((*mime).boundary).as_mut_ptr() };
        }
    } else if !contenttype.is_null()
        && customct.is_null()
        && content_type_match(contenttype, b"text/plain\0" as *const u8 as *const i8) as i32 != 0
    {
        if strategy as u32 == MIMESTRATEGY_MAIL as i32 as u32 || (unsafe { (*part).filename }).is_null() {
            contenttype = 0 as *const i8;
        }
    }
    if (search_header(
        unsafe { (*part).userheaders },
        b"Content-Disposition\0" as *const u8 as *const i8,
    ))
    .is_null()
    {
        if disposition.is_null() {
            if !(unsafe { (*part).filename }).is_null()
                || !(unsafe { (*part).name }).is_null()
                || !contenttype.is_null()
                    && Curl_strncasecompare(
                        contenttype,
                        b"multipart/\0" as *const u8 as *const i8,
                        10 as i32 as size_t,
                    ) == 0
            {
                disposition = b"attachment\0" as *const u8 as *const i8;
            }
        }
        if !disposition.is_null()
            && curl_strequal(disposition, b"attachment\0" as *const u8 as *const i8) != 0
            && (unsafe { (*part).name }).is_null()
            && (unsafe { (*part).filename }).is_null()
        {
            disposition = 0 as *const i8;
        }
        if !disposition.is_null() {
            let mut name: *mut i8 = 0 as *mut i8;
            let mut filename: *mut i8 = 0 as *mut i8;
            if !(unsafe { (*part).name }).is_null() {
                name = escape_string(unsafe { (*part).name });
                if name.is_null() {
                    ret = CURLE_OUT_OF_MEMORY;
                }
            }
            if ret as u64 == 0 && !(unsafe { (*part).filename }).is_null() {
                filename = escape_string(unsafe { (*part).filename });
                if filename.is_null() {
                    ret = CURLE_OUT_OF_MEMORY;
                }
            }
            if ret as u64 == 0 {
                ret = unsafe { Curl_mime_add_header(
                    Some(&mut (*part).curlheaders),
                    b"Content-Disposition: %s%s%s%s%s%s%s\0" as *const u8 as *const i8,
                    disposition,
                    if !name.is_null() {
                        b"; name=\"\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !name.is_null() {
                        name as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !name.is_null() {
                        b"\"\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !filename.is_null() {
                        b"; filename=\"\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !filename.is_null() {
                        filename as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !filename.is_null() {
                        b"\"\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                ) };
            }
            (unsafe { Curl_cfree.expect("non-null function pointer")(name as *mut libc::c_void) });
            name = 0 as *mut i8;
            (unsafe { Curl_cfree.expect("non-null function pointer")(filename as *mut libc::c_void) });
            filename = 0 as *mut i8;
            if ret as u64 != 0 {
                return ret;
            }
        }
    }
    if !contenttype.is_null() {
        ret = add_content_type(Some(unsafe { &mut (*part).curlheaders }), contenttype, boundary);
        if ret as u64 != 0 {
            return ret;
        }
    }
    if (search_header(
        unsafe { (*part).userheaders },
        b"Content-Transfer-Encoding\0" as *const u8 as *const i8,
    ))
    .is_null()
    {
        if !(unsafe { (*part).encoder }).is_null() {
            cte = unsafe { (*(*part).encoder).name };
        } else if !contenttype.is_null()
            && strategy as u32 == MIMESTRATEGY_MAIL as i32 as u32
            && (unsafe { (*part).kind }) as u32 != MIMEKIND_MULTIPART as i32 as u32
        {
            cte = b"8bit\0" as *const u8 as *const i8;
        }
        if !cte.is_null() {
            ret = unsafe { Curl_mime_add_header(
                Some(&mut (*part).curlheaders),
                b"Content-Transfer-Encoding: %s\0" as *const u8 as *const i8,
                cte,
            ) };
            if ret as u64 != 0 {
                return ret;
            }
        }
    }
    if (unsafe { (*part).state.state }) as u32 == MIMESTATE_CURLHEADERS as i32 as u32 {
        mimesetstate(
            Some(unsafe { &mut (*part).state }),
            MIMESTATE_CURLHEADERS,
            (unsafe { (*part).curlheaders }) as *mut libc::c_void,
        );
    }
    if (unsafe { (*part).kind }) as u32 == MIMEKIND_MULTIPART as i32 as u32 && !mime.is_null() {
        let mut subpart: *mut crate::src::lib::http2::curl_mimepart = 0 as *mut curl_mimepart;
        disposition = 0 as *const i8;
        if content_type_match(
            contenttype,
            b"multipart/form-data\0" as *const u8 as *const i8,
        ) {
            disposition = b"form-data\0" as *const u8 as *const i8;
        }
        subpart = unsafe { (*mime).firstpart };
        while !subpart.is_null() {
            ret = Curl_mime_prepare_headers(subpart, 0 as *const i8, disposition, strategy);
            if ret as u64 != 0 {
                return ret;
            }
            subpart = unsafe { (*subpart).nextpart };
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn Curl_mime_unpause(mut part: *mut crate::src::lib::http2::curl_mimepart) {
    if !part.is_null() {
        if (unsafe { (*part).lastreadstatus }) == 0x10000001 as i32 as u64 {
            (unsafe { (*part).lastreadstatus = 1 as i32 as size_t });
        }
        if (unsafe { (*part).kind }) as u32 == MIMEKIND_MULTIPART as i32 as u32 {
            let mut mime: *mut crate::src::lib::http2::curl_mime = (unsafe { (*part).arg }) as *mut curl_mime;
            if !mime.is_null() {
                let mut subpart: *mut crate::src::lib::http2::curl_mimepart =
                    0 as *mut curl_mimepart;
                subpart = unsafe { (*mime).firstpart };
                while !subpart.is_null() {
                    Curl_mime_unpause(subpart);
                    subpart = unsafe { (*subpart).nextpart };
                }
            }
        }
    }
}
use crate::laertes_rt::*;
