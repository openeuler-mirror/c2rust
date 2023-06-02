
use :: libc;
extern "C" {
    fn fread(
        _: *mut core::ffi::c_void,
        _: u64,
        _: u64,
        _: *mut crate::src::lib::http2::_IO_FILE,
    ) -> u64;
    fn fseek(__stream: *mut crate::src::lib::http2::_IO_FILE, __off: i64, __whence: i32) -> i32;
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn strlen(_: *const i8) -> u64;
}
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::connect::Curl_conncontrol;
pub use crate::src::lib::connect::Curl_timeleft;
pub use crate::src::lib::content_encoding::Curl_unencode_write;
pub use crate::src::lib::cookie::Curl_cookie_loadfiles;
pub use crate::src::lib::dynbuf::Curl_dyn_free;
pub use crate::src::lib::dynbuf::Curl_dyn_init;
pub use crate::src::lib::dynbuf::Curl_dyn_len;
pub use crate::src::lib::dynbuf::Curl_dyn_ptr;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_cstrdup;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::getinfo::Curl_initinfo;
pub use crate::src::lib::hostip::Curl_loadhostpairs;
pub use crate::src::lib::hsts::Curl_hsts_loadcb;
pub use crate::src::lib::http::Curl_http_compile_trailers;
pub use crate::src::lib::http::Curl_http_firstwrite;
pub use crate::src::lib::http::Curl_http_readwrite_headers;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::http2::Curl_http2_done_sending;
pub use crate::src::lib::http2::Curl_http2_init_state;
pub use crate::src::lib::http_chunks::Curl_chunked_strerror;
pub use crate::src::lib::http_chunks::Curl_httpchunk_read;
pub use crate::src::lib::mime::Curl_mime_rewind;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::multi::Curl_expire;
pub use crate::src::lib::multi::Curl_expire_done;
pub use crate::src::lib::multi::Curl_set_in_callback;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::pop3::Curl_pop3_write;
pub use crate::src::lib::progress::Curl_pgrsResetTransferSizes;
pub use crate::src::lib::progress::Curl_pgrsSetDownloadCounter;
pub use crate::src::lib::progress::Curl_pgrsSetDownloadSize;
pub use crate::src::lib::progress::Curl_pgrsSetUploadCounter;
pub use crate::src::lib::progress::Curl_pgrsStartNow;
pub use crate::src::lib::progress::Curl_pgrsTime;
pub use crate::src::lib::progress::Curl_pgrsUpdate;
pub use crate::src::lib::select::Curl_socket_check;
pub use crate::src::lib::sendf::Curl_client_write;
pub use crate::src::lib::sendf::Curl_debug;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::sendf::Curl_read;
pub use crate::src::lib::sendf::Curl_write;
pub use crate::src::lib::setopt::Curl_setstropt;
pub use crate::src::lib::slist::curl_slist_free_all;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::smtp::Curl_smtp_escape_eob;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::speedcheck::Curl_speedcheck;
pub use crate::src::lib::strcase::Curl_strncasecompare;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::timeval::Curl_now;
pub use crate::src::lib::timeval::Curl_timediff;
pub use crate::src::lib::url::Curl_uc_to_curlcode;
pub use crate::src::lib::urlapi::curl_url;
pub use crate::src::lib::urlapi::curl_url_cleanup;
pub use crate::src::lib::urlapi::curl_url_get;
pub use crate::src::lib::urlapi::curl_url_set;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::urlapi::Curl_is_absolute_url;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
pub use crate::src::lib::vtls::vtls::Curl_ssl_data_pending;
pub use crate::src::lib::vtls::vtls::Curl_ssl_initsessions;
pub use crate::src::lib::wildcard::Curl_wildcard_init;
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
pub type hsts = crate::src::lib::easy::hsts;
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
pub type contenc_writer = crate::src::lib::content_encoding::contenc_writer;
pub type content_encoding = crate::src::lib::content_encoding::content_encoding;
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
pub type C2RustUnnamed_6 = u32;
pub const CURLIOCMD_LAST: C2RustUnnamed_6 = 2;
pub const CURLIOCMD_RESTARTREAD: C2RustUnnamed_6 = 1;
pub const CURLIOCMD_NOP: C2RustUnnamed_6 = 0;
pub type curl_malloc_callback<'a1> =
    Option<unsafe extern "C" fn(_: u64) -> Option<&'a1 mut core::ffi::c_void>>;
pub type curl_strdup_callback<'a1, 'a2> =
    Option<unsafe extern "C" fn(_: Option<&'a1 i8>) -> Option<&'a2 mut i8>>;
pub type CURLUcode = u32;
pub const CURLUE_NO_FRAGMENT: CURLUcode = 17;
pub const CURLUE_NO_QUERY: CURLUcode = 16;
pub const CURLUE_NO_PORT: CURLUcode = 15;
pub const CURLUE_NO_HOST: CURLUcode = 14;
pub const CURLUE_NO_OPTIONS: CURLUcode = 13;
pub const CURLUE_NO_PASSWORD: CURLUcode = 12;
pub const CURLUE_NO_USER: CURLUcode = 11;
pub const CURLUE_NO_SCHEME: CURLUcode = 10;
pub const CURLUE_UNKNOWN_PART: CURLUcode = 9;
pub const CURLUE_USER_NOT_ALLOWED: CURLUcode = 8;
pub const CURLUE_OUT_OF_MEMORY: CURLUcode = 7;
pub const CURLUE_URLDECODE: CURLUcode = 6;
pub const CURLUE_UNSUPPORTED_SCHEME: CURLUcode = 5;
pub const CURLUE_BAD_PORT_NUMBER: CURLUcode = 4;
pub const CURLUE_MALFORMED_INPUT: CURLUcode = 3;
pub const CURLUE_BAD_PARTPOINTER: CURLUcode = 2;
pub const CURLUE_BAD_HANDLE: CURLUcode = 1;
pub const CURLUE_OK: CURLUcode = 0;
pub type CURLUPart = u32;
pub const CURLUPART_ZONEID: CURLUPart = 10;
pub const CURLUPART_FRAGMENT: CURLUPart = 9;
pub const CURLUPART_QUERY: CURLUPart = 8;
pub const CURLUPART_PATH: CURLUPart = 7;
pub const CURLUPART_PORT: CURLUPart = 6;
pub const CURLUPART_HOST: CURLUPart = 5;
pub const CURLUPART_OPTIONS: CURLUPart = 4;
pub const CURLUPART_PASSWORD: CURLUPart = 3;
pub const CURLUPART_USER: CURLUPart = 2;
pub const CURLUPART_SCHEME: CURLUPart = 1;
pub const CURLUPART_URL: CURLUPart = 0;
pub type CHUNKcode = i32;
pub const CHUNKE_LAST: CHUNKcode = 7;
pub const CHUNKE_PASSTHRU_ERROR: CHUNKcode = 6;
pub const CHUNKE_OUT_OF_MEMORY: CHUNKcode = 5;
pub const CHUNKE_BAD_ENCODING: CHUNKcode = 4;
pub const CHUNKE_BAD_CHUNK: CHUNKcode = 3;
pub const CHUNKE_ILLEGAL_HEX: CHUNKcode = 2;
pub const CHUNKE_TOO_LONG_HEX: CHUNKcode = 1;
pub const CHUNKE_OK: CHUNKcode = 0;
pub const CHUNKE_STOP: CHUNKcode = -1;
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
pub type followtype = u32;
pub const FOLLOW_REDIR: followtype = 3;
pub const FOLLOW_RETRY: followtype = 2;
pub const FOLLOW_FAKE: followtype = 1;
pub const FOLLOW_NONE: followtype = 0;
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
#[no_mangle]
pub extern "C" fn Curl_checkheaders(
    mut data: *const crate::src::lib::http2::Curl_easy,
    mut thisheader: *const i8,
) -> *mut i8 {
    let mut head: *mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
    let mut thislen: u64 = unsafe { strlen(thisheader) };
    head = unsafe { (*data).set.headers };
    while !head.is_null() {
        if Curl_strncasecompare(unsafe { (*head).data }, thisheader, thislen) != 0
            && ((unsafe { *((*head).data).offset(thislen as isize) }) as i32 == ':' as i32
                || (unsafe { *((*head).data).offset(thislen as isize) }) as i32 == ';' as i32)
        {
            return unsafe { (*head).data };
        }
        head = unsafe { (*head).next };
    }
    return 0 as *mut i8;
}
#[no_mangle]
pub extern "C" fn Curl_get_upload_buffer(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    if (unsafe { (*data).state.ulbuf }).is_null() {
        let mut fresh0 = unsafe { &mut ((*data).state.ulbuf) };
        *fresh0 = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
            (*data).set.upload_buffer_size as size_t,
        ) }) as *mut i8;
        if (unsafe { (*data).state.ulbuf }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
extern "C" fn trailers_read(
    mut buffer: *mut i8,
    mut size: u64,
    mut nitems: u64,
    mut raw: *mut core::ffi::c_void,
) -> u64 {
    let mut data: *mut crate::src::lib::http2::Curl_easy = raw as *mut Curl_easy;
    let mut trailers_buf: *mut crate::src::lib::http2::dynbuf = unsafe { &mut (*data).state.trailers_buf };
    let mut bytes_left: u64 =
        (Curl_dyn_len(trailers_buf)).wrapping_sub(unsafe { (*data).state.trailers_bytes_sent });
    let mut to_copy: u64 = if size.wrapping_mul(nitems) < bytes_left {
        size.wrapping_mul(nitems)
    } else {
        bytes_left
    };
    if to_copy != 0 {
        (unsafe { memcpy(
            buffer as *mut libc::c_void,
            (Curl_dyn_ptr(trailers_buf)).offset((*data).state.trailers_bytes_sent as isize)
                as *const libc::c_void,
            to_copy,
        ) });
        let mut fresh1 = unsafe { &mut ((*data).state.trailers_bytes_sent) };
        *fresh1 = (*fresh1 as u64).wrapping_add(to_copy) as size_t as size_t;
    }
    return to_copy;
}
extern "C" fn trailers_left(mut raw: *mut core::ffi::c_void) -> u64 {
    let mut data: *mut crate::src::lib::http2::Curl_easy = raw as *mut Curl_easy;
    let mut trailers_buf: *mut crate::src::lib::http2::dynbuf = unsafe { &mut (*data).state.trailers_buf };
    return (Curl_dyn_len(trailers_buf)).wrapping_sub(unsafe { (*data).state.trailers_bytes_sent });
}
#[no_mangle]
pub extern "C" fn Curl_fillreadbuffer<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut bytes: u64,
    mut nreadp: Option<&'a1 mut u64>,
) -> u32 {
    let mut buffersize: u64 = bytes;
    let mut nread: u64 = 0;
    let mut readfunc: Option<
        unsafe extern "C" fn(_: *mut i8, _: u64, _: u64, _: *mut core::ffi::c_void) -> u64,
    > = None;
    let mut extra_data: *mut core::ffi::c_void = 0 as *mut libc::c_void;
    if (unsafe { (*data).state.trailers_state }) as u32 == TRAILERS_INITIALIZED as i32 as u32 {
        let mut trailers: *mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
        let mut result: u32 = CURLE_OK;
        let mut trailers_ret_code: i32 = 0;
        (unsafe { Curl_infof(
            data,
            b"Moving trailers state machine from initialized to sending.\0" as *const u8
                as *const i8,
        ) });
        (unsafe { (*data).state.trailers_state = TRAILERS_SENDING });
        Curl_dyn_init(
            unsafe { &mut (*data).state.trailers_buf },
            (64 as i32 * 1024 as i32) as size_t,
        );
        (unsafe { (*data).state.trailers_bytes_sent = 0 as i32 as size_t });
        Curl_set_in_callback(data, 1 as i32 != 0);
        trailers_ret_code = unsafe { ((*data).set.trailer_callback).expect("non-null function pointer")(
            &mut trailers,
            (*data).set.trailer_data,
        ) };
        Curl_set_in_callback(data, 0 as i32 != 0);
        if trailers_ret_code == 0 as i32 {
            result = Curl_http_compile_trailers(trailers, unsafe { &mut (*data).state.trailers_buf }, data);
        } else {
            (unsafe { Curl_failf(
                data,
                b"operation aborted by trailing headers callback\0" as *const u8 as *const i8,
            ) });
            *(borrow_mut(&mut nreadp)).unwrap() = 0 as i32 as size_t;
            result = CURLE_ABORTED_BY_CALLBACK;
        }
        if result as u64 != 0 {
            Curl_dyn_free(unsafe { &mut (*data).state.trailers_buf });
            curl_slist_free_all(trailers);
            return result;
        }
        (unsafe { Curl_infof(
            data,
            b"Successfully compiled trailers.\0" as *const u8 as *const i8,
        ) });
        curl_slist_free_all(trailers);
    }
    if (unsafe { ((*data).req).upload_chunky() }) as i32 != 0
        && (unsafe { (*data).state.trailers_state }) as u32 == TRAILERS_NONE as i32 as u32
    {
        buffersize = (buffersize as u64).wrapping_sub((8 as i32 + 2 as i32 + 2 as i32) as u64)
            as size_t as size_t;
        let mut fresh2 = unsafe { &mut ((*data).req.upload_fromhere) };
        *fresh2 = unsafe { (*fresh2).offset((8 as i32 + 2 as i32) as isize) };
    }
    if (unsafe { (*data).state.trailers_state }) as u32 == TRAILERS_SENDING as i32 as u32 {
        readfunc = Some(trailers_read);
        extra_data = data as *mut libc::c_void;
    } else {
        readfunc = unsafe { (*data).state.fread_func };
        extra_data = unsafe { (*data).state.in_0 };
    }
    Curl_set_in_callback(data, 1 as i32 != 0);
    nread = unsafe { readfunc.expect("non-null function pointer")(
        (*data).req.upload_fromhere,
        1 as i32 as size_t,
        buffersize,
        extra_data,
    ) };
    Curl_set_in_callback(data, 0 as i32 != 0);
    if nread == 0x10000000 as i32 as u64 {
        (unsafe { Curl_failf(
            data,
            b"operation aborted by callback\0" as *const u8 as *const i8,
        ) });
        *(borrow_mut(&mut nreadp)).unwrap() = 0 as i32 as size_t;
        return CURLE_ABORTED_BY_CALLBACK;
    }
    if nread == 0x10000001 as i32 as u64 {
        let mut k: Option<&'_ mut crate::src::lib::http2::SingleRequest> = Some(unsafe { &mut (*data).req });
        if (unsafe { (*(*(*data).conn).handler).flags }) & ((1 as i32) << 4 as i32) as u32 != 0 {
            (unsafe { Curl_failf(
                data,
                b"Read callback asked for PAUSE when not supported!\0" as *const u8 as *const i8,
            ) });
            return CURLE_READ_ERROR;
        }
        (*(borrow_mut(&mut k)).unwrap()).keepon |= (1 as i32) << 5 as i32;
        if (unsafe { ((*data).req).upload_chunky() }) != 0 {
            let mut fresh3 = unsafe { &mut ((*data).req.upload_fromhere) };
            *fresh3 = unsafe { (*fresh3).offset(-((8 as i32 + 2 as i32) as isize)) };
        }
        *(borrow_mut(&mut nreadp)).unwrap() = 0 as i32 as size_t;
        return CURLE_OK;
    } else {
        if nread > buffersize {
            *(borrow_mut(&mut nreadp)).unwrap() = 0 as i32 as size_t;
            (unsafe { Curl_failf(
                data,
                b"read function returned funny value\0" as *const u8 as *const i8,
            ) });
            return CURLE_READ_ERROR;
        }
    }
    if (unsafe { ((*data).req).forbidchunk() }) == 0 && (unsafe { ((*data).req).upload_chunky() }) as i32 != 0 {
        let mut added_crlf: bool = 0 as i32 != 0;
        let mut hexlen: i32 = 0 as i32;
        let mut endofline_native: *const i8 = 0 as *const i8;
        let mut endofline_network: *const i8 = 0 as *const i8;
        if (unsafe { ((*data).state).prefer_ascii() }) as i32 != 0 || (unsafe { ((*data).set).crlf() }) as i32 != 0 {
            endofline_native = b"\n\0" as *const u8 as *const i8;
            endofline_network = b"\n\0" as *const u8 as *const i8;
        } else {
            endofline_native = b"\r\n\0" as *const u8 as *const i8;
            endofline_network = b"\r\n\0" as *const u8 as *const i8;
        }
        if (unsafe { (*data).state.trailers_state }) as u32 != TRAILERS_SENDING as i32 as u32 {
            let mut hexbuffer: [i8; 11] = *(unsafe { core::intrinsics::transmute::<
                &'_ [u8; 11],
                &'_ mut [i8; 11],
            >(b"\0\0\0\0\0\0\0\0\0\0\0") });
            hexlen = unsafe { curl_msnprintf(
                hexbuffer.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 11]>() as u64,
                b"%zx%s\0" as *const u8 as *const i8,
                nread,
                endofline_native,
            ) };
            let mut fresh4 = unsafe { &mut ((*data).req.upload_fromhere) };
            *fresh4 = unsafe { (*fresh4).offset(-(hexlen as isize)) };
            nread = (nread as u64).wrapping_add(hexlen as u64) as size_t as size_t;
            (unsafe { memcpy(
                (*data).req.upload_fromhere as *mut libc::c_void,
                hexbuffer.as_mut_ptr() as *const libc::c_void,
                hexlen as u64,
            ) });
            if nread.wrapping_sub(hexlen as u64) == 0 as i32 as u64
                && (unsafe { ((*data).set.trailer_callback).is_some() })
                && (unsafe { (*data).state.trailers_state }) as u32 == TRAILERS_NONE as i32 as u32
            {
                (unsafe { (*data).state.trailers_state = TRAILERS_INITIALIZED });
            } else {
                (unsafe { memcpy(
                    ((*data).req.upload_fromhere).offset(nread as isize) as *mut libc::c_void,
                    endofline_network as *const libc::c_void,
                    strlen(endofline_network),
                ) });
                added_crlf = 1 as i32 != 0;
            }
        }
        if (unsafe { (*data).state.trailers_state }) as u32 == TRAILERS_SENDING as i32 as u32
            && trailers_left(data as *mut libc::c_void) == 0
        {
            Curl_dyn_free(unsafe { &mut (*data).state.trailers_buf });
            (unsafe { (*data).state.trailers_state = TRAILERS_DONE });
            let mut fresh5 = unsafe { &mut ((*data).set.trailer_data) };
            *fresh5 = 0 as *mut libc::c_void;
            let mut fresh6 = unsafe { &mut ((*data).set.trailer_callback) };
            *fresh6 = None;
            let mut fresh7 = unsafe { &mut ((*data).req) };
            (*fresh7).set_upload_done(1 as i32 as bit);
            (unsafe { Curl_infof(
                data,
                b"Signaling end of chunked upload after trailers.\0" as *const u8 as *const i8,
            ) });
        } else if nread.wrapping_sub(hexlen as u64) == 0 as i32 as u64
            && (unsafe { (*data).state.trailers_state }) as u32 != TRAILERS_INITIALIZED as i32 as u32
        {
            let mut fresh8 = unsafe { &mut ((*data).req) };
            (*fresh8).set_upload_done(1 as i32 as bit);
            (unsafe { Curl_infof(
                data,
                b"Signaling end of chunked upload via terminating chunk.\0" as *const u8
                    as *const i8,
            ) });
        }
        if added_crlf {
            nread = (nread as u64).wrapping_add(unsafe { strlen(endofline_network) }) as size_t as size_t;
        }
    }
    *(borrow_mut(&mut nreadp)).unwrap() = nread;
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_readrewind(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut mimepart: *mut crate::src::lib::http2::curl_mimepart = unsafe { &mut (*data).set.mimepost };
    let mut fresh9 = unsafe { &mut ((*conn).bits) };
    (*fresh9).set_rewindaftersend(0 as i32 as bit);
    (unsafe { (*data).req.keepon &= !((1 as i32) << 1 as i32) });
    if (unsafe { (*(*conn).handler).protocol }) & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32 != 0 {
        let mut http: *mut crate::src::lib::http2::HTTP = unsafe { (*data).req.p.http };
        if !(unsafe { (*http).sendit }).is_null() {
            mimepart = unsafe { (*http).sendit };
        }
    }
    if (unsafe { (*data).set.postfields }).is_null() {
        if (unsafe { (*data).state.httpreq }) as u32 == HTTPREQ_POST_MIME as i32 as u32
            || (unsafe { (*data).state.httpreq }) as u32 == HTTPREQ_POST_FORM as i32 as u32
        {
            let mut result: u32 = Curl_mime_rewind(mimepart);
            if result as u64 != 0 {
                (unsafe { Curl_failf(
                    data,
                    b"Cannot rewind mime/post data\0" as *const u8 as *const i8,
                ) });
                return result;
            }
        } else if unsafe { ((*data).set.seek_func).is_some() } {
            let mut err: i32 = 0;
            Curl_set_in_callback(data, 1 as i32 != 0);
            err = unsafe { ((*data).set.seek_func).expect("non-null function pointer")(
                (*data).set.seek_client,
                0 as i32 as curl_off_t,
                0 as i32,
            ) };
            Curl_set_in_callback(data, 0 as i32 != 0);
            if err != 0 {
                (unsafe { Curl_failf(
                    data,
                    b"seek callback returned error %d\0" as *const u8 as *const i8,
                    err,
                ) });
                return CURLE_SEND_FAIL_REWIND;
            }
        } else if unsafe { ((*data).set.ioctl_func).is_some() } {
            let mut err_0: u32 = CURLIOE_OK;
            Curl_set_in_callback(data, 1 as i32 != 0);
            err_0 = unsafe { ((*data).set.ioctl_func).expect("non-null function pointer")(
                data,
                CURLIOCMD_RESTARTREAD as i32,
                (*data).set.ioctl_client,
            ) };
            Curl_set_in_callback(data, 0 as i32 != 0);
            (unsafe { Curl_infof(
                data,
                b"the ioctl callback returned %d\0" as *const u8 as *const i8,
                err_0 as i32,
            ) });
            if err_0 as u64 != 0 {
                (unsafe { Curl_failf(
                    data,
                    b"ioctl callback returned error %d\0" as *const u8 as *const i8,
                    err_0 as i32,
                ) });
                return CURLE_SEND_FAIL_REWIND;
            }
        } else {
            if (unsafe { (*data).state.fread_func }).map(|f| f as usize)
                == (unsafe { core::intrinsics::transmute::<
                    Option<
                        unsafe extern "C" fn(
                            _: *mut core::ffi::c_void,
                            _: u64,
                            _: u64,
                            _: *mut crate::src::lib::http2::_IO_FILE,
                        ) -> u64,
                    >,
                    Option<
                        unsafe extern "C" fn(
                            _: *mut i8,
                            _: u64,
                            _: u64,
                            _: *mut core::ffi::c_void,
                        ) -> u64,
                    >,
                >(Some(fread)) })
                .map(|f| f as usize)
            {
                if -(1 as i32) != (unsafe { fseek((*data).state.in_0 as *mut FILE, 0 as i32 as i64, 0 as i32) })
                {
                    return CURLE_OK;
                }
            }
            (unsafe { Curl_failf(
                data,
                b"necessary data rewind wasn't possible\0" as *const u8 as *const i8,
            ) });
            return CURLE_SEND_FAIL_REWIND;
        }
    }
    return CURLE_OK;
}
extern "C" fn data_pending(mut data: *const crate::src::lib::http2::Curl_easy) -> i32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    if (unsafe { (*(*conn).handler).protocol }) & ((1 as i32) << 2 as i32 | (1 as i32) << 3 as i32) as u32 != 0 {
        return Curl_ssl_data_pending(conn, 1 as i32) as i32;
    }
    return ((unsafe { (*(*conn).handler).protocol }) & ((1 as i32) << 4 as i32 | (1 as i32) << 5 as i32) as u32
        != 0
        || (unsafe { (*(*conn).handler).protocol }) & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32
            != 0
            && (unsafe { (*conn).httpversion }) as i32 >= 20 as i32
        || Curl_ssl_data_pending(conn, 0 as i32) as i32 != 0) as i32;
}
#[no_mangle]
pub extern "C" fn Curl_meets_timecondition(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut timeofdoc: i64,
) -> bool {
    if timeofdoc == 0 as i32 as i64 || (unsafe { (*data).set.timevalue }) == 0 as i32 as i64 {
        return 1 as i32 != 0;
    }
    match (unsafe { (*data).set.timecondition }) as u32 {
        2 => {
            if timeofdoc >= (unsafe { (*data).set.timevalue }) {
                (unsafe { Curl_infof(
                    data,
                    b"The requested document is not old enough\0" as *const u8 as *const i8,
                ) });
                let mut fresh11 = unsafe { &mut ((*data).info) };
                (*fresh11).set_timecond(1 as i32 as bit);
                return 0 as i32 != 0;
            }
        }
        1 | _ => {
            if timeofdoc <= (unsafe { (*data).set.timevalue }) {
                (unsafe { Curl_infof(
                    data,
                    b"The requested document is not new enough\0" as *const u8 as *const i8,
                ) });
                let mut fresh10 = unsafe { &mut ((*data).info) };
                (*fresh10).set_timecond(1 as i32 as bit);
                return 0 as i32 != 0;
            }
        }
    }
    return 1 as i32 != 0;
}
extern "C" fn readwrite_data<'a1, 'a2, 'a3, 'a4>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut k: Option<&'a1 mut crate::src::lib::http2::SingleRequest>,
    mut didwhat: Option<&'a2 mut i32>,
    mut done: Option<&'a3 mut bool>,
    mut comeback: Option<&'a4 mut bool>,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut nread: i64 = 0;
    let mut excess: u64 = 0 as i32 as size_t;
    let mut readmore: bool = 0 as i32 != 0;
    let mut maxloops: i32 = 100 as i32;
    let mut buf: *mut i8 = unsafe { (*data).state.buffer };
    *(borrow_mut(&mut done)).unwrap() = 0 as i32 != 0;
    *(borrow_mut(&mut comeback)).unwrap() = 0 as i32 != 0;
    loop {
        let mut is_empty_data: bool = 0 as i32 != 0;
        let mut buffersize: u64 = (unsafe { (*data).set.buffer_size }) as size_t;
        let mut bytestoread: u64 = buffersize;
        let mut is_http2: bool = (unsafe { (*(*conn).handler).protocol })
            & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32
            != 0
            && (unsafe { (*conn).httpversion }) as i32 == 20 as i32;
        if !is_http2
            && (*(borrow(&k)).unwrap()).size != -(1 as i32) as i64
            && (*(borrow(&k)).unwrap()).header() == 0
        {
            let mut totalleft: i64 =
                (*(borrow(&k)).unwrap()).size - (*(borrow(&k)).unwrap()).bytecount;
            if totalleft < bytestoread as curl_off_t {
                bytestoread = totalleft as size_t;
            }
        }
        if bytestoread != 0 {
            result = Curl_read(data, unsafe { (*conn).sockfd }, buf, bytestoread, Some(&mut nread));
            if CURLE_AGAIN as i32 as u32 == result as u32 {
                break;
            }
            if result as u32 > 0 as i32 as u32 {
                return result;
            }
        } else {
            nread = 0 as i32 as ssize_t;
        }
        if (*(borrow(&k)).unwrap()).bytecount == 0 {
            Curl_pgrsTime(data, TIMER_STARTTRANSFER);
            if (*(borrow(&k)).unwrap()).exp100 as u32 > EXP100_SEND_DATA as i32 as u32 {
                (*(borrow_mut(&mut k)).unwrap()).start100 = Curl_now();
            }
        }
        *(borrow_mut(&mut didwhat)).unwrap() |= (1 as i32) << 0 as i32;
        is_empty_data =
            if nread == 0 as i32 as i64 && (*(borrow(&k)).unwrap()).bodywrites == 0 as i32 as i64 {
                1 as i32
            } else {
                0 as i32
            } != 0;
        if (0 as i32 as i64) < nread || is_empty_data as i32 != 0 {
            (unsafe { *buf.offset(nread as isize) = 0 as i32 as i8 });
            let mut fresh12 = &mut ((*(borrow_mut(&mut k)).unwrap()).str_0);
            *fresh12 = buf;
            if unsafe { ((*(*conn).handler).readwrite).is_some() } {
                result = unsafe { ((*(*conn).handler).readwrite).expect("non-null function pointer")(
                    data,
                    conn,
                    &mut nread,
                    &mut readmore,
                ) };
                if result as u64 != 0 {
                    return result;
                }
                if readmore {
                    break;
                }
            }
            if (*(borrow(&k)).unwrap()).header() != 0 {
                let mut stop_reading: bool = 0 as i32 != 0;
                result = Curl_http_readwrite_headers(
                    data,
                    conn,
                    Some(&mut nread),
                    Some(&mut stop_reading),
                );
                if result as u64 != 0 {
                    return result;
                }
                if (unsafe { ((*(*conn).handler).readwrite).is_some() })
                    && ((*(borrow(&k)).unwrap()).maxdownload <= 0 as i32 as i64
                        && nread > 0 as i32 as i64)
                {
                    result = unsafe { ((*(*conn).handler).readwrite).expect("non-null function pointer")(
                        data,
                        conn,
                        &mut nread,
                        &mut readmore,
                    ) };
                    if result as u64 != 0 {
                        return result;
                    }
                    if readmore {
                        break;
                    }
                }
                if stop_reading {
                    if nread > 0 as i32 as i64 {
                        (unsafe { Curl_infof(
                            data,
                            b"Excess found: excess = %zd url = %s (zero-length body)\0" as *const u8
                                as *const i8,
                            nread,
                            (*data).state.up.path,
                        ) });
                    }
                    break;
                }
            }
            if (*(borrow(&k)).unwrap()).header() == 0
                && (nread > 0 as i32 as i64 || is_empty_data as i32 != 0)
            {
                if (unsafe { ((*data).set).opt_no_body() }) != 0 {
                    Curl_conncontrol(conn, 2 as i32);
                    *(borrow_mut(&mut done)).unwrap() = 1 as i32 != 0;
                    return CURLE_WEIRD_SERVER_REPLY;
                }
                if 0 as i32 as i64 == (*(borrow(&k)).unwrap()).bodywrites && !is_empty_data {
                    if (unsafe { (*(*conn).handler).protocol })
                        & ((1 as i32) << 0 as i32
                            | (1 as i32) << 1 as i32
                            | (1 as i32) << 18 as i32) as u32
                        != 0
                    {
                        result = Curl_http_firstwrite(data, conn, borrow_mut(&mut done));
                        if result as u32 != 0 || *(borrow(&done)).unwrap() as i32 != 0 {
                            return result;
                        }
                    }
                }
                let mut fresh13 = &mut ((*(borrow_mut(&mut k)).unwrap()).bodywrites);
                *fresh13 += 1;
                if (unsafe { ((*data).set).verbose() }) != 0 {
                    if (*(borrow(&k)).unwrap()).badheader as u64 != 0 {
                        Curl_debug(
                            data,
                            CURLINFO_DATA_IN,
                            Curl_dyn_ptr(unsafe { &mut (*data).state.headerb }),
                            Curl_dyn_len(unsafe { &mut (*data).state.headerb }),
                        );
                        if (*(borrow(&k)).unwrap()).badheader as u32
                            == HEADER_PARTHEADER as i32 as u32
                        {
                            Curl_debug(
                                data,
                                CURLINFO_DATA_IN,
                                (*(borrow_mut(&mut k)).unwrap()).str_0,
                                nread as size_t,
                            );
                        }
                    } else {
                        Curl_debug(
                            data,
                            CURLINFO_DATA_IN,
                            (*(borrow_mut(&mut k)).unwrap()).str_0,
                            nread as size_t,
                        );
                    }
                }
                if (*(borrow(&k)).unwrap()).chunk() != 0 {
                    let mut extra: u32 = CURLE_OK;
                    let mut res: i32 = Curl_httpchunk_read(
                        data,
                        (*(borrow_mut(&mut k)).unwrap()).str_0,
                        nread,
                        &mut nread,
                        Some(&mut extra),
                    );
                    if (CHUNKE_OK as i32) < res as i32 {
                        if CHUNKE_PASSTHRU_ERROR as i32 == res as i32 {
                            (unsafe { Curl_failf(
                                data,
                                b"Failed reading the chunked-encoded stream\0" as *const u8
                                    as *const i8,
                            ) });
                            return extra;
                        }
                        (unsafe { Curl_failf(
                            data,
                            b"%s in chunked-encoding\0" as *const u8 as *const i8,
                            Curl_chunked_strerror(res),
                        ) });
                        return CURLE_RECV_ERROR;
                    }
                    if CHUNKE_STOP as i32 == res as i32 {
                        (*(borrow_mut(&mut k)).unwrap()).keepon &= !((1 as i32) << 0 as i32);
                        if (unsafe { (*conn).chunk.datasize }) != 0 {
                            (unsafe { Curl_infof(
                                data,
                                b"Leftovers after chunking: % ldu bytes\0" as *const u8
                                    as *const i8,
                                (*conn).chunk.datasize,
                            ) });
                        }
                    }
                }
                if (*(borrow(&k)).unwrap()).badheader as u32 == HEADER_PARTHEADER as i32 as u32
                    && (*(borrow(&k)).unwrap()).ignorebody() == 0
                {
                    let mut headlen: u64 = Curl_dyn_len(unsafe { &mut (*data).state.headerb });
                    let mut fresh14 = &mut ((*(borrow_mut(&mut k)).unwrap()).bytecount);
                    *fresh14 = (*fresh14 as u64).wrapping_add(headlen) as curl_off_t as curl_off_t;
                }
                if -(1 as i32) as i64 != (*(borrow(&k)).unwrap()).maxdownload
                    && (*(borrow(&k)).unwrap()).bytecount + nread
                        >= (*(borrow(&k)).unwrap()).maxdownload
                {
                    excess = ((*(borrow(&k)).unwrap()).bytecount + nread
                        - (*(borrow(&k)).unwrap()).maxdownload)
                        as size_t;
                    if excess > 0 as i32 as u64 && (*(borrow(&k)).unwrap()).ignorebody() == 0 {
                        (unsafe { Curl_infof (data , b"Excess found in a read: excess = %zu, size = %ld, maxdownload = %ld, bytecount = %ld\0" as * const u8 as * const i8 , excess , (* (borrow (& k)) . unwrap ()) . size , (* (borrow (& k)) . unwrap ()) . maxdownload , (* (borrow (& k)) . unwrap ()) . bytecount ,) }) ;
                        Curl_conncontrol(conn, 1 as i32);
                    }
                    nread =
                        (*(borrow(&k)).unwrap()).maxdownload - (*(borrow(&k)).unwrap()).bytecount;
                    if nread < 0 as i32 as i64 {
                        nread = 0 as i32 as ssize_t;
                    }
                    (*(borrow_mut(&mut k)).unwrap()).keepon &= !((1 as i32) << 0 as i32);
                }
                let mut fresh15 = &mut ((*(borrow_mut(&mut k)).unwrap()).bytecount);
                *fresh15 += nread;
                Curl_pgrsSetDownloadCounter(data, (*(borrow_mut(&mut k)).unwrap()).bytecount);
                if (*(borrow(&k)).unwrap()).chunk() == 0
                    && (nread != 0
                        || (*(borrow(&k)).unwrap()).badheader as u32 != 0
                        || is_empty_data as i32 != 0)
                {
                    if (*(borrow(&k)).unwrap()).badheader as u32 != 0
                        && (*(borrow(&k)).unwrap()).ignorebody() == 0
                    {
                        let mut headlen_0: u64 = Curl_dyn_len(unsafe { &mut (*data).state.headerb });
                        if (*(borrow(&k)).unwrap()).maxdownload == -(1 as i32) as i64
                            || headlen_0 as curl_off_t <= (*(borrow(&k)).unwrap()).maxdownload
                        {
                            result = Curl_client_write(
                                data,
                                (1 as i32) << 0 as i32,
                                Curl_dyn_ptr(unsafe { &mut (*data).state.headerb }),
                                headlen_0,
                            );
                        } else {
                            result = Curl_client_write(
                                data,
                                (1 as i32) << 0 as i32,
                                Curl_dyn_ptr(unsafe { &mut (*data).state.headerb }),
                                (*(borrow_mut(&mut k)).unwrap()).maxdownload as size_t,
                            );
                        }
                        if result as u64 != 0 {
                            return result;
                        }
                    }
                    if ((*(borrow(&k)).unwrap()).badheader as u32) < HEADER_ALLBAD as i32 as u32 {
                        if (unsafe { ((*data).set).http_ce_skip() }) as i32 != 0
                            || ((*(borrow(&k)).unwrap()).writer_stack).is_null()
                        {
                            if (*(borrow(&k)).unwrap()).ignorebody() == 0 && nread != 0 {
                                if (unsafe { (*(*conn).handler).protocol })
                                    & ((1 as i32) << 14 as i32 | (1 as i32) << 15 as i32) as u32
                                    != 0
                                {
                                    result = Curl_pop3_write(
                                        data,
                                        (*(borrow_mut(&mut k)).unwrap()).str_0,
                                        nread as size_t,
                                    );
                                } else {
                                    result = Curl_client_write(
                                        data,
                                        (1 as i32) << 0 as i32,
                                        (*(borrow_mut(&mut k)).unwrap()).str_0,
                                        nread as size_t,
                                    );
                                }
                            }
                        } else if (*(borrow(&k)).unwrap()).ignorebody() == 0 && nread != 0 {
                            result = Curl_unencode_write(
                                data,
                                (*(borrow_mut(&mut k)).unwrap()).writer_stack,
                                (*(borrow(&k)).unwrap()).str_0,
                                nread as size_t,
                            );
                        }
                    }
                    (*(borrow_mut(&mut k)).unwrap()).badheader = HEADER_NORMAL;
                    if result as u64 != 0 {
                        return result;
                    }
                }
            }
            if (unsafe { ((*(*conn).handler).readwrite).is_some() }) && excess != 0 {
                let mut fresh16 = &mut ((*(borrow_mut(&mut k)).unwrap()).str_0);
                *fresh16 = unsafe { (*fresh16).offset(nread as isize) };
                if Some(unsafe { &mut *((*(borrow(&k)).unwrap()).str_0).offset(excess as isize) })
                    > Some(unsafe { &mut *buf.offset((*data).set.buffer_size as isize) })
                {
                    excess = (unsafe { (&mut *buf.offset((*data).set.buffer_size as isize) as *mut i8)
                        .offset_from((*(borrow(&k)).unwrap()).str_0) })
                        as i64 as size_t;
                }
                nread = excess as ssize_t;
                result = unsafe { ((*(*conn).handler).readwrite).expect("non-null function pointer")(
                    data,
                    conn,
                    &mut nread,
                    &mut readmore,
                ) };
                if result as u64 != 0 {
                    return result;
                }
                if readmore {
                    (*(borrow_mut(&mut k)).unwrap()).keepon |= (1 as i32) << 0 as i32;
                }
                break;
            } else {
                if is_empty_data {
                    (*(borrow_mut(&mut k)).unwrap()).keepon &= !((1 as i32) << 0 as i32);
                }
                if (*(borrow(&k)).unwrap()).keepon & (1 as i32) << 4 as i32 != 0 {
                    break;
                }
                if !(data_pending(data) != 0 && {
                    let mut fresh17 = maxloops;
                    maxloops = maxloops - 1;
                    fresh17 != 0
                }) {
                    break;
                }
            }
        } else {
            let _ = is_http2 as i32 != 0 && nread == 0;
            (*(borrow_mut(&mut k)).unwrap()).keepon &= !((1 as i32) << 0 as i32);
            break;
        }
    }
    if maxloops <= 0 as i32 {
        (unsafe { (*conn).cselect_bits = 0x1 as i32 });
        *(borrow_mut(&mut comeback)).unwrap() = 1 as i32 != 0;
    }
    if (*(borrow(&k)).unwrap()).keepon & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32)
        == (1 as i32) << 1 as i32
        && (unsafe { ((*conn).bits).close() }) as i32 != 0
    {
        (unsafe { Curl_infof(
            data,
            b"we are done reading and this is set to close, stop send\0" as *const u8 as *const i8,
        ) });
        (*(borrow_mut(&mut k)).unwrap()).keepon &= !((1 as i32) << 1 as i32);
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_done_sending<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut k: Option<&'a1 mut crate::src::lib::http2::SingleRequest>,
) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    (*(borrow_mut(&mut k)).unwrap()).keepon &= !((1 as i32) << 1 as i32);
    Curl_http2_done_sending(data, conn);
    if (unsafe { ((*conn).bits).rewindaftersend() }) != 0 {
        let mut result: u32 = Curl_readrewind(data);
        if result as u64 != 0 {
            return result;
        }
    }
    return CURLE_OK;
}
extern "C" fn readwrite_upload<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut didwhat: Option<&'a1 mut i32>,
) -> u32 {
    let mut i: i64 = 0;
    let mut si: i64 = 0;
    let mut bytes_written: i64 = 0;
    let mut result: u32 = CURLE_OK;
    let mut nread: i64 = 0;
    let mut sending_http_headers: bool = 0 as i32 != 0;
    let mut k: Option<&'_ mut crate::src::lib::http2::SingleRequest> = Some(unsafe { &mut (*data).req });
    if (*(borrow(&k)).unwrap()).bytecount == 0 as i32 as i64
        && (*(borrow(&k)).unwrap()).writebytecount == 0 as i32 as i64
    {
        Curl_pgrsTime(data, TIMER_STARTTRANSFER);
    }
    *(borrow_mut(&mut didwhat)).unwrap() |= (1 as i32) << 1 as i32;
    let mut current_block_91: u64;
    let mut nbody: i64 = 0;
    if 0 as i32 as i64 == (*(borrow(&k)).unwrap()).upload_present {
        result = Curl_get_upload_buffer(data);
        if result as u64 != 0 {
            return result;
        }
        let mut fresh18 = &mut ((*(borrow_mut(&mut k)).unwrap()).upload_fromhere);
        *fresh18 = unsafe { (*data).state.ulbuf };
        if (*(borrow(&k)).unwrap()).upload_done() == 0 {
            let mut fillcount: u64 = 0;
            let mut http: *mut crate::src::lib::http2::HTTP =
                unsafe { (*(borrow_mut(&mut k)).unwrap()).p.http };
            if (*(borrow(&k)).unwrap()).exp100 as u32 == EXP100_SENDING_REQUEST as i32 as u32
                && (unsafe { (*http).sending }) as u32 == HTTPSEND_BODY as i32 as u32
            {
                (*(borrow_mut(&mut k)).unwrap()).exp100 = EXP100_AWAITING_CONTINUE;
                (*(borrow_mut(&mut k)).unwrap()).keepon &= !((1 as i32) << 1 as i32);
                (*(borrow_mut(&mut k)).unwrap()).start100 = Curl_now();
                *(borrow_mut(&mut didwhat)).unwrap() &= !((1 as i32) << 1 as i32);
                Curl_expire(data, unsafe { (*data).set.expect_100_timeout }, EXPIRE_100_TIMEOUT);
                current_block_91 = 7416055328783156979;
            } else {
                if (unsafe { (*(*conn).handler).protocol })
                    & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32 | (1 as i32) << 18 as i32)
                        as u32
                    != 0
                {
                    if (unsafe { (*http).sending }) as u32 == HTTPSEND_REQUEST as i32 as u32 {
                        sending_http_headers = 1 as i32 != 0;
                    } else {
                        sending_http_headers = 0 as i32 != 0;
                    }
                }
                result = Curl_fillreadbuffer(
                    data,
                    (unsafe { (*data).set.upload_buffer_size }) as size_t,
                    Some(&mut fillcount),
                );
                if result as u64 != 0 {
                    return result;
                }
                nread = fillcount as ssize_t;
                current_block_91 = 16924917904204750491;
            }
        } else {
            nread = 0 as i32 as ssize_t;
            current_block_91 = 16924917904204750491;
        }
        match current_block_91 {
            7416055328783156979 => {}
            _ => {
                if nread == 0 && (*(borrow(&k)).unwrap()).keepon & (1 as i32) << 5 as i32 != 0 {
                    current_block_91 = 7416055328783156979;
                } else if nread <= 0 as i32 as i64 {
                    result = Curl_done_sending(data, borrow_mut(&mut k));
                    if result as u64 != 0 {
                        return result;
                    }
                    current_block_91 = 7416055328783156979;
                } else {
                    (*(borrow_mut(&mut k)).unwrap()).upload_present = nread;
                    if !sending_http_headers
                        && ((unsafe { ((*data).state).prefer_ascii() }) as i32 != 0
                            || (unsafe { ((*data).set).crlf() }) as i32 != 0)
                    {
                        if (unsafe { (*data).state.scratch }).is_null() {
                            let mut fresh19 = unsafe { &mut ((*data).state.scratch) };
                            *fresh19 = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
                                (2 as i32 as u32).wrapping_mul((*data).set.upload_buffer_size)
                                    as size_t,
                            ) }) as *mut i8;
                            if (unsafe { (*data).state.scratch }).is_null() {
                                (unsafe { Curl_failf(
                                    data,
                                    b"Failed to alloc scratch buffer!\0" as *const u8 as *const i8,
                                ) });
                                return CURLE_OUT_OF_MEMORY;
                            }
                        }
                        i = 0 as i32 as ssize_t;
                        si = 0 as i32 as ssize_t;
                        while i < nread {
                            if (unsafe { *((*(borrow(&k)).unwrap()).upload_fromhere).offset(i as isize) }) as i32
                                == 0xa as i32
                            {
                                let mut fresh20 = si;
                                si = si + 1;
                                (unsafe { *((*data).state.scratch).offset(fresh20 as isize) =
                                    0xd as i32 as i8 });
                                (unsafe { *((*data).state.scratch).offset(si as isize) = 0xa as i32 as i8 });
                                if (unsafe { ((*data).set).crlf() }) == 0 {
                                    if (unsafe { (*data).state.infilesize }) != -(1 as i32) as i64 {
                                        let mut fresh21 = unsafe { &mut ((*data).state.infilesize) };
                                        *fresh21 += 1;
                                    }
                                }
                            } else {
                                (unsafe { *((*data).state.scratch).offset(si as isize) =
                                    *((*(borrow(&k)).unwrap()).upload_fromhere).offset(i as isize) });
                            }
                            i += 1;
                            si += 1;
                        }
                        if si != nread {
                            nread = si;
                            let mut fresh22 =
                                &mut ((*(borrow_mut(&mut k)).unwrap()).upload_fromhere);
                            *fresh22 = unsafe { (*data).state.scratch };
                            (*(borrow_mut(&mut k)).unwrap()).upload_present = nread;
                        }
                    }
                    if (unsafe { (*(*conn).handler).protocol })
                        & ((1 as i32) << 16 as i32 | (1 as i32) << 17 as i32) as u32
                        != 0
                    {
                        result = Curl_smtp_escape_eob(data, nread);
                        if result as u64 != 0 {
                            return result;
                        }
                    }
                    current_block_91 = 981995395831942902;
                }
            }
        }
    } else {
        current_block_91 = 981995395831942902;
    }
    match current_block_91 {
        981995395831942902 => {
            result = Curl_write(
                data,
                unsafe { (*conn).writesockfd },
                (*(borrow(&k)).unwrap()).upload_fromhere as *const libc::c_void,
                (*(borrow_mut(&mut k)).unwrap()).upload_present as size_t,
                Some(&mut bytes_written),
            );
            if result as u64 != 0 {
                return result;
            }
            if (*(borrow(&k)).unwrap()).pendingheader != 0 {
                let mut n: i64 = if (*(borrow(&k)).unwrap()).pendingheader < bytes_written {
                    (*(borrow_mut(&mut k)).unwrap()).pendingheader
                } else {
                    bytes_written
                };
                Curl_debug(
                    data,
                    CURLINFO_HEADER_OUT,
                    (*(borrow_mut(&mut k)).unwrap()).upload_fromhere,
                    n as size_t,
                );
                let mut fresh23 = &mut ((*(borrow_mut(&mut k)).unwrap()).pendingheader);
                *fresh23 -= n;
                nbody = bytes_written - n;
            } else {
                nbody = bytes_written;
            }
            if nbody != 0 {
                Curl_debug(
                    data,
                    CURLINFO_DATA_OUT,
                    unsafe { &mut *((*(borrow(&k)).unwrap()).upload_fromhere)
                        .offset((bytes_written - nbody) as isize) },
                    nbody as size_t,
                );
                let mut fresh24 = &mut ((*(borrow_mut(&mut k)).unwrap()).writebytecount);
                *fresh24 += nbody;
                Curl_pgrsSetUploadCounter(data, (*(borrow_mut(&mut k)).unwrap()).writebytecount);
            }
            if ((*(borrow(&k)).unwrap()).upload_chunky() == 0
                || (*(borrow(&k)).unwrap()).forbidchunk() as i32 != 0)
                && (*(borrow(&k)).unwrap()).writebytecount == (unsafe { (*data).state.infilesize })
            {
                (*(borrow_mut(&mut k)).unwrap()).set_upload_done(1 as i32 as bit);
                (unsafe { Curl_infof(
                    data,
                    b"We are completely uploaded and fine\0" as *const u8 as *const i8,
                ) });
            }
            if (*(borrow(&k)).unwrap()).upload_present != bytes_written {
                let mut fresh25 = &mut ((*(borrow_mut(&mut k)).unwrap()).upload_present);
                *fresh25 -= bytes_written;
                let mut fresh26 = &mut ((*(borrow_mut(&mut k)).unwrap()).upload_fromhere);
                *fresh26 = unsafe { (*fresh26).offset(bytes_written as isize) };
            } else {
                result = Curl_get_upload_buffer(data);
                if result as u64 != 0 {
                    return result;
                }
                let mut fresh27 = &mut ((*(borrow_mut(&mut k)).unwrap()).upload_fromhere);
                *fresh27 = unsafe { (*data).state.ulbuf };
                (*(borrow_mut(&mut k)).unwrap()).upload_present = 0 as i32 as ssize_t;
                if (*(borrow(&k)).unwrap()).upload_done() != 0 {
                    result = Curl_done_sending(data, borrow_mut(&mut k));
                    if result as u64 != 0 {
                        return result;
                    }
                }
            }
        }
        _ => {}
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_readwrite<'a1, 'a2>(
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut done: Option<&'a1 mut bool>,
    mut comeback: Option<&'a2 mut bool>,
) -> u32 {
    let mut k: Option<&'_ mut crate::src::lib::http2::SingleRequest> = Some(unsafe { &mut (*data).req });
    let mut result: u32 = CURLE_OK;
    let mut didwhat: i32 = 0 as i32;
    let mut fd_read: i32 = 0;
    let mut fd_write: i32 = 0;
    let mut select_res: i32 = unsafe { (*conn).cselect_bits };
    (unsafe { (*conn).cselect_bits = 0 as i32 });
    if (*(borrow(&k)).unwrap()).keepon
        & ((1 as i32) << 0 as i32 | (1 as i32) << 2 as i32 | (1 as i32) << 4 as i32)
        == (1 as i32) << 0 as i32
    {
        fd_read = unsafe { (*conn).sockfd };
    } else {
        fd_read = -(1 as i32);
    }
    if (*(borrow(&k)).unwrap()).keepon
        & ((1 as i32) << 1 as i32 | (1 as i32) << 3 as i32 | (1 as i32) << 5 as i32)
        == (1 as i32) << 1 as i32
    {
        fd_write = unsafe { (*conn).writesockfd };
    } else {
        fd_write = -(1 as i32);
    }
    if (unsafe { (*data).state.drain }) != 0 {
        select_res |= 0x1 as i32;
    }
    if select_res == 0 {
        select_res = Curl_socket_check(fd_read, -(1 as i32), fd_write, 0 as i32 as timediff_t);
    }
    if select_res == 0x4 as i32 {
        (unsafe { Curl_failf(
            data,
            b"select/poll returned error\0" as *const u8 as *const i8,
        ) });
        return CURLE_SEND_ERROR;
    }
    if (*(borrow(&k)).unwrap()).keepon & (1 as i32) << 0 as i32 != 0 && select_res & 0x1 as i32 != 0
    {
        result = readwrite_data(
            data,
            conn,
            borrow_mut(&mut k),
            Some(&mut didwhat),
            borrow_mut(&mut done),
            borrow_mut(&mut comeback),
        );
        if result as u32 != 0 || *(borrow(&done)).unwrap() as i32 != 0 {
            return result;
        }
    }
    if (*(borrow(&k)).unwrap()).keepon & (1 as i32) << 1 as i32 != 0 && select_res & 0x2 as i32 != 0
    {
        result = readwrite_upload(data, conn, Some(&mut didwhat));
        if result as u64 != 0 {
            return result;
        }
    }
    (*(borrow_mut(&mut k)).unwrap()).now = Curl_now();
    if didwhat == 0 {
        if (*(borrow(&k)).unwrap()).exp100 as u32 == EXP100_AWAITING_CONTINUE as i32 as u32 {
            let mut ms: i64 = Curl_timediff(
                (*(borrow_mut(&mut k)).unwrap()).now,
                (*(borrow_mut(&mut k)).unwrap()).start100,
            );
            if ms >= (unsafe { (*data).set.expect_100_timeout }) {
                (*(borrow_mut(&mut k)).unwrap()).exp100 = EXP100_SEND_DATA;
                (*(borrow_mut(&mut k)).unwrap()).keepon |= (1 as i32) << 1 as i32;
                Curl_expire_done(data, EXPIRE_100_TIMEOUT);
                (unsafe { Curl_infof(
                    data,
                    b"Done waiting for 100-continue\0" as *const u8 as *const i8,
                ) });
            }
        }
    }
    if Curl_pgrsUpdate(data) != 0 {
        result = CURLE_ABORTED_BY_CALLBACK;
    } else {
        result = Curl_speedcheck(data, (*(borrow_mut(&mut k)).unwrap()).now);
    }
    if result as u64 != 0 {
        return result;
    }
    if (*(borrow(&k)).unwrap()).keepon != 0 {
        if 0 as i32 as i64
            > Curl_timeleft(
                data,
                &mut (*(borrow_mut(&mut k)).unwrap()).now,
                0 as i32 != 0,
            )
        {
            if (*(borrow(&k)).unwrap()).size != -(1 as i32) as i64 {
                (unsafe { Curl_failf (data , b"Operation timed out after %ld milliseconds with %ld out of %ld bytes received\0" as * const u8 as * const i8 , Curl_timediff ((* (borrow_mut (& mut k)) . unwrap ()) . now , (* data) . progress . t_startsingle) , (* (borrow (& k)) . unwrap ()) . bytecount , (* (borrow (& k)) . unwrap ()) . size ,) }) ;
            } else {
                (unsafe { Curl_failf(
                    data,
                    b"Operation timed out after %ld milliseconds with %ld bytes received\0"
                        as *const u8 as *const i8,
                    Curl_timediff(
                        (*(borrow_mut(&mut k)).unwrap()).now,
                        (*data).progress.t_startsingle,
                    ),
                    (*(borrow(&k)).unwrap()).bytecount,
                ) });
            }
            return CURLE_OPERATION_TIMEDOUT;
        }
    } else {
        if (unsafe { ((*data).set).opt_no_body() }) == 0
            && (*(borrow(&k)).unwrap()).size != -(1 as i32) as i64
            && (*(borrow(&k)).unwrap()).bytecount != (*(borrow(&k)).unwrap()).size
            && (*(borrow(&k)).unwrap()).bytecount
                != (*(borrow(&k)).unwrap()).size + (unsafe { (*data).state.crlf_conversions })
            && ((*(borrow(&k)).unwrap()).newurl).is_null()
        {
            (unsafe { Curl_failf(
                data,
                b"transfer closed with %ld bytes remaining to read\0" as *const u8 as *const i8,
                (*(borrow(&k)).unwrap()).size - (*(borrow(&k)).unwrap()).bytecount,
            ) });
            return CURLE_PARTIAL_FILE;
        }
        if (unsafe { ((*data).set).opt_no_body() }) == 0
            && (*(borrow(&k)).unwrap()).chunk() as i32 != 0
            && (unsafe { (*conn).chunk.state }) as u32 != CHUNK_STOP as i32 as u32
        {
            (unsafe { Curl_failf(
                data,
                b"transfer closed with outstanding read data remaining\0" as *const u8 as *const i8,
            ) });
            return CURLE_PARTIAL_FILE;
        }
        if Curl_pgrsUpdate(data) != 0 {
            return CURLE_ABORTED_BY_CALLBACK;
        }
    }
    *(borrow_mut(&mut done)).unwrap() = if 0 as i32
        == (*(borrow(&k)).unwrap()).keepon
            & ((1 as i32) << 0 as i32
                | (1 as i32) << 1 as i32
                | (1 as i32) << 4 as i32
                | (1 as i32) << 5 as i32)
    {
        1 as i32
    } else {
        0 as i32
    } != 0;
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_single_getsock(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut sock: *mut i32,
) -> i32 {
    let mut bitmap: i32 = 0 as i32;
    let mut sockindex: u32 = 0 as i32 as u32;
    if unsafe { ((*(*conn).handler).perform_getsock).is_some() } {
        return unsafe { ((*(*conn).handler).perform_getsock).expect("non-null function pointer")(
            data, conn, sock,
        ) };
    }
    if (unsafe { (*data).req.keepon })
        & ((1 as i32) << 0 as i32 | (1 as i32) << 2 as i32 | (1 as i32) << 4 as i32)
        == (1 as i32) << 0 as i32
    {
        bitmap |= (1 as i32) << sockindex;
        (unsafe { *sock.offset(sockindex as isize) = (*conn).sockfd });
    }
    if (unsafe { (*data).req.keepon })
        & ((1 as i32) << 1 as i32 | (1 as i32) << 3 as i32 | (1 as i32) << 5 as i32)
        == (1 as i32) << 1 as i32
    {
        if (unsafe { (*conn).sockfd }) != (unsafe { (*conn).writesockfd }) || bitmap == 0 as i32 {
            if bitmap != 0 as i32 {
                sockindex = sockindex.wrapping_add(1);
            }
            (unsafe { *sock.offset(sockindex as isize) = (*conn).writesockfd });
        }
        bitmap |= (1 as i32) << (16 as i32 as u32).wrapping_add(sockindex);
    }
    return bitmap;
}
#[no_mangle]
pub extern "C" fn Curl_init_CONNECT(mut data: *mut crate::src::lib::http2::Curl_easy) {
    let mut fresh28 = unsafe { &mut ((*data).state.fread_func) };
    *fresh28 = unsafe { (*data).set.fread_func_set };
    let mut fresh29 = unsafe { &mut ((*data).state.in_0) };
    *fresh29 = unsafe { (*data).set.in_set };
}
#[no_mangle]
pub extern "C" fn Curl_pretransfer(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut result: u32 = CURLE_OK;
    if (unsafe { (*data).state.url }).is_null() && (unsafe { (*data).set.uh }).is_null() {
        (unsafe { Curl_failf(data, b"No URL set!\0" as *const u8 as *const i8) });
        return CURLE_URL_MALFORMAT;
    }
    if (unsafe { ((*data).state).url_alloc() }) != 0 {
        (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.url as *mut libc::c_void) });
        let mut fresh30 = unsafe { &mut ((*data).state.url) };
        *fresh30 = 0 as *mut i8;
        let mut fresh31 = unsafe { &mut ((*data).state) };
        (*fresh31).set_url_alloc(0 as i32 as bit);
    }
    if (unsafe { (*data).state.url }).is_null() && !(unsafe { (*data).set.uh }).is_null() {
        let mut uc: u32 = CURLUE_OK;
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            (*data).set.str_0[STRING_SET_URL as i32 as usize] as *mut libc::c_void,
        ) });
        uc = curl_url_get(
            unsafe { (*data).set.uh },
            CURLUPART_URL,
            Some(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SET_URL as i32 as isize) },
            ),
            0 as i32 as u32,
        );
        if uc as u64 != 0 {
            (unsafe { Curl_failf(data, b"No URL set!\0" as *const u8 as *const i8) });
            return CURLE_URL_MALFORMAT;
        }
    }
    let mut fresh32 = unsafe { &mut ((*data).state) };
    (*fresh32).set_prefer_ascii(unsafe { ((*data).set).prefer_ascii() });
    let mut fresh33 = unsafe { &mut ((*data).state) };
    (*fresh33).set_list_only(unsafe { ((*data).set).list_only() });
    (unsafe { (*data).state.httpreq = (*data).set.method });
    let mut fresh34 = unsafe { &mut ((*data).state.url) };
    *fresh34 = unsafe { (*data).set.str_0[STRING_SET_URL as i32 as usize] };
    result = Curl_ssl_initsessions(data, unsafe { (*data).set.general_ssl.max_ssl_sessions });
    if result as u64 != 0 {
        return result;
    }
    let mut fresh35 = unsafe { &mut ((*data).state) };
    (*fresh35).set_wildcardmatch(unsafe { ((*data).set).wildcard_enabled() });
    (unsafe { (*data).state.followlocation = 0 as i32 as i64 });
    let mut fresh36 = unsafe { &mut ((*data).state) };
    (*fresh36).set_this_is_a_follow(0 as i32 as bit);
    let mut fresh37 = unsafe { &mut ((*data).state) };
    (*fresh37).set_errorbuf(0 as i32 as bit);
    (unsafe { (*data).state.httpwant = (*data).set.httpwant });
    (unsafe { (*data).state.httpversion = 0 as i32 as u8 });
    let mut fresh38 = unsafe { &mut ((*data).state) };
    (*fresh38).set_authproblem(0 as i32 as bit);
    (unsafe { (*data).state.authhost.want = (*data).set.httpauth });
    (unsafe { (*data).state.authproxy.want = (*data).set.proxyauth });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).info.wouldredirect as *mut libc::c_void) });
    let mut fresh39 = unsafe { &mut ((*data).info.wouldredirect) };
    *fresh39 = 0 as *mut i8;
    if (unsafe { (*data).state.httpreq }) as u32 == HTTPREQ_PUT as i32 as u32 {
        (unsafe { (*data).state.infilesize = (*data).set.filesize });
    } else if (unsafe { (*data).state.httpreq }) as u32 != HTTPREQ_GET as i32 as u32
        && (unsafe { (*data).state.httpreq }) as u32 != HTTPREQ_HEAD as i32 as u32
    {
        (unsafe { (*data).state.infilesize = (*data).set.postfieldsize });
        if !(unsafe { (*data).set.postfields }).is_null() && (unsafe { (*data).state.infilesize }) == -(1 as i32) as i64 {
            (unsafe { (*data).state.infilesize = strlen((*data).set.postfields as *const i8) as curl_off_t });
        }
    } else {
        (unsafe { (*data).state.infilesize = 0 as i32 as curl_off_t });
    }
    if !(unsafe { (*data).state.cookielist }).is_null() {
        Curl_cookie_loadfiles(data);
    }
    if !(unsafe { (*data).state.resolve }).is_null() {
        result = Curl_loadhostpairs(data);
    }
    if result as u64 == 0 {
        let mut fresh40 = unsafe { &mut ((*data).state) };
        (*fresh40).set_allow_port(1 as i32 as bit);
        Curl_initinfo(data);
        Curl_pgrsResetTransferSizes(data);
        Curl_pgrsStartNow(data);
        (unsafe { (*data).state.authhost.picked &= (*data).state.authhost.want });
        (unsafe { (*data).state.authproxy.picked &= (*data).state.authproxy.want });
        if (unsafe { ((*data).state).wildcardmatch() }) != 0 {
            let mut wc: Option<&'_ mut crate::src::lib::http2::WildcardData> =
                Some(unsafe { &mut (*data).wildcard });
            if ((*(borrow(&wc)).unwrap()).state as u32) < CURLWC_INIT as i32 as u32 {
                result = Curl_wildcard_init(borrow_mut(&mut wc));
                if result as u64 != 0 {
                    return CURLE_OUT_OF_MEMORY;
                }
            }
        }
        Curl_http2_init_state(Some(unsafe { &mut (*data).state }));
        result = Curl_hsts_loadcb(data, unsafe { (*data).hsts });
    }
    if !(unsafe { (*data).set.str_0[STRING_USERAGENT as i32 as usize] }).is_null() {
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            (*data).state.aptr.uagent as *mut libc::c_void,
        ) });
        let mut fresh41 = unsafe { &mut ((*data).state.aptr.uagent) };
        *fresh41 = 0 as *mut i8;
        let mut fresh42 = unsafe { &mut ((*data).state.aptr.uagent) };
        *fresh42 = unsafe { curl_maprintf(
            b"User-Agent: %s\r\n\0" as *const u8 as *const i8,
            (*data).set.str_0[STRING_USERAGENT as i32 as usize],
        ) };
        if (unsafe { (*data).state.aptr.uagent }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if result as u64 == 0 {
        result = Curl_setstropt(
            Some(unsafe { &mut (*data).state.aptr.user }),
            unsafe { (*data).set.str_0[STRING_USERNAME as i32 as usize] },
        );
    }
    if result as u64 == 0 {
        result = Curl_setstropt(
            Some(unsafe { &mut (*data).state.aptr.passwd }),
            unsafe { (*data).set.str_0[STRING_PASSWORD as i32 as usize] },
        );
    }
    if result as u64 == 0 {
        result = Curl_setstropt(
            Some(unsafe { &mut (*data).state.aptr.proxyuser }),
            unsafe { (*data).set.str_0[STRING_PROXYUSERNAME as i32 as usize] },
        );
    }
    if result as u64 == 0 {
        result = Curl_setstropt(
            Some(unsafe { &mut (*data).state.aptr.proxypasswd }),
            unsafe { (*data).set.str_0[STRING_PROXYPASSWORD as i32 as usize] },
        );
    }
    (unsafe { (*data).req.headerbytecount = 0 as i32 as curl_off_t });
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_posttransfer(mut _data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_follow(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut newurl: *mut i8,
    mut type_0: u32,
) -> u32 {
    let mut disallowport: bool = 0 as i32 != 0;
    let mut reachedmax: bool = 0 as i32 != 0;
    let mut uc: u32 = CURLUE_OK;
    if type_0 as u32 == FOLLOW_REDIR as i32 as u32 {
        if (unsafe { (*data).set.maxredirs }) != -(1 as i32) as i64
            && (unsafe { (*data).state.followlocation }) >= (unsafe { (*data).set.maxredirs })
        {
            reachedmax = 1 as i32 != 0;
            type_0 = FOLLOW_FAKE;
        } else {
            let mut fresh43 = unsafe { &mut ((*data).state) };
            (*fresh43).set_this_is_a_follow(1 as i32 as bit);
            let mut fresh44 = unsafe { &mut ((*data).state.followlocation) };
            *fresh44 += 1;
            if (unsafe { ((*data).set).http_auto_referer() }) != 0 {
                let mut u: *mut crate::src::lib::urlapi::Curl_URL = 0 as *mut CURLU;
                let mut referer: *mut i8 = 0 as *mut i8;
                if (unsafe { ((*data).state).referer_alloc() }) != 0 {
                    (unsafe { Curl_cfree.expect("non-null function pointer")(
                        (*data).state.referer as *mut libc::c_void,
                    ) });
                    let mut fresh45 = unsafe { &mut ((*data).state.referer) };
                    *fresh45 = 0 as *mut i8;
                    let mut fresh46 = unsafe { &mut ((*data).state) };
                    (*fresh46).set_referer_alloc(0 as i32 as bit);
                }
                u = curl_url();
                if u.is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
                uc = curl_url_set(u, CURLUPART_URL, unsafe { (*data).state.url }, 0 as i32 as u32);
                if uc as u64 == 0 {
                    uc = curl_url_set(u, CURLUPART_FRAGMENT, 0 as *const i8, 0 as i32 as u32);
                }
                if uc as u64 == 0 {
                    uc = curl_url_set(u, CURLUPART_USER, 0 as *const i8, 0 as i32 as u32);
                }
                if uc as u64 == 0 {
                    uc = curl_url_set(u, CURLUPART_PASSWORD, 0 as *const i8, 0 as i32 as u32);
                }
                if uc as u64 == 0 {
                    uc = curl_url_get(u, CURLUPART_URL, Some(&mut referer), 0 as i32 as u32);
                }
                curl_url_cleanup(u);
                if uc as u32 != 0 || referer.is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
                let mut fresh47 = unsafe { &mut ((*data).state.referer) };
                *fresh47 = referer;
                let mut fresh48 = unsafe { &mut ((*data).state) };
                (*fresh48).set_referer_alloc(1 as i32 as bit);
            }
        }
    }
    if type_0 as u32 != FOLLOW_RETRY as i32 as u32
        && (unsafe { (*data).req.httpcode }) != 401 as i32
        && (unsafe { (*data).req.httpcode }) != 407 as i32
        && Curl_is_absolute_url(newurl, 0 as *mut i8, 40 as i32 as size_t) as i32 != 0
    {
        disallowport = 1 as i32 != 0;
    }
    uc = curl_url_set(
        unsafe { (*data).state.uh },
        CURLUPART_URL,
        newurl,
        (if type_0 as u32 == FOLLOW_FAKE as i32 as u32 {
            (1 as i32) << 3 as i32
        } else {
            (if type_0 as u32 == FOLLOW_REDIR as i32 as u32 {
                (1 as i32) << 7 as i32
            } else {
                0 as i32
            }) | (1 as i32) << 11 as i32
        }) as u32,
    );
    if uc as u64 != 0 {
        if type_0 as u32 != FOLLOW_FAKE as i32 as u32 {
            return Curl_uc_to_curlcode(uc);
        }
        newurl = unsafe { Curl_cstrdup.expect("non-null function pointer")(newurl) };
        if newurl.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    } else {
        uc = curl_url_get(
            unsafe { (*data).state.uh },
            CURLUPART_URL,
            Some(&mut newurl),
            0 as i32 as u32,
        );
        if uc as u64 != 0 {
            return Curl_uc_to_curlcode(uc);
        }
    }
    if type_0 as u32 == FOLLOW_FAKE as i32 as u32 {
        let mut fresh49 = unsafe { &mut ((*data).info.wouldredirect) };
        *fresh49 = newurl;
        if reachedmax {
            (unsafe { Curl_failf(
                data,
                b"Maximum (%ld) redirects followed\0" as *const u8 as *const i8,
                (*data).set.maxredirs,
            ) });
            return CURLE_TOO_MANY_REDIRECTS;
        }
        return CURLE_OK;
    }
    if disallowport {
        let mut fresh50 = unsafe { &mut ((*data).state) };
        (*fresh50).set_allow_port(0 as i32 as bit);
    }
    if (unsafe { ((*data).state).url_alloc() }) != 0 {
        (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.url as *mut libc::c_void) });
        let mut fresh51 = unsafe { &mut ((*data).state.url) };
        *fresh51 = 0 as *mut i8;
    }
    let mut fresh52 = unsafe { &mut ((*data).state.url) };
    *fresh52 = newurl;
    let mut fresh53 = unsafe { &mut ((*data).state) };
    (*fresh53).set_url_alloc(1 as i32 as bit);
    (unsafe { Curl_infof(
        data,
        b"Issue another request to this URL: '%s'\0" as *const u8 as *const i8,
        (*data).state.url,
    ) });
    match unsafe { (*data).info.httpcode } {
        301 => {
            if ((unsafe { (*data).state.httpreq }) as u32 == HTTPREQ_POST as i32 as u32
                || (unsafe { (*data).state.httpreq }) as u32 == HTTPREQ_POST_FORM as i32 as u32
                || (unsafe { (*data).state.httpreq }) as u32 == HTTPREQ_POST_MIME as i32 as u32)
                && (unsafe { (*data).set.keep_post }) & 1 as i32 == 0
            {
                (unsafe { Curl_infof(data, b"Switch from POST to GET\0" as *const u8 as *const i8) });
                (unsafe { (*data).state.httpreq = HTTPREQ_GET });
            }
        }
        302 => {
            if ((unsafe { (*data).state.httpreq }) as u32 == HTTPREQ_POST as i32 as u32
                || (unsafe { (*data).state.httpreq }) as u32 == HTTPREQ_POST_FORM as i32 as u32
                || (unsafe { (*data).state.httpreq }) as u32 == HTTPREQ_POST_MIME as i32 as u32)
                && (unsafe { (*data).set.keep_post }) & 2 as i32 == 0
            {
                (unsafe { Curl_infof(data, b"Switch from POST to GET\0" as *const u8 as *const i8) });
                (unsafe { (*data).state.httpreq = HTTPREQ_GET });
            }
        }
        303 => {
            if (unsafe { (*data).state.httpreq }) as u32 != HTTPREQ_GET as i32 as u32
                && ((unsafe { (*data).state.httpreq }) as u32 != HTTPREQ_POST as i32 as u32
                    && (unsafe { (*data).state.httpreq }) as u32 != HTTPREQ_POST_FORM as i32 as u32
                    && (unsafe { (*data).state.httpreq }) as u32 != HTTPREQ_POST_MIME as i32 as u32
                    || (unsafe { (*data).set.keep_post }) & 4 as i32 == 0)
            {
                (unsafe { (*data).state.httpreq = HTTPREQ_GET });
                let mut fresh54 = unsafe { &mut ((*data).set) };
                (*fresh54).set_upload(0 as i32 as bit);
                (unsafe { Curl_infof(
                    data,
                    b"Switch to %s\0" as *const u8 as *const i8,
                    if ((*data).set).opt_no_body() as i32 != 0 {
                        b"HEAD\0" as *const u8 as *const i8
                    } else {
                        b"GET\0" as *const u8 as *const i8
                    },
                ) });
            }
        }
        304 => {}
        305 => {}
        _ => {}
    }
    Curl_pgrsTime(data, TIMER_REDIRECT);
    Curl_pgrsResetTransferSizes(data);
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_retry_request<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut url: Option<&'a1 mut *mut i8>,
) -> u32 {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut retry: bool = 0 as i32 != 0;
    *(borrow_mut(&mut url)).unwrap() = 0 as *mut i8;
    if (unsafe { ((*data).set).upload() }) as i32 != 0
        && (unsafe { (*(*conn).handler).protocol })
            & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32 | (1 as i32) << 18 as i32) as u32
            == 0
    {
        return CURLE_OK;
    }
    if (unsafe { (*data).req.bytecount }) + (unsafe { (*data).req.headerbytecount }) == 0 as i32 as i64
        && (unsafe { ((*conn).bits).reuse() }) as i32 != 0
        && ((unsafe { ((*data).set).opt_no_body() }) == 0
            || (unsafe { (*(*conn).handler).protocol })
                & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32
                != 0)
        && (unsafe { (*data).set.rtspreq }) as u32 != RTSPREQ_RECEIVE as i32 as u32
    {
        retry = 1 as i32 != 0;
    } else if (unsafe { ((*data).state).refused_stream() }) as i32 != 0
        && (unsafe { (*data).req.bytecount }) + (unsafe { (*data).req.headerbytecount }) == 0 as i32 as i64
    {
        (unsafe { Curl_infof(
            data,
            b"REFUSED_STREAM, retrying a fresh connect\0" as *const u8 as *const i8,
        ) });
        let mut fresh55 = unsafe { &mut ((*data).state) };
        (*fresh55).set_refused_stream(0 as i32 as bit);
        retry = 1 as i32 != 0;
    }
    if retry {
        let mut fresh56 = unsafe { &mut ((*data).state.retrycount) };
        let mut fresh57 = *fresh56;
        *fresh56 = *fresh56 + 1;
        if fresh57 >= 5 as i32 {
            (unsafe { Curl_failf(
                data,
                b"Connection died, tried %d times before giving up\0" as *const u8 as *const i8,
                5 as i32,
            ) });
            (unsafe { (*data).state.retrycount = 0 as i32 });
            return CURLE_SEND_ERROR;
        }
        (unsafe { Curl_infof(
            data,
            b"Connection died, retrying a fresh connect (retry count: %d)\0" as *const u8
                as *const i8,
            (*data).state.retrycount,
        ) });
        *(borrow_mut(&mut url)).unwrap() =
            unsafe { Curl_cstrdup.expect("non-null function pointer")((*data).state.url) };
        if (*(borrow_mut(&mut url)).unwrap()).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        Curl_conncontrol(conn, 1 as i32);
        let mut fresh58 = unsafe { &mut ((*conn).bits) };
        (*fresh58).set_retry(1 as i32 as bit);
        if (unsafe { (*(*conn).handler).protocol }) & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32
            != 0
        {
            if (unsafe { (*data).req.writebytecount }) != 0 {
                let mut result: u32 = Curl_readrewind(data);
                if result as u64 != 0 {
                    (unsafe { Curl_cfree.expect("non-null function pointer")(
                        *(borrow_mut(&mut url)).unwrap() as *mut libc::c_void,
                    ) });
                    *(borrow_mut(&mut url)).unwrap() = 0 as *mut i8;
                    return result;
                }
            }
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_setup_transfer(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut sockindex: i32,
    mut size: i64,
    mut getheader: bool,
    mut writesockindex: i32,
) {
    let mut k: Option<&'_ mut crate::src::lib::http2::SingleRequest> = Some(unsafe { &mut (*data).req });
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut http: *mut crate::src::lib::http2::HTTP = unsafe { (*data).req.p.http };
    let mut httpsending: bool =
        (unsafe { (*(*conn).handler).protocol }) & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32 != 0
            && (unsafe { (*http).sending }) as u32 == HTTPSEND_REQUEST as i32 as u32;
    if (unsafe { ((*conn).bits).multiplex() }) as i32 != 0
        || (unsafe { (*conn).httpversion }) as i32 == 20 as i32
        || httpsending as i32 != 0
    {
        (unsafe { (*conn).sockfd = if sockindex == -(1 as i32) {
            if writesockindex == -(1 as i32) {
                -(1 as i32)
            } else {
                (*conn).sock[writesockindex as usize]
            }
        } else {
            (*conn).sock[sockindex as usize]
        } });
        (unsafe { (*conn).writesockfd = (*conn).sockfd });
        if httpsending {
            writesockindex = 0 as i32;
        }
    } else {
        (unsafe { (*conn).sockfd = if sockindex == -(1 as i32) {
            -(1 as i32)
        } else {
            (*conn).sock[sockindex as usize]
        } });
        (unsafe { (*conn).writesockfd = if writesockindex == -(1 as i32) {
            -(1 as i32)
        } else {
            (*conn).sock[writesockindex as usize]
        } });
    }
    (*(borrow_mut(&mut k)).unwrap()).set_getheader(getheader as bit);
    (*(borrow_mut(&mut k)).unwrap()).size = size;
    if (*(borrow(&k)).unwrap()).getheader() == 0 {
        (*(borrow_mut(&mut k)).unwrap()).set_header(0 as i32 as bit);
        if size > 0 as i32 as i64 {
            Curl_pgrsSetDownloadSize(data, size);
        }
    }
    if (*(borrow(&k)).unwrap()).getheader() as i32 != 0 || (unsafe { ((*data).set).opt_no_body() }) == 0 {
        if sockindex != -(1 as i32) {
            (*(borrow_mut(&mut k)).unwrap()).keepon |= (1 as i32) << 0 as i32;
        }
        if writesockindex != -(1 as i32) {
            if (unsafe { ((*data).state).expect100header() }) as i32 != 0
                && (unsafe { (*(*conn).handler).protocol })
                    & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32
                    != 0
                && (unsafe { (*http).sending }) as u32 == HTTPSEND_BODY as i32 as u32
            {
                (*(borrow_mut(&mut k)).unwrap()).exp100 = EXP100_AWAITING_CONTINUE;
                (*(borrow_mut(&mut k)).unwrap()).start100 = Curl_now();
                Curl_expire(data, unsafe { (*data).set.expect_100_timeout }, EXPIRE_100_TIMEOUT);
            } else {
                if (unsafe { ((*data).state).expect100header() }) != 0 {
                    (*(borrow_mut(&mut k)).unwrap()).exp100 = EXP100_SENDING_REQUEST;
                }
                (*(borrow_mut(&mut k)).unwrap()).keepon |= (1 as i32) << 1 as i32;
            }
        }
    }
}
use crate::laertes_rt::*;
