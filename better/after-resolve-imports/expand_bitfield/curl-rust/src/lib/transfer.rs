use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn fread(
        _: *mut libc::c_void,
        _: u64,
        _: u64,
        _: *mut FILE,
    ) -> u64;
    fn fseek(
        __stream: *mut FILE,
        __off: i64,
        __whence: i32,
    ) -> i32;
    
    
    
    
    
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> *mut libc::c_void;
    fn strlen(_: *const i8) -> u64;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::connect::Curl_conncontrol;
pub use crate::src::lib::connect::Curl_timeleft;
pub use crate::src::lib::content_encoding::Curl_unencode_write;
pub use crate::src::lib::cookie::Curl_cookie_loadfiles;
pub use crate::src::lib::dynbuf::Curl_dyn_free;
pub use crate::src::lib::dynbuf::Curl_dyn_init;
pub use crate::src::lib::dynbuf::Curl_dyn_len;
pub use crate::src::lib::dynbuf::Curl_dyn_ptr;
pub use crate::src::lib::getinfo::Curl_initinfo;
pub use crate::src::lib::hostip::Curl_loadhostpairs;
pub use crate::src::lib::hsts::Curl_hsts_loadcb;
pub use crate::src::lib::http2::Curl_http2_done_sending;
pub use crate::src::lib::http2::Curl_http2_init_state;
pub use crate::src::lib::http::Curl_http_compile_trailers;
pub use crate::src::lib::http::Curl_http_firstwrite;
pub use crate::src::lib::http::Curl_http_readwrite_headers;
pub use crate::src::lib::http_chunks::Curl_chunked_strerror;
pub use crate::src::lib::http_chunks::Curl_httpchunk_read;
pub use crate::src::lib::mime::Curl_mime_rewind;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::multi::Curl_expire;
pub use crate::src::lib::multi::Curl_expire_done;
pub use crate::src::lib::multi::Curl_set_in_callback;
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
pub use crate::src::lib::smtp::Curl_smtp_escape_eob;
pub use crate::src::lib::speedcheck::Curl_speedcheck;
pub use crate::src::lib::strcase::Curl_strncasecompare;
pub use crate::src::lib::timeval::Curl_now;
pub use crate::src::lib::timeval::Curl_timediff;
pub use crate::src::lib::url::Curl_uc_to_curlcode;
pub use crate::src::lib::urlapi::Curl_is_absolute_url;
pub use crate::src::lib::urlapi::curl_url;
pub use crate::src::lib::urlapi::curl_url_cleanup;
pub use crate::src::lib::urlapi::curl_url_get;
pub use crate::src::lib::urlapi::curl_url_set;
pub use crate::src::lib::vtls::vtls::Curl_ssl_data_pending;
pub use crate::src::lib::vtls::vtls::Curl_ssl_initsessions;
pub use crate::src::lib::wildcard::Curl_wildcard_init;
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_cstrdup;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
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

pub type hsts = crate::src::lib::easy::hsts;
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
// #[derive(Copy, Clone)]

pub type contenc_writer = crate::src::lib::content_encoding::contenc_writer;
// #[derive(Copy, Clone)]

pub type content_encoding = crate::src::lib::content_encoding::content_encoding;
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
pub type C2RustUnnamed_6 = u32;
pub const CURLIOCMD_LAST: C2RustUnnamed_6 = 2;
pub const CURLIOCMD_RESTARTREAD: C2RustUnnamed_6 = 1;
pub const CURLIOCMD_NOP: C2RustUnnamed_6 = 0;
pub type curl_malloc_callback = crate::src::lib::http2::curl_malloc_callback;
pub type curl_strdup_callback = crate::src::lib::altsvc::curl_strdup_callback;
pub type CURLUcode = crate::src::lib::http2::CURLUcode;
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
pub type CURLUPart = crate::src::lib::http2::CURLUPart;
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
pub type CHUNKcode = crate::src::lib::http_chunks::CHUNKcode;
pub const CHUNKE_LAST: CHUNKcode = 7;
pub const CHUNKE_PASSTHRU_ERROR: CHUNKcode = 6;
pub const CHUNKE_OUT_OF_MEMORY: CHUNKcode = 5;
pub const CHUNKE_BAD_ENCODING: CHUNKcode = 4;
pub const CHUNKE_BAD_CHUNK: CHUNKcode = 3;
pub const CHUNKE_ILLEGAL_HEX: CHUNKcode = 2;
pub const CHUNKE_TOO_LONG_HEX: CHUNKcode = 1;
pub const CHUNKE_OK: CHUNKcode = 0;
pub const CHUNKE_STOP: CHUNKcode = -1;
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
pub type followtype = crate::src::lib::multi::followtype;
pub const FOLLOW_REDIR: followtype = 3;
pub const FOLLOW_RETRY: followtype = 2;
pub const FOLLOW_FAKE: followtype = 1;
pub const FOLLOW_NONE: followtype = 0;
pub type timerid = crate::src::lib::connect::timerid;
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
pub unsafe extern "C" fn Curl_checkheaders(
    mut data: *const Curl_easy,
    mut thisheader: *const i8,
) -> *mut i8 {
    let mut head: *mut curl_slist = 0 as *mut curl_slist;
    let mut thislen: size_t = strlen(thisheader);
    head = (*data).set.headers;
    while !head.is_null() {
        if Curl_strncasecompare((*head).data, thisheader, thislen) != 0
            && (*((*head).data).offset(thislen as isize) as i32 == ':' as i32
                || *((*head).data).offset(thislen as isize) as i32 == ';' as i32)
        {
            return (*head).data;
        }
        head = (*head).next;
    }
    return 0 as *mut i8;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_get_upload_buffer(mut data: *mut Curl_easy) -> CURLcode {
    if ((*data).state.ulbuf).is_null() {
        let ref mut fresh0 = (*data).state.ulbuf;
        *fresh0 = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )((*data).set.upload_buffer_size as size_t) as *mut i8;
        if ((*data).state.ulbuf).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
unsafe extern "C" fn trailers_read(
    mut buffer: *mut i8,
    mut size: size_t,
    mut nitems: size_t,
    mut raw: *mut libc::c_void,
) -> size_t {
    let mut data: *mut Curl_easy = raw as *mut Curl_easy;
    let mut trailers_buf: *mut dynbuf = &mut (*data).state.trailers_buf;
    let mut bytes_left: size_t = (Curl_dyn_len(trailers_buf))
        .wrapping_sub((*data).state.trailers_bytes_sent);
    let mut to_copy: size_t = if size.wrapping_mul(nitems) < bytes_left {
        size.wrapping_mul(nitems)
    } else {
        bytes_left
    };
    if to_copy != 0 {
        memcpy(
            buffer as *mut libc::c_void,
            (Curl_dyn_ptr(trailers_buf))
                .offset((*data).state.trailers_bytes_sent as isize)
                as *const libc::c_void,
            to_copy,
        );
        let ref mut fresh1 = (*data).state.trailers_bytes_sent;
        *fresh1 = (*fresh1 as u64).wrapping_add(to_copy) as size_t as size_t;
    }
    return to_copy;
}
unsafe extern "C" fn trailers_left(mut raw: *mut libc::c_void) -> size_t {
    let mut data: *mut Curl_easy = raw as *mut Curl_easy;
    let mut trailers_buf: *mut dynbuf = &mut (*data).state.trailers_buf;
    return (Curl_dyn_len(trailers_buf)).wrapping_sub((*data).state.trailers_bytes_sent);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_fillreadbuffer(
    mut data: *mut Curl_easy,
    mut bytes: size_t,
    mut nreadp: *mut size_t,
) -> CURLcode {
    let mut buffersize: size_t = bytes;
    let mut nread: size_t = 0;
    let mut readfunc: curl_read_callback = None;
    let mut extra_data: *mut libc::c_void = 0 as *mut libc::c_void;
    if (*data).state.trailers_state as u32
        == TRAILERS_INITIALIZED as i32 as u32
    {
        let mut trailers: *mut curl_slist = 0 as *mut curl_slist;
        let mut result: CURLcode = CURLE_OK;
        let mut trailers_ret_code: i32 = 0;
        Curl_infof(
            data,
            b"Moving trailers state machine from initialized to sending.\0" as *const u8
                as *const i8,
        );
        (*data).state.trailers_state = TRAILERS_SENDING;
        Curl_dyn_init(
            &mut (*data).state.trailers_buf,
            (64 as i32 * 1024 as i32) as size_t,
        );
        (*data).state.trailers_bytes_sent = 0 as i32 as size_t;
        Curl_set_in_callback(data, 1 as i32 != 0);
        trailers_ret_code = ((*data).set.trailer_callback)
            .expect(
                "non-null function pointer",
            )(&mut trailers, (*data).set.trailer_data);
        Curl_set_in_callback(data, 0 as i32 != 0);
        if trailers_ret_code == 0 as i32 {
            result = Curl_http_compile_trailers(
                trailers,
                &mut (*data).state.trailers_buf,
                data,
            );
        } else {
            Curl_failf(
                data,
                b"operation aborted by trailing headers callback\0" as *const u8
                    as *const i8,
            );
            *nreadp = 0 as i32 as size_t;
            result = CURLE_ABORTED_BY_CALLBACK;
        }
        if result as u64 != 0 {
            Curl_dyn_free(&mut (*data).state.trailers_buf);
            curl_slist_free_all(trailers);
            return result;
        }
        Curl_infof(
            data,
            b"Successfully compiled trailers.\0" as *const u8 as *const i8,
        );
        curl_slist_free_all(trailers);
    }
    if ((*data).req).upload_chunky() as i32 != 0
        && (*data).state.trailers_state as u32
            == TRAILERS_NONE as i32 as u32
    {
        buffersize = (buffersize as u64)
            .wrapping_sub(
                (8 as i32 + 2 as i32 + 2 as i32) as u64,
            ) as size_t as size_t;
        let ref mut fresh2 = (*data).req.upload_fromhere;
        *fresh2 = (*fresh2).offset((8 as i32 + 2 as i32) as isize);
    }
    if (*data).state.trailers_state as u32
        == TRAILERS_SENDING as i32 as u32
    {
        readfunc = Some(
            trailers_read
                as unsafe extern "C" fn(
                    *mut i8,
                    size_t,
                    size_t,
                    *mut libc::c_void,
                ) -> size_t,
        );
        extra_data = data as *mut libc::c_void;
    } else {
        readfunc = (*data).state.fread_func;
        extra_data = (*data).state.in_0;
    }
    Curl_set_in_callback(data, 1 as i32 != 0);
    nread = readfunc
        .expect(
            "non-null function pointer",
        )(
        (*data).req.upload_fromhere,
        1 as i32 as size_t,
        buffersize,
        extra_data,
    );
    Curl_set_in_callback(data, 0 as i32 != 0);
    if nread == 0x10000000 as i32 as u64 {
        Curl_failf(
            data,
            b"operation aborted by callback\0" as *const u8 as *const i8,
        );
        *nreadp = 0 as i32 as size_t;
        return CURLE_ABORTED_BY_CALLBACK;
    }
    if nread == 0x10000001 as i32 as u64 {
        let mut k: *mut SingleRequest = &mut (*data).req;
        if (*(*(*data).conn).handler).flags
            & ((1 as i32) << 4 as i32) as u32 != 0
        {
            Curl_failf(
                data,
                b"Read callback asked for PAUSE when not supported!\0" as *const u8
                    as *const i8,
            );
            return CURLE_READ_ERROR;
        }
        (*k).keepon |= (1 as i32) << 5 as i32;
        if ((*data).req).upload_chunky() != 0 {
            let ref mut fresh3 = (*data).req.upload_fromhere;
            *fresh3 = (*fresh3)
                .offset(-((8 as i32 + 2 as i32) as isize));
        }
        *nreadp = 0 as i32 as size_t;
        return CURLE_OK;
    } else {
        if nread > buffersize {
            *nreadp = 0 as i32 as size_t;
            Curl_failf(
                data,
                b"read function returned funny value\0" as *const u8
                    as *const i8,
            );
            return CURLE_READ_ERROR;
        }
    }
    if ((*data).req).forbidchunk() == 0
        && ((*data).req).upload_chunky() as i32 != 0
    {
        let mut added_crlf: bool = 0 as i32 != 0;
        let mut hexlen: i32 = 0 as i32;
        let mut endofline_native: *const i8 = 0 as *const i8;
        let mut endofline_network: *const i8 = 0 as *const i8;
        if ((*data).state).prefer_ascii() as i32 != 0
            || ((*data).set).crlf() as i32 != 0
        {
            endofline_native = b"\n\0" as *const u8 as *const i8;
            endofline_network = b"\n\0" as *const u8 as *const i8;
        } else {
            endofline_native = b"\r\n\0" as *const u8 as *const i8;
            endofline_network = b"\r\n\0" as *const u8 as *const i8;
        }
        if (*data).state.trailers_state as u32
            != TRAILERS_SENDING as i32 as u32
        {
            let mut hexbuffer: [i8; 11] = *::std::mem::transmute::<
                &[u8; 11],
                &mut [i8; 11],
            >(b"\0\0\0\0\0\0\0\0\0\0\0");
            hexlen = curl_msnprintf(
                hexbuffer.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 11]>() as u64,
                b"%zx%s\0" as *const u8 as *const i8,
                nread,
                endofline_native,
            );
            let ref mut fresh4 = (*data).req.upload_fromhere;
            *fresh4 = (*fresh4).offset(-(hexlen as isize));
            nread = (nread as u64).wrapping_add(hexlen as u64)
                as size_t as size_t;
            memcpy(
                (*data).req.upload_fromhere as *mut libc::c_void,
                hexbuffer.as_mut_ptr() as *const libc::c_void,
                hexlen as u64,
            );
            if nread.wrapping_sub(hexlen as u64)
                == 0 as i32 as u64
                && ((*data).set.trailer_callback).is_some()
                && (*data).state.trailers_state as u32
                    == TRAILERS_NONE as i32 as u32
            {
                (*data).state.trailers_state = TRAILERS_INITIALIZED;
            } else {
                memcpy(
                    ((*data).req.upload_fromhere).offset(nread as isize)
                        as *mut libc::c_void,
                    endofline_network as *const libc::c_void,
                    strlen(endofline_network),
                );
                added_crlf = 1 as i32 != 0;
            }
        }
        if (*data).state.trailers_state as u32
            == TRAILERS_SENDING as i32 as u32
            && trailers_left(data as *mut libc::c_void) == 0
        {
            Curl_dyn_free(&mut (*data).state.trailers_buf);
            (*data).state.trailers_state = TRAILERS_DONE;
            let ref mut fresh5 = (*data).set.trailer_data;
            *fresh5 = 0 as *mut libc::c_void;
            let ref mut fresh6 = (*data).set.trailer_callback;
            *fresh6 = None;
            let ref mut fresh7 = (*data).req;
            (*fresh7).set_upload_done(1 as i32 as bit);
            Curl_infof(
                data,
                b"Signaling end of chunked upload after trailers.\0" as *const u8
                    as *const i8,
            );
        } else if nread.wrapping_sub(hexlen as u64)
                == 0 as i32 as u64
                && (*data).state.trailers_state as u32
                    != TRAILERS_INITIALIZED as i32 as u32
            {
            let ref mut fresh8 = (*data).req;
            (*fresh8).set_upload_done(1 as i32 as bit);
            Curl_infof(
                data,
                b"Signaling end of chunked upload via terminating chunk.\0" as *const u8
                    as *const i8,
            );
        }
        if added_crlf {
            nread = (nread as u64).wrapping_add(strlen(endofline_network))
                as size_t as size_t;
        }
    }
    *nreadp = nread;
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_readrewind(mut data: *mut Curl_easy) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut mimepart: *mut curl_mimepart = &mut (*data).set.mimepost;
    let ref mut fresh9 = (*conn).bits;
    (*fresh9).set_rewindaftersend(0 as i32 as bit);
    (*data).req.keepon &= !((1 as i32) << 1 as i32);
    if (*(*conn).handler).protocol
        & ((1 as i32) << 0 as i32
            | (1 as i32) << 1 as i32) as u32 != 0
    {
        let mut http: *mut HTTP = (*data).req.p.http;
        if !((*http).sendit).is_null() {
            mimepart = (*http).sendit;
        }
    }
    if ((*data).set.postfields).is_null() {
        if (*data).state.httpreq as u32
            == HTTPREQ_POST_MIME as i32 as u32
            || (*data).state.httpreq as u32
                == HTTPREQ_POST_FORM as i32 as u32
        {
            let mut result: CURLcode = Curl_mime_rewind(mimepart);
            if result as u64 != 0 {
                Curl_failf(
                    data,
                    b"Cannot rewind mime/post data\0" as *const u8 as *const i8,
                );
                return result;
            }
        } else if ((*data).set.seek_func).is_some() {
            let mut err: i32 = 0;
            Curl_set_in_callback(data, 1 as i32 != 0);
            err = ((*data).set.seek_func)
                .expect(
                    "non-null function pointer",
                )(
                (*data).set.seek_client,
                0 as i32 as curl_off_t,
                0 as i32,
            );
            Curl_set_in_callback(data, 0 as i32 != 0);
            if err != 0 {
                Curl_failf(
                    data,
                    b"seek callback returned error %d\0" as *const u8
                        as *const i8,
                    err,
                );
                return CURLE_SEND_FAIL_REWIND;
            }
        } else if ((*data).set.ioctl_func).is_some() {
            let mut err_0: curlioerr = CURLIOE_OK;
            Curl_set_in_callback(data, 1 as i32 != 0);
            err_0 = ((*data).set.ioctl_func)
                .expect(
                    "non-null function pointer",
                )(data, CURLIOCMD_RESTARTREAD as i32, (*data).set.ioctl_client);
            Curl_set_in_callback(data, 0 as i32 != 0);
            Curl_infof(
                data,
                b"the ioctl callback returned %d\0" as *const u8 as *const i8,
                err_0 as i32,
            );
            if err_0 as u64 != 0 {
                Curl_failf(
                    data,
                    b"ioctl callback returned error %d\0" as *const u8
                        as *const i8,
                    err_0 as i32,
                );
                return CURLE_SEND_FAIL_REWIND;
            }
        } else {
            if (*data).state.fread_func
                == ::std::mem::transmute::<
                    Option::<
                        unsafe extern "C" fn(
                            *mut libc::c_void,
                            u64,
                            u64,
                            *mut FILE,
                        ) -> u64,
                    >,
                    curl_read_callback,
                >(
                    Some(
                        fread
                            as unsafe extern "C" fn(
                                *mut libc::c_void,
                                u64,
                                u64,
                                *mut FILE,
                            ) -> u64,
                    ),
                )
            {
                if -(1 as i32)
                    != fseek(
                        (*data).state.in_0 as *mut FILE,
                        0 as i32 as i64,
                        0 as i32,
                    )
                {
                    return CURLE_OK;
                }
            }
            Curl_failf(
                data,
                b"necessary data rewind wasn't possible\0" as *const u8
                    as *const i8,
            );
            return CURLE_SEND_FAIL_REWIND;
        }
    }
    return CURLE_OK;
}
unsafe extern "C" fn data_pending(mut data: *const Curl_easy) -> i32 {
    let mut conn: *mut connectdata = (*data).conn;
    if (*(*conn).handler).protocol
        & ((1 as i32) << 2 as i32
            | (1 as i32) << 3 as i32) as u32 != 0
    {
        return Curl_ssl_data_pending(conn, 1 as i32) as i32;
    }
    return ((*(*conn).handler).protocol
        & ((1 as i32) << 4 as i32
            | (1 as i32) << 5 as i32) as u32 != 0
        || (*(*conn).handler).protocol
            & ((1 as i32) << 0 as i32
                | (1 as i32) << 1 as i32) as u32 != 0
            && (*conn).httpversion as i32 >= 20 as i32
        || Curl_ssl_data_pending(conn, 0 as i32) as i32 != 0)
        as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_meets_timecondition(
    mut data: *mut Curl_easy,
    mut timeofdoc: time_t,
) -> bool {
    if timeofdoc == 0 as i32 as i64
        || (*data).set.timevalue == 0 as i32 as i64
    {
        return 1 as i32 != 0;
    }
    match (*data).set.timecondition as u32 {
        2 => {
            if timeofdoc >= (*data).set.timevalue {
                Curl_infof(
                    data,
                    b"The requested document is not old enough\0" as *const u8
                        as *const i8,
                );
                let ref mut fresh11 = (*data).info;
                (*fresh11).set_timecond(1 as i32 as bit);
                return 0 as i32 != 0;
            }
        }
        1 | _ => {
            if timeofdoc <= (*data).set.timevalue {
                Curl_infof(
                    data,
                    b"The requested document is not new enough\0" as *const u8
                        as *const i8,
                );
                let ref mut fresh10 = (*data).info;
                (*fresh10).set_timecond(1 as i32 as bit);
                return 0 as i32 != 0;
            }
        }
    }
    return 1 as i32 != 0;
}
unsafe extern "C" fn readwrite_data(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut k: *mut SingleRequest,
    mut didwhat: *mut i32,
    mut done: *mut bool,
    mut comeback: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut nread: ssize_t = 0;
    let mut excess: size_t = 0 as i32 as size_t;
    let mut readmore: bool = 0 as i32 != 0;
    let mut maxloops: i32 = 100 as i32;
    let mut buf: *mut i8 = (*data).state.buffer;
    *done = 0 as i32 != 0;
    *comeback = 0 as i32 != 0;
    loop {
        let mut is_empty_data: bool = 0 as i32 != 0;
        let mut buffersize: size_t = (*data).set.buffer_size as size_t;
        let mut bytestoread: size_t = buffersize;
        let mut is_http2: bool = (*(*conn).handler).protocol
            & ((1 as i32) << 0 as i32
                | (1 as i32) << 1 as i32) as u32 != 0
            && (*conn).httpversion as i32 == 20 as i32;
        if !is_http2 && (*k).size != -(1 as i32) as i64
            && (*k).header() == 0
        {
            let mut totalleft: curl_off_t = (*k).size - (*k).bytecount;
            if totalleft < bytestoread as curl_off_t {
                bytestoread = totalleft as size_t;
            }
        }
        if bytestoread != 0 {
            result = Curl_read(data, (*conn).sockfd, buf, bytestoread, &mut nread);
            if CURLE_AGAIN as i32 as u32 == result as u32 {
                break;
            }
            if result as u32 > 0 as i32 as u32 {
                return result;
            }
        } else {
            nread = 0 as i32 as ssize_t;
        }
        if (*k).bytecount == 0 {
            Curl_pgrsTime(data, TIMER_STARTTRANSFER);
            if (*k).exp100 as u32
                > EXP100_SEND_DATA as i32 as u32
            {
                (*k).start100 = Curl_now();
            }
        }
        *didwhat |= (1 as i32) << 0 as i32;
        is_empty_data = if nread == 0 as i32 as i64
            && (*k).bodywrites == 0 as i32 as i64
        {
            1 as i32
        } else {
            0 as i32
        } != 0;
        if (0 as i32 as i64) < nread
            || is_empty_data as i32 != 0
        {
            *buf.offset(nread as isize) = 0 as i32 as i8;
            let ref mut fresh12 = (*k).str_0;
            *fresh12 = buf;
            if ((*(*conn).handler).readwrite).is_some() {
                result = ((*(*conn).handler).readwrite)
                    .expect(
                        "non-null function pointer",
                    )(data, conn, &mut nread, &mut readmore);
                if result as u64 != 0 {
                    return result;
                }
                if readmore {
                    break;
                }
            }
            if (*k).header() != 0 {
                let mut stop_reading: bool = 0 as i32 != 0;
                result = Curl_http_readwrite_headers(
                    data,
                    conn,
                    &mut nread,
                    &mut stop_reading,
                );
                if result as u64 != 0 {
                    return result;
                }
                if ((*(*conn).handler).readwrite).is_some()
                    && ((*k).maxdownload <= 0 as i32 as i64
                        && nread > 0 as i32 as i64)
                {
                    result = ((*(*conn).handler).readwrite)
                        .expect(
                            "non-null function pointer",
                        )(data, conn, &mut nread, &mut readmore);
                    if result as u64 != 0 {
                        return result;
                    }
                    if readmore {
                        break;
                    }
                }
                if stop_reading {
                    if nread > 0 as i32 as i64 {
                        Curl_infof(
                            data,
                            b"Excess found: excess = %zd url = %s (zero-length body)\0"
                                as *const u8 as *const i8,
                            nread,
                            (*data).state.up.path,
                        );
                    }
                    break;
                }
            }
            if (*k).header() == 0
                && (nread > 0 as i32 as i64
                    || is_empty_data as i32 != 0)
            {
                if ((*data).set).opt_no_body() != 0 {
                    Curl_conncontrol(conn, 2 as i32);
                    *done = 1 as i32 != 0;
                    return CURLE_WEIRD_SERVER_REPLY;
                }
                if 0 as i32 as i64 == (*k).bodywrites && !is_empty_data
                {
                    if (*(*conn).handler).protocol
                        & ((1 as i32) << 0 as i32
                            | (1 as i32) << 1 as i32
                            | (1 as i32) << 18 as i32) as u32
                        != 0
                    {
                        result = Curl_http_firstwrite(data, conn, done);
                        if result as u32 != 0 || *done as i32 != 0 {
                            return result;
                        }
                    }
                }
                let ref mut fresh13 = (*k).bodywrites;
                *fresh13 += 1;
                if ((*data).set).verbose() != 0 {
                    if (*k).badheader as u64 != 0 {
                        Curl_debug(
                            data,
                            CURLINFO_DATA_IN,
                            Curl_dyn_ptr(&mut (*data).state.headerb),
                            Curl_dyn_len(&mut (*data).state.headerb),
                        );
                        if (*k).badheader as u32
                            == HEADER_PARTHEADER as i32 as u32
                        {
                            Curl_debug(
                                data,
                                CURLINFO_DATA_IN,
                                (*k).str_0,
                                nread as size_t,
                            );
                        }
                    } else {
                        Curl_debug(data, CURLINFO_DATA_IN, (*k).str_0, nread as size_t);
                    }
                }
                if (*k).chunk() != 0 {
                    let mut extra: CURLcode = CURLE_OK;
                    let mut res: CHUNKcode = Curl_httpchunk_read(
                        data,
                        (*k).str_0,
                        nread,
                        &mut nread,
                        &mut extra,
                    );
                    if (CHUNKE_OK as i32) < res as i32 {
                        if CHUNKE_PASSTHRU_ERROR as i32 == res as i32 {
                            Curl_failf(
                                data,
                                b"Failed reading the chunked-encoded stream\0" as *const u8
                                    as *const i8,
                            );
                            return extra;
                        }
                        Curl_failf(
                            data,
                            b"%s in chunked-encoding\0" as *const u8
                                as *const i8,
                            Curl_chunked_strerror(res),
                        );
                        return CURLE_RECV_ERROR;
                    }
                    if CHUNKE_STOP as i32 == res as i32 {
                        (*k).keepon &= !((1 as i32) << 0 as i32);
                        if (*conn).chunk.datasize != 0 {
                            Curl_infof(
                                data,
                                b"Leftovers after chunking: % ldu bytes\0" as *const u8
                                    as *const i8,
                                (*conn).chunk.datasize,
                            );
                        }
                    }
                }
                if (*k).badheader as u32
                    == HEADER_PARTHEADER as i32 as u32
                    && (*k).ignorebody() == 0
                {
                    let mut headlen: size_t = Curl_dyn_len(&mut (*data).state.headerb);
                    let ref mut fresh14 = (*k).bytecount;
                    *fresh14 = (*fresh14 as u64).wrapping_add(headlen)
                        as curl_off_t as curl_off_t;
                }
                if -(1 as i32) as i64 != (*k).maxdownload
                    && (*k).bytecount + nread >= (*k).maxdownload
                {
                    excess = ((*k).bytecount + nread - (*k).maxdownload) as size_t;
                    if excess > 0 as i32 as u64
                        && (*k).ignorebody() == 0
                    {
                        Curl_infof(
                            data,
                            b"Excess found in a read: excess = %zu, size = %ld, maxdownload = %ld, bytecount = %ld\0"
                                as *const u8 as *const i8,
                            excess,
                            (*k).size,
                            (*k).maxdownload,
                            (*k).bytecount,
                        );
                        Curl_conncontrol(conn, 1 as i32);
                    }
                    nread = (*k).maxdownload - (*k).bytecount;
                    if nread < 0 as i32 as i64 {
                        nread = 0 as i32 as ssize_t;
                    }
                    (*k).keepon &= !((1 as i32) << 0 as i32);
                }
                let ref mut fresh15 = (*k).bytecount;
                *fresh15 += nread;
                Curl_pgrsSetDownloadCounter(data, (*k).bytecount);
                if (*k).chunk() == 0
                    && (nread != 0 || (*k).badheader as u32 != 0
                        || is_empty_data as i32 != 0)
                {
                    if (*k).badheader as u32 != 0 && (*k).ignorebody() == 0 {
                        let mut headlen_0: size_t = Curl_dyn_len(
                            &mut (*data).state.headerb,
                        );
                        if (*k).maxdownload == -(1 as i32) as i64
                            || headlen_0 as curl_off_t <= (*k).maxdownload
                        {
                            result = Curl_client_write(
                                data,
                                (1 as i32) << 0 as i32,
                                Curl_dyn_ptr(&mut (*data).state.headerb),
                                headlen_0,
                            );
                        } else {
                            result = Curl_client_write(
                                data,
                                (1 as i32) << 0 as i32,
                                Curl_dyn_ptr(&mut (*data).state.headerb),
                                (*k).maxdownload as size_t,
                            );
                        }
                        if result as u64 != 0 {
                            return result;
                        }
                    }
                    if ((*k).badheader as u32)
                        < HEADER_ALLBAD as i32 as u32
                    {
                        if ((*data).set).http_ce_skip() as i32 != 0
                            || ((*k).writer_stack).is_null()
                        {
                            if (*k).ignorebody() == 0 && nread != 0 {
                                if (*(*conn).handler).protocol
                                    & ((1 as i32) << 14 as i32
                                        | (1 as i32) << 15 as i32) as u32
                                    != 0
                                {
                                    result = Curl_pop3_write(data, (*k).str_0, nread as size_t);
                                } else {
                                    result = Curl_client_write(
                                        data,
                                        (1 as i32) << 0 as i32,
                                        (*k).str_0,
                                        nread as size_t,
                                    );
                                }
                            }
                        } else if (*k).ignorebody() == 0 && nread != 0 {
                            result = Curl_unencode_write(
                                data,
                                (*k).writer_stack,
                                (*k).str_0,
                                nread as size_t,
                            );
                        }
                    }
                    (*k).badheader = HEADER_NORMAL;
                    if result as u64 != 0 {
                        return result;
                    }
                }
            }
            if ((*(*conn).handler).readwrite).is_some() && excess != 0 {
                let ref mut fresh16 = (*k).str_0;
                *fresh16 = (*fresh16).offset(nread as isize);
                if &mut *((*k).str_0).offset(excess as isize) as *mut i8
                    > &mut *buf.offset((*data).set.buffer_size as isize)
                        as *mut i8
                {
                    excess = (&mut *buf.offset((*data).set.buffer_size as isize)
                        as *mut i8)
                        .offset_from((*k).str_0) as i64 as size_t;
                }
                nread = excess as ssize_t;
                result = ((*(*conn).handler).readwrite)
                    .expect(
                        "non-null function pointer",
                    )(data, conn, &mut nread, &mut readmore);
                if result as u64 != 0 {
                    return result;
                }
                if readmore {
                    (*k).keepon |= (1 as i32) << 0 as i32;
                }
                break;
            } else {
                if is_empty_data {
                    (*k).keepon &= !((1 as i32) << 0 as i32);
                }
                if (*k).keepon & (1 as i32) << 4 as i32 != 0 {
                    break;
                }
                if !(data_pending(data) != 0
                    && {
                        let fresh17 = maxloops;
                        maxloops = maxloops - 1;
                        fresh17 != 0
                    })
                {
                    break;
                }
            }
        } else {
            is_http2 as i32 != 0 && nread == 0;
            (*k).keepon &= !((1 as i32) << 0 as i32);
            break;
        }
    }
    if maxloops <= 0 as i32 {
        (*conn).cselect_bits = 0x1 as i32;
        *comeback = 1 as i32 != 0;
    }
    if (*k).keepon
        & ((1 as i32) << 0 as i32
            | (1 as i32) << 1 as i32)
        == (1 as i32) << 1 as i32
        && ((*conn).bits).close() as i32 != 0
    {
        Curl_infof(
            data,
            b"we are done reading and this is set to close, stop send\0" as *const u8
                as *const i8,
        );
        (*k).keepon &= !((1 as i32) << 1 as i32);
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_done_sending(
    mut data: *mut Curl_easy,
    mut k: *mut SingleRequest,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    (*k).keepon &= !((1 as i32) << 1 as i32);
    Curl_http2_done_sending(data, conn);
    if ((*conn).bits).rewindaftersend() != 0 {
        let mut result: CURLcode = Curl_readrewind(data);
        if result as u64 != 0 {
            return result;
        }
    }
    return CURLE_OK;
}
unsafe extern "C" fn readwrite_upload(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut didwhat: *mut i32,
) -> CURLcode {
    let mut i: ssize_t = 0;
    let mut si: ssize_t = 0;
    let mut bytes_written: ssize_t = 0;
    let mut result: CURLcode = CURLE_OK;
    let mut nread: ssize_t = 0;
    let mut sending_http_headers: bool = 0 as i32 != 0;
    let mut k: *mut SingleRequest = &mut (*data).req;
    if (*k).bytecount == 0 as i32 as i64
        && (*k).writebytecount == 0 as i32 as i64
    {
        Curl_pgrsTime(data, TIMER_STARTTRANSFER);
    }
    *didwhat |= (1 as i32) << 1 as i32;
    let mut current_block_91: u64;
    let mut nbody: curl_off_t = 0;
    if 0 as i32 as i64 == (*k).upload_present {
        result = Curl_get_upload_buffer(data);
        if result as u64 != 0 {
            return result;
        }
        let ref mut fresh18 = (*k).upload_fromhere;
        *fresh18 = (*data).state.ulbuf;
        if (*k).upload_done() == 0 {
            let mut fillcount: size_t = 0;
            let mut http: *mut HTTP = (*k).p.http;
            if (*k).exp100 as u32
                == EXP100_SENDING_REQUEST as i32 as u32
                && (*http).sending as u32
                    == HTTPSEND_BODY as i32 as u32
            {
                (*k).exp100 = EXP100_AWAITING_CONTINUE;
                (*k).keepon &= !((1 as i32) << 1 as i32);
                (*k).start100 = Curl_now();
                *didwhat &= !((1 as i32) << 1 as i32);
                Curl_expire(data, (*data).set.expect_100_timeout, EXPIRE_100_TIMEOUT);
                current_block_91 = 7416055328783156979;
            } else {
                if (*(*conn).handler).protocol
                    & ((1 as i32) << 0 as i32
                        | (1 as i32) << 1 as i32
                        | (1 as i32) << 18 as i32) as u32 != 0
                {
                    if (*http).sending as u32
                        == HTTPSEND_REQUEST as i32 as u32
                    {
                        sending_http_headers = 1 as i32 != 0;
                    } else {
                        sending_http_headers = 0 as i32 != 0;
                    }
                }
                result = Curl_fillreadbuffer(
                    data,
                    (*data).set.upload_buffer_size as size_t,
                    &mut fillcount,
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
                if nread == 0
                    && (*k).keepon & (1 as i32) << 5 as i32 != 0
                {
                    current_block_91 = 7416055328783156979;
                } else if nread <= 0 as i32 as i64 {
                    result = Curl_done_sending(data, k);
                    if result as u64 != 0 {
                        return result;
                    }
                    current_block_91 = 7416055328783156979;
                } else {
                    (*k).upload_present = nread;
                    if !sending_http_headers
                        && (((*data).state).prefer_ascii() as i32 != 0
                            || ((*data).set).crlf() as i32 != 0)
                    {
                        if ((*data).state.scratch).is_null() {
                            let ref mut fresh19 = (*data).state.scratch;
                            *fresh19 = Curl_cmalloc
                                .expect(
                                    "non-null function pointer",
                                )(
                                (2 as i32 as u32)
                                    .wrapping_mul((*data).set.upload_buffer_size) as size_t,
                            ) as *mut i8;
                            if ((*data).state.scratch).is_null() {
                                Curl_failf(
                                    data,
                                    b"Failed to alloc scratch buffer!\0" as *const u8
                                        as *const i8,
                                );
                                return CURLE_OUT_OF_MEMORY;
                            }
                        }
                        i = 0 as i32 as ssize_t;
                        si = 0 as i32 as ssize_t;
                        while i < nread {
                            if *((*k).upload_fromhere).offset(i as isize) as i32
                                == 0xa as i32
                            {
                                let fresh20 = si;
                                si = si + 1;
                                *((*data).state.scratch)
                                    .offset(
                                        fresh20 as isize,
                                    ) = 0xd as i32 as i8;
                                *((*data).state.scratch)
                                    .offset(si as isize) = 0xa as i32 as i8;
                                if ((*data).set).crlf() == 0 {
                                    if (*data).state.infilesize
                                        != -(1 as i32) as i64
                                    {
                                        let ref mut fresh21 = (*data).state.infilesize;
                                        *fresh21 += 1;
                                    }
                                }
                            } else {
                                *((*data).state.scratch)
                                    .offset(
                                        si as isize,
                                    ) = *((*k).upload_fromhere).offset(i as isize);
                            }
                            i += 1;
                            si += 1;
                        }
                        if si != nread {
                            nread = si;
                            let ref mut fresh22 = (*k).upload_fromhere;
                            *fresh22 = (*data).state.scratch;
                            (*k).upload_present = nread;
                        }
                    }
                    if (*(*conn).handler).protocol
                        & ((1 as i32) << 16 as i32
                            | (1 as i32) << 17 as i32) as u32
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
                (*conn).writesockfd,
                (*k).upload_fromhere as *const libc::c_void,
                (*k).upload_present as size_t,
                &mut bytes_written,
            );
            if result as u64 != 0 {
                return result;
            }
            if (*k).pendingheader != 0 {
                let mut n: curl_off_t = if (*k).pendingheader < bytes_written {
                    (*k).pendingheader
                } else {
                    bytes_written
                };
                Curl_debug(data, CURLINFO_HEADER_OUT, (*k).upload_fromhere, n as size_t);
                let ref mut fresh23 = (*k).pendingheader;
                *fresh23 -= n;
                nbody = bytes_written - n;
            } else {
                nbody = bytes_written;
            }
            if nbody != 0 {
                Curl_debug(
                    data,
                    CURLINFO_DATA_OUT,
                    &mut *((*k).upload_fromhere)
                        .offset((bytes_written - nbody) as isize),
                    nbody as size_t,
                );
                let ref mut fresh24 = (*k).writebytecount;
                *fresh24 += nbody;
                Curl_pgrsSetUploadCounter(data, (*k).writebytecount);
            }
            if ((*k).upload_chunky() == 0 || (*k).forbidchunk() as i32 != 0)
                && (*k).writebytecount == (*data).state.infilesize
            {
                (*k).set_upload_done(1 as i32 as bit);
                Curl_infof(
                    data,
                    b"We are completely uploaded and fine\0" as *const u8
                        as *const i8,
                );
            }
            if (*k).upload_present != bytes_written {
                let ref mut fresh25 = (*k).upload_present;
                *fresh25 -= bytes_written;
                let ref mut fresh26 = (*k).upload_fromhere;
                *fresh26 = (*fresh26).offset(bytes_written as isize);
            } else {
                result = Curl_get_upload_buffer(data);
                if result as u64 != 0 {
                    return result;
                }
                let ref mut fresh27 = (*k).upload_fromhere;
                *fresh27 = (*data).state.ulbuf;
                (*k).upload_present = 0 as i32 as ssize_t;
                if (*k).upload_done() != 0 {
                    result = Curl_done_sending(data, k);
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
pub unsafe extern "C" fn Curl_readwrite(
    mut conn: *mut connectdata,
    mut data: *mut Curl_easy,
    mut done: *mut bool,
    mut comeback: *mut bool,
) -> CURLcode {
    let mut k: *mut SingleRequest = &mut (*data).req;
    let mut result: CURLcode = CURLE_OK;
    let mut didwhat: i32 = 0 as i32;
    let mut fd_read: curl_socket_t = 0;
    let mut fd_write: curl_socket_t = 0;
    let mut select_res: i32 = (*conn).cselect_bits;
    (*conn).cselect_bits = 0 as i32;
    if (*k).keepon
        & ((1 as i32) << 0 as i32
            | (1 as i32) << 2 as i32
            | (1 as i32) << 4 as i32)
        == (1 as i32) << 0 as i32
    {
        fd_read = (*conn).sockfd;
    } else {
        fd_read = -(1 as i32);
    }
    if (*k).keepon
        & ((1 as i32) << 1 as i32
            | (1 as i32) << 3 as i32
            | (1 as i32) << 5 as i32)
        == (1 as i32) << 1 as i32
    {
        fd_write = (*conn).writesockfd;
    } else {
        fd_write = -(1 as i32);
    }
    if (*data).state.drain != 0 {
        select_res |= 0x1 as i32;
    }
    if select_res == 0 {
        select_res = Curl_socket_check(
            fd_read,
            -(1 as i32),
            fd_write,
            0 as i32 as timediff_t,
        );
    }
    if select_res == 0x4 as i32 {
        Curl_failf(
            data,
            b"select/poll returned error\0" as *const u8 as *const i8,
        );
        return CURLE_SEND_ERROR;
    }
    if (*k).keepon & (1 as i32) << 0 as i32 != 0
        && select_res & 0x1 as i32 != 0
    {
        result = readwrite_data(data, conn, k, &mut didwhat, done, comeback);
        if result as u32 != 0 || *done as i32 != 0 {
            return result;
        }
    }
    if (*k).keepon & (1 as i32) << 1 as i32 != 0
        && select_res & 0x2 as i32 != 0
    {
        result = readwrite_upload(data, conn, &mut didwhat);
        if result as u64 != 0 {
            return result;
        }
    }
    (*k).now = Curl_now();
    if didwhat == 0 {
        if (*k).exp100 as u32
            == EXP100_AWAITING_CONTINUE as i32 as u32
        {
            let mut ms: timediff_t = Curl_timediff((*k).now, (*k).start100);
            if ms >= (*data).set.expect_100_timeout {
                (*k).exp100 = EXP100_SEND_DATA;
                (*k).keepon |= (1 as i32) << 1 as i32;
                Curl_expire_done(data, EXPIRE_100_TIMEOUT);
                Curl_infof(
                    data,
                    b"Done waiting for 100-continue\0" as *const u8
                        as *const i8,
                );
            }
        }
    }
    if Curl_pgrsUpdate(data) != 0 {
        result = CURLE_ABORTED_BY_CALLBACK;
    } else {
        result = Curl_speedcheck(data, (*k).now);
    }
    if result as u64 != 0 {
        return result;
    }
    if (*k).keepon != 0 {
        if 0 as i32 as i64
            > Curl_timeleft(data, &mut (*k).now, 0 as i32 != 0)
        {
            if (*k).size != -(1 as i32) as i64 {
                Curl_failf(
                    data,
                    b"Operation timed out after %ld milliseconds with %ld out of %ld bytes received\0"
                        as *const u8 as *const i8,
                    Curl_timediff((*k).now, (*data).progress.t_startsingle),
                    (*k).bytecount,
                    (*k).size,
                );
            } else {
                Curl_failf(
                    data,
                    b"Operation timed out after %ld milliseconds with %ld bytes received\0"
                        as *const u8 as *const i8,
                    Curl_timediff((*k).now, (*data).progress.t_startsingle),
                    (*k).bytecount,
                );
            }
            return CURLE_OPERATION_TIMEDOUT;
        }
    } else {
        if ((*data).set).opt_no_body() == 0
            && (*k).size != -(1 as i32) as i64
            && (*k).bytecount != (*k).size
            && (*k).bytecount != (*k).size + (*data).state.crlf_conversions
            && ((*k).newurl).is_null()
        {
            Curl_failf(
                data,
                b"transfer closed with %ld bytes remaining to read\0" as *const u8
                    as *const i8,
                (*k).size - (*k).bytecount,
            );
            return CURLE_PARTIAL_FILE;
        }
        if ((*data).set).opt_no_body() == 0 && (*k).chunk() as i32 != 0
            && (*conn).chunk.state as u32
                != CHUNK_STOP as i32 as u32
        {
            Curl_failf(
                data,
                b"transfer closed with outstanding read data remaining\0" as *const u8
                    as *const i8,
            );
            return CURLE_PARTIAL_FILE;
        }
        if Curl_pgrsUpdate(data) != 0 {
            return CURLE_ABORTED_BY_CALLBACK;
        }
    }
    *done = if 0 as i32
        == (*k).keepon
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
pub unsafe extern "C" fn Curl_single_getsock(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sock: *mut curl_socket_t,
) -> i32 {
    let mut bitmap: i32 = 0 as i32;
    let mut sockindex: u32 = 0 as i32 as u32;
    if ((*(*conn).handler).perform_getsock).is_some() {
        return ((*(*conn).handler).perform_getsock)
            .expect("non-null function pointer")(data, conn, sock);
    }
    if (*data).req.keepon
        & ((1 as i32) << 0 as i32
            | (1 as i32) << 2 as i32
            | (1 as i32) << 4 as i32)
        == (1 as i32) << 0 as i32
    {
        bitmap |= (1 as i32) << sockindex;
        *sock.offset(sockindex as isize) = (*conn).sockfd;
    }
    if (*data).req.keepon
        & ((1 as i32) << 1 as i32
            | (1 as i32) << 3 as i32
            | (1 as i32) << 5 as i32)
        == (1 as i32) << 1 as i32
    {
        if (*conn).sockfd != (*conn).writesockfd || bitmap == 0 as i32 {
            if bitmap != 0 as i32 {
                sockindex = sockindex.wrapping_add(1);
            }
            *sock.offset(sockindex as isize) = (*conn).writesockfd;
        }
        bitmap
            |= (1 as i32)
                << (16 as i32 as u32).wrapping_add(sockindex);
    }
    return bitmap;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_init_CONNECT(mut data: *mut Curl_easy) {
    let ref mut fresh28 = (*data).state.fread_func;
    *fresh28 = (*data).set.fread_func_set;
    let ref mut fresh29 = (*data).state.in_0;
    *fresh29 = (*data).set.in_set;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_pretransfer(mut data: *mut Curl_easy) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    if ((*data).state.url).is_null() && ((*data).set.uh).is_null() {
        Curl_failf(data, b"No URL set!\0" as *const u8 as *const i8);
        return CURLE_URL_MALFORMAT;
    }
    if ((*data).state).url_alloc() != 0 {
        Curl_cfree
            .expect("non-null function pointer")((*data).state.url as *mut libc::c_void);
        let ref mut fresh30 = (*data).state.url;
        *fresh30 = 0 as *mut i8;
        let ref mut fresh31 = (*data).state;
        (*fresh31).set_url_alloc(0 as i32 as bit);
    }
    if ((*data).state.url).is_null() && !((*data).set.uh).is_null() {
        let mut uc: CURLUcode = CURLUE_OK;
        Curl_cfree
            .expect(
                "non-null function pointer",
            )(
            (*data).set.str_0[STRING_SET_URL as i32 as usize]
                as *mut libc::c_void,
        );
        uc = curl_url_get(
            (*data).set.uh,
            CURLUPART_URL,
            &mut *((*data).set.str_0)
                .as_mut_ptr()
                .offset(STRING_SET_URL as i32 as isize),
            0 as i32 as u32,
        );
        if uc as u64 != 0 {
            Curl_failf(data, b"No URL set!\0" as *const u8 as *const i8);
            return CURLE_URL_MALFORMAT;
        }
    }
    let ref mut fresh32 = (*data).state;
    (*fresh32).set_prefer_ascii(((*data).set).prefer_ascii());
    let ref mut fresh33 = (*data).state;
    (*fresh33).set_list_only(((*data).set).list_only());
    (*data).state.httpreq = (*data).set.method;
    let ref mut fresh34 = (*data).state.url;
    *fresh34 = (*data).set.str_0[STRING_SET_URL as i32 as usize];
    result = Curl_ssl_initsessions(data, (*data).set.general_ssl.max_ssl_sessions);
    if result as u64 != 0 {
        return result;
    }
    let ref mut fresh35 = (*data).state;
    (*fresh35).set_wildcardmatch(((*data).set).wildcard_enabled());
    (*data).state.followlocation = 0 as i32 as i64;
    let ref mut fresh36 = (*data).state;
    (*fresh36).set_this_is_a_follow(0 as i32 as bit);
    let ref mut fresh37 = (*data).state;
    (*fresh37).set_errorbuf(0 as i32 as bit);
    (*data).state.httpwant = (*data).set.httpwant;
    (*data).state.httpversion = 0 as i32 as u8;
    let ref mut fresh38 = (*data).state;
    (*fresh38).set_authproblem(0 as i32 as bit);
    (*data).state.authhost.want = (*data).set.httpauth;
    (*data).state.authproxy.want = (*data).set.proxyauth;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).info.wouldredirect as *mut libc::c_void);
    let ref mut fresh39 = (*data).info.wouldredirect;
    *fresh39 = 0 as *mut i8;
    if (*data).state.httpreq as u32
        == HTTPREQ_PUT as i32 as u32
    {
        (*data).state.infilesize = (*data).set.filesize;
    } else if (*data).state.httpreq as u32
            != HTTPREQ_GET as i32 as u32
            && (*data).state.httpreq as u32
                != HTTPREQ_HEAD as i32 as u32
        {
        (*data).state.infilesize = (*data).set.postfieldsize;
        if !((*data).set.postfields).is_null()
            && (*data).state.infilesize == -(1 as i32) as i64
        {
            (*data)
                .state
                .infilesize = strlen((*data).set.postfields as *const i8)
                as curl_off_t;
        }
    } else {
        (*data).state.infilesize = 0 as i32 as curl_off_t;
    }
    if !((*data).state.cookielist).is_null() {
        Curl_cookie_loadfiles(data);
    }
    if !((*data).state.resolve).is_null() {
        result = Curl_loadhostpairs(data);
    }
    if result as u64 == 0 {
        let ref mut fresh40 = (*data).state;
        (*fresh40).set_allow_port(1 as i32 as bit);
        Curl_initinfo(data);
        Curl_pgrsResetTransferSizes(data);
        Curl_pgrsStartNow(data);
        (*data).state.authhost.picked &= (*data).state.authhost.want;
        (*data).state.authproxy.picked &= (*data).state.authproxy.want;
        if ((*data).state).wildcardmatch() != 0 {
            let mut wc: *mut WildcardData = &mut (*data).wildcard;
            if ((*wc).state as u32) < CURLWC_INIT as i32 as u32
            {
                result = Curl_wildcard_init(wc);
                if result as u64 != 0 {
                    return CURLE_OUT_OF_MEMORY;
                }
            }
        }
        Curl_http2_init_state(&mut (*data).state);
        result = Curl_hsts_loadcb(data, (*data).hsts);
    }
    if !((*data).set.str_0[STRING_USERAGENT as i32 as usize]).is_null() {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.aptr.uagent as *mut libc::c_void);
        let ref mut fresh41 = (*data).state.aptr.uagent;
        *fresh41 = 0 as *mut i8;
        let ref mut fresh42 = (*data).state.aptr.uagent;
        *fresh42 = curl_maprintf(
            b"User-Agent: %s\r\n\0" as *const u8 as *const i8,
            (*data).set.str_0[STRING_USERAGENT as i32 as usize],
        );
        if ((*data).state.aptr.uagent).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if result as u64 == 0 {
        result = Curl_setstropt(
            &mut (*data).state.aptr.user,
            (*data).set.str_0[STRING_USERNAME as i32 as usize],
        );
    }
    if result as u64 == 0 {
        result = Curl_setstropt(
            &mut (*data).state.aptr.passwd,
            (*data).set.str_0[STRING_PASSWORD as i32 as usize],
        );
    }
    if result as u64 == 0 {
        result = Curl_setstropt(
            &mut (*data).state.aptr.proxyuser,
            (*data).set.str_0[STRING_PROXYUSERNAME as i32 as usize],
        );
    }
    if result as u64 == 0 {
        result = Curl_setstropt(
            &mut (*data).state.aptr.proxypasswd,
            (*data).set.str_0[STRING_PROXYPASSWORD as i32 as usize],
        );
    }
    (*data).req.headerbytecount = 0 as i32 as curl_off_t;
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_posttransfer(mut data: *mut Curl_easy) -> CURLcode {
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_follow(
    mut data: *mut Curl_easy,
    mut newurl: *mut i8,
    mut type_0: followtype,
) -> CURLcode {
    let mut disallowport: bool = 0 as i32 != 0;
    let mut reachedmax: bool = 0 as i32 != 0;
    let mut uc: CURLUcode = CURLUE_OK;
    if type_0 as u32 == FOLLOW_REDIR as i32 as u32 {
        if (*data).set.maxredirs != -(1 as i32) as i64
            && (*data).state.followlocation >= (*data).set.maxredirs
        {
            reachedmax = 1 as i32 != 0;
            type_0 = FOLLOW_FAKE;
        } else {
            let ref mut fresh43 = (*data).state;
            (*fresh43).set_this_is_a_follow(1 as i32 as bit);
            let ref mut fresh44 = (*data).state.followlocation;
            *fresh44 += 1;
            if ((*data).set).http_auto_referer() != 0 {
                let mut u: *mut CURLU = 0 as *mut CURLU;
                let mut referer: *mut i8 = 0 as *mut i8;
                if ((*data).state).referer_alloc() != 0 {
                    Curl_cfree
                        .expect(
                            "non-null function pointer",
                        )((*data).state.referer as *mut libc::c_void);
                    let ref mut fresh45 = (*data).state.referer;
                    *fresh45 = 0 as *mut i8;
                    let ref mut fresh46 = (*data).state;
                    (*fresh46).set_referer_alloc(0 as i32 as bit);
                }
                u = curl_url();
                if u.is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
                uc = curl_url_set(
                    u,
                    CURLUPART_URL,
                    (*data).state.url,
                    0 as i32 as u32,
                );
                if uc as u64 == 0 {
                    uc = curl_url_set(
                        u,
                        CURLUPART_FRAGMENT,
                        0 as *const i8,
                        0 as i32 as u32,
                    );
                }
                if uc as u64 == 0 {
                    uc = curl_url_set(
                        u,
                        CURLUPART_USER,
                        0 as *const i8,
                        0 as i32 as u32,
                    );
                }
                if uc as u64 == 0 {
                    uc = curl_url_set(
                        u,
                        CURLUPART_PASSWORD,
                        0 as *const i8,
                        0 as i32 as u32,
                    );
                }
                if uc as u64 == 0 {
                    uc = curl_url_get(
                        u,
                        CURLUPART_URL,
                        &mut referer,
                        0 as i32 as u32,
                    );
                }
                curl_url_cleanup(u);
                if uc as u32 != 0 || referer.is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
                let ref mut fresh47 = (*data).state.referer;
                *fresh47 = referer;
                let ref mut fresh48 = (*data).state;
                (*fresh48).set_referer_alloc(1 as i32 as bit);
            }
        }
    }
    if type_0 as u32 != FOLLOW_RETRY as i32 as u32
        && (*data).req.httpcode != 401 as i32
        && (*data).req.httpcode != 407 as i32
        && Curl_is_absolute_url(
            newurl,
            0 as *mut i8,
            40 as i32 as size_t,
        ) as i32 != 0
    {
        disallowport = 1 as i32 != 0;
    }
    uc = curl_url_set(
        (*data).state.uh,
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
        newurl = Curl_cstrdup.expect("non-null function pointer")(newurl);
        if newurl.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    } else {
        uc = curl_url_get(
            (*data).state.uh,
            CURLUPART_URL,
            &mut newurl,
            0 as i32 as u32,
        );
        if uc as u64 != 0 {
            return Curl_uc_to_curlcode(uc);
        }
    }
    if type_0 as u32 == FOLLOW_FAKE as i32 as u32 {
        let ref mut fresh49 = (*data).info.wouldredirect;
        *fresh49 = newurl;
        if reachedmax {
            Curl_failf(
                data,
                b"Maximum (%ld) redirects followed\0" as *const u8
                    as *const i8,
                (*data).set.maxredirs,
            );
            return CURLE_TOO_MANY_REDIRECTS;
        }
        return CURLE_OK;
    }
    if disallowport {
        let ref mut fresh50 = (*data).state;
        (*fresh50).set_allow_port(0 as i32 as bit);
    }
    if ((*data).state).url_alloc() != 0 {
        Curl_cfree
            .expect("non-null function pointer")((*data).state.url as *mut libc::c_void);
        let ref mut fresh51 = (*data).state.url;
        *fresh51 = 0 as *mut i8;
    }
    let ref mut fresh52 = (*data).state.url;
    *fresh52 = newurl;
    let ref mut fresh53 = (*data).state;
    (*fresh53).set_url_alloc(1 as i32 as bit);
    Curl_infof(
        data,
        b"Issue another request to this URL: '%s'\0" as *const u8 as *const i8,
        (*data).state.url,
    );
    match (*data).info.httpcode {
        301 => {
            if ((*data).state.httpreq as u32
                == HTTPREQ_POST as i32 as u32
                || (*data).state.httpreq as u32
                    == HTTPREQ_POST_FORM as i32 as u32
                || (*data).state.httpreq as u32
                    == HTTPREQ_POST_MIME as i32 as u32)
                && (*data).set.keep_post & 1 as i32 == 0
            {
                Curl_infof(
                    data,
                    b"Switch from POST to GET\0" as *const u8 as *const i8,
                );
                (*data).state.httpreq = HTTPREQ_GET;
            }
        }
        302 => {
            if ((*data).state.httpreq as u32
                == HTTPREQ_POST as i32 as u32
                || (*data).state.httpreq as u32
                    == HTTPREQ_POST_FORM as i32 as u32
                || (*data).state.httpreq as u32
                    == HTTPREQ_POST_MIME as i32 as u32)
                && (*data).set.keep_post & 2 as i32 == 0
            {
                Curl_infof(
                    data,
                    b"Switch from POST to GET\0" as *const u8 as *const i8,
                );
                (*data).state.httpreq = HTTPREQ_GET;
            }
        }
        303 => {
            if (*data).state.httpreq as u32
                != HTTPREQ_GET as i32 as u32
                && ((*data).state.httpreq as u32
                    != HTTPREQ_POST as i32 as u32
                    && (*data).state.httpreq as u32
                        != HTTPREQ_POST_FORM as i32 as u32
                    && (*data).state.httpreq as u32
                        != HTTPREQ_POST_MIME as i32 as u32
                    || (*data).set.keep_post & 4 as i32 == 0)
            {
                (*data).state.httpreq = HTTPREQ_GET;
                let ref mut fresh54 = (*data).set;
                (*fresh54).set_upload(0 as i32 as bit);
                Curl_infof(
                    data,
                    b"Switch to %s\0" as *const u8 as *const i8,
                    if ((*data).set).opt_no_body() as i32 != 0 {
                        b"HEAD\0" as *const u8 as *const i8
                    } else {
                        b"GET\0" as *const u8 as *const i8
                    },
                );
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
pub unsafe extern "C" fn Curl_retry_request(
    mut data: *mut Curl_easy,
    mut url: *mut *mut i8,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut retry: bool = 0 as i32 != 0;
    *url = 0 as *mut i8;
    if ((*data).set).upload() as i32 != 0
        && (*(*conn).handler).protocol
            & ((1 as i32) << 0 as i32
                | (1 as i32) << 1 as i32
                | (1 as i32) << 18 as i32) as u32 == 0
    {
        return CURLE_OK;
    }
    if (*data).req.bytecount + (*data).req.headerbytecount
        == 0 as i32 as i64 && ((*conn).bits).reuse() as i32 != 0
        && (((*data).set).opt_no_body() == 0
            || (*(*conn).handler).protocol
                & ((1 as i32) << 0 as i32
                    | (1 as i32) << 1 as i32) as u32 != 0)
        && (*data).set.rtspreq as u32
            != RTSPREQ_RECEIVE as i32 as u32
    {
        retry = 1 as i32 != 0;
    } else if ((*data).state).refused_stream() as i32 != 0
            && (*data).req.bytecount + (*data).req.headerbytecount
                == 0 as i32 as i64
        {
        Curl_infof(
            data,
            b"REFUSED_STREAM, retrying a fresh connect\0" as *const u8
                as *const i8,
        );
        let ref mut fresh55 = (*data).state;
        (*fresh55).set_refused_stream(0 as i32 as bit);
        retry = 1 as i32 != 0;
    }
    if retry {
        let ref mut fresh56 = (*data).state.retrycount;
        let fresh57 = *fresh56;
        *fresh56 = *fresh56 + 1;
        if fresh57 >= 5 as i32 {
            Curl_failf(
                data,
                b"Connection died, tried %d times before giving up\0" as *const u8
                    as *const i8,
                5 as i32,
            );
            (*data).state.retrycount = 0 as i32;
            return CURLE_SEND_ERROR;
        }
        Curl_infof(
            data,
            b"Connection died, retrying a fresh connect (retry count: %d)\0" as *const u8
                as *const i8,
            (*data).state.retrycount,
        );
        *url = Curl_cstrdup.expect("non-null function pointer")((*data).state.url);
        if (*url).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        Curl_conncontrol(conn, 1 as i32);
        let ref mut fresh58 = (*conn).bits;
        (*fresh58).set_retry(1 as i32 as bit);
        if (*(*conn).handler).protocol
            & ((1 as i32) << 0 as i32
                | (1 as i32) << 1 as i32) as u32 != 0
        {
            if (*data).req.writebytecount != 0 {
                let mut result: CURLcode = Curl_readrewind(data);
                if result as u64 != 0 {
                    Curl_cfree
                        .expect("non-null function pointer")(*url as *mut libc::c_void);
                    *url = 0 as *mut i8;
                    return result;
                }
            }
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_setup_transfer(
    mut data: *mut Curl_easy,
    mut sockindex: i32,
    mut size: curl_off_t,
    mut getheader: bool,
    mut writesockindex: i32,
) {
    let mut k: *mut SingleRequest = &mut (*data).req;
    let mut conn: *mut connectdata = (*data).conn;
    let mut http: *mut HTTP = (*data).req.p.http;
    let mut httpsending: bool = (*(*conn).handler).protocol
        & ((1 as i32) << 0 as i32
            | (1 as i32) << 1 as i32) as u32 != 0
        && (*http).sending as u32
            == HTTPSEND_REQUEST as i32 as u32;
    if ((*conn).bits).multiplex() as i32 != 0
        || (*conn).httpversion as i32 == 20 as i32
        || httpsending as i32 != 0
    {
        (*conn)
            .sockfd = if sockindex == -(1 as i32) {
            if writesockindex == -(1 as i32) {
                -(1 as i32)
            } else {
                (*conn).sock[writesockindex as usize]
            }
        } else {
            (*conn).sock[sockindex as usize]
        };
        (*conn).writesockfd = (*conn).sockfd;
        if httpsending {
            writesockindex = 0 as i32;
        }
    } else {
        (*conn)
            .sockfd = if sockindex == -(1 as i32) {
            -(1 as i32)
        } else {
            (*conn).sock[sockindex as usize]
        };
        (*conn)
            .writesockfd = if writesockindex == -(1 as i32) {
            -(1 as i32)
        } else {
            (*conn).sock[writesockindex as usize]
        };
    }
    (*k).set_getheader(getheader as bit);
    (*k).size = size;
    if (*k).getheader() == 0 {
        (*k).set_header(0 as i32 as bit);
        if size > 0 as i32 as i64 {
            Curl_pgrsSetDownloadSize(data, size);
        }
    }
    if (*k).getheader() as i32 != 0 || ((*data).set).opt_no_body() == 0 {
        if sockindex != -(1 as i32) {
            (*k).keepon |= (1 as i32) << 0 as i32;
        }
        if writesockindex != -(1 as i32) {
            if ((*data).state).expect100header() as i32 != 0
                && (*(*conn).handler).protocol
                    & ((1 as i32) << 0 as i32
                        | (1 as i32) << 1 as i32) as u32 != 0
                && (*http).sending as u32
                    == HTTPSEND_BODY as i32 as u32
            {
                (*k).exp100 = EXP100_AWAITING_CONTINUE;
                (*k).start100 = Curl_now();
                Curl_expire(data, (*data).set.expect_100_timeout, EXPIRE_100_TIMEOUT);
            } else {
                if ((*data).state).expect100header() != 0 {
                    (*k).exp100 = EXP100_SENDING_REQUEST;
                }
                (*k).keepon |= (1 as i32) << 1 as i32;
            }
        }
    }
}
