use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn sscanf(_: * const i8, _: * const i8, _: ...) -> i32;
    fn time(__timer: * mut i64) -> i64;
    
    
    
    
    
    
    fn memcpy(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn memmove(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn memchr(
        _: * const core::ffi::c_void,
        _: i32,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn strcmp(_: * const i8, _: * const i8) -> i32;
    fn strchr(_: * const i8, _: i32) -> * mut i8;
    fn strstr(_: * const i8, _: * const i8) -> * mut i8;
    fn strlen(_: * const i8) -> u64;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    static mut Curl_ssl: * const crate::src::lib::getinfo::Curl_ssl;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::altsvc::Curl_altsvc_parse;
pub use crate::src::lib::base64::Curl_base64_encode;
pub use crate::src::lib::connect::Curl_conncontrol;
pub use crate::src::lib::content_encoding::Curl_build_unencoding_stack;
pub use crate::src::lib::content_encoding::Curl_unencode_cleanup;
pub use crate::src::lib::cookie::Curl_cookie_add;
pub use crate::src::lib::cookie::Curl_cookie_freelist;
pub use crate::src::lib::cookie::Curl_cookie_getlist;
pub use crate::src::lib::curl_ctype::Curl_isdigit;
pub use crate::src::lib::curl_ctype::Curl_isspace;
pub use crate::src::lib::curl_ntlm_wb::Curl_input_ntlm_wb;
pub use crate::src::lib::curl_ntlm_wb::Curl_output_ntlm_wb;
pub use crate::src::lib::dynbuf::Curl_dyn_add;
pub use crate::src::lib::dynbuf::Curl_dyn_addf;
pub use crate::src::lib::dynbuf::Curl_dyn_addn;
pub use crate::src::lib::dynbuf::Curl_dyn_free;
pub use crate::src::lib::dynbuf::Curl_dyn_init;
pub use crate::src::lib::dynbuf::Curl_dyn_len;
pub use crate::src::lib::dynbuf::Curl_dyn_ptr;
pub use crate::src::lib::dynbuf::Curl_dyn_reset;
pub use crate::src::lib::formdata::Curl_getformdata;
pub use crate::src::lib::hsts::Curl_hsts_parse;
pub use crate::src::lib::http2::Curl_http2_done;
pub use crate::src::lib::http2::Curl_http2_request_upgrade;
pub use crate::src::lib::http2::Curl_http2_setup;
pub use crate::src::lib::http2::Curl_http2_setup_conn;
pub use crate::src::lib::http2::Curl_http2_setup_req;
pub use crate::src::lib::http2::Curl_http2_switched;
pub use crate::src::lib::http_aws_sigv4::Curl_output_aws_sigv4;
pub use crate::src::lib::http_digest::Curl_input_digest;
pub use crate::src::lib::http_digest::Curl_output_digest;
pub use crate::src::lib::http_ntlm::Curl_input_ntlm;
pub use crate::src::lib::http_ntlm::Curl_output_ntlm;
pub use crate::src::lib::http_proxy::Curl_connect_ongoing;
pub use crate::src::lib::http_proxy::Curl_proxy_connect;
pub use crate::src::lib::mime::Curl_mime_cleanpart;
pub use crate::src::lib::mime::Curl_mime_initpart;
pub use crate::src::lib::mime::Curl_mime_prepare_headers;
pub use crate::src::lib::mime::Curl_mime_read;
pub use crate::src::lib::mime::Curl_mime_rewind;
pub use crate::src::lib::mime::Curl_mime_size;
pub use crate::src::lib::mime::curl_mime_headers;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::multi::Curl_expire_done;
pub use crate::src::lib::multi::Curl_set_in_callback;
pub use crate::src::lib::parsedate::Curl_getdate_capped;
pub use crate::src::lib::parsedate::Curl_gmtime;
pub use crate::src::lib::progress::Curl_pgrsSetDownloadSize;
pub use crate::src::lib::progress::Curl_pgrsSetUploadCounter;
pub use crate::src::lib::progress::Curl_pgrsSetUploadSize;
pub use crate::src::lib::progress::Curl_pgrsUpdate;
pub use crate::src::lib::rtsp::Curl_rtsp_parseheader;
pub use crate::src::lib::sendf::Curl_client_write;
pub use crate::src::lib::sendf::Curl_debug;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::sendf::Curl_write;
pub use crate::src::lib::share::Curl_share_lock;
pub use crate::src::lib::share::Curl_share_unlock;
pub use crate::src::lib::strcase::Curl_raw_toupper;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::strcase::Curl_strncasecompare;
pub use crate::src::lib::strcase::curl_strnequal;
pub use crate::src::lib::strtoofft::curlx_strtoofft;
pub use crate::src::lib::transfer::Curl_checkheaders;
pub use crate::src::lib::transfer::Curl_done_sending;
pub use crate::src::lib::transfer::Curl_get_upload_buffer;
pub use crate::src::lib::transfer::Curl_meets_timecondition;
pub use crate::src::lib::transfer::Curl_readrewind;
pub use crate::src::lib::transfer::Curl_setup_transfer;
pub use crate::src::lib::urlapi::curl_url_cleanup;
pub use crate::src::lib::urlapi::curl_url_dup;
pub use crate::src::lib::urlapi::curl_url_get;
pub use crate::src::lib::urlapi::curl_url_set;
pub use crate::src::lib::vauth::digest::Curl_auth_is_digest_supported;
pub use crate::src::lib::vauth::ntlm::Curl_auth_is_ntlm_supported;
pub use crate::src::lib::vtls::vtls::Curl_ssl_connect_nonblocking;
pub use crate::src::lib::warnless::curlx_sotouz;
pub use crate::src::lib::warnless::curlx_uitous;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::easy::Curl_ccalloc;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_cstrdup;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::parsedate::Curl_month;
pub use crate::src::lib::parsedate::Curl_wkday;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::vtls::openssl::ssl_backend_data;
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
// #[derive(Copy, Clone)]

pub type sockaddr = crate::src::lib::http2::sockaddr;
pub type curl_socklen_t = u32;
pub type curl_off_t = i64;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::lib::http2::_IO_FILE;
// #[derive(Copy, Clone)]

pub type tm = crate::src::lib::altsvc::tm;
// #[derive(Copy, Clone)]

pub type Curl_easy = crate::src::lib::http2::Curl_easy;
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone, BitfieldStruct)]

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
// #[derive(Copy, Clone)]

pub type curl_certinfo = crate::src::lib::http2::curl_certinfo;
// #[derive(Copy, Clone)]

pub type curl_slist = crate::src::lib::http2::curl_slist;
// #[derive(Copy, Clone)]

pub type WildcardData = crate::src::lib::http2::WildcardData;
pub type wildcard_dtor<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> ()>;
// #[derive(Copy, Clone)]

pub type Curl_llist = crate::src::lib::http2::Curl_llist;
pub type Curl_llist_dtor<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: Option<&'a2 mut core::ffi::c_void>,) -> ()>;
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone, BitfieldStruct)]

pub type UrlState = crate::src::lib::http2::UrlState;
// #[derive(Copy, Clone)]

pub type dynamically_allocated_data = crate::src::lib::http2::dynamically_allocated_data;
pub type trailers_state = u32;
pub const TRAILERS_DONE: trailers_state = 3;
pub const TRAILERS_SENDING: trailers_state = 2;
pub const TRAILERS_INITIALIZED: trailers_state = 1;
pub const TRAILERS_NONE: trailers_state = 0;
// #[derive(Copy, Clone)]

pub type dynbuf = crate::src::lib::http2::dynbuf;
pub type Curl_HttpReq = u32;
pub const HTTPREQ_HEAD: Curl_HttpReq = 5;
pub const HTTPREQ_PUT: Curl_HttpReq = 4;
pub const HTTPREQ_POST_MIME: Curl_HttpReq = 3;
pub const HTTPREQ_POST_FORM: Curl_HttpReq = 2;
pub const HTTPREQ_POST: Curl_HttpReq = 1;
pub const HTTPREQ_GET: Curl_HttpReq = 0;
// #[derive(Copy, Clone)]

pub type urlpieces = crate::src::lib::http2::urlpieces;
pub type CURLU = crate::src::lib::urlapi::Curl_URL;
pub type curl_read_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut i8>,_: u64,_: u64,_: Option<&'a2 mut core::ffi::c_void>,) -> u64>;
// #[derive(Copy, Clone)]

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
pub type Curl_hash_dtor<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> ()>;
pub type comp_function<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: u64,_: Option<&'a2 mut core::ffi::c_void>,_: u64,) -> u64>;
pub type hash_function<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: u64,_: u64,) -> u64>;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type Progress = crate::src::lib::http2::Progress;
pub type timediff_t = i64;
// #[derive(Copy, Clone)]

pub type altsvcinfo = crate::src::lib::altsvc::altsvcinfo;
// #[derive(Copy, Clone)]

pub type hsts = crate::src::lib::easy::hsts;
// #[derive(Copy, Clone)]

pub type CookieInfo = crate::src::lib::http2::CookieInfo;
// #[derive(Copy, Clone)]

pub type Cookie = crate::src::lib::http2::Cookie;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type UserDefined = crate::src::lib::http2::UserDefined;
pub type curl_trailer_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut Option<&'a2 mut crate::src::lib::http2::curl_slist>>,_: Option<&'a3 mut core::ffi::c_void>,) -> i32>;
pub type multidone_func<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: u32,) -> i32>;
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
pub type curl_resolver_start_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: Option<&'a2 mut core::ffi::c_void>,_: Option<&'a3 mut core::ffi::c_void>,) -> i32>;
// #[derive(Copy, Clone)]

pub type Curl_http2_dep = crate::src::lib::http2::Curl_http2_dep;
pub type curl_fnmatch_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: Option<&'a2 i8>,_: Option<&'a3 i8>,) -> i32>;
pub type curl_chunk_end_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> i64>;
pub type curl_chunk_bgn_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 core::ffi::c_void>,_: Option<&'a2 mut core::ffi::c_void>,_: i32,) -> i64>;
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
pub type curl_sshkeycallback<'a1, 'a2, 'a3, 'a4> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: Option<&'a2 crate::src::lib::http2::curl_khkey>,_: Option<&'a3 crate::src::lib::http2::curl_khkey>,_: u32,_: Option<&'a4 mut core::ffi::c_void>,) -> i32>;
pub type curl_khmatch = u32;
pub const CURLKHMATCH_LAST: curl_khmatch = 3;
pub const CURLKHMATCH_MISSING: curl_khmatch = 2;
pub const CURLKHMATCH_MISMATCH: curl_khmatch = 1;
pub const CURLKHMATCH_OK: curl_khmatch = 0;
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone)]

pub type ssl_general_config = crate::src::lib::http2::ssl_general_config;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type ssl_config_data = crate::src::lib::http2::ssl_config_data;
pub type CURL_TLSAUTH = u32;
pub const CURL_TLSAUTH_LAST: CURL_TLSAUTH = 2;
pub const CURL_TLSAUTH_SRP: CURL_TLSAUTH = 1;
pub const CURL_TLSAUTH_NONE: CURL_TLSAUTH = 0;
pub type curl_ssl_ctx_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: Option<&'a2 mut core::ffi::c_void>,_: Option<&'a3 mut core::ffi::c_void>,) -> u32>;
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
// #[derive(Copy, Clone)]

pub type curl_mimepart = crate::src::lib::http2::curl_mimepart;
// #[derive(Copy, Clone)]

pub type mime_encoder_state = crate::src::lib::http2::mime_encoder_state;
// #[derive(Copy, Clone)]

pub type mime_encoder = crate::src::lib::http2::mime_encoder;
// #[derive(Copy, Clone)]

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
pub type curl_free_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> ()>;
pub type curl_seek_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: i64,_: i32,) -> i32>;
pub type mimekind = u32;
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
pub type curl_hstswrite_callback<'a1, 'a2, 'a3, 'a4> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: Option<&'a2 mut crate::src::lib::http2::curl_hstsentry>,_: Option<&'a3 mut crate::src::lib::http2::curl_index>,_: Option<&'a4 mut core::ffi::c_void>,) -> u32>;
// #[derive(Copy, Clone)]

pub type curl_index = crate::src::lib::http2::curl_index;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type curl_hstsentry = crate::src::lib::http2::curl_hstsentry;
pub type CURLSTScode = u32;
pub const CURLSTS_FAIL: CURLSTScode = 2;
pub const CURLSTS_DONE: CURLSTScode = 1;
pub const CURLSTS_OK: CURLSTScode = 0;
pub type curl_hstsread_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: Option<&'a2 mut crate::src::lib::http2::curl_hstsentry>,_: Option<&'a3 mut core::ffi::c_void>,) -> u32>;
pub type curl_conv_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut i8>,_: u64,) -> u32>;
pub type curl_closesocket_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: i32,) -> i32>;
pub type curl_socket_t = i32;
pub type curl_opensocket_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: u32,_: Option<&'a2 mut crate::src::lib::http2::curl_sockaddr>,) -> i32>;
// #[derive(Copy, Clone)]

pub type curl_sockaddr = crate::src::lib::http2::curl_sockaddr;
pub type curlsocktype = u32;
pub const CURLSOCKTYPE_LAST: curlsocktype = 2;
pub const CURLSOCKTYPE_ACCEPT: curlsocktype = 1;
pub const CURLSOCKTYPE_IPCXN: curlsocktype = 0;
pub type curl_sockopt_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: i32,_: u32,) -> i32>;
pub type curl_ioctl_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: i32,_: Option<&'a2 mut core::ffi::c_void>,) -> u32>;
pub type curlioerr = u32;
pub const CURLIOE_LAST: curlioerr = 3;
pub const CURLIOE_FAILRESTART: curlioerr = 2;
pub const CURLIOE_UNKNOWNCMD: curlioerr = 1;
pub const CURLIOE_OK: curlioerr = 0;
pub type curl_debug_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: u32,_: Option<&'a2 mut i8>,_: u64,_: Option<&'a3 mut core::ffi::c_void>,) -> i32>;
pub type curl_infotype = u32;
pub const CURLINFO_END: curl_infotype = 7;
pub const CURLINFO_SSL_DATA_OUT: curl_infotype = 6;
pub const CURLINFO_SSL_DATA_IN: curl_infotype = 5;
pub const CURLINFO_DATA_OUT: curl_infotype = 4;
pub const CURLINFO_DATA_IN: curl_infotype = 3;
pub const CURLINFO_HEADER_OUT: curl_infotype = 2;
pub const CURLINFO_HEADER_IN: curl_infotype = 1;
pub const CURLINFO_TEXT: curl_infotype = 0;
pub type curl_xferinfo_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: i64,_: i64,_: i64,_: i64,) -> i32>;
pub type curl_progress_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: f64,_: f64,_: f64,_: f64,) -> i32>;
pub type curl_write_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut i8>,_: u64,_: u64,_: Option<&'a2 mut core::ffi::c_void>,) -> u64>;
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
pub type curl_pp_transfer = u32;
pub const PPTRANSFER_NONE: curl_pp_transfer = 2;
pub const PPTRANSFER_INFO: curl_pp_transfer = 1;
pub const PPTRANSFER_BODY: curl_pp_transfer = 0;
// #[derive(Copy, Clone)]

pub type RTSP = crate::src::lib::http2::RTSP;
// #[derive(Copy, Clone)]

pub type HTTP = crate::src::lib::http2::HTTP;
pub type uint8_t = u8;
pub type uint32_t = u32;
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
// #[derive(Copy, Clone)]

pub type PslCache = crate::src::lib::http2::PslCache;
pub type psl_ctx_t = crate::src::lib::urlapi::psl_ctx_st;
// #[derive(Copy, Clone)]

pub type Curl_share = crate::src::lib::asyn_thread::Curl_share;
pub type curl_unlock_function<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: u32,_: Option<&'a2 mut core::ffi::c_void>,) -> ()>;
pub type curl_lock_data = u32;
pub const CURL_LOCK_DATA_LAST: curl_lock_data = 7;
pub const CURL_LOCK_DATA_PSL: curl_lock_data = 6;
pub const CURL_LOCK_DATA_CONNECT: curl_lock_data = 5;
pub const CURL_LOCK_DATA_SSL_SESSION: curl_lock_data = 4;
pub const CURL_LOCK_DATA_DNS: curl_lock_data = 3;
pub const CURL_LOCK_DATA_COOKIE: curl_lock_data = 2;
pub const CURL_LOCK_DATA_SHARE: curl_lock_data = 1;
pub const CURL_LOCK_DATA_NONE: curl_lock_data = 0;
pub type curl_lock_function<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: u32,_: u32,_: Option<&'a2 mut core::ffi::c_void>,) -> ()>;
pub type curl_lock_access = u32;
pub const CURL_LOCK_ACCESS_LAST: curl_lock_access = 3;
pub const CURL_LOCK_ACCESS_SINGLE: curl_lock_access = 2;
pub const CURL_LOCK_ACCESS_SHARED: curl_lock_access = 1;
pub const CURL_LOCK_ACCESS_NONE: curl_lock_access = 0;
// #[derive(Copy, Clone)]

pub type Curl_multi = crate::src::lib::http2::Curl_multi;
pub type curl_multi_timer_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_multi>,_: i64,_: Option<&'a2 mut core::ffi::c_void>,) -> i32>;
pub type CURLM = crate::src::lib::http2::Curl_multi;
pub type curl_push_callback<'a1, 'a2, 'a3, 'a4> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: Option<&'a2 mut crate::src::lib::http2::Curl_easy>,_: u64,_: Option<&'a3 mut crate::src::lib::http2::curl_pushheaders>,_: Option<&'a4 mut core::ffi::c_void>,) -> i32>;
pub type curl_socket_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: i32,_: i32,_: Option<&'a2 mut core::ffi::c_void>,_: Option<&'a3 mut core::ffi::c_void>,) -> i32>;
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
// #[derive(Copy, Clone)]

pub type connectdata = crate::src::lib::http2::connectdata;
// #[derive(Copy, Clone)]

pub type connectbundle = crate::src::lib::http2::connectbundle;
// #[derive(Copy, Clone, BitfieldStruct)]

pub type http_connect_state = crate::src::lib::ftp::http_connect_state;
pub type C2RustUnnamed_4 = u32;
pub const TUNNEL_EXIT: C2RustUnnamed_4 = 3;
pub const TUNNEL_COMPLETE: C2RustUnnamed_4 = 2;
pub const TUNNEL_CONNECT: C2RustUnnamed_4 = 1;
pub const TUNNEL_INIT: C2RustUnnamed_4 = 0;
pub type keeponval = u32;
pub const KEEPON_IGNORE: keeponval = 2;
pub const KEEPON_CONNECT: keeponval = 1;
pub const KEEPON_DONE: keeponval = 0;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_5 = crate::src::lib::http2::C2RustUnnamed_4;
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone)]

pub type smb_conn = crate::src::lib::http2::smb_conn;
pub type smb_conn_state = u32;
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
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone)]

pub type pingpong = crate::src::lib::http2::pingpong;
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone)]

pub type http_conn = crate::src::lib::http2::http_conn;
// #[derive(Copy, Clone)]

pub type nghttp2_settings_entry = crate::src::lib::http2::nghttp2_settings_entry;
// #[derive(Copy, Clone)]

pub type h2settings = crate::src::lib::http2::h2settings;
pub type Curl_recv<'a1, 'a2, 'a3> = unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: i32,_: Option<&'a2 mut i8>,_: u64,_: Option<&'a3 mut u32>,) -> i64;
pub type Curl_send<'a1, 'a2, 'a3> = unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: i32,_: Option<&'a2 core::ffi::c_void>,_: u64,_: Option<&'a3 mut u32>,) -> i64;
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone)]

pub type ntlmdata = crate::src::lib::http2::ntlmdata;
pub type curlntlm = u32;
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
// #[derive(Copy, Clone)]

pub type proxy_info = crate::src::lib::http2::proxy_info;
// #[derive(Copy, Clone)]

pub type hostname = crate::src::lib::http2::hostname;
pub type C2RustUnnamed_6 = u32;
pub const TRNSPRT_QUIC: C2RustUnnamed_6 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_6 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_6 = 3;
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone)]

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
pub type curl_malloc_callback<'a1> = Option<unsafe extern "C"  fn(_: u64,) -> Option<&'a1 mut core::ffi::c_void>>;
pub type curl_strdup_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 i8>,) -> Option<&'a2 mut i8>>;
pub type curl_calloc_callback<'a1> = Option<unsafe extern "C"  fn(_: u64,_: u64,) -> Option<&'a1 mut core::ffi::c_void>>;
pub type C2RustUnnamed_7 = u32;
pub const CURL_HTTP_VERSION_LAST: C2RustUnnamed_7 = 31;
pub const CURL_HTTP_VERSION_3: C2RustUnnamed_7 = 30;
pub const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: C2RustUnnamed_7 = 5;
pub const CURL_HTTP_VERSION_2TLS: C2RustUnnamed_7 = 4;
pub const CURL_HTTP_VERSION_2_0: C2RustUnnamed_7 = 3;
pub const CURL_HTTP_VERSION_1_1: C2RustUnnamed_7 = 2;
pub const CURL_HTTP_VERSION_1_0: C2RustUnnamed_7 = 1;
pub const CURL_HTTP_VERSION_NONE: C2RustUnnamed_7 = 0;
// #[derive(Copy, Clone)]

pub type curl_ssl_backend = crate::src::lib::getinfo::curl_ssl_backend;
pub type CURLINFO = u32;
pub const CURLINFO_LASTONE: CURLINFO = 60;
pub const CURLINFO_REFERER: CURLINFO = 1048636;
pub const CURLINFO_PROXY_ERROR: CURLINFO = 2097211;
pub const CURLINFO_EFFECTIVE_METHOD: CURLINFO = 1048634;
pub const CURLINFO_RETRY_AFTER: CURLINFO = 6291513;
pub const CURLINFO_APPCONNECT_TIME_T: CURLINFO = 6291512;
pub const CURLINFO_REDIRECT_TIME_T: CURLINFO = 6291511;
pub const CURLINFO_STARTTRANSFER_TIME_T: CURLINFO = 6291510;
pub const CURLINFO_PRETRANSFER_TIME_T: CURLINFO = 6291509;
pub const CURLINFO_CONNECT_TIME_T: CURLINFO = 6291508;
pub const CURLINFO_NAMELOOKUP_TIME_T: CURLINFO = 6291507;
pub const CURLINFO_TOTAL_TIME_T: CURLINFO = 6291506;
pub const CURLINFO_SCHEME: CURLINFO = 1048625;
pub const CURLINFO_PROTOCOL: CURLINFO = 2097200;
pub const CURLINFO_PROXY_SSL_VERIFYRESULT: CURLINFO = 2097199;
pub const CURLINFO_HTTP_VERSION: CURLINFO = 2097198;
pub const CURLINFO_TLS_SSL_PTR: CURLINFO = 4194349;
pub const CURLINFO_ACTIVESOCKET: CURLINFO = 5242924;
pub const CURLINFO_TLS_SESSION: CURLINFO = 4194347;
pub const CURLINFO_LOCAL_PORT: CURLINFO = 2097194;
pub const CURLINFO_LOCAL_IP: CURLINFO = 1048617;
pub const CURLINFO_PRIMARY_PORT: CURLINFO = 2097192;
pub const CURLINFO_RTSP_CSEQ_RECV: CURLINFO = 2097191;
pub const CURLINFO_RTSP_SERVER_CSEQ: CURLINFO = 2097190;
pub const CURLINFO_RTSP_CLIENT_CSEQ: CURLINFO = 2097189;
pub const CURLINFO_RTSP_SESSION_ID: CURLINFO = 1048612;
pub const CURLINFO_CONDITION_UNMET: CURLINFO = 2097187;
pub const CURLINFO_CERTINFO: CURLINFO = 4194338;
pub const CURLINFO_APPCONNECT_TIME: CURLINFO = 3145761;
pub const CURLINFO_PRIMARY_IP: CURLINFO = 1048608;
pub const CURLINFO_REDIRECT_URL: CURLINFO = 1048607;
pub const CURLINFO_FTP_ENTRY_PATH: CURLINFO = 1048606;
pub const CURLINFO_LASTSOCKET: CURLINFO = 2097181;
pub const CURLINFO_COOKIELIST: CURLINFO = 4194332;
pub const CURLINFO_SSL_ENGINES: CURLINFO = 4194331;
pub const CURLINFO_NUM_CONNECTS: CURLINFO = 2097178;
pub const CURLINFO_OS_ERRNO: CURLINFO = 2097177;
pub const CURLINFO_PROXYAUTH_AVAIL: CURLINFO = 2097176;
pub const CURLINFO_HTTPAUTH_AVAIL: CURLINFO = 2097175;
pub const CURLINFO_HTTP_CONNECTCODE: CURLINFO = 2097174;
pub const CURLINFO_PRIVATE: CURLINFO = 1048597;
pub const CURLINFO_REDIRECT_COUNT: CURLINFO = 2097172;
pub const CURLINFO_REDIRECT_TIME: CURLINFO = 3145747;
pub const CURLINFO_CONTENT_TYPE: CURLINFO = 1048594;
pub const CURLINFO_STARTTRANSFER_TIME: CURLINFO = 3145745;
pub const CURLINFO_CONTENT_LENGTH_UPLOAD_T: CURLINFO = 6291472;
pub const CURLINFO_CONTENT_LENGTH_UPLOAD: CURLINFO = 3145744;
pub const CURLINFO_CONTENT_LENGTH_DOWNLOAD_T: CURLINFO = 6291471;
pub const CURLINFO_CONTENT_LENGTH_DOWNLOAD: CURLINFO = 3145743;
pub const CURLINFO_FILETIME_T: CURLINFO = 6291470;
pub const CURLINFO_FILETIME: CURLINFO = 2097166;
pub const CURLINFO_SSL_VERIFYRESULT: CURLINFO = 2097165;
pub const CURLINFO_REQUEST_SIZE: CURLINFO = 2097164;
pub const CURLINFO_HEADER_SIZE: CURLINFO = 2097163;
pub const CURLINFO_SPEED_UPLOAD_T: CURLINFO = 6291466;
pub const CURLINFO_SPEED_UPLOAD: CURLINFO = 3145738;
pub const CURLINFO_SPEED_DOWNLOAD_T: CURLINFO = 6291465;
pub const CURLINFO_SPEED_DOWNLOAD: CURLINFO = 3145737;
pub const CURLINFO_SIZE_DOWNLOAD_T: CURLINFO = 6291464;
pub const CURLINFO_SIZE_DOWNLOAD: CURLINFO = 3145736;
pub const CURLINFO_SIZE_UPLOAD_T: CURLINFO = 6291463;
pub const CURLINFO_SIZE_UPLOAD: CURLINFO = 3145735;
pub const CURLINFO_PRETRANSFER_TIME: CURLINFO = 3145734;
pub const CURLINFO_CONNECT_TIME: CURLINFO = 3145733;
pub const CURLINFO_NAMELOOKUP_TIME: CURLINFO = 3145732;
pub const CURLINFO_TOTAL_TIME: CURLINFO = 3145731;
pub const CURLINFO_RESPONSE_CODE: CURLINFO = 2097154;
pub const CURLINFO_EFFECTIVE_URL: CURLINFO = 1048577;
pub const CURLINFO_NONE: CURLINFO = 0;
pub type CURLSHcode = u32;
pub const CURLSHE_LAST: CURLSHcode = 6;
pub const CURLSHE_NOT_BUILT_IN: CURLSHcode = 5;
pub const CURLSHE_NOMEM: CURLSHcode = 4;
pub const CURLSHE_INVALID: CURLSHcode = 3;
pub const CURLSHE_IN_USE: CURLSHcode = 2;
pub const CURLSHE_BAD_OPTION: CURLSHcode = 1;
pub const CURLSHE_OK: CURLSHcode = 0;
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
pub type mimestrategy = u32;
pub const MIMESTRATEGY_LAST: mimestrategy = 2;
pub const MIMESTRATEGY_FORM: mimestrategy = 1;
pub const MIMESTRATEGY_MAIL: mimestrategy = 0;
pub const HEADER_CONNECT: proxy_use = 2;
pub const HEADER_PROXY: proxy_use = 1;
pub const HEADER_SERVER: proxy_use = 0;
pub type proxy_use = u32;
pub const STRING_COOKIE: dupstring = 4;
pub const STRING_ENCODING: dupstring = 9;
pub const STRING_USERAGENT: dupstring = 38;
pub const STRING_TARGET: dupstring = 67;
pub const STRING_BEARER: dupstring = 65;
pub const STRING_CUSTOMREQUEST: dupstring = 6;
// #[derive(Copy, Clone)]

pub type Curl_ssl = crate::src::lib::getinfo::Curl_ssl;
pub type alpnid = u32;
pub const ALPN_h3: alpnid = 32;
pub const ALPN_h2: alpnid = 16;
pub const ALPN_h1: alpnid = 8;
pub const ALPN_none: alpnid = 0;
pub type CURLofft = u32;
pub const CURL_OFFT_INVAL: CURLofft = 2;
pub const CURL_OFFT_FLOW: CURLofft = 1;
pub const CURL_OFFT_OK: CURLofft = 0;
pub const STATUS_DONE: statusline = 1;
pub type statusline = u32;
pub const STATUS_BAD: statusline = 2;
pub const STATUS_UNKNOWN: statusline = 0;
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
pub const STRING_UNIX_SOCKET_PATH: dupstring = 66;
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
pub const STRING_DEVICE: dupstring = 8;
pub const STRING_DEFAULT_PROTOCOL: dupstring = 7;
pub const STRING_COOKIEJAR: dupstring = 5;
pub const STRING_CERT_TYPE_PROXY: dupstring = 3;
pub const STRING_CERT_TYPE: dupstring = 2;
pub const STRING_CERT_PROXY: dupstring = 1;
pub const STRING_CERT: dupstring = 0;
#[no_mangle]
pub static mut Curl_handler_http: crate::src::lib::http2::Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"HTTP\0" as *const u8 as *const i8,
            setup_connection: Some(
                http_setup_conn,
            ),
            do_it: Some(
                Curl_http,
            ),
            done: Some(
                Curl_http_done,
            ),
            do_more: None,
            connect_it: Some(
                Curl_http_connect,
            ),
            connecting: None,
            doing: None,
            proto_getsock: None,
            doing_getsock: Some(
                http_getsock_do,
            ),
            domore_getsock: None,
            perform_getsock: None,
            disconnect: None,
            readwrite: None,
            connection_check: None,
            attach: None,
            defport: 80 as i32,
            protocol: ((1 as i32) << 0 as i32) as u32,
            family: ((1 as i32) << 0 as i32) as u32,
            flags: ((1 as i32) << 7 as i32
                | (1 as i32) << 13 as i32) as u32,
        };
        init
    }
};
#[no_mangle]
pub static mut Curl_handler_https: crate::src::lib::http2::Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"HTTPS\0" as *const u8 as *const i8,
            setup_connection: Some(
                http_setup_conn,
            ),
            do_it: Some(
                Curl_http,
            ),
            done: Some(
                Curl_http_done,
            ),
            do_more: None,
            connect_it: Some(
                Curl_http_connect,
            ),
            connecting: Some(
                https_connecting,
            ),
            doing: None,
            proto_getsock: Some(
                https_getsock,
            ),
            doing_getsock: Some(
                http_getsock_do,
            ),
            domore_getsock: None,
            perform_getsock: None,
            disconnect: None,
            readwrite: None,
            connection_check: None,
            attach: None,
            defport: 443 as i32,
            protocol: ((1 as i32) << 1 as i32) as u32,
            family: ((1 as i32) << 0 as i32) as u32,
            flags: ((1 as i32) << 0 as i32
                | (1 as i32) << 7 as i32
                | (1 as i32) << 8 as i32
                | (1 as i32) << 13 as i32) as u32,
        };
        init
    }
};
unsafe extern "C" fn http_setup_conn(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut http: * mut crate::src::lib::http2::HTTP = 0 as *mut HTTP;
    http = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(1 as i32 as size_t, ::std::mem::size_of::<HTTP>() as u64)
        as *mut HTTP;
    if http.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    Curl_mime_initpart(&mut (*http).form, data);
    let mut fresh0 = &mut ((*data).req.p.http);
    *fresh0 = http;
    if (*data).state.httpwant as i32 == CURL_HTTP_VERSION_3 as i32 {
        if (*(*conn).handler).flags
            & ((1 as i32) << 0 as i32) as u32 != 0
        {
            (*conn).transport = TRNSPRT_QUIC;
        } else {
            Curl_failf(
                data,
                b"HTTP/3 requested for non-HTTPS URL\0" as *const u8
                    as *const i8,
            );
            return CURLE_URL_MALFORMAT;
        }
    } else {
        if (*conn).easyq.size == 0 {
            Curl_http2_setup_conn(conn);
        }
        Curl_http2_setup_req(data);
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_checkProxyheaders(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * const crate::src::lib::http2::connectdata,
    mut thisheader: * const i8,
) -> * mut i8 {
    let mut head: * mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
    let mut thislen: u64 = strlen(thisheader);
    head = if ((*conn).bits).proxy() as i32 != 0
        && ((*data).set).sep_headers() as i32 != 0
    {
        (*data).set.proxyheaders
    } else {
        (*data).set.headers
    };
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
pub unsafe extern "C" fn Curl_copy_header_value(
    mut header: * const i8,
) -> * mut i8 {
    let mut start: * const i8 = 0 as *const i8;
    let mut end: * const i8 = 0 as *const i8;
    let mut value: * mut i8 = 0 as *mut i8;
    let mut len: u64 = 0;
    while *header as i32 != 0 && *header as i32 != ':' as i32 {
        header = header.offset(1);
    }
    if *header != 0 {
        header = header.offset(1);
    }
    start = header;
    while *start as i32 != 0
        && Curl_isspace(*start as u8 as i32) != 0
    {
        start = start.offset(1);
    }
    end = strchr(start, '\r' as i32);
    if end.is_null() {
        end = strchr(start, '\n' as i32);
    }
    if end.is_null() {
        end = strchr(start, '\u{0}' as i32);
    }
    if end.is_null() {
        return 0 as *mut i8;
    }
    while end > start && Curl_isspace(*end as u8 as i32) != 0 {
        end = end.offset(-1);
    }
    len = (end.offset_from(start) as i64 + 1 as i32 as i64)
        as size_t;
    value = Curl_cmalloc
        .expect(
            "non-null function pointer",
        )(len.wrapping_add(1 as i32 as u64)) as *mut i8;
    if value.is_null() {
        return 0 as *mut i8;
    }
    memcpy(value as *mut libc::c_void, start as *const libc::c_void, len);
    *value.offset(len as isize) = 0 as i32 as i8;
    return value;
}
unsafe extern "C" fn http_output_basic(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut proxy: bool,
) -> u32 {
    let mut size: u64 = 0 as i32 as size_t;
    let mut authorization: * mut i8 = 0 as *mut i8;
    let mut userp: Option<&'_ mut * mut i8> = Option::<&'_ mut * mut i8>::None;
    let mut user: * const i8 = 0 as *const i8;
    let mut pwd: * const i8 = 0 as *const i8;
    let mut result: u32 = CURLE_OK;
    let mut out: * mut i8 = 0 as *mut i8;
    if proxy {
        userp = Some(&mut (*data).state.aptr.proxyuserpwd);
        user = (*data).state.aptr.proxyuser;
        pwd = (*data).state.aptr.proxypasswd;
    } else {
        userp = Some(&mut (*data).state.aptr.userpwd);
        user = (*data).state.aptr.user;
        pwd = (*data).state.aptr.passwd;
    }
    out = curl_maprintf(
        b"%s:%s\0" as *const u8 as *const i8,
        user,
        if !pwd.is_null() { pwd } else { b"\0" as *const u8 as *const i8 },
    );
    if out.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    result = Curl_base64_encode(data, out, strlen(out), Some(&mut authorization), Some(&mut size));
    if !(result as u64 != 0) {
        if authorization.is_null() {
            result = CURLE_REMOTE_ACCESS_DENIED;
        } else {
            Curl_cfree.expect("non-null function pointer")(*(borrow_mut(&mut userp)).unwrap() as *mut libc::c_void);
            *(borrow_mut(&mut userp)).unwrap() = curl_maprintf(
                b"%sAuthorization: Basic %s\r\n\0" as *const u8 as *const i8,
                if proxy as i32 != 0 {
                    b"Proxy-\0" as *const u8 as *const i8
                } else {
                    b"\0" as *const u8 as *const i8
                },
                authorization,
            );
            Curl_cfree
                .expect("non-null function pointer")(authorization as *mut libc::c_void);
            if (*(borrow(& userp)).unwrap()).is_null() {
                result = CURLE_OUT_OF_MEMORY;
            }
        }
    }
    Curl_cfree.expect("non-null function pointer")(out as *mut libc::c_void);
    return result;
}
unsafe extern "C" fn http_output_bearer(mut data: * mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut userp: Option<&'_ mut * mut i8> = Option::<&'_ mut * mut i8>::None;
    let mut result: u32 = CURLE_OK;
    userp = Some(&mut (*data).state.aptr.userpwd);
    Curl_cfree.expect("non-null function pointer")(*(borrow_mut(&mut userp)).unwrap() as *mut libc::c_void);
    *(borrow_mut(&mut userp)).unwrap() = curl_maprintf(
        b"Authorization: Bearer %s\r\n\0" as *const u8 as *const i8,
        (*data).set.str_0[STRING_BEARER as i32 as usize],
    );
    if (*(borrow_mut(&mut userp)).unwrap()).is_null() {
        result = CURLE_OUT_OF_MEMORY;
    }
    return result;
}
unsafe extern "C" fn pickoneauth<'a1>(mut pick: Option<&'a1 mut crate::src::lib::http2::auth>, mut mask: u64) -> bool {
    let mut picked: bool = false;
    let mut avail: u64 = (*(borrow(& pick)).unwrap()).avail & (*(borrow(& pick)).unwrap()).want & mask;
    picked = 1 as i32 != 0;
    if avail & (1 as i32 as u64) << 2 as i32 != 0 {
        (*(borrow_mut(&mut pick)).unwrap()).picked = (1 as i32 as u64) << 2 as i32;
    } else if avail & (1 as i32 as u64) << 6 as i32 != 0 {
        (*(borrow_mut(&mut pick)).unwrap()).picked = (1 as i32 as u64) << 6 as i32;
    } else if avail & (1 as i32 as u64) << 1 as i32 != 0 {
        (*(borrow_mut(&mut pick)).unwrap()).picked = (1 as i32 as u64) << 1 as i32;
    } else if avail & (1 as i32 as u64) << 3 as i32 != 0 {
        (*(borrow_mut(&mut pick)).unwrap()).picked = (1 as i32 as u64) << 3 as i32;
    } else if avail & (1 as i32 as u64) << 5 as i32 != 0 {
        (*(borrow_mut(&mut pick)).unwrap()).picked = (1 as i32 as u64) << 5 as i32;
    } else if avail & (1 as i32 as u64) << 0 as i32 != 0 {
        (*(borrow_mut(&mut pick)).unwrap()).picked = (1 as i32 as u64) << 0 as i32;
    } else if avail & (1 as i32 as u64) << 7 as i32 != 0 {
        (*(borrow_mut(&mut pick)).unwrap()).picked = (1 as i32 as u64) << 7 as i32;
    } else {
        (*(borrow_mut(&mut pick)).unwrap()).picked = ((1 as i32) << 30 as i32) as u64;
        picked = 0 as i32 != 0;
    }
    (*(borrow_mut(&mut pick)).unwrap()).avail = 0 as i32 as u64;
    return picked;
}
unsafe extern "C" fn http_perhapsrewind(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut http: * mut crate::src::lib::http2::HTTP = (*data).req.p.http;
    let mut bytessent: i64 = 0;
    let mut expectsend: i64 = -(1 as i32) as curl_off_t;
    if http.is_null() {
        return CURLE_OK;
    }
    match (*data).state.httpreq as u32 {
        0 | 5 => return CURLE_OK,
        _ => {}
    }
    bytessent = (*data).req.writebytecount;
    if ((*conn).bits).authneg() != 0 {
        expectsend = 0 as i32 as curl_off_t;
    } else if ((*conn).bits).protoconnstart() == 0 {
        expectsend = 0 as i32 as curl_off_t;
    } else {
        match (*data).state.httpreq as u32 {
            1 | 4 => {
                if (*data).state.infilesize != -(1 as i32) as i64 {
                    expectsend = (*data).state.infilesize;
                }
            }
            2 | 3 => {
                expectsend = (*http).postsize;
            }
            _ => {}
        }
    }
    let mut fresh1 = &mut ((*conn).bits);
    (*fresh1).set_rewindaftersend(0 as i32 as bit);
    if expectsend == -(1 as i32) as i64 || expectsend > bytessent {
        if (*data).state.authproxy.picked
            == (1 as i32 as u64) << 3 as i32
            || (*data).state.authhost.picked
                == (1 as i32 as u64) << 3 as i32
            || (*data).state.authproxy.picked
                == (1 as i32 as u64) << 5 as i32
            || (*data).state.authhost.picked
                == (1 as i32 as u64) << 5 as i32
        {
            if expectsend - bytessent < 2000 as i32 as i64
                || (*conn).http_ntlm_state as u32
                    != NTLMSTATE_NONE as i32 as u32
                || (*conn).proxy_ntlm_state as u32
                    != NTLMSTATE_NONE as i32 as u32
            {
                if ((*conn).bits).authneg() == 0
                    && (*conn).writesockfd != -(1 as i32)
                {
                    let mut fresh2 = &mut ((*conn).bits);
                    (*fresh2).set_rewindaftersend(1 as i32 as bit);
                    Curl_infof(
                        data,
                        b"Rewind stream after send\0" as *const u8 as *const i8,
                    );
                }
                return CURLE_OK;
            }
            if ((*conn).bits).close() != 0 {
                return CURLE_OK;
            }
            Curl_infof(
                data,
                b"NTLM send, close instead of sending %ld bytes\0" as *const u8
                    as *const i8,
                expectsend - bytessent,
            );
        }
        Curl_conncontrol(conn, 2 as i32);
        (*data).req.size = 0 as i32 as curl_off_t;
    }
    if bytessent != 0 {
        return Curl_readrewind(data);
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_auth_act(mut data: * mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    let mut pickhost: bool = 0 as i32 != 0;
    let mut pickproxy: bool = 0 as i32 != 0;
    let mut result: u32 = CURLE_OK;
    let mut authmask: u64 = !(0 as u64);
    if ((*data).set.str_0[STRING_BEARER as i32 as usize]).is_null() {
        authmask &= !((1 as i32 as u64) << 6 as i32);
    }
    if 100 as i32 <= (*data).req.httpcode
        && 199 as i32 >= (*data).req.httpcode
    {
        return CURLE_OK;
    }
    if ((*data).state).authproblem() != 0 {
        return (if ((*data).set).http_fail_on_error() as i32 != 0 {
            CURLE_HTTP_RETURNED_ERROR as i32
        } else {
            CURLE_OK as i32
        }) as CURLcode;
    }
    if (((*conn).bits).user_passwd() as i32 != 0
        || !((*data).set.str_0[STRING_BEARER as i32 as usize]).is_null())
        && ((*data).req.httpcode == 401 as i32
            || ((*conn).bits).authneg() as i32 != 0
                && (*data).req.httpcode < 300 as i32)
    {
        pickhost = pickoneauth(Some(&mut (*data).state.authhost), authmask);
        if !pickhost {
            let mut fresh3 = &mut ((*data).state);
            (*fresh3).set_authproblem(1 as i32 as bit);
        }
        if (*data).state.authhost.picked
            == (1 as i32 as u64) << 3 as i32
            && (*conn).httpversion as i32 > 11 as i32
        {
            Curl_infof(
                data,
                b"Forcing HTTP/1.1 for NTLM\0" as *const u8 as *const i8,
            );
            Curl_conncontrol(conn, 1 as i32);
            (*data)
                .state
                .httpwant = CURL_HTTP_VERSION_1_1 as i32 as u8;
        }
    }
    if ((*conn).bits).proxy_user_passwd() as i32 != 0
        && ((*data).req.httpcode == 407 as i32
            || ((*conn).bits).authneg() as i32 != 0
                && (*data).req.httpcode < 300 as i32)
    {
        pickproxy = pickoneauth(
            Some(&mut (*data).state.authproxy),
            authmask & !((1 as i32 as u64) << 6 as i32),
        );
        if !pickproxy {
            let mut fresh4 = &mut ((*data).state);
            (*fresh4).set_authproblem(1 as i32 as bit);
        }
    }
    if pickhost as i32 != 0 || pickproxy as i32 != 0 {
        if (*data).state.httpreq as u32
            != HTTPREQ_GET as i32 as u32
            && (*data).state.httpreq as u32
                != HTTPREQ_HEAD as i32 as u32
            && ((*conn).bits).rewindaftersend() == 0
        {
            result = http_perhapsrewind(data, conn);
            if result as u64 != 0 {
                return result;
            }
        }
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).req.newurl as *mut libc::c_void);
        let mut fresh5 = &mut ((*data).req.newurl);
        *fresh5 = 0 as *mut i8;
        let mut fresh6 = &mut ((*data).req.newurl);
        *fresh6 = Curl_cstrdup.expect("non-null function pointer")((*data).state.url);
        if ((*data).req.newurl).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    } else if (*data).req.httpcode < 300 as i32
            && ((*data).state.authhost).done() == 0
            && ((*conn).bits).authneg() as i32 != 0
        {
        if (*data).state.httpreq as u32
            != HTTPREQ_GET as i32 as u32
            && (*data).state.httpreq as u32
                != HTTPREQ_HEAD as i32 as u32
        {
            let mut fresh7 = &mut ((*data).req.newurl);
            *fresh7 = Curl_cstrdup
                .expect("non-null function pointer")((*data).state.url);
            if ((*data).req.newurl).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            let mut fresh8 = &mut ((*data).state.authhost);
            (*fresh8).set_done(1 as i32 as bit);
        }
    }
    if http_should_fail(data) {
        Curl_failf(
            data,
            b"The requested URL returned error: %d\0" as *const u8
                as *const i8,
            (*data).req.httpcode,
        );
        result = CURLE_HTTP_RETURNED_ERROR;
    }
    return result;
}
unsafe extern "C" fn output_auth_headers(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut authstatus: * mut crate::src::lib::http2::auth,
    mut request: * const i8,
    mut path: * const i8,
    mut proxy: bool,
) -> u32 {
    let mut auth: * const i8 = 0 as *const i8;
    let mut result: u32 = CURLE_OK;
    if (*authstatus).picked == (1 as i32 as u64) << 7 as i32 {
        auth = b"AWS_SIGV4\0" as *const u8 as *const i8;
        result = Curl_output_aws_sigv4(data, proxy);
        if result as u64 != 0 {
            return result;
        }
    } else if (*authstatus).picked
            == (1 as i32 as u64) << 3 as i32
        {
        auth = b"NTLM\0" as *const u8 as *const i8;
        result = Curl_output_ntlm(data, proxy);
        if result as u64 != 0 {
            return result;
        }
    } else if (*authstatus).picked
            == (1 as i32 as u64) << 5 as i32
        {
        auth = b"NTLM_WB\0" as *const u8 as *const i8;
        result = Curl_output_ntlm_wb(data, conn, proxy);
        if result as u64 != 0 {
            return result;
        }
    } else if (*authstatus).picked
            == (1 as i32 as u64) << 1 as i32
        {
        auth = b"Digest\0" as *const u8 as *const i8;
        result = Curl_output_digest(
            data,
            proxy,
            request as *const u8,
            path as *const u8,
        );
        if result as u64 != 0 {
            return result;
        }
    } else if (*authstatus).picked
            == (1 as i32 as u64) << 0 as i32
        {
        if proxy as i32 != 0
            && ((*conn).bits).proxy_user_passwd() as i32 != 0
            && (Curl_checkProxyheaders(
                data,
                conn,
                b"Proxy-authorization\0" as *const u8 as *const i8,
            ))
                .is_null()
            || !proxy && ((*conn).bits).user_passwd() as i32 != 0
                && (Curl_checkheaders(
                    data,
                    b"Authorization\0" as *const u8 as *const i8,
                ))
                    .is_null()
        {
            auth = b"Basic\0" as *const u8 as *const i8;
            result = http_output_basic(data, proxy);
            if result as u64 != 0 {
                return result;
            }
        }
        (*authstatus).set_done(1 as i32 as bit);
    }
    if (*authstatus).picked == (1 as i32 as u64) << 6 as i32 {
        if !proxy
            && !((*data).set.str_0[STRING_BEARER as i32 as usize]).is_null()
            && (Curl_checkheaders(
                data,
                b"Authorization\0" as *const u8 as *const i8,
            ))
                .is_null()
        {
            auth = b"Bearer\0" as *const u8 as *const i8;
            result = http_output_bearer(data);
            if result as u64 != 0 {
                return result;
            }
        }
        (*authstatus).set_done(1 as i32 as bit);
    }
    if !auth.is_null() {
        Curl_infof(
            data,
            b"%s auth using %s with user '%s'\0" as *const u8 as *const i8,
            if proxy as i32 != 0 {
                b"Proxy\0" as *const u8 as *const i8
            } else {
                b"Server\0" as *const u8 as *const i8
            },
            auth,
            if proxy as i32 != 0 {
                if !((*data).state.aptr.proxyuser).is_null() {
                    (*data).state.aptr.proxyuser as *const i8
                } else {
                    b"\0" as *const u8 as *const i8
                }
            } else if !((*data).state.aptr.user).is_null() {
                (*data).state.aptr.user as *const i8
            } else {
                b"\0" as *const u8 as *const i8
            },
        );
        (*authstatus)
            .set_multipass(
                (if (*authstatus).done() == 0 {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
    } else {
        (*authstatus).set_multipass(0 as i32 as bit);
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_output_auth(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut request: * const i8,
    mut httpreq: u32,
    mut path: * const i8,
    mut proxytunnel: bool,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut authhost: * mut crate::src::lib::http2::auth = (0 as * mut crate::src::lib::http2::auth);
    let mut authproxy: * mut crate::src::lib::http2::auth = (0 as * mut crate::src::lib::http2::auth);
    authhost = &mut (*data).state.authhost;
    authproxy = &mut (*data).state.authproxy;
    if ((*conn).bits).httpproxy() as i32 != 0
        && ((*conn).bits).proxy_user_passwd() as i32 != 0
        || ((*conn).bits).user_passwd() as i32 != 0
        || !((*data).set.str_0[STRING_BEARER as i32 as usize]).is_null()
    {} else {
        (*authhost).set_done(1 as i32 as bit);
        (*authproxy).set_done(1 as i32 as bit);
        return CURLE_OK;
    }
    if (*authhost).want != 0 && (*authhost).picked == 0 {
        (*authhost).picked = (*authhost).want;
    }
    if (*authproxy).want != 0 && (*authproxy).picked == 0 {
        (*authproxy).picked = (*authproxy).want;
    }
    if ((*conn).bits).httpproxy() as i32 != 0
        && ((*conn).bits).tunnel_proxy() == proxytunnel as bit
    {
        result = output_auth_headers(
            data,
            conn,
            authproxy,
            request,
            path,
            1 as i32 != 0,
        );
        if result as u64 != 0 {
            return result;
        }
    } else {
        (*authproxy).set_done(1 as i32 as bit);
    }
    if ((*data).state).this_is_a_follow() == 0
        || ((*conn).bits).netrc() as i32 != 0
        || ((*data).state.first_host).is_null()
        || ((*data).set).allow_auth_to_other_hosts() as i32 != 0
        || Curl_strcasecompare((*data).state.first_host, (*conn).host.name) != 0
    {
        result = output_auth_headers(
            data,
            conn,
            authhost,
            request,
            path,
            0 as i32 != 0,
        );
    } else {
        (*authhost).set_done(1 as i32 as bit);
    }
    if ((*authhost).multipass() as i32 != 0 && (*authhost).done() == 0
        || (*authproxy).multipass() as i32 != 0 && (*authproxy).done() == 0)
        && httpreq as u32 != HTTPREQ_GET as i32 as u32
        && httpreq as u32 != HTTPREQ_HEAD as i32 as u32
    {
        let mut fresh9 = &mut ((*conn).bits);
        (*fresh9).set_authneg(1 as i32 as bit);
    } else {
        let mut fresh10 = &mut ((*conn).bits);
        (*fresh10).set_authneg(0 as i32 as bit);
    }
    return result;
}
unsafe extern "C" fn is_valid_auth_separator(mut ch: i8) -> i32 {
    return (ch as i32 == '\u{0}' as i32 || ch as i32 == ',' as i32
        || Curl_isspace(ch as u8 as i32) != 0) as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_input_auth(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut proxy: bool,
    mut auth: * const i8,
) -> u32 {
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    let mut availp: Option<&'_ mut u64> = Option::<&'_ mut u64>::None;
    let mut authp: Option<&'_ mut crate::src::lib::http2::auth> = Option::<&'_ mut crate::src::lib::http2::auth>::None;
    if proxy {
        availp = Some(&mut (*data).info.proxyauthavail);
        authp = Some(&mut (*data).state.authproxy);
    } else {
        availp = Some(&mut (*data).info.httpauthavail);
        authp = Some(&mut (*data).state.authhost);
    }
    while *auth != 0 {
        if curl_strnequal(
            b"NTLM\0" as *const u8 as *const i8,
            auth,
            strlen(b"NTLM\0" as *const u8 as *const i8),
        ) != 0 && is_valid_auth_separator(*auth.offset(4 as i32 as isize)) != 0
        {
            if (*(borrow(& authp)).unwrap()).avail & (1 as i32 as u64) << 3 as i32
                != 0
                || (*(borrow(& authp)).unwrap()).avail
                    & (1 as i32 as u64) << 5 as i32 != 0
                || Curl_auth_is_ntlm_supported() as i32 != 0
            {
                *(borrow_mut(&mut availp)).unwrap() |= (1 as i32 as u64) << 3 as i32;
                (*(borrow_mut(&mut authp)).unwrap()).avail
                    |= (1 as i32 as u64) << 3 as i32;
                if (*(borrow(& authp)).unwrap()).picked
                    == (1 as i32 as u64) << 3 as i32
                    || (*(borrow(& authp)).unwrap()).picked
                        == (1 as i32 as u64) << 5 as i32
                {
                    let mut result: u32 = Curl_input_ntlm(data, proxy, auth);
                    if result as u64 == 0 {
                        let mut fresh11 = &mut ((*data).state);
                        (*fresh11).set_authproblem(0 as i32 as bit);
                        if (*(borrow(& authp)).unwrap()).picked
                            == (1 as i32 as u64) << 5 as i32
                        {
                            *(borrow_mut(&mut availp)).unwrap()
                                &= !((1 as i32 as u64)
                                    << 3 as i32);
                            (*(borrow_mut(&mut authp)).unwrap()).avail
                                &= !((1 as i32 as u64)
                                    << 3 as i32);
                            *(borrow_mut(&mut availp)).unwrap()
                                |= (1 as i32 as u64) << 5 as i32;
                            (*(borrow_mut(&mut authp)).unwrap()).avail
                                |= (1 as i32 as u64) << 5 as i32;
                            result = Curl_input_ntlm_wb(data, conn, proxy, auth);
                            if result as u64 != 0 {
                                Curl_infof(
                                    data,
                                    b"Authentication problem. Ignoring this.\0" as *const u8
                                        as *const i8,
                                );
                                let mut fresh12 = &mut ((*data).state);
                                (*fresh12).set_authproblem(1 as i32 as bit);
                            }
                        }
                    } else {
                        Curl_infof(
                            data,
                            b"Authentication problem. Ignoring this.\0" as *const u8
                                as *const i8,
                        );
                        let mut fresh13 = &mut ((*data).state);
                        (*fresh13).set_authproblem(1 as i32 as bit);
                    }
                }
            }
        } else if curl_strnequal(
                b"Digest\0" as *const u8 as *const i8,
                auth,
                strlen(b"Digest\0" as *const u8 as *const i8),
            ) != 0
                && is_valid_auth_separator(*auth.offset(6 as i32 as isize)) != 0
            {
            if (*(borrow(& authp)).unwrap()).avail & (1 as i32 as u64) << 1 as i32
                != 0 as i32 as u64
            {
                Curl_infof(
                    data,
                    b"Ignoring duplicate digest auth header.\0" as *const u8
                        as *const i8,
                );
            } else if Curl_auth_is_digest_supported() {
                let mut result_0: u32 = CURLE_OK;
                *(borrow_mut(&mut availp)).unwrap() |= (1 as i32 as u64) << 1 as i32;
                (*(borrow_mut(&mut authp)).unwrap()).avail
                    |= (1 as i32 as u64) << 1 as i32;
                result_0 = Curl_input_digest(data, proxy, auth);
                if result_0 as u64 != 0 {
                    Curl_infof(
                        data,
                        b"Authentication problem. Ignoring this.\0" as *const u8
                            as *const i8,
                    );
                    let mut fresh14 = &mut ((*data).state);
                    (*fresh14).set_authproblem(1 as i32 as bit);
                }
            }
        } else if curl_strnequal(
                b"Basic\0" as *const u8 as *const i8,
                auth,
                strlen(b"Basic\0" as *const u8 as *const i8),
            ) != 0
                && is_valid_auth_separator(*auth.offset(5 as i32 as isize)) != 0
            {
            *(borrow_mut(&mut availp)).unwrap() |= (1 as i32 as u64) << 0 as i32;
            (*(borrow_mut(&mut authp)).unwrap()).avail |= (1 as i32 as u64) << 0 as i32;
            if (*(borrow(& authp)).unwrap()).picked == (1 as i32 as u64) << 0 as i32
            {
                (*(borrow_mut(&mut authp)).unwrap()).avail = 0 as i32 as u64;
                Curl_infof(
                    data,
                    b"Authentication problem. Ignoring this.\0" as *const u8
                        as *const i8,
                );
                let mut fresh15 = &mut ((*data).state);
                (*fresh15).set_authproblem(1 as i32 as bit);
            }
        } else if curl_strnequal(
                b"Bearer\0" as *const u8 as *const i8,
                auth,
                strlen(b"Bearer\0" as *const u8 as *const i8),
            ) != 0
                && is_valid_auth_separator(*auth.offset(6 as i32 as isize)) != 0
            {
            *(borrow_mut(&mut availp)).unwrap() |= (1 as i32 as u64) << 6 as i32;
            (*(borrow_mut(&mut authp)).unwrap()).avail |= (1 as i32 as u64) << 6 as i32;
            if (*(borrow(& authp)).unwrap()).picked == (1 as i32 as u64) << 6 as i32
            {
                (*(borrow_mut(&mut authp)).unwrap()).avail = 0 as i32 as u64;
                Curl_infof(
                    data,
                    b"Authentication problem. Ignoring this.\0" as *const u8
                        as *const i8,
                );
                let mut fresh16 = &mut ((*data).state);
                (*fresh16).set_authproblem(1 as i32 as bit);
            }
        }
        while *auth as i32 != 0 && *auth as i32 != ',' as i32 {
            auth = auth.offset(1);
        }
        if *auth as i32 == ',' as i32 {
            auth = auth.offset(1);
        }
        while *auth as i32 != 0
            && Curl_isspace(*auth as u8 as i32) != 0
        {
            auth = auth.offset(1);
        }
    }
    return CURLE_OK;
}
unsafe extern "C" fn http_should_fail(mut data: * mut crate::src::lib::http2::Curl_easy) -> bool {
    let mut httpcode: i32 = 0;
    httpcode = (*data).req.httpcode;
    if ((*data).set).http_fail_on_error() == 0 {
        return 0 as i32 != 0;
    }
    if httpcode < 400 as i32 {
        return 0 as i32 != 0;
    }
    if (*data).state.resume_from != 0
        && (*data).state.httpreq as u32
            == HTTPREQ_GET as i32 as u32
        && httpcode == 416 as i32
    {
        return 0 as i32 != 0;
    }
    if httpcode != 401 as i32 && httpcode != 407 as i32 {
        return 1 as i32 != 0;
    }
    if httpcode == 401 as i32 && ((*(*data).conn).bits).user_passwd() == 0 {
        return 1 as i32 != 0;
    }
    if httpcode == 407 as i32 && ((*(*data).conn).bits).proxy_user_passwd() == 0
    {
        return 1 as i32 != 0;
    }
    return ((*data).state).authproblem() != 0;
}
unsafe extern "C" fn readmoredata(
    mut buffer: * mut i8,
    mut size: u64,
    mut nitems: u64,
    mut userp: * mut core::ffi::c_void,
) -> u64 {
    let mut data: * mut crate::src::lib::http2::Curl_easy = userp as *mut Curl_easy;
    let mut http: * mut crate::src::lib::http2::HTTP = (*data).req.p.http;
    let mut fullsize: u64 = size.wrapping_mul(nitems);
    if (*http).postsize == 0 {
        return 0 as i32 as size_t;
    }
    let mut fresh17 = &mut ((*data).req);
    (*fresh17)
        .set_forbidchunk(
            (if (*http).sending as u32
                == HTTPSEND_REQUEST as i32 as u32
            {
                1 as i32
            } else {
                0 as i32
            }) as bit,
        );
    if (*data).set.max_send_speed != 0
        && (*data).set.max_send_speed < fullsize as curl_off_t
        && (*data).set.max_send_speed < (*http).postsize
    {
        fullsize = (*data).set.max_send_speed as size_t;
    } else if (*http).postsize <= fullsize as curl_off_t {
        memcpy(
            buffer as *mut libc::c_void,
            (*http).postdata as *const libc::c_void,
            (*http).postsize as size_t,
        );
        fullsize = (*http).postsize as size_t;
        if (*http).backup.postsize != 0 {
            let mut fresh18 = &mut ((*http).postdata);
            *fresh18 = (*http).backup.postdata;
            (*http).postsize = (*http).backup.postsize;
            let mut fresh19 = &mut ((*data).state.fread_func);
            *fresh19 = (*http).backup.fread_func;
            let mut fresh20 = &mut ((*data).state.in_0);
            *fresh20 = (*http).backup.fread_in;
            let mut fresh21 = &mut ((*http).sending);
            *fresh21 += 1;
            (*http).backup.postsize = 0 as i32 as curl_off_t;
        } else {
            (*http).postsize = 0 as i32 as curl_off_t;
        }
        return fullsize;
    }
    memcpy(
        buffer as *mut libc::c_void,
        (*http).postdata as *const libc::c_void,
        fullsize,
    );
    let mut fresh22 = &mut ((*http).postdata);
    *fresh22 = (*fresh22).offset(fullsize as isize);
    let mut fresh23 = &mut ((*http).postsize);
    *fresh23 = (*fresh23 as u64).wrapping_sub(fullsize) as curl_off_t
        as curl_off_t;
    return fullsize;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_buffer_send<'a1>(
    mut in_0: * mut crate::src::lib::http2::dynbuf,
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut bytes_written: Option<&'a1 mut i64>,
    mut included_body_bytes: i64,
    mut socketindex: i32,
) -> u32 {
    let mut amount: i64 = 0;
    let mut result: u32 = CURLE_OK;
    let mut ptr: * mut i8 = 0 as *mut i8;
    let mut size: u64 = 0;
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    let mut http: * mut crate::src::lib::http2::HTTP = (*data).req.p.http;
    let mut sendsize: u64 = 0;
    let mut sockfd: i32 = 0;
    let mut headersize: u64 = 0;
    sockfd = (*conn).sock[socketindex as usize];
    ptr = Curl_dyn_ptr(in_0);
    size = Curl_dyn_len(in_0);
    headersize = size.wrapping_sub(included_body_bytes as size_t);
    result = CURLE_OK as i32 as CURLcode;
    if result as u64 != 0 {
        Curl_dyn_free(in_0);
        return result;
    }
    if ((*(*conn).handler).flags
        & ((1 as i32) << 0 as i32) as u32 != 0
        || (*conn).http_proxy.proxytype as u32
            == CURLPROXY_HTTPS as i32 as u32)
        && (*conn).httpversion as i32 != 20 as i32
    {
        if (*data).set.max_send_speed != 0
            && included_body_bytes > (*data).set.max_send_speed
        {
            let mut overflow: i64 = included_body_bytes
                - (*data).set.max_send_speed;
            sendsize = size.wrapping_sub(overflow as size_t);
        } else {
            sendsize = size;
        }
        result = Curl_get_upload_buffer(data);
        if result as u64 != 0 {
            Curl_dyn_free(in_0);
            return result;
        }
        if sendsize > (*data).set.upload_buffer_size as size_t {
            sendsize = (*data).set.upload_buffer_size as size_t;
        }
        memcpy(
            (*data).state.ulbuf as *mut libc::c_void,
            ptr as *const libc::c_void,
            sendsize,
        );
        ptr = (*data).state.ulbuf;
    } else if (*data).set.max_send_speed != 0
            && included_body_bytes > (*data).set.max_send_speed
        {
        let mut overflow_0: i64 = included_body_bytes
            - (*data).set.max_send_speed;
        sendsize = size.wrapping_sub(overflow_0 as size_t);
    } else {
        sendsize = size;
    }
    result = Curl_write(data, sockfd, ptr as *const libc::c_void, sendsize, Some(&mut amount));
    if result as u64 == 0 {
        let mut headlen: u64 = if amount as size_t > headersize {
            headersize
        } else {
            amount as size_t
        };
        let mut bodylen: u64 = (amount as u64).wrapping_sub(headlen);
        Curl_debug(data, CURLINFO_HEADER_OUT, ptr, headlen);
        if bodylen != 0 {
            Curl_debug(data, CURLINFO_DATA_OUT, ptr.offset(headlen as isize), bodylen);
        }
        *(borrow_mut(&mut bytes_written)).unwrap() += amount;
        if !http.is_null() {
            let mut fresh24 = &mut ((*data).req.writebytecount);
            *fresh24 = (*fresh24 as u64).wrapping_add(bodylen) as curl_off_t
                as curl_off_t;
            Curl_pgrsSetUploadCounter(data, (*data).req.writebytecount);
            if amount as size_t != size {
                size = (size as u64).wrapping_sub(amount as u64)
                    as size_t as size_t;
                ptr = (Curl_dyn_ptr(in_0)).offset(amount as isize);
                let mut fresh25 = &mut ((*http).backup.fread_func);
                *fresh25 = (*data).state.fread_func;
                let mut fresh26 = &mut ((*http).backup.fread_in);
                *fresh26 = (*data).state.in_0;
                let mut fresh27 = &mut ((*http).backup.postdata);
                *fresh27 = (*http).postdata;
                (*http).backup.postsize = (*http).postsize;
                let mut fresh28 = &mut ((*data).state.fread_func);
                *fresh28 = core::intrinsics::transmute::<Option<unsafe extern "C"  fn(_: * mut i8,_: u64,_: u64,_: * mut core::ffi::c_void,) -> u64>, Option<unsafe extern "C"  fn(_: * mut i8,_: u64,_: u64,_: * mut core::ffi::c_void,) -> u64>>(
                    Some(
                        readmoredata,
                    ),
                );
                let mut fresh29 = &mut ((*data).state.in_0);
                *fresh29 = data as *mut libc::c_void;
                let mut fresh30 = &mut ((*http).postdata);
                *fresh30 = ptr;
                (*http).postsize = size as curl_off_t;
                (*data)
                    .req
                    .pendingheader = headersize.wrapping_sub(headlen) as curl_off_t;
                (*http).send_buffer = *in_0;
                (*http).sending = HTTPSEND_REQUEST;
                return CURLE_OK;
            }
            (*http).sending = HTTPSEND_BODY;
        } else if amount as size_t != size {
            return CURLE_SEND_ERROR
        }
    }
    Curl_dyn_free(in_0);
    (*data).req.pendingheader = 0 as i32 as curl_off_t;
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_compareheader(
    mut headerline: * const i8,
    mut header: * const i8,
    mut content: * const i8,
) -> bool {
    let mut hlen: u64 = strlen(header);
    let mut clen: u64 = 0;
    let mut len: u64 = 0;
    let mut start: * const i8 = 0 as *const i8;
    let mut end: * const i8 = 0 as *const i8;
    if Curl_strncasecompare(headerline, header, hlen) == 0 {
        return 0 as i32 != 0;
    }
    start = &*headerline.offset(hlen as isize) as *const i8;
    while *start as i32 != 0
        && Curl_isspace(*start as u8 as i32) != 0
    {
        start = start.offset(1);
    }
    end = strchr(start, '\r' as i32);
    if end.is_null() {
        end = strchr(start, '\n' as i32);
        if end.is_null() {
            end = strchr(start, '\u{0}' as i32);
        }
    }
    len = end.offset_from(start) as i64 as size_t;
    clen = strlen(content);
    while len >= clen {
        if Curl_strncasecompare(start, content, clen) != 0 {
            return 1 as i32 != 0;
        }
        len = len.wrapping_sub(1);
        start = start.offset(1);
    }
    return 0 as i32 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_connect(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut done: * mut bool,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    Curl_conncontrol(conn, 0 as i32);
    result = Curl_proxy_connect(data, 0 as i32);
    if result as u64 != 0 {
        return result;
    }
    if ((*conn).bits).proxy_connect_closed() != 0 {
        return CURLE_OK;
    }
    if (*conn).http_proxy.proxytype as u32
        == CURLPROXY_HTTPS as i32 as u32
        && !(*conn).bits.proxy_ssl_connected[0 as i32 as usize]
    {
        return CURLE_OK;
    }
    if Curl_connect_ongoing(conn) {
        return CURLE_OK;
    }
    if ((*data).set).haproxyprotocol() != 0 {
        result = add_haproxy_protocol_header(data);
        if result as u64 != 0 {
            return result;
        }
    }
    if (*(*conn).given).protocol
        & ((1 as i32) << 1 as i32) as u32 != 0
    {
        result = https_connecting(data, done);
        if result as u64 != 0 {
            return result;
        }
    } else {
        *done = 1 as i32 != 0;
    }
    return CURLE_OK;
}
unsafe extern "C" fn http_getsock_do(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut socks: * mut i32,
) -> i32 {
    *socks.offset(0 as i32 as isize) = (*conn).sock[0 as i32 as usize];
    return (1 as i32) << 16 as i32 + 0 as i32;
}
unsafe extern "C" fn add_haproxy_protocol_header(mut data: * mut crate::src::lib::http2::Curl_easy) -> u32 {
    let mut req: crate::src::lib::http2::dynbuf = dynbuf {
        bufr: 0 as *mut i8,
        leng: 0,
        allc: 0,
        toobig: 0,
    };
    let mut result: u32 = CURLE_OK;
    let mut tcp_version: * const i8 = 0 as *const i8;
    Curl_dyn_init(&mut req, 2048 as i32 as size_t);
    if !((*(*data).conn).unix_domain_socket).is_null() {
        result = Curl_dyn_add(
            &mut req,
            b"PROXY UNKNOWN\r\n\0" as *const u8 as *const i8,
        );
    } else {
        tcp_version = if ((*(*data).conn).bits).ipv6() as i32 != 0 {
            b"TCP6\0" as *const u8 as *const i8
        } else {
            b"TCP4\0" as *const u8 as *const i8
        };
        result = Curl_dyn_addf(
            &mut req as *mut dynbuf,
            b"PROXY %s %s %s %i %i\r\n\0" as *const u8 as *const i8,
            tcp_version,
            ((*data).info.conn_local_ip).as_mut_ptr(),
            ((*data).info.conn_primary_ip).as_mut_ptr(),
            (*data).info.conn_local_port,
            (*data).info.conn_primary_port,
        );
    }
    if result as u64 == 0 {
        result = Curl_buffer_send(
            &mut req,
            data,
            Some(&mut (*data).info.request_size),
            0 as i32 as curl_off_t,
            0 as i32,
        );
    }
    return result;
}
unsafe extern "C" fn https_connecting(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut done: * mut bool,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    result = Curl_ssl_connect_nonblocking(
        data,
        conn,
        0 as i32 != 0,
        0 as i32,
        done,
    );
    if result as u64 != 0 {
        Curl_conncontrol(conn, 1 as i32);
    }
    return result;
}
unsafe extern "C" fn https_getsock(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut socks: * mut i32,
) -> i32 {
    if (*(*conn).handler).flags
        & ((1 as i32) << 0 as i32) as u32 != 0
    {
        return ((*Curl_ssl).getsock).expect("non-null function pointer")(conn, socks);
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_done(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut status: u32,
    mut premature: bool,
) -> u32 {
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    let mut http: * mut crate::src::lib::http2::HTTP = (*data).req.p.http;
    let mut fresh31 = &mut ((*data).state.authhost);
    (*fresh31).set_multipass(0 as i32 as bit);
    let mut fresh32 = &mut ((*data).state.authproxy);
    (*fresh32).set_multipass(0 as i32 as bit);
    Curl_unencode_cleanup(data);
    let mut fresh33 = &mut ((*conn).seek_func);
    *fresh33 = (*data).set.seek_func;
    let mut fresh34 = &mut ((*conn).seek_client);
    *fresh34 = (*data).set.seek_client;
    if http.is_null() {
        return CURLE_OK;
    }
    Curl_dyn_free(&mut (*http).send_buffer);
    Curl_http2_done(data, premature);
    Curl_mime_cleanpart(&mut (*http).form);
    Curl_dyn_reset(Some(&mut (*data).state.headerb));
    if status as u64 != 0 {
        return status;
    }
    if !premature && ((*conn).bits).retry() == 0 && ((*data).set).connect_only() == 0
        && (*data).req.bytecount + (*data).req.headerbytecount
            - (*data).req.deductheadercount <= 0 as i32 as i64
    {
        Curl_failf(
            data,
            b"Empty reply from server\0" as *const u8 as *const i8,
        );
        Curl_conncontrol(conn, 2 as i32);
        return CURLE_GOT_NOTHING;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_use_http_1_1plus(
    mut data: * const crate::src::lib::http2::Curl_easy,
    mut conn: * const crate::src::lib::http2::connectdata,
) -> bool {
    if (*data).state.httpversion as i32 == 10 as i32
        || (*conn).httpversion as i32 == 10 as i32
    {
        return 0 as i32 != 0;
    }
    if (*data).state.httpwant as i32 == CURL_HTTP_VERSION_1_0 as i32
        && (*conn).httpversion as i32 <= 10 as i32
    {
        return 0 as i32 != 0;
    }
    return (*data).state.httpwant as i32 == CURL_HTTP_VERSION_NONE as i32
        || (*data).state.httpwant as i32 >= CURL_HTTP_VERSION_1_1 as i32;
}
unsafe extern "C" fn get_http_string(
    mut data: * const crate::src::lib::http2::Curl_easy,
    mut conn: * const crate::src::lib::http2::connectdata,
) -> * const i8 {
    if !((*conn).proto.httpc.h2).is_null() {
        return b"2\0" as *const u8 as *const i8;
    }
    if Curl_use_http_1_1plus(data, conn) {
        return b"1.1\0" as *const u8 as *const i8;
    }
    return b"1.0\0" as *const u8 as *const i8;
}
unsafe extern "C" fn expect100(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut req: * mut crate::src::lib::http2::dynbuf,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut fresh35 = &mut ((*data).state);
    (*fresh35).set_expect100header(0 as i32 as bit);
    if ((*data).state).disableexpect() == 0
        && Curl_use_http_1_1plus(data, conn) as i32 != 0
        && ((*conn).httpversion as i32) < 20 as i32
    {
        let mut ptr: * const i8 = Curl_checkheaders(
            data,
            b"Expect\0" as *const u8 as *const i8,
        );
        if !ptr.is_null() {
            let mut fresh36 = &mut ((*data).state);
            (*fresh36)
                .set_expect100header(
                    Curl_compareheader(
                        ptr,
                        b"Expect:\0" as *const u8 as *const i8,
                        b"100-continue\0" as *const u8 as *const i8,
                    ) as bit,
                );
        } else {
            result = Curl_dyn_add(
                req,
                b"Expect: 100-continue\r\n\0" as *const u8 as *const i8,
            );
            if result as u64 == 0 {
                let mut fresh37 = &mut ((*data).state);
                (*fresh37).set_expect100header(1 as i32 as bit);
            }
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_compile_trailers(
    mut trailers: * mut crate::src::lib::http2::curl_slist,
    mut b: * mut crate::src::lib::http2::dynbuf,
    mut handle: * mut crate::src::lib::http2::Curl_easy,
) -> u32 {
    let mut ptr: * mut i8 = 0 as *mut i8;
    let mut result: u32 = CURLE_OK;
    let mut endofline_native: * const i8 = 0 as *const i8;
    let mut endofline_network: * const i8 = 0 as *const i8;
    if ((*handle).state).prefer_ascii() as i32 != 0
        || ((*handle).set).crlf() as i32 != 0
    {
        endofline_native = b"\n\0" as *const u8 as *const i8;
        endofline_network = b"\n\0" as *const u8 as *const i8;
    } else {
        endofline_native = b"\r\n\0" as *const u8 as *const i8;
        endofline_network = b"\r\n\0" as *const u8 as *const i8;
    }
    while !trailers.is_null() {
        ptr = strchr((*trailers).data, ':' as i32);
        if !ptr.is_null()
            && *ptr.offset(1 as i32 as isize) as i32 == ' ' as i32
        {
            result = Curl_dyn_add(b, (*trailers).data);
            if result as u64 != 0 {
                return result;
            }
            result = Curl_dyn_add(b, endofline_native);
            if result as u64 != 0 {
                return result;
            }
        } else {
            Curl_infof(
                handle,
                b"Malformatted trailing header ! Skipping trailer.\0" as *const u8
                    as *const i8,
            );
        }
        trailers = (*trailers).next;
    }
    result = Curl_dyn_add(b, endofline_network);
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_add_custom_headers(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut is_connect: bool,
    mut req: * mut crate::src::lib::http2::dynbuf,
) -> u32 {
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    let mut ptr: * mut i8 = 0 as *mut i8;
    let mut h: [* mut crate::src::lib::http2::curl_slist; 2] = [0 as *mut curl_slist; 2];
    let mut headers: * mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
    let mut numlists: i32 = 1 as i32;
    let mut i: i32 = 0;
    let mut proxy: u32 = HEADER_SERVER;
    if is_connect {
        proxy = HEADER_CONNECT;
    } else {
        proxy = (if ((*conn).bits).httpproxy() as i32 != 0
            && ((*conn).bits).tunnel_proxy() == 0
        {
            HEADER_PROXY as i32
        } else {
            HEADER_SERVER as i32
        }) as proxy_use;
    }
    match proxy as u32 {
        0 => {
            h[0 as i32 as usize] = (*data).set.headers;
        }
        1 => {
            h[0 as i32 as usize] = (*data).set.headers;
            if ((*data).set).sep_headers() != 0 {
                h[1 as i32 as usize] = (*data).set.proxyheaders;
                numlists += 1;
            }
        }
        2 => {
            if ((*data).set).sep_headers() != 0 {
                h[0 as i32 as usize] = (*data).set.proxyheaders;
            } else {
                h[0 as i32 as usize] = (*data).set.headers;
            }
        }
        _ => {}
    }
    i = 0 as i32;
    while i < numlists {
        headers = h[i as usize];
        while !headers.is_null() {
            let mut semicolonp: * mut i8 = 0 as *mut i8;
            ptr = strchr((*headers).data, ':' as i32);
            if ptr.is_null() {
                let mut optr: * mut i8 = 0 as *mut i8;
                ptr = strchr((*headers).data, ';' as i32);
                if !ptr.is_null() {
                    optr = ptr;
                    ptr = ptr.offset(1);
                    while *ptr as i32 != 0
                        && Curl_isspace(*ptr as u8 as i32) != 0
                    {
                        ptr = ptr.offset(1);
                    }
                    if *ptr != 0 {
                        optr = 0 as *mut i8;
                    } else {
                        ptr = ptr.offset(-1);
                        if *ptr as i32 == ';' as i32 {
                            semicolonp = Curl_cstrdup
                                .expect("non-null function pointer")((*headers).data);
                            if semicolonp.is_null() {
                                Curl_dyn_free(req);
                                return CURLE_OUT_OF_MEMORY;
                            }
                            *semicolonp
                                .offset(
                                    ptr.offset_from((*headers).data) as i64 as isize,
                                ) = ':' as i32 as i8;
                            optr = &mut *semicolonp
                                .offset(
                                    ptr.offset_from((*headers).data) as i64 as isize,
                                ) as *mut i8;
                        }
                    }
                    ptr = optr;
                }
            }
            if !ptr.is_null() {
                ptr = ptr.offset(1);
                while *ptr as i32 != 0
                    && Curl_isspace(*ptr as u8 as i32) != 0
                {
                    ptr = ptr.offset(1);
                }
                if *ptr as i32 != 0 || !semicolonp.is_null() {
                    let mut result: u32 = CURLE_OK;
                    let mut compare: * mut i8 = if !semicolonp.is_null() {
                        semicolonp
                    } else {
                        (*headers).data
                    };
                    if !(!((*data).state.aptr.host).is_null()
                        && curl_strnequal(
                            b"Host:\0" as *const u8 as *const i8,
                            compare,
                            strlen(b"Host:\0" as *const u8 as *const i8),
                        ) != 0)
                    {
                        if !((*data).state.httpreq as u32
                            == HTTPREQ_POST_FORM as i32 as u32
                            && curl_strnequal(
                                b"Content-Type:\0" as *const u8 as *const i8,
                                compare,
                                strlen(
                                    b"Content-Type:\0" as *const u8 as *const i8,
                                ),
                            ) != 0)
                        {
                            if !((*data).state.httpreq as u32
                                == HTTPREQ_POST_MIME as i32 as u32
                                && curl_strnequal(
                                    b"Content-Type:\0" as *const u8 as *const i8,
                                    compare,
                                    strlen(
                                        b"Content-Type:\0" as *const u8 as *const i8,
                                    ),
                                ) != 0)
                            {
                                if !(((*conn).bits).authneg() as i32 != 0
                                    && curl_strnequal(
                                        b"Content-Length:\0" as *const u8 as *const i8,
                                        compare,
                                        strlen(
                                            b"Content-Length:\0" as *const u8 as *const i8,
                                        ),
                                    ) != 0)
                                {
                                    if !(!((*data).state.aptr.te).is_null()
                                        && curl_strnequal(
                                            b"Connection:\0" as *const u8 as *const i8,
                                            compare,
                                            strlen(b"Connection:\0" as *const u8 as *const i8),
                                        ) != 0)
                                    {
                                        if !((*conn).httpversion as i32 >= 20 as i32
                                            && curl_strnequal(
                                                b"Transfer-Encoding:\0" as *const u8 as *const i8,
                                                compare,
                                                strlen(
                                                    b"Transfer-Encoding:\0" as *const u8 as *const i8,
                                                ),
                                            ) != 0)
                                        {
                                            if !((curl_strnequal(
                                                b"Authorization:\0" as *const u8 as *const i8,
                                                compare,
                                                strlen(
                                                    b"Authorization:\0" as *const u8 as *const i8,
                                                ),
                                            ) != 0
                                                || curl_strnequal(
                                                    b"Cookie:\0" as *const u8 as *const i8,
                                                    compare,
                                                    strlen(b"Cookie:\0" as *const u8 as *const i8),
                                                ) != 0)
                                                && (((*data).state).this_is_a_follow() as i32 != 0
                                                    && !((*data).state.first_host).is_null()
                                                    && ((*data).set).allow_auth_to_other_hosts() == 0
                                                    && Curl_strcasecompare(
                                                        (*data).state.first_host,
                                                        (*conn).host.name,
                                                    ) == 0))
                                            {
                                                result = Curl_dyn_addf(
                                                    req,
                                                    b"%s\r\n\0" as *const u8 as *const i8,
                                                    compare,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if !semicolonp.is_null() {
                        Curl_cfree
                            .expect(
                                "non-null function pointer",
                            )(semicolonp as *mut libc::c_void);
                    }
                    if result as u64 != 0 {
                        return result;
                    }
                }
            }
            headers = (*headers).next;
        }
        i += 1;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_add_timecondition(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut req: * mut crate::src::lib::http2::dynbuf,
) -> u32 {
    let mut tm: Option<&'_ crate::src::lib::altsvc::tm> = Option::<&'_ crate::src::lib::altsvc::tm>::None;
    let mut keeptime: crate::src::lib::altsvc::tm = tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: 0 as *const i8,
    };
    let mut result: u32 = CURLE_OK;
    let mut datestr: [i8; 80] = [0; 80];
    let mut condp: * const i8 = 0 as *const i8;
    if (*data).set.timecondition as u32
        == CURL_TIMECOND_NONE as i32 as u32
    {
        return CURLE_OK;
    }
    result = Curl_gmtime((*data).set.timevalue, &mut keeptime);
    if result as u64 != 0 {
        Curl_failf(data, b"Invalid TIMEVALUE\0" as *const u8 as *const i8);
        return result;
    }
    tm = Some(&mut keeptime);
    match (*data).set.timecondition as u32 {
        1 => {
            condp = b"If-Modified-Since\0" as *const u8 as *const i8;
        }
        2 => {
            condp = b"If-Unmodified-Since\0" as *const u8 as *const i8;
        }
        3 => {
            condp = b"Last-Modified\0" as *const u8 as *const i8;
        }
        _ => return CURLE_BAD_FUNCTION_ARGUMENT,
    }
    if !(Curl_checkheaders(data, condp)).is_null() {
        return CURLE_OK;
    }
    curl_msnprintf(
        datestr.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 80]>() as u64,
        b"%s: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n\0" as *const u8
            as *const i8,
        condp,
        Curl_wkday[(if (*((tm).clone()).unwrap()).tm_wday != 0 {
            (*((tm).clone()).unwrap()).tm_wday - 1 as i32
        } else {
            6 as i32
        }) as usize],
        (*((tm).clone()).unwrap()).tm_mday,
        Curl_month[(*((tm).clone()).unwrap()).tm_mon as usize],
        (*((tm).clone()).unwrap()).tm_year + 1900 as i32,
        (*((tm).clone()).unwrap()).tm_hour,
        (*((tm).clone()).unwrap()).tm_min,
        (*((tm).clone()).unwrap()).tm_sec,
    );
    result = Curl_dyn_add(req, datestr.as_mut_ptr());
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_method<'a1, 'a2>(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut method: Option<&'a1 mut * const i8>,
    mut reqp: Option<&'a2 mut u32>,
) {
    let mut httpreq: u32 = (*data).state.httpreq;
    let mut request: * const i8 = 0 as *const i8;
    if (*(*conn).handler).protocol
        & ((1 as i32) << 0 as i32
            | (1 as i32) << 1 as i32
            | (1 as i32) << 2 as i32) as u32 != 0
        && ((*data).set).upload() as i32 != 0
    {
        httpreq = HTTPREQ_PUT;
    }
    if !((*data).set.str_0[STRING_CUSTOMREQUEST as i32 as usize]).is_null() {
        request = (*data).set.str_0[STRING_CUSTOMREQUEST as i32 as usize];
    } else if ((*data).set).opt_no_body() != 0 {
        request = b"HEAD\0" as *const u8 as *const i8;
    } else {
        match httpreq as u32 {
            1 | 2 | 3 => {
                request = b"POST\0" as *const u8 as *const i8;
            }
            4 => {
                request = b"PUT\0" as *const u8 as *const i8;
            }
            5 => {
                request = b"HEAD\0" as *const u8 as *const i8;
            }
            0 | _ => {
                request = b"GET\0" as *const u8 as *const i8;
            }
        }
    }
    *(borrow_mut(&mut method)).unwrap() = request;
    *(borrow_mut(&mut reqp)).unwrap() = httpreq;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_useragent(mut data: * mut crate::src::lib::http2::Curl_easy) -> u32 {
    if !(Curl_checkheaders(data, b"User-Agent\0" as *const u8 as *const i8))
        .is_null()
    {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.aptr.uagent as *mut libc::c_void);
        let mut fresh38 = &mut ((*data).state.aptr.uagent);
        *fresh38 = 0 as *mut i8;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_host(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut ptr: * const i8 = 0 as *const i8;
    if ((*data).state).this_is_a_follow() == 0 {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.first_host as *mut libc::c_void);
        let mut fresh39 = &mut ((*data).state.first_host);
        *fresh39 = Curl_cstrdup.expect("non-null function pointer")((*conn).host.name);
        if ((*data).state.first_host).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (*data).state.first_remote_port = (*conn).remote_port;
    }
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.host as *mut libc::c_void);
    let mut fresh40 = &mut ((*data).state.aptr.host);
    *fresh40 = 0 as *mut i8;
    ptr = Curl_checkheaders(data, b"Host\0" as *const u8 as *const i8);
    if !ptr.is_null()
        && (((*data).state).this_is_a_follow() == 0
            || Curl_strcasecompare((*data).state.first_host, (*conn).host.name) != 0)
    {
        let mut cookiehost: * mut i8 = Curl_copy_header_value(ptr);
        if cookiehost.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if *cookiehost == 0 {
            Curl_cfree
                .expect("non-null function pointer")(cookiehost as *mut libc::c_void);
        } else {
            if *cookiehost as i32 == '[' as i32 {
                let mut closingbracket: * mut i8 = 0 as *mut i8;
                memmove(
                    cookiehost as *mut libc::c_void,
                    cookiehost.offset(1 as i32 as isize) as *const libc::c_void,
                    (strlen(cookiehost)).wrapping_sub(1 as i32 as u64),
                );
                closingbracket = strchr(cookiehost, ']' as i32);
                if !closingbracket.is_null() {
                    *closingbracket = 0 as i32 as i8;
                }
            } else {
                let mut startsearch: i32 = 0 as i32;
                let mut colon: * mut i8 = strchr(
                    cookiehost.offset(startsearch as isize),
                    ':' as i32,
                );
                if !colon.is_null() {
                    *colon = 0 as i32 as i8;
                }
            }
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).state.aptr.cookiehost as *mut libc::c_void);
            let mut fresh41 = &mut ((*data).state.aptr.cookiehost);
            *fresh41 = 0 as *mut i8;
            let mut fresh42 = &mut ((*data).state.aptr.cookiehost);
            *fresh42 = cookiehost;
        }
        if strcmp(b"Host:\0" as *const u8 as *const i8, ptr) != 0 {
            let mut fresh43 = &mut ((*data).state.aptr.host);
            *fresh43 = curl_maprintf(
                b"Host:%s\r\n\0" as *const u8 as *const i8,
                &*ptr.offset(5 as i32 as isize) as *const i8,
            );
            if ((*data).state.aptr.host).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        } else {
            let mut fresh44 = &mut ((*data).state.aptr.host);
            *fresh44 = 0 as *mut i8;
        }
    } else {
        let mut host: * const i8 = (*conn).host.name;
        if (*(*conn).given).protocol
            & ((1 as i32) << 1 as i32) as u32 != 0
            && (*conn).remote_port == 443 as i32
            || (*(*conn).given).protocol
                & ((1 as i32) << 0 as i32) as u32 != 0
                && (*conn).remote_port == 80 as i32
        {
            let mut fresh45 = &mut ((*data).state.aptr.host);
            *fresh45 = curl_maprintf(
                b"Host: %s%s%s\r\n\0" as *const u8 as *const i8,
                if ((*conn).bits).ipv6_ip() as i32 != 0 {
                    b"[\0" as *const u8 as *const i8
                } else {
                    b"\0" as *const u8 as *const i8
                },
                host,
                if ((*conn).bits).ipv6_ip() as i32 != 0 {
                    b"]\0" as *const u8 as *const i8
                } else {
                    b"\0" as *const u8 as *const i8
                },
            );
        } else {
            let mut fresh46 = &mut ((*data).state.aptr.host);
            *fresh46 = curl_maprintf(
                b"Host: %s%s%s:%d\r\n\0" as *const u8 as *const i8,
                if ((*conn).bits).ipv6_ip() as i32 != 0 {
                    b"[\0" as *const u8 as *const i8
                } else {
                    b"\0" as *const u8 as *const i8
                },
                host,
                if ((*conn).bits).ipv6_ip() as i32 != 0 {
                    b"]\0" as *const u8 as *const i8
                } else {
                    b"\0" as *const u8 as *const i8
                },
                (*conn).remote_port,
            );
        }
        if ((*data).state.aptr.host).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_target(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut r: * mut crate::src::lib::http2::dynbuf,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut path: * const i8 = (*data).state.up.path;
    let mut query: * const i8 = (*data).state.up.query;
    if !((*data).set.str_0[STRING_TARGET as i32 as usize]).is_null() {
        path = (*data).set.str_0[STRING_TARGET as i32 as usize];
        query = 0 as *const i8;
    }
    if ((*conn).bits).httpproxy() as i32 != 0
        && ((*conn).bits).tunnel_proxy() == 0
    {
        let mut uc: u32 = CURLUE_OK;
        let mut url: * mut i8 = 0 as *mut i8;
        let mut h: * mut crate::src::lib::urlapi::Curl_URL = curl_url_dup((*data).state.uh);
        if h.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if (*conn).host.dispname != (*conn).host.name as *const i8 {
            uc = curl_url_set(
                h,
                CURLUPART_HOST,
                (*conn).host.name,
                0 as i32 as u32,
            );
            if uc as u64 != 0 {
                curl_url_cleanup(h);
                return CURLE_OUT_OF_MEMORY;
            }
        }
        uc = curl_url_set(
            h,
            CURLUPART_FRAGMENT,
            0 as *const i8,
            0 as i32 as u32,
        );
        if uc as u64 != 0 {
            curl_url_cleanup(h);
            return CURLE_OUT_OF_MEMORY;
        }
        if Curl_strcasecompare(
            b"http\0" as *const u8 as *const i8,
            (*data).state.up.scheme,
        ) != 0
        {
            uc = curl_url_set(
                h,
                CURLUPART_USER,
                0 as *const i8,
                0 as i32 as u32,
            );
            if uc as u64 != 0 {
                curl_url_cleanup(h);
                return CURLE_OUT_OF_MEMORY;
            }
            uc = curl_url_set(
                h,
                CURLUPART_PASSWORD,
                0 as *const i8,
                0 as i32 as u32,
            );
            if uc as u64 != 0 {
                curl_url_cleanup(h);
                return CURLE_OUT_OF_MEMORY;
            }
        }
        uc = curl_url_get(
            h,
            CURLUPART_URL,
            Some(&mut url),
            ((1 as i32) << 1 as i32) as u32,
        );
        if uc as u64 != 0 {
            curl_url_cleanup(h);
            return CURLE_OUT_OF_MEMORY;
        }
        curl_url_cleanup(h);
        result = Curl_dyn_add(
            r,
            if !((*data).set.str_0[STRING_TARGET as i32 as usize]).is_null() {
                (*data).set.str_0[STRING_TARGET as i32 as usize]
            } else {
                url
            },
        );
        Curl_cfree.expect("non-null function pointer")(url as *mut libc::c_void);
        if result as u64 != 0 {
            return result;
        }
        if Curl_strcasecompare(
            b"ftp\0" as *const u8 as *const i8,
            (*data).state.up.scheme,
        ) != 0
        {
            if ((*data).set).proxy_transfer_mode() != 0 {
                let mut type_0: * mut i8 = strstr(
                    path,
                    b";type=\0" as *const u8 as *const i8,
                );
                if !type_0.is_null()
                    && *type_0.offset(6 as i32 as isize) as i32 != 0
                    && *type_0.offset(7 as i32 as isize) as i32
                        == 0 as i32
                {
                    match Curl_raw_toupper(*type_0.offset(6 as i32 as isize))
                        as i32
                    {
                        65 | 68 | 73 => {}
                        _ => {
                            type_0 = (0 as * mut i8);
                        }
                    }
                }
                if type_0.is_null() {
                    result = Curl_dyn_addf(
                        r,
                        b";type=%c\0" as *const u8 as *const i8,
                        if ((*data).state).prefer_ascii() as i32 != 0 {
                            'a' as i32
                        } else {
                            'i' as i32
                        },
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                }
            }
        }
    } else {
        result = Curl_dyn_add(r, path);
        if result as u64 != 0 {
            return result;
        }
        if !query.is_null() {
            result = Curl_dyn_addf(
                r,
                b"?%s\0" as *const u8 as *const i8,
                query,
            );
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_body<'a1>(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut httpreq: u32,
    mut tep: Option<&'a1 mut * const i8>,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut ptr: * const i8 = 0 as *const i8;
    let mut http: * mut crate::src::lib::http2::HTTP = (*data).req.p.http;
    (*http).postsize = 0 as i32 as curl_off_t;
    match httpreq as u32 {
        3 => {
            let mut fresh47 = &mut ((*http).sendit);
            *fresh47 = &mut (*data).set.mimepost;
        }
        2 => {
            Curl_mime_cleanpart(&mut (*http).form);
            result = Curl_getformdata(
                data,
                &mut (*http).form,
                (*data).set.httppost,
                (*data).state.fread_func,
            );
            if result as u64 != 0 {
                return result;
            }
            let mut fresh48 = &mut ((*http).sendit);
            *fresh48 = &mut (*http).form;
        }
        _ => {
            let mut fresh49 = &mut ((*http).sendit);
            *fresh49 = 0 as *mut curl_mimepart;
        }
    }
    if !((*http).sendit).is_null() {
        let mut cthdr: * const i8 = Curl_checkheaders(
            data,
            b"Content-Type\0" as *const u8 as *const i8,
        );
        (*(*http).sendit).flags
            |= ((1 as i32) << 1 as i32) as u32;
        if !cthdr.is_null() {
            cthdr = cthdr.offset(13 as i32 as isize);
            while *cthdr as i32 == ' ' as i32 {
                cthdr = cthdr.offset(1);
            }
        } else if (*(*http).sendit).kind as u32
                == MIMEKIND_MULTIPART as i32 as u32
            {
            cthdr = b"multipart/form-data\0" as *const u8 as *const i8;
        }
        curl_mime_headers((*http).sendit, (*data).set.headers, 0 as i32);
        result = Curl_mime_prepare_headers(
            (*http).sendit,
            cthdr,
            0 as *const i8,
            MIMESTRATEGY_FORM,
        );
        curl_mime_headers((*http).sendit, 0 as *mut curl_slist, 0 as i32);
        if result as u64 == 0 {
            result = Curl_mime_rewind((*http).sendit);
        }
        if result as u64 != 0 {
            return result;
        }
        (*http).postsize = Curl_mime_size((*http).sendit);
    }
    ptr = Curl_checkheaders(
        data,
        b"Transfer-Encoding\0" as *const u8 as *const i8,
    );
    if !ptr.is_null() {
        let mut fresh50 = &mut ((*data).req);
        (*fresh50)
            .set_upload_chunky(
                Curl_compareheader(
                    ptr,
                    b"Transfer-Encoding:\0" as *const u8 as *const i8,
                    b"chunked\0" as *const u8 as *const i8,
                ) as bit,
            );
    } else {
        if (*(*conn).handler).protocol
            & ((1 as i32) << 0 as i32
                | (1 as i32) << 1 as i32) as u32 != 0
            && ((httpreq as u32
                == HTTPREQ_POST_MIME as i32 as u32
                || httpreq as u32
                    == HTTPREQ_POST_FORM as i32 as u32)
                && (*http).postsize < 0 as i32 as i64
                || (((*data).set).upload() as i32 != 0
                    || httpreq as u32
                        == HTTPREQ_POST as i32 as u32)
                    && (*data).state.infilesize == -(1 as i32) as i64)
        {
            if !(((*conn).bits).authneg() != 0) {
                if Curl_use_http_1_1plus(data, conn) {
                    if ((*conn).httpversion as i32) < 20 as i32 {
                        let mut fresh51 = &mut ((*data).req);
                        (*fresh51).set_upload_chunky(1 as i32 as bit);
                    }
                } else {
                    Curl_failf(
                        data,
                        b"Chunky upload is not supported by HTTP 1.0\0" as *const u8
                            as *const i8,
                    );
                    return CURLE_UPLOAD_FAILED;
                }
            }
        } else {
            let mut fresh52 = &mut ((*data).req);
            (*fresh52).set_upload_chunky(0 as i32 as bit);
        }
        if ((*data).req).upload_chunky() != 0 {
            *(borrow_mut(&mut tep)).unwrap() = b"Transfer-Encoding: chunked\r\n\0" as *const u8
                as *const i8;
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_bodysend(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut r: * mut crate::src::lib::http2::dynbuf,
    mut httpreq: u32,
) -> u32 {
    let mut included_body: i64 = 0 as i32 as curl_off_t;
    let mut result: u32 = CURLE_OK;
    let mut http: * mut crate::src::lib::http2::HTTP = (*data).req.p.http;
    let mut ptr: * const i8 = 0 as *const i8;
    match httpreq as u32 {
        4 => {
            if ((*conn).bits).authneg() != 0 {
                (*http).postsize = 0 as i32 as curl_off_t;
            } else {
                (*http).postsize = (*data).state.infilesize;
            }
            if (*http).postsize != -(1 as i32) as i64
                && ((*data).req).upload_chunky() == 0
                && (((*conn).bits).authneg() as i32 != 0
                    || (Curl_checkheaders(
                        data,
                        b"Content-Length\0" as *const u8 as *const i8,
                    ))
                        .is_null())
            {
                result = Curl_dyn_addf(
                    r,
                    b"Content-Length: %ld\r\n\0" as *const u8 as *const i8,
                    (*http).postsize,
                );
                if result as u64 != 0 {
                    return result;
                }
            }
            if (*http).postsize != 0 {
                result = expect100(data, conn, r);
                if result as u64 != 0 {
                    return result;
                }
            }
            result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const i8);
            if result as u64 != 0 {
                return result;
            }
            Curl_pgrsSetUploadSize(data, (*http).postsize);
            result = Curl_buffer_send(
                r,
                data,
                Some(&mut (*data).info.request_size),
                0 as i32 as curl_off_t,
                0 as i32,
            );
            if result as u64 != 0 {
                Curl_failf(
                    data,
                    b"Failed sending PUT request\0" as *const u8 as *const i8,
                );
            } else {
                Curl_setup_transfer(
                    data,
                    0 as i32,
                    -(1 as i32) as curl_off_t,
                    1 as i32 != 0,
                    if (*http).postsize != 0 {
                        0 as i32
                    } else {
                        -(1 as i32)
                    },
                );
            }
            if result as u64 != 0 {
                return result;
            }
        }
        2 | 3 => {
            if ((*conn).bits).authneg() != 0 {
                result = Curl_dyn_add(
                    r,
                    b"Content-Length: 0\r\n\r\n\0" as *const u8 as *const i8,
                );
                if result as u64 != 0 {
                    return result;
                }
                result = Curl_buffer_send(
                    r,
                    data,
                    Some(&mut (*data).info.request_size),
                    0 as i32 as curl_off_t,
                    0 as i32,
                );
                if result as u64 != 0 {
                    Curl_failf(
                        data,
                        b"Failed sending POST request\0" as *const u8
                            as *const i8,
                    );
                } else {
                    Curl_setup_transfer(
                        data,
                        0 as i32,
                        -(1 as i32) as curl_off_t,
                        1 as i32 != 0,
                        -(1 as i32),
                    );
                }
            } else {
                (*data).state.infilesize = (*http).postsize;
                if (*http).postsize != -(1 as i32) as i64
                    && ((*data).req).upload_chunky() == 0
                    && (((*conn).bits).authneg() as i32 != 0
                        || (Curl_checkheaders(
                            data,
                            b"Content-Length\0" as *const u8 as *const i8,
                        ))
                            .is_null())
                {
                    result = Curl_dyn_addf(
                        r,
                        b"Content-Length: %ld\r\n\0" as *const u8 as *const i8,
                        (*http).postsize,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                }
                let mut hdr: * mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
                hdr = (*(*http).sendit).curlheaders;
                while !hdr.is_null() {
                    result = Curl_dyn_addf(
                        r,
                        b"%s\r\n\0" as *const u8 as *const i8,
                        (*hdr).data,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                    hdr = (*hdr).next;
                }
                ptr = Curl_checkheaders(
                    data,
                    b"Expect\0" as *const u8 as *const i8,
                );
                if !ptr.is_null() {
                    let mut fresh53 = &mut ((*data).state);
                    (*fresh53)
                        .set_expect100header(
                            Curl_compareheader(
                                ptr,
                                b"Expect:\0" as *const u8 as *const i8,
                                b"100-continue\0" as *const u8 as *const i8,
                            ) as bit,
                        );
                } else if (*http).postsize
                        > (1024 as i32 * 1024 as i32) as i64
                        || (*http).postsize < 0 as i32 as i64
                    {
                    result = expect100(data, conn, r);
                    if result as u64 != 0 {
                        return result;
                    }
                } else {
                    let mut fresh54 = &mut ((*data).state);
                    (*fresh54).set_expect100header(0 as i32 as bit);
                }
                result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const i8);
                if result as u64 != 0 {
                    return result;
                }
                Curl_pgrsSetUploadSize(data, (*http).postsize);
                let mut fresh55 = &mut ((*data).state.fread_func);
                *fresh55 = core::intrinsics::transmute::<Option<unsafe extern "C"  fn(_: * mut i8,_: u64,_: u64,_: * mut core::ffi::c_void,) -> u64>, Option<unsafe extern "C"  fn(_: * mut i8,_: u64,_: u64,_: * mut core::ffi::c_void,) -> u64>>(
                    Some(
                        Curl_mime_read,
                    ),
                );
                let mut fresh56 = &mut ((*data).state.in_0);
                *fresh56 = (*http).sendit as *mut libc::c_void;
                (*http).sending = HTTPSEND_BODY;
                result = Curl_buffer_send(
                    r,
                    data,
                    Some(&mut (*data).info.request_size),
                    0 as i32 as curl_off_t,
                    0 as i32,
                );
                if result as u64 != 0 {
                    Curl_failf(
                        data,
                        b"Failed sending POST request\0" as *const u8
                            as *const i8,
                    );
                } else {
                    Curl_setup_transfer(
                        data,
                        0 as i32,
                        -(1 as i32) as curl_off_t,
                        1 as i32 != 0,
                        if (*http).postsize != 0 {
                            0 as i32
                        } else {
                            -(1 as i32)
                        },
                    );
                }
                if result as u64 != 0 {
                    return result;
                }
            }
        }
        1 => {
            if ((*conn).bits).authneg() != 0 {
                (*http).postsize = 0 as i32 as curl_off_t;
            } else {
                (*http).postsize = (*data).state.infilesize;
            }
            if (*http).postsize != -(1 as i32) as i64
                && ((*data).req).upload_chunky() == 0
                && (((*conn).bits).authneg() as i32 != 0
                    || (Curl_checkheaders(
                        data,
                        b"Content-Length\0" as *const u8 as *const i8,
                    ))
                        .is_null())
            {
                result = Curl_dyn_addf(
                    r,
                    b"Content-Length: %ld\r\n\0" as *const u8 as *const i8,
                    (*http).postsize,
                );
                if result as u64 != 0 {
                    return result;
                }
            }
            if (Curl_checkheaders(
                data,
                b"Content-Type\0" as *const u8 as *const i8,
            ))
                .is_null()
            {
                result = Curl_dyn_add(
                    r,
                    b"Content-Type: application/x-www-form-urlencoded\r\n\0" as *const u8
                        as *const i8,
                );
                if result as u64 != 0 {
                    return result;
                }
            }
            ptr = Curl_checkheaders(
                data,
                b"Expect\0" as *const u8 as *const i8,
            );
            if !ptr.is_null() {
                let mut fresh57 = &mut ((*data).state);
                (*fresh57)
                    .set_expect100header(
                        Curl_compareheader(
                            ptr,
                            b"Expect:\0" as *const u8 as *const i8,
                            b"100-continue\0" as *const u8 as *const i8,
                        ) as bit,
                    );
            } else if (*http).postsize
                    > (1024 as i32 * 1024 as i32) as i64
                    || (*http).postsize < 0 as i32 as i64
                {
                result = expect100(data, conn, r);
                if result as u64 != 0 {
                    return result;
                }
            } else {
                let mut fresh58 = &mut ((*data).state);
                (*fresh58).set_expect100header(0 as i32 as bit);
            }
            if !((*data).set.postfields).is_null() {
                if (*conn).httpversion as i32 != 20 as i32
                    && ((*data).state).expect100header() == 0
                    && (*http).postsize
                        < (64 as i32 * 1024 as i32) as i64
                {
                    result = Curl_dyn_add(
                        r,
                        b"\r\n\0" as *const u8 as *const i8,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                    if ((*data).req).upload_chunky() == 0 {
                        result = Curl_dyn_addn(
                            r,
                            (*data).set.postfields,
                            (*http).postsize as size_t,
                        );
                        included_body = (*http).postsize;
                    } else {
                        if (*http).postsize != 0 {
                            let mut chunk: [i8; 16] = [0; 16];
                            curl_msnprintf(
                                chunk.as_mut_ptr(),
                                ::std::mem::size_of::<[i8; 16]>()
                                    as u64,
                                b"%x\r\n\0" as *const u8 as *const i8,
                                (*http).postsize as i32,
                            );
                            result = Curl_dyn_add(r, chunk.as_mut_ptr());
                            if result as u64 == 0 {
                                included_body = ((*http).postsize as u64)
                                    .wrapping_add(strlen(chunk.as_mut_ptr())) as curl_off_t;
                                result = Curl_dyn_addn(
                                    r,
                                    (*data).set.postfields,
                                    (*http).postsize as size_t,
                                );
                                if result as u64 == 0 {
                                    result = Curl_dyn_add(
                                        r,
                                        b"\r\n\0" as *const u8 as *const i8,
                                    );
                                }
                                included_body += 2 as i32 as i64;
                            }
                        }
                        if result as u64 == 0 {
                            result = Curl_dyn_add(
                                r,
                                b"0\r\n\r\n\0" as *const u8 as *const i8,
                            );
                            included_body += 5 as i32 as i64;
                        }
                    }
                    if result as u64 != 0 {
                        return result;
                    }
                    Curl_pgrsSetUploadSize(data, (*http).postsize);
                } else {
                    let mut fresh59 = &mut ((*http).postdata);
                    *fresh59 = (*data).set.postfields as *const i8;
                    (*http).sending = HTTPSEND_BODY;
                    let mut fresh60 = &mut ((*data).state.fread_func);
                    *fresh60 = core::intrinsics::transmute::<Option<unsafe extern "C"  fn(_: * mut i8,_: u64,_: u64,_: * mut core::ffi::c_void,) -> u64>, Option<unsafe extern "C"  fn(_: * mut i8,_: u64,_: u64,_: * mut core::ffi::c_void,) -> u64>>(
                        Some(
                            readmoredata,
                        ),
                    );
                    let mut fresh61 = &mut ((*data).state.in_0);
                    *fresh61 = data as *mut libc::c_void;
                    Curl_pgrsSetUploadSize(data, (*http).postsize);
                    result = Curl_dyn_add(
                        r,
                        b"\r\n\0" as *const u8 as *const i8,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                }
            } else {
                result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const i8);
                if result as u64 != 0 {
                    return result;
                }
                if ((*data).req).upload_chunky() as i32 != 0
                    && ((*conn).bits).authneg() as i32 != 0
                {
                    result = Curl_dyn_add(
                        r,
                        b"0\r\n\r\n\0" as *const u8 as *const i8
                            as *mut i8,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                } else if (*data).state.infilesize != 0 {
                    Curl_pgrsSetUploadSize(
                        data,
                        if (*http).postsize != 0 {
                            (*http).postsize
                        } else {
                            -(1 as i32) as i64
                        },
                    );
                    if ((*conn).bits).authneg() == 0 {
                        let mut fresh62 = &mut ((*http).postdata);
                        *fresh62 = &mut (*http).postdata as *mut *const i8
                            as *mut i8;
                    }
                }
            }
            result = Curl_buffer_send(
                r,
                data,
                Some(&mut (*data).info.request_size),
                included_body,
                0 as i32,
            );
            if result as u64 != 0 {
                Curl_failf(
                    data,
                    b"Failed sending HTTP POST request\0" as *const u8
                        as *const i8,
                );
            } else {
                Curl_setup_transfer(
                    data,
                    0 as i32,
                    -(1 as i32) as curl_off_t,
                    1 as i32 != 0,
                    if !((*http).postdata).is_null() {
                        0 as i32
                    } else {
                        -(1 as i32)
                    },
                );
            }
        }
        _ => {
            result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const i8);
            if result as u64 != 0 {
                return result;
            }
            result = Curl_buffer_send(
                r,
                data,
                Some(&mut (*data).info.request_size),
                0 as i32 as curl_off_t,
                0 as i32,
            );
            if result as u64 != 0 {
                Curl_failf(
                    data,
                    b"Failed sending HTTP request\0" as *const u8 as *const i8,
                );
            } else {
                Curl_setup_transfer(
                    data,
                    0 as i32,
                    -(1 as i32) as curl_off_t,
                    1 as i32 != 0,
                    -(1 as i32),
                );
            }
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_cookies(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut r: * mut crate::src::lib::http2::dynbuf,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut addcookies: * mut i8 = 0 as *mut i8;
    if !((*data).set.str_0[STRING_COOKIE as i32 as usize]).is_null()
        && (Curl_checkheaders(data, b"Cookie\0" as *const u8 as *const i8))
            .is_null()
    {
        addcookies = (*data).set.str_0[STRING_COOKIE as i32 as usize];
    }
    if !((*data).cookies).is_null() || !addcookies.is_null() {
        let mut co: * mut crate::src::lib::http2::Cookie = 0 as *mut Cookie;
        let mut count: i32 = 0 as i32;
        if !((*data).cookies).is_null()
            && ((*data).state).cookie_engine() as i32 != 0
        {
            let mut host: * const i8 = if !((*data).state.aptr.cookiehost)
                .is_null()
            {
                (*data).state.aptr.cookiehost
            } else {
                (*conn).host.name
            };
            let secure_context: bool = if (*(*conn).handler).protocol
                & ((1 as i32) << 1 as i32) as u32 != 0
                || Curl_strcasecompare(
                    b"localhost\0" as *const u8 as *const i8,
                    host,
                ) != 0
                || strcmp(host, b"127.0.0.1\0" as *const u8 as *const i8) == 0
                || strcmp(host, b"[::1]\0" as *const u8 as *const i8) == 0
            {
                1 as i32
            } else {
                0 as i32
            } != 0;
            Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
            co = Curl_cookie_getlist(
                (*data).cookies,
                host,
                (*data).state.up.path,
                secure_context,
            );
            Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
        }
        if !co.is_null() {
            let mut store: * mut crate::src::lib::http2::Cookie = co;
            while !co.is_null() {
                if !((*co).value).is_null() {
                    if 0 as i32 == count {
                        result = Curl_dyn_add(
                            r,
                            b"Cookie: \0" as *const u8 as *const i8,
                        );
                        if result as u64 != 0 {
                            break;
                        }
                    }
                    result = Curl_dyn_addf(
                        r,
                        b"%s%s=%s\0" as *const u8 as *const i8,
                        if count != 0 {
                            b"; \0" as *const u8 as *const i8
                        } else {
                            b"\0" as *const u8 as *const i8
                        },
                        (*co).name,
                        (*co).value,
                    );
                    if result as u64 != 0 {
                        break;
                    }
                    count += 1;
                }
                co = (*co).next;
            }
            Curl_cookie_freelist(store);
        }
        if !addcookies.is_null() && result as u64 == 0 {
            if count == 0 {
                result = Curl_dyn_add(
                    r,
                    b"Cookie: \0" as *const u8 as *const i8,
                );
            }
            if result as u64 == 0 {
                result = Curl_dyn_addf(
                    r,
                    b"%s%s\0" as *const u8 as *const i8,
                    if count != 0 {
                        b"; \0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    addcookies,
                );
                count += 1;
            }
        }
        if count != 0 && result as u64 == 0 {
            result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const i8);
        }
        if result as u64 != 0 {
            return result;
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_range(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut httpreq: u32,
) -> u32 {
    if ((*data).state).use_range() != 0 {
        if (httpreq as u32 == HTTPREQ_GET as i32 as u32
            || httpreq as u32 == HTTPREQ_HEAD as i32 as u32)
            && (Curl_checkheaders(data, b"Range\0" as *const u8 as *const i8))
                .is_null()
        {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).state.aptr.rangeline as *mut libc::c_void);
            let mut fresh63 = &mut ((*data).state.aptr.rangeline);
            *fresh63 = curl_maprintf(
                b"Range: bytes=%s\r\n\0" as *const u8 as *const i8,
                (*data).state.range,
            );
        } else if (httpreq as u32 == HTTPREQ_POST as i32 as u32
                || httpreq as u32 == HTTPREQ_PUT as i32 as u32)
                && (Curl_checkheaders(
                    data,
                    b"Content-Range\0" as *const u8 as *const i8,
                ))
                    .is_null()
            {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).state.aptr.rangeline as *mut libc::c_void);
            if (*data).set.set_resume_from < 0 as i32 as i64 {
                let mut fresh64 = &mut ((*data).state.aptr.rangeline);
                *fresh64 = curl_maprintf(
                    b"Content-Range: bytes 0-%ld/%ld\r\n\0" as *const u8
                        as *const i8,
                    (*data).state.infilesize - 1 as i32 as i64,
                    (*data).state.infilesize,
                );
            } else if (*data).state.resume_from != 0 {
                let mut total_expected_size: i64 = (*data).state.resume_from
                    + (*data).state.infilesize;
                let mut fresh65 = &mut ((*data).state.aptr.rangeline);
                *fresh65 = curl_maprintf(
                    b"Content-Range: bytes %s%ld/%ld\r\n\0" as *const u8
                        as *const i8,
                    (*data).state.range,
                    total_expected_size - 1 as i32 as i64,
                    total_expected_size,
                );
            } else {
                let mut fresh66 = &mut ((*data).state.aptr.rangeline);
                *fresh66 = curl_maprintf(
                    b"Content-Range: bytes %s/%ld\r\n\0" as *const u8
                        as *const i8,
                    (*data).state.range,
                    (*data).state.infilesize,
                );
            }
            if ((*data).state.aptr.rangeline).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_resume(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut httpreq: u32,
) -> u32 {
    if (HTTPREQ_POST as i32 as u32 == httpreq as u32
        || HTTPREQ_PUT as i32 as u32 == httpreq as u32)
        && (*data).state.resume_from != 0
    {
        if (*data).state.resume_from < 0 as i32 as i64 {
            (*data).state.resume_from = 0 as i32 as curl_off_t;
        }
        if (*data).state.resume_from != 0 && ((*data).state).this_is_a_follow() == 0 {
            let mut seekerr: i32 = 2 as i32;
            if ((*conn).seek_func).is_some() {
                Curl_set_in_callback(data, 1 as i32 != 0);
                seekerr = ((*conn).seek_func)
                    .expect(
                        "non-null function pointer",
                    )((*conn).seek_client, (*data).state.resume_from, 0 as i32);
                Curl_set_in_callback(data, 0 as i32 != 0);
            }
            if seekerr != 0 as i32 {
                let mut passed: i64 = 0 as i32 as curl_off_t;
                if seekerr != 2 as i32 {
                    Curl_failf(
                        data,
                        b"Could not seek stream\0" as *const u8 as *const i8,
                    );
                    return CURLE_READ_ERROR;
                }
                loop {
                    let mut readthisamountnow: u64 = if (*data).state.resume_from
                        - passed > (*data).set.buffer_size
                    {
                        (*data).set.buffer_size as size_t
                    } else {
                        curlx_sotouz((*data).state.resume_from - passed)
                    };
                    let mut actuallyread: u64 = ((*data).state.fread_func)
                        .expect(
                            "non-null function pointer",
                        )(
                        (*data).state.buffer,
                        1 as i32 as size_t,
                        readthisamountnow,
                        (*data).state.in_0,
                    );
                    passed = (passed as u64).wrapping_add(actuallyread)
                        as curl_off_t as curl_off_t;
                    if actuallyread == 0 as i32 as u64
                        || actuallyread > readthisamountnow
                    {
                        Curl_failf(
                            data,
                            b"Could only read %ld bytes from the input\0" as *const u8
                                as *const i8,
                            passed,
                        );
                        return CURLE_READ_ERROR;
                    }
                    if !(passed < (*data).state.resume_from) {
                        break;
                    }
                }
            }
            if (*data).state.infilesize > 0 as i32 as i64 {
                let mut fresh67 = &mut ((*data).state.infilesize);
                *fresh67 -= (*data).state.resume_from;
                if (*data).state.infilesize <= 0 as i32 as i64 {
                    Curl_failf(
                        data,
                        b"File already completely uploaded\0" as *const u8
                            as *const i8,
                    );
                    return CURLE_PARTIAL_FILE;
                }
            }
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_firstwrite<'a1>(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut done: Option<&'a1 mut bool>,
) -> u32 {
    let mut k: Option<&'_ mut crate::src::lib::http2::SingleRequest> = Some(&mut (*data).req);
    if ((*data).req).ignore_cl() != 0 {
        let mut fresh68 = &mut ((*(borrow_mut(&mut k)).unwrap()).maxdownload);
        *fresh68 = -(1 as i32) as curl_off_t;
        (*(borrow_mut(&mut k)).unwrap()).size = *fresh68;
    } else if (*(borrow(& k)).unwrap()).size != -(1 as i32) as i64 {
        if (*data).set.max_filesize != 0 && (*(borrow(& k)).unwrap()).size > (*data).set.max_filesize {
            Curl_failf(
                data,
                b"Maximum file size exceeded\0" as *const u8 as *const i8,
            );
            return CURLE_FILESIZE_EXCEEDED;
        }
        Curl_pgrsSetDownloadSize(data, (*(borrow_mut(&mut k)).unwrap()).size);
    }
    if !((*data).req.newurl).is_null() {
        if ((*conn).bits).close() != 0 {
            (*(borrow_mut(&mut k)).unwrap()).keepon &= !((1 as i32) << 0 as i32);
            *(borrow_mut(&mut done)).unwrap() = 1 as i32 != 0;
            return CURLE_OK;
        }
        (*(borrow_mut(&mut k)).unwrap()).set_ignorebody(1 as i32 as bit);
        Curl_infof(
            data,
            b"Ignoring the response-body\0" as *const u8 as *const i8,
        );
    }
    if (*data).state.resume_from != 0 && (*(borrow(& k)).unwrap()).content_range() == 0
        && (*data).state.httpreq as u32
            == HTTPREQ_GET as i32 as u32 && (*(borrow(& k)).unwrap()).ignorebody() == 0
    {
        if (*(borrow(& k)).unwrap()).size == (*data).state.resume_from {
            Curl_infof(
                data,
                b"The entire document is already downloaded\0" as *const u8
                    as *const i8,
            );
            Curl_conncontrol(conn, 1 as i32);
            (*(borrow_mut(&mut k)).unwrap()).keepon &= !((1 as i32) << 0 as i32);
            *(borrow_mut(&mut done)).unwrap() = 1 as i32 != 0;
            return CURLE_OK;
        }
        Curl_failf(
            data,
            b"HTTP server doesn't seem to support byte ranges. Cannot resume.\0"
                as *const u8 as *const i8,
        );
        return CURLE_RANGE_ERROR;
    }
    if (*data).set.timecondition as u32 != 0 && ((*data).state.range).is_null()
    {
        if !Curl_meets_timecondition(data, (*(borrow_mut(&mut k)).unwrap()).timeofdoc) {
            *(borrow_mut(&mut done)).unwrap() = 1 as i32 != 0;
            (*data).info.httpcode = 304 as i32;
            Curl_infof(
                data,
                b"Simulate a HTTP 304 response!\0" as *const u8 as *const i8,
            );
            Curl_conncontrol(conn, 1 as i32);
            return CURLE_OK;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_transferencode(mut data: * mut crate::src::lib::http2::Curl_easy) -> u32 {
    if (Curl_checkheaders(data, b"TE\0" as *const u8 as *const i8)).is_null()
        && ((*data).set).http_transfer_encoding() as i32 != 0
    {
        let mut cptr: * mut i8 = Curl_checkheaders(
            data,
            b"Connection\0" as *const u8 as *const i8,
        );
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.aptr.te as *mut libc::c_void);
        let mut fresh69 = &mut ((*data).state.aptr.te);
        *fresh69 = 0 as *mut i8;
        if !cptr.is_null() {
            cptr = Curl_copy_header_value(cptr);
            if cptr.is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        }
        let mut fresh70 = &mut ((*data).state.aptr.te);
        *fresh70 = curl_maprintf(
            b"Connection: %s%sTE\r\nTE: gzip\r\n\0" as *const u8 as *const i8,
            if !cptr.is_null() {
                cptr as *const i8
            } else {
                b"\0" as *const u8 as *const i8
            },
            if !cptr.is_null() && *cptr as i32 != 0 {
                b", \0" as *const u8 as *const i8
            } else {
                b"\0" as *const u8 as *const i8
            },
        );
        Curl_cfree.expect("non-null function pointer")(cptr as *mut libc::c_void);
        if ((*data).state.aptr.te).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut done: * mut bool,
) -> u32 {
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    let mut result: u32 = CURLE_OK;
    let mut http: * mut crate::src::lib::http2::HTTP = 0 as *mut HTTP;
    let mut httpreq: u32 = HTTPREQ_GET;
    let mut te: * const i8 = b"\0" as *const u8 as *const i8;
    let mut request: * const i8 = 0 as *const i8;
    let mut httpstring: * const i8 = 0 as *const i8;
    let mut req: crate::src::lib::http2::dynbuf = dynbuf {
        bufr: 0 as *mut i8,
        leng: 0,
        allc: 0,
        toobig: 0,
    };
    let mut altused: * mut i8 = 0 as *mut i8;
    let mut p_accept: * const i8 = 0 as *const i8;
    *done = 1 as i32 != 0;
    if (*conn).transport as u32 != TRNSPRT_QUIC as i32 as u32 {
        if ((*conn).httpversion as i32) < 20 as i32 {
            match (*conn).negnpn {
                3 => {
                    (*conn).httpversion = 20 as i32 as u8;
                    result = Curl_http2_switched(
                        data,
                        0 as *const i8,
                        0 as i32 as size_t,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                }
                2 => {}
                _ => {
                    if (*data).state.httpwant as i32
                        == CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE as i32
                    {
                        if ((*conn).bits).httpproxy() as i32 != 0
                            && ((*conn).bits).tunnel_proxy() == 0
                        {
                            Curl_infof(
                                data,
                                b"Ignoring HTTP/2 prior knowledge due to proxy\0"
                                    as *const u8 as *const i8,
                            );
                        } else {
                            (*conn).httpversion = 20 as i32 as u8;
                            result = Curl_http2_switched(
                                data,
                                0 as *const i8,
                                0 as i32 as size_t,
                            );
                            if result as u64 != 0 {
                                return result;
                            }
                        }
                    }
                }
            }
        } else {
            result = Curl_http2_setup(data, conn);
            if result as u64 != 0 {
                return result;
            }
        }
    }
    http = (*data).req.p.http;
    result = Curl_http_host(data, conn);
    if result as u64 != 0 {
        return result;
    }
    result = Curl_http_useragent(data);
    if result as u64 != 0 {
        return result;
    }
    Curl_http_method(data, conn, Some(&mut request), Some(&mut httpreq));
    let mut pq: * mut i8 = 0 as *mut i8;
    if !((*data).state.up.query).is_null() {
        pq = curl_maprintf(
            b"%s?%s\0" as *const u8 as *const i8,
            (*data).state.up.path,
            (*data).state.up.query,
        );
        if pq.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    result = Curl_http_output_auth(
        data,
        conn,
        request,
        httpreq,
        if !pq.is_null() { pq } else { (*data).state.up.path },
        0 as i32 != 0,
    );
    Curl_cfree.expect("non-null function pointer")(pq as *mut libc::c_void);
    if result as u64 != 0 {
        return result;
    }
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.ref_0 as *mut libc::c_void);
    let mut fresh71 = &mut ((*data).state.aptr.ref_0);
    *fresh71 = 0 as *mut i8;
    if !((*data).state.referer).is_null()
        && (Curl_checkheaders(data, b"Referer\0" as *const u8 as *const i8))
            .is_null()
    {
        let mut fresh72 = &mut ((*data).state.aptr.ref_0);
        *fresh72 = curl_maprintf(
            b"Referer: %s\r\n\0" as *const u8 as *const i8,
            (*data).state.referer,
        );
        if ((*data).state.aptr.ref_0).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if (Curl_checkheaders(
        data,
        b"Accept-Encoding\0" as *const u8 as *const i8,
    ))
        .is_null()
        && !((*data).set.str_0[STRING_ENCODING as i32 as usize]).is_null()
    {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.aptr.accept_encoding as *mut libc::c_void);
        let mut fresh73 = &mut ((*data).state.aptr.accept_encoding);
        *fresh73 = 0 as *mut i8;
        let mut fresh74 = &mut ((*data).state.aptr.accept_encoding);
        *fresh74 = curl_maprintf(
            b"Accept-Encoding: %s\r\n\0" as *const u8 as *const i8,
            (*data).set.str_0[STRING_ENCODING as i32 as usize],
        );
        if ((*data).state.aptr.accept_encoding).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    } else {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.aptr.accept_encoding as *mut libc::c_void);
        let mut fresh75 = &mut ((*data).state.aptr.accept_encoding);
        *fresh75 = 0 as *mut i8;
    }
    result = Curl_transferencode(data);
    if result as u64 != 0 {
        return result;
    }
    result = Curl_http_body(data, conn, httpreq, Some(&mut te));
    if result as u64 != 0 {
        return result;
    }
    p_accept = if !(Curl_checkheaders(
        data,
        b"Accept\0" as *const u8 as *const i8,
    ))
        .is_null()
    {
        0 as *const i8
    } else {
        b"Accept: */*\r\n\0" as *const u8 as *const i8
    };
    result = Curl_http_resume(data, conn, httpreq);
    if result as u64 != 0 {
        return result;
    }
    result = Curl_http_range(data, httpreq);
    if result as u64 != 0 {
        return result;
    }
    httpstring = get_http_string(data, conn);
    Curl_dyn_init(&mut req, (1024 as i32 * 1024 as i32) as size_t);
    Curl_dyn_reset(Some(&mut (*data).state.headerb));
    result = Curl_dyn_addf(
        &mut req as *mut dynbuf,
        b"%s \0" as *const u8 as *const i8,
        request,
    );
    if result as u64 == 0 {
        result = Curl_http_target(data, conn, &mut req);
    }
    if result as u64 != 0 {
        Curl_dyn_free(&mut req);
        return result;
    }
    if ((*conn).bits).altused() as i32 != 0
        && (Curl_checkheaders(data, b"Alt-Used\0" as *const u8 as *const i8))
            .is_null()
    {
        altused = curl_maprintf(
            b"Alt-Used: %s:%d\r\n\0" as *const u8 as *const i8,
            (*conn).conn_to_host.name,
            (*conn).conn_to_port,
        );
        if altused.is_null() {
            Curl_dyn_free(&mut req);
            return CURLE_OUT_OF_MEMORY;
        }
    }
    result = Curl_dyn_addf(
        &mut req as *mut dynbuf,
        b" HTTP/%s\r\n%s%s%s%s%s%s%s%s%s%s%s%s\0" as *const u8 as *const i8,
        httpstring,
        if !((*data).state.aptr.host).is_null() {
            (*data).state.aptr.host as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !((*data).state.aptr.proxyuserpwd).is_null() {
            (*data).state.aptr.proxyuserpwd as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !((*data).state.aptr.userpwd).is_null() {
            (*data).state.aptr.userpwd as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        if ((*data).state).use_range() as i32 != 0
            && !((*data).state.aptr.rangeline).is_null()
        {
            (*data).state.aptr.rangeline as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !((*data).set.str_0[STRING_USERAGENT as i32 as usize]).is_null()
            && *(*data).set.str_0[STRING_USERAGENT as i32 as usize]
                as i32 != 0 && !((*data).state.aptr.uagent).is_null()
        {
            (*data).state.aptr.uagent as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !p_accept.is_null() {
            p_accept
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !((*data).state.aptr.te).is_null() {
            (*data).state.aptr.te as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !((*data).set.str_0[STRING_ENCODING as i32 as usize]).is_null()
            && *(*data).set.str_0[STRING_ENCODING as i32 as usize] as i32
                != 0 && !((*data).state.aptr.accept_encoding).is_null()
        {
            (*data).state.aptr.accept_encoding as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !((*data).state.referer).is_null() && !((*data).state.aptr.ref_0).is_null() {
            (*data).state.aptr.ref_0 as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        if ((*conn).bits).httpproxy() as i32 != 0
            && ((*conn).bits).tunnel_proxy() == 0
            && (Curl_checkheaders(
                data,
                b"Proxy-Connection\0" as *const u8 as *const i8,
            ))
                .is_null()
            && (Curl_checkProxyheaders(
                data,
                conn,
                b"Proxy-Connection\0" as *const u8 as *const i8,
            ))
                .is_null()
        {
            b"Proxy-Connection: Keep-Alive\r\n\0" as *const u8 as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        te,
        if !altused.is_null() {
            altused as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
    );
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.userpwd as *mut libc::c_void);
    let mut fresh76 = &mut ((*data).state.aptr.userpwd);
    *fresh76 = 0 as *mut i8;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.proxyuserpwd as *mut libc::c_void);
    let mut fresh77 = &mut ((*data).state.aptr.proxyuserpwd);
    *fresh77 = 0 as *mut i8;
    Curl_cfree.expect("non-null function pointer")(altused as *mut libc::c_void);
    if result as u64 != 0 {
        Curl_dyn_free(&mut req);
        return result;
    }
    if (*(*conn).handler).flags
        & ((1 as i32) << 0 as i32) as u32 == 0
        && (*conn).httpversion as i32 != 20 as i32
        && (*data).state.httpwant as i32 == CURL_HTTP_VERSION_2_0 as i32
    {
        result = Curl_http2_request_upgrade(&mut req, data);
        if result as u64 != 0 {
            Curl_dyn_free(&mut req);
            return result;
        }
    }
    result = Curl_http_cookies(data, conn, &mut req);
    if result as u64 == 0 {
        result = Curl_add_timecondition(data, &mut req);
    }
    if result as u64 == 0 {
        result = Curl_add_custom_headers(data, 0 as i32 != 0, &mut req);
    }
    if result as u64 == 0 {
        let mut fresh78 = &mut ((*http).postdata);
        *fresh78 = 0 as *const i8;
        if httpreq as u32 == HTTPREQ_GET as i32 as u32
            || httpreq as u32 == HTTPREQ_HEAD as i32 as u32
        {
            Curl_pgrsSetUploadSize(data, 0 as i32 as curl_off_t);
        }
        result = Curl_http_bodysend(data, conn, &mut req, httpreq);
    }
    if result as u64 != 0 {
        Curl_dyn_free(&mut req);
        return result;
    }
    if (*http).postsize > -(1 as i32) as i64
        && (*http).postsize <= (*data).req.writebytecount
        && (*http).sending as u32
            != HTTPSEND_REQUEST as i32 as u32
    {
        let mut fresh79 = &mut ((*data).req);
        (*fresh79).set_upload_done(1 as i32 as bit);
    }
    if (*data).req.writebytecount != 0 {
        Curl_pgrsSetUploadCounter(data, (*data).req.writebytecount);
        if Curl_pgrsUpdate(data) != 0 {
            result = CURLE_ABORTED_BY_CALLBACK;
        }
        if (*http).postsize == 0 {
            Curl_infof(
                data,
                b"upload completely sent off: %ld out of %ld bytes\0" as *const u8
                    as *const i8,
                (*data).req.writebytecount,
                (*http).postsize,
            );
            let mut fresh80 = &mut ((*data).req);
            (*fresh80).set_upload_done(1 as i32 as bit);
            (*data).req.keepon &= !((1 as i32) << 1 as i32);
            (*data).req.exp100 = EXP100_SEND_DATA;
            Curl_expire_done(data, EXPIRE_100_TIMEOUT);
        }
    }
    if (*conn).httpversion as i32 == 20 as i32
        && ((*data).req).upload_chunky() as i32 != 0
    {
        let mut fresh81 = &mut ((*data).req);
        (*fresh81).set_upload_chunky(0 as i32 as bit);
    }
    return result;
}
unsafe extern "C" fn checkprefixmax(
    mut prefix: * const i8,
    mut buffer: * const i8,
    mut len: u64,
) -> bool {
    let mut ch: u64 = if strlen(prefix) < len { strlen(prefix) } else { len };
    return curl_strnequal(prefix, buffer, ch) != 0;
}
unsafe extern "C" fn checkhttpprefix(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut s: * const i8,
    mut len: u64,
) -> u32 {
    let mut head: * mut crate::src::lib::http2::curl_slist = (*data).set.http200aliases;
    let mut rc: u32 = STATUS_BAD;
    let mut onmatch: u32 = (if len >= 5 as i32 as u64 {
        STATUS_DONE as i32
    } else {
        STATUS_UNKNOWN as i32
    }) as statusline;
    while !head.is_null() {
        if checkprefixmax((*head).data, s, len) {
            rc = onmatch;
            break;
        } else {
            head = (*head).next;
        }
    }
    if rc as u32 != STATUS_DONE as i32 as u32
        && checkprefixmax(b"HTTP/\0" as *const u8 as *const i8, s, len)
            as i32 != 0
    {
        rc = onmatch;
    }
    return rc;
}
unsafe extern "C" fn checkrtspprefix(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut s: * const i8,
    mut len: u64,
) -> u32 {
    let mut result: u32 = STATUS_BAD;
    let mut onmatch: u32 = (if len >= 5 as i32 as u64 {
        STATUS_DONE as i32
    } else {
        STATUS_UNKNOWN as i32
    }) as statusline;
    if checkprefixmax(b"RTSP/\0" as *const u8 as *const i8, s, len) {
        result = onmatch;
    }
    return result;
}
unsafe extern "C" fn checkprotoprefix(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut s: * const i8,
    mut len: u64,
) -> u32 {
    if (*(*conn).handler).protocol
        & ((1 as i32) << 18 as i32) as u32 != 0
    {
        return checkrtspprefix(data, s, len);
    }
    return checkhttpprefix(data, s, len);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_header(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut headp: * mut i8,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut k: Option<&'_ mut crate::src::lib::http2::SingleRequest> = Some(&mut (*data).req);
    if (*(borrow(& k)).unwrap()).http_bodyless() == 0 && ((*data).set).ignorecl() == 0
        && curl_strnequal(
            b"Content-Length:\0" as *const u8 as *const i8,
            headp,
            strlen(b"Content-Length:\0" as *const u8 as *const i8),
        ) != 0
    {
        let mut contentlength: i64 = 0;
        let mut offt: u32 = curlx_strtoofft(
            headp
                .offset(
                    strlen(b"Content-Length:\0" as *const u8 as *const i8)
                        as isize,
                ),
            Option::<&'_ mut * mut i8>::None,
            10 as i32,
            Some(&mut contentlength),
        );
        if offt as u32 == CURL_OFFT_OK as i32 as u32 {
            (*(borrow_mut(&mut k)).unwrap()).size = contentlength;
            (*(borrow_mut(&mut k)).unwrap()).maxdownload = (*(borrow_mut(&mut k)).unwrap()).size;
        } else if offt as u32 == CURL_OFFT_FLOW as i32 as u32 {
            if (*data).set.max_filesize != 0 {
                Curl_failf(
                    data,
                    b"Maximum file size exceeded\0" as *const u8 as *const i8,
                );
                return CURLE_FILESIZE_EXCEEDED;
            }
            Curl_conncontrol(conn, 2 as i32);
            Curl_infof(
                data,
                b"Overflow Content-Length: value!\0" as *const u8 as *const i8,
            );
        } else {
            Curl_failf(
                data,
                b"Invalid Content-Length: value\0" as *const u8 as *const i8,
            );
            return CURLE_WEIRD_SERVER_REPLY;
        }
    } else if curl_strnequal(
            b"Content-Type:\0" as *const u8 as *const i8,
            headp,
            strlen(b"Content-Type:\0" as *const u8 as *const i8),
        ) != 0
        {
        let mut contenttype: * mut i8 = Curl_copy_header_value(headp);
        if contenttype.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if *contenttype == 0 {
            Curl_cfree
                .expect("non-null function pointer")(contenttype as *mut libc::c_void);
        } else {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).info.contenttype as *mut libc::c_void);
            let mut fresh82 = &mut ((*data).info.contenttype);
            *fresh82 = 0 as *mut i8;
            let mut fresh83 = &mut ((*data).info.contenttype);
            *fresh83 = contenttype;
        }
    } else if (*conn).httpversion as i32 == 10 as i32
            && ((*conn).bits).httpproxy() as i32 != 0
            && Curl_compareheader(
                headp,
                b"Proxy-Connection:\0" as *const u8 as *const i8,
                b"keep-alive\0" as *const u8 as *const i8,
            ) as i32 != 0
        {
        Curl_conncontrol(conn, 0 as i32);
        Curl_infof(
            data,
            b"HTTP/1.0 proxy connection set to keep alive!\0" as *const u8
                as *const i8,
        );
    } else if (*conn).httpversion as i32 == 11 as i32
            && ((*conn).bits).httpproxy() as i32 != 0
            && Curl_compareheader(
                headp,
                b"Proxy-Connection:\0" as *const u8 as *const i8,
                b"close\0" as *const u8 as *const i8,
            ) as i32 != 0
        {
        Curl_conncontrol(conn, 1 as i32);
        Curl_infof(
            data,
            b"HTTP/1.1 proxy connection set close!\0" as *const u8 as *const i8,
        );
    } else if (*conn).httpversion as i32 == 10 as i32
            && Curl_compareheader(
                headp,
                b"Connection:\0" as *const u8 as *const i8,
                b"keep-alive\0" as *const u8 as *const i8,
            ) as i32 != 0
        {
        Curl_conncontrol(conn, 0 as i32);
        Curl_infof(
            data,
            b"HTTP/1.0 connection set to keep alive!\0" as *const u8
                as *const i8,
        );
    } else if Curl_compareheader(
            headp,
            b"Connection:\0" as *const u8 as *const i8,
            b"close\0" as *const u8 as *const i8,
        ) {
        Curl_conncontrol(conn, 2 as i32);
    } else if (*(borrow(& k)).unwrap()).http_bodyless() == 0
            && curl_strnequal(
                b"Transfer-Encoding:\0" as *const u8 as *const i8,
                headp,
                strlen(b"Transfer-Encoding:\0" as *const u8 as *const i8),
            ) != 0
        {
        result = Curl_build_unencoding_stack(
            data,
            headp
                .offset(
                    strlen(b"Transfer-Encoding:\0" as *const u8 as *const i8)
                        as isize,
                ),
            1 as i32,
        );
        if result as u64 != 0 {
            return result;
        }
        if (*(borrow(& k)).unwrap()).chunk() == 0 {
            Curl_conncontrol(conn, 1 as i32);
            (*(borrow_mut(&mut k)).unwrap()).set_ignore_cl(1 as i32 as bit);
        }
    } else if (*(borrow(& k)).unwrap()).http_bodyless() == 0
            && curl_strnequal(
                b"Content-Encoding:\0" as *const u8 as *const i8,
                headp,
                strlen(b"Content-Encoding:\0" as *const u8 as *const i8),
            ) != 0
            && !((*data).set.str_0[STRING_ENCODING as i32 as usize]).is_null()
        {
        result = Curl_build_unencoding_stack(
            data,
            headp
                .offset(
                    strlen(b"Content-Encoding:\0" as *const u8 as *const i8)
                        as isize,
                ),
            0 as i32,
        );
        if result as u64 != 0 {
            return result;
        }
    } else if curl_strnequal(
            b"Retry-After:\0" as *const u8 as *const i8,
            headp,
            strlen(b"Retry-After:\0" as *const u8 as *const i8),
        ) != 0
        {
        let mut retry_after: i64 = 0 as i32 as curl_off_t;
        let mut date: i64 = Curl_getdate_capped(
            headp
                .offset(
                    strlen(b"Retry-After:\0" as *const u8 as *const i8)
                        as isize,
                ),
        );
        if -(1 as i32) as i64 == date {
            curlx_strtoofft(
                headp
                    .offset(
                        strlen(b"Retry-After:\0" as *const u8 as *const i8)
                            as isize,
                    ),
                Option::<&'_ mut * mut i8>::None,
                10 as i32,
                Some(&mut retry_after),
            );
        } else {
            retry_after = date - time(0 as *mut time_t);
        }
        (*data).info.retry_after = retry_after;
    } else if (*(borrow(& k)).unwrap()).http_bodyless() == 0
            && curl_strnequal(
                b"Content-Range:\0" as *const u8 as *const i8,
                headp,
                strlen(b"Content-Range:\0" as *const u8 as *const i8),
            ) != 0
        {
        let mut ptr: * mut i8 = headp
            .offset(
                strlen(b"Content-Range:\0" as *const u8 as *const i8) as isize,
            );
        while *ptr as i32 != 0
            && Curl_isdigit(*ptr as u8 as i32) == 0
            && *ptr as i32 != '*' as i32
        {
            ptr = ptr.offset(1);
        }
        if Curl_isdigit(*ptr as u8 as i32) != 0 {
            if curlx_strtoofft(
                ptr,
                Option::<&'_ mut * mut i8>::None,
                10 as i32,
                Some(&mut (*(borrow_mut(&mut k)).unwrap()).offset),
            ) as u64 == 0
            {
                if (*data).state.resume_from == (*(borrow(& k)).unwrap()).offset {
                    (*(borrow_mut(&mut k)).unwrap()).set_content_range(1 as i32 as bit);
                }
            }
        } else {
            (*data).state.resume_from = 0 as i32 as curl_off_t;
        }
    } else if !((*data).cookies).is_null()
            && ((*data).state).cookie_engine() as i32 != 0
            && curl_strnequal(
                b"Set-Cookie:\0" as *const u8 as *const i8,
                headp,
                strlen(b"Set-Cookie:\0" as *const u8 as *const i8),
            ) != 0
        {
        let mut host: * const i8 = if !((*data).state.aptr.cookiehost).is_null()
        {
            (*data).state.aptr.cookiehost
        } else {
            (*conn).host.name
        };
        let secure_context: bool = if (*(*conn).handler).protocol
            & ((1 as i32) << 1 as i32) as u32 != 0
            || Curl_strcasecompare(
                b"localhost\0" as *const u8 as *const i8,
                host,
            ) != 0
            || strcmp(host, b"127.0.0.1\0" as *const u8 as *const i8) == 0
            || strcmp(host, b"[::1]\0" as *const u8 as *const i8) == 0
        {
            1 as i32
        } else {
            0 as i32
        } != 0;
        Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
        Curl_cookie_add(
            data,
            (*data).cookies,
            1 as i32 != 0,
            0 as i32 != 0,
            headp
                .offset(
                    strlen(b"Set-Cookie:\0" as *const u8 as *const i8) as isize,
                ),
            host,
            (*data).state.up.path,
            secure_context,
        );
        Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
    } else if (*(borrow(& k)).unwrap()).http_bodyless() == 0
            && curl_strnequal(
                b"Last-Modified:\0" as *const u8 as *const i8,
                headp,
                strlen(b"Last-Modified:\0" as *const u8 as *const i8),
            ) != 0
            && ((*data).set.timecondition as u32 != 0
                || ((*data).set).get_filetime() as i32 != 0)
        {
        (*(borrow_mut(&mut k)).unwrap())
            .timeofdoc = Curl_getdate_capped(
            headp
                .offset(
                    strlen(b"Last-Modified:\0" as *const u8 as *const i8)
                        as isize,
                ),
        );
        if ((*data).set).get_filetime() != 0 {
            (*data).info.filetime = (*(borrow_mut(&mut k)).unwrap()).timeofdoc;
        }
    } else if curl_strnequal(
            b"WWW-Authenticate:\0" as *const u8 as *const i8,
            headp,
            strlen(b"WWW-Authenticate:\0" as *const u8 as *const i8),
        ) != 0 && 401 as i32 == (*(borrow(& k)).unwrap()).httpcode
            || curl_strnequal(
                b"Proxy-authenticate:\0" as *const u8 as *const i8,
                headp,
                strlen(b"Proxy-authenticate:\0" as *const u8 as *const i8),
            ) != 0 && 407 as i32 == (*(borrow(& k)).unwrap()).httpcode
        {
        let mut proxy: bool = if (*(borrow(& k)).unwrap()).httpcode == 407 as i32 {
            1 as i32
        } else {
            0 as i32
        } != 0;
        let mut auth: * mut i8 = Curl_copy_header_value(headp);
        if auth.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        result = Curl_http_input_auth(data, proxy, auth);
        Curl_cfree.expect("non-null function pointer")(auth as *mut libc::c_void);
        if result as u64 != 0 {
            return result;
        }
    } else if (*(borrow(& k)).unwrap()).httpcode >= 300 as i32 && (*(borrow(& k)).unwrap()).httpcode < 400 as i32
            && curl_strnequal(
                b"Location:\0" as *const u8 as *const i8,
                headp,
                strlen(b"Location:\0" as *const u8 as *const i8),
            ) != 0 && ((*data).req.location).is_null()
        {
        let mut location: * mut i8 = Curl_copy_header_value(headp);
        if location.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if *location == 0 {
            Curl_cfree
                .expect("non-null function pointer")(location as *mut libc::c_void);
        } else {
            let mut fresh84 = &mut ((*data).req.location);
            *fresh84 = location;
            if ((*data).set).http_follow_location() != 0 {
                let mut fresh85 = &mut ((*data).req.newurl);
                *fresh85 = Curl_cstrdup
                    .expect("non-null function pointer")((*data).req.location);
                if ((*data).req.newurl).is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
                result = http_perhapsrewind(data, conn);
                if result as u64 != 0 {
                    return result;
                }
            }
        }
    } else if !((*data).hsts).is_null()
            && curl_strnequal(
                b"Strict-Transport-Security:\0" as *const u8 as *const i8,
                headp,
                strlen(
                    b"Strict-Transport-Security:\0" as *const u8 as *const i8,
                ),
            ) != 0
            && (*(*conn).handler).flags
                & ((1 as i32) << 0 as i32) as u32 != 0
        {
        let mut check: u32 = Curl_hsts_parse(
            (*data).hsts,
            (*data).state.up.hostname,
            headp
                .offset(
                    strlen(
                        b"Strict-Transport-Security:\0" as *const u8
                            as *const i8,
                    ) as isize,
                ),
        );
        if check as u64 != 0 {
            Curl_infof(
                data,
                b"Illegal STS header skipped\0" as *const u8 as *const i8,
            );
        }
    } else if !((*data).asi).is_null()
            && curl_strnequal(
                b"Alt-Svc:\0" as *const u8 as *const i8,
                headp,
                strlen(b"Alt-Svc:\0" as *const u8 as *const i8),
            ) != 0
            && ((*(*conn).handler).flags
                & ((1 as i32) << 0 as i32) as u32 != 0
                || 0 as i32 != 0)
        {
        let mut id: u32 = (if (*conn).httpversion as i32 == 20 as i32
        {
            ALPN_h2 as i32
        } else {
            ALPN_h1 as i32
        }) as alpnid;
        result = Curl_altsvc_parse(
            data,
            (*data).asi,
            headp
                .offset(
                    strlen(b"Alt-Svc:\0" as *const u8 as *const i8) as isize,
                ),
            id,
            (*conn).host.name,
            curlx_uitous((*conn).remote_port as u32),
        );
        if result as u64 != 0 {
            return result;
        }
    } else if (*(*conn).handler).protocol
            & ((1 as i32) << 18 as i32) as u32 != 0
        {
        result = Curl_rtsp_parseheader(data, headp);
        if result as u64 != 0 {
            return result;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_statusline(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut k: * mut crate::src::lib::http2::SingleRequest = &mut (*data).req;
    (*data).info.httpcode = (*k).httpcode;
    (*data).info.httpversion = (*conn).httpversion as i32;
    if (*data).state.httpversion == 0
        || (*data).state.httpversion as i32 > (*conn).httpversion as i32
    {
        (*data).state.httpversion = (*conn).httpversion;
    }
    if (*data).state.resume_from != 0
        && (*data).state.httpreq as u32
            == HTTPREQ_GET as i32 as u32
        && (*k).httpcode == 416 as i32
    {
        (*k).set_ignorebody(1 as i32 as bit);
    }
    if (*conn).httpversion as i32 == 10 as i32 {
        Curl_infof(
            data,
            b"HTTP 1.0, assume close after body\0" as *const u8 as *const i8,
        );
        Curl_conncontrol(conn, 1 as i32);
    } else if (*conn).httpversion as i32 == 20 as i32
            || (*k).upgr101 as u32
                == UPGR101_REQUESTED as i32 as u32
                && (*k).httpcode == 101 as i32
        {
        (*(*conn).bundle).multiuse = 2 as i32;
    } else {
        (*conn).httpversion as i32 >= 11 as i32
            && ((*conn).bits).close() == 0;
    }
    (*k)
        .set_http_bodyless(
            ((*k).httpcode >= 100 as i32 && (*k).httpcode < 200 as i32)
                as i32 as bit,
        );
    let mut current_block_25: u64;
    match (*k).httpcode {
        304 => {
            if (*data).set.timecondition as u64 != 0 {
                let mut fresh86 = &mut ((*data).info);
                (*fresh86).set_timecond(1 as i32 as bit);
            }
            current_block_25 = 9427725525305667067;
        }
        204 => {
            current_block_25 = 9427725525305667067;
        }
        _ => {
            current_block_25 = 14763689060501151050;
        }
    }
    match current_block_25 {
        9427725525305667067 => {
            (*k).size = 0 as i32 as curl_off_t;
            (*k).maxdownload = 0 as i32 as curl_off_t;
            (*k).set_http_bodyless(1 as i32 as bit);
        }
        _ => {}
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_readwrite_headers<'a1, 'a2>(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut nread: Option<&'a1 mut i64>,
    mut stop_reading: Option<&'a2 mut bool>,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut k: Option<&'_ mut crate::src::lib::http2::SingleRequest> = Some(&mut (*data).req);
    let mut onread: i64 = *(borrow_mut(&mut nread)).unwrap();
    let mut ostr: * mut i8 = (*(borrow_mut(&mut k)).unwrap()).str_0;
    let mut headp: * mut i8 = 0 as *mut i8;
    let mut str_start: * mut i8 = 0 as *mut i8;
    let mut end_ptr: * mut i8 = 0 as *mut i8;
    loop {
        let mut rest_length: u64 = 0;
        let mut full_length: u64 = 0;
        let mut writetype: i32 = 0;
        str_start = (*(borrow_mut(&mut k)).unwrap()).str_0;
        end_ptr = memchr(
            str_start as *const libc::c_void,
            0xa as i32,
            *(borrow_mut(&mut nread)).unwrap() as u64,
        ) as *mut i8;
        if end_ptr.is_null() {
            result = Curl_dyn_addn(
                &mut (*data).state.headerb,
                str_start as *const libc::c_void,
                *(borrow_mut(&mut nread)).unwrap() as size_t,
            );
            if result as u64 != 0 {
                return result;
            }
            if !((*(borrow(& k)).unwrap()).headerline == 0) {
                break;
            }
            let mut st: u32 = checkprotoprefix(
                data,
                conn,
                Curl_dyn_ptr(&mut (*data).state.headerb),
                Curl_dyn_len(&mut (*data).state.headerb),
            );
            if !(st as u32 == STATUS_BAD as i32 as u32) {
                break;
            }
            (*(borrow_mut(&mut k)).unwrap()).set_header(0 as i32 as bit);
            (*(borrow_mut(&mut k)).unwrap()).badheader = HEADER_ALLBAD;
            Curl_conncontrol(conn, 2 as i32);
            if ((*data).set).http09_allowed() == 0 {
                Curl_failf(
                    data,
                    b"Received HTTP/0.9 when not allowed\0" as *const u8
                        as *const i8,
                );
                return CURLE_UNSUPPORTED_PROTOCOL;
            }
            break;
        } else {
            rest_length = (end_ptr.offset_from((*(borrow(& k)).unwrap()).str_0) as i64
                + 1 as i32 as i64) as size_t;
            *(borrow_mut(&mut nread)).unwrap() -= rest_length as ssize_t;
            let mut fresh87 = &mut ((*(borrow_mut(&mut k)).unwrap()).str_0);
            *fresh87 = end_ptr.offset(1 as i32 as isize);
            full_length = ((*(borrow(& k)).unwrap()).str_0).offset_from(str_start) as i64 as size_t;
            result = Curl_dyn_addn(
                &mut (*data).state.headerb,
                str_start as *const libc::c_void,
                full_length,
            );
            if result as u64 != 0 {
                return result;
            }
            if (*(borrow(& k)).unwrap()).headerline == 0 {
                let mut st_0: u32 = checkprotoprefix(
                    data,
                    conn,
                    Curl_dyn_ptr(&mut (*data).state.headerb),
                    Curl_dyn_len(&mut (*data).state.headerb),
                );
                if st_0 as u32 == STATUS_BAD as i32 as u32 {
                    Curl_conncontrol(conn, 2 as i32);
                    if ((*data).set).http09_allowed() == 0 {
                        Curl_failf(
                            data,
                            b"Received HTTP/0.9 when not allowed\0" as *const u8
                                as *const i8,
                        );
                        return CURLE_UNSUPPORTED_PROTOCOL;
                    }
                    (*(borrow_mut(&mut k)).unwrap()).set_header(0 as i32 as bit);
                    if *(borrow(& nread)).unwrap() != 0 {
                        (*(borrow_mut(&mut k)).unwrap()).badheader = HEADER_PARTHEADER;
                    } else {
                        (*(borrow_mut(&mut k)).unwrap()).badheader = HEADER_ALLBAD;
                        *(borrow_mut(&mut nread)).unwrap() = onread;
                        let mut fresh88 = &mut ((*(borrow_mut(&mut k)).unwrap()).str_0);
                        *fresh88 = ostr;
                        return CURLE_OK;
                    }
                    break;
                }
            }
            headp = Curl_dyn_ptr(&mut (*data).state.headerb);
            if 0xa as i32 == *headp as i32
                || 0xd as i32 == *headp as i32
            {
                let mut headerlen: u64 = 0;
                if '\r' as i32 == *headp as i32 {
                    headp = headp.offset(1);
                }
                if '\n' as i32 == *headp as i32 {
                    headp = headp.offset(1);
                }
                if 100 as i32 <= (*(borrow(& k)).unwrap()).httpcode
                    && 199 as i32 >= (*(borrow(& k)).unwrap()).httpcode
                {
                    match (*(borrow(& k)).unwrap()).httpcode {
                        100 => {
                            (*(borrow_mut(&mut k)).unwrap()).set_header(1 as i32 as bit);
                            (*(borrow_mut(&mut k)).unwrap()).headerline = 0 as i32;
                            if (*(borrow(& k)).unwrap()).exp100 as u32
                                > EXP100_SEND_DATA as i32 as u32
                            {
                                (*(borrow_mut(&mut k)).unwrap()).exp100 = EXP100_SEND_DATA;
                                (*(borrow_mut(&mut k)).unwrap()).keepon |= (1 as i32) << 1 as i32;
                                Curl_expire_done(data, EXPIRE_100_TIMEOUT);
                            }
                        }
                        101 => {
                            if (*(borrow(& k)).unwrap()).upgr101 as u32
                                == UPGR101_REQUESTED as i32 as u32
                            {
                                Curl_infof(
                                    data,
                                    b"Received 101\0" as *const u8 as *const i8,
                                );
                                (*(borrow_mut(&mut k)).unwrap()).upgr101 = UPGR101_RECEIVED;
                                (*(borrow_mut(&mut k)).unwrap()).set_header(1 as i32 as bit);
                                (*(borrow_mut(&mut k)).unwrap()).headerline = 0 as i32;
                                result = Curl_http2_switched(
                                    data,
                                    (*(borrow(& k)).unwrap()).str_0,
                                    *(borrow_mut(&mut nread)).unwrap() as size_t,
                                );
                                if result as u64 != 0 {
                                    return result;
                                }
                                *(borrow_mut(&mut nread)).unwrap() = 0 as i32 as ssize_t;
                            } else {
                                (*(borrow_mut(&mut k)).unwrap()).set_header(0 as i32 as bit);
                            }
                        }
                        _ => {
                            (*(borrow_mut(&mut k)).unwrap()).set_header(1 as i32 as bit);
                            (*(borrow_mut(&mut k)).unwrap()).headerline = 0 as i32;
                        }
                    }
                } else {
                    (*(borrow_mut(&mut k)).unwrap()).set_header(0 as i32 as bit);
                    if (*(borrow(& k)).unwrap()).size == -(1 as i32) as i64
                        && (*(borrow(& k)).unwrap()).chunk() == 0 && ((*conn).bits).close() == 0
                        && (*conn).httpversion as i32 == 11 as i32
                        && (*(*conn).handler).protocol
                            & ((1 as i32) << 18 as i32) as u32
                            == 0
                        && (*data).state.httpreq as u32
                            != HTTPREQ_HEAD as i32 as u32
                    {
                        Curl_infof(
                            data,
                            b"no chunk, no close, no size. Assume close to signal end\0"
                                as *const u8 as *const i8,
                        );
                        Curl_conncontrol(conn, 2 as i32);
                    }
                }
                if ((*conn).bits).close() as i32 != 0
                    && ((*data).req.httpcode == 401 as i32
                        && (*conn).http_ntlm_state as u32
                            == NTLMSTATE_TYPE2 as i32 as u32
                        || (*data).req.httpcode == 407 as i32
                            && (*conn).proxy_ntlm_state as u32
                                == NTLMSTATE_TYPE2 as i32 as u32)
                {
                    Curl_infof(
                        data,
                        b"Connection closure while negotiating auth (HTTP 1.0?)\0"
                            as *const u8 as *const i8,
                    );
                    let mut fresh89 = &mut ((*data).state);
                    (*fresh89).set_authproblem(1 as i32 as bit);
                }
                writetype = (1 as i32) << 1 as i32;
                if ((*data).set).include_header() != 0 {
                    writetype |= (1 as i32) << 0 as i32;
                }
                headerlen = Curl_dyn_len(&mut (*data).state.headerb);
                result = Curl_client_write(
                    data,
                    writetype,
                    Curl_dyn_ptr(&mut (*data).state.headerb),
                    headerlen,
                );
                if result as u64 != 0 {
                    return result;
                }
                let mut fresh90 = &mut ((*data).info.header_size);
                *fresh90 += headerlen as i64;
                let mut fresh91 = &mut ((*data).req.headerbytecount);
                *fresh91 += headerlen as i64;
                if http_should_fail(data) {
                    Curl_failf(
                        data,
                        b"The requested URL returned error: %d\0" as *const u8
                            as *const i8,
                        (*(borrow(& k)).unwrap()).httpcode,
                    );
                    return CURLE_HTTP_RETURNED_ERROR;
                }
                (*data)
                    .req
                    .deductheadercount = if 100 as i32 <= (*(borrow(& k)).unwrap()).httpcode
                    && 199 as i32 >= (*(borrow(& k)).unwrap()).httpcode
                {
                    (*data).req.headerbytecount
                } else {
                    0 as i32 as i64
                };
                result = Curl_http_auth_act(data);
                if result as u64 != 0 {
                    return result;
                }
                if (*(borrow(& k)).unwrap()).httpcode >= 300 as i32 {
                    if ((*conn).bits).authneg() == 0 && ((*conn).bits).close() == 0
                        && ((*conn).bits).rewindaftersend() == 0
                    {
                        match (*data).state.httpreq as u32 {
                            4 | 1 | 2 | 3 => {
                                Curl_expire_done(data, EXPIRE_100_TIMEOUT);
                                if (*(borrow(& k)).unwrap()).upload_done() == 0 {
                                    if (*(borrow(& k)).unwrap()).httpcode == 417 as i32
                                        && ((*data).state).expect100header() as i32 != 0
                                    {
                                        Curl_infof(
                                            data,
                                            b"Got 417 while waiting for a 100\0" as *const u8
                                                as *const i8,
                                        );
                                        let mut fresh92 = &mut ((*data).state);
                                        (*fresh92).set_disableexpect(1 as i32 as bit);
                                        let mut fresh93 = &mut ((*data).req.newurl);
                                        *fresh93 = Curl_cstrdup
                                            .expect("non-null function pointer")((*data).state.url);
                                        Curl_done_sending(data, borrow_mut(&mut k));
                                    } else if ((*data).set).http_keep_sending_on_error() != 0 {
                                        Curl_infof(
                                            data,
                                            b"HTTP error before end of send, keep sending\0"
                                                as *const u8 as *const i8,
                                        );
                                        if (*(borrow(& k)).unwrap()).exp100 as u32
                                            > EXP100_SEND_DATA as i32 as u32
                                        {
                                            (*(borrow_mut(&mut k)).unwrap()).exp100 = EXP100_SEND_DATA;
                                            (*(borrow_mut(&mut k)).unwrap()).keepon |= (1 as i32) << 1 as i32;
                                        }
                                    } else {
                                        Curl_infof(
                                            data,
                                            b"HTTP error before end of send, stop sending\0"
                                                as *const u8 as *const i8,
                                        );
                                        Curl_conncontrol(conn, 2 as i32);
                                        result = Curl_done_sending(data, borrow_mut(&mut k));
                                        if result as u64 != 0 {
                                            return result;
                                        }
                                        (*(borrow_mut(&mut k)).unwrap()).set_upload_done(1 as i32 as bit);
                                        if ((*data).state).expect100header() != 0 {
                                            (*(borrow_mut(&mut k)).unwrap()).exp100 = EXP100_FAILED;
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    if ((*conn).bits).rewindaftersend() != 0 {
                        Curl_infof(
                            data,
                            b"Keep sending data to get tossed away!\0" as *const u8
                                as *const i8,
                        );
                        (*(borrow_mut(&mut k)).unwrap()).keepon |= (1 as i32) << 1 as i32;
                    }
                }
                if (*(borrow(& k)).unwrap()).header() == 0 {
                    if ((*data).set).opt_no_body() != 0 {
                        *(borrow_mut(&mut stop_reading)).unwrap() = 1 as i32 != 0;
                    } else if (*(*conn).handler).protocol
                            & ((1 as i32) << 18 as i32) as u32
                            != 0
                            && (*data).set.rtspreq as u32
                                == RTSPREQ_DESCRIBE as i32 as u32
                            && (*(borrow(& k)).unwrap()).size <= -(1 as i32) as i64
                        {
                        *(borrow_mut(&mut stop_reading)).unwrap() = 1 as i32 != 0;
                    } else if (*(borrow(& k)).unwrap()).chunk() != 0 {
                        let mut fresh94 = &mut ((*(borrow_mut(&mut k)).unwrap()).size);
                        *fresh94 = -(1 as i32) as curl_off_t;
                        (*(borrow_mut(&mut k)).unwrap()).maxdownload = *fresh94;
                    }
                    if -(1 as i32) as i64 != (*(borrow(& k)).unwrap()).size {
                        Curl_pgrsSetDownloadSize(data, (*(borrow_mut(&mut k)).unwrap()).size);
                        (*(borrow_mut(&mut k)).unwrap()).maxdownload = (*(borrow_mut(&mut k)).unwrap()).size;
                    }
                    if 0 as i32 as i64 == (*(borrow(& k)).unwrap()).maxdownload
                        && !((*(*conn).handler).protocol
                            & ((1 as i32) << 0 as i32
                                | (1 as i32) << 1 as i32) as u32
                            != 0
                            && (*conn).httpversion as i32 == 20 as i32)
                    {
                        *(borrow_mut(&mut stop_reading)).unwrap() = 1 as i32 != 0;
                    }
                    if *(borrow(& stop_reading)).unwrap() {
                        (*(borrow_mut(&mut k)).unwrap()).keepon &= !((1 as i32) << 0 as i32);
                    }
                    Curl_debug(data, CURLINFO_HEADER_IN, str_start, headerlen);
                    break;
                } else {
                    Curl_dyn_reset(Some(&mut (*data).state.headerb));
                }
            } else {
                let mut fresh95 = &mut ((*(borrow_mut(&mut k)).unwrap()).headerline);
                let mut fresh96 = *fresh95;
                *fresh95 = *fresh95 + 1;
                if fresh96 == 0 {
                    let mut httpversion_major: i32 = 0;
                    let mut rtspversion_major: i32 = 0;
                    let mut nc: i32 = 0 as i32;
                    if (*(*conn).handler).protocol
                        & ((1 as i32) << 0 as i32
                            | (1 as i32) << 1 as i32) as u32
                        != 0
                    {
                        let mut separator: i8 = 0;
                        let mut twoorthree: [i8; 2] = [0; 2];
                        let mut httpversion: i32 = 0 as i32;
                        let mut digit4: i8 = 0 as i32 as i8;
                        nc = sscanf(
                            headp,
                            b" HTTP/%1d.%1d%c%3d%c\0" as *const u8
                                as *const i8,
                            &mut httpversion_major as *mut i32,
                            &mut httpversion as *mut i32,
                            &mut separator as *mut i8,
                            &mut (*(borrow_mut(&mut k)).unwrap()).httpcode as *mut i32,
                            &mut digit4 as *mut i8,
                        );
                        if nc == 1 as i32
                            && httpversion_major >= 2 as i32
                            && 2 as i32
                                == sscanf(
                                    headp,
                                    b" HTTP/%1[23] %d\0" as *const u8 as *const i8,
                                    twoorthree.as_mut_ptr(),
                                    &mut (*(borrow_mut(&mut k)).unwrap()).httpcode as *mut i32,
                                )
                        {
                            (*conn).httpversion = 0 as i32 as u8;
                            nc = 4 as i32;
                            separator = ' ' as i32 as i8;
                        } else if Curl_isdigit(digit4 as u8 as i32)
                                != 0
                            {
                            Curl_failf(
                                data,
                                b"Unsupported response code in HTTP response\0" as *const u8
                                    as *const i8,
                            );
                            return CURLE_UNSUPPORTED_PROTOCOL;
                        }
                        if nc >= 4 as i32
                            && ' ' as i32 == separator as i32
                        {
                            httpversion += 10 as i32 * httpversion_major;
                            match httpversion {
                                10 | 11 | 20 => {
                                    (*conn).httpversion = httpversion as u8;
                                }
                                _ => {
                                    Curl_failf(
                                        data,
                                        b"Unsupported HTTP version (%u.%d) in response\0"
                                            as *const u8 as *const i8,
                                        httpversion / 10 as i32,
                                        httpversion % 10 as i32,
                                    );
                                    return CURLE_UNSUPPORTED_PROTOCOL;
                                }
                            }
                            if (*(borrow(& k)).unwrap()).upgr101 as u32
                                == UPGR101_RECEIVED as i32 as u32
                            {
                                if (*conn).httpversion as i32 != 20 as i32 {
                                    Curl_infof(
                                        data,
                                        b"Lying server, not serving HTTP/2\0" as *const u8
                                            as *const i8,
                                    );
                                }
                            }
                            if ((*conn).httpversion as i32) < 20 as i32 {
                                (*(*conn).bundle).multiuse = -(1 as i32);
                                Curl_infof(
                                    data,
                                    b"Mark bundle as not supporting multiuse\0" as *const u8
                                        as *const i8,
                                );
                            }
                        } else if nc == 0 {
                            nc = sscanf(
                                headp,
                                b" HTTP %3d\0" as *const u8 as *const i8,
                                &mut (*(borrow_mut(&mut k)).unwrap()).httpcode as *mut i32,
                            );
                            (*conn).httpversion = 10 as i32 as u8;
                            if nc == 0 {
                                let mut check: u32 = checkhttpprefix(
                                    data,
                                    Curl_dyn_ptr(&mut (*data).state.headerb),
                                    Curl_dyn_len(&mut (*data).state.headerb),
                                );
                                if check as u32
                                    == STATUS_DONE as i32 as u32
                                {
                                    nc = 1 as i32;
                                    (*(borrow_mut(&mut k)).unwrap()).httpcode = 200 as i32;
                                    (*conn).httpversion = 10 as i32 as u8;
                                }
                            }
                        } else {
                            Curl_failf(
                                data,
                                b"Unsupported HTTP version in response\0" as *const u8
                                    as *const i8,
                            );
                            return CURLE_UNSUPPORTED_PROTOCOL;
                        }
                    } else if (*(*conn).handler).protocol
                            & ((1 as i32) << 18 as i32) as u32
                            != 0
                        {
                        let mut separator_0: i8 = 0;
                        let mut rtspversion: i32 = 0;
                        nc = sscanf(
                            headp,
                            b" RTSP/%1d.%1d%c%3d\0" as *const u8 as *const i8,
                            &mut rtspversion_major as *mut i32,
                            &mut rtspversion as *mut i32,
                            &mut separator_0 as *mut i8,
                            &mut (*(borrow_mut(&mut k)).unwrap()).httpcode as *mut i32,
                        );
                        if nc == 4 as i32
                            && ' ' as i32 == separator_0 as i32
                        {
                            (*conn).httpversion = 11 as i32 as u8;
                        } else {
                            nc = 0 as i32;
                        }
                    }
                    if nc != 0 {
                        result = Curl_http_statusline(data, conn);
                        if result as u64 != 0 {
                            return result;
                        }
                    } else {
                        (*(borrow_mut(&mut k)).unwrap()).set_header(0 as i32 as bit);
                        break;
                    }
                }
                result = CURLE_OK as i32 as CURLcode;
                if result as u64 != 0 {
                    return result;
                }
                result = Curl_http_header(data, conn, headp);
                if result as u64 != 0 {
                    return result;
                }
                writetype = (1 as i32) << 1 as i32;
                if ((*data).set).include_header() != 0 {
                    writetype |= (1 as i32) << 0 as i32;
                }
                Curl_debug(
                    data,
                    CURLINFO_HEADER_IN,
                    headp,
                    Curl_dyn_len(&mut (*data).state.headerb),
                );
                result = Curl_client_write(
                    data,
                    writetype,
                    headp,
                    Curl_dyn_len(&mut (*data).state.headerb),
                );
                if result as u64 != 0 {
                    return result;
                }
                let mut fresh97 = &mut ((*data).info.header_size);
                *fresh97 = (*fresh97 as u64)
                    .wrapping_add(Curl_dyn_len(&mut (*data).state.headerb)) as curl_off_t
                    as curl_off_t;
                let mut fresh98 = &mut ((*data).req.headerbytecount);
                *fresh98 = (*fresh98 as u64)
                    .wrapping_add(Curl_dyn_len(&mut (*data).state.headerb)) as curl_off_t
                    as curl_off_t;
                Curl_dyn_reset(Some(&mut (*data).state.headerb));
            }
            if !(*(*(borrow(& k)).unwrap()).str_0 != 0) {
                break;
            }
        }
    }
    return CURLE_OK;
}
use crate::laertes_rt::*;
