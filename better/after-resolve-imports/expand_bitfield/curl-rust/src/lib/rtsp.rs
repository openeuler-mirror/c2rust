use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn sscanf(_: *const i8, _: *const i8, _: ...) -> i32;
    
    
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> *mut libc::c_void;
    fn strncmp(
        _: *const i8,
        _: *const i8,
        _: u64,
    ) -> i32;
    fn strlen(_: *const i8) -> u64;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::connect::Curl_connalive;
pub use crate::src::lib::curl_ctype::Curl_isspace;
pub use crate::src::lib::dynbuf::Curl_dyn_add;
pub use crate::src::lib::dynbuf::Curl_dyn_addf;
pub use crate::src::lib::dynbuf::Curl_dyn_addn;
pub use crate::src::lib::dynbuf::Curl_dyn_init;
pub use crate::src::lib::http::Curl_add_custom_headers;
pub use crate::src::lib::http::Curl_add_timecondition;
pub use crate::src::lib::http::Curl_buffer_send;
pub use crate::src::lib::http::Curl_http_connect;
pub use crate::src::lib::http::Curl_http_done;
pub use crate::src::lib::http::Curl_http_output_auth;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::multi::Curl_set_in_callback;
pub use crate::src::lib::progress::Curl_pgrsSetUploadCounter;
pub use crate::src::lib::progress::Curl_pgrsUpdate;
pub use crate::src::lib::select::Curl_socket_check;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::strcase::curl_strnequal;
pub use crate::src::lib::strdup::Curl_saferealloc;
pub use crate::src::lib::transfer::Curl_checkheaders;
pub use crate::src::lib::transfer::Curl_setup_transfer;
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::easy::Curl_ccalloc;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
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
pub type curl_calloc_callback = crate::src::lib::http2::curl_calloc_callback;
pub const STRING_USERAGENT: dupstring = 38;
pub const STRING_ENCODING: dupstring = 9;
pub const STRING_RTSP_TRANSPORT: dupstring = 52;
pub const STRING_RTSP_STREAM_URI: dupstring = 51;
pub const STRING_RTSP_SESSION_ID: dupstring = 50;
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
pub const STRING_CUSTOMREQUEST: dupstring = 6;
pub const STRING_COOKIEJAR: dupstring = 5;
pub const STRING_COOKIE: dupstring = 4;
pub const STRING_CERT_TYPE_PROXY: dupstring = 3;
pub const STRING_CERT_TYPE: dupstring = 2;
pub const STRING_CERT_PROXY: dupstring = 1;
pub const STRING_CERT: dupstring = 0;
unsafe extern "C" fn rtsp_getsock_do(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> i32 {
    *socks.offset(0 as i32 as isize) = (*conn).sock[0 as i32 as usize];
    return (1 as i32) << 16 as i32 + 0 as i32;
}
#[no_mangle]
pub static mut Curl_handler_rtsp: Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"RTSP\0" as *const u8 as *const i8,
            setup_connection: Some(
                rtsp_setup_connection
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
            ),
            do_it: Some(
                rtsp_do as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            done: Some(
                rtsp_done
                    as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
            ),
            do_more: None,
            connect_it: Some(
                rtsp_connect
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            connecting: None,
            doing: None,
            proto_getsock: None,
            doing_getsock: Some(
                rtsp_getsock_do
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            domore_getsock: None,
            perform_getsock: None,
            disconnect: Some(
                rtsp_disconnect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        bool,
                    ) -> CURLcode,
            ),
            readwrite: Some(
                rtsp_rtp_readwrite
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut ssize_t,
                        *mut bool,
                    ) -> CURLcode,
            ),
            connection_check: Some(
                rtsp_conncheck
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        u32,
                    ) -> u32,
            ),
            attach: None,
            defport: 554 as i32,
            protocol: ((1 as i32) << 18 as i32) as u32,
            family: ((1 as i32) << 18 as i32) as u32,
            flags: 0 as i32 as u32,
        };
        init
    }
};
unsafe extern "C" fn rtsp_setup_connection(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut rtsp: *mut RTSP = 0 as *mut RTSP;
    rtsp = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(1 as i32 as size_t, ::std::mem::size_of::<RTSP>() as u64)
        as *mut RTSP;
    let ref mut fresh0 = (*data).req.p.rtsp;
    *fresh0 = rtsp;
    if rtsp.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    return CURLE_OK;
}
unsafe extern "C" fn rtsp_connisdead(mut check: *mut connectdata) -> bool {
    let mut sval: i32 = 0;
    let mut ret_val: bool = 1 as i32 != 0;
    sval = Curl_socket_check(
        (*check).sock[0 as i32 as usize],
        -(1 as i32),
        -(1 as i32),
        0 as i32 as timediff_t,
    );
    if sval == 0 as i32 {
        ret_val = 0 as i32 != 0;
    } else if sval & 0x4 as i32 != 0 {
        ret_val = 1 as i32 != 0;
    } else if sval & 0x1 as i32 != 0 {
        ret_val = !Curl_connalive(check);
    }
    return ret_val;
}
unsafe extern "C" fn rtsp_conncheck(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut checks_to_perform: u32,
) -> u32 {
    let mut ret_val: u32 = 0 as i32 as u32;
    if checks_to_perform & ((1 as i32) << 0 as i32) as u32 != 0
    {
        if rtsp_connisdead(conn) {
            ret_val |= ((1 as i32) << 0 as i32) as u32;
        }
    }
    return ret_val;
}
unsafe extern "C" fn rtsp_connect(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    let mut httpStatus: CURLcode = CURLE_OK;
    httpStatus = Curl_http_connect(data, done);
    if (*data).state.rtsp_next_client_CSeq == 0 as i32 as i64 {
        (*data).state.rtsp_next_client_CSeq = 1 as i32 as i64;
    }
    if (*data).state.rtsp_next_server_CSeq == 0 as i32 as i64 {
        (*data).state.rtsp_next_server_CSeq = 1 as i32 as i64;
    }
    (*(*data).conn).proto.rtspc.rtp_channel = -(1 as i32);
    return httpStatus;
}
unsafe extern "C" fn rtsp_disconnect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut dead: bool,
) -> CURLcode {
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).proto.rtspc.rtp_buf as *mut libc::c_void);
    let ref mut fresh1 = (*conn).proto.rtspc.rtp_buf;
    *fresh1 = 0 as *mut i8;
    return CURLE_OK;
}
unsafe extern "C" fn rtsp_done(
    mut data: *mut Curl_easy,
    mut status: CURLcode,
    mut premature: bool,
) -> CURLcode {
    let mut rtsp: *mut RTSP = (*data).req.p.rtsp;
    let mut httpStatus: CURLcode = CURLE_OK;
    if (*data).set.rtspreq as u32
        == RTSPREQ_RECEIVE as i32 as u32
    {
        premature = 1 as i32 != 0;
    }
    httpStatus = Curl_http_done(data, status, premature);
    if !rtsp.is_null() {
        let mut CSeq_sent: i64 = (*rtsp).CSeq_sent;
        let mut CSeq_recv: i64 = (*rtsp).CSeq_recv;
        if (*data).set.rtspreq as u32
            != RTSPREQ_RECEIVE as i32 as u32 && CSeq_sent != CSeq_recv
        {
            Curl_failf(
                data,
                b"The CSeq of this request %ld did not match the response %ld\0"
                    as *const u8 as *const i8,
                CSeq_sent,
                CSeq_recv,
            );
            return CURLE_RTSP_CSEQ_ERROR;
        }
        if (*data).set.rtspreq as u32
            == RTSPREQ_RECEIVE as i32 as u32
            && (*(*data).conn).proto.rtspc.rtp_channel == -(1 as i32)
        {
            Curl_infof(
                data,
                b"Got an RTP Receive with a CSeq of %ld\0" as *const u8
                    as *const i8,
                CSeq_recv,
            );
        }
    }
    return httpStatus;
}
unsafe extern "C" fn rtsp_do(mut data: *mut Curl_easy, mut done: *mut bool) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut result: CURLcode = CURLE_OK;
    let mut rtspreq: Curl_RtspReq = (*data).set.rtspreq;
    let mut rtsp: *mut RTSP = (*data).req.p.rtsp;
    let mut req_buffer: dynbuf = dynbuf {
        bufr: 0 as *mut i8,
        leng: 0,
        allc: 0,
        toobig: 0,
    };
    let mut postsize: curl_off_t = 0 as i32 as curl_off_t;
    let mut putsize: curl_off_t = 0 as i32 as curl_off_t;
    let mut p_request: *const i8 = 0 as *const i8;
    let mut p_session_id: *const i8 = 0 as *const i8;
    let mut p_accept: *const i8 = 0 as *const i8;
    let mut p_accept_encoding: *const i8 = 0 as *const i8;
    let mut p_range: *const i8 = 0 as *const i8;
    let mut p_referrer: *const i8 = 0 as *const i8;
    let mut p_stream_uri: *const i8 = 0 as *const i8;
    let mut p_transport: *const i8 = 0 as *const i8;
    let mut p_uagent: *const i8 = 0 as *const i8;
    let mut p_proxyuserpwd: *const i8 = 0 as *const i8;
    let mut p_userpwd: *const i8 = 0 as *const i8;
    *done = 1 as i32 != 0;
    (*rtsp).CSeq_sent = (*data).state.rtsp_next_client_CSeq;
    (*rtsp).CSeq_recv = 0 as i32 as i64;
    let ref mut fresh2 = (*data).set;
    (*fresh2).set_opt_no_body(1 as i32 as bit);
    match rtspreq as u32 {
        1 => {
            p_request = b"OPTIONS\0" as *const u8 as *const i8;
        }
        2 => {
            p_request = b"DESCRIBE\0" as *const u8 as *const i8;
            let ref mut fresh3 = (*data).set;
            (*fresh3).set_opt_no_body(0 as i32 as bit);
        }
        3 => {
            p_request = b"ANNOUNCE\0" as *const u8 as *const i8;
        }
        4 => {
            p_request = b"SETUP\0" as *const u8 as *const i8;
        }
        5 => {
            p_request = b"PLAY\0" as *const u8 as *const i8;
        }
        6 => {
            p_request = b"PAUSE\0" as *const u8 as *const i8;
        }
        7 => {
            p_request = b"TEARDOWN\0" as *const u8 as *const i8;
        }
        8 => {
            p_request = b"GET_PARAMETER\0" as *const u8 as *const i8;
            let ref mut fresh4 = (*data).set;
            (*fresh4).set_opt_no_body(0 as i32 as bit);
        }
        9 => {
            p_request = b"SET_PARAMETER\0" as *const u8 as *const i8;
        }
        10 => {
            p_request = b"RECORD\0" as *const u8 as *const i8;
        }
        11 => {
            p_request = b"\0" as *const u8 as *const i8;
            let ref mut fresh5 = (*data).set;
            (*fresh5).set_opt_no_body(0 as i32 as bit);
        }
        12 => {
            Curl_failf(
                data,
                b"Got invalid RTSP request: RTSPREQ_LAST\0" as *const u8
                    as *const i8,
            );
            return CURLE_BAD_FUNCTION_ARGUMENT;
        }
        _ => {
            Curl_failf(
                data,
                b"Got invalid RTSP request\0" as *const u8 as *const i8,
            );
            return CURLE_BAD_FUNCTION_ARGUMENT;
        }
    }
    if rtspreq as u32 == RTSPREQ_RECEIVE as i32 as u32 {
        Curl_setup_transfer(
            data,
            0 as i32,
            -(1 as i32) as curl_off_t,
            1 as i32 != 0,
            -(1 as i32),
        );
        return result;
    }
    p_session_id = (*data).set.str_0[STRING_RTSP_SESSION_ID as i32 as usize];
    if p_session_id.is_null()
        && rtspreq as u32
            & !(RTSPREQ_OPTIONS as i32 | RTSPREQ_DESCRIBE as i32
                | RTSPREQ_SETUP as i32) as u32 != 0
    {
        Curl_failf(
            data,
            b"Refusing to issue an RTSP request [%s] without a session ID.\0"
                as *const u8 as *const i8,
            p_request,
        );
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if !((*data).set.str_0[STRING_RTSP_STREAM_URI as i32 as usize]).is_null() {
        p_stream_uri = (*data).set.str_0[STRING_RTSP_STREAM_URI as i32 as usize];
    } else {
        p_stream_uri = b"*\0" as *const u8 as *const i8;
    }
    p_transport = Curl_checkheaders(
        data,
        b"Transport\0" as *const u8 as *const i8,
    );
    if rtspreq as u32 == RTSPREQ_SETUP as i32 as u32
        && p_transport.is_null()
    {
        if !((*data).set.str_0[STRING_RTSP_TRANSPORT as i32 as usize]).is_null()
        {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).state.aptr.rtsp_transport as *mut libc::c_void);
            let ref mut fresh6 = (*data).state.aptr.rtsp_transport;
            *fresh6 = 0 as *mut i8;
            let ref mut fresh7 = (*data).state.aptr.rtsp_transport;
            *fresh7 = curl_maprintf(
                b"Transport: %s\r\n\0" as *const u8 as *const i8,
                (*data).set.str_0[STRING_RTSP_TRANSPORT as i32 as usize],
            );
            if ((*data).state.aptr.rtsp_transport).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        } else {
            Curl_failf(
                data,
                b"Refusing to issue an RTSP SETUP without a Transport: header.\0"
                    as *const u8 as *const i8,
            );
            return CURLE_BAD_FUNCTION_ARGUMENT;
        }
        p_transport = (*data).state.aptr.rtsp_transport;
    }
    if rtspreq as u32 == RTSPREQ_DESCRIBE as i32 as u32 {
        p_accept = if !(Curl_checkheaders(
            data,
            b"Accept\0" as *const u8 as *const i8,
        ))
            .is_null()
        {
            0 as *const i8
        } else {
            b"Accept: application/sdp\r\n\0" as *const u8 as *const i8
        };
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
            let ref mut fresh8 = (*data).state.aptr.accept_encoding;
            *fresh8 = 0 as *mut i8;
            let ref mut fresh9 = (*data).state.aptr.accept_encoding;
            *fresh9 = curl_maprintf(
                b"Accept-Encoding: %s\r\n\0" as *const u8 as *const i8,
                (*data).set.str_0[STRING_ENCODING as i32 as usize],
            );
            if ((*data).state.aptr.accept_encoding).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            p_accept_encoding = (*data).state.aptr.accept_encoding;
        }
    }
    if !(Curl_checkheaders(data, b"User-Agent\0" as *const u8 as *const i8))
        .is_null() && !((*data).state.aptr.uagent).is_null()
    {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.aptr.uagent as *mut libc::c_void);
        let ref mut fresh10 = (*data).state.aptr.uagent;
        *fresh10 = 0 as *mut i8;
        let ref mut fresh11 = (*data).state.aptr.uagent;
        *fresh11 = 0 as *mut i8;
    } else if (Curl_checkheaders(
            data,
            b"User-Agent\0" as *const u8 as *const i8,
        ))
            .is_null()
            && !((*data).set.str_0[STRING_USERAGENT as i32 as usize]).is_null()
        {
        p_uagent = (*data).state.aptr.uagent;
    }
    result = Curl_http_output_auth(
        data,
        conn,
        p_request,
        HTTPREQ_GET,
        p_stream_uri,
        0 as i32 != 0,
    );
    if result as u64 != 0 {
        return result;
    }
    p_proxyuserpwd = (*data).state.aptr.proxyuserpwd;
    p_userpwd = (*data).state.aptr.userpwd;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.ref_0 as *mut libc::c_void);
    let ref mut fresh12 = (*data).state.aptr.ref_0;
    *fresh12 = 0 as *mut i8;
    if !((*data).state.referer).is_null()
        && (Curl_checkheaders(data, b"Referer\0" as *const u8 as *const i8))
            .is_null()
    {
        let ref mut fresh13 = (*data).state.aptr.ref_0;
        *fresh13 = curl_maprintf(
            b"Referer: %s\r\n\0" as *const u8 as *const i8,
            (*data).state.referer,
        );
    } else {
        let ref mut fresh14 = (*data).state.aptr.ref_0;
        *fresh14 = 0 as *mut i8;
    }
    p_referrer = (*data).state.aptr.ref_0;
    if ((*data).state).use_range() as i32 != 0
        && rtspreq as u32
            & (RTSPREQ_PLAY as i32 | RTSPREQ_PAUSE as i32
                | RTSPREQ_RECORD as i32) as u32 != 0
    {
        if (Curl_checkheaders(data, b"Range\0" as *const u8 as *const i8))
            .is_null() && !((*data).state.range).is_null()
        {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).state.aptr.rangeline as *mut libc::c_void);
            let ref mut fresh15 = (*data).state.aptr.rangeline;
            *fresh15 = 0 as *mut i8;
            let ref mut fresh16 = (*data).state.aptr.rangeline;
            *fresh16 = curl_maprintf(
                b"Range: %s\r\n\0" as *const u8 as *const i8,
                (*data).state.range,
            );
            p_range = (*data).state.aptr.rangeline;
        }
    }
    if !(Curl_checkheaders(data, b"CSeq\0" as *const u8 as *const i8))
        .is_null()
    {
        Curl_failf(
            data,
            b"CSeq cannot be set as a custom header.\0" as *const u8
                as *const i8,
        );
        return CURLE_RTSP_CSEQ_ERROR;
    }
    if !(Curl_checkheaders(data, b"Session\0" as *const u8 as *const i8))
        .is_null()
    {
        Curl_failf(
            data,
            b"Session ID cannot be set as a custom header.\0" as *const u8
                as *const i8,
        );
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    Curl_dyn_init(&mut req_buffer, (64 as i32 * 1024 as i32) as size_t);
    result = Curl_dyn_addf(
        &mut req_buffer as *mut dynbuf,
        b"%s %s RTSP/1.0\r\nCSeq: %ld\r\n\0" as *const u8 as *const i8,
        p_request,
        p_stream_uri,
        (*rtsp).CSeq_sent,
    );
    if result as u64 != 0 {
        return result;
    }
    if !p_session_id.is_null() {
        result = Curl_dyn_addf(
            &mut req_buffer as *mut dynbuf,
            b"Session: %s\r\n\0" as *const u8 as *const i8,
            p_session_id,
        );
        if result as u64 != 0 {
            return result;
        }
    }
    result = Curl_dyn_addf(
        &mut req_buffer as *mut dynbuf,
        b"%s%s%s%s%s%s%s%s\0" as *const u8 as *const i8,
        if !p_transport.is_null() {
            p_transport
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !p_accept.is_null() {
            p_accept
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !p_accept_encoding.is_null() {
            p_accept_encoding
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !p_range.is_null() {
            p_range
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !p_referrer.is_null() {
            p_referrer
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !p_uagent.is_null() {
            p_uagent
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !p_proxyuserpwd.is_null() {
            p_proxyuserpwd
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !p_userpwd.is_null() {
            p_userpwd
        } else {
            b"\0" as *const u8 as *const i8
        },
    );
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.userpwd as *mut libc::c_void);
    let ref mut fresh17 = (*data).state.aptr.userpwd;
    *fresh17 = 0 as *mut i8;
    let ref mut fresh18 = (*data).state.aptr.userpwd;
    *fresh18 = 0 as *mut i8;
    if result as u64 != 0 {
        return result;
    }
    if rtspreq as u32 == RTSPREQ_SETUP as i32 as u32
        || rtspreq as u32 == RTSPREQ_DESCRIBE as i32 as u32
    {
        result = Curl_add_timecondition(data, &mut req_buffer);
        if result as u64 != 0 {
            return result;
        }
    }
    result = Curl_add_custom_headers(data, 0 as i32 != 0, &mut req_buffer);
    if result as u64 != 0 {
        return result;
    }
    if rtspreq as u32 == RTSPREQ_ANNOUNCE as i32 as u32
        || rtspreq as u32
            == RTSPREQ_SET_PARAMETER as i32 as u32
        || rtspreq as u32
            == RTSPREQ_GET_PARAMETER as i32 as u32
    {
        if ((*data).set).upload() != 0 {
            putsize = (*data).state.infilesize;
            (*data).state.httpreq = HTTPREQ_PUT;
        } else {
            postsize = if (*data).state.infilesize != -(1 as i32) as i64
            {
                (*data).state.infilesize
            } else if !((*data).set.postfields).is_null() {
                strlen((*data).set.postfields as *const i8) as curl_off_t
            } else {
                0 as i32 as i64
            };
            (*data).state.httpreq = HTTPREQ_POST;
        }
        if putsize > 0 as i32 as i64
            || postsize > 0 as i32 as i64
        {
            if (Curl_checkheaders(
                data,
                b"Content-Length\0" as *const u8 as *const i8,
            ))
                .is_null()
            {
                result = Curl_dyn_addf(
                    &mut req_buffer as *mut dynbuf,
                    b"Content-Length: %ld\r\n\0" as *const u8 as *const i8,
                    if ((*data).set).upload() as i32 != 0 {
                        putsize
                    } else {
                        postsize
                    },
                );
                if result as u64 != 0 {
                    return result;
                }
            }
            if rtspreq as u32
                == RTSPREQ_SET_PARAMETER as i32 as u32
                || rtspreq as u32
                    == RTSPREQ_GET_PARAMETER as i32 as u32
            {
                if (Curl_checkheaders(
                    data,
                    b"Content-Type\0" as *const u8 as *const i8,
                ))
                    .is_null()
                {
                    result = Curl_dyn_addf(
                        &mut req_buffer as *mut dynbuf,
                        b"Content-Type: text/parameters\r\n\0" as *const u8
                            as *const i8,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                }
            }
            if rtspreq as u32 == RTSPREQ_ANNOUNCE as i32 as u32
            {
                if (Curl_checkheaders(
                    data,
                    b"Content-Type\0" as *const u8 as *const i8,
                ))
                    .is_null()
                {
                    result = Curl_dyn_addf(
                        &mut req_buffer as *mut dynbuf,
                        b"Content-Type: application/sdp\r\n\0" as *const u8
                            as *const i8,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                }
            }
            let ref mut fresh19 = (*data).state;
            (*fresh19).set_expect100header(0 as i32 as bit);
        } else if rtspreq as u32
                == RTSPREQ_GET_PARAMETER as i32 as u32
            {
            (*data).state.httpreq = HTTPREQ_HEAD;
            let ref mut fresh20 = (*data).set;
            (*fresh20).set_opt_no_body(1 as i32 as bit);
        }
    }
    let ref mut fresh21 = (*data).req;
    (*fresh21).set_forbidchunk(1 as i32 as bit);
    result = Curl_dyn_add(
        &mut req_buffer,
        b"\r\n\0" as *const u8 as *const i8,
    );
    if result as u64 != 0 {
        return result;
    }
    if postsize > 0 as i32 as i64 {
        result = Curl_dyn_addn(
            &mut req_buffer,
            (*data).set.postfields,
            postsize as size_t,
        );
        if result as u64 != 0 {
            return result;
        }
    }
    result = Curl_buffer_send(
        &mut req_buffer,
        data,
        &mut (*data).info.request_size,
        0 as i32 as curl_off_t,
        0 as i32,
    );
    if result as u64 != 0 {
        Curl_failf(
            data,
            b"Failed sending RTSP request\0" as *const u8 as *const i8,
        );
        return result;
    }
    Curl_setup_transfer(
        data,
        0 as i32,
        -(1 as i32) as curl_off_t,
        1 as i32 != 0,
        if putsize != 0 { 0 as i32 } else { -(1 as i32) },
    );
    let ref mut fresh22 = (*data).state.rtsp_next_client_CSeq;
    *fresh22 += 1;
    if (*data).req.writebytecount != 0 {
        Curl_pgrsSetUploadCounter(data, (*data).req.writebytecount);
        if Curl_pgrsUpdate(data) != 0 {
            result = CURLE_ABORTED_BY_CALLBACK;
        }
    }
    return result;
}
unsafe extern "C" fn rtsp_rtp_readwrite(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut nread: *mut ssize_t,
    mut readmore: *mut bool,
) -> CURLcode {
    let mut k: *mut SingleRequest = &mut (*data).req;
    let mut rtspc: *mut rtsp_conn = &mut (*conn).proto.rtspc;
    let mut rtp: *mut i8 = 0 as *mut i8;
    let mut rtp_dataleft: ssize_t = 0;
    let mut scratch: *mut i8 = 0 as *mut i8;
    let mut result: CURLcode = CURLE_OK;
    if !((*rtspc).rtp_buf).is_null() {
        let mut newptr: *mut i8 = Curl_saferealloc(
            (*rtspc).rtp_buf as *mut libc::c_void,
            ((*rtspc).rtp_bufsize + *nread) as size_t,
        ) as *mut i8;
        if newptr.is_null() {
            let ref mut fresh23 = (*rtspc).rtp_buf;
            *fresh23 = 0 as *mut i8;
            (*rtspc).rtp_bufsize = 0 as i32 as ssize_t;
            return CURLE_OUT_OF_MEMORY;
        }
        let ref mut fresh24 = (*rtspc).rtp_buf;
        *fresh24 = newptr;
        memcpy(
            ((*rtspc).rtp_buf).offset((*rtspc).rtp_bufsize as isize)
                as *mut libc::c_void,
            (*k).str_0 as *const libc::c_void,
            *nread as u64,
        );
        let ref mut fresh25 = (*rtspc).rtp_bufsize;
        *fresh25 += *nread;
        rtp = (*rtspc).rtp_buf;
        rtp_dataleft = (*rtspc).rtp_bufsize;
    } else {
        rtp = (*k).str_0;
        rtp_dataleft = *nread;
    }
    while rtp_dataleft > 0 as i32 as i64
        && *rtp.offset(0 as i32 as isize) as i32 == '$' as i32
    {
        if rtp_dataleft > 4 as i32 as i64 {
            let mut rtp_length: i32 = 0;
            (*rtspc)
                .rtp_channel = *rtp.offset(1 as i32 as isize) as u8
                as i32;
            rtp_length = (*rtp.offset(2 as i32 as isize) as u8
                as i32) << 8 as i32
                | *rtp.offset(3 as i32 as isize) as u8 as i32;
            if rtp_dataleft < (rtp_length + 4 as i32) as i64 {
                *readmore = 1 as i32 != 0;
                break;
            } else {
                result = rtp_client_write(
                    data,
                    &mut *rtp.offset(0 as i32 as isize),
                    (rtp_length + 4 as i32) as size_t,
                );
                if result as u64 != 0 {
                    Curl_failf(
                        data,
                        b"Got an error writing an RTP packet\0" as *const u8
                            as *const i8,
                    );
                    *readmore = 0 as i32 != 0;
                    Curl_cfree
                        .expect(
                            "non-null function pointer",
                        )((*rtspc).rtp_buf as *mut libc::c_void);
                    let ref mut fresh26 = (*rtspc).rtp_buf;
                    *fresh26 = 0 as *mut i8;
                    let ref mut fresh27 = (*rtspc).rtp_buf;
                    *fresh27 = 0 as *mut i8;
                    (*rtspc).rtp_bufsize = 0 as i32 as ssize_t;
                    return result;
                }
                rtp_dataleft -= (rtp_length + 4 as i32) as i64;
                rtp = rtp.offset((rtp_length + 4 as i32) as isize);
                if (*data).set.rtspreq as u32
                    == RTSPREQ_RECEIVE as i32 as u32
                {
                    (*k).keepon &= !((1 as i32) << 0 as i32);
                }
            }
        } else {
            *readmore = 1 as i32 != 0;
            break;
        }
    }
    if rtp_dataleft != 0
        && *rtp.offset(0 as i32 as isize) as i32 == '$' as i32
    {
        scratch = Curl_cmalloc
            .expect("non-null function pointer")(rtp_dataleft as size_t)
            as *mut i8;
        if scratch.is_null() {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*rtspc).rtp_buf as *mut libc::c_void);
            let ref mut fresh28 = (*rtspc).rtp_buf;
            *fresh28 = 0 as *mut i8;
            let ref mut fresh29 = (*rtspc).rtp_buf;
            *fresh29 = 0 as *mut i8;
            (*rtspc).rtp_bufsize = 0 as i32 as ssize_t;
            return CURLE_OUT_OF_MEMORY;
        }
        memcpy(
            scratch as *mut libc::c_void,
            rtp as *const libc::c_void,
            rtp_dataleft as u64,
        );
        Curl_cfree
            .expect("non-null function pointer")((*rtspc).rtp_buf as *mut libc::c_void);
        let ref mut fresh30 = (*rtspc).rtp_buf;
        *fresh30 = 0 as *mut i8;
        let ref mut fresh31 = (*rtspc).rtp_buf;
        *fresh31 = scratch;
        (*rtspc).rtp_bufsize = rtp_dataleft;
        *nread = 0 as i32 as ssize_t;
        return CURLE_OK;
    }
    let ref mut fresh32 = (*k).str_0;
    *fresh32 = (*fresh32).offset((*nread - rtp_dataleft) as isize);
    rtp_dataleft > 0 as i32 as i64;
    *nread = rtp_dataleft;
    Curl_cfree
        .expect("non-null function pointer")((*rtspc).rtp_buf as *mut libc::c_void);
    let ref mut fresh33 = (*rtspc).rtp_buf;
    *fresh33 = 0 as *mut i8;
    let ref mut fresh34 = (*rtspc).rtp_buf;
    *fresh34 = 0 as *mut i8;
    (*rtspc).rtp_bufsize = 0 as i32 as ssize_t;
    return CURLE_OK;
}
unsafe extern "C" fn rtp_client_write(
    mut data: *mut Curl_easy,
    mut ptr: *mut i8,
    mut len: size_t,
) -> CURLcode {
    let mut wrote: size_t = 0;
    let mut writeit: curl_write_callback = None;
    let mut user_ptr: *mut libc::c_void = 0 as *mut libc::c_void;
    if len == 0 as i32 as u64 {
        Curl_failf(
            data,
            b"Cannot write a 0 size RTP packet.\0" as *const u8 as *const i8,
        );
        return CURLE_WRITE_ERROR;
    }
    if ((*data).set.fwrite_rtp).is_some() {
        writeit = (*data).set.fwrite_rtp;
        user_ptr = (*data).set.rtp_out;
    } else {
        writeit = (*data).set.fwrite_func;
        user_ptr = (*data).set.out;
    }
    Curl_set_in_callback(data, 1 as i32 != 0);
    wrote = writeit
        .expect(
            "non-null function pointer",
        )(ptr, 1 as i32 as size_t, len, user_ptr);
    Curl_set_in_callback(data, 0 as i32 != 0);
    if 0x10000001 as i32 as u64 == wrote {
        Curl_failf(data, b"Cannot pause RTP\0" as *const u8 as *const i8);
        return CURLE_WRITE_ERROR;
    }
    if wrote != len {
        Curl_failf(
            data,
            b"Failed writing RTP data\0" as *const u8 as *const i8,
        );
        return CURLE_WRITE_ERROR;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_rtsp_parseheader(
    mut data: *mut Curl_easy,
    mut header: *mut i8,
) -> CURLcode {
    let mut CSeq: i64 = 0 as i32 as i64;
    if curl_strnequal(
        b"CSeq:\0" as *const u8 as *const i8,
        header,
        strlen(b"CSeq:\0" as *const u8 as *const i8),
    ) != 0
    {
        let mut nc: i32 = sscanf(
            &mut *header.offset(4 as i32 as isize) as *mut i8,
            b": %ld\0" as *const u8 as *const i8,
            &mut CSeq as *mut i64,
        );
        if nc == 1 as i32 {
            let mut rtsp: *mut RTSP = (*data).req.p.rtsp;
            (*rtsp).CSeq_recv = CSeq;
            (*data).state.rtsp_CSeq_recv = CSeq;
        } else {
            Curl_failf(
                data,
                b"Unable to read the CSeq header: [%s]\0" as *const u8
                    as *const i8,
                header,
            );
            return CURLE_RTSP_CSEQ_ERROR;
        }
    } else if curl_strnequal(
            b"Session:\0" as *const u8 as *const i8,
            header,
            strlen(b"Session:\0" as *const u8 as *const i8),
        ) != 0
        {
        let mut start: *mut i8 = 0 as *mut i8;
        let mut end: *mut i8 = 0 as *mut i8;
        let mut idlen: size_t = 0;
        start = header.offset(8 as i32 as isize);
        while *start as i32 != 0
            && Curl_isspace(*start as u8 as i32) != 0
        {
            start = start.offset(1);
        }
        if *start == 0 {
            Curl_failf(
                data,
                b"Got a blank Session ID\0" as *const u8 as *const i8,
            );
            return CURLE_RTSP_SESSION_ERROR;
        }
        end = start;
        while *end as i32 != 0 && *end as i32 != ';' as i32
            && Curl_isspace(*end as u8 as i32) == 0
        {
            end = end.offset(1);
        }
        idlen = end.offset_from(start) as i64 as size_t;
        if !((*data).set.str_0[STRING_RTSP_SESSION_ID as i32 as usize]).is_null()
        {
            if strlen((*data).set.str_0[STRING_RTSP_SESSION_ID as i32 as usize])
                != idlen
                || strncmp(
                    start,
                    (*data).set.str_0[STRING_RTSP_SESSION_ID as i32 as usize],
                    idlen,
                ) != 0 as i32
            {
                Curl_failf(
                    data,
                    b"Got RTSP Session ID Line [%s], but wanted ID [%s]\0" as *const u8
                        as *const i8,
                    start,
                    (*data).set.str_0[STRING_RTSP_SESSION_ID as i32 as usize],
                );
                return CURLE_RTSP_SESSION_ERROR;
            }
        } else {
            let ref mut fresh35 = (*data)
                .set
                .str_0[STRING_RTSP_SESSION_ID as i32 as usize];
            *fresh35 = Curl_cmalloc
                .expect(
                    "non-null function pointer",
                )(idlen.wrapping_add(1 as i32 as u64))
                as *mut i8;
            if ((*data).set.str_0[STRING_RTSP_SESSION_ID as i32 as usize])
                .is_null()
            {
                return CURLE_OUT_OF_MEMORY;
            }
            memcpy(
                (*data).set.str_0[STRING_RTSP_SESSION_ID as i32 as usize]
                    as *mut libc::c_void,
                start as *const libc::c_void,
                idlen,
            );
            *((*data).set.str_0[STRING_RTSP_SESSION_ID as i32 as usize])
                .offset(idlen as isize) = '\u{0}' as i32 as i8;
        }
    }
    return CURLE_OK;
}
