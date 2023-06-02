use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    pub type nghttp2_session_callbacks;
    
    fn strlen(_: *const i8) -> u64;
    fn strncmp(
        _: *const i8,
        _: *const i8,
        _: u64,
    ) -> i32;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    
    
    
    
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> *mut libc::c_void;
    fn memmove(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> *mut libc::c_void;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> i32;
    fn memchr(
        _: *const libc::c_void,
        _: i32,
        _: u64,
    ) -> *mut libc::c_void;
    fn nghttp2_session_get_remote_settings(
        session: *mut nghttp2_session,
        id: nghttp2_settings_id,
    ) -> uint32_t;
    fn nghttp2_session_upgrade2(
        session: *mut nghttp2_session,
        settings_payload: *const uint8_t,
        settings_payloadlen: size_t,
        head_request: i32,
        stream_user_data: *mut libc::c_void,
    ) -> i32;
    fn nghttp2_pack_settings_payload(
        buf: *mut uint8_t,
        buflen: size_t,
        iv: *const nghttp2_settings_entry,
        niv: size_t,
    ) -> ssize_t;
    fn nghttp2_strerror(lib_error_code: i32) -> *const i8;
    fn nghttp2_http2_strerror(error_code: uint32_t) -> *const i8;
    fn nghttp2_priority_spec_init(
        pri_spec: *mut nghttp2_priority_spec,
        stream_id: int32_t,
        weight: int32_t,
        exclusive: i32,
    );
    fn nghttp2_submit_request(
        session: *mut nghttp2_session,
        pri_spec: *const nghttp2_priority_spec,
        nva: *const nghttp2_nv,
        nvlen: size_t,
        data_prd: *const nghttp2_data_provider,
        stream_user_data: *mut libc::c_void,
    ) -> int32_t;
    fn nghttp2_session_want_write(session: *mut nghttp2_session) -> i32;
    fn nghttp2_submit_priority(
        session: *mut nghttp2_session,
        flags: uint8_t,
        stream_id: int32_t,
        pri_spec: *const nghttp2_priority_spec,
    ) -> i32;
    fn nghttp2_submit_rst_stream(
        session: *mut nghttp2_session,
        flags: uint8_t,
        stream_id: int32_t,
        error_code: uint32_t,
    ) -> i32;
    fn nghttp2_submit_settings(
        session: *mut nghttp2_session,
        flags: uint8_t,
        iv: *const nghttp2_settings_entry,
        niv: size_t,
    ) -> i32;
    fn nghttp2_submit_ping(
        session: *mut nghttp2_session,
        flags: uint8_t,
        opaque_data: *const uint8_t,
    ) -> i32;
    fn nghttp2_session_check_request_allowed(
        session: *mut nghttp2_session,
    ) -> i32;
    fn nghttp2_session_set_local_window_size(
        session: *mut nghttp2_session,
        flags: uint8_t,
        stream_id: int32_t,
        window_size: int32_t,
    ) -> i32;
    fn nghttp2_version(least_version: i32) -> *mut nghttp2_info;
    fn nghttp2_is_fatal(lib_error_code: i32) -> i32;
    fn nghttp2_session_want_read(session: *mut nghttp2_session) -> i32;
    fn nghttp2_session_resume_data(
        session: *mut nghttp2_session,
        stream_id: int32_t,
    ) -> i32;
    fn nghttp2_session_mem_recv(
        session: *mut nghttp2_session,
        in_0: *const uint8_t,
        inlen: size_t,
    ) -> ssize_t;
    fn nghttp2_session_send(session: *mut nghttp2_session) -> i32;
    fn nghttp2_session_del(session: *mut nghttp2_session);
    fn nghttp2_session_client_new(
        session_ptr: *mut *mut nghttp2_session,
        callbacks: *const nghttp2_session_callbacks,
        user_data: *mut libc::c_void,
    ) -> i32;
    fn nghttp2_session_callbacks_set_error_callback(
        cbs: *mut nghttp2_session_callbacks,
        error_callback_0: nghttp2_error_callback,
    );
    fn nghttp2_session_get_stream_user_data(
        session: *mut nghttp2_session,
        stream_id: int32_t,
    ) -> *mut libc::c_void;
    fn nghttp2_session_set_stream_user_data(
        session: *mut nghttp2_session,
        stream_id: int32_t,
        stream_user_data: *mut libc::c_void,
    ) -> i32;
    fn nghttp2_session_callbacks_new(
        callbacks_ptr: *mut *mut nghttp2_session_callbacks,
    ) -> i32;
    fn nghttp2_session_callbacks_del(callbacks: *mut nghttp2_session_callbacks);
    fn nghttp2_session_callbacks_set_send_callback(
        cbs: *mut nghttp2_session_callbacks,
        send_callback_0: nghttp2_send_callback,
    );
    fn nghttp2_session_callbacks_set_on_frame_recv_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_frame_recv_callback: nghttp2_on_frame_recv_callback,
    );
    fn nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_data_chunk_recv_callback: nghttp2_on_data_chunk_recv_callback,
    );
    fn nghttp2_session_callbacks_set_on_stream_close_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_stream_close_callback: nghttp2_on_stream_close_callback,
    );
    fn nghttp2_session_callbacks_set_on_begin_headers_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_begin_headers_callback: nghttp2_on_begin_headers_callback,
    );
    fn nghttp2_session_callbacks_set_on_header_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_header_callback: nghttp2_on_header_callback,
    );
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::base64::Curl_base64url_encode;
pub use crate::src::lib::connect::Curl_connalive;
pub use crate::src::lib::connect::Curl_conncontrol;
pub use crate::src::lib::dynbuf::Curl_dyn_add;
pub use crate::src::lib::dynbuf::Curl_dyn_addf;
pub use crate::src::lib::dynbuf::Curl_dyn_addn;
pub use crate::src::lib::dynbuf::Curl_dyn_free;
pub use crate::src::lib::dynbuf::Curl_dyn_init;
pub use crate::src::lib::dynbuf::Curl_dyn_len;
pub use crate::src::lib::dynbuf::Curl_dyn_ptr;
pub use crate::src::lib::easy::curl_easy_duphandle;
pub use crate::src::lib::http::Curl_http;
pub use crate::src::lib::http::Curl_http_done;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::multi::Curl_expire;
pub use crate::src::lib::multi::Curl_multi_add_perform;
pub use crate::src::lib::multi::Curl_multi_max_concurrent_streams;
pub use crate::src::lib::multi::Curl_set_in_callback;
pub use crate::src::lib::select::Curl_socket_check;
pub use crate::src::lib::sendf::Curl_client_write;
pub use crate::src::lib::sendf::Curl_debug;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::strcase::Curl_strncasecompare;
pub use crate::src::lib::strcase::Curl_strntolower;
pub use crate::src::lib::strdup::Curl_saferealloc;
pub use crate::src::lib::timeval::Curl_now;
pub use crate::src::lib::timeval::Curl_timediff;
pub use crate::src::lib::url::Curl_close;
pub use crate::src::lib::urlapi::curl_url;
pub use crate::src::lib::urlapi::curl_url_cleanup;
pub use crate::src::lib::urlapi::curl_url_get;
pub use crate::src::lib::urlapi::curl_url_set;
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::altsvc::Gsasl;
pub use crate::src::lib::easy::Curl_ccalloc;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::hostip6::psl_ctx_st;
pub use crate::src::lib::imap::_IO_marker;
pub use crate::src::lib::speedcheck::_IO_codecvt;
pub use crate::src::lib::urlapi::Gsasl_session;
pub use crate::src::lib::version::nghttp2_session;
pub use crate::src::lib::vtls::vtls::_IO_wide_data;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::smb::smb_request;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_pushheaders {
    pub data: *mut Curl_easy,
    pub frame: *const nghttp2_push_promise,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_push_promise {
    pub hd: nghttp2_frame_hd,
    pub padlen: size_t,
    pub nva: *mut nghttp2_nv,
    pub nvlen: size_t,
    pub promised_stream_id: int32_t,
    pub reserved: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_nv {
    pub name: *mut uint8_t,
    pub value: *mut uint8_t,
    pub namelen: size_t,
    pub valuelen: size_t,
    pub flags: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_frame_hd {
    pub length: size_t,
    pub stream_id: int32_t,
    pub type_0: uint8_t,
    pub flags: uint8_t,
    pub reserved: uint8_t,
}
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
pub type curl_calloc_callback = crate::src::lib::altsvc::curl_calloc_callback;
pub type CURLMcode = crate::src::lib::doh::CURLMcode;
pub const CURLM_LAST: CURLMcode = 11;
pub const CURLM_BAD_FUNCTION_ARGUMENT: CURLMcode = 10;
pub const CURLM_WAKEUP_FAILURE: CURLMcode = 9;
pub const CURLM_RECURSIVE_API_CALL: CURLMcode = 8;
pub const CURLM_ADDED_ALREADY: CURLMcode = 7;
pub const CURLM_UNKNOWN_OPTION: CURLMcode = 6;
pub const CURLM_BAD_SOCKET: CURLMcode = 5;
pub const CURLM_INTERNAL_ERROR: CURLMcode = 4;
pub const CURLM_OUT_OF_MEMORY: CURLMcode = 3;
pub const CURLM_BAD_EASY_HANDLE: CURLMcode = 2;
pub const CURLM_BAD_HANDLE: CURLMcode = 1;
pub const CURLM_OK: CURLMcode = 0;
pub const CURLM_CALL_MULTI_PERFORM: CURLMcode = -1;
pub type CURLUcode = crate::src::lib::http::CURLUcode;
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
pub type CURLUPart = crate::src::lib::http::CURLUPart;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_info {
    pub age: i32,
    pub version_num: i32,
    pub version_str: *const i8,
    pub proto_str: *const i8,
}
pub type C2RustUnnamed_6 = i32;
pub const NGHTTP2_ERR_FLOODED: C2RustUnnamed_6 = -904;
pub const NGHTTP2_ERR_BAD_CLIENT_MAGIC: C2RustUnnamed_6 = -903;
pub const NGHTTP2_ERR_CALLBACK_FAILURE: C2RustUnnamed_6 = -902;
pub const NGHTTP2_ERR_NOMEM: C2RustUnnamed_6 = -901;
pub const NGHTTP2_ERR_FATAL: C2RustUnnamed_6 = -900;
pub const NGHTTP2_ERR_TOO_MANY_SETTINGS: C2RustUnnamed_6 = -537;
pub const NGHTTP2_ERR_SETTINGS_EXPECTED: C2RustUnnamed_6 = -536;
pub const NGHTTP2_ERR_CANCEL: C2RustUnnamed_6 = -535;
pub const NGHTTP2_ERR_INTERNAL: C2RustUnnamed_6 = -534;
pub const NGHTTP2_ERR_REFUSED_STREAM: C2RustUnnamed_6 = -533;
pub const NGHTTP2_ERR_HTTP_MESSAGING: C2RustUnnamed_6 = -532;
pub const NGHTTP2_ERR_HTTP_HEADER: C2RustUnnamed_6 = -531;
pub const NGHTTP2_ERR_SESSION_CLOSING: C2RustUnnamed_6 = -530;
pub const NGHTTP2_ERR_DATA_EXIST: C2RustUnnamed_6 = -529;
pub const NGHTTP2_ERR_PUSH_DISABLED: C2RustUnnamed_6 = -528;
pub const NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS: C2RustUnnamed_6 = -527;
pub const NGHTTP2_ERR_PAUSE: C2RustUnnamed_6 = -526;
pub const NGHTTP2_ERR_INSUFF_BUFSIZE: C2RustUnnamed_6 = -525;
pub const NGHTTP2_ERR_FLOW_CONTROL: C2RustUnnamed_6 = -524;
pub const NGHTTP2_ERR_HEADER_COMP: C2RustUnnamed_6 = -523;
pub const NGHTTP2_ERR_FRAME_SIZE_ERROR: C2RustUnnamed_6 = -522;
pub const NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE: C2RustUnnamed_6 = -521;
pub const NGHTTP2_ERR_INVALID_STATE: C2RustUnnamed_6 = -519;
pub const NGHTTP2_ERR_INVALID_HEADER_BLOCK: C2RustUnnamed_6 = -518;
pub const NGHTTP2_ERR_GOAWAY_ALREADY_SENT: C2RustUnnamed_6 = -517;
pub const NGHTTP2_ERR_START_STREAM_NOT_ALLOWED: C2RustUnnamed_6 = -516;
pub const NGHTTP2_ERR_DEFERRED_DATA_EXIST: C2RustUnnamed_6 = -515;
pub const NGHTTP2_ERR_INVALID_STREAM_STATE: C2RustUnnamed_6 = -514;
pub const NGHTTP2_ERR_INVALID_STREAM_ID: C2RustUnnamed_6 = -513;
pub const NGHTTP2_ERR_STREAM_SHUT_WR: C2RustUnnamed_6 = -512;
pub const NGHTTP2_ERR_STREAM_CLOSING: C2RustUnnamed_6 = -511;
pub const NGHTTP2_ERR_STREAM_CLOSED: C2RustUnnamed_6 = -510;
pub const NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE: C2RustUnnamed_6 = -509;
pub const NGHTTP2_ERR_DEFERRED: C2RustUnnamed_6 = -508;
pub const NGHTTP2_ERR_EOF: C2RustUnnamed_6 = -507;
pub const NGHTTP2_ERR_INVALID_FRAME: C2RustUnnamed_6 = -506;
pub const NGHTTP2_ERR_PROTO: C2RustUnnamed_6 = -505;
pub const NGHTTP2_ERR_WOULDBLOCK: C2RustUnnamed_6 = -504;
pub const NGHTTP2_ERR_UNSUPPORTED_VERSION: C2RustUnnamed_6 = -503;
pub const NGHTTP2_ERR_BUFFER_ERROR: C2RustUnnamed_6 = -502;
pub const NGHTTP2_ERR_INVALID_ARGUMENT: C2RustUnnamed_6 = -501;
pub type C2RustUnnamed_7 = u32;
pub const NGHTTP2_NV_FLAG_NO_COPY_VALUE: C2RustUnnamed_7 = 4;
pub const NGHTTP2_NV_FLAG_NO_COPY_NAME: C2RustUnnamed_7 = 2;
pub const NGHTTP2_NV_FLAG_NO_INDEX: C2RustUnnamed_7 = 1;
pub const NGHTTP2_NV_FLAG_NONE: C2RustUnnamed_7 = 0;
pub type C2RustUnnamed_8 = u32;
pub const NGHTTP2_PRIORITY_UPDATE: C2RustUnnamed_8 = 16;
pub const NGHTTP2_ORIGIN: C2RustUnnamed_8 = 12;
pub const NGHTTP2_ALTSVC: C2RustUnnamed_8 = 10;
pub const NGHTTP2_CONTINUATION: C2RustUnnamed_8 = 9;
pub const NGHTTP2_WINDOW_UPDATE: C2RustUnnamed_8 = 8;
pub const NGHTTP2_GOAWAY: C2RustUnnamed_8 = 7;
pub const NGHTTP2_PING: C2RustUnnamed_8 = 6;
pub const NGHTTP2_PUSH_PROMISE: C2RustUnnamed_8 = 5;
pub const NGHTTP2_SETTINGS: C2RustUnnamed_8 = 4;
pub const NGHTTP2_RST_STREAM: C2RustUnnamed_8 = 3;
pub const NGHTTP2_PRIORITY: C2RustUnnamed_8 = 2;
pub const NGHTTP2_HEADERS: C2RustUnnamed_8 = 1;
pub const NGHTTP2_DATA: C2RustUnnamed_8 = 0;
pub type C2RustUnnamed_9 = u32;
pub const NGHTTP2_FLAG_PRIORITY: C2RustUnnamed_9 = 32;
pub const NGHTTP2_FLAG_PADDED: C2RustUnnamed_9 = 8;
pub const NGHTTP2_FLAG_ACK: C2RustUnnamed_9 = 1;
pub const NGHTTP2_FLAG_END_HEADERS: C2RustUnnamed_9 = 4;
pub const NGHTTP2_FLAG_END_STREAM: C2RustUnnamed_9 = 1;
pub const NGHTTP2_FLAG_NONE: C2RustUnnamed_9 = 0;
pub type nghttp2_settings_id = u32;
pub const NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES: nghttp2_settings_id = 9;
pub const NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL: nghttp2_settings_id = 8;
pub const NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE: nghttp2_settings_id = 6;
pub const NGHTTP2_SETTINGS_MAX_FRAME_SIZE: nghttp2_settings_id = 5;
pub const NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE: nghttp2_settings_id = 4;
pub const NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS: nghttp2_settings_id = 3;
pub const NGHTTP2_SETTINGS_ENABLE_PUSH: nghttp2_settings_id = 2;
pub const NGHTTP2_SETTINGS_HEADER_TABLE_SIZE: nghttp2_settings_id = 1;
pub type C2RustUnnamed_10 = u32;
pub const NGHTTP2_HTTP_1_1_REQUIRED: C2RustUnnamed_10 = 13;
pub const NGHTTP2_INADEQUATE_SECURITY: C2RustUnnamed_10 = 12;
pub const NGHTTP2_ENHANCE_YOUR_CALM: C2RustUnnamed_10 = 11;
pub const NGHTTP2_CONNECT_ERROR: C2RustUnnamed_10 = 10;
pub const NGHTTP2_COMPRESSION_ERROR: C2RustUnnamed_10 = 9;
pub const NGHTTP2_CANCEL: C2RustUnnamed_10 = 8;
pub const NGHTTP2_REFUSED_STREAM: C2RustUnnamed_10 = 7;
pub const NGHTTP2_FRAME_SIZE_ERROR: C2RustUnnamed_10 = 6;
pub const NGHTTP2_STREAM_CLOSED: C2RustUnnamed_10 = 5;
pub const NGHTTP2_SETTINGS_TIMEOUT: C2RustUnnamed_10 = 4;
pub const NGHTTP2_FLOW_CONTROL_ERROR: C2RustUnnamed_10 = 3;
pub const NGHTTP2_INTERNAL_ERROR: C2RustUnnamed_10 = 2;
pub const NGHTTP2_PROTOCOL_ERROR: C2RustUnnamed_10 = 1;
pub const NGHTTP2_NO_ERROR: C2RustUnnamed_10 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub union nghttp2_data_source {
    pub fd: i32,
    pub ptr: *mut libc::c_void,
}
pub type C2RustUnnamed_11 = u32;
pub const NGHTTP2_DATA_FLAG_NO_COPY: C2RustUnnamed_11 = 4;
pub const NGHTTP2_DATA_FLAG_NO_END_STREAM: C2RustUnnamed_11 = 2;
pub const NGHTTP2_DATA_FLAG_EOF: C2RustUnnamed_11 = 1;
pub const NGHTTP2_DATA_FLAG_NONE: C2RustUnnamed_11 = 0;
pub type nghttp2_data_source_read_callback = Option::<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        int32_t,
        *mut uint8_t,
        size_t,
        *mut uint32_t,
        *mut nghttp2_data_source,
        *mut libc::c_void,
    ) -> ssize_t,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_data_provider {
    pub source: nghttp2_data_source,
    pub read_callback: nghttp2_data_source_read_callback,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_data {
    pub hd: nghttp2_frame_hd,
    pub padlen: size_t,
}
pub type nghttp2_headers_category = u32;
pub const NGHTTP2_HCAT_HEADERS: nghttp2_headers_category = 3;
pub const NGHTTP2_HCAT_PUSH_RESPONSE: nghttp2_headers_category = 2;
pub const NGHTTP2_HCAT_RESPONSE: nghttp2_headers_category = 1;
pub const NGHTTP2_HCAT_REQUEST: nghttp2_headers_category = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_priority_spec {
    pub stream_id: int32_t,
    pub weight: int32_t,
    pub exclusive: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_headers {
    pub hd: nghttp2_frame_hd,
    pub padlen: size_t,
    pub pri_spec: nghttp2_priority_spec,
    pub nva: *mut nghttp2_nv,
    pub nvlen: size_t,
    pub cat: nghttp2_headers_category,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_priority {
    pub hd: nghttp2_frame_hd,
    pub pri_spec: nghttp2_priority_spec,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_rst_stream {
    pub hd: nghttp2_frame_hd,
    pub error_code: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_settings {
    pub hd: nghttp2_frame_hd,
    pub niv: size_t,
    pub iv: *mut nghttp2_settings_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_ping {
    pub hd: nghttp2_frame_hd,
    pub opaque_data: [uint8_t; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_goaway {
    pub hd: nghttp2_frame_hd,
    pub last_stream_id: int32_t,
    pub error_code: uint32_t,
    pub opaque_data: *mut uint8_t,
    pub opaque_data_len: size_t,
    pub reserved: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_window_update {
    pub hd: nghttp2_frame_hd,
    pub window_size_increment: int32_t,
    pub reserved: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_extension {
    pub hd: nghttp2_frame_hd,
    pub payload: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union nghttp2_frame {
    pub hd: nghttp2_frame_hd,
    pub data: nghttp2_data,
    pub headers: nghttp2_headers,
    pub priority: nghttp2_priority,
    pub rst_stream: nghttp2_rst_stream,
    pub settings: nghttp2_settings,
    pub push_promise: nghttp2_push_promise,
    pub ping: nghttp2_ping,
    pub goaway: nghttp2_goaway,
    pub window_update: nghttp2_window_update,
    pub ext: nghttp2_extension,
}
pub type nghttp2_send_callback = Option::<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        *const uint8_t,
        size_t,
        i32,
        *mut libc::c_void,
    ) -> ssize_t,
>;
pub type nghttp2_on_frame_recv_callback = Option::<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        *const nghttp2_frame,
        *mut libc::c_void,
    ) -> i32,
>;
pub type nghttp2_on_data_chunk_recv_callback = Option::<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        uint8_t,
        int32_t,
        *const uint8_t,
        size_t,
        *mut libc::c_void,
    ) -> i32,
>;
pub type nghttp2_on_stream_close_callback = Option::<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        int32_t,
        uint32_t,
        *mut libc::c_void,
    ) -> i32,
>;
pub type nghttp2_on_begin_headers_callback = Option::<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        *const nghttp2_frame,
        *mut libc::c_void,
    ) -> i32,
>;
pub type nghttp2_on_header_callback = Option::<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        *const nghttp2_frame,
        *const uint8_t,
        size_t,
        *const uint8_t,
        size_t,
        uint8_t,
        *mut libc::c_void,
    ) -> i32,
>;
pub type nghttp2_error_callback = Option::<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        *const i8,
        size_t,
        *mut libc::c_void,
    ) -> i32,
>;
pub const HEADERINST_TE_TRAILERS: header_instruction = 2;
pub const HEADERINST_IGNORE: header_instruction = 1;
pub type header_instruction = u32;
pub const HEADERINST_FORWARD: header_instruction = 0;
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_init_state(mut state: *mut UrlState) {
    (*state).stream_weight = 16 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_init_userset(mut set: *mut UserDefined) {
    (*set).stream_weight = 16 as i32;
}
unsafe extern "C" fn http2_getsock(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sock: *mut curl_socket_t,
) -> i32 {
    let mut c: *const http_conn = &mut (*conn).proto.httpc;
    let mut k: *mut SingleRequest = &mut (*data).req;
    let mut bitmap: i32 = 0 as i32;
    *sock.offset(0 as i32 as isize) = (*conn).sock[0 as i32 as usize];
    if (*k).keepon & (1 as i32) << 4 as i32 == 0 {
        bitmap |= (1 as i32) << 0 as i32;
    }
    if (*k).keepon
        & ((1 as i32) << 1 as i32
            | (1 as i32) << 5 as i32)
        == (1 as i32) << 1 as i32
        || nghttp2_session_want_write((*c).h2) != 0
    {
        bitmap |= (1 as i32) << 16 as i32 + 0 as i32;
    }
    return bitmap;
}
unsafe extern "C" fn http2_stream_free(mut http: *mut HTTP) {
    if !http.is_null() {
        Curl_dyn_free(&mut (*http).header_recvbuf);
        while (*http).push_headers_used > 0 as i32 as u64 {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )(
                *((*http).push_headers)
                    .offset(
                        ((*http).push_headers_used)
                            .wrapping_sub(1 as i32 as u64) as isize,
                    ) as *mut libc::c_void,
            );
            let fresh0 = &mut ((*http).push_headers_used);
            *fresh0 = (*fresh0).wrapping_sub(1);
        }
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*http).push_headers as *mut libc::c_void);
        let fresh1 = &mut ((*http).push_headers);
        *fresh1 = 0 as *mut *mut i8;
    }
}
unsafe extern "C" fn http2_disconnect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut dead_connection: bool,
) -> CURLcode {
    let mut c: *mut http_conn = &mut (*conn).proto.httpc;
    nghttp2_session_del((*c).h2);
    Curl_cfree.expect("non-null function pointer")((*c).inbuf as *mut libc::c_void);
    let fresh2 = &mut ((*c).inbuf);
    *fresh2 = 0 as *mut i8;
    return CURLE_OK;
}
unsafe extern "C" fn http2_connisdead(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> bool {
    let mut sval: i32 = 0;
    let mut dead: bool = 1 as i32 != 0;
    if ((*conn).bits).close() != 0 {
        return 1 as i32 != 0;
    }
    sval = Curl_socket_check(
        (*conn).sock[0 as i32 as usize],
        -(1 as i32),
        -(1 as i32),
        0 as i32 as timediff_t,
    );
    if sval == 0 as i32 {
        dead = 0 as i32 != 0;
    } else if sval & 0x4 as i32 != 0 {
        dead = 1 as i32 != 0;
    } else if sval & 0x1 as i32 != 0 {
        dead = !Curl_connalive(conn);
        if !dead {
            let mut result: CURLcode = CURLE_OK;
            let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
            let mut nread: ssize_t = -(1 as i32) as ssize_t;
            if ((*httpc).recv_underlying).is_some() {
                nread = ((*httpc).recv_underlying)
                    .expect(
                        "non-null function pointer",
                    )(
                    data,
                    0 as i32,
                    (*httpc).inbuf,
                    32768 as i32 as size_t,
                    &mut result,
                );
            }
            if nread != -(1 as i32) as i64 {
                Curl_infof(
                    data,
                    b"%d bytes stray data read before trying h2 connection\0"
                        as *const u8 as *const i8,
                    nread as i32,
                );
                (*httpc).nread_inbuf = 0 as i32 as size_t;
                (*httpc).inbuflen = nread as size_t;
                if h2_process_pending_input(data, httpc, &mut result) < 0 as i32
                {
                    dead = 1 as i32 != 0;
                }
            } else {
                dead = 1 as i32 != 0;
            }
        }
    }
    return dead;
}
unsafe extern "C" fn set_transfer(mut c: *mut http_conn, mut data: *mut Curl_easy) {
    let fresh3 = &mut ((*c).trnsfr);
    *fresh3 = data;
}
unsafe extern "C" fn get_transfer(mut c: *mut http_conn) -> *mut Curl_easy {
    return (*c).trnsfr;
}
unsafe extern "C" fn http2_conncheck(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut checks_to_perform: u32,
) -> u32 {
    let mut ret_val: u32 = 0 as i32 as u32;
    let mut c: *mut http_conn = &mut (*conn).proto.httpc;
    let mut rc: i32 = 0;
    let mut send_frames: bool = 0 as i32 != 0;
    if checks_to_perform & ((1 as i32) << 0 as i32) as u32 != 0
    {
        if http2_connisdead(data, conn) {
            ret_val |= ((1 as i32) << 0 as i32) as u32;
        }
    }
    if checks_to_perform & ((1 as i32) << 1 as i32) as u32 != 0
    {
        let mut now: curltime = Curl_now();
        let mut elapsed: timediff_t = Curl_timediff(now, (*conn).keepalive);
        if elapsed > (*data).set.upkeep_interval_ms {
            rc = nghttp2_submit_ping(
                (*c).h2,
                0 as i32 as uint8_t,
                0 as *const uint8_t,
            );
            if rc == 0 {
                send_frames = 1 as i32 != 0;
            } else {
                Curl_failf(
                    data,
                    b"nghttp2_submit_ping() failed: %s(%d)\0" as *const u8
                        as *const i8,
                    nghttp2_strerror(rc),
                    rc,
                );
            }
            (*conn).keepalive = now;
        }
    }
    if send_frames {
        set_transfer(c, data);
        rc = nghttp2_session_send((*c).h2);
        if rc != 0 {
            Curl_failf(
                data,
                b"nghttp2_session_send() failed: %s(%d)\0" as *const u8
                    as *const i8,
                nghttp2_strerror(rc),
                rc,
            );
        }
    }
    return ret_val;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_setup_req(mut data: *mut Curl_easy) {
    let mut http: *mut HTTP = (*data).req.p.http;
    (*http).bodystarted = 0 as i32 != 0;
    (*http).status_code = -(1 as i32);
    let fresh4 = &mut ((*http).pausedata);
    *fresh4 = 0 as *const uint8_t;
    (*http).pauselen = 0 as i32 as size_t;
    (*http).closed = 0 as i32 != 0;
    (*http).close_handled = 0 as i32 != 0;
    let fresh5 = &mut ((*http).mem);
    *fresh5 = 0 as *mut i8;
    (*http).len = 0 as i32 as size_t;
    (*http).memlen = 0 as i32 as size_t;
    (*http).error = NGHTTP2_NO_ERROR as i32 as uint32_t;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_setup_conn(mut conn: *mut connectdata) {
    (*conn).proto.httpc.settings.max_concurrent_streams = 100 as i32 as uint32_t;
}
static mut Curl_handler_http2: Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"HTTP\0" as *const u8 as *const i8,
            setup_connection: None,
            do_it: Some(
                Curl_http as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            done: Some(
                Curl_http_done
                    as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
            ),
            do_more: None,
            connect_it: None,
            connecting: None,
            doing: None,
            proto_getsock: Some(
                http2_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            doing_getsock: Some(
                http2_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            domore_getsock: None,
            perform_getsock: Some(
                http2_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            disconnect: Some(
                http2_disconnect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        bool,
                    ) -> CURLcode,
            ),
            readwrite: None,
            connection_check: Some(
                http2_conncheck
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        u32,
                    ) -> u32,
            ),
            attach: None,
            defport: 80 as i32,
            protocol: ((1 as i32) << 0 as i32) as u32,
            family: ((1 as i32) << 0 as i32) as u32,
            flags: ((1 as i32) << 9 as i32) as u32,
        };
        init
    }
};
static mut Curl_handler_http2_ssl: Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"HTTPS\0" as *const u8 as *const i8,
            setup_connection: None,
            do_it: Some(
                Curl_http as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            done: Some(
                Curl_http_done
                    as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
            ),
            do_more: None,
            connect_it: None,
            connecting: None,
            doing: None,
            proto_getsock: Some(
                http2_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            doing_getsock: Some(
                http2_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            domore_getsock: None,
            perform_getsock: Some(
                http2_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            disconnect: Some(
                http2_disconnect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        bool,
                    ) -> CURLcode,
            ),
            readwrite: None,
            connection_check: Some(
                http2_conncheck
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        u32,
                    ) -> u32,
            ),
            attach: None,
            defport: 80 as i32,
            protocol: ((1 as i32) << 1 as i32) as u32,
            family: ((1 as i32) << 0 as i32) as u32,
            flags: ((1 as i32) << 0 as i32
                | (1 as i32) << 9 as i32) as u32,
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_ver(mut p: *mut i8, mut len: size_t) {
    let mut h2: *mut nghttp2_info = nghttp2_version(0 as i32);
    curl_msnprintf(
        p,
        len,
        b"nghttp2/%s\0" as *const u8 as *const i8,
        (*h2).version_str,
    );
}
unsafe extern "C" fn send_callback(
    mut h2: *mut nghttp2_session,
    mut mem: *const uint8_t,
    mut length: size_t,
    mut flags: i32,
    mut userp: *mut libc::c_void,
) -> ssize_t {
    let mut conn: *mut connectdata = userp as *mut connectdata;
    let mut c: *mut http_conn = &mut (*conn).proto.httpc;
    let mut data: *mut Curl_easy = get_transfer(c);
    let mut written: ssize_t = 0;
    let mut result: CURLcode = CURLE_OK;
    if ((*c).send_underlying).is_none() {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32 as ssize_t;
    }
    written = ((*c).send_underlying)
        .expect(
            "non-null function pointer",
        )(data, 0 as i32, mem as *const libc::c_void, length, &mut result);
    if result as u32 == CURLE_AGAIN as i32 as u32 {
        return NGHTTP2_ERR_WOULDBLOCK as i32 as ssize_t;
    }
    if written == -(1 as i32) as i64 {
        Curl_failf(
            data,
            b"Failed sending HTTP2 data\0" as *const u8 as *const i8,
        );
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32 as ssize_t;
    }
    if written == 0 {
        return NGHTTP2_ERR_WOULDBLOCK as i32 as ssize_t;
    }
    return written;
}
#[no_mangle]
pub unsafe extern "C" fn curl_pushheader_bynum(
    mut h: *mut curl_pushheaders,
    mut num: size_t,
) -> *mut i8 {
    if h.is_null()
        || !(!((*h).data).is_null() && (*(*h).data).magic == 0xc0dedbad as u32)
    {
        return 0 as *mut i8
    } else {
        let mut stream: *mut HTTP = (*(*h).data).req.p.http;
        if num < (*stream).push_headers_used {
            return *((*stream).push_headers).offset(num as isize);
        }
    }
    return 0 as *mut i8;
}
#[no_mangle]
pub unsafe extern "C" fn curl_pushheader_byname(
    mut h: *mut curl_pushheaders,
    mut header: *const i8,
) -> *mut i8 {
    if h.is_null()
        || !(!((*h).data).is_null() && (*(*h).data).magic == 0xc0dedbad as u32)
        || header.is_null() || *header.offset(0 as i32 as isize) == 0
        || strcmp(header, b":\0" as *const u8 as *const i8) == 0
        || !(strchr(header.offset(1 as i32 as isize), ':' as i32)).is_null()
    {
        return 0 as *mut i8
    } else {
        let mut stream: *mut HTTP = (*(*h).data).req.p.http;
        let mut len: size_t = strlen(header);
        let mut i: size_t = 0;
        i = 0 as i32 as size_t;
        while i < (*stream).push_headers_used {
            if strncmp(header, *((*stream).push_headers).offset(i as isize), len) == 0 {
                if !(*(*((*stream).push_headers).offset(i as isize)).offset(len as isize)
                    as i32 != ':' as i32)
                {
                    return &mut *(*((*stream).push_headers).offset(i as isize))
                        .offset(
                            len.wrapping_add(1 as i32 as u64) as isize,
                        ) as *mut i8;
                }
            }
            i = i.wrapping_add(1);
        }
    }
    return 0 as *mut i8;
}
unsafe extern "C" fn drained_transfer(
    mut data: *mut Curl_easy,
    mut httpc: *mut http_conn,
) {
    let fresh6 = &mut ((*httpc).drain_total);
    *fresh6 = (*fresh6 as u64).wrapping_sub((*data).state.drain) as size_t
        as size_t;
    (*data).state.drain = 0 as i32 as size_t;
}
unsafe extern "C" fn drain_this(mut data: *mut Curl_easy, mut httpc: *mut http_conn) {
    let fresh7 = &mut ((*data).state.drain);
    *fresh7 = (*fresh7).wrapping_add(1);
    let fresh8 = &mut ((*httpc).drain_total);
    *fresh8 = (*fresh8).wrapping_add(1);
}
unsafe extern "C" fn duphandle(mut data: *mut Curl_easy) -> *mut Curl_easy {
    let mut second: *mut Curl_easy = curl_easy_duphandle(data);
    if !second.is_null() {
        let mut http: *mut HTTP = Curl_ccalloc
            .expect(
                "non-null function pointer",
            )(1 as i32 as size_t, ::std::mem::size_of::<HTTP>() as u64)
            as *mut HTTP;
        if http.is_null() {
            Curl_close(&mut second);
        } else {
            let fresh9 = &mut ((*second).req.p.http);
            *fresh9 = http;
            Curl_dyn_init(
                &mut (*http).header_recvbuf,
                (128 as i32 * 1024 as i32) as size_t,
            );
            Curl_http2_setup_req(second);
            (*second).state.stream_weight = (*data).state.stream_weight;
        }
    }
    return second;
}
unsafe extern "C" fn set_transfer_url(
    mut data: *mut Curl_easy,
    mut hp: *mut curl_pushheaders,
) -> i32 {
    let mut current_block: u64;
    let mut v: *const i8 = 0 as *const i8;
    let mut u: *mut CURLU = curl_url();
    let mut uc: CURLUcode = CURLUE_OK;
    let mut url: *mut i8 = 0 as *mut i8;
    let mut rc: i32 = 0 as i32;
    v = curl_pushheader_byname(hp, b":scheme\0" as *const u8 as *const i8);
    if !v.is_null() {
        uc = curl_url_set(u, CURLUPART_SCHEME, v, 0 as i32 as u32);
        if uc as u64 != 0 {
            rc = 1 as i32;
            current_block = 15190465896548324989;
        } else {
            current_block = 8515828400728868193;
        }
    } else {
        current_block = 8515828400728868193;
    }
    match current_block {
        8515828400728868193 => {
            v = curl_pushheader_byname(
                hp,
                b":authority\0" as *const u8 as *const i8,
            );
            if !v.is_null() {
                uc = curl_url_set(
                    u,
                    CURLUPART_HOST,
                    v,
                    0 as i32 as u32,
                );
                if uc as u64 != 0 {
                    rc = 2 as i32;
                    current_block = 15190465896548324989;
                } else {
                    current_block = 12349973810996921269;
                }
            } else {
                current_block = 12349973810996921269;
            }
            match current_block {
                15190465896548324989 => {}
                _ => {
                    v = curl_pushheader_byname(
                        hp,
                        b":path\0" as *const u8 as *const i8,
                    );
                    if !v.is_null() {
                        uc = curl_url_set(
                            u,
                            CURLUPART_PATH,
                            v,
                            0 as i32 as u32,
                        );
                        if uc as u64 != 0 {
                            rc = 3 as i32;
                            current_block = 15190465896548324989;
                        } else {
                            current_block = 4808432441040389987;
                        }
                    } else {
                        current_block = 4808432441040389987;
                    }
                    match current_block {
                        15190465896548324989 => {}
                        _ => {
                            uc = curl_url_get(
                                u,
                                CURLUPART_URL,
                                &mut url,
                                0 as i32 as u32,
                            );
                            if uc as u64 != 0 {
                                rc = 4 as i32;
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    curl_url_cleanup(u);
    if rc != 0 {
        return rc;
    }
    if ((*data).state).url_alloc() != 0 {
        Curl_cfree
            .expect("non-null function pointer")((*data).state.url as *mut libc::c_void);
    }
    let fresh10 = &mut ((*data).state);
    (*fresh10).set_url_alloc(1 as i32 as bit);
    let fresh11 = &mut ((*data).state.url);
    *fresh11 = url;
    return 0 as i32;
}
unsafe extern "C" fn push_promise(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut frame: *const nghttp2_push_promise,
) -> i32 {
    let mut rv: i32 = 0;
    if ((*(*data).multi).push_cb).is_some() {
        let mut stream: *mut HTTP = 0 as *mut HTTP;
        let mut newstream: *mut HTTP = 0 as *mut HTTP;
        let mut heads: curl_pushheaders = curl_pushheaders {
            data: 0 as *mut Curl_easy,
            frame: 0 as *const nghttp2_push_promise,
        };
        let mut rc: CURLMcode = CURLM_OK;
        let mut httpc: *mut http_conn = 0 as *mut http_conn;
        let mut i: size_t = 0;
        let mut newhandle: *mut Curl_easy = duphandle(data);
        if newhandle.is_null() {
            Curl_infof(
                data,
                b"failed to duplicate handle\0" as *const u8 as *const i8,
            );
            rv = 1 as i32;
        } else {
            heads.data = data;
            heads.frame = frame;
            stream = (*data).req.p.http;
            if stream.is_null() {
                Curl_failf(
                    data,
                    b"Internal NULL stream!\0" as *const u8 as *const i8,
                );
                Curl_close(&mut newhandle);
                rv = 1 as i32;
            } else {
                rv = set_transfer_url(newhandle, &mut heads);
                if rv != 0 {
                    Curl_close(&mut newhandle);
                    rv = 1 as i32;
                } else {
                    Curl_set_in_callback(data, 1 as i32 != 0);
                    rv = ((*(*data).multi).push_cb)
                        .expect(
                            "non-null function pointer",
                        )(
                        data,
                        newhandle,
                        (*stream).push_headers_used,
                        &mut heads,
                        (*(*data).multi).push_userp,
                    );
                    Curl_set_in_callback(data, 0 as i32 != 0);
                    i = 0 as i32 as size_t;
                    while i < (*stream).push_headers_used {
                        Curl_cfree
                            .expect(
                                "non-null function pointer",
                            )(
                            *((*stream).push_headers).offset(i as isize)
                                as *mut libc::c_void,
                        );
                        i = i.wrapping_add(1);
                    }
                    Curl_cfree
                        .expect(
                            "non-null function pointer",
                        )((*stream).push_headers as *mut libc::c_void);
                    let fresh12 = &mut ((*stream).push_headers);
                    *fresh12 = 0 as *mut *mut i8;
                    (*stream).push_headers_used = 0 as i32 as size_t;
                    if rv != 0 {
                        http2_stream_free((*newhandle).req.p.http);
                        let fresh13 = &mut ((*newhandle).req.p.http);
                        *fresh13 = 0 as *mut HTTP;
                        Curl_close(&mut newhandle);
                    } else {
                        newstream = (*newhandle).req.p.http;
                        (*newstream).stream_id = (*frame).promised_stream_id;
                        (*newhandle).req.maxdownload = -(1 as i32) as curl_off_t;
                        (*newhandle).req.size = -(1 as i32) as curl_off_t;
                        rc = Curl_multi_add_perform((*data).multi, newhandle, conn);
                        if rc as u64 != 0 {
                            Curl_infof(
                                data,
                                b"failed to add handle to multi\0" as *const u8
                                    as *const i8,
                            );
                            http2_stream_free((*newhandle).req.p.http);
                            let fresh14 = &mut ((*newhandle).req.p.http);
                            *fresh14 = 0 as *mut HTTP;
                            Curl_close(&mut newhandle);
                            rv = 1 as i32;
                        } else {
                            httpc = &mut (*conn).proto.httpc;
                            rv = nghttp2_session_set_stream_user_data(
                                (*httpc).h2,
                                (*frame).promised_stream_id,
                                newhandle as *mut libc::c_void,
                            );
                            if rv != 0 {
                                Curl_infof(
                                    data,
                                    b"failed to set user_data for stream %d\0" as *const u8
                                        as *const i8,
                                    (*frame).promised_stream_id,
                                );
                                rv = 1 as i32;
                            } else {
                                Curl_dyn_init(
                                    &mut (*newstream).header_recvbuf,
                                    (128 as i32 * 1024 as i32) as size_t,
                                );
                                Curl_dyn_init(
                                    &mut (*newstream).trailer_recvbuf,
                                    (128 as i32 * 1024 as i32) as size_t,
                                );
                            }
                        }
                    }
                }
            }
        }
    } else {
        rv = 1 as i32;
    }
    return rv;
}
unsafe extern "C" fn multi_connchanged(mut multi: *mut Curl_multi) {
    (*multi).recheckstate = 1 as i32 != 0;
}
unsafe extern "C" fn on_frame_recv(
    mut session: *mut nghttp2_session,
    mut frame: *const nghttp2_frame,
    mut userp: *mut libc::c_void,
) -> i32 {
    let mut conn: *mut connectdata = userp as *mut connectdata;
    let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
    let mut data_s: *mut Curl_easy = 0 as *mut Curl_easy;
    let mut stream: *mut HTTP = 0 as *mut HTTP;
    let mut data: *mut Curl_easy = get_transfer(httpc);
    let mut rv: i32 = 0;
    let mut left: size_t = 0;
    let mut ncopy: size_t = 0;
    let mut stream_id: int32_t = (*frame).hd.stream_id;
    let mut result: CURLcode = CURLE_OK;
    if stream_id == 0 {
        if (*frame).hd.type_0 as i32 == NGHTTP2_SETTINGS as i32 {
            let mut max_conn: uint32_t = (*httpc).settings.max_concurrent_streams;
            (*httpc)
                .settings
                .max_concurrent_streams = nghttp2_session_get_remote_settings(
                session,
                NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
            );
            (*httpc)
                .settings
                .enable_push = nghttp2_session_get_remote_settings(
                session,
                NGHTTP2_SETTINGS_ENABLE_PUSH,
            ) != 0;
            if max_conn != (*httpc).settings.max_concurrent_streams {
                Curl_infof(
                    data,
                    b"Connection state changed (MAX_CONCURRENT_STREAMS == %u)!\0"
                        as *const u8 as *const i8,
                    (*httpc).settings.max_concurrent_streams,
                );
                multi_connchanged((*data).multi);
            }
        }
        return 0 as i32;
    }
    data_s = nghttp2_session_get_stream_user_data(session, stream_id) as *mut Curl_easy;
    if data_s.is_null() {
        return 0 as i32;
    }
    stream = (*data_s).req.p.http;
    if stream.is_null() {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    match (*frame).hd.type_0 as i32 {
        0 => {
            if !(*stream).bodystarted {
                rv = nghttp2_submit_rst_stream(
                    session,
                    NGHTTP2_FLAG_NONE as i32 as uint8_t,
                    stream_id,
                    NGHTTP2_PROTOCOL_ERROR as i32 as uint32_t,
                );
                if nghttp2_is_fatal(rv) != 0 {
                    return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
                }
            }
        }
        1 => {
            if !(*stream).bodystarted {
                if (*stream).status_code == -(1 as i32) {
                    return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
                }
                if (*stream).status_code / 100 as i32 != 1 as i32 {
                    (*stream).bodystarted = 1 as i32 != 0;
                    (*stream).status_code = -(1 as i32);
                }
                result = Curl_dyn_add(
                    &mut (*stream).header_recvbuf,
                    b"\r\n\0" as *const u8 as *const i8,
                );
                if result as u64 != 0 {
                    return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
                }
                left = (Curl_dyn_len(&mut (*stream).header_recvbuf))
                    .wrapping_sub((*stream).nread_header_recvbuf);
                ncopy = if (*stream).len < left { (*stream).len } else { left };
                memcpy(
                    &mut *((*stream).mem).offset((*stream).memlen as isize)
                        as *mut i8 as *mut libc::c_void,
                    (Curl_dyn_ptr(&mut (*stream).header_recvbuf))
                        .offset((*stream).nread_header_recvbuf as isize)
                        as *const libc::c_void,
                    ncopy,
                );
                let fresh15 = &mut ((*stream).nread_header_recvbuf);
                *fresh15 = (*fresh15 as u64).wrapping_add(ncopy) as size_t
                    as size_t;
                let fresh16 = &mut ((*stream).len);
                *fresh16 = (*fresh16 as u64).wrapping_sub(ncopy) as size_t
                    as size_t;
                let fresh17 = &mut ((*stream).memlen);
                *fresh17 = (*fresh17 as u64).wrapping_add(ncopy) as size_t
                    as size_t;
                drain_this(data_s, httpc);
                if get_transfer(httpc) != data_s {
                    Curl_expire(data_s, 0 as i32 as timediff_t, EXPIRE_RUN_NOW);
                }
            }
        }
        5 => {
            rv = push_promise(data_s, conn, &(*frame).push_promise);
            if rv != 0 {
                let mut h2: i32 = 0;
                h2 = nghttp2_submit_rst_stream(
                    session,
                    NGHTTP2_FLAG_NONE as i32 as uint8_t,
                    (*frame).push_promise.promised_stream_id,
                    NGHTTP2_CANCEL as i32 as uint32_t,
                );
                if nghttp2_is_fatal(h2) != 0 {
                    return NGHTTP2_ERR_CALLBACK_FAILURE as i32
                } else {
                    if rv == 2 as i32 {
                        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
                    }
                }
            }
        }
        _ => {}
    }
    return 0 as i32;
}
unsafe extern "C" fn on_data_chunk_recv(
    mut session: *mut nghttp2_session,
    mut flags: uint8_t,
    mut stream_id: int32_t,
    mut mem: *const uint8_t,
    mut len: size_t,
    mut userp: *mut libc::c_void,
) -> i32 {
    let mut stream: *mut HTTP = 0 as *mut HTTP;
    let mut data_s: *mut Curl_easy = 0 as *mut Curl_easy;
    let mut nread: size_t = 0;
    let mut conn: *mut connectdata = userp as *mut connectdata;
    let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
    data_s = nghttp2_session_get_stream_user_data(session, stream_id) as *mut Curl_easy;
    if data_s.is_null() {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    stream = (*data_s).req.p.http;
    if stream.is_null() {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    nread = if (*stream).len < len { (*stream).len } else { len };
    memcpy(
        &mut *((*stream).mem).offset((*stream).memlen as isize) as *mut i8
            as *mut libc::c_void,
        mem as *const libc::c_void,
        nread,
    );
    let fresh18 = &mut ((*stream).len);
    *fresh18 = (*fresh18 as u64).wrapping_sub(nread) as size_t as size_t;
    let fresh19 = &mut ((*stream).memlen);
    *fresh19 = (*fresh19 as u64).wrapping_add(nread) as size_t as size_t;
    drain_this(data_s, &mut (*conn).proto.httpc);
    if get_transfer(httpc) != data_s {
        Curl_expire(data_s, 0 as i32 as timediff_t, EXPIRE_RUN_NOW);
    }
    if nread < len {
        let fresh20 = &mut ((*stream).pausedata);
        *fresh20 = mem.offset(nread as isize);
        (*stream).pauselen = len.wrapping_sub(nread);
        (*(*data_s).conn).proto.httpc.pause_stream_id = stream_id;
        return NGHTTP2_ERR_PAUSE as i32;
    }
    if get_transfer(httpc) != data_s {
        (*(*data_s).conn).proto.httpc.pause_stream_id = stream_id;
        return NGHTTP2_ERR_PAUSE as i32;
    }
    return 0 as i32;
}
unsafe extern "C" fn on_stream_close(
    mut session: *mut nghttp2_session,
    mut stream_id: int32_t,
    mut error_code: uint32_t,
    mut userp: *mut libc::c_void,
) -> i32 {
    let mut data_s: *mut Curl_easy = 0 as *mut Curl_easy;
    let mut stream: *mut HTTP = 0 as *mut HTTP;
    let mut conn: *mut connectdata = userp as *mut connectdata;
    let mut rv: i32 = 0;
    if stream_id != 0 {
        let mut httpc: *mut http_conn = 0 as *mut http_conn;
        data_s = nghttp2_session_get_stream_user_data(session, stream_id)
            as *mut Curl_easy;
        if data_s.is_null() {
            return 0 as i32;
        }
        stream = (*data_s).req.p.http;
        if stream.is_null() {
            return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
        }
        (*stream).closed = 1 as i32 != 0;
        httpc = &mut (*conn).proto.httpc;
        drain_this(data_s, httpc);
        Curl_expire(data_s, 0 as i32 as timediff_t, EXPIRE_RUN_NOW);
        (*stream).error = error_code;
        rv = nghttp2_session_set_stream_user_data(
            session,
            stream_id,
            0 as *mut libc::c_void,
        );
        if rv != 0 {
            Curl_infof(
                data_s,
                b"http/2: failed to clear user_data for stream %d!\0" as *const u8
                    as *const i8,
                stream_id,
            );
        }
        if stream_id == (*httpc).pause_stream_id {
            (*httpc).pause_stream_id = 0 as i32;
        }
        (*stream).stream_id = 0 as i32;
    }
    return 0 as i32;
}
unsafe extern "C" fn on_begin_headers(
    mut session: *mut nghttp2_session,
    mut frame: *const nghttp2_frame,
    mut userp: *mut libc::c_void,
) -> i32 {
    let mut stream: *mut HTTP = 0 as *mut HTTP;
    let mut data_s: *mut Curl_easy = 0 as *mut Curl_easy;
    data_s = nghttp2_session_get_stream_user_data(session, (*frame).hd.stream_id)
        as *mut Curl_easy;
    if data_s.is_null() {
        return 0 as i32;
    }
    if (*frame).hd.type_0 as i32 != NGHTTP2_HEADERS as i32 {
        return 0 as i32;
    }
    stream = (*data_s).req.p.http;
    if stream.is_null() || !(*stream).bodystarted {
        return 0 as i32;
    }
    return 0 as i32;
}
unsafe extern "C" fn decode_status_code(
    mut value: *const uint8_t,
    mut len: size_t,
) -> i32 {
    let mut i: i32 = 0;
    let mut res: i32 = 0;
    if len != 3 as i32 as u64 {
        return -(1 as i32);
    }
    res = 0 as i32;
    i = 0 as i32;
    while i < 3 as i32 {
        let mut c: i8 = *value.offset(i as isize) as i8;
        if (c as i32) < '0' as i32 || c as i32 > '9' as i32 {
            return -(1 as i32);
        }
        res *= 10 as i32;
        res += c as i32 - '0' as i32;
        i += 1;
    }
    return res;
}
unsafe extern "C" fn on_header(
    mut session: *mut nghttp2_session,
    mut frame: *const nghttp2_frame,
    mut name: *const uint8_t,
    mut namelen: size_t,
    mut value: *const uint8_t,
    mut valuelen: size_t,
    mut flags: uint8_t,
    mut userp: *mut libc::c_void,
) -> i32 {
    let mut stream: *mut HTTP = 0 as *mut HTTP;
    let mut data_s: *mut Curl_easy = 0 as *mut Curl_easy;
    let mut stream_id: int32_t = (*frame).hd.stream_id;
    let mut conn: *mut connectdata = userp as *mut connectdata;
    let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
    let mut result: CURLcode = CURLE_OK;
    data_s = nghttp2_session_get_stream_user_data(session, stream_id) as *mut Curl_easy;
    if data_s.is_null() {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    stream = (*data_s).req.p.http;
    if stream.is_null() {
        Curl_failf(
            data_s,
            b"Internal NULL stream!\0" as *const u8 as *const i8,
        );
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    if (*frame).hd.type_0 as i32 == NGHTTP2_PUSH_PROMISE as i32 {
        let mut h: *mut i8 = 0 as *mut i8;
        if strcmp(
            b":authority\0" as *const u8 as *const i8,
            name as *const i8,
        ) == 0
        {
            let mut rc: i32 = 0 as i32;
            let mut check: *mut i8 = curl_maprintf(
                b"%s:%d\0" as *const u8 as *const i8,
                (*conn).host.name,
                (*conn).remote_port,
            );
            if check.is_null() {
                return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
            }
            if Curl_strcasecompare(check, value as *const i8) == 0
                && ((*conn).remote_port != (*(*conn).given).defport
                    || Curl_strcasecompare(
                        (*conn).host.name,
                        value as *const i8,
                    ) == 0)
            {
                nghttp2_submit_rst_stream(
                    session,
                    NGHTTP2_FLAG_NONE as i32 as uint8_t,
                    stream_id,
                    NGHTTP2_PROTOCOL_ERROR as i32 as uint32_t,
                );
                rc = NGHTTP2_ERR_CALLBACK_FAILURE as i32;
            }
            Curl_cfree.expect("non-null function pointer")(check as *mut libc::c_void);
            if rc != 0 {
                return rc;
            }
        }
        if ((*stream).push_headers).is_null() {
            (*stream).push_headers_alloc = 10 as i32 as size_t;
            let fresh21 = &mut ((*stream).push_headers);
            *fresh21 = Curl_cmalloc
                .expect(
                    "non-null function pointer",
                )(
                ((*stream).push_headers_alloc)
                    .wrapping_mul(
                        ::std::mem::size_of::<*mut i8>() as u64,
                    ),
            ) as *mut *mut i8;
            if ((*stream).push_headers).is_null() {
                return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE as i32;
            }
            (*stream).push_headers_used = 0 as i32 as size_t;
        } else if (*stream).push_headers_used == (*stream).push_headers_alloc {
            let mut headp: *mut *mut i8 = 0 as *mut *mut i8;
            let fresh22 = &mut ((*stream).push_headers_alloc);
            *fresh22 = (*fresh22 as u64)
                .wrapping_mul(2 as i32 as u64) as size_t as size_t;
            headp = Curl_saferealloc(
                (*stream).push_headers as *mut libc::c_void,
                ((*stream).push_headers_alloc)
                    .wrapping_mul(
                        ::std::mem::size_of::<*mut i8>() as u64,
                    ),
            ) as *mut *mut i8;
            if headp.is_null() {
                let fresh23 = &mut ((*stream).push_headers);
                *fresh23 = 0 as *mut *mut i8;
                return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE as i32;
            }
            let fresh24 = &mut ((*stream).push_headers);
            *fresh24 = headp;
        }
        h = curl_maprintf(b"%s:%s\0" as *const u8 as *const i8, name, value);
        if !h.is_null() {
            let fresh25 = &mut ((*stream).push_headers_used);
            let fresh26 = *fresh25;
            *fresh25 = (*fresh25).wrapping_add(1);
            let fresh27 = &mut (*((*stream).push_headers).offset(fresh26 as isize));
            *fresh27 = h;
        }
        return 0 as i32;
    }
    if (*stream).bodystarted {
        result = Curl_dyn_addf(
            &mut (*stream).trailer_recvbuf as *mut dynbuf,
            b"%.*s: %.*s\r\n\0" as *const u8 as *const i8,
            namelen,
            name,
            valuelen,
            value,
        );
        if result as u64 != 0 {
            return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
        }
        return 0 as i32;
    }
    if namelen
        == (::std::mem::size_of::<[i8; 8]>() as u64)
            .wrapping_sub(1 as i32 as u64)
        && memcmp(
            b":status\0" as *const u8 as *const i8 as *const libc::c_void,
            name as *const libc::c_void,
            namelen,
        ) == 0 as i32
    {
        (*stream).status_code = decode_status_code(value, valuelen);
        result = Curl_dyn_add(
            &mut (*stream).header_recvbuf,
            b"HTTP/2 \0" as *const u8 as *const i8,
        );
        if result as u64 != 0 {
            return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
        }
        result = Curl_dyn_addn(
            &mut (*stream).header_recvbuf,
            value as *const libc::c_void,
            valuelen,
        );
        if result as u64 != 0 {
            return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
        }
        result = Curl_dyn_add(
            &mut (*stream).header_recvbuf,
            b" \r\n\0" as *const u8 as *const i8,
        );
        if result as u64 != 0 {
            return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
        }
        if get_transfer(httpc) != data_s {
            Curl_expire(data_s, 0 as i32 as timediff_t, EXPIRE_RUN_NOW);
        }
        return 0 as i32;
    }
    result = Curl_dyn_addn(
        &mut (*stream).header_recvbuf,
        name as *const libc::c_void,
        namelen,
    );
    if result as u64 != 0 {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    result = Curl_dyn_add(
        &mut (*stream).header_recvbuf,
        b": \0" as *const u8 as *const i8,
    );
    if result as u64 != 0 {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    result = Curl_dyn_addn(
        &mut (*stream).header_recvbuf,
        value as *const libc::c_void,
        valuelen,
    );
    if result as u64 != 0 {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    result = Curl_dyn_add(
        &mut (*stream).header_recvbuf,
        b"\r\n\0" as *const u8 as *const i8,
    );
    if result as u64 != 0 {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    if get_transfer(httpc) != data_s {
        Curl_expire(data_s, 0 as i32 as timediff_t, EXPIRE_RUN_NOW);
    }
    return 0 as i32;
}
unsafe extern "C" fn data_source_read_callback(
    mut session: *mut nghttp2_session,
    mut stream_id: int32_t,
    mut buf: *mut uint8_t,
    mut length: size_t,
    mut data_flags: *mut uint32_t,
    mut source: *mut nghttp2_data_source,
    mut userp: *mut libc::c_void,
) -> ssize_t {
    let mut data_s: *mut Curl_easy = 0 as *mut Curl_easy;
    let mut stream: *mut HTTP = 0 as *mut HTTP;
    let mut nread: size_t = 0;
    if stream_id != 0 {
        data_s = nghttp2_session_get_stream_user_data(session, stream_id)
            as *mut Curl_easy;
        if data_s.is_null() {
            return NGHTTP2_ERR_CALLBACK_FAILURE as i32 as ssize_t;
        }
        stream = (*data_s).req.p.http;
        if stream.is_null() {
            return NGHTTP2_ERR_CALLBACK_FAILURE as i32 as ssize_t;
        }
    } else {
        return NGHTTP2_ERR_INVALID_ARGUMENT as i32 as ssize_t
    }
    nread = if (*stream).upload_len < length { (*stream).upload_len } else { length };
    if nread > 0 as i32 as u64 {
        memcpy(
            buf as *mut libc::c_void,
            (*stream).upload_mem as *const libc::c_void,
            nread,
        );
        let fresh28 = &mut ((*stream).upload_mem);
        *fresh28 = (*fresh28).offset(nread as isize);
        let fresh29 = &mut ((*stream).upload_len);
        *fresh29 = (*fresh29 as u64).wrapping_sub(nread) as size_t as size_t;
        if (*data_s).state.infilesize != -(1 as i32) as i64 {
            let fresh30 = &mut ((*stream).upload_left);
            *fresh30 = (*fresh30 as u64).wrapping_sub(nread) as curl_off_t
                as curl_off_t;
        }
    }
    if (*stream).upload_left == 0 as i32 as i64 {
        *data_flags = NGHTTP2_DATA_FLAG_EOF as i32 as uint32_t;
    } else if nread == 0 as i32 as u64 {
        return NGHTTP2_ERR_DEFERRED as i32 as ssize_t
    }
    return nread as ssize_t;
}
 extern "C" fn error_callback(
    mut session: *mut nghttp2_session,
    mut msg: *const i8,
    mut len: size_t,
    mut userp: *mut libc::c_void,
) -> i32 {
    return 0 as i32;
}
unsafe extern "C" fn populate_settings(
    mut data: *mut Curl_easy,
    mut httpc: *mut http_conn,
) {
    let mut iv: *mut nghttp2_settings_entry = ((*httpc).local_settings).as_mut_ptr();
    (*iv.offset(0 as i32 as isize))
        .settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS as i32;
    (*iv.offset(0 as i32 as isize))
        .value = Curl_multi_max_concurrent_streams((*data).multi);
    (*iv.offset(1 as i32 as isize))
        .settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE as i32;
    (*iv.offset(1 as i32 as isize))
        .value = (32 as i32 * 1024 as i32 * 1024 as i32)
        as uint32_t;
    (*iv.offset(2 as i32 as isize))
        .settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH as i32;
    (*iv.offset(2 as i32 as isize))
        .value = ((*(*data).multi).push_cb).is_some() as i32 as uint32_t;
    (*httpc).local_settings_num = 3 as i32 as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_done(mut data: *mut Curl_easy, mut premature: bool) {
    let mut http: *mut HTTP = (*data).req.p.http;
    let mut httpc: *mut http_conn = &mut (*(*data).conn).proto.httpc;
    Curl_dyn_free(&mut (*http).header_recvbuf);
    Curl_dyn_free(&mut (*http).trailer_recvbuf);
    if !((*http).push_headers).is_null() {
        while (*http).push_headers_used > 0 as i32 as u64 {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )(
                *((*http).push_headers)
                    .offset(
                        ((*http).push_headers_used)
                            .wrapping_sub(1 as i32 as u64) as isize,
                    ) as *mut libc::c_void,
            );
            let fresh31 = &mut ((*http).push_headers_used);
            *fresh31 = (*fresh31).wrapping_sub(1);
        }
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*http).push_headers as *mut libc::c_void);
        let fresh32 = &mut ((*http).push_headers);
        *fresh32 = 0 as *mut *mut i8;
    }
    if (*(*(*data).conn).handler).protocol
        & ((1 as i32) << 0 as i32
            | (1 as i32) << 1 as i32) as u32 == 0
        || ((*httpc).h2).is_null()
    {
        return;
    }
    if premature {
        set_transfer(httpc, data);
        if nghttp2_submit_rst_stream(
            (*httpc).h2,
            NGHTTP2_FLAG_NONE as i32 as uint8_t,
            (*http).stream_id,
            NGHTTP2_STREAM_CLOSED as i32 as uint32_t,
        ) == 0
        {
            nghttp2_session_send((*httpc).h2);
        }
        if (*http).stream_id == (*httpc).pause_stream_id {
            Curl_infof(
                data,
                b"stopped the pause stream!\0" as *const u8 as *const i8,
            );
            (*httpc).pause_stream_id = 0 as i32;
        }
    }
    if (*data).state.drain != 0 {
        drained_transfer(data, httpc);
    }
    if (*http).stream_id > 0 as i32 {
        let mut rv: i32 = nghttp2_session_set_stream_user_data(
            (*httpc).h2,
            (*http).stream_id,
            0 as *mut libc::c_void,
        );
        if rv != 0 {
            Curl_infof(
                data,
                b"http/2: failed to clear user_data for stream %d!\0" as *const u8
                    as *const i8,
                (*http).stream_id,
            );
        }
        set_transfer(httpc, 0 as *mut Curl_easy);
        (*http).stream_id = 0 as i32;
    }
}
unsafe extern "C" fn http2_init(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    if ((*conn).proto.httpc.h2).is_null() {
        let mut rc: i32 = 0;
        let mut callbacks: *mut nghttp2_session_callbacks = 0
            as *mut nghttp2_session_callbacks;
        let fresh33 = &mut ((*conn).proto.httpc.inbuf);
        *fresh33 = Curl_cmalloc
            .expect("non-null function pointer")(32768 as i32 as size_t)
            as *mut i8;
        if ((*conn).proto.httpc.inbuf).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        rc = nghttp2_session_callbacks_new(&mut callbacks);
        if rc != 0 {
            Curl_failf(
                data,
                b"Couldn't initialize nghttp2 callbacks!\0" as *const u8
                    as *const i8,
            );
            return CURLE_OUT_OF_MEMORY;
        }
        nghttp2_session_callbacks_set_send_callback(
            callbacks,
            Some(
                send_callback
                    as unsafe extern "C" fn(
                        *mut nghttp2_session,
                        *const uint8_t,
                        size_t,
                        i32,
                        *mut libc::c_void,
                    ) -> ssize_t,
            ),
        );
        nghttp2_session_callbacks_set_on_frame_recv_callback(
            callbacks,
            Some(
                on_frame_recv
                    as unsafe extern "C" fn(
                        *mut nghttp2_session,
                        *const nghttp2_frame,
                        *mut libc::c_void,
                    ) -> i32,
            ),
        );
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
            callbacks,
            Some(
                on_data_chunk_recv
                    as unsafe extern "C" fn(
                        *mut nghttp2_session,
                        uint8_t,
                        int32_t,
                        *const uint8_t,
                        size_t,
                        *mut libc::c_void,
                    ) -> i32,
            ),
        );
        nghttp2_session_callbacks_set_on_stream_close_callback(
            callbacks,
            Some(
                on_stream_close
                    as unsafe extern "C" fn(
                        *mut nghttp2_session,
                        int32_t,
                        uint32_t,
                        *mut libc::c_void,
                    ) -> i32,
            ),
        );
        nghttp2_session_callbacks_set_on_begin_headers_callback(
            callbacks,
            Some(
                on_begin_headers
                    as unsafe extern "C" fn(
                        *mut nghttp2_session,
                        *const nghttp2_frame,
                        *mut libc::c_void,
                    ) -> i32,
            ),
        );
        nghttp2_session_callbacks_set_on_header_callback(
            callbacks,
            Some(
                on_header
                    as unsafe extern "C" fn(
                        *mut nghttp2_session,
                        *const nghttp2_frame,
                        *const uint8_t,
                        size_t,
                        *const uint8_t,
                        size_t,
                        uint8_t,
                        *mut libc::c_void,
                    ) -> i32,
            ),
        );
        nghttp2_session_callbacks_set_error_callback(
            callbacks,
            Some(
                error_callback
                    as unsafe extern "C" fn(
                        *mut nghttp2_session,
                        *const i8,
                        size_t,
                        *mut libc::c_void,
                    ) -> i32,
            ),
        );
        rc = nghttp2_session_client_new(
            &mut (*conn).proto.httpc.h2,
            callbacks,
            conn as *mut libc::c_void,
        );
        nghttp2_session_callbacks_del(callbacks);
        if rc != 0 {
            Curl_failf(
                data,
                b"Couldn't initialize nghttp2!\0" as *const u8 as *const i8,
            );
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_request_upgrade(
    mut req: *mut dynbuf,
    mut data: *mut Curl_easy,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut binlen: ssize_t = 0;
    let mut base64: *mut i8 = 0 as *mut i8;
    let mut blen: size_t = 0;
    let mut conn: *mut connectdata = (*data).conn;
    let mut k: *mut SingleRequest = &mut (*data).req;
    let mut binsettings: *mut uint8_t = ((*conn).proto.httpc.binsettings).as_mut_ptr();
    let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
    populate_settings(data, httpc);
    binlen = nghttp2_pack_settings_payload(
        binsettings,
        80 as i32 as size_t,
        ((*httpc).local_settings).as_mut_ptr(),
        (*httpc).local_settings_num,
    );
    if binlen <= 0 as i32 as i64 {
        Curl_failf(
            data,
            b"nghttp2 unexpectedly failed on pack_settings_payload\0" as *const u8
                as *const i8,
        );
        Curl_dyn_free(req);
        return CURLE_FAILED_INIT;
    }
    (*conn).proto.httpc.binlen = binlen as size_t;
    result = Curl_base64url_encode(
        data,
        binsettings as *const i8,
        binlen as size_t,
        &mut base64,
        &mut blen,
    );
    if result as u64 != 0 {
        Curl_dyn_free(req);
        return result;
    }
    result = Curl_dyn_addf(
        req,
        b"Connection: Upgrade, HTTP2-Settings\r\nUpgrade: %s\r\nHTTP2-Settings: %s\r\n\0"
            as *const u8 as *const i8,
        b"h2c\0" as *const u8 as *const i8,
        base64,
    );
    Curl_cfree.expect("non-null function pointer")(base64 as *mut libc::c_void);
    (*k).upgr101 = UPGR101_REQUESTED;
    return result;
}
unsafe extern "C" fn should_close_session(mut httpc: *mut http_conn) -> i32 {
    return ((*httpc).drain_total == 0 as i32 as u64
        && nghttp2_session_want_read((*httpc).h2) == 0
        && nghttp2_session_want_write((*httpc).h2) == 0) as i32;
}
unsafe extern "C" fn h2_process_pending_input(
    mut data: *mut Curl_easy,
    mut httpc: *mut http_conn,
    mut err: *mut CURLcode,
) -> i32 {
    let mut nread: ssize_t = 0;
    let mut inbuf: *mut i8 = 0 as *mut i8;
    let mut rv: ssize_t = 0;
    nread = ((*httpc).inbuflen).wrapping_sub((*httpc).nread_inbuf) as ssize_t;
    inbuf = ((*httpc).inbuf).offset((*httpc).nread_inbuf as isize);
    set_transfer(httpc, data);
    rv = nghttp2_session_mem_recv((*httpc).h2, inbuf as *const uint8_t, nread as size_t);
    if rv < 0 as i32 as i64 {
        Curl_failf(
            data,
            b"h2_process_pending_input: nghttp2_session_mem_recv() returned %zd:%s\0"
                as *const u8 as *const i8,
            rv,
            nghttp2_strerror(rv as i32),
        );
        *err = CURLE_RECV_ERROR;
        return -(1 as i32);
    }
    if nread == rv {
        (*httpc).inbuflen = 0 as i32 as size_t;
        (*httpc).nread_inbuf = 0 as i32 as size_t;
    } else {
        let fresh34 = &mut ((*httpc).nread_inbuf);
        *fresh34 = (*fresh34 as u64).wrapping_add(rv as u64)
            as size_t as size_t;
    }
    rv = h2_session_send(data, (*httpc).h2) as ssize_t;
    if rv != 0 {
        *err = CURLE_SEND_ERROR;
        return -(1 as i32);
    }
    if nghttp2_session_check_request_allowed((*httpc).h2) == 0 as i32 {
        Curl_conncontrol((*data).conn, 1 as i32);
    }
    if should_close_session(httpc) != 0 {
        let mut stream: *mut HTTP = (*data).req.p.http;
        if (*stream).error != 0 {
            *err = CURLE_HTTP2;
        } else {
            Curl_conncontrol((*data).conn, 1 as i32);
            *err = CURLE_OK;
        }
        return -(1 as i32);
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_done_sending(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    if (*conn).handler == &Curl_handler_http2_ssl as *const Curl_handler
        || (*conn).handler == &Curl_handler_http2 as *const Curl_handler
    {
        let mut stream: *mut HTTP = (*data).req.p.http;
        let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
        let mut h2: *mut nghttp2_session = (*httpc).h2;
        if (*stream).upload_left != 0 {
            (*stream).upload_left = 0 as i32 as curl_off_t;
            nghttp2_session_resume_data(h2, (*stream).stream_id);
            h2_process_pending_input(data, httpc, &mut result);
        }
        if nghttp2_session_want_write(h2) != 0 {
            let mut k: *mut SingleRequest = &mut (*data).req;
            let mut rv: i32 = 0;
            rv = h2_session_send(data, h2);
            if rv != 0 {
                result = CURLE_SEND_ERROR;
            }
            if nghttp2_session_want_write(h2) != 0 {
                (*k).keepon |= (1 as i32) << 1 as i32;
            }
        }
    }
    return result;
}
unsafe extern "C" fn http2_handle_stream_close(
    mut conn: *mut connectdata,
    mut data: *mut Curl_easy,
    mut stream: *mut HTTP,
    mut err: *mut CURLcode,
) -> ssize_t {
    let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
    if (*httpc).pause_stream_id == (*stream).stream_id {
        (*httpc).pause_stream_id = 0 as i32;
    }
    drained_transfer(data, httpc);
    if (*httpc).pause_stream_id == 0 as i32 {
        if h2_process_pending_input(data, httpc, err) != 0 as i32 {
            return -(1 as i32) as ssize_t;
        }
    }
    (*stream).closed = 0 as i32 != 0;
    if (*stream).error == NGHTTP2_REFUSED_STREAM as i32 as u32 {
        Curl_conncontrol(conn, 1 as i32);
        let fresh35 = &mut ((*data).state);
        (*fresh35).set_refused_stream(1 as i32 as bit);
        *err = CURLE_RECV_ERROR;
        return -(1 as i32) as ssize_t;
    } else {
        if (*stream).error != NGHTTP2_NO_ERROR as i32 as u32 {
            Curl_failf(
                data,
                b"HTTP/2 stream %d was not closed cleanly: %s (err %u)\0" as *const u8
                    as *const i8,
                (*stream).stream_id,
                nghttp2_http2_strerror((*stream).error),
                (*stream).error,
            );
            *err = CURLE_HTTP2_STREAM;
            return -(1 as i32) as ssize_t;
        }
    }
    if !(*stream).bodystarted {
        Curl_failf(
            data,
            b"HTTP/2 stream %d was closed cleanly, but before getting  all response header fields, treated as error\0"
                as *const u8 as *const i8,
            (*stream).stream_id,
        );
        *err = CURLE_HTTP2_STREAM;
        return -(1 as i32) as ssize_t;
    }
    if Curl_dyn_len(&mut (*stream).trailer_recvbuf) != 0 {
        let mut trailp: *mut i8 = Curl_dyn_ptr(&mut (*stream).trailer_recvbuf);
        let mut lf: *mut i8 = 0 as *mut i8;
        loop {
            let mut len: size_t = 0 as i32 as size_t;
            let mut result: CURLcode = CURLE_OK;
            lf = strchr(trailp, '\n' as i32);
            if lf.is_null() {
                break;
            }
            len = lf.offset(1 as i32 as isize).offset_from(trailp)
                as i64 as size_t;
            Curl_debug(data, CURLINFO_HEADER_IN, trailp, len);
            result = Curl_client_write(
                data,
                (1 as i32) << 1 as i32,
                trailp,
                len,
            );
            if result as u64 != 0 {
                *err = result;
                return -(1 as i32) as ssize_t;
            }
            lf = lf.offset(1);
            trailp = lf;
            if lf.is_null() {
                break;
            }
        }
    }
    (*stream).close_handled = 1 as i32 != 0;
    return 0 as i32 as ssize_t;
}
unsafe extern "C" fn h2_pri_spec(
    mut data: *mut Curl_easy,
    mut pri_spec: *mut nghttp2_priority_spec,
) {
    let mut depstream: *mut HTTP = if !((*data).set.stream_depends_on).is_null() {
        (*(*data).set.stream_depends_on).req.p.http
    } else {
        0 as *mut HTTP
    };
    let mut depstream_id: int32_t = if !depstream.is_null() {
        (*depstream).stream_id
    } else {
        0 as i32
    };
    nghttp2_priority_spec_init(
        pri_spec,
        depstream_id,
        (*data).set.stream_weight,
        ((*data).set).stream_depends_e() as i32,
    );
    (*data).state.stream_weight = (*data).set.stream_weight;
    let fresh36 = &mut ((*data).state);
    (*fresh36).set_stream_depends_e(((*data).set).stream_depends_e());
    let fresh37 = &mut ((*data).state.stream_depends_on);
    *fresh37 = (*data).set.stream_depends_on;
}
unsafe extern "C" fn h2_session_send(
    mut data: *mut Curl_easy,
    mut h2: *mut nghttp2_session,
) -> i32 {
    let mut stream: *mut HTTP = (*data).req.p.http;
    let mut httpc: *mut http_conn = &mut (*(*data).conn).proto.httpc;
    set_transfer(httpc, data);
    if (*data).set.stream_weight != (*data).state.stream_weight
        || ((*data).set).stream_depends_e() as i32
            != ((*data).state).stream_depends_e() as i32
        || (*data).set.stream_depends_on != (*data).state.stream_depends_on
    {
        let mut pri_spec: nghttp2_priority_spec = nghttp2_priority_spec {
            stream_id: 0,
            weight: 0,
            exclusive: 0,
        };
        let mut rv: i32 = 0;
        h2_pri_spec(data, &mut pri_spec);
        rv = nghttp2_submit_priority(
            h2,
            NGHTTP2_FLAG_NONE as i32 as uint8_t,
            (*stream).stream_id,
            &mut pri_spec,
        );
        if rv != 0 {
            return rv;
        }
    }
    return nghttp2_session_send(h2);
}
unsafe extern "C" fn http2_recv(
    mut data: *mut Curl_easy,
    mut sockindex: i32,
    mut mem: *mut i8,
    mut len: size_t,
    mut err: *mut CURLcode,
) -> ssize_t {
    let mut nread: ssize_t = 0;
    let mut conn: *mut connectdata = (*data).conn;
    let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
    let mut stream: *mut HTTP = (*data).req.p.http;
    if should_close_session(httpc) != 0 {
        if ((*conn).bits).close() != 0 {
            *err = CURLE_OK;
            return 0 as i32 as ssize_t;
        }
        *err = CURLE_HTTP2;
        return -(1 as i32) as ssize_t;
    }
    let fresh38 = &mut ((*stream).upload_mem);
    *fresh38 = 0 as *const uint8_t;
    (*stream).upload_len = 0 as i32 as size_t;
    if (*stream).bodystarted as i32 != 0
        && (*stream).nread_header_recvbuf < Curl_dyn_len(&mut (*stream).header_recvbuf)
    {
        let mut left: size_t = (Curl_dyn_len(&mut (*stream).header_recvbuf))
            .wrapping_sub((*stream).nread_header_recvbuf);
        let mut ncopy: size_t = if len < left { len } else { left };
        memcpy(
            mem as *mut libc::c_void,
            (Curl_dyn_ptr(&mut (*stream).header_recvbuf))
                .offset((*stream).nread_header_recvbuf as isize) as *const libc::c_void,
            ncopy,
        );
        let fresh39 = &mut ((*stream).nread_header_recvbuf);
        *fresh39 = (*fresh39 as u64).wrapping_add(ncopy) as size_t as size_t;
        return ncopy as ssize_t;
    }
    if (*data).state.drain != 0 && (*stream).memlen != 0 {
        if mem != (*stream).mem {
            memmove(
                mem as *mut libc::c_void,
                (*stream).mem as *const libc::c_void,
                (*stream).memlen,
            );
            (*stream).len = len.wrapping_sub((*stream).memlen);
            let fresh40 = &mut ((*stream).mem);
            *fresh40 = mem;
        }
        if (*httpc).pause_stream_id == (*stream).stream_id
            && ((*stream).pausedata).is_null()
        {
            (*httpc).pause_stream_id = 0 as i32;
            if h2_process_pending_input(data, httpc, err) != 0 as i32 {
                return -(1 as i32) as ssize_t;
            }
        }
    } else if !((*stream).pausedata).is_null() {
        nread = (if len < (*stream).pauselen { len } else { (*stream).pauselen })
            as ssize_t;
        memcpy(
            mem as *mut libc::c_void,
            (*stream).pausedata as *const libc::c_void,
            nread as u64,
        );
        let fresh41 = &mut ((*stream).pausedata);
        *fresh41 = (*fresh41).offset(nread as isize);
        let fresh42 = &mut ((*stream).pauselen);
        *fresh42 = (*fresh42 as u64).wrapping_sub(nread as u64)
            as size_t as size_t;
        if (*stream).pauselen == 0 as i32 as u64 {
            (*httpc).pause_stream_id = 0 as i32;
            let fresh43 = &mut ((*stream).pausedata);
            *fresh43 = 0 as *const uint8_t;
            (*stream).pauselen = 0 as i32 as size_t;
            if h2_process_pending_input(data, httpc, err) != 0 as i32 {
                return -(1 as i32) as ssize_t;
            }
        }
        return nread;
    } else {
        if (*httpc).pause_stream_id != 0 {
            if (*stream).closed {
                return 0 as i32 as ssize_t;
            }
            *err = CURLE_AGAIN;
            return -(1 as i32) as ssize_t;
        } else {
            let fresh44 = &mut ((*stream).mem);
            *fresh44 = mem;
            (*stream).len = len;
            (*stream).memlen = 0 as i32 as size_t;
            if (*httpc).inbuflen == 0 as i32 as u64 {
                nread = ((*httpc).recv_underlying)
                    .expect(
                        "non-null function pointer",
                    )(
                    data,
                    0 as i32,
                    (*httpc).inbuf,
                    32768 as i32 as size_t,
                    err,
                );
                if nread == -(1 as i32) as i64 {
                    if *err as u32 != CURLE_AGAIN as i32 as u32
                    {
                        Curl_failf(
                            data,
                            b"Failed receiving HTTP2 data\0" as *const u8
                                as *const i8,
                        );
                    } else if (*stream).closed {
                        return http2_handle_stream_close(conn, data, stream, err)
                    }
                    return -(1 as i32) as ssize_t;
                }
                if nread == 0 as i32 as i64 {
                    if !(*stream).closed {
                        Curl_failf(
                            data,
                            b"HTTP/2 stream %d was not closed cleanly before end of the underlying stream\0"
                                as *const u8 as *const i8,
                            (*stream).stream_id,
                        );
                        *err = CURLE_HTTP2_STREAM;
                        return -(1 as i32) as ssize_t;
                    }
                    *err = CURLE_OK;
                    return 0 as i32 as ssize_t;
                }
                (*httpc).inbuflen = nread as size_t;
            } else {
                nread = ((*httpc).inbuflen).wrapping_sub((*httpc).nread_inbuf)
                    as ssize_t;
            }
            if h2_process_pending_input(data, httpc, err) != 0 {
                return -(1 as i32) as ssize_t;
            }
        }
    }
    if (*stream).memlen != 0 {
        let mut retlen: ssize_t = (*stream).memlen as ssize_t;
        (*stream).memlen = 0 as i32 as size_t;
        if !((*httpc).pause_stream_id == (*stream).stream_id) {
            if !(*stream).closed {
                drained_transfer(data, httpc);
            } else {
                Curl_expire(data, 0 as i32 as timediff_t, EXPIRE_RUN_NOW);
            }
        }
        return retlen;
    }
    if (*stream).closed {
        return http2_handle_stream_close(conn, data, stream, err);
    }
    *err = CURLE_AGAIN;
    return -(1 as i32) as ssize_t;
}
unsafe extern "C" fn contains_trailers(
    mut p: *const i8,
    mut len: size_t,
) -> bool {
    let mut end: *const i8 = p.offset(len as isize);
    loop {
        while p != end
            && (*p as i32 == ' ' as i32 || *p as i32 == '\t' as i32)
        {
            p = p.offset(1);
        }
        if p == end
            || (end.offset_from(p) as i64 as size_t)
                < (::std::mem::size_of::<[i8; 9]>() as u64)
                    .wrapping_sub(1 as i32 as u64)
        {
            return 0 as i32 != 0;
        }
        if Curl_strncasecompare(
            b"trailers\0" as *const u8 as *const i8,
            p,
            (::std::mem::size_of::<[i8; 9]>() as u64)
                .wrapping_sub(1 as i32 as u64),
        ) != 0
        {
            p = p
                .offset(
                    (::std::mem::size_of::<[i8; 9]>() as u64)
                        .wrapping_sub(1 as i32 as u64) as isize,
                );
            while p != end
                && (*p as i32 == ' ' as i32 || *p as i32 == '\t' as i32)
            {
                p = p.offset(1);
            }
            if p == end || *p as i32 == ',' as i32 {
                return 1 as i32 != 0;
            }
        }
        while p != end && *p as i32 != ',' as i32 {
            p = p.offset(1);
        }
        if p == end {
            return 0 as i32 != 0;
        }
        p = p.offset(1);
    };
}
unsafe extern "C" fn inspect_header(
    mut name: *const i8,
    mut namelen: size_t,
    mut value: *const i8,
    mut valuelen: size_t,
) -> header_instruction {
    match namelen {
        2 => {
            if Curl_strncasecompare(
                b"te\0" as *const u8 as *const i8,
                name,
                namelen,
            ) == 0
            {
                return HEADERINST_FORWARD;
            }
            return (if contains_trailers(value, valuelen) as i32 != 0 {
                HEADERINST_TE_TRAILERS as i32
            } else {
                HEADERINST_IGNORE as i32
            }) as header_instruction;
        }
        7 => {
            return (if Curl_strncasecompare(
                b"upgrade\0" as *const u8 as *const i8,
                name,
                namelen,
            ) != 0
            {
                HEADERINST_IGNORE as i32
            } else {
                HEADERINST_FORWARD as i32
            }) as header_instruction;
        }
        10 => {
            return (if Curl_strncasecompare(
                b"connection\0" as *const u8 as *const i8,
                name,
                namelen,
            ) != 0
                || Curl_strncasecompare(
                    b"keep-alive\0" as *const u8 as *const i8,
                    name,
                    namelen,
                ) != 0
            {
                HEADERINST_IGNORE as i32
            } else {
                HEADERINST_FORWARD as i32
            }) as header_instruction;
        }
        16 => {
            return (if Curl_strncasecompare(
                b"proxy-connection\0" as *const u8 as *const i8,
                name,
                namelen,
            ) != 0
            {
                HEADERINST_IGNORE as i32
            } else {
                HEADERINST_FORWARD as i32
            }) as header_instruction;
        }
        17 => {
            return (if Curl_strncasecompare(
                b"transfer-encoding\0" as *const u8 as *const i8,
                name,
                namelen,
            ) != 0
            {
                HEADERINST_IGNORE as i32
            } else {
                HEADERINST_FORWARD as i32
            }) as header_instruction;
        }
        _ => return HEADERINST_FORWARD,
    };
}
unsafe extern "C" fn http2_send(
    mut data: *mut Curl_easy,
    mut sockindex: i32,
    mut mem: *const libc::c_void,
    mut len: size_t,
    mut err: *mut CURLcode,
) -> ssize_t {
    let mut current_block: u64;
    let mut rv: i32 = 0;
    let mut conn: *mut connectdata = (*data).conn;
    let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
    let mut stream: *mut HTTP = (*data).req.p.http;
    let mut nva: *mut nghttp2_nv = 0 as *mut nghttp2_nv;
    let mut nheader: size_t = 0;
    let mut i: size_t = 0;
    let mut authority_idx: size_t = 0;
    let mut hdbuf: *mut i8 = mem as *mut i8;
    let mut end: *mut i8 = 0 as *mut i8;
    let mut line_end: *mut i8 = 0 as *mut i8;
    let mut data_prd: nghttp2_data_provider = nghttp2_data_provider {
        source: nghttp2_data_source { fd: 0 },
        read_callback: None,
    };
    let mut stream_id: int32_t = 0;
    let mut h2: *mut nghttp2_session = (*httpc).h2;
    let mut pri_spec: nghttp2_priority_spec = nghttp2_priority_spec {
        stream_id: 0,
        weight: 0,
        exclusive: 0,
    };
    if (*stream).stream_id != -(1 as i32) {
        if (*stream).close_handled {
            Curl_infof(
                data,
                b"stream %d closed\0" as *const u8 as *const i8,
                (*stream).stream_id,
            );
            *err = CURLE_HTTP2_STREAM;
            return -(1 as i32) as ssize_t;
        } else {
            if (*stream).closed {
                return http2_handle_stream_close(conn, data, stream, err);
            }
        }
        let fresh45 = &mut ((*stream).upload_mem);
        *fresh45 = mem as *const uint8_t;
        (*stream).upload_len = len;
        rv = nghttp2_session_resume_data(h2, (*stream).stream_id);
        if nghttp2_is_fatal(rv) != 0 {
            *err = CURLE_SEND_ERROR;
            return -(1 as i32) as ssize_t;
        }
        rv = h2_session_send(data, h2);
        if nghttp2_is_fatal(rv) != 0 {
            *err = CURLE_SEND_ERROR;
            return -(1 as i32) as ssize_t;
        }
        len = (len as u64).wrapping_sub((*stream).upload_len) as size_t
            as size_t;
        let fresh46 = &mut ((*stream).upload_mem);
        *fresh46 = 0 as *const uint8_t;
        (*stream).upload_len = 0 as i32 as size_t;
        if should_close_session(httpc) != 0 {
            *err = CURLE_HTTP2;
            return -(1 as i32) as ssize_t;
        }
        if (*stream).upload_left != 0 {
            nghttp2_session_resume_data(h2, (*stream).stream_id);
        }
        return len as ssize_t;
    }
    nheader = 0 as i32 as size_t;
    i = 1 as i32 as size_t;
    while i < len {
        if *hdbuf.offset(i as isize) as i32 == '\n' as i32
            && *hdbuf.offset(i.wrapping_sub(1 as i32 as u64) as isize)
                as i32 == '\r' as i32
        {
            nheader = nheader.wrapping_add(1);
            i = i.wrapping_add(1);
        }
        i = i.wrapping_add(1);
    }
    if !(nheader < 2 as i32 as u64) {
        nheader = (nheader as u64)
            .wrapping_add(1 as i32 as u64) as size_t as size_t;
        nva = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )(
            (::std::mem::size_of::<nghttp2_nv>() as u64).wrapping_mul(nheader),
        ) as *mut nghttp2_nv;
        if nva.is_null() {
            *err = CURLE_OUT_OF_MEMORY;
            return -(1 as i32) as ssize_t;
        }
        line_end = memchr(hdbuf as *const libc::c_void, '\r' as i32, len)
            as *mut i8;
        if !line_end.is_null() {
            end = memchr(
                hdbuf as *const libc::c_void,
                ' ' as i32,
                line_end.offset_from(hdbuf) as i64 as u64,
            ) as *mut i8;
            if !(end.is_null() || end == hdbuf) {
                let fresh47 = &mut ((*nva.offset(0 as i32 as isize)).name);
                *fresh47 = b":method\0" as *const u8 as *const i8
                    as *mut u8;
                (*nva.offset(0 as i32 as isize))
                    .namelen = strlen(
                    (*nva.offset(0 as i32 as isize)).name as *mut i8,
                );
                let fresh48 = &mut ((*nva.offset(0 as i32 as isize)).value);
                *fresh48 = hdbuf as *mut u8;
                (*nva.offset(0 as i32 as isize))
                    .valuelen = end.offset_from(hdbuf) as i64 as size_t;
                (*nva.offset(0 as i32 as isize))
                    .flags = NGHTTP2_NV_FLAG_NONE as i32 as uint8_t;
                if (*nva.offset(0 as i32 as isize)).namelen
                    > 0xffff as i32 as u64
                    || (*nva.offset(0 as i32 as isize)).valuelen
                        > (0xffff as i32 as u64)
                            .wrapping_sub(
                                (*nva.offset(0 as i32 as isize)).namelen,
                            )
                {
                    Curl_failf(
                        data,
                        b"Failed sending HTTP request: Header overflow\0" as *const u8
                            as *const i8,
                    );
                } else {
                    hdbuf = end.offset(1 as i32 as isize);
                    end = 0 as *mut i8;
                    i = line_end.offset_from(hdbuf) as i64 as size_t;
                    while i != 0 {
                        if *hdbuf
                            .offset(
                                i.wrapping_sub(1 as i32 as u64) as isize,
                            ) as i32 == ' ' as i32
                        {
                            end = &mut *hdbuf
                                .offset(
                                    i.wrapping_sub(1 as i32 as u64) as isize,
                                ) as *mut i8;
                            break;
                        } else {
                            i = i.wrapping_sub(1);
                        }
                    }
                    if !(end.is_null() || end == hdbuf) {
                        let fresh49 = &mut ((*nva.offset(1 as i32 as isize))
                            .name);
                        *fresh49 = b":path\0" as *const u8 as *const i8
                            as *mut u8;
                        (*nva.offset(1 as i32 as isize))
                            .namelen = strlen(
                            (*nva.offset(1 as i32 as isize)).name
                                as *mut i8,
                        );
                        let fresh50 = &mut ((*nva.offset(1 as i32 as isize))
                            .value);
                        *fresh50 = hdbuf as *mut u8;
                        (*nva.offset(1 as i32 as isize))
                            .valuelen = end.offset_from(hdbuf) as i64 as size_t;
                        (*nva.offset(1 as i32 as isize))
                            .flags = NGHTTP2_NV_FLAG_NONE as i32 as uint8_t;
                        if (*nva.offset(1 as i32 as isize)).namelen
                            > 0xffff as i32 as u64
                            || (*nva.offset(1 as i32 as isize)).valuelen
                                > (0xffff as i32 as u64)
                                    .wrapping_sub(
                                        (*nva.offset(1 as i32 as isize)).namelen,
                                    )
                        {
                            Curl_failf(
                                data,
                                b"Failed sending HTTP request: Header overflow\0"
                                    as *const u8 as *const i8,
                            );
                        } else {
                            let fresh51 = &mut ((*nva
                                .offset(2 as i32 as isize))
                                .name);
                            *fresh51 = b":scheme\0" as *const u8 as *const i8
                                as *mut u8;
                            (*nva.offset(2 as i32 as isize))
                                .namelen = strlen(
                                (*nva.offset(2 as i32 as isize)).name
                                    as *mut i8,
                            );
                            if (*(*conn).handler).flags
                                & ((1 as i32) << 0 as i32) as u32
                                != 0
                            {
                                let fresh52 = &mut ((*nva
                                    .offset(2 as i32 as isize))
                                    .value);
                                *fresh52 = b"https\0" as *const u8 as *const i8
                                    as *mut u8;
                            } else {
                                let fresh53 = &mut ((*nva
                                    .offset(2 as i32 as isize))
                                    .value);
                                *fresh53 = b"http\0" as *const u8 as *const i8
                                    as *mut u8;
                            }
                            (*nva.offset(2 as i32 as isize))
                                .valuelen = strlen(
                                (*nva.offset(2 as i32 as isize)).value
                                    as *mut i8,
                            );
                            (*nva.offset(2 as i32 as isize))
                                .flags = NGHTTP2_NV_FLAG_NONE as i32 as uint8_t;
                            if (*nva.offset(2 as i32 as isize)).namelen
                                > 0xffff as i32 as u64
                                || (*nva.offset(2 as i32 as isize)).valuelen
                                    > (0xffff as i32 as u64)
                                        .wrapping_sub(
                                            (*nva.offset(2 as i32 as isize)).namelen,
                                        )
                            {
                                Curl_failf(
                                    data,
                                    b"Failed sending HTTP request: Header overflow\0"
                                        as *const u8 as *const i8,
                                );
                            } else {
                                authority_idx = 0 as i32 as size_t;
                                i = 3 as i32 as size_t;
                                loop {
                                    if !(i < nheader) {
                                        current_block = 228501038991332163;
                                        break;
                                    }
                                    let mut hlen: size_t = 0;
                                    hdbuf = line_end.offset(2 as i32 as isize);
                                    line_end = memchr(
                                        hdbuf as *const libc::c_void,
                                        '\r' as i32,
                                        len
                                            .wrapping_sub(
                                                hdbuf.offset_from(mem as *mut i8) as i64
                                                    as u64,
                                            ),
                                    ) as *mut i8;
                                    if line_end.is_null() || line_end == hdbuf {
                                        current_block = 337463635748514786;
                                        break;
                                    }
                                    if *hdbuf as i32 == ' ' as i32
                                        || *hdbuf as i32 == '\t' as i32
                                    {
                                        current_block = 337463635748514786;
                                        break;
                                    }
                                    end = hdbuf;
                                    while end < line_end && *end as i32 != ':' as i32 {
                                        end = end.offset(1);
                                    }
                                    if end == hdbuf || end == line_end {
                                        current_block = 337463635748514786;
                                        break;
                                    }
                                    hlen = end.offset_from(hdbuf) as i64 as size_t;
                                    if hlen == 4 as i32 as u64
                                        && Curl_strncasecompare(
                                            b"host\0" as *const u8 as *const i8,
                                            hdbuf,
                                            4 as i32 as size_t,
                                        ) != 0
                                    {
                                        authority_idx = i;
                                        let fresh54 = &mut ((*nva.offset(i as isize)).name);
                                        *fresh54 = b":authority\0" as *const u8
                                            as *const i8 as *mut u8;
                                        (*nva.offset(i as isize))
                                            .namelen = strlen(
                                            (*nva.offset(i as isize)).name as *mut i8,
                                        );
                                    } else {
                                        (*nva.offset(i as isize))
                                            .namelen = end.offset_from(hdbuf) as i64 as size_t;
                                        Curl_strntolower(
                                            hdbuf,
                                            hdbuf,
                                            (*nva.offset(i as isize)).namelen,
                                        );
                                        let fresh55 = &mut ((*nva.offset(i as isize)).name);
                                        *fresh55 = hdbuf as *mut u8;
                                    }
                                    hdbuf = end.offset(1 as i32 as isize);
                                    while *hdbuf as i32 == ' ' as i32
                                        || *hdbuf as i32 == '\t' as i32
                                    {
                                        hdbuf = hdbuf.offset(1);
                                    }
                                    end = line_end;
                                    match inspect_header(
                                        (*nva.offset(i as isize)).name as *const i8,
                                        (*nva.offset(i as isize)).namelen,
                                        hdbuf,
                                        end.offset_from(hdbuf) as i64 as size_t,
                                    ) as u32
                                    {
                                        1 => {
                                            nheader = nheader.wrapping_sub(1);
                                            continue;
                                        }
                                        2 => {
                                            let fresh56 = &mut ((*nva.offset(i as isize)).value);
                                            *fresh56 = b"trailers\0" as *const u8 as *const i8
                                                as *mut uint8_t;
                                            (*nva.offset(i as isize))
                                                .valuelen = (::std::mem::size_of::<[i8; 9]>()
                                                as u64)
                                                .wrapping_sub(1 as i32 as u64);
                                        }
                                        _ => {
                                            let fresh57 = &mut ((*nva.offset(i as isize)).value);
                                            *fresh57 = hdbuf as *mut u8;
                                            (*nva.offset(i as isize))
                                                .valuelen = end.offset_from(hdbuf) as i64
                                                as size_t;
                                        }
                                    }
                                    (*nva.offset(i as isize))
                                        .flags = NGHTTP2_NV_FLAG_NONE as i32 as uint8_t;
                                    if (*nva.offset(i as isize)).namelen
                                        > 0xffff as i32 as u64
                                        || (*nva.offset(i as isize)).valuelen
                                            > (0xffff as i32 as u64)
                                                .wrapping_sub((*nva.offset(i as isize)).namelen)
                                    {
                                        Curl_failf(
                                            data,
                                            b"Failed sending HTTP request: Header overflow\0"
                                                as *const u8 as *const i8,
                                        );
                                        current_block = 337463635748514786;
                                        break;
                                    } else {
                                        i = i.wrapping_add(1);
                                    }
                                }
                                match current_block {
                                    337463635748514786 => {}
                                    _ => {
                                        if authority_idx != 0
                                            && authority_idx != 3 as i32 as u64
                                        {
                                            let mut authority: nghttp2_nv = *nva
                                                .offset(authority_idx as isize);
                                            i = authority_idx;
                                            while i > 3 as i32 as u64 {
                                                *nva
                                                    .offset(
                                                        i as isize,
                                                    ) = *nva
                                                    .offset(
                                                        i.wrapping_sub(1 as i32 as u64) as isize,
                                                    );
                                                i = i.wrapping_sub(1);
                                            }
                                            *nva.offset(i as isize) = authority;
                                        }
                                        let mut acc: size_t = 0 as i32 as size_t;
                                        i = 0 as i32 as size_t;
                                        while i < nheader {
                                            acc = (acc as u64)
                                                .wrapping_add(
                                                    ((*nva.offset(i as isize)).namelen)
                                                        .wrapping_add((*nva.offset(i as isize)).valuelen),
                                                ) as size_t as size_t;
                                            i = i.wrapping_add(1);
                                        }
                                        if acc > 60000 as i32 as u64 {
                                            Curl_infof(
                                                data,
                                                b"http2_send: Warning: The cumulative length of all headers exceeds %d bytes and that could cause the stream to be rejected.\0"
                                                    as *const u8 as *const i8,
                                                60000 as i32,
                                            );
                                        }
                                        h2_pri_spec(data, &mut pri_spec);
                                        match (*data).state.httpreq as u32 {
                                            1 | 2 | 3 | 4 => {
                                                if (*data).state.infilesize
                                                    != -(1 as i32) as i64
                                                {
                                                    (*stream).upload_left = (*data).state.infilesize;
                                                } else {
                                                    (*stream).upload_left = -(1 as i32) as curl_off_t;
                                                }
                                                data_prd
                                                    .read_callback = Some(
                                                    data_source_read_callback
                                                        as unsafe extern "C" fn(
                                                            *mut nghttp2_session,
                                                            int32_t,
                                                            *mut uint8_t,
                                                            size_t,
                                                            *mut uint32_t,
                                                            *mut nghttp2_data_source,
                                                            *mut libc::c_void,
                                                        ) -> ssize_t,
                                                );
                                                data_prd.source.ptr = 0 as *mut libc::c_void;
                                                stream_id = nghttp2_submit_request(
                                                    h2,
                                                    &mut pri_spec,
                                                    nva,
                                                    nheader,
                                                    &mut data_prd,
                                                    data as *mut libc::c_void,
                                                );
                                            }
                                            _ => {
                                                stream_id = nghttp2_submit_request(
                                                    h2,
                                                    &mut pri_spec,
                                                    nva,
                                                    nheader,
                                                    0 as *const nghttp2_data_provider,
                                                    data as *mut libc::c_void,
                                                );
                                            }
                                        }
                                        Curl_cfree
                                            .expect(
                                                "non-null function pointer",
                                            )(nva as *mut libc::c_void);
                                        nva = 0 as *mut nghttp2_nv;
                                        if stream_id < 0 as i32 {
                                            *err = CURLE_SEND_ERROR;
                                            return -(1 as i32) as ssize_t;
                                        }
                                        Curl_infof(
                                            data,
                                            b"Using Stream ID: %x (easy handle %p)\0" as *const u8
                                                as *const i8,
                                            stream_id,
                                            data as *mut libc::c_void,
                                        );
                                        (*stream).stream_id = stream_id;
                                        rv = h2_session_send(data, h2);
                                        if rv != 0 {
                                            *err = CURLE_SEND_ERROR;
                                            return -(1 as i32) as ssize_t;
                                        }
                                        if should_close_session(httpc) != 0 {
                                            *err = CURLE_HTTP2;
                                            return -(1 as i32) as ssize_t;
                                        }
                                        nghttp2_session_resume_data(h2, (*stream).stream_id);
                                        return len as ssize_t;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Curl_cfree.expect("non-null function pointer")(nva as *mut libc::c_void);
    *err = CURLE_SEND_ERROR;
    return -(1 as i32) as ssize_t;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_setup(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
    let mut stream: *mut HTTP = (*data).req.p.http;
    (*stream).stream_id = -(1 as i32);
    Curl_dyn_init(
        &mut (*stream).header_recvbuf,
        (128 as i32 * 1024 as i32) as size_t,
    );
    Curl_dyn_init(
        &mut (*stream).trailer_recvbuf,
        (128 as i32 * 1024 as i32) as size_t,
    );
    (*stream).upload_left = 0 as i32 as curl_off_t;
    let fresh58 = &mut ((*stream).upload_mem);
    *fresh58 = 0 as *const uint8_t;
    (*stream).upload_len = 0 as i32 as size_t;
    let fresh59 = &mut ((*stream).mem);
    *fresh59 = (*data).state.buffer;
    (*stream).len = (*data).set.buffer_size as size_t;
    multi_connchanged((*data).multi);
    if (*conn).handler == &Curl_handler_http2_ssl as *const Curl_handler
        || (*conn).handler == &Curl_handler_http2 as *const Curl_handler
    {
        return CURLE_OK;
    }
    if (*(*conn).handler).flags
        & ((1 as i32) << 0 as i32) as u32 != 0
    {
        let fresh60 = &mut ((*conn).handler);
        *fresh60 = &Curl_handler_http2_ssl;
    } else {
        let fresh61 = &mut ((*conn).handler);
        *fresh61 = &Curl_handler_http2;
    }
    result = http2_init(data, conn);
    if result as u64 != 0 {
        Curl_dyn_free(&mut (*stream).header_recvbuf);
        return result;
    }
    Curl_infof(
        data,
        b"Using HTTP2, server supports multiplexing\0" as *const u8
            as *const i8,
    );
    let fresh62 = &mut ((*conn).bits);
    (*fresh62).set_multiplex(1 as i32 as bit);
    (*conn).httpversion = 20 as i32 as u8;
    (*(*conn).bundle).multiuse = 2 as i32;
    (*httpc).inbuflen = 0 as i32 as size_t;
    (*httpc).nread_inbuf = 0 as i32 as size_t;
    (*httpc).pause_stream_id = 0 as i32;
    (*httpc).drain_total = 0 as i32 as size_t;
    Curl_infof(
        data,
        b"Connection state changed (HTTP/2 confirmed)\0" as *const u8
            as *const i8,
    );
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_switched(
    mut data: *mut Curl_easy,
    mut mem: *const i8,
    mut nread: size_t,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut httpc: *mut http_conn = &mut (*conn).proto.httpc;
    let mut rv: i32 = 0;
    let mut stream: *mut HTTP = (*data).req.p.http;
    result = Curl_http2_setup(data, conn);
    if result as u64 != 0 {
        return result;
    }
    let fresh63 = &mut ((*httpc).recv_underlying);
    *fresh63 = (*conn).recv[0 as i32 as usize];
    let fresh64 = &mut ((*httpc).send_underlying);
    *fresh64 = (*conn).send[0 as i32 as usize];
    let fresh65 = &mut ((*conn).recv[0 as i32 as usize]);
    *fresh65 = Some(
        http2_recv
            as unsafe extern "C" fn(
                *mut Curl_easy,
                i32,
                *mut i8,
                size_t,
                *mut CURLcode,
            ) -> ssize_t,
    );
    let fresh66 = &mut ((*conn).send[0 as i32 as usize]);
    *fresh66 = Some(
        http2_send
            as unsafe extern "C" fn(
                *mut Curl_easy,
                i32,
                *const libc::c_void,
                size_t,
                *mut CURLcode,
            ) -> ssize_t,
    );
    if (*data).req.upgr101 as u32
        == UPGR101_RECEIVED as i32 as u32
    {
        (*stream).stream_id = 1 as i32;
        rv = nghttp2_session_upgrade2(
            (*httpc).h2,
            ((*httpc).binsettings).as_mut_ptr(),
            (*httpc).binlen,
            ((*data).state.httpreq as u32
                == HTTPREQ_HEAD as i32 as u32) as i32,
            0 as *mut libc::c_void,
        );
        if rv != 0 {
            Curl_failf(
                data,
                b"nghttp2_session_upgrade2() failed: %s(%d)\0" as *const u8
                    as *const i8,
                nghttp2_strerror(rv),
                rv,
            );
            return CURLE_HTTP2;
        }
        rv = nghttp2_session_set_stream_user_data(
            (*httpc).h2,
            (*stream).stream_id,
            data as *mut libc::c_void,
        );
        if rv != 0 {
            Curl_infof(
                data,
                b"http/2: failed to set user_data for stream %d!\0" as *const u8
                    as *const i8,
                (*stream).stream_id,
            );
        }
    } else {
        populate_settings(data, httpc);
        (*stream).stream_id = -(1 as i32);
        rv = nghttp2_submit_settings(
            (*httpc).h2,
            NGHTTP2_FLAG_NONE as i32 as uint8_t,
            ((*httpc).local_settings).as_mut_ptr(),
            (*httpc).local_settings_num,
        );
        if rv != 0 {
            Curl_failf(
                data,
                b"nghttp2_submit_settings() failed: %s(%d)\0" as *const u8
                    as *const i8,
                nghttp2_strerror(rv),
                rv,
            );
            return CURLE_HTTP2;
        }
    }
    rv = nghttp2_session_set_local_window_size(
        (*httpc).h2,
        NGHTTP2_FLAG_NONE as i32 as uint8_t,
        0 as i32,
        32 as i32 * 1024 as i32 * 1024 as i32,
    );
    if rv != 0 {
        Curl_failf(
            data,
            b"nghttp2_session_set_local_window_size() failed: %s(%d)\0" as *const u8
                as *const i8,
            nghttp2_strerror(rv),
            rv,
        );
        return CURLE_HTTP2;
    }
    if (32768 as i32 as u64) < nread {
        Curl_failf(
            data,
            b"connection buffer size is too small to store data following HTTP Upgrade response header: buflen=%d, datalen=%zu\0"
                as *const u8 as *const i8,
            32768 as i32,
            nread,
        );
        return CURLE_HTTP2;
    }
    Curl_infof(
        data,
        b"Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=%zu\0"
            as *const u8 as *const i8,
        nread,
    );
    if nread != 0 {
        memcpy((*httpc).inbuf as *mut libc::c_void, mem as *const libc::c_void, nread);
    }
    (*httpc).inbuflen = nread;
    if -(1 as i32) == h2_process_pending_input(data, httpc, &mut result) {
        return CURLE_HTTP2;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_stream_pause(
    mut data: *mut Curl_easy,
    mut pause: bool,
) -> CURLcode {
    if (*(*(*data).conn).handler).protocol
        & ((1 as i32) << 0 as i32
            | (1 as i32) << 1 as i32) as u32 == 0
        || ((*(*data).conn).proto.httpc.h2).is_null()
    {
        return CURLE_OK
    } else {
        let mut stream: *mut HTTP = (*data).req.p.http;
        let mut httpc: *mut http_conn = &mut (*(*data).conn).proto.httpc;
        let mut window: uint32_t = (!pause as i32
            * (32 as i32 * 1024 as i32 * 1024 as i32))
            as uint32_t;
        let mut rv: i32 = nghttp2_session_set_local_window_size(
            (*httpc).h2,
            NGHTTP2_FLAG_NONE as i32 as uint8_t,
            (*stream).stream_id,
            window as int32_t,
        );
        if rv != 0 {
            Curl_failf(
                data,
                b"nghttp2_session_set_local_window_size() failed: %s(%d)\0" as *const u8
                    as *const i8,
                nghttp2_strerror(rv),
                rv,
            );
            return CURLE_HTTP2;
        }
        rv = h2_session_send(data, (*httpc).h2);
        if rv != 0 {
            return CURLE_SEND_ERROR;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_add_child(
    mut parent: *mut Curl_easy,
    mut child: *mut Curl_easy,
    mut exclusive: bool,
) -> CURLcode {
    if !parent.is_null() {
        let mut tail: *mut *mut Curl_http2_dep = 0 as *mut *mut Curl_http2_dep;
        let mut dep: *mut Curl_http2_dep = Curl_ccalloc
            .expect(
                "non-null function pointer",
            )(
            1 as i32 as size_t,
            ::std::mem::size_of::<Curl_http2_dep>() as u64,
        ) as *mut Curl_http2_dep;
        if dep.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        let fresh67 = &mut ((*dep).data);
        *fresh67 = child;
        if !((*parent).set.stream_dependents).is_null() && exclusive as i32 != 0
        {
            let mut node: *mut Curl_http2_dep = (*parent).set.stream_dependents;
            while !node.is_null() {
                let fresh68 = &mut ((*(*node).data).set.stream_depends_on);
                *fresh68 = child;
                node = (*node).next;
            }
            tail = &mut (*child).set.stream_dependents;
            while !(*tail).is_null() {
                tail = &mut (**tail).next;
            }
            *tail = (*parent).set.stream_dependents;
            let fresh69 = &mut ((*parent).set.stream_dependents);
            *fresh69 = 0 as *mut Curl_http2_dep;
        }
        tail = &mut (*parent).set.stream_dependents;
        while !(*tail).is_null() {
            let fresh70 = &mut ((*(**tail).data).set);
            (*fresh70).set_stream_depends_e(0 as i32 as bit);
            tail = &mut (**tail).next;
        }
        *tail = dep;
    }
    let fresh71 = &mut ((*child).set.stream_depends_on);
    *fresh71 = parent;
    let fresh72 = &mut ((*child).set);
    (*fresh72).set_stream_depends_e(exclusive as bit);
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_remove_child(
    mut parent: *mut Curl_easy,
    mut child: *mut Curl_easy,
) {
    let mut last: *mut Curl_http2_dep = 0 as *mut Curl_http2_dep;
    let mut data: *mut Curl_http2_dep = (*parent).set.stream_dependents;
    while !data.is_null() && (*data).data != child {
        last = data;
        data = (*data).next;
    }
    if !data.is_null() {
        if !last.is_null() {
            let fresh73 = &mut ((*last).next);
            *fresh73 = (*data).next;
        } else {
            let fresh74 = &mut ((*parent).set.stream_dependents);
            *fresh74 = (*data).next;
        }
        Curl_cfree.expect("non-null function pointer")(data as *mut libc::c_void);
    }
    let fresh75 = &mut ((*child).set.stream_depends_on);
    *fresh75 = 0 as *mut Curl_easy;
    let fresh76 = &mut ((*child).set);
    (*fresh76).set_stream_depends_e(0 as i32 as bit);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_cleanup_dependencies(mut data: *mut Curl_easy) {
    while !((*data).set.stream_dependents).is_null() {
        let mut tmp: *mut Curl_easy = (*(*data).set.stream_dependents).data;
        Curl_http2_remove_child(data, tmp);
        if !((*data).set.stream_depends_on).is_null() {
            Curl_http2_add_child(
                (*data).set.stream_depends_on,
                tmp,
                0 as i32 != 0,
            );
        }
    }
    if !((*data).set.stream_depends_on).is_null() {
        Curl_http2_remove_child((*data).set.stream_depends_on, data);
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_h2_http_1_1_error(mut data: *mut Curl_easy) -> bool {
    let mut stream: *mut HTTP = (*data).req.p.http;
    return (*stream).error == NGHTTP2_HTTP_1_1_REQUIRED as i32 as u32;
}
