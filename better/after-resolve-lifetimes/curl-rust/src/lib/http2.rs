use ::libc;
use ::c2rust_bitfields;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    pub type nghttp2_session_callbacks;
    
    fn strlen(_: * const i8) -> u64;
    fn strncmp(
        _: * const i8,
        _: * const i8,
        _: u64,
    ) -> i32;
    fn strchr(_: * const i8, _: i32) -> * mut i8;
    fn strcmp(_: * const i8, _: * const i8) -> i32;
    
    
    
    
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
    fn memcmp(
        _: * const core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> i32;
    fn memchr(
        _: * const core::ffi::c_void,
        _: i32,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn nghttp2_session_get_remote_settings(
        session: * mut crate::src::lib::speedcheck::nghttp2_session,
        id: u32,
    ) -> u32;
    fn nghttp2_session_upgrade2(
        session: * mut crate::src::lib::speedcheck::nghttp2_session,
        settings_payload: * const u8,
        settings_payloadlen: u64,
        head_request: i32,
        stream_user_data: * mut core::ffi::c_void,
    ) -> i32;
    fn nghttp2_pack_settings_payload(
        buf: * mut u8,
        buflen: u64,
        iv: * const crate::src::lib::http2::nghttp2_settings_entry,
        niv: u64,
    ) -> i64;
    fn nghttp2_strerror(lib_error_code: i32) -> * const i8;
    fn nghttp2_http2_strerror(error_code: u32) -> * const i8;
    fn nghttp2_priority_spec_init(
        pri_spec: * mut crate::src::lib::http2::nghttp2_priority_spec,
        stream_id: i32,
        weight: i32,
        exclusive: i32,
    );
    fn nghttp2_submit_request(
        session: * mut crate::src::lib::speedcheck::nghttp2_session,
        pri_spec: * const crate::src::lib::http2::nghttp2_priority_spec,
        nva: * const crate::src::lib::http2::nghttp2_nv,
        nvlen: u64,
        data_prd: * const crate::src::lib::http2::nghttp2_data_provider,
        stream_user_data: * mut core::ffi::c_void,
    ) -> i32;
    fn nghttp2_session_want_write(session: * mut crate::src::lib::speedcheck::nghttp2_session) -> i32;
    fn nghttp2_submit_priority(
        session: * mut crate::src::lib::speedcheck::nghttp2_session,
        flags: u8,
        stream_id: i32,
        pri_spec: * const crate::src::lib::http2::nghttp2_priority_spec,
    ) -> i32;
    fn nghttp2_submit_rst_stream(
        session: * mut crate::src::lib::speedcheck::nghttp2_session,
        flags: u8,
        stream_id: i32,
        error_code: u32,
    ) -> i32;
    fn nghttp2_submit_settings(
        session: * mut crate::src::lib::speedcheck::nghttp2_session,
        flags: u8,
        iv: * const crate::src::lib::http2::nghttp2_settings_entry,
        niv: u64,
    ) -> i32;
    fn nghttp2_submit_ping(
        session: * mut crate::src::lib::speedcheck::nghttp2_session,
        flags: u8,
        opaque_data: * const u8,
    ) -> i32;
    fn nghttp2_session_check_request_allowed(
        session: * mut crate::src::lib::speedcheck::nghttp2_session,
    ) -> i32;
    fn nghttp2_session_set_local_window_size(
        session: * mut crate::src::lib::speedcheck::nghttp2_session,
        flags: u8,
        stream_id: i32,
        window_size: i32,
    ) -> i32;
    fn nghttp2_version(least_version: i32) -> * mut crate::src::lib::http2::nghttp2_info;
    fn nghttp2_is_fatal(lib_error_code: i32) -> i32;
    fn nghttp2_session_want_read(session: * mut crate::src::lib::speedcheck::nghttp2_session) -> i32;
    fn nghttp2_session_resume_data(
        session: * mut crate::src::lib::speedcheck::nghttp2_session,
        stream_id: i32,
    ) -> i32;
    fn nghttp2_session_mem_recv(
        session: * mut crate::src::lib::speedcheck::nghttp2_session,
        in_0: * const u8,
        inlen: u64,
    ) -> i64;
    fn nghttp2_session_send(session: * mut crate::src::lib::speedcheck::nghttp2_session) -> i32;
    fn nghttp2_session_del(session: * mut crate::src::lib::speedcheck::nghttp2_session);
    fn nghttp2_session_client_new(
        session_ptr: * mut * mut crate::src::lib::speedcheck::nghttp2_session,
        callbacks: * const crate::src::lib::http2::nghttp2_session_callbacks,
        user_data: * mut core::ffi::c_void,
    ) -> i32;
    fn nghttp2_session_callbacks_set_error_callback(
        cbs: * mut crate::src::lib::http2::nghttp2_session_callbacks,
        error_callback_0: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::speedcheck::nghttp2_session,_: * const i8,_: u64,_: * mut core::ffi::c_void,) -> i32>,
    );
    fn nghttp2_session_get_stream_user_data(
        session: * mut crate::src::lib::speedcheck::nghttp2_session,
        stream_id: i32,
    ) -> * mut core::ffi::c_void;
    fn nghttp2_session_set_stream_user_data(
        session: * mut crate::src::lib::speedcheck::nghttp2_session,
        stream_id: i32,
        stream_user_data: * mut core::ffi::c_void,
    ) -> i32;
    fn nghttp2_session_callbacks_new(
        callbacks_ptr: * mut * mut crate::src::lib::http2::nghttp2_session_callbacks,
    ) -> i32;
    fn nghttp2_session_callbacks_del(callbacks: * mut crate::src::lib::http2::nghttp2_session_callbacks);
    fn nghttp2_session_callbacks_set_send_callback(
        cbs: * mut crate::src::lib::http2::nghttp2_session_callbacks,
        send_callback_0: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::speedcheck::nghttp2_session,_: * const u8,_: u64,_: i32,_: * mut core::ffi::c_void,) -> i64>,
    );
    fn nghttp2_session_callbacks_set_on_frame_recv_callback(
        cbs: * mut crate::src::lib::http2::nghttp2_session_callbacks,
        on_frame_recv_callback: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::speedcheck::nghttp2_session,_: * const crate::src::lib::http2::nghttp2_frame,_: * mut core::ffi::c_void,) -> i32>,
    );
    fn nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        cbs: * mut crate::src::lib::http2::nghttp2_session_callbacks,
        on_data_chunk_recv_callback: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::speedcheck::nghttp2_session,_: u8,_: i32,_: * const u8,_: u64,_: * mut core::ffi::c_void,) -> i32>,
    );
    fn nghttp2_session_callbacks_set_on_stream_close_callback(
        cbs: * mut crate::src::lib::http2::nghttp2_session_callbacks,
        on_stream_close_callback: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::speedcheck::nghttp2_session,_: i32,_: u32,_: * mut core::ffi::c_void,) -> i32>,
    );
    fn nghttp2_session_callbacks_set_on_begin_headers_callback(
        cbs: * mut crate::src::lib::http2::nghttp2_session_callbacks,
        on_begin_headers_callback: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::speedcheck::nghttp2_session,_: * const crate::src::lib::http2::nghttp2_frame,_: * mut core::ffi::c_void,) -> i32>,
    );
    fn nghttp2_session_callbacks_set_on_header_callback(
        cbs: * mut crate::src::lib::http2::nghttp2_session_callbacks,
        on_header_callback: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::speedcheck::nghttp2_session,_: * const crate::src::lib::http2::nghttp2_frame,_: * const u8,_: u64,_: * const u8,_: u64,_: u8,_: * mut core::ffi::c_void,) -> i32>,
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
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::ftp::http_connect_state;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: u16,
    pub sa_data: [i8; 14],
}
impl sockaddr {
    pub const fn new() -> Self {
        sockaddr {
        sa_family: 0,
        sa_data: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,]
        }
    }
}

impl std::default::Default for sockaddr {
    fn default() -> Self { sockaddr::new() }
}

pub type curl_socklen_t = u32;
pub type curl_off_t = i64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: i32,
    pub _IO_read_ptr: * mut i8,
    pub _IO_read_end: * mut i8,
    pub _IO_read_base: * mut i8,
    pub _IO_write_base: * mut i8,
    pub _IO_write_ptr: * mut i8,
    pub _IO_write_end: * mut i8,
    pub _IO_buf_base: * mut i8,
    pub _IO_buf_end: * mut i8,
    pub _IO_save_base: * mut i8,
    pub _IO_backup_base: * mut i8,
    pub _IO_save_end: * mut i8,
    pub _markers: * mut crate::src::src::tool_msgs::_IO_marker,
    pub _chain: * mut crate::src::lib::http2::_IO_FILE,
    pub _fileno: i32,
    pub _flags2: i32,
    pub _old_offset: i64,
    pub _cur_column: u16,
    pub _vtable_offset: i8,
    pub _shortbuf: [i8; 1],
    pub _lock: * mut core::ffi::c_void,
    pub _offset: i64,
    pub _codecvt: * mut crate::src::lib::mqtt::_IO_codecvt,
    pub _wide_data: * mut crate::src::src::tool_cb_rea::_IO_wide_data,
    pub _freeres_list: * mut crate::src::lib::http2::_IO_FILE,
    pub _freeres_buf: * mut core::ffi::c_void,
    pub __pad5: u64,
    pub _mode: i32,
    pub _unused2: [i8; 20],
}
impl _IO_FILE {
    pub const fn new() -> Self {
        _IO_FILE {
        _flags: 0,
        _IO_read_ptr: (0 as * mut i8),
        _IO_read_end: (0 as * mut i8),
        _IO_read_base: (0 as * mut i8),
        _IO_write_base: (0 as * mut i8),
        _IO_write_ptr: (0 as * mut i8),
        _IO_write_end: (0 as * mut i8),
        _IO_buf_base: (0 as * mut i8),
        _IO_buf_end: (0 as * mut i8),
        _IO_save_base: (0 as * mut i8),
        _IO_backup_base: (0 as * mut i8),
        _IO_save_end: (0 as * mut i8),
        _markers: (0 as * mut crate::src::src::tool_msgs::_IO_marker),
        _chain: (0 as * mut crate::src::lib::http2::_IO_FILE),
        _fileno: 0,
        _flags2: 0,
        _old_offset: 0,
        _cur_column: 0,
        _vtable_offset: 0,
        _shortbuf: [0,],
        _lock: (0 as * mut core::ffi::c_void),
        _offset: 0,
        _codecvt: (0 as * mut crate::src::lib::mqtt::_IO_codecvt),
        _wide_data: (0 as * mut crate::src::src::tool_cb_rea::_IO_wide_data),
        _freeres_list: (0 as * mut crate::src::lib::http2::_IO_FILE),
        _freeres_buf: (0 as * mut core::ffi::c_void),
        __pad5: 0,
        _mode: 0,
        _unused2: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,]
        }
    }
}

impl std::default::Default for _IO_FILE {
    fn default() -> Self { _IO_FILE::new() }
}

pub type _IO_lock_t = ();
pub type FILE = crate::src::lib::http2::_IO_FILE;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_easy {
    pub magic: u32,
    pub next: * mut crate::src::lib::http2::Curl_easy,
    pub prev: * mut crate::src::lib::http2::Curl_easy,
    pub conn: * mut crate::src::lib::http2::connectdata,
    pub connect_queue: crate::src::lib::http2::Curl_llist_element,
    pub conn_queue: crate::src::lib::http2::Curl_llist_element,
    pub mstate: u32,
    pub result: u32,
    pub msg: crate::src::lib::http2::Curl_message,
    pub sockets: [i32; 5],
    pub actions: [u8; 5],
    pub numsocks: i32,
    pub dns: crate::src::lib::http2::Names,
    pub multi: * mut crate::src::lib::http2::Curl_multi,
    pub multi_easy: * mut crate::src::lib::http2::Curl_multi,
    pub share: * mut crate::src::lib::asyn_thread::Curl_share,
    pub psl: * mut crate::src::lib::http2::PslCache,
    pub req: crate::src::lib::http2::SingleRequest,
    pub set: crate::src::lib::http2::UserDefined,
    pub cookies: * mut crate::src::lib::http2::CookieInfo,
    pub hsts: * mut crate::src::lib::easy::hsts,
    pub asi: * mut crate::src::lib::altsvc::altsvcinfo,
    pub progress: crate::src::lib::http2::Progress,
    pub state: crate::src::lib::http2::UrlState,
    pub wildcard: crate::src::lib::http2::WildcardData,
    pub info: crate::src::lib::http2::PureInfo,
    pub tsi: crate::src::lib::http2::curl_tlssessioninfo,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_tlssessioninfo {
    pub backend: u32,
    pub internals: * mut core::ffi::c_void,
}
impl curl_tlssessioninfo {
    pub const fn new() -> Self {
        curl_tlssessioninfo {
        backend: 0,
        internals: (0 as * mut core::ffi::c_void)
        }
    }
}

impl std::default::Default for curl_tlssessioninfo {
    fn default() -> Self { curl_tlssessioninfo::new() }
}

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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PureInfo {
    pub httpcode: i32,
    pub httpproxycode: i32,
    pub httpversion: i32,
    pub filetime: i64,
    pub header_size: i64,
    pub request_size: i64,
    pub proxyauthavail: u64,
    pub httpauthavail: u64,
    pub numconnects: i64,
    pub contenttype: * mut i8,
    pub wouldredirect: * mut i8,
    pub retry_after: i64,
    pub conn_primary_ip: [i8; 46],
    pub conn_primary_port: i32,
    pub conn_local_ip: [i8; 46],
    pub conn_local_port: i32,
    pub conn_scheme: * const i8,
    pub conn_protocol: u32,
    pub certs: crate::src::lib::http2::curl_certinfo,
    pub pxcode: u32,
    // #[bitfield(name = "timecond", ty = "bit", bits = "0..=0")]
    pub timecond: [u8; 1],
    // #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
impl PureInfo {
    pub const fn new() -> Self {
        PureInfo {
        httpcode: 0,
        httpproxycode: 0,
        httpversion: 0,
        filetime: 0,
        header_size: 0,
        request_size: 0,
        proxyauthavail: 0,
        httpauthavail: 0,
        numconnects: 0,
        contenttype: (0 as * mut i8),
        wouldredirect: (0 as * mut i8),
        retry_after: 0,
        conn_primary_ip: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],
        conn_primary_port: 0,
        conn_local_ip: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],
        conn_local_port: 0,
        conn_scheme: (0 as * const i8),
        conn_protocol: 0,
        certs: crate::src::lib::http2::curl_certinfo::new(),
        pxcode: 0,
        timecond: [0,],
        c2rust_padding: [0,0,0,]
        }
    }
}

impl std::default::Default for PureInfo {
    fn default() -> Self { PureInfo::new() }
}

impl PureInfo {
    /// This method allows you to write to a bitfield with a value
    pub fn set_timecond(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.timecond;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn timecond(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.timecond;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_certinfo {
    pub num_of_certs: i32,
    pub certinfo: * mut * mut crate::src::lib::http2::curl_slist,
}
impl curl_certinfo {
    pub const fn new() -> Self {
        curl_certinfo {
        num_of_certs: 0,
        certinfo: (0 as * mut * mut crate::src::lib::http2::curl_slist)
        }
    }
}

impl std::default::Default for curl_certinfo {
    fn default() -> Self { curl_certinfo::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_slist {
    pub data: * mut i8,
    pub next: * mut crate::src::lib::http2::curl_slist,
}
impl curl_slist {
    pub const fn new() -> Self {
        curl_slist {
        data: (0 as * mut i8),
        next: (0 as * mut crate::src::lib::http2::curl_slist)
        }
    }
}

impl std::default::Default for curl_slist {
    fn default() -> Self { curl_slist::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct WildcardData {
    pub state: u32,
    pub path: * mut i8,
    pub pattern: * mut i8,
    pub filelist: crate::src::lib::http2::Curl_llist,
    pub protdata: * mut core::ffi::c_void,
    pub dtor: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>,
    pub customptr: * mut core::ffi::c_void,
}
impl WildcardData {
    pub const fn new() -> Self {
        WildcardData {
        state: 0,
        path: (0 as * mut i8),
        pattern: (0 as * mut i8),
        filelist: crate::src::lib::http2::Curl_llist::new(),
        protdata: (0 as * mut core::ffi::c_void),
        dtor: None,
        customptr: (0 as * mut core::ffi::c_void)
        }
    }
}

impl std::default::Default for WildcardData {
    fn default() -> Self { WildcardData::new() }
}

pub type wildcard_dtor<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_llist {
    pub head: * mut crate::src::lib::http2::Curl_llist_element,
    pub tail: * mut crate::src::lib::http2::Curl_llist_element,
    pub dtor: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut core::ffi::c_void,) -> ()>,
    pub size: u64,
}
impl Curl_llist {
    pub const fn new() -> Self {
        Curl_llist {
        head: (0 as * mut crate::src::lib::http2::Curl_llist_element),
        tail: (0 as * mut crate::src::lib::http2::Curl_llist_element),
        dtor: None,
        size: 0
        }
    }
}

impl std::default::Default for Curl_llist {
    fn default() -> Self { Curl_llist::new() }
}

pub type Curl_llist_dtor<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: Option<&'a2 mut core::ffi::c_void>,) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_llist_element {
    pub ptr: * mut core::ffi::c_void,
    pub prev: * mut crate::src::lib::http2::Curl_llist_element,
    pub next: * mut crate::src::lib::http2::Curl_llist_element,
}
impl Curl_llist_element {
    pub const fn new() -> Self {
        Curl_llist_element {
        ptr: (0 as * mut core::ffi::c_void),
        prev: (0 as * mut crate::src::lib::http2::Curl_llist_element),
        next: (0 as * mut crate::src::lib::http2::Curl_llist_element)
        }
    }
}

impl std::default::Default for Curl_llist_element {
    fn default() -> Self { Curl_llist_element::new() }
}

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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct UrlState {
    pub conn_cache: * mut crate::src::lib::http2::conncache,
    pub keeps_speed: crate::src::lib::http2::curltime,
    pub lastconnect_id: i64,
    pub headerb: crate::src::lib::http2::dynbuf,
    pub buffer: * mut i8,
    pub ulbuf: * mut i8,
    pub current_speed: i64,
    pub first_host: * mut i8,
    pub retrycount: i32,
    pub first_remote_port: i32,
    pub session: * mut crate::src::lib::http2::Curl_ssl_session,
    pub sessionage: i64,
    pub tempwrite: [crate::src::lib::http2::tempbuf; 3],
    pub tempcount: u32,
    pub os_errno: i32,
    pub scratch: * mut i8,
    pub followlocation: i64,
    pub prev_signal: Option<unsafe extern "C"  fn(_: i32,) -> ()>,
    pub digest: crate::src::lib::http2::digestdata,
    pub proxydigest: crate::src::lib::http2::digestdata,
    pub authhost: crate::src::lib::http2::auth,
    pub authproxy: crate::src::lib::http2::auth,
    pub async_0: crate::src::lib::http2::Curl_async,
    pub engine: * mut core::ffi::c_void,
    pub expiretime: crate::src::lib::http2::curltime,
    pub timenode: crate::src::lib::http2::Curl_tree,
    pub timeoutlist: crate::src::lib::http2::Curl_llist,
    pub expires: [crate::src::lib::http2::time_node; 13],
    pub most_recent_ftp_entrypath: * mut i8,
    pub httpwant: u8,
    pub httpversion: u8,
    // #[bitfield(name = "prev_block_had_trailing_cr", ty = "bit", bits = "0..=0")]
    pub prev_block_had_trailing_cr: [u8; 1],
    // #[bitfield(padding)]
    pub c2rust_padding: [u8; 5],
    pub crlf_conversions: i64,
    pub range: * mut i8,
    pub resume_from: i64,
    pub rtsp_next_client_CSeq: i64,
    pub rtsp_next_server_CSeq: i64,
    pub rtsp_CSeq_recv: i64,
    pub infilesize: i64,
    pub drain: u64,
    pub fread_func: Option<unsafe extern "C"  fn(_: * mut i8,_: u64,_: u64,_: * mut core::ffi::c_void,) -> u64>,
    pub in_0: * mut core::ffi::c_void,
    pub stream_depends_on: * mut crate::src::lib::http2::Curl_easy,
    pub stream_weight: i32,
    pub uh: * mut crate::src::lib::urlapi::Curl_URL,
    pub up: crate::src::lib::http2::urlpieces,
    pub httpreq: u32,
    pub url: * mut i8,
    pub referer: * mut i8,
    pub cookielist: * mut crate::src::lib::http2::curl_slist,
    pub resolve: * mut crate::src::lib::http2::curl_slist,
    pub trailers_bytes_sent: u64,
    pub trailers_buf: crate::src::lib::http2::dynbuf,
    pub trailers_state: u32,
    pub aptr: crate::src::lib::http2::dynamically_allocated_data,
    // #[bitfield(name = "multi_owned_by_easy", ty = "bit", bits = "0..=0")]
    // #[bitfield(name = "this_is_a_follow", ty = "bit", bits = "1..=1")]
    // #[bitfield(name = "refused_stream", ty = "bit", bits = "2..=2")]
    // #[bitfield(name = "errorbuf", ty = "bit", bits = "3..=3")]
    // #[bitfield(name = "allow_port", ty = "bit", bits = "4..=4")]
    // #[bitfield(name = "authproblem", ty = "bit", bits = "5..=5")]
    // #[bitfield(name = "ftp_trying_alternative", ty = "bit", bits = "6..=6")]
    // #[bitfield(name = "wildcardmatch", ty = "bit", bits = "7..=7")]
    // #[bitfield(name = "expect100header", ty = "bit", bits = "8..=8")]
    // #[bitfield(name = "disableexpect", ty = "bit", bits = "9..=9")]
    // #[bitfield(name = "use_range", ty = "bit", bits = "10..=10")]
    // #[bitfield(name = "rangestringalloc", ty = "bit", bits = "11..=11")]
    // #[bitfield(name = "done", ty = "bit", bits = "12..=12")]
    // #[bitfield(name = "stream_depends_e", ty = "bit", bits = "13..=13")]
    // #[bitfield(name = "previouslypending", ty = "bit", bits = "14..=14")]
    // #[bitfield(name = "cookie_engine", ty = "bit", bits = "15..=15")]
    // #[bitfield(name = "prefer_ascii", ty = "bit", bits = "16..=16")]
    // #[bitfield(name = "list_only", ty = "bit", bits = "17..=17")]
    // #[bitfield(name = "url_alloc", ty = "bit", bits = "18..=18")]
    // #[bitfield(name = "referer_alloc", ty = "bit", bits = "19..=19")]
    // #[bitfield(name = "wildcard_resolve", ty = "bit", bits = "20..=20")]
    pub multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve: [u8; 3],
    // #[bitfield(padding)]
    pub c2rust_padding_0: [u8; 5],
}
impl UrlState {
    pub const fn new() -> Self {
        UrlState {
        conn_cache: (0 as * mut crate::src::lib::http2::conncache),
        keeps_speed: crate::src::lib::http2::curltime::new(),
        lastconnect_id: 0,
        headerb: crate::src::lib::http2::dynbuf::new(),
        buffer: (0 as * mut i8),
        ulbuf: (0 as * mut i8),
        current_speed: 0,
        first_host: (0 as * mut i8),
        retrycount: 0,
        first_remote_port: 0,
        session: (0 as * mut crate::src::lib::http2::Curl_ssl_session),
        sessionage: 0,
        tempwrite: [crate::src::lib::http2::tempbuf::new(),crate::src::lib::http2::tempbuf::new(),crate::src::lib::http2::tempbuf::new(),],
        tempcount: 0,
        os_errno: 0,
        scratch: (0 as * mut i8),
        followlocation: 0,
        prev_signal: None,
        digest: crate::src::lib::http2::digestdata::new(),
        proxydigest: crate::src::lib::http2::digestdata::new(),
        authhost: crate::src::lib::http2::auth::new(),
        authproxy: crate::src::lib::http2::auth::new(),
        async_0: crate::src::lib::http2::Curl_async::new(),
        engine: (0 as * mut core::ffi::c_void),
        expiretime: crate::src::lib::http2::curltime::new(),
        timenode: crate::src::lib::http2::Curl_tree::new(),
        timeoutlist: crate::src::lib::http2::Curl_llist::new(),
        expires: [crate::src::lib::http2::time_node::new(),crate::src::lib::http2::time_node::new(),crate::src::lib::http2::time_node::new(),crate::src::lib::http2::time_node::new(),crate::src::lib::http2::time_node::new(),crate::src::lib::http2::time_node::new(),crate::src::lib::http2::time_node::new(),crate::src::lib::http2::time_node::new(),crate::src::lib::http2::time_node::new(),crate::src::lib::http2::time_node::new(),crate::src::lib::http2::time_node::new(),crate::src::lib::http2::time_node::new(),crate::src::lib::http2::time_node::new(),],
        most_recent_ftp_entrypath: (0 as * mut i8),
        httpwant: 0,
        httpversion: 0,
        prev_block_had_trailing_cr: [0,],
        c2rust_padding: [0,0,0,0,0,],
        crlf_conversions: 0,
        range: (0 as * mut i8),
        resume_from: 0,
        rtsp_next_client_CSeq: 0,
        rtsp_next_server_CSeq: 0,
        rtsp_CSeq_recv: 0,
        infilesize: 0,
        drain: 0,
        fread_func: None,
        in_0: (0 as * mut core::ffi::c_void),
        stream_depends_on: (0 as * mut crate::src::lib::http2::Curl_easy),
        stream_weight: 0,
        uh: (0 as * mut crate::src::lib::urlapi::Curl_URL),
        up: crate::src::lib::http2::urlpieces::new(),
        httpreq: 0,
        url: (0 as * mut i8),
        referer: (0 as * mut i8),
        cookielist: (0 as * mut crate::src::lib::http2::curl_slist),
        resolve: (0 as * mut crate::src::lib::http2::curl_slist),
        trailers_bytes_sent: 0,
        trailers_buf: crate::src::lib::http2::dynbuf::new(),
        trailers_state: 0,
        aptr: crate::src::lib::http2::dynamically_allocated_data::new(),
        multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve: [0,0,0,],
        c2rust_padding_0: [0,0,0,0,0,]
        }
    }
}

impl std::default::Default for UrlState {
    fn default() -> Self { UrlState::new() }
}

impl UrlState {
    /// This method allows you to write to a bitfield with a value
    pub fn set_prev_block_had_trailing_cr(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.prev_block_had_trailing_cr;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn prev_block_had_trailing_cr(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.prev_block_had_trailing_cr;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_multi_owned_by_easy(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn multi_owned_by_easy(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_this_is_a_follow(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn this_is_a_follow(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_refused_stream(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (2usize, 2usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn refused_stream(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (2usize, 2usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_errorbuf(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (3usize, 3usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn errorbuf(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (3usize, 3usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_allow_port(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (4usize, 4usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn allow_port(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (4usize, 4usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_authproblem(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (5usize, 5usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn authproblem(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (5usize, 5usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ftp_trying_alternative(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (6usize, 6usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ftp_trying_alternative(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (6usize, 6usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_wildcardmatch(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (7usize, 7usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn wildcardmatch(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (7usize, 7usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_expect100header(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (8usize, 8usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn expect100header(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (8usize, 8usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_disableexpect(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (9usize, 9usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn disableexpect(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (9usize, 9usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_use_range(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (10usize, 10usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn use_range(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (10usize, 10usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_rangestringalloc(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (11usize, 11usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn rangestringalloc(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (11usize, 11usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_done(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (12usize, 12usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn done(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (12usize, 12usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_stream_depends_e(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (13usize, 13usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn stream_depends_e(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (13usize, 13usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_previouslypending(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (14usize, 14usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn previouslypending(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (14usize, 14usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_cookie_engine(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (15usize, 15usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn cookie_engine(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (15usize, 15usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_prefer_ascii(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (16usize, 16usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn prefer_ascii(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (16usize, 16usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_list_only(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (17usize, 17usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn list_only(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (17usize, 17usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_url_alloc(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (18usize, 18usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn url_alloc(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (18usize, 18usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_referer_alloc(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (19usize, 19usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn referer_alloc(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (19usize, 19usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_wildcard_resolve(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (20usize, 20usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn wildcard_resolve(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve;
        let (lhs_bit, rhs_bit) = (20usize, 20usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dynamically_allocated_data {
    pub proxyuserpwd: * mut i8,
    pub uagent: * mut i8,
    pub accept_encoding: * mut i8,
    pub userpwd: * mut i8,
    pub rangeline: * mut i8,
    pub ref_0: * mut i8,
    pub host: * mut i8,
    pub cookiehost: * mut i8,
    pub rtsp_transport: * mut i8,
    pub te: * mut i8,
    pub user: * mut i8,
    pub passwd: * mut i8,
    pub proxyuser: * mut i8,
    pub proxypasswd: * mut i8,
}
impl dynamically_allocated_data {
    pub const fn new() -> Self {
        dynamically_allocated_data {
        proxyuserpwd: (0 as * mut i8),
        uagent: (0 as * mut i8),
        accept_encoding: (0 as * mut i8),
        userpwd: (0 as * mut i8),
        rangeline: (0 as * mut i8),
        ref_0: (0 as * mut i8),
        host: (0 as * mut i8),
        cookiehost: (0 as * mut i8),
        rtsp_transport: (0 as * mut i8),
        te: (0 as * mut i8),
        user: (0 as * mut i8),
        passwd: (0 as * mut i8),
        proxyuser: (0 as * mut i8),
        proxypasswd: (0 as * mut i8)
        }
    }
}

impl std::default::Default for dynamically_allocated_data {
    fn default() -> Self { dynamically_allocated_data::new() }
}

pub type trailers_state = u32;
pub const TRAILERS_DONE: trailers_state = 3;
pub const TRAILERS_SENDING: trailers_state = 2;
pub const TRAILERS_INITIALIZED: trailers_state = 1;
pub const TRAILERS_NONE: trailers_state = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dynbuf {
    pub bufr: * mut i8,
    pub leng: u64,
    pub allc: u64,
    pub toobig: u64,
}
impl dynbuf {
    pub const fn new() -> Self {
        dynbuf {
        bufr: (0 as * mut i8),
        leng: 0,
        allc: 0,
        toobig: 0
        }
    }
}

impl std::default::Default for dynbuf {
    fn default() -> Self { dynbuf::new() }
}

pub type Curl_HttpReq = u32;
pub const HTTPREQ_HEAD: Curl_HttpReq = 5;
pub const HTTPREQ_PUT: Curl_HttpReq = 4;
pub const HTTPREQ_POST_MIME: Curl_HttpReq = 3;
pub const HTTPREQ_POST_FORM: Curl_HttpReq = 2;
pub const HTTPREQ_POST: Curl_HttpReq = 1;
pub const HTTPREQ_GET: Curl_HttpReq = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct urlpieces {
    pub scheme: * mut i8,
    pub hostname: * mut i8,
    pub port: * mut i8,
    pub user: * mut i8,
    pub password: * mut i8,
    pub options: * mut i8,
    pub path: * mut i8,
    pub query: * mut i8,
}
impl urlpieces {
    pub const fn new() -> Self {
        urlpieces {
        scheme: (0 as * mut i8),
        hostname: (0 as * mut i8),
        port: (0 as * mut i8),
        user: (0 as * mut i8),
        password: (0 as * mut i8),
        options: (0 as * mut i8),
        path: (0 as * mut i8),
        query: (0 as * mut i8)
        }
    }
}

impl std::default::Default for urlpieces {
    fn default() -> Self { urlpieces::new() }
}

pub type CURLU = crate::src::lib::urlapi::Curl_URL;
pub type curl_read_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut i8>,_: u64,_: u64,_: Option<&'a2 mut core::ffi::c_void>,) -> u64>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct time_node {
    pub list: crate::src::lib::http2::Curl_llist_element,
    pub time: crate::src::lib::http2::curltime,
    pub eid: u32,
}
impl time_node {
    pub const fn new() -> Self {
        time_node {
        list: crate::src::lib::http2::Curl_llist_element::new(),
        time: crate::src::lib::http2::curltime::new(),
        eid: 0
        }
    }
}

impl std::default::Default for time_node {
    fn default() -> Self { time_node::new() }
}

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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curltime {
    pub tv_sec: i64,
    pub tv_usec: i32,
}
impl curltime {
    pub const fn new() -> Self {
        curltime {
        tv_sec: 0,
        tv_usec: 0
        }
    }
}

impl std::default::Default for curltime {
    fn default() -> Self { curltime::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_tree {
    pub smaller: * mut crate::src::lib::http2::Curl_tree,
    pub larger: * mut crate::src::lib::http2::Curl_tree,
    pub samen: * mut crate::src::lib::http2::Curl_tree,
    pub samep: * mut crate::src::lib::http2::Curl_tree,
    pub key: crate::src::lib::http2::curltime,
    pub payload: * mut core::ffi::c_void,
}
impl Curl_tree {
    pub const fn new() -> Self {
        Curl_tree {
        smaller: (0 as * mut crate::src::lib::http2::Curl_tree),
        larger: (0 as * mut crate::src::lib::http2::Curl_tree),
        samen: (0 as * mut crate::src::lib::http2::Curl_tree),
        samep: (0 as * mut crate::src::lib::http2::Curl_tree),
        key: crate::src::lib::http2::curltime::new(),
        payload: (0 as * mut core::ffi::c_void)
        }
    }
}

impl std::default::Default for Curl_tree {
    fn default() -> Self { Curl_tree::new() }
}

// #[derive(Copy, Clone, BitfieldStruct)]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_async {
    pub hostname: * mut i8,
    pub dns: * mut crate::src::lib::http2::Curl_dns_entry,
    pub tdata: * mut crate::src::lib::asyn_thread::thread_data,
    pub resolver: * mut core::ffi::c_void,
    pub port: i32,
    pub status: i32,
    // #[bitfield(name = "done", ty = "bit", bits = "0..=0")]
    pub done: [u8; 1],
    // #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
impl Curl_async {
    pub const fn new() -> Self {
        Curl_async {
        hostname: (0 as * mut i8),
        dns: (0 as * mut crate::src::lib::http2::Curl_dns_entry),
        tdata: (0 as * mut crate::src::lib::asyn_thread::thread_data),
        resolver: (0 as * mut core::ffi::c_void),
        port: 0,
        status: 0,
        done: [0,],
        c2rust_padding: [0,0,0,0,0,0,0,]
        }
    }
}

impl std::default::Default for Curl_async {
    fn default() -> Self { Curl_async::new() }
}

impl Curl_async {
    /// This method allows you to write to a bitfield with a value
    pub fn set_done(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.done;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn done(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.done;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_dns_entry {
    pub addr: * mut crate::src::lib::http2::Curl_addrinfo,
    pub timestamp: i64,
    pub inuse: i64,
}
impl Curl_dns_entry {
    pub const fn new() -> Self {
        Curl_dns_entry {
        addr: (0 as * mut crate::src::lib::http2::Curl_addrinfo),
        timestamp: 0,
        inuse: 0
        }
    }
}

impl std::default::Default for Curl_dns_entry {
    fn default() -> Self { Curl_dns_entry::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_addrinfo {
    pub ai_flags: i32,
    pub ai_family: i32,
    pub ai_socktype: i32,
    pub ai_protocol: i32,
    pub ai_addrlen: u32,
    pub ai_canonname: * mut i8,
    pub ai_addr: * mut crate::src::lib::http2::sockaddr,
    pub ai_next: * mut crate::src::lib::http2::Curl_addrinfo,
}
impl Curl_addrinfo {
    pub const fn new() -> Self {
        Curl_addrinfo {
        ai_flags: 0,
        ai_family: 0,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_canonname: (0 as * mut i8),
        ai_addr: (0 as * mut crate::src::lib::http2::sockaddr),
        ai_next: (0 as * mut crate::src::lib::http2::Curl_addrinfo)
        }
    }
}

impl std::default::Default for Curl_addrinfo {
    fn default() -> Self { Curl_addrinfo::new() }
}

// #[derive(Copy, Clone, BitfieldStruct)]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct auth {
    pub want: u64,
    pub picked: u64,
    pub avail: u64,
    // #[bitfield(name = "done", ty = "bit", bits = "0..=0")]
    // #[bitfield(name = "multipass", ty = "bit", bits = "1..=1")]
    // #[bitfield(name = "iestyle", ty = "bit", bits = "2..=2")]
    pub done_multipass_iestyle: [u8; 1],
    // #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
impl auth {
    pub const fn new() -> Self {
        auth {
        want: 0,
        picked: 0,
        avail: 0,
        done_multipass_iestyle: [0,],
        c2rust_padding: [0,0,0,0,0,0,0,]
        }
    }
}

impl std::default::Default for auth {
    fn default() -> Self { auth::new() }
}

impl auth {
    /// This method allows you to write to a bitfield with a value
    pub fn set_done(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.done_multipass_iestyle;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn done(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.done_multipass_iestyle;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_multipass(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.done_multipass_iestyle;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn multipass(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.done_multipass_iestyle;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_iestyle(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.done_multipass_iestyle;
        let (lhs_bit, rhs_bit) = (2usize, 2usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn iestyle(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.done_multipass_iestyle;
        let (lhs_bit, rhs_bit) = (2usize, 2usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
}
// #[derive(Copy, Clone, BitfieldStruct)]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct digestdata {
    pub nonce: * mut i8,
    pub cnonce: * mut i8,
    pub realm: * mut i8,
    pub algo: i32,
    pub opaque: * mut i8,
    pub qop: * mut i8,
    pub algorithm: * mut i8,
    pub nc: i32,
    // #[bitfield(name = "stale", ty = "bit", bits = "0..=0")]
    // #[bitfield(name = "userhash", ty = "bit", bits = "1..=1")]
    pub stale_userhash: [u8; 1],
    // #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
impl digestdata {
    pub const fn new() -> Self {
        digestdata {
        nonce: (0 as * mut i8),
        cnonce: (0 as * mut i8),
        realm: (0 as * mut i8),
        algo: 0,
        opaque: (0 as * mut i8),
        qop: (0 as * mut i8),
        algorithm: (0 as * mut i8),
        nc: 0,
        stale_userhash: [0,],
        c2rust_padding: [0,0,0,]
        }
    }
}

impl std::default::Default for digestdata {
    fn default() -> Self { digestdata::new() }
}

impl digestdata {
    /// This method allows you to write to a bitfield with a value
    pub fn set_stale(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.stale_userhash;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn stale(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.stale_userhash;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_userhash(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.stale_userhash;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn userhash(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.stale_userhash;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tempbuf {
    pub b: crate::src::lib::http2::dynbuf,
    pub type_0: i32,
}
impl tempbuf {
    pub const fn new() -> Self {
        tempbuf {
        b: crate::src::lib::http2::dynbuf::new(),
        type_0: 0
        }
    }
}

impl std::default::Default for tempbuf {
    fn default() -> Self { tempbuf::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_ssl_session {
    pub name: * mut i8,
    pub conn_to_host: * mut i8,
    pub scheme: * const i8,
    pub sessionid: * mut core::ffi::c_void,
    pub idsize: u64,
    pub age: i64,
    pub remote_port: i32,
    pub conn_to_port: i32,
    pub ssl_config: crate::src::lib::http2::ssl_primary_config,
}
impl Curl_ssl_session {
    pub const fn new() -> Self {
        Curl_ssl_session {
        name: (0 as * mut i8),
        conn_to_host: (0 as * mut i8),
        scheme: (0 as * const i8),
        sessionid: (0 as * mut core::ffi::c_void),
        idsize: 0,
        age: 0,
        remote_port: 0,
        conn_to_port: 0,
        ssl_config: crate::src::lib::http2::ssl_primary_config::new()
        }
    }
}

impl std::default::Default for Curl_ssl_session {
    fn default() -> Self { Curl_ssl_session::new() }
}

// #[derive(Copy, Clone, BitfieldStruct)]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssl_primary_config {
    pub version: i64,
    pub version_max: i64,
    pub CApath: * mut i8,
    pub CAfile: * mut i8,
    pub issuercert: * mut i8,
    pub clientcert: * mut i8,
    pub random_file: * mut i8,
    pub egdsocket: * mut i8,
    pub cipher_list: * mut i8,
    pub cipher_list13: * mut i8,
    pub pinned_key: * mut i8,
    pub cert_blob: * mut crate::src::lib::http2::curl_blob,
    pub ca_info_blob: * mut crate::src::lib::http2::curl_blob,
    pub issuercert_blob: * mut crate::src::lib::http2::curl_blob,
    pub curves: * mut i8,
    // #[bitfield(name = "verifypeer", ty = "bit", bits = "0..=0")]
    // #[bitfield(name = "verifyhost", ty = "bit", bits = "1..=1")]
    // #[bitfield(name = "verifystatus", ty = "bit", bits = "2..=2")]
    // #[bitfield(name = "sessionid", ty = "bit", bits = "3..=3")]
    pub verifypeer_verifyhost_verifystatus_sessionid: [u8; 1],
    // #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
impl ssl_primary_config {
    pub const fn new() -> Self {
        ssl_primary_config {
        version: 0,
        version_max: 0,
        CApath: (0 as * mut i8),
        CAfile: (0 as * mut i8),
        issuercert: (0 as * mut i8),
        clientcert: (0 as * mut i8),
        random_file: (0 as * mut i8),
        egdsocket: (0 as * mut i8),
        cipher_list: (0 as * mut i8),
        cipher_list13: (0 as * mut i8),
        pinned_key: (0 as * mut i8),
        cert_blob: (0 as * mut crate::src::lib::http2::curl_blob),
        ca_info_blob: (0 as * mut crate::src::lib::http2::curl_blob),
        issuercert_blob: (0 as * mut crate::src::lib::http2::curl_blob),
        curves: (0 as * mut i8),
        verifypeer_verifyhost_verifystatus_sessionid: [0,],
        c2rust_padding: [0,0,0,0,0,0,0,]
        }
    }
}

impl std::default::Default for ssl_primary_config {
    fn default() -> Self { ssl_primary_config::new() }
}

impl ssl_primary_config {
    /// This method allows you to write to a bitfield with a value
    pub fn set_verifypeer(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.verifypeer_verifyhost_verifystatus_sessionid;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn verifypeer(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.verifypeer_verifyhost_verifystatus_sessionid;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_verifyhost(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.verifypeer_verifyhost_verifystatus_sessionid;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn verifyhost(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.verifypeer_verifyhost_verifystatus_sessionid;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_verifystatus(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.verifypeer_verifyhost_verifystatus_sessionid;
        let (lhs_bit, rhs_bit) = (2usize, 2usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn verifystatus(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.verifypeer_verifyhost_verifystatus_sessionid;
        let (lhs_bit, rhs_bit) = (2usize, 2usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_sessionid(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.verifypeer_verifyhost_verifystatus_sessionid;
        let (lhs_bit, rhs_bit) = (3usize, 3usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn sessionid(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.verifypeer_verifyhost_verifystatus_sessionid;
        let (lhs_bit, rhs_bit) = (3usize, 3usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_blob {
    pub data: * mut core::ffi::c_void,
    pub len: u64,
    pub flags: u32,
}
impl curl_blob {
    pub const fn new() -> Self {
        curl_blob {
        data: (0 as * mut core::ffi::c_void),
        len: 0,
        flags: 0
        }
    }
}

impl std::default::Default for curl_blob {
    fn default() -> Self { curl_blob::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct conncache {
    pub hash: crate::src::lib::http2::Curl_hash,
    pub num_conn: u64,
    pub next_connection_id: i64,
    pub last_cleanup: crate::src::lib::http2::curltime,
    pub closure_handle: * mut crate::src::lib::http2::Curl_easy,
}
impl conncache {
    pub const fn new() -> Self {
        conncache {
        hash: crate::src::lib::http2::Curl_hash::new(),
        num_conn: 0,
        next_connection_id: 0,
        last_cleanup: crate::src::lib::http2::curltime::new(),
        closure_handle: (0 as * mut crate::src::lib::http2::Curl_easy)
        }
    }
}

impl std::default::Default for conncache {
    fn default() -> Self { conncache::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_hash {
    pub table: * mut crate::src::lib::http2::Curl_llist,
    pub hash_func: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: u64,_: u64,) -> u64>,
    pub comp_func: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: u64,_: * mut core::ffi::c_void,_: u64,) -> u64>,
    pub dtor: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>,
    pub slots: i32,
    pub size: u64,
}
impl Curl_hash {
    pub const fn new() -> Self {
        Curl_hash {
        table: (0 as * mut crate::src::lib::http2::Curl_llist),
        hash_func: None,
        comp_func: None,
        dtor: None,
        slots: 0,
        size: 0
        }
    }
}

impl std::default::Default for Curl_hash {
    fn default() -> Self { Curl_hash::new() }
}

pub type Curl_hash_dtor<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> ()>;
pub type comp_function<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: u64,_: Option<&'a2 mut core::ffi::c_void>,_: u64,) -> u64>;
pub type hash_function<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: u64,_: u64,) -> u64>;
// #[derive(Copy, Clone, BitfieldStruct)]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Progress {
    pub lastshow: i64,
    pub size_dl: i64,
    pub size_ul: i64,
    pub downloaded: i64,
    pub uploaded: i64,
    pub current_speed: i64,
    pub width: i32,
    pub flags: i32,
    pub timespent: i64,
    pub dlspeed: i64,
    pub ulspeed: i64,
    pub t_nslookup: i64,
    pub t_connect: i64,
    pub t_appconnect: i64,
    pub t_pretransfer: i64,
    pub t_starttransfer: i64,
    pub t_redirect: i64,
    pub start: crate::src::lib::http2::curltime,
    pub t_startsingle: crate::src::lib::http2::curltime,
    pub t_startop: crate::src::lib::http2::curltime,
    pub t_acceptdata: crate::src::lib::http2::curltime,
    pub ul_limit_start: crate::src::lib::http2::curltime,
    pub ul_limit_size: i64,
    pub dl_limit_start: crate::src::lib::http2::curltime,
    pub dl_limit_size: i64,
    pub speeder: [i64; 6],
    pub speeder_time: [crate::src::lib::http2::curltime; 6],
    pub speeder_c: i32,
    // #[bitfield(name = "callback", ty = "bit", bits = "0..=0")]
    // #[bitfield(name = "is_t_startransfer_set", ty = "bit", bits = "1..=1")]
    pub callback_is_t_startransfer_set: [u8; 1],
    // #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
impl Progress {
    pub const fn new() -> Self {
        Progress {
        lastshow: 0,
        size_dl: 0,
        size_ul: 0,
        downloaded: 0,
        uploaded: 0,
        current_speed: 0,
        width: 0,
        flags: 0,
        timespent: 0,
        dlspeed: 0,
        ulspeed: 0,
        t_nslookup: 0,
        t_connect: 0,
        t_appconnect: 0,
        t_pretransfer: 0,
        t_starttransfer: 0,
        t_redirect: 0,
        start: crate::src::lib::http2::curltime::new(),
        t_startsingle: crate::src::lib::http2::curltime::new(),
        t_startop: crate::src::lib::http2::curltime::new(),
        t_acceptdata: crate::src::lib::http2::curltime::new(),
        ul_limit_start: crate::src::lib::http2::curltime::new(),
        ul_limit_size: 0,
        dl_limit_start: crate::src::lib::http2::curltime::new(),
        dl_limit_size: 0,
        speeder: [0,0,0,0,0,0,],
        speeder_time: [crate::src::lib::http2::curltime::new(),crate::src::lib::http2::curltime::new(),crate::src::lib::http2::curltime::new(),crate::src::lib::http2::curltime::new(),crate::src::lib::http2::curltime::new(),crate::src::lib::http2::curltime::new(),],
        speeder_c: 0,
        callback_is_t_startransfer_set: [0,],
        c2rust_padding: [0,0,0,]
        }
    }
}

impl std::default::Default for Progress {
    fn default() -> Self { Progress::new() }
}

impl Progress {
    /// This method allows you to write to a bitfield with a value
    pub fn set_callback(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.callback_is_t_startransfer_set;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn callback(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.callback_is_t_startransfer_set;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_is_t_startransfer_set(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.callback_is_t_startransfer_set;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn is_t_startransfer_set(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.callback_is_t_startransfer_set;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
}
pub type timediff_t = i64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CookieInfo {
    pub cookies: [* mut crate::src::lib::http2::Cookie; 256],
    pub filename: * mut i8,
    pub numcookies: i64,
    pub running: bool,
    pub newsession: bool,
    pub lastct: i32,
    pub next_expiration: i64,
}
impl CookieInfo {
    pub const fn new() -> Self {
        CookieInfo {
        cookies: [(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),(0 as * mut crate::src::lib::http2::Cookie),],
        filename: (0 as * mut i8),
        numcookies: 0,
        running: false,
        newsession: false,
        lastct: 0,
        next_expiration: 0
        }
    }
}

impl std::default::Default for CookieInfo {
    fn default() -> Self { CookieInfo::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Cookie {
    pub next: * mut crate::src::lib::http2::Cookie,
    pub name: * mut i8,
    pub value: * mut i8,
    pub path: * mut i8,
    pub spath: * mut i8,
    pub domain: * mut i8,
    pub expires: i64,
    pub expirestr: * mut i8,
    pub version: * mut i8,
    pub maxage: * mut i8,
    pub tailmatch: bool,
    pub secure: bool,
    pub livecookie: bool,
    pub httponly: bool,
    pub creationtime: i32,
    pub prefix: u8,
}
impl Cookie {
    pub const fn new() -> Self {
        Cookie {
        next: (0 as * mut crate::src::lib::http2::Cookie),
        name: (0 as * mut i8),
        value: (0 as * mut i8),
        path: (0 as * mut i8),
        spath: (0 as * mut i8),
        domain: (0 as * mut i8),
        expires: 0,
        expirestr: (0 as * mut i8),
        version: (0 as * mut i8),
        maxage: (0 as * mut i8),
        tailmatch: false,
        secure: false,
        livecookie: false,
        httponly: false,
        creationtime: 0,
        prefix: 0
        }
    }
}

impl std::default::Default for Cookie {
    fn default() -> Self { Cookie::new() }
}

// #[derive(Copy, Clone, BitfieldStruct)]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct UserDefined {
    pub err: * mut crate::src::lib::http2::_IO_FILE,
    pub debugdata: * mut core::ffi::c_void,
    pub errorbuffer: * mut i8,
    pub proxyport: i64,
    pub out: * mut core::ffi::c_void,
    pub in_set: * mut core::ffi::c_void,
    pub writeheader: * mut core::ffi::c_void,
    pub rtp_out: * mut core::ffi::c_void,
    pub use_port: i64,
    pub httpauth: u64,
    pub proxyauth: u64,
    pub socks5auth: u64,
    pub maxredirs: i64,
    pub keep_post: i32,
    pub postfields: * mut core::ffi::c_void,
    pub seek_func: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: i64,_: i32,) -> i32>,
    pub postfieldsize: i64,
    pub localport: u16,
    pub localportrange: i32,
    pub fwrite_func: Option<unsafe extern "C"  fn(_: * mut i8,_: u64,_: u64,_: * mut core::ffi::c_void,) -> u64>,
    pub fwrite_header: Option<unsafe extern "C"  fn(_: * mut i8,_: u64,_: u64,_: * mut core::ffi::c_void,) -> u64>,
    pub fwrite_rtp: Option<unsafe extern "C"  fn(_: * mut i8,_: u64,_: u64,_: * mut core::ffi::c_void,) -> u64>,
    pub fread_func_set: Option<unsafe extern "C"  fn(_: * mut i8,_: u64,_: u64,_: * mut core::ffi::c_void,) -> u64>,
    pub fprogress: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: f64,_: f64,_: f64,_: f64,) -> i32>,
    pub fxferinfo: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: i64,_: i64,_: i64,_: i64,) -> i32>,
    pub fdebug: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: u32,_: * mut i8,_: u64,_: * mut core::ffi::c_void,) -> i32>,
    pub ioctl_func: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: i32,_: * mut core::ffi::c_void,) -> u32>,
    pub fsockopt: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: i32,_: u32,) -> i32>,
    pub sockopt_client: * mut core::ffi::c_void,
    pub fopensocket: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: u32,_: * mut crate::src::lib::http2::curl_sockaddr,) -> i32>,
    pub opensocket_client: * mut core::ffi::c_void,
    pub fclosesocket: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: i32,) -> i32>,
    pub closesocket_client: * mut core::ffi::c_void,
    pub seek_client: * mut core::ffi::c_void,
    pub convfromnetwork: Option<unsafe extern "C"  fn(_: * mut i8,_: u64,) -> u32>,
    pub convtonetwork: Option<unsafe extern "C"  fn(_: * mut i8,_: u64,) -> u32>,
    pub convfromutf8: Option<unsafe extern "C"  fn(_: * mut i8,_: u64,) -> u32>,
    pub hsts_read: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut crate::src::lib::http2::curl_hstsentry,_: * mut core::ffi::c_void,) -> u32>,
    pub hsts_read_userp: * mut core::ffi::c_void,
    pub hsts_write: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut crate::src::lib::http2::curl_hstsentry,_: * mut crate::src::lib::http2::curl_index,_: * mut core::ffi::c_void,) -> u32>,
    pub hsts_write_userp: * mut core::ffi::c_void,
    pub progress_client: * mut core::ffi::c_void,
    pub ioctl_client: * mut core::ffi::c_void,
    pub timeout: i64,
    pub connecttimeout: i64,
    pub accepttimeout: i64,
    pub happy_eyeballs_timeout: i64,
    pub server_response_timeout: i64,
    pub maxage_conn: i64,
    pub tftp_blksize: i64,
    pub filesize: i64,
    pub low_speed_limit: i64,
    pub low_speed_time: i64,
    pub max_send_speed: i64,
    pub max_recv_speed: i64,
    pub set_resume_from: i64,
    pub headers: * mut crate::src::lib::http2::curl_slist,
    pub proxyheaders: * mut crate::src::lib::http2::curl_slist,
    pub httppost: * mut crate::src::lib::http2::curl_httppost,
    pub mimepost: crate::src::lib::http2::curl_mimepart,
    pub quote: * mut crate::src::lib::http2::curl_slist,
    pub postquote: * mut crate::src::lib::http2::curl_slist,
    pub prequote: * mut crate::src::lib::http2::curl_slist,
    pub source_quote: * mut crate::src::lib::http2::curl_slist,
    pub source_prequote: * mut crate::src::lib::http2::curl_slist,
    pub source_postquote: * mut crate::src::lib::http2::curl_slist,
    pub telnet_options: * mut crate::src::lib::http2::curl_slist,
    pub resolve: * mut crate::src::lib::http2::curl_slist,
    pub connect_to: * mut crate::src::lib::http2::curl_slist,
    pub timecondition: u32,
    pub proxytype: u32,
    pub timevalue: i64,
    pub method: u32,
    pub httpwant: u8,
    pub ssl: crate::src::lib::http2::ssl_config_data,
    pub proxy_ssl: crate::src::lib::http2::ssl_config_data,
    pub general_ssl: crate::src::lib::http2::ssl_general_config,
    pub dns_cache_timeout: i64,
    pub buffer_size: i64,
    pub upload_buffer_size: u32,
    pub private_data: * mut core::ffi::c_void,
    pub http200aliases: * mut crate::src::lib::http2::curl_slist,
    pub ipver: u8,
    pub max_filesize: i64,
    pub ftp_filemethod: u32,
    pub ftpsslauth: u32,
    pub ftp_ccc: u32,
    pub ftp_create_missing_dirs: i32,
    pub ssh_keyfunc: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * const crate::src::lib::http2::curl_khkey,_: * const crate::src::lib::http2::curl_khkey,_: u32,_: * mut core::ffi::c_void,) -> i32>,
    pub ssh_keyfunc_userp: * mut core::ffi::c_void,
    pub use_netrc: u32,
    pub use_ssl: u32,
    pub new_file_perms: i64,
    pub new_directory_perms: i64,
    pub ssh_auth_types: i64,
    pub str_0: [* mut i8; 80],
    pub blobs: [* mut crate::src::lib::http2::curl_blob; 8],
    pub scope_id: u32,
    pub allowed_protocols: i64,
    pub redir_protocols: i64,
    pub mail_rcpt: * mut crate::src::lib::http2::curl_slist,
    pub rtspreq: u32,
    pub rtspversion: i64,
    pub chunk_bgn: Option<unsafe extern "C"  fn(_: * const core::ffi::c_void,_: * mut core::ffi::c_void,_: i32,) -> i64>,
    pub chunk_end: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i64>,
    pub fnmatch: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,_: * const i8,) -> i32>,
    pub fnmatch_data: * mut core::ffi::c_void,
    pub gssapi_delegation: i64,
    pub tcp_keepidle: i64,
    pub tcp_keepintvl: i64,
    pub maxconnects: u64,
    pub expect_100_timeout: i64,
    pub stream_depends_on: * mut crate::src::lib::http2::Curl_easy,
    pub stream_weight: i32,
    pub stream_dependents: * mut crate::src::lib::http2::Curl_http2_dep,
    pub resolver_start: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut core::ffi::c_void,_: * mut core::ffi::c_void,) -> i32>,
    pub resolver_start_client: * mut core::ffi::c_void,
    pub upkeep_interval_ms: i64,
    pub fmultidone: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: u32,) -> i32>,
    pub dohfor: * mut crate::src::lib::http2::Curl_easy,
    pub uh: * mut crate::src::lib::urlapi::Curl_URL,
    pub trailer_data: * mut core::ffi::c_void,
    pub trailer_callback: Option<unsafe extern "C"  fn(_: * mut * mut crate::src::lib::http2::curl_slist,_: * mut core::ffi::c_void,) -> i32>,
    // #[bitfield(name = "is_fread_set", ty = "bit", bits = "0..=0")]
    // #[bitfield(name = "is_fwrite_set", ty = "bit", bits = "1..=1")]
    // #[bitfield(name = "free_referer", ty = "bit", bits = "2..=2")]
    // #[bitfield(name = "tftp_no_options", ty = "bit", bits = "3..=3")]
    // #[bitfield(name = "sep_headers", ty = "bit", bits = "4..=4")]
    // #[bitfield(name = "cookiesession", ty = "bit", bits = "5..=5")]
    // #[bitfield(name = "crlf", ty = "bit", bits = "6..=6")]
    // #[bitfield(name = "strip_path_slash", ty = "bit", bits = "7..=7")]
    // #[bitfield(name = "ssh_compression", ty = "bit", bits = "8..=8")]
    // #[bitfield(name = "get_filetime", ty = "bit", bits = "9..=9")]
    // #[bitfield(name = "tunnel_thru_httpproxy", ty = "bit", bits = "10..=10")]
    // #[bitfield(name = "prefer_ascii", ty = "bit", bits = "11..=11")]
    // #[bitfield(name = "remote_append", ty = "bit", bits = "12..=12")]
    // #[bitfield(name = "list_only", ty = "bit", bits = "13..=13")]
    // #[bitfield(name = "ftp_use_port", ty = "bit", bits = "14..=14")]
    // #[bitfield(name = "ftp_use_epsv", ty = "bit", bits = "15..=15")]
    // #[bitfield(name = "ftp_use_eprt", ty = "bit", bits = "16..=16")]
    // #[bitfield(name = "ftp_use_pret", ty = "bit", bits = "17..=17")]
    // #[bitfield(name = "ftp_skip_ip", ty = "bit", bits = "18..=18")]
    // #[bitfield(name = "hide_progress", ty = "bit", bits = "19..=19")]
    // #[bitfield(name = "http_fail_on_error", ty = "bit", bits = "20..=20")]
    // #[bitfield(name = "http_keep_sending_on_error", ty = "bit", bits = "21..=21")]
    // #[bitfield(name = "http_follow_location", ty = "bit", bits = "22..=22")]
    // #[bitfield(name = "http_transfer_encoding", ty = "bit", bits = "23..=23")]
    // #[bitfield(name = "allow_auth_to_other_hosts", ty = "bit", bits = "24..=24")]
    // #[bitfield(name = "include_header", ty = "bit", bits = "25..=25")]
    // #[bitfield(name = "http_set_referer", ty = "bit", bits = "26..=26")]
    // #[bitfield(name = "http_auto_referer", ty = "bit", bits = "27..=27")]
    // #[bitfield(name = "opt_no_body", ty = "bit", bits = "28..=28")]
    // #[bitfield(name = "upload", ty = "bit", bits = "29..=29")]
    // #[bitfield(name = "verbose", ty = "bit", bits = "30..=30")]
    // #[bitfield(name = "krb", ty = "bit", bits = "31..=31")]
    // #[bitfield(name = "reuse_forbid", ty = "bit", bits = "32..=32")]
    // #[bitfield(name = "reuse_fresh", ty = "bit", bits = "33..=33")]
    // #[bitfield(name = "no_signal", ty = "bit", bits = "34..=34")]
    // #[bitfield(name = "tcp_nodelay", ty = "bit", bits = "35..=35")]
    // #[bitfield(name = "ignorecl", ty = "bit", bits = "36..=36")]
    // #[bitfield(name = "connect_only", ty = "bit", bits = "37..=37")]
    // #[bitfield(name = "http_te_skip", ty = "bit", bits = "38..=38")]
    // #[bitfield(name = "http_ce_skip", ty = "bit", bits = "39..=39")]
    // #[bitfield(name = "proxy_transfer_mode", ty = "bit", bits = "40..=40")]
    // #[bitfield(name = "sasl_ir", ty = "bit", bits = "41..=41")]
    // #[bitfield(name = "wildcard_enabled", ty = "bit", bits = "42..=42")]
    // #[bitfield(name = "tcp_keepalive", ty = "bit", bits = "43..=43")]
    // #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "44..=44")]
    // #[bitfield(name = "ssl_enable_npn", ty = "bit", bits = "45..=45")]
    // #[bitfield(name = "ssl_enable_alpn", ty = "bit", bits = "46..=46")]
    // #[bitfield(name = "path_as_is", ty = "bit", bits = "47..=47")]
    // #[bitfield(name = "pipewait", ty = "bit", bits = "48..=48")]
    // #[bitfield(name = "suppress_connect_headers", ty = "bit", bits = "49..=49")]
    // #[bitfield(name = "dns_shuffle_addresses", ty = "bit", bits = "50..=50")]
    // #[bitfield(name = "stream_depends_e", ty = "bit", bits = "51..=51")]
    // #[bitfield(name = "haproxyprotocol", ty = "bit", bits = "52..=52")]
    // #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "53..=53")]
    // #[bitfield(name = "disallow_username_in_url", ty = "bit", bits = "54..=54")]
    // #[bitfield(name = "doh", ty = "bit", bits = "55..=55")]
    // #[bitfield(name = "doh_get", ty = "bit", bits = "56..=56")]
    // #[bitfield(name = "doh_verifypeer", ty = "bit", bits = "57..=57")]
    // #[bitfield(name = "doh_verifyhost", ty = "bit", bits = "58..=58")]
    // #[bitfield(name = "doh_verifystatus", ty = "bit", bits = "59..=59")]
    // #[bitfield(name = "http09_allowed", ty = "bit", bits = "60..=60")]
    // #[bitfield(name = "mail_rcpt_allowfails", ty = "bit", bits = "61..=61")]
    pub is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails: [u8; 8],
}
impl UserDefined {
    pub const fn new() -> Self {
        UserDefined {
        err: (0 as * mut crate::src::lib::http2::_IO_FILE),
        debugdata: (0 as * mut core::ffi::c_void),
        errorbuffer: (0 as * mut i8),
        proxyport: 0,
        out: (0 as * mut core::ffi::c_void),
        in_set: (0 as * mut core::ffi::c_void),
        writeheader: (0 as * mut core::ffi::c_void),
        rtp_out: (0 as * mut core::ffi::c_void),
        use_port: 0,
        httpauth: 0,
        proxyauth: 0,
        socks5auth: 0,
        maxredirs: 0,
        keep_post: 0,
        postfields: (0 as * mut core::ffi::c_void),
        seek_func: None,
        postfieldsize: 0,
        localport: 0,
        localportrange: 0,
        fwrite_func: None,
        fwrite_header: None,
        fwrite_rtp: None,
        fread_func_set: None,
        fprogress: None,
        fxferinfo: None,
        fdebug: None,
        ioctl_func: None,
        fsockopt: None,
        sockopt_client: (0 as * mut core::ffi::c_void),
        fopensocket: None,
        opensocket_client: (0 as * mut core::ffi::c_void),
        fclosesocket: None,
        closesocket_client: (0 as * mut core::ffi::c_void),
        seek_client: (0 as * mut core::ffi::c_void),
        convfromnetwork: None,
        convtonetwork: None,
        convfromutf8: None,
        hsts_read: None,
        hsts_read_userp: (0 as * mut core::ffi::c_void),
        hsts_write: None,
        hsts_write_userp: (0 as * mut core::ffi::c_void),
        progress_client: (0 as * mut core::ffi::c_void),
        ioctl_client: (0 as * mut core::ffi::c_void),
        timeout: 0,
        connecttimeout: 0,
        accepttimeout: 0,
        happy_eyeballs_timeout: 0,
        server_response_timeout: 0,
        maxage_conn: 0,
        tftp_blksize: 0,
        filesize: 0,
        low_speed_limit: 0,
        low_speed_time: 0,
        max_send_speed: 0,
        max_recv_speed: 0,
        set_resume_from: 0,
        headers: (0 as * mut crate::src::lib::http2::curl_slist),
        proxyheaders: (0 as * mut crate::src::lib::http2::curl_slist),
        httppost: (0 as * mut crate::src::lib::http2::curl_httppost),
        mimepost: crate::src::lib::http2::curl_mimepart::new(),
        quote: (0 as * mut crate::src::lib::http2::curl_slist),
        postquote: (0 as * mut crate::src::lib::http2::curl_slist),
        prequote: (0 as * mut crate::src::lib::http2::curl_slist),
        source_quote: (0 as * mut crate::src::lib::http2::curl_slist),
        source_prequote: (0 as * mut crate::src::lib::http2::curl_slist),
        source_postquote: (0 as * mut crate::src::lib::http2::curl_slist),
        telnet_options: (0 as * mut crate::src::lib::http2::curl_slist),
        resolve: (0 as * mut crate::src::lib::http2::curl_slist),
        connect_to: (0 as * mut crate::src::lib::http2::curl_slist),
        timecondition: 0,
        proxytype: 0,
        timevalue: 0,
        method: 0,
        httpwant: 0,
        ssl: crate::src::lib::http2::ssl_config_data::new(),
        proxy_ssl: crate::src::lib::http2::ssl_config_data::new(),
        general_ssl: crate::src::lib::http2::ssl_general_config::new(),
        dns_cache_timeout: 0,
        buffer_size: 0,
        upload_buffer_size: 0,
        private_data: (0 as * mut core::ffi::c_void),
        http200aliases: (0 as * mut crate::src::lib::http2::curl_slist),
        ipver: 0,
        max_filesize: 0,
        ftp_filemethod: 0,
        ftpsslauth: 0,
        ftp_ccc: 0,
        ftp_create_missing_dirs: 0,
        ssh_keyfunc: None,
        ssh_keyfunc_userp: (0 as * mut core::ffi::c_void),
        use_netrc: 0,
        use_ssl: 0,
        new_file_perms: 0,
        new_directory_perms: 0,
        ssh_auth_types: 0,
        str_0: [(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),(0 as * mut i8),],
        blobs: [(0 as * mut crate::src::lib::http2::curl_blob),(0 as * mut crate::src::lib::http2::curl_blob),(0 as * mut crate::src::lib::http2::curl_blob),(0 as * mut crate::src::lib::http2::curl_blob),(0 as * mut crate::src::lib::http2::curl_blob),(0 as * mut crate::src::lib::http2::curl_blob),(0 as * mut crate::src::lib::http2::curl_blob),(0 as * mut crate::src::lib::http2::curl_blob),],
        scope_id: 0,
        allowed_protocols: 0,
        redir_protocols: 0,
        mail_rcpt: (0 as * mut crate::src::lib::http2::curl_slist),
        rtspreq: 0,
        rtspversion: 0,
        chunk_bgn: None,
        chunk_end: None,
        fnmatch: None,
        fnmatch_data: (0 as * mut core::ffi::c_void),
        gssapi_delegation: 0,
        tcp_keepidle: 0,
        tcp_keepintvl: 0,
        maxconnects: 0,
        expect_100_timeout: 0,
        stream_depends_on: (0 as * mut crate::src::lib::http2::Curl_easy),
        stream_weight: 0,
        stream_dependents: (0 as * mut crate::src::lib::http2::Curl_http2_dep),
        resolver_start: None,
        resolver_start_client: (0 as * mut core::ffi::c_void),
        upkeep_interval_ms: 0,
        fmultidone: None,
        dohfor: (0 as * mut crate::src::lib::http2::Curl_easy),
        uh: (0 as * mut crate::src::lib::urlapi::Curl_URL),
        trailer_data: (0 as * mut core::ffi::c_void),
        trailer_callback: None,
        is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails: [0,0,0,0,0,0,0,0,]
        }
    }
}

impl std::default::Default for UserDefined {
    fn default() -> Self { UserDefined::new() }
}

impl UserDefined {
    /// This method allows you to write to a bitfield with a value
    pub fn set_is_fread_set(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn is_fread_set(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_is_fwrite_set(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn is_fwrite_set(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_free_referer(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (2usize, 2usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn free_referer(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (2usize, 2usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_tftp_no_options(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (3usize, 3usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn tftp_no_options(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (3usize, 3usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_sep_headers(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (4usize, 4usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn sep_headers(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (4usize, 4usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_cookiesession(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (5usize, 5usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn cookiesession(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (5usize, 5usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_crlf(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (6usize, 6usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn crlf(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (6usize, 6usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_strip_path_slash(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (7usize, 7usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn strip_path_slash(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (7usize, 7usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ssh_compression(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (8usize, 8usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ssh_compression(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (8usize, 8usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_get_filetime(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (9usize, 9usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn get_filetime(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (9usize, 9usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_tunnel_thru_httpproxy(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (10usize, 10usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn tunnel_thru_httpproxy(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (10usize, 10usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_prefer_ascii(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (11usize, 11usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn prefer_ascii(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (11usize, 11usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_remote_append(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (12usize, 12usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn remote_append(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (12usize, 12usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_list_only(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (13usize, 13usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn list_only(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (13usize, 13usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ftp_use_port(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (14usize, 14usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ftp_use_port(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (14usize, 14usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ftp_use_epsv(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (15usize, 15usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ftp_use_epsv(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (15usize, 15usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ftp_use_eprt(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (16usize, 16usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ftp_use_eprt(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (16usize, 16usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ftp_use_pret(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (17usize, 17usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ftp_use_pret(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (17usize, 17usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ftp_skip_ip(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (18usize, 18usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ftp_skip_ip(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (18usize, 18usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_hide_progress(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (19usize, 19usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn hide_progress(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (19usize, 19usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_http_fail_on_error(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (20usize, 20usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn http_fail_on_error(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (20usize, 20usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_http_keep_sending_on_error(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (21usize, 21usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn http_keep_sending_on_error(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (21usize, 21usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_http_follow_location(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (22usize, 22usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn http_follow_location(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (22usize, 22usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_http_transfer_encoding(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (23usize, 23usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn http_transfer_encoding(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (23usize, 23usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_allow_auth_to_other_hosts(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (24usize, 24usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn allow_auth_to_other_hosts(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (24usize, 24usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_include_header(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (25usize, 25usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn include_header(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (25usize, 25usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_http_set_referer(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (26usize, 26usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn http_set_referer(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (26usize, 26usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_http_auto_referer(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (27usize, 27usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn http_auto_referer(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (27usize, 27usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_opt_no_body(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (28usize, 28usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn opt_no_body(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (28usize, 28usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_upload(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (29usize, 29usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn upload(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (29usize, 29usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_verbose(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (30usize, 30usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn verbose(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (30usize, 30usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_krb(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (31usize, 31usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn krb(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (31usize, 31usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_reuse_forbid(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (32usize, 32usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn reuse_forbid(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (32usize, 32usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_reuse_fresh(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (33usize, 33usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn reuse_fresh(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (33usize, 33usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_no_signal(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (34usize, 34usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn no_signal(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (34usize, 34usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_tcp_nodelay(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (35usize, 35usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn tcp_nodelay(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (35usize, 35usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ignorecl(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (36usize, 36usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ignorecl(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (36usize, 36usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_connect_only(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (37usize, 37usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn connect_only(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (37usize, 37usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_http_te_skip(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (38usize, 38usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn http_te_skip(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (38usize, 38usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_http_ce_skip(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (39usize, 39usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn http_ce_skip(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (39usize, 39usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_proxy_transfer_mode(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (40usize, 40usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn proxy_transfer_mode(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (40usize, 40usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_sasl_ir(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (41usize, 41usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn sasl_ir(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (41usize, 41usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_wildcard_enabled(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (42usize, 42usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn wildcard_enabled(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (42usize, 42usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_tcp_keepalive(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (43usize, 43usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn tcp_keepalive(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (43usize, 43usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_tcp_fastopen(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (44usize, 44usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn tcp_fastopen(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (44usize, 44usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ssl_enable_npn(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (45usize, 45usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ssl_enable_npn(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (45usize, 45usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ssl_enable_alpn(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (46usize, 46usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ssl_enable_alpn(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (46usize, 46usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_path_as_is(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (47usize, 47usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn path_as_is(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (47usize, 47usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_pipewait(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (48usize, 48usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn pipewait(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (48usize, 48usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_suppress_connect_headers(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (49usize, 49usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn suppress_connect_headers(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (49usize, 49usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_dns_shuffle_addresses(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (50usize, 50usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn dns_shuffle_addresses(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (50usize, 50usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_stream_depends_e(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (51usize, 51usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn stream_depends_e(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (51usize, 51usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_haproxyprotocol(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (52usize, 52usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn haproxyprotocol(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (52usize, 52usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_abstract_unix_socket(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (53usize, 53usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn abstract_unix_socket(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (53usize, 53usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_disallow_username_in_url(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (54usize, 54usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn disallow_username_in_url(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (54usize, 54usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_doh(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (55usize, 55usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn doh(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (55usize, 55usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_doh_get(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (56usize, 56usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn doh_get(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (56usize, 56usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_doh_verifypeer(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (57usize, 57usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn doh_verifypeer(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (57usize, 57usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_doh_verifyhost(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (58usize, 58usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn doh_verifyhost(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (58usize, 58usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_doh_verifystatus(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (59usize, 59usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn doh_verifystatus(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (59usize, 59usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_http09_allowed(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (60usize, 60usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn http09_allowed(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (60usize, 60usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_mail_rcpt_allowfails(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (61usize, 61usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn mail_rcpt_allowfails(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails;
        let (lhs_bit, rhs_bit) = (61usize, 61usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_http2_dep {
    pub next: * mut crate::src::lib::http2::Curl_http2_dep,
    pub data: * mut crate::src::lib::http2::Curl_easy,
}
impl Curl_http2_dep {
    pub const fn new() -> Self {
        Curl_http2_dep {
        next: (0 as * mut crate::src::lib::http2::Curl_http2_dep),
        data: (0 as * mut crate::src::lib::http2::Curl_easy)
        }
    }
}

impl std::default::Default for Curl_http2_dep {
    fn default() -> Self { Curl_http2_dep::new() }
}

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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_khkey {
    pub key: * const i8,
    pub len: u64,
    pub keytype: u32,
}
impl curl_khkey {
    pub const fn new() -> Self {
        curl_khkey {
        key: (0 as * const i8),
        len: 0,
        keytype: 0
        }
    }
}

impl std::default::Default for curl_khkey {
    fn default() -> Self { curl_khkey::new() }
}

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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssl_general_config {
    pub max_ssl_sessions: u64,
}
impl ssl_general_config {
    pub const fn new() -> Self {
        ssl_general_config {
        max_ssl_sessions: 0
        }
    }
}

impl std::default::Default for ssl_general_config {
    fn default() -> Self { ssl_general_config::new() }
}

// #[derive(Copy, Clone, BitfieldStruct)]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssl_config_data {
    pub primary: crate::src::lib::http2::ssl_primary_config,
    pub certverifyresult: i64,
    pub CRLfile: * mut i8,
    pub fsslctx: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut core::ffi::c_void,_: * mut core::ffi::c_void,) -> u32>,
    pub fsslctxp: * mut core::ffi::c_void,
    pub cert_type: * mut i8,
    pub key: * mut i8,
    pub key_blob: * mut crate::src::lib::http2::curl_blob,
    pub key_type: * mut i8,
    pub key_passwd: * mut i8,
    pub username: * mut i8,
    pub password: * mut i8,
    pub authtype: u32,
    // #[bitfield(name = "certinfo", ty = "bit", bits = "0..=0")]
    // #[bitfield(name = "falsestart", ty = "bit", bits = "1..=1")]
    // #[bitfield(name = "enable_beast", ty = "bit", bits = "2..=2")]
    // #[bitfield(name = "no_revoke", ty = "bit", bits = "3..=3")]
    // #[bitfield(name = "no_partialchain", ty = "bit", bits = "4..=4")]
    // #[bitfield(name = "revoke_best_effort", ty = "bit", bits = "5..=5")]
    // #[bitfield(name = "native_ca_store", ty = "bit", bits = "6..=6")]
    // #[bitfield(name = "auto_client_cert", ty = "bit", bits = "7..=7")]
    pub certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert: [u8; 1],
    // #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
impl ssl_config_data {
    pub const fn new() -> Self {
        ssl_config_data {
        primary: crate::src::lib::http2::ssl_primary_config::new(),
        certverifyresult: 0,
        CRLfile: (0 as * mut i8),
        fsslctx: None,
        fsslctxp: (0 as * mut core::ffi::c_void),
        cert_type: (0 as * mut i8),
        key: (0 as * mut i8),
        key_blob: (0 as * mut crate::src::lib::http2::curl_blob),
        key_type: (0 as * mut i8),
        key_passwd: (0 as * mut i8),
        username: (0 as * mut i8),
        password: (0 as * mut i8),
        authtype: 0,
        certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert: [0,],
        c2rust_padding: [0,0,0,]
        }
    }
}

impl std::default::Default for ssl_config_data {
    fn default() -> Self { ssl_config_data::new() }
}

impl ssl_config_data {
    /// This method allows you to write to a bitfield with a value
    pub fn set_certinfo(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn certinfo(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_falsestart(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn falsestart(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_enable_beast(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert;
        let (lhs_bit, rhs_bit) = (2usize, 2usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn enable_beast(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert;
        let (lhs_bit, rhs_bit) = (2usize, 2usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_no_revoke(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert;
        let (lhs_bit, rhs_bit) = (3usize, 3usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn no_revoke(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert;
        let (lhs_bit, rhs_bit) = (3usize, 3usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_no_partialchain(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert;
        let (lhs_bit, rhs_bit) = (4usize, 4usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn no_partialchain(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert;
        let (lhs_bit, rhs_bit) = (4usize, 4usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_revoke_best_effort(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert;
        let (lhs_bit, rhs_bit) = (5usize, 5usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn revoke_best_effort(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert;
        let (lhs_bit, rhs_bit) = (5usize, 5usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_native_ca_store(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert;
        let (lhs_bit, rhs_bit) = (6usize, 6usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn native_ca_store(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert;
        let (lhs_bit, rhs_bit) = (6usize, 6usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_auto_client_cert(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert;
        let (lhs_bit, rhs_bit) = (7usize, 7usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn auto_client_cert(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert;
        let (lhs_bit, rhs_bit) = (7usize, 7usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_mimepart {
    pub easy: * mut crate::src::lib::http2::Curl_easy,
    pub parent: * mut crate::src::lib::http2::curl_mime,
    pub nextpart: * mut crate::src::lib::http2::curl_mimepart,
    pub kind: u32,
    pub flags: u32,
    pub data: * mut i8,
    pub readfunc: Option<unsafe extern "C"  fn(_: * mut i8,_: u64,_: u64,_: * mut core::ffi::c_void,) -> u64>,
    pub seekfunc: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: i64,_: i32,) -> i32>,
    pub freefunc: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>,
    pub arg: * mut core::ffi::c_void,
    pub fp: * mut crate::src::lib::http2::_IO_FILE,
    pub curlheaders: * mut crate::src::lib::http2::curl_slist,
    pub userheaders: * mut crate::src::lib::http2::curl_slist,
    pub mimetype: * mut i8,
    pub filename: * mut i8,
    pub name: * mut i8,
    pub datasize: i64,
    pub state: crate::src::lib::http2::mime_state,
    pub encoder: * const crate::src::lib::http2::mime_encoder,
    pub encstate: crate::src::lib::http2::mime_encoder_state,
    pub lastreadstatus: u64,
}
impl curl_mimepart {
    pub const fn new() -> Self {
        curl_mimepart {
        easy: (0 as * mut crate::src::lib::http2::Curl_easy),
        parent: (0 as * mut crate::src::lib::http2::curl_mime),
        nextpart: (0 as * mut crate::src::lib::http2::curl_mimepart),
        kind: 0,
        flags: 0,
        data: (0 as * mut i8),
        readfunc: None,
        seekfunc: None,
        freefunc: None,
        arg: (0 as * mut core::ffi::c_void),
        fp: (0 as * mut crate::src::lib::http2::_IO_FILE),
        curlheaders: (0 as * mut crate::src::lib::http2::curl_slist),
        userheaders: (0 as * mut crate::src::lib::http2::curl_slist),
        mimetype: (0 as * mut i8),
        filename: (0 as * mut i8),
        name: (0 as * mut i8),
        datasize: 0,
        state: crate::src::lib::http2::mime_state::new(),
        encoder: (0 as * const crate::src::lib::http2::mime_encoder),
        encstate: crate::src::lib::http2::mime_encoder_state::new(),
        lastreadstatus: 0
        }
    }
}

impl std::default::Default for curl_mimepart {
    fn default() -> Self { curl_mimepart::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct mime_encoder_state {
    pub pos: u64,
    pub bufbeg: u64,
    pub bufend: u64,
    pub buf: [i8; 256],
}
impl mime_encoder_state {
    pub const fn new() -> Self {
        mime_encoder_state {
        pos: 0,
        bufbeg: 0,
        bufend: 0,
        buf: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,]
        }
    }
}

impl std::default::Default for mime_encoder_state {
    fn default() -> Self { mime_encoder_state::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct mime_encoder {
    pub name: * const i8,
    pub encodefunc: Option<unsafe extern "C"  fn(_: * mut i8,_: u64,_: bool,_: * mut crate::src::lib::http2::curl_mimepart,) -> u64>,
    pub sizefunc: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::curl_mimepart,) -> i64>,
}
impl mime_encoder {
    pub const fn new() -> Self {
        mime_encoder {
        name: (0 as * const i8),
        encodefunc: None,
        sizefunc: None
        }
    }
}

impl std::default::Default for mime_encoder {
    fn default() -> Self { mime_encoder::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct mime_state {
    pub state: u32,
    pub ptr: * mut core::ffi::c_void,
    pub offset: i64,
}
impl mime_state {
    pub const fn new() -> Self {
        mime_state {
        state: 0,
        ptr: (0 as * mut core::ffi::c_void),
        offset: 0
        }
    }
}

impl std::default::Default for mime_state {
    fn default() -> Self { mime_state::new() }
}

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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_mime {
    pub easy: * mut crate::src::lib::http2::Curl_easy,
    pub parent: * mut crate::src::lib::http2::curl_mimepart,
    pub firstpart: * mut crate::src::lib::http2::curl_mimepart,
    pub lastpart: * mut crate::src::lib::http2::curl_mimepart,
    pub boundary: [i8; 41],
    pub state: crate::src::lib::http2::mime_state,
}
impl curl_mime {
    pub const fn new() -> Self {
        curl_mime {
        easy: (0 as * mut crate::src::lib::http2::Curl_easy),
        parent: (0 as * mut crate::src::lib::http2::curl_mimepart),
        firstpart: (0 as * mut crate::src::lib::http2::curl_mimepart),
        lastpart: (0 as * mut crate::src::lib::http2::curl_mimepart),
        boundary: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],
        state: crate::src::lib::http2::mime_state::new()
        }
    }
}

impl std::default::Default for curl_mime {
    fn default() -> Self { curl_mime::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_httppost {
    pub next: * mut crate::src::lib::http2::curl_httppost,
    pub name: * mut i8,
    pub namelength: i64,
    pub contents: * mut i8,
    pub contentslength: i64,
    pub buffer: * mut i8,
    pub bufferlength: i64,
    pub contenttype: * mut i8,
    pub contentheader: * mut crate::src::lib::http2::curl_slist,
    pub more: * mut crate::src::lib::http2::curl_httppost,
    pub flags: i64,
    pub showfilename: * mut i8,
    pub userp: * mut core::ffi::c_void,
    pub contentlen: i64,
}
impl curl_httppost {
    pub const fn new() -> Self {
        curl_httppost {
        next: (0 as * mut crate::src::lib::http2::curl_httppost),
        name: (0 as * mut i8),
        namelength: 0,
        contents: (0 as * mut i8),
        contentslength: 0,
        buffer: (0 as * mut i8),
        bufferlength: 0,
        contenttype: (0 as * mut i8),
        contentheader: (0 as * mut crate::src::lib::http2::curl_slist),
        more: (0 as * mut crate::src::lib::http2::curl_httppost),
        flags: 0,
        showfilename: (0 as * mut i8),
        userp: (0 as * mut core::ffi::c_void),
        contentlen: 0
        }
    }
}

impl std::default::Default for curl_httppost {
    fn default() -> Self { curl_httppost::new() }
}

pub type curl_hstswrite_callback<'a1, 'a2, 'a3, 'a4> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: Option<&'a2 mut crate::src::lib::http2::curl_hstsentry>,_: Option<&'a3 mut crate::src::lib::http2::curl_index>,_: Option<&'a4 mut core::ffi::c_void>,) -> u32>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_index {
    pub index: u64,
    pub total: u64,
}
impl curl_index {
    pub const fn new() -> Self {
        curl_index {
        index: 0,
        total: 0
        }
    }
}

impl std::default::Default for curl_index {
    fn default() -> Self { curl_index::new() }
}

// #[derive(Copy, Clone, BitfieldStruct)]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_hstsentry {
    pub name: * mut i8,
    pub namelen: u64,
    // #[bitfield(name = "includeSubDomains", ty = "u32", bits = "0..=0")]
    pub includeSubDomains: [u8; 1],
    pub expire: [i8; 18],
}
impl curl_hstsentry {
    pub const fn new() -> Self {
        curl_hstsentry {
        name: (0 as * mut i8),
        namelen: 0,
        includeSubDomains: [0,],
        expire: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,]
        }
    }
}

impl std::default::Default for curl_hstsentry {
    fn default() -> Self { curl_hstsentry::new() }
}

impl curl_hstsentry {
    /// This method allows you to write to a bitfield with a value
    pub fn set_includeSubDomains(&mut self, int: u32) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.includeSubDomains;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn includeSubDomains(&self) -> u32 {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.includeSubDomains;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
}
pub type CURLSTScode = u32;
pub const CURLSTS_FAIL: CURLSTScode = 2;
pub const CURLSTS_DONE: CURLSTScode = 1;
pub const CURLSTS_OK: CURLSTScode = 0;
pub type curl_hstsread_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: Option<&'a2 mut crate::src::lib::http2::curl_hstsentry>,_: Option<&'a3 mut core::ffi::c_void>,) -> u32>;
pub type curl_conv_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut i8>,_: u64,) -> u32>;
pub type curl_closesocket_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: i32,) -> i32>;
pub type curl_socket_t = i32;
pub type curl_opensocket_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: u32,_: Option<&'a2 mut crate::src::lib::http2::curl_sockaddr>,) -> i32>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_sockaddr {
    pub family: i32,
    pub socktype: i32,
    pub protocol: i32,
    pub addrlen: u32,
    pub addr: crate::src::lib::http2::sockaddr,
}
impl curl_sockaddr {
    pub const fn new() -> Self {
        curl_sockaddr {
        family: 0,
        socktype: 0,
        protocol: 0,
        addrlen: 0,
        addr: crate::src::lib::http2::sockaddr::new()
        }
    }
}

impl std::default::Default for curl_sockaddr {
    fn default() -> Self { curl_sockaddr::new() }
}

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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SingleRequest {
    pub size: i64,
    pub maxdownload: i64,
    pub bytecount: i64,
    pub writebytecount: i64,
    pub headerbytecount: i64,
    pub deductheadercount: i64,
    pub pendingheader: i64,
    pub start: crate::src::lib::http2::curltime,
    pub now: crate::src::lib::http2::curltime,
    pub badheader: u32,
    pub headerline: i32,
    pub str_0: * mut i8,
    pub offset: i64,
    pub httpcode: i32,
    pub keepon: i32,
    pub start100: crate::src::lib::http2::curltime,
    pub exp100: u32,
    pub upgr101: u32,
    pub writer_stack: * mut crate::src::lib::content_encoding::contenc_writer,
    pub timeofdoc: i64,
    pub bodywrites: i64,
    pub location: * mut i8,
    pub newurl: * mut i8,
    pub upload_present: i64,
    pub upload_fromhere: * mut i8,
    pub p: crate::src::lib::http2::C2RustUnnamed,
    pub doh: * mut crate::src::lib::http2::dohdata,
    // #[bitfield(name = "header", ty = "bit", bits = "0..=0")]
    // #[bitfield(name = "content_range", ty = "bit", bits = "1..=1")]
    // #[bitfield(name = "upload_done", ty = "bit", bits = "2..=2")]
    // #[bitfield(name = "ignorebody", ty = "bit", bits = "3..=3")]
    // #[bitfield(name = "http_bodyless", ty = "bit", bits = "4..=4")]
    // #[bitfield(name = "chunk", ty = "bit", bits = "5..=5")]
    // #[bitfield(name = "ignore_cl", ty = "bit", bits = "6..=6")]
    // #[bitfield(name = "upload_chunky", ty = "bit", bits = "7..=7")]
    // #[bitfield(name = "getheader", ty = "bit", bits = "8..=8")]
    // #[bitfield(name = "forbidchunk", ty = "bit", bits = "9..=9")]
    pub header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk: [u8; 2],
    // #[bitfield(padding)]
    pub c2rust_padding: [u8; 6],
}
impl SingleRequest {
    /// This method allows you to write to a bitfield with a value
    pub fn set_header(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn header(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_content_range(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn content_range(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_upload_done(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (2usize, 2usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn upload_done(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (2usize, 2usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ignorebody(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (3usize, 3usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ignorebody(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (3usize, 3usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_http_bodyless(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (4usize, 4usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn http_bodyless(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (4usize, 4usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_chunk(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (5usize, 5usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn chunk(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (5usize, 5usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ignore_cl(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (6usize, 6usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ignore_cl(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (6usize, 6usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_upload_chunky(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (7usize, 7usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn upload_chunky(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (7usize, 7usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_getheader(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (8usize, 8usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn getheader(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (8usize, 8usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_forbidchunk(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (9usize, 9usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn forbidchunk(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk;
        let (lhs_bit, rhs_bit) = (9usize, 9usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dohdata {
    pub headers: * mut crate::src::lib::http2::curl_slist,
    pub probe: [crate::src::lib::http2::dnsprobe; 2],
    pub pending: u32,
    pub port: i32,
    pub host: * const i8,
}
impl dohdata {
    pub const fn new() -> Self {
        dohdata {
        headers: (0 as * mut crate::src::lib::http2::curl_slist),
        probe: [crate::src::lib::http2::dnsprobe::new(),crate::src::lib::http2::dnsprobe::new(),],
        pending: 0,
        port: 0,
        host: (0 as * const i8)
        }
    }
}

impl std::default::Default for dohdata {
    fn default() -> Self { dohdata::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct dnsprobe {
    pub easy: * mut crate::src::lib::http2::Curl_easy,
    pub dnstype: i32,
    pub dohbuffer: [u8; 512],
    pub dohlen: u64,
    pub serverdoh: crate::src::lib::http2::dynbuf,
}
impl dnsprobe {
    pub const fn new() -> Self {
        dnsprobe {
        easy: (0 as * mut crate::src::lib::http2::Curl_easy),
        dnstype: 0,
        dohbuffer: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],
        dohlen: 0,
        serverdoh: crate::src::lib::http2::dynbuf::new()
        }
    }
}

impl std::default::Default for dnsprobe {
    fn default() -> Self { dnsprobe::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub file: *mut FILEPROTO,
    pub ftp: *mut FTP,
    pub http: *mut HTTP,
    pub imap: *mut IMAP,
    pub ldap: *mut ldapreqinfo,
    pub mqtt: *mut MQTT,
    pub pop3: *mut POP3,
    pub rtsp: *mut RTSP,
    pub smb: *mut smb_request,
    pub smtp: *mut SMTP,
    pub ssh: *mut SSHPROTO,
    pub telnet: *mut TELNET,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SSHPROTO {
    pub path: * mut i8,
}
impl SSHPROTO {
    pub const fn new() -> Self {
        SSHPROTO {
        path: (0 as * mut i8)
        }
    }
}

impl std::default::Default for SSHPROTO {
    fn default() -> Self { SSHPROTO::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct SMTP {
    pub transfer: u32,
    pub custom: * mut i8,
    pub rcpt: * mut crate::src::lib::http2::curl_slist,
    pub rcpt_had_ok: bool,
    pub trailing_crlf: bool,
    pub rcpt_last_error: i32,
    pub eob: u64,
}
impl SMTP {
    pub const fn new() -> Self {
        SMTP {
        transfer: 0,
        custom: (0 as * mut i8),
        rcpt: (0 as * mut crate::src::lib::http2::curl_slist),
        rcpt_had_ok: false,
        trailing_crlf: false,
        rcpt_last_error: 0,
        eob: 0
        }
    }
}

impl std::default::Default for SMTP {
    fn default() -> Self { SMTP::new() }
}

pub type curl_pp_transfer = u32;
pub const PPTRANSFER_NONE: curl_pp_transfer = 2;
pub const PPTRANSFER_INFO: curl_pp_transfer = 1;
pub const PPTRANSFER_BODY: curl_pp_transfer = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct RTSP {
    pub http_wrapper: crate::src::lib::http2::HTTP,
    pub CSeq_sent: i64,
    pub CSeq_recv: i64,
}
impl RTSP {
    pub const fn new() -> Self {
        RTSP {
        http_wrapper: crate::src::lib::http2::HTTP::new(),
        CSeq_sent: 0,
        CSeq_recv: 0
        }
    }
}

impl std::default::Default for RTSP {
    fn default() -> Self { RTSP::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct HTTP {
    pub sendit: * mut crate::src::lib::http2::curl_mimepart,
    pub postsize: i64,
    pub postdata: * const i8,
    pub p_pragma: * const i8,
    pub form: crate::src::lib::http2::curl_mimepart,
    pub backup: crate::src::lib::http2::back,
    pub sending: u32,
    pub send_buffer: crate::src::lib::http2::dynbuf,
    pub stream_id: i32,
    pub bodystarted: bool,
    pub header_recvbuf: crate::src::lib::http2::dynbuf,
    pub nread_header_recvbuf: u64,
    pub trailer_recvbuf: crate::src::lib::http2::dynbuf,
    pub status_code: i32,
    pub pausedata: * const u8,
    pub pauselen: u64,
    pub close_handled: bool,
    pub push_headers: * mut * mut i8,
    pub push_headers_used: u64,
    pub push_headers_alloc: u64,
    pub error: u32,
    pub closed: bool,
    pub mem: * mut i8,
    pub len: u64,
    pub memlen: u64,
    pub upload_mem: * const u8,
    pub upload_len: u64,
    pub upload_left: i64,
}
impl HTTP {
    pub const fn new() -> Self {
        HTTP {
        sendit: (0 as * mut crate::src::lib::http2::curl_mimepart),
        postsize: 0,
        postdata: (0 as * const i8),
        p_pragma: (0 as * const i8),
        form: crate::src::lib::http2::curl_mimepart::new(),
        backup: crate::src::lib::http2::back::new(),
        sending: 0,
        send_buffer: crate::src::lib::http2::dynbuf::new(),
        stream_id: 0,
        bodystarted: false,
        header_recvbuf: crate::src::lib::http2::dynbuf::new(),
        nread_header_recvbuf: 0,
        trailer_recvbuf: crate::src::lib::http2::dynbuf::new(),
        status_code: 0,
        pausedata: (0 as * const u8),
        pauselen: 0,
        close_handled: false,
        push_headers: (0 as * mut * mut i8),
        push_headers_used: 0,
        push_headers_alloc: 0,
        error: 0,
        closed: false,
        mem: (0 as * mut i8),
        len: 0,
        memlen: 0,
        upload_mem: (0 as * const u8),
        upload_len: 0,
        upload_left: 0
        }
    }
}

impl std::default::Default for HTTP {
    fn default() -> Self { HTTP::new() }
}

pub type uint8_t = u8;
pub type uint32_t = u32;
pub type C2RustUnnamed_0 = u32;
pub const HTTPSEND_BODY: C2RustUnnamed_0 = 2;
pub const HTTPSEND_REQUEST: C2RustUnnamed_0 = 1;
pub const HTTPSEND_NADA: C2RustUnnamed_0 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct back {
    pub fread_func: Option<unsafe extern "C"  fn(_: * mut i8,_: u64,_: u64,_: * mut core::ffi::c_void,) -> u64>,
    pub fread_in: * mut core::ffi::c_void,
    pub postdata: * const i8,
    pub postsize: i64,
}
impl back {
    pub const fn new() -> Self {
        back {
        fread_func: None,
        fread_in: (0 as * mut core::ffi::c_void),
        postdata: (0 as * const i8),
        postsize: 0
        }
    }
}

impl std::default::Default for back {
    fn default() -> Self { back::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct POP3 {
    pub transfer: u32,
    pub id: * mut i8,
    pub custom: * mut i8,
}
impl POP3 {
    pub const fn new() -> Self {
        POP3 {
        transfer: 0,
        id: (0 as * mut i8),
        custom: (0 as * mut i8)
        }
    }
}

impl std::default::Default for POP3 {
    fn default() -> Self { POP3::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct MQTT {
    pub sendleftovers: * mut i8,
    pub nsend: u64,
    pub npacket: u64,
    pub firstbyte: u8,
    pub remaining_length: u64,
}
impl MQTT {
    pub const fn new() -> Self {
        MQTT {
        sendleftovers: (0 as * mut i8),
        nsend: 0,
        npacket: 0,
        firstbyte: 0,
        remaining_length: 0
        }
    }
}

impl std::default::Default for MQTT {
    fn default() -> Self { MQTT::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct IMAP {
    pub transfer: u32,
    pub mailbox: * mut i8,
    pub uidvalidity: * mut i8,
    pub uid: * mut i8,
    pub mindex: * mut i8,
    pub section: * mut i8,
    pub partial: * mut i8,
    pub query: * mut i8,
    pub custom: * mut i8,
    pub custom_params: * mut i8,
}
impl IMAP {
    pub const fn new() -> Self {
        IMAP {
        transfer: 0,
        mailbox: (0 as * mut i8),
        uidvalidity: (0 as * mut i8),
        uid: (0 as * mut i8),
        mindex: (0 as * mut i8),
        section: (0 as * mut i8),
        partial: (0 as * mut i8),
        query: (0 as * mut i8),
        custom: (0 as * mut i8),
        custom_params: (0 as * mut i8)
        }
    }
}

impl std::default::Default for IMAP {
    fn default() -> Self { IMAP::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct FTP {
    pub path: * mut i8,
    pub pathalloc: * mut i8,
    pub transfer: u32,
    pub downloadsize: i64,
}
impl FTP {
    pub const fn new() -> Self {
        FTP {
        path: (0 as * mut i8),
        pathalloc: (0 as * mut i8),
        transfer: 0,
        downloadsize: 0
        }
    }
}

impl std::default::Default for FTP {
    fn default() -> Self { FTP::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct FILEPROTO {
    pub path: * mut i8,
    pub freepath: * mut i8,
    pub fd: i32,
}
impl FILEPROTO {
    pub const fn new() -> Self {
        FILEPROTO {
        path: (0 as * mut i8),
        freepath: (0 as * mut i8),
        fd: 0
        }
    }
}

impl std::default::Default for FILEPROTO {
    fn default() -> Self { FILEPROTO::new() }
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PslCache {
    pub psl: * const crate::src::lib::urlapi::psl_ctx_st,
    pub expires: i64,
    pub dynamic: bool,
}
impl PslCache {
    pub const fn new() -> Self {
        PslCache {
        psl: (0 as * const crate::src::lib::urlapi::psl_ctx_st),
        expires: 0,
        dynamic: false
        }
    }
}

impl std::default::Default for PslCache {
    fn default() -> Self { PslCache::new() }
}

pub type psl_ctx_t = crate::src::lib::urlapi::psl_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_multi {
    pub magic: u32,
    pub easyp: * mut crate::src::lib::http2::Curl_easy,
    pub easylp: * mut crate::src::lib::http2::Curl_easy,
    pub num_easy: i32,
    pub num_alive: i32,
    pub msglist: crate::src::lib::http2::Curl_llist,
    pub pending: crate::src::lib::http2::Curl_llist,
    pub socket_cb: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: i32,_: i32,_: * mut core::ffi::c_void,_: * mut core::ffi::c_void,) -> i32>,
    pub socket_userp: * mut core::ffi::c_void,
    pub push_cb: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut crate::src::lib::http2::Curl_easy,_: u64,_: * mut crate::src::lib::http2::curl_pushheaders,_: * mut core::ffi::c_void,) -> i32>,
    pub push_userp: * mut core::ffi::c_void,
    pub hostcache: crate::src::lib::http2::Curl_hash,
    pub psl: crate::src::lib::http2::PslCache,
    pub timetree: * mut crate::src::lib::http2::Curl_tree,
    pub sockhash: crate::src::lib::http2::Curl_hash,
    pub conn_cache: crate::src::lib::http2::conncache,
    pub maxconnects: i64,
    pub max_host_connections: i64,
    pub max_total_connections: i64,
    pub timer_cb: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_multi,_: i64,_: * mut core::ffi::c_void,) -> i32>,
    pub timer_userp: * mut core::ffi::c_void,
    pub timer_lastcall: crate::src::lib::http2::curltime,
    pub max_concurrent_streams: u32,
    pub wakeup_pair: [i32; 2],
    pub multiplexing: bool,
    pub recheckstate: bool,
    pub in_callback: bool,
    pub ipv6_works: bool,
    pub ssl_seeded: bool,
}
impl Curl_multi {
    pub const fn new() -> Self {
        Curl_multi {
        magic: 0,
        easyp: (0 as * mut crate::src::lib::http2::Curl_easy),
        easylp: (0 as * mut crate::src::lib::http2::Curl_easy),
        num_easy: 0,
        num_alive: 0,
        msglist: crate::src::lib::http2::Curl_llist::new(),
        pending: crate::src::lib::http2::Curl_llist::new(),
        socket_cb: None,
        socket_userp: (0 as * mut core::ffi::c_void),
        push_cb: None,
        push_userp: (0 as * mut core::ffi::c_void),
        hostcache: crate::src::lib::http2::Curl_hash::new(),
        psl: crate::src::lib::http2::PslCache::new(),
        timetree: (0 as * mut crate::src::lib::http2::Curl_tree),
        sockhash: crate::src::lib::http2::Curl_hash::new(),
        conn_cache: crate::src::lib::http2::conncache::new(),
        maxconnects: 0,
        max_host_connections: 0,
        max_total_connections: 0,
        timer_cb: None,
        timer_userp: (0 as * mut core::ffi::c_void),
        timer_lastcall: crate::src::lib::http2::curltime::new(),
        max_concurrent_streams: 0,
        wakeup_pair: [0,0,],
        multiplexing: false,
        recheckstate: false,
        in_callback: false,
        ipv6_works: false,
        ssl_seeded: false
        }
    }
}

impl std::default::Default for Curl_multi {
    fn default() -> Self { Curl_multi::new() }
}

pub type curl_multi_timer_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_multi>,_: i64,_: Option<&'a2 mut core::ffi::c_void>,) -> i32>;
pub type CURLM = crate::src::lib::http2::Curl_multi;
pub type curl_push_callback<'a1, 'a2, 'a3, 'a4> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: Option<&'a2 mut crate::src::lib::http2::Curl_easy>,_: u64,_: Option<&'a3 mut crate::src::lib::http2::curl_pushheaders>,_: Option<&'a4 mut core::ffi::c_void>,) -> i32>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_pushheaders {
    pub data: * mut crate::src::lib::http2::Curl_easy,
    pub frame: * const crate::src::lib::http2::nghttp2_push_promise,
}
impl curl_pushheaders {
    pub const fn new() -> Self {
        curl_pushheaders {
        data: (0 as * mut crate::src::lib::http2::Curl_easy),
        frame: (0 as * const crate::src::lib::http2::nghttp2_push_promise)
        }
    }
}

impl std::default::Default for curl_pushheaders {
    fn default() -> Self { curl_pushheaders::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_push_promise {
    pub hd: crate::src::lib::http2::nghttp2_frame_hd,
    pub padlen: u64,
    pub nva: * mut crate::src::lib::http2::nghttp2_nv,
    pub nvlen: u64,
    pub promised_stream_id: i32,
    pub reserved: u8,
}
impl nghttp2_push_promise {
    pub const fn new() -> Self {
        nghttp2_push_promise {
        hd: crate::src::lib::http2::nghttp2_frame_hd::new(),
        padlen: 0,
        nva: (0 as * mut crate::src::lib::http2::nghttp2_nv),
        nvlen: 0,
        promised_stream_id: 0,
        reserved: 0
        }
    }
}

impl std::default::Default for nghttp2_push_promise {
    fn default() -> Self { nghttp2_push_promise::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_nv {
    pub name: * mut u8,
    pub value: * mut u8,
    pub namelen: u64,
    pub valuelen: u64,
    pub flags: u8,
}
impl nghttp2_nv {
    pub const fn new() -> Self {
        nghttp2_nv {
        name: (0 as * mut u8),
        value: (0 as * mut u8),
        namelen: 0,
        valuelen: 0,
        flags: 0
        }
    }
}

impl std::default::Default for nghttp2_nv {
    fn default() -> Self { nghttp2_nv::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_frame_hd {
    pub length: u64,
    pub stream_id: i32,
    pub type_0: u8,
    pub flags: u8,
    pub reserved: u8,
}
impl nghttp2_frame_hd {
    pub const fn new() -> Self {
        nghttp2_frame_hd {
        length: 0,
        stream_id: 0,
        type_0: 0,
        flags: 0,
        reserved: 0
        }
    }
}

impl std::default::Default for nghttp2_frame_hd {
    fn default() -> Self { nghttp2_frame_hd::new() }
}

pub type curl_socket_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: i32,_: i32,_: Option<&'a2 mut core::ffi::c_void>,_: Option<&'a3 mut core::ffi::c_void>,) -> i32>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Names {
    pub hostcache: * mut crate::src::lib::http2::Curl_hash,
    pub hostcachetype: u32,
}
impl Names {
    pub const fn new() -> Self {
        Names {
        hostcache: (0 as * mut crate::src::lib::http2::Curl_hash),
        hostcachetype: 0
        }
    }
}

impl std::default::Default for Names {
    fn default() -> Self { Names::new() }
}

pub type C2RustUnnamed_2 = u32;
pub const HCACHE_SHARED: C2RustUnnamed_2 = 2;
pub const HCACHE_MULTI: C2RustUnnamed_2 = 1;
pub const HCACHE_NONE: C2RustUnnamed_2 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_message {
    pub list: crate::src::lib::http2::Curl_llist_element,
    pub extmsg: crate::src::lib::http2::CURLMsg,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CURLMsg {
    pub msg: u32,
    pub easy_handle: * mut crate::src::lib::http2::Curl_easy,
    pub data: crate::src::lib::http2::C2RustUnnamed_3,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_3 {
    pub whatever: *mut libc::c_void,
    pub result: CURLcode,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct connectdata {
    pub cnnct: crate::src::lib::http2::connstate,
    pub bundle_node: crate::src::lib::http2::Curl_llist_element,
    pub chunk: crate::src::lib::http2::Curl_chunker,
    pub fclosesocket: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: i32,) -> i32>,
    pub closesocket_client: * mut core::ffi::c_void,
    pub connection_id: i64,
    pub dns_entry: * mut crate::src::lib::http2::Curl_dns_entry,
    pub ip_addr: * mut crate::src::lib::http2::Curl_addrinfo,
    pub tempaddr: [* mut crate::src::lib::http2::Curl_addrinfo; 2],
    pub scope_id: u32,
    pub transport: u32,
    pub host: crate::src::lib::http2::hostname,
    pub hostname_resolve: * mut i8,
    pub secondaryhostname: * mut i8,
    pub conn_to_host: crate::src::lib::http2::hostname,
    pub socks_proxy: crate::src::lib::http2::proxy_info,
    pub http_proxy: crate::src::lib::http2::proxy_info,
    pub port: i32,
    pub remote_port: i32,
    pub conn_to_port: i32,
    pub secondary_port: u16,
    pub primary_ip: [i8; 46],
    pub ip_version: u8,
    pub user: * mut i8,
    pub passwd: * mut i8,
    pub options: * mut i8,
    pub sasl_authzid: * mut i8,
    pub httpversion: u8,
    pub now: crate::src::lib::http2::curltime,
    pub created: crate::src::lib::http2::curltime,
    pub lastused: crate::src::lib::http2::curltime,
    pub sock: [i32; 2],
    pub tempsock: [i32; 2],
    pub tempfamily: [i32; 2],
    pub recv: [Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: i32,_: * mut i8,_: u64,_: * mut u32,) -> i64>; 2],
    pub send: [Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: i32,_: * const core::ffi::c_void,_: u64,_: * mut u32,) -> i64>; 2],
    pub ssl: [crate::src::lib::http2::ssl_connect_data; 2],
    pub proxy_ssl: [crate::src::lib::http2::ssl_connect_data; 2],
    pub ssl_extra: * mut core::ffi::c_void,
    pub ssl_config: crate::src::lib::http2::ssl_primary_config,
    pub proxy_ssl_config: crate::src::lib::http2::ssl_primary_config,
    pub bits: crate::src::lib::http2::ConnectBits,
    pub num_addr: i32,
    pub connecttime: crate::src::lib::http2::curltime,
    pub timeoutms_per_addr: [i64; 2],
    pub handler: * const crate::src::lib::http2::Curl_handler,
    pub given: * const crate::src::lib::http2::Curl_handler,
    pub keepalive: crate::src::lib::http2::curltime,
    pub sockfd: i32,
    pub writesockfd: i32,
    pub easyq: crate::src::lib::http2::Curl_llist,
    pub seek_func: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: i64,_: i32,) -> i32>,
    pub seek_client: * mut core::ffi::c_void,
    pub gsasl: crate::src::lib::http2::gsasldata,
    pub http_ntlm_state: u32,
    pub proxy_ntlm_state: u32,
    pub ntlm: crate::src::lib::http2::ntlmdata,
    pub proxyntlm: crate::src::lib::http2::ntlmdata,
    pub trailer: crate::src::lib::http2::dynbuf,
    pub proto: crate::src::lib::http2::C2RustUnnamed_4,
    pub connect_state: * mut crate::src::lib::ftp::http_connect_state,
    pub bundle: * mut crate::src::lib::http2::connectbundle,
    pub unix_domain_socket: * mut i8,
    pub localdev: * mut i8,
    pub localportrange: i32,
    pub cselect_bits: i32,
    pub waitfor: i32,
    pub negnpn: i32,
    pub localport: u16,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct connectbundle {
    pub multiuse: i32,
    pub num_connections: u64,
    pub conn_list: crate::src::lib::http2::Curl_llist,
}
impl connectbundle {
    pub const fn new() -> Self {
        connectbundle {
        multiuse: 0,
        num_connections: 0,
        conn_list: crate::src::lib::http2::Curl_llist::new()
        }
    }
}

impl std::default::Default for connectbundle {
    fn default() -> Self { connectbundle::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_4 {
    pub ftpc: ftp_conn,
    pub httpc: http_conn,
    pub sshc: ssh_conn,
    pub tftpc: *mut tftp_state_data,
    pub imapc: imap_conn,
    pub pop3c: pop3_conn,
    pub smtpc: smtp_conn,
    pub rtspc: rtsp_conn,
    pub smbc: smb_conn,
    pub rtmp: *mut libc::c_void,
    pub ldapc: *mut ldapconninfo,
    pub mqtt: mqtt_conn,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mqtt_conn {
    pub state: u32,
    pub nextstate: u32,
    pub packetid: u32,
}
impl mqtt_conn {
    pub const fn new() -> Self {
        mqtt_conn {
        state: 0,
        nextstate: 0,
        packetid: 0
        }
    }
}

impl std::default::Default for mqtt_conn {
    fn default() -> Self { mqtt_conn::new() }
}

pub type mqttstate = u32;
pub const MQTT_NOSTATE: mqttstate = 7;
pub const MQTT_PUB_REMAIN: mqttstate = 6;
pub const MQTT_PUBWAIT: mqttstate = 5;
pub const MQTT_SUBACK_COMING: mqttstate = 4;
pub const MQTT_SUBACK: mqttstate = 3;
pub const MQTT_CONNACK: mqttstate = 2;
pub const MQTT_REMAINING_LENGTH: mqttstate = 1;
pub const MQTT_FIRST: mqttstate = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct smb_conn {
    pub state: u32,
    pub user: * mut i8,
    pub domain: * mut i8,
    pub share: * mut i8,
    pub challenge: [u8; 8],
    pub session_key: u32,
    pub uid: u16,
    pub recv_buf: * mut i8,
    pub upload_size: u64,
    pub send_size: u64,
    pub sent: u64,
    pub got: u64,
}
impl smb_conn {
    pub const fn new() -> Self {
        smb_conn {
        state: 0,
        user: (0 as * mut i8),
        domain: (0 as * mut i8),
        share: (0 as * mut i8),
        challenge: [0,0,0,0,0,0,0,0,],
        session_key: 0,
        uid: 0,
        recv_buf: (0 as * mut i8),
        upload_size: 0,
        send_size: 0,
        sent: 0,
        got: 0
        }
    }
}

impl std::default::Default for smb_conn {
    fn default() -> Self { smb_conn::new() }
}

pub type smb_conn_state = u32;
pub const SMB_CONNECTED: smb_conn_state = 4;
pub const SMB_SETUP: smb_conn_state = 3;
pub const SMB_NEGOTIATE: smb_conn_state = 2;
pub const SMB_CONNECTING: smb_conn_state = 1;
pub const SMB_NOT_CONNECTED: smb_conn_state = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rtsp_conn {
    pub rtp_buf: * mut i8,
    pub rtp_bufsize: i64,
    pub rtp_channel: i32,
}
impl rtsp_conn {
    pub const fn new() -> Self {
        rtsp_conn {
        rtp_buf: (0 as * mut i8),
        rtp_bufsize: 0,
        rtp_channel: 0
        }
    }
}

impl std::default::Default for rtsp_conn {
    fn default() -> Self { rtsp_conn::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct smtp_conn {
    pub pp: crate::src::lib::http2::pingpong,
    pub state: u32,
    pub ssldone: bool,
    pub domain: * mut i8,
    pub sasl: crate::src::lib::http2::SASL,
    pub tls_supported: bool,
    pub size_supported: bool,
    pub utf8_supported: bool,
    pub auth_supported: bool,
}
impl smtp_conn {
    pub const fn new() -> Self {
        smtp_conn {
        pp: crate::src::lib::http2::pingpong::new(),
        state: 0,
        ssldone: false,
        domain: (0 as * mut i8),
        sasl: crate::src::lib::http2::SASL::new(),
        tls_supported: false,
        size_supported: false,
        utf8_supported: false,
        auth_supported: false
        }
    }
}

impl std::default::Default for smtp_conn {
    fn default() -> Self { smtp_conn::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct SASL {
    pub params: * const crate::src::lib::http2::SASLproto,
    pub state: u32,
    pub authmechs: u16,
    pub prefmech: u16,
    pub authused: u16,
    pub resetprefs: bool,
    pub mutual_auth: bool,
    pub force_ir: bool,
}
impl SASL {
    pub const fn new() -> Self {
        SASL {
        params: (0 as * const crate::src::lib::http2::SASLproto),
        state: 0,
        authmechs: 0,
        prefmech: 0,
        authused: 0,
        resetprefs: false,
        mutual_auth: false,
        force_ir: false
        }
    }
}

impl std::default::Default for SASL {
    fn default() -> Self { SASL::new() }
}

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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SASLproto {
    pub service: * const i8,
    pub contcode: i32,
    pub finalcode: i32,
    pub maxirlen: u64,
    pub sendauth: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut crate::src::lib::http2::connectdata,_: * const i8,_: * const i8,) -> u32>,
    pub sendcont: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut crate::src::lib::http2::connectdata,_: * const i8,) -> u32>,
    pub getmessage: Option<unsafe extern "C"  fn(_: * mut i8,_: * mut * mut i8,) -> ()>,
}
impl SASLproto {
    pub const fn new() -> Self {
        SASLproto {
        service: (0 as * const i8),
        contcode: 0,
        finalcode: 0,
        maxirlen: 0,
        sendauth: None,
        sendcont: None,
        getmessage: None
        }
    }
}

impl std::default::Default for SASLproto {
    fn default() -> Self { SASLproto::new() }
}

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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pingpong {
    pub cache: * mut i8,
    pub cache_size: u64,
    pub nread_resp: u64,
    pub linestart_resp: * mut i8,
    pub pending_resp: bool,
    pub sendthis: * mut i8,
    pub sendleft: u64,
    pub sendsize: u64,
    pub response: crate::src::lib::http2::curltime,
    pub response_time: i64,
    pub sendbuf: crate::src::lib::http2::dynbuf,
    pub statemachine: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut crate::src::lib::http2::connectdata,) -> u32>,
    pub endofresp: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut crate::src::lib::http2::connectdata,_: * mut i8,_: u64,_: * mut i32,) -> bool>,
}
impl pingpong {
    pub const fn new() -> Self {
        pingpong {
        cache: (0 as * mut i8),
        cache_size: 0,
        nread_resp: 0,
        linestart_resp: (0 as * mut i8),
        pending_resp: false,
        sendthis: (0 as * mut i8),
        sendleft: 0,
        sendsize: 0,
        response: crate::src::lib::http2::curltime::new(),
        response_time: 0,
        sendbuf: crate::src::lib::http2::dynbuf::new(),
        statemachine: None,
        endofresp: None
        }
    }
}

impl std::default::Default for pingpong {
    fn default() -> Self { pingpong::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct pop3_conn {
    pub pp: crate::src::lib::http2::pingpong,
    pub state: u32,
    pub ssldone: bool,
    pub tls_supported: bool,
    pub eob: u64,
    pub strip: u64,
    pub sasl: crate::src::lib::http2::SASL,
    pub authtypes: u32,
    pub preftype: u32,
    pub apoptimestamp: * mut i8,
}
impl pop3_conn {
    pub const fn new() -> Self {
        pop3_conn {
        pp: crate::src::lib::http2::pingpong::new(),
        state: 0,
        ssldone: false,
        tls_supported: false,
        eob: 0,
        strip: 0,
        sasl: crate::src::lib::http2::SASL::new(),
        authtypes: 0,
        preftype: 0,
        apoptimestamp: (0 as * mut i8)
        }
    }
}

impl std::default::Default for pop3_conn {
    fn default() -> Self { pop3_conn::new() }
}

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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct imap_conn {
    pub pp: crate::src::lib::http2::pingpong,
    pub state: u32,
    pub ssldone: bool,
    pub preauth: bool,
    pub sasl: crate::src::lib::http2::SASL,
    pub preftype: u32,
    pub cmdid: u32,
    pub resptag: [i8; 5],
    pub tls_supported: bool,
    pub login_disabled: bool,
    pub ir_supported: bool,
    pub mailbox: * mut i8,
    pub mailbox_uidvalidity: * mut i8,
    pub dyn_0: crate::src::lib::http2::dynbuf,
}
impl imap_conn {
    pub const fn new() -> Self {
        imap_conn {
        pp: crate::src::lib::http2::pingpong::new(),
        state: 0,
        ssldone: false,
        preauth: false,
        sasl: crate::src::lib::http2::SASL::new(),
        preftype: 0,
        cmdid: 0,
        resptag: [0,0,0,0,0,],
        tls_supported: false,
        login_disabled: false,
        ir_supported: false,
        mailbox: (0 as * mut i8),
        mailbox_uidvalidity: (0 as * mut i8),
        dyn_0: crate::src::lib::http2::dynbuf::new()
        }
    }
}

impl std::default::Default for imap_conn {
    fn default() -> Self { imap_conn::new() }
}

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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssh_conn {
    pub authlist: * const i8,
    pub passphrase: * const i8,
    pub rsa_pub: * mut i8,
    pub rsa: * mut i8,
    pub authed: bool,
    pub acceptfail: bool,
    pub state: i32,
    pub nextstate: i32,
    pub actualcode: u32,
    pub quote_item: * mut crate::src::lib::http2::curl_slist,
    pub quote_path1: * mut i8,
    pub quote_path2: * mut i8,
    pub homedir: * mut i8,
    pub readdir_line: * mut i8,
    pub secondCreateDirs: i32,
    pub orig_waitfor: i32,
    pub slash_pos: * mut i8,
}
impl ssh_conn {
    pub const fn new() -> Self {
        ssh_conn {
        authlist: (0 as * const i8),
        passphrase: (0 as * const i8),
        rsa_pub: (0 as * mut i8),
        rsa: (0 as * mut i8),
        authed: false,
        acceptfail: false,
        state: 0,
        nextstate: 0,
        actualcode: 0,
        quote_item: (0 as * mut crate::src::lib::http2::curl_slist),
        quote_path1: (0 as * mut i8),
        quote_path2: (0 as * mut i8),
        homedir: (0 as * mut i8),
        readdir_line: (0 as * mut i8),
        secondCreateDirs: 0,
        orig_waitfor: 0,
        slash_pos: (0 as * mut i8)
        }
    }
}

impl std::default::Default for ssh_conn {
    fn default() -> Self { ssh_conn::new() }
}

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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct http_conn {
    pub binsettings: [u8; 80],
    pub binlen: u64,
    pub trnsfr: * mut crate::src::lib::http2::Curl_easy,
    pub h2: * mut crate::src::lib::speedcheck::nghttp2_session,
    pub send_underlying: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: i32,_: * const core::ffi::c_void,_: u64,_: * mut u32,) -> i64>,
    pub recv_underlying: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: i32,_: * mut i8,_: u64,_: * mut u32,) -> i64>,
    pub inbuf: * mut i8,
    pub inbuflen: u64,
    pub nread_inbuf: u64,
    pub pause_stream_id: i32,
    pub drain_total: u64,
    pub settings: crate::src::lib::http2::h2settings,
    pub local_settings: [crate::src::lib::http2::nghttp2_settings_entry; 3],
    pub local_settings_num: u64,
}
impl http_conn {
    pub const fn new() -> Self {
        http_conn {
        binsettings: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],
        binlen: 0,
        trnsfr: (0 as * mut crate::src::lib::http2::Curl_easy),
        h2: (0 as * mut crate::src::lib::speedcheck::nghttp2_session),
        send_underlying: None,
        recv_underlying: None,
        inbuf: (0 as * mut i8),
        inbuflen: 0,
        nread_inbuf: 0,
        pause_stream_id: 0,
        drain_total: 0,
        settings: crate::src::lib::http2::h2settings::new(),
        local_settings: [crate::src::lib::http2::nghttp2_settings_entry::new(),crate::src::lib::http2::nghttp2_settings_entry::new(),crate::src::lib::http2::nghttp2_settings_entry::new(),],
        local_settings_num: 0
        }
    }
}

impl std::default::Default for http_conn {
    fn default() -> Self { http_conn::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_settings_entry {
    pub settings_id: i32,
    pub value: u32,
}
impl nghttp2_settings_entry {
    pub const fn new() -> Self {
        nghttp2_settings_entry {
        settings_id: 0,
        value: 0
        }
    }
}

impl std::default::Default for nghttp2_settings_entry {
    fn default() -> Self { nghttp2_settings_entry::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct h2settings {
    pub max_concurrent_streams: u32,
    pub enable_push: bool,
}
impl h2settings {
    pub const fn new() -> Self {
        h2settings {
        max_concurrent_streams: 0,
        enable_push: false
        }
    }
}

impl std::default::Default for h2settings {
    fn default() -> Self { h2settings::new() }
}

pub type Curl_recv<'a1, 'a2, 'a3> = unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: i32,_: Option<&'a2 mut i8>,_: u64,_: Option<&'a3 mut u32>,) -> i64;
pub type Curl_send<'a1, 'a2, 'a3> = unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,_: i32,_: Option<&'a2 core::ffi::c_void>,_: u64,_: Option<&'a3 mut u32>,) -> i64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ftp_conn {
    pub pp: crate::src::lib::http2::pingpong,
    pub entrypath: * mut i8,
    pub file: * mut i8,
    pub dirs: * mut * mut i8,
    pub dirdepth: i32,
    pub dont_check: bool,
    pub ctl_valid: bool,
    pub cwddone: bool,
    pub cwdcount: i32,
    pub cwdfail: bool,
    pub wait_data_conn: bool,
    pub newport: u16,
    pub newhost: * mut i8,
    pub prevpath: * mut i8,
    pub transfertype: i8,
    pub count1: i32,
    pub count2: i32,
    pub count3: i32,
    pub state: u32,
    pub state_saved: u32,
    pub retr_size_saved: i64,
    pub server_os: * mut i8,
    pub known_filesize: i64,
}
impl ftp_conn {
    pub const fn new() -> Self {
        ftp_conn {
        pp: crate::src::lib::http2::pingpong::new(),
        entrypath: (0 as * mut i8),
        file: (0 as * mut i8),
        dirs: (0 as * mut * mut i8),
        dirdepth: 0,
        dont_check: false,
        ctl_valid: false,
        cwddone: false,
        cwdcount: 0,
        cwdfail: false,
        wait_data_conn: false,
        newport: 0,
        newhost: (0 as * mut i8),
        prevpath: (0 as * mut i8),
        transfertype: 0,
        count1: 0,
        count2: 0,
        count3: 0,
        state: 0,
        state_saved: 0,
        retr_size_saved: 0,
        server_os: (0 as * mut i8),
        known_filesize: 0
        }
    }
}

impl std::default::Default for ftp_conn {
    fn default() -> Self { ftp_conn::new() }
}

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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ntlmdata {
    pub flags: u32,
    pub nonce: [u8; 8],
    pub target_info_len: u32,
    pub target_info: * mut core::ffi::c_void,
    pub ntlm_auth_hlpr_socket: i32,
    pub ntlm_auth_hlpr_pid: i32,
    pub challenge: * mut i8,
    pub response: * mut i8,
}
impl ntlmdata {
    pub const fn new() -> Self {
        ntlmdata {
        flags: 0,
        nonce: [0,0,0,0,0,0,0,0,],
        target_info_len: 0,
        target_info: (0 as * mut core::ffi::c_void),
        ntlm_auth_hlpr_socket: 0,
        ntlm_auth_hlpr_pid: 0,
        challenge: (0 as * mut i8),
        response: (0 as * mut i8)
        }
    }
}

impl std::default::Default for ntlmdata {
    fn default() -> Self { ntlmdata::new() }
}

pub type curlntlm = u32;
pub const NTLMSTATE_LAST: curlntlm = 4;
pub const NTLMSTATE_TYPE3: curlntlm = 3;
pub const NTLMSTATE_TYPE2: curlntlm = 2;
pub const NTLMSTATE_TYPE1: curlntlm = 1;
pub const NTLMSTATE_NONE: curlntlm = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct gsasldata {
    pub ctx: * mut crate::src::lib::escape::Gsasl,
    pub client: * mut crate::src::lib::conncache::Gsasl_session,
}
impl gsasldata {
    pub const fn new() -> Self {
        gsasldata {
        ctx: (0 as * mut crate::src::lib::escape::Gsasl),
        client: (0 as * mut crate::src::lib::conncache::Gsasl_session)
        }
    }
}

impl std::default::Default for gsasldata {
    fn default() -> Self { gsasldata::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_handler {
    pub scheme: * const i8,
    pub setup_connection: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut crate::src::lib::http2::connectdata,) -> u32>,
    pub do_it: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut bool,) -> u32>,
    pub done: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: u32,_: bool,) -> u32>,
    pub do_more: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut i32,) -> u32>,
    pub connect_it: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut bool,) -> u32>,
    pub connecting: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut bool,) -> u32>,
    pub doing: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut bool,) -> u32>,
    pub proto_getsock: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut crate::src::lib::http2::connectdata,_: * mut i32,) -> i32>,
    pub doing_getsock: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut crate::src::lib::http2::connectdata,_: * mut i32,) -> i32>,
    pub domore_getsock: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut crate::src::lib::http2::connectdata,_: * mut i32,) -> i32>,
    pub perform_getsock: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut crate::src::lib::http2::connectdata,_: * mut i32,) -> i32>,
    pub disconnect: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut crate::src::lib::http2::connectdata,_: bool,) -> u32>,
    pub readwrite: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut crate::src::lib::http2::connectdata,_: * mut i64,_: * mut bool,) -> u32>,
    pub connection_check: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut crate::src::lib::http2::connectdata,_: u32,) -> u32>,
    pub attach: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::http2::Curl_easy,_: * mut crate::src::lib::http2::connectdata,) -> ()>,
    pub defport: i32,
    pub protocol: u32,
    pub family: u32,
    pub flags: u32,
}
impl Curl_handler {
    pub const fn new() -> Self {
        Curl_handler {
        scheme: (0 as * const i8),
        setup_connection: None,
        do_it: None,
        done: None,
        do_more: None,
        connect_it: None,
        connecting: None,
        doing: None,
        proto_getsock: None,
        doing_getsock: None,
        domore_getsock: None,
        perform_getsock: None,
        disconnect: None,
        readwrite: None,
        connection_check: None,
        attach: None,
        defport: 0,
        protocol: 0,
        family: 0,
        flags: 0
        }
    }
}

impl std::default::Default for Curl_handler {
    fn default() -> Self { Curl_handler::new() }
}

// #[derive(Copy, Clone, BitfieldStruct)]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ConnectBits {
    pub tcpconnect: [bool; 2],
    pub proxy_ssl_connected: [bool; 2],
    // #[bitfield(name = "httpproxy", ty = "bit", bits = "0..=0")]
    // #[bitfield(name = "socksproxy", ty = "bit", bits = "1..=1")]
    // #[bitfield(name = "proxy_user_passwd", ty = "bit", bits = "2..=2")]
    // #[bitfield(name = "tunnel_proxy", ty = "bit", bits = "3..=3")]
    // #[bitfield(name = "proxy_connect_closed", ty = "bit", bits = "4..=4")]
    // #[bitfield(name = "close", ty = "bit", bits = "5..=5")]
    // #[bitfield(name = "reuse", ty = "bit", bits = "6..=6")]
    // #[bitfield(name = "altused", ty = "bit", bits = "7..=7")]
    // #[bitfield(name = "conn_to_host", ty = "bit", bits = "8..=8")]
    // #[bitfield(name = "conn_to_port", ty = "bit", bits = "9..=9")]
    // #[bitfield(name = "proxy", ty = "bit", bits = "10..=10")]
    // #[bitfield(name = "user_passwd", ty = "bit", bits = "11..=11")]
    // #[bitfield(name = "ipv6_ip", ty = "bit", bits = "12..=12")]
    // #[bitfield(name = "ipv6", ty = "bit", bits = "13..=13")]
    // #[bitfield(name = "do_more", ty = "bit", bits = "14..=14")]
    // #[bitfield(name = "protoconnstart", ty = "bit", bits = "15..=15")]
    // #[bitfield(name = "retry", ty = "bit", bits = "16..=16")]
    // #[bitfield(name = "authneg", ty = "bit", bits = "17..=17")]
    // #[bitfield(name = "rewindaftersend", ty = "bit", bits = "18..=18")]
    // #[bitfield(name = "ftp_use_epsv", ty = "bit", bits = "19..=19")]
    // #[bitfield(name = "ftp_use_eprt", ty = "bit", bits = "20..=20")]
    // #[bitfield(name = "ftp_use_data_ssl", ty = "bit", bits = "21..=21")]
    // #[bitfield(name = "ftp_use_control_ssl", ty = "bit", bits = "22..=22")]
    // #[bitfield(name = "netrc", ty = "bit", bits = "23..=23")]
    // #[bitfield(name = "bound", ty = "bit", bits = "24..=24")]
    // #[bitfield(name = "multiplex", ty = "bit", bits = "25..=25")]
    // #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "26..=26")]
    // #[bitfield(name = "tls_enable_npn", ty = "bit", bits = "27..=27")]
    // #[bitfield(name = "tls_enable_alpn", ty = "bit", bits = "28..=28")]
    // #[bitfield(name = "connect_only", ty = "bit", bits = "29..=29")]
    // #[bitfield(name = "doh", ty = "bit", bits = "30..=30")]
    // #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "31..=31")]
    // #[bitfield(name = "tls_upgraded", ty = "bit", bits = "32..=32")]
    // #[bitfield(name = "sock_accepted", ty = "bit", bits = "33..=33")]
    // #[bitfield(name = "parallel_connect", ty = "bit", bits = "34..=34")]
    pub httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect: [u8; 5],
    // #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
impl ConnectBits {
    pub const fn new() -> Self {
        ConnectBits {
        tcpconnect: [false,false,],
        proxy_ssl_connected: [false,false,],
        httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect: [0,0,0,0,0,],
        c2rust_padding: [0,0,0,]
        }
    }
}

impl std::default::Default for ConnectBits {
    fn default() -> Self { ConnectBits::new() }
}

impl ConnectBits {
    /// This method allows you to write to a bitfield with a value
    pub fn set_httpproxy(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn httpproxy(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_socksproxy(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn socksproxy(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (1usize, 1usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_proxy_user_passwd(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (2usize, 2usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn proxy_user_passwd(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (2usize, 2usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_tunnel_proxy(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (3usize, 3usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn tunnel_proxy(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (3usize, 3usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_proxy_connect_closed(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (4usize, 4usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn proxy_connect_closed(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (4usize, 4usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_close(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (5usize, 5usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn close(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (5usize, 5usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_reuse(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (6usize, 6usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn reuse(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (6usize, 6usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_altused(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (7usize, 7usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn altused(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (7usize, 7usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_conn_to_host(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (8usize, 8usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn conn_to_host(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (8usize, 8usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_conn_to_port(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (9usize, 9usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn conn_to_port(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (9usize, 9usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_proxy(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (10usize, 10usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn proxy(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (10usize, 10usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_user_passwd(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (11usize, 11usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn user_passwd(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (11usize, 11usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ipv6_ip(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (12usize, 12usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ipv6_ip(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (12usize, 12usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ipv6(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (13usize, 13usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ipv6(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (13usize, 13usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_do_more(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (14usize, 14usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn do_more(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (14usize, 14usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_protoconnstart(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (15usize, 15usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn protoconnstart(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (15usize, 15usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_retry(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (16usize, 16usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn retry(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (16usize, 16usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_authneg(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (17usize, 17usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn authneg(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (17usize, 17usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_rewindaftersend(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (18usize, 18usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn rewindaftersend(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (18usize, 18usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ftp_use_epsv(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (19usize, 19usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ftp_use_epsv(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (19usize, 19usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ftp_use_eprt(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (20usize, 20usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ftp_use_eprt(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (20usize, 20usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ftp_use_data_ssl(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (21usize, 21usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ftp_use_data_ssl(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (21usize, 21usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_ftp_use_control_ssl(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (22usize, 22usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn ftp_use_control_ssl(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (22usize, 22usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_netrc(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (23usize, 23usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn netrc(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (23usize, 23usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_bound(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (24usize, 24usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn bound(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (24usize, 24usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_multiplex(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (25usize, 25usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn multiplex(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (25usize, 25usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_tcp_fastopen(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (26usize, 26usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn tcp_fastopen(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (26usize, 26usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_tls_enable_npn(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (27usize, 27usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn tls_enable_npn(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (27usize, 27usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_tls_enable_alpn(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (28usize, 28usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn tls_enable_alpn(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (28usize, 28usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_connect_only(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (29usize, 29usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn connect_only(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (29usize, 29usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_doh(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (30usize, 30usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn doh(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (30usize, 30usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_abstract_unix_socket(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (31usize, 31usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn abstract_unix_socket(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (31usize, 31usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_tls_upgraded(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (32usize, 32usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn tls_upgraded(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (32usize, 32usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_sock_accepted(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (33usize, 33usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn sock_accepted(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (33usize, 33usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    /// This method allows you to write to a bitfield with a value
    pub fn set_parallel_connect(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (34usize, 34usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn parallel_connect(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self
            .httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect;
        let (lhs_bit, rhs_bit) = (34usize, 34usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
}

// #[derive(Copy, Clone, BitfieldStruct)]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssl_connect_data {
    pub state: u32,
    pub connecting_state: u32,
    pub backend: * mut crate::src::lib::vtls::openssl::ssl_backend_data,
    // #[bitfield(name = "use_0", ty = "bit", bits = "0..=0")]
    pub use_0: [u8; 1],
    // #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
impl ssl_connect_data {
    pub const fn new() -> Self {
        ssl_connect_data {
        state: 0,
        connecting_state: 0,
        backend: (0 as * mut crate::src::lib::vtls::openssl::ssl_backend_data),
        use_0: [0,],
        c2rust_padding: [0,0,0,0,0,0,0,]
        }
    }
}

impl std::default::Default for ssl_connect_data {
    fn default() -> Self { ssl_connect_data::new() }
}

impl ssl_connect_data {
    /// This method allows you to write to a bitfield with a value
    pub fn set_use_0(&mut self, int: bit) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.use_0;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    /// This method allows you to read from a bitfield to a value
    pub fn use_0(&self) -> bit {
        use c2rust_bitfields::FieldType;
        type IntType = u32;
        let field = &self.use_0;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        <IntType as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct proxy_info {
    pub host: crate::src::lib::http2::hostname,
    pub port: i64,
    pub proxytype: u32,
    pub user: * mut i8,
    pub passwd: * mut i8,
}
impl proxy_info {
    pub const fn new() -> Self {
        proxy_info {
        host: crate::src::lib::http2::hostname::new(),
        port: 0,
        proxytype: 0,
        user: (0 as * mut i8),
        passwd: (0 as * mut i8)
        }
    }
}

impl std::default::Default for proxy_info {
    fn default() -> Self { proxy_info::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostname {
    pub rawalloc: * mut i8,
    pub encalloc: * mut i8,
    pub name: * mut i8,
    pub dispname: * const i8,
}
impl hostname {
    pub const fn new() -> Self {
        hostname {
        rawalloc: (0 as * mut i8),
        encalloc: (0 as * mut i8),
        name: (0 as * mut i8),
        dispname: (0 as * const i8)
        }
    }
}

impl std::default::Default for hostname {
    fn default() -> Self { hostname::new() }
}

pub type C2RustUnnamed_5 = u32;
pub const TRNSPRT_QUIC: C2RustUnnamed_5 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_5 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_5 = 3;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_chunker {
    pub datasize: i64,
    pub state: u32,
    pub hexindex: u8,
    pub hexbuffer: [i8; 17],
}
impl Curl_chunker {
    pub const fn new() -> Self {
        Curl_chunker {
        datasize: 0,
        state: 0,
        hexindex: 0,
        hexbuffer: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,]
        }
    }
}

impl std::default::Default for Curl_chunker {
    fn default() -> Self { Curl_chunker::new() }
}

pub type ChunkyState = u32;
pub const CHUNK_TRAILER_POSTCR: ChunkyState = 7;
pub const CHUNK_TRAILER_CR: ChunkyState = 6;
pub const CHUNK_TRAILER: ChunkyState = 5;
pub const CHUNK_STOP: ChunkyState = 4;
pub const CHUNK_POSTLF: ChunkyState = 3;
pub const CHUNK_DATA: ChunkyState = 2;
pub const CHUNK_LF: ChunkyState = 1;
pub const CHUNK_HEX: ChunkyState = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct connstate {
    pub state: u32,
    pub outstanding: i64,
    pub outp: * mut u8,
}
impl connstate {
    pub const fn new() -> Self {
        connstate {
        state: 0,
        outstanding: 0,
        outp: (0 as * mut u8)
        }
    }
}

impl std::default::Default for connstate {
    fn default() -> Self { connstate::new() }
}

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
pub type curl_calloc_callback<'a1> = Option<unsafe extern "C"  fn(_: u64,_: u64,) -> Option<&'a1 mut core::ffi::c_void>>;
pub type CURLMcode = i32;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_info {
    pub age: i32,
    pub version_num: i32,
    pub version_str: * const i8,
    pub proto_str: * const i8,
}
impl nghttp2_info {
    pub const fn new() -> Self {
        nghttp2_info {
        age: 0,
        version_num: 0,
        version_str: (0 as * const i8),
        proto_str: (0 as * const i8)
        }
    }
}

impl std::default::Default for nghttp2_info {
    fn default() -> Self { nghttp2_info::new() }
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
pub type nghttp2_data_source_read_callback<'a1, 'a2, 'a3, 'a4, 'a5> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::speedcheck::nghttp2_session>,_: i32,_: Option<&'a2 mut u8>,_: u64,_: Option<&'a3 mut u32>,_: Option<&'a4 mut crate::src::lib::http2::nghttp2_data_source>,_: Option<&'a5 mut core::ffi::c_void>,) -> i64>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_data_provider {
    pub source: crate::src::lib::http2::nghttp2_data_source,
    pub read_callback: Option<unsafe extern "C"  fn(_: * mut crate::src::lib::speedcheck::nghttp2_session,_: i32,_: * mut u8,_: u64,_: * mut u32,_: * mut crate::src::lib::http2::nghttp2_data_source,_: * mut core::ffi::c_void,) -> i64>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_data {
    pub hd: crate::src::lib::http2::nghttp2_frame_hd,
    pub padlen: u64,
}
impl nghttp2_data {
    pub const fn new() -> Self {
        nghttp2_data {
        hd: crate::src::lib::http2::nghttp2_frame_hd::new(),
        padlen: 0
        }
    }
}

impl std::default::Default for nghttp2_data {
    fn default() -> Self { nghttp2_data::new() }
}

pub type nghttp2_headers_category = u32;
pub const NGHTTP2_HCAT_HEADERS: nghttp2_headers_category = 3;
pub const NGHTTP2_HCAT_PUSH_RESPONSE: nghttp2_headers_category = 2;
pub const NGHTTP2_HCAT_RESPONSE: nghttp2_headers_category = 1;
pub const NGHTTP2_HCAT_REQUEST: nghttp2_headers_category = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_priority_spec {
    pub stream_id: i32,
    pub weight: i32,
    pub exclusive: u8,
}
impl nghttp2_priority_spec {
    pub const fn new() -> Self {
        nghttp2_priority_spec {
        stream_id: 0,
        weight: 0,
        exclusive: 0
        }
    }
}

impl std::default::Default for nghttp2_priority_spec {
    fn default() -> Self { nghttp2_priority_spec::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_headers {
    pub hd: crate::src::lib::http2::nghttp2_frame_hd,
    pub padlen: u64,
    pub pri_spec: crate::src::lib::http2::nghttp2_priority_spec,
    pub nva: * mut crate::src::lib::http2::nghttp2_nv,
    pub nvlen: u64,
    pub cat: u32,
}
impl nghttp2_headers {
    pub const fn new() -> Self {
        nghttp2_headers {
        hd: crate::src::lib::http2::nghttp2_frame_hd::new(),
        padlen: 0,
        pri_spec: crate::src::lib::http2::nghttp2_priority_spec::new(),
        nva: (0 as * mut crate::src::lib::http2::nghttp2_nv),
        nvlen: 0,
        cat: 0
        }
    }
}

impl std::default::Default for nghttp2_headers {
    fn default() -> Self { nghttp2_headers::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_priority {
    pub hd: crate::src::lib::http2::nghttp2_frame_hd,
    pub pri_spec: crate::src::lib::http2::nghttp2_priority_spec,
}
impl nghttp2_priority {
    pub const fn new() -> Self {
        nghttp2_priority {
        hd: crate::src::lib::http2::nghttp2_frame_hd::new(),
        pri_spec: crate::src::lib::http2::nghttp2_priority_spec::new()
        }
    }
}

impl std::default::Default for nghttp2_priority {
    fn default() -> Self { nghttp2_priority::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_rst_stream {
    pub hd: crate::src::lib::http2::nghttp2_frame_hd,
    pub error_code: u32,
}
impl nghttp2_rst_stream {
    pub const fn new() -> Self {
        nghttp2_rst_stream {
        hd: crate::src::lib::http2::nghttp2_frame_hd::new(),
        error_code: 0
        }
    }
}

impl std::default::Default for nghttp2_rst_stream {
    fn default() -> Self { nghttp2_rst_stream::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_settings {
    pub hd: crate::src::lib::http2::nghttp2_frame_hd,
    pub niv: u64,
    pub iv: * mut crate::src::lib::http2::nghttp2_settings_entry,
}
impl nghttp2_settings {
    pub const fn new() -> Self {
        nghttp2_settings {
        hd: crate::src::lib::http2::nghttp2_frame_hd::new(),
        niv: 0,
        iv: (0 as * mut crate::src::lib::http2::nghttp2_settings_entry)
        }
    }
}

impl std::default::Default for nghttp2_settings {
    fn default() -> Self { nghttp2_settings::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_ping {
    pub hd: crate::src::lib::http2::nghttp2_frame_hd,
    pub opaque_data: [u8; 8],
}
impl nghttp2_ping {
    pub const fn new() -> Self {
        nghttp2_ping {
        hd: crate::src::lib::http2::nghttp2_frame_hd::new(),
        opaque_data: [0,0,0,0,0,0,0,0,]
        }
    }
}

impl std::default::Default for nghttp2_ping {
    fn default() -> Self { nghttp2_ping::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_goaway {
    pub hd: crate::src::lib::http2::nghttp2_frame_hd,
    pub last_stream_id: i32,
    pub error_code: u32,
    pub opaque_data: * mut u8,
    pub opaque_data_len: u64,
    pub reserved: u8,
}
impl nghttp2_goaway {
    pub const fn new() -> Self {
        nghttp2_goaway {
        hd: crate::src::lib::http2::nghttp2_frame_hd::new(),
        last_stream_id: 0,
        error_code: 0,
        opaque_data: (0 as * mut u8),
        opaque_data_len: 0,
        reserved: 0
        }
    }
}

impl std::default::Default for nghttp2_goaway {
    fn default() -> Self { nghttp2_goaway::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_window_update {
    pub hd: crate::src::lib::http2::nghttp2_frame_hd,
    pub window_size_increment: i32,
    pub reserved: u8,
}
impl nghttp2_window_update {
    pub const fn new() -> Self {
        nghttp2_window_update {
        hd: crate::src::lib::http2::nghttp2_frame_hd::new(),
        window_size_increment: 0,
        reserved: 0
        }
    }
}

impl std::default::Default for nghttp2_window_update {
    fn default() -> Self { nghttp2_window_update::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_extension {
    pub hd: crate::src::lib::http2::nghttp2_frame_hd,
    pub payload: * mut core::ffi::c_void,
}
impl nghttp2_extension {
    pub const fn new() -> Self {
        nghttp2_extension {
        hd: crate::src::lib::http2::nghttp2_frame_hd::new(),
        payload: (0 as * mut core::ffi::c_void)
        }
    }
}

impl std::default::Default for nghttp2_extension {
    fn default() -> Self { nghttp2_extension::new() }
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
pub type nghttp2_send_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::speedcheck::nghttp2_session>,_: Option<&'a2 u8>,_: u64,_: i32,_: Option<&'a3 mut core::ffi::c_void>,) -> i64>;
pub type nghttp2_on_frame_recv_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::speedcheck::nghttp2_session>,_: Option<&'a2 crate::src::lib::http2::nghttp2_frame>,_: Option<&'a3 mut core::ffi::c_void>,) -> i32>;
pub type nghttp2_on_data_chunk_recv_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::speedcheck::nghttp2_session>,_: u8,_: i32,_: Option<&'a2 u8>,_: u64,_: Option<&'a3 mut core::ffi::c_void>,) -> i32>;
pub type nghttp2_on_stream_close_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::speedcheck::nghttp2_session>,_: i32,_: u32,_: Option<&'a2 mut core::ffi::c_void>,) -> i32>;
pub type nghttp2_on_begin_headers_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::speedcheck::nghttp2_session>,_: Option<&'a2 crate::src::lib::http2::nghttp2_frame>,_: Option<&'a3 mut core::ffi::c_void>,) -> i32>;
pub type nghttp2_on_header_callback<'a1, 'a2, 'a3, 'a4, 'a5> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::speedcheck::nghttp2_session>,_: Option<&'a2 crate::src::lib::http2::nghttp2_frame>,_: Option<&'a3 u8>,_: u64,_: Option<&'a4 u8>,_: u64,_: u8,_: Option<&'a5 mut core::ffi::c_void>,) -> i32>;
pub type nghttp2_error_callback<'a1, 'a2, 'a3> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut crate::src::lib::speedcheck::nghttp2_session>,_: Option<&'a2 i8>,_: u64,_: Option<&'a3 mut core::ffi::c_void>,) -> i32>;
pub const HEADERINST_TE_TRAILERS: header_instruction = 2;
pub const HEADERINST_IGNORE: header_instruction = 1;
pub type header_instruction = u32;
pub const HEADERINST_FORWARD: header_instruction = 0;
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_init_state<'a1>(mut state: Option<&'a1 mut crate::src::lib::http2::UrlState>) {
    (*(borrow_mut(&mut state)).unwrap()).stream_weight = 16 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_init_userset<'a1>(mut set: Option<&'a1 mut crate::src::lib::http2::UserDefined>) {
    (*(borrow_mut(&mut set)).unwrap()).stream_weight = 16 as i32;
}
unsafe extern "C" fn http2_getsock(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut sock: * mut i32,
) -> i32 {
    let mut c: Option<&'_ crate::src::lib::http2::http_conn> = Some(&mut (*conn).proto.httpc);
    let mut k: Option<&'_ mut crate::src::lib::http2::SingleRequest> = Some(&mut (*data).req);
    let mut bitmap: i32 = 0 as i32;
    *sock.offset(0 as i32 as isize) = (*conn).sock[0 as i32 as usize];
    if (*(borrow(& k)).unwrap()).keepon & (1 as i32) << 4 as i32 == 0 {
        bitmap |= (1 as i32) << 0 as i32;
    }
    if (*(borrow(& k)).unwrap()).keepon
        & ((1 as i32) << 1 as i32
            | (1 as i32) << 5 as i32)
        == (1 as i32) << 1 as i32
        || nghttp2_session_want_write((*((c).clone()).unwrap()).h2) != 0
    {
        bitmap |= (1 as i32) << 16 as i32 + 0 as i32;
    }
    return bitmap;
}
unsafe extern "C" fn http2_stream_free(mut http: * mut crate::src::lib::http2::HTTP) {
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
            let mut fresh0 = &mut ((*http).push_headers_used);
            *fresh0 = (*fresh0).wrapping_sub(1);
        }
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*http).push_headers as *mut libc::c_void);
        let mut fresh1 = &mut ((*http).push_headers);
        *fresh1 = 0 as *mut *mut i8;
    }
}
unsafe extern "C" fn http2_disconnect(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut dead_connection: bool,
) -> u32 {
    let mut c: Option<&'_ mut crate::src::lib::http2::http_conn> = Some(&mut (*conn).proto.httpc);
    nghttp2_session_del((*(borrow_mut(&mut c)).unwrap()).h2);
    Curl_cfree.expect("non-null function pointer")((*(borrow_mut(&mut c)).unwrap()).inbuf as *mut libc::c_void);
    let mut fresh2 = &mut ((*(borrow_mut(&mut c)).unwrap()).inbuf);
    *fresh2 = 0 as *mut i8;
    return CURLE_OK;
}
unsafe extern "C" fn http2_connisdead(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
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
            let mut result: u32 = CURLE_OK;
            let mut httpc: Option<&'_ mut crate::src::lib::http2::http_conn> = Some(&mut (*conn).proto.httpc);
            let mut nread: i64 = -(1 as i32) as ssize_t;
            if ((*(borrow(& httpc)).unwrap()).recv_underlying).is_some() {
                nread = ((*(borrow(& httpc)).unwrap()).recv_underlying)
                    .expect(
                        "non-null function pointer",
                    )(
                    data,
                    0 as i32,
                    (*(borrow_mut(&mut httpc)).unwrap()).inbuf,
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
                (*(borrow_mut(&mut httpc)).unwrap()).nread_inbuf = 0 as i32 as size_t;
                (*(borrow_mut(&mut httpc)).unwrap()).inbuflen = nread as size_t;
                if h2_process_pending_input(data, borrow_mut(&mut httpc), &mut result) < 0 as i32
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
unsafe extern "C" fn set_transfer<'a1>(mut c: Option<&'a1 mut crate::src::lib::http2::http_conn>, mut data: * mut crate::src::lib::http2::Curl_easy) {
    let mut fresh3 = &mut ((*(borrow_mut(&mut c)).unwrap()).trnsfr);
    *fresh3 = data;
}
unsafe extern "C" fn get_transfer<'a1>(mut c: Option<&'a1 mut crate::src::lib::http2::http_conn>) -> * mut crate::src::lib::http2::Curl_easy {
    return (*(borrow_mut(&mut c)).unwrap()).trnsfr;
}
unsafe extern "C" fn http2_conncheck(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut checks_to_perform: u32,
) -> u32 {
    let mut ret_val: u32 = 0 as i32 as u32;
    let mut c: Option<&'_ mut crate::src::lib::http2::http_conn> = Some(&mut (*conn).proto.httpc);
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
        let mut now: crate::src::lib::http2::curltime = Curl_now();
        let mut elapsed: i64 = Curl_timediff(now, (*conn).keepalive);
        if elapsed > (*data).set.upkeep_interval_ms {
            rc = nghttp2_submit_ping(
                (*(borrow_mut(&mut c)).unwrap()).h2,
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
        set_transfer(borrow_mut(&mut c), data);
        rc = nghttp2_session_send((*(borrow_mut(&mut c)).unwrap()).h2);
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
pub unsafe extern "C" fn Curl_http2_setup_req(mut data: * mut crate::src::lib::http2::Curl_easy) {
    let mut http: * mut crate::src::lib::http2::HTTP = (*data).req.p.http;
    (*http).bodystarted = 0 as i32 != 0;
    (*http).status_code = -(1 as i32);
    let mut fresh4 = &mut ((*http).pausedata);
    *fresh4 = 0 as *const uint8_t;
    (*http).pauselen = 0 as i32 as size_t;
    (*http).closed = 0 as i32 != 0;
    (*http).close_handled = 0 as i32 != 0;
    let mut fresh5 = &mut ((*http).mem);
    *fresh5 = 0 as *mut i8;
    (*http).len = 0 as i32 as size_t;
    (*http).memlen = 0 as i32 as size_t;
    (*http).error = NGHTTP2_NO_ERROR as i32 as uint32_t;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_setup_conn(mut conn: * mut crate::src::lib::http2::connectdata) {
    (*conn).proto.httpc.settings.max_concurrent_streams = 100 as i32 as uint32_t;
}
static mut Curl_handler_http2: crate::src::lib::http2::Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"HTTP\0" as *const u8 as *const i8,
            setup_connection: None,
            do_it: Some(
                Curl_http,
            ),
            done: Some(
                Curl_http_done,
            ),
            do_more: None,
            connect_it: None,
            connecting: None,
            doing: None,
            proto_getsock: Some(
                http2_getsock,
            ),
            doing_getsock: Some(
                http2_getsock,
            ),
            domore_getsock: None,
            perform_getsock: Some(
                http2_getsock,
            ),
            disconnect: Some(
                http2_disconnect,
            ),
            readwrite: None,
            connection_check: Some(
                http2_conncheck,
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
static mut Curl_handler_http2_ssl: crate::src::lib::http2::Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"HTTPS\0" as *const u8 as *const i8,
            setup_connection: None,
            do_it: Some(
                Curl_http,
            ),
            done: Some(
                Curl_http_done,
            ),
            do_more: None,
            connect_it: None,
            connecting: None,
            doing: None,
            proto_getsock: Some(
                http2_getsock,
            ),
            doing_getsock: Some(
                http2_getsock,
            ),
            domore_getsock: None,
            perform_getsock: Some(
                http2_getsock,
            ),
            disconnect: Some(
                http2_disconnect,
            ),
            readwrite: None,
            connection_check: Some(
                http2_conncheck,
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
pub unsafe extern "C" fn Curl_http2_ver(mut p: * mut i8, mut len: u64) {
    let mut h2: * mut crate::src::lib::http2::nghttp2_info = nghttp2_version(0 as i32);
    curl_msnprintf(
        p,
        len,
        b"nghttp2/%s\0" as *const u8 as *const i8,
        (*h2).version_str,
    );
}
unsafe extern "C" fn send_callback(
    mut h2: * mut crate::src::lib::speedcheck::nghttp2_session,
    mut mem: * const u8,
    mut length: u64,
    mut flags: i32,
    mut userp: * mut core::ffi::c_void,
) -> i64 {
    let mut conn: * mut crate::src::lib::http2::connectdata = userp as *mut connectdata;
    let mut c: Option<&'_ mut crate::src::lib::http2::http_conn> = Some(&mut (*conn).proto.httpc);
    let mut data: * mut crate::src::lib::http2::Curl_easy = get_transfer(borrow_mut(&mut c));
    let mut written: i64 = 0;
    let mut result: u32 = CURLE_OK;
    if ((*(borrow(& c)).unwrap()).send_underlying).is_none() {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32 as ssize_t;
    }
    written = ((*(borrow(& c)).unwrap()).send_underlying)
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
pub unsafe extern "C" fn curl_pushheader_bynum<'a1>(
    mut h: Option<&'a1 mut crate::src::lib::http2::curl_pushheaders>,
    mut num: u64,
) -> * mut i8 {
    if borrow(& h).is_none()
        || !(!((*(borrow(& h)).unwrap()).data).is_null() && (*(*(borrow(& h)).unwrap()).data).magic == 0xc0dedbad as u32)
    {
        return 0 as *mut i8
    } else {
        let mut stream: * mut crate::src::lib::http2::HTTP = (*(*(borrow_mut(&mut h)).unwrap()).data).req.p.http;
        if num < (*stream).push_headers_used {
            return *((*stream).push_headers).offset(num as isize);
        }
    }
    return 0 as *mut i8;
}
#[no_mangle]
pub unsafe extern "C" fn curl_pushheader_byname<'a1>(
    mut h: Option<&'a1 mut crate::src::lib::http2::curl_pushheaders>,
    mut header: * const i8,
) -> * mut i8 {
    if borrow(& h).is_none()
        || !(!((*(borrow(& h)).unwrap()).data).is_null() && (*(*(borrow(& h)).unwrap()).data).magic == 0xc0dedbad as u32)
        || header.is_null() || *header.offset(0 as i32 as isize) == 0
        || strcmp(header, b":\0" as *const u8 as *const i8) == 0
        || !(strchr(header.offset(1 as i32 as isize), ':' as i32)).is_null()
    {
        return 0 as *mut i8
    } else {
        let mut stream: * mut crate::src::lib::http2::HTTP = (*(*(borrow_mut(&mut h)).unwrap()).data).req.p.http;
        let mut len: u64 = strlen(header);
        let mut i: u64 = 0;
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
unsafe extern "C" fn drained_transfer<'a1>(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut httpc: Option<&'a1 mut crate::src::lib::http2::http_conn>,
) {
    let mut fresh6 = &mut ((*(borrow_mut(&mut httpc)).unwrap()).drain_total);
    *fresh6 = (*fresh6 as u64).wrapping_sub((*data).state.drain) as size_t
        as size_t;
    (*data).state.drain = 0 as i32 as size_t;
}
unsafe extern "C" fn drain_this<'a1>(mut data: * mut crate::src::lib::http2::Curl_easy, mut httpc: Option<&'a1 mut crate::src::lib::http2::http_conn>) {
    let mut fresh7 = &mut ((*data).state.drain);
    *fresh7 = (*fresh7).wrapping_add(1);
    let mut fresh8 = &mut ((*(borrow_mut(&mut httpc)).unwrap()).drain_total);
    *fresh8 = (*fresh8).wrapping_add(1);
}
unsafe extern "C" fn duphandle(mut data: * mut crate::src::lib::http2::Curl_easy) -> * mut crate::src::lib::http2::Curl_easy {
    let mut second: * mut crate::src::lib::http2::Curl_easy = curl_easy_duphandle(data);
    if !second.is_null() {
        let mut http: * mut crate::src::lib::http2::HTTP = Curl_ccalloc
            .expect(
                "non-null function pointer",
            )(1 as i32 as size_t, ::std::mem::size_of::<HTTP>() as u64)
            as *mut HTTP;
        if http.is_null() {
            Curl_close(Some(&mut second));
        } else {
            let mut fresh9 = &mut ((*second).req.p.http);
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
unsafe extern "C" fn set_transfer_url<'a1>(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut hp: Option<&'a1 mut crate::src::lib::http2::curl_pushheaders>,
) -> i32 {
    let mut current_block: u64;
    let mut v: * const i8 = 0 as *const i8;
    let mut u: * mut crate::src::lib::urlapi::Curl_URL = curl_url();
    let mut uc: u32 = CURLUE_OK;
    let mut url: * mut i8 = 0 as *mut i8;
    let mut rc: i32 = 0 as i32;
    v = curl_pushheader_byname(borrow_mut(&mut hp), b":scheme\0" as *const u8 as *const i8);
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
                borrow_mut(&mut hp),
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
                        borrow_mut(&mut hp),
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
                                Some(&mut url),
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
    let mut fresh10 = &mut ((*data).state);
    (*fresh10).set_url_alloc(1 as i32 as bit);
    let mut fresh11 = &mut ((*data).state.url);
    *fresh11 = url;
    return 0 as i32;
}
unsafe extern "C" fn push_promise(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut frame: * const crate::src::lib::http2::nghttp2_push_promise,
) -> i32 {
    let mut rv: i32 = 0;
    if ((*(*data).multi).push_cb).is_some() {
        let mut stream: * mut crate::src::lib::http2::HTTP = 0 as *mut HTTP;
        let mut newstream: * mut crate::src::lib::http2::HTTP = 0 as *mut HTTP;
        let mut heads: crate::src::lib::http2::curl_pushheaders = curl_pushheaders {
            data: 0 as *mut Curl_easy,
            frame: 0 as *const nghttp2_push_promise,
        };
        let mut rc: i32 = CURLM_OK;
        let mut httpc: Option<&'_ mut crate::src::lib::http2::http_conn> = Option::<&'_ mut crate::src::lib::http2::http_conn>::None;
        let mut i: u64 = 0;
        let mut newhandle: * mut crate::src::lib::http2::Curl_easy = duphandle(data);
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
                Curl_close(Some(&mut newhandle));
                rv = 1 as i32;
            } else {
                rv = set_transfer_url(newhandle, Some(&mut heads));
                if rv != 0 {
                    Curl_close(Some(&mut newhandle));
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
                    let mut fresh12 = &mut ((*stream).push_headers);
                    *fresh12 = 0 as *mut *mut i8;
                    (*stream).push_headers_used = 0 as i32 as size_t;
                    if rv != 0 {
                        http2_stream_free((*newhandle).req.p.http);
                        let mut fresh13 = &mut ((*newhandle).req.p.http);
                        *fresh13 = 0 as *mut HTTP;
                        Curl_close(Some(&mut newhandle));
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
                            let mut fresh14 = &mut ((*newhandle).req.p.http);
                            *fresh14 = 0 as *mut HTTP;
                            Curl_close(Some(&mut newhandle));
                            rv = 1 as i32;
                        } else {
                            httpc = Some(&mut (*conn).proto.httpc);
                            rv = nghttp2_session_set_stream_user_data(
                                (*(borrow_mut(&mut httpc)).unwrap()).h2,
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
unsafe extern "C" fn multi_connchanged(mut multi: * mut crate::src::lib::http2::Curl_multi) {
    (*multi).recheckstate = 1 as i32 != 0;
}
unsafe extern "C" fn on_frame_recv(
    mut session: * mut crate::src::lib::speedcheck::nghttp2_session,
    mut frame: * const crate::src::lib::http2::nghttp2_frame,
    mut userp: * mut core::ffi::c_void,
) -> i32 {
    let mut conn: * mut crate::src::lib::http2::connectdata = userp as *mut connectdata;
    let mut httpc: Option<&'_ mut crate::src::lib::http2::http_conn> = Some(&mut (*conn).proto.httpc);
    let mut data_s: * mut crate::src::lib::http2::Curl_easy = 0 as *mut Curl_easy;
    let mut stream: * mut crate::src::lib::http2::HTTP = 0 as *mut HTTP;
    let mut data: * mut crate::src::lib::http2::Curl_easy = get_transfer(borrow_mut(&mut httpc));
    let mut rv: i32 = 0;
    let mut left: u64 = 0;
    let mut ncopy: u64 = 0;
    let mut stream_id: i32 = (*frame).hd.stream_id;
    let mut result: u32 = CURLE_OK;
    if stream_id == 0 {
        if (*frame).hd.type_0 as i32 == NGHTTP2_SETTINGS as i32 {
            let mut max_conn: u32 = (*(borrow_mut(&mut httpc)).unwrap()).settings.max_concurrent_streams;
            (*(borrow_mut(&mut httpc)).unwrap())
                .settings
                .max_concurrent_streams = nghttp2_session_get_remote_settings(
                session,
                NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
            );
            (*(borrow_mut(&mut httpc)).unwrap())
                .settings
                .enable_push = nghttp2_session_get_remote_settings(
                session,
                NGHTTP2_SETTINGS_ENABLE_PUSH,
            ) != 0;
            if max_conn != (*(borrow(& httpc)).unwrap()).settings.max_concurrent_streams {
                Curl_infof(
                    data,
                    b"Connection state changed (MAX_CONCURRENT_STREAMS == %u)!\0"
                        as *const u8 as *const i8,
                    (*(borrow(& httpc)).unwrap()).settings.max_concurrent_streams,
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
                let mut fresh15 = &mut ((*stream).nread_header_recvbuf);
                *fresh15 = (*fresh15 as u64).wrapping_add(ncopy) as size_t
                    as size_t;
                let mut fresh16 = &mut ((*stream).len);
                *fresh16 = (*fresh16 as u64).wrapping_sub(ncopy) as size_t
                    as size_t;
                let mut fresh17 = &mut ((*stream).memlen);
                *fresh17 = (*fresh17 as u64).wrapping_add(ncopy) as size_t
                    as size_t;
                drain_this(data_s, borrow_mut(&mut httpc));
                if get_transfer(borrow_mut(&mut httpc)) != data_s {
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
    mut session: * mut crate::src::lib::speedcheck::nghttp2_session,
    mut flags: u8,
    mut stream_id: i32,
    mut mem: * const u8,
    mut len: u64,
    mut userp: * mut core::ffi::c_void,
) -> i32 {
    let mut stream: * mut crate::src::lib::http2::HTTP = 0 as *mut HTTP;
    let mut data_s: * mut crate::src::lib::http2::Curl_easy = 0 as *mut Curl_easy;
    let mut nread: u64 = 0;
    let mut conn: * mut crate::src::lib::http2::connectdata = userp as *mut connectdata;
    let mut httpc: Option<&'_ mut crate::src::lib::http2::http_conn> = Some(&mut (*conn).proto.httpc);
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
    let mut fresh18 = &mut ((*stream).len);
    *fresh18 = (*fresh18 as u64).wrapping_sub(nread) as size_t as size_t;
    let mut fresh19 = &mut ((*stream).memlen);
    *fresh19 = (*fresh19 as u64).wrapping_add(nread) as size_t as size_t;
    drain_this(data_s, Some(&mut (*conn).proto.httpc));
    if get_transfer(borrow_mut(&mut httpc)) != data_s {
        Curl_expire(data_s, 0 as i32 as timediff_t, EXPIRE_RUN_NOW);
    }
    if nread < len {
        let mut fresh20 = &mut ((*stream).pausedata);
        *fresh20 = mem.offset(nread as isize);
        (*stream).pauselen = len.wrapping_sub(nread);
        (*(*data_s).conn).proto.httpc.pause_stream_id = stream_id;
        return NGHTTP2_ERR_PAUSE as i32;
    }
    if get_transfer(borrow_mut(&mut httpc)) != data_s {
        (*(*data_s).conn).proto.httpc.pause_stream_id = stream_id;
        return NGHTTP2_ERR_PAUSE as i32;
    }
    return 0 as i32;
}
unsafe extern "C" fn on_stream_close(
    mut session: * mut crate::src::lib::speedcheck::nghttp2_session,
    mut stream_id: i32,
    mut error_code: u32,
    mut userp: * mut core::ffi::c_void,
) -> i32 {
    let mut data_s: * mut crate::src::lib::http2::Curl_easy = 0 as *mut Curl_easy;
    let mut stream: * mut crate::src::lib::http2::HTTP = 0 as *mut HTTP;
    let mut conn: * mut crate::src::lib::http2::connectdata = userp as *mut connectdata;
    let mut rv: i32 = 0;
    if stream_id != 0 {
        let mut httpc: Option<&'_ mut crate::src::lib::http2::http_conn> = Option::<&'_ mut crate::src::lib::http2::http_conn>::None;
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
        httpc = Some(&mut (*conn).proto.httpc);
        drain_this(data_s, borrow_mut(&mut httpc));
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
        if stream_id == (*(borrow(& httpc)).unwrap()).pause_stream_id {
            (*(borrow_mut(&mut httpc)).unwrap()).pause_stream_id = 0 as i32;
        }
        (*stream).stream_id = 0 as i32;
    }
    return 0 as i32;
}
unsafe extern "C" fn on_begin_headers(
    mut session: * mut crate::src::lib::speedcheck::nghttp2_session,
    mut frame: * const crate::src::lib::http2::nghttp2_frame,
    mut userp: * mut core::ffi::c_void,
) -> i32 {
    let mut stream: * mut crate::src::lib::http2::HTTP = 0 as *mut HTTP;
    let mut data_s: * mut crate::src::lib::http2::Curl_easy = (0 as * mut crate::src::lib::http2::Curl_easy);
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
    mut value: * const u8,
    mut len: u64,
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
    mut session: * mut crate::src::lib::speedcheck::nghttp2_session,
    mut frame: * const crate::src::lib::http2::nghttp2_frame,
    mut name: * const u8,
    mut namelen: u64,
    mut value: * const u8,
    mut valuelen: u64,
    mut flags: u8,
    mut userp: * mut core::ffi::c_void,
) -> i32 {
    let mut stream: * mut crate::src::lib::http2::HTTP = 0 as *mut HTTP;
    let mut data_s: * mut crate::src::lib::http2::Curl_easy = 0 as *mut Curl_easy;
    let mut stream_id: i32 = (*frame).hd.stream_id;
    let mut conn: * mut crate::src::lib::http2::connectdata = userp as *mut connectdata;
    let mut httpc: Option<&'_ mut crate::src::lib::http2::http_conn> = Some(&mut (*conn).proto.httpc);
    let mut result: u32 = CURLE_OK;
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
        let mut h: * mut i8 = 0 as *mut i8;
        if strcmp(
            b":authority\0" as *const u8 as *const i8,
            name as *const i8,
        ) == 0
        {
            let mut rc: i32 = 0 as i32;
            let mut check: * mut i8 = curl_maprintf(
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
            let mut fresh21 = &mut ((*stream).push_headers);
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
            let mut headp: * mut * mut i8 = 0 as *mut *mut i8;
            let mut fresh22 = &mut ((*stream).push_headers_alloc);
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
                let mut fresh23 = &mut ((*stream).push_headers);
                *fresh23 = 0 as *mut *mut i8;
                return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE as i32;
            }
            let mut fresh24 = &mut ((*stream).push_headers);
            *fresh24 = headp;
        }
        h = curl_maprintf(b"%s:%s\0" as *const u8 as *const i8, name, value);
        if !h.is_null() {
            let mut fresh25 = &mut ((*stream).push_headers_used);
            let mut fresh26 = *fresh25;
            *fresh25 = (*fresh25).wrapping_add(1);
            let mut fresh27 = &mut (*((*stream).push_headers).offset(fresh26 as isize));
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
        if get_transfer(borrow_mut(&mut httpc)) != data_s {
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
    if get_transfer(borrow_mut(&mut httpc)) != data_s {
        Curl_expire(data_s, 0 as i32 as timediff_t, EXPIRE_RUN_NOW);
    }
    return 0 as i32;
}
unsafe extern "C" fn data_source_read_callback(
    mut session: * mut crate::src::lib::speedcheck::nghttp2_session,
    mut stream_id: i32,
    mut buf: * mut u8,
    mut length: u64,
    mut data_flags: * mut u32,
    mut source: * mut crate::src::lib::http2::nghttp2_data_source,
    mut userp: * mut core::ffi::c_void,
) -> i64 {
    let mut data_s: * mut crate::src::lib::http2::Curl_easy = (0 as * mut crate::src::lib::http2::Curl_easy);
    let mut stream: * mut crate::src::lib::http2::HTTP = 0 as *mut HTTP;
    let mut nread: u64 = 0;
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
        let mut fresh28 = &mut ((*stream).upload_mem);
        *fresh28 = (*fresh28).offset(nread as isize);
        let mut fresh29 = &mut ((*stream).upload_len);
        *fresh29 = (*fresh29 as u64).wrapping_sub(nread) as size_t as size_t;
        if (*data_s).state.infilesize != -(1 as i32) as i64 {
            let mut fresh30 = &mut ((*stream).upload_left);
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
    mut session: * mut crate::src::lib::speedcheck::nghttp2_session,
    mut msg: * const i8,
    mut len: u64,
    mut userp: * mut core::ffi::c_void,
) -> i32 {
    return 0 as i32;
}
unsafe extern "C" fn populate_settings<'a1>(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut httpc: Option<&'a1 mut crate::src::lib::http2::http_conn>,
) {
    let mut iv: * mut crate::src::lib::http2::nghttp2_settings_entry = ((*(borrow_mut(&mut httpc)).unwrap()).local_settings).as_mut_ptr();
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
    (*(borrow_mut(&mut httpc)).unwrap()).local_settings_num = 3 as i32 as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_done(mut data: * mut crate::src::lib::http2::Curl_easy, mut premature: bool) {
    let mut http: * mut crate::src::lib::http2::HTTP = (*data).req.p.http;
    let mut httpc: Option<&'_ mut crate::src::lib::http2::http_conn> = Some(&mut (*(*data).conn).proto.httpc);
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
            let mut fresh31 = &mut ((*http).push_headers_used);
            *fresh31 = (*fresh31).wrapping_sub(1);
        }
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*http).push_headers as *mut libc::c_void);
        let mut fresh32 = &mut ((*http).push_headers);
        *fresh32 = 0 as *mut *mut i8;
    }
    if (*(*(*data).conn).handler).protocol
        & ((1 as i32) << 0 as i32
            | (1 as i32) << 1 as i32) as u32 == 0
        || ((*(borrow(& httpc)).unwrap()).h2).is_null()
    {
        return;
    }
    if premature {
        set_transfer(borrow_mut(&mut httpc), data);
        if nghttp2_submit_rst_stream(
            (*(borrow_mut(&mut httpc)).unwrap()).h2,
            NGHTTP2_FLAG_NONE as i32 as uint8_t,
            (*http).stream_id,
            NGHTTP2_STREAM_CLOSED as i32 as uint32_t,
        ) == 0
        {
            nghttp2_session_send((*(borrow_mut(&mut httpc)).unwrap()).h2);
        }
        if (*http).stream_id == (*(borrow(& httpc)).unwrap()).pause_stream_id {
            Curl_infof(
                data,
                b"stopped the pause stream!\0" as *const u8 as *const i8,
            );
            (*(borrow_mut(&mut httpc)).unwrap()).pause_stream_id = 0 as i32;
        }
    }
    if (*data).state.drain != 0 {
        drained_transfer(data, borrow_mut(&mut httpc));
    }
    if (*http).stream_id > 0 as i32 {
        let mut rv: i32 = nghttp2_session_set_stream_user_data(
            (*(borrow_mut(&mut httpc)).unwrap()).h2,
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
        set_transfer(borrow_mut(&mut httpc), 0 as *mut Curl_easy);
        (*http).stream_id = 0 as i32;
    }
}
unsafe extern "C" fn http2_init(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
) -> u32 {
    if ((*conn).proto.httpc.h2).is_null() {
        let mut rc: i32 = 0;
        let mut callbacks: * mut crate::src::lib::http2::nghttp2_session_callbacks = 0
            as *mut nghttp2_session_callbacks;
        let mut fresh33 = &mut ((*conn).proto.httpc.inbuf);
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
                send_callback,
            ),
        );
        nghttp2_session_callbacks_set_on_frame_recv_callback(
            callbacks,
            Some(
                on_frame_recv,
            ),
        );
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
            callbacks,
            Some(
                on_data_chunk_recv,
            ),
        );
        nghttp2_session_callbacks_set_on_stream_close_callback(
            callbacks,
            Some(
                on_stream_close,
            ),
        );
        nghttp2_session_callbacks_set_on_begin_headers_callback(
            callbacks,
            Some(
                on_begin_headers,
            ),
        );
        nghttp2_session_callbacks_set_on_header_callback(
            callbacks,
            Some(
                on_header,
            ),
        );
        nghttp2_session_callbacks_set_error_callback(
            callbacks,
            Some(
                error_callback,
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
    mut req: * mut crate::src::lib::http2::dynbuf,
    mut data: * mut crate::src::lib::http2::Curl_easy,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut binlen: i64 = 0;
    let mut base64: * mut i8 = 0 as *mut i8;
    let mut blen: u64 = 0;
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    let mut k: Option<&'_ mut crate::src::lib::http2::SingleRequest> = Some(&mut (*data).req);
    let mut binsettings: * mut u8 = ((*conn).proto.httpc.binsettings).as_mut_ptr();
    let mut httpc: Option<&'_ mut crate::src::lib::http2::http_conn> = Some(&mut (*conn).proto.httpc);
    populate_settings(data, borrow_mut(&mut httpc));
    binlen = nghttp2_pack_settings_payload(
        binsettings,
        80 as i32 as size_t,
        ((*(borrow_mut(&mut httpc)).unwrap()).local_settings).as_mut_ptr(),
        (*(borrow_mut(&mut httpc)).unwrap()).local_settings_num,
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
        Some(&mut base64),
        Some(&mut blen),
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
    (*(borrow_mut(&mut k)).unwrap()).upgr101 = UPGR101_REQUESTED;
    return result;
}
unsafe extern "C" fn should_close_session<'a1>(mut httpc: Option<&'a1 mut crate::src::lib::http2::http_conn>) -> i32 {
    return ((*(borrow(& httpc)).unwrap()).drain_total == 0 as i32 as u64
        && nghttp2_session_want_read((*(borrow_mut(&mut httpc)).unwrap()).h2) == 0
        && nghttp2_session_want_write((*(borrow_mut(&mut httpc)).unwrap()).h2) == 0) as i32;
}
unsafe extern "C" fn h2_process_pending_input<'a1>(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut httpc: Option<&'a1 mut crate::src::lib::http2::http_conn>,
    mut err: * mut u32,
) -> i32 {
    let mut nread: i64 = 0;
    let mut inbuf: * mut i8 = 0 as *mut i8;
    let mut rv: i64 = 0;
    nread = ((*(borrow(& httpc)).unwrap()).inbuflen).wrapping_sub((*(borrow(& httpc)).unwrap()).nread_inbuf) as ssize_t;
    inbuf = ((*(borrow(& httpc)).unwrap()).inbuf).offset((*(borrow(& httpc)).unwrap()).nread_inbuf as isize);
    set_transfer(borrow_mut(&mut httpc), data);
    rv = nghttp2_session_mem_recv((*(borrow_mut(&mut httpc)).unwrap()).h2, inbuf as *const uint8_t, nread as size_t);
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
        (*(borrow_mut(&mut httpc)).unwrap()).inbuflen = 0 as i32 as size_t;
        (*(borrow_mut(&mut httpc)).unwrap()).nread_inbuf = 0 as i32 as size_t;
    } else {
        let mut fresh34 = &mut ((*(borrow_mut(&mut httpc)).unwrap()).nread_inbuf);
        *fresh34 = (*fresh34 as u64).wrapping_add(rv as u64)
            as size_t as size_t;
    }
    rv = h2_session_send(data, (*(borrow_mut(&mut httpc)).unwrap()).h2) as ssize_t;
    if rv != 0 {
        *err = CURLE_SEND_ERROR;
        return -(1 as i32);
    }
    if nghttp2_session_check_request_allowed((*(borrow_mut(&mut httpc)).unwrap()).h2) == 0 as i32 {
        Curl_conncontrol((*data).conn, 1 as i32);
    }
    if should_close_session(borrow_mut(&mut httpc)) != 0 {
        let mut stream: * mut crate::src::lib::http2::HTTP = (*data).req.p.http;
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
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    if (*conn).handler == &Curl_handler_http2_ssl as *const Curl_handler
        || (*conn).handler == &Curl_handler_http2 as *const Curl_handler
    {
        let mut stream: * mut crate::src::lib::http2::HTTP = (*data).req.p.http;
        let mut httpc: Option<&'_ mut crate::src::lib::http2::http_conn> = Some(&mut (*conn).proto.httpc);
        let mut h2: * mut crate::src::lib::speedcheck::nghttp2_session = (*(borrow_mut(&mut httpc)).unwrap()).h2;
        if (*stream).upload_left != 0 {
            (*stream).upload_left = 0 as i32 as curl_off_t;
            nghttp2_session_resume_data(h2, (*stream).stream_id);
            h2_process_pending_input(data, borrow_mut(&mut httpc), &mut result);
        }
        if nghttp2_session_want_write(h2) != 0 {
            let mut k: Option<&'_ mut crate::src::lib::http2::SingleRequest> = Some(&mut (*data).req);
            let mut rv: i32 = 0;
            rv = h2_session_send(data, h2);
            if rv != 0 {
                result = CURLE_SEND_ERROR;
            }
            if nghttp2_session_want_write(h2) != 0 {
                (*(borrow_mut(&mut k)).unwrap()).keepon |= (1 as i32) << 1 as i32;
            }
        }
    }
    return result;
}
unsafe extern "C" fn http2_handle_stream_close(
    mut conn: * mut crate::src::lib::http2::connectdata,
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut stream: * mut crate::src::lib::http2::HTTP,
    mut err: * mut u32,
) -> i64 {
    let mut httpc: Option<&'_ mut crate::src::lib::http2::http_conn> = Some(&mut (*conn).proto.httpc);
    if (*(borrow(& httpc)).unwrap()).pause_stream_id == (*stream).stream_id {
        (*(borrow_mut(&mut httpc)).unwrap()).pause_stream_id = 0 as i32;
    }
    drained_transfer(data, borrow_mut(&mut httpc));
    if (*(borrow(& httpc)).unwrap()).pause_stream_id == 0 as i32 {
        if h2_process_pending_input(data, borrow_mut(&mut httpc), err) != 0 as i32 {
            return -(1 as i32) as ssize_t;
        }
    }
    (*stream).closed = 0 as i32 != 0;
    if (*stream).error == NGHTTP2_REFUSED_STREAM as i32 as u32 {
        Curl_conncontrol(conn, 1 as i32);
        let mut fresh35 = &mut ((*data).state);
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
        let mut trailp: * mut i8 = Curl_dyn_ptr(&mut (*stream).trailer_recvbuf);
        let mut lf: * mut i8 = 0 as *mut i8;
        loop {
            let mut len: u64 = 0 as i32 as size_t;
            let mut result: u32 = CURLE_OK;
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
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut pri_spec: * mut crate::src::lib::http2::nghttp2_priority_spec,
) {
    let mut depstream: * mut crate::src::lib::http2::HTTP = if !((*data).set.stream_depends_on).is_null() {
        (*(*data).set.stream_depends_on).req.p.http
    } else {
        0 as *mut HTTP
    };
    let mut depstream_id: i32 = if !depstream.is_null() {
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
    let mut fresh36 = &mut ((*data).state);
    (*fresh36).set_stream_depends_e(((*data).set).stream_depends_e());
    let mut fresh37 = &mut ((*data).state.stream_depends_on);
    *fresh37 = (*data).set.stream_depends_on;
}
unsafe extern "C" fn h2_session_send(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut h2: * mut crate::src::lib::speedcheck::nghttp2_session,
) -> i32 {
    let mut stream: * mut crate::src::lib::http2::HTTP = (*data).req.p.http;
    let mut httpc: Option<&'_ mut crate::src::lib::http2::http_conn> = Some(&mut (*(*data).conn).proto.httpc);
    set_transfer(borrow_mut(&mut httpc), data);
    if (*data).set.stream_weight != (*data).state.stream_weight
        || ((*data).set).stream_depends_e() as i32
            != ((*data).state).stream_depends_e() as i32
        || (*data).set.stream_depends_on != (*data).state.stream_depends_on
    {
        let mut pri_spec: crate::src::lib::http2::nghttp2_priority_spec = nghttp2_priority_spec {
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
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut sockindex: i32,
    mut mem: * mut i8,
    mut len: u64,
    mut err: * mut u32,
) -> i64 {
    let mut nread: i64 = 0;
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    let mut httpc: Option<&'_ mut crate::src::lib::http2::http_conn> = Some(&mut (*conn).proto.httpc);
    let mut stream: * mut crate::src::lib::http2::HTTP = (*data).req.p.http;
    if should_close_session(borrow_mut(&mut httpc)) != 0 {
        if ((*conn).bits).close() != 0 {
            *err = CURLE_OK;
            return 0 as i32 as ssize_t;
        }
        *err = CURLE_HTTP2;
        return -(1 as i32) as ssize_t;
    }
    let mut fresh38 = &mut ((*stream).upload_mem);
    *fresh38 = 0 as *const uint8_t;
    (*stream).upload_len = 0 as i32 as size_t;
    if (*stream).bodystarted as i32 != 0
        && (*stream).nread_header_recvbuf < Curl_dyn_len(&mut (*stream).header_recvbuf)
    {
        let mut left: u64 = (Curl_dyn_len(&mut (*stream).header_recvbuf))
            .wrapping_sub((*stream).nread_header_recvbuf);
        let mut ncopy: u64 = if len < left { len } else { left };
        memcpy(
            mem as *mut libc::c_void,
            (Curl_dyn_ptr(&mut (*stream).header_recvbuf))
                .offset((*stream).nread_header_recvbuf as isize) as *const libc::c_void,
            ncopy,
        );
        let mut fresh39 = &mut ((*stream).nread_header_recvbuf);
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
            let mut fresh40 = &mut ((*stream).mem);
            *fresh40 = mem;
        }
        if (*(borrow(& httpc)).unwrap()).pause_stream_id == (*stream).stream_id
            && ((*stream).pausedata).is_null()
        {
            (*(borrow_mut(&mut httpc)).unwrap()).pause_stream_id = 0 as i32;
            if h2_process_pending_input(data, borrow_mut(&mut httpc), err) != 0 as i32 {
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
        let mut fresh41 = &mut ((*stream).pausedata);
        *fresh41 = (*fresh41).offset(nread as isize);
        let mut fresh42 = &mut ((*stream).pauselen);
        *fresh42 = (*fresh42 as u64).wrapping_sub(nread as u64)
            as size_t as size_t;
        if (*stream).pauselen == 0 as i32 as u64 {
            (*(borrow_mut(&mut httpc)).unwrap()).pause_stream_id = 0 as i32;
            let mut fresh43 = &mut ((*stream).pausedata);
            *fresh43 = 0 as *const uint8_t;
            (*stream).pauselen = 0 as i32 as size_t;
            if h2_process_pending_input(data, borrow_mut(&mut httpc), err) != 0 as i32 {
                return -(1 as i32) as ssize_t;
            }
        }
        return nread;
    } else {
        if (*(borrow(& httpc)).unwrap()).pause_stream_id != 0 {
            if (*stream).closed {
                return 0 as i32 as ssize_t;
            }
            *err = CURLE_AGAIN;
            return -(1 as i32) as ssize_t;
        } else {
            let mut fresh44 = &mut ((*stream).mem);
            *fresh44 = mem;
            (*stream).len = len;
            (*stream).memlen = 0 as i32 as size_t;
            if (*(borrow(& httpc)).unwrap()).inbuflen == 0 as i32 as u64 {
                nread = ((*(borrow(& httpc)).unwrap()).recv_underlying)
                    .expect(
                        "non-null function pointer",
                    )(
                    data,
                    0 as i32,
                    (*(borrow_mut(&mut httpc)).unwrap()).inbuf,
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
                (*(borrow_mut(&mut httpc)).unwrap()).inbuflen = nread as size_t;
            } else {
                nread = ((*(borrow(& httpc)).unwrap()).inbuflen).wrapping_sub((*(borrow(& httpc)).unwrap()).nread_inbuf)
                    as ssize_t;
            }
            if h2_process_pending_input(data, borrow_mut(&mut httpc), err) != 0 {
                return -(1 as i32) as ssize_t;
            }
        }
    }
    if (*stream).memlen != 0 {
        let mut retlen: i64 = (*stream).memlen as ssize_t;
        (*stream).memlen = 0 as i32 as size_t;
        if !((*(borrow(& httpc)).unwrap()).pause_stream_id == (*stream).stream_id) {
            if !(*stream).closed {
                drained_transfer(data, borrow_mut(&mut httpc));
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
    mut p: * const i8,
    mut len: u64,
) -> bool {
    let mut end: * const i8 = p.offset(len as isize);
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
    mut name: * const i8,
    mut namelen: u64,
    mut value: * const i8,
    mut valuelen: u64,
) -> u32 {
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
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut sockindex: i32,
    mut mem: * const core::ffi::c_void,
    mut len: u64,
    mut err: * mut u32,
) -> i64 {
    let mut current_block: u64;
    let mut rv: i32 = 0;
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    let mut httpc: Option<&'_ mut crate::src::lib::http2::http_conn> = Some(&mut (*conn).proto.httpc);
    let mut stream: * mut crate::src::lib::http2::HTTP = (*data).req.p.http;
    let mut nva: * mut crate::src::lib::http2::nghttp2_nv = 0 as *mut nghttp2_nv;
    let mut nheader: u64 = 0;
    let mut i: u64 = 0;
    let mut authority_idx: u64 = 0;
    let mut hdbuf: * mut i8 = mem as *mut i8;
    let mut end: * mut i8 = 0 as *mut i8;
    let mut line_end: * mut i8 = 0 as *mut i8;
    let mut data_prd: crate::src::lib::http2::nghttp2_data_provider = nghttp2_data_provider {
        source: nghttp2_data_source { fd: 0 },
        read_callback: None,
    };
    let mut stream_id: i32 = 0;
    let mut h2: * mut crate::src::lib::speedcheck::nghttp2_session = (*(borrow_mut(&mut httpc)).unwrap()).h2;
    let mut pri_spec: crate::src::lib::http2::nghttp2_priority_spec = nghttp2_priority_spec {
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
        let mut fresh45 = &mut ((*stream).upload_mem);
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
        let mut fresh46 = &mut ((*stream).upload_mem);
        *fresh46 = 0 as *const uint8_t;
        (*stream).upload_len = 0 as i32 as size_t;
        if should_close_session(borrow_mut(&mut httpc)) != 0 {
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
                let mut fresh47 = &mut ((*nva.offset(0 as i32 as isize)).name);
                *fresh47 = b":method\0" as *const u8 as *const i8
                    as *mut u8;
                (*nva.offset(0 as i32 as isize))
                    .namelen = strlen(
                    (*nva.offset(0 as i32 as isize)).name as *mut i8,
                );
                let mut fresh48 = &mut ((*nva.offset(0 as i32 as isize)).value);
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
                        let mut fresh49 = &mut ((*nva.offset(1 as i32 as isize))
                            .name);
                        *fresh49 = b":path\0" as *const u8 as *const i8
                            as *mut u8;
                        (*nva.offset(1 as i32 as isize))
                            .namelen = strlen(
                            (*nva.offset(1 as i32 as isize)).name
                                as *mut i8,
                        );
                        let mut fresh50 = &mut ((*nva.offset(1 as i32 as isize))
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
                            let mut fresh51 = &mut ((*nva
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
                                let mut fresh52 = &mut ((*nva
                                    .offset(2 as i32 as isize))
                                    .value);
                                *fresh52 = b"https\0" as *const u8 as *const i8
                                    as *mut u8;
                            } else {
                                let mut fresh53 = &mut ((*nva
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
                                    let mut hlen: u64 = 0;
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
                                        let mut fresh54 = &mut ((*nva.offset(i as isize)).name);
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
                                        let mut fresh55 = &mut ((*nva.offset(i as isize)).name);
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
                                            let mut fresh56 = &mut ((*nva.offset(i as isize)).value);
                                            *fresh56 = b"trailers\0" as *const u8 as *const i8
                                                as *mut uint8_t;
                                            (*nva.offset(i as isize))
                                                .valuelen = (::std::mem::size_of::<[i8; 9]>()
                                                as u64)
                                                .wrapping_sub(1 as i32 as u64);
                                        }
                                        _ => {
                                            let mut fresh57 = &mut ((*nva.offset(i as isize)).value);
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
                                            let mut authority: crate::src::lib::http2::nghttp2_nv = *nva
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
                                        let mut acc: u64 = 0 as i32 as size_t;
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
                                                    data_source_read_callback,
                                                );
                                                data_prd.source.ptr = (0 as * mut core::ffi::c_void);
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
                                        if should_close_session(borrow_mut(&mut httpc)) != 0 {
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
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut conn: * mut crate::src::lib::http2::connectdata,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut httpc: Option<&'_ mut crate::src::lib::http2::http_conn> = Some(&mut (*conn).proto.httpc);
    let mut stream: * mut crate::src::lib::http2::HTTP = (*data).req.p.http;
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
    let mut fresh58 = &mut ((*stream).upload_mem);
    *fresh58 = 0 as *const uint8_t;
    (*stream).upload_len = 0 as i32 as size_t;
    let mut fresh59 = &mut ((*stream).mem);
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
        let mut fresh60 = &mut ((*conn).handler);
        *fresh60 = &Curl_handler_http2_ssl;
    } else {
        let mut fresh61 = &mut ((*conn).handler);
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
    let mut fresh62 = &mut ((*conn).bits);
    (*fresh62).set_multiplex(1 as i32 as bit);
    (*conn).httpversion = 20 as i32 as u8;
    (*(*conn).bundle).multiuse = 2 as i32;
    (*(borrow_mut(&mut httpc)).unwrap()).inbuflen = 0 as i32 as size_t;
    (*(borrow_mut(&mut httpc)).unwrap()).nread_inbuf = 0 as i32 as size_t;
    (*(borrow_mut(&mut httpc)).unwrap()).pause_stream_id = 0 as i32;
    (*(borrow_mut(&mut httpc)).unwrap()).drain_total = 0 as i32 as size_t;
    Curl_infof(
        data,
        b"Connection state changed (HTTP/2 confirmed)\0" as *const u8
            as *const i8,
    );
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_switched(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut mem: * const i8,
    mut nread: u64,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut conn: * mut crate::src::lib::http2::connectdata = (*data).conn;
    let mut httpc: Option<&'_ mut crate::src::lib::http2::http_conn> = Some(&mut (*conn).proto.httpc);
    let mut rv: i32 = 0;
    let mut stream: * mut crate::src::lib::http2::HTTP = (*data).req.p.http;
    result = Curl_http2_setup(data, conn);
    if result as u64 != 0 {
        return result;
    }
    let mut fresh63 = &mut ((*(borrow_mut(&mut httpc)).unwrap()).recv_underlying);
    *fresh63 = (*conn).recv[0 as i32 as usize];
    let mut fresh64 = &mut ((*(borrow_mut(&mut httpc)).unwrap()).send_underlying);
    *fresh64 = (*conn).send[0 as i32 as usize];
    let mut fresh65 = &mut ((*conn).recv[0 as i32 as usize]);
    *fresh65 = Some(
        http2_recv,
    );
    let mut fresh66 = &mut ((*conn).send[0 as i32 as usize]);
    *fresh66 = Some(
        http2_send,
    );
    if (*data).req.upgr101 as u32
        == UPGR101_RECEIVED as i32 as u32
    {
        (*stream).stream_id = 1 as i32;
        rv = nghttp2_session_upgrade2(
            (*(borrow_mut(&mut httpc)).unwrap()).h2,
            ((*(borrow_mut(&mut httpc)).unwrap()).binsettings).as_mut_ptr(),
            (*(borrow_mut(&mut httpc)).unwrap()).binlen,
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
            (*(borrow_mut(&mut httpc)).unwrap()).h2,
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
        populate_settings(data, borrow_mut(&mut httpc));
        (*stream).stream_id = -(1 as i32);
        rv = nghttp2_submit_settings(
            (*(borrow_mut(&mut httpc)).unwrap()).h2,
            NGHTTP2_FLAG_NONE as i32 as uint8_t,
            ((*(borrow_mut(&mut httpc)).unwrap()).local_settings).as_mut_ptr(),
            (*(borrow_mut(&mut httpc)).unwrap()).local_settings_num,
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
        (*(borrow_mut(&mut httpc)).unwrap()).h2,
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
        memcpy((*(borrow_mut(&mut httpc)).unwrap()).inbuf as *mut libc::c_void, mem as *const libc::c_void, nread);
    }
    (*(borrow_mut(&mut httpc)).unwrap()).inbuflen = nread;
    if -(1 as i32) == h2_process_pending_input(data, borrow_mut(&mut httpc), &mut result) {
        return CURLE_HTTP2;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_stream_pause(
    mut data: * mut crate::src::lib::http2::Curl_easy,
    mut pause: bool,
) -> u32 {
    if (*(*(*data).conn).handler).protocol
        & ((1 as i32) << 0 as i32
            | (1 as i32) << 1 as i32) as u32 == 0
        || ((*(*data).conn).proto.httpc.h2).is_null()
    {
        return CURLE_OK
    } else {
        let mut stream: * mut crate::src::lib::http2::HTTP = (*data).req.p.http;
        let mut httpc: Option<&'_ mut crate::src::lib::http2::http_conn> = Some(&mut (*(*data).conn).proto.httpc);
        let mut window: u32 = (!pause as i32
            * (32 as i32 * 1024 as i32 * 1024 as i32))
            as uint32_t;
        let mut rv: i32 = nghttp2_session_set_local_window_size(
            (*(borrow_mut(&mut httpc)).unwrap()).h2,
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
        rv = h2_session_send(data, (*(borrow_mut(&mut httpc)).unwrap()).h2);
        if rv != 0 {
            return CURLE_SEND_ERROR;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_add_child(
    mut parent: * mut crate::src::lib::http2::Curl_easy,
    mut child: * mut crate::src::lib::http2::Curl_easy,
    mut exclusive: bool,
) -> u32 {
    if !parent.is_null() {
        let mut tail: Option<&'_ mut * mut crate::src::lib::http2::Curl_http2_dep> = Option::<&'_ mut * mut crate::src::lib::http2::Curl_http2_dep>::None;
        let mut dep: * mut crate::src::lib::http2::Curl_http2_dep = Curl_ccalloc
            .expect(
                "non-null function pointer",
            )(
            1 as i32 as size_t,
            ::std::mem::size_of::<Curl_http2_dep>() as u64,
        ) as *mut Curl_http2_dep;
        if dep.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        let mut fresh67 = &mut ((*dep).data);
        *fresh67 = child;
        if !((*parent).set.stream_dependents).is_null() && exclusive as i32 != 0
        {
            let mut node: * mut crate::src::lib::http2::Curl_http2_dep = (*parent).set.stream_dependents;
            while !node.is_null() {
                let mut fresh68 = &mut ((*(*node).data).set.stream_depends_on);
                *fresh68 = child;
                node = (*node).next;
            }
            tail = Some(&mut (*child).set.stream_dependents);
            while !(*(borrow_mut(&mut tail)).unwrap()).is_null() {
                tail = Some(&mut (**(borrow_mut(&mut tail)).unwrap()).next);
            }
            *(borrow_mut(&mut tail)).unwrap() = (*parent).set.stream_dependents;
            let mut fresh69 = &mut ((*parent).set.stream_dependents);
            *fresh69 = 0 as *mut Curl_http2_dep;
        }
        tail = Some(&mut (*parent).set.stream_dependents);
        while !(*(borrow_mut(&mut tail)).unwrap()).is_null() {
            let mut fresh70 = &mut ((*(**(borrow_mut(&mut tail)).unwrap()).data).set);
            (*fresh70).set_stream_depends_e(0 as i32 as bit);
            tail = Some(&mut (**(borrow_mut(&mut tail)).unwrap()).next);
        }
        *(borrow_mut(&mut tail)).unwrap() = dep;
    }
    let mut fresh71 = &mut ((*child).set.stream_depends_on);
    *fresh71 = parent;
    let mut fresh72 = &mut ((*child).set);
    (*fresh72).set_stream_depends_e(exclusive as bit);
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_remove_child(
    mut parent: * mut crate::src::lib::http2::Curl_easy,
    mut child: * mut crate::src::lib::http2::Curl_easy,
) {
    let mut last: * mut crate::src::lib::http2::Curl_http2_dep = 0 as *mut Curl_http2_dep;
    let mut data: * mut crate::src::lib::http2::Curl_http2_dep = (*parent).set.stream_dependents;
    while !data.is_null() && (*data).data != child {
        last = data;
        data = (*data).next;
    }
    if !data.is_null() {
        if !last.is_null() {
            let mut fresh73 = &mut ((*last).next);
            *fresh73 = (*data).next;
        } else {
            let mut fresh74 = &mut ((*parent).set.stream_dependents);
            *fresh74 = (*data).next;
        }
        Curl_cfree.expect("non-null function pointer")(data as *mut libc::c_void);
    }
    let mut fresh75 = &mut ((*child).set.stream_depends_on);
    *fresh75 = 0 as *mut Curl_easy;
    let mut fresh76 = &mut ((*child).set);
    (*fresh76).set_stream_depends_e(0 as i32 as bit);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http2_cleanup_dependencies(mut data: * mut crate::src::lib::http2::Curl_easy) {
    while !((*data).set.stream_dependents).is_null() {
        let mut tmp: * mut crate::src::lib::http2::Curl_easy = (*(*data).set.stream_dependents).data;
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
pub unsafe extern "C" fn Curl_h2_http_1_1_error(mut data: * mut crate::src::lib::http2::Curl_easy) -> bool {
    let mut stream: * mut crate::src::lib::http2::HTTP = (*data).req.p.http;
    return (*stream).error == NGHTTP2_HTTP_1_1_REQUIRED as i32 as u32;
}
use crate::laertes_rt::*;
