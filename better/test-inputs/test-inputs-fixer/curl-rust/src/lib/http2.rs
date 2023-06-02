use :: c2rust_bitfields;
use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type Curl_URL;
    pub type thread_data;
    pub type altsvcinfo;
    pub type hsts;
    pub type TELNET;
    pub type smb_request;
    pub type ldapreqinfo;
    pub type contenc_writer;
    pub type psl_ctx_st;
    pub type Curl_share;
    pub type http_connect_state;
    pub type ldapconninfo;
    pub type tftp_state_data;
    pub type nghttp2_session;
    pub type Gsasl_session;
    pub type Gsasl;
    pub type ssl_backend_data;
    pub type nghttp2_session_callbacks;
    fn curl_easy_duphandle(curl: *mut CURL) -> *mut CURL;
    fn strlen(_: *const i8) -> u64;
    fn strncmp(_: *const i8, _: *const i8, _: u64) -> i32;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn curl_url() -> *mut CURLU;
    fn curl_url_cleanup(handle: *mut CURLU);
    fn curl_url_get(
        handle: *mut CURLU,
        what: CURLUPart,
        part: *mut *mut i8,
        flags: u32,
    ) -> CURLUcode;
    fn curl_url_set(handle: *mut CURLU, what: CURLUPart, part: *const i8, flags: u32) -> CURLUcode;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: u64) -> i32;
    fn memchr(_: *const libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
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
    fn nghttp2_session_check_request_allowed(session: *mut nghttp2_session) -> i32;
    fn nghttp2_session_set_local_window_size(
        session: *mut nghttp2_session,
        flags: uint8_t,
        stream_id: int32_t,
        window_size: int32_t,
    ) -> i32;
    fn nghttp2_version(least_version: i32) -> *mut nghttp2_info;
    fn nghttp2_is_fatal(lib_error_code: i32) -> i32;
    fn nghttp2_session_want_read(session: *mut nghttp2_session) -> i32;
    fn nghttp2_session_resume_data(session: *mut nghttp2_session, stream_id: int32_t) -> i32;
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
    fn nghttp2_session_callbacks_new(callbacks_ptr: *mut *mut nghttp2_session_callbacks) -> i32;
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
    fn Curl_now() -> curltime;
    fn Curl_timediff(t1: curltime, t2: curltime) -> timediff_t;
    fn Curl_dyn_init(s: *mut dynbuf, toobig: size_t);
    fn Curl_dyn_free(s: *mut dynbuf);
    fn Curl_dyn_addn(s: *mut dynbuf, mem: *const libc::c_void, len: size_t) -> CURLcode;
    fn Curl_dyn_add(s: *mut dynbuf, str: *const i8) -> CURLcode;
    fn Curl_dyn_addf(s: *mut dynbuf, fmt: *const i8, _: ...) -> CURLcode;
    fn Curl_dyn_ptr(s: *const dynbuf) -> *mut i8;
    fn Curl_dyn_len(s: *const dynbuf) -> size_t;
    fn Curl_http(data: *mut Curl_easy, done: *mut bool) -> CURLcode;
    fn Curl_http_done(data: *mut Curl_easy, _: CURLcode, premature: bool) -> CURLcode;
    fn Curl_infof(_: *mut Curl_easy, fmt: *const i8, _: ...);
    fn Curl_failf(_: *mut Curl_easy, fmt: *const i8, _: ...);
    fn Curl_client_write(data: *mut Curl_easy, type_0: i32, ptr: *mut i8, len: size_t) -> CURLcode;
    fn Curl_debug(data: *mut Curl_easy, type_0: curl_infotype, ptr: *mut i8, size: size_t) -> i32;
    fn Curl_socket_check(
        readfd: curl_socket_t,
        readfd2: curl_socket_t,
        writefd: curl_socket_t,
        timeout_ms: timediff_t,
    ) -> i32;
    fn Curl_base64url_encode(
        data: *mut Curl_easy,
        inputbuff: *const i8,
        insize: size_t,
        outptr: *mut *mut i8,
        outlen: *mut size_t,
    ) -> CURLcode;
    fn Curl_strcasecompare(first: *const i8, second: *const i8) -> i32;
    fn Curl_strncasecompare(first: *const i8, second: *const i8, max: size_t) -> i32;
    fn Curl_strntolower(dest: *mut i8, src: *const i8, n: size_t);
    fn Curl_expire(data: *mut Curl_easy, milli: timediff_t, _: expire_id);
    fn Curl_set_in_callback(data: *mut Curl_easy, value: bool);
    fn Curl_multi_add_perform(
        multi: *mut Curl_multi,
        data: *mut Curl_easy,
        conn: *mut connectdata,
    ) -> CURLMcode;
    fn Curl_multi_max_concurrent_streams(multi: *mut Curl_multi) -> u32;
    fn Curl_close(datap: *mut *mut Curl_easy) -> CURLcode;
    fn Curl_connalive(conn: *mut connectdata) -> bool;
    fn Curl_conncontrol(conn: *mut connectdata, closeit: i32);
    fn Curl_saferealloc(ptr: *mut libc::c_void, size: size_t) -> *mut libc::c_void;
    fn curl_msnprintf(buffer: *mut i8, maxlength: size_t, format: *const i8, _: ...) -> i32;
    fn curl_maprintf(format: *const i8, _: ...) -> *mut i8;
    static mut Curl_cmalloc: curl_malloc_callback;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_ccalloc: curl_calloc_callback;
}
pub type __uint8_t = u8;
pub type __int32_t = i32;
pub type __uint32_t = u32;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __pid_t = i32;
pub type __time_t = i64;
pub type __ssize_t = i64;
pub type __socklen_t = u32;
pub type pid_t = __pid_t;
pub type ssize_t = __ssize_t;
pub type time_t = __time_t;
pub type size_t = u64;
pub type int32_t = __int32_t;
pub type socklen_t = __socklen_t;
pub type sa_family_t = u16;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [i8; 14],
}
pub type curl_socklen_t = socklen_t;
pub type curl_off_t = i64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: i32,
    pub _IO_read_ptr: *mut i8,
    pub _IO_read_end: *mut i8,
    pub _IO_read_base: *mut i8,
    pub _IO_write_base: *mut i8,
    pub _IO_write_ptr: *mut i8,
    pub _IO_write_end: *mut i8,
    pub _IO_buf_base: *mut i8,
    pub _IO_buf_end: *mut i8,
    pub _IO_save_base: *mut i8,
    pub _IO_backup_base: *mut i8,
    pub _IO_save_end: *mut i8,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: i32,
    pub _flags2: i32,
    pub _old_offset: __off_t,
    pub _cur_column: u16,
    pub _vtable_offset: i8,
    pub _shortbuf: [i8; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: i32,
    pub _unused2: [i8; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_easy {
    pub magic: u32,
    pub next: *mut Curl_easy,
    pub prev: *mut Curl_easy,
    pub conn: *mut connectdata,
    pub connect_queue: Curl_llist_element,
    pub conn_queue: Curl_llist_element,
    pub mstate: CURLMstate,
    pub result: CURLcode,
    pub msg: Curl_message,
    pub sockets: [curl_socket_t; 5],
    pub actions: [u8; 5],
    pub numsocks: i32,
    pub dns: Names,
    pub multi: *mut Curl_multi,
    pub multi_easy: *mut Curl_multi,
    pub share: *mut Curl_share,
    pub psl: *mut PslCache,
    pub req: SingleRequest,
    pub set: UserDefined,
    pub cookies: *mut CookieInfo,
    pub hsts: *mut hsts,
    pub asi: *mut altsvcinfo,
    pub progress: Progress,
    pub state: UrlState,
    pub wildcard: WildcardData,
    pub info: PureInfo,
    pub tsi: curl_tlssessioninfo,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_tlssessioninfo {
    pub backend: curl_sslbackend,
    pub internals: *mut libc::c_void,
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
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct PureInfo {
    pub httpcode: i32,
    pub httpproxycode: i32,
    pub httpversion: i32,
    pub filetime: time_t,
    pub header_size: curl_off_t,
    pub request_size: curl_off_t,
    pub proxyauthavail: u64,
    pub httpauthavail: u64,
    pub numconnects: i64,
    pub contenttype: *mut i8,
    pub wouldredirect: *mut i8,
    pub retry_after: curl_off_t,
    pub conn_primary_ip: [i8; 46],
    pub conn_primary_port: i32,
    pub conn_local_ip: [i8; 46],
    pub conn_local_port: i32,
    pub conn_scheme: *const i8,
    pub conn_protocol: u32,
    pub certs: curl_certinfo,
    pub pxcode: CURLproxycode,
    #[bitfield(name = "timecond", ty = "bit", bits = "0..=0")]
    pub timecond: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
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
    pub certinfo: *mut *mut curl_slist,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_slist {
    pub data: *mut i8,
    pub next: *mut curl_slist,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct WildcardData {
    pub state: wildcard_states,
    pub path: *mut i8,
    pub pattern: *mut i8,
    pub filelist: Curl_llist,
    pub protdata: *mut libc::c_void,
    pub dtor: wildcard_dtor,
    pub customptr: *mut libc::c_void,
}
pub type wildcard_dtor = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_llist {
    pub head: *mut Curl_llist_element,
    pub tail: *mut Curl_llist_element,
    pub dtor: Curl_llist_dtor,
    pub size: size_t,
}
pub type Curl_llist_dtor = Option<unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_llist_element {
    pub ptr: *mut libc::c_void,
    pub prev: *mut Curl_llist_element,
    pub next: *mut Curl_llist_element,
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
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct UrlState {
    pub conn_cache: *mut conncache,
    pub keeps_speed: curltime,
    pub lastconnect_id: i64,
    pub headerb: dynbuf,
    pub buffer: *mut i8,
    pub ulbuf: *mut i8,
    pub current_speed: curl_off_t,
    pub first_host: *mut i8,
    pub retrycount: i32,
    pub first_remote_port: i32,
    pub session: *mut Curl_ssl_session,
    pub sessionage: i64,
    pub tempwrite: [tempbuf; 3],
    pub tempcount: u32,
    pub os_errno: i32,
    pub scratch: *mut i8,
    pub followlocation: i64,
    pub prev_signal: Option<unsafe extern "C" fn(i32) -> ()>,
    pub digest: digestdata,
    pub proxydigest: digestdata,
    pub authhost: auth,
    pub authproxy: auth,
    pub async_0: Curl_async,
    pub engine: *mut libc::c_void,
    pub expiretime: curltime,
    pub timenode: Curl_tree,
    pub timeoutlist: Curl_llist,
    pub expires: [time_node; 13],
    pub most_recent_ftp_entrypath: *mut i8,
    pub httpwant: u8,
    pub httpversion: u8,
    #[bitfield(name = "prev_block_had_trailing_cr", ty = "bit", bits = "0..=0")]
    pub prev_block_had_trailing_cr: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 5],
    pub crlf_conversions: curl_off_t,
    pub range: *mut i8,
    pub resume_from: curl_off_t,
    pub rtsp_next_client_CSeq: i64,
    pub rtsp_next_server_CSeq: i64,
    pub rtsp_CSeq_recv: i64,
    pub infilesize: curl_off_t,
    pub drain: size_t,
    pub fread_func: curl_read_callback,
    pub in_0: *mut libc::c_void,
    pub stream_depends_on: *mut Curl_easy,
    pub stream_weight: i32,
    pub uh: *mut CURLU,
    pub up: urlpieces,
    pub httpreq: Curl_HttpReq,
    pub url: *mut i8,
    pub referer: *mut i8,
    pub cookielist: *mut curl_slist,
    pub resolve: *mut curl_slist,
    pub trailers_bytes_sent: size_t,
    pub trailers_buf: dynbuf,
    pub trailers_state: trailers_state,
    pub aptr: dynamically_allocated_data,
    #[bitfield(name = "multi_owned_by_easy", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "this_is_a_follow", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "refused_stream", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "errorbuf", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "allow_port", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "authproblem", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "ftp_trying_alternative", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "wildcardmatch", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "expect100header", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "disableexpect", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "use_range", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "rangestringalloc", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "done", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "stream_depends_e", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "previouslypending", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "cookie_engine", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "prefer_ascii", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "list_only", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "url_alloc", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "referer_alloc", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "wildcard_resolve", ty = "bit", bits = "20..=20")]
    pub multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve:
        [u8; 3],
    #[bitfield(padding)]
    pub c2rust_padding_0: [u8; 5],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dynamically_allocated_data {
    pub proxyuserpwd: *mut i8,
    pub uagent: *mut i8,
    pub accept_encoding: *mut i8,
    pub userpwd: *mut i8,
    pub rangeline: *mut i8,
    pub ref_0: *mut i8,
    pub host: *mut i8,
    pub cookiehost: *mut i8,
    pub rtsp_transport: *mut i8,
    pub te: *mut i8,
    pub user: *mut i8,
    pub passwd: *mut i8,
    pub proxyuser: *mut i8,
    pub proxypasswd: *mut i8,
}
pub type trailers_state = u32;
pub const TRAILERS_DONE: trailers_state = 3;
pub const TRAILERS_SENDING: trailers_state = 2;
pub const TRAILERS_INITIALIZED: trailers_state = 1;
pub const TRAILERS_NONE: trailers_state = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dynbuf {
    pub bufr: *mut i8,
    pub leng: size_t,
    pub allc: size_t,
    pub toobig: size_t,
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
    pub scheme: *mut i8,
    pub hostname: *mut i8,
    pub port: *mut i8,
    pub user: *mut i8,
    pub password: *mut i8,
    pub options: *mut i8,
    pub path: *mut i8,
    pub query: *mut i8,
}
pub type CURLU = Curl_URL;
pub type curl_read_callback =
    Option<unsafe extern "C" fn(*mut i8, size_t, size_t, *mut libc::c_void) -> size_t>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct time_node {
    pub list: Curl_llist_element,
    pub time: curltime,
    pub eid: expire_id,
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
    pub tv_sec: time_t,
    pub tv_usec: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_tree {
    pub smaller: *mut Curl_tree,
    pub larger: *mut Curl_tree,
    pub samen: *mut Curl_tree,
    pub samep: *mut Curl_tree,
    pub key: curltime,
    pub payload: *mut libc::c_void,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct Curl_async {
    pub hostname: *mut i8,
    pub dns: *mut Curl_dns_entry,
    pub tdata: *mut thread_data,
    pub resolver: *mut libc::c_void,
    pub port: i32,
    pub status: i32,
    #[bitfield(name = "done", ty = "bit", bits = "0..=0")]
    pub done: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_dns_entry {
    pub addr: *mut Curl_addrinfo,
    pub timestamp: time_t,
    pub inuse: i64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_addrinfo {
    pub ai_flags: i32,
    pub ai_family: i32,
    pub ai_socktype: i32,
    pub ai_protocol: i32,
    pub ai_addrlen: curl_socklen_t,
    pub ai_canonname: *mut i8,
    pub ai_addr: *mut sockaddr,
    pub ai_next: *mut Curl_addrinfo,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct auth {
    pub want: u64,
    pub picked: u64,
    pub avail: u64,
    #[bitfield(name = "done", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "multipass", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "iestyle", ty = "bit", bits = "2..=2")]
    pub done_multipass_iestyle: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct digestdata {
    pub nonce: *mut i8,
    pub cnonce: *mut i8,
    pub realm: *mut i8,
    pub algo: i32,
    pub opaque: *mut i8,
    pub qop: *mut i8,
    pub algorithm: *mut i8,
    pub nc: i32,
    #[bitfield(name = "stale", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "userhash", ty = "bit", bits = "1..=1")]
    pub stale_userhash: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tempbuf {
    pub b: dynbuf,
    pub type_0: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_ssl_session {
    pub name: *mut i8,
    pub conn_to_host: *mut i8,
    pub scheme: *const i8,
    pub sessionid: *mut libc::c_void,
    pub idsize: size_t,
    pub age: i64,
    pub remote_port: i32,
    pub conn_to_port: i32,
    pub ssl_config: ssl_primary_config,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ssl_primary_config {
    pub version: i64,
    pub version_max: i64,
    pub CApath: *mut i8,
    pub CAfile: *mut i8,
    pub issuercert: *mut i8,
    pub clientcert: *mut i8,
    pub random_file: *mut i8,
    pub egdsocket: *mut i8,
    pub cipher_list: *mut i8,
    pub cipher_list13: *mut i8,
    pub pinned_key: *mut i8,
    pub cert_blob: *mut curl_blob,
    pub ca_info_blob: *mut curl_blob,
    pub issuercert_blob: *mut curl_blob,
    pub curves: *mut i8,
    #[bitfield(name = "verifypeer", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "verifyhost", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "verifystatus", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "sessionid", ty = "bit", bits = "3..=3")]
    pub verifypeer_verifyhost_verifystatus_sessionid: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_blob {
    pub data: *mut libc::c_void,
    pub len: size_t,
    pub flags: u32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct conncache {
    pub hash: Curl_hash,
    pub num_conn: size_t,
    pub next_connection_id: i64,
    pub last_cleanup: curltime,
    pub closure_handle: *mut Curl_easy,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_hash {
    pub table: *mut Curl_llist,
    pub hash_func: hash_function,
    pub comp_func: comp_function,
    pub dtor: Curl_hash_dtor,
    pub slots: i32,
    pub size: size_t,
}
pub type Curl_hash_dtor = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type comp_function =
    Option<unsafe extern "C" fn(*mut libc::c_void, size_t, *mut libc::c_void, size_t) -> size_t>;
pub type hash_function = Option<unsafe extern "C" fn(*mut libc::c_void, size_t, size_t) -> size_t>;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct Progress {
    pub lastshow: time_t,
    pub size_dl: curl_off_t,
    pub size_ul: curl_off_t,
    pub downloaded: curl_off_t,
    pub uploaded: curl_off_t,
    pub current_speed: curl_off_t,
    pub width: i32,
    pub flags: i32,
    pub timespent: timediff_t,
    pub dlspeed: curl_off_t,
    pub ulspeed: curl_off_t,
    pub t_nslookup: timediff_t,
    pub t_connect: timediff_t,
    pub t_appconnect: timediff_t,
    pub t_pretransfer: timediff_t,
    pub t_starttransfer: timediff_t,
    pub t_redirect: timediff_t,
    pub start: curltime,
    pub t_startsingle: curltime,
    pub t_startop: curltime,
    pub t_acceptdata: curltime,
    pub ul_limit_start: curltime,
    pub ul_limit_size: curl_off_t,
    pub dl_limit_start: curltime,
    pub dl_limit_size: curl_off_t,
    pub speeder: [curl_off_t; 6],
    pub speeder_time: [curltime; 6],
    pub speeder_c: i32,
    #[bitfield(name = "callback", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "is_t_startransfer_set", ty = "bit", bits = "1..=1")]
    pub callback_is_t_startransfer_set: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
pub type timediff_t = curl_off_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CookieInfo {
    pub cookies: [*mut Cookie; 256],
    pub filename: *mut i8,
    pub numcookies: i64,
    pub running: bool,
    pub newsession: bool,
    pub lastct: i32,
    pub next_expiration: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Cookie {
    pub next: *mut Cookie,
    pub name: *mut i8,
    pub value: *mut i8,
    pub path: *mut i8,
    pub spath: *mut i8,
    pub domain: *mut i8,
    pub expires: curl_off_t,
    pub expirestr: *mut i8,
    pub version: *mut i8,
    pub maxage: *mut i8,
    pub tailmatch: bool,
    pub secure: bool,
    pub livecookie: bool,
    pub httponly: bool,
    pub creationtime: i32,
    pub prefix: u8,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct UserDefined {
    pub err: *mut FILE,
    pub debugdata: *mut libc::c_void,
    pub errorbuffer: *mut i8,
    pub proxyport: i64,
    pub out: *mut libc::c_void,
    pub in_set: *mut libc::c_void,
    pub writeheader: *mut libc::c_void,
    pub rtp_out: *mut libc::c_void,
    pub use_port: i64,
    pub httpauth: u64,
    pub proxyauth: u64,
    pub socks5auth: u64,
    pub maxredirs: i64,
    pub keep_post: i32,
    pub postfields: *mut libc::c_void,
    pub seek_func: curl_seek_callback,
    pub postfieldsize: curl_off_t,
    pub localport: u16,
    pub localportrange: i32,
    pub fwrite_func: curl_write_callback,
    pub fwrite_header: curl_write_callback,
    pub fwrite_rtp: curl_write_callback,
    pub fread_func_set: curl_read_callback,
    pub fprogress: curl_progress_callback,
    pub fxferinfo: curl_xferinfo_callback,
    pub fdebug: curl_debug_callback,
    pub ioctl_func: curl_ioctl_callback,
    pub fsockopt: curl_sockopt_callback,
    pub sockopt_client: *mut libc::c_void,
    pub fopensocket: curl_opensocket_callback,
    pub opensocket_client: *mut libc::c_void,
    pub fclosesocket: curl_closesocket_callback,
    pub closesocket_client: *mut libc::c_void,
    pub seek_client: *mut libc::c_void,
    pub convfromnetwork: curl_conv_callback,
    pub convtonetwork: curl_conv_callback,
    pub convfromutf8: curl_conv_callback,
    pub hsts_read: curl_hstsread_callback,
    pub hsts_read_userp: *mut libc::c_void,
    pub hsts_write: curl_hstswrite_callback,
    pub hsts_write_userp: *mut libc::c_void,
    pub progress_client: *mut libc::c_void,
    pub ioctl_client: *mut libc::c_void,
    pub timeout: i64,
    pub connecttimeout: i64,
    pub accepttimeout: i64,
    pub happy_eyeballs_timeout: i64,
    pub server_response_timeout: i64,
    pub maxage_conn: i64,
    pub tftp_blksize: i64,
    pub filesize: curl_off_t,
    pub low_speed_limit: i64,
    pub low_speed_time: i64,
    pub max_send_speed: curl_off_t,
    pub max_recv_speed: curl_off_t,
    pub set_resume_from: curl_off_t,
    pub headers: *mut curl_slist,
    pub proxyheaders: *mut curl_slist,
    pub httppost: *mut curl_httppost,
    pub mimepost: curl_mimepart,
    pub quote: *mut curl_slist,
    pub postquote: *mut curl_slist,
    pub prequote: *mut curl_slist,
    pub source_quote: *mut curl_slist,
    pub source_prequote: *mut curl_slist,
    pub source_postquote: *mut curl_slist,
    pub telnet_options: *mut curl_slist,
    pub resolve: *mut curl_slist,
    pub connect_to: *mut curl_slist,
    pub timecondition: curl_TimeCond,
    pub proxytype: curl_proxytype,
    pub timevalue: time_t,
    pub method: Curl_HttpReq,
    pub httpwant: u8,
    pub ssl: ssl_config_data,
    pub proxy_ssl: ssl_config_data,
    pub general_ssl: ssl_general_config,
    pub dns_cache_timeout: i64,
    pub buffer_size: i64,
    pub upload_buffer_size: u32,
    pub private_data: *mut libc::c_void,
    pub http200aliases: *mut curl_slist,
    pub ipver: u8,
    pub max_filesize: curl_off_t,
    pub ftp_filemethod: curl_ftpfile,
    pub ftpsslauth: curl_ftpauth,
    pub ftp_ccc: curl_ftpccc,
    pub ftp_create_missing_dirs: i32,
    pub ssh_keyfunc: curl_sshkeycallback,
    pub ssh_keyfunc_userp: *mut libc::c_void,
    pub use_netrc: CURL_NETRC_OPTION,
    pub use_ssl: curl_usessl,
    pub new_file_perms: i64,
    pub new_directory_perms: i64,
    pub ssh_auth_types: i64,
    pub str_0: [*mut i8; 80],
    pub blobs: [*mut curl_blob; 8],
    pub scope_id: u32,
    pub allowed_protocols: i64,
    pub redir_protocols: i64,
    pub mail_rcpt: *mut curl_slist,
    pub rtspreq: Curl_RtspReq,
    pub rtspversion: i64,
    pub chunk_bgn: curl_chunk_bgn_callback,
    pub chunk_end: curl_chunk_end_callback,
    pub fnmatch: curl_fnmatch_callback,
    pub fnmatch_data: *mut libc::c_void,
    pub gssapi_delegation: i64,
    pub tcp_keepidle: i64,
    pub tcp_keepintvl: i64,
    pub maxconnects: size_t,
    pub expect_100_timeout: i64,
    pub stream_depends_on: *mut Curl_easy,
    pub stream_weight: i32,
    pub stream_dependents: *mut Curl_http2_dep,
    pub resolver_start: curl_resolver_start_callback,
    pub resolver_start_client: *mut libc::c_void,
    pub upkeep_interval_ms: i64,
    pub fmultidone: multidone_func,
    pub dohfor: *mut Curl_easy,
    pub uh: *mut CURLU,
    pub trailer_data: *mut libc::c_void,
    pub trailer_callback: curl_trailer_callback,
    #[bitfield(name = "is_fread_set", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "is_fwrite_set", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "free_referer", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "tftp_no_options", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "sep_headers", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "cookiesession", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "crlf", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "strip_path_slash", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "ssh_compression", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "get_filetime", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "tunnel_thru_httpproxy", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "prefer_ascii", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "remote_append", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "list_only", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "ftp_use_port", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "ftp_use_epsv", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "ftp_use_eprt", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "ftp_use_pret", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "ftp_skip_ip", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "hide_progress", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "http_fail_on_error", ty = "bit", bits = "20..=20")]
    #[bitfield(name = "http_keep_sending_on_error", ty = "bit", bits = "21..=21")]
    #[bitfield(name = "http_follow_location", ty = "bit", bits = "22..=22")]
    #[bitfield(name = "http_transfer_encoding", ty = "bit", bits = "23..=23")]
    #[bitfield(name = "allow_auth_to_other_hosts", ty = "bit", bits = "24..=24")]
    #[bitfield(name = "include_header", ty = "bit", bits = "25..=25")]
    #[bitfield(name = "http_set_referer", ty = "bit", bits = "26..=26")]
    #[bitfield(name = "http_auto_referer", ty = "bit", bits = "27..=27")]
    #[bitfield(name = "opt_no_body", ty = "bit", bits = "28..=28")]
    #[bitfield(name = "upload", ty = "bit", bits = "29..=29")]
    #[bitfield(name = "verbose", ty = "bit", bits = "30..=30")]
    #[bitfield(name = "krb", ty = "bit", bits = "31..=31")]
    #[bitfield(name = "reuse_forbid", ty = "bit", bits = "32..=32")]
    #[bitfield(name = "reuse_fresh", ty = "bit", bits = "33..=33")]
    #[bitfield(name = "no_signal", ty = "bit", bits = "34..=34")]
    #[bitfield(name = "tcp_nodelay", ty = "bit", bits = "35..=35")]
    #[bitfield(name = "ignorecl", ty = "bit", bits = "36..=36")]
    #[bitfield(name = "connect_only", ty = "bit", bits = "37..=37")]
    #[bitfield(name = "http_te_skip", ty = "bit", bits = "38..=38")]
    #[bitfield(name = "http_ce_skip", ty = "bit", bits = "39..=39")]
    #[bitfield(name = "proxy_transfer_mode", ty = "bit", bits = "40..=40")]
    #[bitfield(name = "sasl_ir", ty = "bit", bits = "41..=41")]
    #[bitfield(name = "wildcard_enabled", ty = "bit", bits = "42..=42")]
    #[bitfield(name = "tcp_keepalive", ty = "bit", bits = "43..=43")]
    #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "44..=44")]
    #[bitfield(name = "ssl_enable_npn", ty = "bit", bits = "45..=45")]
    #[bitfield(name = "ssl_enable_alpn", ty = "bit", bits = "46..=46")]
    #[bitfield(name = "path_as_is", ty = "bit", bits = "47..=47")]
    #[bitfield(name = "pipewait", ty = "bit", bits = "48..=48")]
    #[bitfield(name = "suppress_connect_headers", ty = "bit", bits = "49..=49")]
    #[bitfield(name = "dns_shuffle_addresses", ty = "bit", bits = "50..=50")]
    #[bitfield(name = "stream_depends_e", ty = "bit", bits = "51..=51")]
    #[bitfield(name = "haproxyprotocol", ty = "bit", bits = "52..=52")]
    #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "53..=53")]
    #[bitfield(name = "disallow_username_in_url", ty = "bit", bits = "54..=54")]
    #[bitfield(name = "doh", ty = "bit", bits = "55..=55")]
    #[bitfield(name = "doh_get", ty = "bit", bits = "56..=56")]
    #[bitfield(name = "doh_verifypeer", ty = "bit", bits = "57..=57")]
    #[bitfield(name = "doh_verifyhost", ty = "bit", bits = "58..=58")]
    #[bitfield(name = "doh_verifystatus", ty = "bit", bits = "59..=59")]
    #[bitfield(name = "http09_allowed", ty = "bit", bits = "60..=60")]
    #[bitfield(name = "mail_rcpt_allowfails", ty = "bit", bits = "61..=61")]
    pub is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails:
        [u8; 8],
}
pub type curl_trailer_callback =
    Option<unsafe extern "C" fn(*mut *mut curl_slist, *mut libc::c_void) -> i32>;
pub type multidone_func = Option<unsafe extern "C" fn(*mut Curl_easy, CURLcode) -> i32>;
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
pub type curl_resolver_start_callback =
    Option<unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void, *mut libc::c_void) -> i32>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_http2_dep {
    pub next: *mut Curl_http2_dep,
    pub data: *mut Curl_easy,
}
pub type curl_fnmatch_callback =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, *const i8) -> i32>;
pub type curl_chunk_end_callback = Option<unsafe extern "C" fn(*mut libc::c_void) -> i64>;
pub type curl_chunk_bgn_callback =
    Option<unsafe extern "C" fn(*const libc::c_void, *mut libc::c_void, i32) -> i64>;
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
pub type curl_sshkeycallback = Option<
    unsafe extern "C" fn(
        *mut CURL,
        *const curl_khkey,
        *const curl_khkey,
        curl_khmatch,
        *mut libc::c_void,
    ) -> i32,
>;
pub type curl_khmatch = u32;
pub const CURLKHMATCH_LAST: curl_khmatch = 3;
pub const CURLKHMATCH_MISSING: curl_khmatch = 2;
pub const CURLKHMATCH_MISMATCH: curl_khmatch = 1;
pub const CURLKHMATCH_OK: curl_khmatch = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_khkey {
    pub key: *const i8,
    pub len: size_t,
    pub keytype: curl_khtype,
}
pub type curl_khtype = u32;
pub const CURLKHTYPE_ED25519: curl_khtype = 5;
pub const CURLKHTYPE_ECDSA: curl_khtype = 4;
pub const CURLKHTYPE_DSS: curl_khtype = 3;
pub const CURLKHTYPE_RSA: curl_khtype = 2;
pub const CURLKHTYPE_RSA1: curl_khtype = 1;
pub const CURLKHTYPE_UNKNOWN: curl_khtype = 0;
pub type CURL = Curl_easy;
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
    pub max_ssl_sessions: size_t,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ssl_config_data {
    pub primary: ssl_primary_config,
    pub certverifyresult: i64,
    pub CRLfile: *mut i8,
    pub fsslctx: curl_ssl_ctx_callback,
    pub fsslctxp: *mut libc::c_void,
    pub cert_type: *mut i8,
    pub key: *mut i8,
    pub key_blob: *mut curl_blob,
    pub key_type: *mut i8,
    pub key_passwd: *mut i8,
    pub username: *mut i8,
    pub password: *mut i8,
    pub authtype: CURL_TLSAUTH,
    #[bitfield(name = "certinfo", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "falsestart", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "enable_beast", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "no_revoke", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "no_partialchain", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "revoke_best_effort", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "native_ca_store", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "auto_client_cert", ty = "bit", bits = "7..=7")]
    pub certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert:
        [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
pub type CURL_TLSAUTH = u32;
pub const CURL_TLSAUTH_LAST: CURL_TLSAUTH = 2;
pub const CURL_TLSAUTH_SRP: CURL_TLSAUTH = 1;
pub const CURL_TLSAUTH_NONE: CURL_TLSAUTH = 0;
pub type curl_ssl_ctx_callback =
    Option<unsafe extern "C" fn(*mut CURL, *mut libc::c_void, *mut libc::c_void) -> CURLcode>;
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
    pub easy: *mut Curl_easy,
    pub parent: *mut curl_mime,
    pub nextpart: *mut curl_mimepart,
    pub kind: mimekind,
    pub flags: u32,
    pub data: *mut i8,
    pub readfunc: curl_read_callback,
    pub seekfunc: curl_seek_callback,
    pub freefunc: curl_free_callback,
    pub arg: *mut libc::c_void,
    pub fp: *mut FILE,
    pub curlheaders: *mut curl_slist,
    pub userheaders: *mut curl_slist,
    pub mimetype: *mut i8,
    pub filename: *mut i8,
    pub name: *mut i8,
    pub datasize: curl_off_t,
    pub state: mime_state,
    pub encoder: *const mime_encoder,
    pub encstate: mime_encoder_state,
    pub lastreadstatus: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mime_encoder_state {
    pub pos: size_t,
    pub bufbeg: size_t,
    pub bufend: size_t,
    pub buf: [i8; 256],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mime_encoder {
    pub name: *const i8,
    pub encodefunc:
        Option<unsafe extern "C" fn(*mut i8, size_t, bool, *mut curl_mimepart) -> size_t>,
    pub sizefunc: Option<unsafe extern "C" fn(*mut curl_mimepart) -> curl_off_t>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mime_state {
    pub state: mimestate,
    pub ptr: *mut libc::c_void,
    pub offset: curl_off_t,
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
pub type curl_free_callback = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type curl_seek_callback =
    Option<unsafe extern "C" fn(*mut libc::c_void, curl_off_t, i32) -> i32>;
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
    pub easy: *mut Curl_easy,
    pub parent: *mut curl_mimepart,
    pub firstpart: *mut curl_mimepart,
    pub lastpart: *mut curl_mimepart,
    pub boundary: [i8; 41],
    pub state: mime_state,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_httppost {
    pub next: *mut curl_httppost,
    pub name: *mut i8,
    pub namelength: i64,
    pub contents: *mut i8,
    pub contentslength: i64,
    pub buffer: *mut i8,
    pub bufferlength: i64,
    pub contenttype: *mut i8,
    pub contentheader: *mut curl_slist,
    pub more: *mut curl_httppost,
    pub flags: i64,
    pub showfilename: *mut i8,
    pub userp: *mut libc::c_void,
    pub contentlen: curl_off_t,
}
pub type curl_hstswrite_callback = Option<
    unsafe extern "C" fn(
        *mut CURL,
        *mut curl_hstsentry,
        *mut curl_index,
        *mut libc::c_void,
    ) -> CURLSTScode,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_index {
    pub index: size_t,
    pub total: size_t,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct curl_hstsentry {
    pub name: *mut i8,
    pub namelen: size_t,
    #[bitfield(name = "includeSubDomains", ty = "u32", bits = "0..=0")]
    pub includeSubDomains: [u8; 1],
    pub expire: [i8; 18],
}
pub type CURLSTScode = u32;
pub const CURLSTS_FAIL: CURLSTScode = 2;
pub const CURLSTS_DONE: CURLSTScode = 1;
pub const CURLSTS_OK: CURLSTScode = 0;
pub type curl_hstsread_callback =
    Option<unsafe extern "C" fn(*mut CURL, *mut curl_hstsentry, *mut libc::c_void) -> CURLSTScode>;
pub type curl_conv_callback = Option<unsafe extern "C" fn(*mut i8, size_t) -> CURLcode>;
pub type curl_closesocket_callback =
    Option<unsafe extern "C" fn(*mut libc::c_void, curl_socket_t) -> i32>;
pub type curl_socket_t = i32;
pub type curl_opensocket_callback = Option<
    unsafe extern "C" fn(*mut libc::c_void, curlsocktype, *mut curl_sockaddr) -> curl_socket_t,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_sockaddr {
    pub family: i32,
    pub socktype: i32,
    pub protocol: i32,
    pub addrlen: u32,
    pub addr: sockaddr,
}
pub type curlsocktype = u32;
pub const CURLSOCKTYPE_LAST: curlsocktype = 2;
pub const CURLSOCKTYPE_ACCEPT: curlsocktype = 1;
pub const CURLSOCKTYPE_IPCXN: curlsocktype = 0;
pub type curl_sockopt_callback =
    Option<unsafe extern "C" fn(*mut libc::c_void, curl_socket_t, curlsocktype) -> i32>;
pub type curl_ioctl_callback =
    Option<unsafe extern "C" fn(*mut CURL, i32, *mut libc::c_void) -> curlioerr>;
pub type curlioerr = u32;
pub const CURLIOE_LAST: curlioerr = 3;
pub const CURLIOE_FAILRESTART: curlioerr = 2;
pub const CURLIOE_UNKNOWNCMD: curlioerr = 1;
pub const CURLIOE_OK: curlioerr = 0;
pub type curl_debug_callback = Option<
    unsafe extern "C" fn(*mut CURL, curl_infotype, *mut i8, size_t, *mut libc::c_void) -> i32,
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
pub type curl_xferinfo_callback = Option<
    unsafe extern "C" fn(*mut libc::c_void, curl_off_t, curl_off_t, curl_off_t, curl_off_t) -> i32,
>;
pub type curl_progress_callback =
    Option<unsafe extern "C" fn(*mut libc::c_void, f64, f64, f64, f64) -> i32>;
pub type curl_write_callback =
    Option<unsafe extern "C" fn(*mut i8, size_t, size_t, *mut libc::c_void) -> size_t>;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct SingleRequest {
    pub size: curl_off_t,
    pub maxdownload: curl_off_t,
    pub bytecount: curl_off_t,
    pub writebytecount: curl_off_t,
    pub headerbytecount: curl_off_t,
    pub deductheadercount: curl_off_t,
    pub pendingheader: curl_off_t,
    pub start: curltime,
    pub now: curltime,
    pub badheader: C2RustUnnamed_1,
    pub headerline: i32,
    pub str_0: *mut i8,
    pub offset: curl_off_t,
    pub httpcode: i32,
    pub keepon: i32,
    pub start100: curltime,
    pub exp100: expect100,
    pub upgr101: upgrade101,
    pub writer_stack: *mut contenc_writer,
    pub timeofdoc: time_t,
    pub bodywrites: i64,
    pub location: *mut i8,
    pub newurl: *mut i8,
    pub upload_present: ssize_t,
    pub upload_fromhere: *mut i8,
    pub p: C2RustUnnamed,
    pub doh: *mut dohdata,
    #[bitfield(name = "header", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "content_range", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "upload_done", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "ignorebody", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "http_bodyless", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "chunk", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "ignore_cl", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "upload_chunky", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "getheader", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "forbidchunk", ty = "bit", bits = "9..=9")]
    pub header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk:
        [u8; 2],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 6],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dohdata {
    pub headers: *mut curl_slist,
    pub probe: [dnsprobe; 2],
    pub pending: u32,
    pub port: i32,
    pub host: *const i8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dnsprobe {
    pub easy: *mut CURL,
    pub dnstype: i32,
    pub dohbuffer: [u8; 512],
    pub dohlen: size_t,
    pub serverdoh: dynbuf,
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
    pub path: *mut i8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SMTP {
    pub transfer: curl_pp_transfer,
    pub custom: *mut i8,
    pub rcpt: *mut curl_slist,
    pub rcpt_had_ok: bool,
    pub trailing_crlf: bool,
    pub rcpt_last_error: i32,
    pub eob: size_t,
}
pub type curl_pp_transfer = u32;
pub const PPTRANSFER_NONE: curl_pp_transfer = 2;
pub const PPTRANSFER_INFO: curl_pp_transfer = 1;
pub const PPTRANSFER_BODY: curl_pp_transfer = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct RTSP {
    pub http_wrapper: HTTP,
    pub CSeq_sent: i64,
    pub CSeq_recv: i64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HTTP {
    pub sendit: *mut curl_mimepart,
    pub postsize: curl_off_t,
    pub postdata: *const i8,
    pub p_pragma: *const i8,
    pub form: curl_mimepart,
    pub backup: back,
    pub sending: C2RustUnnamed_0,
    pub send_buffer: dynbuf,
    pub stream_id: int32_t,
    pub bodystarted: bool,
    pub header_recvbuf: dynbuf,
    pub nread_header_recvbuf: size_t,
    pub trailer_recvbuf: dynbuf,
    pub status_code: i32,
    pub pausedata: *const uint8_t,
    pub pauselen: size_t,
    pub close_handled: bool,
    pub push_headers: *mut *mut i8,
    pub push_headers_used: size_t,
    pub push_headers_alloc: size_t,
    pub error: uint32_t,
    pub closed: bool,
    pub mem: *mut i8,
    pub len: size_t,
    pub memlen: size_t,
    pub upload_mem: *const uint8_t,
    pub upload_len: size_t,
    pub upload_left: curl_off_t,
}
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type C2RustUnnamed_0 = u32;
pub const HTTPSEND_BODY: C2RustUnnamed_0 = 2;
pub const HTTPSEND_REQUEST: C2RustUnnamed_0 = 1;
pub const HTTPSEND_NADA: C2RustUnnamed_0 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct back {
    pub fread_func: curl_read_callback,
    pub fread_in: *mut libc::c_void,
    pub postdata: *const i8,
    pub postsize: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct POP3 {
    pub transfer: curl_pp_transfer,
    pub id: *mut i8,
    pub custom: *mut i8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct MQTT {
    pub sendleftovers: *mut i8,
    pub nsend: size_t,
    pub npacket: size_t,
    pub firstbyte: u8,
    pub remaining_length: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct IMAP {
    pub transfer: curl_pp_transfer,
    pub mailbox: *mut i8,
    pub uidvalidity: *mut i8,
    pub uid: *mut i8,
    pub mindex: *mut i8,
    pub section: *mut i8,
    pub partial: *mut i8,
    pub query: *mut i8,
    pub custom: *mut i8,
    pub custom_params: *mut i8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct FTP {
    pub path: *mut i8,
    pub pathalloc: *mut i8,
    pub transfer: curl_pp_transfer,
    pub downloadsize: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct FILEPROTO {
    pub path: *mut i8,
    pub freepath: *mut i8,
    pub fd: i32,
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
    pub psl: *const psl_ctx_t,
    pub expires: time_t,
    pub dynamic: bool,
}
pub type psl_ctx_t = psl_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_multi {
    pub magic: u32,
    pub easyp: *mut Curl_easy,
    pub easylp: *mut Curl_easy,
    pub num_easy: i32,
    pub num_alive: i32,
    pub msglist: Curl_llist,
    pub pending: Curl_llist,
    pub socket_cb: curl_socket_callback,
    pub socket_userp: *mut libc::c_void,
    pub push_cb: curl_push_callback,
    pub push_userp: *mut libc::c_void,
    pub hostcache: Curl_hash,
    pub psl: PslCache,
    pub timetree: *mut Curl_tree,
    pub sockhash: Curl_hash,
    pub conn_cache: conncache,
    pub maxconnects: i64,
    pub max_host_connections: i64,
    pub max_total_connections: i64,
    pub timer_cb: curl_multi_timer_callback,
    pub timer_userp: *mut libc::c_void,
    pub timer_lastcall: curltime,
    pub max_concurrent_streams: u32,
    pub wakeup_pair: [curl_socket_t; 2],
    pub multiplexing: bool,
    pub recheckstate: bool,
    pub in_callback: bool,
    pub ipv6_works: bool,
    pub ssl_seeded: bool,
}
pub type curl_multi_timer_callback =
    Option<unsafe extern "C" fn(*mut CURLM, i64, *mut libc::c_void) -> i32>;
pub type CURLM = Curl_multi;
pub type curl_push_callback = Option<
    unsafe extern "C" fn(
        *mut CURL,
        *mut CURL,
        size_t,
        *mut curl_pushheaders,
        *mut libc::c_void,
    ) -> i32,
>;
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
pub type curl_socket_callback = Option<
    unsafe extern "C" fn(
        *mut CURL,
        curl_socket_t,
        i32,
        *mut libc::c_void,
        *mut libc::c_void,
    ) -> i32,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Names {
    pub hostcache: *mut Curl_hash,
    pub hostcachetype: C2RustUnnamed_2,
}
pub type C2RustUnnamed_2 = u32;
pub const HCACHE_SHARED: C2RustUnnamed_2 = 2;
pub const HCACHE_MULTI: C2RustUnnamed_2 = 1;
pub const HCACHE_NONE: C2RustUnnamed_2 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_message {
    pub list: Curl_llist_element,
    pub extmsg: CURLMsg,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CURLMsg {
    pub msg: CURLMSG,
    pub easy_handle: *mut CURL,
    pub data: C2RustUnnamed_3,
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
    pub cnnct: connstate,
    pub bundle_node: Curl_llist_element,
    pub chunk: Curl_chunker,
    pub fclosesocket: curl_closesocket_callback,
    pub closesocket_client: *mut libc::c_void,
    pub connection_id: i64,
    pub dns_entry: *mut Curl_dns_entry,
    pub ip_addr: *mut Curl_addrinfo,
    pub tempaddr: [*mut Curl_addrinfo; 2],
    pub scope_id: u32,
    pub transport: C2RustUnnamed_5,
    pub host: hostname,
    pub hostname_resolve: *mut i8,
    pub secondaryhostname: *mut i8,
    pub conn_to_host: hostname,
    pub socks_proxy: proxy_info,
    pub http_proxy: proxy_info,
    pub port: i32,
    pub remote_port: i32,
    pub conn_to_port: i32,
    pub secondary_port: u16,
    pub primary_ip: [i8; 46],
    pub ip_version: u8,
    pub user: *mut i8,
    pub passwd: *mut i8,
    pub options: *mut i8,
    pub sasl_authzid: *mut i8,
    pub httpversion: u8,
    pub now: curltime,
    pub created: curltime,
    pub lastused: curltime,
    pub sock: [curl_socket_t; 2],
    pub tempsock: [curl_socket_t; 2],
    pub tempfamily: [i32; 2],
    pub recv: [Option<Curl_recv>; 2],
    pub send: [Option<Curl_send>; 2],
    pub ssl: [ssl_connect_data; 2],
    pub proxy_ssl: [ssl_connect_data; 2],
    pub ssl_extra: *mut libc::c_void,
    pub ssl_config: ssl_primary_config,
    pub proxy_ssl_config: ssl_primary_config,
    pub bits: ConnectBits,
    pub num_addr: i32,
    pub connecttime: curltime,
    pub timeoutms_per_addr: [timediff_t; 2],
    pub handler: *const Curl_handler,
    pub given: *const Curl_handler,
    pub keepalive: curltime,
    pub sockfd: curl_socket_t,
    pub writesockfd: curl_socket_t,
    pub easyq: Curl_llist,
    pub seek_func: curl_seek_callback,
    pub seek_client: *mut libc::c_void,
    pub gsasl: gsasldata,
    pub http_ntlm_state: curlntlm,
    pub proxy_ntlm_state: curlntlm,
    pub ntlm: ntlmdata,
    pub proxyntlm: ntlmdata,
    pub trailer: dynbuf,
    pub proto: C2RustUnnamed_4,
    pub connect_state: *mut http_connect_state,
    pub bundle: *mut connectbundle,
    pub unix_domain_socket: *mut i8,
    pub localdev: *mut i8,
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
    pub num_connections: size_t,
    pub conn_list: Curl_llist,
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
    pub state: mqttstate,
    pub nextstate: mqttstate,
    pub packetid: u32,
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
    pub state: smb_conn_state,
    pub user: *mut i8,
    pub domain: *mut i8,
    pub share: *mut i8,
    pub challenge: [u8; 8],
    pub session_key: u32,
    pub uid: u16,
    pub recv_buf: *mut i8,
    pub upload_size: size_t,
    pub send_size: size_t,
    pub sent: size_t,
    pub got: size_t,
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
    pub rtp_buf: *mut i8,
    pub rtp_bufsize: ssize_t,
    pub rtp_channel: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct smtp_conn {
    pub pp: pingpong,
    pub state: smtpstate,
    pub ssldone: bool,
    pub domain: *mut i8,
    pub sasl: SASL,
    pub tls_supported: bool,
    pub size_supported: bool,
    pub utf8_supported: bool,
    pub auth_supported: bool,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SASL {
    pub params: *const SASLproto,
    pub state: saslstate,
    pub authmechs: u16,
    pub prefmech: u16,
    pub authused: u16,
    pub resetprefs: bool,
    pub mutual_auth: bool,
    pub force_ir: bool,
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
    pub service: *const i8,
    pub contcode: i32,
    pub finalcode: i32,
    pub maxirlen: size_t,
    pub sendauth: Option<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *const i8, *const i8) -> CURLcode,
    >,
    pub sendcont:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *const i8) -> CURLcode>,
    pub getmessage: Option<unsafe extern "C" fn(*mut i8, *mut *mut i8) -> ()>,
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
    pub cache: *mut i8,
    pub cache_size: size_t,
    pub nread_resp: size_t,
    pub linestart_resp: *mut i8,
    pub pending_resp: bool,
    pub sendthis: *mut i8,
    pub sendleft: size_t,
    pub sendsize: size_t,
    pub response: curltime,
    pub response_time: timediff_t,
    pub sendbuf: dynbuf,
    pub statemachine: Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode>,
    pub endofresp: Option<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut i8, size_t, *mut i32) -> bool,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pop3_conn {
    pub pp: pingpong,
    pub state: pop3state,
    pub ssldone: bool,
    pub tls_supported: bool,
    pub eob: size_t,
    pub strip: size_t,
    pub sasl: SASL,
    pub authtypes: u32,
    pub preftype: u32,
    pub apoptimestamp: *mut i8,
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
    pub pp: pingpong,
    pub state: imapstate,
    pub ssldone: bool,
    pub preauth: bool,
    pub sasl: SASL,
    pub preftype: u32,
    pub cmdid: u32,
    pub resptag: [i8; 5],
    pub tls_supported: bool,
    pub login_disabled: bool,
    pub ir_supported: bool,
    pub mailbox: *mut i8,
    pub mailbox_uidvalidity: *mut i8,
    pub dyn_0: dynbuf,
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
    pub authlist: *const i8,
    pub passphrase: *const i8,
    pub rsa_pub: *mut i8,
    pub rsa: *mut i8,
    pub authed: bool,
    pub acceptfail: bool,
    pub state: sshstate,
    pub nextstate: sshstate,
    pub actualcode: CURLcode,
    pub quote_item: *mut curl_slist,
    pub quote_path1: *mut i8,
    pub quote_path2: *mut i8,
    pub homedir: *mut i8,
    pub readdir_line: *mut i8,
    pub secondCreateDirs: i32,
    pub orig_waitfor: i32,
    pub slash_pos: *mut i8,
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
    pub binsettings: [uint8_t; 80],
    pub binlen: size_t,
    pub trnsfr: *mut Curl_easy,
    pub h2: *mut nghttp2_session,
    pub send_underlying: Option<Curl_send>,
    pub recv_underlying: Option<Curl_recv>,
    pub inbuf: *mut i8,
    pub inbuflen: size_t,
    pub nread_inbuf: size_t,
    pub pause_stream_id: int32_t,
    pub drain_total: size_t,
    pub settings: h2settings,
    pub local_settings: [nghttp2_settings_entry; 3],
    pub local_settings_num: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_settings_entry {
    pub settings_id: int32_t,
    pub value: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct h2settings {
    pub max_concurrent_streams: uint32_t,
    pub enable_push: bool,
}
pub type Curl_recv =
    unsafe extern "C" fn(*mut Curl_easy, i32, *mut i8, size_t, *mut CURLcode) -> ssize_t;
pub type Curl_send = unsafe extern "C" fn(
    *mut Curl_easy,
    i32,
    *const libc::c_void,
    size_t,
    *mut CURLcode,
) -> ssize_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ftp_conn {
    pub pp: pingpong,
    pub entrypath: *mut i8,
    pub file: *mut i8,
    pub dirs: *mut *mut i8,
    pub dirdepth: i32,
    pub dont_check: bool,
    pub ctl_valid: bool,
    pub cwddone: bool,
    pub cwdcount: i32,
    pub cwdfail: bool,
    pub wait_data_conn: bool,
    pub newport: u16,
    pub newhost: *mut i8,
    pub prevpath: *mut i8,
    pub transfertype: i8,
    pub count1: i32,
    pub count2: i32,
    pub count3: i32,
    pub state: ftpstate,
    pub state_saved: ftpstate,
    pub retr_size_saved: curl_off_t,
    pub server_os: *mut i8,
    pub known_filesize: curl_off_t,
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
    pub target_info: *mut libc::c_void,
    pub ntlm_auth_hlpr_socket: curl_socket_t,
    pub ntlm_auth_hlpr_pid: pid_t,
    pub challenge: *mut i8,
    pub response: *mut i8,
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
    pub ctx: *mut Gsasl,
    pub client: *mut Gsasl_session,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_handler {
    pub scheme: *const i8,
    pub setup_connection:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode>,
    pub do_it: Option<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
    pub done: Option<unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode>,
    pub do_more: Option<unsafe extern "C" fn(*mut Curl_easy, *mut i32) -> CURLcode>,
    pub connect_it: Option<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
    pub connecting: Option<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
    pub doing: Option<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
    pub proto_getsock:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> i32>,
    pub doing_getsock:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> i32>,
    pub domore_getsock:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> i32>,
    pub perform_getsock:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> i32>,
    pub disconnect:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, bool) -> CURLcode>,
    pub readwrite: Option<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut ssize_t, *mut bool) -> CURLcode,
    >,
    pub connection_check:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, u32) -> u32>,
    pub attach: Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> ()>,
    pub defport: i32,
    pub protocol: u32,
    pub family: u32,
    pub flags: u32,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ConnectBits {
    pub tcpconnect: [bool; 2],
    pub proxy_ssl_connected: [bool; 2],
    #[bitfield(name = "httpproxy", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "socksproxy", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "proxy_user_passwd", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "tunnel_proxy", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "proxy_connect_closed", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "close", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "reuse", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "altused", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "conn_to_host", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "conn_to_port", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "proxy", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "user_passwd", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "ipv6_ip", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "ipv6", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "do_more", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "protoconnstart", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "retry", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "authneg", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "rewindaftersend", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "ftp_use_epsv", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "ftp_use_eprt", ty = "bit", bits = "20..=20")]
    #[bitfield(name = "ftp_use_data_ssl", ty = "bit", bits = "21..=21")]
    #[bitfield(name = "ftp_use_control_ssl", ty = "bit", bits = "22..=22")]
    #[bitfield(name = "netrc", ty = "bit", bits = "23..=23")]
    #[bitfield(name = "bound", ty = "bit", bits = "24..=24")]
    #[bitfield(name = "multiplex", ty = "bit", bits = "25..=25")]
    #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "26..=26")]
    #[bitfield(name = "tls_enable_npn", ty = "bit", bits = "27..=27")]
    #[bitfield(name = "tls_enable_alpn", ty = "bit", bits = "28..=28")]
    #[bitfield(name = "connect_only", ty = "bit", bits = "29..=29")]
    #[bitfield(name = "doh", ty = "bit", bits = "30..=30")]
    #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "31..=31")]
    #[bitfield(name = "tls_upgraded", ty = "bit", bits = "32..=32")]
    #[bitfield(name = "sock_accepted", ty = "bit", bits = "33..=33")]
    #[bitfield(name = "parallel_connect", ty = "bit", bits = "34..=34")]
    pub httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect:
        [u8; 5],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ssl_connect_data {
    pub state: ssl_connection_state,
    pub connecting_state: ssl_connect_state,
    pub backend: *mut ssl_backend_data,
    #[bitfield(name = "use_0", ty = "bit", bits = "0..=0")]
    pub use_0: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
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
    pub host: hostname,
    pub port: i64,
    pub proxytype: curl_proxytype,
    pub user: *mut i8,
    pub passwd: *mut i8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostname {
    pub rawalloc: *mut i8,
    pub encalloc: *mut i8,
    pub name: *mut i8,
    pub dispname: *const i8,
}
pub type C2RustUnnamed_5 = u32;
pub const TRNSPRT_QUIC: C2RustUnnamed_5 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_5 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_5 = 3;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_chunker {
    pub datasize: curl_off_t,
    pub state: ChunkyState,
    pub hexindex: u8,
    pub hexbuffer: [i8; 17],
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
    pub state: connect_t,
    pub outstanding: ssize_t,
    pub outp: *mut u8,
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
pub type curl_malloc_callback = Option<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
pub type curl_calloc_callback = Option<unsafe extern "C" fn(size_t, size_t) -> *mut libc::c_void>;
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
pub type nghttp2_data_source_read_callback = Option<
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
pub type nghttp2_send_callback = Option<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        *const uint8_t,
        size_t,
        i32,
        *mut libc::c_void,
    ) -> ssize_t,
>;
pub type nghttp2_on_frame_recv_callback = Option<
    unsafe extern "C" fn(*mut nghttp2_session, *const nghttp2_frame, *mut libc::c_void) -> i32,
>;
pub type nghttp2_on_data_chunk_recv_callback = Option<
    unsafe extern "C" fn(
        *mut nghttp2_session,
        uint8_t,
        int32_t,
        *const uint8_t,
        size_t,
        *mut libc::c_void,
    ) -> i32,
>;
pub type nghttp2_on_stream_close_callback =
    Option<unsafe extern "C" fn(*mut nghttp2_session, int32_t, uint32_t, *mut libc::c_void) -> i32>;
pub type nghttp2_on_begin_headers_callback = Option<
    unsafe extern "C" fn(*mut nghttp2_session, *const nghttp2_frame, *mut libc::c_void) -> i32,
>;
pub type nghttp2_on_header_callback = Option<
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
pub type nghttp2_error_callback =
    Option<unsafe extern "C" fn(*mut nghttp2_session, *const i8, size_t, *mut libc::c_void) -> i32>;
pub const HEADERINST_TE_TRAILERS: header_instruction = 2;
pub const HEADERINST_IGNORE: header_instruction = 1;
pub type header_instruction = u32;
pub const HEADERINST_FORWARD: header_instruction = 0;
#[no_mangle]
pub extern "C" fn Curl_http2_init_state(mut state: *mut UrlState) {
    (unsafe { (*state).stream_weight = 16 as i32 });
}
#[no_mangle]
pub extern "C" fn Curl_http2_init_userset(mut set: *mut UserDefined) {
    (unsafe { (*set).stream_weight = 16 as i32 });
}
extern "C" fn http2_getsock(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sock: *mut curl_socket_t,
) -> i32 {
    let mut c: *const http_conn = unsafe { &mut (*conn).proto.httpc };
    let mut k: *mut SingleRequest = unsafe { &mut (*data).req };
    let mut bitmap: i32 = 0 as i32;
    (unsafe { *sock.offset(0 as i32 as isize) = (*conn).sock[0 as i32 as usize] });
    if (unsafe { (*k).keepon }) & (1 as i32) << 4 as i32 == 0 {
        bitmap |= (1 as i32) << 0 as i32;
    }
    if (unsafe { (*k).keepon }) & ((1 as i32) << 1 as i32 | (1 as i32) << 5 as i32) == (1 as i32) << 1 as i32
        || (unsafe { nghttp2_session_want_write((*c).h2) }) != 0
    {
        bitmap |= (1 as i32) << 16 as i32 + 0 as i32;
    }
    return bitmap;
}
extern "C" fn http2_stream_free(mut http: *mut HTTP) {
    if !http.is_null() {
        (unsafe { Curl_dyn_free(&mut (*http).header_recvbuf) });
        while (unsafe { (*http).push_headers_used }) > 0 as i32 as u64 {
            (unsafe { Curl_cfree.expect("non-null function pointer")(
                *((*http).push_headers)
                    .offset(((*http).push_headers_used).wrapping_sub(1 as i32 as u64) as isize)
                    as *mut libc::c_void,
            ) });
            let fresh0 = unsafe { &mut ((*http).push_headers_used) };
            *fresh0 = (*fresh0).wrapping_sub(1);
        }
        (unsafe { Curl_cfree.expect("non-null function pointer")((*http).push_headers as *mut libc::c_void) });
        let fresh1 = unsafe { &mut ((*http).push_headers) };
        *fresh1 = 0 as *mut *mut i8;
    }
}
extern "C" fn http2_disconnect(
    mut _data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut _dead_connection: bool,
) -> CURLcode {
    let mut c: *mut http_conn = unsafe { &mut (*conn).proto.httpc };
    (unsafe { nghttp2_session_del((*c).h2) });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*c).inbuf as *mut libc::c_void) });
    let fresh2 = unsafe { &mut ((*c).inbuf) };
    *fresh2 = 0 as *mut i8;
    return CURLE_OK;
}
extern "C" fn http2_connisdead(mut data: *mut Curl_easy, mut conn: *mut connectdata) -> bool {
    let mut sval: i32 = 0;
    let mut dead: bool = 1 as i32 != 0;
    if (unsafe { ((*conn).bits).close() }) != 0 {
        return 1 as i32 != 0;
    }
    sval = unsafe { Curl_socket_check(
        (*conn).sock[0 as i32 as usize],
        -(1 as i32),
        -(1 as i32),
        0 as i32 as timediff_t,
    ) };
    if sval == 0 as i32 {
        dead = 0 as i32 != 0;
    } else if sval & 0x4 as i32 != 0 {
        dead = 1 as i32 != 0;
    } else if sval & 0x1 as i32 != 0 {
        dead = !(unsafe { Curl_connalive(conn) });
        if !dead {
            let mut result: CURLcode = CURLE_OK;
            let mut httpc: *mut http_conn = unsafe { &mut (*conn).proto.httpc };
            let mut nread: ssize_t = -(1 as i32) as ssize_t;
            if unsafe { ((*httpc).recv_underlying).is_some() } {
                nread = unsafe { ((*httpc).recv_underlying).expect("non-null function pointer")(
                    data,
                    0 as i32,
                    (*httpc).inbuf,
                    32768 as i32 as size_t,
                    &mut result,
                ) };
            }
            if nread != -(1 as i32) as i64 {
                (unsafe { Curl_infof(
                    data,
                    b"%d bytes stray data read before trying h2 connection\0" as *const u8
                        as *const i8,
                    nread as i32,
                ) });
                (unsafe { (*httpc).nread_inbuf = 0 as i32 as size_t });
                (unsafe { (*httpc).inbuflen = nread as size_t });
                if h2_process_pending_input(data, httpc, &mut result) < 0 as i32 {
                    dead = 1 as i32 != 0;
                }
            } else {
                dead = 1 as i32 != 0;
            }
        }
    }
    return dead;
}
extern "C" fn set_transfer(mut c: *mut http_conn, mut data: *mut Curl_easy) {
    let fresh3 = unsafe { &mut ((*c).trnsfr) };
    *fresh3 = data;
}
extern "C" fn get_transfer(mut c: *mut http_conn) -> *mut Curl_easy {
    return unsafe { (*c).trnsfr };
}
extern "C" fn http2_conncheck(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut checks_to_perform: u32,
) -> u32 {
    let mut ret_val: u32 = 0 as i32 as u32;
    let mut c: *mut http_conn = unsafe { &mut (*conn).proto.httpc };
    let mut rc: i32 = 0;
    let mut send_frames: bool = 0 as i32 != 0;
    if checks_to_perform & ((1 as i32) << 0 as i32) as u32 != 0 {
        if http2_connisdead(data, conn) {
            ret_val |= ((1 as i32) << 0 as i32) as u32;
        }
    }
    if checks_to_perform & ((1 as i32) << 1 as i32) as u32 != 0 {
        let mut now: curltime = unsafe { Curl_now() };
        let mut elapsed: timediff_t = unsafe { Curl_timediff(now, (*conn).keepalive) };
        if elapsed > (unsafe { (*data).set.upkeep_interval_ms }) {
            rc = unsafe { nghttp2_submit_ping((*c).h2, 0 as i32 as uint8_t, 0 as *const uint8_t) };
            if rc == 0 {
                send_frames = 1 as i32 != 0;
            } else {
                (unsafe { Curl_failf(
                    data,
                    b"nghttp2_submit_ping() failed: %s(%d)\0" as *const u8 as *const i8,
                    nghttp2_strerror(rc),
                    rc,
                ) });
            }
            (unsafe { (*conn).keepalive = now });
        }
    }
    if send_frames {
        set_transfer(c, data);
        rc = unsafe { nghttp2_session_send((*c).h2) };
        if rc != 0 {
            (unsafe { Curl_failf(
                data,
                b"nghttp2_session_send() failed: %s(%d)\0" as *const u8 as *const i8,
                nghttp2_strerror(rc),
                rc,
            ) });
        }
    }
    return ret_val;
}
#[no_mangle]
pub extern "C" fn Curl_http2_setup_req(mut data: *mut Curl_easy) {
    let mut http: *mut HTTP = unsafe { (*data).req.p.http };
    (unsafe { (*http).bodystarted = 0 as i32 != 0 });
    (unsafe { (*http).status_code = -(1 as i32) });
    let fresh4 = unsafe { &mut ((*http).pausedata) };
    *fresh4 = 0 as *const uint8_t;
    (unsafe { (*http).pauselen = 0 as i32 as size_t });
    (unsafe { (*http).closed = 0 as i32 != 0 });
    (unsafe { (*http).close_handled = 0 as i32 != 0 });
    let fresh5 = unsafe { &mut ((*http).mem) };
    *fresh5 = 0 as *mut i8;
    (unsafe { (*http).len = 0 as i32 as size_t });
    (unsafe { (*http).memlen = 0 as i32 as size_t });
    (unsafe { (*http).error = NGHTTP2_NO_ERROR as i32 as uint32_t });
}
#[no_mangle]
pub extern "C" fn Curl_http2_setup_conn(mut conn: *mut connectdata) {
    (unsafe { (*conn).proto.httpc.settings.max_concurrent_streams = 100 as i32 as uint32_t });
}
static mut Curl_handler_http2: Curl_handler =  {
    {
        let mut init = Curl_handler {
            scheme: b"HTTP\0" as *const u8 as *const i8,
            setup_connection: None,
            do_it: Some(Curl_http as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode),
            done: Some(
                Curl_http_done as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
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
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, bool) -> CURLcode,
            ),
            readwrite: None,
            connection_check: Some(
                http2_conncheck
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, u32) -> u32,
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
static mut Curl_handler_http2_ssl: Curl_handler =  {
    {
        let mut init = Curl_handler {
            scheme: b"HTTPS\0" as *const u8 as *const i8,
            setup_connection: None,
            do_it: Some(Curl_http as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode),
            done: Some(
                Curl_http_done as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
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
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, bool) -> CURLcode,
            ),
            readwrite: None,
            connection_check: Some(
                http2_conncheck
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, u32) -> u32,
            ),
            attach: None,
            defport: 80 as i32,
            protocol: ((1 as i32) << 1 as i32) as u32,
            family: ((1 as i32) << 0 as i32) as u32,
            flags: ((1 as i32) << 0 as i32 | (1 as i32) << 9 as i32) as u32,
        };
        init
    }
};
#[no_mangle]
pub extern "C" fn Curl_http2_ver(mut p: *mut i8, mut len: size_t) {
    let mut h2: *mut nghttp2_info = unsafe { nghttp2_version(0 as i32) };
    (unsafe { curl_msnprintf(
        p,
        len,
        b"nghttp2/%s\0" as *const u8 as *const i8,
        (*h2).version_str,
    ) });
}
extern "C" fn send_callback(
    mut _h2: *mut nghttp2_session,
    mut mem: *const uint8_t,
    mut length: size_t,
    mut _flags: i32,
    mut userp: *mut libc::c_void,
) -> ssize_t {
    let mut conn: *mut connectdata = userp as *mut connectdata;
    let mut c: *mut http_conn = unsafe { &mut (*conn).proto.httpc };
    let mut data: *mut Curl_easy = get_transfer(c);
    let mut written: ssize_t = 0;
    let mut result: CURLcode = CURLE_OK;
    if unsafe { ((*c).send_underlying).is_none() } {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32 as ssize_t;
    }
    written = unsafe { ((*c).send_underlying).expect("non-null function pointer")(
        data,
        0 as i32,
        mem as *const libc::c_void,
        length,
        &mut result,
    ) };
    if result as u32 == CURLE_AGAIN as i32 as u32 {
        return NGHTTP2_ERR_WOULDBLOCK as i32 as ssize_t;
    }
    if written == -(1 as i32) as i64 {
        (unsafe { Curl_failf(
            data,
            b"Failed sending HTTP2 data\0" as *const u8 as *const i8,
        ) });
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32 as ssize_t;
    }
    if written == 0 {
        return NGHTTP2_ERR_WOULDBLOCK as i32 as ssize_t;
    }
    return written;
}
#[no_mangle]
pub extern "C" fn curl_pushheader_bynum(mut h: *mut curl_pushheaders, mut num: size_t) -> *mut i8 {
    if h.is_null() || !(!(unsafe { (*h).data }).is_null() && (unsafe { (*(*h).data).magic }) == 0xc0dedbad as u32) {
        return 0 as *mut i8;
    } else {
        let mut stream: *mut HTTP = unsafe { (*(*h).data).req.p.http };
        if num < (unsafe { (*stream).push_headers_used }) {
            return unsafe { *((*stream).push_headers).offset(num as isize) };
        }
    }
    return 0 as *mut i8;
}
#[no_mangle]
pub extern "C" fn curl_pushheader_byname(
    mut h: *mut curl_pushheaders,
    mut header: *const i8,
) -> *mut i8 {
    if h.is_null()
        || !(!(unsafe { (*h).data }).is_null() && (unsafe { (*(*h).data).magic }) == 0xc0dedbad as u32)
        || header.is_null()
        || (unsafe { *header.offset(0 as i32 as isize) }) == 0
        || (unsafe { strcmp(header, b":\0" as *const u8 as *const i8) }) == 0
        || !(unsafe { strchr(header.offset(1 as i32 as isize), ':' as i32) }).is_null()
    {
        return 0 as *mut i8;
    } else {
        let mut stream: *mut HTTP = unsafe { (*(*h).data).req.p.http };
        let mut len: size_t = unsafe { strlen(header) };
        let mut i: size_t = 0;
        i = 0 as i32 as size_t;
        while i < (unsafe { (*stream).push_headers_used }) {
            if (unsafe { strncmp(header, *((*stream).push_headers).offset(i as isize), len) }) == 0 {
                if !((unsafe { *(*((*stream).push_headers).offset(i as isize)).offset(len as isize) }) as i32
                    != ':' as i32)
                {
                    return (unsafe { &mut *(*((*stream).push_headers).offset(i as isize))
                        .offset(len.wrapping_add(1 as i32 as u64) as isize) })
                        as *mut i8;
                }
            }
            i = i.wrapping_add(1);
        }
    }
    return 0 as *mut i8;
}
extern "C" fn drained_transfer(mut data: *mut Curl_easy, mut httpc: *mut http_conn) {
    let fresh6 = unsafe { &mut ((*httpc).drain_total) };
    *fresh6 = (*fresh6 as u64).wrapping_sub(unsafe { (*data).state.drain }) as size_t as size_t;
    (unsafe { (*data).state.drain = 0 as i32 as size_t });
}
extern "C" fn drain_this(mut data: *mut Curl_easy, mut httpc: *mut http_conn) {
    let fresh7 = unsafe { &mut ((*data).state.drain) };
    *fresh7 = (*fresh7).wrapping_add(1);
    let fresh8 = unsafe { &mut ((*httpc).drain_total) };
    *fresh8 = (*fresh8).wrapping_add(1);
}
extern "C" fn duphandle(mut data: *mut Curl_easy) -> *mut Curl_easy {
    let mut second: *mut Curl_easy = unsafe { curl_easy_duphandle(data) };
    if !second.is_null() {
        let mut http: *mut HTTP = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
            1 as i32 as size_t,
            ::std::mem::size_of::<HTTP>() as u64,
        ) }) as *mut HTTP;
        if http.is_null() {
            (unsafe { Curl_close(&mut second) });
        } else {
            let fresh9 = unsafe { &mut ((*second).req.p.http) };
            *fresh9 = http;
            (unsafe { Curl_dyn_init(
                &mut (*http).header_recvbuf,
                (128 as i32 * 1024 as i32) as size_t,
            ) });
            Curl_http2_setup_req(second);
            (unsafe { (*second).state.stream_weight = (*data).state.stream_weight });
        }
    }
    return second;
}
extern "C" fn set_transfer_url(mut data: *mut Curl_easy, mut hp: *mut curl_pushheaders) -> i32 {
    let mut current_block: u64;
    let mut v: *const i8 = 0 as *const i8;
    let mut u: *mut CURLU = unsafe { curl_url() };
    let mut uc: CURLUcode = CURLUE_OK;
    let mut url: *mut i8 = 0 as *mut i8;
    let mut rc: i32 = 0 as i32;
    v = curl_pushheader_byname(hp, b":scheme\0" as *const u8 as *const i8);
    if !v.is_null() {
        uc = unsafe { curl_url_set(u, CURLUPART_SCHEME, v, 0 as i32 as u32) };
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
            v = curl_pushheader_byname(hp, b":authority\0" as *const u8 as *const i8);
            if !v.is_null() {
                uc = unsafe { curl_url_set(u, CURLUPART_HOST, v, 0 as i32 as u32) };
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
                    v = curl_pushheader_byname(hp, b":path\0" as *const u8 as *const i8);
                    if !v.is_null() {
                        uc = unsafe { curl_url_set(u, CURLUPART_PATH, v, 0 as i32 as u32) };
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
                            uc = unsafe { curl_url_get(u, CURLUPART_URL, &mut url, 0 as i32 as u32) };
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
    (unsafe { curl_url_cleanup(u) });
    if rc != 0 {
        return rc;
    }
    if (unsafe { ((*data).state).url_alloc() }) != 0 {
        (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.url as *mut libc::c_void) });
    }
    let fresh10 = unsafe { &mut ((*data).state) };
    (*fresh10).set_url_alloc(1 as i32 as bit);
    let fresh11 = unsafe { &mut ((*data).state.url) };
    *fresh11 = url;
    return 0 as i32;
}
extern "C" fn push_promise(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut frame: *const nghttp2_push_promise,
) -> i32 {
    let mut rv: i32 = 0;
    if unsafe { ((*(*data).multi).push_cb).is_some() } {
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
            (unsafe { Curl_infof(
                data,
                b"failed to duplicate handle\0" as *const u8 as *const i8,
            ) });
            rv = 1 as i32;
        } else {
            heads.data = data;
            heads.frame = frame;
            stream = unsafe { (*data).req.p.http };
            if stream.is_null() {
                (unsafe { Curl_failf(data, b"Internal NULL stream!\0" as *const u8 as *const i8) });
                (unsafe { Curl_close(&mut newhandle) });
                rv = 1 as i32;
            } else {
                rv = set_transfer_url(newhandle, &mut heads);
                if rv != 0 {
                    (unsafe { Curl_close(&mut newhandle) });
                    rv = 1 as i32;
                } else {
                    (unsafe { Curl_set_in_callback(data, 1 as i32 != 0) });
                    rv = unsafe { ((*(*data).multi).push_cb).expect("non-null function pointer")(
                        data,
                        newhandle,
                        (*stream).push_headers_used,
                        &mut heads,
                        (*(*data).multi).push_userp,
                    ) };
                    (unsafe { Curl_set_in_callback(data, 0 as i32 != 0) });
                    i = 0 as i32 as size_t;
                    while i < (unsafe { (*stream).push_headers_used }) {
                        (unsafe { Curl_cfree.expect("non-null function pointer")(
                            *((*stream).push_headers).offset(i as isize) as *mut libc::c_void,
                        ) });
                        i = i.wrapping_add(1);
                    }
                    (unsafe { Curl_cfree.expect("non-null function pointer")(
                        (*stream).push_headers as *mut libc::c_void,
                    ) });
                    let fresh12 = unsafe { &mut ((*stream).push_headers) };
                    *fresh12 = 0 as *mut *mut i8;
                    (unsafe { (*stream).push_headers_used = 0 as i32 as size_t });
                    if rv != 0 {
                        http2_stream_free(unsafe { (*newhandle).req.p.http });
                        let fresh13 = unsafe { &mut ((*newhandle).req.p.http) };
                        *fresh13 = 0 as *mut HTTP;
                        (unsafe { Curl_close(&mut newhandle) });
                    } else {
                        newstream = unsafe { (*newhandle).req.p.http };
                        (unsafe { (*newstream).stream_id = (*frame).promised_stream_id });
                        (unsafe { (*newhandle).req.maxdownload = -(1 as i32) as curl_off_t });
                        (unsafe { (*newhandle).req.size = -(1 as i32) as curl_off_t });
                        rc = unsafe { Curl_multi_add_perform((*data).multi, newhandle, conn) };
                        if rc as u64 != 0 {
                            (unsafe { Curl_infof(
                                data,
                                b"failed to add handle to multi\0" as *const u8 as *const i8,
                            ) });
                            http2_stream_free(unsafe { (*newhandle).req.p.http });
                            let fresh14 = unsafe { &mut ((*newhandle).req.p.http) };
                            *fresh14 = 0 as *mut HTTP;
                            (unsafe { Curl_close(&mut newhandle) });
                            rv = 1 as i32;
                        } else {
                            httpc = unsafe { &mut (*conn).proto.httpc };
                            rv = unsafe { nghttp2_session_set_stream_user_data(
                                (*httpc).h2,
                                (*frame).promised_stream_id,
                                newhandle as *mut libc::c_void,
                            ) };
                            if rv != 0 {
                                (unsafe { Curl_infof(
                                    data,
                                    b"failed to set user_data for stream %d\0" as *const u8
                                        as *const i8,
                                    (*frame).promised_stream_id,
                                ) });
                                rv = 1 as i32;
                            } else {
                                (unsafe { Curl_dyn_init(
                                    &mut (*newstream).header_recvbuf,
                                    (128 as i32 * 1024 as i32) as size_t,
                                ) });
                                (unsafe { Curl_dyn_init(
                                    &mut (*newstream).trailer_recvbuf,
                                    (128 as i32 * 1024 as i32) as size_t,
                                ) });
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
extern "C" fn multi_connchanged(mut multi: *mut Curl_multi) {
    (unsafe { (*multi).recheckstate = 1 as i32 != 0 });
}
extern "C" fn on_frame_recv(
    mut session: *mut nghttp2_session,
    mut frame: *const nghttp2_frame,
    mut userp: *mut libc::c_void,
) -> i32 {
    let mut conn: *mut connectdata = userp as *mut connectdata;
    let mut httpc: *mut http_conn = unsafe { &mut (*conn).proto.httpc };
    let mut data_s: *mut Curl_easy = 0 as *mut Curl_easy;
    let mut stream: *mut HTTP = 0 as *mut HTTP;
    let mut data: *mut Curl_easy = get_transfer(httpc);
    let mut rv: i32 = 0;
    let mut left: size_t = 0;
    let mut ncopy: size_t = 0;
    let mut stream_id: int32_t = unsafe { (*frame).hd.stream_id };
    let mut result: CURLcode = CURLE_OK;
    if stream_id == 0 {
        if (unsafe { (*frame).hd.type_0 }) as i32 == NGHTTP2_SETTINGS as i32 {
            let mut max_conn: uint32_t = unsafe { (*httpc).settings.max_concurrent_streams };
            (unsafe { (*httpc).settings.max_concurrent_streams = nghttp2_session_get_remote_settings(
                session,
                NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
            ) });
            (unsafe { (*httpc).settings.enable_push =
                nghttp2_session_get_remote_settings(session, NGHTTP2_SETTINGS_ENABLE_PUSH) != 0 });
            if max_conn != (unsafe { (*httpc).settings.max_concurrent_streams }) {
                (unsafe { Curl_infof(
                    data,
                    b"Connection state changed (MAX_CONCURRENT_STREAMS == %u)!\0" as *const u8
                        as *const i8,
                    (*httpc).settings.max_concurrent_streams,
                ) });
                multi_connchanged(unsafe { (*data).multi });
            }
        }
        return 0 as i32;
    }
    data_s = (unsafe { nghttp2_session_get_stream_user_data(session, stream_id) }) as *mut Curl_easy;
    if data_s.is_null() {
        return 0 as i32;
    }
    stream = unsafe { (*data_s).req.p.http };
    if stream.is_null() {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    match (unsafe { (*frame).hd.type_0 }) as i32 {
        0 => {
            if !(unsafe { (*stream).bodystarted }) {
                rv = unsafe { nghttp2_submit_rst_stream(
                    session,
                    NGHTTP2_FLAG_NONE as i32 as uint8_t,
                    stream_id,
                    NGHTTP2_PROTOCOL_ERROR as i32 as uint32_t,
                ) };
                if (unsafe { nghttp2_is_fatal(rv) }) != 0 {
                    return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
                }
            }
        }
        1 => {
            if !(unsafe { (*stream).bodystarted }) {
                if (unsafe { (*stream).status_code }) == -(1 as i32) {
                    return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
                }
                if (unsafe { (*stream).status_code }) / 100 as i32 != 1 as i32 {
                    (unsafe { (*stream).bodystarted = 1 as i32 != 0 });
                    (unsafe { (*stream).status_code = -(1 as i32) });
                }
                result = unsafe { Curl_dyn_add(
                    &mut (*stream).header_recvbuf,
                    b"\r\n\0" as *const u8 as *const i8,
                ) };
                if result as u64 != 0 {
                    return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
                }
                left = (unsafe { Curl_dyn_len(&mut (*stream).header_recvbuf) })
                    .wrapping_sub(unsafe { (*stream).nread_header_recvbuf });
                ncopy = if (unsafe { (*stream).len }) < left {
                    unsafe { (*stream).len }
                } else {
                    left
                };
                (unsafe { memcpy(
                    &mut *((*stream).mem).offset((*stream).memlen as isize) as *mut i8
                        as *mut libc::c_void,
                    (Curl_dyn_ptr(&mut (*stream).header_recvbuf))
                        .offset((*stream).nread_header_recvbuf as isize)
                        as *const libc::c_void,
                    ncopy,
                ) });
                let fresh15 = unsafe { &mut ((*stream).nread_header_recvbuf) };
                *fresh15 = (*fresh15 as u64).wrapping_add(ncopy) as size_t as size_t;
                let fresh16 = unsafe { &mut ((*stream).len) };
                *fresh16 = (*fresh16 as u64).wrapping_sub(ncopy) as size_t as size_t;
                let fresh17 = unsafe { &mut ((*stream).memlen) };
                *fresh17 = (*fresh17 as u64).wrapping_add(ncopy) as size_t as size_t;
                drain_this(data_s, httpc);
                if get_transfer(httpc) != data_s {
                    (unsafe { Curl_expire(data_s, 0 as i32 as timediff_t, EXPIRE_RUN_NOW) });
                }
            }
        }
        5 => {
            rv = push_promise(data_s, conn, unsafe { &(*frame).push_promise });
            if rv != 0 {
                let mut h2: i32 = 0;
                h2 = unsafe { nghttp2_submit_rst_stream(
                    session,
                    NGHTTP2_FLAG_NONE as i32 as uint8_t,
                    (*frame).push_promise.promised_stream_id,
                    NGHTTP2_CANCEL as i32 as uint32_t,
                ) };
                if (unsafe { nghttp2_is_fatal(h2) }) != 0 {
                    return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
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
extern "C" fn on_data_chunk_recv(
    mut session: *mut nghttp2_session,
    mut _flags: uint8_t,
    mut stream_id: int32_t,
    mut mem: *const uint8_t,
    mut len: size_t,
    mut userp: *mut libc::c_void,
) -> i32 {
    let mut stream: *mut HTTP = 0 as *mut HTTP;
    let mut data_s: *mut Curl_easy = 0 as *mut Curl_easy;
    let mut nread: size_t = 0;
    let mut conn: *mut connectdata = userp as *mut connectdata;
    let mut httpc: *mut http_conn = unsafe { &mut (*conn).proto.httpc };
    data_s = (unsafe { nghttp2_session_get_stream_user_data(session, stream_id) }) as *mut Curl_easy;
    if data_s.is_null() {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    stream = unsafe { (*data_s).req.p.http };
    if stream.is_null() {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    nread = if (unsafe { (*stream).len }) < len {
        unsafe { (*stream).len }
    } else {
        len
    };
    (unsafe { memcpy(
        &mut *((*stream).mem).offset((*stream).memlen as isize) as *mut i8 as *mut libc::c_void,
        mem as *const libc::c_void,
        nread,
    ) });
    let fresh18 = unsafe { &mut ((*stream).len) };
    *fresh18 = (*fresh18 as u64).wrapping_sub(nread) as size_t as size_t;
    let fresh19 = unsafe { &mut ((*stream).memlen) };
    *fresh19 = (*fresh19 as u64).wrapping_add(nread) as size_t as size_t;
    drain_this(data_s, unsafe { &mut (*conn).proto.httpc });
    if get_transfer(httpc) != data_s {
        (unsafe { Curl_expire(data_s, 0 as i32 as timediff_t, EXPIRE_RUN_NOW) });
    }
    if nread < len {
        let fresh20 = unsafe { &mut ((*stream).pausedata) };
        *fresh20 = unsafe { mem.offset(nread as isize) };
        (unsafe { (*stream).pauselen = len.wrapping_sub(nread) });
        (unsafe { (*(*data_s).conn).proto.httpc.pause_stream_id = stream_id });
        return NGHTTP2_ERR_PAUSE as i32;
    }
    if get_transfer(httpc) != data_s {
        (unsafe { (*(*data_s).conn).proto.httpc.pause_stream_id = stream_id });
        return NGHTTP2_ERR_PAUSE as i32;
    }
    return 0 as i32;
}
extern "C" fn on_stream_close(
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
        data_s = (unsafe { nghttp2_session_get_stream_user_data(session, stream_id) }) as *mut Curl_easy;
        if data_s.is_null() {
            return 0 as i32;
        }
        stream = unsafe { (*data_s).req.p.http };
        if stream.is_null() {
            return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
        }
        (unsafe { (*stream).closed = 1 as i32 != 0 });
        httpc = unsafe { &mut (*conn).proto.httpc };
        drain_this(data_s, httpc);
        (unsafe { Curl_expire(data_s, 0 as i32 as timediff_t, EXPIRE_RUN_NOW) });
        (unsafe { (*stream).error = error_code });
        rv = unsafe { nghttp2_session_set_stream_user_data(session, stream_id, 0 as *mut libc::c_void) };
        if rv != 0 {
            (unsafe { Curl_infof(
                data_s,
                b"http/2: failed to clear user_data for stream %d!\0" as *const u8 as *const i8,
                stream_id,
            ) });
        }
        if stream_id == (unsafe { (*httpc).pause_stream_id }) {
            (unsafe { (*httpc).pause_stream_id = 0 as i32 });
        }
        (unsafe { (*stream).stream_id = 0 as i32 });
    }
    return 0 as i32;
}
extern "C" fn on_begin_headers(
    mut session: *mut nghttp2_session,
    mut frame: *const nghttp2_frame,
    mut _userp: *mut libc::c_void,
) -> i32 {
    let mut stream: *mut HTTP = 0 as *mut HTTP;
    let mut data_s: *mut Curl_easy = 0 as *mut Curl_easy;
    data_s = (unsafe { nghttp2_session_get_stream_user_data(session, (*frame).hd.stream_id) }) as *mut Curl_easy;
    if data_s.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*frame).hd.type_0 }) as i32 != NGHTTP2_HEADERS as i32 {
        return 0 as i32;
    }
    stream = unsafe { (*data_s).req.p.http };
    if stream.is_null() || !(unsafe { (*stream).bodystarted }) {
        return 0 as i32;
    }
    return 0 as i32;
}
extern "C" fn decode_status_code(mut value: *const uint8_t, mut len: size_t) -> i32 {
    let mut i: i32 = 0;
    let mut res: i32 = 0;
    if len != 3 as i32 as u64 {
        return -(1 as i32);
    }
    res = 0 as i32;
    i = 0 as i32;
    while i < 3 as i32 {
        let mut c: i8 = (unsafe { *value.offset(i as isize) }) as i8;
        if (c as i32) < '0' as i32 || c as i32 > '9' as i32 {
            return -(1 as i32);
        }
        res *= 10 as i32;
        res += c as i32 - '0' as i32;
        i += 1;
    }
    return res;
}
extern "C" fn on_header(
    mut session: *mut nghttp2_session,
    mut frame: *const nghttp2_frame,
    mut name: *const uint8_t,
    mut namelen: size_t,
    mut value: *const uint8_t,
    mut valuelen: size_t,
    mut _flags: uint8_t,
    mut userp: *mut libc::c_void,
) -> i32 {
    let mut stream: *mut HTTP = 0 as *mut HTTP;
    let mut data_s: *mut Curl_easy = 0 as *mut Curl_easy;
    let mut stream_id: int32_t = unsafe { (*frame).hd.stream_id };
    let mut conn: *mut connectdata = userp as *mut connectdata;
    let mut httpc: *mut http_conn = unsafe { &mut (*conn).proto.httpc };
    let mut result: CURLcode = CURLE_OK;
    data_s = (unsafe { nghttp2_session_get_stream_user_data(session, stream_id) }) as *mut Curl_easy;
    if data_s.is_null() {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    stream = unsafe { (*data_s).req.p.http };
    if stream.is_null() {
        (unsafe { Curl_failf(data_s, b"Internal NULL stream!\0" as *const u8 as *const i8) });
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    if (unsafe { (*frame).hd.type_0 }) as i32 == NGHTTP2_PUSH_PROMISE as i32 {
        let mut h: *mut i8 = 0 as *mut i8;
        if (unsafe { strcmp(b":authority\0" as *const u8 as *const i8, name as *const i8) }) == 0 {
            let mut rc: i32 = 0 as i32;
            let mut check: *mut i8 = unsafe { curl_maprintf(
                b"%s:%d\0" as *const u8 as *const i8,
                (*conn).host.name,
                (*conn).remote_port,
            ) };
            if check.is_null() {
                return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
            }
            if (unsafe { Curl_strcasecompare(check, value as *const i8) }) == 0
                && ((unsafe { (*conn).remote_port }) != (unsafe { (*(*conn).given).defport })
                    || (unsafe { Curl_strcasecompare((*conn).host.name, value as *const i8) }) == 0)
            {
                (unsafe { nghttp2_submit_rst_stream(
                    session,
                    NGHTTP2_FLAG_NONE as i32 as uint8_t,
                    stream_id,
                    NGHTTP2_PROTOCOL_ERROR as i32 as uint32_t,
                ) });
                rc = NGHTTP2_ERR_CALLBACK_FAILURE as i32;
            }
            (unsafe { Curl_cfree.expect("non-null function pointer")(check as *mut libc::c_void) });
            if rc != 0 {
                return rc;
            }
        }
        if (unsafe { (*stream).push_headers }).is_null() {
            (unsafe { (*stream).push_headers_alloc = 10 as i32 as size_t });
            let fresh21 = unsafe { &mut ((*stream).push_headers) };
            *fresh21 = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
                ((*stream).push_headers_alloc)
                    .wrapping_mul(::std::mem::size_of::<*mut i8>() as u64),
            ) }) as *mut *mut i8;
            if (unsafe { (*stream).push_headers }).is_null() {
                return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE as i32;
            }
            (unsafe { (*stream).push_headers_used = 0 as i32 as size_t });
        } else if (unsafe { (*stream).push_headers_used }) == (unsafe { (*stream).push_headers_alloc }) {
            let mut headp: *mut *mut i8 = 0 as *mut *mut i8;
            let fresh22 = unsafe { &mut ((*stream).push_headers_alloc) };
            *fresh22 = (*fresh22 as u64).wrapping_mul(2 as i32 as u64) as size_t as size_t;
            headp = (unsafe { Curl_saferealloc(
                (*stream).push_headers as *mut libc::c_void,
                ((*stream).push_headers_alloc)
                    .wrapping_mul(::std::mem::size_of::<*mut i8>() as u64),
            ) }) as *mut *mut i8;
            if headp.is_null() {
                let fresh23 = unsafe { &mut ((*stream).push_headers) };
                *fresh23 = 0 as *mut *mut i8;
                return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE as i32;
            }
            let fresh24 = unsafe { &mut ((*stream).push_headers) };
            *fresh24 = headp;
        }
        h = unsafe { curl_maprintf(b"%s:%s\0" as *const u8 as *const i8, name, value) };
        if !h.is_null() {
            let fresh25 = unsafe { &mut ((*stream).push_headers_used) };
            let fresh26 = *fresh25;
            *fresh25 = (*fresh25).wrapping_add(1);
            let fresh27 = unsafe { &mut (*((*stream).push_headers).offset(fresh26 as isize)) };
            *fresh27 = h;
        }
        return 0 as i32;
    }
    if unsafe { (*stream).bodystarted } {
        result = unsafe { Curl_dyn_addf(
            &mut (*stream).trailer_recvbuf as *mut dynbuf,
            b"%.*s: %.*s\r\n\0" as *const u8 as *const i8,
            namelen,
            name,
            valuelen,
            value,
        ) };
        if result as u64 != 0 {
            return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
        }
        return 0 as i32;
    }
    if namelen == (::std::mem::size_of::<[i8; 8]>() as u64).wrapping_sub(1 as i32 as u64)
        && (unsafe { memcmp(
            b":status\0" as *const u8 as *const i8 as *const libc::c_void,
            name as *const libc::c_void,
            namelen,
        ) }) == 0 as i32
    {
        (unsafe { (*stream).status_code = decode_status_code(value, valuelen) });
        result = unsafe { Curl_dyn_add(
            &mut (*stream).header_recvbuf,
            b"HTTP/2 \0" as *const u8 as *const i8,
        ) };
        if result as u64 != 0 {
            return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
        }
        result = unsafe { Curl_dyn_addn(
            &mut (*stream).header_recvbuf,
            value as *const libc::c_void,
            valuelen,
        ) };
        if result as u64 != 0 {
            return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
        }
        result = unsafe { Curl_dyn_add(
            &mut (*stream).header_recvbuf,
            b" \r\n\0" as *const u8 as *const i8,
        ) };
        if result as u64 != 0 {
            return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
        }
        if get_transfer(httpc) != data_s {
            (unsafe { Curl_expire(data_s, 0 as i32 as timediff_t, EXPIRE_RUN_NOW) });
        }
        return 0 as i32;
    }
    result = unsafe { Curl_dyn_addn(
        &mut (*stream).header_recvbuf,
        name as *const libc::c_void,
        namelen,
    ) };
    if result as u64 != 0 {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    result = unsafe { Curl_dyn_add(
        &mut (*stream).header_recvbuf,
        b": \0" as *const u8 as *const i8,
    ) };
    if result as u64 != 0 {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    result = unsafe { Curl_dyn_addn(
        &mut (*stream).header_recvbuf,
        value as *const libc::c_void,
        valuelen,
    ) };
    if result as u64 != 0 {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    result = unsafe { Curl_dyn_add(
        &mut (*stream).header_recvbuf,
        b"\r\n\0" as *const u8 as *const i8,
    ) };
    if result as u64 != 0 {
        return NGHTTP2_ERR_CALLBACK_FAILURE as i32;
    }
    if get_transfer(httpc) != data_s {
        (unsafe { Curl_expire(data_s, 0 as i32 as timediff_t, EXPIRE_RUN_NOW) });
    }
    return 0 as i32;
}
extern "C" fn data_source_read_callback(
    mut session: *mut nghttp2_session,
    mut stream_id: int32_t,
    mut buf: *mut uint8_t,
    mut length: size_t,
    mut data_flags: *mut uint32_t,
    mut _source: *mut nghttp2_data_source,
    mut _userp: *mut libc::c_void,
) -> ssize_t {
    let mut data_s: *mut Curl_easy = 0 as *mut Curl_easy;
    let mut stream: *mut HTTP = 0 as *mut HTTP;
    let mut nread: size_t = 0;
    if stream_id != 0 {
        data_s = (unsafe { nghttp2_session_get_stream_user_data(session, stream_id) }) as *mut Curl_easy;
        if data_s.is_null() {
            return NGHTTP2_ERR_CALLBACK_FAILURE as i32 as ssize_t;
        }
        stream = unsafe { (*data_s).req.p.http };
        if stream.is_null() {
            return NGHTTP2_ERR_CALLBACK_FAILURE as i32 as ssize_t;
        }
    } else {
        return NGHTTP2_ERR_INVALID_ARGUMENT as i32 as ssize_t;
    }
    nread = if (unsafe { (*stream).upload_len }) < length {
        unsafe { (*stream).upload_len }
    } else {
        length
    };
    if nread > 0 as i32 as u64 {
        (unsafe { memcpy(
            buf as *mut libc::c_void,
            (*stream).upload_mem as *const libc::c_void,
            nread,
        ) });
        let fresh28 = unsafe { &mut ((*stream).upload_mem) };
        *fresh28 = unsafe { (*fresh28).offset(nread as isize) };
        let fresh29 = unsafe { &mut ((*stream).upload_len) };
        *fresh29 = (*fresh29 as u64).wrapping_sub(nread) as size_t as size_t;
        if (unsafe { (*data_s).state.infilesize }) != -(1 as i32) as i64 {
            let fresh30 = unsafe { &mut ((*stream).upload_left) };
            *fresh30 = (*fresh30 as u64).wrapping_sub(nread) as curl_off_t as curl_off_t;
        }
    }
    if (unsafe { (*stream).upload_left }) == 0 as i32 as i64 {
        (unsafe { *data_flags = NGHTTP2_DATA_FLAG_EOF as i32 as uint32_t });
    } else if nread == 0 as i32 as u64 {
        return NGHTTP2_ERR_DEFERRED as i32 as ssize_t;
    }
    return nread as ssize_t;
}
extern "C" fn error_callback(
    mut _session: *mut nghttp2_session,
    mut _msg: *const i8,
    mut _len: size_t,
    mut _userp: *mut libc::c_void,
) -> i32 {
    return 0 as i32;
}
extern "C" fn populate_settings(mut data: *mut Curl_easy, mut httpc: *mut http_conn) {
    let mut iv: *mut nghttp2_settings_entry = unsafe { ((*httpc).local_settings).as_mut_ptr() };
    (unsafe { (*iv.offset(0 as i32 as isize)).settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS as i32 });
    (unsafe { (*iv.offset(0 as i32 as isize)).value = Curl_multi_max_concurrent_streams((*data).multi) });
    (unsafe { (*iv.offset(1 as i32 as isize)).settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE as i32 });
    (unsafe { (*iv.offset(1 as i32 as isize)).value = (32 as i32 * 1024 as i32 * 1024 as i32) as uint32_t });
    (unsafe { (*iv.offset(2 as i32 as isize)).settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH as i32 });
    (unsafe { (*iv.offset(2 as i32 as isize)).value = ((*(*data).multi).push_cb).is_some() as i32 as uint32_t });
    (unsafe { (*httpc).local_settings_num = 3 as i32 as size_t });
}
#[no_mangle]
pub extern "C" fn Curl_http2_done(mut data: *mut Curl_easy, mut premature: bool) {
    let mut http: *mut HTTP = unsafe { (*data).req.p.http };
    let mut httpc: *mut http_conn = unsafe { &mut (*(*data).conn).proto.httpc };
    (unsafe { Curl_dyn_free(&mut (*http).header_recvbuf) });
    (unsafe { Curl_dyn_free(&mut (*http).trailer_recvbuf) });
    if !(unsafe { (*http).push_headers }).is_null() {
        while (unsafe { (*http).push_headers_used }) > 0 as i32 as u64 {
            (unsafe { Curl_cfree.expect("non-null function pointer")(
                *((*http).push_headers)
                    .offset(((*http).push_headers_used).wrapping_sub(1 as i32 as u64) as isize)
                    as *mut libc::c_void,
            ) });
            let fresh31 = unsafe { &mut ((*http).push_headers_used) };
            *fresh31 = (*fresh31).wrapping_sub(1);
        }
        (unsafe { Curl_cfree.expect("non-null function pointer")((*http).push_headers as *mut libc::c_void) });
        let fresh32 = unsafe { &mut ((*http).push_headers) };
        *fresh32 = 0 as *mut *mut i8;
    }
    if (unsafe { (*(*(*data).conn).handler).protocol })
        & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32
        == 0
        || (unsafe { (*httpc).h2 }).is_null()
    {
        return;
    }
    if premature {
        set_transfer(httpc, data);
        if (unsafe { nghttp2_submit_rst_stream(
            (*httpc).h2,
            NGHTTP2_FLAG_NONE as i32 as uint8_t,
            (*http).stream_id,
            NGHTTP2_STREAM_CLOSED as i32 as uint32_t,
        ) }) == 0
        {
            (unsafe { nghttp2_session_send((*httpc).h2) });
        }
        if (unsafe { (*http).stream_id }) == (unsafe { (*httpc).pause_stream_id }) {
            (unsafe { Curl_infof(
                data,
                b"stopped the pause stream!\0" as *const u8 as *const i8,
            ) });
            (unsafe { (*httpc).pause_stream_id = 0 as i32 });
        }
    }
    if (unsafe { (*data).state.drain }) != 0 {
        drained_transfer(data, httpc);
    }
    if (unsafe { (*http).stream_id }) > 0 as i32 {
        let mut rv: i32 = unsafe { nghttp2_session_set_stream_user_data(
            (*httpc).h2,
            (*http).stream_id,
            0 as *mut libc::c_void,
        ) };
        if rv != 0 {
            (unsafe { Curl_infof(
                data,
                b"http/2: failed to clear user_data for stream %d!\0" as *const u8 as *const i8,
                (*http).stream_id,
            ) });
        }
        set_transfer(httpc, 0 as *mut Curl_easy);
        (unsafe { (*http).stream_id = 0 as i32 });
    }
}
extern "C" fn http2_init(mut data: *mut Curl_easy, mut conn: *mut connectdata) -> CURLcode {
    if (unsafe { (*conn).proto.httpc.h2 }).is_null() {
        let mut rc: i32 = 0;
        let mut callbacks: *mut nghttp2_session_callbacks = 0 as *mut nghttp2_session_callbacks;
        let fresh33 = unsafe { &mut ((*conn).proto.httpc.inbuf) };
        *fresh33 =
            (unsafe { Curl_cmalloc.expect("non-null function pointer")(32768 as i32 as size_t) }) as *mut i8;
        if (unsafe { (*conn).proto.httpc.inbuf }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        rc = unsafe { nghttp2_session_callbacks_new(&mut callbacks) };
        if rc != 0 {
            (unsafe { Curl_failf(
                data,
                b"Couldn't initialize nghttp2 callbacks!\0" as *const u8 as *const i8,
            ) });
            return CURLE_OUT_OF_MEMORY;
        }
        (unsafe { nghttp2_session_callbacks_set_send_callback(
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
        ) });
        (unsafe { nghttp2_session_callbacks_set_on_frame_recv_callback(
            callbacks,
            Some(
                on_frame_recv
                    as unsafe extern "C" fn(
                        *mut nghttp2_session,
                        *const nghttp2_frame,
                        *mut libc::c_void,
                    ) -> i32,
            ),
        ) });
        (unsafe { nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
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
        ) });
        (unsafe { nghttp2_session_callbacks_set_on_stream_close_callback(
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
        ) });
        (unsafe { nghttp2_session_callbacks_set_on_begin_headers_callback(
            callbacks,
            Some(
                on_begin_headers
                    as unsafe extern "C" fn(
                        *mut nghttp2_session,
                        *const nghttp2_frame,
                        *mut libc::c_void,
                    ) -> i32,
            ),
        ) });
        (unsafe { nghttp2_session_callbacks_set_on_header_callback(
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
        ) });
        (unsafe { nghttp2_session_callbacks_set_error_callback(
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
        ) });
        rc = unsafe { nghttp2_session_client_new(
            &mut (*conn).proto.httpc.h2,
            callbacks,
            conn as *mut libc::c_void,
        ) };
        (unsafe { nghttp2_session_callbacks_del(callbacks) });
        if rc != 0 {
            (unsafe { Curl_failf(
                data,
                b"Couldn't initialize nghttp2!\0" as *const u8 as *const i8,
            ) });
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_http2_request_upgrade(
    mut req: *mut dynbuf,
    mut data: *mut Curl_easy,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut binlen: ssize_t = 0;
    let mut base64: *mut i8 = 0 as *mut i8;
    let mut blen: size_t = 0;
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    let mut k: *mut SingleRequest = unsafe { &mut (*data).req };
    let mut binsettings: *mut uint8_t = unsafe { ((*conn).proto.httpc.binsettings).as_mut_ptr() };
    let mut httpc: *mut http_conn = unsafe { &mut (*conn).proto.httpc };
    populate_settings(data, httpc);
    binlen = unsafe { nghttp2_pack_settings_payload(
        binsettings,
        80 as i32 as size_t,
        ((*httpc).local_settings).as_mut_ptr(),
        (*httpc).local_settings_num,
    ) };
    if binlen <= 0 as i32 as i64 {
        (unsafe { Curl_failf(
            data,
            b"nghttp2 unexpectedly failed on pack_settings_payload\0" as *const u8 as *const i8,
        ) });
        (unsafe { Curl_dyn_free(req) });
        return CURLE_FAILED_INIT;
    }
    (unsafe { (*conn).proto.httpc.binlen = binlen as size_t });
    result = unsafe { Curl_base64url_encode(
        data,
        binsettings as *const i8,
        binlen as size_t,
        &mut base64,
        &mut blen,
    ) };
    if result as u64 != 0 {
        (unsafe { Curl_dyn_free(req) });
        return result;
    }
    result = unsafe { Curl_dyn_addf(
        req,
        b"Connection: Upgrade, HTTP2-Settings\r\nUpgrade: %s\r\nHTTP2-Settings: %s\r\n\0"
            as *const u8 as *const i8,
        b"h2c\0" as *const u8 as *const i8,
        base64,
    ) };
    (unsafe { Curl_cfree.expect("non-null function pointer")(base64 as *mut libc::c_void) });
    (unsafe { (*k).upgr101 = UPGR101_REQUESTED });
    return result;
}
extern "C" fn should_close_session(mut httpc: *mut http_conn) -> i32 {
    return ((unsafe { (*httpc).drain_total }) == 0 as i32 as u64
        && (unsafe { nghttp2_session_want_read((*httpc).h2) }) == 0
        && (unsafe { nghttp2_session_want_write((*httpc).h2) }) == 0) as i32;
}
extern "C" fn h2_process_pending_input(
    mut data: *mut Curl_easy,
    mut httpc: *mut http_conn,
    mut err: *mut CURLcode,
) -> i32 {
    let mut nread: ssize_t = 0;
    let mut inbuf: *mut i8 = 0 as *mut i8;
    let mut rv: ssize_t = 0;
    nread = (unsafe { (*httpc).inbuflen }).wrapping_sub(unsafe { (*httpc).nread_inbuf }) as ssize_t;
    inbuf = unsafe { ((*httpc).inbuf).offset((*httpc).nread_inbuf as isize) };
    set_transfer(httpc, data);
    rv = unsafe { nghttp2_session_mem_recv((*httpc).h2, inbuf as *const uint8_t, nread as size_t) };
    if rv < 0 as i32 as i64 {
        (unsafe { Curl_failf(
            data,
            b"h2_process_pending_input: nghttp2_session_mem_recv() returned %zd:%s\0" as *const u8
                as *const i8,
            rv,
            nghttp2_strerror(rv as i32),
        ) });
        (unsafe { *err = CURLE_RECV_ERROR });
        return -(1 as i32);
    }
    if nread == rv {
        (unsafe { (*httpc).inbuflen = 0 as i32 as size_t });
        (unsafe { (*httpc).nread_inbuf = 0 as i32 as size_t });
    } else {
        let fresh34 = unsafe { &mut ((*httpc).nread_inbuf) };
        *fresh34 = (*fresh34 as u64).wrapping_add(rv as u64) as size_t as size_t;
    }
    rv = h2_session_send(data, unsafe { (*httpc).h2 }) as ssize_t;
    if rv != 0 {
        (unsafe { *err = CURLE_SEND_ERROR });
        return -(1 as i32);
    }
    if (unsafe { nghttp2_session_check_request_allowed((*httpc).h2) }) == 0 as i32 {
        (unsafe { Curl_conncontrol((*data).conn, 1 as i32) });
    }
    if should_close_session(httpc) != 0 {
        let mut stream: *mut HTTP = unsafe { (*data).req.p.http };
        if (unsafe { (*stream).error }) != 0 {
            (unsafe { *err = CURLE_HTTP2 });
        } else {
            (unsafe { Curl_conncontrol((*data).conn, 1 as i32) });
            (unsafe { *err = CURLE_OK });
        }
        return -(1 as i32);
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn Curl_http2_done_sending(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    if (unsafe { (*conn).handler }) == (unsafe { &Curl_handler_http2_ssl }) as *const Curl_handler
        || (unsafe { (*conn).handler }) == (unsafe { &Curl_handler_http2 }) as *const Curl_handler
    {
        let mut stream: *mut HTTP = unsafe { (*data).req.p.http };
        let mut httpc: *mut http_conn = unsafe { &mut (*conn).proto.httpc };
        let mut h2: *mut nghttp2_session = unsafe { (*httpc).h2 };
        if (unsafe { (*stream).upload_left }) != 0 {
            (unsafe { (*stream).upload_left = 0 as i32 as curl_off_t });
            (unsafe { nghttp2_session_resume_data(h2, (*stream).stream_id) });
            h2_process_pending_input(data, httpc, &mut result);
        }
        if (unsafe { nghttp2_session_want_write(h2) }) != 0 {
            let mut k: *mut SingleRequest = unsafe { &mut (*data).req };
            let mut rv: i32 = 0;
            rv = h2_session_send(data, h2);
            if rv != 0 {
                result = CURLE_SEND_ERROR;
            }
            if (unsafe { nghttp2_session_want_write(h2) }) != 0 {
                (unsafe { (*k).keepon |= (1 as i32) << 1 as i32 });
            }
        }
    }
    return result;
}
extern "C" fn http2_handle_stream_close(
    mut conn: *mut connectdata,
    mut data: *mut Curl_easy,
    mut stream: *mut HTTP,
    mut err: *mut CURLcode,
) -> ssize_t {
    let mut httpc: *mut http_conn = unsafe { &mut (*conn).proto.httpc };
    if (unsafe { (*httpc).pause_stream_id }) == (unsafe { (*stream).stream_id }) {
        (unsafe { (*httpc).pause_stream_id = 0 as i32 });
    }
    drained_transfer(data, httpc);
    if (unsafe { (*httpc).pause_stream_id }) == 0 as i32 {
        if h2_process_pending_input(data, httpc, err) != 0 as i32 {
            return -(1 as i32) as ssize_t;
        }
    }
    (unsafe { (*stream).closed = 0 as i32 != 0 });
    if (unsafe { (*stream).error }) == NGHTTP2_REFUSED_STREAM as i32 as u32 {
        (unsafe { Curl_conncontrol(conn, 1 as i32) });
        let fresh35 = unsafe { &mut ((*data).state) };
        (*fresh35).set_refused_stream(1 as i32 as bit);
        (unsafe { *err = CURLE_RECV_ERROR });
        return -(1 as i32) as ssize_t;
    } else {
        if (unsafe { (*stream).error }) != NGHTTP2_NO_ERROR as i32 as u32 {
            (unsafe { Curl_failf(
                data,
                b"HTTP/2 stream %d was not closed cleanly: %s (err %u)\0" as *const u8 as *const i8,
                (*stream).stream_id,
                nghttp2_http2_strerror((*stream).error),
                (*stream).error,
            ) });
            (unsafe { *err = CURLE_HTTP2_STREAM });
            return -(1 as i32) as ssize_t;
        }
    }
    if !(unsafe { (*stream).bodystarted }) {
        (unsafe { Curl_failf (data , b"HTTP/2 stream %d was closed cleanly, but before getting  all response header fields, treated as error\0" as * const u8 as * const i8 , (* stream) . stream_id ,) }) ;
        (unsafe { *err = CURLE_HTTP2_STREAM });
        return -(1 as i32) as ssize_t;
    }
    if (unsafe { Curl_dyn_len(&mut (*stream).trailer_recvbuf) }) != 0 {
        let mut trailp: *mut i8 = unsafe { Curl_dyn_ptr(&mut (*stream).trailer_recvbuf) };
        let mut lf: *mut i8 = 0 as *mut i8;
        loop {
            let mut len: size_t = 0 as i32 as size_t;
            let mut result: CURLcode = CURLE_OK;
            lf = unsafe { strchr(trailp, '\n' as i32) };
            if lf.is_null() {
                break;
            }
            len = (unsafe { lf.offset(1 as i32 as isize).offset_from(trailp) }) as i64 as size_t;
            (unsafe { Curl_debug(data, CURLINFO_HEADER_IN, trailp, len) });
            result = unsafe { Curl_client_write(data, (1 as i32) << 1 as i32, trailp, len) };
            if result as u64 != 0 {
                (unsafe { *err = result });
                return -(1 as i32) as ssize_t;
            }
            lf = unsafe { lf.offset(1) };
            trailp = lf;
            if lf.is_null() {
                break;
            }
        }
    }
    (unsafe { (*stream).close_handled = 1 as i32 != 0 });
    return 0 as i32 as ssize_t;
}
extern "C" fn h2_pri_spec(mut data: *mut Curl_easy, mut pri_spec: *mut nghttp2_priority_spec) {
    let mut depstream: *mut HTTP = if !(unsafe { (*data).set.stream_depends_on }).is_null() {
        unsafe { (*(*data).set.stream_depends_on).req.p.http }
    } else {
        0 as *mut HTTP
    };
    let mut depstream_id: int32_t = if !depstream.is_null() {
        unsafe { (*depstream).stream_id }
    } else {
        0 as i32
    };
    (unsafe { nghttp2_priority_spec_init(
        pri_spec,
        depstream_id,
        (*data).set.stream_weight,
        ((*data).set).stream_depends_e() as i32,
    ) });
    (unsafe { (*data).state.stream_weight = (*data).set.stream_weight });
    let fresh36 = unsafe { &mut ((*data).state) };
    (*fresh36).set_stream_depends_e(unsafe { ((*data).set).stream_depends_e() });
    let fresh37 = unsafe { &mut ((*data).state.stream_depends_on) };
    *fresh37 = unsafe { (*data).set.stream_depends_on };
}
extern "C" fn h2_session_send(mut data: *mut Curl_easy, mut h2: *mut nghttp2_session) -> i32 {
    let mut stream: *mut HTTP = unsafe { (*data).req.p.http };
    let mut httpc: *mut http_conn = unsafe { &mut (*(*data).conn).proto.httpc };
    set_transfer(httpc, data);
    if (unsafe { (*data).set.stream_weight }) != (unsafe { (*data).state.stream_weight })
        || (unsafe { ((*data).set).stream_depends_e() }) as i32 != (unsafe { ((*data).state).stream_depends_e() }) as i32
        || (unsafe { (*data).set.stream_depends_on }) != (unsafe { (*data).state.stream_depends_on })
    {
        let mut pri_spec: nghttp2_priority_spec = nghttp2_priority_spec {
            stream_id: 0,
            weight: 0,
            exclusive: 0,
        };
        let mut rv: i32 = 0;
        h2_pri_spec(data, &mut pri_spec);
        rv = unsafe { nghttp2_submit_priority(
            h2,
            NGHTTP2_FLAG_NONE as i32 as uint8_t,
            (*stream).stream_id,
            &mut pri_spec,
        ) };
        if rv != 0 {
            return rv;
        }
    }
    return unsafe { nghttp2_session_send(h2) };
}
extern "C" fn http2_recv(
    mut data: *mut Curl_easy,
    mut _sockindex: i32,
    mut mem: *mut i8,
    mut len: size_t,
    mut err: *mut CURLcode,
) -> ssize_t {
    let mut nread: ssize_t = 0;
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    let mut httpc: *mut http_conn = unsafe { &mut (*conn).proto.httpc };
    let mut stream: *mut HTTP = unsafe { (*data).req.p.http };
    if should_close_session(httpc) != 0 {
        if (unsafe { ((*conn).bits).close() }) != 0 {
            (unsafe { *err = CURLE_OK });
            return 0 as i32 as ssize_t;
        }
        (unsafe { *err = CURLE_HTTP2 });
        return -(1 as i32) as ssize_t;
    }
    let fresh38 = unsafe { &mut ((*stream).upload_mem) };
    *fresh38 = 0 as *const uint8_t;
    (unsafe { (*stream).upload_len = 0 as i32 as size_t });
    if (unsafe { (*stream).bodystarted }) as i32 != 0
        && (unsafe { (*stream).nread_header_recvbuf }) < (unsafe { Curl_dyn_len(&mut (*stream).header_recvbuf) })
    {
        let mut left: size_t = (unsafe { Curl_dyn_len(&mut (*stream).header_recvbuf) })
            .wrapping_sub(unsafe { (*stream).nread_header_recvbuf });
        let mut ncopy: size_t = if len < left { len } else { left };
        (unsafe { memcpy(
            mem as *mut libc::c_void,
            (Curl_dyn_ptr(&mut (*stream).header_recvbuf))
                .offset((*stream).nread_header_recvbuf as isize) as *const libc::c_void,
            ncopy,
        ) });
        let fresh39 = unsafe { &mut ((*stream).nread_header_recvbuf) };
        *fresh39 = (*fresh39 as u64).wrapping_add(ncopy) as size_t as size_t;
        return ncopy as ssize_t;
    }
    if (unsafe { (*data).state.drain }) != 0 && (unsafe { (*stream).memlen }) != 0 {
        if mem != (unsafe { (*stream).mem }) {
            (unsafe { memmove(
                mem as *mut libc::c_void,
                (*stream).mem as *const libc::c_void,
                (*stream).memlen,
            ) });
            (unsafe { (*stream).len = len.wrapping_sub((*stream).memlen) });
            let fresh40 = unsafe { &mut ((*stream).mem) };
            *fresh40 = mem;
        }
        if (unsafe { (*httpc).pause_stream_id }) == (unsafe { (*stream).stream_id }) && (unsafe { (*stream).pausedata }).is_null() {
            (unsafe { (*httpc).pause_stream_id = 0 as i32 });
            if h2_process_pending_input(data, httpc, err) != 0 as i32 {
                return -(1 as i32) as ssize_t;
            }
        }
    } else if !(unsafe { (*stream).pausedata }).is_null() {
        nread = (if len < (unsafe { (*stream).pauselen }) {
            len
        } else {
            unsafe { (*stream).pauselen }
        }) as ssize_t;
        (unsafe { memcpy(
            mem as *mut libc::c_void,
            (*stream).pausedata as *const libc::c_void,
            nread as u64,
        ) });
        let fresh41 = unsafe { &mut ((*stream).pausedata) };
        *fresh41 = unsafe { (*fresh41).offset(nread as isize) };
        let fresh42 = unsafe { &mut ((*stream).pauselen) };
        *fresh42 = (*fresh42 as u64).wrapping_sub(nread as u64) as size_t as size_t;
        if (unsafe { (*stream).pauselen }) == 0 as i32 as u64 {
            (unsafe { (*httpc).pause_stream_id = 0 as i32 });
            let fresh43 = unsafe { &mut ((*stream).pausedata) };
            *fresh43 = 0 as *const uint8_t;
            (unsafe { (*stream).pauselen = 0 as i32 as size_t });
            if h2_process_pending_input(data, httpc, err) != 0 as i32 {
                return -(1 as i32) as ssize_t;
            }
        }
        return nread;
    } else {
        if (unsafe { (*httpc).pause_stream_id }) != 0 {
            if unsafe { (*stream).closed } {
                return 0 as i32 as ssize_t;
            }
            (unsafe { *err = CURLE_AGAIN });
            return -(1 as i32) as ssize_t;
        } else {
            let fresh44 = unsafe { &mut ((*stream).mem) };
            *fresh44 = mem;
            (unsafe { (*stream).len = len });
            (unsafe { (*stream).memlen = 0 as i32 as size_t });
            if (unsafe { (*httpc).inbuflen }) == 0 as i32 as u64 {
                nread = unsafe { ((*httpc).recv_underlying).expect("non-null function pointer")(
                    data,
                    0 as i32,
                    (*httpc).inbuf,
                    32768 as i32 as size_t,
                    err,
                ) };
                if nread == -(1 as i32) as i64 {
                    if (unsafe { *err }) as u32 != CURLE_AGAIN as i32 as u32 {
                        (unsafe { Curl_failf(
                            data,
                            b"Failed receiving HTTP2 data\0" as *const u8 as *const i8,
                        ) });
                    } else if unsafe { (*stream).closed } {
                        return http2_handle_stream_close(conn, data, stream, err);
                    }
                    return -(1 as i32) as ssize_t;
                }
                if nread == 0 as i32 as i64 {
                    if !(unsafe { (*stream).closed }) {
                        (unsafe { Curl_failf (data , b"HTTP/2 stream %d was not closed cleanly before end of the underlying stream\0" as * const u8 as * const i8 , (* stream) . stream_id ,) }) ;
                        (unsafe { *err = CURLE_HTTP2_STREAM });
                        return -(1 as i32) as ssize_t;
                    }
                    (unsafe { *err = CURLE_OK });
                    return 0 as i32 as ssize_t;
                }
                (unsafe { (*httpc).inbuflen = nread as size_t });
            } else {
                nread = (unsafe { (*httpc).inbuflen }).wrapping_sub(unsafe { (*httpc).nread_inbuf }) as ssize_t;
            }
            if h2_process_pending_input(data, httpc, err) != 0 {
                return -(1 as i32) as ssize_t;
            }
        }
    }
    if (unsafe { (*stream).memlen }) != 0 {
        let mut retlen: ssize_t = (unsafe { (*stream).memlen }) as ssize_t;
        (unsafe { (*stream).memlen = 0 as i32 as size_t });
        if !((unsafe { (*httpc).pause_stream_id }) == (unsafe { (*stream).stream_id })) {
            if !(unsafe { (*stream).closed }) {
                drained_transfer(data, httpc);
            } else {
                (unsafe { Curl_expire(data, 0 as i32 as timediff_t, EXPIRE_RUN_NOW) });
            }
        }
        return retlen;
    }
    if unsafe { (*stream).closed } {
        return http2_handle_stream_close(conn, data, stream, err);
    }
    (unsafe { *err = CURLE_AGAIN });
    return -(1 as i32) as ssize_t;
}
extern "C" fn contains_trailers(mut p: *const i8, mut len: size_t) -> bool {
    let mut end: *const i8 = unsafe { p.offset(len as isize) };
    loop {
        while p != end && ((unsafe { *p }) as i32 == ' ' as i32 || (unsafe { *p }) as i32 == '\t' as i32) {
            p = unsafe { p.offset(1) };
        }
        if p == end
            || ((unsafe { end.offset_from(p) }) as i64 as size_t)
                < (::std::mem::size_of::<[i8; 9]>() as u64).wrapping_sub(1 as i32 as u64)
        {
            return 0 as i32 != 0;
        }
        if (unsafe { Curl_strncasecompare(
            b"trailers\0" as *const u8 as *const i8,
            p,
            (::std::mem::size_of::<[i8; 9]>() as u64).wrapping_sub(1 as i32 as u64),
        ) }) != 0
        {
            p = unsafe { p.offset(
                (::std::mem::size_of::<[i8; 9]>() as u64).wrapping_sub(1 as i32 as u64) as isize,
            ) };
            while p != end && ((unsafe { *p }) as i32 == ' ' as i32 || (unsafe { *p }) as i32 == '\t' as i32) {
                p = unsafe { p.offset(1) };
            }
            if p == end || (unsafe { *p }) as i32 == ',' as i32 {
                return 1 as i32 != 0;
            }
        }
        while p != end && (unsafe { *p }) as i32 != ',' as i32 {
            p = unsafe { p.offset(1) };
        }
        if p == end {
            return 0 as i32 != 0;
        }
        p = unsafe { p.offset(1) };
    }
}
extern "C" fn inspect_header(
    mut name: *const i8,
    mut namelen: size_t,
    mut value: *const i8,
    mut valuelen: size_t,
) -> header_instruction {
    match namelen {
        2 => {
            if (unsafe { Curl_strncasecompare(b"te\0" as *const u8 as *const i8, name, namelen) }) == 0 {
                return HEADERINST_FORWARD;
            }
            return (if contains_trailers(value, valuelen) as i32 != 0 {
                HEADERINST_TE_TRAILERS as i32
            } else {
                HEADERINST_IGNORE as i32
            }) as header_instruction;
        }
        7 => {
            return (if (unsafe { Curl_strncasecompare(b"upgrade\0" as *const u8 as *const i8, name, namelen) })
                != 0
            {
                HEADERINST_IGNORE as i32
            } else {
                HEADERINST_FORWARD as i32
            }) as header_instruction;
        }
        10 => {
            return (if (unsafe { Curl_strncasecompare(
                b"connection\0" as *const u8 as *const i8,
                name,
                namelen,
            ) }) != 0
                || (unsafe { Curl_strncasecompare(b"keep-alive\0" as *const u8 as *const i8, name, namelen) })
                    != 0
            {
                HEADERINST_IGNORE as i32
            } else {
                HEADERINST_FORWARD as i32
            }) as header_instruction;
        }
        16 => {
            return (if (unsafe { Curl_strncasecompare(
                b"proxy-connection\0" as *const u8 as *const i8,
                name,
                namelen,
            ) }) != 0
            {
                HEADERINST_IGNORE as i32
            } else {
                HEADERINST_FORWARD as i32
            }) as header_instruction;
        }
        17 => {
            return (if (unsafe { Curl_strncasecompare(
                b"transfer-encoding\0" as *const u8 as *const i8,
                name,
                namelen,
            ) }) != 0
            {
                HEADERINST_IGNORE as i32
            } else {
                HEADERINST_FORWARD as i32
            }) as header_instruction;
        }
        _ => return HEADERINST_FORWARD,
    };
}
extern "C" fn http2_send(
    mut data: *mut Curl_easy,
    mut _sockindex: i32,
    mut mem: *const libc::c_void,
    mut len: size_t,
    mut err: *mut CURLcode,
) -> ssize_t {
    let mut current_block: u64;
    let mut rv: i32 = 0;
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    let mut httpc: *mut http_conn = unsafe { &mut (*conn).proto.httpc };
    let mut stream: *mut HTTP = unsafe { (*data).req.p.http };
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
    let mut h2: *mut nghttp2_session = unsafe { (*httpc).h2 };
    let mut pri_spec: nghttp2_priority_spec = nghttp2_priority_spec {
        stream_id: 0,
        weight: 0,
        exclusive: 0,
    };
    if (unsafe { (*stream).stream_id }) != -(1 as i32) {
        if unsafe { (*stream).close_handled } {
            (unsafe { Curl_infof(
                data,
                b"stream %d closed\0" as *const u8 as *const i8,
                (*stream).stream_id,
            ) });
            (unsafe { *err = CURLE_HTTP2_STREAM });
            return -(1 as i32) as ssize_t;
        } else {
            if unsafe { (*stream).closed } {
                return http2_handle_stream_close(conn, data, stream, err);
            }
        }
        let fresh45 = unsafe { &mut ((*stream).upload_mem) };
        *fresh45 = mem as *const uint8_t;
        (unsafe { (*stream).upload_len = len });
        rv = unsafe { nghttp2_session_resume_data(h2, (*stream).stream_id) };
        if (unsafe { nghttp2_is_fatal(rv) }) != 0 {
            (unsafe { *err = CURLE_SEND_ERROR });
            return -(1 as i32) as ssize_t;
        }
        rv = h2_session_send(data, h2);
        if (unsafe { nghttp2_is_fatal(rv) }) != 0 {
            (unsafe { *err = CURLE_SEND_ERROR });
            return -(1 as i32) as ssize_t;
        }
        len = (len as u64).wrapping_sub(unsafe { (*stream).upload_len }) as size_t as size_t;
        let fresh46 = unsafe { &mut ((*stream).upload_mem) };
        *fresh46 = 0 as *const uint8_t;
        (unsafe { (*stream).upload_len = 0 as i32 as size_t });
        if should_close_session(httpc) != 0 {
            (unsafe { *err = CURLE_HTTP2 });
            return -(1 as i32) as ssize_t;
        }
        if (unsafe { (*stream).upload_left }) != 0 {
            (unsafe { nghttp2_session_resume_data(h2, (*stream).stream_id) });
        }
        return len as ssize_t;
    }
    nheader = 0 as i32 as size_t;
    i = 1 as i32 as size_t;
    while i < len {
        if (unsafe { *hdbuf.offset(i as isize) }) as i32 == '\n' as i32
            && (unsafe { *hdbuf.offset(i.wrapping_sub(1 as i32 as u64) as isize) }) as i32 == '\r' as i32
        {
            nheader = nheader.wrapping_add(1);
            i = i.wrapping_add(1);
        }
        i = i.wrapping_add(1);
    }
    if !(nheader < 2 as i32 as u64) {
        nheader = (nheader as u64).wrapping_add(1 as i32 as u64) as size_t as size_t;
        nva = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
            (::std::mem::size_of::<nghttp2_nv>() as u64).wrapping_mul(nheader),
        ) }) as *mut nghttp2_nv;
        if nva.is_null() {
            (unsafe { *err = CURLE_OUT_OF_MEMORY });
            return -(1 as i32) as ssize_t;
        }
        line_end = (unsafe { memchr(hdbuf as *const libc::c_void, '\r' as i32, len) }) as *mut i8;
        if !line_end.is_null() {
            end = (unsafe { memchr(
                hdbuf as *const libc::c_void,
                ' ' as i32,
                line_end.offset_from(hdbuf) as i64 as u64,
            ) }) as *mut i8;
            if !(end.is_null() || end == hdbuf) {
                let fresh47 = unsafe { &mut ((*nva.offset(0 as i32 as isize)).name) };
                *fresh47 = b":method\0" as *const u8 as *const i8 as *mut u8;
                (unsafe { (*nva.offset(0 as i32 as isize)).namelen =
                    strlen((*nva.offset(0 as i32 as isize)).name as *mut i8) });
                let fresh48 = unsafe { &mut ((*nva.offset(0 as i32 as isize)).value) };
                *fresh48 = hdbuf as *mut u8;
                (unsafe { (*nva.offset(0 as i32 as isize)).valuelen = end.offset_from(hdbuf) as i64 as size_t });
                (unsafe { (*nva.offset(0 as i32 as isize)).flags = NGHTTP2_NV_FLAG_NONE as i32 as uint8_t });
                if (unsafe { (*nva.offset(0 as i32 as isize)).namelen }) > 0xffff as i32 as u64
                    || (unsafe { (*nva.offset(0 as i32 as isize)).valuelen })
                        > (0xffff as i32 as u64)
                            .wrapping_sub(unsafe { (*nva.offset(0 as i32 as isize)).namelen })
                {
                    (unsafe { Curl_failf(
                        data,
                        b"Failed sending HTTP request: Header overflow\0" as *const u8 as *const i8,
                    ) });
                } else {
                    hdbuf = unsafe { end.offset(1 as i32 as isize) };
                    end = 0 as *mut i8;
                    i = (unsafe { line_end.offset_from(hdbuf) }) as i64 as size_t;
                    while i != 0 {
                        if (unsafe { *hdbuf.offset(i.wrapping_sub(1 as i32 as u64) as isize) }) as i32
                            == ' ' as i32
                        {
                            end = (unsafe { &mut *hdbuf.offset(i.wrapping_sub(1 as i32 as u64) as isize) })
                                as *mut i8;
                            break;
                        } else {
                            i = i.wrapping_sub(1);
                        }
                    }
                    if !(end.is_null() || end == hdbuf) {
                        let fresh49 = unsafe { &mut ((*nva.offset(1 as i32 as isize)).name) };
                        *fresh49 = b":path\0" as *const u8 as *const i8 as *mut u8;
                        (unsafe { (*nva.offset(1 as i32 as isize)).namelen =
                            strlen((*nva.offset(1 as i32 as isize)).name as *mut i8) });
                        let fresh50 = unsafe { &mut ((*nva.offset(1 as i32 as isize)).value) };
                        *fresh50 = hdbuf as *mut u8;
                        (unsafe { (*nva.offset(1 as i32 as isize)).valuelen =
                            end.offset_from(hdbuf) as i64 as size_t });
                        (unsafe { (*nva.offset(1 as i32 as isize)).flags =
                            NGHTTP2_NV_FLAG_NONE as i32 as uint8_t });
                        if (unsafe { (*nva.offset(1 as i32 as isize)).namelen }) > 0xffff as i32 as u64
                            || (unsafe { (*nva.offset(1 as i32 as isize)).valuelen })
                                > (0xffff as i32 as u64)
                                    .wrapping_sub(unsafe { (*nva.offset(1 as i32 as isize)).namelen })
                        {
                            (unsafe { Curl_failf(
                                data,
                                b"Failed sending HTTP request: Header overflow\0" as *const u8
                                    as *const i8,
                            ) });
                        } else {
                            let fresh51 = unsafe { &mut ((*nva.offset(2 as i32 as isize)).name) };
                            *fresh51 = b":scheme\0" as *const u8 as *const i8 as *mut u8;
                            (unsafe { (*nva.offset(2 as i32 as isize)).namelen =
                                strlen((*nva.offset(2 as i32 as isize)).name as *mut i8) });
                            if (unsafe { (*(*conn).handler).flags }) & ((1 as i32) << 0 as i32) as u32 != 0 {
                                let fresh52 = unsafe { &mut ((*nva.offset(2 as i32 as isize)).value) };
                                *fresh52 = b"https\0" as *const u8 as *const i8 as *mut u8;
                            } else {
                                let fresh53 = unsafe { &mut ((*nva.offset(2 as i32 as isize)).value) };
                                *fresh53 = b"http\0" as *const u8 as *const i8 as *mut u8;
                            }
                            (unsafe { (*nva.offset(2 as i32 as isize)).valuelen =
                                strlen((*nva.offset(2 as i32 as isize)).value as *mut i8) });
                            (unsafe { (*nva.offset(2 as i32 as isize)).flags =
                                NGHTTP2_NV_FLAG_NONE as i32 as uint8_t });
                            if (unsafe { (*nva.offset(2 as i32 as isize)).namelen }) > 0xffff as i32 as u64
                                || (unsafe { (*nva.offset(2 as i32 as isize)).valuelen })
                                    > (0xffff as i32 as u64)
                                        .wrapping_sub(unsafe { (*nva.offset(2 as i32 as isize)).namelen })
                            {
                                (unsafe { Curl_failf(
                                    data,
                                    b"Failed sending HTTP request: Header overflow\0" as *const u8
                                        as *const i8,
                                ) });
                            } else {
                                authority_idx = 0 as i32 as size_t;
                                i = 3 as i32 as size_t;
                                loop {
                                    if !(i < nheader) {
                                        current_block = 228501038991332163;
                                        break;
                                    }
                                    let mut hlen: size_t = 0;
                                    hdbuf = unsafe { line_end.offset(2 as i32 as isize) };
                                    line_end = (unsafe { memchr(
                                        hdbuf as *const libc::c_void,
                                        '\r' as i32,
                                        len.wrapping_sub(
                                            hdbuf.offset_from(mem as *mut i8) as i64 as u64
                                        ),
                                    ) }) as *mut i8;
                                    if line_end.is_null() || line_end == hdbuf {
                                        current_block = 337463635748514786;
                                        break;
                                    }
                                    if (unsafe { *hdbuf }) as i32 == ' ' as i32 || (unsafe { *hdbuf }) as i32 == '\t' as i32 {
                                        current_block = 337463635748514786;
                                        break;
                                    }
                                    end = hdbuf;
                                    while end < line_end && (unsafe { *end }) as i32 != ':' as i32 {
                                        end = unsafe { end.offset(1) };
                                    }
                                    if end == hdbuf || end == line_end {
                                        current_block = 337463635748514786;
                                        break;
                                    }
                                    hlen = (unsafe { end.offset_from(hdbuf) }) as i64 as size_t;
                                    if hlen == 4 as i32 as u64
                                        && (unsafe { Curl_strncasecompare(
                                            b"host\0" as *const u8 as *const i8,
                                            hdbuf,
                                            4 as i32 as size_t,
                                        ) }) != 0
                                    {
                                        authority_idx = i;
                                        let fresh54 = unsafe { &mut ((*nva.offset(i as isize)).name) };
                                        *fresh54 =
                                            b":authority\0" as *const u8 as *const i8 as *mut u8;
                                        (unsafe { (*nva.offset(i as isize)).namelen =
                                            strlen((*nva.offset(i as isize)).name as *mut i8) });
                                    } else {
                                        (unsafe { (*nva.offset(i as isize)).namelen =
                                            end.offset_from(hdbuf) as i64 as size_t });
                                        (unsafe { Curl_strntolower(
                                            hdbuf,
                                            hdbuf,
                                            (*nva.offset(i as isize)).namelen,
                                        ) });
                                        let fresh55 = unsafe { &mut ((*nva.offset(i as isize)).name) };
                                        *fresh55 = hdbuf as *mut u8;
                                    }
                                    hdbuf = unsafe { end.offset(1 as i32 as isize) };
                                    while (unsafe { *hdbuf }) as i32 == ' ' as i32
                                        || (unsafe { *hdbuf }) as i32 == '\t' as i32
                                    {
                                        hdbuf = unsafe { hdbuf.offset(1) };
                                    }
                                    end = line_end;
                                    match inspect_header(
                                        (unsafe { (*nva.offset(i as isize)).name }) as *const i8,
                                        unsafe { (*nva.offset(i as isize)).namelen },
                                        hdbuf,
                                        (unsafe { end.offset_from(hdbuf) }) as i64 as size_t,
                                    ) as u32
                                    {
                                        1 => {
                                            nheader = nheader.wrapping_sub(1);
                                            continue;
                                        }
                                        2 => {
                                            let fresh56 = unsafe { &mut ((*nva.offset(i as isize)).value) };
                                            *fresh56 = b"trailers\0" as *const u8 as *const i8
                                                as *mut uint8_t;
                                            (unsafe { (*nva.offset(i as isize)).valuelen =
                                                (::std::mem::size_of::<[i8; 9]>() as u64)
                                                    .wrapping_sub(1 as i32 as u64) });
                                        }
                                        _ => {
                                            let fresh57 = unsafe { &mut ((*nva.offset(i as isize)).value) };
                                            *fresh57 = hdbuf as *mut u8;
                                            (unsafe { (*nva.offset(i as isize)).valuelen =
                                                end.offset_from(hdbuf) as i64 as size_t });
                                        }
                                    }
                                    (unsafe { (*nva.offset(i as isize)).flags =
                                        NGHTTP2_NV_FLAG_NONE as i32 as uint8_t });
                                    if (unsafe { (*nva.offset(i as isize)).namelen }) > 0xffff as i32 as u64
                                        || (unsafe { (*nva.offset(i as isize)).valuelen })
                                            > (0xffff as i32 as u64)
                                                .wrapping_sub(unsafe { (*nva.offset(i as isize)).namelen })
                                    {
                                        (unsafe { Curl_failf(
                                            data,
                                            b"Failed sending HTTP request: Header overflow\0"
                                                as *const u8
                                                as *const i8,
                                        ) });
                                        current_block = 337463635748514786;
                                        break;
                                    } else {
                                        i = i.wrapping_add(1);
                                    }
                                }
                                match current_block {
                                    337463635748514786 => {}
                                    _ => {
                                        if authority_idx != 0 && authority_idx != 3 as i32 as u64 {
                                            let mut authority: nghttp2_nv =
                                                unsafe { *nva.offset(authority_idx as isize) };
                                            i = authority_idx;
                                            while i > 3 as i32 as u64 {
                                                (unsafe { *nva.offset(i as isize) = *nva.offset(
                                                    i.wrapping_sub(1 as i32 as u64) as isize,
                                                ) });
                                                i = i.wrapping_sub(1);
                                            }
                                            (unsafe { *nva.offset(i as isize) = authority });
                                        }
                                        let mut acc: size_t = 0 as i32 as size_t;
                                        i = 0 as i32 as size_t;
                                        while i < nheader {
                                            acc = (acc as u64).wrapping_add(
                                                (unsafe { (*nva.offset(i as isize)).namelen }).wrapping_add(
                                                    unsafe { (*nva.offset(i as isize)).valuelen },
                                                ),
                                            )
                                                as size_t
                                                as size_t;
                                            i = i.wrapping_add(1);
                                        }
                                        if acc > 60000 as i32 as u64 {
                                            (unsafe { Curl_infof (data , b"http2_send: Warning: The cumulative length of all headers exceeds %d bytes and that could cause the stream to be rejected.\0" as * const u8 as * const i8 , 60000 as i32 ,) }) ;
                                        }
                                        h2_pri_spec(data, &mut pri_spec);
                                        match (unsafe { (*data).state.httpreq }) as u32 {
                                            1 | 2 | 3 | 4 => {
                                                if (unsafe { (*data).state.infilesize }) != -(1 as i32) as i64 {
                                                    (unsafe { (*stream).upload_left =
                                                        (*data).state.infilesize });
                                                } else {
                                                    (unsafe { (*stream).upload_left =
                                                        -(1 as i32) as curl_off_t });
                                                }
                                                data_prd.read_callback = Some(
                                                    data_source_read_callback
                                                        as unsafe extern "C" fn(
                                                            *mut nghttp2_session,
                                                            int32_t,
                                                            *mut uint8_t,
                                                            size_t,
                                                            *mut uint32_t,
                                                            *mut nghttp2_data_source,
                                                            *mut libc::c_void,
                                                        )
                                                            -> ssize_t,
                                                );
                                                data_prd.source.ptr = 0 as *mut libc::c_void;
                                                stream_id = unsafe { nghttp2_submit_request(
                                                    h2,
                                                    &mut pri_spec,
                                                    nva,
                                                    nheader,
                                                    &mut data_prd,
                                                    data as *mut libc::c_void,
                                                ) };
                                            }
                                            _ => {
                                                stream_id = unsafe { nghttp2_submit_request(
                                                    h2,
                                                    &mut pri_spec,
                                                    nva,
                                                    nheader,
                                                    0 as *const nghttp2_data_provider,
                                                    data as *mut libc::c_void,
                                                ) };
                                            }
                                        }
                                        (unsafe { Curl_cfree.expect("non-null function pointer")(
                                            nva as *mut libc::c_void,
                                        ) });
                                        nva = 0 as *mut nghttp2_nv;
                                        if stream_id < 0 as i32 {
                                            (unsafe { *err = CURLE_SEND_ERROR });
                                            return -(1 as i32) as ssize_t;
                                        }
                                        (unsafe { Curl_infof(
                                            data,
                                            b"Using Stream ID: %x (easy handle %p)\0" as *const u8
                                                as *const i8,
                                            stream_id,
                                            data as *mut libc::c_void,
                                        ) });
                                        (unsafe { (*stream).stream_id = stream_id });
                                        rv = h2_session_send(data, h2);
                                        if rv != 0 {
                                            (unsafe { *err = CURLE_SEND_ERROR });
                                            return -(1 as i32) as ssize_t;
                                        }
                                        if should_close_session(httpc) != 0 {
                                            (unsafe { *err = CURLE_HTTP2 });
                                            return -(1 as i32) as ssize_t;
                                        }
                                        (unsafe { nghttp2_session_resume_data(h2, (*stream).stream_id) });
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
    (unsafe { Curl_cfree.expect("non-null function pointer")(nva as *mut libc::c_void) });
    (unsafe { *err = CURLE_SEND_ERROR });
    return -(1 as i32) as ssize_t;
}
#[no_mangle]
pub extern "C" fn Curl_http2_setup(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut httpc: *mut http_conn = unsafe { &mut (*conn).proto.httpc };
    let mut stream: *mut HTTP = unsafe { (*data).req.p.http };
    (unsafe { (*stream).stream_id = -(1 as i32) });
    (unsafe { Curl_dyn_init(
        &mut (*stream).header_recvbuf,
        (128 as i32 * 1024 as i32) as size_t,
    ) });
    (unsafe { Curl_dyn_init(
        &mut (*stream).trailer_recvbuf,
        (128 as i32 * 1024 as i32) as size_t,
    ) });
    (unsafe { (*stream).upload_left = 0 as i32 as curl_off_t });
    let fresh58 = unsafe { &mut ((*stream).upload_mem) };
    *fresh58 = 0 as *const uint8_t;
    (unsafe { (*stream).upload_len = 0 as i32 as size_t });
    let fresh59 = unsafe { &mut ((*stream).mem) };
    *fresh59 = unsafe { (*data).state.buffer };
    (unsafe { (*stream).len = (*data).set.buffer_size as size_t });
    multi_connchanged(unsafe { (*data).multi });
    if (unsafe { (*conn).handler }) == (unsafe { &Curl_handler_http2_ssl }) as *const Curl_handler
        || (unsafe { (*conn).handler }) == (unsafe { &Curl_handler_http2 }) as *const Curl_handler
    {
        return CURLE_OK;
    }
    if (unsafe { (*(*conn).handler).flags }) & ((1 as i32) << 0 as i32) as u32 != 0 {
        let fresh60 = unsafe { &mut ((*conn).handler) };
        *fresh60 = unsafe { &Curl_handler_http2_ssl };
    } else {
        let fresh61 = unsafe { &mut ((*conn).handler) };
        *fresh61 = unsafe { &Curl_handler_http2 };
    }
    result = http2_init(data, conn);
    if result as u64 != 0 {
        (unsafe { Curl_dyn_free(&mut (*stream).header_recvbuf) });
        return result;
    }
    (unsafe { Curl_infof(
        data,
        b"Using HTTP2, server supports multiplexing\0" as *const u8 as *const i8,
    ) });
    let fresh62 = unsafe { &mut ((*conn).bits) };
    (*fresh62).set_multiplex(1 as i32 as bit);
    (unsafe { (*conn).httpversion = 20 as i32 as u8 });
    (unsafe { (*(*conn).bundle).multiuse = 2 as i32 });
    (unsafe { (*httpc).inbuflen = 0 as i32 as size_t });
    (unsafe { (*httpc).nread_inbuf = 0 as i32 as size_t });
    (unsafe { (*httpc).pause_stream_id = 0 as i32 });
    (unsafe { (*httpc).drain_total = 0 as i32 as size_t });
    (unsafe { Curl_infof(
        data,
        b"Connection state changed (HTTP/2 confirmed)\0" as *const u8 as *const i8,
    ) });
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_http2_switched(
    mut data: *mut Curl_easy,
    mut mem: *const i8,
    mut nread: size_t,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    let mut httpc: *mut http_conn = unsafe { &mut (*conn).proto.httpc };
    let mut rv: i32 = 0;
    let mut stream: *mut HTTP = unsafe { (*data).req.p.http };
    result = Curl_http2_setup(data, conn);
    if result as u64 != 0 {
        return result;
    }
    let fresh63 = unsafe { &mut ((*httpc).recv_underlying) };
    *fresh63 = unsafe { (*conn).recv[0 as i32 as usize] };
    let fresh64 = unsafe { &mut ((*httpc).send_underlying) };
    *fresh64 = unsafe { (*conn).send[0 as i32 as usize] };
    let fresh65 = unsafe { &mut ((*conn).recv[0 as i32 as usize]) };
    *fresh65 = Some(
        http2_recv
            as unsafe extern "C" fn(*mut Curl_easy, i32, *mut i8, size_t, *mut CURLcode) -> ssize_t,
    );
    let fresh66 = unsafe { &mut ((*conn).send[0 as i32 as usize]) };
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
    if (unsafe { (*data).req.upgr101 }) as u32 == UPGR101_RECEIVED as i32 as u32 {
        (unsafe { (*stream).stream_id = 1 as i32 });
        rv = unsafe { nghttp2_session_upgrade2(
            (*httpc).h2,
            ((*httpc).binsettings).as_mut_ptr(),
            (*httpc).binlen,
            ((*data).state.httpreq as u32 == HTTPREQ_HEAD as i32 as u32) as i32,
            0 as *mut libc::c_void,
        ) };
        if rv != 0 {
            (unsafe { Curl_failf(
                data,
                b"nghttp2_session_upgrade2() failed: %s(%d)\0" as *const u8 as *const i8,
                nghttp2_strerror(rv),
                rv,
            ) });
            return CURLE_HTTP2;
        }
        rv = unsafe { nghttp2_session_set_stream_user_data(
            (*httpc).h2,
            (*stream).stream_id,
            data as *mut libc::c_void,
        ) };
        if rv != 0 {
            (unsafe { Curl_infof(
                data,
                b"http/2: failed to set user_data for stream %d!\0" as *const u8 as *const i8,
                (*stream).stream_id,
            ) });
        }
    } else {
        populate_settings(data, httpc);
        (unsafe { (*stream).stream_id = -(1 as i32) });
        rv = unsafe { nghttp2_submit_settings(
            (*httpc).h2,
            NGHTTP2_FLAG_NONE as i32 as uint8_t,
            ((*httpc).local_settings).as_mut_ptr(),
            (*httpc).local_settings_num,
        ) };
        if rv != 0 {
            (unsafe { Curl_failf(
                data,
                b"nghttp2_submit_settings() failed: %s(%d)\0" as *const u8 as *const i8,
                nghttp2_strerror(rv),
                rv,
            ) });
            return CURLE_HTTP2;
        }
    }
    rv = unsafe { nghttp2_session_set_local_window_size(
        (*httpc).h2,
        NGHTTP2_FLAG_NONE as i32 as uint8_t,
        0 as i32,
        32 as i32 * 1024 as i32 * 1024 as i32,
    ) };
    if rv != 0 {
        (unsafe { Curl_failf(
            data,
            b"nghttp2_session_set_local_window_size() failed: %s(%d)\0" as *const u8 as *const i8,
            nghttp2_strerror(rv),
            rv,
        ) });
        return CURLE_HTTP2;
    }
    if (32768 as i32 as u64) < nread {
        (unsafe { Curl_failf (data , b"connection buffer size is too small to store data following HTTP Upgrade response header: buflen=%d, datalen=%zu\0" as * const u8 as * const i8 , 32768 as i32 , nread ,) }) ;
        return CURLE_HTTP2;
    }
    (unsafe { Curl_infof(
        data,
        b"Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=%zu\0"
            as *const u8 as *const i8,
        nread,
    ) });
    if nread != 0 {
        (unsafe { memcpy(
            (*httpc).inbuf as *mut libc::c_void,
            mem as *const libc::c_void,
            nread,
        ) });
    }
    (unsafe { (*httpc).inbuflen = nread });
    if -(1 as i32) == h2_process_pending_input(data, httpc, &mut result) {
        return CURLE_HTTP2;
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_http2_stream_pause(mut data: *mut Curl_easy, mut pause: bool) -> CURLcode {
    if (unsafe { (*(*(*data).conn).handler).protocol })
        & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32
        == 0
        || (unsafe { (*(*data).conn).proto.httpc.h2 }).is_null()
    {
        return CURLE_OK;
    } else {
        let mut stream: *mut HTTP = unsafe { (*data).req.p.http };
        let mut httpc: *mut http_conn = unsafe { &mut (*(*data).conn).proto.httpc };
        let mut window: uint32_t =
            (!pause as i32 * (32 as i32 * 1024 as i32 * 1024 as i32)) as uint32_t;
        let mut rv: i32 = unsafe { nghttp2_session_set_local_window_size(
            (*httpc).h2,
            NGHTTP2_FLAG_NONE as i32 as uint8_t,
            (*stream).stream_id,
            window as int32_t,
        ) };
        if rv != 0 {
            (unsafe { Curl_failf(
                data,
                b"nghttp2_session_set_local_window_size() failed: %s(%d)\0" as *const u8
                    as *const i8,
                nghttp2_strerror(rv),
                rv,
            ) });
            return CURLE_HTTP2;
        }
        rv = h2_session_send(data, unsafe { (*httpc).h2 });
        if rv != 0 {
            return CURLE_SEND_ERROR;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_http2_add_child(
    mut parent: *mut Curl_easy,
    mut child: *mut Curl_easy,
    mut exclusive: bool,
) -> CURLcode {
    if !parent.is_null() {
        let mut tail: *mut *mut Curl_http2_dep = 0 as *mut *mut Curl_http2_dep;
        let mut dep: *mut Curl_http2_dep = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
            1 as i32 as size_t,
            ::std::mem::size_of::<Curl_http2_dep>() as u64,
        ) }) as *mut Curl_http2_dep;
        if dep.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        let fresh67 = unsafe { &mut ((*dep).data) };
        *fresh67 = child;
        if !(unsafe { (*parent).set.stream_dependents }).is_null() && exclusive as i32 != 0 {
            let mut node: *mut Curl_http2_dep = unsafe { (*parent).set.stream_dependents };
            while !node.is_null() {
                let fresh68 = unsafe { &mut ((*(*node).data).set.stream_depends_on) };
                *fresh68 = child;
                node = unsafe { (*node).next };
            }
            tail = unsafe { &mut (*child).set.stream_dependents };
            while !(unsafe { *tail }).is_null() {
                tail = unsafe { &mut (**tail).next };
            }
            (unsafe { *tail = (*parent).set.stream_dependents });
            let fresh69 = unsafe { &mut ((*parent).set.stream_dependents) };
            *fresh69 = 0 as *mut Curl_http2_dep;
        }
        tail = unsafe { &mut (*parent).set.stream_dependents };
        while !(unsafe { *tail }).is_null() {
            let fresh70 = unsafe { &mut ((*(**tail).data).set) };
            (*fresh70).set_stream_depends_e(0 as i32 as bit);
            tail = unsafe { &mut (**tail).next };
        }
        (unsafe { *tail = dep });
    }
    let fresh71 = unsafe { &mut ((*child).set.stream_depends_on) };
    *fresh71 = parent;
    let fresh72 = unsafe { &mut ((*child).set) };
    (*fresh72).set_stream_depends_e(exclusive as bit);
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_http2_remove_child(mut parent: *mut Curl_easy, mut child: *mut Curl_easy) {
    let mut last: *mut Curl_http2_dep = 0 as *mut Curl_http2_dep;
    let mut data: *mut Curl_http2_dep = unsafe { (*parent).set.stream_dependents };
    while !data.is_null() && (unsafe { (*data).data }) != child {
        last = data;
        data = unsafe { (*data).next };
    }
    if !data.is_null() {
        if !last.is_null() {
            let fresh73 = unsafe { &mut ((*last).next) };
            *fresh73 = unsafe { (*data).next };
        } else {
            let fresh74 = unsafe { &mut ((*parent).set.stream_dependents) };
            *fresh74 = unsafe { (*data).next };
        }
        (unsafe { Curl_cfree.expect("non-null function pointer")(data as *mut libc::c_void) });
    }
    let fresh75 = unsafe { &mut ((*child).set.stream_depends_on) };
    *fresh75 = 0 as *mut Curl_easy;
    let fresh76 = unsafe { &mut ((*child).set) };
    (*fresh76).set_stream_depends_e(0 as i32 as bit);
}
#[no_mangle]
pub extern "C" fn Curl_http2_cleanup_dependencies(mut data: *mut Curl_easy) {
    while !(unsafe { (*data).set.stream_dependents }).is_null() {
        let mut tmp: *mut Curl_easy = unsafe { (*(*data).set.stream_dependents).data };
        Curl_http2_remove_child(data, tmp);
        if !(unsafe { (*data).set.stream_depends_on }).is_null() {
            Curl_http2_add_child(unsafe { (*data).set.stream_depends_on }, tmp, 0 as i32 != 0);
        }
    }
    if !(unsafe { (*data).set.stream_depends_on }).is_null() {
        Curl_http2_remove_child(unsafe { (*data).set.stream_depends_on }, data);
    }
}
#[no_mangle]
pub extern "C" fn Curl_h2_http_1_1_error(mut data: *mut Curl_easy) -> bool {
    let mut stream: *mut HTTP = unsafe { (*data).req.p.http };
    return (unsafe { (*stream).error }) == NGHTTP2_HTTP_1_1_REQUIRED as i32 as u32;
}
