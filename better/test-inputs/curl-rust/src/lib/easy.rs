use ::libc;
use ::c2rust_bitfields;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type Curl_URL;
    pub type thread_data;
    pub type TELNET;
    pub type smb_request;
    pub type ldapreqinfo;
    pub type contenc_writer;
    pub type psl_ctx_st;
    pub type curl_pushheaders;
    pub type http_connect_state;
    pub type ldapconninfo;
    pub type tftp_state_data;
    pub type nghttp2_session;
    pub type Gsasl_session;
    pub type Gsasl;
    pub type ssl_backend_data;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn curl_slist_free_all(_: *mut curl_slist);
    fn curl_multi_remove_handle(
        multi_handle: *mut CURLM,
        curl_handle: *mut CURL,
    ) -> CURLMcode;
    fn curl_multi_info_read(
        multi_handle: *mut CURLM,
        msgs_in_queue: *mut libc::c_int,
    ) -> *mut CURLMsg;
    fn curl_multi_perform(
        multi_handle: *mut CURLM,
        running_handles: *mut libc::c_int,
    ) -> CURLMcode;
    fn curl_multi_poll(
        multi_handle: *mut CURLM,
        extra_fds: *mut curl_waitfd,
        extra_nfds: libc::c_uint,
        timeout_ms: libc::c_int,
        ret: *mut libc::c_int,
    ) -> CURLMcode;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn curl_multi_cleanup(multi_handle: *mut CURLM) -> CURLMcode;
    fn curl_multi_add_handle(
        multi_handle: *mut CURLM,
        curl_handle: *mut CURL,
    ) -> CURLMcode;
    fn curl_multi_setopt(
        multi_handle: *mut CURLM,
        option: CURLMoption,
        _: ...
    ) -> CURLMcode;
    fn sigaction(
        __sig: libc::c_int,
        __act: *const sigaction,
        __oact: *mut sigaction,
    ) -> libc::c_int;
    fn Curl_mime_initpart(part: *mut curl_mimepart, easy: *mut Curl_easy);
    fn Curl_mime_duppart(dst: *mut curl_mimepart, src: *const curl_mimepart) -> CURLcode;
    fn Curl_cookie_init(
        data: *mut Curl_easy,
        file: *const libc::c_char,
        inc: *mut CookieInfo,
        newsession: bool,
    ) -> *mut CookieInfo;
    fn Curl_resolver_duphandle(
        easy: *mut Curl_easy,
        to: *mut *mut libc::c_void,
        from: *mut libc::c_void,
    ) -> CURLcode;
    fn Curl_mime_read(
        buffer: *mut libc::c_char,
        size: size_t,
        nitems: size_t,
        instream: *mut libc::c_void,
    ) -> size_t;
    fn Curl_mime_unpause(part: *mut curl_mimepart);
    fn Curl_dyn_init(s: *mut dynbuf, toobig: size_t);
    fn Curl_dyn_ptr(s: *const dynbuf) -> *mut libc::c_char;
    fn Curl_dyn_len(s: *const dynbuf) -> size_t;
    fn Curl_dyn_free(s: *mut dynbuf);
    fn Curl_resolver_global_cleanup();
    fn Curl_resolver_global_init() -> libc::c_int;
    fn Curl_conncache_foreach(
        data: *mut Curl_easy,
        connc: *mut conncache,
        param: *mut libc::c_void,
        func: Option::<
            unsafe extern "C" fn(
                *mut Curl_easy,
                *mut connectdata,
                *mut libc::c_void,
            ) -> libc::c_int,
        >,
    ) -> bool;
    fn Curl_ssl_init() -> libc::c_int;
    fn Curl_ssl_cleanup();
    fn Curl_ssl_set_engine(
        data: *mut Curl_easy,
        engine: *const libc::c_char,
    ) -> CURLcode;
    fn Curl_open(curl: *mut *mut Curl_easy) -> CURLcode;
    fn Curl_init_userdefined(data: *mut Curl_easy) -> CURLcode;
    fn Curl_freeset(data: *mut Curl_easy);
    fn Curl_close(datap: *mut *mut Curl_easy) -> CURLcode;
    fn Curl_free_request_state(data: *mut Curl_easy);
    fn Curl_getinfo(data: *mut Curl_easy, info: CURLINFO, _: ...) -> CURLcode;
    fn Curl_initinfo(data: *mut Curl_easy) -> CURLcode;
    fn Curl_memdup(src: *const libc::c_void, buffer_length: size_t) -> *mut libc::c_void;
    fn Curl_updatesocket(data: *mut Curl_easy);
    fn Curl_expire(data: *mut Curl_easy, milli: timediff_t, _: expire_id);
    fn Curl_update_timer(multi: *mut Curl_multi);
    fn Curl_attach_connnection(data: *mut Curl_easy, conn: *mut connectdata);
    fn Curl_detach_connnection(data: *mut Curl_easy);
    fn Curl_is_in_callback(easy: *mut Curl_easy) -> bool;
    fn Curl_multi_handle(
        hashsize: libc::c_int,
        chashsize: libc::c_int,
    ) -> *mut Curl_multi;
    fn Curl_failf(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
    fn Curl_client_write(
        data: *mut Curl_easy,
        type_0: libc::c_int,
        ptr: *mut libc::c_char,
        len: size_t,
    ) -> CURLcode;
    fn Curl_read(
        data: *mut Curl_easy,
        sockfd: curl_socket_t,
        buf: *mut libc::c_char,
        buffersize: size_t,
        n: *mut ssize_t,
    ) -> CURLcode;
    fn Curl_write(
        data: *mut Curl_easy,
        sockfd: curl_socket_t,
        mem: *const libc::c_void,
        len: size_t,
        written: *mut ssize_t,
    ) -> CURLcode;
    fn Curl_getconnectinfo(
        data: *mut Curl_easy,
        connp: *mut *mut connectdata,
    ) -> curl_socket_t;
    fn Curl_slist_duplicate(inlist: *mut curl_slist) -> *mut curl_slist;
    fn curlx_sotouz(sonum: curl_off_t) -> size_t;
    fn Curl_setstropt(charp: *mut *mut libc::c_char, s: *const libc::c_char) -> CURLcode;
    fn Curl_setblobopt(blobp: *mut *mut curl_blob, blob: *const curl_blob) -> CURLcode;
    fn Curl_http_auth_cleanup_digest(data: *mut Curl_easy);
    fn Curl_http2_stream_pause(data: *mut Curl_easy, pause: bool) -> CURLcode;
    fn Curl_altsvc_cleanup(altsvc: *mut *mut altsvcinfo);
    fn Curl_hsts_init() -> *mut hsts;
    fn Curl_hsts_cleanup(hp: *mut *mut hsts);
    fn Curl_hsts_loadfile(
        data: *mut Curl_easy,
        h: *mut hsts,
        file: *const libc::c_char,
    ) -> CURLcode;
    fn Curl_hsts_loadcb(data: *mut Curl_easy, h: *mut hsts) -> CURLcode;
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: libc::c_uint,
    pub fp_offset: libc::c_uint,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type __uint8_t = libc::c_uchar;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __uid_t = libc::c_uint;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __clock_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type pid_t = __pid_t;
pub type ssize_t = __ssize_t;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type int32_t = __int32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __sigset_t {
    pub __val: [libc::c_ulong; 16],
}
pub type socklen_t = __socklen_t;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
pub type curl_socklen_t = socklen_t;
pub type curl_off_t = libc::c_long;
pub type va_list = __builtin_va_list;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type __sigval_t = sigval;
#[derive(Copy, Clone)]
#[repr(C)]
pub union sigval {
    pub sival_int: libc::c_int,
    pub sival_ptr: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_easy {
    pub magic: libc::c_uint,
    pub next: *mut Curl_easy,
    pub prev: *mut Curl_easy,
    pub conn: *mut connectdata,
    pub connect_queue: Curl_llist_element,
    pub conn_queue: Curl_llist_element,
    pub mstate: CURLMstate,
    pub result: CURLcode,
    pub msg: Curl_message,
    pub sockets: [curl_socket_t; 5],
    pub actions: [libc::c_uchar; 5],
    pub numsocks: libc::c_int,
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
pub type curl_sslbackend = libc::c_uint;
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
    pub httpcode: libc::c_int,
    pub httpproxycode: libc::c_int,
    pub httpversion: libc::c_int,
    pub filetime: time_t,
    pub header_size: curl_off_t,
    pub request_size: curl_off_t,
    pub proxyauthavail: libc::c_ulong,
    pub httpauthavail: libc::c_ulong,
    pub numconnects: libc::c_long,
    pub contenttype: *mut libc::c_char,
    pub wouldredirect: *mut libc::c_char,
    pub retry_after: curl_off_t,
    pub conn_primary_ip: [libc::c_char; 46],
    pub conn_primary_port: libc::c_int,
    pub conn_local_ip: [libc::c_char; 46],
    pub conn_local_port: libc::c_int,
    pub conn_scheme: *const libc::c_char,
    pub conn_protocol: libc::c_uint,
    pub certs: curl_certinfo,
    pub pxcode: CURLproxycode,
    #[bitfield(name = "timecond", ty = "bit", bits = "0..=0")]
    pub timecond: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
pub type bit = libc::c_uint;
pub type CURLproxycode = libc::c_uint;
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
    pub num_of_certs: libc::c_int,
    pub certinfo: *mut *mut curl_slist,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_slist {
    pub data: *mut libc::c_char,
    pub next: *mut curl_slist,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct WildcardData {
    pub state: wildcard_states,
    pub path: *mut libc::c_char,
    pub pattern: *mut libc::c_char,
    pub filelist: Curl_llist,
    pub protdata: *mut libc::c_void,
    pub dtor: wildcard_dtor,
    pub customptr: *mut libc::c_void,
}
pub type wildcard_dtor = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_llist {
    pub head: *mut Curl_llist_element,
    pub tail: *mut Curl_llist_element,
    pub dtor: Curl_llist_dtor,
    pub size: size_t,
}
pub type Curl_llist_dtor = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> (),
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_llist_element {
    pub ptr: *mut libc::c_void,
    pub prev: *mut Curl_llist_element,
    pub next: *mut Curl_llist_element,
}
pub type wildcard_states = libc::c_uint;
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
    pub lastconnect_id: libc::c_long,
    pub headerb: dynbuf,
    pub buffer: *mut libc::c_char,
    pub ulbuf: *mut libc::c_char,
    pub current_speed: curl_off_t,
    pub first_host: *mut libc::c_char,
    pub retrycount: libc::c_int,
    pub first_remote_port: libc::c_int,
    pub session: *mut Curl_ssl_session,
    pub sessionage: libc::c_long,
    pub tempwrite: [tempbuf; 3],
    pub tempcount: libc::c_uint,
    pub os_errno: libc::c_int,
    pub scratch: *mut libc::c_char,
    pub followlocation: libc::c_long,
    pub prev_signal: Option::<unsafe extern "C" fn(libc::c_int) -> ()>,
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
    pub most_recent_ftp_entrypath: *mut libc::c_char,
    pub httpwant: libc::c_uchar,
    pub httpversion: libc::c_uchar,
    #[bitfield(name = "prev_block_had_trailing_cr", ty = "bit", bits = "0..=0")]
    pub prev_block_had_trailing_cr: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 5],
    pub crlf_conversions: curl_off_t,
    pub range: *mut libc::c_char,
    pub resume_from: curl_off_t,
    pub rtsp_next_client_CSeq: libc::c_long,
    pub rtsp_next_server_CSeq: libc::c_long,
    pub rtsp_CSeq_recv: libc::c_long,
    pub infilesize: curl_off_t,
    pub drain: size_t,
    pub fread_func: curl_read_callback,
    pub in_0: *mut libc::c_void,
    pub stream_depends_on: *mut Curl_easy,
    pub stream_weight: libc::c_int,
    pub uh: *mut CURLU,
    pub up: urlpieces,
    pub httpreq: Curl_HttpReq,
    pub url: *mut libc::c_char,
    pub referer: *mut libc::c_char,
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
    pub multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve: [u8; 3],
    #[bitfield(padding)]
    pub c2rust_padding_0: [u8; 5],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dynamically_allocated_data {
    pub proxyuserpwd: *mut libc::c_char,
    pub uagent: *mut libc::c_char,
    pub accept_encoding: *mut libc::c_char,
    pub userpwd: *mut libc::c_char,
    pub rangeline: *mut libc::c_char,
    pub ref_0: *mut libc::c_char,
    pub host: *mut libc::c_char,
    pub cookiehost: *mut libc::c_char,
    pub rtsp_transport: *mut libc::c_char,
    pub te: *mut libc::c_char,
    pub user: *mut libc::c_char,
    pub passwd: *mut libc::c_char,
    pub proxyuser: *mut libc::c_char,
    pub proxypasswd: *mut libc::c_char,
}
pub type trailers_state = libc::c_uint;
pub const TRAILERS_DONE: trailers_state = 3;
pub const TRAILERS_SENDING: trailers_state = 2;
pub const TRAILERS_INITIALIZED: trailers_state = 1;
pub const TRAILERS_NONE: trailers_state = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dynbuf {
    pub bufr: *mut libc::c_char,
    pub leng: size_t,
    pub allc: size_t,
    pub toobig: size_t,
}
pub type Curl_HttpReq = libc::c_uint;
pub const HTTPREQ_HEAD: Curl_HttpReq = 5;
pub const HTTPREQ_PUT: Curl_HttpReq = 4;
pub const HTTPREQ_POST_MIME: Curl_HttpReq = 3;
pub const HTTPREQ_POST_FORM: Curl_HttpReq = 2;
pub const HTTPREQ_POST: Curl_HttpReq = 1;
pub const HTTPREQ_GET: Curl_HttpReq = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct urlpieces {
    pub scheme: *mut libc::c_char,
    pub hostname: *mut libc::c_char,
    pub port: *mut libc::c_char,
    pub user: *mut libc::c_char,
    pub password: *mut libc::c_char,
    pub options: *mut libc::c_char,
    pub path: *mut libc::c_char,
    pub query: *mut libc::c_char,
}
pub type CURLU = Curl_URL;
pub type curl_read_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_char, size_t, size_t, *mut libc::c_void) -> size_t,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct time_node {
    pub list: Curl_llist_element,
    pub time: curltime,
    pub eid: expire_id,
}
pub type expire_id = libc::c_uint;
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
    pub tv_usec: libc::c_int,
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
    pub hostname: *mut libc::c_char,
    pub dns: *mut Curl_dns_entry,
    pub tdata: *mut thread_data,
    pub resolver: *mut libc::c_void,
    pub port: libc::c_int,
    pub status: libc::c_int,
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
    pub inuse: libc::c_long,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_addrinfo {
    pub ai_flags: libc::c_int,
    pub ai_family: libc::c_int,
    pub ai_socktype: libc::c_int,
    pub ai_protocol: libc::c_int,
    pub ai_addrlen: curl_socklen_t,
    pub ai_canonname: *mut libc::c_char,
    pub ai_addr: *mut sockaddr,
    pub ai_next: *mut Curl_addrinfo,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct auth {
    pub want: libc::c_ulong,
    pub picked: libc::c_ulong,
    pub avail: libc::c_ulong,
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
    pub nonce: *mut libc::c_char,
    pub cnonce: *mut libc::c_char,
    pub realm: *mut libc::c_char,
    pub algo: libc::c_int,
    pub opaque: *mut libc::c_char,
    pub qop: *mut libc::c_char,
    pub algorithm: *mut libc::c_char,
    pub nc: libc::c_int,
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
    pub type_0: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_ssl_session {
    pub name: *mut libc::c_char,
    pub conn_to_host: *mut libc::c_char,
    pub scheme: *const libc::c_char,
    pub sessionid: *mut libc::c_void,
    pub idsize: size_t,
    pub age: libc::c_long,
    pub remote_port: libc::c_int,
    pub conn_to_port: libc::c_int,
    pub ssl_config: ssl_primary_config,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ssl_primary_config {
    pub version: libc::c_long,
    pub version_max: libc::c_long,
    pub CApath: *mut libc::c_char,
    pub CAfile: *mut libc::c_char,
    pub issuercert: *mut libc::c_char,
    pub clientcert: *mut libc::c_char,
    pub random_file: *mut libc::c_char,
    pub egdsocket: *mut libc::c_char,
    pub cipher_list: *mut libc::c_char,
    pub cipher_list13: *mut libc::c_char,
    pub pinned_key: *mut libc::c_char,
    pub cert_blob: *mut curl_blob,
    pub ca_info_blob: *mut curl_blob,
    pub issuercert_blob: *mut curl_blob,
    pub curves: *mut libc::c_char,
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
    pub flags: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct conncache {
    pub hash: Curl_hash,
    pub num_conn: size_t,
    pub next_connection_id: libc::c_long,
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
    pub slots: libc::c_int,
    pub size: size_t,
}
pub type Curl_hash_dtor = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type comp_function = Option::<
    unsafe extern "C" fn(*mut libc::c_void, size_t, *mut libc::c_void, size_t) -> size_t,
>;
pub type hash_function = Option::<
    unsafe extern "C" fn(*mut libc::c_void, size_t, size_t) -> size_t,
>;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct Progress {
    pub lastshow: time_t,
    pub size_dl: curl_off_t,
    pub size_ul: curl_off_t,
    pub downloaded: curl_off_t,
    pub uploaded: curl_off_t,
    pub current_speed: curl_off_t,
    pub width: libc::c_int,
    pub flags: libc::c_int,
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
    pub speeder_c: libc::c_int,
    #[bitfield(name = "callback", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "is_t_startransfer_set", ty = "bit", bits = "1..=1")]
    pub callback_is_t_startransfer_set: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
pub type timediff_t = curl_off_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct altsvcinfo {
    pub filename: *mut libc::c_char,
    pub list: Curl_llist,
    pub flags: libc::c_long,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hsts {
    pub list: Curl_llist,
    pub filename: *mut libc::c_char,
    pub flags: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CookieInfo {
    pub cookies: [*mut Cookie; 256],
    pub filename: *mut libc::c_char,
    pub numcookies: libc::c_long,
    pub running: bool,
    pub newsession: bool,
    pub lastct: libc::c_int,
    pub next_expiration: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Cookie {
    pub next: *mut Cookie,
    pub name: *mut libc::c_char,
    pub value: *mut libc::c_char,
    pub path: *mut libc::c_char,
    pub spath: *mut libc::c_char,
    pub domain: *mut libc::c_char,
    pub expires: curl_off_t,
    pub expirestr: *mut libc::c_char,
    pub version: *mut libc::c_char,
    pub maxage: *mut libc::c_char,
    pub tailmatch: bool,
    pub secure: bool,
    pub livecookie: bool,
    pub httponly: bool,
    pub creationtime: libc::c_int,
    pub prefix: libc::c_uchar,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct UserDefined {
    pub err: *mut FILE,
    pub debugdata: *mut libc::c_void,
    pub errorbuffer: *mut libc::c_char,
    pub proxyport: libc::c_long,
    pub out: *mut libc::c_void,
    pub in_set: *mut libc::c_void,
    pub writeheader: *mut libc::c_void,
    pub rtp_out: *mut libc::c_void,
    pub use_port: libc::c_long,
    pub httpauth: libc::c_ulong,
    pub proxyauth: libc::c_ulong,
    pub socks5auth: libc::c_ulong,
    pub maxredirs: libc::c_long,
    pub keep_post: libc::c_int,
    pub postfields: *mut libc::c_void,
    pub seek_func: curl_seek_callback,
    pub postfieldsize: curl_off_t,
    pub localport: libc::c_ushort,
    pub localportrange: libc::c_int,
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
    pub timeout: libc::c_long,
    pub connecttimeout: libc::c_long,
    pub accepttimeout: libc::c_long,
    pub happy_eyeballs_timeout: libc::c_long,
    pub server_response_timeout: libc::c_long,
    pub maxage_conn: libc::c_long,
    pub tftp_blksize: libc::c_long,
    pub filesize: curl_off_t,
    pub low_speed_limit: libc::c_long,
    pub low_speed_time: libc::c_long,
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
    pub httpwant: libc::c_uchar,
    pub ssl: ssl_config_data,
    pub proxy_ssl: ssl_config_data,
    pub general_ssl: ssl_general_config,
    pub dns_cache_timeout: libc::c_long,
    pub buffer_size: libc::c_long,
    pub upload_buffer_size: libc::c_uint,
    pub private_data: *mut libc::c_void,
    pub http200aliases: *mut curl_slist,
    pub ipver: libc::c_uchar,
    pub max_filesize: curl_off_t,
    pub ftp_filemethod: curl_ftpfile,
    pub ftpsslauth: curl_ftpauth,
    pub ftp_ccc: curl_ftpccc,
    pub ftp_create_missing_dirs: libc::c_int,
    pub ssh_keyfunc: curl_sshkeycallback,
    pub ssh_keyfunc_userp: *mut libc::c_void,
    pub use_netrc: CURL_NETRC_OPTION,
    pub use_ssl: curl_usessl,
    pub new_file_perms: libc::c_long,
    pub new_directory_perms: libc::c_long,
    pub ssh_auth_types: libc::c_long,
    pub str_0: [*mut libc::c_char; 80],
    pub blobs: [*mut curl_blob; 8],
    pub scope_id: libc::c_uint,
    pub allowed_protocols: libc::c_long,
    pub redir_protocols: libc::c_long,
    pub mail_rcpt: *mut curl_slist,
    pub rtspreq: Curl_RtspReq,
    pub rtspversion: libc::c_long,
    pub chunk_bgn: curl_chunk_bgn_callback,
    pub chunk_end: curl_chunk_end_callback,
    pub fnmatch: curl_fnmatch_callback,
    pub fnmatch_data: *mut libc::c_void,
    pub gssapi_delegation: libc::c_long,
    pub tcp_keepidle: libc::c_long,
    pub tcp_keepintvl: libc::c_long,
    pub maxconnects: size_t,
    pub expect_100_timeout: libc::c_long,
    pub stream_depends_on: *mut Curl_easy,
    pub stream_weight: libc::c_int,
    pub stream_dependents: *mut Curl_http2_dep,
    pub resolver_start: curl_resolver_start_callback,
    pub resolver_start_client: *mut libc::c_void,
    pub upkeep_interval_ms: libc::c_long,
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
    pub is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails: [u8; 8],
}
pub type curl_trailer_callback = Option::<
    unsafe extern "C" fn(*mut *mut curl_slist, *mut libc::c_void) -> libc::c_int,
>;
pub type multidone_func = Option::<
    unsafe extern "C" fn(*mut Curl_easy, CURLcode) -> libc::c_int,
>;
pub type CURLcode = libc::c_uint;
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
pub type curl_resolver_start_callback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut libc::c_void,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_http2_dep {
    pub next: *mut Curl_http2_dep,
    pub data: *mut Curl_easy,
}
pub type curl_fnmatch_callback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const libc::c_char,
        *const libc::c_char,
    ) -> libc::c_int,
>;
pub type curl_chunk_end_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> libc::c_long,
>;
pub type curl_chunk_bgn_callback = Option::<
    unsafe extern "C" fn(
        *const libc::c_void,
        *mut libc::c_void,
        libc::c_int,
    ) -> libc::c_long,
>;
pub type Curl_RtspReq = libc::c_uint;
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
pub type curl_usessl = libc::c_uint;
pub const CURLUSESSL_LAST: curl_usessl = 4;
pub const CURLUSESSL_ALL: curl_usessl = 3;
pub const CURLUSESSL_CONTROL: curl_usessl = 2;
pub const CURLUSESSL_TRY: curl_usessl = 1;
pub const CURLUSESSL_NONE: curl_usessl = 0;
pub type CURL_NETRC_OPTION = libc::c_uint;
pub const CURL_NETRC_LAST: CURL_NETRC_OPTION = 3;
pub const CURL_NETRC_REQUIRED: CURL_NETRC_OPTION = 2;
pub const CURL_NETRC_OPTIONAL: CURL_NETRC_OPTION = 1;
pub const CURL_NETRC_IGNORED: CURL_NETRC_OPTION = 0;
pub type curl_sshkeycallback = Option::<
    unsafe extern "C" fn(
        *mut CURL,
        *const curl_khkey,
        *const curl_khkey,
        curl_khmatch,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
pub type curl_khmatch = libc::c_uint;
pub const CURLKHMATCH_LAST: curl_khmatch = 3;
pub const CURLKHMATCH_MISSING: curl_khmatch = 2;
pub const CURLKHMATCH_MISMATCH: curl_khmatch = 1;
pub const CURLKHMATCH_OK: curl_khmatch = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_khkey {
    pub key: *const libc::c_char,
    pub len: size_t,
    pub keytype: curl_khtype,
}
pub type curl_khtype = libc::c_uint;
pub const CURLKHTYPE_ED25519: curl_khtype = 5;
pub const CURLKHTYPE_ECDSA: curl_khtype = 4;
pub const CURLKHTYPE_DSS: curl_khtype = 3;
pub const CURLKHTYPE_RSA: curl_khtype = 2;
pub const CURLKHTYPE_RSA1: curl_khtype = 1;
pub const CURLKHTYPE_UNKNOWN: curl_khtype = 0;
pub type CURL = Curl_easy;
pub type curl_ftpccc = libc::c_uint;
pub const CURLFTPSSL_CCC_LAST: curl_ftpccc = 3;
pub const CURLFTPSSL_CCC_ACTIVE: curl_ftpccc = 2;
pub const CURLFTPSSL_CCC_PASSIVE: curl_ftpccc = 1;
pub const CURLFTPSSL_CCC_NONE: curl_ftpccc = 0;
pub type curl_ftpauth = libc::c_uint;
pub const CURLFTPAUTH_LAST: curl_ftpauth = 3;
pub const CURLFTPAUTH_TLS: curl_ftpauth = 2;
pub const CURLFTPAUTH_SSL: curl_ftpauth = 1;
pub const CURLFTPAUTH_DEFAULT: curl_ftpauth = 0;
pub type curl_ftpfile = libc::c_uint;
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
    pub certverifyresult: libc::c_long,
    pub CRLfile: *mut libc::c_char,
    pub fsslctx: curl_ssl_ctx_callback,
    pub fsslctxp: *mut libc::c_void,
    pub cert_type: *mut libc::c_char,
    pub key: *mut libc::c_char,
    pub key_blob: *mut curl_blob,
    pub key_type: *mut libc::c_char,
    pub key_passwd: *mut libc::c_char,
    pub username: *mut libc::c_char,
    pub password: *mut libc::c_char,
    pub authtype: CURL_TLSAUTH,
    #[bitfield(name = "certinfo", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "falsestart", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "enable_beast", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "no_revoke", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "no_partialchain", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "revoke_best_effort", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "native_ca_store", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "auto_client_cert", ty = "bit", bits = "7..=7")]
    pub certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
pub type CURL_TLSAUTH = libc::c_uint;
pub const CURL_TLSAUTH_LAST: CURL_TLSAUTH = 2;
pub const CURL_TLSAUTH_SRP: CURL_TLSAUTH = 1;
pub const CURL_TLSAUTH_NONE: CURL_TLSAUTH = 0;
pub type curl_ssl_ctx_callback = Option::<
    unsafe extern "C" fn(*mut CURL, *mut libc::c_void, *mut libc::c_void) -> CURLcode,
>;
pub type curl_proxytype = libc::c_uint;
pub const CURLPROXY_SOCKS5_HOSTNAME: curl_proxytype = 7;
pub const CURLPROXY_SOCKS4A: curl_proxytype = 6;
pub const CURLPROXY_SOCKS5: curl_proxytype = 5;
pub const CURLPROXY_SOCKS4: curl_proxytype = 4;
pub const CURLPROXY_HTTPS: curl_proxytype = 2;
pub const CURLPROXY_HTTP_1_0: curl_proxytype = 1;
pub const CURLPROXY_HTTP: curl_proxytype = 0;
pub type curl_TimeCond = libc::c_uint;
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
    pub flags: libc::c_uint,
    pub data: *mut libc::c_char,
    pub readfunc: curl_read_callback,
    pub seekfunc: curl_seek_callback,
    pub freefunc: curl_free_callback,
    pub arg: *mut libc::c_void,
    pub fp: *mut FILE,
    pub curlheaders: *mut curl_slist,
    pub userheaders: *mut curl_slist,
    pub mimetype: *mut libc::c_char,
    pub filename: *mut libc::c_char,
    pub name: *mut libc::c_char,
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
    pub buf: [libc::c_char; 256],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mime_encoder {
    pub name: *const libc::c_char,
    pub encodefunc: Option::<
        unsafe extern "C" fn(
            *mut libc::c_char,
            size_t,
            bool,
            *mut curl_mimepart,
        ) -> size_t,
    >,
    pub sizefunc: Option::<unsafe extern "C" fn(*mut curl_mimepart) -> curl_off_t>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mime_state {
    pub state: mimestate,
    pub ptr: *mut libc::c_void,
    pub offset: curl_off_t,
}
pub type mimestate = libc::c_uint;
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
pub type curl_free_callback = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type curl_seek_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_void, curl_off_t, libc::c_int) -> libc::c_int,
>;
pub type mimekind = libc::c_uint;
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
    pub boundary: [libc::c_char; 41],
    pub state: mime_state,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_httppost {
    pub next: *mut curl_httppost,
    pub name: *mut libc::c_char,
    pub namelength: libc::c_long,
    pub contents: *mut libc::c_char,
    pub contentslength: libc::c_long,
    pub buffer: *mut libc::c_char,
    pub bufferlength: libc::c_long,
    pub contenttype: *mut libc::c_char,
    pub contentheader: *mut curl_slist,
    pub more: *mut curl_httppost,
    pub flags: libc::c_long,
    pub showfilename: *mut libc::c_char,
    pub userp: *mut libc::c_void,
    pub contentlen: curl_off_t,
}
pub type curl_hstswrite_callback = Option::<
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
    pub name: *mut libc::c_char,
    pub namelen: size_t,
    #[bitfield(name = "includeSubDomains", ty = "libc::c_uint", bits = "0..=0")]
    pub includeSubDomains: [u8; 1],
    pub expire: [libc::c_char; 18],
}
pub type CURLSTScode = libc::c_uint;
pub const CURLSTS_FAIL: CURLSTScode = 2;
pub const CURLSTS_DONE: CURLSTScode = 1;
pub const CURLSTS_OK: CURLSTScode = 0;
pub type curl_hstsread_callback = Option::<
    unsafe extern "C" fn(
        *mut CURL,
        *mut curl_hstsentry,
        *mut libc::c_void,
    ) -> CURLSTScode,
>;
pub type curl_conv_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_char, size_t) -> CURLcode,
>;
pub type curl_closesocket_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_void, curl_socket_t) -> libc::c_int,
>;
pub type curl_socket_t = libc::c_int;
pub type curl_opensocket_callback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        curlsocktype,
        *mut curl_sockaddr,
    ) -> curl_socket_t,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_sockaddr {
    pub family: libc::c_int,
    pub socktype: libc::c_int,
    pub protocol: libc::c_int,
    pub addrlen: libc::c_uint,
    pub addr: sockaddr,
}
pub type curlsocktype = libc::c_uint;
pub const CURLSOCKTYPE_LAST: curlsocktype = 2;
pub const CURLSOCKTYPE_ACCEPT: curlsocktype = 1;
pub const CURLSOCKTYPE_IPCXN: curlsocktype = 0;
pub type curl_sockopt_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_void, curl_socket_t, curlsocktype) -> libc::c_int,
>;
pub type curl_ioctl_callback = Option::<
    unsafe extern "C" fn(*mut CURL, libc::c_int, *mut libc::c_void) -> curlioerr,
>;
pub type curlioerr = libc::c_uint;
pub const CURLIOE_LAST: curlioerr = 3;
pub const CURLIOE_FAILRESTART: curlioerr = 2;
pub const CURLIOE_UNKNOWNCMD: curlioerr = 1;
pub const CURLIOE_OK: curlioerr = 0;
pub type curl_debug_callback = Option::<
    unsafe extern "C" fn(
        *mut CURL,
        curl_infotype,
        *mut libc::c_char,
        size_t,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
pub type curl_infotype = libc::c_uint;
pub const CURLINFO_END: curl_infotype = 7;
pub const CURLINFO_SSL_DATA_OUT: curl_infotype = 6;
pub const CURLINFO_SSL_DATA_IN: curl_infotype = 5;
pub const CURLINFO_DATA_OUT: curl_infotype = 4;
pub const CURLINFO_DATA_IN: curl_infotype = 3;
pub const CURLINFO_HEADER_OUT: curl_infotype = 2;
pub const CURLINFO_HEADER_IN: curl_infotype = 1;
pub const CURLINFO_TEXT: curl_infotype = 0;
pub type curl_xferinfo_callback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        curl_off_t,
        curl_off_t,
        curl_off_t,
        curl_off_t,
    ) -> libc::c_int,
>;
pub type curl_progress_callback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        libc::c_double,
        libc::c_double,
        libc::c_double,
        libc::c_double,
    ) -> libc::c_int,
>;
pub type curl_write_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_char, size_t, size_t, *mut libc::c_void) -> size_t,
>;
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
    pub headerline: libc::c_int,
    pub str_0: *mut libc::c_char,
    pub offset: curl_off_t,
    pub httpcode: libc::c_int,
    pub keepon: libc::c_int,
    pub start100: curltime,
    pub exp100: expect100,
    pub upgr101: upgrade101,
    pub writer_stack: *mut contenc_writer,
    pub timeofdoc: time_t,
    pub bodywrites: libc::c_long,
    pub location: *mut libc::c_char,
    pub newurl: *mut libc::c_char,
    pub upload_present: ssize_t,
    pub upload_fromhere: *mut libc::c_char,
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
    pub header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk: [u8; 2],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 6],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dohdata {
    pub headers: *mut curl_slist,
    pub probe: [dnsprobe; 2],
    pub pending: libc::c_uint,
    pub port: libc::c_int,
    pub host: *const libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dnsprobe {
    pub easy: *mut CURL,
    pub dnstype: libc::c_int,
    pub dohbuffer: [libc::c_uchar; 512],
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
    pub path: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SMTP {
    pub transfer: curl_pp_transfer,
    pub custom: *mut libc::c_char,
    pub rcpt: *mut curl_slist,
    pub rcpt_had_ok: bool,
    pub trailing_crlf: bool,
    pub rcpt_last_error: libc::c_int,
    pub eob: size_t,
}
pub type curl_pp_transfer = libc::c_uint;
pub const PPTRANSFER_NONE: curl_pp_transfer = 2;
pub const PPTRANSFER_INFO: curl_pp_transfer = 1;
pub const PPTRANSFER_BODY: curl_pp_transfer = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct RTSP {
    pub http_wrapper: HTTP,
    pub CSeq_sent: libc::c_long,
    pub CSeq_recv: libc::c_long,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HTTP {
    pub sendit: *mut curl_mimepart,
    pub postsize: curl_off_t,
    pub postdata: *const libc::c_char,
    pub p_pragma: *const libc::c_char,
    pub form: curl_mimepart,
    pub backup: back,
    pub sending: C2RustUnnamed_0,
    pub send_buffer: dynbuf,
    pub stream_id: int32_t,
    pub bodystarted: bool,
    pub header_recvbuf: dynbuf,
    pub nread_header_recvbuf: size_t,
    pub trailer_recvbuf: dynbuf,
    pub status_code: libc::c_int,
    pub pausedata: *const uint8_t,
    pub pauselen: size_t,
    pub close_handled: bool,
    pub push_headers: *mut *mut libc::c_char,
    pub push_headers_used: size_t,
    pub push_headers_alloc: size_t,
    pub error: uint32_t,
    pub closed: bool,
    pub mem: *mut libc::c_char,
    pub len: size_t,
    pub memlen: size_t,
    pub upload_mem: *const uint8_t,
    pub upload_len: size_t,
    pub upload_left: curl_off_t,
}
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type C2RustUnnamed_0 = libc::c_uint;
pub const HTTPSEND_BODY: C2RustUnnamed_0 = 2;
pub const HTTPSEND_REQUEST: C2RustUnnamed_0 = 1;
pub const HTTPSEND_NADA: C2RustUnnamed_0 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct back {
    pub fread_func: curl_read_callback,
    pub fread_in: *mut libc::c_void,
    pub postdata: *const libc::c_char,
    pub postsize: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct POP3 {
    pub transfer: curl_pp_transfer,
    pub id: *mut libc::c_char,
    pub custom: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct MQTT {
    pub sendleftovers: *mut libc::c_char,
    pub nsend: size_t,
    pub npacket: size_t,
    pub firstbyte: libc::c_uchar,
    pub remaining_length: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct IMAP {
    pub transfer: curl_pp_transfer,
    pub mailbox: *mut libc::c_char,
    pub uidvalidity: *mut libc::c_char,
    pub uid: *mut libc::c_char,
    pub mindex: *mut libc::c_char,
    pub section: *mut libc::c_char,
    pub partial: *mut libc::c_char,
    pub query: *mut libc::c_char,
    pub custom: *mut libc::c_char,
    pub custom_params: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct FTP {
    pub path: *mut libc::c_char,
    pub pathalloc: *mut libc::c_char,
    pub transfer: curl_pp_transfer,
    pub downloadsize: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct FILEPROTO {
    pub path: *mut libc::c_char,
    pub freepath: *mut libc::c_char,
    pub fd: libc::c_int,
}
pub type upgrade101 = libc::c_uint;
pub const UPGR101_WORKING: upgrade101 = 3;
pub const UPGR101_RECEIVED: upgrade101 = 2;
pub const UPGR101_REQUESTED: upgrade101 = 1;
pub const UPGR101_INIT: upgrade101 = 0;
pub type expect100 = libc::c_uint;
pub const EXP100_FAILED: expect100 = 3;
pub const EXP100_SENDING_REQUEST: expect100 = 2;
pub const EXP100_AWAITING_CONTINUE: expect100 = 1;
pub const EXP100_SEND_DATA: expect100 = 0;
pub type C2RustUnnamed_1 = libc::c_uint;
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
pub struct Curl_share {
    pub magic: libc::c_uint,
    pub specifier: libc::c_uint,
    pub dirty: libc::c_uint,
    pub lockfunc: curl_lock_function,
    pub unlockfunc: curl_unlock_function,
    pub clientdata: *mut libc::c_void,
    pub conn_cache: conncache,
    pub hostcache: Curl_hash,
    pub cookies: *mut CookieInfo,
    pub psl: PslCache,
    pub sslsession: *mut Curl_ssl_session,
    pub max_ssl_sessions: size_t,
    pub sessionage: libc::c_long,
}
pub type curl_unlock_function = Option::<
    unsafe extern "C" fn(*mut CURL, curl_lock_data, *mut libc::c_void) -> (),
>;
pub type curl_lock_data = libc::c_uint;
pub const CURL_LOCK_DATA_LAST: curl_lock_data = 7;
pub const CURL_LOCK_DATA_PSL: curl_lock_data = 6;
pub const CURL_LOCK_DATA_CONNECT: curl_lock_data = 5;
pub const CURL_LOCK_DATA_SSL_SESSION: curl_lock_data = 4;
pub const CURL_LOCK_DATA_DNS: curl_lock_data = 3;
pub const CURL_LOCK_DATA_COOKIE: curl_lock_data = 2;
pub const CURL_LOCK_DATA_SHARE: curl_lock_data = 1;
pub const CURL_LOCK_DATA_NONE: curl_lock_data = 0;
pub type curl_lock_function = Option::<
    unsafe extern "C" fn(
        *mut CURL,
        curl_lock_data,
        curl_lock_access,
        *mut libc::c_void,
    ) -> (),
>;
pub type curl_lock_access = libc::c_uint;
pub const CURL_LOCK_ACCESS_LAST: curl_lock_access = 3;
pub const CURL_LOCK_ACCESS_SINGLE: curl_lock_access = 2;
pub const CURL_LOCK_ACCESS_SHARED: curl_lock_access = 1;
pub const CURL_LOCK_ACCESS_NONE: curl_lock_access = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_multi {
    pub magic: libc::c_uint,
    pub easyp: *mut Curl_easy,
    pub easylp: *mut Curl_easy,
    pub num_easy: libc::c_int,
    pub num_alive: libc::c_int,
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
    pub maxconnects: libc::c_long,
    pub max_host_connections: libc::c_long,
    pub max_total_connections: libc::c_long,
    pub timer_cb: curl_multi_timer_callback,
    pub timer_userp: *mut libc::c_void,
    pub timer_lastcall: curltime,
    pub max_concurrent_streams: libc::c_uint,
    pub wakeup_pair: [curl_socket_t; 2],
    pub multiplexing: bool,
    pub recheckstate: bool,
    pub in_callback: bool,
    pub ipv6_works: bool,
    pub ssl_seeded: bool,
}
pub type curl_multi_timer_callback = Option::<
    unsafe extern "C" fn(*mut CURLM, libc::c_long, *mut libc::c_void) -> libc::c_int,
>;
pub type CURLM = Curl_multi;
pub type curl_push_callback = Option::<
    unsafe extern "C" fn(
        *mut CURL,
        *mut CURL,
        size_t,
        *mut curl_pushheaders,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
pub type curl_socket_callback = Option::<
    unsafe extern "C" fn(
        *mut CURL,
        curl_socket_t,
        libc::c_int,
        *mut libc::c_void,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Names {
    pub hostcache: *mut Curl_hash,
    pub hostcachetype: C2RustUnnamed_2,
}
pub type C2RustUnnamed_2 = libc::c_uint;
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
pub type CURLMSG = libc::c_uint;
pub const CURLMSG_LAST: CURLMSG = 2;
pub const CURLMSG_DONE: CURLMSG = 1;
pub const CURLMSG_NONE: CURLMSG = 0;
pub type CURLMstate = libc::c_uint;
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
    pub connection_id: libc::c_long,
    pub dns_entry: *mut Curl_dns_entry,
    pub ip_addr: *mut Curl_addrinfo,
    pub tempaddr: [*mut Curl_addrinfo; 2],
    pub scope_id: libc::c_uint,
    pub transport: C2RustUnnamed_5,
    pub host: hostname,
    pub hostname_resolve: *mut libc::c_char,
    pub secondaryhostname: *mut libc::c_char,
    pub conn_to_host: hostname,
    pub socks_proxy: proxy_info,
    pub http_proxy: proxy_info,
    pub port: libc::c_int,
    pub remote_port: libc::c_int,
    pub conn_to_port: libc::c_int,
    pub secondary_port: libc::c_ushort,
    pub primary_ip: [libc::c_char; 46],
    pub ip_version: libc::c_uchar,
    pub user: *mut libc::c_char,
    pub passwd: *mut libc::c_char,
    pub options: *mut libc::c_char,
    pub sasl_authzid: *mut libc::c_char,
    pub httpversion: libc::c_uchar,
    pub now: curltime,
    pub created: curltime,
    pub lastused: curltime,
    pub sock: [curl_socket_t; 2],
    pub tempsock: [curl_socket_t; 2],
    pub tempfamily: [libc::c_int; 2],
    pub recv: [Option::<Curl_recv>; 2],
    pub send: [Option::<Curl_send>; 2],
    pub ssl: [ssl_connect_data; 2],
    pub proxy_ssl: [ssl_connect_data; 2],
    pub ssl_extra: *mut libc::c_void,
    pub ssl_config: ssl_primary_config,
    pub proxy_ssl_config: ssl_primary_config,
    pub bits: ConnectBits,
    pub num_addr: libc::c_int,
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
    pub unix_domain_socket: *mut libc::c_char,
    pub localdev: *mut libc::c_char,
    pub localportrange: libc::c_int,
    pub cselect_bits: libc::c_int,
    pub waitfor: libc::c_int,
    pub negnpn: libc::c_int,
    pub localport: libc::c_ushort,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct connectbundle {
    pub multiuse: libc::c_int,
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
    pub packetid: libc::c_uint,
}
pub type mqttstate = libc::c_uint;
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
    pub user: *mut libc::c_char,
    pub domain: *mut libc::c_char,
    pub share: *mut libc::c_char,
    pub challenge: [libc::c_uchar; 8],
    pub session_key: libc::c_uint,
    pub uid: libc::c_ushort,
    pub recv_buf: *mut libc::c_char,
    pub upload_size: size_t,
    pub send_size: size_t,
    pub sent: size_t,
    pub got: size_t,
}
pub type smb_conn_state = libc::c_uint;
pub const SMB_CONNECTED: smb_conn_state = 4;
pub const SMB_SETUP: smb_conn_state = 3;
pub const SMB_NEGOTIATE: smb_conn_state = 2;
pub const SMB_CONNECTING: smb_conn_state = 1;
pub const SMB_NOT_CONNECTED: smb_conn_state = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rtsp_conn {
    pub rtp_buf: *mut libc::c_char,
    pub rtp_bufsize: ssize_t,
    pub rtp_channel: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct smtp_conn {
    pub pp: pingpong,
    pub state: smtpstate,
    pub ssldone: bool,
    pub domain: *mut libc::c_char,
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
    pub authmechs: libc::c_ushort,
    pub prefmech: libc::c_ushort,
    pub authused: libc::c_ushort,
    pub resetprefs: bool,
    pub mutual_auth: bool,
    pub force_ir: bool,
}
pub type saslstate = libc::c_uint;
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
    pub service: *const libc::c_char,
    pub contcode: libc::c_int,
    pub finalcode: libc::c_int,
    pub maxirlen: size_t,
    pub sendauth: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            *const libc::c_char,
            *const libc::c_char,
        ) -> CURLcode,
    >,
    pub sendcont: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            *const libc::c_char,
        ) -> CURLcode,
    >,
    pub getmessage: Option::<
        unsafe extern "C" fn(*mut libc::c_char, *mut *mut libc::c_char) -> (),
    >,
}
pub type smtpstate = libc::c_uint;
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
    pub cache: *mut libc::c_char,
    pub cache_size: size_t,
    pub nread_resp: size_t,
    pub linestart_resp: *mut libc::c_char,
    pub pending_resp: bool,
    pub sendthis: *mut libc::c_char,
    pub sendleft: size_t,
    pub sendsize: size_t,
    pub response: curltime,
    pub response_time: timediff_t,
    pub sendbuf: dynbuf,
    pub statemachine: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
    >,
    pub endofresp: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            *mut libc::c_char,
            size_t,
            *mut libc::c_int,
        ) -> bool,
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
    pub authtypes: libc::c_uint,
    pub preftype: libc::c_uint,
    pub apoptimestamp: *mut libc::c_char,
}
pub type pop3state = libc::c_uint;
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
    pub preftype: libc::c_uint,
    pub cmdid: libc::c_uint,
    pub resptag: [libc::c_char; 5],
    pub tls_supported: bool,
    pub login_disabled: bool,
    pub ir_supported: bool,
    pub mailbox: *mut libc::c_char,
    pub mailbox_uidvalidity: *mut libc::c_char,
    pub dyn_0: dynbuf,
}
pub type imapstate = libc::c_uint;
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
    pub authlist: *const libc::c_char,
    pub passphrase: *const libc::c_char,
    pub rsa_pub: *mut libc::c_char,
    pub rsa: *mut libc::c_char,
    pub authed: bool,
    pub acceptfail: bool,
    pub state: sshstate,
    pub nextstate: sshstate,
    pub actualcode: CURLcode,
    pub quote_item: *mut curl_slist,
    pub quote_path1: *mut libc::c_char,
    pub quote_path2: *mut libc::c_char,
    pub homedir: *mut libc::c_char,
    pub readdir_line: *mut libc::c_char,
    pub secondCreateDirs: libc::c_int,
    pub orig_waitfor: libc::c_int,
    pub slash_pos: *mut libc::c_char,
}
pub type sshstate = libc::c_int;
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
    pub send_underlying: Option::<Curl_send>,
    pub recv_underlying: Option::<Curl_recv>,
    pub inbuf: *mut libc::c_char,
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
pub type Curl_recv = unsafe extern "C" fn(
    *mut Curl_easy,
    libc::c_int,
    *mut libc::c_char,
    size_t,
    *mut CURLcode,
) -> ssize_t;
pub type Curl_send = unsafe extern "C" fn(
    *mut Curl_easy,
    libc::c_int,
    *const libc::c_void,
    size_t,
    *mut CURLcode,
) -> ssize_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ftp_conn {
    pub pp: pingpong,
    pub entrypath: *mut libc::c_char,
    pub file: *mut libc::c_char,
    pub dirs: *mut *mut libc::c_char,
    pub dirdepth: libc::c_int,
    pub dont_check: bool,
    pub ctl_valid: bool,
    pub cwddone: bool,
    pub cwdcount: libc::c_int,
    pub cwdfail: bool,
    pub wait_data_conn: bool,
    pub newport: libc::c_ushort,
    pub newhost: *mut libc::c_char,
    pub prevpath: *mut libc::c_char,
    pub transfertype: libc::c_char,
    pub count1: libc::c_int,
    pub count2: libc::c_int,
    pub count3: libc::c_int,
    pub state: ftpstate,
    pub state_saved: ftpstate,
    pub retr_size_saved: curl_off_t,
    pub server_os: *mut libc::c_char,
    pub known_filesize: curl_off_t,
}
pub type ftpstate = libc::c_uint;
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
    pub flags: libc::c_uint,
    pub nonce: [libc::c_uchar; 8],
    pub target_info_len: libc::c_uint,
    pub target_info: *mut libc::c_void,
    pub ntlm_auth_hlpr_socket: curl_socket_t,
    pub ntlm_auth_hlpr_pid: pid_t,
    pub challenge: *mut libc::c_char,
    pub response: *mut libc::c_char,
}
pub type curlntlm = libc::c_uint;
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
    pub scheme: *const libc::c_char,
    pub setup_connection: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
    >,
    pub do_it: Option::<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
    pub done: Option::<unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode>,
    pub do_more: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut libc::c_int) -> CURLcode,
    >,
    pub connect_it: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
    >,
    pub connecting: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
    >,
    pub doing: Option::<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
    pub proto_getsock: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            *mut curl_socket_t,
        ) -> libc::c_int,
    >,
    pub doing_getsock: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            *mut curl_socket_t,
        ) -> libc::c_int,
    >,
    pub domore_getsock: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            *mut curl_socket_t,
        ) -> libc::c_int,
    >,
    pub perform_getsock: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            *mut curl_socket_t,
        ) -> libc::c_int,
    >,
    pub disconnect: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, bool) -> CURLcode,
    >,
    pub readwrite: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            *mut ssize_t,
            *mut bool,
        ) -> CURLcode,
    >,
    pub connection_check: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            libc::c_uint,
        ) -> libc::c_uint,
    >,
    pub attach: Option::<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> ()>,
    pub defport: libc::c_int,
    pub protocol: libc::c_uint,
    pub family: libc::c_uint,
    pub flags: libc::c_uint,
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
    pub httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect: [u8; 5],
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
pub type ssl_connect_state = libc::c_uint;
pub const ssl_connect_done: ssl_connect_state = 5;
pub const ssl_connect_3: ssl_connect_state = 4;
pub const ssl_connect_2_writing: ssl_connect_state = 3;
pub const ssl_connect_2_reading: ssl_connect_state = 2;
pub const ssl_connect_2: ssl_connect_state = 1;
pub const ssl_connect_1: ssl_connect_state = 0;
pub type ssl_connection_state = libc::c_uint;
pub const ssl_connection_complete: ssl_connection_state = 2;
pub const ssl_connection_negotiating: ssl_connection_state = 1;
pub const ssl_connection_none: ssl_connection_state = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct proxy_info {
    pub host: hostname,
    pub port: libc::c_long,
    pub proxytype: curl_proxytype,
    pub user: *mut libc::c_char,
    pub passwd: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostname {
    pub rawalloc: *mut libc::c_char,
    pub encalloc: *mut libc::c_char,
    pub name: *mut libc::c_char,
    pub dispname: *const libc::c_char,
}
pub type C2RustUnnamed_5 = libc::c_uint;
pub const TRNSPRT_QUIC: C2RustUnnamed_5 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_5 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_5 = 3;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_chunker {
    pub datasize: curl_off_t,
    pub state: ChunkyState,
    pub hexindex: libc::c_uchar,
    pub hexbuffer: [libc::c_char; 17],
}
pub type ChunkyState = libc::c_uint;
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
    pub outp: *mut libc::c_uchar,
}
pub type connect_t = libc::c_uint;
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
pub type curl_malloc_callback = Option::<
    unsafe extern "C" fn(size_t) -> *mut libc::c_void,
>;
pub type curl_realloc_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void,
>;
pub type curl_strdup_callback = Option::<
    unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
>;
pub type curl_calloc_callback = Option::<
    unsafe extern "C" fn(size_t, size_t) -> *mut libc::c_void,
>;
pub type CURLINFO = libc::c_uint;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sigpipe_ignore {
    pub old_pipe_act: sigaction,
    pub no_signal: bool,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sigaction {
    pub __sigaction_handler: C2RustUnnamed_6,
    pub sa_mask: __sigset_t,
    pub sa_flags: libc::c_int,
    pub sa_restorer: Option::<unsafe extern "C" fn() -> ()>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_6 {
    pub sa_handler: __sighandler_t,
    pub sa_sigaction: Option::<
        unsafe extern "C" fn(libc::c_int, *mut siginfo_t, *mut libc::c_void) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct siginfo_t {
    pub si_signo: libc::c_int,
    pub si_errno: libc::c_int,
    pub si_code: libc::c_int,
    pub __pad0: libc::c_int,
    pub _sifields: C2RustUnnamed_7,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_7 {
    pub _pad: [libc::c_int; 28],
    pub _kill: C2RustUnnamed_16,
    pub _timer: C2RustUnnamed_15,
    pub _rt: C2RustUnnamed_14,
    pub _sigchld: C2RustUnnamed_13,
    pub _sigfault: C2RustUnnamed_10,
    pub _sigpoll: C2RustUnnamed_9,
    pub _sigsys: C2RustUnnamed_8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_8 {
    pub _call_addr: *mut libc::c_void,
    pub _syscall: libc::c_int,
    pub _arch: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_9 {
    pub si_band: libc::c_long,
    pub si_fd: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_10 {
    pub si_addr: *mut libc::c_void,
    pub si_addr_lsb: libc::c_short,
    pub _bounds: C2RustUnnamed_11,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_11 {
    pub _addr_bnd: C2RustUnnamed_12,
    pub _pkey: __uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_12 {
    pub _lower: *mut libc::c_void,
    pub _upper: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_13 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
    pub si_status: libc::c_int,
    pub si_utime: __clock_t,
    pub si_stime: __clock_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_14 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
    pub si_sigval: __sigval_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_15 {
    pub si_tid: libc::c_int,
    pub si_overrun: libc::c_int,
    pub si_sigval: __sigval_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_16 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
}
pub type __sighandler_t = Option::<unsafe extern "C" fn(libc::c_int) -> ()>;
pub type CURLMcode = libc::c_int;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_waitfd {
    pub fd: curl_socket_t,
    pub events: libc::c_short,
    pub revents: libc::c_short,
}
pub type CURLMoption = libc::c_uint;
pub const CURLMOPT_LASTENTRY: CURLMoption = 17;
pub const CURLMOPT_MAX_CONCURRENT_STREAMS: CURLMoption = 16;
pub const CURLMOPT_PUSHDATA: CURLMoption = 10015;
pub const CURLMOPT_PUSHFUNCTION: CURLMoption = 20014;
pub const CURLMOPT_MAX_TOTAL_CONNECTIONS: CURLMoption = 13;
pub const CURLMOPT_PIPELINING_SERVER_BL: CURLMoption = 10012;
pub const CURLMOPT_PIPELINING_SITE_BL: CURLMoption = 10011;
pub const CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE: CURLMoption = 30010;
pub const CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE: CURLMoption = 30009;
pub const CURLMOPT_MAX_PIPELINE_LENGTH: CURLMoption = 8;
pub const CURLMOPT_MAX_HOST_CONNECTIONS: CURLMoption = 7;
pub const CURLMOPT_MAXCONNECTS: CURLMoption = 6;
pub const CURLMOPT_TIMERDATA: CURLMoption = 10005;
pub const CURLMOPT_TIMERFUNCTION: CURLMoption = 20004;
pub const CURLMOPT_PIPELINING: CURLMoption = 3;
pub const CURLMOPT_SOCKETDATA: CURLMoption = 10002;
pub const CURLMOPT_SOCKETFUNCTION: CURLMoption = 20001;
pub const STRING_HSTS: dupstring = 70;
pub const STRING_SSL_ENGINE: dupstring = 43;
pub type dupstring = libc::c_uint;
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
pub type dupblob = libc::c_uint;
pub const BLOB_LAST: dupblob = 8;
pub const BLOB_CAINFO_PROXY: dupblob = 7;
pub const BLOB_CAINFO: dupblob = 6;
pub const BLOB_SSL_ISSUERCERT_PROXY: dupblob = 5;
pub const BLOB_SSL_ISSUERCERT: dupblob = 4;
pub const BLOB_KEY_PROXY: dupblob = 3;
pub const BLOB_KEY: dupblob = 2;
pub const BLOB_CERT_PROXY: dupblob = 1;
pub const BLOB_CERT: dupblob = 0;
unsafe extern "C" fn sigpipe_ignore(
    mut data: *mut Curl_easy,
    mut ig: *mut sigpipe_ignore,
) {
    (*ig).no_signal = ((*data).set).no_signal() != 0;
    if ((*data).set).no_signal() == 0 {
        let mut action: sigaction = sigaction {
            __sigaction_handler: C2RustUnnamed_6 {
                sa_handler: None,
            },
            sa_mask: __sigset_t { __val: [0; 16] },
            sa_flags: 0,
            sa_restorer: None,
        };
        memset(
            &mut (*ig).old_pipe_act as *mut sigaction as *mut libc::c_void,
            0 as libc::c_int,
            ::std::mem::size_of::<sigaction>() as libc::c_ulong,
        );
        sigaction(13 as libc::c_int, 0 as *const sigaction, &mut (*ig).old_pipe_act);
        action = (*ig).old_pipe_act;
        action
            .__sigaction_handler
            .sa_handler = ::std::mem::transmute::<
            libc::intptr_t,
            __sighandler_t,
        >(1 as libc::c_int as libc::intptr_t);
        sigaction(13 as libc::c_int, &mut action, 0 as *mut sigaction);
    }
}
unsafe extern "C" fn sigpipe_restore(mut ig: *mut sigpipe_ignore) {
    if !(*ig).no_signal {
        sigaction(13 as libc::c_int, &mut (*ig).old_pipe_act, 0 as *mut sigaction);
    }
}
static mut initialized: libc::c_uint = 0;
static mut init_flags: libc::c_long = 0;
#[no_mangle]
pub static mut Curl_cmalloc: curl_malloc_callback = unsafe {
    ::std::mem::transmute::<
        Option::<unsafe extern "C" fn(libc::c_ulong) -> *mut libc::c_void>,
        curl_malloc_callback,
    >(Some(malloc as unsafe extern "C" fn(libc::c_ulong) -> *mut libc::c_void))
};
#[no_mangle]
pub static mut Curl_cfree: curl_free_callback = unsafe {
    ::std::mem::transmute::<
        Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
        curl_free_callback,
    >(Some(free as unsafe extern "C" fn(*mut libc::c_void) -> ()))
};
#[no_mangle]
pub static mut Curl_crealloc: curl_realloc_callback = unsafe {
    ::std::mem::transmute::<
        Option::<
            unsafe extern "C" fn(*mut libc::c_void, libc::c_ulong) -> *mut libc::c_void,
        >,
        curl_realloc_callback,
    >(
        Some(
            realloc
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    libc::c_ulong,
                ) -> *mut libc::c_void,
        ),
    )
};
#[no_mangle]
pub static mut Curl_cstrdup: curl_strdup_callback = unsafe {
    ::std::mem::transmute::<
        Option::<unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char>,
        curl_strdup_callback,
    >(Some(strdup as unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char))
};
#[no_mangle]
pub static mut Curl_ccalloc: curl_calloc_callback = unsafe {
    ::std::mem::transmute::<
        Option::<
            unsafe extern "C" fn(libc::c_ulong, libc::c_ulong) -> *mut libc::c_void,
        >,
        curl_calloc_callback,
    >(
        Some(
            calloc
                as unsafe extern "C" fn(
                    libc::c_ulong,
                    libc::c_ulong,
                ) -> *mut libc::c_void,
        ),
    )
};
unsafe extern "C" fn global_init(
    mut flags: libc::c_long,
    mut memoryfuncs: bool,
) -> CURLcode {
    let fresh0 = initialized;
    initialized = initialized.wrapping_add(1);
    if fresh0 != 0 {
        return CURLE_OK;
    }
    if memoryfuncs {
        Curl_cmalloc = ::std::mem::transmute::<
            Option::<unsafe extern "C" fn(libc::c_ulong) -> *mut libc::c_void>,
            curl_malloc_callback,
        >(Some(malloc as unsafe extern "C" fn(libc::c_ulong) -> *mut libc::c_void));
        Curl_cfree = ::std::mem::transmute::<
            Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
            curl_free_callback,
        >(Some(free as unsafe extern "C" fn(*mut libc::c_void) -> ()));
        Curl_crealloc = ::std::mem::transmute::<
            Option::<
                unsafe extern "C" fn(
                    *mut libc::c_void,
                    libc::c_ulong,
                ) -> *mut libc::c_void,
            >,
            curl_realloc_callback,
        >(
            Some(
                realloc
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        libc::c_ulong,
                    ) -> *mut libc::c_void,
            ),
        );
        Curl_cstrdup = ::std::mem::transmute::<
            Option::<unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char>,
            curl_strdup_callback,
        >(
            Some(
                strdup as unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
            ),
        );
        Curl_ccalloc = ::std::mem::transmute::<
            Option::<
                unsafe extern "C" fn(libc::c_ulong, libc::c_ulong) -> *mut libc::c_void,
            >,
            curl_calloc_callback,
        >(
            Some(
                calloc
                    as unsafe extern "C" fn(
                        libc::c_ulong,
                        libc::c_ulong,
                    ) -> *mut libc::c_void,
            ),
        );
    }
    if !(Curl_ssl_init() == 0) {
        if !(Curl_resolver_global_init() != 0) {
            init_flags = flags;
            return CURLE_OK;
        }
    }
    initialized = initialized.wrapping_sub(1);
    return CURLE_FAILED_INIT;
}
#[no_mangle]
pub unsafe extern "C" fn curl_global_init(mut flags: libc::c_long) -> CURLcode {
    return global_init(flags, 1 as libc::c_int != 0);
}
#[no_mangle]
pub unsafe extern "C" fn curl_global_init_mem(
    mut flags: libc::c_long,
    mut m: curl_malloc_callback,
    mut f: curl_free_callback,
    mut r: curl_realloc_callback,
    mut s: curl_strdup_callback,
    mut c: curl_calloc_callback,
) -> CURLcode {
    if m.is_none() || f.is_none() || r.is_none() || s.is_none() || c.is_none() {
        return CURLE_FAILED_INIT;
    }
    if initialized != 0 {
        initialized = initialized.wrapping_add(1);
        return CURLE_OK;
    }
    Curl_cmalloc = m;
    Curl_cfree = f;
    Curl_cstrdup = s;
    Curl_crealloc = r;
    Curl_ccalloc = c;
    return global_init(flags, 0 as libc::c_int != 0);
}
#[no_mangle]
pub unsafe extern "C" fn curl_global_cleanup() {
    if initialized == 0 {
        return;
    }
    initialized = initialized.wrapping_sub(1);
    if initialized != 0 {
        return;
    }
    Curl_ssl_cleanup();
    Curl_resolver_global_cleanup();
    init_flags = 0 as libc::c_int as libc::c_long;
}
#[no_mangle]
pub unsafe extern "C" fn curl_easy_init() -> *mut CURL {
    let mut result: CURLcode = CURLE_OK;
    let mut data: *mut Curl_easy = 0 as *mut Curl_easy;
    if initialized == 0 {
        result = curl_global_init(
            ((1 as libc::c_int) << 0 as libc::c_int
                | (1 as libc::c_int) << 1 as libc::c_int) as libc::c_long,
        );
        if result as u64 != 0 {
            return 0 as *mut CURL;
        }
    }
    result = Curl_open(&mut data);
    if result as u64 != 0 {
        return 0 as *mut CURL;
    }
    return data;
}
unsafe extern "C" fn easy_transfer(mut multi: *mut Curl_multi) -> CURLcode {
    let mut done: bool = 0 as libc::c_int != 0;
    let mut mcode: CURLMcode = CURLM_OK;
    let mut result: CURLcode = CURLE_OK;
    while !done && mcode as u64 == 0 {
        let mut still_running: libc::c_int = 0 as libc::c_int;
        mcode = curl_multi_poll(
            multi,
            0 as *mut curl_waitfd,
            0 as libc::c_int as libc::c_uint,
            1000 as libc::c_int,
            0 as *mut libc::c_int,
        );
        if mcode as u64 == 0 {
            mcode = curl_multi_perform(multi, &mut still_running);
        }
        if mcode as u64 == 0 && still_running == 0 {
            let mut rc: libc::c_int = 0;
            let mut msg: *mut CURLMsg = curl_multi_info_read(multi, &mut rc);
            if !msg.is_null() {
                result = (*msg).data.result;
                done = 1 as libc::c_int != 0;
            }
        }
    }
    if mcode as u64 != 0 {
        result = (if mcode as libc::c_int == CURLM_OUT_OF_MEMORY as libc::c_int {
            CURLE_OUT_OF_MEMORY as libc::c_int
        } else {
            CURLE_BAD_FUNCTION_ARGUMENT as libc::c_int
        }) as CURLcode;
    }
    return result;
}
unsafe extern "C" fn easy_perform(
    mut data: *mut Curl_easy,
    mut events: bool,
) -> CURLcode {
    let mut multi: *mut Curl_multi = 0 as *mut Curl_multi;
    let mut mcode: CURLMcode = CURLM_OK;
    let mut result: CURLcode = CURLE_OK;
    let mut pipe_st: sigpipe_ignore = sigpipe_ignore {
        old_pipe_act: sigaction {
            __sigaction_handler: C2RustUnnamed_6 {
                sa_handler: None,
            },
            sa_mask: __sigset_t { __val: [0; 16] },
            sa_flags: 0,
            sa_restorer: None,
        },
        no_signal: false,
    };
    if data.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if !((*data).set.errorbuffer).is_null() {
        *((*data).set.errorbuffer)
            .offset(0 as libc::c_int as isize) = 0 as libc::c_int as libc::c_char;
    }
    if !((*data).multi).is_null() {
        Curl_failf(
            data,
            b"easy handle already used in multi handle\0" as *const u8
                as *const libc::c_char,
        );
        return CURLE_FAILED_INIT;
    }
    if !((*data).multi_easy).is_null() {
        multi = (*data).multi_easy;
    } else {
        multi = Curl_multi_handle(1 as libc::c_int, 3 as libc::c_int);
        if multi.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        let ref mut fresh1 = (*data).multi_easy;
        *fresh1 = multi;
    }
    if (*multi).in_callback {
        return CURLE_RECURSIVE_API_CALL;
    }
    curl_multi_setopt(multi, CURLMOPT_MAXCONNECTS, (*data).set.maxconnects);
    mcode = curl_multi_add_handle(multi, data);
    if mcode as u64 != 0 {
        curl_multi_cleanup(multi);
        let ref mut fresh2 = (*data).multi_easy;
        *fresh2 = 0 as *mut Curl_multi;
        if mcode as libc::c_int == CURLM_OUT_OF_MEMORY as libc::c_int {
            return CURLE_OUT_OF_MEMORY;
        }
        return CURLE_FAILED_INIT;
    }
    sigpipe_ignore(data, &mut pipe_st);
    result = (if events as libc::c_int != 0 {
        CURLE_NOT_BUILT_IN as libc::c_int as libc::c_uint
    } else {
        easy_transfer(multi) as libc::c_uint
    }) as CURLcode;
    curl_multi_remove_handle(multi, data);
    sigpipe_restore(&mut pipe_st);
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn curl_easy_perform(mut data: *mut Curl_easy) -> CURLcode {
    return easy_perform(data, 0 as libc::c_int != 0);
}
#[no_mangle]
pub unsafe extern "C" fn curl_easy_cleanup(mut data: *mut Curl_easy) {
    let mut pipe_st: sigpipe_ignore = sigpipe_ignore {
        old_pipe_act: sigaction {
            __sigaction_handler: C2RustUnnamed_6 {
                sa_handler: None,
            },
            sa_mask: __sigset_t { __val: [0; 16] },
            sa_flags: 0,
            sa_restorer: None,
        },
        no_signal: false,
    };
    if data.is_null() {
        return;
    }
    sigpipe_ignore(data, &mut pipe_st);
    Curl_close(&mut data);
    sigpipe_restore(&mut pipe_st);
}
#[no_mangle]
pub unsafe extern "C" fn curl_easy_getinfo(
    mut data: *mut Curl_easy,
    mut info: CURLINFO,
    mut args: ...
) -> CURLcode {
    let mut arg: ::std::ffi::VaListImpl;
    let mut paramp: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut result: CURLcode = CURLE_OK;
    arg = args.clone();
    paramp = arg.arg::<*mut libc::c_void>();
    result = Curl_getinfo(data, info, paramp);
    return result;
}
unsafe extern "C" fn dupset(
    mut dst: *mut Curl_easy,
    mut src: *mut Curl_easy,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut i: dupstring = STRING_CERT;
    let mut j: dupblob = BLOB_CERT;
    (*dst).set = (*src).set;
    Curl_mime_initpart(&mut (*dst).set.mimepost, dst);
    memset(
        ((*dst).set.str_0).as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        (STRING_LAST as libc::c_int as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<*mut libc::c_char>() as libc::c_ulong),
    );
    i = STRING_CERT;
    while (i as libc::c_uint) < STRING_LASTZEROTERMINATED as libc::c_int as libc::c_uint
    {
        result = Curl_setstropt(
            &mut *((*dst).set.str_0).as_mut_ptr().offset(i as isize),
            (*src).set.str_0[i as usize],
        );
        if result as u64 != 0 {
            return result;
        }
        i += 1;
    }
    memset(
        ((*dst).set.blobs).as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        (BLOB_LAST as libc::c_int as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<*mut curl_blob>() as libc::c_ulong),
    );
    j = BLOB_CERT;
    while (j as libc::c_uint) < BLOB_LAST as libc::c_int as libc::c_uint {
        result = Curl_setblobopt(
            &mut *((*dst).set.blobs).as_mut_ptr().offset(j as isize),
            (*src).set.blobs[j as usize],
        );
        if result as u64 != 0 {
            return result;
        }
        j += 1;
    }
    i = STRING_COPYPOSTFIELDS;
    if (*src).set.postfieldsize != 0 && !((*src).set.str_0[i as usize]).is_null() {
        let ref mut fresh3 = (*dst).set.str_0[i as usize];
        *fresh3 = Curl_memdup(
            (*src).set.str_0[i as usize] as *const libc::c_void,
            curlx_sotouz((*src).set.postfieldsize),
        ) as *mut libc::c_char;
        if ((*dst).set.str_0[i as usize]).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        let ref mut fresh4 = (*dst).set.postfields;
        *fresh4 = (*dst).set.str_0[i as usize] as *mut libc::c_void;
    }
    result = Curl_mime_duppart(&mut (*dst).set.mimepost, &mut (*src).set.mimepost);
    if !((*src).set.resolve).is_null() {
        let ref mut fresh5 = (*dst).state.resolve;
        *fresh5 = (*dst).set.resolve;
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn curl_easy_duphandle(mut data: *mut Curl_easy) -> *mut CURL {
    let mut current_block: u64;
    let mut outcurl: *mut Curl_easy = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(
        1 as libc::c_int as size_t,
        ::std::mem::size_of::<Curl_easy>() as libc::c_ulong,
    ) as *mut Curl_easy;
    if !outcurl.is_null() {
        (*outcurl).set.buffer_size = (*data).set.buffer_size;
        if !(dupset(outcurl, data) as u64 != 0) {
            Curl_dyn_init(
                &mut (*outcurl).state.headerb,
                (100 as libc::c_int * 1024 as libc::c_int) as size_t,
            );
            let ref mut fresh6 = (*outcurl).state.conn_cache;
            *fresh6 = 0 as *mut conncache;
            (*outcurl).state.lastconnect_id = -(1 as libc::c_int) as libc::c_long;
            (*outcurl).progress.flags = (*data).progress.flags;
            let ref mut fresh7 = (*outcurl).progress;
            (*fresh7).set_callback(((*data).progress).callback());
            if !((*data).cookies).is_null() {
                let ref mut fresh8 = (*outcurl).cookies;
                *fresh8 = Curl_cookie_init(
                    data,
                    (*(*data).cookies).filename,
                    (*outcurl).cookies,
                    ((*data).set).cookiesession() != 0,
                );
                if ((*outcurl).cookies).is_null() {
                    current_block = 12715656406826180841;
                } else {
                    current_block = 17965632435239708295;
                }
            } else {
                current_block = 17965632435239708295;
            }
            match current_block {
                12715656406826180841 => {}
                _ => {
                    if !((*data).state.cookielist).is_null() {
                        let ref mut fresh9 = (*outcurl).state.cookielist;
                        *fresh9 = Curl_slist_duplicate((*data).state.cookielist);
                        if ((*outcurl).state.cookielist).is_null() {
                            current_block = 12715656406826180841;
                        } else {
                            current_block = 8236137900636309791;
                        }
                    } else {
                        current_block = 8236137900636309791;
                    }
                    match current_block {
                        12715656406826180841 => {}
                        _ => {
                            if !((*data).state.url).is_null() {
                                let ref mut fresh10 = (*outcurl).state.url;
                                *fresh10 = Curl_cstrdup
                                    .expect("non-null function pointer")((*data).state.url);
                                if ((*outcurl).state.url).is_null() {
                                    current_block = 12715656406826180841;
                                } else {
                                    let ref mut fresh11 = (*outcurl).state;
                                    (*fresh11).set_url_alloc(1 as libc::c_int as bit);
                                    current_block = 13242334135786603907;
                                }
                            } else {
                                current_block = 13242334135786603907;
                            }
                            match current_block {
                                12715656406826180841 => {}
                                _ => {
                                    if !((*data).state.referer).is_null() {
                                        let ref mut fresh12 = (*outcurl).state.referer;
                                        *fresh12 = Curl_cstrdup
                                            .expect("non-null function pointer")((*data).state.referer);
                                        if ((*outcurl).state.referer).is_null() {
                                            current_block = 12715656406826180841;
                                        } else {
                                            let ref mut fresh13 = (*outcurl).state;
                                            (*fresh13).set_referer_alloc(1 as libc::c_int as bit);
                                            current_block = 11298138898191919651;
                                        }
                                    } else {
                                        current_block = 11298138898191919651;
                                    }
                                    match current_block {
                                        12715656406826180841 => {}
                                        _ => {
                                            if !((*outcurl)
                                                .set
                                                .str_0[STRING_SSL_ENGINE as libc::c_int as usize])
                                                .is_null()
                                            {
                                                if Curl_ssl_set_engine(
                                                    outcurl,
                                                    (*outcurl)
                                                        .set
                                                        .str_0[STRING_SSL_ENGINE as libc::c_int as usize],
                                                ) as u64 != 0
                                                {
                                                    current_block = 12715656406826180841;
                                                } else {
                                                    current_block = 4068382217303356765;
                                                }
                                            } else {
                                                current_block = 4068382217303356765;
                                            }
                                            match current_block {
                                                12715656406826180841 => {}
                                                _ => {
                                                    if !((*data).hsts).is_null() {
                                                        let ref mut fresh14 = (*outcurl).hsts;
                                                        *fresh14 = Curl_hsts_init();
                                                        if ((*outcurl).hsts).is_null() {
                                                            current_block = 12715656406826180841;
                                                        } else {
                                                            if !((*outcurl)
                                                                .set
                                                                .str_0[STRING_HSTS as libc::c_int as usize])
                                                                .is_null()
                                                            {
                                                                Curl_hsts_loadfile(
                                                                    outcurl,
                                                                    (*outcurl).hsts,
                                                                    (*outcurl).set.str_0[STRING_HSTS as libc::c_int as usize],
                                                                );
                                                            }
                                                            Curl_hsts_loadcb(outcurl, (*outcurl).hsts);
                                                            current_block = 18377268871191777778;
                                                        }
                                                    } else {
                                                        current_block = 18377268871191777778;
                                                    }
                                                    match current_block {
                                                        12715656406826180841 => {}
                                                        _ => {
                                                            if !(Curl_resolver_duphandle(
                                                                outcurl,
                                                                &mut (*outcurl).state.async_0.resolver,
                                                                (*data).state.async_0.resolver,
                                                            ) as u64 != 0)
                                                            {
                                                                Curl_initinfo(outcurl);
                                                                (*outcurl).magic = 0xc0dedbad as libc::c_uint;
                                                                return outcurl;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if !outcurl.is_null() {
        curl_slist_free_all((*outcurl).state.cookielist);
        let ref mut fresh15 = (*outcurl).state.cookielist;
        *fresh15 = 0 as *mut curl_slist;
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*outcurl).state.buffer as *mut libc::c_void);
        let ref mut fresh16 = (*outcurl).state.buffer;
        *fresh16 = 0 as *mut libc::c_char;
        Curl_dyn_free(&mut (*outcurl).state.headerb);
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*outcurl).state.url as *mut libc::c_void);
        let ref mut fresh17 = (*outcurl).state.url;
        *fresh17 = 0 as *mut libc::c_char;
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*outcurl).state.referer as *mut libc::c_void);
        let ref mut fresh18 = (*outcurl).state.referer;
        *fresh18 = 0 as *mut libc::c_char;
        Curl_altsvc_cleanup(&mut (*outcurl).asi);
        Curl_hsts_cleanup(&mut (*outcurl).hsts);
        Curl_freeset(outcurl);
        Curl_cfree.expect("non-null function pointer")(outcurl as *mut libc::c_void);
    }
    return 0 as *mut CURL;
}
#[no_mangle]
pub unsafe extern "C" fn curl_easy_reset(mut data: *mut Curl_easy) {
    Curl_free_request_state(data);
    Curl_freeset(data);
    memset(
        &mut (*data).set as *mut UserDefined as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<UserDefined>() as libc::c_ulong,
    );
    Curl_init_userdefined(data);
    memset(
        &mut (*data).progress as *mut Progress as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<Progress>() as libc::c_ulong,
    );
    Curl_initinfo(data);
    (*data).progress.flags |= (1 as libc::c_int) << 4 as libc::c_int;
    (*data).state.current_speed = -(1 as libc::c_int) as curl_off_t;
    (*data).state.retrycount = 0 as libc::c_int;
    memset(
        &mut (*data).state.authhost as *mut auth as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<auth>() as libc::c_ulong,
    );
    memset(
        &mut (*data).state.authproxy as *mut auth as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<auth>() as libc::c_ulong,
    );
    Curl_http_auth_cleanup_digest(data);
}
#[no_mangle]
pub unsafe extern "C" fn curl_easy_pause(
    mut data: *mut Curl_easy,
    mut action: libc::c_int,
) -> CURLcode {
    let mut k: *mut SingleRequest = 0 as *mut SingleRequest;
    let mut result: CURLcode = CURLE_OK;
    let mut oldstate: libc::c_int = 0;
    let mut newstate: libc::c_int = 0;
    if !(!data.is_null() && (*data).magic == 0xc0dedbad as libc::c_uint)
        || ((*data).conn).is_null()
    {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    k = &mut (*data).req;
    oldstate = (*k).keepon
        & ((1 as libc::c_int) << 4 as libc::c_int
            | (1 as libc::c_int) << 5 as libc::c_int);
    newstate = (*k).keepon
        & !((1 as libc::c_int) << 4 as libc::c_int
            | (1 as libc::c_int) << 5 as libc::c_int)
        | (if action & (1 as libc::c_int) << 0 as libc::c_int != 0 {
            (1 as libc::c_int) << 4 as libc::c_int
        } else {
            0 as libc::c_int
        })
        | (if action & (1 as libc::c_int) << 2 as libc::c_int != 0 {
            (1 as libc::c_int) << 5 as libc::c_int
        } else {
            0 as libc::c_int
        });
    if newstate
        & ((1 as libc::c_int) << 4 as libc::c_int
            | (1 as libc::c_int) << 5 as libc::c_int) == oldstate
    {
        return CURLE_OK;
    }
    if (*k).keepon & !newstate & (1 as libc::c_int) << 5 as libc::c_int != 0
        && ((*data).mstate as libc::c_uint
            == MSTATE_PERFORMING as libc::c_int as libc::c_uint
            || (*data).mstate as libc::c_uint
                == MSTATE_RATELIMITING as libc::c_int as libc::c_uint)
        && (*data).state.fread_func
            == ::std::mem::transmute::<
                Option::<
                    unsafe extern "C" fn(
                        *mut libc::c_char,
                        size_t,
                        size_t,
                        *mut libc::c_void,
                    ) -> size_t,
                >,
                curl_read_callback,
            >(
                Some(
                    Curl_mime_read
                        as unsafe extern "C" fn(
                            *mut libc::c_char,
                            size_t,
                            size_t,
                            *mut libc::c_void,
                        ) -> size_t,
                ),
            )
    {
        Curl_mime_unpause((*data).state.in_0 as *mut curl_mimepart);
    }
    (*k).keepon = newstate;
    if newstate & (1 as libc::c_int) << 4 as libc::c_int == 0 {
        Curl_http2_stream_pause(data, 0 as libc::c_int != 0);
        if (*data).state.tempcount != 0 {
            let mut i: libc::c_uint = 0;
            let mut count: libc::c_uint = (*data).state.tempcount;
            let mut writebuf: [tempbuf; 3] = [tempbuf {
                b: dynbuf {
                    bufr: 0 as *mut libc::c_char,
                    leng: 0,
                    allc: 0,
                    toobig: 0,
                },
                type_0: 0,
            }; 3];
            i = 0 as libc::c_int as libc::c_uint;
            while i < (*data).state.tempcount {
                writebuf[i as usize] = (*data).state.tempwrite[i as usize];
                Curl_dyn_init(
                    &mut (*((*data).state.tempwrite).as_mut_ptr().offset(i as isize)).b,
                    (64 as libc::c_int * 1024 as libc::c_int * 1024 as libc::c_int)
                        as size_t,
                );
                i = i.wrapping_add(1);
            }
            (*data).state.tempcount = 0 as libc::c_int as libc::c_uint;
            i = 0 as libc::c_int as libc::c_uint;
            while i < count {
                if result as u64 == 0 {
                    result = Curl_client_write(
                        data,
                        writebuf[i as usize].type_0,
                        Curl_dyn_ptr(&mut (*writebuf.as_mut_ptr().offset(i as isize)).b),
                        Curl_dyn_len(&mut (*writebuf.as_mut_ptr().offset(i as isize)).b),
                    );
                }
                Curl_dyn_free(&mut (*writebuf.as_mut_ptr().offset(i as isize)).b);
                i = i.wrapping_add(1);
            }
            if result as u64 != 0 {
                return result;
            }
        }
    }
    if newstate
        & ((1 as libc::c_int) << 4 as libc::c_int
            | (1 as libc::c_int) << 5 as libc::c_int)
        != (1 as libc::c_int) << 4 as libc::c_int
            | (1 as libc::c_int) << 5 as libc::c_int
    {
        Curl_expire(data, 0 as libc::c_int as timediff_t, EXPIRE_RUN_NOW);
        (*data).state.keeps_speed.tv_sec = 0 as libc::c_int as time_t;
        if (*data).state.tempcount == 0 {
            (*(*data).conn).cselect_bits = 0x1 as libc::c_int | 0x2 as libc::c_int;
        }
        if !((*data).multi).is_null() {
            Curl_update_timer((*data).multi);
        }
    }
    if ((*data).state).done() == 0 {
        Curl_updatesocket(data);
    }
    return result;
}
unsafe extern "C" fn easy_connection(
    mut data: *mut Curl_easy,
    mut sfd: *mut curl_socket_t,
    mut connp: *mut *mut connectdata,
) -> CURLcode {
    if data.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if ((*data).set).connect_only() == 0 {
        Curl_failf(
            data,
            b"CONNECT_ONLY is required!\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_UNSUPPORTED_PROTOCOL;
    }
    *sfd = Curl_getconnectinfo(data, connp);
    if *sfd == -(1 as libc::c_int) {
        Curl_failf(
            data,
            b"Failed to get recent socket\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_UNSUPPORTED_PROTOCOL;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn curl_easy_recv(
    mut data: *mut Curl_easy,
    mut buffer: *mut libc::c_void,
    mut buflen: size_t,
    mut n: *mut size_t,
) -> CURLcode {
    let mut sfd: curl_socket_t = 0;
    let mut result: CURLcode = CURLE_OK;
    let mut n1: ssize_t = 0;
    let mut c: *mut connectdata = 0 as *mut connectdata;
    if Curl_is_in_callback(data) {
        return CURLE_RECURSIVE_API_CALL;
    }
    result = easy_connection(data, &mut sfd, &mut c);
    if result as u64 != 0 {
        return result;
    }
    if ((*data).conn).is_null() {
        Curl_attach_connnection(data, c);
    }
    *n = 0 as libc::c_int as size_t;
    result = Curl_read(data, sfd, buffer as *mut libc::c_char, buflen, &mut n1);
    if result as u64 != 0 {
        return result;
    }
    *n = n1 as size_t;
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn curl_easy_send(
    mut data: *mut Curl_easy,
    mut buffer: *const libc::c_void,
    mut buflen: size_t,
    mut n: *mut size_t,
) -> CURLcode {
    let mut sfd: curl_socket_t = 0;
    let mut result: CURLcode = CURLE_OK;
    let mut n1: ssize_t = 0;
    let mut c: *mut connectdata = 0 as *mut connectdata;
    let mut pipe_st: sigpipe_ignore = sigpipe_ignore {
        old_pipe_act: sigaction {
            __sigaction_handler: C2RustUnnamed_6 {
                sa_handler: None,
            },
            sa_mask: __sigset_t { __val: [0; 16] },
            sa_flags: 0,
            sa_restorer: None,
        },
        no_signal: false,
    };
    if Curl_is_in_callback(data) {
        return CURLE_RECURSIVE_API_CALL;
    }
    result = easy_connection(data, &mut sfd, &mut c);
    if result as u64 != 0 {
        return result;
    }
    if ((*data).conn).is_null() {
        Curl_attach_connnection(data, c);
    }
    *n = 0 as libc::c_int as size_t;
    sigpipe_ignore(data, &mut pipe_st);
    result = Curl_write(data, sfd, buffer, buflen, &mut n1);
    sigpipe_restore(&mut pipe_st);
    if n1 == -(1 as libc::c_int) as libc::c_long {
        return CURLE_SEND_ERROR;
    }
    if result as u64 == 0 && n1 == 0 {
        return CURLE_AGAIN;
    }
    *n = n1 as size_t;
    return result;
}
unsafe extern "C" fn conn_upkeep(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut param: *mut libc::c_void,
) -> libc::c_int {
    if ((*(*conn).handler).connection_check).is_some() {
        Curl_attach_connnection(data, conn);
        ((*(*conn).handler).connection_check)
            .expect(
                "non-null function pointer",
            )(data, conn, ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint);
        Curl_detach_connnection(data);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn upkeep(
    mut conn_cache: *mut conncache,
    mut data: *mut libc::c_void,
) -> CURLcode {
    Curl_conncache_foreach(
        data as *mut Curl_easy,
        conn_cache,
        data,
        Some(
            conn_upkeep
                as unsafe extern "C" fn(
                    *mut Curl_easy,
                    *mut connectdata,
                    *mut libc::c_void,
                ) -> libc::c_int,
        ),
    );
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn curl_easy_upkeep(mut data: *mut Curl_easy) -> CURLcode {
    if !(!data.is_null() && (*data).magic == 0xc0dedbad as libc::c_uint) {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if !((*data).multi_easy).is_null() {
        return upkeep(&mut (*(*data).multi_easy).conn_cache, data as *mut libc::c_void)
    } else {
        return CURLE_OK
    };
}
