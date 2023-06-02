use :: c2rust_bitfields;
use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type Curl_URL;
    pub type thread_data;
    pub type TELNET;
    pub type smb_request;
    pub type ldapreqinfo;
    pub type psl_ctx_st;
    pub type curl_pushheaders;
    pub type http_connect_state;
    pub type ldapconninfo;
    pub type tftp_state_data;
    pub type nghttp2_session;
    pub type Gsasl_session;
    pub type Gsasl;
    pub type ssl_backend_data;
    static mut stderr: *mut FILE;
    fn curl_strnequal(s1: *const i8, s2: *const i8, n: size_t) -> i32;
    fn curl_slist_append(_: *mut curl_slist, _: *const i8) -> *mut curl_slist;
    fn curl_slist_free_all(_: *mut curl_slist);
    fn strlen(_: *const i8) -> u64;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn fwrite(_: *const libc::c_void, _: u64, _: u64, _: *mut FILE) -> u64;
    fn fread(_: *mut libc::c_void, _: u64, _: u64, _: *mut FILE) -> u64;
    fn Curl_mime_set_subparts(
        part: *mut curl_mimepart,
        subparts: *mut curl_mime,
        take_ownership: i32,
    ) -> CURLcode;
    fn Curl_cookie_clearall(cookies: *mut CookieInfo);
    fn Curl_cookie_clearsess(cookies: *mut CookieInfo);
    fn Curl_flush_cookies(data: *mut Curl_easy, cleanup: bool);
    fn Curl_cookie_loadfiles(data: *mut Curl_easy);
    fn Curl_cookie_add(
        data: *mut Curl_easy,
        c: *mut CookieInfo,
        header: bool,
        noexpiry: bool,
        lineptr: *mut i8,
        domain: *const i8,
        path: *const i8,
        secure: bool,
    ) -> *mut Cookie;
    fn Curl_cookie_cleanup(c: *mut CookieInfo);
    fn Curl_cookie_init(
        data: *mut Curl_easy,
        file: *const i8,
        inc: *mut CookieInfo,
        newsession: bool,
    ) -> *mut CookieInfo;
    fn Curl_parse_login_details(
        login: *const i8,
        len: size_t,
        userptr: *mut *mut i8,
        passwdptr: *mut *mut i8,
        optionsptr: *mut *mut i8,
    ) -> CURLcode;
    fn Curl_all_content_encodings() -> *mut i8;
    fn Curl_strcasecompare(first: *const i8, second: *const i8) -> i32;
    fn Curl_strncasecompare(first: *const i8, second: *const i8, max: size_t) -> i32;
    fn Curl_share_lock(_: *mut Curl_easy, _: curl_lock_data, _: curl_lock_access) -> CURLSHcode;
    fn Curl_share_unlock(_: *mut Curl_easy, _: curl_lock_data) -> CURLSHcode;
    static mut Curl_ssl: *const Curl_ssl;
    fn Curl_ssl_tls13_ciphersuites() -> bool;
    fn Curl_ssl_set_engine(data: *mut Curl_easy, engine: *const i8) -> CURLcode;
    fn Curl_ssl_set_engine_default(data: *mut Curl_easy) -> CURLcode;
    fn Curl_ssl_cert_status_request() -> bool;
    fn Curl_ssl_false_start() -> bool;
    fn curlx_sltosi(slnum: i64) -> i32;
    fn curlx_sltous(slnum: i64) -> u16;
    fn Curl_http2_add_child(
        parent: *mut Curl_easy,
        child: *mut Curl_easy,
        exclusive: bool,
    ) -> CURLcode;
    fn Curl_http2_remove_child(parent: *mut Curl_easy, child: *mut Curl_easy);
    fn Curl_altsvc_init() -> *mut altsvcinfo;
    fn Curl_altsvc_load(asi: *mut altsvcinfo, file: *const i8) -> CURLcode;
    fn Curl_altsvc_ctrl(asi: *mut altsvcinfo, ctrl: i64) -> CURLcode;
    fn Curl_hsts_init() -> *mut hsts;
    fn Curl_hsts_cleanup(hp: *mut *mut hsts);
    fn Curl_hsts_loadfile(data: *mut Curl_easy, h: *mut hsts, file: *const i8) -> CURLcode;
    static mut Curl_cmalloc: curl_malloc_callback;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_cstrdup: curl_strdup_callback;
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: u32,
    pub fp_offset: u32,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
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
pub type va_list = __builtin_va_list;
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
pub struct altsvcinfo {
    pub filename: *mut i8,
    pub list: Curl_llist,
    pub flags: i64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hsts {
    pub list: Curl_llist,
    pub filename: *mut i8,
    pub flags: u32,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct contenc_writer {
    pub handler: *const content_encoding,
    pub downstream: *mut contenc_writer,
    pub params: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct content_encoding {
    pub name: *const i8,
    pub alias: *const i8,
    pub init_writer: Option<unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer) -> CURLcode>,
    pub unencode_write: Option<
        unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer, *const i8, size_t) -> CURLcode,
    >,
    pub close_writer: Option<unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer) -> ()>,
    pub paramsize: size_t,
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
pub struct Curl_share {
    pub magic: u32,
    pub specifier: u32,
    pub dirty: u32,
    pub lockfunc: curl_lock_function,
    pub unlockfunc: curl_unlock_function,
    pub clientdata: *mut libc::c_void,
    pub conn_cache: conncache,
    pub hostcache: Curl_hash,
    pub cookies: *mut CookieInfo,
    pub psl: PslCache,
    pub sslsession: *mut Curl_ssl_session,
    pub max_ssl_sessions: size_t,
    pub sessionage: i64,
}
pub type curl_unlock_function =
    Option<unsafe extern "C" fn(*mut CURL, curl_lock_data, *mut libc::c_void) -> ()>;
pub type curl_lock_data = u32;
pub const CURL_LOCK_DATA_LAST: curl_lock_data = 7;
pub const CURL_LOCK_DATA_PSL: curl_lock_data = 6;
pub const CURL_LOCK_DATA_CONNECT: curl_lock_data = 5;
pub const CURL_LOCK_DATA_SSL_SESSION: curl_lock_data = 4;
pub const CURL_LOCK_DATA_DNS: curl_lock_data = 3;
pub const CURL_LOCK_DATA_COOKIE: curl_lock_data = 2;
pub const CURL_LOCK_DATA_SHARE: curl_lock_data = 1;
pub const CURL_LOCK_DATA_NONE: curl_lock_data = 0;
pub type curl_lock_function = Option<
    unsafe extern "C" fn(*mut CURL, curl_lock_data, curl_lock_access, *mut libc::c_void) -> (),
>;
pub type curl_lock_access = u32;
pub const CURL_LOCK_ACCESS_LAST: curl_lock_access = 3;
pub const CURL_LOCK_ACCESS_SINGLE: curl_lock_access = 2;
pub const CURL_LOCK_ACCESS_SHARED: curl_lock_access = 1;
pub const CURL_LOCK_ACCESS_NONE: curl_lock_access = 0;
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
pub type curl_strdup_callback = Option<unsafe extern "C" fn(*const i8) -> *mut i8>;
pub type C2RustUnnamed_6 = u32;
pub const CURLFTP_CREATE_DIR_LAST: C2RustUnnamed_6 = 3;
pub const CURLFTP_CREATE_DIR_RETRY: C2RustUnnamed_6 = 2;
pub const CURLFTP_CREATE_DIR: C2RustUnnamed_6 = 1;
pub const CURLFTP_CREATE_DIR_NONE: C2RustUnnamed_6 = 0;
pub type C2RustUnnamed_7 = u32;
pub const CURLFTPMETHOD_LAST: C2RustUnnamed_7 = 4;
pub const CURLFTPMETHOD_SINGLECWD: C2RustUnnamed_7 = 3;
pub const CURLFTPMETHOD_NOCWD: C2RustUnnamed_7 = 2;
pub const CURLFTPMETHOD_MULTICWD: C2RustUnnamed_7 = 1;
pub const CURLFTPMETHOD_DEFAULT: C2RustUnnamed_7 = 0;
pub type CURLoption = u32;
pub const CURLOPT_LASTENTRY: CURLoption = 40311;
pub const CURLOPT_PROXY_CAINFO_BLOB: CURLoption = 40310;
pub const CURLOPT_CAINFO_BLOB: CURLoption = 40309;
pub const CURLOPT_DOH_SSL_VERIFYSTATUS: CURLoption = 308;
pub const CURLOPT_DOH_SSL_VERIFYHOST: CURLoption = 307;
pub const CURLOPT_DOH_SSL_VERIFYPEER: CURLoption = 306;
pub const CURLOPT_AWS_SIGV4: CURLoption = 10305;
pub const CURLOPT_HSTSWRITEDATA: CURLoption = 10304;
pub const CURLOPT_HSTSWRITEFUNCTION: CURLoption = 20303;
pub const CURLOPT_HSTSREADDATA: CURLoption = 10302;
pub const CURLOPT_HSTSREADFUNCTION: CURLoption = 20301;
pub const CURLOPT_HSTS: CURLoption = 10300;
pub const CURLOPT_HSTS_CTRL: CURLoption = 299;
pub const CURLOPT_SSL_EC_CURVES: CURLoption = 10298;
pub const CURLOPT_PROXY_ISSUERCERT_BLOB: CURLoption = 40297;
pub const CURLOPT_PROXY_ISSUERCERT: CURLoption = 10296;
pub const CURLOPT_ISSUERCERT_BLOB: CURLoption = 40295;
pub const CURLOPT_PROXY_SSLKEY_BLOB: CURLoption = 40294;
pub const CURLOPT_PROXY_SSLCERT_BLOB: CURLoption = 40293;
pub const CURLOPT_SSLKEY_BLOB: CURLoption = 40292;
pub const CURLOPT_SSLCERT_BLOB: CURLoption = 40291;
pub const CURLOPT_MAIL_RCPT_ALLLOWFAILS: CURLoption = 290;
pub const CURLOPT_SASL_AUTHZID: CURLoption = 10289;
pub const CURLOPT_MAXAGE_CONN: CURLoption = 288;
pub const CURLOPT_ALTSVC: CURLoption = 10287;
pub const CURLOPT_ALTSVC_CTRL: CURLoption = 286;
pub const CURLOPT_HTTP09_ALLOWED: CURLoption = 285;
pub const CURLOPT_TRAILERDATA: CURLoption = 10284;
pub const CURLOPT_TRAILERFUNCTION: CURLoption = 20283;
pub const CURLOPT_CURLU: CURLoption = 10282;
pub const CURLOPT_UPKEEP_INTERVAL_MS: CURLoption = 281;
pub const CURLOPT_UPLOAD_BUFFERSIZE: CURLoption = 280;
pub const CURLOPT_DOH_URL: CURLoption = 10279;
pub const CURLOPT_DISALLOW_USERNAME_IN_URL: CURLoption = 278;
pub const CURLOPT_PROXY_TLS13_CIPHERS: CURLoption = 10277;
pub const CURLOPT_TLS13_CIPHERS: CURLoption = 10276;
pub const CURLOPT_DNS_SHUFFLE_ADDRESSES: CURLoption = 275;
pub const CURLOPT_HAPROXYPROTOCOL: CURLoption = 274;
pub const CURLOPT_RESOLVER_START_DATA: CURLoption = 10273;
pub const CURLOPT_RESOLVER_START_FUNCTION: CURLoption = 20272;
pub const CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS: CURLoption = 271;
pub const CURLOPT_TIMEVALUE_LARGE: CURLoption = 30270;
pub const CURLOPT_MIMEPOST: CURLoption = 10269;
pub const CURLOPT_SSH_COMPRESSION: CURLoption = 268;
pub const CURLOPT_SOCKS5_AUTH: CURLoption = 267;
pub const CURLOPT_REQUEST_TARGET: CURLoption = 10266;
pub const CURLOPT_SUPPRESS_CONNECT_HEADERS: CURLoption = 265;
pub const CURLOPT_ABSTRACT_UNIX_SOCKET: CURLoption = 10264;
pub const CURLOPT_PROXY_PINNEDPUBLICKEY: CURLoption = 10263;
pub const CURLOPT_PRE_PROXY: CURLoption = 10262;
pub const CURLOPT_PROXY_SSL_OPTIONS: CURLoption = 261;
pub const CURLOPT_PROXY_CRLFILE: CURLoption = 10260;
pub const CURLOPT_PROXY_SSL_CIPHER_LIST: CURLoption = 10259;
pub const CURLOPT_PROXY_KEYPASSWD: CURLoption = 10258;
pub const CURLOPT_PROXY_SSLKEYTYPE: CURLoption = 10257;
pub const CURLOPT_PROXY_SSLKEY: CURLoption = 10256;
pub const CURLOPT_PROXY_SSLCERTTYPE: CURLoption = 10255;
pub const CURLOPT_PROXY_SSLCERT: CURLoption = 10254;
pub const CURLOPT_PROXY_TLSAUTH_TYPE: CURLoption = 10253;
pub const CURLOPT_PROXY_TLSAUTH_PASSWORD: CURLoption = 10252;
pub const CURLOPT_PROXY_TLSAUTH_USERNAME: CURLoption = 10251;
pub const CURLOPT_PROXY_SSLVERSION: CURLoption = 250;
pub const CURLOPT_PROXY_SSL_VERIFYHOST: CURLoption = 249;
pub const CURLOPT_PROXY_SSL_VERIFYPEER: CURLoption = 248;
pub const CURLOPT_PROXY_CAPATH: CURLoption = 10247;
pub const CURLOPT_PROXY_CAINFO: CURLoption = 10246;
pub const CURLOPT_KEEP_SENDING_ON_ERROR: CURLoption = 245;
pub const CURLOPT_TCP_FASTOPEN: CURLoption = 244;
pub const CURLOPT_CONNECT_TO: CURLoption = 10243;
pub const CURLOPT_TFTP_NO_OPTIONS: CURLoption = 242;
pub const CURLOPT_STREAM_DEPENDS_E: CURLoption = 10241;
pub const CURLOPT_STREAM_DEPENDS: CURLoption = 10240;
pub const CURLOPT_STREAM_WEIGHT: CURLoption = 239;
pub const CURLOPT_DEFAULT_PROTOCOL: CURLoption = 10238;
pub const CURLOPT_PIPEWAIT: CURLoption = 237;
pub const CURLOPT_SERVICE_NAME: CURLoption = 10236;
pub const CURLOPT_PROXY_SERVICE_NAME: CURLoption = 10235;
pub const CURLOPT_PATH_AS_IS: CURLoption = 234;
pub const CURLOPT_SSL_FALSESTART: CURLoption = 233;
pub const CURLOPT_SSL_VERIFYSTATUS: CURLoption = 232;
pub const CURLOPT_UNIX_SOCKET_PATH: CURLoption = 10231;
pub const CURLOPT_PINNEDPUBLICKEY: CURLoption = 10230;
pub const CURLOPT_HEADEROPT: CURLoption = 229;
pub const CURLOPT_PROXYHEADER: CURLoption = 10228;
pub const CURLOPT_EXPECT_100_TIMEOUT_MS: CURLoption = 227;
pub const CURLOPT_SSL_ENABLE_ALPN: CURLoption = 226;
pub const CURLOPT_SSL_ENABLE_NPN: CURLoption = 225;
pub const CURLOPT_LOGIN_OPTIONS: CURLoption = 10224;
pub const CURLOPT_DNS_LOCAL_IP6: CURLoption = 10223;
pub const CURLOPT_DNS_LOCAL_IP4: CURLoption = 10222;
pub const CURLOPT_DNS_INTERFACE: CURLoption = 10221;
pub const CURLOPT_XOAUTH2_BEARER: CURLoption = 10220;
pub const CURLOPT_XFERINFOFUNCTION: CURLoption = 20219;
pub const CURLOPT_SASL_IR: CURLoption = 218;
pub const CURLOPT_MAIL_AUTH: CURLoption = 10217;
pub const CURLOPT_SSL_OPTIONS: CURLoption = 216;
pub const CURLOPT_TCP_KEEPINTVL: CURLoption = 215;
pub const CURLOPT_TCP_KEEPIDLE: CURLoption = 214;
pub const CURLOPT_TCP_KEEPALIVE: CURLoption = 213;
pub const CURLOPT_ACCEPTTIMEOUT_MS: CURLoption = 212;
pub const CURLOPT_DNS_SERVERS: CURLoption = 10211;
pub const CURLOPT_GSSAPI_DELEGATION: CURLoption = 210;
pub const CURLOPT_CLOSESOCKETDATA: CURLoption = 10209;
pub const CURLOPT_CLOSESOCKETFUNCTION: CURLoption = 20208;
pub const CURLOPT_TRANSFER_ENCODING: CURLoption = 207;
pub const CURLOPT_TLSAUTH_TYPE: CURLoption = 10206;
pub const CURLOPT_TLSAUTH_PASSWORD: CURLoption = 10205;
pub const CURLOPT_TLSAUTH_USERNAME: CURLoption = 10204;
pub const CURLOPT_RESOLVE: CURLoption = 10203;
pub const CURLOPT_FNMATCH_DATA: CURLoption = 10202;
pub const CURLOPT_CHUNK_DATA: CURLoption = 10201;
pub const CURLOPT_FNMATCH_FUNCTION: CURLoption = 20200;
pub const CURLOPT_CHUNK_END_FUNCTION: CURLoption = 20199;
pub const CURLOPT_CHUNK_BGN_FUNCTION: CURLoption = 20198;
pub const CURLOPT_WILDCARDMATCH: CURLoption = 197;
pub const CURLOPT_INTERLEAVEFUNCTION: CURLoption = 20196;
pub const CURLOPT_INTERLEAVEDATA: CURLoption = 10195;
pub const CURLOPT_RTSP_SERVER_CSEQ: CURLoption = 194;
pub const CURLOPT_RTSP_CLIENT_CSEQ: CURLoption = 193;
pub const CURLOPT_RTSP_TRANSPORT: CURLoption = 10192;
pub const CURLOPT_RTSP_STREAM_URI: CURLoption = 10191;
pub const CURLOPT_RTSP_SESSION_ID: CURLoption = 10190;
pub const CURLOPT_RTSP_REQUEST: CURLoption = 189;
pub const CURLOPT_FTP_USE_PRET: CURLoption = 188;
pub const CURLOPT_MAIL_RCPT: CURLoption = 10187;
pub const CURLOPT_MAIL_FROM: CURLoption = 10186;
pub const CURLOPT_SSH_KEYDATA: CURLoption = 10185;
pub const CURLOPT_SSH_KEYFUNCTION: CURLoption = 20184;
pub const CURLOPT_SSH_KNOWNHOSTS: CURLoption = 10183;
pub const CURLOPT_REDIR_PROTOCOLS: CURLoption = 182;
pub const CURLOPT_PROTOCOLS: CURLoption = 181;
pub const CURLOPT_SOCKS5_GSSAPI_NEC: CURLoption = 180;
pub const CURLOPT_SOCKS5_GSSAPI_SERVICE: CURLoption = 10179;
pub const CURLOPT_TFTP_BLKSIZE: CURLoption = 178;
pub const CURLOPT_NOPROXY: CURLoption = 10177;
pub const CURLOPT_PROXYPASSWORD: CURLoption = 10176;
pub const CURLOPT_PROXYUSERNAME: CURLoption = 10175;
pub const CURLOPT_PASSWORD: CURLoption = 10174;
pub const CURLOPT_USERNAME: CURLoption = 10173;
pub const CURLOPT_CERTINFO: CURLoption = 172;
pub const CURLOPT_ADDRESS_SCOPE: CURLoption = 171;
pub const CURLOPT_ISSUERCERT: CURLoption = 10170;
pub const CURLOPT_CRLFILE: CURLoption = 10169;
pub const CURLOPT_SEEKDATA: CURLoption = 10168;
pub const CURLOPT_SEEKFUNCTION: CURLoption = 20167;
pub const CURLOPT_PROXY_TRANSFER_MODE: CURLoption = 166;
pub const CURLOPT_COPYPOSTFIELDS: CURLoption = 10165;
pub const CURLOPT_OPENSOCKETDATA: CURLoption = 10164;
pub const CURLOPT_OPENSOCKETFUNCTION: CURLoption = 20163;
pub const CURLOPT_SSH_HOST_PUBLIC_KEY_MD5: CURLoption = 10162;
pub const CURLOPT_POSTREDIR: CURLoption = 161;
pub const CURLOPT_NEW_DIRECTORY_PERMS: CURLoption = 160;
pub const CURLOPT_NEW_FILE_PERMS: CURLoption = 159;
pub const CURLOPT_HTTP_CONTENT_DECODING: CURLoption = 158;
pub const CURLOPT_HTTP_TRANSFER_DECODING: CURLoption = 157;
pub const CURLOPT_CONNECTTIMEOUT_MS: CURLoption = 156;
pub const CURLOPT_TIMEOUT_MS: CURLoption = 155;
pub const CURLOPT_FTP_SSL_CCC: CURLoption = 154;
pub const CURLOPT_SSH_PRIVATE_KEYFILE: CURLoption = 10153;
pub const CURLOPT_SSH_PUBLIC_KEYFILE: CURLoption = 10152;
pub const CURLOPT_SSH_AUTH_TYPES: CURLoption = 151;
pub const CURLOPT_SSL_SESSIONID_CACHE: CURLoption = 150;
pub const CURLOPT_SOCKOPTDATA: CURLoption = 10149;
pub const CURLOPT_SOCKOPTFUNCTION: CURLoption = 20148;
pub const CURLOPT_FTP_ALTERNATIVE_TO_USER: CURLoption = 10147;
pub const CURLOPT_MAX_RECV_SPEED_LARGE: CURLoption = 30146;
pub const CURLOPT_MAX_SEND_SPEED_LARGE: CURLoption = 30145;
pub const CURLOPT_CONV_FROM_UTF8_FUNCTION: CURLoption = 20144;
pub const CURLOPT_CONV_TO_NETWORK_FUNCTION: CURLoption = 20143;
pub const CURLOPT_CONV_FROM_NETWORK_FUNCTION: CURLoption = 20142;
pub const CURLOPT_CONNECT_ONLY: CURLoption = 141;
pub const CURLOPT_LOCALPORTRANGE: CURLoption = 140;
pub const CURLOPT_LOCALPORT: CURLoption = 139;
pub const CURLOPT_FTP_FILEMETHOD: CURLoption = 138;
pub const CURLOPT_FTP_SKIP_PASV_IP: CURLoption = 137;
pub const CURLOPT_IGNORE_CONTENT_LENGTH: CURLoption = 136;
pub const CURLOPT_COOKIELIST: CURLoption = 10135;
pub const CURLOPT_FTP_ACCOUNT: CURLoption = 10134;
pub const CURLOPT_IOCTLDATA: CURLoption = 10131;
pub const CURLOPT_IOCTLFUNCTION: CURLoption = 20130;
pub const CURLOPT_FTPSSLAUTH: CURLoption = 129;
pub const CURLOPT_TCP_NODELAY: CURLoption = 121;
pub const CURLOPT_POSTFIELDSIZE_LARGE: CURLoption = 30120;
pub const CURLOPT_USE_SSL: CURLoption = 119;
pub const CURLOPT_NETRC_FILE: CURLoption = 10118;
pub const CURLOPT_MAXFILESIZE_LARGE: CURLoption = 30117;
pub const CURLOPT_RESUME_FROM_LARGE: CURLoption = 30116;
pub const CURLOPT_INFILESIZE_LARGE: CURLoption = 30115;
pub const CURLOPT_MAXFILESIZE: CURLoption = 114;
pub const CURLOPT_IPRESOLVE: CURLoption = 113;
pub const CURLOPT_FTP_RESPONSE_TIMEOUT: CURLoption = 112;
pub const CURLOPT_PROXYAUTH: CURLoption = 111;
pub const CURLOPT_FTP_CREATE_MISSING_DIRS: CURLoption = 110;
pub const CURLOPT_SSL_CTX_DATA: CURLoption = 10109;
pub const CURLOPT_SSL_CTX_FUNCTION: CURLoption = 20108;
pub const CURLOPT_HTTPAUTH: CURLoption = 107;
pub const CURLOPT_FTP_USE_EPRT: CURLoption = 106;
pub const CURLOPT_UNRESTRICTED_AUTH: CURLoption = 105;
pub const CURLOPT_HTTP200ALIASES: CURLoption = 10104;
pub const CURLOPT_PRIVATE: CURLoption = 10103;
pub const CURLOPT_ACCEPT_ENCODING: CURLoption = 10102;
pub const CURLOPT_PROXYTYPE: CURLoption = 101;
pub const CURLOPT_SHARE: CURLoption = 10100;
pub const CURLOPT_NOSIGNAL: CURLoption = 99;
pub const CURLOPT_BUFFERSIZE: CURLoption = 98;
pub const CURLOPT_CAPATH: CURLoption = 10097;
pub const CURLOPT_COOKIESESSION: CURLoption = 96;
pub const CURLOPT_DEBUGDATA: CURLoption = 10095;
pub const CURLOPT_DEBUGFUNCTION: CURLoption = 20094;
pub const CURLOPT_PREQUOTE: CURLoption = 10093;
pub const CURLOPT_DNS_CACHE_TIMEOUT: CURLoption = 92;
pub const CURLOPT_DNS_USE_GLOBAL_CACHE: CURLoption = 91;
pub const CURLOPT_SSLENGINE_DEFAULT: CURLoption = 90;
pub const CURLOPT_SSLENGINE: CURLoption = 10089;
pub const CURLOPT_SSLKEYTYPE: CURLoption = 10088;
pub const CURLOPT_SSLKEY: CURLoption = 10087;
pub const CURLOPT_SSLCERTTYPE: CURLoption = 10086;
pub const CURLOPT_FTP_USE_EPSV: CURLoption = 85;
pub const CURLOPT_HTTP_VERSION: CURLoption = 84;
pub const CURLOPT_SSL_CIPHER_LIST: CURLoption = 10083;
pub const CURLOPT_COOKIEJAR: CURLoption = 10082;
pub const CURLOPT_SSL_VERIFYHOST: CURLoption = 81;
pub const CURLOPT_HTTPGET: CURLoption = 80;
pub const CURLOPT_HEADERFUNCTION: CURLoption = 20079;
pub const CURLOPT_CONNECTTIMEOUT: CURLoption = 78;
pub const CURLOPT_EGDSOCKET: CURLoption = 10077;
pub const CURLOPT_RANDOM_FILE: CURLoption = 10076;
pub const CURLOPT_FORBID_REUSE: CURLoption = 75;
pub const CURLOPT_FRESH_CONNECT: CURLoption = 74;
pub const CURLOPT_OBSOLETE72: CURLoption = 72;
pub const CURLOPT_MAXCONNECTS: CURLoption = 71;
pub const CURLOPT_TELNETOPTIONS: CURLoption = 10070;
pub const CURLOPT_FILETIME: CURLoption = 69;
pub const CURLOPT_MAXREDIRS: CURLoption = 68;
pub const CURLOPT_CAINFO: CURLoption = 10065;
pub const CURLOPT_SSL_VERIFYPEER: CURLoption = 64;
pub const CURLOPT_KRBLEVEL: CURLoption = 10063;
pub const CURLOPT_INTERFACE: CURLoption = 10062;
pub const CURLOPT_HTTPPROXYTUNNEL: CURLoption = 61;
pub const CURLOPT_POSTFIELDSIZE: CURLoption = 60;
pub const CURLOPT_PROXYPORT: CURLoption = 59;
pub const CURLOPT_AUTOREFERER: CURLoption = 58;
pub const CURLOPT_XFERINFODATA: CURLoption = 10057;
pub const CURLOPT_PROGRESSFUNCTION: CURLoption = 20056;
pub const CURLOPT_PUT: CURLoption = 54;
pub const CURLOPT_TRANSFERTEXT: CURLoption = 53;
pub const CURLOPT_FOLLOWLOCATION: CURLoption = 52;
pub const CURLOPT_NETRC: CURLoption = 51;
pub const CURLOPT_APPEND: CURLoption = 50;
pub const CURLOPT_DIRLISTONLY: CURLoption = 48;
pub const CURLOPT_POST: CURLoption = 47;
pub const CURLOPT_UPLOAD: CURLoption = 46;
pub const CURLOPT_FAILONERROR: CURLoption = 45;
pub const CURLOPT_NOBODY: CURLoption = 44;
pub const CURLOPT_NOPROGRESS: CURLoption = 43;
pub const CURLOPT_HEADER: CURLoption = 42;
pub const CURLOPT_VERBOSE: CURLoption = 41;
pub const CURLOPT_OBSOLETE40: CURLoption = 10040;
pub const CURLOPT_POSTQUOTE: CURLoption = 10039;
pub const CURLOPT_STDERR: CURLoption = 10037;
pub const CURLOPT_CUSTOMREQUEST: CURLoption = 10036;
pub const CURLOPT_TIMEVALUE: CURLoption = 34;
pub const CURLOPT_TIMECONDITION: CURLoption = 33;
pub const CURLOPT_SSLVERSION: CURLoption = 32;
pub const CURLOPT_COOKIEFILE: CURLoption = 10031;
pub const CURLOPT_HEADERDATA: CURLoption = 10029;
pub const CURLOPT_QUOTE: CURLoption = 10028;
pub const CURLOPT_CRLF: CURLoption = 27;
pub const CURLOPT_KEYPASSWD: CURLoption = 10026;
pub const CURLOPT_SSLCERT: CURLoption = 10025;
pub const CURLOPT_HTTPPOST: CURLoption = 10024;
pub const CURLOPT_HTTPHEADER: CURLoption = 10023;
pub const CURLOPT_COOKIE: CURLoption = 10022;
pub const CURLOPT_RESUME_FROM: CURLoption = 21;
pub const CURLOPT_LOW_SPEED_TIME: CURLoption = 20;
pub const CURLOPT_LOW_SPEED_LIMIT: CURLoption = 19;
pub const CURLOPT_USERAGENT: CURLoption = 10018;
pub const CURLOPT_FTPPORT: CURLoption = 10017;
pub const CURLOPT_REFERER: CURLoption = 10016;
pub const CURLOPT_POSTFIELDS: CURLoption = 10015;
pub const CURLOPT_INFILESIZE: CURLoption = 14;
pub const CURLOPT_TIMEOUT: CURLoption = 13;
pub const CURLOPT_READFUNCTION: CURLoption = 20012;
pub const CURLOPT_WRITEFUNCTION: CURLoption = 20011;
pub const CURLOPT_ERRORBUFFER: CURLoption = 10010;
pub const CURLOPT_READDATA: CURLoption = 10009;
pub const CURLOPT_RANGE: CURLoption = 10007;
pub const CURLOPT_PROXYUSERPWD: CURLoption = 10006;
pub const CURLOPT_USERPWD: CURLoption = 10005;
pub const CURLOPT_PROXY: CURLoption = 10004;
pub const CURLOPT_PORT: CURLoption = 3;
pub const CURLOPT_URL: CURLoption = 10002;
pub const CURLOPT_WRITEDATA: CURLoption = 10001;
pub type C2RustUnnamed_8 = u32;
pub const CURL_HTTP_VERSION_LAST: C2RustUnnamed_8 = 31;
pub const CURL_HTTP_VERSION_3: C2RustUnnamed_8 = 30;
pub const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: C2RustUnnamed_8 = 5;
pub const CURL_HTTP_VERSION_2TLS: C2RustUnnamed_8 = 4;
pub const CURL_HTTP_VERSION_2_0: C2RustUnnamed_8 = 3;
pub const CURL_HTTP_VERSION_1_1: C2RustUnnamed_8 = 2;
pub const CURL_HTTP_VERSION_1_0: C2RustUnnamed_8 = 1;
pub const CURL_HTTP_VERSION_NONE: C2RustUnnamed_8 = 0;
pub type C2RustUnnamed_9 = u32;
pub const CURL_RTSPREQ_LAST: C2RustUnnamed_9 = 12;
pub const CURL_RTSPREQ_RECEIVE: C2RustUnnamed_9 = 11;
pub const CURL_RTSPREQ_RECORD: C2RustUnnamed_9 = 10;
pub const CURL_RTSPREQ_SET_PARAMETER: C2RustUnnamed_9 = 9;
pub const CURL_RTSPREQ_GET_PARAMETER: C2RustUnnamed_9 = 8;
pub const CURL_RTSPREQ_TEARDOWN: C2RustUnnamed_9 = 7;
pub const CURL_RTSPREQ_PAUSE: C2RustUnnamed_9 = 6;
pub const CURL_RTSPREQ_PLAY: C2RustUnnamed_9 = 5;
pub const CURL_RTSPREQ_SETUP: C2RustUnnamed_9 = 4;
pub const CURL_RTSPREQ_ANNOUNCE: C2RustUnnamed_9 = 3;
pub const CURL_RTSPREQ_DESCRIBE: C2RustUnnamed_9 = 2;
pub const CURL_RTSPREQ_OPTIONS: C2RustUnnamed_9 = 1;
pub const CURL_RTSPREQ_NONE: C2RustUnnamed_9 = 0;
pub type C2RustUnnamed_10 = u32;
pub const CURL_SSLVERSION_LAST: C2RustUnnamed_10 = 8;
pub const CURL_SSLVERSION_TLSv1_3: C2RustUnnamed_10 = 7;
pub const CURL_SSLVERSION_TLSv1_2: C2RustUnnamed_10 = 6;
pub const CURL_SSLVERSION_TLSv1_1: C2RustUnnamed_10 = 5;
pub const CURL_SSLVERSION_TLSv1_0: C2RustUnnamed_10 = 4;
pub const CURL_SSLVERSION_SSLv3: C2RustUnnamed_10 = 3;
pub const CURL_SSLVERSION_SSLv2: C2RustUnnamed_10 = 2;
pub const CURL_SSLVERSION_TLSv1: C2RustUnnamed_10 = 1;
pub const CURL_SSLVERSION_DEFAULT: C2RustUnnamed_10 = 0;
pub type C2RustUnnamed_11 = u32;
pub const CURL_SSLVERSION_MAX_LAST: C2RustUnnamed_11 = 524288;
pub const CURL_SSLVERSION_MAX_TLSv1_3: C2RustUnnamed_11 = 458752;
pub const CURL_SSLVERSION_MAX_TLSv1_2: C2RustUnnamed_11 = 393216;
pub const CURL_SSLVERSION_MAX_TLSv1_1: C2RustUnnamed_11 = 327680;
pub const CURL_SSLVERSION_MAX_TLSv1_0: C2RustUnnamed_11 = 262144;
pub const CURL_SSLVERSION_MAX_DEFAULT: C2RustUnnamed_11 = 65536;
pub const CURL_SSLVERSION_MAX_NONE: C2RustUnnamed_11 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_ssl_backend {
    pub id: curl_sslbackend,
    pub name: *const i8,
}
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
pub const STRING_ALTSVC: dupstring = 69;
pub const STRING_HSTS: dupstring = 70;
pub const STRING_DOH: dupstring = 68;
pub const STRING_UNIX_SOCKET_PATH: dupstring = 66;
pub const STRING_TLSAUTH_USERNAME_PROXY: dupstring = 62;
pub const STRING_TLSAUTH_PASSWORD_PROXY: dupstring = 64;
pub const STRING_TLSAUTH_USERNAME: dupstring = 61;
pub const STRING_TLSAUTH_PASSWORD: dupstring = 63;
pub const STRING_RTSP_TRANSPORT: dupstring = 52;
pub const STRING_RTSP_STREAM_URI: dupstring = 51;
pub const STRING_RTSP_SESSION_ID: dupstring = 50;
pub const STRING_SASL_AUTHZID: dupstring = 71;
pub const STRING_MAIL_AUTH: dupstring = 60;
pub const STRING_MAIL_FROM: dupstring = 59;
pub const STRING_DEFAULT_PROTOCOL: dupstring = 7;
pub const STRING_SSL_EC_CURVES: dupstring = 76;
pub const BLOB_SSL_ISSUERCERT_PROXY: dupblob = 5;
pub const STRING_SSL_ISSUERCERT_PROXY: dupstring = 42;
pub const BLOB_SSL_ISSUERCERT: dupblob = 4;
pub const STRING_SSL_ISSUERCERT: dupstring = 41;
pub const STRING_SSL_CRLFILE_PROXY: dupstring = 40;
pub const STRING_SSL_CRLFILE: dupstring = 39;
pub const STRING_SSL_CAPATH_PROXY: dupstring = 27;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_ssl {
    pub info: curl_ssl_backend,
    pub supports: u32,
    pub sizeof_ssl_backend_data: size_t,
    pub init: Option<unsafe extern "C" fn() -> i32>,
    pub cleanup: Option<unsafe extern "C" fn() -> ()>,
    pub version: Option<unsafe extern "C" fn(*mut i8, size_t) -> size_t>,
    pub check_cxn: Option<unsafe extern "C" fn(*mut connectdata) -> i32>,
    pub shut_down: Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> i32>,
    pub data_pending: Option<unsafe extern "C" fn(*const connectdata, i32) -> bool>,
    pub random: Option<unsafe extern "C" fn(*mut Curl_easy, *mut u8, size_t) -> CURLcode>,
    pub cert_status_request: Option<unsafe extern "C" fn() -> bool>,
    pub connect_blocking:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> CURLcode>,
    pub connect_nonblocking:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32, *mut bool) -> CURLcode>,
    pub getsock: Option<unsafe extern "C" fn(*mut connectdata, *mut curl_socket_t) -> i32>,
    pub get_internals:
        Option<unsafe extern "C" fn(*mut ssl_connect_data, CURLINFO) -> *mut libc::c_void>,
    pub close_one: Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> ()>,
    pub close_all: Option<unsafe extern "C" fn(*mut Curl_easy) -> ()>,
    pub session_free: Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    pub set_engine: Option<unsafe extern "C" fn(*mut Curl_easy, *const i8) -> CURLcode>,
    pub set_engine_default: Option<unsafe extern "C" fn(*mut Curl_easy) -> CURLcode>,
    pub engines_list: Option<unsafe extern "C" fn(*mut Curl_easy) -> *mut curl_slist>,
    pub false_start: Option<unsafe extern "C" fn() -> bool>,
    pub sha256sum: Option<unsafe extern "C" fn(*const u8, size_t, *mut u8, size_t) -> CURLcode>,
    pub associate_connection:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> ()>,
    pub disassociate_connection: Option<unsafe extern "C" fn(*mut Curl_easy, i32) -> ()>,
}
pub const STRING_SSL_CAPATH: dupstring = 26;
pub const BLOB_CAINFO_PROXY: dupblob = 7;
pub const STRING_SSL_CAFILE_PROXY: dupstring = 29;
pub const BLOB_CAINFO: dupblob = 6;
pub const STRING_SSL_CAFILE: dupstring = 28;
pub const STRING_SSL_PINNEDPUBLICKEY_PROXY: dupstring = 31;
pub const STRING_SSL_PINNEDPUBLICKEY: dupstring = 30;
pub const STRING_DEVICE: dupstring = 8;
pub const STRING_SSL_ENGINE: dupstring = 43;
pub const STRING_KEY_PASSWD_PROXY: dupstring = 16;
pub const STRING_KEY_PASSWD: dupstring = 15;
pub const STRING_KEY_TYPE_PROXY: dupstring = 18;
pub const STRING_KEY_TYPE: dupstring = 17;
pub const BLOB_KEY_PROXY: dupblob = 3;
pub const STRING_KEY_PROXY: dupstring = 14;
pub const BLOB_KEY: dupblob = 2;
pub const STRING_KEY: dupstring = 13;
pub const STRING_CERT_TYPE_PROXY: dupstring = 3;
pub const STRING_CERT_TYPE: dupstring = 2;
pub const BLOB_CERT_PROXY: dupblob = 1;
pub const STRING_CERT_PROXY: dupstring = 1;
pub const BLOB_CERT: dupblob = 0;
pub const STRING_CERT: dupstring = 0;
pub const STRING_SET_RANGE: dupstring = 23;
pub const STRING_NOPROXY: dupstring = 49;
pub const STRING_PROXYPASSWORD: dupstring = 48;
pub const STRING_PROXYUSERNAME: dupstring = 47;
pub const STRING_BEARER: dupstring = 65;
pub const STRING_OPTIONS: dupstring = 46;
pub const STRING_PASSWORD: dupstring = 45;
pub const STRING_USERNAME: dupstring = 44;
pub const STRING_SET_URL: dupstring = 25;
pub const STRING_KRB_LEVEL: dupstring = 19;
pub const STRING_FTP_ALTERNATIVE_TO_USER: dupstring = 11;
pub const STRING_FTP_ACCOUNT: dupstring = 10;
pub const STRING_FTPPORT: dupstring = 12;
pub const STRING_SERVICE_NAME: dupstring = 58;
pub const STRING_PROXY_SERVICE_NAME: dupstring = 57;
pub const STRING_PRE_PROXY: dupstring = 22;
pub const STRING_PROXY: dupstring = 21;
pub const STRING_CUSTOMREQUEST: dupstring = 6;
pub const STRING_COOKIEJAR: dupstring = 5;
pub const STRING_COOKIE: dupstring = 4;
pub const STRING_USERAGENT: dupstring = 38;
pub const STRING_SET_REFERER: dupstring = 24;
pub const STRING_AWS_SIGV4: dupstring = 79;
pub const STRING_ENCODING: dupstring = 9;
pub const STRING_COPYPOSTFIELDS: dupstring = 78;
pub const STRING_NETRC_FILE: dupstring = 20;
pub const STRING_TARGET: dupstring = 67;
pub const STRING_SSL_EGDSOCKET: dupstring = 36;
pub const STRING_SSL_RANDOM_FILE: dupstring = 37;
pub const STRING_SSL_CIPHER13_LIST_PROXY: dupstring = 35;
pub const STRING_SSL_CIPHER13_LIST: dupstring = 34;
pub const STRING_SSL_CIPHER_LIST_PROXY: dupstring = 33;
pub const STRING_SSL_CIPHER_LIST: dupstring = 32;
pub type dupstring = u32;
pub const STRING_LAST: dupstring = 80;
pub const STRING_LASTZEROTERMINATED: dupstring = 77;
pub const STRING_DNS_LOCAL_IP6: dupstring = 75;
pub const STRING_DNS_LOCAL_IP4: dupstring = 74;
pub const STRING_DNS_INTERFACE: dupstring = 73;
pub const STRING_DNS_SERVERS: dupstring = 72;
pub const STRING_SSH_KNOWNHOSTS: dupstring = 56;
pub const STRING_SSH_HOST_PUBLIC_KEY_MD5: dupstring = 55;
pub const STRING_SSH_PUBLIC_KEY: dupstring = 54;
pub const STRING_SSH_PRIVATE_KEY: dupstring = 53;
pub type dupblob = u32;
pub const BLOB_LAST: dupblob = 8;
#[no_mangle]
pub extern "C" fn Curl_setstropt(mut charp: *mut *mut i8, mut s: *const i8) -> CURLcode {
    (unsafe { Curl_cfree.expect("non-null function pointer")(*charp as *mut libc::c_void) });
    (unsafe { *charp = 0 as *mut i8 });
    if !s.is_null() {
        let mut str: *mut i8 = unsafe { Curl_cstrdup.expect("non-null function pointer")(s) };
        if !str.is_null() {
            let mut len: size_t = unsafe { strlen(str) };
            if len > 8000000 as i32 as u64 {
                (unsafe { Curl_cfree.expect("non-null function pointer")(str as *mut libc::c_void) });
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
        }
        if str.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (unsafe { *charp = str });
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_setblobopt(
    mut blobp: *mut *mut curl_blob,
    mut blob: *const curl_blob,
) -> CURLcode {
    (unsafe { Curl_cfree.expect("non-null function pointer")(*blobp as *mut libc::c_void) });
    (unsafe { *blobp = 0 as *mut curl_blob });
    if !blob.is_null() {
        let mut nblob: *mut curl_blob = 0 as *mut curl_blob;
        if (unsafe { (*blob).len }) > 8000000 as i32 as u64 {
            return CURLE_BAD_FUNCTION_ARGUMENT;
        }
        nblob = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
            (::std::mem::size_of::<curl_blob>() as u64).wrapping_add(
                if (*blob).flags & 1 as i32 as u32 != 0 {
                    (*blob).len
                } else {
                    0 as i32 as u64
                },
            ),
        ) }) as *mut curl_blob;
        if nblob.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (unsafe { *nblob = *blob });
        if (unsafe { (*blob).flags }) & 1 as i32 as u32 != 0 {
            let fresh0 = unsafe { &mut ((*nblob).data) };
            *fresh0 = (unsafe { (nblob as *mut i8).offset(::std::mem::size_of::<curl_blob>() as u64 as isize) })
                as *mut libc::c_void;
            (unsafe { memcpy((*nblob).data, (*blob).data, (*blob).len) });
        }
        (unsafe { *blobp = nblob });
        return CURLE_OK;
    }
    return CURLE_OK;
}
extern "C" fn setstropt_userpwd(
    mut option: *mut i8,
    mut userp: *mut *mut i8,
    mut passwdp: *mut *mut i8,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut user: *mut i8 = 0 as *mut i8;
    let mut passwd: *mut i8 = 0 as *mut i8;
    if !option.is_null() {
        result = unsafe { Curl_parse_login_details(
            option,
            strlen(option),
            if !userp.is_null() {
                &mut user
            } else {
                0 as *mut *mut i8
            },
            if !passwdp.is_null() {
                &mut passwd
            } else {
                0 as *mut *mut i8
            },
            0 as *mut *mut i8,
        ) };
    }
    if result as u64 == 0 {
        if !userp.is_null() {
            if user.is_null()
                && !option.is_null()
                && (unsafe { *option.offset(0 as i32 as isize) }) as i32 == ':' as i32
            {
                user = unsafe { Curl_cstrdup.expect("non-null function pointer")(
                    b"\0" as *const u8 as *const i8,
                ) };
                if user.is_null() {
                    result = CURLE_OUT_OF_MEMORY;
                }
            }
            (unsafe { Curl_cfree.expect("non-null function pointer")(*userp as *mut libc::c_void) });
            (unsafe { *userp = 0 as *mut i8 });
            (unsafe { *userp = user });
        }
        if !passwdp.is_null() {
            (unsafe { Curl_cfree.expect("non-null function pointer")(*passwdp as *mut libc::c_void) });
            (unsafe { *passwdp = 0 as *mut i8 });
            (unsafe { *passwdp = passwd });
        }
    }
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_vsetopt(
    mut data: *mut Curl_easy,
    mut option: CURLoption,
    mut param: ::std::ffi::VaList,
) -> CURLcode {
    let mut argptr: *mut i8 = 0 as *mut i8;
    let mut result: CURLcode = CURLE_OK;
    let mut arg: i64 = 0;
    let mut uarg: u64 = 0;
    let mut bigsize: curl_off_t = 0;
    match option as u32 {
        92 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < -(1 as i32) as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.dns_cache_timeout = arg });
        }
        91 => {}
        10083 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SSL_CIPHER_LIST as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10259 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SSL_CIPHER_LIST_PROXY as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10276 => {
            if unsafe { Curl_ssl_tls13_ciphersuites() } {
                result = Curl_setstropt(
                    unsafe { &mut *((*data).set.str_0)
                        .as_mut_ptr()
                        .offset(STRING_SSL_CIPHER13_LIST as i32 as isize) },
                    unsafe { param.arg::<*mut i8>() },
                );
            } else {
                return CURLE_NOT_BUILT_IN;
            }
        }
        10277 => {
            if unsafe { Curl_ssl_tls13_ciphersuites() } {
                result = Curl_setstropt(
                    unsafe { &mut *((*data).set.str_0)
                        .as_mut_ptr()
                        .offset(STRING_SSL_CIPHER13_LIST_PROXY as i32 as isize) },
                    unsafe { param.arg::<*mut i8>() },
                );
            } else {
                return CURLE_NOT_BUILT_IN;
            }
        }
        10076 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SSL_RANDOM_FILE as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10077 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SSL_EGDSOCKET as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        71 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.maxconnects = arg as size_t });
        }
        75 => {
            let fresh1 = unsafe { &mut ((*data).set) };
            (*fresh1).set_reuse_forbid(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        74 => {
            let fresh2 = unsafe { &mut ((*data).set) };
            (*fresh2).set_reuse_fresh(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        41 => {
            let fresh3 = unsafe { &mut ((*data).set) };
            (*fresh3).set_verbose(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        42 => {
            let fresh4 = unsafe { &mut ((*data).set) };
            (*fresh4).set_include_header(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        43 => {
            let fresh5 = unsafe { &mut ((*data).set) };
            (*fresh5).set_hide_progress(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
            if (unsafe { ((*data).set).hide_progress() }) != 0 {
                (unsafe { (*data).progress.flags |= (1 as i32) << 4 as i32 });
            } else {
                (unsafe { (*data).progress.flags &= !((1 as i32) << 4 as i32) });
            }
        }
        44 => {
            let fresh6 = unsafe { &mut ((*data).set) };
            (*fresh6).set_opt_no_body(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
            if (unsafe { ((*data).set).opt_no_body() }) != 0 {
                (unsafe { (*data).set.method = HTTPREQ_HEAD });
            } else if (unsafe { (*data).set.method }) as u32 == HTTPREQ_HEAD as i32 as u32 {
                (unsafe { (*data).set.method = HTTPREQ_GET });
            }
        }
        45 => {
            let fresh7 = unsafe { &mut ((*data).set) };
            (*fresh7).set_http_fail_on_error(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        245 => {
            let fresh8 = unsafe { &mut ((*data).set) };
            (*fresh8).set_http_keep_sending_on_error(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        46 | 54 => {
            let fresh9 = unsafe { &mut ((*data).set) };
            (*fresh9).set_upload(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
            if (unsafe { ((*data).set).upload() }) != 0 {
                (unsafe { (*data).set.method = HTTPREQ_PUT });
                let fresh10 = unsafe { &mut ((*data).set) };
                (*fresh10).set_opt_no_body(0 as i32 as bit);
            } else {
                (unsafe { (*data).set.method = HTTPREQ_GET });
            }
        }
        10266 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_TARGET as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        69 => {
            let fresh11 = unsafe { &mut ((*data).set) };
            (*fresh11).set_get_filetime(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        112 => {
            arg = unsafe { param.arg::<i64>() };
            if arg >= 0 as i32 as i64 && arg <= (2147483647 as i32 / 1000 as i32) as i64 {
                (unsafe { (*data).set.server_response_timeout = arg * 1000 as i32 as i64 });
            } else {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
        }
        242 => {
            let fresh12 = unsafe { &mut ((*data).set) };
            (*fresh12).set_tftp_no_options(((unsafe { param.arg::<i64>() }) != 0 as i32 as i64) as i32 as bit);
        }
        178 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.tftp_blksize = arg });
        }
        51 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < CURL_NETRC_IGNORED as i32 as i64 || arg >= CURL_NETRC_LAST as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.use_netrc = arg as CURL_NETRC_OPTION });
        }
        10118 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_NETRC_FILE as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        53 => {
            let fresh13 = unsafe { &mut ((*data).set) };
            (*fresh13).set_prefer_ascii(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        33 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < CURL_TIMECOND_NONE as i32 as i64 || arg >= CURL_TIMECOND_LAST as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.timecondition = arg as curl_TimeCond });
        }
        34 => {
            (unsafe { (*data).set.timevalue = param.arg::<i64>() });
        }
        30270 => {
            (unsafe { (*data).set.timevalue = param.arg::<curl_off_t>() });
        }
        32 | 250 => {
            let mut version: i64 = 0;
            let mut version_max: i64 = 0;
            let mut primary: *mut ssl_primary_config = unsafe { &mut (*data).set.ssl.primary };
            if option as u32 != CURLOPT_SSLVERSION as i32 as u32 {
                primary = unsafe { &mut (*data).set.proxy_ssl.primary };
            }
            arg = unsafe { param.arg::<i64>() };
            version = arg & 0xffff as i32 as i64;
            version_max = arg & 0xffff0000 as u32 as i64;
            if version < CURL_SSLVERSION_DEFAULT as i32 as i64
                || version == CURL_SSLVERSION_SSLv2 as i32 as i64
                || version == CURL_SSLVERSION_SSLv3 as i32 as i64
                || version >= CURL_SSLVERSION_LAST as i32 as i64
                || version_max < CURL_SSLVERSION_MAX_NONE as i32 as i64
                || version_max >= CURL_SSLVERSION_MAX_LAST as i32 as i64
            {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*primary).version = version });
            (unsafe { (*primary).version_max = version_max });
        }
        10165 => {
            argptr = unsafe { param.arg::<*mut i8>() };
            if argptr.is_null() || (unsafe { (*data).set.postfieldsize }) == -(1 as i32) as i64 {
                result = Curl_setstropt(
                    unsafe { &mut *((*data).set.str_0)
                        .as_mut_ptr()
                        .offset(STRING_COPYPOSTFIELDS as i32 as isize) },
                    argptr,
                );
            } else if (unsafe { (*data).set.postfieldsize }) < 0 as i32 as i64
                || ::std::mem::size_of::<curl_off_t>() as u64
                    != ::std::mem::size_of::<size_t>() as u64
                    && (unsafe { (*data).set.postfieldsize }) > -(1 as i32) as size_t as curl_off_t
            {
                result = CURLE_OUT_OF_MEMORY;
            } else {
                let mut p: *mut i8 = 0 as *mut i8;
                Curl_setstropt(
                    unsafe { &mut *((*data).set.str_0)
                        .as_mut_ptr()
                        .offset(STRING_COPYPOSTFIELDS as i32 as isize) },
                    0 as *const i8,
                );
                p = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
                    (if (*data).set.postfieldsize != 0 {
                        (*data).set.postfieldsize
                    } else {
                        1 as i32 as i64
                    }) as size_t,
                ) }) as *mut i8;
                if p.is_null() {
                    result = CURLE_OUT_OF_MEMORY;
                } else {
                    if (unsafe { (*data).set.postfieldsize }) != 0 {
                        (unsafe { memcpy(
                            p as *mut libc::c_void,
                            argptr as *const libc::c_void,
                            (*data).set.postfieldsize as size_t,
                        ) });
                    }
                    let fresh14 = unsafe { &mut ((*data).set.str_0[STRING_COPYPOSTFIELDS as i32 as usize]) };
                    *fresh14 = p;
                }
            }
            let fresh15 = unsafe { &mut ((*data).set.postfields) };
            *fresh15 =
                (unsafe { (*data).set.str_0[STRING_COPYPOSTFIELDS as i32 as usize] }) as *mut libc::c_void;
            (unsafe { (*data).set.method = HTTPREQ_POST });
        }
        10015 => {
            let fresh16 = unsafe { &mut ((*data).set.postfields) };
            *fresh16 = unsafe { param.arg::<*mut libc::c_void>() };
            Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_COPYPOSTFIELDS as i32 as isize) },
                0 as *const i8,
            );
            (unsafe { (*data).set.method = HTTPREQ_POST });
        }
        60 => {
            bigsize = unsafe { param.arg::<i64>() };
            if bigsize < -(1 as i32) as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            if (unsafe { (*data).set.postfieldsize }) < bigsize
                && (unsafe { (*data).set.postfields })
                    == (unsafe { (*data).set.str_0[STRING_COPYPOSTFIELDS as i32 as usize] }) as *mut libc::c_void
            {
                Curl_setstropt(
                    unsafe { &mut *((*data).set.str_0)
                        .as_mut_ptr()
                        .offset(STRING_COPYPOSTFIELDS as i32 as isize) },
                    0 as *const i8,
                );
                let fresh17 = unsafe { &mut ((*data).set.postfields) };
                *fresh17 = 0 as *mut libc::c_void;
            }
            (unsafe { (*data).set.postfieldsize = bigsize });
        }
        30120 => {
            bigsize = unsafe { param.arg::<curl_off_t>() };
            if bigsize < -(1 as i32) as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            if (unsafe { (*data).set.postfieldsize }) < bigsize
                && (unsafe { (*data).set.postfields })
                    == (unsafe { (*data).set.str_0[STRING_COPYPOSTFIELDS as i32 as usize] }) as *mut libc::c_void
            {
                Curl_setstropt(
                    unsafe { &mut *((*data).set.str_0)
                        .as_mut_ptr()
                        .offset(STRING_COPYPOSTFIELDS as i32 as isize) },
                    0 as *const i8,
                );
                let fresh18 = unsafe { &mut ((*data).set.postfields) };
                *fresh18 = 0 as *mut libc::c_void;
            }
            (unsafe { (*data).set.postfieldsize = bigsize });
        }
        58 => {
            let fresh19 = unsafe { &mut ((*data).set) };
            (*fresh19).set_http_auto_referer(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        10102 => {
            argptr = unsafe { param.arg::<*mut i8>() };
            if !argptr.is_null() && (unsafe { *argptr }) == 0 {
                argptr = unsafe { Curl_all_content_encodings() };
                if argptr.is_null() {
                    result = CURLE_OUT_OF_MEMORY;
                } else {
                    result = Curl_setstropt(
                        unsafe { &mut *((*data).set.str_0)
                            .as_mut_ptr()
                            .offset(STRING_ENCODING as i32 as isize) },
                        argptr,
                    );
                    (unsafe { Curl_cfree.expect("non-null function pointer")(argptr as *mut libc::c_void) });
                }
            } else {
                result = Curl_setstropt(
                    unsafe { &mut *((*data).set.str_0)
                        .as_mut_ptr()
                        .offset(STRING_ENCODING as i32 as isize) },
                    argptr,
                );
            }
        }
        207 => {
            let fresh20 = unsafe { &mut ((*data).set) };
            (*fresh20).set_http_transfer_encoding(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        52 => {
            let fresh21 = unsafe { &mut ((*data).set) };
            (*fresh21).set_http_follow_location(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        105 => {
            let fresh22 = unsafe { &mut ((*data).set) };
            (*fresh22).set_allow_auth_to_other_hosts(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        68 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < -(1 as i32) as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.maxredirs = arg });
        }
        161 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.keep_post = (arg & (1 as i32 | 2 as i32 | 4 as i32) as i64) as i32 });
        }
        47 => {
            if (unsafe { param.arg::<i64>() }) != 0 {
                (unsafe { (*data).set.method = HTTPREQ_POST });
                let fresh23 = unsafe { &mut ((*data).set) };
                (*fresh23).set_opt_no_body(0 as i32 as bit);
            } else {
                (unsafe { (*data).set.method = HTTPREQ_GET });
            }
        }
        10024 => {
            let fresh24 = unsafe { &mut ((*data).set.httppost) };
            *fresh24 = unsafe { param.arg::<*mut curl_httppost>() };
            (unsafe { (*data).set.method = HTTPREQ_POST_FORM });
            let fresh25 = unsafe { &mut ((*data).set) };
            (*fresh25).set_opt_no_body(0 as i32 as bit);
        }
        10305 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_AWS_SIGV4 as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
            if !(unsafe { (*data).set.str_0[STRING_AWS_SIGV4 as i32 as usize] }).is_null() {
                (unsafe { (*data).set.httpauth = (1 as i32 as u64) << 7 as i32 });
            }
        }
        10269 => {
            result = unsafe { Curl_mime_set_subparts(
                &mut (*data).set.mimepost,
                param.arg::<*mut curl_mime>(),
                0 as i32,
            ) };
            if result as u64 == 0 {
                (unsafe { (*data).set.method = HTTPREQ_POST_MIME });
                let fresh26 = unsafe { &mut ((*data).set) };
                (*fresh26).set_opt_no_body(0 as i32 as bit);
            }
        }
        10016 => {
            if (unsafe { ((*data).state).referer_alloc() }) != 0 {
                (unsafe { Curl_cfree.expect("non-null function pointer")(
                    (*data).state.referer as *mut libc::c_void,
                ) });
                let fresh27 = unsafe { &mut ((*data).state.referer) };
                *fresh27 = 0 as *mut i8;
                let fresh28 = unsafe { &mut ((*data).state) };
                (*fresh28).set_referer_alloc(0 as i32 as bit);
            }
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SET_REFERER as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
            let fresh29 = unsafe { &mut ((*data).state.referer) };
            *fresh29 = unsafe { (*data).set.str_0[STRING_SET_REFERER as i32 as usize] };
        }
        10018 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_USERAGENT as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10023 => {
            let fresh30 = unsafe { &mut ((*data).set.headers) };
            *fresh30 = unsafe { param.arg::<*mut curl_slist>() };
        }
        10228 => {
            let fresh31 = unsafe { &mut ((*data).set.proxyheaders) };
            *fresh31 = unsafe { param.arg::<*mut curl_slist>() };
        }
        229 => {
            arg = unsafe { param.arg::<i64>() };
            let fresh32 = unsafe { &mut ((*data).set) };
            (*fresh32).set_sep_headers(
                (if arg & ((1 as i32) << 0 as i32) as i64 != 0 {
                    1 as i32
                } else {
                    0 as i32
                } != 0) as bit,
            );
        }
        10104 => {
            let fresh33 = unsafe { &mut ((*data).set.http200aliases) };
            *fresh33 = unsafe { param.arg::<*mut curl_slist>() };
        }
        10022 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_COOKIE as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10031 => {
            argptr = (unsafe { param.arg::<*mut libc::c_void>() }) as *mut i8;
            if !argptr.is_null() {
                let mut cl: *mut curl_slist = 0 as *mut curl_slist;
                if (unsafe { strlen(argptr) }) > 8000000 as i32 as u64 {
                    return CURLE_BAD_FUNCTION_ARGUMENT;
                }
                cl = unsafe { curl_slist_append((*data).state.cookielist, argptr) };
                if cl.is_null() {
                    (unsafe { curl_slist_free_all((*data).state.cookielist) });
                    let fresh34 = unsafe { &mut ((*data).state.cookielist) };
                    *fresh34 = 0 as *mut curl_slist;
                    return CURLE_OUT_OF_MEMORY;
                }
                let fresh35 = unsafe { &mut ((*data).state.cookielist) };
                *fresh35 = cl;
            } else {
                (unsafe { curl_slist_free_all((*data).state.cookielist) });
                let fresh36 = unsafe { &mut ((*data).state.cookielist) };
                *fresh36 = 0 as *mut curl_slist;
                if (unsafe { (*data).share }).is_null() || (unsafe { (*(*data).share).cookies }).is_null() {
                    (unsafe { Curl_cookie_clearall((*data).cookies) });
                    (unsafe { Curl_cookie_cleanup((*data).cookies) });
                }
                let fresh37 = unsafe { &mut ((*data).cookies) };
                *fresh37 = 0 as *mut CookieInfo;
            }
        }
        10082 => {
            let mut newcookies: *mut CookieInfo = 0 as *mut CookieInfo;
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_COOKIEJAR as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
            newcookies = unsafe { Curl_cookie_init(
                data,
                0 as *const i8,
                (*data).cookies,
                ((*data).set).cookiesession() != 0,
            ) };
            if newcookies.is_null() {
                result = CURLE_OUT_OF_MEMORY;
            }
            let fresh38 = unsafe { &mut ((*data).cookies) };
            *fresh38 = newcookies;
        }
        96 => {
            let fresh39 = unsafe { &mut ((*data).set) };
            (*fresh39).set_cookiesession(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        10135 => {
            argptr = unsafe { param.arg::<*mut i8>() };
            if !argptr.is_null() {
                if (unsafe { Curl_strcasecompare(argptr, b"ALL\0" as *const u8 as *const i8) }) != 0 {
                    (unsafe { Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE) });
                    (unsafe { Curl_cookie_clearall((*data).cookies) });
                    (unsafe { Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE) });
                } else if (unsafe { Curl_strcasecompare(argptr, b"SESS\0" as *const u8 as *const i8) }) != 0 {
                    (unsafe { Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE) });
                    (unsafe { Curl_cookie_clearsess((*data).cookies) });
                    (unsafe { Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE) });
                } else if (unsafe { Curl_strcasecompare(argptr, b"FLUSH\0" as *const u8 as *const i8) }) != 0 {
                    (unsafe { Curl_flush_cookies(data, 0 as i32 != 0) });
                } else if (unsafe { Curl_strcasecompare(argptr, b"RELOAD\0" as *const u8 as *const i8) }) != 0 {
                    (unsafe { Curl_cookie_loadfiles(data) });
                } else {
                    if (unsafe { (*data).cookies }).is_null() {
                        let fresh40 = unsafe { &mut ((*data).cookies) };
                        *fresh40 = unsafe { Curl_cookie_init(
                            data,
                            0 as *const i8,
                            0 as *mut CookieInfo,
                            1 as i32 != 0,
                        ) };
                    }
                    if (unsafe { strlen(argptr) }) > 8000000 as i32 as u64 {
                        return CURLE_BAD_FUNCTION_ARGUMENT;
                    }
                    argptr = unsafe { Curl_cstrdup.expect("non-null function pointer")(argptr) };
                    if argptr.is_null() || (unsafe { (*data).cookies }).is_null() {
                        result = CURLE_OUT_OF_MEMORY;
                        (unsafe { Curl_cfree.expect("non-null function pointer")(argptr as *mut libc::c_void) });
                    } else {
                        (unsafe { Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE) });
                        if (unsafe { curl_strnequal(
                            b"Set-Cookie:\0" as *const u8 as *const i8,
                            argptr,
                            strlen(b"Set-Cookie:\0" as *const u8 as *const i8),
                        ) }) != 0
                        {
                            (unsafe { Curl_cookie_add(
                                data,
                                (*data).cookies,
                                1 as i32 != 0,
                                0 as i32 != 0,
                                argptr.offset(11 as i32 as isize),
                                0 as *const i8,
                                0 as *const i8,
                                1 as i32 != 0,
                            ) });
                        } else {
                            (unsafe { Curl_cookie_add(
                                data,
                                (*data).cookies,
                                0 as i32 != 0,
                                0 as i32 != 0,
                                argptr,
                                0 as *const i8,
                                0 as *const i8,
                                1 as i32 != 0,
                            ) });
                        }
                        (unsafe { Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE) });
                        (unsafe { Curl_cfree.expect("non-null function pointer")(argptr as *mut libc::c_void) });
                    }
                }
            }
        }
        80 => {
            if (unsafe { param.arg::<i64>() }) != 0 {
                (unsafe { (*data).set.method = HTTPREQ_GET });
                let fresh41 = unsafe { &mut ((*data).set) };
                (*fresh41).set_upload(0 as i32 as bit);
                let fresh42 = unsafe { &mut ((*data).set) };
                (*fresh42).set_opt_no_body(0 as i32 as bit);
            }
        }
        84 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < CURL_HTTP_VERSION_NONE as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            if arg >= CURL_HTTP_VERSION_LAST as i32 as i64 {
                return CURLE_UNSUPPORTED_PROTOCOL;
            }
            if arg == CURL_HTTP_VERSION_NONE as i32 as i64 {
                arg = CURL_HTTP_VERSION_2TLS as i32 as i64;
            }
            (unsafe { (*data).set.httpwant = arg as u8 });
        }
        227 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.expect_100_timeout = arg });
        }
        285 => {
            arg = (unsafe { param.arg::<u64>() }) as i64;
            if arg > 1 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            let fresh43 = unsafe { &mut ((*data).set) };
            (*fresh43).set_http09_allowed((if arg != 0 { 1 as i32 } else { 0 as i32 }) as bit);
        }
        107 => {
            let mut bitcheck: i32 = 0;
            let mut authbits: bool = false;
            let mut auth: u64 = unsafe { param.arg::<u64>() };
            if auth == 0 as i32 as u64 {
                (unsafe { (*data).set.httpauth = auth });
            } else {
                let fresh44 = unsafe { &mut ((*data).state.authhost) };
                (*fresh44).set_iestyle(
                    (if auth & (1 as i32 as u64) << 4 as i32 != 0 {
                        1 as i32
                    } else {
                        0 as i32
                    } != 0) as bit,
                );
                if auth & (1 as i32 as u64) << 4 as i32 != 0 {
                    auth |= (1 as i32 as u64) << 1 as i32;
                    auth &= !((1 as i32 as u64) << 4 as i32);
                }
                auth &= !((1 as i32 as u64) << 2 as i32);
                bitcheck = 0 as i32;
                authbits = 0 as i32 != 0;
                while bitcheck < 31 as i32 {
                    let fresh45 = bitcheck;
                    bitcheck = bitcheck + 1;
                    if !(auth & (1 as u64) << fresh45 != 0) {
                        continue;
                    }
                    authbits = 1 as i32 != 0;
                    break;
                }
                if !authbits {
                    return CURLE_NOT_BUILT_IN;
                }
                (unsafe { (*data).set.httpauth = auth });
            }
        }
        10036 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_CUSTOMREQUEST as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        61 => {
            let fresh46 = unsafe { &mut ((*data).set) };
            (*fresh46).set_tunnel_thru_httpproxy(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        59 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 || arg > 65535 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.proxyport = arg });
        }
        111 => {
            let mut bitcheck_0: i32 = 0;
            let mut authbits_0: bool = false;
            let mut auth_0: u64 = unsafe { param.arg::<u64>() };
            if auth_0 == 0 as i32 as u64 {
                (unsafe { (*data).set.proxyauth = auth_0 });
            } else {
                let fresh47 = unsafe { &mut ((*data).state.authproxy) };
                (*fresh47).set_iestyle(
                    (if auth_0 & (1 as i32 as u64) << 4 as i32 != 0 {
                        1 as i32
                    } else {
                        0 as i32
                    } != 0) as bit,
                );
                if auth_0 & (1 as i32 as u64) << 4 as i32 != 0 {
                    auth_0 |= (1 as i32 as u64) << 1 as i32;
                    auth_0 &= !((1 as i32 as u64) << 4 as i32);
                }
                auth_0 &= !((1 as i32 as u64) << 2 as i32);
                bitcheck_0 = 0 as i32;
                authbits_0 = 0 as i32 != 0;
                while bitcheck_0 < 31 as i32 {
                    let fresh48 = bitcheck_0;
                    bitcheck_0 = bitcheck_0 + 1;
                    if !(auth_0 & (1 as u64) << fresh48 != 0) {
                        continue;
                    }
                    authbits_0 = 1 as i32 != 0;
                    break;
                }
                if !authbits_0 {
                    return CURLE_NOT_BUILT_IN;
                }
                (unsafe { (*data).set.proxyauth = auth_0 });
            }
        }
        10004 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_PROXY as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10262 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_PRE_PROXY as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        101 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < CURLPROXY_HTTP as i32 as i64 || arg > CURLPROXY_SOCKS5_HOSTNAME as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.proxytype = arg as curl_proxytype });
        }
        166 => match unsafe { param.arg::<i64>() } {
            0 => {
                let fresh49 = unsafe { &mut ((*data).set) };
                (*fresh49).set_proxy_transfer_mode(0 as i32 as bit);
            }
            1 => {
                let fresh50 = unsafe { &mut ((*data).set) };
                (*fresh50).set_proxy_transfer_mode(1 as i32 as bit);
            }
            _ => {
                result = CURLE_BAD_FUNCTION_ARGUMENT;
            }
        },
        267 => {
            (unsafe { (*data).set.socks5auth = param.arg::<u64>() });
            if (unsafe { (*data).set.socks5auth })
                & !((1 as i32 as u64) << 0 as i32 | (1 as i32 as u64) << 2 as i32)
                != 0
            {
                result = CURLE_NOT_BUILT_IN;
            }
        }
        10179 | 10235 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_PROXY_SERVICE_NAME as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10236 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SERVICE_NAME as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10029 => {
            let fresh51 = unsafe { &mut ((*data).set.writeheader) };
            *fresh51 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        10010 => {
            let fresh52 = unsafe { &mut ((*data).set.errorbuffer) };
            *fresh52 = unsafe { param.arg::<*mut i8>() };
        }
        10001 => {
            let fresh53 = unsafe { &mut ((*data).set.out) };
            *fresh53 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        48 => {
            let fresh54 = unsafe { &mut ((*data).set) };
            (*fresh54).set_list_only(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        50 => {
            let fresh55 = unsafe { &mut ((*data).set) };
            (*fresh55).set_remote_append(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        138 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < CURLFTPMETHOD_DEFAULT as i32 as i64 || arg >= CURLFTPMETHOD_LAST as i32 as i64
            {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.ftp_filemethod = arg as curl_ftpfile });
        }
        10017 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_FTPPORT as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
            let fresh56 = unsafe { &mut ((*data).set) };
            (*fresh56).set_ftp_use_port(
                (if !(unsafe { (*data).set.str_0[STRING_FTPPORT as i32 as usize] }).is_null() {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        106 => {
            let fresh57 = unsafe { &mut ((*data).set) };
            (*fresh57).set_ftp_use_eprt(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        85 => {
            let fresh58 = unsafe { &mut ((*data).set) };
            (*fresh58).set_ftp_use_epsv(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        188 => {
            let fresh59 = unsafe { &mut ((*data).set) };
            (*fresh59).set_ftp_use_pret(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        154 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < CURLFTPSSL_CCC_NONE as i32 as i64 || arg >= CURLFTPSSL_CCC_LAST as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.ftp_ccc = arg as curl_ftpccc });
        }
        137 => {
            let fresh60 = unsafe { &mut ((*data).set) };
            (*fresh60).set_ftp_skip_ip(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        10134 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_FTP_ACCOUNT as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10147 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_FTP_ALTERNATIVE_TO_USER as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        129 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < CURLFTPAUTH_DEFAULT as i32 as i64 || arg >= CURLFTPAUTH_LAST as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.ftpsslauth = arg as curl_ftpauth });
        }
        10063 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_KRB_LEVEL as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
            let fresh61 = unsafe { &mut ((*data).set) };
            (*fresh61).set_krb(
                (if !(unsafe { (*data).set.str_0[STRING_KRB_LEVEL as i32 as usize] }).is_null() {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        110 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < CURLFTP_CREATE_DIR_NONE as i32 as i64
                || arg > CURLFTP_CREATE_DIR_RETRY as i32 as i64
            {
                result = CURLE_BAD_FUNCTION_ARGUMENT;
            } else {
                (unsafe { (*data).set.ftp_create_missing_dirs = arg as i32 });
            }
        }
        10009 => {
            let fresh62 = unsafe { &mut ((*data).set.in_set) };
            *fresh62 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        14 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < -(1 as i32) as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.filesize = arg });
        }
        30115 => {
            bigsize = unsafe { param.arg::<curl_off_t>() };
            if bigsize < -(1 as i32) as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.filesize = bigsize });
        }
        19 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.low_speed_limit = arg });
        }
        30145 => {
            bigsize = unsafe { param.arg::<curl_off_t>() };
            if bigsize < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.max_send_speed = bigsize });
        }
        30146 => {
            bigsize = unsafe { param.arg::<curl_off_t>() };
            if bigsize < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.max_recv_speed = bigsize });
        }
        20 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.low_speed_time = arg });
        }
        10282 => {
            let fresh63 = unsafe { &mut ((*data).set.uh) };
            *fresh63 = (unsafe { param.arg::<*mut libc::c_void>() }) as *mut CURLU;
        }
        10002 => {
            if (unsafe { ((*data).state).url_alloc() }) != 0 {
                (unsafe { Curl_cfree.expect("non-null function pointer")(
                    (*data).state.url as *mut libc::c_void,
                ) });
                let fresh64 = unsafe { &mut ((*data).state.url) };
                *fresh64 = 0 as *mut i8;
                let fresh65 = unsafe { &mut ((*data).state) };
                (*fresh65).set_url_alloc(0 as i32 as bit);
            }
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SET_URL as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
            let fresh66 = unsafe { &mut ((*data).state.url) };
            *fresh66 = unsafe { (*data).set.str_0[STRING_SET_URL as i32 as usize] };
        }
        3 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 || arg > 65535 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.use_port = arg });
        }
        13 => {
            arg = unsafe { param.arg::<i64>() };
            if arg >= 0 as i32 as i64 && arg <= (2147483647 as i32 / 1000 as i32) as i64 {
                (unsafe { (*data).set.timeout = arg * 1000 as i32 as i64 });
            } else {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
        }
        155 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.timeout = arg });
        }
        78 => {
            arg = unsafe { param.arg::<i64>() };
            if arg >= 0 as i32 as i64 && arg <= (2147483647 as i32 / 1000 as i32) as i64 {
                (unsafe { (*data).set.connecttimeout = arg * 1000 as i32 as i64 });
            } else {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
        }
        156 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.connecttimeout = arg });
        }
        212 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.accepttimeout = arg });
        }
        10005 => {
            result = setstropt_userpwd(
                unsafe { param.arg::<*mut i8>() },
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_USERNAME as i32 as isize) },
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_PASSWORD as i32 as isize) },
            );
        }
        10173 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_USERNAME as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10174 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_PASSWORD as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10224 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_OPTIONS as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10220 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_BEARER as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10039 => {
            let fresh67 = unsafe { &mut ((*data).set.postquote) };
            *fresh67 = unsafe { param.arg::<*mut curl_slist>() };
        }
        10093 => {
            let fresh68 = unsafe { &mut ((*data).set.prequote) };
            *fresh68 = unsafe { param.arg::<*mut curl_slist>() };
        }
        10028 => {
            let fresh69 = unsafe { &mut ((*data).set.quote) };
            *fresh69 = unsafe { param.arg::<*mut curl_slist>() };
        }
        10203 => {
            let fresh70 = unsafe { &mut ((*data).set.resolve) };
            *fresh70 = unsafe { param.arg::<*mut curl_slist>() };
            let fresh71 = unsafe { &mut ((*data).state.resolve) };
            *fresh71 = unsafe { (*data).set.resolve };
        }
        20056 => {
            let fresh72 = unsafe { &mut ((*data).set.fprogress) };
            *fresh72 = unsafe { ::std::mem::transmute(param.arg::<*mut unsafe extern "C" fn(
                *mut libc::c_void,
                f64,
                f64,
                f64,
                f64,
            ) -> i32>()) };
            if unsafe { ((*data).set.fprogress).is_some() } {
                let fresh73 = unsafe { &mut ((*data).progress) };
                (*fresh73).set_callback(1 as i32 as bit);
            } else {
                let fresh74 = unsafe { &mut ((*data).progress) };
                (*fresh74).set_callback(0 as i32 as bit);
            }
        }
        20219 => {
            let fresh75 = unsafe { &mut ((*data).set.fxferinfo) };
            *fresh75 = unsafe { ::std::mem::transmute(param.arg::<*mut unsafe extern "C" fn(
                *mut libc::c_void,
                curl_off_t,
                curl_off_t,
                curl_off_t,
                curl_off_t,
            ) -> i32>()) };
            if unsafe { ((*data).set.fxferinfo).is_some() } {
                let fresh76 = unsafe { &mut ((*data).progress) };
                (*fresh76).set_callback(1 as i32 as bit);
            } else {
                let fresh77 = unsafe { &mut ((*data).progress) };
                (*fresh77).set_callback(0 as i32 as bit);
            }
        }
        10057 => {
            let fresh78 = unsafe { &mut ((*data).set.progress_client) };
            *fresh78 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        10006 => {
            result = setstropt_userpwd(
                unsafe { param.arg::<*mut i8>() },
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_PROXYUSERNAME as i32 as isize) },
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_PROXYPASSWORD as i32 as isize) },
            );
        }
        10175 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_PROXYUSERNAME as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10176 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_PROXYPASSWORD as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10177 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_NOPROXY as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10007 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SET_RANGE as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        21 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < -(1 as i32) as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.set_resume_from = arg });
        }
        30116 => {
            bigsize = unsafe { param.arg::<curl_off_t>() };
            if bigsize < -(1 as i32) as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.set_resume_from = bigsize });
        }
        20094 => {
            let fresh79 = unsafe { &mut ((*data).set.fdebug) };
            *fresh79 = unsafe { ::std::mem::transmute(param.arg::<*mut unsafe extern "C" fn(
                *mut CURL,
                curl_infotype,
                *mut i8,
                size_t,
                *mut libc::c_void,
            ) -> i32>()) };
        }
        10095 => {
            let fresh80 = unsafe { &mut ((*data).set.debugdata) };
            *fresh80 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        10037 => {
            let fresh81 = unsafe { &mut ((*data).set.err) };
            *fresh81 = unsafe { param.arg::<*mut FILE>() };
            if (unsafe { (*data).set.err }).is_null() {
                let fresh82 = unsafe { &mut ((*data).set.err) };
                *fresh82 = unsafe { stderr };
            }
        }
        20079 => {
            let fresh83 = unsafe { &mut ((*data).set.fwrite_header) };
            *fresh83 = unsafe { ::std::mem::transmute(param.arg::<*mut unsafe extern "C" fn(
                *mut i8,
                size_t,
                size_t,
                *mut libc::c_void,
            ) -> size_t>()) };
        }
        20011 => {
            let fresh84 = unsafe { &mut ((*data).set.fwrite_func) };
            *fresh84 = unsafe { ::std::mem::transmute(param.arg::<*mut unsafe extern "C" fn(
                *mut i8,
                size_t,
                size_t,
                *mut libc::c_void,
            ) -> size_t>()) };
            if unsafe { ((*data).set.fwrite_func).is_none() } {
                let fresh85 = unsafe { &mut ((*data).set) };
                (*fresh85).set_is_fwrite_set(0 as i32 as bit);
                let fresh86 = unsafe { &mut ((*data).set.fwrite_func) };
                *fresh86 = unsafe { ::std::mem::transmute::<
                    Option<unsafe extern "C" fn(*const libc::c_void, u64, u64, *mut FILE) -> u64>,
                    curl_write_callback,
                >(Some(
                    fwrite as unsafe extern "C" fn(*const libc::c_void, u64, u64, *mut FILE) -> u64,
                )) };
            } else {
                let fresh87 = unsafe { &mut ((*data).set) };
                (*fresh87).set_is_fwrite_set(1 as i32 as bit);
            }
        }
        20012 => {
            let fresh88 = unsafe { &mut ((*data).set.fread_func_set) };
            *fresh88 = unsafe { ::std::mem::transmute(param.arg::<*mut unsafe extern "C" fn(
                *mut i8,
                size_t,
                size_t,
                *mut libc::c_void,
            ) -> size_t>()) };
            if unsafe { ((*data).set.fread_func_set).is_none() } {
                let fresh89 = unsafe { &mut ((*data).set) };
                (*fresh89).set_is_fread_set(0 as i32 as bit);
                let fresh90 = unsafe { &mut ((*data).set.fread_func_set) };
                *fresh90 = unsafe { ::std::mem::transmute::<
                    Option<unsafe extern "C" fn(*mut libc::c_void, u64, u64, *mut FILE) -> u64>,
                    curl_read_callback,
                >(Some(
                    fread as unsafe extern "C" fn(*mut libc::c_void, u64, u64, *mut FILE) -> u64,
                )) };
            } else {
                let fresh91 = unsafe { &mut ((*data).set) };
                (*fresh91).set_is_fread_set(1 as i32 as bit);
            }
        }
        20167 => {
            let fresh92 = unsafe { &mut ((*data).set.seek_func) };
            *fresh92 = unsafe { ::std::mem::transmute(param.arg::<*mut unsafe extern "C" fn(
                *mut libc::c_void,
                curl_off_t,
                i32,
            ) -> i32>()) };
        }
        10168 => {
            let fresh93 = unsafe { &mut ((*data).set.seek_client) };
            *fresh93 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        20142 => {
            let fresh94 = unsafe { &mut ((*data).set.convfromnetwork) };
            *fresh94 =
                unsafe { ::std::mem::transmute(
                    param.arg::<*mut unsafe extern "C" fn(*mut i8, size_t) -> CURLcode>(),
                ) };
        }
        20143 => {
            let fresh95 = unsafe { &mut ((*data).set.convtonetwork) };
            *fresh95 =
                unsafe { ::std::mem::transmute(
                    param.arg::<*mut unsafe extern "C" fn(*mut i8, size_t) -> CURLcode>(),
                ) };
        }
        20144 => {
            let fresh96 = unsafe { &mut ((*data).set.convfromutf8) };
            *fresh96 =
                unsafe { ::std::mem::transmute(
                    param.arg::<*mut unsafe extern "C" fn(*mut i8, size_t) -> CURLcode>(),
                ) };
        }
        20130 => {
            let fresh97 = unsafe { &mut ((*data).set.ioctl_func) };
            *fresh97 = unsafe { ::std::mem::transmute(param.arg::<*mut unsafe extern "C" fn(
                *mut CURL,
                i32,
                *mut libc::c_void,
            )
                -> curlioerr>()) };
        }
        10131 => {
            let fresh98 = unsafe { &mut ((*data).set.ioctl_client) };
            *fresh98 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        10025 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_CERT as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        40291 => {
            result = Curl_setblobopt(
                unsafe { &mut *((*data).set.blobs)
                    .as_mut_ptr()
                    .offset(BLOB_CERT as i32 as isize) },
                unsafe { param.arg::<*mut curl_blob>() },
            );
        }
        10254 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_CERT_PROXY as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        40293 => {
            result = Curl_setblobopt(
                unsafe { &mut *((*data).set.blobs)
                    .as_mut_ptr()
                    .offset(BLOB_CERT_PROXY as i32 as isize) },
                unsafe { param.arg::<*mut curl_blob>() },
            );
        }
        10086 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_CERT_TYPE as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10255 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_CERT_TYPE_PROXY as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10087 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_KEY as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        40292 => {
            result = Curl_setblobopt(
                unsafe { &mut *((*data).set.blobs)
                    .as_mut_ptr()
                    .offset(BLOB_KEY as i32 as isize) },
                unsafe { param.arg::<*mut curl_blob>() },
            );
        }
        10256 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_KEY_PROXY as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        40294 => {
            result = Curl_setblobopt(
                unsafe { &mut *((*data).set.blobs)
                    .as_mut_ptr()
                    .offset(BLOB_KEY_PROXY as i32 as isize) },
                unsafe { param.arg::<*mut curl_blob>() },
            );
        }
        10088 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_KEY_TYPE as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10257 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_KEY_TYPE_PROXY as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10026 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_KEY_PASSWD as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10258 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_KEY_PASSWD_PROXY as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10089 => {
            argptr = unsafe { param.arg::<*mut i8>() };
            if !argptr.is_null() && (unsafe { *argptr.offset(0 as i32 as isize) }) as i32 != 0 {
                result = Curl_setstropt(
                    unsafe { &mut *((*data).set.str_0)
                        .as_mut_ptr()
                        .offset(STRING_SSL_ENGINE as i32 as isize) },
                    argptr,
                );
                if result as u64 == 0 {
                    result = unsafe { Curl_ssl_set_engine(data, argptr) };
                }
            }
        }
        90 => {
            Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SSL_ENGINE as i32 as isize) },
                0 as *const i8,
            );
            result = unsafe { Curl_ssl_set_engine_default(data) };
        }
        27 => {
            let fresh99 = unsafe { &mut ((*data).set) };
            (*fresh99).set_crlf(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        274 => {
            let fresh100 = unsafe { &mut ((*data).set) };
            (*fresh100).set_haproxyprotocol(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        10062 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_DEVICE as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        139 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 || arg > 65535 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.localport = curlx_sltous(arg) });
        }
        140 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 || arg > 65535 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.localportrange = curlx_sltosi(arg) });
        }
        210 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.gssapi_delegation = arg });
        }
        64 => {
            let fresh101 = unsafe { &mut ((*data).set.ssl.primary) };
            (*fresh101).set_verifypeer(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
            if !(unsafe { (*data).conn }).is_null() {
                let fresh102 = unsafe { &mut ((*(*data).conn).ssl_config) };
                (*fresh102).set_verifypeer(unsafe { ((*data).set.ssl.primary).verifypeer() });
            }
        }
        306 => {
            let fresh103 = unsafe { &mut ((*data).set) };
            (*fresh103).set_doh_verifypeer(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        248 => {
            let fresh104 = unsafe { &mut ((*data).set.proxy_ssl.primary) };
            (*fresh104).set_verifypeer(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
            if !(unsafe { (*data).conn }).is_null() {
                let fresh105 = unsafe { &mut ((*(*data).conn).proxy_ssl_config) };
                (*fresh105).set_verifypeer(unsafe { ((*data).set.proxy_ssl.primary).verifypeer() });
            }
        }
        81 => {
            arg = unsafe { param.arg::<i64>() };
            let fresh106 = unsafe { &mut ((*data).set.ssl.primary) };
            (*fresh106).set_verifyhost(
                (if arg & 3 as i32 as i64 != 0 {
                    1 as i32
                } else {
                    0 as i32
                } != 0) as bit,
            );
            if !(unsafe { (*data).conn }).is_null() {
                let fresh107 = unsafe { &mut ((*(*data).conn).ssl_config) };
                (*fresh107).set_verifyhost(unsafe { ((*data).set.ssl.primary).verifyhost() });
            }
        }
        307 => {
            arg = unsafe { param.arg::<i64>() };
            let fresh108 = unsafe { &mut ((*data).set) };
            (*fresh108).set_doh_verifyhost(
                (if arg & 3 as i32 as i64 != 0 {
                    1 as i32
                } else {
                    0 as i32
                } != 0) as bit,
            );
        }
        249 => {
            arg = unsafe { param.arg::<i64>() };
            let fresh109 = unsafe { &mut ((*data).set.proxy_ssl.primary) };
            (*fresh109).set_verifyhost(
                (if arg & 3 as i32 as i64 != 0 {
                    1 as i32
                } else {
                    0 as i32
                } != 0) as bit,
            );
            if !(unsafe { (*data).conn }).is_null() {
                let fresh110 = unsafe { &mut ((*(*data).conn).proxy_ssl_config) };
                (*fresh110).set_verifyhost(unsafe { ((*data).set.proxy_ssl.primary).verifyhost() });
            }
        }
        232 => {
            if !(unsafe { Curl_ssl_cert_status_request() }) {
                result = CURLE_NOT_BUILT_IN;
            } else {
                let fresh111 = unsafe { &mut ((*data).set.ssl.primary) };
                (*fresh111).set_verifystatus(
                    (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                        1 as i32
                    } else {
                        0 as i32
                    }) as bit,
                );
                if !(unsafe { (*data).conn }).is_null() {
                    let fresh112 = unsafe { &mut ((*(*data).conn).ssl_config) };
                    (*fresh112).set_verifystatus(unsafe { ((*data).set.ssl.primary).verifystatus() });
                }
            }
        }
        308 => {
            if !(unsafe { Curl_ssl_cert_status_request() }) {
                result = CURLE_NOT_BUILT_IN;
            } else {
                let fresh113 = unsafe { &mut ((*data).set) };
                (*fresh113).set_doh_verifystatus(
                    (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                        1 as i32
                    } else {
                        0 as i32
                    }) as bit,
                );
            }
        }
        20108 => {
            if (unsafe { (*Curl_ssl).supports }) & ((1 as i32) << 3 as i32) as u32 != 0 {
                let fresh114 = unsafe { &mut ((*data).set.ssl.fsslctx) };
                *fresh114 = unsafe { ::std::mem::transmute(param.arg::<*mut unsafe extern "C" fn(
                    *mut CURL,
                    *mut libc::c_void,
                    *mut libc::c_void,
                )
                    -> CURLcode>()) };
            } else {
                result = CURLE_NOT_BUILT_IN;
            }
        }
        10109 => {
            if (unsafe { (*Curl_ssl).supports }) & ((1 as i32) << 3 as i32) as u32 != 0 {
                let fresh115 = unsafe { &mut ((*data).set.ssl.fsslctxp) };
                *fresh115 = unsafe { param.arg::<*mut libc::c_void>() };
            } else {
                result = CURLE_NOT_BUILT_IN;
            }
        }
        233 => {
            if !(unsafe { Curl_ssl_false_start() }) {
                result = CURLE_NOT_BUILT_IN;
            } else {
                let fresh116 = unsafe { &mut ((*data).set.ssl) };
                (*fresh116).set_falsestart(
                    (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                        1 as i32
                    } else {
                        0 as i32
                    }) as bit,
                );
            }
        }
        172 => {
            if (unsafe { (*Curl_ssl).supports }) & ((1 as i32) << 1 as i32) as u32 != 0 {
                let fresh117 = unsafe { &mut ((*data).set.ssl) };
                (*fresh117).set_certinfo(
                    (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                        1 as i32
                    } else {
                        0 as i32
                    }) as bit,
                );
            } else {
                result = CURLE_NOT_BUILT_IN;
            }
        }
        10230 => {
            if (unsafe { (*Curl_ssl).supports }) & ((1 as i32) << 2 as i32) as u32 != 0 {
                result = Curl_setstropt(
                    unsafe { &mut *((*data).set.str_0)
                        .as_mut_ptr()
                        .offset(STRING_SSL_PINNEDPUBLICKEY as i32 as isize) },
                    unsafe { param.arg::<*mut i8>() },
                );
            } else {
                result = CURLE_NOT_BUILT_IN;
            }
        }
        10263 => {
            if (unsafe { (*Curl_ssl).supports }) & ((1 as i32) << 2 as i32) as u32 != 0 {
                result = Curl_setstropt(
                    unsafe { &mut *((*data).set.str_0)
                        .as_mut_ptr()
                        .offset(STRING_SSL_PINNEDPUBLICKEY_PROXY as i32 as isize) },
                    unsafe { param.arg::<*mut i8>() },
                );
            } else {
                result = CURLE_NOT_BUILT_IN;
            }
        }
        10065 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SSL_CAFILE as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        40309 => {
            if (unsafe { (*Curl_ssl).supports }) & ((1 as i32) << 6 as i32) as u32 != 0 {
                result = Curl_setblobopt(
                    unsafe { &mut *((*data).set.blobs)
                        .as_mut_ptr()
                        .offset(BLOB_CAINFO as i32 as isize) },
                    unsafe { param.arg::<*mut curl_blob>() },
                );
            } else {
                return CURLE_NOT_BUILT_IN;
            }
        }
        10246 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SSL_CAFILE_PROXY as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        40310 => {
            if (unsafe { (*Curl_ssl).supports }) & ((1 as i32) << 6 as i32) as u32 != 0 {
                result = Curl_setblobopt(
                    unsafe { &mut *((*data).set.blobs)
                        .as_mut_ptr()
                        .offset(BLOB_CAINFO_PROXY as i32 as isize) },
                    unsafe { param.arg::<*mut curl_blob>() },
                );
            } else {
                return CURLE_NOT_BUILT_IN;
            }
        }
        10097 => {
            if (unsafe { (*Curl_ssl).supports }) & ((1 as i32) << 0 as i32) as u32 != 0 {
                result = Curl_setstropt(
                    unsafe { &mut *((*data).set.str_0)
                        .as_mut_ptr()
                        .offset(STRING_SSL_CAPATH as i32 as isize) },
                    unsafe { param.arg::<*mut i8>() },
                );
            } else {
                result = CURLE_NOT_BUILT_IN;
            }
        }
        10247 => {
            if (unsafe { (*Curl_ssl).supports }) & ((1 as i32) << 0 as i32) as u32 != 0 {
                result = Curl_setstropt(
                    unsafe { &mut *((*data).set.str_0)
                        .as_mut_ptr()
                        .offset(STRING_SSL_CAPATH_PROXY as i32 as isize) },
                    unsafe { param.arg::<*mut i8>() },
                );
            } else {
                result = CURLE_NOT_BUILT_IN;
            }
        }
        10169 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SSL_CRLFILE as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10260 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SSL_CRLFILE_PROXY as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10170 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SSL_ISSUERCERT as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        40295 => {
            result = Curl_setblobopt(
                unsafe { &mut *((*data).set.blobs)
                    .as_mut_ptr()
                    .offset(BLOB_SSL_ISSUERCERT as i32 as isize) },
                unsafe { param.arg::<*mut curl_blob>() },
            );
        }
        10296 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SSL_ISSUERCERT_PROXY as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        40297 => {
            result = Curl_setblobopt(
                unsafe { &mut *((*data).set.blobs)
                    .as_mut_ptr()
                    .offset(BLOB_SSL_ISSUERCERT_PROXY as i32 as isize) },
                unsafe { param.arg::<*mut curl_blob>() },
            );
        }
        10070 => {
            let fresh118 = unsafe { &mut ((*data).set.telnet_options) };
            *fresh118 = unsafe { param.arg::<*mut curl_slist>() };
        }
        98 => {
            if !(unsafe { (*data).state.buffer }).is_null() {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            arg = unsafe { param.arg::<i64>() };
            if arg > 524288 as i32 as i64 {
                arg = 524288 as i32 as i64;
            } else if arg < 1 as i32 as i64 {
                arg = 16384 as i32 as i64;
            } else if arg < 1024 as i32 as i64 {
                arg = 1024 as i32 as i64;
            }
            (unsafe { (*data).set.buffer_size = arg });
        }
        280 => {
            arg = unsafe { param.arg::<i64>() };
            if arg > (2 as i32 * 1024 as i32 * 1024 as i32) as i64 {
                arg = (2 as i32 * 1024 as i32 * 1024 as i32) as i64;
            } else if arg < 16384 as i32 as i64 {
                arg = 16384 as i32 as i64;
            }
            (unsafe { (*data).set.upload_buffer_size = arg as u32 });
            (unsafe { Curl_cfree.expect("non-null function pointer")(
                (*data).state.ulbuf as *mut libc::c_void,
            ) });
            let fresh119 = unsafe { &mut ((*data).state.ulbuf) };
            *fresh119 = 0 as *mut i8;
        }
        99 => {
            let fresh120 = unsafe { &mut ((*data).set) };
            (*fresh120).set_no_signal(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        10100 => {
            let mut set: *mut Curl_share = 0 as *mut Curl_share;
            set = unsafe { param.arg::<*mut Curl_share>() };
            if !(unsafe { (*data).share }).is_null() {
                (unsafe { Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE) });
                if (unsafe { (*data).dns.hostcachetype }) as u32 == HCACHE_SHARED as i32 as u32 {
                    let fresh121 = unsafe { &mut ((*data).dns.hostcache) };
                    *fresh121 = 0 as *mut Curl_hash;
                    (unsafe { (*data).dns.hostcachetype = HCACHE_NONE });
                }
                if (unsafe { (*(*data).share).cookies }) == (unsafe { (*data).cookies }) {
                    let fresh122 = unsafe { &mut ((*data).cookies) };
                    *fresh122 = 0 as *mut CookieInfo;
                }
                if (unsafe { (*(*data).share).sslsession }) == (unsafe { (*data).state.session }) {
                    let fresh123 = unsafe { &mut ((*data).state.session) };
                    *fresh123 = 0 as *mut Curl_ssl_session;
                }
                if (unsafe { (*data).psl }) == (unsafe { &mut (*(*data).share).psl }) as *mut PslCache {
                    let fresh124 = unsafe { &mut ((*data).psl) };
                    *fresh124 = if !(unsafe { (*data).multi }).is_null() {
                        unsafe { &mut (*(*data).multi).psl }
                    } else {
                        0 as *mut PslCache
                    };
                }
                let fresh125 = unsafe { &mut ((*(*data).share).dirty) };
                (unsafe { ::std::ptr::write_volatile(
                    fresh125,
                    (::std::ptr::read_volatile::<u32>(fresh125 as *const u32)).wrapping_sub(1),
                ) });
                (unsafe { Curl_share_unlock(data, CURL_LOCK_DATA_SHARE) });
                let fresh126 = unsafe { &mut ((*data).share) };
                *fresh126 = 0 as *mut Curl_share;
            }
            if !set.is_null() && (unsafe { (*set).magic }) == 0x7e117a1e as i32 as u32 {
                let fresh127 = unsafe { &mut ((*data).share) };
                *fresh127 = set;
            }
            if !(unsafe { (*data).share }).is_null() {
                (unsafe { Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE) });
                let fresh128 = unsafe { &mut ((*(*data).share).dirty) };
                (unsafe { ::std::ptr::write_volatile(
                    fresh128,
                    (::std::ptr::read_volatile::<u32>(fresh128 as *const u32)).wrapping_add(1),
                ) });
                if (unsafe { (*(*data).share).specifier }) & ((1 as i32) << CURL_LOCK_DATA_DNS as i32) as u32
                    != 0
                {
                    let fresh129 = unsafe { &mut ((*data).dns.hostcache) };
                    *fresh129 = unsafe { &mut (*(*data).share).hostcache };
                    (unsafe { (*data).dns.hostcachetype = HCACHE_SHARED });
                }
                if !(unsafe { (*(*data).share).cookies }).is_null() {
                    (unsafe { Curl_cookie_cleanup((*data).cookies) });
                    let fresh130 = unsafe { &mut ((*data).cookies) };
                    *fresh130 = unsafe { (*(*data).share).cookies };
                }
                if !(unsafe { (*(*data).share).sslsession }).is_null() {
                    (unsafe { (*data).set.general_ssl.max_ssl_sessions = (*(*data).share).max_ssl_sessions });
                    let fresh131 = unsafe { &mut ((*data).state.session) };
                    *fresh131 = unsafe { (*(*data).share).sslsession };
                }
                if (unsafe { (*(*data).share).specifier }) & ((1 as i32) << CURL_LOCK_DATA_PSL as i32) as u32
                    != 0
                {
                    let fresh132 = unsafe { &mut ((*data).psl) };
                    *fresh132 = unsafe { &mut (*(*data).share).psl };
                }
                (unsafe { Curl_share_unlock(data, CURL_LOCK_DATA_SHARE) });
            }
        }
        10103 => {
            let fresh133 = unsafe { &mut ((*data).set.private_data) };
            *fresh133 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        114 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.max_filesize = arg });
        }
        119 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < CURLUSESSL_NONE as i32 as i64 || arg >= CURLUSESSL_LAST as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.use_ssl = arg as curl_usessl });
        }
        216 => {
            arg = unsafe { param.arg::<i64>() };
            let fresh134 = unsafe { &mut ((*data).set.ssl) };
            (*fresh134)
                .set_enable_beast((arg & ((1 as i32) << 0 as i32) as i64 != 0) as i32 as bit);
            let fresh135 = unsafe { &mut ((*data).set.ssl) };
            (*fresh135).set_no_revoke((arg & ((1 as i32) << 1 as i32) as i64 != 0) as i32 as bit);
            let fresh136 = unsafe { &mut ((*data).set.ssl) };
            (*fresh136)
                .set_no_partialchain((arg & ((1 as i32) << 2 as i32) as i64 != 0) as i32 as bit);
            let fresh137 = unsafe { &mut ((*data).set.ssl) };
            (*fresh137)
                .set_revoke_best_effort((arg & ((1 as i32) << 3 as i32) as i64 != 0) as i32 as bit);
            let fresh138 = unsafe { &mut ((*data).set.ssl) };
            (*fresh138)
                .set_native_ca_store((arg & ((1 as i32) << 4 as i32) as i64 != 0) as i32 as bit);
            let fresh139 = unsafe { &mut ((*data).set.ssl) };
            (*fresh139)
                .set_auto_client_cert((arg & ((1 as i32) << 5 as i32) as i64 != 0) as i32 as bit);
        }
        261 => {
            arg = unsafe { param.arg::<i64>() };
            let fresh140 = unsafe { &mut ((*data).set.proxy_ssl) };
            (*fresh140)
                .set_enable_beast((arg & ((1 as i32) << 0 as i32) as i64 != 0) as i32 as bit);
            let fresh141 = unsafe { &mut ((*data).set.proxy_ssl) };
            (*fresh141).set_no_revoke((arg & ((1 as i32) << 1 as i32) as i64 != 0) as i32 as bit);
            let fresh142 = unsafe { &mut ((*data).set.proxy_ssl) };
            (*fresh142)
                .set_no_partialchain((arg & ((1 as i32) << 2 as i32) as i64 != 0) as i32 as bit);
            let fresh143 = unsafe { &mut ((*data).set.proxy_ssl) };
            (*fresh143)
                .set_revoke_best_effort((arg & ((1 as i32) << 3 as i32) as i64 != 0) as i32 as bit);
            let fresh144 = unsafe { &mut ((*data).set.proxy_ssl) };
            (*fresh144)
                .set_native_ca_store((arg & ((1 as i32) << 4 as i32) as i64 != 0) as i32 as bit);
            let fresh145 = unsafe { &mut ((*data).set.proxy_ssl) };
            (*fresh145)
                .set_auto_client_cert((arg & ((1 as i32) << 5 as i32) as i64 != 0) as i32 as bit);
        }
        10298 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SSL_EC_CURVES as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        113 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 || arg > 2 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.ipver = arg as u8 });
        }
        30117 => {
            bigsize = unsafe { param.arg::<curl_off_t>() };
            if bigsize < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.max_filesize = bigsize });
        }
        121 => {
            let fresh146 = unsafe { &mut ((*data).set) };
            (*fresh146).set_tcp_nodelay(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        136 => {
            let fresh147 = unsafe { &mut ((*data).set) };
            (*fresh147).set_ignorecl(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        141 => {
            let fresh148 = unsafe { &mut ((*data).set) };
            (*fresh148).set_connect_only(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        20148 => {
            let fresh149 = unsafe { &mut ((*data).set.fsockopt) };
            *fresh149 = unsafe { ::std::mem::transmute(param.arg::<*mut unsafe extern "C" fn(
                *mut libc::c_void,
                curl_socket_t,
                curlsocktype,
            ) -> i32>()) };
        }
        10149 => {
            let fresh150 = unsafe { &mut ((*data).set.sockopt_client) };
            *fresh150 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        20163 => {
            let fresh151 = unsafe { &mut ((*data).set.fopensocket) };
            *fresh151 = unsafe { ::std::mem::transmute(param.arg::<*mut unsafe extern "C" fn(
                *mut libc::c_void,
                curlsocktype,
                *mut curl_sockaddr,
            )
                -> curl_socket_t>()) };
        }
        10164 => {
            let fresh152 = unsafe { &mut ((*data).set.opensocket_client) };
            *fresh152 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        20208 => {
            let fresh153 = unsafe { &mut ((*data).set.fclosesocket) };
            *fresh153 = unsafe { ::std::mem::transmute(
                param.arg::<*mut unsafe extern "C" fn(*mut libc::c_void, curl_socket_t) -> i32>(),
            ) };
        }
        20272 => {
            let fresh154 = unsafe { &mut ((*data).set.resolver_start) };
            *fresh154 = unsafe { ::std::mem::transmute(param.arg::<*mut unsafe extern "C" fn(
                *mut libc::c_void,
                *mut libc::c_void,
                *mut libc::c_void,
            ) -> i32>()) };
        }
        10273 => {
            let fresh155 = unsafe { &mut ((*data).set.resolver_start_client) };
            *fresh155 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        10209 => {
            let fresh156 = unsafe { &mut ((*data).set.closesocket_client) };
            *fresh156 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        150 => {
            let fresh157 = unsafe { &mut ((*data).set.ssl.primary) };
            (*fresh157).set_sessionid(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
            let fresh158 = unsafe { &mut ((*data).set.proxy_ssl.primary) };
            (*fresh158).set_sessionid(unsafe { ((*data).set.ssl.primary).sessionid() });
        }
        157 => {
            let fresh159 = unsafe { &mut ((*data).set) };
            (*fresh159).set_http_te_skip(
                (if 0 as i32 as i64 == (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        158 => {
            let fresh160 = unsafe { &mut ((*data).set) };
            (*fresh160).set_http_ce_skip(
                (if 0 as i32 as i64 == (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        159 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 || arg > 0o777 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.new_file_perms = arg });
        }
        160 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 || arg > 0o777 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.new_directory_perms = arg });
        }
        171 => {
            uarg = unsafe { param.arg::<u64>() };
            if uarg
                > (2147483647 as i32 as u32)
                    .wrapping_mul(2 as u32)
                    .wrapping_add(1 as u32) as u64
            {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.scope_id = uarg as u32 });
        }
        181 => {
            (unsafe { (*data).set.allowed_protocols = param.arg::<i64>() });
        }
        182 => {
            (unsafe { (*data).set.redir_protocols = param.arg::<i64>() });
        }
        10238 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_DEFAULT_PROTOCOL as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10186 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_MAIL_FROM as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10217 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_MAIL_AUTH as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10187 => {
            let fresh161 = unsafe { &mut ((*data).set.mail_rcpt) };
            *fresh161 = unsafe { param.arg::<*mut curl_slist>() };
        }
        290 => {
            let fresh162 = unsafe { &mut ((*data).set) };
            (*fresh162).set_mail_rcpt_allowfails(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        10289 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_SASL_AUTHZID as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        218 => {
            let fresh163 = unsafe { &mut ((*data).set) };
            (*fresh163).set_sasl_ir(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        189 => {
            let mut in_rtspreq: i64 = unsafe { param.arg::<i64>() };
            let mut rtspreq: Curl_RtspReq = RTSPREQ_NONE;
            match in_rtspreq {
                1 => {
                    rtspreq = RTSPREQ_OPTIONS;
                }
                2 => {
                    rtspreq = RTSPREQ_DESCRIBE;
                }
                3 => {
                    rtspreq = RTSPREQ_ANNOUNCE;
                }
                4 => {
                    rtspreq = RTSPREQ_SETUP;
                }
                5 => {
                    rtspreq = RTSPREQ_PLAY;
                }
                6 => {
                    rtspreq = RTSPREQ_PAUSE;
                }
                7 => {
                    rtspreq = RTSPREQ_TEARDOWN;
                }
                8 => {
                    rtspreq = RTSPREQ_GET_PARAMETER;
                }
                9 => {
                    rtspreq = RTSPREQ_SET_PARAMETER;
                }
                10 => {
                    rtspreq = RTSPREQ_RECORD;
                }
                11 => {
                    rtspreq = RTSPREQ_RECEIVE;
                }
                _ => {
                    rtspreq = RTSPREQ_NONE;
                }
            }
            (unsafe { (*data).set.rtspreq = rtspreq });
        }
        10190 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_RTSP_SESSION_ID as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10191 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_RTSP_STREAM_URI as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10192 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_RTSP_TRANSPORT as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        193 => {
            (unsafe { (*data).state.rtsp_next_client_CSeq = param.arg::<i64>() });
        }
        194 => {
            (unsafe { (*data).state.rtsp_next_server_CSeq = param.arg::<i64>() });
        }
        10195 => {
            let fresh164 = unsafe { &mut ((*data).set.rtp_out) };
            *fresh164 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        20196 => {
            let fresh165 = unsafe { &mut ((*data).set.fwrite_rtp) };
            *fresh165 = unsafe { ::std::mem::transmute(param.arg::<*mut unsafe extern "C" fn(
                *mut i8,
                size_t,
                size_t,
                *mut libc::c_void,
            )
                -> size_t>()) };
        }
        197 => {
            let fresh166 = unsafe { &mut ((*data).set) };
            (*fresh166).set_wildcard_enabled(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        20198 => {
            let fresh167 = unsafe { &mut ((*data).set.chunk_bgn) };
            *fresh167 = unsafe { ::std::mem::transmute(param.arg::<*mut unsafe extern "C" fn(
                *const libc::c_void,
                *mut libc::c_void,
                i32,
            ) -> i64>()) };
        }
        20199 => {
            let fresh168 = unsafe { &mut ((*data).set.chunk_end) };
            *fresh168 = unsafe { ::std::mem::transmute(
                param.arg::<*mut unsafe extern "C" fn(*mut libc::c_void) -> i64>(),
            ) };
        }
        20200 => {
            let fresh169 = unsafe { &mut ((*data).set.fnmatch) };
            *fresh169 = unsafe { ::std::mem::transmute(param.arg::<*mut unsafe extern "C" fn(
                *mut libc::c_void,
                *const i8,
                *const i8,
            ) -> i32>()) };
        }
        10201 => {
            let fresh170 = unsafe { &mut ((*data).wildcard.customptr) };
            *fresh170 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        10202 => {
            let fresh171 = unsafe { &mut ((*data).set.fnmatch_data) };
            *fresh171 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        10204 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_TLSAUTH_USERNAME as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
            if !(unsafe { (*data).set.str_0[STRING_TLSAUTH_USERNAME as i32 as usize] }).is_null()
                && (unsafe { (*data).set.ssl.authtype }) as u64 == 0
            {
                (unsafe { (*data).set.ssl.authtype = CURL_TLSAUTH_SRP });
            }
        }
        10251 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_TLSAUTH_USERNAME_PROXY as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
            if !(unsafe { (*data).set.str_0[STRING_TLSAUTH_USERNAME_PROXY as i32 as usize] }).is_null()
                && (unsafe { (*data).set.proxy_ssl.authtype }) as u64 == 0
            {
                (unsafe { (*data).set.proxy_ssl.authtype = CURL_TLSAUTH_SRP });
            }
        }
        10205 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_TLSAUTH_PASSWORD as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
            if !(unsafe { (*data).set.str_0[STRING_TLSAUTH_USERNAME as i32 as usize] }).is_null()
                && (unsafe { (*data).set.ssl.authtype }) as u64 == 0
            {
                (unsafe { (*data).set.ssl.authtype = CURL_TLSAUTH_SRP });
            }
        }
        10252 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_TLSAUTH_PASSWORD_PROXY as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
            if !(unsafe { (*data).set.str_0[STRING_TLSAUTH_USERNAME_PROXY as i32 as usize] }).is_null()
                && (unsafe { (*data).set.proxy_ssl.authtype }) as u64 == 0
            {
                (unsafe { (*data).set.proxy_ssl.authtype = CURL_TLSAUTH_SRP });
            }
        }
        10206 => {
            argptr = unsafe { param.arg::<*mut i8>() };
            if argptr.is_null()
                || (unsafe { Curl_strncasecompare(
                    argptr,
                    b"SRP\0" as *const u8 as *const i8,
                    strlen(b"SRP\0" as *const u8 as *const i8),
                ) }) != 0
            {
                (unsafe { (*data).set.ssl.authtype = CURL_TLSAUTH_SRP });
            } else {
                (unsafe { (*data).set.ssl.authtype = CURL_TLSAUTH_NONE });
            }
        }
        10253 => {
            argptr = unsafe { param.arg::<*mut i8>() };
            if argptr.is_null()
                || (unsafe { Curl_strncasecompare(
                    argptr,
                    b"SRP\0" as *const u8 as *const i8,
                    strlen(b"SRP\0" as *const u8 as *const i8),
                ) }) != 0
            {
                (unsafe { (*data).set.proxy_ssl.authtype = CURL_TLSAUTH_SRP });
            } else {
                (unsafe { (*data).set.proxy_ssl.authtype = CURL_TLSAUTH_NONE });
            }
        }
        213 => {
            let fresh172 = unsafe { &mut ((*data).set) };
            (*fresh172).set_tcp_keepalive(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        214 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.tcp_keepidle = arg });
        }
        215 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.tcp_keepintvl = arg });
        }
        244 => {
            let fresh173 = unsafe { &mut ((*data).set) };
            (*fresh173).set_tcp_fastopen(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        225 => {
            let fresh174 = unsafe { &mut ((*data).set) };
            (*fresh174).set_ssl_enable_npn(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        226 => {
            let fresh175 = unsafe { &mut ((*data).set) };
            (*fresh175).set_ssl_enable_alpn(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        10231 => {
            let fresh176 = unsafe { &mut ((*data).set) };
            (*fresh176).set_abstract_unix_socket(0 as i32 as bit);
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_UNIX_SOCKET_PATH as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        10264 => {
            let fresh177 = unsafe { &mut ((*data).set) };
            (*fresh177).set_abstract_unix_socket(1 as i32 as bit);
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_UNIX_SOCKET_PATH as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
        }
        234 => {
            let fresh178 = unsafe { &mut ((*data).set) };
            (*fresh178).set_path_as_is(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        237 => {
            let fresh179 = unsafe { &mut ((*data).set) };
            (*fresh179).set_pipewait(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        239 => {
            arg = unsafe { param.arg::<i64>() };
            if arg >= 1 as i32 as i64 && arg <= 256 as i32 as i64 {
                (unsafe { (*data).set.stream_weight = arg as i32 });
            }
        }
        10240 | 10241 => {
            let mut dep: *mut Curl_easy = unsafe { param.arg::<*mut Curl_easy>() };
            if dep.is_null() || !dep.is_null() && (unsafe { (*dep).magic }) == 0xc0dedbad as u32 {
                if !(unsafe { (*data).set.stream_depends_on }).is_null() {
                    (unsafe { Curl_http2_remove_child((*data).set.stream_depends_on, data) });
                }
                (unsafe { Curl_http2_add_child(
                    dep,
                    data,
                    option as u32 == CURLOPT_STREAM_DEPENDS_E as i32 as u32,
                ) });
            }
        }
        10243 => {
            let fresh180 = unsafe { &mut ((*data).set.connect_to) };
            *fresh180 = unsafe { param.arg::<*mut curl_slist>() };
        }
        265 => {
            let fresh181 = unsafe { &mut ((*data).set) };
            (*fresh181).set_suppress_connect_headers(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        271 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.happy_eyeballs_timeout = arg });
        }
        275 => {
            let fresh182 = unsafe { &mut ((*data).set) };
            (*fresh182).set_dns_shuffle_addresses(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        278 => {
            let fresh183 = unsafe { &mut ((*data).set) };
            (*fresh183).set_disallow_username_in_url(
                (if 0 as i32 as i64 != (unsafe { param.arg::<i64>() }) {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        10279 => {
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_DOH as i32 as isize) },
                unsafe { param.arg::<*mut i8>() },
            );
            let fresh184 = unsafe { &mut ((*data).set) };
            (*fresh184).set_doh(
                (if !(unsafe { (*data).set.str_0[STRING_DOH as i32 as usize] }).is_null() {
                    1 as i32
                } else {
                    0 as i32
                }) as bit,
            );
        }
        281 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.upkeep_interval_ms = arg });
        }
        288 => {
            arg = unsafe { param.arg::<i64>() };
            if arg < 0 as i32 as i64 {
                return CURLE_BAD_FUNCTION_ARGUMENT;
            }
            (unsafe { (*data).set.maxage_conn = arg });
        }
        20283 => {
            let fresh185 = unsafe { &mut ((*data).set.trailer_callback) };
            * fresh185 = unsafe { :: std :: mem :: transmute (param . arg :: < * mut unsafe extern "C" fn (* mut * mut curl_slist , * mut libc :: c_void ,) -> i32 , > () ,) } ;
        }
        10284 => {
            let fresh186 = unsafe { &mut ((*data).set.trailer_data) };
            *fresh186 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        20301 => {
            let fresh187 = unsafe { &mut ((*data).set.hsts_read) };
            *fresh187 = unsafe { ::std::mem::transmute(param.arg::<*mut unsafe extern "C" fn(
                *mut CURL,
                *mut curl_hstsentry,
                *mut libc::c_void,
            )
                -> CURLSTScode>()) };
        }
        10302 => {
            let fresh188 = unsafe { &mut ((*data).set.hsts_read_userp) };
            *fresh188 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        20303 => {
            let fresh189 = unsafe { &mut ((*data).set.hsts_write) };
            *fresh189 = unsafe { ::std::mem::transmute(param.arg::<*mut unsafe extern "C" fn(
                *mut CURL,
                *mut curl_hstsentry,
                *mut curl_index,
                *mut libc::c_void,
            )
                -> CURLSTScode>()) };
        }
        10304 => {
            let fresh190 = unsafe { &mut ((*data).set.hsts_write_userp) };
            *fresh190 = unsafe { param.arg::<*mut libc::c_void>() };
        }
        10300 => {
            if (unsafe { (*data).hsts }).is_null() {
                let fresh191 = unsafe { &mut ((*data).hsts) };
                *fresh191 = unsafe { Curl_hsts_init() };
                if (unsafe { (*data).hsts }).is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
            }
            argptr = unsafe { param.arg::<*mut i8>() };
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_HSTS as i32 as isize) },
                argptr,
            );
            if result as u64 != 0 {
                return result;
            }
            if !argptr.is_null() {
                (unsafe { Curl_hsts_loadfile(data, (*data).hsts, argptr) });
            }
        }
        299 => {
            arg = unsafe { param.arg::<i64>() };
            if arg & ((1 as i32) << 0 as i32) as i64 != 0 {
                if (unsafe { (*data).hsts }).is_null() {
                    let fresh192 = unsafe { &mut ((*data).hsts) };
                    *fresh192 = unsafe { Curl_hsts_init() };
                    if (unsafe { (*data).hsts }).is_null() {
                        return CURLE_OUT_OF_MEMORY;
                    }
                }
            } else {
                (unsafe { Curl_hsts_cleanup(&mut (*data).hsts) });
            }
        }
        10287 => {
            if (unsafe { (*data).asi }).is_null() {
                let fresh193 = unsafe { &mut ((*data).asi) };
                *fresh193 = unsafe { Curl_altsvc_init() };
                if (unsafe { (*data).asi }).is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
            }
            argptr = unsafe { param.arg::<*mut i8>() };
            result = Curl_setstropt(
                unsafe { &mut *((*data).set.str_0)
                    .as_mut_ptr()
                    .offset(STRING_ALTSVC as i32 as isize) },
                argptr,
            );
            if result as u64 != 0 {
                return result;
            }
            if !argptr.is_null() {
                (unsafe { Curl_altsvc_load((*data).asi, argptr) });
            }
        }
        286 => {
            if (unsafe { (*data).asi }).is_null() {
                let fresh194 = unsafe { &mut ((*data).asi) };
                *fresh194 = unsafe { Curl_altsvc_init() };
                if (unsafe { (*data).asi }).is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
            }
            arg = unsafe { param.arg::<i64>() };
            result = unsafe { Curl_altsvc_ctrl((*data).asi, arg) };
            if result as u64 != 0 {
                return result;
            }
        }
        _ => {
            result = CURLE_UNKNOWN_OPTION;
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn curl_easy_setopt(
    mut data: *mut Curl_easy,
    mut tag: CURLoption,
    mut args: ...
) -> CURLcode {
    let mut arg: ::std::ffi::VaListImpl;
    let mut result: CURLcode = CURLE_OK;
    if data.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    arg = args.clone();
    result = Curl_vsetopt(data, tag, arg.as_va_list());
    return result;
}
