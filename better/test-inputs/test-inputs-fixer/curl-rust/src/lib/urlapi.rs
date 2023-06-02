use :: c2rust_bitfields;
use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type thread_data;
    pub type altsvcinfo;
    pub type hsts;
    pub type TELNET;
    pub type smb_request;
    pub type ldapreqinfo;
    pub type contenc_writer;
    pub type psl_ctx_st;
    pub type Curl_share;
    pub type curl_pushheaders;
    pub type http_connect_state;
    pub type ldapconninfo;
    pub type tftp_state_data;
    pub type nghttp2_session;
    pub type Gsasl_session;
    pub type Gsasl;
    pub type ssl_backend_data;
    fn sscanf(_: *const i8, _: *const i8, _: ...) -> i32;
    fn curl_strnequal(s1: *const i8, s2: *const i8, n: size_t) -> i32;
    fn strlen(_: *const i8) -> u64;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn strcspn(_: *const i8, _: *const i8) -> u64;
    fn strncmp(_: *const i8, _: *const i8, _: u64) -> i32;
    fn strspn(_: *const i8, _: *const i8) -> u64;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn __ctype_tolower_loc() -> *mut *const __int32_t;
    fn Curl_isupper(c: i32) -> i32;
    fn Curl_isxdigit(c: i32) -> i32;
    fn __errno_location() -> *mut i32;
    fn strtoul(_: *const i8, _: *mut *mut i8, _: i32) -> u64;
    fn strtol(_: *const i8, _: *mut *mut i8, _: i32) -> i64;
    fn Curl_isdigit(c: i32) -> i32;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn Curl_isgraph(c: i32) -> i32;
    fn Curl_isspace(c: i32) -> i32;
    fn Curl_iscntrl(c: i32) -> i32;
    fn strstr(_: *const i8, _: *const i8) -> *mut i8;
    fn Curl_isalnum(c: i32) -> i32;
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn strrchr(_: *const i8, _: i32) -> *mut i8;
    fn inet_pton(__af: i32, __cp: *const i8, __buf: *mut libc::c_void) -> i32;
    fn Curl_strcasecompare(first: *const i8, second: *const i8) -> i32;
    fn Curl_dedotdotify(input: *const i8) -> *mut i8;
    fn Curl_parse_login_details(
        login: *const i8,
        len: size_t,
        userptr: *mut *mut i8,
        passwdptr: *mut *mut i8,
        optionsptr: *mut *mut i8,
    ) -> CURLcode;
    fn Curl_builtin_scheme(scheme: *const i8) -> *const Curl_handler;
    fn Curl_isunreserved(in_0: u8) -> bool;
    fn Curl_urldecode(
        data: *mut Curl_easy,
        string: *const i8,
        length: size_t,
        ostring: *mut *mut i8,
        olen: *mut size_t,
        ctrl: urlreject,
    ) -> CURLcode;
    fn curl_msnprintf(buffer: *mut i8, maxlength: size_t, format: *const i8, _: ...) -> i32;
    fn curl_maprintf(format: *const i8, _: ...) -> *mut i8;
    static mut Curl_cmalloc: curl_malloc_callback;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_cstrdup: curl_strdup_callback;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_URL {
    pub scheme: *mut i8,
    pub user: *mut i8,
    pub password: *mut i8,
    pub options: *mut i8,
    pub host: *mut i8,
    pub zoneid: *mut i8,
    pub port: *mut i8,
    pub path: *mut i8,
    pub query: *mut i8,
    pub fragment: *mut i8,
    pub scratch: *mut i8,
    pub temppath: *mut i8,
    pub portnum: i64,
}
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
pub type curl_calloc_callback = Option<unsafe extern "C" fn(size_t, size_t) -> *mut libc::c_void>;
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
pub type urlreject = u32;
pub const REJECT_ZERO: urlreject = 4;
pub const REJECT_CTRL: urlreject = 3;
pub const REJECT_NADA: urlreject = 2;
#[inline]
extern "C" fn tolower(mut __c: i32) -> i32 {
    return if __c >= -(128 as i32) && __c < 256 as i32 {
        unsafe { *(*__ctype_tolower_loc()).offset(__c as isize) }
    } else {
        __c
    };
}
extern "C" fn free_urlhandle(mut u: *mut Curl_URL) {
    (unsafe { Curl_cfree.expect("non-null function pointer")((*u).scheme as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*u).user as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*u).password as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*u).options as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*u).host as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*u).zoneid as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*u).port as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*u).path as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*u).query as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*u).fragment as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*u).scratch as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*u).temppath as *mut libc::c_void) });
}
extern "C" fn mv_urlhandle(mut from: *mut Curl_URL, mut to: *mut Curl_URL) {
    free_urlhandle(to);
    (unsafe { *to = *from });
    (unsafe { Curl_cfree.expect("non-null function pointer")(from as *mut libc::c_void) });
}
extern "C" fn find_host_sep(mut url: *const i8) -> *const i8 {
    let mut sep: *const i8 = 0 as *const i8;
    let mut query: *const i8 = 0 as *const i8;
    sep = unsafe { strstr(url, b"//\0" as *const u8 as *const i8) };
    if sep.is_null() {
        sep = url;
    } else {
        sep = unsafe { sep.offset(2 as i32 as isize) };
    }
    query = unsafe { strchr(sep, '?' as i32) };
    sep = unsafe { strchr(sep, '/' as i32) };
    if sep.is_null() {
        sep = unsafe { url.offset(strlen(url) as isize) };
    }
    if query.is_null() {
        query = unsafe { url.offset(strlen(url) as isize) };
    }
    return if sep < query { sep } else { query };
}
extern "C" fn urlchar_needs_escaping(mut c: i32) -> bool {
    return !((unsafe { Curl_iscntrl(c as u8 as i32) }) != 0
        || (unsafe { Curl_isspace(c as u8 as i32) }) != 0
        || (unsafe { Curl_isgraph(c as u8 as i32) }) != 0);
}
extern "C" fn strlen_url(mut url: *const i8, mut relative: bool) -> size_t {
    let mut ptr: *const u8 = 0 as *const u8;
    let mut newlen: size_t = 0 as i32 as size_t;
    let mut left: bool = 1 as i32 != 0;
    let mut host_sep: *const u8 = url as *const u8;
    if !relative {
        host_sep = find_host_sep(url) as *const u8;
    }
    ptr = url as *mut u8;
    while (unsafe { *ptr }) != 0 {
        if ptr < host_sep {
            newlen = newlen.wrapping_add(1);
        } else {
            let mut current_block_10: u64;
            match (unsafe { *ptr }) as i32 {
                63 => {
                    left = 0 as i32 != 0;
                    current_block_10 = 8167214597936611784;
                }
                32 => {
                    if left {
                        newlen = (newlen as u64).wrapping_add(3 as i32 as u64) as size_t as size_t;
                    } else {
                        newlen = newlen.wrapping_add(1);
                    }
                    current_block_10 = 8457315219000651999;
                }
                _ => {
                    current_block_10 = 8167214597936611784;
                }
            }
            match current_block_10 {
                8167214597936611784 => {
                    if urlchar_needs_escaping((unsafe { *ptr }) as i32) {
                        newlen = (newlen as u64).wrapping_add(2 as i32 as u64) as size_t as size_t;
                    }
                    newlen = newlen.wrapping_add(1);
                }
                _ => {}
            }
        }
        ptr = unsafe { ptr.offset(1) };
    }
    return newlen;
}
extern "C" fn strcpy_url(mut output: *mut i8, mut url: *const i8, mut relative: bool) {
    let mut left: bool = 1 as i32 != 0;
    let mut iptr: *const u8 = 0 as *const u8;
    let mut optr: *mut i8 = output;
    let mut host_sep: *const u8 = url as *const u8;
    if !relative {
        host_sep = find_host_sep(url) as *const u8;
    }
    iptr = url as *mut u8;
    while (unsafe { *iptr }) != 0 {
        if iptr < host_sep {
            let fresh0 = optr;
            optr = unsafe { optr.offset(1) };
            (unsafe { *fresh0 = *iptr as i8 });
        } else {
            let mut current_block_15: u64;
            match (unsafe { *iptr }) as i32 {
                63 => {
                    left = 0 as i32 != 0;
                    current_block_15 = 11997719445127346396;
                }
                32 => {
                    if left {
                        let fresh2 = optr;
                        optr = unsafe { optr.offset(1) };
                        (unsafe { *fresh2 = '%' as i32 as i8 });
                        let fresh3 = optr;
                        optr = unsafe { optr.offset(1) };
                        (unsafe { *fresh3 = '2' as i32 as i8 });
                        let fresh4 = optr;
                        optr = unsafe { optr.offset(1) };
                        (unsafe { *fresh4 = '0' as i32 as i8 });
                    } else {
                        let fresh5 = optr;
                        optr = unsafe { optr.offset(1) };
                        (unsafe { *fresh5 = '+' as i32 as i8 });
                    }
                    current_block_15 = 11042950489265723346;
                }
                _ => {
                    current_block_15 = 11997719445127346396;
                }
            }
            match current_block_15 {
                11997719445127346396 => {
                    if urlchar_needs_escaping((unsafe { *iptr }) as i32) {
                        (unsafe { curl_msnprintf(
                            optr,
                            4 as i32 as size_t,
                            b"%%%02x\0" as *const u8 as *const i8,
                            *iptr as i32,
                        ) });
                        optr = unsafe { optr.offset(3 as i32 as isize) };
                    } else {
                        let fresh1 = optr;
                        optr = unsafe { optr.offset(1) };
                        (unsafe { *fresh1 = *iptr as i8 });
                    }
                }
                _ => {}
            }
        }
        iptr = unsafe { iptr.offset(1) };
    }
    (unsafe { *optr = 0 as i32 as i8 });
}
#[no_mangle]
pub extern "C" fn Curl_is_absolute_url(
    mut url: *const i8,
    mut buf: *mut i8,
    mut buflen: size_t,
) -> bool {
    let mut i: size_t = 0;
    i = 0 as i32 as size_t;
    while i < buflen && (unsafe { *url.offset(i as isize) }) as i32 != 0 {
        let mut s: i8 = unsafe { *url.offset(i as isize) };
        if s as i32 == ':' as i32
            && (unsafe { *url.offset(i.wrapping_add(1 as i32 as u64) as isize) }) as i32 == '/' as i32
        {
            if !buf.is_null() {
                (unsafe { *buf.offset(i as isize) = 0 as i32 as i8 });
            }
            return 1 as i32 != 0;
        } else {
            if !((unsafe { Curl_isalnum(s as u8 as i32) }) != 0
                || s as i32 == '+' as i32
                || s as i32 == '-' as i32
                || s as i32 == '.' as i32)
            {
                break;
            }
            if !buf.is_null() {
                (unsafe { *buf.offset(i as isize) = ({
                    let mut __res: i32 = 0;
                    if ::std::mem::size_of::<i32>() as u64 > 1 as i32 as u64 {
                        if 0 != 0 {
                            let mut __c: i32 = s as u8 as i32;
                            __res = if __c < -(128 as i32) || __c > 255 as i32 {
                                __c
                            } else {
                                *(*__ctype_tolower_loc()).offset(__c as isize)
                            };
                        } else {
                            __res = tolower(s as u8 as i32);
                        }
                    } else {
                        __res = *(*__ctype_tolower_loc()).offset(s as u8 as i32 as isize);
                    }
                    __res
                }) as i8 });
            }
            i = i.wrapping_add(1);
        }
    }
    return 0 as i32 != 0;
}
extern "C" fn concat_url(mut base: *const i8, mut relurl: *const i8) -> *mut i8 {
    let mut newest: *mut i8 = 0 as *mut i8;
    let mut protsep: *mut i8 = 0 as *mut i8;
    let mut pathsep: *mut i8 = 0 as *mut i8;
    let mut newlen: size_t = 0;
    let mut host_changed: bool = 0 as i32 != 0;
    let mut useurl: *const i8 = relurl;
    let mut urllen: size_t = 0;
    let mut url_clone: *mut i8 = unsafe { Curl_cstrdup.expect("non-null function pointer")(base) };
    if url_clone.is_null() {
        return 0 as *mut i8;
    }
    protsep = unsafe { strstr(url_clone, b"//\0" as *const u8 as *const i8) };
    if protsep.is_null() {
        protsep = url_clone;
    } else {
        protsep = unsafe { protsep.offset(2 as i32 as isize) };
    }
    if '/' as i32 != (unsafe { *relurl.offset(0 as i32 as isize) }) as i32 {
        let mut level: i32 = 0 as i32;
        pathsep = unsafe { strchr(protsep, '?' as i32) };
        if !pathsep.is_null() {
            (unsafe { *pathsep = 0 as i32 as i8 });
        }
        if (unsafe { *useurl.offset(0 as i32 as isize) }) as i32 != '?' as i32 {
            pathsep = unsafe { strrchr(protsep, '/' as i32) };
            if !pathsep.is_null() {
                (unsafe { *pathsep = 0 as i32 as i8 });
            }
        }
        pathsep = unsafe { strchr(protsep, '/' as i32) };
        if !pathsep.is_null() {
            protsep = unsafe { pathsep.offset(1 as i32 as isize) };
        } else {
            protsep = 0 as *mut i8;
        }
        if (unsafe { *useurl.offset(0 as i32 as isize) }) as i32 == '.' as i32
            && (unsafe { *useurl.offset(1 as i32 as isize) }) as i32 == '/' as i32
        {
            useurl = unsafe { useurl.offset(2 as i32 as isize) };
        }
        while (unsafe { *useurl.offset(0 as i32 as isize) }) as i32 == '.' as i32
            && (unsafe { *useurl.offset(1 as i32 as isize) }) as i32 == '.' as i32
            && (unsafe { *useurl.offset(2 as i32 as isize) }) as i32 == '/' as i32
        {
            level += 1;
            useurl = unsafe { useurl.offset(3 as i32 as isize) };
        }
        if !protsep.is_null() {
            loop {
                let fresh6 = level;
                level = level - 1;
                if !(fresh6 != 0) {
                    break;
                }
                pathsep = unsafe { strrchr(protsep, '/' as i32) };
                if !pathsep.is_null() {
                    (unsafe { *pathsep = 0 as i32 as i8 });
                } else {
                    (unsafe { *protsep = 0 as i32 as i8 });
                    break;
                }
            }
        }
    } else if (unsafe { *relurl.offset(1 as i32 as isize) }) as i32 == '/' as i32 {
        (unsafe { *protsep = 0 as i32 as i8 });
        useurl = (unsafe { &*relurl.offset(2 as i32 as isize) }) as *const i8;
        host_changed = 1 as i32 != 0;
    } else {
        pathsep = unsafe { strchr(protsep, '/' as i32) };
        if !pathsep.is_null() {
            let mut sep: *mut i8 = unsafe { strchr(protsep, '?' as i32) };
            if !sep.is_null() && sep < pathsep {
                pathsep = sep;
            }
            (unsafe { *pathsep = 0 as i32 as i8 });
        } else {
            pathsep = unsafe { strchr(protsep, '?' as i32) };
            if !pathsep.is_null() {
                (unsafe { *pathsep = 0 as i32 as i8 });
            }
        }
    }
    newlen = strlen_url(useurl, !host_changed);
    urllen = unsafe { strlen(url_clone) };
    newest = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
        urllen
            .wrapping_add(1 as i32 as u64)
            .wrapping_add(newlen)
            .wrapping_add(1 as i32 as u64),
    ) }) as *mut i8;
    if newest.is_null() {
        (unsafe { Curl_cfree.expect("non-null function pointer")(url_clone as *mut libc::c_void) });
        return 0 as *mut i8;
    }
    (unsafe { memcpy(
        newest as *mut libc::c_void,
        url_clone as *const libc::c_void,
        urllen,
    ) });
    if !('/' as i32 == (unsafe { *useurl.offset(0 as i32 as isize) }) as i32
        || !protsep.is_null() && (unsafe { *protsep }) == 0
        || '?' as i32 == (unsafe { *useurl.offset(0 as i32 as isize) }) as i32)
    {
        let fresh7 = urllen;
        urllen = urllen.wrapping_add(1);
        (unsafe { *newest.offset(fresh7 as isize) = '/' as i32 as i8 });
    }
    strcpy_url(unsafe { &mut *newest.offset(urllen as isize) }, useurl, !host_changed);
    (unsafe { Curl_cfree.expect("non-null function pointer")(url_clone as *mut libc::c_void) });
    return newest;
}
extern "C" fn parse_hostname_login(
    mut u: *mut Curl_URL,
    mut hostname: *mut *mut i8,
    mut flags: u32,
) -> CURLUcode {
    let mut current_block: u64;
    let mut result: CURLUcode = CURLUE_OK;
    let mut ccode: CURLcode = CURLE_OK;
    let mut userp: *mut i8 = 0 as *mut i8;
    let mut passwdp: *mut i8 = 0 as *mut i8;
    let mut optionsp: *mut i8 = 0 as *mut i8;
    let mut h: *const Curl_handler = 0 as *const Curl_handler;
    let mut ptr: *mut i8 = unsafe { strchr(*hostname, '@' as i32) };
    let mut login: *mut i8 = unsafe { *hostname };
    if !ptr.is_null() {
        ptr = unsafe { ptr.offset(1) };
        (unsafe { *hostname = ptr });
        if !(unsafe { (*u).scheme }).is_null() {
            h = unsafe { Curl_builtin_scheme((*u).scheme) };
        }
        ccode = unsafe { Curl_parse_login_details(
            login,
            (ptr.offset_from(login) as i64 - 1 as i32 as i64) as size_t,
            &mut userp,
            &mut passwdp,
            if !h.is_null() && (*h).flags & ((1 as i32) << 10 as i32) as u32 != 0 {
                &mut optionsp
            } else {
                0 as *mut *mut i8
            },
        ) };
        if ccode as u64 != 0 {
            result = CURLUE_MALFORMED_INPUT;
        } else {
            if !userp.is_null() {
                if flags & ((1 as i32) << 5 as i32) as u32 != 0 {
                    result = CURLUE_USER_NOT_ALLOWED;
                    current_block = 3551955217870244501;
                } else {
                    let fresh8 = unsafe { &mut ((*u).user) };
                    *fresh8 = userp;
                    current_block = 5143058163439228106;
                }
            } else {
                current_block = 5143058163439228106;
            }
            match current_block {
                3551955217870244501 => {}
                _ => {
                    if !passwdp.is_null() {
                        let fresh9 = unsafe { &mut ((*u).password) };
                        *fresh9 = passwdp;
                    }
                    if !optionsp.is_null() {
                        let fresh10 = unsafe { &mut ((*u).options) };
                        *fresh10 = optionsp;
                    }
                    return CURLUE_OK;
                }
            }
        }
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")(userp as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")(passwdp as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")(optionsp as *mut libc::c_void) });
    return result;
}
extern "C" fn Curl_parse_port(
    mut u: *mut Curl_URL,
    mut hostname: *mut i8,
    mut has_scheme: bool,
) -> CURLUcode {
    let mut portptr: *mut i8 = 0 as *mut i8;
    let mut endbracket: i8 = 0;
    let mut len: i32 = 0;
    if 1 as i32
        == (unsafe { sscanf(
            hostname,
            b"[%*45[0123456789abcdefABCDEF:.]%c%n\0" as *const u8 as *const i8,
            &mut endbracket as *mut i8,
            &mut len as *mut i32,
        ) })
    {
        if ']' as i32 == endbracket as i32 {
            portptr = (unsafe { &mut *hostname.offset(len as isize) }) as *mut i8;
        } else if '%' as i32 == endbracket as i32 {
            let mut zonelen: i32 = len;
            if 1 as i32
                == (unsafe { sscanf(
                    hostname.offset(zonelen as isize),
                    b"%*[^]]%c%n\0" as *const u8 as *const i8,
                    &mut endbracket as *mut i8,
                    &mut len as *mut i32,
                ) })
            {
                if ']' as i32 != endbracket as i32 {
                    return CURLUE_MALFORMED_INPUT;
                }
                zonelen -= 1;
                portptr = (unsafe { &mut *hostname.offset((zonelen + len + 1 as i32) as isize) }) as *mut i8;
            } else {
                return CURLUE_MALFORMED_INPUT;
            }
        } else {
            return CURLUE_MALFORMED_INPUT;
        }
        if !portptr.is_null() && (unsafe { *portptr }) as i32 != 0 {
            if (unsafe { *portptr }) as i32 != ':' as i32 {
                return CURLUE_MALFORMED_INPUT;
            }
        } else {
            portptr = 0 as *mut i8;
        }
    } else {
        portptr = unsafe { strchr(hostname, ':' as i32) };
    }
    if !portptr.is_null() {
        let mut rest: *mut i8 = 0 as *mut i8;
        let mut port: i64 = 0;
        let mut portbuf: [i8; 7] = [0; 7];
        if (unsafe { *portptr.offset(1 as i32 as isize) }) == 0 {
            (unsafe { *portptr = '\u{0}' as i32 as i8 });
            return (if has_scheme as i32 != 0 {
                CURLUE_OK as i32
            } else {
                CURLUE_BAD_PORT_NUMBER as i32
            }) as CURLUcode;
        }
        if (unsafe { Curl_isdigit(*portptr.offset(1 as i32 as isize) as u8 as i32) }) == 0 {
            return CURLUE_BAD_PORT_NUMBER;
        }
        port = unsafe { strtol(portptr.offset(1 as i32 as isize), &mut rest, 10 as i32) };
        if port <= 0 as i32 as i64 || port > 0xffff as i32 as i64 {
            return CURLUE_BAD_PORT_NUMBER;
        }
        if (unsafe { *rest.offset(0 as i32 as isize) }) != 0 {
            return CURLUE_BAD_PORT_NUMBER;
        }
        let fresh11 = portptr;
        portptr = unsafe { portptr.offset(1) };
        (unsafe { *fresh11 = '\u{0}' as i32 as i8 });
        (unsafe { *rest = 0 as i32 as i8 });
        (unsafe { curl_msnprintf(
            portbuf.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 7]>() as u64,
            b"%ld\0" as *const u8 as *const i8,
            port,
        ) });
        (unsafe { (*u).portnum = port });
        let fresh12 = unsafe { &mut ((*u).port) };
        *fresh12 = unsafe { Curl_cstrdup.expect("non-null function pointer")(portbuf.as_mut_ptr()) };
        if (unsafe { (*u).port }).is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
    }
    return CURLUE_OK;
}
extern "C" fn junkscan(mut part: *const i8, mut flags: u32) -> bool {
    if !part.is_null() {
        static mut badbytes: [i8; 33] = [
            0x1 as i32 as i8,
            0x2 as i32 as i8,
            0x3 as i32 as i8,
            0x4 as i32 as i8,
            0x5 as i32 as i8,
            0x6 as i32 as i8,
            0x7 as i32 as i8,
            0x8 as i32 as i8,
            0x9 as i32 as i8,
            0xa as i32 as i8,
            0xb as i32 as i8,
            0xc as i32 as i8,
            0xd as i32 as i8,
            0xe as i32 as i8,
            0xf as i32 as i8,
            0x10 as i32 as i8,
            0x11 as i32 as i8,
            0x12 as i32 as i8,
            0x13 as i32 as i8,
            0x14 as i32 as i8,
            0x15 as i32 as i8,
            0x16 as i32 as i8,
            0x17 as i32 as i8,
            0x18 as i32 as i8,
            0x19 as i32 as i8,
            0x1a as i32 as i8,
            0x1b as i32 as i8,
            0x1c as i32 as i8,
            0x1d as i32 as i8,
            0x1e as i32 as i8,
            0x1f as i32 as i8,
            0x7f as i32 as i8,
            0 as i32 as i8,
        ];
        let mut n: size_t = unsafe { strlen(part) };
        let mut nfine: size_t = unsafe { strcspn(part, badbytes.as_ptr()) };
        if nfine != n {
            return 1 as i32 != 0;
        }
        if flags & ((1 as i32) << 11 as i32) as u32 == 0 && !(unsafe { strchr(part, ' ' as i32) }).is_null() {
            return 1 as i32 != 0;
        }
    }
    return 0 as i32 != 0;
}
extern "C" fn hostname_check(mut u: *mut Curl_URL, mut hostname: *mut i8) -> CURLUcode {
    let mut len: size_t = 0;
    let mut hlen: size_t = unsafe { strlen(hostname) };
    if (unsafe { *hostname.offset(0 as i32 as isize) }) as i32 == '[' as i32 {
        let mut dest: [i8; 16] = [0; 16];
        let mut l: *const i8 = b"0123456789abcdefABCDEF:.\0" as *const u8 as *const i8;
        if hlen < 4 as i32 as u64 {
            return CURLUE_MALFORMED_INPUT;
        }
        hostname = unsafe { hostname.offset(1) };
        hlen = (hlen as u64).wrapping_sub(2 as i32 as u64) as size_t as size_t;
        if (unsafe { *hostname.offset(hlen as isize) }) as i32 != ']' as i32 {
            return CURLUE_MALFORMED_INPUT;
        }
        len = unsafe { strspn(hostname, l) };
        if hlen != len {
            hlen = len;
            if (unsafe { *hostname.offset(len as isize) }) as i32 == '%' as i32 {
                let mut zoneid: [i8; 16] = [0; 16];
                let mut i: i32 = 0 as i32;
                let mut h: *mut i8 =
                    (unsafe { &mut *hostname.offset(len.wrapping_add(1 as i32 as u64) as isize) }) as *mut i8;
                if (unsafe { strncmp(h, b"25\0" as *const u8 as *const i8, 2 as i32 as u64) }) == 0
                    && (unsafe { *h.offset(2 as i32 as isize) }) as i32 != 0
                    && (unsafe { *h.offset(2 as i32 as isize) }) as i32 != ']' as i32
                {
                    h = unsafe { h.offset(2 as i32 as isize) };
                }
                while (unsafe { *h }) as i32 != 0 && (unsafe { *h }) as i32 != ']' as i32 && i < 15 as i32 {
                    let fresh13 = h;
                    h = unsafe { h.offset(1) };
                    let fresh14 = i;
                    i = i + 1;
                    zoneid[fresh14 as usize] = unsafe { *fresh13 };
                }
                if i == 0 || ']' as i32 != (unsafe { *h }) as i32 {
                    return CURLUE_MALFORMED_INPUT;
                }
                zoneid[i as usize] = 0 as i32 as i8;
                let fresh15 = unsafe { &mut ((*u).zoneid) };
                *fresh15 = unsafe { Curl_cstrdup.expect("non-null function pointer")(zoneid.as_mut_ptr()) };
                if (unsafe { (*u).zoneid }).is_null() {
                    return CURLUE_OUT_OF_MEMORY;
                }
                (unsafe { *hostname.offset(len as isize) = ']' as i32 as i8 });
                (unsafe { *hostname.offset(len.wrapping_add(1 as i32 as u64) as isize) = 0 as i32 as i8 });
            } else {
                return CURLUE_MALFORMED_INPUT;
            }
        }
        (unsafe { *hostname.offset(hlen as isize) = 0 as i32 as i8 });
        if 1 as i32 != (unsafe { inet_pton(10 as i32, hostname, dest.as_mut_ptr() as *mut libc::c_void) }) {
            return CURLUE_MALFORMED_INPUT;
        }
        (unsafe { *hostname.offset(hlen as isize) = ']' as i32 as i8 });
    } else {
        len = unsafe { strcspn(hostname, b" \0" as *const u8 as *const i8) };
        if hlen != len {
            return CURLUE_MALFORMED_INPUT;
        }
    }
    if (unsafe { *hostname.offset(0 as i32 as isize) }) == 0 {
        return CURLUE_NO_HOST;
    }
    return CURLUE_OK;
}
extern "C" fn ipv4_normalize(mut hostname: *const i8, mut outp: *mut i8, mut olen: size_t) -> bool {
    let mut done: bool = 0 as i32 != 0;
    let mut n: i32 = 0 as i32;
    let mut c: *const i8 = hostname;
    let mut parts: [u64; 4] = [
        0 as i32 as u64,
        0 as i32 as u64,
        0 as i32 as u64,
        0 as i32 as u64,
    ];
    while !done {
        let mut endp: *mut i8 = 0 as *mut i8;
        let mut l: u64 = 0;
        if ((unsafe { *c }) as i32) < '0' as i32 || (unsafe { *c }) as i32 > '9' as i32 {
            return 0 as i32 != 0;
        }
        l = unsafe { strtoul(c, &mut endp, 0 as i32) };
        if l == (9223372036854775807 as i64 as u64)
            .wrapping_mul(2 as u64)
            .wrapping_add(1 as u64)
            && (unsafe { *__errno_location() }) == 34 as i32
            || endp == c as *mut i8
        {
            return 0 as i32 != 0;
        }
        if l > (2147483647 as i32 as u32)
            .wrapping_mul(2 as u32)
            .wrapping_add(1 as u32) as u64
        {
            return 0 as i32 != 0;
        }
        parts[n as usize] = l;
        c = endp;
        match (unsafe { *c }) as i32 {
            46 => {
                if n == 3 as i32 {
                    return 0 as i32 != 0;
                }
                n += 1;
                c = unsafe { c.offset(1) };
            }
            0 => {
                done = 1 as i32 != 0;
            }
            _ => return 0 as i32 != 0,
        }
    }
    match n {
        0 => {
            (unsafe { curl_msnprintf(
                outp,
                olen,
                b"%u.%u.%u.%u\0" as *const u8 as *const i8,
                parts[0 as i32 as usize] >> 24 as i32,
                parts[0 as i32 as usize] >> 16 as i32 & 0xff as i32 as u64,
                parts[0 as i32 as usize] >> 8 as i32 & 0xff as i32 as u64,
                parts[0 as i32 as usize] & 0xff as i32 as u64,
            ) });
        }
        1 => {
            if parts[0 as i32 as usize] > 0xff as i32 as u64
                || parts[1 as i32 as usize] > 0xffffff as i32 as u64
            {
                return 0 as i32 != 0;
            }
            (unsafe { curl_msnprintf(
                outp,
                olen,
                b"%u.%u.%u.%u\0" as *const u8 as *const i8,
                parts[0 as i32 as usize],
                parts[1 as i32 as usize] >> 16 as i32 & 0xff as i32 as u64,
                parts[1 as i32 as usize] >> 8 as i32 & 0xff as i32 as u64,
                parts[1 as i32 as usize] & 0xff as i32 as u64,
            ) });
        }
        2 => {
            if parts[0 as i32 as usize] > 0xff as i32 as u64
                || parts[1 as i32 as usize] > 0xff as i32 as u64
                || parts[2 as i32 as usize] > 0xffff as i32 as u64
            {
                return 0 as i32 != 0;
            }
            (unsafe { curl_msnprintf(
                outp,
                olen,
                b"%u.%u.%u.%u\0" as *const u8 as *const i8,
                parts[0 as i32 as usize],
                parts[1 as i32 as usize],
                parts[2 as i32 as usize] >> 8 as i32 & 0xff as i32 as u64,
                parts[2 as i32 as usize] & 0xff as i32 as u64,
            ) });
        }
        3 => {
            if parts[0 as i32 as usize] > 0xff as i32 as u64
                || parts[1 as i32 as usize] > 0xff as i32 as u64
                || parts[2 as i32 as usize] > 0xff as i32 as u64
                || parts[3 as i32 as usize] > 0xff as i32 as u64
            {
                return 0 as i32 != 0;
            }
            (unsafe { curl_msnprintf(
                outp,
                olen,
                b"%u.%u.%u.%u\0" as *const u8 as *const i8,
                parts[0 as i32 as usize],
                parts[1 as i32 as usize],
                parts[2 as i32 as usize],
                parts[3 as i32 as usize],
            ) });
        }
        _ => {}
    }
    return 1 as i32 != 0;
}
extern "C" fn seturl(mut url: *const i8, mut u: *mut CURLU, mut flags: u32) -> CURLUcode {
    let mut path: *mut i8 = 0 as *mut i8;
    let mut path_alloced: bool = 0 as i32 != 0;
    let mut hostname: *mut i8 = 0 as *mut i8;
    let mut query: *mut i8 = 0 as *mut i8;
    let mut fragment: *mut i8 = 0 as *mut i8;
    let mut result: CURLUcode = CURLUE_OK;
    let mut url_has_scheme: bool = 0 as i32 != 0;
    let mut schemebuf: [i8; 41] = [0; 41];
    let mut schemep: *const i8 = 0 as *const i8;
    let mut schemelen: size_t = 0 as i32 as size_t;
    let mut urllen: size_t = 0;
    urllen = unsafe { strlen(url) };
    if urllen > 8000000 as i32 as u64 {
        return CURLUE_MALFORMED_INPUT;
    }
    let fresh16 = unsafe { &mut ((*u).scratch) };
    *fresh16 = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
        urllen
            .wrapping_mul(2 as i32 as u64)
            .wrapping_add(2 as i32 as u64),
    ) }) as *mut i8;
    path = *fresh16;
    if path.is_null() {
        return CURLUE_OUT_OF_MEMORY;
    }
    hostname = (unsafe { &mut *path.offset(urllen.wrapping_add(1 as i32 as u64) as isize) }) as *mut i8;
    (unsafe { *hostname.offset(0 as i32 as isize) = 0 as i32 as i8 });
    if Curl_is_absolute_url(
        url,
        schemebuf.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 41]>() as u64,
    ) {
        url_has_scheme = 1 as i32 != 0;
        schemelen = unsafe { strlen(schemebuf.as_mut_ptr()) };
    }
    if url_has_scheme as i32 != 0
        && (unsafe { Curl_strcasecompare(schemebuf.as_mut_ptr(), b"file\0" as *const u8 as *const i8) }) != 0
    {
        (unsafe { strcpy(path, &*url.offset(5 as i32 as isize)) });
        hostname = 0 as *mut i8;
        let fresh17 = unsafe { &mut ((*u).scheme) };
        *fresh17 =
            unsafe { Curl_cstrdup.expect("non-null function pointer")(b"file\0" as *const u8 as *const i8) };
        if (unsafe { (*u).scheme }).is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
        if (unsafe { *path.offset(0 as i32 as isize) }) as i32 == '/' as i32
            && (unsafe { *path.offset(1 as i32 as isize) }) as i32 == '/' as i32
        {
            let mut ptr: *mut i8 = (unsafe { &mut *path.offset(2 as i32 as isize) }) as *mut i8;
            if (unsafe { *ptr.offset(0 as i32 as isize) }) as i32 != '/' as i32
                && !(('a' as i32 <= (unsafe { *ptr.offset(0 as i32 as isize) }) as i32
                    && (unsafe { *ptr.offset(0 as i32 as isize) }) as i32 <= 'z' as i32
                    || 'A' as i32 <= (unsafe { *ptr.offset(0 as i32 as isize) }) as i32
                        && (unsafe { *ptr.offset(0 as i32 as isize) }) as i32 <= 'Z' as i32)
                    && ((unsafe { *ptr.offset(1 as i32 as isize) }) as i32 == ':' as i32
                        || (unsafe { *ptr.offset(1 as i32 as isize) }) as i32 == '|' as i32)
                    && ((unsafe { *ptr.offset(2 as i32 as isize) }) as i32 == '/' as i32
                        || (unsafe { *ptr.offset(2 as i32 as isize) }) as i32 == '\\' as i32
                        || (unsafe { *ptr.offset(2 as i32 as isize) }) as i32 == 0 as i32))
            {
                if (unsafe { curl_strnequal(
                    b"localhost/\0" as *const u8 as *const i8,
                    ptr,
                    strlen(b"localhost/\0" as *const u8 as *const i8),
                ) }) == 0
                    && (unsafe { curl_strnequal(
                        b"127.0.0.1/\0" as *const u8 as *const i8,
                        ptr,
                        strlen(b"127.0.0.1/\0" as *const u8 as *const i8),
                    ) }) == 0
                {
                    return CURLUE_MALFORMED_INPUT;
                }
                ptr = unsafe { ptr.offset(9 as i32 as isize) };
            }
            path = ptr;
        }
        if '/' as i32 == (unsafe { *path.offset(0 as i32 as isize) }) as i32
            && (('a' as i32
                <= (unsafe { *(&mut *path.offset(1 as i32 as isize) as *mut i8).offset(0 as i32 as isize) })
                    as i32
                && (unsafe { *(&mut *path.offset(1 as i32 as isize) as *mut i8).offset(0 as i32 as isize) })
                    as i32
                    <= 'z' as i32
                || 'A' as i32
                    <= (unsafe { *(&mut *path.offset(1 as i32 as isize) as *mut i8).offset(0 as i32 as isize) })
                        as i32
                    && (unsafe { *(&mut *path.offset(1 as i32 as isize) as *mut i8).offset(0 as i32 as isize) })
                        as i32
                        <= 'Z' as i32)
                && ((unsafe { *(&mut *path.offset(1 as i32 as isize) as *mut i8).offset(1 as i32 as isize) })
                    as i32
                    == ':' as i32
                    || (unsafe { *(&mut *path.offset(1 as i32 as isize) as *mut i8).offset(1 as i32 as isize) })
                        as i32
                        == '|' as i32)
                && ((unsafe { *(&mut *path.offset(1 as i32 as isize) as *mut i8).offset(2 as i32 as isize) })
                    as i32
                    == '/' as i32
                    || (unsafe { *(&mut *path.offset(1 as i32 as isize) as *mut i8).offset(2 as i32 as isize) })
                        as i32
                        == '\\' as i32
                    || (unsafe { *(&mut *path.offset(1 as i32 as isize) as *mut i8).offset(2 as i32 as isize) })
                        as i32
                        == 0 as i32))
            || ('a' as i32 <= (unsafe { *path.offset(0 as i32 as isize) }) as i32
                && (unsafe { *path.offset(0 as i32 as isize) }) as i32 <= 'z' as i32
                || 'A' as i32 <= (unsafe { *path.offset(0 as i32 as isize) }) as i32
                    && (unsafe { *path.offset(0 as i32 as isize) }) as i32 <= 'Z' as i32)
                && ((unsafe { *path.offset(1 as i32 as isize) }) as i32 == ':' as i32
                    || (unsafe { *path.offset(1 as i32 as isize) }) as i32 == '|' as i32)
                && ((unsafe { *path.offset(2 as i32 as isize) }) as i32 == '/' as i32
                    || (unsafe { *path.offset(2 as i32 as isize) }) as i32 == '\\' as i32
                    || (unsafe { *path.offset(2 as i32 as isize) }) as i32 == 0 as i32)
        {
            return CURLUE_MALFORMED_INPUT;
        }
    } else {
        let mut p: *const i8 = 0 as *const i8;
        let mut hostp: *const i8 = 0 as *const i8;
        let mut len: size_t = 0;
        (unsafe { *path.offset(0 as i32 as isize) = 0 as i32 as i8 });
        if url_has_scheme {
            let mut i: i32 = 0 as i32;
            p = (unsafe { &*url.offset(schemelen.wrapping_add(1 as i32 as u64) as isize) }) as *const i8;
            while !p.is_null() && (unsafe { *p }) as i32 == '/' as i32 && i < 4 as i32 {
                p = unsafe { p.offset(1) };
                i += 1;
            }
            if i < 1 as i32 || i > 3 as i32 {
                return CURLUE_MALFORMED_INPUT;
            }
            schemep = schemebuf.as_mut_ptr();
            if (unsafe { Curl_builtin_scheme(schemep) }).is_null()
                && flags & ((1 as i32) << 3 as i32) as u32 == 0
            {
                return CURLUE_UNSUPPORTED_SCHEME;
            }
            if junkscan(schemep, flags) {
                return CURLUE_MALFORMED_INPUT;
            }
        } else {
            if flags & ((1 as i32) << 2 as i32 | (1 as i32) << 9 as i32) as u32 == 0 {
                return CURLUE_MALFORMED_INPUT;
            }
            if flags & ((1 as i32) << 2 as i32) as u32 != 0 {
                schemep = b"https\0" as *const u8 as *const i8;
            }
            p = url;
        }
        hostp = p;
        while (unsafe { *p }) as i32 != 0
            && !((unsafe { *p }) as i32 == '/' as i32 || (unsafe { *p }) as i32 == '?' as i32 || (unsafe { *p }) as i32 == '#' as i32)
        {
            p = unsafe { p.offset(1) };
        }
        len = (unsafe { p.offset_from(hostp) }) as i64 as size_t;
        if len != 0 {
            (unsafe { memcpy(
                hostname as *mut libc::c_void,
                hostp as *const libc::c_void,
                len,
            ) });
            (unsafe { *hostname.offset(len as isize) = 0 as i32 as i8 });
        } else if flags & ((1 as i32) << 10 as i32) as u32 == 0 {
            return CURLUE_MALFORMED_INPUT;
        }
        len = unsafe { strlen(p) };
        (unsafe { memcpy(path as *mut libc::c_void, p as *const libc::c_void, len) });
        (unsafe { *path.offset(len as isize) = 0 as i32 as i8 });
        if !schemep.is_null() {
            let fresh18 = unsafe { &mut ((*u).scheme) };
            *fresh18 = unsafe { Curl_cstrdup.expect("non-null function pointer")(schemep) };
            if (unsafe { (*u).scheme }).is_null() {
                return CURLUE_OUT_OF_MEMORY;
            }
        }
    }
    if junkscan(path, flags) {
        return CURLUE_MALFORMED_INPUT;
    }
    if flags & ((1 as i32) << 7 as i32) as u32 != 0 && (unsafe { *path.offset(0 as i32 as isize) }) as i32 != 0 {
        let mut newp: *mut i8 = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
            (strlen(path)).wrapping_mul(3 as i32 as u64),
        ) }) as *mut i8;
        if newp.is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
        path_alloced = 1 as i32 != 0;
        strcpy_url(newp, path, 1 as i32 != 0);
        path = newp;
        let fresh19 = unsafe { &mut ((*u).temppath) };
        *fresh19 = path;
    }
    fragment = unsafe { strchr(path, '#' as i32) };
    if !fragment.is_null() {
        let fresh20 = fragment;
        fragment = unsafe { fragment.offset(1) };
        (unsafe { *fresh20 = 0 as i32 as i8 });
        if (unsafe { *fragment.offset(0 as i32 as isize) }) != 0 {
            let fresh21 = unsafe { &mut ((*u).fragment) };
            *fresh21 = unsafe { Curl_cstrdup.expect("non-null function pointer")(fragment) };
            if (unsafe { (*u).fragment }).is_null() {
                return CURLUE_OUT_OF_MEMORY;
            }
        }
    }
    query = unsafe { strchr(path, '?' as i32) };
    if !query.is_null() {
        let fresh22 = query;
        query = unsafe { query.offset(1) };
        (unsafe { *fresh22 = 0 as i32 as i8 });
        let fresh23 = unsafe { &mut ((*u).query) };
        *fresh23 = unsafe { Curl_cstrdup.expect("non-null function pointer")(query) };
        if (unsafe { (*u).query }).is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
    }
    if (unsafe { *path.offset(0 as i32 as isize) }) == 0 {
        path = 0 as *mut i8;
    } else {
        if flags & ((1 as i32) << 4 as i32) as u32 == 0 {
            let mut newp_0: *mut i8 = unsafe { Curl_dedotdotify(path) };
            if newp_0.is_null() {
                return CURLUE_OUT_OF_MEMORY;
            }
            if (unsafe { strcmp(newp_0, path) }) != 0 {
                if path_alloced {
                    (unsafe { Curl_cfree.expect("non-null function pointer")(
                        (*u).temppath as *mut libc::c_void,
                    ) });
                    let fresh24 = unsafe { &mut ((*u).temppath) };
                    *fresh24 = 0 as *mut i8;
                }
                path = newp_0;
                let fresh25 = unsafe { &mut ((*u).temppath) };
                *fresh25 = path;
                path_alloced = 1 as i32 != 0;
            } else {
                (unsafe { Curl_cfree.expect("non-null function pointer")(newp_0 as *mut libc::c_void) });
            }
        }
        let fresh26 = unsafe { &mut ((*u).path) };
        *fresh26 = if path_alloced as i32 != 0 {
            path
        } else {
            unsafe { Curl_cstrdup.expect("non-null function pointer")(path) }
        };
        if (unsafe { (*u).path }).is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
        let fresh27 = unsafe { &mut ((*u).temppath) };
        *fresh27 = 0 as *mut i8;
    }
    if !hostname.is_null() {
        let mut normalized_ipv4: [i8; 17] = [0; 17];
        if junkscan(hostname, flags) {
            return CURLUE_MALFORMED_INPUT;
        }
        result = parse_hostname_login(u, &mut hostname, flags);
        if result as u64 != 0 {
            return result;
        }
        result = Curl_parse_port(u, hostname, url_has_scheme);
        if result as u64 != 0 {
            return result;
        }
        if !(0 as i32 as u64 == (unsafe { strlen(hostname) }) && flags & ((1 as i32) << 10 as i32) as u32 != 0) {
            result = hostname_check(u, hostname);
            if result as u64 != 0 {
                return result;
            }
        }
        if ipv4_normalize(
            hostname,
            normalized_ipv4.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 17]>() as u64,
        ) {
            let fresh28 = unsafe { &mut ((*u).host) };
            *fresh28 =
                unsafe { Curl_cstrdup.expect("non-null function pointer")(normalized_ipv4.as_mut_ptr()) };
        } else {
            let fresh29 = unsafe { &mut ((*u).host) };
            *fresh29 = unsafe { Curl_cstrdup.expect("non-null function pointer")(hostname) };
        }
        if (unsafe { (*u).host }).is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
        if flags & ((1 as i32) << 9 as i32) as u32 != 0 && schemep.is_null() {
            if (unsafe { curl_strnequal(
                b"ftp.\0" as *const u8 as *const i8,
                hostname,
                strlen(b"ftp.\0" as *const u8 as *const i8),
            ) }) != 0
            {
                schemep = b"ftp\0" as *const u8 as *const i8;
            } else if (unsafe { curl_strnequal(
                b"dict.\0" as *const u8 as *const i8,
                hostname,
                strlen(b"dict.\0" as *const u8 as *const i8),
            ) }) != 0
            {
                schemep = b"dict\0" as *const u8 as *const i8;
            } else if (unsafe { curl_strnequal(
                b"ldap.\0" as *const u8 as *const i8,
                hostname,
                strlen(b"ldap.\0" as *const u8 as *const i8),
            ) }) != 0
            {
                schemep = b"ldap\0" as *const u8 as *const i8;
            } else if (unsafe { curl_strnequal(
                b"imap.\0" as *const u8 as *const i8,
                hostname,
                strlen(b"imap.\0" as *const u8 as *const i8),
            ) }) != 0
            {
                schemep = b"imap\0" as *const u8 as *const i8;
            } else if (unsafe { curl_strnequal(
                b"smtp.\0" as *const u8 as *const i8,
                hostname,
                strlen(b"smtp.\0" as *const u8 as *const i8),
            ) }) != 0
            {
                schemep = b"smtp\0" as *const u8 as *const i8;
            } else if (unsafe { curl_strnequal(
                b"pop3.\0" as *const u8 as *const i8,
                hostname,
                strlen(b"pop3.\0" as *const u8 as *const i8),
            ) }) != 0
            {
                schemep = b"pop3\0" as *const u8 as *const i8;
            } else {
                schemep = b"http\0" as *const u8 as *const i8;
            }
            let fresh30 = unsafe { &mut ((*u).scheme) };
            *fresh30 = unsafe { Curl_cstrdup.expect("non-null function pointer")(schemep) };
            if (unsafe { (*u).scheme }).is_null() {
                return CURLUE_OUT_OF_MEMORY;
            }
        }
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")((*u).scratch as *mut libc::c_void) });
    let fresh31 = unsafe { &mut ((*u).scratch) };
    *fresh31 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*u).temppath as *mut libc::c_void) });
    let fresh32 = unsafe { &mut ((*u).temppath) };
    *fresh32 = 0 as *mut i8;
    return CURLUE_OK;
}
extern "C" fn parseurl(mut url: *const i8, mut u: *mut CURLU, mut flags: u32) -> CURLUcode {
    let mut result: CURLUcode = seturl(url, u, flags);
    if result as u64 != 0 {
        free_urlhandle(u);
        (unsafe { memset(
            u as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<Curl_URL>() as u64,
        ) });
    }
    return result;
}
#[no_mangle]
pub extern "C" fn curl_url() -> *mut CURLU {
    return (unsafe { Curl_ccalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<Curl_URL>() as u64,
        1 as i32 as size_t,
    ) }) as *mut CURLU;
}
#[no_mangle]
pub extern "C" fn curl_url_cleanup(mut u: *mut CURLU) {
    if !u.is_null() {
        free_urlhandle(u);
        (unsafe { Curl_cfree.expect("non-null function pointer")(u as *mut libc::c_void) });
    }
}
#[no_mangle]
pub extern "C" fn curl_url_dup(mut in_0: *mut CURLU) -> *mut CURLU {
    let mut current_block: u64;
    let mut u: *mut Curl_URL = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<Curl_URL>() as u64,
        1 as i32 as size_t,
    ) }) as *mut Curl_URL;
    if !u.is_null() {
        if !(unsafe { (*in_0).scheme }).is_null() {
            let fresh33 = unsafe { &mut ((*u).scheme) };
            *fresh33 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*in_0).scheme) };
            if (unsafe { (*u).scheme }).is_null() {
                current_block = 3421950808998859186;
            } else {
                current_block = 7815301370352969686;
            }
        } else {
            current_block = 7815301370352969686;
        }
        match current_block {
            7815301370352969686 => {
                if !(unsafe { (*in_0).user }).is_null() {
                    let fresh34 = unsafe { &mut ((*u).user) };
                    *fresh34 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*in_0).user) };
                    if (unsafe { (*u).user }).is_null() {
                        current_block = 3421950808998859186;
                    } else {
                        current_block = 11050875288958768710;
                    }
                } else {
                    current_block = 11050875288958768710;
                }
                match current_block {
                    3421950808998859186 => {}
                    _ => {
                        if !(unsafe { (*in_0).password }).is_null() {
                            let fresh35 = unsafe { &mut ((*u).password) };
                            *fresh35 =
                                unsafe { Curl_cstrdup.expect("non-null function pointer")((*in_0).password) };
                            if (unsafe { (*u).password }).is_null() {
                                current_block = 3421950808998859186;
                            } else {
                                current_block = 5948590327928692120;
                            }
                        } else {
                            current_block = 5948590327928692120;
                        }
                        match current_block {
                            3421950808998859186 => {}
                            _ => {
                                if !(unsafe { (*in_0).options }).is_null() {
                                    let fresh36 = unsafe { &mut ((*u).options) };
                                    *fresh36 = unsafe { Curl_cstrdup.expect("non-null function pointer")(
                                        (*in_0).options,
                                    ) };
                                    if (unsafe { (*u).options }).is_null() {
                                        current_block = 3421950808998859186;
                                    } else {
                                        current_block = 10652014663920648156;
                                    }
                                } else {
                                    current_block = 10652014663920648156;
                                }
                                match current_block {
                                    3421950808998859186 => {}
                                    _ => {
                                        if !(unsafe { (*in_0).host }).is_null() {
                                            let fresh37 = unsafe { &mut ((*u).host) };
                                            *fresh37 = unsafe { Curl_cstrdup
                                                .expect("non-null function pointer")(
                                                (*in_0).host
                                            ) };
                                            if (unsafe { (*u).host }).is_null() {
                                                current_block = 3421950808998859186;
                                            } else {
                                                current_block = 4775909272756257391;
                                            }
                                        } else {
                                            current_block = 4775909272756257391;
                                        }
                                        match current_block {
                                            3421950808998859186 => {}
                                            _ => {
                                                if !(unsafe { (*in_0).port }).is_null() {
                                                    let fresh38 = unsafe { &mut ((*u).port) };
                                                    *fresh38 = unsafe { Curl_cstrdup
                                                        .expect("non-null function pointer")(
                                                        (*in_0).port,
                                                    ) };
                                                    if (unsafe { (*u).port }).is_null() {
                                                        current_block = 3421950808998859186;
                                                    } else {
                                                        current_block = 11385396242402735691;
                                                    }
                                                } else {
                                                    current_block = 11385396242402735691;
                                                }
                                                match current_block {
                                                    3421950808998859186 => {}
                                                    _ => {
                                                        if !(unsafe { (*in_0).path }).is_null() {
                                                            let fresh39 = unsafe { &mut ((*u).path) };
                                                            *fresh39 = unsafe { Curl_cstrdup.expect(
                                                                "non-null function pointer",
                                                            )(
                                                                (*in_0).path
                                                            ) };
                                                            if (unsafe { (*u).path }).is_null() {
                                                                current_block = 3421950808998859186;
                                                            } else {
                                                                current_block =
                                                                    15090052786889560393;
                                                            }
                                                        } else {
                                                            current_block = 15090052786889560393;
                                                        }
                                                        match current_block {
                                                            3421950808998859186 => {}
                                                            _ => {
                                                                if !(unsafe { (*in_0).query }).is_null() {
                                                                    let fresh40 = unsafe { &mut ((*u).query) };
                                                                    *fresh40 = unsafe { Curl_cstrdup.expect(
                                                                        "non-null function pointer",
                                                                    )(
                                                                        (*in_0).query
                                                                    ) };
                                                                    if (unsafe { (*u).query }).is_null() {
                                                                        current_block =
                                                                            3421950808998859186;
                                                                    } else {
                                                                        current_block =
                                                                            16799951812150840583;
                                                                    }
                                                                } else {
                                                                    current_block =
                                                                        16799951812150840583;
                                                                }
                                                                match current_block {
                                                                    3421950808998859186 => {}
                                                                    _ => {
                                                                        if !(unsafe { (*in_0).fragment })
                                                                            .is_null()
                                                                        {
                                                                            let fresh41 =
                                                                                unsafe { &mut ((*u)
                                                                                    .fragment) };
                                                                            * fresh41 = unsafe { Curl_cstrdup . expect ("non-null function pointer") ((* in_0) . fragment) } ;
                                                                            if (unsafe { (*u).fragment })
                                                                                .is_null()
                                                                            {
                                                                                current_block = 3421950808998859186 ;
                                                                            } else {
                                                                                current_block = 3689906465960840878 ;
                                                                            }
                                                                        } else {
                                                                            current_block =
                                                                                3689906465960840878;
                                                                        }
                                                                        match current_block {
                                                                            3421950808998859186 => {
                                                                            }
                                                                            _ => {
                                                                                (unsafe { (*u).portnum =
                                                                                    (*in_0).portnum });
                                                                                current_block = 7990025728955927862 ;
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
                }
            }
            _ => {}
        }
        match current_block {
            7990025728955927862 => {}
            _ => {
                curl_url_cleanup(u);
                return 0 as *mut CURLU;
            }
        }
    }
    return u;
}
#[no_mangle]
pub extern "C" fn curl_url_get(
    mut u: *mut CURLU,
    mut what: CURLUPart,
    mut part: *mut *mut i8,
    mut flags: u32,
) -> CURLUcode {
    let mut ptr: *mut i8 = 0 as *mut i8;
    let mut ifmissing: CURLUcode = CURLUE_UNKNOWN_PART;
    let mut portbuf: [i8; 7] = [0; 7];
    let mut urldecode: bool = if flags & ((1 as i32) << 6 as i32) as u32 != 0 {
        1 as i32
    } else {
        0 as i32
    } != 0;
    let mut plusdecode: bool = 0 as i32 != 0;
    if u.is_null() {
        return CURLUE_BAD_HANDLE;
    }
    if part.is_null() {
        return CURLUE_BAD_PARTPOINTER;
    }
    (unsafe { *part = 0 as *mut i8 });
    match what as u32 {
        1 => {
            ptr = unsafe { (*u).scheme };
            ifmissing = CURLUE_NO_SCHEME;
            urldecode = 0 as i32 != 0;
        }
        2 => {
            ptr = unsafe { (*u).user };
            ifmissing = CURLUE_NO_USER;
        }
        3 => {
            ptr = unsafe { (*u).password };
            ifmissing = CURLUE_NO_PASSWORD;
        }
        4 => {
            ptr = unsafe { (*u).options };
            ifmissing = CURLUE_NO_OPTIONS;
        }
        5 => {
            ptr = unsafe { (*u).host };
            ifmissing = CURLUE_NO_HOST;
        }
        10 => {
            ptr = unsafe { (*u).zoneid };
        }
        6 => {
            ptr = unsafe { (*u).port };
            ifmissing = CURLUE_NO_PORT;
            urldecode = 0 as i32 != 0;
            if ptr.is_null()
                && flags & ((1 as i32) << 0 as i32) as u32 != 0
                && !(unsafe { (*u).scheme }).is_null()
            {
                let mut h: *const Curl_handler = unsafe { Curl_builtin_scheme((*u).scheme) };
                if !h.is_null() {
                    (unsafe { curl_msnprintf(
                        portbuf.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 7]>() as u64,
                        b"%u\0" as *const u8 as *const i8,
                        (*h).defport,
                    ) });
                    ptr = portbuf.as_mut_ptr();
                }
            } else if !ptr.is_null() && !(unsafe { (*u).scheme }).is_null() {
                let mut h_0: *const Curl_handler = unsafe { Curl_builtin_scheme((*u).scheme) };
                if !h_0.is_null()
                    && (unsafe { (*h_0).defport }) as i64 == (unsafe { (*u).portnum })
                    && flags & ((1 as i32) << 1 as i32) as u32 != 0
                {
                    ptr = 0 as *mut i8;
                }
            }
        }
        7 => {
            ptr = unsafe { (*u).path };
            if ptr.is_null() {
                let fresh42 = unsafe { &mut ((*u).path) };
                *fresh42 = unsafe { Curl_cstrdup.expect("non-null function pointer")(
                    b"/\0" as *const u8 as *const i8,
                ) };
                ptr = *fresh42;
                if (unsafe { (*u).path }).is_null() {
                    return CURLUE_OUT_OF_MEMORY;
                }
            }
        }
        8 => {
            ptr = unsafe { (*u).query };
            ifmissing = CURLUE_NO_QUERY;
            plusdecode = urldecode;
        }
        9 => {
            ptr = unsafe { (*u).fragment };
            ifmissing = CURLUE_NO_FRAGMENT;
        }
        0 => {
            let mut url: *mut i8 = 0 as *mut i8;
            let mut scheme: *mut i8 = 0 as *mut i8;
            let mut options: *mut i8 = unsafe { (*u).options };
            let mut port: *mut i8 = unsafe { (*u).port };
            let mut allochost: *mut i8 = 0 as *mut i8;
            if !(unsafe { (*u).scheme }).is_null()
                && (unsafe { Curl_strcasecompare(b"file\0" as *const u8 as *const i8, (*u).scheme) }) != 0
            {
                url = unsafe { curl_maprintf(
                    b"file://%s%s%s\0" as *const u8 as *const i8,
                    (*u).path,
                    if !((*u).fragment).is_null() {
                        b"#\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).fragment).is_null() {
                        (*u).fragment as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                ) };
            } else if (unsafe { (*u).host }).is_null() {
                return CURLUE_NO_HOST;
            } else {
                let mut h_1: *const Curl_handler = 0 as *const Curl_handler;
                if !(unsafe { (*u).scheme }).is_null() {
                    scheme = unsafe { (*u).scheme };
                } else if flags & ((1 as i32) << 2 as i32) as u32 != 0 {
                    scheme = b"https\0" as *const u8 as *const i8 as *mut i8;
                } else {
                    return CURLUE_NO_SCHEME;
                }
                h_1 = unsafe { Curl_builtin_scheme(scheme) };
                if port.is_null() && flags & ((1 as i32) << 0 as i32) as u32 != 0 {
                    if !h_1.is_null() {
                        (unsafe { curl_msnprintf(
                            portbuf.as_mut_ptr(),
                            ::std::mem::size_of::<[i8; 7]>() as u64,
                            b"%u\0" as *const u8 as *const i8,
                            (*h_1).defport,
                        ) });
                        port = portbuf.as_mut_ptr();
                    }
                } else if !port.is_null() {
                    if !h_1.is_null()
                        && (unsafe { (*h_1).defport }) as i64 == (unsafe { (*u).portnum })
                        && flags & ((1 as i32) << 1 as i32) as u32 != 0
                    {
                        port = 0 as *mut i8;
                    }
                }
                if !h_1.is_null() && (unsafe { (*h_1).flags }) & ((1 as i32) << 10 as i32) as u32 == 0 {
                    options = 0 as *mut i8;
                }
                if (unsafe { *((*u).host).offset(0 as i32 as isize) }) as i32 == '[' as i32
                    && !(unsafe { (*u).zoneid }).is_null()
                {
                    let mut hostlen: size_t = unsafe { strlen((*u).host) };
                    let mut alen: size_t = hostlen
                        .wrapping_add(3 as i32 as u64)
                        .wrapping_add(unsafe { strlen((*u).zoneid) })
                        .wrapping_add(1 as i32 as u64);
                    allochost = (unsafe { Curl_cmalloc.expect("non-null function pointer")(alen) }) as *mut i8;
                    if allochost.is_null() {
                        return CURLUE_OUT_OF_MEMORY;
                    }
                    (unsafe { memcpy(
                        allochost as *mut libc::c_void,
                        (*u).host as *const libc::c_void,
                        hostlen.wrapping_sub(1 as i32 as u64),
                    ) });
                    (unsafe { curl_msnprintf(
                        &mut *allochost.offset(hostlen.wrapping_sub(1 as i32 as u64) as isize)
                            as *mut i8,
                        alen.wrapping_sub(hostlen).wrapping_add(1 as i32 as u64),
                        b"%%25%s]\0" as *const u8 as *const i8,
                        (*u).zoneid,
                    ) });
                }
                url = unsafe { curl_maprintf(
                    b"%s://%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\0" as *const u8 as *const i8,
                    scheme,
                    if !((*u).user).is_null() {
                        (*u).user as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).password).is_null() {
                        b":\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).password).is_null() {
                        (*u).password as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !options.is_null() {
                        b";\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !options.is_null() {
                        options as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).user).is_null() || !((*u).password).is_null() || !options.is_null() {
                        b"@\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !allochost.is_null() {
                        allochost
                    } else {
                        (*u).host
                    },
                    if !port.is_null() {
                        b":\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !port.is_null() {
                        port as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).path).is_null()
                        && *((*u).path).offset(0 as i32 as isize) as i32 != '/' as i32
                    {
                        b"/\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).path).is_null() {
                        (*u).path as *const i8
                    } else {
                        b"/\0" as *const u8 as *const i8
                    },
                    if !((*u).query).is_null()
                        && *((*u).query).offset(0 as i32 as isize) as i32 != 0
                    {
                        b"?\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).query).is_null()
                        && *((*u).query).offset(0 as i32 as isize) as i32 != 0
                    {
                        (*u).query as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).fragment).is_null() {
                        b"#\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if !((*u).fragment).is_null() {
                        (*u).fragment as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                ) };
                (unsafe { Curl_cfree.expect("non-null function pointer")(allochost as *mut libc::c_void) });
            }
            if url.is_null() {
                return CURLUE_OUT_OF_MEMORY;
            }
            (unsafe { *part = url });
            return CURLUE_OK;
        }
        _ => {
            ptr = 0 as *mut i8;
        }
    }
    if !ptr.is_null() {
        (unsafe { *part = Curl_cstrdup.expect("non-null function pointer")(ptr) });
        if (unsafe { *part }).is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
        if plusdecode {
            let mut plus: *mut i8 = 0 as *mut i8;
            plus = unsafe { *part };
            while (unsafe { *plus }) != 0 {
                if (unsafe { *plus }) as i32 == '+' as i32 {
                    (unsafe { *plus = ' ' as i32 as i8 });
                }
                plus = unsafe { plus.offset(1) };
            }
        }
        if urldecode {
            let mut decoded: *mut i8 = 0 as *mut i8;
            let mut dlen: size_t = 0;
            let mut res: CURLcode = unsafe { Curl_urldecode(
                0 as *mut Curl_easy,
                *part,
                0 as i32 as size_t,
                &mut decoded,
                &mut dlen,
                REJECT_CTRL,
            ) };
            (unsafe { Curl_cfree.expect("non-null function pointer")(*part as *mut libc::c_void) });
            if res as u64 != 0 {
                (unsafe { *part = 0 as *mut i8 });
                return CURLUE_URLDECODE;
            }
            (unsafe { *part = decoded });
        }
        return CURLUE_OK;
    } else {
        return ifmissing;
    };
}
#[no_mangle]
pub extern "C" fn curl_url_set(
    mut u: *mut CURLU,
    mut what: CURLUPart,
    mut part: *const i8,
    mut flags: u32,
) -> CURLUcode {
    let mut storep: *mut *mut i8 = 0 as *mut *mut i8;
    let mut port: i64 = 0 as i32 as i64;
    let mut urlencode: bool = if flags & ((1 as i32) << 7 as i32) as u32 != 0 {
        1 as i32
    } else {
        0 as i32
    } != 0;
    let mut plusencode: bool = 0 as i32 != 0;
    let mut urlskipslash: bool = 0 as i32 != 0;
    let mut appendquery: bool = 0 as i32 != 0;
    let mut equalsencode: bool = 0 as i32 != 0;
    if u.is_null() {
        return CURLUE_BAD_HANDLE;
    }
    if part.is_null() {
        match what as u32 {
            0 => {}
            1 => {
                storep = unsafe { &mut (*u).scheme };
            }
            2 => {
                storep = unsafe { &mut (*u).user };
            }
            3 => {
                storep = unsafe { &mut (*u).password };
            }
            4 => {
                storep = unsafe { &mut (*u).options };
            }
            5 => {
                storep = unsafe { &mut (*u).host };
            }
            10 => {
                storep = unsafe { &mut (*u).zoneid };
            }
            6 => {
                (unsafe { (*u).portnum = 0 as i32 as i64 });
                storep = unsafe { &mut (*u).port };
            }
            7 => {
                storep = unsafe { &mut (*u).path };
            }
            8 => {
                storep = unsafe { &mut (*u).query };
            }
            9 => {
                storep = unsafe { &mut (*u).fragment };
            }
            _ => return CURLUE_UNKNOWN_PART,
        }
        if !storep.is_null() && !(unsafe { *storep }).is_null() {
            (unsafe { Curl_cfree.expect("non-null function pointer")(*storep as *mut libc::c_void) });
            (unsafe { *storep = 0 as *mut i8 });
        }
        return CURLUE_OK;
    }
    match what as u32 {
        1 => {
            if (unsafe { strlen(part) }) > 40 as i32 as u64 {
                return CURLUE_MALFORMED_INPUT;
            }
            if flags & ((1 as i32) << 3 as i32) as u32 == 0 && (unsafe { Curl_builtin_scheme(part) }).is_null()
            {
                return CURLUE_UNSUPPORTED_SCHEME;
            }
            storep = unsafe { &mut (*u).scheme };
            urlencode = 0 as i32 != 0;
        }
        2 => {
            storep = unsafe { &mut (*u).user };
        }
        3 => {
            storep = unsafe { &mut (*u).password };
        }
        4 => {
            storep = unsafe { &mut (*u).options };
        }
        5 => {
            storep = unsafe { &mut (*u).host };
            (unsafe { Curl_cfree.expect("non-null function pointer")((*u).zoneid as *mut libc::c_void) });
            let fresh43 = unsafe { &mut ((*u).zoneid) };
            *fresh43 = 0 as *mut i8;
        }
        10 => {
            storep = unsafe { &mut (*u).zoneid };
        }
        6 => {
            let mut endp: *mut i8 = 0 as *mut i8;
            urlencode = 0 as i32 != 0;
            port = unsafe { strtol(part, &mut endp, 10 as i32) };
            if port <= 0 as i32 as i64 || port > 0xffff as i32 as i64 {
                return CURLUE_BAD_PORT_NUMBER;
            }
            if (unsafe { *endp }) != 0 {
                return CURLUE_MALFORMED_INPUT;
            }
            storep = unsafe { &mut (*u).port };
        }
        7 => {
            urlskipslash = 1 as i32 != 0;
            storep = unsafe { &mut (*u).path };
        }
        8 => {
            plusencode = urlencode;
            appendquery = if flags & ((1 as i32) << 8 as i32) as u32 != 0 {
                1 as i32
            } else {
                0 as i32
            } != 0;
            equalsencode = appendquery;
            storep = unsafe { &mut (*u).query };
        }
        9 => {
            storep = unsafe { &mut (*u).fragment };
        }
        0 => {
            let mut result: CURLUcode = CURLUE_OK;
            let mut oldurl: *mut i8 = 0 as *mut i8;
            let mut redired_url: *mut i8 = 0 as *mut i8;
            let mut handle2: *mut CURLU = 0 as *mut CURLU;
            if Curl_is_absolute_url(part, 0 as *mut i8, (40 as i32 + 1 as i32) as size_t) {
                handle2 = curl_url();
                if handle2.is_null() {
                    return CURLUE_OUT_OF_MEMORY;
                }
                result = parseurl(part, handle2, flags);
                if result as u64 == 0 {
                    mv_urlhandle(handle2, u);
                } else {
                    curl_url_cleanup(handle2);
                }
                return result;
            }
            result = curl_url_get(u, CURLUPART_URL, &mut oldurl, flags);
            if result as u64 != 0 {
                handle2 = curl_url();
                if handle2.is_null() {
                    return CURLUE_OUT_OF_MEMORY;
                }
                result = parseurl(part, handle2, flags);
                if result as u64 == 0 {
                    mv_urlhandle(handle2, u);
                } else {
                    curl_url_cleanup(handle2);
                }
                return result;
            }
            redired_url = concat_url(oldurl, part);
            (unsafe { Curl_cfree.expect("non-null function pointer")(oldurl as *mut libc::c_void) });
            if redired_url.is_null() {
                return CURLUE_OUT_OF_MEMORY;
            }
            handle2 = curl_url();
            if handle2.is_null() {
                (unsafe { Curl_cfree.expect("non-null function pointer")(redired_url as *mut libc::c_void) });
                return CURLUE_OUT_OF_MEMORY;
            }
            result = parseurl(redired_url, handle2, flags);
            (unsafe { Curl_cfree.expect("non-null function pointer")(redired_url as *mut libc::c_void) });
            if result as u64 == 0 {
                mv_urlhandle(handle2, u);
            } else {
                curl_url_cleanup(handle2);
            }
            return result;
        }
        _ => return CURLUE_UNKNOWN_PART,
    }
    let mut newp: *const i8 = part;
    let mut nalloc: size_t = unsafe { strlen(part) };
    if nalloc > 8000000 as i32 as u64 {
        return CURLUE_MALFORMED_INPUT;
    }
    if urlencode {
        let mut i: *const u8 = 0 as *const u8;
        let mut o: *mut i8 = 0 as *mut i8;
        let mut enc: *mut i8 = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
            nalloc
                .wrapping_mul(3 as i32 as u64)
                .wrapping_add(1 as i32 as u64),
        ) }) as *mut i8;
        if enc.is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
        i = part as *const u8;
        o = enc;
        while (unsafe { *i }) != 0 {
            if (unsafe { *i }) as i32 == ' ' as i32 && plusencode as i32 != 0 {
                (unsafe { *o = '+' as i32 as i8 });
                o = unsafe { o.offset(1) };
            } else if (unsafe { Curl_isunreserved(*i) }) as i32 != 0
                || (unsafe { *i }) as i32 == '/' as i32 && urlskipslash as i32 != 0
                || (unsafe { *i }) as i32 == '=' as i32 && equalsencode as i32 != 0
            {
                if (unsafe { *i }) as i32 == '=' as i32 && equalsencode as i32 != 0 {
                    equalsencode = 0 as i32 != 0;
                }
                (unsafe { *o = *i as i8 });
                o = unsafe { o.offset(1) };
            } else {
                (unsafe { curl_msnprintf(
                    o,
                    4 as i32 as size_t,
                    b"%%%02x\0" as *const u8 as *const i8,
                    *i as i32,
                ) });
                o = unsafe { o.offset(3 as i32 as isize) };
            }
            i = unsafe { i.offset(1) };
        }
        (unsafe { *o = 0 as i32 as i8 });
        newp = enc;
    } else {
        let mut p: *mut i8 = 0 as *mut i8;
        newp = unsafe { Curl_cstrdup.expect("non-null function pointer")(part) };
        if newp.is_null() {
            return CURLUE_OUT_OF_MEMORY;
        }
        p = newp as *mut i8;
        while (unsafe { *p }) != 0 {
            if (unsafe { *p }) as i32 == '%' as i32
                && (unsafe { Curl_isxdigit(*p.offset(1 as i32 as isize) as u8 as i32) }) != 0
                && (unsafe { Curl_isxdigit(*p.offset(2 as i32 as isize) as u8 as i32) }) != 0
                && ((unsafe { Curl_isupper(*p.offset(1 as i32 as isize) as u8 as i32) }) != 0
                    || (unsafe { Curl_isupper(*p.offset(2 as i32 as isize) as u8 as i32) }) != 0)
            {
                (unsafe { *p.offset(1 as i32 as isize) = ({
                    let mut __res: i32 = 0;
                    if ::std::mem::size_of::<i32>() as u64 > 1 as i32 as u64 {
                        if 0 != 0 {
                            let mut __c: i32 = *p.offset(1 as i32 as isize) as u8 as i32;
                            __res = if __c < -(128 as i32) || __c > 255 as i32 {
                                __c
                            } else {
                                *(*__ctype_tolower_loc()).offset(__c as isize)
                            };
                        } else {
                            __res = tolower(*p.offset(1 as i32 as isize) as u8 as i32);
                        }
                    } else {
                        __res = *(*__ctype_tolower_loc())
                            .offset(*p.offset(1 as i32 as isize) as u8 as i32 as isize);
                    }
                    __res
                }) as i8 });
                (unsafe { *p.offset(2 as i32 as isize) = ({
                    let mut __res: i32 = 0;
                    if ::std::mem::size_of::<i32>() as u64 > 1 as i32 as u64 {
                        if 0 != 0 {
                            let mut __c: i32 = *p.offset(2 as i32 as isize) as u8 as i32;
                            __res = if __c < -(128 as i32) || __c > 255 as i32 {
                                __c
                            } else {
                                *(*__ctype_tolower_loc()).offset(__c as isize)
                            };
                        } else {
                            __res = tolower(*p.offset(2 as i32 as isize) as u8 as i32);
                        }
                    } else {
                        __res = *(*__ctype_tolower_loc())
                            .offset(*p.offset(2 as i32 as isize) as u8 as i32 as isize);
                    }
                    __res
                }) as i8 });
                p = unsafe { p.offset(3 as i32 as isize) };
            } else {
                p = unsafe { p.offset(1) };
            }
        }
    }
    if appendquery {
        let mut querylen: size_t = if !(unsafe { (*u).query }).is_null() {
            unsafe { strlen((*u).query) }
        } else {
            0 as i32 as u64
        };
        let mut addamperand: bool = querylen != 0
            && (unsafe { *((*u).query).offset(querylen.wrapping_sub(1 as i32 as u64) as isize) }) as i32
                != '&' as i32;
        if querylen != 0 {
            let mut newplen: size_t = unsafe { strlen(newp) };
            let mut p_0: *mut i8 = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
                querylen
                    .wrapping_add(addamperand as u64)
                    .wrapping_add(newplen)
                    .wrapping_add(1 as i32 as u64),
            ) }) as *mut i8;
            if p_0.is_null() {
                (unsafe { Curl_cfree.expect("non-null function pointer")(
                    newp as *mut i8 as *mut libc::c_void,
                ) });
                return CURLUE_OUT_OF_MEMORY;
            }
            (unsafe { strcpy(p_0, (*u).query) });
            if addamperand {
                (unsafe { *p_0.offset(querylen as isize) = '&' as i32 as i8 });
            }
            (unsafe { strcpy(
                &mut *p_0.offset(querylen.wrapping_add(addamperand as u64) as isize),
                newp,
            ) });
            (unsafe { Curl_cfree.expect("non-null function pointer")(newp as *mut i8 as *mut libc::c_void) });
            (unsafe { Curl_cfree.expect("non-null function pointer")(*storep as *mut libc::c_void) });
            (unsafe { *storep = p_0 });
            return CURLUE_OK;
        }
    }
    if what as u32 == CURLUPART_HOST as i32 as u32 {
        if !(0 as i32 as u64 == (unsafe { strlen(newp) }) && flags & ((1 as i32) << 10 as i32) as u32 != 0) {
            if hostname_check(u, newp as *mut i8) as u64 != 0 {
                (unsafe { Curl_cfree.expect("non-null function pointer")(
                    newp as *mut i8 as *mut libc::c_void,
                ) });
                return CURLUE_MALFORMED_INPUT;
            }
        }
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")(*storep as *mut libc::c_void) });
    (unsafe { *storep = newp as *mut i8 });
    if port != 0 {
        (unsafe { (*u).portnum = port });
    }
    return CURLUE_OK;
}
