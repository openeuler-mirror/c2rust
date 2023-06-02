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
    pub type curl_pushheaders;
    pub type http_connect_state;
    pub type ldapconninfo;
    pub type tftp_state_data;
    pub type nghttp2_session;
    pub type Gsasl_session;
    pub type Gsasl;
    pub type ssl_backend_data;
    fn fclose(__stream: *mut FILE) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut FILE;
    fn fread(_: *mut libc::c_void, _: u64, _: u64, _: *mut FILE) -> u64;
    fn fseek(__stream: *mut FILE, __off: i64, __whence: i32) -> i32;
    fn ftell(__stream: *mut FILE) -> i64;
    fn curl_getenv(variable: *const i8) -> *mut i8;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strncpy(_: *mut i8, _: *const i8, _: u64) -> *mut i8;
    fn curl_slist_free_all(_: *mut curl_slist);
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: u64) -> i32;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strncmp(_: *const i8, _: *const i8, _: u64) -> i32;
    fn strstr(_: *const i8, _: *const i8) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    static Curl_ssl_openssl: Curl_ssl;
    fn Curl_slist_append_nodup(list: *mut curl_slist, data: *mut i8) -> *mut curl_slist;
    fn Curl_infof(_: *mut Curl_easy, fmt: *const i8, _: ...);
    fn Curl_failf(_: *mut Curl_easy, fmt: *const i8, _: ...);
    fn Curl_recv_plain(
        data: *mut Curl_easy,
        num: i32,
        buf: *mut i8,
        len: size_t,
        code: *mut CURLcode,
    ) -> ssize_t;
    fn Curl_send_plain(
        data: *mut Curl_easy,
        num: i32,
        mem: *const libc::c_void,
        len: size_t,
        code: *mut CURLcode,
    ) -> ssize_t;
    fn Curl_strcasecompare(first: *const i8, second: *const i8) -> i32;
    fn Curl_safe_strcasecompare(first: *const i8, second: *const i8) -> i32;
    fn Curl_pgrsTime(data: *mut Curl_easy, timer: timerid) -> curltime;
    fn Curl_share_lock(_: *mut Curl_easy, _: curl_lock_data, _: curl_lock_access) -> CURLSHcode;
    fn Curl_share_unlock(_: *mut Curl_easy, _: curl_lock_data) -> CURLSHcode;
    fn curlx_sotouz(sonum: curl_off_t) -> size_t;
    fn Curl_base64_encode(
        data: *mut Curl_easy,
        inputbuff: *const i8,
        insize: size_t,
        outptr: *mut *mut i8,
        outlen: *mut size_t,
    ) -> CURLcode;
    fn Curl_base64_decode(src: *const i8, outptr: *mut *mut u8, outlen: *mut size_t) -> CURLcode;
    fn curl_msnprintf(buffer: *mut i8, maxlength: size_t, format: *const i8, _: ...) -> i32;
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
pub type curl_calloc_callback = Option<unsafe extern "C" fn(size_t, size_t) -> *mut libc::c_void>;
pub type C2RustUnnamed_6 = u32;
pub const CURL_SSLVERSION_LAST: C2RustUnnamed_6 = 8;
pub const CURL_SSLVERSION_TLSv1_3: C2RustUnnamed_6 = 7;
pub const CURL_SSLVERSION_TLSv1_2: C2RustUnnamed_6 = 6;
pub const CURL_SSLVERSION_TLSv1_1: C2RustUnnamed_6 = 5;
pub const CURL_SSLVERSION_TLSv1_0: C2RustUnnamed_6 = 4;
pub const CURL_SSLVERSION_SSLv3: C2RustUnnamed_6 = 3;
pub const CURL_SSLVERSION_SSLv2: C2RustUnnamed_6 = 2;
pub const CURL_SSLVERSION_TLSv1: C2RustUnnamed_6 = 1;
pub const CURL_SSLVERSION_DEFAULT: C2RustUnnamed_6 = 0;
pub type C2RustUnnamed_7 = u32;
pub const CURL_SSLVERSION_MAX_LAST: C2RustUnnamed_7 = 524288;
pub const CURL_SSLVERSION_MAX_TLSv1_3: C2RustUnnamed_7 = 458752;
pub const CURL_SSLVERSION_MAX_TLSv1_2: C2RustUnnamed_7 = 393216;
pub const CURL_SSLVERSION_MAX_TLSv1_1: C2RustUnnamed_7 = 327680;
pub const CURL_SSLVERSION_MAX_TLSv1_0: C2RustUnnamed_7 = 262144;
pub const CURL_SSLVERSION_MAX_DEFAULT: C2RustUnnamed_7 = 65536;
pub const CURL_SSLVERSION_MAX_NONE: C2RustUnnamed_7 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_ssl_backend {
    pub id: curl_sslbackend,
    pub name: *const i8,
}
pub type CURLsslset = u32;
pub const CURLSSLSET_NO_BACKENDS: CURLsslset = 3;
pub const CURLSSLSET_TOO_LATE: CURLsslset = 2;
pub const CURLSSLSET_UNKNOWN_BACKEND: CURLsslset = 1;
pub const CURLSSLSET_OK: CURLsslset = 0;
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
extern "C" fn blobdup(mut dest: *mut *mut curl_blob, mut src: *mut curl_blob) -> CURLcode {
    if !src.is_null() {
        let mut d: *mut curl_blob = 0 as *mut curl_blob;
        d = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
            (::std::mem::size_of::<curl_blob>() as u64).wrapping_add((*src).len),
        ) }) as *mut curl_blob;
        if d.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (unsafe { (*d).len = (*src).len });
        (unsafe { (*d).flags = 1 as i32 as u32 });
        let fresh0 = unsafe { &mut ((*d).data) };
        *fresh0 = (unsafe { (d as *mut i8).offset(::std::mem::size_of::<curl_blob>() as u64 as isize) })
            as *mut libc::c_void;
        (unsafe { memcpy((*d).data, (*src).data, (*src).len) });
        (unsafe { *dest = d });
    }
    return CURLE_OK;
}
extern "C" fn blobcmp(mut first: *mut curl_blob, mut second: *mut curl_blob) -> bool {
    if first.is_null() && second.is_null() {
        return 1 as i32 != 0;
    }
    if first.is_null() || second.is_null() {
        return 0 as i32 != 0;
    }
    if (unsafe { (*first).len }) != (unsafe { (*second).len }) {
        return 0 as i32 != 0;
    }
    return (unsafe { memcmp((*first).data, (*second).data, (*first).len) }) == 0;
}
extern "C" fn safecmp(mut a: *mut i8, mut b: *mut i8) -> bool {
    if !a.is_null() && !b.is_null() {
        return (unsafe { strcmp(a, b) }) == 0;
    } else {
        if a.is_null() && b.is_null() {
            return 1 as i32 != 0;
        }
    }
    return 0 as i32 != 0;
}
#[no_mangle]
pub extern "C" fn Curl_ssl_config_matches(
    mut data: *mut ssl_primary_config,
    mut needle: *mut ssl_primary_config,
) -> bool {
    if (unsafe { (*data).version }) == (unsafe { (*needle).version })
        && (unsafe { (*data).version_max }) == (unsafe { (*needle).version_max })
        && (unsafe { (*data).verifypeer() }) as i32 == (unsafe { (*needle).verifypeer() }) as i32
        && (unsafe { (*data).verifyhost() }) as i32 == (unsafe { (*needle).verifyhost() }) as i32
        && (unsafe { (*data).verifystatus() }) as i32 == (unsafe { (*needle).verifystatus() }) as i32
        && blobcmp(unsafe { (*data).cert_blob }, unsafe { (*needle).cert_blob }) as i32 != 0
        && blobcmp(unsafe { (*data).ca_info_blob }, unsafe { (*needle).ca_info_blob }) as i32 != 0
        && blobcmp(unsafe { (*data).issuercert_blob }, unsafe { (*needle).issuercert_blob }) as i32 != 0
        && safecmp(unsafe { (*data).CApath }, unsafe { (*needle).CApath }) as i32 != 0
        && safecmp(unsafe { (*data).CAfile }, unsafe { (*needle).CAfile }) as i32 != 0
        && safecmp(unsafe { (*data).issuercert }, unsafe { (*needle).issuercert }) as i32 != 0
        && safecmp(unsafe { (*data).clientcert }, unsafe { (*needle).clientcert }) as i32 != 0
        && safecmp(unsafe { (*data).random_file }, unsafe { (*needle).random_file }) as i32 != 0
        && safecmp(unsafe { (*data).egdsocket }, unsafe { (*needle).egdsocket }) as i32 != 0
        && (unsafe { Curl_safe_strcasecompare((*data).cipher_list, (*needle).cipher_list) }) != 0
        && (unsafe { Curl_safe_strcasecompare((*data).cipher_list13, (*needle).cipher_list13) }) != 0
        && (unsafe { Curl_safe_strcasecompare((*data).curves, (*needle).curves) }) != 0
        && (unsafe { Curl_safe_strcasecompare((*data).pinned_key, (*needle).pinned_key) }) != 0
    {
        return 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
#[no_mangle]
pub extern "C" fn Curl_clone_primary_ssl_config(
    mut source: *mut ssl_primary_config,
    mut dest: *mut ssl_primary_config,
) -> bool {
    (unsafe { (*dest).version = (*source).version });
    (unsafe { (*dest).version_max = (*source).version_max });
    (unsafe { (*dest).set_verifypeer((*source).verifypeer()) });
    (unsafe { (*dest).set_verifyhost((*source).verifyhost()) });
    (unsafe { (*dest).set_verifystatus((*source).verifystatus()) });
    (unsafe { (*dest).set_sessionid((*source).sessionid()) });
    if blobdup(unsafe { &mut (*dest).cert_blob }, unsafe { (*source).cert_blob }) as u64 != 0 {
        return 0 as i32 != 0;
    }
    if blobdup(unsafe { &mut (*dest).ca_info_blob }, unsafe { (*source).ca_info_blob }) as u64 != 0 {
        return 0 as i32 != 0;
    }
    if blobdup(unsafe { &mut (*dest).issuercert_blob }, unsafe { (*source).issuercert_blob }) as u64 != 0 {
        return 0 as i32 != 0;
    }
    if !(unsafe { (*source).CApath }).is_null() {
        let fresh1 = unsafe { &mut ((*dest).CApath) };
        *fresh1 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*source).CApath) };
        if (unsafe { (*dest).CApath }).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let fresh2 = unsafe { &mut ((*dest).CApath) };
        *fresh2 = 0 as *mut i8;
    }
    if !(unsafe { (*source).CAfile }).is_null() {
        let fresh3 = unsafe { &mut ((*dest).CAfile) };
        *fresh3 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*source).CAfile) };
        if (unsafe { (*dest).CAfile }).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let fresh4 = unsafe { &mut ((*dest).CAfile) };
        *fresh4 = 0 as *mut i8;
    }
    if !(unsafe { (*source).issuercert }).is_null() {
        let fresh5 = unsafe { &mut ((*dest).issuercert) };
        *fresh5 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*source).issuercert) };
        if (unsafe { (*dest).issuercert }).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let fresh6 = unsafe { &mut ((*dest).issuercert) };
        *fresh6 = 0 as *mut i8;
    }
    if !(unsafe { (*source).clientcert }).is_null() {
        let fresh7 = unsafe { &mut ((*dest).clientcert) };
        *fresh7 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*source).clientcert) };
        if (unsafe { (*dest).clientcert }).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let fresh8 = unsafe { &mut ((*dest).clientcert) };
        *fresh8 = 0 as *mut i8;
    }
    if !(unsafe { (*source).random_file }).is_null() {
        let fresh9 = unsafe { &mut ((*dest).random_file) };
        *fresh9 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*source).random_file) };
        if (unsafe { (*dest).random_file }).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let fresh10 = unsafe { &mut ((*dest).random_file) };
        *fresh10 = 0 as *mut i8;
    }
    if !(unsafe { (*source).egdsocket }).is_null() {
        let fresh11 = unsafe { &mut ((*dest).egdsocket) };
        *fresh11 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*source).egdsocket) };
        if (unsafe { (*dest).egdsocket }).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let fresh12 = unsafe { &mut ((*dest).egdsocket) };
        *fresh12 = 0 as *mut i8;
    }
    if !(unsafe { (*source).cipher_list }).is_null() {
        let fresh13 = unsafe { &mut ((*dest).cipher_list) };
        *fresh13 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*source).cipher_list) };
        if (unsafe { (*dest).cipher_list }).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let fresh14 = unsafe { &mut ((*dest).cipher_list) };
        *fresh14 = 0 as *mut i8;
    }
    if !(unsafe { (*source).cipher_list13 }).is_null() {
        let fresh15 = unsafe { &mut ((*dest).cipher_list13) };
        *fresh15 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*source).cipher_list13) };
        if (unsafe { (*dest).cipher_list13 }).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let fresh16 = unsafe { &mut ((*dest).cipher_list13) };
        *fresh16 = 0 as *mut i8;
    }
    if !(unsafe { (*source).pinned_key }).is_null() {
        let fresh17 = unsafe { &mut ((*dest).pinned_key) };
        *fresh17 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*source).pinned_key) };
        if (unsafe { (*dest).pinned_key }).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let fresh18 = unsafe { &mut ((*dest).pinned_key) };
        *fresh18 = 0 as *mut i8;
    }
    if !(unsafe { (*source).curves }).is_null() {
        let fresh19 = unsafe { &mut ((*dest).curves) };
        *fresh19 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*source).curves) };
        if (unsafe { (*dest).curves }).is_null() {
            return 0 as i32 != 0;
        }
    } else {
        let fresh20 = unsafe { &mut ((*dest).curves) };
        *fresh20 = 0 as *mut i8;
    }
    return 1 as i32 != 0;
}
#[no_mangle]
pub extern "C" fn Curl_free_primary_ssl_config(mut sslc: *mut ssl_primary_config) {
    (unsafe { Curl_cfree.expect("non-null function pointer")((*sslc).CApath as *mut libc::c_void) });
    let fresh21 = unsafe { &mut ((*sslc).CApath) };
    *fresh21 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*sslc).CAfile as *mut libc::c_void) });
    let fresh22 = unsafe { &mut ((*sslc).CAfile) };
    *fresh22 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*sslc).issuercert as *mut libc::c_void) });
    let fresh23 = unsafe { &mut ((*sslc).issuercert) };
    *fresh23 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*sslc).clientcert as *mut libc::c_void) });
    let fresh24 = unsafe { &mut ((*sslc).clientcert) };
    *fresh24 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*sslc).random_file as *mut libc::c_void) });
    let fresh25 = unsafe { &mut ((*sslc).random_file) };
    *fresh25 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*sslc).egdsocket as *mut libc::c_void) });
    let fresh26 = unsafe { &mut ((*sslc).egdsocket) };
    *fresh26 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*sslc).cipher_list as *mut libc::c_void) });
    let fresh27 = unsafe { &mut ((*sslc).cipher_list) };
    *fresh27 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*sslc).cipher_list13 as *mut libc::c_void) });
    let fresh28 = unsafe { &mut ((*sslc).cipher_list13) };
    *fresh28 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*sslc).pinned_key as *mut libc::c_void) });
    let fresh29 = unsafe { &mut ((*sslc).pinned_key) };
    *fresh29 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*sslc).cert_blob as *mut libc::c_void) });
    let fresh30 = unsafe { &mut ((*sslc).cert_blob) };
    *fresh30 = 0 as *mut curl_blob;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*sslc).ca_info_blob as *mut libc::c_void) });
    let fresh31 = unsafe { &mut ((*sslc).ca_info_blob) };
    *fresh31 = 0 as *mut curl_blob;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*sslc).issuercert_blob as *mut libc::c_void) });
    let fresh32 = unsafe { &mut ((*sslc).issuercert_blob) };
    *fresh32 = 0 as *mut curl_blob;
    (unsafe { Curl_cfree.expect("non-null function pointer")((*sslc).curves as *mut libc::c_void) });
    let fresh33 = unsafe { &mut ((*sslc).curves) };
    *fresh33 = 0 as *mut i8;
}
#[no_mangle]
pub extern "C" fn Curl_ssl_backend() -> i32 {
    multissl_setup(0 as *const Curl_ssl);
    return (unsafe { (*Curl_ssl).info.id }) as i32;
}
static mut init_ssl: bool = 0 as i32 != 0;
#[no_mangle]
pub extern "C" fn Curl_ssl_init() -> i32 {
    if unsafe { init_ssl } {
        return 1 as i32;
    }
    (unsafe { init_ssl = 1 as i32 != 0 });
    return unsafe { ((*Curl_ssl).init).expect("non-null function pointer")() };
}
#[no_mangle]
pub extern "C" fn Curl_ssl_cleanup() {
    if unsafe { init_ssl } {
        (unsafe { ((*Curl_ssl).cleanup).expect("non-null function pointer")() });
        (unsafe { init_ssl = 0 as i32 != 0 });
    }
}
extern "C" fn ssl_prefs_check(mut data: *mut Curl_easy) -> bool {
    let sslver: i64 = unsafe { (*data).set.ssl.primary.version };
    if sslver < 0 as i32 as i64 || sslver >= CURL_SSLVERSION_LAST as i32 as i64 {
        (unsafe { Curl_failf(
            data,
            b"Unrecognized parameter value passed via CURLOPT_SSLVERSION\0" as *const u8
                as *const i8,
        ) });
        return 0 as i32 != 0;
    }
    match unsafe { (*data).set.ssl.primary.version_max } {
        0 | 65536 => {}
        _ => {
            if ((unsafe { (*data).set.ssl.primary.version_max }) >> 16 as i32) < sslver {
                (unsafe { Curl_failf(
                    data,
                    b"CURL_SSLVERSION_MAX incompatible with CURL_SSLVERSION\0" as *const u8
                        as *const i8,
                ) });
                return 0 as i32 != 0;
            }
        }
    }
    return 1 as i32 != 0;
}
extern "C" fn ssl_connect_init_proxy(mut conn: *mut connectdata, mut sockindex: i32) -> CURLcode {
    if ssl_connection_complete as i32 as u32 == (unsafe { (*conn).ssl[sockindex as usize].state }) as u32
        && (unsafe { ((*conn).proxy_ssl[sockindex as usize]).use_0() }) == 0
    {
        let mut pbdata: *mut ssl_backend_data = 0 as *mut ssl_backend_data;
        if (unsafe { (*Curl_ssl).supports }) & ((1 as i32) << 4 as i32) as u32 == 0 {
            return CURLE_NOT_BUILT_IN;
        }
        pbdata = unsafe { (*conn).proxy_ssl[sockindex as usize].backend };
        (unsafe { (*conn).proxy_ssl[sockindex as usize] = (*conn).ssl[sockindex as usize] });
        (unsafe { memset(
            &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) as *mut ssl_connect_data
                as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<ssl_connect_data>() as u64,
        ) });
        (unsafe { memset(
            pbdata as *mut libc::c_void,
            0 as i32,
            (*Curl_ssl).sizeof_ssl_backend_data,
        ) });
        let fresh34 = unsafe { &mut ((*conn).ssl[sockindex as usize].backend) };
        *fresh34 = pbdata;
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_ssl_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    if unsafe { (*conn).bits.proxy_ssl_connected[sockindex as usize] } {
        result = ssl_connect_init_proxy(conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    if !ssl_prefs_check(data) {
        return CURLE_SSL_CONNECT_ERROR;
    }
    let fresh35 = unsafe { &mut ((*conn).ssl[sockindex as usize]) };
    (*fresh35).set_use_0(1 as i32 as bit);
    (unsafe { (*conn).ssl[sockindex as usize].state = ssl_connection_negotiating });
    result =
        unsafe { ((*Curl_ssl).connect_blocking).expect("non-null function pointer")(data, conn, sockindex) };
    if result as u64 == 0 {
        (unsafe { Curl_pgrsTime(data, TIMER_APPCONNECT) });
    } else {
        let fresh36 = unsafe { &mut ((*conn).ssl[sockindex as usize]) };
        (*fresh36).set_use_0(0 as i32 as bit);
    }
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_ssl_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut isproxy: bool,
    mut sockindex: i32,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    if unsafe { (*conn).bits.proxy_ssl_connected[sockindex as usize] } {
        result = ssl_connect_init_proxy(conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    if !ssl_prefs_check(data) {
        return CURLE_SSL_CONNECT_ERROR;
    }
    let fresh37 = unsafe { &mut ((*conn).ssl[sockindex as usize]) };
    (*fresh37).set_use_0(1 as i32 as bit);
    result = unsafe { ((*Curl_ssl).connect_nonblocking).expect("non-null function pointer")(
        data, conn, sockindex, done,
    ) };
    if result as u64 != 0 {
        let fresh38 = unsafe { &mut ((*conn).ssl[sockindex as usize]) };
        (*fresh38).set_use_0(0 as i32 as bit);
    } else if (unsafe { *done }) as i32 != 0 && !isproxy {
        (unsafe { Curl_pgrsTime(data, TIMER_APPCONNECT) });
    }
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_ssl_sessionid_lock(mut data: *mut Curl_easy) {
    if !(unsafe { (*data).share }).is_null()
        && (unsafe { (*(*data).share).specifier }) & ((1 as i32) << CURL_LOCK_DATA_SSL_SESSION as i32) as u32
            != 0
    {
        (unsafe { Curl_share_lock(data, CURL_LOCK_DATA_SSL_SESSION, CURL_LOCK_ACCESS_SINGLE) });
    }
}
#[no_mangle]
pub extern "C" fn Curl_ssl_sessionid_unlock(mut data: *mut Curl_easy) {
    if !(unsafe { (*data).share }).is_null()
        && (unsafe { (*(*data).share).specifier }) & ((1 as i32) << CURL_LOCK_DATA_SSL_SESSION as i32) as u32
            != 0
    {
        (unsafe { Curl_share_unlock(data, CURL_LOCK_DATA_SSL_SESSION) });
    }
}
#[no_mangle]
pub extern "C" fn Curl_ssl_getsessionid(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    isProxy: bool,
    mut ssl_sessionid: *mut *mut libc::c_void,
    mut idsize: *mut size_t,
    mut _sockindex: i32,
) -> bool {
    let mut check: *mut Curl_ssl_session = 0 as *mut Curl_ssl_session;
    let mut i: size_t = 0;
    let mut general_age: *mut i64 = 0 as *mut i64;
    let mut no_match: bool = 1 as i32 != 0;
    let ssl_config: *mut ssl_primary_config = if isProxy as i32 != 0 {
        unsafe { &mut (*conn).proxy_ssl_config }
    } else {
        unsafe { &mut (*conn).ssl_config }
    };
    let name: *const i8 = if isProxy as i32 != 0 {
        unsafe { (*conn).http_proxy.host.name }
    } else {
        unsafe { (*conn).host.name }
    };
    let mut port: i32 = if isProxy as i32 != 0 {
        unsafe { (*conn).port }
    } else {
        unsafe { (*conn).remote_port }
    };
    (unsafe { *ssl_sessionid = 0 as *mut libc::c_void });
    if (if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        (unsafe { ((*data).set.proxy_ssl.primary).sessionid() }) as i32
    } else {
        (unsafe { ((*data).set.ssl.primary).sessionid() }) as i32
    }) == 0
        || (unsafe { (*data).state.session }).is_null()
    {
        return 1 as i32 != 0;
    }
    if !(unsafe { (*data).share }).is_null()
        && (unsafe { (*(*data).share).specifier }) & ((1 as i32) << CURL_LOCK_DATA_SSL_SESSION as i32) as u32
            != 0
    {
        general_age = unsafe { &mut (*(*data).share).sessionage };
    } else {
        general_age = unsafe { &mut (*data).state.sessionage };
    }
    i = 0 as i32 as size_t;
    while i < (unsafe { (*data).set.general_ssl.max_ssl_sessions }) {
        check = (unsafe { &mut *((*data).state.session).offset(i as isize) }) as *mut Curl_ssl_session;
        if !(unsafe { (*check).sessionid }).is_null() {
            if (unsafe { Curl_strcasecompare(name, (*check).name) }) != 0
                && ((unsafe { ((*conn).bits).conn_to_host() }) == 0 && (unsafe { (*check).conn_to_host }).is_null()
                    || (unsafe { ((*conn).bits).conn_to_host() }) as i32 != 0
                        && !(unsafe { (*check).conn_to_host }).is_null()
                        && (unsafe { Curl_strcasecompare((*conn).conn_to_host.name, (*check).conn_to_host) })
                            != 0)
                && ((unsafe { ((*conn).bits).conn_to_port() }) == 0 && (unsafe { (*check).conn_to_port }) == -(1 as i32)
                    || (unsafe { ((*conn).bits).conn_to_port() }) as i32 != 0
                        && (unsafe { (*check).conn_to_port }) != -(1 as i32)
                        && (unsafe { (*conn).conn_to_port }) == (unsafe { (*check).conn_to_port }))
                && port == (unsafe { (*check).remote_port })
                && (unsafe { Curl_strcasecompare((*(*conn).handler).scheme, (*check).scheme) }) != 0
                && Curl_ssl_config_matches(ssl_config, unsafe { &mut (*check).ssl_config }) as i32 != 0
            {
                (unsafe { *general_age += 1 });
                (unsafe { (*check).age = *general_age });
                (unsafe { *ssl_sessionid = (*check).sessionid });
                if !idsize.is_null() {
                    (unsafe { *idsize = (*check).idsize });
                }
                no_match = 0 as i32 != 0;
                break;
            }
        }
        i = i.wrapping_add(1);
    }
    return no_match;
}
#[no_mangle]
pub extern "C" fn Curl_ssl_kill_session(mut session: *mut Curl_ssl_session) {
    if !(unsafe { (*session).sessionid }).is_null() {
        (unsafe { ((*Curl_ssl).session_free).expect("non-null function pointer")((*session).sessionid) });
        let fresh39 = unsafe { &mut ((*session).sessionid) };
        *fresh39 = 0 as *mut libc::c_void;
        (unsafe { (*session).age = 0 as i32 as i64 });
        Curl_free_primary_ssl_config(unsafe { &mut (*session).ssl_config });
        (unsafe { Curl_cfree.expect("non-null function pointer")((*session).name as *mut libc::c_void) });
        let fresh40 = unsafe { &mut ((*session).name) };
        *fresh40 = 0 as *mut i8;
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            (*session).conn_to_host as *mut libc::c_void,
        ) });
        let fresh41 = unsafe { &mut ((*session).conn_to_host) };
        *fresh41 = 0 as *mut i8;
    }
}
#[no_mangle]
pub extern "C" fn Curl_ssl_delsessionid(
    mut data: *mut Curl_easy,
    mut ssl_sessionid: *mut libc::c_void,
) {
    let mut i: size_t = 0;
    i = 0 as i32 as size_t;
    while i < (unsafe { (*data).set.general_ssl.max_ssl_sessions }) {
        let mut check: *mut Curl_ssl_session =
            (unsafe { &mut *((*data).state.session).offset(i as isize) }) as *mut Curl_ssl_session;
        if (unsafe { (*check).sessionid }) == ssl_sessionid {
            Curl_ssl_kill_session(check);
            break;
        } else {
            i = i.wrapping_add(1);
        }
    }
}
#[no_mangle]
pub extern "C" fn Curl_ssl_addsessionid(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    isProxy: bool,
    mut ssl_sessionid: *mut libc::c_void,
    mut idsize: size_t,
    mut _sockindex: i32,
) -> CURLcode {
    let mut i: size_t = 0;
    let mut store: *mut Curl_ssl_session = 0 as *mut Curl_ssl_session;
    let mut oldest_age: i64 = 0;
    let mut clone_host: *mut i8 = 0 as *mut i8;
    let mut clone_conn_to_host: *mut i8 = 0 as *mut i8;
    let mut conn_to_port: i32 = 0;
    let mut general_age: *mut i64 = 0 as *mut i64;
    let ssl_config: *mut ssl_primary_config = if isProxy as i32 != 0 {
        unsafe { &mut (*conn).proxy_ssl_config }
    } else {
        unsafe { &mut (*conn).ssl_config }
    };
    let mut hostname: *const i8 = if isProxy as i32 != 0 {
        unsafe { (*conn).http_proxy.host.name }
    } else {
        unsafe { (*conn).host.name }
    };
    if (unsafe { (*data).state.session }).is_null() {
        return CURLE_OK;
    }
    store = (unsafe { &mut *((*data).state.session).offset(0 as i32 as isize) }) as *mut Curl_ssl_session;
    oldest_age = unsafe { (*((*data).state.session).offset(0 as i32 as isize)).age };
    clone_host = unsafe { Curl_cstrdup.expect("non-null function pointer")(hostname) };
    if clone_host.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if (unsafe { ((*conn).bits).conn_to_host() }) != 0 {
        clone_conn_to_host =
            unsafe { Curl_cstrdup.expect("non-null function pointer")((*conn).conn_to_host.name) };
        if clone_conn_to_host.is_null() {
            (unsafe { Curl_cfree.expect("non-null function pointer")(clone_host as *mut libc::c_void) });
            return CURLE_OUT_OF_MEMORY;
        }
    } else {
        clone_conn_to_host = 0 as *mut i8;
    }
    if (unsafe { ((*conn).bits).conn_to_port() }) != 0 {
        conn_to_port = unsafe { (*conn).conn_to_port };
    } else {
        conn_to_port = -(1 as i32);
    }
    if !(unsafe { (*data).share }).is_null()
        && (unsafe { (*(*data).share).specifier }) & ((1 as i32) << CURL_LOCK_DATA_SSL_SESSION as i32) as u32
            != 0
    {
        general_age = unsafe { &mut (*(*data).share).sessionage };
    } else {
        general_age = unsafe { &mut (*data).state.sessionage };
    }
    i = 1 as i32 as size_t;
    while i < (unsafe { (*data).set.general_ssl.max_ssl_sessions })
        && !(unsafe { (*((*data).state.session).offset(i as isize)).sessionid }).is_null()
    {
        if (unsafe { (*((*data).state.session).offset(i as isize)).age }) < oldest_age {
            oldest_age = unsafe { (*((*data).state.session).offset(i as isize)).age };
            store = (unsafe { &mut *((*data).state.session).offset(i as isize) }) as *mut Curl_ssl_session;
        }
        i = i.wrapping_add(1);
    }
    if i == (unsafe { (*data).set.general_ssl.max_ssl_sessions }) {
        Curl_ssl_kill_session(store);
    } else {
        store = (unsafe { &mut *((*data).state.session).offset(i as isize) }) as *mut Curl_ssl_session;
    }
    let fresh42 = unsafe { &mut ((*store).sessionid) };
    *fresh42 = ssl_sessionid;
    (unsafe { (*store).idsize = idsize });
    (unsafe { (*store).age = *general_age });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*store).name as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")((*store).conn_to_host as *mut libc::c_void) });
    let fresh43 = unsafe { &mut ((*store).name) };
    *fresh43 = clone_host;
    let fresh44 = unsafe { &mut ((*store).conn_to_host) };
    *fresh44 = clone_conn_to_host;
    (unsafe { (*store).conn_to_port = conn_to_port });
    (unsafe { (*store).remote_port = if isProxy as i32 != 0 {
        (*conn).port
    } else {
        (*conn).remote_port
    } });
    let fresh45 = unsafe { &mut ((*store).scheme) };
    *fresh45 = unsafe { (*(*conn).handler).scheme };
    if !Curl_clone_primary_ssl_config(ssl_config, unsafe { &mut (*store).ssl_config }) {
        Curl_free_primary_ssl_config(unsafe { &mut (*store).ssl_config });
        let fresh46 = unsafe { &mut ((*store).sessionid) };
        *fresh46 = 0 as *mut libc::c_void;
        (unsafe { Curl_cfree.expect("non-null function pointer")(clone_host as *mut libc::c_void) });
        (unsafe { Curl_cfree.expect("non-null function pointer")(clone_conn_to_host as *mut libc::c_void) });
        return CURLE_OUT_OF_MEMORY;
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_ssl_associate_conn(mut data: *mut Curl_easy, mut conn: *mut connectdata) {
    if unsafe { ((*Curl_ssl).associate_connection).is_some() } {
        (unsafe { ((*Curl_ssl).associate_connection).expect("non-null function pointer")(
            data, conn, 0 as i32,
        ) });
        if (unsafe { (*conn).sock[1 as i32 as usize] }) != 0 && (unsafe { ((*conn).bits).sock_accepted() }) as i32 != 0 {
            (unsafe { ((*Curl_ssl).associate_connection).expect("non-null function pointer")(
                data, conn, 1 as i32,
            ) });
        }
    }
}
#[no_mangle]
pub extern "C" fn Curl_ssl_detach_conn(mut data: *mut Curl_easy, mut conn: *mut connectdata) {
    if unsafe { ((*Curl_ssl).disassociate_connection).is_some() } {
        (unsafe { ((*Curl_ssl).disassociate_connection).expect("non-null function pointer")(data, 0 as i32) });
        if (unsafe { (*conn).sock[1 as i32 as usize] }) != 0 && (unsafe { ((*conn).bits).sock_accepted() }) as i32 != 0 {
            (unsafe { ((*Curl_ssl).disassociate_connection).expect("non-null function pointer")(
                data, 1 as i32,
            ) });
        }
    }
}
#[no_mangle]
pub extern "C" fn Curl_ssl_close_all(mut data: *mut Curl_easy) {
    if !(unsafe { (*data).state.session }).is_null()
        && !(!(unsafe { (*data).share }).is_null()
            && (unsafe { (*(*data).share).specifier })
                & ((1 as i32) << CURL_LOCK_DATA_SSL_SESSION as i32) as u32
                != 0)
    {
        let mut i: size_t = 0;
        i = 0 as i32 as size_t;
        while i < (unsafe { (*data).set.general_ssl.max_ssl_sessions }) {
            Curl_ssl_kill_session(unsafe { &mut *((*data).state.session).offset(i as isize) });
            i = i.wrapping_add(1);
        }
        (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.session as *mut libc::c_void) });
        let fresh47 = unsafe { &mut ((*data).state.session) };
        *fresh47 = 0 as *mut Curl_ssl_session;
    }
    (unsafe { ((*Curl_ssl).close_all).expect("non-null function pointer")(data) });
}
#[no_mangle]
pub extern "C" fn Curl_ssl_getsock(
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> i32 {
    let mut connssl: *mut ssl_connect_data =
        (unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(0 as i32 as isize) }) as *mut ssl_connect_data;
    if (unsafe { (*connssl).connecting_state }) as u32 == ssl_connect_2_writing as i32 as u32 {
        (unsafe { *socks.offset(0 as i32 as isize) = (*conn).sock[0 as i32 as usize] });
        return (1 as i32) << 16 as i32 + 0 as i32;
    }
    if (unsafe { (*connssl).connecting_state }) as u32 == ssl_connect_2_reading as i32 as u32 {
        (unsafe { *socks.offset(0 as i32 as isize) = (*conn).sock[0 as i32 as usize] });
        return (1 as i32) << 0 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn Curl_ssl_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) {
    (unsafe { ((*Curl_ssl).close_one).expect("non-null function pointer")(data, conn, sockindex) });
    (unsafe { (*conn).ssl[sockindex as usize].state = ssl_connection_none });
}
#[no_mangle]
pub extern "C" fn Curl_ssl_shutdown(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    if (unsafe { ((*Curl_ssl).shut_down).expect("non-null function pointer")(data, conn, sockindex) }) != 0 {
        return CURLE_SSL_SHUTDOWN_FAILED;
    }
    let fresh48 = unsafe { &mut ((*conn).ssl[sockindex as usize]) };
    (*fresh48).set_use_0(0 as i32 as bit);
    (unsafe { (*conn).ssl[sockindex as usize].state = ssl_connection_none });
    let fresh49 = unsafe { &mut ((*conn).recv[sockindex as usize]) };
    *fresh49 = Some(
        Curl_recv_plain
            as unsafe extern "C" fn(*mut Curl_easy, i32, *mut i8, size_t, *mut CURLcode) -> ssize_t,
    );
    let fresh50 = unsafe { &mut ((*conn).send[sockindex as usize]) };
    *fresh50 = Some(
        Curl_send_plain
            as unsafe extern "C" fn(
                *mut Curl_easy,
                i32,
                *const libc::c_void,
                size_t,
                *mut CURLcode,
            ) -> ssize_t,
    );
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_ssl_set_engine(mut data: *mut Curl_easy, mut engine: *const i8) -> CURLcode {
    return unsafe { ((*Curl_ssl).set_engine).expect("non-null function pointer")(data, engine) };
}
#[no_mangle]
pub extern "C" fn Curl_ssl_set_engine_default(mut data: *mut Curl_easy) -> CURLcode {
    return unsafe { ((*Curl_ssl).set_engine_default).expect("non-null function pointer")(data) };
}
#[no_mangle]
pub extern "C" fn Curl_ssl_engines_list(mut data: *mut Curl_easy) -> *mut curl_slist {
    return unsafe { ((*Curl_ssl).engines_list).expect("non-null function pointer")(data) };
}
#[no_mangle]
pub extern "C" fn Curl_ssl_initsessions(mut data: *mut Curl_easy, mut amount: size_t) -> CURLcode {
    let mut session: *mut Curl_ssl_session = 0 as *mut Curl_ssl_session;
    if !(unsafe { (*data).state.session }).is_null() {
        return CURLE_OK;
    }
    session = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
        amount,
        ::std::mem::size_of::<Curl_ssl_session>() as u64,
    ) }) as *mut Curl_ssl_session;
    if session.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    (unsafe { (*data).set.general_ssl.max_ssl_sessions = amount });
    let fresh51 = unsafe { &mut ((*data).state.session) };
    *fresh51 = session;
    (unsafe { (*data).state.sessionage = 1 as i32 as i64 });
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_ssl_version(mut buffer: *mut i8, mut size: size_t) {
    (unsafe { ((*Curl_ssl).version).expect("non-null function pointer")(buffer, size) });
}
#[no_mangle]
pub extern "C" fn Curl_ssl_check_cxn(mut conn: *mut connectdata) -> i32 {
    return unsafe { ((*Curl_ssl).check_cxn).expect("non-null function pointer")(conn) };
}
#[no_mangle]
pub extern "C" fn Curl_ssl_data_pending(mut conn: *const connectdata, mut connindex: i32) -> bool {
    return unsafe { ((*Curl_ssl).data_pending).expect("non-null function pointer")(conn, connindex) };
}
#[no_mangle]
pub extern "C" fn Curl_ssl_free_certinfo(mut data: *mut Curl_easy) {
    let mut ci: *mut curl_certinfo = unsafe { &mut (*data).info.certs };
    if (unsafe { (*ci).num_of_certs }) != 0 {
        let mut i: i32 = 0;
        i = 0 as i32;
        while i < (unsafe { (*ci).num_of_certs }) {
            (unsafe { curl_slist_free_all(*((*ci).certinfo).offset(i as isize)) });
            let fresh52 = unsafe { &mut (*((*ci).certinfo).offset(i as isize)) };
            *fresh52 = 0 as *mut curl_slist;
            i += 1;
        }
        (unsafe { Curl_cfree.expect("non-null function pointer")((*ci).certinfo as *mut libc::c_void) });
        let fresh53 = unsafe { &mut ((*ci).certinfo) };
        *fresh53 = 0 as *mut *mut curl_slist;
        (unsafe { (*ci).num_of_certs = 0 as i32 });
    }
}
#[no_mangle]
pub extern "C" fn Curl_ssl_init_certinfo(mut data: *mut Curl_easy, mut num: i32) -> CURLcode {
    let mut ci: *mut curl_certinfo = unsafe { &mut (*data).info.certs };
    let mut table: *mut *mut curl_slist = 0 as *mut *mut curl_slist;
    Curl_ssl_free_certinfo(data);
    table = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
        num as size_t,
        ::std::mem::size_of::<*mut curl_slist>() as u64,
    ) }) as *mut *mut curl_slist;
    if table.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    (unsafe { (*ci).num_of_certs = num });
    let fresh54 = unsafe { &mut ((*ci).certinfo) };
    *fresh54 = table;
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_ssl_push_certinfo_len(
    mut data: *mut Curl_easy,
    mut certnum: i32,
    mut label: *const i8,
    mut value: *const i8,
    mut valuelen: size_t,
) -> CURLcode {
    let mut ci: *mut curl_certinfo = unsafe { &mut (*data).info.certs };
    let mut output: *mut i8 = 0 as *mut i8;
    let mut nl: *mut curl_slist = 0 as *mut curl_slist;
    let mut result: CURLcode = CURLE_OK;
    let mut labellen: size_t = unsafe { strlen(label) };
    let mut outlen: size_t = labellen
        .wrapping_add(1 as i32 as u64)
        .wrapping_add(valuelen)
        .wrapping_add(1 as i32 as u64);
    output = (unsafe { Curl_cmalloc.expect("non-null function pointer")(outlen) }) as *mut i8;
    if output.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    (unsafe { curl_msnprintf(output, outlen, b"%s:\0" as *const u8 as *const i8, label) });
    (unsafe { memcpy(
        &mut *output.offset(labellen.wrapping_add(1 as i32 as u64) as isize) as *mut i8
            as *mut libc::c_void,
        value as *const libc::c_void,
        valuelen,
    ) });
    (unsafe { *output.offset(
        labellen
            .wrapping_add(1 as i32 as u64)
            .wrapping_add(valuelen) as isize,
    ) = 0 as i32 as i8 });
    nl = unsafe { Curl_slist_append_nodup(*((*ci).certinfo).offset(certnum as isize), output) };
    if nl.is_null() {
        (unsafe { Curl_cfree.expect("non-null function pointer")(output as *mut libc::c_void) });
        (unsafe { curl_slist_free_all(*((*ci).certinfo).offset(certnum as isize)) });
        result = CURLE_OUT_OF_MEMORY;
    }
    let fresh55 = unsafe { &mut (*((*ci).certinfo).offset(certnum as isize)) };
    *fresh55 = nl;
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_ssl_push_certinfo(
    mut data: *mut Curl_easy,
    mut certnum: i32,
    mut label: *const i8,
    mut value: *const i8,
) -> CURLcode {
    let mut valuelen: size_t = unsafe { strlen(value) };
    return Curl_ssl_push_certinfo_len(data, certnum, label, value, valuelen);
}
#[no_mangle]
pub extern "C" fn Curl_ssl_random(
    mut data: *mut Curl_easy,
    mut entropy: *mut u8,
    mut length: size_t,
) -> CURLcode {
    return unsafe { ((*Curl_ssl).random).expect("non-null function pointer")(data, entropy, length) };
}
extern "C" fn pubkey_pem_to_der(
    mut pem: *const i8,
    mut der: *mut *mut u8,
    mut der_len: *mut size_t,
) -> CURLcode {
    let mut stripped_pem: *mut i8 = 0 as *mut i8;
    let mut begin_pos: *mut i8 = 0 as *mut i8;
    let mut end_pos: *mut i8 = 0 as *mut i8;
    let mut pem_count: size_t = 0;
    let mut stripped_pem_count: size_t = 0 as i32 as size_t;
    let mut pem_len: size_t = 0;
    let mut result: CURLcode = CURLE_OK;
    if pem.is_null() {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    begin_pos = unsafe { strstr(
        pem,
        b"-----BEGIN PUBLIC KEY-----\0" as *const u8 as *const i8,
    ) };
    if begin_pos.is_null() {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    pem_count = (unsafe { begin_pos.offset_from(pem) }) as i64 as size_t;
    if 0 as i32 as u64 != pem_count
        && '\n' as i32 != (unsafe { *pem.offset(pem_count.wrapping_sub(1 as i32 as u64) as isize) }) as i32
    {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    pem_count = (pem_count as u64).wrapping_add(26 as i32 as u64) as size_t as size_t;
    end_pos = unsafe { strstr(
        pem.offset(pem_count as isize),
        b"\n-----END PUBLIC KEY-----\0" as *const u8 as *const i8,
    ) };
    if end_pos.is_null() {
        return CURLE_BAD_CONTENT_ENCODING;
    }
    pem_len = (unsafe { end_pos.offset_from(pem) }) as i64 as size_t;
    stripped_pem = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
        pem_len
            .wrapping_sub(pem_count)
            .wrapping_add(1 as i32 as u64),
    ) }) as *mut i8;
    if stripped_pem.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    while pem_count < pem_len {
        if '\n' as i32 != (unsafe { *pem.offset(pem_count as isize) }) as i32
            && '\r' as i32 != (unsafe { *pem.offset(pem_count as isize) }) as i32
        {
            let fresh56 = stripped_pem_count;
            stripped_pem_count = stripped_pem_count.wrapping_add(1);
            (unsafe { *stripped_pem.offset(fresh56 as isize) = *pem.offset(pem_count as isize) });
        }
        pem_count = pem_count.wrapping_add(1);
    }
    (unsafe { *stripped_pem.offset(stripped_pem_count as isize) = '\u{0}' as i32 as i8 });
    result = unsafe { Curl_base64_decode(stripped_pem, der, der_len) };
    (unsafe { Curl_cfree.expect("non-null function pointer")(stripped_pem as *mut libc::c_void) });
    stripped_pem = 0 as *mut i8;
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_pin_peer_pubkey(
    mut data: *mut Curl_easy,
    mut pinnedpubkey: *const i8,
    mut pubkey: *const u8,
    mut pubkeylen: size_t,
) -> CURLcode {
    let mut fp: *mut FILE = 0 as *mut FILE;
    let mut buf: *mut u8 = 0 as *mut u8;
    let mut pem_ptr: *mut u8 = 0 as *mut u8;
    let mut result: CURLcode = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    if pinnedpubkey.is_null() {
        return CURLE_OK;
    }
    if pubkey.is_null() || pubkeylen == 0 {
        return result;
    }
    if (unsafe { strncmp(
        pinnedpubkey,
        b"sha256//\0" as *const u8 as *const i8,
        8 as i32 as u64,
    ) }) == 0 as i32
    {
        let mut encode: CURLcode = CURLE_OK;
        let mut encodedlen: size_t = 0;
        let mut pinkeylen: size_t = 0;
        let mut encoded: *mut i8 = 0 as *mut i8;
        let mut pinkeycopy: *mut i8 = 0 as *mut i8;
        let mut begin_pos: *mut i8 = 0 as *mut i8;
        let mut end_pos: *mut i8 = 0 as *mut i8;
        let mut sha256sumdigest: *mut u8 = 0 as *mut u8;
        if unsafe { ((*Curl_ssl).sha256sum).is_none() } {
            return result;
        }
        sha256sumdigest =
            (unsafe { Curl_cmalloc.expect("non-null function pointer")(32 as i32 as size_t) }) as *mut u8;
        if sha256sumdigest.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        encode = unsafe { ((*Curl_ssl).sha256sum).expect("non-null function pointer")(
            pubkey,
            pubkeylen,
            sha256sumdigest,
            32 as i32 as size_t,
        ) };
        if encode as u32 != CURLE_OK as i32 as u32 {
            return encode;
        }
        encode = unsafe { Curl_base64_encode(
            data,
            sha256sumdigest as *mut i8,
            32 as i32 as size_t,
            &mut encoded,
            &mut encodedlen,
        ) };
        (unsafe { Curl_cfree.expect("non-null function pointer")(sha256sumdigest as *mut libc::c_void) });
        sha256sumdigest = 0 as *mut u8;
        if encode as u64 != 0 {
            return encode;
        }
        (unsafe { Curl_infof(
            data,
            b" public key hash: sha256//%s\0" as *const u8 as *const i8,
            encoded,
        ) });
        pinkeylen = (unsafe { strlen(pinnedpubkey) }).wrapping_add(1 as i32 as u64);
        pinkeycopy = (unsafe { Curl_cmalloc.expect("non-null function pointer")(pinkeylen) }) as *mut i8;
        if pinkeycopy.is_null() {
            (unsafe { Curl_cfree.expect("non-null function pointer")(encoded as *mut libc::c_void) });
            encoded = 0 as *mut i8;
            return CURLE_OUT_OF_MEMORY;
        }
        (unsafe { memcpy(
            pinkeycopy as *mut libc::c_void,
            pinnedpubkey as *const libc::c_void,
            pinkeylen,
        ) });
        begin_pos = pinkeycopy;
        loop {
            end_pos = unsafe { strstr(begin_pos, b";sha256//\0" as *const u8 as *const i8) };
            if !end_pos.is_null() {
                (unsafe { *end_pos.offset(0 as i32 as isize) = '\u{0}' as i32 as i8 });
            }
            if encodedlen == (unsafe { strlen(begin_pos.offset(8 as i32 as isize)) })
                && (unsafe { memcmp(
                    encoded as *const libc::c_void,
                    begin_pos.offset(8 as i32 as isize) as *const libc::c_void,
                    encodedlen,
                ) }) == 0
            {
                result = CURLE_OK;
                break;
            } else {
                if !end_pos.is_null() {
                    (unsafe { *end_pos.offset(0 as i32 as isize) = ';' as i32 as i8 });
                    begin_pos = unsafe { strstr(end_pos, b"sha256//\0" as *const u8 as *const i8) };
                }
                if !(!end_pos.is_null() && !begin_pos.is_null()) {
                    break;
                }
            }
        }
        (unsafe { Curl_cfree.expect("non-null function pointer")(encoded as *mut libc::c_void) });
        encoded = 0 as *mut i8;
        (unsafe { Curl_cfree.expect("non-null function pointer")(pinkeycopy as *mut libc::c_void) });
        pinkeycopy = 0 as *mut i8;
        return result;
    }
    fp = unsafe { fopen(pinnedpubkey, b"rb\0" as *const u8 as *const i8) };
    if fp.is_null() {
        return result;
    }
    let mut filesize: i64 = 0;
    let mut size: size_t = 0;
    let mut pem_len: size_t = 0;
    let mut pem_read: CURLcode = CURLE_OK;
    if !((unsafe { fseek(fp, 0 as i32 as i64, 2 as i32) }) != 0) {
        filesize = unsafe { ftell(fp) };
        if !((unsafe { fseek(fp, 0 as i32 as i64, 0 as i32) }) != 0) {
            if !(filesize < 0 as i32 as i64 || filesize > 1048576 as i32 as i64) {
                size = unsafe { curlx_sotouz(filesize) };
                if !(pubkeylen > size) {
                    buf = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
                        size.wrapping_add(1 as i32 as u64),
                    ) }) as *mut u8;
                    if !buf.is_null() {
                        if !((unsafe { fread(buf as *mut libc::c_void, size, 1 as i32 as u64, fp) }) as i32
                            != 1 as i32)
                        {
                            if pubkeylen == size {
                                if (unsafe { memcmp(
                                    pubkey as *const libc::c_void,
                                    buf as *const libc::c_void,
                                    pubkeylen,
                                ) }) == 0
                                {
                                    result = CURLE_OK;
                                }
                            } else {
                                (unsafe { *buf.offset(size as isize) = '\u{0}' as i32 as u8 });
                                pem_read =
                                    pubkey_pem_to_der(buf as *const i8, &mut pem_ptr, &mut pem_len);
                                if !(pem_read as u64 != 0) {
                                    if pubkeylen == pem_len
                                        && (unsafe { memcmp(
                                            pubkey as *const libc::c_void,
                                            pem_ptr as *const libc::c_void,
                                            pubkeylen,
                                        ) }) == 0
                                    {
                                        result = CURLE_OK;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    buf = 0 as *mut u8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(pem_ptr as *mut libc::c_void) });
    pem_ptr = 0 as *mut u8;
    (unsafe { fclose(fp) });
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_ssl_cert_status_request() -> bool {
    return unsafe { ((*Curl_ssl).cert_status_request).expect("non-null function pointer")() };
}
#[no_mangle]
pub extern "C" fn Curl_ssl_false_start() -> bool {
    return unsafe { ((*Curl_ssl).false_start).expect("non-null function pointer")() };
}
#[no_mangle]
pub extern "C" fn Curl_ssl_tls13_ciphersuites() -> bool {
    return (unsafe { (*Curl_ssl).supports }) & ((1 as i32) << 5 as i32) as u32 != 0;
}
#[no_mangle]
pub extern "C" fn Curl_none_init() -> i32 {
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn Curl_none_cleanup() {}
#[no_mangle]
pub extern "C" fn Curl_none_shutdown(
    mut _data: *mut Curl_easy,
    mut _conn: *mut connectdata,
    mut _sockindex: i32,
) -> i32 {
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn Curl_none_check_cxn(mut _conn: *mut connectdata) -> i32 {
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn Curl_none_random(
    mut _data: *mut Curl_easy,
    mut _entropy: *mut u8,
    mut _length: size_t,
) -> CURLcode {
    return CURLE_NOT_BUILT_IN;
}
#[no_mangle]
pub extern "C" fn Curl_none_close_all(mut _data: *mut Curl_easy) {}
#[no_mangle]
pub extern "C" fn Curl_none_session_free(mut _ptr: *mut libc::c_void) {}
#[no_mangle]
pub extern "C" fn Curl_none_data_pending(mut _conn: *const connectdata, mut _connindex: i32) -> bool {
    return 0 as i32 != 0;
}
#[no_mangle]
pub extern "C" fn Curl_none_cert_status_request() -> bool {
    return 0 as i32 != 0;
}
#[no_mangle]
pub extern "C" fn Curl_none_set_engine(
    mut _data: *mut Curl_easy,
    mut _engine: *const i8,
) -> CURLcode {
    return CURLE_NOT_BUILT_IN;
}
#[no_mangle]
pub extern "C" fn Curl_none_set_engine_default(mut _data: *mut Curl_easy) -> CURLcode {
    return CURLE_NOT_BUILT_IN;
}
#[no_mangle]
pub extern "C" fn Curl_none_engines_list(mut _data: *mut Curl_easy) -> *mut curl_slist {
    return 0 as *mut libc::c_void as *mut curl_slist;
}
#[no_mangle]
pub extern "C" fn Curl_none_false_start() -> bool {
    return 0 as i32 != 0;
}
extern "C" fn multissl_init() -> i32 {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return 1 as i32;
    }
    return unsafe { ((*Curl_ssl).init).expect("non-null function pointer")() };
}
extern "C" fn multissl_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return CURLE_FAILED_INIT;
    }
    return unsafe { ((*Curl_ssl).connect_blocking).expect("non-null function pointer")(
        data, conn, sockindex,
    ) };
}
extern "C" fn multissl_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
    mut done: *mut bool,
) -> CURLcode {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return CURLE_FAILED_INIT;
    }
    return unsafe { ((*Curl_ssl).connect_nonblocking).expect("non-null function pointer")(
        data, conn, sockindex, done,
    ) };
}
extern "C" fn multissl_getsock(mut conn: *mut connectdata, mut socks: *mut curl_socket_t) -> i32 {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return 0 as i32;
    }
    return unsafe { ((*Curl_ssl).getsock).expect("non-null function pointer")(conn, socks) };
}
extern "C" fn multissl_get_internals(
    mut connssl: *mut ssl_connect_data,
    mut info: CURLINFO,
) -> *mut libc::c_void {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return 0 as *mut libc::c_void;
    }
    return unsafe { ((*Curl_ssl).get_internals).expect("non-null function pointer")(connssl, info) };
}
extern "C" fn multissl_close(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) {
    if multissl_setup(0 as *const Curl_ssl) != 0 {
        return;
    }
    (unsafe { ((*Curl_ssl).close_one).expect("non-null function pointer")(data, conn, sockindex) });
}
static mut Curl_ssl_multi: Curl_ssl =  {
    {
        let mut init = Curl_ssl {
            info: {
                let mut init = curl_ssl_backend {
                    id: CURLSSLBACKEND_NONE,
                    name: b"multi\0" as *const u8 as *const i8,
                };
                init
            },
            supports: 0 as i32 as u32,
            sizeof_ssl_backend_data: -(1 as i32) as size_t,
            init: Some(multissl_init as unsafe extern "C" fn() -> i32),
            cleanup: Some(Curl_none_cleanup as unsafe extern "C" fn() -> ()),
            version: Some(multissl_version as unsafe extern "C" fn(*mut i8, size_t) -> size_t),
            check_cxn: Some(Curl_none_check_cxn as unsafe extern "C" fn(*mut connectdata) -> i32),
            shut_down: Some(
                Curl_none_shutdown
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> i32,
            ),
            data_pending: Some(
                Curl_none_data_pending as unsafe extern "C" fn(*const connectdata, i32) -> bool,
            ),
            random: Some(
                Curl_none_random
                    as unsafe extern "C" fn(*mut Curl_easy, *mut u8, size_t) -> CURLcode,
            ),
            cert_status_request: Some(
                Curl_none_cert_status_request as unsafe extern "C" fn() -> bool,
            ),
            connect_blocking: Some(
                multissl_connect
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> CURLcode,
            ),
            connect_nonblocking: Some(
                multissl_connect_nonblocking
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        i32,
                        *mut bool,
                    ) -> CURLcode,
            ),
            getsock: Some(
                multissl_getsock
                    as unsafe extern "C" fn(*mut connectdata, *mut curl_socket_t) -> i32,
            ),
            get_internals: Some(
                multissl_get_internals
                    as unsafe extern "C" fn(*mut ssl_connect_data, CURLINFO) -> *mut libc::c_void,
            ),
            close_one: Some(
                multissl_close as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> (),
            ),
            close_all: Some(Curl_none_close_all as unsafe extern "C" fn(*mut Curl_easy) -> ()),
            session_free: Some(
                Curl_none_session_free as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ),
            set_engine: Some(
                Curl_none_set_engine as unsafe extern "C" fn(*mut Curl_easy, *const i8) -> CURLcode,
            ),
            set_engine_default: Some(
                Curl_none_set_engine_default as unsafe extern "C" fn(*mut Curl_easy) -> CURLcode,
            ),
            engines_list: Some(
                Curl_none_engines_list as unsafe extern "C" fn(*mut Curl_easy) -> *mut curl_slist,
            ),
            false_start: Some(Curl_none_false_start as unsafe extern "C" fn() -> bool),
            sha256sum: None,
            associate_connection: None,
            disassociate_connection: None,
        };
        init
    }
};
#[no_mangle]
pub static mut Curl_ssl: *const Curl_ssl = unsafe { &Curl_ssl_openssl as *const Curl_ssl };
static mut available_backends: [*const Curl_ssl; 2] =
    unsafe { [&Curl_ssl_openssl as *const Curl_ssl, 0 as *const Curl_ssl] };
extern "C" fn multissl_version(mut buffer: *mut i8, mut size: size_t) -> size_t {
    static mut selected: *const Curl_ssl = 0 as *const Curl_ssl;
    static mut backends: [i8; 200] = [0; 200];
    static mut backends_len: size_t = 0;
    let mut current: *const Curl_ssl = 0 as *const Curl_ssl;
    current = if (unsafe { Curl_ssl }) == (unsafe { &Curl_ssl_multi }) as *const Curl_ssl {
        unsafe { available_backends[0 as i32 as usize] }
    } else {
        unsafe { Curl_ssl }
    };
    if current != (unsafe { selected }) {
        let mut p: *mut i8 = unsafe { backends.as_mut_ptr() };
        let mut end: *mut i8 = unsafe { backends
            .as_mut_ptr()
            .offset(::std::mem::size_of::<[i8; 200]>() as u64 as isize) };
        let mut i: i32 = 0;
        (unsafe { selected = current });
        (unsafe { backends[0 as i32 as usize] = '\u{0}' as i32 as i8 });
        i = 0 as i32;
        while !(unsafe { available_backends[i as usize] }).is_null() {
            let mut vb: [i8; 200] = [0; 200];
            let mut paren: bool = (unsafe { selected }) != (unsafe { available_backends[i as usize] });
            if (unsafe { ((*available_backends[i as usize]).version).expect("non-null function pointer")(
                vb.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 200]>() as u64,
            ) }) != 0
            {
                p = unsafe { p.offset(curl_msnprintf(
                    p,
                    end.offset_from(p) as i64 as size_t,
                    b"%s%s%s%s\0" as *const u8 as *const i8,
                    if p != backends.as_mut_ptr() {
                        b" \0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    if paren as i32 != 0 {
                        b"(\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    vb.as_mut_ptr(),
                    if paren as i32 != 0 {
                        b")\0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                ) as isize) };
            }
            i += 1;
        }
        (unsafe { backends_len = p.offset_from(backends.as_mut_ptr()) as i64 as size_t });
    }
    if size == 0 {
        return 0 as i32 as size_t;
    }
    if size <= (unsafe { backends_len }) {
        (unsafe { strncpy(
            buffer,
            backends.as_mut_ptr(),
            size.wrapping_sub(1 as i32 as u64),
        ) });
        (unsafe { *buffer.offset(size.wrapping_sub(1 as i32 as u64) as isize) = '\u{0}' as i32 as i8 });
        return size.wrapping_sub(1 as i32 as u64);
    }
    (unsafe { strcpy(buffer, backends.as_mut_ptr()) });
    return unsafe { backends_len };
}
extern "C" fn multissl_setup(mut backend: *const Curl_ssl) -> i32 {
    let mut env: *const i8 = 0 as *const i8;
    let mut env_tmp: *mut i8 = 0 as *mut i8;
    if (unsafe { Curl_ssl }) != (unsafe { &Curl_ssl_multi }) as *const Curl_ssl {
        return 1 as i32;
    }
    if !backend.is_null() {
        (unsafe { Curl_ssl = backend });
        return 0 as i32;
    }
    if (unsafe { available_backends[0 as i32 as usize] }).is_null() {
        return 1 as i32;
    }
    env_tmp = unsafe { curl_getenv(b"CURL_SSL_BACKEND\0" as *const u8 as *const i8) };
    env = env_tmp;
    if !env.is_null() {
        let mut i: i32 = 0;
        i = 0 as i32;
        while !(unsafe { available_backends[i as usize] }).is_null() {
            if (unsafe { Curl_strcasecompare(env, (*available_backends[i as usize]).info.name) }) != 0 {
                (unsafe { Curl_ssl = available_backends[i as usize] });
                (unsafe { Curl_cfree.expect("non-null function pointer")(env_tmp as *mut libc::c_void) });
                return 0 as i32;
            }
            i += 1;
        }
    }
    (unsafe { Curl_ssl = available_backends[0 as i32 as usize] });
    (unsafe { Curl_cfree.expect("non-null function pointer")(env_tmp as *mut libc::c_void) });
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn curl_global_sslset(
    mut id: curl_sslbackend,
    mut name: *const i8,
    mut avail: *mut *mut *const curl_ssl_backend,
) -> CURLsslset {
    let mut i: i32 = 0;
    if !avail.is_null() {
        (unsafe { *avail =
            &mut available_backends as *mut [*const Curl_ssl; 2] as *mut *const curl_ssl_backend });
    }
    if (unsafe { Curl_ssl }) != (unsafe { &Curl_ssl_multi }) as *const Curl_ssl {
        return (if id as u32 == (unsafe { (*Curl_ssl).info.id }) as u32
            || !name.is_null() && (unsafe { Curl_strcasecompare(name, (*Curl_ssl).info.name) }) != 0
        {
            CURLSSLSET_OK as i32
        } else {
            CURLSSLSET_UNKNOWN_BACKEND as i32
        }) as CURLsslset;
    }
    i = 0 as i32;
    while !(unsafe { available_backends[i as usize] }).is_null() {
        if (unsafe { (*available_backends[i as usize]).info.id }) as u32 == id as u32
            || !name.is_null()
                && (unsafe { Curl_strcasecompare((*available_backends[i as usize]).info.name, name) }) != 0
        {
            multissl_setup(unsafe { available_backends[i as usize] });
            return CURLSSLSET_OK;
        }
        i += 1;
    }
    return CURLSSLSET_UNKNOWN_BACKEND;
}