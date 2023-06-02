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
    pub type ldapconninfo;
    pub type tftp_state_data;
    pub type nghttp2_session;
    pub type Gsasl_session;
    pub type Gsasl;
    pub type ssl_backend_data;
    fn curl_strnequal(s1: *const i8, s2: *const i8, n: size_t) -> i32;
    fn curl_mime_headers(
        part: *mut curl_mimepart,
        headers: *mut curl_slist,
        take_ownership: i32,
    ) -> CURLcode;
    fn sscanf(_: *const i8, _: *const i8, _: ...) -> i32;
    fn time(__timer: *mut time_t) -> time_t;
    fn Curl_isdigit(c: i32) -> i32;
    fn Curl_isspace(c: i32) -> i32;
    fn curl_url_cleanup(handle: *mut CURLU);
    fn curl_url_dup(in_0: *mut CURLU) -> *mut CURLU;
    fn curl_url_get(
        handle: *mut CURLU,
        what: CURLUPart,
        part: *mut *mut i8,
        flags: u32,
    ) -> CURLUcode;
    fn curl_url_set(handle: *mut CURLU, what: CURLUPart, part: *const i8, flags: u32) -> CURLUcode;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memchr(_: *const libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strstr(_: *const i8, _: *const i8) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn Curl_dyn_init(s: *mut dynbuf, toobig: size_t);
    fn Curl_dyn_free(s: *mut dynbuf);
    fn Curl_dyn_addn(s: *mut dynbuf, mem: *const libc::c_void, len: size_t) -> CURLcode;
    fn Curl_dyn_add(s: *mut dynbuf, str: *const i8) -> CURLcode;
    fn Curl_dyn_addf(s: *mut dynbuf, fmt: *const i8, _: ...) -> CURLcode;
    fn Curl_dyn_reset(s: *mut dynbuf);
    fn Curl_dyn_ptr(s: *const dynbuf) -> *mut i8;
    fn Curl_dyn_len(s: *const dynbuf) -> size_t;
    fn Curl_mime_initpart(part: *mut curl_mimepart, easy: *mut Curl_easy);
    fn Curl_mime_cleanpart(part: *mut curl_mimepart);
    fn Curl_mime_prepare_headers(
        part: *mut curl_mimepart,
        contenttype: *const i8,
        disposition: *const i8,
        strategy: mimestrategy,
    ) -> CURLcode;
    fn Curl_mime_size(part: *mut curl_mimepart) -> curl_off_t;
    fn Curl_mime_read(
        buffer: *mut i8,
        size: size_t,
        nitems: size_t,
        instream: *mut libc::c_void,
    ) -> size_t;
    fn Curl_mime_rewind(part: *mut curl_mimepart) -> CURLcode;
    fn Curl_getformdata(
        data: *mut Curl_easy,
        _: *mut curl_mimepart,
        post: *mut curl_httppost,
        fread_func: curl_read_callback,
    ) -> CURLcode;
    fn Curl_cookie_freelist(cookies: *mut Cookie);
    fn Curl_cookie_getlist(
        c: *mut CookieInfo,
        host: *const i8,
        path: *const i8,
        secure: bool,
    ) -> *mut Cookie;
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
    fn Curl_rtsp_parseheader(data: *mut Curl_easy, header: *mut i8) -> CURLcode;
    fn Curl_checkheaders(data: *const Curl_easy, thisheader: *const i8) -> *mut i8;
    fn Curl_readrewind(data: *mut Curl_easy) -> CURLcode;
    fn Curl_meets_timecondition(data: *mut Curl_easy, timeofdoc: time_t) -> bool;
    fn Curl_get_upload_buffer(data: *mut Curl_easy) -> CURLcode;
    fn Curl_done_sending(data: *mut Curl_easy, k: *mut SingleRequest) -> CURLcode;
    fn Curl_setup_transfer(
        data: *mut Curl_easy,
        sockindex: i32,
        size: curl_off_t,
        getheader: bool,
        writesockindex: i32,
    );
    fn Curl_infof(_: *mut Curl_easy, fmt: *const i8, _: ...);
    fn Curl_failf(_: *mut Curl_easy, fmt: *const i8, _: ...);
    fn Curl_client_write(data: *mut Curl_easy, type_0: i32, ptr: *mut i8, len: size_t) -> CURLcode;
    fn Curl_write(
        data: *mut Curl_easy,
        sockfd: curl_socket_t,
        mem: *const libc::c_void,
        len: size_t,
        written: *mut ssize_t,
    ) -> CURLcode;
    fn Curl_debug(data: *mut Curl_easy, type_0: curl_infotype, ptr: *mut i8, size: size_t) -> i32;
    fn Curl_pgrsSetDownloadSize(data: *mut Curl_easy, size: curl_off_t);
    fn Curl_pgrsSetUploadSize(data: *mut Curl_easy, size: curl_off_t);
    fn Curl_pgrsSetUploadCounter(data: *mut Curl_easy, size: curl_off_t);
    fn Curl_pgrsUpdate(data: *mut Curl_easy) -> i32;
    fn Curl_base64_encode(
        data: *mut Curl_easy,
        inputbuff: *const i8,
        insize: size_t,
        outptr: *mut *mut i8,
        outlen: *mut size_t,
    ) -> CURLcode;
    fn Curl_auth_is_digest_supported() -> bool;
    fn Curl_auth_is_ntlm_supported() -> bool;
    static mut Curl_ssl: *const Curl_ssl;
    fn Curl_ssl_connect_nonblocking(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        isproxy: bool,
        sockindex: i32,
        done: *mut bool,
    ) -> CURLcode;
    fn Curl_input_digest(data: *mut Curl_easy, proxy: bool, header: *const i8) -> CURLcode;
    fn Curl_output_digest(
        data: *mut Curl_easy,
        proxy: bool,
        request: *const u8,
        uripath: *const u8,
    ) -> CURLcode;
    fn Curl_input_ntlm(data: *mut Curl_easy, proxy: bool, header: *const i8) -> CURLcode;
    fn Curl_output_ntlm(data: *mut Curl_easy, proxy: bool) -> CURLcode;
    fn Curl_input_ntlm_wb(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        proxy: bool,
        header: *const i8,
    ) -> CURLcode;
    fn Curl_output_ntlm_wb(data: *mut Curl_easy, conn: *mut connectdata, proxy: bool) -> CURLcode;
    fn Curl_output_aws_sigv4(data: *mut Curl_easy, proxy: bool) -> CURLcode;
    fn Curl_share_lock(_: *mut Curl_easy, _: curl_lock_data, _: curl_lock_access) -> CURLSHcode;
    fn Curl_share_unlock(_: *mut Curl_easy, _: curl_lock_data) -> CURLSHcode;
    static Curl_wkday: [*const i8; 7];
    static Curl_month: [*const i8; 12];
    fn Curl_gmtime(intime: time_t, store: *mut tm) -> CURLcode;
    fn Curl_getdate_capped(p: *const i8) -> time_t;
    fn curlx_strtoofft(
        str: *const i8,
        endp: *mut *mut i8,
        base: i32,
        num: *mut curl_off_t,
    ) -> CURLofft;
    fn Curl_expire_done(data: *mut Curl_easy, id: expire_id);
    fn Curl_set_in_callback(data: *mut Curl_easy, value: bool);
    fn Curl_strcasecompare(first: *const i8, second: *const i8) -> i32;
    fn Curl_strncasecompare(first: *const i8, second: *const i8, max: size_t) -> i32;
    fn Curl_raw_toupper(in_0: i8) -> i8;
    fn Curl_build_unencoding_stack(
        data: *mut Curl_easy,
        enclist: *const i8,
        maybechunked: i32,
    ) -> CURLcode;
    fn Curl_unencode_cleanup(data: *mut Curl_easy);
    fn Curl_proxy_connect(data: *mut Curl_easy, sockindex: i32) -> CURLcode;
    fn Curl_connect_ongoing(conn: *mut connectdata) -> bool;
    fn curlx_sotouz(sonum: curl_off_t) -> size_t;
    fn curlx_uitous(uinum: u32) -> u16;
    fn Curl_http2_request_upgrade(req: *mut dynbuf, data: *mut Curl_easy) -> CURLcode;
    fn Curl_http2_setup(data: *mut Curl_easy, conn: *mut connectdata) -> CURLcode;
    fn Curl_http2_switched(data: *mut Curl_easy, ptr: *const i8, nread: size_t) -> CURLcode;
    fn Curl_http2_setup_conn(conn: *mut connectdata);
    fn Curl_http2_setup_req(data: *mut Curl_easy);
    fn Curl_http2_done(data: *mut Curl_easy, premature: bool);
    fn Curl_conncontrol(conn: *mut connectdata, closeit: i32);
    fn Curl_altsvc_parse(
        data: *mut Curl_easy,
        altsvc: *mut altsvcinfo,
        value: *const i8,
        srcalpn: alpnid,
        srchost: *const i8,
        srcport: u16,
    ) -> CURLcode;
    fn Curl_hsts_parse(h: *mut hsts, hostname: *const i8, sts: *const i8) -> CURLcode;
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
pub struct tm {
    pub tm_sec: i32,
    pub tm_min: i32,
    pub tm_hour: i32,
    pub tm_mday: i32,
    pub tm_mon: i32,
    pub tm_year: i32,
    pub tm_wday: i32,
    pub tm_yday: i32,
    pub tm_isdst: i32,
    pub tm_gmtoff: i64,
    pub tm_zone: *const i8,
}
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
    pub transport: C2RustUnnamed_6,
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
    pub proto: C2RustUnnamed_5,
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
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct http_connect_state {
    pub http_proxy: HTTP,
    pub prot_save: *mut HTTP,
    pub rcvbuf: dynbuf,
    pub req: dynbuf,
    pub nsend: size_t,
    pub keepon: keeponval,
    pub cl: curl_off_t,
    pub tunnel_state: C2RustUnnamed_4,
    #[bitfield(name = "chunked_encoding", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "close_connection", ty = "bit", bits = "1..=1")]
    pub chunked_encoding_close_connection: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
pub type C2RustUnnamed_4 = u32;
pub const TUNNEL_EXIT: C2RustUnnamed_4 = 3;
pub const TUNNEL_COMPLETE: C2RustUnnamed_4 = 2;
pub const TUNNEL_CONNECT: C2RustUnnamed_4 = 1;
pub const TUNNEL_INIT: C2RustUnnamed_4 = 0;
pub type keeponval = u32;
pub const KEEPON_IGNORE: keeponval = 2;
pub const KEEPON_CONNECT: keeponval = 1;
pub const KEEPON_DONE: keeponval = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_5 {
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
pub type C2RustUnnamed_6 = u32;
pub const TRNSPRT_QUIC: C2RustUnnamed_6 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_6 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_6 = 3;
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
pub type C2RustUnnamed_7 = u32;
pub const CURL_HTTP_VERSION_LAST: C2RustUnnamed_7 = 31;
pub const CURL_HTTP_VERSION_3: C2RustUnnamed_7 = 30;
pub const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: C2RustUnnamed_7 = 5;
pub const CURL_HTTP_VERSION_2TLS: C2RustUnnamed_7 = 4;
pub const CURL_HTTP_VERSION_2_0: C2RustUnnamed_7 = 3;
pub const CURL_HTTP_VERSION_1_1: C2RustUnnamed_7 = 2;
pub const CURL_HTTP_VERSION_1_0: C2RustUnnamed_7 = 1;
pub const CURL_HTTP_VERSION_NONE: C2RustUnnamed_7 = 0;
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
pub static mut Curl_handler_http: Curl_handler =  {
    {
        let mut init = Curl_handler {
            scheme: b"HTTP\0" as *const u8 as *const i8,
            setup_connection: Some(
                http_setup_conn
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
            ),
            do_it: Some(Curl_http as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode),
            done: Some(
                Curl_http_done as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
            ),
            do_more: None,
            connect_it: Some(
                Curl_http_connect as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            connecting: None,
            doing: None,
            proto_getsock: None,
            doing_getsock: Some(
                http_getsock_do
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
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
            flags: ((1 as i32) << 7 as i32 | (1 as i32) << 13 as i32) as u32,
        };
        init
    }
};
#[no_mangle]
pub static mut Curl_handler_https: Curl_handler =  {
    {
        let mut init = Curl_handler {
            scheme: b"HTTPS\0" as *const u8 as *const i8,
            setup_connection: Some(
                http_setup_conn
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
            ),
            do_it: Some(Curl_http as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode),
            done: Some(
                Curl_http_done as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
            ),
            do_more: None,
            connect_it: Some(
                Curl_http_connect as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            connecting: Some(
                https_connecting as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            doing: None,
            proto_getsock: Some(
                https_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
            ),
            doing_getsock: Some(
                http_getsock_do
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> i32,
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
extern "C" fn http_setup_conn(mut data: *mut Curl_easy, mut conn: *mut connectdata) -> CURLcode {
    let mut http: *mut HTTP = 0 as *mut HTTP;
    http = (unsafe { Curl_ccalloc.expect("non-null function pointer")(
        1 as i32 as size_t,
        ::std::mem::size_of::<HTTP>() as u64,
    ) }) as *mut HTTP;
    if http.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    (unsafe { Curl_mime_initpart(&mut (*http).form, data) });
    let fresh0 = unsafe { &mut ((*data).req.p.http) };
    *fresh0 = http;
    if (unsafe { (*data).state.httpwant }) as i32 == CURL_HTTP_VERSION_3 as i32 {
        if (unsafe { (*(*conn).handler).flags }) & ((1 as i32) << 0 as i32) as u32 != 0 {
            (unsafe { (*conn).transport = TRNSPRT_QUIC });
        } else {
            (unsafe { Curl_failf(
                data,
                b"HTTP/3 requested for non-HTTPS URL\0" as *const u8 as *const i8,
            ) });
            return CURLE_URL_MALFORMAT;
        }
    } else {
        if (unsafe { (*conn).easyq.size }) == 0 {
            (unsafe { Curl_http2_setup_conn(conn) });
        }
        (unsafe { Curl_http2_setup_req(data) });
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_checkProxyheaders(
    mut data: *mut Curl_easy,
    mut conn: *const connectdata,
    mut thisheader: *const i8,
) -> *mut i8 {
    let mut head: *mut curl_slist = 0 as *mut curl_slist;
    let mut thislen: size_t = unsafe { strlen(thisheader) };
    head = if (unsafe { ((*conn).bits).proxy() }) as i32 != 0 && (unsafe { ((*data).set).sep_headers() }) as i32 != 0 {
        unsafe { (*data).set.proxyheaders }
    } else {
        unsafe { (*data).set.headers }
    };
    while !head.is_null() {
        if (unsafe { Curl_strncasecompare((*head).data, thisheader, thislen) }) != 0
            && ((unsafe { *((*head).data).offset(thislen as isize) }) as i32 == ':' as i32
                || (unsafe { *((*head).data).offset(thislen as isize) }) as i32 == ';' as i32)
        {
            return unsafe { (*head).data };
        }
        head = unsafe { (*head).next };
    }
    return 0 as *mut i8;
}
#[no_mangle]
pub extern "C" fn Curl_copy_header_value(mut header: *const i8) -> *mut i8 {
    let mut start: *const i8 = 0 as *const i8;
    let mut end: *const i8 = 0 as *const i8;
    let mut value: *mut i8 = 0 as *mut i8;
    let mut len: size_t = 0;
    while (unsafe { *header }) as i32 != 0 && (unsafe { *header }) as i32 != ':' as i32 {
        header = unsafe { header.offset(1) };
    }
    if (unsafe { *header }) != 0 {
        header = unsafe { header.offset(1) };
    }
    start = header;
    while (unsafe { *start }) as i32 != 0 && (unsafe { Curl_isspace(*start as u8 as i32) }) != 0 {
        start = unsafe { start.offset(1) };
    }
    end = unsafe { strchr(start, '\r' as i32) };
    if end.is_null() {
        end = unsafe { strchr(start, '\n' as i32) };
    }
    if end.is_null() {
        end = unsafe { strchr(start, '\u{0}' as i32) };
    }
    if end.is_null() {
        return 0 as *mut i8;
    }
    while end > start && (unsafe { Curl_isspace(*end as u8 as i32) }) != 0 {
        end = unsafe { end.offset(-1) };
    }
    len = ((unsafe { end.offset_from(start) }) as i64 + 1 as i32 as i64) as size_t;
    value = (unsafe { Curl_cmalloc.expect("non-null function pointer")(len.wrapping_add(1 as i32 as u64)) })
        as *mut i8;
    if value.is_null() {
        return 0 as *mut i8;
    }
    (unsafe { memcpy(
        value as *mut libc::c_void,
        start as *const libc::c_void,
        len,
    ) });
    (unsafe { *value.offset(len as isize) = 0 as i32 as i8 });
    return value;
}
extern "C" fn http_output_basic(mut data: *mut Curl_easy, mut proxy: bool) -> CURLcode {
    let mut size: size_t = 0 as i32 as size_t;
    let mut authorization: *mut i8 = 0 as *mut i8;
    let mut userp: *mut *mut i8 = 0 as *mut *mut i8;
    let mut user: *const i8 = 0 as *const i8;
    let mut pwd: *const i8 = 0 as *const i8;
    let mut result: CURLcode = CURLE_OK;
    let mut out: *mut i8 = 0 as *mut i8;
    if proxy {
        userp = unsafe { &mut (*data).state.aptr.proxyuserpwd };
        user = unsafe { (*data).state.aptr.proxyuser };
        pwd = unsafe { (*data).state.aptr.proxypasswd };
    } else {
        userp = unsafe { &mut (*data).state.aptr.userpwd };
        user = unsafe { (*data).state.aptr.user };
        pwd = unsafe { (*data).state.aptr.passwd };
    }
    out = unsafe { curl_maprintf(
        b"%s:%s\0" as *const u8 as *const i8,
        user,
        if !pwd.is_null() {
            pwd
        } else {
            b"\0" as *const u8 as *const i8
        },
    ) };
    if out.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    result = unsafe { Curl_base64_encode(data, out, strlen(out), &mut authorization, &mut size) };
    if !(result as u64 != 0) {
        if authorization.is_null() {
            result = CURLE_REMOTE_ACCESS_DENIED;
        } else {
            (unsafe { Curl_cfree.expect("non-null function pointer")(*userp as *mut libc::c_void) });
            (unsafe { *userp = curl_maprintf(
                b"%sAuthorization: Basic %s\r\n\0" as *const u8 as *const i8,
                if proxy as i32 != 0 {
                    b"Proxy-\0" as *const u8 as *const i8
                } else {
                    b"\0" as *const u8 as *const i8
                },
                authorization,
            ) });
            (unsafe { Curl_cfree.expect("non-null function pointer")(authorization as *mut libc::c_void) });
            if (unsafe { *userp }).is_null() {
                result = CURLE_OUT_OF_MEMORY;
            }
        }
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")(out as *mut libc::c_void) });
    return result;
}
extern "C" fn http_output_bearer(mut data: *mut Curl_easy) -> CURLcode {
    let mut userp: *mut *mut i8 = 0 as *mut *mut i8;
    let mut result: CURLcode = CURLE_OK;
    userp = unsafe { &mut (*data).state.aptr.userpwd };
    (unsafe { Curl_cfree.expect("non-null function pointer")(*userp as *mut libc::c_void) });
    (unsafe { *userp = curl_maprintf(
        b"Authorization: Bearer %s\r\n\0" as *const u8 as *const i8,
        (*data).set.str_0[STRING_BEARER as i32 as usize],
    ) });
    if (unsafe { *userp }).is_null() {
        result = CURLE_OUT_OF_MEMORY;
    }
    return result;
}
extern "C" fn pickoneauth(mut pick: *mut auth, mut mask: u64) -> bool {
    let mut picked: bool = false;
    let mut avail: u64 = (unsafe { (*pick).avail }) & (unsafe { (*pick).want }) & mask;
    picked = 1 as i32 != 0;
    if avail & (1 as i32 as u64) << 2 as i32 != 0 {
        (unsafe { (*pick).picked = (1 as i32 as u64) << 2 as i32 });
    } else if avail & (1 as i32 as u64) << 6 as i32 != 0 {
        (unsafe { (*pick).picked = (1 as i32 as u64) << 6 as i32 });
    } else if avail & (1 as i32 as u64) << 1 as i32 != 0 {
        (unsafe { (*pick).picked = (1 as i32 as u64) << 1 as i32 });
    } else if avail & (1 as i32 as u64) << 3 as i32 != 0 {
        (unsafe { (*pick).picked = (1 as i32 as u64) << 3 as i32 });
    } else if avail & (1 as i32 as u64) << 5 as i32 != 0 {
        (unsafe { (*pick).picked = (1 as i32 as u64) << 5 as i32 });
    } else if avail & (1 as i32 as u64) << 0 as i32 != 0 {
        (unsafe { (*pick).picked = (1 as i32 as u64) << 0 as i32 });
    } else if avail & (1 as i32 as u64) << 7 as i32 != 0 {
        (unsafe { (*pick).picked = (1 as i32 as u64) << 7 as i32 });
    } else {
        (unsafe { (*pick).picked = ((1 as i32) << 30 as i32) as u64 });
        picked = 0 as i32 != 0;
    }
    (unsafe { (*pick).avail = 0 as i32 as u64 });
    return picked;
}
extern "C" fn http_perhapsrewind(mut data: *mut Curl_easy, mut conn: *mut connectdata) -> CURLcode {
    let mut http: *mut HTTP = unsafe { (*data).req.p.http };
    let mut bytessent: curl_off_t = 0;
    let mut expectsend: curl_off_t = -(1 as i32) as curl_off_t;
    if http.is_null() {
        return CURLE_OK;
    }
    match (unsafe { (*data).state.httpreq }) as u32 {
        0 | 5 => return CURLE_OK,
        _ => {}
    }
    bytessent = unsafe { (*data).req.writebytecount };
    if (unsafe { ((*conn).bits).authneg() }) != 0 {
        expectsend = 0 as i32 as curl_off_t;
    } else if (unsafe { ((*conn).bits).protoconnstart() }) == 0 {
        expectsend = 0 as i32 as curl_off_t;
    } else {
        match (unsafe { (*data).state.httpreq }) as u32 {
            1 | 4 => {
                if (unsafe { (*data).state.infilesize }) != -(1 as i32) as i64 {
                    expectsend = unsafe { (*data).state.infilesize };
                }
            }
            2 | 3 => {
                expectsend = unsafe { (*http).postsize };
            }
            _ => {}
        }
    }
    let fresh1 = unsafe { &mut ((*conn).bits) };
    (*fresh1).set_rewindaftersend(0 as i32 as bit);
    if expectsend == -(1 as i32) as i64 || expectsend > bytessent {
        if (unsafe { (*data).state.authproxy.picked }) == (1 as i32 as u64) << 3 as i32
            || (unsafe { (*data).state.authhost.picked }) == (1 as i32 as u64) << 3 as i32
            || (unsafe { (*data).state.authproxy.picked }) == (1 as i32 as u64) << 5 as i32
            || (unsafe { (*data).state.authhost.picked }) == (1 as i32 as u64) << 5 as i32
        {
            if expectsend - bytessent < 2000 as i32 as i64
                || (unsafe { (*conn).http_ntlm_state }) as u32 != NTLMSTATE_NONE as i32 as u32
                || (unsafe { (*conn).proxy_ntlm_state }) as u32 != NTLMSTATE_NONE as i32 as u32
            {
                if (unsafe { ((*conn).bits).authneg() }) == 0 && (unsafe { (*conn).writesockfd }) != -(1 as i32) {
                    let fresh2 = unsafe { &mut ((*conn).bits) };
                    (*fresh2).set_rewindaftersend(1 as i32 as bit);
                    (unsafe { Curl_infof(
                        data,
                        b"Rewind stream after send\0" as *const u8 as *const i8,
                    ) });
                }
                return CURLE_OK;
            }
            if (unsafe { ((*conn).bits).close() }) != 0 {
                return CURLE_OK;
            }
            (unsafe { Curl_infof(
                data,
                b"NTLM send, close instead of sending %ld bytes\0" as *const u8 as *const i8,
                expectsend - bytessent,
            ) });
        }
        (unsafe { Curl_conncontrol(conn, 2 as i32) });
        (unsafe { (*data).req.size = 0 as i32 as curl_off_t });
    }
    if bytessent != 0 {
        return unsafe { Curl_readrewind(data) };
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_http_auth_act(mut data: *mut Curl_easy) -> CURLcode {
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    let mut pickhost: bool = 0 as i32 != 0;
    let mut pickproxy: bool = 0 as i32 != 0;
    let mut result: CURLcode = CURLE_OK;
    let mut authmask: u64 = !(0 as u64);
    if (unsafe { (*data).set.str_0[STRING_BEARER as i32 as usize] }).is_null() {
        authmask &= !((1 as i32 as u64) << 6 as i32);
    }
    if 100 as i32 <= (unsafe { (*data).req.httpcode }) && 199 as i32 >= (unsafe { (*data).req.httpcode }) {
        return CURLE_OK;
    }
    if (unsafe { ((*data).state).authproblem() }) != 0 {
        return (if (unsafe { ((*data).set).http_fail_on_error() }) as i32 != 0 {
            CURLE_HTTP_RETURNED_ERROR as i32
        } else {
            CURLE_OK as i32
        }) as CURLcode;
    }
    if ((unsafe { ((*conn).bits).user_passwd() }) as i32 != 0
        || !(unsafe { (*data).set.str_0[STRING_BEARER as i32 as usize] }).is_null())
        && ((unsafe { (*data).req.httpcode }) == 401 as i32
            || (unsafe { ((*conn).bits).authneg() }) as i32 != 0 && (unsafe { (*data).req.httpcode }) < 300 as i32)
    {
        pickhost = pickoneauth(unsafe { &mut (*data).state.authhost }, authmask);
        if !pickhost {
            let fresh3 = unsafe { &mut ((*data).state) };
            (*fresh3).set_authproblem(1 as i32 as bit);
        }
        if (unsafe { (*data).state.authhost.picked }) == (1 as i32 as u64) << 3 as i32
            && (unsafe { (*conn).httpversion }) as i32 > 11 as i32
        {
            (unsafe { Curl_infof(
                data,
                b"Forcing HTTP/1.1 for NTLM\0" as *const u8 as *const i8,
            ) });
            (unsafe { Curl_conncontrol(conn, 1 as i32) });
            (unsafe { (*data).state.httpwant = CURL_HTTP_VERSION_1_1 as i32 as u8 });
        }
    }
    if (unsafe { ((*conn).bits).proxy_user_passwd() }) as i32 != 0
        && ((unsafe { (*data).req.httpcode }) == 407 as i32
            || (unsafe { ((*conn).bits).authneg() }) as i32 != 0 && (unsafe { (*data).req.httpcode }) < 300 as i32)
    {
        pickproxy = pickoneauth(
            unsafe { &mut (*data).state.authproxy },
            authmask & !((1 as i32 as u64) << 6 as i32),
        );
        if !pickproxy {
            let fresh4 = unsafe { &mut ((*data).state) };
            (*fresh4).set_authproblem(1 as i32 as bit);
        }
    }
    if pickhost as i32 != 0 || pickproxy as i32 != 0 {
        if (unsafe { (*data).state.httpreq }) as u32 != HTTPREQ_GET as i32 as u32
            && (unsafe { (*data).state.httpreq }) as u32 != HTTPREQ_HEAD as i32 as u32
            && (unsafe { ((*conn).bits).rewindaftersend() }) == 0
        {
            result = http_perhapsrewind(data, conn);
            if result as u64 != 0 {
                return result;
            }
        }
        (unsafe { Curl_cfree.expect("non-null function pointer")((*data).req.newurl as *mut libc::c_void) });
        let fresh5 = unsafe { &mut ((*data).req.newurl) };
        *fresh5 = 0 as *mut i8;
        let fresh6 = unsafe { &mut ((*data).req.newurl) };
        *fresh6 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*data).state.url) };
        if (unsafe { (*data).req.newurl }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    } else if (unsafe { (*data).req.httpcode }) < 300 as i32
        && (unsafe { ((*data).state.authhost).done() }) == 0
        && (unsafe { ((*conn).bits).authneg() }) as i32 != 0
    {
        if (unsafe { (*data).state.httpreq }) as u32 != HTTPREQ_GET as i32 as u32
            && (unsafe { (*data).state.httpreq }) as u32 != HTTPREQ_HEAD as i32 as u32
        {
            let fresh7 = unsafe { &mut ((*data).req.newurl) };
            *fresh7 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*data).state.url) };
            if (unsafe { (*data).req.newurl }).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            let fresh8 = unsafe { &mut ((*data).state.authhost) };
            (*fresh8).set_done(1 as i32 as bit);
        }
    }
    if http_should_fail(data) {
        (unsafe { Curl_failf(
            data,
            b"The requested URL returned error: %d\0" as *const u8 as *const i8,
            (*data).req.httpcode,
        ) });
        result = CURLE_HTTP_RETURNED_ERROR;
    }
    return result;
}
extern "C" fn output_auth_headers(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut authstatus: *mut auth,
    mut request: *const i8,
    mut path: *const i8,
    mut proxy: bool,
) -> CURLcode {
    let mut auth: *const i8 = 0 as *const i8;
    let mut result: CURLcode = CURLE_OK;
    if (unsafe { (*authstatus).picked }) == (1 as i32 as u64) << 7 as i32 {
        auth = b"AWS_SIGV4\0" as *const u8 as *const i8;
        result = unsafe { Curl_output_aws_sigv4(data, proxy) };
        if result as u64 != 0 {
            return result;
        }
    } else if (unsafe { (*authstatus).picked }) == (1 as i32 as u64) << 3 as i32 {
        auth = b"NTLM\0" as *const u8 as *const i8;
        result = unsafe { Curl_output_ntlm(data, proxy) };
        if result as u64 != 0 {
            return result;
        }
    } else if (unsafe { (*authstatus).picked }) == (1 as i32 as u64) << 5 as i32 {
        auth = b"NTLM_WB\0" as *const u8 as *const i8;
        result = unsafe { Curl_output_ntlm_wb(data, conn, proxy) };
        if result as u64 != 0 {
            return result;
        }
    } else if (unsafe { (*authstatus).picked }) == (1 as i32 as u64) << 1 as i32 {
        auth = b"Digest\0" as *const u8 as *const i8;
        result = unsafe { Curl_output_digest(data, proxy, request as *const u8, path as *const u8) };
        if result as u64 != 0 {
            return result;
        }
    } else if (unsafe { (*authstatus).picked }) == (1 as i32 as u64) << 0 as i32 {
        if proxy as i32 != 0
            && (unsafe { ((*conn).bits).proxy_user_passwd() }) as i32 != 0
            && (Curl_checkProxyheaders(
                data,
                conn,
                b"Proxy-authorization\0" as *const u8 as *const i8,
            ))
            .is_null()
            || !proxy
                && (unsafe { ((*conn).bits).user_passwd() }) as i32 != 0
                && (unsafe { Curl_checkheaders(data, b"Authorization\0" as *const u8 as *const i8) }).is_null()
        {
            auth = b"Basic\0" as *const u8 as *const i8;
            result = http_output_basic(data, proxy);
            if result as u64 != 0 {
                return result;
            }
        }
        (unsafe { (*authstatus).set_done(1 as i32 as bit) });
    }
    if (unsafe { (*authstatus).picked }) == (1 as i32 as u64) << 6 as i32 {
        if !proxy
            && !(unsafe { (*data).set.str_0[STRING_BEARER as i32 as usize] }).is_null()
            && (unsafe { Curl_checkheaders(data, b"Authorization\0" as *const u8 as *const i8) }).is_null()
        {
            auth = b"Bearer\0" as *const u8 as *const i8;
            result = http_output_bearer(data);
            if result as u64 != 0 {
                return result;
            }
        }
        (unsafe { (*authstatus).set_done(1 as i32 as bit) });
    }
    if !auth.is_null() {
        (unsafe { Curl_infof(
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
        ) });
        (unsafe { (*authstatus).set_multipass(
            (if (*authstatus).done() == 0 {
                1 as i32
            } else {
                0 as i32
            }) as bit,
        ) });
    } else {
        (unsafe { (*authstatus).set_multipass(0 as i32 as bit) });
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_http_output_auth(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut request: *const i8,
    mut httpreq: Curl_HttpReq,
    mut path: *const i8,
    mut proxytunnel: bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut authhost: *mut auth = 0 as *mut auth;
    let mut authproxy: *mut auth = 0 as *mut auth;
    authhost = unsafe { &mut (*data).state.authhost };
    authproxy = unsafe { &mut (*data).state.authproxy };
    if (unsafe { ((*conn).bits).httpproxy() }) as i32 != 0 && (unsafe { ((*conn).bits).proxy_user_passwd() }) as i32 != 0
        || (unsafe { ((*conn).bits).user_passwd() }) as i32 != 0
        || !(unsafe { (*data).set.str_0[STRING_BEARER as i32 as usize] }).is_null()
    {
    } else {
        (unsafe { (*authhost).set_done(1 as i32 as bit) });
        (unsafe { (*authproxy).set_done(1 as i32 as bit) });
        return CURLE_OK;
    }
    if (unsafe { (*authhost).want }) != 0 && (unsafe { (*authhost).picked }) == 0 {
        (unsafe { (*authhost).picked = (*authhost).want });
    }
    if (unsafe { (*authproxy).want }) != 0 && (unsafe { (*authproxy).picked }) == 0 {
        (unsafe { (*authproxy).picked = (*authproxy).want });
    }
    if (unsafe { ((*conn).bits).httpproxy() }) as i32 != 0 && (unsafe { ((*conn).bits).tunnel_proxy() }) == proxytunnel as bit
    {
        result = output_auth_headers(data, conn, authproxy, request, path, 1 as i32 != 0);
        if result as u64 != 0 {
            return result;
        }
    } else {
        (unsafe { (*authproxy).set_done(1 as i32 as bit) });
    }
    if (unsafe { ((*data).state).this_is_a_follow() }) == 0
        || (unsafe { ((*conn).bits).netrc() }) as i32 != 0
        || (unsafe { (*data).state.first_host }).is_null()
        || (unsafe { ((*data).set).allow_auth_to_other_hosts() }) as i32 != 0
        || (unsafe { Curl_strcasecompare((*data).state.first_host, (*conn).host.name) }) != 0
    {
        result = output_auth_headers(data, conn, authhost, request, path, 0 as i32 != 0);
    } else {
        (unsafe { (*authhost).set_done(1 as i32 as bit) });
    }
    if ((unsafe { (*authhost).multipass() }) as i32 != 0 && (unsafe { (*authhost).done() }) == 0
        || (unsafe { (*authproxy).multipass() }) as i32 != 0 && (unsafe { (*authproxy).done() }) == 0)
        && httpreq as u32 != HTTPREQ_GET as i32 as u32
        && httpreq as u32 != HTTPREQ_HEAD as i32 as u32
    {
        let fresh9 = unsafe { &mut ((*conn).bits) };
        (*fresh9).set_authneg(1 as i32 as bit);
    } else {
        let fresh10 = unsafe { &mut ((*conn).bits) };
        (*fresh10).set_authneg(0 as i32 as bit);
    }
    return result;
}
extern "C" fn is_valid_auth_separator(mut ch: i8) -> i32 {
    return (ch as i32 == '\u{0}' as i32
        || ch as i32 == ',' as i32
        || (unsafe { Curl_isspace(ch as u8 as i32) }) != 0) as i32;
}
#[no_mangle]
pub extern "C" fn Curl_http_input_auth(
    mut data: *mut Curl_easy,
    mut proxy: bool,
    mut auth: *const i8,
) -> CURLcode {
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    let mut availp: *mut u64 = 0 as *mut u64;
    let mut authp: *mut auth = 0 as *mut auth;
    if proxy {
        availp = unsafe { &mut (*data).info.proxyauthavail };
        authp = unsafe { &mut (*data).state.authproxy };
    } else {
        availp = unsafe { &mut (*data).info.httpauthavail };
        authp = unsafe { &mut (*data).state.authhost };
    }
    while (unsafe { *auth }) != 0 {
        if (unsafe { curl_strnequal(
            b"NTLM\0" as *const u8 as *const i8,
            auth,
            strlen(b"NTLM\0" as *const u8 as *const i8),
        ) }) != 0
            && is_valid_auth_separator(unsafe { *auth.offset(4 as i32 as isize) }) != 0
        {
            if (unsafe { (*authp).avail }) & (1 as i32 as u64) << 3 as i32 != 0
                || (unsafe { (*authp).avail }) & (1 as i32 as u64) << 5 as i32 != 0
                || (unsafe { Curl_auth_is_ntlm_supported() }) as i32 != 0
            {
                (unsafe { *availp |= (1 as i32 as u64) << 3 as i32 });
                (unsafe { (*authp).avail |= (1 as i32 as u64) << 3 as i32 });
                if (unsafe { (*authp).picked }) == (1 as i32 as u64) << 3 as i32
                    || (unsafe { (*authp).picked }) == (1 as i32 as u64) << 5 as i32
                {
                    let mut result: CURLcode = unsafe { Curl_input_ntlm(data, proxy, auth) };
                    if result as u64 == 0 {
                        let fresh11 = unsafe { &mut ((*data).state) };
                        (*fresh11).set_authproblem(0 as i32 as bit);
                        if (unsafe { (*authp).picked }) == (1 as i32 as u64) << 5 as i32 {
                            (unsafe { *availp &= !((1 as i32 as u64) << 3 as i32) });
                            (unsafe { (*authp).avail &= !((1 as i32 as u64) << 3 as i32) });
                            (unsafe { *availp |= (1 as i32 as u64) << 5 as i32 });
                            (unsafe { (*authp).avail |= (1 as i32 as u64) << 5 as i32 });
                            result = unsafe { Curl_input_ntlm_wb(data, conn, proxy, auth) };
                            if result as u64 != 0 {
                                (unsafe { Curl_infof(
                                    data,
                                    b"Authentication problem. Ignoring this.\0" as *const u8
                                        as *const i8,
                                ) });
                                let fresh12 = unsafe { &mut ((*data).state) };
                                (*fresh12).set_authproblem(1 as i32 as bit);
                            }
                        }
                    } else {
                        (unsafe { Curl_infof(
                            data,
                            b"Authentication problem. Ignoring this.\0" as *const u8 as *const i8,
                        ) });
                        let fresh13 = unsafe { &mut ((*data).state) };
                        (*fresh13).set_authproblem(1 as i32 as bit);
                    }
                }
            }
        } else if (unsafe { curl_strnequal(
            b"Digest\0" as *const u8 as *const i8,
            auth,
            strlen(b"Digest\0" as *const u8 as *const i8),
        ) }) != 0
            && is_valid_auth_separator(unsafe { *auth.offset(6 as i32 as isize) }) != 0
        {
            if (unsafe { (*authp).avail }) & (1 as i32 as u64) << 1 as i32 != 0 as i32 as u64 {
                (unsafe { Curl_infof(
                    data,
                    b"Ignoring duplicate digest auth header.\0" as *const u8 as *const i8,
                ) });
            } else if unsafe { Curl_auth_is_digest_supported() } {
                let mut result_0: CURLcode = CURLE_OK;
                (unsafe { *availp |= (1 as i32 as u64) << 1 as i32 });
                (unsafe { (*authp).avail |= (1 as i32 as u64) << 1 as i32 });
                result_0 = unsafe { Curl_input_digest(data, proxy, auth) };
                if result_0 as u64 != 0 {
                    (unsafe { Curl_infof(
                        data,
                        b"Authentication problem. Ignoring this.\0" as *const u8 as *const i8,
                    ) });
                    let fresh14 = unsafe { &mut ((*data).state) };
                    (*fresh14).set_authproblem(1 as i32 as bit);
                }
            }
        } else if (unsafe { curl_strnequal(
            b"Basic\0" as *const u8 as *const i8,
            auth,
            strlen(b"Basic\0" as *const u8 as *const i8),
        ) }) != 0
            && is_valid_auth_separator(unsafe { *auth.offset(5 as i32 as isize) }) != 0
        {
            (unsafe { *availp |= (1 as i32 as u64) << 0 as i32 });
            (unsafe { (*authp).avail |= (1 as i32 as u64) << 0 as i32 });
            if (unsafe { (*authp).picked }) == (1 as i32 as u64) << 0 as i32 {
                (unsafe { (*authp).avail = 0 as i32 as u64 });
                (unsafe { Curl_infof(
                    data,
                    b"Authentication problem. Ignoring this.\0" as *const u8 as *const i8,
                ) });
                let fresh15 = unsafe { &mut ((*data).state) };
                (*fresh15).set_authproblem(1 as i32 as bit);
            }
        } else if (unsafe { curl_strnequal(
            b"Bearer\0" as *const u8 as *const i8,
            auth,
            strlen(b"Bearer\0" as *const u8 as *const i8),
        ) }) != 0
            && is_valid_auth_separator(unsafe { *auth.offset(6 as i32 as isize) }) != 0
        {
            (unsafe { *availp |= (1 as i32 as u64) << 6 as i32 });
            (unsafe { (*authp).avail |= (1 as i32 as u64) << 6 as i32 });
            if (unsafe { (*authp).picked }) == (1 as i32 as u64) << 6 as i32 {
                (unsafe { (*authp).avail = 0 as i32 as u64 });
                (unsafe { Curl_infof(
                    data,
                    b"Authentication problem. Ignoring this.\0" as *const u8 as *const i8,
                ) });
                let fresh16 = unsafe { &mut ((*data).state) };
                (*fresh16).set_authproblem(1 as i32 as bit);
            }
        }
        while (unsafe { *auth }) as i32 != 0 && (unsafe { *auth }) as i32 != ',' as i32 {
            auth = unsafe { auth.offset(1) };
        }
        if (unsafe { *auth }) as i32 == ',' as i32 {
            auth = unsafe { auth.offset(1) };
        }
        while (unsafe { *auth }) as i32 != 0 && (unsafe { Curl_isspace(*auth as u8 as i32) }) != 0 {
            auth = unsafe { auth.offset(1) };
        }
    }
    return CURLE_OK;
}
extern "C" fn http_should_fail(mut data: *mut Curl_easy) -> bool {
    let mut httpcode: i32 = 0;
    httpcode = unsafe { (*data).req.httpcode };
    if (unsafe { ((*data).set).http_fail_on_error() }) == 0 {
        return 0 as i32 != 0;
    }
    if httpcode < 400 as i32 {
        return 0 as i32 != 0;
    }
    if (unsafe { (*data).state.resume_from }) != 0
        && (unsafe { (*data).state.httpreq }) as u32 == HTTPREQ_GET as i32 as u32
        && httpcode == 416 as i32
    {
        return 0 as i32 != 0;
    }
    if httpcode != 401 as i32 && httpcode != 407 as i32 {
        return 1 as i32 != 0;
    }
    if httpcode == 401 as i32 && (unsafe { ((*(*data).conn).bits).user_passwd() }) == 0 {
        return 1 as i32 != 0;
    }
    if httpcode == 407 as i32 && (unsafe { ((*(*data).conn).bits).proxy_user_passwd() }) == 0 {
        return 1 as i32 != 0;
    }
    return (unsafe { ((*data).state).authproblem() }) != 0;
}
extern "C" fn readmoredata(
    mut buffer: *mut i8,
    mut size: size_t,
    mut nitems: size_t,
    mut userp: *mut libc::c_void,
) -> size_t {
    let mut data: *mut Curl_easy = userp as *mut Curl_easy;
    let mut http: *mut HTTP = unsafe { (*data).req.p.http };
    let mut fullsize: size_t = size.wrapping_mul(nitems);
    if (unsafe { (*http).postsize }) == 0 {
        return 0 as i32 as size_t;
    }
    let fresh17 = unsafe { &mut ((*data).req) };
    (*fresh17).set_forbidchunk(
        (if (unsafe { (*http).sending }) as u32 == HTTPSEND_REQUEST as i32 as u32 {
            1 as i32
        } else {
            0 as i32
        }) as bit,
    );
    if (unsafe { (*data).set.max_send_speed }) != 0
        && (unsafe { (*data).set.max_send_speed }) < fullsize as curl_off_t
        && (unsafe { (*data).set.max_send_speed }) < (unsafe { (*http).postsize })
    {
        fullsize = (unsafe { (*data).set.max_send_speed }) as size_t;
    } else if (unsafe { (*http).postsize }) <= fullsize as curl_off_t {
        (unsafe { memcpy(
            buffer as *mut libc::c_void,
            (*http).postdata as *const libc::c_void,
            (*http).postsize as size_t,
        ) });
        fullsize = (unsafe { (*http).postsize }) as size_t;
        if (unsafe { (*http).backup.postsize }) != 0 {
            let fresh18 = unsafe { &mut ((*http).postdata) };
            *fresh18 = unsafe { (*http).backup.postdata };
            (unsafe { (*http).postsize = (*http).backup.postsize });
            let fresh19 = unsafe { &mut ((*data).state.fread_func) };
            *fresh19 = unsafe { (*http).backup.fread_func };
            let fresh20 = unsafe { &mut ((*data).state.in_0) };
            *fresh20 = unsafe { (*http).backup.fread_in };
            let fresh21 = unsafe { &mut ((*http).sending) };
            *fresh21 += 1;
            (unsafe { (*http).backup.postsize = 0 as i32 as curl_off_t });
        } else {
            (unsafe { (*http).postsize = 0 as i32 as curl_off_t });
        }
        return fullsize;
    }
    (unsafe { memcpy(
        buffer as *mut libc::c_void,
        (*http).postdata as *const libc::c_void,
        fullsize,
    ) });
    let fresh22 = unsafe { &mut ((*http).postdata) };
    *fresh22 = unsafe { (*fresh22).offset(fullsize as isize) };
    let fresh23 = unsafe { &mut ((*http).postsize) };
    *fresh23 = (*fresh23 as u64).wrapping_sub(fullsize) as curl_off_t as curl_off_t;
    return fullsize;
}
#[no_mangle]
pub extern "C" fn Curl_buffer_send(
    mut in_0: *mut dynbuf,
    mut data: *mut Curl_easy,
    mut bytes_written: *mut curl_off_t,
    mut included_body_bytes: curl_off_t,
    mut socketindex: i32,
) -> CURLcode {
    let mut amount: ssize_t = 0;
    let mut result: CURLcode = CURLE_OK;
    let mut ptr: *mut i8 = 0 as *mut i8;
    let mut size: size_t = 0;
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    let mut http: *mut HTTP = unsafe { (*data).req.p.http };
    let mut sendsize: size_t = 0;
    let mut sockfd: curl_socket_t = 0;
    let mut headersize: size_t = 0;
    sockfd = unsafe { (*conn).sock[socketindex as usize] };
    ptr = unsafe { Curl_dyn_ptr(in_0) };
    size = unsafe { Curl_dyn_len(in_0) };
    headersize = size.wrapping_sub(included_body_bytes as size_t);
    result = CURLE_OK as i32 as CURLcode;
    if result as u64 != 0 {
        (unsafe { Curl_dyn_free(in_0) });
        return result;
    }
    if ((unsafe { (*(*conn).handler).flags }) & ((1 as i32) << 0 as i32) as u32 != 0
        || (unsafe { (*conn).http_proxy.proxytype }) as u32 == CURLPROXY_HTTPS as i32 as u32)
        && (unsafe { (*conn).httpversion }) as i32 != 20 as i32
    {
        if (unsafe { (*data).set.max_send_speed }) != 0 && included_body_bytes > (unsafe { (*data).set.max_send_speed }) {
            let mut overflow: curl_off_t = included_body_bytes - (unsafe { (*data).set.max_send_speed });
            sendsize = size.wrapping_sub(overflow as size_t);
        } else {
            sendsize = size;
        }
        result = unsafe { Curl_get_upload_buffer(data) };
        if result as u64 != 0 {
            (unsafe { Curl_dyn_free(in_0) });
            return result;
        }
        if sendsize > (unsafe { (*data).set.upload_buffer_size }) as size_t {
            sendsize = (unsafe { (*data).set.upload_buffer_size }) as size_t;
        }
        (unsafe { memcpy(
            (*data).state.ulbuf as *mut libc::c_void,
            ptr as *const libc::c_void,
            sendsize,
        ) });
        ptr = unsafe { (*data).state.ulbuf };
    } else if (unsafe { (*data).set.max_send_speed }) != 0 && included_body_bytes > (unsafe { (*data).set.max_send_speed }) {
        let mut overflow_0: curl_off_t = included_body_bytes - (unsafe { (*data).set.max_send_speed });
        sendsize = size.wrapping_sub(overflow_0 as size_t);
    } else {
        sendsize = size;
    }
    result = unsafe { Curl_write(
        data,
        sockfd,
        ptr as *const libc::c_void,
        sendsize,
        &mut amount,
    ) };
    if result as u64 == 0 {
        let mut headlen: size_t = if amount as size_t > headersize {
            headersize
        } else {
            amount as size_t
        };
        let mut bodylen: size_t = (amount as u64).wrapping_sub(headlen);
        (unsafe { Curl_debug(data, CURLINFO_HEADER_OUT, ptr, headlen) });
        if bodylen != 0 {
            (unsafe { Curl_debug(
                data,
                CURLINFO_DATA_OUT,
                ptr.offset(headlen as isize),
                bodylen,
            ) });
        }
        (unsafe { *bytes_written += amount });
        if !http.is_null() {
            let fresh24 = unsafe { &mut ((*data).req.writebytecount) };
            *fresh24 = (*fresh24 as u64).wrapping_add(bodylen) as curl_off_t as curl_off_t;
            (unsafe { Curl_pgrsSetUploadCounter(data, (*data).req.writebytecount) });
            if amount as size_t != size {
                size = (size as u64).wrapping_sub(amount as u64) as size_t as size_t;
                ptr = unsafe { (Curl_dyn_ptr(in_0)).offset(amount as isize) };
                let fresh25 = unsafe { &mut ((*http).backup.fread_func) };
                *fresh25 = unsafe { (*data).state.fread_func };
                let fresh26 = unsafe { &mut ((*http).backup.fread_in) };
                *fresh26 = unsafe { (*data).state.in_0 };
                let fresh27 = unsafe { &mut ((*http).backup.postdata) };
                *fresh27 = unsafe { (*http).postdata };
                (unsafe { (*http).backup.postsize = (*http).postsize });
                let fresh28 = unsafe { &mut ((*data).state.fread_func) };
                *fresh28 = unsafe { ::std::mem::transmute::<
                    Option<
                        unsafe extern "C" fn(*mut i8, size_t, size_t, *mut libc::c_void) -> size_t,
                    >,
                    curl_read_callback,
                >(Some(
                    readmoredata
                        as unsafe extern "C" fn(
                            *mut i8,
                            size_t,
                            size_t,
                            *mut libc::c_void,
                        ) -> size_t,
                )) };
                let fresh29 = unsafe { &mut ((*data).state.in_0) };
                *fresh29 = data as *mut libc::c_void;
                let fresh30 = unsafe { &mut ((*http).postdata) };
                *fresh30 = ptr;
                (unsafe { (*http).postsize = size as curl_off_t });
                (unsafe { (*data).req.pendingheader = headersize.wrapping_sub(headlen) as curl_off_t });
                (unsafe { (*http).send_buffer = *in_0 });
                (unsafe { (*http).sending = HTTPSEND_REQUEST });
                return CURLE_OK;
            }
            (unsafe { (*http).sending = HTTPSEND_BODY });
        } else if amount as size_t != size {
            return CURLE_SEND_ERROR;
        }
    }
    (unsafe { Curl_dyn_free(in_0) });
    (unsafe { (*data).req.pendingheader = 0 as i32 as curl_off_t });
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_compareheader(
    mut headerline: *const i8,
    mut header: *const i8,
    mut content: *const i8,
) -> bool {
    let mut hlen: size_t = unsafe { strlen(header) };
    let mut clen: size_t = 0;
    let mut len: size_t = 0;
    let mut start: *const i8 = 0 as *const i8;
    let mut end: *const i8 = 0 as *const i8;
    if (unsafe { Curl_strncasecompare(headerline, header, hlen) }) == 0 {
        return 0 as i32 != 0;
    }
    start = (unsafe { &*headerline.offset(hlen as isize) }) as *const i8;
    while (unsafe { *start }) as i32 != 0 && (unsafe { Curl_isspace(*start as u8 as i32) }) != 0 {
        start = unsafe { start.offset(1) };
    }
    end = unsafe { strchr(start, '\r' as i32) };
    if end.is_null() {
        end = unsafe { strchr(start, '\n' as i32) };
        if end.is_null() {
            end = unsafe { strchr(start, '\u{0}' as i32) };
        }
    }
    len = (unsafe { end.offset_from(start) }) as i64 as size_t;
    clen = unsafe { strlen(content) };
    while len >= clen {
        if (unsafe { Curl_strncasecompare(start, content, clen) }) != 0 {
            return 1 as i32 != 0;
        }
        len = len.wrapping_sub(1);
        start = unsafe { start.offset(1) };
    }
    return 0 as i32 != 0;
}
#[no_mangle]
pub extern "C" fn Curl_http_connect(mut data: *mut Curl_easy, mut done: *mut bool) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    (unsafe { Curl_conncontrol(conn, 0 as i32) });
    result = unsafe { Curl_proxy_connect(data, 0 as i32) };
    if result as u64 != 0 {
        return result;
    }
    if (unsafe { ((*conn).bits).proxy_connect_closed() }) != 0 {
        return CURLE_OK;
    }
    if (unsafe { (*conn).http_proxy.proxytype }) as u32 == CURLPROXY_HTTPS as i32 as u32
        && !(unsafe { (*conn).bits.proxy_ssl_connected[0 as i32 as usize] })
    {
        return CURLE_OK;
    }
    if unsafe { Curl_connect_ongoing(conn) } {
        return CURLE_OK;
    }
    if (unsafe { ((*data).set).haproxyprotocol() }) != 0 {
        result = add_haproxy_protocol_header(data);
        if result as u64 != 0 {
            return result;
        }
    }
    if (unsafe { (*(*conn).given).protocol }) & ((1 as i32) << 1 as i32) as u32 != 0 {
        result = https_connecting(data, done);
        if result as u64 != 0 {
            return result;
        }
    } else {
        (unsafe { *done = 1 as i32 != 0 });
    }
    return CURLE_OK;
}
extern "C" fn http_getsock_do(
    mut _data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> i32 {
    (unsafe { *socks.offset(0 as i32 as isize) = (*conn).sock[0 as i32 as usize] });
    return (1 as i32) << 16 as i32 + 0 as i32;
}
extern "C" fn add_haproxy_protocol_header(mut data: *mut Curl_easy) -> CURLcode {
    let mut req: dynbuf = dynbuf {
        bufr: 0 as *mut i8,
        leng: 0,
        allc: 0,
        toobig: 0,
    };
    let mut result: CURLcode = CURLE_OK;
    let mut tcp_version: *const i8 = 0 as *const i8;
    (unsafe { Curl_dyn_init(&mut req, 2048 as i32 as size_t) });
    if !(unsafe { (*(*data).conn).unix_domain_socket }).is_null() {
        result = unsafe { Curl_dyn_add(&mut req, b"PROXY UNKNOWN\r\n\0" as *const u8 as *const i8) };
    } else {
        tcp_version = if (unsafe { ((*(*data).conn).bits).ipv6() }) as i32 != 0 {
            b"TCP6\0" as *const u8 as *const i8
        } else {
            b"TCP4\0" as *const u8 as *const i8
        };
        result = unsafe { Curl_dyn_addf(
            &mut req as *mut dynbuf,
            b"PROXY %s %s %s %i %i\r\n\0" as *const u8 as *const i8,
            tcp_version,
            ((*data).info.conn_local_ip).as_mut_ptr(),
            ((*data).info.conn_primary_ip).as_mut_ptr(),
            (*data).info.conn_local_port,
            (*data).info.conn_primary_port,
        ) };
    }
    if result as u64 == 0 {
        result = Curl_buffer_send(
            &mut req,
            data,
            unsafe { &mut (*data).info.request_size },
            0 as i32 as curl_off_t,
            0 as i32,
        );
    }
    return result;
}
extern "C" fn https_connecting(mut data: *mut Curl_easy, mut done: *mut bool) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    result = unsafe { Curl_ssl_connect_nonblocking(data, conn, 0 as i32 != 0, 0 as i32, done) };
    if result as u64 != 0 {
        (unsafe { Curl_conncontrol(conn, 1 as i32) });
    }
    return result;
}
extern "C" fn https_getsock(
    mut _data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> i32 {
    if (unsafe { (*(*conn).handler).flags }) & ((1 as i32) << 0 as i32) as u32 != 0 {
        return unsafe { ((*Curl_ssl).getsock).expect("non-null function pointer")(conn, socks) };
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn Curl_http_done(
    mut data: *mut Curl_easy,
    mut status: CURLcode,
    mut premature: bool,
) -> CURLcode {
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    let mut http: *mut HTTP = unsafe { (*data).req.p.http };
    let fresh31 = unsafe { &mut ((*data).state.authhost) };
    (*fresh31).set_multipass(0 as i32 as bit);
    let fresh32 = unsafe { &mut ((*data).state.authproxy) };
    (*fresh32).set_multipass(0 as i32 as bit);
    (unsafe { Curl_unencode_cleanup(data) });
    let fresh33 = unsafe { &mut ((*conn).seek_func) };
    *fresh33 = unsafe { (*data).set.seek_func };
    let fresh34 = unsafe { &mut ((*conn).seek_client) };
    *fresh34 = unsafe { (*data).set.seek_client };
    if http.is_null() {
        return CURLE_OK;
    }
    (unsafe { Curl_dyn_free(&mut (*http).send_buffer) });
    (unsafe { Curl_http2_done(data, premature) });
    (unsafe { Curl_mime_cleanpart(&mut (*http).form) });
    (unsafe { Curl_dyn_reset(&mut (*data).state.headerb) });
    if status as u64 != 0 {
        return status;
    }
    if !premature
        && (unsafe { ((*conn).bits).retry() }) == 0
        && (unsafe { ((*data).set).connect_only() }) == 0
        && (unsafe { (*data).req.bytecount }) + (unsafe { (*data).req.headerbytecount }) - (unsafe { (*data).req.deductheadercount })
            <= 0 as i32 as i64
    {
        (unsafe { Curl_failf(data, b"Empty reply from server\0" as *const u8 as *const i8) });
        (unsafe { Curl_conncontrol(conn, 2 as i32) });
        return CURLE_GOT_NOTHING;
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_use_http_1_1plus(
    mut data: *const Curl_easy,
    mut conn: *const connectdata,
) -> bool {
    if (unsafe { (*data).state.httpversion }) as i32 == 10 as i32 || (unsafe { (*conn).httpversion }) as i32 == 10 as i32 {
        return 0 as i32 != 0;
    }
    if (unsafe { (*data).state.httpwant }) as i32 == CURL_HTTP_VERSION_1_0 as i32
        && (unsafe { (*conn).httpversion }) as i32 <= 10 as i32
    {
        return 0 as i32 != 0;
    }
    return (unsafe { (*data).state.httpwant }) as i32 == CURL_HTTP_VERSION_NONE as i32
        || (unsafe { (*data).state.httpwant }) as i32 >= CURL_HTTP_VERSION_1_1 as i32;
}
extern "C" fn get_http_string(
    mut data: *const Curl_easy,
    mut conn: *const connectdata,
) -> *const i8 {
    if !(unsafe { (*conn).proto.httpc.h2 }).is_null() {
        return b"2\0" as *const u8 as *const i8;
    }
    if Curl_use_http_1_1plus(data, conn) {
        return b"1.1\0" as *const u8 as *const i8;
    }
    return b"1.0\0" as *const u8 as *const i8;
}
extern "C" fn expect100(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut req: *mut dynbuf,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let fresh35 = unsafe { &mut ((*data).state) };
    (*fresh35).set_expect100header(0 as i32 as bit);
    if (unsafe { ((*data).state).disableexpect() }) == 0
        && Curl_use_http_1_1plus(data, conn) as i32 != 0
        && ((unsafe { (*conn).httpversion }) as i32) < 20 as i32
    {
        let mut ptr: *const i8 = unsafe { Curl_checkheaders(data, b"Expect\0" as *const u8 as *const i8) };
        if !ptr.is_null() {
            let fresh36 = unsafe { &mut ((*data).state) };
            (*fresh36).set_expect100header(Curl_compareheader(
                ptr,
                b"Expect:\0" as *const u8 as *const i8,
                b"100-continue\0" as *const u8 as *const i8,
            ) as bit);
        } else {
            result = unsafe { Curl_dyn_add(req, b"Expect: 100-continue\r\n\0" as *const u8 as *const i8) };
            if result as u64 == 0 {
                let fresh37 = unsafe { &mut ((*data).state) };
                (*fresh37).set_expect100header(1 as i32 as bit);
            }
        }
    }
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_http_compile_trailers(
    mut trailers: *mut curl_slist,
    mut b: *mut dynbuf,
    mut handle: *mut Curl_easy,
) -> CURLcode {
    let mut ptr: *mut i8 = 0 as *mut i8;
    let mut result: CURLcode = CURLE_OK;
    let mut endofline_native: *const i8 = 0 as *const i8;
    let mut endofline_network: *const i8 = 0 as *const i8;
    if (unsafe { ((*handle).state).prefer_ascii() }) as i32 != 0 || (unsafe { ((*handle).set).crlf() }) as i32 != 0 {
        endofline_native = b"\n\0" as *const u8 as *const i8;
        endofline_network = b"\n\0" as *const u8 as *const i8;
    } else {
        endofline_native = b"\r\n\0" as *const u8 as *const i8;
        endofline_network = b"\r\n\0" as *const u8 as *const i8;
    }
    while !trailers.is_null() {
        ptr = unsafe { strchr((*trailers).data, ':' as i32) };
        if !ptr.is_null() && (unsafe { *ptr.offset(1 as i32 as isize) }) as i32 == ' ' as i32 {
            result = unsafe { Curl_dyn_add(b, (*trailers).data) };
            if result as u64 != 0 {
                return result;
            }
            result = unsafe { Curl_dyn_add(b, endofline_native) };
            if result as u64 != 0 {
                return result;
            }
        } else {
            (unsafe { Curl_infof(
                handle,
                b"Malformatted trailing header ! Skipping trailer.\0" as *const u8 as *const i8,
            ) });
        }
        trailers = unsafe { (*trailers).next };
    }
    result = unsafe { Curl_dyn_add(b, endofline_network) };
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_add_custom_headers(
    mut data: *mut Curl_easy,
    mut is_connect: bool,
    mut req: *mut dynbuf,
) -> CURLcode {
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    let mut ptr: *mut i8 = 0 as *mut i8;
    let mut h: [*mut curl_slist; 2] = [0 as *mut curl_slist; 2];
    let mut headers: *mut curl_slist = 0 as *mut curl_slist;
    let mut numlists: i32 = 1 as i32;
    let mut i: i32 = 0;
    let mut proxy: proxy_use = HEADER_SERVER;
    if is_connect {
        proxy = HEADER_CONNECT;
    } else {
        proxy = (if (unsafe { ((*conn).bits).httpproxy() }) as i32 != 0 && (unsafe { ((*conn).bits).tunnel_proxy() }) == 0 {
            HEADER_PROXY as i32
        } else {
            HEADER_SERVER as i32
        }) as proxy_use;
    }
    match proxy as u32 {
        0 => {
            h[0 as i32 as usize] = unsafe { (*data).set.headers };
        }
        1 => {
            h[0 as i32 as usize] = unsafe { (*data).set.headers };
            if (unsafe { ((*data).set).sep_headers() }) != 0 {
                h[1 as i32 as usize] = unsafe { (*data).set.proxyheaders };
                numlists += 1;
            }
        }
        2 => {
            if (unsafe { ((*data).set).sep_headers() }) != 0 {
                h[0 as i32 as usize] = unsafe { (*data).set.proxyheaders };
            } else {
                h[0 as i32 as usize] = unsafe { (*data).set.headers };
            }
        }
        _ => {}
    }
    i = 0 as i32;
    while i < numlists {
        headers = h[i as usize];
        while !headers.is_null() {
            let mut semicolonp: *mut i8 = 0 as *mut i8;
            ptr = unsafe { strchr((*headers).data, ':' as i32) };
            if ptr.is_null() {
                let mut optr: *mut i8 = 0 as *mut i8;
                ptr = unsafe { strchr((*headers).data, ';' as i32) };
                if !ptr.is_null() {
                    optr = ptr;
                    ptr = unsafe { ptr.offset(1) };
                    while (unsafe { *ptr }) as i32 != 0 && (unsafe { Curl_isspace(*ptr as u8 as i32) }) != 0 {
                        ptr = unsafe { ptr.offset(1) };
                    }
                    if (unsafe { *ptr }) != 0 {
                        optr = 0 as *mut i8;
                    } else {
                        ptr = unsafe { ptr.offset(-1) };
                        if (unsafe { *ptr }) as i32 == ';' as i32 {
                            semicolonp =
                                unsafe { Curl_cstrdup.expect("non-null function pointer")((*headers).data) };
                            if semicolonp.is_null() {
                                (unsafe { Curl_dyn_free(req) });
                                return CURLE_OUT_OF_MEMORY;
                            }
                            (unsafe { *semicolonp.offset(ptr.offset_from((*headers).data) as i64 as isize) =
                                ':' as i32 as i8 });
                            optr = (unsafe { &mut *semicolonp
                                .offset(ptr.offset_from((*headers).data) as i64 as isize) })
                                as *mut i8;
                        }
                    }
                    ptr = optr;
                }
            }
            if !ptr.is_null() {
                ptr = unsafe { ptr.offset(1) };
                while (unsafe { *ptr }) as i32 != 0 && (unsafe { Curl_isspace(*ptr as u8 as i32) }) != 0 {
                    ptr = unsafe { ptr.offset(1) };
                }
                if (unsafe { *ptr }) as i32 != 0 || !semicolonp.is_null() {
                    let mut result: CURLcode = CURLE_OK;
                    let mut compare: *mut i8 = if !semicolonp.is_null() {
                        semicolonp
                    } else {
                        unsafe { (*headers).data }
                    };
                    if !(!(unsafe { (*data).state.aptr.host }).is_null()
                        && (unsafe { curl_strnequal(
                            b"Host:\0" as *const u8 as *const i8,
                            compare,
                            strlen(b"Host:\0" as *const u8 as *const i8),
                        ) }) != 0)
                    {
                        if !((unsafe { (*data).state.httpreq }) as u32 == HTTPREQ_POST_FORM as i32 as u32
                            && (unsafe { curl_strnequal(
                                b"Content-Type:\0" as *const u8 as *const i8,
                                compare,
                                strlen(b"Content-Type:\0" as *const u8 as *const i8),
                            ) }) != 0)
                        {
                            if !((unsafe { (*data).state.httpreq }) as u32 == HTTPREQ_POST_MIME as i32 as u32
                                && (unsafe { curl_strnequal(
                                    b"Content-Type:\0" as *const u8 as *const i8,
                                    compare,
                                    strlen(b"Content-Type:\0" as *const u8 as *const i8),
                                ) }) != 0)
                            {
                                if !((unsafe { ((*conn).bits).authneg() }) as i32 != 0
                                    && (unsafe { curl_strnequal(
                                        b"Content-Length:\0" as *const u8 as *const i8,
                                        compare,
                                        strlen(b"Content-Length:\0" as *const u8 as *const i8),
                                    ) }) != 0)
                                {
                                    if !(!(unsafe { (*data).state.aptr.te }).is_null()
                                        && (unsafe { curl_strnequal(
                                            b"Connection:\0" as *const u8 as *const i8,
                                            compare,
                                            strlen(b"Connection:\0" as *const u8 as *const i8),
                                        ) }) != 0)
                                    {
                                        if !((unsafe { (*conn).httpversion }) as i32 >= 20 as i32
                                            && (unsafe { curl_strnequal(
                                                b"Transfer-Encoding:\0" as *const u8 as *const i8,
                                                compare,
                                                strlen(
                                                    b"Transfer-Encoding:\0" as *const u8
                                                        as *const i8,
                                                ),
                                            ) }) != 0)
                                        {
                                            if !(((unsafe { curl_strnequal(
                                                b"Authorization:\0" as *const u8 as *const i8,
                                                compare,
                                                strlen(
                                                    b"Authorization:\0" as *const u8 as *const i8,
                                                ),
                                            ) }) != 0
                                                || (unsafe { curl_strnequal(
                                                    b"Cookie:\0" as *const u8 as *const i8,
                                                    compare,
                                                    strlen(b"Cookie:\0" as *const u8 as *const i8),
                                                ) }) != 0)
                                                && ((unsafe { ((*data).state).this_is_a_follow() }) as i32 != 0
                                                    && !(unsafe { (*data).state.first_host }).is_null()
                                                    && (unsafe { ((*data).set).allow_auth_to_other_hosts() })
                                                        == 0
                                                    && (unsafe { Curl_strcasecompare(
                                                        (*data).state.first_host,
                                                        (*conn).host.name,
                                                    ) }) == 0))
                                            {
                                                result = unsafe { Curl_dyn_addf(
                                                    req,
                                                    b"%s\r\n\0" as *const u8 as *const i8,
                                                    compare,
                                                ) };
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if !semicolonp.is_null() {
                        (unsafe { Curl_cfree.expect("non-null function pointer")(
                            semicolonp as *mut libc::c_void,
                        ) });
                    }
                    if result as u64 != 0 {
                        return result;
                    }
                }
            }
            headers = unsafe { (*headers).next };
        }
        i += 1;
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_add_timecondition(
    mut data: *mut Curl_easy,
    mut req: *mut dynbuf,
) -> CURLcode {
    let mut tm: *const tm = 0 as *const tm;
    let mut keeptime: tm = tm {
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
    let mut result: CURLcode = CURLE_OK;
    let mut datestr: [i8; 80] = [0; 80];
    let mut condp: *const i8 = 0 as *const i8;
    if (unsafe { (*data).set.timecondition }) as u32 == CURL_TIMECOND_NONE as i32 as u32 {
        return CURLE_OK;
    }
    result = unsafe { Curl_gmtime((*data).set.timevalue, &mut keeptime) };
    if result as u64 != 0 {
        (unsafe { Curl_failf(data, b"Invalid TIMEVALUE\0" as *const u8 as *const i8) });
        return result;
    }
    tm = &mut keeptime;
    match (unsafe { (*data).set.timecondition }) as u32 {
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
    if !(unsafe { Curl_checkheaders(data, condp) }).is_null() {
        return CURLE_OK;
    }
    (unsafe { curl_msnprintf(
        datestr.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 80]>() as u64,
        b"%s: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n\0" as *const u8 as *const i8,
        condp,
        Curl_wkday[(if (*tm).tm_wday != 0 {
            (*tm).tm_wday - 1 as i32
        } else {
            6 as i32
        }) as usize],
        (*tm).tm_mday,
        Curl_month[(*tm).tm_mon as usize],
        (*tm).tm_year + 1900 as i32,
        (*tm).tm_hour,
        (*tm).tm_min,
        (*tm).tm_sec,
    ) });
    result = unsafe { Curl_dyn_add(req, datestr.as_mut_ptr()) };
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_http_method(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut method: *mut *const i8,
    mut reqp: *mut Curl_HttpReq,
) {
    let mut httpreq: Curl_HttpReq = unsafe { (*data).state.httpreq };
    let mut request: *const i8 = 0 as *const i8;
    if (unsafe { (*(*conn).handler).protocol })
        & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32 | (1 as i32) << 2 as i32) as u32
        != 0
        && (unsafe { ((*data).set).upload() }) as i32 != 0
    {
        httpreq = HTTPREQ_PUT;
    }
    if !(unsafe { (*data).set.str_0[STRING_CUSTOMREQUEST as i32 as usize] }).is_null() {
        request = unsafe { (*data).set.str_0[STRING_CUSTOMREQUEST as i32 as usize] };
    } else if (unsafe { ((*data).set).opt_no_body() }) != 0 {
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
    (unsafe { *method = request });
    (unsafe { *reqp = httpreq });
}
#[no_mangle]
pub extern "C" fn Curl_http_useragent(mut data: *mut Curl_easy) -> CURLcode {
    if !(unsafe { Curl_checkheaders(data, b"User-Agent\0" as *const u8 as *const i8) }).is_null() {
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            (*data).state.aptr.uagent as *mut libc::c_void,
        ) });
        let fresh38 = unsafe { &mut ((*data).state.aptr.uagent) };
        *fresh38 = 0 as *mut i8;
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_http_host(mut data: *mut Curl_easy, mut conn: *mut connectdata) -> CURLcode {
    let mut ptr: *const i8 = 0 as *const i8;
    if (unsafe { ((*data).state).this_is_a_follow() }) == 0 {
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            (*data).state.first_host as *mut libc::c_void,
        ) });
        let fresh39 = unsafe { &mut ((*data).state.first_host) };
        *fresh39 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*conn).host.name) };
        if (unsafe { (*data).state.first_host }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (unsafe { (*data).state.first_remote_port = (*conn).remote_port });
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.aptr.host as *mut libc::c_void) });
    let fresh40 = unsafe { &mut ((*data).state.aptr.host) };
    *fresh40 = 0 as *mut i8;
    ptr = unsafe { Curl_checkheaders(data, b"Host\0" as *const u8 as *const i8) };
    if !ptr.is_null()
        && ((unsafe { ((*data).state).this_is_a_follow() }) == 0
            || (unsafe { Curl_strcasecompare((*data).state.first_host, (*conn).host.name) }) != 0)
    {
        let mut cookiehost: *mut i8 = Curl_copy_header_value(ptr);
        if cookiehost.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if (unsafe { *cookiehost }) == 0 {
            (unsafe { Curl_cfree.expect("non-null function pointer")(cookiehost as *mut libc::c_void) });
        } else {
            if (unsafe { *cookiehost }) as i32 == '[' as i32 {
                let mut closingbracket: *mut i8 = 0 as *mut i8;
                (unsafe { memmove(
                    cookiehost as *mut libc::c_void,
                    cookiehost.offset(1 as i32 as isize) as *const libc::c_void,
                    (strlen(cookiehost)).wrapping_sub(1 as i32 as u64),
                ) });
                closingbracket = unsafe { strchr(cookiehost, ']' as i32) };
                if !closingbracket.is_null() {
                    (unsafe { *closingbracket = 0 as i32 as i8 });
                }
            } else {
                let mut startsearch: i32 = 0 as i32;
                let mut colon: *mut i8 =
                    unsafe { strchr(cookiehost.offset(startsearch as isize), ':' as i32) };
                if !colon.is_null() {
                    (unsafe { *colon = 0 as i32 as i8 });
                }
            }
            (unsafe { Curl_cfree.expect("non-null function pointer")(
                (*data).state.aptr.cookiehost as *mut libc::c_void,
            ) });
            let fresh41 = unsafe { &mut ((*data).state.aptr.cookiehost) };
            *fresh41 = 0 as *mut i8;
            let fresh42 = unsafe { &mut ((*data).state.aptr.cookiehost) };
            *fresh42 = cookiehost;
        }
        if (unsafe { strcmp(b"Host:\0" as *const u8 as *const i8, ptr) }) != 0 {
            let fresh43 = unsafe { &mut ((*data).state.aptr.host) };
            *fresh43 = unsafe { curl_maprintf(
                b"Host:%s\r\n\0" as *const u8 as *const i8,
                &*ptr.offset(5 as i32 as isize) as *const i8,
            ) };
            if (unsafe { (*data).state.aptr.host }).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        } else {
            let fresh44 = unsafe { &mut ((*data).state.aptr.host) };
            *fresh44 = 0 as *mut i8;
        }
    } else {
        let mut host: *const i8 = unsafe { (*conn).host.name };
        if (unsafe { (*(*conn).given).protocol }) & ((1 as i32) << 1 as i32) as u32 != 0
            && (unsafe { (*conn).remote_port }) == 443 as i32
            || (unsafe { (*(*conn).given).protocol }) & ((1 as i32) << 0 as i32) as u32 != 0
                && (unsafe { (*conn).remote_port }) == 80 as i32
        {
            let fresh45 = unsafe { &mut ((*data).state.aptr.host) };
            *fresh45 = unsafe { curl_maprintf(
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
            ) };
        } else {
            let fresh46 = unsafe { &mut ((*data).state.aptr.host) };
            *fresh46 = unsafe { curl_maprintf(
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
            ) };
        }
        if (unsafe { (*data).state.aptr.host }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_http_target(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut r: *mut dynbuf,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut path: *const i8 = unsafe { (*data).state.up.path };
    let mut query: *const i8 = unsafe { (*data).state.up.query };
    if !(unsafe { (*data).set.str_0[STRING_TARGET as i32 as usize] }).is_null() {
        path = unsafe { (*data).set.str_0[STRING_TARGET as i32 as usize] };
        query = 0 as *const i8;
    }
    if (unsafe { ((*conn).bits).httpproxy() }) as i32 != 0 && (unsafe { ((*conn).bits).tunnel_proxy() }) == 0 {
        let mut uc: CURLUcode = CURLUE_OK;
        let mut url: *mut i8 = 0 as *mut i8;
        let mut h: *mut CURLU = unsafe { curl_url_dup((*data).state.uh) };
        if h.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if (unsafe { (*conn).host.dispname }) != (unsafe { (*conn).host.name }) as *const i8 {
            uc = unsafe { curl_url_set(h, CURLUPART_HOST, (*conn).host.name, 0 as i32 as u32) };
            if uc as u64 != 0 {
                (unsafe { curl_url_cleanup(h) });
                return CURLE_OUT_OF_MEMORY;
            }
        }
        uc = unsafe { curl_url_set(h, CURLUPART_FRAGMENT, 0 as *const i8, 0 as i32 as u32) };
        if uc as u64 != 0 {
            (unsafe { curl_url_cleanup(h) });
            return CURLE_OUT_OF_MEMORY;
        }
        if (unsafe { Curl_strcasecompare(b"http\0" as *const u8 as *const i8, (*data).state.up.scheme) }) != 0 {
            uc = unsafe { curl_url_set(h, CURLUPART_USER, 0 as *const i8, 0 as i32 as u32) };
            if uc as u64 != 0 {
                (unsafe { curl_url_cleanup(h) });
                return CURLE_OUT_OF_MEMORY;
            }
            uc = unsafe { curl_url_set(h, CURLUPART_PASSWORD, 0 as *const i8, 0 as i32 as u32) };
            if uc as u64 != 0 {
                (unsafe { curl_url_cleanup(h) });
                return CURLE_OUT_OF_MEMORY;
            }
        }
        uc = unsafe { curl_url_get(h, CURLUPART_URL, &mut url, ((1 as i32) << 1 as i32) as u32) };
        if uc as u64 != 0 {
            (unsafe { curl_url_cleanup(h) });
            return CURLE_OUT_OF_MEMORY;
        }
        (unsafe { curl_url_cleanup(h) });
        result = unsafe { Curl_dyn_add(
            r,
            if !((*data).set.str_0[STRING_TARGET as i32 as usize]).is_null() {
                (*data).set.str_0[STRING_TARGET as i32 as usize]
            } else {
                url
            },
        ) };
        (unsafe { Curl_cfree.expect("non-null function pointer")(url as *mut libc::c_void) });
        if result as u64 != 0 {
            return result;
        }
        if (unsafe { Curl_strcasecompare(b"ftp\0" as *const u8 as *const i8, (*data).state.up.scheme) }) != 0 {
            if (unsafe { ((*data).set).proxy_transfer_mode() }) != 0 {
                let mut type_0: *mut i8 = unsafe { strstr(path, b";type=\0" as *const u8 as *const i8) };
                if !type_0.is_null()
                    && (unsafe { *type_0.offset(6 as i32 as isize) }) as i32 != 0
                    && (unsafe { *type_0.offset(7 as i32 as isize) }) as i32 == 0 as i32
                {
                    match (unsafe { Curl_raw_toupper(*type_0.offset(6 as i32 as isize)) }) as i32 {
                        65 | 68 | 73 => {}
                        _ => {
                            type_0 = 0 as *mut i8;
                        }
                    }
                }
                if type_0.is_null() {
                    result = unsafe { Curl_dyn_addf(
                        r,
                        b";type=%c\0" as *const u8 as *const i8,
                        if ((*data).state).prefer_ascii() as i32 != 0 {
                            'a' as i32
                        } else {
                            'i' as i32
                        },
                    ) };
                    if result as u64 != 0 {
                        return result;
                    }
                }
            }
        }
    } else {
        result = unsafe { Curl_dyn_add(r, path) };
        if result as u64 != 0 {
            return result;
        }
        if !query.is_null() {
            result = unsafe { Curl_dyn_addf(r, b"?%s\0" as *const u8 as *const i8, query) };
        }
    }
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_http_body(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut httpreq: Curl_HttpReq,
    mut tep: *mut *const i8,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ptr: *const i8 = 0 as *const i8;
    let mut http: *mut HTTP = unsafe { (*data).req.p.http };
    (unsafe { (*http).postsize = 0 as i32 as curl_off_t });
    match httpreq as u32 {
        3 => {
            let fresh47 = unsafe { &mut ((*http).sendit) };
            *fresh47 = unsafe { &mut (*data).set.mimepost };
        }
        2 => {
            (unsafe { Curl_mime_cleanpart(&mut (*http).form) });
            result = unsafe { Curl_getformdata(
                data,
                &mut (*http).form,
                (*data).set.httppost,
                (*data).state.fread_func,
            ) };
            if result as u64 != 0 {
                return result;
            }
            let fresh48 = unsafe { &mut ((*http).sendit) };
            *fresh48 = unsafe { &mut (*http).form };
        }
        _ => {
            let fresh49 = unsafe { &mut ((*http).sendit) };
            *fresh49 = 0 as *mut curl_mimepart;
        }
    }
    if !(unsafe { (*http).sendit }).is_null() {
        let mut cthdr: *const i8 =
            unsafe { Curl_checkheaders(data, b"Content-Type\0" as *const u8 as *const i8) };
        (unsafe { (*(*http).sendit).flags |= ((1 as i32) << 1 as i32) as u32 });
        if !cthdr.is_null() {
            cthdr = unsafe { cthdr.offset(13 as i32 as isize) };
            while (unsafe { *cthdr }) as i32 == ' ' as i32 {
                cthdr = unsafe { cthdr.offset(1) };
            }
        } else if (unsafe { (*(*http).sendit).kind }) as u32 == MIMEKIND_MULTIPART as i32 as u32 {
            cthdr = b"multipart/form-data\0" as *const u8 as *const i8;
        }
        (unsafe { curl_mime_headers((*http).sendit, (*data).set.headers, 0 as i32) });
        result =
            unsafe { Curl_mime_prepare_headers((*http).sendit, cthdr, 0 as *const i8, MIMESTRATEGY_FORM) };
        (unsafe { curl_mime_headers((*http).sendit, 0 as *mut curl_slist, 0 as i32) });
        if result as u64 == 0 {
            result = unsafe { Curl_mime_rewind((*http).sendit) };
        }
        if result as u64 != 0 {
            return result;
        }
        (unsafe { (*http).postsize = Curl_mime_size((*http).sendit) });
    }
    ptr = unsafe { Curl_checkheaders(data, b"Transfer-Encoding\0" as *const u8 as *const i8) };
    if !ptr.is_null() {
        let fresh50 = unsafe { &mut ((*data).req) };
        (*fresh50).set_upload_chunky(Curl_compareheader(
            ptr,
            b"Transfer-Encoding:\0" as *const u8 as *const i8,
            b"chunked\0" as *const u8 as *const i8,
        ) as bit);
    } else {
        if (unsafe { (*(*conn).handler).protocol }) & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32
            != 0
            && ((httpreq as u32 == HTTPREQ_POST_MIME as i32 as u32
                || httpreq as u32 == HTTPREQ_POST_FORM as i32 as u32)
                && (unsafe { (*http).postsize }) < 0 as i32 as i64
                || ((unsafe { ((*data).set).upload() }) as i32 != 0
                    || httpreq as u32 == HTTPREQ_POST as i32 as u32)
                    && (unsafe { (*data).state.infilesize }) == -(1 as i32) as i64)
        {
            if !((unsafe { ((*conn).bits).authneg() }) != 0) {
                if Curl_use_http_1_1plus(data, conn) {
                    if ((unsafe { (*conn).httpversion }) as i32) < 20 as i32 {
                        let fresh51 = unsafe { &mut ((*data).req) };
                        (*fresh51).set_upload_chunky(1 as i32 as bit);
                    }
                } else {
                    (unsafe { Curl_failf(
                        data,
                        b"Chunky upload is not supported by HTTP 1.0\0" as *const u8 as *const i8,
                    ) });
                    return CURLE_UPLOAD_FAILED;
                }
            }
        } else {
            let fresh52 = unsafe { &mut ((*data).req) };
            (*fresh52).set_upload_chunky(0 as i32 as bit);
        }
        if (unsafe { ((*data).req).upload_chunky() }) != 0 {
            (unsafe { *tep = b"Transfer-Encoding: chunked\r\n\0" as *const u8 as *const i8 });
        }
    }
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_http_bodysend(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut r: *mut dynbuf,
    mut httpreq: Curl_HttpReq,
) -> CURLcode {
    let mut included_body: curl_off_t = 0 as i32 as curl_off_t;
    let mut result: CURLcode = CURLE_OK;
    let mut http: *mut HTTP = unsafe { (*data).req.p.http };
    let mut ptr: *const i8 = 0 as *const i8;
    match httpreq as u32 {
        4 => {
            if (unsafe { ((*conn).bits).authneg() }) != 0 {
                (unsafe { (*http).postsize = 0 as i32 as curl_off_t });
            } else {
                (unsafe { (*http).postsize = (*data).state.infilesize });
            }
            if (unsafe { (*http).postsize }) != -(1 as i32) as i64
                && (unsafe { ((*data).req).upload_chunky() }) == 0
                && ((unsafe { ((*conn).bits).authneg() }) as i32 != 0
                    || (unsafe { Curl_checkheaders(data, b"Content-Length\0" as *const u8 as *const i8) })
                        .is_null())
            {
                result = unsafe { Curl_dyn_addf(
                    r,
                    b"Content-Length: %ld\r\n\0" as *const u8 as *const i8,
                    (*http).postsize,
                ) };
                if result as u64 != 0 {
                    return result;
                }
            }
            if (unsafe { (*http).postsize }) != 0 {
                result = expect100(data, conn, r);
                if result as u64 != 0 {
                    return result;
                }
            }
            result = unsafe { Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const i8) };
            if result as u64 != 0 {
                return result;
            }
            (unsafe { Curl_pgrsSetUploadSize(data, (*http).postsize) });
            result = Curl_buffer_send(
                r,
                data,
                unsafe { &mut (*data).info.request_size },
                0 as i32 as curl_off_t,
                0 as i32,
            );
            if result as u64 != 0 {
                (unsafe { Curl_failf(
                    data,
                    b"Failed sending PUT request\0" as *const u8 as *const i8,
                ) });
            } else {
                (unsafe { Curl_setup_transfer(
                    data,
                    0 as i32,
                    -(1 as i32) as curl_off_t,
                    1 as i32 != 0,
                    if (*http).postsize != 0 {
                        0 as i32
                    } else {
                        -(1 as i32)
                    },
                ) });
            }
            if result as u64 != 0 {
                return result;
            }
        }
        2 | 3 => {
            if (unsafe { ((*conn).bits).authneg() }) != 0 {
                result = unsafe { Curl_dyn_add(r, b"Content-Length: 0\r\n\r\n\0" as *const u8 as *const i8) };
                if result as u64 != 0 {
                    return result;
                }
                result = Curl_buffer_send(
                    r,
                    data,
                    unsafe { &mut (*data).info.request_size },
                    0 as i32 as curl_off_t,
                    0 as i32,
                );
                if result as u64 != 0 {
                    (unsafe { Curl_failf(
                        data,
                        b"Failed sending POST request\0" as *const u8 as *const i8,
                    ) });
                } else {
                    (unsafe { Curl_setup_transfer(
                        data,
                        0 as i32,
                        -(1 as i32) as curl_off_t,
                        1 as i32 != 0,
                        -(1 as i32),
                    ) });
                }
            } else {
                (unsafe { (*data).state.infilesize = (*http).postsize });
                if (unsafe { (*http).postsize }) != -(1 as i32) as i64
                    && (unsafe { ((*data).req).upload_chunky() }) == 0
                    && ((unsafe { ((*conn).bits).authneg() }) as i32 != 0
                        || (unsafe { Curl_checkheaders(data, b"Content-Length\0" as *const u8 as *const i8) })
                            .is_null())
                {
                    result = unsafe { Curl_dyn_addf(
                        r,
                        b"Content-Length: %ld\r\n\0" as *const u8 as *const i8,
                        (*http).postsize,
                    ) };
                    if result as u64 != 0 {
                        return result;
                    }
                }
                let mut hdr: *mut curl_slist = 0 as *mut curl_slist;
                hdr = unsafe { (*(*http).sendit).curlheaders };
                while !hdr.is_null() {
                    result = unsafe { Curl_dyn_addf(r, b"%s\r\n\0" as *const u8 as *const i8, (*hdr).data) };
                    if result as u64 != 0 {
                        return result;
                    }
                    hdr = unsafe { (*hdr).next };
                }
                ptr = unsafe { Curl_checkheaders(data, b"Expect\0" as *const u8 as *const i8) };
                if !ptr.is_null() {
                    let fresh53 = unsafe { &mut ((*data).state) };
                    (*fresh53).set_expect100header(Curl_compareheader(
                        ptr,
                        b"Expect:\0" as *const u8 as *const i8,
                        b"100-continue\0" as *const u8 as *const i8,
                    ) as bit);
                } else if (unsafe { (*http).postsize }) > (1024 as i32 * 1024 as i32) as i64
                    || (unsafe { (*http).postsize }) < 0 as i32 as i64
                {
                    result = expect100(data, conn, r);
                    if result as u64 != 0 {
                        return result;
                    }
                } else {
                    let fresh54 = unsafe { &mut ((*data).state) };
                    (*fresh54).set_expect100header(0 as i32 as bit);
                }
                result = unsafe { Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const i8) };
                if result as u64 != 0 {
                    return result;
                }
                (unsafe { Curl_pgrsSetUploadSize(data, (*http).postsize) });
                let fresh55 = unsafe { &mut ((*data).state.fread_func) };
                *fresh55 = unsafe { ::std::mem::transmute::<
                    Option<
                        unsafe extern "C" fn(*mut i8, size_t, size_t, *mut libc::c_void) -> size_t,
                    >,
                    curl_read_callback,
                >(Some(
                    Curl_mime_read
                        as unsafe extern "C" fn(
                            *mut i8,
                            size_t,
                            size_t,
                            *mut libc::c_void,
                        ) -> size_t,
                )) };
                let fresh56 = unsafe { &mut ((*data).state.in_0) };
                *fresh56 = (unsafe { (*http).sendit }) as *mut libc::c_void;
                (unsafe { (*http).sending = HTTPSEND_BODY });
                result = Curl_buffer_send(
                    r,
                    data,
                    unsafe { &mut (*data).info.request_size },
                    0 as i32 as curl_off_t,
                    0 as i32,
                );
                if result as u64 != 0 {
                    (unsafe { Curl_failf(
                        data,
                        b"Failed sending POST request\0" as *const u8 as *const i8,
                    ) });
                } else {
                    (unsafe { Curl_setup_transfer(
                        data,
                        0 as i32,
                        -(1 as i32) as curl_off_t,
                        1 as i32 != 0,
                        if (*http).postsize != 0 {
                            0 as i32
                        } else {
                            -(1 as i32)
                        },
                    ) });
                }
                if result as u64 != 0 {
                    return result;
                }
            }
        }
        1 => {
            if (unsafe { ((*conn).bits).authneg() }) != 0 {
                (unsafe { (*http).postsize = 0 as i32 as curl_off_t });
            } else {
                (unsafe { (*http).postsize = (*data).state.infilesize });
            }
            if (unsafe { (*http).postsize }) != -(1 as i32) as i64
                && (unsafe { ((*data).req).upload_chunky() }) == 0
                && ((unsafe { ((*conn).bits).authneg() }) as i32 != 0
                    || (unsafe { Curl_checkheaders(data, b"Content-Length\0" as *const u8 as *const i8) })
                        .is_null())
            {
                result = unsafe { Curl_dyn_addf(
                    r,
                    b"Content-Length: %ld\r\n\0" as *const u8 as *const i8,
                    (*http).postsize,
                ) };
                if result as u64 != 0 {
                    return result;
                }
            }
            if (unsafe { Curl_checkheaders(data, b"Content-Type\0" as *const u8 as *const i8) }).is_null() {
                result = unsafe { Curl_dyn_add(
                    r,
                    b"Content-Type: application/x-www-form-urlencoded\r\n\0" as *const u8
                        as *const i8,
                ) };
                if result as u64 != 0 {
                    return result;
                }
            }
            ptr = unsafe { Curl_checkheaders(data, b"Expect\0" as *const u8 as *const i8) };
            if !ptr.is_null() {
                let fresh57 = unsafe { &mut ((*data).state) };
                (*fresh57).set_expect100header(Curl_compareheader(
                    ptr,
                    b"Expect:\0" as *const u8 as *const i8,
                    b"100-continue\0" as *const u8 as *const i8,
                ) as bit);
            } else if (unsafe { (*http).postsize }) > (1024 as i32 * 1024 as i32) as i64
                || (unsafe { (*http).postsize }) < 0 as i32 as i64
            {
                result = expect100(data, conn, r);
                if result as u64 != 0 {
                    return result;
                }
            } else {
                let fresh58 = unsafe { &mut ((*data).state) };
                (*fresh58).set_expect100header(0 as i32 as bit);
            }
            if !(unsafe { (*data).set.postfields }).is_null() {
                if (unsafe { (*conn).httpversion }) as i32 != 20 as i32
                    && (unsafe { ((*data).state).expect100header() }) == 0
                    && (unsafe { (*http).postsize }) < (64 as i32 * 1024 as i32) as i64
                {
                    result = unsafe { Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const i8) };
                    if result as u64 != 0 {
                        return result;
                    }
                    if (unsafe { ((*data).req).upload_chunky() }) == 0 {
                        result =
                            unsafe { Curl_dyn_addn(r, (*data).set.postfields, (*http).postsize as size_t) };
                        included_body = unsafe { (*http).postsize };
                    } else {
                        if (unsafe { (*http).postsize }) != 0 {
                            let mut chunk: [i8; 16] = [0; 16];
                            (unsafe { curl_msnprintf(
                                chunk.as_mut_ptr(),
                                ::std::mem::size_of::<[i8; 16]>() as u64,
                                b"%x\r\n\0" as *const u8 as *const i8,
                                (*http).postsize as i32,
                            ) });
                            result = unsafe { Curl_dyn_add(r, chunk.as_mut_ptr()) };
                            if result as u64 == 0 {
                                included_body = ((unsafe { (*http).postsize }) as u64)
                                    .wrapping_add(unsafe { strlen(chunk.as_mut_ptr()) })
                                    as curl_off_t;
                                result = unsafe { Curl_dyn_addn(
                                    r,
                                    (*data).set.postfields,
                                    (*http).postsize as size_t,
                                ) };
                                if result as u64 == 0 {
                                    result = unsafe { Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const i8) };
                                }
                                included_body += 2 as i32 as i64;
                            }
                        }
                        if result as u64 == 0 {
                            result = unsafe { Curl_dyn_add(r, b"0\r\n\r\n\0" as *const u8 as *const i8) };
                            included_body += 5 as i32 as i64;
                        }
                    }
                    if result as u64 != 0 {
                        return result;
                    }
                    (unsafe { Curl_pgrsSetUploadSize(data, (*http).postsize) });
                } else {
                    let fresh59 = unsafe { &mut ((*http).postdata) };
                    *fresh59 = (unsafe { (*data).set.postfields }) as *const i8;
                    (unsafe { (*http).sending = HTTPSEND_BODY });
                    let fresh60 = unsafe { &mut ((*data).state.fread_func) };
                    *fresh60 = unsafe { ::std::mem::transmute::<
                        Option<
                            unsafe extern "C" fn(
                                *mut i8,
                                size_t,
                                size_t,
                                *mut libc::c_void,
                            ) -> size_t,
                        >,
                        curl_read_callback,
                    >(Some(
                        readmoredata
                            as unsafe extern "C" fn(
                                *mut i8,
                                size_t,
                                size_t,
                                *mut libc::c_void,
                            ) -> size_t,
                    )) };
                    let fresh61 = unsafe { &mut ((*data).state.in_0) };
                    *fresh61 = data as *mut libc::c_void;
                    (unsafe { Curl_pgrsSetUploadSize(data, (*http).postsize) });
                    result = unsafe { Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const i8) };
                    if result as u64 != 0 {
                        return result;
                    }
                }
            } else {
                result = unsafe { Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const i8) };
                if result as u64 != 0 {
                    return result;
                }
                if (unsafe { ((*data).req).upload_chunky() }) as i32 != 0 && (unsafe { ((*conn).bits).authneg() }) as i32 != 0
                {
                    result = unsafe { Curl_dyn_add(r, b"0\r\n\r\n\0" as *const u8 as *const i8 as *mut i8) };
                    if result as u64 != 0 {
                        return result;
                    }
                } else if (unsafe { (*data).state.infilesize }) != 0 {
                    (unsafe { Curl_pgrsSetUploadSize(
                        data,
                        if (*http).postsize != 0 {
                            (*http).postsize
                        } else {
                            -(1 as i32) as i64
                        },
                    ) });
                    if (unsafe { ((*conn).bits).authneg() }) == 0 {
                        let fresh62 = unsafe { &mut ((*http).postdata) };
                        *fresh62 = (unsafe { &mut (*http).postdata }) as *mut *const i8 as *mut i8;
                    }
                }
            }
            result = Curl_buffer_send(
                r,
                data,
                unsafe { &mut (*data).info.request_size },
                included_body,
                0 as i32,
            );
            if result as u64 != 0 {
                (unsafe { Curl_failf(
                    data,
                    b"Failed sending HTTP POST request\0" as *const u8 as *const i8,
                ) });
            } else {
                (unsafe { Curl_setup_transfer(
                    data,
                    0 as i32,
                    -(1 as i32) as curl_off_t,
                    1 as i32 != 0,
                    if !((*http).postdata).is_null() {
                        0 as i32
                    } else {
                        -(1 as i32)
                    },
                ) });
            }
        }
        _ => {
            result = unsafe { Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const i8) };
            if result as u64 != 0 {
                return result;
            }
            result = Curl_buffer_send(
                r,
                data,
                unsafe { &mut (*data).info.request_size },
                0 as i32 as curl_off_t,
                0 as i32,
            );
            if result as u64 != 0 {
                (unsafe { Curl_failf(
                    data,
                    b"Failed sending HTTP request\0" as *const u8 as *const i8,
                ) });
            } else {
                (unsafe { Curl_setup_transfer(
                    data,
                    0 as i32,
                    -(1 as i32) as curl_off_t,
                    1 as i32 != 0,
                    -(1 as i32),
                ) });
            }
        }
    }
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_http_cookies(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut r: *mut dynbuf,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut addcookies: *mut i8 = 0 as *mut i8;
    if !(unsafe { (*data).set.str_0[STRING_COOKIE as i32 as usize] }).is_null()
        && (unsafe { Curl_checkheaders(data, b"Cookie\0" as *const u8 as *const i8) }).is_null()
    {
        addcookies = unsafe { (*data).set.str_0[STRING_COOKIE as i32 as usize] };
    }
    if !(unsafe { (*data).cookies }).is_null() || !addcookies.is_null() {
        let mut co: *mut Cookie = 0 as *mut Cookie;
        let mut count: i32 = 0 as i32;
        if !(unsafe { (*data).cookies }).is_null() && (unsafe { ((*data).state).cookie_engine() }) as i32 != 0 {
            let mut host: *const i8 = if !(unsafe { (*data).state.aptr.cookiehost }).is_null() {
                unsafe { (*data).state.aptr.cookiehost }
            } else {
                unsafe { (*conn).host.name }
            };
            let secure_context: bool =
                if (unsafe { (*(*conn).handler).protocol }) & ((1 as i32) << 1 as i32) as u32 != 0
                    || (unsafe { Curl_strcasecompare(b"localhost\0" as *const u8 as *const i8, host) }) != 0
                    || (unsafe { strcmp(host, b"127.0.0.1\0" as *const u8 as *const i8) }) == 0
                    || (unsafe { strcmp(host, b"[::1]\0" as *const u8 as *const i8) }) == 0
                {
                    1 as i32
                } else {
                    0 as i32
                } != 0;
            (unsafe { Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE) });
            co = unsafe { Curl_cookie_getlist((*data).cookies, host, (*data).state.up.path, secure_context) };
            (unsafe { Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE) });
        }
        if !co.is_null() {
            let mut store: *mut Cookie = co;
            while !co.is_null() {
                if !(unsafe { (*co).value }).is_null() {
                    if 0 as i32 == count {
                        result = unsafe { Curl_dyn_add(r, b"Cookie: \0" as *const u8 as *const i8) };
                        if result as u64 != 0 {
                            break;
                        }
                    }
                    result = unsafe { Curl_dyn_addf(
                        r,
                        b"%s%s=%s\0" as *const u8 as *const i8,
                        if count != 0 {
                            b"; \0" as *const u8 as *const i8
                        } else {
                            b"\0" as *const u8 as *const i8
                        },
                        (*co).name,
                        (*co).value,
                    ) };
                    if result as u64 != 0 {
                        break;
                    }
                    count += 1;
                }
                co = unsafe { (*co).next };
            }
            (unsafe { Curl_cookie_freelist(store) });
        }
        if !addcookies.is_null() && result as u64 == 0 {
            if count == 0 {
                result = unsafe { Curl_dyn_add(r, b"Cookie: \0" as *const u8 as *const i8) };
            }
            if result as u64 == 0 {
                result = unsafe { Curl_dyn_addf(
                    r,
                    b"%s%s\0" as *const u8 as *const i8,
                    if count != 0 {
                        b"; \0" as *const u8 as *const i8
                    } else {
                        b"\0" as *const u8 as *const i8
                    },
                    addcookies,
                ) };
                count += 1;
            }
        }
        if count != 0 && result as u64 == 0 {
            result = unsafe { Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const i8) };
        }
        if result as u64 != 0 {
            return result;
        }
    }
    return result;
}
#[no_mangle]
pub extern "C" fn Curl_http_range(mut data: *mut Curl_easy, mut httpreq: Curl_HttpReq) -> CURLcode {
    if (unsafe { ((*data).state).use_range() }) != 0 {
        if (httpreq as u32 == HTTPREQ_GET as i32 as u32
            || httpreq as u32 == HTTPREQ_HEAD as i32 as u32)
            && (unsafe { Curl_checkheaders(data, b"Range\0" as *const u8 as *const i8) }).is_null()
        {
            (unsafe { Curl_cfree.expect("non-null function pointer")(
                (*data).state.aptr.rangeline as *mut libc::c_void,
            ) });
            let fresh63 = unsafe { &mut ((*data).state.aptr.rangeline) };
            *fresh63 = unsafe { curl_maprintf(
                b"Range: bytes=%s\r\n\0" as *const u8 as *const i8,
                (*data).state.range,
            ) };
        } else if (httpreq as u32 == HTTPREQ_POST as i32 as u32
            || httpreq as u32 == HTTPREQ_PUT as i32 as u32)
            && (unsafe { Curl_checkheaders(data, b"Content-Range\0" as *const u8 as *const i8) }).is_null()
        {
            (unsafe { Curl_cfree.expect("non-null function pointer")(
                (*data).state.aptr.rangeline as *mut libc::c_void,
            ) });
            if (unsafe { (*data).set.set_resume_from }) < 0 as i32 as i64 {
                let fresh64 = unsafe { &mut ((*data).state.aptr.rangeline) };
                *fresh64 = unsafe { curl_maprintf(
                    b"Content-Range: bytes 0-%ld/%ld\r\n\0" as *const u8 as *const i8,
                    (*data).state.infilesize - 1 as i32 as i64,
                    (*data).state.infilesize,
                ) };
            } else if (unsafe { (*data).state.resume_from }) != 0 {
                let mut total_expected_size: curl_off_t =
                    (unsafe { (*data).state.resume_from }) + (unsafe { (*data).state.infilesize });
                let fresh65 = unsafe { &mut ((*data).state.aptr.rangeline) };
                *fresh65 = unsafe { curl_maprintf(
                    b"Content-Range: bytes %s%ld/%ld\r\n\0" as *const u8 as *const i8,
                    (*data).state.range,
                    total_expected_size - 1 as i32 as i64,
                    total_expected_size,
                ) };
            } else {
                let fresh66 = unsafe { &mut ((*data).state.aptr.rangeline) };
                *fresh66 = unsafe { curl_maprintf(
                    b"Content-Range: bytes %s/%ld\r\n\0" as *const u8 as *const i8,
                    (*data).state.range,
                    (*data).state.infilesize,
                ) };
            }
            if (unsafe { (*data).state.aptr.rangeline }).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_http_resume(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut httpreq: Curl_HttpReq,
) -> CURLcode {
    if (HTTPREQ_POST as i32 as u32 == httpreq as u32 || HTTPREQ_PUT as i32 as u32 == httpreq as u32)
        && (unsafe { (*data).state.resume_from }) != 0
    {
        if (unsafe { (*data).state.resume_from }) < 0 as i32 as i64 {
            (unsafe { (*data).state.resume_from = 0 as i32 as curl_off_t });
        }
        if (unsafe { (*data).state.resume_from }) != 0 && (unsafe { ((*data).state).this_is_a_follow() }) == 0 {
            let mut seekerr: i32 = 2 as i32;
            if unsafe { ((*conn).seek_func).is_some() } {
                (unsafe { Curl_set_in_callback(data, 1 as i32 != 0) });
                seekerr = unsafe { ((*conn).seek_func).expect("non-null function pointer")(
                    (*conn).seek_client,
                    (*data).state.resume_from,
                    0 as i32,
                ) };
                (unsafe { Curl_set_in_callback(data, 0 as i32 != 0) });
            }
            if seekerr != 0 as i32 {
                let mut passed: curl_off_t = 0 as i32 as curl_off_t;
                if seekerr != 2 as i32 {
                    (unsafe { Curl_failf(data, b"Could not seek stream\0" as *const u8 as *const i8) });
                    return CURLE_READ_ERROR;
                }
                loop {
                    let mut readthisamountnow: size_t =
                        if (unsafe { (*data).state.resume_from }) - passed > (unsafe { (*data).set.buffer_size }) {
                            (unsafe { (*data).set.buffer_size }) as size_t
                        } else {
                            unsafe { curlx_sotouz((*data).state.resume_from - passed) }
                        };
                    let mut actuallyread: size_t = unsafe { ((*data).state.fread_func)
                        .expect("non-null function pointer")(
                        (*data).state.buffer,
                        1 as i32 as size_t,
                        readthisamountnow,
                        (*data).state.in_0,
                    ) };
                    passed = (passed as u64).wrapping_add(actuallyread) as curl_off_t as curl_off_t;
                    if actuallyread == 0 as i32 as u64 || actuallyread > readthisamountnow {
                        (unsafe { Curl_failf(
                            data,
                            b"Could only read %ld bytes from the input\0" as *const u8 as *const i8,
                            passed,
                        ) });
                        return CURLE_READ_ERROR;
                    }
                    if !(passed < (unsafe { (*data).state.resume_from })) {
                        break;
                    }
                }
            }
            if (unsafe { (*data).state.infilesize }) > 0 as i32 as i64 {
                let fresh67 = unsafe { &mut ((*data).state.infilesize) };
                *fresh67 -= unsafe { (*data).state.resume_from };
                if (unsafe { (*data).state.infilesize }) <= 0 as i32 as i64 {
                    (unsafe { Curl_failf(
                        data,
                        b"File already completely uploaded\0" as *const u8 as *const i8,
                    ) });
                    return CURLE_PARTIAL_FILE;
                }
            }
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_http_firstwrite(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut done: *mut bool,
) -> CURLcode {
    let mut k: *mut SingleRequest = unsafe { &mut (*data).req };
    if (unsafe { ((*data).req).ignore_cl() }) != 0 {
        let fresh68 = unsafe { &mut ((*k).maxdownload) };
        *fresh68 = -(1 as i32) as curl_off_t;
        (unsafe { (*k).size = *fresh68 });
    } else if (unsafe { (*k).size }) != -(1 as i32) as i64 {
        if (unsafe { (*data).set.max_filesize }) != 0 && (unsafe { (*k).size }) > (unsafe { (*data).set.max_filesize }) {
            (unsafe { Curl_failf(
                data,
                b"Maximum file size exceeded\0" as *const u8 as *const i8,
            ) });
            return CURLE_FILESIZE_EXCEEDED;
        }
        (unsafe { Curl_pgrsSetDownloadSize(data, (*k).size) });
    }
    if !(unsafe { (*data).req.newurl }).is_null() {
        if (unsafe { ((*conn).bits).close() }) != 0 {
            (unsafe { (*k).keepon &= !((1 as i32) << 0 as i32) });
            (unsafe { *done = 1 as i32 != 0 });
            return CURLE_OK;
        }
        (unsafe { (*k).set_ignorebody(1 as i32 as bit) });
        (unsafe { Curl_infof(
            data,
            b"Ignoring the response-body\0" as *const u8 as *const i8,
        ) });
    }
    if (unsafe { (*data).state.resume_from }) != 0
        && (unsafe { (*k).content_range() }) == 0
        && (unsafe { (*data).state.httpreq }) as u32 == HTTPREQ_GET as i32 as u32
        && (unsafe { (*k).ignorebody() }) == 0
    {
        if (unsafe { (*k).size }) == (unsafe { (*data).state.resume_from }) {
            (unsafe { Curl_infof(
                data,
                b"The entire document is already downloaded\0" as *const u8 as *const i8,
            ) });
            (unsafe { Curl_conncontrol(conn, 1 as i32) });
            (unsafe { (*k).keepon &= !((1 as i32) << 0 as i32) });
            (unsafe { *done = 1 as i32 != 0 });
            return CURLE_OK;
        }
        (unsafe { Curl_failf(
            data,
            b"HTTP server doesn't seem to support byte ranges. Cannot resume.\0" as *const u8
                as *const i8,
        ) });
        return CURLE_RANGE_ERROR;
    }
    if (unsafe { (*data).set.timecondition }) as u32 != 0 && (unsafe { (*data).state.range }).is_null() {
        if !(unsafe { Curl_meets_timecondition(data, (*k).timeofdoc) }) {
            (unsafe { *done = 1 as i32 != 0 });
            (unsafe { (*data).info.httpcode = 304 as i32 });
            (unsafe { Curl_infof(
                data,
                b"Simulate a HTTP 304 response!\0" as *const u8 as *const i8,
            ) });
            (unsafe { Curl_conncontrol(conn, 1 as i32) });
            return CURLE_OK;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_transferencode(mut data: *mut Curl_easy) -> CURLcode {
    if (unsafe { Curl_checkheaders(data, b"TE\0" as *const u8 as *const i8) }).is_null()
        && (unsafe { ((*data).set).http_transfer_encoding() }) as i32 != 0
    {
        let mut cptr: *mut i8 = unsafe { Curl_checkheaders(data, b"Connection\0" as *const u8 as *const i8) };
        (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.aptr.te as *mut libc::c_void) });
        let fresh69 = unsafe { &mut ((*data).state.aptr.te) };
        *fresh69 = 0 as *mut i8;
        if !cptr.is_null() {
            cptr = Curl_copy_header_value(cptr);
            if cptr.is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        }
        let fresh70 = unsafe { &mut ((*data).state.aptr.te) };
        *fresh70 = unsafe { curl_maprintf(
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
        ) };
        (unsafe { Curl_cfree.expect("non-null function pointer")(cptr as *mut libc::c_void) });
        if (unsafe { (*data).state.aptr.te }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_http(mut data: *mut Curl_easy, mut done: *mut bool) -> CURLcode {
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    let mut result: CURLcode = CURLE_OK;
    let mut http: *mut HTTP = 0 as *mut HTTP;
    let mut httpreq: Curl_HttpReq = HTTPREQ_GET;
    let mut te: *const i8 = b"\0" as *const u8 as *const i8;
    let mut request: *const i8 = 0 as *const i8;
    let mut httpstring: *const i8 = 0 as *const i8;
    let mut req: dynbuf = dynbuf {
        bufr: 0 as *mut i8,
        leng: 0,
        allc: 0,
        toobig: 0,
    };
    let mut altused: *mut i8 = 0 as *mut i8;
    let mut p_accept: *const i8 = 0 as *const i8;
    (unsafe { *done = 1 as i32 != 0 });
    if (unsafe { (*conn).transport }) as u32 != TRNSPRT_QUIC as i32 as u32 {
        if ((unsafe { (*conn).httpversion }) as i32) < 20 as i32 {
            match unsafe { (*conn).negnpn } {
                3 => {
                    (unsafe { (*conn).httpversion = 20 as i32 as u8 });
                    result = unsafe { Curl_http2_switched(data, 0 as *const i8, 0 as i32 as size_t) };
                    if result as u64 != 0 {
                        return result;
                    }
                }
                2 => {}
                _ => {
                    if (unsafe { (*data).state.httpwant }) as i32 == CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE as i32 {
                        if (unsafe { ((*conn).bits).httpproxy() }) as i32 != 0
                            && (unsafe { ((*conn).bits).tunnel_proxy() }) == 0
                        {
                            (unsafe { Curl_infof(
                                data,
                                b"Ignoring HTTP/2 prior knowledge due to proxy\0" as *const u8
                                    as *const i8,
                            ) });
                        } else {
                            (unsafe { (*conn).httpversion = 20 as i32 as u8 });
                            result = unsafe { Curl_http2_switched(data, 0 as *const i8, 0 as i32 as size_t) };
                            if result as u64 != 0 {
                                return result;
                            }
                        }
                    }
                }
            }
        } else {
            result = unsafe { Curl_http2_setup(data, conn) };
            if result as u64 != 0 {
                return result;
            }
        }
    }
    http = unsafe { (*data).req.p.http };
    result = Curl_http_host(data, conn);
    if result as u64 != 0 {
        return result;
    }
    result = Curl_http_useragent(data);
    if result as u64 != 0 {
        return result;
    }
    Curl_http_method(data, conn, &mut request, &mut httpreq);
    let mut pq: *mut i8 = 0 as *mut i8;
    if !(unsafe { (*data).state.up.query }).is_null() {
        pq = unsafe { curl_maprintf(
            b"%s?%s\0" as *const u8 as *const i8,
            (*data).state.up.path,
            (*data).state.up.query,
        ) };
        if pq.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    result = Curl_http_output_auth(
        data,
        conn,
        request,
        httpreq,
        if !pq.is_null() {
            pq
        } else {
            unsafe { (*data).state.up.path }
        },
        0 as i32 != 0,
    );
    (unsafe { Curl_cfree.expect("non-null function pointer")(pq as *mut libc::c_void) });
    if result as u64 != 0 {
        return result;
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.aptr.ref_0 as *mut libc::c_void) });
    let fresh71 = unsafe { &mut ((*data).state.aptr.ref_0) };
    *fresh71 = 0 as *mut i8;
    if !(unsafe { (*data).state.referer }).is_null()
        && (unsafe { Curl_checkheaders(data, b"Referer\0" as *const u8 as *const i8) }).is_null()
    {
        let fresh72 = unsafe { &mut ((*data).state.aptr.ref_0) };
        *fresh72 = unsafe { curl_maprintf(
            b"Referer: %s\r\n\0" as *const u8 as *const i8,
            (*data).state.referer,
        ) };
        if (unsafe { (*data).state.aptr.ref_0 }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if (unsafe { Curl_checkheaders(data, b"Accept-Encoding\0" as *const u8 as *const i8) }).is_null()
        && !(unsafe { (*data).set.str_0[STRING_ENCODING as i32 as usize] }).is_null()
    {
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            (*data).state.aptr.accept_encoding as *mut libc::c_void,
        ) });
        let fresh73 = unsafe { &mut ((*data).state.aptr.accept_encoding) };
        *fresh73 = 0 as *mut i8;
        let fresh74 = unsafe { &mut ((*data).state.aptr.accept_encoding) };
        *fresh74 = unsafe { curl_maprintf(
            b"Accept-Encoding: %s\r\n\0" as *const u8 as *const i8,
            (*data).set.str_0[STRING_ENCODING as i32 as usize],
        ) };
        if (unsafe { (*data).state.aptr.accept_encoding }).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    } else {
        (unsafe { Curl_cfree.expect("non-null function pointer")(
            (*data).state.aptr.accept_encoding as *mut libc::c_void,
        ) });
        let fresh75 = unsafe { &mut ((*data).state.aptr.accept_encoding) };
        *fresh75 = 0 as *mut i8;
    }
    result = Curl_transferencode(data);
    if result as u64 != 0 {
        return result;
    }
    result = Curl_http_body(data, conn, httpreq, &mut te);
    if result as u64 != 0 {
        return result;
    }
    p_accept = if !(unsafe { Curl_checkheaders(data, b"Accept\0" as *const u8 as *const i8) }).is_null() {
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
    (unsafe { Curl_dyn_init(&mut req, (1024 as i32 * 1024 as i32) as size_t) });
    (unsafe { Curl_dyn_reset(&mut (*data).state.headerb) });
    result = unsafe { Curl_dyn_addf(
        &mut req as *mut dynbuf,
        b"%s \0" as *const u8 as *const i8,
        request,
    ) };
    if result as u64 == 0 {
        result = Curl_http_target(data, conn, &mut req);
    }
    if result as u64 != 0 {
        (unsafe { Curl_dyn_free(&mut req) });
        return result;
    }
    if (unsafe { ((*conn).bits).altused() }) as i32 != 0
        && (unsafe { Curl_checkheaders(data, b"Alt-Used\0" as *const u8 as *const i8) }).is_null()
    {
        altused = unsafe { curl_maprintf(
            b"Alt-Used: %s:%d\r\n\0" as *const u8 as *const i8,
            (*conn).conn_to_host.name,
            (*conn).conn_to_port,
        ) };
        if altused.is_null() {
            (unsafe { Curl_dyn_free(&mut req) });
            return CURLE_OUT_OF_MEMORY;
        }
    }
    result = unsafe { Curl_dyn_addf(
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
        if ((*data).state).use_range() as i32 != 0 && !((*data).state.aptr.rangeline).is_null() {
            (*data).state.aptr.rangeline as *const i8
        } else {
            b"\0" as *const u8 as *const i8
        },
        if !((*data).set.str_0[STRING_USERAGENT as i32 as usize]).is_null()
            && *(*data).set.str_0[STRING_USERAGENT as i32 as usize] as i32 != 0
            && !((*data).state.aptr.uagent).is_null()
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
            && *(*data).set.str_0[STRING_ENCODING as i32 as usize] as i32 != 0
            && !((*data).state.aptr.accept_encoding).is_null()
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
            && (Curl_checkheaders(data, b"Proxy-Connection\0" as *const u8 as *const i8)).is_null()
            && (Curl_checkProxyheaders(data, conn, b"Proxy-Connection\0" as *const u8 as *const i8))
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
    ) };
    (unsafe { Curl_cfree.expect("non-null function pointer")((*data).state.aptr.userpwd as *mut libc::c_void) });
    let fresh76 = unsafe { &mut ((*data).state.aptr.userpwd) };
    *fresh76 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(
        (*data).state.aptr.proxyuserpwd as *mut libc::c_void,
    ) });
    let fresh77 = unsafe { &mut ((*data).state.aptr.proxyuserpwd) };
    *fresh77 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(altused as *mut libc::c_void) });
    if result as u64 != 0 {
        (unsafe { Curl_dyn_free(&mut req) });
        return result;
    }
    if (unsafe { (*(*conn).handler).flags }) & ((1 as i32) << 0 as i32) as u32 == 0
        && (unsafe { (*conn).httpversion }) as i32 != 20 as i32
        && (unsafe { (*data).state.httpwant }) as i32 == CURL_HTTP_VERSION_2_0 as i32
    {
        result = unsafe { Curl_http2_request_upgrade(&mut req, data) };
        if result as u64 != 0 {
            (unsafe { Curl_dyn_free(&mut req) });
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
        let fresh78 = unsafe { &mut ((*http).postdata) };
        *fresh78 = 0 as *const i8;
        if httpreq as u32 == HTTPREQ_GET as i32 as u32
            || httpreq as u32 == HTTPREQ_HEAD as i32 as u32
        {
            (unsafe { Curl_pgrsSetUploadSize(data, 0 as i32 as curl_off_t) });
        }
        result = Curl_http_bodysend(data, conn, &mut req, httpreq);
    }
    if result as u64 != 0 {
        (unsafe { Curl_dyn_free(&mut req) });
        return result;
    }
    if (unsafe { (*http).postsize }) > -(1 as i32) as i64
        && (unsafe { (*http).postsize }) <= (unsafe { (*data).req.writebytecount })
        && (unsafe { (*http).sending }) as u32 != HTTPSEND_REQUEST as i32 as u32
    {
        let fresh79 = unsafe { &mut ((*data).req) };
        (*fresh79).set_upload_done(1 as i32 as bit);
    }
    if (unsafe { (*data).req.writebytecount }) != 0 {
        (unsafe { Curl_pgrsSetUploadCounter(data, (*data).req.writebytecount) });
        if (unsafe { Curl_pgrsUpdate(data) }) != 0 {
            result = CURLE_ABORTED_BY_CALLBACK;
        }
        if (unsafe { (*http).postsize }) == 0 {
            (unsafe { Curl_infof(
                data,
                b"upload completely sent off: %ld out of %ld bytes\0" as *const u8 as *const i8,
                (*data).req.writebytecount,
                (*http).postsize,
            ) });
            let fresh80 = unsafe { &mut ((*data).req) };
            (*fresh80).set_upload_done(1 as i32 as bit);
            (unsafe { (*data).req.keepon &= !((1 as i32) << 1 as i32) });
            (unsafe { (*data).req.exp100 = EXP100_SEND_DATA });
            (unsafe { Curl_expire_done(data, EXPIRE_100_TIMEOUT) });
        }
    }
    if (unsafe { (*conn).httpversion }) as i32 == 20 as i32 && (unsafe { ((*data).req).upload_chunky() }) as i32 != 0 {
        let fresh81 = unsafe { &mut ((*data).req) };
        (*fresh81).set_upload_chunky(0 as i32 as bit);
    }
    return result;
}
extern "C" fn checkprefixmax(
    mut prefix: *const i8,
    mut buffer: *const i8,
    mut len: size_t,
) -> bool {
    let mut ch: size_t = if (unsafe { strlen(prefix) }) < len {
        unsafe { strlen(prefix) }
    } else {
        len
    };
    return (unsafe { curl_strnequal(prefix, buffer, ch) }) != 0;
}
extern "C" fn checkhttpprefix(
    mut data: *mut Curl_easy,
    mut s: *const i8,
    mut len: size_t,
) -> statusline {
    let mut head: *mut curl_slist = unsafe { (*data).set.http200aliases };
    let mut rc: statusline = STATUS_BAD;
    let mut onmatch: statusline = (if len >= 5 as i32 as u64 {
        STATUS_DONE as i32
    } else {
        STATUS_UNKNOWN as i32
    }) as statusline;
    while !head.is_null() {
        if checkprefixmax(unsafe { (*head).data }, s, len) {
            rc = onmatch;
            break;
        } else {
            head = unsafe { (*head).next };
        }
    }
    if rc as u32 != STATUS_DONE as i32 as u32
        && checkprefixmax(b"HTTP/\0" as *const u8 as *const i8, s, len) as i32 != 0
    {
        rc = onmatch;
    }
    return rc;
}
extern "C" fn checkrtspprefix(
    mut _data: *mut Curl_easy,
    mut s: *const i8,
    mut len: size_t,
) -> statusline {
    let mut result: statusline = STATUS_BAD;
    let mut onmatch: statusline = (if len >= 5 as i32 as u64 {
        STATUS_DONE as i32
    } else {
        STATUS_UNKNOWN as i32
    }) as statusline;
    if checkprefixmax(b"RTSP/\0" as *const u8 as *const i8, s, len) {
        result = onmatch;
    }
    return result;
}
extern "C" fn checkprotoprefix(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut s: *const i8,
    mut len: size_t,
) -> statusline {
    if (unsafe { (*(*conn).handler).protocol }) & ((1 as i32) << 18 as i32) as u32 != 0 {
        return checkrtspprefix(data, s, len);
    }
    return checkhttpprefix(data, s, len);
}
#[no_mangle]
pub extern "C" fn Curl_http_header(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut headp: *mut i8,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut k: *mut SingleRequest = unsafe { &mut (*data).req };
    if (unsafe { (*k).http_bodyless() }) == 0
        && (unsafe { ((*data).set).ignorecl() }) == 0
        && (unsafe { curl_strnequal(
            b"Content-Length:\0" as *const u8 as *const i8,
            headp,
            strlen(b"Content-Length:\0" as *const u8 as *const i8),
        ) }) != 0
    {
        let mut contentlength: curl_off_t = 0;
        let mut offt: CURLofft = unsafe { curlx_strtoofft(
            headp.offset(strlen(b"Content-Length:\0" as *const u8 as *const i8) as isize),
            0 as *mut *mut i8,
            10 as i32,
            &mut contentlength,
        ) };
        if offt as u32 == CURL_OFFT_OK as i32 as u32 {
            (unsafe { (*k).size = contentlength });
            (unsafe { (*k).maxdownload = (*k).size });
        } else if offt as u32 == CURL_OFFT_FLOW as i32 as u32 {
            if (unsafe { (*data).set.max_filesize }) != 0 {
                (unsafe { Curl_failf(
                    data,
                    b"Maximum file size exceeded\0" as *const u8 as *const i8,
                ) });
                return CURLE_FILESIZE_EXCEEDED;
            }
            (unsafe { Curl_conncontrol(conn, 2 as i32) });
            (unsafe { Curl_infof(
                data,
                b"Overflow Content-Length: value!\0" as *const u8 as *const i8,
            ) });
        } else {
            (unsafe { Curl_failf(
                data,
                b"Invalid Content-Length: value\0" as *const u8 as *const i8,
            ) });
            return CURLE_WEIRD_SERVER_REPLY;
        }
    } else if (unsafe { curl_strnequal(
        b"Content-Type:\0" as *const u8 as *const i8,
        headp,
        strlen(b"Content-Type:\0" as *const u8 as *const i8),
    ) }) != 0
    {
        let mut contenttype: *mut i8 = Curl_copy_header_value(headp);
        if contenttype.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if (unsafe { *contenttype }) == 0 {
            (unsafe { Curl_cfree.expect("non-null function pointer")(contenttype as *mut libc::c_void) });
        } else {
            (unsafe { Curl_cfree.expect("non-null function pointer")(
                (*data).info.contenttype as *mut libc::c_void,
            ) });
            let fresh82 = unsafe { &mut ((*data).info.contenttype) };
            *fresh82 = 0 as *mut i8;
            let fresh83 = unsafe { &mut ((*data).info.contenttype) };
            *fresh83 = contenttype;
        }
    } else if (unsafe { (*conn).httpversion }) as i32 == 10 as i32
        && (unsafe { ((*conn).bits).httpproxy() }) as i32 != 0
        && Curl_compareheader(
            headp,
            b"Proxy-Connection:\0" as *const u8 as *const i8,
            b"keep-alive\0" as *const u8 as *const i8,
        ) as i32
            != 0
    {
        (unsafe { Curl_conncontrol(conn, 0 as i32) });
        (unsafe { Curl_infof(
            data,
            b"HTTP/1.0 proxy connection set to keep alive!\0" as *const u8 as *const i8,
        ) });
    } else if (unsafe { (*conn).httpversion }) as i32 == 11 as i32
        && (unsafe { ((*conn).bits).httpproxy() }) as i32 != 0
        && Curl_compareheader(
            headp,
            b"Proxy-Connection:\0" as *const u8 as *const i8,
            b"close\0" as *const u8 as *const i8,
        ) as i32
            != 0
    {
        (unsafe { Curl_conncontrol(conn, 1 as i32) });
        (unsafe { Curl_infof(
            data,
            b"HTTP/1.1 proxy connection set close!\0" as *const u8 as *const i8,
        ) });
    } else if (unsafe { (*conn).httpversion }) as i32 == 10 as i32
        && Curl_compareheader(
            headp,
            b"Connection:\0" as *const u8 as *const i8,
            b"keep-alive\0" as *const u8 as *const i8,
        ) as i32
            != 0
    {
        (unsafe { Curl_conncontrol(conn, 0 as i32) });
        (unsafe { Curl_infof(
            data,
            b"HTTP/1.0 connection set to keep alive!\0" as *const u8 as *const i8,
        ) });
    } else if Curl_compareheader(
        headp,
        b"Connection:\0" as *const u8 as *const i8,
        b"close\0" as *const u8 as *const i8,
    ) {
        (unsafe { Curl_conncontrol(conn, 2 as i32) });
    } else if (unsafe { (*k).http_bodyless() }) == 0
        && (unsafe { curl_strnequal(
            b"Transfer-Encoding:\0" as *const u8 as *const i8,
            headp,
            strlen(b"Transfer-Encoding:\0" as *const u8 as *const i8),
        ) }) != 0
    {
        result = unsafe { Curl_build_unencoding_stack(
            data,
            headp.offset(strlen(b"Transfer-Encoding:\0" as *const u8 as *const i8) as isize),
            1 as i32,
        ) };
        if result as u64 != 0 {
            return result;
        }
        if (unsafe { (*k).chunk() }) == 0 {
            (unsafe { Curl_conncontrol(conn, 1 as i32) });
            (unsafe { (*k).set_ignore_cl(1 as i32 as bit) });
        }
    } else if (unsafe { (*k).http_bodyless() }) == 0
        && (unsafe { curl_strnequal(
            b"Content-Encoding:\0" as *const u8 as *const i8,
            headp,
            strlen(b"Content-Encoding:\0" as *const u8 as *const i8),
        ) }) != 0
        && !(unsafe { (*data).set.str_0[STRING_ENCODING as i32 as usize] }).is_null()
    {
        result = unsafe { Curl_build_unencoding_stack(
            data,
            headp.offset(strlen(b"Content-Encoding:\0" as *const u8 as *const i8) as isize),
            0 as i32,
        ) };
        if result as u64 != 0 {
            return result;
        }
    } else if (unsafe { curl_strnequal(
        b"Retry-After:\0" as *const u8 as *const i8,
        headp,
        strlen(b"Retry-After:\0" as *const u8 as *const i8),
    ) }) != 0
    {
        let mut retry_after: curl_off_t = 0 as i32 as curl_off_t;
        let mut date: time_t = unsafe { Curl_getdate_capped(
            headp.offset(strlen(b"Retry-After:\0" as *const u8 as *const i8) as isize),
        ) };
        if -(1 as i32) as i64 == date {
            (unsafe { curlx_strtoofft(
                headp.offset(strlen(b"Retry-After:\0" as *const u8 as *const i8) as isize),
                0 as *mut *mut i8,
                10 as i32,
                &mut retry_after,
            ) });
        } else {
            retry_after = date - (unsafe { time(0 as *mut time_t) });
        }
        (unsafe { (*data).info.retry_after = retry_after });
    } else if (unsafe { (*k).http_bodyless() }) == 0
        && (unsafe { curl_strnequal(
            b"Content-Range:\0" as *const u8 as *const i8,
            headp,
            strlen(b"Content-Range:\0" as *const u8 as *const i8),
        ) }) != 0
    {
        let mut ptr: *mut i8 =
            unsafe { headp.offset(strlen(b"Content-Range:\0" as *const u8 as *const i8) as isize) };
        while (unsafe { *ptr }) as i32 != 0 && (unsafe { Curl_isdigit(*ptr as u8 as i32) }) == 0 && (unsafe { *ptr }) as i32 != '*' as i32
        {
            ptr = unsafe { ptr.offset(1) };
        }
        if (unsafe { Curl_isdigit(*ptr as u8 as i32) }) != 0 {
            if (unsafe { curlx_strtoofft(ptr, 0 as *mut *mut i8, 10 as i32, &mut (*k).offset) }) as u64 == 0 {
                if (unsafe { (*data).state.resume_from }) == (unsafe { (*k).offset }) {
                    (unsafe { (*k).set_content_range(1 as i32 as bit) });
                }
            }
        } else {
            (unsafe { (*data).state.resume_from = 0 as i32 as curl_off_t });
        }
    } else if !(unsafe { (*data).cookies }).is_null()
        && (unsafe { ((*data).state).cookie_engine() }) as i32 != 0
        && (unsafe { curl_strnequal(
            b"Set-Cookie:\0" as *const u8 as *const i8,
            headp,
            strlen(b"Set-Cookie:\0" as *const u8 as *const i8),
        ) }) != 0
    {
        let mut host: *const i8 = if !(unsafe { (*data).state.aptr.cookiehost }).is_null() {
            unsafe { (*data).state.aptr.cookiehost }
        } else {
            unsafe { (*conn).host.name }
        };
        let secure_context: bool = if (unsafe { (*(*conn).handler).protocol }) & ((1 as i32) << 1 as i32) as u32
            != 0
            || (unsafe { Curl_strcasecompare(b"localhost\0" as *const u8 as *const i8, host) }) != 0
            || (unsafe { strcmp(host, b"127.0.0.1\0" as *const u8 as *const i8) }) == 0
            || (unsafe { strcmp(host, b"[::1]\0" as *const u8 as *const i8) }) == 0
        {
            1 as i32
        } else {
            0 as i32
        } != 0;
        (unsafe { Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE) });
        (unsafe { Curl_cookie_add(
            data,
            (*data).cookies,
            1 as i32 != 0,
            0 as i32 != 0,
            headp.offset(strlen(b"Set-Cookie:\0" as *const u8 as *const i8) as isize),
            host,
            (*data).state.up.path,
            secure_context,
        ) });
        (unsafe { Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE) });
    } else if (unsafe { (*k).http_bodyless() }) == 0
        && (unsafe { curl_strnequal(
            b"Last-Modified:\0" as *const u8 as *const i8,
            headp,
            strlen(b"Last-Modified:\0" as *const u8 as *const i8),
        ) }) != 0
        && ((unsafe { (*data).set.timecondition }) as u32 != 0 || (unsafe { ((*data).set).get_filetime() }) as i32 != 0)
    {
        (unsafe { (*k).timeofdoc = Curl_getdate_capped(
            headp.offset(strlen(b"Last-Modified:\0" as *const u8 as *const i8) as isize),
        ) });
        if (unsafe { ((*data).set).get_filetime() }) != 0 {
            (unsafe { (*data).info.filetime = (*k).timeofdoc });
        }
    } else if (unsafe { curl_strnequal(
        b"WWW-Authenticate:\0" as *const u8 as *const i8,
        headp,
        strlen(b"WWW-Authenticate:\0" as *const u8 as *const i8),
    ) }) != 0
        && 401 as i32 == (unsafe { (*k).httpcode })
        || (unsafe { curl_strnequal(
            b"Proxy-authenticate:\0" as *const u8 as *const i8,
            headp,
            strlen(b"Proxy-authenticate:\0" as *const u8 as *const i8),
        ) }) != 0
            && 407 as i32 == (unsafe { (*k).httpcode })
    {
        let mut proxy: bool = if (unsafe { (*k).httpcode }) == 407 as i32 {
            1 as i32
        } else {
            0 as i32
        } != 0;
        let mut auth: *mut i8 = Curl_copy_header_value(headp);
        if auth.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        result = Curl_http_input_auth(data, proxy, auth);
        (unsafe { Curl_cfree.expect("non-null function pointer")(auth as *mut libc::c_void) });
        if result as u64 != 0 {
            return result;
        }
    } else if (unsafe { (*k).httpcode }) >= 300 as i32
        && (unsafe { (*k).httpcode }) < 400 as i32
        && (unsafe { curl_strnequal(
            b"Location:\0" as *const u8 as *const i8,
            headp,
            strlen(b"Location:\0" as *const u8 as *const i8),
        ) }) != 0
        && (unsafe { (*data).req.location }).is_null()
    {
        let mut location: *mut i8 = Curl_copy_header_value(headp);
        if location.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if (unsafe { *location }) == 0 {
            (unsafe { Curl_cfree.expect("non-null function pointer")(location as *mut libc::c_void) });
        } else {
            let fresh84 = unsafe { &mut ((*data).req.location) };
            *fresh84 = location;
            if (unsafe { ((*data).set).http_follow_location() }) != 0 {
                let fresh85 = unsafe { &mut ((*data).req.newurl) };
                *fresh85 = unsafe { Curl_cstrdup.expect("non-null function pointer")((*data).req.location) };
                if (unsafe { (*data).req.newurl }).is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
                result = http_perhapsrewind(data, conn);
                if result as u64 != 0 {
                    return result;
                }
            }
        }
    } else if !(unsafe { (*data).hsts }).is_null()
        && (unsafe { curl_strnequal(
            b"Strict-Transport-Security:\0" as *const u8 as *const i8,
            headp,
            strlen(b"Strict-Transport-Security:\0" as *const u8 as *const i8),
        ) }) != 0
        && (unsafe { (*(*conn).handler).flags }) & ((1 as i32) << 0 as i32) as u32 != 0
    {
        let mut check: CURLcode = unsafe { Curl_hsts_parse(
            (*data).hsts,
            (*data).state.up.hostname,
            headp
                .offset(strlen(b"Strict-Transport-Security:\0" as *const u8 as *const i8) as isize),
        ) };
        if check as u64 != 0 {
            (unsafe { Curl_infof(
                data,
                b"Illegal STS header skipped\0" as *const u8 as *const i8,
            ) });
        }
    } else if !(unsafe { (*data).asi }).is_null()
        && (unsafe { curl_strnequal(
            b"Alt-Svc:\0" as *const u8 as *const i8,
            headp,
            strlen(b"Alt-Svc:\0" as *const u8 as *const i8),
        ) }) != 0
        && ((unsafe { (*(*conn).handler).flags }) & ((1 as i32) << 0 as i32) as u32 != 0 || 0 as i32 != 0)
    {
        let mut id: alpnid = (if (unsafe { (*conn).httpversion }) as i32 == 20 as i32 {
            ALPN_h2 as i32
        } else {
            ALPN_h1 as i32
        }) as alpnid;
        result = unsafe { Curl_altsvc_parse(
            data,
            (*data).asi,
            headp.offset(strlen(b"Alt-Svc:\0" as *const u8 as *const i8) as isize),
            id,
            (*conn).host.name,
            curlx_uitous((*conn).remote_port as u32),
        ) };
        if result as u64 != 0 {
            return result;
        }
    } else if (unsafe { (*(*conn).handler).protocol }) & ((1 as i32) << 18 as i32) as u32 != 0 {
        result = unsafe { Curl_rtsp_parseheader(data, headp) };
        if result as u64 != 0 {
            return result;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_http_statusline(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut k: *mut SingleRequest = unsafe { &mut (*data).req };
    (unsafe { (*data).info.httpcode = (*k).httpcode });
    (unsafe { (*data).info.httpversion = (*conn).httpversion as i32 });
    if (unsafe { (*data).state.httpversion }) == 0
        || (unsafe { (*data).state.httpversion }) as i32 > (unsafe { (*conn).httpversion }) as i32
    {
        (unsafe { (*data).state.httpversion = (*conn).httpversion });
    }
    if (unsafe { (*data).state.resume_from }) != 0
        && (unsafe { (*data).state.httpreq }) as u32 == HTTPREQ_GET as i32 as u32
        && (unsafe { (*k).httpcode }) == 416 as i32
    {
        (unsafe { (*k).set_ignorebody(1 as i32 as bit) });
    }
    if (unsafe { (*conn).httpversion }) as i32 == 10 as i32 {
        (unsafe { Curl_infof(
            data,
            b"HTTP 1.0, assume close after body\0" as *const u8 as *const i8,
        ) });
        (unsafe { Curl_conncontrol(conn, 1 as i32) });
    } else if (unsafe { (*conn).httpversion }) as i32 == 20 as i32
        || (unsafe { (*k).upgr101 }) as u32 == UPGR101_REQUESTED as i32 as u32 && (unsafe { (*k).httpcode }) == 101 as i32
    {
        (unsafe { (*(*conn).bundle).multiuse = 2 as i32 });
    } else {
        let _ = (unsafe { (*conn).httpversion }) as i32 >= 11 as i32 && (unsafe { ((*conn).bits).close() }) == 0;
    }
    (unsafe { (*k).set_http_bodyless(
        ((*k).httpcode >= 100 as i32 && (*k).httpcode < 200 as i32) as i32 as bit,
    ) });
    let mut current_block_25: u64;
    match unsafe { (*k).httpcode } {
        304 => {
            if (unsafe { (*data).set.timecondition }) as u64 != 0 {
                let fresh86 = unsafe { &mut ((*data).info) };
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
            (unsafe { (*k).size = 0 as i32 as curl_off_t });
            (unsafe { (*k).maxdownload = 0 as i32 as curl_off_t });
            (unsafe { (*k).set_http_bodyless(1 as i32 as bit) });
        }
        _ => {}
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn Curl_http_readwrite_headers(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut nread: *mut ssize_t,
    mut stop_reading: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut k: *mut SingleRequest = unsafe { &mut (*data).req };
    let mut onread: ssize_t = unsafe { *nread };
    let mut ostr: *mut i8 = unsafe { (*k).str_0 };
    let mut headp: *mut i8 = 0 as *mut i8;
    let mut str_start: *mut i8 = 0 as *mut i8;
    let mut end_ptr: *mut i8 = 0 as *mut i8;
    loop {
        let mut rest_length: size_t = 0;
        let mut full_length: size_t = 0;
        let mut writetype: i32 = 0;
        str_start = unsafe { (*k).str_0 };
        end_ptr = (unsafe { memchr(str_start as *const libc::c_void, 0xa as i32, *nread as u64) }) as *mut i8;
        if end_ptr.is_null() {
            result = unsafe { Curl_dyn_addn(
                &mut (*data).state.headerb,
                str_start as *const libc::c_void,
                *nread as size_t,
            ) };
            if result as u64 != 0 {
                return result;
            }
            if !((unsafe { (*k).headerline }) == 0) {
                break;
            }
            let mut st: statusline = checkprotoprefix(
                data,
                conn,
                unsafe { Curl_dyn_ptr(&mut (*data).state.headerb) },
                unsafe { Curl_dyn_len(&mut (*data).state.headerb) },
            );
            if !(st as u32 == STATUS_BAD as i32 as u32) {
                break;
            }
            (unsafe { (*k).set_header(0 as i32 as bit) });
            (unsafe { (*k).badheader = HEADER_ALLBAD });
            (unsafe { Curl_conncontrol(conn, 2 as i32) });
            if (unsafe { ((*data).set).http09_allowed() }) == 0 {
                (unsafe { Curl_failf(
                    data,
                    b"Received HTTP/0.9 when not allowed\0" as *const u8 as *const i8,
                ) });
                return CURLE_UNSUPPORTED_PROTOCOL;
            }
            break;
        } else {
            rest_length = ((unsafe { end_ptr.offset_from((*k).str_0) }) as i64 + 1 as i32 as i64) as size_t;
            (unsafe { *nread -= rest_length as ssize_t });
            let fresh87 = unsafe { &mut ((*k).str_0) };
            *fresh87 = unsafe { end_ptr.offset(1 as i32 as isize) };
            full_length = (unsafe { ((*k).str_0).offset_from(str_start) }) as i64 as size_t;
            result = unsafe { Curl_dyn_addn(
                &mut (*data).state.headerb,
                str_start as *const libc::c_void,
                full_length,
            ) };
            if result as u64 != 0 {
                return result;
            }
            if (unsafe { (*k).headerline }) == 0 {
                let mut st_0: statusline = checkprotoprefix(
                    data,
                    conn,
                    unsafe { Curl_dyn_ptr(&mut (*data).state.headerb) },
                    unsafe { Curl_dyn_len(&mut (*data).state.headerb) },
                );
                if st_0 as u32 == STATUS_BAD as i32 as u32 {
                    (unsafe { Curl_conncontrol(conn, 2 as i32) });
                    if (unsafe { ((*data).set).http09_allowed() }) == 0 {
                        (unsafe { Curl_failf(
                            data,
                            b"Received HTTP/0.9 when not allowed\0" as *const u8 as *const i8,
                        ) });
                        return CURLE_UNSUPPORTED_PROTOCOL;
                    }
                    (unsafe { (*k).set_header(0 as i32 as bit) });
                    if (unsafe { *nread }) != 0 {
                        (unsafe { (*k).badheader = HEADER_PARTHEADER });
                    } else {
                        (unsafe { (*k).badheader = HEADER_ALLBAD });
                        (unsafe { *nread = onread });
                        let fresh88 = unsafe { &mut ((*k).str_0) };
                        *fresh88 = ostr;
                        return CURLE_OK;
                    }
                    break;
                }
            }
            headp = unsafe { Curl_dyn_ptr(&mut (*data).state.headerb) };
            if 0xa as i32 == (unsafe { *headp }) as i32 || 0xd as i32 == (unsafe { *headp }) as i32 {
                let mut headerlen: size_t = 0;
                if '\r' as i32 == (unsafe { *headp }) as i32 {
                    headp = unsafe { headp.offset(1) };
                }
                if '\n' as i32 == (unsafe { *headp }) as i32 {
                    headp = unsafe { headp.offset(1) };
                }
                if 100 as i32 <= (unsafe { (*k).httpcode }) && 199 as i32 >= (unsafe { (*k).httpcode }) {
                    match unsafe { (*k).httpcode } {
                        100 => {
                            (unsafe { (*k).set_header(1 as i32 as bit) });
                            (unsafe { (*k).headerline = 0 as i32 });
                            if (unsafe { (*k).exp100 }) as u32 > EXP100_SEND_DATA as i32 as u32 {
                                (unsafe { (*k).exp100 = EXP100_SEND_DATA });
                                (unsafe { (*k).keepon |= (1 as i32) << 1 as i32 });
                                (unsafe { Curl_expire_done(data, EXPIRE_100_TIMEOUT) });
                            }
                        }
                        101 => {
                            if (unsafe { (*k).upgr101 }) as u32 == UPGR101_REQUESTED as i32 as u32 {
                                (unsafe { Curl_infof(data, b"Received 101\0" as *const u8 as *const i8) });
                                (unsafe { (*k).upgr101 = UPGR101_RECEIVED });
                                (unsafe { (*k).set_header(1 as i32 as bit) });
                                (unsafe { (*k).headerline = 0 as i32 });
                                result = unsafe { Curl_http2_switched(data, (*k).str_0, *nread as size_t) };
                                if result as u64 != 0 {
                                    return result;
                                }
                                (unsafe { *nread = 0 as i32 as ssize_t });
                            } else {
                                (unsafe { (*k).set_header(0 as i32 as bit) });
                            }
                        }
                        _ => {
                            (unsafe { (*k).set_header(1 as i32 as bit) });
                            (unsafe { (*k).headerline = 0 as i32 });
                        }
                    }
                } else {
                    (unsafe { (*k).set_header(0 as i32 as bit) });
                    if (unsafe { (*k).size }) == -(1 as i32) as i64
                        && (unsafe { (*k).chunk() }) == 0
                        && (unsafe { ((*conn).bits).close() }) == 0
                        && (unsafe { (*conn).httpversion }) as i32 == 11 as i32
                        && (unsafe { (*(*conn).handler).protocol }) & ((1 as i32) << 18 as i32) as u32 == 0
                        && (unsafe { (*data).state.httpreq }) as u32 != HTTPREQ_HEAD as i32 as u32
                    {
                        (unsafe { Curl_infof(
                            data,
                            b"no chunk, no close, no size. Assume close to signal end\0"
                                as *const u8 as *const i8,
                        ) });
                        (unsafe { Curl_conncontrol(conn, 2 as i32) });
                    }
                }
                if (unsafe { ((*conn).bits).close() }) as i32 != 0
                    && ((unsafe { (*data).req.httpcode }) == 401 as i32
                        && (unsafe { (*conn).http_ntlm_state }) as u32 == NTLMSTATE_TYPE2 as i32 as u32
                        || (unsafe { (*data).req.httpcode }) == 407 as i32
                            && (unsafe { (*conn).proxy_ntlm_state }) as u32 == NTLMSTATE_TYPE2 as i32 as u32)
                {
                    (unsafe { Curl_infof(
                        data,
                        b"Connection closure while negotiating auth (HTTP 1.0?)\0" as *const u8
                            as *const i8,
                    ) });
                    let fresh89 = unsafe { &mut ((*data).state) };
                    (*fresh89).set_authproblem(1 as i32 as bit);
                }
                writetype = (1 as i32) << 1 as i32;
                if (unsafe { ((*data).set).include_header() }) != 0 {
                    writetype |= (1 as i32) << 0 as i32;
                }
                headerlen = unsafe { Curl_dyn_len(&mut (*data).state.headerb) };
                result = unsafe { Curl_client_write(
                    data,
                    writetype,
                    Curl_dyn_ptr(&mut (*data).state.headerb),
                    headerlen,
                ) };
                if result as u64 != 0 {
                    return result;
                }
                let fresh90 = unsafe { &mut ((*data).info.header_size) };
                *fresh90 += headerlen as i64;
                let fresh91 = unsafe { &mut ((*data).req.headerbytecount) };
                *fresh91 += headerlen as i64;
                if http_should_fail(data) {
                    (unsafe { Curl_failf(
                        data,
                        b"The requested URL returned error: %d\0" as *const u8 as *const i8,
                        (*k).httpcode,
                    ) });
                    return CURLE_HTTP_RETURNED_ERROR;
                }
                (unsafe { (*data).req.deductheadercount =
                    if 100 as i32 <= (*k).httpcode && 199 as i32 >= (*k).httpcode {
                        (*data).req.headerbytecount
                    } else {
                        0 as i32 as i64
                    } });
                result = Curl_http_auth_act(data);
                if result as u64 != 0 {
                    return result;
                }
                if (unsafe { (*k).httpcode }) >= 300 as i32 {
                    if (unsafe { ((*conn).bits).authneg() }) == 0
                        && (unsafe { ((*conn).bits).close() }) == 0
                        && (unsafe { ((*conn).bits).rewindaftersend() }) == 0
                    {
                        match (unsafe { (*data).state.httpreq }) as u32 {
                            4 | 1 | 2 | 3 => {
                                (unsafe { Curl_expire_done(data, EXPIRE_100_TIMEOUT) });
                                if (unsafe { (*k).upload_done() }) == 0 {
                                    if (unsafe { (*k).httpcode }) == 417 as i32
                                        && (unsafe { ((*data).state).expect100header() }) as i32 != 0
                                    {
                                        (unsafe { Curl_infof(
                                            data,
                                            b"Got 417 while waiting for a 100\0" as *const u8
                                                as *const i8,
                                        ) });
                                        let fresh92 = unsafe { &mut ((*data).state) };
                                        (*fresh92).set_disableexpect(1 as i32 as bit);
                                        let fresh93 = unsafe { &mut ((*data).req.newurl) };
                                        *fresh93 = unsafe { Curl_cstrdup.expect("non-null function pointer")(
                                            (*data).state.url,
                                        ) };
                                        (unsafe { Curl_done_sending(data, k) });
                                    } else if (unsafe { ((*data).set).http_keep_sending_on_error() }) != 0 {
                                        (unsafe { Curl_infof(
                                            data,
                                            b"HTTP error before end of send, keep sending\0"
                                                as *const u8
                                                as *const i8,
                                        ) });
                                        if (unsafe { (*k).exp100 }) as u32 > EXP100_SEND_DATA as i32 as u32 {
                                            (unsafe { (*k).exp100 = EXP100_SEND_DATA });
                                            (unsafe { (*k).keepon |= (1 as i32) << 1 as i32 });
                                        }
                                    } else {
                                        (unsafe { Curl_infof(
                                            data,
                                            b"HTTP error before end of send, stop sending\0"
                                                as *const u8
                                                as *const i8,
                                        ) });
                                        (unsafe { Curl_conncontrol(conn, 2 as i32) });
                                        result = unsafe { Curl_done_sending(data, k) };
                                        if result as u64 != 0 {
                                            return result;
                                        }
                                        (unsafe { (*k).set_upload_done(1 as i32 as bit) });
                                        if (unsafe { ((*data).state).expect100header() }) != 0 {
                                            (unsafe { (*k).exp100 = EXP100_FAILED });
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    if (unsafe { ((*conn).bits).rewindaftersend() }) != 0 {
                        (unsafe { Curl_infof(
                            data,
                            b"Keep sending data to get tossed away!\0" as *const u8 as *const i8,
                        ) });
                        (unsafe { (*k).keepon |= (1 as i32) << 1 as i32 });
                    }
                }
                if (unsafe { (*k).header() }) == 0 {
                    if (unsafe { ((*data).set).opt_no_body() }) != 0 {
                        (unsafe { *stop_reading = 1 as i32 != 0 });
                    } else if (unsafe { (*(*conn).handler).protocol }) & ((1 as i32) << 18 as i32) as u32 != 0
                        && (unsafe { (*data).set.rtspreq }) as u32 == RTSPREQ_DESCRIBE as i32 as u32
                        && (unsafe { (*k).size }) <= -(1 as i32) as i64
                    {
                        (unsafe { *stop_reading = 1 as i32 != 0 });
                    } else if (unsafe { (*k).chunk() }) != 0 {
                        let fresh94 = unsafe { &mut ((*k).size) };
                        *fresh94 = -(1 as i32) as curl_off_t;
                        (unsafe { (*k).maxdownload = *fresh94 });
                    }
                    if -(1 as i32) as i64 != (unsafe { (*k).size }) {
                        (unsafe { Curl_pgrsSetDownloadSize(data, (*k).size) });
                        (unsafe { (*k).maxdownload = (*k).size });
                    }
                    if 0 as i32 as i64 == (unsafe { (*k).maxdownload })
                        && !((unsafe { (*(*conn).handler).protocol })
                            & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32
                            != 0
                            && (unsafe { (*conn).httpversion }) as i32 == 20 as i32)
                    {
                        (unsafe { *stop_reading = 1 as i32 != 0 });
                    }
                    if unsafe { *stop_reading } {
                        (unsafe { (*k).keepon &= !((1 as i32) << 0 as i32) });
                    }
                    (unsafe { Curl_debug(data, CURLINFO_HEADER_IN, str_start, headerlen) });
                    break;
                } else {
                    (unsafe { Curl_dyn_reset(&mut (*data).state.headerb) });
                }
            } else {
                let fresh95 = unsafe { &mut ((*k).headerline) };
                let fresh96 = *fresh95;
                *fresh95 = *fresh95 + 1;
                if fresh96 == 0 {
                    let mut httpversion_major: i32 = 0;
                    let mut rtspversion_major: i32 = 0;
                    let mut nc: i32 = 0 as i32;
                    if (unsafe { (*(*conn).handler).protocol })
                        & ((1 as i32) << 0 as i32 | (1 as i32) << 1 as i32) as u32
                        != 0
                    {
                        let mut separator: i8 = 0;
                        let mut twoorthree: [i8; 2] = [0; 2];
                        let mut httpversion: i32 = 0 as i32;
                        let mut digit4: i8 = 0 as i32 as i8;
                        nc = unsafe { sscanf(
                            headp,
                            b" HTTP/%1d.%1d%c%3d%c\0" as *const u8 as *const i8,
                            &mut httpversion_major as *mut i32,
                            &mut httpversion as *mut i32,
                            &mut separator as *mut i8,
                            &mut (*k).httpcode as *mut i32,
                            &mut digit4 as *mut i8,
                        ) };
                        if nc == 1 as i32
                            && httpversion_major >= 2 as i32
                            && 2 as i32
                                == (unsafe { sscanf(
                                    headp,
                                    b" HTTP/%1[23] %d\0" as *const u8 as *const i8,
                                    twoorthree.as_mut_ptr(),
                                    &mut (*k).httpcode as *mut i32,
                                ) })
                        {
                            (unsafe { (*conn).httpversion = 0 as i32 as u8 });
                            nc = 4 as i32;
                            separator = ' ' as i32 as i8;
                        } else if (unsafe { Curl_isdigit(digit4 as u8 as i32) }) != 0 {
                            (unsafe { Curl_failf(
                                data,
                                b"Unsupported response code in HTTP response\0" as *const u8
                                    as *const i8,
                            ) });
                            return CURLE_UNSUPPORTED_PROTOCOL;
                        }
                        if nc >= 4 as i32 && ' ' as i32 == separator as i32 {
                            httpversion += 10 as i32 * httpversion_major;
                            match httpversion {
                                10 | 11 | 20 => {
                                    (unsafe { (*conn).httpversion = httpversion as u8 });
                                }
                                _ => {
                                    (unsafe { Curl_failf(
                                        data,
                                        b"Unsupported HTTP version (%u.%d) in response\0"
                                            as *const u8
                                            as *const i8,
                                        httpversion / 10 as i32,
                                        httpversion % 10 as i32,
                                    ) });
                                    return CURLE_UNSUPPORTED_PROTOCOL;
                                }
                            }
                            if (unsafe { (*k).upgr101 }) as u32 == UPGR101_RECEIVED as i32 as u32 {
                                if (unsafe { (*conn).httpversion }) as i32 != 20 as i32 {
                                    (unsafe { Curl_infof(
                                        data,
                                        b"Lying server, not serving HTTP/2\0" as *const u8
                                            as *const i8,
                                    ) });
                                }
                            }
                            if ((unsafe { (*conn).httpversion }) as i32) < 20 as i32 {
                                (unsafe { (*(*conn).bundle).multiuse = -(1 as i32) });
                                (unsafe { Curl_infof(
                                    data,
                                    b"Mark bundle as not supporting multiuse\0" as *const u8
                                        as *const i8,
                                ) });
                            }
                        } else if nc == 0 {
                            nc = unsafe { sscanf(
                                headp,
                                b" HTTP %3d\0" as *const u8 as *const i8,
                                &mut (*k).httpcode as *mut i32,
                            ) };
                            (unsafe { (*conn).httpversion = 10 as i32 as u8 });
                            if nc == 0 {
                                let mut check: statusline = checkhttpprefix(
                                    data,
                                    unsafe { Curl_dyn_ptr(&mut (*data).state.headerb) },
                                    unsafe { Curl_dyn_len(&mut (*data).state.headerb) },
                                );
                                if check as u32 == STATUS_DONE as i32 as u32 {
                                    nc = 1 as i32;
                                    (unsafe { (*k).httpcode = 200 as i32 });
                                    (unsafe { (*conn).httpversion = 10 as i32 as u8 });
                                }
                            }
                        } else {
                            (unsafe { Curl_failf(
                                data,
                                b"Unsupported HTTP version in response\0" as *const u8 as *const i8,
                            ) });
                            return CURLE_UNSUPPORTED_PROTOCOL;
                        }
                    } else if (unsafe { (*(*conn).handler).protocol }) & ((1 as i32) << 18 as i32) as u32 != 0 {
                        let mut separator_0: i8 = 0;
                        let mut rtspversion: i32 = 0;
                        nc = unsafe { sscanf(
                            headp,
                            b" RTSP/%1d.%1d%c%3d\0" as *const u8 as *const i8,
                            &mut rtspversion_major as *mut i32,
                            &mut rtspversion as *mut i32,
                            &mut separator_0 as *mut i8,
                            &mut (*k).httpcode as *mut i32,
                        ) };
                        if nc == 4 as i32 && ' ' as i32 == separator_0 as i32 {
                            (unsafe { (*conn).httpversion = 11 as i32 as u8 });
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
                        (unsafe { (*k).set_header(0 as i32 as bit) });
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
                if (unsafe { ((*data).set).include_header() }) != 0 {
                    writetype |= (1 as i32) << 0 as i32;
                }
                (unsafe { Curl_debug(
                    data,
                    CURLINFO_HEADER_IN,
                    headp,
                    Curl_dyn_len(&mut (*data).state.headerb),
                ) });
                result = unsafe { Curl_client_write(
                    data,
                    writetype,
                    headp,
                    Curl_dyn_len(&mut (*data).state.headerb),
                ) };
                if result as u64 != 0 {
                    return result;
                }
                let fresh97 = unsafe { &mut ((*data).info.header_size) };
                *fresh97 = (*fresh97 as u64).wrapping_add(unsafe { Curl_dyn_len(&mut (*data).state.headerb) })
                    as curl_off_t as curl_off_t;
                let fresh98 = unsafe { &mut ((*data).req.headerbytecount) };
                *fresh98 = (*fresh98 as u64).wrapping_add(unsafe { Curl_dyn_len(&mut (*data).state.headerb) })
                    as curl_off_t as curl_off_t;
                (unsafe { Curl_dyn_reset(&mut (*data).state.headerb) });
            }
            if !((unsafe { *(*k).str_0 }) != 0) {
                break;
            }
        }
    }
    return CURLE_OK;
}
