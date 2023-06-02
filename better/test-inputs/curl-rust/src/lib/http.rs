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
    pub type psl_ctx_st;
    pub type curl_pushheaders;
    pub type ldapconninfo;
    pub type tftp_state_data;
    pub type nghttp2_session;
    pub type Gsasl_session;
    pub type Gsasl;
    pub type ssl_backend_data;
    fn curl_strnequal(
        s1: *const libc::c_char,
        s2: *const libc::c_char,
        n: size_t,
    ) -> libc::c_int;
    fn curl_mime_headers(
        part: *mut curl_mimepart,
        headers: *mut curl_slist,
        take_ownership: libc::c_int,
    ) -> CURLcode;
    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn time(__timer: *mut time_t) -> time_t;
    fn Curl_isdigit(c: libc::c_int) -> libc::c_int;
    fn Curl_isspace(c: libc::c_int) -> libc::c_int;
    fn curl_url_cleanup(handle: *mut CURLU);
    fn curl_url_dup(in_0: *mut CURLU) -> *mut CURLU;
    fn curl_url_get(
        handle: *mut CURLU,
        what: CURLUPart,
        part: *mut *mut libc::c_char,
        flags: libc::c_uint,
    ) -> CURLUcode;
    fn curl_url_set(
        handle: *mut CURLU,
        what: CURLUPart,
        part: *const libc::c_char,
        flags: libc::c_uint,
    ) -> CURLUcode;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memmove(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memchr(
        _: *const libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strstr(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn Curl_dyn_init(s: *mut dynbuf, toobig: size_t);
    fn Curl_dyn_free(s: *mut dynbuf);
    fn Curl_dyn_addn(s: *mut dynbuf, mem: *const libc::c_void, len: size_t) -> CURLcode;
    fn Curl_dyn_add(s: *mut dynbuf, str: *const libc::c_char) -> CURLcode;
    fn Curl_dyn_addf(s: *mut dynbuf, fmt: *const libc::c_char, _: ...) -> CURLcode;
    fn Curl_dyn_reset(s: *mut dynbuf);
    fn Curl_dyn_ptr(s: *const dynbuf) -> *mut libc::c_char;
    fn Curl_dyn_len(s: *const dynbuf) -> size_t;
    fn Curl_mime_initpart(part: *mut curl_mimepart, easy: *mut Curl_easy);
    fn Curl_mime_cleanpart(part: *mut curl_mimepart);
    fn Curl_mime_prepare_headers(
        part: *mut curl_mimepart,
        contenttype: *const libc::c_char,
        disposition: *const libc::c_char,
        strategy: mimestrategy,
    ) -> CURLcode;
    fn Curl_mime_size(part: *mut curl_mimepart) -> curl_off_t;
    fn Curl_mime_read(
        buffer: *mut libc::c_char,
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
        host: *const libc::c_char,
        path: *const libc::c_char,
        secure: bool,
    ) -> *mut Cookie;
    fn Curl_cookie_add(
        data: *mut Curl_easy,
        c: *mut CookieInfo,
        header: bool,
        noexpiry: bool,
        lineptr: *mut libc::c_char,
        domain: *const libc::c_char,
        path: *const libc::c_char,
        secure: bool,
    ) -> *mut Cookie;
    fn Curl_rtsp_parseheader(
        data: *mut Curl_easy,
        header: *mut libc::c_char,
    ) -> CURLcode;
    fn Curl_checkheaders(
        data: *const Curl_easy,
        thisheader: *const libc::c_char,
    ) -> *mut libc::c_char;
    fn Curl_readrewind(data: *mut Curl_easy) -> CURLcode;
    fn Curl_meets_timecondition(data: *mut Curl_easy, timeofdoc: time_t) -> bool;
    fn Curl_get_upload_buffer(data: *mut Curl_easy) -> CURLcode;
    fn Curl_done_sending(data: *mut Curl_easy, k: *mut SingleRequest) -> CURLcode;
    fn Curl_setup_transfer(
        data: *mut Curl_easy,
        sockindex: libc::c_int,
        size: curl_off_t,
        getheader: bool,
        writesockindex: libc::c_int,
    );
    fn Curl_infof(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
    fn Curl_failf(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
    fn Curl_client_write(
        data: *mut Curl_easy,
        type_0: libc::c_int,
        ptr: *mut libc::c_char,
        len: size_t,
    ) -> CURLcode;
    fn Curl_write(
        data: *mut Curl_easy,
        sockfd: curl_socket_t,
        mem: *const libc::c_void,
        len: size_t,
        written: *mut ssize_t,
    ) -> CURLcode;
    fn Curl_debug(
        data: *mut Curl_easy,
        type_0: curl_infotype,
        ptr: *mut libc::c_char,
        size: size_t,
    ) -> libc::c_int;
    fn Curl_pgrsSetDownloadSize(data: *mut Curl_easy, size: curl_off_t);
    fn Curl_pgrsSetUploadSize(data: *mut Curl_easy, size: curl_off_t);
    fn Curl_pgrsSetUploadCounter(data: *mut Curl_easy, size: curl_off_t);
    fn Curl_pgrsUpdate(data: *mut Curl_easy) -> libc::c_int;
    fn Curl_base64_encode(
        data: *mut Curl_easy,
        inputbuff: *const libc::c_char,
        insize: size_t,
        outptr: *mut *mut libc::c_char,
        outlen: *mut size_t,
    ) -> CURLcode;
    fn Curl_auth_is_digest_supported() -> bool;
    fn Curl_auth_is_ntlm_supported() -> bool;
    static mut Curl_ssl: *const Curl_ssl;
    fn Curl_ssl_connect_nonblocking(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        isproxy: bool,
        sockindex: libc::c_int,
        done: *mut bool,
    ) -> CURLcode;
    fn Curl_input_digest(
        data: *mut Curl_easy,
        proxy: bool,
        header: *const libc::c_char,
    ) -> CURLcode;
    fn Curl_output_digest(
        data: *mut Curl_easy,
        proxy: bool,
        request: *const libc::c_uchar,
        uripath: *const libc::c_uchar,
    ) -> CURLcode;
    fn Curl_input_ntlm(
        data: *mut Curl_easy,
        proxy: bool,
        header: *const libc::c_char,
    ) -> CURLcode;
    fn Curl_output_ntlm(data: *mut Curl_easy, proxy: bool) -> CURLcode;
    fn Curl_input_ntlm_wb(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        proxy: bool,
        header: *const libc::c_char,
    ) -> CURLcode;
    fn Curl_output_ntlm_wb(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        proxy: bool,
    ) -> CURLcode;
    fn Curl_output_aws_sigv4(data: *mut Curl_easy, proxy: bool) -> CURLcode;
    fn Curl_share_lock(
        _: *mut Curl_easy,
        _: curl_lock_data,
        _: curl_lock_access,
    ) -> CURLSHcode;
    fn Curl_share_unlock(_: *mut Curl_easy, _: curl_lock_data) -> CURLSHcode;
    static Curl_wkday: [*const libc::c_char; 7];
    static Curl_month: [*const libc::c_char; 12];
    fn Curl_gmtime(intime: time_t, store: *mut tm) -> CURLcode;
    fn Curl_getdate_capped(p: *const libc::c_char) -> time_t;
    fn curlx_strtoofft(
        str: *const libc::c_char,
        endp: *mut *mut libc::c_char,
        base: libc::c_int,
        num: *mut curl_off_t,
    ) -> CURLofft;
    fn Curl_expire_done(data: *mut Curl_easy, id: expire_id);
    fn Curl_set_in_callback(data: *mut Curl_easy, value: bool);
    fn Curl_strcasecompare(
        first: *const libc::c_char,
        second: *const libc::c_char,
    ) -> libc::c_int;
    fn Curl_strncasecompare(
        first: *const libc::c_char,
        second: *const libc::c_char,
        max: size_t,
    ) -> libc::c_int;
    fn Curl_raw_toupper(in_0: libc::c_char) -> libc::c_char;
    fn Curl_build_unencoding_stack(
        data: *mut Curl_easy,
        enclist: *const libc::c_char,
        maybechunked: libc::c_int,
    ) -> CURLcode;
    fn Curl_unencode_cleanup(data: *mut Curl_easy);
    fn Curl_proxy_connect(data: *mut Curl_easy, sockindex: libc::c_int) -> CURLcode;
    fn Curl_connect_ongoing(conn: *mut connectdata) -> bool;
    fn curlx_sotouz(sonum: curl_off_t) -> size_t;
    fn curlx_uitous(uinum: libc::c_uint) -> libc::c_ushort;
    fn Curl_http2_request_upgrade(req: *mut dynbuf, data: *mut Curl_easy) -> CURLcode;
    fn Curl_http2_setup(data: *mut Curl_easy, conn: *mut connectdata) -> CURLcode;
    fn Curl_http2_switched(
        data: *mut Curl_easy,
        ptr: *const libc::c_char,
        nread: size_t,
    ) -> CURLcode;
    fn Curl_http2_setup_conn(conn: *mut connectdata);
    fn Curl_http2_setup_req(data: *mut Curl_easy);
    fn Curl_http2_done(data: *mut Curl_easy, premature: bool);
    fn Curl_conncontrol(conn: *mut connectdata, closeit: libc::c_int);
    fn Curl_altsvc_parse(
        data: *mut Curl_easy,
        altsvc: *mut altsvcinfo,
        value: *const libc::c_char,
        srcalpn: alpnid,
        srchost: *const libc::c_char,
        srcport: libc::c_ushort,
    ) -> CURLcode;
    fn Curl_hsts_parse(
        h: *mut hsts,
        hostname: *const libc::c_char,
        sts: *const libc::c_char,
    ) -> CURLcode;
    fn curl_msnprintf(
        buffer: *mut libc::c_char,
        maxlength: size_t,
        format: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn curl_maprintf(format: *const libc::c_char, _: ...) -> *mut libc::c_char;
    static mut Curl_cmalloc: curl_malloc_callback;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_cstrdup: curl_strdup_callback;
    static mut Curl_ccalloc: curl_calloc_callback;
}
pub type __uint8_t = libc::c_uchar;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __time_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type pid_t = __pid_t;
pub type ssize_t = __ssize_t;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type int32_t = __int32_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tm {
    pub tm_sec: libc::c_int,
    pub tm_min: libc::c_int,
    pub tm_hour: libc::c_int,
    pub tm_mday: libc::c_int,
    pub tm_mon: libc::c_int,
    pub tm_year: libc::c_int,
    pub tm_wday: libc::c_int,
    pub tm_yday: libc::c_int,
    pub tm_isdst: libc::c_int,
    pub tm_gmtoff: libc::c_long,
    pub tm_zone: *const libc::c_char,
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
    pub name: *const libc::c_char,
    pub alias: *const libc::c_char,
    pub init_writer: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer) -> CURLcode,
    >,
    pub unencode_write: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut contenc_writer,
            *const libc::c_char,
            size_t,
        ) -> CURLcode,
    >,
    pub close_writer: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut contenc_writer) -> (),
    >,
    pub paramsize: size_t,
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
    pub transport: C2RustUnnamed_6,
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
    pub proto: C2RustUnnamed_5,
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
pub type C2RustUnnamed_4 = libc::c_uint;
pub const TUNNEL_EXIT: C2RustUnnamed_4 = 3;
pub const TUNNEL_COMPLETE: C2RustUnnamed_4 = 2;
pub const TUNNEL_CONNECT: C2RustUnnamed_4 = 1;
pub const TUNNEL_INIT: C2RustUnnamed_4 = 0;
pub type keeponval = libc::c_uint;
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
pub type C2RustUnnamed_6 = libc::c_uint;
pub const TRNSPRT_QUIC: C2RustUnnamed_6 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_6 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_6 = 3;
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
pub type curl_strdup_callback = Option::<
    unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
>;
pub type curl_calloc_callback = Option::<
    unsafe extern "C" fn(size_t, size_t) -> *mut libc::c_void,
>;
pub type C2RustUnnamed_7 = libc::c_uint;
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
    pub name: *const libc::c_char,
}
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
pub type CURLSHcode = libc::c_uint;
pub const CURLSHE_LAST: CURLSHcode = 6;
pub const CURLSHE_NOT_BUILT_IN: CURLSHcode = 5;
pub const CURLSHE_NOMEM: CURLSHcode = 4;
pub const CURLSHE_INVALID: CURLSHcode = 3;
pub const CURLSHE_IN_USE: CURLSHcode = 2;
pub const CURLSHE_BAD_OPTION: CURLSHcode = 1;
pub const CURLSHE_OK: CURLSHcode = 0;
pub type CURLUcode = libc::c_uint;
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
pub type CURLUPart = libc::c_uint;
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
pub type mimestrategy = libc::c_uint;
pub const MIMESTRATEGY_LAST: mimestrategy = 2;
pub const MIMESTRATEGY_FORM: mimestrategy = 1;
pub const MIMESTRATEGY_MAIL: mimestrategy = 0;
pub const HEADER_CONNECT: proxy_use = 2;
pub const HEADER_PROXY: proxy_use = 1;
pub const HEADER_SERVER: proxy_use = 0;
pub type proxy_use = libc::c_uint;
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
    pub supports: libc::c_uint,
    pub sizeof_ssl_backend_data: size_t,
    pub init: Option::<unsafe extern "C" fn() -> libc::c_int>,
    pub cleanup: Option::<unsafe extern "C" fn() -> ()>,
    pub version: Option::<unsafe extern "C" fn(*mut libc::c_char, size_t) -> size_t>,
    pub check_cxn: Option::<unsafe extern "C" fn(*mut connectdata) -> libc::c_int>,
    pub shut_down: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub data_pending: Option::<
        unsafe extern "C" fn(*const connectdata, libc::c_int) -> bool,
    >,
    pub random: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut libc::c_uchar, size_t) -> CURLcode,
    >,
    pub cert_status_request: Option::<unsafe extern "C" fn() -> bool>,
    pub connect_blocking: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, libc::c_int) -> CURLcode,
    >,
    pub connect_nonblocking: Option::<
        unsafe extern "C" fn(
            *mut Curl_easy,
            *mut connectdata,
            libc::c_int,
            *mut bool,
        ) -> CURLcode,
    >,
    pub getsock: Option::<
        unsafe extern "C" fn(*mut connectdata, *mut curl_socket_t) -> libc::c_int,
    >,
    pub get_internals: Option::<
        unsafe extern "C" fn(*mut ssl_connect_data, CURLINFO) -> *mut libc::c_void,
    >,
    pub close_one: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, libc::c_int) -> (),
    >,
    pub close_all: Option::<unsafe extern "C" fn(*mut Curl_easy) -> ()>,
    pub session_free: Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    pub set_engine: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *const libc::c_char) -> CURLcode,
    >,
    pub set_engine_default: Option::<unsafe extern "C" fn(*mut Curl_easy) -> CURLcode>,
    pub engines_list: Option::<unsafe extern "C" fn(*mut Curl_easy) -> *mut curl_slist>,
    pub false_start: Option::<unsafe extern "C" fn() -> bool>,
    pub sha256sum: Option::<
        unsafe extern "C" fn(
            *const libc::c_uchar,
            size_t,
            *mut libc::c_uchar,
            size_t,
        ) -> CURLcode,
    >,
    pub associate_connection: Option::<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, libc::c_int) -> (),
    >,
    pub disassociate_connection: Option::<
        unsafe extern "C" fn(*mut Curl_easy, libc::c_int) -> (),
    >,
}
pub type alpnid = libc::c_uint;
pub const ALPN_h3: alpnid = 32;
pub const ALPN_h2: alpnid = 16;
pub const ALPN_h1: alpnid = 8;
pub const ALPN_none: alpnid = 0;
pub type CURLofft = libc::c_uint;
pub const CURL_OFFT_INVAL: CURLofft = 2;
pub const CURL_OFFT_FLOW: CURLofft = 1;
pub const CURL_OFFT_OK: CURLofft = 0;
pub const STATUS_DONE: statusline = 1;
pub type statusline = libc::c_uint;
pub const STATUS_BAD: statusline = 2;
pub const STATUS_UNKNOWN: statusline = 0;
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
pub static mut Curl_handler_http: Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"HTTP\0" as *const u8 as *const libc::c_char,
            setup_connection: Some(
                http_setup_conn
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
            ),
            do_it: Some(
                Curl_http as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            done: Some(
                Curl_http_done
                    as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
            ),
            do_more: None,
            connect_it: Some(
                Curl_http_connect
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
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
                    ) -> libc::c_int,
            ),
            domore_getsock: None,
            perform_getsock: None,
            disconnect: None,
            readwrite: None,
            connection_check: None,
            attach: None,
            defport: 80 as libc::c_int,
            protocol: ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint,
            family: ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint,
            flags: ((1 as libc::c_int) << 7 as libc::c_int
                | (1 as libc::c_int) << 13 as libc::c_int) as libc::c_uint,
        };
        init
    }
};
#[no_mangle]
pub static mut Curl_handler_https: Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"HTTPS\0" as *const u8 as *const libc::c_char,
            setup_connection: Some(
                http_setup_conn
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
            ),
            do_it: Some(
                Curl_http as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            done: Some(
                Curl_http_done
                    as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
            ),
            do_more: None,
            connect_it: Some(
                Curl_http_connect
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            connecting: Some(
                https_connecting
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            doing: None,
            proto_getsock: Some(
                https_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> libc::c_int,
            ),
            doing_getsock: Some(
                http_getsock_do
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> libc::c_int,
            ),
            domore_getsock: None,
            perform_getsock: None,
            disconnect: None,
            readwrite: None,
            connection_check: None,
            attach: None,
            defport: 443 as libc::c_int,
            protocol: ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint,
            family: ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint,
            flags: ((1 as libc::c_int) << 0 as libc::c_int
                | (1 as libc::c_int) << 7 as libc::c_int
                | (1 as libc::c_int) << 8 as libc::c_int
                | (1 as libc::c_int) << 13 as libc::c_int) as libc::c_uint,
        };
        init
    }
};
unsafe extern "C" fn http_setup_conn(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut http: *mut HTTP = 0 as *mut HTTP;
    http = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(1 as libc::c_int as size_t, ::std::mem::size_of::<HTTP>() as libc::c_ulong)
        as *mut HTTP;
    if http.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    Curl_mime_initpart(&mut (*http).form, data);
    let ref mut fresh0 = (*data).req.p.http;
    *fresh0 = http;
    if (*data).state.httpwant as libc::c_int == CURL_HTTP_VERSION_3 as libc::c_int {
        if (*(*conn).handler).flags
            & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0
        {
            (*conn).transport = TRNSPRT_QUIC;
        } else {
            Curl_failf(
                data,
                b"HTTP/3 requested for non-HTTPS URL\0" as *const u8
                    as *const libc::c_char,
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
    mut data: *mut Curl_easy,
    mut conn: *const connectdata,
    mut thisheader: *const libc::c_char,
) -> *mut libc::c_char {
    let mut head: *mut curl_slist = 0 as *mut curl_slist;
    let mut thislen: size_t = strlen(thisheader);
    head = if ((*conn).bits).proxy() as libc::c_int != 0
        && ((*data).set).sep_headers() as libc::c_int != 0
    {
        (*data).set.proxyheaders
    } else {
        (*data).set.headers
    };
    while !head.is_null() {
        if Curl_strncasecompare((*head).data, thisheader, thislen) != 0
            && (*((*head).data).offset(thislen as isize) as libc::c_int == ':' as i32
                || *((*head).data).offset(thislen as isize) as libc::c_int == ';' as i32)
        {
            return (*head).data;
        }
        head = (*head).next;
    }
    return 0 as *mut libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_copy_header_value(
    mut header: *const libc::c_char,
) -> *mut libc::c_char {
    let mut start: *const libc::c_char = 0 as *const libc::c_char;
    let mut end: *const libc::c_char = 0 as *const libc::c_char;
    let mut value: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: size_t = 0;
    while *header as libc::c_int != 0 && *header as libc::c_int != ':' as i32 {
        header = header.offset(1);
    }
    if *header != 0 {
        header = header.offset(1);
    }
    start = header;
    while *start as libc::c_int != 0
        && Curl_isspace(*start as libc::c_uchar as libc::c_int) != 0
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
        return 0 as *mut libc::c_char;
    }
    while end > start && Curl_isspace(*end as libc::c_uchar as libc::c_int) != 0 {
        end = end.offset(-1);
    }
    len = (end.offset_from(start) as libc::c_long + 1 as libc::c_int as libc::c_long)
        as size_t;
    value = Curl_cmalloc
        .expect(
            "non-null function pointer",
        )(len.wrapping_add(1 as libc::c_int as libc::c_ulong)) as *mut libc::c_char;
    if value.is_null() {
        return 0 as *mut libc::c_char;
    }
    memcpy(value as *mut libc::c_void, start as *const libc::c_void, len);
    *value.offset(len as isize) = 0 as libc::c_int as libc::c_char;
    return value;
}
unsafe extern "C" fn http_output_basic(
    mut data: *mut Curl_easy,
    mut proxy: bool,
) -> CURLcode {
    let mut size: size_t = 0 as libc::c_int as size_t;
    let mut authorization: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut userp: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut user: *const libc::c_char = 0 as *const libc::c_char;
    let mut pwd: *const libc::c_char = 0 as *const libc::c_char;
    let mut result: CURLcode = CURLE_OK;
    let mut out: *mut libc::c_char = 0 as *mut libc::c_char;
    if proxy {
        userp = &mut (*data).state.aptr.proxyuserpwd;
        user = (*data).state.aptr.proxyuser;
        pwd = (*data).state.aptr.proxypasswd;
    } else {
        userp = &mut (*data).state.aptr.userpwd;
        user = (*data).state.aptr.user;
        pwd = (*data).state.aptr.passwd;
    }
    out = curl_maprintf(
        b"%s:%s\0" as *const u8 as *const libc::c_char,
        user,
        if !pwd.is_null() { pwd } else { b"\0" as *const u8 as *const libc::c_char },
    );
    if out.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    result = Curl_base64_encode(data, out, strlen(out), &mut authorization, &mut size);
    if !(result as u64 != 0) {
        if authorization.is_null() {
            result = CURLE_REMOTE_ACCESS_DENIED;
        } else {
            Curl_cfree.expect("non-null function pointer")(*userp as *mut libc::c_void);
            *userp = curl_maprintf(
                b"%sAuthorization: Basic %s\r\n\0" as *const u8 as *const libc::c_char,
                if proxy as libc::c_int != 0 {
                    b"Proxy-\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                authorization,
            );
            Curl_cfree
                .expect("non-null function pointer")(authorization as *mut libc::c_void);
            if (*userp).is_null() {
                result = CURLE_OUT_OF_MEMORY;
            }
        }
    }
    Curl_cfree.expect("non-null function pointer")(out as *mut libc::c_void);
    return result;
}
unsafe extern "C" fn http_output_bearer(mut data: *mut Curl_easy) -> CURLcode {
    let mut userp: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut result: CURLcode = CURLE_OK;
    userp = &mut (*data).state.aptr.userpwd;
    Curl_cfree.expect("non-null function pointer")(*userp as *mut libc::c_void);
    *userp = curl_maprintf(
        b"Authorization: Bearer %s\r\n\0" as *const u8 as *const libc::c_char,
        (*data).set.str_0[STRING_BEARER as libc::c_int as usize],
    );
    if (*userp).is_null() {
        result = CURLE_OUT_OF_MEMORY;
    }
    return result;
}
unsafe extern "C" fn pickoneauth(mut pick: *mut auth, mut mask: libc::c_ulong) -> bool {
    let mut picked: bool = false;
    let mut avail: libc::c_ulong = (*pick).avail & (*pick).want & mask;
    picked = 1 as libc::c_int != 0;
    if avail & (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int != 0 {
        (*pick).picked = (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int;
    } else if avail & (1 as libc::c_int as libc::c_ulong) << 6 as libc::c_int != 0 {
        (*pick).picked = (1 as libc::c_int as libc::c_ulong) << 6 as libc::c_int;
    } else if avail & (1 as libc::c_int as libc::c_ulong) << 1 as libc::c_int != 0 {
        (*pick).picked = (1 as libc::c_int as libc::c_ulong) << 1 as libc::c_int;
    } else if avail & (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int != 0 {
        (*pick).picked = (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int;
    } else if avail & (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int != 0 {
        (*pick).picked = (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int;
    } else if avail & (1 as libc::c_int as libc::c_ulong) << 0 as libc::c_int != 0 {
        (*pick).picked = (1 as libc::c_int as libc::c_ulong) << 0 as libc::c_int;
    } else if avail & (1 as libc::c_int as libc::c_ulong) << 7 as libc::c_int != 0 {
        (*pick).picked = (1 as libc::c_int as libc::c_ulong) << 7 as libc::c_int;
    } else {
        (*pick).picked = ((1 as libc::c_int) << 30 as libc::c_int) as libc::c_ulong;
        picked = 0 as libc::c_int != 0;
    }
    (*pick).avail = 0 as libc::c_int as libc::c_ulong;
    return picked;
}
unsafe extern "C" fn http_perhapsrewind(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut http: *mut HTTP = (*data).req.p.http;
    let mut bytessent: curl_off_t = 0;
    let mut expectsend: curl_off_t = -(1 as libc::c_int) as curl_off_t;
    if http.is_null() {
        return CURLE_OK;
    }
    match (*data).state.httpreq as libc::c_uint {
        0 | 5 => return CURLE_OK,
        _ => {}
    }
    bytessent = (*data).req.writebytecount;
    if ((*conn).bits).authneg() != 0 {
        expectsend = 0 as libc::c_int as curl_off_t;
    } else if ((*conn).bits).protoconnstart() == 0 {
        expectsend = 0 as libc::c_int as curl_off_t;
    } else {
        match (*data).state.httpreq as libc::c_uint {
            1 | 4 => {
                if (*data).state.infilesize != -(1 as libc::c_int) as libc::c_long {
                    expectsend = (*data).state.infilesize;
                }
            }
            2 | 3 => {
                expectsend = (*http).postsize;
            }
            _ => {}
        }
    }
    let ref mut fresh1 = (*conn).bits;
    (*fresh1).set_rewindaftersend(0 as libc::c_int as bit);
    if expectsend == -(1 as libc::c_int) as libc::c_long || expectsend > bytessent {
        if (*data).state.authproxy.picked
            == (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int
            || (*data).state.authhost.picked
                == (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int
            || (*data).state.authproxy.picked
                == (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int
            || (*data).state.authhost.picked
                == (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int
        {
            if expectsend - bytessent < 2000 as libc::c_int as libc::c_long
                || (*conn).http_ntlm_state as libc::c_uint
                    != NTLMSTATE_NONE as libc::c_int as libc::c_uint
                || (*conn).proxy_ntlm_state as libc::c_uint
                    != NTLMSTATE_NONE as libc::c_int as libc::c_uint
            {
                if ((*conn).bits).authneg() == 0
                    && (*conn).writesockfd != -(1 as libc::c_int)
                {
                    let ref mut fresh2 = (*conn).bits;
                    (*fresh2).set_rewindaftersend(1 as libc::c_int as bit);
                    Curl_infof(
                        data,
                        b"Rewind stream after send\0" as *const u8 as *const libc::c_char,
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
                    as *const libc::c_char,
                expectsend - bytessent,
            );
        }
        Curl_conncontrol(conn, 2 as libc::c_int);
        (*data).req.size = 0 as libc::c_int as curl_off_t;
    }
    if bytessent != 0 {
        return Curl_readrewind(data);
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_auth_act(mut data: *mut Curl_easy) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut pickhost: bool = 0 as libc::c_int != 0;
    let mut pickproxy: bool = 0 as libc::c_int != 0;
    let mut result: CURLcode = CURLE_OK;
    let mut authmask: libc::c_ulong = !(0 as libc::c_ulong);
    if ((*data).set.str_0[STRING_BEARER as libc::c_int as usize]).is_null() {
        authmask &= !((1 as libc::c_int as libc::c_ulong) << 6 as libc::c_int);
    }
    if 100 as libc::c_int <= (*data).req.httpcode
        && 199 as libc::c_int >= (*data).req.httpcode
    {
        return CURLE_OK;
    }
    if ((*data).state).authproblem() != 0 {
        return (if ((*data).set).http_fail_on_error() as libc::c_int != 0 {
            CURLE_HTTP_RETURNED_ERROR as libc::c_int
        } else {
            CURLE_OK as libc::c_int
        }) as CURLcode;
    }
    if (((*conn).bits).user_passwd() as libc::c_int != 0
        || !((*data).set.str_0[STRING_BEARER as libc::c_int as usize]).is_null())
        && ((*data).req.httpcode == 401 as libc::c_int
            || ((*conn).bits).authneg() as libc::c_int != 0
                && (*data).req.httpcode < 300 as libc::c_int)
    {
        pickhost = pickoneauth(&mut (*data).state.authhost, authmask);
        if !pickhost {
            let ref mut fresh3 = (*data).state;
            (*fresh3).set_authproblem(1 as libc::c_int as bit);
        }
        if (*data).state.authhost.picked
            == (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int
            && (*conn).httpversion as libc::c_int > 11 as libc::c_int
        {
            Curl_infof(
                data,
                b"Forcing HTTP/1.1 for NTLM\0" as *const u8 as *const libc::c_char,
            );
            Curl_conncontrol(conn, 1 as libc::c_int);
            (*data)
                .state
                .httpwant = CURL_HTTP_VERSION_1_1 as libc::c_int as libc::c_uchar;
        }
    }
    if ((*conn).bits).proxy_user_passwd() as libc::c_int != 0
        && ((*data).req.httpcode == 407 as libc::c_int
            || ((*conn).bits).authneg() as libc::c_int != 0
                && (*data).req.httpcode < 300 as libc::c_int)
    {
        pickproxy = pickoneauth(
            &mut (*data).state.authproxy,
            authmask & !((1 as libc::c_int as libc::c_ulong) << 6 as libc::c_int),
        );
        if !pickproxy {
            let ref mut fresh4 = (*data).state;
            (*fresh4).set_authproblem(1 as libc::c_int as bit);
        }
    }
    if pickhost as libc::c_int != 0 || pickproxy as libc::c_int != 0 {
        if (*data).state.httpreq as libc::c_uint
            != HTTPREQ_GET as libc::c_int as libc::c_uint
            && (*data).state.httpreq as libc::c_uint
                != HTTPREQ_HEAD as libc::c_int as libc::c_uint
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
        let ref mut fresh5 = (*data).req.newurl;
        *fresh5 = 0 as *mut libc::c_char;
        let ref mut fresh6 = (*data).req.newurl;
        *fresh6 = Curl_cstrdup.expect("non-null function pointer")((*data).state.url);
        if ((*data).req.newurl).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    } else if (*data).req.httpcode < 300 as libc::c_int
            && ((*data).state.authhost).done() == 0
            && ((*conn).bits).authneg() as libc::c_int != 0
        {
        if (*data).state.httpreq as libc::c_uint
            != HTTPREQ_GET as libc::c_int as libc::c_uint
            && (*data).state.httpreq as libc::c_uint
                != HTTPREQ_HEAD as libc::c_int as libc::c_uint
        {
            let ref mut fresh7 = (*data).req.newurl;
            *fresh7 = Curl_cstrdup
                .expect("non-null function pointer")((*data).state.url);
            if ((*data).req.newurl).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            let ref mut fresh8 = (*data).state.authhost;
            (*fresh8).set_done(1 as libc::c_int as bit);
        }
    }
    if http_should_fail(data) {
        Curl_failf(
            data,
            b"The requested URL returned error: %d\0" as *const u8
                as *const libc::c_char,
            (*data).req.httpcode,
        );
        result = CURLE_HTTP_RETURNED_ERROR;
    }
    return result;
}
unsafe extern "C" fn output_auth_headers(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut authstatus: *mut auth,
    mut request: *const libc::c_char,
    mut path: *const libc::c_char,
    mut proxy: bool,
) -> CURLcode {
    let mut auth: *const libc::c_char = 0 as *const libc::c_char;
    let mut result: CURLcode = CURLE_OK;
    if (*authstatus).picked == (1 as libc::c_int as libc::c_ulong) << 7 as libc::c_int {
        auth = b"AWS_SIGV4\0" as *const u8 as *const libc::c_char;
        result = Curl_output_aws_sigv4(data, proxy);
        if result as u64 != 0 {
            return result;
        }
    } else if (*authstatus).picked
            == (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int
        {
        auth = b"NTLM\0" as *const u8 as *const libc::c_char;
        result = Curl_output_ntlm(data, proxy);
        if result as u64 != 0 {
            return result;
        }
    } else if (*authstatus).picked
            == (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int
        {
        auth = b"NTLM_WB\0" as *const u8 as *const libc::c_char;
        result = Curl_output_ntlm_wb(data, conn, proxy);
        if result as u64 != 0 {
            return result;
        }
    } else if (*authstatus).picked
            == (1 as libc::c_int as libc::c_ulong) << 1 as libc::c_int
        {
        auth = b"Digest\0" as *const u8 as *const libc::c_char;
        result = Curl_output_digest(
            data,
            proxy,
            request as *const libc::c_uchar,
            path as *const libc::c_uchar,
        );
        if result as u64 != 0 {
            return result;
        }
    } else if (*authstatus).picked
            == (1 as libc::c_int as libc::c_ulong) << 0 as libc::c_int
        {
        if proxy as libc::c_int != 0
            && ((*conn).bits).proxy_user_passwd() as libc::c_int != 0
            && (Curl_checkProxyheaders(
                data,
                conn,
                b"Proxy-authorization\0" as *const u8 as *const libc::c_char,
            ))
                .is_null()
            || !proxy && ((*conn).bits).user_passwd() as libc::c_int != 0
                && (Curl_checkheaders(
                    data,
                    b"Authorization\0" as *const u8 as *const libc::c_char,
                ))
                    .is_null()
        {
            auth = b"Basic\0" as *const u8 as *const libc::c_char;
            result = http_output_basic(data, proxy);
            if result as u64 != 0 {
                return result;
            }
        }
        (*authstatus).set_done(1 as libc::c_int as bit);
    }
    if (*authstatus).picked == (1 as libc::c_int as libc::c_ulong) << 6 as libc::c_int {
        if !proxy
            && !((*data).set.str_0[STRING_BEARER as libc::c_int as usize]).is_null()
            && (Curl_checkheaders(
                data,
                b"Authorization\0" as *const u8 as *const libc::c_char,
            ))
                .is_null()
        {
            auth = b"Bearer\0" as *const u8 as *const libc::c_char;
            result = http_output_bearer(data);
            if result as u64 != 0 {
                return result;
            }
        }
        (*authstatus).set_done(1 as libc::c_int as bit);
    }
    if !auth.is_null() {
        Curl_infof(
            data,
            b"%s auth using %s with user '%s'\0" as *const u8 as *const libc::c_char,
            if proxy as libc::c_int != 0 {
                b"Proxy\0" as *const u8 as *const libc::c_char
            } else {
                b"Server\0" as *const u8 as *const libc::c_char
            },
            auth,
            if proxy as libc::c_int != 0 {
                if !((*data).state.aptr.proxyuser).is_null() {
                    (*data).state.aptr.proxyuser as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                }
            } else if !((*data).state.aptr.user).is_null() {
                (*data).state.aptr.user as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
        );
        (*authstatus)
            .set_multipass(
                (if (*authstatus).done() == 0 {
                    1 as libc::c_int
                } else {
                    0 as libc::c_int
                }) as bit,
            );
    } else {
        (*authstatus).set_multipass(0 as libc::c_int as bit);
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_output_auth(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut request: *const libc::c_char,
    mut httpreq: Curl_HttpReq,
    mut path: *const libc::c_char,
    mut proxytunnel: bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut authhost: *mut auth = 0 as *mut auth;
    let mut authproxy: *mut auth = 0 as *mut auth;
    authhost = &mut (*data).state.authhost;
    authproxy = &mut (*data).state.authproxy;
    if ((*conn).bits).httpproxy() as libc::c_int != 0
        && ((*conn).bits).proxy_user_passwd() as libc::c_int != 0
        || ((*conn).bits).user_passwd() as libc::c_int != 0
        || !((*data).set.str_0[STRING_BEARER as libc::c_int as usize]).is_null()
    {} else {
        (*authhost).set_done(1 as libc::c_int as bit);
        (*authproxy).set_done(1 as libc::c_int as bit);
        return CURLE_OK;
    }
    if (*authhost).want != 0 && (*authhost).picked == 0 {
        (*authhost).picked = (*authhost).want;
    }
    if (*authproxy).want != 0 && (*authproxy).picked == 0 {
        (*authproxy).picked = (*authproxy).want;
    }
    if ((*conn).bits).httpproxy() as libc::c_int != 0
        && ((*conn).bits).tunnel_proxy() == proxytunnel as bit
    {
        result = output_auth_headers(
            data,
            conn,
            authproxy,
            request,
            path,
            1 as libc::c_int != 0,
        );
        if result as u64 != 0 {
            return result;
        }
    } else {
        (*authproxy).set_done(1 as libc::c_int as bit);
    }
    if ((*data).state).this_is_a_follow() == 0
        || ((*conn).bits).netrc() as libc::c_int != 0
        || ((*data).state.first_host).is_null()
        || ((*data).set).allow_auth_to_other_hosts() as libc::c_int != 0
        || Curl_strcasecompare((*data).state.first_host, (*conn).host.name) != 0
    {
        result = output_auth_headers(
            data,
            conn,
            authhost,
            request,
            path,
            0 as libc::c_int != 0,
        );
    } else {
        (*authhost).set_done(1 as libc::c_int as bit);
    }
    if ((*authhost).multipass() as libc::c_int != 0 && (*authhost).done() == 0
        || (*authproxy).multipass() as libc::c_int != 0 && (*authproxy).done() == 0)
        && httpreq as libc::c_uint != HTTPREQ_GET as libc::c_int as libc::c_uint
        && httpreq as libc::c_uint != HTTPREQ_HEAD as libc::c_int as libc::c_uint
    {
        let ref mut fresh9 = (*conn).bits;
        (*fresh9).set_authneg(1 as libc::c_int as bit);
    } else {
        let ref mut fresh10 = (*conn).bits;
        (*fresh10).set_authneg(0 as libc::c_int as bit);
    }
    return result;
}
unsafe extern "C" fn is_valid_auth_separator(mut ch: libc::c_char) -> libc::c_int {
    return (ch as libc::c_int == '\u{0}' as i32 || ch as libc::c_int == ',' as i32
        || Curl_isspace(ch as libc::c_uchar as libc::c_int) != 0) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_input_auth(
    mut data: *mut Curl_easy,
    mut proxy: bool,
    mut auth: *const libc::c_char,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut availp: *mut libc::c_ulong = 0 as *mut libc::c_ulong;
    let mut authp: *mut auth = 0 as *mut auth;
    if proxy {
        availp = &mut (*data).info.proxyauthavail;
        authp = &mut (*data).state.authproxy;
    } else {
        availp = &mut (*data).info.httpauthavail;
        authp = &mut (*data).state.authhost;
    }
    while *auth != 0 {
        if curl_strnequal(
            b"NTLM\0" as *const u8 as *const libc::c_char,
            auth,
            strlen(b"NTLM\0" as *const u8 as *const libc::c_char),
        ) != 0 && is_valid_auth_separator(*auth.offset(4 as libc::c_int as isize)) != 0
        {
            if (*authp).avail & (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int
                != 0
                || (*authp).avail
                    & (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int != 0
                || Curl_auth_is_ntlm_supported() as libc::c_int != 0
            {
                *availp |= (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int;
                (*authp).avail
                    |= (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int;
                if (*authp).picked
                    == (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int
                    || (*authp).picked
                        == (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int
                {
                    let mut result: CURLcode = Curl_input_ntlm(data, proxy, auth);
                    if result as u64 == 0 {
                        let ref mut fresh11 = (*data).state;
                        (*fresh11).set_authproblem(0 as libc::c_int as bit);
                        if (*authp).picked
                            == (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int
                        {
                            *availp
                                &= !((1 as libc::c_int as libc::c_ulong)
                                    << 3 as libc::c_int);
                            (*authp).avail
                                &= !((1 as libc::c_int as libc::c_ulong)
                                    << 3 as libc::c_int);
                            *availp
                                |= (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int;
                            (*authp).avail
                                |= (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int;
                            result = Curl_input_ntlm_wb(data, conn, proxy, auth);
                            if result as u64 != 0 {
                                Curl_infof(
                                    data,
                                    b"Authentication problem. Ignoring this.\0" as *const u8
                                        as *const libc::c_char,
                                );
                                let ref mut fresh12 = (*data).state;
                                (*fresh12).set_authproblem(1 as libc::c_int as bit);
                            }
                        }
                    } else {
                        Curl_infof(
                            data,
                            b"Authentication problem. Ignoring this.\0" as *const u8
                                as *const libc::c_char,
                        );
                        let ref mut fresh13 = (*data).state;
                        (*fresh13).set_authproblem(1 as libc::c_int as bit);
                    }
                }
            }
        } else if curl_strnequal(
                b"Digest\0" as *const u8 as *const libc::c_char,
                auth,
                strlen(b"Digest\0" as *const u8 as *const libc::c_char),
            ) != 0
                && is_valid_auth_separator(*auth.offset(6 as libc::c_int as isize)) != 0
            {
            if (*authp).avail & (1 as libc::c_int as libc::c_ulong) << 1 as libc::c_int
                != 0 as libc::c_int as libc::c_ulong
            {
                Curl_infof(
                    data,
                    b"Ignoring duplicate digest auth header.\0" as *const u8
                        as *const libc::c_char,
                );
            } else if Curl_auth_is_digest_supported() {
                let mut result_0: CURLcode = CURLE_OK;
                *availp |= (1 as libc::c_int as libc::c_ulong) << 1 as libc::c_int;
                (*authp).avail
                    |= (1 as libc::c_int as libc::c_ulong) << 1 as libc::c_int;
                result_0 = Curl_input_digest(data, proxy, auth);
                if result_0 as u64 != 0 {
                    Curl_infof(
                        data,
                        b"Authentication problem. Ignoring this.\0" as *const u8
                            as *const libc::c_char,
                    );
                    let ref mut fresh14 = (*data).state;
                    (*fresh14).set_authproblem(1 as libc::c_int as bit);
                }
            }
        } else if curl_strnequal(
                b"Basic\0" as *const u8 as *const libc::c_char,
                auth,
                strlen(b"Basic\0" as *const u8 as *const libc::c_char),
            ) != 0
                && is_valid_auth_separator(*auth.offset(5 as libc::c_int as isize)) != 0
            {
            *availp |= (1 as libc::c_int as libc::c_ulong) << 0 as libc::c_int;
            (*authp).avail |= (1 as libc::c_int as libc::c_ulong) << 0 as libc::c_int;
            if (*authp).picked == (1 as libc::c_int as libc::c_ulong) << 0 as libc::c_int
            {
                (*authp).avail = 0 as libc::c_int as libc::c_ulong;
                Curl_infof(
                    data,
                    b"Authentication problem. Ignoring this.\0" as *const u8
                        as *const libc::c_char,
                );
                let ref mut fresh15 = (*data).state;
                (*fresh15).set_authproblem(1 as libc::c_int as bit);
            }
        } else if curl_strnequal(
                b"Bearer\0" as *const u8 as *const libc::c_char,
                auth,
                strlen(b"Bearer\0" as *const u8 as *const libc::c_char),
            ) != 0
                && is_valid_auth_separator(*auth.offset(6 as libc::c_int as isize)) != 0
            {
            *availp |= (1 as libc::c_int as libc::c_ulong) << 6 as libc::c_int;
            (*authp).avail |= (1 as libc::c_int as libc::c_ulong) << 6 as libc::c_int;
            if (*authp).picked == (1 as libc::c_int as libc::c_ulong) << 6 as libc::c_int
            {
                (*authp).avail = 0 as libc::c_int as libc::c_ulong;
                Curl_infof(
                    data,
                    b"Authentication problem. Ignoring this.\0" as *const u8
                        as *const libc::c_char,
                );
                let ref mut fresh16 = (*data).state;
                (*fresh16).set_authproblem(1 as libc::c_int as bit);
            }
        }
        while *auth as libc::c_int != 0 && *auth as libc::c_int != ',' as i32 {
            auth = auth.offset(1);
        }
        if *auth as libc::c_int == ',' as i32 {
            auth = auth.offset(1);
        }
        while *auth as libc::c_int != 0
            && Curl_isspace(*auth as libc::c_uchar as libc::c_int) != 0
        {
            auth = auth.offset(1);
        }
    }
    return CURLE_OK;
}
unsafe extern "C" fn http_should_fail(mut data: *mut Curl_easy) -> bool {
    let mut httpcode: libc::c_int = 0;
    httpcode = (*data).req.httpcode;
    if ((*data).set).http_fail_on_error() == 0 {
        return 0 as libc::c_int != 0;
    }
    if httpcode < 400 as libc::c_int {
        return 0 as libc::c_int != 0;
    }
    if (*data).state.resume_from != 0
        && (*data).state.httpreq as libc::c_uint
            == HTTPREQ_GET as libc::c_int as libc::c_uint
        && httpcode == 416 as libc::c_int
    {
        return 0 as libc::c_int != 0;
    }
    if httpcode != 401 as libc::c_int && httpcode != 407 as libc::c_int {
        return 1 as libc::c_int != 0;
    }
    if httpcode == 401 as libc::c_int && ((*(*data).conn).bits).user_passwd() == 0 {
        return 1 as libc::c_int != 0;
    }
    if httpcode == 407 as libc::c_int && ((*(*data).conn).bits).proxy_user_passwd() == 0
    {
        return 1 as libc::c_int != 0;
    }
    return ((*data).state).authproblem() != 0;
}
unsafe extern "C" fn readmoredata(
    mut buffer: *mut libc::c_char,
    mut size: size_t,
    mut nitems: size_t,
    mut userp: *mut libc::c_void,
) -> size_t {
    let mut data: *mut Curl_easy = userp as *mut Curl_easy;
    let mut http: *mut HTTP = (*data).req.p.http;
    let mut fullsize: size_t = size.wrapping_mul(nitems);
    if (*http).postsize == 0 {
        return 0 as libc::c_int as size_t;
    }
    let ref mut fresh17 = (*data).req;
    (*fresh17)
        .set_forbidchunk(
            (if (*http).sending as libc::c_uint
                == HTTPSEND_REQUEST as libc::c_int as libc::c_uint
            {
                1 as libc::c_int
            } else {
                0 as libc::c_int
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
            let ref mut fresh18 = (*http).postdata;
            *fresh18 = (*http).backup.postdata;
            (*http).postsize = (*http).backup.postsize;
            let ref mut fresh19 = (*data).state.fread_func;
            *fresh19 = (*http).backup.fread_func;
            let ref mut fresh20 = (*data).state.in_0;
            *fresh20 = (*http).backup.fread_in;
            let ref mut fresh21 = (*http).sending;
            *fresh21 += 1;
            (*http).backup.postsize = 0 as libc::c_int as curl_off_t;
        } else {
            (*http).postsize = 0 as libc::c_int as curl_off_t;
        }
        return fullsize;
    }
    memcpy(
        buffer as *mut libc::c_void,
        (*http).postdata as *const libc::c_void,
        fullsize,
    );
    let ref mut fresh22 = (*http).postdata;
    *fresh22 = (*fresh22).offset(fullsize as isize);
    let ref mut fresh23 = (*http).postsize;
    *fresh23 = (*fresh23 as libc::c_ulong).wrapping_sub(fullsize) as curl_off_t
        as curl_off_t;
    return fullsize;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_buffer_send(
    mut in_0: *mut dynbuf,
    mut data: *mut Curl_easy,
    mut bytes_written: *mut curl_off_t,
    mut included_body_bytes: curl_off_t,
    mut socketindex: libc::c_int,
) -> CURLcode {
    let mut amount: ssize_t = 0;
    let mut result: CURLcode = CURLE_OK;
    let mut ptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut size: size_t = 0;
    let mut conn: *mut connectdata = (*data).conn;
    let mut http: *mut HTTP = (*data).req.p.http;
    let mut sendsize: size_t = 0;
    let mut sockfd: curl_socket_t = 0;
    let mut headersize: size_t = 0;
    sockfd = (*conn).sock[socketindex as usize];
    ptr = Curl_dyn_ptr(in_0);
    size = Curl_dyn_len(in_0);
    headersize = size.wrapping_sub(included_body_bytes as size_t);
    result = CURLE_OK as libc::c_int as CURLcode;
    if result as u64 != 0 {
        Curl_dyn_free(in_0);
        return result;
    }
    if ((*(*conn).handler).flags
        & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0
        || (*conn).http_proxy.proxytype as libc::c_uint
            == CURLPROXY_HTTPS as libc::c_int as libc::c_uint)
        && (*conn).httpversion as libc::c_int != 20 as libc::c_int
    {
        if (*data).set.max_send_speed != 0
            && included_body_bytes > (*data).set.max_send_speed
        {
            let mut overflow: curl_off_t = included_body_bytes
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
        let mut overflow_0: curl_off_t = included_body_bytes
            - (*data).set.max_send_speed;
        sendsize = size.wrapping_sub(overflow_0 as size_t);
    } else {
        sendsize = size;
    }
    result = Curl_write(data, sockfd, ptr as *const libc::c_void, sendsize, &mut amount);
    if result as u64 == 0 {
        let mut headlen: size_t = if amount as size_t > headersize {
            headersize
        } else {
            amount as size_t
        };
        let mut bodylen: size_t = (amount as libc::c_ulong).wrapping_sub(headlen);
        Curl_debug(data, CURLINFO_HEADER_OUT, ptr, headlen);
        if bodylen != 0 {
            Curl_debug(data, CURLINFO_DATA_OUT, ptr.offset(headlen as isize), bodylen);
        }
        *bytes_written += amount;
        if !http.is_null() {
            let ref mut fresh24 = (*data).req.writebytecount;
            *fresh24 = (*fresh24 as libc::c_ulong).wrapping_add(bodylen) as curl_off_t
                as curl_off_t;
            Curl_pgrsSetUploadCounter(data, (*data).req.writebytecount);
            if amount as size_t != size {
                size = (size as libc::c_ulong).wrapping_sub(amount as libc::c_ulong)
                    as size_t as size_t;
                ptr = (Curl_dyn_ptr(in_0)).offset(amount as isize);
                let ref mut fresh25 = (*http).backup.fread_func;
                *fresh25 = (*data).state.fread_func;
                let ref mut fresh26 = (*http).backup.fread_in;
                *fresh26 = (*data).state.in_0;
                let ref mut fresh27 = (*http).backup.postdata;
                *fresh27 = (*http).postdata;
                (*http).backup.postsize = (*http).postsize;
                let ref mut fresh28 = (*data).state.fread_func;
                *fresh28 = ::std::mem::transmute::<
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
                        readmoredata
                            as unsafe extern "C" fn(
                                *mut libc::c_char,
                                size_t,
                                size_t,
                                *mut libc::c_void,
                            ) -> size_t,
                    ),
                );
                let ref mut fresh29 = (*data).state.in_0;
                *fresh29 = data as *mut libc::c_void;
                let ref mut fresh30 = (*http).postdata;
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
    (*data).req.pendingheader = 0 as libc::c_int as curl_off_t;
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_compareheader(
    mut headerline: *const libc::c_char,
    mut header: *const libc::c_char,
    mut content: *const libc::c_char,
) -> bool {
    let mut hlen: size_t = strlen(header);
    let mut clen: size_t = 0;
    let mut len: size_t = 0;
    let mut start: *const libc::c_char = 0 as *const libc::c_char;
    let mut end: *const libc::c_char = 0 as *const libc::c_char;
    if Curl_strncasecompare(headerline, header, hlen) == 0 {
        return 0 as libc::c_int != 0;
    }
    start = &*headerline.offset(hlen as isize) as *const libc::c_char;
    while *start as libc::c_int != 0
        && Curl_isspace(*start as libc::c_uchar as libc::c_int) != 0
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
    len = end.offset_from(start) as libc::c_long as size_t;
    clen = strlen(content);
    while len >= clen {
        if Curl_strncasecompare(start, content, clen) != 0 {
            return 1 as libc::c_int != 0;
        }
        len = len.wrapping_sub(1);
        start = start.offset(1);
    }
    return 0 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_connect(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    Curl_conncontrol(conn, 0 as libc::c_int);
    result = Curl_proxy_connect(data, 0 as libc::c_int);
    if result as u64 != 0 {
        return result;
    }
    if ((*conn).bits).proxy_connect_closed() != 0 {
        return CURLE_OK;
    }
    if (*conn).http_proxy.proxytype as libc::c_uint
        == CURLPROXY_HTTPS as libc::c_int as libc::c_uint
        && !(*conn).bits.proxy_ssl_connected[0 as libc::c_int as usize]
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
        & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint != 0
    {
        result = https_connecting(data, done);
        if result as u64 != 0 {
            return result;
        }
    } else {
        *done = 1 as libc::c_int != 0;
    }
    return CURLE_OK;
}
unsafe extern "C" fn http_getsock_do(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> libc::c_int {
    *socks.offset(0 as libc::c_int as isize) = (*conn).sock[0 as libc::c_int as usize];
    return (1 as libc::c_int) << 16 as libc::c_int + 0 as libc::c_int;
}
unsafe extern "C" fn add_haproxy_protocol_header(mut data: *mut Curl_easy) -> CURLcode {
    let mut req: dynbuf = dynbuf {
        bufr: 0 as *mut libc::c_char,
        leng: 0,
        allc: 0,
        toobig: 0,
    };
    let mut result: CURLcode = CURLE_OK;
    let mut tcp_version: *const libc::c_char = 0 as *const libc::c_char;
    Curl_dyn_init(&mut req, 2048 as libc::c_int as size_t);
    if !((*(*data).conn).unix_domain_socket).is_null() {
        result = Curl_dyn_add(
            &mut req,
            b"PROXY UNKNOWN\r\n\0" as *const u8 as *const libc::c_char,
        );
    } else {
        tcp_version = if ((*(*data).conn).bits).ipv6() as libc::c_int != 0 {
            b"TCP6\0" as *const u8 as *const libc::c_char
        } else {
            b"TCP4\0" as *const u8 as *const libc::c_char
        };
        result = Curl_dyn_addf(
            &mut req as *mut dynbuf,
            b"PROXY %s %s %s %i %i\r\n\0" as *const u8 as *const libc::c_char,
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
            &mut (*data).info.request_size,
            0 as libc::c_int as curl_off_t,
            0 as libc::c_int,
        );
    }
    return result;
}
unsafe extern "C" fn https_connecting(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    result = Curl_ssl_connect_nonblocking(
        data,
        conn,
        0 as libc::c_int != 0,
        0 as libc::c_int,
        done,
    );
    if result as u64 != 0 {
        Curl_conncontrol(conn, 1 as libc::c_int);
    }
    return result;
}
unsafe extern "C" fn https_getsock(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> libc::c_int {
    if (*(*conn).handler).flags
        & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0
    {
        return ((*Curl_ssl).getsock).expect("non-null function pointer")(conn, socks);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_done(
    mut data: *mut Curl_easy,
    mut status: CURLcode,
    mut premature: bool,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut http: *mut HTTP = (*data).req.p.http;
    let ref mut fresh31 = (*data).state.authhost;
    (*fresh31).set_multipass(0 as libc::c_int as bit);
    let ref mut fresh32 = (*data).state.authproxy;
    (*fresh32).set_multipass(0 as libc::c_int as bit);
    Curl_unencode_cleanup(data);
    let ref mut fresh33 = (*conn).seek_func;
    *fresh33 = (*data).set.seek_func;
    let ref mut fresh34 = (*conn).seek_client;
    *fresh34 = (*data).set.seek_client;
    if http.is_null() {
        return CURLE_OK;
    }
    Curl_dyn_free(&mut (*http).send_buffer);
    Curl_http2_done(data, premature);
    Curl_mime_cleanpart(&mut (*http).form);
    Curl_dyn_reset(&mut (*data).state.headerb);
    if status as u64 != 0 {
        return status;
    }
    if !premature && ((*conn).bits).retry() == 0 && ((*data).set).connect_only() == 0
        && (*data).req.bytecount + (*data).req.headerbytecount
            - (*data).req.deductheadercount <= 0 as libc::c_int as libc::c_long
    {
        Curl_failf(
            data,
            b"Empty reply from server\0" as *const u8 as *const libc::c_char,
        );
        Curl_conncontrol(conn, 2 as libc::c_int);
        return CURLE_GOT_NOTHING;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_use_http_1_1plus(
    mut data: *const Curl_easy,
    mut conn: *const connectdata,
) -> bool {
    if (*data).state.httpversion as libc::c_int == 10 as libc::c_int
        || (*conn).httpversion as libc::c_int == 10 as libc::c_int
    {
        return 0 as libc::c_int != 0;
    }
    if (*data).state.httpwant as libc::c_int == CURL_HTTP_VERSION_1_0 as libc::c_int
        && (*conn).httpversion as libc::c_int <= 10 as libc::c_int
    {
        return 0 as libc::c_int != 0;
    }
    return (*data).state.httpwant as libc::c_int == CURL_HTTP_VERSION_NONE as libc::c_int
        || (*data).state.httpwant as libc::c_int >= CURL_HTTP_VERSION_1_1 as libc::c_int;
}
unsafe extern "C" fn get_http_string(
    mut data: *const Curl_easy,
    mut conn: *const connectdata,
) -> *const libc::c_char {
    if !((*conn).proto.httpc.h2).is_null() {
        return b"2\0" as *const u8 as *const libc::c_char;
    }
    if Curl_use_http_1_1plus(data, conn) {
        return b"1.1\0" as *const u8 as *const libc::c_char;
    }
    return b"1.0\0" as *const u8 as *const libc::c_char;
}
unsafe extern "C" fn expect100(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut req: *mut dynbuf,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let ref mut fresh35 = (*data).state;
    (*fresh35).set_expect100header(0 as libc::c_int as bit);
    if ((*data).state).disableexpect() == 0
        && Curl_use_http_1_1plus(data, conn) as libc::c_int != 0
        && ((*conn).httpversion as libc::c_int) < 20 as libc::c_int
    {
        let mut ptr: *const libc::c_char = Curl_checkheaders(
            data,
            b"Expect\0" as *const u8 as *const libc::c_char,
        );
        if !ptr.is_null() {
            let ref mut fresh36 = (*data).state;
            (*fresh36)
                .set_expect100header(
                    Curl_compareheader(
                        ptr,
                        b"Expect:\0" as *const u8 as *const libc::c_char,
                        b"100-continue\0" as *const u8 as *const libc::c_char,
                    ) as bit,
                );
        } else {
            result = Curl_dyn_add(
                req,
                b"Expect: 100-continue\r\n\0" as *const u8 as *const libc::c_char,
            );
            if result as u64 == 0 {
                let ref mut fresh37 = (*data).state;
                (*fresh37).set_expect100header(1 as libc::c_int as bit);
            }
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_compile_trailers(
    mut trailers: *mut curl_slist,
    mut b: *mut dynbuf,
    mut handle: *mut Curl_easy,
) -> CURLcode {
    let mut ptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut result: CURLcode = CURLE_OK;
    let mut endofline_native: *const libc::c_char = 0 as *const libc::c_char;
    let mut endofline_network: *const libc::c_char = 0 as *const libc::c_char;
    if ((*handle).state).prefer_ascii() as libc::c_int != 0
        || ((*handle).set).crlf() as libc::c_int != 0
    {
        endofline_native = b"\n\0" as *const u8 as *const libc::c_char;
        endofline_network = b"\n\0" as *const u8 as *const libc::c_char;
    } else {
        endofline_native = b"\r\n\0" as *const u8 as *const libc::c_char;
        endofline_network = b"\r\n\0" as *const u8 as *const libc::c_char;
    }
    while !trailers.is_null() {
        ptr = strchr((*trailers).data, ':' as i32);
        if !ptr.is_null()
            && *ptr.offset(1 as libc::c_int as isize) as libc::c_int == ' ' as i32
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
                    as *const libc::c_char,
            );
        }
        trailers = (*trailers).next;
    }
    result = Curl_dyn_add(b, endofline_network);
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_add_custom_headers(
    mut data: *mut Curl_easy,
    mut is_connect: bool,
    mut req: *mut dynbuf,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut ptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut h: [*mut curl_slist; 2] = [0 as *mut curl_slist; 2];
    let mut headers: *mut curl_slist = 0 as *mut curl_slist;
    let mut numlists: libc::c_int = 1 as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut proxy: proxy_use = HEADER_SERVER;
    if is_connect {
        proxy = HEADER_CONNECT;
    } else {
        proxy = (if ((*conn).bits).httpproxy() as libc::c_int != 0
            && ((*conn).bits).tunnel_proxy() == 0
        {
            HEADER_PROXY as libc::c_int
        } else {
            HEADER_SERVER as libc::c_int
        }) as proxy_use;
    }
    match proxy as libc::c_uint {
        0 => {
            h[0 as libc::c_int as usize] = (*data).set.headers;
        }
        1 => {
            h[0 as libc::c_int as usize] = (*data).set.headers;
            if ((*data).set).sep_headers() != 0 {
                h[1 as libc::c_int as usize] = (*data).set.proxyheaders;
                numlists += 1;
            }
        }
        2 => {
            if ((*data).set).sep_headers() != 0 {
                h[0 as libc::c_int as usize] = (*data).set.proxyheaders;
            } else {
                h[0 as libc::c_int as usize] = (*data).set.headers;
            }
        }
        _ => {}
    }
    i = 0 as libc::c_int;
    while i < numlists {
        headers = h[i as usize];
        while !headers.is_null() {
            let mut semicolonp: *mut libc::c_char = 0 as *mut libc::c_char;
            ptr = strchr((*headers).data, ':' as i32);
            if ptr.is_null() {
                let mut optr: *mut libc::c_char = 0 as *mut libc::c_char;
                ptr = strchr((*headers).data, ';' as i32);
                if !ptr.is_null() {
                    optr = ptr;
                    ptr = ptr.offset(1);
                    while *ptr as libc::c_int != 0
                        && Curl_isspace(*ptr as libc::c_uchar as libc::c_int) != 0
                    {
                        ptr = ptr.offset(1);
                    }
                    if *ptr != 0 {
                        optr = 0 as *mut libc::c_char;
                    } else {
                        ptr = ptr.offset(-1);
                        if *ptr as libc::c_int == ';' as i32 {
                            semicolonp = Curl_cstrdup
                                .expect("non-null function pointer")((*headers).data);
                            if semicolonp.is_null() {
                                Curl_dyn_free(req);
                                return CURLE_OUT_OF_MEMORY;
                            }
                            *semicolonp
                                .offset(
                                    ptr.offset_from((*headers).data) as libc::c_long as isize,
                                ) = ':' as i32 as libc::c_char;
                            optr = &mut *semicolonp
                                .offset(
                                    ptr.offset_from((*headers).data) as libc::c_long as isize,
                                ) as *mut libc::c_char;
                        }
                    }
                    ptr = optr;
                }
            }
            if !ptr.is_null() {
                ptr = ptr.offset(1);
                while *ptr as libc::c_int != 0
                    && Curl_isspace(*ptr as libc::c_uchar as libc::c_int) != 0
                {
                    ptr = ptr.offset(1);
                }
                if *ptr as libc::c_int != 0 || !semicolonp.is_null() {
                    let mut result: CURLcode = CURLE_OK;
                    let mut compare: *mut libc::c_char = if !semicolonp.is_null() {
                        semicolonp
                    } else {
                        (*headers).data
                    };
                    if !(!((*data).state.aptr.host).is_null()
                        && curl_strnequal(
                            b"Host:\0" as *const u8 as *const libc::c_char,
                            compare,
                            strlen(b"Host:\0" as *const u8 as *const libc::c_char),
                        ) != 0)
                    {
                        if !((*data).state.httpreq as libc::c_uint
                            == HTTPREQ_POST_FORM as libc::c_int as libc::c_uint
                            && curl_strnequal(
                                b"Content-Type:\0" as *const u8 as *const libc::c_char,
                                compare,
                                strlen(
                                    b"Content-Type:\0" as *const u8 as *const libc::c_char,
                                ),
                            ) != 0)
                        {
                            if !((*data).state.httpreq as libc::c_uint
                                == HTTPREQ_POST_MIME as libc::c_int as libc::c_uint
                                && curl_strnequal(
                                    b"Content-Type:\0" as *const u8 as *const libc::c_char,
                                    compare,
                                    strlen(
                                        b"Content-Type:\0" as *const u8 as *const libc::c_char,
                                    ),
                                ) != 0)
                            {
                                if !(((*conn).bits).authneg() as libc::c_int != 0
                                    && curl_strnequal(
                                        b"Content-Length:\0" as *const u8 as *const libc::c_char,
                                        compare,
                                        strlen(
                                            b"Content-Length:\0" as *const u8 as *const libc::c_char,
                                        ),
                                    ) != 0)
                                {
                                    if !(!((*data).state.aptr.te).is_null()
                                        && curl_strnequal(
                                            b"Connection:\0" as *const u8 as *const libc::c_char,
                                            compare,
                                            strlen(b"Connection:\0" as *const u8 as *const libc::c_char),
                                        ) != 0)
                                    {
                                        if !((*conn).httpversion as libc::c_int >= 20 as libc::c_int
                                            && curl_strnequal(
                                                b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char,
                                                compare,
                                                strlen(
                                                    b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char,
                                                ),
                                            ) != 0)
                                        {
                                            if !((curl_strnequal(
                                                b"Authorization:\0" as *const u8 as *const libc::c_char,
                                                compare,
                                                strlen(
                                                    b"Authorization:\0" as *const u8 as *const libc::c_char,
                                                ),
                                            ) != 0
                                                || curl_strnequal(
                                                    b"Cookie:\0" as *const u8 as *const libc::c_char,
                                                    compare,
                                                    strlen(b"Cookie:\0" as *const u8 as *const libc::c_char),
                                                ) != 0)
                                                && (((*data).state).this_is_a_follow() as libc::c_int != 0
                                                    && !((*data).state.first_host).is_null()
                                                    && ((*data).set).allow_auth_to_other_hosts() == 0
                                                    && Curl_strcasecompare(
                                                        (*data).state.first_host,
                                                        (*conn).host.name,
                                                    ) == 0))
                                            {
                                                result = Curl_dyn_addf(
                                                    req,
                                                    b"%s\r\n\0" as *const u8 as *const libc::c_char,
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
        tm_zone: 0 as *const libc::c_char,
    };
    let mut result: CURLcode = CURLE_OK;
    let mut datestr: [libc::c_char; 80] = [0; 80];
    let mut condp: *const libc::c_char = 0 as *const libc::c_char;
    if (*data).set.timecondition as libc::c_uint
        == CURL_TIMECOND_NONE as libc::c_int as libc::c_uint
    {
        return CURLE_OK;
    }
    result = Curl_gmtime((*data).set.timevalue, &mut keeptime);
    if result as u64 != 0 {
        Curl_failf(data, b"Invalid TIMEVALUE\0" as *const u8 as *const libc::c_char);
        return result;
    }
    tm = &mut keeptime;
    match (*data).set.timecondition as libc::c_uint {
        1 => {
            condp = b"If-Modified-Since\0" as *const u8 as *const libc::c_char;
        }
        2 => {
            condp = b"If-Unmodified-Since\0" as *const u8 as *const libc::c_char;
        }
        3 => {
            condp = b"Last-Modified\0" as *const u8 as *const libc::c_char;
        }
        _ => return CURLE_BAD_FUNCTION_ARGUMENT,
    }
    if !(Curl_checkheaders(data, condp)).is_null() {
        return CURLE_OK;
    }
    curl_msnprintf(
        datestr.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 80]>() as libc::c_ulong,
        b"%s: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n\0" as *const u8
            as *const libc::c_char,
        condp,
        Curl_wkday[(if (*tm).tm_wday != 0 {
            (*tm).tm_wday - 1 as libc::c_int
        } else {
            6 as libc::c_int
        }) as usize],
        (*tm).tm_mday,
        Curl_month[(*tm).tm_mon as usize],
        (*tm).tm_year + 1900 as libc::c_int,
        (*tm).tm_hour,
        (*tm).tm_min,
        (*tm).tm_sec,
    );
    result = Curl_dyn_add(req, datestr.as_mut_ptr());
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_method(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut method: *mut *const libc::c_char,
    mut reqp: *mut Curl_HttpReq,
) {
    let mut httpreq: Curl_HttpReq = (*data).state.httpreq;
    let mut request: *const libc::c_char = 0 as *const libc::c_char;
    if (*(*conn).handler).protocol
        & ((1 as libc::c_int) << 0 as libc::c_int
            | (1 as libc::c_int) << 1 as libc::c_int
            | (1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint != 0
        && ((*data).set).upload() as libc::c_int != 0
    {
        httpreq = HTTPREQ_PUT;
    }
    if !((*data).set.str_0[STRING_CUSTOMREQUEST as libc::c_int as usize]).is_null() {
        request = (*data).set.str_0[STRING_CUSTOMREQUEST as libc::c_int as usize];
    } else if ((*data).set).opt_no_body() != 0 {
        request = b"HEAD\0" as *const u8 as *const libc::c_char;
    } else {
        match httpreq as libc::c_uint {
            1 | 2 | 3 => {
                request = b"POST\0" as *const u8 as *const libc::c_char;
            }
            4 => {
                request = b"PUT\0" as *const u8 as *const libc::c_char;
            }
            5 => {
                request = b"HEAD\0" as *const u8 as *const libc::c_char;
            }
            0 | _ => {
                request = b"GET\0" as *const u8 as *const libc::c_char;
            }
        }
    }
    *method = request;
    *reqp = httpreq;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_useragent(mut data: *mut Curl_easy) -> CURLcode {
    if !(Curl_checkheaders(data, b"User-Agent\0" as *const u8 as *const libc::c_char))
        .is_null()
    {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.aptr.uagent as *mut libc::c_void);
        let ref mut fresh38 = (*data).state.aptr.uagent;
        *fresh38 = 0 as *mut libc::c_char;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_host(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut ptr: *const libc::c_char = 0 as *const libc::c_char;
    if ((*data).state).this_is_a_follow() == 0 {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.first_host as *mut libc::c_void);
        let ref mut fresh39 = (*data).state.first_host;
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
    let ref mut fresh40 = (*data).state.aptr.host;
    *fresh40 = 0 as *mut libc::c_char;
    ptr = Curl_checkheaders(data, b"Host\0" as *const u8 as *const libc::c_char);
    if !ptr.is_null()
        && (((*data).state).this_is_a_follow() == 0
            || Curl_strcasecompare((*data).state.first_host, (*conn).host.name) != 0)
    {
        let mut cookiehost: *mut libc::c_char = Curl_copy_header_value(ptr);
        if cookiehost.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if *cookiehost == 0 {
            Curl_cfree
                .expect("non-null function pointer")(cookiehost as *mut libc::c_void);
        } else {
            if *cookiehost as libc::c_int == '[' as i32 {
                let mut closingbracket: *mut libc::c_char = 0 as *mut libc::c_char;
                memmove(
                    cookiehost as *mut libc::c_void,
                    cookiehost.offset(1 as libc::c_int as isize) as *const libc::c_void,
                    (strlen(cookiehost)).wrapping_sub(1 as libc::c_int as libc::c_ulong),
                );
                closingbracket = strchr(cookiehost, ']' as i32);
                if !closingbracket.is_null() {
                    *closingbracket = 0 as libc::c_int as libc::c_char;
                }
            } else {
                let mut startsearch: libc::c_int = 0 as libc::c_int;
                let mut colon: *mut libc::c_char = strchr(
                    cookiehost.offset(startsearch as isize),
                    ':' as i32,
                );
                if !colon.is_null() {
                    *colon = 0 as libc::c_int as libc::c_char;
                }
            }
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).state.aptr.cookiehost as *mut libc::c_void);
            let ref mut fresh41 = (*data).state.aptr.cookiehost;
            *fresh41 = 0 as *mut libc::c_char;
            let ref mut fresh42 = (*data).state.aptr.cookiehost;
            *fresh42 = cookiehost;
        }
        if strcmp(b"Host:\0" as *const u8 as *const libc::c_char, ptr) != 0 {
            let ref mut fresh43 = (*data).state.aptr.host;
            *fresh43 = curl_maprintf(
                b"Host:%s\r\n\0" as *const u8 as *const libc::c_char,
                &*ptr.offset(5 as libc::c_int as isize) as *const libc::c_char,
            );
            if ((*data).state.aptr.host).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        } else {
            let ref mut fresh44 = (*data).state.aptr.host;
            *fresh44 = 0 as *mut libc::c_char;
        }
    } else {
        let mut host: *const libc::c_char = (*conn).host.name;
        if (*(*conn).given).protocol
            & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint != 0
            && (*conn).remote_port == 443 as libc::c_int
            || (*(*conn).given).protocol
                & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0
                && (*conn).remote_port == 80 as libc::c_int
        {
            let ref mut fresh45 = (*data).state.aptr.host;
            *fresh45 = curl_maprintf(
                b"Host: %s%s%s\r\n\0" as *const u8 as *const libc::c_char,
                if ((*conn).bits).ipv6_ip() as libc::c_int != 0 {
                    b"[\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                host,
                if ((*conn).bits).ipv6_ip() as libc::c_int != 0 {
                    b"]\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
            );
        } else {
            let ref mut fresh46 = (*data).state.aptr.host;
            *fresh46 = curl_maprintf(
                b"Host: %s%s%s:%d\r\n\0" as *const u8 as *const libc::c_char,
                if ((*conn).bits).ipv6_ip() as libc::c_int != 0 {
                    b"[\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                host,
                if ((*conn).bits).ipv6_ip() as libc::c_int != 0 {
                    b"]\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
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
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut r: *mut dynbuf,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut path: *const libc::c_char = (*data).state.up.path;
    let mut query: *const libc::c_char = (*data).state.up.query;
    if !((*data).set.str_0[STRING_TARGET as libc::c_int as usize]).is_null() {
        path = (*data).set.str_0[STRING_TARGET as libc::c_int as usize];
        query = 0 as *const libc::c_char;
    }
    if ((*conn).bits).httpproxy() as libc::c_int != 0
        && ((*conn).bits).tunnel_proxy() == 0
    {
        let mut uc: CURLUcode = CURLUE_OK;
        let mut url: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut h: *mut CURLU = curl_url_dup((*data).state.uh);
        if h.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if (*conn).host.dispname != (*conn).host.name as *const libc::c_char {
            uc = curl_url_set(
                h,
                CURLUPART_HOST,
                (*conn).host.name,
                0 as libc::c_int as libc::c_uint,
            );
            if uc as u64 != 0 {
                curl_url_cleanup(h);
                return CURLE_OUT_OF_MEMORY;
            }
        }
        uc = curl_url_set(
            h,
            CURLUPART_FRAGMENT,
            0 as *const libc::c_char,
            0 as libc::c_int as libc::c_uint,
        );
        if uc as u64 != 0 {
            curl_url_cleanup(h);
            return CURLE_OUT_OF_MEMORY;
        }
        if Curl_strcasecompare(
            b"http\0" as *const u8 as *const libc::c_char,
            (*data).state.up.scheme,
        ) != 0
        {
            uc = curl_url_set(
                h,
                CURLUPART_USER,
                0 as *const libc::c_char,
                0 as libc::c_int as libc::c_uint,
            );
            if uc as u64 != 0 {
                curl_url_cleanup(h);
                return CURLE_OUT_OF_MEMORY;
            }
            uc = curl_url_set(
                h,
                CURLUPART_PASSWORD,
                0 as *const libc::c_char,
                0 as libc::c_int as libc::c_uint,
            );
            if uc as u64 != 0 {
                curl_url_cleanup(h);
                return CURLE_OUT_OF_MEMORY;
            }
        }
        uc = curl_url_get(
            h,
            CURLUPART_URL,
            &mut url,
            ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint,
        );
        if uc as u64 != 0 {
            curl_url_cleanup(h);
            return CURLE_OUT_OF_MEMORY;
        }
        curl_url_cleanup(h);
        result = Curl_dyn_add(
            r,
            if !((*data).set.str_0[STRING_TARGET as libc::c_int as usize]).is_null() {
                (*data).set.str_0[STRING_TARGET as libc::c_int as usize]
            } else {
                url
            },
        );
        Curl_cfree.expect("non-null function pointer")(url as *mut libc::c_void);
        if result as u64 != 0 {
            return result;
        }
        if Curl_strcasecompare(
            b"ftp\0" as *const u8 as *const libc::c_char,
            (*data).state.up.scheme,
        ) != 0
        {
            if ((*data).set).proxy_transfer_mode() != 0 {
                let mut type_0: *mut libc::c_char = strstr(
                    path,
                    b";type=\0" as *const u8 as *const libc::c_char,
                );
                if !type_0.is_null()
                    && *type_0.offset(6 as libc::c_int as isize) as libc::c_int != 0
                    && *type_0.offset(7 as libc::c_int as isize) as libc::c_int
                        == 0 as libc::c_int
                {
                    match Curl_raw_toupper(*type_0.offset(6 as libc::c_int as isize))
                        as libc::c_int
                    {
                        65 | 68 | 73 => {}
                        _ => {
                            type_0 = 0 as *mut libc::c_char;
                        }
                    }
                }
                if type_0.is_null() {
                    result = Curl_dyn_addf(
                        r,
                        b";type=%c\0" as *const u8 as *const libc::c_char,
                        if ((*data).state).prefer_ascii() as libc::c_int != 0 {
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
                b"?%s\0" as *const u8 as *const libc::c_char,
                query,
            );
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_body(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut httpreq: Curl_HttpReq,
    mut tep: *mut *const libc::c_char,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ptr: *const libc::c_char = 0 as *const libc::c_char;
    let mut http: *mut HTTP = (*data).req.p.http;
    (*http).postsize = 0 as libc::c_int as curl_off_t;
    match httpreq as libc::c_uint {
        3 => {
            let ref mut fresh47 = (*http).sendit;
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
            let ref mut fresh48 = (*http).sendit;
            *fresh48 = &mut (*http).form;
        }
        _ => {
            let ref mut fresh49 = (*http).sendit;
            *fresh49 = 0 as *mut curl_mimepart;
        }
    }
    if !((*http).sendit).is_null() {
        let mut cthdr: *const libc::c_char = Curl_checkheaders(
            data,
            b"Content-Type\0" as *const u8 as *const libc::c_char,
        );
        (*(*http).sendit).flags
            |= ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint;
        if !cthdr.is_null() {
            cthdr = cthdr.offset(13 as libc::c_int as isize);
            while *cthdr as libc::c_int == ' ' as i32 {
                cthdr = cthdr.offset(1);
            }
        } else if (*(*http).sendit).kind as libc::c_uint
                == MIMEKIND_MULTIPART as libc::c_int as libc::c_uint
            {
            cthdr = b"multipart/form-data\0" as *const u8 as *const libc::c_char;
        }
        curl_mime_headers((*http).sendit, (*data).set.headers, 0 as libc::c_int);
        result = Curl_mime_prepare_headers(
            (*http).sendit,
            cthdr,
            0 as *const libc::c_char,
            MIMESTRATEGY_FORM,
        );
        curl_mime_headers((*http).sendit, 0 as *mut curl_slist, 0 as libc::c_int);
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
        b"Transfer-Encoding\0" as *const u8 as *const libc::c_char,
    );
    if !ptr.is_null() {
        let ref mut fresh50 = (*data).req;
        (*fresh50)
            .set_upload_chunky(
                Curl_compareheader(
                    ptr,
                    b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char,
                    b"chunked\0" as *const u8 as *const libc::c_char,
                ) as bit,
            );
    } else {
        if (*(*conn).handler).protocol
            & ((1 as libc::c_int) << 0 as libc::c_int
                | (1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint != 0
            && ((httpreq as libc::c_uint
                == HTTPREQ_POST_MIME as libc::c_int as libc::c_uint
                || httpreq as libc::c_uint
                    == HTTPREQ_POST_FORM as libc::c_int as libc::c_uint)
                && (*http).postsize < 0 as libc::c_int as libc::c_long
                || (((*data).set).upload() as libc::c_int != 0
                    || httpreq as libc::c_uint
                        == HTTPREQ_POST as libc::c_int as libc::c_uint)
                    && (*data).state.infilesize == -(1 as libc::c_int) as libc::c_long)
        {
            if !(((*conn).bits).authneg() != 0) {
                if Curl_use_http_1_1plus(data, conn) {
                    if ((*conn).httpversion as libc::c_int) < 20 as libc::c_int {
                        let ref mut fresh51 = (*data).req;
                        (*fresh51).set_upload_chunky(1 as libc::c_int as bit);
                    }
                } else {
                    Curl_failf(
                        data,
                        b"Chunky upload is not supported by HTTP 1.0\0" as *const u8
                            as *const libc::c_char,
                    );
                    return CURLE_UPLOAD_FAILED;
                }
            }
        } else {
            let ref mut fresh52 = (*data).req;
            (*fresh52).set_upload_chunky(0 as libc::c_int as bit);
        }
        if ((*data).req).upload_chunky() != 0 {
            *tep = b"Transfer-Encoding: chunked\r\n\0" as *const u8
                as *const libc::c_char;
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_bodysend(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut r: *mut dynbuf,
    mut httpreq: Curl_HttpReq,
) -> CURLcode {
    let mut included_body: curl_off_t = 0 as libc::c_int as curl_off_t;
    let mut result: CURLcode = CURLE_OK;
    let mut http: *mut HTTP = (*data).req.p.http;
    let mut ptr: *const libc::c_char = 0 as *const libc::c_char;
    match httpreq as libc::c_uint {
        4 => {
            if ((*conn).bits).authneg() != 0 {
                (*http).postsize = 0 as libc::c_int as curl_off_t;
            } else {
                (*http).postsize = (*data).state.infilesize;
            }
            if (*http).postsize != -(1 as libc::c_int) as libc::c_long
                && ((*data).req).upload_chunky() == 0
                && (((*conn).bits).authneg() as libc::c_int != 0
                    || (Curl_checkheaders(
                        data,
                        b"Content-Length\0" as *const u8 as *const libc::c_char,
                    ))
                        .is_null())
            {
                result = Curl_dyn_addf(
                    r,
                    b"Content-Length: %ld\r\n\0" as *const u8 as *const libc::c_char,
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
            result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char);
            if result as u64 != 0 {
                return result;
            }
            Curl_pgrsSetUploadSize(data, (*http).postsize);
            result = Curl_buffer_send(
                r,
                data,
                &mut (*data).info.request_size,
                0 as libc::c_int as curl_off_t,
                0 as libc::c_int,
            );
            if result as u64 != 0 {
                Curl_failf(
                    data,
                    b"Failed sending PUT request\0" as *const u8 as *const libc::c_char,
                );
            } else {
                Curl_setup_transfer(
                    data,
                    0 as libc::c_int,
                    -(1 as libc::c_int) as curl_off_t,
                    1 as libc::c_int != 0,
                    if (*http).postsize != 0 {
                        0 as libc::c_int
                    } else {
                        -(1 as libc::c_int)
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
                    b"Content-Length: 0\r\n\r\n\0" as *const u8 as *const libc::c_char,
                );
                if result as u64 != 0 {
                    return result;
                }
                result = Curl_buffer_send(
                    r,
                    data,
                    &mut (*data).info.request_size,
                    0 as libc::c_int as curl_off_t,
                    0 as libc::c_int,
                );
                if result as u64 != 0 {
                    Curl_failf(
                        data,
                        b"Failed sending POST request\0" as *const u8
                            as *const libc::c_char,
                    );
                } else {
                    Curl_setup_transfer(
                        data,
                        0 as libc::c_int,
                        -(1 as libc::c_int) as curl_off_t,
                        1 as libc::c_int != 0,
                        -(1 as libc::c_int),
                    );
                }
            } else {
                (*data).state.infilesize = (*http).postsize;
                if (*http).postsize != -(1 as libc::c_int) as libc::c_long
                    && ((*data).req).upload_chunky() == 0
                    && (((*conn).bits).authneg() as libc::c_int != 0
                        || (Curl_checkheaders(
                            data,
                            b"Content-Length\0" as *const u8 as *const libc::c_char,
                        ))
                            .is_null())
                {
                    result = Curl_dyn_addf(
                        r,
                        b"Content-Length: %ld\r\n\0" as *const u8 as *const libc::c_char,
                        (*http).postsize,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                }
                let mut hdr: *mut curl_slist = 0 as *mut curl_slist;
                hdr = (*(*http).sendit).curlheaders;
                while !hdr.is_null() {
                    result = Curl_dyn_addf(
                        r,
                        b"%s\r\n\0" as *const u8 as *const libc::c_char,
                        (*hdr).data,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                    hdr = (*hdr).next;
                }
                ptr = Curl_checkheaders(
                    data,
                    b"Expect\0" as *const u8 as *const libc::c_char,
                );
                if !ptr.is_null() {
                    let ref mut fresh53 = (*data).state;
                    (*fresh53)
                        .set_expect100header(
                            Curl_compareheader(
                                ptr,
                                b"Expect:\0" as *const u8 as *const libc::c_char,
                                b"100-continue\0" as *const u8 as *const libc::c_char,
                            ) as bit,
                        );
                } else if (*http).postsize
                        > (1024 as libc::c_int * 1024 as libc::c_int) as libc::c_long
                        || (*http).postsize < 0 as libc::c_int as libc::c_long
                    {
                    result = expect100(data, conn, r);
                    if result as u64 != 0 {
                        return result;
                    }
                } else {
                    let ref mut fresh54 = (*data).state;
                    (*fresh54).set_expect100header(0 as libc::c_int as bit);
                }
                result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char);
                if result as u64 != 0 {
                    return result;
                }
                Curl_pgrsSetUploadSize(data, (*http).postsize);
                let ref mut fresh55 = (*data).state.fread_func;
                *fresh55 = ::std::mem::transmute::<
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
                );
                let ref mut fresh56 = (*data).state.in_0;
                *fresh56 = (*http).sendit as *mut libc::c_void;
                (*http).sending = HTTPSEND_BODY;
                result = Curl_buffer_send(
                    r,
                    data,
                    &mut (*data).info.request_size,
                    0 as libc::c_int as curl_off_t,
                    0 as libc::c_int,
                );
                if result as u64 != 0 {
                    Curl_failf(
                        data,
                        b"Failed sending POST request\0" as *const u8
                            as *const libc::c_char,
                    );
                } else {
                    Curl_setup_transfer(
                        data,
                        0 as libc::c_int,
                        -(1 as libc::c_int) as curl_off_t,
                        1 as libc::c_int != 0,
                        if (*http).postsize != 0 {
                            0 as libc::c_int
                        } else {
                            -(1 as libc::c_int)
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
                (*http).postsize = 0 as libc::c_int as curl_off_t;
            } else {
                (*http).postsize = (*data).state.infilesize;
            }
            if (*http).postsize != -(1 as libc::c_int) as libc::c_long
                && ((*data).req).upload_chunky() == 0
                && (((*conn).bits).authneg() as libc::c_int != 0
                    || (Curl_checkheaders(
                        data,
                        b"Content-Length\0" as *const u8 as *const libc::c_char,
                    ))
                        .is_null())
            {
                result = Curl_dyn_addf(
                    r,
                    b"Content-Length: %ld\r\n\0" as *const u8 as *const libc::c_char,
                    (*http).postsize,
                );
                if result as u64 != 0 {
                    return result;
                }
            }
            if (Curl_checkheaders(
                data,
                b"Content-Type\0" as *const u8 as *const libc::c_char,
            ))
                .is_null()
            {
                result = Curl_dyn_add(
                    r,
                    b"Content-Type: application/x-www-form-urlencoded\r\n\0" as *const u8
                        as *const libc::c_char,
                );
                if result as u64 != 0 {
                    return result;
                }
            }
            ptr = Curl_checkheaders(
                data,
                b"Expect\0" as *const u8 as *const libc::c_char,
            );
            if !ptr.is_null() {
                let ref mut fresh57 = (*data).state;
                (*fresh57)
                    .set_expect100header(
                        Curl_compareheader(
                            ptr,
                            b"Expect:\0" as *const u8 as *const libc::c_char,
                            b"100-continue\0" as *const u8 as *const libc::c_char,
                        ) as bit,
                    );
            } else if (*http).postsize
                    > (1024 as libc::c_int * 1024 as libc::c_int) as libc::c_long
                    || (*http).postsize < 0 as libc::c_int as libc::c_long
                {
                result = expect100(data, conn, r);
                if result as u64 != 0 {
                    return result;
                }
            } else {
                let ref mut fresh58 = (*data).state;
                (*fresh58).set_expect100header(0 as libc::c_int as bit);
            }
            if !((*data).set.postfields).is_null() {
                if (*conn).httpversion as libc::c_int != 20 as libc::c_int
                    && ((*data).state).expect100header() == 0
                    && (*http).postsize
                        < (64 as libc::c_int * 1024 as libc::c_int) as libc::c_long
                {
                    result = Curl_dyn_add(
                        r,
                        b"\r\n\0" as *const u8 as *const libc::c_char,
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
                            let mut chunk: [libc::c_char; 16] = [0; 16];
                            curl_msnprintf(
                                chunk.as_mut_ptr(),
                                ::std::mem::size_of::<[libc::c_char; 16]>()
                                    as libc::c_ulong,
                                b"%x\r\n\0" as *const u8 as *const libc::c_char,
                                (*http).postsize as libc::c_int,
                            );
                            result = Curl_dyn_add(r, chunk.as_mut_ptr());
                            if result as u64 == 0 {
                                included_body = ((*http).postsize as libc::c_ulong)
                                    .wrapping_add(strlen(chunk.as_mut_ptr())) as curl_off_t;
                                result = Curl_dyn_addn(
                                    r,
                                    (*data).set.postfields,
                                    (*http).postsize as size_t,
                                );
                                if result as u64 == 0 {
                                    result = Curl_dyn_add(
                                        r,
                                        b"\r\n\0" as *const u8 as *const libc::c_char,
                                    );
                                }
                                included_body += 2 as libc::c_int as libc::c_long;
                            }
                        }
                        if result as u64 == 0 {
                            result = Curl_dyn_add(
                                r,
                                b"0\r\n\r\n\0" as *const u8 as *const libc::c_char,
                            );
                            included_body += 5 as libc::c_int as libc::c_long;
                        }
                    }
                    if result as u64 != 0 {
                        return result;
                    }
                    Curl_pgrsSetUploadSize(data, (*http).postsize);
                } else {
                    let ref mut fresh59 = (*http).postdata;
                    *fresh59 = (*data).set.postfields as *const libc::c_char;
                    (*http).sending = HTTPSEND_BODY;
                    let ref mut fresh60 = (*data).state.fread_func;
                    *fresh60 = ::std::mem::transmute::<
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
                            readmoredata
                                as unsafe extern "C" fn(
                                    *mut libc::c_char,
                                    size_t,
                                    size_t,
                                    *mut libc::c_void,
                                ) -> size_t,
                        ),
                    );
                    let ref mut fresh61 = (*data).state.in_0;
                    *fresh61 = data as *mut libc::c_void;
                    Curl_pgrsSetUploadSize(data, (*http).postsize);
                    result = Curl_dyn_add(
                        r,
                        b"\r\n\0" as *const u8 as *const libc::c_char,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                }
            } else {
                result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char);
                if result as u64 != 0 {
                    return result;
                }
                if ((*data).req).upload_chunky() as libc::c_int != 0
                    && ((*conn).bits).authneg() as libc::c_int != 0
                {
                    result = Curl_dyn_add(
                        r,
                        b"0\r\n\r\n\0" as *const u8 as *const libc::c_char
                            as *mut libc::c_char,
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
                            -(1 as libc::c_int) as libc::c_long
                        },
                    );
                    if ((*conn).bits).authneg() == 0 {
                        let ref mut fresh62 = (*http).postdata;
                        *fresh62 = &mut (*http).postdata as *mut *const libc::c_char
                            as *mut libc::c_char;
                    }
                }
            }
            result = Curl_buffer_send(
                r,
                data,
                &mut (*data).info.request_size,
                included_body,
                0 as libc::c_int,
            );
            if result as u64 != 0 {
                Curl_failf(
                    data,
                    b"Failed sending HTTP POST request\0" as *const u8
                        as *const libc::c_char,
                );
            } else {
                Curl_setup_transfer(
                    data,
                    0 as libc::c_int,
                    -(1 as libc::c_int) as curl_off_t,
                    1 as libc::c_int != 0,
                    if !((*http).postdata).is_null() {
                        0 as libc::c_int
                    } else {
                        -(1 as libc::c_int)
                    },
                );
            }
        }
        _ => {
            result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char);
            if result as u64 != 0 {
                return result;
            }
            result = Curl_buffer_send(
                r,
                data,
                &mut (*data).info.request_size,
                0 as libc::c_int as curl_off_t,
                0 as libc::c_int,
            );
            if result as u64 != 0 {
                Curl_failf(
                    data,
                    b"Failed sending HTTP request\0" as *const u8 as *const libc::c_char,
                );
            } else {
                Curl_setup_transfer(
                    data,
                    0 as libc::c_int,
                    -(1 as libc::c_int) as curl_off_t,
                    1 as libc::c_int != 0,
                    -(1 as libc::c_int),
                );
            }
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_cookies(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut r: *mut dynbuf,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut addcookies: *mut libc::c_char = 0 as *mut libc::c_char;
    if !((*data).set.str_0[STRING_COOKIE as libc::c_int as usize]).is_null()
        && (Curl_checkheaders(data, b"Cookie\0" as *const u8 as *const libc::c_char))
            .is_null()
    {
        addcookies = (*data).set.str_0[STRING_COOKIE as libc::c_int as usize];
    }
    if !((*data).cookies).is_null() || !addcookies.is_null() {
        let mut co: *mut Cookie = 0 as *mut Cookie;
        let mut count: libc::c_int = 0 as libc::c_int;
        if !((*data).cookies).is_null()
            && ((*data).state).cookie_engine() as libc::c_int != 0
        {
            let mut host: *const libc::c_char = if !((*data).state.aptr.cookiehost)
                .is_null()
            {
                (*data).state.aptr.cookiehost
            } else {
                (*conn).host.name
            };
            let secure_context: bool = if (*(*conn).handler).protocol
                & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint != 0
                || Curl_strcasecompare(
                    b"localhost\0" as *const u8 as *const libc::c_char,
                    host,
                ) != 0
                || strcmp(host, b"127.0.0.1\0" as *const u8 as *const libc::c_char) == 0
                || strcmp(host, b"[::1]\0" as *const u8 as *const libc::c_char) == 0
            {
                1 as libc::c_int
            } else {
                0 as libc::c_int
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
            let mut store: *mut Cookie = co;
            while !co.is_null() {
                if !((*co).value).is_null() {
                    if 0 as libc::c_int == count {
                        result = Curl_dyn_add(
                            r,
                            b"Cookie: \0" as *const u8 as *const libc::c_char,
                        );
                        if result as u64 != 0 {
                            break;
                        }
                    }
                    result = Curl_dyn_addf(
                        r,
                        b"%s%s=%s\0" as *const u8 as *const libc::c_char,
                        if count != 0 {
                            b"; \0" as *const u8 as *const libc::c_char
                        } else {
                            b"\0" as *const u8 as *const libc::c_char
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
                    b"Cookie: \0" as *const u8 as *const libc::c_char,
                );
            }
            if result as u64 == 0 {
                result = Curl_dyn_addf(
                    r,
                    b"%s%s\0" as *const u8 as *const libc::c_char,
                    if count != 0 {
                        b"; \0" as *const u8 as *const libc::c_char
                    } else {
                        b"\0" as *const u8 as *const libc::c_char
                    },
                    addcookies,
                );
                count += 1;
            }
        }
        if count != 0 && result as u64 == 0 {
            result = Curl_dyn_add(r, b"\r\n\0" as *const u8 as *const libc::c_char);
        }
        if result as u64 != 0 {
            return result;
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_range(
    mut data: *mut Curl_easy,
    mut httpreq: Curl_HttpReq,
) -> CURLcode {
    if ((*data).state).use_range() != 0 {
        if (httpreq as libc::c_uint == HTTPREQ_GET as libc::c_int as libc::c_uint
            || httpreq as libc::c_uint == HTTPREQ_HEAD as libc::c_int as libc::c_uint)
            && (Curl_checkheaders(data, b"Range\0" as *const u8 as *const libc::c_char))
                .is_null()
        {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).state.aptr.rangeline as *mut libc::c_void);
            let ref mut fresh63 = (*data).state.aptr.rangeline;
            *fresh63 = curl_maprintf(
                b"Range: bytes=%s\r\n\0" as *const u8 as *const libc::c_char,
                (*data).state.range,
            );
        } else if (httpreq as libc::c_uint == HTTPREQ_POST as libc::c_int as libc::c_uint
                || httpreq as libc::c_uint == HTTPREQ_PUT as libc::c_int as libc::c_uint)
                && (Curl_checkheaders(
                    data,
                    b"Content-Range\0" as *const u8 as *const libc::c_char,
                ))
                    .is_null()
            {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).state.aptr.rangeline as *mut libc::c_void);
            if (*data).set.set_resume_from < 0 as libc::c_int as libc::c_long {
                let ref mut fresh64 = (*data).state.aptr.rangeline;
                *fresh64 = curl_maprintf(
                    b"Content-Range: bytes 0-%ld/%ld\r\n\0" as *const u8
                        as *const libc::c_char,
                    (*data).state.infilesize - 1 as libc::c_int as libc::c_long,
                    (*data).state.infilesize,
                );
            } else if (*data).state.resume_from != 0 {
                let mut total_expected_size: curl_off_t = (*data).state.resume_from
                    + (*data).state.infilesize;
                let ref mut fresh65 = (*data).state.aptr.rangeline;
                *fresh65 = curl_maprintf(
                    b"Content-Range: bytes %s%ld/%ld\r\n\0" as *const u8
                        as *const libc::c_char,
                    (*data).state.range,
                    total_expected_size - 1 as libc::c_int as libc::c_long,
                    total_expected_size,
                );
            } else {
                let ref mut fresh66 = (*data).state.aptr.rangeline;
                *fresh66 = curl_maprintf(
                    b"Content-Range: bytes %s/%ld\r\n\0" as *const u8
                        as *const libc::c_char,
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
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut httpreq: Curl_HttpReq,
) -> CURLcode {
    if (HTTPREQ_POST as libc::c_int as libc::c_uint == httpreq as libc::c_uint
        || HTTPREQ_PUT as libc::c_int as libc::c_uint == httpreq as libc::c_uint)
        && (*data).state.resume_from != 0
    {
        if (*data).state.resume_from < 0 as libc::c_int as libc::c_long {
            (*data).state.resume_from = 0 as libc::c_int as curl_off_t;
        }
        if (*data).state.resume_from != 0 && ((*data).state).this_is_a_follow() == 0 {
            let mut seekerr: libc::c_int = 2 as libc::c_int;
            if ((*conn).seek_func).is_some() {
                Curl_set_in_callback(data, 1 as libc::c_int != 0);
                seekerr = ((*conn).seek_func)
                    .expect(
                        "non-null function pointer",
                    )((*conn).seek_client, (*data).state.resume_from, 0 as libc::c_int);
                Curl_set_in_callback(data, 0 as libc::c_int != 0);
            }
            if seekerr != 0 as libc::c_int {
                let mut passed: curl_off_t = 0 as libc::c_int as curl_off_t;
                if seekerr != 2 as libc::c_int {
                    Curl_failf(
                        data,
                        b"Could not seek stream\0" as *const u8 as *const libc::c_char,
                    );
                    return CURLE_READ_ERROR;
                }
                loop {
                    let mut readthisamountnow: size_t = if (*data).state.resume_from
                        - passed > (*data).set.buffer_size
                    {
                        (*data).set.buffer_size as size_t
                    } else {
                        curlx_sotouz((*data).state.resume_from - passed)
                    };
                    let mut actuallyread: size_t = ((*data).state.fread_func)
                        .expect(
                            "non-null function pointer",
                        )(
                        (*data).state.buffer,
                        1 as libc::c_int as size_t,
                        readthisamountnow,
                        (*data).state.in_0,
                    );
                    passed = (passed as libc::c_ulong).wrapping_add(actuallyread)
                        as curl_off_t as curl_off_t;
                    if actuallyread == 0 as libc::c_int as libc::c_ulong
                        || actuallyread > readthisamountnow
                    {
                        Curl_failf(
                            data,
                            b"Could only read %ld bytes from the input\0" as *const u8
                                as *const libc::c_char,
                            passed,
                        );
                        return CURLE_READ_ERROR;
                    }
                    if !(passed < (*data).state.resume_from) {
                        break;
                    }
                }
            }
            if (*data).state.infilesize > 0 as libc::c_int as libc::c_long {
                let ref mut fresh67 = (*data).state.infilesize;
                *fresh67 -= (*data).state.resume_from;
                if (*data).state.infilesize <= 0 as libc::c_int as libc::c_long {
                    Curl_failf(
                        data,
                        b"File already completely uploaded\0" as *const u8
                            as *const libc::c_char,
                    );
                    return CURLE_PARTIAL_FILE;
                }
            }
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_firstwrite(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut done: *mut bool,
) -> CURLcode {
    let mut k: *mut SingleRequest = &mut (*data).req;
    if ((*data).req).ignore_cl() != 0 {
        let ref mut fresh68 = (*k).maxdownload;
        *fresh68 = -(1 as libc::c_int) as curl_off_t;
        (*k).size = *fresh68;
    } else if (*k).size != -(1 as libc::c_int) as libc::c_long {
        if (*data).set.max_filesize != 0 && (*k).size > (*data).set.max_filesize {
            Curl_failf(
                data,
                b"Maximum file size exceeded\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_FILESIZE_EXCEEDED;
        }
        Curl_pgrsSetDownloadSize(data, (*k).size);
    }
    if !((*data).req.newurl).is_null() {
        if ((*conn).bits).close() != 0 {
            (*k).keepon &= !((1 as libc::c_int) << 0 as libc::c_int);
            *done = 1 as libc::c_int != 0;
            return CURLE_OK;
        }
        (*k).set_ignorebody(1 as libc::c_int as bit);
        Curl_infof(
            data,
            b"Ignoring the response-body\0" as *const u8 as *const libc::c_char,
        );
    }
    if (*data).state.resume_from != 0 && (*k).content_range() == 0
        && (*data).state.httpreq as libc::c_uint
            == HTTPREQ_GET as libc::c_int as libc::c_uint && (*k).ignorebody() == 0
    {
        if (*k).size == (*data).state.resume_from {
            Curl_infof(
                data,
                b"The entire document is already downloaded\0" as *const u8
                    as *const libc::c_char,
            );
            Curl_conncontrol(conn, 1 as libc::c_int);
            (*k).keepon &= !((1 as libc::c_int) << 0 as libc::c_int);
            *done = 1 as libc::c_int != 0;
            return CURLE_OK;
        }
        Curl_failf(
            data,
            b"HTTP server doesn't seem to support byte ranges. Cannot resume.\0"
                as *const u8 as *const libc::c_char,
        );
        return CURLE_RANGE_ERROR;
    }
    if (*data).set.timecondition as libc::c_uint != 0 && ((*data).state.range).is_null()
    {
        if !Curl_meets_timecondition(data, (*k).timeofdoc) {
            *done = 1 as libc::c_int != 0;
            (*data).info.httpcode = 304 as libc::c_int;
            Curl_infof(
                data,
                b"Simulate a HTTP 304 response!\0" as *const u8 as *const libc::c_char,
            );
            Curl_conncontrol(conn, 1 as libc::c_int);
            return CURLE_OK;
        }
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_transferencode(mut data: *mut Curl_easy) -> CURLcode {
    if (Curl_checkheaders(data, b"TE\0" as *const u8 as *const libc::c_char)).is_null()
        && ((*data).set).http_transfer_encoding() as libc::c_int != 0
    {
        let mut cptr: *mut libc::c_char = Curl_checkheaders(
            data,
            b"Connection\0" as *const u8 as *const libc::c_char,
        );
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.aptr.te as *mut libc::c_void);
        let ref mut fresh69 = (*data).state.aptr.te;
        *fresh69 = 0 as *mut libc::c_char;
        if !cptr.is_null() {
            cptr = Curl_copy_header_value(cptr);
            if cptr.is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        }
        let ref mut fresh70 = (*data).state.aptr.te;
        *fresh70 = curl_maprintf(
            b"Connection: %s%sTE\r\nTE: gzip\r\n\0" as *const u8 as *const libc::c_char,
            if !cptr.is_null() {
                cptr as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            if !cptr.is_null() && *cptr as libc::c_int != 0 {
                b", \0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
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
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut result: CURLcode = CURLE_OK;
    let mut http: *mut HTTP = 0 as *mut HTTP;
    let mut httpreq: Curl_HttpReq = HTTPREQ_GET;
    let mut te: *const libc::c_char = b"\0" as *const u8 as *const libc::c_char;
    let mut request: *const libc::c_char = 0 as *const libc::c_char;
    let mut httpstring: *const libc::c_char = 0 as *const libc::c_char;
    let mut req: dynbuf = dynbuf {
        bufr: 0 as *mut libc::c_char,
        leng: 0,
        allc: 0,
        toobig: 0,
    };
    let mut altused: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p_accept: *const libc::c_char = 0 as *const libc::c_char;
    *done = 1 as libc::c_int != 0;
    if (*conn).transport as libc::c_uint != TRNSPRT_QUIC as libc::c_int as libc::c_uint {
        if ((*conn).httpversion as libc::c_int) < 20 as libc::c_int {
            match (*conn).negnpn {
                3 => {
                    (*conn).httpversion = 20 as libc::c_int as libc::c_uchar;
                    result = Curl_http2_switched(
                        data,
                        0 as *const libc::c_char,
                        0 as libc::c_int as size_t,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                }
                2 => {}
                _ => {
                    if (*data).state.httpwant as libc::c_int
                        == CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE as libc::c_int
                    {
                        if ((*conn).bits).httpproxy() as libc::c_int != 0
                            && ((*conn).bits).tunnel_proxy() == 0
                        {
                            Curl_infof(
                                data,
                                b"Ignoring HTTP/2 prior knowledge due to proxy\0"
                                    as *const u8 as *const libc::c_char,
                            );
                        } else {
                            (*conn).httpversion = 20 as libc::c_int as libc::c_uchar;
                            result = Curl_http2_switched(
                                data,
                                0 as *const libc::c_char,
                                0 as libc::c_int as size_t,
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
    Curl_http_method(data, conn, &mut request, &mut httpreq);
    let mut pq: *mut libc::c_char = 0 as *mut libc::c_char;
    if !((*data).state.up.query).is_null() {
        pq = curl_maprintf(
            b"%s?%s\0" as *const u8 as *const libc::c_char,
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
        0 as libc::c_int != 0,
    );
    Curl_cfree.expect("non-null function pointer")(pq as *mut libc::c_void);
    if result as u64 != 0 {
        return result;
    }
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.ref_0 as *mut libc::c_void);
    let ref mut fresh71 = (*data).state.aptr.ref_0;
    *fresh71 = 0 as *mut libc::c_char;
    if !((*data).state.referer).is_null()
        && (Curl_checkheaders(data, b"Referer\0" as *const u8 as *const libc::c_char))
            .is_null()
    {
        let ref mut fresh72 = (*data).state.aptr.ref_0;
        *fresh72 = curl_maprintf(
            b"Referer: %s\r\n\0" as *const u8 as *const libc::c_char,
            (*data).state.referer,
        );
        if ((*data).state.aptr.ref_0).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if (Curl_checkheaders(
        data,
        b"Accept-Encoding\0" as *const u8 as *const libc::c_char,
    ))
        .is_null()
        && !((*data).set.str_0[STRING_ENCODING as libc::c_int as usize]).is_null()
    {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.aptr.accept_encoding as *mut libc::c_void);
        let ref mut fresh73 = (*data).state.aptr.accept_encoding;
        *fresh73 = 0 as *mut libc::c_char;
        let ref mut fresh74 = (*data).state.aptr.accept_encoding;
        *fresh74 = curl_maprintf(
            b"Accept-Encoding: %s\r\n\0" as *const u8 as *const libc::c_char,
            (*data).set.str_0[STRING_ENCODING as libc::c_int as usize],
        );
        if ((*data).state.aptr.accept_encoding).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    } else {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.aptr.accept_encoding as *mut libc::c_void);
        let ref mut fresh75 = (*data).state.aptr.accept_encoding;
        *fresh75 = 0 as *mut libc::c_char;
    }
    result = Curl_transferencode(data);
    if result as u64 != 0 {
        return result;
    }
    result = Curl_http_body(data, conn, httpreq, &mut te);
    if result as u64 != 0 {
        return result;
    }
    p_accept = if !(Curl_checkheaders(
        data,
        b"Accept\0" as *const u8 as *const libc::c_char,
    ))
        .is_null()
    {
        0 as *const libc::c_char
    } else {
        b"Accept: */*\r\n\0" as *const u8 as *const libc::c_char
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
    Curl_dyn_init(&mut req, (1024 as libc::c_int * 1024 as libc::c_int) as size_t);
    Curl_dyn_reset(&mut (*data).state.headerb);
    result = Curl_dyn_addf(
        &mut req as *mut dynbuf,
        b"%s \0" as *const u8 as *const libc::c_char,
        request,
    );
    if result as u64 == 0 {
        result = Curl_http_target(data, conn, &mut req);
    }
    if result as u64 != 0 {
        Curl_dyn_free(&mut req);
        return result;
    }
    if ((*conn).bits).altused() as libc::c_int != 0
        && (Curl_checkheaders(data, b"Alt-Used\0" as *const u8 as *const libc::c_char))
            .is_null()
    {
        altused = curl_maprintf(
            b"Alt-Used: %s:%d\r\n\0" as *const u8 as *const libc::c_char,
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
        b" HTTP/%s\r\n%s%s%s%s%s%s%s%s%s%s%s%s\0" as *const u8 as *const libc::c_char,
        httpstring,
        if !((*data).state.aptr.host).is_null() {
            (*data).state.aptr.host as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*data).state.aptr.proxyuserpwd).is_null() {
            (*data).state.aptr.proxyuserpwd as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*data).state.aptr.userpwd).is_null() {
            (*data).state.aptr.userpwd as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if ((*data).state).use_range() as libc::c_int != 0
            && !((*data).state.aptr.rangeline).is_null()
        {
            (*data).state.aptr.rangeline as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*data).set.str_0[STRING_USERAGENT as libc::c_int as usize]).is_null()
            && *(*data).set.str_0[STRING_USERAGENT as libc::c_int as usize]
                as libc::c_int != 0 && !((*data).state.aptr.uagent).is_null()
        {
            (*data).state.aptr.uagent as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !p_accept.is_null() {
            p_accept
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*data).state.aptr.te).is_null() {
            (*data).state.aptr.te as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*data).set.str_0[STRING_ENCODING as libc::c_int as usize]).is_null()
            && *(*data).set.str_0[STRING_ENCODING as libc::c_int as usize] as libc::c_int
                != 0 && !((*data).state.aptr.accept_encoding).is_null()
        {
            (*data).state.aptr.accept_encoding as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*data).state.referer).is_null() && !((*data).state.aptr.ref_0).is_null() {
            (*data).state.aptr.ref_0 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if ((*conn).bits).httpproxy() as libc::c_int != 0
            && ((*conn).bits).tunnel_proxy() == 0
            && (Curl_checkheaders(
                data,
                b"Proxy-Connection\0" as *const u8 as *const libc::c_char,
            ))
                .is_null()
            && (Curl_checkProxyheaders(
                data,
                conn,
                b"Proxy-Connection\0" as *const u8 as *const libc::c_char,
            ))
                .is_null()
        {
            b"Proxy-Connection: Keep-Alive\r\n\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        te,
        if !altused.is_null() {
            altused as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.userpwd as *mut libc::c_void);
    let ref mut fresh76 = (*data).state.aptr.userpwd;
    *fresh76 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.proxyuserpwd as *mut libc::c_void);
    let ref mut fresh77 = (*data).state.aptr.proxyuserpwd;
    *fresh77 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")(altused as *mut libc::c_void);
    if result as u64 != 0 {
        Curl_dyn_free(&mut req);
        return result;
    }
    if (*(*conn).handler).flags
        & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint == 0
        && (*conn).httpversion as libc::c_int != 20 as libc::c_int
        && (*data).state.httpwant as libc::c_int == CURL_HTTP_VERSION_2_0 as libc::c_int
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
        result = Curl_add_custom_headers(data, 0 as libc::c_int != 0, &mut req);
    }
    if result as u64 == 0 {
        let ref mut fresh78 = (*http).postdata;
        *fresh78 = 0 as *const libc::c_char;
        if httpreq as libc::c_uint == HTTPREQ_GET as libc::c_int as libc::c_uint
            || httpreq as libc::c_uint == HTTPREQ_HEAD as libc::c_int as libc::c_uint
        {
            Curl_pgrsSetUploadSize(data, 0 as libc::c_int as curl_off_t);
        }
        result = Curl_http_bodysend(data, conn, &mut req, httpreq);
    }
    if result as u64 != 0 {
        Curl_dyn_free(&mut req);
        return result;
    }
    if (*http).postsize > -(1 as libc::c_int) as libc::c_long
        && (*http).postsize <= (*data).req.writebytecount
        && (*http).sending as libc::c_uint
            != HTTPSEND_REQUEST as libc::c_int as libc::c_uint
    {
        let ref mut fresh79 = (*data).req;
        (*fresh79).set_upload_done(1 as libc::c_int as bit);
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
                    as *const libc::c_char,
                (*data).req.writebytecount,
                (*http).postsize,
            );
            let ref mut fresh80 = (*data).req;
            (*fresh80).set_upload_done(1 as libc::c_int as bit);
            (*data).req.keepon &= !((1 as libc::c_int) << 1 as libc::c_int);
            (*data).req.exp100 = EXP100_SEND_DATA;
            Curl_expire_done(data, EXPIRE_100_TIMEOUT);
        }
    }
    if (*conn).httpversion as libc::c_int == 20 as libc::c_int
        && ((*data).req).upload_chunky() as libc::c_int != 0
    {
        let ref mut fresh81 = (*data).req;
        (*fresh81).set_upload_chunky(0 as libc::c_int as bit);
    }
    return result;
}
unsafe extern "C" fn checkprefixmax(
    mut prefix: *const libc::c_char,
    mut buffer: *const libc::c_char,
    mut len: size_t,
) -> bool {
    let mut ch: size_t = if strlen(prefix) < len { strlen(prefix) } else { len };
    return curl_strnequal(prefix, buffer, ch) != 0;
}
unsafe extern "C" fn checkhttpprefix(
    mut data: *mut Curl_easy,
    mut s: *const libc::c_char,
    mut len: size_t,
) -> statusline {
    let mut head: *mut curl_slist = (*data).set.http200aliases;
    let mut rc: statusline = STATUS_BAD;
    let mut onmatch: statusline = (if len >= 5 as libc::c_int as libc::c_ulong {
        STATUS_DONE as libc::c_int
    } else {
        STATUS_UNKNOWN as libc::c_int
    }) as statusline;
    while !head.is_null() {
        if checkprefixmax((*head).data, s, len) {
            rc = onmatch;
            break;
        } else {
            head = (*head).next;
        }
    }
    if rc as libc::c_uint != STATUS_DONE as libc::c_int as libc::c_uint
        && checkprefixmax(b"HTTP/\0" as *const u8 as *const libc::c_char, s, len)
            as libc::c_int != 0
    {
        rc = onmatch;
    }
    return rc;
}
unsafe extern "C" fn checkrtspprefix(
    mut data: *mut Curl_easy,
    mut s: *const libc::c_char,
    mut len: size_t,
) -> statusline {
    let mut result: statusline = STATUS_BAD;
    let mut onmatch: statusline = (if len >= 5 as libc::c_int as libc::c_ulong {
        STATUS_DONE as libc::c_int
    } else {
        STATUS_UNKNOWN as libc::c_int
    }) as statusline;
    if checkprefixmax(b"RTSP/\0" as *const u8 as *const libc::c_char, s, len) {
        result = onmatch;
    }
    return result;
}
unsafe extern "C" fn checkprotoprefix(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut s: *const libc::c_char,
    mut len: size_t,
) -> statusline {
    if (*(*conn).handler).protocol
        & ((1 as libc::c_int) << 18 as libc::c_int) as libc::c_uint != 0
    {
        return checkrtspprefix(data, s, len);
    }
    return checkhttpprefix(data, s, len);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_header(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut headp: *mut libc::c_char,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut k: *mut SingleRequest = &mut (*data).req;
    if (*k).http_bodyless() == 0 && ((*data).set).ignorecl() == 0
        && curl_strnequal(
            b"Content-Length:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Content-Length:\0" as *const u8 as *const libc::c_char),
        ) != 0
    {
        let mut contentlength: curl_off_t = 0;
        let mut offt: CURLofft = curlx_strtoofft(
            headp
                .offset(
                    strlen(b"Content-Length:\0" as *const u8 as *const libc::c_char)
                        as isize,
                ),
            0 as *mut *mut libc::c_char,
            10 as libc::c_int,
            &mut contentlength,
        );
        if offt as libc::c_uint == CURL_OFFT_OK as libc::c_int as libc::c_uint {
            (*k).size = contentlength;
            (*k).maxdownload = (*k).size;
        } else if offt as libc::c_uint == CURL_OFFT_FLOW as libc::c_int as libc::c_uint {
            if (*data).set.max_filesize != 0 {
                Curl_failf(
                    data,
                    b"Maximum file size exceeded\0" as *const u8 as *const libc::c_char,
                );
                return CURLE_FILESIZE_EXCEEDED;
            }
            Curl_conncontrol(conn, 2 as libc::c_int);
            Curl_infof(
                data,
                b"Overflow Content-Length: value!\0" as *const u8 as *const libc::c_char,
            );
        } else {
            Curl_failf(
                data,
                b"Invalid Content-Length: value\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_WEIRD_SERVER_REPLY;
        }
    } else if curl_strnequal(
            b"Content-Type:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Content-Type:\0" as *const u8 as *const libc::c_char),
        ) != 0
        {
        let mut contenttype: *mut libc::c_char = Curl_copy_header_value(headp);
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
            let ref mut fresh82 = (*data).info.contenttype;
            *fresh82 = 0 as *mut libc::c_char;
            let ref mut fresh83 = (*data).info.contenttype;
            *fresh83 = contenttype;
        }
    } else if (*conn).httpversion as libc::c_int == 10 as libc::c_int
            && ((*conn).bits).httpproxy() as libc::c_int != 0
            && Curl_compareheader(
                headp,
                b"Proxy-Connection:\0" as *const u8 as *const libc::c_char,
                b"keep-alive\0" as *const u8 as *const libc::c_char,
            ) as libc::c_int != 0
        {
        Curl_conncontrol(conn, 0 as libc::c_int);
        Curl_infof(
            data,
            b"HTTP/1.0 proxy connection set to keep alive!\0" as *const u8
                as *const libc::c_char,
        );
    } else if (*conn).httpversion as libc::c_int == 11 as libc::c_int
            && ((*conn).bits).httpproxy() as libc::c_int != 0
            && Curl_compareheader(
                headp,
                b"Proxy-Connection:\0" as *const u8 as *const libc::c_char,
                b"close\0" as *const u8 as *const libc::c_char,
            ) as libc::c_int != 0
        {
        Curl_conncontrol(conn, 1 as libc::c_int);
        Curl_infof(
            data,
            b"HTTP/1.1 proxy connection set close!\0" as *const u8 as *const libc::c_char,
        );
    } else if (*conn).httpversion as libc::c_int == 10 as libc::c_int
            && Curl_compareheader(
                headp,
                b"Connection:\0" as *const u8 as *const libc::c_char,
                b"keep-alive\0" as *const u8 as *const libc::c_char,
            ) as libc::c_int != 0
        {
        Curl_conncontrol(conn, 0 as libc::c_int);
        Curl_infof(
            data,
            b"HTTP/1.0 connection set to keep alive!\0" as *const u8
                as *const libc::c_char,
        );
    } else if Curl_compareheader(
            headp,
            b"Connection:\0" as *const u8 as *const libc::c_char,
            b"close\0" as *const u8 as *const libc::c_char,
        ) {
        Curl_conncontrol(conn, 2 as libc::c_int);
    } else if (*k).http_bodyless() == 0
            && curl_strnequal(
                b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char,
                headp,
                strlen(b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char),
            ) != 0
        {
        result = Curl_build_unencoding_stack(
            data,
            headp
                .offset(
                    strlen(b"Transfer-Encoding:\0" as *const u8 as *const libc::c_char)
                        as isize,
                ),
            1 as libc::c_int,
        );
        if result as u64 != 0 {
            return result;
        }
        if (*k).chunk() == 0 {
            Curl_conncontrol(conn, 1 as libc::c_int);
            (*k).set_ignore_cl(1 as libc::c_int as bit);
        }
    } else if (*k).http_bodyless() == 0
            && curl_strnequal(
                b"Content-Encoding:\0" as *const u8 as *const libc::c_char,
                headp,
                strlen(b"Content-Encoding:\0" as *const u8 as *const libc::c_char),
            ) != 0
            && !((*data).set.str_0[STRING_ENCODING as libc::c_int as usize]).is_null()
        {
        result = Curl_build_unencoding_stack(
            data,
            headp
                .offset(
                    strlen(b"Content-Encoding:\0" as *const u8 as *const libc::c_char)
                        as isize,
                ),
            0 as libc::c_int,
        );
        if result as u64 != 0 {
            return result;
        }
    } else if curl_strnequal(
            b"Retry-After:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"Retry-After:\0" as *const u8 as *const libc::c_char),
        ) != 0
        {
        let mut retry_after: curl_off_t = 0 as libc::c_int as curl_off_t;
        let mut date: time_t = Curl_getdate_capped(
            headp
                .offset(
                    strlen(b"Retry-After:\0" as *const u8 as *const libc::c_char)
                        as isize,
                ),
        );
        if -(1 as libc::c_int) as libc::c_long == date {
            curlx_strtoofft(
                headp
                    .offset(
                        strlen(b"Retry-After:\0" as *const u8 as *const libc::c_char)
                            as isize,
                    ),
                0 as *mut *mut libc::c_char,
                10 as libc::c_int,
                &mut retry_after,
            );
        } else {
            retry_after = date - time(0 as *mut time_t);
        }
        (*data).info.retry_after = retry_after;
    } else if (*k).http_bodyless() == 0
            && curl_strnequal(
                b"Content-Range:\0" as *const u8 as *const libc::c_char,
                headp,
                strlen(b"Content-Range:\0" as *const u8 as *const libc::c_char),
            ) != 0
        {
        let mut ptr: *mut libc::c_char = headp
            .offset(
                strlen(b"Content-Range:\0" as *const u8 as *const libc::c_char) as isize,
            );
        while *ptr as libc::c_int != 0
            && Curl_isdigit(*ptr as libc::c_uchar as libc::c_int) == 0
            && *ptr as libc::c_int != '*' as i32
        {
            ptr = ptr.offset(1);
        }
        if Curl_isdigit(*ptr as libc::c_uchar as libc::c_int) != 0 {
            if curlx_strtoofft(
                ptr,
                0 as *mut *mut libc::c_char,
                10 as libc::c_int,
                &mut (*k).offset,
            ) as u64 == 0
            {
                if (*data).state.resume_from == (*k).offset {
                    (*k).set_content_range(1 as libc::c_int as bit);
                }
            }
        } else {
            (*data).state.resume_from = 0 as libc::c_int as curl_off_t;
        }
    } else if !((*data).cookies).is_null()
            && ((*data).state).cookie_engine() as libc::c_int != 0
            && curl_strnequal(
                b"Set-Cookie:\0" as *const u8 as *const libc::c_char,
                headp,
                strlen(b"Set-Cookie:\0" as *const u8 as *const libc::c_char),
            ) != 0
        {
        let mut host: *const libc::c_char = if !((*data).state.aptr.cookiehost).is_null()
        {
            (*data).state.aptr.cookiehost
        } else {
            (*conn).host.name
        };
        let secure_context: bool = if (*(*conn).handler).protocol
            & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint != 0
            || Curl_strcasecompare(
                b"localhost\0" as *const u8 as *const libc::c_char,
                host,
            ) != 0
            || strcmp(host, b"127.0.0.1\0" as *const u8 as *const libc::c_char) == 0
            || strcmp(host, b"[::1]\0" as *const u8 as *const libc::c_char) == 0
        {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        } != 0;
        Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
        Curl_cookie_add(
            data,
            (*data).cookies,
            1 as libc::c_int != 0,
            0 as libc::c_int != 0,
            headp
                .offset(
                    strlen(b"Set-Cookie:\0" as *const u8 as *const libc::c_char) as isize,
                ),
            host,
            (*data).state.up.path,
            secure_context,
        );
        Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
    } else if (*k).http_bodyless() == 0
            && curl_strnequal(
                b"Last-Modified:\0" as *const u8 as *const libc::c_char,
                headp,
                strlen(b"Last-Modified:\0" as *const u8 as *const libc::c_char),
            ) != 0
            && ((*data).set.timecondition as libc::c_uint != 0
                || ((*data).set).get_filetime() as libc::c_int != 0)
        {
        (*k)
            .timeofdoc = Curl_getdate_capped(
            headp
                .offset(
                    strlen(b"Last-Modified:\0" as *const u8 as *const libc::c_char)
                        as isize,
                ),
        );
        if ((*data).set).get_filetime() != 0 {
            (*data).info.filetime = (*k).timeofdoc;
        }
    } else if curl_strnequal(
            b"WWW-Authenticate:\0" as *const u8 as *const libc::c_char,
            headp,
            strlen(b"WWW-Authenticate:\0" as *const u8 as *const libc::c_char),
        ) != 0 && 401 as libc::c_int == (*k).httpcode
            || curl_strnequal(
                b"Proxy-authenticate:\0" as *const u8 as *const libc::c_char,
                headp,
                strlen(b"Proxy-authenticate:\0" as *const u8 as *const libc::c_char),
            ) != 0 && 407 as libc::c_int == (*k).httpcode
        {
        let mut proxy: bool = if (*k).httpcode == 407 as libc::c_int {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        } != 0;
        let mut auth: *mut libc::c_char = Curl_copy_header_value(headp);
        if auth.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        result = Curl_http_input_auth(data, proxy, auth);
        Curl_cfree.expect("non-null function pointer")(auth as *mut libc::c_void);
        if result as u64 != 0 {
            return result;
        }
    } else if (*k).httpcode >= 300 as libc::c_int && (*k).httpcode < 400 as libc::c_int
            && curl_strnequal(
                b"Location:\0" as *const u8 as *const libc::c_char,
                headp,
                strlen(b"Location:\0" as *const u8 as *const libc::c_char),
            ) != 0 && ((*data).req.location).is_null()
        {
        let mut location: *mut libc::c_char = Curl_copy_header_value(headp);
        if location.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if *location == 0 {
            Curl_cfree
                .expect("non-null function pointer")(location as *mut libc::c_void);
        } else {
            let ref mut fresh84 = (*data).req.location;
            *fresh84 = location;
            if ((*data).set).http_follow_location() != 0 {
                let ref mut fresh85 = (*data).req.newurl;
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
                b"Strict-Transport-Security:\0" as *const u8 as *const libc::c_char,
                headp,
                strlen(
                    b"Strict-Transport-Security:\0" as *const u8 as *const libc::c_char,
                ),
            ) != 0
            && (*(*conn).handler).flags
                & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0
        {
        let mut check: CURLcode = Curl_hsts_parse(
            (*data).hsts,
            (*data).state.up.hostname,
            headp
                .offset(
                    strlen(
                        b"Strict-Transport-Security:\0" as *const u8
                            as *const libc::c_char,
                    ) as isize,
                ),
        );
        if check as u64 != 0 {
            Curl_infof(
                data,
                b"Illegal STS header skipped\0" as *const u8 as *const libc::c_char,
            );
        }
    } else if !((*data).asi).is_null()
            && curl_strnequal(
                b"Alt-Svc:\0" as *const u8 as *const libc::c_char,
                headp,
                strlen(b"Alt-Svc:\0" as *const u8 as *const libc::c_char),
            ) != 0
            && ((*(*conn).handler).flags
                & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0
                || 0 as libc::c_int != 0)
        {
        let mut id: alpnid = (if (*conn).httpversion as libc::c_int == 20 as libc::c_int
        {
            ALPN_h2 as libc::c_int
        } else {
            ALPN_h1 as libc::c_int
        }) as alpnid;
        result = Curl_altsvc_parse(
            data,
            (*data).asi,
            headp
                .offset(
                    strlen(b"Alt-Svc:\0" as *const u8 as *const libc::c_char) as isize,
                ),
            id,
            (*conn).host.name,
            curlx_uitous((*conn).remote_port as libc::c_uint),
        );
        if result as u64 != 0 {
            return result;
        }
    } else if (*(*conn).handler).protocol
            & ((1 as libc::c_int) << 18 as libc::c_int) as libc::c_uint != 0
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
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut k: *mut SingleRequest = &mut (*data).req;
    (*data).info.httpcode = (*k).httpcode;
    (*data).info.httpversion = (*conn).httpversion as libc::c_int;
    if (*data).state.httpversion == 0
        || (*data).state.httpversion as libc::c_int > (*conn).httpversion as libc::c_int
    {
        (*data).state.httpversion = (*conn).httpversion;
    }
    if (*data).state.resume_from != 0
        && (*data).state.httpreq as libc::c_uint
            == HTTPREQ_GET as libc::c_int as libc::c_uint
        && (*k).httpcode == 416 as libc::c_int
    {
        (*k).set_ignorebody(1 as libc::c_int as bit);
    }
    if (*conn).httpversion as libc::c_int == 10 as libc::c_int {
        Curl_infof(
            data,
            b"HTTP 1.0, assume close after body\0" as *const u8 as *const libc::c_char,
        );
        Curl_conncontrol(conn, 1 as libc::c_int);
    } else if (*conn).httpversion as libc::c_int == 20 as libc::c_int
            || (*k).upgr101 as libc::c_uint
                == UPGR101_REQUESTED as libc::c_int as libc::c_uint
                && (*k).httpcode == 101 as libc::c_int
        {
        (*(*conn).bundle).multiuse = 2 as libc::c_int;
    } else {
        (*conn).httpversion as libc::c_int >= 11 as libc::c_int
            && ((*conn).bits).close() == 0;
    }
    (*k)
        .set_http_bodyless(
            ((*k).httpcode >= 100 as libc::c_int && (*k).httpcode < 200 as libc::c_int)
                as libc::c_int as bit,
        );
    let mut current_block_25: u64;
    match (*k).httpcode {
        304 => {
            if (*data).set.timecondition as u64 != 0 {
                let ref mut fresh86 = (*data).info;
                (*fresh86).set_timecond(1 as libc::c_int as bit);
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
            (*k).size = 0 as libc::c_int as curl_off_t;
            (*k).maxdownload = 0 as libc::c_int as curl_off_t;
            (*k).set_http_bodyless(1 as libc::c_int as bit);
        }
        _ => {}
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_http_readwrite_headers(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut nread: *mut ssize_t,
    mut stop_reading: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut k: *mut SingleRequest = &mut (*data).req;
    let mut onread: ssize_t = *nread;
    let mut ostr: *mut libc::c_char = (*k).str_0;
    let mut headp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut str_start: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut end_ptr: *mut libc::c_char = 0 as *mut libc::c_char;
    loop {
        let mut rest_length: size_t = 0;
        let mut full_length: size_t = 0;
        let mut writetype: libc::c_int = 0;
        str_start = (*k).str_0;
        end_ptr = memchr(
            str_start as *const libc::c_void,
            0xa as libc::c_int,
            *nread as libc::c_ulong,
        ) as *mut libc::c_char;
        if end_ptr.is_null() {
            result = Curl_dyn_addn(
                &mut (*data).state.headerb,
                str_start as *const libc::c_void,
                *nread as size_t,
            );
            if result as u64 != 0 {
                return result;
            }
            if !((*k).headerline == 0) {
                break;
            }
            let mut st: statusline = checkprotoprefix(
                data,
                conn,
                Curl_dyn_ptr(&mut (*data).state.headerb),
                Curl_dyn_len(&mut (*data).state.headerb),
            );
            if !(st as libc::c_uint == STATUS_BAD as libc::c_int as libc::c_uint) {
                break;
            }
            (*k).set_header(0 as libc::c_int as bit);
            (*k).badheader = HEADER_ALLBAD;
            Curl_conncontrol(conn, 2 as libc::c_int);
            if ((*data).set).http09_allowed() == 0 {
                Curl_failf(
                    data,
                    b"Received HTTP/0.9 when not allowed\0" as *const u8
                        as *const libc::c_char,
                );
                return CURLE_UNSUPPORTED_PROTOCOL;
            }
            break;
        } else {
            rest_length = (end_ptr.offset_from((*k).str_0) as libc::c_long
                + 1 as libc::c_int as libc::c_long) as size_t;
            *nread -= rest_length as ssize_t;
            let ref mut fresh87 = (*k).str_0;
            *fresh87 = end_ptr.offset(1 as libc::c_int as isize);
            full_length = ((*k).str_0).offset_from(str_start) as libc::c_long as size_t;
            result = Curl_dyn_addn(
                &mut (*data).state.headerb,
                str_start as *const libc::c_void,
                full_length,
            );
            if result as u64 != 0 {
                return result;
            }
            if (*k).headerline == 0 {
                let mut st_0: statusline = checkprotoprefix(
                    data,
                    conn,
                    Curl_dyn_ptr(&mut (*data).state.headerb),
                    Curl_dyn_len(&mut (*data).state.headerb),
                );
                if st_0 as libc::c_uint == STATUS_BAD as libc::c_int as libc::c_uint {
                    Curl_conncontrol(conn, 2 as libc::c_int);
                    if ((*data).set).http09_allowed() == 0 {
                        Curl_failf(
                            data,
                            b"Received HTTP/0.9 when not allowed\0" as *const u8
                                as *const libc::c_char,
                        );
                        return CURLE_UNSUPPORTED_PROTOCOL;
                    }
                    (*k).set_header(0 as libc::c_int as bit);
                    if *nread != 0 {
                        (*k).badheader = HEADER_PARTHEADER;
                    } else {
                        (*k).badheader = HEADER_ALLBAD;
                        *nread = onread;
                        let ref mut fresh88 = (*k).str_0;
                        *fresh88 = ostr;
                        return CURLE_OK;
                    }
                    break;
                }
            }
            headp = Curl_dyn_ptr(&mut (*data).state.headerb);
            if 0xa as libc::c_int == *headp as libc::c_int
                || 0xd as libc::c_int == *headp as libc::c_int
            {
                let mut headerlen: size_t = 0;
                if '\r' as i32 == *headp as libc::c_int {
                    headp = headp.offset(1);
                }
                if '\n' as i32 == *headp as libc::c_int {
                    headp = headp.offset(1);
                }
                if 100 as libc::c_int <= (*k).httpcode
                    && 199 as libc::c_int >= (*k).httpcode
                {
                    match (*k).httpcode {
                        100 => {
                            (*k).set_header(1 as libc::c_int as bit);
                            (*k).headerline = 0 as libc::c_int;
                            if (*k).exp100 as libc::c_uint
                                > EXP100_SEND_DATA as libc::c_int as libc::c_uint
                            {
                                (*k).exp100 = EXP100_SEND_DATA;
                                (*k).keepon |= (1 as libc::c_int) << 1 as libc::c_int;
                                Curl_expire_done(data, EXPIRE_100_TIMEOUT);
                            }
                        }
                        101 => {
                            if (*k).upgr101 as libc::c_uint
                                == UPGR101_REQUESTED as libc::c_int as libc::c_uint
                            {
                                Curl_infof(
                                    data,
                                    b"Received 101\0" as *const u8 as *const libc::c_char,
                                );
                                (*k).upgr101 = UPGR101_RECEIVED;
                                (*k).set_header(1 as libc::c_int as bit);
                                (*k).headerline = 0 as libc::c_int;
                                result = Curl_http2_switched(
                                    data,
                                    (*k).str_0,
                                    *nread as size_t,
                                );
                                if result as u64 != 0 {
                                    return result;
                                }
                                *nread = 0 as libc::c_int as ssize_t;
                            } else {
                                (*k).set_header(0 as libc::c_int as bit);
                            }
                        }
                        _ => {
                            (*k).set_header(1 as libc::c_int as bit);
                            (*k).headerline = 0 as libc::c_int;
                        }
                    }
                } else {
                    (*k).set_header(0 as libc::c_int as bit);
                    if (*k).size == -(1 as libc::c_int) as libc::c_long
                        && (*k).chunk() == 0 && ((*conn).bits).close() == 0
                        && (*conn).httpversion as libc::c_int == 11 as libc::c_int
                        && (*(*conn).handler).protocol
                            & ((1 as libc::c_int) << 18 as libc::c_int) as libc::c_uint
                            == 0
                        && (*data).state.httpreq as libc::c_uint
                            != HTTPREQ_HEAD as libc::c_int as libc::c_uint
                    {
                        Curl_infof(
                            data,
                            b"no chunk, no close, no size. Assume close to signal end\0"
                                as *const u8 as *const libc::c_char,
                        );
                        Curl_conncontrol(conn, 2 as libc::c_int);
                    }
                }
                if ((*conn).bits).close() as libc::c_int != 0
                    && ((*data).req.httpcode == 401 as libc::c_int
                        && (*conn).http_ntlm_state as libc::c_uint
                            == NTLMSTATE_TYPE2 as libc::c_int as libc::c_uint
                        || (*data).req.httpcode == 407 as libc::c_int
                            && (*conn).proxy_ntlm_state as libc::c_uint
                                == NTLMSTATE_TYPE2 as libc::c_int as libc::c_uint)
                {
                    Curl_infof(
                        data,
                        b"Connection closure while negotiating auth (HTTP 1.0?)\0"
                            as *const u8 as *const libc::c_char,
                    );
                    let ref mut fresh89 = (*data).state;
                    (*fresh89).set_authproblem(1 as libc::c_int as bit);
                }
                writetype = (1 as libc::c_int) << 1 as libc::c_int;
                if ((*data).set).include_header() != 0 {
                    writetype |= (1 as libc::c_int) << 0 as libc::c_int;
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
                let ref mut fresh90 = (*data).info.header_size;
                *fresh90 += headerlen as libc::c_long;
                let ref mut fresh91 = (*data).req.headerbytecount;
                *fresh91 += headerlen as libc::c_long;
                if http_should_fail(data) {
                    Curl_failf(
                        data,
                        b"The requested URL returned error: %d\0" as *const u8
                            as *const libc::c_char,
                        (*k).httpcode,
                    );
                    return CURLE_HTTP_RETURNED_ERROR;
                }
                (*data)
                    .req
                    .deductheadercount = if 100 as libc::c_int <= (*k).httpcode
                    && 199 as libc::c_int >= (*k).httpcode
                {
                    (*data).req.headerbytecount
                } else {
                    0 as libc::c_int as libc::c_long
                };
                result = Curl_http_auth_act(data);
                if result as u64 != 0 {
                    return result;
                }
                if (*k).httpcode >= 300 as libc::c_int {
                    if ((*conn).bits).authneg() == 0 && ((*conn).bits).close() == 0
                        && ((*conn).bits).rewindaftersend() == 0
                    {
                        match (*data).state.httpreq as libc::c_uint {
                            4 | 1 | 2 | 3 => {
                                Curl_expire_done(data, EXPIRE_100_TIMEOUT);
                                if (*k).upload_done() == 0 {
                                    if (*k).httpcode == 417 as libc::c_int
                                        && ((*data).state).expect100header() as libc::c_int != 0
                                    {
                                        Curl_infof(
                                            data,
                                            b"Got 417 while waiting for a 100\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                        let ref mut fresh92 = (*data).state;
                                        (*fresh92).set_disableexpect(1 as libc::c_int as bit);
                                        let ref mut fresh93 = (*data).req.newurl;
                                        *fresh93 = Curl_cstrdup
                                            .expect("non-null function pointer")((*data).state.url);
                                        Curl_done_sending(data, k);
                                    } else if ((*data).set).http_keep_sending_on_error() != 0 {
                                        Curl_infof(
                                            data,
                                            b"HTTP error before end of send, keep sending\0"
                                                as *const u8 as *const libc::c_char,
                                        );
                                        if (*k).exp100 as libc::c_uint
                                            > EXP100_SEND_DATA as libc::c_int as libc::c_uint
                                        {
                                            (*k).exp100 = EXP100_SEND_DATA;
                                            (*k).keepon |= (1 as libc::c_int) << 1 as libc::c_int;
                                        }
                                    } else {
                                        Curl_infof(
                                            data,
                                            b"HTTP error before end of send, stop sending\0"
                                                as *const u8 as *const libc::c_char,
                                        );
                                        Curl_conncontrol(conn, 2 as libc::c_int);
                                        result = Curl_done_sending(data, k);
                                        if result as u64 != 0 {
                                            return result;
                                        }
                                        (*k).set_upload_done(1 as libc::c_int as bit);
                                        if ((*data).state).expect100header() != 0 {
                                            (*k).exp100 = EXP100_FAILED;
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
                                as *const libc::c_char,
                        );
                        (*k).keepon |= (1 as libc::c_int) << 1 as libc::c_int;
                    }
                }
                if (*k).header() == 0 {
                    if ((*data).set).opt_no_body() != 0 {
                        *stop_reading = 1 as libc::c_int != 0;
                    } else if (*(*conn).handler).protocol
                            & ((1 as libc::c_int) << 18 as libc::c_int) as libc::c_uint
                            != 0
                            && (*data).set.rtspreq as libc::c_uint
                                == RTSPREQ_DESCRIBE as libc::c_int as libc::c_uint
                            && (*k).size <= -(1 as libc::c_int) as libc::c_long
                        {
                        *stop_reading = 1 as libc::c_int != 0;
                    } else if (*k).chunk() != 0 {
                        let ref mut fresh94 = (*k).size;
                        *fresh94 = -(1 as libc::c_int) as curl_off_t;
                        (*k).maxdownload = *fresh94;
                    }
                    if -(1 as libc::c_int) as libc::c_long != (*k).size {
                        Curl_pgrsSetDownloadSize(data, (*k).size);
                        (*k).maxdownload = (*k).size;
                    }
                    if 0 as libc::c_int as libc::c_long == (*k).maxdownload
                        && !((*(*conn).handler).protocol
                            & ((1 as libc::c_int) << 0 as libc::c_int
                                | (1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
                            != 0
                            && (*conn).httpversion as libc::c_int == 20 as libc::c_int)
                    {
                        *stop_reading = 1 as libc::c_int != 0;
                    }
                    if *stop_reading {
                        (*k).keepon &= !((1 as libc::c_int) << 0 as libc::c_int);
                    }
                    Curl_debug(data, CURLINFO_HEADER_IN, str_start, headerlen);
                    break;
                } else {
                    Curl_dyn_reset(&mut (*data).state.headerb);
                }
            } else {
                let ref mut fresh95 = (*k).headerline;
                let fresh96 = *fresh95;
                *fresh95 = *fresh95 + 1;
                if fresh96 == 0 {
                    let mut httpversion_major: libc::c_int = 0;
                    let mut rtspversion_major: libc::c_int = 0;
                    let mut nc: libc::c_int = 0 as libc::c_int;
                    if (*(*conn).handler).protocol
                        & ((1 as libc::c_int) << 0 as libc::c_int
                            | (1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
                        != 0
                    {
                        let mut separator: libc::c_char = 0;
                        let mut twoorthree: [libc::c_char; 2] = [0; 2];
                        let mut httpversion: libc::c_int = 0 as libc::c_int;
                        let mut digit4: libc::c_char = 0 as libc::c_int as libc::c_char;
                        nc = sscanf(
                            headp,
                            b" HTTP/%1d.%1d%c%3d%c\0" as *const u8
                                as *const libc::c_char,
                            &mut httpversion_major as *mut libc::c_int,
                            &mut httpversion as *mut libc::c_int,
                            &mut separator as *mut libc::c_char,
                            &mut (*k).httpcode as *mut libc::c_int,
                            &mut digit4 as *mut libc::c_char,
                        );
                        if nc == 1 as libc::c_int
                            && httpversion_major >= 2 as libc::c_int
                            && 2 as libc::c_int
                                == sscanf(
                                    headp,
                                    b" HTTP/%1[23] %d\0" as *const u8 as *const libc::c_char,
                                    twoorthree.as_mut_ptr(),
                                    &mut (*k).httpcode as *mut libc::c_int,
                                )
                        {
                            (*conn).httpversion = 0 as libc::c_int as libc::c_uchar;
                            nc = 4 as libc::c_int;
                            separator = ' ' as i32 as libc::c_char;
                        } else if Curl_isdigit(digit4 as libc::c_uchar as libc::c_int)
                                != 0
                            {
                            Curl_failf(
                                data,
                                b"Unsupported response code in HTTP response\0" as *const u8
                                    as *const libc::c_char,
                            );
                            return CURLE_UNSUPPORTED_PROTOCOL;
                        }
                        if nc >= 4 as libc::c_int
                            && ' ' as i32 == separator as libc::c_int
                        {
                            httpversion += 10 as libc::c_int * httpversion_major;
                            match httpversion {
                                10 | 11 | 20 => {
                                    (*conn).httpversion = httpversion as libc::c_uchar;
                                }
                                _ => {
                                    Curl_failf(
                                        data,
                                        b"Unsupported HTTP version (%u.%d) in response\0"
                                            as *const u8 as *const libc::c_char,
                                        httpversion / 10 as libc::c_int,
                                        httpversion % 10 as libc::c_int,
                                    );
                                    return CURLE_UNSUPPORTED_PROTOCOL;
                                }
                            }
                            if (*k).upgr101 as libc::c_uint
                                == UPGR101_RECEIVED as libc::c_int as libc::c_uint
                            {
                                if (*conn).httpversion as libc::c_int != 20 as libc::c_int {
                                    Curl_infof(
                                        data,
                                        b"Lying server, not serving HTTP/2\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                }
                            }
                            if ((*conn).httpversion as libc::c_int) < 20 as libc::c_int {
                                (*(*conn).bundle).multiuse = -(1 as libc::c_int);
                                Curl_infof(
                                    data,
                                    b"Mark bundle as not supporting multiuse\0" as *const u8
                                        as *const libc::c_char,
                                );
                            }
                        } else if nc == 0 {
                            nc = sscanf(
                                headp,
                                b" HTTP %3d\0" as *const u8 as *const libc::c_char,
                                &mut (*k).httpcode as *mut libc::c_int,
                            );
                            (*conn).httpversion = 10 as libc::c_int as libc::c_uchar;
                            if nc == 0 {
                                let mut check: statusline = checkhttpprefix(
                                    data,
                                    Curl_dyn_ptr(&mut (*data).state.headerb),
                                    Curl_dyn_len(&mut (*data).state.headerb),
                                );
                                if check as libc::c_uint
                                    == STATUS_DONE as libc::c_int as libc::c_uint
                                {
                                    nc = 1 as libc::c_int;
                                    (*k).httpcode = 200 as libc::c_int;
                                    (*conn).httpversion = 10 as libc::c_int as libc::c_uchar;
                                }
                            }
                        } else {
                            Curl_failf(
                                data,
                                b"Unsupported HTTP version in response\0" as *const u8
                                    as *const libc::c_char,
                            );
                            return CURLE_UNSUPPORTED_PROTOCOL;
                        }
                    } else if (*(*conn).handler).protocol
                            & ((1 as libc::c_int) << 18 as libc::c_int) as libc::c_uint
                            != 0
                        {
                        let mut separator_0: libc::c_char = 0;
                        let mut rtspversion: libc::c_int = 0;
                        nc = sscanf(
                            headp,
                            b" RTSP/%1d.%1d%c%3d\0" as *const u8 as *const libc::c_char,
                            &mut rtspversion_major as *mut libc::c_int,
                            &mut rtspversion as *mut libc::c_int,
                            &mut separator_0 as *mut libc::c_char,
                            &mut (*k).httpcode as *mut libc::c_int,
                        );
                        if nc == 4 as libc::c_int
                            && ' ' as i32 == separator_0 as libc::c_int
                        {
                            (*conn).httpversion = 11 as libc::c_int as libc::c_uchar;
                        } else {
                            nc = 0 as libc::c_int;
                        }
                    }
                    if nc != 0 {
                        result = Curl_http_statusline(data, conn);
                        if result as u64 != 0 {
                            return result;
                        }
                    } else {
                        (*k).set_header(0 as libc::c_int as bit);
                        break;
                    }
                }
                result = CURLE_OK as libc::c_int as CURLcode;
                if result as u64 != 0 {
                    return result;
                }
                result = Curl_http_header(data, conn, headp);
                if result as u64 != 0 {
                    return result;
                }
                writetype = (1 as libc::c_int) << 1 as libc::c_int;
                if ((*data).set).include_header() != 0 {
                    writetype |= (1 as libc::c_int) << 0 as libc::c_int;
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
                let ref mut fresh97 = (*data).info.header_size;
                *fresh97 = (*fresh97 as libc::c_ulong)
                    .wrapping_add(Curl_dyn_len(&mut (*data).state.headerb)) as curl_off_t
                    as curl_off_t;
                let ref mut fresh98 = (*data).req.headerbytecount;
                *fresh98 = (*fresh98 as libc::c_ulong)
                    .wrapping_add(Curl_dyn_len(&mut (*data).state.headerb)) as curl_off_t
                    as curl_off_t;
                Curl_dyn_reset(&mut (*data).state.headerb);
            }
            if !(*(*k).str_0 != 0) {
                break;
            }
        }
    }
    return CURLE_OK;
}
