use ::libc;
use ::c2rust_bitfields;
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
    pub type curl_pushheaders;
    pub type ldapconninfo;
    pub type tftp_state_data;
    pub type nghttp2_session;
    pub type Gsasl_session;
    pub type Gsasl;
    pub type ssl_backend_data;
    pub type ftp_parselist_data;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcpy(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strncpy(
        _: *mut libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> *mut libc::c_char;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn bind(__fd: libc::c_int, __addr: *const sockaddr, __len: socklen_t) -> libc::c_int;
    fn getsockname(
        __fd: libc::c_int,
        __addr: *mut sockaddr,
        __len: *mut socklen_t,
    ) -> libc::c_int;
    fn listen(__fd: libc::c_int, __n: libc::c_int) -> libc::c_int;
    fn accept(
        __fd: libc::c_int,
        __addr: *mut sockaddr,
        __addr_len: *mut socklen_t,
    ) -> libc::c_int;
    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn Curl_isdigit(c: libc::c_int) -> libc::c_int;
    fn strtol(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_long;
    fn strtoul(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_ulong;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strrchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strstr(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn __errno_location() -> *mut libc::c_int;
    fn curl_easy_strerror(_: CURLcode) -> *const libc::c_char;
    fn inet_pton(
        __af: libc::c_int,
        __cp: *const libc::c_char,
        __buf: *mut libc::c_void,
    ) -> libc::c_int;
    fn inet_ntop(
        __af: libc::c_int,
        __cp: *const libc::c_void,
        __buf: *mut libc::c_char,
        __len: socklen_t,
    ) -> *const libc::c_char;
    fn Curl_now() -> curltime;
    fn Curl_timediff(t1: curltime, t2: curltime) -> timediff_t;
    fn Curl_llist_remove(
        _: *mut Curl_llist,
        _: *mut Curl_llist_element,
        _: *mut libc::c_void,
    );
    fn Curl_resolver_wait_resolv(
        data: *mut Curl_easy,
        dnsentry: *mut *mut Curl_dns_entry,
    ) -> CURLcode;
    fn Curl_resolv(
        data: *mut Curl_easy,
        hostname: *const libc::c_char,
        port: libc::c_int,
        allowDOH: bool,
        dnsentry: *mut *mut Curl_dns_entry,
    ) -> resolve_t;
    fn Curl_resolv_unlock(data: *mut Curl_easy, dns: *mut Curl_dns_entry);
    fn Curl_printable_address(
        ip: *const Curl_addrinfo,
        buf: *mut libc::c_char,
        bufsize: size_t,
    );
    fn Curl_pp_statemach(
        data: *mut Curl_easy,
        pp: *mut pingpong,
        block: bool,
        disconnecting: bool,
    ) -> CURLcode;
    fn Curl_pp_init(data: *mut Curl_easy, pp: *mut pingpong);
    fn Curl_pp_setup(pp: *mut pingpong);
    fn Curl_pp_state_timeout(
        data: *mut Curl_easy,
        pp: *mut pingpong,
        disconnecting: bool,
    ) -> timediff_t;
    fn Curl_pp_sendf(
        data: *mut Curl_easy,
        pp: *mut pingpong,
        fmt: *const libc::c_char,
        _: ...
    ) -> CURLcode;
    fn Curl_pp_readresp(
        data: *mut Curl_easy,
        sockfd: curl_socket_t,
        pp: *mut pingpong,
        code: *mut libc::c_int,
        size: *mut size_t,
    ) -> CURLcode;
    fn Curl_pp_flushsend(data: *mut Curl_easy, pp: *mut pingpong) -> CURLcode;
    fn Curl_pp_disconnect(pp: *mut pingpong) -> CURLcode;
    fn Curl_pp_getsock(
        data: *mut Curl_easy,
        pp: *mut pingpong,
        socks: *mut curl_socket_t,
    ) -> libc::c_int;
    fn Curl_infof(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
    fn Curl_failf(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
    fn Curl_client_write(
        data: *mut Curl_easy,
        type_0: libc::c_int,
        ptr: *mut libc::c_char,
        len: size_t,
    ) -> CURLcode;
    fn Curl_ipv6_scope(sa: *const sockaddr) -> libc::c_uint;
    fn Curl_if2ip(
        af: libc::c_int,
        remote_scope: libc::c_uint,
        local_scope_id: libc::c_uint,
        interf: *const libc::c_char,
        buf: *mut libc::c_char,
        buf_size: libc::c_int,
    ) -> if2ip_result_t;
    fn Curl_pgrsSetDownloadSize(data: *mut Curl_easy, size: curl_off_t);
    fn Curl_pgrsSetUploadSize(data: *mut Curl_easy, size: curl_off_t);
    fn Curl_pgrsSetDownloadCounter(data: *mut Curl_easy, size: curl_off_t);
    fn Curl_pgrsSetUploadCounter(data: *mut Curl_easy, size: curl_off_t);
    fn Curl_pgrsUpdate(data: *mut Curl_easy) -> libc::c_int;
    fn Curl_pgrsTime(data: *mut Curl_easy, timer: timerid) -> curltime;
    fn Curl_setup_transfer(
        data: *mut Curl_easy,
        sockindex: libc::c_int,
        size: curl_off_t,
        getheader: bool,
        writesockindex: libc::c_int,
    );
    fn Curl_urldecode(
        data: *mut Curl_easy,
        string: *const libc::c_char,
        length: size_t,
        ostring: *mut *mut libc::c_char,
        olen: *mut size_t,
        ctrl: urlreject,
    ) -> CURLcode;
    fn Curl_ftp_parselist(
        buffer: *mut libc::c_char,
        size: size_t,
        nmemb: size_t,
        connptr: *mut libc::c_void,
    ) -> size_t;
    fn Curl_ftp_parselist_geterror(pl_data: *mut ftp_parselist_data) -> CURLcode;
    fn Curl_ftp_parselist_data_alloc() -> *mut ftp_parselist_data;
    fn Curl_ftp_parselist_data_free(pl_data: *mut *mut ftp_parselist_data);
    fn Curl_range(data: *mut Curl_easy) -> CURLcode;
    fn curlx_strtoofft(
        str: *const libc::c_char,
        endp: *mut *mut libc::c_char,
        base: libc::c_int,
        num: *mut curl_off_t,
    ) -> CURLofft;
    fn Curl_strcasecompare(
        first: *const libc::c_char,
        second: *const libc::c_char,
    ) -> libc::c_int;
    fn Curl_raw_toupper(in_0: libc::c_char) -> libc::c_char;
    fn Curl_ssl_connect(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        sockindex: libc::c_int,
    ) -> CURLcode;
    fn Curl_ssl_close(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        sockindex: libc::c_int,
    );
    fn Curl_ssl_shutdown(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        sockindex: libc::c_int,
    ) -> CURLcode;
    fn Curl_is_connected(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        sockindex: libc::c_int,
        connected: *mut bool,
    ) -> CURLcode;
    fn Curl_connecthost(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        host: *const Curl_dns_entry,
    ) -> CURLcode;
    fn Curl_timeleft(
        data: *mut Curl_easy,
        nowp: *mut curltime,
        duringconnect: bool,
    ) -> timediff_t;
    fn Curl_conninfo_remote(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        sockfd: curl_socket_t,
    );
    fn Curl_closesocket(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        sock: curl_socket_t,
    ) -> libc::c_int;
    fn Curl_socket(
        data: *mut Curl_easy,
        ai: *const Curl_addrinfo,
        addr: *mut Curl_sockaddr_ex,
        sockfd: *mut curl_socket_t,
    ) -> CURLcode;
    fn Curl_conncontrol(conn: *mut connectdata, closeit: libc::c_int);
    fn curlx_nonblock(sockfd: curl_socket_t, nonblock: libc::c_int) -> libc::c_int;
    fn Curl_conn_data_pending(conn: *mut connectdata, sockindex: libc::c_int) -> bool;
    fn Curl_strerror(
        err: libc::c_int,
        buf: *mut libc::c_char,
        buflen: size_t,
    ) -> *const libc::c_char;
    fn Curl_socket_check(
        readfd: curl_socket_t,
        readfd2: curl_socket_t,
        writefd: curl_socket_t,
        timeout_ms: timediff_t,
    ) -> libc::c_int;
    static Curl_wkday: [*const libc::c_char; 7];
    static Curl_month: [*const libc::c_char; 12];
    fn Curl_gmtime(intime: time_t, store: *mut tm) -> CURLcode;
    fn Curl_getdate_capped(p: *const libc::c_char) -> time_t;
    fn Curl_expire(data: *mut Curl_easy, milli: timediff_t, _: expire_id);
    fn Curl_set_in_callback(data: *mut Curl_easy, value: bool);
    fn curlx_ultous(ulnum: libc::c_ulong) -> libc::c_ushort;
    fn curlx_sltosi(slnum: libc::c_long) -> libc::c_int;
    fn curlx_sotouz(sonum: curl_off_t) -> size_t;
    fn Curl_proxyCONNECT(
        data: *mut Curl_easy,
        tunnelsocket: libc::c_int,
        hostname: *const libc::c_char,
        remote_port: libc::c_int,
    ) -> CURLcode;
    fn Curl_proxy_connect(data: *mut Curl_easy, sockindex: libc::c_int) -> CURLcode;
    fn Curl_connect_ongoing(conn: *mut connectdata) -> bool;
    fn Curl_SOCKS_getsock(
        conn: *mut connectdata,
        sock: *mut curl_socket_t,
        sockindex: libc::c_int,
    ) -> libc::c_int;
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
pub type __uint16_t = libc::c_ushort;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_padding: [libc::c_char; 118],
    pub __ss_align: libc::c_ulong,
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
pub type curlfiletype = libc::c_uint;
pub const CURLFILETYPE_UNKNOWN: curlfiletype = 8;
pub const CURLFILETYPE_DOOR: curlfiletype = 7;
pub const CURLFILETYPE_SOCKET: curlfiletype = 6;
pub const CURLFILETYPE_NAMEDPIPE: curlfiletype = 5;
pub const CURLFILETYPE_DEVICE_CHAR: curlfiletype = 4;
pub const CURLFILETYPE_DEVICE_BLOCK: curlfiletype = 3;
pub const CURLFILETYPE_SYMLINK: curlfiletype = 2;
pub const CURLFILETYPE_DIRECTORY: curlfiletype = 1;
pub const CURLFILETYPE_FILE: curlfiletype = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_fileinfo {
    pub filename: *mut libc::c_char,
    pub filetype: curlfiletype,
    pub time: time_t,
    pub perm: libc::c_uint,
    pub uid: libc::c_int,
    pub gid: libc::c_int,
    pub size: curl_off_t,
    pub hardlinks: libc::c_long,
    pub strings: C2RustUnnamed_7,
    pub flags: libc::c_uint,
    pub b_data: *mut libc::c_char,
    pub b_size: size_t,
    pub b_used: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_7 {
    pub time: *mut libc::c_char,
    pub perm: *mut libc::c_char,
    pub user: *mut libc::c_char,
    pub group: *mut libc::c_char,
    pub target: *mut libc::c_char,
}
pub type curl_malloc_callback = Option::<
    unsafe extern "C" fn(size_t) -> *mut libc::c_void,
>;
pub type curl_strdup_callback = Option::<
    unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
>;
pub type curl_calloc_callback = Option::<
    unsafe extern "C" fn(size_t, size_t) -> *mut libc::c_void,
>;
pub type uint16_t = __uint16_t;
pub type in_addr_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type in_port_t = uint16_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in6_addr {
    pub __in6_u: C2RustUnnamed_8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_8 {
    pub __u6_addr8: [uint8_t; 16],
    pub __u6_addr16: [uint16_t; 8],
    pub __u6_addr32: [uint32_t; 4],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [libc::c_uchar; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: uint32_t,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: uint32_t,
}
pub type resolve_t = libc::c_int;
pub const CURLRESOLV_PENDING: resolve_t = 1;
pub const CURLRESOLV_RESOLVED: resolve_t = 0;
pub const CURLRESOLV_ERROR: resolve_t = -1;
pub const CURLRESOLV_TIMEDOUT: resolve_t = -2;
pub const STRING_CUSTOMREQUEST: dupstring = 6;
pub type ftpport = libc::c_uint;
pub const DONE: ftpport = 2;
pub const PORT: ftpport = 1;
pub const EPRT: ftpport = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_sockaddr_storage {
    pub buffer: C2RustUnnamed_9,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_9 {
    pub sa: sockaddr,
    pub sa_in: sockaddr_in,
    pub sa_in6: sockaddr_in6,
    pub sa_stor: sockaddr_storage,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_sockaddr_ex {
    pub family: libc::c_int,
    pub socktype: libc::c_int,
    pub protocol: libc::c_int,
    pub addrlen: libc::c_uint,
    pub _sa_ex_u: C2RustUnnamed_10,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_10 {
    pub addr: sockaddr,
    pub buff: Curl_sockaddr_storage,
}
pub const IF2IP_FOUND: if2ip_result_t = 2;
pub const IF2IP_AF_NOT_SUPPORTED: if2ip_result_t = 1;
pub const IF2IP_NOT_FOUND: if2ip_result_t = 0;
pub type if2ip_result_t = libc::c_uint;
pub const STRING_FTPPORT: dupstring = 12;
pub type urlreject = libc::c_uint;
pub const REJECT_ZERO: urlreject = 4;
pub const REJECT_CTRL: urlreject = 3;
pub const REJECT_NADA: urlreject = 2;
pub type timerid = libc::c_uint;
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
pub type CURLofft = libc::c_uint;
pub const CURL_OFFT_INVAL: CURLofft = 2;
pub const CURL_OFFT_FLOW: CURLofft = 1;
pub const CURL_OFFT_OK: CURLofft = 0;
pub const STRING_FTP_ALTERNATIVE_TO_USER: dupstring = 11;
pub const STRING_FTP_ACCOUNT: dupstring = 10;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ftp_wc {
    pub parser: *mut ftp_parselist_data,
    pub backup: C2RustUnnamed_11,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_11 {
    pub write_function: curl_write_callback,
    pub file_descriptor: *mut FILE,
}
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
pub const STRING_SSL_ENGINE: dupstring = 43;
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
pub const STRING_ENCODING: dupstring = 9;
pub const STRING_DEVICE: dupstring = 8;
pub const STRING_DEFAULT_PROTOCOL: dupstring = 7;
pub const STRING_COOKIEJAR: dupstring = 5;
pub const STRING_COOKIE: dupstring = 4;
pub const STRING_CERT_TYPE_PROXY: dupstring = 3;
pub const STRING_CERT_TYPE: dupstring = 2;
pub const STRING_CERT_PROXY: dupstring = 1;
pub const STRING_CERT: dupstring = 0;
#[inline]
unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int
        | (__bsx as libc::c_int & 0xff as libc::c_int) << 8 as libc::c_int)
        as __uint16_t;
}
#[no_mangle]
pub static mut Curl_handler_ftp: Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"FTP\0" as *const u8 as *const libc::c_char,
            setup_connection: Some(
                ftp_setup_connection
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
            ),
            do_it: Some(
                ftp_do as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            done: Some(
                ftp_done
                    as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
            ),
            do_more: Some(
                ftp_do_more
                    as unsafe extern "C" fn(*mut Curl_easy, *mut libc::c_int) -> CURLcode,
            ),
            connect_it: Some(
                ftp_connect
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            connecting: Some(
                ftp_multi_statemach
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            doing: Some(
                ftp_doing as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            proto_getsock: Some(
                ftp_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> libc::c_int,
            ),
            doing_getsock: Some(
                ftp_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> libc::c_int,
            ),
            domore_getsock: Some(
                ftp_domore_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> libc::c_int,
            ),
            perform_getsock: None,
            disconnect: Some(
                ftp_disconnect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        bool,
                    ) -> CURLcode,
            ),
            readwrite: None,
            connection_check: None,
            attach: None,
            defport: 21 as libc::c_int,
            protocol: ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint,
            family: ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint,
            flags: ((1 as libc::c_int) << 1 as libc::c_int
                | (1 as libc::c_int) << 2 as libc::c_int
                | (1 as libc::c_int) << 5 as libc::c_int
                | (1 as libc::c_int) << 6 as libc::c_int
                | (1 as libc::c_int) << 11 as libc::c_int
                | (1 as libc::c_int) << 12 as libc::c_int) as libc::c_uint,
        };
        init
    }
};
#[no_mangle]
pub static mut Curl_handler_ftps: Curl_handler = unsafe {
    {
        let mut init = Curl_handler {
            scheme: b"FTPS\0" as *const u8 as *const libc::c_char,
            setup_connection: Some(
                ftp_setup_connection
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
            ),
            do_it: Some(
                ftp_do as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            done: Some(
                ftp_done
                    as unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode,
            ),
            do_more: Some(
                ftp_do_more
                    as unsafe extern "C" fn(*mut Curl_easy, *mut libc::c_int) -> CURLcode,
            ),
            connect_it: Some(
                ftp_connect
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            connecting: Some(
                ftp_multi_statemach
                    as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            doing: Some(
                ftp_doing as unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode,
            ),
            proto_getsock: Some(
                ftp_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> libc::c_int,
            ),
            doing_getsock: Some(
                ftp_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> libc::c_int,
            ),
            domore_getsock: Some(
                ftp_domore_getsock
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut curl_socket_t,
                    ) -> libc::c_int,
            ),
            perform_getsock: None,
            disconnect: Some(
                ftp_disconnect
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        bool,
                    ) -> CURLcode,
            ),
            readwrite: None,
            connection_check: None,
            attach: None,
            defport: 990 as libc::c_int,
            protocol: ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint,
            family: ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint,
            flags: ((1 as libc::c_int) << 0 as libc::c_int
                | (1 as libc::c_int) << 1 as libc::c_int
                | (1 as libc::c_int) << 2 as libc::c_int
                | (1 as libc::c_int) << 5 as libc::c_int
                | (1 as libc::c_int) << 6 as libc::c_int
                | (1 as libc::c_int) << 12 as libc::c_int) as libc::c_uint,
        };
        init
    }
};
unsafe extern "C" fn close_secondarysocket(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) {
    if -(1 as libc::c_int) != (*conn).sock[1 as libc::c_int as usize] {
        Curl_closesocket(data, conn, (*conn).sock[1 as libc::c_int as usize]);
        (*conn).sock[1 as libc::c_int as usize] = -(1 as libc::c_int);
    }
    (*conn).bits.tcpconnect[1 as libc::c_int as usize] = 0 as libc::c_int != 0;
    (*conn).bits.proxy_ssl_connected[1 as libc::c_int as usize] = 0 as libc::c_int != 0;
}
unsafe extern "C" fn freedirs(mut ftpc: *mut ftp_conn) {
    if !((*ftpc).dirs).is_null() {
        let mut i: libc::c_int = 0;
        i = 0 as libc::c_int;
        while i < (*ftpc).dirdepth {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )(*((*ftpc).dirs).offset(i as isize) as *mut libc::c_void);
            let ref mut fresh0 = *((*ftpc).dirs).offset(i as isize);
            *fresh0 = 0 as *mut libc::c_char;
            i += 1;
        }
        Curl_cfree
            .expect("non-null function pointer")((*ftpc).dirs as *mut libc::c_void);
        let ref mut fresh1 = (*ftpc).dirs;
        *fresh1 = 0 as *mut *mut libc::c_char;
        (*ftpc).dirdepth = 0 as libc::c_int;
    }
    Curl_cfree.expect("non-null function pointer")((*ftpc).file as *mut libc::c_void);
    let ref mut fresh2 = (*ftpc).file;
    *fresh2 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*ftpc).newhost as *mut libc::c_void);
    let ref mut fresh3 = (*ftpc).newhost;
    *fresh3 = 0 as *mut libc::c_char;
}
unsafe extern "C" fn AcceptServerConnect(mut data: *mut Curl_easy) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut sock: curl_socket_t = (*conn).sock[1 as libc::c_int as usize];
    let mut s: curl_socket_t = -(1 as libc::c_int);
    let mut add: Curl_sockaddr_storage = Curl_sockaddr_storage {
        buffer: C2RustUnnamed_9 {
            sa: sockaddr {
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    };
    let mut size: curl_socklen_t = ::std::mem::size_of::<Curl_sockaddr_storage>()
        as libc::c_ulong as curl_socklen_t;
    if 0 as libc::c_int
        == getsockname(
            sock,
            &mut add as *mut Curl_sockaddr_storage as *mut sockaddr,
            &mut size,
        )
    {
        size = ::std::mem::size_of::<Curl_sockaddr_storage>() as libc::c_ulong
            as curl_socklen_t;
        s = accept(
            sock,
            &mut add as *mut Curl_sockaddr_storage as *mut sockaddr,
            &mut size,
        );
    }
    Curl_closesocket(data, conn, sock);
    if -(1 as libc::c_int) == s {
        Curl_failf(
            data,
            b"Error accept()ing server connect\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_FTP_PORT_FAILED;
    }
    Curl_infof(
        data,
        b"Connection accepted from server\0" as *const u8 as *const libc::c_char,
    );
    let ref mut fresh4 = (*conn).bits;
    (*fresh4).set_do_more(0 as libc::c_int as bit);
    (*conn).sock[1 as libc::c_int as usize] = s;
    curlx_nonblock(s, 1 as libc::c_int);
    let ref mut fresh5 = (*conn).bits;
    (*fresh5).set_sock_accepted(1 as libc::c_int as bit);
    if ((*data).set.fsockopt).is_some() {
        let mut error: libc::c_int = 0 as libc::c_int;
        Curl_set_in_callback(data, 1 as libc::c_int != 0);
        error = ((*data).set.fsockopt)
            .expect(
                "non-null function pointer",
            )((*data).set.sockopt_client, s, CURLSOCKTYPE_ACCEPT);
        Curl_set_in_callback(data, 0 as libc::c_int != 0);
        if error != 0 {
            close_secondarysocket(data, conn);
            return CURLE_ABORTED_BY_CALLBACK;
        }
    }
    return CURLE_OK;
}
unsafe extern "C" fn ftp_timeleft_accept(mut data: *mut Curl_easy) -> timediff_t {
    let mut timeout_ms: timediff_t = 60000 as libc::c_int as timediff_t;
    let mut other: timediff_t = 0;
    let mut now: curltime = curltime { tv_sec: 0, tv_usec: 0 };
    if (*data).set.accepttimeout > 0 as libc::c_int as libc::c_long {
        timeout_ms = (*data).set.accepttimeout;
    }
    now = Curl_now();
    other = Curl_timeleft(data, &mut now, 0 as libc::c_int != 0);
    if other != 0 && other < timeout_ms {
        timeout_ms = other;
    } else {
        timeout_ms -= Curl_timediff(now, (*data).progress.t_acceptdata);
        if timeout_ms == 0 {
            return -(1 as libc::c_int) as timediff_t;
        }
    }
    return timeout_ms;
}
unsafe extern "C" fn ReceivedServerConnect(
    mut data: *mut Curl_easy,
    mut received: *mut bool,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut ctrl_sock: curl_socket_t = (*conn).sock[0 as libc::c_int as usize];
    let mut data_sock: curl_socket_t = (*conn).sock[1 as libc::c_int as usize];
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut pp: *mut pingpong = &mut (*ftpc).pp;
    let mut result: libc::c_int = 0;
    let mut timeout_ms: timediff_t = 0;
    let mut nread: ssize_t = 0;
    let mut ftpcode: libc::c_int = 0;
    *received = 0 as libc::c_int != 0;
    timeout_ms = ftp_timeleft_accept(data);
    Curl_infof(
        data,
        b"Checking for server connect\0" as *const u8 as *const libc::c_char,
    );
    if timeout_ms < 0 as libc::c_int as libc::c_long {
        Curl_failf(
            data,
            b"Accept timeout occurred while waiting server connect\0" as *const u8
                as *const libc::c_char,
        );
        return CURLE_FTP_ACCEPT_TIMEOUT;
    }
    if (*pp).cache_size != 0 && !((*pp).cache).is_null()
        && *((*pp).cache).offset(0 as libc::c_int as isize) as libc::c_int > '3' as i32
    {
        Curl_infof(
            data,
            b"There is negative response in cache while serv connect\0" as *const u8
                as *const libc::c_char,
        );
        Curl_GetFTPResponse(data, &mut nread, &mut ftpcode);
        return CURLE_FTP_ACCEPT_FAILED;
    }
    result = Curl_socket_check(
        ctrl_sock,
        data_sock,
        -(1 as libc::c_int),
        0 as libc::c_int as timediff_t,
    );
    match result {
        -1 => {
            Curl_failf(
                data,
                b"Error while waiting for server connect\0" as *const u8
                    as *const libc::c_char,
            );
            return CURLE_FTP_ACCEPT_FAILED;
        }
        0 => {}
        _ => {
            if result & (0x4 as libc::c_int) << 1 as libc::c_int != 0 {
                Curl_infof(
                    data,
                    b"Ready to accept data connection from server\0" as *const u8
                        as *const libc::c_char,
                );
                *received = 1 as libc::c_int != 0;
            } else if result & 0x1 as libc::c_int != 0 {
                Curl_infof(
                    data,
                    b"Ctrl conn has data while waiting for data conn\0" as *const u8
                        as *const libc::c_char,
                );
                Curl_GetFTPResponse(data, &mut nread, &mut ftpcode);
                if ftpcode / 100 as libc::c_int > 3 as libc::c_int {
                    return CURLE_FTP_ACCEPT_FAILED;
                }
                return CURLE_WEIRD_SERVER_REPLY;
            }
        }
    }
    return CURLE_OK;
}
unsafe extern "C" fn InitiateTransfer(mut data: *mut Curl_easy) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    if ((*conn).bits).ftp_use_data_ssl() != 0 {
        Curl_infof(
            data,
            b"Doing the SSL/TLS handshake on the data stream\0" as *const u8
                as *const libc::c_char,
        );
        result = Curl_ssl_connect(data, conn, 1 as libc::c_int);
        if result as u64 != 0 {
            return result;
        }
    }
    if (*conn).proto.ftpc.state_saved as libc::c_uint
        == FTP_STOR as libc::c_int as libc::c_uint
    {
        Curl_pgrsSetUploadSize(data, (*data).state.infilesize);
        Curl_setup_transfer(
            data,
            -(1 as libc::c_int),
            -(1 as libc::c_int) as curl_off_t,
            0 as libc::c_int != 0,
            1 as libc::c_int,
        );
    } else {
        Curl_setup_transfer(
            data,
            1 as libc::c_int,
            (*conn).proto.ftpc.retr_size_saved,
            0 as libc::c_int != 0,
            -(1 as libc::c_int),
        );
    }
    (*conn).proto.ftpc.pp.pending_resp = 1 as libc::c_int != 0;
    _state(data, FTP_STOP);
    return CURLE_OK;
}
unsafe extern "C" fn AllowServerConnect(
    mut data: *mut Curl_easy,
    mut connected: *mut bool,
) -> CURLcode {
    let mut timeout_ms: timediff_t = 0;
    let mut result: CURLcode = CURLE_OK;
    *connected = 0 as libc::c_int != 0;
    Curl_infof(
        data,
        b"Preparing for accepting server on data port\0" as *const u8
            as *const libc::c_char,
    );
    Curl_pgrsTime(data, TIMER_STARTACCEPT);
    timeout_ms = ftp_timeleft_accept(data);
    if timeout_ms < 0 as libc::c_int as libc::c_long {
        Curl_failf(
            data,
            b"Accept timeout occurred while waiting server connect\0" as *const u8
                as *const libc::c_char,
        );
        return CURLE_FTP_ACCEPT_TIMEOUT;
    }
    result = ReceivedServerConnect(data, connected);
    if result as u64 != 0 {
        return result;
    }
    if *connected {
        result = AcceptServerConnect(data);
        if result as u64 != 0 {
            return result;
        }
        result = InitiateTransfer(data);
        if result as u64 != 0 {
            return result;
        }
    } else if *connected as libc::c_int == 0 as libc::c_int {
        Curl_expire(
            data,
            if (*data).set.accepttimeout > 0 as libc::c_int as libc::c_long {
                (*data).set.accepttimeout
            } else {
                60000 as libc::c_int as libc::c_long
            },
            EXPIRE_100_TIMEOUT,
        );
    }
    return result;
}
unsafe extern "C" fn ftp_endofresp(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut line: *mut libc::c_char,
    mut len: size_t,
    mut code: *mut libc::c_int,
) -> bool {
    if len > 3 as libc::c_int as libc::c_ulong
        && (Curl_isdigit(
            *line.offset(0 as libc::c_int as isize) as libc::c_uchar as libc::c_int,
        ) != 0
            && Curl_isdigit(
                *line.offset(1 as libc::c_int as isize) as libc::c_uchar as libc::c_int,
            ) != 0
            && Curl_isdigit(
                *line.offset(2 as libc::c_int as isize) as libc::c_uchar as libc::c_int,
            ) != 0
            && ' ' as i32 == *line.offset(3 as libc::c_int as isize) as libc::c_int)
    {
        *code = curlx_sltosi(
            strtol(line, 0 as *mut *mut libc::c_char, 10 as libc::c_int),
        );
        return 1 as libc::c_int != 0;
    }
    return 0 as libc::c_int != 0;
}
unsafe extern "C" fn ftp_readresp(
    mut data: *mut Curl_easy,
    mut sockfd: curl_socket_t,
    mut pp: *mut pingpong,
    mut ftpcode: *mut libc::c_int,
    mut size: *mut size_t,
) -> CURLcode {
    let mut code: libc::c_int = 0;
    let mut result: CURLcode = Curl_pp_readresp(data, sockfd, pp, &mut code, size);
    (*data).info.httpcode = code;
    if !ftpcode.is_null() {
        *ftpcode = code;
    }
    if 421 as libc::c_int == code {
        Curl_infof(
            data,
            b"We got a 421 - timeout!\0" as *const u8 as *const libc::c_char,
        );
        _state(data, FTP_STOP);
        return CURLE_OPERATION_TIMEDOUT;
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_GetFTPResponse(
    mut data: *mut Curl_easy,
    mut nreadp: *mut ssize_t,
    mut ftpcode: *mut libc::c_int,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut sockfd: curl_socket_t = (*conn).sock[0 as libc::c_int as usize];
    let mut result: CURLcode = CURLE_OK;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut pp: *mut pingpong = &mut (*ftpc).pp;
    let mut nread: size_t = 0;
    let mut cache_skip: libc::c_int = 0 as libc::c_int;
    let mut value_to_be_ignored: libc::c_int = 0 as libc::c_int;
    if !ftpcode.is_null() {
        *ftpcode = 0 as libc::c_int;
    } else {
        ftpcode = &mut value_to_be_ignored;
    }
    *nreadp = 0 as libc::c_int as ssize_t;
    let mut current_block_20: u64;
    while *ftpcode == 0 && result as u64 == 0 {
        let mut timeout: timediff_t = Curl_pp_state_timeout(
            data,
            pp,
            0 as libc::c_int != 0,
        );
        let mut interval_ms: timediff_t = 0;
        if timeout <= 0 as libc::c_int as libc::c_long {
            Curl_failf(
                data,
                b"FTP response timeout\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_OPERATION_TIMEDOUT;
        }
        interval_ms = 1000 as libc::c_int as timediff_t;
        if timeout < interval_ms {
            interval_ms = timeout;
        }
        if !(!((*pp).cache).is_null() && cache_skip < 2 as libc::c_int) {
            if !Curl_conn_data_pending(conn, 0 as libc::c_int) {
                match Curl_socket_check(
                    sockfd,
                    -(1 as libc::c_int),
                    -(1 as libc::c_int),
                    interval_ms,
                ) {
                    -1 => {
                        current_block_20 = 5150713838310018186;
                        match current_block_20 {
                            5150713838310018186 => {
                                Curl_failf(
                                    data,
                                    b"FTP response aborted due to select/poll error: %d\0"
                                        as *const u8 as *const libc::c_char,
                                    *__errno_location(),
                                );
                                return CURLE_RECV_ERROR;
                            }
                            _ => {
                                if Curl_pgrsUpdate(data) != 0 {
                                    return CURLE_ABORTED_BY_CALLBACK;
                                }
                                continue;
                            }
                        }
                    }
                    0 => {
                        current_block_20 = 7791345847782151099;
                        match current_block_20 {
                            5150713838310018186 => {
                                Curl_failf(
                                    data,
                                    b"FTP response aborted due to select/poll error: %d\0"
                                        as *const u8 as *const libc::c_char,
                                    *__errno_location(),
                                );
                                return CURLE_RECV_ERROR;
                            }
                            _ => {
                                if Curl_pgrsUpdate(data) != 0 {
                                    return CURLE_ABORTED_BY_CALLBACK;
                                }
                                continue;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        result = ftp_readresp(data, sockfd, pp, ftpcode, &mut nread);
        if result as u64 != 0 {
            break;
        }
        if nread == 0 && !((*pp).cache).is_null() {
            cache_skip += 1;
        } else {
            cache_skip = 0 as libc::c_int;
        }
        *nreadp = (*nreadp as libc::c_ulong).wrapping_add(nread) as ssize_t as ssize_t;
    }
    (*pp).pending_resp = 0 as libc::c_int != 0;
    return result;
}
unsafe extern "C" fn _state(mut data: *mut Curl_easy, mut newstate: ftpstate) {
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    (*ftpc).state = newstate;
}
unsafe extern "C" fn ftp_state_user(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = Curl_pp_sendf(
        data,
        &mut (*conn).proto.ftpc.pp as *mut pingpong,
        b"USER %s\0" as *const u8 as *const libc::c_char,
        if !((*conn).user).is_null() {
            (*conn).user as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    if result as u64 == 0 {
        _state(data, FTP_USER);
        let ref mut fresh6 = (*data).state;
        (*fresh6).set_ftp_trying_alternative(0 as libc::c_int as bit);
    }
    return result;
}
unsafe extern "C" fn ftp_state_pwd(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = Curl_pp_sendf(
        data,
        &mut (*conn).proto.ftpc.pp as *mut pingpong,
        b"%s\0" as *const u8 as *const libc::c_char,
        b"PWD\0" as *const u8 as *const libc::c_char,
    );
    if result as u64 == 0 {
        _state(data, FTP_PWD);
    }
    return result;
}
unsafe extern "C" fn ftp_getsock(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> libc::c_int {
    return Curl_pp_getsock(data, &mut (*conn).proto.ftpc.pp, socks);
}
unsafe extern "C" fn ftp_domore_getsock(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut socks: *mut curl_socket_t,
) -> libc::c_int {
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    if (*conn).cnnct.state as libc::c_uint
        >= CONNECT_SOCKS_INIT as libc::c_int as libc::c_uint
        && ((*conn).cnnct.state as libc::c_uint)
            < CONNECT_DONE as libc::c_int as libc::c_uint
    {
        return Curl_SOCKS_getsock(conn, socks, 1 as libc::c_int);
    }
    if FTP_STOP as libc::c_int as libc::c_uint == (*ftpc).state as libc::c_uint {
        let mut bits: libc::c_int = (1 as libc::c_int) << 0 as libc::c_int;
        let mut any: bool = 0 as libc::c_int != 0;
        *socks
            .offset(0 as libc::c_int as isize) = (*conn).sock[0 as libc::c_int as usize];
        if ((*data).set).ftp_use_port() == 0 {
            let mut s: libc::c_int = 0;
            let mut i: libc::c_int = 0;
            s = 1 as libc::c_int;
            i = 0 as libc::c_int;
            while i < 2 as libc::c_int {
                if (*conn).tempsock[i as usize] != -(1 as libc::c_int) {
                    *socks.offset(s as isize) = (*conn).tempsock[i as usize];
                    let fresh7 = s;
                    s = s + 1;
                    bits |= (1 as libc::c_int) << 16 as libc::c_int + fresh7;
                    any = 1 as libc::c_int != 0;
                }
                i += 1;
            }
        }
        if !any {
            *socks
                .offset(
                    1 as libc::c_int as isize,
                ) = (*conn).sock[1 as libc::c_int as usize];
            bits
                |= (1 as libc::c_int) << 16 as libc::c_int + 1 as libc::c_int
                    | (1 as libc::c_int) << 1 as libc::c_int;
        }
        return bits;
    }
    return Curl_pp_getsock(data, &mut (*conn).proto.ftpc.pp, socks);
}
unsafe extern "C" fn ftp_state_cwd(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    if (*ftpc).cwddone {
        result = ftp_state_mdtm(data);
    } else {
        (*ftpc).count2 = 0 as libc::c_int;
        (*ftpc)
            .count3 = if (*data).set.ftp_create_missing_dirs == 2 as libc::c_int {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        };
        if ((*conn).bits).reuse() as libc::c_int != 0 && !((*ftpc).entrypath).is_null()
            && !((*ftpc).dirdepth != 0
                && *(*((*ftpc).dirs).offset(0 as libc::c_int as isize))
                    .offset(0 as libc::c_int as isize) as libc::c_int == '/' as i32)
        {
            (*ftpc).cwdcount = 0 as libc::c_int;
            result = Curl_pp_sendf(
                data,
                &mut (*ftpc).pp as *mut pingpong,
                b"CWD %s\0" as *const u8 as *const libc::c_char,
                (*ftpc).entrypath,
            );
            if result as u64 == 0 {
                _state(data, FTP_CWD);
            }
        } else if (*ftpc).dirdepth != 0 {
            (*ftpc).cwdcount = 1 as libc::c_int;
            result = Curl_pp_sendf(
                data,
                &mut (*ftpc).pp as *mut pingpong,
                b"CWD %s\0" as *const u8 as *const libc::c_char,
                *((*ftpc).dirs).offset(((*ftpc).cwdcount - 1 as libc::c_int) as isize),
            );
            if result as u64 == 0 {
                _state(data, FTP_CWD);
            }
        } else {
            result = ftp_state_mdtm(data);
        }
    }
    return result;
}
unsafe extern "C" fn ftp_state_use_port(
    mut data: *mut Curl_easy,
    mut fcmd: ftpport,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut portsock: curl_socket_t = -(1 as libc::c_int);
    let mut myhost: [libc::c_char; 47] = *::std::mem::transmute::<
        &[u8; 47],
        &mut [libc::c_char; 47],
    >(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut ss: Curl_sockaddr_storage = Curl_sockaddr_storage {
        buffer: C2RustUnnamed_9 {
            sa: sockaddr {
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    };
    let mut res: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut ai: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut sslen: curl_socklen_t = 0;
    let mut hbuf: [libc::c_char; 1025] = [0; 1025];
    let mut sa: *mut sockaddr = &mut ss as *mut Curl_sockaddr_storage as *mut sockaddr;
    let sa4: *mut sockaddr_in = sa as *mut libc::c_void as *mut sockaddr_in;
    let sa6: *mut sockaddr_in6 = sa as *mut libc::c_void as *mut sockaddr_in6;
    static mut mode: [[libc::c_char; 5]; 2] = unsafe {
        [
            *::std::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"EPRT\0"),
            *::std::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"PORT\0"),
        ]
    };
    let mut rc: resolve_t = CURLRESOLV_RESOLVED;
    let mut error: libc::c_int = 0;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut string_ftpport: *mut libc::c_char = (*data)
        .set
        .str_0[STRING_FTPPORT as libc::c_int as usize];
    let mut h: *mut Curl_dns_entry = 0 as *mut Curl_dns_entry;
    let mut port_min: libc::c_ushort = 0 as libc::c_int as libc::c_ushort;
    let mut port_max: libc::c_ushort = 0 as libc::c_int as libc::c_ushort;
    let mut port: libc::c_ushort = 0;
    let mut possibly_non_local: bool = 1 as libc::c_int != 0;
    let mut buffer: [libc::c_char; 256] = [0; 256];
    let mut addr: *mut libc::c_char = 0 as *mut libc::c_char;
    if !((*data).set.str_0[STRING_FTPPORT as libc::c_int as usize]).is_null()
        && strlen((*data).set.str_0[STRING_FTPPORT as libc::c_int as usize])
            > 1 as libc::c_int as libc::c_ulong
    {
        let mut addrlen: size_t = if 46 as libc::c_int as libc::c_ulong
            > strlen(string_ftpport)
        {
            46 as libc::c_int as libc::c_ulong
        } else {
            strlen(string_ftpport)
        };
        let mut ip_start: *mut libc::c_char = string_ftpport;
        let mut ip_end: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut port_start: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut port_sep: *mut libc::c_char = 0 as *mut libc::c_char;
        addr = Curl_ccalloc
            .expect(
                "non-null function pointer",
            )(
            addrlen.wrapping_add(1 as libc::c_int as libc::c_ulong),
            1 as libc::c_int as size_t,
        ) as *mut libc::c_char;
        if addr.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if *string_ftpport as libc::c_int == '[' as i32 {
            ip_start = string_ftpport.offset(1 as libc::c_int as isize);
            ip_end = strchr(string_ftpport, ']' as i32);
            if !ip_end.is_null() {
                strncpy(
                    addr,
                    ip_start,
                    ip_end.offset_from(ip_start) as libc::c_long as libc::c_ulong,
                );
            }
        } else if *string_ftpport as libc::c_int == ':' as i32 {
            ip_end = string_ftpport;
        } else {
            ip_end = strchr(string_ftpport, ':' as i32);
            if !ip_end.is_null() {
                if inet_pton(10 as libc::c_int, string_ftpport, sa6 as *mut libc::c_void)
                    == 1 as libc::c_int
                {
                    port_max = 0 as libc::c_int as libc::c_ushort;
                    port_min = port_max;
                    strcpy(addr, string_ftpport);
                    ip_end = 0 as *mut libc::c_char;
                } else {
                    strncpy(
                        addr,
                        string_ftpport,
                        ip_end.offset_from(ip_start) as libc::c_long as libc::c_ulong,
                    );
                }
            } else {
                strcpy(addr, string_ftpport);
            }
        }
        if !ip_end.is_null() {
            port_start = strchr(ip_end, ':' as i32);
            if !port_start.is_null() {
                port_min = curlx_ultous(
                    strtoul(
                        port_start.offset(1 as libc::c_int as isize),
                        0 as *mut *mut libc::c_char,
                        10 as libc::c_int,
                    ),
                );
                port_sep = strchr(port_start, '-' as i32);
                if !port_sep.is_null() {
                    port_max = curlx_ultous(
                        strtoul(
                            port_sep.offset(1 as libc::c_int as isize),
                            0 as *mut *mut libc::c_char,
                            10 as libc::c_int,
                        ),
                    );
                } else {
                    port_max = port_min;
                }
            }
        }
        if port_min as libc::c_int > port_max as libc::c_int {
            port_max = 0 as libc::c_int as libc::c_ushort;
            port_min = port_max;
        }
        if *addr as libc::c_int != '\u{0}' as i32 {
            match Curl_if2ip(
                (*(*conn).ip_addr).ai_family,
                Curl_ipv6_scope((*(*conn).ip_addr).ai_addr),
                (*conn).scope_id,
                addr,
                hbuf.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong
                    as libc::c_int,
            ) as libc::c_uint
            {
                0 => {
                    host = addr;
                }
                1 => return CURLE_FTP_PORT_FAILED,
                2 => {
                    host = hbuf.as_mut_ptr();
                }
                _ => {}
            }
        } else {
            host = 0 as *mut libc::c_char;
        }
    }
    if host.is_null() {
        let mut r: *const libc::c_char = 0 as *const libc::c_char;
        sslen = ::std::mem::size_of::<Curl_sockaddr_storage>() as libc::c_ulong
            as curl_socklen_t;
        if getsockname((*conn).sock[0 as libc::c_int as usize], sa, &mut sslen) != 0 {
            Curl_failf(
                data,
                b"getsockname() failed: %s\0" as *const u8 as *const libc::c_char,
                Curl_strerror(
                    *__errno_location(),
                    buffer.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                ),
            );
            Curl_cfree.expect("non-null function pointer")(addr as *mut libc::c_void);
            return CURLE_FTP_PORT_FAILED;
        }
        match (*sa).sa_family as libc::c_int {
            10 => {
                r = inet_ntop(
                    (*sa).sa_family as libc::c_int,
                    &mut (*sa6).sin6_addr as *mut in6_addr as *const libc::c_void,
                    hbuf.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong
                        as curl_socklen_t,
                );
            }
            _ => {
                r = inet_ntop(
                    (*sa).sa_family as libc::c_int,
                    &mut (*sa4).sin_addr as *mut in_addr as *const libc::c_void,
                    hbuf.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong
                        as curl_socklen_t,
                );
            }
        }
        if r.is_null() {
            return CURLE_FTP_PORT_FAILED;
        }
        host = hbuf.as_mut_ptr();
        possibly_non_local = 0 as libc::c_int != 0;
    }
    rc = Curl_resolv(data, host, 0 as libc::c_int, 0 as libc::c_int != 0, &mut h);
    if rc as libc::c_int == CURLRESOLV_PENDING as libc::c_int {
        Curl_resolver_wait_resolv(data, &mut h);
    }
    if !h.is_null() {
        res = (*h).addr;
        Curl_resolv_unlock(data, h);
    } else {
        res = 0 as *mut Curl_addrinfo;
    }
    if res.is_null() {
        Curl_failf(
            data,
            b"failed to resolve the address provided to PORT: %s\0" as *const u8
                as *const libc::c_char,
            host,
        );
        Curl_cfree.expect("non-null function pointer")(addr as *mut libc::c_void);
        return CURLE_FTP_PORT_FAILED;
    }
    Curl_cfree.expect("non-null function pointer")(addr as *mut libc::c_void);
    host = 0 as *mut libc::c_char;
    portsock = -(1 as libc::c_int);
    error = 0 as libc::c_int;
    ai = res;
    while !ai.is_null() {
        result = Curl_socket(data, ai, 0 as *mut Curl_sockaddr_ex, &mut portsock);
        if !(result as u64 != 0) {
            break;
        }
        error = *__errno_location();
        ai = (*ai).ai_next;
    }
    if ai.is_null() {
        Curl_failf(
            data,
            b"socket failure: %s\0" as *const u8 as *const libc::c_char,
            Curl_strerror(
                error,
                buffer.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
            ),
        );
        return CURLE_FTP_PORT_FAILED;
    }
    memcpy(
        sa as *mut libc::c_void,
        (*ai).ai_addr as *const libc::c_void,
        (*ai).ai_addrlen as libc::c_ulong,
    );
    sslen = (*ai).ai_addrlen;
    port = port_min;
    while port as libc::c_int <= port_max as libc::c_int {
        if (*sa).sa_family as libc::c_int == 2 as libc::c_int {
            (*sa4).sin_port = __bswap_16(port);
        } else {
            (*sa6).sin6_port = __bswap_16(port);
        }
        if !(bind(portsock, sa, sslen) != 0) {
            break;
        }
        error = *__errno_location();
        if possibly_non_local as libc::c_int != 0 && error == 99 as libc::c_int {
            Curl_infof(
                data,
                b"bind(port=%hu) on non-local address failed: %s\0" as *const u8
                    as *const libc::c_char,
                port as libc::c_int,
                Curl_strerror(
                    error,
                    buffer.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                ),
            );
            sslen = ::std::mem::size_of::<Curl_sockaddr_storage>() as libc::c_ulong
                as curl_socklen_t;
            if getsockname((*conn).sock[0 as libc::c_int as usize], sa, &mut sslen) != 0
            {
                Curl_failf(
                    data,
                    b"getsockname() failed: %s\0" as *const u8 as *const libc::c_char,
                    Curl_strerror(
                        *__errno_location(),
                        buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                    ),
                );
                Curl_closesocket(data, conn, portsock);
                return CURLE_FTP_PORT_FAILED;
            }
            port = port_min;
            possibly_non_local = 0 as libc::c_int != 0;
        } else {
            if error != 98 as libc::c_int && error != 13 as libc::c_int {
                Curl_failf(
                    data,
                    b"bind(port=%hu) failed: %s\0" as *const u8 as *const libc::c_char,
                    port as libc::c_int,
                    Curl_strerror(
                        error,
                        buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                    ),
                );
                Curl_closesocket(data, conn, portsock);
                return CURLE_FTP_PORT_FAILED;
            }
            port = port.wrapping_add(1);
        }
    }
    if port as libc::c_int > port_max as libc::c_int {
        Curl_failf(
            data,
            b"bind() failed, we ran out of ports!\0" as *const u8 as *const libc::c_char,
        );
        Curl_closesocket(data, conn, portsock);
        return CURLE_FTP_PORT_FAILED;
    }
    sslen = ::std::mem::size_of::<Curl_sockaddr_storage>() as libc::c_ulong
        as curl_socklen_t;
    if getsockname(portsock, sa, &mut sslen) != 0 {
        Curl_failf(
            data,
            b"getsockname() failed: %s\0" as *const u8 as *const libc::c_char,
            Curl_strerror(
                *__errno_location(),
                buffer.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
            ),
        );
        Curl_closesocket(data, conn, portsock);
        return CURLE_FTP_PORT_FAILED;
    }
    if listen(portsock, 1 as libc::c_int) != 0 {
        Curl_failf(
            data,
            b"socket failure: %s\0" as *const u8 as *const libc::c_char,
            Curl_strerror(
                *__errno_location(),
                buffer.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
            ),
        );
        Curl_closesocket(data, conn, portsock);
        return CURLE_FTP_PORT_FAILED;
    }
    Curl_printable_address(
        ai,
        myhost.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 47]>() as libc::c_ulong,
    );
    if ((*conn).bits).ftp_use_eprt() == 0 && ((*conn).bits).ipv6() as libc::c_int != 0 {
        let ref mut fresh8 = (*conn).bits;
        (*fresh8).set_ftp_use_eprt(1 as libc::c_int as bit);
    }
    let mut current_block_152: u64;
    while fcmd as libc::c_uint != DONE as libc::c_int as libc::c_uint {
        if !(((*conn).bits).ftp_use_eprt() == 0
            && EPRT as libc::c_int as libc::c_uint == fcmd as libc::c_uint)
        {
            if !(PORT as libc::c_int as libc::c_uint == fcmd as libc::c_uint
                && (*sa).sa_family as libc::c_int != 2 as libc::c_int)
            {
                match (*sa).sa_family as libc::c_int {
                    2 => {
                        current_block_152 = 8167214597936611784;
                        match current_block_152 {
                            11945233418868655198 => {
                                port = __bswap_16((*sa6).sin6_port);
                            }
                            _ => {
                                port = __bswap_16((*sa4).sin_port);
                            }
                        }
                        if EPRT as libc::c_int as libc::c_uint == fcmd as libc::c_uint {
                            result = Curl_pp_sendf(
                                data,
                                &mut (*ftpc).pp as *mut pingpong,
                                b"%s |%d|%s|%hu|\0" as *const u8 as *const libc::c_char,
                                (mode[fcmd as usize]).as_ptr(),
                                if (*sa).sa_family as libc::c_int == 2 as libc::c_int {
                                    1 as libc::c_int
                                } else {
                                    2 as libc::c_int
                                },
                                myhost.as_mut_ptr(),
                                port as libc::c_int,
                            );
                            if result as u64 != 0 {
                                Curl_failf(
                                    data,
                                    b"Failure sending EPRT command: %s\0" as *const u8
                                        as *const libc::c_char,
                                    curl_easy_strerror(result),
                                );
                                Curl_closesocket(data, conn, portsock);
                                (*ftpc).count1 = PORT as libc::c_int;
                                _state(data, FTP_STOP);
                                return result;
                            }
                            break;
                        } else if PORT as libc::c_int as libc::c_uint
                                == fcmd as libc::c_uint
                            {
                            let mut target: [libc::c_char; 67] = [0; 67];
                            let mut source: *mut libc::c_char = myhost.as_mut_ptr();
                            let mut dest: *mut libc::c_char = target.as_mut_ptr();
                            while !source.is_null() && *source as libc::c_int != 0 {
                                if *source as libc::c_int == '.' as i32 {
                                    *dest = ',' as i32 as libc::c_char;
                                } else {
                                    *dest = *source;
                                }
                                dest = dest.offset(1);
                                source = source.offset(1);
                            }
                            *dest = 0 as libc::c_int as libc::c_char;
                            curl_msnprintf(
                                dest,
                                20 as libc::c_int as size_t,
                                b",%d,%d\0" as *const u8 as *const libc::c_char,
                                port as libc::c_int >> 8 as libc::c_int,
                                port as libc::c_int & 0xff as libc::c_int,
                            );
                            result = Curl_pp_sendf(
                                data,
                                &mut (*ftpc).pp as *mut pingpong,
                                b"%s %s\0" as *const u8 as *const libc::c_char,
                                (mode[fcmd as usize]).as_ptr(),
                                target.as_mut_ptr(),
                            );
                            if result as u64 != 0 {
                                Curl_failf(
                                    data,
                                    b"Failure sending PORT command: %s\0" as *const u8
                                        as *const libc::c_char,
                                    curl_easy_strerror(result),
                                );
                                Curl_closesocket(data, conn, portsock);
                                _state(data, FTP_STOP);
                                return result;
                            }
                            break;
                        }
                    }
                    10 => {
                        current_block_152 = 11945233418868655198;
                        match current_block_152 {
                            11945233418868655198 => {
                                port = __bswap_16((*sa6).sin6_port);
                            }
                            _ => {
                                port = __bswap_16((*sa4).sin_port);
                            }
                        }
                        if EPRT as libc::c_int as libc::c_uint == fcmd as libc::c_uint {
                            result = Curl_pp_sendf(
                                data,
                                &mut (*ftpc).pp as *mut pingpong,
                                b"%s |%d|%s|%hu|\0" as *const u8 as *const libc::c_char,
                                (mode[fcmd as usize]).as_ptr(),
                                if (*sa).sa_family as libc::c_int == 2 as libc::c_int {
                                    1 as libc::c_int
                                } else {
                                    2 as libc::c_int
                                },
                                myhost.as_mut_ptr(),
                                port as libc::c_int,
                            );
                            if result as u64 != 0 {
                                Curl_failf(
                                    data,
                                    b"Failure sending EPRT command: %s\0" as *const u8
                                        as *const libc::c_char,
                                    curl_easy_strerror(result),
                                );
                                Curl_closesocket(data, conn, portsock);
                                (*ftpc).count1 = PORT as libc::c_int;
                                _state(data, FTP_STOP);
                                return result;
                            }
                            break;
                        } else if PORT as libc::c_int as libc::c_uint
                                == fcmd as libc::c_uint
                            {
                            let mut target: [libc::c_char; 67] = [0; 67];
                            let mut source: *mut libc::c_char = myhost.as_mut_ptr();
                            let mut dest: *mut libc::c_char = target.as_mut_ptr();
                            while !source.is_null() && *source as libc::c_int != 0 {
                                if *source as libc::c_int == '.' as i32 {
                                    *dest = ',' as i32 as libc::c_char;
                                } else {
                                    *dest = *source;
                                }
                                dest = dest.offset(1);
                                source = source.offset(1);
                            }
                            *dest = 0 as libc::c_int as libc::c_char;
                            curl_msnprintf(
                                dest,
                                20 as libc::c_int as size_t,
                                b",%d,%d\0" as *const u8 as *const libc::c_char,
                                port as libc::c_int >> 8 as libc::c_int,
                                port as libc::c_int & 0xff as libc::c_int,
                            );
                            result = Curl_pp_sendf(
                                data,
                                &mut (*ftpc).pp as *mut pingpong,
                                b"%s %s\0" as *const u8 as *const libc::c_char,
                                (mode[fcmd as usize]).as_ptr(),
                                target.as_mut_ptr(),
                            );
                            if result as u64 != 0 {
                                Curl_failf(
                                    data,
                                    b"Failure sending PORT command: %s\0" as *const u8
                                        as *const libc::c_char,
                                    curl_easy_strerror(result),
                                );
                                Curl_closesocket(data, conn, portsock);
                                _state(data, FTP_STOP);
                                return result;
                            }
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
        fcmd += 1;
    }
    (*ftpc).count1 = fcmd as libc::c_int;
    close_secondarysocket(data, conn);
    (*conn).sock[1 as libc::c_int as usize] = portsock;
    (*conn).bits.tcpconnect[1 as libc::c_int as usize] = 1 as libc::c_int != 0;
    _state(data, FTP_PORT);
    return result;
}
unsafe extern "C" fn ftp_state_use_pasv(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut result: CURLcode = CURLE_OK;
    static mut mode: [[libc::c_char; 5]; 2] = unsafe {
        [
            *::std::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"EPSV\0"),
            *::std::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"PASV\0"),
        ]
    };
    let mut modeoff: libc::c_int = 0;
    if ((*conn).bits).ftp_use_epsv() == 0 && ((*conn).bits).ipv6() as libc::c_int != 0 {
        let ref mut fresh9 = (*conn).bits;
        (*fresh9).set_ftp_use_epsv(1 as libc::c_int as bit);
    }
    modeoff = if ((*conn).bits).ftp_use_epsv() as libc::c_int != 0 {
        0 as libc::c_int
    } else {
        1 as libc::c_int
    };
    result = Curl_pp_sendf(
        data,
        &mut (*ftpc).pp as *mut pingpong,
        b"%s\0" as *const u8 as *const libc::c_char,
        (mode[modeoff as usize]).as_ptr(),
    );
    if result as u64 == 0 {
        (*ftpc).count1 = modeoff;
        _state(data, FTP_PASV);
        Curl_infof(
            data,
            b"Connect data stream passively\0" as *const u8 as *const libc::c_char,
        );
    }
    return result;
}
unsafe extern "C" fn ftp_state_prepare_transfer(mut data: *mut Curl_easy) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ftp: *mut FTP = (*data).req.p.ftp;
    let mut conn: *mut connectdata = (*data).conn;
    if (*ftp).transfer as libc::c_uint != PPTRANSFER_BODY as libc::c_int as libc::c_uint
    {
        _state(data, FTP_RETR_PREQUOTE);
        result = ftp_state_quote(data, 1 as libc::c_int != 0, FTP_RETR_PREQUOTE);
    } else if ((*data).set).ftp_use_port() != 0 {
        result = ftp_state_use_port(data, EPRT);
    } else if ((*data).set).ftp_use_pret() != 0 {
        let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
        if ((*conn).proto.ftpc.file).is_null() {
            result = Curl_pp_sendf(
                data,
                &mut (*ftpc).pp as *mut pingpong,
                b"PRET %s\0" as *const u8 as *const libc::c_char,
                if !((*data).set.str_0[STRING_CUSTOMREQUEST as libc::c_int as usize])
                    .is_null()
                {
                    (*data).set.str_0[STRING_CUSTOMREQUEST as libc::c_int as usize]
                        as *const libc::c_char
                } else if ((*data).state).list_only() as libc::c_int != 0 {
                    b"NLST\0" as *const u8 as *const libc::c_char
                } else {
                    b"LIST\0" as *const u8 as *const libc::c_char
                },
            );
        } else if ((*data).set).upload() != 0 {
            result = Curl_pp_sendf(
                data,
                &mut (*ftpc).pp as *mut pingpong,
                b"PRET STOR %s\0" as *const u8 as *const libc::c_char,
                (*conn).proto.ftpc.file,
            );
        } else {
            result = Curl_pp_sendf(
                data,
                &mut (*ftpc).pp as *mut pingpong,
                b"PRET RETR %s\0" as *const u8 as *const libc::c_char,
                (*conn).proto.ftpc.file,
            );
        }
        if result as u64 == 0 {
            _state(data, FTP_PRET);
        }
    } else {
        result = ftp_state_use_pasv(data, conn);
    }
    return result;
}
unsafe extern "C" fn ftp_state_rest(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ftp: *mut FTP = (*data).req.p.ftp;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    if (*ftp).transfer as libc::c_uint != PPTRANSFER_BODY as libc::c_int as libc::c_uint
        && !((*ftpc).file).is_null()
    {
        result = Curl_pp_sendf(
            data,
            &mut (*ftpc).pp as *mut pingpong,
            b"REST %d\0" as *const u8 as *const libc::c_char,
            0 as libc::c_int,
        );
        if result as u64 == 0 {
            _state(data, FTP_REST);
        }
    } else {
        result = ftp_state_prepare_transfer(data);
    }
    return result;
}
unsafe extern "C" fn ftp_state_size(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ftp: *mut FTP = (*data).req.p.ftp;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    if (*ftp).transfer as libc::c_uint == PPTRANSFER_INFO as libc::c_int as libc::c_uint
        && !((*ftpc).file).is_null()
    {
        result = Curl_pp_sendf(
            data,
            &mut (*ftpc).pp as *mut pingpong,
            b"SIZE %s\0" as *const u8 as *const libc::c_char,
            (*ftpc).file,
        );
        if result as u64 == 0 {
            _state(data, FTP_SIZE);
        }
    } else {
        result = ftp_state_rest(data, conn);
    }
    return result;
}
unsafe extern "C" fn ftp_state_list(mut data: *mut Curl_easy) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ftp: *mut FTP = (*data).req.p.ftp;
    let mut conn: *mut connectdata = (*data).conn;
    let mut lstArg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cmd: *mut libc::c_char = 0 as *mut libc::c_char;
    if (*data).set.ftp_filemethod as libc::c_uint
        == FTPFILE_NOCWD as libc::c_int as libc::c_uint && !((*ftp).path).is_null()
    {
        let mut slashPos: *const libc::c_char = 0 as *const libc::c_char;
        let mut rawPath: *mut libc::c_char = 0 as *mut libc::c_char;
        result = Curl_urldecode(
            data,
            (*ftp).path,
            0 as libc::c_int as size_t,
            &mut rawPath,
            0 as *mut size_t,
            REJECT_CTRL,
        );
        if result as u64 != 0 {
            return result;
        }
        slashPos = strrchr(rawPath, '/' as i32);
        if !slashPos.is_null() {
            let mut n: size_t = slashPos.offset_from(rawPath) as libc::c_long as size_t;
            if n == 0 as libc::c_int as libc::c_ulong {
                n = n.wrapping_add(1);
            }
            lstArg = rawPath;
            *lstArg.offset(n as isize) = '\u{0}' as i32 as libc::c_char;
        } else {
            Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);
        }
    }
    cmd = curl_maprintf(
        b"%s%s%s\0" as *const u8 as *const libc::c_char,
        if !((*data).set.str_0[STRING_CUSTOMREQUEST as libc::c_int as usize]).is_null() {
            (*data).set.str_0[STRING_CUSTOMREQUEST as libc::c_int as usize]
                as *const libc::c_char
        } else if ((*data).state).list_only() as libc::c_int != 0 {
            b"NLST\0" as *const u8 as *const libc::c_char
        } else {
            b"LIST\0" as *const u8 as *const libc::c_char
        },
        if !lstArg.is_null() {
            b" \0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !lstArg.is_null() {
            lstArg as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    Curl_cfree.expect("non-null function pointer")(lstArg as *mut libc::c_void);
    if cmd.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    result = Curl_pp_sendf(
        data,
        &mut (*conn).proto.ftpc.pp as *mut pingpong,
        b"%s\0" as *const u8 as *const libc::c_char,
        cmd,
    );
    Curl_cfree.expect("non-null function pointer")(cmd as *mut libc::c_void);
    if result as u64 == 0 {
        _state(data, FTP_LIST);
    }
    return result;
}
unsafe extern "C" fn ftp_state_retr_prequote(mut data: *mut Curl_easy) -> CURLcode {
    return ftp_state_quote(data, 1 as libc::c_int != 0, FTP_RETR_PREQUOTE);
}
unsafe extern "C" fn ftp_state_stor_prequote(mut data: *mut Curl_easy) -> CURLcode {
    return ftp_state_quote(data, 1 as libc::c_int != 0, FTP_STOR_PREQUOTE);
}
unsafe extern "C" fn ftp_state_type(mut data: *mut Curl_easy) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ftp: *mut FTP = (*data).req.p.ftp;
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    if ((*data).set).opt_no_body() as libc::c_int != 0 && !((*ftpc).file).is_null()
        && ftp_need_type(conn, ((*data).state).prefer_ascii() != 0) != 0
    {
        (*ftp).transfer = PPTRANSFER_INFO;
        result = ftp_nb_type(data, conn, ((*data).state).prefer_ascii() != 0, FTP_TYPE);
        if result as u64 != 0 {
            return result;
        }
    } else {
        result = ftp_state_size(data, conn);
    }
    return result;
}
unsafe extern "C" fn ftp_state_mdtm(mut data: *mut Curl_easy) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    if (((*data).set).get_filetime() as libc::c_int != 0
        || (*data).set.timecondition as libc::c_uint != 0) && !((*ftpc).file).is_null()
    {
        result = Curl_pp_sendf(
            data,
            &mut (*ftpc).pp as *mut pingpong,
            b"MDTM %s\0" as *const u8 as *const libc::c_char,
            (*ftpc).file,
        );
        if result as u64 == 0 {
            _state(data, FTP_MDTM);
        }
    } else {
        result = ftp_state_type(data);
    }
    return result;
}
unsafe extern "C" fn ftp_state_ul_setup(
    mut data: *mut Curl_easy,
    mut sizechecked: bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftp: *mut FTP = (*data).req.p.ftp;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut append: bool = ((*data).set).remote_append() != 0;
    if (*data).state.resume_from != 0 && !sizechecked
        || (*data).state.resume_from > 0 as libc::c_int as libc::c_long
            && sizechecked as libc::c_int != 0
    {
        let mut seekerr: libc::c_int = 0 as libc::c_int;
        if (*data).state.resume_from < 0 as libc::c_int as libc::c_long {
            result = Curl_pp_sendf(
                data,
                &mut (*ftpc).pp as *mut pingpong,
                b"SIZE %s\0" as *const u8 as *const libc::c_char,
                (*ftpc).file,
            );
            if result as u64 == 0 {
                _state(data, FTP_STOR_SIZE);
            }
            return result;
        }
        append = 1 as libc::c_int != 0;
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
                return CURLE_FTP_COULDNT_USE_REST;
            }
            loop {
                let mut readthisamountnow: size_t = if (*data).state.resume_from - passed
                    > (*data).set.buffer_size
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
                        b"Failed to read data\0" as *const u8 as *const libc::c_char,
                    );
                    return CURLE_FTP_COULDNT_USE_REST;
                }
                if !(passed < (*data).state.resume_from) {
                    break;
                }
            }
        }
        if (*data).state.infilesize > 0 as libc::c_int as libc::c_long {
            let ref mut fresh10 = (*data).state.infilesize;
            *fresh10 -= (*data).state.resume_from;
            if (*data).state.infilesize <= 0 as libc::c_int as libc::c_long {
                Curl_infof(
                    data,
                    b"File already completely uploaded\0" as *const u8
                        as *const libc::c_char,
                );
                Curl_setup_transfer(
                    data,
                    -(1 as libc::c_int),
                    -(1 as libc::c_int) as curl_off_t,
                    0 as libc::c_int != 0,
                    -(1 as libc::c_int),
                );
                (*ftp).transfer = PPTRANSFER_NONE;
                _state(data, FTP_STOP);
                return CURLE_OK;
            }
        }
    }
    result = Curl_pp_sendf(
        data,
        &mut (*ftpc).pp as *mut pingpong,
        if append as libc::c_int != 0 {
            b"APPE %s\0" as *const u8 as *const libc::c_char
        } else {
            b"STOR %s\0" as *const u8 as *const libc::c_char
        },
        (*ftpc).file,
    );
    if result as u64 == 0 {
        _state(data, FTP_STOR);
    }
    return result;
}
unsafe extern "C" fn ftp_state_quote(
    mut data: *mut Curl_easy,
    mut init: bool,
    mut instate: ftpstate,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ftp: *mut FTP = (*data).req.p.ftp;
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut quote: bool = 0 as libc::c_int != 0;
    let mut item: *mut curl_slist = 0 as *mut curl_slist;
    match instate as libc::c_uint {
        13 | 14 => {
            item = (*data).set.prequote;
        }
        15 => {
            item = (*data).set.postquote;
        }
        12 | _ => {
            item = (*data).set.quote;
        }
    }
    if init {
        (*ftpc).count1 = 0 as libc::c_int;
    } else {
        let ref mut fresh11 = (*ftpc).count1;
        *fresh11 += 1;
    }
    if !item.is_null() {
        let mut i: libc::c_int = 0 as libc::c_int;
        while i < (*ftpc).count1 && !item.is_null() {
            item = (*item).next;
            i += 1;
        }
        if !item.is_null() {
            let mut cmd: *mut libc::c_char = (*item).data;
            if *cmd.offset(0 as libc::c_int as isize) as libc::c_int == '*' as i32 {
                cmd = cmd.offset(1);
                (*ftpc).count2 = 1 as libc::c_int;
            } else {
                (*ftpc).count2 = 0 as libc::c_int;
            }
            result = Curl_pp_sendf(
                data,
                &mut (*ftpc).pp as *mut pingpong,
                b"%s\0" as *const u8 as *const libc::c_char,
                cmd,
            );
            if result as u64 != 0 {
                return result;
            }
            _state(data, instate);
            quote = 1 as libc::c_int != 0;
        }
    }
    if !quote {
        match instate as libc::c_uint {
            13 => {
                if (*ftp).transfer as libc::c_uint
                    != PPTRANSFER_BODY as libc::c_int as libc::c_uint
                {
                    _state(data, FTP_STOP);
                } else if (*ftpc).known_filesize != -(1 as libc::c_int) as libc::c_long {
                    Curl_pgrsSetDownloadSize(data, (*ftpc).known_filesize);
                    result = ftp_state_retr(data, (*ftpc).known_filesize);
                } else if ((*data).set).ignorecl() as libc::c_int != 0
                        || ((*data).state).prefer_ascii() as libc::c_int != 0
                    {
                    result = Curl_pp_sendf(
                        data,
                        &mut (*ftpc).pp as *mut pingpong,
                        b"RETR %s\0" as *const u8 as *const libc::c_char,
                        (*ftpc).file,
                    );
                    if result as u64 == 0 {
                        _state(data, FTP_RETR);
                    }
                } else {
                    result = Curl_pp_sendf(
                        data,
                        &mut (*ftpc).pp as *mut pingpong,
                        b"SIZE %s\0" as *const u8 as *const libc::c_char,
                        (*ftpc).file,
                    );
                    if result as u64 == 0 {
                        _state(data, FTP_RETR_SIZE);
                    }
                }
            }
            14 => {
                result = ftp_state_ul_setup(data, 0 as libc::c_int != 0);
            }
            15 => {}
            12 | _ => {
                result = ftp_state_cwd(data, conn);
            }
        }
    }
    return result;
}
unsafe extern "C" fn ftp_epsv_disable(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    if ((*conn).bits).ipv6() as libc::c_int != 0
        && !(((*conn).bits).tunnel_proxy() as libc::c_int != 0
            || ((*conn).bits).socksproxy() as libc::c_int != 0)
    {
        Curl_failf(
            data,
            b"Failed EPSV attempt, exiting\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_WEIRD_SERVER_REPLY;
    }
    Curl_infof(
        data,
        b"Failed EPSV attempt. Disabling EPSV\0" as *const u8 as *const libc::c_char,
    );
    let ref mut fresh12 = (*conn).bits;
    (*fresh12).set_ftp_use_epsv(0 as libc::c_int as bit);
    let ref mut fresh13 = (*data).state;
    (*fresh13).set_errorbuf(0 as libc::c_int as bit);
    result = Curl_pp_sendf(
        data,
        &mut (*conn).proto.ftpc.pp as *mut pingpong,
        b"%s\0" as *const u8 as *const libc::c_char,
        b"PASV\0" as *const u8 as *const libc::c_char,
    );
    if result as u64 == 0 {
        let ref mut fresh14 = (*conn).proto.ftpc.count1;
        *fresh14 += 1;
        _state(data, FTP_PASV);
    }
    return result;
}
unsafe extern "C" fn control_address(mut conn: *mut connectdata) -> *mut libc::c_char {
    if ((*conn).bits).tunnel_proxy() as libc::c_int != 0
        || ((*conn).bits).socksproxy() as libc::c_int != 0
    {
        return (*conn).host.name;
    }
    return ((*conn).primary_ip).as_mut_ptr();
}
unsafe extern "C" fn ftp_state_pasv_resp(
    mut data: *mut Curl_easy,
    mut ftpcode: libc::c_int,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut result: CURLcode = CURLE_OK;
    let mut addr: *mut Curl_dns_entry = 0 as *mut Curl_dns_entry;
    let mut rc: resolve_t = CURLRESOLV_RESOLVED;
    let mut connectport: libc::c_ushort = 0;
    let mut str: *mut libc::c_char = &mut *((*data).state.buffer)
        .offset(4 as libc::c_int as isize) as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*ftpc).newhost as *mut libc::c_void);
    let ref mut fresh15 = (*ftpc).newhost;
    *fresh15 = 0 as *mut libc::c_char;
    if (*ftpc).count1 == 0 as libc::c_int && ftpcode == 229 as libc::c_int {
        let mut ptr: *mut libc::c_char = strchr(str, '(' as i32);
        if !ptr.is_null() {
            let mut num: libc::c_uint = 0;
            let mut separator: [libc::c_char; 4] = [0; 4];
            ptr = ptr.offset(1);
            if 5 as libc::c_int
                == sscanf(
                    ptr,
                    b"%c%c%c%u%c\0" as *const u8 as *const libc::c_char,
                    &mut *separator.as_mut_ptr().offset(0 as libc::c_int as isize)
                        as *mut libc::c_char,
                    &mut *separator.as_mut_ptr().offset(1 as libc::c_int as isize)
                        as *mut libc::c_char,
                    &mut *separator.as_mut_ptr().offset(2 as libc::c_int as isize)
                        as *mut libc::c_char,
                    &mut num as *mut libc::c_uint,
                    &mut *separator.as_mut_ptr().offset(3 as libc::c_int as isize)
                        as *mut libc::c_char,
                )
            {
                let sep1: libc::c_char = separator[0 as libc::c_int as usize];
                let mut i: libc::c_int = 0;
                i = 1 as libc::c_int;
                while i < 4 as libc::c_int {
                    if separator[i as usize] as libc::c_int != sep1 as libc::c_int {
                        ptr = 0 as *mut libc::c_char;
                        break;
                    } else {
                        i += 1;
                    }
                }
                if num > 0xffff as libc::c_int as libc::c_uint {
                    Curl_failf(
                        data,
                        b"Illegal port number in EPSV reply\0" as *const u8
                            as *const libc::c_char,
                    );
                    return CURLE_FTP_WEIRD_PASV_REPLY;
                }
                if !ptr.is_null() {
                    (*ftpc)
                        .newport = (num & 0xffff as libc::c_int as libc::c_uint)
                        as libc::c_ushort;
                    let ref mut fresh16 = (*ftpc).newhost;
                    *fresh16 = Curl_cstrdup
                        .expect("non-null function pointer")(control_address(conn));
                    if ((*ftpc).newhost).is_null() {
                        return CURLE_OUT_OF_MEMORY;
                    }
                }
            } else {
                ptr = 0 as *mut libc::c_char;
            }
        }
        if ptr.is_null() {
            Curl_failf(
                data,
                b"Weirdly formatted EPSV reply\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_FTP_WEIRD_PASV_REPLY;
        }
    } else if (*ftpc).count1 == 1 as libc::c_int && ftpcode == 227 as libc::c_int {
        let mut ip: [libc::c_uint; 4] = [
            0 as libc::c_int as libc::c_uint,
            0 as libc::c_int as libc::c_uint,
            0 as libc::c_int as libc::c_uint,
            0 as libc::c_int as libc::c_uint,
        ];
        let mut port: [libc::c_uint; 2] = [
            0 as libc::c_int as libc::c_uint,
            0 as libc::c_int as libc::c_uint,
        ];
        while *str != 0 {
            if 6 as libc::c_int
                == sscanf(
                    str,
                    b"%u,%u,%u,%u,%u,%u\0" as *const u8 as *const libc::c_char,
                    &mut *ip.as_mut_ptr().offset(0 as libc::c_int as isize)
                        as *mut libc::c_uint,
                    &mut *ip.as_mut_ptr().offset(1 as libc::c_int as isize)
                        as *mut libc::c_uint,
                    &mut *ip.as_mut_ptr().offset(2 as libc::c_int as isize)
                        as *mut libc::c_uint,
                    &mut *ip.as_mut_ptr().offset(3 as libc::c_int as isize)
                        as *mut libc::c_uint,
                    &mut *port.as_mut_ptr().offset(0 as libc::c_int as isize)
                        as *mut libc::c_uint,
                    &mut *port.as_mut_ptr().offset(1 as libc::c_int as isize)
                        as *mut libc::c_uint,
                )
            {
                break;
            }
            str = str.offset(1);
        }
        if *str == 0
            || ip[0 as libc::c_int as usize] > 255 as libc::c_int as libc::c_uint
            || ip[1 as libc::c_int as usize] > 255 as libc::c_int as libc::c_uint
            || ip[2 as libc::c_int as usize] > 255 as libc::c_int as libc::c_uint
            || ip[3 as libc::c_int as usize] > 255 as libc::c_int as libc::c_uint
            || port[0 as libc::c_int as usize] > 255 as libc::c_int as libc::c_uint
            || port[1 as libc::c_int as usize] > 255 as libc::c_int as libc::c_uint
        {
            Curl_failf(
                data,
                b"Couldn't interpret the 227-response\0" as *const u8
                    as *const libc::c_char,
            );
            return CURLE_FTP_WEIRD_227_FORMAT;
        }
        if ((*data).set).ftp_skip_ip() != 0 {
            Curl_infof(
                data,
                b"Skip %u.%u.%u.%u for data connection, re-use %s instead\0" as *const u8
                    as *const libc::c_char,
                ip[0 as libc::c_int as usize],
                ip[1 as libc::c_int as usize],
                ip[2 as libc::c_int as usize],
                ip[3 as libc::c_int as usize],
                (*conn).host.name,
            );
            let ref mut fresh17 = (*ftpc).newhost;
            *fresh17 = Curl_cstrdup
                .expect("non-null function pointer")(control_address(conn));
        } else {
            let ref mut fresh18 = (*ftpc).newhost;
            *fresh18 = curl_maprintf(
                b"%u.%u.%u.%u\0" as *const u8 as *const libc::c_char,
                ip[0 as libc::c_int as usize],
                ip[1 as libc::c_int as usize],
                ip[2 as libc::c_int as usize],
                ip[3 as libc::c_int as usize],
            );
        }
        if ((*ftpc).newhost).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (*ftpc)
            .newport = ((port[0 as libc::c_int as usize] << 8 as libc::c_int)
            .wrapping_add(port[1 as libc::c_int as usize])
            & 0xffff as libc::c_int as libc::c_uint) as libc::c_ushort;
    } else if (*ftpc).count1 == 0 as libc::c_int {
        return ftp_epsv_disable(data, conn)
    } else {
        Curl_failf(
            data,
            b"Bad PASV/EPSV response: %03d\0" as *const u8 as *const libc::c_char,
            ftpcode,
        );
        return CURLE_FTP_WEIRD_PASV_REPLY;
    }
    if ((*conn).bits).proxy() != 0 {
        let host_name: *const libc::c_char = if ((*conn).bits).socksproxy()
            as libc::c_int != 0
        {
            (*conn).socks_proxy.host.name
        } else {
            (*conn).http_proxy.host.name
        };
        rc = Curl_resolv(
            data,
            host_name,
            (*conn).port,
            0 as libc::c_int != 0,
            &mut addr,
        );
        if rc as libc::c_int == CURLRESOLV_PENDING as libc::c_int {
            Curl_resolver_wait_resolv(data, &mut addr);
        }
        connectport = (*conn).port as libc::c_ushort;
        if addr.is_null() {
            Curl_failf(
                data,
                b"Can't resolve proxy host %s:%hu\0" as *const u8 as *const libc::c_char,
                host_name,
                connectport as libc::c_int,
            );
            return CURLE_COULDNT_RESOLVE_PROXY;
        }
    } else {
        if ((*conn).bits).tcp_fastopen() as libc::c_int != 0
            && ((*conn).bits).reuse() == 0
            && *((*ftpc).newhost).offset(0 as libc::c_int as isize) == 0
        {
            Curl_conninfo_remote(data, conn, (*conn).sock[0 as libc::c_int as usize]);
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*ftpc).newhost as *mut libc::c_void);
            let ref mut fresh19 = (*ftpc).newhost;
            *fresh19 = 0 as *mut libc::c_char;
            let ref mut fresh20 = (*ftpc).newhost;
            *fresh20 = Curl_cstrdup
                .expect("non-null function pointer")(control_address(conn));
            if ((*ftpc).newhost).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        }
        rc = Curl_resolv(
            data,
            (*ftpc).newhost,
            (*ftpc).newport as libc::c_int,
            0 as libc::c_int != 0,
            &mut addr,
        );
        if rc as libc::c_int == CURLRESOLV_PENDING as libc::c_int {
            Curl_resolver_wait_resolv(data, &mut addr);
        }
        connectport = (*ftpc).newport;
        if addr.is_null() {
            Curl_failf(
                data,
                b"Can't resolve new host %s:%hu\0" as *const u8 as *const libc::c_char,
                (*ftpc).newhost,
                connectport as libc::c_int,
            );
            return CURLE_FTP_CANT_GET_HOST;
        }
    }
    (*conn).bits.tcpconnect[1 as libc::c_int as usize] = 0 as libc::c_int != 0;
    result = Curl_connecthost(data, conn, addr);
    if result as u64 != 0 {
        Curl_resolv_unlock(data, addr);
        if (*ftpc).count1 == 0 as libc::c_int && ftpcode == 229 as libc::c_int {
            return ftp_epsv_disable(data, conn);
        }
        return result;
    }
    if ((*data).set).verbose() != 0 {
        ftp_pasv_verbose(
            data,
            (*addr).addr,
            (*ftpc).newhost,
            connectport as libc::c_int,
        );
    }
    Curl_resolv_unlock(data, addr);
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).secondaryhostname as *mut libc::c_void);
    let ref mut fresh21 = (*conn).secondaryhostname;
    *fresh21 = 0 as *mut libc::c_char;
    (*conn).secondary_port = (*ftpc).newport;
    let ref mut fresh22 = (*conn).secondaryhostname;
    *fresh22 = Curl_cstrdup.expect("non-null function pointer")((*ftpc).newhost);
    if ((*conn).secondaryhostname).is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    let ref mut fresh23 = (*conn).bits;
    (*fresh23).set_do_more(1 as libc::c_int as bit);
    _state(data, FTP_STOP);
    return result;
}
unsafe extern "C" fn ftp_state_port_resp(
    mut data: *mut Curl_easy,
    mut ftpcode: libc::c_int,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut fcmd: ftpport = (*ftpc).count1 as ftpport;
    let mut result: CURLcode = CURLE_OK;
    if ftpcode / 100 as libc::c_int != 2 as libc::c_int {
        if EPRT as libc::c_int as libc::c_uint == fcmd as libc::c_uint {
            Curl_infof(
                data,
                b"disabling EPRT usage\0" as *const u8 as *const libc::c_char,
            );
            let ref mut fresh24 = (*conn).bits;
            (*fresh24).set_ftp_use_eprt(0 as libc::c_int as bit);
        }
        fcmd += 1;
        if fcmd as libc::c_uint == DONE as libc::c_int as libc::c_uint {
            Curl_failf(data, b"Failed to do PORT\0" as *const u8 as *const libc::c_char);
            result = CURLE_FTP_PORT_FAILED;
        } else {
            result = ftp_state_use_port(data, fcmd);
        }
    } else {
        Curl_infof(
            data,
            b"Connect data stream actively\0" as *const u8 as *const libc::c_char,
        );
        _state(data, FTP_STOP);
        result = ftp_dophase_done(data, 0 as libc::c_int != 0);
    }
    return result;
}
unsafe extern "C" fn ftp_state_mdtm_resp(
    mut data: *mut Curl_easy,
    mut ftpcode: libc::c_int,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ftp: *mut FTP = (*data).req.p.ftp;
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    match ftpcode {
        213 => {
            let mut year: libc::c_int = 0;
            let mut month: libc::c_int = 0;
            let mut day: libc::c_int = 0;
            let mut hour: libc::c_int = 0;
            let mut minute: libc::c_int = 0;
            let mut second: libc::c_int = 0;
            if 6 as libc::c_int
                == sscanf(
                    &mut *((*data).state.buffer).offset(4 as libc::c_int as isize)
                        as *mut libc::c_char,
                    b"%04d%02d%02d%02d%02d%02d\0" as *const u8 as *const libc::c_char,
                    &mut year as *mut libc::c_int,
                    &mut month as *mut libc::c_int,
                    &mut day as *mut libc::c_int,
                    &mut hour as *mut libc::c_int,
                    &mut minute as *mut libc::c_int,
                    &mut second as *mut libc::c_int,
                )
            {
                let mut timebuf: [libc::c_char; 24] = [0; 24];
                curl_msnprintf(
                    timebuf.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 24]>() as libc::c_ulong,
                    b"%04d%02d%02d %02d:%02d:%02d GMT\0" as *const u8
                        as *const libc::c_char,
                    year,
                    month,
                    day,
                    hour,
                    minute,
                    second,
                );
                (*data).info.filetime = Curl_getdate_capped(timebuf.as_mut_ptr());
            }
            if ((*data).set).opt_no_body() as libc::c_int != 0
                && !((*ftpc).file).is_null()
                && ((*data).set).get_filetime() as libc::c_int != 0
                && (*data).info.filetime >= 0 as libc::c_int as libc::c_long
            {
                let mut headerbuf: [libc::c_char; 128] = [0; 128];
                let mut headerbuflen: libc::c_int = 0;
                let mut filetime: time_t = (*data).info.filetime;
                let mut buffer: tm = tm {
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
                let mut tm: *const tm = &mut buffer;
                result = Curl_gmtime(filetime, &mut buffer);
                if result as u64 != 0 {
                    return result;
                }
                headerbuflen = curl_msnprintf(
                    headerbuf.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                    b"Last-Modified: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n\0"
                        as *const u8 as *const libc::c_char,
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
                result = Curl_client_write(
                    data,
                    (1 as libc::c_int) << 0 as libc::c_int
                        | (1 as libc::c_int) << 1 as libc::c_int,
                    headerbuf.as_mut_ptr(),
                    headerbuflen as size_t,
                );
                if result as u64 != 0 {
                    return result;
                }
            }
        }
        550 => {
            Curl_failf(
                data,
                b"Given file does not exist\0" as *const u8 as *const libc::c_char,
            );
            result = CURLE_REMOTE_FILE_NOT_FOUND;
        }
        _ => {
            Curl_infof(
                data,
                b"unsupported MDTM reply format\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    if (*data).set.timecondition as u64 != 0 {
        if (*data).info.filetime > 0 as libc::c_int as libc::c_long
            && (*data).set.timevalue > 0 as libc::c_int as libc::c_long
        {
            match (*data).set.timecondition as libc::c_uint {
                2 => {
                    if (*data).info.filetime > (*data).set.timevalue {
                        Curl_infof(
                            data,
                            b"The requested document is not old enough\0" as *const u8
                                as *const libc::c_char,
                        );
                        (*ftp).transfer = PPTRANSFER_NONE;
                        let ref mut fresh26 = (*data).info;
                        (*fresh26).set_timecond(1 as libc::c_int as bit);
                        _state(data, FTP_STOP);
                        return CURLE_OK;
                    }
                }
                1 | _ => {
                    if (*data).info.filetime <= (*data).set.timevalue {
                        Curl_infof(
                            data,
                            b"The requested document is not new enough\0" as *const u8
                                as *const libc::c_char,
                        );
                        (*ftp).transfer = PPTRANSFER_NONE;
                        let ref mut fresh25 = (*data).info;
                        (*fresh25).set_timecond(1 as libc::c_int as bit);
                        _state(data, FTP_STOP);
                        return CURLE_OK;
                    }
                }
            }
        } else {
            Curl_infof(
                data,
                b"Skipping time comparison\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    if result as u64 == 0 {
        result = ftp_state_type(data);
    }
    return result;
}
unsafe extern "C" fn ftp_state_type_resp(
    mut data: *mut Curl_easy,
    mut ftpcode: libc::c_int,
    mut instate: ftpstate,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    if ftpcode / 100 as libc::c_int != 2 as libc::c_int {
        Curl_failf(
            data,
            b"Couldn't set desired mode\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_FTP_COULDNT_SET_TYPE;
    }
    if ftpcode != 200 as libc::c_int {
        Curl_infof(
            data,
            b"Got a %03d response code instead of the assumed 200\0" as *const u8
                as *const libc::c_char,
            ftpcode,
        );
    }
    if instate as libc::c_uint == FTP_TYPE as libc::c_int as libc::c_uint {
        result = ftp_state_size(data, conn);
    } else if instate as libc::c_uint == FTP_LIST_TYPE as libc::c_int as libc::c_uint {
        result = ftp_state_list(data);
    } else if instate as libc::c_uint == FTP_RETR_TYPE as libc::c_int as libc::c_uint {
        result = ftp_state_retr_prequote(data);
    } else if instate as libc::c_uint == FTP_STOR_TYPE as libc::c_int as libc::c_uint {
        result = ftp_state_stor_prequote(data);
    }
    return result;
}
unsafe extern "C" fn ftp_state_retr(
    mut data: *mut Curl_easy,
    mut filesize: curl_off_t,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ftp: *mut FTP = (*data).req.p.ftp;
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    if (*data).set.max_filesize != 0 && filesize > (*data).set.max_filesize {
        Curl_failf(
            data,
            b"Maximum file size exceeded\0" as *const u8 as *const libc::c_char,
        );
        return CURLE_FILESIZE_EXCEEDED;
    }
    (*ftp).downloadsize = filesize;
    if (*data).state.resume_from != 0 {
        if filesize == -(1 as libc::c_int) as libc::c_long {
            Curl_infof(
                data,
                b"ftp server doesn't support SIZE\0" as *const u8 as *const libc::c_char,
            );
        } else if (*data).state.resume_from < 0 as libc::c_int as libc::c_long {
            if filesize < -(*data).state.resume_from {
                Curl_failf(
                    data,
                    b"Offset (%ld) was beyond file size (%ld)\0" as *const u8
                        as *const libc::c_char,
                    (*data).state.resume_from,
                    filesize,
                );
                return CURLE_BAD_DOWNLOAD_RESUME;
            }
            (*ftp).downloadsize = -(*data).state.resume_from;
            (*data).state.resume_from = filesize - (*ftp).downloadsize;
        } else {
            if filesize < (*data).state.resume_from {
                Curl_failf(
                    data,
                    b"Offset (%ld) was beyond file size (%ld)\0" as *const u8
                        as *const libc::c_char,
                    (*data).state.resume_from,
                    filesize,
                );
                return CURLE_BAD_DOWNLOAD_RESUME;
            }
            (*ftp).downloadsize = filesize - (*data).state.resume_from;
        }
        if (*ftp).downloadsize == 0 as libc::c_int as libc::c_long {
            Curl_setup_transfer(
                data,
                -(1 as libc::c_int),
                -(1 as libc::c_int) as curl_off_t,
                0 as libc::c_int != 0,
                -(1 as libc::c_int),
            );
            Curl_infof(
                data,
                b"File already completely downloaded\0" as *const u8
                    as *const libc::c_char,
            );
            (*ftp).transfer = PPTRANSFER_NONE;
            _state(data, FTP_STOP);
            return CURLE_OK;
        }
        Curl_infof(
            data,
            b"Instructs server to resume from offset %ld\0" as *const u8
                as *const libc::c_char,
            (*data).state.resume_from,
        );
        result = Curl_pp_sendf(
            data,
            &mut (*ftpc).pp as *mut pingpong,
            b"REST %ld\0" as *const u8 as *const libc::c_char,
            (*data).state.resume_from,
        );
        if result as u64 == 0 {
            _state(data, FTP_RETR_REST);
        }
    } else {
        result = Curl_pp_sendf(
            data,
            &mut (*ftpc).pp as *mut pingpong,
            b"RETR %s\0" as *const u8 as *const libc::c_char,
            (*ftpc).file,
        );
        if result as u64 == 0 {
            _state(data, FTP_RETR);
        }
    }
    return result;
}
unsafe extern "C" fn ftp_state_size_resp(
    mut data: *mut Curl_easy,
    mut ftpcode: libc::c_int,
    mut instate: ftpstate,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut filesize: curl_off_t = -(1 as libc::c_int) as curl_off_t;
    let mut buf: *mut libc::c_char = (*data).state.buffer;
    if ftpcode == 213 as libc::c_int {
        let mut start: *mut libc::c_char = &mut *buf.offset(4 as libc::c_int as isize)
            as *mut libc::c_char;
        let mut fdigit: *mut libc::c_char = strchr(start, '\r' as i32);
        if !fdigit.is_null() {
            loop {
                fdigit = fdigit.offset(-1);
                if !(Curl_isdigit(*fdigit as libc::c_uchar as libc::c_int) != 0
                    && fdigit > start)
                {
                    break;
                }
            }
            if Curl_isdigit(*fdigit as libc::c_uchar as libc::c_int) == 0 {
                fdigit = fdigit.offset(1);
            }
        } else {
            fdigit = start;
        }
        curlx_strtoofft(
            fdigit,
            0 as *mut *mut libc::c_char,
            0 as libc::c_int,
            &mut filesize,
        );
    } else if ftpcode == 550 as libc::c_int {
        if instate as libc::c_uint != FTP_STOR_SIZE as libc::c_int as libc::c_uint {
            Curl_failf(
                data,
                b"The file does not exist\0" as *const u8 as *const libc::c_char,
            );
            return CURLE_REMOTE_FILE_NOT_FOUND;
        }
    }
    if instate as libc::c_uint == FTP_SIZE as libc::c_int as libc::c_uint {
        if -(1 as libc::c_int) as libc::c_long != filesize {
            let mut clbuf: [libc::c_char; 128] = [0; 128];
            let mut clbuflen: libc::c_int = curl_msnprintf(
                clbuf.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                b"Content-Length: %ld\r\n\0" as *const u8 as *const libc::c_char,
                filesize,
            );
            result = Curl_client_write(
                data,
                (1 as libc::c_int) << 0 as libc::c_int
                    | (1 as libc::c_int) << 1 as libc::c_int,
                clbuf.as_mut_ptr(),
                clbuflen as size_t,
            );
            if result as u64 != 0 {
                return result;
            }
        }
        Curl_pgrsSetDownloadSize(data, filesize);
        result = ftp_state_rest(data, (*data).conn);
    } else if instate as libc::c_uint == FTP_RETR_SIZE as libc::c_int as libc::c_uint {
        Curl_pgrsSetDownloadSize(data, filesize);
        result = ftp_state_retr(data, filesize);
    } else if instate as libc::c_uint == FTP_STOR_SIZE as libc::c_int as libc::c_uint {
        (*data).state.resume_from = filesize;
        result = ftp_state_ul_setup(data, 1 as libc::c_int != 0);
    }
    return result;
}
unsafe extern "C" fn ftp_state_rest_resp(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut ftpcode: libc::c_int,
    mut instate: ftpstate,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    match instate as libc::c_uint {
        27 => {
            if ftpcode != 350 as libc::c_int {
                Curl_failf(
                    data,
                    b"Couldn't use REST\0" as *const u8 as *const libc::c_char,
                );
                result = CURLE_FTP_COULDNT_USE_REST;
            } else {
                result = Curl_pp_sendf(
                    data,
                    &mut (*ftpc).pp as *mut pingpong,
                    b"RETR %s\0" as *const u8 as *const libc::c_char,
                    (*ftpc).file,
                );
                if result as u64 == 0 {
                    _state(data, FTP_RETR);
                }
            }
        }
        26 | _ => {
            if ftpcode == 350 as libc::c_int {
                let mut buffer: [libc::c_char; 24] = *::std::mem::transmute::<
                    &[u8; 24],
                    &mut [libc::c_char; 24],
                >(b"Accept-ranges: bytes\r\n\0\0");
                result = Curl_client_write(
                    data,
                    (1 as libc::c_int) << 0 as libc::c_int
                        | (1 as libc::c_int) << 1 as libc::c_int,
                    buffer.as_mut_ptr(),
                    strlen(buffer.as_mut_ptr()),
                );
                if result as u64 != 0 {
                    return result;
                }
            }
            result = ftp_state_prepare_transfer(data);
        }
    }
    return result;
}
unsafe extern "C" fn ftp_state_stor_resp(
    mut data: *mut Curl_easy,
    mut ftpcode: libc::c_int,
    mut instate: ftpstate,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    if ftpcode >= 400 as libc::c_int {
        Curl_failf(
            data,
            b"Failed FTP upload: %0d\0" as *const u8 as *const libc::c_char,
            ftpcode,
        );
        _state(data, FTP_STOP);
        return CURLE_UPLOAD_FAILED;
    }
    (*conn).proto.ftpc.state_saved = instate;
    if ((*data).set).ftp_use_port() != 0 {
        let mut connected: bool = false;
        _state(data, FTP_STOP);
        result = AllowServerConnect(data, &mut connected);
        if result as u64 != 0 {
            return result;
        }
        if !connected {
            let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
            Curl_infof(
                data,
                b"Data conn was not available immediately\0" as *const u8
                    as *const libc::c_char,
            );
            (*ftpc).wait_data_conn = 1 as libc::c_int != 0;
        }
        return CURLE_OK;
    }
    return InitiateTransfer(data);
}
unsafe extern "C" fn ftp_state_get_resp(
    mut data: *mut Curl_easy,
    mut ftpcode: libc::c_int,
    mut instate: ftpstate,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ftp: *mut FTP = (*data).req.p.ftp;
    let mut conn: *mut connectdata = (*data).conn;
    if ftpcode == 150 as libc::c_int || ftpcode == 125 as libc::c_int {
        let mut size: curl_off_t = -(1 as libc::c_int) as curl_off_t;
        if instate as libc::c_uint != FTP_LIST as libc::c_int as libc::c_uint
            && ((*data).state).prefer_ascii() == 0
            && (*ftp).downloadsize < 1 as libc::c_int as libc::c_long
        {
            let mut bytes: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut buf: *mut libc::c_char = (*data).state.buffer;
            bytes = strstr(buf, b" bytes\0" as *const u8 as *const libc::c_char);
            if !bytes.is_null() {
                bytes = bytes.offset(-1);
                let mut in_0: libc::c_long = bytes.offset_from(buf) as libc::c_long;
                loop {
                    in_0 -= 1;
                    if !(in_0 != 0) {
                        break;
                    }
                    if '(' as i32 == *bytes as libc::c_int {
                        break;
                    }
                    if Curl_isdigit(*bytes as libc::c_uchar as libc::c_int) == 0 {
                        bytes = 0 as *mut libc::c_char;
                        break;
                    } else {
                        bytes = bytes.offset(-1);
                    }
                }
                if !bytes.is_null() {
                    bytes = bytes.offset(1);
                    curlx_strtoofft(
                        bytes,
                        0 as *mut *mut libc::c_char,
                        0 as libc::c_int,
                        &mut size,
                    );
                }
            }
        } else if (*ftp).downloadsize > -(1 as libc::c_int) as libc::c_long {
            size = (*ftp).downloadsize;
        }
        if size > (*data).req.maxdownload
            && (*data).req.maxdownload > 0 as libc::c_int as libc::c_long
        {
            let ref mut fresh27 = (*data).req.size;
            *fresh27 = (*data).req.maxdownload;
            size = *fresh27;
        } else if instate as libc::c_uint != FTP_LIST as libc::c_int as libc::c_uint
                && ((*data).state).prefer_ascii() as libc::c_int != 0
            {
            size = -(1 as libc::c_int) as curl_off_t;
        }
        Curl_infof(
            data,
            b"Maxdownload = %ld\0" as *const u8 as *const libc::c_char,
            (*data).req.maxdownload,
        );
        if instate as libc::c_uint != FTP_LIST as libc::c_int as libc::c_uint {
            Curl_infof(
                data,
                b"Getting file with size: %ld\0" as *const u8 as *const libc::c_char,
                size,
            );
        }
        (*conn).proto.ftpc.state_saved = instate;
        (*conn).proto.ftpc.retr_size_saved = size;
        if ((*data).set).ftp_use_port() != 0 {
            let mut connected: bool = false;
            result = AllowServerConnect(data, &mut connected);
            if result as u64 != 0 {
                return result;
            }
            if !connected {
                let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
                Curl_infof(
                    data,
                    b"Data conn was not available immediately\0" as *const u8
                        as *const libc::c_char,
                );
                _state(data, FTP_STOP);
                (*ftpc).wait_data_conn = 1 as libc::c_int != 0;
            }
        } else {
            return InitiateTransfer(data)
        }
    } else if instate as libc::c_uint == FTP_LIST as libc::c_int as libc::c_uint
            && ftpcode == 450 as libc::c_int
        {
        (*ftp).transfer = PPTRANSFER_NONE;
        _state(data, FTP_STOP);
    } else {
        Curl_failf(
            data,
            b"RETR response: %03d\0" as *const u8 as *const libc::c_char,
            ftpcode,
        );
        return (if instate as libc::c_uint == FTP_RETR as libc::c_int as libc::c_uint
            && ftpcode == 550 as libc::c_int
        {
            CURLE_REMOTE_FILE_NOT_FOUND as libc::c_int
        } else {
            CURLE_FTP_COULDNT_RETR_FILE as libc::c_int
        }) as CURLcode;
    }
    return result;
}
unsafe extern "C" fn ftp_state_loggedin(mut data: *mut Curl_easy) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    if ((*conn).bits).ftp_use_control_ssl() != 0 {
        result = Curl_pp_sendf(
            data,
            &mut (*conn).proto.ftpc.pp as *mut pingpong,
            b"PBSZ %d\0" as *const u8 as *const libc::c_char,
            0 as libc::c_int,
        );
        if result as u64 == 0 {
            _state(data, FTP_PBSZ);
        }
    } else {
        result = ftp_state_pwd(data, conn);
    }
    return result;
}
unsafe extern "C" fn ftp_state_user_resp(
    mut data: *mut Curl_easy,
    mut ftpcode: libc::c_int,
    mut instate: ftpstate,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    if ftpcode == 331 as libc::c_int
        && (*ftpc).state as libc::c_uint == FTP_USER as libc::c_int as libc::c_uint
    {
        result = Curl_pp_sendf(
            data,
            &mut (*ftpc).pp as *mut pingpong,
            b"PASS %s\0" as *const u8 as *const libc::c_char,
            if !((*conn).passwd).is_null() {
                (*conn).passwd as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
        );
        if result as u64 == 0 {
            _state(data, FTP_PASS);
        }
    } else if ftpcode / 100 as libc::c_int == 2 as libc::c_int {
        result = ftp_state_loggedin(data);
    } else if ftpcode == 332 as libc::c_int {
        if !((*data).set.str_0[STRING_FTP_ACCOUNT as libc::c_int as usize]).is_null() {
            result = Curl_pp_sendf(
                data,
                &mut (*ftpc).pp as *mut pingpong,
                b"ACCT %s\0" as *const u8 as *const libc::c_char,
                (*data).set.str_0[STRING_FTP_ACCOUNT as libc::c_int as usize],
            );
            if result as u64 == 0 {
                _state(data, FTP_ACCT);
            }
        } else {
            Curl_failf(
                data,
                b"ACCT requested but none available\0" as *const u8
                    as *const libc::c_char,
            );
            result = CURLE_LOGIN_DENIED;
        }
    } else if !((*data)
            .set
            .str_0[STRING_FTP_ALTERNATIVE_TO_USER as libc::c_int as usize])
            .is_null() && ((*data).state).ftp_trying_alternative() == 0
        {
        result = Curl_pp_sendf(
            data,
            &mut (*ftpc).pp as *mut pingpong,
            b"%s\0" as *const u8 as *const libc::c_char,
            (*data).set.str_0[STRING_FTP_ALTERNATIVE_TO_USER as libc::c_int as usize],
        );
        if result as u64 == 0 {
            let ref mut fresh28 = (*data).state;
            (*fresh28).set_ftp_trying_alternative(1 as libc::c_int as bit);
            _state(data, FTP_USER);
        }
    } else {
        Curl_failf(
            data,
            b"Access denied: %03d\0" as *const u8 as *const libc::c_char,
            ftpcode,
        );
        result = CURLE_LOGIN_DENIED;
    }
    return result;
}
unsafe extern "C" fn ftp_state_acct_resp(
    mut data: *mut Curl_easy,
    mut ftpcode: libc::c_int,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    if ftpcode != 230 as libc::c_int {
        Curl_failf(
            data,
            b"ACCT rejected by server: %03d\0" as *const u8 as *const libc::c_char,
            ftpcode,
        );
        result = CURLE_FTP_WEIRD_PASS_REPLY;
    } else {
        result = ftp_state_loggedin(data);
    }
    return result;
}
unsafe extern "C" fn ftp_statemachine(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut sock: curl_socket_t = (*conn).sock[0 as libc::c_int as usize];
    let mut ftpcode: libc::c_int = 0;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut pp: *mut pingpong = &mut (*ftpc).pp;
    static mut ftpauth: [[libc::c_char; 4]; 2] = unsafe {
        [
            *::std::mem::transmute::<&[u8; 4], &[libc::c_char; 4]>(b"SSL\0"),
            *::std::mem::transmute::<&[u8; 4], &[libc::c_char; 4]>(b"TLS\0"),
        ]
    };
    let mut nread: size_t = 0 as libc::c_int as size_t;
    if (*pp).sendleft != 0 {
        return Curl_pp_flushsend(data, pp);
    }
    result = ftp_readresp(data, sock, pp, &mut ftpcode, &mut nread);
    if result as u64 != 0 {
        return result;
    }
    if ftpcode != 0 {
        let mut current_block_187: u64;
        match (*ftpc).state as libc::c_uint {
            1 => {
                if ftpcode == 230 as libc::c_int {
                    if (*data).set.use_ssl as libc::c_uint
                        <= CURLUSESSL_TRY as libc::c_int as libc::c_uint
                        || ((*conn).bits).ftp_use_control_ssl() as libc::c_int != 0
                    {
                        return ftp_state_user_resp(data, ftpcode, (*ftpc).state);
                    }
                } else if ftpcode != 220 as libc::c_int {
                    Curl_failf(
                        data,
                        b"Got a %03d ftp-server response when 220 was expected\0"
                            as *const u8 as *const libc::c_char,
                        ftpcode,
                    );
                    return CURLE_WEIRD_SERVER_REPLY;
                }
                if (*data).set.use_ssl as libc::c_uint != 0
                    && ((*conn).bits).ftp_use_control_ssl() == 0
                {
                    (*ftpc).count3 = 0 as libc::c_int;
                    match (*data).set.ftpsslauth as libc::c_uint {
                        0 | 1 => {
                            (*ftpc).count2 = 1 as libc::c_int;
                            (*ftpc).count1 = 0 as libc::c_int;
                        }
                        2 => {
                            (*ftpc).count2 = -(1 as libc::c_int);
                            (*ftpc).count1 = 1 as libc::c_int;
                        }
                        _ => {
                            Curl_failf(
                                data,
                                b"unsupported parameter to CURLOPT_FTPSSLAUTH: %d\0"
                                    as *const u8 as *const libc::c_char,
                                (*data).set.ftpsslauth as libc::c_int,
                            );
                            return CURLE_UNKNOWN_OPTION;
                        }
                    }
                    result = Curl_pp_sendf(
                        data,
                        &mut (*ftpc).pp as *mut pingpong,
                        b"AUTH %s\0" as *const u8 as *const libc::c_char,
                        (ftpauth[(*ftpc).count1 as usize]).as_ptr(),
                    );
                    if result as u64 == 0 {
                        _state(data, FTP_AUTH);
                    }
                } else {
                    result = ftp_state_user(data, conn);
                }
            }
            2 => {
                if (*pp).cache_size != 0 {
                    return CURLE_WEIRD_SERVER_REPLY;
                }
                if ftpcode == 234 as libc::c_int || ftpcode == 334 as libc::c_int {
                    result = Curl_ssl_connect(data, conn, 0 as libc::c_int);
                    if result as u64 == 0 {
                        let ref mut fresh29 = (*conn).bits;
                        (*fresh29).set_ftp_use_data_ssl(0 as libc::c_int as bit);
                        let ref mut fresh30 = (*conn).bits;
                        (*fresh30).set_ftp_use_control_ssl(1 as libc::c_int as bit);
                        result = ftp_state_user(data, conn);
                    }
                } else if (*ftpc).count3 < 1 as libc::c_int {
                    let ref mut fresh31 = (*ftpc).count3;
                    *fresh31 += 1;
                    (*ftpc).count1 += (*ftpc).count2;
                    result = Curl_pp_sendf(
                        data,
                        &mut (*ftpc).pp as *mut pingpong,
                        b"AUTH %s\0" as *const u8 as *const libc::c_char,
                        (ftpauth[(*ftpc).count1 as usize]).as_ptr(),
                    );
                } else if (*data).set.use_ssl as libc::c_uint
                        > CURLUSESSL_TRY as libc::c_int as libc::c_uint
                    {
                    result = CURLE_USE_SSL_FAILED;
                } else {
                    result = ftp_state_user(data, conn);
                }
            }
            3 | 4 => {
                result = ftp_state_user_resp(data, ftpcode, (*ftpc).state);
            }
            5 => {
                result = ftp_state_acct_resp(data, ftpcode);
            }
            6 => {
                result = Curl_pp_sendf(
                    data,
                    &mut (*ftpc).pp as *mut pingpong,
                    b"PROT %c\0" as *const u8 as *const libc::c_char,
                    if (*data).set.use_ssl as libc::c_uint
                        == CURLUSESSL_CONTROL as libc::c_int as libc::c_uint
                    {
                        'C' as i32
                    } else {
                        'P' as i32
                    },
                );
                if result as u64 == 0 {
                    _state(data, FTP_PROT);
                }
            }
            7 => {
                if ftpcode / 100 as libc::c_int == 2 as libc::c_int {
                    let ref mut fresh32 = (*conn).bits;
                    (*fresh32)
                        .set_ftp_use_data_ssl(
                            (if (*data).set.use_ssl as libc::c_uint
                                != CURLUSESSL_CONTROL as libc::c_int as libc::c_uint
                            {
                                1 as libc::c_int
                            } else {
                                0 as libc::c_int
                            }) as bit,
                        );
                } else if (*data).set.use_ssl as libc::c_uint
                        > CURLUSESSL_CONTROL as libc::c_int as libc::c_uint
                    {
                    return CURLE_USE_SSL_FAILED
                }
                if (*data).set.ftp_ccc as u64 != 0 {
                    result = Curl_pp_sendf(
                        data,
                        &mut (*ftpc).pp as *mut pingpong,
                        b"%s\0" as *const u8 as *const libc::c_char,
                        b"CCC\0" as *const u8 as *const libc::c_char,
                    );
                    if result as u64 == 0 {
                        _state(data, FTP_CCC);
                    }
                } else {
                    result = ftp_state_pwd(data, conn);
                }
            }
            8 => {
                if ftpcode < 500 as libc::c_int {
                    result = Curl_ssl_shutdown(data, conn, 0 as libc::c_int);
                    if result as u64 != 0 {
                        Curl_failf(
                            data,
                            b"Failed to clear the command channel (CCC)\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                }
                if result as u64 == 0 {
                    result = ftp_state_pwd(data, conn);
                }
            }
            9 => {
                if ftpcode == 257 as libc::c_int {
                    let mut ptr: *mut libc::c_char = &mut *((*data).state.buffer)
                        .offset(4 as libc::c_int as isize) as *mut libc::c_char;
                    let buf_size: size_t = (*data).set.buffer_size as size_t;
                    let mut dir: *mut libc::c_char = 0 as *mut libc::c_char;
                    let mut entry_extracted: bool = 0 as libc::c_int != 0;
                    dir = Curl_cmalloc
                        .expect(
                            "non-null function pointer",
                        )(nread.wrapping_add(1 as libc::c_int as libc::c_ulong))
                        as *mut libc::c_char;
                    if dir.is_null() {
                        return CURLE_OUT_OF_MEMORY;
                    }
                    while ptr
                        < &mut *((*data).state.buffer).offset(buf_size as isize)
                            as *mut libc::c_char && *ptr as libc::c_int != '\n' as i32
                        && *ptr as libc::c_int != '\u{0}' as i32
                        && *ptr as libc::c_int != '"' as i32
                    {
                        ptr = ptr.offset(1);
                    }
                    if '"' as i32 == *ptr as libc::c_int {
                        let mut store: *mut libc::c_char = 0 as *mut libc::c_char;
                        ptr = ptr.offset(1);
                        store = dir;
                        while *ptr != 0 {
                            if '"' as i32 == *ptr as libc::c_int {
                                if '"' as i32
                                    == *ptr.offset(1 as libc::c_int as isize) as libc::c_int
                                {
                                    *store = *ptr.offset(1 as libc::c_int as isize);
                                    ptr = ptr.offset(1);
                                } else {
                                    entry_extracted = 1 as libc::c_int != 0;
                                    break;
                                }
                            } else {
                                *store = *ptr;
                            }
                            store = store.offset(1);
                            ptr = ptr.offset(1);
                        }
                        *store = '\u{0}' as i32 as libc::c_char;
                    }
                    if entry_extracted {
                        if ((*ftpc).server_os).is_null()
                            && *dir.offset(0 as libc::c_int as isize) as libc::c_int
                                != '/' as i32
                        {
                            result = Curl_pp_sendf(
                                data,
                                &mut (*ftpc).pp as *mut pingpong,
                                b"%s\0" as *const u8 as *const libc::c_char,
                                b"SYST\0" as *const u8 as *const libc::c_char,
                            );
                            if result as u64 != 0 {
                                Curl_cfree
                                    .expect(
                                        "non-null function pointer",
                                    )(dir as *mut libc::c_void);
                                return result;
                            }
                            Curl_cfree
                                .expect(
                                    "non-null function pointer",
                                )((*ftpc).entrypath as *mut libc::c_void);
                            let ref mut fresh33 = (*ftpc).entrypath;
                            *fresh33 = 0 as *mut libc::c_char;
                            let ref mut fresh34 = (*ftpc).entrypath;
                            *fresh34 = dir;
                            Curl_infof(
                                data,
                                b"Entry path is '%s'\0" as *const u8 as *const libc::c_char,
                                (*ftpc).entrypath,
                            );
                            let ref mut fresh35 = (*data)
                                .state
                                .most_recent_ftp_entrypath;
                            *fresh35 = (*ftpc).entrypath;
                            _state(data, FTP_SYST);
                            current_block_187 = 10490607306284298299;
                        } else {
                            Curl_cfree
                                .expect(
                                    "non-null function pointer",
                                )((*ftpc).entrypath as *mut libc::c_void);
                            let ref mut fresh36 = (*ftpc).entrypath;
                            *fresh36 = 0 as *mut libc::c_char;
                            let ref mut fresh37 = (*ftpc).entrypath;
                            *fresh37 = dir;
                            Curl_infof(
                                data,
                                b"Entry path is '%s'\0" as *const u8 as *const libc::c_char,
                                (*ftpc).entrypath,
                            );
                            let ref mut fresh38 = (*data)
                                .state
                                .most_recent_ftp_entrypath;
                            *fresh38 = (*ftpc).entrypath;
                            current_block_187 = 17917672080766325409;
                        }
                    } else {
                        Curl_cfree
                            .expect(
                                "non-null function pointer",
                            )(dir as *mut libc::c_void);
                        Curl_infof(
                            data,
                            b"Failed to figure out path\0" as *const u8
                                as *const libc::c_char,
                        );
                        current_block_187 = 17917672080766325409;
                    }
                } else {
                    current_block_187 = 17917672080766325409;
                }
                match current_block_187 {
                    10490607306284298299 => {}
                    _ => {
                        _state(data, FTP_STOP);
                    }
                }
            }
            10 => {
                if ftpcode == 215 as libc::c_int {
                    let mut ptr_0: *mut libc::c_char = &mut *((*data).state.buffer)
                        .offset(4 as libc::c_int as isize) as *mut libc::c_char;
                    let mut os: *mut libc::c_char = 0 as *mut libc::c_char;
                    let mut store_0: *mut libc::c_char = 0 as *mut libc::c_char;
                    os = Curl_cmalloc
                        .expect(
                            "non-null function pointer",
                        )(nread.wrapping_add(1 as libc::c_int as libc::c_ulong))
                        as *mut libc::c_char;
                    if os.is_null() {
                        return CURLE_OUT_OF_MEMORY;
                    }
                    while *ptr_0 as libc::c_int == ' ' as i32 {
                        ptr_0 = ptr_0.offset(1);
                    }
                    store_0 = os;
                    while *ptr_0 as libc::c_int != 0
                        && *ptr_0 as libc::c_int != ' ' as i32
                    {
                        let fresh39 = ptr_0;
                        ptr_0 = ptr_0.offset(1);
                        let fresh40 = store_0;
                        store_0 = store_0.offset(1);
                        *fresh40 = *fresh39;
                    }
                    *store_0 = '\u{0}' as i32 as libc::c_char;
                    if Curl_strcasecompare(
                        os,
                        b"OS/400\0" as *const u8 as *const libc::c_char,
                    ) != 0
                    {
                        result = Curl_pp_sendf(
                            data,
                            &mut (*ftpc).pp as *mut pingpong,
                            b"%s\0" as *const u8 as *const libc::c_char,
                            b"SITE NAMEFMT 1\0" as *const u8 as *const libc::c_char,
                        );
                        if result as u64 != 0 {
                            Curl_cfree
                                .expect(
                                    "non-null function pointer",
                                )(os as *mut libc::c_void);
                            return result;
                        }
                        Curl_cfree
                            .expect(
                                "non-null function pointer",
                            )((*ftpc).server_os as *mut libc::c_void);
                        let ref mut fresh41 = (*ftpc).server_os;
                        *fresh41 = 0 as *mut libc::c_char;
                        let ref mut fresh42 = (*ftpc).server_os;
                        *fresh42 = os;
                        _state(data, FTP_NAMEFMT);
                        current_block_187 = 10490607306284298299;
                    } else {
                        Curl_cfree
                            .expect(
                                "non-null function pointer",
                            )((*ftpc).server_os as *mut libc::c_void);
                        let ref mut fresh43 = (*ftpc).server_os;
                        *fresh43 = 0 as *mut libc::c_char;
                        let ref mut fresh44 = (*ftpc).server_os;
                        *fresh44 = os;
                        current_block_187 = 6938158527927677584;
                    }
                } else {
                    current_block_187 = 6938158527927677584;
                }
                match current_block_187 {
                    10490607306284298299 => {}
                    _ => {
                        _state(data, FTP_STOP);
                    }
                }
            }
            11 => {
                if ftpcode == 250 as libc::c_int {
                    ftp_state_pwd(data, conn);
                } else {
                    _state(data, FTP_STOP);
                }
            }
            12 | 15 | 13 | 14 => {
                if ftpcode >= 400 as libc::c_int && (*ftpc).count2 == 0 {
                    Curl_failf(
                        data,
                        b"QUOT command failed with %03d\0" as *const u8
                            as *const libc::c_char,
                        ftpcode,
                    );
                    result = CURLE_QUOTE_ERROR;
                } else {
                    result = ftp_state_quote(data, 0 as libc::c_int != 0, (*ftpc).state);
                }
            }
            16 => {
                if ftpcode / 100 as libc::c_int != 2 as libc::c_int {
                    if (*data).set.ftp_create_missing_dirs != 0 && (*ftpc).cwdcount != 0
                        && (*ftpc).count2 == 0
                    {
                        let ref mut fresh45 = (*ftpc).count2;
                        *fresh45 += 1;
                        result = Curl_pp_sendf(
                            data,
                            &mut (*ftpc).pp as *mut pingpong,
                            b"MKD %s\0" as *const u8 as *const libc::c_char,
                            *((*ftpc).dirs)
                                .offset(((*ftpc).cwdcount - 1 as libc::c_int) as isize),
                        );
                        if result as u64 == 0 {
                            _state(data, FTP_MKD);
                        }
                    } else {
                        Curl_failf(
                            data,
                            b"Server denied you to change to the given directory\0"
                                as *const u8 as *const libc::c_char,
                        );
                        (*ftpc).cwdfail = 1 as libc::c_int != 0;
                        result = CURLE_REMOTE_ACCESS_DENIED;
                    }
                } else {
                    (*ftpc).count2 = 0 as libc::c_int;
                    let ref mut fresh46 = (*ftpc).cwdcount;
                    *fresh46 += 1;
                    if *fresh46 <= (*ftpc).dirdepth {
                        result = Curl_pp_sendf(
                            data,
                            &mut (*ftpc).pp as *mut pingpong,
                            b"CWD %s\0" as *const u8 as *const libc::c_char,
                            *((*ftpc).dirs)
                                .offset(((*ftpc).cwdcount - 1 as libc::c_int) as isize),
                        );
                    } else {
                        result = ftp_state_mdtm(data);
                    }
                }
            }
            17 => {
                if ftpcode / 100 as libc::c_int != 2 as libc::c_int
                    && {
                        let ref mut fresh47 = (*ftpc).count3;
                        let fresh48 = *fresh47;
                        *fresh47 = *fresh47 - 1;
                        fresh48 == 0
                    }
                {
                    Curl_failf(
                        data,
                        b"Failed to MKD dir: %03d\0" as *const u8 as *const libc::c_char,
                        ftpcode,
                    );
                    result = CURLE_REMOTE_ACCESS_DENIED;
                } else {
                    _state(data, FTP_CWD);
                    result = Curl_pp_sendf(
                        data,
                        &mut (*ftpc).pp as *mut pingpong,
                        b"CWD %s\0" as *const u8 as *const libc::c_char,
                        *((*ftpc).dirs)
                            .offset(((*ftpc).cwdcount - 1 as libc::c_int) as isize),
                    );
                }
            }
            18 => {
                result = ftp_state_mdtm_resp(data, ftpcode);
            }
            19 | 20 | 21 | 22 => {
                result = ftp_state_type_resp(data, ftpcode, (*ftpc).state);
            }
            23 | 24 | 25 => {
                result = ftp_state_size_resp(data, ftpcode, (*ftpc).state);
            }
            26 | 27 => {
                result = ftp_state_rest_resp(data, conn, ftpcode, (*ftpc).state);
            }
            29 => {
                if ftpcode != 200 as libc::c_int {
                    Curl_failf(
                        data,
                        b"PRET command not accepted: %03d\0" as *const u8
                            as *const libc::c_char,
                        ftpcode,
                    );
                    return CURLE_FTP_PRET_FAILED;
                }
                result = ftp_state_use_pasv(data, conn);
            }
            30 => {
                result = ftp_state_pasv_resp(data, ftpcode);
            }
            28 => {
                result = ftp_state_port_resp(data, ftpcode);
            }
            31 | 32 => {
                result = ftp_state_get_resp(data, ftpcode, (*ftpc).state);
            }
            33 => {
                result = ftp_state_stor_resp(data, ftpcode, (*ftpc).state);
            }
            34 | _ => {
                _state(data, FTP_STOP);
            }
        }
    }
    return result;
}
unsafe extern "C" fn ftp_multi_statemach(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut result: CURLcode = Curl_pp_statemach(
        data,
        &mut (*ftpc).pp,
        0 as libc::c_int != 0,
        0 as libc::c_int != 0,
    );
    *done = if (*ftpc).state as libc::c_uint == FTP_STOP as libc::c_int as libc::c_uint {
        1 as libc::c_int
    } else {
        0 as libc::c_int
    } != 0;
    return result;
}
unsafe extern "C" fn ftp_block_statemach(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut pp: *mut pingpong = &mut (*ftpc).pp;
    let mut result: CURLcode = CURLE_OK;
    while (*ftpc).state as libc::c_uint != FTP_STOP as libc::c_int as libc::c_uint {
        result = Curl_pp_statemach(
            data,
            pp,
            1 as libc::c_int != 0,
            1 as libc::c_int != 0,
        );
        if result as u64 != 0 {
            break;
        }
    }
    return result;
}
unsafe extern "C" fn ftp_connect(
    mut data: *mut Curl_easy,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut pp: *mut pingpong = &mut (*ftpc).pp;
    *done = 0 as libc::c_int != 0;
    Curl_conncontrol(conn, 0 as libc::c_int);
    (*pp).response_time = (120 as libc::c_int * 1000 as libc::c_int) as timediff_t;
    let ref mut fresh49 = (*pp).statemachine;
    *fresh49 = Some(
        ftp_statemachine
            as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode,
    );
    let ref mut fresh50 = (*pp).endofresp;
    *fresh50 = Some(
        ftp_endofresp
            as unsafe extern "C" fn(
                *mut Curl_easy,
                *mut connectdata,
                *mut libc::c_char,
                size_t,
                *mut libc::c_int,
            ) -> bool,
    );
    if (*(*conn).handler).flags
        & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0
    {
        result = Curl_ssl_connect(data, conn, 0 as libc::c_int);
        if result as u64 != 0 {
            return result;
        }
        let ref mut fresh51 = (*conn).bits;
        (*fresh51).set_ftp_use_control_ssl(1 as libc::c_int as bit);
    }
    Curl_pp_setup(pp);
    Curl_pp_init(data, pp);
    _state(data, FTP_WAIT220);
    result = ftp_multi_statemach(data, done);
    return result;
}
unsafe extern "C" fn ftp_done(
    mut data: *mut Curl_easy,
    mut status: CURLcode,
    mut premature: bool,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftp: *mut FTP = (*data).req.p.ftp;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut pp: *mut pingpong = &mut (*ftpc).pp;
    let mut nread: ssize_t = 0;
    let mut ftpcode: libc::c_int = 0;
    let mut result: CURLcode = CURLE_OK;
    let mut rawPath: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pathLen: size_t = 0 as libc::c_int as size_t;
    if ftp.is_null() {
        return CURLE_OK;
    }
    let mut current_block_5: u64;
    match status as libc::c_uint {
        23 => {
            current_block_5 = 6900697668027202712;
        }
        36 | 13 | 30 | 10 | 12 | 17 | 19 | 18 | 25 | 9 | 63 | 78 | 0 => {
            current_block_5 = 6900697668027202712;
        }
        _ => {
            current_block_5 = 7085979425372231744;
        }
    }
    match current_block_5 {
        6900697668027202712 => {
            if !premature {
                current_block_5 = 6057473163062296781;
            } else {
                current_block_5 = 7085979425372231744;
            }
        }
        _ => {}
    }
    match current_block_5 {
        7085979425372231744 => {
            (*ftpc).ctl_valid = 0 as libc::c_int != 0;
            (*ftpc).cwdfail = 1 as libc::c_int != 0;
            Curl_conncontrol(conn, 1 as libc::c_int);
            result = status;
        }
        _ => {}
    }
    if ((*data).state).wildcardmatch() != 0 {
        if ((*data).set.chunk_end).is_some() && !((*ftpc).file).is_null() {
            Curl_set_in_callback(data, 1 as libc::c_int != 0);
            ((*data).set.chunk_end)
                .expect("non-null function pointer")((*data).wildcard.customptr);
            Curl_set_in_callback(data, 0 as libc::c_int != 0);
        }
        (*ftpc).known_filesize = -(1 as libc::c_int) as curl_off_t;
    }
    if result as u64 == 0 {
        result = Curl_urldecode(
            data,
            (*ftp).path,
            0 as libc::c_int as size_t,
            &mut rawPath,
            &mut pathLen,
            REJECT_CTRL,
        );
    }
    if result as u64 != 0 {
        (*ftpc).ctl_valid = 0 as libc::c_int != 0;
        Curl_conncontrol(conn, 1 as libc::c_int);
        Curl_cfree
            .expect("non-null function pointer")((*ftpc).prevpath as *mut libc::c_void);
        let ref mut fresh52 = (*ftpc).prevpath;
        *fresh52 = 0 as *mut libc::c_char;
    } else {
        if (*data).set.ftp_filemethod as libc::c_uint
            == FTPFILE_NOCWD as libc::c_int as libc::c_uint
            && *rawPath.offset(0 as libc::c_int as isize) as libc::c_int == '/' as i32
        {
            Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);
        } else {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*ftpc).prevpath as *mut libc::c_void);
            if !(*ftpc).cwdfail {
                if (*data).set.ftp_filemethod as libc::c_uint
                    == FTPFILE_NOCWD as libc::c_int as libc::c_uint
                {
                    pathLen = 0 as libc::c_int as size_t;
                } else {
                    pathLen = (pathLen as libc::c_ulong)
                        .wrapping_sub(
                            if !((*ftpc).file).is_null() {
                                strlen((*ftpc).file)
                            } else {
                                0 as libc::c_int as libc::c_ulong
                            },
                        ) as size_t as size_t;
                }
                *rawPath.offset(pathLen as isize) = '\u{0}' as i32 as libc::c_char;
                let ref mut fresh53 = (*ftpc).prevpath;
                *fresh53 = rawPath;
            } else {
                Curl_cfree
                    .expect("non-null function pointer")(rawPath as *mut libc::c_void);
                let ref mut fresh54 = (*ftpc).prevpath;
                *fresh54 = 0 as *mut libc::c_char;
            }
        }
        if !((*ftpc).prevpath).is_null() {
            Curl_infof(
                data,
                b"Remembering we are in dir \"%s\"\0" as *const u8
                    as *const libc::c_char,
                (*ftpc).prevpath,
            );
        }
    }
    freedirs(ftpc);
    if (*conn).sock[1 as libc::c_int as usize] != -(1 as libc::c_int) {
        if result as u64 == 0 && (*ftpc).dont_check as libc::c_int != 0
            && (*data).req.maxdownload > 0 as libc::c_int as libc::c_long
        {
            result = Curl_pp_sendf(
                data,
                pp,
                b"%s\0" as *const u8 as *const libc::c_char,
                b"ABOR\0" as *const u8 as *const libc::c_char,
            );
            if result as u64 != 0 {
                Curl_failf(
                    data,
                    b"Failure sending ABOR command: %s\0" as *const u8
                        as *const libc::c_char,
                    curl_easy_strerror(result),
                );
                (*ftpc).ctl_valid = 0 as libc::c_int != 0;
                Curl_conncontrol(conn, 1 as libc::c_int);
            }
        }
        if ((*conn).ssl[1 as libc::c_int as usize]).use_0() != 0 {
            Curl_ssl_close(data, conn, 1 as libc::c_int);
        }
        close_secondarysocket(data, conn);
    }
    if result as u64 == 0
        && (*ftp).transfer as libc::c_uint
            == PPTRANSFER_BODY as libc::c_int as libc::c_uint
        && (*ftpc).ctl_valid as libc::c_int != 0
        && (*pp).pending_resp as libc::c_int != 0 && !premature
    {
        let mut old_time: timediff_t = (*pp).response_time;
        (*pp).response_time = (60 as libc::c_int * 1000 as libc::c_int) as timediff_t;
        (*pp).response = Curl_now();
        result = Curl_GetFTPResponse(data, &mut nread, &mut ftpcode);
        (*pp).response_time = old_time;
        if nread == 0
            && CURLE_OPERATION_TIMEDOUT as libc::c_int as libc::c_uint
                == result as libc::c_uint
        {
            Curl_failf(
                data,
                b"control connection looks dead\0" as *const u8 as *const libc::c_char,
            );
            (*ftpc).ctl_valid = 0 as libc::c_int != 0;
            Curl_conncontrol(conn, 1 as libc::c_int);
        }
        if result as u64 != 0 {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*ftp).pathalloc as *mut libc::c_void);
            let ref mut fresh55 = (*ftp).pathalloc;
            *fresh55 = 0 as *mut libc::c_char;
            return result;
        }
        if (*ftpc).dont_check as libc::c_int != 0
            && (*data).req.maxdownload > 0 as libc::c_int as libc::c_long
        {
            Curl_infof(
                data,
                b"partial download completed, closing connection\0" as *const u8
                    as *const libc::c_char,
            );
            Curl_conncontrol(conn, 1 as libc::c_int);
            return result;
        }
        if !(*ftpc).dont_check {
            match ftpcode {
                226 | 250 => {}
                552 => {
                    Curl_failf(
                        data,
                        b"Exceeded storage allocation\0" as *const u8
                            as *const libc::c_char,
                    );
                    result = CURLE_REMOTE_DISK_FULL;
                }
                _ => {
                    Curl_failf(
                        data,
                        b"server did not report OK, got %d\0" as *const u8
                            as *const libc::c_char,
                        ftpcode,
                    );
                    result = CURLE_PARTIAL_FILE;
                }
            }
        }
    }
    if !(result as libc::c_uint != 0 || premature as libc::c_int != 0) {
        if ((*data).set).upload() != 0 {
            if -(1 as libc::c_int) as libc::c_long != (*data).state.infilesize
                && (*data).state.infilesize != (*data).req.writebytecount
                && ((*data).set).crlf() == 0
                && (*ftp).transfer as libc::c_uint
                    == PPTRANSFER_BODY as libc::c_int as libc::c_uint
            {
                Curl_failf(
                    data,
                    b"Uploaded unaligned file size (%ld out of %ld bytes)\0" as *const u8
                        as *const libc::c_char,
                    (*data).req.bytecount,
                    (*data).state.infilesize,
                );
                result = CURLE_PARTIAL_FILE;
            }
        } else if -(1 as libc::c_int) as libc::c_long != (*data).req.size
                && (*data).req.size != (*data).req.bytecount
                && (*data).req.size + (*data).state.crlf_conversions
                    != (*data).req.bytecount
                && (*data).req.maxdownload != (*data).req.bytecount
            {
            Curl_failf(
                data,
                b"Received only partial file: %ld bytes\0" as *const u8
                    as *const libc::c_char,
                (*data).req.bytecount,
            );
            result = CURLE_PARTIAL_FILE;
        } else if !(*ftpc).dont_check && (*data).req.bytecount == 0
                && (*data).req.size > 0 as libc::c_int as libc::c_long
            {
            Curl_failf(
                data,
                b"No data was received!\0" as *const u8 as *const libc::c_char,
            );
            result = CURLE_FTP_COULDNT_RETR_FILE;
        }
    }
    (*ftp).transfer = PPTRANSFER_BODY;
    (*ftpc).dont_check = 0 as libc::c_int != 0;
    if status as u64 == 0 && result as u64 == 0 && !premature
        && !((*data).set.postquote).is_null()
    {
        result = ftp_sendquote(data, conn, (*data).set.postquote);
    }
    Curl_cfree
        .expect("non-null function pointer")((*ftp).pathalloc as *mut libc::c_void);
    let ref mut fresh56 = (*ftp).pathalloc;
    *fresh56 = 0 as *mut libc::c_char;
    return result;
}
unsafe extern "C" fn ftp_sendquote(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut quote: *mut curl_slist,
) -> CURLcode {
    let mut item: *mut curl_slist = 0 as *mut curl_slist;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut pp: *mut pingpong = &mut (*ftpc).pp;
    item = quote;
    while !item.is_null() {
        if !((*item).data).is_null() {
            let mut nread: ssize_t = 0;
            let mut cmd: *mut libc::c_char = (*item).data;
            let mut acceptfail: bool = 0 as libc::c_int != 0;
            let mut result: CURLcode = CURLE_OK;
            let mut ftpcode: libc::c_int = 0 as libc::c_int;
            if *cmd.offset(0 as libc::c_int as isize) as libc::c_int == '*' as i32 {
                cmd = cmd.offset(1);
                acceptfail = 1 as libc::c_int != 0;
            }
            result = Curl_pp_sendf(
                data,
                &mut (*ftpc).pp as *mut pingpong,
                b"%s\0" as *const u8 as *const libc::c_char,
                cmd,
            );
            if result as u64 == 0 {
                (*pp).response = Curl_now();
                result = Curl_GetFTPResponse(data, &mut nread, &mut ftpcode);
            }
            if result as u64 != 0 {
                return result;
            }
            if !acceptfail && ftpcode >= 400 as libc::c_int {
                Curl_failf(
                    data,
                    b"QUOT string not accepted: %s\0" as *const u8
                        as *const libc::c_char,
                    cmd,
                );
                return CURLE_QUOTE_ERROR;
            }
        }
        item = (*item).next;
    }
    return CURLE_OK;
}
unsafe extern "C" fn ftp_need_type(
    mut conn: *mut connectdata,
    mut ascii_wanted: bool,
) -> libc::c_int {
    return ((*conn).proto.ftpc.transfertype as libc::c_int
        != (if ascii_wanted as libc::c_int != 0 { 'A' as i32 } else { 'I' as i32 }))
        as libc::c_int;
}
unsafe extern "C" fn ftp_nb_type(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut ascii: bool,
    mut newstate: ftpstate,
) -> CURLcode {
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut result: CURLcode = CURLE_OK;
    let mut want: libc::c_char = (if ascii as libc::c_int != 0 {
        'A' as i32
    } else {
        'I' as i32
    }) as libc::c_char;
    if (*ftpc).transfertype as libc::c_int == want as libc::c_int {
        _state(data, newstate);
        return ftp_state_type_resp(data, 200 as libc::c_int, newstate);
    }
    result = Curl_pp_sendf(
        data,
        &mut (*ftpc).pp as *mut pingpong,
        b"TYPE %c\0" as *const u8 as *const libc::c_char,
        want as libc::c_int,
    );
    if result as u64 == 0 {
        _state(data, newstate);
        (*ftpc).transfertype = want;
    }
    return result;
}
unsafe extern "C" fn ftp_pasv_verbose(
    mut data: *mut Curl_easy,
    mut ai: *mut Curl_addrinfo,
    mut newhost: *mut libc::c_char,
    mut port: libc::c_int,
) {
    let mut buf: [libc::c_char; 256] = [0; 256];
    Curl_printable_address(
        ai,
        buf.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
    );
    Curl_infof(
        data,
        b"Connecting to %s (%s) port %d\0" as *const u8 as *const libc::c_char,
        newhost,
        buf.as_mut_ptr(),
        port,
    );
}
unsafe extern "C" fn ftp_do_more(
    mut data: *mut Curl_easy,
    mut completep: *mut libc::c_int,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut result: CURLcode = CURLE_OK;
    let mut connected: bool = 0 as libc::c_int != 0;
    let mut complete: bool = 0 as libc::c_int != 0;
    let mut ftp: *mut FTP = (*data).req.p.ftp;
    if !(*conn).bits.tcpconnect[1 as libc::c_int as usize] {
        if Curl_connect_ongoing(conn) {
            result = Curl_proxyCONNECT(
                data,
                1 as libc::c_int,
                0 as *const libc::c_char,
                0 as libc::c_int,
            );
            return result;
        }
        result = Curl_is_connected(data, conn, 1 as libc::c_int, &mut connected);
        if connected {} else {
            if result as libc::c_uint != 0 && (*ftpc).count1 == 0 as libc::c_int {
                *completep = -(1 as libc::c_int);
                return ftp_epsv_disable(data, conn);
            }
            return result;
        }
    }
    result = Curl_proxy_connect(data, 1 as libc::c_int);
    if result as u64 != 0 {
        return result;
    }
    if (*conn).http_proxy.proxytype as libc::c_uint
        == CURLPROXY_HTTPS as libc::c_int as libc::c_uint
        && !(*conn).bits.proxy_ssl_connected[1 as libc::c_int as usize]
    {
        return result;
    }
    if ((*conn).bits).tunnel_proxy() as libc::c_int != 0
        && ((*conn).bits).httpproxy() as libc::c_int != 0
        && Curl_connect_ongoing(conn) as libc::c_int != 0
    {
        return result;
    }
    if (*ftpc).state as u64 != 0 {
        result = ftp_multi_statemach(data, &mut complete);
        *completep = complete as libc::c_int;
        if result as libc::c_uint != 0 || !(*ftpc).wait_data_conn {
            return result;
        }
        *completep = 0 as libc::c_int;
    }
    if (*ftp).transfer as libc::c_uint <= PPTRANSFER_INFO as libc::c_int as libc::c_uint
    {
        if (*ftpc).wait_data_conn as libc::c_int == 1 as libc::c_int {
            let mut serv_conned: bool = false;
            result = ReceivedServerConnect(data, &mut serv_conned);
            if result as u64 != 0 {
                return result;
            }
            if serv_conned {
                result = AcceptServerConnect(data);
                (*ftpc).wait_data_conn = 0 as libc::c_int != 0;
                if result as u64 == 0 {
                    result = InitiateTransfer(data);
                }
                if result as u64 != 0 {
                    return result;
                }
                *completep = 1 as libc::c_int;
            }
        } else if ((*data).set).upload() != 0 {
            result = ftp_nb_type(
                data,
                conn,
                ((*data).state).prefer_ascii() != 0,
                FTP_STOR_TYPE,
            );
            if result as u64 != 0 {
                return result;
            }
            result = ftp_multi_statemach(data, &mut complete);
            if (*ftpc).wait_data_conn {
                *completep = 0 as libc::c_int;
            } else {
                *completep = complete as libc::c_int;
            }
        } else {
            (*ftp).downloadsize = -(1 as libc::c_int) as curl_off_t;
            result = Curl_range(data);
            if result as libc::c_uint == CURLE_OK as libc::c_int as libc::c_uint
                && (*data).req.maxdownload >= 0 as libc::c_int as libc::c_long
            {
                (*ftpc).dont_check = 1 as libc::c_int != 0;
            }
            if !(result as u64 != 0) {
                if ((*data).state).list_only() as libc::c_int != 0
                    || ((*ftpc).file).is_null()
                {
                    if (*ftp).transfer as libc::c_uint
                        == PPTRANSFER_BODY as libc::c_int as libc::c_uint
                    {
                        result = ftp_nb_type(
                            data,
                            conn,
                            1 as libc::c_int != 0,
                            FTP_LIST_TYPE,
                        );
                        if result as u64 != 0 {
                            return result;
                        }
                    }
                } else {
                    result = ftp_nb_type(
                        data,
                        conn,
                        ((*data).state).prefer_ascii() != 0,
                        FTP_RETR_TYPE,
                    );
                    if result as u64 != 0 {
                        return result;
                    }
                }
            }
            result = ftp_multi_statemach(data, &mut complete);
            *completep = complete as libc::c_int;
        }
        return result;
    }
    Curl_setup_transfer(
        data,
        -(1 as libc::c_int),
        -(1 as libc::c_int) as curl_off_t,
        0 as libc::c_int != 0,
        -(1 as libc::c_int),
    );
    if !(*ftpc).wait_data_conn {
        *completep = 1 as libc::c_int;
    }
    return result;
}
unsafe extern "C" fn ftp_perform(
    mut data: *mut Curl_easy,
    mut connected: *mut bool,
    mut dophase_done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    if ((*data).set).opt_no_body() != 0 {
        let mut ftp: *mut FTP = (*data).req.p.ftp;
        (*ftp).transfer = PPTRANSFER_INFO;
    }
    *dophase_done = 0 as libc::c_int != 0;
    result = ftp_state_quote(data, 1 as libc::c_int != 0, FTP_QUOTE);
    if result as u64 != 0 {
        return result;
    }
    result = ftp_multi_statemach(data, dophase_done);
    *connected = (*conn).bits.tcpconnect[1 as libc::c_int as usize];
    Curl_infof(
        data,
        b"ftp_perform ends with SECONDARY: %d\0" as *const u8 as *const libc::c_char,
        *connected as libc::c_int,
    );
    *dophase_done;
    return result;
}
unsafe extern "C" fn wc_data_dtor(mut ptr: *mut libc::c_void) {
    let mut ftpwc: *mut ftp_wc = ptr as *mut ftp_wc;
    if !ftpwc.is_null() && !((*ftpwc).parser).is_null() {
        Curl_ftp_parselist_data_free(&mut (*ftpwc).parser);
    }
    Curl_cfree.expect("non-null function pointer")(ftpwc as *mut libc::c_void);
}
unsafe extern "C" fn init_wc_data(mut data: *mut Curl_easy) -> CURLcode {
    let mut last_slash: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ftp: *mut FTP = (*data).req.p.ftp;
    let mut path: *mut libc::c_char = (*ftp).path;
    let mut wildcard: *mut WildcardData = &mut (*data).wildcard;
    let mut result: CURLcode = CURLE_OK;
    let mut ftpwc: *mut ftp_wc = 0 as *mut ftp_wc;
    last_slash = strrchr((*ftp).path, '/' as i32);
    if !last_slash.is_null() {
        last_slash = last_slash.offset(1);
        if *last_slash.offset(0 as libc::c_int as isize) as libc::c_int == '\u{0}' as i32
        {
            (*wildcard).state = CURLWC_CLEAN;
            result = ftp_parse_url_path(data);
            return result;
        }
        let ref mut fresh57 = (*wildcard).pattern;
        *fresh57 = Curl_cstrdup.expect("non-null function pointer")(last_slash);
        if ((*wildcard).pattern).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        *last_slash.offset(0 as libc::c_int as isize) = '\u{0}' as i32 as libc::c_char;
    } else if *path.offset(0 as libc::c_int as isize) != 0 {
        let ref mut fresh58 = (*wildcard).pattern;
        *fresh58 = Curl_cstrdup.expect("non-null function pointer")(path);
        if ((*wildcard).pattern).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        *path.offset(0 as libc::c_int as isize) = '\u{0}' as i32 as libc::c_char;
    } else {
        (*wildcard).state = CURLWC_CLEAN;
        result = ftp_parse_url_path(data);
        return result;
    }
    ftpwc = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(1 as libc::c_int as size_t, ::std::mem::size_of::<ftp_wc>() as libc::c_ulong)
        as *mut ftp_wc;
    if ftpwc.is_null() {
        result = CURLE_OUT_OF_MEMORY;
    } else {
        let ref mut fresh59 = (*ftpwc).parser;
        *fresh59 = Curl_ftp_parselist_data_alloc();
        if ((*ftpwc).parser).is_null() {
            result = CURLE_OUT_OF_MEMORY;
        } else {
            let ref mut fresh60 = (*wildcard).protdata;
            *fresh60 = ftpwc as *mut libc::c_void;
            let ref mut fresh61 = (*wildcard).dtor;
            *fresh61 = Some(
                wc_data_dtor as unsafe extern "C" fn(*mut libc::c_void) -> (),
            );
            if (*data).set.ftp_filemethod as libc::c_uint
                == FTPFILE_NOCWD as libc::c_int as libc::c_uint
            {
                (*data).set.ftp_filemethod = FTPFILE_MULTICWD;
            }
            result = ftp_parse_url_path(data);
            if !(result as u64 != 0) {
                let ref mut fresh62 = (*wildcard).path;
                *fresh62 = Curl_cstrdup.expect("non-null function pointer")((*ftp).path);
                if ((*wildcard).path).is_null() {
                    result = CURLE_OUT_OF_MEMORY;
                } else {
                    let ref mut fresh63 = (*ftpwc).backup.write_function;
                    *fresh63 = (*data).set.fwrite_func;
                    let ref mut fresh64 = (*data).set.fwrite_func;
                    *fresh64 = Some(
                        Curl_ftp_parselist
                            as unsafe extern "C" fn(
                                *mut libc::c_char,
                                size_t,
                                size_t,
                                *mut libc::c_void,
                            ) -> size_t,
                    );
                    let ref mut fresh65 = (*ftpwc).backup.file_descriptor;
                    *fresh65 = (*data).set.out as *mut FILE;
                    let ref mut fresh66 = (*data).set.out;
                    *fresh66 = data as *mut libc::c_void;
                    Curl_infof(
                        data,
                        b"Wildcard - Parsing started\0" as *const u8
                            as *const libc::c_char,
                    );
                    return CURLE_OK;
                }
            }
        }
    }
    if !ftpwc.is_null() {
        Curl_ftp_parselist_data_free(&mut (*ftpwc).parser);
        Curl_cfree.expect("non-null function pointer")(ftpwc as *mut libc::c_void);
    }
    Curl_cfree
        .expect("non-null function pointer")((*wildcard).pattern as *mut libc::c_void);
    let ref mut fresh67 = (*wildcard).pattern;
    *fresh67 = 0 as *mut libc::c_char;
    let ref mut fresh68 = (*wildcard).dtor;
    *fresh68 = None;
    let ref mut fresh69 = (*wildcard).protdata;
    *fresh69 = 0 as *mut libc::c_void;
    return result;
}
unsafe extern "C" fn wc_statemach(mut data: *mut Curl_easy) -> CURLcode {
    let wildcard: *mut WildcardData = &mut (*data).wildcard;
    let mut conn: *mut connectdata = (*data).conn;
    let mut result: CURLcode = CURLE_OK;
    let mut current_block_53: u64;
    loop {
        match (*wildcard).state as libc::c_uint {
            1 => {
                result = init_wc_data(data);
                if (*wildcard).state as libc::c_uint
                    == CURLWC_CLEAN as libc::c_int as libc::c_uint
                {
                    return result;
                }
                (*wildcard)
                    .state = (if result as libc::c_uint != 0 {
                    CURLWC_ERROR as libc::c_int
                } else {
                    CURLWC_MATCHING as libc::c_int
                }) as wildcard_states;
                return result;
            }
            2 => {
                let mut ftpwc: *mut ftp_wc = (*wildcard).protdata as *mut ftp_wc;
                let ref mut fresh70 = (*data).set.fwrite_func;
                *fresh70 = (*ftpwc).backup.write_function;
                let ref mut fresh71 = (*data).set.out;
                *fresh71 = (*ftpwc).backup.file_descriptor as *mut libc::c_void;
                let ref mut fresh72 = (*ftpwc).backup.write_function;
                *fresh72 = None;
                let ref mut fresh73 = (*ftpwc).backup.file_descriptor;
                *fresh73 = 0 as *mut FILE;
                (*wildcard).state = CURLWC_DOWNLOADING;
                if Curl_ftp_parselist_geterror((*ftpwc).parser) as u64 != 0 {
                    (*wildcard).state = CURLWC_CLEAN;
                } else if (*wildcard).filelist.size == 0 as libc::c_int as libc::c_ulong
                    {
                    (*wildcard).state = CURLWC_CLEAN;
                    return CURLE_REMOTE_FILE_NOT_FOUND;
                }
            }
            3 => {
                let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
                let mut finfo: *mut curl_fileinfo = (*(*wildcard).filelist.head).ptr
                    as *mut curl_fileinfo;
                let mut ftp: *mut FTP = (*data).req.p.ftp;
                let mut tmp_path: *mut libc::c_char = curl_maprintf(
                    b"%s%s\0" as *const u8 as *const libc::c_char,
                    (*wildcard).path,
                    (*finfo).filename,
                );
                if tmp_path.is_null() {
                    return CURLE_OUT_OF_MEMORY;
                }
                Curl_cfree
                    .expect(
                        "non-null function pointer",
                    )((*ftp).pathalloc as *mut libc::c_void);
                let ref mut fresh74 = (*ftp).path;
                *fresh74 = tmp_path;
                let ref mut fresh75 = (*ftp).pathalloc;
                *fresh75 = *fresh74;
                Curl_infof(
                    data,
                    b"Wildcard - START of \"%s\"\0" as *const u8 as *const libc::c_char,
                    (*finfo).filename,
                );
                if ((*data).set.chunk_bgn).is_some() {
                    let mut userresponse: libc::c_long = 0;
                    Curl_set_in_callback(data, 1 as libc::c_int != 0);
                    userresponse = ((*data).set.chunk_bgn)
                        .expect(
                            "non-null function pointer",
                        )(
                        finfo as *const libc::c_void,
                        (*wildcard).customptr,
                        (*wildcard).filelist.size as libc::c_int,
                    );
                    Curl_set_in_callback(data, 0 as libc::c_int != 0);
                    match userresponse {
                        2 => {
                            current_block_53 = 12241815505008426805;
                            match current_block_53 {
                                15782252138314684429 => return CURLE_CHUNK_FAILED,
                                _ => {
                                    Curl_infof(
                                        data,
                                        b"Wildcard - \"%s\" skipped by user\0" as *const u8
                                            as *const libc::c_char,
                                        (*finfo).filename,
                                    );
                                    (*wildcard).state = CURLWC_SKIP;
                                    continue;
                                }
                            }
                        }
                        1 => {
                            current_block_53 = 15782252138314684429;
                            match current_block_53 {
                                15782252138314684429 => return CURLE_CHUNK_FAILED,
                                _ => {
                                    Curl_infof(
                                        data,
                                        b"Wildcard - \"%s\" skipped by user\0" as *const u8
                                            as *const libc::c_char,
                                        (*finfo).filename,
                                    );
                                    (*wildcard).state = CURLWC_SKIP;
                                    continue;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if (*finfo).filetype as libc::c_uint
                    != CURLFILETYPE_FILE as libc::c_int as libc::c_uint
                {
                    (*wildcard).state = CURLWC_SKIP;
                } else {
                    if (*finfo).flags
                        & ((1 as libc::c_int) << 6 as libc::c_int) as libc::c_uint != 0
                    {
                        (*ftpc).known_filesize = (*finfo).size;
                    }
                    result = ftp_parse_url_path(data);
                    if result as u64 != 0 {
                        return result;
                    }
                    Curl_llist_remove(
                        &mut (*wildcard).filelist,
                        (*wildcard).filelist.head,
                        0 as *mut libc::c_void,
                    );
                    if (*wildcard).filelist.size == 0 as libc::c_int as libc::c_ulong {
                        (*wildcard).state = CURLWC_CLEAN;
                        return CURLE_OK;
                    }
                    return result;
                }
            }
            5 => {
                if ((*data).set.chunk_end).is_some() {
                    Curl_set_in_callback(data, 1 as libc::c_int != 0);
                    ((*data).set.chunk_end)
                        .expect("non-null function pointer")((*data).wildcard.customptr);
                    Curl_set_in_callback(data, 0 as libc::c_int != 0);
                }
                Curl_llist_remove(
                    &mut (*wildcard).filelist,
                    (*wildcard).filelist.head,
                    0 as *mut libc::c_void,
                );
                (*wildcard)
                    .state = (if (*wildcard).filelist.size
                    == 0 as libc::c_int as libc::c_ulong
                {
                    CURLWC_CLEAN as libc::c_int
                } else {
                    CURLWC_DOWNLOADING as libc::c_int
                }) as wildcard_states;
            }
            4 => {
                let mut ftpwc_0: *mut ftp_wc = (*wildcard).protdata as *mut ftp_wc;
                result = CURLE_OK;
                if !ftpwc_0.is_null() {
                    result = Curl_ftp_parselist_geterror((*ftpwc_0).parser);
                }
                (*wildcard)
                    .state = (if result as libc::c_uint != 0 {
                    CURLWC_ERROR as libc::c_int
                } else {
                    CURLWC_DONE as libc::c_int
                }) as wildcard_states;
                return result;
            }
            7 | 6 | 0 => {
                if ((*wildcard).dtor).is_some() {
                    ((*wildcard).dtor)
                        .expect("non-null function pointer")((*wildcard).protdata);
                }
                return result;
            }
            _ => {}
        }
    };
}
unsafe extern "C" fn ftp_do(mut data: *mut Curl_easy, mut done: *mut bool) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    *done = 0 as libc::c_int != 0;
    (*ftpc).wait_data_conn = 0 as libc::c_int != 0;
    if ((*data).state).wildcardmatch() != 0 {
        result = wc_statemach(data);
        if (*data).wildcard.state as libc::c_uint
            == CURLWC_SKIP as libc::c_int as libc::c_uint
            || (*data).wildcard.state as libc::c_uint
                == CURLWC_DONE as libc::c_int as libc::c_uint
        {
            return CURLE_OK;
        }
        if result as u64 != 0 {
            return result;
        }
    } else {
        result = ftp_parse_url_path(data);
        if result as u64 != 0 {
            return result;
        }
    }
    result = ftp_regular_transfer(data, done);
    return result;
}
unsafe extern "C" fn ftp_quit(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    if (*conn).proto.ftpc.ctl_valid {
        result = Curl_pp_sendf(
            data,
            &mut (*conn).proto.ftpc.pp as *mut pingpong,
            b"%s\0" as *const u8 as *const libc::c_char,
            b"QUIT\0" as *const u8 as *const libc::c_char,
        );
        if result as u64 != 0 {
            Curl_failf(
                data,
                b"Failure sending QUIT command: %s\0" as *const u8
                    as *const libc::c_char,
                curl_easy_strerror(result),
            );
            (*conn).proto.ftpc.ctl_valid = 0 as libc::c_int != 0;
            Curl_conncontrol(conn, 1 as libc::c_int);
            _state(data, FTP_STOP);
            return result;
        }
        _state(data, FTP_QUIT);
        result = ftp_block_statemach(data, conn);
    }
    return result;
}
unsafe extern "C" fn ftp_disconnect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut dead_connection: bool,
) -> CURLcode {
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut pp: *mut pingpong = &mut (*ftpc).pp;
    if dead_connection {
        (*ftpc).ctl_valid = 0 as libc::c_int != 0;
    }
    ftp_quit(data, conn);
    if !((*ftpc).entrypath).is_null() {
        if (*data).state.most_recent_ftp_entrypath == (*ftpc).entrypath {
            let ref mut fresh76 = (*data).state.most_recent_ftp_entrypath;
            *fresh76 = 0 as *mut libc::c_char;
        }
        Curl_cfree
            .expect("non-null function pointer")((*ftpc).entrypath as *mut libc::c_void);
        let ref mut fresh77 = (*ftpc).entrypath;
        *fresh77 = 0 as *mut libc::c_char;
    }
    freedirs(ftpc);
    Curl_cfree
        .expect("non-null function pointer")((*ftpc).prevpath as *mut libc::c_void);
    let ref mut fresh78 = (*ftpc).prevpath;
    *fresh78 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect("non-null function pointer")((*ftpc).server_os as *mut libc::c_void);
    let ref mut fresh79 = (*ftpc).server_os;
    *fresh79 = 0 as *mut libc::c_char;
    Curl_pp_disconnect(pp);
    return CURLE_OK;
}
unsafe extern "C" fn ftp_parse_url_path(mut data: *mut Curl_easy) -> CURLcode {
    let mut ftp: *mut FTP = (*data).req.p.ftp;
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    let mut slashPos: *const libc::c_char = 0 as *const libc::c_char;
    let mut fileName: *const libc::c_char = 0 as *const libc::c_char;
    let mut result: CURLcode = CURLE_OK;
    let mut rawPath: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pathLen: size_t = 0 as libc::c_int as size_t;
    (*ftpc).ctl_valid = 0 as libc::c_int != 0;
    (*ftpc).cwdfail = 0 as libc::c_int != 0;
    result = Curl_urldecode(
        data,
        (*ftp).path,
        0 as libc::c_int as size_t,
        &mut rawPath,
        &mut pathLen,
        REJECT_CTRL,
    );
    if result as u64 != 0 {
        return result;
    }
    match (*data).set.ftp_filemethod as libc::c_uint {
        2 => {
            if pathLen > 0 as libc::c_int as libc::c_ulong
                && *rawPath
                    .offset(
                        pathLen.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                    ) as libc::c_int != '/' as i32
            {
                fileName = rawPath;
            }
        }
        3 => {
            slashPos = strrchr(rawPath, '/' as i32);
            if !slashPos.is_null() {
                let mut dirlen: size_t = slashPos.offset_from(rawPath) as libc::c_long
                    as size_t;
                if dirlen == 0 as libc::c_int as libc::c_ulong {
                    dirlen = dirlen.wrapping_add(1);
                }
                let ref mut fresh80 = (*ftpc).dirs;
                *fresh80 = Curl_ccalloc
                    .expect(
                        "non-null function pointer",
                    )(
                    1 as libc::c_int as size_t,
                    ::std::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                ) as *mut *mut libc::c_char;
                if ((*ftpc).dirs).is_null() {
                    Curl_cfree
                        .expect(
                            "non-null function pointer",
                        )(rawPath as *mut libc::c_void);
                    return CURLE_OUT_OF_MEMORY;
                }
                let ref mut fresh81 = *((*ftpc).dirs).offset(0 as libc::c_int as isize);
                *fresh81 = Curl_ccalloc
                    .expect(
                        "non-null function pointer",
                    )(
                    1 as libc::c_int as size_t,
                    dirlen.wrapping_add(1 as libc::c_int as libc::c_ulong),
                ) as *mut libc::c_char;
                if (*((*ftpc).dirs).offset(0 as libc::c_int as isize)).is_null() {
                    Curl_cfree
                        .expect(
                            "non-null function pointer",
                        )(rawPath as *mut libc::c_void);
                    return CURLE_OUT_OF_MEMORY;
                }
                strncpy(
                    *((*ftpc).dirs).offset(0 as libc::c_int as isize),
                    rawPath,
                    dirlen,
                );
                (*ftpc).dirdepth = 1 as libc::c_int;
                fileName = slashPos.offset(1 as libc::c_int as isize);
            } else {
                fileName = rawPath;
            }
        }
        1 | _ => {
            let mut curPos: *const libc::c_char = rawPath;
            let mut dirAlloc: libc::c_int = 0 as libc::c_int;
            let mut str: *const libc::c_char = rawPath;
            while *str as libc::c_int != 0 as libc::c_int {
                if *str as libc::c_int == '/' as i32 {
                    dirAlloc += 1;
                }
                str = str.offset(1);
            }
            if dirAlloc > 0 as libc::c_int {
                let ref mut fresh82 = (*ftpc).dirs;
                *fresh82 = Curl_ccalloc
                    .expect(
                        "non-null function pointer",
                    )(
                    dirAlloc as size_t,
                    ::std::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                ) as *mut *mut libc::c_char;
                if ((*ftpc).dirs).is_null() {
                    Curl_cfree
                        .expect(
                            "non-null function pointer",
                        )(rawPath as *mut libc::c_void);
                    return CURLE_OUT_OF_MEMORY;
                }
                loop {
                    slashPos = strchr(curPos, '/' as i32);
                    if slashPos.is_null() {
                        break;
                    }
                    let mut compLen: size_t = slashPos.offset_from(curPos)
                        as libc::c_long as size_t;
                    if compLen == 0 as libc::c_int as libc::c_ulong
                        && (*ftpc).dirdepth == 0 as libc::c_int
                    {
                        compLen = compLen.wrapping_add(1);
                    }
                    if compLen > 0 as libc::c_int as libc::c_ulong {
                        let mut comp: *mut libc::c_char = Curl_ccalloc
                            .expect(
                                "non-null function pointer",
                            )(
                            1 as libc::c_int as size_t,
                            compLen.wrapping_add(1 as libc::c_int as libc::c_ulong),
                        ) as *mut libc::c_char;
                        if comp.is_null() {
                            Curl_cfree
                                .expect(
                                    "non-null function pointer",
                                )(rawPath as *mut libc::c_void);
                            return CURLE_OUT_OF_MEMORY;
                        }
                        strncpy(comp, curPos, compLen);
                        let ref mut fresh83 = (*ftpc).dirdepth;
                        let fresh84 = *fresh83;
                        *fresh83 = *fresh83 + 1;
                        let ref mut fresh85 = *((*ftpc).dirs).offset(fresh84 as isize);
                        *fresh85 = comp;
                    }
                    curPos = slashPos.offset(1 as libc::c_int as isize);
                }
            }
            fileName = curPos;
        }
    }
    if !fileName.is_null() && *fileName as libc::c_int != 0 {
        let ref mut fresh86 = (*ftpc).file;
        *fresh86 = Curl_cstrdup.expect("non-null function pointer")(fileName);
    } else {
        let ref mut fresh87 = (*ftpc).file;
        *fresh87 = 0 as *mut libc::c_char;
    }
    if ((*data).set).upload() as libc::c_int != 0 && ((*ftpc).file).is_null()
        && (*ftp).transfer as libc::c_uint
            == PPTRANSFER_BODY as libc::c_int as libc::c_uint
    {
        Curl_failf(
            data,
            b"Uploading to a URL without a file name!\0" as *const u8
                as *const libc::c_char,
        );
        Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);
        return CURLE_URL_MALFORMAT;
    }
    (*ftpc).cwddone = 0 as libc::c_int != 0;
    if (*data).set.ftp_filemethod as libc::c_uint
        == FTPFILE_NOCWD as libc::c_int as libc::c_uint
        && *rawPath.offset(0 as libc::c_int as isize) as libc::c_int == '/' as i32
    {
        (*ftpc).cwddone = 1 as libc::c_int != 0;
    } else {
        let mut oldPath: *const libc::c_char = if ((*conn).bits).reuse() as libc::c_int
            != 0
        {
            (*ftpc).prevpath as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        };
        if !oldPath.is_null() {
            let mut n: size_t = pathLen;
            if (*data).set.ftp_filemethod as libc::c_uint
                == FTPFILE_NOCWD as libc::c_int as libc::c_uint
            {
                n = 0 as libc::c_int as size_t;
            } else {
                n = (n as libc::c_ulong)
                    .wrapping_sub(
                        if !((*ftpc).file).is_null() {
                            strlen((*ftpc).file)
                        } else {
                            0 as libc::c_int as libc::c_ulong
                        },
                    ) as size_t as size_t;
            }
            if strlen(oldPath) == n && strncmp(rawPath, oldPath, n) == 0 {
                Curl_infof(
                    data,
                    b"Request has same path as previous transfer\0" as *const u8
                        as *const libc::c_char,
                );
                (*ftpc).cwddone = 1 as libc::c_int != 0;
            }
        }
    }
    Curl_cfree.expect("non-null function pointer")(rawPath as *mut libc::c_void);
    return CURLE_OK;
}
unsafe extern "C" fn ftp_dophase_done(
    mut data: *mut Curl_easy,
    mut connected: bool,
) -> CURLcode {
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftp: *mut FTP = (*data).req.p.ftp;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    if connected {
        let mut completed: libc::c_int = 0;
        let mut result: CURLcode = ftp_do_more(data, &mut completed);
        if result as u64 != 0 {
            close_secondarysocket(data, conn);
            return result;
        }
    }
    if (*ftp).transfer as libc::c_uint != PPTRANSFER_BODY as libc::c_int as libc::c_uint
    {
        Curl_setup_transfer(
            data,
            -(1 as libc::c_int),
            -(1 as libc::c_int) as curl_off_t,
            0 as libc::c_int != 0,
            -(1 as libc::c_int),
        );
    } else if !connected {
        let ref mut fresh88 = (*conn).bits;
        (*fresh88).set_do_more(1 as libc::c_int as bit);
    }
    (*ftpc).ctl_valid = 1 as libc::c_int != 0;
    return CURLE_OK;
}
unsafe extern "C" fn ftp_doing(
    mut data: *mut Curl_easy,
    mut dophase_done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = ftp_multi_statemach(data, dophase_done);
    if !(result as u64 != 0) {
        if *dophase_done {
            result = ftp_dophase_done(data, 0 as libc::c_int != 0);
        }
    }
    return result;
}
unsafe extern "C" fn ftp_regular_transfer(
    mut data: *mut Curl_easy,
    mut dophase_done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut connected: bool = 0 as libc::c_int != 0;
    let mut conn: *mut connectdata = (*data).conn;
    let mut ftpc: *mut ftp_conn = &mut (*conn).proto.ftpc;
    (*data).req.size = -(1 as libc::c_int) as curl_off_t;
    Curl_pgrsSetUploadCounter(data, 0 as libc::c_int as curl_off_t);
    Curl_pgrsSetDownloadCounter(data, 0 as libc::c_int as curl_off_t);
    Curl_pgrsSetUploadSize(data, -(1 as libc::c_int) as curl_off_t);
    Curl_pgrsSetDownloadSize(data, -(1 as libc::c_int) as curl_off_t);
    (*ftpc).ctl_valid = 1 as libc::c_int != 0;
    result = ftp_perform(data, &mut connected, dophase_done);
    if result as u64 == 0 {
        if !*dophase_done {
            return CURLE_OK;
        }
        result = ftp_dophase_done(data, connected);
        if result as u64 != 0 {
            return result;
        }
    } else {
        freedirs(ftpc);
    }
    return result;
}
unsafe extern "C" fn ftp_setup_connection(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut type_0: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ftp: *mut FTP = 0 as *mut FTP;
    ftp = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<FTP>() as libc::c_ulong, 1 as libc::c_int as size_t)
        as *mut FTP;
    let ref mut fresh89 = (*data).req.p.ftp;
    *fresh89 = ftp;
    if ftp.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    let ref mut fresh90 = (*ftp).path;
    *fresh90 = &mut *((*data).state.up.path).offset(1 as libc::c_int as isize)
        as *mut libc::c_char;
    type_0 = strstr((*ftp).path, b";type=\0" as *const u8 as *const libc::c_char);
    if type_0.is_null() {
        type_0 = strstr(
            (*conn).host.rawalloc,
            b";type=\0" as *const u8 as *const libc::c_char,
        );
    }
    if !type_0.is_null() {
        let mut command: libc::c_char = 0;
        *type_0 = 0 as libc::c_int as libc::c_char;
        command = Curl_raw_toupper(*type_0.offset(6 as libc::c_int as isize));
        match command as libc::c_int {
            65 => {
                let ref mut fresh91 = (*data).state;
                (*fresh91).set_prefer_ascii(1 as libc::c_int as bit);
            }
            68 => {
                let ref mut fresh92 = (*data).state;
                (*fresh92).set_list_only(1 as libc::c_int as bit);
            }
            73 | _ => {
                let ref mut fresh93 = (*data).state;
                (*fresh93).set_prefer_ascii(0 as libc::c_int as bit);
            }
        }
    }
    (*ftp).transfer = PPTRANSFER_BODY;
    (*ftp).downloadsize = 0 as libc::c_int as curl_off_t;
    (*conn).proto.ftpc.known_filesize = -(1 as libc::c_int) as curl_off_t;
    return CURLE_OK;
}
