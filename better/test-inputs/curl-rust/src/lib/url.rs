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
    static mut stdin: *mut FILE;
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn Curl_isalpha(c: libc::c_int) -> libc::c_int;
    fn Curl_isxdigit(c: libc::c_int) -> libc::c_int;
    fn __errno_location() -> *mut libc::c_int;
    fn curl_getenv(variable: *const libc::c_char) -> *mut libc::c_char;
    fn curl_slist_free_all(_: *mut curl_slist);
    fn curl_multi_remove_handle(
        multi_handle: *mut CURLM,
        curl_handle: *mut CURL,
    ) -> CURLMcode;
    fn curl_multi_cleanup(multi_handle: *mut CURLM) -> CURLMcode;
    fn curl_url() -> *mut CURLU;
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
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcpy(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn __ctype_tolower_loc() -> *mut *const __int32_t;
    fn fread(
        _: *mut libc::c_void,
        _: libc::c_ulong,
        _: libc::c_ulong,
        _: *mut FILE,
    ) -> libc::c_ulong;
    fn fwrite(
        _: *const libc::c_void,
        _: libc::c_ulong,
        _: libc::c_ulong,
        _: *mut FILE,
    ) -> libc::c_ulong;
    fn if_nametoindex(__ifname: *const libc::c_char) -> libc::c_uint;
    fn Curl_flush_cookies(data: *mut Curl_easy, cleanup: bool);
    fn Curl_now() -> curltime;
    fn Curl_timediff(t1: curltime, t2: curltime) -> timediff_t;
    fn Curl_llist_init(_: *mut Curl_llist, _: Curl_llist_dtor);
    fn Curl_llist_destroy(_: *mut Curl_llist, _: *mut libc::c_void);
    fn Curl_unix2addr(
        path: *const libc::c_char,
        longpath: *mut bool,
        abstract_0: bool,
    ) -> *mut Curl_addrinfo;
    fn Curl_resolver_init(
        easy: *mut Curl_easy,
        resolver: *mut *mut libc::c_void,
    ) -> CURLcode;
    fn Curl_resolver_cleanup(resolver: *mut libc::c_void);
    fn Curl_resolver_cancel(data: *mut Curl_easy);
    fn Curl_resolv_timeout(
        data: *mut Curl_easy,
        hostname: *const libc::c_char,
        port: libc::c_int,
        dnsentry: *mut *mut Curl_dns_entry,
        timeoutms: timediff_t,
    ) -> resolve_t;
    fn Curl_resolv_unlock(data: *mut Curl_easy, dns: *mut Curl_dns_entry);
    fn Curl_dyn_init(s: *mut dynbuf, toobig: size_t);
    fn Curl_dyn_free(s: *mut dynbuf);
    fn Curl_mime_initpart(part: *mut curl_mimepart, easy: *mut Curl_easy);
    fn Curl_mime_cleanpart(part: *mut curl_mimepart);
    static Curl_handler_imap: Curl_handler;
    static Curl_handler_imaps: Curl_handler;
    static Curl_handler_pop3: Curl_handler;
    static Curl_handler_pop3s: Curl_handler;
    static Curl_handler_smtp: Curl_handler;
    static Curl_handler_smtps: Curl_handler;
    static Curl_handler_ftp: Curl_handler;
    static Curl_handler_ftps: Curl_handler;
    static Curl_handler_file: Curl_handler;
    static Curl_handler_http: Curl_handler;
    static Curl_handler_https: Curl_handler;
    static Curl_handler_rtsp: Curl_handler;
    static Curl_handler_smb: Curl_handler;
    static Curl_handler_smbs: Curl_handler;
    static Curl_handler_mqtt: Curl_handler;
    fn Curl_wildcard_dtor(wc: *mut WildcardData);
    fn Curl_conncache_find_bundle(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        connc: *mut conncache,
        hostp: *mut *const libc::c_char,
    ) -> *mut connectbundle;
    fn Curl_conncache_size(data: *mut Curl_easy) -> size_t;
    fn Curl_conncache_add_conn(data: *mut Curl_easy) -> CURLcode;
    fn Curl_conncache_remove_conn(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        lock: bool,
    );
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
    fn Curl_conncache_extract_bundle(
        data: *mut Curl_easy,
        bundle: *mut connectbundle,
    ) -> *mut connectdata;
    fn Curl_conncache_extract_oldest(data: *mut Curl_easy) -> *mut connectdata;
    fn Curl_parsenetrc(
        host: *const libc::c_char,
        loginp: *mut *mut libc::c_char,
        passwordp: *mut *mut libc::c_char,
        login_changed: *mut bool,
        password_changed: *mut bool,
        filename: *mut libc::c_char,
    ) -> libc::c_int;
    static mut Curl_ssl: *const Curl_ssl;
    fn Curl_ssl_config_matches(
        data: *mut ssl_primary_config,
        needle: *mut ssl_primary_config,
    ) -> bool;
    fn Curl_clone_primary_ssl_config(
        source: *mut ssl_primary_config,
        dest: *mut ssl_primary_config,
    ) -> bool;
    fn Curl_free_primary_ssl_config(sslc: *mut ssl_primary_config);
    fn Curl_ssl_backend() -> libc::c_int;
    fn Curl_ssl_close_all(data: *mut Curl_easy);
    fn Curl_ssl_close(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        sockindex: libc::c_int,
    );
    fn Curl_ssl_free_certinfo(data: *mut Curl_easy);
    fn Curl_setup_transfer(
        data: *mut Curl_easy,
        sockindex: libc::c_int,
        size: curl_off_t,
        getheader: bool,
        writesockindex: libc::c_int,
    );
    fn Curl_infof(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
    fn Curl_failf(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
    fn Curl_recv_plain(
        data: *mut Curl_easy,
        num: libc::c_int,
        buf: *mut libc::c_char,
        len: size_t,
        code: *mut CURLcode,
    ) -> ssize_t;
    fn Curl_send_plain(
        data: *mut Curl_easy,
        num: libc::c_int,
        mem: *const libc::c_void,
        len: size_t,
        code: *mut CURLcode,
    ) -> ssize_t;
    fn Curl_pgrsSetDownloadCounter(data: *mut Curl_easy, size: curl_off_t);
    fn Curl_pgrsSetUploadCounter(data: *mut Curl_easy, size: curl_off_t);
    fn Curl_pgrsTime(data: *mut Curl_easy, timer: timerid) -> curltime;
    fn Curl_strcasecompare(
        first: *const libc::c_char,
        second: *const libc::c_char,
    ) -> libc::c_int;
    fn Curl_safe_strcasecompare(
        first: *const libc::c_char,
        second: *const libc::c_char,
    ) -> libc::c_int;
    fn Curl_strncasecompare(
        first: *const libc::c_char,
        second: *const libc::c_char,
        max: size_t,
    ) -> libc::c_int;
    fn Curl_strntoupper(dest: *mut libc::c_char, src: *const libc::c_char, n: size_t);
    fn Curl_strerror(
        err: libc::c_int,
        buf: *mut libc::c_char,
        buflen: size_t,
    ) -> *const libc::c_char;
    fn Curl_urldecode(
        data: *mut Curl_easy,
        string: *const libc::c_char,
        length: size_t,
        ostring: *mut *mut libc::c_char,
        olen: *mut size_t,
        ctrl: urlreject,
    ) -> CURLcode;
    fn Curl_share_lock(
        _: *mut Curl_easy,
        _: curl_lock_data,
        _: curl_lock_access,
    ) -> CURLSHcode;
    fn Curl_share_unlock(_: *mut Curl_easy, _: curl_lock_data) -> CURLSHcode;
    fn Curl_http_auth_cleanup_digest(data: *mut Curl_easy);
    fn Curl_socket_check(
        readfd: curl_socket_t,
        readfd2: curl_socket_t,
        writefd: curl_socket_t,
        timeout_ms: timediff_t,
    ) -> libc::c_int;
    fn Curl_expire_clear(data: *mut Curl_easy);
    fn Curl_attach_connnection(data: *mut Curl_easy, conn: *mut connectdata);
    fn Curl_detach_connnection(data: *mut Curl_easy);
    fn Curl_multiplex_wanted(multi: *const Curl_multi) -> bool;
    fn Curl_preconnect(data: *mut Curl_easy) -> CURLcode;
    fn Curl_multi_max_host_connections(multi: *mut Curl_multi) -> size_t;
    fn Curl_multi_max_total_connections(multi: *mut Curl_multi) -> size_t;
    fn Curl_multi_max_concurrent_streams(multi: *mut Curl_multi) -> libc::c_uint;
    fn Curl_speedinit(data: *mut Curl_easy);
    fn curlx_ultous(ulnum: libc::c_ulong) -> libc::c_ushort;
    fn Curl_initinfo(data: *mut Curl_easy) -> CURLcode;
    fn Curl_is_absolute_url(
        url: *const libc::c_char,
        scheme: *mut libc::c_char,
        buflen: size_t,
    ) -> bool;
    fn Curl_hsts_cleanup(hp: *mut *mut hsts);
    fn Curl_hsts(
        h: *mut hsts,
        hostname: *const libc::c_char,
        subdomain: bool,
    ) -> *mut stsentry;
    fn Curl_hsts_save(
        data: *mut Curl_easy,
        h: *mut hsts,
        file: *const libc::c_char,
    ) -> CURLcode;
    static Curl_handler_dict: Curl_handler;
    static Curl_handler_telnet: Curl_handler;
    static Curl_handler_tftp: Curl_handler;
    fn Curl_http2_init_userset(set: *mut UserDefined);
    fn Curl_http2_cleanup_dependencies(data: *mut Curl_easy);
    static Curl_handler_ldap: Curl_handler;
    static Curl_handler_ldaps: Curl_handler;
    fn Curl_connecthost(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        host: *const Curl_dns_entry,
    ) -> CURLcode;
    fn Curl_conninfo_local(
        data: *mut Curl_easy,
        sockfd: curl_socket_t,
        local_ip: *mut libc::c_char,
        local_port: *mut libc::c_int,
    );
    fn Curl_persistconninfo(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        local_ip: *mut libc::c_char,
        local_port: libc::c_int,
    );
    fn Curl_closesocket(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        sock: curl_socket_t,
    ) -> libc::c_int;
    fn Curl_conncontrol(conn: *mut connectdata, closeit: libc::c_int);
    fn Curl_timeleft(
        data: *mut Curl_easy,
        nowp: *mut curltime,
        duringconnect: bool,
    ) -> timediff_t;
    fn Curl_updateconninfo(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        sockfd: curl_socket_t,
    );
    fn Curl_http_auth_cleanup_ntlm(conn: *mut connectdata);
    static Curl_handler_gopher: Curl_handler;
    static Curl_handler_gophers: Curl_handler;
    fn Curl_setstropt(charp: *mut *mut libc::c_char, s: *const libc::c_char) -> CURLcode;
    fn Curl_alpnid2str(id: alpnid) -> *const libc::c_char;
    fn Curl_altsvc_save(
        data: *mut Curl_easy,
        asi: *mut altsvcinfo,
        file: *const libc::c_char,
    ) -> CURLcode;
    fn Curl_altsvc_cleanup(altsvc: *mut *mut altsvcinfo);
    fn Curl_altsvc_lookup(
        asi: *mut altsvcinfo,
        srcalpnid: alpnid,
        srchost: *const libc::c_char,
        srcport: libc::c_int,
        dstentry: *mut *mut altsvc,
        versions: libc::c_int,
    ) -> bool;
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
pub type resolve_t = libc::c_int;
pub const CURLRESOLV_PENDING: resolve_t = 1;
pub const CURLRESOLV_RESOLVED: resolve_t = 0;
pub const CURLRESOLV_ERROR: resolve_t = -1;
pub const CURLRESOLV_TIMEDOUT: resolve_t = -2;
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
pub type urlreject = libc::c_uint;
pub const REJECT_ZERO: urlreject = 4;
pub const REJECT_CTRL: urlreject = 3;
pub const REJECT_NADA: urlreject = 2;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stsentry {
    pub node: Curl_llist_element,
    pub host: *const libc::c_char,
    pub includeSubDomains: bool,
    pub expires: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct prunedead {
    pub data: *mut Curl_easy,
    pub extracted: *mut connectdata,
}
pub const ALPN_h3: alpnid = 32;
pub const ALPN_h2: alpnid = 16;
pub const ALPN_h1: alpnid = 8;
pub type alpnid = libc::c_uint;
pub const ALPN_none: alpnid = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct althost {
    pub host: *mut libc::c_char,
    pub port: libc::c_ushort,
    pub alpnid: alpnid,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct altsvc {
    pub src: althost,
    pub dst: althost,
    pub expires: time_t,
    pub persist: bool,
    pub prio: libc::c_int,
    pub node: Curl_llist_element,
}
#[inline]
unsafe extern "C" fn tolower(mut __c: libc::c_int) -> libc::c_int {
    return if __c >= -(128 as libc::c_int) && __c < 256 as libc::c_int {
        *(*__ctype_tolower_loc()).offset(__c as isize)
    } else {
        __c
    };
}
unsafe extern "C" fn get_protocol_family(mut h: *const Curl_handler) -> libc::c_uint {
    return (*h).family;
}
static mut protocols: [*const Curl_handler; 23] = unsafe {
    [
        &Curl_handler_https as *const Curl_handler,
        &Curl_handler_http as *const Curl_handler,
        &Curl_handler_ftp as *const Curl_handler,
        &Curl_handler_ftps as *const Curl_handler,
        &Curl_handler_file as *const Curl_handler,
        &Curl_handler_smtp as *const Curl_handler,
        &Curl_handler_smtps as *const Curl_handler,
        &Curl_handler_ldap as *const Curl_handler,
        &Curl_handler_ldaps as *const Curl_handler,
        &Curl_handler_imap as *const Curl_handler,
        &Curl_handler_imaps as *const Curl_handler,
        &Curl_handler_telnet as *const Curl_handler,
        &Curl_handler_tftp as *const Curl_handler,
        &Curl_handler_pop3 as *const Curl_handler,
        &Curl_handler_pop3s as *const Curl_handler,
        &Curl_handler_smb as *const Curl_handler,
        &Curl_handler_smbs as *const Curl_handler,
        &Curl_handler_rtsp as *const Curl_handler,
        &Curl_handler_mqtt as *const Curl_handler,
        &Curl_handler_gopher as *const Curl_handler,
        &Curl_handler_gophers as *const Curl_handler,
        &Curl_handler_dict as *const Curl_handler,
        0 as *const libc::c_void as *mut libc::c_void as *mut Curl_handler
            as *const Curl_handler,
    ]
};
static mut Curl_handler_dummy: Curl_handler = {
    let mut init = Curl_handler {
        scheme: b"<no protocol>\0" as *const u8 as *const libc::c_char,
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
        defport: 0 as libc::c_int,
        protocol: 0 as libc::c_int as libc::c_uint,
        family: 0 as libc::c_int as libc::c_uint,
        flags: 0 as libc::c_int as libc::c_uint,
    };
    init
};
#[no_mangle]
pub unsafe extern "C" fn Curl_freeset(mut data: *mut Curl_easy) {
    let mut i: dupstring = STRING_CERT;
    let mut j: dupblob = BLOB_CERT;
    i = STRING_CERT;
    while (i as libc::c_uint) < STRING_LAST as libc::c_int as libc::c_uint {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).set.str_0[i as usize] as *mut libc::c_void);
        let ref mut fresh0 = (*data).set.str_0[i as usize];
        *fresh0 = 0 as *mut libc::c_char;
        i += 1;
    }
    j = BLOB_CERT;
    while (j as libc::c_uint) < BLOB_LAST as libc::c_int as libc::c_uint {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).set.blobs[j as usize] as *mut libc::c_void);
        let ref mut fresh1 = (*data).set.blobs[j as usize];
        *fresh1 = 0 as *mut curl_blob;
        j += 1;
    }
    if ((*data).state).referer_alloc() != 0 {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.referer as *mut libc::c_void);
        let ref mut fresh2 = (*data).state.referer;
        *fresh2 = 0 as *mut libc::c_char;
        let ref mut fresh3 = (*data).state;
        (*fresh3).set_referer_alloc(0 as libc::c_int as bit);
    }
    let ref mut fresh4 = (*data).state.referer;
    *fresh4 = 0 as *mut libc::c_char;
    if ((*data).state).url_alloc() != 0 {
        Curl_cfree
            .expect("non-null function pointer")((*data).state.url as *mut libc::c_void);
        let ref mut fresh5 = (*data).state.url;
        *fresh5 = 0 as *mut libc::c_char;
        let ref mut fresh6 = (*data).state;
        (*fresh6).set_url_alloc(0 as libc::c_int as bit);
    }
    let ref mut fresh7 = (*data).state.url;
    *fresh7 = 0 as *mut libc::c_char;
    Curl_mime_cleanpart(&mut (*data).set.mimepost);
}
unsafe extern "C" fn up_free(mut data: *mut Curl_easy) {
    let mut up: *mut urlpieces = &mut (*data).state.up;
    Curl_cfree.expect("non-null function pointer")((*up).scheme as *mut libc::c_void);
    let ref mut fresh8 = (*up).scheme;
    *fresh8 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*up).hostname as *mut libc::c_void);
    let ref mut fresh9 = (*up).hostname;
    *fresh9 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*up).port as *mut libc::c_void);
    let ref mut fresh10 = (*up).port;
    *fresh10 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*up).user as *mut libc::c_void);
    let ref mut fresh11 = (*up).user;
    *fresh11 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*up).password as *mut libc::c_void);
    let ref mut fresh12 = (*up).password;
    *fresh12 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*up).options as *mut libc::c_void);
    let ref mut fresh13 = (*up).options;
    *fresh13 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*up).path as *mut libc::c_void);
    let ref mut fresh14 = (*up).path;
    *fresh14 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*up).query as *mut libc::c_void);
    let ref mut fresh15 = (*up).query;
    *fresh15 = 0 as *mut libc::c_char;
    curl_url_cleanup((*data).state.uh);
    let ref mut fresh16 = (*data).state.uh;
    *fresh16 = 0 as *mut CURLU;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_close(mut datap: *mut *mut Curl_easy) -> CURLcode {
    let mut m: *mut Curl_multi = 0 as *mut Curl_multi;
    let mut data: *mut Curl_easy = 0 as *mut Curl_easy;
    if datap.is_null() || (*datap).is_null() {
        return CURLE_OK;
    }
    data = *datap;
    *datap = 0 as *mut Curl_easy;
    Curl_expire_clear(data);
    Curl_detach_connnection(data);
    m = (*data).multi;
    if !m.is_null() {
        curl_multi_remove_handle((*data).multi, data);
    }
    if !((*data).multi_easy).is_null() {
        curl_multi_cleanup((*data).multi_easy);
        let ref mut fresh17 = (*data).multi_easy;
        *fresh17 = 0 as *mut Curl_multi;
    }
    Curl_llist_destroy(&mut (*data).state.timeoutlist, 0 as *mut libc::c_void);
    (*data).magic = 0 as libc::c_int as libc::c_uint;
    if ((*data).state).rangestringalloc() != 0 {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.range as *mut libc::c_void);
    }
    Curl_free_request_state(data);
    Curl_ssl_close_all(data);
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.first_host as *mut libc::c_void);
    let ref mut fresh18 = (*data).state.first_host;
    *fresh18 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect("non-null function pointer")((*data).state.scratch as *mut libc::c_void);
    let ref mut fresh19 = (*data).state.scratch;
    *fresh19 = 0 as *mut libc::c_char;
    Curl_ssl_free_certinfo(data);
    Curl_cfree
        .expect("non-null function pointer")((*data).req.newurl as *mut libc::c_void);
    let ref mut fresh20 = (*data).req.newurl;
    *fresh20 = 0 as *mut libc::c_char;
    if ((*data).state).referer_alloc() != 0 {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*data).state.referer as *mut libc::c_void);
        let ref mut fresh21 = (*data).state.referer;
        *fresh21 = 0 as *mut libc::c_char;
        let ref mut fresh22 = (*data).state;
        (*fresh22).set_referer_alloc(0 as libc::c_int as bit);
    }
    let ref mut fresh23 = (*data).state.referer;
    *fresh23 = 0 as *mut libc::c_char;
    up_free(data);
    Curl_cfree
        .expect("non-null function pointer")((*data).state.buffer as *mut libc::c_void);
    let ref mut fresh24 = (*data).state.buffer;
    *fresh24 = 0 as *mut libc::c_char;
    Curl_dyn_free(&mut (*data).state.headerb);
    Curl_cfree
        .expect("non-null function pointer")((*data).state.ulbuf as *mut libc::c_void);
    let ref mut fresh25 = (*data).state.ulbuf;
    *fresh25 = 0 as *mut libc::c_char;
    Curl_flush_cookies(data, 1 as libc::c_int != 0);
    Curl_altsvc_save(
        data,
        (*data).asi,
        (*data).set.str_0[STRING_ALTSVC as libc::c_int as usize],
    );
    Curl_altsvc_cleanup(&mut (*data).asi);
    Curl_hsts_save(
        data,
        (*data).hsts,
        (*data).set.str_0[STRING_HSTS as libc::c_int as usize],
    );
    Curl_hsts_cleanup(&mut (*data).hsts);
    Curl_http_auth_cleanup_digest(data);
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).info.contenttype as *mut libc::c_void);
    let ref mut fresh26 = (*data).info.contenttype;
    *fresh26 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).info.wouldredirect as *mut libc::c_void);
    let ref mut fresh27 = (*data).info.wouldredirect;
    *fresh27 = 0 as *mut libc::c_char;
    Curl_resolver_cleanup((*data).state.async_0.resolver);
    Curl_http2_cleanup_dependencies(data);
    if !((*data).share).is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE);
        let ref mut fresh28 = (*(*data).share).dirty;
        ::std::ptr::write_volatile(
            fresh28,
            (::std::ptr::read_volatile::<libc::c_uint>(fresh28 as *const libc::c_uint))
                .wrapping_sub(1),
        );
        Curl_share_unlock(data, CURL_LOCK_DATA_SHARE);
    }
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.proxyuserpwd as *mut libc::c_void);
    let ref mut fresh29 = (*data).state.aptr.proxyuserpwd;
    *fresh29 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.uagent as *mut libc::c_void);
    let ref mut fresh30 = (*data).state.aptr.uagent;
    *fresh30 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.userpwd as *mut libc::c_void);
    let ref mut fresh31 = (*data).state.aptr.userpwd;
    *fresh31 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.accept_encoding as *mut libc::c_void);
    let ref mut fresh32 = (*data).state.aptr.accept_encoding;
    *fresh32 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect("non-null function pointer")((*data).state.aptr.te as *mut libc::c_void);
    let ref mut fresh33 = (*data).state.aptr.te;
    *fresh33 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.rangeline as *mut libc::c_void);
    let ref mut fresh34 = (*data).state.aptr.rangeline;
    *fresh34 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.ref_0 as *mut libc::c_void);
    let ref mut fresh35 = (*data).state.aptr.ref_0;
    *fresh35 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.host as *mut libc::c_void);
    let ref mut fresh36 = (*data).state.aptr.host;
    *fresh36 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.cookiehost as *mut libc::c_void);
    let ref mut fresh37 = (*data).state.aptr.cookiehost;
    *fresh37 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.rtsp_transport as *mut libc::c_void);
    let ref mut fresh38 = (*data).state.aptr.rtsp_transport;
    *fresh38 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.user as *mut libc::c_void);
    let ref mut fresh39 = (*data).state.aptr.user;
    *fresh39 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.passwd as *mut libc::c_void);
    let ref mut fresh40 = (*data).state.aptr.passwd;
    *fresh40 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.proxyuser as *mut libc::c_void);
    let ref mut fresh41 = (*data).state.aptr.proxyuser;
    *fresh41 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*data).state.aptr.proxypasswd as *mut libc::c_void);
    let ref mut fresh42 = (*data).state.aptr.proxypasswd;
    *fresh42 = 0 as *mut libc::c_char;
    if !((*data).req.doh).is_null() {
        Curl_dyn_free(
            &mut (*((*(*data).req.doh).probe)
                .as_mut_ptr()
                .offset(0 as libc::c_int as isize))
                .serverdoh,
        );
        Curl_dyn_free(
            &mut (*((*(*data).req.doh).probe)
                .as_mut_ptr()
                .offset(1 as libc::c_int as isize))
                .serverdoh,
        );
        curl_slist_free_all((*(*data).req.doh).headers);
        Curl_cfree
            .expect("non-null function pointer")((*data).req.doh as *mut libc::c_void);
        let ref mut fresh43 = (*data).req.doh;
        *fresh43 = 0 as *mut dohdata;
    }
    Curl_wildcard_dtor(&mut (*data).wildcard);
    Curl_freeset(data);
    Curl_cfree.expect("non-null function pointer")(data as *mut libc::c_void);
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_init_userdefined(mut data: *mut Curl_easy) -> CURLcode {
    let mut set: *mut UserDefined = &mut (*data).set;
    let mut result: CURLcode = CURLE_OK;
    let ref mut fresh44 = (*set).out;
    *fresh44 = stdout as *mut libc::c_void;
    let ref mut fresh45 = (*set).in_set;
    *fresh45 = stdin as *mut libc::c_void;
    let ref mut fresh46 = (*set).err;
    *fresh46 = stderr;
    let ref mut fresh47 = (*set).fwrite_func;
    *fresh47 = ::std::mem::transmute::<
        Option::<
            unsafe extern "C" fn(
                *const libc::c_void,
                libc::c_ulong,
                libc::c_ulong,
                *mut FILE,
            ) -> libc::c_ulong,
        >,
        curl_write_callback,
    >(
        Some(
            fwrite
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    libc::c_ulong,
                    libc::c_ulong,
                    *mut FILE,
                ) -> libc::c_ulong,
        ),
    );
    let ref mut fresh48 = (*set).fread_func_set;
    *fresh48 = ::std::mem::transmute::<
        Option::<
            unsafe extern "C" fn(
                *mut libc::c_void,
                libc::c_ulong,
                libc::c_ulong,
                *mut FILE,
            ) -> libc::c_ulong,
        >,
        curl_read_callback,
    >(
        Some(
            fread
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    libc::c_ulong,
                    libc::c_ulong,
                    *mut FILE,
                ) -> libc::c_ulong,
        ),
    );
    (*set).set_is_fread_set(0 as libc::c_int as bit);
    (*set).set_is_fwrite_set(0 as libc::c_int as bit);
    let ref mut fresh49 = (*set).seek_func;
    *fresh49 = None;
    let ref mut fresh50 = (*set).seek_client;
    *fresh50 = 0 as *mut libc::c_void;
    let ref mut fresh51 = (*set).convfromnetwork;
    *fresh51 = None;
    let ref mut fresh52 = (*set).convtonetwork;
    *fresh52 = None;
    let ref mut fresh53 = (*set).convfromutf8;
    *fresh53 = None;
    (*set).filesize = -(1 as libc::c_int) as curl_off_t;
    (*set).postfieldsize = -(1 as libc::c_int) as curl_off_t;
    (*set).maxredirs = -(1 as libc::c_int) as libc::c_long;
    (*set).method = HTTPREQ_GET;
    (*set).rtspreq = RTSPREQ_OPTIONS;
    (*set).set_ftp_use_epsv(1 as libc::c_int as bit);
    (*set).set_ftp_use_eprt(1 as libc::c_int as bit);
    (*set).set_ftp_use_pret(0 as libc::c_int as bit);
    (*set).ftp_filemethod = FTPFILE_MULTICWD;
    (*set).set_ftp_skip_ip(1 as libc::c_int as bit);
    (*set).dns_cache_timeout = 60 as libc::c_int as libc::c_long;
    (*set).general_ssl.max_ssl_sessions = 5 as libc::c_int as size_t;
    (*set).proxyport = 0 as libc::c_int as libc::c_long;
    (*set).proxytype = CURLPROXY_HTTP;
    (*set).httpauth = (1 as libc::c_int as libc::c_ulong) << 0 as libc::c_int;
    (*set).proxyauth = (1 as libc::c_int as libc::c_ulong) << 0 as libc::c_int;
    (*set)
        .socks5auth = (1 as libc::c_int as libc::c_ulong) << 0 as libc::c_int
        | (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int;
    (*set).set_hide_progress(1 as libc::c_int as bit);
    Curl_mime_initpart(&mut (*set).mimepost, data);
    (*set).set_doh_verifyhost(1 as libc::c_int as bit);
    (*set).set_doh_verifypeer(1 as libc::c_int as bit);
    let ref mut fresh54 = (*set).ssl.primary;
    (*fresh54).set_verifypeer(1 as libc::c_int as bit);
    let ref mut fresh55 = (*set).ssl.primary;
    (*fresh55).set_verifyhost(1 as libc::c_int as bit);
    (*set).ssl.authtype = CURL_TLSAUTH_NONE;
    (*set).ssh_auth_types = !(0 as libc::c_int) as libc::c_long;
    let ref mut fresh56 = (*set).ssl.primary;
    (*fresh56).set_sessionid(1 as libc::c_int as bit);
    (*set).proxy_ssl = (*set).ssl;
    (*set).new_file_perms = 0o644 as libc::c_int as libc::c_long;
    (*set).new_directory_perms = 0o755 as libc::c_int as libc::c_long;
    (*set).allowed_protocols = !(0 as libc::c_int) as libc::c_long;
    (*set)
        .redir_protocols = ((1 as libc::c_int) << 0 as libc::c_int
        | (1 as libc::c_int) << 1 as libc::c_int | (1 as libc::c_int) << 2 as libc::c_int
        | (1 as libc::c_int) << 3 as libc::c_int) as libc::c_long;
    if Curl_ssl_backend() != CURLSSLBACKEND_SCHANNEL as libc::c_int {
        result = Curl_setstropt(
            &mut *((*set).str_0)
                .as_mut_ptr()
                .offset(STRING_SSL_CAFILE as libc::c_int as isize),
            b"/etc/ssl/certs/ca-certificates.crt\0" as *const u8 as *const libc::c_char,
        );
        if result as u64 != 0 {
            return result;
        }
        result = Curl_setstropt(
            &mut *((*set).str_0)
                .as_mut_ptr()
                .offset(STRING_SSL_CAFILE_PROXY as libc::c_int as isize),
            b"/etc/ssl/certs/ca-certificates.crt\0" as *const u8 as *const libc::c_char,
        );
        if result as u64 != 0 {
            return result;
        }
    }
    (*set).set_wildcard_enabled(0 as libc::c_int as bit);
    let ref mut fresh57 = (*set).chunk_bgn;
    *fresh57 = None;
    let ref mut fresh58 = (*set).chunk_end;
    *fresh58 = None;
    (*set).set_tcp_keepalive(0 as libc::c_int as bit);
    (*set).tcp_keepintvl = 60 as libc::c_int as libc::c_long;
    (*set).tcp_keepidle = 60 as libc::c_int as libc::c_long;
    (*set).set_tcp_fastopen(0 as libc::c_int as bit);
    (*set).set_tcp_nodelay(1 as libc::c_int as bit);
    (*set).set_ssl_enable_npn(1 as libc::c_int as bit);
    (*set).set_ssl_enable_alpn(1 as libc::c_int as bit);
    (*set).expect_100_timeout = 1000 as libc::c_long;
    (*set).set_sep_headers(1 as libc::c_int as bit);
    (*set).buffer_size = 16384 as libc::c_int as libc::c_long;
    (*set).upload_buffer_size = 65536 as libc::c_int as libc::c_uint;
    (*set).happy_eyeballs_timeout = 200 as libc::c_long;
    let ref mut fresh59 = (*set).fnmatch;
    *fresh59 = None;
    (*set).upkeep_interval_ms = 60000 as libc::c_long;
    (*set).maxconnects = 5 as libc::c_int as size_t;
    (*set).maxage_conn = 118 as libc::c_int as libc::c_long;
    (*set).set_http09_allowed(0 as libc::c_int as bit);
    (*set).httpwant = CURL_HTTP_VERSION_2TLS as libc::c_int as libc::c_uchar;
    Curl_http2_init_userset(set);
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_open(mut curl: *mut *mut Curl_easy) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut data: *mut Curl_easy = 0 as *mut Curl_easy;
    data = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(
        1 as libc::c_int as size_t,
        ::std::mem::size_of::<Curl_easy>() as libc::c_ulong,
    ) as *mut Curl_easy;
    if data.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    (*data).magic = 0xc0dedbad as libc::c_uint;
    result = Curl_resolver_init(data, &mut (*data).state.async_0.resolver);
    if result as u64 != 0 {
        Curl_cfree.expect("non-null function pointer")(data as *mut libc::c_void);
        return result;
    }
    result = Curl_init_userdefined(data);
    if result as u64 == 0 {
        Curl_dyn_init(
            &mut (*data).state.headerb,
            (100 as libc::c_int * 1024 as libc::c_int) as size_t,
        );
        Curl_initinfo(data);
        (*data).state.lastconnect_id = -(1 as libc::c_int) as libc::c_long;
        (*data).progress.flags |= (1 as libc::c_int) << 4 as libc::c_int;
        (*data).state.current_speed = -(1 as libc::c_int) as curl_off_t;
    }
    if result as u64 != 0 {
        Curl_resolver_cleanup((*data).state.async_0.resolver);
        Curl_dyn_free(&mut (*data).state.headerb);
        Curl_freeset(data);
        Curl_cfree.expect("non-null function pointer")(data as *mut libc::c_void);
        data = 0 as *mut Curl_easy;
    } else {
        *curl = data;
    }
    return result;
}
unsafe extern "C" fn conn_shutdown(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) {
    Curl_infof(
        data,
        b"Closing connection %ld\0" as *const u8 as *const libc::c_char,
        (*conn).connection_id,
    );
    if !((*conn).connect_state).is_null()
        && !((*(*conn).connect_state).prot_save).is_null()
    {
        let ref mut fresh60 = (*data).req.p.http;
        *fresh60 = 0 as *mut HTTP;
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*(*conn).connect_state).prot_save as *mut libc::c_void);
        let ref mut fresh61 = (*(*conn).connect_state).prot_save;
        *fresh61 = 0 as *mut HTTP;
    }
    Curl_resolver_cancel(data);
    Curl_ssl_close(data, conn, 0 as libc::c_int);
    Curl_ssl_close(data, conn, 1 as libc::c_int);
    if -(1 as libc::c_int) != (*conn).sock[1 as libc::c_int as usize] {
        Curl_closesocket(data, conn, (*conn).sock[1 as libc::c_int as usize]);
    }
    if -(1 as libc::c_int) != (*conn).sock[0 as libc::c_int as usize] {
        Curl_closesocket(data, conn, (*conn).sock[0 as libc::c_int as usize]);
    }
    if -(1 as libc::c_int) != (*conn).tempsock[0 as libc::c_int as usize] {
        Curl_closesocket(data, conn, (*conn).tempsock[0 as libc::c_int as usize]);
    }
    if -(1 as libc::c_int) != (*conn).tempsock[1 as libc::c_int as usize] {
        Curl_closesocket(data, conn, (*conn).tempsock[1 as libc::c_int as usize]);
    }
}
unsafe extern "C" fn conn_free(mut conn: *mut connectdata) {
    Curl_free_idnconverted_hostname(&mut (*conn).host);
    Curl_free_idnconverted_hostname(&mut (*conn).conn_to_host);
    Curl_free_idnconverted_hostname(&mut (*conn).http_proxy.host);
    Curl_free_idnconverted_hostname(&mut (*conn).socks_proxy.host);
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).http_proxy.user as *mut libc::c_void);
    let ref mut fresh62 = (*conn).http_proxy.user;
    *fresh62 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).socks_proxy.user as *mut libc::c_void);
    let ref mut fresh63 = (*conn).socks_proxy.user;
    *fresh63 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).http_proxy.passwd as *mut libc::c_void);
    let ref mut fresh64 = (*conn).http_proxy.passwd;
    *fresh64 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).socks_proxy.passwd as *mut libc::c_void);
    let ref mut fresh65 = (*conn).socks_proxy.passwd;
    *fresh65 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).http_proxy.host.rawalloc as *mut libc::c_void);
    let ref mut fresh66 = (*conn).http_proxy.host.rawalloc;
    *fresh66 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).socks_proxy.host.rawalloc as *mut libc::c_void);
    let ref mut fresh67 = (*conn).socks_proxy.host.rawalloc;
    *fresh67 = 0 as *mut libc::c_char;
    Curl_free_primary_ssl_config(&mut (*conn).proxy_ssl_config);
    Curl_cfree.expect("non-null function pointer")((*conn).user as *mut libc::c_void);
    let ref mut fresh68 = (*conn).user;
    *fresh68 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*conn).passwd as *mut libc::c_void);
    let ref mut fresh69 = (*conn).passwd;
    *fresh69 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect("non-null function pointer")((*conn).sasl_authzid as *mut libc::c_void);
    let ref mut fresh70 = (*conn).sasl_authzid;
    *fresh70 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*conn).options as *mut libc::c_void);
    let ref mut fresh71 = (*conn).options;
    *fresh71 = 0 as *mut libc::c_char;
    Curl_dyn_free(&mut (*conn).trailer);
    Curl_cfree
        .expect("non-null function pointer")((*conn).host.rawalloc as *mut libc::c_void);
    let ref mut fresh72 = (*conn).host.rawalloc;
    *fresh72 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).conn_to_host.rawalloc as *mut libc::c_void);
    let ref mut fresh73 = (*conn).conn_to_host.rawalloc;
    *fresh73 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).hostname_resolve as *mut libc::c_void);
    let ref mut fresh74 = (*conn).hostname_resolve;
    *fresh74 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).secondaryhostname as *mut libc::c_void);
    let ref mut fresh75 = (*conn).secondaryhostname;
    *fresh75 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect("non-null function pointer")((*conn).connect_state as *mut libc::c_void);
    let ref mut fresh76 = (*conn).connect_state;
    *fresh76 = 0 as *mut http_connect_state;
    Curl_llist_destroy(&mut (*conn).easyq, 0 as *mut libc::c_void);
    Curl_cfree
        .expect("non-null function pointer")((*conn).localdev as *mut libc::c_void);
    let ref mut fresh77 = (*conn).localdev;
    *fresh77 = 0 as *mut libc::c_char;
    Curl_free_primary_ssl_config(&mut (*conn).ssl_config);
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).unix_domain_socket as *mut libc::c_void);
    let ref mut fresh78 = (*conn).unix_domain_socket;
    *fresh78 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")((*conn).ssl_extra);
    let ref mut fresh79 = (*conn).ssl_extra;
    *fresh79 = 0 as *mut libc::c_void;
    Curl_cfree.expect("non-null function pointer")(conn as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_disconnect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut dead_connection: bool,
) -> CURLcode {
    if (*conn).easyq.size != 0 && !dead_connection {
        return CURLE_OK;
    }
    if !((*conn).dns_entry).is_null() {
        Curl_resolv_unlock(data, (*conn).dns_entry);
        let ref mut fresh80 = (*conn).dns_entry;
        *fresh80 = 0 as *mut Curl_dns_entry;
    }
    Curl_http_auth_cleanup_ntlm(conn);
    if ((*conn).bits).connect_only() != 0 {
        dead_connection = 1 as libc::c_int != 0;
    }
    Curl_attach_connnection(data, conn);
    if ((*(*conn).handler).disconnect).is_some() {
        ((*(*conn).handler).disconnect)
            .expect("non-null function pointer")(data, conn, dead_connection);
    }
    conn_shutdown(data, conn);
    Curl_detach_connnection(data);
    conn_free(conn);
    return CURLE_OK;
}
unsafe extern "C" fn SocketIsDead(mut sock: curl_socket_t) -> bool {
    let mut sval: libc::c_int = 0;
    let mut ret_val: bool = 1 as libc::c_int != 0;
    sval = Curl_socket_check(
        sock,
        -(1 as libc::c_int),
        -(1 as libc::c_int),
        0 as libc::c_int as timediff_t,
    );
    if sval == 0 as libc::c_int {
        ret_val = 0 as libc::c_int != 0;
    }
    return ret_val;
}
unsafe extern "C" fn IsMultiplexingPossible(
    mut handle: *const Curl_easy,
    mut conn: *const connectdata,
) -> libc::c_int {
    let mut avail: libc::c_int = 0 as libc::c_int;
    if (*(*conn).handler).protocol
        & ((1 as libc::c_int) << 0 as libc::c_int
            | (1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint != 0
        && (((*conn).bits).protoconnstart() == 0 || ((*conn).bits).close() == 0)
    {
        if Curl_multiplex_wanted((*handle).multi) as libc::c_int != 0
            && (*handle).state.httpwant as libc::c_int
                >= CURL_HTTP_VERSION_2_0 as libc::c_int
        {
            avail = (avail as libc::c_long | 2 as libc::c_long) as libc::c_int;
        }
    }
    return avail;
}
unsafe extern "C" fn proxy_info_matches(
    mut data: *const proxy_info,
    mut needle: *const proxy_info,
) -> bool {
    if (*data).proxytype as libc::c_uint == (*needle).proxytype as libc::c_uint
        && (*data).port == (*needle).port
        && Curl_safe_strcasecompare((*data).host.name, (*needle).host.name) != 0
    {
        return 1 as libc::c_int != 0;
    }
    return 0 as libc::c_int != 0;
}
unsafe extern "C" fn socks_proxy_info_matches(
    mut data: *const proxy_info,
    mut needle: *const proxy_info,
) -> bool {
    if !proxy_info_matches(data, needle) {
        return 0 as libc::c_int != 0;
    }
    if ((*data).user).is_null() as libc::c_int
        != ((*needle).user).is_null() as libc::c_int
    {
        return 0 as libc::c_int != 0;
    }
    if !((*data).user).is_null() && !((*needle).user).is_null()
        && strcmp((*data).user, (*needle).user) != 0 as libc::c_int
    {
        return 0 as libc::c_int != 0;
    }
    if ((*data).passwd).is_null() as libc::c_int
        != ((*needle).passwd).is_null() as libc::c_int
    {
        return 0 as libc::c_int != 0;
    }
    if !((*data).passwd).is_null() && !((*needle).passwd).is_null()
        && strcmp((*data).passwd, (*needle).passwd) != 0 as libc::c_int
    {
        return 0 as libc::c_int != 0;
    }
    return 1 as libc::c_int != 0;
}
unsafe extern "C" fn conn_maxage(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut now: curltime,
) -> bool {
    let mut idletime: timediff_t = Curl_timediff(now, (*conn).lastused);
    idletime /= 1000 as libc::c_int as libc::c_long;
    if idletime > (*data).set.maxage_conn {
        Curl_infof(
            data,
            b"Too old connection (%ld seconds), disconnect it\0" as *const u8
                as *const libc::c_char,
            idletime,
        );
        return 1 as libc::c_int != 0;
    }
    return 0 as libc::c_int != 0;
}
unsafe extern "C" fn extract_if_dead(
    mut conn: *mut connectdata,
    mut data: *mut Curl_easy,
) -> bool {
    if (*conn).easyq.size == 0 {
        let mut dead: bool = false;
        let mut now: curltime = Curl_now();
        if conn_maxage(data, conn, now) {
            dead = 1 as libc::c_int != 0;
        } else if ((*(*conn).handler).connection_check).is_some() {
            let mut state: libc::c_uint = 0;
            Curl_attach_connnection(data, conn);
            state = ((*(*conn).handler).connection_check)
                .expect(
                    "non-null function pointer",
                )(data, conn, ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint);
            dead = state & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0;
            Curl_detach_connnection(data);
        } else {
            dead = SocketIsDead((*conn).sock[0 as libc::c_int as usize]);
        }
        if dead {
            Curl_infof(
                data,
                b"Connection %ld seems to be dead!\0" as *const u8
                    as *const libc::c_char,
                (*conn).connection_id,
            );
            Curl_conncache_remove_conn(data, conn, 0 as libc::c_int != 0);
            return 1 as libc::c_int != 0;
        }
    }
    return 0 as libc::c_int != 0;
}
unsafe extern "C" fn call_extract_if_dead(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut param: *mut libc::c_void,
) -> libc::c_int {
    let mut p: *mut prunedead = param as *mut prunedead;
    if extract_if_dead(conn, data) {
        let ref mut fresh81 = (*p).extracted;
        *fresh81 = conn;
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn prune_dead_connections(mut data: *mut Curl_easy) {
    let mut now: curltime = Curl_now();
    let mut elapsed: timediff_t = 0;
    if !((*data).share).is_null() {
        Curl_share_lock(data, CURL_LOCK_DATA_CONNECT, CURL_LOCK_ACCESS_SINGLE);
    }
    elapsed = Curl_timediff(now, (*(*data).state.conn_cache).last_cleanup);
    if !((*data).share).is_null() {
        Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
    }
    if elapsed >= 1000 as libc::c_long {
        let mut prune: prunedead = prunedead {
            data: 0 as *mut Curl_easy,
            extracted: 0 as *mut connectdata,
        };
        prune.data = data;
        prune.extracted = 0 as *mut connectdata;
        while Curl_conncache_foreach(
            data,
            (*data).state.conn_cache,
            &mut prune as *mut prunedead as *mut libc::c_void,
            Some(
                call_extract_if_dead
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
        ) {
            Curl_conncache_remove_conn(data, prune.extracted, 1 as libc::c_int != 0);
            Curl_disconnect(data, prune.extracted, 1 as libc::c_int != 0);
        }
        if !((*data).share).is_null() {
            Curl_share_lock(data, CURL_LOCK_DATA_CONNECT, CURL_LOCK_ACCESS_SINGLE);
        }
        (*(*data).state.conn_cache).last_cleanup = now;
        if !((*data).share).is_null() {
            Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
        }
    }
}
unsafe extern "C" fn ConnectionExists(
    mut data: *mut Curl_easy,
    mut needle: *mut connectdata,
    mut usethis: *mut *mut connectdata,
    mut force_reuse: *mut bool,
    mut waitpipe: *mut bool,
) -> bool {
    let mut check: *mut connectdata = 0 as *mut connectdata;
    let mut chosen: *mut connectdata = 0 as *mut connectdata;
    let mut foundPendingCandidate: bool = 0 as libc::c_int != 0;
    let mut canmultiplex: bool = IsMultiplexingPossible(data, needle) != 0;
    let mut bundle: *mut connectbundle = 0 as *mut connectbundle;
    let mut hostbundle: *const libc::c_char = 0 as *const libc::c_char;
    let mut wantNTLMhttp: bool = (*data).state.authhost.want
        & ((1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int
            | (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int) != 0
        && (*(*needle).handler).protocol
            & ((1 as libc::c_int) << 0 as libc::c_int
                | (1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint != 0;
    let mut wantProxyNTLMhttp: bool = ((*needle).bits).proxy_user_passwd() as libc::c_int
        != 0
        && ((*data).state.authproxy.want
            & ((1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int
                | (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int) != 0
            && (*(*needle).handler).protocol
                & ((1 as libc::c_int) << 0 as libc::c_int
                    | (1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint != 0);
    *force_reuse = 0 as libc::c_int != 0;
    *waitpipe = 0 as libc::c_int != 0;
    bundle = Curl_conncache_find_bundle(
        data,
        needle,
        (*data).state.conn_cache,
        &mut hostbundle,
    );
    if !bundle.is_null() {
        let mut curr: *mut Curl_llist_element = 0 as *mut Curl_llist_element;
        Curl_infof(
            data,
            b"Found bundle for host %s: %p [%s]\0" as *const u8 as *const libc::c_char,
            hostbundle,
            bundle as *mut libc::c_void,
            if (*bundle).multiuse == 2 as libc::c_int {
                b"can multiplex\0" as *const u8 as *const libc::c_char
            } else {
                b"serially\0" as *const u8 as *const libc::c_char
            },
        );
        if canmultiplex {
            if (*bundle).multiuse == 0 as libc::c_int {
                if ((*data).set).pipewait() != 0 {
                    Curl_infof(
                        data,
                        b"Server doesn't support multiplex yet, wait\0" as *const u8
                            as *const libc::c_char,
                    );
                    *waitpipe = 1 as libc::c_int != 0;
                    if !((*data).share).is_null() {
                        Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
                    }
                    return 0 as libc::c_int != 0;
                }
                Curl_infof(
                    data,
                    b"Server doesn't support multiplex (yet)\0" as *const u8
                        as *const libc::c_char,
                );
                canmultiplex = 0 as libc::c_int != 0;
            }
            if (*bundle).multiuse == 2 as libc::c_int
                && !Curl_multiplex_wanted((*data).multi)
            {
                Curl_infof(
                    data,
                    b"Could multiplex, but not asked to!\0" as *const u8
                        as *const libc::c_char,
                );
                canmultiplex = 0 as libc::c_int != 0;
            }
            if (*bundle).multiuse == -(1 as libc::c_int) {
                Curl_infof(
                    data,
                    b"Can not multiplex, even if we wanted to!\0" as *const u8
                        as *const libc::c_char,
                );
                canmultiplex = 0 as libc::c_int != 0;
            }
        }
        curr = (*bundle).conn_list.head;
        while !curr.is_null() {
            let mut match_0: bool = 0 as libc::c_int != 0;
            let mut multiplexed: size_t = 0 as libc::c_int as size_t;
            check = (*curr).ptr as *mut connectdata;
            curr = (*curr).next;
            if !(((*check).bits).connect_only() as libc::c_int != 0
                || ((*check).bits).close() as libc::c_int != 0)
            {
                if extract_if_dead(check, data) {
                    Curl_disconnect(data, check, 1 as libc::c_int != 0);
                } else if !((*data).set.ipver as libc::c_int != 0 as libc::c_int
                        && (*data).set.ipver as libc::c_int
                            != (*check).ip_version as libc::c_int)
                    {
                    if (*bundle).multiuse == 2 as libc::c_int {
                        multiplexed = (*check).easyq.size;
                    }
                    if !canmultiplex {
                        if multiplexed != 0 {
                            continue;
                        } else if (*check).primary_ip[0 as libc::c_int as usize] == 0 {
                            Curl_infof(
                                data,
                                b"Connection #%ld is still name resolving, can't reuse\0"
                                    as *const u8 as *const libc::c_char,
                                (*check).connection_id,
                            );
                            continue;
                        } else if (*check).sock[0 as libc::c_int as usize]
                                == -(1 as libc::c_int)
                            {
                            foundPendingCandidate = 1 as libc::c_int != 0;
                            Curl_infof(
                                data,
                                b"Connection #%ld isn't open enough, can't reuse\0"
                                    as *const u8 as *const libc::c_char,
                                (*check).connection_id,
                            );
                            continue;
                        }
                    }
                    if !((*needle).unix_domain_socket).is_null() {
                        if ((*check).unix_domain_socket).is_null() {
                            continue;
                        }
                        if strcmp(
                            (*needle).unix_domain_socket,
                            (*check).unix_domain_socket,
                        ) != 0
                        {
                            continue;
                        }
                        if ((*needle).bits).abstract_unix_socket() as libc::c_int
                            != ((*check).bits).abstract_unix_socket() as libc::c_int
                        {
                            continue;
                        }
                    } else if !((*check).unix_domain_socket).is_null() {
                        continue;
                    }
                    if (*(*needle).handler).flags
                        & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint
                        != (*(*check).handler).flags
                            & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint
                    {
                        if get_protocol_family((*check).handler)
                            != (*(*needle).handler).protocol
                            || ((*check).bits).tls_upgraded() == 0
                        {
                            continue;
                        }
                    }
                    if ((*needle).bits).httpproxy() as libc::c_int
                        != ((*check).bits).httpproxy() as libc::c_int
                        || ((*needle).bits).socksproxy() as libc::c_int
                            != ((*check).bits).socksproxy() as libc::c_int
                    {
                        continue;
                    }
                    if ((*needle).bits).socksproxy() as libc::c_int != 0
                        && !socks_proxy_info_matches(
                            &mut (*needle).socks_proxy,
                            &mut (*check).socks_proxy,
                        )
                    {
                        continue;
                    }
                    if !(((*needle).bits).conn_to_host() as libc::c_int
                        != ((*check).bits).conn_to_host() as libc::c_int)
                    {
                        if !(((*needle).bits).conn_to_port() as libc::c_int
                            != ((*check).bits).conn_to_port() as libc::c_int)
                        {
                            if ((*needle).bits).httpproxy() != 0 {
                                if !proxy_info_matches(
                                    &mut (*needle).http_proxy,
                                    &mut (*check).http_proxy,
                                ) {
                                    continue;
                                }
                                if ((*needle).bits).tunnel_proxy() as libc::c_int
                                    != ((*check).bits).tunnel_proxy() as libc::c_int
                                {
                                    continue;
                                }
                                if (*needle).http_proxy.proxytype as libc::c_uint
                                    == CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                {
                                    if (*(*needle).handler).flags
                                        & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint
                                        != 0
                                    {
                                        if !Curl_ssl_config_matches(
                                            &mut (*needle).proxy_ssl_config,
                                            &mut (*check).proxy_ssl_config,
                                        ) {
                                            continue;
                                        }
                                        if (*check).proxy_ssl[0 as libc::c_int as usize].state
                                            as libc::c_uint
                                            != ssl_connection_complete as libc::c_int as libc::c_uint
                                        {
                                            continue;
                                        }
                                    } else {
                                        if !Curl_ssl_config_matches(
                                            &mut (*needle).ssl_config,
                                            &mut (*check).ssl_config,
                                        ) {
                                            continue;
                                        }
                                        if (*check).ssl[0 as libc::c_int as usize].state
                                            as libc::c_uint
                                            != ssl_connection_complete as libc::c_int as libc::c_uint
                                        {
                                            continue;
                                        }
                                    }
                                }
                            }
                            if !(!canmultiplex && (*check).easyq.size != 0) {
                                if (*check).easyq.size != 0 {
                                    let mut e: *mut Curl_llist_element = (*check).easyq.head;
                                    let mut entry: *mut Curl_easy = (*e).ptr as *mut Curl_easy;
                                    if (*entry).multi != (*data).multi {
                                        continue;
                                    }
                                }
                                if !((*needle).localdev).is_null()
                                    || (*needle).localport as libc::c_int != 0
                                {
                                    if (*check).localport as libc::c_int
                                        != (*needle).localport as libc::c_int
                                        || (*check).localportrange != (*needle).localportrange
                                        || !((*needle).localdev).is_null()
                                            && (((*check).localdev).is_null()
                                                || strcmp((*check).localdev, (*needle).localdev) != 0)
                                    {
                                        continue;
                                    }
                                }
                                if (*(*needle).handler).flags
                                    & ((1 as libc::c_int) << 7 as libc::c_int) as libc::c_uint
                                    == 0
                                {
                                    if strcmp((*needle).user, (*check).user) != 0
                                        || strcmp((*needle).passwd, (*check).passwd) != 0
                                    {
                                        continue;
                                    }
                                }
                                if (*(*needle).handler).protocol
                                    & ((1 as libc::c_int) << 0 as libc::c_int
                                        | (1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
                                    != 0
                                    && (*check).httpversion as libc::c_int >= 20 as libc::c_int
                                    && ((*data).state.httpwant as libc::c_int)
                                        < CURL_HTTP_VERSION_2_0 as libc::c_int
                                {
                                    continue;
                                }
                                if (*(*needle).handler).flags
                                    & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint
                                    != 0 || ((*needle).bits).httpproxy() == 0
                                    || ((*needle).bits).tunnel_proxy() as libc::c_int != 0
                                {
                                    if (Curl_strcasecompare(
                                        (*(*needle).handler).scheme,
                                        (*(*check).handler).scheme,
                                    ) != 0
                                        || get_protocol_family((*check).handler)
                                            == (*(*needle).handler).protocol
                                            && ((*check).bits).tls_upgraded() as libc::c_int != 0)
                                        && (((*needle).bits).conn_to_host() == 0
                                            || Curl_strcasecompare(
                                                (*needle).conn_to_host.name,
                                                (*check).conn_to_host.name,
                                            ) != 0)
                                        && (((*needle).bits).conn_to_port() == 0
                                            || (*needle).conn_to_port == (*check).conn_to_port)
                                        && Curl_strcasecompare(
                                            (*needle).host.name,
                                            (*check).host.name,
                                        ) != 0 && (*needle).remote_port == (*check).remote_port
                                    {
                                        if (*(*needle).handler).flags
                                            & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint
                                            != 0
                                        {
                                            if !Curl_ssl_config_matches(
                                                &mut (*needle).ssl_config,
                                                &mut (*check).ssl_config,
                                            ) {
                                                continue;
                                            }
                                            if (*check).ssl[0 as libc::c_int as usize].state
                                                as libc::c_uint
                                                != ssl_connection_complete as libc::c_int as libc::c_uint
                                            {
                                                foundPendingCandidate = 1 as libc::c_int != 0;
                                                continue;
                                            }
                                        }
                                        match_0 = 1 as libc::c_int != 0;
                                    }
                                } else {
                                    match_0 = 1 as libc::c_int != 0;
                                }
                                if !match_0 {
                                    continue;
                                }
                                if wantNTLMhttp {
                                    if strcmp((*needle).user, (*check).user) != 0
                                        || strcmp((*needle).passwd, (*check).passwd) != 0
                                    {
                                        if (*check).http_ntlm_state as libc::c_uint
                                            == NTLMSTATE_NONE as libc::c_int as libc::c_uint
                                        {
                                            chosen = check;
                                        }
                                        continue;
                                    }
                                } else if (*check).http_ntlm_state as libc::c_uint
                                        != NTLMSTATE_NONE as libc::c_int as libc::c_uint
                                    {
                                    continue;
                                }
                                if wantProxyNTLMhttp {
                                    if ((*check).http_proxy.user).is_null()
                                        || ((*check).http_proxy.passwd).is_null()
                                    {
                                        continue;
                                    }
                                    if strcmp(
                                        (*needle).http_proxy.user,
                                        (*check).http_proxy.user,
                                    ) != 0
                                        || strcmp(
                                            (*needle).http_proxy.passwd,
                                            (*check).http_proxy.passwd,
                                        ) != 0
                                    {
                                        continue;
                                    }
                                } else if (*check).proxy_ntlm_state as libc::c_uint
                                        != NTLMSTATE_NONE as libc::c_int as libc::c_uint
                                    {
                                    continue;
                                }
                                if wantNTLMhttp as libc::c_int != 0
                                    || wantProxyNTLMhttp as libc::c_int != 0
                                {
                                    chosen = check;
                                    if !(wantNTLMhttp as libc::c_int != 0
                                        && (*check).http_ntlm_state as libc::c_uint
                                            != NTLMSTATE_NONE as libc::c_int as libc::c_uint
                                        || wantProxyNTLMhttp as libc::c_int != 0
                                            && (*check).proxy_ntlm_state as libc::c_uint
                                                != NTLMSTATE_NONE as libc::c_int as libc::c_uint)
                                    {
                                        continue;
                                    }
                                    *force_reuse = 1 as libc::c_int != 0;
                                    break;
                                } else if canmultiplex {
                                    if multiplexed == 0 {
                                        chosen = check;
                                        break;
                                    } else {
                                        if ((*check).bits).multiplex() != 0 {
                                            let mut httpc: *mut http_conn = &mut (*check).proto.httpc;
                                            if multiplexed
                                                >= (*httpc).settings.max_concurrent_streams as libc::c_ulong
                                            {
                                                Curl_infof(
                                                    data,
                                                    b"MAX_CONCURRENT_STREAMS reached, skip (%zu)\0" as *const u8
                                                        as *const libc::c_char,
                                                    multiplexed,
                                                );
                                                continue;
                                            } else if multiplexed
                                                    >= Curl_multi_max_concurrent_streams((*data).multi)
                                                        as libc::c_ulong
                                                {
                                                Curl_infof(
                                                    data,
                                                    b"client side MAX_CONCURRENT_STREAMS reached, skip (%zu)\0"
                                                        as *const u8 as *const libc::c_char,
                                                    multiplexed,
                                                );
                                                continue;
                                            }
                                        }
                                        chosen = check;
                                        Curl_infof(
                                            data,
                                            b"Multiplexed connection found!\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                        break;
                                    }
                                } else {
                                    chosen = check;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if !chosen.is_null() {
        Curl_attach_connnection(data, chosen);
        if !((*data).share).is_null() {
            Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
        }
        *usethis = chosen;
        return 1 as libc::c_int != 0;
    }
    if !((*data).share).is_null() {
        Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
    }
    if foundPendingCandidate as libc::c_int != 0
        && ((*data).set).pipewait() as libc::c_int != 0
    {
        Curl_infof(
            data,
            b"Found pending candidate for reuse and CURLOPT_PIPEWAIT is set\0"
                as *const u8 as *const libc::c_char,
        );
        *waitpipe = 1 as libc::c_int != 0;
    }
    return 0 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_verboseconnect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) {
    if ((*data).set).verbose() != 0 {
        Curl_infof(
            data,
            b"Connected to %s (%s) port %u (#%ld)\0" as *const u8 as *const libc::c_char,
            if ((*conn).bits).socksproxy() as libc::c_int != 0 {
                (*conn).socks_proxy.host.dispname
            } else if ((*conn).bits).httpproxy() as libc::c_int != 0 {
                (*conn).http_proxy.host.dispname
            } else if ((*conn).bits).conn_to_host() as libc::c_int != 0 {
                (*conn).conn_to_host.dispname
            } else {
                (*conn).host.dispname
            },
            ((*conn).primary_ip).as_mut_ptr(),
            (*conn).port,
            (*conn).connection_id,
        );
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_is_ASCII_name(mut hostname: *const libc::c_char) -> bool {
    let mut ch: *const libc::c_uchar = hostname as *const libc::c_uchar;
    if hostname.is_null() {
        return 1 as libc::c_int != 0;
    }
    while *ch != 0 {
        let fresh82 = ch;
        ch = ch.offset(1);
        if *fresh82 as libc::c_int & 0x80 as libc::c_int != 0 {
            return 0 as libc::c_int != 0;
        }
    }
    return 1 as libc::c_int != 0;
}
unsafe extern "C" fn strip_trailing_dot(mut host: *mut hostname) {
    let mut len: size_t = 0;
    if host.is_null() || ((*host).name).is_null() {
        return;
    }
    len = strlen((*host).name);
    if len != 0
        && *((*host).name)
            .offset(len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
            as libc::c_int == '.' as i32
    {
        *((*host).name)
            .offset(
                len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
            ) = 0 as libc::c_int as libc::c_char;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_idnconvert_hostname(
    mut data: *mut Curl_easy,
    mut host: *mut hostname,
) -> CURLcode {
    let ref mut fresh83 = (*host).dispname;
    *fresh83 = (*host).name;
    if !Curl_is_ASCII_name((*host).name) {
        Curl_infof(
            data,
            b"IDN support not present, can't parse Unicode domains\0" as *const u8
                as *const libc::c_char,
        );
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_free_idnconverted_hostname(mut host: *mut hostname) {}
unsafe extern "C" fn allocate_conn(mut data: *mut Curl_easy) -> *mut connectdata {
    let mut conn: *mut connectdata = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(
        1 as libc::c_int as size_t,
        ::std::mem::size_of::<connectdata>() as libc::c_ulong,
    ) as *mut connectdata;
    if conn.is_null() {
        return 0 as *mut connectdata;
    }
    let mut sslsize: size_t = (*Curl_ssl).sizeof_ssl_backend_data;
    let mut ssl: *mut libc::c_char = Curl_ccalloc
        .expect("non-null function pointer")(4 as libc::c_int as size_t, sslsize)
        as *mut libc::c_char;
    if ssl.is_null() {
        Curl_cfree.expect("non-null function pointer")(conn as *mut libc::c_void);
        return 0 as *mut connectdata;
    }
    let ref mut fresh84 = (*conn).ssl_extra;
    *fresh84 = ssl as *mut libc::c_void;
    let ref mut fresh85 = (*conn).ssl[0 as libc::c_int as usize].backend;
    *fresh85 = ssl as *mut libc::c_void as *mut ssl_backend_data;
    let ref mut fresh86 = (*conn).ssl[1 as libc::c_int as usize].backend;
    *fresh86 = ssl.offset(sslsize as isize) as *mut libc::c_void
        as *mut ssl_backend_data;
    let ref mut fresh87 = (*conn).proxy_ssl[0 as libc::c_int as usize].backend;
    *fresh87 = ssl
        .offset((2 as libc::c_int as libc::c_ulong).wrapping_mul(sslsize) as isize)
        as *mut libc::c_void as *mut ssl_backend_data;
    let ref mut fresh88 = (*conn).proxy_ssl[1 as libc::c_int as usize].backend;
    *fresh88 = ssl
        .offset((3 as libc::c_int as libc::c_ulong).wrapping_mul(sslsize) as isize)
        as *mut libc::c_void as *mut ssl_backend_data;
    let ref mut fresh89 = (*conn).handler;
    *fresh89 = &Curl_handler_dummy;
    (*conn).sock[0 as libc::c_int as usize] = -(1 as libc::c_int);
    (*conn).sock[1 as libc::c_int as usize] = -(1 as libc::c_int);
    (*conn).tempsock[0 as libc::c_int as usize] = -(1 as libc::c_int);
    (*conn).tempsock[1 as libc::c_int as usize] = -(1 as libc::c_int);
    (*conn).connection_id = -(1 as libc::c_int) as libc::c_long;
    (*conn).port = -(1 as libc::c_int);
    (*conn).remote_port = -(1 as libc::c_int);
    Curl_conncontrol(conn, 1 as libc::c_int);
    (*conn).created = Curl_now();
    (*conn).keepalive = Curl_now();
    (*conn).http_proxy.proxytype = (*data).set.proxytype;
    (*conn).socks_proxy.proxytype = CURLPROXY_SOCKS4;
    let ref mut fresh90 = (*conn).bits;
    (*fresh90)
        .set_proxy(
            (if !((*data).set.str_0[STRING_PROXY as libc::c_int as usize]).is_null()
                && *(*data).set.str_0[STRING_PROXY as libc::c_int as usize]
                    as libc::c_int != 0
            {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            }) as bit,
        );
    let ref mut fresh91 = (*conn).bits;
    (*fresh91)
        .set_httpproxy(
            (if ((*conn).bits).proxy() as libc::c_int != 0
                && ((*conn).http_proxy.proxytype as libc::c_uint
                    == CURLPROXY_HTTP as libc::c_int as libc::c_uint
                    || (*conn).http_proxy.proxytype as libc::c_uint
                        == CURLPROXY_HTTP_1_0 as libc::c_int as libc::c_uint
                    || (*conn).http_proxy.proxytype as libc::c_uint
                        == CURLPROXY_HTTPS as libc::c_int as libc::c_uint)
            {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            }) as bit,
        );
    let ref mut fresh92 = (*conn).bits;
    (*fresh92)
        .set_socksproxy(
            (if ((*conn).bits).proxy() as libc::c_int != 0
                && ((*conn).bits).httpproxy() == 0
            {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            }) as bit,
        );
    if !((*data).set.str_0[STRING_PRE_PROXY as libc::c_int as usize]).is_null()
        && *(*data).set.str_0[STRING_PRE_PROXY as libc::c_int as usize] as libc::c_int
            != 0
    {
        let ref mut fresh93 = (*conn).bits;
        (*fresh93).set_proxy(1 as libc::c_int as bit);
        let ref mut fresh94 = (*conn).bits;
        (*fresh94).set_socksproxy(1 as libc::c_int as bit);
    }
    let ref mut fresh95 = (*conn).bits;
    (*fresh95)
        .set_proxy_user_passwd(
            (if !((*data).state.aptr.proxyuser).is_null() {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            }) as bit,
        );
    let ref mut fresh96 = (*conn).bits;
    (*fresh96).set_tunnel_proxy(((*data).set).tunnel_thru_httpproxy());
    let ref mut fresh97 = (*conn).bits;
    (*fresh97)
        .set_user_passwd(
            (if !((*data).state.aptr.user).is_null() {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            }) as bit,
        );
    let ref mut fresh98 = (*conn).bits;
    (*fresh98).set_ftp_use_epsv(((*data).set).ftp_use_epsv());
    let ref mut fresh99 = (*conn).bits;
    (*fresh99).set_ftp_use_eprt(((*data).set).ftp_use_eprt());
    let ref mut fresh100 = (*conn).ssl_config;
    (*fresh100).set_verifystatus(((*data).set.ssl.primary).verifystatus());
    let ref mut fresh101 = (*conn).ssl_config;
    (*fresh101).set_verifypeer(((*data).set.ssl.primary).verifypeer());
    let ref mut fresh102 = (*conn).ssl_config;
    (*fresh102).set_verifyhost(((*data).set.ssl.primary).verifyhost());
    let ref mut fresh103 = (*conn).proxy_ssl_config;
    (*fresh103).set_verifystatus(((*data).set.proxy_ssl.primary).verifystatus());
    let ref mut fresh104 = (*conn).proxy_ssl_config;
    (*fresh104).set_verifypeer(((*data).set.proxy_ssl.primary).verifypeer());
    let ref mut fresh105 = (*conn).proxy_ssl_config;
    (*fresh105).set_verifyhost(((*data).set.proxy_ssl.primary).verifyhost());
    (*conn).ip_version = (*data).set.ipver;
    let ref mut fresh106 = (*conn).bits;
    (*fresh106).set_connect_only(((*data).set).connect_only());
    (*conn).transport = TRNSPRT_TCP;
    (*conn).ntlm.ntlm_auth_hlpr_socket = -(1 as libc::c_int);
    (*conn).proxyntlm.ntlm_auth_hlpr_socket = -(1 as libc::c_int);
    Curl_llist_init(&mut (*conn).easyq, None);
    if !((*data).set.str_0[STRING_DEVICE as libc::c_int as usize]).is_null() {
        let ref mut fresh107 = (*conn).localdev;
        *fresh107 = Curl_cstrdup
            .expect(
                "non-null function pointer",
            )((*data).set.str_0[STRING_DEVICE as libc::c_int as usize]);
        if ((*conn).localdev).is_null() {
            Curl_llist_destroy(&mut (*conn).easyq, 0 as *mut libc::c_void);
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*conn).localdev as *mut libc::c_void);
            Curl_cfree.expect("non-null function pointer")((*conn).ssl_extra);
            Curl_cfree.expect("non-null function pointer")(conn as *mut libc::c_void);
            return 0 as *mut connectdata;
        }
    }
    (*conn).localportrange = (*data).set.localportrange;
    (*conn).localport = (*data).set.localport;
    let ref mut fresh108 = (*conn).fclosesocket;
    *fresh108 = (*data).set.fclosesocket;
    let ref mut fresh109 = (*conn).closesocket_client;
    *fresh109 = (*data).set.closesocket_client;
    (*conn).lastused = Curl_now();
    return conn;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_builtin_scheme(
    mut scheme: *const libc::c_char,
) -> *const Curl_handler {
    let mut pp: *const *const Curl_handler = 0 as *const *const Curl_handler;
    let mut p: *const Curl_handler = 0 as *const Curl_handler;
    pp = protocols.as_ptr();
    loop {
        p = *pp;
        if p.is_null() {
            break;
        }
        if Curl_strcasecompare((*p).scheme, scheme) != 0 {
            return p;
        }
        pp = pp.offset(1);
    }
    return 0 as *const Curl_handler;
}
unsafe extern "C" fn findprotocol(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut protostr: *const libc::c_char,
) -> CURLcode {
    let mut p: *const Curl_handler = Curl_builtin_scheme(protostr);
    if !p.is_null() && (*data).set.allowed_protocols & (*p).protocol as libc::c_long != 0
    {
        if ((*data).state).this_is_a_follow() as libc::c_int != 0
            && (*data).set.redir_protocols & (*p).protocol as libc::c_long == 0
        {} else {
            let ref mut fresh110 = (*conn).given;
            *fresh110 = p;
            let ref mut fresh111 = (*conn).handler;
            *fresh111 = *fresh110;
            return CURLE_OK;
        }
    }
    Curl_failf(
        data,
        b"Protocol \"%s\" not supported or disabled in libcurl\0" as *const u8
            as *const libc::c_char,
        protostr,
    );
    return CURLE_UNSUPPORTED_PROTOCOL;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_uc_to_curlcode(mut uc: CURLUcode) -> CURLcode {
    match uc as libc::c_uint {
        5 => return CURLE_UNSUPPORTED_PROTOCOL,
        7 => return CURLE_OUT_OF_MEMORY,
        8 => return CURLE_LOGIN_DENIED,
        _ => return CURLE_URL_MALFORMAT,
    };
}
unsafe extern "C" fn zonefrom_url(
    mut uh: *mut CURLU,
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) {
    let mut zoneid: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut uc: CURLUcode = curl_url_get(
        uh,
        CURLUPART_ZONEID,
        &mut zoneid,
        0 as libc::c_int as libc::c_uint,
    );
    if uc as u64 == 0 && !zoneid.is_null() {
        let mut endp: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut scope: libc::c_ulong = strtoul(zoneid, &mut endp, 10 as libc::c_int);
        if *endp == 0
            && scope
                < (2147483647 as libc::c_int as libc::c_uint)
                    .wrapping_mul(2 as libc::c_uint)
                    .wrapping_add(1 as libc::c_uint) as libc::c_ulong
        {
            (*conn).scope_id = scope as libc::c_uint;
        } else {
            let mut scopeidx: libc::c_uint = 0 as libc::c_int as libc::c_uint;
            scopeidx = if_nametoindex(zoneid);
            if scopeidx == 0 {
                let mut buffer: [libc::c_char; 256] = [0; 256];
                Curl_infof(
                    data,
                    b"Invalid zoneid: %s; %s\0" as *const u8 as *const libc::c_char,
                    zoneid,
                    Curl_strerror(
                        *__errno_location(),
                        buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                    ),
                );
            } else {
                (*conn).scope_id = scopeidx;
            }
        }
        Curl_cfree.expect("non-null function pointer")(zoneid as *mut libc::c_void);
    }
}
unsafe extern "C" fn parseurlandfillconn(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut uh: *mut CURLU = 0 as *mut CURLU;
    let mut uc: CURLUcode = CURLUE_OK;
    let mut hostname: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut use_set_uh: bool = !((*data).set.uh).is_null()
        && ((*data).state).this_is_a_follow() == 0;
    up_free(data);
    if use_set_uh {
        let ref mut fresh112 = (*data).state.uh;
        *fresh112 = curl_url_dup((*data).set.uh);
        uh = *fresh112;
    } else {
        let ref mut fresh113 = (*data).state.uh;
        *fresh113 = curl_url();
        uh = *fresh113;
    }
    if uh.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if !((*data).set.str_0[STRING_DEFAULT_PROTOCOL as libc::c_int as usize]).is_null()
        && !Curl_is_absolute_url(
            (*data).state.url,
            0 as *mut libc::c_char,
            40 as libc::c_int as size_t,
        )
    {
        let mut url: *mut libc::c_char = curl_maprintf(
            b"%s://%s\0" as *const u8 as *const libc::c_char,
            (*data).set.str_0[STRING_DEFAULT_PROTOCOL as libc::c_int as usize],
            (*data).state.url,
        );
        if url.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        if ((*data).state).url_alloc() != 0 {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).state.url as *mut libc::c_void);
        }
        let ref mut fresh114 = (*data).state.url;
        *fresh114 = url;
        let ref mut fresh115 = (*data).state;
        (*fresh115).set_url_alloc(1 as libc::c_int as bit);
    }
    if !use_set_uh {
        let mut newurl: *mut libc::c_char = 0 as *mut libc::c_char;
        uc = curl_url_set(
            uh,
            CURLUPART_URL,
            (*data).state.url,
            ((1 as libc::c_int) << 9 as libc::c_int
                | (1 as libc::c_int) << 3 as libc::c_int
                | (if ((*data).set).disallow_username_in_url() as libc::c_int != 0 {
                    (1 as libc::c_int) << 5 as libc::c_int
                } else {
                    0 as libc::c_int
                })
                | (if ((*data).set).path_as_is() as libc::c_int != 0 {
                    (1 as libc::c_int) << 4 as libc::c_int
                } else {
                    0 as libc::c_int
                })) as libc::c_uint,
        );
        if uc as u64 != 0 {
            return Curl_uc_to_curlcode(uc);
        }
        uc = curl_url_get(
            uh,
            CURLUPART_URL,
            &mut newurl,
            0 as libc::c_int as libc::c_uint,
        );
        if uc as u64 != 0 {
            return Curl_uc_to_curlcode(uc);
        }
        if ((*data).state).url_alloc() != 0 {
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).state.url as *mut libc::c_void);
        }
        let ref mut fresh116 = (*data).state.url;
        *fresh116 = newurl;
        let ref mut fresh117 = (*data).state;
        (*fresh117).set_url_alloc(1 as libc::c_int as bit);
    }
    uc = curl_url_get(
        uh,
        CURLUPART_SCHEME,
        &mut (*data).state.up.scheme,
        0 as libc::c_int as libc::c_uint,
    );
    if uc as u64 != 0 {
        return Curl_uc_to_curlcode(uc);
    }
    uc = curl_url_get(
        uh,
        CURLUPART_HOST,
        &mut (*data).state.up.hostname,
        0 as libc::c_int as libc::c_uint,
    );
    if uc as u64 != 0 {
        if Curl_strcasecompare(
            b"file\0" as *const u8 as *const libc::c_char,
            (*data).state.up.scheme,
        ) == 0
        {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if !((*data).hsts).is_null()
        && Curl_strcasecompare(
            b"http\0" as *const u8 as *const libc::c_char,
            (*data).state.up.scheme,
        ) != 0
    {
        if !(Curl_hsts((*data).hsts, (*data).state.up.hostname, 1 as libc::c_int != 0))
            .is_null()
        {
            let mut url_0: *mut libc::c_char = 0 as *mut libc::c_char;
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )((*data).state.up.scheme as *mut libc::c_void);
            let ref mut fresh118 = (*data).state.up.scheme;
            *fresh118 = 0 as *mut libc::c_char;
            uc = curl_url_set(
                uh,
                CURLUPART_SCHEME,
                b"https\0" as *const u8 as *const libc::c_char,
                0 as libc::c_int as libc::c_uint,
            );
            if uc as u64 != 0 {
                return Curl_uc_to_curlcode(uc);
            }
            if ((*data).state).url_alloc() != 0 {
                Curl_cfree
                    .expect(
                        "non-null function pointer",
                    )((*data).state.url as *mut libc::c_void);
                let ref mut fresh119 = (*data).state.url;
                *fresh119 = 0 as *mut libc::c_char;
            }
            uc = curl_url_get(
                uh,
                CURLUPART_URL,
                &mut url_0,
                0 as libc::c_int as libc::c_uint,
            );
            if uc as u64 != 0 {
                return Curl_uc_to_curlcode(uc);
            }
            uc = curl_url_get(
                uh,
                CURLUPART_SCHEME,
                &mut (*data).state.up.scheme,
                0 as libc::c_int as libc::c_uint,
            );
            if uc as u64 != 0 {
                Curl_cfree
                    .expect("non-null function pointer")(url_0 as *mut libc::c_void);
                return Curl_uc_to_curlcode(uc);
            }
            let ref mut fresh120 = (*data).state.url;
            *fresh120 = url_0;
            let ref mut fresh121 = (*data).state;
            (*fresh121).set_url_alloc(1 as libc::c_int as bit);
            Curl_infof(
                data,
                b"Switched from HTTP to HTTPS due to HSTS => %s\0" as *const u8
                    as *const libc::c_char,
                (*data).state.url,
            );
        }
    }
    result = findprotocol(data, conn, (*data).state.up.scheme);
    if result as u64 != 0 {
        return result;
    }
    if ((*data).state.aptr.user).is_null() {
        uc = curl_url_get(
            uh,
            CURLUPART_USER,
            &mut (*data).state.up.user,
            0 as libc::c_int as libc::c_uint,
        );
        if uc as u64 == 0 {
            let mut decoded: *mut libc::c_char = 0 as *mut libc::c_char;
            result = Curl_urldecode(
                0 as *mut Curl_easy,
                (*data).state.up.user,
                0 as libc::c_int as size_t,
                &mut decoded,
                0 as *mut size_t,
                (if (*(*conn).handler).flags
                    & ((1 as libc::c_int) << 13 as libc::c_int) as libc::c_uint != 0
                {
                    REJECT_ZERO as libc::c_int
                } else {
                    REJECT_CTRL as libc::c_int
                }) as urlreject,
            );
            if result as u64 != 0 {
                return result;
            }
            let ref mut fresh122 = (*conn).user;
            *fresh122 = decoded;
            let ref mut fresh123 = (*conn).bits;
            (*fresh123).set_user_passwd(1 as libc::c_int as bit);
            result = Curl_setstropt(&mut (*data).state.aptr.user, decoded);
            if result as u64 != 0 {
                return result;
            }
        } else if uc as libc::c_uint != CURLUE_NO_USER as libc::c_int as libc::c_uint {
            return Curl_uc_to_curlcode(uc)
        }
    }
    if ((*data).state.aptr.passwd).is_null() {
        uc = curl_url_get(
            uh,
            CURLUPART_PASSWORD,
            &mut (*data).state.up.password,
            0 as libc::c_int as libc::c_uint,
        );
        if uc as u64 == 0 {
            let mut decoded_0: *mut libc::c_char = 0 as *mut libc::c_char;
            result = Curl_urldecode(
                0 as *mut Curl_easy,
                (*data).state.up.password,
                0 as libc::c_int as size_t,
                &mut decoded_0,
                0 as *mut size_t,
                (if (*(*conn).handler).flags
                    & ((1 as libc::c_int) << 13 as libc::c_int) as libc::c_uint != 0
                {
                    REJECT_ZERO as libc::c_int
                } else {
                    REJECT_CTRL as libc::c_int
                }) as urlreject,
            );
            if result as u64 != 0 {
                return result;
            }
            let ref mut fresh124 = (*conn).passwd;
            *fresh124 = decoded_0;
            let ref mut fresh125 = (*conn).bits;
            (*fresh125).set_user_passwd(1 as libc::c_int as bit);
            result = Curl_setstropt(&mut (*data).state.aptr.passwd, decoded_0);
            if result as u64 != 0 {
                return result;
            }
        } else if uc as libc::c_uint != CURLUE_NO_PASSWORD as libc::c_int as libc::c_uint
            {
            return Curl_uc_to_curlcode(uc)
        }
    }
    uc = curl_url_get(
        uh,
        CURLUPART_OPTIONS,
        &mut (*data).state.up.options,
        ((1 as libc::c_int) << 6 as libc::c_int) as libc::c_uint,
    );
    if uc as u64 == 0 {
        let ref mut fresh126 = (*conn).options;
        *fresh126 = Curl_cstrdup
            .expect("non-null function pointer")((*data).state.up.options);
        if ((*conn).options).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    } else if uc as libc::c_uint != CURLUE_NO_OPTIONS as libc::c_int as libc::c_uint {
        return Curl_uc_to_curlcode(uc)
    }
    uc = curl_url_get(
        uh,
        CURLUPART_PATH,
        &mut (*data).state.up.path,
        0 as libc::c_int as libc::c_uint,
    );
    if uc as u64 != 0 {
        return Curl_uc_to_curlcode(uc);
    }
    uc = curl_url_get(
        uh,
        CURLUPART_PORT,
        &mut (*data).state.up.port,
        ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint,
    );
    if uc as u64 != 0 {
        if Curl_strcasecompare(
            b"file\0" as *const u8 as *const libc::c_char,
            (*data).state.up.scheme,
        ) == 0
        {
            return CURLE_OUT_OF_MEMORY;
        }
    } else {
        let mut port: libc::c_ulong = strtoul(
            (*data).state.up.port,
            0 as *mut *mut libc::c_char,
            10 as libc::c_int,
        );
        let ref mut fresh127 = (*conn).remote_port;
        *fresh127 = if (*data).set.use_port != 0
            && ((*data).state).allow_port() as libc::c_int != 0
        {
            (*data).set.use_port as libc::c_int
        } else {
            curlx_ultous(port) as libc::c_int
        };
        (*conn).port = *fresh127;
    }
    curl_url_get(
        uh,
        CURLUPART_QUERY,
        &mut (*data).state.up.query,
        0 as libc::c_int as libc::c_uint,
    );
    hostname = (*data).state.up.hostname;
    if !hostname.is_null()
        && *hostname.offset(0 as libc::c_int as isize) as libc::c_int == '[' as i32
    {
        let mut hlen: size_t = 0;
        let ref mut fresh128 = (*conn).bits;
        (*fresh128).set_ipv6_ip(1 as libc::c_int as bit);
        hostname = hostname.offset(1);
        hlen = strlen(hostname);
        *hostname
            .offset(
                hlen.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
            ) = 0 as libc::c_int as libc::c_char;
        zonefrom_url(uh, data, conn);
    }
    let ref mut fresh129 = (*conn).host.rawalloc;
    *fresh129 = Curl_cstrdup
        .expect(
            "non-null function pointer",
        )(
        if !hostname.is_null() {
            hostname as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    if ((*conn).host.rawalloc).is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    let ref mut fresh130 = (*conn).host.name;
    *fresh130 = (*conn).host.rawalloc;
    if (*data).set.scope_id != 0 {
        (*conn).scope_id = (*data).set.scope_id;
    }
    return CURLE_OK;
}
unsafe extern "C" fn setup_range(mut data: *mut Curl_easy) -> CURLcode {
    let mut s: *mut UrlState = &mut (*data).state;
    (*s).resume_from = (*data).set.set_resume_from;
    if (*s).resume_from != 0
        || !((*data).set.str_0[STRING_SET_RANGE as libc::c_int as usize]).is_null()
    {
        if (*s).rangestringalloc() != 0 {
            Curl_cfree
                .expect("non-null function pointer")((*s).range as *mut libc::c_void);
        }
        if (*s).resume_from != 0 {
            let ref mut fresh131 = (*s).range;
            *fresh131 = curl_maprintf(
                b"%ld-\0" as *const u8 as *const libc::c_char,
                (*s).resume_from,
            );
        } else {
            let ref mut fresh132 = (*s).range;
            *fresh132 = Curl_cstrdup
                .expect(
                    "non-null function pointer",
                )((*data).set.str_0[STRING_SET_RANGE as libc::c_int as usize]);
        }
        (*s)
            .set_rangestringalloc(
                (if !((*s).range).is_null() {
                    1 as libc::c_int
                } else {
                    0 as libc::c_int
                }) as bit,
            );
        if ((*s).range).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        (*s).set_use_range(1 as libc::c_int as bit);
    } else {
        (*s).set_use_range(0 as libc::c_int as bit);
    }
    return CURLE_OK;
}
unsafe extern "C" fn setup_connection_internals(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut p: *const Curl_handler = 0 as *const Curl_handler;
    let mut result: CURLcode = CURLE_OK;
    p = (*conn).handler;
    if ((*p).setup_connection).is_some() {
        result = (Some(((*p).setup_connection).expect("non-null function pointer")))
            .expect("non-null function pointer")(data, conn);
        if result as u64 != 0 {
            return result;
        }
        p = (*conn).handler;
    }
    if (*conn).port < 0 as libc::c_int {
        (*conn).port = (*p).defport;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_free_request_state(mut data: *mut Curl_easy) {
    Curl_cfree
        .expect("non-null function pointer")((*data).req.p.http as *mut libc::c_void);
    let ref mut fresh133 = (*data).req.p.http;
    *fresh133 = 0 as *mut HTTP;
    Curl_cfree
        .expect("non-null function pointer")((*data).req.newurl as *mut libc::c_void);
    let ref mut fresh134 = (*data).req.newurl;
    *fresh134 = 0 as *mut libc::c_char;
    if !((*data).req.doh).is_null() {
        Curl_close(
            &mut (*((*(*data).req.doh).probe)
                .as_mut_ptr()
                .offset(0 as libc::c_int as isize))
                .easy,
        );
        Curl_close(
            &mut (*((*(*data).req.doh).probe)
                .as_mut_ptr()
                .offset(1 as libc::c_int as isize))
                .easy,
        );
    }
}
unsafe extern "C" fn check_noproxy(
    mut name: *const libc::c_char,
    mut no_proxy: *const libc::c_char,
) -> bool {
    if !no_proxy.is_null()
        && *no_proxy.offset(0 as libc::c_int as isize) as libc::c_int != 0
    {
        let mut tok_start: size_t = 0;
        let mut tok_end: size_t = 0;
        let mut separator: *const libc::c_char = b", \0" as *const u8
            as *const libc::c_char;
        let mut no_proxy_len: size_t = 0;
        let mut namelen: size_t = 0;
        let mut endptr: *mut libc::c_char = 0 as *mut libc::c_char;
        if Curl_strcasecompare(b"*\0" as *const u8 as *const libc::c_char, no_proxy) != 0
        {
            return 1 as libc::c_int != 0;
        }
        no_proxy_len = strlen(no_proxy);
        if *name.offset(0 as libc::c_int as isize) as libc::c_int == '[' as i32 {
            endptr = strchr(name, ']' as i32);
            if endptr.is_null() {
                return 0 as libc::c_int != 0;
            }
            name = name.offset(1);
            namelen = endptr.offset_from(name) as libc::c_long as size_t;
        } else {
            namelen = strlen(name);
        }
        tok_start = 0 as libc::c_int as size_t;
        while tok_start < no_proxy_len {
            while tok_start < no_proxy_len
                && !(strchr(
                    separator,
                    *no_proxy.offset(tok_start as isize) as libc::c_int,
                ))
                    .is_null()
            {
                tok_start = tok_start.wrapping_add(1);
            }
            if tok_start == no_proxy_len {
                break;
            }
            tok_end = tok_start;
            while tok_end < no_proxy_len
                && (strchr(separator, *no_proxy.offset(tok_end as isize) as libc::c_int))
                    .is_null()
            {
                tok_end = tok_end.wrapping_add(1);
            }
            if *no_proxy.offset(tok_start as isize) as libc::c_int == '.' as i32 {
                tok_start = tok_start.wrapping_add(1);
            }
            if tok_end.wrapping_sub(tok_start) <= namelen {
                let mut checkn: *const libc::c_char = name
                    .offset(namelen as isize)
                    .offset(-(tok_end.wrapping_sub(tok_start) as isize));
                if Curl_strncasecompare(
                    no_proxy.offset(tok_start as isize),
                    checkn,
                    tok_end.wrapping_sub(tok_start),
                ) != 0
                {
                    if tok_end.wrapping_sub(tok_start) == namelen
                        || *checkn.offset(-(1 as libc::c_int as isize)) as libc::c_int
                            == '.' as i32
                    {
                        return 1 as libc::c_int != 0;
                    }
                }
            }
            tok_start = tok_end.wrapping_add(1 as libc::c_int as libc::c_ulong);
        }
    }
    return 0 as libc::c_int != 0;
}
unsafe extern "C" fn detect_proxy(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> *mut libc::c_char {
    let mut proxy: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut proxy_env: [libc::c_char; 128] = [0; 128];
    let mut protop: *const libc::c_char = (*(*conn).handler).scheme;
    let mut envp: *mut libc::c_char = proxy_env.as_mut_ptr();
    let mut prox: *mut libc::c_char = 0 as *mut libc::c_char;
    while *protop != 0 {
        let fresh138 = envp;
        envp = envp.offset(1);
        *fresh138 = ({
            let mut __res: libc::c_int = 0;
            if ::std::mem::size_of::<libc::c_int>() as libc::c_ulong
                > 1 as libc::c_int as libc::c_ulong
            {
                if 0 != 0 {
                    let fresh135 = protop;
                    protop = protop.offset(1);
                    let mut __c: libc::c_int = *fresh135 as libc::c_int;
                    __res = if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                        __c
                    } else {
                        *(*__ctype_tolower_loc()).offset(__c as isize)
                    };
                } else {
                    let fresh136 = protop;
                    protop = protop.offset(1);
                    __res = tolower(*fresh136 as libc::c_int);
                }
            } else {
                let fresh137 = protop;
                protop = protop.offset(1);
                __res = *(*__ctype_tolower_loc())
                    .offset(*fresh137 as libc::c_int as isize);
            }
            __res
        }) as libc::c_char;
    }
    strcpy(envp, b"_proxy\0" as *const u8 as *const libc::c_char);
    prox = curl_getenv(proxy_env.as_mut_ptr());
    if prox.is_null()
        && Curl_strcasecompare(
            b"http_proxy\0" as *const u8 as *const libc::c_char,
            proxy_env.as_mut_ptr(),
        ) == 0
    {
        Curl_strntoupper(
            proxy_env.as_mut_ptr(),
            proxy_env.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
        );
        prox = curl_getenv(proxy_env.as_mut_ptr());
    }
    envp = proxy_env.as_mut_ptr();
    if !prox.is_null() {
        proxy = prox;
    } else {
        envp = b"all_proxy\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        proxy = curl_getenv(envp);
        if proxy.is_null() {
            envp = b"ALL_PROXY\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char;
            proxy = curl_getenv(envp);
        }
    }
    if !proxy.is_null() {
        Curl_infof(
            data,
            b"Uses proxy env variable %s == '%s'\0" as *const u8 as *const libc::c_char,
            envp,
            proxy,
        );
    }
    return proxy;
}
unsafe extern "C" fn parse_proxy(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut proxy: *mut libc::c_char,
    mut proxytype: curl_proxytype,
) -> CURLcode {
    let mut current_block: u64;
    let mut portptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut port: libc::c_int = -(1 as libc::c_int);
    let mut proxyuser: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut proxypasswd: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sockstype: bool = false;
    let mut uc: CURLUcode = CURLUE_OK;
    let mut proxyinfo: *mut proxy_info = 0 as *mut proxy_info;
    let mut uhp: *mut CURLU = curl_url();
    let mut result: CURLcode = CURLE_OK;
    let mut scheme: *mut libc::c_char = 0 as *mut libc::c_char;
    uc = curl_url_set(
        uhp,
        CURLUPART_URL,
        proxy,
        ((1 as libc::c_int) << 3 as libc::c_int | (1 as libc::c_int) << 9 as libc::c_int)
            as libc::c_uint,
    );
    if uc as u64 == 0 {
        uc = curl_url_get(
            uhp,
            CURLUPART_SCHEME,
            &mut scheme,
            0 as libc::c_int as libc::c_uint,
        );
        if uc as u64 != 0 {
            result = CURLE_OUT_OF_MEMORY;
        } else {
            if Curl_strcasecompare(
                b"https\0" as *const u8 as *const libc::c_char,
                scheme,
            ) != 0
            {
                proxytype = CURLPROXY_HTTPS;
                current_block = 15125582407903384992;
            } else if Curl_strcasecompare(
                    b"socks5h\0" as *const u8 as *const libc::c_char,
                    scheme,
                ) != 0
                {
                proxytype = CURLPROXY_SOCKS5_HOSTNAME;
                current_block = 15125582407903384992;
            } else if Curl_strcasecompare(
                    b"socks5\0" as *const u8 as *const libc::c_char,
                    scheme,
                ) != 0
                {
                proxytype = CURLPROXY_SOCKS5;
                current_block = 15125582407903384992;
            } else if Curl_strcasecompare(
                    b"socks4a\0" as *const u8 as *const libc::c_char,
                    scheme,
                ) != 0
                {
                proxytype = CURLPROXY_SOCKS4A;
                current_block = 15125582407903384992;
            } else if Curl_strcasecompare(
                    b"socks4\0" as *const u8 as *const libc::c_char,
                    scheme,
                ) != 0
                    || Curl_strcasecompare(
                        b"socks\0" as *const u8 as *const libc::c_char,
                        scheme,
                    ) != 0
                {
                proxytype = CURLPROXY_SOCKS4;
                current_block = 15125582407903384992;
            } else if Curl_strcasecompare(
                    b"http\0" as *const u8 as *const libc::c_char,
                    scheme,
                ) != 0
                {
                current_block = 15125582407903384992;
            } else {
                Curl_failf(
                    data,
                    b"Unsupported proxy scheme for '%s'\0" as *const u8
                        as *const libc::c_char,
                    proxy,
                );
                result = CURLE_COULDNT_CONNECT;
                current_block = 467357264955599708;
            }
            match current_block {
                467357264955599708 => {}
                _ => {
                    if (*Curl_ssl).supports
                        & ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uint == 0
                    {
                        if proxytype as libc::c_uint
                            == CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                        {
                            Curl_failf(
                                data,
                                b"Unsupported proxy '%s', libcurl is built without the HTTPS-proxy support.\0"
                                    as *const u8 as *const libc::c_char,
                                proxy,
                            );
                            result = CURLE_NOT_BUILT_IN;
                            current_block = 467357264955599708;
                        } else {
                            current_block = 2569451025026770673;
                        }
                    } else {
                        current_block = 2569451025026770673;
                    }
                    match current_block {
                        467357264955599708 => {}
                        _ => {
                            sockstype = proxytype as libc::c_uint
                                == CURLPROXY_SOCKS5_HOSTNAME as libc::c_int as libc::c_uint
                                || proxytype as libc::c_uint
                                    == CURLPROXY_SOCKS5 as libc::c_int as libc::c_uint
                                || proxytype as libc::c_uint
                                    == CURLPROXY_SOCKS4A as libc::c_int as libc::c_uint
                                || proxytype as libc::c_uint
                                    == CURLPROXY_SOCKS4 as libc::c_int as libc::c_uint;
                            proxyinfo = if sockstype as libc::c_int != 0 {
                                &mut (*conn).socks_proxy
                            } else {
                                &mut (*conn).http_proxy
                            };
                            (*proxyinfo).proxytype = proxytype;
                            uc = curl_url_get(
                                uhp,
                                CURLUPART_USER,
                                &mut proxyuser,
                                ((1 as libc::c_int) << 6 as libc::c_int) as libc::c_uint,
                            );
                            if !(uc as libc::c_uint != 0
                                && uc as libc::c_uint
                                    != CURLUE_NO_USER as libc::c_int as libc::c_uint)
                            {
                                uc = curl_url_get(
                                    uhp,
                                    CURLUPART_PASSWORD,
                                    &mut proxypasswd,
                                    ((1 as libc::c_int) << 6 as libc::c_int) as libc::c_uint,
                                );
                                if !(uc as libc::c_uint != 0
                                    && uc as libc::c_uint
                                        != CURLUE_NO_PASSWORD as libc::c_int as libc::c_uint)
                                {
                                    if !proxyuser.is_null() || !proxypasswd.is_null() {
                                        Curl_cfree
                                            .expect(
                                                "non-null function pointer",
                                            )((*proxyinfo).user as *mut libc::c_void);
                                        let ref mut fresh139 = (*proxyinfo).user;
                                        *fresh139 = 0 as *mut libc::c_char;
                                        let ref mut fresh140 = (*proxyinfo).user;
                                        *fresh140 = proxyuser;
                                        result = Curl_setstropt(
                                            &mut (*data).state.aptr.proxyuser,
                                            proxyuser,
                                        );
                                        proxyuser = 0 as *mut libc::c_char;
                                        if result as u64 != 0 {
                                            current_block = 467357264955599708;
                                        } else {
                                            Curl_cfree
                                                .expect(
                                                    "non-null function pointer",
                                                )((*proxyinfo).passwd as *mut libc::c_void);
                                            let ref mut fresh141 = (*proxyinfo).passwd;
                                            *fresh141 = 0 as *mut libc::c_char;
                                            if proxypasswd.is_null() {
                                                proxypasswd = Curl_cstrdup
                                                    .expect(
                                                        "non-null function pointer",
                                                    )(b"\0" as *const u8 as *const libc::c_char);
                                                if proxypasswd.is_null() {
                                                    result = CURLE_OUT_OF_MEMORY;
                                                    current_block = 467357264955599708;
                                                } else {
                                                    current_block = 1854459640724737493;
                                                }
                                            } else {
                                                current_block = 1854459640724737493;
                                            }
                                            match current_block {
                                                467357264955599708 => {}
                                                _ => {
                                                    let ref mut fresh142 = (*proxyinfo).passwd;
                                                    *fresh142 = proxypasswd;
                                                    result = Curl_setstropt(
                                                        &mut (*data).state.aptr.proxypasswd,
                                                        proxypasswd,
                                                    );
                                                    proxypasswd = 0 as *mut libc::c_char;
                                                    if result as u64 != 0 {
                                                        current_block = 467357264955599708;
                                                    } else {
                                                        let ref mut fresh143 = (*conn).bits;
                                                        (*fresh143).set_proxy_user_passwd(1 as libc::c_int as bit);
                                                        current_block = 11441799814184323368;
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        current_block = 11441799814184323368;
                                    }
                                    match current_block {
                                        467357264955599708 => {}
                                        _ => {
                                            curl_url_get(
                                                uhp,
                                                CURLUPART_PORT,
                                                &mut portptr,
                                                0 as libc::c_int as libc::c_uint,
                                            );
                                            if !portptr.is_null() {
                                                port = strtol(
                                                    portptr,
                                                    0 as *mut *mut libc::c_char,
                                                    10 as libc::c_int,
                                                ) as libc::c_int;
                                                Curl_cfree
                                                    .expect(
                                                        "non-null function pointer",
                                                    )(portptr as *mut libc::c_void);
                                            } else if (*data).set.proxyport != 0 {
                                                port = (*data).set.proxyport as libc::c_int;
                                            } else if proxytype as libc::c_uint
                                                    == CURLPROXY_HTTPS as libc::c_int as libc::c_uint
                                                {
                                                port = 443 as libc::c_int;
                                            } else {
                                                port = 1080 as libc::c_int;
                                            }
                                            if port >= 0 as libc::c_int {
                                                (*proxyinfo).port = port as libc::c_long;
                                                if (*conn).port < 0 as libc::c_int
                                                    || sockstype as libc::c_int != 0
                                                    || ((*conn).socks_proxy.host.rawalloc).is_null()
                                                {
                                                    (*conn).port = port;
                                                }
                                            }
                                            uc = curl_url_get(
                                                uhp,
                                                CURLUPART_HOST,
                                                &mut host,
                                                ((1 as libc::c_int) << 6 as libc::c_int) as libc::c_uint,
                                            );
                                            if uc as u64 != 0 {
                                                result = CURLE_OUT_OF_MEMORY;
                                            } else {
                                                Curl_cfree
                                                    .expect(
                                                        "non-null function pointer",
                                                    )((*proxyinfo).host.rawalloc as *mut libc::c_void);
                                                let ref mut fresh144 = (*proxyinfo).host.rawalloc;
                                                *fresh144 = 0 as *mut libc::c_char;
                                                let ref mut fresh145 = (*proxyinfo).host.rawalloc;
                                                *fresh145 = host;
                                                if *host.offset(0 as libc::c_int as isize) as libc::c_int
                                                    == '[' as i32
                                                {
                                                    let mut len: size_t = strlen(host);
                                                    *host
                                                        .offset(
                                                            len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                                                        ) = 0 as libc::c_int as libc::c_char;
                                                    host = host.offset(1);
                                                    zonefrom_url(uhp, data, conn);
                                                }
                                                let ref mut fresh146 = (*proxyinfo).host.name;
                                                *fresh146 = host;
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
    } else {
        Curl_failf(
            data,
            b"Unsupported proxy syntax in '%s'\0" as *const u8 as *const libc::c_char,
            proxy,
        );
        result = CURLE_COULDNT_RESOLVE_PROXY;
    }
    Curl_cfree.expect("non-null function pointer")(proxyuser as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(proxypasswd as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(scheme as *mut libc::c_void);
    curl_url_cleanup(uhp);
    return result;
}
unsafe extern "C" fn parse_proxy_auth(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut proxyuser: *const libc::c_char = if !((*data).state.aptr.proxyuser).is_null()
    {
        (*data).state.aptr.proxyuser as *const libc::c_char
    } else {
        b"\0" as *const u8 as *const libc::c_char
    };
    let mut proxypasswd: *const libc::c_char = if !((*data).state.aptr.proxypasswd)
        .is_null()
    {
        (*data).state.aptr.proxypasswd as *const libc::c_char
    } else {
        b"\0" as *const u8 as *const libc::c_char
    };
    let mut result: CURLcode = CURLE_OK;
    if !proxyuser.is_null() {
        result = Curl_urldecode(
            data,
            proxyuser,
            0 as libc::c_int as size_t,
            &mut (*conn).http_proxy.user,
            0 as *mut size_t,
            REJECT_ZERO,
        );
        if result as u64 == 0 {
            result = Curl_setstropt(
                &mut (*data).state.aptr.proxyuser,
                (*conn).http_proxy.user,
            );
        }
    }
    if result as u64 == 0 && !proxypasswd.is_null() {
        result = Curl_urldecode(
            data,
            proxypasswd,
            0 as libc::c_int as size_t,
            &mut (*conn).http_proxy.passwd,
            0 as *mut size_t,
            REJECT_ZERO,
        );
        if result as u64 == 0 {
            result = Curl_setstropt(
                &mut (*data).state.aptr.proxypasswd,
                (*conn).http_proxy.passwd,
            );
        }
    }
    return result;
}
unsafe extern "C" fn create_conn_helper_init_proxy(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut current_block: u64;
    let mut proxy: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut socksproxy: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut no_proxy: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut result: CURLcode = CURLE_OK;
    if ((*conn).bits).proxy_user_passwd() != 0 {
        result = parse_proxy_auth(data, conn);
        if result as u64 != 0 {
            current_block = 5128804967847913759;
        } else {
            current_block = 6873731126896040597;
        }
    } else {
        current_block = 6873731126896040597;
    }
    match current_block {
        6873731126896040597 => {
            if !((*data).set.str_0[STRING_PROXY as libc::c_int as usize]).is_null() {
                proxy = Curl_cstrdup
                    .expect(
                        "non-null function pointer",
                    )((*data).set.str_0[STRING_PROXY as libc::c_int as usize]);
                if proxy.is_null() {
                    Curl_failf(
                        data,
                        b"memory shortage\0" as *const u8 as *const libc::c_char,
                    );
                    result = CURLE_OUT_OF_MEMORY;
                    current_block = 5128804967847913759;
                } else {
                    current_block = 2968425633554183086;
                }
            } else {
                current_block = 2968425633554183086;
            }
            match current_block {
                5128804967847913759 => {}
                _ => {
                    if !((*data).set.str_0[STRING_PRE_PROXY as libc::c_int as usize])
                        .is_null()
                    {
                        socksproxy = Curl_cstrdup
                            .expect(
                                "non-null function pointer",
                            )(
                            (*data).set.str_0[STRING_PRE_PROXY as libc::c_int as usize],
                        );
                        if socksproxy.is_null() {
                            Curl_failf(
                                data,
                                b"memory shortage\0" as *const u8 as *const libc::c_char,
                            );
                            result = CURLE_OUT_OF_MEMORY;
                            current_block = 5128804967847913759;
                        } else {
                            current_block = 15652330335145281839;
                        }
                    } else {
                        current_block = 15652330335145281839;
                    }
                    match current_block {
                        5128804967847913759 => {}
                        _ => {
                            if ((*data)
                                .set
                                .str_0[STRING_NOPROXY as libc::c_int as usize])
                                .is_null()
                            {
                                let mut p: *const libc::c_char = b"no_proxy\0" as *const u8
                                    as *const libc::c_char;
                                no_proxy = curl_getenv(p);
                                if no_proxy.is_null() {
                                    p = b"NO_PROXY\0" as *const u8 as *const libc::c_char;
                                    no_proxy = curl_getenv(p);
                                }
                                if !no_proxy.is_null() {
                                    Curl_infof(
                                        data,
                                        b"Uses proxy env variable %s == '%s'\0" as *const u8
                                            as *const libc::c_char,
                                        p,
                                        no_proxy,
                                    );
                                }
                            }
                            if check_noproxy(
                                (*conn).host.name,
                                if !((*data)
                                    .set
                                    .str_0[STRING_NOPROXY as libc::c_int as usize])
                                    .is_null()
                                {
                                    (*data).set.str_0[STRING_NOPROXY as libc::c_int as usize]
                                } else {
                                    no_proxy
                                },
                            ) {
                                Curl_cfree
                                    .expect(
                                        "non-null function pointer",
                                    )(proxy as *mut libc::c_void);
                                proxy = 0 as *mut libc::c_char;
                                Curl_cfree
                                    .expect(
                                        "non-null function pointer",
                                    )(socksproxy as *mut libc::c_void);
                                socksproxy = 0 as *mut libc::c_char;
                            } else if proxy.is_null() && socksproxy.is_null() {
                                proxy = detect_proxy(data, conn);
                            }
                            Curl_cfree
                                .expect(
                                    "non-null function pointer",
                                )(no_proxy as *mut libc::c_void);
                            no_proxy = 0 as *mut libc::c_char;
                            if !proxy.is_null()
                                && !((*conn).unix_domain_socket).is_null()
                            {
                                Curl_cfree
                                    .expect(
                                        "non-null function pointer",
                                    )(proxy as *mut libc::c_void);
                                proxy = 0 as *mut libc::c_char;
                            }
                            if !proxy.is_null()
                                && (*proxy == 0
                                    || (*(*conn).handler).flags
                                        & ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uint
                                        != 0)
                            {
                                Curl_cfree
                                    .expect(
                                        "non-null function pointer",
                                    )(proxy as *mut libc::c_void);
                                proxy = 0 as *mut libc::c_char;
                            }
                            if !socksproxy.is_null()
                                && (*socksproxy == 0
                                    || (*(*conn).handler).flags
                                        & ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uint
                                        != 0)
                            {
                                Curl_cfree
                                    .expect(
                                        "non-null function pointer",
                                    )(socksproxy as *mut libc::c_void);
                                socksproxy = 0 as *mut libc::c_char;
                            }
                            if !proxy.is_null() || !socksproxy.is_null() {
                                if !proxy.is_null() {
                                    result = parse_proxy(
                                        data,
                                        conn,
                                        proxy,
                                        (*conn).http_proxy.proxytype,
                                    );
                                    Curl_cfree
                                        .expect(
                                            "non-null function pointer",
                                        )(proxy as *mut libc::c_void);
                                    proxy = 0 as *mut libc::c_char;
                                    if result as u64 != 0 {
                                        current_block = 5128804967847913759;
                                    } else {
                                        current_block = 2706659501864706830;
                                    }
                                } else {
                                    current_block = 2706659501864706830;
                                }
                                match current_block {
                                    5128804967847913759 => {}
                                    _ => {
                                        if !socksproxy.is_null() {
                                            result = parse_proxy(
                                                data,
                                                conn,
                                                socksproxy,
                                                (*conn).socks_proxy.proxytype,
                                            );
                                            Curl_cfree
                                                .expect(
                                                    "non-null function pointer",
                                                )(socksproxy as *mut libc::c_void);
                                            socksproxy = 0 as *mut libc::c_char;
                                            if result as u64 != 0 {
                                                current_block = 5128804967847913759;
                                            } else {
                                                current_block = 10853015579903106591;
                                            }
                                        } else {
                                            current_block = 10853015579903106591;
                                        }
                                        match current_block {
                                            5128804967847913759 => {}
                                            _ => {
                                                if !((*conn).http_proxy.host.rawalloc).is_null() {
                                                    if (*(*conn).handler).protocol
                                                        & ((1 as libc::c_int) << 0 as libc::c_int
                                                            | (1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
                                                        == 0
                                                    {
                                                        if (*(*conn).handler).flags
                                                            & ((1 as libc::c_int) << 11 as libc::c_int) as libc::c_uint
                                                            != 0 && ((*conn).bits).tunnel_proxy() == 0
                                                        {
                                                            let ref mut fresh147 = (*conn).handler;
                                                            *fresh147 = &Curl_handler_http;
                                                        } else {
                                                            let ref mut fresh148 = (*conn).bits;
                                                            (*fresh148).set_tunnel_proxy(1 as libc::c_int as bit);
                                                        }
                                                    }
                                                    let ref mut fresh149 = (*conn).bits;
                                                    (*fresh149).set_httpproxy(1 as libc::c_int as bit);
                                                } else {
                                                    let ref mut fresh150 = (*conn).bits;
                                                    (*fresh150).set_httpproxy(0 as libc::c_int as bit);
                                                    let ref mut fresh151 = (*conn).bits;
                                                    (*fresh151).set_tunnel_proxy(0 as libc::c_int as bit);
                                                }
                                                if !((*conn).socks_proxy.host.rawalloc).is_null() {
                                                    if ((*conn).http_proxy.host.rawalloc).is_null() {
                                                        if ((*conn).socks_proxy.user).is_null() {
                                                            let ref mut fresh152 = (*conn).socks_proxy.user;
                                                            *fresh152 = (*conn).http_proxy.user;
                                                            let ref mut fresh153 = (*conn).http_proxy.user;
                                                            *fresh153 = 0 as *mut libc::c_char;
                                                            Curl_cfree
                                                                .expect(
                                                                    "non-null function pointer",
                                                                )((*conn).socks_proxy.passwd as *mut libc::c_void);
                                                            let ref mut fresh154 = (*conn).socks_proxy.passwd;
                                                            *fresh154 = 0 as *mut libc::c_char;
                                                            let ref mut fresh155 = (*conn).socks_proxy.passwd;
                                                            *fresh155 = (*conn).http_proxy.passwd;
                                                            let ref mut fresh156 = (*conn).http_proxy.passwd;
                                                            *fresh156 = 0 as *mut libc::c_char;
                                                        }
                                                    }
                                                    let ref mut fresh157 = (*conn).bits;
                                                    (*fresh157).set_socksproxy(1 as libc::c_int as bit);
                                                } else {
                                                    let ref mut fresh158 = (*conn).bits;
                                                    (*fresh158).set_socksproxy(0 as libc::c_int as bit);
                                                }
                                                current_block = 16463303006880176998;
                                            }
                                        }
                                    }
                                }
                            } else {
                                let ref mut fresh159 = (*conn).bits;
                                (*fresh159).set_socksproxy(0 as libc::c_int as bit);
                                let ref mut fresh160 = (*conn).bits;
                                (*fresh160).set_httpproxy(0 as libc::c_int as bit);
                                current_block = 16463303006880176998;
                            }
                            match current_block {
                                5128804967847913759 => {}
                                _ => {
                                    let ref mut fresh161 = (*conn).bits;
                                    (*fresh161)
                                        .set_proxy(
                                            (((*conn).bits).httpproxy() as libc::c_int != 0
                                                || ((*conn).bits).socksproxy() as libc::c_int != 0)
                                                as libc::c_int as bit,
                                        );
                                    if ((*conn).bits).proxy() == 0 {
                                        let ref mut fresh162 = (*conn).bits;
                                        (*fresh162).set_proxy(0 as libc::c_int as bit);
                                        let ref mut fresh163 = (*conn).bits;
                                        (*fresh163).set_httpproxy(0 as libc::c_int as bit);
                                        let ref mut fresh164 = (*conn).bits;
                                        (*fresh164).set_socksproxy(0 as libc::c_int as bit);
                                        let ref mut fresh165 = (*conn).bits;
                                        (*fresh165).set_proxy_user_passwd(0 as libc::c_int as bit);
                                        let ref mut fresh166 = (*conn).bits;
                                        (*fresh166).set_tunnel_proxy(0 as libc::c_int as bit);
                                        (*conn).http_proxy.proxytype = CURLPROXY_HTTP;
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
    Curl_cfree.expect("non-null function pointer")(socksproxy as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(proxy as *mut libc::c_void);
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_parse_login_details(
    mut login: *const libc::c_char,
    len: size_t,
    mut userp: *mut *mut libc::c_char,
    mut passwdp: *mut *mut libc::c_char,
    mut optionsp: *mut *mut libc::c_char,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ubuf: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pbuf: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut obuf: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut psep: *const libc::c_char = 0 as *const libc::c_char;
    let mut osep: *const libc::c_char = 0 as *const libc::c_char;
    let mut ulen: size_t = 0;
    let mut plen: size_t = 0;
    let mut olen: size_t = 0;
    let mut llen: size_t = strlen(login);
    if llen > 8000000 as libc::c_int as libc::c_ulong {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if !passwdp.is_null() {
        psep = strchr(login, ':' as i32);
        if psep >= login.offset(len as isize) {
            psep = 0 as *const libc::c_char;
        }
    }
    if !optionsp.is_null() {
        osep = strchr(login, ';' as i32);
        if osep >= login.offset(len as isize) {
            osep = 0 as *const libc::c_char;
        }
    }
    ulen = if !psep.is_null() {
        (if !osep.is_null() && psep > osep {
            osep.offset_from(login) as libc::c_long
        } else {
            psep.offset_from(login) as libc::c_long
        }) as size_t
    } else if !osep.is_null() {
        osep.offset_from(login) as libc::c_long as size_t
    } else {
        len
    };
    plen = if !psep.is_null() {
        (if !osep.is_null() && osep > psep {
            osep.offset_from(psep) as libc::c_long as size_t
        } else {
            login.offset(len as isize).offset_from(psep) as libc::c_long as size_t
        })
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
    } else {
        0 as libc::c_int as libc::c_ulong
    };
    olen = if !osep.is_null() {
        (if !psep.is_null() && psep > osep {
            psep.offset_from(osep) as libc::c_long as size_t
        } else {
            login.offset(len as isize).offset_from(osep) as libc::c_long as size_t
        })
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
    } else {
        0 as libc::c_int as libc::c_ulong
    };
    if !userp.is_null() && ulen != 0 {
        ubuf = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )(ulen.wrapping_add(1 as libc::c_int as libc::c_ulong)) as *mut libc::c_char;
        if ubuf.is_null() {
            result = CURLE_OUT_OF_MEMORY;
        }
    }
    if result as u64 == 0 && !passwdp.is_null() && plen != 0 {
        pbuf = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )(plen.wrapping_add(1 as libc::c_int as libc::c_ulong)) as *mut libc::c_char;
        if pbuf.is_null() {
            Curl_cfree.expect("non-null function pointer")(ubuf as *mut libc::c_void);
            result = CURLE_OUT_OF_MEMORY;
        }
    }
    if result as u64 == 0 && !optionsp.is_null() && olen != 0 {
        obuf = Curl_cmalloc
            .expect(
                "non-null function pointer",
            )(olen.wrapping_add(1 as libc::c_int as libc::c_ulong)) as *mut libc::c_char;
        if obuf.is_null() {
            Curl_cfree.expect("non-null function pointer")(pbuf as *mut libc::c_void);
            Curl_cfree.expect("non-null function pointer")(ubuf as *mut libc::c_void);
            result = CURLE_OUT_OF_MEMORY;
        }
    }
    if result as u64 == 0 {
        if !ubuf.is_null() {
            memcpy(ubuf as *mut libc::c_void, login as *const libc::c_void, ulen);
            *ubuf.offset(ulen as isize) = '\u{0}' as i32 as libc::c_char;
            Curl_cfree.expect("non-null function pointer")(*userp as *mut libc::c_void);
            *userp = 0 as *mut libc::c_char;
            *userp = ubuf;
        }
        if !pbuf.is_null() {
            memcpy(
                pbuf as *mut libc::c_void,
                psep.offset(1 as libc::c_int as isize) as *const libc::c_void,
                plen,
            );
            *pbuf.offset(plen as isize) = '\u{0}' as i32 as libc::c_char;
            Curl_cfree
                .expect("non-null function pointer")(*passwdp as *mut libc::c_void);
            *passwdp = 0 as *mut libc::c_char;
            *passwdp = pbuf;
        }
        if !obuf.is_null() {
            memcpy(
                obuf as *mut libc::c_void,
                osep.offset(1 as libc::c_int as isize) as *const libc::c_void,
                olen,
            );
            *obuf.offset(olen as isize) = '\u{0}' as i32 as libc::c_char;
            Curl_cfree
                .expect("non-null function pointer")(*optionsp as *mut libc::c_void);
            *optionsp = 0 as *mut libc::c_char;
            *optionsp = obuf;
        }
    }
    return result;
}
unsafe extern "C" fn parse_remote_port(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    if (*data).set.use_port != 0 && ((*data).state).allow_port() as libc::c_int != 0 {
        let mut portbuf: [libc::c_char; 16] = [0; 16];
        let mut uc: CURLUcode = CURLUE_OK;
        (*conn).remote_port = (*data).set.use_port as libc::c_ushort as libc::c_int;
        curl_msnprintf(
            portbuf.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong,
            b"%d\0" as *const u8 as *const libc::c_char,
            (*conn).remote_port,
        );
        uc = curl_url_set(
            (*data).state.uh,
            CURLUPART_PORT,
            portbuf.as_mut_ptr(),
            0 as libc::c_int as libc::c_uint,
        );
        if uc as u64 != 0 {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    return CURLE_OK;
}
unsafe extern "C" fn override_login(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut uc: CURLUcode = CURLUE_OK;
    let mut userp: *mut *mut libc::c_char = &mut (*conn).user;
    let mut passwdp: *mut *mut libc::c_char = &mut (*conn).passwd;
    let mut optionsp: *mut *mut libc::c_char = &mut (*conn).options;
    if (*data).set.use_netrc as libc::c_uint
        == CURL_NETRC_REQUIRED as libc::c_int as libc::c_uint
        && ((*conn).bits).user_passwd() as libc::c_int != 0
    {
        Curl_cfree.expect("non-null function pointer")(*userp as *mut libc::c_void);
        *userp = 0 as *mut libc::c_char;
        Curl_cfree.expect("non-null function pointer")(*passwdp as *mut libc::c_void);
        *passwdp = 0 as *mut libc::c_char;
        let ref mut fresh167 = (*conn).bits;
        (*fresh167).set_user_passwd(0 as libc::c_int as bit);
    }
    if !((*data).set.str_0[STRING_OPTIONS as libc::c_int as usize]).is_null() {
        Curl_cfree.expect("non-null function pointer")(*optionsp as *mut libc::c_void);
        *optionsp = Curl_cstrdup
            .expect(
                "non-null function pointer",
            )((*data).set.str_0[STRING_OPTIONS as libc::c_int as usize]);
        if (*optionsp).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    let ref mut fresh168 = (*conn).bits;
    (*fresh168).set_netrc(0 as libc::c_int as bit);
    if (*data).set.use_netrc as libc::c_uint != 0
        && ((*data).set.str_0[STRING_USERNAME as libc::c_int as usize]).is_null()
    {
        let mut netrc_user_changed: bool = 0 as libc::c_int != 0;
        let mut netrc_passwd_changed: bool = 0 as libc::c_int != 0;
        let mut ret: libc::c_int = 0;
        ret = Curl_parsenetrc(
            (*conn).host.name,
            userp,
            passwdp,
            &mut netrc_user_changed,
            &mut netrc_passwd_changed,
            (*data).set.str_0[STRING_NETRC_FILE as libc::c_int as usize],
        );
        if ret > 0 as libc::c_int {
            Curl_infof(
                data,
                b"Couldn't find host %s in the %s file; using defaults\0" as *const u8
                    as *const libc::c_char,
                (*conn).host.name,
                (*data).set.str_0[STRING_NETRC_FILE as libc::c_int as usize],
            );
        } else if ret < 0 as libc::c_int {
            return CURLE_OUT_OF_MEMORY
        } else {
            let ref mut fresh169 = (*conn).bits;
            (*fresh169).set_netrc(1 as libc::c_int as bit);
            let ref mut fresh170 = (*conn).bits;
            (*fresh170).set_user_passwd(1 as libc::c_int as bit);
        }
    }
    if !(*userp).is_null() {
        let mut result: CURLcode = Curl_setstropt(&mut (*data).state.aptr.user, *userp);
        if result as u64 != 0 {
            return result;
        }
    }
    if !((*data).state.aptr.user).is_null() {
        uc = curl_url_set(
            (*data).state.uh,
            CURLUPART_USER,
            (*data).state.aptr.user,
            ((1 as libc::c_int) << 7 as libc::c_int) as libc::c_uint,
        );
        if uc as u64 != 0 {
            return Curl_uc_to_curlcode(uc);
        }
        if (*userp).is_null() {
            *userp = Curl_cstrdup
                .expect("non-null function pointer")((*data).state.aptr.user);
            if (*userp).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        }
    }
    if !(*passwdp).is_null() {
        let mut result_0: CURLcode = Curl_setstropt(
            &mut (*data).state.aptr.passwd,
            *passwdp,
        );
        if result_0 as u64 != 0 {
            return result_0;
        }
    }
    if !((*data).state.aptr.passwd).is_null() {
        uc = curl_url_set(
            (*data).state.uh,
            CURLUPART_PASSWORD,
            (*data).state.aptr.passwd,
            ((1 as libc::c_int) << 7 as libc::c_int) as libc::c_uint,
        );
        if uc as u64 != 0 {
            return Curl_uc_to_curlcode(uc);
        }
        if (*passwdp).is_null() {
            *passwdp = Curl_cstrdup
                .expect("non-null function pointer")((*data).state.aptr.passwd);
            if (*passwdp).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
        }
    }
    return CURLE_OK;
}
unsafe extern "C" fn set_login(mut conn: *mut connectdata) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut setuser: *const libc::c_char = b"anonymous\0" as *const u8
        as *const libc::c_char;
    let mut setpasswd: *const libc::c_char = b"ftp@example.com\0" as *const u8
        as *const libc::c_char;
    if !((*(*conn).handler).flags
        & ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uint != 0
        && ((*conn).bits).user_passwd() == 0)
    {
        setuser = b"\0" as *const u8 as *const libc::c_char;
        setpasswd = b"\0" as *const u8 as *const libc::c_char;
    }
    if ((*conn).user).is_null() {
        let ref mut fresh171 = (*conn).user;
        *fresh171 = Curl_cstrdup.expect("non-null function pointer")(setuser);
        if ((*conn).user).is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if ((*conn).passwd).is_null() {
        let ref mut fresh172 = (*conn).passwd;
        *fresh172 = Curl_cstrdup.expect("non-null function pointer")(setpasswd);
        if ((*conn).passwd).is_null() {
            result = CURLE_OUT_OF_MEMORY;
        }
    }
    return result;
}
unsafe extern "C" fn parse_connect_to_host_port(
    mut data: *mut Curl_easy,
    mut host: *const libc::c_char,
    mut hostname_result: *mut *mut libc::c_char,
    mut port_result: *mut libc::c_int,
) -> CURLcode {
    let mut current_block: u64;
    let mut host_dup: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut hostptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut host_portno: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut portptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut port: libc::c_int = -(1 as libc::c_int);
    let mut result: CURLcode = CURLE_OK;
    *hostname_result = 0 as *mut libc::c_char;
    *port_result = -(1 as libc::c_int);
    if host.is_null() || *host == 0 {
        return CURLE_OK;
    }
    host_dup = Curl_cstrdup.expect("non-null function pointer")(host);
    if host_dup.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    hostptr = host_dup;
    portptr = hostptr;
    if *hostptr as libc::c_int == '[' as i32 {
        hostptr = hostptr.offset(1);
        let mut ptr: *mut libc::c_char = hostptr;
        while *ptr as libc::c_int != 0
            && (Curl_isxdigit(*ptr as libc::c_uchar as libc::c_int) != 0
                || *ptr as libc::c_int == ':' as i32
                || *ptr as libc::c_int == '.' as i32)
        {
            ptr = ptr.offset(1);
        }
        if *ptr as libc::c_int == '%' as i32 {
            if strncmp(
                b"%25\0" as *const u8 as *const libc::c_char,
                ptr,
                3 as libc::c_int as libc::c_ulong,
            ) != 0
            {
                Curl_infof(
                    data,
                    b"Please URL encode %% as %%25, see RFC 6874.\0" as *const u8
                        as *const libc::c_char,
                );
            }
            ptr = ptr.offset(1);
            while *ptr as libc::c_int != 0
                && (Curl_isalpha(*ptr as libc::c_uchar as libc::c_int) != 0
                    || Curl_isxdigit(*ptr as libc::c_uchar as libc::c_int) != 0
                    || *ptr as libc::c_int == '-' as i32
                    || *ptr as libc::c_int == '.' as i32
                    || *ptr as libc::c_int == '_' as i32
                    || *ptr as libc::c_int == '~' as i32)
            {
                ptr = ptr.offset(1);
            }
        }
        if *ptr as libc::c_int == ']' as i32 {
            let fresh173 = ptr;
            ptr = ptr.offset(1);
            *fresh173 = '\u{0}' as i32 as libc::c_char;
        } else {
            Curl_infof(
                data,
                b"Invalid IPv6 address format\0" as *const u8 as *const libc::c_char,
            );
        }
        portptr = ptr;
    }
    host_portno = strchr(portptr, ':' as i32);
    if !host_portno.is_null() {
        let mut endp: *mut libc::c_char = 0 as *mut libc::c_char;
        *host_portno = '\u{0}' as i32 as libc::c_char;
        host_portno = host_portno.offset(1);
        if *host_portno != 0 {
            let mut portparse: libc::c_long = strtol(
                host_portno,
                &mut endp,
                10 as libc::c_int,
            );
            if !endp.is_null() && *endp as libc::c_int != 0
                || portparse < 0 as libc::c_int as libc::c_long
                || portparse > 65535 as libc::c_int as libc::c_long
            {
                Curl_failf(
                    data,
                    b"No valid port number in connect to host string (%s)\0" as *const u8
                        as *const libc::c_char,
                    host_portno,
                );
                result = CURLE_SETOPT_OPTION_SYNTAX;
                current_block = 1356886395307775006;
            } else {
                port = portparse as libc::c_int;
                current_block = 10692455896603418738;
            }
        } else {
            current_block = 10692455896603418738;
        }
    } else {
        current_block = 10692455896603418738;
    }
    match current_block {
        10692455896603418738 => {
            if !hostptr.is_null() {
                *hostname_result = Curl_cstrdup
                    .expect("non-null function pointer")(hostptr);
                if (*hostname_result).is_null() {
                    result = CURLE_OUT_OF_MEMORY;
                    current_block = 1356886395307775006;
                } else {
                    current_block = 572715077006366937;
                }
            } else {
                current_block = 572715077006366937;
            }
            match current_block {
                1356886395307775006 => {}
                _ => {
                    *port_result = port;
                }
            }
        }
        _ => {}
    }
    Curl_cfree.expect("non-null function pointer")(host_dup as *mut libc::c_void);
    return result;
}
unsafe extern "C" fn parse_connect_to_string(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut conn_to_host: *const libc::c_char,
    mut host_result: *mut *mut libc::c_char,
    mut port_result: *mut libc::c_int,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ptr: *const libc::c_char = conn_to_host;
    let mut host_match: libc::c_int = 0 as libc::c_int;
    let mut port_match: libc::c_int = 0 as libc::c_int;
    *host_result = 0 as *mut libc::c_char;
    *port_result = -(1 as libc::c_int);
    if *ptr as libc::c_int == ':' as i32 {
        host_match = 1 as libc::c_int;
        ptr = ptr.offset(1);
    } else {
        let mut hostname_to_match_len: size_t = 0;
        let mut hostname_to_match: *mut libc::c_char = curl_maprintf(
            b"%s%s%s\0" as *const u8 as *const libc::c_char,
            if ((*conn).bits).ipv6_ip() as libc::c_int != 0 {
                b"[\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            (*conn).host.name,
            if ((*conn).bits).ipv6_ip() as libc::c_int != 0 {
                b"]\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
        );
        if hostname_to_match.is_null() {
            return CURLE_OUT_OF_MEMORY;
        }
        hostname_to_match_len = strlen(hostname_to_match);
        host_match = Curl_strncasecompare(ptr, hostname_to_match, hostname_to_match_len);
        Curl_cfree
            .expect("non-null function pointer")(hostname_to_match as *mut libc::c_void);
        ptr = ptr.offset(hostname_to_match_len as isize);
        host_match = (host_match != 0 && *ptr as libc::c_int == ':' as i32)
            as libc::c_int;
        ptr = ptr.offset(1);
    }
    if host_match != 0 {
        if *ptr as libc::c_int == ':' as i32 {
            port_match = 1 as libc::c_int;
            ptr = ptr.offset(1);
        } else {
            let mut ptr_next: *mut libc::c_char = strchr(ptr, ':' as i32);
            if !ptr_next.is_null() {
                let mut endp: *mut libc::c_char = 0 as *mut libc::c_char;
                let mut port_to_match: libc::c_long = strtol(
                    ptr,
                    &mut endp,
                    10 as libc::c_int,
                );
                if endp == ptr_next
                    && port_to_match == (*conn).remote_port as libc::c_long
                {
                    port_match = 1 as libc::c_int;
                    ptr = ptr_next.offset(1 as libc::c_int as isize);
                }
            }
        }
    }
    if host_match != 0 && port_match != 0 {
        result = parse_connect_to_host_port(data, ptr, host_result, port_result);
    }
    return result;
}
unsafe extern "C" fn parse_connect_to_slist(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut conn_to_host: *mut curl_slist,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut port: libc::c_int = -(1 as libc::c_int);
    while !conn_to_host.is_null() && host.is_null() && port == -(1 as libc::c_int) {
        result = parse_connect_to_string(
            data,
            conn,
            (*conn_to_host).data,
            &mut host,
            &mut port,
        );
        if result as u64 != 0 {
            return result;
        }
        if !host.is_null() && *host as libc::c_int != 0 {
            let ref mut fresh174 = (*conn).conn_to_host.rawalloc;
            *fresh174 = host;
            let ref mut fresh175 = (*conn).conn_to_host.name;
            *fresh175 = host;
            let ref mut fresh176 = (*conn).bits;
            (*fresh176).set_conn_to_host(1 as libc::c_int as bit);
            Curl_infof(
                data,
                b"Connecting to hostname: %s\0" as *const u8 as *const libc::c_char,
                host,
            );
        } else {
            let ref mut fresh177 = (*conn).bits;
            (*fresh177).set_conn_to_host(0 as libc::c_int as bit);
            Curl_cfree.expect("non-null function pointer")(host as *mut libc::c_void);
            host = 0 as *mut libc::c_char;
        }
        if port >= 0 as libc::c_int {
            (*conn).conn_to_port = port;
            let ref mut fresh178 = (*conn).bits;
            (*fresh178).set_conn_to_port(1 as libc::c_int as bit);
            Curl_infof(
                data,
                b"Connecting to port: %d\0" as *const u8 as *const libc::c_char,
                port,
            );
        } else {
            let ref mut fresh179 = (*conn).bits;
            (*fresh179).set_conn_to_port(0 as libc::c_int as bit);
            port = -(1 as libc::c_int);
        }
        conn_to_host = (*conn_to_host).next;
    }
    if !((*data).asi).is_null() && host.is_null() && port == -(1 as libc::c_int)
        && ((*(*conn).handler).protocol
            == ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
            || 0 as libc::c_int != 0)
    {
        let mut srcalpnid: alpnid = ALPN_none;
        let mut hit: bool = false;
        let mut as_0: *mut altsvc = 0 as *mut altsvc;
        let allowed_versions: libc::c_int = ((ALPN_h1 as libc::c_int
            | ALPN_h2 as libc::c_int) as libc::c_long & (*(*data).asi).flags)
            as libc::c_int;
        host = (*conn).host.rawalloc;
        srcalpnid = ALPN_h2;
        hit = Curl_altsvc_lookup(
            (*data).asi,
            srcalpnid,
            host,
            (*conn).remote_port,
            &mut as_0,
            allowed_versions,
        );
        if !hit {
            srcalpnid = ALPN_h1;
            hit = Curl_altsvc_lookup(
                (*data).asi,
                srcalpnid,
                host,
                (*conn).remote_port,
                &mut as_0,
                allowed_versions,
            );
        }
        if hit {
            let mut hostd: *mut libc::c_char = Curl_cstrdup
                .expect("non-null function pointer")((*as_0).dst.host);
            if hostd.is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            let ref mut fresh180 = (*conn).conn_to_host.rawalloc;
            *fresh180 = hostd;
            let ref mut fresh181 = (*conn).conn_to_host.name;
            *fresh181 = hostd;
            let ref mut fresh182 = (*conn).bits;
            (*fresh182).set_conn_to_host(1 as libc::c_int as bit);
            (*conn).conn_to_port = (*as_0).dst.port as libc::c_int;
            let ref mut fresh183 = (*conn).bits;
            (*fresh183).set_conn_to_port(1 as libc::c_int as bit);
            let ref mut fresh184 = (*conn).bits;
            (*fresh184).set_altused(1 as libc::c_int as bit);
            Curl_infof(
                data,
                b"Alt-svc connecting from [%s]%s:%d to [%s]%s:%d\0" as *const u8
                    as *const libc::c_char,
                Curl_alpnid2str(srcalpnid),
                host,
                (*conn).remote_port,
                Curl_alpnid2str((*as_0).dst.alpnid),
                hostd,
                (*as_0).dst.port as libc::c_int,
            );
            if srcalpnid as libc::c_uint != (*as_0).dst.alpnid as libc::c_uint {
                match (*as_0).dst.alpnid as libc::c_uint {
                    8 => {
                        (*conn).httpversion = 11 as libc::c_int as libc::c_uchar;
                    }
                    16 => {
                        (*conn).httpversion = 20 as libc::c_int as libc::c_uchar;
                    }
                    32 => {
                        (*conn).transport = TRNSPRT_QUIC;
                        (*conn).httpversion = 30 as libc::c_int as libc::c_uchar;
                    }
                    _ => {}
                }
            }
        }
    }
    return result;
}
unsafe extern "C" fn resolve_server(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut async_0: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut timeout_ms: timediff_t = Curl_timeleft(
        data,
        0 as *mut curltime,
        1 as libc::c_int != 0,
    );
    if ((*conn).bits).reuse() != 0 {
        *async_0 = 0 as libc::c_int != 0;
    } else {
        let mut rc: libc::c_int = 0;
        let mut hostaddr: *mut Curl_dns_entry = 0 as *mut Curl_dns_entry;
        if !((*conn).unix_domain_socket).is_null() {
            let mut path: *const libc::c_char = (*conn).unix_domain_socket;
            hostaddr = Curl_ccalloc
                .expect(
                    "non-null function pointer",
                )(
                1 as libc::c_int as size_t,
                ::std::mem::size_of::<Curl_dns_entry>() as libc::c_ulong,
            ) as *mut Curl_dns_entry;
            if hostaddr.is_null() {
                result = CURLE_OUT_OF_MEMORY;
            } else {
                let mut longpath: bool = 0 as libc::c_int != 0;
                let ref mut fresh185 = (*hostaddr).addr;
                *fresh185 = Curl_unix2addr(
                    path,
                    &mut longpath,
                    ((*conn).bits).abstract_unix_socket() != 0,
                );
                if !((*hostaddr).addr).is_null() {
                    let ref mut fresh186 = (*hostaddr).inuse;
                    *fresh186 += 1;
                } else {
                    if longpath {
                        Curl_failf(
                            data,
                            b"Unix socket path too long: '%s'\0" as *const u8
                                as *const libc::c_char,
                            path,
                        );
                        result = CURLE_COULDNT_RESOLVE_HOST;
                    } else {
                        result = CURLE_OUT_OF_MEMORY;
                    }
                    Curl_cfree
                        .expect(
                            "non-null function pointer",
                        )(hostaddr as *mut libc::c_void);
                    hostaddr = 0 as *mut Curl_dns_entry;
                }
            }
        } else if ((*conn).bits).proxy() == 0 {
            let mut connhost: *mut hostname = 0 as *mut hostname;
            if ((*conn).bits).conn_to_host() != 0 {
                connhost = &mut (*conn).conn_to_host;
            } else {
                connhost = &mut (*conn).host;
            }
            if ((*conn).bits).conn_to_port() != 0 {
                (*conn).port = (*conn).conn_to_port;
            } else {
                (*conn).port = (*conn).remote_port;
            }
            let ref mut fresh187 = (*conn).hostname_resolve;
            *fresh187 = Curl_cstrdup
                .expect("non-null function pointer")((*connhost).name);
            if ((*conn).hostname_resolve).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            rc = Curl_resolv_timeout(
                data,
                (*conn).hostname_resolve,
                (*conn).port,
                &mut hostaddr,
                timeout_ms,
            ) as libc::c_int;
            if rc == CURLRESOLV_PENDING as libc::c_int {
                *async_0 = 1 as libc::c_int != 0;
            } else if rc == CURLRESOLV_TIMEDOUT as libc::c_int {
                Curl_failf(
                    data,
                    b"Failed to resolve host '%s' with timeout after %ld ms\0"
                        as *const u8 as *const libc::c_char,
                    (*connhost).dispname,
                    Curl_timediff(Curl_now(), (*data).progress.t_startsingle),
                );
                result = CURLE_OPERATION_TIMEDOUT;
            } else if hostaddr.is_null() {
                Curl_failf(
                    data,
                    b"Could not resolve host: %s\0" as *const u8 as *const libc::c_char,
                    (*connhost).dispname,
                );
                result = CURLE_COULDNT_RESOLVE_HOST;
            }
        } else {
            let host: *mut hostname = if ((*conn).bits).socksproxy() as libc::c_int != 0
            {
                &mut (*conn).socks_proxy.host
            } else {
                &mut (*conn).http_proxy.host
            };
            let ref mut fresh188 = (*conn).hostname_resolve;
            *fresh188 = Curl_cstrdup.expect("non-null function pointer")((*host).name);
            if ((*conn).hostname_resolve).is_null() {
                return CURLE_OUT_OF_MEMORY;
            }
            rc = Curl_resolv_timeout(
                data,
                (*conn).hostname_resolve,
                (*conn).port,
                &mut hostaddr,
                timeout_ms,
            ) as libc::c_int;
            if rc == CURLRESOLV_PENDING as libc::c_int {
                *async_0 = 1 as libc::c_int != 0;
            } else if rc == CURLRESOLV_TIMEDOUT as libc::c_int {
                result = CURLE_OPERATION_TIMEDOUT;
            } else if hostaddr.is_null() {
                Curl_failf(
                    data,
                    b"Couldn't resolve proxy '%s'\0" as *const u8 as *const libc::c_char,
                    (*host).dispname,
                );
                result = CURLE_COULDNT_RESOLVE_PROXY;
            }
        }
        let ref mut fresh189 = (*conn).dns_entry;
        *fresh189 = hostaddr;
    }
    return result;
}
unsafe extern "C" fn reuse_conn(
    mut data: *mut Curl_easy,
    mut old_conn: *mut connectdata,
    mut conn: *mut connectdata,
) {
    let mut local_ip: [libc::c_char; 46] = *::std::mem::transmute::<
        &[u8; 46],
        &mut [libc::c_char; 46],
    >(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut local_port: libc::c_int = -(1 as libc::c_int);
    Curl_free_idnconverted_hostname(&mut (*old_conn).http_proxy.host);
    Curl_free_idnconverted_hostname(&mut (*old_conn).socks_proxy.host);
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*old_conn).http_proxy.host.rawalloc as *mut libc::c_void);
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*old_conn).socks_proxy.host.rawalloc as *mut libc::c_void);
    Curl_free_primary_ssl_config(&mut (*old_conn).proxy_ssl_config);
    Curl_free_primary_ssl_config(&mut (*old_conn).ssl_config);
    let ref mut fresh190 = (*conn).bits;
    (*fresh190).set_user_passwd(((*old_conn).bits).user_passwd());
    if ((*conn).bits).user_passwd() != 0 {
        Curl_cfree
            .expect("non-null function pointer")((*conn).user as *mut libc::c_void);
        let ref mut fresh191 = (*conn).user;
        *fresh191 = 0 as *mut libc::c_char;
        Curl_cfree
            .expect("non-null function pointer")((*conn).passwd as *mut libc::c_void);
        let ref mut fresh192 = (*conn).passwd;
        *fresh192 = 0 as *mut libc::c_char;
        let ref mut fresh193 = (*conn).user;
        *fresh193 = (*old_conn).user;
        let ref mut fresh194 = (*conn).passwd;
        *fresh194 = (*old_conn).passwd;
        let ref mut fresh195 = (*old_conn).user;
        *fresh195 = 0 as *mut libc::c_char;
        let ref mut fresh196 = (*old_conn).passwd;
        *fresh196 = 0 as *mut libc::c_char;
    }
    let ref mut fresh197 = (*conn).bits;
    (*fresh197).set_proxy_user_passwd(((*old_conn).bits).proxy_user_passwd());
    if ((*conn).bits).proxy_user_passwd() != 0 {
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*conn).http_proxy.user as *mut libc::c_void);
        let ref mut fresh198 = (*conn).http_proxy.user;
        *fresh198 = 0 as *mut libc::c_char;
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*conn).socks_proxy.user as *mut libc::c_void);
        let ref mut fresh199 = (*conn).socks_proxy.user;
        *fresh199 = 0 as *mut libc::c_char;
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*conn).http_proxy.passwd as *mut libc::c_void);
        let ref mut fresh200 = (*conn).http_proxy.passwd;
        *fresh200 = 0 as *mut libc::c_char;
        Curl_cfree
            .expect(
                "non-null function pointer",
            )((*conn).socks_proxy.passwd as *mut libc::c_void);
        let ref mut fresh201 = (*conn).socks_proxy.passwd;
        *fresh201 = 0 as *mut libc::c_char;
        let ref mut fresh202 = (*conn).http_proxy.user;
        *fresh202 = (*old_conn).http_proxy.user;
        let ref mut fresh203 = (*conn).socks_proxy.user;
        *fresh203 = (*old_conn).socks_proxy.user;
        let ref mut fresh204 = (*conn).http_proxy.passwd;
        *fresh204 = (*old_conn).http_proxy.passwd;
        let ref mut fresh205 = (*conn).socks_proxy.passwd;
        *fresh205 = (*old_conn).socks_proxy.passwd;
        let ref mut fresh206 = (*old_conn).http_proxy.user;
        *fresh206 = 0 as *mut libc::c_char;
        let ref mut fresh207 = (*old_conn).socks_proxy.user;
        *fresh207 = 0 as *mut libc::c_char;
        let ref mut fresh208 = (*old_conn).http_proxy.passwd;
        *fresh208 = 0 as *mut libc::c_char;
        let ref mut fresh209 = (*old_conn).socks_proxy.passwd;
        *fresh209 = 0 as *mut libc::c_char;
    }
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*old_conn).http_proxy.user as *mut libc::c_void);
    let ref mut fresh210 = (*old_conn).http_proxy.user;
    *fresh210 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*old_conn).socks_proxy.user as *mut libc::c_void);
    let ref mut fresh211 = (*old_conn).socks_proxy.user;
    *fresh211 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*old_conn).http_proxy.passwd as *mut libc::c_void);
    let ref mut fresh212 = (*old_conn).http_proxy.passwd;
    *fresh212 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*old_conn).socks_proxy.passwd as *mut libc::c_void);
    let ref mut fresh213 = (*old_conn).socks_proxy.passwd;
    *fresh213 = 0 as *mut libc::c_char;
    Curl_free_idnconverted_hostname(&mut (*conn).host);
    Curl_free_idnconverted_hostname(&mut (*conn).conn_to_host);
    Curl_cfree
        .expect("non-null function pointer")((*conn).host.rawalloc as *mut libc::c_void);
    let ref mut fresh214 = (*conn).host.rawalloc;
    *fresh214 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).conn_to_host.rawalloc as *mut libc::c_void);
    let ref mut fresh215 = (*conn).conn_to_host.rawalloc;
    *fresh215 = 0 as *mut libc::c_char;
    (*conn).host = (*old_conn).host;
    (*conn).conn_to_host = (*old_conn).conn_to_host;
    (*conn).conn_to_port = (*old_conn).conn_to_port;
    (*conn).remote_port = (*old_conn).remote_port;
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*conn).hostname_resolve as *mut libc::c_void);
    let ref mut fresh216 = (*conn).hostname_resolve;
    *fresh216 = 0 as *mut libc::c_char;
    let ref mut fresh217 = (*conn).hostname_resolve;
    *fresh217 = (*old_conn).hostname_resolve;
    let ref mut fresh218 = (*old_conn).hostname_resolve;
    *fresh218 = 0 as *mut libc::c_char;
    if (*conn).transport as libc::c_uint == TRNSPRT_TCP as libc::c_int as libc::c_uint {
        Curl_conninfo_local(
            data,
            (*conn).sock[0 as libc::c_int as usize],
            local_ip.as_mut_ptr(),
            &mut local_port,
        );
    }
    Curl_persistconninfo(data, conn, local_ip.as_mut_ptr(), local_port);
    let ref mut fresh219 = (*conn).bits;
    (*fresh219).set_reuse(1 as libc::c_int as bit);
    Curl_cfree
        .expect("non-null function pointer")((*old_conn).user as *mut libc::c_void);
    let ref mut fresh220 = (*old_conn).user;
    *fresh220 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect("non-null function pointer")((*old_conn).passwd as *mut libc::c_void);
    let ref mut fresh221 = (*old_conn).passwd;
    *fresh221 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect("non-null function pointer")((*old_conn).options as *mut libc::c_void);
    let ref mut fresh222 = (*old_conn).options;
    *fresh222 = 0 as *mut libc::c_char;
    Curl_cfree
        .expect("non-null function pointer")((*old_conn).localdev as *mut libc::c_void);
    let ref mut fresh223 = (*old_conn).localdev;
    *fresh223 = 0 as *mut libc::c_char;
    Curl_llist_destroy(&mut (*old_conn).easyq, 0 as *mut libc::c_void);
    Curl_cfree
        .expect(
            "non-null function pointer",
        )((*old_conn).unix_domain_socket as *mut libc::c_void);
    let ref mut fresh224 = (*old_conn).unix_domain_socket;
    *fresh224 = 0 as *mut libc::c_char;
}
unsafe extern "C" fn create_conn(
    mut data: *mut Curl_easy,
    mut in_connect: *mut *mut connectdata,
    mut async_0: *mut bool,
) -> CURLcode {
    let mut current_block: u64;
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = 0 as *mut connectdata;
    let mut conn_temp: *mut connectdata = 0 as *mut connectdata;
    let mut reuse: bool = false;
    let mut connections_available: bool = 1 as libc::c_int != 0;
    let mut force_reuse: bool = 0 as libc::c_int != 0;
    let mut waitpipe: bool = 0 as libc::c_int != 0;
    let mut max_host_connections: size_t = Curl_multi_max_host_connections(
        (*data).multi,
    );
    let mut max_total_connections: size_t = Curl_multi_max_total_connections(
        (*data).multi,
    );
    *async_0 = 0 as libc::c_int != 0;
    *in_connect = 0 as *mut connectdata;
    if ((*data).state.url).is_null() {
        result = CURLE_URL_MALFORMAT;
    } else {
        conn = allocate_conn(data);
        if conn.is_null() {
            result = CURLE_OUT_OF_MEMORY;
        } else {
            *in_connect = conn;
            result = parseurlandfillconn(data, conn);
            if !(result as u64 != 0) {
                if !((*data).set.str_0[STRING_SASL_AUTHZID as libc::c_int as usize])
                    .is_null()
                {
                    let ref mut fresh225 = (*conn).sasl_authzid;
                    *fresh225 = Curl_cstrdup
                        .expect(
                            "non-null function pointer",
                        )(
                        (*data).set.str_0[STRING_SASL_AUTHZID as libc::c_int as usize],
                    );
                    if ((*conn).sasl_authzid).is_null() {
                        result = CURLE_OUT_OF_MEMORY;
                        current_block = 4631372686411729056;
                    } else {
                        current_block = 11584701595673473500;
                    }
                } else {
                    current_block = 11584701595673473500;
                }
                match current_block {
                    4631372686411729056 => {}
                    _ => {
                        if !((*data)
                            .set
                            .str_0[STRING_UNIX_SOCKET_PATH as libc::c_int as usize])
                            .is_null()
                        {
                            let ref mut fresh226 = (*conn).unix_domain_socket;
                            *fresh226 = Curl_cstrdup
                                .expect(
                                    "non-null function pointer",
                                )(
                                (*data)
                                    .set
                                    .str_0[STRING_UNIX_SOCKET_PATH as libc::c_int as usize],
                            );
                            if ((*conn).unix_domain_socket).is_null() {
                                result = CURLE_OUT_OF_MEMORY;
                                current_block = 4631372686411729056;
                            } else {
                                let ref mut fresh227 = (*conn).bits;
                                (*fresh227)
                                    .set_abstract_unix_socket(
                                        ((*data).set).abstract_unix_socket(),
                                    );
                                current_block = 4068382217303356765;
                            }
                        } else {
                            current_block = 4068382217303356765;
                        }
                        match current_block {
                            4631372686411729056 => {}
                            _ => {
                                result = create_conn_helper_init_proxy(data, conn);
                                if !(result as u64 != 0) {
                                    if (*(*conn).given).flags
                                        & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint
                                        != 0 && ((*conn).bits).httpproxy() as libc::c_int != 0
                                    {
                                        let ref mut fresh228 = (*conn).bits;
                                        (*fresh228).set_tunnel_proxy(1 as libc::c_int as bit);
                                    }
                                    result = parse_remote_port(data, conn);
                                    if !(result as u64 != 0) {
                                        result = override_login(data, conn);
                                        if !(result as u64 != 0) {
                                            result = set_login(conn);
                                            if !(result as u64 != 0) {
                                                result = parse_connect_to_slist(
                                                    data,
                                                    conn,
                                                    (*data).set.connect_to,
                                                );
                                                if !(result as u64 != 0) {
                                                    result = Curl_idnconvert_hostname(data, &mut (*conn).host);
                                                    if !(result as u64 != 0) {
                                                        if ((*conn).bits).conn_to_host() != 0 {
                                                            result = Curl_idnconvert_hostname(
                                                                data,
                                                                &mut (*conn).conn_to_host,
                                                            );
                                                            if result as u64 != 0 {
                                                                current_block = 4631372686411729056;
                                                            } else {
                                                                current_block = 721385680381463314;
                                                            }
                                                        } else {
                                                            current_block = 721385680381463314;
                                                        }
                                                        match current_block {
                                                            4631372686411729056 => {}
                                                            _ => {
                                                                if ((*conn).bits).httpproxy() != 0 {
                                                                    result = Curl_idnconvert_hostname(
                                                                        data,
                                                                        &mut (*conn).http_proxy.host,
                                                                    );
                                                                    if result as u64 != 0 {
                                                                        current_block = 4631372686411729056;
                                                                    } else {
                                                                        current_block = 14775119014532381840;
                                                                    }
                                                                } else {
                                                                    current_block = 14775119014532381840;
                                                                }
                                                                match current_block {
                                                                    4631372686411729056 => {}
                                                                    _ => {
                                                                        if ((*conn).bits).socksproxy() != 0 {
                                                                            result = Curl_idnconvert_hostname(
                                                                                data,
                                                                                &mut (*conn).socks_proxy.host,
                                                                            );
                                                                            if result as u64 != 0 {
                                                                                current_block = 4631372686411729056;
                                                                            } else {
                                                                                current_block = 5141539773904409130;
                                                                            }
                                                                        } else {
                                                                            current_block = 5141539773904409130;
                                                                        }
                                                                        match current_block {
                                                                            4631372686411729056 => {}
                                                                            _ => {
                                                                                if ((*conn).bits).conn_to_host() as libc::c_int != 0
                                                                                    && Curl_strcasecompare(
                                                                                        (*conn).conn_to_host.name,
                                                                                        (*conn).host.name,
                                                                                    ) != 0
                                                                                {
                                                                                    let ref mut fresh229 = (*conn).bits;
                                                                                    (*fresh229).set_conn_to_host(0 as libc::c_int as bit);
                                                                                }
                                                                                if ((*conn).bits).conn_to_port() as libc::c_int != 0
                                                                                    && (*conn).conn_to_port == (*conn).remote_port
                                                                                {
                                                                                    let ref mut fresh230 = (*conn).bits;
                                                                                    (*fresh230).set_conn_to_port(0 as libc::c_int as bit);
                                                                                }
                                                                                if (((*conn).bits).conn_to_host() as libc::c_int != 0
                                                                                    || ((*conn).bits).conn_to_port() as libc::c_int != 0)
                                                                                    && ((*conn).bits).httpproxy() as libc::c_int != 0
                                                                                {
                                                                                    let ref mut fresh231 = (*conn).bits;
                                                                                    (*fresh231).set_tunnel_proxy(1 as libc::c_int as bit);
                                                                                }
                                                                                result = setup_connection_internals(data, conn);
                                                                                if !(result as u64 != 0) {
                                                                                    let ref mut fresh232 = (*conn)
                                                                                        .recv[0 as libc::c_int as usize];
                                                                                    *fresh232 = Some(
                                                                                        Curl_recv_plain
                                                                                            as unsafe extern "C" fn(
                                                                                                *mut Curl_easy,
                                                                                                libc::c_int,
                                                                                                *mut libc::c_char,
                                                                                                size_t,
                                                                                                *mut CURLcode,
                                                                                            ) -> ssize_t,
                                                                                    );
                                                                                    let ref mut fresh233 = (*conn)
                                                                                        .send[0 as libc::c_int as usize];
                                                                                    *fresh233 = Some(
                                                                                        Curl_send_plain
                                                                                            as unsafe extern "C" fn(
                                                                                                *mut Curl_easy,
                                                                                                libc::c_int,
                                                                                                *const libc::c_void,
                                                                                                size_t,
                                                                                                *mut CURLcode,
                                                                                            ) -> ssize_t,
                                                                                    );
                                                                                    let ref mut fresh234 = (*conn)
                                                                                        .recv[1 as libc::c_int as usize];
                                                                                    *fresh234 = Some(
                                                                                        Curl_recv_plain
                                                                                            as unsafe extern "C" fn(
                                                                                                *mut Curl_easy,
                                                                                                libc::c_int,
                                                                                                *mut libc::c_char,
                                                                                                size_t,
                                                                                                *mut CURLcode,
                                                                                            ) -> ssize_t,
                                                                                    );
                                                                                    let ref mut fresh235 = (*conn)
                                                                                        .send[1 as libc::c_int as usize];
                                                                                    *fresh235 = Some(
                                                                                        Curl_send_plain
                                                                                            as unsafe extern "C" fn(
                                                                                                *mut Curl_easy,
                                                                                                libc::c_int,
                                                                                                *const libc::c_void,
                                                                                                size_t,
                                                                                                *mut CURLcode,
                                                                                            ) -> ssize_t,
                                                                                    );
                                                                                    let ref mut fresh236 = (*conn).bits;
                                                                                    (*fresh236).set_tcp_fastopen(((*data).set).tcp_fastopen());
                                                                                    if (*(*conn).handler).flags
                                                                                        & ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uint
                                                                                        != 0
                                                                                    {
                                                                                        let mut done: bool = false;
                                                                                        Curl_persistconninfo(
                                                                                            data,
                                                                                            conn,
                                                                                            0 as *mut libc::c_char,
                                                                                            -(1 as libc::c_int),
                                                                                        );
                                                                                        result = ((*(*conn).handler).connect_it)
                                                                                            .expect("non-null function pointer")(data, &mut done);
                                                                                        if result as u64 == 0 {
                                                                                            (*conn)
                                                                                                .bits
                                                                                                .tcpconnect[0 as libc::c_int
                                                                                                as usize] = 1 as libc::c_int != 0;
                                                                                            Curl_attach_connnection(data, conn);
                                                                                            result = Curl_conncache_add_conn(data);
                                                                                            if result as u64 != 0 {
                                                                                                current_block = 4631372686411729056;
                                                                                            } else {
                                                                                                result = setup_range(data);
                                                                                                if result as u64 != 0 {
                                                                                                    ((*(*conn).handler).done)
                                                                                                        .expect(
                                                                                                            "non-null function pointer",
                                                                                                        )(data, result, 0 as libc::c_int != 0);
                                                                                                    current_block = 4631372686411729056;
                                                                                                } else {
                                                                                                    Curl_setup_transfer(
                                                                                                        data,
                                                                                                        -(1 as libc::c_int),
                                                                                                        -(1 as libc::c_int) as curl_off_t,
                                                                                                        0 as libc::c_int != 0,
                                                                                                        -(1 as libc::c_int),
                                                                                                    );
                                                                                                    current_block = 17019156190352891614;
                                                                                                }
                                                                                            }
                                                                                        } else {
                                                                                            current_block = 17019156190352891614;
                                                                                        }
                                                                                        match current_block {
                                                                                            4631372686411729056 => {}
                                                                                            _ => {
                                                                                                Curl_init_do(data, conn);
                                                                                            }
                                                                                        }
                                                                                    } else {
                                                                                        let ref mut fresh237 = (*data).set.ssl.primary.CApath;
                                                                                        *fresh237 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CAPATH as libc::c_int as usize];
                                                                                        let ref mut fresh238 = (*data).set.ssl.primary.CAfile;
                                                                                        *fresh238 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CAFILE as libc::c_int as usize];
                                                                                        let ref mut fresh239 = (*data).set.ssl.primary.issuercert;
                                                                                        *fresh239 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_ISSUERCERT as libc::c_int as usize];
                                                                                        let ref mut fresh240 = (*data)
                                                                                            .set
                                                                                            .ssl
                                                                                            .primary
                                                                                            .issuercert_blob;
                                                                                        *fresh240 = (*data)
                                                                                            .set
                                                                                            .blobs[BLOB_SSL_ISSUERCERT as libc::c_int as usize];
                                                                                        let ref mut fresh241 = (*data).set.ssl.primary.random_file;
                                                                                        *fresh241 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_RANDOM_FILE as libc::c_int as usize];
                                                                                        let ref mut fresh242 = (*data).set.ssl.primary.egdsocket;
                                                                                        *fresh242 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_EGDSOCKET as libc::c_int as usize];
                                                                                        let ref mut fresh243 = (*data).set.ssl.primary.cipher_list;
                                                                                        *fresh243 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CIPHER_LIST as libc::c_int as usize];
                                                                                        let ref mut fresh244 = (*data)
                                                                                            .set
                                                                                            .ssl
                                                                                            .primary
                                                                                            .cipher_list13;
                                                                                        *fresh244 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CIPHER13_LIST as libc::c_int as usize];
                                                                                        let ref mut fresh245 = (*data).set.ssl.primary.pinned_key;
                                                                                        *fresh245 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_PINNEDPUBLICKEY as libc::c_int as usize];
                                                                                        let ref mut fresh246 = (*data).set.ssl.primary.cert_blob;
                                                                                        *fresh246 = (*data)
                                                                                            .set
                                                                                            .blobs[BLOB_CERT as libc::c_int as usize];
                                                                                        let ref mut fresh247 = (*data).set.ssl.primary.ca_info_blob;
                                                                                        *fresh247 = (*data)
                                                                                            .set
                                                                                            .blobs[BLOB_CAINFO as libc::c_int as usize];
                                                                                        let ref mut fresh248 = (*data).set.ssl.primary.curves;
                                                                                        *fresh248 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_EC_CURVES as libc::c_int as usize];
                                                                                        let ref mut fresh249 = (*data).set.proxy_ssl.primary.CApath;
                                                                                        *fresh249 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CAPATH_PROXY as libc::c_int as usize];
                                                                                        let ref mut fresh250 = (*data).set.proxy_ssl.primary.CAfile;
                                                                                        *fresh250 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CAFILE_PROXY as libc::c_int as usize];
                                                                                        let ref mut fresh251 = (*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .random_file;
                                                                                        *fresh251 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_RANDOM_FILE as libc::c_int as usize];
                                                                                        let ref mut fresh252 = (*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .egdsocket;
                                                                                        *fresh252 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_EGDSOCKET as libc::c_int as usize];
                                                                                        let ref mut fresh253 = (*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .cipher_list;
                                                                                        *fresh253 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CIPHER_LIST_PROXY as libc::c_int
                                                                                            as usize];
                                                                                        let ref mut fresh254 = (*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .cipher_list13;
                                                                                        *fresh254 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CIPHER13_LIST_PROXY as libc::c_int
                                                                                            as usize];
                                                                                        let ref mut fresh255 = (*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .pinned_key;
                                                                                        *fresh255 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_PINNEDPUBLICKEY_PROXY as libc::c_int
                                                                                            as usize];
                                                                                        let ref mut fresh256 = (*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .cert_blob;
                                                                                        *fresh256 = (*data)
                                                                                            .set
                                                                                            .blobs[BLOB_CERT_PROXY as libc::c_int as usize];
                                                                                        let ref mut fresh257 = (*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .ca_info_blob;
                                                                                        *fresh257 = (*data)
                                                                                            .set
                                                                                            .blobs[BLOB_CAINFO_PROXY as libc::c_int as usize];
                                                                                        let ref mut fresh258 = (*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .issuercert;
                                                                                        *fresh258 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_ISSUERCERT_PROXY as libc::c_int as usize];
                                                                                        let ref mut fresh259 = (*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .issuercert_blob;
                                                                                        *fresh259 = (*data)
                                                                                            .set
                                                                                            .blobs[BLOB_SSL_ISSUERCERT_PROXY as libc::c_int as usize];
                                                                                        let ref mut fresh260 = (*data).set.proxy_ssl.CRLfile;
                                                                                        *fresh260 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CRLFILE_PROXY as libc::c_int as usize];
                                                                                        let ref mut fresh261 = (*data).set.proxy_ssl.cert_type;
                                                                                        *fresh261 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_CERT_TYPE_PROXY as libc::c_int as usize];
                                                                                        let ref mut fresh262 = (*data).set.proxy_ssl.key;
                                                                                        *fresh262 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_KEY_PROXY as libc::c_int as usize];
                                                                                        let ref mut fresh263 = (*data).set.proxy_ssl.key_type;
                                                                                        *fresh263 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_KEY_TYPE_PROXY as libc::c_int as usize];
                                                                                        let ref mut fresh264 = (*data).set.proxy_ssl.key_passwd;
                                                                                        *fresh264 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_KEY_PASSWD_PROXY as libc::c_int as usize];
                                                                                        let ref mut fresh265 = (*data)
                                                                                            .set
                                                                                            .proxy_ssl
                                                                                            .primary
                                                                                            .clientcert;
                                                                                        *fresh265 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_CERT_PROXY as libc::c_int as usize];
                                                                                        let ref mut fresh266 = (*data).set.proxy_ssl.key_blob;
                                                                                        *fresh266 = (*data)
                                                                                            .set
                                                                                            .blobs[BLOB_KEY_PROXY as libc::c_int as usize];
                                                                                        let ref mut fresh267 = (*data).set.ssl.CRLfile;
                                                                                        *fresh267 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_SSL_CRLFILE as libc::c_int as usize];
                                                                                        let ref mut fresh268 = (*data).set.ssl.cert_type;
                                                                                        *fresh268 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_CERT_TYPE as libc::c_int as usize];
                                                                                        let ref mut fresh269 = (*data).set.ssl.key;
                                                                                        *fresh269 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_KEY as libc::c_int as usize];
                                                                                        let ref mut fresh270 = (*data).set.ssl.key_type;
                                                                                        *fresh270 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_KEY_TYPE as libc::c_int as usize];
                                                                                        let ref mut fresh271 = (*data).set.ssl.key_passwd;
                                                                                        *fresh271 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_KEY_PASSWD as libc::c_int as usize];
                                                                                        let ref mut fresh272 = (*data).set.ssl.primary.clientcert;
                                                                                        *fresh272 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_CERT as libc::c_int as usize];
                                                                                        let ref mut fresh273 = (*data).set.ssl.username;
                                                                                        *fresh273 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_TLSAUTH_USERNAME as libc::c_int as usize];
                                                                                        let ref mut fresh274 = (*data).set.ssl.password;
                                                                                        *fresh274 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_TLSAUTH_PASSWORD as libc::c_int as usize];
                                                                                        let ref mut fresh275 = (*data).set.proxy_ssl.username;
                                                                                        *fresh275 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_TLSAUTH_USERNAME_PROXY as libc::c_int
                                                                                            as usize];
                                                                                        let ref mut fresh276 = (*data).set.proxy_ssl.password;
                                                                                        *fresh276 = (*data)
                                                                                            .set
                                                                                            .str_0[STRING_TLSAUTH_PASSWORD_PROXY as libc::c_int
                                                                                            as usize];
                                                                                        let ref mut fresh277 = (*data).set.ssl.key_blob;
                                                                                        *fresh277 = (*data)
                                                                                            .set
                                                                                            .blobs[BLOB_KEY as libc::c_int as usize];
                                                                                        if !Curl_clone_primary_ssl_config(
                                                                                            &mut (*data).set.ssl.primary,
                                                                                            &mut (*conn).ssl_config,
                                                                                        ) {
                                                                                            result = CURLE_OUT_OF_MEMORY;
                                                                                        } else if !Curl_clone_primary_ssl_config(
                                                                                                &mut (*data).set.proxy_ssl.primary,
                                                                                                &mut (*conn).proxy_ssl_config,
                                                                                            ) {
                                                                                            result = CURLE_OUT_OF_MEMORY;
                                                                                        } else {
                                                                                            prune_dead_connections(data);
                                                                                            if ((*data).set).reuse_fresh() as libc::c_int != 0
                                                                                                && ((*data).state).this_is_a_follow() == 0
                                                                                                || ((*data).set).connect_only() as libc::c_int != 0
                                                                                            {
                                                                                                reuse = 0 as libc::c_int != 0;
                                                                                            } else {
                                                                                                reuse = ConnectionExists(
                                                                                                    data,
                                                                                                    conn,
                                                                                                    &mut conn_temp,
                                                                                                    &mut force_reuse,
                                                                                                    &mut waitpipe,
                                                                                                );
                                                                                            }
                                                                                            if reuse {
                                                                                                reuse_conn(data, conn, conn_temp);
                                                                                                Curl_cfree
                                                                                                    .expect("non-null function pointer")((*conn).ssl_extra);
                                                                                                Curl_cfree
                                                                                                    .expect(
                                                                                                        "non-null function pointer",
                                                                                                    )(conn as *mut libc::c_void);
                                                                                                conn = conn_temp;
                                                                                                *in_connect = conn;
                                                                                                Curl_infof(
                                                                                                    data,
                                                                                                    b"Re-using existing connection! (#%ld) with %s %s\0"
                                                                                                        as *const u8 as *const libc::c_char,
                                                                                                    (*conn).connection_id,
                                                                                                    if ((*conn).bits).proxy() as libc::c_int != 0 {
                                                                                                        b"proxy\0" as *const u8 as *const libc::c_char
                                                                                                    } else {
                                                                                                        b"host\0" as *const u8 as *const libc::c_char
                                                                                                    },
                                                                                                    if !((*conn).socks_proxy.host.name).is_null() {
                                                                                                        (*conn).socks_proxy.host.dispname
                                                                                                    } else if !((*conn).http_proxy.host.name).is_null() {
                                                                                                        (*conn).http_proxy.host.dispname
                                                                                                    } else {
                                                                                                        (*conn).host.dispname
                                                                                                    },
                                                                                                );
                                                                                                current_block = 2182835884935087477;
                                                                                            } else {
                                                                                                if (*(*conn).handler).flags
                                                                                                    & ((1 as libc::c_int) << 8 as libc::c_int) as libc::c_uint
                                                                                                    != 0
                                                                                                {
                                                                                                    if ((*data).set).ssl_enable_alpn() != 0 {
                                                                                                        let ref mut fresh278 = (*conn).bits;
                                                                                                        (*fresh278).set_tls_enable_alpn(1 as libc::c_int as bit);
                                                                                                    }
                                                                                                    if ((*data).set).ssl_enable_npn() != 0 {
                                                                                                        let ref mut fresh279 = (*conn).bits;
                                                                                                        (*fresh279).set_tls_enable_npn(1 as libc::c_int as bit);
                                                                                                    }
                                                                                                }
                                                                                                if waitpipe {
                                                                                                    connections_available = 0 as libc::c_int != 0;
                                                                                                } else {
                                                                                                    let mut bundlehost: *const libc::c_char = 0
                                                                                                        as *const libc::c_char;
                                                                                                    let mut bundle: *mut connectbundle = Curl_conncache_find_bundle(
                                                                                                        data,
                                                                                                        conn,
                                                                                                        (*data).state.conn_cache,
                                                                                                        &mut bundlehost,
                                                                                                    );
                                                                                                    if max_host_connections > 0 as libc::c_int as libc::c_ulong
                                                                                                        && !bundle.is_null()
                                                                                                        && (*bundle).num_connections >= max_host_connections
                                                                                                    {
                                                                                                        let mut conn_candidate: *mut connectdata = 0
                                                                                                            as *mut connectdata;
                                                                                                        conn_candidate = Curl_conncache_extract_bundle(
                                                                                                            data,
                                                                                                            bundle,
                                                                                                        );
                                                                                                        if !((*data).share).is_null() {
                                                                                                            Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
                                                                                                        }
                                                                                                        if !conn_candidate.is_null() {
                                                                                                            Curl_disconnect(
                                                                                                                data,
                                                                                                                conn_candidate,
                                                                                                                0 as libc::c_int != 0,
                                                                                                            );
                                                                                                        } else {
                                                                                                            Curl_infof(
                                                                                                                data,
                                                                                                                b"No more connections allowed to host %s: %zu\0"
                                                                                                                    as *const u8 as *const libc::c_char,
                                                                                                                bundlehost,
                                                                                                                max_host_connections,
                                                                                                            );
                                                                                                            connections_available = 0 as libc::c_int != 0;
                                                                                                        }
                                                                                                    } else if !((*data).share).is_null() {
                                                                                                        Curl_share_unlock(data, CURL_LOCK_DATA_CONNECT);
                                                                                                    }
                                                                                                }
                                                                                                if connections_available as libc::c_int != 0
                                                                                                    && max_total_connections > 0 as libc::c_int as libc::c_ulong
                                                                                                    && Curl_conncache_size(data) >= max_total_connections
                                                                                                {
                                                                                                    let mut conn_candidate_0: *mut connectdata = 0
                                                                                                        as *mut connectdata;
                                                                                                    conn_candidate_0 = Curl_conncache_extract_oldest(data);
                                                                                                    if !conn_candidate_0.is_null() {
                                                                                                        Curl_disconnect(
                                                                                                            data,
                                                                                                            conn_candidate_0,
                                                                                                            0 as libc::c_int != 0,
                                                                                                        );
                                                                                                    } else {
                                                                                                        Curl_infof(
                                                                                                            data,
                                                                                                            b"No connections available in cache\0" as *const u8
                                                                                                                as *const libc::c_char,
                                                                                                        );
                                                                                                        connections_available = 0 as libc::c_int != 0;
                                                                                                    }
                                                                                                }
                                                                                                if !connections_available {
                                                                                                    Curl_infof(
                                                                                                        data,
                                                                                                        b"No connections available.\0" as *const u8
                                                                                                            as *const libc::c_char,
                                                                                                    );
                                                                                                    conn_free(conn);
                                                                                                    *in_connect = 0 as *mut connectdata;
                                                                                                    result = CURLE_NO_CONNECTION_AVAILABLE;
                                                                                                    current_block = 4631372686411729056;
                                                                                                } else {
                                                                                                    Curl_attach_connnection(data, conn);
                                                                                                    result = Curl_conncache_add_conn(data);
                                                                                                    if result as u64 != 0 {
                                                                                                        current_block = 4631372686411729056;
                                                                                                    } else {
                                                                                                        if (*data).state.authhost.picked
                                                                                                            & ((1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int
                                                                                                                | (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int)
                                                                                                            != 0 && ((*data).state.authhost).done() as libc::c_int != 0
                                                                                                        {
                                                                                                            Curl_infof(
                                                                                                                data,
                                                                                                                b"NTLM picked AND auth done set, clear picked!\0"
                                                                                                                    as *const u8 as *const libc::c_char,
                                                                                                            );
                                                                                                            (*data)
                                                                                                                .state
                                                                                                                .authhost
                                                                                                                .picked = 0 as libc::c_int as libc::c_ulong;
                                                                                                            let ref mut fresh280 = (*data).state.authhost;
                                                                                                            (*fresh280).set_done(0 as libc::c_int as bit);
                                                                                                        }
                                                                                                        if (*data).state.authproxy.picked
                                                                                                            & ((1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int
                                                                                                                | (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int)
                                                                                                            != 0 && ((*data).state.authproxy).done() as libc::c_int != 0
                                                                                                        {
                                                                                                            Curl_infof(
                                                                                                                data,
                                                                                                                b"NTLM-proxy picked AND auth done set, clear picked!\0"
                                                                                                                    as *const u8 as *const libc::c_char,
                                                                                                            );
                                                                                                            (*data)
                                                                                                                .state
                                                                                                                .authproxy
                                                                                                                .picked = 0 as libc::c_int as libc::c_ulong;
                                                                                                            let ref mut fresh281 = (*data).state.authproxy;
                                                                                                            (*fresh281).set_done(0 as libc::c_int as bit);
                                                                                                        }
                                                                                                        current_block = 2182835884935087477;
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                            match current_block {
                                                                                                4631372686411729056 => {}
                                                                                                _ => {
                                                                                                    Curl_init_do(data, conn);
                                                                                                    result = setup_range(data);
                                                                                                    if !(result as u64 != 0) {
                                                                                                        let ref mut fresh282 = (*conn).seek_func;
                                                                                                        *fresh282 = (*data).set.seek_func;
                                                                                                        let ref mut fresh283 = (*conn).seek_client;
                                                                                                        *fresh283 = (*data).set.seek_client;
                                                                                                        result = resolve_server(data, conn, async_0);
                                                                                                        strip_trailing_dot(&mut (*conn).host);
                                                                                                        if ((*conn).bits).httpproxy() != 0 {
                                                                                                            strip_trailing_dot(&mut (*conn).http_proxy.host);
                                                                                                        }
                                                                                                        if ((*conn).bits).socksproxy() != 0 {
                                                                                                            strip_trailing_dot(&mut (*conn).socks_proxy.host);
                                                                                                        }
                                                                                                        if ((*conn).bits).conn_to_host() != 0 {
                                                                                                            strip_trailing_dot(&mut (*conn).conn_to_host);
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
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_setup_conn(
    mut data: *mut Curl_easy,
    mut protocol_done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = (*data).conn;
    Curl_pgrsTime(data, TIMER_NAMELOOKUP);
    if (*(*conn).handler).flags
        & ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uint != 0
    {
        *protocol_done = 1 as libc::c_int != 0;
        return result;
    }
    *protocol_done = 0 as libc::c_int != 0;
    let ref mut fresh284 = (*conn).bits;
    (*fresh284).set_proxy_connect_closed(0 as libc::c_int as bit);
    (*data).state.crlf_conversions = 0 as libc::c_int as curl_off_t;
    (*conn).now = Curl_now();
    if -(1 as libc::c_int) == (*conn).sock[0 as libc::c_int as usize] {
        (*conn).bits.tcpconnect[0 as libc::c_int as usize] = 0 as libc::c_int != 0;
        result = Curl_connecthost(data, conn, (*conn).dns_entry);
        if result as u64 != 0 {
            return result;
        }
    } else {
        Curl_pgrsTime(data, TIMER_CONNECT);
        if ((*conn).ssl[0 as libc::c_int as usize]).use_0() as libc::c_int != 0
            || (*(*conn).handler).protocol
                & ((1 as libc::c_int) << 4 as libc::c_int
                    | (1 as libc::c_int) << 5 as libc::c_int) as libc::c_uint != 0
        {
            Curl_pgrsTime(data, TIMER_APPCONNECT);
        }
        (*conn).bits.tcpconnect[0 as libc::c_int as usize] = 1 as libc::c_int != 0;
        *protocol_done = 1 as libc::c_int != 0;
        Curl_updateconninfo(data, conn, (*conn).sock[0 as libc::c_int as usize]);
        Curl_verboseconnect(data, conn);
    }
    (*conn).now = Curl_now();
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_connect(
    mut data: *mut Curl_easy,
    mut asyncp: *mut bool,
    mut protocol_done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut conn: *mut connectdata = 0 as *mut connectdata;
    *asyncp = 0 as libc::c_int != 0;
    Curl_free_request_state(data);
    memset(
        &mut (*data).req as *mut SingleRequest as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<SingleRequest>() as libc::c_ulong,
    );
    (*data).req.maxdownload = -(1 as libc::c_int) as curl_off_t;
    result = create_conn(data, &mut conn, asyncp);
    if result as u64 == 0 {
        if (*conn).easyq.size > 1 as libc::c_int as libc::c_ulong {
            *protocol_done = 1 as libc::c_int != 0;
        } else if !*asyncp {
            result = Curl_setup_conn(data, protocol_done);
        }
    }
    if result as libc::c_uint
        == CURLE_NO_CONNECTION_AVAILABLE as libc::c_int as libc::c_uint
    {
        return result
    } else {
        if result as libc::c_uint != 0 && !conn.is_null() {
            Curl_detach_connnection(data);
            Curl_conncache_remove_conn(data, conn, 1 as libc::c_int != 0);
            Curl_disconnect(data, conn, 1 as libc::c_int != 0);
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_init_do(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut k: *mut SingleRequest = &mut (*data).req;
    let mut result: CURLcode = Curl_preconnect(data);
    if result as u64 != 0 {
        return result;
    }
    if !conn.is_null() {
        let ref mut fresh285 = (*conn).bits;
        (*fresh285).set_do_more(0 as libc::c_int as bit);
        if ((*data).state).wildcardmatch() as libc::c_int != 0
            && (*(*conn).handler).flags
                & ((1 as libc::c_int) << 12 as libc::c_int) as libc::c_uint == 0
        {
            let ref mut fresh286 = (*data).state;
            (*fresh286).set_wildcardmatch(0 as libc::c_int as bit);
        }
    }
    let ref mut fresh287 = (*data).state;
    (*fresh287).set_done(0 as libc::c_int as bit);
    let ref mut fresh288 = (*data).state;
    (*fresh288).set_expect100header(0 as libc::c_int as bit);
    if ((*data).set).opt_no_body() != 0 {
        (*data).state.httpreq = HTTPREQ_HEAD;
    }
    (*k).start = Curl_now();
    (*k).now = (*k).start;
    (*k).set_header(1 as libc::c_int as bit);
    (*k).bytecount = 0 as libc::c_int as curl_off_t;
    (*k).set_ignorebody(0 as libc::c_int as bit);
    Curl_speedinit(data);
    Curl_pgrsSetUploadCounter(data, 0 as libc::c_int as curl_off_t);
    Curl_pgrsSetDownloadCounter(data, 0 as libc::c_int as curl_off_t);
    return CURLE_OK;
}
