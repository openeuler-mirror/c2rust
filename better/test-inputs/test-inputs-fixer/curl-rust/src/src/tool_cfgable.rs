use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type curl_mime;
    fn curl_mime_free(mime: *mut curl_mime);
    fn curl_slist_free_all(_: *mut curl_slist);
    fn free(__ptr: *mut libc::c_void);
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn tool_mime_free(mime: *mut tool_mime);
}
pub type __off_t = i64;
pub type __off64_t = i64;
pub type size_t = u64;
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
pub struct curl_slist {
    pub data: *mut i8,
    pub next: *mut curl_slist,
}
pub type curl_TimeCond = u32;
pub const CURL_TIMECOND_LAST: curl_TimeCond = 4;
pub const CURL_TIMECOND_LASTMOD: curl_TimeCond = 3;
pub const CURL_TIMECOND_IFUNMODSINCE: curl_TimeCond = 2;
pub const CURL_TIMECOND_IFMODSINCE: curl_TimeCond = 1;
pub const CURL_TIMECOND_NONE: curl_TimeCond = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct OperationConfig {
    pub remote_time: bool,
    pub random_file: *mut i8,
    pub egd_file: *mut i8,
    pub useragent: *mut i8,
    pub cookies: *mut curl_slist,
    pub cookiejar: *mut i8,
    pub cookiefiles: *mut curl_slist,
    pub altsvc: *mut i8,
    pub hsts: *mut i8,
    pub cookiesession: bool,
    pub encoding: bool,
    pub tr_encoding: bool,
    pub authtype: u64,
    pub use_resume: bool,
    pub resume_from_current: bool,
    pub disable_epsv: bool,
    pub disable_eprt: bool,
    pub ftp_pret: bool,
    pub proto: i64,
    pub proto_present: bool,
    pub proto_redir: i64,
    pub proto_redir_present: bool,
    pub proto_default: *mut i8,
    pub resume_from: curl_off_t,
    pub postfields: *mut i8,
    pub postfieldsize: curl_off_t,
    pub referer: *mut i8,
    pub timeout: f64,
    pub connecttimeout: f64,
    pub maxredirs: i64,
    pub max_filesize: curl_off_t,
    pub output_dir: *mut i8,
    pub headerfile: *mut i8,
    pub ftpport: *mut i8,
    pub iface: *mut i8,
    pub localport: i64,
    pub localportrange: i64,
    pub porttouse: u16,
    pub range: *mut i8,
    pub low_speed_limit: i64,
    pub low_speed_time: i64,
    pub dns_servers: *mut i8,
    pub dns_interface: *mut i8,
    pub dns_ipv4_addr: *mut i8,
    pub dns_ipv6_addr: *mut i8,
    pub userpwd: *mut i8,
    pub login_options: *mut i8,
    pub tls_username: *mut i8,
    pub tls_password: *mut i8,
    pub tls_authtype: *mut i8,
    pub proxy_tls_username: *mut i8,
    pub proxy_tls_password: *mut i8,
    pub proxy_tls_authtype: *mut i8,
    pub proxyuserpwd: *mut i8,
    pub proxy: *mut i8,
    pub proxyver: i32,
    pub noproxy: *mut i8,
    pub mail_from: *mut i8,
    pub mail_rcpt: *mut curl_slist,
    pub mail_auth: *mut i8,
    pub mail_rcpt_allowfails: bool,
    pub sasl_authzid: *mut i8,
    pub sasl_ir: bool,
    pub proxytunnel: bool,
    pub ftp_append: bool,
    pub use_ascii: bool,
    pub autoreferer: bool,
    pub failonerror: bool,
    pub failwithbody: bool,
    pub show_headers: bool,
    pub no_body: bool,
    pub dirlistonly: bool,
    pub followlocation: bool,
    pub unrestricted_auth: bool,
    pub netrc_opt: bool,
    pub netrc: bool,
    pub netrc_file: *mut i8,
    pub url_list: *mut getout,
    pub url_last: *mut getout,
    pub url_get: *mut getout,
    pub url_out: *mut getout,
    pub url_ul: *mut getout,
    pub doh_url: *mut i8,
    pub cipher_list: *mut i8,
    pub proxy_cipher_list: *mut i8,
    pub cipher13_list: *mut i8,
    pub proxy_cipher13_list: *mut i8,
    pub cert: *mut i8,
    pub proxy_cert: *mut i8,
    pub cert_type: *mut i8,
    pub proxy_cert_type: *mut i8,
    pub cacert: *mut i8,
    pub proxy_cacert: *mut i8,
    pub capath: *mut i8,
    pub proxy_capath: *mut i8,
    pub crlfile: *mut i8,
    pub proxy_crlfile: *mut i8,
    pub pinnedpubkey: *mut i8,
    pub proxy_pinnedpubkey: *mut i8,
    pub key: *mut i8,
    pub proxy_key: *mut i8,
    pub key_type: *mut i8,
    pub proxy_key_type: *mut i8,
    pub key_passwd: *mut i8,
    pub proxy_key_passwd: *mut i8,
    pub pubkey: *mut i8,
    pub hostpubmd5: *mut i8,
    pub engine: *mut i8,
    pub etag_save_file: *mut i8,
    pub etag_compare_file: *mut i8,
    pub crlf: bool,
    pub customrequest: *mut i8,
    pub ssl_ec_curves: *mut i8,
    pub krblevel: *mut i8,
    pub request_target: *mut i8,
    pub httpversion: i64,
    pub http09_allowed: bool,
    pub nobuffer: bool,
    pub readbusy: bool,
    pub globoff: bool,
    pub use_httpget: bool,
    pub insecure_ok: bool,
    pub doh_insecure_ok: bool,
    pub proxy_insecure_ok: bool,
    pub terminal_binary_ok: bool,
    pub verifystatus: bool,
    pub doh_verifystatus: bool,
    pub create_dirs: bool,
    pub ftp_create_dirs: bool,
    pub ftp_skip_ip: bool,
    pub proxynegotiate: bool,
    pub proxyntlm: bool,
    pub proxydigest: bool,
    pub proxybasic: bool,
    pub proxyanyauth: bool,
    pub writeout: *mut i8,
    pub quote: *mut curl_slist,
    pub postquote: *mut curl_slist,
    pub prequote: *mut curl_slist,
    pub ssl_version: i64,
    pub ssl_version_max: i64,
    pub proxy_ssl_version: i64,
    pub ip_version: i64,
    pub create_file_mode: i64,
    pub timecond: curl_TimeCond,
    pub condtime: curl_off_t,
    pub headers: *mut curl_slist,
    pub proxyheaders: *mut curl_slist,
    pub mimeroot: *mut tool_mime,
    pub mimecurrent: *mut tool_mime,
    pub mimepost: *mut curl_mime,
    pub telnet_options: *mut curl_slist,
    pub resolve: *mut curl_slist,
    pub connect_to: *mut curl_slist,
    pub httpreq: HttpReq,
    pub sendpersecond: curl_off_t,
    pub recvpersecond: curl_off_t,
    pub ftp_ssl: bool,
    pub ftp_ssl_reqd: bool,
    pub ftp_ssl_control: bool,
    pub ftp_ssl_ccc: bool,
    pub ftp_ssl_ccc_mode: i32,
    pub preproxy: *mut i8,
    pub socks5_gssapi_nec: i32,
    pub socks5_auth: u64,
    pub proxy_service_name: *mut i8,
    pub service_name: *mut i8,
    pub tcp_nodelay: bool,
    pub tcp_fastopen: bool,
    pub req_retry: i64,
    pub retry_all_errors: bool,
    pub retry_connrefused: bool,
    pub retry_delay: i64,
    pub retry_maxtime: i64,
    pub ftp_account: *mut i8,
    pub ftp_alternative_to_user: *mut i8,
    pub ftp_filemethod: i32,
    pub tftp_blksize: i64,
    pub tftp_no_options: bool,
    pub ignorecl: bool,
    pub disable_sessionid: bool,
    pub raw: bool,
    pub post301: bool,
    pub post302: bool,
    pub post303: bool,
    pub nokeepalive: bool,
    pub alivetime: i64,
    pub content_disposition: bool,
    pub default_node_flags: i32,
    pub xattr: bool,
    pub gssapi_delegation: i64,
    pub ssl_allow_beast: bool,
    pub proxy_ssl_allow_beast: bool,
    pub ssl_no_revoke: bool,
    pub ssl_revoke_best_effort: bool,
    pub native_ca_store: bool,
    pub ssl_auto_client_cert: bool,
    pub proxy_ssl_auto_client_cert: bool,
    pub oauth_bearer: *mut i8,
    pub nonpn: bool,
    pub noalpn: bool,
    pub unix_socket_path: *mut i8,
    pub abstract_unix_socket: bool,
    pub falsestart: bool,
    pub path_as_is: bool,
    pub expect100timeout: f64,
    pub suppress_connect_headers: bool,
    pub synthetic_error: curl_error,
    pub ssh_compression: bool,
    pub happy_eyeballs_timeout_ms: i64,
    pub haproxy_protocol: bool,
    pub disallow_username_in_url: bool,
    pub aws_sigv4: *mut i8,
    pub global: *mut GlobalConfig,
    pub prev: *mut OperationConfig,
    pub next: *mut OperationConfig,
    pub state: State,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct State {
    pub urlnode: *mut getout,
    pub inglob: *mut URLGlob,
    pub urls: *mut URLGlob,
    pub outfiles: *mut i8,
    pub httpgetfields: *mut i8,
    pub uploadfile: *mut i8,
    pub infilenum: u64,
    pub up: u64,
    pub urlnum: u64,
    pub li: u64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct URLGlob {
    pub pattern: [URLPattern; 100],
    pub size: size_t,
    pub urllen: size_t,
    pub glob_buffer: *mut i8,
    pub beenhere: i8,
    pub error: *const i8,
    pub pos: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct URLPattern {
    pub type_0: URLPatternType,
    pub globindex: i32,
    pub content: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub Set: C2RustUnnamed_2,
    pub CharRange: C2RustUnnamed_1,
    pub NumRange: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub min_n: u64,
    pub max_n: u64,
    pub padlength: i32,
    pub ptr_n: u64,
    pub step: u64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub min_c: i8,
    pub max_c: i8,
    pub ptr_c: i8,
    pub step: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub elements: *mut *mut i8,
    pub size: i32,
    pub ptr_s: i32,
}
pub type URLPatternType = u32;
pub const UPTNumRange: URLPatternType = 3;
pub const UPTCharRange: URLPatternType = 2;
pub const UPTSet: URLPatternType = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct getout {
    pub next: *mut getout,
    pub url: *mut i8,
    pub outfile: *mut i8,
    pub infile: *mut i8,
    pub flags: i32,
    pub num: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct GlobalConfig {
    pub showerror: i32,
    pub mute: bool,
    pub noprogress: bool,
    pub isatty: bool,
    pub errors: *mut FILE,
    pub errors_fopened: bool,
    pub trace_dump: *mut i8,
    pub trace_stream: *mut FILE,
    pub trace_fopened: bool,
    pub tracetype: trace,
    pub tracetime: bool,
    pub progressmode: i32,
    pub libcurl: *mut i8,
    pub fail_early: bool,
    pub styled_output: bool,
    pub parallel: bool,
    pub parallel_max: i64,
    pub parallel_connect: bool,
    pub help_category: *mut i8,
    pub first: *mut OperationConfig,
    pub current: *mut OperationConfig,
    pub last: *mut OperationConfig,
}
pub type trace = u32;
pub const TRACE_PLAIN: trace = 3;
pub const TRACE_ASCII: trace = 2;
pub const TRACE_BIN: trace = 1;
pub const TRACE_NONE: trace = 0;
pub type curl_error = u32;
pub const ERR_LAST: curl_error = 2;
pub const ERR_BINARY_TERMINAL: curl_error = 1;
pub const ERR_NONE: curl_error = 0;
pub type HttpReq = u32;
pub const HTTPREQ_SIMPLEPOST: HttpReq = 4;
pub const HTTPREQ_MIMEPOST: HttpReq = 3;
pub const HTTPREQ_HEAD: HttpReq = 2;
pub const HTTPREQ_GET: HttpReq = 1;
pub const HTTPREQ_UNSPEC: HttpReq = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tool_mime {
    pub kind: toolmimekind,
    pub parent: *mut tool_mime,
    pub prev: *mut tool_mime,
    pub data: *const i8,
    pub name: *const i8,
    pub filename: *const i8,
    pub type_0: *const i8,
    pub encoder: *const i8,
    pub headers: *mut curl_slist,
    pub subparts: *mut tool_mime,
    pub origin: curl_off_t,
    pub size: curl_off_t,
    pub curpos: curl_off_t,
    pub config: *mut GlobalConfig,
}
pub type toolmimekind = u32;
pub const TOOLMIME_STDINDATA: toolmimekind = 6;
pub const TOOLMIME_STDIN: toolmimekind = 5;
pub const TOOLMIME_FILEDATA: toolmimekind = 4;
pub const TOOLMIME_FILE: toolmimekind = 3;
pub const TOOLMIME_DATA: toolmimekind = 2;
pub const TOOLMIME_PARTS: toolmimekind = 1;
pub const TOOLMIME_NONE: toolmimekind = 0;
#[no_mangle]
pub extern "C" fn config_init(mut config: *mut OperationConfig) {
    (unsafe { memset(
        config as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<OperationConfig>() as u64,
    ) });
    (unsafe { (*config).postfieldsize = -(1 as i32) as curl_off_t });
    (unsafe { (*config).use_httpget = 0 as i32 != 0 });
    (unsafe { (*config).create_dirs = 0 as i32 != 0 });
    (unsafe { (*config).maxredirs = 50 as i64 });
    (unsafe { (*config).proto = !(0 as i32) as i64 });
    (unsafe { (*config).proto_present = 0 as i32 != 0 });
    (unsafe { (*config).proto_redir = (!(0 as i32)
        & !((1 as i32) << 10 as i32
            | (1 as i32) << 4 as i32
            | (1 as i32) << 26 as i32
            | (1 as i32) << 27 as i32)) as i64 });
    (unsafe { (*config).proto_redir_present = 0 as i32 != 0 });
    let fresh0 = unsafe { &mut ((*config).proto_default) };
    *fresh0 = 0 as *mut i8;
    (unsafe { (*config).tcp_nodelay = 1 as i32 != 0 });
    (unsafe { (*config).happy_eyeballs_timeout_ms = 200 as i64 });
    (unsafe { (*config).http09_allowed = 0 as i32 != 0 });
    (unsafe { (*config).ftp_skip_ip = 1 as i32 != 0 });
}
extern "C" fn free_config_fields(mut config: *mut OperationConfig) {
    let mut urlnode: *mut getout = 0 as *mut getout;
    (unsafe { free((*config).random_file as *mut libc::c_void) });
    let fresh1 = unsafe { &mut ((*config).random_file) };
    *fresh1 = 0 as *mut i8;
    (unsafe { free((*config).egd_file as *mut libc::c_void) });
    let fresh2 = unsafe { &mut ((*config).egd_file) };
    *fresh2 = 0 as *mut i8;
    (unsafe { free((*config).useragent as *mut libc::c_void) });
    let fresh3 = unsafe { &mut ((*config).useragent) };
    *fresh3 = 0 as *mut i8;
    (unsafe { free((*config).altsvc as *mut libc::c_void) });
    let fresh4 = unsafe { &mut ((*config).altsvc) };
    *fresh4 = 0 as *mut i8;
    (unsafe { free((*config).hsts as *mut libc::c_void) });
    let fresh5 = unsafe { &mut ((*config).hsts) };
    *fresh5 = 0 as *mut i8;
    (unsafe { curl_slist_free_all((*config).cookies) });
    (unsafe { free((*config).cookiejar as *mut libc::c_void) });
    let fresh6 = unsafe { &mut ((*config).cookiejar) };
    *fresh6 = 0 as *mut i8;
    (unsafe { curl_slist_free_all((*config).cookiefiles) });
    (unsafe { free((*config).postfields as *mut libc::c_void) });
    let fresh7 = unsafe { &mut ((*config).postfields) };
    *fresh7 = 0 as *mut i8;
    (unsafe { free((*config).referer as *mut libc::c_void) });
    let fresh8 = unsafe { &mut ((*config).referer) };
    *fresh8 = 0 as *mut i8;
    (unsafe { free((*config).headerfile as *mut libc::c_void) });
    let fresh9 = unsafe { &mut ((*config).headerfile) };
    *fresh9 = 0 as *mut i8;
    (unsafe { free((*config).ftpport as *mut libc::c_void) });
    let fresh10 = unsafe { &mut ((*config).ftpport) };
    *fresh10 = 0 as *mut i8;
    (unsafe { free((*config).iface as *mut libc::c_void) });
    let fresh11 = unsafe { &mut ((*config).iface) };
    *fresh11 = 0 as *mut i8;
    (unsafe { free((*config).range as *mut libc::c_void) });
    let fresh12 = unsafe { &mut ((*config).range) };
    *fresh12 = 0 as *mut i8;
    (unsafe { free((*config).userpwd as *mut libc::c_void) });
    let fresh13 = unsafe { &mut ((*config).userpwd) };
    *fresh13 = 0 as *mut i8;
    (unsafe { free((*config).tls_username as *mut libc::c_void) });
    let fresh14 = unsafe { &mut ((*config).tls_username) };
    *fresh14 = 0 as *mut i8;
    (unsafe { free((*config).tls_password as *mut libc::c_void) });
    let fresh15 = unsafe { &mut ((*config).tls_password) };
    *fresh15 = 0 as *mut i8;
    (unsafe { free((*config).tls_authtype as *mut libc::c_void) });
    let fresh16 = unsafe { &mut ((*config).tls_authtype) };
    *fresh16 = 0 as *mut i8;
    (unsafe { free((*config).proxy_tls_username as *mut libc::c_void) });
    let fresh17 = unsafe { &mut ((*config).proxy_tls_username) };
    *fresh17 = 0 as *mut i8;
    (unsafe { free((*config).proxy_tls_password as *mut libc::c_void) });
    let fresh18 = unsafe { &mut ((*config).proxy_tls_password) };
    *fresh18 = 0 as *mut i8;
    (unsafe { free((*config).proxy_tls_authtype as *mut libc::c_void) });
    let fresh19 = unsafe { &mut ((*config).proxy_tls_authtype) };
    *fresh19 = 0 as *mut i8;
    (unsafe { free((*config).proxyuserpwd as *mut libc::c_void) });
    let fresh20 = unsafe { &mut ((*config).proxyuserpwd) };
    *fresh20 = 0 as *mut i8;
    (unsafe { free((*config).proxy as *mut libc::c_void) });
    let fresh21 = unsafe { &mut ((*config).proxy) };
    *fresh21 = 0 as *mut i8;
    (unsafe { free((*config).dns_ipv6_addr as *mut libc::c_void) });
    let fresh22 = unsafe { &mut ((*config).dns_ipv6_addr) };
    *fresh22 = 0 as *mut i8;
    (unsafe { free((*config).dns_ipv4_addr as *mut libc::c_void) });
    let fresh23 = unsafe { &mut ((*config).dns_ipv4_addr) };
    *fresh23 = 0 as *mut i8;
    (unsafe { free((*config).dns_interface as *mut libc::c_void) });
    let fresh24 = unsafe { &mut ((*config).dns_interface) };
    *fresh24 = 0 as *mut i8;
    (unsafe { free((*config).dns_servers as *mut libc::c_void) });
    let fresh25 = unsafe { &mut ((*config).dns_servers) };
    *fresh25 = 0 as *mut i8;
    (unsafe { free((*config).noproxy as *mut libc::c_void) });
    let fresh26 = unsafe { &mut ((*config).noproxy) };
    *fresh26 = 0 as *mut i8;
    (unsafe { free((*config).mail_from as *mut libc::c_void) });
    let fresh27 = unsafe { &mut ((*config).mail_from) };
    *fresh27 = 0 as *mut i8;
    (unsafe { curl_slist_free_all((*config).mail_rcpt) });
    (unsafe { free((*config).mail_auth as *mut libc::c_void) });
    let fresh28 = unsafe { &mut ((*config).mail_auth) };
    *fresh28 = 0 as *mut i8;
    (unsafe { free((*config).netrc_file as *mut libc::c_void) });
    let fresh29 = unsafe { &mut ((*config).netrc_file) };
    *fresh29 = 0 as *mut i8;
    (unsafe { free((*config).output_dir as *mut libc::c_void) });
    let fresh30 = unsafe { &mut ((*config).output_dir) };
    *fresh30 = 0 as *mut i8;
    urlnode = unsafe { (*config).url_list };
    while !urlnode.is_null() {
        let mut next: *mut getout = unsafe { (*urlnode).next };
        (unsafe { free((*urlnode).url as *mut libc::c_void) });
        let fresh31 = unsafe { &mut ((*urlnode).url) };
        *fresh31 = 0 as *mut i8;
        (unsafe { free((*urlnode).outfile as *mut libc::c_void) });
        let fresh32 = unsafe { &mut ((*urlnode).outfile) };
        *fresh32 = 0 as *mut i8;
        (unsafe { free((*urlnode).infile as *mut libc::c_void) });
        let fresh33 = unsafe { &mut ((*urlnode).infile) };
        *fresh33 = 0 as *mut i8;
        (unsafe { free(urlnode as *mut libc::c_void) });
        urlnode = 0 as *mut getout;
        urlnode = next;
    }
    let fresh34 = unsafe { &mut ((*config).url_list) };
    *fresh34 = 0 as *mut getout;
    let fresh35 = unsafe { &mut ((*config).url_last) };
    *fresh35 = 0 as *mut getout;
    let fresh36 = unsafe { &mut ((*config).url_get) };
    *fresh36 = 0 as *mut getout;
    let fresh37 = unsafe { &mut ((*config).url_out) };
    *fresh37 = 0 as *mut getout;
    (unsafe { free((*config).doh_url as *mut libc::c_void) });
    let fresh38 = unsafe { &mut ((*config).doh_url) };
    *fresh38 = 0 as *mut i8;
    (unsafe { free((*config).cipher_list as *mut libc::c_void) });
    let fresh39 = unsafe { &mut ((*config).cipher_list) };
    *fresh39 = 0 as *mut i8;
    (unsafe { free((*config).proxy_cipher_list as *mut libc::c_void) });
    let fresh40 = unsafe { &mut ((*config).proxy_cipher_list) };
    *fresh40 = 0 as *mut i8;
    (unsafe { free((*config).cert as *mut libc::c_void) });
    let fresh41 = unsafe { &mut ((*config).cert) };
    *fresh41 = 0 as *mut i8;
    (unsafe { free((*config).proxy_cert as *mut libc::c_void) });
    let fresh42 = unsafe { &mut ((*config).proxy_cert) };
    *fresh42 = 0 as *mut i8;
    (unsafe { free((*config).cert_type as *mut libc::c_void) });
    let fresh43 = unsafe { &mut ((*config).cert_type) };
    *fresh43 = 0 as *mut i8;
    (unsafe { free((*config).proxy_cert_type as *mut libc::c_void) });
    let fresh44 = unsafe { &mut ((*config).proxy_cert_type) };
    *fresh44 = 0 as *mut i8;
    (unsafe { free((*config).cacert as *mut libc::c_void) });
    let fresh45 = unsafe { &mut ((*config).cacert) };
    *fresh45 = 0 as *mut i8;
    (unsafe { free((*config).login_options as *mut libc::c_void) });
    let fresh46 = unsafe { &mut ((*config).login_options) };
    *fresh46 = 0 as *mut i8;
    (unsafe { free((*config).proxy_cacert as *mut libc::c_void) });
    let fresh47 = unsafe { &mut ((*config).proxy_cacert) };
    *fresh47 = 0 as *mut i8;
    (unsafe { free((*config).capath as *mut libc::c_void) });
    let fresh48 = unsafe { &mut ((*config).capath) };
    *fresh48 = 0 as *mut i8;
    (unsafe { free((*config).proxy_capath as *mut libc::c_void) });
    let fresh49 = unsafe { &mut ((*config).proxy_capath) };
    *fresh49 = 0 as *mut i8;
    (unsafe { free((*config).crlfile as *mut libc::c_void) });
    let fresh50 = unsafe { &mut ((*config).crlfile) };
    *fresh50 = 0 as *mut i8;
    (unsafe { free((*config).pinnedpubkey as *mut libc::c_void) });
    let fresh51 = unsafe { &mut ((*config).pinnedpubkey) };
    *fresh51 = 0 as *mut i8;
    (unsafe { free((*config).proxy_pinnedpubkey as *mut libc::c_void) });
    let fresh52 = unsafe { &mut ((*config).proxy_pinnedpubkey) };
    *fresh52 = 0 as *mut i8;
    (unsafe { free((*config).proxy_crlfile as *mut libc::c_void) });
    let fresh53 = unsafe { &mut ((*config).proxy_crlfile) };
    *fresh53 = 0 as *mut i8;
    (unsafe { free((*config).key as *mut libc::c_void) });
    let fresh54 = unsafe { &mut ((*config).key) };
    *fresh54 = 0 as *mut i8;
    (unsafe { free((*config).proxy_key as *mut libc::c_void) });
    let fresh55 = unsafe { &mut ((*config).proxy_key) };
    *fresh55 = 0 as *mut i8;
    (unsafe { free((*config).key_type as *mut libc::c_void) });
    let fresh56 = unsafe { &mut ((*config).key_type) };
    *fresh56 = 0 as *mut i8;
    (unsafe { free((*config).proxy_key_type as *mut libc::c_void) });
    let fresh57 = unsafe { &mut ((*config).proxy_key_type) };
    *fresh57 = 0 as *mut i8;
    (unsafe { free((*config).key_passwd as *mut libc::c_void) });
    let fresh58 = unsafe { &mut ((*config).key_passwd) };
    *fresh58 = 0 as *mut i8;
    (unsafe { free((*config).proxy_key_passwd as *mut libc::c_void) });
    let fresh59 = unsafe { &mut ((*config).proxy_key_passwd) };
    *fresh59 = 0 as *mut i8;
    (unsafe { free((*config).pubkey as *mut libc::c_void) });
    let fresh60 = unsafe { &mut ((*config).pubkey) };
    *fresh60 = 0 as *mut i8;
    (unsafe { free((*config).hostpubmd5 as *mut libc::c_void) });
    let fresh61 = unsafe { &mut ((*config).hostpubmd5) };
    *fresh61 = 0 as *mut i8;
    (unsafe { free((*config).engine as *mut libc::c_void) });
    let fresh62 = unsafe { &mut ((*config).engine) };
    *fresh62 = 0 as *mut i8;
    (unsafe { free((*config).etag_save_file as *mut libc::c_void) });
    let fresh63 = unsafe { &mut ((*config).etag_save_file) };
    *fresh63 = 0 as *mut i8;
    (unsafe { free((*config).etag_compare_file as *mut libc::c_void) });
    let fresh64 = unsafe { &mut ((*config).etag_compare_file) };
    *fresh64 = 0 as *mut i8;
    (unsafe { free((*config).request_target as *mut libc::c_void) });
    let fresh65 = unsafe { &mut ((*config).request_target) };
    *fresh65 = 0 as *mut i8;
    (unsafe { free((*config).customrequest as *mut libc::c_void) });
    let fresh66 = unsafe { &mut ((*config).customrequest) };
    *fresh66 = 0 as *mut i8;
    (unsafe { free((*config).krblevel as *mut libc::c_void) });
    let fresh67 = unsafe { &mut ((*config).krblevel) };
    *fresh67 = 0 as *mut i8;
    (unsafe { free((*config).oauth_bearer as *mut libc::c_void) });
    let fresh68 = unsafe { &mut ((*config).oauth_bearer) };
    *fresh68 = 0 as *mut i8;
    (unsafe { free((*config).sasl_authzid as *mut libc::c_void) });
    let fresh69 = unsafe { &mut ((*config).sasl_authzid) };
    *fresh69 = 0 as *mut i8;
    (unsafe { free((*config).unix_socket_path as *mut libc::c_void) });
    let fresh70 = unsafe { &mut ((*config).unix_socket_path) };
    *fresh70 = 0 as *mut i8;
    (unsafe { free((*config).writeout as *mut libc::c_void) });
    let fresh71 = unsafe { &mut ((*config).writeout) };
    *fresh71 = 0 as *mut i8;
    (unsafe { free((*config).proto_default as *mut libc::c_void) });
    let fresh72 = unsafe { &mut ((*config).proto_default) };
    *fresh72 = 0 as *mut i8;
    (unsafe { curl_slist_free_all((*config).quote) });
    (unsafe { curl_slist_free_all((*config).postquote) });
    (unsafe { curl_slist_free_all((*config).prequote) });
    (unsafe { curl_slist_free_all((*config).headers) });
    (unsafe { curl_slist_free_all((*config).proxyheaders) });
    (unsafe { curl_mime_free((*config).mimepost) });
    let fresh73 = unsafe { &mut ((*config).mimepost) };
    *fresh73 = 0 as *mut curl_mime;
    (unsafe { tool_mime_free((*config).mimeroot) });
    let fresh74 = unsafe { &mut ((*config).mimeroot) };
    *fresh74 = 0 as *mut tool_mime;
    let fresh75 = unsafe { &mut ((*config).mimecurrent) };
    *fresh75 = 0 as *mut tool_mime;
    (unsafe { curl_slist_free_all((*config).telnet_options) });
    (unsafe { curl_slist_free_all((*config).resolve) });
    (unsafe { curl_slist_free_all((*config).connect_to) });
    (unsafe { free((*config).preproxy as *mut libc::c_void) });
    let fresh76 = unsafe { &mut ((*config).preproxy) };
    *fresh76 = 0 as *mut i8;
    (unsafe { free((*config).proxy_service_name as *mut libc::c_void) });
    let fresh77 = unsafe { &mut ((*config).proxy_service_name) };
    *fresh77 = 0 as *mut i8;
    (unsafe { free((*config).service_name as *mut libc::c_void) });
    let fresh78 = unsafe { &mut ((*config).service_name) };
    *fresh78 = 0 as *mut i8;
    (unsafe { free((*config).ftp_account as *mut libc::c_void) });
    let fresh79 = unsafe { &mut ((*config).ftp_account) };
    *fresh79 = 0 as *mut i8;
    (unsafe { free((*config).ftp_alternative_to_user as *mut libc::c_void) });
    let fresh80 = unsafe { &mut ((*config).ftp_alternative_to_user) };
    *fresh80 = 0 as *mut i8;
    (unsafe { free((*config).aws_sigv4 as *mut libc::c_void) });
    let fresh81 = unsafe { &mut ((*config).aws_sigv4) };
    *fresh81 = 0 as *mut i8;
}
#[no_mangle]
pub extern "C" fn config_free(mut config: *mut OperationConfig) {
    let mut last: *mut OperationConfig = config;
    while !last.is_null() {
        let mut prev: *mut OperationConfig = unsafe { (*last).prev };
        free_config_fields(last);
        (unsafe { free(last as *mut libc::c_void) });
        last = prev;
    }
}
