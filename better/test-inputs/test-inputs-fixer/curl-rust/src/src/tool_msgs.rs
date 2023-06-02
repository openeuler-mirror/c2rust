use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type curl_mime;
    fn curl_free(p: *mut libc::c_void);
    fn fputs(__s: *const i8, __stream: *mut FILE) -> i32;
    fn fwrite(_: *const libc::c_void, _: u64, _: u64, _: *mut FILE) -> u64;
    fn Curl_isspace(c: i32) -> i32;
    fn strlen(_: *const i8) -> u64;
    fn curl_mvfprintf(fd: *mut FILE, format: *const i8, args: ::std::ffi::VaList) -> i32;
    fn curl_mvaprintf(format: *const i8, args: ::std::ffi::VaList) -> *mut i8;
    fn curl_mfprintf(fd: *mut FILE, format: *const i8, _: ...) -> i32;
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
pub type __off_t = i64;
pub type __off64_t = i64;
pub type size_t = u64;
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
extern "C" fn voutf(
    mut config: *mut GlobalConfig,
    mut prefix: *const i8,
    mut fmt: *const i8,
    mut ap: ::std::ffi::VaList,
) {
    let mut width: size_t = (79 as i32 as u64).wrapping_sub(unsafe { strlen(prefix) });
    if !(unsafe { (*config).mute }) {
        let mut len: size_t = 0;
        let mut ptr: *mut i8 = 0 as *mut i8;
        let mut print_buffer: *mut i8 = 0 as *mut i8;
        print_buffer = unsafe { curl_mvaprintf(fmt, ap.as_va_list()) };
        if print_buffer.is_null() {
            return;
        }
        len = unsafe { strlen(print_buffer) };
        ptr = print_buffer;
        while len > 0 as i32 as u64 {
            (unsafe { fputs(prefix, (*config).errors) });
            if len > width {
                let mut cut: size_t = width.wrapping_sub(1 as i32 as u64);
                while (unsafe { Curl_isspace(*ptr.offset(cut as isize) as u8 as i32) }) == 0 && cut != 0 {
                    cut = cut.wrapping_sub(1);
                }
                if 0 as i32 as u64 == cut {
                    cut = width.wrapping_sub(1 as i32 as u64);
                }
                (unsafe { fwrite(
                    ptr as *const libc::c_void,
                    cut.wrapping_add(1 as i32 as u64),
                    1 as i32 as u64,
                    (*config).errors,
                ) });
                (unsafe { fputs(b"\n\0" as *const u8 as *const i8, (*config).errors) });
                ptr = unsafe { ptr.offset(cut.wrapping_add(1 as i32 as u64) as isize) };
                len = (len as u64).wrapping_sub(cut.wrapping_add(1 as i32 as u64)) as size_t
                    as size_t;
            } else {
                (unsafe { fputs(ptr, (*config).errors) });
                len = 0 as i32 as size_t;
            }
        }
        (unsafe { curl_free(print_buffer as *mut libc::c_void) });
    }
}
#[no_mangle]
pub unsafe extern "C" fn notef(mut config: *mut GlobalConfig, mut fmt: *const i8, mut args: ...) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    if (*config).tracetype as u64 != 0 {
        voutf(
            config,
            b"Note: \0" as *const u8 as *const i8,
            fmt,
            ap.as_va_list(),
        );
    }
}
#[no_mangle]
pub unsafe extern "C" fn warnf(mut config: *mut GlobalConfig, mut fmt: *const i8, mut args: ...) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    voutf(
        config,
        b"Warning: \0" as *const u8 as *const i8,
        fmt,
        ap.as_va_list(),
    );
}
#[no_mangle]
pub unsafe extern "C" fn helpf(mut errors: *mut FILE, mut fmt: *const i8, mut args: ...) {
    if !fmt.is_null() {
        let mut ap: ::std::ffi::VaListImpl;
        ap = args.clone();
        fputs(b"curl: \0" as *const u8 as *const i8, errors);
        curl_mvfprintf(errors, fmt, ap.as_va_list());
    }
    curl_mfprintf(
        errors,
        b"curl: try 'curl --help' or 'curl --manual' for more information\n\0" as *const u8
            as *const i8,
    );
}
#[no_mangle]
pub unsafe extern "C" fn errorf(mut config: *mut GlobalConfig, mut fmt: *const i8, mut args: ...) {
    if !(*config).mute {
        let mut ap: ::std::ffi::VaListImpl;
        ap = args.clone();
        voutf(
            config,
            b"curl: \0" as *const u8 as *const i8,
            fmt,
            ap.as_va_list(),
        );
    }
}
