use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type curl_mime;
    fn curl_mime_free(mime: *mut curl_mime);
    fn curl_slist_free_all(_: *mut curl_slist);
    fn free(__ptr: *mut libc::c_void);
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn tool_mime_free(mime: *mut tool_mime);
}
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type size_t = libc::c_ulong;
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
pub struct curl_slist {
    pub data: *mut libc::c_char,
    pub next: *mut curl_slist,
}
pub type curl_TimeCond = libc::c_uint;
pub const CURL_TIMECOND_LAST: curl_TimeCond = 4;
pub const CURL_TIMECOND_LASTMOD: curl_TimeCond = 3;
pub const CURL_TIMECOND_IFUNMODSINCE: curl_TimeCond = 2;
pub const CURL_TIMECOND_IFMODSINCE: curl_TimeCond = 1;
pub const CURL_TIMECOND_NONE: curl_TimeCond = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct OperationConfig {
    pub remote_time: bool,
    pub random_file: *mut libc::c_char,
    pub egd_file: *mut libc::c_char,
    pub useragent: *mut libc::c_char,
    pub cookies: *mut curl_slist,
    pub cookiejar: *mut libc::c_char,
    pub cookiefiles: *mut curl_slist,
    pub altsvc: *mut libc::c_char,
    pub hsts: *mut libc::c_char,
    pub cookiesession: bool,
    pub encoding: bool,
    pub tr_encoding: bool,
    pub authtype: libc::c_ulong,
    pub use_resume: bool,
    pub resume_from_current: bool,
    pub disable_epsv: bool,
    pub disable_eprt: bool,
    pub ftp_pret: bool,
    pub proto: libc::c_long,
    pub proto_present: bool,
    pub proto_redir: libc::c_long,
    pub proto_redir_present: bool,
    pub proto_default: *mut libc::c_char,
    pub resume_from: curl_off_t,
    pub postfields: *mut libc::c_char,
    pub postfieldsize: curl_off_t,
    pub referer: *mut libc::c_char,
    pub timeout: libc::c_double,
    pub connecttimeout: libc::c_double,
    pub maxredirs: libc::c_long,
    pub max_filesize: curl_off_t,
    pub output_dir: *mut libc::c_char,
    pub headerfile: *mut libc::c_char,
    pub ftpport: *mut libc::c_char,
    pub iface: *mut libc::c_char,
    pub localport: libc::c_long,
    pub localportrange: libc::c_long,
    pub porttouse: libc::c_ushort,
    pub range: *mut libc::c_char,
    pub low_speed_limit: libc::c_long,
    pub low_speed_time: libc::c_long,
    pub dns_servers: *mut libc::c_char,
    pub dns_interface: *mut libc::c_char,
    pub dns_ipv4_addr: *mut libc::c_char,
    pub dns_ipv6_addr: *mut libc::c_char,
    pub userpwd: *mut libc::c_char,
    pub login_options: *mut libc::c_char,
    pub tls_username: *mut libc::c_char,
    pub tls_password: *mut libc::c_char,
    pub tls_authtype: *mut libc::c_char,
    pub proxy_tls_username: *mut libc::c_char,
    pub proxy_tls_password: *mut libc::c_char,
    pub proxy_tls_authtype: *mut libc::c_char,
    pub proxyuserpwd: *mut libc::c_char,
    pub proxy: *mut libc::c_char,
    pub proxyver: libc::c_int,
    pub noproxy: *mut libc::c_char,
    pub mail_from: *mut libc::c_char,
    pub mail_rcpt: *mut curl_slist,
    pub mail_auth: *mut libc::c_char,
    pub mail_rcpt_allowfails: bool,
    pub sasl_authzid: *mut libc::c_char,
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
    pub netrc_file: *mut libc::c_char,
    pub url_list: *mut getout,
    pub url_last: *mut getout,
    pub url_get: *mut getout,
    pub url_out: *mut getout,
    pub url_ul: *mut getout,
    pub doh_url: *mut libc::c_char,
    pub cipher_list: *mut libc::c_char,
    pub proxy_cipher_list: *mut libc::c_char,
    pub cipher13_list: *mut libc::c_char,
    pub proxy_cipher13_list: *mut libc::c_char,
    pub cert: *mut libc::c_char,
    pub proxy_cert: *mut libc::c_char,
    pub cert_type: *mut libc::c_char,
    pub proxy_cert_type: *mut libc::c_char,
    pub cacert: *mut libc::c_char,
    pub proxy_cacert: *mut libc::c_char,
    pub capath: *mut libc::c_char,
    pub proxy_capath: *mut libc::c_char,
    pub crlfile: *mut libc::c_char,
    pub proxy_crlfile: *mut libc::c_char,
    pub pinnedpubkey: *mut libc::c_char,
    pub proxy_pinnedpubkey: *mut libc::c_char,
    pub key: *mut libc::c_char,
    pub proxy_key: *mut libc::c_char,
    pub key_type: *mut libc::c_char,
    pub proxy_key_type: *mut libc::c_char,
    pub key_passwd: *mut libc::c_char,
    pub proxy_key_passwd: *mut libc::c_char,
    pub pubkey: *mut libc::c_char,
    pub hostpubmd5: *mut libc::c_char,
    pub engine: *mut libc::c_char,
    pub etag_save_file: *mut libc::c_char,
    pub etag_compare_file: *mut libc::c_char,
    pub crlf: bool,
    pub customrequest: *mut libc::c_char,
    pub ssl_ec_curves: *mut libc::c_char,
    pub krblevel: *mut libc::c_char,
    pub request_target: *mut libc::c_char,
    pub httpversion: libc::c_long,
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
    pub writeout: *mut libc::c_char,
    pub quote: *mut curl_slist,
    pub postquote: *mut curl_slist,
    pub prequote: *mut curl_slist,
    pub ssl_version: libc::c_long,
    pub ssl_version_max: libc::c_long,
    pub proxy_ssl_version: libc::c_long,
    pub ip_version: libc::c_long,
    pub create_file_mode: libc::c_long,
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
    pub ftp_ssl_ccc_mode: libc::c_int,
    pub preproxy: *mut libc::c_char,
    pub socks5_gssapi_nec: libc::c_int,
    pub socks5_auth: libc::c_ulong,
    pub proxy_service_name: *mut libc::c_char,
    pub service_name: *mut libc::c_char,
    pub tcp_nodelay: bool,
    pub tcp_fastopen: bool,
    pub req_retry: libc::c_long,
    pub retry_all_errors: bool,
    pub retry_connrefused: bool,
    pub retry_delay: libc::c_long,
    pub retry_maxtime: libc::c_long,
    pub ftp_account: *mut libc::c_char,
    pub ftp_alternative_to_user: *mut libc::c_char,
    pub ftp_filemethod: libc::c_int,
    pub tftp_blksize: libc::c_long,
    pub tftp_no_options: bool,
    pub ignorecl: bool,
    pub disable_sessionid: bool,
    pub raw: bool,
    pub post301: bool,
    pub post302: bool,
    pub post303: bool,
    pub nokeepalive: bool,
    pub alivetime: libc::c_long,
    pub content_disposition: bool,
    pub default_node_flags: libc::c_int,
    pub xattr: bool,
    pub gssapi_delegation: libc::c_long,
    pub ssl_allow_beast: bool,
    pub proxy_ssl_allow_beast: bool,
    pub ssl_no_revoke: bool,
    pub ssl_revoke_best_effort: bool,
    pub native_ca_store: bool,
    pub ssl_auto_client_cert: bool,
    pub proxy_ssl_auto_client_cert: bool,
    pub oauth_bearer: *mut libc::c_char,
    pub nonpn: bool,
    pub noalpn: bool,
    pub unix_socket_path: *mut libc::c_char,
    pub abstract_unix_socket: bool,
    pub falsestart: bool,
    pub path_as_is: bool,
    pub expect100timeout: libc::c_double,
    pub suppress_connect_headers: bool,
    pub synthetic_error: curl_error,
    pub ssh_compression: bool,
    pub happy_eyeballs_timeout_ms: libc::c_long,
    pub haproxy_protocol: bool,
    pub disallow_username_in_url: bool,
    pub aws_sigv4: *mut libc::c_char,
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
    pub outfiles: *mut libc::c_char,
    pub httpgetfields: *mut libc::c_char,
    pub uploadfile: *mut libc::c_char,
    pub infilenum: libc::c_ulong,
    pub up: libc::c_ulong,
    pub urlnum: libc::c_ulong,
    pub li: libc::c_ulong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct URLGlob {
    pub pattern: [URLPattern; 100],
    pub size: size_t,
    pub urllen: size_t,
    pub glob_buffer: *mut libc::c_char,
    pub beenhere: libc::c_char,
    pub error: *const libc::c_char,
    pub pos: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct URLPattern {
    pub type_0: URLPatternType,
    pub globindex: libc::c_int,
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
    pub min_n: libc::c_ulong,
    pub max_n: libc::c_ulong,
    pub padlength: libc::c_int,
    pub ptr_n: libc::c_ulong,
    pub step: libc::c_ulong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub min_c: libc::c_char,
    pub max_c: libc::c_char,
    pub ptr_c: libc::c_char,
    pub step: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub elements: *mut *mut libc::c_char,
    pub size: libc::c_int,
    pub ptr_s: libc::c_int,
}
pub type URLPatternType = libc::c_uint;
pub const UPTNumRange: URLPatternType = 3;
pub const UPTCharRange: URLPatternType = 2;
pub const UPTSet: URLPatternType = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct getout {
    pub next: *mut getout,
    pub url: *mut libc::c_char,
    pub outfile: *mut libc::c_char,
    pub infile: *mut libc::c_char,
    pub flags: libc::c_int,
    pub num: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct GlobalConfig {
    pub showerror: libc::c_int,
    pub mute: bool,
    pub noprogress: bool,
    pub isatty: bool,
    pub errors: *mut FILE,
    pub errors_fopened: bool,
    pub trace_dump: *mut libc::c_char,
    pub trace_stream: *mut FILE,
    pub trace_fopened: bool,
    pub tracetype: trace,
    pub tracetime: bool,
    pub progressmode: libc::c_int,
    pub libcurl: *mut libc::c_char,
    pub fail_early: bool,
    pub styled_output: bool,
    pub parallel: bool,
    pub parallel_max: libc::c_long,
    pub parallel_connect: bool,
    pub help_category: *mut libc::c_char,
    pub first: *mut OperationConfig,
    pub current: *mut OperationConfig,
    pub last: *mut OperationConfig,
}
pub type trace = libc::c_uint;
pub const TRACE_PLAIN: trace = 3;
pub const TRACE_ASCII: trace = 2;
pub const TRACE_BIN: trace = 1;
pub const TRACE_NONE: trace = 0;
pub type curl_error = libc::c_uint;
pub const ERR_LAST: curl_error = 2;
pub const ERR_BINARY_TERMINAL: curl_error = 1;
pub const ERR_NONE: curl_error = 0;
pub type HttpReq = libc::c_uint;
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
    pub data: *const libc::c_char,
    pub name: *const libc::c_char,
    pub filename: *const libc::c_char,
    pub type_0: *const libc::c_char,
    pub encoder: *const libc::c_char,
    pub headers: *mut curl_slist,
    pub subparts: *mut tool_mime,
    pub origin: curl_off_t,
    pub size: curl_off_t,
    pub curpos: curl_off_t,
    pub config: *mut GlobalConfig,
}
pub type toolmimekind = libc::c_uint;
pub const TOOLMIME_STDINDATA: toolmimekind = 6;
pub const TOOLMIME_STDIN: toolmimekind = 5;
pub const TOOLMIME_FILEDATA: toolmimekind = 4;
pub const TOOLMIME_FILE: toolmimekind = 3;
pub const TOOLMIME_DATA: toolmimekind = 2;
pub const TOOLMIME_PARTS: toolmimekind = 1;
pub const TOOLMIME_NONE: toolmimekind = 0;
#[no_mangle]
pub unsafe extern "C" fn config_init(mut config: *mut OperationConfig) {
    memset(
        config as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<OperationConfig>() as libc::c_ulong,
    );
    (*config).postfieldsize = -(1 as libc::c_int) as curl_off_t;
    (*config).use_httpget = 0 as libc::c_int != 0;
    (*config).create_dirs = 0 as libc::c_int != 0;
    (*config).maxredirs = 50 as libc::c_long;
    (*config).proto = !(0 as libc::c_int) as libc::c_long;
    (*config).proto_present = 0 as libc::c_int != 0;
    (*config)
        .proto_redir = (!(0 as libc::c_int)
        & !((1 as libc::c_int) << 10 as libc::c_int
            | (1 as libc::c_int) << 4 as libc::c_int
            | (1 as libc::c_int) << 26 as libc::c_int
            | (1 as libc::c_int) << 27 as libc::c_int)) as libc::c_long;
    (*config).proto_redir_present = 0 as libc::c_int != 0;
    let ref mut fresh0 = (*config).proto_default;
    *fresh0 = 0 as *mut libc::c_char;
    (*config).tcp_nodelay = 1 as libc::c_int != 0;
    (*config).happy_eyeballs_timeout_ms = 200 as libc::c_long;
    (*config).http09_allowed = 0 as libc::c_int != 0;
    (*config).ftp_skip_ip = 1 as libc::c_int != 0;
}
unsafe extern "C" fn free_config_fields(mut config: *mut OperationConfig) {
    let mut urlnode: *mut getout = 0 as *mut getout;
    free((*config).random_file as *mut libc::c_void);
    let ref mut fresh1 = (*config).random_file;
    *fresh1 = 0 as *mut libc::c_char;
    free((*config).egd_file as *mut libc::c_void);
    let ref mut fresh2 = (*config).egd_file;
    *fresh2 = 0 as *mut libc::c_char;
    free((*config).useragent as *mut libc::c_void);
    let ref mut fresh3 = (*config).useragent;
    *fresh3 = 0 as *mut libc::c_char;
    free((*config).altsvc as *mut libc::c_void);
    let ref mut fresh4 = (*config).altsvc;
    *fresh4 = 0 as *mut libc::c_char;
    free((*config).hsts as *mut libc::c_void);
    let ref mut fresh5 = (*config).hsts;
    *fresh5 = 0 as *mut libc::c_char;
    curl_slist_free_all((*config).cookies);
    free((*config).cookiejar as *mut libc::c_void);
    let ref mut fresh6 = (*config).cookiejar;
    *fresh6 = 0 as *mut libc::c_char;
    curl_slist_free_all((*config).cookiefiles);
    free((*config).postfields as *mut libc::c_void);
    let ref mut fresh7 = (*config).postfields;
    *fresh7 = 0 as *mut libc::c_char;
    free((*config).referer as *mut libc::c_void);
    let ref mut fresh8 = (*config).referer;
    *fresh8 = 0 as *mut libc::c_char;
    free((*config).headerfile as *mut libc::c_void);
    let ref mut fresh9 = (*config).headerfile;
    *fresh9 = 0 as *mut libc::c_char;
    free((*config).ftpport as *mut libc::c_void);
    let ref mut fresh10 = (*config).ftpport;
    *fresh10 = 0 as *mut libc::c_char;
    free((*config).iface as *mut libc::c_void);
    let ref mut fresh11 = (*config).iface;
    *fresh11 = 0 as *mut libc::c_char;
    free((*config).range as *mut libc::c_void);
    let ref mut fresh12 = (*config).range;
    *fresh12 = 0 as *mut libc::c_char;
    free((*config).userpwd as *mut libc::c_void);
    let ref mut fresh13 = (*config).userpwd;
    *fresh13 = 0 as *mut libc::c_char;
    free((*config).tls_username as *mut libc::c_void);
    let ref mut fresh14 = (*config).tls_username;
    *fresh14 = 0 as *mut libc::c_char;
    free((*config).tls_password as *mut libc::c_void);
    let ref mut fresh15 = (*config).tls_password;
    *fresh15 = 0 as *mut libc::c_char;
    free((*config).tls_authtype as *mut libc::c_void);
    let ref mut fresh16 = (*config).tls_authtype;
    *fresh16 = 0 as *mut libc::c_char;
    free((*config).proxy_tls_username as *mut libc::c_void);
    let ref mut fresh17 = (*config).proxy_tls_username;
    *fresh17 = 0 as *mut libc::c_char;
    free((*config).proxy_tls_password as *mut libc::c_void);
    let ref mut fresh18 = (*config).proxy_tls_password;
    *fresh18 = 0 as *mut libc::c_char;
    free((*config).proxy_tls_authtype as *mut libc::c_void);
    let ref mut fresh19 = (*config).proxy_tls_authtype;
    *fresh19 = 0 as *mut libc::c_char;
    free((*config).proxyuserpwd as *mut libc::c_void);
    let ref mut fresh20 = (*config).proxyuserpwd;
    *fresh20 = 0 as *mut libc::c_char;
    free((*config).proxy as *mut libc::c_void);
    let ref mut fresh21 = (*config).proxy;
    *fresh21 = 0 as *mut libc::c_char;
    free((*config).dns_ipv6_addr as *mut libc::c_void);
    let ref mut fresh22 = (*config).dns_ipv6_addr;
    *fresh22 = 0 as *mut libc::c_char;
    free((*config).dns_ipv4_addr as *mut libc::c_void);
    let ref mut fresh23 = (*config).dns_ipv4_addr;
    *fresh23 = 0 as *mut libc::c_char;
    free((*config).dns_interface as *mut libc::c_void);
    let ref mut fresh24 = (*config).dns_interface;
    *fresh24 = 0 as *mut libc::c_char;
    free((*config).dns_servers as *mut libc::c_void);
    let ref mut fresh25 = (*config).dns_servers;
    *fresh25 = 0 as *mut libc::c_char;
    free((*config).noproxy as *mut libc::c_void);
    let ref mut fresh26 = (*config).noproxy;
    *fresh26 = 0 as *mut libc::c_char;
    free((*config).mail_from as *mut libc::c_void);
    let ref mut fresh27 = (*config).mail_from;
    *fresh27 = 0 as *mut libc::c_char;
    curl_slist_free_all((*config).mail_rcpt);
    free((*config).mail_auth as *mut libc::c_void);
    let ref mut fresh28 = (*config).mail_auth;
    *fresh28 = 0 as *mut libc::c_char;
    free((*config).netrc_file as *mut libc::c_void);
    let ref mut fresh29 = (*config).netrc_file;
    *fresh29 = 0 as *mut libc::c_char;
    free((*config).output_dir as *mut libc::c_void);
    let ref mut fresh30 = (*config).output_dir;
    *fresh30 = 0 as *mut libc::c_char;
    urlnode = (*config).url_list;
    while !urlnode.is_null() {
        let mut next: *mut getout = (*urlnode).next;
        free((*urlnode).url as *mut libc::c_void);
        let ref mut fresh31 = (*urlnode).url;
        *fresh31 = 0 as *mut libc::c_char;
        free((*urlnode).outfile as *mut libc::c_void);
        let ref mut fresh32 = (*urlnode).outfile;
        *fresh32 = 0 as *mut libc::c_char;
        free((*urlnode).infile as *mut libc::c_void);
        let ref mut fresh33 = (*urlnode).infile;
        *fresh33 = 0 as *mut libc::c_char;
        free(urlnode as *mut libc::c_void);
        urlnode = 0 as *mut getout;
        urlnode = next;
    }
    let ref mut fresh34 = (*config).url_list;
    *fresh34 = 0 as *mut getout;
    let ref mut fresh35 = (*config).url_last;
    *fresh35 = 0 as *mut getout;
    let ref mut fresh36 = (*config).url_get;
    *fresh36 = 0 as *mut getout;
    let ref mut fresh37 = (*config).url_out;
    *fresh37 = 0 as *mut getout;
    free((*config).doh_url as *mut libc::c_void);
    let ref mut fresh38 = (*config).doh_url;
    *fresh38 = 0 as *mut libc::c_char;
    free((*config).cipher_list as *mut libc::c_void);
    let ref mut fresh39 = (*config).cipher_list;
    *fresh39 = 0 as *mut libc::c_char;
    free((*config).proxy_cipher_list as *mut libc::c_void);
    let ref mut fresh40 = (*config).proxy_cipher_list;
    *fresh40 = 0 as *mut libc::c_char;
    free((*config).cert as *mut libc::c_void);
    let ref mut fresh41 = (*config).cert;
    *fresh41 = 0 as *mut libc::c_char;
    free((*config).proxy_cert as *mut libc::c_void);
    let ref mut fresh42 = (*config).proxy_cert;
    *fresh42 = 0 as *mut libc::c_char;
    free((*config).cert_type as *mut libc::c_void);
    let ref mut fresh43 = (*config).cert_type;
    *fresh43 = 0 as *mut libc::c_char;
    free((*config).proxy_cert_type as *mut libc::c_void);
    let ref mut fresh44 = (*config).proxy_cert_type;
    *fresh44 = 0 as *mut libc::c_char;
    free((*config).cacert as *mut libc::c_void);
    let ref mut fresh45 = (*config).cacert;
    *fresh45 = 0 as *mut libc::c_char;
    free((*config).login_options as *mut libc::c_void);
    let ref mut fresh46 = (*config).login_options;
    *fresh46 = 0 as *mut libc::c_char;
    free((*config).proxy_cacert as *mut libc::c_void);
    let ref mut fresh47 = (*config).proxy_cacert;
    *fresh47 = 0 as *mut libc::c_char;
    free((*config).capath as *mut libc::c_void);
    let ref mut fresh48 = (*config).capath;
    *fresh48 = 0 as *mut libc::c_char;
    free((*config).proxy_capath as *mut libc::c_void);
    let ref mut fresh49 = (*config).proxy_capath;
    *fresh49 = 0 as *mut libc::c_char;
    free((*config).crlfile as *mut libc::c_void);
    let ref mut fresh50 = (*config).crlfile;
    *fresh50 = 0 as *mut libc::c_char;
    free((*config).pinnedpubkey as *mut libc::c_void);
    let ref mut fresh51 = (*config).pinnedpubkey;
    *fresh51 = 0 as *mut libc::c_char;
    free((*config).proxy_pinnedpubkey as *mut libc::c_void);
    let ref mut fresh52 = (*config).proxy_pinnedpubkey;
    *fresh52 = 0 as *mut libc::c_char;
    free((*config).proxy_crlfile as *mut libc::c_void);
    let ref mut fresh53 = (*config).proxy_crlfile;
    *fresh53 = 0 as *mut libc::c_char;
    free((*config).key as *mut libc::c_void);
    let ref mut fresh54 = (*config).key;
    *fresh54 = 0 as *mut libc::c_char;
    free((*config).proxy_key as *mut libc::c_void);
    let ref mut fresh55 = (*config).proxy_key;
    *fresh55 = 0 as *mut libc::c_char;
    free((*config).key_type as *mut libc::c_void);
    let ref mut fresh56 = (*config).key_type;
    *fresh56 = 0 as *mut libc::c_char;
    free((*config).proxy_key_type as *mut libc::c_void);
    let ref mut fresh57 = (*config).proxy_key_type;
    *fresh57 = 0 as *mut libc::c_char;
    free((*config).key_passwd as *mut libc::c_void);
    let ref mut fresh58 = (*config).key_passwd;
    *fresh58 = 0 as *mut libc::c_char;
    free((*config).proxy_key_passwd as *mut libc::c_void);
    let ref mut fresh59 = (*config).proxy_key_passwd;
    *fresh59 = 0 as *mut libc::c_char;
    free((*config).pubkey as *mut libc::c_void);
    let ref mut fresh60 = (*config).pubkey;
    *fresh60 = 0 as *mut libc::c_char;
    free((*config).hostpubmd5 as *mut libc::c_void);
    let ref mut fresh61 = (*config).hostpubmd5;
    *fresh61 = 0 as *mut libc::c_char;
    free((*config).engine as *mut libc::c_void);
    let ref mut fresh62 = (*config).engine;
    *fresh62 = 0 as *mut libc::c_char;
    free((*config).etag_save_file as *mut libc::c_void);
    let ref mut fresh63 = (*config).etag_save_file;
    *fresh63 = 0 as *mut libc::c_char;
    free((*config).etag_compare_file as *mut libc::c_void);
    let ref mut fresh64 = (*config).etag_compare_file;
    *fresh64 = 0 as *mut libc::c_char;
    free((*config).request_target as *mut libc::c_void);
    let ref mut fresh65 = (*config).request_target;
    *fresh65 = 0 as *mut libc::c_char;
    free((*config).customrequest as *mut libc::c_void);
    let ref mut fresh66 = (*config).customrequest;
    *fresh66 = 0 as *mut libc::c_char;
    free((*config).krblevel as *mut libc::c_void);
    let ref mut fresh67 = (*config).krblevel;
    *fresh67 = 0 as *mut libc::c_char;
    free((*config).oauth_bearer as *mut libc::c_void);
    let ref mut fresh68 = (*config).oauth_bearer;
    *fresh68 = 0 as *mut libc::c_char;
    free((*config).sasl_authzid as *mut libc::c_void);
    let ref mut fresh69 = (*config).sasl_authzid;
    *fresh69 = 0 as *mut libc::c_char;
    free((*config).unix_socket_path as *mut libc::c_void);
    let ref mut fresh70 = (*config).unix_socket_path;
    *fresh70 = 0 as *mut libc::c_char;
    free((*config).writeout as *mut libc::c_void);
    let ref mut fresh71 = (*config).writeout;
    *fresh71 = 0 as *mut libc::c_char;
    free((*config).proto_default as *mut libc::c_void);
    let ref mut fresh72 = (*config).proto_default;
    *fresh72 = 0 as *mut libc::c_char;
    curl_slist_free_all((*config).quote);
    curl_slist_free_all((*config).postquote);
    curl_slist_free_all((*config).prequote);
    curl_slist_free_all((*config).headers);
    curl_slist_free_all((*config).proxyheaders);
    curl_mime_free((*config).mimepost);
    let ref mut fresh73 = (*config).mimepost;
    *fresh73 = 0 as *mut curl_mime;
    tool_mime_free((*config).mimeroot);
    let ref mut fresh74 = (*config).mimeroot;
    *fresh74 = 0 as *mut tool_mime;
    let ref mut fresh75 = (*config).mimecurrent;
    *fresh75 = 0 as *mut tool_mime;
    curl_slist_free_all((*config).telnet_options);
    curl_slist_free_all((*config).resolve);
    curl_slist_free_all((*config).connect_to);
    free((*config).preproxy as *mut libc::c_void);
    let ref mut fresh76 = (*config).preproxy;
    *fresh76 = 0 as *mut libc::c_char;
    free((*config).proxy_service_name as *mut libc::c_void);
    let ref mut fresh77 = (*config).proxy_service_name;
    *fresh77 = 0 as *mut libc::c_char;
    free((*config).service_name as *mut libc::c_void);
    let ref mut fresh78 = (*config).service_name;
    *fresh78 = 0 as *mut libc::c_char;
    free((*config).ftp_account as *mut libc::c_void);
    let ref mut fresh79 = (*config).ftp_account;
    *fresh79 = 0 as *mut libc::c_char;
    free((*config).ftp_alternative_to_user as *mut libc::c_void);
    let ref mut fresh80 = (*config).ftp_alternative_to_user;
    *fresh80 = 0 as *mut libc::c_char;
    free((*config).aws_sigv4 as *mut libc::c_void);
    let ref mut fresh81 = (*config).aws_sigv4;
    *fresh81 = 0 as *mut libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn config_free(mut config: *mut OperationConfig) {
    let mut last: *mut OperationConfig = config;
    while !last.is_null() {
        let mut prev: *mut OperationConfig = (*last).prev;
        free_config_fields(last);
        free(last as *mut libc::c_void);
        last = prev;
    }
}
