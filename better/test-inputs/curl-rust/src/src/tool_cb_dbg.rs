use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type Curl_easy;
    pub type curl_mime;
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    fn fputc(__c: libc::c_int, __stream: *mut FILE) -> libc::c_int;
    fn fputs(__s: *const libc::c_char, __stream: *mut FILE) -> libc::c_int;
    fn fwrite(
        _: *const libc::c_void,
        _: libc::c_ulong,
        _: libc::c_ulong,
        _: *mut FILE,
    ) -> libc::c_ulong;
    fn time(__timer: *mut time_t) -> time_t;
    fn localtime(__timer: *const time_t) -> *mut tm;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn curl_mfprintf(fd: *mut FILE, format: *const libc::c_char, _: ...) -> libc::c_int;
    fn curl_msnprintf(
        buffer: *mut libc::c_char,
        maxlength: size_t,
        format: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn warnf(config: *mut GlobalConfig, fmt: *const libc::c_char, _: ...);
    fn tvnow() -> timeval;
}
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __suseconds_t = libc::c_long;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timeval {
    pub tv_sec: __time_t,
    pub tv_usec: __suseconds_t,
}
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
pub type CURL = Curl_easy;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_slist {
    pub data: *mut libc::c_char,
    pub next: *mut curl_slist,
}
pub type curl_infotype = libc::c_uint;
pub const CURLINFO_END: curl_infotype = 7;
pub const CURLINFO_SSL_DATA_OUT: curl_infotype = 6;
pub const CURLINFO_SSL_DATA_IN: curl_infotype = 5;
pub const CURLINFO_DATA_OUT: curl_infotype = 4;
pub const CURLINFO_DATA_IN: curl_infotype = 3;
pub const CURLINFO_HEADER_OUT: curl_infotype = 2;
pub const CURLINFO_HEADER_IN: curl_infotype = 1;
pub const CURLINFO_TEXT: curl_infotype = 0;
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
pub unsafe extern "C" fn tool_debug_cb(
    mut handle: *mut CURL,
    mut type_0: curl_infotype,
    mut data: *mut libc::c_char,
    mut size: size_t,
    mut userdata: *mut libc::c_void,
) -> libc::c_int {
    let mut operation: *mut OperationConfig = userdata as *mut OperationConfig;
    let mut config: *mut GlobalConfig = (*operation).global;
    let mut output: *mut FILE = (*config).errors;
    let mut text: *const libc::c_char = 0 as *const libc::c_char;
    let mut tv: timeval = timeval { tv_sec: 0, tv_usec: 0 };
    let mut timebuf: [libc::c_char; 20] = [0; 20];
    let mut secs: time_t = 0;
    if (*config).tracetime {
        let mut now: *mut tm = 0 as *mut tm;
        static mut epoch_offset: time_t = 0;
        static mut known_offset: libc::c_int = 0;
        tv = tvnow();
        if known_offset == 0 {
            epoch_offset = time(0 as *mut time_t) - tv.tv_sec;
            known_offset = 1 as libc::c_int;
        }
        secs = epoch_offset + tv.tv_sec;
        now = localtime(&mut secs);
        curl_msnprintf(
            timebuf.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 20]>() as libc::c_ulong,
            b"%02d:%02d:%02d.%06ld \0" as *const u8 as *const libc::c_char,
            (*now).tm_hour,
            (*now).tm_min,
            (*now).tm_sec,
            tv.tv_usec,
        );
    } else {
        timebuf[0 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
    }
    if ((*config).trace_stream).is_null() {
        if strcmp(b"-\0" as *const u8 as *const libc::c_char, (*config).trace_dump) == 0
        {
            let ref mut fresh0 = (*config).trace_stream;
            *fresh0 = stdout;
        } else if strcmp(
                b"%\0" as *const u8 as *const libc::c_char,
                (*config).trace_dump,
            ) == 0
            {
            let ref mut fresh1 = (*config).trace_stream;
            *fresh1 = (*config).errors;
        } else {
            let ref mut fresh2 = (*config).trace_stream;
            *fresh2 = fopen(
                (*config).trace_dump,
                b"w\0" as *const u8 as *const libc::c_char,
            );
            (*config).trace_fopened = 1 as libc::c_int != 0;
        }
    }
    if !((*config).trace_stream).is_null() {
        output = (*config).trace_stream;
    }
    if output.is_null() {
        warnf(
            config,
            b"Failed to create/open output\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    if (*config).tracetype as libc::c_uint == TRACE_PLAIN as libc::c_int as libc::c_uint
    {
        static mut s_infotype: [*const libc::c_char; 7] = [
            b"*\0" as *const u8 as *const libc::c_char,
            b"<\0" as *const u8 as *const libc::c_char,
            b">\0" as *const u8 as *const libc::c_char,
            b"{\0" as *const u8 as *const libc::c_char,
            b"}\0" as *const u8 as *const libc::c_char,
            b"{\0" as *const u8 as *const libc::c_char,
            b"}\0" as *const u8 as *const libc::c_char,
        ];
        static mut newl: bool = 0 as libc::c_int != 0;
        static mut traced_data: bool = 0 as libc::c_int != 0;
        match type_0 as libc::c_uint {
            2 => {
                if size > 0 as libc::c_int as libc::c_ulong {
                    let mut st: size_t = 0 as libc::c_int as size_t;
                    let mut i: size_t = 0;
                    i = 0 as libc::c_int as size_t;
                    while i < size.wrapping_sub(1 as libc::c_int as libc::c_ulong) {
                        if *data.offset(i as isize) as libc::c_int == '\n' as i32 {
                            if !newl {
                                curl_mfprintf(
                                    output,
                                    b"%s%s \0" as *const u8 as *const libc::c_char,
                                    timebuf.as_mut_ptr(),
                                    s_infotype[type_0 as usize],
                                );
                            }
                            fwrite(
                                data.offset(st as isize) as *const libc::c_void,
                                i
                                    .wrapping_sub(st)
                                    .wrapping_add(1 as libc::c_int as libc::c_ulong),
                                1 as libc::c_int as libc::c_ulong,
                                output,
                            );
                            st = i.wrapping_add(1 as libc::c_int as libc::c_ulong);
                            newl = 0 as libc::c_int != 0;
                        }
                        i = i.wrapping_add(1);
                    }
                    if !newl {
                        curl_mfprintf(
                            output,
                            b"%s%s \0" as *const u8 as *const libc::c_char,
                            timebuf.as_mut_ptr(),
                            s_infotype[type_0 as usize],
                        );
                    }
                    fwrite(
                        data.offset(st as isize) as *const libc::c_void,
                        i
                            .wrapping_sub(st)
                            .wrapping_add(1 as libc::c_int as libc::c_ulong),
                        1 as libc::c_int as libc::c_ulong,
                        output,
                    );
                }
                newl = if size != 0
                    && *data
                        .offset(
                            size.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                        ) as libc::c_int != '\n' as i32
                {
                    1 as libc::c_int
                } else {
                    0 as libc::c_int
                } != 0;
                traced_data = 0 as libc::c_int != 0;
            }
            0 | 1 => {
                if !newl {
                    curl_mfprintf(
                        output,
                        b"%s%s \0" as *const u8 as *const libc::c_char,
                        timebuf.as_mut_ptr(),
                        s_infotype[type_0 as usize],
                    );
                }
                fwrite(
                    data as *const libc::c_void,
                    size,
                    1 as libc::c_int as libc::c_ulong,
                    output,
                );
                newl = if size != 0
                    && *data
                        .offset(
                            size.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                        ) as libc::c_int != '\n' as i32
                {
                    1 as libc::c_int
                } else {
                    0 as libc::c_int
                } != 0;
                traced_data = 0 as libc::c_int != 0;
            }
            4 | 3 | 5 | 6 => {
                if !traced_data {
                    if !(*config).isatty || output != stderr && output != stdout {
                        if !newl {
                            curl_mfprintf(
                                output,
                                b"%s%s \0" as *const u8 as *const libc::c_char,
                                timebuf.as_mut_ptr(),
                                s_infotype[type_0 as usize],
                            );
                        }
                        curl_mfprintf(
                            output,
                            b"[%zu bytes data]\n\0" as *const u8 as *const libc::c_char,
                            size,
                        );
                        newl = 0 as libc::c_int != 0;
                        traced_data = 1 as libc::c_int != 0;
                    }
                }
            }
            _ => {
                newl = 0 as libc::c_int != 0;
                traced_data = 0 as libc::c_int != 0;
            }
        }
        return 0 as libc::c_int;
    }
    let mut current_block_72: u64;
    match type_0 as libc::c_uint {
        0 => {
            curl_mfprintf(
                output,
                b"%s== Info: %.*s\0" as *const u8 as *const libc::c_char,
                timebuf.as_mut_ptr(),
                size as libc::c_int,
                data,
            );
            current_block_72 = 7639355510481400074;
        }
        2 => {
            text = b"=> Send header\0" as *const u8 as *const libc::c_char;
            current_block_72 = 12027283704867122503;
        }
        4 => {
            text = b"=> Send data\0" as *const u8 as *const libc::c_char;
            current_block_72 = 12027283704867122503;
        }
        1 => {
            text = b"<= Recv header\0" as *const u8 as *const libc::c_char;
            current_block_72 = 12027283704867122503;
        }
        3 => {
            text = b"<= Recv data\0" as *const u8 as *const libc::c_char;
            current_block_72 = 12027283704867122503;
        }
        5 => {
            text = b"<= Recv SSL data\0" as *const u8 as *const libc::c_char;
            current_block_72 = 12027283704867122503;
        }
        6 => {
            text = b"=> Send SSL data\0" as *const u8 as *const libc::c_char;
            current_block_72 = 12027283704867122503;
        }
        _ => {
            current_block_72 = 7639355510481400074;
        }
    }
    match current_block_72 {
        12027283704867122503 => {}
        _ => return 0 as libc::c_int,
    }
    dump(
        timebuf.as_mut_ptr(),
        text,
        output,
        data as *mut libc::c_uchar,
        size,
        (*config).tracetype,
        type_0,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn dump(
    mut timebuf: *const libc::c_char,
    mut text: *const libc::c_char,
    mut stream: *mut FILE,
    mut ptr: *const libc::c_uchar,
    mut size: size_t,
    mut tracetype: trace,
    mut infotype: curl_infotype,
) {
    let mut i: size_t = 0;
    let mut c: size_t = 0;
    let mut width: libc::c_uint = 0x10 as libc::c_int as libc::c_uint;
    if tracetype as libc::c_uint == TRACE_ASCII as libc::c_int as libc::c_uint {
        width = 0x40 as libc::c_int as libc::c_uint;
    }
    curl_mfprintf(
        stream,
        b"%s%s, %zu bytes (0x%zx)\n\0" as *const u8 as *const libc::c_char,
        timebuf,
        text,
        size,
        size,
    );
    i = 0 as libc::c_int as size_t;
    while i < size {
        curl_mfprintf(stream, b"%04zx: \0" as *const u8 as *const libc::c_char, i);
        if tracetype as libc::c_uint == TRACE_BIN as libc::c_int as libc::c_uint {
            c = 0 as libc::c_int as size_t;
            while c < width as libc::c_ulong {
                if i.wrapping_add(c) < size {
                    curl_mfprintf(
                        stream,
                        b"%02x \0" as *const u8 as *const libc::c_char,
                        *ptr.offset(i.wrapping_add(c) as isize) as libc::c_int,
                    );
                } else {
                    fputs(b"   \0" as *const u8 as *const libc::c_char, stream);
                }
                c = c.wrapping_add(1);
            }
        }
        c = 0 as libc::c_int as size_t;
        while c < width as libc::c_ulong && i.wrapping_add(c) < size {
            if tracetype as libc::c_uint == TRACE_ASCII as libc::c_int as libc::c_uint
                && i.wrapping_add(c).wrapping_add(1 as libc::c_int as libc::c_ulong)
                    < size
                && *ptr.offset(i.wrapping_add(c) as isize) as libc::c_int
                    == 0xd as libc::c_int
                && *ptr
                    .offset(
                        i.wrapping_add(c).wrapping_add(1 as libc::c_int as libc::c_ulong)
                            as isize,
                    ) as libc::c_int == 0xa as libc::c_int
            {
                i = (i as libc::c_ulong)
                    .wrapping_add(
                        c
                            .wrapping_add(2 as libc::c_int as libc::c_ulong)
                            .wrapping_sub(width as libc::c_ulong),
                    ) as size_t as size_t;
                break;
            } else {
                curl_mfprintf(
                    stream,
                    b"%c\0" as *const u8 as *const libc::c_char,
                    if *ptr.offset(i.wrapping_add(c) as isize) as libc::c_int
                        >= 0x20 as libc::c_int
                        && (*ptr.offset(i.wrapping_add(c) as isize) as libc::c_int)
                            < 0x80 as libc::c_int
                    {
                        *ptr.offset(i.wrapping_add(c) as isize) as libc::c_int
                    } else {
                        '.' as i32
                    },
                );
                if tracetype as libc::c_uint
                    == TRACE_ASCII as libc::c_int as libc::c_uint
                    && i.wrapping_add(c).wrapping_add(2 as libc::c_int as libc::c_ulong)
                        < size
                    && *ptr
                        .offset(
                            i
                                .wrapping_add(c)
                                .wrapping_add(1 as libc::c_int as libc::c_ulong) as isize,
                        ) as libc::c_int == 0xd as libc::c_int
                    && *ptr
                        .offset(
                            i
                                .wrapping_add(c)
                                .wrapping_add(2 as libc::c_int as libc::c_ulong) as isize,
                        ) as libc::c_int == 0xa as libc::c_int
                {
                    i = (i as libc::c_ulong)
                        .wrapping_add(
                            c
                                .wrapping_add(3 as libc::c_int as libc::c_ulong)
                                .wrapping_sub(width as libc::c_ulong),
                        ) as size_t as size_t;
                    break;
                } else {
                    c = c.wrapping_add(1);
                }
            }
        }
        fputc('\n' as i32, stream);
        i = (i as libc::c_ulong).wrapping_add(width as libc::c_ulong) as size_t
            as size_t;
    }
    fflush(stream);
}
