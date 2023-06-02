use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type curl_mime;
    static mut stdin: *mut FILE;
    fn fclose(__stream: *mut FILE) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut FILE;
    fn fgets(__s: *mut i8, __n: i32, __stream: *mut FILE) -> *mut i8;
    fn curl_free(p: *mut libc::c_void);
    fn malloc(_: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn Curl_isspace(c: i32) -> i32;
    fn curl_maprintf(format: *const i8, _: ...) -> *mut i8;
    fn config_init(config: *mut OperationConfig);
    fn getparameter(
        flag: *const i8,
        nextarg: *mut i8,
        usedarg: *mut bool,
        global: *mut GlobalConfig,
        operation: *mut OperationConfig,
    ) -> ParameterError;
    fn param2text(res: i32) -> *const i8;
    fn homedir(fname: *const i8) -> *mut i8;
    fn warnf(config: *mut GlobalConfig, fmt: *const i8, _: ...);
    fn curlx_dyn_init(s: *mut dynbuf, toobig: size_t);
    fn curlx_dyn_free(s: *mut dynbuf);
    fn curlx_dyn_add(s: *mut dynbuf, str: *const i8) -> CURLcode;
    fn curlx_dyn_reset(s: *mut dynbuf);
    fn curlx_dyn_ptr(s: *const dynbuf) -> *mut i8;
    fn curlx_dyn_len(s: *const dynbuf) -> size_t;
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
pub type ParameterError = u32;
pub const PARAM_LAST: ParameterError = 21;
pub const PARAM_CONTDISP_RESUME_FROM: ParameterError = 20;
pub const PARAM_CONTDISP_SHOW_HEADER: ParameterError = 19;
pub const PARAM_NO_NOT_BOOLEAN: ParameterError = 18;
pub const PARAM_NUMBER_TOO_LARGE: ParameterError = 17;
pub const PARAM_NO_PREFIX: ParameterError = 16;
pub const PARAM_NEXT_OPERATION: ParameterError = 15;
pub const PARAM_NO_MEM: ParameterError = 14;
pub const PARAM_LIBCURL_UNSUPPORTED_PROTOCOL: ParameterError = 13;
pub const PARAM_LIBCURL_DOESNT_SUPPORT: ParameterError = 12;
pub const PARAM_NEGATIVE_NUMERIC: ParameterError = 11;
pub const PARAM_BAD_NUMERIC: ParameterError = 10;
pub const PARAM_GOT_EXTRA_PARAMETER: ParameterError = 9;
pub const PARAM_ENGINES_REQUESTED: ParameterError = 8;
pub const PARAM_VERSION_INFO_REQUESTED: ParameterError = 7;
pub const PARAM_MANUAL_REQUESTED: ParameterError = 6;
pub const PARAM_HELP_REQUESTED: ParameterError = 5;
pub const PARAM_BAD_USE: ParameterError = 4;
pub const PARAM_REQUIRES_PARAMETER: ParameterError = 3;
pub const PARAM_OPTION_UNKNOWN: ParameterError = 2;
pub const PARAM_OPTION_AMBIGUOUS: ParameterError = 1;
pub const PARAM_OK: ParameterError = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dynbuf {
    pub bufr: *mut i8,
    pub leng: size_t,
    pub allc: size_t,
    pub toobig: size_t,
}
#[no_mangle]
pub extern "C" fn parseconfig(mut filename: *const i8, mut global: *mut GlobalConfig) -> i32 {
    let mut file: *mut FILE = 0 as *mut FILE;
    let mut usedarg: bool = 0 as i32 != 0;
    let mut rc: i32 = 0 as i32;
    let mut operation: *mut OperationConfig = unsafe { (*global).last };
    let mut pathalloc: *mut i8 = 0 as *mut i8;
    if filename.is_null() || (unsafe { *filename }) == 0 {
        let mut home: *mut i8 = unsafe { homedir(b".curlrc\0" as *const u8 as *const i8) };
        if !home.is_null() {
            pathalloc = unsafe { curl_maprintf(
                b"%s%s.curlrc\0" as *const u8 as *const i8,
                home,
                b"/\0" as *const u8 as *const i8,
            ) };
            if pathalloc.is_null() {
                (unsafe { free(home as *mut libc::c_void) });
                return 1 as i32;
            }
            filename = pathalloc;
        }
        (unsafe { free(home as *mut libc::c_void) });
        home = 0 as *mut i8;
    }
    if file.is_null() && !filename.is_null() {
        if (unsafe { strcmp(filename, b"-\0" as *const u8 as *const i8) }) != 0 {
            file = unsafe { fopen(filename, b"r\0" as *const u8 as *const i8) };
        } else {
            file = unsafe { stdin };
        }
    }
    if !file.is_null() {
        let mut line: *mut i8 = 0 as *mut i8;
        let mut option: *mut i8 = 0 as *mut i8;
        let mut param: *mut i8 = 0 as *mut i8;
        let mut lineno: i32 = 0 as i32;
        let mut dashed_option: bool = false;
        let mut buf: dynbuf = dynbuf {
            bufr: 0 as *mut i8,
            leng: 0,
            allc: 0,
            toobig: 0,
        };
        let mut fileerror: bool = false;
        (unsafe { curlx_dyn_init(&mut buf, (100 as i32 * 1024 as i32) as size_t) });
        while my_get_line(file, &mut buf, &mut fileerror) {
            let mut res: i32 = 0;
            let mut alloced_param: bool = 0 as i32 != 0;
            lineno += 1;
            line = unsafe { curlx_dyn_ptr(&mut buf) };
            if line.is_null() {
                rc = 1 as i32;
                break;
            } else {
                while (unsafe { *line }) as i32 != 0 && (unsafe { Curl_isspace(*line as u8 as i32) }) != 0 {
                    line = unsafe { line.offset(1) };
                }
                match (unsafe { *line }) as i32 {
                    35 | 47 | 13 | 10 | 42 | 0 => {
                        (unsafe { curlx_dyn_reset(&mut buf) });
                    }
                    _ => {
                        option = line;
                        dashed_option = if (unsafe { *option.offset(0 as i32 as isize) }) as i32 == '-' as i32 {
                            1 as i32
                        } else {
                            0 as i32
                        } != 0;
                        while (unsafe { *line }) as i32 != 0
                            && (unsafe { Curl_isspace(*line as u8 as i32) }) == 0
                            && !(!dashed_option
                                && ((unsafe { *line }) as i32 == '=' as i32 || (unsafe { *line }) as i32 == ':' as i32))
                        {
                            line = unsafe { line.offset(1) };
                        }
                        if (unsafe { *line }) != 0 {
                            let fresh0 = line;
                            line = unsafe { line.offset(1) };
                            (unsafe { *fresh0 = '\u{0}' as i32 as i8 });
                        }
                        while (unsafe { *line }) as i32 != 0
                            && ((unsafe { Curl_isspace(*line as u8 as i32) }) != 0
                                || !dashed_option
                                    && ((unsafe { *line }) as i32 == '=' as i32 || (unsafe { *line }) as i32 == ':' as i32))
                        {
                            line = unsafe { line.offset(1) };
                        }
                        if (unsafe { *line }) as i32 == '"' as i32 {
                            line = unsafe { line.offset(1) };
                            param = (unsafe { malloc((strlen(line)).wrapping_add(1 as i32 as u64)) }) as *mut i8;
                            if param.is_null() {
                                rc = 1 as i32;
                                break;
                            } else {
                                alloced_param = 1 as i32 != 0;
                                unslashquote(line, param);
                            }
                        } else {
                            param = line;
                            while (unsafe { *line }) as i32 != 0 && (unsafe { Curl_isspace(*line as u8 as i32) }) == 0 {
                                line = unsafe { line.offset(1) };
                            }
                            if (unsafe { *line }) != 0 {
                                (unsafe { *line = '\u{0}' as i32 as i8 });
                                line = unsafe { line.offset(1) };
                                while (unsafe { *line }) as i32 != 0 && (unsafe { Curl_isspace(*line as u8 as i32) }) != 0 {
                                    line = unsafe { line.offset(1) };
                                }
                                match (unsafe { *line }) as i32 {
                                    0 | 13 | 10 | 35 => {}
                                    _ => {
                                        (unsafe { warnf ((* operation) . global , b"%s:%d: warning: '%s' uses unquoted whitespace in the line that may cause side-effects!\n\0" as * const u8 as * const i8 , filename , lineno , option ,) }) ;
                                    }
                                }
                            }
                            if (unsafe { *param }) == 0 {
                                param = 0 as *mut i8;
                            }
                        }
                        res = (unsafe { getparameter(option, param, &mut usedarg, global, operation) }) as i32;
                        operation = unsafe { (*global).last };
                        if res == 0 && !param.is_null() && (unsafe { *param }) as i32 != 0 && !usedarg {
                            res = PARAM_GOT_EXTRA_PARAMETER as i32;
                        }
                        if res == PARAM_NEXT_OPERATION as i32 {
                            if !(unsafe { (*operation).url_list }).is_null()
                                && !(unsafe { (*(*operation).url_list).url }).is_null()
                            {
                                let fresh1 = unsafe { &mut ((*operation).next) };
                                *fresh1 = (unsafe { malloc(::std::mem::size_of::<OperationConfig>() as u64) })
                                    as *mut OperationConfig;
                                if !(unsafe { (*operation).next }).is_null() {
                                    (unsafe { config_init((*operation).next) });
                                    let fresh2 = unsafe { &mut ((*(*operation).next).global) };
                                    *fresh2 = global;
                                    let fresh3 = unsafe { &mut ((*global).last) };
                                    *fresh3 = unsafe { (*operation).next };
                                    let fresh4 = unsafe { &mut ((*(*operation).next).prev) };
                                    *fresh4 = operation;
                                    operation = unsafe { (*operation).next };
                                } else {
                                    res = PARAM_NO_MEM as i32;
                                }
                            }
                        }
                        if res != PARAM_OK as i32 && res != PARAM_NEXT_OPERATION as i32 {
                            if (unsafe { strcmp(filename, b"-\0" as *const u8 as *const i8) }) == 0 {
                                filename = b"<stdin>\0" as *const u8 as *const i8;
                            }
                            if res != PARAM_HELP_REQUESTED as i32
                                && res != PARAM_MANUAL_REQUESTED as i32
                                && res != PARAM_VERSION_INFO_REQUESTED as i32
                                && res != PARAM_ENGINES_REQUESTED as i32
                            {
                                let mut reason: *const i8 = unsafe { param2text(res) };
                                (unsafe { warnf(
                                    (*operation).global,
                                    b"%s:%d: warning: '%s' %s\n\0" as *const u8 as *const i8,
                                    filename,
                                    lineno,
                                    option,
                                    reason,
                                ) });
                            }
                        }
                        if alloced_param {
                            (unsafe { free(param as *mut libc::c_void) });
                            param = 0 as *mut i8;
                        }
                        (unsafe { curlx_dyn_reset(&mut buf) });
                    }
                }
            }
        }
        (unsafe { curlx_dyn_free(&mut buf) });
        if file != (unsafe { stdin }) {
            (unsafe { fclose(file) });
        }
        if fileerror {
            rc = 1 as i32;
        }
    } else {
        rc = 1 as i32;
    }
    (unsafe { curl_free(pathalloc as *mut libc::c_void) });
    return rc;
}
extern "C" fn unslashquote(mut line: *const i8, mut param: *mut i8) -> *const i8 {
    while (unsafe { *line }) as i32 != 0 && (unsafe { *line }) as i32 != '"' as i32 {
        if (unsafe { *line }) as i32 == '\\' as i32 {
            let mut out: i8 = 0;
            line = unsafe { line.offset(1) };
            out = unsafe { *line };
            match out as i32 {
                0 => {
                    continue;
                }
                116 => {
                    out = '\t' as i32 as i8;
                }
                110 => {
                    out = '\n' as i32 as i8;
                }
                114 => {
                    out = '\r' as i32 as i8;
                }
                118 => {
                    out = '\u{b}' as i32 as i8;
                }
                _ => {}
            }
            let fresh5 = param;
            param = unsafe { param.offset(1) };
            (unsafe { *fresh5 = out });
            line = unsafe { line.offset(1) };
        } else {
            let fresh6 = line;
            line = unsafe { line.offset(1) };
            let fresh7 = param;
            param = unsafe { param.offset(1) };
            (unsafe { *fresh7 = *fresh6 });
        }
    }
    (unsafe { *param = '\u{0}' as i32 as i8 });
    return line;
}
extern "C" fn my_get_line(mut fp: *mut FILE, mut db: *mut dynbuf, mut error: *mut bool) -> bool {
    let mut buf: [i8; 4096] = [0; 4096];
    (unsafe { *error = 0 as i32 != 0 });
    loop {
        if (unsafe { fgets(
            buf.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 4096]>() as u64 as i32,
            fp,
        ) })
        .is_null()
        {
            return if (unsafe { curlx_dyn_len(db) }) != 0 {
                1 as i32
            } else {
                0 as i32
            } != 0;
        }
        if (unsafe { curlx_dyn_add(db, buf.as_mut_ptr()) }) as u64 != 0 {
            (unsafe { *error = 1 as i32 != 0 });
            return 0 as i32 != 0;
        }
        if !(unsafe { strchr(buf.as_mut_ptr(), '\n' as i32) }).is_null() {
            break;
        }
    }
    return 1 as i32 != 0;
}
