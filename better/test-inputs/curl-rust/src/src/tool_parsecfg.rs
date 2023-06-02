use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type curl_mime;
    static mut stdin: *mut FILE;
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    fn fgets(
        __s: *mut libc::c_char,
        __n: libc::c_int,
        __stream: *mut FILE,
    ) -> *mut libc::c_char;
    fn curl_free(p: *mut libc::c_void);
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn Curl_isspace(c: libc::c_int) -> libc::c_int;
    fn curl_maprintf(format: *const libc::c_char, _: ...) -> *mut libc::c_char;
    fn config_init(config: *mut OperationConfig);
    fn getparameter(
        flag: *const libc::c_char,
        nextarg: *mut libc::c_char,
        usedarg: *mut bool,
        global: *mut GlobalConfig,
        operation: *mut OperationConfig,
    ) -> ParameterError;
    fn param2text(res: libc::c_int) -> *const libc::c_char;
    fn homedir(fname: *const libc::c_char) -> *mut libc::c_char;
    fn warnf(config: *mut GlobalConfig, fmt: *const libc::c_char, _: ...);
    fn curlx_dyn_init(s: *mut dynbuf, toobig: size_t);
    fn curlx_dyn_free(s: *mut dynbuf);
    fn curlx_dyn_add(s: *mut dynbuf, str: *const libc::c_char) -> CURLcode;
    fn curlx_dyn_reset(s: *mut dynbuf);
    fn curlx_dyn_ptr(s: *const dynbuf) -> *mut libc::c_char;
    fn curlx_dyn_len(s: *const dynbuf) -> size_t;
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
pub type ParameterError = libc::c_uint;
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
    pub bufr: *mut libc::c_char,
    pub leng: size_t,
    pub allc: size_t,
    pub toobig: size_t,
}
#[no_mangle]
pub unsafe extern "C" fn parseconfig(
    mut filename: *const libc::c_char,
    mut global: *mut GlobalConfig,
) -> libc::c_int {
    let mut file: *mut FILE = 0 as *mut FILE;
    let mut usedarg: bool = 0 as libc::c_int != 0;
    let mut rc: libc::c_int = 0 as libc::c_int;
    let mut operation: *mut OperationConfig = (*global).last;
    let mut pathalloc: *mut libc::c_char = 0 as *mut libc::c_char;
    if filename.is_null() || *filename == 0 {
        let mut home: *mut libc::c_char = homedir(
            b".curlrc\0" as *const u8 as *const libc::c_char,
        );
        if !home.is_null() {
            pathalloc = curl_maprintf(
                b"%s%s.curlrc\0" as *const u8 as *const libc::c_char,
                home,
                b"/\0" as *const u8 as *const libc::c_char,
            );
            if pathalloc.is_null() {
                free(home as *mut libc::c_void);
                return 1 as libc::c_int;
            }
            filename = pathalloc;
        }
        free(home as *mut libc::c_void);
        home = 0 as *mut libc::c_char;
    }
    if file.is_null() && !filename.is_null() {
        if strcmp(filename, b"-\0" as *const u8 as *const libc::c_char) != 0 {
            file = fopen(filename, b"r\0" as *const u8 as *const libc::c_char);
        } else {
            file = stdin;
        }
    }
    if !file.is_null() {
        let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut option: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut param: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut lineno: libc::c_int = 0 as libc::c_int;
        let mut dashed_option: bool = false;
        let mut buf: dynbuf = dynbuf {
            bufr: 0 as *mut libc::c_char,
            leng: 0,
            allc: 0,
            toobig: 0,
        };
        let mut fileerror: bool = false;
        curlx_dyn_init(&mut buf, (100 as libc::c_int * 1024 as libc::c_int) as size_t);
        while my_get_line(file, &mut buf, &mut fileerror) {
            let mut res: libc::c_int = 0;
            let mut alloced_param: bool = 0 as libc::c_int != 0;
            lineno += 1;
            line = curlx_dyn_ptr(&mut buf);
            if line.is_null() {
                rc = 1 as libc::c_int;
                break;
            } else {
                while *line as libc::c_int != 0
                    && Curl_isspace(*line as libc::c_uchar as libc::c_int) != 0
                {
                    line = line.offset(1);
                }
                match *line as libc::c_int {
                    35 | 47 | 13 | 10 | 42 | 0 => {
                        curlx_dyn_reset(&mut buf);
                    }
                    _ => {
                        option = line;
                        dashed_option = if *option.offset(0 as libc::c_int as isize)
                            as libc::c_int == '-' as i32
                        {
                            1 as libc::c_int
                        } else {
                            0 as libc::c_int
                        } != 0;
                        while *line as libc::c_int != 0
                            && Curl_isspace(*line as libc::c_uchar as libc::c_int) == 0
                            && !(!dashed_option
                                && (*line as libc::c_int == '=' as i32
                                    || *line as libc::c_int == ':' as i32))
                        {
                            line = line.offset(1);
                        }
                        if *line != 0 {
                            let fresh0 = line;
                            line = line.offset(1);
                            *fresh0 = '\u{0}' as i32 as libc::c_char;
                        }
                        while *line as libc::c_int != 0
                            && (Curl_isspace(*line as libc::c_uchar as libc::c_int) != 0
                                || !dashed_option
                                    && (*line as libc::c_int == '=' as i32
                                        || *line as libc::c_int == ':' as i32))
                        {
                            line = line.offset(1);
                        }
                        if *line as libc::c_int == '"' as i32 {
                            line = line.offset(1);
                            param = malloc(
                                (strlen(line))
                                    .wrapping_add(1 as libc::c_int as libc::c_ulong),
                            ) as *mut libc::c_char;
                            if param.is_null() {
                                rc = 1 as libc::c_int;
                                break;
                            } else {
                                alloced_param = 1 as libc::c_int != 0;
                                unslashquote(line, param);
                            }
                        } else {
                            param = line;
                            while *line as libc::c_int != 0
                                && Curl_isspace(*line as libc::c_uchar as libc::c_int) == 0
                            {
                                line = line.offset(1);
                            }
                            if *line != 0 {
                                *line = '\u{0}' as i32 as libc::c_char;
                                line = line.offset(1);
                                while *line as libc::c_int != 0
                                    && Curl_isspace(*line as libc::c_uchar as libc::c_int) != 0
                                {
                                    line = line.offset(1);
                                }
                                match *line as libc::c_int {
                                    0 | 13 | 10 | 35 => {}
                                    _ => {
                                        warnf(
                                            (*operation).global,
                                            b"%s:%d: warning: '%s' uses unquoted whitespace in the line that may cause side-effects!\n\0"
                                                as *const u8 as *const libc::c_char,
                                            filename,
                                            lineno,
                                            option,
                                        );
                                    }
                                }
                            }
                            if *param == 0 {
                                param = 0 as *mut libc::c_char;
                            }
                        }
                        res = getparameter(
                            option,
                            param,
                            &mut usedarg,
                            global,
                            operation,
                        ) as libc::c_int;
                        operation = (*global).last;
                        if res == 0 && !param.is_null() && *param as libc::c_int != 0
                            && !usedarg
                        {
                            res = PARAM_GOT_EXTRA_PARAMETER as libc::c_int;
                        }
                        if res == PARAM_NEXT_OPERATION as libc::c_int {
                            if !((*operation).url_list).is_null()
                                && !((*(*operation).url_list).url).is_null()
                            {
                                let ref mut fresh1 = (*operation).next;
                                *fresh1 = malloc(
                                    ::std::mem::size_of::<OperationConfig>() as libc::c_ulong,
                                ) as *mut OperationConfig;
                                if !((*operation).next).is_null() {
                                    config_init((*operation).next);
                                    let ref mut fresh2 = (*(*operation).next).global;
                                    *fresh2 = global;
                                    let ref mut fresh3 = (*global).last;
                                    *fresh3 = (*operation).next;
                                    let ref mut fresh4 = (*(*operation).next).prev;
                                    *fresh4 = operation;
                                    operation = (*operation).next;
                                } else {
                                    res = PARAM_NO_MEM as libc::c_int;
                                }
                            }
                        }
                        if res != PARAM_OK as libc::c_int
                            && res != PARAM_NEXT_OPERATION as libc::c_int
                        {
                            if strcmp(
                                filename,
                                b"-\0" as *const u8 as *const libc::c_char,
                            ) == 0
                            {
                                filename = b"<stdin>\0" as *const u8 as *const libc::c_char;
                            }
                            if res != PARAM_HELP_REQUESTED as libc::c_int
                                && res != PARAM_MANUAL_REQUESTED as libc::c_int
                                && res != PARAM_VERSION_INFO_REQUESTED as libc::c_int
                                && res != PARAM_ENGINES_REQUESTED as libc::c_int
                            {
                                let mut reason: *const libc::c_char = param2text(res);
                                warnf(
                                    (*operation).global,
                                    b"%s:%d: warning: '%s' %s\n\0" as *const u8
                                        as *const libc::c_char,
                                    filename,
                                    lineno,
                                    option,
                                    reason,
                                );
                            }
                        }
                        if alloced_param {
                            free(param as *mut libc::c_void);
                            param = 0 as *mut libc::c_char;
                        }
                        curlx_dyn_reset(&mut buf);
                    }
                }
            }
        }
        curlx_dyn_free(&mut buf);
        if file != stdin {
            fclose(file);
        }
        if fileerror {
            rc = 1 as libc::c_int;
        }
    } else {
        rc = 1 as libc::c_int;
    }
    curl_free(pathalloc as *mut libc::c_void);
    return rc;
}
unsafe extern "C" fn unslashquote(
    mut line: *const libc::c_char,
    mut param: *mut libc::c_char,
) -> *const libc::c_char {
    while *line as libc::c_int != 0 && *line as libc::c_int != '"' as i32 {
        if *line as libc::c_int == '\\' as i32 {
            let mut out: libc::c_char = 0;
            line = line.offset(1);
            out = *line;
            match out as libc::c_int {
                0 => {
                    continue;
                }
                116 => {
                    out = '\t' as i32 as libc::c_char;
                }
                110 => {
                    out = '\n' as i32 as libc::c_char;
                }
                114 => {
                    out = '\r' as i32 as libc::c_char;
                }
                118 => {
                    out = '\u{b}' as i32 as libc::c_char;
                }
                _ => {}
            }
            let fresh5 = param;
            param = param.offset(1);
            *fresh5 = out;
            line = line.offset(1);
        } else {
            let fresh6 = line;
            line = line.offset(1);
            let fresh7 = param;
            param = param.offset(1);
            *fresh7 = *fresh6;
        }
    }
    *param = '\u{0}' as i32 as libc::c_char;
    return line;
}
unsafe extern "C" fn my_get_line(
    mut fp: *mut FILE,
    mut db: *mut dynbuf,
    mut error: *mut bool,
) -> bool {
    let mut buf: [libc::c_char; 4096] = [0; 4096];
    *error = 0 as libc::c_int != 0;
    loop {
        if (fgets(
            buf.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong
                as libc::c_int,
            fp,
        ))
            .is_null()
        {
            return if curlx_dyn_len(db) != 0 {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            } != 0;
        }
        if curlx_dyn_add(db, buf.as_mut_ptr()) as u64 != 0 {
            *error = 1 as libc::c_int != 0;
            return 0 as libc::c_int != 0;
        }
        if !(strchr(buf.as_mut_ptr(), '\n' as i32)).is_null() {
            break;
        }
    }
    return 1 as libc::c_int != 0;
}
