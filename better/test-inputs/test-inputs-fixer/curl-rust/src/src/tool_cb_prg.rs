use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type Curl_easy;
    pub type curl_mime;
    fn fflush(__stream: *mut FILE) -> i32;
    fn fputs(__s: *const i8, __stream: *mut FILE) -> i32;
    fn curl_getenv(variable: *const i8) -> *mut i8;
    fn curl_free(p: *mut libc::c_void);
    fn strtol(_: *const i8, _: *mut *mut i8, _: i32) -> i64;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn strlen(_: *const i8) -> u64;
    fn curl_easy_pause(handle: *mut CURL, bitmask: i32) -> CURLcode;
    fn ioctl(__fd: i32, __request: u64, _: ...) -> i32;
    fn curl_mfprintf(fd: *mut FILE, format: *const i8, _: ...) -> i32;
    fn curl_msnprintf(buffer: *mut i8, maxlength: size_t, format: *const i8, _: ...) -> i32;
    fn tvnow() -> timeval;
    fn tvdiff(t1: timeval, t2: timeval) -> i64;
}
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __time_t = i64;
pub type __suseconds_t = i64;
pub type time_t = __time_t;
pub type size_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timeval {
    pub tv_sec: __time_t,
    pub tv_usec: __suseconds_t,
}
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
pub type CURL = Curl_easy;
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
pub struct winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct OutStruct {
    pub filename: *mut i8,
    pub alloc_filename: bool,
    pub is_cd_filename: bool,
    pub s_isreg: bool,
    pub fopened: bool,
    pub stream: *mut FILE,
    pub bytes: curl_off_t,
    pub init: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct InStruct {
    pub fd: i32,
    pub config: *mut OperationConfig,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ProgressData {
    pub calls: i32,
    pub prev: curl_off_t,
    pub prevtime: timeval,
    pub width: i32,
    pub out: *mut FILE,
    pub initial_size: curl_off_t,
    pub tick: u32,
    pub bar: i32,
    pub barmove: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct per_transfer {
    pub next: *mut per_transfer,
    pub prev: *mut per_transfer,
    pub config: *mut OperationConfig,
    pub curl: *mut CURL,
    pub retry_numretries: i64,
    pub retry_sleep_default: i64,
    pub retry_sleep: i64,
    pub retrystart: timeval,
    pub this_url: *mut i8,
    pub urlnum: u32,
    pub outfile: *mut i8,
    pub infdopen: bool,
    pub infd: i32,
    pub noprogress: bool,
    pub progressbar: ProgressData,
    pub outs: OutStruct,
    pub heads: OutStruct,
    pub etag_save: OutStruct,
    pub input: InStruct,
    pub hdrcbdata: HdrCbData,
    pub num_headers: i64,
    pub was_last_header_empty: bool,
    pub errorbuffer: [i8; 256],
    pub added: bool,
    pub startat: time_t,
    pub abort: bool,
    pub dltotal: curl_off_t,
    pub dlnow: curl_off_t,
    pub ultotal: curl_off_t,
    pub ulnow: curl_off_t,
    pub dltotal_added: bool,
    pub ultotal_added: bool,
    pub separator_err: *mut i8,
    pub separator: *mut i8,
    pub uploadfile: *mut i8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HdrCbData {
    pub global: *mut GlobalConfig,
    pub config: *mut OperationConfig,
    pub outs: *mut OutStruct,
    pub heads: *mut OutStruct,
    pub etag_save: *mut OutStruct,
    pub honor_cd_filename: bool,
}
static mut sinus: [u32; 200] = [
    515704 as i32 as u32,
    531394 as i32 as u32,
    547052 as i32 as u32,
    562664 as i32 as u32,
    578214 as i32 as u32,
    593687 as i32 as u32,
    609068 as i32 as u32,
    624341 as i32 as u32,
    639491 as i32 as u32,
    654504 as i32 as u32,
    669364 as i32 as u32,
    684057 as i32 as u32,
    698568 as i32 as u32,
    712883 as i32 as u32,
    726989 as i32 as u32,
    740870 as i32 as u32,
    754513 as i32 as u32,
    767906 as i32 as u32,
    781034 as i32 as u32,
    793885 as i32 as u32,
    806445 as i32 as u32,
    818704 as i32 as u32,
    830647 as i32 as u32,
    842265 as i32 as u32,
    853545 as i32 as u32,
    864476 as i32 as u32,
    875047 as i32 as u32,
    885248 as i32 as u32,
    895069 as i32 as u32,
    904500 as i32 as u32,
    913532 as i32 as u32,
    922156 as i32 as u32,
    930363 as i32 as u32,
    938145 as i32 as u32,
    945495 as i32 as u32,
    952406 as i32 as u32,
    958870 as i32 as u32,
    964881 as i32 as u32,
    970434 as i32 as u32,
    975522 as i32 as u32,
    980141 as i32 as u32,
    984286 as i32 as u32,
    987954 as i32 as u32,
    991139 as i32 as u32,
    993840 as i32 as u32,
    996054 as i32 as u32,
    997778 as i32 as u32,
    999011 as i32 as u32,
    999752 as i32 as u32,
    999999 as i32 as u32,
    999754 as i32 as u32,
    999014 as i32 as u32,
    997783 as i32 as u32,
    996060 as i32 as u32,
    993848 as i32 as u32,
    991148 as i32 as u32,
    987964 as i32 as u32,
    984298 as i32 as u32,
    980154 as i32 as u32,
    975536 as i32 as u32,
    970449 as i32 as u32,
    964898 as i32 as u32,
    958888 as i32 as u32,
    952426 as i32 as u32,
    945516 as i32 as u32,
    938168 as i32 as u32,
    930386 as i32 as u32,
    922180 as i32 as u32,
    913558 as i32 as u32,
    904527 as i32 as u32,
    895097 as i32 as u32,
    885277 as i32 as u32,
    875077 as i32 as u32,
    864507 as i32 as u32,
    853577 as i32 as u32,
    842299 as i32 as u32,
    830682 as i32 as u32,
    818739 as i32 as u32,
    806482 as i32 as u32,
    793922 as i32 as u32,
    781072 as i32 as u32,
    767945 as i32 as u32,
    754553 as i32 as u32,
    740910 as i32 as u32,
    727030 as i32 as u32,
    712925 as i32 as u32,
    698610 as i32 as u32,
    684100 as i32 as u32,
    669407 as i32 as u32,
    654548 as i32 as u32,
    639536 as i32 as u32,
    624386 as i32 as u32,
    609113 as i32 as u32,
    593733 as i32 as u32,
    578260 as i32 as u32,
    562710 as i32 as u32,
    547098 as i32 as u32,
    531440 as i32 as u32,
    515751 as i32 as u32,
    500046 as i32 as u32,
    484341 as i32 as u32,
    468651 as i32 as u32,
    452993 as i32 as u32,
    437381 as i32 as u32,
    421830 as i32 as u32,
    406357 as i32 as u32,
    390976 as i32 as u32,
    375703 as i32 as u32,
    360552 as i32 as u32,
    345539 as i32 as u32,
    330679 as i32 as u32,
    315985 as i32 as u32,
    301474 as i32 as u32,
    287158 as i32 as u32,
    273052 as i32 as u32,
    259170 as i32 as u32,
    245525 as i32 as u32,
    232132 as i32 as u32,
    219003 as i32 as u32,
    206152 as i32 as u32,
    193590 as i32 as u32,
    181331 as i32 as u32,
    169386 as i32 as u32,
    157768 as i32 as u32,
    146487 as i32 as u32,
    135555 as i32 as u32,
    124983 as i32 as u32,
    114781 as i32 as u32,
    104959 as i32 as u32,
    95526 as i32 as u32,
    86493 as i32 as u32,
    77868 as i32 as u32,
    69660 as i32 as u32,
    61876 as i32 as u32,
    54525 as i32 as u32,
    47613 as i32 as u32,
    41147 as i32 as u32,
    35135 as i32 as u32,
    29581 as i32 as u32,
    24491 as i32 as u32,
    19871 as i32 as u32,
    15724 as i32 as u32,
    12056 as i32 as u32,
    8868 as i32 as u32,
    6166 as i32 as u32,
    3951 as i32 as u32,
    2225 as i32 as u32,
    990 as i32 as u32,
    248 as i32 as u32,
    0 as i32 as u32,
    244 as i32 as u32,
    982 as i32 as u32,
    2212 as i32 as u32,
    3933 as i32 as u32,
    6144 as i32 as u32,
    8842 as i32 as u32,
    12025 as i32 as u32,
    15690 as i32 as u32,
    19832 as i32 as u32,
    24448 as i32 as u32,
    29534 as i32 as u32,
    35084 as i32 as u32,
    41092 as i32 as u32,
    47554 as i32 as u32,
    54462 as i32 as u32,
    61809 as i32 as u32,
    69589 as i32 as u32,
    77794 as i32 as u32,
    86415 as i32 as u32,
    95445 as i32 as u32,
    104873 as i32 as u32,
    114692 as i32 as u32,
    124891 as i32 as u32,
    135460 as i32 as u32,
    146389 as i32 as u32,
    157667 as i32 as u32,
    169282 as i32 as u32,
    181224 as i32 as u32,
    193480 as i32 as u32,
    206039 as i32 as u32,
    218888 as i32 as u32,
    232015 as i32 as u32,
    245406 as i32 as u32,
    259048 as i32 as u32,
    272928 as i32 as u32,
    287032 as i32 as u32,
    301346 as i32 as u32,
    315856 as i32 as u32,
    330548 as i32 as u32,
    345407 as i32 as u32,
    360419 as i32 as u32,
    375568 as i32 as u32,
    390841 as i32 as u32,
    406221 as i32 as u32,
    421693 as i32 as u32,
    437243 as i32 as u32,
    452854 as i32 as u32,
    468513 as i32 as u32,
    484202 as i32 as u32,
    499907 as i32 as u32,
];
extern "C" fn fly(mut bar: *mut ProgressData, mut moved: bool) {
    let mut buf: [i8; 256] = [0; 256];
    let mut pos: i32 = 0;
    let mut check: i32 = (unsafe { (*bar).width }) - 2 as i32;
    (unsafe { curl_msnprintf(
        buf.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 256]>() as u64,
        b"%*s\r\0" as *const u8 as *const i8,
        (*bar).width - 1 as i32,
        b" \0" as *const u8 as *const i8,
    ) });
    (unsafe { memcpy(
        &mut *buf.as_mut_ptr().offset((*bar).bar as isize) as *mut i8 as *mut libc::c_void,
        b"-=O=-\0" as *const u8 as *const i8 as *const libc::c_void,
        5 as i32 as u64,
    ) });
    pos = (unsafe { sinus[((*bar).tick).wrapping_rem(200 as i32 as u32) as usize] })
        .wrapping_div((1000000 as i32 / check) as u32) as i32;
    buf[pos as usize] = '#' as i32 as i8;
    pos = (unsafe { sinus[((*bar).tick)
        .wrapping_add(5 as i32 as u32)
        .wrapping_rem(200 as i32 as u32) as usize] })
        .wrapping_div((1000000 as i32 / check) as u32) as i32;
    buf[pos as usize] = '#' as i32 as i8;
    pos = (unsafe { sinus[((*bar).tick)
        .wrapping_add(10 as i32 as u32)
        .wrapping_rem(200 as i32 as u32) as usize] })
        .wrapping_div((1000000 as i32 / check) as u32) as i32;
    buf[pos as usize] = '#' as i32 as i8;
    pos = (unsafe { sinus[((*bar).tick)
        .wrapping_add(15 as i32 as u32)
        .wrapping_rem(200 as i32 as u32) as usize] })
        .wrapping_div((1000000 as i32 / check) as u32) as i32;
    buf[pos as usize] = '#' as i32 as i8;
    (unsafe { fputs(buf.as_mut_ptr(), (*bar).out) });
    let fresh0 = unsafe { &mut ((*bar).tick) };
    *fresh0 = (*fresh0).wrapping_add(2 as i32 as u32);
    if (unsafe { (*bar).tick }) >= 200 as i32 as u32 {
        let fresh1 = unsafe { &mut ((*bar).tick) };
        *fresh1 = (*fresh1).wrapping_sub(200 as i32 as u32);
    }
    (unsafe { (*bar).bar += if moved as i32 != 0 {
        (*bar).barmove
    } else {
        0 as i32
    } });
    if (unsafe { (*bar).bar }) >= (unsafe { (*bar).width }) - 6 as i32 {
        (unsafe { (*bar).barmove = -(1 as i32) });
        (unsafe { (*bar).bar = (*bar).width - 6 as i32 });
    } else if (unsafe { (*bar).bar }) < 0 as i32 {
        (unsafe { (*bar).barmove = 1 as i32 });
        (unsafe { (*bar).bar = 0 as i32 });
    }
}
#[no_mangle]
pub extern "C" fn tool_progress_cb(
    mut clientp: *mut libc::c_void,
    mut dltotal: curl_off_t,
    mut dlnow: curl_off_t,
    mut ultotal: curl_off_t,
    mut ulnow: curl_off_t,
) -> i32 {
    let mut now: timeval = unsafe { tvnow() };
    let mut per: *mut per_transfer = clientp as *mut per_transfer;
    let mut config: *mut OperationConfig = unsafe { (*per).config };
    let mut bar: *mut ProgressData = unsafe { &mut (*per).progressbar };
    let mut total: curl_off_t = 0;
    let mut point: curl_off_t = 0;
    if (unsafe { (*bar).initial_size }) < 0 as i32 as i64
        || 0x7fffffffffffffff as i64 - (unsafe { (*bar).initial_size }) < dltotal + ultotal
    {
        total = 0x7fffffffffffffff as i64;
    } else {
        total = dltotal + ultotal + (unsafe { (*bar).initial_size });
    }
    if (unsafe { (*bar).initial_size }) < 0 as i32 as i64
        || 0x7fffffffffffffff as i64 - (unsafe { (*bar).initial_size }) < dlnow + ulnow
    {
        point = 0x7fffffffffffffff as i64;
    } else {
        point = dlnow + ulnow + (unsafe { (*bar).initial_size });
    }
    if (unsafe { (*bar).calls }) != 0 {
        if total != 0 {
            if (unsafe { (*bar).prev }) == point {
                return 0 as i32;
            } else {
                if (unsafe { tvdiff(now, (*bar).prevtime) }) < 100 as i64 && point < total {
                    return 0 as i32;
                }
            }
        } else {
            if (unsafe { tvdiff(now, (*bar).prevtime) }) < 100 as i64 {
                return 0 as i32;
            }
            fly(bar, point != (unsafe { (*bar).prev }));
        }
    }
    let fresh2 = unsafe { &mut ((*bar).calls) };
    *fresh2 += 1;
    if total > 0 as i32 as i64 && point != (unsafe { (*bar).prev }) {
        let mut line: [i8; 257] = [0; 257];
        let mut format: [i8; 40] = [0; 40];
        let mut frac: f64 = 0.;
        let mut percent: f64 = 0.;
        let mut barwidth: i32 = 0;
        let mut num: i32 = 0;
        if point > total {
            total = point;
        }
        frac = point as f64 / total as f64;
        percent = frac * 100.0f64;
        barwidth = (unsafe { (*bar).width }) - 7 as i32;
        num = (barwidth as f64 * frac) as i32;
        if num > 256 as i32 {
            num = 256 as i32;
        }
        (unsafe { memset(
            line.as_mut_ptr() as *mut libc::c_void,
            '#' as i32,
            num as u64,
        ) });
        line[num as usize] = '\u{0}' as i32 as i8;
        (unsafe { curl_msnprintf(
            format.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 40]>() as u64,
            b"\r%%-%ds %%5.1f%%%%\0" as *const u8 as *const i8,
            barwidth,
        ) });
        (unsafe { curl_mfprintf((*bar).out, format.as_mut_ptr(), line.as_mut_ptr(), percent) });
    }
    (unsafe { fflush((*bar).out) });
    (unsafe { (*bar).prev = point });
    (unsafe { (*bar).prevtime = now });
    if unsafe { (*config).readbusy } {
        (unsafe { (*config).readbusy = 0 as i32 != 0 });
        (unsafe { curl_easy_pause((*per).curl, 0 as i32 | 0 as i32) });
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn progressbarinit(mut bar: *mut ProgressData, mut config: *mut OperationConfig) {
    let mut colp: *mut i8 = 0 as *mut i8;
    (unsafe { memset(
        bar as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<ProgressData>() as u64,
    ) });
    if unsafe { (*config).use_resume } {
        (unsafe { (*bar).initial_size = (*config).resume_from });
    }
    colp = unsafe { curl_getenv(b"COLUMNS\0" as *const u8 as *const i8) };
    if !colp.is_null() {
        let mut endptr: *mut i8 = 0 as *mut i8;
        let mut num: i64 = unsafe { strtol(colp, &mut endptr, 10 as i32) };
        if endptr != colp
            && endptr == (unsafe { colp.offset(strlen(colp) as isize) })
            && num > 20 as i32 as i64
            && num < 10000 as i32 as i64
        {
            (unsafe { (*bar).width = num as i32 });
        }
        (unsafe { curl_free(colp as *mut libc::c_void) });
    }
    if (unsafe { (*bar).width }) == 0 {
        let mut cols: i32 = 0 as i32;
        let mut ts: winsize = winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        if (unsafe { ioctl(0 as i32, 0x5413 as i32 as u64, &mut ts as *mut winsize) }) == 0 {
            cols = ts.ws_col as i32;
        }
        if cols > 20 as i32 {
            (unsafe { (*bar).width = cols });
        }
    }
    if (unsafe { (*bar).width }) == 0 {
        (unsafe { (*bar).width = 79 as i32 });
    } else if (unsafe { (*bar).width }) > 256 as i32 {
        (unsafe { (*bar).width = 256 as i32 });
    }
    let fresh3 = unsafe { &mut ((*bar).out) };
    *fresh3 = unsafe { (*(*config).global).errors };
    (unsafe { (*bar).tick = 150 as i32 as u32 });
    (unsafe { (*bar).barmove = 1 as i32 });
}
