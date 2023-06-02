use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type Curl_easy;
    pub type curl_mime;
    fn fputs(__s: *const i8, __stream: *mut FILE) -> i32;
    fn curl_easy_pause(handle: *mut CURL, bitmask: i32) -> CURLcode;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    static mut transfers: *mut per_transfer;
    fn tvnow() -> timeval;
    fn tvdiff(t1: timeval, t2: timeval) -> i64;
    fn curl_msnprintf(buffer: *mut i8, maxlength: size_t, format: *const i8, _: ...) -> i32;
    fn curl_mfprintf(fd: *mut FILE, format: *const i8, _: ...) -> i32;
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
pub struct HdrCbData {
    pub global: *mut GlobalConfig,
    pub config: *mut OperationConfig,
    pub outs: *mut OutStruct,
    pub heads: *mut OutStruct,
    pub etag_save: *mut OutStruct,
    pub honor_cd_filename: bool,
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
pub struct InStruct {
    pub fd: i32,
    pub config: *mut OperationConfig,
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
pub struct speedcount {
    pub dl: curl_off_t,
    pub ul: curl_off_t,
    pub stamp: timeval,
}
extern "C" fn max5data(mut bytes: curl_off_t, mut max5: *mut i8) -> *mut i8 {
    if bytes < 100000 as i64 {
        (unsafe { curl_msnprintf(
            max5,
            6 as i32 as size_t,
            b"%5ld\0" as *const u8 as *const i8,
            bytes,
        ) });
    } else if bytes < 10000 as i64 * 1024 as i64 {
        (unsafe { curl_msnprintf(
            max5,
            6 as i32 as size_t,
            b"%4ldk\0" as *const u8 as *const i8,
            bytes / 1024 as i64,
        ) });
    } else if bytes < 100 as i64 * (1024 as i64 * 1024 as i64) {
        (unsafe { curl_msnprintf(
            max5,
            6 as i32 as size_t,
            b"%2ld.%0ldM\0" as *const u8 as *const i8,
            bytes / (1024 as i64 * 1024 as i64),
            bytes % (1024 as i64 * 1024 as i64) / (1024 as i64 * 1024 as i64 / 10 as i64),
        ) });
    } else if bytes < 10000 as i64 * (1024 as i64 * 1024 as i64) {
        (unsafe { curl_msnprintf(
            max5,
            6 as i32 as size_t,
            b"%4ldM\0" as *const u8 as *const i8,
            bytes / (1024 as i64 * 1024 as i64),
        ) });
    } else if bytes < 100 as i64 * (1024 as i64 * (1024 as i64 * 1024 as i64)) {
        (unsafe { curl_msnprintf(
            max5,
            6 as i32 as size_t,
            b"%2ld.%0ldG\0" as *const u8 as *const i8,
            bytes / (1024 as i64 * (1024 as i64 * 1024 as i64)),
            bytes % (1024 as i64 * (1024 as i64 * 1024 as i64))
                / (1024 as i64 * (1024 as i64 * 1024 as i64) / 10 as i64),
        ) });
    } else if bytes < 10000 as i64 * (1024 as i64 * (1024 as i64 * 1024 as i64)) {
        (unsafe { curl_msnprintf(
            max5,
            6 as i32 as size_t,
            b"%4ldG\0" as *const u8 as *const i8,
            bytes / (1024 as i64 * (1024 as i64 * 1024 as i64)),
        ) });
    } else if bytes < 10000 as i64 * (1024 as i64 * (1024 as i64 * (1024 as i64 * 1024 as i64))) {
        (unsafe { curl_msnprintf(
            max5,
            6 as i32 as size_t,
            b"%4ldT\0" as *const u8 as *const i8,
            bytes / (1024 as i64 * (1024 as i64 * (1024 as i64 * 1024 as i64))),
        ) });
    } else {
        (unsafe { curl_msnprintf(
            max5,
            6 as i32 as size_t,
            b"%4ldP\0" as *const u8 as *const i8,
            bytes / (1024 as i64 * (1024 as i64 * (1024 as i64 * (1024 as i64 * 1024 as i64)))),
        ) });
    }
    return max5;
}
#[no_mangle]
pub extern "C" fn xferinfo_cb(
    mut clientp: *mut libc::c_void,
    mut dltotal: curl_off_t,
    mut dlnow: curl_off_t,
    mut ultotal: curl_off_t,
    mut ulnow: curl_off_t,
) -> i32 {
    let mut per: *mut per_transfer = clientp as *mut per_transfer;
    let mut config: *mut OperationConfig = unsafe { (*per).config };
    (unsafe { (*per).dltotal = dltotal });
    (unsafe { (*per).dlnow = dlnow });
    (unsafe { (*per).ultotal = ultotal });
    (unsafe { (*per).ulnow = ulnow });
    if unsafe { (*per).abort } {
        return 1 as i32;
    }
    if unsafe { (*config).readbusy } {
        (unsafe { (*config).readbusy = 0 as i32 != 0 });
        (unsafe { curl_easy_pause((*per).curl, 0 as i32 | 0 as i32) });
    }
    return 0 as i32;
}
extern "C" fn time2str(mut r: *mut i8, mut seconds: curl_off_t) {
    let mut h: curl_off_t = 0;
    if seconds <= 0 as i32 as i64 {
        (unsafe { strcpy(r, b"--:--:--\0" as *const u8 as *const i8) });
        return;
    }
    h = seconds / 3600 as i64;
    if h <= 99 as i64 {
        let mut m: curl_off_t = (seconds - h * 3600 as i64) / 60 as i64;
        let mut s: curl_off_t = seconds - h * 3600 as i64 - m * 60 as i64;
        (unsafe { curl_msnprintf(
            r,
            9 as i32 as size_t,
            b"%2ld:%02ld:%02ld\0" as *const u8 as *const i8,
            h,
            m,
            s,
        ) });
    } else {
        let mut d: curl_off_t = seconds / 86400 as i64;
        h = (seconds - d * 86400 as i64) / 3600 as i64;
        if d <= 999 as i64 {
            (unsafe { curl_msnprintf(
                r,
                9 as i32 as size_t,
                b"%3ldd %02ldh\0" as *const u8 as *const i8,
                d,
                h,
            ) });
        } else {
            (unsafe { curl_msnprintf(
                r,
                9 as i32 as size_t,
                b"%7ldd\0" as *const u8 as *const i8,
                d,
            ) });
        }
    };
}
static mut all_dltotal: curl_off_t = 0 as i32 as curl_off_t;
static mut all_ultotal: curl_off_t = 0 as i32 as curl_off_t;
static mut all_dlalready: curl_off_t = 0 as i32 as curl_off_t;
static mut all_ulalready: curl_off_t = 0 as i32 as curl_off_t;
#[no_mangle]
pub static mut all_xfers: curl_off_t = 0 as i32 as curl_off_t;
static mut speedindex: u32 = 0;
static mut indexwrapped: bool = false;
static mut speedstore: [speedcount; 10] = [speedcount {
    dl: 0,
    ul: 0,
    stamp: timeval {
        tv_sec: 0,
        tv_usec: 0,
    },
}; 10];
#[no_mangle]
pub extern "C" fn progress_meter(
    mut global: *mut GlobalConfig,
    mut start: *mut timeval,
    mut final_0: bool,
) -> bool {
    static mut stamp: timeval = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    static mut header: bool = 0 as i32 != 0;
    let mut now: timeval = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut diff: i64 = 0;
    if unsafe { (*global).noprogress } {
        return 0 as i32 != 0;
    }
    now = unsafe { tvnow() };
    diff = unsafe { tvdiff(now, stamp) };
    if !(unsafe { header }) {
        (unsafe { header = 1 as i32 != 0 });
        (unsafe { fputs(
            b"DL% UL%  Dled  Uled  Xfers  Live   Qd Total     Current  Left    Speed\n\0"
                as *const u8 as *const i8,
            (*global).errors,
        ) });
    }
    if final_0 as i32 != 0 || diff > 500 as i32 as i64 {
        let mut time_left: [i8; 10] = [0; 10];
        let mut time_total: [i8; 10] = [0; 10];
        let mut time_spent: [i8; 10] = [0; 10];
        let mut buffer: [[i8; 6]; 3] = [[0; 6]; 3];
        let mut spent: curl_off_t = (unsafe { tvdiff(now, *start) }) / 1000 as i32 as i64;
        let mut dlpercen: [i8; 4] = *(unsafe { ::std::mem::transmute::<&[u8; 4], &mut [i8; 4]>(b"--\0\0") });
        let mut ulpercen: [i8; 4] = *(unsafe { ::std::mem::transmute::<&[u8; 4], &mut [i8; 4]>(b"--\0\0") });
        let mut per: *mut per_transfer = 0 as *mut per_transfer;
        let mut all_dlnow: curl_off_t = 0 as i32 as curl_off_t;
        let mut all_ulnow: curl_off_t = 0 as i32 as curl_off_t;
        let mut dlknown: bool = 1 as i32 != 0;
        let mut ulknown: bool = 1 as i32 != 0;
        let mut all_running: curl_off_t = 0 as i32 as curl_off_t;
        let mut all_queued: curl_off_t = 0 as i32 as curl_off_t;
        let mut speed: curl_off_t = 0 as i32 as curl_off_t;
        let mut i: u32 = 0;
        (unsafe { stamp = now });
        all_dlnow += unsafe { all_dlalready };
        all_ulnow += unsafe { all_ulalready };
        per = unsafe { transfers };
        while !per.is_null() {
            all_dlnow += unsafe { (*per).dlnow };
            all_ulnow += unsafe { (*per).ulnow };
            if (unsafe { (*per).dltotal }) == 0 {
                dlknown = 0 as i32 != 0;
            } else if !(unsafe { (*per).dltotal_added }) {
                (unsafe { all_dltotal += (*per).dltotal });
                (unsafe { (*per).dltotal_added = 1 as i32 != 0 });
            }
            if (unsafe { (*per).ultotal }) == 0 {
                ulknown = 0 as i32 != 0;
            } else if !(unsafe { (*per).ultotal_added }) {
                (unsafe { all_ultotal += (*per).ultotal });
                (unsafe { (*per).ultotal_added = 1 as i32 != 0 });
            }
            if !(unsafe { (*per).added }) {
                all_queued += 1;
            } else {
                all_running += 1;
            }
            per = unsafe { (*per).next };
        }
        if dlknown as i32 != 0 && (unsafe { all_dltotal }) != 0 {
            (unsafe { curl_msnprintf(
                dlpercen.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 4]>() as u64,
                b"%3ld\0" as *const u8 as *const i8,
                all_dlnow * 100 as i32 as i64 / all_dltotal,
            ) });
        }
        if ulknown as i32 != 0 && (unsafe { all_ultotal }) != 0 {
            (unsafe { curl_msnprintf(
                ulpercen.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 4]>() as u64,
                b"%3ld\0" as *const u8 as *const i8,
                all_ulnow * 100 as i32 as i64 / all_ultotal,
            ) });
        }
        i = unsafe { speedindex };
        (unsafe { speedstore[i as usize].dl = all_dlnow });
        (unsafe { speedstore[i as usize].ul = all_ulnow });
        (unsafe { speedstore[i as usize].stamp = now });
        (unsafe { speedindex = speedindex.wrapping_add(1) });
        if (unsafe { speedindex }) >= 10 as i32 as u32 {
            (unsafe { indexwrapped = 1 as i32 != 0 });
            (unsafe { speedindex = 0 as i32 as u32 });
        }
        let mut deltams: i64 = 0;
        let mut dl: curl_off_t = 0;
        let mut ul: curl_off_t = 0;
        let mut dls: curl_off_t = 0;
        let mut uls: curl_off_t = 0;
        if unsafe { indexwrapped } {
            deltams = unsafe { tvdiff(now, speedstore[speedindex as usize].stamp) };
            dl = all_dlnow - (unsafe { speedstore[speedindex as usize].dl });
            ul = all_ulnow - (unsafe { speedstore[speedindex as usize].ul });
        } else {
            deltams = unsafe { tvdiff(now, *start) };
            dl = all_dlnow;
            ul = all_ulnow;
        }
        dls = (dl as f64 / (deltams as f64 / 1000.0f64)) as curl_off_t;
        uls = (ul as f64 / (deltams as f64 / 1000.0f64)) as curl_off_t;
        speed = if dls > uls { dls } else { uls };
        if dlknown as i32 != 0 && speed != 0 {
            let mut est: curl_off_t = (unsafe { all_dltotal }) / speed;
            let mut left: curl_off_t = ((unsafe { all_dltotal }) - all_dlnow) / speed;
            time2str(time_left.as_mut_ptr(), left);
            time2str(time_total.as_mut_ptr(), est);
        } else {
            time2str(time_left.as_mut_ptr(), 0 as i32 as curl_off_t);
            time2str(time_total.as_mut_ptr(), 0 as i32 as curl_off_t);
        }
        time2str(time_spent.as_mut_ptr(), spent);
        (unsafe { curl_mfprintf(
            (*global).errors,
            b"\r%-3s %-3s %s %s %5ld %5ld %5ld %s %s %s %s %5s\0" as *const u8 as *const i8,
            dlpercen.as_mut_ptr(),
            ulpercen.as_mut_ptr(),
            max5data(all_dlnow, (buffer[0 as i32 as usize]).as_mut_ptr()),
            max5data(all_ulnow, (buffer[1 as i32 as usize]).as_mut_ptr()),
            all_xfers,
            all_running,
            all_queued,
            time_total.as_mut_ptr(),
            time_spent.as_mut_ptr(),
            time_left.as_mut_ptr(),
            max5data(speed, (buffer[2 as i32 as usize]).as_mut_ptr()),
            if final_0 as i32 != 0 {
                b"\n\0" as *const u8 as *const i8
            } else {
                b"\0" as *const u8 as *const i8
            },
        ) });
        return 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
#[no_mangle]
pub extern "C" fn progress_finalize(mut per: *mut per_transfer) {
    (unsafe { all_dlalready += (*per).dlnow });
    (unsafe { all_ulalready += (*per).ulnow });
    if !(unsafe { (*per).dltotal_added }) {
        (unsafe { all_dltotal += (*per).dltotal });
        (unsafe { (*per).dltotal_added = 1 as i32 != 0 });
    }
    if !(unsafe { (*per).ultotal_added }) {
        (unsafe { all_ultotal += (*per).ultotal });
        (unsafe { (*per).ultotal_added = 1 as i32 != 0 });
    }
}
