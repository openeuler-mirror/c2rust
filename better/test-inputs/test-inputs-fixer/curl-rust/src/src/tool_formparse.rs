use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type Curl_easy;
    pub type curl_mime;
    pub type curl_mimepart;
    static mut stdin: *mut FILE;
    fn Curl_isspace(c: i32) -> i32;
    fn curl_strnequal(s1: *const i8, s2: *const i8, n: size_t) -> i32;
    fn curl_mime_init(easy: *mut CURL) -> *mut curl_mime;
    fn curl_mime_free(mime: *mut curl_mime);
    fn curl_mime_addpart(mime: *mut curl_mime) -> *mut curl_mimepart;
    fn curl_mime_name(part: *mut curl_mimepart, name: *const i8) -> CURLcode;
    fn curl_mime_filename(part: *mut curl_mimepart, filename: *const i8) -> CURLcode;
    fn curl_mime_type(part: *mut curl_mimepart, mimetype: *const i8) -> CURLcode;
    fn curl_mime_encoder(part: *mut curl_mimepart, encoding: *const i8) -> CURLcode;
    fn curl_mime_data(part: *mut curl_mimepart, data: *const i8, datasize: size_t) -> CURLcode;
    fn curl_mime_filedata(part: *mut curl_mimepart, filename: *const i8) -> CURLcode;
    fn curl_mime_data_cb(
        part: *mut curl_mimepart,
        datasize: curl_off_t,
        readfunc: curl_read_callback,
        seekfunc: curl_seek_callback,
        freefunc: curl_free_callback,
        arg: *mut libc::c_void,
    ) -> CURLcode;
    fn curl_mime_subparts(part: *mut curl_mimepart, subparts: *mut curl_mime) -> CURLcode;
    fn curl_mime_headers(
        part: *mut curl_mimepart,
        headers: *mut curl_slist,
        take_ownership: i32,
    ) -> CURLcode;
    fn curl_slist_append(_: *mut curl_slist, _: *const i8) -> *mut curl_slist;
    fn curl_slist_free_all(_: *mut curl_slist);
    fn calloc(_: u64, _: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strdup(_: *const i8) -> *mut i8;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn strerror(_: i32) -> *mut i8;
    fn __errno_location() -> *mut i32;
    fn __fxstat(__ver: i32, __fildes: i32, __stat_buf: *mut stat) -> i32;
    fn fclose(__stream: *mut FILE) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut FILE;
    fn sscanf(_: *const i8, _: *const i8, _: ...) -> i32;
    fn getc(__stream: *mut FILE) -> i32;
    fn fseek(__stream: *mut FILE, __off: i64, __whence: i32) -> i32;
    fn ftell(__stream: *mut FILE) -> i64;
    fn fread(_: *mut libc::c_void, _: u64, _: u64, _: *mut FILE) -> u64;
    fn ferror(__stream: *mut FILE) -> i32;
    fn fileno(__stream: *mut FILE) -> i32;
    fn curlx_uztoso(uznum: size_t) -> curl_off_t;
    fn curlx_sotouz(sonum: curl_off_t) -> size_t;
    fn curl_mfprintf(fd: *mut FILE, format: *const i8, _: ...) -> i32;
    fn warnf(config: *mut GlobalConfig, fmt: *const i8, _: ...);
    fn file2memory(bufp: *mut *mut i8, size: *mut size_t, file: *mut FILE) -> ParameterError;
}
pub type __dev_t = u64;
pub type __uid_t = u32;
pub type __gid_t = u32;
pub type __ino_t = u64;
pub type __mode_t = u32;
pub type __nlink_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __time_t = i64;
pub type __blksize_t = i64;
pub type __blkcnt_t = i64;
pub type __syscall_slong_t = i64;
pub type size_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
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
pub type curl_seek_callback =
    Option<unsafe extern "C" fn(*mut libc::c_void, curl_off_t, i32) -> i32>;
pub type curl_read_callback =
    Option<unsafe extern "C" fn(*mut i8, size_t, size_t, *mut libc::c_void) -> size_t>;
pub type curl_free_callback = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
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
pub struct stat {
    pub st_dev: __dev_t,
    pub st_ino: __ino_t,
    pub st_nlink: __nlink_t,
    pub st_mode: __mode_t,
    pub st_uid: __uid_t,
    pub st_gid: __gid_t,
    pub __pad0: i32,
    pub st_rdev: __dev_t,
    pub st_size: __off_t,
    pub st_blksize: __blksize_t,
    pub st_blocks: __blkcnt_t,
    pub st_atim: timespec,
    pub st_mtim: timespec,
    pub st_ctim: timespec,
    pub __glibc_reserved: [__syscall_slong_t; 3],
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
pub const PARAM_OK: ParameterError = 0;
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
#[inline]
extern "C" fn fstat(mut __fd: i32, mut __statbuf: *mut stat) -> i32 {
    return unsafe { __fxstat(1 as i32, __fd, __statbuf) };
}
extern "C" fn tool_mime_new(mut parent: *mut tool_mime, mut kind: toolmimekind) -> *mut tool_mime {
    let mut m: *mut tool_mime =
        (unsafe { calloc(1 as i32 as u64, ::std::mem::size_of::<tool_mime>() as u64) }) as *mut tool_mime;
    if !m.is_null() {
        (unsafe { (*m).kind = kind });
        let fresh0 = unsafe { &mut ((*m).parent) };
        *fresh0 = parent;
        if !parent.is_null() {
            let fresh1 = unsafe { &mut ((*m).prev) };
            *fresh1 = unsafe { (*parent).subparts };
            let fresh2 = unsafe { &mut ((*parent).subparts) };
            *fresh2 = m;
        }
    }
    return m;
}
extern "C" fn tool_mime_new_parts(mut parent: *mut tool_mime) -> *mut tool_mime {
    return tool_mime_new(parent, TOOLMIME_PARTS);
}
extern "C" fn tool_mime_new_data(
    mut parent: *mut tool_mime,
    mut data: *const i8,
) -> *mut tool_mime {
    let mut m: *mut tool_mime = 0 as *mut tool_mime;
    data = unsafe { strdup(data) };
    if !data.is_null() {
        m = tool_mime_new(parent, TOOLMIME_DATA);
        if m.is_null() {
            (unsafe { free(data as *mut libc::c_void) });
        } else {
            let fresh3 = unsafe { &mut ((*m).data) };
            *fresh3 = data;
        }
    }
    return m;
}
extern "C" fn tool_mime_new_filedata(
    mut parent: *mut tool_mime,
    mut filename: *const i8,
    mut isremotefile: bool,
    mut errcode: *mut CURLcode,
) -> *mut tool_mime {
    let mut result: CURLcode = CURLE_OK;
    let mut m: *mut tool_mime = 0 as *mut tool_mime;
    (unsafe { *errcode = CURLE_OUT_OF_MEMORY });
    if (unsafe { strcmp(filename, b"-\0" as *const u8 as *const i8) }) != 0 {
        filename = unsafe { strdup(filename) };
        if !filename.is_null() {
            m = tool_mime_new(parent, TOOLMIME_FILE);
            if m.is_null() {
                (unsafe { free(filename as *mut libc::c_void) });
            } else {
                let fresh4 = unsafe { &mut ((*m).data) };
                *fresh4 = filename;
                if !isremotefile {
                    (unsafe { (*m).kind = TOOLMIME_FILEDATA });
                }
                (unsafe { *errcode = CURLE_OK });
            }
        }
    } else {
        let mut fd: i32 = unsafe { fileno(stdin) };
        let mut data: *mut i8 = 0 as *mut i8;
        let mut size: curl_off_t = 0;
        let mut origin: curl_off_t = 0;
        let mut sbuf: stat = stat {
            st_dev: 0,
            st_ino: 0,
            st_nlink: 0,
            st_mode: 0,
            st_uid: 0,
            st_gid: 0,
            __pad0: 0,
            st_rdev: 0,
            st_size: 0,
            st_blksize: 0,
            st_blocks: 0,
            st_atim: timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            st_mtim: timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            st_ctim: timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            __glibc_reserved: [0; 3],
        };
        origin = unsafe { ftell(stdin) };
        if fd >= 0 as i32
            && origin >= 0 as i32 as i64
            && fstat(fd, &mut sbuf) == 0
            && sbuf.st_mode & 0o170000 as i32 as u32 == 0o100000 as i32 as u32
        {
            size = sbuf.st_size - origin;
            if size < 0 as i32 as i64 {
                size = 0 as i32 as curl_off_t;
            }
        } else {
            let mut stdinsize: size_t = 0 as i32 as size_t;
            if (unsafe { file2memory(&mut data, &mut stdinsize, stdin) }) as u32 != PARAM_OK as i32 as u32 {
                return m;
            }
            if (unsafe { ferror(stdin) }) != 0 {
                result = CURLE_READ_ERROR;
                (unsafe { free(data as *mut libc::c_void) });
                data = 0 as *mut i8;
                data = 0 as *mut i8;
            } else if stdinsize == 0 {
                data = unsafe { strdup(b"\0" as *const u8 as *const i8) };
                if data.is_null() {
                    return m;
                }
            }
            size = unsafe { curlx_uztoso(stdinsize) };
            origin = 0 as i32 as curl_off_t;
        }
        m = tool_mime_new(parent, TOOLMIME_STDIN);
        if m.is_null() {
            (unsafe { free(data as *mut libc::c_void) });
            data = 0 as *mut i8;
        } else {
            let fresh5 = unsafe { &mut ((*m).data) };
            *fresh5 = data;
            (unsafe { (*m).origin = origin });
            (unsafe { (*m).size = size });
            (unsafe { (*m).curpos = 0 as i32 as curl_off_t });
            if !isremotefile {
                (unsafe { (*m).kind = TOOLMIME_STDINDATA });
            }
            (unsafe { *errcode = result });
        }
    }
    return m;
}
#[no_mangle]
pub extern "C" fn tool_mime_free(mut mime: *mut tool_mime) {
    if !mime.is_null() {
        if !(unsafe { (*mime).subparts }).is_null() {
            tool_mime_free(unsafe { (*mime).subparts });
        }
        if !(unsafe { (*mime).prev }).is_null() {
            tool_mime_free(unsafe { (*mime).prev });
        }
        (unsafe { free(*(&mut (*mime).name as *mut *const i8 as *mut *mut libc::c_void)) });
        let fresh6 = unsafe { &mut (*(&mut (*mime).name as *mut *const i8 as *mut *mut libc::c_void)) };
        *fresh6 = 0 as *mut libc::c_void;
        (unsafe { free(*(&mut (*mime).filename as *mut *const i8 as *mut *mut libc::c_void)) });
        let fresh7 = unsafe { &mut (*(&mut (*mime).filename as *mut *const i8 as *mut *mut libc::c_void)) };
        *fresh7 = 0 as *mut libc::c_void;
        (unsafe { free(*(&mut (*mime).type_0 as *mut *const i8 as *mut *mut libc::c_void)) });
        let fresh8 = unsafe { &mut (*(&mut (*mime).type_0 as *mut *const i8 as *mut *mut libc::c_void)) };
        *fresh8 = 0 as *mut libc::c_void;
        (unsafe { free(*(&mut (*mime).encoder as *mut *const i8 as *mut *mut libc::c_void)) });
        let fresh9 = unsafe { &mut (*(&mut (*mime).encoder as *mut *const i8 as *mut *mut libc::c_void)) };
        *fresh9 = 0 as *mut libc::c_void;
        (unsafe { free(*(&mut (*mime).data as *mut *const i8 as *mut *mut libc::c_void)) });
        let fresh10 = unsafe { &mut (*(&mut (*mime).data as *mut *const i8 as *mut *mut libc::c_void)) };
        *fresh10 = 0 as *mut libc::c_void;
        (unsafe { curl_slist_free_all((*mime).headers) });
        (unsafe { free(mime as *mut libc::c_void) });
    }
}
#[no_mangle]
pub extern "C" fn tool_mime_stdin_read(
    mut buffer: *mut i8,
    mut _size: size_t,
    mut nitems: size_t,
    mut arg: *mut libc::c_void,
) -> size_t {
    let mut sip: *mut tool_mime = arg as *mut tool_mime;
    let mut bytesleft: curl_off_t = 0;
    if (unsafe { (*sip).size }) >= 0 as i32 as i64 {
        if (unsafe { (*sip).curpos }) >= (unsafe { (*sip).size }) {
            return 0 as i32 as size_t;
        }
        bytesleft = (unsafe { (*sip).size }) - (unsafe { (*sip).curpos });
        if (unsafe { curlx_uztoso(nitems) }) > bytesleft {
            nitems = unsafe { curlx_sotouz(bytesleft) };
        }
    }
    if nitems != 0 {
        if !(unsafe { (*sip).data }).is_null() {
            (unsafe { memcpy(
                buffer as *mut libc::c_void,
                ((*sip).data).offset(curlx_sotouz((*sip).curpos) as isize) as *const libc::c_void,
                nitems,
            ) });
        } else {
            nitems = unsafe { fread(buffer as *mut libc::c_void, 1 as i32 as u64, nitems, stdin) };
            if (unsafe { ferror(stdin) }) != 0 {
                if !(unsafe { (*sip).config }).is_null() {
                    (unsafe { warnf(
                        (*sip).config,
                        b"stdin: %s\n\0" as *const u8 as *const i8,
                        strerror(*__errno_location()),
                    ) });
                    let fresh11 = unsafe { &mut ((*sip).config) };
                    *fresh11 = 0 as *mut GlobalConfig;
                }
                return 0x10000000 as i32 as size_t;
            }
        }
        let fresh12 = unsafe { &mut ((*sip).curpos) };
        *fresh12 += unsafe { curlx_uztoso(nitems) };
    }
    return nitems;
}
#[no_mangle]
pub extern "C" fn tool_mime_stdin_seek(
    mut instream: *mut libc::c_void,
    mut offset: curl_off_t,
    mut whence: i32,
) -> i32 {
    let mut sip: *mut tool_mime = instream as *mut tool_mime;
    match whence {
        1 => {
            offset += unsafe { (*sip).curpos };
        }
        2 => {
            offset += unsafe { (*sip).size };
        }
        _ => {}
    }
    if offset < 0 as i32 as i64 {
        return 2 as i32;
    }
    if (unsafe { (*sip).data }).is_null() {
        if (unsafe { fseek(stdin, offset + (*sip).origin, 0 as i32) }) != 0 {
            return 2 as i32;
        }
    }
    (unsafe { (*sip).curpos = offset });
    return 0 as i32;
}
extern "C" fn tool2curlparts(
    mut curl: *mut CURL,
    mut m: *mut tool_mime,
    mut mime: *mut curl_mime,
) -> CURLcode {
    let mut ret: CURLcode = CURLE_OK;
    let mut part: *mut curl_mimepart = 0 as *mut curl_mimepart;
    let mut submime: *mut curl_mime = 0 as *mut curl_mime;
    let mut filename: *const i8 = 0 as *const i8;
    if !m.is_null() {
        ret = tool2curlparts(curl, unsafe { (*m).prev }, mime);
        if ret as u64 == 0 {
            part = unsafe { curl_mime_addpart(mime) };
            if part.is_null() {
                ret = CURLE_OUT_OF_MEMORY;
            }
        }
        if ret as u64 == 0 {
            filename = unsafe { (*m).filename };
            let mut current_block_19: u64;
            match (unsafe { (*m).kind }) as u32 {
                1 => {
                    ret = tool2curlmime(curl, m, &mut submime);
                    if ret as u64 == 0 {
                        ret = unsafe { curl_mime_subparts(part, submime) };
                        if ret as u64 != 0 {
                            (unsafe { curl_mime_free(submime) });
                        }
                    }
                    current_block_19 = 14818589718467733107;
                }
                2 => {
                    ret = unsafe { curl_mime_data(part, (*m).data, -(1 as i32) as size_t) };
                    current_block_19 = 14818589718467733107;
                }
                3 | 4 => {
                    ret = unsafe { curl_mime_filedata(part, (*m).data) };
                    if ret as u64 == 0
                        && (unsafe { (*m).kind }) as u32 == TOOLMIME_FILEDATA as i32 as u32
                        && filename.is_null()
                    {
                        ret = unsafe { curl_mime_filename(part, 0 as *const i8) };
                    }
                    current_block_19 = 14818589718467733107;
                }
                5 => {
                    if filename.is_null() {
                        filename = b"-\0" as *const u8 as *const i8;
                    }
                    current_block_19 = 4814211256656441226;
                }
                6 => {
                    current_block_19 = 4814211256656441226;
                }
                _ => {
                    current_block_19 = 14818589718467733107;
                }
            }
            match current_block_19 {
                4814211256656441226 => {
                    ret = unsafe { curl_mime_data_cb(
                        part,
                        (*m).size,
                        ::std::mem::transmute::<
                            Option<
                                unsafe extern "C" fn(
                                    *mut i8,
                                    size_t,
                                    size_t,
                                    *mut libc::c_void,
                                ) -> size_t,
                            >,
                            curl_read_callback,
                        >(Some(
                            tool_mime_stdin_read
                                as unsafe extern "C" fn(
                                    *mut i8,
                                    size_t,
                                    size_t,
                                    *mut libc::c_void,
                                ) -> size_t,
                        )),
                        ::std::mem::transmute::<
                            Option<unsafe extern "C" fn(*mut libc::c_void, curl_off_t, i32) -> i32>,
                            curl_seek_callback,
                        >(Some(
                            tool_mime_stdin_seek
                                as unsafe extern "C" fn(*mut libc::c_void, curl_off_t, i32) -> i32,
                        )),
                        None,
                        m as *mut libc::c_void,
                    ) };
                }
                _ => {}
            }
        }
        if ret as u64 == 0 && !filename.is_null() {
            ret = unsafe { curl_mime_filename(part, filename) };
        }
        if ret as u64 == 0 {
            ret = unsafe { curl_mime_type(part, (*m).type_0) };
        }
        if ret as u64 == 0 {
            ret = unsafe { curl_mime_headers(part, (*m).headers, 0 as i32) };
        }
        if ret as u64 == 0 {
            ret = unsafe { curl_mime_encoder(part, (*m).encoder) };
        }
        if ret as u64 == 0 {
            ret = unsafe { curl_mime_name(part, (*m).name) };
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn tool2curlmime(
    mut curl: *mut CURL,
    mut m: *mut tool_mime,
    mut mime: *mut *mut curl_mime,
) -> CURLcode {
    let mut ret: CURLcode = CURLE_OK;
    (unsafe { *mime = curl_mime_init(curl) });
    if (unsafe { *mime }).is_null() {
        ret = CURLE_OUT_OF_MEMORY;
    } else {
        ret = tool2curlparts(curl, unsafe { (*m).subparts }, unsafe { *mime });
    }
    if ret as u64 != 0 {
        (unsafe { curl_mime_free(*mime) });
        (unsafe { *mime = 0 as *mut curl_mime });
    }
    return ret;
}
extern "C" fn get_param_word(
    mut config: *mut OperationConfig,
    mut str: *mut *mut i8,
    mut end_pos: *mut *mut i8,
    mut endchar: i8,
) -> *mut i8 {
    let mut ptr: *mut i8 = unsafe { *str };
    let mut word_begin: *mut i8 = ptr;
    let mut ptr2: *mut i8 = 0 as *mut i8;
    let mut escape: *mut i8 = 0 as *mut i8;
    if (unsafe { *ptr }) as i32 == '"' as i32 {
        ptr = unsafe { ptr.offset(1) };
        while (unsafe { *ptr }) != 0 {
            if (unsafe { *ptr }) as i32 == '\\' as i32 {
                if (unsafe { *ptr.offset(1 as i32 as isize) }) as i32 == '\\' as i32
                    || (unsafe { *ptr.offset(1 as i32 as isize) }) as i32 == '"' as i32
                {
                    if escape.is_null() {
                        escape = ptr;
                    }
                    ptr = unsafe { ptr.offset(2 as i32 as isize) };
                    continue;
                }
            }
            if (unsafe { *ptr }) as i32 == '"' as i32 {
                let mut trailing_data: bool = 0 as i32 != 0;
                (unsafe { *end_pos = ptr });
                if !escape.is_null() {
                    ptr2 = escape;
                    ptr = ptr2;
                    loop {
                        if (unsafe { *ptr }) as i32 == '\\' as i32
                            && ((unsafe { *ptr.offset(1 as i32 as isize) }) as i32 == '\\' as i32
                                || (unsafe { *ptr.offset(1 as i32 as isize) }) as i32 == '"' as i32)
                        {
                            ptr = unsafe { ptr.offset(1) };
                        }
                        let fresh13 = ptr;
                        ptr = unsafe { ptr.offset(1) };
                        let fresh14 = ptr2;
                        ptr2 = unsafe { ptr2.offset(1) };
                        (unsafe { *fresh14 = *fresh13 });
                        if !(ptr < (unsafe { *end_pos })) {
                            break;
                        }
                    }
                    (unsafe { *end_pos = ptr2 });
                }
                ptr = unsafe { ptr.offset(1) };
                while (unsafe { *ptr }) as i32 != 0 && (unsafe { *ptr }) as i32 != ';' as i32 && (unsafe { *ptr }) as i32 != endchar as i32
                {
                    if (unsafe { Curl_isspace(*ptr as u8 as i32) }) == 0 {
                        trailing_data = 1 as i32 != 0;
                    }
                    ptr = unsafe { ptr.offset(1) };
                }
                if trailing_data {
                    (unsafe { warnf(
                        (*config).global,
                        b"Trailing data after quoted form parameter\n\0" as *const u8 as *const i8,
                    ) });
                }
                (unsafe { *str = ptr });
                return unsafe { word_begin.offset(1 as i32 as isize) };
            }
            ptr = unsafe { ptr.offset(1) };
        }
        ptr = word_begin;
    }
    while (unsafe { *ptr }) as i32 != 0 && (unsafe { *ptr }) as i32 != ';' as i32 && (unsafe { *ptr }) as i32 != endchar as i32 {
        ptr = unsafe { ptr.offset(1) };
    }
    (unsafe { *end_pos = ptr });
    (unsafe { *str = *end_pos });
    return word_begin;
}
extern "C" fn slist_append(mut plist: *mut *mut curl_slist, mut data: *const i8) -> i32 {
    let mut s: *mut curl_slist = unsafe { curl_slist_append(*plist, data) };
    if s.is_null() {
        return -(1 as i32);
    }
    (unsafe { *plist = s });
    return 0 as i32;
}
extern "C" fn read_field_headers(
    mut config: *mut OperationConfig,
    mut filename: *const i8,
    mut fp: *mut FILE,
    mut pheaders: *mut *mut curl_slist,
) -> i32 {
    let mut hdrlen: size_t = 0 as i32 as size_t;
    let mut pos: size_t = 0 as i32 as size_t;
    let mut incomment: bool = 0 as i32 != 0;
    let mut lineno: i32 = 1 as i32;
    let mut hdrbuf: [i8; 999] = [0; 999];
    loop {
        let mut c: i32 = unsafe { getc(fp) };
        if c == -(1 as i32) || pos == 0 && (unsafe { Curl_isspace(c as u8 as i32) }) == 0 {
            while hdrlen != 0
                && (unsafe { Curl_isspace(hdrbuf[hdrlen.wrapping_sub(1 as i32 as u64) as usize] as u8 as i32) })
                    != 0
            {
                hdrlen = hdrlen.wrapping_sub(1);
            }
            if hdrlen != 0 {
                hdrbuf[hdrlen as usize] = '\u{0}' as i32 as i8;
                if slist_append(pheaders, hdrbuf.as_mut_ptr()) != 0 {
                    (unsafe { curl_mfprintf(
                        (*(*config).global).errors,
                        b"Out of memory for field headers!\n\0" as *const u8 as *const i8,
                    ) });
                    return -(1 as i32);
                }
                hdrlen = 0 as i32 as size_t;
            }
        }
        match c {
            -1 => {
                if (unsafe { ferror(fp) }) != 0 {
                    (unsafe { curl_mfprintf(
                        (*(*config).global).errors,
                        b"Header file %s read error: %s\n\0" as *const u8 as *const i8,
                        filename,
                        strerror(*__errno_location()),
                    ) });
                    return -(1 as i32);
                }
                return 0 as i32;
            }
            13 => {
                continue;
            }
            10 => {
                pos = 0 as i32 as size_t;
                incomment = 0 as i32 != 0;
                lineno += 1;
                continue;
            }
            35 => {
                if pos == 0 {
                    incomment = 1 as i32 != 0;
                }
            }
            _ => {}
        }
        pos = pos.wrapping_add(1);
        if !incomment {
            if hdrlen == (::std::mem::size_of::<[i8; 999]>() as u64).wrapping_sub(1 as i32 as u64) {
                (unsafe { warnf(
                    (*config).global,
                    b"File %s line %d: header too long (truncated)\n\0" as *const u8 as *const i8,
                    filename,
                    lineno,
                ) });
                c = ' ' as i32;
            }
            if hdrlen <= (::std::mem::size_of::<[i8; 999]>() as u64).wrapping_sub(1 as i32 as u64) {
                let fresh15 = hdrlen;
                hdrlen = hdrlen.wrapping_add(1);
                hdrbuf[fresh15 as usize] = c as i8;
            }
        }
    }
}
extern "C" fn get_param_part(
    mut config: *mut OperationConfig,
    mut endchar: i8,
    mut str: *mut *mut i8,
    mut pdata: *mut *mut i8,
    mut ptype: *mut *mut i8,
    mut pfilename: *mut *mut i8,
    mut pencoder: *mut *mut i8,
    mut pheaders: *mut *mut curl_slist,
) -> i32 {
    let mut p: *mut i8 = unsafe { *str };
    let mut type_0: *mut i8 = 0 as *mut i8;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoder: *mut i8 = 0 as *mut i8;
    let mut endpos: *mut i8 = 0 as *mut i8;
    let mut tp: *mut i8 = 0 as *mut i8;
    let mut sep: i8 = 0;
    let mut type_major : [i8 ; 128] = * (unsafe { :: std :: mem :: transmute :: < & [u8 ; 128] , & mut [i8 ; 128] , > (b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" ,) }) ;
    let mut type_minor : [i8 ; 128] = * (unsafe { :: std :: mem :: transmute :: < & [u8 ; 128] , & mut [i8 ; 128] , > (b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" ,) }) ;
    let mut endct: *mut i8 = 0 as *mut i8;
    let mut headers: *mut curl_slist = 0 as *mut curl_slist;
    if !ptype.is_null() {
        (unsafe { *ptype = 0 as *mut i8 });
    }
    if !pfilename.is_null() {
        (unsafe { *pfilename = 0 as *mut i8 });
    }
    if !pheaders.is_null() {
        (unsafe { *pheaders = 0 as *mut curl_slist });
    }
    if !pencoder.is_null() {
        (unsafe { *pencoder = 0 as *mut i8 });
    }
    while (unsafe { Curl_isspace(*p as u8 as i32) }) != 0 {
        p = unsafe { p.offset(1) };
    }
    tp = p;
    (unsafe { *pdata = get_param_word(config, &mut p, &mut endpos, endchar) });
    if (unsafe { *pdata }) == tp {
        while endpos > (unsafe { *pdata })
            && (unsafe { Curl_isspace(*endpos.offset(-(1 as i32) as isize) as u8 as i32) }) != 0
        {
            endpos = unsafe { endpos.offset(-1) };
        }
    }
    sep = unsafe { *p };
    (unsafe { *endpos = '\u{0}' as i32 as i8 });
    while sep as i32 == ';' as i32 {
        loop {
            p = unsafe { p.offset(1) };
            if !((unsafe { Curl_isspace(*p as u8 as i32) }) != 0) {
                break;
            }
        }
        if endct.is_null()
            && (unsafe { curl_strnequal(
                b"type=\0" as *const u8 as *const i8,
                p,
                strlen(b"type=\0" as *const u8 as *const i8),
            ) }) != 0
        {
            p = unsafe { p.offset(5 as i32 as isize) };
            while (unsafe { Curl_isspace(*p as u8 as i32) }) != 0 {
                p = unsafe { p.offset(1) };
            }
            type_0 = p;
            if 2 as i32
                != (unsafe { sscanf(
                    type_0,
                    b"%127[^/ ]/%127[^;, \n]\0" as *const u8 as *const i8,
                    type_major.as_mut_ptr(),
                    type_minor.as_mut_ptr(),
                ) })
            {
                (unsafe { warnf(
                    (*config).global,
                    b"Illegally formatted content-type field!\n\0" as *const u8 as *const i8,
                ) });
                (unsafe { curl_slist_free_all(headers) });
                return -(1 as i32);
            }
            p = unsafe { type_0
                .offset(strlen(type_major.as_mut_ptr()) as isize)
                .offset(strlen(type_minor.as_mut_ptr()) as isize)
                .offset(1 as i32 as isize) };
            endct = p;
            while (unsafe { *p }) as i32 != 0 && (unsafe { *p }) as i32 != ';' as i32 && (unsafe { *p }) as i32 != endchar as i32 {
                if (unsafe { Curl_isspace(*p as u8 as i32) }) == 0 {
                    endct = unsafe { p.offset(1 as i32 as isize) };
                }
                p = unsafe { p.offset(1) };
            }
            sep = unsafe { *p };
        } else if (unsafe { curl_strnequal(
            b"filename=\0" as *const u8 as *const i8,
            p,
            strlen(b"filename=\0" as *const u8 as *const i8),
        ) }) != 0
        {
            if !endct.is_null() {
                (unsafe { *endct = '\u{0}' as i32 as i8 });
                endct = 0 as *mut i8;
            }
            p = unsafe { p.offset(9 as i32 as isize) };
            while (unsafe { Curl_isspace(*p as u8 as i32) }) != 0 {
                p = unsafe { p.offset(1) };
            }
            tp = p;
            filename = get_param_word(config, &mut p, &mut endpos, endchar);
            if filename == tp {
                while endpos > filename
                    && (unsafe { Curl_isspace(*endpos.offset(-(1 as i32) as isize) as u8 as i32) }) != 0
                {
                    endpos = unsafe { endpos.offset(-1) };
                }
            }
            sep = unsafe { *p };
            (unsafe { *endpos = '\u{0}' as i32 as i8 });
        } else if (unsafe { curl_strnequal(
            b"headers=\0" as *const u8 as *const i8,
            p,
            strlen(b"headers=\0" as *const u8 as *const i8),
        ) }) != 0
        {
            if !endct.is_null() {
                (unsafe { *endct = '\u{0}' as i32 as i8 });
                endct = 0 as *mut i8;
            }
            p = unsafe { p.offset(8 as i32 as isize) };
            if (unsafe { *p }) as i32 == '@' as i32 || (unsafe { *p }) as i32 == '<' as i32 {
                let mut hdrfile: *mut i8 = 0 as *mut i8;
                let mut fp: *mut FILE = 0 as *mut FILE;
                loop {
                    p = unsafe { p.offset(1) };
                    if !((unsafe { Curl_isspace(*p as u8 as i32) }) != 0) {
                        break;
                    }
                }
                tp = p;
                hdrfile = get_param_word(config, &mut p, &mut endpos, endchar);
                if hdrfile == tp {
                    while endpos > hdrfile
                        && (unsafe { Curl_isspace(*endpos.offset(-(1 as i32) as isize) as u8 as i32) }) != 0
                    {
                        endpos = unsafe { endpos.offset(-1) };
                    }
                }
                sep = unsafe { *p };
                (unsafe { *endpos = '\u{0}' as i32 as i8 });
                fp = unsafe { fopen(hdrfile, b"r\0" as *const u8 as *const i8) };
                if fp.is_null() {
                    (unsafe { warnf(
                        (*config).global,
                        b"Cannot read from %s: %s\n\0" as *const u8 as *const i8,
                        hdrfile,
                        strerror(*__errno_location()),
                    ) });
                } else {
                    let mut i: i32 = read_field_headers(config, hdrfile, fp, &mut headers);
                    (unsafe { fclose(fp) });
                    if i != 0 {
                        (unsafe { curl_slist_free_all(headers) });
                        return -(1 as i32);
                    }
                }
            } else {
                let mut hdr: *mut i8 = 0 as *mut i8;
                while (unsafe { Curl_isspace(*p as u8 as i32) }) != 0 {
                    p = unsafe { p.offset(1) };
                }
                tp = p;
                hdr = get_param_word(config, &mut p, &mut endpos, endchar);
                if hdr == tp {
                    while endpos > hdr
                        && (unsafe { Curl_isspace(*endpos.offset(-(1 as i32) as isize) as u8 as i32) }) != 0
                    {
                        endpos = unsafe { endpos.offset(-1) };
                    }
                }
                sep = unsafe { *p };
                (unsafe { *endpos = '\u{0}' as i32 as i8 });
                if slist_append(&mut headers, hdr) != 0 {
                    (unsafe { curl_mfprintf(
                        (*(*config).global).errors,
                        b"Out of memory for field header!\n\0" as *const u8 as *const i8,
                    ) });
                    (unsafe { curl_slist_free_all(headers) });
                    return -(1 as i32);
                }
            }
        } else if (unsafe { curl_strnequal(
            b"encoder=\0" as *const u8 as *const i8,
            p,
            strlen(b"encoder=\0" as *const u8 as *const i8),
        ) }) != 0
        {
            if !endct.is_null() {
                (unsafe { *endct = '\u{0}' as i32 as i8 });
                endct = 0 as *mut i8;
            }
            p = unsafe { p.offset(8 as i32 as isize) };
            while (unsafe { Curl_isspace(*p as u8 as i32) }) != 0 {
                p = unsafe { p.offset(1) };
            }
            tp = p;
            encoder = get_param_word(config, &mut p, &mut endpos, endchar);
            if encoder == tp {
                while endpos > encoder
                    && (unsafe { Curl_isspace(*endpos.offset(-(1 as i32) as isize) as u8 as i32) }) != 0
                {
                    endpos = unsafe { endpos.offset(-1) };
                }
            }
            sep = unsafe { *p };
            (unsafe { *endpos = '\u{0}' as i32 as i8 });
        } else if !endct.is_null() {
            endct = p;
            while (unsafe { *p }) as i32 != 0 && (unsafe { *p }) as i32 != ';' as i32 && (unsafe { *p }) as i32 != endchar as i32 {
                if (unsafe { Curl_isspace(*p as u8 as i32) }) == 0 {
                    endct = unsafe { p.offset(1 as i32 as isize) };
                }
                p = unsafe { p.offset(1) };
            }
            sep = unsafe { *p };
        } else {
            let mut unknown: *mut i8 = get_param_word(config, &mut p, &mut endpos, endchar);
            sep = unsafe { *p };
            (unsafe { *endpos = '\u{0}' as i32 as i8 });
            if (unsafe { *unknown }) != 0 {
                (unsafe { warnf(
                    (*config).global,
                    b"skip unknown form field: %s\n\0" as *const u8 as *const i8,
                    unknown,
                ) });
            }
        }
    }
    if !endct.is_null() {
        (unsafe { *endct = '\u{0}' as i32 as i8 });
    }
    if !ptype.is_null() {
        (unsafe { *ptype = type_0 });
    } else if !type_0.is_null() {
        (unsafe { warnf(
            (*config).global,
            b"Field content type not allowed here: %s\n\0" as *const u8 as *const i8,
            type_0,
        ) });
    }
    if !pfilename.is_null() {
        (unsafe { *pfilename = filename });
    } else if !filename.is_null() {
        (unsafe { warnf(
            (*config).global,
            b"Field file name not allowed here: %s\n\0" as *const u8 as *const i8,
            filename,
        ) });
    }
    if !pencoder.is_null() {
        (unsafe { *pencoder = encoder });
    } else if !encoder.is_null() {
        (unsafe { warnf(
            (*config).global,
            b"Field encoder not allowed here: %s\n\0" as *const u8 as *const i8,
            encoder,
        ) });
    }
    if !pheaders.is_null() {
        (unsafe { *pheaders = headers });
    } else if !headers.is_null() {
        (unsafe { warnf(
            (*config).global,
            b"Field headers not allowed here: %s\n\0" as *const u8 as *const i8,
            (*headers).data,
        ) });
        (unsafe { curl_slist_free_all(headers) });
    }
    (unsafe { *str = p });
    return sep as i32 & 0xff as i32;
}
#[no_mangle]
pub extern "C" fn formparse(
    mut config: *mut OperationConfig,
    mut input: *const i8,
    mut mimeroot: *mut *mut tool_mime,
    mut mimecurrent: *mut *mut tool_mime,
    mut literal_value: bool,
) -> i32 {
    let mut name: *mut i8 = 0 as *mut i8;
    let mut contents: *mut i8 = 0 as *mut i8;
    let mut contp: *mut i8 = 0 as *mut i8;
    let mut data: *mut i8 = 0 as *mut i8;
    let mut type_0: *mut i8 = 0 as *mut i8;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoder: *mut i8 = 0 as *mut i8;
    let mut headers: *mut curl_slist = 0 as *mut curl_slist;
    let mut part: *mut tool_mime = 0 as *mut tool_mime;
    let mut res: CURLcode = CURLE_OK;
    if (unsafe { *mimecurrent }).is_null() {
        (unsafe { *mimeroot = tool_mime_new_parts(0 as *mut tool_mime) });
        if (unsafe { *mimeroot }).is_null() {
            (unsafe { warnf(
                (*config).global,
                b"out of memory!\n\0" as *const u8 as *const i8,
            ) });
            (unsafe { curl_slist_free_all(headers) });
            (unsafe { free(contents as *mut libc::c_void) });
            contents = 0 as *mut i8;
            return 1 as i32;
        }
        (unsafe { *mimecurrent = *mimeroot });
    }
    contents = unsafe { strdup(input) };
    if contents.is_null() {
        (unsafe { warnf(
            (*config).global,
            b"out of memory!\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { curl_slist_free_all(headers) });
        (unsafe { free(contents as *mut libc::c_void) });
        contents = 0 as *mut i8;
        return 2 as i32;
    }
    contp = unsafe { strchr(contents, '=' as i32) };
    if !contp.is_null() {
        let mut sep: i32 = '\u{0}' as i32;
        if contp > contents {
            name = contents;
        }
        let fresh16 = contp;
        contp = unsafe { contp.offset(1) };
        (unsafe { *fresh16 = '\u{0}' as i32 as i8 });
        if (unsafe { *contp }) as i32 == '(' as i32 && !literal_value {
            sep = get_param_part(
                config,
                '\u{0}' as i32 as i8,
                &mut contp,
                &mut data,
                &mut type_0,
                0 as *mut *mut i8,
                0 as *mut *mut i8,
                &mut headers,
            );
            if sep < 0 as i32 {
                (unsafe { free(contents as *mut libc::c_void) });
                contents = 0 as *mut i8;
                return 3 as i32;
            }
            part = tool_mime_new_parts(unsafe { *mimecurrent });
            if part.is_null() {
                (unsafe { warnf(
                    (*config).global,
                    b"out of memory!\n\0" as *const u8 as *const i8,
                ) });
                (unsafe { curl_slist_free_all(headers) });
                (unsafe { free(contents as *mut libc::c_void) });
                contents = 0 as *mut i8;
                return 4 as i32;
            }
            (unsafe { *mimecurrent = part });
            let fresh17 = unsafe { &mut ((*part).headers) };
            *fresh17 = headers;
            headers = 0 as *mut curl_slist;
            if !type_0.is_null() {
                let fresh18 = unsafe { &mut ((*part).type_0) };
                *fresh18 = unsafe { strdup(type_0) };
                if (unsafe { (*part).type_0 }).is_null() {
                    (unsafe { warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const i8,
                    ) });
                    (unsafe { curl_slist_free_all(headers) });
                    (unsafe { free(contents as *mut libc::c_void) });
                    contents = 0 as *mut i8;
                    return 5 as i32;
                }
            }
        } else if name.is_null()
            && (unsafe { strcmp(contp, b")\0" as *const u8 as *const i8) }) == 0
            && !literal_value
        {
            if (unsafe { *mimecurrent }) == (unsafe { *mimeroot }) {
                (unsafe { warnf(
                    (*config).global,
                    b"no multipart to terminate!\n\0" as *const u8 as *const i8,
                ) });
                (unsafe { free(contents as *mut libc::c_void) });
                contents = 0 as *mut i8;
                return 6 as i32;
            }
            (unsafe { *mimecurrent = (**mimecurrent).parent });
        } else if '@' as i32 == (unsafe { *contp.offset(0 as i32 as isize) }) as i32 && !literal_value {
            let mut subparts: *mut tool_mime = 0 as *mut tool_mime;
            loop {
                contp = unsafe { contp.offset(1) };
                sep = get_param_part(
                    config,
                    ',' as i32 as i8,
                    &mut contp,
                    &mut data,
                    &mut type_0,
                    &mut filename,
                    &mut encoder,
                    &mut headers,
                );
                if sep < 0 as i32 {
                    (unsafe { free(contents as *mut libc::c_void) });
                    contents = 0 as *mut i8;
                    return 7 as i32;
                }
                if subparts.is_null() {
                    if sep != ',' as i32 {
                        subparts = unsafe { *mimecurrent };
                    } else {
                        subparts = tool_mime_new_parts(unsafe { *mimecurrent });
                        if subparts.is_null() {
                            (unsafe { warnf(
                                (*config).global,
                                b"out of memory!\n\0" as *const u8 as *const i8,
                            ) });
                            (unsafe { curl_slist_free_all(headers) });
                            (unsafe { free(contents as *mut libc::c_void) });
                            contents = 0 as *mut i8;
                            return 8 as i32;
                        }
                    }
                }
                part = tool_mime_new_filedata(subparts, data, 1 as i32 != 0, &mut res);
                if part.is_null() {
                    (unsafe { warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const i8,
                    ) });
                    (unsafe { curl_slist_free_all(headers) });
                    (unsafe { free(contents as *mut libc::c_void) });
                    contents = 0 as *mut i8;
                    return 9 as i32;
                }
                let fresh19 = unsafe { &mut ((*part).headers) };
                *fresh19 = headers;
                headers = 0 as *mut curl_slist;
                let fresh20 = unsafe { &mut ((*part).config) };
                *fresh20 = unsafe { (*config).global };
                if res as u32 == CURLE_READ_ERROR as i32 as u32 {
                    if (unsafe { (*part).size }) > 0 as i32 as i64 {
                        (unsafe { warnf(
                            (*config).global,
                            b"error while reading standard input\n\0" as *const u8 as *const i8,
                        ) });
                        (unsafe { free(contents as *mut libc::c_void) });
                        contents = 0 as *mut i8;
                        return 10 as i32;
                    }
                    (unsafe { free(*(&mut (*part).data as *mut *const i8 as *mut *mut libc::c_void)) });
                    let fresh21 =
                        unsafe { &mut (*(&mut (*part).data as *mut *const i8 as *mut *mut libc::c_void)) };
                    *fresh21 = 0 as *mut libc::c_void;
                    let fresh22 = unsafe { &mut ((*part).data) };
                    *fresh22 = 0 as *const i8;
                    (unsafe { (*part).size = -(1 as i32) as curl_off_t });
                    res = CURLE_OK;
                }
                if !filename.is_null() {
                    let fresh23 = unsafe { &mut ((*part).filename) };
                    *fresh23 = unsafe { strdup(filename) };
                    if (unsafe { (*part).filename }).is_null() {
                        (unsafe { warnf(
                            (*config).global,
                            b"out of memory!\n\0" as *const u8 as *const i8,
                        ) });
                        (unsafe { curl_slist_free_all(headers) });
                        (unsafe { free(contents as *mut libc::c_void) });
                        contents = 0 as *mut i8;
                        return 11 as i32;
                    }
                }
                if !type_0.is_null() {
                    let fresh24 = unsafe { &mut ((*part).type_0) };
                    *fresh24 = unsafe { strdup(type_0) };
                    if (unsafe { (*part).type_0 }).is_null() {
                        (unsafe { warnf(
                            (*config).global,
                            b"out of memory!\n\0" as *const u8 as *const i8,
                        ) });
                        (unsafe { curl_slist_free_all(headers) });
                        (unsafe { free(contents as *mut libc::c_void) });
                        contents = 0 as *mut i8;
                        return 12 as i32;
                    }
                }
                if !encoder.is_null() {
                    let fresh25 = unsafe { &mut ((*part).encoder) };
                    *fresh25 = unsafe { strdup(encoder) };
                    if (unsafe { (*part).encoder }).is_null() {
                        (unsafe { warnf(
                            (*config).global,
                            b"out of memory!\n\0" as *const u8 as *const i8,
                        ) });
                        (unsafe { curl_slist_free_all(headers) });
                        (unsafe { free(contents as *mut libc::c_void) });
                        contents = 0 as *mut i8;
                        return 13 as i32;
                    }
                }
                if !(sep != 0) {
                    break;
                }
            }
            part = unsafe { (**mimecurrent).subparts };
        } else {
            if (unsafe { *contp }) as i32 == '<' as i32 && !literal_value {
                contp = unsafe { contp.offset(1) };
                sep = get_param_part(
                    config,
                    '\u{0}' as i32 as i8,
                    &mut contp,
                    &mut data,
                    &mut type_0,
                    0 as *mut *mut i8,
                    &mut encoder,
                    &mut headers,
                );
                if sep < 0 as i32 {
                    (unsafe { free(contents as *mut libc::c_void) });
                    contents = 0 as *mut i8;
                    return 14 as i32;
                }
                part = tool_mime_new_filedata(unsafe { *mimecurrent }, data, 0 as i32 != 0, &mut res);
                if part.is_null() {
                    (unsafe { warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const i8,
                    ) });
                    (unsafe { curl_slist_free_all(headers) });
                    (unsafe { free(contents as *mut libc::c_void) });
                    contents = 0 as *mut i8;
                    return 15 as i32;
                }
                let fresh26 = unsafe { &mut ((*part).headers) };
                *fresh26 = headers;
                headers = 0 as *mut curl_slist;
                let fresh27 = unsafe { &mut ((*part).config) };
                *fresh27 = unsafe { (*config).global };
                if res as u32 == CURLE_READ_ERROR as i32 as u32 {
                    if (unsafe { (*part).size }) > 0 as i32 as i64 {
                        (unsafe { warnf(
                            (*config).global,
                            b"error while reading standard input\n\0" as *const u8 as *const i8,
                        ) });
                        (unsafe { free(contents as *mut libc::c_void) });
                        contents = 0 as *mut i8;
                        return 16 as i32;
                    }
                    (unsafe { free(*(&mut (*part).data as *mut *const i8 as *mut *mut libc::c_void)) });
                    let fresh28 =
                        unsafe { &mut (*(&mut (*part).data as *mut *const i8 as *mut *mut libc::c_void)) };
                    *fresh28 = 0 as *mut libc::c_void;
                    let fresh29 = unsafe { &mut ((*part).data) };
                    *fresh29 = 0 as *const i8;
                    (unsafe { (*part).size = -(1 as i32) as curl_off_t });
                    res = CURLE_OK;
                }
            } else {
                if literal_value {
                    data = contp;
                } else {
                    sep = get_param_part(
                        config,
                        '\u{0}' as i32 as i8,
                        &mut contp,
                        &mut data,
                        &mut type_0,
                        &mut filename,
                        &mut encoder,
                        &mut headers,
                    );
                    if sep < 0 as i32 {
                        (unsafe { free(contents as *mut libc::c_void) });
                        contents = 0 as *mut i8;
                        return 17 as i32;
                    }
                }
                part = tool_mime_new_data(unsafe { *mimecurrent }, data);
                if part.is_null() {
                    (unsafe { warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const i8,
                    ) });
                    (unsafe { curl_slist_free_all(headers) });
                    (unsafe { free(contents as *mut libc::c_void) });
                    contents = 0 as *mut i8;
                    return 18 as i32;
                }
                let fresh30 = unsafe { &mut ((*part).headers) };
                *fresh30 = headers;
                headers = 0 as *mut curl_slist;
            }
            if !filename.is_null() {
                let fresh31 = unsafe { &mut ((*part).filename) };
                *fresh31 = unsafe { strdup(filename) };
                if (unsafe { (*part).filename }).is_null() {
                    (unsafe { warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const i8,
                    ) });
                    (unsafe { curl_slist_free_all(headers) });
                    (unsafe { free(contents as *mut libc::c_void) });
                    contents = 0 as *mut i8;
                    return 19 as i32;
                }
            }
            if !type_0.is_null() {
                let fresh32 = unsafe { &mut ((*part).type_0) };
                *fresh32 = unsafe { strdup(type_0) };
                if (unsafe { (*part).type_0 }).is_null() {
                    (unsafe { warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const i8,
                    ) });
                    (unsafe { curl_slist_free_all(headers) });
                    (unsafe { free(contents as *mut libc::c_void) });
                    contents = 0 as *mut i8;
                    return 20 as i32;
                }
            }
            if !encoder.is_null() {
                let fresh33 = unsafe { &mut ((*part).encoder) };
                *fresh33 = unsafe { strdup(encoder) };
                if (unsafe { (*part).encoder }).is_null() {
                    (unsafe { warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const i8,
                    ) });
                    (unsafe { curl_slist_free_all(headers) });
                    (unsafe { free(contents as *mut libc::c_void) });
                    contents = 0 as *mut i8;
                    return 21 as i32;
                }
            }
            if sep != 0 {
                (unsafe { *contp = sep as i8 });
                (unsafe { warnf(
                    (*config).global,
                    b"garbage at end of field specification: %s\n\0" as *const u8 as *const i8,
                    contp,
                ) });
            }
        }
        if !name.is_null() {
            let fresh34 = unsafe { &mut ((*part).name) };
            *fresh34 = unsafe { strdup(name) };
            if (unsafe { (*part).name }).is_null() {
                (unsafe { warnf(
                    (*config).global,
                    b"out of memory!\n\0" as *const u8 as *const i8,
                ) });
                (unsafe { curl_slist_free_all(headers) });
                (unsafe { free(contents as *mut libc::c_void) });
                contents = 0 as *mut i8;
                return 22 as i32;
            }
        }
    } else {
        (unsafe { warnf(
            (*config).global,
            b"Illegally formatted input field!\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { free(contents as *mut libc::c_void) });
        contents = 0 as *mut i8;
        return 23 as i32;
    }
    (unsafe { free(contents as *mut libc::c_void) });
    contents = 0 as *mut i8;
    return 0 as i32;
}
