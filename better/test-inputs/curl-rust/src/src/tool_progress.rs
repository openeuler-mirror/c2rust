use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type Curl_easy;
    pub type curl_mime;
    fn fputs(__s: *const libc::c_char, __stream: *mut FILE) -> libc::c_int;
    fn curl_easy_pause(handle: *mut CURL, bitmask: libc::c_int) -> CURLcode;
    fn strcpy(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    static mut transfers: *mut per_transfer;
    fn tvnow() -> timeval;
    fn tvdiff(t1: timeval, t2: timeval) -> libc::c_long;
    fn curl_msnprintf(
        buffer: *mut libc::c_char,
        maxlength: size_t,
        format: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn curl_mfprintf(fd: *mut FILE, format: *const libc::c_char, _: ...) -> libc::c_int;
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
pub type CURL = Curl_easy;
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
    pub filename: *mut libc::c_char,
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ProgressData {
    pub calls: libc::c_int,
    pub prev: curl_off_t,
    pub prevtime: timeval,
    pub width: libc::c_int,
    pub out: *mut FILE,
    pub initial_size: curl_off_t,
    pub tick: libc::c_uint,
    pub bar: libc::c_int,
    pub barmove: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct InStruct {
    pub fd: libc::c_int,
    pub config: *mut OperationConfig,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct per_transfer {
    pub next: *mut per_transfer,
    pub prev: *mut per_transfer,
    pub config: *mut OperationConfig,
    pub curl: *mut CURL,
    pub retry_numretries: libc::c_long,
    pub retry_sleep_default: libc::c_long,
    pub retry_sleep: libc::c_long,
    pub retrystart: timeval,
    pub this_url: *mut libc::c_char,
    pub urlnum: libc::c_uint,
    pub outfile: *mut libc::c_char,
    pub infdopen: bool,
    pub infd: libc::c_int,
    pub noprogress: bool,
    pub progressbar: ProgressData,
    pub outs: OutStruct,
    pub heads: OutStruct,
    pub etag_save: OutStruct,
    pub input: InStruct,
    pub hdrcbdata: HdrCbData,
    pub num_headers: libc::c_long,
    pub was_last_header_empty: bool,
    pub errorbuffer: [libc::c_char; 256],
    pub added: bool,
    pub startat: time_t,
    pub abort: bool,
    pub dltotal: curl_off_t,
    pub dlnow: curl_off_t,
    pub ultotal: curl_off_t,
    pub ulnow: curl_off_t,
    pub dltotal_added: bool,
    pub ultotal_added: bool,
    pub separator_err: *mut libc::c_char,
    pub separator: *mut libc::c_char,
    pub uploadfile: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct speedcount {
    pub dl: curl_off_t,
    pub ul: curl_off_t,
    pub stamp: timeval,
}
unsafe extern "C" fn max5data(
    mut bytes: curl_off_t,
    mut max5: *mut libc::c_char,
) -> *mut libc::c_char {
    if bytes < 100000 as libc::c_long {
        curl_msnprintf(
            max5,
            6 as libc::c_int as size_t,
            b"%5ld\0" as *const u8 as *const libc::c_char,
            bytes,
        );
    } else if bytes < 10000 as libc::c_long * 1024 as libc::c_long {
        curl_msnprintf(
            max5,
            6 as libc::c_int as size_t,
            b"%4ldk\0" as *const u8 as *const libc::c_char,
            bytes / 1024 as libc::c_long,
        );
    } else if bytes < 100 as libc::c_long * (1024 as libc::c_long * 1024 as libc::c_long)
        {
        curl_msnprintf(
            max5,
            6 as libc::c_int as size_t,
            b"%2ld.%0ldM\0" as *const u8 as *const libc::c_char,
            bytes / (1024 as libc::c_long * 1024 as libc::c_long),
            bytes % (1024 as libc::c_long * 1024 as libc::c_long)
                / (1024 as libc::c_long * 1024 as libc::c_long / 10 as libc::c_long),
        );
    } else if bytes
            < 10000 as libc::c_long * (1024 as libc::c_long * 1024 as libc::c_long)
        {
        curl_msnprintf(
            max5,
            6 as libc::c_int as size_t,
            b"%4ldM\0" as *const u8 as *const libc::c_char,
            bytes / (1024 as libc::c_long * 1024 as libc::c_long),
        );
    } else if bytes
            < 100 as libc::c_long
                * (1024 as libc::c_long * (1024 as libc::c_long * 1024 as libc::c_long))
        {
        curl_msnprintf(
            max5,
            6 as libc::c_int as size_t,
            b"%2ld.%0ldG\0" as *const u8 as *const libc::c_char,
            bytes
                / (1024 as libc::c_long * (1024 as libc::c_long * 1024 as libc::c_long)),
            bytes
                % (1024 as libc::c_long * (1024 as libc::c_long * 1024 as libc::c_long))
                / (1024 as libc::c_long * (1024 as libc::c_long * 1024 as libc::c_long)
                    / 10 as libc::c_long),
        );
    } else if bytes
            < 10000 as libc::c_long
                * (1024 as libc::c_long * (1024 as libc::c_long * 1024 as libc::c_long))
        {
        curl_msnprintf(
            max5,
            6 as libc::c_int as size_t,
            b"%4ldG\0" as *const u8 as *const libc::c_char,
            bytes
                / (1024 as libc::c_long * (1024 as libc::c_long * 1024 as libc::c_long)),
        );
    } else if bytes
            < 10000 as libc::c_long
                * (1024 as libc::c_long
                    * (1024 as libc::c_long
                        * (1024 as libc::c_long * 1024 as libc::c_long)))
        {
        curl_msnprintf(
            max5,
            6 as libc::c_int as size_t,
            b"%4ldT\0" as *const u8 as *const libc::c_char,
            bytes
                / (1024 as libc::c_long
                    * (1024 as libc::c_long
                        * (1024 as libc::c_long * 1024 as libc::c_long))),
        );
    } else {
        curl_msnprintf(
            max5,
            6 as libc::c_int as size_t,
            b"%4ldP\0" as *const u8 as *const libc::c_char,
            bytes
                / (1024 as libc::c_long
                    * (1024 as libc::c_long
                        * (1024 as libc::c_long
                            * (1024 as libc::c_long * 1024 as libc::c_long)))),
        );
    }
    return max5;
}
#[no_mangle]
pub unsafe extern "C" fn xferinfo_cb(
    mut clientp: *mut libc::c_void,
    mut dltotal: curl_off_t,
    mut dlnow: curl_off_t,
    mut ultotal: curl_off_t,
    mut ulnow: curl_off_t,
) -> libc::c_int {
    let mut per: *mut per_transfer = clientp as *mut per_transfer;
    let mut config: *mut OperationConfig = (*per).config;
    (*per).dltotal = dltotal;
    (*per).dlnow = dlnow;
    (*per).ultotal = ultotal;
    (*per).ulnow = ulnow;
    if (*per).abort {
        return 1 as libc::c_int;
    }
    if (*config).readbusy {
        (*config).readbusy = 0 as libc::c_int != 0;
        curl_easy_pause((*per).curl, 0 as libc::c_int | 0 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn time2str(mut r: *mut libc::c_char, mut seconds: curl_off_t) {
    let mut h: curl_off_t = 0;
    if seconds <= 0 as libc::c_int as libc::c_long {
        strcpy(r, b"--:--:--\0" as *const u8 as *const libc::c_char);
        return;
    }
    h = seconds / 3600 as libc::c_long;
    if h <= 99 as libc::c_long {
        let mut m: curl_off_t = (seconds - h * 3600 as libc::c_long)
            / 60 as libc::c_long;
        let mut s: curl_off_t = seconds - h * 3600 as libc::c_long
            - m * 60 as libc::c_long;
        curl_msnprintf(
            r,
            9 as libc::c_int as size_t,
            b"%2ld:%02ld:%02ld\0" as *const u8 as *const libc::c_char,
            h,
            m,
            s,
        );
    } else {
        let mut d: curl_off_t = seconds / 86400 as libc::c_long;
        h = (seconds - d * 86400 as libc::c_long) / 3600 as libc::c_long;
        if d <= 999 as libc::c_long {
            curl_msnprintf(
                r,
                9 as libc::c_int as size_t,
                b"%3ldd %02ldh\0" as *const u8 as *const libc::c_char,
                d,
                h,
            );
        } else {
            curl_msnprintf(
                r,
                9 as libc::c_int as size_t,
                b"%7ldd\0" as *const u8 as *const libc::c_char,
                d,
            );
        }
    };
}
static mut all_dltotal: curl_off_t = 0 as libc::c_int as curl_off_t;
static mut all_ultotal: curl_off_t = 0 as libc::c_int as curl_off_t;
static mut all_dlalready: curl_off_t = 0 as libc::c_int as curl_off_t;
static mut all_ulalready: curl_off_t = 0 as libc::c_int as curl_off_t;
#[no_mangle]
pub static mut all_xfers: curl_off_t = 0 as libc::c_int as curl_off_t;
static mut speedindex: libc::c_uint = 0;
static mut indexwrapped: bool = false;
static mut speedstore: [speedcount; 10] = [speedcount {
    dl: 0,
    ul: 0,
    stamp: timeval { tv_sec: 0, tv_usec: 0 },
}; 10];
#[no_mangle]
pub unsafe extern "C" fn progress_meter(
    mut global: *mut GlobalConfig,
    mut start: *mut timeval,
    mut final_0: bool,
) -> bool {
    static mut stamp: timeval = timeval { tv_sec: 0, tv_usec: 0 };
    static mut header: bool = 0 as libc::c_int != 0;
    let mut now: timeval = timeval { tv_sec: 0, tv_usec: 0 };
    let mut diff: libc::c_long = 0;
    if (*global).noprogress {
        return 0 as libc::c_int != 0;
    }
    now = tvnow();
    diff = tvdiff(now, stamp);
    if !header {
        header = 1 as libc::c_int != 0;
        fputs(
            b"DL% UL%  Dled  Uled  Xfers  Live   Qd Total     Current  Left    Speed\n\0"
                as *const u8 as *const libc::c_char,
            (*global).errors,
        );
    }
    if final_0 as libc::c_int != 0 || diff > 500 as libc::c_int as libc::c_long {
        let mut time_left: [libc::c_char; 10] = [0; 10];
        let mut time_total: [libc::c_char; 10] = [0; 10];
        let mut time_spent: [libc::c_char; 10] = [0; 10];
        let mut buffer: [[libc::c_char; 6]; 3] = [[0; 6]; 3];
        let mut spent: curl_off_t = tvdiff(now, *start)
            / 1000 as libc::c_int as libc::c_long;
        let mut dlpercen: [libc::c_char; 4] = *::std::mem::transmute::<
            &[u8; 4],
            &mut [libc::c_char; 4],
        >(b"--\0\0");
        let mut ulpercen: [libc::c_char; 4] = *::std::mem::transmute::<
            &[u8; 4],
            &mut [libc::c_char; 4],
        >(b"--\0\0");
        let mut per: *mut per_transfer = 0 as *mut per_transfer;
        let mut all_dlnow: curl_off_t = 0 as libc::c_int as curl_off_t;
        let mut all_ulnow: curl_off_t = 0 as libc::c_int as curl_off_t;
        let mut dlknown: bool = 1 as libc::c_int != 0;
        let mut ulknown: bool = 1 as libc::c_int != 0;
        let mut all_running: curl_off_t = 0 as libc::c_int as curl_off_t;
        let mut all_queued: curl_off_t = 0 as libc::c_int as curl_off_t;
        let mut speed: curl_off_t = 0 as libc::c_int as curl_off_t;
        let mut i: libc::c_uint = 0;
        stamp = now;
        all_dlnow += all_dlalready;
        all_ulnow += all_ulalready;
        per = transfers;
        while !per.is_null() {
            all_dlnow += (*per).dlnow;
            all_ulnow += (*per).ulnow;
            if (*per).dltotal == 0 {
                dlknown = 0 as libc::c_int != 0;
            } else if !(*per).dltotal_added {
                all_dltotal += (*per).dltotal;
                (*per).dltotal_added = 1 as libc::c_int != 0;
            }
            if (*per).ultotal == 0 {
                ulknown = 0 as libc::c_int != 0;
            } else if !(*per).ultotal_added {
                all_ultotal += (*per).ultotal;
                (*per).ultotal_added = 1 as libc::c_int != 0;
            }
            if !(*per).added {
                all_queued += 1;
            } else {
                all_running += 1;
            }
            per = (*per).next;
        }
        if dlknown as libc::c_int != 0 && all_dltotal != 0 {
            curl_msnprintf(
                dlpercen.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 4]>() as libc::c_ulong,
                b"%3ld\0" as *const u8 as *const libc::c_char,
                all_dlnow * 100 as libc::c_int as libc::c_long / all_dltotal,
            );
        }
        if ulknown as libc::c_int != 0 && all_ultotal != 0 {
            curl_msnprintf(
                ulpercen.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 4]>() as libc::c_ulong,
                b"%3ld\0" as *const u8 as *const libc::c_char,
                all_ulnow * 100 as libc::c_int as libc::c_long / all_ultotal,
            );
        }
        i = speedindex;
        speedstore[i as usize].dl = all_dlnow;
        speedstore[i as usize].ul = all_ulnow;
        speedstore[i as usize].stamp = now;
        speedindex = speedindex.wrapping_add(1);
        if speedindex >= 10 as libc::c_int as libc::c_uint {
            indexwrapped = 1 as libc::c_int != 0;
            speedindex = 0 as libc::c_int as libc::c_uint;
        }
        let mut deltams: libc::c_long = 0;
        let mut dl: curl_off_t = 0;
        let mut ul: curl_off_t = 0;
        let mut dls: curl_off_t = 0;
        let mut uls: curl_off_t = 0;
        if indexwrapped {
            deltams = tvdiff(now, speedstore[speedindex as usize].stamp);
            dl = all_dlnow - speedstore[speedindex as usize].dl;
            ul = all_ulnow - speedstore[speedindex as usize].ul;
        } else {
            deltams = tvdiff(now, *start);
            dl = all_dlnow;
            ul = all_ulnow;
        }
        dls = (dl as libc::c_double / (deltams as libc::c_double / 1000.0f64))
            as curl_off_t;
        uls = (ul as libc::c_double / (deltams as libc::c_double / 1000.0f64))
            as curl_off_t;
        speed = if dls > uls { dls } else { uls };
        if dlknown as libc::c_int != 0 && speed != 0 {
            let mut est: curl_off_t = all_dltotal / speed;
            let mut left: curl_off_t = (all_dltotal - all_dlnow) / speed;
            time2str(time_left.as_mut_ptr(), left);
            time2str(time_total.as_mut_ptr(), est);
        } else {
            time2str(time_left.as_mut_ptr(), 0 as libc::c_int as curl_off_t);
            time2str(time_total.as_mut_ptr(), 0 as libc::c_int as curl_off_t);
        }
        time2str(time_spent.as_mut_ptr(), spent);
        curl_mfprintf(
            (*global).errors,
            b"\r%-3s %-3s %s %s %5ld %5ld %5ld %s %s %s %s %5s\0" as *const u8
                as *const libc::c_char,
            dlpercen.as_mut_ptr(),
            ulpercen.as_mut_ptr(),
            max5data(all_dlnow, (buffer[0 as libc::c_int as usize]).as_mut_ptr()),
            max5data(all_ulnow, (buffer[1 as libc::c_int as usize]).as_mut_ptr()),
            all_xfers,
            all_running,
            all_queued,
            time_total.as_mut_ptr(),
            time_spent.as_mut_ptr(),
            time_left.as_mut_ptr(),
            max5data(speed, (buffer[2 as libc::c_int as usize]).as_mut_ptr()),
            if final_0 as libc::c_int != 0 {
                b"\n\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
        );
        return 1 as libc::c_int != 0;
    }
    return 0 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn progress_finalize(mut per: *mut per_transfer) {
    all_dlalready += (*per).dlnow;
    all_ulalready += (*per).ulnow;
    if !(*per).dltotal_added {
        all_dltotal += (*per).dltotal;
        (*per).dltotal_added = 1 as libc::c_int != 0;
    }
    if !(*per).ultotal_added {
        all_ultotal += (*per).ultotal;
        (*per).ultotal_added = 1 as libc::c_int != 0;
    }
}
