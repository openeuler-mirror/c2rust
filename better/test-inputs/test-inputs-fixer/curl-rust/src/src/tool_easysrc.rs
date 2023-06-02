use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type curl_mime;
    static mut stdout: *mut FILE;
    fn fclose(__stream: *mut FILE) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut FILE;
    fn curl_free(p: *mut libc::c_void);
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn slist_wc_append(_: *mut slist_wc, _: *const i8) -> *mut slist_wc;
    fn slist_wc_free_all(_: *mut slist_wc);
    fn curl_mfprintf(fd: *mut FILE, format: *const i8, _: ...) -> i32;
    fn curl_mvaprintf(format: *const i8, args: ::std::ffi::VaList) -> *mut i8;
    fn warnf(config: *mut GlobalConfig, fmt: *const i8, _: ...);
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
pub struct slist_wc {
    pub first: *mut curl_slist,
    pub last: *mut curl_slist,
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
#[no_mangle]
pub static mut easysrc_decl: *mut slist_wc = 0 as *const slist_wc as *mut slist_wc;
#[no_mangle]
pub static mut easysrc_data: *mut slist_wc = 0 as *const slist_wc as *mut slist_wc;
#[no_mangle]
pub static mut easysrc_code: *mut slist_wc = 0 as *const slist_wc as *mut slist_wc;
#[no_mangle]
pub static mut easysrc_toohard: *mut slist_wc = 0 as *const slist_wc as *mut slist_wc;
#[no_mangle]
pub static mut easysrc_clean: *mut slist_wc = 0 as *const slist_wc as *mut slist_wc;
#[no_mangle]
pub static mut easysrc_mime_count: i32 = 0 as i32;
#[no_mangle]
pub static mut easysrc_slist_count: i32 = 0 as i32;
static mut srchead: [*const i8; 11] = [
    b"/********* Sample code generated by the curl command line tool **********\0" as *const u8
        as *const i8,
    b" * All curl_easy_setopt() options are documented at:\0" as *const u8 as *const i8,
    b" * https://curl.se/libcurl/c/curl_easy_setopt.html\0" as *const u8 as *const i8,
    b" ************************************************************************/\0" as *const u8
        as *const i8,
    b"#include <curl/curl.h>\0" as *const u8 as *const i8,
    b"\0" as *const u8 as *const i8,
    b"int main(int argc, char *argv[])\0" as *const u8 as *const i8,
    b"{\0" as *const u8 as *const i8,
    b"  CURLcode ret;\0" as *const u8 as *const i8,
    b"  CURL *hnd;\0" as *const u8 as *const i8,
    0 as *const i8,
];
static mut srchard: [*const i8; 5] = [
    b"/* Here is a list of options the curl code used that cannot get generated\0" as *const u8
        as *const i8,
    b"   as source easily. You may select to either not use them or implement\0" as *const u8
        as *const i8,
    b"   them yourself.\0" as *const u8 as *const i8,
    b"\0" as *const u8 as *const i8,
    0 as *const i8,
];
static mut srcend: [*const i8; 5] = [
    b"\0" as *const u8 as *const i8,
    b"  return (int)ret;\0" as *const u8 as *const i8,
    b"}\0" as *const u8 as *const i8,
    b"/**** End of sample code ****/\0" as *const u8 as *const i8,
    0 as *const i8,
];
extern "C" fn easysrc_free() {
    (unsafe { slist_wc_free_all(easysrc_decl) });
    (unsafe { easysrc_decl = 0 as *mut slist_wc });
    (unsafe { slist_wc_free_all(easysrc_data) });
    (unsafe { easysrc_data = 0 as *mut slist_wc });
    (unsafe { slist_wc_free_all(easysrc_code) });
    (unsafe { easysrc_code = 0 as *mut slist_wc });
    (unsafe { slist_wc_free_all(easysrc_toohard) });
    (unsafe { easysrc_toohard = 0 as *mut slist_wc });
    (unsafe { slist_wc_free_all(easysrc_clean) });
    (unsafe { easysrc_clean = 0 as *mut slist_wc });
}
#[no_mangle]
pub extern "C" fn easysrc_add(mut plist: *mut *mut slist_wc, mut line: *const i8) -> CURLcode {
    let mut ret: CURLcode = CURLE_OK;
    let mut list: *mut slist_wc = unsafe { slist_wc_append(*plist, line) };
    if list.is_null() {
        easysrc_free();
        ret = CURLE_OUT_OF_MEMORY;
    } else {
        (unsafe { *plist = list });
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn easysrc_addf(
    mut plist: *mut *mut slist_wc,
    mut fmt: *const i8,
    mut args: ...
) -> CURLcode {
    let mut ret: CURLcode = CURLE_OK;
    let mut bufp: *mut i8 = 0 as *mut i8;
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    bufp = curl_mvaprintf(fmt, ap.as_va_list());
    if bufp.is_null() {
        ret = CURLE_OUT_OF_MEMORY;
    } else {
        ret = easysrc_add(plist, bufp);
        curl_free(bufp as *mut libc::c_void);
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn easysrc_init() -> CURLcode {
    let mut ret: CURLcode = easysrc_add(
        unsafe { &mut easysrc_code },
        b"hnd = curl_easy_init();\0" as *const u8 as *const i8,
    );
    if ret as u64 != 0 {
        return ret;
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn easysrc_perform() -> CURLcode {
    if !(unsafe { easysrc_toohard }).is_null() {
        let mut i: i32 = 0;
        let mut ptr: *mut curl_slist = 0 as *mut curl_slist;
        let mut c: *const i8 = 0 as *const i8;
        let mut ret: CURLcode = easysrc_add(unsafe { &mut easysrc_code }, b"\0" as *const u8 as *const i8);
        if ret as u64 != 0 {
            return ret;
        }
        i = 0 as i32;
        loop {
            c = unsafe { srchard[i as usize] };
            if c.is_null() {
                break;
            }
            let mut ret_0: CURLcode = easysrc_add(unsafe { &mut easysrc_code }, c);
            if ret_0 as u64 != 0 {
                return ret_0;
            }
            i += 1;
        }
        if !(unsafe { easysrc_toohard }).is_null() {
            ptr = unsafe { (*easysrc_toohard).first };
            while !ptr.is_null() {
                let mut ret_1: CURLcode = easysrc_add(unsafe { &mut easysrc_code }, unsafe { (*ptr).data });
                if ret_1 as u64 != 0 {
                    return ret_1;
                }
                ptr = unsafe { (*ptr).next };
            }
        }
        let mut ret_2: CURLcode = easysrc_add(unsafe { &mut easysrc_code }, b"\0" as *const u8 as *const i8);
        if ret_2 as u64 != 0 {
            return ret_2;
        }
        let mut ret_3: CURLcode = easysrc_add(unsafe { &mut easysrc_code }, b"*/\0" as *const u8 as *const i8);
        if ret_3 as u64 != 0 {
            return ret_3;
        }
        (unsafe { slist_wc_free_all(easysrc_toohard) });
        (unsafe { easysrc_toohard = 0 as *mut slist_wc });
    }
    let mut ret_4: CURLcode = easysrc_add(unsafe { &mut easysrc_code }, b"\0" as *const u8 as *const i8);
    if ret_4 as u64 != 0 {
        return ret_4;
    }
    let mut ret_5: CURLcode = easysrc_add(
        unsafe { &mut easysrc_code },
        b"ret = curl_easy_perform(hnd);\0" as *const u8 as *const i8,
    );
    if ret_5 as u64 != 0 {
        return ret_5;
    }
    let mut ret_6: CURLcode = easysrc_add(unsafe { &mut easysrc_code }, b"\0" as *const u8 as *const i8);
    if ret_6 as u64 != 0 {
        return ret_6;
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn easysrc_cleanup() -> CURLcode {
    let mut ret: CURLcode = easysrc_add(
        unsafe { &mut easysrc_code },
        b"curl_easy_cleanup(hnd);\0" as *const u8 as *const i8,
    );
    if ret as u64 != 0 {
        return ret;
    }
    let mut ret_0: CURLcode = easysrc_add(
        unsafe { &mut easysrc_code },
        b"hnd = NULL;\0" as *const u8 as *const i8,
    );
    if ret_0 as u64 != 0 {
        return ret_0;
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn dumpeasysrc(mut config: *mut GlobalConfig) {
    let mut ptr: *mut curl_slist = 0 as *mut curl_slist;
    let mut o: *mut i8 = unsafe { (*config).libcurl };
    let mut out: *mut FILE = 0 as *mut FILE;
    let mut fopened: bool = 0 as i32 != 0;
    if (unsafe { strcmp(o, b"-\0" as *const u8 as *const i8) }) != 0 {
        out = unsafe { fopen(o, b"w\0" as *const u8 as *const i8) };
        fopened = 1 as i32 != 0;
    } else {
        out = unsafe { stdout };
    }
    if out.is_null() {
        (unsafe { warnf(
            config,
            b"Failed to open %s to write libcurl code!\n\0" as *const u8 as *const i8,
            o,
        ) });
    } else {
        let mut i: i32 = 0;
        let mut c: *const i8 = 0 as *const i8;
        i = 0 as i32;
        loop {
            c = unsafe { srchead[i as usize] };
            if c.is_null() {
                break;
            }
            (unsafe { curl_mfprintf(out, b"%s\n\0" as *const u8 as *const i8, c) });
            i += 1;
        }
        if !(unsafe { easysrc_decl }).is_null() {
            ptr = unsafe { (*easysrc_decl).first };
            while !ptr.is_null() {
                (unsafe { curl_mfprintf(out, b"  %s\n\0" as *const u8 as *const i8, (*ptr).data) });
                ptr = unsafe { (*ptr).next };
            }
        }
        if !(unsafe { easysrc_data }).is_null() {
            (unsafe { curl_mfprintf(out, b"\n\0" as *const u8 as *const i8) });
            ptr = unsafe { (*easysrc_data).first };
            while !ptr.is_null() {
                (unsafe { curl_mfprintf(out, b"  %s\n\0" as *const u8 as *const i8, (*ptr).data) });
                ptr = unsafe { (*ptr).next };
            }
        }
        (unsafe { curl_mfprintf(out, b"\n\0" as *const u8 as *const i8) });
        if !(unsafe { easysrc_code }).is_null() {
            ptr = unsafe { (*easysrc_code).first };
            while !ptr.is_null() {
                if (unsafe { *((*ptr).data).offset(0 as i32 as isize) }) != 0 {
                    (unsafe { curl_mfprintf(out, b"  %s\n\0" as *const u8 as *const i8, (*ptr).data) });
                } else {
                    (unsafe { curl_mfprintf(out, b"\n\0" as *const u8 as *const i8) });
                }
                ptr = unsafe { (*ptr).next };
            }
        }
        if !(unsafe { easysrc_clean }).is_null() {
            ptr = unsafe { (*easysrc_clean).first };
            while !ptr.is_null() {
                (unsafe { curl_mfprintf(out, b"  %s\n\0" as *const u8 as *const i8, (*ptr).data) });
                ptr = unsafe { (*ptr).next };
            }
        }
        i = 0 as i32;
        loop {
            c = unsafe { srcend[i as usize] };
            if c.is_null() {
                break;
            }
            (unsafe { curl_mfprintf(out, b"%s\n\0" as *const u8 as *const i8, c) });
            i += 1;
        }
        if fopened {
            (unsafe { fclose(out) });
        }
    }
    easysrc_free();
}
