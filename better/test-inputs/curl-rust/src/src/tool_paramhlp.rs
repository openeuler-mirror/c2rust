use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type curl_mime;
    fn fgets(
        __s: *mut libc::c_char,
        __n: libc::c_int,
        __stream: *mut FILE,
    ) -> *mut libc::c_char;
    fn fread(
        _: *mut libc::c_void,
        _: libc::c_ulong,
        _: libc::c_ulong,
        _: *mut FILE,
    ) -> libc::c_ulong;
    fn curl_strequal(s1: *const libc::c_char, s2: *const libc::c_char) -> libc::c_int;
    fn curl_slist_append(_: *mut curl_slist, _: *const libc::c_char) -> *mut curl_slist;
    fn curl_version_info(_: CURLversion) -> *mut curl_version_info_data;
    fn strtod(_: *const libc::c_char, _: *mut *mut libc::c_char) -> libc::c_double;
    fn strtol(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_long;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strtok(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn __errno_location() -> *mut libc::c_int;
    fn Curl_isalnum(c: libc::c_int) -> libc::c_int;
    fn curl_msnprintf(
        buffer: *mut libc::c_char,
        maxlength: size_t,
        format: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn getpass_r(
        prompt: *const libc::c_char,
        buffer: *mut libc::c_char,
        buflen: size_t,
    ) -> *mut libc::c_char;
    fn warnf(config: *mut GlobalConfig, fmt: *const libc::c_char, _: ...);
    fn errorf(config: *mut GlobalConfig, fmt: *const libc::c_char, _: ...);
    fn curlx_dyn_init(s: *mut dynbuf, toobig: size_t);
    fn curlx_dyn_addn(s: *mut dynbuf, mem: *const libc::c_void, len: size_t) -> CURLcode;
    fn curlx_dyn_add(s: *mut dynbuf, str: *const libc::c_char) -> CURLcode;
    fn curlx_dyn_addf(s: *mut dynbuf, fmt: *const libc::c_char, _: ...) -> CURLcode;
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
pub type C2RustUnnamed = libc::c_uint;
pub const CURLFTPSSL_CCC_LAST: C2RustUnnamed = 3;
pub const CURLFTPSSL_CCC_ACTIVE: C2RustUnnamed = 2;
pub const CURLFTPSSL_CCC_PASSIVE: C2RustUnnamed = 1;
pub const CURLFTPSSL_CCC_NONE: C2RustUnnamed = 0;
pub type C2RustUnnamed_0 = libc::c_uint;
pub const CURLFTPMETHOD_LAST: C2RustUnnamed_0 = 4;
pub const CURLFTPMETHOD_SINGLECWD: C2RustUnnamed_0 = 3;
pub const CURLFTPMETHOD_NOCWD: C2RustUnnamed_0 = 2;
pub const CURLFTPMETHOD_MULTICWD: C2RustUnnamed_0 = 1;
pub const CURLFTPMETHOD_DEFAULT: C2RustUnnamed_0 = 0;
pub type C2RustUnnamed_1 = libc::c_uint;
pub const CURL_SSLVERSION_MAX_LAST: C2RustUnnamed_1 = 524288;
pub const CURL_SSLVERSION_MAX_TLSv1_3: C2RustUnnamed_1 = 458752;
pub const CURL_SSLVERSION_MAX_TLSv1_2: C2RustUnnamed_1 = 393216;
pub const CURL_SSLVERSION_MAX_TLSv1_1: C2RustUnnamed_1 = 327680;
pub const CURL_SSLVERSION_MAX_TLSv1_0: C2RustUnnamed_1 = 262144;
pub const CURL_SSLVERSION_MAX_DEFAULT: C2RustUnnamed_1 = 65536;
pub const CURL_SSLVERSION_MAX_NONE: C2RustUnnamed_1 = 0;
pub type curl_TimeCond = libc::c_uint;
pub const CURL_TIMECOND_LAST: curl_TimeCond = 4;
pub const CURL_TIMECOND_LASTMOD: curl_TimeCond = 3;
pub const CURL_TIMECOND_IFUNMODSINCE: curl_TimeCond = 2;
pub const CURL_TIMECOND_IFMODSINCE: curl_TimeCond = 1;
pub const CURL_TIMECOND_NONE: curl_TimeCond = 0;
pub type CURLversion = libc::c_uint;
pub const CURLVERSION_LAST: CURLversion = 10;
pub const CURLVERSION_TENTH: CURLversion = 9;
pub const CURLVERSION_NINTH: CURLversion = 8;
pub const CURLVERSION_EIGHTH: CURLversion = 7;
pub const CURLVERSION_SEVENTH: CURLversion = 6;
pub const CURLVERSION_SIXTH: CURLversion = 5;
pub const CURLVERSION_FIFTH: CURLversion = 4;
pub const CURLVERSION_FOURTH: CURLversion = 3;
pub const CURLVERSION_THIRD: CURLversion = 2;
pub const CURLVERSION_SECOND: CURLversion = 1;
pub const CURLVERSION_FIRST: CURLversion = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_version_info_data {
    pub age: CURLversion,
    pub version: *const libc::c_char,
    pub version_num: libc::c_uint,
    pub host: *const libc::c_char,
    pub features: libc::c_int,
    pub ssl_version: *const libc::c_char,
    pub ssl_version_num: libc::c_long,
    pub libz_version: *const libc::c_char,
    pub protocols: *const *const libc::c_char,
    pub ares: *const libc::c_char,
    pub ares_num: libc::c_int,
    pub libidn: *const libc::c_char,
    pub iconv_ver_num: libc::c_int,
    pub libssh_version: *const libc::c_char,
    pub brotli_ver_num: libc::c_uint,
    pub brotli_version: *const libc::c_char,
    pub nghttp2_ver_num: libc::c_uint,
    pub nghttp2_version: *const libc::c_char,
    pub quic_version: *const libc::c_char,
    pub cainfo: *const libc::c_char,
    pub capath: *const libc::c_char,
    pub zstd_ver_num: libc::c_uint,
    pub zstd_version: *const libc::c_char,
    pub hyper_version: *const libc::c_char,
    pub gsasl_version: *const libc::c_char,
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
    pub content: C2RustUnnamed_2,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_2 {
    pub Set: C2RustUnnamed_5,
    pub CharRange: C2RustUnnamed_4,
    pub NumRange: C2RustUnnamed_3,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_3 {
    pub min_n: libc::c_ulong,
    pub max_n: libc::c_ulong,
    pub padlength: libc::c_int,
    pub ptr_n: libc::c_ulong,
    pub step: libc::c_ulong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_4 {
    pub min_c: libc::c_char,
    pub max_c: libc::c_char,
    pub ptr_c: libc::c_char,
    pub step: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_5 {
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
pub const set: e_action = 2;
pub type e_action = libc::c_uint;
pub const deny: e_action = 1;
pub const allow: e_action = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sprotos {
    pub name: *const libc::c_char,
    pub bit: libc::c_long,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct s_tls_max {
    pub tls_max_str: *const libc::c_char,
    pub tls_max: libc::c_long,
}
#[no_mangle]
pub unsafe extern "C" fn new_getout(mut config: *mut OperationConfig) -> *mut getout {
    let mut node: *mut getout = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::std::mem::size_of::<getout>() as libc::c_ulong,
    ) as *mut getout;
    let mut last: *mut getout = (*config).url_last;
    if !node.is_null() {
        static mut outnum: libc::c_int = 0 as libc::c_int;
        if !last.is_null() {
            let ref mut fresh0 = (*last).next;
            *fresh0 = node;
        } else {
            let ref mut fresh1 = (*config).url_list;
            *fresh1 = node;
        }
        let ref mut fresh2 = (*config).url_last;
        *fresh2 = node;
        (*node).flags = (*config).default_node_flags;
        let fresh3 = outnum;
        outnum = outnum + 1;
        (*node).num = fresh3;
    }
    return node;
}
#[no_mangle]
pub unsafe extern "C" fn file2string(
    mut bufp: *mut *mut libc::c_char,
    mut file: *mut FILE,
) -> ParameterError {
    let mut dyn_0: dynbuf = dynbuf {
        bufr: 0 as *mut libc::c_char,
        leng: 0,
        allc: 0,
        toobig: 0,
    };
    curlx_dyn_init(
        &mut dyn_0,
        (256 as libc::c_int * 1024 as libc::c_int * 1024 as libc::c_int) as size_t,
    );
    if !file.is_null() {
        let mut buffer: [libc::c_char; 256] = [0; 256];
        while !(fgets(
            buffer.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong as libc::c_int,
            file,
        ))
            .is_null()
        {
            let mut ptr: *mut libc::c_char = strchr(buffer.as_mut_ptr(), '\r' as i32);
            if !ptr.is_null() {
                *ptr = '\u{0}' as i32 as libc::c_char;
            }
            ptr = strchr(buffer.as_mut_ptr(), '\n' as i32);
            if !ptr.is_null() {
                *ptr = '\u{0}' as i32 as libc::c_char;
            }
            if curlx_dyn_add(&mut dyn_0, buffer.as_mut_ptr()) as u64 != 0 {
                return PARAM_NO_MEM;
            }
        }
    }
    *bufp = curlx_dyn_ptr(&mut dyn_0);
    return PARAM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn file2memory(
    mut bufp: *mut *mut libc::c_char,
    mut size: *mut size_t,
    mut file: *mut FILE,
) -> ParameterError {
    if !file.is_null() {
        let mut nread: size_t = 0;
        let mut dyn_0: dynbuf = dynbuf {
            bufr: 0 as *mut libc::c_char,
            leng: 0,
            allc: 0,
            toobig: 0,
        };
        curlx_dyn_init(
            &mut dyn_0,
            (1024 as libc::c_int * 1024 as libc::c_int * 1024 as libc::c_int) as size_t,
        );
        loop {
            let mut buffer: [libc::c_char; 4096] = [0; 4096];
            nread = fread(
                buffer.as_mut_ptr() as *mut libc::c_void,
                1 as libc::c_int as libc::c_ulong,
                ::std::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
                file,
            );
            if nread != 0 {
                if curlx_dyn_addn(
                    &mut dyn_0,
                    buffer.as_mut_ptr() as *const libc::c_void,
                    nread,
                ) as u64 != 0
                {
                    return PARAM_NO_MEM;
                }
            }
            if !(nread != 0) {
                break;
            }
        }
        *size = curlx_dyn_len(&mut dyn_0);
        *bufp = curlx_dyn_ptr(&mut dyn_0);
    } else {
        *size = 0 as libc::c_int as size_t;
        *bufp = 0 as *mut libc::c_char;
    }
    return PARAM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn cleanarg(mut str: *mut libc::c_char) {
    if !str.is_null() {
        let mut len: size_t = strlen(str);
        memset(str as *mut libc::c_void, ' ' as i32, len);
    }
}
unsafe extern "C" fn getnum(
    mut val: *mut libc::c_long,
    mut str: *const libc::c_char,
    mut base: libc::c_int,
) -> ParameterError {
    if !str.is_null() {
        let mut endptr: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut num: libc::c_long = 0;
        *__errno_location() = 0 as libc::c_int;
        num = strtol(str, &mut endptr, base);
        if *__errno_location() == 34 as libc::c_int {
            return PARAM_NUMBER_TOO_LARGE;
        }
        if endptr != str as *mut libc::c_char
            && endptr == str.offset(strlen(str) as isize) as *mut libc::c_char
        {
            *val = num;
            return PARAM_OK;
        }
    }
    return PARAM_BAD_NUMERIC;
}
#[no_mangle]
pub unsafe extern "C" fn str2num(
    mut val: *mut libc::c_long,
    mut str: *const libc::c_char,
) -> ParameterError {
    return getnum(val, str, 10 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn oct2nummax(
    mut val: *mut libc::c_long,
    mut str: *const libc::c_char,
    mut max: libc::c_long,
) -> ParameterError {
    let mut result: ParameterError = getnum(val, str, 8 as libc::c_int);
    if result as libc::c_uint != PARAM_OK as libc::c_int as libc::c_uint {
        return result
    } else {
        if *val > max {
            return PARAM_NUMBER_TOO_LARGE
        } else {
            if *val < 0 as libc::c_int as libc::c_long {
                return PARAM_NEGATIVE_NUMERIC;
            }
        }
    }
    return PARAM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn str2unum(
    mut val: *mut libc::c_long,
    mut str: *const libc::c_char,
) -> ParameterError {
    let mut result: ParameterError = getnum(val, str, 10 as libc::c_int);
    if result as libc::c_uint != PARAM_OK as libc::c_int as libc::c_uint {
        return result;
    }
    if *val < 0 as libc::c_int as libc::c_long {
        return PARAM_NEGATIVE_NUMERIC;
    }
    return PARAM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn str2unummax(
    mut val: *mut libc::c_long,
    mut str: *const libc::c_char,
    mut max: libc::c_long,
) -> ParameterError {
    let mut result: ParameterError = str2unum(val, str);
    if result as libc::c_uint != PARAM_OK as libc::c_int as libc::c_uint {
        return result;
    }
    if *val > max {
        return PARAM_NUMBER_TOO_LARGE;
    }
    return PARAM_OK;
}
unsafe extern "C" fn str2double(
    mut val: *mut libc::c_double,
    mut str: *const libc::c_char,
    mut max: libc::c_long,
) -> ParameterError {
    if !str.is_null() {
        let mut endptr: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut num: libc::c_double = 0.;
        *__errno_location() = 0 as libc::c_int;
        num = strtod(str, &mut endptr);
        if *__errno_location() == 34 as libc::c_int {
            return PARAM_NUMBER_TOO_LARGE;
        }
        if num > max as libc::c_double {
            return PARAM_NUMBER_TOO_LARGE;
        }
        if endptr != str as *mut libc::c_char
            && endptr == str.offset(strlen(str) as isize) as *mut libc::c_char
        {
            *val = num;
            return PARAM_OK;
        }
    }
    return PARAM_BAD_NUMERIC;
}
#[no_mangle]
pub unsafe extern "C" fn str2udouble(
    mut valp: *mut libc::c_double,
    mut str: *const libc::c_char,
    mut max: libc::c_long,
) -> ParameterError {
    let mut value: libc::c_double = 0.;
    let mut result: ParameterError = str2double(&mut value, str, max);
    if result as libc::c_uint != PARAM_OK as libc::c_int as libc::c_uint {
        return result;
    }
    if value < 0 as libc::c_int as libc::c_double {
        return PARAM_NEGATIVE_NUMERIC;
    }
    *valp = value;
    return PARAM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn proto2num(
    mut config: *mut OperationConfig,
    mut val: *mut libc::c_long,
    mut str: *const libc::c_char,
) -> libc::c_long {
    let mut buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sep: *const libc::c_char = b",\0" as *const u8 as *const libc::c_char;
    let mut token: *mut libc::c_char = 0 as *mut libc::c_char;
    static mut protos: [sprotos; 24] = [
        {
            let mut init = sprotos {
                name: b"all\0" as *const u8 as *const libc::c_char,
                bit: !(0 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"http\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"https\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"ftp\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"ftps\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"scp\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"sftp\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"telnet\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 6 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"ldap\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 7 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"ldaps\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 8 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"dict\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 9 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"file\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 10 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"tftp\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 11 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"imap\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 12 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"imaps\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 13 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"pop3\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 14 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"pop3s\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 15 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"smtp\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 16 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"smtps\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 17 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"rtsp\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 18 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"gopher\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 25 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"smb\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 26 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: b"smbs\0" as *const u8 as *const libc::c_char,
                bit: ((1 as libc::c_int) << 27 as libc::c_int) as libc::c_long,
            };
            init
        },
        {
            let mut init = sprotos {
                name: 0 as *const libc::c_char,
                bit: 0 as libc::c_int as libc::c_long,
            };
            init
        },
    ];
    if str.is_null() {
        return 1 as libc::c_int as libc::c_long;
    }
    buffer = strdup(str);
    if buffer.is_null() {
        return 1 as libc::c_int as libc::c_long;
    }
    token = strtok(buffer, sep);
    while !token.is_null() {
        let mut action: e_action = allow;
        let mut pp: *const sprotos = 0 as *const sprotos;
        while Curl_isalnum(*token as libc::c_uchar as libc::c_int) == 0 {
            let fresh4 = token;
            token = token.offset(1);
            match *fresh4 as libc::c_int {
                61 => {
                    action = set;
                }
                45 => {
                    action = deny;
                }
                43 => {
                    action = allow;
                }
                _ => {
                    free(buffer as *mut libc::c_void);
                    buffer = 0 as *mut libc::c_char;
                    return 1 as libc::c_int as libc::c_long;
                }
            }
        }
        pp = protos.as_ptr();
        while !((*pp).name).is_null() {
            if curl_strequal(token, (*pp).name) != 0 {
                match action as libc::c_uint {
                    1 => {
                        *val &= !(*pp).bit;
                    }
                    0 => {
                        *val |= (*pp).bit;
                    }
                    2 => {
                        *val = (*pp).bit;
                    }
                    _ => {}
                }
                break;
            } else {
                pp = pp.offset(1);
            }
        }
        if ((*pp).name).is_null() {
            if action as libc::c_uint == set as libc::c_int as libc::c_uint {
                *val = 0 as libc::c_int as libc::c_long;
            }
            warnf(
                (*config).global,
                b"unrecognized protocol '%s'\n\0" as *const u8 as *const libc::c_char,
                token,
            );
        }
        token = strtok(0 as *mut libc::c_char, sep);
    }
    free(buffer as *mut libc::c_void);
    buffer = 0 as *mut libc::c_char;
    return 0 as libc::c_int as libc::c_long;
}
#[no_mangle]
pub unsafe extern "C" fn check_protocol(mut str: *const libc::c_char) -> libc::c_int {
    let mut pp: *const *const libc::c_char = 0 as *const *const libc::c_char;
    let mut curlinfo: *const curl_version_info_data = curl_version_info(
        CURLVERSION_TENTH,
    );
    if str.is_null() {
        return PARAM_REQUIRES_PARAMETER as libc::c_int;
    }
    pp = (*curlinfo).protocols;
    while !(*pp).is_null() {
        if curl_strequal(*pp, str) != 0 {
            return PARAM_OK as libc::c_int;
        }
        pp = pp.offset(1);
    }
    return PARAM_LIBCURL_UNSUPPORTED_PROTOCOL as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn str2offset(
    mut val: *mut curl_off_t,
    mut str: *const libc::c_char,
) -> ParameterError {
    let mut endptr: *mut libc::c_char = 0 as *mut libc::c_char;
    if *str.offset(0 as libc::c_int as isize) as libc::c_int == '-' as i32 {
        return PARAM_NEGATIVE_NUMERIC;
    }
    *__errno_location() = 0 as libc::c_int;
    *val = strtol(str, &mut endptr, 0 as libc::c_int);
    if (*val == -(9223372036854775807 as libc::c_long) - 1 as libc::c_long
        || *val == 9223372036854775807 as libc::c_long)
        && *__errno_location() == 34 as libc::c_int
    {
        return PARAM_NUMBER_TOO_LARGE;
    }
    if endptr != str as *mut libc::c_char
        && endptr == str.offset(strlen(str) as isize) as *mut libc::c_char
    {
        return PARAM_OK;
    }
    return PARAM_BAD_NUMERIC;
}
unsafe extern "C" fn checkpasswd(
    mut kind: *const libc::c_char,
    i: size_t,
    last: bool,
    mut userpwd: *mut *mut libc::c_char,
) -> CURLcode {
    let mut psep: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut osep: *mut libc::c_char = 0 as *mut libc::c_char;
    if (*userpwd).is_null() {
        return CURLE_OK;
    }
    psep = strchr(*userpwd, ':' as i32);
    osep = strchr(*userpwd, ';' as i32);
    if psep.is_null() && **userpwd as libc::c_int != ';' as i32 {
        let mut passwd: [libc::c_char; 2048] = *::std::mem::transmute::<
            &[u8; 2048],
            &mut [libc::c_char; 2048],
        >(
            b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        );
        let mut prompt: [libc::c_char; 256] = [0; 256];
        let mut dyn_0: dynbuf = dynbuf {
            bufr: 0 as *mut libc::c_char,
            leng: 0,
            allc: 0,
            toobig: 0,
        };
        curlx_dyn_init(&mut dyn_0, (100 as libc::c_int * 1024 as libc::c_int) as size_t);
        if !osep.is_null() {
            *osep = '\u{0}' as i32 as libc::c_char;
        }
        if i == 0 && last as libc::c_int != 0 {
            curl_msnprintf(
                prompt.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                b"Enter %s password for user '%s':\0" as *const u8
                    as *const libc::c_char,
                kind,
                *userpwd,
            );
        } else {
            curl_msnprintf(
                prompt.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                b"Enter %s password for user '%s' on URL #%zu:\0" as *const u8
                    as *const libc::c_char,
                kind,
                *userpwd,
                i.wrapping_add(1 as libc::c_int as libc::c_ulong),
            );
        }
        getpass_r(
            prompt.as_mut_ptr(),
            passwd.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong,
        );
        if !osep.is_null() {
            *osep = ';' as i32 as libc::c_char;
        }
        if curlx_dyn_addf(
            &mut dyn_0 as *mut dynbuf,
            b"%s:%s\0" as *const u8 as *const libc::c_char,
            *userpwd,
            passwd.as_mut_ptr(),
        ) as u64 != 0
        {
            return CURLE_OUT_OF_MEMORY;
        }
        free(*userpwd as *mut libc::c_void);
        *userpwd = curlx_dyn_ptr(&mut dyn_0);
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn add2list(
    mut list: *mut *mut curl_slist,
    mut ptr: *const libc::c_char,
) -> ParameterError {
    let mut newlist: *mut curl_slist = curl_slist_append(*list, ptr);
    if !newlist.is_null() {
        *list = newlist;
    } else {
        return PARAM_NO_MEM
    }
    return PARAM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn ftpfilemethod(
    mut config: *mut OperationConfig,
    mut str: *const libc::c_char,
) -> libc::c_int {
    if curl_strequal(b"singlecwd\0" as *const u8 as *const libc::c_char, str) != 0 {
        return CURLFTPMETHOD_SINGLECWD as libc::c_int;
    }
    if curl_strequal(b"nocwd\0" as *const u8 as *const libc::c_char, str) != 0 {
        return CURLFTPMETHOD_NOCWD as libc::c_int;
    }
    if curl_strequal(b"multicwd\0" as *const u8 as *const libc::c_char, str) != 0 {
        return CURLFTPMETHOD_MULTICWD as libc::c_int;
    }
    warnf(
        (*config).global,
        b"unrecognized ftp file method '%s', using default\n\0" as *const u8
            as *const libc::c_char,
        str,
    );
    return CURLFTPMETHOD_MULTICWD as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ftpcccmethod(
    mut config: *mut OperationConfig,
    mut str: *const libc::c_char,
) -> libc::c_int {
    if curl_strequal(b"passive\0" as *const u8 as *const libc::c_char, str) != 0 {
        return CURLFTPSSL_CCC_PASSIVE as libc::c_int;
    }
    if curl_strequal(b"active\0" as *const u8 as *const libc::c_char, str) != 0 {
        return CURLFTPSSL_CCC_ACTIVE as libc::c_int;
    }
    warnf(
        (*config).global,
        b"unrecognized ftp CCC method '%s', using default\n\0" as *const u8
            as *const libc::c_char,
        str,
    );
    return CURLFTPSSL_CCC_PASSIVE as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn delegation(
    mut config: *mut OperationConfig,
    mut str: *const libc::c_char,
) -> libc::c_long {
    if curl_strequal(b"none\0" as *const u8 as *const libc::c_char, str) != 0 {
        return 0 as libc::c_int as libc::c_long;
    }
    if curl_strequal(b"policy\0" as *const u8 as *const libc::c_char, str) != 0 {
        return ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_long;
    }
    if curl_strequal(b"always\0" as *const u8 as *const libc::c_char, str) != 0 {
        return ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_long;
    }
    warnf(
        (*config).global,
        b"unrecognized delegation method '%s', using none\n\0" as *const u8
            as *const libc::c_char,
        str,
    );
    return 0 as libc::c_int as libc::c_long;
}
unsafe extern "C" fn my_useragent() -> *mut libc::c_char {
    return strdup(b"curl/7.79.1\0" as *const u8 as *const libc::c_char);
}
#[no_mangle]
pub unsafe extern "C" fn get_args(
    mut config: *mut OperationConfig,
    i: size_t,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut last: bool = if !((*config).next).is_null() {
        0 as libc::c_int
    } else {
        1 as libc::c_int
    } != 0;
    if !((*config).userpwd).is_null() && ((*config).oauth_bearer).is_null() {
        result = checkpasswd(
            b"host\0" as *const u8 as *const libc::c_char,
            i,
            last,
            &mut (*config).userpwd,
        );
        if result as u64 != 0 {
            return result;
        }
    }
    if !((*config).proxyuserpwd).is_null() {
        result = checkpasswd(
            b"proxy\0" as *const u8 as *const libc::c_char,
            i,
            last,
            &mut (*config).proxyuserpwd,
        );
        if result as u64 != 0 {
            return result;
        }
    }
    if ((*config).useragent).is_null() {
        let ref mut fresh5 = (*config).useragent;
        *fresh5 = my_useragent();
        if ((*config).useragent).is_null() {
            errorf(
                (*config).global,
                b"out of memory\n\0" as *const u8 as *const libc::c_char,
            );
            result = CURLE_OUT_OF_MEMORY;
        }
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn str2tls_max(
    mut val: *mut libc::c_long,
    mut str: *const libc::c_char,
) -> ParameterError {
    static mut tls_max_array: [s_tls_max; 5] = [
        {
            let mut init = s_tls_max {
                tls_max_str: b"default\0" as *const u8 as *const libc::c_char,
                tls_max: CURL_SSLVERSION_MAX_DEFAULT as libc::c_int as libc::c_long,
            };
            init
        },
        {
            let mut init = s_tls_max {
                tls_max_str: b"1.0\0" as *const u8 as *const libc::c_char,
                tls_max: CURL_SSLVERSION_MAX_TLSv1_0 as libc::c_int as libc::c_long,
            };
            init
        },
        {
            let mut init = s_tls_max {
                tls_max_str: b"1.1\0" as *const u8 as *const libc::c_char,
                tls_max: CURL_SSLVERSION_MAX_TLSv1_1 as libc::c_int as libc::c_long,
            };
            init
        },
        {
            let mut init = s_tls_max {
                tls_max_str: b"1.2\0" as *const u8 as *const libc::c_char,
                tls_max: CURL_SSLVERSION_MAX_TLSv1_2 as libc::c_int as libc::c_long,
            };
            init
        },
        {
            let mut init = s_tls_max {
                tls_max_str: b"1.3\0" as *const u8 as *const libc::c_char,
                tls_max: CURL_SSLVERSION_MAX_TLSv1_3 as libc::c_int as libc::c_long,
            };
            init
        },
    ];
    let mut i: size_t = 0 as libc::c_int as size_t;
    if str.is_null() {
        return PARAM_REQUIRES_PARAMETER;
    }
    i = 0 as libc::c_int as size_t;
    while i
        < (::std::mem::size_of::<[s_tls_max; 5]>() as libc::c_ulong)
            .wrapping_div(::std::mem::size_of::<s_tls_max>() as libc::c_ulong)
    {
        if strcmp(str, tls_max_array[i as usize].tls_max_str) == 0 {
            *val = tls_max_array[i as usize].tls_max;
            return PARAM_OK;
        }
        i = i.wrapping_add(1);
    }
    return PARAM_BAD_USE;
}
