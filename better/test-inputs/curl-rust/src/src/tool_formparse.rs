use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type Curl_easy;
    pub type curl_mime;
    pub type curl_mimepart;
    static mut stdin: *mut FILE;
    fn Curl_isspace(c: libc::c_int) -> libc::c_int;
    fn curl_strnequal(
        s1: *const libc::c_char,
        s2: *const libc::c_char,
        n: size_t,
    ) -> libc::c_int;
    fn curl_mime_init(easy: *mut CURL) -> *mut curl_mime;
    fn curl_mime_free(mime: *mut curl_mime);
    fn curl_mime_addpart(mime: *mut curl_mime) -> *mut curl_mimepart;
    fn curl_mime_name(part: *mut curl_mimepart, name: *const libc::c_char) -> CURLcode;
    fn curl_mime_filename(
        part: *mut curl_mimepart,
        filename: *const libc::c_char,
    ) -> CURLcode;
    fn curl_mime_type(
        part: *mut curl_mimepart,
        mimetype: *const libc::c_char,
    ) -> CURLcode;
    fn curl_mime_encoder(
        part: *mut curl_mimepart,
        encoding: *const libc::c_char,
    ) -> CURLcode;
    fn curl_mime_data(
        part: *mut curl_mimepart,
        data: *const libc::c_char,
        datasize: size_t,
    ) -> CURLcode;
    fn curl_mime_filedata(
        part: *mut curl_mimepart,
        filename: *const libc::c_char,
    ) -> CURLcode;
    fn curl_mime_data_cb(
        part: *mut curl_mimepart,
        datasize: curl_off_t,
        readfunc: curl_read_callback,
        seekfunc: curl_seek_callback,
        freefunc: curl_free_callback,
        arg: *mut libc::c_void,
    ) -> CURLcode;
    fn curl_mime_subparts(
        part: *mut curl_mimepart,
        subparts: *mut curl_mime,
    ) -> CURLcode;
    fn curl_mime_headers(
        part: *mut curl_mimepart,
        headers: *mut curl_slist,
        take_ownership: libc::c_int,
    ) -> CURLcode;
    fn curl_slist_append(_: *mut curl_slist, _: *const libc::c_char) -> *mut curl_slist;
    fn curl_slist_free_all(_: *mut curl_slist);
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn __errno_location() -> *mut libc::c_int;
    fn __fxstat(
        __ver: libc::c_int,
        __fildes: libc::c_int,
        __stat_buf: *mut stat,
    ) -> libc::c_int;
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn getc(__stream: *mut FILE) -> libc::c_int;
    fn fseek(
        __stream: *mut FILE,
        __off: libc::c_long,
        __whence: libc::c_int,
    ) -> libc::c_int;
    fn ftell(__stream: *mut FILE) -> libc::c_long;
    fn fread(
        _: *mut libc::c_void,
        _: libc::c_ulong,
        _: libc::c_ulong,
        _: *mut FILE,
    ) -> libc::c_ulong;
    fn ferror(__stream: *mut FILE) -> libc::c_int;
    fn fileno(__stream: *mut FILE) -> libc::c_int;
    fn curlx_uztoso(uznum: size_t) -> curl_off_t;
    fn curlx_sotouz(sonum: curl_off_t) -> size_t;
    fn curl_mfprintf(fd: *mut FILE, format: *const libc::c_char, _: ...) -> libc::c_int;
    fn warnf(config: *mut GlobalConfig, fmt: *const libc::c_char, _: ...);
    fn file2memory(
        bufp: *mut *mut libc::c_char,
        size: *mut size_t,
        file: *mut FILE,
    ) -> ParameterError;
}
pub type __dev_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __ino_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
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
pub type curl_seek_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_void, curl_off_t, libc::c_int) -> libc::c_int,
>;
pub type curl_read_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_char, size_t, size_t, *mut libc::c_void) -> size_t,
>;
pub type curl_free_callback = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
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
pub struct stat {
    pub st_dev: __dev_t,
    pub st_ino: __ino_t,
    pub st_nlink: __nlink_t,
    pub st_mode: __mode_t,
    pub st_uid: __uid_t,
    pub st_gid: __gid_t,
    pub __pad0: libc::c_int,
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
pub const PARAM_OK: ParameterError = 0;
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
#[inline]
unsafe extern "C" fn fstat(
    mut __fd: libc::c_int,
    mut __statbuf: *mut stat,
) -> libc::c_int {
    return __fxstat(1 as libc::c_int, __fd, __statbuf);
}
unsafe extern "C" fn tool_mime_new(
    mut parent: *mut tool_mime,
    mut kind: toolmimekind,
) -> *mut tool_mime {
    let mut m: *mut tool_mime = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::std::mem::size_of::<tool_mime>() as libc::c_ulong,
    ) as *mut tool_mime;
    if !m.is_null() {
        (*m).kind = kind;
        let ref mut fresh0 = (*m).parent;
        *fresh0 = parent;
        if !parent.is_null() {
            let ref mut fresh1 = (*m).prev;
            *fresh1 = (*parent).subparts;
            let ref mut fresh2 = (*parent).subparts;
            *fresh2 = m;
        }
    }
    return m;
}
unsafe extern "C" fn tool_mime_new_parts(mut parent: *mut tool_mime) -> *mut tool_mime {
    return tool_mime_new(parent, TOOLMIME_PARTS);
}
unsafe extern "C" fn tool_mime_new_data(
    mut parent: *mut tool_mime,
    mut data: *const libc::c_char,
) -> *mut tool_mime {
    let mut m: *mut tool_mime = 0 as *mut tool_mime;
    data = strdup(data);
    if !data.is_null() {
        m = tool_mime_new(parent, TOOLMIME_DATA);
        if m.is_null() {
            free(data as *mut libc::c_void);
        } else {
            let ref mut fresh3 = (*m).data;
            *fresh3 = data;
        }
    }
    return m;
}
unsafe extern "C" fn tool_mime_new_filedata(
    mut parent: *mut tool_mime,
    mut filename: *const libc::c_char,
    mut isremotefile: bool,
    mut errcode: *mut CURLcode,
) -> *mut tool_mime {
    let mut result: CURLcode = CURLE_OK;
    let mut m: *mut tool_mime = 0 as *mut tool_mime;
    *errcode = CURLE_OUT_OF_MEMORY;
    if strcmp(filename, b"-\0" as *const u8 as *const libc::c_char) != 0 {
        filename = strdup(filename);
        if !filename.is_null() {
            m = tool_mime_new(parent, TOOLMIME_FILE);
            if m.is_null() {
                free(filename as *mut libc::c_void);
            } else {
                let ref mut fresh4 = (*m).data;
                *fresh4 = filename;
                if !isremotefile {
                    (*m).kind = TOOLMIME_FILEDATA;
                }
                *errcode = CURLE_OK;
            }
        }
    } else {
        let mut fd: libc::c_int = fileno(stdin);
        let mut data: *mut libc::c_char = 0 as *mut libc::c_char;
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
            st_atim: timespec { tv_sec: 0, tv_nsec: 0 },
            st_mtim: timespec { tv_sec: 0, tv_nsec: 0 },
            st_ctim: timespec { tv_sec: 0, tv_nsec: 0 },
            __glibc_reserved: [0; 3],
        };
        origin = ftell(stdin);
        if fd >= 0 as libc::c_int && origin >= 0 as libc::c_int as libc::c_long
            && fstat(fd, &mut sbuf) == 0
            && sbuf.st_mode & 0o170000 as libc::c_int as libc::c_uint
                == 0o100000 as libc::c_int as libc::c_uint
        {
            size = sbuf.st_size - origin;
            if size < 0 as libc::c_int as libc::c_long {
                size = 0 as libc::c_int as curl_off_t;
            }
        } else {
            let mut stdinsize: size_t = 0 as libc::c_int as size_t;
            if file2memory(&mut data, &mut stdinsize, stdin) as libc::c_uint
                != PARAM_OK as libc::c_int as libc::c_uint
            {
                return m;
            }
            if ferror(stdin) != 0 {
                result = CURLE_READ_ERROR;
                free(data as *mut libc::c_void);
                data = 0 as *mut libc::c_char;
                data = 0 as *mut libc::c_char;
            } else if stdinsize == 0 {
                data = strdup(b"\0" as *const u8 as *const libc::c_char);
                if data.is_null() {
                    return m;
                }
            }
            size = curlx_uztoso(stdinsize);
            origin = 0 as libc::c_int as curl_off_t;
        }
        m = tool_mime_new(parent, TOOLMIME_STDIN);
        if m.is_null() {
            free(data as *mut libc::c_void);
            data = 0 as *mut libc::c_char;
        } else {
            let ref mut fresh5 = (*m).data;
            *fresh5 = data;
            (*m).origin = origin;
            (*m).size = size;
            (*m).curpos = 0 as libc::c_int as curl_off_t;
            if !isremotefile {
                (*m).kind = TOOLMIME_STDINDATA;
            }
            *errcode = result;
        }
    }
    return m;
}
#[no_mangle]
pub unsafe extern "C" fn tool_mime_free(mut mime: *mut tool_mime) {
    if !mime.is_null() {
        if !((*mime).subparts).is_null() {
            tool_mime_free((*mime).subparts);
        }
        if !((*mime).prev).is_null() {
            tool_mime_free((*mime).prev);
        }
        free(*(&mut (*mime).name as *mut *const libc::c_char as *mut *mut libc::c_void));
        let ref mut fresh6 = *(&mut (*mime).name as *mut *const libc::c_char
            as *mut *mut libc::c_void);
        *fresh6 = 0 as *mut libc::c_void;
        free(
            *(&mut (*mime).filename as *mut *const libc::c_char
                as *mut *mut libc::c_void),
        );
        let ref mut fresh7 = *(&mut (*mime).filename as *mut *const libc::c_char
            as *mut *mut libc::c_void);
        *fresh7 = 0 as *mut libc::c_void;
        free(
            *(&mut (*mime).type_0 as *mut *const libc::c_char as *mut *mut libc::c_void),
        );
        let ref mut fresh8 = *(&mut (*mime).type_0 as *mut *const libc::c_char
            as *mut *mut libc::c_void);
        *fresh8 = 0 as *mut libc::c_void;
        free(
            *(&mut (*mime).encoder as *mut *const libc::c_char as *mut *mut libc::c_void),
        );
        let ref mut fresh9 = *(&mut (*mime).encoder as *mut *const libc::c_char
            as *mut *mut libc::c_void);
        *fresh9 = 0 as *mut libc::c_void;
        free(*(&mut (*mime).data as *mut *const libc::c_char as *mut *mut libc::c_void));
        let ref mut fresh10 = *(&mut (*mime).data as *mut *const libc::c_char
            as *mut *mut libc::c_void);
        *fresh10 = 0 as *mut libc::c_void;
        curl_slist_free_all((*mime).headers);
        free(mime as *mut libc::c_void);
    }
}
#[no_mangle]
pub unsafe extern "C" fn tool_mime_stdin_read(
    mut buffer: *mut libc::c_char,
    mut size: size_t,
    mut nitems: size_t,
    mut arg: *mut libc::c_void,
) -> size_t {
    let mut sip: *mut tool_mime = arg as *mut tool_mime;
    let mut bytesleft: curl_off_t = 0;
    if (*sip).size >= 0 as libc::c_int as libc::c_long {
        if (*sip).curpos >= (*sip).size {
            return 0 as libc::c_int as size_t;
        }
        bytesleft = (*sip).size - (*sip).curpos;
        if curlx_uztoso(nitems) > bytesleft {
            nitems = curlx_sotouz(bytesleft);
        }
    }
    if nitems != 0 {
        if !((*sip).data).is_null() {
            memcpy(
                buffer as *mut libc::c_void,
                ((*sip).data).offset(curlx_sotouz((*sip).curpos) as isize)
                    as *const libc::c_void,
                nitems,
            );
        } else {
            nitems = fread(
                buffer as *mut libc::c_void,
                1 as libc::c_int as libc::c_ulong,
                nitems,
                stdin,
            );
            if ferror(stdin) != 0 {
                if !((*sip).config).is_null() {
                    warnf(
                        (*sip).config,
                        b"stdin: %s\n\0" as *const u8 as *const libc::c_char,
                        strerror(*__errno_location()),
                    );
                    let ref mut fresh11 = (*sip).config;
                    *fresh11 = 0 as *mut GlobalConfig;
                }
                return 0x10000000 as libc::c_int as size_t;
            }
        }
        let ref mut fresh12 = (*sip).curpos;
        *fresh12 += curlx_uztoso(nitems);
    }
    return nitems;
}
#[no_mangle]
pub unsafe extern "C" fn tool_mime_stdin_seek(
    mut instream: *mut libc::c_void,
    mut offset: curl_off_t,
    mut whence: libc::c_int,
) -> libc::c_int {
    let mut sip: *mut tool_mime = instream as *mut tool_mime;
    match whence {
        1 => {
            offset += (*sip).curpos;
        }
        2 => {
            offset += (*sip).size;
        }
        _ => {}
    }
    if offset < 0 as libc::c_int as libc::c_long {
        return 2 as libc::c_int;
    }
    if ((*sip).data).is_null() {
        if fseek(stdin, offset + (*sip).origin, 0 as libc::c_int) != 0 {
            return 2 as libc::c_int;
        }
    }
    (*sip).curpos = offset;
    return 0 as libc::c_int;
}
unsafe extern "C" fn tool2curlparts(
    mut curl: *mut CURL,
    mut m: *mut tool_mime,
    mut mime: *mut curl_mime,
) -> CURLcode {
    let mut ret: CURLcode = CURLE_OK;
    let mut part: *mut curl_mimepart = 0 as *mut curl_mimepart;
    let mut submime: *mut curl_mime = 0 as *mut curl_mime;
    let mut filename: *const libc::c_char = 0 as *const libc::c_char;
    if !m.is_null() {
        ret = tool2curlparts(curl, (*m).prev, mime);
        if ret as u64 == 0 {
            part = curl_mime_addpart(mime);
            if part.is_null() {
                ret = CURLE_OUT_OF_MEMORY;
            }
        }
        if ret as u64 == 0 {
            filename = (*m).filename;
            let mut current_block_19: u64;
            match (*m).kind as libc::c_uint {
                1 => {
                    ret = tool2curlmime(curl, m, &mut submime);
                    if ret as u64 == 0 {
                        ret = curl_mime_subparts(part, submime);
                        if ret as u64 != 0 {
                            curl_mime_free(submime);
                        }
                    }
                    current_block_19 = 14818589718467733107;
                }
                2 => {
                    ret = curl_mime_data(part, (*m).data, -(1 as libc::c_int) as size_t);
                    current_block_19 = 14818589718467733107;
                }
                3 | 4 => {
                    ret = curl_mime_filedata(part, (*m).data);
                    if ret as u64 == 0
                        && (*m).kind as libc::c_uint
                            == TOOLMIME_FILEDATA as libc::c_int as libc::c_uint
                        && filename.is_null()
                    {
                        ret = curl_mime_filename(part, 0 as *const libc::c_char);
                    }
                    current_block_19 = 14818589718467733107;
                }
                5 => {
                    if filename.is_null() {
                        filename = b"-\0" as *const u8 as *const libc::c_char;
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
                    ret = curl_mime_data_cb(
                        part,
                        (*m).size,
                        ::std::mem::transmute::<
                            Option::<
                                unsafe extern "C" fn(
                                    *mut libc::c_char,
                                    size_t,
                                    size_t,
                                    *mut libc::c_void,
                                ) -> size_t,
                            >,
                            curl_read_callback,
                        >(
                            Some(
                                tool_mime_stdin_read
                                    as unsafe extern "C" fn(
                                        *mut libc::c_char,
                                        size_t,
                                        size_t,
                                        *mut libc::c_void,
                                    ) -> size_t,
                            ),
                        ),
                        ::std::mem::transmute::<
                            Option::<
                                unsafe extern "C" fn(
                                    *mut libc::c_void,
                                    curl_off_t,
                                    libc::c_int,
                                ) -> libc::c_int,
                            >,
                            curl_seek_callback,
                        >(
                            Some(
                                tool_mime_stdin_seek
                                    as unsafe extern "C" fn(
                                        *mut libc::c_void,
                                        curl_off_t,
                                        libc::c_int,
                                    ) -> libc::c_int,
                            ),
                        ),
                        None,
                        m as *mut libc::c_void,
                    );
                }
                _ => {}
            }
        }
        if ret as u64 == 0 && !filename.is_null() {
            ret = curl_mime_filename(part, filename);
        }
        if ret as u64 == 0 {
            ret = curl_mime_type(part, (*m).type_0);
        }
        if ret as u64 == 0 {
            ret = curl_mime_headers(part, (*m).headers, 0 as libc::c_int);
        }
        if ret as u64 == 0 {
            ret = curl_mime_encoder(part, (*m).encoder);
        }
        if ret as u64 == 0 {
            ret = curl_mime_name(part, (*m).name);
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn tool2curlmime(
    mut curl: *mut CURL,
    mut m: *mut tool_mime,
    mut mime: *mut *mut curl_mime,
) -> CURLcode {
    let mut ret: CURLcode = CURLE_OK;
    *mime = curl_mime_init(curl);
    if (*mime).is_null() {
        ret = CURLE_OUT_OF_MEMORY;
    } else {
        ret = tool2curlparts(curl, (*m).subparts, *mime);
    }
    if ret as u64 != 0 {
        curl_mime_free(*mime);
        *mime = 0 as *mut curl_mime;
    }
    return ret;
}
unsafe extern "C" fn get_param_word(
    mut config: *mut OperationConfig,
    mut str: *mut *mut libc::c_char,
    mut end_pos: *mut *mut libc::c_char,
    mut endchar: libc::c_char,
) -> *mut libc::c_char {
    let mut ptr: *mut libc::c_char = *str;
    let mut word_begin: *mut libc::c_char = ptr;
    let mut ptr2: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut escape: *mut libc::c_char = 0 as *mut libc::c_char;
    if *ptr as libc::c_int == '"' as i32 {
        ptr = ptr.offset(1);
        while *ptr != 0 {
            if *ptr as libc::c_int == '\\' as i32 {
                if *ptr.offset(1 as libc::c_int as isize) as libc::c_int == '\\' as i32
                    || *ptr.offset(1 as libc::c_int as isize) as libc::c_int
                        == '"' as i32
                {
                    if escape.is_null() {
                        escape = ptr;
                    }
                    ptr = ptr.offset(2 as libc::c_int as isize);
                    continue;
                }
            }
            if *ptr as libc::c_int == '"' as i32 {
                let mut trailing_data: bool = 0 as libc::c_int != 0;
                *end_pos = ptr;
                if !escape.is_null() {
                    ptr2 = escape;
                    ptr = ptr2;
                    loop {
                        if *ptr as libc::c_int == '\\' as i32
                            && (*ptr.offset(1 as libc::c_int as isize) as libc::c_int
                                == '\\' as i32
                                || *ptr.offset(1 as libc::c_int as isize) as libc::c_int
                                    == '"' as i32)
                        {
                            ptr = ptr.offset(1);
                        }
                        let fresh13 = ptr;
                        ptr = ptr.offset(1);
                        let fresh14 = ptr2;
                        ptr2 = ptr2.offset(1);
                        *fresh14 = *fresh13;
                        if !(ptr < *end_pos) {
                            break;
                        }
                    }
                    *end_pos = ptr2;
                }
                ptr = ptr.offset(1);
                while *ptr as libc::c_int != 0 && *ptr as libc::c_int != ';' as i32
                    && *ptr as libc::c_int != endchar as libc::c_int
                {
                    if Curl_isspace(*ptr as libc::c_uchar as libc::c_int) == 0 {
                        trailing_data = 1 as libc::c_int != 0;
                    }
                    ptr = ptr.offset(1);
                }
                if trailing_data {
                    warnf(
                        (*config).global,
                        b"Trailing data after quoted form parameter\n\0" as *const u8
                            as *const libc::c_char,
                    );
                }
                *str = ptr;
                return word_begin.offset(1 as libc::c_int as isize);
            }
            ptr = ptr.offset(1);
        }
        ptr = word_begin;
    }
    while *ptr as libc::c_int != 0 && *ptr as libc::c_int != ';' as i32
        && *ptr as libc::c_int != endchar as libc::c_int
    {
        ptr = ptr.offset(1);
    }
    *end_pos = ptr;
    *str = *end_pos;
    return word_begin;
}
unsafe extern "C" fn slist_append(
    mut plist: *mut *mut curl_slist,
    mut data: *const libc::c_char,
) -> libc::c_int {
    let mut s: *mut curl_slist = curl_slist_append(*plist, data);
    if s.is_null() {
        return -(1 as libc::c_int);
    }
    *plist = s;
    return 0 as libc::c_int;
}
unsafe extern "C" fn read_field_headers(
    mut config: *mut OperationConfig,
    mut filename: *const libc::c_char,
    mut fp: *mut FILE,
    mut pheaders: *mut *mut curl_slist,
) -> libc::c_int {
    let mut hdrlen: size_t = 0 as libc::c_int as size_t;
    let mut pos: size_t = 0 as libc::c_int as size_t;
    let mut incomment: bool = 0 as libc::c_int != 0;
    let mut lineno: libc::c_int = 1 as libc::c_int;
    let mut hdrbuf: [libc::c_char; 999] = [0; 999];
    loop {
        let mut c: libc::c_int = getc(fp);
        if c == -(1 as libc::c_int)
            || pos == 0 && Curl_isspace(c as libc::c_uchar as libc::c_int) == 0
        {
            while hdrlen != 0
                && Curl_isspace(
                    hdrbuf[hdrlen.wrapping_sub(1 as libc::c_int as libc::c_ulong)
                        as usize] as libc::c_uchar as libc::c_int,
                ) != 0
            {
                hdrlen = hdrlen.wrapping_sub(1);
            }
            if hdrlen != 0 {
                hdrbuf[hdrlen as usize] = '\u{0}' as i32 as libc::c_char;
                if slist_append(pheaders, hdrbuf.as_mut_ptr()) != 0 {
                    curl_mfprintf(
                        (*(*config).global).errors,
                        b"Out of memory for field headers!\n\0" as *const u8
                            as *const libc::c_char,
                    );
                    return -(1 as libc::c_int);
                }
                hdrlen = 0 as libc::c_int as size_t;
            }
        }
        match c {
            -1 => {
                if ferror(fp) != 0 {
                    curl_mfprintf(
                        (*(*config).global).errors,
                        b"Header file %s read error: %s\n\0" as *const u8
                            as *const libc::c_char,
                        filename,
                        strerror(*__errno_location()),
                    );
                    return -(1 as libc::c_int);
                }
                return 0 as libc::c_int;
            }
            13 => {
                continue;
            }
            10 => {
                pos = 0 as libc::c_int as size_t;
                incomment = 0 as libc::c_int != 0;
                lineno += 1;
                continue;
            }
            35 => {
                if pos == 0 {
                    incomment = 1 as libc::c_int != 0;
                }
            }
            _ => {}
        }
        pos = pos.wrapping_add(1);
        if !incomment {
            if hdrlen
                == (::std::mem::size_of::<[libc::c_char; 999]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            {
                warnf(
                    (*config).global,
                    b"File %s line %d: header too long (truncated)\n\0" as *const u8
                        as *const libc::c_char,
                    filename,
                    lineno,
                );
                c = ' ' as i32;
            }
            if hdrlen
                <= (::std::mem::size_of::<[libc::c_char; 999]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            {
                let fresh15 = hdrlen;
                hdrlen = hdrlen.wrapping_add(1);
                hdrbuf[fresh15 as usize] = c as libc::c_char;
            }
        }
    };
}
unsafe extern "C" fn get_param_part(
    mut config: *mut OperationConfig,
    mut endchar: libc::c_char,
    mut str: *mut *mut libc::c_char,
    mut pdata: *mut *mut libc::c_char,
    mut ptype: *mut *mut libc::c_char,
    mut pfilename: *mut *mut libc::c_char,
    mut pencoder: *mut *mut libc::c_char,
    mut pheaders: *mut *mut curl_slist,
) -> libc::c_int {
    let mut p: *mut libc::c_char = *str;
    let mut type_0: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoder: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut endpos: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sep: libc::c_char = 0;
    let mut type_major: [libc::c_char; 128] = *::std::mem::transmute::<
        &[u8; 128],
        &mut [libc::c_char; 128],
    >(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut type_minor: [libc::c_char; 128] = *::std::mem::transmute::<
        &[u8; 128],
        &mut [libc::c_char; 128],
    >(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut endct: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut headers: *mut curl_slist = 0 as *mut curl_slist;
    if !ptype.is_null() {
        *ptype = 0 as *mut libc::c_char;
    }
    if !pfilename.is_null() {
        *pfilename = 0 as *mut libc::c_char;
    }
    if !pheaders.is_null() {
        *pheaders = 0 as *mut curl_slist;
    }
    if !pencoder.is_null() {
        *pencoder = 0 as *mut libc::c_char;
    }
    while Curl_isspace(*p as libc::c_uchar as libc::c_int) != 0 {
        p = p.offset(1);
    }
    tp = p;
    *pdata = get_param_word(config, &mut p, &mut endpos, endchar);
    if *pdata == tp {
        while endpos > *pdata
            && Curl_isspace(
                *endpos.offset(-(1 as libc::c_int) as isize) as libc::c_uchar
                    as libc::c_int,
            ) != 0
        {
            endpos = endpos.offset(-1);
        }
    }
    sep = *p;
    *endpos = '\u{0}' as i32 as libc::c_char;
    while sep as libc::c_int == ';' as i32 {
        loop {
            p = p.offset(1);
            if !(Curl_isspace(*p as libc::c_uchar as libc::c_int) != 0) {
                break;
            }
        }
        if endct.is_null()
            && curl_strnequal(
                b"type=\0" as *const u8 as *const libc::c_char,
                p,
                strlen(b"type=\0" as *const u8 as *const libc::c_char),
            ) != 0
        {
            p = p.offset(5 as libc::c_int as isize);
            while Curl_isspace(*p as libc::c_uchar as libc::c_int) != 0 {
                p = p.offset(1);
            }
            type_0 = p;
            if 2 as libc::c_int
                != sscanf(
                    type_0,
                    b"%127[^/ ]/%127[^;, \n]\0" as *const u8 as *const libc::c_char,
                    type_major.as_mut_ptr(),
                    type_minor.as_mut_ptr(),
                )
            {
                warnf(
                    (*config).global,
                    b"Illegally formatted content-type field!\n\0" as *const u8
                        as *const libc::c_char,
                );
                curl_slist_free_all(headers);
                return -(1 as libc::c_int);
            }
            p = type_0
                .offset(strlen(type_major.as_mut_ptr()) as isize)
                .offset(strlen(type_minor.as_mut_ptr()) as isize)
                .offset(1 as libc::c_int as isize);
            endct = p;
            while *p as libc::c_int != 0 && *p as libc::c_int != ';' as i32
                && *p as libc::c_int != endchar as libc::c_int
            {
                if Curl_isspace(*p as libc::c_uchar as libc::c_int) == 0 {
                    endct = p.offset(1 as libc::c_int as isize);
                }
                p = p.offset(1);
            }
            sep = *p;
        } else if curl_strnequal(
                b"filename=\0" as *const u8 as *const libc::c_char,
                p,
                strlen(b"filename=\0" as *const u8 as *const libc::c_char),
            ) != 0
            {
            if !endct.is_null() {
                *endct = '\u{0}' as i32 as libc::c_char;
                endct = 0 as *mut libc::c_char;
            }
            p = p.offset(9 as libc::c_int as isize);
            while Curl_isspace(*p as libc::c_uchar as libc::c_int) != 0 {
                p = p.offset(1);
            }
            tp = p;
            filename = get_param_word(config, &mut p, &mut endpos, endchar);
            if filename == tp {
                while endpos > filename
                    && Curl_isspace(
                        *endpos.offset(-(1 as libc::c_int) as isize) as libc::c_uchar
                            as libc::c_int,
                    ) != 0
                {
                    endpos = endpos.offset(-1);
                }
            }
            sep = *p;
            *endpos = '\u{0}' as i32 as libc::c_char;
        } else if curl_strnequal(
                b"headers=\0" as *const u8 as *const libc::c_char,
                p,
                strlen(b"headers=\0" as *const u8 as *const libc::c_char),
            ) != 0
            {
            if !endct.is_null() {
                *endct = '\u{0}' as i32 as libc::c_char;
                endct = 0 as *mut libc::c_char;
            }
            p = p.offset(8 as libc::c_int as isize);
            if *p as libc::c_int == '@' as i32 || *p as libc::c_int == '<' as i32 {
                let mut hdrfile: *mut libc::c_char = 0 as *mut libc::c_char;
                let mut fp: *mut FILE = 0 as *mut FILE;
                loop {
                    p = p.offset(1);
                    if !(Curl_isspace(*p as libc::c_uchar as libc::c_int) != 0) {
                        break;
                    }
                }
                tp = p;
                hdrfile = get_param_word(config, &mut p, &mut endpos, endchar);
                if hdrfile == tp {
                    while endpos > hdrfile
                        && Curl_isspace(
                            *endpos.offset(-(1 as libc::c_int) as isize) as libc::c_uchar
                                as libc::c_int,
                        ) != 0
                    {
                        endpos = endpos.offset(-1);
                    }
                }
                sep = *p;
                *endpos = '\u{0}' as i32 as libc::c_char;
                fp = fopen(hdrfile, b"r\0" as *const u8 as *const libc::c_char);
                if fp.is_null() {
                    warnf(
                        (*config).global,
                        b"Cannot read from %s: %s\n\0" as *const u8
                            as *const libc::c_char,
                        hdrfile,
                        strerror(*__errno_location()),
                    );
                } else {
                    let mut i: libc::c_int = read_field_headers(
                        config,
                        hdrfile,
                        fp,
                        &mut headers,
                    );
                    fclose(fp);
                    if i != 0 {
                        curl_slist_free_all(headers);
                        return -(1 as libc::c_int);
                    }
                }
            } else {
                let mut hdr: *mut libc::c_char = 0 as *mut libc::c_char;
                while Curl_isspace(*p as libc::c_uchar as libc::c_int) != 0 {
                    p = p.offset(1);
                }
                tp = p;
                hdr = get_param_word(config, &mut p, &mut endpos, endchar);
                if hdr == tp {
                    while endpos > hdr
                        && Curl_isspace(
                            *endpos.offset(-(1 as libc::c_int) as isize) as libc::c_uchar
                                as libc::c_int,
                        ) != 0
                    {
                        endpos = endpos.offset(-1);
                    }
                }
                sep = *p;
                *endpos = '\u{0}' as i32 as libc::c_char;
                if slist_append(&mut headers, hdr) != 0 {
                    curl_mfprintf(
                        (*(*config).global).errors,
                        b"Out of memory for field header!\n\0" as *const u8
                            as *const libc::c_char,
                    );
                    curl_slist_free_all(headers);
                    return -(1 as libc::c_int);
                }
            }
        } else if curl_strnequal(
                b"encoder=\0" as *const u8 as *const libc::c_char,
                p,
                strlen(b"encoder=\0" as *const u8 as *const libc::c_char),
            ) != 0
            {
            if !endct.is_null() {
                *endct = '\u{0}' as i32 as libc::c_char;
                endct = 0 as *mut libc::c_char;
            }
            p = p.offset(8 as libc::c_int as isize);
            while Curl_isspace(*p as libc::c_uchar as libc::c_int) != 0 {
                p = p.offset(1);
            }
            tp = p;
            encoder = get_param_word(config, &mut p, &mut endpos, endchar);
            if encoder == tp {
                while endpos > encoder
                    && Curl_isspace(
                        *endpos.offset(-(1 as libc::c_int) as isize) as libc::c_uchar
                            as libc::c_int,
                    ) != 0
                {
                    endpos = endpos.offset(-1);
                }
            }
            sep = *p;
            *endpos = '\u{0}' as i32 as libc::c_char;
        } else if !endct.is_null() {
            endct = p;
            while *p as libc::c_int != 0 && *p as libc::c_int != ';' as i32
                && *p as libc::c_int != endchar as libc::c_int
            {
                if Curl_isspace(*p as libc::c_uchar as libc::c_int) == 0 {
                    endct = p.offset(1 as libc::c_int as isize);
                }
                p = p.offset(1);
            }
            sep = *p;
        } else {
            let mut unknown: *mut libc::c_char = get_param_word(
                config,
                &mut p,
                &mut endpos,
                endchar,
            );
            sep = *p;
            *endpos = '\u{0}' as i32 as libc::c_char;
            if *unknown != 0 {
                warnf(
                    (*config).global,
                    b"skip unknown form field: %s\n\0" as *const u8
                        as *const libc::c_char,
                    unknown,
                );
            }
        }
    }
    if !endct.is_null() {
        *endct = '\u{0}' as i32 as libc::c_char;
    }
    if !ptype.is_null() {
        *ptype = type_0;
    } else if !type_0.is_null() {
        warnf(
            (*config).global,
            b"Field content type not allowed here: %s\n\0" as *const u8
                as *const libc::c_char,
            type_0,
        );
    }
    if !pfilename.is_null() {
        *pfilename = filename;
    } else if !filename.is_null() {
        warnf(
            (*config).global,
            b"Field file name not allowed here: %s\n\0" as *const u8
                as *const libc::c_char,
            filename,
        );
    }
    if !pencoder.is_null() {
        *pencoder = encoder;
    } else if !encoder.is_null() {
        warnf(
            (*config).global,
            b"Field encoder not allowed here: %s\n\0" as *const u8
                as *const libc::c_char,
            encoder,
        );
    }
    if !pheaders.is_null() {
        *pheaders = headers;
    } else if !headers.is_null() {
        warnf(
            (*config).global,
            b"Field headers not allowed here: %s\n\0" as *const u8
                as *const libc::c_char,
            (*headers).data,
        );
        curl_slist_free_all(headers);
    }
    *str = p;
    return sep as libc::c_int & 0xff as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn formparse(
    mut config: *mut OperationConfig,
    mut input: *const libc::c_char,
    mut mimeroot: *mut *mut tool_mime,
    mut mimecurrent: *mut *mut tool_mime,
    mut literal_value: bool,
) -> libc::c_int {
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut contents: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut contp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut data: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut type_0: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoder: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut headers: *mut curl_slist = 0 as *mut curl_slist;
    let mut part: *mut tool_mime = 0 as *mut tool_mime;
    let mut res: CURLcode = CURLE_OK;
    if (*mimecurrent).is_null() {
        *mimeroot = tool_mime_new_parts(0 as *mut tool_mime);
        if (*mimeroot).is_null() {
            warnf(
                (*config).global,
                b"out of memory!\n\0" as *const u8 as *const libc::c_char,
            );
            curl_slist_free_all(headers);
            free(contents as *mut libc::c_void);
            contents = 0 as *mut libc::c_char;
            return 1 as libc::c_int;
        }
        *mimecurrent = *mimeroot;
    }
    contents = strdup(input);
    if contents.is_null() {
        warnf(
            (*config).global,
            b"out of memory!\n\0" as *const u8 as *const libc::c_char,
        );
        curl_slist_free_all(headers);
        free(contents as *mut libc::c_void);
        contents = 0 as *mut libc::c_char;
        return 2 as libc::c_int;
    }
    contp = strchr(contents, '=' as i32);
    if !contp.is_null() {
        let mut sep: libc::c_int = '\u{0}' as i32;
        if contp > contents {
            name = contents;
        }
        let fresh16 = contp;
        contp = contp.offset(1);
        *fresh16 = '\u{0}' as i32 as libc::c_char;
        if *contp as libc::c_int == '(' as i32 && !literal_value {
            sep = get_param_part(
                config,
                '\u{0}' as i32 as libc::c_char,
                &mut contp,
                &mut data,
                &mut type_0,
                0 as *mut *mut libc::c_char,
                0 as *mut *mut libc::c_char,
                &mut headers,
            );
            if sep < 0 as libc::c_int {
                free(contents as *mut libc::c_void);
                contents = 0 as *mut libc::c_char;
                return 3 as libc::c_int;
            }
            part = tool_mime_new_parts(*mimecurrent);
            if part.is_null() {
                warnf(
                    (*config).global,
                    b"out of memory!\n\0" as *const u8 as *const libc::c_char,
                );
                curl_slist_free_all(headers);
                free(contents as *mut libc::c_void);
                contents = 0 as *mut libc::c_char;
                return 4 as libc::c_int;
            }
            *mimecurrent = part;
            let ref mut fresh17 = (*part).headers;
            *fresh17 = headers;
            headers = 0 as *mut curl_slist;
            if !type_0.is_null() {
                let ref mut fresh18 = (*part).type_0;
                *fresh18 = strdup(type_0);
                if ((*part).type_0).is_null() {
                    warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const libc::c_char,
                    );
                    curl_slist_free_all(headers);
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut libc::c_char;
                    return 5 as libc::c_int;
                }
            }
        } else if name.is_null()
                && strcmp(contp, b")\0" as *const u8 as *const libc::c_char) == 0
                && !literal_value
            {
            if *mimecurrent == *mimeroot {
                warnf(
                    (*config).global,
                    b"no multipart to terminate!\n\0" as *const u8 as *const libc::c_char,
                );
                free(contents as *mut libc::c_void);
                contents = 0 as *mut libc::c_char;
                return 6 as libc::c_int;
            }
            *mimecurrent = (**mimecurrent).parent;
        } else if '@' as i32 == *contp.offset(0 as libc::c_int as isize) as libc::c_int
                && !literal_value
            {
            let mut subparts: *mut tool_mime = 0 as *mut tool_mime;
            loop {
                contp = contp.offset(1);
                sep = get_param_part(
                    config,
                    ',' as i32 as libc::c_char,
                    &mut contp,
                    &mut data,
                    &mut type_0,
                    &mut filename,
                    &mut encoder,
                    &mut headers,
                );
                if sep < 0 as libc::c_int {
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut libc::c_char;
                    return 7 as libc::c_int;
                }
                if subparts.is_null() {
                    if sep != ',' as i32 {
                        subparts = *mimecurrent;
                    } else {
                        subparts = tool_mime_new_parts(*mimecurrent);
                        if subparts.is_null() {
                            warnf(
                                (*config).global,
                                b"out of memory!\n\0" as *const u8 as *const libc::c_char,
                            );
                            curl_slist_free_all(headers);
                            free(contents as *mut libc::c_void);
                            contents = 0 as *mut libc::c_char;
                            return 8 as libc::c_int;
                        }
                    }
                }
                part = tool_mime_new_filedata(
                    subparts,
                    data,
                    1 as libc::c_int != 0,
                    &mut res,
                );
                if part.is_null() {
                    warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const libc::c_char,
                    );
                    curl_slist_free_all(headers);
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut libc::c_char;
                    return 9 as libc::c_int;
                }
                let ref mut fresh19 = (*part).headers;
                *fresh19 = headers;
                headers = 0 as *mut curl_slist;
                let ref mut fresh20 = (*part).config;
                *fresh20 = (*config).global;
                if res as libc::c_uint == CURLE_READ_ERROR as libc::c_int as libc::c_uint
                {
                    if (*part).size > 0 as libc::c_int as libc::c_long {
                        warnf(
                            (*config).global,
                            b"error while reading standard input\n\0" as *const u8
                                as *const libc::c_char,
                        );
                        free(contents as *mut libc::c_void);
                        contents = 0 as *mut libc::c_char;
                        return 10 as libc::c_int;
                    }
                    free(
                        *(&mut (*part).data as *mut *const libc::c_char
                            as *mut *mut libc::c_void),
                    );
                    let ref mut fresh21 = *(&mut (*part).data as *mut *const libc::c_char
                        as *mut *mut libc::c_void);
                    *fresh21 = 0 as *mut libc::c_void;
                    let ref mut fresh22 = (*part).data;
                    *fresh22 = 0 as *const libc::c_char;
                    (*part).size = -(1 as libc::c_int) as curl_off_t;
                    res = CURLE_OK;
                }
                if !filename.is_null() {
                    let ref mut fresh23 = (*part).filename;
                    *fresh23 = strdup(filename);
                    if ((*part).filename).is_null() {
                        warnf(
                            (*config).global,
                            b"out of memory!\n\0" as *const u8 as *const libc::c_char,
                        );
                        curl_slist_free_all(headers);
                        free(contents as *mut libc::c_void);
                        contents = 0 as *mut libc::c_char;
                        return 11 as libc::c_int;
                    }
                }
                if !type_0.is_null() {
                    let ref mut fresh24 = (*part).type_0;
                    *fresh24 = strdup(type_0);
                    if ((*part).type_0).is_null() {
                        warnf(
                            (*config).global,
                            b"out of memory!\n\0" as *const u8 as *const libc::c_char,
                        );
                        curl_slist_free_all(headers);
                        free(contents as *mut libc::c_void);
                        contents = 0 as *mut libc::c_char;
                        return 12 as libc::c_int;
                    }
                }
                if !encoder.is_null() {
                    let ref mut fresh25 = (*part).encoder;
                    *fresh25 = strdup(encoder);
                    if ((*part).encoder).is_null() {
                        warnf(
                            (*config).global,
                            b"out of memory!\n\0" as *const u8 as *const libc::c_char,
                        );
                        curl_slist_free_all(headers);
                        free(contents as *mut libc::c_void);
                        contents = 0 as *mut libc::c_char;
                        return 13 as libc::c_int;
                    }
                }
                if !(sep != 0) {
                    break;
                }
            }
            part = (**mimecurrent).subparts;
        } else {
            if *contp as libc::c_int == '<' as i32 && !literal_value {
                contp = contp.offset(1);
                sep = get_param_part(
                    config,
                    '\u{0}' as i32 as libc::c_char,
                    &mut contp,
                    &mut data,
                    &mut type_0,
                    0 as *mut *mut libc::c_char,
                    &mut encoder,
                    &mut headers,
                );
                if sep < 0 as libc::c_int {
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut libc::c_char;
                    return 14 as libc::c_int;
                }
                part = tool_mime_new_filedata(
                    *mimecurrent,
                    data,
                    0 as libc::c_int != 0,
                    &mut res,
                );
                if part.is_null() {
                    warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const libc::c_char,
                    );
                    curl_slist_free_all(headers);
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut libc::c_char;
                    return 15 as libc::c_int;
                }
                let ref mut fresh26 = (*part).headers;
                *fresh26 = headers;
                headers = 0 as *mut curl_slist;
                let ref mut fresh27 = (*part).config;
                *fresh27 = (*config).global;
                if res as libc::c_uint == CURLE_READ_ERROR as libc::c_int as libc::c_uint
                {
                    if (*part).size > 0 as libc::c_int as libc::c_long {
                        warnf(
                            (*config).global,
                            b"error while reading standard input\n\0" as *const u8
                                as *const libc::c_char,
                        );
                        free(contents as *mut libc::c_void);
                        contents = 0 as *mut libc::c_char;
                        return 16 as libc::c_int;
                    }
                    free(
                        *(&mut (*part).data as *mut *const libc::c_char
                            as *mut *mut libc::c_void),
                    );
                    let ref mut fresh28 = *(&mut (*part).data as *mut *const libc::c_char
                        as *mut *mut libc::c_void);
                    *fresh28 = 0 as *mut libc::c_void;
                    let ref mut fresh29 = (*part).data;
                    *fresh29 = 0 as *const libc::c_char;
                    (*part).size = -(1 as libc::c_int) as curl_off_t;
                    res = CURLE_OK;
                }
            } else {
                if literal_value {
                    data = contp;
                } else {
                    sep = get_param_part(
                        config,
                        '\u{0}' as i32 as libc::c_char,
                        &mut contp,
                        &mut data,
                        &mut type_0,
                        &mut filename,
                        &mut encoder,
                        &mut headers,
                    );
                    if sep < 0 as libc::c_int {
                        free(contents as *mut libc::c_void);
                        contents = 0 as *mut libc::c_char;
                        return 17 as libc::c_int;
                    }
                }
                part = tool_mime_new_data(*mimecurrent, data);
                if part.is_null() {
                    warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const libc::c_char,
                    );
                    curl_slist_free_all(headers);
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut libc::c_char;
                    return 18 as libc::c_int;
                }
                let ref mut fresh30 = (*part).headers;
                *fresh30 = headers;
                headers = 0 as *mut curl_slist;
            }
            if !filename.is_null() {
                let ref mut fresh31 = (*part).filename;
                *fresh31 = strdup(filename);
                if ((*part).filename).is_null() {
                    warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const libc::c_char,
                    );
                    curl_slist_free_all(headers);
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut libc::c_char;
                    return 19 as libc::c_int;
                }
            }
            if !type_0.is_null() {
                let ref mut fresh32 = (*part).type_0;
                *fresh32 = strdup(type_0);
                if ((*part).type_0).is_null() {
                    warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const libc::c_char,
                    );
                    curl_slist_free_all(headers);
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut libc::c_char;
                    return 20 as libc::c_int;
                }
            }
            if !encoder.is_null() {
                let ref mut fresh33 = (*part).encoder;
                *fresh33 = strdup(encoder);
                if ((*part).encoder).is_null() {
                    warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const libc::c_char,
                    );
                    curl_slist_free_all(headers);
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut libc::c_char;
                    return 21 as libc::c_int;
                }
            }
            if sep != 0 {
                *contp = sep as libc::c_char;
                warnf(
                    (*config).global,
                    b"garbage at end of field specification: %s\n\0" as *const u8
                        as *const libc::c_char,
                    contp,
                );
            }
        }
        if !name.is_null() {
            let ref mut fresh34 = (*part).name;
            *fresh34 = strdup(name);
            if ((*part).name).is_null() {
                warnf(
                    (*config).global,
                    b"out of memory!\n\0" as *const u8 as *const libc::c_char,
                );
                curl_slist_free_all(headers);
                free(contents as *mut libc::c_void);
                contents = 0 as *mut libc::c_char;
                return 22 as libc::c_int;
            }
        }
    } else {
        warnf(
            (*config).global,
            b"Illegally formatted input field!\n\0" as *const u8 as *const libc::c_char,
        );
        free(contents as *mut libc::c_void);
        contents = 0 as *mut libc::c_char;
        return 23 as libc::c_int;
    }
    free(contents as *mut libc::c_void);
    contents = 0 as *mut libc::c_char;
    return 0 as libc::c_int;
}
