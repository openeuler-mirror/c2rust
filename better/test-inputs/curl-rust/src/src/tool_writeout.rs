use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type Curl_easy;
    pub type curl_mime;
    fn curl_easy_getinfo(curl: *mut CURL, info: CURLINFO, _: ...) -> CURLcode;
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn fputc(__c: libc::c_int, __stream: *mut FILE) -> libc::c_int;
    fn fputs(__s: *const libc::c_char, __stream: *mut FILE) -> libc::c_int;
    fn curl_strequal(s1: *const libc::c_char, s2: *const libc::c_char) -> libc::c_int;
    fn curl_easy_strerror(_: CURLcode) -> *const libc::c_char;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn curl_mfprintf(fd: *mut FILE, format: *const libc::c_char, _: ...) -> libc::c_int;
    fn ourWriteOutJSON(
        stream: *mut FILE,
        mappings: *const writeoutvar,
        per: *mut per_transfer,
        per_result: CURLcode,
    );
    fn jsonWriteString(stream: *mut FILE, in_0: *const libc::c_char);
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
pub type CURLINFO = libc::c_uint;
pub const CURLINFO_LASTONE: CURLINFO = 60;
pub const CURLINFO_REFERER: CURLINFO = 1048636;
pub const CURLINFO_PROXY_ERROR: CURLINFO = 2097211;
pub const CURLINFO_EFFECTIVE_METHOD: CURLINFO = 1048634;
pub const CURLINFO_RETRY_AFTER: CURLINFO = 6291513;
pub const CURLINFO_APPCONNECT_TIME_T: CURLINFO = 6291512;
pub const CURLINFO_REDIRECT_TIME_T: CURLINFO = 6291511;
pub const CURLINFO_STARTTRANSFER_TIME_T: CURLINFO = 6291510;
pub const CURLINFO_PRETRANSFER_TIME_T: CURLINFO = 6291509;
pub const CURLINFO_CONNECT_TIME_T: CURLINFO = 6291508;
pub const CURLINFO_NAMELOOKUP_TIME_T: CURLINFO = 6291507;
pub const CURLINFO_TOTAL_TIME_T: CURLINFO = 6291506;
pub const CURLINFO_SCHEME: CURLINFO = 1048625;
pub const CURLINFO_PROTOCOL: CURLINFO = 2097200;
pub const CURLINFO_PROXY_SSL_VERIFYRESULT: CURLINFO = 2097199;
pub const CURLINFO_HTTP_VERSION: CURLINFO = 2097198;
pub const CURLINFO_TLS_SSL_PTR: CURLINFO = 4194349;
pub const CURLINFO_ACTIVESOCKET: CURLINFO = 5242924;
pub const CURLINFO_TLS_SESSION: CURLINFO = 4194347;
pub const CURLINFO_LOCAL_PORT: CURLINFO = 2097194;
pub const CURLINFO_LOCAL_IP: CURLINFO = 1048617;
pub const CURLINFO_PRIMARY_PORT: CURLINFO = 2097192;
pub const CURLINFO_RTSP_CSEQ_RECV: CURLINFO = 2097191;
pub const CURLINFO_RTSP_SERVER_CSEQ: CURLINFO = 2097190;
pub const CURLINFO_RTSP_CLIENT_CSEQ: CURLINFO = 2097189;
pub const CURLINFO_RTSP_SESSION_ID: CURLINFO = 1048612;
pub const CURLINFO_CONDITION_UNMET: CURLINFO = 2097187;
pub const CURLINFO_CERTINFO: CURLINFO = 4194338;
pub const CURLINFO_APPCONNECT_TIME: CURLINFO = 3145761;
pub const CURLINFO_PRIMARY_IP: CURLINFO = 1048608;
pub const CURLINFO_REDIRECT_URL: CURLINFO = 1048607;
pub const CURLINFO_FTP_ENTRY_PATH: CURLINFO = 1048606;
pub const CURLINFO_LASTSOCKET: CURLINFO = 2097181;
pub const CURLINFO_COOKIELIST: CURLINFO = 4194332;
pub const CURLINFO_SSL_ENGINES: CURLINFO = 4194331;
pub const CURLINFO_NUM_CONNECTS: CURLINFO = 2097178;
pub const CURLINFO_OS_ERRNO: CURLINFO = 2097177;
pub const CURLINFO_PROXYAUTH_AVAIL: CURLINFO = 2097176;
pub const CURLINFO_HTTPAUTH_AVAIL: CURLINFO = 2097175;
pub const CURLINFO_HTTP_CONNECTCODE: CURLINFO = 2097174;
pub const CURLINFO_PRIVATE: CURLINFO = 1048597;
pub const CURLINFO_REDIRECT_COUNT: CURLINFO = 2097172;
pub const CURLINFO_REDIRECT_TIME: CURLINFO = 3145747;
pub const CURLINFO_CONTENT_TYPE: CURLINFO = 1048594;
pub const CURLINFO_STARTTRANSFER_TIME: CURLINFO = 3145745;
pub const CURLINFO_CONTENT_LENGTH_UPLOAD_T: CURLINFO = 6291472;
pub const CURLINFO_CONTENT_LENGTH_UPLOAD: CURLINFO = 3145744;
pub const CURLINFO_CONTENT_LENGTH_DOWNLOAD_T: CURLINFO = 6291471;
pub const CURLINFO_CONTENT_LENGTH_DOWNLOAD: CURLINFO = 3145743;
pub const CURLINFO_FILETIME_T: CURLINFO = 6291470;
pub const CURLINFO_FILETIME: CURLINFO = 2097166;
pub const CURLINFO_SSL_VERIFYRESULT: CURLINFO = 2097165;
pub const CURLINFO_REQUEST_SIZE: CURLINFO = 2097164;
pub const CURLINFO_HEADER_SIZE: CURLINFO = 2097163;
pub const CURLINFO_SPEED_UPLOAD_T: CURLINFO = 6291466;
pub const CURLINFO_SPEED_UPLOAD: CURLINFO = 3145738;
pub const CURLINFO_SPEED_DOWNLOAD_T: CURLINFO = 6291465;
pub const CURLINFO_SPEED_DOWNLOAD: CURLINFO = 3145737;
pub const CURLINFO_SIZE_DOWNLOAD_T: CURLINFO = 6291464;
pub const CURLINFO_SIZE_DOWNLOAD: CURLINFO = 3145736;
pub const CURLINFO_SIZE_UPLOAD_T: CURLINFO = 6291463;
pub const CURLINFO_SIZE_UPLOAD: CURLINFO = 3145735;
pub const CURLINFO_PRETRANSFER_TIME: CURLINFO = 3145734;
pub const CURLINFO_CONNECT_TIME: CURLINFO = 3145733;
pub const CURLINFO_NAMELOOKUP_TIME: CURLINFO = 3145732;
pub const CURLINFO_TOTAL_TIME: CURLINFO = 3145731;
pub const CURLINFO_RESPONSE_CODE: CURLINFO = 2097154;
pub const CURLINFO_EFFECTIVE_URL: CURLINFO = 1048577;
pub const CURLINFO_NONE: CURLINFO = 0;
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
pub struct InStruct {
    pub fd: libc::c_int,
    pub config: *mut OperationConfig,
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
pub type writeoutid = libc::c_uint;
pub const VAR_NUM_OF_VARS: writeoutid = 42;
pub const VAR_URLNUM: writeoutid = 41;
pub const VAR_TOTAL_TIME: writeoutid = 40;
pub const VAR_STDOUT: writeoutid = 39;
pub const VAR_STDERR: writeoutid = 38;
pub const VAR_STARTTRANSFER_TIME: writeoutid = 37;
pub const VAR_SSL_VERIFY_RESULT: writeoutid = 36;
pub const VAR_SPEED_UPLOAD: writeoutid = 35;
pub const VAR_SPEED_DOWNLOAD: writeoutid = 34;
pub const VAR_SIZE_UPLOAD: writeoutid = 33;
pub const VAR_SIZE_DOWNLOAD: writeoutid = 32;
pub const VAR_SCHEME: writeoutid = 31;
pub const VAR_REQUEST_SIZE: writeoutid = 30;
pub const VAR_REFERER: writeoutid = 29;
pub const VAR_REDIRECT_URL: writeoutid = 28;
pub const VAR_REDIRECT_TIME: writeoutid = 27;
pub const VAR_REDIRECT_COUNT: writeoutid = 26;
pub const VAR_PROXY_SSL_VERIFY_RESULT: writeoutid = 25;
pub const VAR_PRIMARY_PORT: writeoutid = 24;
pub const VAR_PRIMARY_IP: writeoutid = 23;
pub const VAR_PRETRANSFER_TIME: writeoutid = 22;
pub const VAR_ONERROR: writeoutid = 21;
pub const VAR_NUM_HEADERS: writeoutid = 20;
pub const VAR_NUM_CONNECTS: writeoutid = 19;
pub const VAR_NAMELOOKUP_TIME: writeoutid = 18;
pub const VAR_LOCAL_PORT: writeoutid = 17;
pub const VAR_LOCAL_IP: writeoutid = 16;
pub const VAR_JSON: writeoutid = 15;
pub const VAR_INPUT_URL: writeoutid = 14;
pub const VAR_HTTP_VERSION: writeoutid = 13;
pub const VAR_HTTP_CODE_PROXY: writeoutid = 12;
pub const VAR_HTTP_CODE: writeoutid = 11;
pub const VAR_HEADER_SIZE: writeoutid = 10;
pub const VAR_FTP_ENTRY_PATH: writeoutid = 9;
pub const VAR_EXITCODE: writeoutid = 8;
pub const VAR_ERRORMSG: writeoutid = 7;
pub const VAR_EFFECTIVE_URL: writeoutid = 6;
pub const VAR_EFFECTIVE_METHOD: writeoutid = 5;
pub const VAR_EFFECTIVE_FILENAME: writeoutid = 4;
pub const VAR_CONTENT_TYPE: writeoutid = 3;
pub const VAR_CONNECT_TIME: writeoutid = 2;
pub const VAR_APPCONNECT_TIME: writeoutid = 1;
pub const VAR_NONE: writeoutid = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct writeoutvar {
    pub name: *const libc::c_char,
    pub id: writeoutid,
    pub ci: CURLINFO,
    pub writefunc: Option::<
        unsafe extern "C" fn(
            *mut FILE,
            *const writeoutvar,
            *mut per_transfer,
            CURLcode,
            bool,
        ) -> libc::c_int,
    >,
}
static mut http_version: [*const libc::c_char; 5] = [
    b"0\0" as *const u8 as *const libc::c_char,
    b"1\0" as *const u8 as *const libc::c_char,
    b"1.1\0" as *const u8 as *const libc::c_char,
    b"2\0" as *const u8 as *const libc::c_char,
    b"3\0" as *const u8 as *const libc::c_char,
];
static mut variables: [writeoutvar; 43] = unsafe {
    [
        {
            let mut init = writeoutvar {
                name: b"content_type\0" as *const u8 as *const libc::c_char,
                id: VAR_CONTENT_TYPE,
                ci: CURLINFO_CONTENT_TYPE,
                writefunc: Some(
                    writeString
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"errormsg\0" as *const u8 as *const libc::c_char,
                id: VAR_ERRORMSG,
                ci: CURLINFO_NONE,
                writefunc: Some(
                    writeString
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"exitcode\0" as *const u8 as *const libc::c_char,
                id: VAR_EXITCODE,
                ci: CURLINFO_NONE,
                writefunc: Some(
                    writeLong
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"filename_effective\0" as *const u8 as *const libc::c_char,
                id: VAR_EFFECTIVE_FILENAME,
                ci: CURLINFO_NONE,
                writefunc: Some(
                    writeString
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"ftp_entry_path\0" as *const u8 as *const libc::c_char,
                id: VAR_FTP_ENTRY_PATH,
                ci: CURLINFO_FTP_ENTRY_PATH,
                writefunc: Some(
                    writeString
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"http_code\0" as *const u8 as *const libc::c_char,
                id: VAR_HTTP_CODE,
                ci: CURLINFO_RESPONSE_CODE,
                writefunc: Some(
                    writeLong
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"http_connect\0" as *const u8 as *const libc::c_char,
                id: VAR_HTTP_CODE_PROXY,
                ci: CURLINFO_HTTP_CONNECTCODE,
                writefunc: Some(
                    writeLong
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"http_version\0" as *const u8 as *const libc::c_char,
                id: VAR_HTTP_VERSION,
                ci: CURLINFO_HTTP_VERSION,
                writefunc: Some(
                    writeString
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"json\0" as *const u8 as *const libc::c_char,
                id: VAR_JSON,
                ci: CURLINFO_NONE,
                writefunc: None,
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"local_ip\0" as *const u8 as *const libc::c_char,
                id: VAR_LOCAL_IP,
                ci: CURLINFO_LOCAL_IP,
                writefunc: Some(
                    writeString
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"local_port\0" as *const u8 as *const libc::c_char,
                id: VAR_LOCAL_PORT,
                ci: CURLINFO_LOCAL_PORT,
                writefunc: Some(
                    writeLong
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"method\0" as *const u8 as *const libc::c_char,
                id: VAR_EFFECTIVE_METHOD,
                ci: CURLINFO_EFFECTIVE_METHOD,
                writefunc: Some(
                    writeString
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"num_connects\0" as *const u8 as *const libc::c_char,
                id: VAR_NUM_CONNECTS,
                ci: CURLINFO_NUM_CONNECTS,
                writefunc: Some(
                    writeLong
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"num_headers\0" as *const u8 as *const libc::c_char,
                id: VAR_NUM_HEADERS,
                ci: CURLINFO_NONE,
                writefunc: Some(
                    writeLong
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"num_redirects\0" as *const u8 as *const libc::c_char,
                id: VAR_REDIRECT_COUNT,
                ci: CURLINFO_REDIRECT_COUNT,
                writefunc: Some(
                    writeLong
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"onerror\0" as *const u8 as *const libc::c_char,
                id: VAR_ONERROR,
                ci: CURLINFO_NONE,
                writefunc: None,
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"proxy_ssl_verify_result\0" as *const u8 as *const libc::c_char,
                id: VAR_PROXY_SSL_VERIFY_RESULT,
                ci: CURLINFO_PROXY_SSL_VERIFYRESULT,
                writefunc: Some(
                    writeLong
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"redirect_url\0" as *const u8 as *const libc::c_char,
                id: VAR_REDIRECT_URL,
                ci: CURLINFO_REDIRECT_URL,
                writefunc: Some(
                    writeString
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"referer\0" as *const u8 as *const libc::c_char,
                id: VAR_REFERER,
                ci: CURLINFO_REFERER,
                writefunc: Some(
                    writeString
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"remote_ip\0" as *const u8 as *const libc::c_char,
                id: VAR_PRIMARY_IP,
                ci: CURLINFO_PRIMARY_IP,
                writefunc: Some(
                    writeString
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"remote_port\0" as *const u8 as *const libc::c_char,
                id: VAR_PRIMARY_PORT,
                ci: CURLINFO_PRIMARY_PORT,
                writefunc: Some(
                    writeLong
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"response_code\0" as *const u8 as *const libc::c_char,
                id: VAR_HTTP_CODE,
                ci: CURLINFO_RESPONSE_CODE,
                writefunc: Some(
                    writeLong
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"scheme\0" as *const u8 as *const libc::c_char,
                id: VAR_SCHEME,
                ci: CURLINFO_SCHEME,
                writefunc: Some(
                    writeString
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"size_download\0" as *const u8 as *const libc::c_char,
                id: VAR_SIZE_DOWNLOAD,
                ci: CURLINFO_SIZE_DOWNLOAD_T,
                writefunc: Some(
                    writeOffset
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"size_header\0" as *const u8 as *const libc::c_char,
                id: VAR_HEADER_SIZE,
                ci: CURLINFO_HEADER_SIZE,
                writefunc: Some(
                    writeLong
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"size_request\0" as *const u8 as *const libc::c_char,
                id: VAR_REQUEST_SIZE,
                ci: CURLINFO_REQUEST_SIZE,
                writefunc: Some(
                    writeLong
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"size_upload\0" as *const u8 as *const libc::c_char,
                id: VAR_SIZE_UPLOAD,
                ci: CURLINFO_SIZE_UPLOAD_T,
                writefunc: Some(
                    writeOffset
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"speed_download\0" as *const u8 as *const libc::c_char,
                id: VAR_SPEED_DOWNLOAD,
                ci: CURLINFO_SPEED_DOWNLOAD_T,
                writefunc: Some(
                    writeOffset
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"speed_upload\0" as *const u8 as *const libc::c_char,
                id: VAR_SPEED_UPLOAD,
                ci: CURLINFO_SPEED_UPLOAD_T,
                writefunc: Some(
                    writeOffset
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"ssl_verify_result\0" as *const u8 as *const libc::c_char,
                id: VAR_SSL_VERIFY_RESULT,
                ci: CURLINFO_SSL_VERIFYRESULT,
                writefunc: Some(
                    writeLong
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"stderr\0" as *const u8 as *const libc::c_char,
                id: VAR_STDERR,
                ci: CURLINFO_NONE,
                writefunc: None,
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"stdout\0" as *const u8 as *const libc::c_char,
                id: VAR_STDOUT,
                ci: CURLINFO_NONE,
                writefunc: None,
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"time_appconnect\0" as *const u8 as *const libc::c_char,
                id: VAR_APPCONNECT_TIME,
                ci: CURLINFO_APPCONNECT_TIME_T,
                writefunc: Some(
                    writeTime
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"time_connect\0" as *const u8 as *const libc::c_char,
                id: VAR_CONNECT_TIME,
                ci: CURLINFO_CONNECT_TIME_T,
                writefunc: Some(
                    writeTime
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"time_namelookup\0" as *const u8 as *const libc::c_char,
                id: VAR_NAMELOOKUP_TIME,
                ci: CURLINFO_NAMELOOKUP_TIME_T,
                writefunc: Some(
                    writeTime
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"time_pretransfer\0" as *const u8 as *const libc::c_char,
                id: VAR_PRETRANSFER_TIME,
                ci: CURLINFO_PRETRANSFER_TIME_T,
                writefunc: Some(
                    writeTime
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"time_redirect\0" as *const u8 as *const libc::c_char,
                id: VAR_REDIRECT_TIME,
                ci: CURLINFO_REDIRECT_TIME_T,
                writefunc: Some(
                    writeTime
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"time_starttransfer\0" as *const u8 as *const libc::c_char,
                id: VAR_STARTTRANSFER_TIME,
                ci: CURLINFO_STARTTRANSFER_TIME_T,
                writefunc: Some(
                    writeTime
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"time_total\0" as *const u8 as *const libc::c_char,
                id: VAR_TOTAL_TIME,
                ci: CURLINFO_TOTAL_TIME_T,
                writefunc: Some(
                    writeTime
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"url\0" as *const u8 as *const libc::c_char,
                id: VAR_INPUT_URL,
                ci: CURLINFO_NONE,
                writefunc: Some(
                    writeString
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"url_effective\0" as *const u8 as *const libc::c_char,
                id: VAR_EFFECTIVE_URL,
                ci: CURLINFO_EFFECTIVE_URL,
                writefunc: Some(
                    writeString
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: b"urlnum\0" as *const u8 as *const libc::c_char,
                id: VAR_URLNUM,
                ci: CURLINFO_NONE,
                writefunc: Some(
                    writeLong
                        as unsafe extern "C" fn(
                            *mut FILE,
                            *const writeoutvar,
                            *mut per_transfer,
                            CURLcode,
                            bool,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = writeoutvar {
                name: 0 as *const libc::c_char,
                id: VAR_NONE,
                ci: CURLINFO_NONE,
                writefunc: None,
            };
            init
        },
    ]
};
unsafe extern "C" fn writeTime(
    mut stream: *mut FILE,
    mut wovar: *const writeoutvar,
    mut per: *mut per_transfer,
    mut per_result: CURLcode,
    mut use_json: bool,
) -> libc::c_int {
    let mut valid: bool = 0 as libc::c_int != 0;
    let mut us: curl_off_t = 0 as libc::c_int as curl_off_t;
    if (*wovar).ci as u64 != 0 {
        if curl_easy_getinfo((*per).curl, (*wovar).ci, &mut us as *mut curl_off_t) as u64
            == 0
        {
            valid = 1 as libc::c_int != 0;
        }
    }
    if valid {
        let mut secs: curl_off_t = us / 1000000 as libc::c_int as libc::c_long;
        us %= 1000000 as libc::c_int as libc::c_long;
        if use_json {
            curl_mfprintf(
                stream,
                b"\"%s\":\0" as *const u8 as *const libc::c_char,
                (*wovar).name,
            );
        }
        curl_mfprintf(
            stream,
            b"%lu.%06lu\0" as *const u8 as *const libc::c_char,
            secs,
            us,
        );
    } else if use_json {
        curl_mfprintf(
            stream,
            b"\"%s\":null\0" as *const u8 as *const libc::c_char,
            (*wovar).name,
        );
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn writeString(
    mut stream: *mut FILE,
    mut wovar: *const writeoutvar,
    mut per: *mut per_transfer,
    mut per_result: CURLcode,
    mut use_json: bool,
) -> libc::c_int {
    let mut valid: bool = 0 as libc::c_int != 0;
    let mut strinfo: *const libc::c_char = 0 as *const libc::c_char;
    if (*wovar).ci as u64 != 0 {
        if (*wovar).ci as libc::c_uint
            == CURLINFO_HTTP_VERSION as libc::c_int as libc::c_uint
        {
            let mut version: libc::c_long = 0 as libc::c_int as libc::c_long;
            if curl_easy_getinfo(
                (*per).curl,
                CURLINFO_HTTP_VERSION,
                &mut version as *mut libc::c_long,
            ) as u64 == 0 && version >= 0 as libc::c_int as libc::c_long
                && version
                    < (::std::mem::size_of::<[*const libc::c_char; 5]>()
                        as libc::c_ulong)
                        .wrapping_div(
                            ::std::mem::size_of::<*const libc::c_char>() as libc::c_ulong,
                        ) as libc::c_long
            {
                strinfo = http_version[version as usize];
                valid = 1 as libc::c_int != 0;
            }
        } else if curl_easy_getinfo(
                (*per).curl,
                (*wovar).ci,
                &mut strinfo as *mut *const libc::c_char,
            ) as u64 == 0 && !strinfo.is_null()
            {
            valid = 1 as libc::c_int != 0;
        }
    } else {
        match (*wovar).id as libc::c_uint {
            7 => {
                if per_result as u64 != 0 {
                    strinfo = if (*per).errorbuffer[0 as libc::c_int as usize]
                        as libc::c_int != 0
                    {
                        ((*per).errorbuffer).as_mut_ptr() as *const libc::c_char
                    } else {
                        curl_easy_strerror(per_result)
                    };
                    valid = 1 as libc::c_int != 0;
                }
            }
            4 => {
                if !((*per).outs.filename).is_null() {
                    strinfo = (*per).outs.filename;
                    valid = 1 as libc::c_int != 0;
                }
            }
            14 => {
                if !((*per).this_url).is_null() {
                    strinfo = (*per).this_url;
                    valid = 1 as libc::c_int != 0;
                }
            }
            _ => {}
        }
    }
    if valid {
        if use_json {
            curl_mfprintf(
                stream,
                b"\"%s\":\"\0" as *const u8 as *const libc::c_char,
                (*wovar).name,
            );
            jsonWriteString(stream, strinfo);
            fputs(b"\"\0" as *const u8 as *const libc::c_char, stream);
        } else {
            fputs(strinfo, stream);
        }
    } else if use_json {
        curl_mfprintf(
            stream,
            b"\"%s\":null\0" as *const u8 as *const libc::c_char,
            (*wovar).name,
        );
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn writeLong(
    mut stream: *mut FILE,
    mut wovar: *const writeoutvar,
    mut per: *mut per_transfer,
    mut per_result: CURLcode,
    mut use_json: bool,
) -> libc::c_int {
    let mut valid: bool = 0 as libc::c_int != 0;
    let mut longinfo: libc::c_long = 0 as libc::c_int as libc::c_long;
    if (*wovar).ci as u64 != 0 {
        if curl_easy_getinfo(
            (*per).curl,
            (*wovar).ci,
            &mut longinfo as *mut libc::c_long,
        ) as u64 == 0
        {
            valid = 1 as libc::c_int != 0;
        }
    } else {
        match (*wovar).id as libc::c_uint {
            20 => {
                longinfo = (*per).num_headers;
                valid = 1 as libc::c_int != 0;
            }
            8 => {
                longinfo = per_result as libc::c_long;
                valid = 1 as libc::c_int != 0;
            }
            41 => {
                if (*per).urlnum <= 2147483647 as libc::c_int as libc::c_uint {
                    longinfo = (*per).urlnum as libc::c_long;
                    valid = 1 as libc::c_int != 0;
                }
            }
            _ => {}
        }
    }
    if valid {
        if use_json {
            curl_mfprintf(
                stream,
                b"\"%s\":%ld\0" as *const u8 as *const libc::c_char,
                (*wovar).name,
                longinfo,
            );
        } else if (*wovar).id as libc::c_uint
                == VAR_HTTP_CODE as libc::c_int as libc::c_uint
                || (*wovar).id as libc::c_uint
                    == VAR_HTTP_CODE_PROXY as libc::c_int as libc::c_uint
            {
            curl_mfprintf(
                stream,
                b"%03ld\0" as *const u8 as *const libc::c_char,
                longinfo,
            );
        } else {
            curl_mfprintf(
                stream,
                b"%ld\0" as *const u8 as *const libc::c_char,
                longinfo,
            );
        }
    } else if use_json {
        curl_mfprintf(
            stream,
            b"\"%s\":null\0" as *const u8 as *const libc::c_char,
            (*wovar).name,
        );
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn writeOffset(
    mut stream: *mut FILE,
    mut wovar: *const writeoutvar,
    mut per: *mut per_transfer,
    mut per_result: CURLcode,
    mut use_json: bool,
) -> libc::c_int {
    let mut valid: bool = 0 as libc::c_int != 0;
    let mut offinfo: curl_off_t = 0 as libc::c_int as curl_off_t;
    if (*wovar).ci as u64 != 0 {
        if curl_easy_getinfo((*per).curl, (*wovar).ci, &mut offinfo as *mut curl_off_t)
            as u64 == 0
        {
            valid = 1 as libc::c_int != 0;
        }
    }
    if valid {
        if use_json {
            curl_mfprintf(
                stream,
                b"\"%s\":\0" as *const u8 as *const libc::c_char,
                (*wovar).name,
            );
        }
        curl_mfprintf(stream, b"%ld\0" as *const u8 as *const libc::c_char, offinfo);
    } else if use_json {
        curl_mfprintf(
            stream,
            b"\"%s\":null\0" as *const u8 as *const libc::c_char,
            (*wovar).name,
        );
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ourWriteOut(
    mut writeinfo: *const libc::c_char,
    mut per: *mut per_transfer,
    mut per_result: CURLcode,
) {
    let mut stream: *mut FILE = stdout;
    let mut ptr: *const libc::c_char = writeinfo;
    let mut done: bool = 0 as libc::c_int != 0;
    while !ptr.is_null() && *ptr as libc::c_int != 0 && !done {
        if '%' as i32 == *ptr as libc::c_int
            && *ptr.offset(1 as libc::c_int as isize) as libc::c_int != 0
        {
            if '%' as i32 == *ptr.offset(1 as libc::c_int as isize) as libc::c_int {
                fputc('%' as i32, stream);
                ptr = ptr.offset(2 as libc::c_int as isize);
            } else {
                let mut end: *mut libc::c_char = 0 as *mut libc::c_char;
                if '{' as i32 == *ptr.offset(1 as libc::c_int as isize) as libc::c_int {
                    let mut keepit: libc::c_char = 0;
                    let mut i: libc::c_int = 0;
                    let mut match_0: bool = 0 as libc::c_int != 0;
                    end = strchr(ptr, '}' as i32);
                    ptr = ptr.offset(2 as libc::c_int as isize);
                    if end.is_null() {
                        fputs(b"%{\0" as *const u8 as *const libc::c_char, stream);
                    } else {
                        keepit = *end;
                        *end = 0 as libc::c_int as libc::c_char;
                        i = 0 as libc::c_int;
                        while !(variables[i as usize].name).is_null() {
                            if curl_strequal(ptr, variables[i as usize].name) != 0 {
                                match_0 = 1 as libc::c_int != 0;
                                match variables[i as usize].id as libc::c_uint {
                                    21 => {
                                        if per_result as libc::c_uint
                                            == CURLE_OK as libc::c_int as libc::c_uint
                                        {
                                            done = 1 as libc::c_int != 0;
                                        }
                                    }
                                    39 => {
                                        stream = stdout;
                                    }
                                    38 => {
                                        stream = stderr;
                                    }
                                    15 => {
                                        ourWriteOutJSON(
                                            stream,
                                            variables.as_ptr(),
                                            per,
                                            per_result,
                                        );
                                    }
                                    _ => {
                                        (variables[i as usize].writefunc)
                                            .expect(
                                                "non-null function pointer",
                                            )(
                                            stream,
                                            &*variables.as_ptr().offset(i as isize),
                                            per,
                                            per_result,
                                            0 as libc::c_int != 0,
                                        );
                                    }
                                }
                                break;
                            } else {
                                i += 1;
                            }
                        }
                        if !match_0 {
                            curl_mfprintf(
                                stderr,
                                b"curl: unknown --write-out variable: '%s'\n\0" as *const u8
                                    as *const libc::c_char,
                                ptr,
                            );
                        }
                        ptr = end.offset(1 as libc::c_int as isize);
                        *end = keepit;
                    }
                } else {
                    fputc('%' as i32, stream);
                    fputc(*ptr.offset(1 as libc::c_int as isize) as libc::c_int, stream);
                    ptr = ptr.offset(2 as libc::c_int as isize);
                }
            }
        } else if '\\' as i32 == *ptr as libc::c_int
                && *ptr.offset(1 as libc::c_int as isize) as libc::c_int != 0
            {
            match *ptr.offset(1 as libc::c_int as isize) as libc::c_int {
                114 => {
                    fputc('\r' as i32, stream);
                }
                110 => {
                    fputc('\n' as i32, stream);
                }
                116 => {
                    fputc('\t' as i32, stream);
                }
                _ => {
                    fputc(*ptr as libc::c_int, stream);
                    fputc(*ptr.offset(1 as libc::c_int as isize) as libc::c_int, stream);
                }
            }
            ptr = ptr.offset(2 as libc::c_int as isize);
        } else {
            fputc(*ptr as libc::c_int, stream);
            ptr = ptr.offset(1);
        }
    }
}
