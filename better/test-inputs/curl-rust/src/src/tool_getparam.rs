use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type Curl_easy;
    pub type curl_mime;
    static mut stdin: *mut FILE;
    static mut stdout: *mut FILE;
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn time(__timer: *mut time_t) -> time_t;
    fn curl_strequal(s1: *const libc::c_char, s2: *const libc::c_char) -> libc::c_int;
    fn curl_strnequal(
        s1: *const libc::c_char,
        s2: *const libc::c_char,
        n: size_t,
    ) -> libc::c_int;
    fn curl_easy_escape(
        handle: *mut CURL,
        string: *const libc::c_char,
        length: libc::c_int,
    ) -> *mut libc::c_char;
    fn curl_free(p: *mut libc::c_void);
    fn curl_getdate(p: *const libc::c_char, unused: *const time_t) -> time_t;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcpy(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strncpy(
        _: *mut libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> *mut libc::c_char;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strpbrk(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strstr(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strtok(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn Curl_isdigit(c: libc::c_int) -> libc::c_int;
    fn curl_msnprintf(
        buffer: *mut libc::c_char,
        maxlength: size_t,
        format: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn curlx_uztoso(uznum: size_t) -> curl_off_t;
    fn curlx_strtoofft(
        str: *const libc::c_char,
        endp: *mut *mut libc::c_char,
        base: libc::c_int,
        num: *mut curl_off_t,
    ) -> CURLofft;
    fn formparse(
        config: *mut OperationConfig,
        input: *const libc::c_char,
        mimeroot: *mut *mut tool_mime,
        mimecurrent: *mut *mut tool_mime,
        literal_value: bool,
    ) -> libc::c_int;
    fn config_init(config: *mut OperationConfig);
    fn getfiletime(
        filename: *const libc::c_char,
        global: *mut GlobalConfig,
    ) -> curl_off_t;
    fn param2text(res: libc::c_int) -> *const libc::c_char;
    fn SetHTTPrequest(
        config: *mut OperationConfig,
        req: HttpReq,
        store: *mut HttpReq,
    ) -> libc::c_int;
    static mut curlinfo: *mut curl_version_info_data;
    fn warnf(config: *mut GlobalConfig, fmt: *const libc::c_char, _: ...);
    fn helpf(errors: *mut FILE, fmt: *const libc::c_char, _: ...);
    fn errorf(config: *mut GlobalConfig, fmt: *const libc::c_char, _: ...);
    fn new_getout(config: *mut OperationConfig) -> *mut getout;
    fn file2string(bufp: *mut *mut libc::c_char, file: *mut FILE) -> ParameterError;
    fn file2memory(
        bufp: *mut *mut libc::c_char,
        size: *mut size_t,
        file: *mut FILE,
    ) -> ParameterError;
    fn cleanarg(str: *mut libc::c_char);
    fn str2num(val: *mut libc::c_long, str: *const libc::c_char) -> ParameterError;
    fn str2unum(val: *mut libc::c_long, str: *const libc::c_char) -> ParameterError;
    fn oct2nummax(
        val: *mut libc::c_long,
        str: *const libc::c_char,
        max: libc::c_long,
    ) -> ParameterError;
    fn str2unummax(
        val: *mut libc::c_long,
        str: *const libc::c_char,
        max: libc::c_long,
    ) -> ParameterError;
    fn str2udouble(
        val: *mut libc::c_double,
        str: *const libc::c_char,
        max: libc::c_long,
    ) -> ParameterError;
    fn proto2num(
        config: *mut OperationConfig,
        val: *mut libc::c_long,
        str: *const libc::c_char,
    ) -> libc::c_long;
    fn check_protocol(str: *const libc::c_char) -> libc::c_int;
    fn str2offset(val: *mut curl_off_t, str: *const libc::c_char) -> ParameterError;
    fn add2list(list: *mut *mut curl_slist, ptr: *const libc::c_char) -> ParameterError;
    fn ftpfilemethod(
        config: *mut OperationConfig,
        str: *const libc::c_char,
    ) -> libc::c_int;
    fn ftpcccmethod(
        config: *mut OperationConfig,
        str: *const libc::c_char,
    ) -> libc::c_int;
    fn delegation(
        config: *mut OperationConfig,
        str: *const libc::c_char,
    ) -> libc::c_long;
    fn str2tls_max(val: *mut libc::c_long, str: *const libc::c_char) -> ParameterError;
    fn parseconfig(
        filename: *const libc::c_char,
        config: *mut GlobalConfig,
    ) -> libc::c_int;
}
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type time_t = __time_t;
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
pub type CURL = Curl_easy;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_slist {
    pub data: *mut libc::c_char,
    pub next: *mut curl_slist,
}
pub type C2RustUnnamed = libc::c_uint;
pub const CURLPROXY_SOCKS5_HOSTNAME: C2RustUnnamed = 7;
pub const CURLPROXY_SOCKS4A: C2RustUnnamed = 6;
pub const CURLPROXY_SOCKS5: C2RustUnnamed = 5;
pub const CURLPROXY_SOCKS4: C2RustUnnamed = 4;
pub const CURLPROXY_HTTPS: C2RustUnnamed = 2;
pub const CURLPROXY_HTTP_1_0: C2RustUnnamed = 1;
pub const CURLPROXY_HTTP: C2RustUnnamed = 0;
pub type C2RustUnnamed_0 = libc::c_uint;
pub const CURLFTPSSL_CCC_LAST: C2RustUnnamed_0 = 3;
pub const CURLFTPSSL_CCC_ACTIVE: C2RustUnnamed_0 = 2;
pub const CURLFTPSSL_CCC_PASSIVE: C2RustUnnamed_0 = 1;
pub const CURLFTPSSL_CCC_NONE: C2RustUnnamed_0 = 0;
pub type C2RustUnnamed_1 = libc::c_uint;
pub const CURL_HTTP_VERSION_LAST: C2RustUnnamed_1 = 31;
pub const CURL_HTTP_VERSION_3: C2RustUnnamed_1 = 30;
pub const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: C2RustUnnamed_1 = 5;
pub const CURL_HTTP_VERSION_2TLS: C2RustUnnamed_1 = 4;
pub const CURL_HTTP_VERSION_2_0: C2RustUnnamed_1 = 3;
pub const CURL_HTTP_VERSION_1_1: C2RustUnnamed_1 = 2;
pub const CURL_HTTP_VERSION_1_0: C2RustUnnamed_1 = 1;
pub const CURL_HTTP_VERSION_NONE: C2RustUnnamed_1 = 0;
pub type C2RustUnnamed_2 = libc::c_uint;
pub const CURL_SSLVERSION_LAST: C2RustUnnamed_2 = 8;
pub const CURL_SSLVERSION_TLSv1_3: C2RustUnnamed_2 = 7;
pub const CURL_SSLVERSION_TLSv1_2: C2RustUnnamed_2 = 6;
pub const CURL_SSLVERSION_TLSv1_1: C2RustUnnamed_2 = 5;
pub const CURL_SSLVERSION_TLSv1_0: C2RustUnnamed_2 = 4;
pub const CURL_SSLVERSION_SSLv3: C2RustUnnamed_2 = 3;
pub const CURL_SSLVERSION_SSLv2: C2RustUnnamed_2 = 2;
pub const CURL_SSLVERSION_TLSv1: C2RustUnnamed_2 = 1;
pub const CURL_SSLVERSION_DEFAULT: C2RustUnnamed_2 = 0;
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
pub type CURLofft = libc::c_uint;
pub const CURL_OFFT_INVAL: CURLofft = 2;
pub const CURL_OFFT_FLOW: CURLofft = 1;
pub const CURL_OFFT_OK: CURLofft = 0;
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
    pub content: C2RustUnnamed_3,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_3 {
    pub Set: C2RustUnnamed_6,
    pub CharRange: C2RustUnnamed_5,
    pub NumRange: C2RustUnnamed_4,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_4 {
    pub min_n: libc::c_ulong,
    pub max_n: libc::c_ulong,
    pub padlength: libc::c_int,
    pub ptr_n: libc::c_ulong,
    pub step: libc::c_ulong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_5 {
    pub min_c: libc::c_char,
    pub max_c: libc::c_char,
    pub ptr_c: libc::c_char,
    pub step: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_6 {
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
pub const ARG_NONE: C2RustUnnamed_7 = 0;
pub type C2RustUnnamed_7 = libc::c_uint;
pub const ARG_FILENAME: C2RustUnnamed_7 = 3;
pub const ARG_STRING: C2RustUnnamed_7 = 2;
pub const ARG_BOOL: C2RustUnnamed_7 = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct LongShort {
    pub letter: *const libc::c_char,
    pub lname: *const libc::c_char,
    pub desc: C2RustUnnamed_7,
}
static mut aliases: [LongShort; 248] = [
    {
        let mut init = LongShort {
            letter: b"*@\0" as *const u8 as *const libc::c_char,
            lname: b"url\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*4\0" as *const u8 as *const libc::c_char,
            lname: b"dns-ipv4-addr\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*6\0" as *const u8 as *const libc::c_char,
            lname: b"dns-ipv6-addr\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*a\0" as *const u8 as *const libc::c_char,
            lname: b"random-file\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*b\0" as *const u8 as *const libc::c_char,
            lname: b"egd-file\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*B\0" as *const u8 as *const libc::c_char,
            lname: b"oauth2-bearer\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*c\0" as *const u8 as *const libc::c_char,
            lname: b"connect-timeout\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*C\0" as *const u8 as *const libc::c_char,
            lname: b"doh-url\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*d\0" as *const u8 as *const libc::c_char,
            lname: b"ciphers\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*D\0" as *const u8 as *const libc::c_char,
            lname: b"dns-interface\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*e\0" as *const u8 as *const libc::c_char,
            lname: b"disable-epsv\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*f\0" as *const u8 as *const libc::c_char,
            lname: b"disallow-username-in-url\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*E\0" as *const u8 as *const libc::c_char,
            lname: b"epsv\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*F\0" as *const u8 as *const libc::c_char,
            lname: b"dns-servers\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*g\0" as *const u8 as *const libc::c_char,
            lname: b"trace\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*G\0" as *const u8 as *const libc::c_char,
            lname: b"npn\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*h\0" as *const u8 as *const libc::c_char,
            lname: b"trace-ascii\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*H\0" as *const u8 as *const libc::c_char,
            lname: b"alpn\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*i\0" as *const u8 as *const libc::c_char,
            lname: b"limit-rate\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*j\0" as *const u8 as *const libc::c_char,
            lname: b"compressed\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*J\0" as *const u8 as *const libc::c_char,
            lname: b"tr-encoding\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*k\0" as *const u8 as *const libc::c_char,
            lname: b"digest\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*l\0" as *const u8 as *const libc::c_char,
            lname: b"negotiate\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*m\0" as *const u8 as *const libc::c_char,
            lname: b"ntlm\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*M\0" as *const u8 as *const libc::c_char,
            lname: b"ntlm-wb\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*n\0" as *const u8 as *const libc::c_char,
            lname: b"basic\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*o\0" as *const u8 as *const libc::c_char,
            lname: b"anyauth\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*q\0" as *const u8 as *const libc::c_char,
            lname: b"ftp-create-dirs\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*r\0" as *const u8 as *const libc::c_char,
            lname: b"create-dirs\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*R\0" as *const u8 as *const libc::c_char,
            lname: b"create-file-mode\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*s\0" as *const u8 as *const libc::c_char,
            lname: b"max-redirs\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*t\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-ntlm\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*u\0" as *const u8 as *const libc::c_char,
            lname: b"crlf\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*v\0" as *const u8 as *const libc::c_char,
            lname: b"stderr\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*V\0" as *const u8 as *const libc::c_char,
            lname: b"aws-sigv4\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*w\0" as *const u8 as *const libc::c_char,
            lname: b"interface\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*x\0" as *const u8 as *const libc::c_char,
            lname: b"krb\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*x\0" as *const u8 as *const libc::c_char,
            lname: b"krb4\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*X\0" as *const u8 as *const libc::c_char,
            lname: b"haproxy-protocol\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*y\0" as *const u8 as *const libc::c_char,
            lname: b"max-filesize\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*z\0" as *const u8 as *const libc::c_char,
            lname: b"disable-eprt\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*Z\0" as *const u8 as *const libc::c_char,
            lname: b"eprt\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*~\0" as *const u8 as *const libc::c_char,
            lname: b"xattr\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$a\0" as *const u8 as *const libc::c_char,
            lname: b"ftp-ssl\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$a\0" as *const u8 as *const libc::c_char,
            lname: b"ssl\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$b\0" as *const u8 as *const libc::c_char,
            lname: b"ftp-pasv\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$c\0" as *const u8 as *const libc::c_char,
            lname: b"socks5\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$d\0" as *const u8 as *const libc::c_char,
            lname: b"tcp-nodelay\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$e\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-digest\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$f\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-basic\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$g\0" as *const u8 as *const libc::c_char,
            lname: b"retry\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$V\0" as *const u8 as *const libc::c_char,
            lname: b"retry-connrefused\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$h\0" as *const u8 as *const libc::c_char,
            lname: b"retry-delay\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$i\0" as *const u8 as *const libc::c_char,
            lname: b"retry-max-time\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$k\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-negotiate\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$m\0" as *const u8 as *const libc::c_char,
            lname: b"ftp-account\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$n\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-anyauth\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$o\0" as *const u8 as *const libc::c_char,
            lname: b"trace-time\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$p\0" as *const u8 as *const libc::c_char,
            lname: b"ignore-content-length\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$q\0" as *const u8 as *const libc::c_char,
            lname: b"ftp-skip-pasv-ip\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$r\0" as *const u8 as *const libc::c_char,
            lname: b"ftp-method\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$s\0" as *const u8 as *const libc::c_char,
            lname: b"local-port\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$t\0" as *const u8 as *const libc::c_char,
            lname: b"socks4\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$T\0" as *const u8 as *const libc::c_char,
            lname: b"socks4a\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$u\0" as *const u8 as *const libc::c_char,
            lname: b"ftp-alternative-to-user\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$v\0" as *const u8 as *const libc::c_char,
            lname: b"ftp-ssl-reqd\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$v\0" as *const u8 as *const libc::c_char,
            lname: b"ssl-reqd\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$w\0" as *const u8 as *const libc::c_char,
            lname: b"sessionid\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$x\0" as *const u8 as *const libc::c_char,
            lname: b"ftp-ssl-control\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$y\0" as *const u8 as *const libc::c_char,
            lname: b"ftp-ssl-ccc\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$j\0" as *const u8 as *const libc::c_char,
            lname: b"ftp-ssl-ccc-mode\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$z\0" as *const u8 as *const libc::c_char,
            lname: b"libcurl\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$#\0" as *const u8 as *const libc::c_char,
            lname: b"raw\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$0\0" as *const u8 as *const libc::c_char,
            lname: b"post301\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$1\0" as *const u8 as *const libc::c_char,
            lname: b"keepalive\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$2\0" as *const u8 as *const libc::c_char,
            lname: b"socks5-hostname\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$3\0" as *const u8 as *const libc::c_char,
            lname: b"keepalive-time\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$4\0" as *const u8 as *const libc::c_char,
            lname: b"post302\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$5\0" as *const u8 as *const libc::c_char,
            lname: b"noproxy\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$7\0" as *const u8 as *const libc::c_char,
            lname: b"socks5-gssapi-nec\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$8\0" as *const u8 as *const libc::c_char,
            lname: b"proxy1.0\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$9\0" as *const u8 as *const libc::c_char,
            lname: b"tftp-blksize\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$A\0" as *const u8 as *const libc::c_char,
            lname: b"mail-from\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$B\0" as *const u8 as *const libc::c_char,
            lname: b"mail-rcpt\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$C\0" as *const u8 as *const libc::c_char,
            lname: b"ftp-pret\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$D\0" as *const u8 as *const libc::c_char,
            lname: b"proto\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$E\0" as *const u8 as *const libc::c_char,
            lname: b"proto-redir\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$F\0" as *const u8 as *const libc::c_char,
            lname: b"resolve\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$G\0" as *const u8 as *const libc::c_char,
            lname: b"delegation\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$H\0" as *const u8 as *const libc::c_char,
            lname: b"mail-auth\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$I\0" as *const u8 as *const libc::c_char,
            lname: b"post303\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$J\0" as *const u8 as *const libc::c_char,
            lname: b"metalink\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$6\0" as *const u8 as *const libc::c_char,
            lname: b"sasl-authzid\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$K\0" as *const u8 as *const libc::c_char,
            lname: b"sasl-ir\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$L\0" as *const u8 as *const libc::c_char,
            lname: b"test-event\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$M\0" as *const u8 as *const libc::c_char,
            lname: b"unix-socket\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$N\0" as *const u8 as *const libc::c_char,
            lname: b"path-as-is\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$O\0" as *const u8 as *const libc::c_char,
            lname: b"socks5-gssapi-service\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$O\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-service-name\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$P\0" as *const u8 as *const libc::c_char,
            lname: b"service-name\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$Q\0" as *const u8 as *const libc::c_char,
            lname: b"proto-default\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$R\0" as *const u8 as *const libc::c_char,
            lname: b"expect100-timeout\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$S\0" as *const u8 as *const libc::c_char,
            lname: b"tftp-no-options\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$U\0" as *const u8 as *const libc::c_char,
            lname: b"connect-to\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$W\0" as *const u8 as *const libc::c_char,
            lname: b"abstract-unix-socket\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$X\0" as *const u8 as *const libc::c_char,
            lname: b"tls-max\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$Y\0" as *const u8 as *const libc::c_char,
            lname: b"suppress-connect-headers\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$Z\0" as *const u8 as *const libc::c_char,
            lname: b"compressed-ssh\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$~\0" as *const u8 as *const libc::c_char,
            lname: b"happy-eyeballs-timeout-ms\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$!\0" as *const u8 as *const libc::c_char,
            lname: b"retry-all-errors\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"0\0" as *const u8 as *const libc::c_char,
            lname: b"http1.0\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"01\0" as *const u8 as *const libc::c_char,
            lname: b"http1.1\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"02\0" as *const u8 as *const libc::c_char,
            lname: b"http2\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"03\0" as *const u8 as *const libc::c_char,
            lname: b"http2-prior-knowledge\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"04\0" as *const u8 as *const libc::c_char,
            lname: b"http3\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"09\0" as *const u8 as *const libc::c_char,
            lname: b"http0.9\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"1\0" as *const u8 as *const libc::c_char,
            lname: b"tlsv1\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"10\0" as *const u8 as *const libc::c_char,
            lname: b"tlsv1.0\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"11\0" as *const u8 as *const libc::c_char,
            lname: b"tlsv1.1\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"12\0" as *const u8 as *const libc::c_char,
            lname: b"tlsv1.2\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"13\0" as *const u8 as *const libc::c_char,
            lname: b"tlsv1.3\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"1A\0" as *const u8 as *const libc::c_char,
            lname: b"tls13-ciphers\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"1B\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-tls13-ciphers\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"2\0" as *const u8 as *const libc::c_char,
            lname: b"sslv2\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"3\0" as *const u8 as *const libc::c_char,
            lname: b"sslv3\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"4\0" as *const u8 as *const libc::c_char,
            lname: b"ipv4\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"6\0" as *const u8 as *const libc::c_char,
            lname: b"ipv6\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"a\0" as *const u8 as *const libc::c_char,
            lname: b"append\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"A\0" as *const u8 as *const libc::c_char,
            lname: b"user-agent\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"b\0" as *const u8 as *const libc::c_char,
            lname: b"cookie\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"ba\0" as *const u8 as *const libc::c_char,
            lname: b"alt-svc\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"bb\0" as *const u8 as *const libc::c_char,
            lname: b"hsts\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"B\0" as *const u8 as *const libc::c_char,
            lname: b"use-ascii\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"c\0" as *const u8 as *const libc::c_char,
            lname: b"cookie-jar\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"C\0" as *const u8 as *const libc::c_char,
            lname: b"continue-at\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"d\0" as *const u8 as *const libc::c_char,
            lname: b"data\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"dr\0" as *const u8 as *const libc::c_char,
            lname: b"data-raw\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"da\0" as *const u8 as *const libc::c_char,
            lname: b"data-ascii\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"db\0" as *const u8 as *const libc::c_char,
            lname: b"data-binary\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"de\0" as *const u8 as *const libc::c_char,
            lname: b"data-urlencode\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"D\0" as *const u8 as *const libc::c_char,
            lname: b"dump-header\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"e\0" as *const u8 as *const libc::c_char,
            lname: b"referer\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E\0" as *const u8 as *const libc::c_char,
            lname: b"cert\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ea\0" as *const u8 as *const libc::c_char,
            lname: b"cacert\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Eb\0" as *const u8 as *const libc::c_char,
            lname: b"cert-type\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ec\0" as *const u8 as *const libc::c_char,
            lname: b"key\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ed\0" as *const u8 as *const libc::c_char,
            lname: b"key-type\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ee\0" as *const u8 as *const libc::c_char,
            lname: b"pass\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ef\0" as *const u8 as *const libc::c_char,
            lname: b"engine\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Eg\0" as *const u8 as *const libc::c_char,
            lname: b"capath\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Eh\0" as *const u8 as *const libc::c_char,
            lname: b"pubkey\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ei\0" as *const u8 as *const libc::c_char,
            lname: b"hostpubmd5\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ej\0" as *const u8 as *const libc::c_char,
            lname: b"crlfile\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ek\0" as *const u8 as *const libc::c_char,
            lname: b"tlsuser\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"El\0" as *const u8 as *const libc::c_char,
            lname: b"tlspassword\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Em\0" as *const u8 as *const libc::c_char,
            lname: b"tlsauthtype\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"En\0" as *const u8 as *const libc::c_char,
            lname: b"ssl-allow-beast\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Eo\0" as *const u8 as *const libc::c_char,
            lname: b"ssl-auto-client-cert\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"EO\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-ssl-auto-client-cert\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ep\0" as *const u8 as *const libc::c_char,
            lname: b"pinnedpubkey\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"EP\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-pinnedpubkey\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Eq\0" as *const u8 as *const libc::c_char,
            lname: b"cert-status\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"EQ\0" as *const u8 as *const libc::c_char,
            lname: b"doh-cert-status\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Er\0" as *const u8 as *const libc::c_char,
            lname: b"false-start\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Es\0" as *const u8 as *const libc::c_char,
            lname: b"ssl-no-revoke\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"ES\0" as *const u8 as *const libc::c_char,
            lname: b"ssl-revoke-best-effort\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Et\0" as *const u8 as *const libc::c_char,
            lname: b"tcp-fastopen\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Eu\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-tlsuser\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ev\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-tlspassword\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ew\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-tlsauthtype\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ex\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-cert\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ey\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-cert-type\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ez\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-key\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E0\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-key-type\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E1\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-pass\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E2\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-ciphers\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E3\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-crlfile\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E4\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-ssl-allow-beast\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E5\0" as *const u8 as *const libc::c_char,
            lname: b"login-options\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E6\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-cacert\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E7\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-capath\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E8\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-insecure\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E9\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-tlsv1\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"EA\0" as *const u8 as *const libc::c_char,
            lname: b"socks5-basic\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"EB\0" as *const u8 as *const libc::c_char,
            lname: b"socks5-gssapi\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"EC\0" as *const u8 as *const libc::c_char,
            lname: b"etag-save\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"ED\0" as *const u8 as *const libc::c_char,
            lname: b"etag-compare\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"EE\0" as *const u8 as *const libc::c_char,
            lname: b"curves\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"f\0" as *const u8 as *const libc::c_char,
            lname: b"fail\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"fa\0" as *const u8 as *const libc::c_char,
            lname: b"fail-early\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"fb\0" as *const u8 as *const libc::c_char,
            lname: b"styled-output\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"fc\0" as *const u8 as *const libc::c_char,
            lname: b"mail-rcpt-allowfails\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"fd\0" as *const u8 as *const libc::c_char,
            lname: b"fail-with-body\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"F\0" as *const u8 as *const libc::c_char,
            lname: b"form\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Fs\0" as *const u8 as *const libc::c_char,
            lname: b"form-string\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"g\0" as *const u8 as *const libc::c_char,
            lname: b"globoff\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"G\0" as *const u8 as *const libc::c_char,
            lname: b"get\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ga\0" as *const u8 as *const libc::c_char,
            lname: b"request-target\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"h\0" as *const u8 as *const libc::c_char,
            lname: b"help\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"H\0" as *const u8 as *const libc::c_char,
            lname: b"header\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Hp\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-header\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"i\0" as *const u8 as *const libc::c_char,
            lname: b"include\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"I\0" as *const u8 as *const libc::c_char,
            lname: b"head\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"j\0" as *const u8 as *const libc::c_char,
            lname: b"junk-session-cookies\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"J\0" as *const u8 as *const libc::c_char,
            lname: b"remote-header-name\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"k\0" as *const u8 as *const libc::c_char,
            lname: b"insecure\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"kd\0" as *const u8 as *const libc::c_char,
            lname: b"doh-insecure\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"K\0" as *const u8 as *const libc::c_char,
            lname: b"config\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"l\0" as *const u8 as *const libc::c_char,
            lname: b"list-only\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"L\0" as *const u8 as *const libc::c_char,
            lname: b"location\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Lt\0" as *const u8 as *const libc::c_char,
            lname: b"location-trusted\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"m\0" as *const u8 as *const libc::c_char,
            lname: b"max-time\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"M\0" as *const u8 as *const libc::c_char,
            lname: b"manual\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"n\0" as *const u8 as *const libc::c_char,
            lname: b"netrc\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"no\0" as *const u8 as *const libc::c_char,
            lname: b"netrc-optional\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"ne\0" as *const u8 as *const libc::c_char,
            lname: b"netrc-file\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"N\0" as *const u8 as *const libc::c_char,
            lname: b"buffer\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"o\0" as *const u8 as *const libc::c_char,
            lname: b"output\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"O\0" as *const u8 as *const libc::c_char,
            lname: b"remote-name\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Oa\0" as *const u8 as *const libc::c_char,
            lname: b"remote-name-all\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ob\0" as *const u8 as *const libc::c_char,
            lname: b"output-dir\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"p\0" as *const u8 as *const libc::c_char,
            lname: b"proxytunnel\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"P\0" as *const u8 as *const libc::c_char,
            lname: b"ftp-port\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"q\0" as *const u8 as *const libc::c_char,
            lname: b"disable\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Q\0" as *const u8 as *const libc::c_char,
            lname: b"quote\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"r\0" as *const u8 as *const libc::c_char,
            lname: b"range\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"R\0" as *const u8 as *const libc::c_char,
            lname: b"remote-time\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"s\0" as *const u8 as *const libc::c_char,
            lname: b"silent\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"S\0" as *const u8 as *const libc::c_char,
            lname: b"show-error\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"t\0" as *const u8 as *const libc::c_char,
            lname: b"telnet-option\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"T\0" as *const u8 as *const libc::c_char,
            lname: b"upload-file\0" as *const u8 as *const libc::c_char,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"u\0" as *const u8 as *const libc::c_char,
            lname: b"user\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"U\0" as *const u8 as *const libc::c_char,
            lname: b"proxy-user\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"v\0" as *const u8 as *const libc::c_char,
            lname: b"verbose\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"V\0" as *const u8 as *const libc::c_char,
            lname: b"version\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"w\0" as *const u8 as *const libc::c_char,
            lname: b"write-out\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"x\0" as *const u8 as *const libc::c_char,
            lname: b"proxy\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"xa\0" as *const u8 as *const libc::c_char,
            lname: b"preproxy\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"X\0" as *const u8 as *const libc::c_char,
            lname: b"request\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Y\0" as *const u8 as *const libc::c_char,
            lname: b"speed-limit\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"y\0" as *const u8 as *const libc::c_char,
            lname: b"speed-time\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"z\0" as *const u8 as *const libc::c_char,
            lname: b"time-cond\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Z\0" as *const u8 as *const libc::c_char,
            lname: b"parallel\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Zb\0" as *const u8 as *const libc::c_char,
            lname: b"parallel-max\0" as *const u8 as *const libc::c_char,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Zc\0" as *const u8 as *const libc::c_char,
            lname: b"parallel-immediate\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"#\0" as *const u8 as *const libc::c_char,
            lname: b"progress-bar\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"#m\0" as *const u8 as *const libc::c_char,
            lname: b"progress-meter\0" as *const u8 as *const libc::c_char,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b":\0" as *const u8 as *const libc::c_char,
            lname: b"next\0" as *const u8 as *const libc::c_char,
            desc: ARG_NONE,
        };
        init
    },
];
unsafe extern "C" fn parse_cert_parameter(
    mut cert_parameter: *const libc::c_char,
    mut certname: *mut *mut libc::c_char,
    mut passphrase: *mut *mut libc::c_char,
) {
    let mut param_length: size_t = strlen(cert_parameter);
    let mut span: size_t = 0;
    let mut param_place: *const libc::c_char = 0 as *const libc::c_char;
    let mut certname_place: *mut libc::c_char = 0 as *mut libc::c_char;
    *certname = 0 as *mut libc::c_char;
    *passphrase = 0 as *mut libc::c_char;
    if param_length == 0 as libc::c_int as libc::c_ulong {
        return;
    }
    if curl_strnequal(
        cert_parameter,
        b"pkcs11:\0" as *const u8 as *const libc::c_char,
        7 as libc::c_int as size_t,
    ) != 0
        || (strpbrk(cert_parameter, b":\\\0" as *const u8 as *const libc::c_char))
            .is_null()
    {
        *certname = strdup(cert_parameter);
        return;
    }
    certname_place = malloc(param_length.wrapping_add(1 as libc::c_int as libc::c_ulong))
        as *mut libc::c_char;
    if certname_place.is_null() {
        return;
    }
    *certname = certname_place;
    param_place = cert_parameter;
    while *param_place != 0 {
        span = strcspn(param_place, b":\\\0" as *const u8 as *const libc::c_char);
        strncpy(certname_place, param_place, span);
        param_place = param_place.offset(span as isize);
        certname_place = certname_place.offset(span as isize);
        match *param_place as libc::c_int {
            92 => {
                param_place = param_place.offset(1);
                match *param_place as libc::c_int {
                    0 => {
                        let fresh0 = certname_place;
                        certname_place = certname_place.offset(1);
                        *fresh0 = '\\' as i32 as libc::c_char;
                    }
                    92 => {
                        let fresh1 = certname_place;
                        certname_place = certname_place.offset(1);
                        *fresh1 = '\\' as i32 as libc::c_char;
                        param_place = param_place.offset(1);
                    }
                    58 => {
                        let fresh2 = certname_place;
                        certname_place = certname_place.offset(1);
                        *fresh2 = ':' as i32 as libc::c_char;
                        param_place = param_place.offset(1);
                    }
                    _ => {
                        let fresh3 = certname_place;
                        certname_place = certname_place.offset(1);
                        *fresh3 = '\\' as i32 as libc::c_char;
                        let fresh4 = certname_place;
                        certname_place = certname_place.offset(1);
                        *fresh4 = *param_place;
                        param_place = param_place.offset(1);
                    }
                }
            }
            58 => {
                param_place = param_place.offset(1);
                if *param_place != 0 {
                    *passphrase = strdup(param_place);
                }
                break;
            }
            0 | _ => {}
        }
    }
    *certname_place = '\u{0}' as i32 as libc::c_char;
}
unsafe extern "C" fn replace_url_encoded_space_by_plus(
    mut url: *mut libc::c_char,
) -> size_t {
    let mut orig_len: size_t = strlen(url);
    let mut orig_index: size_t = 0 as libc::c_int as size_t;
    let mut new_index: size_t = 0 as libc::c_int as size_t;
    while orig_index < orig_len {
        if *url.offset(orig_index as isize) as libc::c_int == '%' as i32
            && *url
                .offset(
                    orig_index.wrapping_add(1 as libc::c_int as libc::c_ulong) as isize,
                ) as libc::c_int == '2' as i32
            && *url
                .offset(
                    orig_index.wrapping_add(2 as libc::c_int as libc::c_ulong) as isize,
                ) as libc::c_int == '0' as i32
        {
            *url.offset(new_index as isize) = '+' as i32 as libc::c_char;
            orig_index = (orig_index as libc::c_ulong)
                .wrapping_add(3 as libc::c_int as libc::c_ulong) as size_t as size_t;
        } else {
            if new_index != orig_index {
                *url.offset(new_index as isize) = *url.offset(orig_index as isize);
            }
            orig_index = orig_index.wrapping_add(1);
        }
        new_index = new_index.wrapping_add(1);
    }
    *url.offset(new_index as isize) = 0 as libc::c_int as libc::c_char;
    return new_index;
}
unsafe extern "C" fn GetFileAndPassword(
    mut nextarg: *mut libc::c_char,
    mut file: *mut *mut libc::c_char,
    mut password: *mut *mut libc::c_char,
) {
    let mut certname: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut passphrase: *mut libc::c_char = 0 as *mut libc::c_char;
    parse_cert_parameter(nextarg, &mut certname, &mut passphrase);
    free(*file as *mut libc::c_void);
    *file = 0 as *mut libc::c_char;
    *file = certname;
    if !passphrase.is_null() {
        free(*password as *mut libc::c_void);
        *password = 0 as *mut libc::c_char;
        *password = passphrase;
    }
    cleanarg(nextarg);
}
unsafe extern "C" fn GetSizeParameter(
    mut global: *mut GlobalConfig,
    mut arg: *const libc::c_char,
    mut which: *const libc::c_char,
    mut value_out: *mut curl_off_t,
) -> ParameterError {
    let mut unit: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut value: curl_off_t = 0;
    if curlx_strtoofft(arg, &mut unit, 0 as libc::c_int, &mut value) as u64 != 0 {
        warnf(
            global,
            b"invalid number specified for %s\n\0" as *const u8 as *const libc::c_char,
            which,
        );
        return PARAM_BAD_USE;
    }
    if *unit == 0 {
        unit = b"b\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    } else if strlen(unit) > 1 as libc::c_int as libc::c_ulong {
        unit = b"w\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    match *unit as libc::c_int {
        71 | 103 => {
            if value
                > 0x7fffffffffffffff as libc::c_long
                    / (1024 as libc::c_int * 1024 as libc::c_int * 1024 as libc::c_int)
                        as libc::c_long
            {
                return PARAM_NUMBER_TOO_LARGE;
            }
            value
                *= (1024 as libc::c_int * 1024 as libc::c_int * 1024 as libc::c_int)
                    as libc::c_long;
        }
        77 | 109 => {
            if value
                > 0x7fffffffffffffff as libc::c_long
                    / (1024 as libc::c_int * 1024 as libc::c_int) as libc::c_long
            {
                return PARAM_NUMBER_TOO_LARGE;
            }
            value *= (1024 as libc::c_int * 1024 as libc::c_int) as libc::c_long;
        }
        75 | 107 => {
            if value
                > 0x7fffffffffffffff as libc::c_long
                    / 1024 as libc::c_int as libc::c_long
            {
                return PARAM_NUMBER_TOO_LARGE;
            }
            value *= 1024 as libc::c_int as libc::c_long;
        }
        98 | 66 => {}
        _ => {
            warnf(
                global,
                b"unsupported %s unit. Use G, M, K or B!\n\0" as *const u8
                    as *const libc::c_char,
                which,
            );
            return PARAM_BAD_USE;
        }
    }
    *value_out = value;
    return PARAM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn getparameter(
    mut flag: *const libc::c_char,
    mut nextarg: *mut libc::c_char,
    mut usedarg: *mut bool,
    mut global: *mut GlobalConfig,
    mut config: *mut OperationConfig,
) -> ParameterError {
    let mut letter: libc::c_char = 0;
    let mut subletter: libc::c_char = '\u{0}' as i32 as libc::c_char;
    let mut rc: libc::c_int = 0;
    let mut parse: *const libc::c_char = 0 as *const libc::c_char;
    let mut j: libc::c_uint = 0;
    let mut now: time_t = 0;
    let mut hit: libc::c_int = -(1 as libc::c_int);
    let mut longopt: bool = 0 as libc::c_int != 0;
    let mut singleopt: bool = 0 as libc::c_int != 0;
    let mut err: ParameterError = PARAM_OK;
    let mut toggle: bool = 1 as libc::c_int != 0;
    *usedarg = 0 as libc::c_int != 0;
    if '-' as i32 != *flag.offset(0 as libc::c_int as isize) as libc::c_int
        || '-' as i32 == *flag.offset(1 as libc::c_int as isize) as libc::c_int
    {
        let mut word: *const libc::c_char = if '-' as i32
            == *flag.offset(0 as libc::c_int as isize) as libc::c_int
        {
            flag.offset(2 as libc::c_int as isize)
        } else {
            flag
        };
        let mut fnam: size_t = strlen(word);
        let mut numhits: libc::c_int = 0 as libc::c_int;
        let mut noflagged: bool = 0 as libc::c_int != 0;
        if strncmp(
            word,
            b"no-\0" as *const u8 as *const libc::c_char,
            3 as libc::c_int as libc::c_ulong,
        ) == 0
        {
            word = word.offset(3 as libc::c_int as isize);
            toggle = 0 as libc::c_int != 0;
            noflagged = 1 as libc::c_int != 0;
        }
        j = 0 as libc::c_int as libc::c_uint;
        while (j as libc::c_ulong)
            < (::std::mem::size_of::<[LongShort; 248]>() as libc::c_ulong)
                .wrapping_div(::std::mem::size_of::<LongShort>() as libc::c_ulong)
        {
            if curl_strnequal(aliases[j as usize].lname, word, fnam) != 0 {
                longopt = 1 as libc::c_int != 0;
                numhits += 1;
                if curl_strequal(aliases[j as usize].lname, word) != 0 {
                    parse = aliases[j as usize].letter;
                    hit = j as libc::c_int;
                    numhits = 1 as libc::c_int;
                    break;
                } else {
                    parse = aliases[j as usize].letter;
                    hit = j as libc::c_int;
                }
            }
            j = j.wrapping_add(1);
        }
        if numhits > 1 as libc::c_int {
            return PARAM_OPTION_AMBIGUOUS;
        }
        if hit < 0 as libc::c_int {
            return PARAM_OPTION_UNKNOWN;
        }
        if noflagged as libc::c_int != 0
            && aliases[hit as usize].desc as libc::c_uint
                != ARG_BOOL as libc::c_int as libc::c_uint
        {
            return PARAM_NO_NOT_BOOLEAN;
        }
    } else {
        flag = flag.offset(1);
        hit = -(1 as libc::c_int);
        parse = flag;
    }
    loop {
        if !longopt {
            letter = *parse;
            subletter = '\u{0}' as i32 as libc::c_char;
        } else {
            letter = *parse.offset(0 as libc::c_int as isize);
            subletter = *parse.offset(1 as libc::c_int as isize);
        }
        if hit < 0 as libc::c_int {
            j = 0 as libc::c_int as libc::c_uint;
            while (j as libc::c_ulong)
                < (::std::mem::size_of::<[LongShort; 248]>() as libc::c_ulong)
                    .wrapping_div(::std::mem::size_of::<LongShort>() as libc::c_ulong)
            {
                if letter as libc::c_int
                    == *(aliases[j as usize].letter).offset(0 as libc::c_int as isize)
                        as libc::c_int
                {
                    hit = j as libc::c_int;
                    break;
                } else {
                    j = j.wrapping_add(1);
                }
            }
            if hit < 0 as libc::c_int {
                return PARAM_OPTION_UNKNOWN;
            }
        }
        if aliases[hit as usize].desc as libc::c_uint
            >= ARG_STRING as libc::c_int as libc::c_uint
        {
            if !longopt && *parse.offset(1 as libc::c_int as isize) as libc::c_int != 0 {
                nextarg = &*parse.offset(1 as libc::c_int as isize)
                    as *const libc::c_char as *mut libc::c_char;
                singleopt = 1 as libc::c_int != 0;
            } else if nextarg.is_null() {
                return PARAM_REQUIRES_PARAMETER
            } else {
                *usedarg = 1 as libc::c_int != 0;
            }
            if aliases[hit as usize].desc as libc::c_uint
                == ARG_FILENAME as libc::c_int as libc::c_uint
                && *nextarg.offset(0 as libc::c_int as isize) as libc::c_int
                    == '-' as i32
                && *nextarg.offset(1 as libc::c_int as isize) as libc::c_int != 0
            {
                warnf(
                    global,
                    b"The file name argument '%s' looks like a flag.\n\0" as *const u8
                        as *const libc::c_char,
                    nextarg,
                );
            }
        } else if aliases[hit as usize].desc as libc::c_uint
                == ARG_NONE as libc::c_int as libc::c_uint && !toggle
            {
            return PARAM_NO_PREFIX
        }
        let mut current_block_1664: u64;
        match letter as libc::c_int {
            42 => {
                match subletter as libc::c_int {
                    52 => {
                        if !((*config).dns_ipv4_addr).is_null() {
                            free((*config).dns_ipv4_addr as *mut libc::c_void);
                            let ref mut fresh5 = (*config).dns_ipv4_addr;
                            *fresh5 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh6 = (*config).dns_ipv4_addr;
                            *fresh6 = strdup(nextarg);
                            if ((*config).dns_ipv4_addr).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    54 => {
                        if !((*config).dns_ipv6_addr).is_null() {
                            free((*config).dns_ipv6_addr as *mut libc::c_void);
                            let ref mut fresh7 = (*config).dns_ipv6_addr;
                            *fresh7 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh8 = (*config).dns_ipv6_addr;
                            *fresh8 = strdup(nextarg);
                            if ((*config).dns_ipv6_addr).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    97 => {
                        if !((*config).random_file).is_null() {
                            free((*config).random_file as *mut libc::c_void);
                            let ref mut fresh9 = (*config).random_file;
                            *fresh9 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh10 = (*config).random_file;
                            *fresh10 = strdup(nextarg);
                            if ((*config).random_file).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    98 => {
                        if !((*config).egd_file).is_null() {
                            free((*config).egd_file as *mut libc::c_void);
                            let ref mut fresh11 = (*config).egd_file;
                            *fresh11 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh12 = (*config).egd_file;
                            *fresh12 = strdup(nextarg);
                            if ((*config).egd_file).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    66 => {
                        if !((*config).oauth_bearer).is_null() {
                            free((*config).oauth_bearer as *mut libc::c_void);
                            let ref mut fresh13 = (*config).oauth_bearer;
                            *fresh13 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh14 = (*config).oauth_bearer;
                            *fresh14 = strdup(nextarg);
                            if ((*config).oauth_bearer).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        (*config).authtype
                            |= (1 as libc::c_int as libc::c_ulong) << 6 as libc::c_int;
                    }
                    99 => {
                        err = str2udouble(
                            &mut (*config).connecttimeout,
                            nextarg,
                            9223372036854775807 as libc::c_long
                                / 1000 as libc::c_int as libc::c_long,
                        );
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    67 => {
                        if !((*config).doh_url).is_null() {
                            free((*config).doh_url as *mut libc::c_void);
                            let ref mut fresh15 = (*config).doh_url;
                            *fresh15 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh16 = (*config).doh_url;
                            *fresh16 = strdup(nextarg);
                            if ((*config).doh_url).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    100 => {
                        if !((*config).cipher_list).is_null() {
                            free((*config).cipher_list as *mut libc::c_void);
                            let ref mut fresh17 = (*config).cipher_list;
                            *fresh17 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh18 = (*config).cipher_list;
                            *fresh18 = strdup(nextarg);
                            if ((*config).cipher_list).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    68 => {
                        if !((*config).dns_interface).is_null() {
                            free((*config).dns_interface as *mut libc::c_void);
                            let ref mut fresh19 = (*config).dns_interface;
                            *fresh19 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh20 = (*config).dns_interface;
                            *fresh20 = strdup(nextarg);
                            if ((*config).dns_interface).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    101 => {
                        (*config).disable_epsv = toggle;
                    }
                    102 => {
                        (*config).disallow_username_in_url = toggle;
                    }
                    69 => {
                        (*config)
                            .disable_epsv = if !toggle {
                            1 as libc::c_int
                        } else {
                            0 as libc::c_int
                        } != 0;
                    }
                    70 => {
                        if !((*config).dns_servers).is_null() {
                            free((*config).dns_servers as *mut libc::c_void);
                            let ref mut fresh21 = (*config).dns_servers;
                            *fresh21 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh22 = (*config).dns_servers;
                            *fresh22 = strdup(nextarg);
                            if ((*config).dns_servers).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    103 => {
                        if !((*global).trace_dump).is_null() {
                            free((*global).trace_dump as *mut libc::c_void);
                            let ref mut fresh23 = (*global).trace_dump;
                            *fresh23 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh24 = (*global).trace_dump;
                            *fresh24 = strdup(nextarg);
                            if ((*global).trace_dump).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        if (*global).tracetype as libc::c_uint != 0
                            && (*global).tracetype as libc::c_uint
                                != TRACE_BIN as libc::c_int as libc::c_uint
                        {
                            warnf(
                                global,
                                b"--trace overrides an earlier trace/verbose option\n\0"
                                    as *const u8 as *const libc::c_char,
                            );
                        }
                        (*global).tracetype = TRACE_BIN;
                    }
                    71 => {
                        (*config)
                            .nonpn = if !toggle {
                            1 as libc::c_int
                        } else {
                            0 as libc::c_int
                        } != 0;
                    }
                    104 => {
                        if !((*global).trace_dump).is_null() {
                            free((*global).trace_dump as *mut libc::c_void);
                            let ref mut fresh25 = (*global).trace_dump;
                            *fresh25 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh26 = (*global).trace_dump;
                            *fresh26 = strdup(nextarg);
                            if ((*global).trace_dump).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        if (*global).tracetype as libc::c_uint != 0
                            && (*global).tracetype as libc::c_uint
                                != TRACE_ASCII as libc::c_int as libc::c_uint
                        {
                            warnf(
                                global,
                                b"--trace-ascii overrides an earlier trace/verbose option\n\0"
                                    as *const u8 as *const libc::c_char,
                            );
                        }
                        (*global).tracetype = TRACE_ASCII;
                    }
                    72 => {
                        (*config)
                            .noalpn = if !toggle {
                            1 as libc::c_int
                        } else {
                            0 as libc::c_int
                        } != 0;
                    }
                    105 => {
                        let mut value: curl_off_t = 0;
                        let mut pe: ParameterError = GetSizeParameter(
                            global,
                            nextarg,
                            b"rate\0" as *const u8 as *const libc::c_char,
                            &mut value,
                        );
                        if pe as libc::c_uint != PARAM_OK as libc::c_int as libc::c_uint
                        {
                            return pe;
                        }
                        (*config).recvpersecond = value;
                        (*config).sendpersecond = value;
                    }
                    106 => {
                        if toggle as libc::c_int != 0
                            && (*curlinfo).features
                                & ((1 as libc::c_int) << 3 as libc::c_int
                                    | (1 as libc::c_int) << 23 as libc::c_int
                                    | (1 as libc::c_int) << 26 as libc::c_int) == 0
                        {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                        (*config).encoding = toggle;
                    }
                    74 => {
                        (*config).tr_encoding = toggle;
                    }
                    107 => {
                        if toggle {
                            (*config).authtype
                                |= (1 as libc::c_int as libc::c_ulong) << 1 as libc::c_int;
                        } else {
                            (*config).authtype
                                &= !((1 as libc::c_int as libc::c_ulong)
                                    << 1 as libc::c_int);
                        }
                    }
                    108 => {
                        if toggle {
                            if (*curlinfo).features
                                & (1 as libc::c_int) << 8 as libc::c_int != 0
                            {
                                (*config).authtype
                                    |= (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int;
                            } else {
                                return PARAM_LIBCURL_DOESNT_SUPPORT
                            }
                        } else {
                            (*config).authtype
                                &= !((1 as libc::c_int as libc::c_ulong)
                                    << 2 as libc::c_int);
                        }
                    }
                    109 => {
                        if toggle {
                            if (*curlinfo).features
                                & (1 as libc::c_int) << 4 as libc::c_int != 0
                            {
                                (*config).authtype
                                    |= (1 as libc::c_int as libc::c_ulong) << 3 as libc::c_int;
                            } else {
                                return PARAM_LIBCURL_DOESNT_SUPPORT
                            }
                        } else {
                            (*config).authtype
                                &= !((1 as libc::c_int as libc::c_ulong)
                                    << 3 as libc::c_int);
                        }
                    }
                    77 => {
                        if toggle {
                            if (*curlinfo).features
                                & (1 as libc::c_int) << 15 as libc::c_int != 0
                            {
                                (*config).authtype
                                    |= (1 as libc::c_int as libc::c_ulong) << 5 as libc::c_int;
                            } else {
                                return PARAM_LIBCURL_DOESNT_SUPPORT
                            }
                        } else {
                            (*config).authtype
                                &= !((1 as libc::c_int as libc::c_ulong)
                                    << 5 as libc::c_int);
                        }
                    }
                    110 => {
                        if toggle {
                            (*config).authtype
                                |= (1 as libc::c_int as libc::c_ulong) << 0 as libc::c_int;
                        } else {
                            (*config).authtype
                                &= !((1 as libc::c_int as libc::c_ulong)
                                    << 0 as libc::c_int);
                        }
                    }
                    111 => {
                        if toggle {
                            (*config)
                                .authtype = !((1 as libc::c_int as libc::c_ulong)
                                << 4 as libc::c_int);
                        }
                    }
                    113 => {
                        (*config).ftp_create_dirs = toggle;
                    }
                    114 => {
                        (*config).create_dirs = toggle;
                    }
                    82 => {
                        err = oct2nummax(
                            &mut (*config).create_file_mode,
                            nextarg,
                            0o777 as libc::c_int as libc::c_long,
                        );
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    115 => {
                        err = str2num(&mut (*config).maxredirs, nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                        if (*config).maxredirs < -(1 as libc::c_int) as libc::c_long {
                            return PARAM_BAD_NUMERIC;
                        }
                    }
                    116 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 4 as libc::c_int
                            != 0
                        {
                            (*config).proxyntlm = toggle;
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT
                        }
                    }
                    117 => {
                        (*config).crlf = toggle;
                    }
                    86 => {
                        (*config).authtype
                            |= (1 as libc::c_int as libc::c_ulong) << 7 as libc::c_int;
                        if !((*config).aws_sigv4).is_null() {
                            free((*config).aws_sigv4 as *mut libc::c_void);
                            let ref mut fresh27 = (*config).aws_sigv4;
                            *fresh27 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh28 = (*config).aws_sigv4;
                            *fresh28 = strdup(nextarg);
                            if ((*config).aws_sigv4).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    118 => {
                        if strcmp(nextarg, b"-\0" as *const u8 as *const libc::c_char)
                            != 0
                        {
                            let mut newfile: *mut FILE = fopen(
                                nextarg,
                                b"w\0" as *const u8 as *const libc::c_char,
                            );
                            if newfile.is_null() {
                                warnf(
                                    global,
                                    b"Failed to open %s!\n\0" as *const u8
                                        as *const libc::c_char,
                                    nextarg,
                                );
                            } else {
                                if (*global).errors_fopened {
                                    fclose((*global).errors);
                                }
                                let ref mut fresh29 = (*global).errors;
                                *fresh29 = newfile;
                                (*global).errors_fopened = 1 as libc::c_int != 0;
                            }
                        } else {
                            let ref mut fresh30 = (*global).errors;
                            *fresh30 = stdout;
                        }
                    }
                    119 => {
                        if !((*config).iface).is_null() {
                            free((*config).iface as *mut libc::c_void);
                            let ref mut fresh31 = (*config).iface;
                            *fresh31 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh32 = (*config).iface;
                            *fresh32 = strdup(nextarg);
                            if ((*config).iface).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    120 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 8 as libc::c_int
                            != 0
                        {
                            if !((*config).krblevel).is_null() {
                                free((*config).krblevel as *mut libc::c_void);
                                let ref mut fresh33 = (*config).krblevel;
                                *fresh33 = 0 as *mut libc::c_char;
                            }
                            if !nextarg.is_null() {
                                let ref mut fresh34 = (*config).krblevel;
                                *fresh34 = strdup(nextarg);
                                if ((*config).krblevel).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT
                        }
                    }
                    88 => {
                        (*config).haproxy_protocol = toggle;
                    }
                    121 => {
                        let mut value_0: curl_off_t = 0;
                        let mut pe_0: ParameterError = GetSizeParameter(
                            global,
                            nextarg,
                            b"max-filesize\0" as *const u8 as *const libc::c_char,
                            &mut value_0,
                        );
                        if pe_0 as libc::c_uint
                            != PARAM_OK as libc::c_int as libc::c_uint
                        {
                            return pe_0;
                        }
                        (*config).max_filesize = value_0;
                    }
                    122 => {
                        (*config).disable_eprt = toggle;
                    }
                    90 => {
                        (*config)
                            .disable_eprt = if !toggle {
                            1 as libc::c_int
                        } else {
                            0 as libc::c_int
                        } != 0;
                    }
                    126 => {
                        (*config).xattr = toggle;
                    }
                    64 => {
                        let mut url: *mut getout = 0 as *mut getout;
                        if ((*config).url_get).is_null() {
                            let ref mut fresh35 = (*config).url_get;
                            *fresh35 = (*config).url_list;
                        }
                        if !((*config).url_get).is_null() {
                            while !((*config).url_get).is_null()
                                && (*(*config).url_get).flags
                                    & (1 as libc::c_int) << 1 as libc::c_int != 0
                            {
                                let ref mut fresh36 = (*config).url_get;
                                *fresh36 = (*(*config).url_get).next;
                            }
                        }
                        if !((*config).url_get).is_null() {
                            url = (*config).url_get;
                        } else {
                            url = new_getout(config);
                            let ref mut fresh37 = (*config).url_get;
                            *fresh37 = url;
                        }
                        if url.is_null() {
                            return PARAM_NO_MEM;
                        }
                        if !((*url).url).is_null() {
                            free((*url).url as *mut libc::c_void);
                            let ref mut fresh38 = (*url).url;
                            *fresh38 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh39 = (*url).url;
                            *fresh39 = strdup(nextarg);
                            if ((*url).url).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        (*url).flags |= (1 as libc::c_int) << 1 as libc::c_int;
                    }
                    _ => {}
                }
                current_block_1664 = 2210884902194999453;
            }
            36 => {
                match subletter as libc::c_int {
                    97 => {
                        if toggle as libc::c_int != 0
                            && (*curlinfo).features
                                & (1 as libc::c_int) << 2 as libc::c_int == 0
                        {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                        (*config).ftp_ssl = toggle;
                    }
                    98 => {
                        free((*config).ftpport as *mut libc::c_void);
                        let ref mut fresh40 = (*config).ftpport;
                        *fresh40 = 0 as *mut libc::c_char;
                    }
                    99 => {
                        if !((*config).proxy).is_null() {
                            free((*config).proxy as *mut libc::c_void);
                            let ref mut fresh41 = (*config).proxy;
                            *fresh41 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh42 = (*config).proxy;
                            *fresh42 = strdup(nextarg);
                            if ((*config).proxy).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        (*config).proxyver = CURLPROXY_SOCKS5 as libc::c_int;
                    }
                    116 => {
                        if !((*config).proxy).is_null() {
                            free((*config).proxy as *mut libc::c_void);
                            let ref mut fresh43 = (*config).proxy;
                            *fresh43 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh44 = (*config).proxy;
                            *fresh44 = strdup(nextarg);
                            if ((*config).proxy).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        (*config).proxyver = CURLPROXY_SOCKS4 as libc::c_int;
                    }
                    84 => {
                        if !((*config).proxy).is_null() {
                            free((*config).proxy as *mut libc::c_void);
                            let ref mut fresh45 = (*config).proxy;
                            *fresh45 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh46 = (*config).proxy;
                            *fresh46 = strdup(nextarg);
                            if ((*config).proxy).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        (*config).proxyver = CURLPROXY_SOCKS4A as libc::c_int;
                    }
                    50 => {
                        if !((*config).proxy).is_null() {
                            free((*config).proxy as *mut libc::c_void);
                            let ref mut fresh47 = (*config).proxy;
                            *fresh47 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh48 = (*config).proxy;
                            *fresh48 = strdup(nextarg);
                            if ((*config).proxy).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        (*config).proxyver = CURLPROXY_SOCKS5_HOSTNAME as libc::c_int;
                    }
                    100 => {
                        (*config).tcp_nodelay = toggle;
                    }
                    101 => {
                        (*config).proxydigest = toggle;
                    }
                    102 => {
                        (*config).proxybasic = toggle;
                    }
                    103 => {
                        err = str2unum(&mut (*config).req_retry, nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    86 => {
                        (*config).retry_connrefused = toggle;
                    }
                    104 => {
                        err = str2unummax(
                            &mut (*config).retry_delay,
                            nextarg,
                            9223372036854775807 as libc::c_long
                                / 1000 as libc::c_int as libc::c_long,
                        );
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    105 => {
                        err = str2unummax(
                            &mut (*config).retry_maxtime,
                            nextarg,
                            9223372036854775807 as libc::c_long
                                / 1000 as libc::c_int as libc::c_long,
                        );
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    33 => {
                        (*config).retry_all_errors = toggle;
                    }
                    107 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 8 as libc::c_int
                            != 0
                        {
                            (*config).proxynegotiate = toggle;
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT
                        }
                    }
                    109 => {
                        if !((*config).ftp_account).is_null() {
                            free((*config).ftp_account as *mut libc::c_void);
                            let ref mut fresh49 = (*config).ftp_account;
                            *fresh49 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh50 = (*config).ftp_account;
                            *fresh50 = strdup(nextarg);
                            if ((*config).ftp_account).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    110 => {
                        (*config).proxyanyauth = toggle;
                    }
                    111 => {
                        (*global).tracetime = toggle;
                    }
                    112 => {
                        (*config).ignorecl = toggle;
                    }
                    113 => {
                        (*config).ftp_skip_ip = toggle;
                    }
                    114 => {
                        (*config).ftp_filemethod = ftpfilemethod(config, nextarg);
                    }
                    115 => {
                        let mut lrange: [libc::c_char; 7] = *::std::mem::transmute::<
                            &[u8; 7],
                            &mut [libc::c_char; 7],
                        >(b"\0\0\0\0\0\0\0");
                        let mut p: *mut libc::c_char = nextarg;
                        while Curl_isdigit(*p as libc::c_uchar as libc::c_int) != 0 {
                            p = p.offset(1);
                        }
                        if *p != 0 {
                            rc = sscanf(
                                p,
                                b" - %6s\0" as *const u8 as *const libc::c_char,
                                lrange.as_mut_ptr(),
                            );
                            *p = 0 as libc::c_int as libc::c_char;
                        } else {
                            rc = 0 as libc::c_int;
                        }
                        err = str2unum(&mut (*config).localport, nextarg);
                        if err as libc::c_uint != 0
                            || (*config).localport > 65535 as libc::c_int as libc::c_long
                        {
                            return PARAM_BAD_USE;
                        }
                        if rc == 0 {
                            (*config).localportrange = 1 as libc::c_int as libc::c_long;
                        } else {
                            err = str2unum(
                                &mut (*config).localportrange,
                                lrange.as_mut_ptr(),
                            );
                            if err as libc::c_uint != 0
                                || (*config).localportrange
                                    > 65535 as libc::c_int as libc::c_long
                            {
                                return PARAM_BAD_USE;
                            }
                            (*config).localportrange
                                -= (*config).localport - 1 as libc::c_int as libc::c_long;
                            if (*config).localportrange
                                < 1 as libc::c_int as libc::c_long
                            {
                                return PARAM_BAD_USE;
                            }
                        }
                    }
                    117 => {
                        if !((*config).ftp_alternative_to_user).is_null() {
                            free((*config).ftp_alternative_to_user as *mut libc::c_void);
                            let ref mut fresh51 = (*config).ftp_alternative_to_user;
                            *fresh51 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh52 = (*config).ftp_alternative_to_user;
                            *fresh52 = strdup(nextarg);
                            if ((*config).ftp_alternative_to_user).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    118 => {
                        if toggle as libc::c_int != 0
                            && (*curlinfo).features
                                & (1 as libc::c_int) << 2 as libc::c_int == 0
                        {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                        (*config).ftp_ssl_reqd = toggle;
                    }
                    119 => {
                        (*config)
                            .disable_sessionid = if !toggle {
                            1 as libc::c_int
                        } else {
                            0 as libc::c_int
                        } != 0;
                    }
                    120 => {
                        if toggle as libc::c_int != 0
                            && (*curlinfo).features
                                & (1 as libc::c_int) << 2 as libc::c_int == 0
                        {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                        (*config).ftp_ssl_control = toggle;
                    }
                    121 => {
                        (*config).ftp_ssl_ccc = toggle;
                        if (*config).ftp_ssl_ccc_mode == 0 {
                            (*config)
                                .ftp_ssl_ccc_mode = CURLFTPSSL_CCC_PASSIVE as libc::c_int;
                        }
                    }
                    106 => {
                        (*config).ftp_ssl_ccc = 1 as libc::c_int != 0;
                        (*config).ftp_ssl_ccc_mode = ftpcccmethod(config, nextarg);
                    }
                    122 => {
                        if !((*global).libcurl).is_null() {
                            free((*global).libcurl as *mut libc::c_void);
                            let ref mut fresh53 = (*global).libcurl;
                            *fresh53 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh54 = (*global).libcurl;
                            *fresh54 = strdup(nextarg);
                            if ((*global).libcurl).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    35 => {
                        (*config).raw = toggle;
                    }
                    48 => {
                        (*config).post301 = toggle;
                    }
                    49 => {
                        (*config)
                            .nokeepalive = if !toggle {
                            1 as libc::c_int
                        } else {
                            0 as libc::c_int
                        } != 0;
                    }
                    51 => {
                        err = str2unum(&mut (*config).alivetime, nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    52 => {
                        (*config).post302 = toggle;
                    }
                    73 => {
                        (*config).post303 = toggle;
                    }
                    53 => {
                        if !((*config).noproxy).is_null() {
                            free((*config).noproxy as *mut libc::c_void);
                            let ref mut fresh55 = (*config).noproxy;
                            *fresh55 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh56 = (*config).noproxy;
                            *fresh56 = strdup(nextarg);
                            if ((*config).noproxy).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    55 => {
                        (*config).socks5_gssapi_nec = toggle as libc::c_int;
                    }
                    56 => {
                        if !((*config).proxy).is_null() {
                            free((*config).proxy as *mut libc::c_void);
                            let ref mut fresh57 = (*config).proxy;
                            *fresh57 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh58 = (*config).proxy;
                            *fresh58 = strdup(nextarg);
                            if ((*config).proxy).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        (*config).proxyver = CURLPROXY_HTTP_1_0 as libc::c_int;
                    }
                    57 => {
                        err = str2unum(&mut (*config).tftp_blksize, nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    65 => {
                        if !((*config).mail_from).is_null() {
                            free((*config).mail_from as *mut libc::c_void);
                            let ref mut fresh59 = (*config).mail_from;
                            *fresh59 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh60 = (*config).mail_from;
                            *fresh60 = strdup(nextarg);
                            if ((*config).mail_from).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    66 => {
                        err = add2list(&mut (*config).mail_rcpt, nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    67 => {
                        (*config).ftp_pret = toggle;
                    }
                    68 => {
                        (*config).proto_present = 1 as libc::c_int != 0;
                        if proto2num(config, &mut (*config).proto, nextarg) != 0 {
                            return PARAM_BAD_USE;
                        }
                    }
                    69 => {
                        (*config).proto_redir_present = 1 as libc::c_int != 0;
                        if proto2num(config, &mut (*config).proto_redir, nextarg) != 0 {
                            return PARAM_BAD_USE;
                        }
                    }
                    70 => {
                        err = add2list(&mut (*config).resolve, nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    71 => {
                        (*config).gssapi_delegation = delegation(config, nextarg);
                    }
                    72 => {
                        if !((*config).mail_auth).is_null() {
                            free((*config).mail_auth as *mut libc::c_void);
                            let ref mut fresh61 = (*config).mail_auth;
                            *fresh61 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh62 = (*config).mail_auth;
                            *fresh62 = strdup(nextarg);
                            if ((*config).mail_auth).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    74 => {
                        errorf(
                            global,
                            b"--metalink is disabled\n\0" as *const u8
                                as *const libc::c_char,
                        );
                        return PARAM_BAD_USE;
                    }
                    54 => {
                        if !((*config).sasl_authzid).is_null() {
                            free((*config).sasl_authzid as *mut libc::c_void);
                            let ref mut fresh63 = (*config).sasl_authzid;
                            *fresh63 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh64 = (*config).sasl_authzid;
                            *fresh64 = strdup(nextarg);
                            if ((*config).sasl_authzid).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    75 => {
                        (*config).sasl_ir = toggle;
                    }
                    76 => {
                        warnf(
                            global,
                            b"--test-event is ignored unless a debug build!\n\0"
                                as *const u8 as *const libc::c_char,
                        );
                    }
                    77 => {
                        (*config).abstract_unix_socket = 0 as libc::c_int != 0;
                        if !((*config).unix_socket_path).is_null() {
                            free((*config).unix_socket_path as *mut libc::c_void);
                            let ref mut fresh65 = (*config).unix_socket_path;
                            *fresh65 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh66 = (*config).unix_socket_path;
                            *fresh66 = strdup(nextarg);
                            if ((*config).unix_socket_path).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    78 => {
                        (*config).path_as_is = toggle;
                    }
                    79 => {
                        if !((*config).proxy_service_name).is_null() {
                            free((*config).proxy_service_name as *mut libc::c_void);
                            let ref mut fresh67 = (*config).proxy_service_name;
                            *fresh67 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh68 = (*config).proxy_service_name;
                            *fresh68 = strdup(nextarg);
                            if ((*config).proxy_service_name).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    80 => {
                        if !((*config).service_name).is_null() {
                            free((*config).service_name as *mut libc::c_void);
                            let ref mut fresh69 = (*config).service_name;
                            *fresh69 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh70 = (*config).service_name;
                            *fresh70 = strdup(nextarg);
                            if ((*config).service_name).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    81 => {
                        if !((*config).proto_default).is_null() {
                            free((*config).proto_default as *mut libc::c_void);
                            let ref mut fresh71 = (*config).proto_default;
                            *fresh71 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh72 = (*config).proto_default;
                            *fresh72 = strdup(nextarg);
                            if ((*config).proto_default).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        err = check_protocol((*config).proto_default) as ParameterError;
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    82 => {
                        err = str2udouble(
                            &mut (*config).expect100timeout,
                            nextarg,
                            9223372036854775807 as libc::c_long
                                / 1000 as libc::c_int as libc::c_long,
                        );
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    83 => {
                        (*config).tftp_no_options = toggle;
                    }
                    85 => {
                        err = add2list(&mut (*config).connect_to, nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    87 => {
                        (*config).abstract_unix_socket = 1 as libc::c_int != 0;
                        if !((*config).unix_socket_path).is_null() {
                            free((*config).unix_socket_path as *mut libc::c_void);
                            let ref mut fresh73 = (*config).unix_socket_path;
                            *fresh73 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh74 = (*config).unix_socket_path;
                            *fresh74 = strdup(nextarg);
                            if ((*config).unix_socket_path).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    88 => {
                        err = str2tls_max(&mut (*config).ssl_version_max, nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    89 => {
                        (*config).suppress_connect_headers = toggle;
                    }
                    90 => {
                        (*config).ssh_compression = toggle;
                    }
                    126 => {
                        err = str2unum(
                            &mut (*config).happy_eyeballs_timeout_ms,
                            nextarg,
                        );
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    _ => {}
                }
                current_block_1664 = 2210884902194999453;
            }
            35 => {
                match subletter as libc::c_int {
                    109 => {
                        (*global).noprogress = !toggle;
                    }
                    _ => {
                        (*global)
                            .progressmode = if toggle as libc::c_int != 0 {
                            1 as libc::c_int
                        } else {
                            0 as libc::c_int
                        };
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            58 => return PARAM_NEXT_OPERATION,
            48 => {
                match subletter as libc::c_int {
                    0 => {
                        (*config)
                            .httpversion = CURL_HTTP_VERSION_1_0 as libc::c_int
                            as libc::c_long;
                    }
                    49 => {
                        (*config)
                            .httpversion = CURL_HTTP_VERSION_1_1 as libc::c_int
                            as libc::c_long;
                    }
                    50 => {
                        (*config)
                            .httpversion = CURL_HTTP_VERSION_2_0 as libc::c_int
                            as libc::c_long;
                    }
                    51 => {
                        (*config)
                            .httpversion = CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE
                            as libc::c_int as libc::c_long;
                    }
                    52 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 25 as libc::c_int
                            != 0
                        {
                            (*config)
                                .httpversion = CURL_HTTP_VERSION_3 as libc::c_int
                                as libc::c_long;
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT
                        }
                    }
                    57 => {
                        (*config).http09_allowed = toggle;
                    }
                    _ => {}
                }
                current_block_1664 = 2210884902194999453;
            }
            49 => {
                match subletter as libc::c_int {
                    0 => {
                        (*config)
                            .ssl_version = CURL_SSLVERSION_TLSv1 as libc::c_int
                            as libc::c_long;
                    }
                    48 => {
                        (*config)
                            .ssl_version = CURL_SSLVERSION_TLSv1_0 as libc::c_int
                            as libc::c_long;
                    }
                    49 => {
                        (*config)
                            .ssl_version = CURL_SSLVERSION_TLSv1_1 as libc::c_int
                            as libc::c_long;
                    }
                    50 => {
                        (*config)
                            .ssl_version = CURL_SSLVERSION_TLSv1_2 as libc::c_int
                            as libc::c_long;
                    }
                    51 => {
                        (*config)
                            .ssl_version = CURL_SSLVERSION_TLSv1_3 as libc::c_int
                            as libc::c_long;
                    }
                    65 => {
                        if !((*config).cipher13_list).is_null() {
                            free((*config).cipher13_list as *mut libc::c_void);
                            let ref mut fresh75 = (*config).cipher13_list;
                            *fresh75 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh76 = (*config).cipher13_list;
                            *fresh76 = strdup(nextarg);
                            if ((*config).cipher13_list).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    66 => {
                        if !((*config).proxy_cipher13_list).is_null() {
                            free((*config).proxy_cipher13_list as *mut libc::c_void);
                            let ref mut fresh77 = (*config).proxy_cipher13_list;
                            *fresh77 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh78 = (*config).proxy_cipher13_list;
                            *fresh78 = strdup(nextarg);
                            if ((*config).proxy_cipher13_list).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    _ => {}
                }
                current_block_1664 = 2210884902194999453;
            }
            50 => {
                warnf(
                    global,
                    b"Ignores instruction to use SSLv2\n\0" as *const u8
                        as *const libc::c_char,
                );
                current_block_1664 = 2210884902194999453;
            }
            51 => {
                warnf(
                    global,
                    b"Ignores instruction to use SSLv3\n\0" as *const u8
                        as *const libc::c_char,
                );
                current_block_1664 = 2210884902194999453;
            }
            52 => {
                (*config).ip_version = 1 as libc::c_int as libc::c_long;
                current_block_1664 = 2210884902194999453;
            }
            54 => {
                (*config).ip_version = 2 as libc::c_int as libc::c_long;
                current_block_1664 = 2210884902194999453;
            }
            97 => {
                (*config).ftp_append = toggle;
                current_block_1664 = 2210884902194999453;
            }
            65 => {
                if !((*config).useragent).is_null() {
                    free((*config).useragent as *mut libc::c_void);
                    let ref mut fresh79 = (*config).useragent;
                    *fresh79 = 0 as *mut libc::c_char;
                }
                if !nextarg.is_null() {
                    let ref mut fresh80 = (*config).useragent;
                    *fresh80 = strdup(nextarg);
                    if ((*config).useragent).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            98 => {
                let mut current_block_716: u64;
                match subletter as libc::c_int {
                    97 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 24 as libc::c_int
                            != 0
                        {
                            if !((*config).altsvc).is_null() {
                                free((*config).altsvc as *mut libc::c_void);
                                let ref mut fresh81 = (*config).altsvc;
                                *fresh81 = 0 as *mut libc::c_char;
                            }
                            if !nextarg.is_null() {
                                let ref mut fresh82 = (*config).altsvc;
                                *fresh82 = strdup(nextarg);
                                if ((*config).altsvc).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT
                        }
                    }
                    98 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 28 as libc::c_int
                            != 0
                        {
                            if !((*config).hsts).is_null() {
                                free((*config).hsts as *mut libc::c_void);
                                let ref mut fresh83 = (*config).hsts;
                                *fresh83 = 0 as *mut libc::c_char;
                            }
                            if !nextarg.is_null() {
                                let ref mut fresh84 = (*config).hsts;
                                *fresh84 = strdup(nextarg);
                                if ((*config).hsts).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT
                        }
                    }
                    _ => {
                        if *nextarg.offset(0 as libc::c_int as isize) as libc::c_int
                            == '@' as i32
                        {
                            nextarg = nextarg.offset(1);
                            current_block_716 = 17559505768186022594;
                        } else if !(strchr(nextarg, '=' as i32)).is_null() {
                            err = add2list(&mut (*config).cookies, nextarg);
                            if err as u64 != 0 {
                                return err;
                            }
                            current_block_716 = 9607877020798263770;
                        } else {
                            current_block_716 = 17559505768186022594;
                        }
                        match current_block_716 {
                            9607877020798263770 => {}
                            _ => {
                                err = add2list(&mut (*config).cookiefiles, nextarg);
                                if err as u64 != 0 {
                                    return err;
                                }
                            }
                        }
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            66 => {
                (*config).use_ascii = toggle;
                current_block_1664 = 2210884902194999453;
            }
            99 => {
                if !((*config).cookiejar).is_null() {
                    free((*config).cookiejar as *mut libc::c_void);
                    let ref mut fresh85 = (*config).cookiejar;
                    *fresh85 = 0 as *mut libc::c_char;
                }
                if !nextarg.is_null() {
                    let ref mut fresh86 = (*config).cookiejar;
                    *fresh86 = strdup(nextarg);
                    if ((*config).cookiejar).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            67 => {
                if strcmp(nextarg, b"-\0" as *const u8 as *const libc::c_char) != 0 {
                    err = str2offset(&mut (*config).resume_from, nextarg);
                    if err as u64 != 0 {
                        return err;
                    }
                    (*config).resume_from_current = 0 as libc::c_int != 0;
                } else {
                    (*config).resume_from_current = 1 as libc::c_int != 0;
                    (*config).resume_from = 0 as libc::c_int as curl_off_t;
                }
                (*config).use_resume = 1 as libc::c_int != 0;
                current_block_1664 = 2210884902194999453;
            }
            100 => {
                let mut postdata: *mut libc::c_char = 0 as *mut libc::c_char;
                let mut file: *mut FILE = 0 as *mut FILE;
                let mut size: size_t = 0 as libc::c_int as size_t;
                let mut raw_mode: bool = subletter as libc::c_int == 'r' as i32;
                if subletter as libc::c_int == 'e' as i32 {
                    let mut p_0: *const libc::c_char = strchr(nextarg, '=' as i32);
                    let mut nlen: size_t = 0;
                    let mut is_file: libc::c_char = 0;
                    if p_0.is_null() {
                        p_0 = strchr(nextarg, '@' as i32);
                    }
                    if !p_0.is_null() {
                        nlen = p_0.offset_from(nextarg) as libc::c_long as size_t;
                        let fresh87 = p_0;
                        p_0 = p_0.offset(1);
                        is_file = *fresh87;
                    } else {
                        is_file = 0 as libc::c_int as libc::c_char;
                        nlen = is_file as size_t;
                        p_0 = nextarg;
                    }
                    if '@' as i32 == is_file as libc::c_int {
                        if strcmp(b"-\0" as *const u8 as *const libc::c_char, p_0) == 0 {
                            file = stdin;
                        } else {
                            file = fopen(
                                p_0,
                                b"rb\0" as *const u8 as *const libc::c_char,
                            );
                            if file.is_null() {
                                warnf(
                                    global,
                                    b"Couldn't read data from file \"%s\", this makes an empty POST.\n\0"
                                        as *const u8 as *const libc::c_char,
                                    nextarg,
                                );
                            }
                        }
                        err = file2memory(&mut postdata, &mut size, file);
                        if !file.is_null() && file != stdin {
                            fclose(file);
                        }
                        if err as u64 != 0 {
                            return err;
                        }
                    } else {
                        if !postdata.is_null() {
                            free(postdata as *mut libc::c_void);
                            postdata = 0 as *mut libc::c_char;
                        }
                        if !p_0.is_null() {
                            postdata = strdup(p_0);
                            if postdata.is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        if !postdata.is_null() {
                            size = strlen(postdata);
                        }
                    }
                    if postdata.is_null() {
                        postdata = strdup(b"\0" as *const u8 as *const libc::c_char);
                        if postdata.is_null() {
                            return PARAM_NO_MEM;
                        }
                        size = 0 as libc::c_int as size_t;
                    } else {
                        let mut enc: *mut libc::c_char = curl_easy_escape(
                            0 as *mut CURL,
                            postdata,
                            size as libc::c_int,
                        );
                        free(postdata as *mut libc::c_void);
                        postdata = 0 as *mut libc::c_char;
                        if !enc.is_null() {
                            let mut enclen: size_t = replace_url_encoded_space_by_plus(
                                enc,
                            );
                            let mut outlen: size_t = nlen
                                .wrapping_add(enclen)
                                .wrapping_add(2 as libc::c_int as libc::c_ulong);
                            let mut n: *mut libc::c_char = malloc(outlen)
                                as *mut libc::c_char;
                            if n.is_null() {
                                curl_free(enc as *mut libc::c_void);
                                return PARAM_NO_MEM;
                            }
                            if nlen > 0 as libc::c_int as libc::c_ulong {
                                curl_msnprintf(
                                    n,
                                    outlen,
                                    b"%.*s=%s\0" as *const u8 as *const libc::c_char,
                                    nlen,
                                    nextarg,
                                    enc,
                                );
                                size = outlen
                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong);
                            } else {
                                strcpy(n, enc);
                                size = outlen
                                    .wrapping_sub(2 as libc::c_int as libc::c_ulong);
                            }
                            curl_free(enc as *mut libc::c_void);
                            postdata = n;
                        } else {
                            return PARAM_NO_MEM
                        }
                    }
                } else if '@' as i32 == *nextarg as libc::c_int && !raw_mode {
                    nextarg = nextarg.offset(1);
                    if strcmp(b"-\0" as *const u8 as *const libc::c_char, nextarg) == 0 {
                        file = stdin;
                        subletter as libc::c_int == 'b' as i32;
                    } else {
                        file = fopen(
                            nextarg,
                            b"rb\0" as *const u8 as *const libc::c_char,
                        );
                        if file.is_null() {
                            warnf(
                                global,
                                b"Couldn't read data from file \"%s\", this makes an empty POST.\n\0"
                                    as *const u8 as *const libc::c_char,
                                nextarg,
                            );
                        }
                    }
                    if subletter as libc::c_int == 'b' as i32 {
                        err = file2memory(&mut postdata, &mut size, file);
                    } else {
                        err = file2string(&mut postdata, file);
                        if !postdata.is_null() {
                            size = strlen(postdata);
                        }
                    }
                    if !file.is_null() && file != stdin {
                        fclose(file);
                    }
                    if err as u64 != 0 {
                        return err;
                    }
                    if postdata.is_null() {
                        postdata = strdup(b"\0" as *const u8 as *const libc::c_char);
                        if postdata.is_null() {
                            return PARAM_NO_MEM;
                        }
                    }
                } else {
                    if !postdata.is_null() {
                        free(postdata as *mut libc::c_void);
                        postdata = 0 as *mut libc::c_char;
                    }
                    if !nextarg.is_null() {
                        postdata = strdup(nextarg);
                        if postdata.is_null() {
                            return PARAM_NO_MEM;
                        }
                    }
                    if !postdata.is_null() {
                        size = strlen(postdata);
                    }
                }
                if !((*config).postfields).is_null() {
                    let mut oldpost: *mut libc::c_char = (*config).postfields;
                    let mut oldlen: curl_off_t = (*config).postfieldsize;
                    let mut newlen: curl_off_t = oldlen + curlx_uztoso(size)
                        + 2 as libc::c_int as libc::c_long;
                    let ref mut fresh88 = (*config).postfields;
                    *fresh88 = malloc(newlen as size_t) as *mut libc::c_char;
                    if ((*config).postfields).is_null() {
                        free(oldpost as *mut libc::c_void);
                        oldpost = 0 as *mut libc::c_char;
                        free(postdata as *mut libc::c_void);
                        postdata = 0 as *mut libc::c_char;
                        return PARAM_NO_MEM;
                    }
                    memcpy(
                        (*config).postfields as *mut libc::c_void,
                        oldpost as *const libc::c_void,
                        oldlen as size_t,
                    );
                    *((*config).postfields)
                        .offset(oldlen as isize) = '&' as i32 as libc::c_char;
                    memcpy(
                        &mut *((*config).postfields)
                            .offset((oldlen + 1 as libc::c_int as libc::c_long) as isize)
                            as *mut libc::c_char as *mut libc::c_void,
                        postdata as *const libc::c_void,
                        size,
                    );
                    *((*config).postfields)
                        .offset(
                            ((oldlen + 1 as libc::c_int as libc::c_long)
                                as libc::c_ulong)
                                .wrapping_add(size) as isize,
                        ) = '\u{0}' as i32 as libc::c_char;
                    free(oldpost as *mut libc::c_void);
                    oldpost = 0 as *mut libc::c_char;
                    free(postdata as *mut libc::c_void);
                    postdata = 0 as *mut libc::c_char;
                    let ref mut fresh89 = (*config).postfieldsize;
                    *fresh89 = (*fresh89 as libc::c_ulong)
                        .wrapping_add(
                            size.wrapping_add(1 as libc::c_int as libc::c_ulong),
                        ) as curl_off_t as curl_off_t;
                } else {
                    let ref mut fresh90 = (*config).postfields;
                    *fresh90 = postdata;
                    (*config).postfieldsize = curlx_uztoso(size);
                }
                current_block_1664 = 2210884902194999453;
            }
            68 => {
                if !((*config).headerfile).is_null() {
                    free((*config).headerfile as *mut libc::c_void);
                    let ref mut fresh91 = (*config).headerfile;
                    *fresh91 = 0 as *mut libc::c_char;
                }
                if !nextarg.is_null() {
                    let ref mut fresh92 = (*config).headerfile;
                    *fresh92 = strdup(nextarg);
                    if ((*config).headerfile).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            101 => {
                let mut ptr: *mut libc::c_char = strstr(
                    nextarg,
                    b";auto\0" as *const u8 as *const libc::c_char,
                );
                if !ptr.is_null() {
                    (*config).autoreferer = 1 as libc::c_int != 0;
                    *ptr = 0 as libc::c_int as libc::c_char;
                } else {
                    (*config).autoreferer = 0 as libc::c_int != 0;
                }
                ptr = if *nextarg as libc::c_int != 0 {
                    nextarg
                } else {
                    0 as *mut libc::c_char
                };
                if !((*config).referer).is_null() {
                    free((*config).referer as *mut libc::c_void);
                    let ref mut fresh93 = (*config).referer;
                    *fresh93 = 0 as *mut libc::c_char;
                }
                if !ptr.is_null() {
                    let ref mut fresh94 = (*config).referer;
                    *fresh94 = strdup(ptr);
                    if ((*config).referer).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            69 => {
                match subletter as libc::c_int {
                    0 => {
                        GetFileAndPassword(
                            nextarg,
                            &mut (*config).cert,
                            &mut (*config).key_passwd,
                        );
                    }
                    97 => {
                        if !((*config).cacert).is_null() {
                            free((*config).cacert as *mut libc::c_void);
                            let ref mut fresh95 = (*config).cacert;
                            *fresh95 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh96 = (*config).cacert;
                            *fresh96 = strdup(nextarg);
                            if ((*config).cacert).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    98 => {
                        if !((*config).cert_type).is_null() {
                            free((*config).cert_type as *mut libc::c_void);
                            let ref mut fresh97 = (*config).cert_type;
                            *fresh97 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh98 = (*config).cert_type;
                            *fresh98 = strdup(nextarg);
                            if ((*config).cert_type).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    99 => {
                        if !((*config).key).is_null() {
                            free((*config).key as *mut libc::c_void);
                            let ref mut fresh99 = (*config).key;
                            *fresh99 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh100 = (*config).key;
                            *fresh100 = strdup(nextarg);
                            if ((*config).key).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    100 => {
                        if !((*config).key_type).is_null() {
                            free((*config).key_type as *mut libc::c_void);
                            let ref mut fresh101 = (*config).key_type;
                            *fresh101 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh102 = (*config).key_type;
                            *fresh102 = strdup(nextarg);
                            if ((*config).key_type).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    101 => {
                        if !((*config).key_passwd).is_null() {
                            free((*config).key_passwd as *mut libc::c_void);
                            let ref mut fresh103 = (*config).key_passwd;
                            *fresh103 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh104 = (*config).key_passwd;
                            *fresh104 = strdup(nextarg);
                            if ((*config).key_passwd).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        cleanarg(nextarg);
                    }
                    102 => {
                        if !((*config).engine).is_null() {
                            free((*config).engine as *mut libc::c_void);
                            let ref mut fresh105 = (*config).engine;
                            *fresh105 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh106 = (*config).engine;
                            *fresh106 = strdup(nextarg);
                            if ((*config).engine).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        if !((*config).engine).is_null()
                            && curl_strequal(
                                (*config).engine,
                                b"list\0" as *const u8 as *const libc::c_char,
                            ) != 0
                        {
                            return PARAM_ENGINES_REQUESTED;
                        }
                    }
                    103 => {
                        if !((*config).capath).is_null() {
                            free((*config).capath as *mut libc::c_void);
                            let ref mut fresh107 = (*config).capath;
                            *fresh107 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh108 = (*config).capath;
                            *fresh108 = strdup(nextarg);
                            if ((*config).capath).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    104 => {
                        if !((*config).pubkey).is_null() {
                            free((*config).pubkey as *mut libc::c_void);
                            let ref mut fresh109 = (*config).pubkey;
                            *fresh109 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh110 = (*config).pubkey;
                            *fresh110 = strdup(nextarg);
                            if ((*config).pubkey).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    105 => {
                        if !((*config).hostpubmd5).is_null() {
                            free((*config).hostpubmd5 as *mut libc::c_void);
                            let ref mut fresh111 = (*config).hostpubmd5;
                            *fresh111 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh112 = (*config).hostpubmd5;
                            *fresh112 = strdup(nextarg);
                            if ((*config).hostpubmd5).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        if ((*config).hostpubmd5).is_null()
                            || strlen((*config).hostpubmd5)
                                != 32 as libc::c_int as libc::c_ulong
                        {
                            return PARAM_BAD_USE;
                        }
                    }
                    106 => {
                        if !((*config).crlfile).is_null() {
                            free((*config).crlfile as *mut libc::c_void);
                            let ref mut fresh113 = (*config).crlfile;
                            *fresh113 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh114 = (*config).crlfile;
                            *fresh114 = strdup(nextarg);
                            if ((*config).crlfile).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    107 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 14 as libc::c_int
                            != 0
                        {
                            if !((*config).tls_username).is_null() {
                                free((*config).tls_username as *mut libc::c_void);
                                let ref mut fresh115 = (*config).tls_username;
                                *fresh115 = 0 as *mut libc::c_char;
                            }
                            if !nextarg.is_null() {
                                let ref mut fresh116 = (*config).tls_username;
                                *fresh116 = strdup(nextarg);
                                if ((*config).tls_username).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT
                        }
                    }
                    108 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 14 as libc::c_int
                            != 0
                        {
                            if !((*config).tls_password).is_null() {
                                free((*config).tls_password as *mut libc::c_void);
                                let ref mut fresh117 = (*config).tls_password;
                                *fresh117 = 0 as *mut libc::c_char;
                            }
                            if !nextarg.is_null() {
                                let ref mut fresh118 = (*config).tls_password;
                                *fresh118 = strdup(nextarg);
                                if ((*config).tls_password).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT
                        }
                    }
                    109 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 14 as libc::c_int
                            != 0
                        {
                            if !((*config).tls_authtype).is_null() {
                                free((*config).tls_authtype as *mut libc::c_void);
                                let ref mut fresh119 = (*config).tls_authtype;
                                *fresh119 = 0 as *mut libc::c_char;
                            }
                            if !nextarg.is_null() {
                                let ref mut fresh120 = (*config).tls_authtype;
                                *fresh120 = strdup(nextarg);
                                if ((*config).tls_authtype).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                            if curl_strequal(
                                (*config).tls_authtype,
                                b"SRP\0" as *const u8 as *const libc::c_char,
                            ) == 0
                            {
                                return PARAM_LIBCURL_DOESNT_SUPPORT;
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT
                        }
                    }
                    110 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 2 as libc::c_int
                            != 0
                        {
                            (*config).ssl_allow_beast = toggle;
                        }
                    }
                    111 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 2 as libc::c_int
                            != 0
                        {
                            (*config).ssl_auto_client_cert = toggle;
                        }
                    }
                    79 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 2 as libc::c_int
                            != 0
                        {
                            (*config).proxy_ssl_auto_client_cert = toggle;
                        }
                    }
                    112 => {
                        if !((*config).pinnedpubkey).is_null() {
                            free((*config).pinnedpubkey as *mut libc::c_void);
                            let ref mut fresh121 = (*config).pinnedpubkey;
                            *fresh121 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh122 = (*config).pinnedpubkey;
                            *fresh122 = strdup(nextarg);
                            if ((*config).pinnedpubkey).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    80 => {
                        if !((*config).proxy_pinnedpubkey).is_null() {
                            free((*config).proxy_pinnedpubkey as *mut libc::c_void);
                            let ref mut fresh123 = (*config).proxy_pinnedpubkey;
                            *fresh123 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh124 = (*config).proxy_pinnedpubkey;
                            *fresh124 = strdup(nextarg);
                            if ((*config).proxy_pinnedpubkey).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    113 => {
                        (*config).verifystatus = 1 as libc::c_int != 0;
                    }
                    81 => {
                        (*config).doh_verifystatus = 1 as libc::c_int != 0;
                    }
                    114 => {
                        (*config).falsestart = 1 as libc::c_int != 0;
                    }
                    115 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 2 as libc::c_int
                            != 0
                        {
                            (*config).ssl_no_revoke = 1 as libc::c_int != 0;
                        }
                    }
                    83 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 2 as libc::c_int
                            != 0
                        {
                            (*config).ssl_revoke_best_effort = 1 as libc::c_int != 0;
                        }
                    }
                    116 => {
                        (*config).tcp_fastopen = 1 as libc::c_int != 0;
                    }
                    117 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 14 as libc::c_int
                            != 0
                        {
                            if !((*config).proxy_tls_username).is_null() {
                                free((*config).proxy_tls_username as *mut libc::c_void);
                                let ref mut fresh125 = (*config).proxy_tls_username;
                                *fresh125 = 0 as *mut libc::c_char;
                            }
                            if !nextarg.is_null() {
                                let ref mut fresh126 = (*config).proxy_tls_username;
                                *fresh126 = strdup(nextarg);
                                if ((*config).proxy_tls_username).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT
                        }
                    }
                    118 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 14 as libc::c_int
                            != 0
                        {
                            if !((*config).proxy_tls_password).is_null() {
                                free((*config).proxy_tls_password as *mut libc::c_void);
                                let ref mut fresh127 = (*config).proxy_tls_password;
                                *fresh127 = 0 as *mut libc::c_char;
                            }
                            if !nextarg.is_null() {
                                let ref mut fresh128 = (*config).proxy_tls_password;
                                *fresh128 = strdup(nextarg);
                                if ((*config).proxy_tls_password).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT
                        }
                    }
                    119 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 14 as libc::c_int
                            != 0
                        {
                            if !((*config).proxy_tls_authtype).is_null() {
                                free((*config).proxy_tls_authtype as *mut libc::c_void);
                                let ref mut fresh129 = (*config).proxy_tls_authtype;
                                *fresh129 = 0 as *mut libc::c_char;
                            }
                            if !nextarg.is_null() {
                                let ref mut fresh130 = (*config).proxy_tls_authtype;
                                *fresh130 = strdup(nextarg);
                                if ((*config).proxy_tls_authtype).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                            if curl_strequal(
                                (*config).proxy_tls_authtype,
                                b"SRP\0" as *const u8 as *const libc::c_char,
                            ) == 0
                            {
                                return PARAM_LIBCURL_DOESNT_SUPPORT;
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT
                        }
                    }
                    120 => {
                        GetFileAndPassword(
                            nextarg,
                            &mut (*config).proxy_cert,
                            &mut (*config).proxy_key_passwd,
                        );
                    }
                    121 => {
                        if !((*config).proxy_cert_type).is_null() {
                            free((*config).proxy_cert_type as *mut libc::c_void);
                            let ref mut fresh131 = (*config).proxy_cert_type;
                            *fresh131 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh132 = (*config).proxy_cert_type;
                            *fresh132 = strdup(nextarg);
                            if ((*config).proxy_cert_type).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    122 => {
                        if !((*config).proxy_key).is_null() {
                            free((*config).proxy_key as *mut libc::c_void);
                            let ref mut fresh133 = (*config).proxy_key;
                            *fresh133 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh134 = (*config).proxy_key;
                            *fresh134 = strdup(nextarg);
                            if ((*config).proxy_key).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    48 => {
                        if !((*config).proxy_key_type).is_null() {
                            free((*config).proxy_key_type as *mut libc::c_void);
                            let ref mut fresh135 = (*config).proxy_key_type;
                            *fresh135 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh136 = (*config).proxy_key_type;
                            *fresh136 = strdup(nextarg);
                            if ((*config).proxy_key_type).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    49 => {
                        if !((*config).proxy_key_passwd).is_null() {
                            free((*config).proxy_key_passwd as *mut libc::c_void);
                            let ref mut fresh137 = (*config).proxy_key_passwd;
                            *fresh137 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh138 = (*config).proxy_key_passwd;
                            *fresh138 = strdup(nextarg);
                            if ((*config).proxy_key_passwd).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        cleanarg(nextarg);
                    }
                    50 => {
                        if !((*config).proxy_cipher_list).is_null() {
                            free((*config).proxy_cipher_list as *mut libc::c_void);
                            let ref mut fresh139 = (*config).proxy_cipher_list;
                            *fresh139 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh140 = (*config).proxy_cipher_list;
                            *fresh140 = strdup(nextarg);
                            if ((*config).proxy_cipher_list).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    51 => {
                        if !((*config).proxy_crlfile).is_null() {
                            free((*config).proxy_crlfile as *mut libc::c_void);
                            let ref mut fresh141 = (*config).proxy_crlfile;
                            *fresh141 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh142 = (*config).proxy_crlfile;
                            *fresh142 = strdup(nextarg);
                            if ((*config).proxy_crlfile).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    52 => {
                        if (*curlinfo).features & (1 as libc::c_int) << 2 as libc::c_int
                            != 0
                        {
                            (*config).proxy_ssl_allow_beast = toggle;
                        }
                    }
                    53 => {
                        if !((*config).login_options).is_null() {
                            free((*config).login_options as *mut libc::c_void);
                            let ref mut fresh143 = (*config).login_options;
                            *fresh143 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh144 = (*config).login_options;
                            *fresh144 = strdup(nextarg);
                            if ((*config).login_options).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    54 => {
                        if !((*config).proxy_cacert).is_null() {
                            free((*config).proxy_cacert as *mut libc::c_void);
                            let ref mut fresh145 = (*config).proxy_cacert;
                            *fresh145 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh146 = (*config).proxy_cacert;
                            *fresh146 = strdup(nextarg);
                            if ((*config).proxy_cacert).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    55 => {
                        if !((*config).proxy_capath).is_null() {
                            free((*config).proxy_capath as *mut libc::c_void);
                            let ref mut fresh147 = (*config).proxy_capath;
                            *fresh147 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh148 = (*config).proxy_capath;
                            *fresh148 = strdup(nextarg);
                            if ((*config).proxy_capath).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    56 => {
                        (*config).proxy_insecure_ok = toggle;
                    }
                    57 => {
                        (*config)
                            .proxy_ssl_version = CURL_SSLVERSION_TLSv1 as libc::c_int
                            as libc::c_long;
                    }
                    65 => {
                        if toggle {
                            (*config).socks5_auth
                                |= (1 as libc::c_int as libc::c_ulong) << 0 as libc::c_int;
                        } else {
                            (*config).socks5_auth
                                &= !((1 as libc::c_int as libc::c_ulong)
                                    << 0 as libc::c_int);
                        }
                    }
                    66 => {
                        if toggle {
                            (*config).socks5_auth
                                |= (1 as libc::c_int as libc::c_ulong) << 2 as libc::c_int;
                        } else {
                            (*config).socks5_auth
                                &= !((1 as libc::c_int as libc::c_ulong)
                                    << 2 as libc::c_int);
                        }
                    }
                    67 => {
                        if !((*config).etag_save_file).is_null() {
                            free((*config).etag_save_file as *mut libc::c_void);
                            let ref mut fresh149 = (*config).etag_save_file;
                            *fresh149 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh150 = (*config).etag_save_file;
                            *fresh150 = strdup(nextarg);
                            if ((*config).etag_save_file).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    68 => {
                        if !((*config).etag_compare_file).is_null() {
                            free((*config).etag_compare_file as *mut libc::c_void);
                            let ref mut fresh151 = (*config).etag_compare_file;
                            *fresh151 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh152 = (*config).etag_compare_file;
                            *fresh152 = strdup(nextarg);
                            if ((*config).etag_compare_file).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    69 => {
                        if !((*config).ssl_ec_curves).is_null() {
                            free((*config).ssl_ec_curves as *mut libc::c_void);
                            let ref mut fresh153 = (*config).ssl_ec_curves;
                            *fresh153 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh154 = (*config).ssl_ec_curves;
                            *fresh154 = strdup(nextarg);
                            if ((*config).ssl_ec_curves).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    _ => return PARAM_OPTION_UNKNOWN,
                }
                current_block_1664 = 2210884902194999453;
            }
            102 => {
                match subletter as libc::c_int {
                    97 => {
                        (*global).fail_early = toggle;
                    }
                    98 => {
                        (*global).styled_output = toggle;
                    }
                    99 => {
                        (*config).mail_rcpt_allowfails = toggle;
                    }
                    100 => {
                        (*config).failwithbody = toggle;
                    }
                    _ => {
                        (*config).failonerror = toggle;
                    }
                }
                if (*config).failonerror as libc::c_int != 0
                    && (*config).failwithbody as libc::c_int != 0
                {
                    errorf(
                        (*config).global,
                        b"You must select either --fail or --fail-with-body, not both.\n\0"
                            as *const u8 as *const libc::c_char,
                    );
                    return PARAM_BAD_USE;
                }
                current_block_1664 = 2210884902194999453;
            }
            70 => {
                if formparse(
                    config,
                    nextarg,
                    &mut (*config).mimeroot,
                    &mut (*config).mimecurrent,
                    if subletter as libc::c_int == 's' as i32 {
                        1 as libc::c_int
                    } else {
                        0 as libc::c_int
                    } != 0,
                ) != 0
                {
                    return PARAM_BAD_USE;
                }
                if SetHTTPrequest(config, HTTPREQ_MIMEPOST, &mut (*config).httpreq) != 0
                {
                    return PARAM_BAD_USE;
                }
                current_block_1664 = 2210884902194999453;
            }
            103 => {
                (*config).globoff = toggle;
                current_block_1664 = 2210884902194999453;
            }
            71 => {
                if subletter as libc::c_int == 'a' as i32 {
                    if !((*config).request_target).is_null() {
                        free((*config).request_target as *mut libc::c_void);
                        let ref mut fresh155 = (*config).request_target;
                        *fresh155 = 0 as *mut libc::c_char;
                    }
                    if !nextarg.is_null() {
                        let ref mut fresh156 = (*config).request_target;
                        *fresh156 = strdup(nextarg);
                        if ((*config).request_target).is_null() {
                            return PARAM_NO_MEM;
                        }
                    }
                } else {
                    (*config).use_httpget = 1 as libc::c_int != 0;
                }
                current_block_1664 = 2210884902194999453;
            }
            104 => {
                if toggle {
                    if !nextarg.is_null() {
                        let ref mut fresh157 = (*global).help_category;
                        *fresh157 = strdup(nextarg);
                        if ((*global).help_category).is_null() {
                            return PARAM_NO_MEM;
                        }
                    }
                    return PARAM_HELP_REQUESTED;
                }
                current_block_1664 = 2210884902194999453;
            }
            72 => {
                if *nextarg.offset(0 as libc::c_int as isize) as libc::c_int
                    == '@' as i32
                {
                    let mut string: *mut libc::c_char = 0 as *mut libc::c_char;
                    let mut len: size_t = 0;
                    let mut use_stdin: bool = strcmp(
                        &mut *nextarg.offset(1 as libc::c_int as isize),
                        b"-\0" as *const u8 as *const libc::c_char,
                    ) == 0;
                    let mut file_0: *mut FILE = if use_stdin as libc::c_int != 0 {
                        stdin
                    } else {
                        fopen(
                            &mut *nextarg.offset(1 as libc::c_int as isize),
                            b"r\0" as *const u8 as *const libc::c_char,
                        )
                    };
                    if file_0.is_null() {
                        warnf(
                            global,
                            b"Failed to open %s!\n\0" as *const u8
                                as *const libc::c_char,
                            &mut *nextarg.offset(1 as libc::c_int as isize)
                                as *mut libc::c_char,
                        );
                    } else {
                        err = file2memory(&mut string, &mut len, file_0);
                        if err as u64 == 0 && !string.is_null() {
                            let mut h: *mut libc::c_char = strtok(
                                string,
                                b"\r\n\0" as *const u8 as *const libc::c_char,
                            );
                            while !h.is_null() {
                                if subletter as libc::c_int == 'p' as i32 {
                                    err = add2list(&mut (*config).proxyheaders, h);
                                } else {
                                    err = add2list(&mut (*config).headers, h);
                                }
                                if err as u64 != 0 {
                                    break;
                                }
                                h = strtok(
                                    0 as *mut libc::c_char,
                                    b"\r\n\0" as *const u8 as *const libc::c_char,
                                );
                            }
                            free(string as *mut libc::c_void);
                        }
                        if !use_stdin {
                            fclose(file_0);
                        }
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                } else {
                    if subletter as libc::c_int == 'p' as i32 {
                        err = add2list(&mut (*config).proxyheaders, nextarg);
                    } else {
                        err = add2list(&mut (*config).headers, nextarg);
                    }
                    if err as u64 != 0 {
                        return err;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            105 => {
                (*config).show_headers = toggle;
                current_block_1664 = 2210884902194999453;
            }
            106 => {
                (*config).cookiesession = toggle;
                current_block_1664 = 2210884902194999453;
            }
            73 => {
                (*config).no_body = toggle;
                (*config).show_headers = toggle;
                if SetHTTPrequest(
                    config,
                    (if (*config).no_body as libc::c_int != 0 {
                        HTTPREQ_HEAD as libc::c_int
                    } else {
                        HTTPREQ_GET as libc::c_int
                    }) as HttpReq,
                    &mut (*config).httpreq,
                ) != 0
                {
                    return PARAM_BAD_USE;
                }
                current_block_1664 = 2210884902194999453;
            }
            74 => {
                (*config).content_disposition = toggle;
                current_block_1664 = 2210884902194999453;
            }
            107 => {
                if subletter as libc::c_int == 'd' as i32 {
                    (*config).doh_insecure_ok = toggle;
                } else {
                    (*config).insecure_ok = toggle;
                }
                current_block_1664 = 2210884902194999453;
            }
            75 => {
                if parseconfig(nextarg, global) != 0 {
                    warnf(
                        global,
                        b"error trying read config from the '%s' file\n\0" as *const u8
                            as *const libc::c_char,
                        nextarg,
                    );
                }
                current_block_1664 = 2210884902194999453;
            }
            108 => {
                (*config).dirlistonly = toggle;
                current_block_1664 = 2210884902194999453;
            }
            76 => {
                (*config).followlocation = toggle;
                match subletter as libc::c_int {
                    116 => {
                        (*config).unrestricted_auth = toggle;
                    }
                    _ => {}
                }
                current_block_1664 = 2210884902194999453;
            }
            109 => {
                err = str2udouble(
                    &mut (*config).timeout,
                    nextarg,
                    9223372036854775807 as libc::c_long
                        / 1000 as libc::c_int as libc::c_long,
                );
                if err as u64 != 0 {
                    return err;
                }
                current_block_1664 = 2210884902194999453;
            }
            77 => {
                if toggle {
                    return PARAM_MANUAL_REQUESTED;
                }
                current_block_1664 = 2210884902194999453;
            }
            110 => {
                match subletter as libc::c_int {
                    111 => {
                        (*config).netrc_opt = toggle;
                    }
                    101 => {
                        if !((*config).netrc_file).is_null() {
                            free((*config).netrc_file as *mut libc::c_void);
                            let ref mut fresh158 = (*config).netrc_file;
                            *fresh158 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh159 = (*config).netrc_file;
                            *fresh159 = strdup(nextarg);
                            if ((*config).netrc_file).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    _ => {
                        (*config).netrc = toggle;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            78 => {
                if longopt {
                    (*config)
                        .nobuffer = if !toggle {
                        1 as libc::c_int
                    } else {
                        0 as libc::c_int
                    } != 0;
                } else {
                    (*config).nobuffer = toggle;
                }
                current_block_1664 = 2210884902194999453;
            }
            79 => {
                if subletter as libc::c_int == 'a' as i32 {
                    (*config)
                        .default_node_flags = if toggle as libc::c_int != 0 {
                        (1 as libc::c_int) << 2 as libc::c_int
                    } else {
                        0 as libc::c_int
                    };
                    current_block_1664 = 2210884902194999453;
                } else if subletter as libc::c_int == 'b' as i32 {
                    if !((*config).output_dir).is_null() {
                        free((*config).output_dir as *mut libc::c_void);
                        let ref mut fresh160 = (*config).output_dir;
                        *fresh160 = 0 as *mut libc::c_char;
                    }
                    if !nextarg.is_null() {
                        let ref mut fresh161 = (*config).output_dir;
                        *fresh161 = strdup(nextarg);
                        if ((*config).output_dir).is_null() {
                            return PARAM_NO_MEM;
                        }
                    }
                    current_block_1664 = 2210884902194999453;
                } else {
                    current_block_1664 = 11000567119642394172;
                }
            }
            111 => {
                current_block_1664 = 11000567119642394172;
            }
            80 => {
                if !((*config).ftpport).is_null() {
                    free((*config).ftpport as *mut libc::c_void);
                    let ref mut fresh168 = (*config).ftpport;
                    *fresh168 = 0 as *mut libc::c_char;
                }
                if !nextarg.is_null() {
                    let ref mut fresh169 = (*config).ftpport;
                    *fresh169 = strdup(nextarg);
                    if ((*config).ftpport).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            112 => {
                (*config).proxytunnel = toggle;
                current_block_1664 = 2210884902194999453;
            }
            113 => {
                current_block_1664 = 2210884902194999453;
            }
            81 => {
                match *nextarg.offset(0 as libc::c_int as isize) as libc::c_int {
                    45 => {
                        nextarg = nextarg.offset(1);
                        err = add2list(&mut (*config).postquote, nextarg);
                    }
                    43 => {
                        nextarg = nextarg.offset(1);
                        err = add2list(&mut (*config).prequote, nextarg);
                    }
                    _ => {
                        err = add2list(&mut (*config).quote, nextarg);
                    }
                }
                if err as u64 != 0 {
                    return err;
                }
                current_block_1664 = 2210884902194999453;
            }
            114 => {
                if Curl_isdigit(*nextarg as libc::c_uchar as libc::c_int) != 0
                    && (strchr(nextarg, '-' as i32)).is_null()
                {
                    let mut buffer: [libc::c_char; 32] = [0; 32];
                    let mut off: curl_off_t = 0;
                    if curlx_strtoofft(
                        nextarg,
                        0 as *mut *mut libc::c_char,
                        10 as libc::c_int,
                        &mut off,
                    ) as u64 != 0
                    {
                        warnf(
                            global,
                            b"unsupported range point\n\0" as *const u8
                                as *const libc::c_char,
                        );
                        return PARAM_BAD_USE;
                    }
                    warnf(
                        global,
                        b"A specified range MUST include at least one dash (-). Appending one for you!\n\0"
                            as *const u8 as *const libc::c_char,
                    );
                    curl_msnprintf(
                        buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
                        b"%ld-\0" as *const u8 as *const libc::c_char,
                        off,
                    );
                    free((*config).range as *mut libc::c_void);
                    let ref mut fresh170 = (*config).range;
                    *fresh170 = 0 as *mut libc::c_char;
                    let ref mut fresh171 = (*config).range;
                    *fresh171 = strdup(buffer.as_mut_ptr());
                    if ((*config).range).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                let mut tmp_range: *const libc::c_char = nextarg;
                while *tmp_range as libc::c_int != '\u{0}' as i32 {
                    if Curl_isdigit(*tmp_range as libc::c_uchar as libc::c_int) == 0
                        && *tmp_range as libc::c_int != '-' as i32
                        && *tmp_range as libc::c_int != ',' as i32
                    {
                        warnf(
                            global,
                            b"Invalid character is found in given range. A specified range MUST have only digits in 'start'-'stop'. The server's response to this request is uncertain.\n\0"
                                as *const u8 as *const libc::c_char,
                        );
                        break;
                    } else {
                        tmp_range = tmp_range.offset(1);
                    }
                }
                if !((*config).range).is_null() {
                    free((*config).range as *mut libc::c_void);
                    let ref mut fresh172 = (*config).range;
                    *fresh172 = 0 as *mut libc::c_char;
                }
                if !nextarg.is_null() {
                    let ref mut fresh173 = (*config).range;
                    *fresh173 = strdup(nextarg);
                    if ((*config).range).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            82 => {
                (*config).remote_time = toggle;
                current_block_1664 = 2210884902194999453;
            }
            115 => {
                if toggle {
                    let ref mut fresh174 = (*global).noprogress;
                    *fresh174 = 1 as libc::c_int != 0;
                    (*global).mute = *fresh174;
                } else {
                    let ref mut fresh175 = (*global).noprogress;
                    *fresh175 = 0 as libc::c_int != 0;
                    (*global).mute = *fresh175;
                }
                if (*global).showerror < 0 as libc::c_int {
                    (*global)
                        .showerror = if !toggle {
                        1 as libc::c_int
                    } else {
                        0 as libc::c_int
                    };
                }
                current_block_1664 = 2210884902194999453;
            }
            83 => {
                (*global)
                    .showerror = if toggle as libc::c_int != 0 {
                    1 as libc::c_int
                } else {
                    0 as libc::c_int
                };
                current_block_1664 = 2210884902194999453;
            }
            116 => {
                err = add2list(&mut (*config).telnet_options, nextarg);
                if err as u64 != 0 {
                    return err;
                }
                current_block_1664 = 2210884902194999453;
            }
            84 => {
                let mut url_1: *mut getout = 0 as *mut getout;
                if ((*config).url_ul).is_null() {
                    let ref mut fresh176 = (*config).url_ul;
                    *fresh176 = (*config).url_list;
                }
                if !((*config).url_ul).is_null() {
                    while !((*config).url_ul).is_null()
                        && (*(*config).url_ul).flags
                            & (1 as libc::c_int) << 3 as libc::c_int != 0
                    {
                        let ref mut fresh177 = (*config).url_ul;
                        *fresh177 = (*(*config).url_ul).next;
                    }
                }
                if !((*config).url_ul).is_null() {
                    url_1 = (*config).url_ul;
                } else {
                    url_1 = new_getout(config);
                    let ref mut fresh178 = (*config).url_ul;
                    *fresh178 = url_1;
                }
                if url_1.is_null() {
                    return PARAM_NO_MEM;
                }
                (*url_1).flags |= (1 as libc::c_int) << 3 as libc::c_int;
                if *nextarg == 0 {
                    (*url_1).flags |= (1 as libc::c_int) << 4 as libc::c_int;
                } else {
                    if !((*url_1).infile).is_null() {
                        free((*url_1).infile as *mut libc::c_void);
                        let ref mut fresh179 = (*url_1).infile;
                        *fresh179 = 0 as *mut libc::c_char;
                    }
                    if !nextarg.is_null() {
                        let ref mut fresh180 = (*url_1).infile;
                        *fresh180 = strdup(nextarg);
                        if ((*url_1).infile).is_null() {
                            return PARAM_NO_MEM;
                        }
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            117 => {
                if !((*config).userpwd).is_null() {
                    free((*config).userpwd as *mut libc::c_void);
                    let ref mut fresh181 = (*config).userpwd;
                    *fresh181 = 0 as *mut libc::c_char;
                }
                if !nextarg.is_null() {
                    let ref mut fresh182 = (*config).userpwd;
                    *fresh182 = strdup(nextarg);
                    if ((*config).userpwd).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                cleanarg(nextarg);
                current_block_1664 = 2210884902194999453;
            }
            85 => {
                if !((*config).proxyuserpwd).is_null() {
                    free((*config).proxyuserpwd as *mut libc::c_void);
                    let ref mut fresh183 = (*config).proxyuserpwd;
                    *fresh183 = 0 as *mut libc::c_char;
                }
                if !nextarg.is_null() {
                    let ref mut fresh184 = (*config).proxyuserpwd;
                    *fresh184 = strdup(nextarg);
                    if ((*config).proxyuserpwd).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                cleanarg(nextarg);
                current_block_1664 = 2210884902194999453;
            }
            118 => {
                if toggle {
                    free((*global).trace_dump as *mut libc::c_void);
                    let ref mut fresh185 = (*global).trace_dump;
                    *fresh185 = 0 as *mut libc::c_char;
                    let ref mut fresh186 = (*global).trace_dump;
                    *fresh186 = strdup(b"%\0" as *const u8 as *const libc::c_char);
                    if ((*global).trace_dump).is_null() {
                        return PARAM_NO_MEM;
                    }
                    if (*global).tracetype as libc::c_uint != 0
                        && (*global).tracetype as libc::c_uint
                            != TRACE_PLAIN as libc::c_int as libc::c_uint
                    {
                        warnf(
                            global,
                            b"-v, --verbose overrides an earlier trace/verbose option\n\0"
                                as *const u8 as *const libc::c_char,
                        );
                    }
                    (*global).tracetype = TRACE_PLAIN;
                } else {
                    (*global).tracetype = TRACE_NONE;
                }
                current_block_1664 = 2210884902194999453;
            }
            86 => {
                if toggle {
                    return PARAM_VERSION_INFO_REQUESTED;
                }
                current_block_1664 = 2210884902194999453;
            }
            119 => {
                if '@' as i32 == *nextarg as libc::c_int {
                    let mut file_1: *mut FILE = 0 as *mut FILE;
                    let mut fname: *const libc::c_char = 0 as *const libc::c_char;
                    nextarg = nextarg.offset(1);
                    if strcmp(b"-\0" as *const u8 as *const libc::c_char, nextarg) == 0 {
                        fname = b"<stdin>\0" as *const u8 as *const libc::c_char;
                        file_1 = stdin;
                    } else {
                        fname = nextarg;
                        file_1 = fopen(
                            nextarg,
                            b"r\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    free((*config).writeout as *mut libc::c_void);
                    let ref mut fresh187 = (*config).writeout;
                    *fresh187 = 0 as *mut libc::c_char;
                    err = file2string(&mut (*config).writeout, file_1);
                    if !file_1.is_null() && file_1 != stdin {
                        fclose(file_1);
                    }
                    if err as u64 != 0 {
                        return err;
                    }
                    if ((*config).writeout).is_null() {
                        warnf(
                            global,
                            b"Failed to read %s\0" as *const u8 as *const libc::c_char,
                            fname,
                        );
                    }
                } else {
                    if !((*config).writeout).is_null() {
                        free((*config).writeout as *mut libc::c_void);
                        let ref mut fresh188 = (*config).writeout;
                        *fresh188 = 0 as *mut libc::c_char;
                    }
                    if !nextarg.is_null() {
                        let ref mut fresh189 = (*config).writeout;
                        *fresh189 = strdup(nextarg);
                        if ((*config).writeout).is_null() {
                            return PARAM_NO_MEM;
                        }
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            120 => {
                match subletter as libc::c_int {
                    97 => {
                        if !((*config).preproxy).is_null() {
                            free((*config).preproxy as *mut libc::c_void);
                            let ref mut fresh190 = (*config).preproxy;
                            *fresh190 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh191 = (*config).preproxy;
                            *fresh191 = strdup(nextarg);
                            if ((*config).preproxy).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    _ => {
                        if !((*config).proxy).is_null() {
                            free((*config).proxy as *mut libc::c_void);
                            let ref mut fresh192 = (*config).proxy;
                            *fresh192 = 0 as *mut libc::c_char;
                        }
                        if !nextarg.is_null() {
                            let ref mut fresh193 = (*config).proxy;
                            *fresh193 = strdup(nextarg);
                            if ((*config).proxy).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        (*config).proxyver = CURLPROXY_HTTP as libc::c_int;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            88 => {
                if !((*config).customrequest).is_null() {
                    free((*config).customrequest as *mut libc::c_void);
                    let ref mut fresh194 = (*config).customrequest;
                    *fresh194 = 0 as *mut libc::c_char;
                }
                if !nextarg.is_null() {
                    let ref mut fresh195 = (*config).customrequest;
                    *fresh195 = strdup(nextarg);
                    if ((*config).customrequest).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            121 => {
                err = str2unum(&mut (*config).low_speed_time, nextarg);
                if err as u64 != 0 {
                    return err;
                }
                if (*config).low_speed_limit == 0 {
                    (*config).low_speed_limit = 1 as libc::c_int as libc::c_long;
                }
                current_block_1664 = 2210884902194999453;
            }
            89 => {
                err = str2unum(&mut (*config).low_speed_limit, nextarg);
                if err as u64 != 0 {
                    return err;
                }
                if (*config).low_speed_time == 0 {
                    (*config).low_speed_time = 30 as libc::c_int as libc::c_long;
                }
                current_block_1664 = 2210884902194999453;
            }
            90 => {
                match subletter as libc::c_int {
                    0 => {
                        (*global).parallel = toggle;
                    }
                    98 => {
                        err = str2unum(&mut (*global).parallel_max, nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                        if (*global).parallel_max > 300 as libc::c_int as libc::c_long
                            || (*global).parallel_max < 1 as libc::c_int as libc::c_long
                        {
                            (*global).parallel_max = 50 as libc::c_int as libc::c_long;
                        }
                    }
                    99 => {
                        (*global).parallel_connect = toggle;
                    }
                    _ => {}
                }
                current_block_1664 = 2210884902194999453;
            }
            122 => {
                let mut current_block_1652: u64;
                match *nextarg as libc::c_int {
                    43 => {
                        nextarg = nextarg.offset(1);
                        current_block_1652 = 17551501277733230131;
                    }
                    45 => {
                        (*config).timecond = CURL_TIMECOND_IFUNMODSINCE;
                        nextarg = nextarg.offset(1);
                        current_block_1652 = 3197977965602298108;
                    }
                    61 => {
                        (*config).timecond = CURL_TIMECOND_LASTMOD;
                        nextarg = nextarg.offset(1);
                        current_block_1652 = 3197977965602298108;
                    }
                    _ => {
                        current_block_1652 = 17551501277733230131;
                    }
                }
                match current_block_1652 {
                    17551501277733230131 => {
                        (*config).timecond = CURL_TIMECOND_IFMODSINCE;
                    }
                    _ => {}
                }
                now = time(0 as *mut time_t);
                (*config).condtime = curl_getdate(nextarg, &mut now);
                if -(1 as libc::c_int) as libc::c_long == (*config).condtime {
                    let mut filetime: curl_off_t = getfiletime(nextarg, global);
                    if filetime >= 0 as libc::c_int as libc::c_long {
                        (*config).condtime = filetime;
                    } else {
                        (*config).timecond = CURL_TIMECOND_NONE;
                        warnf(
                            global,
                            b"Illegal date format for -z, --time-cond (and not a file name). Disabling time condition. See curl_getdate(3) for valid date syntax.\n\0"
                                as *const u8 as *const libc::c_char,
                        );
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            _ => return PARAM_OPTION_UNKNOWN,
        }
        match current_block_1664 {
            11000567119642394172 => {
                let mut url_0: *mut getout = 0 as *mut getout;
                if ((*config).url_out).is_null() {
                    let ref mut fresh162 = (*config).url_out;
                    *fresh162 = (*config).url_list;
                }
                if !((*config).url_out).is_null() {
                    while !((*config).url_out).is_null()
                        && (*(*config).url_out).flags
                            & (1 as libc::c_int) << 0 as libc::c_int != 0
                    {
                        let ref mut fresh163 = (*config).url_out;
                        *fresh163 = (*(*config).url_out).next;
                    }
                }
                if !((*config).url_out).is_null() {
                    url_0 = (*config).url_out;
                } else {
                    url_0 = new_getout(config);
                    let ref mut fresh164 = (*config).url_out;
                    *fresh164 = url_0;
                }
                if url_0.is_null() {
                    return PARAM_NO_MEM;
                }
                if 'o' as i32 == letter as libc::c_int {
                    if !((*url_0).outfile).is_null() {
                        free((*url_0).outfile as *mut libc::c_void);
                        let ref mut fresh165 = (*url_0).outfile;
                        *fresh165 = 0 as *mut libc::c_char;
                    }
                    if !nextarg.is_null() {
                        let ref mut fresh166 = (*url_0).outfile;
                        *fresh166 = strdup(nextarg);
                        if ((*url_0).outfile).is_null() {
                            return PARAM_NO_MEM;
                        }
                    }
                    (*url_0).flags &= !((1 as libc::c_int) << 2 as libc::c_int);
                } else {
                    let ref mut fresh167 = (*url_0).outfile;
                    *fresh167 = 0 as *mut libc::c_char;
                    if toggle {
                        (*url_0).flags |= (1 as libc::c_int) << 2 as libc::c_int;
                    } else {
                        (*url_0).flags &= !((1 as libc::c_int) << 2 as libc::c_int);
                    }
                }
                (*url_0).flags |= (1 as libc::c_int) << 0 as libc::c_int;
            }
            _ => {}
        }
        hit = -(1 as libc::c_int);
        if !(!longopt && !singleopt
            && {
                parse = parse.offset(1);
                *parse as libc::c_int != 0
            } && !*usedarg)
        {
            break;
        }
    }
    return PARAM_OK;
}
#[no_mangle]
pub unsafe extern "C" fn parse_args(
    mut global: *mut GlobalConfig,
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> ParameterError {
    let mut i: libc::c_int = 0;
    let mut stillflags: bool = false;
    let mut orig_opt: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut result: ParameterError = PARAM_OK;
    let mut config: *mut OperationConfig = (*global).first;
    i = 1 as libc::c_int;
    stillflags = 1 as libc::c_int != 0;
    while i < argc && result as u64 == 0 {
        orig_opt = strdup(*argv.offset(i as isize));
        if orig_opt.is_null() {
            return PARAM_NO_MEM;
        }
        if stillflags as libc::c_int != 0
            && '-' as i32 == *orig_opt.offset(0 as libc::c_int as isize) as libc::c_int
        {
            let mut passarg: bool = false;
            if strcmp(b"--\0" as *const u8 as *const libc::c_char, orig_opt) == 0 {
                stillflags = 0 as libc::c_int != 0;
            } else {
                let mut nextarg: *mut libc::c_char = if i < argc - 1 as libc::c_int {
                    strdup(*argv.offset((i + 1 as libc::c_int) as isize))
                } else {
                    0 as *mut libc::c_char
                };
                result = getparameter(orig_opt, nextarg, &mut passarg, global, config);
                if !nextarg.is_null() {
                    free(nextarg as *mut libc::c_void);
                    nextarg = 0 as *mut libc::c_char;
                }
                config = (*global).last;
                if result as libc::c_uint
                    == PARAM_NEXT_OPERATION as libc::c_int as libc::c_uint
                {
                    result = PARAM_OK;
                    if !((*config).url_list).is_null()
                        && !((*(*config).url_list).url).is_null()
                    {
                        let ref mut fresh196 = (*config).next;
                        *fresh196 = malloc(
                            ::std::mem::size_of::<OperationConfig>() as libc::c_ulong,
                        ) as *mut OperationConfig;
                        if !((*config).next).is_null() {
                            config_init((*config).next);
                            let ref mut fresh197 = (*(*config).next).global;
                            *fresh197 = global;
                            let ref mut fresh198 = (*global).last;
                            *fresh198 = (*config).next;
                            let ref mut fresh199 = (*(*config).next).prev;
                            *fresh199 = config;
                            config = (*config).next;
                        } else {
                            result = PARAM_NO_MEM;
                        }
                    }
                } else if result as u64 == 0 && passarg as libc::c_int != 0 {
                    i += 1;
                }
            }
        } else {
            let mut used: bool = false;
            result = getparameter(
                b"--url\0" as *const u8 as *const libc::c_char,
                orig_opt,
                &mut used,
                global,
                config,
            );
        }
        if result as u64 == 0 {
            if !orig_opt.is_null() {
                free(orig_opt as *mut libc::c_void);
                orig_opt = 0 as *mut libc::c_char;
            }
        }
        i += 1;
    }
    if result as u64 == 0 && (*config).content_disposition as libc::c_int != 0 {
        if (*config).show_headers {
            result = PARAM_CONTDISP_SHOW_HEADER;
        } else if (*config).resume_from_current {
            result = PARAM_CONTDISP_RESUME_FROM;
        }
    }
    if result as libc::c_uint != 0
        && result as libc::c_uint != PARAM_HELP_REQUESTED as libc::c_int as libc::c_uint
        && result as libc::c_uint
            != PARAM_MANUAL_REQUESTED as libc::c_int as libc::c_uint
        && result as libc::c_uint
            != PARAM_VERSION_INFO_REQUESTED as libc::c_int as libc::c_uint
        && result as libc::c_uint
            != PARAM_ENGINES_REQUESTED as libc::c_int as libc::c_uint
    {
        let mut reason: *const libc::c_char = param2text(result as libc::c_int);
        if !orig_opt.is_null()
            && strcmp(b":\0" as *const u8 as *const libc::c_char, orig_opt) != 0
        {
            helpf(
                (*global).errors,
                b"option %s: %s\n\0" as *const u8 as *const libc::c_char,
                orig_opt,
                reason,
            );
        } else {
            helpf(
                (*global).errors,
                b"%s\n\0" as *const u8 as *const libc::c_char,
                reason,
            );
        }
    }
    if !orig_opt.is_null() {
        free(orig_opt as *mut libc::c_void);
        orig_opt = 0 as *mut libc::c_char;
    }
    return result;
}
