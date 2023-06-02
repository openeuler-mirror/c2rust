use ::libc;
extern "C" {
    
    
    
    
    
    static mut stdout: * mut crate::src::lib::http2::_IO_FILE;
    static mut stderr: * mut crate::src::lib::http2::_IO_FILE;
    fn fflush(__stream: * mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn fopen(_: * const i8, _: * const i8) -> * mut crate::src::lib::http2::_IO_FILE;
    fn fputc(__c: i32, __stream: * mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn fputs(__s: * const i8, __stream: * mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn fwrite(
        _: * const core::ffi::c_void,
        _: u64,
        _: u64,
        _: * mut crate::src::lib::http2::_IO_FILE,
    ) -> u64;
    fn time(__timer: * mut i64) -> i64;
    fn localtime(__timer: * const i64) -> * mut crate::src::lib::altsvc::tm;
    fn strcmp(_: * const i8, _: * const i8) -> i32;
    
    
    
    
}
pub use crate::src::lib::mprintf::curl_mfprintf;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::src::tool_msgs::warnf;
pub use crate::src::src::tool_util::tvnow;
pub use crate::src::lib::http2::Curl_easy;
pub use crate::src::lib::http2::curl_mime;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __time_t = i64;
pub type __suseconds_t = i64;
pub type time_t = i64;
pub type size_t = u64;
// #[derive(Copy, Clone)]

pub type timeval = crate::src::lib::openldap::timeval;
pub type curl_off_t = i64;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::lib::http2::_IO_FILE;
// #[derive(Copy, Clone)]

pub type tm = crate::src::lib::altsvc::tm;
pub type CURL = crate::src::lib::http2::Curl_easy;
// #[derive(Copy, Clone)]

pub type curl_slist = crate::src::lib::http2::curl_slist;
pub type curl_infotype = u32;
pub const CURLINFO_END: curl_infotype = 7;
pub const CURLINFO_SSL_DATA_OUT: curl_infotype = 6;
pub const CURLINFO_SSL_DATA_IN: curl_infotype = 5;
pub const CURLINFO_DATA_OUT: curl_infotype = 4;
pub const CURLINFO_DATA_IN: curl_infotype = 3;
pub const CURLINFO_HEADER_OUT: curl_infotype = 2;
pub const CURLINFO_HEADER_IN: curl_infotype = 1;
pub const CURLINFO_TEXT: curl_infotype = 0;
pub type curl_TimeCond = u32;
pub const CURL_TIMECOND_LAST: curl_TimeCond = 4;
pub const CURL_TIMECOND_LASTMOD: curl_TimeCond = 3;
pub const CURL_TIMECOND_IFUNMODSINCE: curl_TimeCond = 2;
pub const CURL_TIMECOND_IFMODSINCE: curl_TimeCond = 1;
pub const CURL_TIMECOND_NONE: curl_TimeCond = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct OperationConfig {
    pub remote_time: bool,
    pub random_file: * mut i8,
    pub egd_file: * mut i8,
    pub useragent: * mut i8,
    pub cookies: * mut crate::src::lib::http2::curl_slist,
    pub cookiejar: * mut i8,
    pub cookiefiles: * mut crate::src::lib::http2::curl_slist,
    pub altsvc: * mut i8,
    pub hsts: * mut i8,
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
    pub proto_default: * mut i8,
    pub resume_from: i64,
    pub postfields: * mut i8,
    pub postfieldsize: i64,
    pub referer: * mut i8,
    pub timeout: f64,
    pub connecttimeout: f64,
    pub maxredirs: i64,
    pub max_filesize: i64,
    pub output_dir: * mut i8,
    pub headerfile: * mut i8,
    pub ftpport: * mut i8,
    pub iface: * mut i8,
    pub localport: i64,
    pub localportrange: i64,
    pub porttouse: u16,
    pub range: * mut i8,
    pub low_speed_limit: i64,
    pub low_speed_time: i64,
    pub dns_servers: * mut i8,
    pub dns_interface: * mut i8,
    pub dns_ipv4_addr: * mut i8,
    pub dns_ipv6_addr: * mut i8,
    pub userpwd: * mut i8,
    pub login_options: * mut i8,
    pub tls_username: * mut i8,
    pub tls_password: * mut i8,
    pub tls_authtype: * mut i8,
    pub proxy_tls_username: * mut i8,
    pub proxy_tls_password: * mut i8,
    pub proxy_tls_authtype: * mut i8,
    pub proxyuserpwd: * mut i8,
    pub proxy: * mut i8,
    pub proxyver: i32,
    pub noproxy: * mut i8,
    pub mail_from: * mut i8,
    pub mail_rcpt: * mut crate::src::lib::http2::curl_slist,
    pub mail_auth: * mut i8,
    pub mail_rcpt_allowfails: bool,
    pub sasl_authzid: * mut i8,
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
    pub netrc_file: * mut i8,
    pub url_list: * mut crate::src::src::tool_cb_dbg::getout,
    pub url_last: * mut crate::src::src::tool_cb_dbg::getout,
    pub url_get: * mut crate::src::src::tool_cb_dbg::getout,
    pub url_out: * mut crate::src::src::tool_cb_dbg::getout,
    pub url_ul: * mut crate::src::src::tool_cb_dbg::getout,
    pub doh_url: * mut i8,
    pub cipher_list: * mut i8,
    pub proxy_cipher_list: * mut i8,
    pub cipher13_list: * mut i8,
    pub proxy_cipher13_list: * mut i8,
    pub cert: * mut i8,
    pub proxy_cert: * mut i8,
    pub cert_type: * mut i8,
    pub proxy_cert_type: * mut i8,
    pub cacert: * mut i8,
    pub proxy_cacert: * mut i8,
    pub capath: * mut i8,
    pub proxy_capath: * mut i8,
    pub crlfile: * mut i8,
    pub proxy_crlfile: * mut i8,
    pub pinnedpubkey: * mut i8,
    pub proxy_pinnedpubkey: * mut i8,
    pub key: * mut i8,
    pub proxy_key: * mut i8,
    pub key_type: * mut i8,
    pub proxy_key_type: * mut i8,
    pub key_passwd: * mut i8,
    pub proxy_key_passwd: * mut i8,
    pub pubkey: * mut i8,
    pub hostpubmd5: * mut i8,
    pub engine: * mut i8,
    pub etag_save_file: * mut i8,
    pub etag_compare_file: * mut i8,
    pub crlf: bool,
    pub customrequest: * mut i8,
    pub ssl_ec_curves: * mut i8,
    pub krblevel: * mut i8,
    pub request_target: * mut i8,
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
    pub writeout: * mut i8,
    pub quote: * mut crate::src::lib::http2::curl_slist,
    pub postquote: * mut crate::src::lib::http2::curl_slist,
    pub prequote: * mut crate::src::lib::http2::curl_slist,
    pub ssl_version: i64,
    pub ssl_version_max: i64,
    pub proxy_ssl_version: i64,
    pub ip_version: i64,
    pub create_file_mode: i64,
    pub timecond: u32,
    pub condtime: i64,
    pub headers: * mut crate::src::lib::http2::curl_slist,
    pub proxyheaders: * mut crate::src::lib::http2::curl_slist,
    pub mimeroot: * mut crate::src::src::tool_cb_dbg::tool_mime,
    pub mimecurrent: * mut crate::src::src::tool_cb_dbg::tool_mime,
    pub mimepost: * mut crate::src::lib::http2::curl_mime,
    pub telnet_options: * mut crate::src::lib::http2::curl_slist,
    pub resolve: * mut crate::src::lib::http2::curl_slist,
    pub connect_to: * mut crate::src::lib::http2::curl_slist,
    pub httpreq: u32,
    pub sendpersecond: i64,
    pub recvpersecond: i64,
    pub ftp_ssl: bool,
    pub ftp_ssl_reqd: bool,
    pub ftp_ssl_control: bool,
    pub ftp_ssl_ccc: bool,
    pub ftp_ssl_ccc_mode: i32,
    pub preproxy: * mut i8,
    pub socks5_gssapi_nec: i32,
    pub socks5_auth: u64,
    pub proxy_service_name: * mut i8,
    pub service_name: * mut i8,
    pub tcp_nodelay: bool,
    pub tcp_fastopen: bool,
    pub req_retry: i64,
    pub retry_all_errors: bool,
    pub retry_connrefused: bool,
    pub retry_delay: i64,
    pub retry_maxtime: i64,
    pub ftp_account: * mut i8,
    pub ftp_alternative_to_user: * mut i8,
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
    pub oauth_bearer: * mut i8,
    pub nonpn: bool,
    pub noalpn: bool,
    pub unix_socket_path: * mut i8,
    pub abstract_unix_socket: bool,
    pub falsestart: bool,
    pub path_as_is: bool,
    pub expect100timeout: f64,
    pub suppress_connect_headers: bool,
    pub synthetic_error: u32,
    pub ssh_compression: bool,
    pub happy_eyeballs_timeout_ms: i64,
    pub haproxy_protocol: bool,
    pub disallow_username_in_url: bool,
    pub aws_sigv4: * mut i8,
    pub global: * mut crate::src::src::tool_cb_dbg::GlobalConfig,
    pub prev: * mut crate::src::src::tool_cb_dbg::OperationConfig,
    pub next: * mut crate::src::src::tool_cb_dbg::OperationConfig,
    pub state: crate::src::src::tool_cb_dbg::State,
}
impl OperationConfig {
    pub const fn new() -> Self {
        OperationConfig {
        remote_time: false,
        random_file: (0 as * mut i8),
        egd_file: (0 as * mut i8),
        useragent: (0 as * mut i8),
        cookies: (0 as * mut crate::src::lib::http2::curl_slist),
        cookiejar: (0 as * mut i8),
        cookiefiles: (0 as * mut crate::src::lib::http2::curl_slist),
        altsvc: (0 as * mut i8),
        hsts: (0 as * mut i8),
        cookiesession: false,
        encoding: false,
        tr_encoding: false,
        authtype: 0,
        use_resume: false,
        resume_from_current: false,
        disable_epsv: false,
        disable_eprt: false,
        ftp_pret: false,
        proto: 0,
        proto_present: false,
        proto_redir: 0,
        proto_redir_present: false,
        proto_default: (0 as * mut i8),
        resume_from: 0,
        postfields: (0 as * mut i8),
        postfieldsize: 0,
        referer: (0 as * mut i8),
        timeout: 0.0,
        connecttimeout: 0.0,
        maxredirs: 0,
        max_filesize: 0,
        output_dir: (0 as * mut i8),
        headerfile: (0 as * mut i8),
        ftpport: (0 as * mut i8),
        iface: (0 as * mut i8),
        localport: 0,
        localportrange: 0,
        porttouse: 0,
        range: (0 as * mut i8),
        low_speed_limit: 0,
        low_speed_time: 0,
        dns_servers: (0 as * mut i8),
        dns_interface: (0 as * mut i8),
        dns_ipv4_addr: (0 as * mut i8),
        dns_ipv6_addr: (0 as * mut i8),
        userpwd: (0 as * mut i8),
        login_options: (0 as * mut i8),
        tls_username: (0 as * mut i8),
        tls_password: (0 as * mut i8),
        tls_authtype: (0 as * mut i8),
        proxy_tls_username: (0 as * mut i8),
        proxy_tls_password: (0 as * mut i8),
        proxy_tls_authtype: (0 as * mut i8),
        proxyuserpwd: (0 as * mut i8),
        proxy: (0 as * mut i8),
        proxyver: 0,
        noproxy: (0 as * mut i8),
        mail_from: (0 as * mut i8),
        mail_rcpt: (0 as * mut crate::src::lib::http2::curl_slist),
        mail_auth: (0 as * mut i8),
        mail_rcpt_allowfails: false,
        sasl_authzid: (0 as * mut i8),
        sasl_ir: false,
        proxytunnel: false,
        ftp_append: false,
        use_ascii: false,
        autoreferer: false,
        failonerror: false,
        failwithbody: false,
        show_headers: false,
        no_body: false,
        dirlistonly: false,
        followlocation: false,
        unrestricted_auth: false,
        netrc_opt: false,
        netrc: false,
        netrc_file: (0 as * mut i8),
        url_list: (0 as * mut crate::src::src::tool_cb_dbg::getout),
        url_last: (0 as * mut crate::src::src::tool_cb_dbg::getout),
        url_get: (0 as * mut crate::src::src::tool_cb_dbg::getout),
        url_out: (0 as * mut crate::src::src::tool_cb_dbg::getout),
        url_ul: (0 as * mut crate::src::src::tool_cb_dbg::getout),
        doh_url: (0 as * mut i8),
        cipher_list: (0 as * mut i8),
        proxy_cipher_list: (0 as * mut i8),
        cipher13_list: (0 as * mut i8),
        proxy_cipher13_list: (0 as * mut i8),
        cert: (0 as * mut i8),
        proxy_cert: (0 as * mut i8),
        cert_type: (0 as * mut i8),
        proxy_cert_type: (0 as * mut i8),
        cacert: (0 as * mut i8),
        proxy_cacert: (0 as * mut i8),
        capath: (0 as * mut i8),
        proxy_capath: (0 as * mut i8),
        crlfile: (0 as * mut i8),
        proxy_crlfile: (0 as * mut i8),
        pinnedpubkey: (0 as * mut i8),
        proxy_pinnedpubkey: (0 as * mut i8),
        key: (0 as * mut i8),
        proxy_key: (0 as * mut i8),
        key_type: (0 as * mut i8),
        proxy_key_type: (0 as * mut i8),
        key_passwd: (0 as * mut i8),
        proxy_key_passwd: (0 as * mut i8),
        pubkey: (0 as * mut i8),
        hostpubmd5: (0 as * mut i8),
        engine: (0 as * mut i8),
        etag_save_file: (0 as * mut i8),
        etag_compare_file: (0 as * mut i8),
        crlf: false,
        customrequest: (0 as * mut i8),
        ssl_ec_curves: (0 as * mut i8),
        krblevel: (0 as * mut i8),
        request_target: (0 as * mut i8),
        httpversion: 0,
        http09_allowed: false,
        nobuffer: false,
        readbusy: false,
        globoff: false,
        use_httpget: false,
        insecure_ok: false,
        doh_insecure_ok: false,
        proxy_insecure_ok: false,
        terminal_binary_ok: false,
        verifystatus: false,
        doh_verifystatus: false,
        create_dirs: false,
        ftp_create_dirs: false,
        ftp_skip_ip: false,
        proxynegotiate: false,
        proxyntlm: false,
        proxydigest: false,
        proxybasic: false,
        proxyanyauth: false,
        writeout: (0 as * mut i8),
        quote: (0 as * mut crate::src::lib::http2::curl_slist),
        postquote: (0 as * mut crate::src::lib::http2::curl_slist),
        prequote: (0 as * mut crate::src::lib::http2::curl_slist),
        ssl_version: 0,
        ssl_version_max: 0,
        proxy_ssl_version: 0,
        ip_version: 0,
        create_file_mode: 0,
        timecond: 0,
        condtime: 0,
        headers: (0 as * mut crate::src::lib::http2::curl_slist),
        proxyheaders: (0 as * mut crate::src::lib::http2::curl_slist),
        mimeroot: (0 as * mut crate::src::src::tool_cb_dbg::tool_mime),
        mimecurrent: (0 as * mut crate::src::src::tool_cb_dbg::tool_mime),
        mimepost: (0 as * mut crate::src::lib::http2::curl_mime),
        telnet_options: (0 as * mut crate::src::lib::http2::curl_slist),
        resolve: (0 as * mut crate::src::lib::http2::curl_slist),
        connect_to: (0 as * mut crate::src::lib::http2::curl_slist),
        httpreq: 0,
        sendpersecond: 0,
        recvpersecond: 0,
        ftp_ssl: false,
        ftp_ssl_reqd: false,
        ftp_ssl_control: false,
        ftp_ssl_ccc: false,
        ftp_ssl_ccc_mode: 0,
        preproxy: (0 as * mut i8),
        socks5_gssapi_nec: 0,
        socks5_auth: 0,
        proxy_service_name: (0 as * mut i8),
        service_name: (0 as * mut i8),
        tcp_nodelay: false,
        tcp_fastopen: false,
        req_retry: 0,
        retry_all_errors: false,
        retry_connrefused: false,
        retry_delay: 0,
        retry_maxtime: 0,
        ftp_account: (0 as * mut i8),
        ftp_alternative_to_user: (0 as * mut i8),
        ftp_filemethod: 0,
        tftp_blksize: 0,
        tftp_no_options: false,
        ignorecl: false,
        disable_sessionid: false,
        raw: false,
        post301: false,
        post302: false,
        post303: false,
        nokeepalive: false,
        alivetime: 0,
        content_disposition: false,
        default_node_flags: 0,
        xattr: false,
        gssapi_delegation: 0,
        ssl_allow_beast: false,
        proxy_ssl_allow_beast: false,
        ssl_no_revoke: false,
        ssl_revoke_best_effort: false,
        native_ca_store: false,
        ssl_auto_client_cert: false,
        proxy_ssl_auto_client_cert: false,
        oauth_bearer: (0 as * mut i8),
        nonpn: false,
        noalpn: false,
        unix_socket_path: (0 as * mut i8),
        abstract_unix_socket: false,
        falsestart: false,
        path_as_is: false,
        expect100timeout: 0.0,
        suppress_connect_headers: false,
        synthetic_error: 0,
        ssh_compression: false,
        happy_eyeballs_timeout_ms: 0,
        haproxy_protocol: false,
        disallow_username_in_url: false,
        aws_sigv4: (0 as * mut i8),
        global: (0 as * mut crate::src::src::tool_cb_dbg::GlobalConfig),
        prev: (0 as * mut crate::src::src::tool_cb_dbg::OperationConfig),
        next: (0 as * mut crate::src::src::tool_cb_dbg::OperationConfig),
        state: crate::src::src::tool_cb_dbg::State::new()
        }
    }
}

impl std::default::Default for OperationConfig {
    fn default() -> Self { OperationConfig::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct State {
    pub urlnode: * mut crate::src::src::tool_cb_dbg::getout,
    pub inglob: * mut crate::src::src::tool_cb_dbg::URLGlob,
    pub urls: * mut crate::src::src::tool_cb_dbg::URLGlob,
    pub outfiles: * mut i8,
    pub httpgetfields: * mut i8,
    pub uploadfile: * mut i8,
    pub infilenum: u64,
    pub up: u64,
    pub urlnum: u64,
    pub li: u64,
}
impl State {
    pub const fn new() -> Self {
        State {
        urlnode: (0 as * mut crate::src::src::tool_cb_dbg::getout),
        inglob: (0 as * mut crate::src::src::tool_cb_dbg::URLGlob),
        urls: (0 as * mut crate::src::src::tool_cb_dbg::URLGlob),
        outfiles: (0 as * mut i8),
        httpgetfields: (0 as * mut i8),
        uploadfile: (0 as * mut i8),
        infilenum: 0,
        up: 0,
        urlnum: 0,
        li: 0
        }
    }
}

impl std::default::Default for State {
    fn default() -> Self { State::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct URLGlob {
    pub pattern: Option<crate::__laertes_array::CustomSlice<'static, crate::src::src::tool_cb_dbg::URLPattern, [crate::src::src::tool_cb_dbg::URLPattern; 100]>>,
    pub size: u64,
    pub urllen: u64,
    pub glob_buffer: * mut i8,
    pub beenhere: i8,
    pub error: * const i8,
    pub pos: u64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct URLPattern {
    pub type_0: u32,
    pub globindex: i32,
    pub content: crate::src::src::tool_cb_dbg::C2RustUnnamed,
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
impl C2RustUnnamed_0 {
    pub const fn new() -> Self {
        C2RustUnnamed_0 {
        min_n: 0,
        max_n: 0,
        padlength: 0,
        ptr_n: 0,
        step: 0
        }
    }
}

impl std::default::Default for C2RustUnnamed_0 {
    fn default() -> Self { C2RustUnnamed_0::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub min_c: i8,
    pub max_c: i8,
    pub ptr_c: i8,
    pub step: i32,
}
impl C2RustUnnamed_1 {
    pub const fn new() -> Self {
        C2RustUnnamed_1 {
        min_c: 0,
        max_c: 0,
        ptr_c: 0,
        step: 0
        }
    }
}

impl std::default::Default for C2RustUnnamed_1 {
    fn default() -> Self { C2RustUnnamed_1::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub elements: * mut * mut i8,
    pub size: i32,
    pub ptr_s: i32,
}
impl C2RustUnnamed_2 {
    pub const fn new() -> Self {
        C2RustUnnamed_2 {
        elements: (0 as * mut * mut i8),
        size: 0,
        ptr_s: 0
        }
    }
}

impl std::default::Default for C2RustUnnamed_2 {
    fn default() -> Self { C2RustUnnamed_2::new() }
}

pub type URLPatternType = u32;
pub const UPTNumRange: URLPatternType = 3;
pub const UPTCharRange: URLPatternType = 2;
pub const UPTSet: URLPatternType = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct getout {
    pub next: * mut crate::src::src::tool_cb_dbg::getout,
    pub url: * mut i8,
    pub outfile: * mut i8,
    pub infile: * mut i8,
    pub flags: i32,
    pub num: i32,
}
impl getout {
    pub const fn new() -> Self {
        getout {
        next: (0 as * mut crate::src::src::tool_cb_dbg::getout),
        url: (0 as * mut i8),
        outfile: (0 as * mut i8),
        infile: (0 as * mut i8),
        flags: 0,
        num: 0
        }
    }
}

impl std::default::Default for getout {
    fn default() -> Self { getout::new() }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct GlobalConfig {
    pub showerror: i32,
    pub mute: bool,
    pub noprogress: bool,
    pub isatty: bool,
    pub errors: * mut crate::src::lib::http2::_IO_FILE,
    pub errors_fopened: bool,
    pub trace_dump: * mut i8,
    pub trace_stream: * mut crate::src::lib::http2::_IO_FILE,
    pub trace_fopened: bool,
    pub tracetype: u32,
    pub tracetime: bool,
    pub progressmode: i32,
    pub libcurl: * mut i8,
    pub fail_early: bool,
    pub styled_output: bool,
    pub parallel: bool,
    pub parallel_max: i64,
    pub parallel_connect: bool,
    pub help_category: * mut i8,
    pub first: * mut crate::src::src::tool_cb_dbg::OperationConfig,
    pub current: * mut crate::src::src::tool_cb_dbg::OperationConfig,
    pub last: * mut crate::src::src::tool_cb_dbg::OperationConfig,
}
impl GlobalConfig {
    pub const fn new() -> Self {
        GlobalConfig {
        showerror: 0,
        mute: false,
        noprogress: false,
        isatty: false,
        errors: (0 as * mut crate::src::lib::http2::_IO_FILE),
        errors_fopened: false,
        trace_dump: (0 as * mut i8),
        trace_stream: (0 as * mut crate::src::lib::http2::_IO_FILE),
        trace_fopened: false,
        tracetype: 0,
        tracetime: false,
        progressmode: 0,
        libcurl: (0 as * mut i8),
        fail_early: false,
        styled_output: false,
        parallel: false,
        parallel_max: 0,
        parallel_connect: false,
        help_category: (0 as * mut i8),
        first: (0 as * mut crate::src::src::tool_cb_dbg::OperationConfig),
        current: (0 as * mut crate::src::src::tool_cb_dbg::OperationConfig),
        last: (0 as * mut crate::src::src::tool_cb_dbg::OperationConfig)
        }
    }
}

impl std::default::Default for GlobalConfig {
    fn default() -> Self { GlobalConfig::new() }
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
    pub kind: u32,
    pub parent: * mut crate::src::src::tool_cb_dbg::tool_mime,
    pub prev: * mut crate::src::src::tool_cb_dbg::tool_mime,
    pub data: * const i8,
    pub name: * const i8,
    pub filename: * const i8,
    pub type_0: * const i8,
    pub encoder: * const i8,
    pub headers: * mut crate::src::lib::http2::curl_slist,
    pub subparts: * mut crate::src::src::tool_cb_dbg::tool_mime,
    pub origin: i64,
    pub size: i64,
    pub curpos: i64,
    pub config: * mut crate::src::src::tool_cb_dbg::GlobalConfig,
}
impl tool_mime {
    pub const fn new() -> Self {
        tool_mime {
        kind: 0,
        parent: (0 as * mut crate::src::src::tool_cb_dbg::tool_mime),
        prev: (0 as * mut crate::src::src::tool_cb_dbg::tool_mime),
        data: (0 as * const i8),
        name: (0 as * const i8),
        filename: (0 as * const i8),
        type_0: (0 as * const i8),
        encoder: (0 as * const i8),
        headers: (0 as * mut crate::src::lib::http2::curl_slist),
        subparts: (0 as * mut crate::src::src::tool_cb_dbg::tool_mime),
        origin: 0,
        size: 0,
        curpos: 0,
        config: (0 as * mut crate::src::src::tool_cb_dbg::GlobalConfig)
        }
    }
}

impl std::default::Default for tool_mime {
    fn default() -> Self { tool_mime::new() }
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
pub unsafe extern "C" fn tool_debug_cb(
    mut handle: * mut crate::src::lib::http2::Curl_easy,
    mut type_0: u32,
    mut data: * mut i8,
    mut size: u64,
    mut userdata: * mut core::ffi::c_void,
) -> i32 {
    let mut operation: * mut crate::src::src::tool_cb_dbg::OperationConfig = userdata as *mut OperationConfig;
    let mut config: * mut crate::src::src::tool_cb_dbg::GlobalConfig = (*operation).global;
    let mut output: * mut crate::src::lib::http2::_IO_FILE = (*config).errors;
    let mut text: * const i8 = 0 as *const i8;
    let mut tv: crate::src::lib::openldap::timeval = timeval { tv_sec: 0, tv_usec: 0 };
    let mut timebuf: [i8; 20] = [0; 20];
    let mut secs: i64 = 0;
    if (*config).tracetime {
        let mut now: * mut crate::src::lib::altsvc::tm = (0 as * mut crate::src::lib::altsvc::tm);
        static mut epoch_offset: i64 = 0;
        static mut known_offset: i32 = 0;
        tv = tvnow();
        if known_offset == 0 {
            epoch_offset = time(0 as *mut time_t) - tv.tv_sec;
            known_offset = 1 as i32;
        }
        secs = epoch_offset + tv.tv_sec;
        now = localtime(&mut secs);
        curl_msnprintf(
            timebuf.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 20]>() as u64,
            b"%02d:%02d:%02d.%06ld \0" as *const u8 as *const i8,
            (*now).tm_hour,
            (*now).tm_min,
            (*now).tm_sec,
            tv.tv_usec,
        );
    } else {
        timebuf[0 as i32 as usize] = 0 as i32 as i8;
    }
    if ((*config).trace_stream).is_null() {
        if strcmp(b"-\0" as *const u8 as *const i8, (*config).trace_dump) == 0
        {
            let mut fresh0 = &mut ((*config).trace_stream);
            *fresh0 = stdout;
        } else if strcmp(
                b"%\0" as *const u8 as *const i8,
                (*config).trace_dump,
            ) == 0
            {
            let mut fresh1 = &mut ((*config).trace_stream);
            *fresh1 = (*config).errors;
        } else {
            let mut fresh2 = &mut ((*config).trace_stream);
            *fresh2 = fopen(
                (*config).trace_dump,
                b"w\0" as *const u8 as *const i8,
            );
            (*config).trace_fopened = 1 as i32 != 0;
        }
    }
    if !((*config).trace_stream).is_null() {
        output = (*config).trace_stream;
    }
    if output.is_null() {
        warnf(
            config,
            b"Failed to create/open output\0" as *const u8 as *const i8,
        );
        return 0 as i32;
    }
    if (*config).tracetype as u32 == TRACE_PLAIN as i32 as u32
    {
        static mut s_infotype: [* const i8; 7] = [
            b"*\0" as *const u8 as *const i8,
            b"<\0" as *const u8 as *const i8,
            b">\0" as *const u8 as *const i8,
            b"{\0" as *const u8 as *const i8,
            b"}\0" as *const u8 as *const i8,
            b"{\0" as *const u8 as *const i8,
            b"}\0" as *const u8 as *const i8,
        ];
        static mut newl: bool = 0 as i32 != 0;
        static mut traced_data: bool = 0 as i32 != 0;
        match type_0 as u32 {
            2 => {
                if size > 0 as i32 as u64 {
                    let mut st: u64 = 0 as i32 as size_t;
                    let mut i: u64 = 0;
                    i = 0 as i32 as size_t;
                    while i < size.wrapping_sub(1 as i32 as u64) {
                        if *data.offset(i as isize) as i32 == '\n' as i32 {
                            if !newl {
                                curl_mfprintf(
                                    output,
                                    b"%s%s \0" as *const u8 as *const i8,
                                    timebuf.as_mut_ptr(),
                                    s_infotype[type_0 as usize],
                                );
                            }
                            fwrite(
                                data.offset(st as isize) as *const libc::c_void,
                                i
                                    .wrapping_sub(st)
                                    .wrapping_add(1 as i32 as u64),
                                1 as i32 as u64,
                                output,
                            );
                            st = i.wrapping_add(1 as i32 as u64);
                            newl = 0 as i32 != 0;
                        }
                        i = i.wrapping_add(1);
                    }
                    if !newl {
                        curl_mfprintf(
                            output,
                            b"%s%s \0" as *const u8 as *const i8,
                            timebuf.as_mut_ptr(),
                            s_infotype[type_0 as usize],
                        );
                    }
                    fwrite(
                        data.offset(st as isize) as *const libc::c_void,
                        i
                            .wrapping_sub(st)
                            .wrapping_add(1 as i32 as u64),
                        1 as i32 as u64,
                        output,
                    );
                }
                newl = if size != 0
                    && *data
                        .offset(
                            size.wrapping_sub(1 as i32 as u64) as isize,
                        ) as i32 != '\n' as i32
                {
                    1 as i32
                } else {
                    0 as i32
                } != 0;
                traced_data = 0 as i32 != 0;
            }
            0 | 1 => {
                if !newl {
                    curl_mfprintf(
                        output,
                        b"%s%s \0" as *const u8 as *const i8,
                        timebuf.as_mut_ptr(),
                        s_infotype[type_0 as usize],
                    );
                }
                fwrite(
                    data as *const libc::c_void,
                    size,
                    1 as i32 as u64,
                    output,
                );
                newl = if size != 0
                    && *data
                        .offset(
                            size.wrapping_sub(1 as i32 as u64) as isize,
                        ) as i32 != '\n' as i32
                {
                    1 as i32
                } else {
                    0 as i32
                } != 0;
                traced_data = 0 as i32 != 0;
            }
            4 | 3 | 5 | 6 => {
                if !traced_data {
                    if !(*config).isatty || output != stderr && output != stdout {
                        if !newl {
                            curl_mfprintf(
                                output,
                                b"%s%s \0" as *const u8 as *const i8,
                                timebuf.as_mut_ptr(),
                                s_infotype[type_0 as usize],
                            );
                        }
                        curl_mfprintf(
                            output,
                            b"[%zu bytes data]\n\0" as *const u8 as *const i8,
                            size,
                        );
                        newl = 0 as i32 != 0;
                        traced_data = 1 as i32 != 0;
                    }
                }
            }
            _ => {
                newl = 0 as i32 != 0;
                traced_data = 0 as i32 != 0;
            }
        }
        return 0 as i32;
    }
    let mut current_block_72: u64;
    match type_0 as u32 {
        0 => {
            curl_mfprintf(
                output,
                b"%s== Info: %.*s\0" as *const u8 as *const i8,
                timebuf.as_mut_ptr(),
                size as i32,
                data,
            );
            current_block_72 = 7639355510481400074;
        }
        2 => {
            text = b"=> Send header\0" as *const u8 as *const i8;
            current_block_72 = 12027283704867122503;
        }
        4 => {
            text = b"=> Send data\0" as *const u8 as *const i8;
            current_block_72 = 12027283704867122503;
        }
        1 => {
            text = b"<= Recv header\0" as *const u8 as *const i8;
            current_block_72 = 12027283704867122503;
        }
        3 => {
            text = b"<= Recv data\0" as *const u8 as *const i8;
            current_block_72 = 12027283704867122503;
        }
        5 => {
            text = b"<= Recv SSL data\0" as *const u8 as *const i8;
            current_block_72 = 12027283704867122503;
        }
        6 => {
            text = b"=> Send SSL data\0" as *const u8 as *const i8;
            current_block_72 = 12027283704867122503;
        }
        _ => {
            current_block_72 = 7639355510481400074;
        }
    }
    match current_block_72 {
        12027283704867122503 => {}
        _ => return 0 as i32,
    }
    dump(
        timebuf.as_mut_ptr(),
        text,
        output,
        data as *mut u8,
        size,
        (*config).tracetype,
        type_0,
    );
    return 0 as i32;
}
unsafe extern "C" fn dump(
    mut timebuf: * const i8,
    mut text: * const i8,
    mut stream: * mut crate::src::lib::http2::_IO_FILE,
    mut ptr: * const u8,
    mut size: u64,
    mut tracetype: u32,
    mut infotype: u32,
) {
    let mut i: u64 = 0;
    let mut c: u64 = 0;
    let mut width: u32 = 0x10 as i32 as u32;
    if tracetype as u32 == TRACE_ASCII as i32 as u32 {
        width = 0x40 as i32 as u32;
    }
    curl_mfprintf(
        stream,
        b"%s%s, %zu bytes (0x%zx)\n\0" as *const u8 as *const i8,
        timebuf,
        text,
        size,
        size,
    );
    i = 0 as i32 as size_t;
    while i < size {
        curl_mfprintf(stream, b"%04zx: \0" as *const u8 as *const i8, i);
        if tracetype as u32 == TRACE_BIN as i32 as u32 {
            c = 0 as i32 as size_t;
            while c < width as u64 {
                if i.wrapping_add(c) < size {
                    curl_mfprintf(
                        stream,
                        b"%02x \0" as *const u8 as *const i8,
                        *ptr.offset(i.wrapping_add(c) as isize) as i32,
                    );
                } else {
                    fputs(b"   \0" as *const u8 as *const i8, stream);
                }
                c = c.wrapping_add(1);
            }
        }
        c = 0 as i32 as size_t;
        while c < width as u64 && i.wrapping_add(c) < size {
            if tracetype as u32 == TRACE_ASCII as i32 as u32
                && i.wrapping_add(c).wrapping_add(1 as i32 as u64)
                    < size
                && *ptr.offset(i.wrapping_add(c) as isize) as i32
                    == 0xd as i32
                && *ptr
                    .offset(
                        i.wrapping_add(c).wrapping_add(1 as i32 as u64)
                            as isize,
                    ) as i32 == 0xa as i32
            {
                i = (i as u64)
                    .wrapping_add(
                        c
                            .wrapping_add(2 as i32 as u64)
                            .wrapping_sub(width as u64),
                    ) as size_t as size_t;
                break;
            } else {
                curl_mfprintf(
                    stream,
                    b"%c\0" as *const u8 as *const i8,
                    if *ptr.offset(i.wrapping_add(c) as isize) as i32
                        >= 0x20 as i32
                        && (*ptr.offset(i.wrapping_add(c) as isize) as i32)
                            < 0x80 as i32
                    {
                        *ptr.offset(i.wrapping_add(c) as isize) as i32
                    } else {
                        '.' as i32
                    },
                );
                if tracetype as u32
                    == TRACE_ASCII as i32 as u32
                    && i.wrapping_add(c).wrapping_add(2 as i32 as u64)
                        < size
                    && *ptr
                        .offset(
                            i
                                .wrapping_add(c)
                                .wrapping_add(1 as i32 as u64) as isize,
                        ) as i32 == 0xd as i32
                    && *ptr
                        .offset(
                            i
                                .wrapping_add(c)
                                .wrapping_add(2 as i32 as u64) as isize,
                        ) as i32 == 0xa as i32
                {
                    i = (i as u64)
                        .wrapping_add(
                            c
                                .wrapping_add(3 as i32 as u64)
                                .wrapping_sub(width as u64),
                        ) as size_t as size_t;
                    break;
                } else {
                    c = c.wrapping_add(1);
                }
            }
        }
        fputc('\n' as i32, stream);
        i = (i as u64).wrapping_add(width as u64) as size_t
            as size_t;
    }
    fflush(stream);
}
use crate::laertes_rt::*;
