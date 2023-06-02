use ::libc;
extern "C" {
    
    
    
    
    
    
    fn free(__ptr: *mut libc::c_void);
    fn memset(
        _: *mut libc::c_void,
        _: i32,
        _: u64,
    ) -> *mut libc::c_void;
    
}
pub use crate::src::lib::mime::curl_mime_free;
pub use crate::src::lib::slist::curl_slist_free_all;
pub use crate::src::src::tool_formparse::tool_mime_free;
pub use crate::src::lib::http2::curl_mime;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub type __off_t = crate::src::lib::http2::__off_t;
pub type __off64_t = crate::src::lib::http2::__off64_t;
pub type size_t = crate::src::lib::http2::size_t;
pub type curl_off_t = crate::src::lib::http2::curl_off_t;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = crate::src::lib::http2::_IO_lock_t;
pub type FILE = crate::src::lib::http2::FILE;
// #[derive(Copy, Clone)]

pub type curl_slist = crate::src::lib::http2::curl_slist;
pub type curl_TimeCond = crate::src::lib::http2::curl_TimeCond;
pub const CURL_TIMECOND_LAST: curl_TimeCond = 4;
pub const CURL_TIMECOND_LASTMOD: curl_TimeCond = 3;
pub const CURL_TIMECOND_IFUNMODSINCE: curl_TimeCond = 2;
pub const CURL_TIMECOND_IFMODSINCE: curl_TimeCond = 1;
pub const CURL_TIMECOND_NONE: curl_TimeCond = 0;
// #[derive(Copy, Clone)]

pub type OperationConfig = crate::src::src::tool_cb_dbg::OperationConfig;
// #[derive(Copy, Clone)]

pub type State = crate::src::src::tool_cb_dbg::State;
// #[derive(Copy, Clone)]

pub type URLGlob = crate::src::src::tool_cb_dbg::URLGlob;
// #[derive(Copy, Clone)]

pub type URLPattern = crate::src::src::tool_cb_dbg::URLPattern;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed = crate::src::src::tool_cb_dbg::C2RustUnnamed;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_0 = crate::src::src::tool_cb_dbg::C2RustUnnamed_0;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_1 = crate::src::src::tool_cb_dbg::C2RustUnnamed_1;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_2 = crate::src::src::tool_cb_dbg::C2RustUnnamed_2;
pub type URLPatternType = crate::src::src::tool_cb_dbg::URLPatternType;
pub const UPTNumRange: URLPatternType = 3;
pub const UPTCharRange: URLPatternType = 2;
pub const UPTSet: URLPatternType = 1;
// #[derive(Copy, Clone)]

pub type getout = crate::src::src::tool_cb_dbg::getout;
// #[derive(Copy, Clone)]

pub type GlobalConfig = crate::src::src::tool_cb_dbg::GlobalConfig;
pub type trace = crate::src::src::tool_cb_dbg::trace;
pub const TRACE_PLAIN: trace = 3;
pub const TRACE_ASCII: trace = 2;
pub const TRACE_BIN: trace = 1;
pub const TRACE_NONE: trace = 0;
pub type curl_error = crate::src::src::tool_cb_dbg::curl_error;
pub const ERR_LAST: curl_error = 2;
pub const ERR_BINARY_TERMINAL: curl_error = 1;
pub const ERR_NONE: curl_error = 0;
pub type HttpReq = crate::src::src::tool_cb_dbg::HttpReq;
pub const HTTPREQ_SIMPLEPOST: HttpReq = 4;
pub const HTTPREQ_MIMEPOST: HttpReq = 3;
pub const HTTPREQ_HEAD: HttpReq = 2;
pub const HTTPREQ_GET: HttpReq = 1;
pub const HTTPREQ_UNSPEC: HttpReq = 0;
// #[derive(Copy, Clone)]

pub type tool_mime = crate::src::src::tool_cb_dbg::tool_mime;
pub type toolmimekind = crate::src::src::tool_cb_dbg::toolmimekind;
pub const TOOLMIME_STDINDATA: toolmimekind = 6;
pub const TOOLMIME_STDIN: toolmimekind = 5;
pub const TOOLMIME_FILEDATA: toolmimekind = 4;
pub const TOOLMIME_FILE: toolmimekind = 3;
pub const TOOLMIME_DATA: toolmimekind = 2;
pub const TOOLMIME_PARTS: toolmimekind = 1;
pub const TOOLMIME_NONE: toolmimekind = 0;
#[no_mangle]
pub unsafe extern "C" fn config_init(mut config: *mut OperationConfig) {
    memset(
        config as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<OperationConfig>() as u64,
    );
    (*config).postfieldsize = -(1 as i32) as curl_off_t;
    (*config).use_httpget = 0 as i32 != 0;
    (*config).create_dirs = 0 as i32 != 0;
    (*config).maxredirs = 50 as i64;
    (*config).proto = !(0 as i32) as i64;
    (*config).proto_present = 0 as i32 != 0;
    (*config)
        .proto_redir = (!(0 as i32)
        & !((1 as i32) << 10 as i32
            | (1 as i32) << 4 as i32
            | (1 as i32) << 26 as i32
            | (1 as i32) << 27 as i32)) as i64;
    (*config).proto_redir_present = 0 as i32 != 0;
    let ref mut fresh0 = (*config).proto_default;
    *fresh0 = 0 as *mut i8;
    (*config).tcp_nodelay = 1 as i32 != 0;
    (*config).happy_eyeballs_timeout_ms = 200 as i64;
    (*config).http09_allowed = 0 as i32 != 0;
    (*config).ftp_skip_ip = 1 as i32 != 0;
}
unsafe extern "C" fn free_config_fields(mut config: *mut OperationConfig) {
    let mut urlnode: *mut getout = 0 as *mut getout;
    free((*config).random_file as *mut libc::c_void);
    let ref mut fresh1 = (*config).random_file;
    *fresh1 = 0 as *mut i8;
    free((*config).egd_file as *mut libc::c_void);
    let ref mut fresh2 = (*config).egd_file;
    *fresh2 = 0 as *mut i8;
    free((*config).useragent as *mut libc::c_void);
    let ref mut fresh3 = (*config).useragent;
    *fresh3 = 0 as *mut i8;
    free((*config).altsvc as *mut libc::c_void);
    let ref mut fresh4 = (*config).altsvc;
    *fresh4 = 0 as *mut i8;
    free((*config).hsts as *mut libc::c_void);
    let ref mut fresh5 = (*config).hsts;
    *fresh5 = 0 as *mut i8;
    curl_slist_free_all((*config).cookies);
    free((*config).cookiejar as *mut libc::c_void);
    let ref mut fresh6 = (*config).cookiejar;
    *fresh6 = 0 as *mut i8;
    curl_slist_free_all((*config).cookiefiles);
    free((*config).postfields as *mut libc::c_void);
    let ref mut fresh7 = (*config).postfields;
    *fresh7 = 0 as *mut i8;
    free((*config).referer as *mut libc::c_void);
    let ref mut fresh8 = (*config).referer;
    *fresh8 = 0 as *mut i8;
    free((*config).headerfile as *mut libc::c_void);
    let ref mut fresh9 = (*config).headerfile;
    *fresh9 = 0 as *mut i8;
    free((*config).ftpport as *mut libc::c_void);
    let ref mut fresh10 = (*config).ftpport;
    *fresh10 = 0 as *mut i8;
    free((*config).iface as *mut libc::c_void);
    let ref mut fresh11 = (*config).iface;
    *fresh11 = 0 as *mut i8;
    free((*config).range as *mut libc::c_void);
    let ref mut fresh12 = (*config).range;
    *fresh12 = 0 as *mut i8;
    free((*config).userpwd as *mut libc::c_void);
    let ref mut fresh13 = (*config).userpwd;
    *fresh13 = 0 as *mut i8;
    free((*config).tls_username as *mut libc::c_void);
    let ref mut fresh14 = (*config).tls_username;
    *fresh14 = 0 as *mut i8;
    free((*config).tls_password as *mut libc::c_void);
    let ref mut fresh15 = (*config).tls_password;
    *fresh15 = 0 as *mut i8;
    free((*config).tls_authtype as *mut libc::c_void);
    let ref mut fresh16 = (*config).tls_authtype;
    *fresh16 = 0 as *mut i8;
    free((*config).proxy_tls_username as *mut libc::c_void);
    let ref mut fresh17 = (*config).proxy_tls_username;
    *fresh17 = 0 as *mut i8;
    free((*config).proxy_tls_password as *mut libc::c_void);
    let ref mut fresh18 = (*config).proxy_tls_password;
    *fresh18 = 0 as *mut i8;
    free((*config).proxy_tls_authtype as *mut libc::c_void);
    let ref mut fresh19 = (*config).proxy_tls_authtype;
    *fresh19 = 0 as *mut i8;
    free((*config).proxyuserpwd as *mut libc::c_void);
    let ref mut fresh20 = (*config).proxyuserpwd;
    *fresh20 = 0 as *mut i8;
    free((*config).proxy as *mut libc::c_void);
    let ref mut fresh21 = (*config).proxy;
    *fresh21 = 0 as *mut i8;
    free((*config).dns_ipv6_addr as *mut libc::c_void);
    let ref mut fresh22 = (*config).dns_ipv6_addr;
    *fresh22 = 0 as *mut i8;
    free((*config).dns_ipv4_addr as *mut libc::c_void);
    let ref mut fresh23 = (*config).dns_ipv4_addr;
    *fresh23 = 0 as *mut i8;
    free((*config).dns_interface as *mut libc::c_void);
    let ref mut fresh24 = (*config).dns_interface;
    *fresh24 = 0 as *mut i8;
    free((*config).dns_servers as *mut libc::c_void);
    let ref mut fresh25 = (*config).dns_servers;
    *fresh25 = 0 as *mut i8;
    free((*config).noproxy as *mut libc::c_void);
    let ref mut fresh26 = (*config).noproxy;
    *fresh26 = 0 as *mut i8;
    free((*config).mail_from as *mut libc::c_void);
    let ref mut fresh27 = (*config).mail_from;
    *fresh27 = 0 as *mut i8;
    curl_slist_free_all((*config).mail_rcpt);
    free((*config).mail_auth as *mut libc::c_void);
    let ref mut fresh28 = (*config).mail_auth;
    *fresh28 = 0 as *mut i8;
    free((*config).netrc_file as *mut libc::c_void);
    let ref mut fresh29 = (*config).netrc_file;
    *fresh29 = 0 as *mut i8;
    free((*config).output_dir as *mut libc::c_void);
    let ref mut fresh30 = (*config).output_dir;
    *fresh30 = 0 as *mut i8;
    urlnode = (*config).url_list;
    while !urlnode.is_null() {
        let mut next: *mut getout = (*urlnode).next;
        free((*urlnode).url as *mut libc::c_void);
        let ref mut fresh31 = (*urlnode).url;
        *fresh31 = 0 as *mut i8;
        free((*urlnode).outfile as *mut libc::c_void);
        let ref mut fresh32 = (*urlnode).outfile;
        *fresh32 = 0 as *mut i8;
        free((*urlnode).infile as *mut libc::c_void);
        let ref mut fresh33 = (*urlnode).infile;
        *fresh33 = 0 as *mut i8;
        free(urlnode as *mut libc::c_void);
        urlnode = 0 as *mut getout;
        urlnode = next;
    }
    let ref mut fresh34 = (*config).url_list;
    *fresh34 = 0 as *mut getout;
    let ref mut fresh35 = (*config).url_last;
    *fresh35 = 0 as *mut getout;
    let ref mut fresh36 = (*config).url_get;
    *fresh36 = 0 as *mut getout;
    let ref mut fresh37 = (*config).url_out;
    *fresh37 = 0 as *mut getout;
    free((*config).doh_url as *mut libc::c_void);
    let ref mut fresh38 = (*config).doh_url;
    *fresh38 = 0 as *mut i8;
    free((*config).cipher_list as *mut libc::c_void);
    let ref mut fresh39 = (*config).cipher_list;
    *fresh39 = 0 as *mut i8;
    free((*config).proxy_cipher_list as *mut libc::c_void);
    let ref mut fresh40 = (*config).proxy_cipher_list;
    *fresh40 = 0 as *mut i8;
    free((*config).cert as *mut libc::c_void);
    let ref mut fresh41 = (*config).cert;
    *fresh41 = 0 as *mut i8;
    free((*config).proxy_cert as *mut libc::c_void);
    let ref mut fresh42 = (*config).proxy_cert;
    *fresh42 = 0 as *mut i8;
    free((*config).cert_type as *mut libc::c_void);
    let ref mut fresh43 = (*config).cert_type;
    *fresh43 = 0 as *mut i8;
    free((*config).proxy_cert_type as *mut libc::c_void);
    let ref mut fresh44 = (*config).proxy_cert_type;
    *fresh44 = 0 as *mut i8;
    free((*config).cacert as *mut libc::c_void);
    let ref mut fresh45 = (*config).cacert;
    *fresh45 = 0 as *mut i8;
    free((*config).login_options as *mut libc::c_void);
    let ref mut fresh46 = (*config).login_options;
    *fresh46 = 0 as *mut i8;
    free((*config).proxy_cacert as *mut libc::c_void);
    let ref mut fresh47 = (*config).proxy_cacert;
    *fresh47 = 0 as *mut i8;
    free((*config).capath as *mut libc::c_void);
    let ref mut fresh48 = (*config).capath;
    *fresh48 = 0 as *mut i8;
    free((*config).proxy_capath as *mut libc::c_void);
    let ref mut fresh49 = (*config).proxy_capath;
    *fresh49 = 0 as *mut i8;
    free((*config).crlfile as *mut libc::c_void);
    let ref mut fresh50 = (*config).crlfile;
    *fresh50 = 0 as *mut i8;
    free((*config).pinnedpubkey as *mut libc::c_void);
    let ref mut fresh51 = (*config).pinnedpubkey;
    *fresh51 = 0 as *mut i8;
    free((*config).proxy_pinnedpubkey as *mut libc::c_void);
    let ref mut fresh52 = (*config).proxy_pinnedpubkey;
    *fresh52 = 0 as *mut i8;
    free((*config).proxy_crlfile as *mut libc::c_void);
    let ref mut fresh53 = (*config).proxy_crlfile;
    *fresh53 = 0 as *mut i8;
    free((*config).key as *mut libc::c_void);
    let ref mut fresh54 = (*config).key;
    *fresh54 = 0 as *mut i8;
    free((*config).proxy_key as *mut libc::c_void);
    let ref mut fresh55 = (*config).proxy_key;
    *fresh55 = 0 as *mut i8;
    free((*config).key_type as *mut libc::c_void);
    let ref mut fresh56 = (*config).key_type;
    *fresh56 = 0 as *mut i8;
    free((*config).proxy_key_type as *mut libc::c_void);
    let ref mut fresh57 = (*config).proxy_key_type;
    *fresh57 = 0 as *mut i8;
    free((*config).key_passwd as *mut libc::c_void);
    let ref mut fresh58 = (*config).key_passwd;
    *fresh58 = 0 as *mut i8;
    free((*config).proxy_key_passwd as *mut libc::c_void);
    let ref mut fresh59 = (*config).proxy_key_passwd;
    *fresh59 = 0 as *mut i8;
    free((*config).pubkey as *mut libc::c_void);
    let ref mut fresh60 = (*config).pubkey;
    *fresh60 = 0 as *mut i8;
    free((*config).hostpubmd5 as *mut libc::c_void);
    let ref mut fresh61 = (*config).hostpubmd5;
    *fresh61 = 0 as *mut i8;
    free((*config).engine as *mut libc::c_void);
    let ref mut fresh62 = (*config).engine;
    *fresh62 = 0 as *mut i8;
    free((*config).etag_save_file as *mut libc::c_void);
    let ref mut fresh63 = (*config).etag_save_file;
    *fresh63 = 0 as *mut i8;
    free((*config).etag_compare_file as *mut libc::c_void);
    let ref mut fresh64 = (*config).etag_compare_file;
    *fresh64 = 0 as *mut i8;
    free((*config).request_target as *mut libc::c_void);
    let ref mut fresh65 = (*config).request_target;
    *fresh65 = 0 as *mut i8;
    free((*config).customrequest as *mut libc::c_void);
    let ref mut fresh66 = (*config).customrequest;
    *fresh66 = 0 as *mut i8;
    free((*config).krblevel as *mut libc::c_void);
    let ref mut fresh67 = (*config).krblevel;
    *fresh67 = 0 as *mut i8;
    free((*config).oauth_bearer as *mut libc::c_void);
    let ref mut fresh68 = (*config).oauth_bearer;
    *fresh68 = 0 as *mut i8;
    free((*config).sasl_authzid as *mut libc::c_void);
    let ref mut fresh69 = (*config).sasl_authzid;
    *fresh69 = 0 as *mut i8;
    free((*config).unix_socket_path as *mut libc::c_void);
    let ref mut fresh70 = (*config).unix_socket_path;
    *fresh70 = 0 as *mut i8;
    free((*config).writeout as *mut libc::c_void);
    let ref mut fresh71 = (*config).writeout;
    *fresh71 = 0 as *mut i8;
    free((*config).proto_default as *mut libc::c_void);
    let ref mut fresh72 = (*config).proto_default;
    *fresh72 = 0 as *mut i8;
    curl_slist_free_all((*config).quote);
    curl_slist_free_all((*config).postquote);
    curl_slist_free_all((*config).prequote);
    curl_slist_free_all((*config).headers);
    curl_slist_free_all((*config).proxyheaders);
    curl_mime_free((*config).mimepost);
    let ref mut fresh73 = (*config).mimepost;
    *fresh73 = 0 as *mut curl_mime;
    tool_mime_free((*config).mimeroot);
    let ref mut fresh74 = (*config).mimeroot;
    *fresh74 = 0 as *mut tool_mime;
    let ref mut fresh75 = (*config).mimecurrent;
    *fresh75 = 0 as *mut tool_mime;
    curl_slist_free_all((*config).telnet_options);
    curl_slist_free_all((*config).resolve);
    curl_slist_free_all((*config).connect_to);
    free((*config).preproxy as *mut libc::c_void);
    let ref mut fresh76 = (*config).preproxy;
    *fresh76 = 0 as *mut i8;
    free((*config).proxy_service_name as *mut libc::c_void);
    let ref mut fresh77 = (*config).proxy_service_name;
    *fresh77 = 0 as *mut i8;
    free((*config).service_name as *mut libc::c_void);
    let ref mut fresh78 = (*config).service_name;
    *fresh78 = 0 as *mut i8;
    free((*config).ftp_account as *mut libc::c_void);
    let ref mut fresh79 = (*config).ftp_account;
    *fresh79 = 0 as *mut i8;
    free((*config).ftp_alternative_to_user as *mut libc::c_void);
    let ref mut fresh80 = (*config).ftp_alternative_to_user;
    *fresh80 = 0 as *mut i8;
    free((*config).aws_sigv4 as *mut libc::c_void);
    let ref mut fresh81 = (*config).aws_sigv4;
    *fresh81 = 0 as *mut i8;
}
#[no_mangle]
pub unsafe extern "C" fn config_free(mut config: *mut OperationConfig) {
    let mut last: *mut OperationConfig = config;
    while !last.is_null() {
        let mut prev: *mut OperationConfig = (*last).prev;
        free_config_fields(last);
        free(last as *mut libc::c_void);
        last = prev;
    }
}
