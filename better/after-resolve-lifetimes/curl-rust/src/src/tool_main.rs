use ::libc;
extern "C" {
    
    
    
    
    static mut stderr: * mut crate::src::lib::http2::_IO_FILE;
    
    
    fn fclose(__stream: * mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn malloc(_: u64) -> * mut core::ffi::c_void;
    fn free(__ptr: * mut core::ffi::c_void);
    fn memset(
        _: * mut core::ffi::c_void,
        _: i32,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn close(__fd: i32) -> i32;
    fn pipe(__pipedes: * mut i32) -> i32;
    fn signal(__sig: i32, __handler: Option<unsafe extern "C"  fn(_: i32,) -> ()>) -> Option<unsafe extern "C"  fn(_: i32,) -> ()>;
    
    
    
    
    
}
pub use crate::src::lib::easy::curl_global_cleanup;
pub use crate::src::lib::easy::curl_global_init;
pub use crate::src::src::tool_cfgable::config_free;
pub use crate::src::src::tool_cfgable::config_init;
pub use crate::src::src::tool_libinfo::get_libcurl_info;
pub use crate::src::src::tool_msgs::errorf;
pub use crate::src::src::tool_operate::operate;
pub use crate::src::lib::http2::curl_mime;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type size_t = u64;
pub type curl_off_t = i64;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::lib::http2::_IO_FILE;
// #[derive(Copy, Clone)]

pub type curl_slist = crate::src::lib::http2::curl_slist;
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
pub type __sighandler_t = Option<unsafe extern "C"  fn(_: i32,) -> ()>;
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
pub type URLPatternType = u32;
pub const UPTNumRange: URLPatternType = 3;
pub const UPTCharRange: URLPatternType = 2;
pub const UPTSet: URLPatternType = 1;
// #[derive(Copy, Clone)]

pub type getout = crate::src::src::tool_cb_dbg::getout;
// #[derive(Copy, Clone)]

pub type GlobalConfig = crate::src::src::tool_cb_dbg::GlobalConfig;
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
// #[derive(Copy, Clone)]

pub type tool_mime = crate::src::src::tool_cb_dbg::tool_mime;
pub type toolmimekind = u32;
pub const TOOLMIME_STDINDATA: toolmimekind = 6;
pub const TOOLMIME_STDIN: toolmimekind = 5;
pub const TOOLMIME_FILEDATA: toolmimekind = 4;
pub const TOOLMIME_FILE: toolmimekind = 3;
pub const TOOLMIME_DATA: toolmimekind = 2;
pub const TOOLMIME_PARTS: toolmimekind = 1;
pub const TOOLMIME_NONE: toolmimekind = 0;
unsafe extern "C" fn main_checkfds() {
    let mut fd: [i32; 2] = [0 as i32, 0 as i32];
    while fd[0 as i32 as usize] == 0 as i32
        || fd[0 as i32 as usize] == 1 as i32
        || fd[0 as i32 as usize] == 2 as i32
        || fd[1 as i32 as usize] == 0 as i32
        || fd[1 as i32 as usize] == 1 as i32
        || fd[1 as i32 as usize] == 2 as i32
    {
        if pipe(fd.as_mut_ptr()) < 0 as i32 {
            return;
        }
    }
    close(fd[0 as i32 as usize]);
    close(fd[1 as i32 as usize]);
}
unsafe extern "C" fn main_init(mut config: * mut crate::src::src::tool_cb_dbg::GlobalConfig) -> u32 {
    let mut result: u32 = CURLE_OK;
    (*config).showerror = -(1 as i32);
    let mut fresh0 = &mut ((*config).errors);
    *fresh0 = stderr;
    (*config).styled_output = 1 as i32 != 0;
    (*config).parallel_max = 50 as i32 as i64;
    let mut fresh1 = &mut ((*config).last);
    *fresh1 = malloc(::std::mem::size_of::<OperationConfig>() as u64)
        as *mut OperationConfig;
    let mut fresh2 = &mut ((*config).first);
    *fresh2 = *fresh1;
    if !((*config).first).is_null() {
        result = curl_global_init(
            ((1 as i32) << 0 as i32
                | (1 as i32) << 1 as i32) as i64,
        );
        if result as u64 == 0 {
            result = get_libcurl_info();
            if result as u64 == 0 {
                config_init((*config).first);
                let mut fresh3 = &mut ((*(*config).first).global);
                *fresh3 = config;
            } else {
                errorf(
                    config,
                    b"error retrieving curl library information\n\0" as *const u8
                        as *const i8,
                );
                free((*config).first as *mut libc::c_void);
            }
        } else {
            errorf(
                config,
                b"error initializing curl library\n\0" as *const u8
                    as *const i8,
            );
            free((*config).first as *mut libc::c_void);
        }
    } else {
        errorf(
            config,
            b"error initializing curl\n\0" as *const u8 as *const i8,
        );
        result = CURLE_FAILED_INIT;
    }
    return result;
}
unsafe extern "C" fn free_globalconfig<'a1>(mut config: Option<&'a1 mut crate::src::src::tool_cb_dbg::GlobalConfig>) {
    free((*(borrow_mut(&mut config)).unwrap()).trace_dump as *mut libc::c_void);
    let mut fresh4 = &mut ((*(borrow_mut(&mut config)).unwrap()).trace_dump);
    *fresh4 = 0 as *mut i8;
    if (*(borrow(& config)).unwrap()).errors_fopened as i32 != 0 && !((*(borrow_mut(&mut config)).unwrap()).errors).is_null() {
        fclose((*(borrow_mut(&mut config)).unwrap()).errors);
    }
    let mut fresh5 = &mut ((*(borrow_mut(&mut config)).unwrap()).errors);
    *fresh5 = 0 as *mut FILE;
    if (*(borrow(& config)).unwrap()).trace_fopened as i32 != 0 && !((*(borrow_mut(&mut config)).unwrap()).trace_stream).is_null()
    {
        fclose((*(borrow_mut(&mut config)).unwrap()).trace_stream);
    }
    let mut fresh6 = &mut ((*(borrow_mut(&mut config)).unwrap()).trace_stream);
    *fresh6 = 0 as *mut FILE;
    free((*(borrow_mut(&mut config)).unwrap()).libcurl as *mut libc::c_void);
    let mut fresh7 = &mut ((*(borrow_mut(&mut config)).unwrap()).libcurl);
    *fresh7 = 0 as *mut i8;
}
unsafe extern "C" fn main_free<'a1>(mut config: Option<&'a1 mut crate::src::src::tool_cb_dbg::GlobalConfig>) {
    curl_global_cleanup();
    free_globalconfig(borrow_mut(&mut config));
    config_free((*(borrow_mut(&mut config)).unwrap()).last);
    let mut fresh8 = &mut ((*(borrow_mut(&mut config)).unwrap()).first);
    *fresh8 = 0 as *mut OperationConfig;
    let mut fresh9 = &mut ((*(borrow_mut(&mut config)).unwrap()).last);
    *fresh9 = 0 as *mut OperationConfig;
}
unsafe fn main_0(
    mut argc: i32,
    mut argv: * mut * mut i8,
) -> i32 {
    let mut result: u32 = CURLE_OK;
    let mut global: crate::src::src::tool_cb_dbg::GlobalConfig = GlobalConfig {
        showerror: 0,
        mute: false,
        noprogress: false,
        isatty: false,
        errors: 0 as *mut FILE,
        errors_fopened: false,
        trace_dump: 0 as *mut i8,
        trace_stream: 0 as *mut FILE,
        trace_fopened: false,
        tracetype: TRACE_NONE,
        tracetime: false,
        progressmode: 0,
        libcurl: 0 as *mut i8,
        fail_early: false,
        styled_output: false,
        parallel: false,
        parallel_max: 0,
        parallel_connect: false,
        help_category: 0 as *mut i8,
        first: 0 as *mut OperationConfig,
        current: 0 as *mut OperationConfig,
        last: 0 as *mut OperationConfig,
    };
    memset(
        &mut global as *mut GlobalConfig as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<GlobalConfig>() as u64,
    );
    main_checkfds();
    signal(
        13 as i32,
        core::intrinsics::transmute::<isize, Option<unsafe extern "C"  fn(_: i32,) -> ()>>(1 as i32 as libc::intptr_t),
    );
    result = main_init(&mut global);
    if result as u64 == 0 {
        result = operate(&mut global, argc, argv);
        main_free(Some(&mut global));
    }
    return result as i32;
}
pub fn main() {
    let mut args: Vec::<*mut i8> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::std::ptr::null_mut());
    unsafe {
        ::std::process::exit(
            main_0(
                (args.len() - 1) as i32,
                args.as_mut_ptr() as *mut *mut i8,
            ) as i32,
        )
    }
}
use crate::laertes_rt::*;
