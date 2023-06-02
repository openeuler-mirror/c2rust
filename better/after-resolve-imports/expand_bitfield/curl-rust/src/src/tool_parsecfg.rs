use ::libc;
extern "C" {
    
    
    
    
    static mut stdin: *mut FILE;
    fn fclose(__stream: *mut FILE) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut FILE;
    fn fgets(
        __s: *mut i8,
        __n: i32,
        __stream: *mut FILE,
    ) -> *mut i8;
    
    fn malloc(_: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    
    
    
    
    
    
    
    fn curlx_dyn_init(s: *mut dynbuf, toobig: size_t);
    fn curlx_dyn_free(s: *mut dynbuf);
    fn curlx_dyn_add(s: *mut dynbuf, str: *const i8) -> CURLcode;
    fn curlx_dyn_reset(s: *mut dynbuf);
    fn curlx_dyn_ptr(s: *const dynbuf) -> *mut i8;
    fn curlx_dyn_len(s: *const dynbuf) -> size_t;
}
pub use crate::src::lib::curl_ctype::Curl_isspace;
pub use crate::src::lib::escape::curl_free;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::src::tool_cfgable::config_init;
pub use crate::src::src::tool_getparam::getparameter;
pub use crate::src::src::tool_helpers::param2text;
pub use crate::src::src::tool_homedir::homedir;
pub use crate::src::src::tool_msgs::warnf;
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
pub type CURLcode = crate::src::lib::http2::CURLcode;
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
pub type ParameterError = crate::src::src::tool_formparse::ParameterError;
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
// #[derive(Copy, Clone)]

pub type dynbuf = crate::src::lib::http2::dynbuf;
#[no_mangle]
pub unsafe extern "C" fn parseconfig(
    mut filename: *const i8,
    mut global: *mut GlobalConfig,
) -> i32 {
    let mut file: *mut FILE = 0 as *mut FILE;
    let mut usedarg: bool = 0 as i32 != 0;
    let mut rc: i32 = 0 as i32;
    let mut operation: *mut OperationConfig = (*global).last;
    let mut pathalloc: *mut i8 = 0 as *mut i8;
    if filename.is_null() || *filename == 0 {
        let mut home: *mut i8 = homedir(
            b".curlrc\0" as *const u8 as *const i8,
        );
        if !home.is_null() {
            pathalloc = curl_maprintf(
                b"%s%s.curlrc\0" as *const u8 as *const i8,
                home,
                b"/\0" as *const u8 as *const i8,
            );
            if pathalloc.is_null() {
                free(home as *mut libc::c_void);
                return 1 as i32;
            }
            filename = pathalloc;
        }
        free(home as *mut libc::c_void);
        home = 0 as *mut i8;
    }
    if file.is_null() && !filename.is_null() {
        if strcmp(filename, b"-\0" as *const u8 as *const i8) != 0 {
            file = fopen(filename, b"r\0" as *const u8 as *const i8);
        } else {
            file = stdin;
        }
    }
    if !file.is_null() {
        let mut line: *mut i8 = 0 as *mut i8;
        let mut option: *mut i8 = 0 as *mut i8;
        let mut param: *mut i8 = 0 as *mut i8;
        let mut lineno: i32 = 0 as i32;
        let mut dashed_option: bool = false;
        let mut buf: dynbuf = dynbuf {
            bufr: 0 as *mut i8,
            leng: 0,
            allc: 0,
            toobig: 0,
        };
        let mut fileerror: bool = false;
        curlx_dyn_init(&mut buf, (100 as i32 * 1024 as i32) as size_t);
        while my_get_line(file, &mut buf, &mut fileerror) {
            let mut res: i32 = 0;
            let mut alloced_param: bool = 0 as i32 != 0;
            lineno += 1;
            line = curlx_dyn_ptr(&mut buf);
            if line.is_null() {
                rc = 1 as i32;
                break;
            } else {
                while *line as i32 != 0
                    && Curl_isspace(*line as u8 as i32) != 0
                {
                    line = line.offset(1);
                }
                match *line as i32 {
                    35 | 47 | 13 | 10 | 42 | 0 => {
                        curlx_dyn_reset(&mut buf);
                    }
                    _ => {
                        option = line;
                        dashed_option = if *option.offset(0 as i32 as isize)
                            as i32 == '-' as i32
                        {
                            1 as i32
                        } else {
                            0 as i32
                        } != 0;
                        while *line as i32 != 0
                            && Curl_isspace(*line as u8 as i32) == 0
                            && !(!dashed_option
                                && (*line as i32 == '=' as i32
                                    || *line as i32 == ':' as i32))
                        {
                            line = line.offset(1);
                        }
                        if *line != 0 {
                            let fresh0 = line;
                            line = line.offset(1);
                            *fresh0 = '\u{0}' as i32 as i8;
                        }
                        while *line as i32 != 0
                            && (Curl_isspace(*line as u8 as i32) != 0
                                || !dashed_option
                                    && (*line as i32 == '=' as i32
                                        || *line as i32 == ':' as i32))
                        {
                            line = line.offset(1);
                        }
                        if *line as i32 == '"' as i32 {
                            line = line.offset(1);
                            param = malloc(
                                (strlen(line))
                                    .wrapping_add(1 as i32 as u64),
                            ) as *mut i8;
                            if param.is_null() {
                                rc = 1 as i32;
                                break;
                            } else {
                                alloced_param = 1 as i32 != 0;
                                unslashquote(line, param);
                            }
                        } else {
                            param = line;
                            while *line as i32 != 0
                                && Curl_isspace(*line as u8 as i32) == 0
                            {
                                line = line.offset(1);
                            }
                            if *line != 0 {
                                *line = '\u{0}' as i32 as i8;
                                line = line.offset(1);
                                while *line as i32 != 0
                                    && Curl_isspace(*line as u8 as i32) != 0
                                {
                                    line = line.offset(1);
                                }
                                match *line as i32 {
                                    0 | 13 | 10 | 35 => {}
                                    _ => {
                                        warnf(
                                            (*operation).global,
                                            b"%s:%d: warning: '%s' uses unquoted whitespace in the line that may cause side-effects!\n\0"
                                                as *const u8 as *const i8,
                                            filename,
                                            lineno,
                                            option,
                                        );
                                    }
                                }
                            }
                            if *param == 0 {
                                param = 0 as *mut i8;
                            }
                        }
                        res = getparameter(
                            option,
                            param,
                            &mut usedarg,
                            global,
                            operation,
                        ) as i32;
                        operation = (*global).last;
                        if res == 0 && !param.is_null() && *param as i32 != 0
                            && !usedarg
                        {
                            res = PARAM_GOT_EXTRA_PARAMETER as i32;
                        }
                        if res == PARAM_NEXT_OPERATION as i32 {
                            if !((*operation).url_list).is_null()
                                && !((*(*operation).url_list).url).is_null()
                            {
                                let ref mut fresh1 = (*operation).next;
                                *fresh1 = malloc(
                                    ::std::mem::size_of::<OperationConfig>() as u64,
                                ) as *mut OperationConfig;
                                if !((*operation).next).is_null() {
                                    config_init((*operation).next);
                                    let ref mut fresh2 = (*(*operation).next).global;
                                    *fresh2 = global;
                                    let ref mut fresh3 = (*global).last;
                                    *fresh3 = (*operation).next;
                                    let ref mut fresh4 = (*(*operation).next).prev;
                                    *fresh4 = operation;
                                    operation = (*operation).next;
                                } else {
                                    res = PARAM_NO_MEM as i32;
                                }
                            }
                        }
                        if res != PARAM_OK as i32
                            && res != PARAM_NEXT_OPERATION as i32
                        {
                            if strcmp(
                                filename,
                                b"-\0" as *const u8 as *const i8,
                            ) == 0
                            {
                                filename = b"<stdin>\0" as *const u8 as *const i8;
                            }
                            if res != PARAM_HELP_REQUESTED as i32
                                && res != PARAM_MANUAL_REQUESTED as i32
                                && res != PARAM_VERSION_INFO_REQUESTED as i32
                                && res != PARAM_ENGINES_REQUESTED as i32
                            {
                                let mut reason: *const i8 = param2text(res);
                                warnf(
                                    (*operation).global,
                                    b"%s:%d: warning: '%s' %s\n\0" as *const u8
                                        as *const i8,
                                    filename,
                                    lineno,
                                    option,
                                    reason,
                                );
                            }
                        }
                        if alloced_param {
                            free(param as *mut libc::c_void);
                            param = 0 as *mut i8;
                        }
                        curlx_dyn_reset(&mut buf);
                    }
                }
            }
        }
        curlx_dyn_free(&mut buf);
        if file != stdin {
            fclose(file);
        }
        if fileerror {
            rc = 1 as i32;
        }
    } else {
        rc = 1 as i32;
    }
    curl_free(pathalloc as *mut libc::c_void);
    return rc;
}
unsafe extern "C" fn unslashquote(
    mut line: *const i8,
    mut param: *mut i8,
) -> *const i8 {
    while *line as i32 != 0 && *line as i32 != '"' as i32 {
        if *line as i32 == '\\' as i32 {
            let mut out: i8 = 0;
            line = line.offset(1);
            out = *line;
            match out as i32 {
                0 => {
                    continue;
                }
                116 => {
                    out = '\t' as i32 as i8;
                }
                110 => {
                    out = '\n' as i32 as i8;
                }
                114 => {
                    out = '\r' as i32 as i8;
                }
                118 => {
                    out = '\u{b}' as i32 as i8;
                }
                _ => {}
            }
            let fresh5 = param;
            param = param.offset(1);
            *fresh5 = out;
            line = line.offset(1);
        } else {
            let fresh6 = line;
            line = line.offset(1);
            let fresh7 = param;
            param = param.offset(1);
            *fresh7 = *fresh6;
        }
    }
    *param = '\u{0}' as i32 as i8;
    return line;
}
unsafe extern "C" fn my_get_line(
    mut fp: *mut FILE,
    mut db: *mut dynbuf,
    mut error: *mut bool,
) -> bool {
    let mut buf: [i8; 4096] = [0; 4096];
    *error = 0 as i32 != 0;
    loop {
        if (fgets(
            buf.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 4096]>() as u64
                as i32,
            fp,
        ))
            .is_null()
        {
            return if curlx_dyn_len(db) != 0 {
                1 as i32
            } else {
                0 as i32
            } != 0;
        }
        if curlx_dyn_add(db, buf.as_mut_ptr()) as u64 != 0 {
            *error = 1 as i32 != 0;
            return 0 as i32 != 0;
        }
        if !(strchr(buf.as_mut_ptr(), '\n' as i32)).is_null() {
            break;
        }
    }
    return 1 as i32 != 0;
}
