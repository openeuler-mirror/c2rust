use ::libc;
extern "C" {
    
    
    
    
    
    
    static mut stdin: *mut FILE;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn calloc(_: u64, _: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strdup(_: *const i8) -> *mut i8;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn strerror(_: i32) -> *mut i8;
    fn __errno_location() -> *mut i32;
    fn __fxstat(
        __ver: i32,
        __fildes: i32,
        __stat_buf: *mut stat,
    ) -> i32;
    fn fclose(__stream: *mut FILE) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut FILE;
    fn sscanf(_: *const i8, _: *const i8, _: ...) -> i32;
    fn getc(__stream: *mut FILE) -> i32;
    fn fseek(
        __stream: *mut FILE,
        __off: i64,
        __whence: i32,
    ) -> i32;
    fn ftell(__stream: *mut FILE) -> i64;
    fn fread(
        _: *mut libc::c_void,
        _: u64,
        _: u64,
        _: *mut FILE,
    ) -> u64;
    fn ferror(__stream: *mut FILE) -> i32;
    fn fileno(__stream: *mut FILE) -> i32;
    
    
    
    
    
}
pub use crate::src::lib::curl_ctype::Curl_isspace;
pub use crate::src::lib::mime::curl_mime_addpart;
pub use crate::src::lib::mime::curl_mime_data;
pub use crate::src::lib::mime::curl_mime_data_cb;
pub use crate::src::lib::mime::curl_mime_encoder;
pub use crate::src::lib::mime::curl_mime_filedata;
pub use crate::src::lib::mime::curl_mime_filename;
pub use crate::src::lib::mime::curl_mime_free;
pub use crate::src::lib::mime::curl_mime_headers;
pub use crate::src::lib::mime::curl_mime_init;
pub use crate::src::lib::mime::curl_mime_name;
pub use crate::src::lib::mime::curl_mime_subparts;
pub use crate::src::lib::mime::curl_mime_type;
pub use crate::src::lib::mprintf::curl_mfprintf;
pub use crate::src::lib::slist::curl_slist_append;
pub use crate::src::lib::slist::curl_slist_free_all;
pub use crate::src::lib::strcase::curl_strnequal;
pub use crate::src::lib::warnless::curlx_sotouz;
pub use crate::src::lib::warnless::curlx_uztoso;
pub use crate::src::src::tool_msgs::warnf;
pub use crate::src::src::tool_paramhlp::file2memory;
pub use crate::src::lib::altsvc::Curl_easy;
pub use crate::src::lib::altsvc::curl_mime;
pub use crate::src::lib::altsvc::curl_mimepart;
pub use crate::src::lib::imap::_IO_marker;
pub use crate::src::lib::speedcheck::_IO_codecvt;
pub use crate::src::lib::vtls::vtls::_IO_wide_data;
pub type __dev_t = crate::src::lib::file::__dev_t;
pub type __uid_t = crate::src::lib::conncache::__uid_t;
pub type __gid_t = crate::src::lib::curl_ntlm_wb::__gid_t;
pub type __ino_t = crate::src::lib::file::__ino_t;
pub type __mode_t = crate::src::lib::file::__mode_t;
pub type __nlink_t = crate::src::lib::file::__nlink_t;
pub type __off_t = crate::src::lib::altsvc::__off_t;
pub type __off64_t = crate::src::lib::altsvc::__off64_t;
pub type __time_t = crate::src::lib::altsvc::__time_t;
pub type __blksize_t = crate::src::lib::file::__blksize_t;
pub type __blkcnt_t = crate::src::lib::file::__blkcnt_t;
pub type __syscall_slong_t = crate::src::lib::file::__syscall_slong_t;
pub type size_t = crate::src::lib::altsvc::size_t;
// #[derive(Copy, Clone)]

pub type timespec = crate::src::lib::file::timespec;
pub type curl_off_t = crate::src::lib::altsvc::curl_off_t;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::altsvc::_IO_FILE;
pub type _IO_lock_t = crate::src::lib::altsvc::_IO_lock_t;
pub type FILE = crate::src::lib::altsvc::FILE;
pub type CURL = crate::src::lib::altsvc::CURL;
// #[derive(Copy, Clone)]

pub type curl_slist = crate::src::lib::altsvc::curl_slist;
pub type curl_seek_callback = crate::src::lib::altsvc::curl_seek_callback;
pub type curl_read_callback = crate::src::lib::altsvc::curl_read_callback;
pub type curl_free_callback = crate::src::lib::altsvc::curl_free_callback;
pub type CURLcode = crate::src::lib::altsvc::CURLcode;
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
pub type curl_TimeCond = crate::src::lib::altsvc::curl_TimeCond;
pub const CURL_TIMECOND_LAST: curl_TimeCond = 4;
pub const CURL_TIMECOND_LASTMOD: curl_TimeCond = 3;
pub const CURL_TIMECOND_IFUNMODSINCE: curl_TimeCond = 2;
pub const CURL_TIMECOND_IFMODSINCE: curl_TimeCond = 1;
pub const CURL_TIMECOND_NONE: curl_TimeCond = 0;
// #[derive(Copy, Clone)]

pub type stat = crate::src::lib::file::stat;
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
pub const PARAM_OK: ParameterError = 0;
pub type ParameterError = u32;
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
    mut __fd: i32,
    mut __statbuf: *mut stat,
) -> i32 {
    return __fxstat(1 as i32, __fd, __statbuf);
}
unsafe extern "C" fn tool_mime_new(
    mut parent: *mut tool_mime,
    mut kind: toolmimekind,
) -> *mut tool_mime {
    let mut m: *mut tool_mime = calloc(
        1 as i32 as u64,
        ::std::mem::size_of::<tool_mime>() as u64,
    ) as *mut tool_mime;
    if !m.is_null() {
        (*m).kind = kind;
        let fresh0 = &mut ((*m).parent);
        *fresh0 = parent;
        if !parent.is_null() {
            let fresh1 = &mut ((*m).prev);
            *fresh1 = (*parent).subparts;
            let fresh2 = &mut ((*parent).subparts);
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
    mut data: *const i8,
) -> *mut tool_mime {
    let mut m: *mut tool_mime = 0 as *mut tool_mime;
    data = strdup(data);
    if !data.is_null() {
        m = tool_mime_new(parent, TOOLMIME_DATA);
        if m.is_null() {
            free(data as *mut libc::c_void);
        } else {
            let fresh3 = &mut ((*m).data);
            *fresh3 = data;
        }
    }
    return m;
}
unsafe extern "C" fn tool_mime_new_filedata(
    mut parent: *mut tool_mime,
    mut filename: *const i8,
    mut isremotefile: bool,
    mut errcode: *mut CURLcode,
) -> *mut tool_mime {
    let mut result: CURLcode = CURLE_OK;
    let mut m: *mut tool_mime = 0 as *mut tool_mime;
    *errcode = CURLE_OUT_OF_MEMORY;
    if strcmp(filename, b"-\0" as *const u8 as *const i8) != 0 {
        filename = strdup(filename);
        if !filename.is_null() {
            m = tool_mime_new(parent, TOOLMIME_FILE);
            if m.is_null() {
                free(filename as *mut libc::c_void);
            } else {
                let fresh4 = &mut ((*m).data);
                *fresh4 = filename;
                if !isremotefile {
                    (*m).kind = TOOLMIME_FILEDATA;
                }
                *errcode = CURLE_OK;
            }
        }
    } else {
        let mut fd: i32 = fileno(stdin);
        let mut data: *mut i8 = 0 as *mut i8;
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
        if fd >= 0 as i32 && origin >= 0 as i32 as i64
            && fstat(fd, &mut sbuf) == 0
            && sbuf.st_mode & 0o170000 as i32 as u32
                == 0o100000 as i32 as u32
        {
            size = sbuf.st_size - origin;
            if size < 0 as i32 as i64 {
                size = 0 as i32 as curl_off_t;
            }
        } else {
            let mut stdinsize: size_t = 0 as i32 as size_t;
            if file2memory(&mut data, &mut stdinsize, stdin) as u32
                != PARAM_OK as i32 as u32
            {
                return m;
            }
            if ferror(stdin) != 0 {
                result = CURLE_READ_ERROR;
                free(data as *mut libc::c_void);
                data = 0 as *mut i8;
                data = 0 as *mut i8;
            } else if stdinsize == 0 {
                data = strdup(b"\0" as *const u8 as *const i8);
                if data.is_null() {
                    return m;
                }
            }
            size = curlx_uztoso(stdinsize);
            origin = 0 as i32 as curl_off_t;
        }
        m = tool_mime_new(parent, TOOLMIME_STDIN);
        if m.is_null() {
            free(data as *mut libc::c_void);
            data = 0 as *mut i8;
        } else {
            let fresh5 = &mut ((*m).data);
            *fresh5 = data;
            (*m).origin = origin;
            (*m).size = size;
            (*m).curpos = 0 as i32 as curl_off_t;
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
        free(*(&mut (*mime).name as *mut *const i8 as *mut *mut libc::c_void));
        let fresh6 = &mut (*(&mut (*mime).name as *mut *const i8
            as *mut *mut libc::c_void));
        *fresh6 = 0 as *mut libc::c_void;
        free(
            *(&mut (*mime).filename as *mut *const i8
                as *mut *mut libc::c_void),
        );
        let fresh7 = &mut (*(&mut (*mime).filename as *mut *const i8
            as *mut *mut libc::c_void));
        *fresh7 = 0 as *mut libc::c_void;
        free(
            *(&mut (*mime).type_0 as *mut *const i8 as *mut *mut libc::c_void),
        );
        let fresh8 = &mut (*(&mut (*mime).type_0 as *mut *const i8
            as *mut *mut libc::c_void));
        *fresh8 = 0 as *mut libc::c_void;
        free(
            *(&mut (*mime).encoder as *mut *const i8 as *mut *mut libc::c_void),
        );
        let fresh9 = &mut (*(&mut (*mime).encoder as *mut *const i8
            as *mut *mut libc::c_void));
        *fresh9 = 0 as *mut libc::c_void;
        free(*(&mut (*mime).data as *mut *const i8 as *mut *mut libc::c_void));
        let fresh10 = &mut (*(&mut (*mime).data as *mut *const i8
            as *mut *mut libc::c_void));
        *fresh10 = 0 as *mut libc::c_void;
        curl_slist_free_all((*mime).headers);
        free(mime as *mut libc::c_void);
    }
}
#[no_mangle]
pub unsafe extern "C" fn tool_mime_stdin_read(
    mut buffer: *mut i8,
    mut size: size_t,
    mut nitems: size_t,
    mut arg: *mut libc::c_void,
) -> size_t {
    let mut sip: *mut tool_mime = arg as *mut tool_mime;
    let mut bytesleft: curl_off_t = 0;
    if (*sip).size >= 0 as i32 as i64 {
        if (*sip).curpos >= (*sip).size {
            return 0 as i32 as size_t;
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
                1 as i32 as u64,
                nitems,
                stdin,
            );
            if ferror(stdin) != 0 {
                if !((*sip).config).is_null() {
                    warnf(
                        (*sip).config,
                        b"stdin: %s\n\0" as *const u8 as *const i8,
                        strerror(*__errno_location()),
                    );
                    let fresh11 = &mut ((*sip).config);
                    *fresh11 = 0 as *mut GlobalConfig;
                }
                return 0x10000000 as i32 as size_t;
            }
        }
        let fresh12 = &mut ((*sip).curpos);
        *fresh12 += curlx_uztoso(nitems);
    }
    return nitems;
}
#[no_mangle]
pub unsafe extern "C" fn tool_mime_stdin_seek(
    mut instream: *mut libc::c_void,
    mut offset: curl_off_t,
    mut whence: i32,
) -> i32 {
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
    if offset < 0 as i32 as i64 {
        return 2 as i32;
    }
    if ((*sip).data).is_null() {
        if fseek(stdin, offset + (*sip).origin, 0 as i32) != 0 {
            return 2 as i32;
        }
    }
    (*sip).curpos = offset;
    return 0 as i32;
}
unsafe extern "C" fn tool2curlparts(
    mut curl: *mut CURL,
    mut m: *mut tool_mime,
    mut mime: *mut curl_mime,
) -> CURLcode {
    let mut ret: CURLcode = CURLE_OK;
    let mut part: *mut curl_mimepart = 0 as *mut curl_mimepart;
    let mut submime: *mut curl_mime = 0 as *mut curl_mime;
    let mut filename: *const i8 = 0 as *const i8;
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
            match (*m).kind as u32 {
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
                    ret = curl_mime_data(part, (*m).data, -(1 as i32) as size_t);
                    current_block_19 = 14818589718467733107;
                }
                3 | 4 => {
                    ret = curl_mime_filedata(part, (*m).data);
                    if ret as u64 == 0
                        && (*m).kind as u32
                            == TOOLMIME_FILEDATA as i32 as u32
                        && filename.is_null()
                    {
                        ret = curl_mime_filename(part, 0 as *const i8);
                    }
                    current_block_19 = 14818589718467733107;
                }
                5 => {
                    if filename.is_null() {
                        filename = b"-\0" as *const u8 as *const i8;
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
                                    *mut i8,
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
                                        *mut i8,
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
                                    i32,
                                ) -> i32,
                            >,
                            curl_seek_callback,
                        >(
                            Some(
                                tool_mime_stdin_seek
                                    as unsafe extern "C" fn(
                                        *mut libc::c_void,
                                        curl_off_t,
                                        i32,
                                    ) -> i32,
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
            ret = curl_mime_headers(part, (*m).headers, 0 as i32);
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
    mut str: *mut *mut i8,
    mut end_pos: *mut *mut i8,
    mut endchar: i8,
) -> *mut i8 {
    let mut ptr: *mut i8 = *str;
    let mut word_begin: *mut i8 = ptr;
    let mut ptr2: *mut i8 = 0 as *mut i8;
    let mut escape: *mut i8 = 0 as *mut i8;
    if *ptr as i32 == '"' as i32 {
        ptr = ptr.offset(1);
        while *ptr != 0 {
            if *ptr as i32 == '\\' as i32 {
                if *ptr.offset(1 as i32 as isize) as i32 == '\\' as i32
                    || *ptr.offset(1 as i32 as isize) as i32
                        == '"' as i32
                {
                    if escape.is_null() {
                        escape = ptr;
                    }
                    ptr = ptr.offset(2 as i32 as isize);
                    continue;
                }
            }
            if *ptr as i32 == '"' as i32 {
                let mut trailing_data: bool = 0 as i32 != 0;
                *end_pos = ptr;
                if !escape.is_null() {
                    ptr2 = escape;
                    ptr = ptr2;
                    loop {
                        if *ptr as i32 == '\\' as i32
                            && (*ptr.offset(1 as i32 as isize) as i32
                                == '\\' as i32
                                || *ptr.offset(1 as i32 as isize) as i32
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
                while *ptr as i32 != 0 && *ptr as i32 != ';' as i32
                    && *ptr as i32 != endchar as i32
                {
                    if Curl_isspace(*ptr as u8 as i32) == 0 {
                        trailing_data = 1 as i32 != 0;
                    }
                    ptr = ptr.offset(1);
                }
                if trailing_data {
                    warnf(
                        (*config).global,
                        b"Trailing data after quoted form parameter\n\0" as *const u8
                            as *const i8,
                    );
                }
                *str = ptr;
                return word_begin.offset(1 as i32 as isize);
            }
            ptr = ptr.offset(1);
        }
        ptr = word_begin;
    }
    while *ptr as i32 != 0 && *ptr as i32 != ';' as i32
        && *ptr as i32 != endchar as i32
    {
        ptr = ptr.offset(1);
    }
    *end_pos = ptr;
    *str = *end_pos;
    return word_begin;
}
unsafe extern "C" fn slist_append(
    mut plist: *mut *mut curl_slist,
    mut data: *const i8,
) -> i32 {
    let mut s: *mut curl_slist = curl_slist_append(*plist, data);
    if s.is_null() {
        return -(1 as i32);
    }
    *plist = s;
    return 0 as i32;
}
unsafe extern "C" fn read_field_headers(
    mut config: *mut OperationConfig,
    mut filename: *const i8,
    mut fp: *mut FILE,
    mut pheaders: *mut *mut curl_slist,
) -> i32 {
    let mut hdrlen: size_t = 0 as i32 as size_t;
    let mut pos: size_t = 0 as i32 as size_t;
    let mut incomment: bool = 0 as i32 != 0;
    let mut lineno: i32 = 1 as i32;
    let mut hdrbuf: [i8; 999] = [0; 999];
    loop {
        let mut c: i32 = getc(fp);
        if c == -(1 as i32)
            || pos == 0 && Curl_isspace(c as u8 as i32) == 0
        {
            while hdrlen != 0
                && Curl_isspace(
                    hdrbuf[hdrlen.wrapping_sub(1 as i32 as u64)
                        as usize] as u8 as i32,
                ) != 0
            {
                hdrlen = hdrlen.wrapping_sub(1);
            }
            if hdrlen != 0 {
                hdrbuf[hdrlen as usize] = '\u{0}' as i32 as i8;
                if slist_append(pheaders, hdrbuf.as_mut_ptr()) != 0 {
                    curl_mfprintf(
                        (*(*config).global).errors,
                        b"Out of memory for field headers!\n\0" as *const u8
                            as *const i8,
                    );
                    return -(1 as i32);
                }
                hdrlen = 0 as i32 as size_t;
            }
        }
        match c {
            -1 => {
                if ferror(fp) != 0 {
                    curl_mfprintf(
                        (*(*config).global).errors,
                        b"Header file %s read error: %s\n\0" as *const u8
                            as *const i8,
                        filename,
                        strerror(*__errno_location()),
                    );
                    return -(1 as i32);
                }
                return 0 as i32;
            }
            13 => {
                continue;
            }
            10 => {
                pos = 0 as i32 as size_t;
                incomment = 0 as i32 != 0;
                lineno += 1;
                continue;
            }
            35 => {
                if pos == 0 {
                    incomment = 1 as i32 != 0;
                }
            }
            _ => {}
        }
        pos = pos.wrapping_add(1);
        if !incomment {
            if hdrlen
                == (::std::mem::size_of::<[i8; 999]>() as u64)
                    .wrapping_sub(1 as i32 as u64)
            {
                warnf(
                    (*config).global,
                    b"File %s line %d: header too long (truncated)\n\0" as *const u8
                        as *const i8,
                    filename,
                    lineno,
                );
                c = ' ' as i32;
            }
            if hdrlen
                <= (::std::mem::size_of::<[i8; 999]>() as u64)
                    .wrapping_sub(1 as i32 as u64)
            {
                let fresh15 = hdrlen;
                hdrlen = hdrlen.wrapping_add(1);
                hdrbuf[fresh15 as usize] = c as i8;
            }
        }
    };
}
unsafe extern "C" fn get_param_part(
    mut config: *mut OperationConfig,
    mut endchar: i8,
    mut str: *mut *mut i8,
    mut pdata: *mut *mut i8,
    mut ptype: *mut *mut i8,
    mut pfilename: *mut *mut i8,
    mut pencoder: *mut *mut i8,
    mut pheaders: *mut *mut curl_slist,
) -> i32 {
    let mut p: *mut i8 = *str;
    let mut type_0: *mut i8 = 0 as *mut i8;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoder: *mut i8 = 0 as *mut i8;
    let mut endpos: *mut i8 = 0 as *mut i8;
    let mut tp: *mut i8 = 0 as *mut i8;
    let mut sep: i8 = 0;
    let mut type_major: [i8; 128] = *::std::mem::transmute::<
        &[u8; 128],
        &mut [i8; 128],
    >(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut type_minor: [i8; 128] = *::std::mem::transmute::<
        &[u8; 128],
        &mut [i8; 128],
    >(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut endct: *mut i8 = 0 as *mut i8;
    let mut headers: *mut curl_slist = 0 as *mut curl_slist;
    if !ptype.is_null() {
        *ptype = 0 as *mut i8;
    }
    if !pfilename.is_null() {
        *pfilename = 0 as *mut i8;
    }
    if !pheaders.is_null() {
        *pheaders = 0 as *mut curl_slist;
    }
    if !pencoder.is_null() {
        *pencoder = 0 as *mut i8;
    }
    while Curl_isspace(*p as u8 as i32) != 0 {
        p = p.offset(1);
    }
    tp = p;
    *pdata = get_param_word(config, &mut p, &mut endpos, endchar);
    if *pdata == tp {
        while endpos > *pdata
            && Curl_isspace(
                *endpos.offset(-(1 as i32) as isize) as u8
                    as i32,
            ) != 0
        {
            endpos = endpos.offset(-1);
        }
    }
    sep = *p;
    *endpos = '\u{0}' as i32 as i8;
    while sep as i32 == ';' as i32 {
        loop {
            p = p.offset(1);
            if !(Curl_isspace(*p as u8 as i32) != 0) {
                break;
            }
        }
        if endct.is_null()
            && curl_strnequal(
                b"type=\0" as *const u8 as *const i8,
                p,
                strlen(b"type=\0" as *const u8 as *const i8),
            ) != 0
        {
            p = p.offset(5 as i32 as isize);
            while Curl_isspace(*p as u8 as i32) != 0 {
                p = p.offset(1);
            }
            type_0 = p;
            if 2 as i32
                != sscanf(
                    type_0,
                    b"%127[^/ ]/%127[^;, \n]\0" as *const u8 as *const i8,
                    type_major.as_mut_ptr(),
                    type_minor.as_mut_ptr(),
                )
            {
                warnf(
                    (*config).global,
                    b"Illegally formatted content-type field!\n\0" as *const u8
                        as *const i8,
                );
                curl_slist_free_all(headers);
                return -(1 as i32);
            }
            p = type_0
                .offset(strlen(type_major.as_mut_ptr()) as isize)
                .offset(strlen(type_minor.as_mut_ptr()) as isize)
                .offset(1 as i32 as isize);
            endct = p;
            while *p as i32 != 0 && *p as i32 != ';' as i32
                && *p as i32 != endchar as i32
            {
                if Curl_isspace(*p as u8 as i32) == 0 {
                    endct = p.offset(1 as i32 as isize);
                }
                p = p.offset(1);
            }
            sep = *p;
        } else if curl_strnequal(
                b"filename=\0" as *const u8 as *const i8,
                p,
                strlen(b"filename=\0" as *const u8 as *const i8),
            ) != 0
            {
            if !endct.is_null() {
                *endct = '\u{0}' as i32 as i8;
                endct = 0 as *mut i8;
            }
            p = p.offset(9 as i32 as isize);
            while Curl_isspace(*p as u8 as i32) != 0 {
                p = p.offset(1);
            }
            tp = p;
            filename = get_param_word(config, &mut p, &mut endpos, endchar);
            if filename == tp {
                while endpos > filename
                    && Curl_isspace(
                        *endpos.offset(-(1 as i32) as isize) as u8
                            as i32,
                    ) != 0
                {
                    endpos = endpos.offset(-1);
                }
            }
            sep = *p;
            *endpos = '\u{0}' as i32 as i8;
        } else if curl_strnequal(
                b"headers=\0" as *const u8 as *const i8,
                p,
                strlen(b"headers=\0" as *const u8 as *const i8),
            ) != 0
            {
            if !endct.is_null() {
                *endct = '\u{0}' as i32 as i8;
                endct = 0 as *mut i8;
            }
            p = p.offset(8 as i32 as isize);
            if *p as i32 == '@' as i32 || *p as i32 == '<' as i32 {
                let mut hdrfile: *mut i8 = 0 as *mut i8;
                let mut fp: *mut FILE = 0 as *mut FILE;
                loop {
                    p = p.offset(1);
                    if !(Curl_isspace(*p as u8 as i32) != 0) {
                        break;
                    }
                }
                tp = p;
                hdrfile = get_param_word(config, &mut p, &mut endpos, endchar);
                if hdrfile == tp {
                    while endpos > hdrfile
                        && Curl_isspace(
                            *endpos.offset(-(1 as i32) as isize) as u8
                                as i32,
                        ) != 0
                    {
                        endpos = endpos.offset(-1);
                    }
                }
                sep = *p;
                *endpos = '\u{0}' as i32 as i8;
                fp = fopen(hdrfile, b"r\0" as *const u8 as *const i8);
                if fp.is_null() {
                    warnf(
                        (*config).global,
                        b"Cannot read from %s: %s\n\0" as *const u8
                            as *const i8,
                        hdrfile,
                        strerror(*__errno_location()),
                    );
                } else {
                    let mut i: i32 = read_field_headers(
                        config,
                        hdrfile,
                        fp,
                        &mut headers,
                    );
                    fclose(fp);
                    if i != 0 {
                        curl_slist_free_all(headers);
                        return -(1 as i32);
                    }
                }
            } else {
                let mut hdr: *mut i8 = 0 as *mut i8;
                while Curl_isspace(*p as u8 as i32) != 0 {
                    p = p.offset(1);
                }
                tp = p;
                hdr = get_param_word(config, &mut p, &mut endpos, endchar);
                if hdr == tp {
                    while endpos > hdr
                        && Curl_isspace(
                            *endpos.offset(-(1 as i32) as isize) as u8
                                as i32,
                        ) != 0
                    {
                        endpos = endpos.offset(-1);
                    }
                }
                sep = *p;
                *endpos = '\u{0}' as i32 as i8;
                if slist_append(&mut headers, hdr) != 0 {
                    curl_mfprintf(
                        (*(*config).global).errors,
                        b"Out of memory for field header!\n\0" as *const u8
                            as *const i8,
                    );
                    curl_slist_free_all(headers);
                    return -(1 as i32);
                }
            }
        } else if curl_strnequal(
                b"encoder=\0" as *const u8 as *const i8,
                p,
                strlen(b"encoder=\0" as *const u8 as *const i8),
            ) != 0
            {
            if !endct.is_null() {
                *endct = '\u{0}' as i32 as i8;
                endct = 0 as *mut i8;
            }
            p = p.offset(8 as i32 as isize);
            while Curl_isspace(*p as u8 as i32) != 0 {
                p = p.offset(1);
            }
            tp = p;
            encoder = get_param_word(config, &mut p, &mut endpos, endchar);
            if encoder == tp {
                while endpos > encoder
                    && Curl_isspace(
                        *endpos.offset(-(1 as i32) as isize) as u8
                            as i32,
                    ) != 0
                {
                    endpos = endpos.offset(-1);
                }
            }
            sep = *p;
            *endpos = '\u{0}' as i32 as i8;
        } else if !endct.is_null() {
            endct = p;
            while *p as i32 != 0 && *p as i32 != ';' as i32
                && *p as i32 != endchar as i32
            {
                if Curl_isspace(*p as u8 as i32) == 0 {
                    endct = p.offset(1 as i32 as isize);
                }
                p = p.offset(1);
            }
            sep = *p;
        } else {
            let mut unknown: *mut i8 = get_param_word(
                config,
                &mut p,
                &mut endpos,
                endchar,
            );
            sep = *p;
            *endpos = '\u{0}' as i32 as i8;
            if *unknown != 0 {
                warnf(
                    (*config).global,
                    b"skip unknown form field: %s\n\0" as *const u8
                        as *const i8,
                    unknown,
                );
            }
        }
    }
    if !endct.is_null() {
        *endct = '\u{0}' as i32 as i8;
    }
    if !ptype.is_null() {
        *ptype = type_0;
    } else if !type_0.is_null() {
        warnf(
            (*config).global,
            b"Field content type not allowed here: %s\n\0" as *const u8
                as *const i8,
            type_0,
        );
    }
    if !pfilename.is_null() {
        *pfilename = filename;
    } else if !filename.is_null() {
        warnf(
            (*config).global,
            b"Field file name not allowed here: %s\n\0" as *const u8
                as *const i8,
            filename,
        );
    }
    if !pencoder.is_null() {
        *pencoder = encoder;
    } else if !encoder.is_null() {
        warnf(
            (*config).global,
            b"Field encoder not allowed here: %s\n\0" as *const u8
                as *const i8,
            encoder,
        );
    }
    if !pheaders.is_null() {
        *pheaders = headers;
    } else if !headers.is_null() {
        warnf(
            (*config).global,
            b"Field headers not allowed here: %s\n\0" as *const u8
                as *const i8,
            (*headers).data,
        );
        curl_slist_free_all(headers);
    }
    *str = p;
    return sep as i32 & 0xff as i32;
}
#[no_mangle]
pub unsafe extern "C" fn formparse(
    mut config: *mut OperationConfig,
    mut input: *const i8,
    mut mimeroot: *mut *mut tool_mime,
    mut mimecurrent: *mut *mut tool_mime,
    mut literal_value: bool,
) -> i32 {
    let mut name: *mut i8 = 0 as *mut i8;
    let mut contents: *mut i8 = 0 as *mut i8;
    let mut contp: *mut i8 = 0 as *mut i8;
    let mut data: *mut i8 = 0 as *mut i8;
    let mut type_0: *mut i8 = 0 as *mut i8;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoder: *mut i8 = 0 as *mut i8;
    let mut headers: *mut curl_slist = 0 as *mut curl_slist;
    let mut part: *mut tool_mime = 0 as *mut tool_mime;
    let mut res: CURLcode = CURLE_OK;
    if (*mimecurrent).is_null() {
        *mimeroot = tool_mime_new_parts(0 as *mut tool_mime);
        if (*mimeroot).is_null() {
            warnf(
                (*config).global,
                b"out of memory!\n\0" as *const u8 as *const i8,
            );
            curl_slist_free_all(headers);
            free(contents as *mut libc::c_void);
            contents = 0 as *mut i8;
            return 1 as i32;
        }
        *mimecurrent = *mimeroot;
    }
    contents = strdup(input);
    if contents.is_null() {
        warnf(
            (*config).global,
            b"out of memory!\n\0" as *const u8 as *const i8,
        );
        curl_slist_free_all(headers);
        free(contents as *mut libc::c_void);
        contents = 0 as *mut i8;
        return 2 as i32;
    }
    contp = strchr(contents, '=' as i32);
    if !contp.is_null() {
        let mut sep: i32 = '\u{0}' as i32;
        if contp > contents {
            name = contents;
        }
        let fresh16 = contp;
        contp = contp.offset(1);
        *fresh16 = '\u{0}' as i32 as i8;
        if *contp as i32 == '(' as i32 && !literal_value {
            sep = get_param_part(
                config,
                '\u{0}' as i32 as i8,
                &mut contp,
                &mut data,
                &mut type_0,
                0 as *mut *mut i8,
                0 as *mut *mut i8,
                &mut headers,
            );
            if sep < 0 as i32 {
                free(contents as *mut libc::c_void);
                contents = 0 as *mut i8;
                return 3 as i32;
            }
            part = tool_mime_new_parts(*mimecurrent);
            if part.is_null() {
                warnf(
                    (*config).global,
                    b"out of memory!\n\0" as *const u8 as *const i8,
                );
                curl_slist_free_all(headers);
                free(contents as *mut libc::c_void);
                contents = 0 as *mut i8;
                return 4 as i32;
            }
            *mimecurrent = part;
            let fresh17 = &mut ((*part).headers);
            *fresh17 = headers;
            headers = 0 as *mut curl_slist;
            if !type_0.is_null() {
                let fresh18 = &mut ((*part).type_0);
                *fresh18 = strdup(type_0);
                if ((*part).type_0).is_null() {
                    warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const i8,
                    );
                    curl_slist_free_all(headers);
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut i8;
                    return 5 as i32;
                }
            }
        } else if name.is_null()
                && strcmp(contp, b")\0" as *const u8 as *const i8) == 0
                && !literal_value
            {
            if *mimecurrent == *mimeroot {
                warnf(
                    (*config).global,
                    b"no multipart to terminate!\n\0" as *const u8 as *const i8,
                );
                free(contents as *mut libc::c_void);
                contents = 0 as *mut i8;
                return 6 as i32;
            }
            *mimecurrent = (**mimecurrent).parent;
        } else if '@' as i32 == *contp.offset(0 as i32 as isize) as i32
                && !literal_value
            {
            let mut subparts: *mut tool_mime = 0 as *mut tool_mime;
            loop {
                contp = contp.offset(1);
                sep = get_param_part(
                    config,
                    ',' as i32 as i8,
                    &mut contp,
                    &mut data,
                    &mut type_0,
                    &mut filename,
                    &mut encoder,
                    &mut headers,
                );
                if sep < 0 as i32 {
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut i8;
                    return 7 as i32;
                }
                if subparts.is_null() {
                    if sep != ',' as i32 {
                        subparts = *mimecurrent;
                    } else {
                        subparts = tool_mime_new_parts(*mimecurrent);
                        if subparts.is_null() {
                            warnf(
                                (*config).global,
                                b"out of memory!\n\0" as *const u8 as *const i8,
                            );
                            curl_slist_free_all(headers);
                            free(contents as *mut libc::c_void);
                            contents = 0 as *mut i8;
                            return 8 as i32;
                        }
                    }
                }
                part = tool_mime_new_filedata(
                    subparts,
                    data,
                    1 as i32 != 0,
                    &mut res,
                );
                if part.is_null() {
                    warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const i8,
                    );
                    curl_slist_free_all(headers);
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut i8;
                    return 9 as i32;
                }
                let fresh19 = &mut ((*part).headers);
                *fresh19 = headers;
                headers = 0 as *mut curl_slist;
                let fresh20 = &mut ((*part).config);
                *fresh20 = (*config).global;
                if res as u32 == CURLE_READ_ERROR as i32 as u32
                {
                    if (*part).size > 0 as i32 as i64 {
                        warnf(
                            (*config).global,
                            b"error while reading standard input\n\0" as *const u8
                                as *const i8,
                        );
                        free(contents as *mut libc::c_void);
                        contents = 0 as *mut i8;
                        return 10 as i32;
                    }
                    free(
                        *(&mut (*part).data as *mut *const i8
                            as *mut *mut libc::c_void),
                    );
                    let fresh21 = &mut (*(&mut (*part).data as *mut *const i8
                        as *mut *mut libc::c_void));
                    *fresh21 = 0 as *mut libc::c_void;
                    let fresh22 = &mut ((*part).data);
                    *fresh22 = 0 as *const i8;
                    (*part).size = -(1 as i32) as curl_off_t;
                    res = CURLE_OK;
                }
                if !filename.is_null() {
                    let fresh23 = &mut ((*part).filename);
                    *fresh23 = strdup(filename);
                    if ((*part).filename).is_null() {
                        warnf(
                            (*config).global,
                            b"out of memory!\n\0" as *const u8 as *const i8,
                        );
                        curl_slist_free_all(headers);
                        free(contents as *mut libc::c_void);
                        contents = 0 as *mut i8;
                        return 11 as i32;
                    }
                }
                if !type_0.is_null() {
                    let fresh24 = &mut ((*part).type_0);
                    *fresh24 = strdup(type_0);
                    if ((*part).type_0).is_null() {
                        warnf(
                            (*config).global,
                            b"out of memory!\n\0" as *const u8 as *const i8,
                        );
                        curl_slist_free_all(headers);
                        free(contents as *mut libc::c_void);
                        contents = 0 as *mut i8;
                        return 12 as i32;
                    }
                }
                if !encoder.is_null() {
                    let fresh25 = &mut ((*part).encoder);
                    *fresh25 = strdup(encoder);
                    if ((*part).encoder).is_null() {
                        warnf(
                            (*config).global,
                            b"out of memory!\n\0" as *const u8 as *const i8,
                        );
                        curl_slist_free_all(headers);
                        free(contents as *mut libc::c_void);
                        contents = 0 as *mut i8;
                        return 13 as i32;
                    }
                }
                if !(sep != 0) {
                    break;
                }
            }
            part = (**mimecurrent).subparts;
        } else {
            if *contp as i32 == '<' as i32 && !literal_value {
                contp = contp.offset(1);
                sep = get_param_part(
                    config,
                    '\u{0}' as i32 as i8,
                    &mut contp,
                    &mut data,
                    &mut type_0,
                    0 as *mut *mut i8,
                    &mut encoder,
                    &mut headers,
                );
                if sep < 0 as i32 {
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut i8;
                    return 14 as i32;
                }
                part = tool_mime_new_filedata(
                    *mimecurrent,
                    data,
                    0 as i32 != 0,
                    &mut res,
                );
                if part.is_null() {
                    warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const i8,
                    );
                    curl_slist_free_all(headers);
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut i8;
                    return 15 as i32;
                }
                let fresh26 = &mut ((*part).headers);
                *fresh26 = headers;
                headers = 0 as *mut curl_slist;
                let fresh27 = &mut ((*part).config);
                *fresh27 = (*config).global;
                if res as u32 == CURLE_READ_ERROR as i32 as u32
                {
                    if (*part).size > 0 as i32 as i64 {
                        warnf(
                            (*config).global,
                            b"error while reading standard input\n\0" as *const u8
                                as *const i8,
                        );
                        free(contents as *mut libc::c_void);
                        contents = 0 as *mut i8;
                        return 16 as i32;
                    }
                    free(
                        *(&mut (*part).data as *mut *const i8
                            as *mut *mut libc::c_void),
                    );
                    let fresh28 = &mut (*(&mut (*part).data as *mut *const i8
                        as *mut *mut libc::c_void));
                    *fresh28 = 0 as *mut libc::c_void;
                    let fresh29 = &mut ((*part).data);
                    *fresh29 = 0 as *const i8;
                    (*part).size = -(1 as i32) as curl_off_t;
                    res = CURLE_OK;
                }
            } else {
                if literal_value {
                    data = contp;
                } else {
                    sep = get_param_part(
                        config,
                        '\u{0}' as i32 as i8,
                        &mut contp,
                        &mut data,
                        &mut type_0,
                        &mut filename,
                        &mut encoder,
                        &mut headers,
                    );
                    if sep < 0 as i32 {
                        free(contents as *mut libc::c_void);
                        contents = 0 as *mut i8;
                        return 17 as i32;
                    }
                }
                part = tool_mime_new_data(*mimecurrent, data);
                if part.is_null() {
                    warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const i8,
                    );
                    curl_slist_free_all(headers);
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut i8;
                    return 18 as i32;
                }
                let fresh30 = &mut ((*part).headers);
                *fresh30 = headers;
                headers = 0 as *mut curl_slist;
            }
            if !filename.is_null() {
                let fresh31 = &mut ((*part).filename);
                *fresh31 = strdup(filename);
                if ((*part).filename).is_null() {
                    warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const i8,
                    );
                    curl_slist_free_all(headers);
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut i8;
                    return 19 as i32;
                }
            }
            if !type_0.is_null() {
                let fresh32 = &mut ((*part).type_0);
                *fresh32 = strdup(type_0);
                if ((*part).type_0).is_null() {
                    warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const i8,
                    );
                    curl_slist_free_all(headers);
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut i8;
                    return 20 as i32;
                }
            }
            if !encoder.is_null() {
                let fresh33 = &mut ((*part).encoder);
                *fresh33 = strdup(encoder);
                if ((*part).encoder).is_null() {
                    warnf(
                        (*config).global,
                        b"out of memory!\n\0" as *const u8 as *const i8,
                    );
                    curl_slist_free_all(headers);
                    free(contents as *mut libc::c_void);
                    contents = 0 as *mut i8;
                    return 21 as i32;
                }
            }
            if sep != 0 {
                *contp = sep as i8;
                warnf(
                    (*config).global,
                    b"garbage at end of field specification: %s\n\0" as *const u8
                        as *const i8,
                    contp,
                );
            }
        }
        if !name.is_null() {
            let fresh34 = &mut ((*part).name);
            *fresh34 = strdup(name);
            if ((*part).name).is_null() {
                warnf(
                    (*config).global,
                    b"out of memory!\n\0" as *const u8 as *const i8,
                );
                curl_slist_free_all(headers);
                free(contents as *mut libc::c_void);
                contents = 0 as *mut i8;
                return 22 as i32;
            }
        }
    } else {
        warnf(
            (*config).global,
            b"Illegally formatted input field!\n\0" as *const u8 as *const i8,
        );
        free(contents as *mut libc::c_void);
        contents = 0 as *mut i8;
        return 23 as i32;
    }
    free(contents as *mut libc::c_void);
    contents = 0 as *mut i8;
    return 0 as i32;
}
