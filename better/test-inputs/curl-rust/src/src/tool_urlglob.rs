use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type Curl_URL;
    static mut stderr: *mut FILE;
    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn Curl_isalpha(c: libc::c_int) -> libc::c_int;
    fn Curl_isdigit(c: libc::c_int) -> libc::c_int;
    fn curl_url() -> *mut CURLU;
    fn curl_url_cleanup(handle: *mut CURLU);
    fn curl_url_set(
        handle: *mut CURLU,
        what: CURLUPart,
        part: *const libc::c_char,
        flags: libc::c_uint,
    ) -> CURLUcode;
    fn strtoul(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_ulong;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn __errno_location() -> *mut libc::c_int;
    fn curl_mprintf(format: *const libc::c_char, _: ...) -> libc::c_int;
    fn curl_mfprintf(fd: *mut FILE, format: *const libc::c_char, _: ...) -> libc::c_int;
    fn curl_msnprintf(
        buffer: *mut libc::c_char,
        maxlength: size_t,
        format: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn curlx_dyn_init(s: *mut dynbuf, toobig: size_t);
    fn curlx_dyn_free(s: *mut dynbuf);
    fn curlx_dyn_addn(s: *mut dynbuf, mem: *const libc::c_void, len: size_t) -> CURLcode;
    fn curlx_dyn_ptr(s: *const dynbuf) -> *mut libc::c_char;
}
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type size_t = libc::c_ulong;
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
pub type CURLUcode = libc::c_uint;
pub const CURLUE_NO_FRAGMENT: CURLUcode = 17;
pub const CURLUE_NO_QUERY: CURLUcode = 16;
pub const CURLUE_NO_PORT: CURLUcode = 15;
pub const CURLUE_NO_HOST: CURLUcode = 14;
pub const CURLUE_NO_OPTIONS: CURLUcode = 13;
pub const CURLUE_NO_PASSWORD: CURLUcode = 12;
pub const CURLUE_NO_USER: CURLUcode = 11;
pub const CURLUE_NO_SCHEME: CURLUcode = 10;
pub const CURLUE_UNKNOWN_PART: CURLUcode = 9;
pub const CURLUE_USER_NOT_ALLOWED: CURLUcode = 8;
pub const CURLUE_OUT_OF_MEMORY: CURLUcode = 7;
pub const CURLUE_URLDECODE: CURLUcode = 6;
pub const CURLUE_UNSUPPORTED_SCHEME: CURLUcode = 5;
pub const CURLUE_BAD_PORT_NUMBER: CURLUcode = 4;
pub const CURLUE_MALFORMED_INPUT: CURLUcode = 3;
pub const CURLUE_BAD_PARTPOINTER: CURLUcode = 2;
pub const CURLUE_BAD_HANDLE: CURLUcode = 1;
pub const CURLUE_OK: CURLUcode = 0;
pub type CURLUPart = libc::c_uint;
pub const CURLUPART_ZONEID: CURLUPart = 10;
pub const CURLUPART_FRAGMENT: CURLUPart = 9;
pub const CURLUPART_QUERY: CURLUPart = 8;
pub const CURLUPART_PATH: CURLUPart = 7;
pub const CURLUPART_PORT: CURLUPart = 6;
pub const CURLUPART_HOST: CURLUPart = 5;
pub const CURLUPART_OPTIONS: CURLUPart = 4;
pub const CURLUPART_PASSWORD: CURLUPart = 3;
pub const CURLUPART_USER: CURLUPart = 2;
pub const CURLUPART_SCHEME: CURLUPart = 1;
pub const CURLUPART_URL: CURLUPart = 0;
pub type CURLU = Curl_URL;
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
pub struct dynbuf {
    pub bufr: *mut libc::c_char,
    pub leng: size_t,
    pub allc: size_t,
    pub toobig: size_t,
}
unsafe extern "C" fn glob_fixed(
    mut glob: *mut URLGlob,
    mut fixed: *mut libc::c_char,
    mut len: size_t,
) -> CURLcode {
    let mut pat: *mut URLPattern = &mut *((*glob).pattern)
        .as_mut_ptr()
        .offset((*glob).size as isize) as *mut URLPattern;
    (*pat).type_0 = UPTSet;
    (*pat).content.Set.size = 1 as libc::c_int;
    (*pat).content.Set.ptr_s = 0 as libc::c_int;
    (*pat).globindex = -(1 as libc::c_int);
    let ref mut fresh0 = (*pat).content.Set.elements;
    *fresh0 = malloc(::std::mem::size_of::<*mut libc::c_char>() as libc::c_ulong)
        as *mut *mut libc::c_char;
    if ((*pat).content.Set.elements).is_null() {
        let ref mut fresh1 = (*glob).error;
        *fresh1 = b"out of memory\0" as *const u8 as *const libc::c_char;
        (*glob).pos = 0 as libc::c_int as size_t;
        return CURLE_OUT_OF_MEMORY as libc::c_int as CURLcode;
    }
    let ref mut fresh2 = *((*pat).content.Set.elements)
        .offset(0 as libc::c_int as isize);
    *fresh2 = malloc(len.wrapping_add(1 as libc::c_int as libc::c_ulong))
        as *mut libc::c_char;
    if (*((*pat).content.Set.elements).offset(0 as libc::c_int as isize)).is_null() {
        let ref mut fresh3 = (*glob).error;
        *fresh3 = b"out of memory\0" as *const u8 as *const libc::c_char;
        (*glob).pos = 0 as libc::c_int as size_t;
        return CURLE_OUT_OF_MEMORY as libc::c_int as CURLcode;
    }
    memcpy(
        *((*pat).content.Set.elements).offset(0 as libc::c_int as isize)
            as *mut libc::c_void,
        fixed as *const libc::c_void,
        len,
    );
    *(*((*pat).content.Set.elements).offset(0 as libc::c_int as isize))
        .offset(len as isize) = 0 as libc::c_int as libc::c_char;
    return CURLE_OK;
}
unsafe extern "C" fn multiply(
    mut amount: *mut libc::c_ulong,
    mut with: libc::c_long,
) -> libc::c_int {
    let mut sum: libc::c_ulong = (*amount).wrapping_mul(with as libc::c_ulong);
    if with == 0 {
        *amount = 0 as libc::c_int as libc::c_ulong;
        return 0 as libc::c_int;
    }
    if sum.wrapping_div(with as libc::c_ulong) != *amount {
        return 1 as libc::c_int;
    }
    *amount = sum;
    return 0 as libc::c_int;
}
unsafe extern "C" fn glob_set(
    mut glob: *mut URLGlob,
    mut patternp: *mut *mut libc::c_char,
    mut posp: *mut size_t,
    mut amount: *mut libc::c_ulong,
    mut globindex: libc::c_int,
) -> CURLcode {
    let mut pat: *mut URLPattern = 0 as *mut URLPattern;
    let mut done: bool = 0 as libc::c_int != 0;
    let mut buf: *mut libc::c_char = (*glob).glob_buffer;
    let mut pattern: *mut libc::c_char = *patternp;
    let mut opattern: *mut libc::c_char = pattern;
    let mut opos: size_t = (*posp).wrapping_sub(1 as libc::c_int as libc::c_ulong);
    pat = &mut *((*glob).pattern).as_mut_ptr().offset((*glob).size as isize)
        as *mut URLPattern;
    (*pat).type_0 = UPTSet;
    (*pat).content.Set.size = 0 as libc::c_int;
    (*pat).content.Set.ptr_s = 0 as libc::c_int;
    let ref mut fresh4 = (*pat).content.Set.elements;
    *fresh4 = 0 as *mut *mut libc::c_char;
    (*pat).globindex = globindex;
    let mut current_block_36: u64;
    while !done {
        match *pattern as libc::c_int {
            0 => {
                let ref mut fresh5 = (*glob).error;
                *fresh5 = b"unmatched brace\0" as *const u8 as *const libc::c_char;
                (*glob).pos = opos;
                return CURLE_URL_MALFORMAT as libc::c_int as CURLcode;
            }
            123 | 91 => {
                let ref mut fresh6 = (*glob).error;
                *fresh6 = b"nested brace\0" as *const u8 as *const libc::c_char;
                (*glob).pos = *posp;
                return CURLE_URL_MALFORMAT as libc::c_int as CURLcode;
            }
            125 => {
                if opattern == pattern {
                    let ref mut fresh7 = (*glob).error;
                    *fresh7 = b"empty string within braces\0" as *const u8
                        as *const libc::c_char;
                    (*glob).pos = *posp;
                    return CURLE_URL_MALFORMAT as libc::c_int as CURLcode;
                }
                if multiply(
                    amount,
                    ((*pat).content.Set.size + 1 as libc::c_int) as libc::c_long,
                ) != 0
                {
                    let ref mut fresh8 = (*glob).error;
                    *fresh8 = b"range overflow\0" as *const u8 as *const libc::c_char;
                    (*glob).pos = 0 as libc::c_int as size_t;
                    return CURLE_URL_MALFORMAT as libc::c_int as CURLcode;
                }
                current_block_36 = 6366302455163204299;
            }
            44 => {
                current_block_36 = 6366302455163204299;
            }
            93 => {
                let ref mut fresh16 = (*glob).error;
                *fresh16 = b"unexpected close bracket\0" as *const u8
                    as *const libc::c_char;
                (*glob).pos = *posp;
                return CURLE_URL_MALFORMAT as libc::c_int as CURLcode;
            }
            92 => {
                if *pattern.offset(1 as libc::c_int as isize) != 0 {
                    pattern = pattern.offset(1);
                    *posp = (*posp).wrapping_add(1);
                }
                current_block_36 = 9754301318773204628;
            }
            _ => {
                current_block_36 = 9754301318773204628;
            }
        }
        match current_block_36 {
            6366302455163204299 => {
                *buf = '\u{0}' as i32 as libc::c_char;
                if !((*pat).content.Set.elements).is_null() {
                    let mut new_arr: *mut *mut libc::c_char = realloc(
                        (*pat).content.Set.elements as *mut libc::c_void,
                        (((*pat).content.Set.size + 1 as libc::c_int) as libc::c_ulong)
                            .wrapping_mul(
                                ::std::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                            ),
                    ) as *mut *mut libc::c_char;
                    if new_arr.is_null() {
                        let ref mut fresh9 = (*glob).error;
                        *fresh9 = b"out of memory\0" as *const u8 as *const libc::c_char;
                        (*glob).pos = 0 as libc::c_int as size_t;
                        return CURLE_OUT_OF_MEMORY as libc::c_int as CURLcode;
                    }
                    let ref mut fresh10 = (*pat).content.Set.elements;
                    *fresh10 = new_arr;
                } else {
                    let ref mut fresh11 = (*pat).content.Set.elements;
                    *fresh11 = malloc(
                        ::std::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                    ) as *mut *mut libc::c_char;
                }
                if ((*pat).content.Set.elements).is_null() {
                    let ref mut fresh12 = (*glob).error;
                    *fresh12 = b"out of memory\0" as *const u8 as *const libc::c_char;
                    (*glob).pos = 0 as libc::c_int as size_t;
                    return CURLE_OUT_OF_MEMORY as libc::c_int as CURLcode;
                }
                let ref mut fresh13 = *((*pat).content.Set.elements)
                    .offset((*pat).content.Set.size as isize);
                *fresh13 = strdup((*glob).glob_buffer);
                if (*((*pat).content.Set.elements)
                    .offset((*pat).content.Set.size as isize))
                    .is_null()
                {
                    let ref mut fresh14 = (*glob).error;
                    *fresh14 = b"out of memory\0" as *const u8 as *const libc::c_char;
                    (*glob).pos = 0 as libc::c_int as size_t;
                    return CURLE_OUT_OF_MEMORY as libc::c_int as CURLcode;
                }
                let ref mut fresh15 = (*pat).content.Set.size;
                *fresh15 += 1;
                if *pattern as libc::c_int == '}' as i32 {
                    pattern = pattern.offset(1);
                    done = 1 as libc::c_int != 0;
                } else {
                    buf = (*glob).glob_buffer;
                    pattern = pattern.offset(1);
                    *posp = (*posp).wrapping_add(1);
                }
            }
            _ => {
                let fresh17 = pattern;
                pattern = pattern.offset(1);
                let fresh18 = buf;
                buf = buf.offset(1);
                *fresh18 = *fresh17;
                *posp = (*posp).wrapping_add(1);
            }
        }
    }
    *patternp = pattern;
    return CURLE_OK;
}
unsafe extern "C" fn glob_range(
    mut glob: *mut URLGlob,
    mut patternp: *mut *mut libc::c_char,
    mut posp: *mut size_t,
    mut amount: *mut libc::c_ulong,
    mut globindex: libc::c_int,
) -> CURLcode {
    let mut pat: *mut URLPattern = 0 as *mut URLPattern;
    let mut rc: libc::c_int = 0;
    let mut pattern: *mut libc::c_char = *patternp;
    let mut c: *mut libc::c_char = 0 as *mut libc::c_char;
    pat = &mut *((*glob).pattern).as_mut_ptr().offset((*glob).size as isize)
        as *mut URLPattern;
    (*pat).globindex = globindex;
    if Curl_isalpha(*pattern as libc::c_uchar as libc::c_int) != 0 {
        let mut min_c: libc::c_char = 0;
        let mut max_c: libc::c_char = 0;
        let mut end_c: libc::c_char = 0;
        let mut step: libc::c_ulong = 1 as libc::c_int as libc::c_ulong;
        (*pat).type_0 = UPTCharRange;
        rc = sscanf(
            pattern,
            b"%c-%c%c\0" as *const u8 as *const libc::c_char,
            &mut min_c as *mut libc::c_char,
            &mut max_c as *mut libc::c_char,
            &mut end_c as *mut libc::c_char,
        );
        if rc == 3 as libc::c_int {
            if end_c as libc::c_int == ':' as i32 {
                let mut endp: *mut libc::c_char = 0 as *mut libc::c_char;
                *__errno_location() = 0 as libc::c_int;
                step = strtoul(
                    &mut *pattern.offset(4 as libc::c_int as isize),
                    &mut endp,
                    10 as libc::c_int,
                );
                if *__errno_location() != 0
                    || &mut *pattern.offset(4 as libc::c_int as isize)
                        as *mut libc::c_char == endp
                    || *endp as libc::c_int != ']' as i32
                {
                    step = 0 as libc::c_int as libc::c_ulong;
                } else {
                    pattern = endp.offset(1 as libc::c_int as isize);
                }
            } else if end_c as libc::c_int != ']' as i32 {
                rc = 0 as libc::c_int;
            } else {
                pattern = pattern.offset(4 as libc::c_int as isize);
            }
        }
        *posp = (*posp as libc::c_ulong)
            .wrapping_add(
                pattern.offset_from(*patternp) as libc::c_long as libc::c_ulong,
            ) as size_t as size_t;
        if rc != 3 as libc::c_int || step == 0
            || step > 2147483647 as libc::c_int as libc::c_uint as libc::c_ulong
            || min_c as libc::c_int == max_c as libc::c_int
                && step != 1 as libc::c_int as libc::c_ulong
            || min_c as libc::c_int != max_c as libc::c_int
                && (min_c as libc::c_int > max_c as libc::c_int
                    || step
                        > (max_c as libc::c_int - min_c as libc::c_int) as libc::c_uint
                            as libc::c_ulong
                    || max_c as libc::c_int - min_c as libc::c_int
                        > 'z' as i32 - 'a' as i32)
        {
            let ref mut fresh19 = (*glob).error;
            *fresh19 = b"bad range\0" as *const u8 as *const libc::c_char;
            (*glob).pos = *posp;
            return CURLE_URL_MALFORMAT as libc::c_int as CURLcode;
        }
        (*pat).content.CharRange.step = step as libc::c_int;
        let ref mut fresh20 = (*pat).content.CharRange.min_c;
        *fresh20 = min_c;
        (*pat).content.CharRange.ptr_c = *fresh20;
        (*pat).content.CharRange.max_c = max_c;
        if multiply(
            amount,
            (((*pat).content.CharRange.max_c as libc::c_int
                - (*pat).content.CharRange.min_c as libc::c_int)
                / (*pat).content.CharRange.step + 1 as libc::c_int) as libc::c_long,
        ) != 0
        {
            let ref mut fresh21 = (*glob).error;
            *fresh21 = b"range overflow\0" as *const u8 as *const libc::c_char;
            (*glob).pos = *posp;
            return CURLE_URL_MALFORMAT as libc::c_int as CURLcode;
        }
    } else if Curl_isdigit(*pattern as libc::c_uchar as libc::c_int) != 0 {
        let mut min_n: libc::c_ulong = 0;
        let mut max_n: libc::c_ulong = 0 as libc::c_int as libc::c_ulong;
        let mut step_n: libc::c_ulong = 0 as libc::c_int as libc::c_ulong;
        let mut endp_0: *mut libc::c_char = 0 as *mut libc::c_char;
        (*pat).type_0 = UPTNumRange;
        (*pat).content.NumRange.padlength = 0 as libc::c_int;
        if *pattern as libc::c_int == '0' as i32 {
            c = pattern;
            while Curl_isdigit(*c as libc::c_uchar as libc::c_int) != 0 {
                c = c.offset(1);
                let ref mut fresh22 = (*pat).content.NumRange.padlength;
                *fresh22 += 1;
            }
        }
        *__errno_location() = 0 as libc::c_int;
        min_n = strtoul(pattern, &mut endp_0, 10 as libc::c_int);
        if *__errno_location() != 0 || endp_0 == pattern {
            endp_0 = 0 as *mut libc::c_char;
        } else if *endp_0 as libc::c_int != '-' as i32 {
            endp_0 = 0 as *mut libc::c_char;
        } else {
            pattern = endp_0.offset(1 as libc::c_int as isize);
            while *pattern as libc::c_int != 0
                && (*pattern as libc::c_uchar as libc::c_int == ' ' as i32
                    || *pattern as libc::c_uchar as libc::c_int == '\t' as i32)
            {
                pattern = pattern.offset(1);
            }
            if Curl_isdigit(*pattern as libc::c_uchar as libc::c_int) == 0 {
                endp_0 = 0 as *mut libc::c_char;
            } else {
                *__errno_location() = 0 as libc::c_int;
                max_n = strtoul(pattern, &mut endp_0, 10 as libc::c_int);
                if *__errno_location() != 0 {
                    endp_0 = 0 as *mut libc::c_char;
                } else if *endp_0 as libc::c_int == ':' as i32 {
                    pattern = endp_0.offset(1 as libc::c_int as isize);
                    *__errno_location() = 0 as libc::c_int;
                    step_n = strtoul(pattern, &mut endp_0, 10 as libc::c_int);
                    if *__errno_location() != 0 {
                        endp_0 = 0 as *mut libc::c_char;
                    }
                } else {
                    step_n = 1 as libc::c_int as libc::c_ulong;
                }
                if !endp_0.is_null() && *endp_0 as libc::c_int == ']' as i32 {
                    pattern = endp_0.offset(1 as libc::c_int as isize);
                } else {
                    endp_0 = 0 as *mut libc::c_char;
                }
            }
        }
        *posp = (*posp as libc::c_ulong)
            .wrapping_add(
                pattern.offset_from(*patternp) as libc::c_long as libc::c_ulong,
            ) as size_t as size_t;
        if endp_0.is_null() || step_n == 0
            || min_n == max_n && step_n != 1 as libc::c_int as libc::c_ulong
            || min_n != max_n && (min_n > max_n || step_n > max_n.wrapping_sub(min_n))
        {
            let ref mut fresh23 = (*glob).error;
            *fresh23 = b"bad range\0" as *const u8 as *const libc::c_char;
            (*glob).pos = *posp;
            return CURLE_URL_MALFORMAT as libc::c_int as CURLcode;
        }
        let ref mut fresh24 = (*pat).content.NumRange.min_n;
        *fresh24 = min_n;
        (*pat).content.NumRange.ptr_n = *fresh24;
        (*pat).content.NumRange.max_n = max_n;
        (*pat).content.NumRange.step = step_n;
        if multiply(
            amount,
            ((*pat).content.NumRange.max_n)
                .wrapping_sub((*pat).content.NumRange.min_n)
                .wrapping_div((*pat).content.NumRange.step)
                .wrapping_add(1 as libc::c_int as libc::c_ulong) as libc::c_long,
        ) != 0
        {
            let ref mut fresh25 = (*glob).error;
            *fresh25 = b"range overflow\0" as *const u8 as *const libc::c_char;
            (*glob).pos = *posp;
            return CURLE_URL_MALFORMAT as libc::c_int as CURLcode;
        }
    } else {
        let ref mut fresh26 = (*glob).error;
        *fresh26 = b"bad range specification\0" as *const u8 as *const libc::c_char;
        (*glob).pos = *posp;
        return CURLE_URL_MALFORMAT as libc::c_int as CURLcode;
    }
    *patternp = pattern;
    return CURLE_OK;
}
unsafe extern "C" fn peek_ipv6(
    mut str: *const libc::c_char,
    mut skip: *mut size_t,
) -> bool {
    let mut hostname: [libc::c_char; 128] = [0; 128];
    let mut u: *mut CURLU = 0 as *mut CURLU;
    let mut endbr: *mut libc::c_char = strchr(str, ']' as i32);
    let mut hlen: size_t = 0;
    let mut rc: CURLUcode = CURLUE_OK;
    if endbr.is_null() {
        return 0 as libc::c_int != 0;
    }
    hlen = (endbr.offset_from(str) as libc::c_long + 1 as libc::c_int as libc::c_long)
        as size_t;
    if hlen >= 128 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int != 0;
    }
    u = curl_url();
    if u.is_null() {
        return 0 as libc::c_int != 0;
    }
    memcpy(hostname.as_mut_ptr() as *mut libc::c_void, str as *const libc::c_void, hlen);
    hostname[hlen as usize] = 0 as libc::c_int as libc::c_char;
    rc = curl_url_set(
        u,
        CURLUPART_URL,
        hostname.as_mut_ptr(),
        ((1 as libc::c_int) << 9 as libc::c_int) as libc::c_uint,
    );
    curl_url_cleanup(u);
    if rc as u64 == 0 {
        *skip = hlen;
    }
    return if rc as libc::c_uint != 0 { 0 as libc::c_int } else { 1 as libc::c_int }
        != 0;
}
unsafe extern "C" fn glob_parse(
    mut glob: *mut URLGlob,
    mut pattern: *mut libc::c_char,
    mut pos: size_t,
    mut amount: *mut libc::c_ulong,
) -> CURLcode {
    let mut res: CURLcode = CURLE_OK;
    let mut globindex: libc::c_int = 0 as libc::c_int;
    *amount = 1 as libc::c_int as libc::c_ulong;
    while *pattern as libc::c_int != 0 && res as u64 == 0 {
        let mut buf: *mut libc::c_char = (*glob).glob_buffer;
        let mut sublen: size_t = 0 as libc::c_int as size_t;
        while *pattern as libc::c_int != 0 && *pattern as libc::c_int != '{' as i32 {
            if *pattern as libc::c_int == '[' as i32 {
                let mut skip: size_t = 0 as libc::c_int as size_t;
                if !peek_ipv6(pattern, &mut skip)
                    && *pattern.offset(1 as libc::c_int as isize) as libc::c_int
                        == ']' as i32
                {
                    skip = 2 as libc::c_int as size_t;
                }
                if !(skip != 0) {
                    break;
                }
                memcpy(buf as *mut libc::c_void, pattern as *const libc::c_void, skip);
                buf = buf.offset(skip as isize);
                pattern = pattern.offset(skip as isize);
                sublen = (sublen as libc::c_ulong).wrapping_add(skip) as size_t
                    as size_t;
            } else {
                if *pattern as libc::c_int == '}' as i32
                    || *pattern as libc::c_int == ']' as i32
                {
                    let ref mut fresh27 = (*glob).error;
                    *fresh27 = b"unmatched close brace/bracket\0" as *const u8
                        as *const libc::c_char;
                    (*glob).pos = pos;
                    return CURLE_URL_MALFORMAT as libc::c_int as CURLcode;
                }
                if *pattern as libc::c_int == '\\' as i32
                    && (*pattern.offset(1 as libc::c_int as isize) as libc::c_int
                        == '{' as i32
                        || *pattern.offset(1 as libc::c_int as isize) as libc::c_int
                            == '[' as i32
                        || *pattern.offset(1 as libc::c_int as isize) as libc::c_int
                            == '}' as i32
                        || *pattern.offset(1 as libc::c_int as isize) as libc::c_int
                            == ']' as i32)
                {
                    pattern = pattern.offset(1);
                    pos = pos.wrapping_add(1);
                }
                let fresh28 = pattern;
                pattern = pattern.offset(1);
                let fresh29 = buf;
                buf = buf.offset(1);
                *fresh29 = *fresh28;
                pos = pos.wrapping_add(1);
                sublen = sublen.wrapping_add(1);
            }
        }
        if sublen != 0 {
            *buf = '\u{0}' as i32 as libc::c_char;
            res = glob_fixed(glob, (*glob).glob_buffer, sublen);
        } else {
            match *pattern as libc::c_int {
                123 => {
                    pattern = pattern.offset(1);
                    pos = pos.wrapping_add(1);
                    let fresh30 = globindex;
                    globindex = globindex + 1;
                    res = glob_set(glob, &mut pattern, &mut pos, amount, fresh30);
                }
                91 => {
                    pattern = pattern.offset(1);
                    pos = pos.wrapping_add(1);
                    let fresh31 = globindex;
                    globindex = globindex + 1;
                    res = glob_range(glob, &mut pattern, &mut pos, amount, fresh31);
                }
                0 | _ => {}
            }
        }
        let ref mut fresh32 = (*glob).size;
        *fresh32 = (*fresh32).wrapping_add(1);
        if *fresh32 >= 100 as libc::c_int as libc::c_ulong {
            let ref mut fresh33 = (*glob).error;
            *fresh33 = b"too many globs\0" as *const u8 as *const libc::c_char;
            (*glob).pos = pos;
            return CURLE_URL_MALFORMAT as libc::c_int as CURLcode;
        }
    }
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn glob_url(
    mut glob: *mut *mut URLGlob,
    mut url: *mut libc::c_char,
    mut urlnum: *mut libc::c_ulong,
    mut error: *mut FILE,
) -> CURLcode {
    let mut glob_expand: *mut URLGlob = 0 as *mut URLGlob;
    let mut amount: libc::c_ulong = 0 as libc::c_int as libc::c_ulong;
    let mut glob_buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut res: CURLcode = CURLE_OK;
    *glob = 0 as *mut URLGlob;
    glob_buffer = malloc((strlen(url)).wrapping_add(1 as libc::c_int as libc::c_ulong))
        as *mut libc::c_char;
    if glob_buffer.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    *glob_buffer.offset(0 as libc::c_int as isize) = 0 as libc::c_int as libc::c_char;
    glob_expand = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::std::mem::size_of::<URLGlob>() as libc::c_ulong,
    ) as *mut URLGlob;
    if glob_expand.is_null() {
        free(glob_buffer as *mut libc::c_void);
        glob_buffer = 0 as *mut libc::c_char;
        return CURLE_OUT_OF_MEMORY;
    }
    (*glob_expand).urllen = strlen(url);
    let ref mut fresh34 = (*glob_expand).glob_buffer;
    *fresh34 = glob_buffer;
    res = glob_parse(glob_expand, url, 1 as libc::c_int as size_t, &mut amount);
    if res as u64 == 0 {
        *urlnum = amount;
    } else {
        if !error.is_null() && !((*glob_expand).error).is_null() {
            let mut text: [libc::c_char; 512] = [0; 512];
            let mut t: *const libc::c_char = 0 as *const libc::c_char;
            if (*glob_expand).pos != 0 {
                curl_msnprintf(
                    text.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong,
                    b"%s in URL position %zu:\n%s\n%*s^\0" as *const u8
                        as *const libc::c_char,
                    (*glob_expand).error,
                    (*glob_expand).pos,
                    url,
                    (*glob_expand).pos as libc::c_int - 1 as libc::c_int,
                    b" \0" as *const u8 as *const libc::c_char,
                );
                t = text.as_mut_ptr();
            } else {
                t = (*glob_expand).error;
            }
            curl_mfprintf(
                error,
                b"curl: (%d) %s\n\0" as *const u8 as *const libc::c_char,
                res as libc::c_uint,
                t,
            );
        }
        glob_cleanup(glob_expand);
        *urlnum = 1 as libc::c_int as libc::c_ulong;
        return res;
    }
    *glob = glob_expand;
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn glob_cleanup(mut glob: *mut URLGlob) {
    let mut i: size_t = 0;
    let mut elem: libc::c_int = 0;
    if glob.is_null() {
        return;
    }
    i = 0 as libc::c_int as size_t;
    while i < (*glob).size {
        if (*glob).pattern[i as usize].type_0 as libc::c_uint
            == UPTSet as libc::c_int as libc::c_uint
            && !((*glob).pattern[i as usize].content.Set.elements).is_null()
        {
            elem = (*glob).pattern[i as usize].content.Set.size - 1 as libc::c_int;
            while elem >= 0 as libc::c_int {
                free(
                    *((*glob).pattern[i as usize].content.Set.elements)
                        .offset(elem as isize) as *mut libc::c_void,
                );
                let ref mut fresh35 = *((*glob).pattern[i as usize].content.Set.elements)
                    .offset(elem as isize);
                *fresh35 = 0 as *mut libc::c_char;
                elem -= 1;
            }
            free((*glob).pattern[i as usize].content.Set.elements as *mut libc::c_void);
            let ref mut fresh36 = (*glob).pattern[i as usize].content.Set.elements;
            *fresh36 = 0 as *mut *mut libc::c_char;
        }
        i = i.wrapping_add(1);
    }
    free((*glob).glob_buffer as *mut libc::c_void);
    let ref mut fresh37 = (*glob).glob_buffer;
    *fresh37 = 0 as *mut libc::c_char;
    free(glob as *mut libc::c_void);
    glob = 0 as *mut URLGlob;
}
#[no_mangle]
pub unsafe extern "C" fn glob_next_url(
    mut globbed: *mut *mut libc::c_char,
    mut glob: *mut URLGlob,
) -> CURLcode {
    let mut pat: *mut URLPattern = 0 as *mut URLPattern;
    let mut i: size_t = 0;
    let mut len: size_t = 0;
    let mut buflen: size_t = ((*glob).urllen)
        .wrapping_add(1 as libc::c_int as libc::c_ulong);
    let mut buf: *mut libc::c_char = (*glob).glob_buffer;
    *globbed = 0 as *mut libc::c_char;
    if (*glob).beenhere == 0 {
        (*glob).beenhere = 1 as libc::c_int as libc::c_char;
    } else {
        let mut carry: bool = 1 as libc::c_int != 0;
        i = 0 as libc::c_int as size_t;
        while carry as libc::c_int != 0 && i < (*glob).size {
            carry = 0 as libc::c_int != 0;
            pat = &mut *((*glob).pattern)
                .as_mut_ptr()
                .offset(
                    ((*glob).size)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                        .wrapping_sub(i) as isize,
                ) as *mut URLPattern;
            match (*pat).type_0 as libc::c_uint {
                1 => {
                    if !((*pat).content.Set.elements).is_null()
                        && {
                            let ref mut fresh38 = (*pat).content.Set.ptr_s;
                            *fresh38 += 1;
                            *fresh38 == (*pat).content.Set.size
                        }
                    {
                        (*pat).content.Set.ptr_s = 0 as libc::c_int;
                        carry = 1 as libc::c_int != 0;
                    }
                }
                2 => {
                    (*pat)
                        .content
                        .CharRange
                        .ptr_c = ((*pat).content.CharRange.step
                        + (*pat).content.CharRange.ptr_c as libc::c_uchar as libc::c_int)
                        as libc::c_char;
                    if (*pat).content.CharRange.ptr_c as libc::c_int
                        > (*pat).content.CharRange.max_c as libc::c_int
                    {
                        (*pat).content.CharRange.ptr_c = (*pat).content.CharRange.min_c;
                        carry = 1 as libc::c_int != 0;
                    }
                }
                3 => {
                    let ref mut fresh39 = (*pat).content.NumRange.ptr_n;
                    *fresh39 = (*fresh39).wrapping_add((*pat).content.NumRange.step);
                    if (*pat).content.NumRange.ptr_n > (*pat).content.NumRange.max_n {
                        (*pat).content.NumRange.ptr_n = (*pat).content.NumRange.min_n;
                        carry = 1 as libc::c_int != 0;
                    }
                }
                _ => {
                    curl_mprintf(
                        b"internal error: invalid pattern type (%d)\n\0" as *const u8
                            as *const libc::c_char,
                        (*pat).type_0 as libc::c_int,
                    );
                    return CURLE_FAILED_INIT;
                }
            }
            i = i.wrapping_add(1);
        }
        if carry {
            return CURLE_OK;
        }
    }
    i = 0 as libc::c_int as size_t;
    while i < (*glob).size {
        pat = &mut *((*glob).pattern).as_mut_ptr().offset(i as isize) as *mut URLPattern;
        match (*pat).type_0 as libc::c_uint {
            1 => {
                if !((*pat).content.Set.elements).is_null() {
                    curl_msnprintf(
                        buf,
                        buflen,
                        b"%s\0" as *const u8 as *const libc::c_char,
                        *((*pat).content.Set.elements)
                            .offset((*pat).content.Set.ptr_s as isize),
                    );
                    len = strlen(buf);
                    buf = buf.offset(len as isize);
                    buflen = (buflen as libc::c_ulong).wrapping_sub(len) as size_t
                        as size_t;
                }
            }
            2 => {
                if buflen != 0 {
                    let fresh40 = buf;
                    buf = buf.offset(1);
                    *fresh40 = (*pat).content.CharRange.ptr_c;
                    *buf = '\u{0}' as i32 as libc::c_char;
                    buflen = buflen.wrapping_sub(1);
                }
            }
            3 => {
                curl_msnprintf(
                    buf,
                    buflen,
                    b"%0*lu\0" as *const u8 as *const libc::c_char,
                    (*pat).content.NumRange.padlength,
                    (*pat).content.NumRange.ptr_n,
                );
                len = strlen(buf);
                buf = buf.offset(len as isize);
                buflen = (buflen as libc::c_ulong).wrapping_sub(len) as size_t as size_t;
            }
            _ => {
                curl_mprintf(
                    b"internal error: invalid pattern type (%d)\n\0" as *const u8
                        as *const libc::c_char,
                    (*pat).type_0 as libc::c_int,
                );
                return CURLE_FAILED_INIT;
            }
        }
        i = i.wrapping_add(1);
    }
    *globbed = strdup((*glob).glob_buffer);
    if (*globbed).is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn glob_match_url(
    mut result: *mut *mut libc::c_char,
    mut filename: *mut libc::c_char,
    mut glob: *mut URLGlob,
) -> CURLcode {
    let mut numbuf: [libc::c_char; 18] = [0; 18];
    let mut appendthis: *mut libc::c_char = b"\0" as *const u8 as *const libc::c_char
        as *mut libc::c_char;
    let mut appendlen: size_t = 0 as libc::c_int as size_t;
    let mut dyn_0: dynbuf = dynbuf {
        bufr: 0 as *mut libc::c_char,
        leng: 0,
        allc: 0,
        toobig: 0,
    };
    *result = 0 as *mut libc::c_char;
    curlx_dyn_init(&mut dyn_0, (10 as libc::c_int * 1024 as libc::c_int) as size_t);
    while *filename != 0 {
        if *filename as libc::c_int == '#' as i32
            && Curl_isdigit(
                *filename.offset(1 as libc::c_int as isize) as libc::c_uchar
                    as libc::c_int,
            ) != 0
        {
            let mut ptr: *mut libc::c_char = filename;
            let mut num: libc::c_ulong = strtoul(
                &mut *filename.offset(1 as libc::c_int as isize),
                &mut filename,
                10 as libc::c_int,
            );
            let mut pat: *mut URLPattern = 0 as *mut URLPattern;
            if num != 0 && num < (*glob).size {
                let mut i: libc::c_ulong = 0;
                num = num.wrapping_sub(1);
                i = 0 as libc::c_int as libc::c_ulong;
                while i < (*glob).size {
                    if (*glob).pattern[i as usize].globindex == num as libc::c_int {
                        pat = &mut *((*glob).pattern).as_mut_ptr().offset(i as isize)
                            as *mut URLPattern;
                        break;
                    } else {
                        i = i.wrapping_add(1);
                    }
                }
            }
            if !pat.is_null() {
                match (*pat).type_0 as libc::c_uint {
                    1 => {
                        if !((*pat).content.Set.elements).is_null() {
                            appendthis = *((*pat).content.Set.elements)
                                .offset((*pat).content.Set.ptr_s as isize);
                            appendlen = strlen(
                                *((*pat).content.Set.elements)
                                    .offset((*pat).content.Set.ptr_s as isize),
                            );
                        }
                    }
                    2 => {
                        numbuf[0 as libc::c_int
                            as usize] = (*pat).content.CharRange.ptr_c;
                        numbuf[1 as libc::c_int
                            as usize] = 0 as libc::c_int as libc::c_char;
                        appendthis = numbuf.as_mut_ptr();
                        appendlen = 1 as libc::c_int as size_t;
                    }
                    3 => {
                        curl_msnprintf(
                            numbuf.as_mut_ptr(),
                            ::std::mem::size_of::<[libc::c_char; 18]>() as libc::c_ulong,
                            b"%0*lu\0" as *const u8 as *const libc::c_char,
                            (*pat).content.NumRange.padlength,
                            (*pat).content.NumRange.ptr_n,
                        );
                        appendthis = numbuf.as_mut_ptr();
                        appendlen = strlen(numbuf.as_mut_ptr());
                    }
                    _ => {
                        curl_mfprintf(
                            stderr,
                            b"internal error: invalid pattern type (%d)\n\0" as *const u8
                                as *const libc::c_char,
                            (*pat).type_0 as libc::c_int,
                        );
                        curlx_dyn_free(&mut dyn_0);
                        return CURLE_FAILED_INIT;
                    }
                }
            } else {
                filename = ptr;
                let fresh41 = filename;
                filename = filename.offset(1);
                appendthis = fresh41;
                appendlen = 1 as libc::c_int as size_t;
            }
        } else {
            let fresh42 = filename;
            filename = filename.offset(1);
            appendthis = fresh42;
            appendlen = 1 as libc::c_int as size_t;
        }
        if curlx_dyn_addn(&mut dyn_0, appendthis as *const libc::c_void, appendlen)
            as u64 != 0
        {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    *result = curlx_dyn_ptr(&mut dyn_0);
    return CURLE_OK;
}
