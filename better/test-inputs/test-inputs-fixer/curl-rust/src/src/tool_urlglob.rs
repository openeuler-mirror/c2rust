use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type Curl_URL;
    static mut stderr: *mut FILE;
    fn sscanf(_: *const i8, _: *const i8, _: ...) -> i32;
    fn Curl_isalpha(c: i32) -> i32;
    fn Curl_isdigit(c: i32) -> i32;
    fn curl_url() -> *mut CURLU;
    fn curl_url_cleanup(handle: *mut CURLU);
    fn curl_url_set(handle: *mut CURLU, what: CURLUPart, part: *const i8, flags: u32) -> CURLUcode;
    fn strtoul(_: *const i8, _: *mut *mut i8, _: i32) -> u64;
    fn malloc(_: u64) -> *mut libc::c_void;
    fn calloc(_: u64, _: u64) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn strdup(_: *const i8) -> *mut i8;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn __errno_location() -> *mut i32;
    fn curl_mprintf(format: *const i8, _: ...) -> i32;
    fn curl_mfprintf(fd: *mut FILE, format: *const i8, _: ...) -> i32;
    fn curl_msnprintf(buffer: *mut i8, maxlength: size_t, format: *const i8, _: ...) -> i32;
    fn curlx_dyn_init(s: *mut dynbuf, toobig: size_t);
    fn curlx_dyn_free(s: *mut dynbuf);
    fn curlx_dyn_addn(s: *mut dynbuf, mem: *const libc::c_void, len: size_t) -> CURLcode;
    fn curlx_dyn_ptr(s: *const dynbuf) -> *mut i8;
}
pub type __off_t = i64;
pub type __off64_t = i64;
pub type size_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: i32,
    pub _IO_read_ptr: *mut i8,
    pub _IO_read_end: *mut i8,
    pub _IO_read_base: *mut i8,
    pub _IO_write_base: *mut i8,
    pub _IO_write_ptr: *mut i8,
    pub _IO_write_end: *mut i8,
    pub _IO_buf_base: *mut i8,
    pub _IO_buf_end: *mut i8,
    pub _IO_save_base: *mut i8,
    pub _IO_backup_base: *mut i8,
    pub _IO_save_end: *mut i8,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: i32,
    pub _flags2: i32,
    pub _old_offset: __off_t,
    pub _cur_column: u16,
    pub _vtable_offset: i8,
    pub _shortbuf: [i8; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: i32,
    pub _unused2: [i8; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
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
pub type CURLUcode = u32;
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
pub type CURLUPart = u32;
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
    pub glob_buffer: *mut i8,
    pub beenhere: i8,
    pub error: *const i8,
    pub pos: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct URLPattern {
    pub type_0: URLPatternType,
    pub globindex: i32,
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
    pub min_n: u64,
    pub max_n: u64,
    pub padlength: i32,
    pub ptr_n: u64,
    pub step: u64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub min_c: i8,
    pub max_c: i8,
    pub ptr_c: i8,
    pub step: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub elements: *mut *mut i8,
    pub size: i32,
    pub ptr_s: i32,
}
pub type URLPatternType = u32;
pub const UPTNumRange: URLPatternType = 3;
pub const UPTCharRange: URLPatternType = 2;
pub const UPTSet: URLPatternType = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dynbuf {
    pub bufr: *mut i8,
    pub leng: size_t,
    pub allc: size_t,
    pub toobig: size_t,
}
extern "C" fn glob_fixed(mut glob: *mut URLGlob, mut fixed: *mut i8, mut len: size_t) -> CURLcode {
    let mut pat: *mut URLPattern =
        (unsafe { &mut *((*glob).pattern).as_mut_ptr().offset((*glob).size as isize) }) as *mut URLPattern;
    (unsafe { (*pat).type_0 = UPTSet });
    (unsafe { (*pat).content.Set.size = 1 as i32 });
    (unsafe { (*pat).content.Set.ptr_s = 0 as i32 });
    (unsafe { (*pat).globindex = -(1 as i32) });
    let fresh0 = unsafe { &mut ((*pat).content.Set.elements) };
    *fresh0 = (unsafe { malloc(::std::mem::size_of::<*mut i8>() as u64) }) as *mut *mut i8;
    if (unsafe { (*pat).content.Set.elements }).is_null() {
        let fresh1 = unsafe { &mut ((*glob).error) };
        *fresh1 = b"out of memory\0" as *const u8 as *const i8;
        (unsafe { (*glob).pos = 0 as i32 as size_t });
        return CURLE_OUT_OF_MEMORY as i32 as CURLcode;
    }
    let fresh2 = unsafe { &mut (*((*pat).content.Set.elements).offset(0 as i32 as isize)) };
    *fresh2 = (unsafe { malloc(len.wrapping_add(1 as i32 as u64)) }) as *mut i8;
    if (unsafe { *((*pat).content.Set.elements).offset(0 as i32 as isize) }).is_null() {
        let fresh3 = unsafe { &mut ((*glob).error) };
        *fresh3 = b"out of memory\0" as *const u8 as *const i8;
        (unsafe { (*glob).pos = 0 as i32 as size_t });
        return CURLE_OUT_OF_MEMORY as i32 as CURLcode;
    }
    (unsafe { memcpy(
        *((*pat).content.Set.elements).offset(0 as i32 as isize) as *mut libc::c_void,
        fixed as *const libc::c_void,
        len,
    ) });
    (unsafe { *(*((*pat).content.Set.elements).offset(0 as i32 as isize)).offset(len as isize) =
        0 as i32 as i8 });
    return CURLE_OK;
}
extern "C" fn multiply(mut amount: *mut u64, mut with: i64) -> i32 {
    let mut sum: u64 = (unsafe { *amount }).wrapping_mul(with as u64);
    if with == 0 {
        (unsafe { *amount = 0 as i32 as u64 });
        return 0 as i32;
    }
    if sum.wrapping_div(with as u64) != (unsafe { *amount }) {
        return 1 as i32;
    }
    (unsafe { *amount = sum });
    return 0 as i32;
}
extern "C" fn glob_set(
    mut glob: *mut URLGlob,
    mut patternp: *mut *mut i8,
    mut posp: *mut size_t,
    mut amount: *mut u64,
    mut globindex: i32,
) -> CURLcode {
    let mut pat: *mut URLPattern = 0 as *mut URLPattern;
    let mut done: bool = 0 as i32 != 0;
    let mut buf: *mut i8 = unsafe { (*glob).glob_buffer };
    let mut pattern: *mut i8 = unsafe { *patternp };
    let mut opattern: *mut i8 = pattern;
    let mut opos: size_t = (unsafe { *posp }).wrapping_sub(1 as i32 as u64);
    pat = (unsafe { &mut *((*glob).pattern).as_mut_ptr().offset((*glob).size as isize) }) as *mut URLPattern;
    (unsafe { (*pat).type_0 = UPTSet });
    (unsafe { (*pat).content.Set.size = 0 as i32 });
    (unsafe { (*pat).content.Set.ptr_s = 0 as i32 });
    let fresh4 = unsafe { &mut ((*pat).content.Set.elements) };
    *fresh4 = 0 as *mut *mut i8;
    (unsafe { (*pat).globindex = globindex });
    let mut current_block_36: u64;
    while !done {
        match (unsafe { *pattern }) as i32 {
            0 => {
                let fresh5 = unsafe { &mut ((*glob).error) };
                *fresh5 = b"unmatched brace\0" as *const u8 as *const i8;
                (unsafe { (*glob).pos = opos });
                return CURLE_URL_MALFORMAT as i32 as CURLcode;
            }
            123 | 91 => {
                let fresh6 = unsafe { &mut ((*glob).error) };
                *fresh6 = b"nested brace\0" as *const u8 as *const i8;
                (unsafe { (*glob).pos = *posp });
                return CURLE_URL_MALFORMAT as i32 as CURLcode;
            }
            125 => {
                if opattern == pattern {
                    let fresh7 = unsafe { &mut ((*glob).error) };
                    *fresh7 = b"empty string within braces\0" as *const u8 as *const i8;
                    (unsafe { (*glob).pos = *posp });
                    return CURLE_URL_MALFORMAT as i32 as CURLcode;
                }
                if multiply(amount, ((unsafe { (*pat).content.Set.size }) + 1 as i32) as i64) != 0 {
                    let fresh8 = unsafe { &mut ((*glob).error) };
                    *fresh8 = b"range overflow\0" as *const u8 as *const i8;
                    (unsafe { (*glob).pos = 0 as i32 as size_t });
                    return CURLE_URL_MALFORMAT as i32 as CURLcode;
                }
                current_block_36 = 6366302455163204299;
            }
            44 => {
                current_block_36 = 6366302455163204299;
            }
            93 => {
                let fresh16 = unsafe { &mut ((*glob).error) };
                *fresh16 = b"unexpected close bracket\0" as *const u8 as *const i8;
                (unsafe { (*glob).pos = *posp });
                return CURLE_URL_MALFORMAT as i32 as CURLcode;
            }
            92 => {
                if (unsafe { *pattern.offset(1 as i32 as isize) }) != 0 {
                    pattern = unsafe { pattern.offset(1) };
                    (unsafe { *posp = (*posp).wrapping_add(1) });
                }
                current_block_36 = 9754301318773204628;
            }
            _ => {
                current_block_36 = 9754301318773204628;
            }
        }
        match current_block_36 {
            6366302455163204299 => {
                (unsafe { *buf = '\u{0}' as i32 as i8 });
                if !(unsafe { (*pat).content.Set.elements }).is_null() {
                    let mut new_arr: *mut *mut i8 = (unsafe { realloc(
                        (*pat).content.Set.elements as *mut libc::c_void,
                        (((*pat).content.Set.size + 1 as i32) as u64)
                            .wrapping_mul(::std::mem::size_of::<*mut i8>() as u64),
                    ) }) as *mut *mut i8;
                    if new_arr.is_null() {
                        let fresh9 = unsafe { &mut ((*glob).error) };
                        *fresh9 = b"out of memory\0" as *const u8 as *const i8;
                        (unsafe { (*glob).pos = 0 as i32 as size_t });
                        return CURLE_OUT_OF_MEMORY as i32 as CURLcode;
                    }
                    let fresh10 = unsafe { &mut ((*pat).content.Set.elements) };
                    *fresh10 = new_arr;
                } else {
                    let fresh11 = unsafe { &mut ((*pat).content.Set.elements) };
                    *fresh11 = (unsafe { malloc(::std::mem::size_of::<*mut i8>() as u64) }) as *mut *mut i8;
                }
                if (unsafe { (*pat).content.Set.elements }).is_null() {
                    let fresh12 = unsafe { &mut ((*glob).error) };
                    *fresh12 = b"out of memory\0" as *const u8 as *const i8;
                    (unsafe { (*glob).pos = 0 as i32 as size_t });
                    return CURLE_OUT_OF_MEMORY as i32 as CURLcode;
                }
                let fresh13 =
                    unsafe { &mut (*((*pat).content.Set.elements).offset((*pat).content.Set.size as isize)) };
                *fresh13 = unsafe { strdup((*glob).glob_buffer) };
                if (unsafe { *((*pat).content.Set.elements).offset((*pat).content.Set.size as isize) })
                    .is_null()
                {
                    let fresh14 = unsafe { &mut ((*glob).error) };
                    *fresh14 = b"out of memory\0" as *const u8 as *const i8;
                    (unsafe { (*glob).pos = 0 as i32 as size_t });
                    return CURLE_OUT_OF_MEMORY as i32 as CURLcode;
                }
                let fresh15 = unsafe { &mut ((*pat).content.Set.size) };
                *fresh15 += 1;
                if (unsafe { *pattern }) as i32 == '}' as i32 {
                    pattern = unsafe { pattern.offset(1) };
                    done = 1 as i32 != 0;
                } else {
                    buf = unsafe { (*glob).glob_buffer };
                    pattern = unsafe { pattern.offset(1) };
                    (unsafe { *posp = (*posp).wrapping_add(1) });
                }
            }
            _ => {
                let fresh17 = pattern;
                pattern = unsafe { pattern.offset(1) };
                let fresh18 = buf;
                buf = unsafe { buf.offset(1) };
                (unsafe { *fresh18 = *fresh17 });
                (unsafe { *posp = (*posp).wrapping_add(1) });
            }
        }
    }
    (unsafe { *patternp = pattern });
    return CURLE_OK;
}
extern "C" fn glob_range(
    mut glob: *mut URLGlob,
    mut patternp: *mut *mut i8,
    mut posp: *mut size_t,
    mut amount: *mut u64,
    mut globindex: i32,
) -> CURLcode {
    let mut pat: *mut URLPattern = 0 as *mut URLPattern;
    let mut rc: i32 = 0;
    let mut pattern: *mut i8 = unsafe { *patternp };
    let mut c: *mut i8 = 0 as *mut i8;
    pat = (unsafe { &mut *((*glob).pattern).as_mut_ptr().offset((*glob).size as isize) }) as *mut URLPattern;
    (unsafe { (*pat).globindex = globindex });
    if (unsafe { Curl_isalpha(*pattern as u8 as i32) }) != 0 {
        let mut min_c: i8 = 0;
        let mut max_c: i8 = 0;
        let mut end_c: i8 = 0;
        let mut step: u64 = 1 as i32 as u64;
        (unsafe { (*pat).type_0 = UPTCharRange });
        rc = unsafe { sscanf(
            pattern,
            b"%c-%c%c\0" as *const u8 as *const i8,
            &mut min_c as *mut i8,
            &mut max_c as *mut i8,
            &mut end_c as *mut i8,
        ) };
        if rc == 3 as i32 {
            if end_c as i32 == ':' as i32 {
                let mut endp: *mut i8 = 0 as *mut i8;
                (unsafe { *__errno_location() = 0 as i32 });
                step = unsafe { strtoul(
                    &mut *pattern.offset(4 as i32 as isize),
                    &mut endp,
                    10 as i32,
                ) };
                if (unsafe { *__errno_location() }) != 0
                    || (unsafe { &mut *pattern.offset(4 as i32 as isize) }) as *mut i8 == endp
                    || (unsafe { *endp }) as i32 != ']' as i32
                {
                    step = 0 as i32 as u64;
                } else {
                    pattern = unsafe { endp.offset(1 as i32 as isize) };
                }
            } else if end_c as i32 != ']' as i32 {
                rc = 0 as i32;
            } else {
                pattern = unsafe { pattern.offset(4 as i32 as isize) };
            }
        }
        (unsafe { *posp = (*posp as u64).wrapping_add(pattern.offset_from(*patternp) as i64 as u64) as size_t
            as size_t });
        if rc != 3 as i32
            || step == 0
            || step > 2147483647 as i32 as u32 as u64
            || min_c as i32 == max_c as i32 && step != 1 as i32 as u64
            || min_c as i32 != max_c as i32
                && (min_c as i32 > max_c as i32
                    || step > (max_c as i32 - min_c as i32) as u32 as u64
                    || max_c as i32 - min_c as i32 > 'z' as i32 - 'a' as i32)
        {
            let fresh19 = unsafe { &mut ((*glob).error) };
            *fresh19 = b"bad range\0" as *const u8 as *const i8;
            (unsafe { (*glob).pos = *posp });
            return CURLE_URL_MALFORMAT as i32 as CURLcode;
        }
        (unsafe { (*pat).content.CharRange.step = step as i32 });
        let fresh20 = unsafe { &mut ((*pat).content.CharRange.min_c) };
        *fresh20 = min_c;
        (unsafe { (*pat).content.CharRange.ptr_c = *fresh20 });
        (unsafe { (*pat).content.CharRange.max_c = max_c });
        if multiply(
            amount,
            (((unsafe { (*pat).content.CharRange.max_c }) as i32 - (unsafe { (*pat).content.CharRange.min_c }) as i32)
                / (unsafe { (*pat).content.CharRange.step })
                + 1 as i32) as i64,
        ) != 0
        {
            let fresh21 = unsafe { &mut ((*glob).error) };
            *fresh21 = b"range overflow\0" as *const u8 as *const i8;
            (unsafe { (*glob).pos = *posp });
            return CURLE_URL_MALFORMAT as i32 as CURLcode;
        }
    } else if (unsafe { Curl_isdigit(*pattern as u8 as i32) }) != 0 {
        let mut min_n: u64 = 0;
        let mut max_n: u64 = 0 as i32 as u64;
        let mut step_n: u64 = 0 as i32 as u64;
        let mut endp_0: *mut i8 = 0 as *mut i8;
        (unsafe { (*pat).type_0 = UPTNumRange });
        (unsafe { (*pat).content.NumRange.padlength = 0 as i32 });
        if (unsafe { *pattern }) as i32 == '0' as i32 {
            c = pattern;
            while (unsafe { Curl_isdigit(*c as u8 as i32) }) != 0 {
                c = unsafe { c.offset(1) };
                let fresh22 = unsafe { &mut ((*pat).content.NumRange.padlength) };
                *fresh22 += 1;
            }
        }
        (unsafe { *__errno_location() = 0 as i32 });
        min_n = unsafe { strtoul(pattern, &mut endp_0, 10 as i32) };
        if (unsafe { *__errno_location() }) != 0 || endp_0 == pattern {
            endp_0 = 0 as *mut i8;
        } else if (unsafe { *endp_0 }) as i32 != '-' as i32 {
            endp_0 = 0 as *mut i8;
        } else {
            pattern = unsafe { endp_0.offset(1 as i32 as isize) };
            while (unsafe { *pattern }) as i32 != 0
                && ((unsafe { *pattern }) as u8 as i32 == ' ' as i32 || (unsafe { *pattern }) as u8 as i32 == '\t' as i32)
            {
                pattern = unsafe { pattern.offset(1) };
            }
            if (unsafe { Curl_isdigit(*pattern as u8 as i32) }) == 0 {
                endp_0 = 0 as *mut i8;
            } else {
                (unsafe { *__errno_location() = 0 as i32 });
                max_n = unsafe { strtoul(pattern, &mut endp_0, 10 as i32) };
                if (unsafe { *__errno_location() }) != 0 {
                    endp_0 = 0 as *mut i8;
                } else if (unsafe { *endp_0 }) as i32 == ':' as i32 {
                    pattern = unsafe { endp_0.offset(1 as i32 as isize) };
                    (unsafe { *__errno_location() = 0 as i32 });
                    step_n = unsafe { strtoul(pattern, &mut endp_0, 10 as i32) };
                    if (unsafe { *__errno_location() }) != 0 {
                        endp_0 = 0 as *mut i8;
                    }
                } else {
                    step_n = 1 as i32 as u64;
                }
                if !endp_0.is_null() && (unsafe { *endp_0 }) as i32 == ']' as i32 {
                    pattern = unsafe { endp_0.offset(1 as i32 as isize) };
                } else {
                    endp_0 = 0 as *mut i8;
                }
            }
        }
        (unsafe { *posp = (*posp as u64).wrapping_add(pattern.offset_from(*patternp) as i64 as u64) as size_t
            as size_t });
        if endp_0.is_null()
            || step_n == 0
            || min_n == max_n && step_n != 1 as i32 as u64
            || min_n != max_n && (min_n > max_n || step_n > max_n.wrapping_sub(min_n))
        {
            let fresh23 = unsafe { &mut ((*glob).error) };
            *fresh23 = b"bad range\0" as *const u8 as *const i8;
            (unsafe { (*glob).pos = *posp });
            return CURLE_URL_MALFORMAT as i32 as CURLcode;
        }
        let fresh24 = unsafe { &mut ((*pat).content.NumRange.min_n) };
        *fresh24 = min_n;
        (unsafe { (*pat).content.NumRange.ptr_n = *fresh24 });
        (unsafe { (*pat).content.NumRange.max_n = max_n });
        (unsafe { (*pat).content.NumRange.step = step_n });
        if multiply(
            amount,
            (unsafe { (*pat).content.NumRange.max_n })
                .wrapping_sub(unsafe { (*pat).content.NumRange.min_n })
                .wrapping_div(unsafe { (*pat).content.NumRange.step })
                .wrapping_add(1 as i32 as u64) as i64,
        ) != 0
        {
            let fresh25 = unsafe { &mut ((*glob).error) };
            *fresh25 = b"range overflow\0" as *const u8 as *const i8;
            (unsafe { (*glob).pos = *posp });
            return CURLE_URL_MALFORMAT as i32 as CURLcode;
        }
    } else {
        let fresh26 = unsafe { &mut ((*glob).error) };
        *fresh26 = b"bad range specification\0" as *const u8 as *const i8;
        (unsafe { (*glob).pos = *posp });
        return CURLE_URL_MALFORMAT as i32 as CURLcode;
    }
    (unsafe { *patternp = pattern });
    return CURLE_OK;
}
extern "C" fn peek_ipv6(mut str: *const i8, mut skip: *mut size_t) -> bool {
    let mut hostname: [i8; 128] = [0; 128];
    let mut u: *mut CURLU = 0 as *mut CURLU;
    let mut endbr: *mut i8 = unsafe { strchr(str, ']' as i32) };
    let mut hlen: size_t = 0;
    let mut rc: CURLUcode = CURLUE_OK;
    if endbr.is_null() {
        return 0 as i32 != 0;
    }
    hlen = ((unsafe { endbr.offset_from(str) }) as i64 + 1 as i32 as i64) as size_t;
    if hlen >= 128 as i32 as u64 {
        return 0 as i32 != 0;
    }
    u = unsafe { curl_url() };
    if u.is_null() {
        return 0 as i32 != 0;
    }
    (unsafe { memcpy(
        hostname.as_mut_ptr() as *mut libc::c_void,
        str as *const libc::c_void,
        hlen,
    ) });
    hostname[hlen as usize] = 0 as i32 as i8;
    rc = unsafe { curl_url_set(
        u,
        CURLUPART_URL,
        hostname.as_mut_ptr(),
        ((1 as i32) << 9 as i32) as u32,
    ) };
    (unsafe { curl_url_cleanup(u) });
    if rc as u64 == 0 {
        (unsafe { *skip = hlen });
    }
    return if rc as u32 != 0 { 0 as i32 } else { 1 as i32 } != 0;
}
extern "C" fn glob_parse(
    mut glob: *mut URLGlob,
    mut pattern: *mut i8,
    mut pos: size_t,
    mut amount: *mut u64,
) -> CURLcode {
    let mut res: CURLcode = CURLE_OK;
    let mut globindex: i32 = 0 as i32;
    (unsafe { *amount = 1 as i32 as u64 });
    while (unsafe { *pattern }) as i32 != 0 && res as u64 == 0 {
        let mut buf: *mut i8 = unsafe { (*glob).glob_buffer };
        let mut sublen: size_t = 0 as i32 as size_t;
        while (unsafe { *pattern }) as i32 != 0 && (unsafe { *pattern }) as i32 != '{' as i32 {
            if (unsafe { *pattern }) as i32 == '[' as i32 {
                let mut skip: size_t = 0 as i32 as size_t;
                if !peek_ipv6(pattern, &mut skip)
                    && (unsafe { *pattern.offset(1 as i32 as isize) }) as i32 == ']' as i32
                {
                    skip = 2 as i32 as size_t;
                }
                if !(skip != 0) {
                    break;
                }
                (unsafe { memcpy(
                    buf as *mut libc::c_void,
                    pattern as *const libc::c_void,
                    skip,
                ) });
                buf = unsafe { buf.offset(skip as isize) };
                pattern = unsafe { pattern.offset(skip as isize) };
                sublen = (sublen as u64).wrapping_add(skip) as size_t as size_t;
            } else {
                if (unsafe { *pattern }) as i32 == '}' as i32 || (unsafe { *pattern }) as i32 == ']' as i32 {
                    let fresh27 = unsafe { &mut ((*glob).error) };
                    *fresh27 = b"unmatched close brace/bracket\0" as *const u8 as *const i8;
                    (unsafe { (*glob).pos = pos });
                    return CURLE_URL_MALFORMAT as i32 as CURLcode;
                }
                if (unsafe { *pattern }) as i32 == '\\' as i32
                    && ((unsafe { *pattern.offset(1 as i32 as isize) }) as i32 == '{' as i32
                        || (unsafe { *pattern.offset(1 as i32 as isize) }) as i32 == '[' as i32
                        || (unsafe { *pattern.offset(1 as i32 as isize) }) as i32 == '}' as i32
                        || (unsafe { *pattern.offset(1 as i32 as isize) }) as i32 == ']' as i32)
                {
                    pattern = unsafe { pattern.offset(1) };
                    pos = pos.wrapping_add(1);
                }
                let fresh28 = pattern;
                pattern = unsafe { pattern.offset(1) };
                let fresh29 = buf;
                buf = unsafe { buf.offset(1) };
                (unsafe { *fresh29 = *fresh28 });
                pos = pos.wrapping_add(1);
                sublen = sublen.wrapping_add(1);
            }
        }
        if sublen != 0 {
            (unsafe { *buf = '\u{0}' as i32 as i8 });
            res = glob_fixed(glob, unsafe { (*glob).glob_buffer }, sublen);
        } else {
            match (unsafe { *pattern }) as i32 {
                123 => {
                    pattern = unsafe { pattern.offset(1) };
                    pos = pos.wrapping_add(1);
                    let fresh30 = globindex;
                    globindex = globindex + 1;
                    res = glob_set(glob, &mut pattern, &mut pos, amount, fresh30);
                }
                91 => {
                    pattern = unsafe { pattern.offset(1) };
                    pos = pos.wrapping_add(1);
                    let fresh31 = globindex;
                    globindex = globindex + 1;
                    res = glob_range(glob, &mut pattern, &mut pos, amount, fresh31);
                }
                0 | _ => {}
            }
        }
        let fresh32 = unsafe { &mut ((*glob).size) };
        *fresh32 = (*fresh32).wrapping_add(1);
        if *fresh32 >= 100 as i32 as u64 {
            let fresh33 = unsafe { &mut ((*glob).error) };
            *fresh33 = b"too many globs\0" as *const u8 as *const i8;
            (unsafe { (*glob).pos = pos });
            return CURLE_URL_MALFORMAT as i32 as CURLcode;
        }
    }
    return res;
}
#[no_mangle]
pub extern "C" fn glob_url(
    mut glob: *mut *mut URLGlob,
    mut url: *mut i8,
    mut urlnum: *mut u64,
    mut error: *mut FILE,
) -> CURLcode {
    let mut glob_expand: *mut URLGlob = 0 as *mut URLGlob;
    let mut amount: u64 = 0 as i32 as u64;
    let mut glob_buffer: *mut i8 = 0 as *mut i8;
    let mut res: CURLcode = CURLE_OK;
    (unsafe { *glob = 0 as *mut URLGlob });
    glob_buffer = (unsafe { malloc((strlen(url)).wrapping_add(1 as i32 as u64)) }) as *mut i8;
    if glob_buffer.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    (unsafe { *glob_buffer.offset(0 as i32 as isize) = 0 as i32 as i8 });
    glob_expand = (unsafe { calloc(1 as i32 as u64, ::std::mem::size_of::<URLGlob>() as u64) }) as *mut URLGlob;
    if glob_expand.is_null() {
        (unsafe { free(glob_buffer as *mut libc::c_void) });
        glob_buffer = 0 as *mut i8;
        return CURLE_OUT_OF_MEMORY;
    }
    (unsafe { (*glob_expand).urllen = strlen(url) });
    let fresh34 = unsafe { &mut ((*glob_expand).glob_buffer) };
    *fresh34 = glob_buffer;
    res = glob_parse(glob_expand, url, 1 as i32 as size_t, &mut amount);
    if res as u64 == 0 {
        (unsafe { *urlnum = amount });
    } else {
        if !error.is_null() && !(unsafe { (*glob_expand).error }).is_null() {
            let mut text: [i8; 512] = [0; 512];
            let mut t: *const i8 = 0 as *const i8;
            if (unsafe { (*glob_expand).pos }) != 0 {
                (unsafe { curl_msnprintf(
                    text.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 512]>() as u64,
                    b"%s in URL position %zu:\n%s\n%*s^\0" as *const u8 as *const i8,
                    (*glob_expand).error,
                    (*glob_expand).pos,
                    url,
                    (*glob_expand).pos as i32 - 1 as i32,
                    b" \0" as *const u8 as *const i8,
                ) });
                t = text.as_mut_ptr();
            } else {
                t = unsafe { (*glob_expand).error };
            }
            (unsafe { curl_mfprintf(
                error,
                b"curl: (%d) %s\n\0" as *const u8 as *const i8,
                res as u32,
                t,
            ) });
        }
        glob_cleanup(glob_expand);
        (unsafe { *urlnum = 1 as i32 as u64 });
        return res;
    }
    (unsafe { *glob = glob_expand });
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn glob_cleanup(mut glob: *mut URLGlob) {
    let mut i: size_t = 0;
    let mut elem: i32 = 0;
    if glob.is_null() {
        return;
    }
    i = 0 as i32 as size_t;
    while i < (unsafe { (*glob).size }) {
        if (unsafe { (*glob).pattern[i as usize].type_0 }) as u32 == UPTSet as i32 as u32
            && !(unsafe { (*glob).pattern[i as usize].content.Set.elements }).is_null()
        {
            elem = (unsafe { (*glob).pattern[i as usize].content.Set.size }) - 1 as i32;
            while elem >= 0 as i32 {
                (unsafe { free(
                    *((*glob).pattern[i as usize].content.Set.elements).offset(elem as isize)
                        as *mut libc::c_void,
                ) });
                let fresh35 = unsafe { &mut (*((*glob).pattern[i as usize].content.Set.elements)
                    .offset(elem as isize)) };
                *fresh35 = 0 as *mut i8;
                elem -= 1;
            }
            (unsafe { free((*glob).pattern[i as usize].content.Set.elements as *mut libc::c_void) });
            let fresh36 = unsafe { &mut ((*glob).pattern[i as usize].content.Set.elements) };
            *fresh36 = 0 as *mut *mut i8;
        }
        i = i.wrapping_add(1);
    }
    (unsafe { free((*glob).glob_buffer as *mut libc::c_void) });
    let fresh37 = unsafe { &mut ((*glob).glob_buffer) };
    *fresh37 = 0 as *mut i8;
    (unsafe { free(glob as *mut libc::c_void) });
    glob = 0 as *mut URLGlob;
}
#[no_mangle]
pub extern "C" fn glob_next_url(mut globbed: *mut *mut i8, mut glob: *mut URLGlob) -> CURLcode {
    let mut pat: *mut URLPattern = 0 as *mut URLPattern;
    let mut i: size_t = 0;
    let mut len: size_t = 0;
    let mut buflen: size_t = (unsafe { (*glob).urllen }).wrapping_add(1 as i32 as u64);
    let mut buf: *mut i8 = unsafe { (*glob).glob_buffer };
    (unsafe { *globbed = 0 as *mut i8 });
    if (unsafe { (*glob).beenhere }) == 0 {
        (unsafe { (*glob).beenhere = 1 as i32 as i8 });
    } else {
        let mut carry: bool = 1 as i32 != 0;
        i = 0 as i32 as size_t;
        while carry as i32 != 0 && i < (unsafe { (*glob).size }) {
            carry = 0 as i32 != 0;
            pat = (unsafe { &mut *((*glob).pattern)
                .as_mut_ptr()
                .offset(((*glob).size).wrapping_sub(1 as i32 as u64).wrapping_sub(i) as isize) })
                as *mut URLPattern;
            match (unsafe { (*pat).type_0 }) as u32 {
                1 => {
                    if !(unsafe { (*pat).content.Set.elements }).is_null() && {
                        let fresh38 = unsafe { &mut ((*pat).content.Set.ptr_s) };
                        *fresh38 += 1;
                        *fresh38 == (unsafe { (*pat).content.Set.size })
                    } {
                        (unsafe { (*pat).content.Set.ptr_s = 0 as i32 });
                        carry = 1 as i32 != 0;
                    }
                }
                2 => {
                    (unsafe { (*pat).content.CharRange.ptr_c = ((*pat).content.CharRange.step
                        + (*pat).content.CharRange.ptr_c as u8 as i32)
                        as i8 });
                    if (unsafe { (*pat).content.CharRange.ptr_c }) as i32 > (unsafe { (*pat).content.CharRange.max_c }) as i32
                    {
                        (unsafe { (*pat).content.CharRange.ptr_c = (*pat).content.CharRange.min_c });
                        carry = 1 as i32 != 0;
                    }
                }
                3 => {
                    let fresh39 = unsafe { &mut ((*pat).content.NumRange.ptr_n) };
                    *fresh39 = (*fresh39).wrapping_add(unsafe { (*pat).content.NumRange.step });
                    if (unsafe { (*pat).content.NumRange.ptr_n }) > (unsafe { (*pat).content.NumRange.max_n }) {
                        (unsafe { (*pat).content.NumRange.ptr_n = (*pat).content.NumRange.min_n });
                        carry = 1 as i32 != 0;
                    }
                }
                _ => {
                    (unsafe { curl_mprintf(
                        b"internal error: invalid pattern type (%d)\n\0" as *const u8 as *const i8,
                        (*pat).type_0 as i32,
                    ) });
                    return CURLE_FAILED_INIT;
                }
            }
            i = i.wrapping_add(1);
        }
        if carry {
            return CURLE_OK;
        }
    }
    i = 0 as i32 as size_t;
    while i < (unsafe { (*glob).size }) {
        pat = (unsafe { &mut *((*glob).pattern).as_mut_ptr().offset(i as isize) }) as *mut URLPattern;
        match (unsafe { (*pat).type_0 }) as u32 {
            1 => {
                if !(unsafe { (*pat).content.Set.elements }).is_null() {
                    (unsafe { curl_msnprintf(
                        buf,
                        buflen,
                        b"%s\0" as *const u8 as *const i8,
                        *((*pat).content.Set.elements).offset((*pat).content.Set.ptr_s as isize),
                    ) });
                    len = unsafe { strlen(buf) };
                    buf = unsafe { buf.offset(len as isize) };
                    buflen = (buflen as u64).wrapping_sub(len) as size_t as size_t;
                }
            }
            2 => {
                if buflen != 0 {
                    let fresh40 = buf;
                    buf = unsafe { buf.offset(1) };
                    (unsafe { *fresh40 = (*pat).content.CharRange.ptr_c });
                    (unsafe { *buf = '\u{0}' as i32 as i8 });
                    buflen = buflen.wrapping_sub(1);
                }
            }
            3 => {
                (unsafe { curl_msnprintf(
                    buf,
                    buflen,
                    b"%0*lu\0" as *const u8 as *const i8,
                    (*pat).content.NumRange.padlength,
                    (*pat).content.NumRange.ptr_n,
                ) });
                len = unsafe { strlen(buf) };
                buf = unsafe { buf.offset(len as isize) };
                buflen = (buflen as u64).wrapping_sub(len) as size_t as size_t;
            }
            _ => {
                (unsafe { curl_mprintf(
                    b"internal error: invalid pattern type (%d)\n\0" as *const u8 as *const i8,
                    (*pat).type_0 as i32,
                ) });
                return CURLE_FAILED_INIT;
            }
        }
        i = i.wrapping_add(1);
    }
    (unsafe { *globbed = strdup((*glob).glob_buffer) });
    if (unsafe { *globbed }).is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    return CURLE_OK;
}
#[no_mangle]
pub extern "C" fn glob_match_url(
    mut result: *mut *mut i8,
    mut filename: *mut i8,
    mut glob: *mut URLGlob,
) -> CURLcode {
    let mut numbuf: [i8; 18] = [0; 18];
    let mut appendthis: *mut i8 = b"\0" as *const u8 as *const i8 as *mut i8;
    let mut appendlen: size_t = 0 as i32 as size_t;
    let mut dyn_0: dynbuf = dynbuf {
        bufr: 0 as *mut i8,
        leng: 0,
        allc: 0,
        toobig: 0,
    };
    (unsafe { *result = 0 as *mut i8 });
    (unsafe { curlx_dyn_init(&mut dyn_0, (10 as i32 * 1024 as i32) as size_t) });
    while (unsafe { *filename }) != 0 {
        if (unsafe { *filename }) as i32 == '#' as i32
            && (unsafe { Curl_isdigit(*filename.offset(1 as i32 as isize) as u8 as i32) }) != 0
        {
            let mut ptr: *mut i8 = filename;
            let mut num: u64 = unsafe { strtoul(
                &mut *filename.offset(1 as i32 as isize),
                &mut filename,
                10 as i32,
            ) };
            let mut pat: *mut URLPattern = 0 as *mut URLPattern;
            if num != 0 && num < (unsafe { (*glob).size }) {
                let mut i: u64 = 0;
                num = num.wrapping_sub(1);
                i = 0 as i32 as u64;
                while i < (unsafe { (*glob).size }) {
                    if (unsafe { (*glob).pattern[i as usize].globindex }) == num as i32 {
                        pat = (unsafe { &mut *((*glob).pattern).as_mut_ptr().offset(i as isize) })
                            as *mut URLPattern;
                        break;
                    } else {
                        i = i.wrapping_add(1);
                    }
                }
            }
            if !pat.is_null() {
                match (unsafe { (*pat).type_0 }) as u32 {
                    1 => {
                        if !(unsafe { (*pat).content.Set.elements }).is_null() {
                            appendthis = unsafe { *((*pat).content.Set.elements)
                                .offset((*pat).content.Set.ptr_s as isize) };
                            appendlen = unsafe { strlen(
                                *((*pat).content.Set.elements)
                                    .offset((*pat).content.Set.ptr_s as isize),
                            ) };
                        }
                    }
                    2 => {
                        numbuf[0 as i32 as usize] = unsafe { (*pat).content.CharRange.ptr_c };
                        numbuf[1 as i32 as usize] = 0 as i32 as i8;
                        appendthis = numbuf.as_mut_ptr();
                        appendlen = 1 as i32 as size_t;
                    }
                    3 => {
                        (unsafe { curl_msnprintf(
                            numbuf.as_mut_ptr(),
                            ::std::mem::size_of::<[i8; 18]>() as u64,
                            b"%0*lu\0" as *const u8 as *const i8,
                            (*pat).content.NumRange.padlength,
                            (*pat).content.NumRange.ptr_n,
                        ) });
                        appendthis = numbuf.as_mut_ptr();
                        appendlen = unsafe { strlen(numbuf.as_mut_ptr()) };
                    }
                    _ => {
                        (unsafe { curl_mfprintf(
                            stderr,
                            b"internal error: invalid pattern type (%d)\n\0" as *const u8
                                as *const i8,
                            (*pat).type_0 as i32,
                        ) });
                        (unsafe { curlx_dyn_free(&mut dyn_0) });
                        return CURLE_FAILED_INIT;
                    }
                }
            } else {
                filename = ptr;
                let fresh41 = filename;
                filename = unsafe { filename.offset(1) };
                appendthis = fresh41;
                appendlen = 1 as i32 as size_t;
            }
        } else {
            let fresh42 = filename;
            filename = unsafe { filename.offset(1) };
            appendthis = fresh42;
            appendlen = 1 as i32 as size_t;
        }
        if (unsafe { curlx_dyn_addn(&mut dyn_0, appendthis as *const libc::c_void, appendlen) }) as u64 != 0 {
            return CURLE_OUT_OF_MEMORY;
        }
    }
    (unsafe { *result = curlx_dyn_ptr(&mut dyn_0) });
    return CURLE_OK;
}
