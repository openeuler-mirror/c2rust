use ::libc;
extern "C" {
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn Curl_dyn_vprintf(
        dyn_0: *mut dynbuf,
        format: *const libc::c_char,
        ap_save: ::std::ffi::VaList,
    ) -> libc::c_int;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_crealloc: curl_realloc_callback;
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: libc::c_uint,
    pub fp_offset: libc::c_uint,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type size_t = libc::c_ulong;
pub type va_list = __builtin_va_list;
pub type curl_free_callback = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type curl_realloc_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void,
>;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dynbuf {
    pub bufr: *mut libc::c_char,
    pub leng: size_t,
    pub allc: size_t,
    pub toobig: size_t,
}
#[no_mangle]
pub unsafe extern "C" fn Curl_dyn_init(mut s: *mut dynbuf, mut toobig: size_t) {
    let ref mut fresh0 = (*s).bufr;
    *fresh0 = 0 as *mut libc::c_char;
    (*s).leng = 0 as libc::c_int as size_t;
    (*s).allc = 0 as libc::c_int as size_t;
    (*s).toobig = toobig;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_dyn_free(mut s: *mut dynbuf) {
    Curl_cfree.expect("non-null function pointer")((*s).bufr as *mut libc::c_void);
    let ref mut fresh1 = (*s).bufr;
    *fresh1 = 0 as *mut libc::c_char;
    let ref mut fresh2 = (*s).allc;
    *fresh2 = 0 as libc::c_int as size_t;
    (*s).leng = *fresh2;
}
unsafe extern "C" fn dyn_nappend(
    mut s: *mut dynbuf,
    mut mem: *const libc::c_uchar,
    mut len: size_t,
) -> CURLcode {
    let mut indx: size_t = (*s).leng;
    let mut a: size_t = (*s).allc;
    let mut fit: size_t = len
        .wrapping_add(indx)
        .wrapping_add(1 as libc::c_int as libc::c_ulong);
    if fit > (*s).toobig {
        Curl_dyn_free(s);
        return CURLE_OUT_OF_MEMORY;
    } else {
        if a == 0 {
            if fit < 32 as libc::c_int as libc::c_ulong {
                a = 32 as libc::c_int as size_t;
            } else {
                a = fit;
            }
        } else {
            while a < fit {
                a = (a as libc::c_ulong).wrapping_mul(2 as libc::c_int as libc::c_ulong)
                    as size_t as size_t;
            }
        }
    }
    if a != (*s).allc {
        let mut p: *mut libc::c_void = Curl_crealloc
            .expect("non-null function pointer")((*s).bufr as *mut libc::c_void, a);
        if p.is_null() {
            Curl_cfree
                .expect("non-null function pointer")((*s).bufr as *mut libc::c_void);
            let ref mut fresh3 = (*s).bufr;
            *fresh3 = 0 as *mut libc::c_char;
            let ref mut fresh4 = (*s).allc;
            *fresh4 = 0 as libc::c_int as size_t;
            (*s).leng = *fresh4;
            return CURLE_OUT_OF_MEMORY;
        }
        let ref mut fresh5 = (*s).bufr;
        *fresh5 = p as *mut libc::c_char;
        (*s).allc = a;
    }
    if len != 0 {
        memcpy(
            &mut *((*s).bufr).offset(indx as isize) as *mut libc::c_char
                as *mut libc::c_void,
            mem as *const libc::c_void,
            len,
        );
    }
    (*s).leng = indx.wrapping_add(len);
    *((*s).bufr).offset((*s).leng as isize) = 0 as libc::c_int as libc::c_char;
    return CURLE_OK;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_dyn_reset(mut s: *mut dynbuf) {
    if (*s).leng != 0 {
        *((*s).bufr)
            .offset(0 as libc::c_int as isize) = 0 as libc::c_int as libc::c_char;
    }
    (*s).leng = 0 as libc::c_int as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_dyn_addn(
    mut s: *mut dynbuf,
    mut mem: *const libc::c_void,
    mut len: size_t,
) -> CURLcode {
    return dyn_nappend(s, mem as *const libc::c_uchar, len);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_dyn_add(
    mut s: *mut dynbuf,
    mut str: *const libc::c_char,
) -> CURLcode {
    let mut n: size_t = strlen(str);
    return dyn_nappend(s, str as *mut libc::c_uchar, n);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_dyn_vaddf(
    mut s: *mut dynbuf,
    mut fmt: *const libc::c_char,
    mut ap: ::std::ffi::VaList,
) -> CURLcode {
    let mut rc: libc::c_int = 0;
    rc = Curl_dyn_vprintf(s, fmt, ap.as_va_list());
    if rc == 0 {
        return CURLE_OK;
    }
    return CURLE_OUT_OF_MEMORY;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_dyn_addf(
    mut s: *mut dynbuf,
    mut fmt: *const libc::c_char,
    mut args: ...
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    result = Curl_dyn_vaddf(s, fmt, ap.as_va_list());
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_dyn_ptr(mut s: *const dynbuf) -> *mut libc::c_char {
    return (*s).bufr;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_dyn_uptr(mut s: *const dynbuf) -> *mut libc::c_uchar {
    return (*s).bufr as *mut libc::c_uchar;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_dyn_len(mut s: *const dynbuf) -> size_t {
    return (*s).leng;
}
