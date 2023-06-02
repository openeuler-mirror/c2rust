use ::libc;
extern "C" {
    
    
    
}
pub use crate::src::lib::warnless::curlx_uztoui;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub type size_t = u64;
pub type curl_malloc_callback<'a1> = Option<unsafe extern "C"  fn(_: u64,) -> Option<&'a1 mut core::ffi::c_void>>;
pub type curl_free_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> ()>;
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
pub type HMAC_hinit_func<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> ()>;
pub type HMAC_hupdate_func<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: Option<&'a2 u8>,_: u32,) -> ()>;
pub type HMAC_hfinal_func<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut u8>,_: Option<&'a2 mut core::ffi::c_void>,) -> ()>;
// #[derive(Copy, Clone)]

pub type HMAC_params = crate::src::lib::curl_ntlm_core::HMAC_params;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HMAC_context {
    pub hmac_hash: * const crate::src::lib::curl_ntlm_core::HMAC_params,
    pub hmac_hashctxt1: * mut core::ffi::c_void,
    pub hmac_hashctxt2: * mut core::ffi::c_void,
}
impl HMAC_context {
    pub const fn new() -> Self {
        HMAC_context {
        hmac_hash: (0 as * const crate::src::lib::curl_ntlm_core::HMAC_params),
        hmac_hashctxt1: (0 as * mut core::ffi::c_void),
        hmac_hashctxt2: (0 as * mut core::ffi::c_void)
        }
    }
}

impl std::default::Default for HMAC_context {
    fn default() -> Self { HMAC_context::new() }
}

static mut hmac_ipad: u8 = 0x36 as i32 as u8;
static mut hmac_opad: u8 = 0x5c as i32 as u8;
#[no_mangle]
pub unsafe extern "C" fn Curl_HMAC_init(
    mut hashparams: * const crate::src::lib::curl_ntlm_core::HMAC_params,
    mut key: * const u8,
    mut keylen: u32,
) -> * mut crate::src::lib::hmac::HMAC_context {
    let mut i: u64 = 0;
    let mut ctxt: * mut crate::src::lib::hmac::HMAC_context = 0 as *mut HMAC_context;
    let mut hkey: * mut u8 = 0 as *mut u8;
    let mut b: u8 = 0;
    i = (::std::mem::size_of::<HMAC_context>() as u64)
        .wrapping_add(
            (2 as i32 as u32).wrapping_mul((*hashparams).hmac_ctxtsize)
                as u64,
        )
        .wrapping_add((*hashparams).hmac_resultlen as u64);
    ctxt = Curl_cmalloc.expect("non-null function pointer")(i) as *mut HMAC_context;
    if ctxt.is_null() {
        return ctxt;
    }
    let mut fresh0 = &mut ((*ctxt).hmac_hash);
    *fresh0 = hashparams;
    let mut fresh1 = &mut ((*ctxt).hmac_hashctxt1);
    *fresh1 = ctxt.offset(1 as i32 as isize) as *mut libc::c_void;
    let mut fresh2 = &mut ((*ctxt).hmac_hashctxt2);
    *fresh2 = ((*ctxt).hmac_hashctxt1 as *mut i8)
        .offset((*hashparams).hmac_ctxtsize as isize) as *mut libc::c_void;
    if keylen > (*hashparams).hmac_maxkeylen {
        (Some(((*hashparams).hmac_hinit).expect("non-null function pointer")))
            .expect("non-null function pointer")((*ctxt).hmac_hashctxt1);
        (Some(((*hashparams).hmac_hupdate).expect("non-null function pointer")))
            .expect("non-null function pointer")((*ctxt).hmac_hashctxt1, key, keylen);
        hkey = ((*ctxt).hmac_hashctxt2 as *mut u8)
            .offset((*hashparams).hmac_ctxtsize as isize);
        (Some(((*hashparams).hmac_hfinal).expect("non-null function pointer")))
            .expect("non-null function pointer")(hkey, (*ctxt).hmac_hashctxt1);
        key = hkey;
        keylen = (*hashparams).hmac_resultlen;
    }
    (Some(((*hashparams).hmac_hinit).expect("non-null function pointer")))
        .expect("non-null function pointer")((*ctxt).hmac_hashctxt1);
    (Some(((*hashparams).hmac_hinit).expect("non-null function pointer")))
        .expect("non-null function pointer")((*ctxt).hmac_hashctxt2);
    i = 0 as i32 as size_t;
    while i < keylen as u64 {
        b = (*key as i32 ^ hmac_ipad as i32) as u8;
        (Some(((*hashparams).hmac_hupdate).expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )((*ctxt).hmac_hashctxt1, &mut b, 1 as i32 as u32);
        let mut fresh3 = key;
        key = key.offset(1);
        b = (*fresh3 as i32 ^ hmac_opad as i32) as u8;
        (Some(((*hashparams).hmac_hupdate).expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )((*ctxt).hmac_hashctxt2, &mut b, 1 as i32 as u32);
        i = i.wrapping_add(1);
    }
    while i < (*hashparams).hmac_maxkeylen as u64 {
        (Some(((*hashparams).hmac_hupdate).expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )((*ctxt).hmac_hashctxt1, &hmac_ipad, 1 as i32 as u32);
        (Some(((*hashparams).hmac_hupdate).expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )((*ctxt).hmac_hashctxt2, &hmac_opad, 1 as i32 as u32);
        i = i.wrapping_add(1);
    }
    return ctxt;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_HMAC_update(
    mut ctxt: * mut crate::src::lib::hmac::HMAC_context,
    mut data: * const u8,
    mut len: u32,
) -> i32 {
    (Some(((*(*ctxt).hmac_hash).hmac_hupdate).expect("non-null function pointer")))
        .expect("non-null function pointer")((*ctxt).hmac_hashctxt1, data, len);
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_HMAC_final(
    mut ctxt: * mut crate::src::lib::hmac::HMAC_context,
    mut result: * mut u8,
) -> i32 {
    let mut hashparams: * const crate::src::lib::curl_ntlm_core::HMAC_params = (*ctxt).hmac_hash;
    if result.is_null() {
        result = ((*ctxt).hmac_hashctxt2 as *mut u8)
            .offset((*(*ctxt).hmac_hash).hmac_ctxtsize as isize);
    }
    (Some(((*hashparams).hmac_hfinal).expect("non-null function pointer")))
        .expect("non-null function pointer")(result, (*ctxt).hmac_hashctxt1);
    (Some(((*hashparams).hmac_hupdate).expect("non-null function pointer")))
        .expect(
            "non-null function pointer",
        )((*ctxt).hmac_hashctxt2, result, (*hashparams).hmac_resultlen);
    (Some(((*hashparams).hmac_hfinal).expect("non-null function pointer")))
        .expect("non-null function pointer")(result, (*ctxt).hmac_hashctxt2);
    Curl_cfree
        .expect(
            "non-null function pointer",
        )(ctxt as *mut i8 as *mut libc::c_void);
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_hmacit(
    mut hashparams: * const crate::src::lib::curl_ntlm_core::HMAC_params,
    mut key: * const u8,
    keylen: u64,
    mut data: * const u8,
    datalen: u64,
    mut output: * mut u8,
) -> u32 {
    let mut ctxt: * mut crate::src::lib::hmac::HMAC_context = Curl_HMAC_init(
        hashparams,
        key,
        curlx_uztoui(keylen),
    );
    if ctxt.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    Curl_HMAC_update(ctxt, data, curlx_uztoui(datalen));
    Curl_HMAC_final(ctxt, output);
    return CURLE_OK;
}
use crate::laertes_rt::*;
