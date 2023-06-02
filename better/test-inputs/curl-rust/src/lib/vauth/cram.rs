use ::libc;
extern "C" {
    fn curl_free(p: *mut libc::c_void);
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn Curl_bufref_set(
        br: *mut bufref,
        ptr: *const libc::c_void,
        len: size_t,
        dtor: Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    );
    fn Curl_bufref_ptr(br: *const bufref) -> *const libc::c_uchar;
    fn Curl_bufref_len(br: *const bufref) -> size_t;
    fn Curl_HMAC_init(
        hashparams: *const HMAC_params,
        key: *const libc::c_uchar,
        keylen: libc::c_uint,
    ) -> *mut HMAC_context;
    fn Curl_HMAC_update(
        context: *mut HMAC_context,
        data: *const libc::c_uchar,
        len: libc::c_uint,
    ) -> libc::c_int;
    fn Curl_HMAC_final(
        context: *mut HMAC_context,
        result: *mut libc::c_uchar,
    ) -> libc::c_int;
    static Curl_HMAC_MD5: [HMAC_params; 1];
    fn curlx_uztoui(uznum: size_t) -> libc::c_uint;
    fn curl_maprintf(format: *const libc::c_char, _: ...) -> *mut libc::c_char;
}
pub type size_t = libc::c_ulong;
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
pub struct bufref {
    pub dtor: Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    pub ptr: *const libc::c_uchar,
    pub len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HMAC_context {
    pub hmac_hash: *const HMAC_params,
    pub hmac_hashctxt1: *mut libc::c_void,
    pub hmac_hashctxt2: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HMAC_params {
    pub hmac_hinit: HMAC_hinit_func,
    pub hmac_hupdate: HMAC_hupdate_func,
    pub hmac_hfinal: HMAC_hfinal_func,
    pub hmac_ctxtsize: libc::c_uint,
    pub hmac_maxkeylen: libc::c_uint,
    pub hmac_resultlen: libc::c_uint,
}
pub type HMAC_hfinal_func = Option::<
    unsafe extern "C" fn(*mut libc::c_uchar, *mut libc::c_void) -> (),
>;
pub type HMAC_hupdate_func = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_uchar, libc::c_uint) -> (),
>;
pub type HMAC_hinit_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
#[no_mangle]
pub unsafe extern "C" fn Curl_auth_create_cram_md5_message(
    mut chlg: *const bufref,
    mut userp: *const libc::c_char,
    mut passwdp: *const libc::c_char,
    mut out: *mut bufref,
) -> CURLcode {
    let mut ctxt: *mut HMAC_context = 0 as *mut HMAC_context;
    let mut digest: [libc::c_uchar; 16] = [0; 16];
    let mut response: *mut libc::c_char = 0 as *mut libc::c_char;
    ctxt = Curl_HMAC_init(
        Curl_HMAC_MD5.as_ptr(),
        passwdp as *const libc::c_uchar,
        curlx_uztoui(strlen(passwdp)),
    );
    if ctxt.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    if Curl_bufref_len(chlg) != 0 {
        Curl_HMAC_update(
            ctxt,
            Curl_bufref_ptr(chlg),
            curlx_uztoui(Curl_bufref_len(chlg)),
        );
    }
    Curl_HMAC_final(ctxt, digest.as_mut_ptr());
    response = curl_maprintf(
        b"%s %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\0"
            as *const u8 as *const libc::c_char,
        userp,
        digest[0 as libc::c_int as usize] as libc::c_int,
        digest[1 as libc::c_int as usize] as libc::c_int,
        digest[2 as libc::c_int as usize] as libc::c_int,
        digest[3 as libc::c_int as usize] as libc::c_int,
        digest[4 as libc::c_int as usize] as libc::c_int,
        digest[5 as libc::c_int as usize] as libc::c_int,
        digest[6 as libc::c_int as usize] as libc::c_int,
        digest[7 as libc::c_int as usize] as libc::c_int,
        digest[8 as libc::c_int as usize] as libc::c_int,
        digest[9 as libc::c_int as usize] as libc::c_int,
        digest[10 as libc::c_int as usize] as libc::c_int,
        digest[11 as libc::c_int as usize] as libc::c_int,
        digest[12 as libc::c_int as usize] as libc::c_int,
        digest[13 as libc::c_int as usize] as libc::c_int,
        digest[14 as libc::c_int as usize] as libc::c_int,
        digest[15 as libc::c_int as usize] as libc::c_int,
    );
    if response.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    Curl_bufref_set(
        out,
        response as *const libc::c_void,
        strlen(response),
        Some(curl_free as unsafe extern "C" fn(*mut libc::c_void) -> ()),
    );
    return CURLE_OK;
}
