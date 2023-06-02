use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn malloc(_: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strdup(_: *const i8) -> *mut i8;
    fn strtok(_: *mut i8, _: *const i8) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn __errno_location() -> *mut i32;
    fn mkdir(__path: *const i8, __mode: __mode_t) -> i32;
    fn curl_msnprintf(buffer: *mut i8, maxlength: size_t, format: *const i8, _: ...) -> i32;
    fn curl_mfprintf(fd: *mut FILE, format: *const i8, _: ...) -> i32;
}
pub type __mode_t = u32;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type mode_t = __mode_t;
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
extern "C" fn show_dir_errno(mut errors: *mut FILE, mut name: *const i8) {
    match unsafe { *__errno_location() } {
        13 => {
            (unsafe { curl_mfprintf(
                errors,
                b"You don't have permission to create %s.\n\0" as *const u8 as *const i8,
                name,
            ) });
        }
        36 => {
            (unsafe { curl_mfprintf(
                errors,
                b"The directory name %s is too long.\n\0" as *const u8 as *const i8,
                name,
            ) });
        }
        30 => {
            (unsafe { curl_mfprintf(
                errors,
                b"%s resides on a read-only file system.\n\0" as *const u8 as *const i8,
                name,
            ) });
        }
        28 => {
            (unsafe { curl_mfprintf(
                errors,
                b"No space left on the file system that will contain the directory %s.\n\0"
                    as *const u8 as *const i8,
                name,
            ) });
        }
        122 => {
            (unsafe { curl_mfprintf(
                errors,
                b"Cannot create directory %s because you exceeded your quota.\n\0" as *const u8
                    as *const i8,
                name,
            ) });
        }
        _ => {
            (unsafe { curl_mfprintf(
                errors,
                b"Error creating directory %s.\n\0" as *const u8 as *const i8,
                name,
            ) });
        }
    };
}
#[no_mangle]
pub extern "C" fn create_dir_hierarchy(mut outfile: *const i8, mut errors: *mut FILE) -> CURLcode {
    let mut tempdir: *mut i8 = 0 as *mut i8;
    let mut tempdir2: *mut i8 = 0 as *mut i8;
    let mut outdup: *mut i8 = 0 as *mut i8;
    let mut dirbuildup: *mut i8 = 0 as *mut i8;
    let mut result: CURLcode = CURLE_OK;
    let mut outlen: size_t = 0;
    outlen = unsafe { strlen(outfile) };
    outdup = unsafe { strdup(outfile) };
    if outdup.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    dirbuildup = (unsafe { malloc(outlen.wrapping_add(1 as i32 as u64)) }) as *mut i8;
    if dirbuildup.is_null() {
        (unsafe { free(outdup as *mut libc::c_void) });
        outdup = 0 as *mut i8;
        return CURLE_OUT_OF_MEMORY;
    }
    (unsafe { *dirbuildup.offset(0 as i32 as isize) = '\u{0}' as i32 as i8 });
    tempdir = unsafe { strtok(outdup, b"/\0" as *const u8 as *const i8) };
    while !tempdir.is_null() {
        let mut skip: bool = 0 as i32 != 0;
        tempdir2 = unsafe { strtok(0 as *mut i8, b"/\0" as *const u8 as *const i8) };
        if !tempdir2.is_null() {
            let mut dlen: size_t = unsafe { strlen(dirbuildup) };
            if dlen != 0 {
                (unsafe { curl_msnprintf(
                    &mut *dirbuildup.offset(dlen as isize) as *mut i8,
                    outlen.wrapping_sub(dlen),
                    b"%s%s\0" as *const u8 as *const i8,
                    b"/\0" as *const u8 as *const i8,
                    tempdir,
                ) });
            } else if outdup == tempdir {
                (unsafe { strcpy(dirbuildup, tempdir) });
            } else {
                (unsafe { curl_msnprintf(
                    dirbuildup,
                    outlen,
                    b"%s%s\0" as *const u8 as *const i8,
                    b"/\0" as *const u8 as *const i8,
                    tempdir,
                ) });
            }
            if !skip
                && -(1 as i32) == (unsafe { mkdir(dirbuildup, 0o750 as i32 as mode_t) })
                && (unsafe { *__errno_location() }) != 13 as i32
                && (unsafe { *__errno_location() }) != 17 as i32
            {
                show_dir_errno(errors, dirbuildup);
                result = CURLE_WRITE_ERROR;
                break;
            }
        }
        tempdir = tempdir2;
    }
    (unsafe { free(dirbuildup as *mut libc::c_void) });
    dirbuildup = 0 as *mut i8;
    (unsafe { free(outdup as *mut libc::c_void) });
    outdup = 0 as *mut i8;
    return result;
}
