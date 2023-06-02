
extern "C" {
    fn __errno_location() -> *mut i32;
    fn strrchr(_: *const i8, _: i32) -> *mut i8;
    fn strerror_r(__errnum: i32, __buf: *mut i8, __buflen: u64) -> i32;
}
pub use crate::src::lib::mprintf::curl_msnprintf;
pub type size_t = u64;
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
pub type CURLSHcode = u32;
pub const CURLSHE_LAST: CURLSHcode = 6;
pub const CURLSHE_NOT_BUILT_IN: CURLSHcode = 5;
pub const CURLSHE_NOMEM: CURLSHcode = 4;
pub const CURLSHE_INVALID: CURLSHcode = 3;
pub const CURLSHE_IN_USE: CURLSHcode = 2;
pub const CURLSHE_BAD_OPTION: CURLSHcode = 1;
pub const CURLSHE_OK: CURLSHcode = 0;
pub type CURLMcode = i32;
pub const CURLM_LAST: CURLMcode = 11;
pub const CURLM_BAD_FUNCTION_ARGUMENT: CURLMcode = 10;
pub const CURLM_WAKEUP_FAILURE: CURLMcode = 9;
pub const CURLM_RECURSIVE_API_CALL: CURLMcode = 8;
pub const CURLM_ADDED_ALREADY: CURLMcode = 7;
pub const CURLM_UNKNOWN_OPTION: CURLMcode = 6;
pub const CURLM_BAD_SOCKET: CURLMcode = 5;
pub const CURLM_INTERNAL_ERROR: CURLMcode = 4;
pub const CURLM_OUT_OF_MEMORY: CURLMcode = 3;
pub const CURLM_BAD_EASY_HANDLE: CURLMcode = 2;
pub const CURLM_BAD_HANDLE: CURLMcode = 1;
pub const CURLM_OK: CURLMcode = 0;
pub const CURLM_CALL_MULTI_PERFORM: CURLMcode = -1;
#[no_mangle]
pub extern "C" fn curl_easy_strerror(mut error: u32) -> *const i8 {
    match error as u32 {
        0 => return b"No error\0" as *const u8 as *const i8,
        1 => return b"Unsupported protocol\0" as *const u8 as *const i8,
        2 => return b"Failed initialization\0" as *const u8 as *const i8,
        3 => {
            return b"URL using bad/illegal format or missing URL\0" as *const u8 as *const i8;
        }
        4 => {
            return b"A requested feature, protocol or option was not found built-in in this libcurl due to a build-time decision.\0" as * const u8 as * const i8 ;
        }
        5 => return b"Couldn't resolve proxy name\0" as *const u8 as *const i8,
        6 => return b"Couldn't resolve host name\0" as *const u8 as *const i8,
        7 => return b"Couldn't connect to server\0" as *const u8 as *const i8,
        8 => return b"Weird server reply\0" as *const u8 as *const i8,
        9 => {
            return b"Access denied to remote resource\0" as *const u8 as *const i8;
        }
        10 => {
            return b"FTP: The server failed to connect to data port\0" as *const u8 as *const i8;
        }
        12 => {
            return b"FTP: Accepting server connect has timed out\0" as *const u8 as *const i8;
        }
        84 => {
            return b"FTP: The server did not accept the PRET command.\0" as *const u8 as *const i8;
        }
        11 => return b"FTP: unknown PASS reply\0" as *const u8 as *const i8,
        13 => return b"FTP: unknown PASV reply\0" as *const u8 as *const i8,
        14 => {
            return b"FTP: unknown 227 response format\0" as *const u8 as *const i8;
        }
        15 => {
            return b"FTP: can't figure out the host in the PASV response\0" as *const u8
                as *const i8;
        }
        16 => {
            return b"Error in the HTTP2 framing layer\0" as *const u8 as *const i8;
        }
        17 => return b"FTP: couldn't set file type\0" as *const u8 as *const i8,
        18 => return b"Transferred a partial file\0" as *const u8 as *const i8,
        19 => {
            return b"FTP: couldn't retrieve (RETR failed) the specified file\0" as *const u8
                as *const i8;
        }
        21 => {
            return b"Quote command returned error\0" as *const u8 as *const i8;
        }
        22 => {
            return b"HTTP response code said error\0" as *const u8 as *const i8;
        }
        23 => {
            return b"Failed writing received data to disk/application\0" as *const u8 as *const i8;
        }
        25 => {
            return b"Upload failed (at start/before it took off)\0" as *const u8 as *const i8;
        }
        26 => {
            return b"Failed to open/read local data from file/application\0" as *const u8
                as *const i8;
        }
        27 => return b"Out of memory\0" as *const u8 as *const i8,
        28 => return b"Timeout was reached\0" as *const u8 as *const i8,
        30 => return b"FTP: command PORT failed\0" as *const u8 as *const i8,
        31 => return b"FTP: command REST failed\0" as *const u8 as *const i8,
        33 => {
            return b"Requested range was not delivered by the server\0" as *const u8 as *const i8;
        }
        34 => {
            return b"Internal problem setting up the POST\0" as *const u8 as *const i8;
        }
        35 => return b"SSL connect error\0" as *const u8 as *const i8,
        36 => return b"Couldn't resume download\0" as *const u8 as *const i8,
        37 => {
            return b"Couldn't read a file:// file\0" as *const u8 as *const i8;
        }
        38 => return b"LDAP: cannot bind\0" as *const u8 as *const i8,
        39 => return b"LDAP: search failed\0" as *const u8 as *const i8,
        41 => {
            return b"A required function in the library was not found\0" as *const u8 as *const i8;
        }
        42 => {
            return b"Operation was aborted by an application callback\0" as *const u8 as *const i8;
        }
        43 => {
            return b"A libcurl function was given a bad argument\0" as *const u8 as *const i8;
        }
        45 => {
            return b"Failed binding local connection end\0" as *const u8 as *const i8;
        }
        47 => {
            return b"Number of redirects hit maximum amount\0" as *const u8 as *const i8;
        }
        48 => {
            return b"An unknown option was passed in to libcurl\0" as *const u8 as *const i8;
        }
        49 => {
            return b"Malformed option provided in a setopt\0" as *const u8 as *const i8;
        }
        52 => {
            return b"Server returned nothing (no headers, no data)\0" as *const u8 as *const i8;
        }
        53 => return b"SSL crypto engine not found\0" as *const u8 as *const i8,
        54 => {
            return b"Can not set SSL crypto engine as default\0" as *const u8 as *const i8;
        }
        66 => {
            return b"Failed to initialise SSL crypto engine\0" as *const u8 as *const i8;
        }
        55 => {
            return b"Failed sending data to the peer\0" as *const u8 as *const i8;
        }
        56 => {
            return b"Failure when receiving data from the peer\0" as *const u8 as *const i8;
        }
        58 => {
            return b"Problem with the local SSL certificate\0" as *const u8 as *const i8;
        }
        59 => {
            return b"Couldn't use specified SSL cipher\0" as *const u8 as *const i8;
        }
        60 => {
            return b"SSL peer certificate or SSH remote key was not OK\0" as *const u8
                as *const i8;
        }
        77 => {
            return b"Problem with the SSL CA cert (path? access rights?)\0" as *const u8
                as *const i8;
        }
        61 => {
            return b"Unrecognized or bad HTTP Content or Transfer-Encoding\0" as *const u8
                as *const i8;
        }
        62 => return b"Invalid LDAP URL\0" as *const u8 as *const i8,
        63 => return b"Maximum file size exceeded\0" as *const u8 as *const i8,
        64 => return b"Requested SSL level failed\0" as *const u8 as *const i8,
        80 => {
            return b"Failed to shut down the SSL connection\0" as *const u8 as *const i8;
        }
        82 => {
            return b"Failed to load CRL file (path? access rights?, format?)\0" as *const u8
                as *const i8;
        }
        83 => {
            return b"Issuer check against peer certificate failed\0" as *const u8 as *const i8;
        }
        65 => {
            return b"Send failed since rewinding of the data stream failed\0" as *const u8
                as *const i8;
        }
        67 => return b"Login denied\0" as *const u8 as *const i8,
        68 => return b"TFTP: File Not Found\0" as *const u8 as *const i8,
        69 => return b"TFTP: Access Violation\0" as *const u8 as *const i8,
        70 => {
            return b"Disk full or allocation exceeded\0" as *const u8 as *const i8;
        }
        71 => return b"TFTP: Illegal operation\0" as *const u8 as *const i8,
        72 => return b"TFTP: Unknown transfer ID\0" as *const u8 as *const i8,
        73 => return b"Remote file already exists\0" as *const u8 as *const i8,
        74 => return b"TFTP: No such user\0" as *const u8 as *const i8,
        75 => return b"Conversion failed\0" as *const u8 as *const i8,
        76 => {
            return b"Caller must register CURLOPT_CONV_ callback options\0" as *const u8
                as *const i8;
        }
        78 => return b"Remote file not found\0" as *const u8 as *const i8,
        79 => return b"Error in the SSH layer\0" as *const u8 as *const i8,
        81 => {
            return b"Socket not ready for send/recv\0" as *const u8 as *const i8;
        }
        85 => {
            return b"RTSP CSeq mismatch or invalid CSeq\0" as *const u8 as *const i8;
        }
        86 => return b"RTSP session error\0" as *const u8 as *const i8,
        87 => {
            return b"Unable to parse FTP file list\0" as *const u8 as *const i8;
        }
        88 => return b"Chunk callback failed\0" as *const u8 as *const i8,
        89 => {
            return b"The max connection limit is reached\0" as *const u8 as *const i8;
        }
        90 => {
            return b"SSL public key does not match pinned public key\0" as *const u8 as *const i8;
        }
        91 => {
            return b"SSL server certificate status verification FAILED\0" as *const u8
                as *const i8;
        }
        92 => {
            return b"Stream error in the HTTP/2 framing layer\0" as *const u8 as *const i8;
        }
        93 => {
            return b"API function called from within callback\0" as *const u8 as *const i8;
        }
        94 => {
            return b"An authentication function returned an error\0" as *const u8 as *const i8;
        }
        95 => return b"HTTP/3 error\0" as *const u8 as *const i8,
        96 => return b"QUIC connection error\0" as *const u8 as *const i8,
        97 => return b"proxy handshake error\0" as *const u8 as *const i8,
        98 => {
            return b"SSL Client Certificate required\0" as *const u8 as *const i8;
        }
        20 | 24 | 29 | 32 | 40 | 44 | 46 | 50 | 51 | 57 | 99 | _ => {}
    }
    return b"Unknown error\0" as *const u8 as *const i8;
}
#[no_mangle]
pub extern "C" fn curl_multi_strerror(mut error: i32) -> *const i8 {
    match error as i32 {
        -1 => {
            return b"Please call curl_multi_perform() soon\0" as *const u8 as *const i8;
        }
        0 => return b"No error\0" as *const u8 as *const i8,
        1 => return b"Invalid multi handle\0" as *const u8 as *const i8,
        2 => return b"Invalid easy handle\0" as *const u8 as *const i8,
        3 => return b"Out of memory\0" as *const u8 as *const i8,
        4 => return b"Internal error\0" as *const u8 as *const i8,
        5 => return b"Invalid socket argument\0" as *const u8 as *const i8,
        6 => return b"Unknown option\0" as *const u8 as *const i8,
        7 => {
            return b"The easy handle is already added to a multi handle\0" as *const u8
                as *const i8;
        }
        8 => {
            return b"API function called from within callback\0" as *const u8 as *const i8;
        }
        9 => {
            return b"Wakeup is unavailable or failed\0" as *const u8 as *const i8;
        }
        10 => {
            return b"A libcurl function was given a bad argument\0" as *const u8 as *const i8;
        }
        11 | _ => {}
    }
    return b"Unknown error\0" as *const u8 as *const i8;
}
#[no_mangle]
pub extern "C" fn curl_share_strerror(mut error: u32) -> *const i8 {
    match error as u32 {
        0 => return b"No error\0" as *const u8 as *const i8,
        1 => return b"Unknown share option\0" as *const u8 as *const i8,
        2 => return b"Share currently in use\0" as *const u8 as *const i8,
        3 => return b"Invalid share handle\0" as *const u8 as *const i8,
        4 => return b"Out of memory\0" as *const u8 as *const i8,
        5 => {
            return b"Feature not enabled in this library\0" as *const u8 as *const i8;
        }
        6 | _ => {}
    }
    return b"CURLSHcode unknown\0" as *const u8 as *const i8;
}
#[no_mangle]
pub extern "C" fn Curl_strerror(mut err: i32, mut buf: *mut i8, mut buflen: u64) -> *const i8 {
    let mut old_errno: i32 = unsafe { *__errno_location() };
    let mut p: *mut i8 = 0 as *mut i8;
    let mut max: u64 = 0;
    if buflen == 0 {
        return 0 as *const i8;
    }
    max = buflen.wrapping_sub(1 as i32 as u64);
    (unsafe { *buf = '\u{0}' as i32 as i8 });
    if 0 as i32 != (unsafe { strerror_r(err, buf, max) }) {
        if '\u{0}' as i32 == (unsafe { *buf.offset(0 as i32 as isize) }) as i32 {
            (unsafe { curl_msnprintf(
                buf,
                max,
                b"Unknown error %d\0" as *const u8 as *const i8,
                err,
            ) });
        }
    }
    (unsafe { *buf.offset(max as isize) = '\u{0}' as i32 as i8 });
    p = unsafe { strrchr(buf, '\n' as i32) };
    if !p.is_null() && (unsafe { p.offset_from(buf) }) as i64 >= 2 as i32 as i64 {
        (unsafe { *p = '\u{0}' as i32 as i8 });
    }
    p = unsafe { strrchr(buf, '\r' as i32) };
    if !p.is_null() && (unsafe { p.offset_from(buf) }) as i64 >= 1 as i32 as i64 {
        (unsafe { *p = '\u{0}' as i32 as i8 });
    }
    if (unsafe { *__errno_location() }) != old_errno {
        (unsafe { *__errno_location() = old_errno });
    }
    return buf;
}

