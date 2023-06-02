use ::libc;
extern "C" {
    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn gmtime_r(__timer: *const time_t, __tp: *mut tm) -> *mut tm;
    fn __errno_location() -> *mut libc::c_int;
    fn strtol(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_long;
    fn Curl_isdigit(c: libc::c_int) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn Curl_isalpha(c: libc::c_int) -> libc::c_int;
    fn Curl_isalnum(c: libc::c_int) -> libc::c_int;
    fn Curl_strcasecompare(
        first: *const libc::c_char,
        second: *const libc::c_char,
    ) -> libc::c_int;
    fn curlx_sltosi(slnum: libc::c_long) -> libc::c_int;
}
pub type __time_t = libc::c_long;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tm {
    pub tm_sec: libc::c_int,
    pub tm_min: libc::c_int,
    pub tm_hour: libc::c_int,
    pub tm_mday: libc::c_int,
    pub tm_mon: libc::c_int,
    pub tm_year: libc::c_int,
    pub tm_wday: libc::c_int,
    pub tm_yday: libc::c_int,
    pub tm_isdst: libc::c_int,
    pub tm_gmtoff: libc::c_long,
    pub tm_zone: *const libc::c_char,
}
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
pub type assume = libc::c_uint;
pub const DATE_TIME: assume = 2;
pub const DATE_YEAR: assume = 1;
pub const DATE_MDAY: assume = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tzinfo {
    pub name: [libc::c_char; 5],
    pub offset: libc::c_int,
}
#[no_mangle]
pub static mut Curl_wkday: [*const libc::c_char; 7] = [
    b"Mon\0" as *const u8 as *const libc::c_char,
    b"Tue\0" as *const u8 as *const libc::c_char,
    b"Wed\0" as *const u8 as *const libc::c_char,
    b"Thu\0" as *const u8 as *const libc::c_char,
    b"Fri\0" as *const u8 as *const libc::c_char,
    b"Sat\0" as *const u8 as *const libc::c_char,
    b"Sun\0" as *const u8 as *const libc::c_char,
];
#[no_mangle]
pub static mut Curl_month: [*const libc::c_char; 12] = [
    b"Jan\0" as *const u8 as *const libc::c_char,
    b"Feb\0" as *const u8 as *const libc::c_char,
    b"Mar\0" as *const u8 as *const libc::c_char,
    b"Apr\0" as *const u8 as *const libc::c_char,
    b"May\0" as *const u8 as *const libc::c_char,
    b"Jun\0" as *const u8 as *const libc::c_char,
    b"Jul\0" as *const u8 as *const libc::c_char,
    b"Aug\0" as *const u8 as *const libc::c_char,
    b"Sep\0" as *const u8 as *const libc::c_char,
    b"Oct\0" as *const u8 as *const libc::c_char,
    b"Nov\0" as *const u8 as *const libc::c_char,
    b"Dec\0" as *const u8 as *const libc::c_char,
];
static mut weekday: [*const libc::c_char; 7] = [
    b"Monday\0" as *const u8 as *const libc::c_char,
    b"Tuesday\0" as *const u8 as *const libc::c_char,
    b"Wednesday\0" as *const u8 as *const libc::c_char,
    b"Thursday\0" as *const u8 as *const libc::c_char,
    b"Friday\0" as *const u8 as *const libc::c_char,
    b"Saturday\0" as *const u8 as *const libc::c_char,
    b"Sunday\0" as *const u8 as *const libc::c_char,
];
static mut tz: [tzinfo; 69] = unsafe {
    [
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"GMT\0\0"),
                offset: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"UT\0\0\0"),
                offset: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"UTC\0\0"),
                offset: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"WET\0\0"),
                offset: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"BST\0\0"),
                offset: 0 as libc::c_int - 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"WAT\0\0"),
                offset: 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"AST\0\0"),
                offset: 240 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"ADT\0\0"),
                offset: 240 as libc::c_int - 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"EST\0\0"),
                offset: 300 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"EDT\0\0"),
                offset: 300 as libc::c_int - 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"CST\0\0"),
                offset: 360 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"CDT\0\0"),
                offset: 360 as libc::c_int - 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"MST\0\0"),
                offset: 420 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"MDT\0\0"),
                offset: 420 as libc::c_int - 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"PST\0\0"),
                offset: 480 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"PDT\0\0"),
                offset: 480 as libc::c_int - 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"YST\0\0"),
                offset: 540 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"YDT\0\0"),
                offset: 540 as libc::c_int - 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"HST\0\0"),
                offset: 600 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"HDT\0\0"),
                offset: 600 as libc::c_int - 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"CAT\0\0"),
                offset: 600 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"AHST\0"),
                offset: 600 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"NT\0\0\0"),
                offset: 660 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"IDLW\0"),
                offset: 720 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"CET\0\0"),
                offset: -(60 as libc::c_int),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"MET\0\0"),
                offset: -(60 as libc::c_int),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"MEWT\0"),
                offset: -(60 as libc::c_int),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"MEST\0"),
                offset: -(60 as libc::c_int) - 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"CEST\0"),
                offset: -(60 as libc::c_int) - 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"MESZ\0"),
                offset: -(60 as libc::c_int) - 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"FWT\0\0"),
                offset: -(60 as libc::c_int),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"FST\0\0"),
                offset: -(60 as libc::c_int) - 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"EET\0\0"),
                offset: -(120 as libc::c_int),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"WAST\0"),
                offset: -(420 as libc::c_int),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"WADT\0"),
                offset: -(420 as libc::c_int) - 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"CCT\0\0"),
                offset: -(480 as libc::c_int),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"JST\0\0"),
                offset: -(540 as libc::c_int),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"EAST\0"),
                offset: -(600 as libc::c_int),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"EADT\0"),
                offset: -(600 as libc::c_int) - 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"GST\0\0"),
                offset: -(600 as libc::c_int),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"NZT\0\0"),
                offset: -(720 as libc::c_int),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"NZST\0"),
                offset: -(720 as libc::c_int),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"NZDT\0"),
                offset: -(720 as libc::c_int) - 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"IDLE\0"),
                offset: -(720 as libc::c_int),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"A\0\0\0\0"),
                offset: 1 as libc::c_int * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"B\0\0\0\0"),
                offset: 2 as libc::c_int * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"C\0\0\0\0"),
                offset: 3 as libc::c_int * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"D\0\0\0\0"),
                offset: 4 as libc::c_int * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"E\0\0\0\0"),
                offset: 5 as libc::c_int * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"F\0\0\0\0"),
                offset: 6 as libc::c_int * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"G\0\0\0\0"),
                offset: 7 as libc::c_int * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"H\0\0\0\0"),
                offset: 8 as libc::c_int * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"I\0\0\0\0"),
                offset: 9 as libc::c_int * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"K\0\0\0\0"),
                offset: 10 as libc::c_int * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"L\0\0\0\0"),
                offset: 11 as libc::c_int * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"M\0\0\0\0"),
                offset: 12 as libc::c_int * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"N\0\0\0\0"),
                offset: -(1 as libc::c_int) * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"O\0\0\0\0"),
                offset: -(2 as libc::c_int) * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"P\0\0\0\0"),
                offset: -(3 as libc::c_int) * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"Q\0\0\0\0"),
                offset: -(4 as libc::c_int) * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"R\0\0\0\0"),
                offset: -(5 as libc::c_int) * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"S\0\0\0\0"),
                offset: -(6 as libc::c_int) * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"T\0\0\0\0"),
                offset: -(7 as libc::c_int) * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"U\0\0\0\0"),
                offset: -(8 as libc::c_int) * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"V\0\0\0\0"),
                offset: -(9 as libc::c_int) * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"W\0\0\0\0"),
                offset: -(10 as libc::c_int) * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"X\0\0\0\0"),
                offset: -(11 as libc::c_int) * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"Y\0\0\0\0"),
                offset: -(12 as libc::c_int) * 60 as libc::c_int,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [libc::c_char; 5],
                >(b"Z\0\0\0\0"),
                offset: 0 as libc::c_int,
            };
            init
        },
    ]
};
unsafe extern "C" fn checkday(
    mut check: *const libc::c_char,
    mut len: size_t,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut what: *const *const libc::c_char = 0 as *const *const libc::c_char;
    let mut found: bool = 0 as libc::c_int != 0;
    if len > 3 as libc::c_int as libc::c_ulong {
        what = &*weekday.as_ptr().offset(0 as libc::c_int as isize)
            as *const *const libc::c_char;
    } else {
        what = &*Curl_wkday.as_ptr().offset(0 as libc::c_int as isize)
            as *const *const libc::c_char;
    }
    i = 0 as libc::c_int;
    while i < 7 as libc::c_int {
        if Curl_strcasecompare(check, *what.offset(0 as libc::c_int as isize)) != 0 {
            found = 1 as libc::c_int != 0;
            break;
        } else {
            what = what.offset(1);
            i += 1;
        }
    }
    return if found as libc::c_int != 0 { i } else { -(1 as libc::c_int) };
}
unsafe extern "C" fn checkmonth(mut check: *const libc::c_char) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut what: *const *const libc::c_char = 0 as *const *const libc::c_char;
    let mut found: bool = 0 as libc::c_int != 0;
    what = &*Curl_month.as_ptr().offset(0 as libc::c_int as isize)
        as *const *const libc::c_char;
    i = 0 as libc::c_int;
    while i < 12 as libc::c_int {
        if Curl_strcasecompare(check, *what.offset(0 as libc::c_int as isize)) != 0 {
            found = 1 as libc::c_int != 0;
            break;
        } else {
            what = what.offset(1);
            i += 1;
        }
    }
    return if found as libc::c_int != 0 { i } else { -(1 as libc::c_int) };
}
unsafe extern "C" fn checktz(mut check: *const libc::c_char) -> libc::c_int {
    let mut i: libc::c_uint = 0;
    let mut what: *const tzinfo = 0 as *const tzinfo;
    let mut found: bool = 0 as libc::c_int != 0;
    what = tz.as_ptr();
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong)
        < (::std::mem::size_of::<[tzinfo; 69]>() as libc::c_ulong)
            .wrapping_div(::std::mem::size_of::<tzinfo>() as libc::c_ulong)
    {
        if Curl_strcasecompare(check, ((*what).name).as_ptr()) != 0 {
            found = 1 as libc::c_int != 0;
            break;
        } else {
            what = what.offset(1);
            i = i.wrapping_add(1);
        }
    }
    return if found as libc::c_int != 0 {
        (*what).offset * 60 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
unsafe extern "C" fn skip(mut date: *mut *const libc::c_char) {
    while **date as libc::c_int != 0
        && Curl_isalnum(**date as libc::c_uchar as libc::c_int) == 0
    {
        *date = (*date).offset(1);
    }
}
unsafe extern "C" fn time2epoch(
    mut sec: libc::c_int,
    mut min: libc::c_int,
    mut hour: libc::c_int,
    mut mday: libc::c_int,
    mut mon: libc::c_int,
    mut year: libc::c_int,
) -> time_t {
    static mut month_days_cumulative: [libc::c_int; 12] = [
        0 as libc::c_int,
        31 as libc::c_int,
        59 as libc::c_int,
        90 as libc::c_int,
        120 as libc::c_int,
        151 as libc::c_int,
        181 as libc::c_int,
        212 as libc::c_int,
        243 as libc::c_int,
        273 as libc::c_int,
        304 as libc::c_int,
        334 as libc::c_int,
    ];
    let mut leap_days: libc::c_int = year - (mon <= 1 as libc::c_int) as libc::c_int;
    leap_days = leap_days / 4 as libc::c_int - leap_days / 100 as libc::c_int
        + leap_days / 400 as libc::c_int - 1969 as libc::c_int / 4 as libc::c_int
        + 1969 as libc::c_int / 100 as libc::c_int
        - 1969 as libc::c_int / 400 as libc::c_int;
    return ((((year - 1970 as libc::c_int) as time_t * 365 as libc::c_int as libc::c_long
        + leap_days as libc::c_long + month_days_cumulative[mon as usize] as libc::c_long
        + mday as libc::c_long - 1 as libc::c_int as libc::c_long)
        * 24 as libc::c_int as libc::c_long + hour as libc::c_long)
        * 60 as libc::c_int as libc::c_long + min as libc::c_long)
        * 60 as libc::c_int as libc::c_long + sec as libc::c_long;
}
unsafe extern "C" fn parsedate(
    mut date: *const libc::c_char,
    mut output: *mut time_t,
) -> libc::c_int {
    let mut t: time_t = 0 as libc::c_int as time_t;
    let mut wdaynum: libc::c_int = -(1 as libc::c_int);
    let mut monnum: libc::c_int = -(1 as libc::c_int);
    let mut mdaynum: libc::c_int = -(1 as libc::c_int);
    let mut hournum: libc::c_int = -(1 as libc::c_int);
    let mut minnum: libc::c_int = -(1 as libc::c_int);
    let mut secnum: libc::c_int = -(1 as libc::c_int);
    let mut yearnum: libc::c_int = -(1 as libc::c_int);
    let mut tzoff: libc::c_int = -(1 as libc::c_int);
    let mut dignext: assume = DATE_MDAY;
    let mut indate: *const libc::c_char = date;
    let mut part: libc::c_int = 0 as libc::c_int;
    while *date as libc::c_int != 0 && part < 6 as libc::c_int {
        let mut found: bool = 0 as libc::c_int != 0;
        skip(&mut date);
        if Curl_isalpha(*date as libc::c_uchar as libc::c_int) != 0 {
            let mut buf: [libc::c_char; 32] = *::std::mem::transmute::<
                &[u8; 32],
                &mut [libc::c_char; 32],
            >(b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
            let mut len: size_t = 0;
            if sscanf(
                date,
                b"%31[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz]\0"
                    as *const u8 as *const libc::c_char,
                buf.as_mut_ptr(),
            ) != 0
            {
                len = strlen(buf.as_mut_ptr());
            } else {
                len = 0 as libc::c_int as size_t;
            }
            if wdaynum == -(1 as libc::c_int) {
                wdaynum = checkday(buf.as_mut_ptr(), len);
                if wdaynum != -(1 as libc::c_int) {
                    found = 1 as libc::c_int != 0;
                }
            }
            if !found && monnum == -(1 as libc::c_int) {
                monnum = checkmonth(buf.as_mut_ptr());
                if monnum != -(1 as libc::c_int) {
                    found = 1 as libc::c_int != 0;
                }
            }
            if !found && tzoff == -(1 as libc::c_int) {
                tzoff = checktz(buf.as_mut_ptr());
                if tzoff != -(1 as libc::c_int) {
                    found = 1 as libc::c_int != 0;
                }
            }
            if !found {
                return -(1 as libc::c_int);
            }
            date = date.offset(len as isize);
        } else if Curl_isdigit(*date as libc::c_uchar as libc::c_int) != 0 {
            let mut val: libc::c_int = 0;
            let mut end: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut len_0: libc::c_int = 0 as libc::c_int;
            if secnum == -(1 as libc::c_int)
                && 3 as libc::c_int
                    == sscanf(
                        date,
                        b"%02d:%02d:%02d%n\0" as *const u8 as *const libc::c_char,
                        &mut hournum as *mut libc::c_int,
                        &mut minnum as *mut libc::c_int,
                        &mut secnum as *mut libc::c_int,
                        &mut len_0 as *mut libc::c_int,
                    )
            {
                date = date.offset(len_0 as isize);
            } else if secnum == -(1 as libc::c_int)
                    && 2 as libc::c_int
                        == sscanf(
                            date,
                            b"%02d:%02d%n\0" as *const u8 as *const libc::c_char,
                            &mut hournum as *mut libc::c_int,
                            &mut minnum as *mut libc::c_int,
                            &mut len_0 as *mut libc::c_int,
                        )
                {
                date = date.offset(len_0 as isize);
                secnum = 0 as libc::c_int;
            } else {
                let mut lval: libc::c_long = 0;
                let mut error: libc::c_int = 0;
                let mut old_errno: libc::c_int = 0;
                old_errno = *__errno_location();
                *__errno_location() = 0 as libc::c_int;
                lval = strtol(date, &mut end, 10 as libc::c_int);
                error = *__errno_location();
                if *__errno_location() != old_errno {
                    *__errno_location() = old_errno;
                }
                if error != 0 {
                    return -(1 as libc::c_int);
                }
                if lval > 2147483647 as libc::c_int as libc::c_long
                    || lval
                        < (-(2147483647 as libc::c_int) - 1 as libc::c_int)
                            as libc::c_long
                {
                    return -(1 as libc::c_int);
                }
                val = curlx_sltosi(lval);
                if tzoff == -(1 as libc::c_int)
                    && end.offset_from(date) as libc::c_long
                        == 4 as libc::c_int as libc::c_long && val <= 1400 as libc::c_int
                    && indate < date
                    && (*date.offset(-(1 as libc::c_int) as isize) as libc::c_int
                        == '+' as i32
                        || *date.offset(-(1 as libc::c_int) as isize) as libc::c_int
                            == '-' as i32)
                {
                    found = 1 as libc::c_int != 0;
                    tzoff = (val / 100 as libc::c_int * 60 as libc::c_int
                        + val % 100 as libc::c_int) * 60 as libc::c_int;
                    tzoff = if *date.offset(-(1 as libc::c_int) as isize) as libc::c_int
                        == '+' as i32
                    {
                        -tzoff
                    } else {
                        tzoff
                    };
                }
                if end.offset_from(date) as libc::c_long
                    == 8 as libc::c_int as libc::c_long && yearnum == -(1 as libc::c_int)
                    && monnum == -(1 as libc::c_int) && mdaynum == -(1 as libc::c_int)
                {
                    found = 1 as libc::c_int != 0;
                    yearnum = val / 10000 as libc::c_int;
                    monnum = val % 10000 as libc::c_int / 100 as libc::c_int
                        - 1 as libc::c_int;
                    mdaynum = val % 100 as libc::c_int;
                }
                if !found
                    && dignext as libc::c_uint
                        == DATE_MDAY as libc::c_int as libc::c_uint
                    && mdaynum == -(1 as libc::c_int)
                {
                    if val > 0 as libc::c_int && val < 32 as libc::c_int {
                        mdaynum = val;
                        found = 1 as libc::c_int != 0;
                    }
                    dignext = DATE_YEAR;
                }
                if !found
                    && dignext as libc::c_uint
                        == DATE_YEAR as libc::c_int as libc::c_uint
                    && yearnum == -(1 as libc::c_int)
                {
                    yearnum = val;
                    found = 1 as libc::c_int != 0;
                    if yearnum < 100 as libc::c_int {
                        if yearnum > 70 as libc::c_int {
                            yearnum += 1900 as libc::c_int;
                        } else {
                            yearnum += 2000 as libc::c_int;
                        }
                    }
                    if mdaynum == -(1 as libc::c_int) {
                        dignext = DATE_MDAY;
                    }
                }
                if !found {
                    return -(1 as libc::c_int);
                }
                date = end;
            }
        }
        part += 1;
    }
    if -(1 as libc::c_int) == secnum {
        hournum = 0 as libc::c_int;
        minnum = hournum;
        secnum = minnum;
    }
    if -(1 as libc::c_int) == mdaynum || -(1 as libc::c_int) == monnum
        || -(1 as libc::c_int) == yearnum
    {
        return -(1 as libc::c_int);
    }
    if yearnum < 1583 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if mdaynum > 31 as libc::c_int || monnum > 11 as libc::c_int
        || hournum > 23 as libc::c_int || minnum > 59 as libc::c_int
        || secnum > 60 as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    t = time2epoch(secnum, minnum, hournum, mdaynum, monnum, yearnum);
    if tzoff == -(1 as libc::c_int) {
        tzoff = 0 as libc::c_int;
    }
    if tzoff > 0 as libc::c_int
        && t > 0x7fffffffffffffff as libc::c_long - tzoff as libc::c_long
    {
        *output = 0x7fffffffffffffff as libc::c_long;
        return 1 as libc::c_int;
    }
    t += tzoff as libc::c_long;
    *output = t;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn curl_getdate(
    mut p: *const libc::c_char,
    mut now: *const time_t,
) -> time_t {
    let mut parsed: time_t = -(1 as libc::c_int) as time_t;
    let mut rc: libc::c_int = parsedate(p, &mut parsed);
    if rc == 0 as libc::c_int {
        if parsed == -(1 as libc::c_int) as libc::c_long {
            parsed += 1;
        }
        return parsed;
    }
    return -(1 as libc::c_int) as time_t;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_getdate_capped(mut p: *const libc::c_char) -> time_t {
    let mut parsed: time_t = -(1 as libc::c_int) as time_t;
    let mut rc: libc::c_int = parsedate(p, &mut parsed);
    match rc {
        0 => {
            if parsed == -(1 as libc::c_int) as libc::c_long {
                parsed += 1;
            }
            return parsed;
        }
        1 => return parsed,
        _ => return -(1 as libc::c_int) as time_t,
    };
}
#[no_mangle]
pub unsafe extern "C" fn Curl_gmtime(
    mut intime: time_t,
    mut store: *mut tm,
) -> CURLcode {
    let mut tm: *const tm = 0 as *const tm;
    tm = gmtime_r(&mut intime, store);
    if tm.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    return CURLE_OK;
}
