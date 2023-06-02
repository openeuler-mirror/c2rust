use ::libc;
extern "C" {
    fn sscanf(_: *const i8, _: *const i8, _: ...) -> i32;
    fn gmtime_r(__timer: *const time_t, __tp: *mut tm) -> *mut tm;
    fn __errno_location() -> *mut i32;
    fn strtol(
        _: *const i8,
        _: *mut *mut i8,
        _: i32,
    ) -> i64;
    
    fn strlen(_: *const i8) -> u64;
    
    
    
    
}
pub use crate::src::lib::curl_ctype::Curl_isalnum;
pub use crate::src::lib::curl_ctype::Curl_isalpha;
pub use crate::src::lib::curl_ctype::Curl_isdigit;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::warnless::curlx_sltosi;
pub type __time_t = crate::src::lib::http2::__time_t;
pub type time_t = crate::src::lib::http2::time_t;
pub type size_t = crate::src::lib::http2::size_t;
// #[derive(Copy, Clone)]

pub type tm = crate::src::lib::altsvc::tm;
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
pub type assume = u32;
pub const DATE_TIME: assume = 2;
pub const DATE_YEAR: assume = 1;
pub const DATE_MDAY: assume = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tzinfo {
    pub name: [i8; 5],
    pub offset: i32,
}
#[no_mangle]
pub static mut Curl_wkday: [*const i8; 7] = [
    b"Mon\0" as *const u8 as *const i8,
    b"Tue\0" as *const u8 as *const i8,
    b"Wed\0" as *const u8 as *const i8,
    b"Thu\0" as *const u8 as *const i8,
    b"Fri\0" as *const u8 as *const i8,
    b"Sat\0" as *const u8 as *const i8,
    b"Sun\0" as *const u8 as *const i8,
];
#[no_mangle]
pub static mut Curl_month: [*const i8; 12] = [
    b"Jan\0" as *const u8 as *const i8,
    b"Feb\0" as *const u8 as *const i8,
    b"Mar\0" as *const u8 as *const i8,
    b"Apr\0" as *const u8 as *const i8,
    b"May\0" as *const u8 as *const i8,
    b"Jun\0" as *const u8 as *const i8,
    b"Jul\0" as *const u8 as *const i8,
    b"Aug\0" as *const u8 as *const i8,
    b"Sep\0" as *const u8 as *const i8,
    b"Oct\0" as *const u8 as *const i8,
    b"Nov\0" as *const u8 as *const i8,
    b"Dec\0" as *const u8 as *const i8,
];
static mut weekday: [*const i8; 7] = [
    b"Monday\0" as *const u8 as *const i8,
    b"Tuesday\0" as *const u8 as *const i8,
    b"Wednesday\0" as *const u8 as *const i8,
    b"Thursday\0" as *const u8 as *const i8,
    b"Friday\0" as *const u8 as *const i8,
    b"Saturday\0" as *const u8 as *const i8,
    b"Sunday\0" as *const u8 as *const i8,
];
static mut tz: [tzinfo; 69] = unsafe {
    [
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"GMT\0\0"),
                offset: 0 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"UT\0\0\0"),
                offset: 0 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"UTC\0\0"),
                offset: 0 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"WET\0\0"),
                offset: 0 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"BST\0\0"),
                offset: 0 as i32 - 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"WAT\0\0"),
                offset: 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"AST\0\0"),
                offset: 240 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"ADT\0\0"),
                offset: 240 as i32 - 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"EST\0\0"),
                offset: 300 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"EDT\0\0"),
                offset: 300 as i32 - 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"CST\0\0"),
                offset: 360 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"CDT\0\0"),
                offset: 360 as i32 - 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"MST\0\0"),
                offset: 420 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"MDT\0\0"),
                offset: 420 as i32 - 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"PST\0\0"),
                offset: 480 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"PDT\0\0"),
                offset: 480 as i32 - 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"YST\0\0"),
                offset: 540 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"YDT\0\0"),
                offset: 540 as i32 - 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"HST\0\0"),
                offset: 600 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"HDT\0\0"),
                offset: 600 as i32 - 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"CAT\0\0"),
                offset: 600 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"AHST\0"),
                offset: 600 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"NT\0\0\0"),
                offset: 660 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"IDLW\0"),
                offset: 720 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"CET\0\0"),
                offset: -(60 as i32),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"MET\0\0"),
                offset: -(60 as i32),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"MEWT\0"),
                offset: -(60 as i32),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"MEST\0"),
                offset: -(60 as i32) - 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"CEST\0"),
                offset: -(60 as i32) - 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"MESZ\0"),
                offset: -(60 as i32) - 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"FWT\0\0"),
                offset: -(60 as i32),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"FST\0\0"),
                offset: -(60 as i32) - 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"EET\0\0"),
                offset: -(120 as i32),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"WAST\0"),
                offset: -(420 as i32),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"WADT\0"),
                offset: -(420 as i32) - 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"CCT\0\0"),
                offset: -(480 as i32),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"JST\0\0"),
                offset: -(540 as i32),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"EAST\0"),
                offset: -(600 as i32),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"EADT\0"),
                offset: -(600 as i32) - 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"GST\0\0"),
                offset: -(600 as i32),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"NZT\0\0"),
                offset: -(720 as i32),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"NZST\0"),
                offset: -(720 as i32),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"NZDT\0"),
                offset: -(720 as i32) - 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"IDLE\0"),
                offset: -(720 as i32),
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"A\0\0\0\0"),
                offset: 1 as i32 * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"B\0\0\0\0"),
                offset: 2 as i32 * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"C\0\0\0\0"),
                offset: 3 as i32 * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"D\0\0\0\0"),
                offset: 4 as i32 * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"E\0\0\0\0"),
                offset: 5 as i32 * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"F\0\0\0\0"),
                offset: 6 as i32 * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"G\0\0\0\0"),
                offset: 7 as i32 * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"H\0\0\0\0"),
                offset: 8 as i32 * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"I\0\0\0\0"),
                offset: 9 as i32 * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"K\0\0\0\0"),
                offset: 10 as i32 * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"L\0\0\0\0"),
                offset: 11 as i32 * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"M\0\0\0\0"),
                offset: 12 as i32 * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"N\0\0\0\0"),
                offset: -(1 as i32) * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"O\0\0\0\0"),
                offset: -(2 as i32) * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"P\0\0\0\0"),
                offset: -(3 as i32) * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"Q\0\0\0\0"),
                offset: -(4 as i32) * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"R\0\0\0\0"),
                offset: -(5 as i32) * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"S\0\0\0\0"),
                offset: -(6 as i32) * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"T\0\0\0\0"),
                offset: -(7 as i32) * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"U\0\0\0\0"),
                offset: -(8 as i32) * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"V\0\0\0\0"),
                offset: -(9 as i32) * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"W\0\0\0\0"),
                offset: -(10 as i32) * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"X\0\0\0\0"),
                offset: -(11 as i32) * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"Y\0\0\0\0"),
                offset: -(12 as i32) * 60 as i32,
            };
            init
        },
        {
            let mut init = tzinfo {
                name: *::std::mem::transmute::<
                    &[u8; 5],
                    &mut [i8; 5],
                >(b"Z\0\0\0\0"),
                offset: 0 as i32,
            };
            init
        },
    ]
};
unsafe extern "C" fn checkday(
    mut check: *const i8,
    mut len: size_t,
) -> i32 {
    let mut i: i32 = 0;
    let mut what: *const *const i8 = 0 as *const *const i8;
    let mut found: bool = 0 as i32 != 0;
    if len > 3 as i32 as u64 {
        what = &*weekday.as_ptr().offset(0 as i32 as isize)
            as *const *const i8;
    } else {
        what = &*Curl_wkday.as_ptr().offset(0 as i32 as isize)
            as *const *const i8;
    }
    i = 0 as i32;
    while i < 7 as i32 {
        if Curl_strcasecompare(check, *what.offset(0 as i32 as isize)) != 0 {
            found = 1 as i32 != 0;
            break;
        } else {
            what = what.offset(1);
            i += 1;
        }
    }
    return if found as i32 != 0 { i } else { -(1 as i32) };
}
unsafe extern "C" fn checkmonth(mut check: *const i8) -> i32 {
    let mut i: i32 = 0;
    let mut what: *const *const i8 = 0 as *const *const i8;
    let mut found: bool = 0 as i32 != 0;
    what = &*Curl_month.as_ptr().offset(0 as i32 as isize)
        as *const *const i8;
    i = 0 as i32;
    while i < 12 as i32 {
        if Curl_strcasecompare(check, *what.offset(0 as i32 as isize)) != 0 {
            found = 1 as i32 != 0;
            break;
        } else {
            what = what.offset(1);
            i += 1;
        }
    }
    return if found as i32 != 0 { i } else { -(1 as i32) };
}
unsafe extern "C" fn checktz(mut check: *const i8) -> i32 {
    let mut i: u32 = 0;
    let mut what: *const tzinfo = 0 as *const tzinfo;
    let mut found: bool = 0 as i32 != 0;
    what = tz.as_ptr();
    i = 0 as i32 as u32;
    while (i as u64)
        < (::std::mem::size_of::<[tzinfo; 69]>() as u64)
            .wrapping_div(::std::mem::size_of::<tzinfo>() as u64)
    {
        if Curl_strcasecompare(check, ((*what).name).as_ptr()) != 0 {
            found = 1 as i32 != 0;
            break;
        } else {
            what = what.offset(1);
            i = i.wrapping_add(1);
        }
    }
    return if found as i32 != 0 {
        (*what).offset * 60 as i32
    } else {
        -(1 as i32)
    };
}
unsafe extern "C" fn skip(mut date: *mut *const i8) {
    while **date as i32 != 0
        && Curl_isalnum(**date as u8 as i32) == 0
    {
        *date = (*date).offset(1);
    }
}
unsafe extern "C" fn time2epoch(
    mut sec: i32,
    mut min: i32,
    mut hour: i32,
    mut mday: i32,
    mut mon: i32,
    mut year: i32,
) -> time_t {
    static mut month_days_cumulative: [i32; 12] = [
        0 as i32,
        31 as i32,
        59 as i32,
        90 as i32,
        120 as i32,
        151 as i32,
        181 as i32,
        212 as i32,
        243 as i32,
        273 as i32,
        304 as i32,
        334 as i32,
    ];
    let mut leap_days: i32 = year - (mon <= 1 as i32) as i32;
    leap_days = leap_days / 4 as i32 - leap_days / 100 as i32
        + leap_days / 400 as i32 - 1969 as i32 / 4 as i32
        + 1969 as i32 / 100 as i32
        - 1969 as i32 / 400 as i32;
    return ((((year - 1970 as i32) as time_t * 365 as i32 as i64
        + leap_days as i64 + month_days_cumulative[mon as usize] as i64
        + mday as i64 - 1 as i32 as i64)
        * 24 as i32 as i64 + hour as i64)
        * 60 as i32 as i64 + min as i64)
        * 60 as i32 as i64 + sec as i64;
}
unsafe extern "C" fn parsedate(
    mut date: *const i8,
    mut output: *mut time_t,
) -> i32 {
    let mut t: time_t = 0 as i32 as time_t;
    let mut wdaynum: i32 = -(1 as i32);
    let mut monnum: i32 = -(1 as i32);
    let mut mdaynum: i32 = -(1 as i32);
    let mut hournum: i32 = -(1 as i32);
    let mut minnum: i32 = -(1 as i32);
    let mut secnum: i32 = -(1 as i32);
    let mut yearnum: i32 = -(1 as i32);
    let mut tzoff: i32 = -(1 as i32);
    let mut dignext: assume = DATE_MDAY;
    let mut indate: *const i8 = date;
    let mut part: i32 = 0 as i32;
    while *date as i32 != 0 && part < 6 as i32 {
        let mut found: bool = 0 as i32 != 0;
        skip(&mut date);
        if Curl_isalpha(*date as u8 as i32) != 0 {
            let mut buf: [i8; 32] = *::std::mem::transmute::<
                &[u8; 32],
                &mut [i8; 32],
            >(b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
            let mut len: size_t = 0;
            if sscanf(
                date,
                b"%31[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz]\0"
                    as *const u8 as *const i8,
                buf.as_mut_ptr(),
            ) != 0
            {
                len = strlen(buf.as_mut_ptr());
            } else {
                len = 0 as i32 as size_t;
            }
            if wdaynum == -(1 as i32) {
                wdaynum = checkday(buf.as_mut_ptr(), len);
                if wdaynum != -(1 as i32) {
                    found = 1 as i32 != 0;
                }
            }
            if !found && monnum == -(1 as i32) {
                monnum = checkmonth(buf.as_mut_ptr());
                if monnum != -(1 as i32) {
                    found = 1 as i32 != 0;
                }
            }
            if !found && tzoff == -(1 as i32) {
                tzoff = checktz(buf.as_mut_ptr());
                if tzoff != -(1 as i32) {
                    found = 1 as i32 != 0;
                }
            }
            if !found {
                return -(1 as i32);
            }
            date = date.offset(len as isize);
        } else if Curl_isdigit(*date as u8 as i32) != 0 {
            let mut val: i32 = 0;
            let mut end: *mut i8 = 0 as *mut i8;
            let mut len_0: i32 = 0 as i32;
            if secnum == -(1 as i32)
                && 3 as i32
                    == sscanf(
                        date,
                        b"%02d:%02d:%02d%n\0" as *const u8 as *const i8,
                        &mut hournum as *mut i32,
                        &mut minnum as *mut i32,
                        &mut secnum as *mut i32,
                        &mut len_0 as *mut i32,
                    )
            {
                date = date.offset(len_0 as isize);
            } else if secnum == -(1 as i32)
                    && 2 as i32
                        == sscanf(
                            date,
                            b"%02d:%02d%n\0" as *const u8 as *const i8,
                            &mut hournum as *mut i32,
                            &mut minnum as *mut i32,
                            &mut len_0 as *mut i32,
                        )
                {
                date = date.offset(len_0 as isize);
                secnum = 0 as i32;
            } else {
                let mut lval: i64 = 0;
                let mut error: i32 = 0;
                let mut old_errno: i32 = 0;
                old_errno = *__errno_location();
                *__errno_location() = 0 as i32;
                lval = strtol(date, &mut end, 10 as i32);
                error = *__errno_location();
                if *__errno_location() != old_errno {
                    *__errno_location() = old_errno;
                }
                if error != 0 {
                    return -(1 as i32);
                }
                if lval > 2147483647 as i32 as i64
                    || lval
                        < (-(2147483647 as i32) - 1 as i32)
                            as i64
                {
                    return -(1 as i32);
                }
                val = curlx_sltosi(lval);
                if tzoff == -(1 as i32)
                    && end.offset_from(date) as i64
                        == 4 as i32 as i64 && val <= 1400 as i32
                    && indate < date
                    && (*date.offset(-(1 as i32) as isize) as i32
                        == '+' as i32
                        || *date.offset(-(1 as i32) as isize) as i32
                            == '-' as i32)
                {
                    found = 1 as i32 != 0;
                    tzoff = (val / 100 as i32 * 60 as i32
                        + val % 100 as i32) * 60 as i32;
                    tzoff = if *date.offset(-(1 as i32) as isize) as i32
                        == '+' as i32
                    {
                        -tzoff
                    } else {
                        tzoff
                    };
                }
                if end.offset_from(date) as i64
                    == 8 as i32 as i64 && yearnum == -(1 as i32)
                    && monnum == -(1 as i32) && mdaynum == -(1 as i32)
                {
                    found = 1 as i32 != 0;
                    yearnum = val / 10000 as i32;
                    monnum = val % 10000 as i32 / 100 as i32
                        - 1 as i32;
                    mdaynum = val % 100 as i32;
                }
                if !found
                    && dignext as u32
                        == DATE_MDAY as i32 as u32
                    && mdaynum == -(1 as i32)
                {
                    if val > 0 as i32 && val < 32 as i32 {
                        mdaynum = val;
                        found = 1 as i32 != 0;
                    }
                    dignext = DATE_YEAR;
                }
                if !found
                    && dignext as u32
                        == DATE_YEAR as i32 as u32
                    && yearnum == -(1 as i32)
                {
                    yearnum = val;
                    found = 1 as i32 != 0;
                    if yearnum < 100 as i32 {
                        if yearnum > 70 as i32 {
                            yearnum += 1900 as i32;
                        } else {
                            yearnum += 2000 as i32;
                        }
                    }
                    if mdaynum == -(1 as i32) {
                        dignext = DATE_MDAY;
                    }
                }
                if !found {
                    return -(1 as i32);
                }
                date = end;
            }
        }
        part += 1;
    }
    if -(1 as i32) == secnum {
        hournum = 0 as i32;
        minnum = hournum;
        secnum = minnum;
    }
    if -(1 as i32) == mdaynum || -(1 as i32) == monnum
        || -(1 as i32) == yearnum
    {
        return -(1 as i32);
    }
    if yearnum < 1583 as i32 {
        return -(1 as i32);
    }
    if mdaynum > 31 as i32 || monnum > 11 as i32
        || hournum > 23 as i32 || minnum > 59 as i32
        || secnum > 60 as i32
    {
        return -(1 as i32);
    }
    t = time2epoch(secnum, minnum, hournum, mdaynum, monnum, yearnum);
    if tzoff == -(1 as i32) {
        tzoff = 0 as i32;
    }
    if tzoff > 0 as i32
        && t > 0x7fffffffffffffff as i64 - tzoff as i64
    {
        *output = 0x7fffffffffffffff as i64;
        return 1 as i32;
    }
    t += tzoff as i64;
    *output = t;
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn curl_getdate(
    mut p: *const i8,
    mut now: *const time_t,
) -> time_t {
    let mut parsed: time_t = -(1 as i32) as time_t;
    let mut rc: i32 = parsedate(p, &mut parsed);
    if rc == 0 as i32 {
        if parsed == -(1 as i32) as i64 {
            parsed += 1;
        }
        return parsed;
    }
    return -(1 as i32) as time_t;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_getdate_capped(mut p: *const i8) -> time_t {
    let mut parsed: time_t = -(1 as i32) as time_t;
    let mut rc: i32 = parsedate(p, &mut parsed);
    match rc {
        0 => {
            if parsed == -(1 as i32) as i64 {
                parsed += 1;
            }
            return parsed;
        }
        1 => return parsed,
        _ => return -(1 as i32) as time_t,
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
