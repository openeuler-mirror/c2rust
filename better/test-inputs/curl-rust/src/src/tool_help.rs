use ::libc;
extern "C" {
    pub type Curl_easy;
    fn puts(__s: *const libc::c_char) -> libc::c_int;
    fn curl_strequal(s1: *const libc::c_char, s2: *const libc::c_char) -> libc::c_int;
    fn curl_version() -> *mut libc::c_char;
    fn curl_slist_free_all(_: *mut curl_slist);
    fn curl_easy_init() -> *mut CURL;
    fn curl_easy_cleanup(curl: *mut CURL);
    fn curl_easy_getinfo(curl: *mut CURL, info: CURLINFO, _: ...) -> CURLcode;
    fn free(__ptr: *mut libc::c_void);
    fn qsort(
        __base: *mut libc::c_void,
        __nmemb: size_t,
        __size: size_t,
        __compar: __compar_fn_t,
    );
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn curl_mprintf(format: *const libc::c_char, _: ...) -> libc::c_int;
    static mut curlinfo: *mut curl_version_info_data;
}
pub type size_t = libc::c_ulong;
pub type CURL = Curl_easy;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_slist {
    pub data: *mut libc::c_char,
    pub next: *mut curl_slist,
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
pub type CURLINFO = libc::c_uint;
pub const CURLINFO_LASTONE: CURLINFO = 60;
pub const CURLINFO_REFERER: CURLINFO = 1048636;
pub const CURLINFO_PROXY_ERROR: CURLINFO = 2097211;
pub const CURLINFO_EFFECTIVE_METHOD: CURLINFO = 1048634;
pub const CURLINFO_RETRY_AFTER: CURLINFO = 6291513;
pub const CURLINFO_APPCONNECT_TIME_T: CURLINFO = 6291512;
pub const CURLINFO_REDIRECT_TIME_T: CURLINFO = 6291511;
pub const CURLINFO_STARTTRANSFER_TIME_T: CURLINFO = 6291510;
pub const CURLINFO_PRETRANSFER_TIME_T: CURLINFO = 6291509;
pub const CURLINFO_CONNECT_TIME_T: CURLINFO = 6291508;
pub const CURLINFO_NAMELOOKUP_TIME_T: CURLINFO = 6291507;
pub const CURLINFO_TOTAL_TIME_T: CURLINFO = 6291506;
pub const CURLINFO_SCHEME: CURLINFO = 1048625;
pub const CURLINFO_PROTOCOL: CURLINFO = 2097200;
pub const CURLINFO_PROXY_SSL_VERIFYRESULT: CURLINFO = 2097199;
pub const CURLINFO_HTTP_VERSION: CURLINFO = 2097198;
pub const CURLINFO_TLS_SSL_PTR: CURLINFO = 4194349;
pub const CURLINFO_ACTIVESOCKET: CURLINFO = 5242924;
pub const CURLINFO_TLS_SESSION: CURLINFO = 4194347;
pub const CURLINFO_LOCAL_PORT: CURLINFO = 2097194;
pub const CURLINFO_LOCAL_IP: CURLINFO = 1048617;
pub const CURLINFO_PRIMARY_PORT: CURLINFO = 2097192;
pub const CURLINFO_RTSP_CSEQ_RECV: CURLINFO = 2097191;
pub const CURLINFO_RTSP_SERVER_CSEQ: CURLINFO = 2097190;
pub const CURLINFO_RTSP_CLIENT_CSEQ: CURLINFO = 2097189;
pub const CURLINFO_RTSP_SESSION_ID: CURLINFO = 1048612;
pub const CURLINFO_CONDITION_UNMET: CURLINFO = 2097187;
pub const CURLINFO_CERTINFO: CURLINFO = 4194338;
pub const CURLINFO_APPCONNECT_TIME: CURLINFO = 3145761;
pub const CURLINFO_PRIMARY_IP: CURLINFO = 1048608;
pub const CURLINFO_REDIRECT_URL: CURLINFO = 1048607;
pub const CURLINFO_FTP_ENTRY_PATH: CURLINFO = 1048606;
pub const CURLINFO_LASTSOCKET: CURLINFO = 2097181;
pub const CURLINFO_COOKIELIST: CURLINFO = 4194332;
pub const CURLINFO_SSL_ENGINES: CURLINFO = 4194331;
pub const CURLINFO_NUM_CONNECTS: CURLINFO = 2097178;
pub const CURLINFO_OS_ERRNO: CURLINFO = 2097177;
pub const CURLINFO_PROXYAUTH_AVAIL: CURLINFO = 2097176;
pub const CURLINFO_HTTPAUTH_AVAIL: CURLINFO = 2097175;
pub const CURLINFO_HTTP_CONNECTCODE: CURLINFO = 2097174;
pub const CURLINFO_PRIVATE: CURLINFO = 1048597;
pub const CURLINFO_REDIRECT_COUNT: CURLINFO = 2097172;
pub const CURLINFO_REDIRECT_TIME: CURLINFO = 3145747;
pub const CURLINFO_CONTENT_TYPE: CURLINFO = 1048594;
pub const CURLINFO_STARTTRANSFER_TIME: CURLINFO = 3145745;
pub const CURLINFO_CONTENT_LENGTH_UPLOAD_T: CURLINFO = 6291472;
pub const CURLINFO_CONTENT_LENGTH_UPLOAD: CURLINFO = 3145744;
pub const CURLINFO_CONTENT_LENGTH_DOWNLOAD_T: CURLINFO = 6291471;
pub const CURLINFO_CONTENT_LENGTH_DOWNLOAD: CURLINFO = 3145743;
pub const CURLINFO_FILETIME_T: CURLINFO = 6291470;
pub const CURLINFO_FILETIME: CURLINFO = 2097166;
pub const CURLINFO_SSL_VERIFYRESULT: CURLINFO = 2097165;
pub const CURLINFO_REQUEST_SIZE: CURLINFO = 2097164;
pub const CURLINFO_HEADER_SIZE: CURLINFO = 2097163;
pub const CURLINFO_SPEED_UPLOAD_T: CURLINFO = 6291466;
pub const CURLINFO_SPEED_UPLOAD: CURLINFO = 3145738;
pub const CURLINFO_SPEED_DOWNLOAD_T: CURLINFO = 6291465;
pub const CURLINFO_SPEED_DOWNLOAD: CURLINFO = 3145737;
pub const CURLINFO_SIZE_DOWNLOAD_T: CURLINFO = 6291464;
pub const CURLINFO_SIZE_DOWNLOAD: CURLINFO = 3145736;
pub const CURLINFO_SIZE_UPLOAD_T: CURLINFO = 6291463;
pub const CURLINFO_SIZE_UPLOAD: CURLINFO = 3145735;
pub const CURLINFO_PRETRANSFER_TIME: CURLINFO = 3145734;
pub const CURLINFO_CONNECT_TIME: CURLINFO = 3145733;
pub const CURLINFO_NAMELOOKUP_TIME: CURLINFO = 3145732;
pub const CURLINFO_TOTAL_TIME: CURLINFO = 3145731;
pub const CURLINFO_RESPONSE_CODE: CURLINFO = 2097154;
pub const CURLINFO_EFFECTIVE_URL: CURLINFO = 1048577;
pub const CURLINFO_NONE: CURLINFO = 0;
pub type CURLversion = libc::c_uint;
pub const CURLVERSION_LAST: CURLversion = 10;
pub const CURLVERSION_TENTH: CURLversion = 9;
pub const CURLVERSION_NINTH: CURLversion = 8;
pub const CURLVERSION_EIGHTH: CURLversion = 7;
pub const CURLVERSION_SEVENTH: CURLversion = 6;
pub const CURLVERSION_SIXTH: CURLversion = 5;
pub const CURLVERSION_FIFTH: CURLversion = 4;
pub const CURLVERSION_FOURTH: CURLversion = 3;
pub const CURLVERSION_THIRD: CURLversion = 2;
pub const CURLVERSION_SECOND: CURLversion = 1;
pub const CURLVERSION_FIRST: CURLversion = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_version_info_data {
    pub age: CURLversion,
    pub version: *const libc::c_char,
    pub version_num: libc::c_uint,
    pub host: *const libc::c_char,
    pub features: libc::c_int,
    pub ssl_version: *const libc::c_char,
    pub ssl_version_num: libc::c_long,
    pub libz_version: *const libc::c_char,
    pub protocols: *const *const libc::c_char,
    pub ares: *const libc::c_char,
    pub ares_num: libc::c_int,
    pub libidn: *const libc::c_char,
    pub iconv_ver_num: libc::c_int,
    pub libssh_version: *const libc::c_char,
    pub brotli_ver_num: libc::c_uint,
    pub brotli_version: *const libc::c_char,
    pub nghttp2_ver_num: libc::c_uint,
    pub nghttp2_version: *const libc::c_char,
    pub quic_version: *const libc::c_char,
    pub cainfo: *const libc::c_char,
    pub capath: *const libc::c_char,
    pub zstd_ver_num: libc::c_uint,
    pub zstd_version: *const libc::c_char,
    pub hyper_version: *const libc::c_char,
    pub gsasl_version: *const libc::c_char,
}
pub type __compar_fn_t = Option::<
    unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct category_descriptors {
    pub opt: *const libc::c_char,
    pub desc: *const libc::c_char,
    pub category: curlhelp_t,
}
pub type curlhelp_t = libc::c_uint;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct helptxt {
    pub opt: *const libc::c_char,
    pub desc: *const libc::c_char,
    pub categories: curlhelp_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct feat {
    pub name: *const libc::c_char,
    pub bitmask: libc::c_int,
}
static mut categories: [category_descriptors; 23] = [
    {
        let mut init = category_descriptors {
            opt: b"auth\0" as *const u8 as *const libc::c_char,
            desc: b"Different types of authentication methods\0" as *const u8
                as *const libc::c_char,
            category: (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"connection\0" as *const u8 as *const libc::c_char,
            desc: b"Low level networking operations\0" as *const u8
                as *const libc::c_char,
            category: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"curl\0" as *const u8 as *const libc::c_char,
            desc: b"The command line tool itself\0" as *const u8 as *const libc::c_char,
            category: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"dns\0" as *const u8 as *const libc::c_char,
            desc: b"General DNS options\0" as *const u8 as *const libc::c_char,
            category: (1 as libc::c_uint) << 4 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"file\0" as *const u8 as *const libc::c_char,
            desc: b"FILE protocol options\0" as *const u8 as *const libc::c_char,
            category: (1 as libc::c_uint) << 5 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"ftp\0" as *const u8 as *const libc::c_char,
            desc: b"FTP protocol options\0" as *const u8 as *const libc::c_char,
            category: (1 as libc::c_uint) << 6 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"http\0" as *const u8 as *const libc::c_char,
            desc: b"HTTP and HTTPS protocol options\0" as *const u8
                as *const libc::c_char,
            category: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"imap\0" as *const u8 as *const libc::c_char,
            desc: b"IMAP protocol options\0" as *const u8 as *const libc::c_char,
            category: (1 as libc::c_uint) << 8 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"misc\0" as *const u8 as *const libc::c_char,
            desc: b"Options that don't fit into any other category\0" as *const u8
                as *const libc::c_char,
            category: (1 as libc::c_uint) << 10 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"output\0" as *const u8 as *const libc::c_char,
            desc: b"Filesystem output\0" as *const u8 as *const libc::c_char,
            category: (1 as libc::c_uint) << 11 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"pop3\0" as *const u8 as *const libc::c_char,
            desc: b"POP3 protocol options\0" as *const u8 as *const libc::c_char,
            category: (1 as libc::c_uint) << 12 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"post\0" as *const u8 as *const libc::c_char,
            desc: b"HTTP Post specific options\0" as *const u8 as *const libc::c_char,
            category: (1 as libc::c_uint) << 13 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"proxy\0" as *const u8 as *const libc::c_char,
            desc: b"All options related to proxies\0" as *const u8
                as *const libc::c_char,
            category: (1 as libc::c_uint) << 14 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"scp\0" as *const u8 as *const libc::c_char,
            desc: b"SCP protocol options\0" as *const u8 as *const libc::c_char,
            category: (1 as libc::c_uint) << 15 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"sftp\0" as *const u8 as *const libc::c_char,
            desc: b"SFTP protocol options\0" as *const u8 as *const libc::c_char,
            category: (1 as libc::c_uint) << 16 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"smtp\0" as *const u8 as *const libc::c_char,
            desc: b"SMTP protocol options\0" as *const u8 as *const libc::c_char,
            category: (1 as libc::c_uint) << 17 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"ssh\0" as *const u8 as *const libc::c_char,
            desc: b"SSH protocol options\0" as *const u8 as *const libc::c_char,
            category: (1 as libc::c_uint) << 18 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"telnet\0" as *const u8 as *const libc::c_char,
            desc: b"TELNET protocol options\0" as *const u8 as *const libc::c_char,
            category: (1 as libc::c_uint) << 19 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"tftp\0" as *const u8 as *const libc::c_char,
            desc: b"TFTP protocol options\0" as *const u8 as *const libc::c_char,
            category: (1 as libc::c_uint) << 20 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"tls\0" as *const u8 as *const libc::c_char,
            desc: b"All TLS/SSL related options\0" as *const u8 as *const libc::c_char,
            category: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"upload\0" as *const u8 as *const libc::c_char,
            desc: b"All options for uploads\0" as *const u8 as *const libc::c_char,
            category: (1 as libc::c_uint) << 22 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: b"verbose\0" as *const u8 as *const libc::c_char,
            desc: b"Options related to any kind of command line output of curl\0"
                as *const u8 as *const libc::c_char,
            category: (1 as libc::c_uint) << 23 as libc::c_uint,
        };
        init
    },
    {
        let mut init = category_descriptors {
            opt: 0 as *const libc::c_char,
            desc: 0 as *const libc::c_char,
            category: (1 as libc::c_uint) << 0 as libc::c_uint,
        };
        init
    },
];
static mut helptext: [helptxt; 243] = [
    {
        let mut init = helptxt {
            opt: b"    --abstract-unix-socket <path>\0" as *const u8
                as *const libc::c_char,
            desc: b"Connect via abstract Unix domain socket\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --alt-svc <file name>\0" as *const u8 as *const libc::c_char,
            desc: b"Enable alt-svc with this cache file\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --anyauth\0" as *const u8 as *const libc::c_char,
            desc: b"Pick any authentication method\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-a, --append\0" as *const u8 as *const libc::c_char,
            desc: b"Append to target file when uploading\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint
                | (1 as libc::c_uint) << 16 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --aws-sigv4 <provider1[:provider2[:region[:service]]]>\0"
                as *const u8 as *const libc::c_char,
            desc: b"Use AWS V4 signature authentication\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 1 as libc::c_uint
                | (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --basic\0" as *const u8 as *const libc::c_char,
            desc: b"Use HTTP Basic Authentication\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --cacert <file>\0" as *const u8 as *const libc::c_char,
            desc: b"CA certificate to verify peer against\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --capath <dir>\0" as *const u8 as *const libc::c_char,
            desc: b"CA directory to verify peer against\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-E, --cert <certificate[:password]>\0" as *const u8
                as *const libc::c_char,
            desc: b"Client certificate file and password\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --cert-status\0" as *const u8 as *const libc::c_char,
            desc: b"Verify the status of the server cert via OCSP-staple\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --cert-type <type>\0" as *const u8 as *const libc::c_char,
            desc: b"Certificate type (DER/PEM/ENG)\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ciphers <list of ciphers>\0" as *const u8
                as *const libc::c_char,
            desc: b"SSL ciphers to use\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --compressed\0" as *const u8 as *const libc::c_char,
            desc: b"Request compressed response\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --compressed-ssh\0" as *const u8 as *const libc::c_char,
            desc: b"Enable SSH compression\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 15 as libc::c_uint
                | (1 as libc::c_uint) << 18 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-K, --config <file>\0" as *const u8 as *const libc::c_char,
            desc: b"Read config from a file\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --connect-timeout <fractional seconds>\0" as *const u8
                as *const libc::c_char,
            desc: b"Maximum time allowed for connection\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --connect-to <HOST1:PORT1:HOST2:PORT2>\0" as *const u8
                as *const libc::c_char,
            desc: b"Connect to host\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-C, --continue-at <offset>\0" as *const u8 as *const libc::c_char,
            desc: b"Resumed transfer offset\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-b, --cookie <data|filename>\0" as *const u8 as *const libc::c_char,
            desc: b"Send cookies from string/file\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-c, --cookie-jar <filename>\0" as *const u8 as *const libc::c_char,
            desc: b"Write cookies to <filename> after operation\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --create-dirs\0" as *const u8 as *const libc::c_char,
            desc: b"Create necessary local directory hierarchy\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --create-file-mode <mode>\0" as *const u8 as *const libc::c_char,
            desc: b"File mode (octal) for created files\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 16 as libc::c_uint
                | (1 as libc::c_uint) << 15 as libc::c_uint
                | (1 as libc::c_uint) << 5 as libc::c_uint
                | (1 as libc::c_uint) << 22 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --crlf\0" as *const u8 as *const libc::c_char,
            desc: b"Convert LF to CRLF in upload\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint
                | (1 as libc::c_uint) << 17 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --crlfile <file>\0" as *const u8 as *const libc::c_char,
            desc: b"Use this CRL list\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --curves <algorithm list>\0" as *const u8 as *const libc::c_char,
            desc: b"(EC) TLS key exchange algorithm(s) to request\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-d, --data <data>\0" as *const u8 as *const libc::c_char,
            desc: b"HTTP POST data\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 9 as libc::c_uint
                | (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 13 as libc::c_uint
                | (1 as libc::c_uint) << 22 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --data-ascii <data>\0" as *const u8 as *const libc::c_char,
            desc: b"HTTP POST ASCII data\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 13 as libc::c_uint
                | (1 as libc::c_uint) << 22 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --data-binary <data>\0" as *const u8 as *const libc::c_char,
            desc: b"HTTP POST binary data\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 13 as libc::c_uint
                | (1 as libc::c_uint) << 22 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --data-raw <data>\0" as *const u8 as *const libc::c_char,
            desc: b"HTTP POST data, '@' allowed\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 13 as libc::c_uint
                | (1 as libc::c_uint) << 22 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --data-urlencode <data>\0" as *const u8 as *const libc::c_char,
            desc: b"HTTP POST data url encoded\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 13 as libc::c_uint
                | (1 as libc::c_uint) << 22 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --delegation <LEVEL>\0" as *const u8 as *const libc::c_char,
            desc: b"GSS-API delegation permission\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --digest\0" as *const u8 as *const libc::c_char,
            desc: b"Use HTTP Digest Authentication\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint
                | (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-q, --disable\0" as *const u8 as *const libc::c_char,
            desc: b"Disable .curlrc\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --disable-eprt\0" as *const u8 as *const libc::c_char,
            desc: b"Inhibit using EPRT or LPRT\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --disable-epsv\0" as *const u8 as *const libc::c_char,
            desc: b"Inhibit using EPSV\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --disallow-username-in-url\0" as *const u8 as *const libc::c_char,
            desc: b"Disallow username in url\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint
                | (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --dns-interface <interface>\0" as *const u8
                as *const libc::c_char,
            desc: b"Interface to use for DNS requests\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 4 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --dns-ipv4-addr <address>\0" as *const u8 as *const libc::c_char,
            desc: b"IPv4 address to use for DNS requests\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 4 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --dns-ipv6-addr <address>\0" as *const u8 as *const libc::c_char,
            desc: b"IPv6 address to use for DNS requests\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 4 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --dns-servers <addresses>\0" as *const u8 as *const libc::c_char,
            desc: b"DNS server addrs to use\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 4 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --doh-cert-status\0" as *const u8 as *const libc::c_char,
            desc: b"Verify the status of the DoH server cert via OCSP-staple\0"
                as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 4 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --doh-insecure\0" as *const u8 as *const libc::c_char,
            desc: b"Allow insecure DoH server connections\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 4 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --doh-url <URL>\0" as *const u8 as *const libc::c_char,
            desc: b"Resolve host names over DoH\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 4 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-D, --dump-header <filename>\0" as *const u8 as *const libc::c_char,
            desc: b"Write the received headers to <filename>\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 6 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --egd-file <file>\0" as *const u8 as *const libc::c_char,
            desc: b"EGD socket path for random data\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --engine <name>\0" as *const u8 as *const libc::c_char,
            desc: b"Crypto engine to use\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --etag-compare <file>\0" as *const u8 as *const libc::c_char,
            desc: b"Pass an ETag from a file as a custom header\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --etag-save <file>\0" as *const u8 as *const libc::c_char,
            desc: b"Parse ETag from a request and save it to a file\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --expect100-timeout <seconds>\0" as *const u8
                as *const libc::c_char,
            desc: b"How long to wait for 100-continue\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-f, --fail\0" as *const u8 as *const libc::c_char,
            desc: b"Fail silently (no output at all) on HTTP errors\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 9 as libc::c_uint
                | (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --fail-early\0" as *const u8 as *const libc::c_char,
            desc: b"Fail on first transfer error, do not continue\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --fail-with-body\0" as *const u8 as *const libc::c_char,
            desc: b"Fail on HTTP errors but save the body\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 11 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --false-start\0" as *const u8 as *const libc::c_char,
            desc: b"Enable TLS False Start\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-F, --form <name=content>\0" as *const u8 as *const libc::c_char,
            desc: b"Specify multipart MIME data\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 22 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --form-string <name=string>\0" as *const u8
                as *const libc::c_char,
            desc: b"Specify multipart MIME data\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 22 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ftp-account <data>\0" as *const u8 as *const libc::c_char,
            desc: b"Account data string\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ftp-alternative-to-user <command>\0" as *const u8
                as *const libc::c_char,
            desc: b"String to replace USER [name]\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ftp-create-dirs\0" as *const u8 as *const libc::c_char,
            desc: b"Create the remote dirs if not present\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint
                | (1 as libc::c_uint) << 16 as libc::c_uint
                | (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ftp-method <method>\0" as *const u8 as *const libc::c_char,
            desc: b"Control CWD usage\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ftp-pasv\0" as *const u8 as *const libc::c_char,
            desc: b"Use PASV/EPSV instead of PORT\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-P, --ftp-port <address>\0" as *const u8 as *const libc::c_char,
            desc: b"Use PORT instead of PASV\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ftp-pret\0" as *const u8 as *const libc::c_char,
            desc: b"Send PRET before PASV\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ftp-skip-pasv-ip\0" as *const u8 as *const libc::c_char,
            desc: b"Skip the IP address for PASV\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ftp-ssl-ccc\0" as *const u8 as *const libc::c_char,
            desc: b"Send CCC after authenticating\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ftp-ssl-ccc-mode <active/passive>\0" as *const u8
                as *const libc::c_char,
            desc: b"Set CCC mode\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ftp-ssl-control\0" as *const u8 as *const libc::c_char,
            desc: b"Require SSL/TLS for FTP login, clear for transfer\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-G, --get\0" as *const u8 as *const libc::c_char,
            desc: b"Put the post data in the URL and use GET\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 22 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-g, --globoff\0" as *const u8 as *const libc::c_char,
            desc: b"Disable URL sequences and ranges using {} and []\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --happy-eyeballs-timeout-ms <milliseconds>\0" as *const u8
                as *const libc::c_char,
            desc: b"Time for IPv6 before trying IPv4\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --haproxy-protocol\0" as *const u8 as *const libc::c_char,
            desc: b"Send HAProxy PROXY protocol v1 header\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 14 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-I, --head\0" as *const u8 as *const libc::c_char,
            desc: b"Show document info only\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 6 as libc::c_uint
                | (1 as libc::c_uint) << 5 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-H, --header <header/@file>\0" as *const u8 as *const libc::c_char,
            desc: b"Pass custom header(s) to server\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-h, --help <category>\0" as *const u8 as *const libc::c_char,
            desc: b"Get help for commands\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 9 as libc::c_uint
                | (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --hostpubmd5 <md5>\0" as *const u8 as *const libc::c_char,
            desc: b"Acceptable MD5 hash of the host public key\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 16 as libc::c_uint
                | (1 as libc::c_uint) << 15 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --hsts <file name>\0" as *const u8 as *const libc::c_char,
            desc: b"Enable HSTS with this cache file\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --http0.9\0" as *const u8 as *const libc::c_char,
            desc: b"Allow HTTP 0.9 responses\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-0, --http1.0\0" as *const u8 as *const libc::c_char,
            desc: b"Use HTTP 1.0\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --http1.1\0" as *const u8 as *const libc::c_char,
            desc: b"Use HTTP 1.1\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --http2\0" as *const u8 as *const libc::c_char,
            desc: b"Use HTTP 2\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --http2-prior-knowledge\0" as *const u8 as *const libc::c_char,
            desc: b"Use HTTP 2 without HTTP/1.1 Upgrade\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --http3\0" as *const u8 as *const libc::c_char,
            desc: b"Use HTTP v3\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ignore-content-length\0" as *const u8 as *const libc::c_char,
            desc: b"Ignore the size of the remote resource\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 6 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-i, --include\0" as *const u8 as *const libc::c_char,
            desc: b"Include protocol response headers in the output\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 9 as libc::c_uint
                | (1 as libc::c_uint) << 23 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-k, --insecure\0" as *const u8 as *const libc::c_char,
            desc: b"Allow insecure server connections when using SSL\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --interface <name>\0" as *const u8 as *const libc::c_char,
            desc: b"Use network INTERFACE (or address)\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-4, --ipv4\0" as *const u8 as *const libc::c_char,
            desc: b"Resolve names to IPv4 addresses\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint
                | (1 as libc::c_uint) << 4 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-6, --ipv6\0" as *const u8 as *const libc::c_char,
            desc: b"Resolve names to IPv6 addresses\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint
                | (1 as libc::c_uint) << 4 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-j, --junk-session-cookies\0" as *const u8 as *const libc::c_char,
            desc: b"Ignore session cookies read from file\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --keepalive-time <seconds>\0" as *const u8 as *const libc::c_char,
            desc: b"Interval time for keepalive probes\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --key <key>\0" as *const u8 as *const libc::c_char,
            desc: b"Private key file name\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint
                | (1 as libc::c_uint) << 18 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --key-type <type>\0" as *const u8 as *const libc::c_char,
            desc: b"Private key file type (DER/PEM/ENG)\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --krb <level>\0" as *const u8 as *const libc::c_char,
            desc: b"Enable Kerberos with security <level>\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --libcurl <file>\0" as *const u8 as *const libc::c_char,
            desc: b"Dump libcurl equivalent code of this command line\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --limit-rate <speed>\0" as *const u8 as *const libc::c_char,
            desc: b"Limit transfer speed to RATE\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-l, --list-only\0" as *const u8 as *const libc::c_char,
            desc: b"List only mode\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint
                | (1 as libc::c_uint) << 12 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --local-port <num/range>\0" as *const u8 as *const libc::c_char,
            desc: b"Force use of RANGE for local port numbers\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-L, --location\0" as *const u8 as *const libc::c_char,
            desc: b"Follow redirects\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --location-trusted\0" as *const u8 as *const libc::c_char,
            desc: b"Like --location, and send auth to other hosts\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --login-options <options>\0" as *const u8 as *const libc::c_char,
            desc: b"Server login options\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 8 as libc::c_uint
                | (1 as libc::c_uint) << 12 as libc::c_uint
                | (1 as libc::c_uint) << 17 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --mail-auth <address>\0" as *const u8 as *const libc::c_char,
            desc: b"Originator address of the original email\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 17 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --mail-from <address>\0" as *const u8 as *const libc::c_char,
            desc: b"Mail from this address\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 17 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --mail-rcpt <address>\0" as *const u8 as *const libc::c_char,
            desc: b"Mail to this address\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 17 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --mail-rcpt-allowfails\0" as *const u8 as *const libc::c_char,
            desc: b"Allow RCPT TO command to fail for some recipients\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 17 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-M, --manual\0" as *const u8 as *const libc::c_char,
            desc: b"Display the full manual\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --max-filesize <bytes>\0" as *const u8 as *const libc::c_char,
            desc: b"Maximum file size to download\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --max-redirs <num>\0" as *const u8 as *const libc::c_char,
            desc: b"Maximum number of redirects allowed\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-m, --max-time <fractional seconds>\0" as *const u8
                as *const libc::c_char,
            desc: b"Maximum time allowed for the transfer\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --metalink\0" as *const u8 as *const libc::c_char,
            desc: b"Process given URLs as metalink XML file\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 10 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --negotiate\0" as *const u8 as *const libc::c_char,
            desc: b"Use HTTP Negotiate (SPNEGO) authentication\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 1 as libc::c_uint
                | (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-n, --netrc\0" as *const u8 as *const libc::c_char,
            desc: b"Must read .netrc for user name and password\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --netrc-file <filename>\0" as *const u8 as *const libc::c_char,
            desc: b"Specify FILE for netrc\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --netrc-optional\0" as *const u8 as *const libc::c_char,
            desc: b"Use either .netrc or URL\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-:, --next\0" as *const u8 as *const libc::c_char,
            desc: b"Make next URL use its separate set of options\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --no-alpn\0" as *const u8 as *const libc::c_char,
            desc: b"Disable the ALPN TLS extension\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint
                | (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-N, --no-buffer\0" as *const u8 as *const libc::c_char,
            desc: b"Disable buffering of the output stream\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --no-keepalive\0" as *const u8 as *const libc::c_char,
            desc: b"Disable TCP keepalive on the connection\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --no-npn\0" as *const u8 as *const libc::c_char,
            desc: b"Disable the NPN TLS extension\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint
                | (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --no-progress-meter\0" as *const u8 as *const libc::c_char,
            desc: b"Do not show the progress meter\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 23 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --no-sessionid\0" as *const u8 as *const libc::c_char,
            desc: b"Disable SSL session-ID reusing\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --noproxy <no-proxy-list>\0" as *const u8 as *const libc::c_char,
            desc: b"List of hosts which do not use proxy\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ntlm\0" as *const u8 as *const libc::c_char,
            desc: b"Use HTTP NTLM authentication\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 1 as libc::c_uint
                | (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ntlm-wb\0" as *const u8 as *const libc::c_char,
            desc: b"Use HTTP NTLM authentication with winbind\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 1 as libc::c_uint
                | (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --oauth2-bearer <token>\0" as *const u8 as *const libc::c_char,
            desc: b"OAuth 2 Bearer Token\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-o, --output <file>\0" as *const u8 as *const libc::c_char,
            desc: b"Write to file instead of stdout\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 9 as libc::c_uint
                | (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --output-dir <dir>\0" as *const u8 as *const libc::c_char,
            desc: b"Directory to save files in\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-Z, --parallel\0" as *const u8 as *const libc::c_char,
            desc: b"Perform transfers in parallel\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint
                | (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --parallel-immediate\0" as *const u8 as *const libc::c_char,
            desc: b"Do not wait for multiplexing (with --parallel)\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint
                | (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --parallel-max <num>\0" as *const u8 as *const libc::c_char,
            desc: b"Maximum concurrency for parallel transfers\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint
                | (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --pass <phrase>\0" as *const u8 as *const libc::c_char,
            desc: b"Pass phrase for the private key\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 18 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --path-as-is\0" as *const u8 as *const libc::c_char,
            desc: b"Do not squash .. sequences in URL path\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --pinnedpubkey <hashes>\0" as *const u8 as *const libc::c_char,
            desc: b"FILE/HASHES Public key to verify peer against\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --post301\0" as *const u8 as *const libc::c_char,
            desc: b"Do not switch to GET after following a 301\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 13 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --post302\0" as *const u8 as *const libc::c_char,
            desc: b"Do not switch to GET after following a 302\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 13 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --post303\0" as *const u8 as *const libc::c_char,
            desc: b"Do not switch to GET after following a 303\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 13 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --preproxy [protocol://]host[:port]\0" as *const u8
                as *const libc::c_char,
            desc: b"Use this proxy first\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-#, --progress-bar\0" as *const u8 as *const libc::c_char,
            desc: b"Display transfer progress as a bar\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 23 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proto <protocols>\0" as *const u8 as *const libc::c_char,
            desc: b"Enable/disable PROTOCOLS\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint
                | (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proto-default <protocol>\0" as *const u8 as *const libc::c_char,
            desc: b"Use PROTOCOL for any URL missing a scheme\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint
                | (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proto-redir <protocols>\0" as *const u8 as *const libc::c_char,
            desc: b"Enable/disable PROTOCOLS on redirect\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint
                | (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-x, --proxy [protocol://]host[:port]\0" as *const u8
                as *const libc::c_char,
            desc: b"Use this proxy\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-anyauth\0" as *const u8 as *const libc::c_char,
            desc: b"Pick any proxy authentication method\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-basic\0" as *const u8 as *const libc::c_char,
            desc: b"Use Basic authentication on the proxy\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-cacert <file>\0" as *const u8 as *const libc::c_char,
            desc: b"CA certificate to verify peer against for proxy\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-capath <dir>\0" as *const u8 as *const libc::c_char,
            desc: b"CA directory to verify peer against for proxy\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-cert <cert[:passwd]>\0" as *const u8
                as *const libc::c_char,
            desc: b"Set client certificate for proxy\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-cert-type <type>\0" as *const u8 as *const libc::c_char,
            desc: b"Client certificate type for HTTPS proxy\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-ciphers <list>\0" as *const u8 as *const libc::c_char,
            desc: b"SSL ciphers to use for proxy\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-crlfile <file>\0" as *const u8 as *const libc::c_char,
            desc: b"Set a CRL list for proxy\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-digest\0" as *const u8 as *const libc::c_char,
            desc: b"Use Digest authentication on the proxy\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-header <header/@file>\0" as *const u8
                as *const libc::c_char,
            desc: b"Pass custom header(s) to proxy\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-insecure\0" as *const u8 as *const libc::c_char,
            desc: b"Do HTTPS proxy connections without verifying the proxy\0"
                as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-key <key>\0" as *const u8 as *const libc::c_char,
            desc: b"Private key for HTTPS proxy\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-key-type <type>\0" as *const u8 as *const libc::c_char,
            desc: b"Private key file type for proxy\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-negotiate\0" as *const u8 as *const libc::c_char,
            desc: b"Use HTTP Negotiate (SPNEGO) authentication on the proxy\0"
                as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-ntlm\0" as *const u8 as *const libc::c_char,
            desc: b"Use NTLM authentication on the proxy\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-pass <phrase>\0" as *const u8 as *const libc::c_char,
            desc: b"Pass phrase for the private key for HTTPS proxy\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-pinnedpubkey <hashes>\0" as *const u8
                as *const libc::c_char,
            desc: b"FILE/HASHES public key to verify proxy with\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-service-name <name>\0" as *const u8
                as *const libc::c_char,
            desc: b"SPNEGO proxy service name\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-ssl-allow-beast\0" as *const u8 as *const libc::c_char,
            desc: b"Allow security flaw for interop for HTTPS proxy\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-ssl-auto-client-cert\0" as *const u8
                as *const libc::c_char,
            desc: b"Use auto client certificate for proxy (Schannel)\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-tls13-ciphers <ciphersuite list>\0" as *const u8
                as *const libc::c_char,
            desc: b"TLS 1.3 proxy cipher suites\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-tlsauthtype <type>\0" as *const u8 as *const libc::c_char,
            desc: b"TLS authentication type for HTTPS proxy\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-tlspassword <string>\0" as *const u8
                as *const libc::c_char,
            desc: b"TLS password for HTTPS proxy\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-tlsuser <name>\0" as *const u8 as *const libc::c_char,
            desc: b"TLS username for HTTPS proxy\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy-tlsv1\0" as *const u8 as *const libc::c_char,
            desc: b"Use TLSv1 for HTTPS proxy\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 21 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-U, --proxy-user <user:password>\0" as *const u8
                as *const libc::c_char,
            desc: b"Proxy user and password\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --proxy1.0 <host[:port]>\0" as *const u8 as *const libc::c_char,
            desc: b"Use HTTP/1.0 proxy on given port\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-p, --proxytunnel\0" as *const u8 as *const libc::c_char,
            desc: b"Operate through an HTTP proxy tunnel (using CONNECT)\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --pubkey <key>\0" as *const u8 as *const libc::c_char,
            desc: b"SSH Public key file name\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 16 as libc::c_uint
                | (1 as libc::c_uint) << 15 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-Q, --quote <command>\0" as *const u8 as *const libc::c_char,
            desc: b"Send command(s) to server before transfer\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 6 as libc::c_uint
                | (1 as libc::c_uint) << 16 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --random-file <file>\0" as *const u8 as *const libc::c_char,
            desc: b"File for reading random data from\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 10 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-r, --range <range>\0" as *const u8 as *const libc::c_char,
            desc: b"Retrieve only the bytes within RANGE\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 6 as libc::c_uint
                | (1 as libc::c_uint) << 16 as libc::c_uint
                | (1 as libc::c_uint) << 5 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --raw\0" as *const u8 as *const libc::c_char,
            desc: b"Do HTTP \"raw\"; no transfer decoding\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-e, --referer <URL>\0" as *const u8 as *const libc::c_char,
            desc: b"Referrer URL\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-J, --remote-header-name\0" as *const u8 as *const libc::c_char,
            desc: b"Use the header-provided filename\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 11 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-O, --remote-name\0" as *const u8 as *const libc::c_char,
            desc: b"Write output to a file named as the remote file\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 9 as libc::c_uint
                | (1 as libc::c_uint) << 11 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --remote-name-all\0" as *const u8 as *const libc::c_char,
            desc: b"Use the remote file name for all URLs\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 11 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-R, --remote-time\0" as *const u8 as *const libc::c_char,
            desc: b"Set the remote file's time on the local output\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 11 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-X, --request <command>\0" as *const u8 as *const libc::c_char,
            desc: b"Specify request command to use\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --request-target <path>\0" as *const u8 as *const libc::c_char,
            desc: b"Specify the target for this request\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --resolve <[+]host:port:addr[,addr]...>\0" as *const u8
                as *const libc::c_char,
            desc: b"Resolve the host+port to this address\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --retry <num>\0" as *const u8 as *const libc::c_char,
            desc: b"Retry request if transient problems occur\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --retry-all-errors\0" as *const u8 as *const libc::c_char,
            desc: b"Retry all errors (use with --retry)\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --retry-connrefused\0" as *const u8 as *const libc::c_char,
            desc: b"Retry on connection refused (use with --retry)\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --retry-delay <seconds>\0" as *const u8 as *const libc::c_char,
            desc: b"Wait time between retries\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --retry-max-time <seconds>\0" as *const u8 as *const libc::c_char,
            desc: b"Retry only within this period\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --sasl-authzid <identity>\0" as *const u8 as *const libc::c_char,
            desc: b"Identity for SASL PLAIN authentication\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --sasl-ir\0" as *const u8 as *const libc::c_char,
            desc: b"Enable initial response in SASL authentication\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --service-name <name>\0" as *const u8 as *const libc::c_char,
            desc: b"SPNEGO service name\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 10 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-S, --show-error\0" as *const u8 as *const libc::c_char,
            desc: b"Show error even when -s is used\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-s, --silent\0" as *const u8 as *const libc::c_char,
            desc: b"Silent mode\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 9 as libc::c_uint
                | (1 as libc::c_uint) << 23 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --socks4 <host[:port]>\0" as *const u8 as *const libc::c_char,
            desc: b"SOCKS4 proxy on given host + port\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --socks4a <host[:port]>\0" as *const u8 as *const libc::c_char,
            desc: b"SOCKS4a proxy on given host + port\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --socks5 <host[:port]>\0" as *const u8 as *const libc::c_char,
            desc: b"SOCKS5 proxy on given host + port\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --socks5-basic\0" as *const u8 as *const libc::c_char,
            desc: b"Enable username/password auth for SOCKS5 proxies\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --socks5-gssapi\0" as *const u8 as *const libc::c_char,
            desc: b"Enable GSS-API auth for SOCKS5 proxies\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --socks5-gssapi-nec\0" as *const u8 as *const libc::c_char,
            desc: b"Compatibility with NEC SOCKS5 server\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --socks5-gssapi-service <name>\0" as *const u8
                as *const libc::c_char,
            desc: b"SOCKS5 proxy service name for GSS-API\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --socks5-hostname <host[:port]>\0" as *const u8
                as *const libc::c_char,
            desc: b"SOCKS5 proxy, pass host name to proxy\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-Y, --speed-limit <speed>\0" as *const u8 as *const libc::c_char,
            desc: b"Stop transfers slower than this\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-y, --speed-time <seconds>\0" as *const u8 as *const libc::c_char,
            desc: b"Trigger 'speed-limit' abort after this time\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ssl\0" as *const u8 as *const libc::c_char,
            desc: b"Try SSL/TLS\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ssl-allow-beast\0" as *const u8 as *const libc::c_char,
            desc: b"Allow security flaw to improve interop\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ssl-auto-client-cert\0" as *const u8 as *const libc::c_char,
            desc: b"Use auto client certificate (Schannel)\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ssl-no-revoke\0" as *const u8 as *const libc::c_char,
            desc: b"Disable cert revocation checks (Schannel)\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ssl-reqd\0" as *const u8 as *const libc::c_char,
            desc: b"Require SSL/TLS\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --ssl-revoke-best-effort\0" as *const u8 as *const libc::c_char,
            desc: b"Ignore missing/offline cert CRL dist points\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-2, --sslv2\0" as *const u8 as *const libc::c_char,
            desc: b"Use SSLv2\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-3, --sslv3\0" as *const u8 as *const libc::c_char,
            desc: b"Use SSLv3\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --stderr <file>\0" as *const u8 as *const libc::c_char,
            desc: b"Where to redirect stderr\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 23 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --styled-output\0" as *const u8 as *const libc::c_char,
            desc: b"Enable styled output for HTTP headers\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 23 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --suppress-connect-headers\0" as *const u8 as *const libc::c_char,
            desc: b"Suppress proxy CONNECT response headers\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 14 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --tcp-fastopen\0" as *const u8 as *const libc::c_char,
            desc: b"Use TCP Fast Open\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --tcp-nodelay\0" as *const u8 as *const libc::c_char,
            desc: b"Use the TCP_NODELAY option\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-t, --telnet-option <opt=val>\0" as *const u8 as *const libc::c_char,
            desc: b"Set telnet option\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 19 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --tftp-blksize <value>\0" as *const u8 as *const libc::c_char,
            desc: b"Set TFTP BLKSIZE option\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 20 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --tftp-no-options\0" as *const u8 as *const libc::c_char,
            desc: b"Do not send any TFTP options\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 20 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-z, --time-cond <time>\0" as *const u8 as *const libc::c_char,
            desc: b"Transfer based on a time condition\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint
                | (1 as libc::c_uint) << 6 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --tls-max <VERSION>\0" as *const u8 as *const libc::c_char,
            desc: b"Set maximum allowed TLS version\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --tls13-ciphers <ciphersuite list>\0" as *const u8
                as *const libc::c_char,
            desc: b"TLS 1.3 cipher suites to use\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --tlsauthtype <type>\0" as *const u8 as *const libc::c_char,
            desc: b"TLS authentication type\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --tlspassword <string>\0" as *const u8 as *const libc::c_char,
            desc: b"TLS password\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --tlsuser <name>\0" as *const u8 as *const libc::c_char,
            desc: b"TLS user name\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-1, --tlsv1\0" as *const u8 as *const libc::c_char,
            desc: b"Use TLSv1.0 or greater\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --tlsv1.0\0" as *const u8 as *const libc::c_char,
            desc: b"Use TLSv1.0 or greater\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --tlsv1.1\0" as *const u8 as *const libc::c_char,
            desc: b"Use TLSv1.1 or greater\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --tlsv1.2\0" as *const u8 as *const libc::c_char,
            desc: b"Use TLSv1.2 or greater\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --tlsv1.3\0" as *const u8 as *const libc::c_char,
            desc: b"Use TLSv1.3 or greater\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 21 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --tr-encoding\0" as *const u8 as *const libc::c_char,
            desc: b"Request compressed transfer encoding\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --trace <file>\0" as *const u8 as *const libc::c_char,
            desc: b"Write a debug trace to FILE\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 23 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --trace-ascii <file>\0" as *const u8 as *const libc::c_char,
            desc: b"Like --trace, but without hex output\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 23 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --trace-time\0" as *const u8 as *const libc::c_char,
            desc: b"Add time stamps to trace/verbose output\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 23 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --unix-socket <path>\0" as *const u8 as *const libc::c_char,
            desc: b"Connect through this Unix domain socket\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 2 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-T, --upload-file <file>\0" as *const u8 as *const libc::c_char,
            desc: b"Transfer local FILE to destination\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 9 as libc::c_uint
                | (1 as libc::c_uint) << 22 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --url <url>\0" as *const u8 as *const libc::c_char,
            desc: b"URL to work with\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-B, --use-ascii\0" as *const u8 as *const libc::c_char,
            desc: b"Use ASCII/text transfer\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 10 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-u, --user <user:password>\0" as *const u8 as *const libc::c_char,
            desc: b"Server user and password\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 9 as libc::c_uint
                | (1 as libc::c_uint) << 1 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-A, --user-agent <name>\0" as *const u8 as *const libc::c_char,
            desc: b"Send User-Agent <name> to server\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 9 as libc::c_uint
                | (1 as libc::c_uint) << 7 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-v, --verbose\0" as *const u8 as *const libc::c_char,
            desc: b"Make the operation more talkative\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 9 as libc::c_uint
                | (1 as libc::c_uint) << 23 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-V, --version\0" as *const u8 as *const libc::c_char,
            desc: b"Show version number and quit\0" as *const u8 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 9 as libc::c_uint
                | (1 as libc::c_uint) << 3 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"-w, --write-out <format>\0" as *const u8 as *const libc::c_char,
            desc: b"Use output FORMAT after completion\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 23 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: b"    --xattr\0" as *const u8 as *const libc::c_char,
            desc: b"Store metadata in extended file attributes\0" as *const u8
                as *const libc::c_char,
            categories: (1 as libc::c_uint) << 10 as libc::c_uint,
        };
        init
    },
    {
        let mut init = helptxt {
            opt: 0 as *const libc::c_char,
            desc: 0 as *const libc::c_char,
            categories: (1 as libc::c_uint) << 0 as libc::c_uint,
        };
        init
    },
];
static mut feats: [feat; 28] = [
    {
        let mut init = feat {
            name: b"AsynchDNS\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 7 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"Debug\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 6 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"TrackMemory\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 13 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"IDN\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 10 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"IPv6\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"Largefile\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 9 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"Unicode\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 27 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"SSPI\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 11 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"GSS-API\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 17 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"Kerberos\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 18 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"SPNEGO\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 8 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"NTLM\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 4 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"NTLM_WB\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 15 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"SSL\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"libz\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 3 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"brotli\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 23 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"zstd\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 26 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"CharConv\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 12 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"TLS-SRP\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 14 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"HTTP2\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 16 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"HTTP3\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 25 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"UnixSockets\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 19 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"HTTPS-proxy\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 21 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"MultiSSL\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 22 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"PSL\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 20 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"alt-svc\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 24 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"HSTS\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 28 as libc::c_int,
        };
        init
    },
    {
        let mut init = feat {
            name: b"gsasl\0" as *const u8 as *const libc::c_char,
            bitmask: (1 as libc::c_int) << 29 as libc::c_int,
        };
        init
    },
];
unsafe extern "C" fn print_category(mut category: curlhelp_t) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while !(helptext[i as usize].opt).is_null() {
        if helptext[i as usize].categories & category != 0 {
            curl_mprintf(
                b" %-18s  %s\n\0" as *const u8 as *const libc::c_char,
                helptext[i as usize].opt,
                helptext[i as usize].desc,
            );
        }
        i = i.wrapping_add(1);
    }
}
unsafe extern "C" fn get_category_content(
    mut category: *const libc::c_char,
) -> libc::c_int {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while !(categories[i as usize].opt).is_null() {
        if curl_strequal(categories[i as usize].opt, category) != 0 {
            curl_mprintf(
                b"%s: %s\n\0" as *const u8 as *const libc::c_char,
                categories[i as usize].opt,
                categories[i as usize].desc,
            );
            print_category(categories[i as usize].category);
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn get_categories() {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while !(categories[i as usize].opt).is_null() {
        curl_mprintf(
            b" %-11s %s\n\0" as *const u8 as *const libc::c_char,
            categories[i as usize].opt,
            categories[i as usize].desc,
        );
        i = i.wrapping_add(1);
    }
}
#[no_mangle]
pub unsafe extern "C" fn tool_help(mut category: *mut libc::c_char) {
    puts(b"Usage: curl [options...] <url>\0" as *const u8 as *const libc::c_char);
    if category.is_null() {
        let mut category_note: *const libc::c_char = b"\nThis is not the full help, this menu is stripped into categories.\nUse \"--help category\" to get an overview of all categories.\nFor all options use the manual or \"--help all\".\0"
            as *const u8 as *const libc::c_char;
        print_category((1 as libc::c_uint) << 9 as libc::c_uint);
        puts(category_note);
    } else if curl_strequal(category, b"all\0" as *const u8 as *const libc::c_char) != 0
        {
        print_category(!((1 as libc::c_uint) << 0 as libc::c_uint));
    } else if curl_strequal(category, b"category\0" as *const u8 as *const libc::c_char)
            != 0
        {
        get_categories();
    } else if get_category_content(category) != 0 {
        puts(
            b"Invalid category provided, here is a list of all categories:\n\0"
                as *const u8 as *const libc::c_char,
        );
        get_categories();
    }
    free(category as *mut libc::c_void);
}
unsafe extern "C" fn featcomp(
    mut p1: *const libc::c_void,
    mut p2: *const libc::c_void,
) -> libc::c_int {
    return strcasecmp(
        *(p1 as *const *mut libc::c_char),
        *(p2 as *const *mut libc::c_char),
    );
}
#[no_mangle]
pub unsafe extern "C" fn tool_version_info() {
    let mut proto: *const *const libc::c_char = 0 as *const *const libc::c_char;
    curl_mprintf(
        b"curl 7.79.1 (x86_64-pc-linux-gnu) %s\n\0" as *const u8 as *const libc::c_char,
        curl_version(),
    );
    curl_mprintf(
        b"Release-Date: %s\n\0" as *const u8 as *const libc::c_char,
        b"2021-09-22\0" as *const u8 as *const libc::c_char,
    );
    if !((*curlinfo).protocols).is_null() {
        curl_mprintf(b"Protocols: \0" as *const u8 as *const libc::c_char);
        proto = (*curlinfo).protocols;
        while !(*proto).is_null() {
            curl_mprintf(b"%s \0" as *const u8 as *const libc::c_char, *proto);
            proto = proto.offset(1);
        }
        puts(b"\0" as *const u8 as *const libc::c_char);
    }
    if (*curlinfo).features != 0 {
        let mut featp: [*mut libc::c_char; 29] = [0 as *mut libc::c_char; 29];
        let mut numfeat: size_t = 0 as libc::c_int as size_t;
        let mut i: libc::c_uint = 0;
        curl_mprintf(b"Features:\0" as *const u8 as *const libc::c_char);
        i = 0 as libc::c_int as libc::c_uint;
        while (i as libc::c_ulong)
            < (::std::mem::size_of::<[feat; 28]>() as libc::c_ulong)
                .wrapping_div(::std::mem::size_of::<feat>() as libc::c_ulong)
        {
            if (*curlinfo).features & feats[i as usize].bitmask != 0 {
                let fresh0 = numfeat;
                numfeat = numfeat.wrapping_add(1);
                featp[fresh0 as usize] = feats[i as usize].name as *mut libc::c_char;
            }
            i = i.wrapping_add(1);
        }
        qsort(
            &mut *featp.as_mut_ptr().offset(0 as libc::c_int as isize)
                as *mut *mut libc::c_char as *mut libc::c_void,
            numfeat,
            ::std::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
            Some(
                featcomp
                    as unsafe extern "C" fn(
                        *const libc::c_void,
                        *const libc::c_void,
                    ) -> libc::c_int,
            ),
        );
        i = 0 as libc::c_int as libc::c_uint;
        while (i as libc::c_ulong) < numfeat {
            curl_mprintf(
                b" %s\0" as *const u8 as *const libc::c_char,
                featp[i as usize],
            );
            i = i.wrapping_add(1);
        }
        puts(b"\0" as *const u8 as *const libc::c_char);
    }
    if strcmp(b"7.79.1\0" as *const u8 as *const libc::c_char, (*curlinfo).version) != 0
    {
        curl_mprintf(
            b"WARNING: curl and libcurl versions do not match. Functionality may be affected.\n\0"
                as *const u8 as *const libc::c_char,
        );
    }
}
#[no_mangle]
pub unsafe extern "C" fn tool_list_engines() {
    let mut curl: *mut CURL = curl_easy_init();
    let mut engines: *mut curl_slist = 0 as *mut curl_slist;
    curl_easy_getinfo(curl, CURLINFO_SSL_ENGINES, &mut engines as *mut *mut curl_slist);
    puts(b"Build-time engines:\0" as *const u8 as *const libc::c_char);
    if !engines.is_null() {
        while !engines.is_null() {
            curl_mprintf(
                b"  %s\n\0" as *const u8 as *const libc::c_char,
                (*engines).data,
            );
            engines = (*engines).next;
        }
    } else {
        puts(b"  <none>\0" as *const u8 as *const libc::c_char);
    }
    curl_slist_free_all(engines);
    curl_easy_cleanup(curl);
}
