use :: libc;
extern "C" {
    static mut stdin: *mut crate::src::lib::http2::_IO_FILE;
    static mut stdout: *mut crate::src::lib::http2::_IO_FILE;
    fn fclose(__stream: *mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut crate::src::lib::http2::_IO_FILE;
    fn sscanf(_: *const i8, _: *const i8, _: ...) -> i32;
    fn time(__timer: *mut i64) -> i64;
    fn malloc(_: u64) -> *mut core::ffi::c_void;
    fn free(__ptr: *mut core::ffi::c_void);
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strncpy(_: *mut i8, _: *const i8, _: u64) -> *mut i8;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strncmp(_: *const i8, _: *const i8, _: u64) -> i32;
    fn strdup(_: *const i8) -> *mut i8;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strcspn(_: *const i8, _: *const i8) -> u64;
    fn strpbrk(_: *const i8, _: *const i8) -> *mut i8;
    fn strstr(_: *const i8, _: *const i8) -> *mut i8;
    fn strtok(_: *mut i8, _: *const i8) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
}
pub use crate::src::lib::curl_ctype::Curl_isdigit;
pub use crate::src::lib::escape::curl_easy_escape;
pub use crate::src::lib::escape::curl_free;
pub use crate::src::lib::http2::curl_mime;
pub use crate::src::lib::http2::Curl_easy;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::parsedate::curl_getdate;
pub use crate::src::lib::strcase::curl_strequal;
pub use crate::src::lib::strcase::curl_strnequal;
pub use crate::src::lib::strtoofft::curlx_strtoofft;
pub use crate::src::lib::warnless::curlx_uztoso;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_cfgable::config_init;
pub use crate::src::src::tool_filetime::getfiletime;
pub use crate::src::src::tool_formparse::formparse;
pub use crate::src::src::tool_helpers::param2text;
pub use crate::src::src::tool_helpers::SetHTTPrequest;
pub use crate::src::src::tool_libinfo::curlinfo;
pub use crate::src::src::tool_msgs::_IO_marker;
pub use crate::src::src::tool_msgs::errorf;
pub use crate::src::src::tool_msgs::helpf;
pub use crate::src::src::tool_msgs::warnf;
pub use crate::src::src::tool_paramhlp::add2list;
pub use crate::src::src::tool_paramhlp::check_protocol;
pub use crate::src::src::tool_paramhlp::cleanarg;
pub use crate::src::src::tool_paramhlp::delegation;
pub use crate::src::src::tool_paramhlp::file2memory;
pub use crate::src::src::tool_paramhlp::file2string;
pub use crate::src::src::tool_paramhlp::ftpcccmethod;
pub use crate::src::src::tool_paramhlp::ftpfilemethod;
pub use crate::src::src::tool_paramhlp::new_getout;
pub use crate::src::src::tool_paramhlp::oct2nummax;
pub use crate::src::src::tool_paramhlp::proto2num;
pub use crate::src::src::tool_paramhlp::str2num;
pub use crate::src::src::tool_paramhlp::str2offset;
pub use crate::src::src::tool_paramhlp::str2tls_max;
pub use crate::src::src::tool_paramhlp::str2udouble;
pub use crate::src::src::tool_paramhlp::str2unum;
pub use crate::src::src::tool_paramhlp::str2unummax;
pub use crate::src::src::tool_parsecfg::parseconfig;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __time_t = i64;
pub type time_t = i64;
pub type size_t = u64;
pub type curl_off_t = i64;
pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::lib::http2::_IO_FILE;
pub type CURL = crate::src::lib::http2::Curl_easy;
pub type curl_slist = crate::src::lib::http2::curl_slist;
pub type C2RustUnnamed = u32;
pub const CURLPROXY_SOCKS5_HOSTNAME: C2RustUnnamed = 7;
pub const CURLPROXY_SOCKS4A: C2RustUnnamed = 6;
pub const CURLPROXY_SOCKS5: C2RustUnnamed = 5;
pub const CURLPROXY_SOCKS4: C2RustUnnamed = 4;
pub const CURLPROXY_HTTPS: C2RustUnnamed = 2;
pub const CURLPROXY_HTTP_1_0: C2RustUnnamed = 1;
pub const CURLPROXY_HTTP: C2RustUnnamed = 0;
pub type C2RustUnnamed_0 = u32;
pub const CURLFTPSSL_CCC_LAST: C2RustUnnamed_0 = 3;
pub const CURLFTPSSL_CCC_ACTIVE: C2RustUnnamed_0 = 2;
pub const CURLFTPSSL_CCC_PASSIVE: C2RustUnnamed_0 = 1;
pub const CURLFTPSSL_CCC_NONE: C2RustUnnamed_0 = 0;
pub type C2RustUnnamed_1 = u32;
pub const CURL_HTTP_VERSION_LAST: C2RustUnnamed_1 = 31;
pub const CURL_HTTP_VERSION_3: C2RustUnnamed_1 = 30;
pub const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: C2RustUnnamed_1 = 5;
pub const CURL_HTTP_VERSION_2TLS: C2RustUnnamed_1 = 4;
pub const CURL_HTTP_VERSION_2_0: C2RustUnnamed_1 = 3;
pub const CURL_HTTP_VERSION_1_1: C2RustUnnamed_1 = 2;
pub const CURL_HTTP_VERSION_1_0: C2RustUnnamed_1 = 1;
pub const CURL_HTTP_VERSION_NONE: C2RustUnnamed_1 = 0;
pub type C2RustUnnamed_2 = u32;
pub const CURL_SSLVERSION_LAST: C2RustUnnamed_2 = 8;
pub const CURL_SSLVERSION_TLSv1_3: C2RustUnnamed_2 = 7;
pub const CURL_SSLVERSION_TLSv1_2: C2RustUnnamed_2 = 6;
pub const CURL_SSLVERSION_TLSv1_1: C2RustUnnamed_2 = 5;
pub const CURL_SSLVERSION_TLSv1_0: C2RustUnnamed_2 = 4;
pub const CURL_SSLVERSION_SSLv3: C2RustUnnamed_2 = 3;
pub const CURL_SSLVERSION_SSLv2: C2RustUnnamed_2 = 2;
pub const CURL_SSLVERSION_TLSv1: C2RustUnnamed_2 = 1;
pub const CURL_SSLVERSION_DEFAULT: C2RustUnnamed_2 = 0;
pub type curl_TimeCond = u32;
pub const CURL_TIMECOND_LAST: curl_TimeCond = 4;
pub const CURL_TIMECOND_LASTMOD: curl_TimeCond = 3;
pub const CURL_TIMECOND_IFUNMODSINCE: curl_TimeCond = 2;
pub const CURL_TIMECOND_IFMODSINCE: curl_TimeCond = 1;
pub const CURL_TIMECOND_NONE: curl_TimeCond = 0;
pub type CURLversion = u32;
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
pub type curl_version_info_data<'a> = crate::src::lib::version::curl_version_info_data<'a>;
pub type CURLofft = u32;
pub const CURL_OFFT_INVAL: CURLofft = 2;
pub const CURL_OFFT_FLOW: CURLofft = 1;
pub const CURL_OFFT_OK: CURLofft = 0;
pub type OperationConfig = crate::src::src::tool_cb_dbg::OperationConfig;
pub type State = crate::src::src::tool_cb_dbg::State;
pub type URLGlob = crate::src::src::tool_cb_dbg::URLGlob;
pub type URLPattern = crate::src::src::tool_cb_dbg::URLPattern;
pub type C2RustUnnamed_3 = crate::src::src::tool_cb_dbg::C2RustUnnamed;
pub type C2RustUnnamed_4 = crate::src::src::tool_cb_dbg::C2RustUnnamed_0;
pub type C2RustUnnamed_5 = crate::src::src::tool_cb_dbg::C2RustUnnamed_1;
pub type C2RustUnnamed_6 = crate::src::src::tool_cb_dbg::C2RustUnnamed_2;
pub type URLPatternType = u32;
pub const UPTNumRange: URLPatternType = 3;
pub const UPTCharRange: URLPatternType = 2;
pub const UPTSet: URLPatternType = 1;
pub type getout = crate::src::src::tool_cb_dbg::getout;
pub type GlobalConfig = crate::src::src::tool_cb_dbg::GlobalConfig;
pub type trace = u32;
pub const TRACE_PLAIN: trace = 3;
pub const TRACE_ASCII: trace = 2;
pub const TRACE_BIN: trace = 1;
pub const TRACE_NONE: trace = 0;
pub type curl_error = u32;
pub const ERR_LAST: curl_error = 2;
pub const ERR_BINARY_TERMINAL: curl_error = 1;
pub const ERR_NONE: curl_error = 0;
pub type HttpReq = u32;
pub const HTTPREQ_SIMPLEPOST: HttpReq = 4;
pub const HTTPREQ_MIMEPOST: HttpReq = 3;
pub const HTTPREQ_HEAD: HttpReq = 2;
pub const HTTPREQ_GET: HttpReq = 1;
pub const HTTPREQ_UNSPEC: HttpReq = 0;
pub type tool_mime = crate::src::src::tool_cb_dbg::tool_mime;
pub type toolmimekind = u32;
pub const TOOLMIME_STDINDATA: toolmimekind = 6;
pub const TOOLMIME_STDIN: toolmimekind = 5;
pub const TOOLMIME_FILEDATA: toolmimekind = 4;
pub const TOOLMIME_FILE: toolmimekind = 3;
pub const TOOLMIME_DATA: toolmimekind = 2;
pub const TOOLMIME_PARTS: toolmimekind = 1;
pub const TOOLMIME_NONE: toolmimekind = 0;
pub type ParameterError = u32;
pub const PARAM_LAST: ParameterError = 21;
pub const PARAM_CONTDISP_RESUME_FROM: ParameterError = 20;
pub const PARAM_CONTDISP_SHOW_HEADER: ParameterError = 19;
pub const PARAM_NO_NOT_BOOLEAN: ParameterError = 18;
pub const PARAM_NUMBER_TOO_LARGE: ParameterError = 17;
pub const PARAM_NO_PREFIX: ParameterError = 16;
pub const PARAM_NEXT_OPERATION: ParameterError = 15;
pub const PARAM_NO_MEM: ParameterError = 14;
pub const PARAM_LIBCURL_UNSUPPORTED_PROTOCOL: ParameterError = 13;
pub const PARAM_LIBCURL_DOESNT_SUPPORT: ParameterError = 12;
pub const PARAM_NEGATIVE_NUMERIC: ParameterError = 11;
pub const PARAM_BAD_NUMERIC: ParameterError = 10;
pub const PARAM_GOT_EXTRA_PARAMETER: ParameterError = 9;
pub const PARAM_ENGINES_REQUESTED: ParameterError = 8;
pub const PARAM_VERSION_INFO_REQUESTED: ParameterError = 7;
pub const PARAM_MANUAL_REQUESTED: ParameterError = 6;
pub const PARAM_HELP_REQUESTED: ParameterError = 5;
pub const PARAM_BAD_USE: ParameterError = 4;
pub const PARAM_REQUIRES_PARAMETER: ParameterError = 3;
pub const PARAM_OPTION_UNKNOWN: ParameterError = 2;
pub const PARAM_OPTION_AMBIGUOUS: ParameterError = 1;
pub const PARAM_OK: ParameterError = 0;
pub const ARG_NONE: C2RustUnnamed_7 = 0;
pub type C2RustUnnamed_7 = u32;
pub const ARG_FILENAME: C2RustUnnamed_7 = 3;
pub const ARG_STRING: C2RustUnnamed_7 = 2;
pub const ARG_BOOL: C2RustUnnamed_7 = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct LongShort {
    pub letter: *const i8,
    pub lname: *const i8,
    pub desc: u32,
}
impl LongShort {
    pub const fn new() -> Self {
        LongShort {
            letter: (0 as *const i8),
            lname: (0 as *const i8),
            desc: 0,
        }
    }
}
impl std::default::Default for LongShort {
    fn default() -> Self {
        LongShort::new()
    }
}
static mut aliases: [crate::src::src::tool_getparam::LongShort; 248] = [
    {
        let mut init = LongShort {
            letter: b"*@\0" as *const u8 as *const i8,
            lname: b"url\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*4\0" as *const u8 as *const i8,
            lname: b"dns-ipv4-addr\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*6\0" as *const u8 as *const i8,
            lname: b"dns-ipv6-addr\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*a\0" as *const u8 as *const i8,
            lname: b"random-file\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*b\0" as *const u8 as *const i8,
            lname: b"egd-file\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*B\0" as *const u8 as *const i8,
            lname: b"oauth2-bearer\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*c\0" as *const u8 as *const i8,
            lname: b"connect-timeout\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*C\0" as *const u8 as *const i8,
            lname: b"doh-url\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*d\0" as *const u8 as *const i8,
            lname: b"ciphers\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*D\0" as *const u8 as *const i8,
            lname: b"dns-interface\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*e\0" as *const u8 as *const i8,
            lname: b"disable-epsv\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*f\0" as *const u8 as *const i8,
            lname: b"disallow-username-in-url\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*E\0" as *const u8 as *const i8,
            lname: b"epsv\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*F\0" as *const u8 as *const i8,
            lname: b"dns-servers\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*g\0" as *const u8 as *const i8,
            lname: b"trace\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*G\0" as *const u8 as *const i8,
            lname: b"npn\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*h\0" as *const u8 as *const i8,
            lname: b"trace-ascii\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*H\0" as *const u8 as *const i8,
            lname: b"alpn\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*i\0" as *const u8 as *const i8,
            lname: b"limit-rate\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*j\0" as *const u8 as *const i8,
            lname: b"compressed\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*J\0" as *const u8 as *const i8,
            lname: b"tr-encoding\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*k\0" as *const u8 as *const i8,
            lname: b"digest\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*l\0" as *const u8 as *const i8,
            lname: b"negotiate\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*m\0" as *const u8 as *const i8,
            lname: b"ntlm\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*M\0" as *const u8 as *const i8,
            lname: b"ntlm-wb\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*n\0" as *const u8 as *const i8,
            lname: b"basic\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*o\0" as *const u8 as *const i8,
            lname: b"anyauth\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*q\0" as *const u8 as *const i8,
            lname: b"ftp-create-dirs\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*r\0" as *const u8 as *const i8,
            lname: b"create-dirs\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*R\0" as *const u8 as *const i8,
            lname: b"create-file-mode\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*s\0" as *const u8 as *const i8,
            lname: b"max-redirs\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*t\0" as *const u8 as *const i8,
            lname: b"proxy-ntlm\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*u\0" as *const u8 as *const i8,
            lname: b"crlf\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*v\0" as *const u8 as *const i8,
            lname: b"stderr\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*V\0" as *const u8 as *const i8,
            lname: b"aws-sigv4\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*w\0" as *const u8 as *const i8,
            lname: b"interface\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*x\0" as *const u8 as *const i8,
            lname: b"krb\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*x\0" as *const u8 as *const i8,
            lname: b"krb4\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*X\0" as *const u8 as *const i8,
            lname: b"haproxy-protocol\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*y\0" as *const u8 as *const i8,
            lname: b"max-filesize\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*z\0" as *const u8 as *const i8,
            lname: b"disable-eprt\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*Z\0" as *const u8 as *const i8,
            lname: b"eprt\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"*~\0" as *const u8 as *const i8,
            lname: b"xattr\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$a\0" as *const u8 as *const i8,
            lname: b"ftp-ssl\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$a\0" as *const u8 as *const i8,
            lname: b"ssl\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$b\0" as *const u8 as *const i8,
            lname: b"ftp-pasv\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$c\0" as *const u8 as *const i8,
            lname: b"socks5\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$d\0" as *const u8 as *const i8,
            lname: b"tcp-nodelay\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$e\0" as *const u8 as *const i8,
            lname: b"proxy-digest\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$f\0" as *const u8 as *const i8,
            lname: b"proxy-basic\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$g\0" as *const u8 as *const i8,
            lname: b"retry\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$V\0" as *const u8 as *const i8,
            lname: b"retry-connrefused\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$h\0" as *const u8 as *const i8,
            lname: b"retry-delay\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$i\0" as *const u8 as *const i8,
            lname: b"retry-max-time\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$k\0" as *const u8 as *const i8,
            lname: b"proxy-negotiate\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$m\0" as *const u8 as *const i8,
            lname: b"ftp-account\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$n\0" as *const u8 as *const i8,
            lname: b"proxy-anyauth\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$o\0" as *const u8 as *const i8,
            lname: b"trace-time\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$p\0" as *const u8 as *const i8,
            lname: b"ignore-content-length\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$q\0" as *const u8 as *const i8,
            lname: b"ftp-skip-pasv-ip\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$r\0" as *const u8 as *const i8,
            lname: b"ftp-method\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$s\0" as *const u8 as *const i8,
            lname: b"local-port\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$t\0" as *const u8 as *const i8,
            lname: b"socks4\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$T\0" as *const u8 as *const i8,
            lname: b"socks4a\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$u\0" as *const u8 as *const i8,
            lname: b"ftp-alternative-to-user\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$v\0" as *const u8 as *const i8,
            lname: b"ftp-ssl-reqd\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$v\0" as *const u8 as *const i8,
            lname: b"ssl-reqd\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$w\0" as *const u8 as *const i8,
            lname: b"sessionid\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$x\0" as *const u8 as *const i8,
            lname: b"ftp-ssl-control\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$y\0" as *const u8 as *const i8,
            lname: b"ftp-ssl-ccc\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$j\0" as *const u8 as *const i8,
            lname: b"ftp-ssl-ccc-mode\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$z\0" as *const u8 as *const i8,
            lname: b"libcurl\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$#\0" as *const u8 as *const i8,
            lname: b"raw\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$0\0" as *const u8 as *const i8,
            lname: b"post301\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$1\0" as *const u8 as *const i8,
            lname: b"keepalive\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$2\0" as *const u8 as *const i8,
            lname: b"socks5-hostname\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$3\0" as *const u8 as *const i8,
            lname: b"keepalive-time\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$4\0" as *const u8 as *const i8,
            lname: b"post302\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$5\0" as *const u8 as *const i8,
            lname: b"noproxy\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$7\0" as *const u8 as *const i8,
            lname: b"socks5-gssapi-nec\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$8\0" as *const u8 as *const i8,
            lname: b"proxy1.0\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$9\0" as *const u8 as *const i8,
            lname: b"tftp-blksize\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$A\0" as *const u8 as *const i8,
            lname: b"mail-from\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$B\0" as *const u8 as *const i8,
            lname: b"mail-rcpt\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$C\0" as *const u8 as *const i8,
            lname: b"ftp-pret\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$D\0" as *const u8 as *const i8,
            lname: b"proto\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$E\0" as *const u8 as *const i8,
            lname: b"proto-redir\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$F\0" as *const u8 as *const i8,
            lname: b"resolve\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$G\0" as *const u8 as *const i8,
            lname: b"delegation\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$H\0" as *const u8 as *const i8,
            lname: b"mail-auth\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$I\0" as *const u8 as *const i8,
            lname: b"post303\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$J\0" as *const u8 as *const i8,
            lname: b"metalink\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$6\0" as *const u8 as *const i8,
            lname: b"sasl-authzid\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$K\0" as *const u8 as *const i8,
            lname: b"sasl-ir\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$L\0" as *const u8 as *const i8,
            lname: b"test-event\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$M\0" as *const u8 as *const i8,
            lname: b"unix-socket\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$N\0" as *const u8 as *const i8,
            lname: b"path-as-is\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$O\0" as *const u8 as *const i8,
            lname: b"socks5-gssapi-service\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$O\0" as *const u8 as *const i8,
            lname: b"proxy-service-name\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$P\0" as *const u8 as *const i8,
            lname: b"service-name\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$Q\0" as *const u8 as *const i8,
            lname: b"proto-default\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$R\0" as *const u8 as *const i8,
            lname: b"expect100-timeout\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$S\0" as *const u8 as *const i8,
            lname: b"tftp-no-options\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$U\0" as *const u8 as *const i8,
            lname: b"connect-to\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$W\0" as *const u8 as *const i8,
            lname: b"abstract-unix-socket\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$X\0" as *const u8 as *const i8,
            lname: b"tls-max\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$Y\0" as *const u8 as *const i8,
            lname: b"suppress-connect-headers\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$Z\0" as *const u8 as *const i8,
            lname: b"compressed-ssh\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$~\0" as *const u8 as *const i8,
            lname: b"happy-eyeballs-timeout-ms\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"$!\0" as *const u8 as *const i8,
            lname: b"retry-all-errors\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"0\0" as *const u8 as *const i8,
            lname: b"http1.0\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"01\0" as *const u8 as *const i8,
            lname: b"http1.1\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"02\0" as *const u8 as *const i8,
            lname: b"http2\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"03\0" as *const u8 as *const i8,
            lname: b"http2-prior-knowledge\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"04\0" as *const u8 as *const i8,
            lname: b"http3\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"09\0" as *const u8 as *const i8,
            lname: b"http0.9\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"1\0" as *const u8 as *const i8,
            lname: b"tlsv1\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"10\0" as *const u8 as *const i8,
            lname: b"tlsv1.0\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"11\0" as *const u8 as *const i8,
            lname: b"tlsv1.1\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"12\0" as *const u8 as *const i8,
            lname: b"tlsv1.2\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"13\0" as *const u8 as *const i8,
            lname: b"tlsv1.3\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"1A\0" as *const u8 as *const i8,
            lname: b"tls13-ciphers\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"1B\0" as *const u8 as *const i8,
            lname: b"proxy-tls13-ciphers\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"2\0" as *const u8 as *const i8,
            lname: b"sslv2\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"3\0" as *const u8 as *const i8,
            lname: b"sslv3\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"4\0" as *const u8 as *const i8,
            lname: b"ipv4\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"6\0" as *const u8 as *const i8,
            lname: b"ipv6\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"a\0" as *const u8 as *const i8,
            lname: b"append\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"A\0" as *const u8 as *const i8,
            lname: b"user-agent\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"b\0" as *const u8 as *const i8,
            lname: b"cookie\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"ba\0" as *const u8 as *const i8,
            lname: b"alt-svc\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"bb\0" as *const u8 as *const i8,
            lname: b"hsts\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"B\0" as *const u8 as *const i8,
            lname: b"use-ascii\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"c\0" as *const u8 as *const i8,
            lname: b"cookie-jar\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"C\0" as *const u8 as *const i8,
            lname: b"continue-at\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"d\0" as *const u8 as *const i8,
            lname: b"data\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"dr\0" as *const u8 as *const i8,
            lname: b"data-raw\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"da\0" as *const u8 as *const i8,
            lname: b"data-ascii\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"db\0" as *const u8 as *const i8,
            lname: b"data-binary\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"de\0" as *const u8 as *const i8,
            lname: b"data-urlencode\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"D\0" as *const u8 as *const i8,
            lname: b"dump-header\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"e\0" as *const u8 as *const i8,
            lname: b"referer\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E\0" as *const u8 as *const i8,
            lname: b"cert\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ea\0" as *const u8 as *const i8,
            lname: b"cacert\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Eb\0" as *const u8 as *const i8,
            lname: b"cert-type\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ec\0" as *const u8 as *const i8,
            lname: b"key\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ed\0" as *const u8 as *const i8,
            lname: b"key-type\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ee\0" as *const u8 as *const i8,
            lname: b"pass\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ef\0" as *const u8 as *const i8,
            lname: b"engine\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Eg\0" as *const u8 as *const i8,
            lname: b"capath\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Eh\0" as *const u8 as *const i8,
            lname: b"pubkey\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ei\0" as *const u8 as *const i8,
            lname: b"hostpubmd5\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ej\0" as *const u8 as *const i8,
            lname: b"crlfile\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ek\0" as *const u8 as *const i8,
            lname: b"tlsuser\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"El\0" as *const u8 as *const i8,
            lname: b"tlspassword\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Em\0" as *const u8 as *const i8,
            lname: b"tlsauthtype\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"En\0" as *const u8 as *const i8,
            lname: b"ssl-allow-beast\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Eo\0" as *const u8 as *const i8,
            lname: b"ssl-auto-client-cert\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"EO\0" as *const u8 as *const i8,
            lname: b"proxy-ssl-auto-client-cert\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ep\0" as *const u8 as *const i8,
            lname: b"pinnedpubkey\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"EP\0" as *const u8 as *const i8,
            lname: b"proxy-pinnedpubkey\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Eq\0" as *const u8 as *const i8,
            lname: b"cert-status\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"EQ\0" as *const u8 as *const i8,
            lname: b"doh-cert-status\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Er\0" as *const u8 as *const i8,
            lname: b"false-start\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Es\0" as *const u8 as *const i8,
            lname: b"ssl-no-revoke\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"ES\0" as *const u8 as *const i8,
            lname: b"ssl-revoke-best-effort\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Et\0" as *const u8 as *const i8,
            lname: b"tcp-fastopen\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Eu\0" as *const u8 as *const i8,
            lname: b"proxy-tlsuser\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ev\0" as *const u8 as *const i8,
            lname: b"proxy-tlspassword\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ew\0" as *const u8 as *const i8,
            lname: b"proxy-tlsauthtype\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ex\0" as *const u8 as *const i8,
            lname: b"proxy-cert\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ey\0" as *const u8 as *const i8,
            lname: b"proxy-cert-type\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ez\0" as *const u8 as *const i8,
            lname: b"proxy-key\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E0\0" as *const u8 as *const i8,
            lname: b"proxy-key-type\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E1\0" as *const u8 as *const i8,
            lname: b"proxy-pass\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E2\0" as *const u8 as *const i8,
            lname: b"proxy-ciphers\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E3\0" as *const u8 as *const i8,
            lname: b"proxy-crlfile\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E4\0" as *const u8 as *const i8,
            lname: b"proxy-ssl-allow-beast\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E5\0" as *const u8 as *const i8,
            lname: b"login-options\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E6\0" as *const u8 as *const i8,
            lname: b"proxy-cacert\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E7\0" as *const u8 as *const i8,
            lname: b"proxy-capath\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E8\0" as *const u8 as *const i8,
            lname: b"proxy-insecure\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"E9\0" as *const u8 as *const i8,
            lname: b"proxy-tlsv1\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"EA\0" as *const u8 as *const i8,
            lname: b"socks5-basic\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"EB\0" as *const u8 as *const i8,
            lname: b"socks5-gssapi\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"EC\0" as *const u8 as *const i8,
            lname: b"etag-save\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"ED\0" as *const u8 as *const i8,
            lname: b"etag-compare\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"EE\0" as *const u8 as *const i8,
            lname: b"curves\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"f\0" as *const u8 as *const i8,
            lname: b"fail\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"fa\0" as *const u8 as *const i8,
            lname: b"fail-early\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"fb\0" as *const u8 as *const i8,
            lname: b"styled-output\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"fc\0" as *const u8 as *const i8,
            lname: b"mail-rcpt-allowfails\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"fd\0" as *const u8 as *const i8,
            lname: b"fail-with-body\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"F\0" as *const u8 as *const i8,
            lname: b"form\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Fs\0" as *const u8 as *const i8,
            lname: b"form-string\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"g\0" as *const u8 as *const i8,
            lname: b"globoff\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"G\0" as *const u8 as *const i8,
            lname: b"get\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ga\0" as *const u8 as *const i8,
            lname: b"request-target\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"h\0" as *const u8 as *const i8,
            lname: b"help\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"H\0" as *const u8 as *const i8,
            lname: b"header\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Hp\0" as *const u8 as *const i8,
            lname: b"proxy-header\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"i\0" as *const u8 as *const i8,
            lname: b"include\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"I\0" as *const u8 as *const i8,
            lname: b"head\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"j\0" as *const u8 as *const i8,
            lname: b"junk-session-cookies\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"J\0" as *const u8 as *const i8,
            lname: b"remote-header-name\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"k\0" as *const u8 as *const i8,
            lname: b"insecure\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"kd\0" as *const u8 as *const i8,
            lname: b"doh-insecure\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"K\0" as *const u8 as *const i8,
            lname: b"config\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"l\0" as *const u8 as *const i8,
            lname: b"list-only\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"L\0" as *const u8 as *const i8,
            lname: b"location\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Lt\0" as *const u8 as *const i8,
            lname: b"location-trusted\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"m\0" as *const u8 as *const i8,
            lname: b"max-time\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"M\0" as *const u8 as *const i8,
            lname: b"manual\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"n\0" as *const u8 as *const i8,
            lname: b"netrc\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"no\0" as *const u8 as *const i8,
            lname: b"netrc-optional\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"ne\0" as *const u8 as *const i8,
            lname: b"netrc-file\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"N\0" as *const u8 as *const i8,
            lname: b"buffer\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"o\0" as *const u8 as *const i8,
            lname: b"output\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"O\0" as *const u8 as *const i8,
            lname: b"remote-name\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Oa\0" as *const u8 as *const i8,
            lname: b"remote-name-all\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Ob\0" as *const u8 as *const i8,
            lname: b"output-dir\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"p\0" as *const u8 as *const i8,
            lname: b"proxytunnel\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"P\0" as *const u8 as *const i8,
            lname: b"ftp-port\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"q\0" as *const u8 as *const i8,
            lname: b"disable\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Q\0" as *const u8 as *const i8,
            lname: b"quote\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"r\0" as *const u8 as *const i8,
            lname: b"range\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"R\0" as *const u8 as *const i8,
            lname: b"remote-time\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"s\0" as *const u8 as *const i8,
            lname: b"silent\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"S\0" as *const u8 as *const i8,
            lname: b"show-error\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"t\0" as *const u8 as *const i8,
            lname: b"telnet-option\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"T\0" as *const u8 as *const i8,
            lname: b"upload-file\0" as *const u8 as *const i8,
            desc: ARG_FILENAME,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"u\0" as *const u8 as *const i8,
            lname: b"user\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"U\0" as *const u8 as *const i8,
            lname: b"proxy-user\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"v\0" as *const u8 as *const i8,
            lname: b"verbose\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"V\0" as *const u8 as *const i8,
            lname: b"version\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"w\0" as *const u8 as *const i8,
            lname: b"write-out\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"x\0" as *const u8 as *const i8,
            lname: b"proxy\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"xa\0" as *const u8 as *const i8,
            lname: b"preproxy\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"X\0" as *const u8 as *const i8,
            lname: b"request\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Y\0" as *const u8 as *const i8,
            lname: b"speed-limit\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"y\0" as *const u8 as *const i8,
            lname: b"speed-time\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"z\0" as *const u8 as *const i8,
            lname: b"time-cond\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Z\0" as *const u8 as *const i8,
            lname: b"parallel\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Zb\0" as *const u8 as *const i8,
            lname: b"parallel-max\0" as *const u8 as *const i8,
            desc: ARG_STRING,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"Zc\0" as *const u8 as *const i8,
            lname: b"parallel-immediate\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"#\0" as *const u8 as *const i8,
            lname: b"progress-bar\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b"#m\0" as *const u8 as *const i8,
            lname: b"progress-meter\0" as *const u8 as *const i8,
            desc: ARG_BOOL,
        };
        init
    },
    {
        let mut init = LongShort {
            letter: b":\0" as *const u8 as *const i8,
            lname: b"next\0" as *const u8 as *const i8,
            desc: ARG_NONE,
        };
        init
    },
];
extern "C" fn parse_cert_parameter<'a1, 'a2>(
    mut cert_parameter: *const i8,
    mut certname: Option<&'a1 mut *mut i8>,
    mut passphrase: Option<&'a2 mut *mut i8>,
) {
    let mut param_length: u64 = unsafe { strlen(cert_parameter) };
    let mut span: u64 = 0;
    let mut param_place: *const i8 = 0 as *const i8;
    let mut certname_place: *mut i8 = 0 as *mut i8;
    *(borrow_mut(&mut certname)).unwrap() = 0 as *mut i8;
    *(borrow_mut(&mut passphrase)).unwrap() = 0 as *mut i8;
    if param_length == 0 as i32 as u64 {
        return;
    }
    if curl_strnequal(
        cert_parameter,
        b"pkcs11:\0" as *const u8 as *const i8,
        7 as i32 as size_t,
    ) != 0
        || (unsafe { strpbrk(cert_parameter, b":\\\0" as *const u8 as *const i8) }).is_null()
    {
        *(borrow_mut(&mut certname)).unwrap() = unsafe { strdup(cert_parameter) };
        return;
    }
    certname_place = (unsafe { malloc(param_length.wrapping_add(1 as i32 as u64)) }) as *mut i8;
    if certname_place.is_null() {
        return;
    }
    *(borrow_mut(&mut certname)).unwrap() = certname_place;
    param_place = cert_parameter;
    while (unsafe { *param_place }) != 0 {
        span = unsafe { strcspn(param_place, b":\\\0" as *const u8 as *const i8) };
        (unsafe { strncpy(certname_place, param_place, span) });
        param_place = unsafe { param_place.offset(span as isize) };
        certname_place = unsafe { certname_place.offset(span as isize) };
        match (unsafe { *param_place }) as i32 {
            92 => {
                param_place = unsafe { param_place.offset(1) };
                match (unsafe { *param_place }) as i32 {
                    0 => {
                        let mut fresh0 = certname_place;
                        certname_place = unsafe { certname_place.offset(1) };
                        (unsafe { *fresh0 = '\\' as i32 as i8 });
                    }
                    92 => {
                        let mut fresh1 = certname_place;
                        certname_place = unsafe { certname_place.offset(1) };
                        (unsafe { *fresh1 = '\\' as i32 as i8 });
                        param_place = unsafe { param_place.offset(1) };
                    }
                    58 => {
                        let mut fresh2 = certname_place;
                        certname_place = unsafe { certname_place.offset(1) };
                        (unsafe { *fresh2 = ':' as i32 as i8 });
                        param_place = unsafe { param_place.offset(1) };
                    }
                    _ => {
                        let mut fresh3 = certname_place;
                        certname_place = unsafe { certname_place.offset(1) };
                        (unsafe { *fresh3 = '\\' as i32 as i8 });
                        let mut fresh4 = certname_place;
                        certname_place = unsafe { certname_place.offset(1) };
                        (unsafe { *fresh4 = *param_place });
                        param_place = unsafe { param_place.offset(1) };
                    }
                }
            }
            58 => {
                param_place = unsafe { param_place.offset(1) };
                if (unsafe { *param_place }) != 0 {
                    *(borrow_mut(&mut passphrase)).unwrap() = unsafe { strdup(param_place) };
                }
                break;
            }
            0 | _ => {}
        }
    }
    (unsafe { *certname_place = '\u{0}' as i32 as i8 });
}
extern "C" fn replace_url_encoded_space_by_plus(mut url: *mut i8) -> u64 {
    let mut orig_len: u64 = unsafe { strlen(url) };
    let mut orig_index: u64 = 0 as i32 as size_t;
    let mut new_index: u64 = 0 as i32 as size_t;
    while orig_index < orig_len {
        if (unsafe { *url.offset(orig_index as isize) }) as i32 == '%' as i32
            && (unsafe { *url.offset(orig_index.wrapping_add(1 as i32 as u64) as isize) }) as i32 == '2' as i32
            && (unsafe { *url.offset(orig_index.wrapping_add(2 as i32 as u64) as isize) }) as i32 == '0' as i32
        {
            (unsafe { *url.offset(new_index as isize) = '+' as i32 as i8 });
            orig_index = (orig_index as u64).wrapping_add(3 as i32 as u64) as size_t as size_t;
        } else {
            if new_index != orig_index {
                (unsafe { *url.offset(new_index as isize) = *url.offset(orig_index as isize) });
            }
            orig_index = orig_index.wrapping_add(1);
        }
        new_index = new_index.wrapping_add(1);
    }
    (unsafe { *url.offset(new_index as isize) = 0 as i32 as i8 });
    return new_index;
}
extern "C" fn GetFileAndPassword<'a1, 'a2>(
    mut nextarg: *mut i8,
    mut file: Option<&'a1 mut *mut i8>,
    mut password: Option<&'a2 mut *mut i8>,
) {
    let mut certname: *mut i8 = 0 as *mut i8;
    let mut passphrase: *mut i8 = 0 as *mut i8;
    parse_cert_parameter(nextarg, Some(&mut certname), Some(&mut passphrase));
    (unsafe { free(*(borrow_mut(&mut file)).unwrap() as *mut libc::c_void) });
    *(borrow_mut(&mut file)).unwrap() = 0 as *mut i8;
    *(borrow_mut(&mut file)).unwrap() = certname;
    if !passphrase.is_null() {
        (unsafe { free(*(borrow_mut(&mut password)).unwrap() as *mut libc::c_void) });
        *(borrow_mut(&mut password)).unwrap() = 0 as *mut i8;
        *(borrow_mut(&mut password)).unwrap() = passphrase;
    }
    cleanarg(nextarg);
}
extern "C" fn GetSizeParameter<'a1>(
    mut global: *mut crate::src::src::tool_cb_dbg::GlobalConfig,
    mut arg: *const i8,
    mut which: *const i8,
    mut value_out: Option<&'a1 mut i64>,
) -> u32 {
    let mut unit: *mut i8 = 0 as *mut i8;
    let mut value: i64 = 0;
    if curlx_strtoofft(arg, Some(&mut unit), 0 as i32, Some(&mut value)) as u64 != 0 {
        (unsafe { warnf(
            global,
            b"invalid number specified for %s\n\0" as *const u8 as *const i8,
            which,
        ) });
        return PARAM_BAD_USE;
    }
    if (unsafe { *unit }) == 0 {
        unit = b"b\0" as *const u8 as *const i8 as *mut i8;
    } else if (unsafe { strlen(unit) }) > 1 as i32 as u64 {
        unit = b"w\0" as *const u8 as *const i8 as *mut i8;
    }
    match (unsafe { *unit }) as i32 {
        71 | 103 => {
            if value > 0x7fffffffffffffff as i64 / (1024 as i32 * 1024 as i32 * 1024 as i32) as i64
            {
                return PARAM_NUMBER_TOO_LARGE;
            }
            value *= (1024 as i32 * 1024 as i32 * 1024 as i32) as i64;
        }
        77 | 109 => {
            if value > 0x7fffffffffffffff as i64 / (1024 as i32 * 1024 as i32) as i64 {
                return PARAM_NUMBER_TOO_LARGE;
            }
            value *= (1024 as i32 * 1024 as i32) as i64;
        }
        75 | 107 => {
            if value > 0x7fffffffffffffff as i64 / 1024 as i32 as i64 {
                return PARAM_NUMBER_TOO_LARGE;
            }
            value *= 1024 as i32 as i64;
        }
        98 | 66 => {}
        _ => {
            (unsafe { warnf(
                global,
                b"unsupported %s unit. Use G, M, K or B!\n\0" as *const u8 as *const i8,
                which,
            ) });
            return PARAM_BAD_USE;
        }
    }
    *(borrow_mut(&mut value_out)).unwrap() = value;
    return PARAM_OK;
}
#[no_mangle]
pub extern "C" fn getparameter<'a1>(
    mut flag: *const i8,
    mut nextarg: *mut i8,
    mut usedarg: Option<&'a1 mut bool>,
    mut global: *mut crate::src::src::tool_cb_dbg::GlobalConfig,
    mut config: *mut crate::src::src::tool_cb_dbg::OperationConfig,
) -> u32 {
    let mut letter: i8 = 0;
    let mut subletter: i8 = '\u{0}' as i32 as i8;
    let mut rc: i32 = 0;
    let mut parse: *const i8 = 0 as *const i8;
    let mut j: u32 = 0;
    let mut now: i64 = 0;
    let mut hit: i32 = -(1 as i32);
    let mut longopt: bool = 0 as i32 != 0;
    let mut singleopt: bool = 0 as i32 != 0;
    let mut err: u32 = PARAM_OK;
    let mut toggle: bool = 1 as i32 != 0;
    *(borrow_mut(&mut usedarg)).unwrap() = 0 as i32 != 0;
    if '-' as i32 != (unsafe { *flag.offset(0 as i32 as isize) }) as i32
        || '-' as i32 == (unsafe { *flag.offset(1 as i32 as isize) }) as i32
    {
        let mut word: *const i8 = if '-' as i32 == (unsafe { *flag.offset(0 as i32 as isize) }) as i32 {
            unsafe { flag.offset(2 as i32 as isize) }
        } else {
            flag
        };
        let mut fnam: u64 = unsafe { strlen(word) };
        let mut numhits: i32 = 0 as i32;
        let mut noflagged: bool = 0 as i32 != 0;
        if (unsafe { strncmp(word, b"no-\0" as *const u8 as *const i8, 3 as i32 as u64) }) == 0 {
            word = unsafe { word.offset(3 as i32 as isize) };
            toggle = 0 as i32 != 0;
            noflagged = 1 as i32 != 0;
        }
        j = 0 as i32 as u32;
        while (j as u64)
            < (::std::mem::size_of::<[LongShort; 248]>() as u64)
                .wrapping_div(::std::mem::size_of::<LongShort>() as u64)
        {
            if curl_strnequal(unsafe { aliases[j as usize].lname }, word, fnam) != 0 {
                longopt = 1 as i32 != 0;
                numhits += 1;
                if curl_strequal(unsafe { aliases[j as usize].lname }, word) != 0 {
                    parse = unsafe { aliases[j as usize].letter };
                    hit = j as i32;
                    numhits = 1 as i32;
                    break;
                } else {
                    parse = unsafe { aliases[j as usize].letter };
                    hit = j as i32;
                }
            }
            j = j.wrapping_add(1);
        }
        if numhits > 1 as i32 {
            return PARAM_OPTION_AMBIGUOUS;
        }
        if hit < 0 as i32 {
            return PARAM_OPTION_UNKNOWN;
        }
        if noflagged as i32 != 0 && (unsafe { aliases[hit as usize].desc }) as u32 != ARG_BOOL as i32 as u32 {
            return PARAM_NO_NOT_BOOLEAN;
        }
    } else {
        flag = unsafe { flag.offset(1) };
        hit = -(1 as i32);
        parse = flag;
    }
    loop {
        if !longopt {
            letter = unsafe { *parse };
            subletter = '\u{0}' as i32 as i8;
        } else {
            letter = unsafe { *parse.offset(0 as i32 as isize) };
            subletter = unsafe { *parse.offset(1 as i32 as isize) };
        }
        if hit < 0 as i32 {
            j = 0 as i32 as u32;
            while (j as u64)
                < (::std::mem::size_of::<[LongShort; 248]>() as u64)
                    .wrapping_div(::std::mem::size_of::<LongShort>() as u64)
            {
                if letter as i32 == (unsafe { *(aliases[j as usize].letter).offset(0 as i32 as isize) }) as i32 {
                    hit = j as i32;
                    break;
                } else {
                    j = j.wrapping_add(1);
                }
            }
            if hit < 0 as i32 {
                return PARAM_OPTION_UNKNOWN;
            }
        }
        if (unsafe { aliases[hit as usize].desc }) as u32 >= ARG_STRING as i32 as u32 {
            if !longopt && (unsafe { *parse.offset(1 as i32 as isize) }) as i32 != 0 {
                nextarg = (unsafe { &*parse.offset(1 as i32 as isize) }) as *const i8 as *mut i8;
                singleopt = 1 as i32 != 0;
            } else if nextarg.is_null() {
                return PARAM_REQUIRES_PARAMETER;
            } else {
                *(borrow_mut(&mut usedarg)).unwrap() = 1 as i32 != 0;
            }
            if (unsafe { aliases[hit as usize].desc }) as u32 == ARG_FILENAME as i32 as u32
                && (unsafe { *nextarg.offset(0 as i32 as isize) }) as i32 == '-' as i32
                && (unsafe { *nextarg.offset(1 as i32 as isize) }) as i32 != 0
            {
                (unsafe { warnf(
                    global,
                    b"The file name argument '%s' looks like a flag.\n\0" as *const u8 as *const i8,
                    nextarg,
                ) });
            }
        } else if (unsafe { aliases[hit as usize].desc }) as u32 == ARG_NONE as i32 as u32 && !toggle {
            return PARAM_NO_PREFIX;
        }
        let mut current_block_1664: u64;
        match letter as i32 {
            42 => {
                match subletter as i32 {
                    52 => {
                        if !(unsafe { (*config).dns_ipv4_addr }).is_null() {
                            (unsafe { free((*config).dns_ipv4_addr as *mut libc::c_void) });
                            let mut fresh5 = unsafe { &mut ((*config).dns_ipv4_addr) };
                            *fresh5 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh6 = unsafe { &mut ((*config).dns_ipv4_addr) };
                            *fresh6 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).dns_ipv4_addr }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    54 => {
                        if !(unsafe { (*config).dns_ipv6_addr }).is_null() {
                            (unsafe { free((*config).dns_ipv6_addr as *mut libc::c_void) });
                            let mut fresh7 = unsafe { &mut ((*config).dns_ipv6_addr) };
                            *fresh7 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh8 = unsafe { &mut ((*config).dns_ipv6_addr) };
                            *fresh8 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).dns_ipv6_addr }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    97 => {
                        if !(unsafe { (*config).random_file }).is_null() {
                            (unsafe { free((*config).random_file as *mut libc::c_void) });
                            let mut fresh9 = unsafe { &mut ((*config).random_file) };
                            *fresh9 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh10 = unsafe { &mut ((*config).random_file) };
                            *fresh10 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).random_file }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    98 => {
                        if !(unsafe { (*config).egd_file }).is_null() {
                            (unsafe { free((*config).egd_file as *mut libc::c_void) });
                            let mut fresh11 = unsafe { &mut ((*config).egd_file) };
                            *fresh11 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh12 = unsafe { &mut ((*config).egd_file) };
                            *fresh12 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).egd_file }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    66 => {
                        if !(unsafe { (*config).oauth_bearer }).is_null() {
                            (unsafe { free((*config).oauth_bearer as *mut libc::c_void) });
                            let mut fresh13 = unsafe { &mut ((*config).oauth_bearer) };
                            *fresh13 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh14 = unsafe { &mut ((*config).oauth_bearer) };
                            *fresh14 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).oauth_bearer }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        (unsafe { (*config).authtype |= (1 as i32 as u64) << 6 as i32 });
                    }
                    99 => {
                        err = str2udouble(
                            Some(unsafe { &mut (*config).connecttimeout }),
                            nextarg,
                            9223372036854775807 as i64 / 1000 as i32 as i64,
                        );
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    67 => {
                        if !(unsafe { (*config).doh_url }).is_null() {
                            (unsafe { free((*config).doh_url as *mut libc::c_void) });
                            let mut fresh15 = unsafe { &mut ((*config).doh_url) };
                            *fresh15 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh16 = unsafe { &mut ((*config).doh_url) };
                            *fresh16 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).doh_url }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    100 => {
                        if !(unsafe { (*config).cipher_list }).is_null() {
                            (unsafe { free((*config).cipher_list as *mut libc::c_void) });
                            let mut fresh17 = unsafe { &mut ((*config).cipher_list) };
                            *fresh17 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh18 = unsafe { &mut ((*config).cipher_list) };
                            *fresh18 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).cipher_list }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    68 => {
                        if !(unsafe { (*config).dns_interface }).is_null() {
                            (unsafe { free((*config).dns_interface as *mut libc::c_void) });
                            let mut fresh19 = unsafe { &mut ((*config).dns_interface) };
                            *fresh19 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh20 = unsafe { &mut ((*config).dns_interface) };
                            *fresh20 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).dns_interface }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    101 => {
                        (unsafe { (*config).disable_epsv = toggle });
                    }
                    102 => {
                        (unsafe { (*config).disallow_username_in_url = toggle });
                    }
                    69 => {
                        (unsafe { (*config).disable_epsv = if !toggle { 1 as i32 } else { 0 as i32 } != 0 });
                    }
                    70 => {
                        if !(unsafe { (*config).dns_servers }).is_null() {
                            (unsafe { free((*config).dns_servers as *mut libc::c_void) });
                            let mut fresh21 = unsafe { &mut ((*config).dns_servers) };
                            *fresh21 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh22 = unsafe { &mut ((*config).dns_servers) };
                            *fresh22 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).dns_servers }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    103 => {
                        if !(unsafe { (*global).trace_dump }).is_null() {
                            (unsafe { free((*global).trace_dump as *mut libc::c_void) });
                            let mut fresh23 = unsafe { &mut ((*global).trace_dump) };
                            *fresh23 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh24 = unsafe { &mut ((*global).trace_dump) };
                            *fresh24 = unsafe { strdup(nextarg) };
                            if (unsafe { (*global).trace_dump }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        if (unsafe { (*global).tracetype }) as u32 != 0
                            && (unsafe { (*global).tracetype }) as u32 != TRACE_BIN as i32 as u32
                        {
                            (unsafe { warnf(
                                global,
                                b"--trace overrides an earlier trace/verbose option\n\0"
                                    as *const u8 as *const i8,
                            ) });
                        }
                        (unsafe { (*global).tracetype = TRACE_BIN });
                    }
                    71 => {
                        (unsafe { (*config).nonpn = if !toggle { 1 as i32 } else { 0 as i32 } != 0 });
                    }
                    104 => {
                        if !(unsafe { (*global).trace_dump }).is_null() {
                            (unsafe { free((*global).trace_dump as *mut libc::c_void) });
                            let mut fresh25 = unsafe { &mut ((*global).trace_dump) };
                            *fresh25 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh26 = unsafe { &mut ((*global).trace_dump) };
                            *fresh26 = unsafe { strdup(nextarg) };
                            if (unsafe { (*global).trace_dump }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        if (unsafe { (*global).tracetype }) as u32 != 0
                            && (unsafe { (*global).tracetype }) as u32 != TRACE_ASCII as i32 as u32
                        {
                            (unsafe { warnf(
                                global,
                                b"--trace-ascii overrides an earlier trace/verbose option\n\0"
                                    as *const u8 as *const i8,
                            ) });
                        }
                        (unsafe { (*global).tracetype = TRACE_ASCII });
                    }
                    72 => {
                        (unsafe { (*config).noalpn = if !toggle { 1 as i32 } else { 0 as i32 } != 0 });
                    }
                    105 => {
                        let mut value: i64 = 0;
                        let mut pe: u32 = GetSizeParameter(
                            global,
                            nextarg,
                            b"rate\0" as *const u8 as *const i8,
                            Some(&mut value),
                        );
                        if pe as u32 != PARAM_OK as i32 as u32 {
                            return pe;
                        }
                        (unsafe { (*config).recvpersecond = value });
                        (unsafe { (*config).sendpersecond = value });
                    }
                    106 => {
                        if toggle as i32 != 0
                            && (unsafe { (*curlinfo).features })
                                & ((1 as i32) << 3 as i32
                                    | (1 as i32) << 23 as i32
                                    | (1 as i32) << 26 as i32)
                                == 0
                        {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                        (unsafe { (*config).encoding = toggle });
                    }
                    74 => {
                        (unsafe { (*config).tr_encoding = toggle });
                    }
                    107 => {
                        if toggle {
                            (unsafe { (*config).authtype |= (1 as i32 as u64) << 1 as i32 });
                        } else {
                            (unsafe { (*config).authtype &= !((1 as i32 as u64) << 1 as i32) });
                        }
                    }
                    108 => {
                        if toggle {
                            if (unsafe { (*curlinfo).features }) & (1 as i32) << 8 as i32 != 0 {
                                (unsafe { (*config).authtype |= (1 as i32 as u64) << 2 as i32 });
                            } else {
                                return PARAM_LIBCURL_DOESNT_SUPPORT;
                            }
                        } else {
                            (unsafe { (*config).authtype &= !((1 as i32 as u64) << 2 as i32) });
                        }
                    }
                    109 => {
                        if toggle {
                            if (unsafe { (*curlinfo).features }) & (1 as i32) << 4 as i32 != 0 {
                                (unsafe { (*config).authtype |= (1 as i32 as u64) << 3 as i32 });
                            } else {
                                return PARAM_LIBCURL_DOESNT_SUPPORT;
                            }
                        } else {
                            (unsafe { (*config).authtype &= !((1 as i32 as u64) << 3 as i32) });
                        }
                    }
                    77 => {
                        if toggle {
                            if (unsafe { (*curlinfo).features }) & (1 as i32) << 15 as i32 != 0 {
                                (unsafe { (*config).authtype |= (1 as i32 as u64) << 5 as i32 });
                            } else {
                                return PARAM_LIBCURL_DOESNT_SUPPORT;
                            }
                        } else {
                            (unsafe { (*config).authtype &= !((1 as i32 as u64) << 5 as i32) });
                        }
                    }
                    110 => {
                        if toggle {
                            (unsafe { (*config).authtype |= (1 as i32 as u64) << 0 as i32 });
                        } else {
                            (unsafe { (*config).authtype &= !((1 as i32 as u64) << 0 as i32) });
                        }
                    }
                    111 => {
                        if toggle {
                            (unsafe { (*config).authtype = !((1 as i32 as u64) << 4 as i32) });
                        }
                    }
                    113 => {
                        (unsafe { (*config).ftp_create_dirs = toggle });
                    }
                    114 => {
                        (unsafe { (*config).create_dirs = toggle });
                    }
                    82 => {
                        err = oct2nummax(
                            Some(unsafe { &mut (*config).create_file_mode }),
                            nextarg,
                            0o777 as i32 as i64,
                        );
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    115 => {
                        err = str2num(Some(unsafe { &mut (*config).maxredirs }), nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                        if (unsafe { (*config).maxredirs }) < -(1 as i32) as i64 {
                            return PARAM_BAD_NUMERIC;
                        }
                    }
                    116 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 4 as i32 != 0 {
                            (unsafe { (*config).proxyntlm = toggle });
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                    }
                    117 => {
                        (unsafe { (*config).crlf = toggle });
                    }
                    86 => {
                        (unsafe { (*config).authtype |= (1 as i32 as u64) << 7 as i32 });
                        if !(unsafe { (*config).aws_sigv4 }).is_null() {
                            (unsafe { free((*config).aws_sigv4 as *mut libc::c_void) });
                            let mut fresh27 = unsafe { &mut ((*config).aws_sigv4) };
                            *fresh27 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh28 = unsafe { &mut ((*config).aws_sigv4) };
                            *fresh28 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).aws_sigv4 }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    118 => {
                        if (unsafe { strcmp(nextarg, b"-\0" as *const u8 as *const i8) }) != 0 {
                            let mut newfile: *mut crate::src::lib::http2::_IO_FILE =
                                unsafe { fopen(nextarg, b"w\0" as *const u8 as *const i8) };
                            if newfile.is_null() {
                                (unsafe { warnf(
                                    global,
                                    b"Failed to open %s!\n\0" as *const u8 as *const i8,
                                    nextarg,
                                ) });
                            } else {
                                if unsafe { (*global).errors_fopened } {
                                    (unsafe { fclose((*global).errors) });
                                }
                                let mut fresh29 = unsafe { &mut ((*global).errors) };
                                *fresh29 = newfile;
                                (unsafe { (*global).errors_fopened = 1 as i32 != 0 });
                            }
                        } else {
                            let mut fresh30 = unsafe { &mut ((*global).errors) };
                            *fresh30 = unsafe { stdout };
                        }
                    }
                    119 => {
                        if !(unsafe { (*config).iface }).is_null() {
                            (unsafe { free((*config).iface as *mut libc::c_void) });
                            let mut fresh31 = unsafe { &mut ((*config).iface) };
                            *fresh31 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh32 = unsafe { &mut ((*config).iface) };
                            *fresh32 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).iface }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    120 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 8 as i32 != 0 {
                            if !(unsafe { (*config).krblevel }).is_null() {
                                (unsafe { free((*config).krblevel as *mut libc::c_void) });
                                let mut fresh33 = unsafe { &mut ((*config).krblevel) };
                                *fresh33 = 0 as *mut i8;
                            }
                            if !nextarg.is_null() {
                                let mut fresh34 = unsafe { &mut ((*config).krblevel) };
                                *fresh34 = unsafe { strdup(nextarg) };
                                if (unsafe { (*config).krblevel }).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                    }
                    88 => {
                        (unsafe { (*config).haproxy_protocol = toggle });
                    }
                    121 => {
                        let mut value_0: i64 = 0;
                        let mut pe_0: u32 = GetSizeParameter(
                            global,
                            nextarg,
                            b"max-filesize\0" as *const u8 as *const i8,
                            Some(&mut value_0),
                        );
                        if pe_0 as u32 != PARAM_OK as i32 as u32 {
                            return pe_0;
                        }
                        (unsafe { (*config).max_filesize = value_0 });
                    }
                    122 => {
                        (unsafe { (*config).disable_eprt = toggle });
                    }
                    90 => {
                        (unsafe { (*config).disable_eprt = if !toggle { 1 as i32 } else { 0 as i32 } != 0 });
                    }
                    126 => {
                        (unsafe { (*config).xattr = toggle });
                    }
                    64 => {
                        let mut url: *mut crate::src::src::tool_cb_dbg::getout = 0 as *mut getout;
                        if (unsafe { (*config).url_get }).is_null() {
                            let mut fresh35 = unsafe { &mut ((*config).url_get) };
                            *fresh35 = unsafe { (*config).url_list };
                        }
                        if !(unsafe { (*config).url_get }).is_null() {
                            while !(unsafe { (*config).url_get }).is_null()
                                && (unsafe { (*(*config).url_get).flags }) & (1 as i32) << 1 as i32 != 0
                            {
                                let mut fresh36 = unsafe { &mut ((*config).url_get) };
                                *fresh36 = unsafe { (*(*config).url_get).next };
                            }
                        }
                        if !(unsafe { (*config).url_get }).is_null() {
                            url = unsafe { (*config).url_get };
                        } else {
                            url = new_getout(config);
                            let mut fresh37 = unsafe { &mut ((*config).url_get) };
                            *fresh37 = url;
                        }
                        if url.is_null() {
                            return PARAM_NO_MEM;
                        }
                        if !(unsafe { (*url).url }).is_null() {
                            (unsafe { free((*url).url as *mut libc::c_void) });
                            let mut fresh38 = unsafe { &mut ((*url).url) };
                            *fresh38 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh39 = unsafe { &mut ((*url).url) };
                            *fresh39 = unsafe { strdup(nextarg) };
                            if (unsafe { (*url).url }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        (unsafe { (*url).flags |= (1 as i32) << 1 as i32 });
                    }
                    _ => {}
                }
                current_block_1664 = 2210884902194999453;
            }
            36 => {
                match subletter as i32 {
                    97 => {
                        if toggle as i32 != 0 && (unsafe { (*curlinfo).features }) & (1 as i32) << 2 as i32 == 0
                        {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                        (unsafe { (*config).ftp_ssl = toggle });
                    }
                    98 => {
                        (unsafe { free((*config).ftpport as *mut libc::c_void) });
                        let mut fresh40 = unsafe { &mut ((*config).ftpport) };
                        *fresh40 = 0 as *mut i8;
                    }
                    99 => {
                        if !(unsafe { (*config).proxy }).is_null() {
                            (unsafe { free((*config).proxy as *mut libc::c_void) });
                            let mut fresh41 = unsafe { &mut ((*config).proxy) };
                            *fresh41 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh42 = unsafe { &mut ((*config).proxy) };
                            *fresh42 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proxy }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        (unsafe { (*config).proxyver = CURLPROXY_SOCKS5 as i32 });
                    }
                    116 => {
                        if !(unsafe { (*config).proxy }).is_null() {
                            (unsafe { free((*config).proxy as *mut libc::c_void) });
                            let mut fresh43 = unsafe { &mut ((*config).proxy) };
                            *fresh43 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh44 = unsafe { &mut ((*config).proxy) };
                            *fresh44 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proxy }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        (unsafe { (*config).proxyver = CURLPROXY_SOCKS4 as i32 });
                    }
                    84 => {
                        if !(unsafe { (*config).proxy }).is_null() {
                            (unsafe { free((*config).proxy as *mut libc::c_void) });
                            let mut fresh45 = unsafe { &mut ((*config).proxy) };
                            *fresh45 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh46 = unsafe { &mut ((*config).proxy) };
                            *fresh46 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proxy }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        (unsafe { (*config).proxyver = CURLPROXY_SOCKS4A as i32 });
                    }
                    50 => {
                        if !(unsafe { (*config).proxy }).is_null() {
                            (unsafe { free((*config).proxy as *mut libc::c_void) });
                            let mut fresh47 = unsafe { &mut ((*config).proxy) };
                            *fresh47 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh48 = unsafe { &mut ((*config).proxy) };
                            *fresh48 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proxy }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        (unsafe { (*config).proxyver = CURLPROXY_SOCKS5_HOSTNAME as i32 });
                    }
                    100 => {
                        (unsafe { (*config).tcp_nodelay = toggle });
                    }
                    101 => {
                        (unsafe { (*config).proxydigest = toggle });
                    }
                    102 => {
                        (unsafe { (*config).proxybasic = toggle });
                    }
                    103 => {
                        err = str2unum(Some(unsafe { &mut (*config).req_retry }), nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    86 => {
                        (unsafe { (*config).retry_connrefused = toggle });
                    }
                    104 => {
                        err = str2unummax(
                            Some(unsafe { &mut (*config).retry_delay }),
                            nextarg,
                            9223372036854775807 as i64 / 1000 as i32 as i64,
                        );
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    105 => {
                        err = str2unummax(
                            Some(unsafe { &mut (*config).retry_maxtime }),
                            nextarg,
                            9223372036854775807 as i64 / 1000 as i32 as i64,
                        );
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    33 => {
                        (unsafe { (*config).retry_all_errors = toggle });
                    }
                    107 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 8 as i32 != 0 {
                            (unsafe { (*config).proxynegotiate = toggle });
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                    }
                    109 => {
                        if !(unsafe { (*config).ftp_account }).is_null() {
                            (unsafe { free((*config).ftp_account as *mut libc::c_void) });
                            let mut fresh49 = unsafe { &mut ((*config).ftp_account) };
                            *fresh49 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh50 = unsafe { &mut ((*config).ftp_account) };
                            *fresh50 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).ftp_account }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    110 => {
                        (unsafe { (*config).proxyanyauth = toggle });
                    }
                    111 => {
                        (unsafe { (*global).tracetime = toggle });
                    }
                    112 => {
                        (unsafe { (*config).ignorecl = toggle });
                    }
                    113 => {
                        (unsafe { (*config).ftp_skip_ip = toggle });
                    }
                    114 => {
                        (unsafe { (*config).ftp_filemethod = ftpfilemethod(config, nextarg) });
                    }
                    115 => {
                        let mut lrange: [i8; 7] = *(unsafe { core::intrinsics::transmute::<
                            &'_ [u8; 7],
                            &'_ mut [i8; 7],
                        >(b"\0\0\0\0\0\0\0") });
                        let mut p: *mut i8 = nextarg;
                        while Curl_isdigit((unsafe { *p }) as u8 as i32) != 0 {
                            p = unsafe { p.offset(1) };
                        }
                        if (unsafe { *p }) != 0 {
                            rc = unsafe { sscanf(
                                p,
                                b" - %6s\0" as *const u8 as *const i8,
                                lrange.as_mut_ptr(),
                            ) };
                            (unsafe { *p = 0 as i32 as i8 });
                        } else {
                            rc = 0 as i32;
                        }
                        err = str2unum(Some(unsafe { &mut (*config).localport }), nextarg);
                        if err as u32 != 0 || (unsafe { (*config).localport }) > 65535 as i32 as i64 {
                            return PARAM_BAD_USE;
                        }
                        if rc == 0 {
                            (unsafe { (*config).localportrange = 1 as i32 as i64 });
                        } else {
                            err =
                                str2unum(Some(unsafe { &mut (*config).localportrange }), lrange.as_mut_ptr());
                            if err as u32 != 0 || (unsafe { (*config).localportrange }) > 65535 as i32 as i64 {
                                return PARAM_BAD_USE;
                            }
                            (unsafe { (*config).localportrange -= (*config).localport - 1 as i32 as i64 });
                            if (unsafe { (*config).localportrange }) < 1 as i32 as i64 {
                                return PARAM_BAD_USE;
                            }
                        }
                    }
                    117 => {
                        if !(unsafe { (*config).ftp_alternative_to_user }).is_null() {
                            (unsafe { free((*config).ftp_alternative_to_user as *mut libc::c_void) });
                            let mut fresh51 = unsafe { &mut ((*config).ftp_alternative_to_user) };
                            *fresh51 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh52 = unsafe { &mut ((*config).ftp_alternative_to_user) };
                            *fresh52 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).ftp_alternative_to_user }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    118 => {
                        if toggle as i32 != 0 && (unsafe { (*curlinfo).features }) & (1 as i32) << 2 as i32 == 0
                        {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                        (unsafe { (*config).ftp_ssl_reqd = toggle });
                    }
                    119 => {
                        (unsafe { (*config).disable_sessionid =
                            if !toggle { 1 as i32 } else { 0 as i32 } != 0 });
                    }
                    120 => {
                        if toggle as i32 != 0 && (unsafe { (*curlinfo).features }) & (1 as i32) << 2 as i32 == 0
                        {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                        (unsafe { (*config).ftp_ssl_control = toggle });
                    }
                    121 => {
                        (unsafe { (*config).ftp_ssl_ccc = toggle });
                        if (unsafe { (*config).ftp_ssl_ccc_mode }) == 0 {
                            (unsafe { (*config).ftp_ssl_ccc_mode = CURLFTPSSL_CCC_PASSIVE as i32 });
                        }
                    }
                    106 => {
                        (unsafe { (*config).ftp_ssl_ccc = 1 as i32 != 0 });
                        (unsafe { (*config).ftp_ssl_ccc_mode = ftpcccmethod(config, nextarg) });
                    }
                    122 => {
                        if !(unsafe { (*global).libcurl }).is_null() {
                            (unsafe { free((*global).libcurl as *mut libc::c_void) });
                            let mut fresh53 = unsafe { &mut ((*global).libcurl) };
                            *fresh53 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh54 = unsafe { &mut ((*global).libcurl) };
                            *fresh54 = unsafe { strdup(nextarg) };
                            if (unsafe { (*global).libcurl }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    35 => {
                        (unsafe { (*config).raw = toggle });
                    }
                    48 => {
                        (unsafe { (*config).post301 = toggle });
                    }
                    49 => {
                        (unsafe { (*config).nokeepalive = if !toggle { 1 as i32 } else { 0 as i32 } != 0 });
                    }
                    51 => {
                        err = str2unum(Some(unsafe { &mut (*config).alivetime }), nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    52 => {
                        (unsafe { (*config).post302 = toggle });
                    }
                    73 => {
                        (unsafe { (*config).post303 = toggle });
                    }
                    53 => {
                        if !(unsafe { (*config).noproxy }).is_null() {
                            (unsafe { free((*config).noproxy as *mut libc::c_void) });
                            let mut fresh55 = unsafe { &mut ((*config).noproxy) };
                            *fresh55 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh56 = unsafe { &mut ((*config).noproxy) };
                            *fresh56 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).noproxy }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    55 => {
                        (unsafe { (*config).socks5_gssapi_nec = toggle as i32 });
                    }
                    56 => {
                        if !(unsafe { (*config).proxy }).is_null() {
                            (unsafe { free((*config).proxy as *mut libc::c_void) });
                            let mut fresh57 = unsafe { &mut ((*config).proxy) };
                            *fresh57 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh58 = unsafe { &mut ((*config).proxy) };
                            *fresh58 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proxy }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        (unsafe { (*config).proxyver = CURLPROXY_HTTP_1_0 as i32 });
                    }
                    57 => {
                        err = str2unum(Some(unsafe { &mut (*config).tftp_blksize }), nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    65 => {
                        if !(unsafe { (*config).mail_from }).is_null() {
                            (unsafe { free((*config).mail_from as *mut libc::c_void) });
                            let mut fresh59 = unsafe { &mut ((*config).mail_from) };
                            *fresh59 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh60 = unsafe { &mut ((*config).mail_from) };
                            *fresh60 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).mail_from }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    66 => {
                        err = add2list(Some(unsafe { &mut (*config).mail_rcpt }), nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    67 => {
                        (unsafe { (*config).ftp_pret = toggle });
                    }
                    68 => {
                        (unsafe { (*config).proto_present = 1 as i32 != 0 });
                        if proto2num(config, Some(unsafe { &mut (*config).proto }), nextarg) != 0 {
                            return PARAM_BAD_USE;
                        }
                    }
                    69 => {
                        (unsafe { (*config).proto_redir_present = 1 as i32 != 0 });
                        if proto2num(config, Some(unsafe { &mut (*config).proto_redir }), nextarg) != 0 {
                            return PARAM_BAD_USE;
                        }
                    }
                    70 => {
                        err = add2list(Some(unsafe { &mut (*config).resolve }), nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    71 => {
                        (unsafe { (*config).gssapi_delegation = delegation(config, nextarg) });
                    }
                    72 => {
                        if !(unsafe { (*config).mail_auth }).is_null() {
                            (unsafe { free((*config).mail_auth as *mut libc::c_void) });
                            let mut fresh61 = unsafe { &mut ((*config).mail_auth) };
                            *fresh61 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh62 = unsafe { &mut ((*config).mail_auth) };
                            *fresh62 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).mail_auth }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    74 => {
                        (unsafe { errorf(
                            global,
                            b"--metalink is disabled\n\0" as *const u8 as *const i8,
                        ) });
                        return PARAM_BAD_USE;
                    }
                    54 => {
                        if !(unsafe { (*config).sasl_authzid }).is_null() {
                            (unsafe { free((*config).sasl_authzid as *mut libc::c_void) });
                            let mut fresh63 = unsafe { &mut ((*config).sasl_authzid) };
                            *fresh63 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh64 = unsafe { &mut ((*config).sasl_authzid) };
                            *fresh64 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).sasl_authzid }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    75 => {
                        (unsafe { (*config).sasl_ir = toggle });
                    }
                    76 => {
                        (unsafe { warnf(
                            global,
                            b"--test-event is ignored unless a debug build!\n\0" as *const u8
                                as *const i8,
                        ) });
                    }
                    77 => {
                        (unsafe { (*config).abstract_unix_socket = 0 as i32 != 0 });
                        if !(unsafe { (*config).unix_socket_path }).is_null() {
                            (unsafe { free((*config).unix_socket_path as *mut libc::c_void) });
                            let mut fresh65 = unsafe { &mut ((*config).unix_socket_path) };
                            *fresh65 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh66 = unsafe { &mut ((*config).unix_socket_path) };
                            *fresh66 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).unix_socket_path }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    78 => {
                        (unsafe { (*config).path_as_is = toggle });
                    }
                    79 => {
                        if !(unsafe { (*config).proxy_service_name }).is_null() {
                            (unsafe { free((*config).proxy_service_name as *mut libc::c_void) });
                            let mut fresh67 = unsafe { &mut ((*config).proxy_service_name) };
                            *fresh67 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh68 = unsafe { &mut ((*config).proxy_service_name) };
                            *fresh68 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proxy_service_name }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    80 => {
                        if !(unsafe { (*config).service_name }).is_null() {
                            (unsafe { free((*config).service_name as *mut libc::c_void) });
                            let mut fresh69 = unsafe { &mut ((*config).service_name) };
                            *fresh69 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh70 = unsafe { &mut ((*config).service_name) };
                            *fresh70 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).service_name }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    81 => {
                        if !(unsafe { (*config).proto_default }).is_null() {
                            (unsafe { free((*config).proto_default as *mut libc::c_void) });
                            let mut fresh71 = unsafe { &mut ((*config).proto_default) };
                            *fresh71 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh72 = unsafe { &mut ((*config).proto_default) };
                            *fresh72 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proto_default }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        err = check_protocol(unsafe { (*config).proto_default }) as ParameterError;
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    82 => {
                        err = str2udouble(
                            Some(unsafe { &mut (*config).expect100timeout }),
                            nextarg,
                            9223372036854775807 as i64 / 1000 as i32 as i64,
                        );
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    83 => {
                        (unsafe { (*config).tftp_no_options = toggle });
                    }
                    85 => {
                        err = add2list(Some(unsafe { &mut (*config).connect_to }), nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    87 => {
                        (unsafe { (*config).abstract_unix_socket = 1 as i32 != 0 });
                        if !(unsafe { (*config).unix_socket_path }).is_null() {
                            (unsafe { free((*config).unix_socket_path as *mut libc::c_void) });
                            let mut fresh73 = unsafe { &mut ((*config).unix_socket_path) };
                            *fresh73 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh74 = unsafe { &mut ((*config).unix_socket_path) };
                            *fresh74 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).unix_socket_path }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    88 => {
                        err = str2tls_max(Some(unsafe { &mut (*config).ssl_version_max }), nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    89 => {
                        (unsafe { (*config).suppress_connect_headers = toggle });
                    }
                    90 => {
                        (unsafe { (*config).ssh_compression = toggle });
                    }
                    126 => {
                        err = str2unum(Some(unsafe { &mut (*config).happy_eyeballs_timeout_ms }), nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                    _ => {}
                }
                current_block_1664 = 2210884902194999453;
            }
            35 => {
                match subletter as i32 {
                    109 => {
                        (unsafe { (*global).noprogress = !toggle });
                    }
                    _ => {
                        (unsafe { (*global).progressmode = if toggle as i32 != 0 {
                            1 as i32
                        } else {
                            0 as i32
                        } });
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            58 => return PARAM_NEXT_OPERATION,
            48 => {
                match subletter as i32 {
                    0 => {
                        (unsafe { (*config).httpversion = CURL_HTTP_VERSION_1_0 as i32 as i64 });
                    }
                    49 => {
                        (unsafe { (*config).httpversion = CURL_HTTP_VERSION_1_1 as i32 as i64 });
                    }
                    50 => {
                        (unsafe { (*config).httpversion = CURL_HTTP_VERSION_2_0 as i32 as i64 });
                    }
                    51 => {
                        (unsafe { (*config).httpversion = CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE as i32 as i64 });
                    }
                    52 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 25 as i32 != 0 {
                            (unsafe { (*config).httpversion = CURL_HTTP_VERSION_3 as i32 as i64 });
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                    }
                    57 => {
                        (unsafe { (*config).http09_allowed = toggle });
                    }
                    _ => {}
                }
                current_block_1664 = 2210884902194999453;
            }
            49 => {
                match subletter as i32 {
                    0 => {
                        (unsafe { (*config).ssl_version = CURL_SSLVERSION_TLSv1 as i32 as i64 });
                    }
                    48 => {
                        (unsafe { (*config).ssl_version = CURL_SSLVERSION_TLSv1_0 as i32 as i64 });
                    }
                    49 => {
                        (unsafe { (*config).ssl_version = CURL_SSLVERSION_TLSv1_1 as i32 as i64 });
                    }
                    50 => {
                        (unsafe { (*config).ssl_version = CURL_SSLVERSION_TLSv1_2 as i32 as i64 });
                    }
                    51 => {
                        (unsafe { (*config).ssl_version = CURL_SSLVERSION_TLSv1_3 as i32 as i64 });
                    }
                    65 => {
                        if !(unsafe { (*config).cipher13_list }).is_null() {
                            (unsafe { free((*config).cipher13_list as *mut libc::c_void) });
                            let mut fresh75 = unsafe { &mut ((*config).cipher13_list) };
                            *fresh75 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh76 = unsafe { &mut ((*config).cipher13_list) };
                            *fresh76 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).cipher13_list }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    66 => {
                        if !(unsafe { (*config).proxy_cipher13_list }).is_null() {
                            (unsafe { free((*config).proxy_cipher13_list as *mut libc::c_void) });
                            let mut fresh77 = unsafe { &mut ((*config).proxy_cipher13_list) };
                            *fresh77 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh78 = unsafe { &mut ((*config).proxy_cipher13_list) };
                            *fresh78 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proxy_cipher13_list }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    _ => {}
                }
                current_block_1664 = 2210884902194999453;
            }
            50 => {
                (unsafe { warnf(
                    global,
                    b"Ignores instruction to use SSLv2\n\0" as *const u8 as *const i8,
                ) });
                current_block_1664 = 2210884902194999453;
            }
            51 => {
                (unsafe { warnf(
                    global,
                    b"Ignores instruction to use SSLv3\n\0" as *const u8 as *const i8,
                ) });
                current_block_1664 = 2210884902194999453;
            }
            52 => {
                (unsafe { (*config).ip_version = 1 as i32 as i64 });
                current_block_1664 = 2210884902194999453;
            }
            54 => {
                (unsafe { (*config).ip_version = 2 as i32 as i64 });
                current_block_1664 = 2210884902194999453;
            }
            97 => {
                (unsafe { (*config).ftp_append = toggle });
                current_block_1664 = 2210884902194999453;
            }
            65 => {
                if !(unsafe { (*config).useragent }).is_null() {
                    (unsafe { free((*config).useragent as *mut libc::c_void) });
                    let mut fresh79 = unsafe { &mut ((*config).useragent) };
                    *fresh79 = 0 as *mut i8;
                }
                if !nextarg.is_null() {
                    let mut fresh80 = unsafe { &mut ((*config).useragent) };
                    *fresh80 = unsafe { strdup(nextarg) };
                    if (unsafe { (*config).useragent }).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            98 => {
                let mut current_block_716: u64;
                match subletter as i32 {
                    97 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 24 as i32 != 0 {
                            if !(unsafe { (*config).altsvc }).is_null() {
                                (unsafe { free((*config).altsvc as *mut libc::c_void) });
                                let mut fresh81 = unsafe { &mut ((*config).altsvc) };
                                *fresh81 = 0 as *mut i8;
                            }
                            if !nextarg.is_null() {
                                let mut fresh82 = unsafe { &mut ((*config).altsvc) };
                                *fresh82 = unsafe { strdup(nextarg) };
                                if (unsafe { (*config).altsvc }).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                    }
                    98 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 28 as i32 != 0 {
                            if !(unsafe { (*config).hsts }).is_null() {
                                (unsafe { free((*config).hsts as *mut libc::c_void) });
                                let mut fresh83 = unsafe { &mut ((*config).hsts) };
                                *fresh83 = 0 as *mut i8;
                            }
                            if !nextarg.is_null() {
                                let mut fresh84 = unsafe { &mut ((*config).hsts) };
                                *fresh84 = unsafe { strdup(nextarg) };
                                if (unsafe { (*config).hsts }).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                    }
                    _ => {
                        if (unsafe { *nextarg.offset(0 as i32 as isize) }) as i32 == '@' as i32 {
                            nextarg = unsafe { nextarg.offset(1) };
                            current_block_716 = 17559505768186022594;
                        } else if !(unsafe { strchr(nextarg, '=' as i32) }).is_null() {
                            err = add2list(Some(unsafe { &mut (*config).cookies }), nextarg);
                            if err as u64 != 0 {
                                return err;
                            }
                            current_block_716 = 9607877020798263770;
                        } else {
                            current_block_716 = 17559505768186022594;
                        }
                        match current_block_716 {
                            9607877020798263770 => {}
                            _ => {
                                err = add2list(Some(unsafe { &mut (*config).cookiefiles }), nextarg);
                                if err as u64 != 0 {
                                    return err;
                                }
                            }
                        }
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            66 => {
                (unsafe { (*config).use_ascii = toggle });
                current_block_1664 = 2210884902194999453;
            }
            99 => {
                if !(unsafe { (*config).cookiejar }).is_null() {
                    (unsafe { free((*config).cookiejar as *mut libc::c_void) });
                    let mut fresh85 = unsafe { &mut ((*config).cookiejar) };
                    *fresh85 = 0 as *mut i8;
                }
                if !nextarg.is_null() {
                    let mut fresh86 = unsafe { &mut ((*config).cookiejar) };
                    *fresh86 = unsafe { strdup(nextarg) };
                    if (unsafe { (*config).cookiejar }).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            67 => {
                if (unsafe { strcmp(nextarg, b"-\0" as *const u8 as *const i8) }) != 0 {
                    err = str2offset(Some(unsafe { &mut (*config).resume_from }), nextarg);
                    if err as u64 != 0 {
                        return err;
                    }
                    (unsafe { (*config).resume_from_current = 0 as i32 != 0 });
                } else {
                    (unsafe { (*config).resume_from_current = 1 as i32 != 0 });
                    (unsafe { (*config).resume_from = 0 as i32 as curl_off_t });
                }
                (unsafe { (*config).use_resume = 1 as i32 != 0 });
                current_block_1664 = 2210884902194999453;
            }
            100 => {
                let mut postdata: *mut i8 = 0 as *mut i8;
                let mut file: *mut crate::src::lib::http2::_IO_FILE = 0 as *mut FILE;
                let mut size: u64 = 0 as i32 as size_t;
                let mut raw_mode: bool = subletter as i32 == 'r' as i32;
                if subletter as i32 == 'e' as i32 {
                    let mut p_0: *const i8 = unsafe { strchr(nextarg, '=' as i32) };
                    let mut nlen: u64 = 0;
                    let mut is_file: i8 = 0;
                    if p_0.is_null() {
                        p_0 = unsafe { strchr(nextarg, '@' as i32) };
                    }
                    if !p_0.is_null() {
                        nlen = (unsafe { p_0.offset_from(nextarg) }) as i64 as size_t;
                        let mut fresh87 = p_0;
                        p_0 = unsafe { p_0.offset(1) };
                        is_file = unsafe { *fresh87 };
                    } else {
                        is_file = 0 as i32 as i8;
                        nlen = is_file as size_t;
                        p_0 = nextarg;
                    }
                    if '@' as i32 == is_file as i32 {
                        if (unsafe { strcmp(b"-\0" as *const u8 as *const i8, p_0) }) == 0 {
                            file = unsafe { stdin };
                        } else {
                            file = unsafe { fopen(p_0, b"rb\0" as *const u8 as *const i8) };
                            if file.is_null() {
                                (unsafe { warnf (global , b"Couldn't read data from file \"%s\", this makes an empty POST.\n\0" as * const u8 as * const i8 , nextarg ,) }) ;
                            }
                        }
                        err = file2memory(Some(&mut postdata), Some(&mut size), file);
                        if !file.is_null() && file != (unsafe { stdin }) {
                            (unsafe { fclose(file) });
                        }
                        if err as u64 != 0 {
                            return err;
                        }
                    } else {
                        if !postdata.is_null() {
                            (unsafe { free(postdata as *mut libc::c_void) });
                            postdata = 0 as *mut i8;
                        }
                        if !p_0.is_null() {
                            postdata = unsafe { strdup(p_0) };
                            if postdata.is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        if !postdata.is_null() {
                            size = unsafe { strlen(postdata) };
                        }
                    }
                    if postdata.is_null() {
                        postdata = unsafe { strdup(b"\0" as *const u8 as *const i8) };
                        if postdata.is_null() {
                            return PARAM_NO_MEM;
                        }
                        size = 0 as i32 as size_t;
                    } else {
                        let mut enc: *mut i8 =
                            curl_easy_escape(0 as *mut CURL, postdata, size as i32);
                        (unsafe { free(postdata as *mut libc::c_void) });
                        postdata = 0 as *mut i8;
                        if !enc.is_null() {
                            let mut enclen: u64 = replace_url_encoded_space_by_plus(enc);
                            let mut outlen: u64 =
                                nlen.wrapping_add(enclen).wrapping_add(2 as i32 as u64);
                            let mut n: *mut i8 = (unsafe { malloc(outlen) }) as *mut i8;
                            if n.is_null() {
                                curl_free(enc as *mut libc::c_void);
                                return PARAM_NO_MEM;
                            }
                            if nlen > 0 as i32 as u64 {
                                (unsafe { curl_msnprintf(
                                    n,
                                    outlen,
                                    b"%.*s=%s\0" as *const u8 as *const i8,
                                    nlen,
                                    nextarg,
                                    enc,
                                ) });
                                size = outlen.wrapping_sub(1 as i32 as u64);
                            } else {
                                (unsafe { strcpy(n, enc) });
                                size = outlen.wrapping_sub(2 as i32 as u64);
                            }
                            curl_free(enc as *mut libc::c_void);
                            postdata = n;
                        } else {
                            return PARAM_NO_MEM;
                        }
                    }
                } else if '@' as i32 == (unsafe { *nextarg }) as i32 && !raw_mode {
                    nextarg = unsafe { nextarg.offset(1) };
                    if (unsafe { strcmp(b"-\0" as *const u8 as *const i8, nextarg) }) == 0 {
                        file = unsafe { stdin };
                        let _ = subletter as i32 == 'b' as i32;
                    } else {
                        file = unsafe { fopen(nextarg, b"rb\0" as *const u8 as *const i8) };
                        if file.is_null() {
                            (unsafe { warnf (global , b"Couldn't read data from file \"%s\", this makes an empty POST.\n\0" as * const u8 as * const i8 , nextarg ,) }) ;
                        }
                    }
                    if subletter as i32 == 'b' as i32 {
                        err = file2memory(Some(&mut postdata), Some(&mut size), file);
                    } else {
                        err = file2string(Some(&mut postdata), file);
                        if !postdata.is_null() {
                            size = unsafe { strlen(postdata) };
                        }
                    }
                    if !file.is_null() && file != (unsafe { stdin }) {
                        (unsafe { fclose(file) });
                    }
                    if err as u64 != 0 {
                        return err;
                    }
                    if postdata.is_null() {
                        postdata = unsafe { strdup(b"\0" as *const u8 as *const i8) };
                        if postdata.is_null() {
                            return PARAM_NO_MEM;
                        }
                    }
                } else {
                    if !postdata.is_null() {
                        (unsafe { free(postdata as *mut libc::c_void) });
                        postdata = 0 as *mut i8;
                    }
                    if !nextarg.is_null() {
                        postdata = unsafe { strdup(nextarg) };
                        if postdata.is_null() {
                            return PARAM_NO_MEM;
                        }
                    }
                    if !postdata.is_null() {
                        size = unsafe { strlen(postdata) };
                    }
                }
                if !(unsafe { (*config).postfields }).is_null() {
                    let mut oldpost: *mut i8 = unsafe { (*config).postfields };
                    let mut oldlen: i64 = unsafe { (*config).postfieldsize };
                    let mut newlen: i64 = oldlen + curlx_uztoso(size) + 2 as i32 as i64;
                    let mut fresh88 = unsafe { &mut ((*config).postfields) };
                    *fresh88 = (unsafe { malloc(newlen as size_t) }) as *mut i8;
                    if (unsafe { (*config).postfields }).is_null() {
                        (unsafe { free(oldpost as *mut libc::c_void) });
                        oldpost = 0 as *mut i8;
                        (unsafe { free(postdata as *mut libc::c_void) });
                        postdata = 0 as *mut i8;
                        return PARAM_NO_MEM;
                    }
                    (unsafe { memcpy(
                        (*config).postfields as *mut libc::c_void,
                        oldpost as *const libc::c_void,
                        oldlen as size_t,
                    ) });
                    (unsafe { *((*config).postfields).offset(oldlen as isize) = '&' as i32 as i8 });
                    (unsafe { memcpy(
                        &mut *((*config).postfields).offset((oldlen + 1 as i32 as i64) as isize)
                            as *mut i8 as *mut libc::c_void,
                        postdata as *const libc::c_void,
                        size,
                    ) });
                    (unsafe { *((*config).postfields)
                        .offset(((oldlen + 1 as i32 as i64) as u64).wrapping_add(size) as isize) =
                        '\u{0}' as i32 as i8 });
                    (unsafe { free(oldpost as *mut libc::c_void) });
                    oldpost = 0 as *mut i8;
                    (unsafe { free(postdata as *mut libc::c_void) });
                    postdata = 0 as *mut i8;
                    let mut fresh89 = unsafe { &mut ((*config).postfieldsize) };
                    *fresh89 = (*fresh89 as u64).wrapping_add(size.wrapping_add(1 as i32 as u64))
                        as curl_off_t as curl_off_t;
                } else {
                    let mut fresh90 = unsafe { &mut ((*config).postfields) };
                    *fresh90 = postdata;
                    (unsafe { (*config).postfieldsize = curlx_uztoso(size) });
                }
                current_block_1664 = 2210884902194999453;
            }
            68 => {
                if !(unsafe { (*config).headerfile }).is_null() {
                    (unsafe { free((*config).headerfile as *mut libc::c_void) });
                    let mut fresh91 = unsafe { &mut ((*config).headerfile) };
                    *fresh91 = 0 as *mut i8;
                }
                if !nextarg.is_null() {
                    let mut fresh92 = unsafe { &mut ((*config).headerfile) };
                    *fresh92 = unsafe { strdup(nextarg) };
                    if (unsafe { (*config).headerfile }).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            101 => {
                let mut ptr: *mut i8 = unsafe { strstr(nextarg, b";auto\0" as *const u8 as *const i8) };
                if !ptr.is_null() {
                    (unsafe { (*config).autoreferer = 1 as i32 != 0 });
                    (unsafe { *ptr = 0 as i32 as i8 });
                } else {
                    (unsafe { (*config).autoreferer = 0 as i32 != 0 });
                }
                ptr = if (unsafe { *nextarg }) as i32 != 0 {
                    nextarg
                } else {
                    0 as *mut i8
                };
                if !(unsafe { (*config).referer }).is_null() {
                    (unsafe { free((*config).referer as *mut libc::c_void) });
                    let mut fresh93 = unsafe { &mut ((*config).referer) };
                    *fresh93 = 0 as *mut i8;
                }
                if !ptr.is_null() {
                    let mut fresh94 = unsafe { &mut ((*config).referer) };
                    *fresh94 = unsafe { strdup(ptr) };
                    if (unsafe { (*config).referer }).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            69 => {
                match subletter as i32 {
                    0 => {
                        GetFileAndPassword(
                            nextarg,
                            Some(unsafe { &mut (*config).cert }),
                            Some(unsafe { &mut (*config).key_passwd }),
                        );
                    }
                    97 => {
                        if !(unsafe { (*config).cacert }).is_null() {
                            (unsafe { free((*config).cacert as *mut libc::c_void) });
                            let mut fresh95 = unsafe { &mut ((*config).cacert) };
                            *fresh95 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh96 = unsafe { &mut ((*config).cacert) };
                            *fresh96 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).cacert }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    98 => {
                        if !(unsafe { (*config).cert_type }).is_null() {
                            (unsafe { free((*config).cert_type as *mut libc::c_void) });
                            let mut fresh97 = unsafe { &mut ((*config).cert_type) };
                            *fresh97 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh98 = unsafe { &mut ((*config).cert_type) };
                            *fresh98 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).cert_type }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    99 => {
                        if !(unsafe { (*config).key }).is_null() {
                            (unsafe { free((*config).key as *mut libc::c_void) });
                            let mut fresh99 = unsafe { &mut ((*config).key) };
                            *fresh99 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh100 = unsafe { &mut ((*config).key) };
                            *fresh100 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).key }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    100 => {
                        if !(unsafe { (*config).key_type }).is_null() {
                            (unsafe { free((*config).key_type as *mut libc::c_void) });
                            let mut fresh101 = unsafe { &mut ((*config).key_type) };
                            *fresh101 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh102 = unsafe { &mut ((*config).key_type) };
                            *fresh102 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).key_type }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    101 => {
                        if !(unsafe { (*config).key_passwd }).is_null() {
                            (unsafe { free((*config).key_passwd as *mut libc::c_void) });
                            let mut fresh103 = unsafe { &mut ((*config).key_passwd) };
                            *fresh103 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh104 = unsafe { &mut ((*config).key_passwd) };
                            *fresh104 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).key_passwd }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        cleanarg(nextarg);
                    }
                    102 => {
                        if !(unsafe { (*config).engine }).is_null() {
                            (unsafe { free((*config).engine as *mut libc::c_void) });
                            let mut fresh105 = unsafe { &mut ((*config).engine) };
                            *fresh105 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh106 = unsafe { &mut ((*config).engine) };
                            *fresh106 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).engine }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        if !(unsafe { (*config).engine }).is_null()
                            && curl_strequal(unsafe { (*config).engine }, b"list\0" as *const u8 as *const i8)
                                != 0
                        {
                            return PARAM_ENGINES_REQUESTED;
                        }
                    }
                    103 => {
                        if !(unsafe { (*config).capath }).is_null() {
                            (unsafe { free((*config).capath as *mut libc::c_void) });
                            let mut fresh107 = unsafe { &mut ((*config).capath) };
                            *fresh107 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh108 = unsafe { &mut ((*config).capath) };
                            *fresh108 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).capath }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    104 => {
                        if !(unsafe { (*config).pubkey }).is_null() {
                            (unsafe { free((*config).pubkey as *mut libc::c_void) });
                            let mut fresh109 = unsafe { &mut ((*config).pubkey) };
                            *fresh109 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh110 = unsafe { &mut ((*config).pubkey) };
                            *fresh110 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).pubkey }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    105 => {
                        if !(unsafe { (*config).hostpubmd5 }).is_null() {
                            (unsafe { free((*config).hostpubmd5 as *mut libc::c_void) });
                            let mut fresh111 = unsafe { &mut ((*config).hostpubmd5) };
                            *fresh111 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh112 = unsafe { &mut ((*config).hostpubmd5) };
                            *fresh112 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).hostpubmd5 }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        if (unsafe { (*config).hostpubmd5 }).is_null()
                            || (unsafe { strlen((*config).hostpubmd5) }) != 32 as i32 as u64
                        {
                            return PARAM_BAD_USE;
                        }
                    }
                    106 => {
                        if !(unsafe { (*config).crlfile }).is_null() {
                            (unsafe { free((*config).crlfile as *mut libc::c_void) });
                            let mut fresh113 = unsafe { &mut ((*config).crlfile) };
                            *fresh113 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh114 = unsafe { &mut ((*config).crlfile) };
                            *fresh114 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).crlfile }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    107 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 14 as i32 != 0 {
                            if !(unsafe { (*config).tls_username }).is_null() {
                                (unsafe { free((*config).tls_username as *mut libc::c_void) });
                                let mut fresh115 = unsafe { &mut ((*config).tls_username) };
                                *fresh115 = 0 as *mut i8;
                            }
                            if !nextarg.is_null() {
                                let mut fresh116 = unsafe { &mut ((*config).tls_username) };
                                *fresh116 = unsafe { strdup(nextarg) };
                                if (unsafe { (*config).tls_username }).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                    }
                    108 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 14 as i32 != 0 {
                            if !(unsafe { (*config).tls_password }).is_null() {
                                (unsafe { free((*config).tls_password as *mut libc::c_void) });
                                let mut fresh117 = unsafe { &mut ((*config).tls_password) };
                                *fresh117 = 0 as *mut i8;
                            }
                            if !nextarg.is_null() {
                                let mut fresh118 = unsafe { &mut ((*config).tls_password) };
                                *fresh118 = unsafe { strdup(nextarg) };
                                if (unsafe { (*config).tls_password }).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                    }
                    109 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 14 as i32 != 0 {
                            if !(unsafe { (*config).tls_authtype }).is_null() {
                                (unsafe { free((*config).tls_authtype as *mut libc::c_void) });
                                let mut fresh119 = unsafe { &mut ((*config).tls_authtype) };
                                *fresh119 = 0 as *mut i8;
                            }
                            if !nextarg.is_null() {
                                let mut fresh120 = unsafe { &mut ((*config).tls_authtype) };
                                *fresh120 = unsafe { strdup(nextarg) };
                                if (unsafe { (*config).tls_authtype }).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                            if curl_strequal(
                                unsafe { (*config).tls_authtype },
                                b"SRP\0" as *const u8 as *const i8,
                            ) == 0
                            {
                                return PARAM_LIBCURL_DOESNT_SUPPORT;
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                    }
                    110 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 2 as i32 != 0 {
                            (unsafe { (*config).ssl_allow_beast = toggle });
                        }
                    }
                    111 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 2 as i32 != 0 {
                            (unsafe { (*config).ssl_auto_client_cert = toggle });
                        }
                    }
                    79 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 2 as i32 != 0 {
                            (unsafe { (*config).proxy_ssl_auto_client_cert = toggle });
                        }
                    }
                    112 => {
                        if !(unsafe { (*config).pinnedpubkey }).is_null() {
                            (unsafe { free((*config).pinnedpubkey as *mut libc::c_void) });
                            let mut fresh121 = unsafe { &mut ((*config).pinnedpubkey) };
                            *fresh121 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh122 = unsafe { &mut ((*config).pinnedpubkey) };
                            *fresh122 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).pinnedpubkey }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    80 => {
                        if !(unsafe { (*config).proxy_pinnedpubkey }).is_null() {
                            (unsafe { free((*config).proxy_pinnedpubkey as *mut libc::c_void) });
                            let mut fresh123 = unsafe { &mut ((*config).proxy_pinnedpubkey) };
                            *fresh123 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh124 = unsafe { &mut ((*config).proxy_pinnedpubkey) };
                            *fresh124 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proxy_pinnedpubkey }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    113 => {
                        (unsafe { (*config).verifystatus = 1 as i32 != 0 });
                    }
                    81 => {
                        (unsafe { (*config).doh_verifystatus = 1 as i32 != 0 });
                    }
                    114 => {
                        (unsafe { (*config).falsestart = 1 as i32 != 0 });
                    }
                    115 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 2 as i32 != 0 {
                            (unsafe { (*config).ssl_no_revoke = 1 as i32 != 0 });
                        }
                    }
                    83 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 2 as i32 != 0 {
                            (unsafe { (*config).ssl_revoke_best_effort = 1 as i32 != 0 });
                        }
                    }
                    116 => {
                        (unsafe { (*config).tcp_fastopen = 1 as i32 != 0 });
                    }
                    117 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 14 as i32 != 0 {
                            if !(unsafe { (*config).proxy_tls_username }).is_null() {
                                (unsafe { free((*config).proxy_tls_username as *mut libc::c_void) });
                                let mut fresh125 = unsafe { &mut ((*config).proxy_tls_username) };
                                *fresh125 = 0 as *mut i8;
                            }
                            if !nextarg.is_null() {
                                let mut fresh126 = unsafe { &mut ((*config).proxy_tls_username) };
                                *fresh126 = unsafe { strdup(nextarg) };
                                if (unsafe { (*config).proxy_tls_username }).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                    }
                    118 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 14 as i32 != 0 {
                            if !(unsafe { (*config).proxy_tls_password }).is_null() {
                                (unsafe { free((*config).proxy_tls_password as *mut libc::c_void) });
                                let mut fresh127 = unsafe { &mut ((*config).proxy_tls_password) };
                                *fresh127 = 0 as *mut i8;
                            }
                            if !nextarg.is_null() {
                                let mut fresh128 = unsafe { &mut ((*config).proxy_tls_password) };
                                *fresh128 = unsafe { strdup(nextarg) };
                                if (unsafe { (*config).proxy_tls_password }).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                    }
                    119 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 14 as i32 != 0 {
                            if !(unsafe { (*config).proxy_tls_authtype }).is_null() {
                                (unsafe { free((*config).proxy_tls_authtype as *mut libc::c_void) });
                                let mut fresh129 = unsafe { &mut ((*config).proxy_tls_authtype) };
                                *fresh129 = 0 as *mut i8;
                            }
                            if !nextarg.is_null() {
                                let mut fresh130 = unsafe { &mut ((*config).proxy_tls_authtype) };
                                *fresh130 = unsafe { strdup(nextarg) };
                                if (unsafe { (*config).proxy_tls_authtype }).is_null() {
                                    return PARAM_NO_MEM;
                                }
                            }
                            if curl_strequal(
                                unsafe { (*config).proxy_tls_authtype },
                                b"SRP\0" as *const u8 as *const i8,
                            ) == 0
                            {
                                return PARAM_LIBCURL_DOESNT_SUPPORT;
                            }
                        } else {
                            return PARAM_LIBCURL_DOESNT_SUPPORT;
                        }
                    }
                    120 => {
                        GetFileAndPassword(
                            nextarg,
                            Some(unsafe { &mut (*config).proxy_cert }),
                            Some(unsafe { &mut (*config).proxy_key_passwd }),
                        );
                    }
                    121 => {
                        if !(unsafe { (*config).proxy_cert_type }).is_null() {
                            (unsafe { free((*config).proxy_cert_type as *mut libc::c_void) });
                            let mut fresh131 = unsafe { &mut ((*config).proxy_cert_type) };
                            *fresh131 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh132 = unsafe { &mut ((*config).proxy_cert_type) };
                            *fresh132 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proxy_cert_type }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    122 => {
                        if !(unsafe { (*config).proxy_key }).is_null() {
                            (unsafe { free((*config).proxy_key as *mut libc::c_void) });
                            let mut fresh133 = unsafe { &mut ((*config).proxy_key) };
                            *fresh133 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh134 = unsafe { &mut ((*config).proxy_key) };
                            *fresh134 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proxy_key }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    48 => {
                        if !(unsafe { (*config).proxy_key_type }).is_null() {
                            (unsafe { free((*config).proxy_key_type as *mut libc::c_void) });
                            let mut fresh135 = unsafe { &mut ((*config).proxy_key_type) };
                            *fresh135 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh136 = unsafe { &mut ((*config).proxy_key_type) };
                            *fresh136 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proxy_key_type }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    49 => {
                        if !(unsafe { (*config).proxy_key_passwd }).is_null() {
                            (unsafe { free((*config).proxy_key_passwd as *mut libc::c_void) });
                            let mut fresh137 = unsafe { &mut ((*config).proxy_key_passwd) };
                            *fresh137 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh138 = unsafe { &mut ((*config).proxy_key_passwd) };
                            *fresh138 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proxy_key_passwd }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        cleanarg(nextarg);
                    }
                    50 => {
                        if !(unsafe { (*config).proxy_cipher_list }).is_null() {
                            (unsafe { free((*config).proxy_cipher_list as *mut libc::c_void) });
                            let mut fresh139 = unsafe { &mut ((*config).proxy_cipher_list) };
                            *fresh139 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh140 = unsafe { &mut ((*config).proxy_cipher_list) };
                            *fresh140 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proxy_cipher_list }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    51 => {
                        if !(unsafe { (*config).proxy_crlfile }).is_null() {
                            (unsafe { free((*config).proxy_crlfile as *mut libc::c_void) });
                            let mut fresh141 = unsafe { &mut ((*config).proxy_crlfile) };
                            *fresh141 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh142 = unsafe { &mut ((*config).proxy_crlfile) };
                            *fresh142 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proxy_crlfile }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    52 => {
                        if (unsafe { (*curlinfo).features }) & (1 as i32) << 2 as i32 != 0 {
                            (unsafe { (*config).proxy_ssl_allow_beast = toggle });
                        }
                    }
                    53 => {
                        if !(unsafe { (*config).login_options }).is_null() {
                            (unsafe { free((*config).login_options as *mut libc::c_void) });
                            let mut fresh143 = unsafe { &mut ((*config).login_options) };
                            *fresh143 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh144 = unsafe { &mut ((*config).login_options) };
                            *fresh144 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).login_options }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    54 => {
                        if !(unsafe { (*config).proxy_cacert }).is_null() {
                            (unsafe { free((*config).proxy_cacert as *mut libc::c_void) });
                            let mut fresh145 = unsafe { &mut ((*config).proxy_cacert) };
                            *fresh145 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh146 = unsafe { &mut ((*config).proxy_cacert) };
                            *fresh146 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proxy_cacert }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    55 => {
                        if !(unsafe { (*config).proxy_capath }).is_null() {
                            (unsafe { free((*config).proxy_capath as *mut libc::c_void) });
                            let mut fresh147 = unsafe { &mut ((*config).proxy_capath) };
                            *fresh147 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh148 = unsafe { &mut ((*config).proxy_capath) };
                            *fresh148 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proxy_capath }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    56 => {
                        (unsafe { (*config).proxy_insecure_ok = toggle });
                    }
                    57 => {
                        (unsafe { (*config).proxy_ssl_version = CURL_SSLVERSION_TLSv1 as i32 as i64 });
                    }
                    65 => {
                        if toggle {
                            (unsafe { (*config).socks5_auth |= (1 as i32 as u64) << 0 as i32 });
                        } else {
                            (unsafe { (*config).socks5_auth &= !((1 as i32 as u64) << 0 as i32) });
                        }
                    }
                    66 => {
                        if toggle {
                            (unsafe { (*config).socks5_auth |= (1 as i32 as u64) << 2 as i32 });
                        } else {
                            (unsafe { (*config).socks5_auth &= !((1 as i32 as u64) << 2 as i32) });
                        }
                    }
                    67 => {
                        if !(unsafe { (*config).etag_save_file }).is_null() {
                            (unsafe { free((*config).etag_save_file as *mut libc::c_void) });
                            let mut fresh149 = unsafe { &mut ((*config).etag_save_file) };
                            *fresh149 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh150 = unsafe { &mut ((*config).etag_save_file) };
                            *fresh150 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).etag_save_file }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    68 => {
                        if !(unsafe { (*config).etag_compare_file }).is_null() {
                            (unsafe { free((*config).etag_compare_file as *mut libc::c_void) });
                            let mut fresh151 = unsafe { &mut ((*config).etag_compare_file) };
                            *fresh151 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh152 = unsafe { &mut ((*config).etag_compare_file) };
                            *fresh152 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).etag_compare_file }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    69 => {
                        if !(unsafe { (*config).ssl_ec_curves }).is_null() {
                            (unsafe { free((*config).ssl_ec_curves as *mut libc::c_void) });
                            let mut fresh153 = unsafe { &mut ((*config).ssl_ec_curves) };
                            *fresh153 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh154 = unsafe { &mut ((*config).ssl_ec_curves) };
                            *fresh154 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).ssl_ec_curves }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    _ => return PARAM_OPTION_UNKNOWN,
                }
                current_block_1664 = 2210884902194999453;
            }
            102 => {
                match subletter as i32 {
                    97 => {
                        (unsafe { (*global).fail_early = toggle });
                    }
                    98 => {
                        (unsafe { (*global).styled_output = toggle });
                    }
                    99 => {
                        (unsafe { (*config).mail_rcpt_allowfails = toggle });
                    }
                    100 => {
                        (unsafe { (*config).failwithbody = toggle });
                    }
                    _ => {
                        (unsafe { (*config).failonerror = toggle });
                    }
                }
                if (unsafe { (*config).failonerror }) as i32 != 0 && (unsafe { (*config).failwithbody }) as i32 != 0 {
                    (unsafe { errorf(
                        (*config).global,
                        b"You must select either --fail or --fail-with-body, not both.\n\0"
                            as *const u8 as *const i8,
                    ) });
                    return PARAM_BAD_USE;
                }
                current_block_1664 = 2210884902194999453;
            }
            70 => {
                if formparse(
                    config,
                    nextarg,
                    Some(unsafe { &mut (*config).mimeroot }),
                    Some(unsafe { &mut (*config).mimecurrent }),
                    if subletter as i32 == 's' as i32 {
                        1 as i32
                    } else {
                        0 as i32
                    } != 0,
                ) != 0
                {
                    return PARAM_BAD_USE;
                }
                if SetHTTPrequest(config, HTTPREQ_MIMEPOST, Some(unsafe { &mut (*config).httpreq })) != 0 {
                    return PARAM_BAD_USE;
                }
                current_block_1664 = 2210884902194999453;
            }
            103 => {
                (unsafe { (*config).globoff = toggle });
                current_block_1664 = 2210884902194999453;
            }
            71 => {
                if subletter as i32 == 'a' as i32 {
                    if !(unsafe { (*config).request_target }).is_null() {
                        (unsafe { free((*config).request_target as *mut libc::c_void) });
                        let mut fresh155 = unsafe { &mut ((*config).request_target) };
                        *fresh155 = 0 as *mut i8;
                    }
                    if !nextarg.is_null() {
                        let mut fresh156 = unsafe { &mut ((*config).request_target) };
                        *fresh156 = unsafe { strdup(nextarg) };
                        if (unsafe { (*config).request_target }).is_null() {
                            return PARAM_NO_MEM;
                        }
                    }
                } else {
                    (unsafe { (*config).use_httpget = 1 as i32 != 0 });
                }
                current_block_1664 = 2210884902194999453;
            }
            104 => {
                if toggle {
                    if !nextarg.is_null() {
                        let mut fresh157 = unsafe { &mut ((*global).help_category) };
                        *fresh157 = unsafe { strdup(nextarg) };
                        if (unsafe { (*global).help_category }).is_null() {
                            return PARAM_NO_MEM;
                        }
                    }
                    return PARAM_HELP_REQUESTED;
                }
                current_block_1664 = 2210884902194999453;
            }
            72 => {
                if (unsafe { *nextarg.offset(0 as i32 as isize) }) as i32 == '@' as i32 {
                    let mut string: *mut i8 = 0 as *mut i8;
                    let mut len: u64 = 0;
                    let mut use_stdin: bool = (unsafe { strcmp(
                        &mut *nextarg.offset(1 as i32 as isize),
                        b"-\0" as *const u8 as *const i8,
                    ) }) == 0;
                    let mut file_0: *mut crate::src::lib::http2::_IO_FILE = if use_stdin as i32 != 0
                    {
                        unsafe { stdin }
                    } else {
                        unsafe { fopen(
                            &mut *nextarg.offset(1 as i32 as isize),
                            b"r\0" as *const u8 as *const i8,
                        ) }
                    };
                    if file_0.is_null() {
                        (unsafe { warnf(
                            global,
                            b"Failed to open %s!\n\0" as *const u8 as *const i8,
                            &mut *nextarg.offset(1 as i32 as isize) as *mut i8,
                        ) });
                    } else {
                        err = file2memory(Some(&mut string), Some(&mut len), file_0);
                        if err as u64 == 0 && !string.is_null() {
                            let mut h: *mut i8 =
                                unsafe { strtok(string, b"\r\n\0" as *const u8 as *const i8) };
                            while !h.is_null() {
                                if subletter as i32 == 'p' as i32 {
                                    err = add2list(Some(unsafe { &mut (*config).proxyheaders }), h);
                                } else {
                                    err = add2list(Some(unsafe { &mut (*config).headers }), h);
                                }
                                if err as u64 != 0 {
                                    break;
                                }
                                h = unsafe { strtok(0 as *mut i8, b"\r\n\0" as *const u8 as *const i8) };
                            }
                            (unsafe { free(string as *mut libc::c_void) });
                        }
                        if !use_stdin {
                            (unsafe { fclose(file_0) });
                        }
                        if err as u64 != 0 {
                            return err;
                        }
                    }
                } else {
                    if subletter as i32 == 'p' as i32 {
                        err = add2list(Some(unsafe { &mut (*config).proxyheaders }), nextarg);
                    } else {
                        err = add2list(Some(unsafe { &mut (*config).headers }), nextarg);
                    }
                    if err as u64 != 0 {
                        return err;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            105 => {
                (unsafe { (*config).show_headers = toggle });
                current_block_1664 = 2210884902194999453;
            }
            106 => {
                (unsafe { (*config).cookiesession = toggle });
                current_block_1664 = 2210884902194999453;
            }
            73 => {
                (unsafe { (*config).no_body = toggle });
                (unsafe { (*config).show_headers = toggle });
                if SetHTTPrequest(
                    config,
                    (if (unsafe { (*config).no_body }) as i32 != 0 {
                        HTTPREQ_HEAD as i32
                    } else {
                        HTTPREQ_GET as i32
                    }) as HttpReq,
                    Some(unsafe { &mut (*config).httpreq }),
                ) != 0
                {
                    return PARAM_BAD_USE;
                }
                current_block_1664 = 2210884902194999453;
            }
            74 => {
                (unsafe { (*config).content_disposition = toggle });
                current_block_1664 = 2210884902194999453;
            }
            107 => {
                if subletter as i32 == 'd' as i32 {
                    (unsafe { (*config).doh_insecure_ok = toggle });
                } else {
                    (unsafe { (*config).insecure_ok = toggle });
                }
                current_block_1664 = 2210884902194999453;
            }
            75 => {
                if parseconfig(nextarg, global) != 0 {
                    (unsafe { warnf(
                        global,
                        b"error trying read config from the '%s' file\n\0" as *const u8
                            as *const i8,
                        nextarg,
                    ) });
                }
                current_block_1664 = 2210884902194999453;
            }
            108 => {
                (unsafe { (*config).dirlistonly = toggle });
                current_block_1664 = 2210884902194999453;
            }
            76 => {
                (unsafe { (*config).followlocation = toggle });
                match subletter as i32 {
                    116 => {
                        (unsafe { (*config).unrestricted_auth = toggle });
                    }
                    _ => {}
                }
                current_block_1664 = 2210884902194999453;
            }
            109 => {
                err = str2udouble(
                    Some(unsafe { &mut (*config).timeout }),
                    nextarg,
                    9223372036854775807 as i64 / 1000 as i32 as i64,
                );
                if err as u64 != 0 {
                    return err;
                }
                current_block_1664 = 2210884902194999453;
            }
            77 => {
                if toggle {
                    return PARAM_MANUAL_REQUESTED;
                }
                current_block_1664 = 2210884902194999453;
            }
            110 => {
                match subletter as i32 {
                    111 => {
                        (unsafe { (*config).netrc_opt = toggle });
                    }
                    101 => {
                        if !(unsafe { (*config).netrc_file }).is_null() {
                            (unsafe { free((*config).netrc_file as *mut libc::c_void) });
                            let mut fresh158 = unsafe { &mut ((*config).netrc_file) };
                            *fresh158 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh159 = unsafe { &mut ((*config).netrc_file) };
                            *fresh159 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).netrc_file }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    _ => {
                        (unsafe { (*config).netrc = toggle });
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            78 => {
                if longopt {
                    (unsafe { (*config).nobuffer = if !toggle { 1 as i32 } else { 0 as i32 } != 0 });
                } else {
                    (unsafe { (*config).nobuffer = toggle });
                }
                current_block_1664 = 2210884902194999453;
            }
            79 => {
                if subletter as i32 == 'a' as i32 {
                    (unsafe { (*config).default_node_flags = if toggle as i32 != 0 {
                        (1 as i32) << 2 as i32
                    } else {
                        0 as i32
                    } });
                    current_block_1664 = 2210884902194999453;
                } else if subletter as i32 == 'b' as i32 {
                    if !(unsafe { (*config).output_dir }).is_null() {
                        (unsafe { free((*config).output_dir as *mut libc::c_void) });
                        let mut fresh160 = unsafe { &mut ((*config).output_dir) };
                        *fresh160 = 0 as *mut i8;
                    }
                    if !nextarg.is_null() {
                        let mut fresh161 = unsafe { &mut ((*config).output_dir) };
                        *fresh161 = unsafe { strdup(nextarg) };
                        if (unsafe { (*config).output_dir }).is_null() {
                            return PARAM_NO_MEM;
                        }
                    }
                    current_block_1664 = 2210884902194999453;
                } else {
                    current_block_1664 = 11000567119642394172;
                }
            }
            111 => {
                current_block_1664 = 11000567119642394172;
            }
            80 => {
                if !(unsafe { (*config).ftpport }).is_null() {
                    (unsafe { free((*config).ftpport as *mut libc::c_void) });
                    let mut fresh168 = unsafe { &mut ((*config).ftpport) };
                    *fresh168 = 0 as *mut i8;
                }
                if !nextarg.is_null() {
                    let mut fresh169 = unsafe { &mut ((*config).ftpport) };
                    *fresh169 = unsafe { strdup(nextarg) };
                    if (unsafe { (*config).ftpport }).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            112 => {
                (unsafe { (*config).proxytunnel = toggle });
                current_block_1664 = 2210884902194999453;
            }
            113 => {
                current_block_1664 = 2210884902194999453;
            }
            81 => {
                match (unsafe { *nextarg.offset(0 as i32 as isize) }) as i32 {
                    45 => {
                        nextarg = unsafe { nextarg.offset(1) };
                        err = add2list(Some(unsafe { &mut (*config).postquote }), nextarg);
                    }
                    43 => {
                        nextarg = unsafe { nextarg.offset(1) };
                        err = add2list(Some(unsafe { &mut (*config).prequote }), nextarg);
                    }
                    _ => {
                        err = add2list(Some(unsafe { &mut (*config).quote }), nextarg);
                    }
                }
                if err as u64 != 0 {
                    return err;
                }
                current_block_1664 = 2210884902194999453;
            }
            114 => {
                if Curl_isdigit((unsafe { *nextarg }) as u8 as i32) != 0
                    && (unsafe { strchr(nextarg, '-' as i32) }).is_null()
                {
                    let mut buffer: [i8; 32] = [0; 32];
                    let mut off: i64 = 0;
                    if curlx_strtoofft(
                        nextarg,
                        Option::<&'_ mut *mut i8>::None,
                        10 as i32,
                        Some(&mut off),
                    ) as u64
                        != 0
                    {
                        (unsafe { warnf(
                            global,
                            b"unsupported range point\n\0" as *const u8 as *const i8,
                        ) });
                        return PARAM_BAD_USE;
                    }
                    (unsafe { warnf (global , b"A specified range MUST include at least one dash (-). Appending one for you!\n\0" as * const u8 as * const i8 ,) }) ;
                    (unsafe { curl_msnprintf(
                        buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 32]>() as u64,
                        b"%ld-\0" as *const u8 as *const i8,
                        off,
                    ) });
                    (unsafe { free((*config).range as *mut libc::c_void) });
                    let mut fresh170 = unsafe { &mut ((*config).range) };
                    *fresh170 = 0 as *mut i8;
                    let mut fresh171 = unsafe { &mut ((*config).range) };
                    *fresh171 = unsafe { strdup(buffer.as_mut_ptr()) };
                    if (unsafe { (*config).range }).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                let mut tmp_range: *const i8 = nextarg;
                while (unsafe { *tmp_range }) as i32 != '\u{0}' as i32 {
                    if Curl_isdigit((unsafe { *tmp_range }) as u8 as i32) == 0
                        && (unsafe { *tmp_range }) as i32 != '-' as i32
                        && (unsafe { *tmp_range }) as i32 != ',' as i32
                    {
                        (unsafe { warnf (global , b"Invalid character is found in given range. A specified range MUST have only digits in 'start'-'stop'. The server's response to this request is uncertain.\n\0" as * const u8 as * const i8 ,) }) ;
                        break;
                    } else {
                        tmp_range = unsafe { tmp_range.offset(1) };
                    }
                }
                if !(unsafe { (*config).range }).is_null() {
                    (unsafe { free((*config).range as *mut libc::c_void) });
                    let mut fresh172 = unsafe { &mut ((*config).range) };
                    *fresh172 = 0 as *mut i8;
                }
                if !nextarg.is_null() {
                    let mut fresh173 = unsafe { &mut ((*config).range) };
                    *fresh173 = unsafe { strdup(nextarg) };
                    if (unsafe { (*config).range }).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            82 => {
                (unsafe { (*config).remote_time = toggle });
                current_block_1664 = 2210884902194999453;
            }
            115 => {
                if toggle {
                    let mut fresh174 = unsafe { &mut ((*global).noprogress) };
                    *fresh174 = 1 as i32 != 0;
                    (unsafe { (*global).mute = *fresh174 });
                } else {
                    let mut fresh175 = unsafe { &mut ((*global).noprogress) };
                    *fresh175 = 0 as i32 != 0;
                    (unsafe { (*global).mute = *fresh175 });
                }
                if (unsafe { (*global).showerror }) < 0 as i32 {
                    (unsafe { (*global).showerror = if !toggle { 1 as i32 } else { 0 as i32 } });
                }
                current_block_1664 = 2210884902194999453;
            }
            83 => {
                (unsafe { (*global).showerror = if toggle as i32 != 0 {
                    1 as i32
                } else {
                    0 as i32
                } });
                current_block_1664 = 2210884902194999453;
            }
            116 => {
                err = add2list(Some(unsafe { &mut (*config).telnet_options }), nextarg);
                if err as u64 != 0 {
                    return err;
                }
                current_block_1664 = 2210884902194999453;
            }
            84 => {
                let mut url_1: *mut crate::src::src::tool_cb_dbg::getout = 0 as *mut getout;
                if (unsafe { (*config).url_ul }).is_null() {
                    let mut fresh176 = unsafe { &mut ((*config).url_ul) };
                    *fresh176 = unsafe { (*config).url_list };
                }
                if !(unsafe { (*config).url_ul }).is_null() {
                    while !(unsafe { (*config).url_ul }).is_null()
                        && (unsafe { (*(*config).url_ul).flags }) & (1 as i32) << 3 as i32 != 0
                    {
                        let mut fresh177 = unsafe { &mut ((*config).url_ul) };
                        *fresh177 = unsafe { (*(*config).url_ul).next };
                    }
                }
                if !(unsafe { (*config).url_ul }).is_null() {
                    url_1 = unsafe { (*config).url_ul };
                } else {
                    url_1 = new_getout(config);
                    let mut fresh178 = unsafe { &mut ((*config).url_ul) };
                    *fresh178 = url_1;
                }
                if url_1.is_null() {
                    return PARAM_NO_MEM;
                }
                (unsafe { (*url_1).flags |= (1 as i32) << 3 as i32 });
                if (unsafe { *nextarg }) == 0 {
                    (unsafe { (*url_1).flags |= (1 as i32) << 4 as i32 });
                } else {
                    if !(unsafe { (*url_1).infile }).is_null() {
                        (unsafe { free((*url_1).infile as *mut libc::c_void) });
                        let mut fresh179 = unsafe { &mut ((*url_1).infile) };
                        *fresh179 = 0 as *mut i8;
                    }
                    if !nextarg.is_null() {
                        let mut fresh180 = unsafe { &mut ((*url_1).infile) };
                        *fresh180 = unsafe { strdup(nextarg) };
                        if (unsafe { (*url_1).infile }).is_null() {
                            return PARAM_NO_MEM;
                        }
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            117 => {
                if !(unsafe { (*config).userpwd }).is_null() {
                    (unsafe { free((*config).userpwd as *mut libc::c_void) });
                    let mut fresh181 = unsafe { &mut ((*config).userpwd) };
                    *fresh181 = 0 as *mut i8;
                }
                if !nextarg.is_null() {
                    let mut fresh182 = unsafe { &mut ((*config).userpwd) };
                    *fresh182 = unsafe { strdup(nextarg) };
                    if (unsafe { (*config).userpwd }).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                cleanarg(nextarg);
                current_block_1664 = 2210884902194999453;
            }
            85 => {
                if !(unsafe { (*config).proxyuserpwd }).is_null() {
                    (unsafe { free((*config).proxyuserpwd as *mut libc::c_void) });
                    let mut fresh183 = unsafe { &mut ((*config).proxyuserpwd) };
                    *fresh183 = 0 as *mut i8;
                }
                if !nextarg.is_null() {
                    let mut fresh184 = unsafe { &mut ((*config).proxyuserpwd) };
                    *fresh184 = unsafe { strdup(nextarg) };
                    if (unsafe { (*config).proxyuserpwd }).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                cleanarg(nextarg);
                current_block_1664 = 2210884902194999453;
            }
            118 => {
                if toggle {
                    (unsafe { free((*global).trace_dump as *mut libc::c_void) });
                    let mut fresh185 = unsafe { &mut ((*global).trace_dump) };
                    *fresh185 = 0 as *mut i8;
                    let mut fresh186 = unsafe { &mut ((*global).trace_dump) };
                    *fresh186 = unsafe { strdup(b"%\0" as *const u8 as *const i8) };
                    if (unsafe { (*global).trace_dump }).is_null() {
                        return PARAM_NO_MEM;
                    }
                    if (unsafe { (*global).tracetype }) as u32 != 0
                        && (unsafe { (*global).tracetype }) as u32 != TRACE_PLAIN as i32 as u32
                    {
                        (unsafe { warnf(
                            global,
                            b"-v, --verbose overrides an earlier trace/verbose option\n\0"
                                as *const u8 as *const i8,
                        ) });
                    }
                    (unsafe { (*global).tracetype = TRACE_PLAIN });
                } else {
                    (unsafe { (*global).tracetype = TRACE_NONE });
                }
                current_block_1664 = 2210884902194999453;
            }
            86 => {
                if toggle {
                    return PARAM_VERSION_INFO_REQUESTED;
                }
                current_block_1664 = 2210884902194999453;
            }
            119 => {
                if '@' as i32 == (unsafe { *nextarg }) as i32 {
                    let mut file_1: *mut crate::src::lib::http2::_IO_FILE = 0 as *mut FILE;
                    let mut fname: *const i8 = 0 as *const i8;
                    nextarg = unsafe { nextarg.offset(1) };
                    if (unsafe { strcmp(b"-\0" as *const u8 as *const i8, nextarg) }) == 0 {
                        fname = b"<stdin>\0" as *const u8 as *const i8;
                        file_1 = unsafe { stdin };
                    } else {
                        fname = nextarg;
                        file_1 = unsafe { fopen(nextarg, b"r\0" as *const u8 as *const i8) };
                    }
                    (unsafe { free((*config).writeout as *mut libc::c_void) });
                    let mut fresh187 = unsafe { &mut ((*config).writeout) };
                    *fresh187 = 0 as *mut i8;
                    err = file2string(Some(unsafe { &mut (*config).writeout }), file_1);
                    if !file_1.is_null() && file_1 != (unsafe { stdin }) {
                        (unsafe { fclose(file_1) });
                    }
                    if err as u64 != 0 {
                        return err;
                    }
                    if (unsafe { (*config).writeout }).is_null() {
                        (unsafe { warnf(
                            global,
                            b"Failed to read %s\0" as *const u8 as *const i8,
                            fname,
                        ) });
                    }
                } else {
                    if !(unsafe { (*config).writeout }).is_null() {
                        (unsafe { free((*config).writeout as *mut libc::c_void) });
                        let mut fresh188 = unsafe { &mut ((*config).writeout) };
                        *fresh188 = 0 as *mut i8;
                    }
                    if !nextarg.is_null() {
                        let mut fresh189 = unsafe { &mut ((*config).writeout) };
                        *fresh189 = unsafe { strdup(nextarg) };
                        if (unsafe { (*config).writeout }).is_null() {
                            return PARAM_NO_MEM;
                        }
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            120 => {
                match subletter as i32 {
                    97 => {
                        if !(unsafe { (*config).preproxy }).is_null() {
                            (unsafe { free((*config).preproxy as *mut libc::c_void) });
                            let mut fresh190 = unsafe { &mut ((*config).preproxy) };
                            *fresh190 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh191 = unsafe { &mut ((*config).preproxy) };
                            *fresh191 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).preproxy }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                    }
                    _ => {
                        if !(unsafe { (*config).proxy }).is_null() {
                            (unsafe { free((*config).proxy as *mut libc::c_void) });
                            let mut fresh192 = unsafe { &mut ((*config).proxy) };
                            *fresh192 = 0 as *mut i8;
                        }
                        if !nextarg.is_null() {
                            let mut fresh193 = unsafe { &mut ((*config).proxy) };
                            *fresh193 = unsafe { strdup(nextarg) };
                            if (unsafe { (*config).proxy }).is_null() {
                                return PARAM_NO_MEM;
                            }
                        }
                        (unsafe { (*config).proxyver = CURLPROXY_HTTP as i32 });
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            88 => {
                if !(unsafe { (*config).customrequest }).is_null() {
                    (unsafe { free((*config).customrequest as *mut libc::c_void) });
                    let mut fresh194 = unsafe { &mut ((*config).customrequest) };
                    *fresh194 = 0 as *mut i8;
                }
                if !nextarg.is_null() {
                    let mut fresh195 = unsafe { &mut ((*config).customrequest) };
                    *fresh195 = unsafe { strdup(nextarg) };
                    if (unsafe { (*config).customrequest }).is_null() {
                        return PARAM_NO_MEM;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            121 => {
                err = str2unum(Some(unsafe { &mut (*config).low_speed_time }), nextarg);
                if err as u64 != 0 {
                    return err;
                }
                if (unsafe { (*config).low_speed_limit }) == 0 {
                    (unsafe { (*config).low_speed_limit = 1 as i32 as i64 });
                }
                current_block_1664 = 2210884902194999453;
            }
            89 => {
                err = str2unum(Some(unsafe { &mut (*config).low_speed_limit }), nextarg);
                if err as u64 != 0 {
                    return err;
                }
                if (unsafe { (*config).low_speed_time }) == 0 {
                    (unsafe { (*config).low_speed_time = 30 as i32 as i64 });
                }
                current_block_1664 = 2210884902194999453;
            }
            90 => {
                match subletter as i32 {
                    0 => {
                        (unsafe { (*global).parallel = toggle });
                    }
                    98 => {
                        err = str2unum(Some(unsafe { &mut (*global).parallel_max }), nextarg);
                        if err as u64 != 0 {
                            return err;
                        }
                        if (unsafe { (*global).parallel_max }) > 300 as i32 as i64
                            || (unsafe { (*global).parallel_max }) < 1 as i32 as i64
                        {
                            (unsafe { (*global).parallel_max = 50 as i32 as i64 });
                        }
                    }
                    99 => {
                        (unsafe { (*global).parallel_connect = toggle });
                    }
                    _ => {}
                }
                current_block_1664 = 2210884902194999453;
            }
            122 => {
                let mut current_block_1652: u64;
                match (unsafe { *nextarg }) as i32 {
                    43 => {
                        nextarg = unsafe { nextarg.offset(1) };
                        current_block_1652 = 17551501277733230131;
                    }
                    45 => {
                        (unsafe { (*config).timecond = CURL_TIMECOND_IFUNMODSINCE });
                        nextarg = unsafe { nextarg.offset(1) };
                        current_block_1652 = 3197977965602298108;
                    }
                    61 => {
                        (unsafe { (*config).timecond = CURL_TIMECOND_LASTMOD });
                        nextarg = unsafe { nextarg.offset(1) };
                        current_block_1652 = 3197977965602298108;
                    }
                    _ => {
                        current_block_1652 = 17551501277733230131;
                    }
                }
                match current_block_1652 {
                    17551501277733230131 => {
                        (unsafe { (*config).timecond = CURL_TIMECOND_IFMODSINCE });
                    }
                    _ => {}
                }
                now = unsafe { time(0 as *mut time_t) };
                (unsafe { (*config).condtime = curl_getdate(nextarg, Some(&mut now)) });
                if -(1 as i32) as i64 == (unsafe { (*config).condtime }) {
                    let mut filetime: i64 = getfiletime(nextarg, global);
                    if filetime >= 0 as i32 as i64 {
                        (unsafe { (*config).condtime = filetime });
                    } else {
                        (unsafe { (*config).timecond = CURL_TIMECOND_NONE });
                        (unsafe { warnf (global , b"Illegal date format for -z, --time-cond (and not a file name). Disabling time condition. See curl_getdate(3) for valid date syntax.\n\0" as * const u8 as * const i8 ,) }) ;
                    }
                }
                current_block_1664 = 2210884902194999453;
            }
            _ => return PARAM_OPTION_UNKNOWN,
        }
        match current_block_1664 {
            11000567119642394172 => {
                let mut url_0: *mut crate::src::src::tool_cb_dbg::getout = 0 as *mut getout;
                if (unsafe { (*config).url_out }).is_null() {
                    let mut fresh162 = unsafe { &mut ((*config).url_out) };
                    *fresh162 = unsafe { (*config).url_list };
                }
                if !(unsafe { (*config).url_out }).is_null() {
                    while !(unsafe { (*config).url_out }).is_null()
                        && (unsafe { (*(*config).url_out).flags }) & (1 as i32) << 0 as i32 != 0
                    {
                        let mut fresh163 = unsafe { &mut ((*config).url_out) };
                        *fresh163 = unsafe { (*(*config).url_out).next };
                    }
                }
                if !(unsafe { (*config).url_out }).is_null() {
                    url_0 = unsafe { (*config).url_out };
                } else {
                    url_0 = new_getout(config);
                    let mut fresh164 = unsafe { &mut ((*config).url_out) };
                    *fresh164 = url_0;
                }
                if url_0.is_null() {
                    return PARAM_NO_MEM;
                }
                if 'o' as i32 == letter as i32 {
                    if !(unsafe { (*url_0).outfile }).is_null() {
                        (unsafe { free((*url_0).outfile as *mut libc::c_void) });
                        let mut fresh165 = unsafe { &mut ((*url_0).outfile) };
                        *fresh165 = 0 as *mut i8;
                    }
                    if !nextarg.is_null() {
                        let mut fresh166 = unsafe { &mut ((*url_0).outfile) };
                        *fresh166 = unsafe { strdup(nextarg) };
                        if (unsafe { (*url_0).outfile }).is_null() {
                            return PARAM_NO_MEM;
                        }
                    }
                    (unsafe { (*url_0).flags &= !((1 as i32) << 2 as i32) });
                } else {
                    let mut fresh167 = unsafe { &mut ((*url_0).outfile) };
                    *fresh167 = 0 as *mut i8;
                    if toggle {
                        (unsafe { (*url_0).flags |= (1 as i32) << 2 as i32 });
                    } else {
                        (unsafe { (*url_0).flags &= !((1 as i32) << 2 as i32) });
                    }
                }
                (unsafe { (*url_0).flags |= (1 as i32) << 0 as i32 });
            }
            _ => {}
        }
        hit = -(1 as i32);
        if !(!longopt
            && !singleopt
            && {
                parse = unsafe { parse.offset(1) };
                (unsafe { *parse }) as i32 != 0
            }
            && !*(borrow(&usedarg)).unwrap())
        {
            break;
        }
    }
    return PARAM_OK;
}
#[no_mangle]
pub extern "C" fn parse_args(
    mut global: *mut crate::src::src::tool_cb_dbg::GlobalConfig,
    mut argc: i32,
    mut argv: *mut *mut i8,
) -> u32 {
    let mut i: i32 = 0;
    let mut stillflags: bool = false;
    let mut orig_opt: *mut i8 = 0 as *mut i8;
    let mut result: u32 = PARAM_OK;
    let mut config: *mut crate::src::src::tool_cb_dbg::OperationConfig = unsafe { (*global).first };
    i = 1 as i32;
    stillflags = 1 as i32 != 0;
    while i < argc && result as u64 == 0 {
        orig_opt = unsafe { strdup(*argv.offset(i as isize)) };
        if orig_opt.is_null() {
            return PARAM_NO_MEM;
        }
        if stillflags as i32 != 0 && '-' as i32 == (unsafe { *orig_opt.offset(0 as i32 as isize) }) as i32 {
            let mut passarg: bool = false;
            if (unsafe { strcmp(b"--\0" as *const u8 as *const i8, orig_opt) }) == 0 {
                stillflags = 0 as i32 != 0;
            } else {
                let mut nextarg: *mut i8 = if i < argc - 1 as i32 {
                    unsafe { strdup(*argv.offset((i + 1 as i32) as isize)) }
                } else {
                    0 as *mut i8
                };
                result = getparameter(orig_opt, nextarg, Some(&mut passarg), global, config);
                if !nextarg.is_null() {
                    (unsafe { free(nextarg as *mut libc::c_void) });
                    nextarg = 0 as *mut i8;
                }
                config = unsafe { (*global).last };
                if result as u32 == PARAM_NEXT_OPERATION as i32 as u32 {
                    result = PARAM_OK;
                    if !(unsafe { (*config).url_list }).is_null() && !(unsafe { (*(*config).url_list).url }).is_null() {
                        let mut fresh196 = unsafe { &mut ((*config).next) };
                        *fresh196 = (unsafe { malloc(::std::mem::size_of::<OperationConfig>() as u64) })
                            as *mut OperationConfig;
                        if !(unsafe { (*config).next }).is_null() {
                            config_init(unsafe { (*config).next });
                            let mut fresh197 = unsafe { &mut ((*(*config).next).global) };
                            *fresh197 = global;
                            let mut fresh198 = unsafe { &mut ((*global).last) };
                            *fresh198 = unsafe { (*config).next };
                            let mut fresh199 = unsafe { &mut ((*(*config).next).prev) };
                            *fresh199 = config;
                            config = unsafe { (*config).next };
                        } else {
                            result = PARAM_NO_MEM;
                        }
                    }
                } else if result as u64 == 0 && passarg as i32 != 0 {
                    i += 1;
                }
            }
        } else {
            let mut used: bool = false;
            result = getparameter(
                b"--url\0" as *const u8 as *const i8,
                orig_opt,
                Some(&mut used),
                global,
                config,
            );
        }
        if result as u64 == 0 {
            if !orig_opt.is_null() {
                (unsafe { free(orig_opt as *mut libc::c_void) });
                orig_opt = 0 as *mut i8;
            }
        }
        i += 1;
    }
    if result as u64 == 0 && (unsafe { (*config).content_disposition }) as i32 != 0 {
        if unsafe { (*config).show_headers } {
            result = PARAM_CONTDISP_SHOW_HEADER;
        } else if unsafe { (*config).resume_from_current } {
            result = PARAM_CONTDISP_RESUME_FROM;
        }
    }
    if result as u32 != 0
        && result as u32 != PARAM_HELP_REQUESTED as i32 as u32
        && result as u32 != PARAM_MANUAL_REQUESTED as i32 as u32
        && result as u32 != PARAM_VERSION_INFO_REQUESTED as i32 as u32
        && result as u32 != PARAM_ENGINES_REQUESTED as i32 as u32
    {
        let mut reason: *const i8 = param2text(result as i32);
        if !orig_opt.is_null() && (unsafe { strcmp(b":\0" as *const u8 as *const i8, orig_opt) }) != 0 {
            (unsafe { helpf(
                (*global).errors,
                b"option %s: %s\n\0" as *const u8 as *const i8,
                orig_opt,
                reason,
            ) });
        } else {
            (unsafe { helpf(
                (*global).errors,
                b"%s\n\0" as *const u8 as *const i8,
                reason,
            ) });
        }
    }
    if !orig_opt.is_null() {
        (unsafe { free(orig_opt as *mut libc::c_void) });
        orig_opt = 0 as *mut i8;
    }
    return result;
}
use crate::laertes_rt::*;
