use :: libc;
extern "C" {
    static mut stdout: *mut crate::src::lib::http2::_IO_FILE;
    fn sprintf(_: *mut i8, _: *const i8, _: ...) -> i32;
    fn fputc(__c: i32, __stream: *mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn strtol(_: *const i8, _: *mut *mut i8, _: i32) -> i64;
    fn strlen(_: *const i8) -> u64;
}
pub use crate::src::lib::curl_ctype::Curl_isdigit;
pub use crate::src::lib::dynbuf::Curl_dyn_addn;
pub use crate::src::lib::dynbuf::Curl_dyn_free;
pub use crate::src::lib::dynbuf::Curl_dyn_init;
pub use crate::src::lib::dynbuf::Curl_dyn_len;
pub use crate::src::lib::dynbuf::Curl_dyn_ptr;
pub use crate::src::lib::easy::Curl_cstrdup;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub type __builtin_va_list = [crate::src::lib::dict::__va_list_tag; 1];
pub type __va_list_tag = crate::src::lib::dict::__va_list_tag;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type size_t = u64;
pub type va_list = [crate::src::lib::dict::__va_list_tag; 1];
pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::lib::http2::_IO_FILE;
pub type curl_strdup_callback<'a1, 'a2> =
    Option<unsafe extern "C" fn(_: Option<&'a1 i8>) -> Option<&'a2 mut i8>>;
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
pub type dynbuf = crate::src::lib::http2::dynbuf;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asprintf {
    pub b: *mut crate::src::lib::http2::dynbuf,
    pub fail: bool,
}
impl asprintf {
    pub const fn new() -> Self {
        asprintf {
            b: (0 as *mut crate::src::lib::http2::dynbuf),
            fail: false,
        }
    }
}
impl std::default::Default for asprintf {
    fn default() -> Self {
        asprintf::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub str_0: *mut i8,
    pub ptr: *mut libc::c_void,
    pub num: C2RustUnnamed_0,
    pub dnum: f64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub as_signed: i64,
    pub as_unsigned: u64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct va_stack {
    pub type_0: u32,
    pub flags: i32,
    pub width: i64,
    pub precision: i64,
    pub data: crate::src::lib::mprintf::C2RustUnnamed,
}
pub type FormatType = u32;
pub const FORMAT_WIDTH: FormatType = 9;
pub const FORMAT_LONGDOUBLE: FormatType = 8;
pub const FORMAT_DOUBLE: FormatType = 7;
pub const FORMAT_LONGLONG: FormatType = 6;
pub const FORMAT_LONG: FormatType = 5;
pub const FORMAT_INTPTR: FormatType = 4;
pub const FORMAT_INT: FormatType = 3;
pub const FORMAT_PTR: FormatType = 2;
pub const FORMAT_STRING: FormatType = 1;
pub const FORMAT_UNKNOWN: FormatType = 0;
pub const FLAGS_SHORT: C2RustUnnamed_1 = 16;
pub const FLAGS_LONG: C2RustUnnamed_1 = 32;
pub const FLAGS_LONGLONG: C2RustUnnamed_1 = 64;
pub const FLAGS_UPPER: C2RustUnnamed_1 = 4096;
pub const FLAGS_FLOATG: C2RustUnnamed_1 = 524288;
pub const FLAGS_FLOATE: C2RustUnnamed_1 = 262144;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nsprintf {
    pub buffer: *mut i8,
    pub length: u64,
    pub max: u64,
}
impl nsprintf {
    pub const fn new() -> Self {
        nsprintf {
            buffer: (0 as *mut i8),
            length: 0,
            max: 0,
        }
    }
}
impl std::default::Default for nsprintf {
    fn default() -> Self {
        nsprintf::new()
    }
}
pub const FLAGS_ALT: C2RustUnnamed_1 = 8;
pub const FLAGS_SPACE: C2RustUnnamed_1 = 1;
pub const FLAGS_SHOWSIGN: C2RustUnnamed_1 = 2;
pub const FLAGS_LEFT: C2RustUnnamed_1 = 4;
pub const FLAGS_PRECPARAM: C2RustUnnamed_1 = 65536;
pub const FLAGS_PREC: C2RustUnnamed_1 = 32768;
pub const FLAGS_WIDTHPARAM: C2RustUnnamed_1 = 16384;
pub const FLAGS_WIDTH: C2RustUnnamed_1 = 8192;
pub const FLAGS_PAD_NIL: C2RustUnnamed_1 = 256;
pub const FLAGS_UNSIGNED: C2RustUnnamed_1 = 512;
pub const FLAGS_HEX: C2RustUnnamed_1 = 2048;
pub const FLAGS_OCTAL: C2RustUnnamed_1 = 1024;
pub const FLAGS_CHAR: C2RustUnnamed_1 = 131072;
pub const FLAGS_NEW: C2RustUnnamed_1 = 0;
pub const FLAGS_LONGDOUBLE: C2RustUnnamed_1 = 128;
pub type C2RustUnnamed_1 = u32;
static mut lower_digits: [i8; 37] = unsafe {
    *core::intrinsics::transmute::<&'_ [u8; 37], &'_ [i8; 37]>(
        b"0123456789abcdefghijklmnopqrstuvwxyz\0",
    )
};
static mut upper_digits: [i8; 37] = unsafe {
    *core::intrinsics::transmute::<&'_ [u8; 37], &'_ [i8; 37]>(
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\0",
    )
};
extern "C" fn dprintf_DollarString<'a1>(
    mut input: *mut i8,
    mut end: Option<&'a1 mut *mut i8>,
) -> i64 {
    let mut number: i32 = 0 as i32;
    while Curl_isdigit((unsafe { *input }) as u8 as i32) != 0 {
        if number < 128 as i32 {
            number *= 10 as i32;
            number += (unsafe { *input }) as i32 - '0' as i32;
        }
        input = unsafe { input.offset(1) };
    }
    if number <= 128 as i32 && '$' as i32 == (unsafe { *input }) as i32 {
        input = unsafe { input.offset(1) };
        *(borrow_mut(&mut end)).unwrap() = input;
        return number as i64;
    }
    return 0 as i32 as i64;
}
extern "C" fn dprintf_IsQualifierNoDollar(mut fmt: *const i8) -> bool {
    match (unsafe { *fmt }) as i32 {
        45 | 43 | 32 | 35 | 46 | 48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 | 56 | 57 | 104 | 108
        | 76 | 122 | 113 | 42 | 79 => return 1 as i32 != 0,
        _ => return 0 as i32 != 0,
    };
}
extern "C" fn dprintf_Pass1(
    mut format: *const i8,
    mut vto: *mut crate::src::lib::mprintf::va_stack,
    mut endpos: *mut *mut i8,
    mut arglist: core::ffi::VaList,
) -> i32 {
    let mut fmt: *mut i8 = format as *mut i8;
    let mut param_num: i32 = 0 as i32;
    let mut this_param: i64 = 0;
    let mut width: i64 = 0;
    let mut precision: i64 = 0;
    let mut flags: i32 = 0;
    let mut max_param: i64 = 0 as i32 as i64;
    let mut i: i64 = 0;
    while (unsafe { *fmt }) != 0 {
        let mut fresh0 = fmt;
        fmt = unsafe { fmt.offset(1) };
        if !((unsafe { *fresh0 }) as i32 == '%' as i32) {
            continue;
        }
        if (unsafe { *fmt }) as i32 == '%' as i32 {
            fmt = unsafe { fmt.offset(1) };
        } else {
            flags = FLAGS_NEW as i32;
            param_num += 1;
            this_param = dprintf_DollarString(fmt, Some(&mut fmt));
            if 0 as i32 as i64 == this_param {
                this_param = param_num as i64;
            }
            if this_param > max_param {
                max_param = this_param;
            }
            width = 0 as i32 as i64;
            precision = 0 as i32 as i64;
            while dprintf_IsQualifierNoDollar(fmt) {
                let mut current_block_49: u64;
                let mut fresh1 = fmt;
                fmt = unsafe { fmt.offset(1) };
                match (unsafe { *fresh1 }) as i32 {
                    32 => {
                        flags |= FLAGS_SPACE as i32;
                        current_block_49 = 13660591889533726445;
                    }
                    43 => {
                        flags |= FLAGS_SHOWSIGN as i32;
                        current_block_49 = 13660591889533726445;
                    }
                    45 => {
                        flags |= FLAGS_LEFT as i32;
                        flags &= !(FLAGS_PAD_NIL as i32);
                        current_block_49 = 13660591889533726445;
                    }
                    35 => {
                        flags |= FLAGS_ALT as i32;
                        current_block_49 = 13660591889533726445;
                    }
                    46 => {
                        if '*' as i32 == (unsafe { *fmt }) as i32 {
                            flags |= FLAGS_PRECPARAM as i32;
                            fmt = unsafe { fmt.offset(1) };
                            param_num += 1;
                            i = dprintf_DollarString(fmt, Some(&mut fmt));
                            if i != 0 {
                                precision = i;
                            } else {
                                precision = param_num as i64;
                            }
                            if precision > max_param {
                                max_param = precision;
                            }
                        } else {
                            flags |= FLAGS_PREC as i32;
                            precision = unsafe { strtol(fmt, &mut fmt, 10 as i32) };
                        }
                        current_block_49 = 13660591889533726445;
                    }
                    104 => {
                        flags |= FLAGS_SHORT as i32;
                        current_block_49 = 13660591889533726445;
                    }
                    108 => {
                        if flags & FLAGS_LONG as i32 != 0 {
                            flags |= FLAGS_LONGLONG as i32;
                        } else {
                            flags |= FLAGS_LONG as i32;
                        }
                        current_block_49 = 13660591889533726445;
                    }
                    76 => {
                        flags |= FLAGS_LONGDOUBLE as i32;
                        current_block_49 = 13660591889533726445;
                    }
                    113 => {
                        flags |= FLAGS_LONGLONG as i32;
                        current_block_49 = 13660591889533726445;
                    }
                    122 => {
                        flags |= FLAGS_LONG as i32;
                        current_block_49 = 13660591889533726445;
                    }
                    79 => {
                        flags |= FLAGS_LONG as i32;
                        current_block_49 = 13660591889533726445;
                    }
                    48 => {
                        if flags & FLAGS_LEFT as i32 == 0 {
                            flags |= FLAGS_PAD_NIL as i32;
                        }
                        current_block_49 = 5374592581586135578;
                    }
                    49 | 50 | 51 | 52 | 53 | 54 | 55 | 56 | 57 => {
                        current_block_49 = 5374592581586135578;
                    }
                    42 => {
                        flags |= FLAGS_WIDTHPARAM as i32;
                        param_num += 1;
                        i = dprintf_DollarString(fmt, Some(&mut fmt));
                        if i != 0 {
                            width = i;
                        } else {
                            width = param_num as i64;
                        }
                        if width > max_param {
                            max_param = width;
                        }
                        current_block_49 = 13660591889533726445;
                    }
                    0 => {
                        fmt = unsafe { fmt.offset(-1) };
                        current_block_49 = 13660591889533726445;
                    }
                    _ => {
                        current_block_49 = 13660591889533726445;
                    }
                }
                match current_block_49 {
                    5374592581586135578 => {
                        flags |= FLAGS_WIDTH as i32;
                        width = unsafe { strtol(fmt.offset(-(1 as i32 as isize)), &mut fmt, 10 as i32) };
                    }
                    _ => {}
                }
            }
            i = this_param - 1 as i32 as i64;
            if i < 0 as i32 as i64 || i >= 128 as i32 as i64 {
                return 1 as i32;
            }
            let mut current_block_80: u64;
            match (unsafe { *fmt }) as i32 {
                83 => {
                    flags |= FLAGS_ALT as i32;
                    current_block_80 = 6189188494327942084;
                }
                115 => {
                    current_block_80 = 6189188494327942084;
                }
                110 => {
                    (unsafe { (*vto.offset(i as isize)).type_0 = FORMAT_INTPTR });
                    current_block_80 = 14155412868135599428;
                }
                112 => {
                    (unsafe { (*vto.offset(i as isize)).type_0 = FORMAT_PTR });
                    current_block_80 = 14155412868135599428;
                }
                100 | 105 => {
                    (unsafe { (*vto.offset(i as isize)).type_0 = FORMAT_INT });
                    current_block_80 = 14155412868135599428;
                }
                117 => {
                    (unsafe { (*vto.offset(i as isize)).type_0 = FORMAT_INT });
                    flags |= FLAGS_UNSIGNED as i32;
                    current_block_80 = 14155412868135599428;
                }
                111 => {
                    (unsafe { (*vto.offset(i as isize)).type_0 = FORMAT_INT });
                    flags |= FLAGS_OCTAL as i32;
                    current_block_80 = 14155412868135599428;
                }
                120 => {
                    (unsafe { (*vto.offset(i as isize)).type_0 = FORMAT_INT });
                    flags |= FLAGS_HEX as i32 | FLAGS_UNSIGNED as i32;
                    current_block_80 = 14155412868135599428;
                }
                88 => {
                    (unsafe { (*vto.offset(i as isize)).type_0 = FORMAT_INT });
                    flags |= FLAGS_HEX as i32 | FLAGS_UPPER as i32 | FLAGS_UNSIGNED as i32;
                    current_block_80 = 14155412868135599428;
                }
                99 => {
                    (unsafe { (*vto.offset(i as isize)).type_0 = FORMAT_INT });
                    flags |= FLAGS_CHAR as i32;
                    current_block_80 = 14155412868135599428;
                }
                102 => {
                    (unsafe { (*vto.offset(i as isize)).type_0 = FORMAT_DOUBLE });
                    current_block_80 = 14155412868135599428;
                }
                101 => {
                    (unsafe { (*vto.offset(i as isize)).type_0 = FORMAT_DOUBLE });
                    flags |= FLAGS_FLOATE as i32;
                    current_block_80 = 14155412868135599428;
                }
                69 => {
                    (unsafe { (*vto.offset(i as isize)).type_0 = FORMAT_DOUBLE });
                    flags |= FLAGS_FLOATE as i32 | FLAGS_UPPER as i32;
                    current_block_80 = 14155412868135599428;
                }
                103 => {
                    (unsafe { (*vto.offset(i as isize)).type_0 = FORMAT_DOUBLE });
                    flags |= FLAGS_FLOATG as i32;
                    current_block_80 = 14155412868135599428;
                }
                71 => {
                    (unsafe { (*vto.offset(i as isize)).type_0 = FORMAT_DOUBLE });
                    flags |= FLAGS_FLOATG as i32 | FLAGS_UPPER as i32;
                    current_block_80 = 14155412868135599428;
                }
                _ => {
                    (unsafe { (*vto.offset(i as isize)).type_0 = FORMAT_UNKNOWN });
                    current_block_80 = 14155412868135599428;
                }
            }
            match current_block_80 {
                6189188494327942084 => {
                    (unsafe { (*vto.offset(i as isize)).type_0 = FORMAT_STRING });
                }
                _ => {}
            }
            (unsafe { (*vto.offset(i as isize)).flags = flags });
            (unsafe { (*vto.offset(i as isize)).width = width });
            (unsafe { (*vto.offset(i as isize)).precision = precision });
            if flags & FLAGS_WIDTHPARAM as i32 != 0 {
                let mut k: i64 = width - 1 as i32 as i64;
                if k < 0 as i32 as i64 || k >= 128 as i32 as i64 {
                    return 1 as i32;
                }
                (unsafe { (*vto.offset(i as isize)).width = k });
                (unsafe { (*vto.offset(k as isize)).type_0 = FORMAT_WIDTH });
                (unsafe { (*vto.offset(k as isize)).flags = FLAGS_NEW as i32 });
                (unsafe { (*vto.offset(k as isize)).width = 0 as i32 as i64 });
                (unsafe { (*vto.offset(k as isize)).precision = 0 as i32 as i64 });
            }
            if flags & FLAGS_PRECPARAM as i32 != 0 {
                let mut k_0: i64 = precision - 1 as i32 as i64;
                if k_0 < 0 as i32 as i64 || k_0 >= 128 as i32 as i64 {
                    return 1 as i32;
                }
                (unsafe { (*vto.offset(i as isize)).precision = k_0 });
                (unsafe { (*vto.offset(k_0 as isize)).type_0 = FORMAT_WIDTH });
                (unsafe { (*vto.offset(k_0 as isize)).flags = FLAGS_NEW as i32 });
                (unsafe { (*vto.offset(k_0 as isize)).width = 0 as i32 as i64 });
                (unsafe { (*vto.offset(k_0 as isize)).precision = 0 as i32 as i64 });
            }
            let mut fresh2 = endpos;
            endpos = unsafe { endpos.offset(1) };
            (unsafe { *fresh2 = fmt.offset(
                (if *fmt as i32 == '\u{0}' as i32 {
                    0 as i32
                } else {
                    1 as i32
                }) as isize,
            ) });
        }
    }
    i = 0 as i32 as i64;
    while i < max_param {
        if (unsafe { (*vto.offset(i as isize)).flags }) & FLAGS_WIDTHPARAM as i32 != 0 {
            (unsafe { (*vto.offset((*vto.offset(i as isize)).width as isize))
                .data
                .num
                .as_signed = arglist.arg::<i32>() as i64 });
        }
        if (unsafe { (*vto.offset(i as isize)).flags }) & FLAGS_PRECPARAM as i32 != 0 {
            (unsafe { (*vto.offset((*vto.offset(i as isize)).precision as isize))
                .data
                .num
                .as_signed = arglist.arg::<i32>() as i64 });
        }
        match (unsafe { (*vto.offset(i as isize)).type_0 }) as u32 {
            1 => {
                let mut fresh3 = unsafe { &mut ((*vto.offset(i as isize)).data.str_0) };
                *fresh3 = unsafe { arglist.arg::<*mut i8>() };
            }
            4 | 0 | 2 => {
                let mut fresh4 = unsafe { &mut ((*vto.offset(i as isize)).data.ptr) };
                *fresh4 = unsafe { arglist.arg::<*mut libc::c_void>() };
            }
            3 => {
                if (unsafe { (*vto.offset(i as isize)).flags }) & FLAGS_LONGLONG as i32 != 0
                    && (unsafe { (*vto.offset(i as isize)).flags }) & FLAGS_UNSIGNED as i32 != 0
                {
                    (unsafe { (*vto.offset(i as isize)).data.num.as_unsigned = arglist.arg::<u64>() });
                } else if (unsafe { (*vto.offset(i as isize)).flags }) & FLAGS_LONGLONG as i32 != 0 {
                    (unsafe { (*vto.offset(i as isize)).data.num.as_signed = arglist.arg::<i64>() });
                } else if (unsafe { (*vto.offset(i as isize)).flags }) & FLAGS_LONG as i32 != 0
                    && (unsafe { (*vto.offset(i as isize)).flags }) & FLAGS_UNSIGNED as i32 != 0
                {
                    (unsafe { (*vto.offset(i as isize)).data.num.as_unsigned = arglist.arg::<u64>() as u64 });
                } else if (unsafe { (*vto.offset(i as isize)).flags }) & FLAGS_LONG as i32 != 0 {
                    (unsafe { (*vto.offset(i as isize)).data.num.as_signed = arglist.arg::<i64>() as i64 });
                } else if (unsafe { (*vto.offset(i as isize)).flags }) & FLAGS_UNSIGNED as i32 != 0 {
                    (unsafe { (*vto.offset(i as isize)).data.num.as_unsigned = arglist.arg::<u32>() as u64 });
                } else {
                    (unsafe { (*vto.offset(i as isize)).data.num.as_signed = arglist.arg::<i32>() as i64 });
                }
            }
            7 => {
                (unsafe { (*vto.offset(i as isize)).data.dnum = arglist.arg::<f64>() });
            }
            9 => {
                (unsafe { (*vto.offset(i as isize)).type_0 = FORMAT_INT });
            }
            _ => {}
        }
        i += 1;
    }
    return 0 as i32;
}
extern "C" fn dprintf_formatf(
    mut data: *mut core::ffi::c_void,
    mut stream: Option<
        unsafe extern "C" fn(_: i32, _: *mut crate::src::lib::http2::_IO_FILE) -> i32,
    >,
    mut format: *const i8,
    mut ap_save: core::ffi::VaList,
) -> i32 {
    let mut current_block: u64;
    let mut digits: *const i8 = unsafe { lower_digits.as_ptr() };
    let mut f: *mut i8 = 0 as *mut i8;
    let mut done: i32 = 0 as i32;
    let mut param: i64 = 0;
    let mut param_num: i64 = 0 as i32 as i64;
    let mut vto: [crate::src::lib::mprintf::va_stack; 128] = [va_stack {
        type_0: FORMAT_UNKNOWN,
        flags: 0,
        width: 0,
        precision: 0,
        data: C2RustUnnamed {
            str_0: 0 as *mut i8,
        },
    }; 128];
    let mut endpos: [*mut i8; 128] = [0 as *mut i8; 128];
    let mut end: *mut *mut i8 = 0 as *mut *mut i8;
    let mut work: [i8; 326] = [0; 326];
    let mut p: Option<&'_ mut crate::src::lib::mprintf::va_stack> =
        Option::<&'_ mut crate::src::lib::mprintf::va_stack>::None;
    let mut workend: *mut i8 = (unsafe { &mut *work
        .as_mut_ptr()
        .offset((::std::mem::size_of::<[i8; 326]>() as u64).wrapping_sub(2 as i32 as u64) as isize) })
        as *mut i8;
    if dprintf_Pass1(
        format,
        vto.as_mut_ptr(),
        endpos.as_mut_ptr(),
        ap_save.as_va_list(),
    ) != 0
    {
        return -(1 as i32);
    }
    end = (unsafe { &mut *endpos.as_mut_ptr().offset(0 as i32 as isize) }) as *mut *mut i8;
    f = format as *mut i8;
    while (unsafe { *f }) as i32 != '\u{0}' as i32 {
        let mut is_alt: i32 = 0;
        let mut width: i64 = 0;
        let mut prec: i64 = 0;
        let mut is_neg: i32 = 0;
        let mut base: u64 = 0;
        let mut num: u64 = 0;
        let mut signed_num: i64 = 0;
        let mut w: *mut i8 = 0 as *mut i8;
        if (unsafe { *f }) as i32 != '%' as i32 {
            loop {
                if (unsafe { stream.expect("non-null function pointer")(*f as u8 as i32, data as *mut FILE) })
                    != -(1 as i32)
                {
                    done += 1;
                } else {
                    return done;
                }
                f = unsafe { f.offset(1) };
                if !((unsafe { *f }) as i32 != 0 && '%' as i32 != (unsafe { *f }) as i32) {
                    break;
                }
            }
        } else {
            f = unsafe { f.offset(1) };
            if (unsafe { *f }) as i32 == '%' as i32 {
                f = unsafe { f.offset(1) };
                if (unsafe { stream.expect("non-null function pointer")(
                    '%' as i32 as u8 as i32,
                    data as *mut FILE,
                ) }) != -(1 as i32)
                {
                    done += 1;
                } else {
                    return done;
                }
            } else {
                param = dprintf_DollarString(f, Some(&mut f));
                if param == 0 {
                    param = param_num;
                } else {
                    param -= 1;
                }
                param_num += 1;
                p = Some(unsafe { &mut *vto.as_mut_ptr().offset(param as isize) });
                if (*(borrow(&p)).unwrap()).flags & FLAGS_WIDTHPARAM as i32 != 0 {
                    width = (unsafe { vto[(*(borrow(&p)).unwrap()).width as usize]
                        .data
                        .num
                        .as_signed }) as i64;
                    param_num += 1;
                    if width < 0 as i32 as i64 {
                        width = -width;
                        (*(borrow_mut(&mut p)).unwrap()).flags |= FLAGS_LEFT as i32;
                        (*(borrow_mut(&mut p)).unwrap()).flags &= !(FLAGS_PAD_NIL as i32);
                    }
                } else {
                    width = (*(borrow_mut(&mut p)).unwrap()).width;
                }
                if (*(borrow(&p)).unwrap()).flags & FLAGS_PRECPARAM as i32 != 0 {
                    prec = (unsafe { vto[(*(borrow(&p)).unwrap()).precision as usize]
                        .data
                        .num
                        .as_signed }) as i64;
                    param_num += 1;
                    if prec < 0 as i32 as i64 {
                        prec = -(1 as i32) as i64;
                    }
                } else if (*(borrow(&p)).unwrap()).flags & FLAGS_PREC as i32 != 0 {
                    prec = (*(borrow_mut(&mut p)).unwrap()).precision;
                } else {
                    prec = -(1 as i32) as i64;
                }
                is_alt = if (*(borrow(&p)).unwrap()).flags & FLAGS_ALT as i32 != 0 {
                    1 as i32
                } else {
                    0 as i32
                };
                match (*(borrow(&p)).unwrap()).type_0 as u32 {
                    3 => {
                        num = unsafe { (*(borrow_mut(&mut p)).unwrap()).data.num.as_unsigned };
                        if (*(borrow(&p)).unwrap()).flags & FLAGS_CHAR as i32 != 0 {
                            if (*(borrow(&p)).unwrap()).flags & FLAGS_LEFT as i32 == 0 {
                                loop {
                                    width -= 1;
                                    if !(width > 0 as i32 as i64) {
                                        break;
                                    }
                                    if (unsafe { stream.expect("non-null function pointer")(
                                        ' ' as i32 as u8 as i32,
                                        data as *mut FILE,
                                    ) }) != -(1 as i32)
                                    {
                                        done += 1;
                                    } else {
                                        return done;
                                    }
                                }
                            }
                            if (unsafe { stream.expect("non-null function pointer")(
                                num as i8 as u8 as i32,
                                data as *mut FILE,
                            ) }) != -(1 as i32)
                            {
                                done += 1;
                            } else {
                                return done;
                            }
                            if (*(borrow(&p)).unwrap()).flags & FLAGS_LEFT as i32 != 0 {
                                loop {
                                    width -= 1;
                                    if !(width > 0 as i32 as i64) {
                                        break;
                                    }
                                    if (unsafe { stream.expect("non-null function pointer")(
                                        ' ' as i32 as u8 as i32,
                                        data as *mut FILE,
                                    ) }) != -(1 as i32)
                                    {
                                        done += 1;
                                    } else {
                                        return done;
                                    }
                                }
                            }
                            current_block = 9657238515557273331;
                        } else {
                            if (*(borrow(&p)).unwrap()).flags & FLAGS_OCTAL as i32 != 0 {
                                base = 8 as i32 as u64;
                                current_block = 924752235070135112;
                            } else if (*(borrow(&p)).unwrap()).flags & FLAGS_HEX as i32 != 0 {
                                digits = if (*(borrow(&p)).unwrap()).flags & FLAGS_UPPER as i32 != 0
                                {
                                    unsafe { upper_digits.as_ptr() }
                                } else {
                                    unsafe { lower_digits.as_ptr() }
                                };
                                base = 16 as i32 as u64;
                                current_block = 924752235070135112;
                            } else if (*(borrow(&p)).unwrap()).flags & FLAGS_UNSIGNED as i32 != 0 {
                                base = 10 as i32 as u64;
                                current_block = 924752235070135112;
                            } else {
                                base = 10 as i32 as u64;
                                is_neg = if (unsafe { (*(borrow(&p)).unwrap()).data.num.as_signed })
                                    < 0 as i32 as i64
                                {
                                    1 as i32
                                } else {
                                    0 as i32
                                };
                                if is_neg != 0 {
                                    signed_num = (unsafe { (*(borrow(&p)).unwrap()).data.num.as_signed })
                                        + 1 as i32 as i64;
                                    signed_num = -signed_num;
                                    num = signed_num as u64;
                                    num = num.wrapping_add(1 as i32 as u64);
                                }
                                current_block = 7867894563361037860;
                            }
                            match current_block {
                                7867894563361037860 => {}
                                _ => {
                                    is_neg = 0 as i32;
                                    current_block = 7867894563361037860;
                                }
                            }
                        }
                    }
                    1 => {
                        static mut null: [i8; 6] = unsafe {
                            *core::intrinsics::transmute::<&'_ [u8; 6], &'_ [i8; 6]>(b"(nil)\0")
                        };
                        let mut str: *const i8 = 0 as *const i8;
                        let mut len: u64 = 0;
                        str = unsafe { (*(borrow(&p)).unwrap()).data.str_0 };
                        if str.is_null() {
                            if prec == -(1 as i32) as i64
                                || prec
                                    >= ::std::mem::size_of::<[i8; 6]>() as u64 as i64
                                        - 1 as i32 as i64
                            {
                                str = unsafe { null.as_ptr() };
                                len = (::std::mem::size_of::<[i8; 6]>() as u64)
                                    .wrapping_sub(1 as i32 as u64);
                                (*(borrow_mut(&mut p)).unwrap()).flags &= !(FLAGS_ALT as i32);
                            } else {
                                str = b"\0" as *const u8 as *const i8;
                                len = 0 as i32 as size_t;
                            }
                        } else if prec != -(1 as i32) as i64 {
                            len = prec as size_t;
                        } else {
                            len = unsafe { strlen(str) };
                        }
                        width -= if len > 9223372036854775807 as i64 as u64 {
                            9223372036854775807 as i64
                        } else {
                            len as i64
                        };
                        if (*(borrow(&p)).unwrap()).flags & FLAGS_ALT as i32 != 0 {
                            if (unsafe { stream.expect("non-null function pointer")(
                                '"' as i32 as u8 as i32,
                                data as *mut FILE,
                            ) }) != -(1 as i32)
                            {
                                done += 1;
                            } else {
                                return done;
                            }
                        }
                        if (*(borrow(&p)).unwrap()).flags & FLAGS_LEFT as i32 == 0 {
                            loop {
                                let mut fresh12 = width;
                                width = width - 1;
                                if !(fresh12 > 0 as i32 as i64) {
                                    break;
                                }
                                if (unsafe { stream.expect("non-null function pointer")(
                                    ' ' as i32 as u8 as i32,
                                    data as *mut FILE,
                                ) }) != -(1 as i32)
                                {
                                    done += 1;
                                } else {
                                    return done;
                                }
                            }
                        }
                        while len != 0 && (unsafe { *str }) as i32 != 0 {
                            let mut fresh13 = str;
                            str = unsafe { str.offset(1) };
                            if (unsafe { stream.expect("non-null function pointer")(
                                *fresh13 as u8 as i32,
                                data as *mut FILE,
                            ) }) != -(1 as i32)
                            {
                                done += 1;
                            } else {
                                return done;
                            }
                            len = len.wrapping_sub(1);
                        }
                        if (*(borrow(&p)).unwrap()).flags & FLAGS_LEFT as i32 != 0 {
                            loop {
                                let mut fresh14 = width;
                                width = width - 1;
                                if !(fresh14 > 0 as i32 as i64) {
                                    break;
                                }
                                if (unsafe { stream.expect("non-null function pointer")(
                                    ' ' as i32 as u8 as i32,
                                    data as *mut FILE,
                                ) }) != -(1 as i32)
                                {
                                    done += 1;
                                } else {
                                    return done;
                                }
                            }
                        }
                        if (*(borrow(&p)).unwrap()).flags & FLAGS_ALT as i32 != 0 {
                            if (unsafe { stream.expect("non-null function pointer")(
                                '"' as i32 as u8 as i32,
                                data as *mut FILE,
                            ) }) != -(1 as i32)
                            {
                                done += 1;
                            } else {
                                return done;
                            }
                        }
                        current_block = 9657238515557273331;
                    }
                    2 => {
                        let mut ptr: *mut core::ffi::c_void = 0 as *mut libc::c_void;
                        ptr = unsafe { (*(borrow_mut(&mut p)).unwrap()).data.ptr };
                        if !ptr.is_null() {
                            base = 16 as i32 as u64;
                            digits = if (*(borrow(&p)).unwrap()).flags & FLAGS_UPPER as i32 != 0 {
                                unsafe { upper_digits.as_ptr() }
                            } else {
                                unsafe { lower_digits.as_ptr() }
                            };
                            is_alt = 1 as i32;
                            num = ptr as size_t as u64;
                            is_neg = 0 as i32;
                            current_block = 7867894563361037860;
                        } else {
                            static mut strnil: [i8; 6] = unsafe {
                                *core::intrinsics::transmute::<&'_ [u8; 6], &'_ [i8; 6]>(b"(nil)\0")
                            };
                            let mut point: *const i8 = 0 as *const i8;
                            width -= (::std::mem::size_of::<[i8; 6]>() as u64)
                                .wrapping_sub(1 as i32 as u64)
                                as i64;
                            if (*(borrow(&p)).unwrap()).flags & FLAGS_LEFT as i32 != 0 {
                                loop {
                                    let mut fresh15 = width;
                                    width = width - 1;
                                    if !(fresh15 > 0 as i32 as i64) {
                                        break;
                                    }
                                    if (unsafe { stream.expect("non-null function pointer")(
                                        ' ' as i32 as u8 as i32,
                                        data as *mut FILE,
                                    ) }) != -(1 as i32)
                                    {
                                        done += 1;
                                    } else {
                                        return done;
                                    }
                                }
                            }
                            point = unsafe { strnil.as_ptr() };
                            while (unsafe { *point }) as i32 != '\u{0}' as i32 {
                                if (unsafe { stream.expect("non-null function pointer")(
                                    *point as u8 as i32,
                                    data as *mut FILE,
                                ) }) != -(1 as i32)
                                {
                                    done += 1;
                                } else {
                                    return done;
                                }
                                point = unsafe { point.offset(1) };
                            }
                            if (*(borrow(&p)).unwrap()).flags & FLAGS_LEFT as i32 == 0 {
                                loop {
                                    let mut fresh16 = width;
                                    width = width - 1;
                                    if !(fresh16 > 0 as i32 as i64) {
                                        break;
                                    }
                                    if (unsafe { stream.expect("non-null function pointer")(
                                        ' ' as i32 as u8 as i32,
                                        data as *mut FILE,
                                    ) }) != -(1 as i32)
                                    {
                                        done += 1;
                                    } else {
                                        return done;
                                    }
                                }
                            }
                            current_block = 9657238515557273331;
                        }
                    }
                    7 => {
                        let mut formatbuf: [i8; 32] =
                            *(unsafe { core::intrinsics::transmute::<&'_ [u8; 32], &'_ mut [i8; 32]>(
                                b"%\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                            ) });
                        let mut fptr: *mut i8 =
                            (unsafe { &mut *formatbuf.as_mut_ptr().offset(1 as i32 as isize) }) as *mut i8;
                        let mut left: u64 = (::std::mem::size_of::<[i8; 32]>() as u64)
                            .wrapping_sub(unsafe { strlen(formatbuf.as_mut_ptr()) });
                        let mut len_0: i32 = 0;
                        width = -(1 as i32) as i64;
                        if (*(borrow(&p)).unwrap()).flags & FLAGS_WIDTH as i32 != 0 {
                            width = (*(borrow_mut(&mut p)).unwrap()).width;
                        } else if (*(borrow(&p)).unwrap()).flags & FLAGS_WIDTHPARAM as i32 != 0 {
                            width = (unsafe { vto[(*(borrow(&p)).unwrap()).width as usize]
                                .data
                                .num
                                .as_signed }) as i64;
                        }
                        prec = -(1 as i32) as i64;
                        if (*(borrow(&p)).unwrap()).flags & FLAGS_PREC as i32 != 0 {
                            prec = (*(borrow_mut(&mut p)).unwrap()).precision;
                        } else if (*(borrow(&p)).unwrap()).flags & FLAGS_PRECPARAM as i32 != 0 {
                            prec = (unsafe { vto[(*(borrow(&p)).unwrap()).precision as usize]
                                .data
                                .num
                                .as_signed }) as i64;
                        }
                        if (*(borrow(&p)).unwrap()).flags & FLAGS_LEFT as i32 != 0 {
                            let mut fresh17 = fptr;
                            fptr = unsafe { fptr.offset(1) };
                            (unsafe { *fresh17 = '-' as i32 as i8 });
                        }
                        if (*(borrow(&p)).unwrap()).flags & FLAGS_SHOWSIGN as i32 != 0 {
                            let mut fresh18 = fptr;
                            fptr = unsafe { fptr.offset(1) };
                            (unsafe { *fresh18 = '+' as i32 as i8 });
                        }
                        if (*(borrow(&p)).unwrap()).flags & FLAGS_SPACE as i32 != 0 {
                            let mut fresh19 = fptr;
                            fptr = unsafe { fptr.offset(1) };
                            (unsafe { *fresh19 = ' ' as i32 as i8 });
                        }
                        if (*(borrow(&p)).unwrap()).flags & FLAGS_ALT as i32 != 0 {
                            let mut fresh20 = fptr;
                            fptr = unsafe { fptr.offset(1) };
                            (unsafe { *fresh20 = '#' as i32 as i8 });
                        }
                        (unsafe { *fptr = 0 as i32 as i8 });
                        if width >= 0 as i32 as i64 {
                            if width >= ::std::mem::size_of::<[i8; 326]>() as u64 as i64 {
                                width = (::std::mem::size_of::<[i8; 326]>() as u64)
                                    .wrapping_sub(1 as i32 as u64)
                                    as i64;
                            }
                            len_0 = unsafe { curl_msnprintf(
                                fptr,
                                left,
                                b"%ld\0" as *const u8 as *const i8,
                                width,
                            ) };
                            fptr = unsafe { fptr.offset(len_0 as isize) };
                            left = (left as u64).wrapping_sub(len_0 as u64) as size_t as size_t;
                        }
                        if prec >= 0 as i32 as i64 {
                            let mut maxprec: u64 = (::std::mem::size_of::<[i8; 326]>() as u64)
                                .wrapping_sub(2 as i32 as u64);
                            let mut val: f64 = unsafe { (*(borrow_mut(&mut p)).unwrap()).data.dnum };
                            if width > 0 as i32 as i64 && prec <= width {
                                maxprec =
                                    (maxprec as u64).wrapping_sub(width as u64) as size_t as size_t;
                            }
                            while val >= 10.0f64 {
                                val /= 10 as i32 as f64;
                                maxprec = maxprec.wrapping_sub(1);
                            }
                            if prec > maxprec as i64 {
                                prec = maxprec as i64 - 1 as i32 as i64;
                            }
                            if prec < 0 as i32 as i64 {
                                prec = 0 as i32 as i64;
                            }
                            len_0 = unsafe { curl_msnprintf(
                                fptr,
                                left,
                                b".%ld\0" as *const u8 as *const i8,
                                prec,
                            ) };
                            fptr = unsafe { fptr.offset(len_0 as isize) };
                        }
                        if (*(borrow(&p)).unwrap()).flags & FLAGS_LONG as i32 != 0 {
                            let mut fresh21 = fptr;
                            fptr = unsafe { fptr.offset(1) };
                            (unsafe { *fresh21 = 'l' as i32 as i8 });
                        }
                        if (*(borrow(&p)).unwrap()).flags & FLAGS_FLOATE as i32 != 0 {
                            let mut fresh22 = fptr;
                            fptr = unsafe { fptr.offset(1) };
                            (unsafe { *fresh22 = (if (*(borrow(&p)).unwrap()).flags & FLAGS_UPPER as i32 != 0
                            {
                                'E' as i32
                            } else {
                                'e' as i32
                            }) as i8 });
                        } else if (*(borrow(&p)).unwrap()).flags & FLAGS_FLOATG as i32 != 0 {
                            let mut fresh23 = fptr;
                            fptr = unsafe { fptr.offset(1) };
                            (unsafe { *fresh23 = (if (*(borrow(&p)).unwrap()).flags & FLAGS_UPPER as i32 != 0
                            {
                                'G' as i32
                            } else {
                                'g' as i32
                            }) as i8 });
                        } else {
                            let mut fresh24 = fptr;
                            fptr = unsafe { fptr.offset(1) };
                            (unsafe { *fresh24 = 'f' as i32 as i8 });
                        }
                        (unsafe { *fptr = 0 as i32 as i8 });
                        (unsafe { sprintf(
                            work.as_mut_ptr(),
                            formatbuf.as_mut_ptr(),
                            (*(borrow(&p)).unwrap()).data.dnum,
                        ) });
                        fptr = work.as_mut_ptr();
                        while (unsafe { *fptr }) != 0 {
                            if (unsafe { stream.expect("non-null function pointer")(
                                *fptr as u8 as i32,
                                data as *mut FILE,
                            ) }) != -(1 as i32)
                            {
                                done += 1;
                            } else {
                                return done;
                            }
                            fptr = unsafe { fptr.offset(1) };
                        }
                        current_block = 9657238515557273331;
                    }
                    4 => {
                        if (*(borrow(&p)).unwrap()).flags & FLAGS_LONGLONG as i32 != 0 {
                            (unsafe { *((*(borrow_mut(&mut p)).unwrap()).data.ptr as *mut i64) = done as i64 });
                        } else if (*(borrow(&p)).unwrap()).flags & FLAGS_LONG as i32 != 0 {
                            (unsafe { *((*(borrow_mut(&mut p)).unwrap()).data.ptr as *mut i64) = done as i64 });
                        } else if (*(borrow(&p)).unwrap()).flags & FLAGS_SHORT as i32 == 0 {
                            (unsafe { *((*(borrow_mut(&mut p)).unwrap()).data.ptr as *mut i32) = done });
                        } else {
                            (unsafe { *((*(borrow_mut(&mut p)).unwrap()).data.ptr as *mut i16) = done as i16 });
                        }
                        current_block = 9657238515557273331;
                    }
                    _ => {
                        current_block = 9657238515557273331;
                    }
                }
                match current_block {
                    7867894563361037860 => {
                        if prec == -(1 as i32) as i64 {
                            prec = 1 as i32 as i64;
                        }
                        w = workend;
                        while num > 0 as i32 as u64 {
                            let mut fresh5 = w;
                            w = unsafe { w.offset(-1) };
                            (unsafe { *fresh5 = *digits.offset(num.wrapping_rem(base as u64) as isize) });
                            num = num.wrapping_div(base as u64);
                        }
                        width -= (unsafe { workend.offset_from(w) }) as i64;
                        prec -= (unsafe { workend.offset_from(w) }) as i64;
                        if is_alt != 0 && base == 8 as i32 as u64 && prec <= 0 as i32 as i64 {
                            let mut fresh6 = w;
                            w = unsafe { w.offset(-1) };
                            (unsafe { *fresh6 = '0' as i32 as i8 });
                            width -= 1;
                        }
                        if prec > 0 as i32 as i64 {
                            width -= prec;
                            loop {
                                let mut fresh7 = prec;
                                prec = prec - 1;
                                if !(fresh7 > 0 as i32 as i64 && w >= work.as_mut_ptr()) {
                                    break;
                                }
                                let mut fresh8 = w;
                                w = unsafe { w.offset(-1) };
                                (unsafe { *fresh8 = '0' as i32 as i8 });
                            }
                        }
                        if is_alt != 0 && base == 16 as i32 as u64 {
                            width -= 2 as i32 as i64;
                        }
                        if is_neg != 0
                            || (*(borrow(&p)).unwrap()).flags & FLAGS_SHOWSIGN as i32 != 0
                            || (*(borrow(&p)).unwrap()).flags & FLAGS_SPACE as i32 != 0
                        {
                            width -= 1;
                        }
                        if (*(borrow(&p)).unwrap()).flags & FLAGS_LEFT as i32 == 0
                            && (*(borrow(&p)).unwrap()).flags & FLAGS_PAD_NIL as i32 == 0
                        {
                            loop {
                                let mut fresh9 = width;
                                width = width - 1;
                                if !(fresh9 > 0 as i32 as i64) {
                                    break;
                                }
                                if (unsafe { stream.expect("non-null function pointer")(
                                    ' ' as i32 as u8 as i32,
                                    data as *mut FILE,
                                ) }) != -(1 as i32)
                                {
                                    done += 1;
                                } else {
                                    return done;
                                }
                            }
                        }
                        if is_neg != 0 {
                            if (unsafe { stream.expect("non-null function pointer")(
                                '-' as i32 as u8 as i32,
                                data as *mut FILE,
                            ) }) != -(1 as i32)
                            {
                                done += 1;
                            } else {
                                return done;
                            }
                        } else if (*(borrow(&p)).unwrap()).flags & FLAGS_SHOWSIGN as i32 != 0 {
                            if (unsafe { stream.expect("non-null function pointer")(
                                '+' as i32 as u8 as i32,
                                data as *mut FILE,
                            ) }) != -(1 as i32)
                            {
                                done += 1;
                            } else {
                                return done;
                            }
                        } else if (*(borrow(&p)).unwrap()).flags & FLAGS_SPACE as i32 != 0 {
                            if (unsafe { stream.expect("non-null function pointer")(
                                ' ' as i32 as u8 as i32,
                                data as *mut FILE,
                            ) }) != -(1 as i32)
                            {
                                done += 1;
                            } else {
                                return done;
                            }
                        }
                        if is_alt != 0 && base == 16 as i32 as u64 {
                            if (unsafe { stream.expect("non-null function pointer")(
                                '0' as i32 as u8 as i32,
                                data as *mut FILE,
                            ) }) != -(1 as i32)
                            {
                                done += 1;
                            } else {
                                return done;
                            }
                            if (*(borrow(&p)).unwrap()).flags & FLAGS_UPPER as i32 != 0 {
                                if (unsafe { stream.expect("non-null function pointer")(
                                    'X' as i32 as u8 as i32,
                                    data as *mut FILE,
                                ) }) != -(1 as i32)
                                {
                                    done += 1;
                                } else {
                                    return done;
                                }
                            } else if (unsafe { stream.expect("non-null function pointer")(
                                'x' as i32 as u8 as i32,
                                data as *mut FILE,
                            ) }) != -(1 as i32)
                            {
                                done += 1;
                            } else {
                                return done;
                            }
                        }
                        if (*(borrow(&p)).unwrap()).flags & FLAGS_LEFT as i32 == 0
                            && (*(borrow(&p)).unwrap()).flags & FLAGS_PAD_NIL as i32 != 0
                        {
                            loop {
                                let mut fresh10 = width;
                                width = width - 1;
                                if !(fresh10 > 0 as i32 as i64) {
                                    break;
                                }
                                if (unsafe { stream.expect("non-null function pointer")(
                                    '0' as i32 as u8 as i32,
                                    data as *mut FILE,
                                ) }) != -(1 as i32)
                                {
                                    done += 1;
                                } else {
                                    return done;
                                }
                            }
                        }
                        loop {
                            w = unsafe { w.offset(1) };
                            if !(w <= workend) {
                                break;
                            }
                            if (unsafe { stream.expect("non-null function pointer")(
                                *w as u8 as i32,
                                data as *mut FILE,
                            ) }) != -(1 as i32)
                            {
                                done += 1;
                            } else {
                                return done;
                            }
                        }
                        if (*(borrow(&p)).unwrap()).flags & FLAGS_LEFT as i32 != 0 {
                            loop {
                                let mut fresh11 = width;
                                width = width - 1;
                                if !(fresh11 > 0 as i32 as i64) {
                                    break;
                                }
                                if (unsafe { stream.expect("non-null function pointer")(
                                    ' ' as i32 as u8 as i32,
                                    data as *mut FILE,
                                ) }) != -(1 as i32)
                                {
                                    done += 1;
                                } else {
                                    return done;
                                }
                            }
                        }
                    }
                    _ => {}
                }
                let mut fresh25 = end;
                end = unsafe { end.offset(1) };
                f = unsafe { *fresh25 };
            }
        }
    }
    return done;
}
extern "C" fn addbyter(mut output: i32, mut data: *mut crate::src::lib::http2::_IO_FILE) -> i32 {
    let mut infop: *mut crate::src::lib::mprintf::nsprintf = data as *mut nsprintf;
    let mut outc: u8 = output as u8;
    if (unsafe { (*infop).length }) < (unsafe { (*infop).max }) {
        (unsafe { *((*infop).buffer).offset(0 as i32 as isize) = outc as i8 });
        let mut fresh26 = unsafe { &mut ((*infop).buffer) };
        *fresh26 = unsafe { (*fresh26).offset(1) };
        let mut fresh27 = unsafe { &mut ((*infop).length) };
        *fresh27 = (*fresh27).wrapping_add(1);
        return outc as i32;
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn curl_mvsnprintf(
    mut buffer: *mut i8,
    mut maxlength: u64,
    mut format: *const i8,
    mut ap_save: core::ffi::VaList,
) -> i32 {
    let mut retcode: i32 = 0;
    let mut info: crate::src::lib::mprintf::nsprintf = nsprintf {
        buffer: 0 as *mut i8,
        length: 0,
        max: 0,
    };
    info.buffer = buffer;
    info.length = 0 as i32 as size_t;
    info.max = maxlength;
    retcode = dprintf_formatf(
        &mut info as *mut nsprintf as *mut libc::c_void,
        Some(addbyter),
        format,
        ap_save.as_va_list(),
    );
    if retcode != -(1 as i32) && info.max != 0 {
        if info.max == info.length {
            (unsafe { *(info.buffer).offset(-(1 as i32) as isize) = 0 as i32 as i8 });
            retcode -= 1;
        } else {
            (unsafe { *(info.buffer).offset(0 as i32 as isize) = 0 as i32 as i8 });
        }
    }
    return retcode;
}
#[no_mangle]
pub unsafe extern "C" fn curl_msnprintf(
    mut buffer: *mut i8,
    mut maxlength: u64,
    mut format: *const i8,
    mut args: ...
) -> i32 {
    let mut retcode: i32 = 0;
    let mut ap_save: core::ffi::VaListImpl;
    ap_save = args.clone();
    retcode = curl_mvsnprintf(buffer, maxlength, format, ap_save.as_va_list());
    return retcode;
}
extern "C" fn alloc_addbyter(
    mut output: i32,
    mut data: *mut crate::src::lib::http2::_IO_FILE,
) -> i32 {
    let mut infop: *mut crate::src::lib::mprintf::asprintf = data as *mut asprintf;
    let mut outc: u8 = output as u8;
    if Curl_dyn_addn(
        unsafe { (*infop).b },
        &mut outc as *mut u8 as *const libc::c_void,
        1 as i32 as size_t,
    ) as u64
        != 0
    {
        (unsafe { (*infop).fail = 1 as i32 != 0 });
        return -(1 as i32);
    }
    return outc as i32;
}
#[no_mangle]
pub extern "C" fn Curl_dyn_vprintf(
    mut dyn_0: *mut crate::src::lib::http2::dynbuf,
    mut format: *const i8,
    mut ap_save: core::ffi::VaList,
) -> i32 {
    let mut retcode: i32 = 0;
    let mut info: crate::src::lib::mprintf::asprintf = asprintf {
        b: (0 as *mut crate::src::lib::http2::dynbuf),
        fail: false,
    };
    info.b = dyn_0;
    info.fail = 0 as i32 != 0;
    retcode = dprintf_formatf(
        &mut info as *mut asprintf as *mut libc::c_void,
        Some(alloc_addbyter),
        format,
        ap_save.as_va_list(),
    );
    if -(1 as i32) == retcode || info.fail as i32 != 0 {
        Curl_dyn_free(info.b);
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn curl_mvaprintf(mut format: *const i8, mut ap_save: core::ffi::VaList) -> *mut i8 {
    let mut retcode: i32 = 0;
    let mut info: crate::src::lib::mprintf::asprintf = asprintf {
        b: (0 as *mut crate::src::lib::http2::dynbuf),
        fail: false,
    };
    let mut dyn_0: crate::src::lib::http2::dynbuf = dynbuf {
        bufr: 0 as *mut i8,
        leng: 0,
        allc: 0,
        toobig: 0,
    };
    info.b = &mut dyn_0;
    Curl_dyn_init(info.b, 8000000 as i32 as size_t);
    info.fail = 0 as i32 != 0;
    retcode = dprintf_formatf(
        &mut info as *mut asprintf as *mut libc::c_void,
        Some(alloc_addbyter),
        format,
        ap_save.as_va_list(),
    );
    if -(1 as i32) == retcode || info.fail as i32 != 0 {
        Curl_dyn_free(info.b);
        return 0 as *mut i8;
    }
    if Curl_dyn_len(info.b) != 0 {
        return Curl_dyn_ptr(info.b);
    }
    return unsafe { Curl_cstrdup.expect("non-null function pointer")(b"\0" as *const u8 as *const i8) };
}
#[no_mangle]
pub unsafe extern "C" fn curl_maprintf(mut format: *const i8, mut args: ...) -> *mut i8 {
    let mut ap_save: core::ffi::VaListImpl;
    let mut s: *mut i8 = 0 as *mut i8;
    ap_save = args.clone();
    s = curl_mvaprintf(format, ap_save.as_va_list());
    return s;
}
extern "C" fn storebuffer(mut output: i32, mut data: *mut crate::src::lib::http2::_IO_FILE) -> i32 {
    let mut buffer: *mut *mut i8 = data as *mut *mut i8;
    let mut outc: u8 = output as u8;
    (unsafe { **buffer = outc as i8 });
    (unsafe { *buffer = (*buffer).offset(1) });
    return outc as i32;
}
#[no_mangle]
pub unsafe extern "C" fn curl_msprintf(
    mut buffer: *mut i8,
    mut format: *const i8,
    mut args: ...
) -> i32 {
    let mut ap_save: core::ffi::VaListImpl;
    let mut retcode: i32 = 0;
    ap_save = args.clone();
    retcode = dprintf_formatf(
        &mut buffer as *mut *mut i8 as *mut libc::c_void,
        Some(storebuffer),
        format,
        ap_save.as_va_list(),
    );
    *buffer = 0 as i32 as i8;
    return retcode;
}
#[no_mangle]
pub unsafe extern "C" fn curl_mprintf(mut format: *const i8, mut args: ...) -> i32 {
    let mut retcode: i32 = 0;
    let mut ap_save: core::ffi::VaListImpl;
    ap_save = args.clone();
    retcode = dprintf_formatf(
        stdout as *mut libc::c_void,
        Some(fputc),
        format,
        ap_save.as_va_list(),
    );
    return retcode;
}
#[no_mangle]
pub unsafe extern "C" fn curl_mfprintf(
    mut whereto: *mut crate::src::lib::http2::_IO_FILE,
    mut format: *const i8,
    mut args: ...
) -> i32 {
    let mut retcode: i32 = 0;
    let mut ap_save: core::ffi::VaListImpl;
    ap_save = args.clone();
    retcode = dprintf_formatf(
        whereto as *mut libc::c_void,
        Some(fputc),
        format,
        ap_save.as_va_list(),
    );
    return retcode;
}
#[no_mangle]
pub extern "C" fn curl_mvsprintf(
    mut buffer: *mut i8,
    mut format: *const i8,
    mut ap_save: core::ffi::VaList,
) -> i32 {
    let mut retcode: i32 = 0;
    retcode = dprintf_formatf(
        &mut buffer as *mut *mut i8 as *mut libc::c_void,
        Some(storebuffer),
        format,
        ap_save.as_va_list(),
    );
    (unsafe { *buffer = 0 as i32 as i8 });
    return retcode;
}
#[no_mangle]
pub extern "C" fn curl_mvprintf(mut format: *const i8, mut ap_save: core::ffi::VaList) -> i32 {
    return dprintf_formatf(
        (unsafe { stdout }) as *mut libc::c_void,
        Some(fputc),
        format,
        ap_save.as_va_list(),
    );
}
#[no_mangle]
pub extern "C" fn curl_mvfprintf(
    mut whereto: *mut crate::src::lib::http2::_IO_FILE,
    mut format: *const i8,
    mut ap_save: core::ffi::VaList,
) -> i32 {
    return dprintf_formatf(
        whereto as *mut libc::c_void,
        Some(fputc),
        format,
        ap_save.as_va_list(),
    );
}
use crate::laertes_rt::*;
