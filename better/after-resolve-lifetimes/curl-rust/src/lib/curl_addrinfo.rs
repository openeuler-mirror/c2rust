use ::libc;
extern "C" {
    fn memcpy(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn strlen(_: * const i8) -> u64;
    fn getaddrinfo(
        __name: * const i8,
        __service: * const i8,
        __req: * const crate::src::lib::asyn_thread::addrinfo,
        __pai: * mut * mut crate::src::lib::asyn_thread::addrinfo,
    ) -> i32;
    fn freeaddrinfo(__ai: * mut crate::src::lib::asyn_thread::addrinfo);
    fn inet_pton(
        __af: i32,
        __cp: * const i8,
        __buf: * mut core::ffi::c_void,
    ) -> i32;
    
    
    
    
}
pub use crate::src::lib::easy::Curl_ccalloc;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_cstrdup;
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type __socklen_t = u32;
pub type size_t = u64;
pub type socklen_t = u32;
pub type __socket_type = u32;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_RAW: __socket_type = 3;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;
pub type sa_family_t = u16;
// #[derive(Copy, Clone)]

pub type sockaddr = crate::src::lib::http2::sockaddr;
pub type curl_socklen_t = u32;
pub type curl_malloc_callback<'a1> = Option<unsafe extern "C"  fn(_: u64,) -> Option<&'a1 mut core::ffi::c_void>>;
pub type curl_free_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> ()>;
pub type curl_strdup_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 i8>,) -> Option<&'a2 mut i8>>;
pub type curl_calloc_callback<'a1> = Option<unsafe extern "C"  fn(_: u64,_: u64,) -> Option<&'a1 mut core::ffi::c_void>>;
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
pub type uint8_t = u8;
pub type uint16_t = u16;
pub type uint32_t = u32;
pub type in_addr_t = u32;
// #[derive(Copy, Clone)]

pub type in_addr = crate::src::lib::connect::in_addr;
pub type in_port_t = u16;
// #[derive(Copy, Clone)]

pub type in6_addr = crate::src::lib::connect::in6_addr;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed = crate::src::lib::connect::C2RustUnnamed_8;
// #[derive(Copy, Clone)]

pub type sockaddr_in = crate::src::lib::connect::sockaddr_in;
// #[derive(Copy, Clone)]

pub type sockaddr_in6 = crate::src::lib::connect::sockaddr_in6;
// #[derive(Copy, Clone)]
#[repr(C)]
pub struct hostent<'a> {
    pub h_name: * mut i8,
    pub h_aliases: Option<&'a mut Option<&'a mut i8>>,
    pub h_addrtype: i32,
    pub h_length: i32,
    pub h_addr_list: * mut * mut i8,
}
impl<'a> hostent<'a> {
    pub const fn new() -> Self {
        hostent {
        h_name: (0 as * mut i8),
        h_aliases: None,
        h_addrtype: 0,
        h_length: 0,
        h_addr_list: (0 as * mut * mut i8)
        }
    }
}

impl<'a> std::default::Default for hostent<'a> {
    fn default() -> Self { hostent::new() }
}

// #[derive(Copy, Clone)]

pub type addrinfo = crate::src::lib::asyn_thread::addrinfo;
// #[derive(Copy, Clone)]

pub type sockaddr_un = crate::src::lib::connect::sockaddr_un;
// #[derive(Copy, Clone)]

pub type Curl_addrinfo = crate::src::lib::http2::Curl_addrinfo;
// #[derive(Copy, Clone)]
#[repr(C)]
pub struct namebuff<'a> {
    pub hostentry: crate::src::lib::curl_addrinfo::hostent<'a>,
    pub addrentry: crate::src::lib::curl_addrinfo::C2RustUnnamed_0,
    pub h_addr_list: [* mut i8; 2],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub ina4: in_addr,
    pub ina6: in6_addr,
}
#[inline]
 extern "C" fn __bswap_16(mut __bsx: u16) -> u16 {
    return (__bsx as i32 >> 8 as i32 & 0xff as i32
        | (__bsx as i32 & 0xff as i32) << 8 as i32)
        as __uint16_t;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_freeaddrinfo(mut cahead: * mut crate::src::lib::http2::Curl_addrinfo) {
    let mut canext: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut ca: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
    ca = cahead;
    while !ca.is_null() {
        canext = (*ca).ai_next;
        Curl_cfree.expect("non-null function pointer")(ca as *mut libc::c_void);
        ca = canext;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_getaddrinfo_ex<'a1>(
    mut nodename: * const i8,
    mut servname: * const i8,
    mut hints: * const crate::src::lib::asyn_thread::addrinfo,
    mut result: Option<&'a1 mut * mut crate::src::lib::http2::Curl_addrinfo>,
) -> i32 {
    let mut ai: * const crate::src::lib::asyn_thread::addrinfo = 0 as *const addrinfo;
    let mut aihead: * mut crate::src::lib::asyn_thread::addrinfo = 0 as *mut addrinfo;
    let mut cafirst: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut calast: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut ca: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut ss_size: u64 = 0;
    let mut error: i32 = 0;
    *(borrow_mut(&mut result)).unwrap() = 0 as *mut Curl_addrinfo;
    error = getaddrinfo(nodename, servname, hints, &mut aihead);
    if error != 0 {
        return error;
    }
    let mut current_block_27: u64;
    ai = aihead;
    while !ai.is_null() {
        let mut namelen: u64 = if !((*ai).ai_canonname).is_null() {
            (strlen((*ai).ai_canonname)).wrapping_add(1 as i32 as u64)
        } else {
            0 as i32 as u64
        };
        if (*ai).ai_family == 2 as i32 {
            ss_size = ::std::mem::size_of::<sockaddr_in>() as u64;
            current_block_27 = 12800627514080957624;
        } else if (*ai).ai_family == 10 as i32 {
            ss_size = ::std::mem::size_of::<sockaddr_in6>() as u64;
            current_block_27 = 12800627514080957624;
        } else {
            current_block_27 = 14523784380283086299;
        }
        match current_block_27 {
            12800627514080957624 => {
                if !(((*ai).ai_addr).is_null()
                    || !((*ai).ai_addrlen > 0 as i32 as u32))
                {
                    if !(((*ai).ai_addrlen as size_t) < ss_size) {
                        ca = Curl_cmalloc
                            .expect(
                                "non-null function pointer",
                            )(
                            (::std::mem::size_of::<Curl_addrinfo>() as u64)
                                .wrapping_add(ss_size)
                                .wrapping_add(namelen),
                        ) as *mut Curl_addrinfo;
                        if ca.is_null() {
                            error = -(10 as i32);
                            break;
                        } else {
                            (*ca).ai_flags = (*ai).ai_flags;
                            (*ca).ai_family = (*ai).ai_family;
                            (*ca).ai_socktype = (*ai).ai_socktype;
                            (*ca).ai_protocol = (*ai).ai_protocol;
                            (*ca).ai_addrlen = ss_size as curl_socklen_t;
                            let mut fresh0 = &mut ((*ca).ai_addr);
                            *fresh0 = 0 as *mut sockaddr;
                            let mut fresh1 = &mut ((*ca).ai_canonname);
                            *fresh1 = 0 as *mut i8;
                            let mut fresh2 = &mut ((*ca).ai_next);
                            *fresh2 = 0 as *mut Curl_addrinfo;
                            let mut fresh3 = &mut ((*ca).ai_addr);
                            *fresh3 = (ca as *mut i8)
                                .offset(
                                    ::std::mem::size_of::<Curl_addrinfo>() as u64
                                        as isize,
                                ) as *mut libc::c_void as *mut sockaddr;
                            memcpy(
                                (*ca).ai_addr as *mut libc::c_void,
                                (*ai).ai_addr as *const libc::c_void,
                                ss_size,
                            );
                            if namelen != 0 {
                                let mut fresh4 = &mut ((*ca).ai_canonname);
                                *fresh4 = ((*ca).ai_addr as *mut i8)
                                    .offset(ss_size as isize) as *mut libc::c_void
                                    as *mut i8;
                                memcpy(
                                    (*ca).ai_canonname as *mut libc::c_void,
                                    (*ai).ai_canonname as *const libc::c_void,
                                    namelen,
                                );
                            }
                            if cafirst.is_null() {
                                cafirst = ca;
                            }
                            if !calast.is_null() {
                                let mut fresh5 = &mut ((*calast).ai_next);
                                *fresh5 = ca;
                            }
                            calast = ca;
                        }
                    }
                }
            }
            _ => {}
        }
        ai = (*ai).ai_next;
    }
    if !aihead.is_null() {
        freeaddrinfo(aihead);
    }
    if error != 0 {
        Curl_freeaddrinfo(cafirst);
        cafirst = 0 as *mut Curl_addrinfo;
    } else if cafirst.is_null() {
        error = -(2 as i32);
    }
    *(borrow_mut(&mut result)).unwrap() = cafirst;
    return error;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_he2ai<'a1, 'a2>(
    mut he: Option<&'a1 crate::src::lib::curl_addrinfo::hostent<'a2>>,
    mut port: i32,
) -> * mut crate::src::lib::http2::Curl_addrinfo {
    let mut ai: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut prevai: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut firstai: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut addr: * mut crate::src::lib::connect::sockaddr_in = (0 as * mut crate::src::lib::connect::sockaddr_in);
    let mut addr6: * mut crate::src::lib::connect::sockaddr_in6 = (0 as * mut crate::src::lib::connect::sockaddr_in6);
    let mut result: u32 = CURLE_OK;
    let mut i: i32 = 0;
    let mut curr: * mut i8 = 0 as *mut i8;
    if (he).clone().is_none() {
        return 0 as *mut Curl_addrinfo;
    }
    i = 0 as i32;
    loop {
        curr = *((*((he).clone()).unwrap()).h_addr_list).offset(i as isize);
        if curr.is_null() {
            break;
        }
        let mut ss_size: u64 = 0;
        let mut namelen: u64 = (strlen((*((he).clone()).unwrap()).h_name))
            .wrapping_add(1 as i32 as u64);
        if (*((he).clone()).unwrap()).h_addrtype == 10 as i32 {
            ss_size = ::std::mem::size_of::<sockaddr_in6>() as u64;
        } else {
            ss_size = ::std::mem::size_of::<sockaddr_in>() as u64;
        }
        ai = Curl_ccalloc
            .expect(
                "non-null function pointer",
            )(
            1 as i32 as size_t,
            (::std::mem::size_of::<Curl_addrinfo>() as u64)
                .wrapping_add(ss_size)
                .wrapping_add(namelen),
        ) as *mut Curl_addrinfo;
        if ai.is_null() {
            result = CURLE_OUT_OF_MEMORY;
            break;
        } else {
            let mut fresh6 = &mut ((*ai).ai_addr);
            *fresh6 = (ai as *mut i8)
                .offset(::std::mem::size_of::<Curl_addrinfo>() as u64 as isize)
                as *mut libc::c_void as *mut sockaddr;
            let mut fresh7 = &mut ((*ai).ai_canonname);
            *fresh7 = ((*ai).ai_addr as *mut i8).offset(ss_size as isize);
            memcpy(
                (*ai).ai_canonname as *mut libc::c_void,
                (*((he).clone()).unwrap()).h_name as *const libc::c_void,
                namelen,
            );
            if firstai.is_null() {
                firstai = ai;
            }
            if !prevai.is_null() {
                let mut fresh8 = &mut ((*prevai).ai_next);
                *fresh8 = ai;
            }
            (*ai).ai_family = (*(he).unwrap()).h_addrtype;
            (*ai).ai_socktype = SOCK_STREAM as i32;
            (*ai).ai_addrlen = ss_size as curl_socklen_t;
            match (*ai).ai_family {
                2 => {
                    addr = (*ai).ai_addr as *mut libc::c_void as *mut sockaddr_in;
                    memcpy(
                        &mut (*addr).sin_addr as *mut in_addr as *mut libc::c_void,
                        curr as *const libc::c_void,
                        ::std::mem::size_of::<in_addr>() as u64,
                    );
                    (*addr).sin_family = (*(he).unwrap()).h_addrtype as sa_family_t;
                    (*addr).sin_port = __bswap_16(port as u16);
                }
                10 => {
                    addr6 = (*ai).ai_addr as *mut libc::c_void as *mut sockaddr_in6;
                    memcpy(
                        &mut (*addr6).sin6_addr as *mut in6_addr as *mut libc::c_void,
                        curr as *const libc::c_void,
                        ::std::mem::size_of::<in6_addr>() as u64,
                    );
                    (*addr6).sin6_family = (*(he).unwrap()).h_addrtype as sa_family_t;
                    (*addr6).sin6_port = __bswap_16(port as u16);
                }
                _ => {}
            }
            prevai = ai;
            i += 1;
        }
    }
    if result as u64 != 0 {
        Curl_freeaddrinfo(firstai);
        firstai = 0 as *mut Curl_addrinfo;
    }
    return firstai;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_ip2addr(
    mut af: i32,
    mut inaddr: * const core::ffi::c_void,
    mut hostname: * const i8,
    mut port: i32,
) -> * mut crate::src::lib::http2::Curl_addrinfo {
    let mut ai: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut h: Option<&'_ mut crate::src::lib::curl_addrinfo::hostent<'_>> = Option::<&'_ mut crate::src::lib::curl_addrinfo::hostent<'_>>::None;
    let mut buf: * mut crate::src::lib::curl_addrinfo::namebuff<'_> = 0 as *mut namebuff;
    let mut addrentry: * mut i8 = 0 as *mut i8;
    let mut hoststr: * mut i8 = 0 as *mut i8;
    let mut addrsize: u64 = 0;
    buf = Curl_cmalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<namebuff>() as u64) as *mut namebuff;
    if buf.is_null() {
        return 0 as *mut Curl_addrinfo;
    }
    hoststr = Curl_cstrdup.expect("non-null function pointer")(hostname);
    if hoststr.is_null() {
        Curl_cfree.expect("non-null function pointer")(buf as *mut libc::c_void);
        return 0 as *mut Curl_addrinfo;
    }
    match af {
        2 => {
            addrsize = ::std::mem::size_of::<in_addr>() as u64;
            addrentry = &mut (*buf).addrentry.ina4 as *mut in_addr as *mut libc::c_void
                as *mut i8;
            memcpy(
                addrentry as *mut libc::c_void,
                inaddr,
                ::std::mem::size_of::<in_addr>() as u64,
            );
        }
        10 => {
            addrsize = ::std::mem::size_of::<in6_addr>() as u64;
            addrentry = &mut (*buf).addrentry.ina6 as *mut in6_addr as *mut libc::c_void
                as *mut i8;
            memcpy(
                addrentry as *mut libc::c_void,
                inaddr,
                ::std::mem::size_of::<in6_addr>() as u64,
            );
        }
        _ => {
            Curl_cfree.expect("non-null function pointer")(hoststr as *mut libc::c_void);
            Curl_cfree.expect("non-null function pointer")(buf as *mut libc::c_void);
            return 0 as *mut Curl_addrinfo;
        }
    }
    h = Some(&mut (*buf).hostentry);
    let mut fresh9 = &mut ((*(borrow_mut(&mut h)).unwrap()).h_name);
    *fresh9 = hoststr;
    let mut fresh10 = &mut ((*(borrow_mut(&mut h)).unwrap()).h_aliases);
    *fresh10 = Option::<&'_ mut Option<&'_ mut i8>>::None;
    (*(borrow_mut(&mut h)).unwrap()).h_addrtype = af as i16 as i32;
    (*(borrow_mut(&mut h)).unwrap()).h_length = addrsize as i16 as i32;
    let mut fresh11 = &mut ((*(borrow_mut(&mut h)).unwrap()).h_addr_list);
    *fresh11 = &mut *((*buf).h_addr_list).as_mut_ptr().offset(0 as i32 as isize)
        as *mut *mut i8;
    let mut fresh12 = &mut (*((*(borrow(& h)).unwrap()).h_addr_list).offset(0 as i32 as isize));
    *fresh12 = addrentry;
    let mut fresh13 = &mut (*((*(borrow(& h)).unwrap()).h_addr_list).offset(1 as i32 as isize));
    *fresh13 = 0 as *mut i8;
    ai = Curl_he2ai(borrow(& h), port);
    Curl_cfree.expect("non-null function pointer")(hoststr as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(buf as *mut libc::c_void);
    return ai;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_str2addr(
    mut address: * mut i8,
    mut port: i32,
) -> * mut crate::src::lib::http2::Curl_addrinfo {
    let mut in_0: crate::src::lib::connect::in_addr = in_addr { s_addr: 0 };
    if inet_pton(
        2 as i32,
        address,
        &mut in_0 as *mut in_addr as *mut libc::c_void,
    ) > 0 as i32
    {
        return Curl_ip2addr(
            2 as i32,
            &mut in_0 as *mut in_addr as *const libc::c_void,
            address,
            port,
        );
    }
    let mut in6: crate::src::lib::connect::in6_addr = in6_addr {
        __in6_u: C2RustUnnamed {
            __u6_addr8: [0; 16],
        },
    };
    if inet_pton(
        10 as i32,
        address,
        &mut in6 as *mut in6_addr as *mut libc::c_void,
    ) > 0 as i32
    {
        return Curl_ip2addr(
            10 as i32,
            &mut in6 as *mut in6_addr as *const libc::c_void,
            address,
            port,
        );
    }
    return 0 as *mut Curl_addrinfo;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_unix2addr<'a1>(
    mut path: * const i8,
    mut longpath: Option<&'a1 mut bool>,
    mut abstract_0: bool,
) -> * mut crate::src::lib::http2::Curl_addrinfo {
    let mut ai: * mut crate::src::lib::http2::Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut sa_un: * mut crate::src::lib::connect::sockaddr_un = (0 as * mut crate::src::lib::connect::sockaddr_un);
    let mut path_len: u64 = 0;
    *(borrow_mut(&mut longpath)).unwrap() = 0 as i32 != 0;
    ai = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(
        1 as i32 as size_t,
        (::std::mem::size_of::<Curl_addrinfo>() as u64)
            .wrapping_add(::std::mem::size_of::<sockaddr_un>() as u64),
    ) as *mut Curl_addrinfo;
    if ai.is_null() {
        return 0 as *mut Curl_addrinfo;
    }
    let mut fresh14 = &mut ((*ai).ai_addr);
    *fresh14 = (ai as *mut i8)
        .offset(::std::mem::size_of::<Curl_addrinfo>() as u64 as isize)
        as *mut libc::c_void as *mut sockaddr;
    sa_un = (*ai).ai_addr as *mut libc::c_void as *mut sockaddr_un;
    (*sa_un).sun_family = 1 as i32 as sa_family_t;
    path_len = (strlen(path)).wrapping_add(1 as i32 as u64);
    if path_len > ::std::mem::size_of::<[i8; 108]>() as u64 {
        Curl_cfree.expect("non-null function pointer")(ai as *mut libc::c_void);
        *(borrow_mut(&mut longpath)).unwrap() = 1 as i32 != 0;
        return 0 as *mut Curl_addrinfo;
    }
    (*ai).ai_family = 1 as i32;
    (*ai).ai_socktype = SOCK_STREAM as i32;
    (*ai)
        .ai_addrlen = ((2 as u64).wrapping_add(path_len)
        & 0x7fffffff as i32 as u64) as curl_socklen_t;
    if abstract_0 {
        memcpy(
            ((*sa_un).sun_path).as_mut_ptr().offset(1 as i32 as isize)
                as *mut libc::c_void,
            path as *const libc::c_void,
            path_len.wrapping_sub(1 as i32 as u64),
        );
    } else {
        memcpy(
            ((*sa_un).sun_path).as_mut_ptr() as *mut libc::c_void,
            path as *const libc::c_void,
            path_len,
        );
    }
    return ai;
}
use crate::laertes_rt::*;
