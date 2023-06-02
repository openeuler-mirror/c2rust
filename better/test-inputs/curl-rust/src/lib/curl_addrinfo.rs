use ::libc;
extern "C" {
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn getaddrinfo(
        __name: *const libc::c_char,
        __service: *const libc::c_char,
        __req: *const addrinfo,
        __pai: *mut *mut addrinfo,
    ) -> libc::c_int;
    fn freeaddrinfo(__ai: *mut addrinfo);
    fn inet_pton(
        __af: libc::c_int,
        __cp: *const libc::c_char,
        __buf: *mut libc::c_void,
    ) -> libc::c_int;
    static mut Curl_cmalloc: curl_malloc_callback;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_cstrdup: curl_strdup_callback;
    static mut Curl_ccalloc: curl_calloc_callback;
}
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __socklen_t = libc::c_uint;
pub type size_t = libc::c_ulong;
pub type socklen_t = __socklen_t;
pub type __socket_type = libc::c_uint;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_RAW: __socket_type = 3;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
pub type curl_socklen_t = socklen_t;
pub type curl_malloc_callback = Option::<
    unsafe extern "C" fn(size_t) -> *mut libc::c_void,
>;
pub type curl_free_callback = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type curl_strdup_callback = Option::<
    unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
>;
pub type curl_calloc_callback = Option::<
    unsafe extern "C" fn(size_t, size_t) -> *mut libc::c_void,
>;
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
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type in_addr_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type in_port_t = uint16_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in6_addr {
    pub __in6_u: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub __u6_addr8: [uint8_t; 16],
    pub __u6_addr16: [uint16_t; 8],
    pub __u6_addr32: [uint32_t; 4],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [libc::c_uchar; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: uint32_t,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostent {
    pub h_name: *mut libc::c_char,
    pub h_aliases: *mut *mut libc::c_char,
    pub h_addrtype: libc::c_int,
    pub h_length: libc::c_int,
    pub h_addr_list: *mut *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct addrinfo {
    pub ai_flags: libc::c_int,
    pub ai_family: libc::c_int,
    pub ai_socktype: libc::c_int,
    pub ai_protocol: libc::c_int,
    pub ai_addrlen: socklen_t,
    pub ai_addr: *mut sockaddr,
    pub ai_canonname: *mut libc::c_char,
    pub ai_next: *mut addrinfo,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_un {
    pub sun_family: sa_family_t,
    pub sun_path: [libc::c_char; 108],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_addrinfo {
    pub ai_flags: libc::c_int,
    pub ai_family: libc::c_int,
    pub ai_socktype: libc::c_int,
    pub ai_protocol: libc::c_int,
    pub ai_addrlen: curl_socklen_t,
    pub ai_canonname: *mut libc::c_char,
    pub ai_addr: *mut sockaddr,
    pub ai_next: *mut Curl_addrinfo,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct namebuff {
    pub hostentry: hostent,
    pub addrentry: C2RustUnnamed_0,
    pub h_addr_list: [*mut libc::c_char; 2],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub ina4: in_addr,
    pub ina6: in6_addr,
}
#[inline]
unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int
        | (__bsx as libc::c_int & 0xff as libc::c_int) << 8 as libc::c_int)
        as __uint16_t;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_freeaddrinfo(mut cahead: *mut Curl_addrinfo) {
    let mut canext: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut ca: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
    ca = cahead;
    while !ca.is_null() {
        canext = (*ca).ai_next;
        Curl_cfree.expect("non-null function pointer")(ca as *mut libc::c_void);
        ca = canext;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_getaddrinfo_ex(
    mut nodename: *const libc::c_char,
    mut servname: *const libc::c_char,
    mut hints: *const addrinfo,
    mut result: *mut *mut Curl_addrinfo,
) -> libc::c_int {
    let mut ai: *const addrinfo = 0 as *const addrinfo;
    let mut aihead: *mut addrinfo = 0 as *mut addrinfo;
    let mut cafirst: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut calast: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut ca: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut ss_size: size_t = 0;
    let mut error: libc::c_int = 0;
    *result = 0 as *mut Curl_addrinfo;
    error = getaddrinfo(nodename, servname, hints, &mut aihead);
    if error != 0 {
        return error;
    }
    let mut current_block_27: u64;
    ai = aihead;
    while !ai.is_null() {
        let mut namelen: size_t = if !((*ai).ai_canonname).is_null() {
            (strlen((*ai).ai_canonname)).wrapping_add(1 as libc::c_int as libc::c_ulong)
        } else {
            0 as libc::c_int as libc::c_ulong
        };
        if (*ai).ai_family == 2 as libc::c_int {
            ss_size = ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong;
            current_block_27 = 12800627514080957624;
        } else if (*ai).ai_family == 10 as libc::c_int {
            ss_size = ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong;
            current_block_27 = 12800627514080957624;
        } else {
            current_block_27 = 14523784380283086299;
        }
        match current_block_27 {
            12800627514080957624 => {
                if !(((*ai).ai_addr).is_null()
                    || !((*ai).ai_addrlen > 0 as libc::c_int as libc::c_uint))
                {
                    if !(((*ai).ai_addrlen as size_t) < ss_size) {
                        ca = Curl_cmalloc
                            .expect(
                                "non-null function pointer",
                            )(
                            (::std::mem::size_of::<Curl_addrinfo>() as libc::c_ulong)
                                .wrapping_add(ss_size)
                                .wrapping_add(namelen),
                        ) as *mut Curl_addrinfo;
                        if ca.is_null() {
                            error = -(10 as libc::c_int);
                            break;
                        } else {
                            (*ca).ai_flags = (*ai).ai_flags;
                            (*ca).ai_family = (*ai).ai_family;
                            (*ca).ai_socktype = (*ai).ai_socktype;
                            (*ca).ai_protocol = (*ai).ai_protocol;
                            (*ca).ai_addrlen = ss_size as curl_socklen_t;
                            let ref mut fresh0 = (*ca).ai_addr;
                            *fresh0 = 0 as *mut sockaddr;
                            let ref mut fresh1 = (*ca).ai_canonname;
                            *fresh1 = 0 as *mut libc::c_char;
                            let ref mut fresh2 = (*ca).ai_next;
                            *fresh2 = 0 as *mut Curl_addrinfo;
                            let ref mut fresh3 = (*ca).ai_addr;
                            *fresh3 = (ca as *mut libc::c_char)
                                .offset(
                                    ::std::mem::size_of::<Curl_addrinfo>() as libc::c_ulong
                                        as isize,
                                ) as *mut libc::c_void as *mut sockaddr;
                            memcpy(
                                (*ca).ai_addr as *mut libc::c_void,
                                (*ai).ai_addr as *const libc::c_void,
                                ss_size,
                            );
                            if namelen != 0 {
                                let ref mut fresh4 = (*ca).ai_canonname;
                                *fresh4 = ((*ca).ai_addr as *mut libc::c_char)
                                    .offset(ss_size as isize) as *mut libc::c_void
                                    as *mut libc::c_char;
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
                                let ref mut fresh5 = (*calast).ai_next;
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
        error = -(2 as libc::c_int);
    }
    *result = cafirst;
    return error;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_he2ai(
    mut he: *const hostent,
    mut port: libc::c_int,
) -> *mut Curl_addrinfo {
    let mut ai: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut prevai: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut firstai: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut addr: *mut sockaddr_in = 0 as *mut sockaddr_in;
    let mut addr6: *mut sockaddr_in6 = 0 as *mut sockaddr_in6;
    let mut result: CURLcode = CURLE_OK;
    let mut i: libc::c_int = 0;
    let mut curr: *mut libc::c_char = 0 as *mut libc::c_char;
    if he.is_null() {
        return 0 as *mut Curl_addrinfo;
    }
    i = 0 as libc::c_int;
    loop {
        curr = *((*he).h_addr_list).offset(i as isize);
        if curr.is_null() {
            break;
        }
        let mut ss_size: size_t = 0;
        let mut namelen: size_t = (strlen((*he).h_name))
            .wrapping_add(1 as libc::c_int as libc::c_ulong);
        if (*he).h_addrtype == 10 as libc::c_int {
            ss_size = ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong;
        } else {
            ss_size = ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong;
        }
        ai = Curl_ccalloc
            .expect(
                "non-null function pointer",
            )(
            1 as libc::c_int as size_t,
            (::std::mem::size_of::<Curl_addrinfo>() as libc::c_ulong)
                .wrapping_add(ss_size)
                .wrapping_add(namelen),
        ) as *mut Curl_addrinfo;
        if ai.is_null() {
            result = CURLE_OUT_OF_MEMORY;
            break;
        } else {
            let ref mut fresh6 = (*ai).ai_addr;
            *fresh6 = (ai as *mut libc::c_char)
                .offset(::std::mem::size_of::<Curl_addrinfo>() as libc::c_ulong as isize)
                as *mut libc::c_void as *mut sockaddr;
            let ref mut fresh7 = (*ai).ai_canonname;
            *fresh7 = ((*ai).ai_addr as *mut libc::c_char).offset(ss_size as isize);
            memcpy(
                (*ai).ai_canonname as *mut libc::c_void,
                (*he).h_name as *const libc::c_void,
                namelen,
            );
            if firstai.is_null() {
                firstai = ai;
            }
            if !prevai.is_null() {
                let ref mut fresh8 = (*prevai).ai_next;
                *fresh8 = ai;
            }
            (*ai).ai_family = (*he).h_addrtype;
            (*ai).ai_socktype = SOCK_STREAM as libc::c_int;
            (*ai).ai_addrlen = ss_size as curl_socklen_t;
            match (*ai).ai_family {
                2 => {
                    addr = (*ai).ai_addr as *mut libc::c_void as *mut sockaddr_in;
                    memcpy(
                        &mut (*addr).sin_addr as *mut in_addr as *mut libc::c_void,
                        curr as *const libc::c_void,
                        ::std::mem::size_of::<in_addr>() as libc::c_ulong,
                    );
                    (*addr).sin_family = (*he).h_addrtype as sa_family_t;
                    (*addr).sin_port = __bswap_16(port as libc::c_ushort);
                }
                10 => {
                    addr6 = (*ai).ai_addr as *mut libc::c_void as *mut sockaddr_in6;
                    memcpy(
                        &mut (*addr6).sin6_addr as *mut in6_addr as *mut libc::c_void,
                        curr as *const libc::c_void,
                        ::std::mem::size_of::<in6_addr>() as libc::c_ulong,
                    );
                    (*addr6).sin6_family = (*he).h_addrtype as sa_family_t;
                    (*addr6).sin6_port = __bswap_16(port as libc::c_ushort);
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
    mut af: libc::c_int,
    mut inaddr: *const libc::c_void,
    mut hostname: *const libc::c_char,
    mut port: libc::c_int,
) -> *mut Curl_addrinfo {
    let mut ai: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut h: *mut hostent = 0 as *mut hostent;
    let mut buf: *mut namebuff = 0 as *mut namebuff;
    let mut addrentry: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut hoststr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut addrsize: size_t = 0;
    buf = Curl_cmalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<namebuff>() as libc::c_ulong) as *mut namebuff;
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
            addrsize = ::std::mem::size_of::<in_addr>() as libc::c_ulong;
            addrentry = &mut (*buf).addrentry.ina4 as *mut in_addr as *mut libc::c_void
                as *mut libc::c_char;
            memcpy(
                addrentry as *mut libc::c_void,
                inaddr,
                ::std::mem::size_of::<in_addr>() as libc::c_ulong,
            );
        }
        10 => {
            addrsize = ::std::mem::size_of::<in6_addr>() as libc::c_ulong;
            addrentry = &mut (*buf).addrentry.ina6 as *mut in6_addr as *mut libc::c_void
                as *mut libc::c_char;
            memcpy(
                addrentry as *mut libc::c_void,
                inaddr,
                ::std::mem::size_of::<in6_addr>() as libc::c_ulong,
            );
        }
        _ => {
            Curl_cfree.expect("non-null function pointer")(hoststr as *mut libc::c_void);
            Curl_cfree.expect("non-null function pointer")(buf as *mut libc::c_void);
            return 0 as *mut Curl_addrinfo;
        }
    }
    h = &mut (*buf).hostentry;
    let ref mut fresh9 = (*h).h_name;
    *fresh9 = hoststr;
    let ref mut fresh10 = (*h).h_aliases;
    *fresh10 = 0 as *mut *mut libc::c_char;
    (*h).h_addrtype = af as libc::c_short as libc::c_int;
    (*h).h_length = addrsize as libc::c_short as libc::c_int;
    let ref mut fresh11 = (*h).h_addr_list;
    *fresh11 = &mut *((*buf).h_addr_list).as_mut_ptr().offset(0 as libc::c_int as isize)
        as *mut *mut libc::c_char;
    let ref mut fresh12 = *((*h).h_addr_list).offset(0 as libc::c_int as isize);
    *fresh12 = addrentry;
    let ref mut fresh13 = *((*h).h_addr_list).offset(1 as libc::c_int as isize);
    *fresh13 = 0 as *mut libc::c_char;
    ai = Curl_he2ai(h, port);
    Curl_cfree.expect("non-null function pointer")(hoststr as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(buf as *mut libc::c_void);
    return ai;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_str2addr(
    mut address: *mut libc::c_char,
    mut port: libc::c_int,
) -> *mut Curl_addrinfo {
    let mut in_0: in_addr = in_addr { s_addr: 0 };
    if inet_pton(
        2 as libc::c_int,
        address,
        &mut in_0 as *mut in_addr as *mut libc::c_void,
    ) > 0 as libc::c_int
    {
        return Curl_ip2addr(
            2 as libc::c_int,
            &mut in_0 as *mut in_addr as *const libc::c_void,
            address,
            port,
        );
    }
    let mut in6: in6_addr = in6_addr {
        __in6_u: C2RustUnnamed {
            __u6_addr8: [0; 16],
        },
    };
    if inet_pton(
        10 as libc::c_int,
        address,
        &mut in6 as *mut in6_addr as *mut libc::c_void,
    ) > 0 as libc::c_int
    {
        return Curl_ip2addr(
            10 as libc::c_int,
            &mut in6 as *mut in6_addr as *const libc::c_void,
            address,
            port,
        );
    }
    return 0 as *mut Curl_addrinfo;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_unix2addr(
    mut path: *const libc::c_char,
    mut longpath: *mut bool,
    mut abstract_0: bool,
) -> *mut Curl_addrinfo {
    let mut ai: *mut Curl_addrinfo = 0 as *mut Curl_addrinfo;
    let mut sa_un: *mut sockaddr_un = 0 as *mut sockaddr_un;
    let mut path_len: size_t = 0;
    *longpath = 0 as libc::c_int != 0;
    ai = Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(
        1 as libc::c_int as size_t,
        (::std::mem::size_of::<Curl_addrinfo>() as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<sockaddr_un>() as libc::c_ulong),
    ) as *mut Curl_addrinfo;
    if ai.is_null() {
        return 0 as *mut Curl_addrinfo;
    }
    let ref mut fresh14 = (*ai).ai_addr;
    *fresh14 = (ai as *mut libc::c_char)
        .offset(::std::mem::size_of::<Curl_addrinfo>() as libc::c_ulong as isize)
        as *mut libc::c_void as *mut sockaddr;
    sa_un = (*ai).ai_addr as *mut libc::c_void as *mut sockaddr_un;
    (*sa_un).sun_family = 1 as libc::c_int as sa_family_t;
    path_len = (strlen(path)).wrapping_add(1 as libc::c_int as libc::c_ulong);
    if path_len > ::std::mem::size_of::<[libc::c_char; 108]>() as libc::c_ulong {
        Curl_cfree.expect("non-null function pointer")(ai as *mut libc::c_void);
        *longpath = 1 as libc::c_int != 0;
        return 0 as *mut Curl_addrinfo;
    }
    (*ai).ai_family = 1 as libc::c_int;
    (*ai).ai_socktype = SOCK_STREAM as libc::c_int;
    (*ai)
        .ai_addrlen = ((2 as libc::c_ulong).wrapping_add(path_len)
        & 0x7fffffff as libc::c_int as libc::c_ulong) as curl_socklen_t;
    if abstract_0 {
        memcpy(
            ((*sa_un).sun_path).as_mut_ptr().offset(1 as libc::c_int as isize)
                as *mut libc::c_void,
            path as *const libc::c_void,
            path_len.wrapping_sub(1 as libc::c_int as libc::c_ulong),
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
