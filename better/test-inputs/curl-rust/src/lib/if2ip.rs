use ::libc;
extern "C" {
    fn inet_ntop(
        __af: libc::c_int,
        __cp: *const libc::c_void,
        __buf: *mut libc::c_char,
        __len: socklen_t,
    ) -> *const libc::c_char;
    fn getifaddrs(__ifap: *mut *mut ifaddrs) -> libc::c_int;
    fn freeifaddrs(__ifa: *mut ifaddrs);
    fn Curl_strcasecompare(
        first: *const libc::c_char,
        second: *const libc::c_char,
    ) -> libc::c_int;
    fn curl_msnprintf(
        buffer: *mut libc::c_char,
        maxlength: size_t,
        format: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
}
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __socklen_t = libc::c_uint;
pub type size_t = libc::c_ulong;
pub type socklen_t = __socklen_t;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
pub type curl_socklen_t = socklen_t;
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
pub struct ifaddrs {
    pub ifa_next: *mut ifaddrs,
    pub ifa_name: *mut libc::c_char,
    pub ifa_flags: libc::c_uint,
    pub ifa_addr: *mut sockaddr,
    pub ifa_netmask: *mut sockaddr,
    pub ifa_ifu: C2RustUnnamed_0,
    pub ifa_data: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub ifu_broadaddr: *mut sockaddr,
    pub ifu_dstaddr: *mut sockaddr,
}
pub type if2ip_result_t = libc::c_uint;
pub const IF2IP_FOUND: if2ip_result_t = 2;
pub const IF2IP_AF_NOT_SUPPORTED: if2ip_result_t = 1;
pub const IF2IP_NOT_FOUND: if2ip_result_t = 0;
#[no_mangle]
pub unsafe extern "C" fn Curl_ipv6_scope(mut sa: *const sockaddr) -> libc::c_uint {
    if (*sa).sa_family as libc::c_int == 10 as libc::c_int {
        let mut sa6: *const sockaddr_in6 = sa as *mut libc::c_void
            as *const sockaddr_in6;
        let mut b: *const libc::c_uchar = ((*sa6).sin6_addr.__in6_u.__u6_addr8).as_ptr();
        let mut w: libc::c_ushort = ((*b.offset(0 as libc::c_int as isize)
            as libc::c_int) << 8 as libc::c_int
            | *b.offset(1 as libc::c_int as isize) as libc::c_int) as libc::c_ushort;
        if *b.offset(0 as libc::c_int as isize) as libc::c_int & 0xfe as libc::c_int
            == 0xfc as libc::c_int
        {
            return 3 as libc::c_int as libc::c_uint;
        }
        match w as libc::c_int & 0xffc0 as libc::c_int {
            65152 => return 1 as libc::c_int as libc::c_uint,
            65216 => return 2 as libc::c_int as libc::c_uint,
            0 => {
                w = (*b.offset(1 as libc::c_int as isize) as libc::c_int
                    | *b.offset(2 as libc::c_int as isize) as libc::c_int
                    | *b.offset(3 as libc::c_int as isize) as libc::c_int
                    | *b.offset(4 as libc::c_int as isize) as libc::c_int
                    | *b.offset(5 as libc::c_int as isize) as libc::c_int
                    | *b.offset(6 as libc::c_int as isize) as libc::c_int
                    | *b.offset(7 as libc::c_int as isize) as libc::c_int
                    | *b.offset(8 as libc::c_int as isize) as libc::c_int
                    | *b.offset(9 as libc::c_int as isize) as libc::c_int
                    | *b.offset(10 as libc::c_int as isize) as libc::c_int
                    | *b.offset(11 as libc::c_int as isize) as libc::c_int
                    | *b.offset(12 as libc::c_int as isize) as libc::c_int
                    | *b.offset(13 as libc::c_int as isize) as libc::c_int
                    | *b.offset(14 as libc::c_int as isize) as libc::c_int)
                    as libc::c_ushort;
                if !(w as libc::c_int != 0
                    || *b.offset(15 as libc::c_int as isize) as libc::c_int
                        != 0x1 as libc::c_int)
                {
                    return 4 as libc::c_int as libc::c_uint;
                }
            }
            _ => {}
        }
    }
    return 0 as libc::c_int as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_if2ip(
    mut af: libc::c_int,
    mut remote_scope: libc::c_uint,
    mut local_scope_id: libc::c_uint,
    mut interf: *const libc::c_char,
    mut buf: *mut libc::c_char,
    mut buf_size: libc::c_int,
) -> if2ip_result_t {
    let mut iface: *mut ifaddrs = 0 as *mut ifaddrs;
    let mut head: *mut ifaddrs = 0 as *mut ifaddrs;
    let mut res: if2ip_result_t = IF2IP_NOT_FOUND;
    if getifaddrs(&mut head) >= 0 as libc::c_int {
        let mut current_block_15: u64;
        iface = head;
        while !iface.is_null() {
            if !((*iface).ifa_addr).is_null() {
                if (*(*iface).ifa_addr).sa_family as libc::c_int == af {
                    if Curl_strcasecompare((*iface).ifa_name, interf) != 0 {
                        let mut addr: *mut libc::c_void = 0 as *mut libc::c_void;
                        let mut ip: *const libc::c_char = 0 as *const libc::c_char;
                        let mut scope: [libc::c_char; 12] = *::std::mem::transmute::<
                            &[u8; 12],
                            &mut [libc::c_char; 12],
                        >(b"\0\0\0\0\0\0\0\0\0\0\0\0");
                        let mut ipstr: [libc::c_char; 64] = [0; 64];
                        if af == 10 as libc::c_int {
                            let mut scopeid: libc::c_uint = 0 as libc::c_int
                                as libc::c_uint;
                            let mut ifscope: libc::c_uint = Curl_ipv6_scope(
                                (*iface).ifa_addr,
                            );
                            if ifscope != remote_scope {
                                if res as libc::c_uint
                                    == IF2IP_NOT_FOUND as libc::c_int as libc::c_uint
                                {
                                    res = IF2IP_AF_NOT_SUPPORTED;
                                }
                                current_block_15 = 14155750587950065367;
                            } else {
                                addr = &mut (*((*iface).ifa_addr as *mut libc::c_void
                                    as *mut sockaddr_in6))
                                    .sin6_addr as *mut in6_addr as *mut libc::c_void;
                                scopeid = (*((*iface).ifa_addr as *mut libc::c_void
                                    as *mut sockaddr_in6))
                                    .sin6_scope_id;
                                if local_scope_id != 0 && scopeid != local_scope_id {
                                    if res as libc::c_uint
                                        == IF2IP_NOT_FOUND as libc::c_int as libc::c_uint
                                    {
                                        res = IF2IP_AF_NOT_SUPPORTED;
                                    }
                                    current_block_15 = 14155750587950065367;
                                } else {
                                    if scopeid != 0 {
                                        curl_msnprintf(
                                            scope.as_mut_ptr(),
                                            ::std::mem::size_of::<[libc::c_char; 12]>()
                                                as libc::c_ulong,
                                            b"%%%u\0" as *const u8 as *const libc::c_char,
                                            scopeid,
                                        );
                                    }
                                    current_block_15 = 14401909646449704462;
                                }
                            }
                        } else {
                            addr = &mut (*((*iface).ifa_addr as *mut libc::c_void
                                as *mut sockaddr_in))
                                .sin_addr as *mut in_addr as *mut libc::c_void;
                            current_block_15 = 14401909646449704462;
                        }
                        match current_block_15 {
                            14155750587950065367 => {}
                            _ => {
                                res = IF2IP_FOUND;
                                ip = inet_ntop(
                                    af,
                                    addr,
                                    ipstr.as_mut_ptr(),
                                    ::std::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong
                                        as curl_socklen_t,
                                );
                                curl_msnprintf(
                                    buf,
                                    buf_size as size_t,
                                    b"%s%s\0" as *const u8 as *const libc::c_char,
                                    ip,
                                    scope.as_mut_ptr(),
                                );
                                break;
                            }
                        }
                    }
                } else if res as libc::c_uint
                        == IF2IP_NOT_FOUND as libc::c_int as libc::c_uint
                        && Curl_strcasecompare((*iface).ifa_name, interf) != 0
                    {
                    res = IF2IP_AF_NOT_SUPPORTED;
                }
            }
            iface = (*iface).ifa_next;
        }
        freeifaddrs(head);
    }
    return res;
}
