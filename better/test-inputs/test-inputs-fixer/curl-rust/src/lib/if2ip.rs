use :: libc;
extern "C" {
    fn inet_ntop(
        __af: i32,
        __cp: *const libc::c_void,
        __buf: *mut i8,
        __len: socklen_t,
    ) -> *const i8;
    fn getifaddrs(__ifap: *mut *mut ifaddrs) -> i32;
    fn freeifaddrs(__ifa: *mut ifaddrs);
    fn Curl_strcasecompare(first: *const i8, second: *const i8) -> i32;
    fn curl_msnprintf(buffer: *mut i8, maxlength: size_t, format: *const i8, _: ...) -> i32;
}
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type __socklen_t = u32;
pub type size_t = u64;
pub type socklen_t = __socklen_t;
pub type sa_family_t = u16;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [i8; 14],
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
    pub sin_zero: [u8; 8],
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
    pub ifa_name: *mut i8,
    pub ifa_flags: u32,
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
pub type if2ip_result_t = u32;
pub const IF2IP_FOUND: if2ip_result_t = 2;
pub const IF2IP_AF_NOT_SUPPORTED: if2ip_result_t = 1;
pub const IF2IP_NOT_FOUND: if2ip_result_t = 0;
#[no_mangle]
pub extern "C" fn Curl_ipv6_scope(mut sa: *const sockaddr) -> u32 {
    if (unsafe { (*sa).sa_family }) as i32 == 10 as i32 {
        let mut sa6: *const sockaddr_in6 = sa as *mut libc::c_void as *const sockaddr_in6;
        let mut b: *const u8 = unsafe { ((*sa6).sin6_addr.__in6_u.__u6_addr8).as_ptr() };
        let mut w: u16 = (((unsafe { *b.offset(0 as i32 as isize) }) as i32) << 8 as i32
            | (unsafe { *b.offset(1 as i32 as isize) }) as i32) as u16;
        if (unsafe { *b.offset(0 as i32 as isize) }) as i32 & 0xfe as i32 == 0xfc as i32 {
            return 3 as i32 as u32;
        }
        match w as i32 & 0xffc0 as i32 {
            65152 => return 1 as i32 as u32,
            65216 => return 2 as i32 as u32,
            0 => {
                w = ((unsafe { *b.offset(1 as i32 as isize) }) as i32
                    | (unsafe { *b.offset(2 as i32 as isize) }) as i32
                    | (unsafe { *b.offset(3 as i32 as isize) }) as i32
                    | (unsafe { *b.offset(4 as i32 as isize) }) as i32
                    | (unsafe { *b.offset(5 as i32 as isize) }) as i32
                    | (unsafe { *b.offset(6 as i32 as isize) }) as i32
                    | (unsafe { *b.offset(7 as i32 as isize) }) as i32
                    | (unsafe { *b.offset(8 as i32 as isize) }) as i32
                    | (unsafe { *b.offset(9 as i32 as isize) }) as i32
                    | (unsafe { *b.offset(10 as i32 as isize) }) as i32
                    | (unsafe { *b.offset(11 as i32 as isize) }) as i32
                    | (unsafe { *b.offset(12 as i32 as isize) }) as i32
                    | (unsafe { *b.offset(13 as i32 as isize) }) as i32
                    | (unsafe { *b.offset(14 as i32 as isize) }) as i32) as u16;
                if !(w as i32 != 0 || (unsafe { *b.offset(15 as i32 as isize) }) as i32 != 0x1 as i32) {
                    return 4 as i32 as u32;
                }
            }
            _ => {}
        }
    }
    return 0 as i32 as u32;
}
#[no_mangle]
pub extern "C" fn Curl_if2ip(
    mut af: i32,
    mut remote_scope: u32,
    mut local_scope_id: u32,
    mut interf: *const i8,
    mut buf: *mut i8,
    mut buf_size: i32,
) -> if2ip_result_t {
    let mut iface: *mut ifaddrs = 0 as *mut ifaddrs;
    let mut head: *mut ifaddrs = 0 as *mut ifaddrs;
    let mut res: if2ip_result_t = IF2IP_NOT_FOUND;
    if (unsafe { getifaddrs(&mut head) }) >= 0 as i32 {
        let mut current_block_15: u64;
        iface = head;
        while !iface.is_null() {
            if !(unsafe { (*iface).ifa_addr }).is_null() {
                if (unsafe { (*(*iface).ifa_addr).sa_family }) as i32 == af {
                    if (unsafe { Curl_strcasecompare((*iface).ifa_name, interf) }) != 0 {
                        let mut addr: *mut libc::c_void = 0 as *mut libc::c_void;
                        let mut ip: *const i8 = 0 as *const i8;
                        let mut scope: [i8; 12] = *(unsafe { ::std::mem::transmute::<&[u8; 12], &mut [i8; 12]>(
                            b"\0\0\0\0\0\0\0\0\0\0\0\0",
                        ) });
                        let mut ipstr: [i8; 64] = [0; 64];
                        if af == 10 as i32 {
                            let mut scopeid: u32 = 0 as i32 as u32;
                            let mut ifscope: u32 = Curl_ipv6_scope(unsafe { (*iface).ifa_addr });
                            if ifscope != remote_scope {
                                if res as u32 == IF2IP_NOT_FOUND as i32 as u32 {
                                    res = IF2IP_AF_NOT_SUPPORTED;
                                }
                                current_block_15 = 14155750587950065367;
                            } else {
                                addr = (unsafe { &mut (*((*iface).ifa_addr as *mut libc::c_void
                                    as *mut sockaddr_in6))
                                    .sin6_addr })
                                    as *mut in6_addr
                                    as *mut libc::c_void;
                                scopeid = unsafe { (*((*iface).ifa_addr as *mut libc::c_void
                                    as *mut sockaddr_in6))
                                    .sin6_scope_id };
                                if local_scope_id != 0 && scopeid != local_scope_id {
                                    if res as u32 == IF2IP_NOT_FOUND as i32 as u32 {
                                        res = IF2IP_AF_NOT_SUPPORTED;
                                    }
                                    current_block_15 = 14155750587950065367;
                                } else {
                                    if scopeid != 0 {
                                        (unsafe { curl_msnprintf(
                                            scope.as_mut_ptr(),
                                            ::std::mem::size_of::<[i8; 12]>() as u64,
                                            b"%%%u\0" as *const u8 as *const i8,
                                            scopeid,
                                        ) });
                                    }
                                    current_block_15 = 14401909646449704462;
                                }
                            }
                        } else {
                            addr = (unsafe { &mut (*((*iface).ifa_addr as *mut libc::c_void
                                as *mut sockaddr_in))
                                .sin_addr }) as *mut in_addr
                                as *mut libc::c_void;
                            current_block_15 = 14401909646449704462;
                        }
                        match current_block_15 {
                            14155750587950065367 => {}
                            _ => {
                                res = IF2IP_FOUND;
                                ip = unsafe { inet_ntop(
                                    af,
                                    addr,
                                    ipstr.as_mut_ptr(),
                                    ::std::mem::size_of::<[i8; 64]>() as u64 as curl_socklen_t,
                                ) };
                                (unsafe { curl_msnprintf(
                                    buf,
                                    buf_size as size_t,
                                    b"%s%s\0" as *const u8 as *const i8,
                                    ip,
                                    scope.as_mut_ptr(),
                                ) });
                                break;
                            }
                        }
                    }
                } else if res as u32 == IF2IP_NOT_FOUND as i32 as u32
                    && (unsafe { Curl_strcasecompare((*iface).ifa_name, interf) }) != 0
                {
                    res = IF2IP_AF_NOT_SUPPORTED;
                }
            }
            iface = unsafe { (*iface).ifa_next };
        }
        (unsafe { freeifaddrs(head) });
    }
    return res;
}
