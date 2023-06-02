use ::libc;
extern "C" {
    fn inet_ntop(
        __af: i32,
        __cp: *const libc::c_void,
        __buf: *mut i8,
        __len: socklen_t,
    ) -> *const i8;
    fn getifaddrs(__ifap: *mut *mut ifaddrs) -> i32;
    fn freeifaddrs(__ifa: *mut ifaddrs);
    
    
}
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub type __uint8_t = crate::src::lib::http2::__uint8_t;
pub type __uint16_t = crate::src::lib::connect::__uint16_t;
pub type __uint32_t = crate::src::lib::http2::__uint32_t;
pub type __socklen_t = crate::src::lib::http2::__socklen_t;
pub type size_t = crate::src::lib::http2::size_t;
pub type socklen_t = crate::src::lib::http2::socklen_t;
pub type sa_family_t = crate::src::lib::http2::sa_family_t;
// #[derive(Copy, Clone)]

pub type sockaddr = crate::src::lib::http2::sockaddr;
pub type curl_socklen_t = crate::src::lib::http2::curl_socklen_t;
pub type uint8_t = crate::src::lib::http2::uint8_t;
pub type uint16_t = crate::src::lib::connect::uint16_t;
pub type uint32_t = crate::src::lib::http2::uint32_t;
pub type in_addr_t = crate::src::lib::connect::in_addr_t;
// #[derive(Copy, Clone)]

pub type in_addr = crate::src::lib::connect::in_addr;
pub type in_port_t = crate::src::lib::connect::in_port_t;
// #[derive(Copy, Clone)]

pub type in6_addr = crate::src::lib::connect::in6_addr;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed = crate::src::lib::connect::C2RustUnnamed_8;
// #[derive(Copy, Clone)]

pub type sockaddr_in = crate::src::lib::connect::sockaddr_in;
// #[derive(Copy, Clone)]

pub type sockaddr_in6 = crate::src::lib::connect::sockaddr_in6;
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
pub type if2ip_result_t = crate::src::lib::connect::if2ip_result_t;
pub const IF2IP_FOUND: if2ip_result_t = 2;
pub const IF2IP_AF_NOT_SUPPORTED: if2ip_result_t = 1;
pub const IF2IP_NOT_FOUND: if2ip_result_t = 0;
#[no_mangle]
pub unsafe extern "C" fn Curl_ipv6_scope(mut sa: *const sockaddr) -> u32 {
    if (*sa).sa_family as i32 == 10 as i32 {
        let mut sa6: *const sockaddr_in6 = sa as *mut libc::c_void
            as *const sockaddr_in6;
        let mut b: *const u8 = ((*sa6).sin6_addr.__in6_u.__u6_addr8).as_ptr();
        let mut w: u16 = ((*b.offset(0 as i32 as isize)
            as i32) << 8 as i32
            | *b.offset(1 as i32 as isize) as i32) as u16;
        if *b.offset(0 as i32 as isize) as i32 & 0xfe as i32
            == 0xfc as i32
        {
            return 3 as i32 as u32;
        }
        match w as i32 & 0xffc0 as i32 {
            65152 => return 1 as i32 as u32,
            65216 => return 2 as i32 as u32,
            0 => {
                w = (*b.offset(1 as i32 as isize) as i32
                    | *b.offset(2 as i32 as isize) as i32
                    | *b.offset(3 as i32 as isize) as i32
                    | *b.offset(4 as i32 as isize) as i32
                    | *b.offset(5 as i32 as isize) as i32
                    | *b.offset(6 as i32 as isize) as i32
                    | *b.offset(7 as i32 as isize) as i32
                    | *b.offset(8 as i32 as isize) as i32
                    | *b.offset(9 as i32 as isize) as i32
                    | *b.offset(10 as i32 as isize) as i32
                    | *b.offset(11 as i32 as isize) as i32
                    | *b.offset(12 as i32 as isize) as i32
                    | *b.offset(13 as i32 as isize) as i32
                    | *b.offset(14 as i32 as isize) as i32)
                    as u16;
                if !(w as i32 != 0
                    || *b.offset(15 as i32 as isize) as i32
                        != 0x1 as i32)
                {
                    return 4 as i32 as u32;
                }
            }
            _ => {}
        }
    }
    return 0 as i32 as u32;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_if2ip(
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
    if getifaddrs(&mut head) >= 0 as i32 {
        let mut current_block_15: u64;
        iface = head;
        while !iface.is_null() {
            if !((*iface).ifa_addr).is_null() {
                if (*(*iface).ifa_addr).sa_family as i32 == af {
                    if Curl_strcasecompare((*iface).ifa_name, interf) != 0 {
                        let mut addr: *mut libc::c_void = 0 as *mut libc::c_void;
                        let mut ip: *const i8 = 0 as *const i8;
                        let mut scope: [i8; 12] = *::std::mem::transmute::<
                            &[u8; 12],
                            &mut [i8; 12],
                        >(b"\0\0\0\0\0\0\0\0\0\0\0\0");
                        let mut ipstr: [i8; 64] = [0; 64];
                        if af == 10 as i32 {
                            let mut scopeid: u32 = 0 as i32
                                as u32;
                            let mut ifscope: u32 = Curl_ipv6_scope(
                                (*iface).ifa_addr,
                            );
                            if ifscope != remote_scope {
                                if res as u32
                                    == IF2IP_NOT_FOUND as i32 as u32
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
                                    if res as u32
                                        == IF2IP_NOT_FOUND as i32 as u32
                                    {
                                        res = IF2IP_AF_NOT_SUPPORTED;
                                    }
                                    current_block_15 = 14155750587950065367;
                                } else {
                                    if scopeid != 0 {
                                        curl_msnprintf(
                                            scope.as_mut_ptr(),
                                            ::std::mem::size_of::<[i8; 12]>()
                                                as u64,
                                            b"%%%u\0" as *const u8 as *const i8,
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
                                    ::std::mem::size_of::<[i8; 64]>() as u64
                                        as curl_socklen_t,
                                );
                                curl_msnprintf(
                                    buf,
                                    buf_size as size_t,
                                    b"%s%s\0" as *const u8 as *const i8,
                                    ip,
                                    scope.as_mut_ptr(),
                                );
                                break;
                            }
                        }
                    }
                } else if res as u32
                        == IF2IP_NOT_FOUND as i32 as u32
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
