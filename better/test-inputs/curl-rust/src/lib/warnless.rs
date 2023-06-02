use ::libc;
pub type __ssize_t = libc::c_long;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
pub type curl_off_t = libc::c_long;
#[no_mangle]
pub unsafe extern "C" fn curlx_ultous(mut ulnum: libc::c_ulong) -> libc::c_ushort {
    return (ulnum & !(0 as libc::c_int) as libc::c_ushort as libc::c_ulong)
        as libc::c_ushort;
}
#[no_mangle]
pub unsafe extern "C" fn curlx_ultouc(mut ulnum: libc::c_ulong) -> libc::c_uchar {
    return (ulnum & !(0 as libc::c_int) as libc::c_uchar as libc::c_ulong)
        as libc::c_uchar;
}
#[no_mangle]
pub unsafe extern "C" fn curlx_uztoso(mut uznum: size_t) -> curl_off_t {
    return (uznum & !(0 as libc::c_int) as libc::c_ulong >> 1 as libc::c_int)
        as curl_off_t;
}
#[no_mangle]
pub unsafe extern "C" fn curlx_uztosi(mut uznum: size_t) -> libc::c_int {
    return (uznum & (!(0 as libc::c_int) as libc::c_uint >> 1 as libc::c_int) as size_t)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn curlx_uztoul(mut uznum: size_t) -> libc::c_ulong {
    return uznum & !(0 as libc::c_int) as libc::c_ulong;
}
#[no_mangle]
pub unsafe extern "C" fn curlx_uztoui(mut uznum: size_t) -> libc::c_uint {
    return (uznum & !(0 as libc::c_int) as libc::c_uint as size_t) as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn curlx_sltosi(mut slnum: libc::c_long) -> libc::c_int {
    return (slnum
        & (!(0 as libc::c_int) as libc::c_uint >> 1 as libc::c_int) as libc::c_long)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn curlx_sltoui(mut slnum: libc::c_long) -> libc::c_uint {
    return (slnum & !(0 as libc::c_int) as libc::c_uint as libc::c_long) as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn curlx_sltous(mut slnum: libc::c_long) -> libc::c_ushort {
    return (slnum & !(0 as libc::c_int) as libc::c_ushort as libc::c_long)
        as libc::c_ushort;
}
#[no_mangle]
pub unsafe extern "C" fn curlx_uztosz(mut uznum: size_t) -> ssize_t {
    return (uznum & !(0 as libc::c_int) as size_t >> 1 as libc::c_int) as ssize_t;
}
#[no_mangle]
pub unsafe extern "C" fn curlx_sotouz(mut sonum: curl_off_t) -> size_t {
    return (sonum & !(0 as libc::c_int) as size_t as curl_off_t) as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn curlx_sztosi(mut sznum: ssize_t) -> libc::c_int {
    return (sznum & (!(0 as libc::c_int) as libc::c_uint >> 1 as libc::c_int) as ssize_t)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn curlx_uitous(mut uinum: libc::c_uint) -> libc::c_ushort {
    return (uinum & !(0 as libc::c_int) as libc::c_ushort as libc::c_uint)
        as libc::c_ushort;
}
#[no_mangle]
pub unsafe extern "C" fn curlx_sitouz(mut sinum: libc::c_int) -> size_t {
    return sinum as size_t;
}
