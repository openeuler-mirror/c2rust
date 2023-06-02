use ::libc;
#[no_mangle]
pub unsafe extern "C" fn Curl_read16_le(
    mut buf: *const libc::c_uchar,
) -> libc::c_ushort {
    return (*buf.offset(0 as libc::c_int as isize) as libc::c_ushort as libc::c_int
        | (*buf.offset(1 as libc::c_int as isize) as libc::c_ushort as libc::c_int)
            << 8 as libc::c_int) as libc::c_ushort;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_read32_le(mut buf: *const libc::c_uchar) -> libc::c_uint {
    return *buf.offset(0 as libc::c_int as isize) as libc::c_uint
        | (*buf.offset(1 as libc::c_int as isize) as libc::c_uint) << 8 as libc::c_int
        | (*buf.offset(2 as libc::c_int as isize) as libc::c_uint) << 16 as libc::c_int
        | (*buf.offset(3 as libc::c_int as isize) as libc::c_uint) << 24 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_read16_be(
    mut buf: *const libc::c_uchar,
) -> libc::c_ushort {
    return ((*buf.offset(0 as libc::c_int as isize) as libc::c_ushort as libc::c_int)
        << 8 as libc::c_int
        | *buf.offset(1 as libc::c_int as isize) as libc::c_ushort as libc::c_int)
        as libc::c_ushort;
}
