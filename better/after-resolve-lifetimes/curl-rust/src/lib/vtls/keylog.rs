use ::libc;
extern "C" {
    
    
    
    
    fn fclose(__stream: * mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn fopen(_: * const i8, _: * const i8) -> * mut crate::src::lib::http2::_IO_FILE;
    fn setvbuf(
        __stream: * mut crate::src::lib::http2::_IO_FILE,
        __buf: * mut i8,
        __modes: i32,
        __n: u64,
    ) -> i32;
    fn fputs(__s: * const i8, __stream: * mut crate::src::lib::http2::_IO_FILE) -> i32;
    fn memcpy(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn strlen(_: * const i8) -> u64;
    
}
pub use crate::src::lib::getenv::curl_getenv;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type size_t = u64;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::lib::http2::_IO_FILE;
pub type curl_free_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> ()>;
static mut keylog_file_fp: * mut crate::src::lib::http2::_IO_FILE = 0 as *const FILE as *mut FILE;
#[no_mangle]
pub unsafe extern "C" fn Curl_tls_keylog_open() {
    let mut keylog_file_name: * mut i8 = 0 as *mut i8;
    if keylog_file_fp.is_null() {
        keylog_file_name = curl_getenv(
            b"SSLKEYLOGFILE\0" as *const u8 as *const i8,
        );
        if !keylog_file_name.is_null() {
            keylog_file_fp = fopen(
                keylog_file_name,
                b"a\0" as *const u8 as *const i8,
            );
            if !keylog_file_fp.is_null() {
                if setvbuf(
                    keylog_file_fp,
                    0 as *mut i8,
                    1 as i32,
                    4096 as i32 as size_t,
                ) != 0
                {
                    fclose(keylog_file_fp);
                    keylog_file_fp = 0 as *mut FILE;
                }
            }
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )(keylog_file_name as *mut libc::c_void);
            keylog_file_name = 0 as *mut i8;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_tls_keylog_close() {
    if !keylog_file_fp.is_null() {
        fclose(keylog_file_fp);
        keylog_file_fp = 0 as *mut FILE;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_tls_keylog_enabled() -> bool {
    return !keylog_file_fp.is_null();
}
#[no_mangle]
pub unsafe extern "C" fn Curl_tls_keylog_write_line(
    mut line: * const i8,
) -> bool {
    let mut linelen: u64 = 0;
    let mut buf: [i8; 256] = [0; 256];
    if keylog_file_fp.is_null() || line.is_null() {
        return 0 as i32 != 0;
    }
    linelen = strlen(line);
    if linelen == 0 as i32 as u64
        || linelen
            > (::std::mem::size_of::<[i8; 256]>() as u64)
                .wrapping_sub(2 as i32 as u64)
    {
        return 0 as i32 != 0;
    }
    memcpy(buf.as_mut_ptr() as *mut libc::c_void, line as *const libc::c_void, linelen);
    if *line.offset(linelen.wrapping_sub(1 as i32 as u64) as isize)
        as i32 != '\n' as i32
    {
        let mut fresh0 = linelen;
        linelen = linelen.wrapping_add(1);
        buf[fresh0 as usize] = '\n' as i32 as i8;
    }
    buf[linelen as usize] = '\u{0}' as i32 as i8;
    fputs(buf.as_mut_ptr(), keylog_file_fp);
    return 1 as i32 != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_tls_keylog_write<'a1, 'a2>(
    mut label: * const i8,
    mut client_random: Option<crate::__laertes_array::CustomSlice<'a1, u8, &'a1  [u8]>>,
    mut secret: Option<crate::__laertes_array::CustomSlice<'a2, u8, &'a2  [u8]>>,
    mut secretlen: u64,
) -> bool {
    let mut hex: * const i8 = b"0123456789ABCDEF\0" as *const u8
        as *const i8;
    let mut pos: u64 = 0;
    let mut i: u64 = 0;
    let mut line: [i8; 195] = [0; 195];
    if keylog_file_fp.is_null() {
        return 0 as i32 != 0;
    }
    pos = strlen(label);
    if pos
        > (::std::mem::size_of::<[i8; 32]>() as u64)
            .wrapping_sub(1 as i32 as u64) || secretlen == 0
        || secretlen > 48 as i32 as u64
    {
        return 0 as i32 != 0;
    }
    memcpy(line.as_mut_ptr() as *mut libc::c_void, label as *const libc::c_void, pos);
    let mut fresh1 = pos;
    pos = pos.wrapping_add(1);
    line[fresh1 as usize] = ' ' as i32 as i8;
    i = 0 as i32 as size_t;
    while i < 32 as i32 as u64 {
        let mut fresh2 = pos;
        pos = pos.wrapping_add(1);
        line[fresh2
            as usize] = *hex
            .offset(
                ((*crate::__laertes_array::Get::<&_>::get_offset(crate::__laertes_array::borrow(& client_random)/*borrow*/.as_ref().unwrap(), (i as isize))) as i32 >> 4 as i32)
                    as isize,
            );
        let mut fresh3 = pos;
        pos = pos.wrapping_add(1);
        line[fresh3
            as usize] = *hex
            .offset(
                ((*crate::__laertes_array::Get::<&_>::get_offset(crate::__laertes_array::borrow(& client_random)/*borrow*/.as_ref().unwrap(), (i as isize))) as i32 & 0xf as i32)
                    as isize,
            );
        i = i.wrapping_add(1);
    }
    let mut fresh4 = pos;
    pos = pos.wrapping_add(1);
    line[fresh4 as usize] = ' ' as i32 as i8;
    i = 0 as i32 as size_t;
    while i < secretlen {
        let mut fresh5 = pos;
        pos = pos.wrapping_add(1);
        line[fresh5
            as usize] = *hex
            .offset(
                ((*crate::__laertes_array::Get::<&_>::get_offset(crate::__laertes_array::borrow(& secret)/*borrow*/.as_ref().unwrap(), (i as isize))) as i32 >> 4 as i32) as isize,
            );
        let mut fresh6 = pos;
        pos = pos.wrapping_add(1);
        line[fresh6
            as usize] = *hex
            .offset(
                ((*crate::__laertes_array::Get::<&_>::get_offset(crate::__laertes_array::borrow(& secret)/*borrow*/.as_ref().unwrap(), (i as isize))) as i32 & 0xf as i32) as isize,
            );
        i = i.wrapping_add(1);
    }
    let mut fresh7 = pos;
    pos = pos.wrapping_add(1);
    line[fresh7 as usize] = '\n' as i32 as i8;
    line[pos as usize] = '\u{0}' as i32 as i8;
    fputs(line.as_mut_ptr(), keylog_file_fp);
    return 1 as i32 != 0;
}
use crate::laertes_rt::*;
