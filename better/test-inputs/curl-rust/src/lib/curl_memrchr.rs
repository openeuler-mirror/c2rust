use ::libc;
pub type size_t = libc::c_ulong;
#[no_mangle]
pub unsafe extern "C" fn Curl_memrchr(
    mut s: *const libc::c_void,
    mut c: libc::c_int,
    mut n: size_t,
) -> *mut libc::c_void {
    if n > 0 as libc::c_int as libc::c_ulong {
        let mut p: *const libc::c_uchar = s as *const libc::c_uchar;
        let mut q: *const libc::c_uchar = s as *const libc::c_uchar;
        p = p.offset(n.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize);
        while p >= q {
            if *p as libc::c_int == c as libc::c_uchar as libc::c_int {
                return p as *mut libc::c_void;
            }
            p = p.offset(-1);
        }
    }
    return 0 as *mut libc::c_void;
}
