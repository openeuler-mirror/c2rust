use ::libc;
pub type size_t = crate::src::lib::altsvc::size_t;
#[no_mangle]
pub unsafe extern "C" fn Curl_memrchr(
    mut s: *const libc::c_void,
    mut c: i32,
    mut n: size_t,
) -> *mut libc::c_void {
    if n > 0 as i32 as u64 {
        let mut p: *const u8 = s as *const u8;
        let mut q: *const u8 = s as *const u8;
        p = p.offset(n.wrapping_sub(1 as i32 as u64) as isize);
        while p >= q {
            if *p as i32 == c as u8 as i32 {
                return p as *mut libc::c_void;
            }
            p = p.offset(-1);
        }
    }
    return 0 as *mut libc::c_void;
}
