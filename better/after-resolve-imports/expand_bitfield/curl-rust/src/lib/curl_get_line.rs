use ::libc;
extern "C" {
    
    
    
    fn fgets(
        __s: *mut i8,
        __n: i32,
        __stream: *mut FILE,
    ) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
}
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub type __off_t = crate::src::lib::http2::__off_t;
pub type __off64_t = crate::src::lib::http2::__off64_t;
pub type size_t = crate::src::lib::http2::size_t;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = crate::src::lib::http2::_IO_lock_t;
pub type FILE = crate::src::lib::http2::FILE;
#[no_mangle]
pub unsafe extern "C" fn Curl_get_line(
    mut buf: *mut i8,
    mut len: i32,
    mut input: *mut FILE,
) -> *mut i8 {
    let mut partial: bool = 0 as i32 != 0;
    loop {
        let mut b: *mut i8 = fgets(buf, len, input);
        if b.is_null() {
            break;
        }
        let mut rlen: size_t = strlen(b);
        if rlen != 0
            && *b.offset(rlen.wrapping_sub(1 as i32 as u64) as isize)
                as i32 == '\n' as i32
        {
            if partial {
                partial = 0 as i32 != 0;
            } else {
                return b
            }
        } else {
            partial = 1 as i32 != 0;
        }
    }
    return 0 as *mut i8;
}
