
extern "C" {
    fn _json_c_strerror(errno_in: i32) -> *mut i8;
    fn puts(__s: *const i8) -> i32;
}
fn main_0(mut _argc: i32, mut _argv: *mut *mut i8) -> i32 {
    (unsafe { puts(_json_c_strerror(10000 as i32)) });
    (unsafe { puts(_json_c_strerror(999 as i32)) });
    return 0 as i32;
}
pub fn main() {
    let mut args: Vec<*mut i8> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::std::ptr::null_mut());
     {
        ::std::process::exit(
            main_0((args.len() - 1) as i32, args.as_mut_ptr() as *mut *mut i8) as i32,
        )
    }
}
