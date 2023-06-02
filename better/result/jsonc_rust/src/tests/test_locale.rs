
extern "C" {
    fn printf(_: *const i8, _: ...) -> i32;
    fn snprintf(_: *mut i8, _: u64, _: *const i8, _: ...) -> i32;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn setlocale(__category: i32, __locale: *const i8) -> *mut i8;
}
pub use crate::src::{
    debug::mc_set_debug,
    json_object::{
        json_object, json_object_array_get_idx, json_object_array_length, json_object_get_double,
        json_object_put, json_object_to_json_string_ext,
    },
    json_tokener::json_tokener_parse,
};
pub type size_t = u64;
fn main_0(mut _argc: i32, mut _argv: *mut *mut i8) -> i32 {
    let mut new_obj: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    (unsafe { setlocale(1 as i32, b"de_DE\0" as *const u8 as *const i8) });
    let mut buf1: [i8; 10] = [0; 10];
    let mut buf2: [i8; 10] = [0; 10];
    (unsafe { snprintf(
        buf1.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 10]>() as u64,
        b"%f\0" as *const u8 as *const i8,
        0.1f64,
    ) });
    new_obj = json_tokener_parse(b"[1.2,3.4,123456.78,5.0,2.3e10]\0" as *const u8 as *const i8);
    (unsafe { snprintf(
        buf2.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 10]>() as u64,
        b"%f\0" as *const u8 as *const i8,
        0.1f64,
    ) });
    if (unsafe { strcmp(buf1.as_mut_ptr(), buf2.as_mut_ptr()) }) != 0 as i32 {
        (unsafe { printf(
            b"ERROR: Original locale not restored \"%s\" != \"%s\"\0" as *const u8 as *const i8,
            buf1.as_mut_ptr(),
            buf2.as_mut_ptr(),
        ) });
    }
    (unsafe { setlocale(1 as i32, b"C\0" as *const u8 as *const i8) });
    (unsafe { printf(b"new_obj.to_string()=[\0" as *const u8 as *const i8) });
    let mut ii: u32 = 0;
    ii = 0 as i32 as u32;
    while (ii as u64) < json_object_array_length(new_obj) {
        let mut val: *mut crate::src::json_object::json_object =
            json_object_array_get_idx(new_obj, ii as size_t);
        (unsafe { printf(
            b"%s%.2lf\0" as *const u8 as *const i8,
            if ii > 0 as i32 as u32 {
                b",\0" as *const u8 as *const i8
            } else {
                b"\0" as *const u8 as *const i8
            },
            json_object_get_double(val),
        ) });
        ii = ii.wrapping_add(1);
    }
    (unsafe { printf(b"]\n\0" as *const u8 as *const i8) });
    (unsafe { printf(
        b"new_obj.to_string()=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string_ext(new_obj, (1 as i32) << 2 as i32),
    ) });
    json_object_put(new_obj);
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

