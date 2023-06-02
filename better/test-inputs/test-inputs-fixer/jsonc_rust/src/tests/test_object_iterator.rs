use :: libc;
extern "C" {
    pub type json_object;
    fn printf(_: *const i8, _: ...) -> i32;
    fn json_object_put(obj: *mut json_object) -> i32;
    fn json_object_to_json_string(obj: *mut json_object) -> *const i8;
    fn json_object_iter_init_default() -> json_object_iterator;
    fn json_object_iter_begin(obj: *mut json_object) -> json_object_iterator;
    fn json_object_iter_end(obj: *const json_object) -> json_object_iterator;
    fn json_object_iter_next(iter: *mut json_object_iterator);
    fn json_object_iter_peek_name(iter: *const json_object_iterator) -> *const i8;
    fn json_object_iter_peek_value(iter: *const json_object_iterator) -> *mut json_object;
    fn json_object_iter_equal(
        iter1: *const json_object_iterator,
        iter2: *const json_object_iterator,
    ) -> json_bool;
    fn json_tokener_parse(str: *const i8) -> *mut json_object;
}
pub type json_bool = i32;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object_iterator {
    pub opaque_: *const libc::c_void,
}
fn main_0(mut _atgc: i32, mut _argv: *mut *mut i8) -> i32 {
    let mut input : * const i8 = b"{\n\t\t\"string_of_digits\": \"123\",\n\t\t\"regular_number\": 222,\n\t\t\"decimal_number\": 99.55,\n\t\t\"boolean_true\": true,\n\t\t\"boolean_false\": false,\n\t\t\"big_number\": 2147483649,\n\t\t\"a_null\": null,\n\t\t}\0" as * const u8 as * const i8 ;
    let mut new_obj: *mut json_object = 0 as *mut json_object;
    let mut it: json_object_iterator = json_object_iterator {
        opaque_: 0 as *const libc::c_void,
    };
    let mut itEnd: json_object_iterator = json_object_iterator {
        opaque_: 0 as *const libc::c_void,
    };
    it = unsafe { json_object_iter_init_default() };
    new_obj = unsafe { json_tokener_parse(input) };
    it = unsafe { json_object_iter_begin(new_obj) };
    itEnd = unsafe { json_object_iter_end(new_obj) };
    while (unsafe { json_object_iter_equal(&mut it, &mut itEnd) }) == 0 {
        (unsafe { printf(
            b"%s\n\0" as *const u8 as *const i8,
            json_object_iter_peek_name(&mut it),
        ) });
        (unsafe { printf(
            b"%s\n\0" as *const u8 as *const i8,
            json_object_to_json_string(json_object_iter_peek_value(&mut it)),
        ) });
        (unsafe { json_object_iter_next(&mut it) });
    }
    (unsafe { json_object_put(new_obj) });
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
