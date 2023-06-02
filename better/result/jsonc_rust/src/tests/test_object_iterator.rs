use :: libc;
extern "C" {
    fn printf(_: *const i8, _: ...) -> i32;
}
pub use crate::src::{
    json_object::{json_object, json_object_put, json_object_to_json_string},
    json_object_iterator::{
        json_object_iter_begin, json_object_iter_end, json_object_iter_equal,
        json_object_iter_init_default, json_object_iter_next, json_object_iter_peek_name,
        json_object_iter_peek_value,
    },
    json_tokener::json_tokener_parse,
};
pub type json_bool = i32;
pub type json_object_iterator = crate::src::json_object_iterator::json_object_iterator;
fn main_0(mut _atgc: i32, mut _argv: *mut *mut i8) -> i32 {
    let mut input : * const i8 = b"{\n\t\t\"string_of_digits\": \"123\",\n\t\t\"regular_number\": 222,\n\t\t\"decimal_number\": 99.55,\n\t\t\"boolean_true\": true,\n\t\t\"boolean_false\": false,\n\t\t\"big_number\": 2147483649,\n\t\t\"a_null\": null,\n\t\t}\0" as * const u8 as * const i8 ;
    let mut new_obj: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut it: crate::src::json_object_iterator::json_object_iterator = json_object_iterator {
        opaque_: 0 as *const libc::c_void,
    };
    let mut itEnd: crate::src::json_object_iterator::json_object_iterator = json_object_iterator {
        opaque_: 0 as *const libc::c_void,
    };
    it = json_object_iter_init_default();
    new_obj = json_tokener_parse(input);
    it = json_object_iter_begin(new_obj);
    itEnd = json_object_iter_end(new_obj);
    while json_object_iter_equal(Some(&mut it), Some(&mut itEnd)) == 0 {
        (unsafe { printf(
            b"%s\n\0" as *const u8 as *const i8,
            json_object_iter_peek_name(Some(&mut it)),
        ) });
        (unsafe { printf(
            b"%s\n\0" as *const u8 as *const i8,
            json_object_to_json_string(json_object_iter_peek_value(Some(&mut it))),
        ) });
        json_object_iter_next(&mut it);
    }
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

