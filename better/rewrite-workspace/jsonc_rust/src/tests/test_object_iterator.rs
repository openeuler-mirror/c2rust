use ::libc;
extern "C" {
    
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::json_object::json_object_put;
pub use crate::src::json_object::json_object_to_json_string;
pub use crate::src::json_object_iterator::json_object_iter_begin;
pub use crate::src::json_object_iterator::json_object_iter_end;
pub use crate::src::json_object_iterator::json_object_iter_equal;
pub use crate::src::json_object_iterator::json_object_iter_init_default;
pub use crate::src::json_object_iterator::json_object_iter_next;
pub use crate::src::json_object_iterator::json_object_iter_peek_name;
pub use crate::src::json_object_iterator::json_object_iter_peek_value;
pub use crate::src::json_tokener::json_tokener_parse;
pub use crate::src::json_object::json_object;
pub use crate::src::json_object::json_bool;
// #[derive(Copy, Clone)]

pub use crate::src::json_object_iterator::json_object_iterator;
unsafe fn main_0(
    mut atgc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut input: *const libc::c_char = b"{\n\t\t\"string_of_digits\": \"123\",\n\t\t\"regular_number\": 222,\n\t\t\"decimal_number\": 99.55,\n\t\t\"boolean_true\": true,\n\t\t\"boolean_false\": false,\n\t\t\"big_number\": 2147483649,\n\t\t\"a_null\": null,\n\t\t}\0"
        as *const u8 as *const libc::c_char;
    let mut new_obj: *mut json_object = 0 as *mut json_object;
    let mut it: json_object_iterator = json_object_iterator {
        opaque_: 0 as *const libc::c_void,
    };
    let mut itEnd: json_object_iterator = json_object_iterator {
        opaque_: 0 as *const libc::c_void,
    };
    it = json_object_iter_init_default();
    new_obj = json_tokener_parse(input);
    it = json_object_iter_begin(new_obj);
    itEnd = json_object_iter_end(new_obj);
    while json_object_iter_equal(&mut it, &mut itEnd) == 0 {
        printf(
            b"%s\n\0" as *const u8 as *const libc::c_char,
            json_object_iter_peek_name(&mut it),
        );
        printf(
            b"%s\n\0" as *const u8 as *const libc::c_char,
            json_object_to_json_string(json_object_iter_peek_value(&mut it)),
        );
        json_object_iter_next(&mut it);
    }
    json_object_put(new_obj);
    return 0 as libc::c_int;
}
pub fn main() {
    let mut args: Vec::<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::std::ptr::null_mut());
    unsafe {
        ::std::process::exit(
            main_0(
                (args.len() - 1) as libc::c_int,
                args.as_mut_ptr() as *mut *mut libc::c_char,
            ) as i32,
        )
    }
}
