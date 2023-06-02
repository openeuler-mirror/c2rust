
extern "C" {
    fn __assert_fail(
        __assertion: *const i8,
        __file: *const i8,
        __line: u32,
        __function: *const i8,
    ) -> !;
    fn printf(_: *const i8, _: ...) -> i32;
}
pub use crate::src::{
    debug::mc_set_debug,
    json_object::json_object,
    json_tokener::{
        json_tokener_free, json_tokener_new, json_tokener_parse_ex, json_tokener_set_flags,
    },
};
pub type printbuf = crate::src::apps::json_parse::printbuf;
pub type json_tokener_error = u32;
pub const json_tokener_error_size: json_tokener_error = 15;
pub const json_tokener_error_parse_utf8_string: json_tokener_error = 14;
pub const json_tokener_error_parse_comment: json_tokener_error = 13;
pub const json_tokener_error_parse_string: json_tokener_error = 12;
pub const json_tokener_error_parse_object_value_sep: json_tokener_error = 11;
pub const json_tokener_error_parse_object_key_sep: json_tokener_error = 10;
pub const json_tokener_error_parse_object_key_name: json_tokener_error = 9;
pub const json_tokener_error_parse_array: json_tokener_error = 8;
pub const json_tokener_error_parse_number: json_tokener_error = 7;
pub const json_tokener_error_parse_boolean: json_tokener_error = 6;
pub const json_tokener_error_parse_null: json_tokener_error = 5;
pub const json_tokener_error_parse_unexpected: json_tokener_error = 4;
pub const json_tokener_error_parse_eof: json_tokener_error = 3;
pub const json_tokener_error_depth: json_tokener_error = 2;
pub const json_tokener_continue: json_tokener_error = 1;
pub const json_tokener_success: json_tokener_error = 0;
pub type json_tokener_state = u32;
pub const json_tokener_state_inf: json_tokener_state = 26;
pub const json_tokener_state_object_field_start_after_sep: json_tokener_state = 25;
pub const json_tokener_state_array_after_sep: json_tokener_state = 24;
pub const json_tokener_state_object_sep: json_tokener_state = 23;
pub const json_tokener_state_object_value_add: json_tokener_state = 22;
pub const json_tokener_state_object_value: json_tokener_state = 21;
pub const json_tokener_state_object_field_end: json_tokener_state = 20;
pub const json_tokener_state_object_field: json_tokener_state = 19;
pub const json_tokener_state_object_field_start: json_tokener_state = 18;
pub const json_tokener_state_array_sep: json_tokener_state = 17;
pub const json_tokener_state_array_add: json_tokener_state = 16;
pub const json_tokener_state_array: json_tokener_state = 15;
pub const json_tokener_state_number: json_tokener_state = 14;
pub const json_tokener_state_boolean: json_tokener_state = 13;
pub const json_tokener_state_escape_unicode_need_u: json_tokener_state = 12;
pub const json_tokener_state_escape_unicode_need_escape: json_tokener_state = 11;
pub const json_tokener_state_escape_unicode: json_tokener_state = 10;
pub const json_tokener_state_string_escape: json_tokener_state = 9;
pub const json_tokener_state_string: json_tokener_state = 8;
pub const json_tokener_state_comment_end: json_tokener_state = 7;
pub const json_tokener_state_comment_eol: json_tokener_state = 6;
pub const json_tokener_state_comment: json_tokener_state = 5;
pub const json_tokener_state_comment_start: json_tokener_state = 4;
pub const json_tokener_state_null: json_tokener_state = 3;
pub const json_tokener_state_finish: json_tokener_state = 2;
pub const json_tokener_state_start: json_tokener_state = 1;
pub const json_tokener_state_eatws: json_tokener_state = 0;
pub type json_tokener_srec<'a> = crate::src::apps::json_parse::json_tokener_srec<'a>;
pub type json_tokener<'a> = crate::src::apps::json_parse::json_tokener<'a>;
fn main_0(mut _argc: i32, mut _argv: *mut *mut i8) -> i32 {
    test_case_parse();
    return 0 as i32;
}
extern "C" fn test_case_parse() {
    let mut tok: *mut crate::src::apps::json_parse::json_tokener<'_> = 0 as *mut json_tokener;
    let mut new_obj: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    tok = json_tokener_new();
    json_tokener_set_flags(tok, 0x1 as i32);
    new_obj = json_tokener_parse_ex(tok, b"True\0" as *const u8 as *const i8, 4 as i32);
    if new_obj.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"new_obj == NULL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_charcase.c\0" as *const u8 as *const i8,
            34 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 27], &'_ [i8; 27]>(
                b"void test_case_parse(void)\0",
            ))
            .as_ptr(),
        ) });
    }
    new_obj = json_tokener_parse_ex(tok, b"False\0" as *const u8 as *const i8, 5 as i32);
    if new_obj.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"new_obj == NULL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_charcase.c\0" as *const u8 as *const i8,
            37 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 27], &'_ [i8; 27]>(
                b"void test_case_parse(void)\0",
            ))
            .as_ptr(),
        ) });
    }
    new_obj = json_tokener_parse_ex(tok, b"Null\0" as *const u8 as *const i8, 4 as i32);
    if new_obj.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"new_obj == NULL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_charcase.c\0" as *const u8 as *const i8,
            40 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 27], &'_ [i8; 27]>(
                b"void test_case_parse(void)\0",
            ))
            .as_ptr(),
        ) });
    }
    (unsafe { printf(b"OK\n\0" as *const u8 as *const i8) });
    json_tokener_free(tok);
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

