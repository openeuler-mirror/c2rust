use ::libc;
extern "C" {
    
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    
    
    
    
    
}
pub use crate::src::debug::mc_set_debug;
pub use crate::src::json_tokener::json_tokener_free;
pub use crate::src::json_tokener::json_tokener_new;
pub use crate::src::json_tokener::json_tokener_parse_ex;
pub use crate::src::json_tokener::json_tokener_set_flags;
pub use crate::src::json_object::json_object;
// #[derive(Copy, Clone)]

pub use crate::src::apps::json_parse::printbuf;
pub use crate::src::apps::json_parse::json_tokener_error;
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
pub use crate::src::apps::json_parse::json_tokener_state;
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
// #[derive(Copy, Clone)]

pub use crate::src::apps::json_parse::json_tokener_srec;
// #[derive(Copy, Clone)]

pub use crate::src::apps::json_parse::json_tokener;
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    test_case_parse();
    return 0 as libc::c_int;
}
unsafe extern "C" fn test_case_parse() {
    let mut tok: *mut json_tokener = 0 as *mut json_tokener;
    let mut new_obj: *mut json_object = 0 as *mut json_object;
    tok = json_tokener_new();
    json_tokener_set_flags(tok, 0x1 as libc::c_int);
    new_obj = json_tokener_parse_ex(
        tok,
        b"True\0" as *const u8 as *const libc::c_char,
        4 as libc::c_int,
    );
    if new_obj.is_null() {} else {
        __assert_fail(
            b"new_obj == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_charcase.c\0" as *const u8
                as *const libc::c_char,
            34 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 27],
                &[libc::c_char; 27],
            >(b"void test_case_parse(void)\0"))
                .as_ptr(),
        );
    }
    new_obj = json_tokener_parse_ex(
        tok,
        b"False\0" as *const u8 as *const libc::c_char,
        5 as libc::c_int,
    );
    if new_obj.is_null() {} else {
        __assert_fail(
            b"new_obj == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_charcase.c\0" as *const u8
                as *const libc::c_char,
            37 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 27],
                &[libc::c_char; 27],
            >(b"void test_case_parse(void)\0"))
                .as_ptr(),
        );
    }
    new_obj = json_tokener_parse_ex(
        tok,
        b"Null\0" as *const u8 as *const libc::c_char,
        4 as libc::c_int,
    );
    if new_obj.is_null() {} else {
        __assert_fail(
            b"new_obj == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_charcase.c\0" as *const u8
                as *const libc::c_char,
            40 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 27],
                &[libc::c_char; 27],
            >(b"void test_case_parse(void)\0"))
                .as_ptr(),
        );
    }
    printf(b"OK\n\0" as *const u8 as *const libc::c_char);
    json_tokener_free(tok);
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
