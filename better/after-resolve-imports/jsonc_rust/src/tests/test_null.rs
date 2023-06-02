use ::libc;
extern "C" {
    
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn puts(__s: *const libc::c_char) -> libc::c_int;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    
    
    
    
    
    
}
pub use crate::src::json_object::json_object_get_string;
pub use crate::src::json_object::json_object_get_string_len;
pub use crate::src::json_object::json_object_new_string_len;
pub use crate::src::json_object::json_object_put;
pub use crate::src::json_object::json_object_to_json_string;
pub use crate::src::json_tokener::json_tokener_parse;
pub use crate::src::json_object::json_object;
unsafe fn main_0() -> libc::c_int {
    let mut input: *const libc::c_char = b" \0 \0" as *const u8 as *const libc::c_char;
    let mut expected: *const libc::c_char = b"\" \\u0000 \"\0" as *const u8
        as *const libc::c_char;
    let mut string: *mut json_object = json_object_new_string_len(
        input,
        3 as libc::c_int,
    );
    let mut json: *const libc::c_char = json_object_to_json_string(string);
    let mut strings_match: libc::c_int = (strcmp(expected, json) == 0) as libc::c_int;
    let mut retval: libc::c_int = 0 as libc::c_int;
    if strings_match != 0 {
        printf(
            b"JSON write result is correct: %s\n\0" as *const u8 as *const libc::c_char,
            json,
        );
        puts(b"PASS\0" as *const u8 as *const libc::c_char);
    } else {
        puts(
            b"JSON write result doesn't match expected string\0" as *const u8
                as *const libc::c_char,
        );
        printf(b"expected string: \0" as *const u8 as *const libc::c_char);
        puts(expected);
        printf(b"parsed string:   \0" as *const u8 as *const libc::c_char);
        puts(json);
        puts(b"FAIL\0" as *const u8 as *const libc::c_char);
        retval = 1 as libc::c_int;
    }
    json_object_put(string);
    let mut parsed_str: *mut json_object = json_tokener_parse(expected);
    if !parsed_str.is_null() {
        let mut parsed_len: libc::c_int = json_object_get_string_len(parsed_str);
        let mut parsed_cstr: *const libc::c_char = json_object_get_string(parsed_str);
        let mut ii: libc::c_int = 0;
        printf(
            b"Re-parsed object string len=%d, chars=[\0" as *const u8
                as *const libc::c_char,
            parsed_len,
        );
        ii = 0 as libc::c_int;
        while ii < parsed_len {
            printf(
                b"%s%d\0" as *const u8 as *const libc::c_char,
                if ii != 0 {
                    b", \0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                *parsed_cstr.offset(ii as isize) as libc::c_int,
            );
            ii += 1;
        }
        puts(b"]\0" as *const u8 as *const libc::c_char);
        json_object_put(parsed_str);
    } else {
        puts(b"ERROR: failed to parse\0" as *const u8 as *const libc::c_char);
    }
    return retval;
}
pub fn main() {
    unsafe { ::std::process::exit(main_0() as i32) }
}
