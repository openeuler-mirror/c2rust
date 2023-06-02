
extern "C" {
    fn printf(_: *const i8, _: ...) -> i32;
    fn puts(__s: *const i8) -> i32;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
}
pub use crate::src::{
    json_object::{
        json_object, json_object_get_string, json_object_get_string_len,
        json_object_new_string_len, json_object_put, json_object_to_json_string,
    },
    json_tokener::json_tokener_parse,
};
fn main_0() -> i32 {
    let mut input: *const i8 = b" \0 \0" as *const u8 as *const i8;
    let mut expected: *const i8 = b"\" \\u0000 \"\0" as *const u8 as *const i8;
    let mut string: *mut crate::src::json_object::json_object =
        json_object_new_string_len(input, 3 as i32);
    let mut json: *const i8 = json_object_to_json_string(string);
    let mut strings_match: i32 = ((unsafe { strcmp(expected, json) }) == 0) as i32;
    let mut retval: i32 = 0 as i32;
    if strings_match != 0 {
        (unsafe { printf(
            b"JSON write result is correct: %s\n\0" as *const u8 as *const i8,
            json,
        ) });
        (unsafe { puts(b"PASS\0" as *const u8 as *const i8) });
    } else {
        (unsafe { puts(b"JSON write result doesn't match expected string\0" as *const u8 as *const i8) });
        (unsafe { printf(b"expected string: \0" as *const u8 as *const i8) });
        (unsafe { puts(expected) });
        (unsafe { printf(b"parsed string:   \0" as *const u8 as *const i8) });
        (unsafe { puts(json) });
        (unsafe { puts(b"FAIL\0" as *const u8 as *const i8) });
        retval = 1 as i32;
    }
    json_object_put(string);
    let mut parsed_str: *mut crate::src::json_object::json_object = json_tokener_parse(expected);
    if !parsed_str.is_null() {
        let mut parsed_len: i32 = json_object_get_string_len(parsed_str);
        let mut parsed_cstr: *const i8 = json_object_get_string(parsed_str);
        let mut ii: i32 = 0;
        (unsafe { printf(
            b"Re-parsed object string len=%d, chars=[\0" as *const u8 as *const i8,
            parsed_len,
        ) });
        ii = 0 as i32;
        while ii < parsed_len {
            (unsafe { printf(
                b"%s%d\0" as *const u8 as *const i8,
                if ii != 0 {
                    b", \0" as *const u8 as *const i8
                } else {
                    b"\0" as *const u8 as *const i8
                },
                *parsed_cstr.offset(ii as isize) as i32,
            ) });
            ii += 1;
        }
        (unsafe { puts(b"]\0" as *const u8 as *const i8) });
        json_object_put(parsed_str);
    } else {
        (unsafe { puts(b"ERROR: failed to parse\0" as *const u8 as *const i8) });
    }
    return retval;
}
pub fn main() {
     ::std::process::exit(main_0() as i32)
}

