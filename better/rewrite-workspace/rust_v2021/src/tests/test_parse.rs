use ::libc;
extern "C" {
    
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn puts(__s: *const libc::c_char) -> libc::c_int;
    fn atoi(__nptr: *const libc::c_char) -> libc::c_int;
    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::json_object::json_object;
pub use crate::debug::mc_set_debug;
pub use crate::json_object::json_object_get_type;
pub use crate::json_object::json_object_put;
pub use crate::json_object::json_object_set_serializer;
pub use crate::json_object::json_object_to_json_string;
pub use crate::json_tokener::json_tokener_error_desc;
pub use crate::json_tokener::json_tokener_free;
pub use crate::json_tokener::json_tokener_get_error;
pub use crate::json_tokener::json_tokener_get_parse_end;
pub use crate::json_tokener::json_tokener_new;
pub use crate::json_tokener::json_tokener_parse;
pub use crate::json_tokener::json_tokener_parse_ex;
pub use crate::json_tokener::json_tokener_parse_verbose;
pub use crate::json_tokener::json_tokener_reset;
pub use crate::json_tokener::json_tokener_set_flags;
pub use crate::json_util::json_type_to_name;
pub use crate::json_visit::json_c_visit;
pub use crate::apps::json_parse::size_t;
// #[derive(Copy, Clone)]

pub use crate::apps::json_parse::printbuf;
pub use crate::json_object::json_object_delete_fn;
pub use crate::json_object::json_object_to_json_string_fn;
pub use crate::json_object::json_type;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
pub use crate::apps::json_parse::json_tokener_error;
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
pub use crate::apps::json_parse::json_tokener_state;
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

pub use crate::apps::json_parse::json_tokener_srec;
// #[derive(Copy, Clone)]

pub use crate::apps::json_parse::json_tokener;
pub use crate::json_visit::json_c_visit_userfunc;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct incremental_step {
    pub string_to_parse: *const libc::c_char,
    pub length: libc::c_int,
    pub char_offset: libc::c_int,
    pub expected_error: json_tokener_error,
    pub reset_tokener: libc::c_int,
    pub tok_flags: libc::c_int,
}
unsafe fn main_0() -> libc::c_int {
    static mut separator: [libc::c_char; 35] = unsafe {
        *::std::mem::transmute::<
            &[u8; 35],
            &[libc::c_char; 35],
        >(b"==================================\0")
    };
    test_basic_parse();
    puts(separator.as_ptr());
    test_utf8_parse();
    puts(separator.as_ptr());
    test_verbose_parse();
    puts(separator.as_ptr());
    test_incremental_parse();
    puts(separator.as_ptr());
    return 0 as libc::c_int;
}
unsafe extern "C" fn single_incremental_parse(
    mut test_string: *const libc::c_char,
    mut clear_serializer_0: libc::c_int,
) {
    let mut ii: size_t = 0;
    let mut chunksize: libc::c_int = atoi(
        getenv(b"TEST_PARSE_CHUNKSIZE\0" as *const u8 as *const libc::c_char),
    );
    let mut tok: *mut json_tokener = 0 as *mut json_tokener;
    let mut jerr: json_tokener_error = json_tokener_success;
    let mut all_at_once_obj: *mut json_object = 0 as *mut json_object;
    let mut new_obj: *mut json_object = 0 as *mut json_object;
    let mut all_at_once_str: *const libc::c_char = 0 as *const libc::c_char;
    let mut new_str: *const libc::c_char = 0 as *const libc::c_char;
    new_obj = 0 as *mut json_object;
    if chunksize > 0 as libc::c_int {} else {
        __assert_fail(
            b"chunksize > 0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_parse.c\0" as *const u8
                as *const libc::c_char,
            49 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 49],
                &[libc::c_char; 49],
            >(b"void single_incremental_parse(const char *, int)\0"))
                .as_ptr(),
        );
    }
    all_at_once_obj = json_tokener_parse(test_string);
    if clear_serializer_0 != 0 {
        do_clear_serializer(all_at_once_obj);
    }
    all_at_once_str = json_object_to_json_string(all_at_once_obj);
    tok = json_tokener_new();
    let mut test_string_len: size_t = (strlen(test_string))
        .wrapping_add(1 as libc::c_int as libc::c_ulong);
    ii = 0 as libc::c_int as size_t;
    while ii < test_string_len {
        let mut len_to_parse: libc::c_int = chunksize;
        if ii.wrapping_add(chunksize as libc::c_ulong) > test_string_len {
            len_to_parse = test_string_len.wrapping_sub(ii) as libc::c_int;
        }
        if !(getenv(b"TEST_PARSE_DEBUG\0" as *const u8 as *const libc::c_char)).is_null()
        {
            printf(
                b" chunk: %.*s\n\0" as *const u8 as *const libc::c_char,
                len_to_parse,
                &*test_string.offset(ii as isize) as *const libc::c_char,
            );
        }
        new_obj = json_tokener_parse_ex(
            tok,
            &*test_string.offset(ii as isize),
            len_to_parse,
        );
        jerr = json_tokener_get_error(tok);
        if jerr as libc::c_uint != json_tokener_continue as libc::c_int as libc::c_uint
            || !new_obj.is_null()
        {
            break;
        }
        ii = (ii as libc::c_ulong).wrapping_add(chunksize as libc::c_ulong) as size_t
            as size_t;
    }
    if clear_serializer_0 != 0 && !new_obj.is_null() {
        do_clear_serializer(new_obj);
    }
    new_str = json_object_to_json_string(new_obj);
    if strcmp(all_at_once_str, new_str) != 0 as libc::c_int {
        printf(
            b"ERROR: failed to parse (%s) in %d byte chunks: %s != %s\n\0" as *const u8
                as *const libc::c_char,
            test_string,
            chunksize,
            all_at_once_str,
            new_str,
        );
    }
    json_tokener_free(tok);
    if !all_at_once_obj.is_null() {
        json_object_put(all_at_once_obj);
    }
    if !new_obj.is_null() {
        json_object_put(new_obj);
    }
}
unsafe extern "C" fn single_basic_parse(
    mut test_string: *const libc::c_char,
    mut clear_serializer_0: libc::c_int,
) {
    let mut new_obj: *mut json_object = 0 as *mut json_object;
    new_obj = json_tokener_parse(test_string);
    if clear_serializer_0 != 0 {
        do_clear_serializer(new_obj);
    }
    printf(
        b"new_obj.to_string(%s)=%s\n\0" as *const u8 as *const libc::c_char,
        test_string,
        json_object_to_json_string(new_obj),
    );
    json_object_put(new_obj);
    if !(getenv(b"TEST_PARSE_CHUNKSIZE\0" as *const u8 as *const libc::c_char)).is_null()
    {
        single_incremental_parse(test_string, clear_serializer_0);
    }
}
unsafe extern "C" fn test_basic_parse() {
    single_basic_parse(
        b"\"\x03\"\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"/* hello */\"foo\"\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"// hello\n\"foo\"\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"\"foo\"blue\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(b"'foo'\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    single_basic_parse(
        b"\"\\u0041\\u0042\\u0043\"\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"\"\\u4e16\\u754c\\u00df\"\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"\"\\u4E16\"\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"\"\\u4e1\"\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"\"\\u4e1@\"\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"\"\\ud840\\u4e16\"\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"\"\\ud840\"\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"\"\\udd27\"\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"[9,'\\uDAD\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(b"null\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    single_basic_parse(b"NaN\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    single_basic_parse(b"-NaN\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    single_basic_parse(b"Inf\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    single_basic_parse(b"inf\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    single_basic_parse(
        b"Infinity\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"infinity\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"-Infinity\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"-infinity\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"{ \"min\": Infinity, \"max\": -Infinity}\0" as *const u8
            as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"Infinity!\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"Infinitynull\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"InfinityXXXX\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"-Infinitynull\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"-InfinityXXXX\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"Infinoodle\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"InfinAAA\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"-Infinoodle\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"-InfinAAA\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(b"True\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    single_basic_parse(b"False\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    single_basic_parse(b"tRue\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    single_basic_parse(b"fAlse\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    single_basic_parse(b"nAn\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    single_basic_parse(
        b"iNfinity\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(b"12\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    single_basic_parse(b"12.3\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    single_basic_parse(
        b"12.3.4\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"2015-01-15\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"12.3xxx\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"12.3{\"a\":123}\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"12.3\n\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(b"12.3 \0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    single_basic_parse(
        b"{\"FoO\"  :   -12.3E512}\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"{\"FoO\"  :   -12.3e512}\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"{\"FoO\"  :   -12.3E51.2}\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"{\"FoO\"  :   -12.3E512E12}\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"[\"\\n\"]\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"[\"\\nabc\\n\"]\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"[null]\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(b"[]\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    single_basic_parse(
        b"[false]\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"[\"abc\",null,\"def\",12]\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(b"{}\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    single_basic_parse(
        b"{ \"foo\": \"bar\" }\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"{ 'foo': 'bar' }\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"{ \"foo\": \"bar\", \"baz\": null, \"bool0\": true }\0" as *const u8
            as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"{ \"foo\": [null, \"foo\"] }\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"{ \"abc\": 12, \"foo\": \"bar\", \"bool0\": false, \"bool1\": true, \"arr\": [ 1, 2, 3, null, 5 ] }\0"
            as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(
        b"{ \"abc\": \"blue\nred\\ngreen\" }\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    single_basic_parse(b"null\0" as *const u8 as *const libc::c_char, 1 as libc::c_int);
    single_basic_parse(b"false\0" as *const u8 as *const libc::c_char, 1 as libc::c_int);
    single_basic_parse(b"[0e]\0" as *const u8 as *const libc::c_char, 1 as libc::c_int);
    single_basic_parse(b"[0e+]\0" as *const u8 as *const libc::c_char, 1 as libc::c_int);
    single_basic_parse(
        b"[0e+-1]\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    single_basic_parse(
        b"\"hello world!\"\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    single_basic_parse(
        b"[9223372036854775806]\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    single_basic_parse(
        b"[9223372036854775807]\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    single_basic_parse(
        b"[9223372036854775808]\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    single_basic_parse(
        b"[-9223372036854775807]\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    single_basic_parse(
        b"[-9223372036854775808]\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    single_basic_parse(
        b"[-9223372036854775809]\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    single_basic_parse(
        b"[18446744073709551614]\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    single_basic_parse(
        b"[18446744073709551615]\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    single_basic_parse(
        b"[18446744073709551616]\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
}
unsafe extern "C" fn test_utf8_parse() {
    let mut utf8_bom: *const libc::c_char = b"\xEF\xBB\xBF\0" as *const u8
        as *const libc::c_char;
    let mut utf8_bom_and_chars: *const libc::c_char = b"\xEF\xBB\xBF{}\0" as *const u8
        as *const libc::c_char;
    single_basic_parse(utf8_bom, 0 as libc::c_int);
    single_basic_parse(utf8_bom_and_chars, 0 as libc::c_int);
}
unsafe extern "C" fn do_clear_serializer(mut jso: *mut json_object) {
    json_c_visit(
        jso,
        0 as libc::c_int,
        Some(clear_serializer as json_c_visit_userfunc),
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn clear_serializer(
    mut jso: *mut json_object,
    mut flags: libc::c_int,
    mut parent_jso: *mut json_object,
    mut jso_key: *const libc::c_char,
    mut jso_index: *mut size_t,
    mut userarg: *mut libc::c_void,
) -> libc::c_int {
    if !jso.is_null() {
        json_object_set_serializer(jso, None, 0 as *mut libc::c_void, None);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn test_verbose_parse() {
    let mut new_obj: *mut json_object = 0 as *mut json_object;
    let mut error: json_tokener_error = json_tokener_success;
    new_obj = json_tokener_parse_verbose(
        b"{ foo }\0" as *const u8 as *const libc::c_char,
        &mut error,
    );
    if error as libc::c_uint
        == json_tokener_error_parse_object_key_name as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"error == json_tokener_error_parse_object_key_name\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_parse.c\0" as *const u8
                as *const libc::c_char,
            235 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 30],
                &[libc::c_char; 30],
            >(b"void test_verbose_parse(void)\0"))
                .as_ptr(),
        );
    }
    if new_obj.is_null() {} else {
        __assert_fail(
            b"new_obj == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_parse.c\0" as *const u8
                as *const libc::c_char,
            236 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 30],
                &[libc::c_char; 30],
            >(b"void test_verbose_parse(void)\0"))
                .as_ptr(),
        );
    }
    new_obj = json_tokener_parse(b"{ foo }\0" as *const u8 as *const libc::c_char);
    if new_obj.is_null() {} else {
        __assert_fail(
            b"new_obj == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_parse.c\0" as *const u8
                as *const libc::c_char,
            239 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 30],
                &[libc::c_char; 30],
            >(b"void test_verbose_parse(void)\0"))
                .as_ptr(),
        );
    }
    new_obj = json_tokener_parse(b"foo\0" as *const u8 as *const libc::c_char);
    if new_obj.is_null() {} else {
        __assert_fail(
            b"new_obj == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_parse.c\0" as *const u8
                as *const libc::c_char,
            242 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 30],
                &[libc::c_char; 30],
            >(b"void test_verbose_parse(void)\0"))
                .as_ptr(),
        );
    }
    new_obj = json_tokener_parse_verbose(
        b"foo\0" as *const u8 as *const libc::c_char,
        &mut error,
    );
    if new_obj.is_null() {} else {
        __assert_fail(
            b"new_obj == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_parse.c\0" as *const u8
                as *const libc::c_char,
            244 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 30],
                &[libc::c_char; 30],
            >(b"void test_verbose_parse(void)\0"))
                .as_ptr(),
        );
    }
    if error as libc::c_uint
        == json_tokener_error_parse_boolean as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"error == json_tokener_error_parse_boolean\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_parse.c\0" as *const u8
                as *const libc::c_char,
            247 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 30],
                &[libc::c_char; 30],
            >(b"void test_verbose_parse(void)\0"))
                .as_ptr(),
        );
    }
    puts(b"json_tokener_parse_verbose() OK\0" as *const u8 as *const libc::c_char);
}
#[no_mangle]
pub static mut incremental_steps: [incremental_step; 199] = [incremental_step {
    string_to_parse: 0 as *const libc::c_char,
    length: 0,
    char_offset: 0,
    expected_error: json_tokener_success,
    reset_tokener: 0,
    tok_flags: 0,
}; 199];
unsafe extern "C" fn test_incremental_parse() {
    let mut new_obj: *mut json_object = 0 as *mut json_object;
    let mut jerr: json_tokener_error = json_tokener_success;
    let mut tok: *mut json_tokener = 0 as *mut json_tokener;
    let mut string_to_parse: *const libc::c_char = 0 as *const libc::c_char;
    let mut ii: libc::c_int = 0;
    let mut num_ok: libc::c_int = 0;
    let mut num_error: libc::c_int = 0;
    num_ok = 0 as libc::c_int;
    num_error = 0 as libc::c_int;
    printf(b"Starting incremental tests.\n\0" as *const u8 as *const libc::c_char);
    printf(
        b"Note: quotes and backslashes seen in the output here are literal values passed\n\0"
            as *const u8 as *const libc::c_char,
    );
    printf(
        b"     to the parse functions.  e.g. this is 4 characters: \"\\f\"\n\0"
            as *const u8 as *const libc::c_char,
    );
    string_to_parse = b"{ \"foo\0" as *const u8 as *const libc::c_char;
    printf(
        b"json_tokener_parse(%s) ... \0" as *const u8 as *const libc::c_char,
        string_to_parse,
    );
    new_obj = json_tokener_parse(string_to_parse);
    if new_obj.is_null() {
        puts(b"got error as expected\0" as *const u8 as *const libc::c_char);
    }
    tok = json_tokener_new();
    ii = 0 as libc::c_int;
    while !(incremental_steps[ii as usize].string_to_parse).is_null() {
        let mut this_step_ok: libc::c_int = 0 as libc::c_int;
        let mut step: *mut incremental_step = &mut *incremental_steps
            .as_mut_ptr()
            .offset(ii as isize) as *mut incremental_step;
        let mut length: libc::c_int = (*step).length;
        let mut expected_char_offset: size_t = 0;
        json_tokener_set_flags(tok, (*step).tok_flags);
        if length == -(1 as libc::c_int) {
            length = strlen((*step).string_to_parse) as libc::c_int;
        }
        if (*step).char_offset == -(1 as libc::c_int) {
            expected_char_offset = length as size_t;
        } else {
            expected_char_offset = (*step).char_offset as size_t;
        }
        printf(
            b"json_tokener_parse_ex(tok, %-12s, %3d) ... \0" as *const u8
                as *const libc::c_char,
            (*step).string_to_parse,
            length,
        );
        new_obj = json_tokener_parse_ex(tok, (*step).string_to_parse, length);
        jerr = json_tokener_get_error(tok);
        if (*step).expected_error as libc::c_uint
            != json_tokener_success as libc::c_int as libc::c_uint
        {
            if !new_obj.is_null() {
                printf(
                    b"ERROR: invalid object returned: %s\n\0" as *const u8
                        as *const libc::c_char,
                    json_object_to_json_string(new_obj),
                );
            } else if jerr as libc::c_uint != (*step).expected_error as libc::c_uint {
                printf(
                    b"ERROR: got wrong error: %s\n\0" as *const u8
                        as *const libc::c_char,
                    json_tokener_error_desc(jerr),
                );
            } else if json_tokener_get_parse_end(tok) != expected_char_offset {
                printf(
                    b"ERROR: wrong char_offset %zu != expected %zu\n\0" as *const u8
                        as *const libc::c_char,
                    json_tokener_get_parse_end(tok),
                    expected_char_offset,
                );
            } else {
                printf(
                    b"OK: got correct error: %s\n\0" as *const u8 as *const libc::c_char,
                    json_tokener_error_desc(jerr),
                );
                this_step_ok = 1 as libc::c_int;
            }
        } else if new_obj.is_null()
                && !((*step).length >= 4 as libc::c_int
                    && strncmp(
                        (*step).string_to_parse,
                        b"null\0" as *const u8 as *const libc::c_char,
                        4 as libc::c_int as libc::c_ulong,
                    ) == 0 as libc::c_int)
            {
            printf(
                b"ERROR: expected valid object, instead: %s\n\0" as *const u8
                    as *const libc::c_char,
                json_tokener_error_desc(jerr),
            );
        } else if json_tokener_get_parse_end(tok) != expected_char_offset {
            printf(
                b"ERROR: wrong char_offset %zu != expected %zu\n\0" as *const u8
                    as *const libc::c_char,
                json_tokener_get_parse_end(tok),
                expected_char_offset,
            );
        } else {
            printf(
                b"OK: got object of type [%s]: %s\n\0" as *const u8
                    as *const libc::c_char,
                json_type_to_name(json_object_get_type(new_obj)),
                json_object_to_json_string(new_obj),
            );
            this_step_ok = 1 as libc::c_int;
        }
        if !new_obj.is_null() {
            json_object_put(new_obj);
        }
        if (*step).reset_tokener & 1 as libc::c_int != 0 {
            json_tokener_reset(tok);
        }
        if this_step_ok != 0 {
            num_ok += 1;
        } else {
            num_error += 1;
        }
        ii += 1;
    }
    json_tokener_free(tok);
    printf(
        b"End Incremental Tests OK=%d ERROR=%d\n\0" as *const u8 as *const libc::c_char,
        num_ok,
        num_error,
    );
}
pub fn main() {
    unsafe { ::std::process::exit(main_0() as i32) }
}
unsafe extern "C" fn run_static_initializers() {
    incremental_steps = [
        {
            let mut init = incremental_step {
                string_to_parse: b"{ \"foo\": 123 }\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{ \"foo\": 456 }\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{ \"foo\": 789 }\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"/* hello */{ \"foo\"\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"/* hello */:/* hello */\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"bar\"/* hello */\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"}/* hello */\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"/ hello \0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_error_parse_comment,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"/* hello\"foo\"\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"/* hello*\"foo\"\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"// hello\"foo\"\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{ \"foo\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\": {\"bar\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\":13}}\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\\\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"u\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"d\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"8\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"3\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"4\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\\\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"u\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"d\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"d\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"1\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"e\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\\u\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"d8\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"34\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\\u\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"dd\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"1e\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\\ud834\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\\udd1e\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\\ud834\\\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"udd1e\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\\ud834\\u\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"dd1e\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"fff \\ud834\\ud\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"d1e bar\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"fff \\ud834\\udd\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"1e bar\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"fff \\ud83d\\ude\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"00 bar\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{ \"foo\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b": \"bar\"}\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 0 as libc::c_int,
                expected_error: json_tokener_error_parse_unexpected,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{ \"foo\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\": {\"bar\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\":13}}XXXX\0" as *const u8 as *const libc::c_char,
                length: 10 as libc::c_int,
                char_offset: 6 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"XXXX\0" as *const u8 as *const libc::c_char,
                length: 4 as libc::c_int,
                char_offset: 0 as libc::c_int,
                expected_error: json_tokener_error_parse_unexpected,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{\"x\": 123 }\"X\"\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 11 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"Y\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{\"foo\":9}{\"bar\":8}\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 9 as libc::c_int,
                expected_error: json_tokener_error_parse_unexpected,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{\"foo\":9}{\"bar\":8}\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 9 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0x1 as libc::c_int | 0x2 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{\"b\":8}ignored garbage\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 7 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int | 0x2 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"1\0" as *const u8 as *const libc::c_char,
                length: 1 as libc::c_int,
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"2\0" as *const u8 as *const libc::c_char,
                length: 2 as libc::c_int,
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"12{\0" as *const u8 as *const libc::c_char,
                length: 3 as libc::c_int,
                char_offset: 2 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[02]\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_error_parse_number,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"0e+0\0" as *const u8 as *const libc::c_char,
                length: 5 as libc::c_int,
                char_offset: 4 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[0e+0]\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"0e\0" as *const u8 as *const libc::c_char,
                length: 2 as libc::c_int,
                char_offset: 2 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"0e\0" as *const u8 as *const libc::c_char,
                length: 3 as libc::c_int,
                char_offset: 2 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"0e\0" as *const u8 as *const libc::c_char,
                length: 3 as libc::c_int,
                char_offset: 2 as libc::c_int,
                expected_error: json_tokener_error_parse_eof,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[0e]\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[0e]\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_error_parse_number,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"0e+\0" as *const u8 as *const libc::c_char,
                length: 3 as libc::c_int,
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"0e+\0" as *const u8 as *const libc::c_char,
                length: 4 as libc::c_int,
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"0e+\0" as *const u8 as *const libc::c_char,
                length: 4 as libc::c_int,
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_error_parse_eof,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[0e+]\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[0e+]\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 4 as libc::c_int,
                expected_error: json_tokener_error_parse_number,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"0e-\0" as *const u8 as *const libc::c_char,
                length: 3 as libc::c_int,
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"0e-\0" as *const u8 as *const libc::c_char,
                length: 4 as libc::c_int,
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"0e-\0" as *const u8 as *const libc::c_char,
                length: 4 as libc::c_int,
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_error_parse_eof,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[0e-]\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[0e-]\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 4 as libc::c_int,
                expected_error: json_tokener_error_parse_number,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"0e+-\0" as *const u8 as *const libc::c_char,
                length: 5 as libc::c_int,
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"0e+-\0" as *const u8 as *const libc::c_char,
                length: 5 as libc::c_int,
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_error_parse_number,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[0e+-]\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 4 as libc::c_int,
                expected_error: json_tokener_error_parse_number,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"false\0" as *const u8 as *const libc::c_char,
                length: 5 as libc::c_int,
                char_offset: 5 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"false\0" as *const u8 as *const libc::c_char,
                length: 6 as libc::c_int,
                char_offset: 5 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"true\0" as *const u8 as *const libc::c_char,
                length: 4 as libc::c_int,
                char_offset: 4 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"true\0" as *const u8 as *const libc::c_char,
                length: 5 as libc::c_int,
                char_offset: 4 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"null\0" as *const u8 as *const libc::c_char,
                length: 4 as libc::c_int,
                char_offset: 4 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"null\0" as *const u8 as *const libc::c_char,
                length: 5 as libc::c_int,
                char_offset: 4 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"Infinity\0" as *const u8 as *const libc::c_char,
                length: 9 as libc::c_int,
                char_offset: 8 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"infinity\0" as *const u8 as *const libc::c_char,
                length: 9 as libc::c_int,
                char_offset: 8 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"-infinity\0" as *const u8 as *const libc::c_char,
                length: 10 as libc::c_int,
                char_offset: 9 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"infinity\0" as *const u8 as *const libc::c_char,
                length: 9 as libc::c_int,
                char_offset: 0 as libc::c_int,
                expected_error: json_tokener_error_parse_unexpected,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"-infinity\0" as *const u8 as *const libc::c_char,
                length: 10 as libc::c_int,
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_error_parse_unexpected,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"inf\0" as *const u8 as *const libc::c_char,
                length: 3 as libc::c_int,
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"inity\0" as *const u8 as *const libc::c_char,
                length: 6 as libc::c_int,
                char_offset: 5 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"-inf\0" as *const u8 as *const libc::c_char,
                length: 4 as libc::c_int,
                char_offset: 4 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"inity\0" as *const u8 as *const libc::c_char,
                length: 6 as libc::c_int,
                char_offset: 5 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"i\0" as *const u8 as *const libc::c_char,
                length: 1 as libc::c_int,
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"n\0" as *const u8 as *const libc::c_char,
                length: 1 as libc::c_int,
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"f\0" as *const u8 as *const libc::c_char,
                length: 1 as libc::c_int,
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"i\0" as *const u8 as *const libc::c_char,
                length: 1 as libc::c_int,
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"n\0" as *const u8 as *const libc::c_char,
                length: 1 as libc::c_int,
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"i\0" as *const u8 as *const libc::c_char,
                length: 1 as libc::c_int,
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"t\0" as *const u8 as *const libc::c_char,
                length: 1 as libc::c_int,
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"y\0" as *const u8 as *const libc::c_char,
                length: 1 as libc::c_int,
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\0" as *const u8 as *const libc::c_char,
                length: 1 as libc::c_int,
                char_offset: 0 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"-\0" as *const u8 as *const libc::c_char,
                length: 1 as libc::c_int,
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"inf\0" as *const u8 as *const libc::c_char,
                length: 3 as libc::c_int,
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"ini\0" as *const u8 as *const libc::c_char,
                length: 3 as libc::c_int,
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"ty\0" as *const u8 as *const libc::c_char,
                length: 3 as libc::c_int,
                char_offset: 2 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"-\0" as *const u8 as *const libc::c_char,
                length: 1 as libc::c_int,
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"i\0" as *const u8 as *const libc::c_char,
                length: 1 as libc::c_int,
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"nfini\0" as *const u8 as *const libc::c_char,
                length: 5 as libc::c_int,
                char_offset: 5 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"ty\0" as *const u8 as *const libc::c_char,
                length: 3 as libc::c_int,
                char_offset: 2 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"-i\0" as *const u8 as *const libc::c_char,
                length: 2 as libc::c_int,
                char_offset: 2 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"nfinity\0" as *const u8 as *const libc::c_char,
                length: 8 as libc::c_int,
                char_offset: 7 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"InfinityX\0" as *const u8 as *const libc::c_char,
                length: 10 as libc::c_int,
                char_offset: 8 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"X\0" as *const u8 as *const libc::c_char,
                length: 1 as libc::c_int,
                char_offset: 0 as libc::c_int,
                expected_error: json_tokener_error_parse_unexpected,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"Infinity1234\0" as *const u8 as *const libc::c_char,
                length: 13 as libc::c_int,
                char_offset: 8 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"1234\0" as *const u8 as *const libc::c_char,
                length: 5 as libc::c_int,
                char_offset: 4 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"Infinity9999\0" as *const u8 as *const libc::c_char,
                length: 8 as libc::c_int,
                char_offset: 8 as libc::c_int,
                expected_error: json_tokener_continue,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"1234\0" as *const u8 as *const libc::c_char,
                length: 5 as libc::c_int,
                char_offset: 0 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"1234\0" as *const u8 as *const libc::c_char,
                length: 5 as libc::c_int,
                char_offset: 4 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[9223372036854775807]\0" as *const u8
                    as *const libc::c_char,
                length: 22 as libc::c_int,
                char_offset: 21 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[9223372036854775808]\0" as *const u8
                    as *const libc::c_char,
                length: 22 as libc::c_int,
                char_offset: 21 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[-9223372036854775808]\0" as *const u8
                    as *const libc::c_char,
                length: 23 as libc::c_int,
                char_offset: 22 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[-9223372036854775809]\0" as *const u8
                    as *const libc::c_char,
                length: 23 as libc::c_int,
                char_offset: 22 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[-9223372036854775809]\0" as *const u8
                    as *const libc::c_char,
                length: 23 as libc::c_int,
                char_offset: 21 as libc::c_int,
                expected_error: json_tokener_error_parse_number,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[18446744073709551615]\0" as *const u8
                    as *const libc::c_char,
                length: 23 as libc::c_int,
                char_offset: 22 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[18446744073709551616]\0" as *const u8
                    as *const libc::c_char,
                length: 23 as libc::c_int,
                char_offset: 22 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[18446744073709551616]\0" as *const u8
                    as *const libc::c_char,
                length: 23 as libc::c_int,
                char_offset: 21 as libc::c_int,
                expected_error: json_tokener_error_parse_number,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"18446744073709551616\0" as *const u8
                    as *const libc::c_char,
                length: 21 as libc::c_int,
                char_offset: 20 as libc::c_int,
                expected_error: json_tokener_error_parse_eof,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[9223372036854775808.0]\0" as *const u8
                    as *const libc::c_char,
                length: 24 as libc::c_int,
                char_offset: 23 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[-9223372036854775809.0]\0" as *const u8
                    as *const libc::c_char,
                length: 25 as libc::c_int,
                char_offset: 24 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[18446744073709551615.0]\0" as *const u8
                    as *const libc::c_char,
                length: 25 as libc::c_int,
                char_offset: 24 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[18446744073709551616.0]\0" as *const u8
                    as *const libc::c_char,
                length: 25 as libc::c_int,
                char_offset: 24 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"noodle\0" as *const u8 as *const libc::c_char,
                length: 7 as libc::c_int,
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_error_parse_null,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"naodle\0" as *const u8 as *const libc::c_char,
                length: 7 as libc::c_int,
                char_offset: 2 as libc::c_int,
                expected_error: json_tokener_error_parse_null,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"track\0" as *const u8 as *const libc::c_char,
                length: 6 as libc::c_int,
                char_offset: 2 as libc::c_int,
                expected_error: json_tokener_error_parse_boolean,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"fail\0" as *const u8 as *const libc::c_char,
                length: 5 as libc::c_int,
                char_offset: 2 as libc::c_int,
                expected_error: json_tokener_error_parse_boolean,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"null123\0" as *const u8 as *const libc::c_char,
                length: 8 as libc::c_int,
                char_offset: 4 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: &*(b"null123\0" as *const u8 as *const libc::c_char)
                    .offset(4 as libc::c_int as isize) as *const libc::c_char,
                length: 4 as libc::c_int,
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"nullx\0" as *const u8 as *const libc::c_char,
                length: 6 as libc::c_int,
                char_offset: 4 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: &*(b"nullx\0" as *const u8 as *const libc::c_char)
                    .offset(4 as libc::c_int as isize) as *const libc::c_char,
                length: 2 as libc::c_int,
                char_offset: 0 as libc::c_int,
                expected_error: json_tokener_error_parse_unexpected,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{\"a\":1}{\"b\":2}\0" as *const u8
                    as *const libc::c_char,
                length: 15 as libc::c_int,
                char_offset: 7 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: &*(b"{\"a\":1}{\"b\":2}\0" as *const u8
                    as *const libc::c_char)
                    .offset(7 as libc::c_int as isize) as *const libc::c_char,
                length: 8 as libc::c_int,
                char_offset: 7 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: &*(b"2015-01-15\0" as *const u8 as *const libc::c_char)
                    .offset(0 as libc::c_int as isize) as *const libc::c_char,
                length: 11 as libc::c_int,
                char_offset: 4 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: &*(b"2015-01-15\0" as *const u8 as *const libc::c_char)
                    .offset(4 as libc::c_int as isize) as *const libc::c_char,
                length: 7 as libc::c_int,
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: &*(b"2015-01-15\0" as *const u8 as *const libc::c_char)
                    .offset(7 as libc::c_int as isize) as *const libc::c_char,
                length: 4 as libc::c_int,
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: &*(b"2015 01 15\0" as *const u8 as *const libc::c_char)
                    .offset(0 as libc::c_int as isize) as *const libc::c_char,
                length: 11 as libc::c_int,
                char_offset: 5 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: &*(b"2015 01 15\0" as *const u8 as *const libc::c_char)
                    .offset(4 as libc::c_int as isize) as *const libc::c_char,
                length: 7 as libc::c_int,
                char_offset: 4 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: &*(b"2015 01 15\0" as *const u8 as *const libc::c_char)
                    .offset(7 as libc::c_int as isize) as *const libc::c_char,
                length: 4 as libc::c_int,
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"blue\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\\\"\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\\\\\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\\b\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\\f\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\\n\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\\r\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\\t\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\\/\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"/\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\\a\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 2 as libc::c_int,
                expected_error: json_tokener_error_parse_string,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"'foo'\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 0 as libc::c_int,
                expected_error: json_tokener_error_parse_unexpected,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[1,2,3]\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[1,2,3}\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 6 as libc::c_int,
                expected_error: json_tokener_error_parse_array,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{\"a\"}\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 4 as libc::c_int,
                expected_error: json_tokener_error_parse_object_key_sep,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{\"a\":1]\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 6 as libc::c_int,
                expected_error: json_tokener_error_parse_object_value_sep,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{\"a\"::1}\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 5 as libc::c_int,
                expected_error: json_tokener_error_parse_unexpected,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{\"a\":}\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 5 as libc::c_int,
                expected_error: json_tokener_error_parse_unexpected,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{\"a\":1,\"a\":2}\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"a\":1}\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{\"a\":1\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_continue,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[,]\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_error_parse_unexpected,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[,1]\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 1 as libc::c_int,
                expected_error: json_tokener_error_parse_unexpected,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[1,2,3,]\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[1,2,,3,]\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 5 as libc::c_int,
                expected_error: json_tokener_error_parse_unexpected,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[1,2,3,]\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 7 as libc::c_int,
                expected_error: json_tokener_error_parse_unexpected,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{\"a\":1,}\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 7 as libc::c_int,
                expected_error: json_tokener_error_parse_unexpected,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"123asc$%&\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"123asc$%&\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\xE4\xB8\x96\xE7\x95\x8C\"\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\xE4\xB8\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_error_parse_utf8_string,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\x96\xE7\x95\x8C\"\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 0 as libc::c_int,
                expected_error: json_tokener_error_parse_utf8_string,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\xE4\xB8\x96\xE7\x95\x8C\"\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\xCF\x80\xCF\x86\"\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\xF0\xA5\x91\x95\"\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\xE6\x9DN\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_error_parse_utf8_string,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\xE6\x9DN\"\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 5 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\xC0\xEE\xC5\xF4\"\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 2 as libc::c_int,
                expected_error: json_tokener_error_parse_utf8_string,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\xC0\xEE\xC5\xF4\"\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 6 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"  \"\xE4\xB8\x96\"\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"  \x81\"\xE4\xB8\x96\"\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 2 as libc::c_int,
                expected_error: json_tokener_error_parse_utf8_string,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"[ \x811]\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 2 as libc::c_int,
                expected_error: json_tokener_error_parse_utf8_string,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"Infinity\0" as *const u8 as *const libc::c_char,
                length: 9 as libc::c_int,
                char_offset: 8 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"Inf\x81nity\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_error_parse_utf8_string,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\\ud855\\udc55\"\0" as *const u8
                    as *const libc::c_char,
                length: 15 as libc::c_int,
                char_offset: 14 as libc::c_int,
                expected_error: json_tokener_success,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\\ud855\xC0udc55\"\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 8 as libc::c_int,
                expected_error: json_tokener_error_parse_utf8_string,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"\"\\ud0031\xC0\"\0" as *const u8
                    as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 9 as libc::c_int,
                expected_error: json_tokener_error_parse_utf8_string,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"11\x8111\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 2 as libc::c_int,
                expected_error: json_tokener_error_parse_utf8_string,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: b"{\"1\x81\":1}\0" as *const u8 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: 3 as libc::c_int,
                expected_error: json_tokener_error_parse_utf8_string,
                reset_tokener: 1 as libc::c_int,
                tok_flags: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = incremental_step {
                string_to_parse: 0 as *const libc::c_char,
                length: -(1 as libc::c_int),
                char_offset: -(1 as libc::c_int),
                expected_error: json_tokener_success,
                reset_tokener: 0 as libc::c_int,
                tok_flags: 0 as libc::c_int,
            };
            init
        },
    ];
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
