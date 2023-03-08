use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::json_object::json_object;
pub use crate::json_object::json_object_get_boolean;
pub use crate::json_object::json_object_get_double;
pub use crate::json_object::json_object_get_int;
pub use crate::json_object::json_object_get_int64;
pub use crate::json_object::json_object_get_string;
pub use crate::json_object::json_object_get_uint64;
pub use crate::json_object::json_object_new_boolean;
pub use crate::json_object::json_object_new_double;
pub use crate::json_object::json_object_new_int;
pub use crate::json_object::json_object_new_string;
pub use crate::json_object::json_object_new_uint64;
pub use crate::json_object::json_object_put;
pub use crate::json_object::json_object_set_boolean;
pub use crate::json_object::json_object_set_double;
pub use crate::json_object::json_object_set_int;
pub use crate::json_object::json_object_set_int64;
pub use crate::json_object::json_object_set_string;
pub use crate::json_object::json_object_set_uint64;
pub use crate::json_object::json_object_to_json_string;
pub use crate::json_tokener::json_tokener_parse;
pub use crate::apps::json_parse::size_t;
pub use crate::json_object::__int32_t;
pub use crate::json_object::__int64_t;
pub use crate::json_object::__uint64_t;
pub use crate::apps::json_parse::__off_t;
pub use crate::apps::json_parse::__off64_t;
// #[derive(Copy, Clone)]

pub use crate::apps::json_parse::_IO_FILE;
pub use crate::apps::json_parse::_IO_lock_t;
pub use crate::apps::json_parse::FILE;
pub use crate::json_object::int32_t;
pub use crate::json_object::int64_t;
pub use crate::json_object::uint64_t;
pub use crate::json_object::json_bool;
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut tmp: *mut json_object = json_object_new_int(123 as libc::c_int);
    if json_object_get_int(tmp) == 123 as libc::c_int {} else {
        __assert_fail(
            b"json_object_get_int(tmp) == 123\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            13 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_int(tmp, 321 as libc::c_int);
    if json_object_get_int(tmp) == 321 as libc::c_int {} else {
        __assert_fail(
            b"json_object_get_int(tmp) == 321\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            15 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    printf(b"INT PASSED\n\0" as *const u8 as *const libc::c_char);
    json_object_set_int64(tmp, 321321321 as libc::c_int as int64_t);
    if json_object_get_int64(tmp) == 321321321 as libc::c_int as libc::c_long {} else {
        __assert_fail(
            b"json_object_get_int64(tmp) == 321321321\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            18 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(tmp);
    printf(b"INT64 PASSED\n\0" as *const u8 as *const libc::c_char);
    tmp = json_object_new_uint64(123 as libc::c_int as uint64_t);
    if json_object_get_boolean(tmp) == 1 as libc::c_int {} else {
        __assert_fail(
            b"json_object_get_boolean(tmp) == 1\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            22 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if json_object_get_int(tmp) == 123 as libc::c_int {} else {
        __assert_fail(
            b"json_object_get_int(tmp) == 123\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            23 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if json_object_get_int64(tmp) == 123 as libc::c_int as libc::c_long {} else {
        __assert_fail(
            b"json_object_get_int64(tmp) == 123\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            24 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if json_object_get_uint64(tmp) == 123 as libc::c_int as libc::c_ulong {} else {
        __assert_fail(
            b"json_object_get_uint64(tmp) == 123\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            25 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if json_object_get_double(tmp) == 123.000000f64 {} else {
        __assert_fail(
            b"json_object_get_double(tmp) == 123.000000\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            26 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_uint64(tmp, 321321321 as libc::c_int as uint64_t);
    if json_object_get_uint64(tmp) == 321321321 as libc::c_int as libc::c_ulong {} else {
        __assert_fail(
            b"json_object_get_uint64(tmp) == 321321321\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            28 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_uint64(tmp, 9223372036854775808 as libc::c_ulong);
    if json_object_get_int(tmp) == 2147483647 as libc::c_int {} else {
        __assert_fail(
            b"json_object_get_int(tmp) == INT32_MAX\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            30 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if json_object_get_uint64(tmp) == 9223372036854775808 as libc::c_ulong {} else {
        __assert_fail(
            b"json_object_get_uint64(tmp) == 9223372036854775808U\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            31 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(tmp);
    printf(b"UINT64 PASSED\n\0" as *const u8 as *const libc::c_char);
    tmp = json_object_new_boolean(1 as libc::c_int);
    if json_object_get_boolean(tmp) == 1 as libc::c_int {} else {
        __assert_fail(
            b"json_object_get_boolean(tmp) == 1\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            35 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_boolean(tmp, 0 as libc::c_int);
    if json_object_get_boolean(tmp) == 0 as libc::c_int {} else {
        __assert_fail(
            b"json_object_get_boolean(tmp) == 0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            37 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_boolean(tmp, 1 as libc::c_int);
    if json_object_get_boolean(tmp) == 1 as libc::c_int {} else {
        __assert_fail(
            b"json_object_get_boolean(tmp) == 1\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            39 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(tmp);
    printf(b"BOOL PASSED\n\0" as *const u8 as *const libc::c_char);
    tmp = json_object_new_double(12.34f64);
    if json_object_get_double(tmp) == 12.34f64 {} else {
        __assert_fail(
            b"json_object_get_double(tmp) == 12.34\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            43 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_double(tmp, 34.56f64);
    if json_object_get_double(tmp) == 34.56f64 {} else {
        __assert_fail(
            b"json_object_get_double(tmp) == 34.56\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            45 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_double(tmp, 6435.34f64);
    if json_object_get_double(tmp) == 6435.34f64 {} else {
        __assert_fail(
            b"json_object_get_double(tmp) == 6435.34\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            47 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_double(tmp, 2e21f64);
    if json_object_get_int(tmp) == 2147483647 as libc::c_int {} else {
        __assert_fail(
            b"json_object_get_int(tmp) == INT32_MAX\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            49 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if json_object_get_int64(tmp) == 9223372036854775807 as libc::c_long {} else {
        __assert_fail(
            b"json_object_get_int64(tmp) == INT64_MAX\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            50 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if json_object_get_uint64(tmp) == 18446744073709551615 as libc::c_ulong {} else {
        __assert_fail(
            b"json_object_get_uint64(tmp) == UINT64_MAX\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            51 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_double(tmp, -2e21f64);
    if json_object_get_int(tmp) == -(2147483647 as libc::c_int) - 1 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int(tmp) == INT32_MIN\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            53 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if json_object_get_int64(tmp)
        == -(9223372036854775807 as libc::c_long) - 1 as libc::c_int as libc::c_long
    {} else {
        __assert_fail(
            b"json_object_get_int64(tmp) == INT64_MIN\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            54 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if json_object_get_uint64(tmp) == 0 as libc::c_int as libc::c_ulong {} else {
        __assert_fail(
            b"json_object_get_uint64(tmp) == 0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            55 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(tmp);
    printf(b"DOUBLE PASSED\n\0" as *const u8 as *const libc::c_char);
    tmp = json_object_new_string(b"A MID STRING\0" as *const u8 as *const libc::c_char);
    if strcmp(
        json_object_get_string(tmp),
        b"A MID STRING\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"strcmp(json_object_get_string(tmp), MID) == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            63 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if strcmp(
        json_object_to_json_string(tmp),
        b"\"A MID STRING\"\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"strcmp(json_object_to_json_string(tmp), \"\\\"\" MID \"\\\"\") == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            64 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_string(tmp, b"SHORT\0" as *const u8 as *const libc::c_char);
    if strcmp(
        json_object_get_string(tmp),
        b"SHORT\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"strcmp(json_object_get_string(tmp), SHORT) == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            66 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if strcmp(
        json_object_to_json_string(tmp),
        b"\"SHORT\"\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"strcmp(json_object_to_json_string(tmp), \"\\\"\" SHORT \"\\\"\") == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            67 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_string(
        tmp,
        b"A string longer than 32 chars as to check non local buf codepath\0"
            as *const u8 as *const libc::c_char,
    );
    if strcmp(
        json_object_get_string(tmp),
        b"A string longer than 32 chars as to check non local buf codepath\0"
            as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"strcmp(json_object_get_string(tmp), HUGE) == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            69 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if strcmp(
        json_object_to_json_string(tmp),
        b"\"A string longer than 32 chars as to check non local buf codepath\"\0"
            as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"strcmp(json_object_to_json_string(tmp), \"\\\"\" HUGE \"\\\"\") == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            70 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_string(tmp, b"SHORT\0" as *const u8 as *const libc::c_char);
    if strcmp(
        json_object_get_string(tmp),
        b"SHORT\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"strcmp(json_object_get_string(tmp), SHORT) == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            72 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if strcmp(
        json_object_to_json_string(tmp),
        b"\"SHORT\"\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"strcmp(json_object_to_json_string(tmp), \"\\\"\" SHORT \"\\\"\") == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            73 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_string(tmp, b"\0" as *const u8 as *const libc::c_char);
    json_object_set_string(
        tmp,
        b"A string longer than 32 chars as to check non local buf codepath\0"
            as *const u8 as *const libc::c_char,
    );
    json_object_set_string(tmp, b"\0" as *const u8 as *const libc::c_char);
    json_object_set_string(
        tmp,
        b"A string longer than 32 chars as to check non local buf codepath\0"
            as *const u8 as *const libc::c_char,
    );
    json_object_put(tmp);
    printf(b"STRING PASSED\n\0" as *const u8 as *const libc::c_char);
    tmp = json_object_new_string(b"STR\0" as *const u8 as *const libc::c_char);
    if json_object_get_double(tmp) == 0.0f64 {} else {
        __assert_fail(
            b"json_object_get_double(tmp) == 0.0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            92 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_string(tmp, b"123.123\0" as *const u8 as *const libc::c_char);
    if json_object_get_double(tmp) == 123.123000f64 {} else {
        __assert_fail(
            b"json_object_get_double(tmp) == 123.123000\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            94 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_string(tmp, b"12E+3\0" as *const u8 as *const libc::c_char);
    if json_object_get_double(tmp) == 12000.000000f64 {} else {
        __assert_fail(
            b"json_object_get_double(tmp) == 12000.000000\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            96 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_string(tmp, b"123.123STR\0" as *const u8 as *const libc::c_char);
    if json_object_get_double(tmp) == 0.0f64 {} else {
        __assert_fail(
            b"json_object_get_double(tmp) == 0.0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            98 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_string(tmp, b"1.8E+308\0" as *const u8 as *const libc::c_char);
    if json_object_get_double(tmp) == 0.0f64 {} else {
        __assert_fail(
            b"json_object_get_double(tmp) == 0.0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            100 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_set_string(tmp, b"-1.8E+308\0" as *const u8 as *const libc::c_char);
    if json_object_get_double(tmp) == 0.0f64 {} else {
        __assert_fail(
            b"json_object_get_double(tmp) == 0.0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            102 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(tmp);
    printf(b"STRINGTODOUBLE PASSED\n\0" as *const u8 as *const libc::c_char);
    tmp = json_tokener_parse(b"1.234\0" as *const u8 as *const libc::c_char);
    json_object_set_double(tmp, 12.3f64);
    let mut serialized: *const libc::c_char = json_object_to_json_string(tmp);
    fprintf(stderr, b"%s\n\0" as *const u8 as *const libc::c_char, serialized);
    if strncmp(
        serialized,
        b"12.3\0" as *const u8 as *const libc::c_char,
        4 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"strncmp(serialized, \"12.3\", 4) == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8
                as *const libc::c_char,
            110 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(tmp);
    printf(b"PARSE AND SET PASSED\n\0" as *const u8 as *const libc::c_char);
    printf(b"PASSED\n\0" as *const u8 as *const libc::c_char);
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
