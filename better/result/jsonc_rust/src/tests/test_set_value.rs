
extern "C" {
    fn __assert_fail(
        __assertion: *const i8,
        __file: *const i8,
        __line: u32,
        __function: *const i8,
    ) -> !;
    static mut stderr: *mut crate::src::apps::json_parse::_IO_FILE;
    fn fprintf(_: *mut crate::src::apps::json_parse::_IO_FILE, _: *const i8, _: ...) -> i32;
    fn printf(_: *const i8, _: ...) -> i32;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strncmp(_: *const i8, _: *const i8, _: u64) -> i32;
}
pub use crate::src::{
    debug::_IO_wide_data,
    json_object::{
        _IO_codecvt, json_object, json_object_get_boolean, json_object_get_double,
        json_object_get_int, json_object_get_int64, json_object_get_string, json_object_get_uint64,
        json_object_new_boolean, json_object_new_double, json_object_new_int,
        json_object_new_string, json_object_new_uint64, json_object_put, json_object_set_boolean,
        json_object_set_double, json_object_set_int, json_object_set_int64, json_object_set_string,
        json_object_set_uint64, json_object_to_json_string,
    },
    json_tokener::json_tokener_parse,
    json_visit::_IO_marker,
};
pub type size_t = u64;
pub type __int32_t = i32;
pub type __int64_t = i64;
pub type __uint64_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type _IO_FILE = crate::src::apps::json_parse::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::apps::json_parse::_IO_FILE;
pub type int32_t = i32;
pub type int64_t = i64;
pub type uint64_t = u64;
pub type json_bool = i32;
fn main_0(mut _argc: i32, mut _argv: *mut *mut i8) -> i32 {
    let mut tmp: *mut crate::src::json_object::json_object = json_object_new_int(123 as i32);
    if json_object_get_int(tmp) == 123 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(tmp) == 123\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            13 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_int(tmp, 321 as i32);
    if json_object_get_int(tmp) == 321 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(tmp) == 321\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            15 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    (unsafe { printf(b"INT PASSED\n\0" as *const u8 as *const i8) });
    json_object_set_int64(tmp, 321321321 as i32 as int64_t);
    if json_object_get_int64(tmp) == 321321321 as i32 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(tmp) == 321321321\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            18 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_put(tmp);
    (unsafe { printf(b"INT64 PASSED\n\0" as *const u8 as *const i8) });
    tmp = json_object_new_uint64(123 as i32 as uint64_t);
    if json_object_get_boolean(tmp) == 1 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_boolean(tmp) == 1\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            22 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if json_object_get_int(tmp) == 123 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(tmp) == 123\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            23 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if json_object_get_int64(tmp) == 123 as i32 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(tmp) == 123\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            24 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if json_object_get_uint64(tmp) == 123 as i32 as u64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(tmp) == 123\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            25 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if json_object_get_double(tmp) == 123.000000f64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_double(tmp) == 123.000000\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            26 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_uint64(tmp, 321321321 as i32 as uint64_t);
    if json_object_get_uint64(tmp) == 321321321 as i32 as u64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(tmp) == 321321321\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            28 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_uint64(tmp, 9223372036854775808 as u64);
    if json_object_get_int(tmp) == 2147483647 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(tmp) == INT32_MAX\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            30 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if json_object_get_uint64(tmp) == 9223372036854775808 as u64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(tmp) == 9223372036854775808U\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            31 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_put(tmp);
    (unsafe { printf(b"UINT64 PASSED\n\0" as *const u8 as *const i8) });
    tmp = json_object_new_boolean(1 as i32);
    if json_object_get_boolean(tmp) == 1 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_boolean(tmp) == 1\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            35 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_boolean(tmp, 0 as i32);
    if json_object_get_boolean(tmp) == 0 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_boolean(tmp) == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            37 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_boolean(tmp, 1 as i32);
    if json_object_get_boolean(tmp) == 1 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_boolean(tmp) == 1\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            39 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_put(tmp);
    (unsafe { printf(b"BOOL PASSED\n\0" as *const u8 as *const i8) });
    tmp = json_object_new_double(12.34f64);
    if json_object_get_double(tmp) == 12.34f64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_double(tmp) == 12.34\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            43 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_double(tmp, 34.56f64);
    if json_object_get_double(tmp) == 34.56f64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_double(tmp) == 34.56\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            45 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_double(tmp, 6435.34f64);
    if json_object_get_double(tmp) == 6435.34f64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_double(tmp) == 6435.34\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            47 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_double(tmp, 2e21f64);
    if json_object_get_int(tmp) == 2147483647 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(tmp) == INT32_MAX\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            49 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if json_object_get_int64(tmp) == 9223372036854775807 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(tmp) == INT64_MAX\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            50 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if json_object_get_uint64(tmp) == 18446744073709551615 as u64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(tmp) == UINT64_MAX\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            51 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_double(tmp, -2e21f64);
    if json_object_get_int(tmp) == -(2147483647 as i32) - 1 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(tmp) == INT32_MIN\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            53 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if json_object_get_int64(tmp) == -(9223372036854775807 as i64) - 1 as i32 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(tmp) == INT64_MIN\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            54 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if json_object_get_uint64(tmp) == 0 as i32 as u64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(tmp) == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            55 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_put(tmp);
    (unsafe { printf(b"DOUBLE PASSED\n\0" as *const u8 as *const i8) });
    tmp = json_object_new_string(b"A MID STRING\0" as *const u8 as *const i8);
    if (unsafe { strcmp(
        json_object_get_string(tmp),
        b"A MID STRING\0" as *const u8 as *const i8,
    ) }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail(
            b"strcmp(json_object_get_string(tmp), MID) == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            63 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if (unsafe { strcmp(
        json_object_to_json_string(tmp),
        b"\"A MID STRING\"\0" as *const u8 as *const i8,
    ) }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail(
            b"strcmp(json_object_to_json_string(tmp), \"\\\"\" MID \"\\\"\") == 0\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            64 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_string(tmp, b"SHORT\0" as *const u8 as *const i8);
    if (unsafe { strcmp(
        json_object_get_string(tmp),
        b"SHORT\0" as *const u8 as *const i8,
    ) }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail(
            b"strcmp(json_object_get_string(tmp), SHORT) == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            66 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if (unsafe { strcmp(
        json_object_to_json_string(tmp),
        b"\"SHORT\"\0" as *const u8 as *const i8,
    ) }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail(
            b"strcmp(json_object_to_json_string(tmp), \"\\\"\" SHORT \"\\\"\") == 0\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            67 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_string(
        tmp,
        b"A string longer than 32 chars as to check non local buf codepath\0" as *const u8
            as *const i8,
    );
    if (unsafe { strcmp(
        json_object_get_string(tmp),
        b"A string longer than 32 chars as to check non local buf codepath\0" as *const u8
            as *const i8,
    ) }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail(
            b"strcmp(json_object_get_string(tmp), HUGE) == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            69 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if (unsafe { strcmp(
        json_object_to_json_string(tmp),
        b"\"A string longer than 32 chars as to check non local buf codepath\"\0" as *const u8
            as *const i8,
    ) }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail(
            b"strcmp(json_object_to_json_string(tmp), \"\\\"\" HUGE \"\\\"\") == 0\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            70 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_string(tmp, b"SHORT\0" as *const u8 as *const i8);
    if (unsafe { strcmp(
        json_object_get_string(tmp),
        b"SHORT\0" as *const u8 as *const i8,
    ) }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail(
            b"strcmp(json_object_get_string(tmp), SHORT) == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            72 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if (unsafe { strcmp(
        json_object_to_json_string(tmp),
        b"\"SHORT\"\0" as *const u8 as *const i8,
    ) }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail(
            b"strcmp(json_object_to_json_string(tmp), \"\\\"\" SHORT \"\\\"\") == 0\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            73 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_string(tmp, b"\0" as *const u8 as *const i8);
    json_object_set_string(
        tmp,
        b"A string longer than 32 chars as to check non local buf codepath\0" as *const u8
            as *const i8,
    );
    json_object_set_string(tmp, b"\0" as *const u8 as *const i8);
    json_object_set_string(
        tmp,
        b"A string longer than 32 chars as to check non local buf codepath\0" as *const u8
            as *const i8,
    );
    json_object_put(tmp);
    (unsafe { printf(b"STRING PASSED\n\0" as *const u8 as *const i8) });
    tmp = json_object_new_string(b"STR\0" as *const u8 as *const i8);
    if json_object_get_double(tmp) == 0.0f64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_double(tmp) == 0.0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            92 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_string(tmp, b"123.123\0" as *const u8 as *const i8);
    if json_object_get_double(tmp) == 123.123000f64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_double(tmp) == 123.123000\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            94 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_string(tmp, b"12E+3\0" as *const u8 as *const i8);
    if json_object_get_double(tmp) == 12000.000000f64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_double(tmp) == 12000.000000\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            96 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_string(tmp, b"123.123STR\0" as *const u8 as *const i8);
    if json_object_get_double(tmp) == 0.0f64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_double(tmp) == 0.0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            98 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_string(tmp, b"1.8E+308\0" as *const u8 as *const i8);
    if json_object_get_double(tmp) == 0.0f64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_double(tmp) == 0.0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            100 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_set_string(tmp, b"-1.8E+308\0" as *const u8 as *const i8);
    if json_object_get_double(tmp) == 0.0f64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_double(tmp) == 0.0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            102 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_put(tmp);
    (unsafe { printf(b"STRINGTODOUBLE PASSED\n\0" as *const u8 as *const i8) });
    tmp = json_tokener_parse(b"1.234\0" as *const u8 as *const i8);
    json_object_set_double(tmp, 12.3f64);
    let mut serialized: *const i8 = json_object_to_json_string(tmp);
    (unsafe { fprintf(stderr, b"%s\n\0" as *const u8 as *const i8, serialized) });
    if (unsafe { strncmp(
        serialized,
        b"12.3\0" as *const u8 as *const i8,
        4 as i32 as u64,
    ) }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail(
            b"strncmp(serialized, \"12.3\", 4) == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_value.c\0" as *const u8 as *const i8,
            110 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_put(tmp);
    (unsafe { printf(b"PARSE AND SET PASSED\n\0" as *const u8 as *const i8) });
    (unsafe { printf(b"PASSED\n\0" as *const u8 as *const i8) });
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

