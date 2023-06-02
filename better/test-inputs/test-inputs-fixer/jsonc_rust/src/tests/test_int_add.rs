
extern "C" {
    pub type json_object;
    fn __assert_fail(
        __assertion: *const i8,
        __file: *const i8,
        __line: u32,
        __function: *const i8,
    ) -> !;
    fn printf(_: *const i8, _: ...) -> i32;
    fn json_object_put(obj: *mut json_object) -> i32;
    fn json_object_new_int(i: int32_t) -> *mut json_object;
    fn json_object_new_int64(i: int64_t) -> *mut json_object;
    fn json_object_new_uint64(i: uint64_t) -> *mut json_object;
    fn json_object_get_int(obj: *const json_object) -> int32_t;
    fn json_object_int_inc(obj: *mut json_object, val: int64_t) -> i32;
    fn json_object_get_int64(obj: *const json_object) -> int64_t;
    fn json_object_get_uint64(obj: *const json_object) -> uint64_t;
}
pub type __int32_t = i32;
pub type __int64_t = i64;
pub type __uint64_t = u64;
pub type int32_t = __int32_t;
pub type int64_t = __int64_t;
pub type uint64_t = __uint64_t;
fn main_0(mut _argc: i32, mut _argv: *mut *mut i8) -> i32 {
    let mut tmp: *mut json_object = unsafe { json_object_new_int(123 as i32) };
    (unsafe { json_object_int_inc(tmp, 123 as i32 as int64_t) });
    if (unsafe { json_object_get_int(tmp) }) == 246 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(tmp) == 246\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            13 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(tmp) });
    (unsafe { printf(b"INT ADD PASSED\n\0" as *const u8 as *const i8) });
    tmp = unsafe { json_object_new_int(2147483647 as i32) };
    (unsafe { json_object_int_inc(tmp, 100 as i32 as int64_t) });
    if (unsafe { json_object_get_int(tmp) }) == 2147483647 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(tmp) == INT32_MAX\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            18 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    if (unsafe { json_object_get_int64(tmp) }) == 2147483647 as i32 as int64_t + 100 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(tmp) == (int64_t)INT32_MAX + 100L\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            19 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(tmp) });
    (unsafe { printf(b"INT ADD OVERFLOW PASSED\n\0" as *const u8 as *const i8) });
    tmp = unsafe { json_object_new_int(-(2147483647 as i32) - 1 as i32) };
    (unsafe { json_object_int_inc(tmp, -(100 as i32) as int64_t) });
    if (unsafe { json_object_get_int(tmp) }) == -(2147483647 as i32) - 1 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(tmp) == INT32_MIN\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            24 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    if (unsafe { json_object_get_int64(tmp) }) == (-(2147483647 as i32) - 1 as i32) as int64_t - 100 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(tmp) == (int64_t)INT32_MIN - 100L\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            25 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(tmp) });
    (unsafe { printf(b"INT ADD UNDERFLOW PASSED\n\0" as *const u8 as *const i8) });
    tmp = unsafe { json_object_new_int64(321321321 as i32 as int64_t) };
    (unsafe { json_object_int_inc(tmp, 321321321 as i32 as int64_t) });
    if (unsafe { json_object_get_int(tmp) }) == 642642642 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(tmp) == 642642642\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            30 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(tmp) });
    (unsafe { printf(b"INT64 ADD PASSED\n\0" as *const u8 as *const i8) });
    tmp = unsafe { json_object_new_int64(9223372036854775807 as i64) };
    (unsafe { json_object_int_inc(tmp, 100 as i32 as int64_t) });
    if (unsafe { json_object_get_int64(tmp) }) == 9223372036854775807 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(tmp) == INT64_MAX\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            35 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    if (unsafe { json_object_get_uint64(tmp) })
        == (9223372036854775807 as i64 as uint64_t).wrapping_add(100 as u32 as u64)
    {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(tmp) == (uint64_t)INT64_MAX + 100U\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            36 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_int_inc(tmp, -(100 as i32) as int64_t) });
    if (unsafe { json_object_get_int64(tmp) }) == 9223372036854775807 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(tmp) == INT64_MAX\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            38 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    if (unsafe { json_object_get_uint64(tmp) }) == 9223372036854775807 as i64 as uint64_t {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(tmp) == (uint64_t)INT64_MAX\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            39 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(tmp) });
    (unsafe { printf(b"INT64 ADD OVERFLOW PASSED\n\0" as *const u8 as *const i8) });
    tmp = unsafe { json_object_new_int64(-(9223372036854775807 as i64) - 1 as i32 as i64) };
    (unsafe { json_object_int_inc(tmp, -(100 as i32) as int64_t) });
    if (unsafe { json_object_get_int64(tmp) }) == -(9223372036854775807 as i64) - 1 as i32 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(tmp) == INT64_MIN\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            44 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_int_inc(tmp, 100 as i32 as int64_t) });
    if (unsafe { json_object_get_int64(tmp) }) != -(9223372036854775807 as i64) - 1 as i32 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(tmp) != INT64_MIN\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            46 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(tmp) });
    (unsafe { printf(b"INT64 ADD UNDERFLOW PASSED\n\0" as *const u8 as *const i8) });
    tmp = unsafe { json_object_new_uint64(400 as i32 as uint64_t) };
    (unsafe { json_object_int_inc(tmp, -(200 as i32) as int64_t) });
    if (unsafe { json_object_get_int64(tmp) }) == 200 as i32 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(tmp) == 200\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            52 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    if (unsafe { json_object_get_uint64(tmp) }) == 200 as i32 as u64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(tmp) == 200\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            53 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_int_inc(tmp, 200 as i32 as int64_t) });
    if (unsafe { json_object_get_int64(tmp) }) == 400 as i32 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(tmp) == 400\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            55 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    if (unsafe { json_object_get_uint64(tmp) }) == 400 as i32 as u64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(tmp) == 400\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            56 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(tmp) });
    (unsafe { printf(b"UINT64 ADD PASSED\n\0" as *const u8 as *const i8) });
    tmp = unsafe { json_object_new_uint64((18446744073709551615 as u64).wrapping_sub(50 as i32 as u64)) };
    (unsafe { json_object_int_inc(tmp, 100 as i32 as int64_t) });
    if (unsafe { json_object_get_int64(tmp) }) == 9223372036854775807 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(tmp) == INT64_MAX\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            61 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    if (unsafe { json_object_get_uint64(tmp) }) == 18446744073709551615 as u64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(tmp) == UINT64_MAX\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            62 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(tmp) });
    (unsafe { printf(b"UINT64 ADD OVERFLOW PASSED\n\0" as *const u8 as *const i8) });
    tmp = unsafe { json_object_new_uint64(100 as i32 as uint64_t) };
    (unsafe { json_object_int_inc(tmp, -(200 as i32) as int64_t) });
    if (unsafe { json_object_get_int64(tmp) }) == -(100 as i32) as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(tmp) == -100\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            67 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    if (unsafe { json_object_get_uint64(tmp) }) == 0 as i32 as u64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(tmp) == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_add.c\0" as *const u8 as *const i8,
            68 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(tmp) });
    (unsafe { printf(b"UINT64 ADD UNDERFLOW PASSED\n\0" as *const u8 as *const i8) });
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
