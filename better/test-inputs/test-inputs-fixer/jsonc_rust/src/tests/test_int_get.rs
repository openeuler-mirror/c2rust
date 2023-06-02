
extern "C" {
    pub type json_object;
    fn __assert_fail(
        __assertion: *const i8,
        __file: *const i8,
        __line: u32,
        __function: *const i8,
    ) -> !;
    fn printf(_: *const i8, _: ...) -> i32;
    fn __errno_location() -> *mut i32;
    fn json_object_put(obj: *mut json_object) -> i32;
    fn json_object_new_int(i: int32_t) -> *mut json_object;
    fn json_object_new_int64(i: int64_t) -> *mut json_object;
    fn json_object_new_uint64(i: uint64_t) -> *mut json_object;
    fn json_object_get_int(obj: *const json_object) -> int32_t;
    fn json_object_get_int64(obj: *const json_object) -> int64_t;
    fn json_object_get_uint64(obj: *const json_object) -> uint64_t;
    fn json_object_new_string(s: *const i8) -> *mut json_object;
}
pub type __int32_t = i32;
pub type __int64_t = i64;
pub type __uint64_t = u64;
pub type int32_t = __int32_t;
pub type int64_t = __int64_t;
pub type uint64_t = __uint64_t;
fn main_0(mut _argc: i32, mut _argv: *mut *mut i8) -> i32 {
    let mut jtmp: *mut json_object = unsafe { json_object_new_int(5 as i32) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int(jtmp) }) == 5 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(jtmp) == 5\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            31 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp) });
    let mut jtmp_0: *mut json_object = unsafe { json_object_new_int(5 as i32) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int64(jtmp_0) }) == 5 as i32 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(jtmp) == 5\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            31 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_0) });
    let mut jtmp_1: *mut json_object = unsafe { json_object_new_int(5 as i32) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_uint64(jtmp_1) }) == 5 as i32 as u64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(jtmp) == 5\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            31 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_1) });
    let mut jtmp_2: *mut json_object = unsafe { json_object_new_int(0 as i32) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int(jtmp_2) }) == 0 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(jtmp) == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            32 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_2) });
    let mut jtmp_3: *mut json_object = unsafe { json_object_new_int(0 as i32) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int64(jtmp_3) }) == 0 as i32 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(jtmp) == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            32 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_3) });
    let mut jtmp_4: *mut json_object = unsafe { json_object_new_int(0 as i32) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_uint64(jtmp_4) }) == 0 as i32 as u64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(jtmp) == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            32 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_4) });
    let mut jtmp_5: *mut json_object = unsafe { json_object_new_string(b"0\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int(jtmp_5) }) == 0 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(jtmp) == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            33 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_5) });
    let mut jtmp_6: *mut json_object = unsafe { json_object_new_string(b"0\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int64(jtmp_6) }) == 0 as i32 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(jtmp) == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            33 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_6) });
    let mut jtmp_7: *mut json_object = unsafe { json_object_new_string(b"0\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_uint64(jtmp_7) }) == 0 as i32 as u64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(jtmp) == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            33 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_7) });
    let mut jtmp_8: *mut json_object = unsafe { json_object_new_string(b"00000\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int(jtmp_8) }) == 0 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(jtmp) == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            34 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_8) });
    let mut jtmp_9: *mut json_object = unsafe { json_object_new_string(b"00000\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int64(jtmp_9) }) == 0 as i32 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(jtmp) == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            34 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_9) });
    let mut jtmp_10: *mut json_object =
        unsafe { json_object_new_string(b"00000\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_uint64(jtmp_10) }) == 0 as i32 as u64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(jtmp) == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            34 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_10) });
    let mut jtmp_11: *mut json_object =
        unsafe { json_object_new_string(b"000004568789\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int(jtmp_11) }) == 4568789 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(jtmp) == 4568789\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            35 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_11) });
    let mut jtmp_12: *mut json_object =
        unsafe { json_object_new_string(b"000004568789\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int64(jtmp_12) }) == 4568789 as i32 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(jtmp) == 4568789\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            35 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_12) });
    let mut jtmp_13: *mut json_object =
        unsafe { json_object_new_string(b"000004568789\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_uint64(jtmp_13) }) == 4568789 as i32 as u64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(jtmp) == 4568789\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            35 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_13) });
    let mut jtmp_14: *mut json_object = unsafe { json_object_new_string(b"0xFF\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int(jtmp_14) }) == 0 as i32 && (unsafe { *__errno_location() }) == 0 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(jtmp) == 0 && (*__errno_location ()) == 0\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            36 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_14) });
    let mut jtmp_15: *mut json_object = unsafe { json_object_new_string(b"0xFF\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int64(jtmp_15) }) == 0 as i32 as i64 && (unsafe { *__errno_location() }) == 0 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(jtmp) == 0 && (*__errno_location ()) == 0\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            36 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_15) });
    let mut jtmp_16: *mut json_object = unsafe { json_object_new_string(b"0xFF\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_uint64(jtmp_16) }) == 0 as i32 as u64 && (unsafe { *__errno_location() }) == 0 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(jtmp) == 0 && (*__errno_location ()) == 0\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            36 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_16) });
    let mut jtmp_17: *mut json_object =
        unsafe { json_object_new_string(b"333this_seems_a_valid_string\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int(jtmp_17) }) == 333 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(jtmp) == 333\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            37 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_17) });
    let mut jtmp_18: *mut json_object =
        unsafe { json_object_new_string(b"333this_seems_a_valid_string\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int64(jtmp_18) }) == 333 as i32 as i64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(jtmp) == 333\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            37 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_18) });
    let mut jtmp_19: *mut json_object =
        unsafe { json_object_new_string(b"333this_seems_a_valid_string\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_uint64(jtmp_19) }) == 333 as i32 as u64 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(jtmp) == 333\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            37 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_19) });
    let mut jtmp_20: *mut json_object =
        unsafe { json_object_new_string(b"this_is_not_a_number\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int(jtmp_20) }) == 0 as i32 && (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(jtmp) == 0 && (*__errno_location ()) == 22\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            38 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_20) });
    let mut jtmp_21: *mut json_object =
        unsafe { json_object_new_string(b"this_is_not_a_number\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int64(jtmp_21) }) == 0 as i32 as i64 && (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(jtmp) == 0 && (*__errno_location ()) == 22\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            38 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_21) });
    let mut jtmp_22: *mut json_object =
        unsafe { json_object_new_string(b"this_is_not_a_number\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_uint64(jtmp_22) }) == 0 as i32 as u64 && (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(jtmp) == 0 && (*__errno_location ()) == 22\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            38 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_22) });
    let mut jtmp_23: *mut json_object = unsafe { json_object_new_string(b"B0\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int(jtmp_23) }) == 0 as i32 && (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(jtmp) == 0 && (*__errno_location ()) == 22\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            39 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_23) });
    let mut jtmp_24: *mut json_object = unsafe { json_object_new_string(b"B0\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int64(jtmp_24) }) == 0 as i32 as i64 && (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int64(jtmp) == 0 && (*__errno_location ()) == 22\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            39 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_24) });
    let mut jtmp_25: *mut json_object = unsafe { json_object_new_string(b"B0\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_uint64(jtmp_25) }) == 0 as i32 as u64 && (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_uint64(jtmp) == 0 && (*__errno_location ()) == 22\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            39 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_25) });
    (unsafe { printf(b"BASE CHECK PASSED\n\0" as *const u8 as *const i8) });
    let mut jtmp_26: *mut json_object = unsafe { json_object_new_int64(2147483647 as i32 as int64_t) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int(jtmp_26) }) == 2147483647 as i32 && (unsafe { *__errno_location() }) == 0 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(jtmp) == (2147483647) && (*__errno_location ()) == 0\0"
                as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            42 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_26) });
    let mut jtmp_27: *mut json_object =
        unsafe { json_object_new_int64((-(2147483647 as i32) - 1 as i32) as int64_t) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int(jtmp_27) }) == -(2147483647 as i32) - 1 as i32
        && (unsafe { *__errno_location() }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(jtmp) == (-2147483647-1) && (*__errno_location ()) == 0\0"
                as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            43 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_27) });
    let mut jtmp_28: *mut json_object = unsafe { json_object_new_int64(9223372036854775807 as i64) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int(jtmp_28) }) == 2147483647 as i32 && (unsafe { *__errno_location() }) == 0 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(jtmp) == (2147483647) && (*__errno_location ()) == 0\0"
                as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            44 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_28) });
    let mut jtmp_29: *mut json_object =
        unsafe { json_object_new_int64(-(9223372036854775807 as i64) - 1 as i32 as i64) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int(jtmp_29) }) == -(2147483647 as i32) - 1 as i32
        && (unsafe { *__errno_location() }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(jtmp) == (-2147483647-1) && (*__errno_location ()) == 0\0"
                as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            45 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_29) });
    let mut jtmp_30: *mut json_object =
        unsafe { json_object_new_string(b"9223372036854775807\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int(jtmp_30) }) == 2147483647 as i32 && (unsafe { *__errno_location() }) == 0 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(jtmp) == (2147483647) && (*__errno_location ()) == 0\0"
                as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            46 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_30) });
    let mut jtmp_31: *mut json_object =
        unsafe { json_object_new_string(b"-9223372036854775808\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int(jtmp_31) }) == -(2147483647 as i32) - 1 as i32
        && (unsafe { *__errno_location() }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_int(jtmp) == (-2147483647-1) && (*__errno_location ()) == 0\0"
                as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8 as *const i8,
            47 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jtmp_31) });
    (unsafe { printf(b"INT GET PASSED\n\0" as *const u8 as *const i8) });
    let mut jtmp_32: *mut json_object = unsafe { json_object_new_int64(9223372036854775807 as i64) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int64(jtmp_32) }) == 9223372036854775807 as i64
        && (unsafe { *__errno_location() }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail (b"json_object_get_int64(jtmp) == (9223372036854775807L) && (*__errno_location ()) == 0\0" as * const u8 as * const i8 , b"/home/xial/json-c/tests/test_int_get.c\0" as * const u8 as * const i8 , 50 as i32 as u32 , (* :: std :: mem :: transmute :: < & [u8 ; 23] , & [i8 ; 23] , > (b"int main(int, char **)\0")) . as_ptr () ,) }) ;
    }
    (unsafe { json_object_put(jtmp_32) });
    let mut jtmp_33: *mut json_object =
        unsafe { json_object_new_int64(-(9223372036854775807 as i64) - 1 as i32 as i64) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int64(jtmp_33) }) == -(9223372036854775807 as i64) - 1 as i32 as i64
        && (unsafe { *__errno_location() }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail (b"json_object_get_int64(jtmp) == (-9223372036854775807L-1) && (*__errno_location ()) == 0\0" as * const u8 as * const i8 , b"/home/xial/json-c/tests/test_int_get.c\0" as * const u8 as * const i8 , 51 as i32 as u32 , (* :: std :: mem :: transmute :: < & [u8 ; 23] , & [i8 ; 23] , > (b"int main(int, char **)\0")) . as_ptr () ,) }) ;
    }
    (unsafe { json_object_put(jtmp_33) });
    let mut jtmp_34: *mut json_object =
        unsafe { json_object_new_string(b"9223372036854775807\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int64(jtmp_34) }) == 9223372036854775807 as i64
        && (unsafe { *__errno_location() }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail (b"json_object_get_int64(jtmp) == (9223372036854775807L) && (*__errno_location ()) == 0\0" as * const u8 as * const i8 , b"/home/xial/json-c/tests/test_int_get.c\0" as * const u8 as * const i8 , 52 as i32 as u32 , (* :: std :: mem :: transmute :: < & [u8 ; 23] , & [i8 ; 23] , > (b"int main(int, char **)\0")) . as_ptr () ,) }) ;
    }
    (unsafe { json_object_put(jtmp_34) });
    let mut jtmp_35: *mut json_object =
        unsafe { json_object_new_string(b"-9223372036854775808\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int64(jtmp_35) }) == -(9223372036854775807 as i64) - 1 as i32 as i64
        && (unsafe { *__errno_location() }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail (b"json_object_get_int64(jtmp) == (-9223372036854775807L-1) && (*__errno_location ()) == 0\0" as * const u8 as * const i8 , b"/home/xial/json-c/tests/test_int_get.c\0" as * const u8 as * const i8 , 53 as i32 as u32 , (* :: std :: mem :: transmute :: < & [u8 ; 23] , & [i8 ; 23] , > (b"int main(int, char **)\0")) . as_ptr () ,) }) ;
    }
    (unsafe { json_object_put(jtmp_35) });
    let mut jtmp_36: *mut json_object =
        unsafe { json_object_new_string(b"9223372036854775808\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int64(jtmp_36) }) == 9223372036854775807 as i64
        && (unsafe { *__errno_location() }) == 34 as i32
    {
    } else {
        (unsafe { __assert_fail (b"json_object_get_int64(jtmp) == (9223372036854775807L) && (*__errno_location ()) == 34\0" as * const u8 as * const i8 , b"/home/xial/json-c/tests/test_int_get.c\0" as * const u8 as * const i8 , 54 as i32 as u32 , (* :: std :: mem :: transmute :: < & [u8 ; 23] , & [i8 ; 23] , > (b"int main(int, char **)\0")) . as_ptr () ,) }) ;
    }
    (unsafe { json_object_put(jtmp_36) });
    let mut jtmp_37: *mut json_object =
        unsafe { json_object_new_string(b"-9223372036854775809\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_int64(jtmp_37) }) == -(9223372036854775807 as i64) - 1 as i32 as i64
        && (unsafe { *__errno_location() }) == 34 as i32
    {
    } else {
        (unsafe { __assert_fail (b"json_object_get_int64(jtmp) == (-9223372036854775807L-1) && (*__errno_location ()) == 34\0" as * const u8 as * const i8 , b"/home/xial/json-c/tests/test_int_get.c\0" as * const u8 as * const i8 , 55 as i32 as u32 , (* :: std :: mem :: transmute :: < & [u8 ; 23] , & [i8 ; 23] , > (b"int main(int, char **)\0")) . as_ptr () ,) }) ;
    }
    (unsafe { json_object_put(jtmp_37) });
    (unsafe { printf(b"INT64 GET PASSED\n\0" as *const u8 as *const i8) });
    let mut jtmp_38: *mut json_object = unsafe { json_object_new_uint64(18446744073709551615 as u64) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_uint64(jtmp_38) }) == 18446744073709551615 as u64
        && (unsafe { *__errno_location() }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail (b"json_object_get_uint64(jtmp) == (18446744073709551615UL) && (*__errno_location ()) == 0\0" as * const u8 as * const i8 , b"/home/xial/json-c/tests/test_int_get.c\0" as * const u8 as * const i8 , 58 as i32 as u32 , (* :: std :: mem :: transmute :: < & [u8 ; 23] , & [i8 ; 23] , > (b"int main(int, char **)\0")) . as_ptr () ,) }) ;
    }
    (unsafe { json_object_put(jtmp_38) });
    let mut jtmp_39: *mut json_object = unsafe { json_object_new_uint64(-(1 as i32) as uint64_t) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_uint64(jtmp_39) }) == 18446744073709551615 as u64
        && (unsafe { *__errno_location() }) == 0 as i32
    {
    } else {
        (unsafe { __assert_fail (b"json_object_get_uint64(jtmp) == (18446744073709551615UL) && (*__errno_location ()) == 0\0" as * const u8 as * const i8 , b"/home/xial/json-c/tests/test_int_get.c\0" as * const u8 as * const i8 , 59 as i32 as u32 , (* :: std :: mem :: transmute :: < & [u8 ; 23] , & [i8 ; 23] , > (b"int main(int, char **)\0")) . as_ptr () ,) }) ;
    }
    (unsafe { json_object_put(jtmp_39) });
    let mut jtmp_40: *mut json_object =
        unsafe { json_object_new_string(b"18446744073709551616\0" as *const u8 as *const i8) };
    (unsafe { *__errno_location() = 0 as i32 });
    if (unsafe { json_object_get_uint64(jtmp_40) }) == 18446744073709551615 as u64
        && (unsafe { *__errno_location() }) == 34 as i32
    {
    } else {
        (unsafe { __assert_fail (b"json_object_get_uint64(jtmp) == (18446744073709551615UL) && (*__errno_location ()) == 34\0" as * const u8 as * const i8 , b"/home/xial/json-c/tests/test_int_get.c\0" as * const u8 as * const i8 , 60 as i32 as u32 , (* :: std :: mem :: transmute :: < & [u8 ; 23] , & [i8 ; 23] , > (b"int main(int, char **)\0")) . as_ptr () ,) }) ;
    }
    (unsafe { json_object_put(jtmp_40) });
    (unsafe { printf(b"UINT64 GET PASSED\n\0" as *const u8 as *const i8) });
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
