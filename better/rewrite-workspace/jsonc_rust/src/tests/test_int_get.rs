use ::libc;
extern "C" {
    
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn __errno_location() -> *mut libc::c_int;
    
    
    
    
    
    
    
    
}
pub use crate::src::json_object::json_object_get_int;
pub use crate::src::json_object::json_object_get_int64;
pub use crate::src::json_object::json_object_get_uint64;
pub use crate::src::json_object::json_object_new_int;
pub use crate::src::json_object::json_object_new_int64;
pub use crate::src::json_object::json_object_new_string;
pub use crate::src::json_object::json_object_new_uint64;
pub use crate::src::json_object::json_object_put;
pub use crate::src::json_object::json_object;
pub use crate::src::json_object::__int32_t;
pub use crate::src::json_object::__int64_t;
pub use crate::src::json_object::__uint64_t;
pub use crate::src::json_object::int32_t;
pub use crate::src::json_object::int64_t;
pub use crate::src::json_object::uint64_t;
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut jtmp: *mut json_object = json_object_new_int(5 as libc::c_int);
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int(jtmp) == 5 as libc::c_int {} else {
        __assert_fail(
            b"json_object_get_int(jtmp) == 5\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            31 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp);
    let mut jtmp_0: *mut json_object = json_object_new_int(5 as libc::c_int);
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int64(jtmp_0) == 5 as libc::c_int as libc::c_long {} else {
        __assert_fail(
            b"json_object_get_int64(jtmp) == 5\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            31 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_0);
    let mut jtmp_1: *mut json_object = json_object_new_int(5 as libc::c_int);
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_uint64(jtmp_1) == 5 as libc::c_int as libc::c_ulong {} else {
        __assert_fail(
            b"json_object_get_uint64(jtmp) == 5\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            31 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_1);
    let mut jtmp_2: *mut json_object = json_object_new_int(0 as libc::c_int);
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int(jtmp_2) == 0 as libc::c_int {} else {
        __assert_fail(
            b"json_object_get_int(jtmp) == 0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            32 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_2);
    let mut jtmp_3: *mut json_object = json_object_new_int(0 as libc::c_int);
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int64(jtmp_3) == 0 as libc::c_int as libc::c_long {} else {
        __assert_fail(
            b"json_object_get_int64(jtmp) == 0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            32 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_3);
    let mut jtmp_4: *mut json_object = json_object_new_int(0 as libc::c_int);
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_uint64(jtmp_4) == 0 as libc::c_int as libc::c_ulong {} else {
        __assert_fail(
            b"json_object_get_uint64(jtmp) == 0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            32 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_4);
    let mut jtmp_5: *mut json_object = json_object_new_string(
        b"0\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int(jtmp_5) == 0 as libc::c_int {} else {
        __assert_fail(
            b"json_object_get_int(jtmp) == 0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            33 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_5);
    let mut jtmp_6: *mut json_object = json_object_new_string(
        b"0\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int64(jtmp_6) == 0 as libc::c_int as libc::c_long {} else {
        __assert_fail(
            b"json_object_get_int64(jtmp) == 0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            33 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_6);
    let mut jtmp_7: *mut json_object = json_object_new_string(
        b"0\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_uint64(jtmp_7) == 0 as libc::c_int as libc::c_ulong {} else {
        __assert_fail(
            b"json_object_get_uint64(jtmp) == 0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            33 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_7);
    let mut jtmp_8: *mut json_object = json_object_new_string(
        b"00000\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int(jtmp_8) == 0 as libc::c_int {} else {
        __assert_fail(
            b"json_object_get_int(jtmp) == 0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            34 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_8);
    let mut jtmp_9: *mut json_object = json_object_new_string(
        b"00000\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int64(jtmp_9) == 0 as libc::c_int as libc::c_long {} else {
        __assert_fail(
            b"json_object_get_int64(jtmp) == 0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            34 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_9);
    let mut jtmp_10: *mut json_object = json_object_new_string(
        b"00000\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_uint64(jtmp_10) == 0 as libc::c_int as libc::c_ulong {} else {
        __assert_fail(
            b"json_object_get_uint64(jtmp) == 0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            34 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_10);
    let mut jtmp_11: *mut json_object = json_object_new_string(
        b"000004568789\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int(jtmp_11) == 4568789 as libc::c_int {} else {
        __assert_fail(
            b"json_object_get_int(jtmp) == 4568789\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            35 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_11);
    let mut jtmp_12: *mut json_object = json_object_new_string(
        b"000004568789\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int64(jtmp_12) == 4568789 as libc::c_int as libc::c_long {} else {
        __assert_fail(
            b"json_object_get_int64(jtmp) == 4568789\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            35 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_12);
    let mut jtmp_13: *mut json_object = json_object_new_string(
        b"000004568789\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_uint64(jtmp_13) == 4568789 as libc::c_int as libc::c_ulong
    {} else {
        __assert_fail(
            b"json_object_get_uint64(jtmp) == 4568789\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            35 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_13);
    let mut jtmp_14: *mut json_object = json_object_new_string(
        b"0xFF\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int(jtmp_14) == 0 as libc::c_int
        && *__errno_location() == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int(jtmp) == 0 && (*__errno_location ()) == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            36 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_14);
    let mut jtmp_15: *mut json_object = json_object_new_string(
        b"0xFF\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int64(jtmp_15) == 0 as libc::c_int as libc::c_long
        && *__errno_location() == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int64(jtmp) == 0 && (*__errno_location ()) == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            36 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_15);
    let mut jtmp_16: *mut json_object = json_object_new_string(
        b"0xFF\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_uint64(jtmp_16) == 0 as libc::c_int as libc::c_ulong
        && *__errno_location() == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_uint64(jtmp) == 0 && (*__errno_location ()) == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            36 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_16);
    let mut jtmp_17: *mut json_object = json_object_new_string(
        b"333this_seems_a_valid_string\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int(jtmp_17) == 333 as libc::c_int {} else {
        __assert_fail(
            b"json_object_get_int(jtmp) == 333\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            37 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_17);
    let mut jtmp_18: *mut json_object = json_object_new_string(
        b"333this_seems_a_valid_string\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int64(jtmp_18) == 333 as libc::c_int as libc::c_long {} else {
        __assert_fail(
            b"json_object_get_int64(jtmp) == 333\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            37 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_18);
    let mut jtmp_19: *mut json_object = json_object_new_string(
        b"333this_seems_a_valid_string\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_uint64(jtmp_19) == 333 as libc::c_int as libc::c_ulong {} else {
        __assert_fail(
            b"json_object_get_uint64(jtmp) == 333\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            37 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_19);
    let mut jtmp_20: *mut json_object = json_object_new_string(
        b"this_is_not_a_number\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int(jtmp_20) == 0 as libc::c_int
        && *__errno_location() == 22 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int(jtmp) == 0 && (*__errno_location ()) == 22\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            38 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_20);
    let mut jtmp_21: *mut json_object = json_object_new_string(
        b"this_is_not_a_number\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int64(jtmp_21) == 0 as libc::c_int as libc::c_long
        && *__errno_location() == 22 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int64(jtmp) == 0 && (*__errno_location ()) == 22\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            38 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_21);
    let mut jtmp_22: *mut json_object = json_object_new_string(
        b"this_is_not_a_number\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_uint64(jtmp_22) == 0 as libc::c_int as libc::c_ulong
        && *__errno_location() == 22 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_uint64(jtmp) == 0 && (*__errno_location ()) == 22\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            38 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_22);
    let mut jtmp_23: *mut json_object = json_object_new_string(
        b"B0\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int(jtmp_23) == 0 as libc::c_int
        && *__errno_location() == 22 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int(jtmp) == 0 && (*__errno_location ()) == 22\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            39 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_23);
    let mut jtmp_24: *mut json_object = json_object_new_string(
        b"B0\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int64(jtmp_24) == 0 as libc::c_int as libc::c_long
        && *__errno_location() == 22 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int64(jtmp) == 0 && (*__errno_location ()) == 22\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            39 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_24);
    let mut jtmp_25: *mut json_object = json_object_new_string(
        b"B0\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_uint64(jtmp_25) == 0 as libc::c_int as libc::c_ulong
        && *__errno_location() == 22 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_uint64(jtmp) == 0 && (*__errno_location ()) == 22\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            39 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_25);
    printf(b"BASE CHECK PASSED\n\0" as *const u8 as *const libc::c_char);
    let mut jtmp_26: *mut json_object = json_object_new_int64(
        2147483647 as libc::c_int as int64_t,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int(jtmp_26) == 2147483647 as libc::c_int
        && *__errno_location() == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int(jtmp) == (2147483647) && (*__errno_location ()) == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            42 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_26);
    let mut jtmp_27: *mut json_object = json_object_new_int64(
        (-(2147483647 as libc::c_int) - 1 as libc::c_int) as int64_t,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int(jtmp_27) == -(2147483647 as libc::c_int) - 1 as libc::c_int
        && *__errno_location() == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int(jtmp) == (-2147483647-1) && (*__errno_location ()) == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            43 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_27);
    let mut jtmp_28: *mut json_object = json_object_new_int64(
        9223372036854775807 as libc::c_long,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int(jtmp_28) == 2147483647 as libc::c_int
        && *__errno_location() == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int(jtmp) == (2147483647) && (*__errno_location ()) == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            44 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_28);
    let mut jtmp_29: *mut json_object = json_object_new_int64(
        -(9223372036854775807 as libc::c_long) - 1 as libc::c_int as libc::c_long,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int(jtmp_29) == -(2147483647 as libc::c_int) - 1 as libc::c_int
        && *__errno_location() == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int(jtmp) == (-2147483647-1) && (*__errno_location ()) == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            45 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_29);
    let mut jtmp_30: *mut json_object = json_object_new_string(
        b"9223372036854775807\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int(jtmp_30) == 2147483647 as libc::c_int
        && *__errno_location() == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int(jtmp) == (2147483647) && (*__errno_location ()) == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            46 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_30);
    let mut jtmp_31: *mut json_object = json_object_new_string(
        b"-9223372036854775808\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int(jtmp_31) == -(2147483647 as libc::c_int) - 1 as libc::c_int
        && *__errno_location() == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int(jtmp) == (-2147483647-1) && (*__errno_location ()) == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            47 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_31);
    printf(b"INT GET PASSED\n\0" as *const u8 as *const libc::c_char);
    let mut jtmp_32: *mut json_object = json_object_new_int64(
        9223372036854775807 as libc::c_long,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int64(jtmp_32) == 9223372036854775807 as libc::c_long
        && *__errno_location() == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int64(jtmp) == (9223372036854775807L) && (*__errno_location ()) == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            50 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_32);
    let mut jtmp_33: *mut json_object = json_object_new_int64(
        -(9223372036854775807 as libc::c_long) - 1 as libc::c_int as libc::c_long,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int64(jtmp_33)
        == -(9223372036854775807 as libc::c_long) - 1 as libc::c_int as libc::c_long
        && *__errno_location() == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int64(jtmp) == (-9223372036854775807L-1) && (*__errno_location ()) == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            51 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_33);
    let mut jtmp_34: *mut json_object = json_object_new_string(
        b"9223372036854775807\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int64(jtmp_34) == 9223372036854775807 as libc::c_long
        && *__errno_location() == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int64(jtmp) == (9223372036854775807L) && (*__errno_location ()) == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            52 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_34);
    let mut jtmp_35: *mut json_object = json_object_new_string(
        b"-9223372036854775808\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int64(jtmp_35)
        == -(9223372036854775807 as libc::c_long) - 1 as libc::c_int as libc::c_long
        && *__errno_location() == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int64(jtmp) == (-9223372036854775807L-1) && (*__errno_location ()) == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            53 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_35);
    let mut jtmp_36: *mut json_object = json_object_new_string(
        b"9223372036854775808\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int64(jtmp_36) == 9223372036854775807 as libc::c_long
        && *__errno_location() == 34 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int64(jtmp) == (9223372036854775807L) && (*__errno_location ()) == 34\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            54 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_36);
    let mut jtmp_37: *mut json_object = json_object_new_string(
        b"-9223372036854775809\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_int64(jtmp_37)
        == -(9223372036854775807 as libc::c_long) - 1 as libc::c_int as libc::c_long
        && *__errno_location() == 34 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_int64(jtmp) == (-9223372036854775807L-1) && (*__errno_location ()) == 34\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            55 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_37);
    printf(b"INT64 GET PASSED\n\0" as *const u8 as *const libc::c_char);
    let mut jtmp_38: *mut json_object = json_object_new_uint64(
        18446744073709551615 as libc::c_ulong,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_uint64(jtmp_38) == 18446744073709551615 as libc::c_ulong
        && *__errno_location() == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_uint64(jtmp) == (18446744073709551615UL) && (*__errno_location ()) == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            58 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_38);
    let mut jtmp_39: *mut json_object = json_object_new_uint64(
        -(1 as libc::c_int) as uint64_t,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_uint64(jtmp_39) == 18446744073709551615 as libc::c_ulong
        && *__errno_location() == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_uint64(jtmp) == (18446744073709551615UL) && (*__errno_location ()) == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            59 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_39);
    let mut jtmp_40: *mut json_object = json_object_new_string(
        b"18446744073709551616\0" as *const u8 as *const libc::c_char,
    );
    *__errno_location() = 0 as libc::c_int;
    if json_object_get_uint64(jtmp_40) == 18446744073709551615 as libc::c_ulong
        && *__errno_location() == 34 as libc::c_int
    {} else {
        __assert_fail(
            b"json_object_get_uint64(jtmp) == (18446744073709551615UL) && (*__errno_location ()) == 34\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_int_get.c\0" as *const u8
                as *const libc::c_char,
            60 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jtmp_40);
    printf(b"UINT64 GET PASSED\n\0" as *const u8 as *const libc::c_char);
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
