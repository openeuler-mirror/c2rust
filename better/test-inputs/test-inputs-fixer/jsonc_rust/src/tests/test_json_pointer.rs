
extern "C" {
    pub type json_object;
    fn __assert_fail(
        __assertion: *const i8,
        __file: *const i8,
        __line: u32,
        __function: *const i8,
    ) -> !;
    fn __errno_location() -> *mut i32;
    fn printf(_: *const i8, _: ...) -> i32;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn json_object_put(obj: *mut json_object) -> i32;
    fn json_object_is_type(obj: *const json_object, type_0: json_type) -> i32;
    fn json_object_new_object() -> *mut json_object;
    fn json_object_object_get(obj: *const json_object, key: *const i8) -> *mut json_object;
    fn json_object_new_array() -> *mut json_object;
    fn json_object_array_add(obj: *mut json_object, val: *mut json_object) -> i32;
    fn json_object_array_get_idx(obj: *const json_object, idx: size_t) -> *mut json_object;
    fn json_object_new_int(i: int32_t) -> *mut json_object;
    fn json_object_get_int(obj: *const json_object) -> int32_t;
    fn json_object_new_string(s: *const i8) -> *mut json_object;
    fn json_object_get_string(obj: *mut json_object) -> *const i8;
    fn json_object_equal(obj1: *mut json_object, obj2: *mut json_object) -> i32;
    fn json_pointer_get(obj: *mut json_object, path: *const i8, res: *mut *mut json_object) -> i32;
    fn json_pointer_getf(
        obj: *mut json_object,
        res: *mut *mut json_object,
        path_fmt: *const i8,
        _: ...
    ) -> i32;
    fn json_pointer_set(
        obj: *mut *mut json_object,
        path: *const i8,
        value: *mut json_object,
    ) -> i32;
    fn json_pointer_setf(
        obj: *mut *mut json_object,
        value: *mut json_object,
        path_fmt: *const i8,
        _: ...
    ) -> i32;
    fn json_tokener_parse(str: *const i8) -> *mut json_object;
}
pub type size_t = u64;
pub type __int32_t = i32;
pub type int32_t = __int32_t;
pub type json_type = u32;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_pointer_map_s_i {
    pub s: *const i8,
    pub i: i32,
}
extern "C" fn test_example_int(
    mut jo1: *mut json_object,
    mut json_pointer: *const i8,
    mut expected_int: i32,
) {
    let mut jo2: *mut json_object = 0 as *mut json_object;
    if 0 as i32 == (unsafe { json_pointer_get(jo1, json_pointer, 0 as *mut *mut json_object) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_get(jo1, json_pointer, NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            14 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 63], &[i8; 63]>(
                b"void test_example_int(struct json_object *, const char *, int)\0",
            ))
            .as_ptr(),
        ) });
    }
    if 0 as i32 == (unsafe { json_pointer_get(jo1, json_pointer, &mut jo2) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_get(jo1, json_pointer, &jo2)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            15 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 63], &[i8; 63]>(
                b"void test_example_int(struct json_object *, const char *, int)\0",
            ))
            .as_ptr(),
        ) });
    }
    if (unsafe { json_object_is_type(jo2, json_type_int) }) != 0 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_is_type(jo2, json_type_int)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            16 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 63], &[i8; 63]>(
                b"void test_example_int(struct json_object *, const char *, int)\0",
            ))
            .as_ptr(),
        ) });
    }
    if expected_int == (unsafe { json_object_get_int(jo2) }) {
    } else {
        (unsafe { __assert_fail(
            b"expected_int == json_object_get_int(jo2)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            17 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 63], &[i8; 63]>(
                b"void test_example_int(struct json_object *, const char *, int)\0",
            ))
            .as_ptr(),
        ) });
    }
    (unsafe { printf(
        b"PASSED - GET -  %s == %d\n\0" as *const u8 as *const i8,
        json_pointer,
        expected_int,
    ) });
}
static mut input_json_str : * const i8 = b"{ 'foo': ['bar', 'baz'], '': 0, 'a/b': 1, 'c%d': 2, 'e^f': 3, 'g|h': 4, 'i\\\\j': 5, 'k\\\"l': 6, ' ': 7, 'm~n': 8 }\0" as * const u8 as * const i8 ;
static mut rec_input_json_str : * const i8 = b"{'arr' : [{'obj': [{},{},{'obj1': 0,'obj2': \"1\"}]}],'obj' : {'obj': {'obj': [{'obj1': 0,'obj2': \"1\"}]}}}\0" as * const u8 as * const i8 ;
extern "C" fn test_example_get() {
    let mut i: i32 = 0;
    let mut jo1: *mut json_object = 0 as *mut json_object;
    let mut jo2: *mut json_object = 0 as *mut json_object;
    let mut jo3: *mut json_object = 0 as *mut json_object;
    let mut json_pointers: [json_pointer_map_s_i; 10] = [
        {
            let mut init = json_pointer_map_s_i {
                s: b"/\0" as *const u8 as *const i8,
                i: 0 as i32,
            };
            init
        },
        {
            let mut init = json_pointer_map_s_i {
                s: b"/a~1b\0" as *const u8 as *const i8,
                i: 1 as i32,
            };
            init
        },
        {
            let mut init = json_pointer_map_s_i {
                s: b"/c%d\0" as *const u8 as *const i8,
                i: 2 as i32,
            };
            init
        },
        {
            let mut init = json_pointer_map_s_i {
                s: b"/e^f\0" as *const u8 as *const i8,
                i: 3 as i32,
            };
            init
        },
        {
            let mut init = json_pointer_map_s_i {
                s: b"/g|h\0" as *const u8 as *const i8,
                i: 4 as i32,
            };
            init
        },
        {
            let mut init = json_pointer_map_s_i {
                s: b"/i\\j\0" as *const u8 as *const i8,
                i: 5 as i32,
            };
            init
        },
        {
            let mut init = json_pointer_map_s_i {
                s: b"/k\"l\0" as *const u8 as *const i8,
                i: 6 as i32,
            };
            init
        },
        {
            let mut init = json_pointer_map_s_i {
                s: b"/ \0" as *const u8 as *const i8,
                i: 7 as i32,
            };
            init
        },
        {
            let mut init = json_pointer_map_s_i {
                s: b"/m~0n\0" as *const u8 as *const i8,
                i: 8 as i32,
            };
            init
        },
        {
            let mut init = json_pointer_map_s_i {
                s: 0 as *const i8,
                i: 0 as i32,
            };
            init
        },
    ];
    jo1 = unsafe { json_tokener_parse(input_json_str) };
    if !jo1.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"NULL != jo1\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            88 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - GET - LOADED TEST JSON\n\0" as *const u8 as *const i8) });
    (unsafe { printf(
        b"%s\n\0" as *const u8 as *const i8,
        json_object_get_string(jo1),
    ) });
    jo2 = 0 as *mut json_object;
    if 0 as i32
        == (unsafe { json_pointer_get(
            jo1,
            b"\0" as *const u8 as *const i8,
            0 as *mut *mut json_object,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_get(jo1, \"\", NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            95 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32 == (unsafe { json_pointer_get(jo1, b"\0" as *const u8 as *const i8, &mut jo2) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_get(jo1, \"\", &jo2)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            96 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { json_object_equal(jo2, jo1) }) != 0 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_equal(jo2, jo1)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            97 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - GET - ENTIRE OBJECT WORKED\n\0" as *const u8 as *const i8) });
    jo3 = unsafe { json_object_new_array() };
    (unsafe { json_object_array_add(
        jo3,
        json_object_new_string(b"bar\0" as *const u8 as *const i8),
    ) });
    (unsafe { json_object_array_add(
        jo3,
        json_object_new_string(b"baz\0" as *const u8 as *const i8),
    ) });
    jo2 = 0 as *mut json_object;
    if 0 as i32
        == (unsafe { json_pointer_get(
            jo1,
            b"/foo\0" as *const u8 as *const i8,
            0 as *mut *mut json_object,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_get(jo1, \"/foo\", NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            106 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32 == (unsafe { json_pointer_get(jo1, b"/foo\0" as *const u8 as *const i8, &mut jo2) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_get(jo1, \"/foo\", &jo2)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            107 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if !jo2.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"NULL != jo2\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            108 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { json_object_equal(jo2, jo3) }) != 0 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_equal(jo2, jo3)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            109 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jo3) });
    (unsafe { printf(b"PASSED - GET - /foo == ['bar', 'baz']\n\0" as *const u8 as *const i8) });
    jo2 = 0 as *mut json_object;
    if 0 as i32
        == (unsafe { json_pointer_get(
            jo1,
            b"/foo/0\0" as *const u8 as *const i8,
            0 as *mut *mut json_object,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_get(jo1, \"/foo/0\", NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            115 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32 == (unsafe { json_pointer_get(jo1, b"/foo/0\0" as *const u8 as *const i8, &mut jo2) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_get(jo1, \"/foo/0\", &jo2)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            116 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if !jo2.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"NULL != jo2\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            117 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32
        == (unsafe { strcmp(
            b"bar\0" as *const u8 as *const i8,
            json_object_get_string(jo2),
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == strcmp(\"bar\", json_object_get_string(jo2))\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            118 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - GET - /foo/0 == 'bar'\n\0" as *const u8 as *const i8) });
    i = 0 as i32;
    while !(json_pointers[i as usize].s).is_null() {
        test_example_int(
            jo1,
            json_pointers[i as usize].s,
            json_pointers[i as usize].i,
        );
        i += 1;
    }
    (unsafe { json_object_put(jo1) });
}
extern "C" fn test_recursion_get() {
    let mut jo2: *mut json_object = 0 as *mut json_object;
    let mut jo1: *mut json_object = unsafe { json_tokener_parse(rec_input_json_str) };
    jo2 = 0 as *mut json_object;
    if !jo1.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"jo1 != NULL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            133 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 30], &[i8; 30]>(b"void test_recursion_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(
        b"%s\n\0" as *const u8 as *const i8,
        json_object_get_string(jo1),
    ) });
    if 0 as i32
        == (unsafe { json_pointer_get(
            jo1,
            b"/arr/0/obj/2/obj1\0" as *const u8 as *const i8,
            &mut jo2,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_get(jo1, \"/arr/0/obj/2/obj1\", &jo2)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            135 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 30], &[i8; 30]>(b"void test_recursion_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { json_object_is_type(jo2, json_type_int) }) != 0 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_is_type(jo2, json_type_int)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            136 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 30], &[i8; 30]>(b"void test_recursion_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32 == (unsafe { json_object_get_int(jo2) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_object_get_int(jo2)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            137 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 30], &[i8; 30]>(b"void test_recursion_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32
        == (unsafe { json_pointer_get(
            jo1,
            b"/arr/0/obj/2/obj2\0" as *const u8 as *const i8,
            &mut jo2,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_get(jo1, \"/arr/0/obj/2/obj2\", &jo2)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            139 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 30], &[i8; 30]>(b"void test_recursion_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { json_object_is_type(jo2, json_type_string) }) != 0 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_is_type(jo2, json_type_string)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            140 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 30], &[i8; 30]>(b"void test_recursion_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32
        == (unsafe { strcmp(
            b"1\0" as *const u8 as *const i8,
            json_object_get_string(jo2),
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == strcmp(\"1\", json_object_get_string(jo2))\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            141 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 30], &[i8; 30]>(b"void test_recursion_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32
        == (unsafe { json_pointer_getf(
            jo1,
            &mut jo2 as *mut *mut json_object,
            b"/%s/%d/%s/%d/%s\0" as *const u8 as *const i8,
            b"arr\0" as *const u8 as *const i8,
            0 as i32,
            b"obj\0" as *const u8 as *const i8,
            2 as i32,
            b"obj2\0" as *const u8 as *const i8,
        ) })
    {
    } else {
        (unsafe { __assert_fail (b"0 == json_pointer_getf(jo1, &jo2, \"/%s/%d/%s/%d/%s\", \"arr\", 0, \"obj\", 2, \"obj2\")\0" as * const u8 as * const i8 , b"/home/xial/json-c/tests/test_json_pointer.c\0" as * const u8 as * const i8 , 143 as i32 as u32 , (* :: std :: mem :: transmute :: < & [u8 ; 30] , & [i8 ; 30] , > (b"void test_recursion_get(void)\0")) . as_ptr () ,) }) ;
    }
    if (unsafe { json_object_is_type(jo2, json_type_string) }) != 0 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_is_type(jo2, json_type_string)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            144 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 30], &[i8; 30]>(b"void test_recursion_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32
        == (unsafe { strcmp(
            b"1\0" as *const u8 as *const i8,
            json_object_get_string(jo2),
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == strcmp(\"1\", json_object_get_string(jo2))\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            145 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 30], &[i8; 30]>(b"void test_recursion_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if !jo1.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"jo1 != NULL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            147 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 30], &[i8; 30]>(b"void test_recursion_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32
        == (unsafe { json_pointer_get(
            jo1,
            b"/obj/obj/obj/0/obj1\0" as *const u8 as *const i8,
            &mut jo2,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_get(jo1, \"/obj/obj/obj/0/obj1\", &jo2)\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            148 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 30], &[i8; 30]>(b"void test_recursion_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { json_object_is_type(jo2, json_type_int) }) != 0 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_is_type(jo2, json_type_int)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            149 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 30], &[i8; 30]>(b"void test_recursion_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32 == (unsafe { json_object_get_int(jo2) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_object_get_int(jo2)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            150 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 30], &[i8; 30]>(b"void test_recursion_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32
        == (unsafe { json_pointer_get(
            jo1,
            b"/obj/obj/obj/0/obj2\0" as *const u8 as *const i8,
            &mut jo2,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_get(jo1, \"/obj/obj/obj/0/obj2\", &jo2)\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            152 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 30], &[i8; 30]>(b"void test_recursion_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { json_object_is_type(jo2, json_type_string) }) != 0 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_is_type(jo2, json_type_string)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            153 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 30], &[i8; 30]>(b"void test_recursion_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32
        == (unsafe { strcmp(
            b"1\0" as *const u8 as *const i8,
            json_object_get_string(jo2),
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == strcmp(\"1\", json_object_get_string(jo2))\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            154 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 30], &[i8; 30]>(b"void test_recursion_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32
        == (unsafe { json_pointer_getf(
            jo1,
            &mut jo2 as *mut *mut json_object,
            b"%s\0" as *const u8 as *const i8,
            b"\0\0" as *const u8 as *const i8,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_getf(jo1, &jo2, \"%s\", \"\\0\")\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            156 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 30], &[i8; 30]>(b"void test_recursion_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - GET - RECURSION TEST\n\0" as *const u8 as *const i8) });
    (unsafe { json_object_put(jo1) });
}
extern "C" fn test_wrong_inputs_get() {
    let mut jo2: *mut json_object = 0 as *mut json_object;
    let mut jo1: *mut json_object = unsafe { json_tokener_parse(input_json_str) };
    if !jo1.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"NULL != jo1\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            167 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - GET - LOADED TEST JSON\n\0" as *const u8 as *const i8) });
    (unsafe { printf(
        b"%s\n\0" as *const u8 as *const i8,
        json_object_get_string(jo1),
    ) });
    jo2 = 0 as *mut json_object;
    (unsafe { *__errno_location() = 0 as i32 });
    if 0 as i32
        != (unsafe { json_pointer_get(
            jo1,
            b"foo/bar\0" as *const u8 as *const i8,
            0 as *mut *mut json_object,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_get(jo1, \"foo/bar\", NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            174 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32 != (unsafe { json_pointer_get(jo1, b"foo/bar\0" as *const u8 as *const i8, &mut jo2) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_get(jo1, \"foo/bar\", &jo2)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            175 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            176 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if jo2.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"jo2 == NULL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            177 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - GET - MISSING /\n\0" as *const u8 as *const i8) });
    (unsafe { *__errno_location() = 0 as i32 });
    if 0 as i32
        != (unsafe { json_pointer_get(
            0 as *mut json_object,
            b"foo/bar\0" as *const u8 as *const i8,
            0 as *mut *mut json_object,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_get(NULL, \"foo/bar\", NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            182 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            183 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { *__errno_location() = 0 as i32 });
    if 0 as i32
        != (unsafe { json_pointer_get(
            0 as *mut json_object,
            0 as *const i8,
            0 as *mut *mut json_object,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_get(NULL, NULL, NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            185 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            186 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { *__errno_location() = 0 as i32 });
    if 0 as i32
        != (unsafe { json_pointer_getf(
            0 as *mut json_object,
            0 as *mut *mut json_object,
            0 as *const i8,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_getf(NULL, NULL, NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            188 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            189 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { *__errno_location() = 0 as i32 });
    if 0 as i32 != (unsafe { json_pointer_get(jo1, 0 as *const i8, 0 as *mut *mut json_object) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_get(jo1, NULL, NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            191 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            192 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { *__errno_location() = 0 as i32 });
    if 0 as i32 != (unsafe { json_pointer_getf(jo1, 0 as *mut *mut json_object, 0 as *const i8) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_getf(jo1, NULL, NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            194 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            195 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - GET - NULL INPUTS\n\0" as *const u8 as *const i8) });
    (unsafe { *__errno_location() = 0 as i32 });
    if 0 as i32
        != (unsafe { json_pointer_get(
            jo1,
            b"/foo/a\0" as *const u8 as *const i8,
            0 as *mut *mut json_object,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_get(jo1, \"/foo/a\", NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            200 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            201 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { *__errno_location() = 0 as i32 });
    if 0 as i32
        != (unsafe { json_pointer_get(
            jo1,
            b"/foo/01\0" as *const u8 as *const i8,
            0 as *mut *mut json_object,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_get(jo1, \"/foo/01\", NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            203 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            204 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { *__errno_location() = 0 as i32 });
    if 0 as i32
        != (unsafe { json_pointer_getf(
            jo1,
            0 as *mut *mut json_object,
            b"/%s/a\0" as *const u8 as *const i8,
            b"foo\0" as *const u8 as *const i8,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_getf(jo1, NULL, \"/%s/a\", \"foo\")\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            206 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            207 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { *__errno_location() = 0 as i32 });
    if 0 as i32
        != (unsafe { json_pointer_get(
            jo1,
            b"/foo/-\0" as *const u8 as *const i8,
            0 as *mut *mut json_object,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_get(jo1, \"/foo/-\", NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            209 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            210 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { *__errno_location() = 0 as i32 });
    if 0 as i32
        != (unsafe { json_pointer_get(
            jo1,
            b"/foo/4\0" as *const u8 as *const i8,
            0 as *mut *mut json_object,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_get(jo1, \"/foo/4\", NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            213 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 2 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == ENOENT\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            214 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { *__errno_location() = 0 as i32 });
    if 0 as i32
        != (unsafe { json_pointer_getf(
            jo1,
            0 as *mut *mut json_object,
            b"%s\0" as *const u8 as *const i8,
            b"/foo/22\0" as *const u8 as *const i8,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_getf(jo1, NULL, \"%s\", \"/foo/22\")\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            217 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 2 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == ENOENT\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            218 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { *__errno_location() = 0 as i32 });
    if 0 as i32
        != (unsafe { json_pointer_getf(
            jo1,
            0 as *mut *mut json_object,
            b"/%s/%d\0" as *const u8 as *const i8,
            b"foo\0" as *const u8 as *const i8,
            22 as i32,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_getf(jo1, NULL, \"/%s/%d\", \"foo\", 22)\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            220 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 2 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == ENOENT\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            221 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { *__errno_location() = 0 as i32 });
    if 0 as i32
        != (unsafe { json_pointer_get(
            jo1,
            b"/foo/-1\0" as *const u8 as *const i8,
            0 as *mut *mut json_object,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_get(jo1, \"/foo/-1\", NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            223 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            224 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { *__errno_location() = 0 as i32 });
    if 0 as i32
        != (unsafe { json_pointer_get(
            jo1,
            b"/foo/10\0" as *const u8 as *const i8,
            0 as *mut *mut json_object,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_get(jo1, \"/foo/10\", NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            226 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 2 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == ENOENT\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            227 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_get(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - GET - INVALID INDEXES\n\0" as *const u8 as *const i8) });
    (unsafe { json_object_put(jo1) });
}
extern "C" fn test_example_set() {
    let mut jo2: *mut json_object = 0 as *mut json_object;
    let mut jo1: *mut json_object = unsafe { json_tokener_parse(input_json_str) };
    if !jo1.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"jo1 != NULL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            237 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_set(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - SET - LOADED TEST JSON\n\0" as *const u8 as *const i8) });
    (unsafe { printf(
        b"%s\n\0" as *const u8 as *const i8,
        json_object_get_string(jo1),
    ) });
    if 0 as i32
        == (unsafe { json_pointer_set(
            &mut jo1,
            b"/foo/1\0" as *const u8 as *const i8,
            json_object_new_string(b"cod\0" as *const u8 as *const i8),
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_set(&jo1, \"/foo/1\", json_object_new_string(\"cod\"))\0"
                as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            241 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_set(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32
        == (unsafe { strcmp(
            b"cod\0" as *const u8 as *const i8,
            json_object_get_string(json_object_array_get_idx(
                json_object_object_get(jo1, b"foo\0" as *const u8 as *const i8),
                1 as i32 as size_t,
            )),
        ) })
    {
    } else {
        (unsafe { __assert_fail (b"0 == strcmp(\"cod\", json_object_get_string(json_object_array_get_idx( json_object_object_get(jo1, \"foo\"), 1)))\0" as * const u8 as * const i8 , b"/home/xial/json-c/tests/test_json_pointer.c\0" as * const u8 as * const i8 , 243 as i32 as u32 , (* :: std :: mem :: transmute :: < & [u8 ; 28] , & [i8 ; 28] , > (b"void test_example_set(void)\0")) . as_ptr () ,) }) ;
    }
    (unsafe { printf(b"PASSED - SET - 'cod' in /foo/1\n\0" as *const u8 as *const i8) });
    jo2 = unsafe { json_tokener_parse(b"[1,2,3]\0" as *const u8 as *const i8) };
    if 0 as i32 != (unsafe { json_pointer_set(&mut jo1, b"/fud/gaw\0" as *const u8 as *const i8, jo2) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_set(&jo1, \"/fud/gaw\", (jo2 = json_tokener_parse(\"[1,2,3]\")))\0"
                as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            245 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_set(void)\0"))
                .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 2 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == ENOENT\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            246 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_set(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - SET - non-existing /fud/gaw\n\0" as *const u8 as *const i8) });
    if 0 as i32
        == (unsafe { json_pointer_set(
            &mut jo1,
            b"/fud\0" as *const u8 as *const i8,
            json_object_new_object(),
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_set(&jo1, \"/fud\", json_object_new_object())\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            248 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_set(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - SET - /fud == {}\n\0" as *const u8 as *const i8) });
    if 0 as i32 == (unsafe { json_pointer_set(&mut jo1, b"/fud/gaw\0" as *const u8 as *const i8, jo2) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_set(&jo1, \"/fud/gaw\", jo2)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            250 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_set(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - SET - /fug/gaw == [1,2,3]\n\0" as *const u8 as *const i8) });
    if 0 as i32
        == (unsafe { json_pointer_set(
            &mut jo1,
            b"/fud/gaw/0\0" as *const u8 as *const i8,
            json_object_new_int(0 as i32),
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_set(&jo1, \"/fud/gaw/0\", json_object_new_int(0))\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            252 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_set(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32
        == (unsafe { json_pointer_setf(
            &mut jo1 as *mut *mut json_object,
            json_object_new_int(0 as i32),
            b"%s%s/%d\0" as *const u8 as *const i8,
            b"/fud\0" as *const u8 as *const i8,
            b"/gaw\0" as *const u8 as *const i8,
            0 as i32,
        ) })
    {
    } else {
        (unsafe { __assert_fail (b"0 == json_pointer_setf(&jo1, json_object_new_int(0), \"%s%s/%d\", \"/fud\", \"/gaw\", 0)\0" as * const u8 as * const i8 , b"/home/xial/json-c/tests/test_json_pointer.c\0" as * const u8 as * const i8 , 253 as i32 as u32 , (* :: std :: mem :: transmute :: < & [u8 ; 28] , & [i8 ; 28] , > (b"void test_example_set(void)\0")) . as_ptr () ,) }) ;
    }
    (unsafe { printf(b"PASSED - SET - /fug/gaw == [0,2,3]\n\0" as *const u8 as *const i8) });
    if 0 as i32
        == (unsafe { json_pointer_set(
            &mut jo1,
            b"/fud/gaw/-\0" as *const u8 as *const i8,
            json_object_new_int(4 as i32),
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_set(&jo1, \"/fud/gaw/-\", json_object_new_int(4))\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            255 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_set(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - SET - /fug/gaw == [0,2,3,4]\n\0" as *const u8 as *const i8) });
    if 0 as i32
        == (unsafe { json_pointer_set(
            &mut jo1,
            b"/\0" as *const u8 as *const i8,
            json_object_new_int(9 as i32),
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_set(&jo1, \"/\", json_object_new_int(9))\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            257 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_set(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - SET - / == 9\n\0" as *const u8 as *const i8) });
    jo2 = unsafe { json_tokener_parse (b"{ 'foo': [ 'bar', 'cod' ], '': 9, 'a/b': 1, 'c%d': 2, 'e^f': 3, 'g|h': 4, 'i\\\\j': 5, 'k\\\"l': 6, ' ': 7, 'm~n': 8, 'fud': { 'gaw': [ 0, 2, 3, 4 ] } }\0" as * const u8 as * const i8 ,) } ;
    if (unsafe { json_object_equal(jo2, jo1) }) != 0 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_equal(jo2, jo1)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            263 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_set(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(
        b"PASSED - SET - Final JSON is: %s\n\0" as *const u8 as *const i8,
        json_object_get_string(jo1),
    ) });
    (unsafe { json_object_put(jo2) });
    if 0 as i32
        == (unsafe { json_pointer_set(
            &mut jo1,
            b"\0" as *const u8 as *const i8,
            json_object_new_int(10 as i32),
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_set(&jo1, \"\", json_object_new_int(10))\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            267 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_set(void)\0"))
                .as_ptr(),
        ) });
    }
    if 10 as i32 == (unsafe { json_object_get_int(jo1) }) {
    } else {
        (unsafe { __assert_fail(
            b"10 == json_object_get_int(jo1)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            268 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_example_set(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(
        b"%s\n\0" as *const u8 as *const i8,
        json_object_get_string(jo1),
    ) });
    (unsafe { json_object_put(jo1) });
}
extern "C" fn test_wrong_inputs_set() {
    let mut jo2: *mut json_object = 0 as *mut json_object;
    let mut jo1: *mut json_object = unsafe { json_tokener_parse(input_json_str) };
    if !jo1.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"jo1 != NULL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            278 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_set(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - SET - LOADED TEST JSON\n\0" as *const u8 as *const i8) });
    (unsafe { printf(
        b"%s\n\0" as *const u8 as *const i8,
        json_object_get_string(jo1),
    ) });
    if 0 as i32
        != (unsafe { json_pointer_set(
            0 as *mut *mut json_object,
            0 as *const i8,
            0 as *mut json_object,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_set(NULL, NULL, NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            282 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_set(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32
        != (unsafe { json_pointer_setf(
            0 as *mut *mut json_object,
            0 as *mut json_object,
            0 as *const i8,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_setf(NULL, NULL, NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            283 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_set(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32 != (unsafe { json_pointer_set(&mut jo1, 0 as *const i8, 0 as *mut json_object) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_set(&jo1, NULL, NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            284 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_set(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32
        != (unsafe { json_pointer_setf(
            &mut jo1 as *mut *mut json_object,
            0 as *mut json_object,
            0 as *const i8,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_setf(&jo1, NULL, NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            285 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_set(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(
        b"PASSED - SET - failed with NULL params for input json & path\n\0" as *const u8
            as *const i8,
    ) });
    jo2 = unsafe { json_object_new_string(b"cod\0" as *const u8 as *const i8) };
    if 0 as i32 != (unsafe { json_pointer_set(&mut jo1, b"foo/bar\0" as *const u8 as *const i8, jo2) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_set(&jo1, \"foo/bar\", (jo2 = json_object_new_string(\"cod\")))\0"
                as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            288 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_set(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - SET - failed 'cod' with path 'foo/bar'\n\0" as *const u8 as *const i8) });
    (unsafe { json_object_put(jo2) });
    jo2 = unsafe { json_object_new_string(b"cod\0" as *const u8 as *const i8) };
    if 0 as i32
        != (unsafe { json_pointer_setf(
            &mut jo1 as *mut *mut json_object,
            jo2,
            b"%s\0" as *const u8 as *const i8,
            b"foo/bar\0" as *const u8 as *const i8,
        ) })
    {
    } else {
        (unsafe { __assert_fail (b"0 != json_pointer_setf(&jo1, (jo2 = json_object_new_string(\"cod\")), \"%s\", \"foo/bar\")\0" as * const u8 as * const i8 , b"/home/xial/json-c/tests/test_json_pointer.c\0" as * const u8 as * const i8 , 293 as i32 as u32 , (* :: std :: mem :: transmute :: < & [u8 ; 33] , & [i8 ; 33] , > (b"void test_wrong_inputs_set(void)\0")) . as_ptr () ,) }) ;
    }
    (unsafe { printf(b"PASSED - SET - failed 'cod' with path 'foo/bar'\n\0" as *const u8 as *const i8) });
    (unsafe { json_object_put(jo2) });
    jo2 = unsafe { json_object_new_string(b"cod\0" as *const u8 as *const i8) };
    if 0 as i32 != (unsafe { json_pointer_set(&mut jo1, b"0\0" as *const u8 as *const i8, jo2) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_set(&jo1, \"0\", (jo2 = json_object_new_string(\"cod\")))\0"
                as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            297 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_set(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - SET - failed with invalid array index'\n\0" as *const u8 as *const i8) });
    (unsafe { json_object_put(jo2) });
    jo2 = unsafe { json_object_new_string(b"whatever\0" as *const u8 as *const i8) };
    if 0 as i32 != (unsafe { json_pointer_set(&mut jo1, b"/fud/gaw\0" as *const u8 as *const i8, jo2) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_set(&jo1, \"/fud/gaw\", jo2)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            302 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_set(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32
        == (unsafe { json_pointer_set(
            &mut jo1,
            b"/fud\0" as *const u8 as *const i8,
            json_object_new_object(),
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_set(&jo1, \"/fud\", json_object_new_object())\0" as *const u8
                as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            303 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_set(void)\0"))
                .as_ptr(),
        ) });
    }
    if 0 as i32 == (unsafe { json_pointer_set(&mut jo1, b"/fud/gaw\0" as *const u8 as *const i8, jo2) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_set(&jo1, \"/fud/gaw\", jo2)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            304 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_set(void)\0"))
                .as_ptr(),
        ) });
    }
    jo2 = unsafe { json_object_new_int(0 as i32) };
    if 0 as i32 != (unsafe { json_pointer_set(&mut jo1, b"/fud/gaw/0\0" as *const u8 as *const i8, jo2) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_set(&jo1, \"/fud/gaw/0\", jo2)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            308 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_set(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jo2) });
    jo2 = unsafe { json_object_new_int(0 as i32) };
    if 0 as i32 != (unsafe { json_pointer_set(&mut jo1, b"/fud/gaw/\0" as *const u8 as *const i8, jo2) }) {
    } else {
        (unsafe { __assert_fail(
            b"0 != json_pointer_set(&jo1, \"/fud/gaw/\", jo2)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            311 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_set(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jo2) });
    (unsafe { printf(b"PASSED - SET - failed to set index to non-array\n\0" as *const u8 as *const i8) });
    if 0 as i32
        == (unsafe { json_pointer_setf(
            &mut jo1 as *mut *mut json_object,
            json_object_new_string(b"cod\0" as *const u8 as *const i8),
            b"%s\0" as *const u8 as *const i8,
            b"\0\0" as *const u8 as *const i8,
        ) })
    {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_pointer_setf(&jo1, json_object_new_string(\"cod\"), \"%s\", \"\\0\")\0"
                as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_json_pointer.c\0" as *const u8 as *const i8,
            315 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 33], &[i8; 33]>(b"void test_wrong_inputs_set(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jo1) });
}
fn main_0(mut _argc: i32, mut _argv: *mut *mut i8) -> i32 {
    test_example_get();
    test_recursion_get();
    test_wrong_inputs_get();
    test_example_set();
    test_wrong_inputs_set();
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
