use :: libc;
extern "C" {
    fn printf(_: *const i8, _: ...) -> i32;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn __assert_fail(
        __assertion: *const i8,
        __file: *const i8,
        __line: u32,
        __function: *const i8,
    ) -> !;
    fn __errno_location() -> *mut i32;
    fn time(__timer: *mut i64) -> i64;
}
pub use crate::src::{
    json_object::{
        json_c_shallow_copy_default, json_object, json_object_deep_copy, json_object_equal,
        json_object_get, json_object_get_string, json_object_get_userdata, json_object_new_string,
        json_object_object_add, json_object_object_get, json_object_put,
        json_object_set_serializer, json_object_to_json_string, json_object_to_json_string_ext,
    },
    json_tokener::json_tokener_parse,
    printbuf::sprintbuf,
};
pub type size_t = u64;
pub type __time_t = i64;
pub type time_t = i64;
pub type printbuf = crate::src::apps::json_parse::printbuf;
pub type json_object_delete_fn = unsafe extern "C" fn(
    _: *mut crate::src::json_object::json_object,
    _: *mut core::ffi::c_void,
) -> ();
pub type json_object_to_json_string_fn = unsafe extern "C" fn(
    _: *mut crate::src::json_object::json_object,
    _: *mut crate::src::apps::json_parse::printbuf,
    _: i32,
    _: i32,
) -> i32;
pub type json_c_shallow_copy_fn = unsafe extern "C" fn(
    _: *mut crate::src::json_object::json_object,
    _: *mut crate::src::json_object::json_object,
    _: *const i8,
    _: u64,
    _: *mut *mut crate::src::json_object::json_object,
) -> i32;
static mut json_str1 : * const i8 = b"{    \"glossary\": {        \"title\": \"example glossary\",        \"GlossDiv\": {            \"number\": 16446744073709551615,            \"title\": \"S\",            \"null_obj\": null,             \"exist\": false,            \"quantity\":20,            \"univalent\":19.8,            \"GlossList\": {                \"GlossEntry\": {                    \"ID\": \"SGML\",                    \"SortAs\": \"SGML\",                    \"GlossTerm\": \"Standard Generalized Markup Language\",                    \"Acronym\": \"SGML\",                    \"Abbrev\": \"ISO 8879:1986\",                    \"GlossDef\": {                        \"para\": \"A meta-markup language, used to create markup languages such as DocBook.\",                        \"GlossSeeAlso\": [\"GML\", \"XML\"]                    },                    \"GlossSee\": \"markup\"                }            }        }    }}\0" as * const u8 as * const i8 ;
static mut json_str2 : * const i8 = b"{\"menu\": {    \"header\": \"SVG Viewer\",    \"items\": [        {\"id\": \"Open\"},        {\"id\": \"OpenNew\", \"label\": \"Open New\"},        null,        {\"id\": \"ZoomIn\", \"label\": \"Zoom In\"},        {\"id\": \"ZoomOut\", \"label\": \"Zoom Out\"},        {\"id\": \"OriginalView\", \"label\": \"Original View\"},        null,        {\"id\": \"Quality\", \"another_null\": null},        {\"id\": \"Pause\"},        {\"id\": \"Mute\"},        null,        {\"id\": \"Find\", \"label\": \"Find...\"},        {\"id\": \"FindAgain\", \"label\": \"Find Again\"},        {\"id\": \"Copy\"},        {\"id\": \"CopyAgain\", \"label\": \"Copy Again\"},        {\"id\": \"CopySVG\", \"label\": \"Copy SVG\"},        {\"id\": \"ViewSVG\", \"label\": \"View SVG\"},        {\"id\": \"ViewSource\", \"label\": \"View Source\"},        {\"id\": \"SaveAs\", \"label\": \"Save As\"},        null,        {\"id\": \"Help\"},        {\"id\": \"About\", \"label\": \"About Adobe CVG Viewer...\"}    ]}}\0" as * const u8 as * const i8 ;
static mut json_str3 : * const i8 = b"{\"menu\": {  \"id\": \"file\",  \"value\": \"File\",  \"popup\": {    \"menuitem\": [      {\"value\": \"New\", \"onclick\": \"CreateNewDoc()\"},      {\"value\": \"Open\", \"onclick\": \"OpenDoc()\"},      {\"value\": \"Close\", \"onclick\": \"CloseDoc()\"}    ]  }}}\0" as * const u8 as * const i8 ;
#[no_mangle]
pub extern "C" fn my_custom_serializer(
    mut _jso: *mut crate::src::json_object::json_object,
    mut pb: *mut crate::src::apps::json_parse::printbuf,
    mut _level: i32,
    mut _flags: i32,
) -> i32 {
    (unsafe { sprintbuf(pb, b"OTHER\0" as *const u8 as *const i8) });
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn my_shallow_copy(
    mut src: *mut crate::src::json_object::json_object,
    mut parent: *mut crate::src::json_object::json_object,
    mut key: *const i8,
    mut index: u64,
    mut dst: *mut *mut crate::src::json_object::json_object,
) -> i32 {
    let mut rc: i32 = 0;
    rc = json_c_shallow_copy_default(src, parent, key, index, dst);
    if rc < 0 as i32 {
        return rc;
    }
    if !key.is_null() && (unsafe { strcmp(key, b"with_serializer\0" as *const u8 as *const i8) }) == 0 as i32 {
        (unsafe { printf(b"CALLED: my_shallow_copy on with_serializer object\n\0" as *const u8 as *const i8) });
        let mut userdata: *mut core::ffi::c_void = json_object_get_userdata(src);
        json_object_set_serializer(unsafe { *dst }, Some(my_custom_serializer), userdata, None);
        return 2 as i32;
    }
    return rc;
}
fn main_0(mut argc: i32, mut argv: *mut *mut i8) -> i32 {
    let mut src1: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut src2: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut src3: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut dst1: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut dst2: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut dst3: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut benchmark: i32 = 0 as i32;
    if argc > 1 as i32
        && (unsafe { strcmp(
            *argv.offset(1 as i32 as isize),
            b"--benchmark\0" as *const u8 as *const i8,
        ) }) == 0 as i32
    {
        benchmark = 1 as i32;
    }
    src1 = json_tokener_parse(unsafe { json_str1 });
    src2 = json_tokener_parse(unsafe { json_str2 });
    src3 = json_tokener_parse(unsafe { json_str3 });
    if !src1.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"src1 != NULL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            128 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if !src2.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"src2 != NULL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            129 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if !src3.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"src3 != NULL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            130 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    (unsafe { printf(b"PASSED - loaded input data\n\0" as *const u8 as *const i8) });
    if 0 as i32 == json_object_deep_copy(src1, &mut dst1, None) {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_object_deep_copy(src1, &dst1, NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            135 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if 0 as i32 == json_object_deep_copy(src2, &mut dst2, None) {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_object_deep_copy(src2, &dst2, NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            136 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if 0 as i32 == json_object_deep_copy(src3, &mut dst3, None) {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_object_deep_copy(src3, &dst3, NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            137 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    (unsafe { printf(
        b"PASSED - all json_object_deep_copy() returned successful\n\0" as *const u8 as *const i8,
    ) });
    if -(1 as i32) == json_object_deep_copy(src1, &mut dst1, None) {
    } else {
        (unsafe { __assert_fail(
            b"-1 == json_object_deep_copy(src1, &dst1, NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            141 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            142 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if -(1 as i32) == json_object_deep_copy(src2, &mut dst2, None) {
    } else {
        (unsafe { __assert_fail(
            b"-1 == json_object_deep_copy(src2, &dst2, NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            143 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            144 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if -(1 as i32) == json_object_deep_copy(src3, &mut dst3, None) {
    } else {
        (unsafe { __assert_fail(
            b"-1 == json_object_deep_copy(src3, &dst3, NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            145 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            146 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    (unsafe { printf(
        b"PASSED - all json_object_deep_copy() returned EINVAL for non-null pointer\n\0"
            as *const u8 as *const i8,
    ) });
    if 1 as i32 == json_object_equal(src1, dst1) {
    } else {
        (unsafe { __assert_fail(
            b"1 == json_object_equal(src1, dst1)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            150 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if 1 as i32 == json_object_equal(src2, dst2) {
    } else {
        (unsafe { __assert_fail(
            b"1 == json_object_equal(src2, dst2)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            151 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if 1 as i32 == json_object_equal(src3, dst3) {
    } else {
        (unsafe { __assert_fail(
            b"1 == json_object_equal(src3, dst3)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            152 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    (unsafe { printf(
        b"PASSED - all json_object_equal() tests returned successful\n\0" as *const u8 as *const i8,
    ) });
    if 0 as i32
        == (unsafe { strcmp(
            json_object_to_json_string_ext(src1, (1 as i32) << 1 as i32),
            json_object_to_json_string_ext(dst1, (1 as i32) << 1 as i32),
        ) })
    {
    } else {
        (unsafe { __assert_fail (b"0 == strcmp(json_object_to_json_string_ext(src1, JSON_C_TO_STRING_PRETTY), json_object_to_json_string_ext(dst1, JSON_C_TO_STRING_PRETTY))\0" as * const u8 as * const i8 , b"/home/xial/json-c/tests/test_deep_copy.c\0" as * const u8 as * const i8 , 157 as i32 as u32 , (* core :: intrinsics :: transmute :: < & '_ [u8 ; 23] , & '_ [i8 ; 23] > (b"int main(int, char **)\0")) . as_ptr () ,) }) ;
    }
    if 0 as i32
        == (unsafe { strcmp(
            json_object_to_json_string_ext(src2, (1 as i32) << 1 as i32),
            json_object_to_json_string_ext(dst2, (1 as i32) << 1 as i32),
        ) })
    {
    } else {
        (unsafe { __assert_fail (b"0 == strcmp(json_object_to_json_string_ext(src2, JSON_C_TO_STRING_PRETTY), json_object_to_json_string_ext(dst2, JSON_C_TO_STRING_PRETTY))\0" as * const u8 as * const i8 , b"/home/xial/json-c/tests/test_deep_copy.c\0" as * const u8 as * const i8 , 159 as i32 as u32 , (* core :: intrinsics :: transmute :: < & '_ [u8 ; 23] , & '_ [i8 ; 23] > (b"int main(int, char **)\0")) . as_ptr () ,) }) ;
    }
    if 0 as i32
        == (unsafe { strcmp(
            json_object_to_json_string_ext(src3, (1 as i32) << 1 as i32),
            json_object_to_json_string_ext(dst3, (1 as i32) << 1 as i32),
        ) })
    {
    } else {
        (unsafe { __assert_fail (b"0 == strcmp(json_object_to_json_string_ext(src3, JSON_C_TO_STRING_PRETTY), json_object_to_json_string_ext(dst3, JSON_C_TO_STRING_PRETTY))\0" as * const u8 as * const i8 , b"/home/xial/json-c/tests/test_deep_copy.c\0" as * const u8 as * const i8 , 161 as i32 as u32 , (* core :: intrinsics :: transmute :: < & '_ [u8 ; 23] , & '_ [i8 ; 23] > (b"int main(int, char **)\0")) . as_ptr () ,) }) ;
    }
    (unsafe { printf(b"PASSED - comparison of string output\n\0" as *const u8 as *const i8) });
    json_object_get(dst1);
    if -(1 as i32) == json_object_deep_copy(src1, &mut dst1, None) {
    } else {
        (unsafe { __assert_fail(
            b"-1 == json_object_deep_copy(src1, &dst1, NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            166 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if (unsafe { *__errno_location() }) == 22 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            167 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    json_object_put(dst1);
    (unsafe { printf(
        b"PASSED - trying to overrwrite an object that has refcount > 1\0" as *const u8
            as *const i8,
    ) });
    (unsafe { printf(b"\nPrinting JSON objects for visual inspection\n\0" as *const u8 as *const i8) });
    (unsafe { printf(b"------------------------------------------------\n\0" as *const u8 as *const i8) });
    (unsafe { printf(b" JSON1\n\0" as *const u8 as *const i8) });
    (unsafe { printf(
        b"%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string_ext(dst1, (1 as i32) << 1 as i32),
    ) });
    (unsafe { printf(b"------------------------------------------------\n\0" as *const u8 as *const i8) });
    (unsafe { printf(b"------------------------------------------------\n\0" as *const u8 as *const i8) });
    (unsafe { printf(b" JSON2\n\0" as *const u8 as *const i8) });
    (unsafe { printf(
        b"%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string_ext(dst2, (1 as i32) << 1 as i32),
    ) });
    (unsafe { printf(b"------------------------------------------------\n\0" as *const u8 as *const i8) });
    (unsafe { printf(b"------------------------------------------------\n\0" as *const u8 as *const i8) });
    (unsafe { printf(b" JSON3\n\0" as *const u8 as *const i8) });
    (unsafe { printf(b"------------------------------------------------\n\0" as *const u8 as *const i8) });
    (unsafe { printf(
        b"%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string_ext(dst3, (1 as i32) << 1 as i32),
    ) });
    (unsafe { printf(b"------------------------------------------------\n\0" as *const u8 as *const i8) });
    json_object_put(dst1);
    json_object_put(dst2);
    json_object_put(dst3);
    (unsafe { printf(b"\nTesting deep_copy with a custom serializer set\n\0" as *const u8 as *const i8) });
    let mut with_serializer: *mut crate::src::json_object::json_object =
        json_object_new_string(b"notemitted\0" as *const u8 as *const i8);
    let mut udata: [i8; 15] =
        *(unsafe { core::intrinsics::transmute::<&'_ [u8; 15], &'_ mut [i8; 15]>(b"dummy userdata\0") });
    json_object_set_serializer(
        with_serializer,
        Some(my_custom_serializer),
        udata.as_mut_ptr() as *mut libc::c_void,
        None,
    );
    json_object_object_add(
        src1,
        b"with_serializer\0" as *const u8 as *const i8,
        with_serializer,
    );
    dst1 = 0 as *mut json_object;
    if -(1 as i32) == json_object_deep_copy(src1, &mut dst1, None) {
    } else {
        (unsafe { __assert_fail(
            b"-1 == json_object_deep_copy(src1, &dst1, NULL)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            201 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    if 0 as i32 == json_object_deep_copy(src1, &mut dst1, Some(my_shallow_copy)) {
    } else {
        (unsafe { __assert_fail(
            b"0 == json_object_deep_copy(src1, &dst1, my_shallow_copy)\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            202 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    let mut dest_with_serializer: *mut crate::src::json_object::json_object =
        json_object_object_get(dst1, b"with_serializer\0" as *const u8 as *const i8);
    if !dest_with_serializer.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"dest_with_serializer != NULL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            205 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    let mut dst_userdata: *mut i8 = json_object_get_userdata(dest_with_serializer) as *mut i8;
    if (unsafe { strcmp(dst_userdata, b"dummy userdata\0" as *const u8 as *const i8) }) == 0 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"strcmp(dst_userdata, \"dummy userdata\") == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            207 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    let mut special_output: *const i8 = json_object_to_json_string(dest_with_serializer);
    if (unsafe { strcmp(special_output, b"OTHER\0" as *const u8 as *const i8) }) == 0 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"strcmp(special_output, \"OTHER\") == 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8 as *const i8,
            210 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    (unsafe { printf(b"\ndeep_copy with custom serializer worked OK.\n\0" as *const u8 as *const i8) });
    json_object_put(dst1);
    if benchmark != 0 {
        do_benchmark(src2);
    }
    json_object_put(src1);
    json_object_put(src2);
    json_object_put(src3);
    return 0 as i32;
}
extern "C" fn do_benchmark(mut src2: *mut crate::src::json_object::json_object) {
    let mut dst2: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut ii: i32 = 0;
    let mut iterations: i32 = 1000000 as i32;
    let mut start: i64 = unsafe { time(0 as *mut time_t) };
    start = unsafe { time(0 as *mut time_t) };
    ii = 0 as i32;
    while ii < iterations {
        dst2 = json_tokener_parse(json_object_get_string(src2));
        json_object_put(dst2);
        ii += 1;
    }
    (unsafe { printf (b"BENCHMARK - %d iterations of 'dst2 = json_tokener_parse(json_object_get_string(src2))' took %d seconds\n\0" as * const u8 as * const i8 , iterations , (time (0 as * mut time_t) - start) as i32 ,) }) ;
    start = unsafe { time(0 as *mut time_t) };
    dst2 = 0 as *mut json_object;
    ii = 0 as i32;
    while ii < iterations {
        json_object_deep_copy(src2, &mut dst2, None);
        json_object_put(dst2);
        dst2 = 0 as *mut json_object;
        ii += 1;
    }
    (unsafe { printf (b"BENCHMARK - %d iterations of 'json_object_deep_copy(src2, &dst2, NULL)' took %d seconds\n\0" as * const u8 as * const i8 , iterations , (time (0 as * mut time_t) - start) as i32 ,) }) ;
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

