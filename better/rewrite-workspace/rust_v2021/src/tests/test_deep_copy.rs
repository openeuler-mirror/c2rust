use ::libc;
extern "C" {
    
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn __errno_location() -> *mut libc::c_int;
    fn time(__timer: *mut time_t) -> time_t;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::json_object::json_object;
pub use crate::json_object::json_c_shallow_copy_default;
pub use crate::json_object::json_object_deep_copy;
pub use crate::json_object::json_object_equal;
pub use crate::json_object::json_object_get;
pub use crate::json_object::json_object_get_string;
pub use crate::json_object::json_object_get_userdata;
pub use crate::json_object::json_object_new_string;
pub use crate::json_object::json_object_object_add;
pub use crate::json_object::json_object_object_get;
pub use crate::json_object::json_object_put;
pub use crate::json_object::json_object_set_serializer;
pub use crate::json_object::json_object_to_json_string;
pub use crate::json_object::json_object_to_json_string_ext;
pub use crate::json_tokener::json_tokener_parse;
pub use crate::printbuf::sprintbuf;
pub use crate::apps::json_parse::size_t;
pub use crate::apps::json_parse::__time_t;
pub use crate::random_seed::time_t;
// #[derive(Copy, Clone)]

pub use crate::apps::json_parse::printbuf;
pub use crate::json_object::json_object_delete_fn;
pub use crate::json_object::json_object_to_json_string_fn;
pub use crate::json_object::json_c_shallow_copy_fn;
static mut json_str1: *const libc::c_char = b"{    \"glossary\": {        \"title\": \"example glossary\",        \"GlossDiv\": {            \"number\": 16446744073709551615,            \"title\": \"S\",            \"null_obj\": null,             \"exist\": false,            \"quantity\":20,            \"univalent\":19.8,            \"GlossList\": {                \"GlossEntry\": {                    \"ID\": \"SGML\",                    \"SortAs\": \"SGML\",                    \"GlossTerm\": \"Standard Generalized Markup Language\",                    \"Acronym\": \"SGML\",                    \"Abbrev\": \"ISO 8879:1986\",                    \"GlossDef\": {                        \"para\": \"A meta-markup language, used to create markup languages such as DocBook.\",                        \"GlossSeeAlso\": [\"GML\", \"XML\"]                    },                    \"GlossSee\": \"markup\"                }            }        }    }}\0"
    as *const u8 as *const libc::c_char;
static mut json_str2: *const libc::c_char = b"{\"menu\": {    \"header\": \"SVG Viewer\",    \"items\": [        {\"id\": \"Open\"},        {\"id\": \"OpenNew\", \"label\": \"Open New\"},        null,        {\"id\": \"ZoomIn\", \"label\": \"Zoom In\"},        {\"id\": \"ZoomOut\", \"label\": \"Zoom Out\"},        {\"id\": \"OriginalView\", \"label\": \"Original View\"},        null,        {\"id\": \"Quality\", \"another_null\": null},        {\"id\": \"Pause\"},        {\"id\": \"Mute\"},        null,        {\"id\": \"Find\", \"label\": \"Find...\"},        {\"id\": \"FindAgain\", \"label\": \"Find Again\"},        {\"id\": \"Copy\"},        {\"id\": \"CopyAgain\", \"label\": \"Copy Again\"},        {\"id\": \"CopySVG\", \"label\": \"Copy SVG\"},        {\"id\": \"ViewSVG\", \"label\": \"View SVG\"},        {\"id\": \"ViewSource\", \"label\": \"View Source\"},        {\"id\": \"SaveAs\", \"label\": \"Save As\"},        null,        {\"id\": \"Help\"},        {\"id\": \"About\", \"label\": \"About Adobe CVG Viewer...\"}    ]}}\0"
    as *const u8 as *const libc::c_char;
static mut json_str3: *const libc::c_char = b"{\"menu\": {  \"id\": \"file\",  \"value\": \"File\",  \"popup\": {    \"menuitem\": [      {\"value\": \"New\", \"onclick\": \"CreateNewDoc()\"},      {\"value\": \"Open\", \"onclick\": \"OpenDoc()\"},      {\"value\": \"Close\", \"onclick\": \"CloseDoc()\"}    ]  }}}\0"
    as *const u8 as *const libc::c_char;
#[no_mangle]
pub unsafe extern "C" fn my_custom_serializer(
    mut jso: *mut json_object,
    mut pb: *mut printbuf,
    mut level: libc::c_int,
    mut flags: libc::c_int,
) -> libc::c_int {
    sprintbuf(pb, b"OTHER\0" as *const u8 as *const libc::c_char);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn my_shallow_copy(
    mut src: *mut json_object,
    mut parent: *mut json_object,
    mut key: *const libc::c_char,
    mut index: size_t,
    mut dst: *mut *mut json_object,
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    rc = json_c_shallow_copy_default(src, parent, key, index, dst);
    if rc < 0 as libc::c_int {
        return rc;
    }
    if !key.is_null()
        && strcmp(key, b"with_serializer\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
    {
        printf(
            b"CALLED: my_shallow_copy on with_serializer object\n\0" as *const u8
                as *const libc::c_char,
        );
        let mut userdata: *mut libc::c_void = json_object_get_userdata(src);
        json_object_set_serializer(
            *dst,
            Some(my_custom_serializer as json_object_to_json_string_fn),
            userdata,
            None,
        );
        return 2 as libc::c_int;
    }
    return rc;
}
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut src1: *mut json_object = 0 as *mut json_object;
    let mut src2: *mut json_object = 0 as *mut json_object;
    let mut src3: *mut json_object = 0 as *mut json_object;
    let mut dst1: *mut json_object = 0 as *mut json_object;
    let mut dst2: *mut json_object = 0 as *mut json_object;
    let mut dst3: *mut json_object = 0 as *mut json_object;
    let mut benchmark: libc::c_int = 0 as libc::c_int;
    if argc > 1 as libc::c_int
        && strcmp(
            *argv.offset(1 as libc::c_int as isize),
            b"--benchmark\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
    {
        benchmark = 1 as libc::c_int;
    }
    src1 = json_tokener_parse(json_str1);
    src2 = json_tokener_parse(json_str2);
    src3 = json_tokener_parse(json_str3);
    if !src1.is_null() {} else {
        __assert_fail(
            b"src1 != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            128 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if !src2.is_null() {} else {
        __assert_fail(
            b"src2 != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            129 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if !src3.is_null() {} else {
        __assert_fail(
            b"src3 != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            130 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    printf(b"PASSED - loaded input data\n\0" as *const u8 as *const libc::c_char);
    if 0 as libc::c_int == json_object_deep_copy(src1, &mut dst1, None) {} else {
        __assert_fail(
            b"0 == json_object_deep_copy(src1, &dst1, NULL)\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            135 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if 0 as libc::c_int == json_object_deep_copy(src2, &mut dst2, None) {} else {
        __assert_fail(
            b"0 == json_object_deep_copy(src2, &dst2, NULL)\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            136 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if 0 as libc::c_int == json_object_deep_copy(src3, &mut dst3, None) {} else {
        __assert_fail(
            b"0 == json_object_deep_copy(src3, &dst3, NULL)\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            137 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    printf(
        b"PASSED - all json_object_deep_copy() returned successful\n\0" as *const u8
            as *const libc::c_char,
    );
    if -(1 as libc::c_int) == json_object_deep_copy(src1, &mut dst1, None) {} else {
        __assert_fail(
            b"-1 == json_object_deep_copy(src1, &dst1, NULL)\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            141 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if *__errno_location() == 22 as libc::c_int {} else {
        __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            142 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if -(1 as libc::c_int) == json_object_deep_copy(src2, &mut dst2, None) {} else {
        __assert_fail(
            b"-1 == json_object_deep_copy(src2, &dst2, NULL)\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            143 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if *__errno_location() == 22 as libc::c_int {} else {
        __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            144 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if -(1 as libc::c_int) == json_object_deep_copy(src3, &mut dst3, None) {} else {
        __assert_fail(
            b"-1 == json_object_deep_copy(src3, &dst3, NULL)\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            145 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if *__errno_location() == 22 as libc::c_int {} else {
        __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            146 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    printf(
        b"PASSED - all json_object_deep_copy() returned EINVAL for non-null pointer\n\0"
            as *const u8 as *const libc::c_char,
    );
    if 1 as libc::c_int == json_object_equal(src1, dst1) {} else {
        __assert_fail(
            b"1 == json_object_equal(src1, dst1)\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            150 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if 1 as libc::c_int == json_object_equal(src2, dst2) {} else {
        __assert_fail(
            b"1 == json_object_equal(src2, dst2)\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            151 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if 1 as libc::c_int == json_object_equal(src3, dst3) {} else {
        __assert_fail(
            b"1 == json_object_equal(src3, dst3)\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            152 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    printf(
        b"PASSED - all json_object_equal() tests returned successful\n\0" as *const u8
            as *const libc::c_char,
    );
    if 0 as libc::c_int
        == strcmp(
            json_object_to_json_string_ext(src1, (1 as libc::c_int) << 1 as libc::c_int),
            json_object_to_json_string_ext(dst1, (1 as libc::c_int) << 1 as libc::c_int),
        )
    {} else {
        __assert_fail(
            b"0 == strcmp(json_object_to_json_string_ext(src1, JSON_C_TO_STRING_PRETTY), json_object_to_json_string_ext(dst1, JSON_C_TO_STRING_PRETTY))\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            157 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if 0 as libc::c_int
        == strcmp(
            json_object_to_json_string_ext(src2, (1 as libc::c_int) << 1 as libc::c_int),
            json_object_to_json_string_ext(dst2, (1 as libc::c_int) << 1 as libc::c_int),
        )
    {} else {
        __assert_fail(
            b"0 == strcmp(json_object_to_json_string_ext(src2, JSON_C_TO_STRING_PRETTY), json_object_to_json_string_ext(dst2, JSON_C_TO_STRING_PRETTY))\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            159 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if 0 as libc::c_int
        == strcmp(
            json_object_to_json_string_ext(src3, (1 as libc::c_int) << 1 as libc::c_int),
            json_object_to_json_string_ext(dst3, (1 as libc::c_int) << 1 as libc::c_int),
        )
    {} else {
        __assert_fail(
            b"0 == strcmp(json_object_to_json_string_ext(src3, JSON_C_TO_STRING_PRETTY), json_object_to_json_string_ext(dst3, JSON_C_TO_STRING_PRETTY))\0"
                as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            161 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    printf(
        b"PASSED - comparison of string output\n\0" as *const u8 as *const libc::c_char,
    );
    json_object_get(dst1);
    if -(1 as libc::c_int) == json_object_deep_copy(src1, &mut dst1, None) {} else {
        __assert_fail(
            b"-1 == json_object_deep_copy(src1, &dst1, NULL)\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            166 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if *__errno_location() == 22 as libc::c_int {} else {
        __assert_fail(
            b"errno == EINVAL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            167 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    json_object_put(dst1);
    printf(
        b"PASSED - trying to overrwrite an object that has refcount > 1\0" as *const u8
            as *const libc::c_char,
    );
    printf(
        b"\nPrinting JSON objects for visual inspection\n\0" as *const u8
            as *const libc::c_char,
    );
    printf(
        b"------------------------------------------------\n\0" as *const u8
            as *const libc::c_char,
    );
    printf(b" JSON1\n\0" as *const u8 as *const libc::c_char);
    printf(
        b"%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string_ext(dst1, (1 as libc::c_int) << 1 as libc::c_int),
    );
    printf(
        b"------------------------------------------------\n\0" as *const u8
            as *const libc::c_char,
    );
    printf(
        b"------------------------------------------------\n\0" as *const u8
            as *const libc::c_char,
    );
    printf(b" JSON2\n\0" as *const u8 as *const libc::c_char);
    printf(
        b"%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string_ext(dst2, (1 as libc::c_int) << 1 as libc::c_int),
    );
    printf(
        b"------------------------------------------------\n\0" as *const u8
            as *const libc::c_char,
    );
    printf(
        b"------------------------------------------------\n\0" as *const u8
            as *const libc::c_char,
    );
    printf(b" JSON3\n\0" as *const u8 as *const libc::c_char);
    printf(
        b"------------------------------------------------\n\0" as *const u8
            as *const libc::c_char,
    );
    printf(
        b"%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string_ext(dst3, (1 as libc::c_int) << 1 as libc::c_int),
    );
    printf(
        b"------------------------------------------------\n\0" as *const u8
            as *const libc::c_char,
    );
    json_object_put(dst1);
    json_object_put(dst2);
    json_object_put(dst3);
    printf(
        b"\nTesting deep_copy with a custom serializer set\n\0" as *const u8
            as *const libc::c_char,
    );
    let mut with_serializer: *mut json_object = json_object_new_string(
        b"notemitted\0" as *const u8 as *const libc::c_char,
    );
    let mut udata: [libc::c_char; 15] = *::std::mem::transmute::<
        &[u8; 15],
        &mut [libc::c_char; 15],
    >(b"dummy userdata\0");
    json_object_set_serializer(
        with_serializer,
        Some(my_custom_serializer as json_object_to_json_string_fn),
        udata.as_mut_ptr() as *mut libc::c_void,
        None,
    );
    json_object_object_add(
        src1,
        b"with_serializer\0" as *const u8 as *const libc::c_char,
        with_serializer,
    );
    dst1 = 0 as *mut json_object;
    if -(1 as libc::c_int) == json_object_deep_copy(src1, &mut dst1, None) {} else {
        __assert_fail(
            b"-1 == json_object_deep_copy(src1, &dst1, NULL)\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            201 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    if 0 as libc::c_int
        == json_object_deep_copy(
            src1,
            &mut dst1,
            Some(my_shallow_copy as json_c_shallow_copy_fn),
        )
    {} else {
        __assert_fail(
            b"0 == json_object_deep_copy(src1, &dst1, my_shallow_copy)\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            202 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    let mut dest_with_serializer: *mut json_object = json_object_object_get(
        dst1,
        b"with_serializer\0" as *const u8 as *const libc::c_char,
    );
    if !dest_with_serializer.is_null() {} else {
        __assert_fail(
            b"dest_with_serializer != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            205 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    let mut dst_userdata: *mut libc::c_char = json_object_get_userdata(
        dest_with_serializer,
    ) as *mut libc::c_char;
    if strcmp(dst_userdata, b"dummy userdata\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"strcmp(dst_userdata, \"dummy userdata\") == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            207 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    let mut special_output: *const libc::c_char = json_object_to_json_string(
        dest_with_serializer,
    );
    if strcmp(special_output, b"OTHER\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"strcmp(special_output, \"OTHER\") == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test_deep_copy.c\0" as *const u8
                as *const libc::c_char,
            210 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    printf(
        b"\ndeep_copy with custom serializer worked OK.\n\0" as *const u8
            as *const libc::c_char,
    );
    json_object_put(dst1);
    if benchmark != 0 {
        do_benchmark(src2);
    }
    json_object_put(src1);
    json_object_put(src2);
    json_object_put(src3);
    return 0 as libc::c_int;
}
unsafe extern "C" fn do_benchmark(mut src2: *mut json_object) {
    let mut dst2: *mut json_object = 0 as *mut json_object;
    let mut ii: libc::c_int = 0;
    let mut iterations: libc::c_int = 1000000 as libc::c_int;
    let mut start: time_t = time(0 as *mut time_t);
    start = time(0 as *mut time_t);
    ii = 0 as libc::c_int;
    while ii < iterations {
        dst2 = json_tokener_parse(json_object_get_string(src2));
        json_object_put(dst2);
        ii += 1;
    }
    printf(
        b"BENCHMARK - %d iterations of 'dst2 = json_tokener_parse(json_object_get_string(src2))' took %d seconds\n\0"
            as *const u8 as *const libc::c_char,
        iterations,
        (time(0 as *mut time_t) - start) as libc::c_int,
    );
    start = time(0 as *mut time_t);
    dst2 = 0 as *mut json_object;
    ii = 0 as libc::c_int;
    while ii < iterations {
        json_object_deep_copy(src2, &mut dst2, None);
        json_object_put(dst2);
        dst2 = 0 as *mut json_object;
        ii += 1;
    }
    printf(
        b"BENCHMARK - %d iterations of 'json_object_deep_copy(src2, &dst2, NULL)' took %d seconds\n\0"
            as *const u8 as *const libc::c_char,
        iterations,
        (time(0 as *mut time_t) - start) as libc::c_int,
    );
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
