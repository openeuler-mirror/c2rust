use ::libc;
extern "C" {
    
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::json_object::json_object_get_boolean;
pub use crate::src::json_object::json_object_get_double;
pub use crate::src::json_object::json_object_get_int;
pub use crate::src::json_object::json_object_get_int64;
pub use crate::src::json_object::json_object_get_type;
pub use crate::src::json_object::json_object_get_uint64;
pub use crate::src::json_object::json_object_is_type;
pub use crate::src::json_object::json_object_object_get_ex;
pub use crate::src::json_object::json_object_put;
pub use crate::src::json_tokener::json_tokener_parse;
pub use crate::src::json_util::json_type_to_name;
pub use crate::src::json_object::json_object;
pub type __int32_t = crate::src::json_object::__int32_t;
pub type __int64_t = crate::src::json_object::__int64_t;
pub type __uint64_t = crate::src::json_object::__uint64_t;
pub type int32_t = crate::src::json_object::int32_t;
pub type int64_t = crate::src::json_object::int64_t;
pub type uint64_t = crate::src::json_object::uint64_t;
pub type json_bool = crate::src::json_object::json_bool;
pub type json_type = crate::src::json_object::json_type;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut input: *const libc::c_char = b"{\n\t\t\"string_of_digits\": \"123\",\n\t\t\"regular_number\": 222,\n\t\t\"decimal_number\": 99.55,\n\t\t\"boolean_true\": true,\n\t\t\"boolean_false\": false,\n\t\t\"int64_number\": 2147483649,\n\t\t\"negative_number\": -321321321,\n\t\t\"a_null\": null,\n\t\t\"empty_array\": [],\n\t\t\"nonempty_array\": [ 123 ],\n\t\t\"array_with_zero\": [ 0 ],\n\t\t\"empty_object\": {},\n\t\t\"nonempty_object\": { \"a\": 123 },\n\t}\0"
        as *const u8 as *const libc::c_char;
    let mut new_obj: *mut json_object = 0 as *mut json_object;
    new_obj = json_tokener_parse(input);
    printf(b"Parsed input: %s\n\0" as *const u8 as *const libc::c_char, input);
    printf(
        b"Result is %s\n\0" as *const u8 as *const libc::c_char,
        if new_obj.is_null() {
            b"NULL (error!)\0" as *const u8 as *const libc::c_char
        } else {
            b"not NULL\0" as *const u8 as *const libc::c_char
        },
    );
    if new_obj.is_null() {
        return 1 as libc::c_int;
    }
    getit(new_obj, b"string_of_digits\0" as *const u8 as *const libc::c_char);
    getit(new_obj, b"regular_number\0" as *const u8 as *const libc::c_char);
    getit(new_obj, b"decimal_number\0" as *const u8 as *const libc::c_char);
    getit(new_obj, b"boolean_true\0" as *const u8 as *const libc::c_char);
    getit(new_obj, b"boolean_false\0" as *const u8 as *const libc::c_char);
    getit(new_obj, b"int64_number\0" as *const u8 as *const libc::c_char);
    getit(new_obj, b"negative_number\0" as *const u8 as *const libc::c_char);
    getit(new_obj, b"a_null\0" as *const u8 as *const libc::c_char);
    getit(new_obj, b"empty_array\0" as *const u8 as *const libc::c_char);
    getit(new_obj, b"nonempty_array\0" as *const u8 as *const libc::c_char);
    getit(new_obj, b"array_with_zero\0" as *const u8 as *const libc::c_char);
    getit(new_obj, b"empty_object\0" as *const u8 as *const libc::c_char);
    getit(new_obj, b"nonempty_object\0" as *const u8 as *const libc::c_char);
    printf(
        b"\n================================\n\0" as *const u8 as *const libc::c_char,
    );
    checktype_header();
    checktype(new_obj, 0 as *const libc::c_char);
    checktype(new_obj, b"string_of_digits\0" as *const u8 as *const libc::c_char);
    checktype(new_obj, b"regular_number\0" as *const u8 as *const libc::c_char);
    checktype(new_obj, b"decimal_number\0" as *const u8 as *const libc::c_char);
    checktype(new_obj, b"boolean_true\0" as *const u8 as *const libc::c_char);
    checktype(new_obj, b"boolean_false\0" as *const u8 as *const libc::c_char);
    checktype(new_obj, b"int64_number\0" as *const u8 as *const libc::c_char);
    checktype(new_obj, b"negative_number\0" as *const u8 as *const libc::c_char);
    checktype(new_obj, b"a_null\0" as *const u8 as *const libc::c_char);
    json_object_put(new_obj);
    return 0 as libc::c_int;
}
unsafe extern "C" fn getit(
    mut new_obj: *mut json_object,
    mut field: *const libc::c_char,
) {
    let mut o: *mut json_object = 0 as *mut json_object;
    if json_object_object_get_ex(new_obj, field, &mut o) == 0 {
        printf(
            b"Field %s does not exist\n\0" as *const u8 as *const libc::c_char,
            field,
        );
    }
    let mut o_type: json_type = json_object_get_type(o);
    printf(
        b"new_obj.%s json_object_get_type()=%s\n\0" as *const u8 as *const libc::c_char,
        field,
        json_type_to_name(o_type),
    );
    printf(
        b"new_obj.%s json_object_get_int()=%d\n\0" as *const u8 as *const libc::c_char,
        field,
        json_object_get_int(o),
    );
    printf(
        b"new_obj.%s json_object_get_int64()=%ld\n\0" as *const u8
            as *const libc::c_char,
        field,
        json_object_get_int64(o),
    );
    printf(
        b"new_obj.%s json_object_get_uint64()=%lu\n\0" as *const u8
            as *const libc::c_char,
        field,
        json_object_get_uint64(o),
    );
    printf(
        b"new_obj.%s json_object_get_boolean()=%d\n\0" as *const u8
            as *const libc::c_char,
        field,
        json_object_get_boolean(o),
    );
    printf(
        b"new_obj.%s json_object_get_double()=%f\n\0" as *const u8
            as *const libc::c_char,
        field,
        json_object_get_double(o),
    );
}
unsafe extern "C" fn checktype_header() {
    printf(
        b"json_object_is_type: %s,%s,%s,%s,%s,%s,%s\n\0" as *const u8
            as *const libc::c_char,
        json_type_to_name(json_type_null),
        json_type_to_name(json_type_boolean),
        json_type_to_name(json_type_double),
        json_type_to_name(json_type_int),
        json_type_to_name(json_type_object),
        json_type_to_name(json_type_array),
        json_type_to_name(json_type_string),
    );
}
unsafe extern "C" fn checktype(
    mut new_obj: *mut json_object,
    mut field: *const libc::c_char,
) {
    let mut o: *mut json_object = new_obj;
    if !field.is_null() && json_object_object_get_ex(new_obj, field, &mut o) == 0 {
        printf(
            b"Field %s does not exist\n\0" as *const u8 as *const libc::c_char,
            field,
        );
    }
    printf(
        b"new_obj%s%-18s: %d,%d,%d,%d,%d,%d,%d\n\0" as *const u8 as *const libc::c_char,
        if !field.is_null() {
            b".\0" as *const u8 as *const libc::c_char
        } else {
            b" \0" as *const u8 as *const libc::c_char
        },
        if !field.is_null() { field } else { b"\0" as *const u8 as *const libc::c_char },
        json_object_is_type(o, json_type_null),
        json_object_is_type(o, json_type_boolean),
        json_object_is_type(o, json_type_double),
        json_object_is_type(o, json_type_int),
        json_object_is_type(o, json_type_object),
        json_object_is_type(o, json_type_array),
        json_object_is_type(o, json_type_string),
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
