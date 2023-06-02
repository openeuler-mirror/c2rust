
extern "C" {
    fn printf(_: *const i8, _: ...) -> i32;
}
pub use crate::src::{
    json_object::{
        json_object, json_object_get_boolean, json_object_get_double, json_object_get_int,
        json_object_get_int64, json_object_get_type, json_object_get_uint64, json_object_is_type,
        json_object_object_get_ex, json_object_put,
    },
    json_tokener::json_tokener_parse,
    json_util::json_type_to_name,
};
pub type __int32_t = i32;
pub type __int64_t = i64;
pub type __uint64_t = u64;
pub type int32_t = i32;
pub type int64_t = i64;
pub type uint64_t = u64;
pub type json_bool = i32;
pub type json_type = u32;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
fn main_0(mut _argc: i32, mut _argv: *mut *mut i8) -> i32 {
    let mut input : * const i8 = b"{\n\t\t\"string_of_digits\": \"123\",\n\t\t\"regular_number\": 222,\n\t\t\"decimal_number\": 99.55,\n\t\t\"boolean_true\": true,\n\t\t\"boolean_false\": false,\n\t\t\"int64_number\": 2147483649,\n\t\t\"negative_number\": -321321321,\n\t\t\"a_null\": null,\n\t\t\"empty_array\": [],\n\t\t\"nonempty_array\": [ 123 ],\n\t\t\"array_with_zero\": [ 0 ],\n\t\t\"empty_object\": {},\n\t\t\"nonempty_object\": { \"a\": 123 },\n\t}\0" as * const u8 as * const i8 ;
    let mut new_obj: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    new_obj = json_tokener_parse(input);
    (unsafe { printf(b"Parsed input: %s\n\0" as *const u8 as *const i8, input) });
    (unsafe { printf(
        b"Result is %s\n\0" as *const u8 as *const i8,
        if new_obj.is_null() {
            b"NULL (error!)\0" as *const u8 as *const i8
        } else {
            b"not NULL\0" as *const u8 as *const i8
        },
    ) });
    if new_obj.is_null() {
        return 1 as i32;
    }
    getit(new_obj, b"string_of_digits\0" as *const u8 as *const i8);
    getit(new_obj, b"regular_number\0" as *const u8 as *const i8);
    getit(new_obj, b"decimal_number\0" as *const u8 as *const i8);
    getit(new_obj, b"boolean_true\0" as *const u8 as *const i8);
    getit(new_obj, b"boolean_false\0" as *const u8 as *const i8);
    getit(new_obj, b"int64_number\0" as *const u8 as *const i8);
    getit(new_obj, b"negative_number\0" as *const u8 as *const i8);
    getit(new_obj, b"a_null\0" as *const u8 as *const i8);
    getit(new_obj, b"empty_array\0" as *const u8 as *const i8);
    getit(new_obj, b"nonempty_array\0" as *const u8 as *const i8);
    getit(new_obj, b"array_with_zero\0" as *const u8 as *const i8);
    getit(new_obj, b"empty_object\0" as *const u8 as *const i8);
    getit(new_obj, b"nonempty_object\0" as *const u8 as *const i8);
    (unsafe { printf(b"\n================================\n\0" as *const u8 as *const i8) });
    checktype_header();
    checktype(new_obj, 0 as *const i8);
    checktype(new_obj, b"string_of_digits\0" as *const u8 as *const i8);
    checktype(new_obj, b"regular_number\0" as *const u8 as *const i8);
    checktype(new_obj, b"decimal_number\0" as *const u8 as *const i8);
    checktype(new_obj, b"boolean_true\0" as *const u8 as *const i8);
    checktype(new_obj, b"boolean_false\0" as *const u8 as *const i8);
    checktype(new_obj, b"int64_number\0" as *const u8 as *const i8);
    checktype(new_obj, b"negative_number\0" as *const u8 as *const i8);
    checktype(new_obj, b"a_null\0" as *const u8 as *const i8);
    json_object_put(new_obj);
    return 0 as i32;
}
extern "C" fn getit(mut new_obj: *mut crate::src::json_object::json_object, mut field: *const i8) {
    let mut o: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    if json_object_object_get_ex(new_obj, field, &mut o) == 0 {
        (unsafe { printf(
            b"Field %s does not exist\n\0" as *const u8 as *const i8,
            field,
        ) });
    }
    let mut o_type: u32 = json_object_get_type(o);
    (unsafe { printf(
        b"new_obj.%s json_object_get_type()=%s\n\0" as *const u8 as *const i8,
        field,
        json_type_to_name(o_type),
    ) });
    (unsafe { printf(
        b"new_obj.%s json_object_get_int()=%d\n\0" as *const u8 as *const i8,
        field,
        json_object_get_int(o),
    ) });
    (unsafe { printf(
        b"new_obj.%s json_object_get_int64()=%ld\n\0" as *const u8 as *const i8,
        field,
        json_object_get_int64(o),
    ) });
    (unsafe { printf(
        b"new_obj.%s json_object_get_uint64()=%lu\n\0" as *const u8 as *const i8,
        field,
        json_object_get_uint64(o),
    ) });
    (unsafe { printf(
        b"new_obj.%s json_object_get_boolean()=%d\n\0" as *const u8 as *const i8,
        field,
        json_object_get_boolean(o),
    ) });
    (unsafe { printf(
        b"new_obj.%s json_object_get_double()=%f\n\0" as *const u8 as *const i8,
        field,
        json_object_get_double(o),
    ) });
}
extern "C" fn checktype_header() {
    (unsafe { printf(
        b"json_object_is_type: %s,%s,%s,%s,%s,%s,%s\n\0" as *const u8 as *const i8,
        json_type_to_name(json_type_null),
        json_type_to_name(json_type_boolean),
        json_type_to_name(json_type_double),
        json_type_to_name(json_type_int),
        json_type_to_name(json_type_object),
        json_type_to_name(json_type_array),
        json_type_to_name(json_type_string),
    ) });
}
extern "C" fn checktype(
    mut new_obj: *mut crate::src::json_object::json_object,
    mut field: *const i8,
) {
    let mut o: *mut crate::src::json_object::json_object = new_obj;
    if !field.is_null() && json_object_object_get_ex(new_obj, field, &mut o) == 0 {
        (unsafe { printf(
            b"Field %s does not exist\n\0" as *const u8 as *const i8,
            field,
        ) });
    }
    (unsafe { printf(
        b"new_obj%s%-18s: %d,%d,%d,%d,%d,%d,%d\n\0" as *const u8 as *const i8,
        if !field.is_null() {
            b".\0" as *const u8 as *const i8
        } else {
            b" \0" as *const u8 as *const i8
        },
        if !field.is_null() {
            field
        } else {
            b"\0" as *const u8 as *const i8
        },
        json_object_is_type(o, json_type_null),
        json_object_is_type(o, json_type_boolean),
        json_object_is_type(o, json_type_double),
        json_object_is_type(o, json_type_int),
        json_object_is_type(o, json_type_object),
        json_object_is_type(o, json_type_array),
        json_object_is_type(o, json_type_string),
    ) });
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

