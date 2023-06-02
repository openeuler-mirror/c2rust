use ::libc;
extern "C" {
    
    fn printf(_: * const i8, _: ...) -> i32;
    fn strcmp(_: * const i8, _: * const i8) -> i32;
    
    
    
    
    
    
}
pub use crate::src::debug::mc_set_debug;
pub use crate::src::json_object::json_object_get_type;
pub use crate::src::json_object::json_object_put;
pub use crate::src::json_object::json_object_to_json_string;
pub use crate::src::json_tokener::json_tokener_parse;
pub use crate::src::json_visit::json_c_visit;
pub use crate::src::json_object::json_object;
pub type size_t = u64;
pub type json_type = u32;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
pub type json_c_visit_userfunc = unsafe extern "C"  fn(_: * mut crate::src::json_object::json_object,_: i32,_: * mut crate::src::json_object::json_object,_: * const i8,_: * mut u64,_: * mut core::ffi::c_void,) -> i32;
unsafe fn main_0() -> i32 {
    let mut input: * const i8 = b"{\t\t\"obj1\": 123,\t\t\"obj2\": {\t\t\t\"subobj1\": \"aaa\",\t\t\t\"subobj2\": \"bbb\",\t\t\t\"subobj3\": [ \"elem1\", \"elem2\", true ],\t\t},\t\t\"obj3\": 1.234,\t\t\"obj4\": [ true, false, null ]\t}\0"
        as *const u8 as *const i8;
    let mut jso: * mut crate::src::json_object::json_object = json_tokener_parse(input);
    printf(
        b"jso.to_string()=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(jso),
    );
    let mut rv: i32 = 0;
    rv = json_c_visit(
        jso,
        0 as i32,
        Some(emit_object),
        (0 as * mut core::ffi::c_void),
    );
    printf(b"json_c_visit(emit_object)=%d\n\0" as *const u8 as *const i8, rv);
    printf(
        b"================================\n\n\0" as *const u8 as *const i8,
    );
    rv = json_c_visit(
        jso,
        0 as i32,
        Some(skip_arrays),
        (0 as * mut core::ffi::c_void),
    );
    printf(b"json_c_visit(skip_arrays)=%d\n\0" as *const u8 as *const i8, rv);
    printf(
        b"================================\n\n\0" as *const u8 as *const i8,
    );
    rv = json_c_visit(
        jso,
        0 as i32,
        Some(pop_and_stop),
        (0 as * mut core::ffi::c_void),
    );
    printf(b"json_c_visit(pop_and_stop)=%d\n\0" as *const u8 as *const i8, rv);
    printf(
        b"================================\n\n\0" as *const u8 as *const i8,
    );
    rv = json_c_visit(
        jso,
        0 as i32,
        Some(err_on_subobj2),
        (0 as * mut core::ffi::c_void),
    );
    printf(
        b"json_c_visit(err_on_subobj2)=%d\n\0" as *const u8 as *const i8,
        rv,
    );
    printf(
        b"================================\n\n\0" as *const u8 as *const i8,
    );
    rv = json_c_visit(
        jso,
        0 as i32,
        Some(pop_array),
        (0 as * mut core::ffi::c_void),
    );
    printf(b"json_c_visit(pop_array)=%d\n\0" as *const u8 as *const i8, rv);
    printf(
        b"================================\n\n\0" as *const u8 as *const i8,
    );
    rv = json_c_visit(
        jso,
        0 as i32,
        Some(stop_array),
        (0 as * mut core::ffi::c_void),
    );
    printf(b"json_c_visit(stop_array)=%d\n\0" as *const u8 as *const i8, rv);
    printf(
        b"================================\n\n\0" as *const u8 as *const i8,
    );
    rv = json_c_visit(
        jso,
        0 as i32,
        Some(err_return),
        (0 as * mut core::ffi::c_void),
    );
    printf(b"json_c_visit(err_return)=%d\n\0" as *const u8 as *const i8, rv);
    printf(
        b"================================\n\n\0" as *const u8 as *const i8,
    );
    json_object_put(jso);
    return 0 as i32;
}
unsafe extern "C" fn emit_object(
    mut jso: * mut crate::src::json_object::json_object,
    mut flags: i32,
    mut parent_jso: * mut crate::src::json_object::json_object,
    mut jso_key: * const i8,
    mut jso_index: * mut u64,
    mut userarg: * mut core::ffi::c_void,
) -> i32 {
    printf(
        b"flags: 0x%x, key: %s, index: %ld, value: %s\n\0" as *const u8
            as *const i8,
        flags,
        if !jso_key.is_null() {
            jso_key
        } else {
            b"(null)\0" as *const u8 as *const i8
        },
        if !jso_index.is_null() {
            *jso_index as i64
        } else {
            -(1 as i64)
        },
        json_object_to_json_string(jso),
    );
    return 0 as i32;
}
unsafe extern "C" fn skip_arrays(
    mut jso: * mut crate::src::json_object::json_object,
    mut flags: i32,
    mut parent_jso: * mut crate::src::json_object::json_object,
    mut jso_key: * const i8,
    mut jso_index: * mut u64,
    mut userarg: * mut core::ffi::c_void,
) -> i32 {
    emit_object(jso, flags, parent_jso, jso_key, jso_index, userarg);
    if json_object_get_type(jso) as u32
        == json_type_array as i32 as u32
    {
        return 7547 as i32;
    }
    return 0 as i32;
}
unsafe extern "C" fn pop_and_stop(
    mut jso: * mut crate::src::json_object::json_object,
    mut flags: i32,
    mut parent_jso: * mut crate::src::json_object::json_object,
    mut jso_key: * const i8,
    mut jso_index: * mut u64,
    mut userarg: * mut core::ffi::c_void,
) -> i32 {
    emit_object(jso, flags, parent_jso, jso_key, jso_index, userarg);
    if !jso_key.is_null()
        && strcmp(jso_key, b"subobj1\0" as *const u8 as *const i8)
            == 0 as i32
    {
        printf(b"POP after handling subobj1\n\0" as *const u8 as *const i8);
        return 767 as i32;
    }
    if !jso_key.is_null()
        && strcmp(jso_key, b"obj3\0" as *const u8 as *const i8)
            == 0 as i32
    {
        printf(b"STOP after handling obj3\n\0" as *const u8 as *const i8);
        return 7867 as i32;
    }
    return 0 as i32;
}
unsafe extern "C" fn err_on_subobj2(
    mut jso: * mut crate::src::json_object::json_object,
    mut flags: i32,
    mut parent_jso: * mut crate::src::json_object::json_object,
    mut jso_key: * const i8,
    mut jso_index: * mut u64,
    mut userarg: * mut core::ffi::c_void,
) -> i32 {
    emit_object(jso, flags, parent_jso, jso_key, jso_index, userarg);
    if !jso_key.is_null()
        && strcmp(jso_key, b"subobj2\0" as *const u8 as *const i8)
            == 0 as i32
    {
        printf(b"ERROR after handling subobj1\n\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    return 0 as i32;
}
unsafe extern "C" fn pop_array(
    mut jso: * mut crate::src::json_object::json_object,
    mut flags: i32,
    mut parent_jso: * mut crate::src::json_object::json_object,
    mut jso_key: * const i8,
    mut jso_index: * mut u64,
    mut userarg: * mut core::ffi::c_void,
) -> i32 {
    emit_object(jso, flags, parent_jso, jso_key, jso_index, userarg);
    if !jso_index.is_null() && *jso_index == 0 as i32 as u64 {
        printf(b"POP after handling array[0]\n\0" as *const u8 as *const i8);
        return 767 as i32;
    }
    return 0 as i32;
}
unsafe extern "C" fn stop_array(
    mut jso: * mut crate::src::json_object::json_object,
    mut flags: i32,
    mut parent_jso: * mut crate::src::json_object::json_object,
    mut jso_key: * const i8,
    mut jso_index: * mut u64,
    mut userarg: * mut core::ffi::c_void,
) -> i32 {
    emit_object(jso, flags, parent_jso, jso_key, jso_index, userarg);
    if !jso_index.is_null() && *jso_index == 0 as i32 as u64 {
        printf(b"STOP after handling array[1]\n\0" as *const u8 as *const i8);
        return 7867 as i32;
    }
    return 0 as i32;
}
unsafe extern "C" fn err_return(
    mut jso: * mut crate::src::json_object::json_object,
    mut flags: i32,
    mut parent_jso: * mut crate::src::json_object::json_object,
    mut jso_key: * const i8,
    mut jso_index: * mut u64,
    mut userarg: * mut core::ffi::c_void,
) -> i32 {
    printf(
        b"flags: 0x%x, key: %s, index: %ld, value: %s\n\0" as *const u8
            as *const i8,
        flags,
        if !jso_key.is_null() {
            jso_key
        } else {
            b"(null)\0" as *const u8 as *const i8
        },
        if !jso_index.is_null() {
            *jso_index as i64
        } else {
            -(1 as i64)
        },
        json_object_to_json_string(jso),
    );
    return 100 as i32;
}
pub fn main() {
    unsafe { ::std::process::exit(main_0() as i32) }
}
use crate::laertes_rt::*;
