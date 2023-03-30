use ::libc;
extern "C" {
    pub type json_object;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn mc_set_debug(debug: libc::c_int);
    fn json_object_put(obj: *mut json_object) -> libc::c_int;
    fn json_object_get_type(obj: *const json_object) -> json_type;
    fn json_object_to_json_string(obj: *mut json_object) -> *const libc::c_char;
    fn json_tokener_parse(str: *const libc::c_char) -> *mut json_object;
    fn json_c_visit(
        jso: *mut json_object,
        future_flags: libc::c_int,
        userfunc: Option::<json_c_visit_userfunc>,
        userarg: *mut libc::c_void,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type json_type = libc::c_uint;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
pub type json_c_visit_userfunc = unsafe extern "C" fn(
    *mut json_object,
    libc::c_int,
    *mut json_object,
    *const libc::c_char,
    *mut size_t,
    *mut libc::c_void,
) -> libc::c_int;
unsafe fn main_0() -> libc::c_int {
    let mut input: *const libc::c_char = b"{\t\t\"obj1\": 123,\t\t\"obj2\": {\t\t\t\"subobj1\": \"aaa\",\t\t\t\"subobj2\": \"bbb\",\t\t\t\"subobj3\": [ \"elem1\", \"elem2\", true ],\t\t},\t\t\"obj3\": 1.234,\t\t\"obj4\": [ true, false, null ]\t}\0"
        as *const u8 as *const libc::c_char;
    let mut jso: *mut json_object = json_tokener_parse(input);
    printf(
        b"jso.to_string()=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(jso),
    );
    let mut rv: libc::c_int = 0;
    rv = json_c_visit(
        jso,
        0 as libc::c_int,
        Some(emit_object as json_c_visit_userfunc),
        0 as *mut libc::c_void,
    );
    printf(b"json_c_visit(emit_object)=%d\n\0" as *const u8 as *const libc::c_char, rv);
    printf(
        b"================================\n\n\0" as *const u8 as *const libc::c_char,
    );
    rv = json_c_visit(
        jso,
        0 as libc::c_int,
        Some(skip_arrays as json_c_visit_userfunc),
        0 as *mut libc::c_void,
    );
    printf(b"json_c_visit(skip_arrays)=%d\n\0" as *const u8 as *const libc::c_char, rv);
    printf(
        b"================================\n\n\0" as *const u8 as *const libc::c_char,
    );
    rv = json_c_visit(
        jso,
        0 as libc::c_int,
        Some(pop_and_stop as json_c_visit_userfunc),
        0 as *mut libc::c_void,
    );
    printf(b"json_c_visit(pop_and_stop)=%d\n\0" as *const u8 as *const libc::c_char, rv);
    printf(
        b"================================\n\n\0" as *const u8 as *const libc::c_char,
    );
    rv = json_c_visit(
        jso,
        0 as libc::c_int,
        Some(err_on_subobj2 as json_c_visit_userfunc),
        0 as *mut libc::c_void,
    );
    printf(
        b"json_c_visit(err_on_subobj2)=%d\n\0" as *const u8 as *const libc::c_char,
        rv,
    );
    printf(
        b"================================\n\n\0" as *const u8 as *const libc::c_char,
    );
    rv = json_c_visit(
        jso,
        0 as libc::c_int,
        Some(pop_array as json_c_visit_userfunc),
        0 as *mut libc::c_void,
    );
    printf(b"json_c_visit(pop_array)=%d\n\0" as *const u8 as *const libc::c_char, rv);
    printf(
        b"================================\n\n\0" as *const u8 as *const libc::c_char,
    );
    rv = json_c_visit(
        jso,
        0 as libc::c_int,
        Some(stop_array as json_c_visit_userfunc),
        0 as *mut libc::c_void,
    );
    printf(b"json_c_visit(stop_array)=%d\n\0" as *const u8 as *const libc::c_char, rv);
    printf(
        b"================================\n\n\0" as *const u8 as *const libc::c_char,
    );
    rv = json_c_visit(
        jso,
        0 as libc::c_int,
        Some(err_return as json_c_visit_userfunc),
        0 as *mut libc::c_void,
    );
    printf(b"json_c_visit(err_return)=%d\n\0" as *const u8 as *const libc::c_char, rv);
    printf(
        b"================================\n\n\0" as *const u8 as *const libc::c_char,
    );
    json_object_put(jso);
    return 0 as libc::c_int;
}
unsafe extern "C" fn emit_object(
    mut jso: *mut json_object,
    mut flags: libc::c_int,
    mut parent_jso: *mut json_object,
    mut jso_key: *const libc::c_char,
    mut jso_index: *mut size_t,
    mut userarg: *mut libc::c_void,
) -> libc::c_int {
    printf(
        b"flags: 0x%x, key: %s, index: %ld, value: %s\n\0" as *const u8
            as *const libc::c_char,
        flags,
        if !jso_key.is_null() {
            jso_key
        } else {
            b"(null)\0" as *const u8 as *const libc::c_char
        },
        if !jso_index.is_null() {
            *jso_index as libc::c_long
        } else {
            -(1 as libc::c_long)
        },
        json_object_to_json_string(jso),
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn skip_arrays(
    mut jso: *mut json_object,
    mut flags: libc::c_int,
    mut parent_jso: *mut json_object,
    mut jso_key: *const libc::c_char,
    mut jso_index: *mut size_t,
    mut userarg: *mut libc::c_void,
) -> libc::c_int {
    emit_object(jso, flags, parent_jso, jso_key, jso_index, userarg);
    if json_object_get_type(jso) as libc::c_uint
        == json_type_array as libc::c_int as libc::c_uint
    {
        return 7547 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn pop_and_stop(
    mut jso: *mut json_object,
    mut flags: libc::c_int,
    mut parent_jso: *mut json_object,
    mut jso_key: *const libc::c_char,
    mut jso_index: *mut size_t,
    mut userarg: *mut libc::c_void,
) -> libc::c_int {
    emit_object(jso, flags, parent_jso, jso_key, jso_index, userarg);
    if !jso_key.is_null()
        && strcmp(jso_key, b"subobj1\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
    {
        printf(b"POP after handling subobj1\n\0" as *const u8 as *const libc::c_char);
        return 767 as libc::c_int;
    }
    if !jso_key.is_null()
        && strcmp(jso_key, b"obj3\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
    {
        printf(b"STOP after handling obj3\n\0" as *const u8 as *const libc::c_char);
        return 7867 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn err_on_subobj2(
    mut jso: *mut json_object,
    mut flags: libc::c_int,
    mut parent_jso: *mut json_object,
    mut jso_key: *const libc::c_char,
    mut jso_index: *mut size_t,
    mut userarg: *mut libc::c_void,
) -> libc::c_int {
    emit_object(jso, flags, parent_jso, jso_key, jso_index, userarg);
    if !jso_key.is_null()
        && strcmp(jso_key, b"subobj2\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
    {
        printf(b"ERROR after handling subobj1\n\0" as *const u8 as *const libc::c_char);
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn pop_array(
    mut jso: *mut json_object,
    mut flags: libc::c_int,
    mut parent_jso: *mut json_object,
    mut jso_key: *const libc::c_char,
    mut jso_index: *mut size_t,
    mut userarg: *mut libc::c_void,
) -> libc::c_int {
    emit_object(jso, flags, parent_jso, jso_key, jso_index, userarg);
    if !jso_index.is_null() && *jso_index == 0 as libc::c_int as libc::c_ulong {
        printf(b"POP after handling array[0]\n\0" as *const u8 as *const libc::c_char);
        return 767 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn stop_array(
    mut jso: *mut json_object,
    mut flags: libc::c_int,
    mut parent_jso: *mut json_object,
    mut jso_key: *const libc::c_char,
    mut jso_index: *mut size_t,
    mut userarg: *mut libc::c_void,
) -> libc::c_int {
    emit_object(jso, flags, parent_jso, jso_key, jso_index, userarg);
    if !jso_index.is_null() && *jso_index == 0 as libc::c_int as libc::c_ulong {
        printf(b"STOP after handling array[1]\n\0" as *const u8 as *const libc::c_char);
        return 7867 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn err_return(
    mut jso: *mut json_object,
    mut flags: libc::c_int,
    mut parent_jso: *mut json_object,
    mut jso_key: *const libc::c_char,
    mut jso_index: *mut size_t,
    mut userarg: *mut libc::c_void,
) -> libc::c_int {
    printf(
        b"flags: 0x%x, key: %s, index: %ld, value: %s\n\0" as *const u8
            as *const libc::c_char,
        flags,
        if !jso_key.is_null() {
            jso_key
        } else {
            b"(null)\0" as *const u8 as *const libc::c_char
        },
        if !jso_index.is_null() {
            *jso_index as libc::c_long
        } else {
            -(1 as libc::c_long)
        },
        json_object_to_json_string(jso),
    );
    return 100 as libc::c_int;
}
pub fn main() {
    unsafe { ::std::process::exit(main_0() as i32) }
}
