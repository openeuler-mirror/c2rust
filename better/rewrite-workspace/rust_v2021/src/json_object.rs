use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    
    
    
    
    
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strcat(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strstr(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn __errno_location() -> *mut libc::c_int;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn free(__ptr: *mut libc::c_void);
    fn strtod(_: *const libc::c_char, _: *mut *mut libc::c_char) -> libc::c_double;
    fn abort() -> !;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::arraylist::array_list_add;
pub use crate::arraylist::array_list_bsearch;
pub use crate::arraylist::array_list_del_idx;
pub use crate::arraylist::array_list_free;
pub use crate::arraylist::array_list_get_idx;
pub use crate::arraylist::array_list_length;
pub use crate::arraylist::array_list_new2;
pub use crate::arraylist::array_list_put_idx;
pub use crate::arraylist::array_list_shrink;
pub use crate::arraylist::array_list_sort;
pub use crate::json_util::_json_c_set_last_err;
pub use crate::json_util::json_parse_int64;
pub use crate::json_util::json_parse_uint64;
pub use crate::linkhash::lh_kchar_table_new;
pub use crate::linkhash::lh_table_delete;
pub use crate::linkhash::lh_table_free;
pub use crate::linkhash::lh_table_insert_w_hash;
pub use crate::linkhash::lh_table_length;
pub use crate::linkhash::lh_table_lookup_entry_w_hash;
pub use crate::linkhash::lh_table_lookup_ex;
pub use crate::printbuf::printbuf_free;
pub use crate::printbuf::printbuf_memappend;
pub use crate::printbuf::printbuf_memset;
pub use crate::printbuf::printbuf_new;
pub use crate::printbuf::printbuf_reset;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub use crate::apps::json_parse::__off_t;
pub use crate::apps::json_parse::__off64_t;
pub use crate::apps::json_parse::__ssize_t;
pub type int32_t = __int32_t;
pub type int64_t = __int64_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type uintptr_t = libc::c_ulong;
// #[derive(Copy, Clone)]

pub use crate::apps::json_parse::printbuf;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object_iter {
    pub key: *mut libc::c_char,
    pub val: *mut json_object,
    pub entry: *mut lh_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct lh_entry {
    pub k: *const libc::c_void,
    pub k_is_constant: libc::c_int,
    pub v: *const libc::c_void,
    pub next: *mut lh_entry,
    pub prev: *mut lh_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object {
    pub o_type: json_type,
    pub _ref_count: uint32_t,
    pub _to_json_string: Option::<json_object_to_json_string_fn>,
    pub _pb: *mut printbuf,
    pub _user_delete: Option::<json_object_delete_fn>,
    pub _userdata: *mut libc::c_void,
}
pub type json_object_delete_fn = unsafe extern "C" fn(
    *mut json_object,
    *mut libc::c_void,
) -> ();
pub type json_object_to_json_string_fn = unsafe extern "C" fn(
    *mut json_object,
    *mut printbuf,
    libc::c_int,
    libc::c_int,
) -> libc::c_int;
pub type json_type = libc::c_uint;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
pub type json_bool = libc::c_int;
pub use crate::apps::json_parse::size_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub idata: [libc::c_char; 1],
    pub pdata: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object_string {
    pub base: json_object,
    pub len: ssize_t,
    pub c_string: C2RustUnnamed,
}
pub use crate::apps::json_parse::ssize_t;
// #[derive(Copy, Clone)]

pub use crate::arraylist::array_list;
pub use crate::arraylist::array_list_free_fn;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object_array {
    pub base: json_object,
    pub c_array: *mut array_list,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct lh_table {
    pub size: libc::c_int,
    pub count: libc::c_int,
    pub head: *mut lh_entry,
    pub tail: *mut lh_entry,
    pub table: *mut lh_entry,
    pub free_fn: Option::<lh_entry_free_fn>,
    pub hash_fn: Option::<lh_hash_fn>,
    pub equal_fn: Option::<lh_equal_fn>,
}
pub type lh_equal_fn = unsafe extern "C" fn(
    *const libc::c_void,
    *const libc::c_void,
) -> libc::c_int;
pub type lh_hash_fn = unsafe extern "C" fn(*const libc::c_void) -> libc::c_ulong;
pub type lh_entry_free_fn = unsafe extern "C" fn(*mut lh_entry) -> ();
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object_object {
    pub base: json_object,
    pub c_object: *mut lh_table,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub c_int64: int64_t,
    pub c_uint64: uint64_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object_int {
    pub base: json_object,
    pub cint_type: json_object_int_type,
    pub cint: C2RustUnnamed_0,
}
pub type json_object_int_type = libc::c_uint;
pub const json_object_int_type_uint64: json_object_int_type = 1;
pub const json_object_int_type_int64: json_object_int_type = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object_double {
    pub base: json_object,
    pub c_double: libc::c_double,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object_boolean {
    pub base: json_object,
    pub c_boolean: json_bool,
}
pub use crate::apps::json_parse::FILE;
// #[derive(Copy, Clone)]

pub use crate::apps::json_parse::_IO_FILE;
pub use crate::apps::json_parse::_IO_lock_t;
pub type json_c_shallow_copy_fn = unsafe extern "C" fn(
    *mut json_object,
    *mut json_object,
    *const libc::c_char,
    size_t,
    *mut *mut json_object,
) -> libc::c_int;
#[inline]
unsafe extern "C" fn lh_table_head(mut t: *const lh_table) -> *mut lh_entry {
    return (*t).head;
}
#[inline]
unsafe extern "C" fn lh_get_hash(
    mut t: *const lh_table,
    mut k: *const libc::c_void,
) -> libc::c_ulong {
    return ((*t).hash_fn).expect("non-null function pointer")(k);
}
#[inline]
unsafe extern "C" fn lh_entry_k(mut e: *const lh_entry) -> *mut libc::c_void {
    return (*e).k as uintptr_t as *mut libc::c_void;
}
#[inline]
unsafe extern "C" fn lh_entry_k_is_constant(mut e: *const lh_entry) -> libc::c_int {
    return (*e).k_is_constant;
}
#[inline]
unsafe extern "C" fn lh_entry_v(mut e: *const lh_entry) -> *mut libc::c_void {
    return (*e).v as uintptr_t as *mut libc::c_void;
}
#[inline]
unsafe extern "C" fn lh_entry_set_val(
    mut e: *mut lh_entry,
    mut newval: *mut libc::c_void,
) {
    let ref mut fresh0 = (*e).v;
    *fresh0 = newval;
}
#[inline]
unsafe extern "C" fn lh_entry_next(mut e: *const lh_entry) -> *mut lh_entry {
    return (*e).next;
}
#[no_mangle]
pub static mut json_hex_chars: *const libc::c_char = b"0123456789abcdefABCDEF\0"
    as *const u8 as *const libc::c_char;
#[inline]
 extern "C" fn JC_OBJECT(mut jso: *mut json_object) -> *mut json_object_object {
    return jso as *mut libc::c_void as *mut json_object_object;
}
#[inline]
 extern "C" fn JC_OBJECT_C(
    mut jso: *const json_object,
) -> *const json_object_object {
    return jso as *const libc::c_void as *const json_object_object;
}
#[inline]
 extern "C" fn JC_ARRAY(mut jso: *mut json_object) -> *mut json_object_array {
    return jso as *mut libc::c_void as *mut json_object_array;
}
#[inline]
 extern "C" fn JC_ARRAY_C(
    mut jso: *const json_object,
) -> *const json_object_array {
    return jso as *const libc::c_void as *const json_object_array;
}
#[inline]
 extern "C" fn JC_BOOL(mut jso: *mut json_object) -> *mut json_object_boolean {
    return jso as *mut libc::c_void as *mut json_object_boolean;
}
#[inline]
 extern "C" fn JC_BOOL_C(
    mut jso: *const json_object,
) -> *const json_object_boolean {
    return jso as *const libc::c_void as *const json_object_boolean;
}
#[inline]
 extern "C" fn JC_DOUBLE(mut jso: *mut json_object) -> *mut json_object_double {
    return jso as *mut libc::c_void as *mut json_object_double;
}
#[inline]
 extern "C" fn JC_DOUBLE_C(
    mut jso: *const json_object,
) -> *const json_object_double {
    return jso as *const libc::c_void as *const json_object_double;
}
#[inline]
 extern "C" fn JC_INT(mut jso: *mut json_object) -> *mut json_object_int {
    return jso as *mut libc::c_void as *mut json_object_int;
}
#[inline]
 extern "C" fn JC_INT_C(mut jso: *const json_object) -> *const json_object_int {
    return jso as *const libc::c_void as *const json_object_int;
}
#[inline]
 extern "C" fn JC_STRING(mut jso: *mut json_object) -> *mut json_object_string {
    return jso as *mut libc::c_void as *mut json_object_string;
}
#[inline]
 extern "C" fn JC_STRING_C(
    mut jso: *const json_object,
) -> *const json_object_string {
    return jso as *const libc::c_void as *const json_object_string;
}
#[inline]
unsafe extern "C" fn get_string_component_mutable(
    mut jso: *mut json_object,
) -> *mut libc::c_char {
    if (*JC_STRING_C(jso)).len < 0 as libc::c_int as libc::c_long {
        return (*JC_STRING(jso)).c_string.pdata;
    }
    return ((*JC_STRING(jso)).c_string.idata).as_mut_ptr();
}
#[inline]
unsafe extern "C" fn get_string_component(
    mut jso: *const json_object,
) -> *const libc::c_char {
    return get_string_component_mutable(
        jso as *const libc::c_void as uintptr_t as *mut libc::c_void as *mut json_object,
    );
}
unsafe extern "C" fn json_escape_str(
    mut pb: *mut printbuf,
    mut str: *const libc::c_char,
    mut len: size_t,
    mut flags: libc::c_int,
) -> libc::c_int {
    let mut pos: size_t = 0 as libc::c_int as size_t;
    let mut start_offset: size_t = 0 as libc::c_int as size_t;
    let mut c: libc::c_uchar = 0;
    while len != 0 {
        len = len.wrapping_sub(1);
        c = *str.offset(pos as isize) as libc::c_uchar;
        match c as libc::c_int {
            8 | 10 | 13 | 9 | 12 | 34 | 92 | 47 => {
                if flags & (1 as libc::c_int) << 4 as libc::c_int != 0
                    && c as libc::c_int == '/' as i32
                {
                    pos = pos.wrapping_add(1);
                } else {
                    if pos > start_offset {
                        printbuf_memappend(
                            pb,
                            str.offset(start_offset as isize),
                            pos.wrapping_sub(start_offset) as libc::c_int,
                        );
                    }
                    if c as libc::c_int == '\u{8}' as i32 {
                        printbuf_memappend(
                            pb,
                            b"\\b\0" as *const u8 as *const libc::c_char,
                            2 as libc::c_int,
                        );
                    } else if c as libc::c_int == '\n' as i32 {
                        printbuf_memappend(
                            pb,
                            b"\\n\0" as *const u8 as *const libc::c_char,
                            2 as libc::c_int,
                        );
                    } else if c as libc::c_int == '\r' as i32 {
                        printbuf_memappend(
                            pb,
                            b"\\r\0" as *const u8 as *const libc::c_char,
                            2 as libc::c_int,
                        );
                    } else if c as libc::c_int == '\t' as i32 {
                        printbuf_memappend(
                            pb,
                            b"\\t\0" as *const u8 as *const libc::c_char,
                            2 as libc::c_int,
                        );
                    } else if c as libc::c_int == '\u{c}' as i32 {
                        printbuf_memappend(
                            pb,
                            b"\\f\0" as *const u8 as *const libc::c_char,
                            2 as libc::c_int,
                        );
                    } else if c as libc::c_int == '"' as i32 {
                        printbuf_memappend(
                            pb,
                            b"\\\"\0" as *const u8 as *const libc::c_char,
                            2 as libc::c_int,
                        );
                    } else if c as libc::c_int == '\\' as i32 {
                        printbuf_memappend(
                            pb,
                            b"\\\\\0" as *const u8 as *const libc::c_char,
                            2 as libc::c_int,
                        );
                    } else if c as libc::c_int == '/' as i32 {
                        printbuf_memappend(
                            pb,
                            b"\\/\0" as *const u8 as *const libc::c_char,
                            2 as libc::c_int,
                        );
                    }
                    pos = pos.wrapping_add(1);
                    start_offset = pos;
                }
            }
            _ => {
                if (c as libc::c_int) < ' ' as i32 {
                    let mut sbuf: [libc::c_char; 7] = [0; 7];
                    if pos > start_offset {
                        printbuf_memappend(
                            pb,
                            str.offset(start_offset as isize),
                            pos.wrapping_sub(start_offset) as libc::c_int,
                        );
                    }
                    snprintf(
                        sbuf.as_mut_ptr(),
                        ::std::mem::size_of::<[libc::c_char; 7]>() as libc::c_ulong,
                        b"\\u00%c%c\0" as *const u8 as *const libc::c_char,
                        *json_hex_chars
                            .offset((c as libc::c_int >> 4 as libc::c_int) as isize)
                            as libc::c_int,
                        *json_hex_chars
                            .offset((c as libc::c_int & 0xf as libc::c_int) as isize)
                            as libc::c_int,
                    );
                    if (*pb).size - (*pb).bpos
                        > ::std::mem::size_of::<[libc::c_char; 7]>() as libc::c_ulong
                            as libc::c_int - 1 as libc::c_int
                    {
                        memcpy(
                            ((*pb).buf).offset((*pb).bpos as isize) as *mut libc::c_void,
                            sbuf.as_mut_ptr() as *const libc::c_void,
                            (::std::mem::size_of::<[libc::c_char; 7]>() as libc::c_ulong
                                as libc::c_int - 1 as libc::c_int) as libc::c_ulong,
                        );
                        (*pb).bpos
                            += ::std::mem::size_of::<[libc::c_char; 7]>()
                                as libc::c_ulong as libc::c_int - 1 as libc::c_int;
                        *((*pb).buf)
                            .offset(
                                (*pb).bpos as isize,
                            ) = '\u{0}' as i32 as libc::c_char;
                    } else {
                        printbuf_memappend(
                            pb,
                            sbuf.as_mut_ptr(),
                            ::std::mem::size_of::<[libc::c_char; 7]>() as libc::c_ulong
                                as libc::c_int - 1 as libc::c_int,
                        );
                    }
                    pos = pos.wrapping_add(1);
                    start_offset = pos;
                } else {
                    pos = pos.wrapping_add(1);
                }
            }
        }
    }
    if pos > start_offset {
        printbuf_memappend(
            pb,
            str.offset(start_offset as isize),
            pos.wrapping_sub(start_offset) as libc::c_int,
        );
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_get(mut jso: *mut json_object) -> *mut json_object {
    if jso.is_null() {
        return jso;
    }
    if (*jso)._ref_count < 4294967295 as libc::c_uint {} else {
        __assert_fail(
            b"jso->_ref_count < UINT32_MAX\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const libc::c_char,
            254 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 58],
                &[libc::c_char; 58],
            >(b"struct json_object *json_object_get(struct json_object *)\0"))
                .as_ptr(),
        );
    }
    let ref mut fresh1 = (*jso)._ref_count;
    *fresh1 = (*fresh1).wrapping_add(1);
    return jso;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_put(mut jso: *mut json_object) -> libc::c_int {
    if jso.is_null() {
        return 0 as libc::c_int;
    }
    if (*jso)._ref_count > 0 as libc::c_int as libc::c_uint {} else {
        __assert_fail(
            b"jso->_ref_count > 0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const libc::c_char,
            273 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 42],
                &[libc::c_char; 42],
            >(b"int json_object_put(struct json_object *)\0"))
                .as_ptr(),
        );
    }
    let ref mut fresh2 = (*jso)._ref_count;
    *fresh2 = (*fresh2).wrapping_sub(1);
    if *fresh2 > 0 as libc::c_int as libc::c_uint {
        return 0 as libc::c_int;
    }
    if ((*jso)._user_delete).is_some() {
        ((*jso)._user_delete).expect("non-null function pointer")(jso, (*jso)._userdata);
    }
    match (*jso).o_type as libc::c_uint {
        4 => {
            json_object_object_delete(jso);
        }
        5 => {
            json_object_array_delete(jso);
        }
        6 => {
            json_object_string_delete(jso);
        }
        _ => {
            json_object_generic_delete(jso);
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn json_object_generic_delete(mut jso: *mut json_object) {
    printbuf_free((*jso)._pb);
    free(jso as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn json_object_new(
    mut o_type: json_type,
    mut alloc_size: size_t,
    mut to_json_string: Option::<json_object_to_json_string_fn>,
) -> *mut json_object {
    let mut jso: *mut json_object = 0 as *mut json_object;
    jso = malloc(alloc_size) as *mut json_object;
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    (*jso).o_type = o_type;
    (*jso)._ref_count = 1 as libc::c_int as uint32_t;
    let ref mut fresh3 = (*jso)._to_json_string;
    *fresh3 = to_json_string;
    let ref mut fresh4 = (*jso)._pb;
    *fresh4 = 0 as *mut printbuf;
    let ref mut fresh5 = (*jso)._user_delete;
    *fresh5 = None;
    let ref mut fresh6 = (*jso)._userdata;
    *fresh6 = 0 as *mut libc::c_void;
    return jso;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_is_type(
    mut jso: *const json_object,
    mut type_0: json_type,
) -> libc::c_int {
    if jso.is_null() {
        return (type_0 as libc::c_uint == json_type_null as libc::c_int as libc::c_uint)
            as libc::c_int;
    }
    return ((*jso).o_type as libc::c_uint == type_0 as libc::c_uint) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_get_type(mut jso: *const json_object) -> json_type {
    if jso.is_null() {
        return json_type_null;
    }
    return (*jso).o_type;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_get_userdata(
    mut jso: *mut json_object,
) -> *mut libc::c_void {
    return if !jso.is_null() { (*jso)._userdata } else { 0 as *mut libc::c_void };
}
#[no_mangle]
pub unsafe extern "C" fn json_object_set_userdata(
    mut jso: *mut json_object,
    mut userdata: *mut libc::c_void,
    mut user_delete: Option::<json_object_delete_fn>,
) {
    if !jso.is_null() {} else {
        __assert_fail(
            b"jso != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const libc::c_char,
            353 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 78],
                &[libc::c_char; 78],
            >(
                b"void json_object_set_userdata(json_object *, void *, json_object_delete_fn *)\0",
            ))
                .as_ptr(),
        );
    }
    if ((*jso)._user_delete).is_some() {
        ((*jso)._user_delete).expect("non-null function pointer")(jso, (*jso)._userdata);
    }
    let ref mut fresh7 = (*jso)._userdata;
    *fresh7 = userdata;
    let ref mut fresh8 = (*jso)._user_delete;
    *fresh8 = user_delete;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_set_serializer(
    mut jso: *mut json_object,
    mut to_string_func: Option::<json_object_to_json_string_fn>,
    mut userdata: *mut libc::c_void,
    mut user_delete: Option::<json_object_delete_fn>,
) {
    json_object_set_userdata(jso, userdata, user_delete);
    if to_string_func.is_none() {
        match (*jso).o_type as libc::c_uint {
            0 => {
                let ref mut fresh9 = (*jso)._to_json_string;
                *fresh9 = None;
            }
            1 => {
                let ref mut fresh10 = (*jso)._to_json_string;
                *fresh10 = Some(
                    json_object_boolean_to_json_string as json_object_to_json_string_fn,
                );
            }
            2 => {
                let ref mut fresh11 = (*jso)._to_json_string;
                *fresh11 = Some(
                    json_object_double_to_json_string_default
                        as json_object_to_json_string_fn,
                );
            }
            3 => {
                let ref mut fresh12 = (*jso)._to_json_string;
                *fresh12 = Some(
                    json_object_int_to_json_string as json_object_to_json_string_fn,
                );
            }
            4 => {
                let ref mut fresh13 = (*jso)._to_json_string;
                *fresh13 = Some(
                    json_object_object_to_json_string as json_object_to_json_string_fn,
                );
            }
            5 => {
                let ref mut fresh14 = (*jso)._to_json_string;
                *fresh14 = Some(
                    json_object_array_to_json_string as json_object_to_json_string_fn,
                );
            }
            6 => {
                let ref mut fresh15 = (*jso)._to_json_string;
                *fresh15 = Some(
                    json_object_string_to_json_string as json_object_to_json_string_fn,
                );
            }
            _ => {}
        }
        return;
    }
    let ref mut fresh16 = (*jso)._to_json_string;
    *fresh16 = to_string_func;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_to_json_string_length(
    mut jso: *mut json_object,
    mut flags: libc::c_int,
    mut length: *mut size_t,
) -> *const libc::c_char {
    let mut r: *const libc::c_char = 0 as *const libc::c_char;
    let mut s: size_t = 0 as libc::c_int as size_t;
    if jso.is_null() {
        s = 4 as libc::c_int as size_t;
        r = b"null\0" as *const u8 as *const libc::c_char;
    } else if !((*jso)._pb).is_null()
            || {
                let ref mut fresh17 = (*jso)._pb;
                *fresh17 = printbuf_new();
                !(*fresh17).is_null()
            }
        {
        printbuf_reset((*jso)._pb);
        if ((*jso)._to_json_string)
            .expect(
                "non-null function pointer",
            )(jso, (*jso)._pb, 0 as libc::c_int, flags) >= 0 as libc::c_int
        {
            s = (*(*jso)._pb).bpos as size_t;
            r = (*(*jso)._pb).buf;
        }
    }
    if !length.is_null() {
        *length = s;
    }
    return r;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_to_json_string_ext(
    mut jso: *mut json_object,
    mut flags: libc::c_int,
) -> *const libc::c_char {
    return json_object_to_json_string_length(jso, flags, 0 as *mut size_t);
}
#[no_mangle]
pub unsafe extern "C" fn json_object_to_json_string(
    mut jso: *mut json_object,
) -> *const libc::c_char {
    return json_object_to_json_string_ext(jso, (1 as libc::c_int) << 0 as libc::c_int);
}
unsafe extern "C" fn indent(
    mut pb: *mut printbuf,
    mut level: libc::c_int,
    mut flags: libc::c_int,
) {
    if flags & (1 as libc::c_int) << 1 as libc::c_int != 0 {
        if flags & (1 as libc::c_int) << 3 as libc::c_int != 0 {
            printbuf_memset(pb, -(1 as libc::c_int), '\t' as i32, level);
        } else {
            printbuf_memset(
                pb,
                -(1 as libc::c_int),
                ' ' as i32,
                level * 2 as libc::c_int,
            );
        }
    }
}
unsafe extern "C" fn json_object_object_to_json_string(
    mut jso: *mut json_object,
    mut pb: *mut printbuf,
    mut level: libc::c_int,
    mut flags: libc::c_int,
) -> libc::c_int {
    let mut had_children: libc::c_int = 0 as libc::c_int;
    let mut iter: json_object_iter = json_object_iter {
        key: 0 as *mut libc::c_char,
        val: 0 as *mut json_object,
        entry: 0 as *mut lh_entry,
    };
    printbuf_memappend(
        pb,
        b"{\0" as *const u8 as *const libc::c_char,
        (::std::mem::size_of::<[libc::c_char; 2]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
    );
    iter.entry = lh_table_head(json_object_get_object(jso));
    while !if !(iter.entry).is_null() {
        iter.key = lh_entry_k(iter.entry) as *mut libc::c_char;
        iter.val = lh_entry_v(iter.entry) as *mut json_object;
        iter.entry
    } else {
        0 as *mut lh_entry
    }
        .is_null()
    {
        if had_children != 0 {
            printbuf_memappend(
                pb,
                b",\0" as *const u8 as *const libc::c_char,
                (::std::mem::size_of::<[libc::c_char; 2]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
            );
        }
        if flags & (1 as libc::c_int) << 1 as libc::c_int != 0 {
            printbuf_memappend(
                pb,
                b"\n\0" as *const u8 as *const libc::c_char,
                (::std::mem::size_of::<[libc::c_char; 2]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
            );
        }
        had_children = 1 as libc::c_int;
        if flags & (1 as libc::c_int) << 0 as libc::c_int != 0
            && flags & (1 as libc::c_int) << 1 as libc::c_int == 0
        {
            printbuf_memappend(
                pb,
                b" \0" as *const u8 as *const libc::c_char,
                (::std::mem::size_of::<[libc::c_char; 2]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
            );
        }
        indent(pb, level + 1 as libc::c_int, flags);
        printbuf_memappend(
            pb,
            b"\"\0" as *const u8 as *const libc::c_char,
            (::std::mem::size_of::<[libc::c_char; 2]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
        );
        json_escape_str(pb, iter.key, strlen(iter.key), flags);
        if flags & (1 as libc::c_int) << 0 as libc::c_int != 0 {
            printbuf_memappend(
                pb,
                b"\": \0" as *const u8 as *const libc::c_char,
                (::std::mem::size_of::<[libc::c_char; 4]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
            );
        } else {
            printbuf_memappend(
                pb,
                b"\":\0" as *const u8 as *const libc::c_char,
                (::std::mem::size_of::<[libc::c_char; 3]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
            );
        }
        if (iter.val).is_null() {
            printbuf_memappend(
                pb,
                b"null\0" as *const u8 as *const libc::c_char,
                (::std::mem::size_of::<[libc::c_char; 5]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
            );
        } else if ((*iter.val)._to_json_string)
                .expect(
                    "non-null function pointer",
                )(iter.val, pb, level + 1 as libc::c_int, flags) < 0 as libc::c_int
            {
            return -(1 as libc::c_int)
        }
        iter.entry = lh_entry_next(iter.entry);
    }
    if flags & (1 as libc::c_int) << 1 as libc::c_int != 0 && had_children != 0 {
        printbuf_memappend(
            pb,
            b"\n\0" as *const u8 as *const libc::c_char,
            (::std::mem::size_of::<[libc::c_char; 2]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
        );
        indent(pb, level, flags);
    }
    if flags & (1 as libc::c_int) << 0 as libc::c_int != 0
        && flags & (1 as libc::c_int) << 1 as libc::c_int == 0
    {
        return printbuf_memappend(
            pb,
            b" }\0" as *const u8 as *const libc::c_char,
            (::std::mem::size_of::<[libc::c_char; 3]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
        )
    } else {
        return printbuf_memappend(
            pb,
            b"}\0" as *const u8 as *const libc::c_char,
            (::std::mem::size_of::<[libc::c_char; 2]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
        )
    };
}
unsafe extern "C" fn json_object_lh_entry_free(mut ent: *mut lh_entry) {
    if lh_entry_k_is_constant(ent) == 0 {
        free(lh_entry_k(ent));
    }
    json_object_put(lh_entry_v(ent) as *mut json_object);
}
unsafe extern "C" fn json_object_object_delete(mut jso_base: *mut json_object) {
    lh_table_free((*JC_OBJECT(jso_base)).c_object);
    json_object_generic_delete(jso_base);
}
#[no_mangle]
pub unsafe extern "C" fn json_object_new_object() -> *mut json_object {
    let mut jso: *mut json_object_object = json_object_new(
        json_type_object,
        ::std::mem::size_of::<json_object_object>() as libc::c_ulong,
        Some(json_object_object_to_json_string as json_object_to_json_string_fn),
    ) as *mut json_object_object;
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    let ref mut fresh18 = (*jso).c_object;
    *fresh18 = lh_kchar_table_new(
        16 as libc::c_int,
        Some(json_object_lh_entry_free as unsafe extern "C" fn(*mut lh_entry) -> ()),
    );
    if ((*jso).c_object).is_null() {
        json_object_generic_delete(&mut (*jso).base);
        *__errno_location() = 12 as libc::c_int;
        return 0 as *mut json_object;
    }
    return &mut (*jso).base;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_get_object(
    mut jso: *const json_object,
) -> *mut lh_table {
    if jso.is_null() {
        return 0 as *mut lh_table;
    }
    match (*jso).o_type as libc::c_uint {
        4 => return (*JC_OBJECT_C(jso)).c_object,
        _ => return 0 as *mut lh_table,
    };
}
#[no_mangle]
pub unsafe extern "C" fn json_object_object_add_ex(
    mut jso: *mut json_object,
    key: *const libc::c_char,
    val: *mut json_object,
    opts: libc::c_uint,
) -> libc::c_int {
    let mut existing_value: *mut json_object = 0 as *mut json_object;
    let mut existing_entry: *mut lh_entry = 0 as *mut lh_entry;
    let mut hash: libc::c_ulong = 0;
    if json_object_get_type(jso) as libc::c_uint
        == json_type_object as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"json_object_get_type(jso) == json_type_object\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const libc::c_char,
            544 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 118],
                &[libc::c_char; 118],
            >(
                b"int json_object_object_add_ex(struct json_object *, const char *const, struct json_object *const, const unsigned int)\0",
            ))
                .as_ptr(),
        );
    }
    hash = lh_get_hash((*JC_OBJECT(jso)).c_object, key as *const libc::c_void);
    existing_entry = if opts & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
        != 0
    {
        0 as *mut lh_entry
    } else {
        lh_table_lookup_entry_w_hash(
            (*JC_OBJECT(jso)).c_object,
            key as *const libc::c_void,
            hash,
        )
    };
    if jso == val {
        return -(1 as libc::c_int);
    }
    if existing_entry.is_null() {
        let k: *const libc::c_void = if opts
            & ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint != 0
        {
            key as *const libc::c_void
        } else {
            strdup(key) as *const libc::c_void
        };
        if k.is_null() {
            return -(1 as libc::c_int);
        }
        return lh_table_insert_w_hash(
            (*JC_OBJECT(jso)).c_object,
            k,
            val as *const libc::c_void,
            hash,
            opts,
        );
    }
    existing_value = lh_entry_v(existing_entry) as *mut json_object;
    if !existing_value.is_null() {
        json_object_put(existing_value);
    }
    lh_entry_set_val(existing_entry, val as *mut libc::c_void);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_object_add(
    mut jso: *mut json_object,
    mut key: *const libc::c_char,
    mut val: *mut json_object,
) -> libc::c_int {
    return json_object_object_add_ex(jso, key, val, 0 as libc::c_int as libc::c_uint);
}
#[no_mangle]
pub unsafe extern "C" fn json_object_object_length(
    mut jso: *const json_object,
) -> libc::c_int {
    if json_object_get_type(jso) as libc::c_uint
        == json_type_object as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"json_object_get_type(jso) == json_type_object\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const libc::c_char,
            581 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 58],
                &[libc::c_char; 58],
            >(b"int json_object_object_length(const struct json_object *)\0"))
                .as_ptr(),
        );
    }
    return lh_table_length((*JC_OBJECT_C(jso)).c_object);
}
#[no_mangle]
pub extern "C" fn json_c_object_sizeof() -> size_t {
    return ::std::mem::size_of::<json_object>() as libc::c_ulong;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_object_get(
    mut jso: *const json_object,
    mut key: *const libc::c_char,
) -> *mut json_object {
    let mut result: *mut json_object = 0 as *mut json_object;
    json_object_object_get_ex(jso, key, &mut result);
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_object_get_ex(
    mut jso: *const json_object,
    mut key: *const libc::c_char,
    mut value: *mut *mut json_object,
) -> json_bool {
    if !value.is_null() {
        *value = 0 as *mut json_object;
    }
    if jso.is_null() {
        return 0 as libc::c_int;
    }
    match (*jso).o_type as libc::c_uint {
        4 => {
            return lh_table_lookup_ex(
                (*JC_OBJECT_C(jso)).c_object,
                key as *const libc::c_void,
                value as *mut *mut libc::c_void,
            );
        }
        _ => {
            if !value.is_null() {
                *value = 0 as *mut json_object;
            }
            return 0 as libc::c_int;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn json_object_object_del(
    mut jso: *mut json_object,
    mut key: *const libc::c_char,
) {
    if json_object_get_type(jso) as libc::c_uint
        == json_type_object as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"json_object_get_type(jso) == json_type_object\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const libc::c_char,
            620 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 64],
                &[libc::c_char; 64],
            >(b"void json_object_object_del(struct json_object *, const char *)\0"))
                .as_ptr(),
        );
    }
    lh_table_delete((*JC_OBJECT(jso)).c_object, key as *const libc::c_void);
}
unsafe extern "C" fn json_object_boolean_to_json_string(
    mut jso: *mut json_object,
    mut pb: *mut printbuf,
    mut level: libc::c_int,
    mut flags: libc::c_int,
) -> libc::c_int {
    if (*JC_BOOL(jso)).c_boolean != 0 {
        return printbuf_memappend(
            pb,
            b"true\0" as *const u8 as *const libc::c_char,
            (::std::mem::size_of::<[libc::c_char; 5]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
        );
    }
    return printbuf_memappend(
        pb,
        b"false\0" as *const u8 as *const libc::c_char,
        (::std::mem::size_of::<[libc::c_char; 6]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn json_object_new_boolean(mut b: json_bool) -> *mut json_object {
    let mut jso: *mut json_object_boolean = json_object_new(
        json_type_boolean,
        ::std::mem::size_of::<json_object_boolean>() as libc::c_ulong,
        Some(json_object_boolean_to_json_string as json_object_to_json_string_fn),
    ) as *mut json_object_boolean;
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    (*jso).c_boolean = b;
    return &mut (*jso).base;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_get_boolean(
    mut jso: *const json_object,
) -> json_bool {
    if jso.is_null() {
        return 0 as libc::c_int;
    }
    match (*jso).o_type as libc::c_uint {
        1 => return (*JC_BOOL_C(jso)).c_boolean,
        3 => {
            match (*JC_INT_C(jso)).cint_type as libc::c_uint {
                0 => {
                    return ((*JC_INT_C(jso)).cint.c_int64
                        != 0 as libc::c_int as libc::c_long) as libc::c_int;
                }
                1 => {
                    return ((*JC_INT_C(jso)).cint.c_uint64
                        != 0 as libc::c_int as libc::c_ulong) as libc::c_int;
                }
                _ => {
                    json_abort(
                        b"invalid cint_type\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
        }
        2 => {
            return ((*JC_DOUBLE_C(jso)).c_double != 0 as libc::c_int as libc::c_double)
                as libc::c_int;
        }
        6 => {
            return ((*JC_STRING_C(jso)).len != 0 as libc::c_int as libc::c_long)
                as libc::c_int;
        }
        _ => return 0 as libc::c_int,
    };
}
#[no_mangle]
pub unsafe extern "C" fn json_object_set_boolean(
    mut jso: *mut json_object,
    mut new_value: json_bool,
) -> libc::c_int {
    if jso.is_null()
        || (*jso).o_type as libc::c_uint
            != json_type_boolean as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    (*JC_BOOL(jso)).c_boolean = new_value;
    return 1 as libc::c_int;
}
unsafe extern "C" fn json_object_int_to_json_string(
    mut jso: *mut json_object,
    mut pb: *mut printbuf,
    mut level: libc::c_int,
    mut flags: libc::c_int,
) -> libc::c_int {
    let mut sbuf: [libc::c_char; 21] = [0; 21];
    if (*JC_INT(jso)).cint_type as libc::c_uint
        == json_object_int_type_int64 as libc::c_int as libc::c_uint
    {
        snprintf(
            sbuf.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 21]>() as libc::c_ulong,
            b"%ld\0" as *const u8 as *const libc::c_char,
            (*JC_INT(jso)).cint.c_int64,
        );
    } else {
        snprintf(
            sbuf.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 21]>() as libc::c_ulong,
            b"%lu\0" as *const u8 as *const libc::c_char,
            (*JC_INT(jso)).cint.c_uint64,
        );
    }
    return printbuf_memappend(
        pb,
        sbuf.as_mut_ptr(),
        strlen(sbuf.as_mut_ptr()) as libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn json_object_new_int(mut i: int32_t) -> *mut json_object {
    return json_object_new_int64(i as int64_t);
}
#[no_mangle]
pub unsafe extern "C" fn json_object_get_int(mut jso: *const json_object) -> int32_t {
    let mut cint64: int64_t = 0 as libc::c_int as int64_t;
    let mut cdouble: libc::c_double = 0.;
    let mut o_type: json_type = json_type_null;
    if jso.is_null() {
        return 0 as libc::c_int;
    }
    o_type = (*jso).o_type;
    if o_type as libc::c_uint == json_type_int as libc::c_int as libc::c_uint {
        let mut jsoint: *const json_object_int = JC_INT_C(jso);
        if (*jsoint).cint_type as libc::c_uint
            == json_object_int_type_int64 as libc::c_int as libc::c_uint
        {
            cint64 = (*jsoint).cint.c_int64;
        } else if (*jsoint).cint.c_uint64
                >= 9223372036854775807 as libc::c_long as libc::c_ulong
            {
            cint64 = 9223372036854775807 as libc::c_long;
        } else {
            cint64 = (*jsoint).cint.c_uint64 as int64_t;
        }
    } else if o_type as libc::c_uint == json_type_string as libc::c_int as libc::c_uint {
        if json_parse_int64(get_string_component(jso), &mut cint64) != 0 as libc::c_int {
            return 0 as libc::c_int;
        }
        o_type = json_type_int;
    }
    match o_type as libc::c_uint {
        3 => {
            if cint64
                <= (-(2147483647 as libc::c_int) - 1 as libc::c_int) as libc::c_long
            {
                return -(2147483647 as libc::c_int) - 1 as libc::c_int;
            }
            if cint64 >= 2147483647 as libc::c_int as libc::c_long {
                return 2147483647 as libc::c_int;
            }
            return cint64 as int32_t;
        }
        2 => {
            cdouble = (*JC_DOUBLE_C(jso)).c_double;
            if cdouble
                <= (-(2147483647 as libc::c_int) - 1 as libc::c_int) as libc::c_double
            {
                return -(2147483647 as libc::c_int) - 1 as libc::c_int;
            }
            if cdouble >= 2147483647 as libc::c_int as libc::c_double {
                return 2147483647 as libc::c_int;
            }
            return cdouble as int32_t;
        }
        1 => return (*JC_BOOL_C(jso)).c_boolean,
        _ => return 0 as libc::c_int,
    };
}
#[no_mangle]
pub unsafe extern "C" fn json_object_set_int(
    mut jso: *mut json_object,
    mut new_value: libc::c_int,
) -> libc::c_int {
    return json_object_set_int64(jso, new_value as int64_t);
}
#[no_mangle]
pub unsafe extern "C" fn json_object_new_int64(mut i: int64_t) -> *mut json_object {
    let mut jso: *mut json_object_int = json_object_new(
        json_type_int,
        ::std::mem::size_of::<json_object_int>() as libc::c_ulong,
        Some(json_object_int_to_json_string as json_object_to_json_string_fn),
    ) as *mut json_object_int;
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    (*jso).cint.c_int64 = i;
    (*jso).cint_type = json_object_int_type_int64;
    return &mut (*jso).base;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_new_uint64(mut i: uint64_t) -> *mut json_object {
    let mut jso: *mut json_object_int = json_object_new(
        json_type_int,
        ::std::mem::size_of::<json_object_int>() as libc::c_ulong,
        Some(json_object_int_to_json_string as json_object_to_json_string_fn),
    ) as *mut json_object_int;
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    (*jso).cint.c_uint64 = i;
    (*jso).cint_type = json_object_int_type_uint64;
    return &mut (*jso).base;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_get_int64(mut jso: *const json_object) -> int64_t {
    let mut cint: int64_t = 0;
    if jso.is_null() {
        return 0 as libc::c_int as int64_t;
    }
    match (*jso).o_type as libc::c_uint {
        3 => {
            let mut jsoint: *const json_object_int = JC_INT_C(jso);
            match (*jsoint).cint_type as libc::c_uint {
                0 => return (*jsoint).cint.c_int64,
                1 => {
                    if (*jsoint).cint.c_uint64
                        >= 9223372036854775807 as libc::c_long as libc::c_ulong
                    {
                        return 9223372036854775807 as libc::c_long;
                    }
                    return (*jsoint).cint.c_uint64 as int64_t;
                }
                _ => {
                    json_abort(
                        b"invalid cint_type\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
        }
        2 => {
            if (*JC_DOUBLE_C(jso)).c_double
                >= 9223372036854775807 as libc::c_long as libc::c_double
            {
                return 9223372036854775807 as libc::c_long;
            }
            if (*JC_DOUBLE_C(jso)).c_double
                <= (-(9223372036854775807 as libc::c_long)
                    - 1 as libc::c_int as libc::c_long) as libc::c_double
            {
                return -(9223372036854775807 as libc::c_long)
                    - 1 as libc::c_int as libc::c_long;
            }
            return (*JC_DOUBLE_C(jso)).c_double as int64_t;
        }
        1 => return (*JC_BOOL_C(jso)).c_boolean as int64_t,
        6 => {
            if json_parse_int64(get_string_component(jso), &mut cint) == 0 as libc::c_int
            {
                return cint;
            }
        }
        _ => {}
    }
    return 0 as libc::c_int as int64_t;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_get_uint64(
    mut jso: *const json_object,
) -> uint64_t {
    let mut cuint: uint64_t = 0;
    if jso.is_null() {
        return 0 as libc::c_int as uint64_t;
    }
    match (*jso).o_type as libc::c_uint {
        3 => {
            let mut jsoint: *const json_object_int = JC_INT_C(jso);
            match (*jsoint).cint_type as libc::c_uint {
                0 => {
                    if (*jsoint).cint.c_int64 < 0 as libc::c_int as libc::c_long {
                        return 0 as libc::c_int as uint64_t;
                    }
                    return (*jsoint).cint.c_int64 as uint64_t;
                }
                1 => return (*jsoint).cint.c_uint64,
                _ => {
                    json_abort(
                        b"invalid cint_type\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
        }
        2 => {
            if (*JC_DOUBLE_C(jso)).c_double
                >= 18446744073709551615 as libc::c_ulong as libc::c_double
            {
                return 18446744073709551615 as libc::c_ulong;
            }
            if (*JC_DOUBLE_C(jso)).c_double < 0 as libc::c_int as libc::c_double {
                return 0 as libc::c_int as uint64_t;
            }
            return (*JC_DOUBLE_C(jso)).c_double as uint64_t;
        }
        1 => return (*JC_BOOL_C(jso)).c_boolean as uint64_t,
        6 => {
            if json_parse_uint64(get_string_component(jso), &mut cuint)
                == 0 as libc::c_int
            {
                return cuint;
            }
        }
        _ => {}
    }
    return 0 as libc::c_int as uint64_t;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_set_int64(
    mut jso: *mut json_object,
    mut new_value: int64_t,
) -> libc::c_int {
    if jso.is_null()
        || (*jso).o_type as libc::c_uint != json_type_int as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    (*JC_INT(jso)).cint.c_int64 = new_value;
    (*JC_INT(jso)).cint_type = json_object_int_type_int64;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_set_uint64(
    mut jso: *mut json_object,
    mut new_value: uint64_t,
) -> libc::c_int {
    if jso.is_null()
        || (*jso).o_type as libc::c_uint != json_type_int as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    (*JC_INT(jso)).cint.c_uint64 = new_value;
    (*JC_INT(jso)).cint_type = json_object_int_type_uint64;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_int_inc(
    mut jso: *mut json_object,
    mut val: int64_t,
) -> libc::c_int {
    let mut jsoint: *mut json_object_int = 0 as *mut json_object_int;
    if jso.is_null()
        || (*jso).o_type as libc::c_uint != json_type_int as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    jsoint = JC_INT(jso);
    match (*jsoint).cint_type as libc::c_uint {
        0 => {
            if val > 0 as libc::c_int as libc::c_long
                && (*jsoint).cint.c_int64 > 9223372036854775807 as libc::c_long - val
            {
                (*jsoint)
                    .cint
                    .c_uint64 = ((*jsoint).cint.c_int64 as uint64_t)
                    .wrapping_add(val as uint64_t);
                (*jsoint).cint_type = json_object_int_type_uint64;
            } else if val < 0 as libc::c_int as libc::c_long
                    && (*jsoint).cint.c_int64
                        < -(9223372036854775807 as libc::c_long)
                            - 1 as libc::c_int as libc::c_long - val
                {
                (*jsoint)
                    .cint
                    .c_int64 = -(9223372036854775807 as libc::c_long)
                    - 1 as libc::c_int as libc::c_long;
            } else {
                let ref mut fresh19 = (*jsoint).cint.c_int64;
                *fresh19 += val;
            }
            return 1 as libc::c_int;
        }
        1 => {
            if val > 0 as libc::c_int as libc::c_long
                && (*jsoint).cint.c_uint64
                    > (18446744073709551615 as libc::c_ulong)
                        .wrapping_sub(val as uint64_t)
            {
                (*jsoint).cint.c_uint64 = 18446744073709551615 as libc::c_ulong;
            } else if val < 0 as libc::c_int as libc::c_long
                    && (*jsoint).cint.c_uint64 < -val as uint64_t
                {
                (*jsoint).cint.c_int64 = (*jsoint).cint.c_uint64 as int64_t + val;
                (*jsoint).cint_type = json_object_int_type_int64;
            } else if val < 0 as libc::c_int as libc::c_long
                    && (*jsoint).cint.c_uint64 >= -val as uint64_t
                {
                let ref mut fresh20 = (*jsoint).cint.c_uint64;
                *fresh20 = (*fresh20 as libc::c_ulong).wrapping_sub(-val as uint64_t)
                    as uint64_t as uint64_t;
            } else {
                let ref mut fresh21 = (*jsoint).cint.c_uint64;
                *fresh21 = (*fresh21 as libc::c_ulong).wrapping_add(val as libc::c_ulong)
                    as uint64_t as uint64_t;
            }
            return 1 as libc::c_int;
        }
        _ => {
            json_abort(b"invalid cint_type\0" as *const u8 as *const libc::c_char);
        }
    };
}
#[thread_local]
static mut tls_serialization_float_format: *mut libc::c_char = 0 as *const libc::c_char
    as *mut libc::c_char;
static mut global_serialization_float_format: *mut libc::c_char = 0
    as *const libc::c_char as *mut libc::c_char;
#[no_mangle]
pub unsafe extern "C" fn json_c_set_serialization_double_format(
    mut double_format: *const libc::c_char,
    mut global_or_thread: libc::c_int,
) -> libc::c_int {
    if global_or_thread == 0 as libc::c_int {
        if !tls_serialization_float_format.is_null() {
            free(tls_serialization_float_format as *mut libc::c_void);
            tls_serialization_float_format = 0 as *mut libc::c_char;
        }
        if !global_serialization_float_format.is_null() {
            free(global_serialization_float_format as *mut libc::c_void);
        }
        if !double_format.is_null() {
            let mut p: *mut libc::c_char = strdup(double_format);
            if p.is_null() {
                _json_c_set_last_err(
                    b"json_c_set_serialization_double_format: out of memory\n\0"
                        as *const u8 as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
            global_serialization_float_format = p;
        } else {
            global_serialization_float_format = 0 as *mut libc::c_char;
        }
    } else if global_or_thread == 1 as libc::c_int {
        if !tls_serialization_float_format.is_null() {
            free(tls_serialization_float_format as *mut libc::c_void);
            tls_serialization_float_format = 0 as *mut libc::c_char;
        }
        if !double_format.is_null() {
            let mut p_0: *mut libc::c_char = strdup(double_format);
            if p_0.is_null() {
                _json_c_set_last_err(
                    b"json_c_set_serialization_double_format: out of memory\n\0"
                        as *const u8 as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
            tls_serialization_float_format = p_0;
        } else {
            tls_serialization_float_format = 0 as *mut libc::c_char;
        }
    } else {
        _json_c_set_last_err(
            b"json_c_set_serialization_double_format: invalid global_or_thread value: %d\n\0"
                as *const u8 as *const libc::c_char,
            global_or_thread,
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn json_object_double_to_json_string_format(
    mut jso: *mut json_object,
    mut pb: *mut printbuf,
    mut level: libc::c_int,
    mut flags: libc::c_int,
    mut format: *const libc::c_char,
) -> libc::c_int {
    let mut jsodbl: *mut json_object_double = JC_DOUBLE(jso);
    let mut buf: [libc::c_char; 128] = [0; 128];
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut q: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut size: libc::c_int = 0;
    if ((*jsodbl).c_double).is_nan() as i32 != 0 {
        size = snprintf(
            buf.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            b"NaN\0" as *const u8 as *const libc::c_char,
        );
    } else if if ((*jsodbl).c_double).is_infinite() {
            if ((*jsodbl).c_double).is_sign_positive() { 1 } else { -1 }
        } else {
            0
        } != 0
        {
        if (*jsodbl).c_double > 0 as libc::c_int as libc::c_double {
            size = snprintf(
                buf.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                b"Infinity\0" as *const u8 as *const libc::c_char,
            );
        } else {
            size = snprintf(
                buf.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                b"-Infinity\0" as *const u8 as *const libc::c_char,
            );
        }
    } else {
        let mut std_format: *const libc::c_char = b"%.17g\0" as *const u8
            as *const libc::c_char;
        let mut format_drops_decimals: libc::c_int = 0 as libc::c_int;
        let mut looks_numeric: libc::c_int = 0 as libc::c_int;
        if format.is_null() {
            if !tls_serialization_float_format.is_null() {
                format = tls_serialization_float_format;
            } else if !global_serialization_float_format.is_null() {
                format = global_serialization_float_format;
            } else {
                format = std_format;
            }
        }
        size = snprintf(
            buf.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            format,
            (*jsodbl).c_double,
        );
        if size < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        p = strchr(buf.as_mut_ptr(), ',' as i32);
        if !p.is_null() {
            *p = '.' as i32 as libc::c_char;
        } else {
            p = strchr(buf.as_mut_ptr(), '.' as i32);
        }
        if format == std_format
            || (strstr(format, b".0f\0" as *const u8 as *const libc::c_char)).is_null()
        {
            format_drops_decimals = 1 as libc::c_int;
        }
        looks_numeric = (buf[0 as libc::c_int as usize] as libc::c_int >= '0' as i32
            && buf[0 as libc::c_int as usize] as libc::c_int <= '9' as i32
            || size > 1 as libc::c_int
                && buf[0 as libc::c_int as usize] as libc::c_int == '-' as i32
                && (buf[1 as libc::c_int as usize] as libc::c_int >= '0' as i32
                    && buf[1 as libc::c_int as usize] as libc::c_int <= '9' as i32))
            as libc::c_int;
        if size
            < ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong
                as libc::c_int - 2 as libc::c_int && looks_numeric != 0 && p.is_null()
            && (strchr(buf.as_mut_ptr(), 'e' as i32)).is_null()
            && format_drops_decimals != 0
        {
            strcat(buf.as_mut_ptr(), b".0\0" as *const u8 as *const libc::c_char);
            size += 2 as libc::c_int;
        }
        if !p.is_null() && flags & (1 as libc::c_int) << 2 as libc::c_int != 0 {
            p = p.offset(1);
            q = p;
            while *q != 0 {
                if *q as libc::c_int != '0' as i32 {
                    p = q;
                }
                q = q.offset(1);
            }
            if *p as libc::c_int != 0 as libc::c_int {
                p = p.offset(1);
                *p = 0 as libc::c_int as libc::c_char;
            }
            size = p.offset_from(buf.as_mut_ptr()) as libc::c_long as libc::c_int;
        }
    }
    if size < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if size
        >= ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong as libc::c_int
    {
        size = (::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int;
    }
    printbuf_memappend(pb, buf.as_mut_ptr(), size);
    return size;
}
unsafe extern "C" fn json_object_double_to_json_string_default(
    mut jso: *mut json_object,
    mut pb: *mut printbuf,
    mut level: libc::c_int,
    mut flags: libc::c_int,
) -> libc::c_int {
    return json_object_double_to_json_string_format(
        jso,
        pb,
        level,
        flags,
        0 as *const libc::c_char,
    );
}
#[no_mangle]
pub unsafe extern "C" fn json_object_double_to_json_string(
    mut jso: *mut json_object,
    mut pb: *mut printbuf,
    mut level: libc::c_int,
    mut flags: libc::c_int,
) -> libc::c_int {
    return json_object_double_to_json_string_format(
        jso,
        pb,
        level,
        flags,
        (*jso)._userdata as *const libc::c_char,
    );
}
#[no_mangle]
pub unsafe extern "C" fn json_object_new_double(
    mut d: libc::c_double,
) -> *mut json_object {
    let mut jso: *mut json_object_double = json_object_new(
        json_type_double,
        ::std::mem::size_of::<json_object_double>() as libc::c_ulong,
        Some(
            json_object_double_to_json_string
                as unsafe extern "C" fn(
                    *mut json_object,
                    *mut printbuf,
                    libc::c_int,
                    libc::c_int,
                ) -> libc::c_int,
        ),
    ) as *mut json_object_double;
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    let ref mut fresh22 = (*jso).base._to_json_string;
    *fresh22 = Some(
        json_object_double_to_json_string_default as json_object_to_json_string_fn,
    );
    (*jso).c_double = d;
    return &mut (*jso).base;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_new_double_s(
    mut d: libc::c_double,
    mut ds: *const libc::c_char,
) -> *mut json_object {
    let mut new_ds: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut jso: *mut json_object = json_object_new_double(d);
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    new_ds = strdup(ds);
    if new_ds.is_null() {
        json_object_generic_delete(jso);
        *__errno_location() = 12 as libc::c_int;
        return 0 as *mut json_object;
    }
    json_object_set_serializer(
        jso,
        Some(_json_object_userdata_to_json_string as json_object_to_json_string_fn),
        new_ds as *mut libc::c_void,
        Some(json_object_free_userdata as json_object_delete_fn),
    );
    return jso;
}
unsafe extern "C" fn _json_object_userdata_to_json_string(
    mut jso: *mut json_object,
    mut pb: *mut printbuf,
    mut level: libc::c_int,
    mut flags: libc::c_int,
) -> libc::c_int {
    return json_object_userdata_to_json_string(jso, pb, level, flags);
}
#[no_mangle]
pub unsafe extern "C" fn json_object_userdata_to_json_string(
    mut jso: *mut json_object,
    mut pb: *mut printbuf,
    mut level: libc::c_int,
    mut flags: libc::c_int,
) -> libc::c_int {
    let mut userdata_len: libc::c_int = strlen((*jso)._userdata as *const libc::c_char)
        as libc::c_int;
    printbuf_memappend(pb, (*jso)._userdata as *const libc::c_char, userdata_len);
    return userdata_len;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_free_userdata(
    mut jso: *mut json_object,
    mut userdata: *mut libc::c_void,
) {
    free(userdata);
}
#[no_mangle]
pub unsafe extern "C" fn json_object_get_double(
    mut jso: *const json_object,
) -> libc::c_double {
    let mut cdouble: libc::c_double = 0.;
    let mut errPtr: *mut libc::c_char = 0 as *mut libc::c_char;
    if jso.is_null() {
        return 0.0f64;
    }
    match (*jso).o_type as libc::c_uint {
        2 => return (*JC_DOUBLE_C(jso)).c_double,
        3 => {
            match (*JC_INT_C(jso)).cint_type as libc::c_uint {
                0 => return (*JC_INT_C(jso)).cint.c_int64 as libc::c_double,
                1 => return (*JC_INT_C(jso)).cint.c_uint64 as libc::c_double,
                _ => {
                    json_abort(
                        b"invalid cint_type\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
        }
        1 => return (*JC_BOOL_C(jso)).c_boolean as libc::c_double,
        6 => {
            *__errno_location() = 0 as libc::c_int;
            cdouble = strtod(get_string_component(jso), &mut errPtr);
            if errPtr == get_string_component(jso) as *mut libc::c_char {
                *__errno_location() = 22 as libc::c_int;
                return 0.0f64;
            }
            if *errPtr as libc::c_int != '\u{0}' as i32 {
                *__errno_location() = 22 as libc::c_int;
                return 0.0f64;
            }
            if (::std::f64::INFINITY == cdouble || -::std::f64::INFINITY == cdouble)
                && 34 as libc::c_int == *__errno_location()
            {
                cdouble = 0.0f64;
            }
            return cdouble;
        }
        _ => {
            *__errno_location() = 22 as libc::c_int;
            return 0.0f64;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn json_object_set_double(
    mut jso: *mut json_object,
    mut new_value: libc::c_double,
) -> libc::c_int {
    if jso.is_null()
        || (*jso).o_type as libc::c_uint
            != json_type_double as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    (*JC_DOUBLE(jso)).c_double = new_value;
    if (*jso)._to_json_string
        == Some(_json_object_userdata_to_json_string as json_object_to_json_string_fn)
    {
        json_object_set_serializer(jso, None, 0 as *mut libc::c_void, None);
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn json_object_string_to_json_string(
    mut jso: *mut json_object,
    mut pb: *mut printbuf,
    mut level: libc::c_int,
    mut flags: libc::c_int,
) -> libc::c_int {
    let mut len: ssize_t = (*JC_STRING(jso)).len;
    printbuf_memappend(
        pb,
        b"\"\0" as *const u8 as *const libc::c_char,
        (::std::mem::size_of::<[libc::c_char; 2]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
    );
    json_escape_str(
        pb,
        get_string_component(jso),
        (if len < 0 as libc::c_int as libc::c_long { -len } else { len }) as size_t,
        flags,
    );
    printbuf_memappend(
        pb,
        b"\"\0" as *const u8 as *const libc::c_char,
        (::std::mem::size_of::<[libc::c_char; 2]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn json_object_string_delete(mut jso: *mut json_object) {
    if (*JC_STRING(jso)).len < 0 as libc::c_int as libc::c_long {
        free((*JC_STRING(jso)).c_string.pdata as *mut libc::c_void);
    }
    json_object_generic_delete(jso);
}
unsafe extern "C" fn _json_object_new_string(
    mut s: *const libc::c_char,
    len: size_t,
) -> *mut json_object {
    let mut objsize: size_t = 0;
    let mut jso: *mut json_object_string = 0 as *mut json_object_string;
    if len
        > (9223372036854775807 as libc::c_long as libc::c_ulong)
            .wrapping_sub(
                (::std::mem::size_of::<json_object_string>() as libc::c_ulong)
                    .wrapping_sub(
                        ::std::mem::size_of::<C2RustUnnamed>() as libc::c_ulong,
                    ),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
    {
        return 0 as *mut json_object;
    }
    objsize = (::std::mem::size_of::<json_object_string>() as libc::c_ulong)
        .wrapping_sub(::std::mem::size_of::<C2RustUnnamed>() as libc::c_ulong)
        .wrapping_add(len)
        .wrapping_add(1 as libc::c_int as libc::c_ulong);
    if len < ::std::mem::size_of::<*mut libc::c_void>() as libc::c_ulong {
        objsize = (objsize as libc::c_ulong)
            .wrapping_add(
                (::std::mem::size_of::<*mut libc::c_void>() as libc::c_ulong)
                    .wrapping_sub(len),
            ) as size_t as size_t;
    }
    jso = json_object_new(
        json_type_string,
        objsize,
        Some(json_object_string_to_json_string as json_object_to_json_string_fn),
    ) as *mut json_object_string;
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    (*jso).len = len as ssize_t;
    memcpy(
        ((*jso).c_string.idata).as_mut_ptr() as *mut libc::c_void,
        s as *const libc::c_void,
        len,
    );
    *((*jso).c_string.idata)
        .as_mut_ptr()
        .offset(len as isize) = '\u{0}' as i32 as libc::c_char;
    return &mut (*jso).base;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_new_string(
    mut s: *const libc::c_char,
) -> *mut json_object {
    return _json_object_new_string(s, strlen(s));
}
#[no_mangle]
pub unsafe extern "C" fn json_object_new_string_len(
    mut s: *const libc::c_char,
    len: libc::c_int,
) -> *mut json_object {
    return _json_object_new_string(s, len as size_t);
}
#[no_mangle]
pub unsafe extern "C" fn json_object_get_string(
    mut jso: *mut json_object,
) -> *const libc::c_char {
    if jso.is_null() {
        return 0 as *const libc::c_char;
    }
    match (*jso).o_type as libc::c_uint {
        6 => return get_string_component(jso),
        _ => return json_object_to_json_string(jso),
    };
}
#[inline]
unsafe extern "C" fn _json_object_get_string_len(
    mut jso: *const json_object_string,
) -> ssize_t {
    let mut len: ssize_t = 0;
    len = (*jso).len;
    return if len < 0 as libc::c_int as libc::c_long { -len } else { len };
}
#[no_mangle]
pub unsafe extern "C" fn json_object_get_string_len(
    mut jso: *const json_object,
) -> libc::c_int {
    if jso.is_null() {
        return 0 as libc::c_int;
    }
    match (*jso).o_type as libc::c_uint {
        6 => return _json_object_get_string_len(JC_STRING_C(jso)) as libc::c_int,
        _ => return 0 as libc::c_int,
    };
}
unsafe extern "C" fn _json_object_set_string_len(
    mut jso: *mut json_object,
    mut s: *const libc::c_char,
    mut len: size_t,
) -> libc::c_int {
    let mut dstbuf: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut curlen: ssize_t = 0;
    let mut newlen: ssize_t = 0;
    if jso.is_null()
        || (*jso).o_type as libc::c_uint
            != json_type_string as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    if len >= (2147483647 as libc::c_int - 1 as libc::c_int) as libc::c_ulong {
        return 0 as libc::c_int;
    }
    curlen = (*JC_STRING(jso)).len;
    if curlen < 0 as libc::c_int as libc::c_long {
        if len == 0 as libc::c_int as libc::c_ulong {
            free((*JC_STRING(jso)).c_string.pdata as *mut libc::c_void);
            curlen = 0 as libc::c_int as ssize_t;
            (*JC_STRING(jso)).len = curlen;
        } else {
            curlen = -curlen;
        }
    }
    newlen = len as ssize_t;
    dstbuf = get_string_component_mutable(jso);
    if len as ssize_t > curlen {
        dstbuf = malloc(len.wrapping_add(1 as libc::c_int as libc::c_ulong))
            as *mut libc::c_char;
        if dstbuf.is_null() {
            return 0 as libc::c_int;
        }
        if (*JC_STRING(jso)).len < 0 as libc::c_int as libc::c_long {
            free((*JC_STRING(jso)).c_string.pdata as *mut libc::c_void);
        }
        let ref mut fresh23 = (*JC_STRING(jso)).c_string.pdata;
        *fresh23 = dstbuf;
        newlen = -(len as ssize_t);
    } else if (*JC_STRING(jso)).len < 0 as libc::c_int as libc::c_long {
        newlen = -(len as ssize_t);
    }
    memcpy(dstbuf as *mut libc::c_void, s as *const libc::c_void, len);
    *dstbuf.offset(len as isize) = '\u{0}' as i32 as libc::c_char;
    (*JC_STRING(jso)).len = newlen;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_set_string(
    mut jso: *mut json_object,
    mut s: *const libc::c_char,
) -> libc::c_int {
    return _json_object_set_string_len(jso, s, strlen(s));
}
#[no_mangle]
pub unsafe extern "C" fn json_object_set_string_len(
    mut jso: *mut json_object,
    mut s: *const libc::c_char,
    mut len: libc::c_int,
) -> libc::c_int {
    return _json_object_set_string_len(jso, s, len as size_t);
}
unsafe extern "C" fn json_object_array_to_json_string(
    mut jso: *mut json_object,
    mut pb: *mut printbuf,
    mut level: libc::c_int,
    mut flags: libc::c_int,
) -> libc::c_int {
    let mut had_children: libc::c_int = 0 as libc::c_int;
    let mut ii: size_t = 0;
    printbuf_memappend(
        pb,
        b"[\0" as *const u8 as *const libc::c_char,
        (::std::mem::size_of::<[libc::c_char; 2]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
    );
    ii = 0 as libc::c_int as size_t;
    while ii < json_object_array_length(jso) {
        let mut val: *mut json_object = 0 as *mut json_object;
        if had_children != 0 {
            printbuf_memappend(
                pb,
                b",\0" as *const u8 as *const libc::c_char,
                (::std::mem::size_of::<[libc::c_char; 2]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
            );
        }
        if flags & (1 as libc::c_int) << 1 as libc::c_int != 0 {
            printbuf_memappend(
                pb,
                b"\n\0" as *const u8 as *const libc::c_char,
                (::std::mem::size_of::<[libc::c_char; 2]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
            );
        }
        had_children = 1 as libc::c_int;
        if flags & (1 as libc::c_int) << 0 as libc::c_int != 0
            && flags & (1 as libc::c_int) << 1 as libc::c_int == 0
        {
            printbuf_memappend(
                pb,
                b" \0" as *const u8 as *const libc::c_char,
                (::std::mem::size_of::<[libc::c_char; 2]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
            );
        }
        indent(pb, level + 1 as libc::c_int, flags);
        val = json_object_array_get_idx(jso, ii);
        if val.is_null() {
            printbuf_memappend(
                pb,
                b"null\0" as *const u8 as *const libc::c_char,
                (::std::mem::size_of::<[libc::c_char; 5]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
            );
        } else if ((*val)._to_json_string)
                .expect(
                    "non-null function pointer",
                )(val, pb, level + 1 as libc::c_int, flags) < 0 as libc::c_int
            {
            return -(1 as libc::c_int)
        }
        ii = ii.wrapping_add(1);
    }
    if flags & (1 as libc::c_int) << 1 as libc::c_int != 0 && had_children != 0 {
        printbuf_memappend(
            pb,
            b"\n\0" as *const u8 as *const libc::c_char,
            (::std::mem::size_of::<[libc::c_char; 2]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
        );
        indent(pb, level, flags);
    }
    if flags & (1 as libc::c_int) << 0 as libc::c_int != 0
        && flags & (1 as libc::c_int) << 1 as libc::c_int == 0
    {
        return printbuf_memappend(
            pb,
            b" ]\0" as *const u8 as *const libc::c_char,
            (::std::mem::size_of::<[libc::c_char; 3]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
        );
    }
    return printbuf_memappend(
        pb,
        b"]\0" as *const u8 as *const libc::c_char,
        (::std::mem::size_of::<[libc::c_char; 2]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int,
    );
}
unsafe extern "C" fn json_object_array_entry_free(mut data: *mut libc::c_void) {
    json_object_put(data as *mut json_object);
}
unsafe extern "C" fn json_object_array_delete(mut jso: *mut json_object) {
    array_list_free((*JC_ARRAY(jso)).c_array);
    json_object_generic_delete(jso);
}
#[no_mangle]
pub unsafe extern "C" fn json_object_new_array() -> *mut json_object {
    return json_object_new_array_ext(32 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn json_object_new_array_ext(
    mut initial_size: libc::c_int,
) -> *mut json_object {
    let mut jso: *mut json_object_array = json_object_new(
        json_type_array,
        ::std::mem::size_of::<json_object_array>() as libc::c_ulong,
        Some(json_object_array_to_json_string as json_object_to_json_string_fn),
    ) as *mut json_object_array;
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    let ref mut fresh24 = (*jso).c_array;
    *fresh24 = array_list_new2(
        Some(
            json_object_array_entry_free as unsafe extern "C" fn(*mut libc::c_void) -> (),
        ),
        initial_size,
    );
    if ((*jso).c_array).is_null() {
        free(jso as *mut libc::c_void);
        return 0 as *mut json_object;
    }
    return &mut (*jso).base;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_get_array(
    mut jso: *const json_object,
) -> *mut array_list {
    if jso.is_null() {
        return 0 as *mut array_list;
    }
    match (*jso).o_type as libc::c_uint {
        5 => return (*JC_ARRAY_C(jso)).c_array,
        _ => return 0 as *mut array_list,
    };
}
#[no_mangle]
pub unsafe extern "C" fn json_object_array_sort(
    mut jso: *mut json_object,
    mut sort_fn: Option::<
        unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
    >,
) {
    if json_object_get_type(jso) as libc::c_uint
        == json_type_array as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"json_object_get_type(jso) == json_type_array\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const libc::c_char,
            1453 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 87],
                &[libc::c_char; 87],
            >(
                b"void json_object_array_sort(struct json_object *, int (*)(const void *, const void *))\0",
            ))
                .as_ptr(),
        );
    }
    array_list_sort((*JC_ARRAY(jso)).c_array, sort_fn);
}
#[no_mangle]
pub unsafe extern "C" fn json_object_array_bsearch(
    mut key: *const json_object,
    mut jso: *const json_object,
    mut sort_fn: Option::<
        unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
    >,
) -> *mut json_object {
    let mut result: *mut *mut json_object = 0 as *mut *mut json_object;
    if json_object_get_type(jso) as libc::c_uint
        == json_type_array as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"json_object_get_type(jso) == json_type_array\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const libc::c_char,
            1463 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 139],
                &[libc::c_char; 139],
            >(
                b"struct json_object *json_object_array_bsearch(const struct json_object *, const struct json_object *, int (*)(const void *, const void *))\0",
            ))
                .as_ptr(),
        );
    }
    result = array_list_bsearch(
        &mut key as *mut *const json_object as *mut libc::c_void
            as *mut *const libc::c_void,
        (*JC_ARRAY_C(jso)).c_array,
        sort_fn,
    ) as *mut *mut json_object;
    if result.is_null() {
        return 0 as *mut json_object;
    }
    return *result;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_array_length(
    mut jso: *const json_object,
) -> size_t {
    if json_object_get_type(jso) as libc::c_uint
        == json_type_array as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"json_object_get_type(jso) == json_type_array\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const libc::c_char,
            1474 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 60],
                &[libc::c_char; 60],
            >(b"size_t json_object_array_length(const struct json_object *)\0"))
                .as_ptr(),
        );
    }
    return array_list_length((*JC_ARRAY_C(jso)).c_array);
}
#[no_mangle]
pub unsafe extern "C" fn json_object_array_add(
    mut jso: *mut json_object,
    mut val: *mut json_object,
) -> libc::c_int {
    if json_object_get_type(jso) as libc::c_uint
        == json_type_array as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"json_object_get_type(jso) == json_type_array\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const libc::c_char,
            1480 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 70],
                &[libc::c_char; 70],
            >(
                b"int json_object_array_add(struct json_object *, struct json_object *)\0",
            ))
                .as_ptr(),
        );
    }
    return array_list_add((*JC_ARRAY(jso)).c_array, val as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn json_object_array_put_idx(
    mut jso: *mut json_object,
    mut idx: size_t,
    mut val: *mut json_object,
) -> libc::c_int {
    if json_object_get_type(jso) as libc::c_uint
        == json_type_array as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"json_object_get_type(jso) == json_type_array\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const libc::c_char,
            1486 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 82],
                &[libc::c_char; 82],
            >(
                b"int json_object_array_put_idx(struct json_object *, size_t, struct json_object *)\0",
            ))
                .as_ptr(),
        );
    }
    return array_list_put_idx((*JC_ARRAY(jso)).c_array, idx, val as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn json_object_array_del_idx(
    mut jso: *mut json_object,
    mut idx: size_t,
    mut count: size_t,
) -> libc::c_int {
    if json_object_get_type(jso) as libc::c_uint
        == json_type_array as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"json_object_get_type(jso) == json_type_array\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const libc::c_char,
            1492 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 68],
                &[libc::c_char; 68],
            >(b"int json_object_array_del_idx(struct json_object *, size_t, size_t)\0"))
                .as_ptr(),
        );
    }
    return array_list_del_idx((*JC_ARRAY(jso)).c_array, idx, count);
}
#[no_mangle]
pub unsafe extern "C" fn json_object_array_get_idx(
    mut jso: *const json_object,
    mut idx: size_t,
) -> *mut json_object {
    if json_object_get_type(jso) as libc::c_uint
        == json_type_array as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"json_object_get_type(jso) == json_type_array\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const libc::c_char,
            1498 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 82],
                &[libc::c_char; 82],
            >(
                b"struct json_object *json_object_array_get_idx(const struct json_object *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    return array_list_get_idx((*JC_ARRAY_C(jso)).c_array, idx) as *mut json_object;
}
unsafe extern "C" fn json_array_equal(
    mut jso1: *mut json_object,
    mut jso2: *mut json_object,
) -> libc::c_int {
    let mut len: size_t = 0;
    let mut i: size_t = 0;
    len = json_object_array_length(jso1);
    if len != json_object_array_length(jso2) {
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int as size_t;
    while i < len {
        if json_object_equal(
            json_object_array_get_idx(jso1, i),
            json_object_array_get_idx(jso2, i),
        ) == 0
        {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_array_shrink(
    mut jso: *mut json_object,
    mut empty_slots: libc::c_int,
) -> libc::c_int {
    if empty_slots < 0 as libc::c_int {
        json_abort(
            b"json_object_array_shrink called with negative empty_slots\0" as *const u8
                as *const libc::c_char,
        );
    }
    return array_list_shrink((*JC_ARRAY(jso)).c_array, empty_slots as size_t);
}
#[no_mangle]
pub extern "C" fn json_object_new_null() -> *mut json_object {
    return 0 as *mut json_object;
}
unsafe extern "C" fn json_object_all_values_equal(
    mut jso1: *mut json_object,
    mut jso2: *mut json_object,
) -> libc::c_int {
    let mut iter: json_object_iter = json_object_iter {
        key: 0 as *mut libc::c_char,
        val: 0 as *mut json_object,
        entry: 0 as *mut lh_entry,
    };
    let mut sub: *mut json_object = 0 as *mut json_object;
    if json_object_get_type(jso1) as libc::c_uint
        == json_type_object as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"json_object_get_type(jso1) == json_type_object\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const libc::c_char,
            1536 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 77],
                &[libc::c_char; 77],
            >(
                b"int json_object_all_values_equal(struct json_object *, struct json_object *)\0",
            ))
                .as_ptr(),
        );
    }
    if json_object_get_type(jso2) as libc::c_uint
        == json_type_object as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"json_object_get_type(jso2) == json_type_object\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const libc::c_char,
            1537 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 77],
                &[libc::c_char; 77],
            >(
                b"int json_object_all_values_equal(struct json_object *, struct json_object *)\0",
            ))
                .as_ptr(),
        );
    }
    iter.entry = lh_table_head(json_object_get_object(jso1));
    while !if !(iter.entry).is_null() {
        iter.key = lh_entry_k(iter.entry) as *mut libc::c_char;
        iter.val = lh_entry_v(iter.entry) as *mut json_object;
        iter.entry
    } else {
        0 as *mut lh_entry
    }
        .is_null()
    {
        if lh_table_lookup_ex(
            (*JC_OBJECT(jso2)).c_object,
            iter.key as *mut libc::c_void,
            &mut sub as *mut *mut json_object as *mut libc::c_void
                as *mut *mut libc::c_void,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        if json_object_equal(iter.val, sub) == 0 {
            return 0 as libc::c_int;
        }
        iter.entry = lh_entry_next(iter.entry);
    }
    iter.entry = lh_table_head(json_object_get_object(jso2));
    while !if !(iter.entry).is_null() {
        iter.key = lh_entry_k(iter.entry) as *mut libc::c_char;
        iter.val = lh_entry_v(iter.entry) as *mut json_object;
        iter.entry
    } else {
        0 as *mut lh_entry
    }
        .is_null()
    {
        if lh_table_lookup_ex(
            (*JC_OBJECT(jso1)).c_object,
            iter.key as *mut libc::c_void,
            &mut sub as *mut *mut json_object as *mut libc::c_void
                as *mut *mut libc::c_void,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        iter.entry = lh_entry_next(iter.entry);
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_equal(
    mut jso1: *mut json_object,
    mut jso2: *mut json_object,
) -> libc::c_int {
    if jso1 == jso2 {
        return 1 as libc::c_int;
    }
    if jso1.is_null() || jso2.is_null() {
        return 0 as libc::c_int;
    }
    if (*jso1).o_type as libc::c_uint != (*jso2).o_type as libc::c_uint {
        return 0 as libc::c_int;
    }
    match (*jso1).o_type as libc::c_uint {
        1 => {
            return ((*JC_BOOL(jso1)).c_boolean == (*JC_BOOL(jso2)).c_boolean)
                as libc::c_int;
        }
        2 => {
            return ((*JC_DOUBLE(jso1)).c_double == (*JC_DOUBLE(jso2)).c_double)
                as libc::c_int;
        }
        3 => {
            let mut int1: *mut json_object_int = JC_INT(jso1);
            let mut int2: *mut json_object_int = JC_INT(jso2);
            if (*int1).cint_type as libc::c_uint
                == json_object_int_type_int64 as libc::c_int as libc::c_uint
            {
                if (*int2).cint_type as libc::c_uint
                    == json_object_int_type_int64 as libc::c_int as libc::c_uint
                {
                    return ((*int1).cint.c_int64 == (*int2).cint.c_int64) as libc::c_int;
                }
                if (*int1).cint.c_int64 < 0 as libc::c_int as libc::c_long {
                    return 0 as libc::c_int;
                }
                return ((*int1).cint.c_int64 as uint64_t == (*int2).cint.c_uint64)
                    as libc::c_int;
            }
            if (*int2).cint_type as libc::c_uint
                == json_object_int_type_uint64 as libc::c_int as libc::c_uint
            {
                return ((*int1).cint.c_uint64 == (*int2).cint.c_uint64) as libc::c_int;
            }
            if (*int2).cint.c_int64 < 0 as libc::c_int as libc::c_long {
                return 0 as libc::c_int;
            }
            return ((*int1).cint.c_uint64 == (*int2).cint.c_int64 as uint64_t)
                as libc::c_int;
        }
        6 => {
            return (_json_object_get_string_len(JC_STRING(jso1))
                == _json_object_get_string_len(JC_STRING(jso2))
                && memcmp(
                    get_string_component(jso1) as *const libc::c_void,
                    get_string_component(jso2) as *const libc::c_void,
                    _json_object_get_string_len(JC_STRING(jso1)) as libc::c_ulong,
                ) == 0 as libc::c_int) as libc::c_int;
        }
        4 => return json_object_all_values_equal(jso1, jso2),
        5 => return json_array_equal(jso1, jso2),
        0 => return 1 as libc::c_int,
        _ => {}
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn json_object_copy_serializer_data(
    mut src: *mut json_object,
    mut dst: *mut json_object,
) -> libc::c_int {
    if ((*src)._userdata).is_null() && ((*src)._user_delete).is_none() {
        return 0 as libc::c_int;
    }
    if (*dst)._to_json_string
        == Some(json_object_userdata_to_json_string as json_object_to_json_string_fn)
        || (*dst)._to_json_string
            == Some(
                _json_object_userdata_to_json_string as json_object_to_json_string_fn,
            )
    {
        let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
        if !((*src)._userdata).is_null() {} else {
            __assert_fail(
                b"src->_userdata\0" as *const u8 as *const libc::c_char,
                b"/home/xial/json-c/json_object.c\0" as *const u8 as *const libc::c_char,
                1623 as libc::c_int as libc::c_uint,
                (*::std::mem::transmute::<
                    &[u8; 81],
                    &[libc::c_char; 81],
                >(
                    b"int json_object_copy_serializer_data(struct json_object *, struct json_object *)\0",
                ))
                    .as_ptr(),
            );
        }
        p = strdup((*src)._userdata as *const libc::c_char);
        if p.is_null() {
            _json_c_set_last_err(
                b"json_object_copy_serializer_data: out of memory\n\0" as *const u8
                    as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        let ref mut fresh25 = (*dst)._userdata;
        *fresh25 = p as *mut libc::c_void;
    } else {
        _json_c_set_last_err(
            b"json_object_copy_serializer_data: unable to copy unknown serializer data: %p\n\0"
                as *const u8 as *const libc::c_char,
            ::std::mem::transmute::<
                Option::<json_object_to_json_string_fn>,
                *mut libc::c_void,
            >((*dst)._to_json_string),
        );
        return -(1 as libc::c_int);
    }
    let ref mut fresh26 = (*dst)._user_delete;
    *fresh26 = (*src)._user_delete;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn json_c_shallow_copy_default(
    mut src: *mut json_object,
    mut parent: *mut json_object,
    mut key: *const libc::c_char,
    mut index: size_t,
    mut dst: *mut *mut json_object,
) -> libc::c_int {
    match (*src).o_type as libc::c_uint {
        1 => {
            *dst = json_object_new_boolean((*JC_BOOL(src)).c_boolean);
        }
        2 => {
            *dst = json_object_new_double((*JC_DOUBLE(src)).c_double);
        }
        3 => {
            match (*JC_INT(src)).cint_type as libc::c_uint {
                0 => {
                    *dst = json_object_new_int64((*JC_INT(src)).cint.c_int64);
                }
                1 => {
                    *dst = json_object_new_uint64((*JC_INT(src)).cint.c_uint64);
                }
                _ => {
                    json_abort(
                        b"invalid cint_type\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
        }
        6 => {
            *dst = json_object_new_string_len(
                get_string_component(src),
                _json_object_get_string_len(JC_STRING(src)) as libc::c_int,
            );
        }
        4 => {
            *dst = json_object_new_object();
        }
        5 => {
            *dst = json_object_new_array();
        }
        _ => {
            *__errno_location() = 22 as libc::c_int;
            return -(1 as libc::c_int);
        }
    }
    if (*dst).is_null() {
        *__errno_location() = 12 as libc::c_int;
        return -(1 as libc::c_int);
    }
    let ref mut fresh27 = (**dst)._to_json_string;
    *fresh27 = (*src)._to_json_string;
    return 1 as libc::c_int;
}
unsafe extern "C" fn json_object_deep_copy_recursive(
    mut src: *mut json_object,
    mut parent: *mut json_object,
    mut key_in_parent: *const libc::c_char,
    mut index_in_parent: size_t,
    mut dst: *mut *mut json_object,
    mut shallow_copy: Option::<json_c_shallow_copy_fn>,
) -> libc::c_int {
    let mut iter: json_object_iter = json_object_iter {
        key: 0 as *mut libc::c_char,
        val: 0 as *mut json_object,
        entry: 0 as *mut lh_entry,
    };
    let mut src_array_len: size_t = 0;
    let mut ii: size_t = 0;
    let mut shallow_copy_rc: libc::c_int = 0 as libc::c_int;
    shallow_copy_rc = shallow_copy
        .expect(
            "non-null function pointer",
        )(src, parent, key_in_parent, index_in_parent, dst);
    if shallow_copy_rc < 1 as libc::c_int {
        *__errno_location() = 22 as libc::c_int;
        return -(1 as libc::c_int);
    }
    if !(*dst).is_null() {} else {
        __assert_fail(
            b"*dst != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const libc::c_char,
            1718 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 151],
                &[libc::c_char; 151],
            >(
                b"int json_object_deep_copy_recursive(struct json_object *, struct json_object *, const char *, size_t, struct json_object **, json_c_shallow_copy_fn *)\0",
            ))
                .as_ptr(),
        );
    }
    match (*src).o_type as libc::c_uint {
        4 => {
            iter.entry = lh_table_head(json_object_get_object(src));
            while !if !(iter.entry).is_null() {
                iter.key = lh_entry_k(iter.entry) as *mut libc::c_char;
                iter.val = lh_entry_v(iter.entry) as *mut json_object;
                iter.entry
            } else {
                0 as *mut lh_entry
            }
                .is_null()
            {
                let mut jso: *mut json_object = 0 as *mut json_object;
                if (iter.val).is_null() {
                    jso = 0 as *mut json_object;
                } else if json_object_deep_copy_recursive(
                        iter.val,
                        src,
                        iter.key,
                        (2147483647 as libc::c_int as libc::c_uint)
                            .wrapping_mul(2 as libc::c_uint)
                            .wrapping_add(1 as libc::c_uint) as size_t,
                        &mut jso,
                        shallow_copy,
                    ) < 0 as libc::c_int
                    {
                    json_object_put(jso);
                    return -(1 as libc::c_int);
                }
                if json_object_object_add(*dst, iter.key, jso) < 0 as libc::c_int {
                    json_object_put(jso);
                    return -(1 as libc::c_int);
                }
                iter.entry = lh_entry_next(iter.entry);
            }
        }
        5 => {
            src_array_len = json_object_array_length(src);
            ii = 0 as libc::c_int as size_t;
            while ii < src_array_len {
                let mut jso_0: *mut json_object = 0 as *mut json_object;
                let mut jso1: *mut json_object = json_object_array_get_idx(src, ii);
                if jso1.is_null() {
                    jso_0 = 0 as *mut json_object;
                } else if json_object_deep_copy_recursive(
                        jso1,
                        src,
                        0 as *const libc::c_char,
                        ii,
                        &mut jso_0,
                        shallow_copy,
                    ) < 0 as libc::c_int
                    {
                    json_object_put(jso_0);
                    return -(1 as libc::c_int);
                }
                if json_object_array_add(*dst, jso_0) < 0 as libc::c_int {
                    json_object_put(jso_0);
                    return -(1 as libc::c_int);
                }
                ii = ii.wrapping_add(1);
            }
        }
        _ => {}
    }
    if shallow_copy_rc != 2 as libc::c_int {
        return json_object_copy_serializer_data(src, *dst);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_deep_copy(
    mut src: *mut json_object,
    mut dst: *mut *mut json_object,
    mut shallow_copy: Option::<json_c_shallow_copy_fn>,
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    if src.is_null() || dst.is_null() || !(*dst).is_null() {
        *__errno_location() = 22 as libc::c_int;
        return -(1 as libc::c_int);
    }
    if shallow_copy.is_none() {
        shallow_copy = Some(json_c_shallow_copy_default as json_c_shallow_copy_fn);
    }
    rc = json_object_deep_copy_recursive(
        src,
        0 as *mut json_object,
        0 as *const libc::c_char,
        (2147483647 as libc::c_int as libc::c_uint)
            .wrapping_mul(2 as libc::c_uint)
            .wrapping_add(1 as libc::c_uint) as size_t,
        dst,
        shallow_copy,
    );
    if rc < 0 as libc::c_int {
        json_object_put(*dst);
        *dst = 0 as *mut json_object;
    }
    return rc;
}
#[cold]
unsafe extern "C" fn json_abort(mut message: *const libc::c_char) -> ! {
    if !message.is_null() {
        fprintf(
            stderr,
            b"json-c aborts with error: %s\n\0" as *const u8 as *const libc::c_char,
            message,
        );
    }
    abort();
}
