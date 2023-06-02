use :: libc;
extern "C" {
    pub type _IO_codecvt;
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn strlen(_: *const i8) -> u64;
    fn strcat(_: *mut i8, _: *const i8) -> *mut i8;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strstr(_: *const i8, _: *const i8) -> *mut i8;
    fn strdup(_: *const i8) -> *mut i8;
    fn __errno_location() -> *mut i32;
    fn memcmp(_: *const core::ffi::c_void, _: *const core::ffi::c_void, _: u64) -> i32;
    fn __assert_fail(
        __assertion: *const i8,
        __file: *const i8,
        __line: u32,
        __function: *const i8,
    ) -> !;
    static mut stderr: *mut crate::src::apps::json_parse::_IO_FILE;
    fn fprintf(_: *mut crate::src::apps::json_parse::_IO_FILE, _: *const i8, _: ...) -> i32;
    fn snprintf(_: *mut i8, _: u64, _: *const i8, _: ...) -> i32;
    fn free(__ptr: *mut core::ffi::c_void);
    fn strtod(_: *const i8, _: *mut *mut i8) -> f64;
    fn abort() -> !;
    fn malloc(_: u64) -> *mut core::ffi::c_void;
}
pub use crate::src::{
    arraylist::{
        array_list_add, array_list_bsearch, array_list_del_idx, array_list_free,
        array_list_get_idx, array_list_length, array_list_new2, array_list_put_idx,
        array_list_shrink, array_list_sort,
    },
    debug::_IO_wide_data,
    json_util::{_json_c_set_last_err, json_parse_int64, json_parse_uint64},
    json_visit::_IO_marker,
    linkhash::{
        lh_kchar_table_new, lh_table_delete, lh_table_free, lh_table_insert_w_hash,
        lh_table_length, lh_table_lookup_entry_w_hash, lh_table_lookup_ex,
    },
    printbuf::{printbuf_free, printbuf_memappend, printbuf_memset, printbuf_new, printbuf_reset},
};
pub type __int32_t = i32;
pub type __uint32_t = u32;
pub type __int64_t = i64;
pub type __uint64_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __ssize_t = i64;
pub type int32_t = i32;
pub type int64_t = i64;
pub type uint32_t = u32;
pub type uint64_t = u64;
pub type uintptr_t = u64;
pub type printbuf = crate::src::apps::json_parse::printbuf;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object_iter {
    pub key: *mut i8,
    pub val: *mut crate::src::json_object::json_object,
    pub entry: *mut crate::src::json_object::lh_entry,
}
impl json_object_iter {
    pub const fn new() -> Self {
        json_object_iter {
            key: (0 as *mut i8),
            val: (0 as *mut crate::src::json_object::json_object),
            entry: (0 as *mut crate::src::json_object::lh_entry),
        }
    }
}
impl std::default::Default for json_object_iter {
    fn default() -> Self {
        json_object_iter::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct lh_entry {
    pub k: *const core::ffi::c_void,
    pub k_is_constant: i32,
    pub v: *const core::ffi::c_void,
    pub next: *mut crate::src::json_object::lh_entry,
    pub prev: *mut crate::src::json_object::lh_entry,
}
impl lh_entry {
    pub const fn new() -> Self {
        lh_entry {
            k: (0 as *const core::ffi::c_void),
            k_is_constant: 0,
            v: (0 as *const core::ffi::c_void),
            next: (0 as *mut crate::src::json_object::lh_entry),
            prev: (0 as *mut crate::src::json_object::lh_entry),
        }
    }
}
impl std::default::Default for lh_entry {
    fn default() -> Self {
        lh_entry::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object {
    pub o_type: u32,
    pub _ref_count: u32,
    pub _to_json_string: Option<
        unsafe extern "C" fn(
            _: *mut crate::src::json_object::json_object,
            _: *mut crate::src::apps::json_parse::printbuf,
            _: i32,
            _: i32,
        ) -> i32,
    >,
    pub _pb: *mut crate::src::apps::json_parse::printbuf,
    pub _user_delete: Option<
        unsafe extern "C" fn(
            _: *mut crate::src::json_object::json_object,
            _: *mut core::ffi::c_void,
        ) -> (),
    >,
    pub _userdata: *mut core::ffi::c_void,
}
impl json_object {
    pub const fn new() -> Self {
        json_object {
            o_type: 0,
            _ref_count: 0,
            _to_json_string: None,
            _pb: (0 as *mut crate::src::apps::json_parse::printbuf),
            _user_delete: None,
            _userdata: (0 as *mut core::ffi::c_void),
        }
    }
}
impl std::default::Default for json_object {
    fn default() -> Self {
        json_object::new()
    }
}
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
pub type json_type = u32;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
pub type json_bool = i32;
pub type size_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub idata: [i8; 1],
    pub pdata: *mut i8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object_string {
    pub base: crate::src::json_object::json_object,
    pub len: i64,
    pub c_string: crate::src::json_object::C2RustUnnamed,
}
pub type ssize_t = i64;
pub type array_list = crate::src::arraylist::array_list;
pub type array_list_free_fn = unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ();
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object_array {
    pub base: crate::src::json_object::json_object,
    pub c_array: *mut crate::src::arraylist::array_list,
}
impl json_object_array {
    pub const fn new() -> Self {
        json_object_array {
            base: crate::src::json_object::json_object::new(),
            c_array: (0 as *mut crate::src::arraylist::array_list),
        }
    }
}
impl std::default::Default for json_object_array {
    fn default() -> Self {
        json_object_array::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct lh_table {
    pub size: i32,
    pub count: i32,
    pub head: *mut crate::src::json_object::lh_entry,
    pub tail: *mut crate::src::json_object::lh_entry,
    pub table: *mut crate::src::json_object::lh_entry,
    pub free_fn: Option<unsafe extern "C" fn(_: *mut crate::src::json_object::lh_entry) -> ()>,
    pub hash_fn: Option<unsafe extern "C" fn(_: *const core::ffi::c_void) -> u64>,
    pub equal_fn: Option<
        unsafe extern "C" fn(_: *const core::ffi::c_void, _: *const core::ffi::c_void) -> i32,
    >,
}
impl lh_table {
    pub const fn new() -> Self {
        lh_table {
            size: 0,
            count: 0,
            head: (0 as *mut crate::src::json_object::lh_entry),
            tail: (0 as *mut crate::src::json_object::lh_entry),
            table: (0 as *mut crate::src::json_object::lh_entry),
            free_fn: None,
            hash_fn: None,
            equal_fn: None,
        }
    }
}
impl std::default::Default for lh_table {
    fn default() -> Self {
        lh_table::new()
    }
}
pub type lh_equal_fn =
    unsafe extern "C" fn(_: *const core::ffi::c_void, _: *const core::ffi::c_void) -> i32;
pub type lh_hash_fn = unsafe extern "C" fn(_: *const core::ffi::c_void) -> u64;
pub type lh_entry_free_fn = unsafe extern "C" fn(_: *mut crate::src::json_object::lh_entry) -> ();
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object_object {
    pub base: crate::src::json_object::json_object,
    pub c_object: *mut crate::src::json_object::lh_table,
}
impl json_object_object {
    pub const fn new() -> Self {
        json_object_object {
            base: crate::src::json_object::json_object::new(),
            c_object: (0 as *mut crate::src::json_object::lh_table),
        }
    }
}
impl std::default::Default for json_object_object {
    fn default() -> Self {
        json_object_object::new()
    }
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
    pub base: crate::src::json_object::json_object,
    pub cint_type: u32,
    pub cint: crate::src::json_object::C2RustUnnamed_0,
}
pub type json_object_int_type = u32;
pub const json_object_int_type_uint64: json_object_int_type = 1;
pub const json_object_int_type_int64: json_object_int_type = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object_double {
    pub base: crate::src::json_object::json_object,
    pub c_double: f64,
}
impl json_object_double {
    pub const fn new() -> Self {
        json_object_double {
            base: crate::src::json_object::json_object::new(),
            c_double: 0.0,
        }
    }
}
impl std::default::Default for json_object_double {
    fn default() -> Self {
        json_object_double::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object_boolean {
    pub base: crate::src::json_object::json_object,
    pub c_boolean: i32,
}
impl json_object_boolean {
    pub const fn new() -> Self {
        json_object_boolean {
            base: crate::src::json_object::json_object::new(),
            c_boolean: 0,
        }
    }
}
impl std::default::Default for json_object_boolean {
    fn default() -> Self {
        json_object_boolean::new()
    }
}
pub type FILE = crate::src::apps::json_parse::_IO_FILE;
pub type _IO_FILE = crate::src::apps::json_parse::_IO_FILE;
pub type _IO_lock_t = ();
pub type json_c_shallow_copy_fn = unsafe extern "C" fn(
    _: *mut crate::src::json_object::json_object,
    _: *mut crate::src::json_object::json_object,
    _: *const i8,
    _: u64,
    _: *mut *mut crate::src::json_object::json_object,
) -> i32;
#[inline]
extern "C" fn lh_table_head(
    mut t: *const crate::src::json_object::lh_table,
) -> *mut crate::src::json_object::lh_entry {
    return unsafe { (*t).head };
}
#[inline]
extern "C" fn lh_get_hash(
    mut t: *const crate::src::json_object::lh_table,
    mut k: *const core::ffi::c_void,
) -> u64 {
    return unsafe { ((*t).hash_fn).expect("non-null function pointer")(k) };
}
#[inline]
extern "C" fn lh_entry_k(
    mut e: *const crate::src::json_object::lh_entry,
) -> *mut core::ffi::c_void {
    return (unsafe { (*e).k }) as uintptr_t as *mut libc::c_void;
}
#[inline]
extern "C" fn lh_entry_k_is_constant(mut e: *const crate::src::json_object::lh_entry) -> i32 {
    return unsafe { (*e).k_is_constant };
}
#[inline]
extern "C" fn lh_entry_v(
    mut e: *const crate::src::json_object::lh_entry,
) -> *mut core::ffi::c_void {
    return (unsafe { (*e).v }) as uintptr_t as *mut libc::c_void;
}
#[inline]
extern "C" fn lh_entry_set_val(
    mut e: *mut crate::src::json_object::lh_entry,
    mut newval: *mut core::ffi::c_void,
) {
    let mut fresh0 = unsafe { &mut ((*e).v) };
    *fresh0 = newval;
}
#[inline]
extern "C" fn lh_entry_next(
    mut e: *const crate::src::json_object::lh_entry,
) -> *mut crate::src::json_object::lh_entry {
    return unsafe { (*e).next };
}
#[no_mangle]
pub static mut json_hex_chars: *const i8 = b"0123456789abcdefABCDEF\0" as *const u8 as *const i8;
#[inline]
extern "C" fn JC_OBJECT(
    mut jso: *mut crate::src::json_object::json_object,
) -> *mut crate::src::json_object::json_object_object {
    return jso as *mut libc::c_void as *mut json_object_object;
}
#[inline]
extern "C" fn JC_OBJECT_C(
    mut jso: *const crate::src::json_object::json_object,
) -> *const crate::src::json_object::json_object_object {
    return jso as *const libc::c_void as *const json_object_object;
}
#[inline]
extern "C" fn JC_ARRAY(
    mut jso: *mut crate::src::json_object::json_object,
) -> *mut crate::src::json_object::json_object_array {
    return jso as *mut libc::c_void as *mut json_object_array;
}
#[inline]
extern "C" fn JC_ARRAY_C(
    mut jso: *const crate::src::json_object::json_object,
) -> *const crate::src::json_object::json_object_array {
    return jso as *const libc::c_void as *const json_object_array;
}
#[inline]
extern "C" fn JC_BOOL(
    mut jso: *mut crate::src::json_object::json_object,
) -> *mut crate::src::json_object::json_object_boolean {
    return jso as *mut libc::c_void as *mut json_object_boolean;
}
#[inline]
extern "C" fn JC_BOOL_C(
    mut jso: *const crate::src::json_object::json_object,
) -> *const crate::src::json_object::json_object_boolean {
    return jso as *const libc::c_void as *const json_object_boolean;
}
#[inline]
extern "C" fn JC_DOUBLE(
    mut jso: *mut crate::src::json_object::json_object,
) -> *mut crate::src::json_object::json_object_double {
    return jso as *mut libc::c_void as *mut json_object_double;
}
#[inline]
extern "C" fn JC_DOUBLE_C(
    mut jso: *const crate::src::json_object::json_object,
) -> *const crate::src::json_object::json_object_double {
    return jso as *const libc::c_void as *const json_object_double;
}
#[inline]
extern "C" fn JC_INT(
    mut jso: *mut crate::src::json_object::json_object,
) -> *mut crate::src::json_object::json_object_int {
    return jso as *mut libc::c_void as *mut json_object_int;
}
#[inline]
extern "C" fn JC_INT_C(
    mut jso: *const crate::src::json_object::json_object,
) -> *const crate::src::json_object::json_object_int {
    return jso as *const libc::c_void as *const json_object_int;
}
#[inline]
extern "C" fn JC_STRING(
    mut jso: *mut crate::src::json_object::json_object,
) -> *mut crate::src::json_object::json_object_string {
    return jso as *mut libc::c_void as *mut json_object_string;
}
#[inline]
extern "C" fn JC_STRING_C(
    mut jso: *const crate::src::json_object::json_object,
) -> *const crate::src::json_object::json_object_string {
    return jso as *const libc::c_void as *const json_object_string;
}
#[inline]
extern "C" fn get_string_component_mutable(
    mut jso: *mut crate::src::json_object::json_object,
) -> *mut i8 {
    if (unsafe { (*JC_STRING_C(jso)).len }) < 0 as i32 as i64 {
        return unsafe { (*JC_STRING(jso)).c_string.pdata };
    }
    return unsafe { ((*JC_STRING(jso)).c_string.idata).as_mut_ptr() };
}
#[inline]
extern "C" fn get_string_component(
    mut jso: *const crate::src::json_object::json_object,
) -> *const i8 {
    return get_string_component_mutable(
        jso as *const libc::c_void as uintptr_t as *mut libc::c_void as *mut json_object,
    );
}
extern "C" fn json_escape_str(
    mut pb: *mut crate::src::apps::json_parse::printbuf,
    mut str: *const i8,
    mut len: u64,
    mut flags: i32,
) -> i32 {
    let mut pos: u64 = 0 as i32 as size_t;
    let mut start_offset: u64 = 0 as i32 as size_t;
    let mut c: u8 = 0;
    while len != 0 {
        len = len.wrapping_sub(1);
        c = (unsafe { *str.offset(pos as isize) }) as u8;
        match c as i32 {
            8 | 10 | 13 | 9 | 12 | 34 | 92 | 47 => {
                if flags & (1 as i32) << 4 as i32 != 0 && c as i32 == '/' as i32 {
                    pos = pos.wrapping_add(1);
                } else {
                    if pos > start_offset {
                        printbuf_memappend(
                            pb,
                            unsafe { str.offset(start_offset as isize) },
                            pos.wrapping_sub(start_offset) as i32,
                        );
                    }
                    if c as i32 == '\u{8}' as i32 {
                        printbuf_memappend(pb, b"\\b\0" as *const u8 as *const i8, 2 as i32);
                    } else if c as i32 == '\n' as i32 {
                        printbuf_memappend(pb, b"\\n\0" as *const u8 as *const i8, 2 as i32);
                    } else if c as i32 == '\r' as i32 {
                        printbuf_memappend(pb, b"\\r\0" as *const u8 as *const i8, 2 as i32);
                    } else if c as i32 == '\t' as i32 {
                        printbuf_memappend(pb, b"\\t\0" as *const u8 as *const i8, 2 as i32);
                    } else if c as i32 == '\u{c}' as i32 {
                        printbuf_memappend(pb, b"\\f\0" as *const u8 as *const i8, 2 as i32);
                    } else if c as i32 == '"' as i32 {
                        printbuf_memappend(pb, b"\\\"\0" as *const u8 as *const i8, 2 as i32);
                    } else if c as i32 == '\\' as i32 {
                        printbuf_memappend(pb, b"\\\\\0" as *const u8 as *const i8, 2 as i32);
                    } else if c as i32 == '/' as i32 {
                        printbuf_memappend(pb, b"\\/\0" as *const u8 as *const i8, 2 as i32);
                    }
                    pos = pos.wrapping_add(1);
                    start_offset = pos;
                }
            },
            _ => {
                if (c as i32) < ' ' as i32 {
                    let mut sbuf: [i8; 7] = [0; 7];
                    if pos > start_offset {
                        printbuf_memappend(
                            pb,
                            unsafe { str.offset(start_offset as isize) },
                            pos.wrapping_sub(start_offset) as i32,
                        );
                    }
                    (unsafe { snprintf(
                        sbuf.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 7]>() as u64,
                        b"\\u00%c%c\0" as *const u8 as *const i8,
                        *json_hex_chars.offset((c as i32 >> 4 as i32) as isize) as i32,
                        *json_hex_chars.offset((c as i32 & 0xf as i32) as isize) as i32,
                    ) });
                    if (unsafe { (*pb).size }) - (unsafe { (*pb).bpos })
                        > ::std::mem::size_of::<[i8; 7]>() as u64 as i32 - 1 as i32
                    {
                        (unsafe { memcpy(
                            ((*pb).buf).offset((*pb).bpos as isize) as *mut libc::c_void,
                            sbuf.as_mut_ptr() as *const libc::c_void,
                            (::std::mem::size_of::<[i8; 7]>() as u64 as i32 - 1 as i32) as u64,
                        ) });
                        (unsafe { (*pb).bpos += ::std::mem::size_of::<[i8; 7]>() as u64 as i32 - 1 as i32 });
                        (unsafe { *((*pb).buf).offset((*pb).bpos as isize) = '\u{0}' as i32 as i8 });
                    } else {
                        printbuf_memappend(
                            pb,
                            sbuf.as_mut_ptr(),
                            ::std::mem::size_of::<[i8; 7]>() as u64 as i32 - 1 as i32,
                        );
                    }
                    pos = pos.wrapping_add(1);
                    start_offset = pos;
                } else {
                    pos = pos.wrapping_add(1);
                }
            },
        }
    }
    if pos > start_offset {
        printbuf_memappend(
            pb,
            unsafe { str.offset(start_offset as isize) },
            pos.wrapping_sub(start_offset) as i32,
        );
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn json_object_get(
    mut jso: *mut crate::src::json_object::json_object,
) -> *mut crate::src::json_object::json_object {
    if jso.is_null() {
        return jso;
    }
    if (unsafe { (*jso)._ref_count }) < 4294967295 as u32 {
    } else {
        (unsafe { __assert_fail(
            b"jso->_ref_count < UINT32_MAX\0" as *const u8 as *const i8,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const i8,
            254 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 58], &'_ [i8; 58]>(
                b"struct json_object *json_object_get(struct json_object *)\0",
            ))
            .as_ptr(),
        ) });
    }
    let mut fresh1 = unsafe { &mut ((*jso)._ref_count) };
    *fresh1 = (*fresh1).wrapping_add(1);
    return jso;
}
#[no_mangle]
pub extern "C" fn json_object_put(mut jso: *mut crate::src::json_object::json_object) -> i32 {
    if jso.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*jso)._ref_count }) > 0 as i32 as u32 {
    } else {
        (unsafe { __assert_fail(
            b"jso->_ref_count > 0\0" as *const u8 as *const i8,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const i8,
            273 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 42], &'_ [i8; 42]>(
                b"int json_object_put(struct json_object *)\0",
            ))
            .as_ptr(),
        ) });
    }
    let mut fresh2 = unsafe { &mut ((*jso)._ref_count) };
    *fresh2 = (*fresh2).wrapping_sub(1);
    if *fresh2 > 0 as i32 as u32 {
        return 0 as i32;
    }
    if unsafe { ((*jso)._user_delete).is_some() } {
        (unsafe { ((*jso)._user_delete).expect("non-null function pointer")(jso, (*jso)._userdata) });
    }
    match (unsafe { (*jso).o_type }) as u32 {
        4 => {
            json_object_object_delete(jso);
        },
        5 => {
            json_object_array_delete(jso);
        },
        6 => {
            json_object_string_delete(jso);
        },
        _ => {
            json_object_generic_delete(jso);
        },
    }
    return 1 as i32;
}
extern "C" fn json_object_generic_delete(mut jso: *mut crate::src::json_object::json_object) {
    printbuf_free(unsafe { (*jso)._pb });
    (unsafe { free(jso as *mut libc::c_void) });
}
#[inline]
extern "C" fn json_object_new(
    mut o_type: u32,
    mut alloc_size: u64,
    mut to_json_string: Option<
        unsafe extern "C" fn(
            _: *mut crate::src::json_object::json_object,
            _: *mut crate::src::apps::json_parse::printbuf,
            _: i32,
            _: i32,
        ) -> i32,
    >,
) -> *mut crate::src::json_object::json_object {
    let mut jso: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    jso = (unsafe { malloc(alloc_size) }) as *mut json_object;
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    (unsafe { (*jso).o_type = o_type });
    (unsafe { (*jso)._ref_count = 1 as i32 as uint32_t });
    let mut fresh3 = unsafe { &mut ((*jso)._to_json_string) };
    *fresh3 = to_json_string;
    let mut fresh4 = unsafe { &mut ((*jso)._pb) };
    *fresh4 = 0 as *mut printbuf;
    let mut fresh5 = unsafe { &mut ((*jso)._user_delete) };
    *fresh5 = None;
    let mut fresh6 = unsafe { &mut ((*jso)._userdata) };
    *fresh6 = 0 as *mut libc::c_void;
    return jso;
}
#[no_mangle]
pub extern "C" fn json_object_is_type(
    mut jso: *const crate::src::json_object::json_object,
    mut type_0: u32,
) -> i32 {
    if jso.is_null() {
        return (type_0 as u32 == json_type_null as i32 as u32) as i32;
    }
    return ((unsafe { (*jso).o_type }) as u32 == type_0 as u32) as i32;
}
#[no_mangle]
pub extern "C" fn json_object_get_type(
    mut jso: *const crate::src::json_object::json_object,
) -> u32 {
    if jso.is_null() {
        return json_type_null;
    }
    return unsafe { (*jso).o_type };
}
#[no_mangle]
pub extern "C" fn json_object_get_userdata(
    mut jso: *mut crate::src::json_object::json_object,
) -> *mut core::ffi::c_void {
    return if !jso.is_null() {
        unsafe { (*jso)._userdata }
    } else {
        0 as *mut libc::c_void
    };
}
#[no_mangle]
pub extern "C" fn json_object_set_userdata(
    mut jso: *mut crate::src::json_object::json_object,
    mut userdata: *mut core::ffi::c_void,
    mut user_delete: Option<
        unsafe extern "C" fn(
            _: *mut crate::src::json_object::json_object,
            _: *mut core::ffi::c_void,
        ) -> (),
    >,
) {
    if !jso.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"jso != NULL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const i8,
            353 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 78], &'_ [i8; 78]>(
                b"void json_object_set_userdata(json_object *, void *, json_object_delete_fn *)\0",
            ))
            .as_ptr(),
        ) });
    }
    if unsafe { ((*jso)._user_delete).is_some() } {
        (unsafe { ((*jso)._user_delete).expect("non-null function pointer")(jso, (*jso)._userdata) });
    }
    let mut fresh7 = unsafe { &mut ((*jso)._userdata) };
    *fresh7 = userdata;
    let mut fresh8 = unsafe { &mut ((*jso)._user_delete) };
    *fresh8 = user_delete;
}
#[no_mangle]
pub extern "C" fn json_object_set_serializer(
    mut jso: *mut crate::src::json_object::json_object,
    mut to_string_func: Option<
        unsafe extern "C" fn(
            _: *mut crate::src::json_object::json_object,
            _: *mut crate::src::apps::json_parse::printbuf,
            _: i32,
            _: i32,
        ) -> i32,
    >,
    mut userdata: *mut core::ffi::c_void,
    mut user_delete: Option<
        unsafe extern "C" fn(
            _: *mut crate::src::json_object::json_object,
            _: *mut core::ffi::c_void,
        ) -> (),
    >,
) {
    json_object_set_userdata(jso, userdata, user_delete);
    if to_string_func.is_none() {
        match (unsafe { (*jso).o_type }) as u32 {
            0 => {
                let mut fresh9 = unsafe { &mut ((*jso)._to_json_string) };
                *fresh9 = None;
            },
            1 => {
                let mut fresh10 = unsafe { &mut ((*jso)._to_json_string) };
                *fresh10 = Some(json_object_boolean_to_json_string);
            },
            2 => {
                let mut fresh11 = unsafe { &mut ((*jso)._to_json_string) };
                *fresh11 = Some(json_object_double_to_json_string_default);
            },
            3 => {
                let mut fresh12 = unsafe { &mut ((*jso)._to_json_string) };
                *fresh12 = Some(json_object_int_to_json_string);
            },
            4 => {
                let mut fresh13 = unsafe { &mut ((*jso)._to_json_string) };
                *fresh13 = Some(json_object_object_to_json_string);
            },
            5 => {
                let mut fresh14 = unsafe { &mut ((*jso)._to_json_string) };
                *fresh14 = Some(json_object_array_to_json_string);
            },
            6 => {
                let mut fresh15 = unsafe { &mut ((*jso)._to_json_string) };
                *fresh15 = Some(json_object_string_to_json_string);
            },
            _ => {},
        }
        return;
    }
    let mut fresh16 = unsafe { &mut ((*jso)._to_json_string) };
    *fresh16 = to_string_func;
}
#[no_mangle]
pub extern "C" fn json_object_to_json_string_length<'a1>(
    mut jso: *mut crate::src::json_object::json_object,
    mut flags: i32,
    mut length: Option<&'a1 mut u64>,
) -> *const i8 {
    let mut r: *const i8 = 0 as *const i8;
    let mut s: u64 = 0 as i32 as size_t;
    if jso.is_null() {
        s = 4 as i32 as size_t;
        r = b"null\0" as *const u8 as *const i8;
    } else if !(unsafe { (*jso)._pb }).is_null() || {
        let mut fresh17 = unsafe { &mut ((*jso)._pb) };
        *fresh17 = printbuf_new();
        !(*fresh17).is_null()
    } {
        printbuf_reset(unsafe { (*jso)._pb });
        if (unsafe { ((*jso)._to_json_string).expect("non-null function pointer")(
            jso,
            (*jso)._pb,
            0 as i32,
            flags,
        ) }) >= 0 as i32
        {
            s = (unsafe { (*(*jso)._pb).bpos }) as size_t;
            r = unsafe { (*(*jso)._pb).buf };
        }
    }
    if !borrow(&length).is_none() {
        *(borrow_mut(&mut length)).unwrap() = s;
    }
    return r;
}
#[no_mangle]
pub extern "C" fn json_object_to_json_string_ext(
    mut jso: *mut crate::src::json_object::json_object,
    mut flags: i32,
) -> *const i8 {
    return json_object_to_json_string_length(jso, flags, Option::<&'_ mut u64>::None);
}
#[no_mangle]
pub extern "C" fn json_object_to_json_string(
    mut jso: *mut crate::src::json_object::json_object,
) -> *const i8 {
    return json_object_to_json_string_ext(jso, (1 as i32) << 0 as i32);
}
extern "C" fn indent(
    mut pb: *mut crate::src::apps::json_parse::printbuf,
    mut level: i32,
    mut flags: i32,
) {
    if flags & (1 as i32) << 1 as i32 != 0 {
        if flags & (1 as i32) << 3 as i32 != 0 {
            printbuf_memset(pb, -(1 as i32), '\t' as i32, level);
        } else {
            printbuf_memset(pb, -(1 as i32), ' ' as i32, level * 2 as i32);
        }
    }
}
extern "C" fn json_object_object_to_json_string(
    mut jso: *mut crate::src::json_object::json_object,
    mut pb: *mut crate::src::apps::json_parse::printbuf,
    mut level: i32,
    mut flags: i32,
) -> i32 {
    let mut had_children: i32 = 0 as i32;
    let mut iter: crate::src::json_object::json_object_iter = json_object_iter {
        key: 0 as *mut i8,
        val: 0 as *mut json_object,
        entry: 0 as *mut lh_entry,
    };
    printbuf_memappend(
        pb,
        b"{\0" as *const u8 as *const i8,
        (::std::mem::size_of::<[i8; 2]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
    );
    iter.entry = lh_table_head(json_object_get_object(jso));
    while !if !(iter.entry).is_null() {
        iter.key = lh_entry_k(iter.entry) as *mut i8;
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
                b",\0" as *const u8 as *const i8,
                (::std::mem::size_of::<[i8; 2]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
            );
        }
        if flags & (1 as i32) << 1 as i32 != 0 {
            printbuf_memappend(
                pb,
                b"\n\0" as *const u8 as *const i8,
                (::std::mem::size_of::<[i8; 2]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
            );
        }
        had_children = 1 as i32;
        if flags & (1 as i32) << 0 as i32 != 0 && flags & (1 as i32) << 1 as i32 == 0 {
            printbuf_memappend(
                pb,
                b" \0" as *const u8 as *const i8,
                (::std::mem::size_of::<[i8; 2]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
            );
        }
        indent(pb, level + 1 as i32, flags);
        printbuf_memappend(
            pb,
            b"\"\0" as *const u8 as *const i8,
            (::std::mem::size_of::<[i8; 2]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
        );
        json_escape_str(pb, iter.key, unsafe { strlen(iter.key) }, flags);
        if flags & (1 as i32) << 0 as i32 != 0 {
            printbuf_memappend(
                pb,
                b"\": \0" as *const u8 as *const i8,
                (::std::mem::size_of::<[i8; 4]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
            );
        } else {
            printbuf_memappend(
                pb,
                b"\":\0" as *const u8 as *const i8,
                (::std::mem::size_of::<[i8; 3]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
            );
        }
        if (iter.val).is_null() {
            printbuf_memappend(
                pb,
                b"null\0" as *const u8 as *const i8,
                (::std::mem::size_of::<[i8; 5]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
            );
        } else if (unsafe { ((*iter.val)._to_json_string).expect("non-null function pointer")(
            iter.val,
            pb,
            level + 1 as i32,
            flags,
        ) }) < 0 as i32
        {
            return -(1 as i32);
        }
        iter.entry = lh_entry_next(iter.entry);
    }
    if flags & (1 as i32) << 1 as i32 != 0 && had_children != 0 {
        printbuf_memappend(
            pb,
            b"\n\0" as *const u8 as *const i8,
            (::std::mem::size_of::<[i8; 2]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
        );
        indent(pb, level, flags);
    }
    if flags & (1 as i32) << 0 as i32 != 0 && flags & (1 as i32) << 1 as i32 == 0 {
        return printbuf_memappend(
            pb,
            b" }\0" as *const u8 as *const i8,
            (::std::mem::size_of::<[i8; 3]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
        );
    } else {
        return printbuf_memappend(
            pb,
            b"}\0" as *const u8 as *const i8,
            (::std::mem::size_of::<[i8; 2]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
        );
    };
}
extern "C" fn json_object_lh_entry_free(mut ent: *mut crate::src::json_object::lh_entry) {
    if lh_entry_k_is_constant(ent) == 0 {
        (unsafe { free(lh_entry_k(ent)) });
    }
    json_object_put(lh_entry_v(ent) as *mut json_object);
}
extern "C" fn json_object_object_delete(mut jso_base: *mut crate::src::json_object::json_object) {
    lh_table_free(unsafe { (*JC_OBJECT(jso_base)).c_object });
    json_object_generic_delete(jso_base);
}
#[no_mangle]
pub extern "C" fn json_object_new_object() -> *mut crate::src::json_object::json_object {
    let mut jso: *mut crate::src::json_object::json_object_object = json_object_new(
        json_type_object,
        ::std::mem::size_of::<json_object_object>() as u64,
        Some(json_object_object_to_json_string),
    )
        as *mut json_object_object;
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    let mut fresh18 = unsafe { &mut ((*jso).c_object) };
    *fresh18 = lh_kchar_table_new(16 as i32, Some(json_object_lh_entry_free));
    if (unsafe { (*jso).c_object }).is_null() {
        json_object_generic_delete(unsafe { &mut (*jso).base });
        (unsafe { *__errno_location() = 12 as i32 });
        return 0 as *mut json_object;
    }
    return unsafe { &mut (*jso).base };
}
#[no_mangle]
pub extern "C" fn json_object_get_object(
    mut jso: *const crate::src::json_object::json_object,
) -> *mut crate::src::json_object::lh_table {
    if jso.is_null() {
        return 0 as *mut lh_table;
    }
    match (unsafe { (*jso).o_type }) as u32 {
        4 => return unsafe { (*JC_OBJECT_C(jso)).c_object },
        _ => return 0 as *mut lh_table,
    };
}
#[no_mangle]
pub extern "C" fn json_object_object_add_ex(
    mut jso: *mut crate::src::json_object::json_object,
    key: *const i8,
    val: *mut crate::src::json_object::json_object,
    opts: u32,
) -> i32 {
    let mut existing_value: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut existing_entry: *mut crate::src::json_object::lh_entry = 0 as *mut lh_entry;
    let mut hash: u64 = 0;
    if json_object_get_type(jso) as u32 == json_type_object as i32 as u32 {
    } else {
        (unsafe { __assert_fail (b"json_object_get_type(jso) == json_type_object\0" as * const u8 as * const i8 , b"/home/xial/json-c/json_object.c\0" as * const u8 as * const i8 , 544 as i32 as u32 , (* core :: intrinsics :: transmute :: < & '_ [u8 ; 118] , & '_ [i8 ; 118] > (b"int json_object_object_add_ex(struct json_object *, const char *const, struct json_object *const, const unsigned int)\0" ,)) . as_ptr () ,) }) ;
    }
    hash = lh_get_hash(unsafe { (*JC_OBJECT(jso)).c_object }, key as *const libc::c_void);
    existing_entry = if opts & ((1 as i32) << 1 as i32) as u32 != 0 {
        0 as *mut lh_entry
    } else {
        lh_table_lookup_entry_w_hash(unsafe { (*JC_OBJECT(jso)).c_object }, key as *const libc::c_void, hash)
    };
    if jso == val {
        return -(1 as i32);
    }
    if existing_entry.is_null() {
        let k: *const core::ffi::c_void = if opts & ((1 as i32) << 2 as i32) as u32 != 0 {
            key as *const libc::c_void
        } else {
            (unsafe { strdup(key) }) as *const libc::c_void
        };
        if k.is_null() {
            return -(1 as i32);
        }
        return lh_table_insert_w_hash(
            unsafe { (*JC_OBJECT(jso)).c_object },
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
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn json_object_object_add(
    mut jso: *mut crate::src::json_object::json_object,
    mut key: *const i8,
    mut val: *mut crate::src::json_object::json_object,
) -> i32 {
    return json_object_object_add_ex(jso, key, val, 0 as i32 as u32);
}
#[no_mangle]
pub extern "C" fn json_object_object_length(
    mut jso: *const crate::src::json_object::json_object,
) -> i32 {
    if json_object_get_type(jso) as u32 == json_type_object as i32 as u32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_type(jso) == json_type_object\0" as *const u8 as *const i8,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const i8,
            581 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 58], &'_ [i8; 58]>(
                b"int json_object_object_length(const struct json_object *)\0",
            ))
            .as_ptr(),
        ) });
    }
    return lh_table_length(unsafe { (*JC_OBJECT_C(jso)).c_object });
}
#[no_mangle]
pub extern "C" fn json_c_object_sizeof() -> u64 {
    return ::std::mem::size_of::<json_object>() as u64;
}
#[no_mangle]
pub extern "C" fn json_object_object_get(
    mut jso: *const crate::src::json_object::json_object,
    mut key: *const i8,
) -> *mut crate::src::json_object::json_object {
    let mut result: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    json_object_object_get_ex(jso, key, &mut result);
    return result;
}
#[no_mangle]
pub extern "C" fn json_object_object_get_ex(
    mut jso: *const crate::src::json_object::json_object,
    mut key: *const i8,
    mut value: *mut *mut crate::src::json_object::json_object,
) -> i32 {
    if !value.is_null() {
        (unsafe { *value = 0 as *mut json_object });
    }
    if jso.is_null() {
        return 0 as i32;
    }
    match (unsafe { (*jso).o_type }) as u32 {
        4 => {
            return lh_table_lookup_ex(
                unsafe { (*JC_OBJECT_C(jso)).c_object },
                key as *const libc::c_void,
                value as *mut *mut libc::c_void,
            );
        },
        _ => {
            if !value.is_null() {
                (unsafe { *value = 0 as *mut json_object });
            }
            return 0 as i32;
        },
    };
}
#[no_mangle]
pub extern "C" fn json_object_object_del(
    mut jso: *mut crate::src::json_object::json_object,
    mut key: *const i8,
) {
    if json_object_get_type(jso) as u32 == json_type_object as i32 as u32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_type(jso) == json_type_object\0" as *const u8 as *const i8,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const i8,
            620 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 64], &'_ [i8; 64]>(
                b"void json_object_object_del(struct json_object *, const char *)\0",
            ))
            .as_ptr(),
        ) });
    }
    lh_table_delete(unsafe { (*JC_OBJECT(jso)).c_object }, key as *const libc::c_void);
}
extern "C" fn json_object_boolean_to_json_string(
    mut jso: *mut crate::src::json_object::json_object,
    mut pb: *mut crate::src::apps::json_parse::printbuf,
    mut _level: i32,
    mut _flags: i32,
) -> i32 {
    if (unsafe { (*JC_BOOL(jso)).c_boolean }) != 0 {
        return printbuf_memappend(
            pb,
            b"true\0" as *const u8 as *const i8,
            (::std::mem::size_of::<[i8; 5]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
        );
    }
    return printbuf_memappend(
        pb,
        b"false\0" as *const u8 as *const i8,
        (::std::mem::size_of::<[i8; 6]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
    );
}
#[no_mangle]
pub extern "C" fn json_object_new_boolean(mut b: i32) -> *mut crate::src::json_object::json_object {
    let mut jso: *mut crate::src::json_object::json_object_boolean = json_object_new(
        json_type_boolean,
        ::std::mem::size_of::<json_object_boolean>() as u64,
        Some(json_object_boolean_to_json_string),
    )
        as *mut json_object_boolean;
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    (unsafe { (*jso).c_boolean = b });
    return unsafe { &mut (*jso).base };
}
#[no_mangle]
pub extern "C" fn json_object_get_boolean(
    mut jso: *const crate::src::json_object::json_object,
) -> i32 {
    if jso.is_null() {
        return 0 as i32;
    }
    match (unsafe { (*jso).o_type }) as u32 {
        1 => return unsafe { (*JC_BOOL_C(jso)).c_boolean },
        3 => match (unsafe { (*JC_INT_C(jso)).cint_type }) as u32 {
            0 => {
                return ((unsafe { (*JC_INT_C(jso)).cint.c_int64 }) != 0 as i32 as i64) as i32;
            },
            1 => {
                return ((unsafe { (*JC_INT_C(jso)).cint.c_uint64 }) != 0 as i32 as u64) as i32;
            },
            _ => {
                json_abort(b"invalid cint_type\0" as *const u8 as *const i8);
            },
        },
        2 => {
            return ((unsafe { (*JC_DOUBLE_C(jso)).c_double }) != 0 as i32 as f64) as i32;
        },
        6 => {
            return ((unsafe { (*JC_STRING_C(jso)).len }) != 0 as i32 as i64) as i32;
        },
        _ => return 0 as i32,
    };
}
#[no_mangle]
pub extern "C" fn json_object_set_boolean(
    mut jso: *mut crate::src::json_object::json_object,
    mut new_value: i32,
) -> i32 {
    if jso.is_null() || (unsafe { (*jso).o_type }) as u32 != json_type_boolean as i32 as u32 {
        return 0 as i32;
    }
    (unsafe { (*JC_BOOL(jso)).c_boolean = new_value });
    return 1 as i32;
}
extern "C" fn json_object_int_to_json_string(
    mut jso: *mut crate::src::json_object::json_object,
    mut pb: *mut crate::src::apps::json_parse::printbuf,
    mut _level: i32,
    mut _flags: i32,
) -> i32 {
    let mut sbuf: [i8; 21] = [0; 21];
    if (unsafe { (*JC_INT(jso)).cint_type }) as u32 == json_object_int_type_int64 as i32 as u32 {
        (unsafe { snprintf(
            sbuf.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 21]>() as u64,
            b"%ld\0" as *const u8 as *const i8,
            (*JC_INT(jso)).cint.c_int64,
        ) });
    } else {
        (unsafe { snprintf(
            sbuf.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 21]>() as u64,
            b"%lu\0" as *const u8 as *const i8,
            (*JC_INT(jso)).cint.c_uint64,
        ) });
    }
    return printbuf_memappend(pb, sbuf.as_mut_ptr(), (unsafe { strlen(sbuf.as_mut_ptr()) }) as i32);
}
#[no_mangle]
pub extern "C" fn json_object_new_int(mut i: i32) -> *mut crate::src::json_object::json_object {
    return json_object_new_int64(i as int64_t);
}
#[no_mangle]
pub extern "C" fn json_object_get_int(mut jso: *const crate::src::json_object::json_object) -> i32 {
    let mut cint64: i64 = 0 as i32 as int64_t;
    let mut cdouble: f64 = 0.;
    let mut o_type: u32 = json_type_null;
    if jso.is_null() {
        return 0 as i32;
    }
    o_type = unsafe { (*jso).o_type };
    if o_type as u32 == json_type_int as i32 as u32 {
        let mut jsoint: *const crate::src::json_object::json_object_int = JC_INT_C(jso);
        if (unsafe { (*jsoint).cint_type }) as u32 == json_object_int_type_int64 as i32 as u32 {
            cint64 = unsafe { (*jsoint).cint.c_int64 };
        } else if (unsafe { (*jsoint).cint.c_uint64 }) >= 9223372036854775807 as i64 as u64 {
            cint64 = 9223372036854775807 as i64;
        } else {
            cint64 = (unsafe { (*jsoint).cint.c_uint64 }) as int64_t;
        }
    } else if o_type as u32 == json_type_string as i32 as u32 {
        if json_parse_int64(get_string_component(jso), Some(&mut cint64)) != 0 as i32 {
            return 0 as i32;
        }
        o_type = json_type_int;
    }
    match o_type as u32 {
        3 => {
            if cint64 <= (-(2147483647 as i32) - 1 as i32) as i64 {
                return -(2147483647 as i32) - 1 as i32;
            }
            if cint64 >= 2147483647 as i32 as i64 {
                return 2147483647 as i32;
            }
            return cint64 as int32_t;
        },
        2 => {
            cdouble = unsafe { (*JC_DOUBLE_C(jso)).c_double };
            if cdouble <= (-(2147483647 as i32) - 1 as i32) as f64 {
                return -(2147483647 as i32) - 1 as i32;
            }
            if cdouble >= 2147483647 as i32 as f64 {
                return 2147483647 as i32;
            }
            return cdouble as int32_t;
        },
        1 => return unsafe { (*JC_BOOL_C(jso)).c_boolean },
        _ => return 0 as i32,
    };
}
#[no_mangle]
pub extern "C" fn json_object_set_int(
    mut jso: *mut crate::src::json_object::json_object,
    mut new_value: i32,
) -> i32 {
    return json_object_set_int64(jso, new_value as int64_t);
}
#[no_mangle]
pub extern "C" fn json_object_new_int64(mut i: i64) -> *mut crate::src::json_object::json_object {
    let mut jso: *mut crate::src::json_object::json_object_int = json_object_new(
        json_type_int,
        ::std::mem::size_of::<json_object_int>() as u64,
        Some(json_object_int_to_json_string),
    ) as *mut json_object_int;
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    (unsafe { (*jso).cint.c_int64 = i });
    (unsafe { (*jso).cint_type = json_object_int_type_int64 });
    return unsafe { &mut (*jso).base };
}
#[no_mangle]
pub extern "C" fn json_object_new_uint64(mut i: u64) -> *mut crate::src::json_object::json_object {
    let mut jso: *mut crate::src::json_object::json_object_int = json_object_new(
        json_type_int,
        ::std::mem::size_of::<json_object_int>() as u64,
        Some(json_object_int_to_json_string),
    ) as *mut json_object_int;
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    (unsafe { (*jso).cint.c_uint64 = i });
    (unsafe { (*jso).cint_type = json_object_int_type_uint64 });
    return unsafe { &mut (*jso).base };
}
#[no_mangle]
pub extern "C" fn json_object_get_int64(
    mut jso: *const crate::src::json_object::json_object,
) -> i64 {
    let mut cint: i64 = 0;
    if jso.is_null() {
        return 0 as i32 as int64_t;
    }
    match (unsafe { (*jso).o_type }) as u32 {
        3 => {
            let mut jsoint: *const crate::src::json_object::json_object_int = JC_INT_C(jso);
            match (unsafe { (*jsoint).cint_type }) as u32 {
                0 => return unsafe { (*jsoint).cint.c_int64 },
                1 => {
                    if (unsafe { (*jsoint).cint.c_uint64 }) >= 9223372036854775807 as i64 as u64 {
                        return 9223372036854775807 as i64;
                    }
                    return (unsafe { (*jsoint).cint.c_uint64 }) as int64_t;
                },
                _ => {
                    json_abort(b"invalid cint_type\0" as *const u8 as *const i8);
                },
            }
        },
        2 => {
            if (unsafe { (*JC_DOUBLE_C(jso)).c_double }) >= 9223372036854775807 as i64 as f64 {
                return 9223372036854775807 as i64;
            }
            if (unsafe { (*JC_DOUBLE_C(jso)).c_double })
                <= (-(9223372036854775807 as i64) - 1 as i32 as i64) as f64
            {
                return -(9223372036854775807 as i64) - 1 as i32 as i64;
            }
            return (unsafe { (*JC_DOUBLE_C(jso)).c_double }) as int64_t;
        },
        1 => return (unsafe { (*JC_BOOL_C(jso)).c_boolean }) as int64_t,
        6 => {
            if json_parse_int64(get_string_component(jso), Some(&mut cint)) == 0 as i32 {
                return cint;
            }
        },
        _ => {},
    }
    return 0 as i32 as int64_t;
}
#[no_mangle]
pub extern "C" fn json_object_get_uint64(
    mut jso: *const crate::src::json_object::json_object,
) -> u64 {
    let mut cuint: u64 = 0;
    if jso.is_null() {
        return 0 as i32 as uint64_t;
    }
    match (unsafe { (*jso).o_type }) as u32 {
        3 => {
            let mut jsoint: *const crate::src::json_object::json_object_int = JC_INT_C(jso);
            match (unsafe { (*jsoint).cint_type }) as u32 {
                0 => {
                    if (unsafe { (*jsoint).cint.c_int64 }) < 0 as i32 as i64 {
                        return 0 as i32 as uint64_t;
                    }
                    return (unsafe { (*jsoint).cint.c_int64 }) as uint64_t;
                },
                1 => return unsafe { (*jsoint).cint.c_uint64 },
                _ => {
                    json_abort(b"invalid cint_type\0" as *const u8 as *const i8);
                },
            }
        },
        2 => {
            if (unsafe { (*JC_DOUBLE_C(jso)).c_double }) >= 18446744073709551615 as u64 as f64 {
                return 18446744073709551615 as u64;
            }
            if (unsafe { (*JC_DOUBLE_C(jso)).c_double }) < 0 as i32 as f64 {
                return 0 as i32 as uint64_t;
            }
            return (unsafe { (*JC_DOUBLE_C(jso)).c_double }) as uint64_t;
        },
        1 => return (unsafe { (*JC_BOOL_C(jso)).c_boolean }) as uint64_t,
        6 => {
            if json_parse_uint64(get_string_component(jso), Some(&mut cuint)) == 0 as i32 {
                return cuint;
            }
        },
        _ => {},
    }
    return 0 as i32 as uint64_t;
}
#[no_mangle]
pub extern "C" fn json_object_set_int64(
    mut jso: *mut crate::src::json_object::json_object,
    mut new_value: i64,
) -> i32 {
    if jso.is_null() || (unsafe { (*jso).o_type }) as u32 != json_type_int as i32 as u32 {
        return 0 as i32;
    }
    (unsafe { (*JC_INT(jso)).cint.c_int64 = new_value });
    (unsafe { (*JC_INT(jso)).cint_type = json_object_int_type_int64 });
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn json_object_set_uint64(
    mut jso: *mut crate::src::json_object::json_object,
    mut new_value: u64,
) -> i32 {
    if jso.is_null() || (unsafe { (*jso).o_type }) as u32 != json_type_int as i32 as u32 {
        return 0 as i32;
    }
    (unsafe { (*JC_INT(jso)).cint.c_uint64 = new_value });
    (unsafe { (*JC_INT(jso)).cint_type = json_object_int_type_uint64 });
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn json_object_int_inc(
    mut jso: *mut crate::src::json_object::json_object,
    mut val: i64,
) -> i32 {
    let mut jsoint: *mut crate::src::json_object::json_object_int =
        0 as *mut crate::src::json_object::json_object_int;
    if jso.is_null() || (unsafe { (*jso).o_type }) as u32 != json_type_int as i32 as u32 {
        return 0 as i32;
    }
    jsoint = JC_INT(jso);
    match (unsafe { (*jsoint).cint_type }) as u32 {
        0 => {
            if val > 0 as i32 as i64 && (unsafe { (*jsoint).cint.c_int64 }) > 9223372036854775807 as i64 - val {
                (unsafe { (*jsoint).cint.c_uint64 =
                    ((*jsoint).cint.c_int64 as uint64_t).wrapping_add(val as uint64_t) });
                (unsafe { (*jsoint).cint_type = json_object_int_type_uint64 });
            } else if val < 0 as i32 as i64
                && (unsafe { (*jsoint).cint.c_int64 }) < -(9223372036854775807 as i64) - 1 as i32 as i64 - val
            {
                (unsafe { (*jsoint).cint.c_int64 = -(9223372036854775807 as i64) - 1 as i32 as i64 });
            } else {
                let mut fresh19 = unsafe { &mut ((*jsoint).cint.c_int64) };
                *fresh19 += val;
            }
            return 1 as i32;
        },
        1 => {
            if val > 0 as i32 as i64
                && (unsafe { (*jsoint).cint.c_uint64 })
                    > (18446744073709551615 as u64).wrapping_sub(val as uint64_t)
            {
                (unsafe { (*jsoint).cint.c_uint64 = 18446744073709551615 as u64 });
            } else if val < 0 as i32 as i64 && (unsafe { (*jsoint).cint.c_uint64 }) < -val as uint64_t {
                (unsafe { (*jsoint).cint.c_int64 = (*jsoint).cint.c_uint64 as int64_t + val });
                (unsafe { (*jsoint).cint_type = json_object_int_type_int64 });
            } else if val < 0 as i32 as i64 && (unsafe { (*jsoint).cint.c_uint64 }) >= -val as uint64_t {
                let mut fresh20 = unsafe { &mut ((*jsoint).cint.c_uint64) };
                *fresh20 = (*fresh20 as u64).wrapping_sub(-val as uint64_t) as uint64_t as uint64_t;
            } else {
                let mut fresh21 = unsafe { &mut ((*jsoint).cint.c_uint64) };
                *fresh21 = (*fresh21 as u64).wrapping_add(val as u64) as uint64_t as uint64_t;
            }
            return 1 as i32;
        },
        _ => {
            json_abort(b"invalid cint_type\0" as *const u8 as *const i8);
        },
    };
}
#[thread_local]
static mut tls_serialization_float_format: *mut i8 = 0 as *const i8 as *mut i8;
static mut global_serialization_float_format: *mut i8 = 0 as *const i8 as *mut i8;
#[no_mangle]
pub extern "C" fn json_c_set_serialization_double_format(
    mut double_format: *const i8,
    mut global_or_thread: i32,
) -> i32 {
    if global_or_thread == 0 as i32 {
        if !(unsafe { tls_serialization_float_format }).is_null() {
            (unsafe { free(tls_serialization_float_format as *mut libc::c_void) });
            (unsafe { tls_serialization_float_format = 0 as *mut i8 });
        }
        if !(unsafe { global_serialization_float_format }).is_null() {
            (unsafe { free(global_serialization_float_format as *mut libc::c_void) });
        }
        if !double_format.is_null() {
            let mut p: *mut i8 = unsafe { strdup(double_format) };
            if p.is_null() {
                (unsafe { _json_c_set_last_err(
                    b"json_c_set_serialization_double_format: out of memory\n\0" as *const u8
                        as *const i8,
                ) });
                return -(1 as i32);
            }
            (unsafe { global_serialization_float_format = p });
        } else {
            (unsafe { global_serialization_float_format = 0 as *mut i8 });
        }
    } else if global_or_thread == 1 as i32 {
        if !(unsafe { tls_serialization_float_format }).is_null() {
            (unsafe { free(tls_serialization_float_format as *mut libc::c_void) });
            (unsafe { tls_serialization_float_format = 0 as *mut i8 });
        }
        if !double_format.is_null() {
            let mut p_0: *mut i8 = unsafe { strdup(double_format) };
            if p_0.is_null() {
                (unsafe { _json_c_set_last_err(
                    b"json_c_set_serialization_double_format: out of memory\n\0" as *const u8
                        as *const i8,
                ) });
                return -(1 as i32);
            }
            (unsafe { tls_serialization_float_format = p_0 });
        } else {
            (unsafe { tls_serialization_float_format = 0 as *mut i8 });
        }
    } else {
        (unsafe { _json_c_set_last_err(
            b"json_c_set_serialization_double_format: invalid global_or_thread value: %d\n\0"
                as *const u8 as *const i8,
            global_or_thread,
        ) });
        return -(1 as i32);
    }
    return 0 as i32;
}
extern "C" fn json_object_double_to_json_string_format(
    mut jso: *mut crate::src::json_object::json_object,
    mut pb: *mut crate::src::apps::json_parse::printbuf,
    mut _level: i32,
    mut flags: i32,
    mut format: *const i8,
) -> i32 {
    let mut jsodbl: *mut crate::src::json_object::json_object_double = JC_DOUBLE(jso);
    let mut buf: [i8; 128] = [0; 128];
    let mut p: *mut i8 = 0 as *mut i8;
    let mut q: *mut i8 = 0 as *mut i8;
    let mut size: i32 = 0;
    if (unsafe { (*jsodbl).c_double }).is_nan() as i32 != 0 {
        size = unsafe { snprintf(
            buf.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 128]>() as u64,
            b"NaN\0" as *const u8 as *const i8,
        ) };
    } else if if (unsafe { (*jsodbl).c_double }).is_infinite() {
        if (unsafe { (*jsodbl).c_double }).is_sign_positive() {
            1
        } else {
            -1
        }
    } else {
        0
    } != 0
    {
        if (unsafe { (*jsodbl).c_double }) > 0 as i32 as f64 {
            size = unsafe { snprintf(
                buf.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 128]>() as u64,
                b"Infinity\0" as *const u8 as *const i8,
            ) };
        } else {
            size = unsafe { snprintf(
                buf.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 128]>() as u64,
                b"-Infinity\0" as *const u8 as *const i8,
            ) };
        }
    } else {
        let mut std_format: *const i8 = b"%.17g\0" as *const u8 as *const i8;
        let mut format_drops_decimals: i32 = 0 as i32;
        let mut looks_numeric: i32 = 0 as i32;
        if format.is_null() {
            if !(unsafe { tls_serialization_float_format }).is_null() {
                format = unsafe { tls_serialization_float_format };
            } else if !(unsafe { global_serialization_float_format }).is_null() {
                format = unsafe { global_serialization_float_format };
            } else {
                format = std_format;
            }
        }
        size = unsafe { snprintf(
            buf.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 128]>() as u64,
            format,
            (*jsodbl).c_double,
        ) };
        if size < 0 as i32 {
            return -(1 as i32);
        }
        p = unsafe { strchr(buf.as_mut_ptr(), ',' as i32) };
        if !p.is_null() {
            (unsafe { *p = '.' as i32 as i8 });
        } else {
            p = unsafe { strchr(buf.as_mut_ptr(), '.' as i32) };
        }
        if format == std_format || (unsafe { strstr(format, b".0f\0" as *const u8 as *const i8) }).is_null() {
            format_drops_decimals = 1 as i32;
        }
        looks_numeric = (buf[0 as i32 as usize] as i32 >= '0' as i32
            && buf[0 as i32 as usize] as i32 <= '9' as i32
            || size > 1 as i32
                && buf[0 as i32 as usize] as i32 == '-' as i32
                && (buf[1 as i32 as usize] as i32 >= '0' as i32
                    && buf[1 as i32 as usize] as i32 <= '9' as i32)) as i32;
        if size < ::std::mem::size_of::<[i8; 128]>() as u64 as i32 - 2 as i32
            && looks_numeric != 0
            && p.is_null()
            && (unsafe { strchr(buf.as_mut_ptr(), 'e' as i32) }).is_null()
            && format_drops_decimals != 0
        {
            (unsafe { strcat(buf.as_mut_ptr(), b".0\0" as *const u8 as *const i8) });
            size += 2 as i32;
        }
        if !p.is_null() && flags & (1 as i32) << 2 as i32 != 0 {
            p = unsafe { p.offset(1) };
            q = p;
            while (unsafe { *q }) != 0 {
                if (unsafe { *q }) as i32 != '0' as i32 {
                    p = q;
                }
                q = unsafe { q.offset(1) };
            }
            if (unsafe { *p }) as i32 != 0 as i32 {
                p = unsafe { p.offset(1) };
                (unsafe { *p = 0 as i32 as i8 });
            }
            size = (unsafe { p.offset_from(buf.as_mut_ptr()) }) as i64 as i32;
        }
    }
    if size < 0 as i32 {
        return -(1 as i32);
    }
    if size >= ::std::mem::size_of::<[i8; 128]>() as u64 as i32 {
        size = (::std::mem::size_of::<[i8; 128]>() as u64).wrapping_sub(1 as i32 as u64) as i32;
    }
    printbuf_memappend(pb, buf.as_mut_ptr(), size);
    return size;
}
extern "C" fn json_object_double_to_json_string_default(
    mut jso: *mut crate::src::json_object::json_object,
    mut pb: *mut crate::src::apps::json_parse::printbuf,
    mut level: i32,
    mut flags: i32,
) -> i32 {
    return json_object_double_to_json_string_format(jso, pb, level, flags, 0 as *const i8);
}
#[no_mangle]
pub extern "C" fn json_object_double_to_json_string(
    mut jso: *mut crate::src::json_object::json_object,
    mut pb: *mut crate::src::apps::json_parse::printbuf,
    mut level: i32,
    mut flags: i32,
) -> i32 {
    return json_object_double_to_json_string_format(
        jso,
        pb,
        level,
        flags,
        (unsafe { (*jso)._userdata }) as *const i8,
    );
}
#[no_mangle]
pub extern "C" fn json_object_new_double(mut d: f64) -> *mut crate::src::json_object::json_object {
    let mut jso: *mut crate::src::json_object::json_object_double = json_object_new(
        json_type_double,
        ::std::mem::size_of::<json_object_double>() as u64,
        Some(json_object_double_to_json_string),
    )
        as *mut json_object_double;
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    let mut fresh22 = unsafe { &mut ((*jso).base._to_json_string) };
    *fresh22 = Some(json_object_double_to_json_string_default);
    (unsafe { (*jso).c_double = d });
    return unsafe { &mut (*jso).base };
}
#[no_mangle]
pub extern "C" fn json_object_new_double_s(
    mut d: f64,
    mut ds: *const i8,
) -> *mut crate::src::json_object::json_object {
    let mut new_ds: *mut i8 = 0 as *mut i8;
    let mut jso: *mut crate::src::json_object::json_object = json_object_new_double(d);
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    new_ds = unsafe { strdup(ds) };
    if new_ds.is_null() {
        json_object_generic_delete(jso);
        (unsafe { *__errno_location() = 12 as i32 });
        return 0 as *mut json_object;
    }
    json_object_set_serializer(
        jso,
        Some(_json_object_userdata_to_json_string),
        new_ds as *mut libc::c_void,
        Some(json_object_free_userdata),
    );
    return jso;
}
extern "C" fn _json_object_userdata_to_json_string(
    mut jso: *mut crate::src::json_object::json_object,
    mut pb: *mut crate::src::apps::json_parse::printbuf,
    mut level: i32,
    mut flags: i32,
) -> i32 {
    return json_object_userdata_to_json_string(jso, pb, level, flags);
}
#[no_mangle]
pub extern "C" fn json_object_userdata_to_json_string(
    mut jso: *mut crate::src::json_object::json_object,
    mut pb: *mut crate::src::apps::json_parse::printbuf,
    mut _level: i32,
    mut _flags: i32,
) -> i32 {
    let mut userdata_len: i32 = (unsafe { strlen((*jso)._userdata as *const i8) }) as i32;
    printbuf_memappend(pb, (unsafe { (*jso)._userdata }) as *const i8, userdata_len);
    return userdata_len;
}
#[no_mangle]
pub extern "C" fn json_object_free_userdata(
    mut _jso: *mut crate::src::json_object::json_object,
    mut userdata: *mut core::ffi::c_void,
) {
    (unsafe { free(userdata) });
}
#[no_mangle]
pub extern "C" fn json_object_get_double(
    mut jso: *const crate::src::json_object::json_object,
) -> f64 {
    let mut cdouble: f64 = 0.;
    let mut errPtr: *mut i8 = 0 as *mut i8;
    if jso.is_null() {
        return 0.0f64;
    }
    match (unsafe { (*jso).o_type }) as u32 {
        2 => return unsafe { (*JC_DOUBLE_C(jso)).c_double },
        3 => match (unsafe { (*JC_INT_C(jso)).cint_type }) as u32 {
            0 => return (unsafe { (*JC_INT_C(jso)).cint.c_int64 }) as f64,
            1 => return (unsafe { (*JC_INT_C(jso)).cint.c_uint64 }) as f64,
            _ => {
                json_abort(b"invalid cint_type\0" as *const u8 as *const i8);
            },
        },
        1 => return (unsafe { (*JC_BOOL_C(jso)).c_boolean }) as f64,
        6 => {
            (unsafe { *__errno_location() = 0 as i32 });
            cdouble = unsafe { strtod(get_string_component(jso), &mut errPtr) };
            if errPtr == get_string_component(jso) as *mut i8 {
                (unsafe { *__errno_location() = 22 as i32 });
                return 0.0f64;
            }
            if (unsafe { *errPtr }) as i32 != '\u{0}' as i32 {
                (unsafe { *__errno_location() = 22 as i32 });
                return 0.0f64;
            }
            if (::std::f64::INFINITY == cdouble || -::std::f64::INFINITY == cdouble)
                && 34 as i32 == (unsafe { *__errno_location() })
            {
                cdouble = 0.0f64;
            }
            return cdouble;
        },
        _ => {
            (unsafe { *__errno_location() = 22 as i32 });
            return 0.0f64;
        },
    };
}
#[no_mangle]
pub extern "C" fn json_object_set_double(
    mut jso: *mut crate::src::json_object::json_object,
    mut new_value: f64,
) -> i32 {
    if jso.is_null() || (unsafe { (*jso).o_type }) as u32 != json_type_double as i32 as u32 {
        return 0 as i32;
    }
    (unsafe { (*JC_DOUBLE(jso)).c_double = new_value });
    if (unsafe { (*jso)._to_json_string }).map(|f| f as usize)
        == (Some(_json_object_userdata_to_json_string)).map(|f| f as usize)
    {
        json_object_set_serializer(jso, None, 0 as *mut libc::c_void, None);
    }
    return 1 as i32;
}
extern "C" fn json_object_string_to_json_string(
    mut jso: *mut crate::src::json_object::json_object,
    mut pb: *mut crate::src::apps::json_parse::printbuf,
    mut _level: i32,
    mut flags: i32,
) -> i32 {
    let mut len: i64 = unsafe { (*JC_STRING(jso)).len };
    printbuf_memappend(
        pb,
        b"\"\0" as *const u8 as *const i8,
        (::std::mem::size_of::<[i8; 2]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
    );
    json_escape_str(
        pb,
        get_string_component(jso),
        (if len < 0 as i32 as i64 { -len } else { len }) as size_t,
        flags,
    );
    printbuf_memappend(
        pb,
        b"\"\0" as *const u8 as *const i8,
        (::std::mem::size_of::<[i8; 2]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
    );
    return 0 as i32;
}
extern "C" fn json_object_string_delete(mut jso: *mut crate::src::json_object::json_object) {
    if (unsafe { (*JC_STRING(jso)).len }) < 0 as i32 as i64 {
        (unsafe { free((*JC_STRING(jso)).c_string.pdata as *mut libc::c_void) });
    }
    json_object_generic_delete(jso);
}
extern "C" fn _json_object_new_string(
    mut s: *const i8,
    len: u64,
) -> *mut crate::src::json_object::json_object {
    let mut objsize: u64 = 0;
    let mut jso: *mut crate::src::json_object::json_object_string = 0 as *mut json_object_string;
    if len
        > (9223372036854775807 as i64 as u64)
            .wrapping_sub(
                (::std::mem::size_of::<json_object_string>() as u64)
                    .wrapping_sub(::std::mem::size_of::<C2RustUnnamed>() as u64),
            )
            .wrapping_sub(1 as i32 as u64)
    {
        return 0 as *mut json_object;
    }
    objsize = (::std::mem::size_of::<json_object_string>() as u64)
        .wrapping_sub(::std::mem::size_of::<C2RustUnnamed>() as u64)
        .wrapping_add(len)
        .wrapping_add(1 as i32 as u64);
    if len < ::std::mem::size_of::<*mut libc::c_void>() as u64 {
        objsize = (objsize as u64)
            .wrapping_add((::std::mem::size_of::<*mut libc::c_void>() as u64).wrapping_sub(len))
            as size_t as size_t;
    }
    jso = json_object_new(
        json_type_string,
        objsize,
        Some(json_object_string_to_json_string),
    ) as *mut json_object_string;
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    (unsafe { (*jso).len = len as ssize_t });
    (unsafe { memcpy(
        ((*jso).c_string.idata).as_mut_ptr() as *mut libc::c_void,
        s as *const libc::c_void,
        len,
    ) });
    (unsafe { *((*jso).c_string.idata).as_mut_ptr().offset(len as isize) = '\u{0}' as i32 as i8 });
    return unsafe { &mut (*jso).base };
}
#[no_mangle]
pub extern "C" fn json_object_new_string(
    mut s: *const i8,
) -> *mut crate::src::json_object::json_object {
    return _json_object_new_string(s, unsafe { strlen(s) });
}
#[no_mangle]
pub extern "C" fn json_object_new_string_len(
    mut s: *const i8,
    len: i32,
) -> *mut crate::src::json_object::json_object {
    return _json_object_new_string(s, len as size_t);
}
#[no_mangle]
pub extern "C" fn json_object_get_string(
    mut jso: *mut crate::src::json_object::json_object,
) -> *const i8 {
    if jso.is_null() {
        return 0 as *const i8;
    }
    match (unsafe { (*jso).o_type }) as u32 {
        6 => return get_string_component(jso),
        _ => return json_object_to_json_string(jso),
    };
}
#[inline]
extern "C" fn _json_object_get_string_len(
    mut jso: *const crate::src::json_object::json_object_string,
) -> i64 {
    let mut len: i64 = 0;
    len = unsafe { (*jso).len };
    return if len < 0 as i32 as i64 { -len } else { len };
}
#[no_mangle]
pub extern "C" fn json_object_get_string_len(
    mut jso: *const crate::src::json_object::json_object,
) -> i32 {
    if jso.is_null() {
        return 0 as i32;
    }
    match (unsafe { (*jso).o_type }) as u32 {
        6 => return _json_object_get_string_len(JC_STRING_C(jso)) as i32,
        _ => return 0 as i32,
    };
}
extern "C" fn _json_object_set_string_len(
    mut jso: *mut crate::src::json_object::json_object,
    mut s: *const i8,
    mut len: u64,
) -> i32 {
    let mut dstbuf: *mut i8 = 0 as *mut i8;
    let mut curlen: i64 = 0;
    let mut newlen: i64 = 0;
    if jso.is_null() || (unsafe { (*jso).o_type }) as u32 != json_type_string as i32 as u32 {
        return 0 as i32;
    }
    if len >= (2147483647 as i32 - 1 as i32) as u64 {
        return 0 as i32;
    }
    curlen = unsafe { (*JC_STRING(jso)).len };
    if curlen < 0 as i32 as i64 {
        if len == 0 as i32 as u64 {
            (unsafe { free((*JC_STRING(jso)).c_string.pdata as *mut libc::c_void) });
            curlen = 0 as i32 as ssize_t;
            (unsafe { (*JC_STRING(jso)).len = curlen });
        } else {
            curlen = -curlen;
        }
    }
    newlen = len as ssize_t;
    dstbuf = get_string_component_mutable(jso);
    if len as ssize_t > curlen {
        dstbuf = (unsafe { malloc(len.wrapping_add(1 as i32 as u64)) }) as *mut i8;
        if dstbuf.is_null() {
            return 0 as i32;
        }
        if (unsafe { (*JC_STRING(jso)).len }) < 0 as i32 as i64 {
            (unsafe { free((*JC_STRING(jso)).c_string.pdata as *mut libc::c_void) });
        }
        let mut fresh23 = unsafe { &mut ((*JC_STRING(jso)).c_string.pdata) };
        *fresh23 = dstbuf;
        newlen = -(len as ssize_t);
    } else if (unsafe { (*JC_STRING(jso)).len }) < 0 as i32 as i64 {
        newlen = -(len as ssize_t);
    }
    (unsafe { memcpy(dstbuf as *mut libc::c_void, s as *const libc::c_void, len) });
    (unsafe { *dstbuf.offset(len as isize) = '\u{0}' as i32 as i8 });
    (unsafe { (*JC_STRING(jso)).len = newlen });
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn json_object_set_string(
    mut jso: *mut crate::src::json_object::json_object,
    mut s: *const i8,
) -> i32 {
    return _json_object_set_string_len(jso, s, unsafe { strlen(s) });
}
#[no_mangle]
pub extern "C" fn json_object_set_string_len(
    mut jso: *mut crate::src::json_object::json_object,
    mut s: *const i8,
    mut len: i32,
) -> i32 {
    return _json_object_set_string_len(jso, s, len as size_t);
}
extern "C" fn json_object_array_to_json_string(
    mut jso: *mut crate::src::json_object::json_object,
    mut pb: *mut crate::src::apps::json_parse::printbuf,
    mut level: i32,
    mut flags: i32,
) -> i32 {
    let mut had_children: i32 = 0 as i32;
    let mut ii: u64 = 0;
    printbuf_memappend(
        pb,
        b"[\0" as *const u8 as *const i8,
        (::std::mem::size_of::<[i8; 2]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
    );
    ii = 0 as i32 as size_t;
    while ii < json_object_array_length(jso) {
        let mut val: *mut crate::src::json_object::json_object = 0 as *mut json_object;
        if had_children != 0 {
            printbuf_memappend(
                pb,
                b",\0" as *const u8 as *const i8,
                (::std::mem::size_of::<[i8; 2]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
            );
        }
        if flags & (1 as i32) << 1 as i32 != 0 {
            printbuf_memappend(
                pb,
                b"\n\0" as *const u8 as *const i8,
                (::std::mem::size_of::<[i8; 2]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
            );
        }
        had_children = 1 as i32;
        if flags & (1 as i32) << 0 as i32 != 0 && flags & (1 as i32) << 1 as i32 == 0 {
            printbuf_memappend(
                pb,
                b" \0" as *const u8 as *const i8,
                (::std::mem::size_of::<[i8; 2]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
            );
        }
        indent(pb, level + 1 as i32, flags);
        val = json_object_array_get_idx(jso, ii);
        if val.is_null() {
            printbuf_memappend(
                pb,
                b"null\0" as *const u8 as *const i8,
                (::std::mem::size_of::<[i8; 5]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
            );
        } else if (unsafe { ((*val)._to_json_string).expect("non-null function pointer")(
            val,
            pb,
            level + 1 as i32,
            flags,
        ) }) < 0 as i32
        {
            return -(1 as i32);
        }
        ii = ii.wrapping_add(1);
    }
    if flags & (1 as i32) << 1 as i32 != 0 && had_children != 0 {
        printbuf_memappend(
            pb,
            b"\n\0" as *const u8 as *const i8,
            (::std::mem::size_of::<[i8; 2]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
        );
        indent(pb, level, flags);
    }
    if flags & (1 as i32) << 0 as i32 != 0 && flags & (1 as i32) << 1 as i32 == 0 {
        return printbuf_memappend(
            pb,
            b" ]\0" as *const u8 as *const i8,
            (::std::mem::size_of::<[i8; 3]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
        );
    }
    return printbuf_memappend(
        pb,
        b"]\0" as *const u8 as *const i8,
        (::std::mem::size_of::<[i8; 2]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
    );
}
extern "C" fn json_object_array_entry_free(mut data: *mut core::ffi::c_void) {
    json_object_put(data as *mut json_object);
}
extern "C" fn json_object_array_delete(mut jso: *mut crate::src::json_object::json_object) {
    array_list_free(unsafe { (*JC_ARRAY(jso)).c_array });
    json_object_generic_delete(jso);
}
#[no_mangle]
pub extern "C" fn json_object_new_array() -> *mut crate::src::json_object::json_object {
    return json_object_new_array_ext(32 as i32);
}
#[no_mangle]
pub extern "C" fn json_object_new_array_ext(
    mut initial_size: i32,
) -> *mut crate::src::json_object::json_object {
    let mut jso: *mut crate::src::json_object::json_object_array = json_object_new(
        json_type_array,
        ::std::mem::size_of::<json_object_array>() as u64,
        Some(json_object_array_to_json_string),
    ) as *mut json_object_array;
    if jso.is_null() {
        return 0 as *mut json_object;
    }
    let mut fresh24 = unsafe { &mut ((*jso).c_array) };
    *fresh24 = array_list_new2(Some(json_object_array_entry_free), initial_size);
    if (unsafe { (*jso).c_array }).is_null() {
        (unsafe { free(jso as *mut libc::c_void) });
        return 0 as *mut json_object;
    }
    return unsafe { &mut (*jso).base };
}
#[no_mangle]
pub extern "C" fn json_object_get_array(
    mut jso: *const crate::src::json_object::json_object,
) -> *mut crate::src::arraylist::array_list {
    if jso.is_null() {
        return 0 as *mut array_list;
    }
    match (unsafe { (*jso).o_type }) as u32 {
        5 => return unsafe { (*JC_ARRAY_C(jso)).c_array },
        _ => return 0 as *mut array_list,
    };
}
#[no_mangle]
pub extern "C" fn json_object_array_sort(
    mut jso: *mut crate::src::json_object::json_object,
    mut sort_fn: Option<
        unsafe extern "C" fn(_: *const core::ffi::c_void, _: *const core::ffi::c_void) -> i32,
    >,
) {
    if json_object_get_type(jso) as u32 == json_type_array as i32 as u32 {
    } else {
        (unsafe { __assert_fail (b"json_object_get_type(jso) == json_type_array\0" as * const u8 as * const i8 , b"/home/xial/json-c/json_object.c\0" as * const u8 as * const i8 , 1453 as i32 as u32 , (* core :: intrinsics :: transmute :: < & '_ [u8 ; 87] , & '_ [i8 ; 87] > (b"void json_object_array_sort(struct json_object *, int (*)(const void *, const void *))\0" ,)) . as_ptr () ,) }) ;
    }
    array_list_sort(unsafe { (*JC_ARRAY(jso)).c_array }, sort_fn);
}
#[no_mangle]
pub extern "C" fn json_object_array_bsearch(
    mut key: *const crate::src::json_object::json_object,
    mut jso: *const crate::src::json_object::json_object,
    mut sort_fn: Option<
        unsafe extern "C" fn(_: *const core::ffi::c_void, _: *const core::ffi::c_void) -> i32,
    >,
) -> *mut crate::src::json_object::json_object {
    let mut result: *mut *mut crate::src::json_object::json_object =
        0 as *mut *mut crate::src::json_object::json_object;
    if json_object_get_type(jso) as u32 == json_type_array as i32 as u32 {
    } else {
        (unsafe { __assert_fail (b"json_object_get_type(jso) == json_type_array\0" as * const u8 as * const i8 , b"/home/xial/json-c/json_object.c\0" as * const u8 as * const i8 , 1463 as i32 as u32 , (* core :: intrinsics :: transmute :: < & '_ [u8 ; 139] , & '_ [i8 ; 139] > (b"struct json_object *json_object_array_bsearch(const struct json_object *, const struct json_object *, int (*)(const void *, const void *))\0" ,)) . as_ptr () ,) }) ;
    }
    result = array_list_bsearch(
        &mut key as *mut *const json_object as *mut libc::c_void as *mut *const libc::c_void,
        unsafe { (*JC_ARRAY_C(jso)).c_array },
        sort_fn,
    ) as *mut *mut json_object;
    if result.is_null() {
        return 0 as *mut json_object;
    }
    return unsafe { *result };
}
#[no_mangle]
pub extern "C" fn json_object_array_length(
    mut jso: *const crate::src::json_object::json_object,
) -> u64 {
    if json_object_get_type(jso) as u32 == json_type_array as i32 as u32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_type(jso) == json_type_array\0" as *const u8 as *const i8,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const i8,
            1474 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 60], &'_ [i8; 60]>(
                b"size_t json_object_array_length(const struct json_object *)\0",
            ))
            .as_ptr(),
        ) });
    }
    return array_list_length(unsafe { (*JC_ARRAY_C(jso)).c_array });
}
#[no_mangle]
pub extern "C" fn json_object_array_add(
    mut jso: *mut crate::src::json_object::json_object,
    mut val: *mut crate::src::json_object::json_object,
) -> i32 {
    if json_object_get_type(jso) as u32 == json_type_array as i32 as u32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_type(jso) == json_type_array\0" as *const u8 as *const i8,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const i8,
            1480 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 70], &'_ [i8; 70]>(
                b"int json_object_array_add(struct json_object *, struct json_object *)\0",
            ))
            .as_ptr(),
        ) });
    }
    return array_list_add(unsafe { (*JC_ARRAY(jso)).c_array }, val as *mut libc::c_void);
}
#[no_mangle]
pub extern "C" fn json_object_array_put_idx(
    mut jso: *mut crate::src::json_object::json_object,
    mut idx: u64,
    mut val: *mut crate::src::json_object::json_object,
) -> i32 {
    if json_object_get_type(jso) as u32 == json_type_array as i32 as u32 {
    } else {
        (unsafe { __assert_fail (b"json_object_get_type(jso) == json_type_array\0" as * const u8 as * const i8 , b"/home/xial/json-c/json_object.c\0" as * const u8 as * const i8 , 1486 as i32 as u32 , (* core :: intrinsics :: transmute :: < & '_ [u8 ; 82] , & '_ [i8 ; 82] > (b"int json_object_array_put_idx(struct json_object *, size_t, struct json_object *)\0" ,)) . as_ptr () ,) }) ;
    }
    return array_list_put_idx(unsafe { (*JC_ARRAY(jso)).c_array }, idx, val as *mut libc::c_void);
}
#[no_mangle]
pub extern "C" fn json_object_array_del_idx(
    mut jso: *mut crate::src::json_object::json_object,
    mut idx: u64,
    mut count: u64,
) -> i32 {
    if json_object_get_type(jso) as u32 == json_type_array as i32 as u32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_type(jso) == json_type_array\0" as *const u8 as *const i8,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const i8,
            1492 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 68], &'_ [i8; 68]>(
                b"int json_object_array_del_idx(struct json_object *, size_t, size_t)\0",
            ))
            .as_ptr(),
        ) });
    }
    return array_list_del_idx(unsafe { (*JC_ARRAY(jso)).c_array }, idx, count);
}
#[no_mangle]
pub extern "C" fn json_object_array_get_idx(
    mut jso: *const crate::src::json_object::json_object,
    mut idx: u64,
) -> *mut crate::src::json_object::json_object {
    if json_object_get_type(jso) as u32 == json_type_array as i32 as u32 {
    } else {
        (unsafe { __assert_fail (b"json_object_get_type(jso) == json_type_array\0" as * const u8 as * const i8 , b"/home/xial/json-c/json_object.c\0" as * const u8 as * const i8 , 1498 as i32 as u32 , (* core :: intrinsics :: transmute :: < & '_ [u8 ; 82] , & '_ [i8 ; 82] > (b"struct json_object *json_object_array_get_idx(const struct json_object *, size_t)\0" ,)) . as_ptr () ,) }) ;
    }
    return array_list_get_idx(unsafe { (*JC_ARRAY_C(jso)).c_array }, idx) as *mut json_object;
}
extern "C" fn json_array_equal(
    mut jso1: *mut crate::src::json_object::json_object,
    mut jso2: *mut crate::src::json_object::json_object,
) -> i32 {
    let mut len: u64 = 0;
    let mut i: u64 = 0;
    len = json_object_array_length(jso1);
    if len != json_object_array_length(jso2) {
        return 0 as i32;
    }
    i = 0 as i32 as size_t;
    while i < len {
        if json_object_equal(
            json_object_array_get_idx(jso1, i),
            json_object_array_get_idx(jso2, i),
        ) == 0
        {
            return 0 as i32;
        }
        i = i.wrapping_add(1);
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn json_object_array_shrink(
    mut jso: *mut crate::src::json_object::json_object,
    mut empty_slots: i32,
) -> i32 {
    if empty_slots < 0 as i32 {
        json_abort(
            b"json_object_array_shrink called with negative empty_slots\0" as *const u8
                as *const i8,
        );
    }
    return array_list_shrink(unsafe { (*JC_ARRAY(jso)).c_array }, empty_slots as size_t);
}
#[no_mangle]
pub extern "C" fn json_object_new_null() -> *mut crate::src::json_object::json_object {
    return 0 as *mut json_object;
}
extern "C" fn json_object_all_values_equal(
    mut jso1: *mut crate::src::json_object::json_object,
    mut jso2: *mut crate::src::json_object::json_object,
) -> i32 {
    let mut iter: crate::src::json_object::json_object_iter = json_object_iter {
        key: 0 as *mut i8,
        val: 0 as *mut json_object,
        entry: 0 as *mut lh_entry,
    };
    let mut sub: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    if json_object_get_type(jso1) as u32 == json_type_object as i32 as u32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_type(jso1) == json_type_object\0" as *const u8 as *const i8,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const i8,
            1536 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 77], &'_ [i8; 77]>(
                b"int json_object_all_values_equal(struct json_object *, struct json_object *)\0",
            ))
            .as_ptr(),
        ) });
    }
    if json_object_get_type(jso2) as u32 == json_type_object as i32 as u32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_get_type(jso2) == json_type_object\0" as *const u8 as *const i8,
            b"/home/xial/json-c/json_object.c\0" as *const u8 as *const i8,
            1537 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 77], &'_ [i8; 77]>(
                b"int json_object_all_values_equal(struct json_object *, struct json_object *)\0",
            ))
            .as_ptr(),
        ) });
    }
    iter.entry = lh_table_head(json_object_get_object(jso1));
    while !if !(iter.entry).is_null() {
        iter.key = lh_entry_k(iter.entry) as *mut i8;
        iter.val = lh_entry_v(iter.entry) as *mut json_object;
        iter.entry
    } else {
        0 as *mut lh_entry
    }
    .is_null()
    {
        if lh_table_lookup_ex(
            unsafe { (*JC_OBJECT(jso2)).c_object },
            iter.key as *mut libc::c_void,
            &mut sub as *mut *mut json_object as *mut libc::c_void as *mut *mut libc::c_void,
        ) == 0
        {
            return 0 as i32;
        }
        if json_object_equal(iter.val, sub) == 0 {
            return 0 as i32;
        }
        iter.entry = lh_entry_next(iter.entry);
    }
    iter.entry = lh_table_head(json_object_get_object(jso2));
    while !if !(iter.entry).is_null() {
        iter.key = lh_entry_k(iter.entry) as *mut i8;
        iter.val = lh_entry_v(iter.entry) as *mut json_object;
        iter.entry
    } else {
        0 as *mut lh_entry
    }
    .is_null()
    {
        if lh_table_lookup_ex(
            unsafe { (*JC_OBJECT(jso1)).c_object },
            iter.key as *mut libc::c_void,
            &mut sub as *mut *mut json_object as *mut libc::c_void as *mut *mut libc::c_void,
        ) == 0
        {
            return 0 as i32;
        }
        iter.entry = lh_entry_next(iter.entry);
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn json_object_equal(
    mut jso1: *mut crate::src::json_object::json_object,
    mut jso2: *mut crate::src::json_object::json_object,
) -> i32 {
    if jso1 == jso2 {
        return 1 as i32;
    }
    if jso1.is_null() || jso2.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*jso1).o_type }) as u32 != (unsafe { (*jso2).o_type }) as u32 {
        return 0 as i32;
    }
    match (unsafe { (*jso1).o_type }) as u32 {
        1 => {
            return ((unsafe { (*JC_BOOL(jso1)).c_boolean }) == (unsafe { (*JC_BOOL(jso2)).c_boolean })) as i32;
        },
        2 => {
            return ((unsafe { (*JC_DOUBLE(jso1)).c_double }) == (unsafe { (*JC_DOUBLE(jso2)).c_double })) as i32;
        },
        3 => {
            let mut int1: *mut crate::src::json_object::json_object_int = JC_INT(jso1);
            let mut int2: *mut crate::src::json_object::json_object_int = JC_INT(jso2);
            if (unsafe { (*int1).cint_type }) as u32 == json_object_int_type_int64 as i32 as u32 {
                if (unsafe { (*int2).cint_type }) as u32 == json_object_int_type_int64 as i32 as u32 {
                    return ((unsafe { (*int1).cint.c_int64 }) == (unsafe { (*int2).cint.c_int64 })) as i32;
                }
                if (unsafe { (*int1).cint.c_int64 }) < 0 as i32 as i64 {
                    return 0 as i32;
                }
                return ((unsafe { (*int1).cint.c_int64 }) as uint64_t == (unsafe { (*int2).cint.c_uint64 })) as i32;
            }
            if (unsafe { (*int2).cint_type }) as u32 == json_object_int_type_uint64 as i32 as u32 {
                return ((unsafe { (*int1).cint.c_uint64 }) == (unsafe { (*int2).cint.c_uint64 })) as i32;
            }
            if (unsafe { (*int2).cint.c_int64 }) < 0 as i32 as i64 {
                return 0 as i32;
            }
            return ((unsafe { (*int1).cint.c_uint64 }) == (unsafe { (*int2).cint.c_int64 }) as uint64_t) as i32;
        },
        6 => {
            return (_json_object_get_string_len(JC_STRING(jso1))
                == _json_object_get_string_len(JC_STRING(jso2))
                && (unsafe { memcmp(
                    get_string_component(jso1) as *const libc::c_void,
                    get_string_component(jso2) as *const libc::c_void,
                    _json_object_get_string_len(JC_STRING(jso1)) as u64,
                ) }) == 0 as i32) as i32;
        },
        4 => return json_object_all_values_equal(jso1, jso2),
        5 => return json_array_equal(jso1, jso2),
        0 => return 1 as i32,
        _ => {},
    }
    return 0 as i32;
}
extern "C" fn json_object_copy_serializer_data(
    mut src: *mut crate::src::json_object::json_object,
    mut dst: *mut crate::src::json_object::json_object,
) -> i32 {
    if (unsafe { (*src)._userdata }).is_null() && (unsafe { ((*src)._user_delete).is_none() }) {
        return 0 as i32;
    }
    if (unsafe { (*dst)._to_json_string }).map(|f| f as usize)
        == (Some(json_object_userdata_to_json_string)).map(|f| f as usize)
        || (unsafe { (*dst)._to_json_string }).map(|f| f as usize)
            == (Some(_json_object_userdata_to_json_string)).map(|f| f as usize)
    {
        let mut p: *mut i8 = 0 as *mut i8;
        if !(unsafe { (*src)._userdata }).is_null() {
        } else {
            (unsafe { __assert_fail (b"src->_userdata\0" as * const u8 as * const i8 , b"/home/xial/json-c/json_object.c\0" as * const u8 as * const i8 , 1623 as i32 as u32 , (* core :: intrinsics :: transmute :: < & '_ [u8 ; 81] , & '_ [i8 ; 81] > (b"int json_object_copy_serializer_data(struct json_object *, struct json_object *)\0" ,)) . as_ptr () ,) }) ;
        }
        p = unsafe { strdup((*src)._userdata as *const i8) };
        if p.is_null() {
            (unsafe { _json_c_set_last_err(
                b"json_object_copy_serializer_data: out of memory\n\0" as *const u8 as *const i8,
            ) });
            return -(1 as i32);
        }
        let mut fresh25 = unsafe { &mut ((*dst)._userdata) };
        *fresh25 = p as *mut libc::c_void;
    } else {
        (unsafe { _json_c_set_last_err(
            b"json_object_copy_serializer_data: unable to copy unknown serializer data: %p\n\0"
                as *const u8 as *const i8,
            core::intrinsics::transmute::<
                Option<
                    unsafe extern "C" fn(
                        _: *mut crate::src::json_object::json_object,
                        _: *mut crate::src::apps::json_parse::printbuf,
                        _: i32,
                        _: i32,
                    ) -> i32,
                >,
                *mut core::ffi::c_void,
            >((*dst)._to_json_string),
        ) });
        return -(1 as i32);
    }
    let mut fresh26 = unsafe { &mut ((*dst)._user_delete) };
    *fresh26 = unsafe { (*src)._user_delete };
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn json_c_shallow_copy_default(
    mut src: *mut crate::src::json_object::json_object,
    mut _parent: *mut crate::src::json_object::json_object,
    mut _key: *const i8,
    mut _index: u64,
    mut dst: *mut *mut crate::src::json_object::json_object,
) -> i32 {
    match (unsafe { (*src).o_type }) as u32 {
        1 => {
            (unsafe { *dst = json_object_new_boolean((*JC_BOOL(src)).c_boolean) });
        },
        2 => {
            (unsafe { *dst = json_object_new_double((*JC_DOUBLE(src)).c_double) });
        },
        3 => match (unsafe { (*JC_INT(src)).cint_type }) as u32 {
            0 => {
                (unsafe { *dst = json_object_new_int64((*JC_INT(src)).cint.c_int64) });
            },
            1 => {
                (unsafe { *dst = json_object_new_uint64((*JC_INT(src)).cint.c_uint64) });
            },
            _ => {
                json_abort(b"invalid cint_type\0" as *const u8 as *const i8);
            },
        },
        6 => {
            (unsafe { *dst = json_object_new_string_len(
                get_string_component(src),
                _json_object_get_string_len(JC_STRING(src)) as i32,
            ) });
        },
        4 => {
            (unsafe { *dst = json_object_new_object() });
        },
        5 => {
            (unsafe { *dst = json_object_new_array() });
        },
        _ => {
            (unsafe { *__errno_location() = 22 as i32 });
            return -(1 as i32);
        },
    }
    if (unsafe { *dst }).is_null() {
        (unsafe { *__errno_location() = 12 as i32 });
        return -(1 as i32);
    }
    let mut fresh27 = unsafe { &mut ((**dst)._to_json_string) };
    *fresh27 = unsafe { (*src)._to_json_string };
    return 1 as i32;
}
extern "C" fn json_object_deep_copy_recursive(
    mut src: *mut crate::src::json_object::json_object,
    mut parent: *mut crate::src::json_object::json_object,
    mut key_in_parent: *const i8,
    mut index_in_parent: u64,
    mut dst: *mut *mut crate::src::json_object::json_object,
    mut shallow_copy: Option<
        unsafe extern "C" fn(
            _: *mut crate::src::json_object::json_object,
            _: *mut crate::src::json_object::json_object,
            _: *const i8,
            _: u64,
            _: *mut *mut crate::src::json_object::json_object,
        ) -> i32,
    >,
) -> i32 {
    let mut iter: crate::src::json_object::json_object_iter = json_object_iter {
        key: 0 as *mut i8,
        val: 0 as *mut json_object,
        entry: 0 as *mut lh_entry,
    };
    let mut src_array_len: u64 = 0;
    let mut ii: u64 = 0;
    let mut shallow_copy_rc: i32 = 0 as i32;
    shallow_copy_rc = unsafe { shallow_copy.expect("non-null function pointer")(
        src,
        parent,
        key_in_parent,
        index_in_parent,
        dst,
    ) };
    if shallow_copy_rc < 1 as i32 {
        (unsafe { *__errno_location() = 22 as i32 });
        return -(1 as i32);
    }
    if !(unsafe { *dst }).is_null() {
    } else {
        (unsafe { __assert_fail (b"*dst != NULL\0" as * const u8 as * const i8 , b"/home/xial/json-c/json_object.c\0" as * const u8 as * const i8 , 1718 as i32 as u32 , (* core :: intrinsics :: transmute :: < & '_ [u8 ; 151] , & '_ [i8 ; 151] > (b"int json_object_deep_copy_recursive(struct json_object *, struct json_object *, const char *, size_t, struct json_object **, json_c_shallow_copy_fn *)\0" ,)) . as_ptr () ,) }) ;
    }
    match (unsafe { (*src).o_type }) as u32 {
        4 => {
            iter.entry = lh_table_head(json_object_get_object(src));
            while !if !(iter.entry).is_null() {
                iter.key = lh_entry_k(iter.entry) as *mut i8;
                iter.val = lh_entry_v(iter.entry) as *mut json_object;
                iter.entry
            } else {
                0 as *mut lh_entry
            }
            .is_null()
            {
                let mut jso: *mut crate::src::json_object::json_object = 0 as *mut json_object;
                if (iter.val).is_null() {
                    jso = 0 as *mut json_object;
                } else if json_object_deep_copy_recursive(
                    iter.val,
                    src,
                    iter.key,
                    (2147483647 as i32 as u32)
                        .wrapping_mul(2 as u32)
                        .wrapping_add(1 as u32) as size_t,
                    &mut jso,
                    shallow_copy,
                ) < 0 as i32
                {
                    json_object_put(jso);
                    return -(1 as i32);
                }
                if json_object_object_add(unsafe { *dst }, iter.key, jso) < 0 as i32 {
                    json_object_put(jso);
                    return -(1 as i32);
                }
                iter.entry = lh_entry_next(iter.entry);
            }
        },
        5 => {
            src_array_len = json_object_array_length(src);
            ii = 0 as i32 as size_t;
            while ii < src_array_len {
                let mut jso_0: *mut crate::src::json_object::json_object = 0 as *mut json_object;
                let mut jso1: *mut crate::src::json_object::json_object =
                    json_object_array_get_idx(src, ii);
                if jso1.is_null() {
                    jso_0 = 0 as *mut json_object;
                } else if json_object_deep_copy_recursive(
                    jso1,
                    src,
                    0 as *const i8,
                    ii,
                    &mut jso_0,
                    shallow_copy,
                ) < 0 as i32
                {
                    json_object_put(jso_0);
                    return -(1 as i32);
                }
                if json_object_array_add(unsafe { *dst }, jso_0) < 0 as i32 {
                    json_object_put(jso_0);
                    return -(1 as i32);
                }
                ii = ii.wrapping_add(1);
            }
        },
        _ => {},
    }
    if shallow_copy_rc != 2 as i32 {
        return json_object_copy_serializer_data(src, unsafe { *dst });
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn json_object_deep_copy(
    mut src: *mut crate::src::json_object::json_object,
    mut dst: *mut *mut crate::src::json_object::json_object,
    mut shallow_copy: Option<
        unsafe extern "C" fn(
            _: *mut crate::src::json_object::json_object,
            _: *mut crate::src::json_object::json_object,
            _: *const i8,
            _: u64,
            _: *mut *mut crate::src::json_object::json_object,
        ) -> i32,
    >,
) -> i32 {
    let mut rc: i32 = 0;
    if src.is_null() || dst.is_null() || !(unsafe { *dst }).is_null() {
        (unsafe { *__errno_location() = 22 as i32 });
        return -(1 as i32);
    }
    if shallow_copy.is_none() {
        shallow_copy = Some(json_c_shallow_copy_default);
    }
    rc = json_object_deep_copy_recursive(
        src,
        0 as *mut json_object,
        0 as *const i8,
        (2147483647 as i32 as u32)
            .wrapping_mul(2 as u32)
            .wrapping_add(1 as u32) as size_t,
        dst,
        shallow_copy,
    );
    if rc < 0 as i32 {
        json_object_put(unsafe { *dst });
        (unsafe { *dst = 0 as *mut json_object });
    }
    return rc;
}
#[cold]
extern "C" fn json_abort(mut message: *const i8) -> ! {
    if !message.is_null() {
        (unsafe { fprintf(
            stderr,
            b"json-c aborts with error: %s\n\0" as *const u8 as *const i8,
            message,
        ) });
    }
    (unsafe { abort() });
}
use crate::laertes_rt::*;
