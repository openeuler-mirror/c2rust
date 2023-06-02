use :: libc;
extern "C" {
    static mut stdout: *mut crate::src::apps::json_parse::_IO_FILE;
    fn fflush(__stream: *mut crate::src::apps::json_parse::_IO_FILE) -> i32;
    fn printf(_: *const i8, _: ...) -> i32;
    fn free(__ptr: *mut core::ffi::c_void);
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strdup(_: *const i8) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
}
pub use crate::src::{
    debug::{_IO_wide_data, mc_set_debug},
    json_object::{
        _IO_codecvt, json_object, json_object_array_add, json_object_array_bsearch,
        json_object_array_del_idx, json_object_array_get_idx, json_object_array_length,
        json_object_array_put_idx, json_object_array_sort, json_object_get, json_object_get_int,
        json_object_get_object, json_object_get_string, json_object_new_array,
        json_object_new_array_ext, json_object_new_boolean, json_object_new_int,
        json_object_new_null, json_object_new_object, json_object_new_string,
        json_object_object_add, json_object_object_del, json_object_put,
        json_object_to_json_string_ext, json_object_to_json_string_length,
    },
    json_visit::_IO_marker,
    tests::parse_flags::parse_flags,
};
pub type size_t = u64;
pub type __int32_t = i32;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type _IO_FILE = crate::src::apps::json_parse::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::apps::json_parse::_IO_FILE;
pub type int32_t = i32;
pub type uintptr_t = u64;
pub type lh_entry = crate::src::json_object::lh_entry;
pub type json_bool = i32;
pub type lh_table = crate::src::json_object::lh_table;
pub type lh_equal_fn =
    unsafe extern "C" fn(_: *const core::ffi::c_void, _: *const core::ffi::c_void) -> i32;
pub type lh_hash_fn = unsafe extern "C" fn(_: *const core::ffi::c_void) -> u64;
pub type lh_entry_free_fn = unsafe extern "C" fn(_: *mut crate::src::json_object::lh_entry) -> ();
#[inline]
extern "C" fn lh_table_head(
    mut t: *const crate::src::json_object::lh_table,
) -> *mut crate::src::json_object::lh_entry {
    return unsafe { (*t).head };
}
#[inline]
extern "C" fn lh_entry_k(
    mut e: *const crate::src::json_object::lh_entry,
) -> *mut core::ffi::c_void {
    return (unsafe { (*e).k }) as uintptr_t as *mut libc::c_void;
}
#[inline]
extern "C" fn lh_entry_v(
    mut e: *const crate::src::json_object::lh_entry,
) -> *mut core::ffi::c_void {
    return (unsafe { (*e).v }) as uintptr_t as *mut libc::c_void;
}
#[inline]
extern "C" fn lh_entry_next(
    mut e: *const crate::src::json_object::lh_entry,
) -> *mut crate::src::json_object::lh_entry {
    return unsafe { (*e).next };
}
extern "C" fn sort_fn(mut j1: *const core::ffi::c_void, mut j2: *const core::ffi::c_void) -> i32 {
    let mut jso1: *const *mut crate::src::json_object::json_object =
        0 as *const *mut crate::src::json_object::json_object;
    let mut jso2: *const *mut crate::src::json_object::json_object =
        0 as *const *mut crate::src::json_object::json_object;
    let mut i1: i32 = 0;
    let mut i2: i32 = 0;
    jso1 = j1 as *const *mut json_object;
    jso2 = j2 as *const *mut json_object;
    if (unsafe { *jso1 }).is_null() && (unsafe { *jso2 }).is_null() {
        return 0 as i32;
    }
    if (unsafe { *jso1 }).is_null() {
        return -(1 as i32);
    }
    if (unsafe { *jso2 }).is_null() {
        return 1 as i32;
    }
    i1 = json_object_get_int(unsafe { *jso1 });
    i2 = json_object_get_int(unsafe { *jso2 });
    return i1 - i2;
}
extern "C" fn to_json_string(
    mut obj: *mut crate::src::json_object::json_object,
    mut flags: i32,
) -> *const i8 {
    let mut length: u64 = 0;
    let mut copy: *mut i8 = 0 as *mut i8;
    let mut result: *const i8 = 0 as *const i8;
    result = json_object_to_json_string_length(obj, flags, Some(&mut length));
    copy = unsafe { strdup(result) };
    if copy.is_null() {
        (unsafe { printf(b"to_json_string: Allocation failed!\n\0" as *const u8 as *const i8) });
    } else {
        result = json_object_to_json_string_ext(obj, flags);
        if length != (unsafe { strlen(result) }) {
            (unsafe { printf(b"to_json_string: Length mismatch!\n\0" as *const u8 as *const i8) });
        }
        if (unsafe { strcmp(copy, result) }) != 0 as i32 {
            (unsafe { printf(b"to_json_string: Comparison Failed!\n\0" as *const u8 as *const i8) });
        }
        (unsafe { free(copy as *mut libc::c_void) });
    }
    return result;
}
#[no_mangle]
pub extern "C" fn make_array() -> *mut crate::src::json_object::json_object {
    let mut my_array: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    my_array = json_object_new_array();
    json_object_array_add(my_array, json_object_new_int(1 as i32));
    json_object_array_add(my_array, json_object_new_int(2 as i32));
    json_object_array_add(my_array, json_object_new_int(3 as i32));
    json_object_array_put_idx(my_array, 4 as i32 as size_t, json_object_new_int(5 as i32));
    json_object_array_put_idx(my_array, 3 as i32 as size_t, json_object_new_int(4 as i32));
    json_object_array_put_idx(my_array, 6 as i32 as size_t, json_object_new_int(7 as i32));
    return my_array;
}
#[no_mangle]
pub extern "C" fn test_array_del_idx() {
    let mut rc: i32 = 0;
    let mut ii: u64 = 0;
    let mut orig_array_len: u64 = 0;
    let mut my_array: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut sflags: i32 = 0 as i32;
    my_array = make_array();
    orig_array_len = json_object_array_length(my_array);
    (unsafe { printf(b"my_array=\n\0" as *const u8 as *const i8) });
    ii = 0 as i32 as size_t;
    while ii < json_object_array_length(my_array) {
        let mut obj: *mut crate::src::json_object::json_object =
            json_object_array_get_idx(my_array, ii);
        (unsafe { printf(
            b"\t[%d]=%s\n\0" as *const u8 as *const i8,
            ii as i32,
            to_json_string(obj, sflags),
        ) });
        ii = ii.wrapping_add(1);
    }
    (unsafe { printf(
        b"my_array.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_array, sflags),
    ) });
    ii = 0 as i32 as size_t;
    while ii < orig_array_len {
        rc = json_object_array_del_idx(my_array, 0 as i32 as size_t, 1 as i32 as size_t);
        (unsafe { printf(
            b"after del_idx(0,1)=%d, my_array.to_string()=%s\n\0" as *const u8 as *const i8,
            rc,
            to_json_string(my_array, sflags),
        ) });
        ii = ii.wrapping_add(1);
    }
    rc = json_object_array_del_idx(my_array, 0 as i32 as size_t, 1 as i32 as size_t);
    (unsafe { printf(
        b"after del_idx(0,1)=%d, my_array.to_string()=%s\n\0" as *const u8 as *const i8,
        rc,
        to_json_string(my_array, sflags),
    ) });
    json_object_put(my_array);
    my_array = make_array();
    rc = json_object_array_del_idx(my_array, 0 as i32 as size_t, orig_array_len);
    (unsafe { printf(
        b"after del_idx(0,%d)=%d, my_array.to_string()=%s\n\0" as *const u8 as *const i8,
        orig_array_len as i32,
        rc,
        to_json_string(my_array, sflags),
    ) });
    json_object_put(my_array);
    my_array = make_array();
    rc = json_object_array_del_idx(
        my_array,
        0 as i32 as size_t,
        orig_array_len.wrapping_add(1 as i32 as u64),
    );
    (unsafe { printf(
        b"after del_idx(0,%d)=%d, my_array.to_string()=%s\n\0" as *const u8 as *const i8,
        orig_array_len.wrapping_add(1 as i32 as u64) as i32,
        rc,
        to_json_string(my_array, sflags),
    ) });
    json_object_put(my_array);
    my_array = make_array();
    rc = json_object_array_del_idx(
        my_array,
        0 as i32 as size_t,
        orig_array_len.wrapping_sub(1 as i32 as u64),
    );
    (unsafe { printf(
        b"after del_idx(0,%d)=%d, my_array.to_string()=%s\n\0" as *const u8 as *const i8,
        orig_array_len.wrapping_sub(1 as i32 as u64) as i32,
        rc,
        to_json_string(my_array, sflags),
    ) });
    json_object_array_add(
        my_array,
        json_object_new_string(b"s1\0" as *const u8 as *const i8),
    );
    json_object_array_add(
        my_array,
        json_object_new_string(b"s2\0" as *const u8 as *const i8),
    );
    json_object_array_add(
        my_array,
        json_object_new_string(b"s3\0" as *const u8 as *const i8),
    );
    (unsafe { printf(
        b"after adding more entries, my_array.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_array, sflags),
    ) });
    json_object_put(my_array);
}
#[no_mangle]
pub extern "C" fn test_array_list_expand_internal() {
    let mut rc: i32 = 0;
    let mut ii: u64 = 0;
    let mut idx: u64 = 0;
    let mut my_array: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut sflags: i32 = 0 as i32;
    my_array = make_array();
    (unsafe { printf(b"my_array=\n\0" as *const u8 as *const i8) });
    ii = 0 as i32 as size_t;
    while ii < json_object_array_length(my_array) {
        let mut obj: *mut crate::src::json_object::json_object =
            json_object_array_get_idx(my_array, ii);
        (unsafe { printf(
            b"\t[%d]=%s\n\0" as *const u8 as *const i8,
            ii as i32,
            to_json_string(obj, sflags),
        ) });
        ii = ii.wrapping_add(1);
    }
    (unsafe { printf(
        b"my_array.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_array, sflags),
    ) });
    rc = json_object_array_put_idx(my_array, 5 as i32 as size_t, json_object_new_int(6 as i32));
    (unsafe { printf(b"put_idx(5,6)=%d\n\0" as *const u8 as *const i8, rc) });
    idx = (32 as i32 * 2 as i32 - 1 as i32) as size_t;
    rc = json_object_array_put_idx(my_array, idx, json_object_new_int(0 as i32));
    (unsafe { printf(
        b"put_idx(%d,0)=%d\n\0" as *const u8 as *const i8,
        idx as i32,
        rc,
    ) });
    idx = (32 as i32 * 2 as i32 * 2 as i32 + 1 as i32) as size_t;
    rc = json_object_array_put_idx(my_array, idx, json_object_new_int(0 as i32));
    (unsafe { printf(
        b"put_idx(%d,0)=%d\n\0" as *const u8 as *const i8,
        idx as i32,
        rc,
    ) });
    idx = 18446744073709551615 as u64;
    let mut tmp: *mut crate::src::json_object::json_object = json_object_new_int(10 as i32);
    rc = json_object_array_put_idx(my_array, idx, tmp);
    (unsafe { printf(
        b"put_idx(SIZE_T_MAX,0)=%d\n\0" as *const u8 as *const i8,
        rc,
    ) });
    if rc == -(1 as i32) {
        json_object_put(tmp);
    }
    json_object_put(my_array);
}
fn main_0(mut argc: i32, mut argv: *mut *mut i8) -> i32 {
    let mut my_string: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut my_int: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut my_null: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut my_object: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut my_array: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut i: u64 = 0;
    let mut sflags: i32 = 0 as i32;
    sflags = parse_flags(argc, argv);
    my_string = json_object_new_string(b"\t\0" as *const u8 as *const i8);
    (unsafe { printf(
        b"my_string=%s\n\0" as *const u8 as *const i8,
        json_object_get_string(my_string),
    ) });
    (unsafe { printf(
        b"my_string.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_string, sflags),
    ) });
    json_object_put(my_string);
    my_string = json_object_new_string(b"\\\0" as *const u8 as *const i8);
    (unsafe { printf(
        b"my_string=%s\n\0" as *const u8 as *const i8,
        json_object_get_string(my_string),
    ) });
    (unsafe { printf(
        b"my_string.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_string, sflags),
    ) });
    json_object_put(my_string);
    my_string = json_object_new_string(b"/\0" as *const u8 as *const i8);
    (unsafe { printf(
        b"my_string=%s\n\0" as *const u8 as *const i8,
        json_object_get_string(my_string),
    ) });
    (unsafe { printf(
        b"my_string.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_string, sflags),
    ) });
    (unsafe { printf(
        b"my_string.to_string(NOSLASHESCAPE)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string_ext(my_string, (1 as i32) << 4 as i32),
    ) });
    json_object_put(my_string);
    my_string = json_object_new_string(b"/foo/bar/baz\0" as *const u8 as *const i8);
    (unsafe { printf(
        b"my_string=%s\n\0" as *const u8 as *const i8,
        json_object_get_string(my_string),
    ) });
    (unsafe { printf(
        b"my_string.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_string, sflags),
    ) });
    (unsafe { printf(
        b"my_string.to_string(NOSLASHESCAPE)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string_ext(my_string, (1 as i32) << 4 as i32),
    ) });
    json_object_put(my_string);
    my_string = json_object_new_string(b"foo\0" as *const u8 as *const i8);
    (unsafe { printf(
        b"my_string=%s\n\0" as *const u8 as *const i8,
        json_object_get_string(my_string),
    ) });
    (unsafe { printf(
        b"my_string.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_string, sflags),
    ) });
    my_int = json_object_new_int(9 as i32);
    (unsafe { printf(
        b"my_int=%d\n\0" as *const u8 as *const i8,
        json_object_get_int(my_int),
    ) });
    (unsafe { printf(
        b"my_int.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_int, sflags),
    ) });
    my_null = json_object_new_null();
    (unsafe { printf(
        b"my_null.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_null, sflags),
    ) });
    my_array = json_object_new_array();
    json_object_array_add(my_array, json_object_new_int(1 as i32));
    json_object_array_add(my_array, json_object_new_int(2 as i32));
    json_object_array_add(my_array, json_object_new_int(3 as i32));
    json_object_array_put_idx(my_array, 4 as i32 as size_t, json_object_new_int(5 as i32));
    (unsafe { printf(b"my_array=\n\0" as *const u8 as *const i8) });
    i = 0 as i32 as size_t;
    while i < json_object_array_length(my_array) {
        let mut obj: *mut crate::src::json_object::json_object =
            json_object_array_get_idx(my_array, i);
        (unsafe { printf(
            b"\t[%d]=%s\n\0" as *const u8 as *const i8,
            i as i32,
            to_json_string(obj, sflags),
        ) });
        i = i.wrapping_add(1);
    }
    (unsafe { printf(
        b"my_array.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_array, sflags),
    ) });
    json_object_put(my_array);
    test_array_del_idx();
    test_array_list_expand_internal();
    my_array = json_object_new_array_ext(5 as i32);
    json_object_array_add(my_array, json_object_new_int(3 as i32));
    json_object_array_add(my_array, json_object_new_int(1 as i32));
    json_object_array_add(my_array, json_object_new_int(2 as i32));
    json_object_array_put_idx(my_array, 4 as i32 as size_t, json_object_new_int(0 as i32));
    (unsafe { printf(b"my_array=\n\0" as *const u8 as *const i8) });
    i = 0 as i32 as size_t;
    while i < json_object_array_length(my_array) {
        let mut obj_0: *mut crate::src::json_object::json_object =
            json_object_array_get_idx(my_array, i);
        (unsafe { printf(
            b"\t[%d]=%s\n\0" as *const u8 as *const i8,
            i as i32,
            to_json_string(obj_0, sflags),
        ) });
        i = i.wrapping_add(1);
    }
    (unsafe { printf(
        b"my_array.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_array, sflags),
    ) });
    json_object_array_sort(my_array, Some(sort_fn));
    (unsafe { printf(b"my_array=\n\0" as *const u8 as *const i8) });
    i = 0 as i32 as size_t;
    while i < json_object_array_length(my_array) {
        let mut obj_1: *mut crate::src::json_object::json_object =
            json_object_array_get_idx(my_array, i);
        (unsafe { printf(
            b"\t[%d]=%s\n\0" as *const u8 as *const i8,
            i as i32,
            to_json_string(obj_1, sflags),
        ) });
        i = i.wrapping_add(1);
    }
    (unsafe { printf(
        b"my_array.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_array, sflags),
    ) });
    let mut one: *mut crate::src::json_object::json_object = json_object_new_int(1 as i32);
    let mut result: *mut crate::src::json_object::json_object =
        json_object_array_bsearch(one, my_array, Some(sort_fn));
    (unsafe { printf(
        b"find json_object(1) in my_array successfully: %s\n\0" as *const u8 as *const i8,
        to_json_string(result, sflags),
    ) });
    json_object_put(one);
    my_object = json_object_new_object();
    let mut rc: i32 =
        json_object_object_add(my_object, b"abc\0" as *const u8 as *const i8, my_object);
    if rc != -(1 as i32) {
        (unsafe { printf(b"ERROR: able to successfully add object to itself!\n\0" as *const u8 as *const i8) });
        (unsafe { fflush(stdout) });
    }
    json_object_object_add(
        my_object,
        b"abc\0" as *const u8 as *const i8,
        json_object_new_int(12 as i32),
    );
    json_object_object_add(
        my_object,
        b"foo\0" as *const u8 as *const i8,
        json_object_new_string(b"bar\0" as *const u8 as *const i8),
    );
    json_object_object_add(
        my_object,
        b"bool0\0" as *const u8 as *const i8,
        json_object_new_boolean(0 as i32),
    );
    json_object_object_add(
        my_object,
        b"bool1\0" as *const u8 as *const i8,
        json_object_new_boolean(1 as i32),
    );
    json_object_object_add(
        my_object,
        b"baz\0" as *const u8 as *const i8,
        json_object_new_string(b"bang\0" as *const u8 as *const i8),
    );
    let mut baz_obj: *mut crate::src::json_object::json_object =
        json_object_new_string(b"fark\0" as *const u8 as *const i8);
    json_object_get(baz_obj);
    json_object_object_add(my_object, b"baz\0" as *const u8 as *const i8, baz_obj);
    json_object_object_del(my_object, b"baz\0" as *const u8 as *const i8);
    (unsafe { printf(
        b"baz_obj.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(baz_obj, sflags),
    ) });
    json_object_put(baz_obj);
    (unsafe { printf(b"my_object=\n\0" as *const u8 as *const i8) });
    let mut key: *mut i8 = 0 as *mut i8;
    let mut val: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut entrykey: *mut crate::src::json_object::lh_entry =
        lh_table_head(json_object_get_object(my_object));
    let mut entry_nextkey: *mut crate::src::json_object::lh_entry = 0 as *mut lh_entry;
    while !({
        if !entrykey.is_null() {
            key = lh_entry_k(entrykey) as *mut i8;
            val = lh_entry_v(entrykey) as *mut json_object;
            entry_nextkey = lh_entry_next(entrykey);
        }
        entrykey
    })
    .is_null()
    {
        (unsafe { printf(
            b"\t%s: %s\n\0" as *const u8 as *const i8,
            key,
            to_json_string(val, sflags),
        ) });
        entrykey = entry_nextkey;
    }
    let mut empty_array: *mut crate::src::json_object::json_object = json_object_new_array();
    let mut empty_obj: *mut crate::src::json_object::json_object = json_object_new_object();
    json_object_object_add(
        my_object,
        b"empty_array\0" as *const u8 as *const i8,
        empty_array,
    );
    json_object_object_add(
        my_object,
        b"empty_obj\0" as *const u8 as *const i8,
        empty_obj,
    );
    (unsafe { printf(
        b"my_object.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_object, sflags),
    ) });
    json_object_put(my_array);
    my_array = json_object_new_array_ext(-(2147483647 as i32) - 1 as i32 + 1 as i32);
    if !my_array.is_null() {
        (unsafe { printf(b"ERROR: able to allocate an array of negative size!\n\0" as *const u8 as *const i8) });
        (unsafe { fflush(stdout) });
        json_object_put(my_array);
        my_array = 0 as *mut json_object;
    }
    json_object_put(my_string);
    json_object_put(my_int);
    json_object_put(my_null);
    json_object_put(my_object);
    json_object_put(my_array);
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

