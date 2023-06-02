use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type json_object;
    static mut stdout: *mut FILE;
    fn fflush(__stream: *mut FILE) -> i32;
    fn printf(_: *const i8, _: ...) -> i32;
    fn free(__ptr: *mut libc::c_void);
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strdup(_: *const i8) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn json_object_get(obj: *mut json_object) -> *mut json_object;
    fn json_object_put(obj: *mut json_object) -> i32;
    fn json_object_to_json_string_ext(obj: *mut json_object, flags: i32) -> *const i8;
    fn json_object_to_json_string_length(
        obj: *mut json_object,
        flags: i32,
        length: *mut size_t,
    ) -> *const i8;
    fn json_object_new_object() -> *mut json_object;
    fn json_object_get_object(obj: *const json_object) -> *mut lh_table;
    fn json_object_object_add(obj: *mut json_object, key: *const i8, val: *mut json_object) -> i32;
    fn json_object_object_del(obj: *mut json_object, key: *const i8);
    fn json_object_new_array() -> *mut json_object;
    fn json_object_new_array_ext(initial_size: i32) -> *mut json_object;
    fn json_object_array_length(obj: *const json_object) -> size_t;
    fn json_object_array_sort(
        jso: *mut json_object,
        sort_fn_0: Option<unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> i32>,
    );
    fn json_object_array_bsearch(
        key: *const json_object,
        jso: *const json_object,
        sort_fn_0: Option<unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> i32>,
    ) -> *mut json_object;
    fn json_object_array_add(obj: *mut json_object, val: *mut json_object) -> i32;
    fn json_object_array_put_idx(obj: *mut json_object, idx: size_t, val: *mut json_object) -> i32;
    fn json_object_array_get_idx(obj: *const json_object, idx: size_t) -> *mut json_object;
    fn json_object_array_del_idx(obj: *mut json_object, idx: size_t, count: size_t) -> i32;
    fn json_object_new_boolean(b: json_bool) -> *mut json_object;
    fn json_object_new_int(i: int32_t) -> *mut json_object;
    fn json_object_get_int(obj: *const json_object) -> int32_t;
    fn json_object_new_string(s: *const i8) -> *mut json_object;
    fn mc_set_debug(debug: i32);
    fn json_object_get_string(obj: *mut json_object) -> *const i8;
    fn json_object_new_null() -> *mut json_object;
    fn parse_flags(argc: i32, argv: *mut *mut i8) -> i32;
}
pub type size_t = u64;
pub type __int32_t = i32;
pub type __off_t = i64;
pub type __off64_t = i64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: i32,
    pub _IO_read_ptr: *mut i8,
    pub _IO_read_end: *mut i8,
    pub _IO_read_base: *mut i8,
    pub _IO_write_base: *mut i8,
    pub _IO_write_ptr: *mut i8,
    pub _IO_write_end: *mut i8,
    pub _IO_buf_base: *mut i8,
    pub _IO_buf_end: *mut i8,
    pub _IO_save_base: *mut i8,
    pub _IO_backup_base: *mut i8,
    pub _IO_save_end: *mut i8,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: i32,
    pub _flags2: i32,
    pub _old_offset: __off_t,
    pub _cur_column: u16,
    pub _vtable_offset: i8,
    pub _shortbuf: [i8; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: i32,
    pub _unused2: [i8; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type int32_t = __int32_t;
pub type uintptr_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct lh_entry {
    pub k: *const libc::c_void,
    pub k_is_constant: i32,
    pub v: *const libc::c_void,
    pub next: *mut lh_entry,
    pub prev: *mut lh_entry,
}
pub type json_bool = i32;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct lh_table {
    pub size: i32,
    pub count: i32,
    pub head: *mut lh_entry,
    pub tail: *mut lh_entry,
    pub table: *mut lh_entry,
    pub free_fn: Option<lh_entry_free_fn>,
    pub hash_fn: Option<lh_hash_fn>,
    pub equal_fn: Option<lh_equal_fn>,
}
pub type lh_equal_fn = unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> i32;
pub type lh_hash_fn = unsafe extern "C" fn(*const libc::c_void) -> u64;
pub type lh_entry_free_fn = unsafe extern "C" fn(*mut lh_entry) -> ();
#[inline]
extern "C" fn lh_table_head(mut t: *const lh_table) -> *mut lh_entry {
    return unsafe { (*t).head };
}
#[inline]
extern "C" fn lh_entry_k(mut e: *const lh_entry) -> *mut libc::c_void {
    return (unsafe { (*e).k }) as uintptr_t as *mut libc::c_void;
}
#[inline]
extern "C" fn lh_entry_v(mut e: *const lh_entry) -> *mut libc::c_void {
    return (unsafe { (*e).v }) as uintptr_t as *mut libc::c_void;
}
#[inline]
extern "C" fn lh_entry_next(mut e: *const lh_entry) -> *mut lh_entry {
    return unsafe { (*e).next };
}
extern "C" fn sort_fn(mut j1: *const libc::c_void, mut j2: *const libc::c_void) -> i32 {
    let mut jso1: *const *mut json_object = 0 as *const *mut json_object;
    let mut jso2: *const *mut json_object = 0 as *const *mut json_object;
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
    i1 = unsafe { json_object_get_int(*jso1) };
    i2 = unsafe { json_object_get_int(*jso2) };
    return i1 - i2;
}
extern "C" fn to_json_string(mut obj: *mut json_object, mut flags: i32) -> *const i8 {
    let mut length: size_t = 0;
    let mut copy: *mut i8 = 0 as *mut i8;
    let mut result: *const i8 = 0 as *const i8;
    result = unsafe { json_object_to_json_string_length(obj, flags, &mut length) };
    copy = unsafe { strdup(result) };
    if copy.is_null() {
        (unsafe { printf(b"to_json_string: Allocation failed!\n\0" as *const u8 as *const i8) });
    } else {
        result = unsafe { json_object_to_json_string_ext(obj, flags) };
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
pub extern "C" fn make_array() -> *mut json_object {
    let mut my_array: *mut json_object = 0 as *mut json_object;
    my_array = unsafe { json_object_new_array() };
    (unsafe { json_object_array_add(my_array, json_object_new_int(1 as i32)) });
    (unsafe { json_object_array_add(my_array, json_object_new_int(2 as i32)) });
    (unsafe { json_object_array_add(my_array, json_object_new_int(3 as i32)) });
    (unsafe { json_object_array_put_idx(my_array, 4 as i32 as size_t, json_object_new_int(5 as i32)) });
    (unsafe { json_object_array_put_idx(my_array, 3 as i32 as size_t, json_object_new_int(4 as i32)) });
    (unsafe { json_object_array_put_idx(my_array, 6 as i32 as size_t, json_object_new_int(7 as i32)) });
    return my_array;
}
#[no_mangle]
pub extern "C" fn test_array_del_idx() {
    let mut rc: i32 = 0;
    let mut ii: size_t = 0;
    let mut orig_array_len: size_t = 0;
    let mut my_array: *mut json_object = 0 as *mut json_object;
    let mut sflags: i32 = 0 as i32;
    my_array = make_array();
    orig_array_len = unsafe { json_object_array_length(my_array) };
    (unsafe { printf(b"my_array=\n\0" as *const u8 as *const i8) });
    ii = 0 as i32 as size_t;
    while ii < (unsafe { json_object_array_length(my_array) }) {
        let mut obj: *mut json_object = unsafe { json_object_array_get_idx(my_array, ii) };
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
        rc = unsafe { json_object_array_del_idx(my_array, 0 as i32 as size_t, 1 as i32 as size_t) };
        (unsafe { printf(
            b"after del_idx(0,1)=%d, my_array.to_string()=%s\n\0" as *const u8 as *const i8,
            rc,
            to_json_string(my_array, sflags),
        ) });
        ii = ii.wrapping_add(1);
    }
    rc = unsafe { json_object_array_del_idx(my_array, 0 as i32 as size_t, 1 as i32 as size_t) };
    (unsafe { printf(
        b"after del_idx(0,1)=%d, my_array.to_string()=%s\n\0" as *const u8 as *const i8,
        rc,
        to_json_string(my_array, sflags),
    ) });
    (unsafe { json_object_put(my_array) });
    my_array = make_array();
    rc = unsafe { json_object_array_del_idx(my_array, 0 as i32 as size_t, orig_array_len) };
    (unsafe { printf(
        b"after del_idx(0,%d)=%d, my_array.to_string()=%s\n\0" as *const u8 as *const i8,
        orig_array_len as i32,
        rc,
        to_json_string(my_array, sflags),
    ) });
    (unsafe { json_object_put(my_array) });
    my_array = make_array();
    rc = unsafe { json_object_array_del_idx(
        my_array,
        0 as i32 as size_t,
        orig_array_len.wrapping_add(1 as i32 as u64),
    ) };
    (unsafe { printf(
        b"after del_idx(0,%d)=%d, my_array.to_string()=%s\n\0" as *const u8 as *const i8,
        orig_array_len.wrapping_add(1 as i32 as u64) as i32,
        rc,
        to_json_string(my_array, sflags),
    ) });
    (unsafe { json_object_put(my_array) });
    my_array = make_array();
    rc = unsafe { json_object_array_del_idx(
        my_array,
        0 as i32 as size_t,
        orig_array_len.wrapping_sub(1 as i32 as u64),
    ) };
    (unsafe { printf(
        b"after del_idx(0,%d)=%d, my_array.to_string()=%s\n\0" as *const u8 as *const i8,
        orig_array_len.wrapping_sub(1 as i32 as u64) as i32,
        rc,
        to_json_string(my_array, sflags),
    ) });
    (unsafe { json_object_array_add(
        my_array,
        json_object_new_string(b"s1\0" as *const u8 as *const i8),
    ) });
    (unsafe { json_object_array_add(
        my_array,
        json_object_new_string(b"s2\0" as *const u8 as *const i8),
    ) });
    (unsafe { json_object_array_add(
        my_array,
        json_object_new_string(b"s3\0" as *const u8 as *const i8),
    ) });
    (unsafe { printf(
        b"after adding more entries, my_array.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_array, sflags),
    ) });
    (unsafe { json_object_put(my_array) });
}
#[no_mangle]
pub extern "C" fn test_array_list_expand_internal() {
    let mut rc: i32 = 0;
    let mut ii: size_t = 0;
    let mut idx: size_t = 0;
    let mut my_array: *mut json_object = 0 as *mut json_object;
    let mut sflags: i32 = 0 as i32;
    my_array = make_array();
    (unsafe { printf(b"my_array=\n\0" as *const u8 as *const i8) });
    ii = 0 as i32 as size_t;
    while ii < (unsafe { json_object_array_length(my_array) }) {
        let mut obj: *mut json_object = unsafe { json_object_array_get_idx(my_array, ii) };
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
    rc = unsafe { json_object_array_put_idx(my_array, 5 as i32 as size_t, json_object_new_int(6 as i32)) };
    (unsafe { printf(b"put_idx(5,6)=%d\n\0" as *const u8 as *const i8, rc) });
    idx = (32 as i32 * 2 as i32 - 1 as i32) as size_t;
    rc = unsafe { json_object_array_put_idx(my_array, idx, json_object_new_int(0 as i32)) };
    (unsafe { printf(
        b"put_idx(%d,0)=%d\n\0" as *const u8 as *const i8,
        idx as i32,
        rc,
    ) });
    idx = (32 as i32 * 2 as i32 * 2 as i32 + 1 as i32) as size_t;
    rc = unsafe { json_object_array_put_idx(my_array, idx, json_object_new_int(0 as i32)) };
    (unsafe { printf(
        b"put_idx(%d,0)=%d\n\0" as *const u8 as *const i8,
        idx as i32,
        rc,
    ) });
    idx = 18446744073709551615 as u64;
    let mut tmp: *mut json_object = unsafe { json_object_new_int(10 as i32) };
    rc = unsafe { json_object_array_put_idx(my_array, idx, tmp) };
    (unsafe { printf(
        b"put_idx(SIZE_T_MAX,0)=%d\n\0" as *const u8 as *const i8,
        rc,
    ) });
    if rc == -(1 as i32) {
        (unsafe { json_object_put(tmp) });
    }
    (unsafe { json_object_put(my_array) });
}
fn main_0(mut argc: i32, mut argv: *mut *mut i8) -> i32 {
    let mut my_string: *mut json_object = 0 as *mut json_object;
    let mut my_int: *mut json_object = 0 as *mut json_object;
    let mut my_null: *mut json_object = 0 as *mut json_object;
    let mut my_object: *mut json_object = 0 as *mut json_object;
    let mut my_array: *mut json_object = 0 as *mut json_object;
    let mut i: size_t = 0;
    let mut sflags: i32 = 0 as i32;
    sflags = unsafe { parse_flags(argc, argv) };
    my_string = unsafe { json_object_new_string(b"\t\0" as *const u8 as *const i8) };
    (unsafe { printf(
        b"my_string=%s\n\0" as *const u8 as *const i8,
        json_object_get_string(my_string),
    ) });
    (unsafe { printf(
        b"my_string.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_string, sflags),
    ) });
    (unsafe { json_object_put(my_string) });
    my_string = unsafe { json_object_new_string(b"\\\0" as *const u8 as *const i8) };
    (unsafe { printf(
        b"my_string=%s\n\0" as *const u8 as *const i8,
        json_object_get_string(my_string),
    ) });
    (unsafe { printf(
        b"my_string.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_string, sflags),
    ) });
    (unsafe { json_object_put(my_string) });
    my_string = unsafe { json_object_new_string(b"/\0" as *const u8 as *const i8) };
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
    (unsafe { json_object_put(my_string) });
    my_string = unsafe { json_object_new_string(b"/foo/bar/baz\0" as *const u8 as *const i8) };
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
    (unsafe { json_object_put(my_string) });
    my_string = unsafe { json_object_new_string(b"foo\0" as *const u8 as *const i8) };
    (unsafe { printf(
        b"my_string=%s\n\0" as *const u8 as *const i8,
        json_object_get_string(my_string),
    ) });
    (unsafe { printf(
        b"my_string.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_string, sflags),
    ) });
    my_int = unsafe { json_object_new_int(9 as i32) };
    (unsafe { printf(
        b"my_int=%d\n\0" as *const u8 as *const i8,
        json_object_get_int(my_int),
    ) });
    (unsafe { printf(
        b"my_int.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_int, sflags),
    ) });
    my_null = unsafe { json_object_new_null() };
    (unsafe { printf(
        b"my_null.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_null, sflags),
    ) });
    my_array = unsafe { json_object_new_array() };
    (unsafe { json_object_array_add(my_array, json_object_new_int(1 as i32)) });
    (unsafe { json_object_array_add(my_array, json_object_new_int(2 as i32)) });
    (unsafe { json_object_array_add(my_array, json_object_new_int(3 as i32)) });
    (unsafe { json_object_array_put_idx(my_array, 4 as i32 as size_t, json_object_new_int(5 as i32)) });
    (unsafe { printf(b"my_array=\n\0" as *const u8 as *const i8) });
    i = 0 as i32 as size_t;
    while i < (unsafe { json_object_array_length(my_array) }) {
        let mut obj: *mut json_object = unsafe { json_object_array_get_idx(my_array, i) };
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
    (unsafe { json_object_put(my_array) });
    test_array_del_idx();
    test_array_list_expand_internal();
    my_array = unsafe { json_object_new_array_ext(5 as i32) };
    (unsafe { json_object_array_add(my_array, json_object_new_int(3 as i32)) });
    (unsafe { json_object_array_add(my_array, json_object_new_int(1 as i32)) });
    (unsafe { json_object_array_add(my_array, json_object_new_int(2 as i32)) });
    (unsafe { json_object_array_put_idx(my_array, 4 as i32 as size_t, json_object_new_int(0 as i32)) });
    (unsafe { printf(b"my_array=\n\0" as *const u8 as *const i8) });
    i = 0 as i32 as size_t;
    while i < (unsafe { json_object_array_length(my_array) }) {
        let mut obj_0: *mut json_object = unsafe { json_object_array_get_idx(my_array, i) };
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
    (unsafe { json_object_array_sort(
        my_array,
        Some(sort_fn as unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> i32),
    ) });
    (unsafe { printf(b"my_array=\n\0" as *const u8 as *const i8) });
    i = 0 as i32 as size_t;
    while i < (unsafe { json_object_array_length(my_array) }) {
        let mut obj_1: *mut json_object = unsafe { json_object_array_get_idx(my_array, i) };
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
    let mut one: *mut json_object = unsafe { json_object_new_int(1 as i32) };
    let mut result: *mut json_object = unsafe { json_object_array_bsearch(
        one,
        my_array,
        Some(sort_fn as unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> i32),
    ) };
    (unsafe { printf(
        b"find json_object(1) in my_array successfully: %s\n\0" as *const u8 as *const i8,
        to_json_string(result, sflags),
    ) });
    (unsafe { json_object_put(one) });
    my_object = unsafe { json_object_new_object() };
    let mut rc: i32 =
        unsafe { json_object_object_add(my_object, b"abc\0" as *const u8 as *const i8, my_object) };
    if rc != -(1 as i32) {
        (unsafe { printf(b"ERROR: able to successfully add object to itself!\n\0" as *const u8 as *const i8) });
        (unsafe { fflush(stdout) });
    }
    (unsafe { json_object_object_add(
        my_object,
        b"abc\0" as *const u8 as *const i8,
        json_object_new_int(12 as i32),
    ) });
    (unsafe { json_object_object_add(
        my_object,
        b"foo\0" as *const u8 as *const i8,
        json_object_new_string(b"bar\0" as *const u8 as *const i8),
    ) });
    (unsafe { json_object_object_add(
        my_object,
        b"bool0\0" as *const u8 as *const i8,
        json_object_new_boolean(0 as i32),
    ) });
    (unsafe { json_object_object_add(
        my_object,
        b"bool1\0" as *const u8 as *const i8,
        json_object_new_boolean(1 as i32),
    ) });
    (unsafe { json_object_object_add(
        my_object,
        b"baz\0" as *const u8 as *const i8,
        json_object_new_string(b"bang\0" as *const u8 as *const i8),
    ) });
    let mut baz_obj: *mut json_object = unsafe { json_object_new_string(b"fark\0" as *const u8 as *const i8) };
    (unsafe { json_object_get(baz_obj) });
    (unsafe { json_object_object_add(my_object, b"baz\0" as *const u8 as *const i8, baz_obj) });
    (unsafe { json_object_object_del(my_object, b"baz\0" as *const u8 as *const i8) });
    (unsafe { printf(
        b"baz_obj.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(baz_obj, sflags),
    ) });
    (unsafe { json_object_put(baz_obj) });
    (unsafe { printf(b"my_object=\n\0" as *const u8 as *const i8) });
    let mut key: *mut i8 = 0 as *mut i8;
    let mut val: *mut json_object = 0 as *mut json_object;
    let mut entrykey: *mut lh_entry = lh_table_head(unsafe { json_object_get_object(my_object) });
    let mut entry_nextkey: *mut lh_entry = 0 as *mut lh_entry;
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
    let mut empty_array: *mut json_object = unsafe { json_object_new_array() };
    let mut empty_obj: *mut json_object = unsafe { json_object_new_object() };
    (unsafe { json_object_object_add(
        my_object,
        b"empty_array\0" as *const u8 as *const i8,
        empty_array,
    ) });
    (unsafe { json_object_object_add(
        my_object,
        b"empty_obj\0" as *const u8 as *const i8,
        empty_obj,
    ) });
    (unsafe { printf(
        b"my_object.to_string()=%s\n\0" as *const u8 as *const i8,
        to_json_string(my_object, sflags),
    ) });
    (unsafe { json_object_put(my_array) });
    my_array = unsafe { json_object_new_array_ext(-(2147483647 as i32) - 1 as i32 + 1 as i32) };
    if !my_array.is_null() {
        (unsafe { printf(b"ERROR: able to allocate an array of negative size!\n\0" as *const u8 as *const i8) });
        (unsafe { fflush(stdout) });
        (unsafe { json_object_put(my_array) });
        my_array = 0 as *mut json_object;
    }
    (unsafe { json_object_put(my_string) });
    (unsafe { json_object_put(my_int) });
    (unsafe { json_object_put(my_null) });
    (unsafe { json_object_put(my_object) });
    (unsafe { json_object_put(my_array) });
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
