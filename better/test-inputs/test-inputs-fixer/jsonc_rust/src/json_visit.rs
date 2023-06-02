use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type json_object;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const i8, _: ...) -> i32;
    fn json_object_get_type(obj: *const json_object) -> json_type;
    fn json_object_get_object(obj: *const json_object) -> *mut lh_table;
    fn json_object_array_length(obj: *const json_object) -> size_t;
    fn json_object_array_get_idx(obj: *const json_object, idx: size_t) -> *mut json_object;
}
pub type size_t = u64;
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
pub type json_type = u32;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
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
pub type json_c_visit_userfunc = unsafe extern "C" fn(
    *mut json_object,
    i32,
    *mut json_object,
    *const i8,
    *mut size_t,
    *mut libc::c_void,
) -> i32;
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
#[no_mangle]
pub extern "C" fn json_c_visit(
    mut jso: *mut json_object,
    mut _future_flags: i32,
    mut userfunc: Option<json_c_visit_userfunc>,
    mut userarg: *mut libc::c_void,
) -> i32 {
    let mut ret: i32 = _json_c_visit(
        jso,
        0 as *mut json_object,
        0 as *const i8,
        0 as *mut size_t,
        userfunc,
        userarg,
    );
    match ret {
        0 | 7547 | 767 | 7867 => return 0 as i32,
        _ => return -(1 as i32),
    };
}
extern "C" fn _json_c_visit(
    mut jso: *mut json_object,
    mut parent_jso: *mut json_object,
    mut jso_key: *const i8,
    mut jso_index: *mut size_t,
    mut userfunc: Option<json_c_visit_userfunc>,
    mut userarg: *mut libc::c_void,
) -> i32 {
    let mut userret: i32 = unsafe { userfunc.expect("non-null function pointer")(
        jso, 0 as i32, parent_jso, jso_key, jso_index, userarg,
    ) };
    match userret {
        0 => {}
        7547 | 767 | 7867 | -1 => return userret,
        _ => {
            (unsafe { fprintf(
                stderr,
                b"ERROR: invalid return value from json_c_visit userfunc: %d\n\0" as *const u8
                    as *const i8,
                userret,
            ) });
            return -(1 as i32);
        }
    }
    match (unsafe { json_object_get_type(jso) }) as u32 {
        0 | 1 | 2 | 3 | 6 => return 0 as i32,
        4 => {
            let mut key: *mut i8 = 0 as *mut i8;
            let mut child: *mut json_object = 0 as *mut json_object;
            let mut entrykey: *mut lh_entry = lh_table_head(unsafe { json_object_get_object(jso) });
            let mut entry_nextkey: *mut lh_entry = 0 as *mut lh_entry;
            while !({
                if !entrykey.is_null() {
                    key = lh_entry_k(entrykey) as *mut i8;
                    child = lh_entry_v(entrykey) as *mut json_object;
                    entry_nextkey = lh_entry_next(entrykey);
                }
                entrykey
            })
            .is_null()
            {
                userret = _json_c_visit(child, jso, key, 0 as *mut size_t, userfunc, userarg);
                if userret == 767 as i32 {
                    break;
                }
                if userret == 7867 as i32 || userret == -(1 as i32) {
                    return userret;
                }
                if userret != 0 as i32 && userret != 7547 as i32 {
                    (unsafe { fprintf(
                        stderr,
                        b"INTERNAL ERROR: _json_c_visit returned %d\n\0" as *const u8 as *const i8,
                        userret,
                    ) });
                    return -(1 as i32);
                }
                entrykey = entry_nextkey;
            }
        }
        5 => {
            let mut array_len: size_t = unsafe { json_object_array_length(jso) };
            let mut ii: size_t = 0;
            ii = 0 as i32 as size_t;
            while ii < array_len {
                let mut child_0: *mut json_object = unsafe { json_object_array_get_idx(jso, ii) };
                userret = _json_c_visit(child_0, jso, 0 as *const i8, &mut ii, userfunc, userarg);
                if userret == 767 as i32 {
                    break;
                }
                if userret == 7867 as i32 || userret == -(1 as i32) {
                    return userret;
                }
                if userret != 0 as i32 && userret != 7547 as i32 {
                    (unsafe { fprintf(
                        stderr,
                        b"INTERNAL ERROR: _json_c_visit returned %d\n\0" as *const u8 as *const i8,
                        userret,
                    ) });
                    return -(1 as i32);
                }
                ii = ii.wrapping_add(1);
            }
        }
        _ => {
            (unsafe { fprintf(
                stderr,
                b"INTERNAL ERROR: _json_c_visit found object of unknown type: %d\n\0" as *const u8
                    as *const i8,
                json_object_get_type(jso) as u32,
            ) });
            return -(1 as i32);
        }
    }
    userret = unsafe { userfunc.expect("non-null function pointer")(
        jso, 0x2 as i32, parent_jso, jso_key, jso_index, userarg,
    ) };
    match userret {
        7547 | 767 | 0 => return 0 as i32,
        7867 | -1 => return userret,
        _ => {
            (unsafe { fprintf(
                stderr,
                b"ERROR: invalid return value from json_c_visit userfunc: %d\n\0" as *const u8
                    as *const i8,
                userret,
            ) });
            return -(1 as i32);
        }
    };
}
