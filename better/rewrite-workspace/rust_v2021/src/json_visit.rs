use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type json_object;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn json_object_get_type(obj: *const json_object) -> json_type;
    fn json_object_get_object(obj: *const json_object) -> *mut lh_table;
    fn json_object_array_length(obj: *const json_object) -> size_t;
    fn json_object_array_get_idx(
        obj: *const json_object,
        idx: size_t,
    ) -> *mut json_object;
}
pub type size_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type uintptr_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct lh_entry {
    pub k: *const libc::c_void,
    pub k_is_constant: libc::c_int,
    pub v: *const libc::c_void,
    pub next: *mut lh_entry,
    pub prev: *mut lh_entry,
}
pub type json_type = libc::c_uint;
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
pub type json_c_visit_userfunc = unsafe extern "C" fn(
    *mut json_object,
    libc::c_int,
    *mut json_object,
    *const libc::c_char,
    *mut size_t,
    *mut libc::c_void,
) -> libc::c_int;
#[inline]
unsafe extern "C" fn lh_table_head(mut t: *const lh_table) -> *mut lh_entry {
    return (*t).head;
}
#[inline]
unsafe extern "C" fn lh_entry_k(mut e: *const lh_entry) -> *mut libc::c_void {
    return (*e).k as uintptr_t as *mut libc::c_void;
}
#[inline]
unsafe extern "C" fn lh_entry_v(mut e: *const lh_entry) -> *mut libc::c_void {
    return (*e).v as uintptr_t as *mut libc::c_void;
}
#[inline]
unsafe extern "C" fn lh_entry_next(mut e: *const lh_entry) -> *mut lh_entry {
    return (*e).next;
}
#[no_mangle]
pub unsafe extern "C" fn json_c_visit(
    mut jso: *mut json_object,
    mut future_flags: libc::c_int,
    mut userfunc: Option::<json_c_visit_userfunc>,
    mut userarg: *mut libc::c_void,
) -> libc::c_int {
    let mut ret: libc::c_int = _json_c_visit(
        jso,
        0 as *mut json_object,
        0 as *const libc::c_char,
        0 as *mut size_t,
        userfunc,
        userarg,
    );
    match ret {
        0 | 7547 | 767 | 7867 => return 0 as libc::c_int,
        _ => return -(1 as libc::c_int),
    };
}
unsafe extern "C" fn _json_c_visit(
    mut jso: *mut json_object,
    mut parent_jso: *mut json_object,
    mut jso_key: *const libc::c_char,
    mut jso_index: *mut size_t,
    mut userfunc: Option::<json_c_visit_userfunc>,
    mut userarg: *mut libc::c_void,
) -> libc::c_int {
    let mut userret: libc::c_int = userfunc
        .expect(
            "non-null function pointer",
        )(jso, 0 as libc::c_int, parent_jso, jso_key, jso_index, userarg);
    match userret {
        0 => {}
        7547 | 767 | 7867 | -1 => return userret,
        _ => {
            fprintf(
                stderr,
                b"ERROR: invalid return value from json_c_visit userfunc: %d\n\0"
                    as *const u8 as *const libc::c_char,
                userret,
            );
            return -(1 as libc::c_int);
        }
    }
    match json_object_get_type(jso) as libc::c_uint {
        0 | 1 | 2 | 3 | 6 => return 0 as libc::c_int,
        4 => {
            let mut key: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut child: *mut json_object = 0 as *mut json_object;
            let mut entrykey: *mut lh_entry = lh_table_head(json_object_get_object(jso));
            let mut entry_nextkey: *mut lh_entry = 0 as *mut lh_entry;
            while !({
                if !entrykey.is_null() {
                    key = lh_entry_k(entrykey) as *mut libc::c_char;
                    child = lh_entry_v(entrykey) as *mut json_object;
                    entry_nextkey = lh_entry_next(entrykey);
                }
                entrykey
            })
                .is_null()
            {
                userret = _json_c_visit(
                    child,
                    jso,
                    key,
                    0 as *mut size_t,
                    userfunc,
                    userarg,
                );
                if userret == 767 as libc::c_int {
                    break;
                }
                if userret == 7867 as libc::c_int || userret == -(1 as libc::c_int) {
                    return userret;
                }
                if userret != 0 as libc::c_int && userret != 7547 as libc::c_int {
                    fprintf(
                        stderr,
                        b"INTERNAL ERROR: _json_c_visit returned %d\n\0" as *const u8
                            as *const libc::c_char,
                        userret,
                    );
                    return -(1 as libc::c_int);
                }
                entrykey = entry_nextkey;
            }
        }
        5 => {
            let mut array_len: size_t = json_object_array_length(jso);
            let mut ii: size_t = 0;
            ii = 0 as libc::c_int as size_t;
            while ii < array_len {
                let mut child_0: *mut json_object = json_object_array_get_idx(jso, ii);
                userret = _json_c_visit(
                    child_0,
                    jso,
                    0 as *const libc::c_char,
                    &mut ii,
                    userfunc,
                    userarg,
                );
                if userret == 767 as libc::c_int {
                    break;
                }
                if userret == 7867 as libc::c_int || userret == -(1 as libc::c_int) {
                    return userret;
                }
                if userret != 0 as libc::c_int && userret != 7547 as libc::c_int {
                    fprintf(
                        stderr,
                        b"INTERNAL ERROR: _json_c_visit returned %d\n\0" as *const u8
                            as *const libc::c_char,
                        userret,
                    );
                    return -(1 as libc::c_int);
                }
                ii = ii.wrapping_add(1);
            }
        }
        _ => {
            fprintf(
                stderr,
                b"INTERNAL ERROR: _json_c_visit found object of unknown type: %d\n\0"
                    as *const u8 as *const libc::c_char,
                json_object_get_type(jso) as libc::c_uint,
            );
            return -(1 as libc::c_int);
        }
    }
    userret = userfunc
        .expect(
            "non-null function pointer",
        )(jso, 0x2 as libc::c_int, parent_jso, jso_key, jso_index, userarg);
    match userret {
        7547 | 767 | 0 => return 0 as libc::c_int,
        7867 | -1 => return userret,
        _ => {
            fprintf(
                stderr,
                b"ERROR: invalid return value from json_c_visit userfunc: %d\n\0"
                    as *const u8 as *const libc::c_char,
                userret,
            );
            return -(1 as libc::c_int);
        }
    };
}
