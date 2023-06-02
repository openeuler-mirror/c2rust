use :: libc;
extern "C" {
    pub type _IO_marker;
    static mut stderr: *mut crate::src::apps::json_parse::_IO_FILE;
    fn fprintf(_: *mut crate::src::apps::json_parse::_IO_FILE, _: *const i8, _: ...) -> i32;
}
pub use crate::src::{
    debug::_IO_wide_data,
    json_object::{
        _IO_codecvt, json_object, json_object_array_get_idx, json_object_array_length,
        json_object_get_object, json_object_get_type,
    },
};
pub type size_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type _IO_FILE = crate::src::apps::json_parse::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::apps::json_parse::_IO_FILE;
pub type uintptr_t = u64;
pub type lh_entry = crate::src::json_object::lh_entry;
pub type json_type = u32;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
pub type lh_table = crate::src::json_object::lh_table;
pub type lh_equal_fn =
    unsafe extern "C" fn(_: *const core::ffi::c_void, _: *const core::ffi::c_void) -> i32;
pub type lh_hash_fn = unsafe extern "C" fn(_: *const core::ffi::c_void) -> u64;
pub type lh_entry_free_fn = unsafe extern "C" fn(_: *mut crate::src::json_object::lh_entry) -> ();
pub type json_c_visit_userfunc = unsafe extern "C" fn(
    _: *mut crate::src::json_object::json_object,
    _: i32,
    _: *mut crate::src::json_object::json_object,
    _: *const i8,
    _: *mut u64,
    _: *mut core::ffi::c_void,
) -> i32;
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
#[no_mangle]
pub extern "C" fn json_c_visit(
    mut jso: *mut crate::src::json_object::json_object,
    mut _future_flags: i32,
    mut userfunc: Option<
        unsafe extern "C" fn(
            _: *mut crate::src::json_object::json_object,
            _: i32,
            _: *mut crate::src::json_object::json_object,
            _: *const i8,
            _: *mut u64,
            _: *mut core::ffi::c_void,
        ) -> i32,
    >,
    mut userarg: *mut core::ffi::c_void,
) -> i32 {
    let mut ret: i32 = _json_c_visit(
        jso,
        0 as *mut json_object,
        0 as *const i8,
        0 as *mut u64,
        userfunc,
        userarg,
    );
    match ret {
        0 | 7547 | 767 | 7867 => return 0 as i32,
        _ => return -(1 as i32),
    };
}
extern "C" fn _json_c_visit(
    mut jso: *mut crate::src::json_object::json_object,
    mut parent_jso: *mut crate::src::json_object::json_object,
    mut jso_key: *const i8,
    mut jso_index: *mut u64,
    mut userfunc: Option<
        unsafe extern "C" fn(
            _: *mut crate::src::json_object::json_object,
            _: i32,
            _: *mut crate::src::json_object::json_object,
            _: *const i8,
            _: *mut u64,
            _: *mut core::ffi::c_void,
        ) -> i32,
    >,
    mut userarg: *mut core::ffi::c_void,
) -> i32 {
    let mut userret: i32 = unsafe { userfunc.expect("non-null function pointer")(
        jso, 0 as i32, parent_jso, jso_key, jso_index, userarg,
    ) };
    match userret {
        0 => {},
        7547 | 767 | 7867 | -1 => return userret,
        _ => {
            (unsafe { fprintf(
                stderr,
                b"ERROR: invalid return value from json_c_visit userfunc: %d\n\0" as *const u8
                    as *const i8,
                userret,
            ) });
            return -(1 as i32);
        },
    }
    match json_object_get_type(jso) as u32 {
        0 | 1 | 2 | 3 | 6 => return 0 as i32,
        4 => {
            let mut key: *mut i8 = 0 as *mut i8;
            let mut child: *mut crate::src::json_object::json_object = 0 as *mut json_object;
            let mut entrykey: *mut crate::src::json_object::lh_entry =
                lh_table_head(json_object_get_object(jso));
            let mut entry_nextkey: *mut crate::src::json_object::lh_entry = 0 as *mut lh_entry;
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
                userret = _json_c_visit(child, jso, key, 0 as *mut u64, userfunc, userarg);
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
        },
        5 => {
            let mut array_len: u64 = json_object_array_length(jso);
            let mut ii: u64 = 0;
            ii = 0 as i32 as size_t;
            while ii < array_len {
                let mut child_0: *mut crate::src::json_object::json_object =
                    json_object_array_get_idx(jso, ii);
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
        },
        _ => {
            (unsafe { fprintf(
                stderr,
                b"INTERNAL ERROR: _json_c_visit found object of unknown type: %d\n\0" as *const u8
                    as *const i8,
                json_object_get_type(jso) as u32,
            ) });
            return -(1 as i32);
        },
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
        },
    };
}

