use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    
    
    
    
}
pub use crate::src::json_object::json_object_array_get_idx;
pub use crate::src::json_object::json_object_array_length;
pub use crate::src::json_object::json_object_get_object;
pub use crate::src::json_object::json_object_get_type;
pub use crate::src::json_object::json_object;
pub use crate::src::apps::json_parse::size_t;
pub use crate::src::apps::json_parse::__off_t;
pub use crate::src::apps::json_parse::__off64_t;
// #[derive(Copy, Clone)]

pub use crate::src::apps::json_parse::_IO_FILE;
pub use crate::src::apps::json_parse::_IO_lock_t;
pub use crate::src::apps::json_parse::FILE;
pub use crate::src::json_object::uintptr_t;
// #[derive(Copy, Clone)]

pub use crate::src::json_object::lh_entry;
pub use crate::src::json_object::json_type;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
// #[derive(Copy, Clone)]

pub use crate::src::json_object::lh_table;
pub use crate::src::json_object::lh_equal_fn;
pub use crate::src::json_object::lh_hash_fn;
pub use crate::src::json_object::lh_entry_free_fn;
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
