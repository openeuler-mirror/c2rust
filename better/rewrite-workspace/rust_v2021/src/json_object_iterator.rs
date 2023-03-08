use ::libc;
extern "C" {
    
}
pub use crate::json_object::json_object_get_object;
pub use crate::json_object::__uint32_t;
pub use crate::json_object::uint32_t;
pub use crate::json_object::uintptr_t;
// #[derive(Copy, Clone)]

pub use crate::apps::json_parse::printbuf;
// #[derive(Copy, Clone)]

pub use crate::json_object::lh_entry;
// #[derive(Copy, Clone)]

pub use crate::json_object::json_object;
pub use crate::json_object::json_object_delete_fn;
pub use crate::json_object::json_object_to_json_string_fn;
pub use crate::json_object::json_type;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
pub use crate::json_object::json_bool;
// #[derive(Copy, Clone)]

pub use crate::json_object::lh_table;
pub use crate::json_object::lh_equal_fn;
pub use crate::json_object::lh_hash_fn;
pub use crate::json_object::lh_entry_free_fn;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object_iterator {
    pub opaque_: *const libc::c_void,
}
#[inline]
unsafe extern "C" fn lh_table_head(mut t: *const lh_table) -> *mut lh_entry {
    return (*t).head;
}
#[inline]
unsafe extern "C" fn lh_entry_next(mut e: *const lh_entry) -> *mut lh_entry {
    return (*e).next;
}
#[inline]
unsafe extern "C" fn lh_entry_v(mut e: *const lh_entry) -> *mut libc::c_void {
    return (*e).v as uintptr_t as *mut libc::c_void;
}
static mut kObjectEndIterValue: *const libc::c_void = 0 as *const libc::c_void;
#[no_mangle]
pub unsafe extern "C" fn json_object_iter_begin(
    mut obj: *mut json_object,
) -> json_object_iterator {
    let mut iter: json_object_iterator = json_object_iterator {
        opaque_: 0 as *const libc::c_void,
    };
    let mut pTable: *mut lh_table = 0 as *mut lh_table;
    pTable = json_object_get_object(obj);
    iter.opaque_ = lh_table_head(pTable) as *const libc::c_void;
    return iter;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_iter_end(
    mut obj: *const json_object,
) -> json_object_iterator {
    let mut iter: json_object_iterator = json_object_iterator {
        opaque_: 0 as *const libc::c_void,
    };
    iter.opaque_ = kObjectEndIterValue;
    return iter;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_iter_next(mut iter: *mut json_object_iterator) {
    let ref mut fresh0 = (*iter).opaque_;
    *fresh0 = lh_entry_next((*iter).opaque_ as *const lh_entry) as *const libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_iter_peek_name(
    mut iter: *const json_object_iterator,
) -> *const libc::c_char {
    return (*((*iter).opaque_ as *const lh_entry)).k as *const libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_iter_peek_value(
    mut iter: *const json_object_iterator,
) -> *mut json_object {
    return lh_entry_v((*iter).opaque_ as *const lh_entry) as *mut json_object;
}
#[no_mangle]
pub unsafe extern "C" fn json_object_iter_equal(
    mut iter1: *const json_object_iterator,
    mut iter2: *const json_object_iterator,
) -> json_bool {
    return ((*iter1).opaque_ == (*iter2).opaque_) as libc::c_int;
}
#[no_mangle]
pub extern "C" fn json_object_iter_init_default() -> json_object_iterator {
    let mut iter: json_object_iterator = json_object_iterator {
        opaque_: 0 as *const libc::c_void,
    };
    iter.opaque_ = 0 as *const libc::c_void;
    return iter;
}
