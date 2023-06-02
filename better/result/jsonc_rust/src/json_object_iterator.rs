use :: libc;
extern "C" {}
pub use crate::src::json_object::json_object_get_object;
pub type __uint32_t = u32;
pub type uint32_t = u32;
pub type uintptr_t = u64;
pub type printbuf = crate::src::apps::json_parse::printbuf;
pub type lh_entry = crate::src::json_object::lh_entry;
pub type json_object = crate::src::json_object::json_object;
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
pub type lh_table = crate::src::json_object::lh_table;
pub type lh_equal_fn =
    unsafe extern "C" fn(_: *const core::ffi::c_void, _: *const core::ffi::c_void) -> i32;
pub type lh_hash_fn = unsafe extern "C" fn(_: *const core::ffi::c_void) -> u64;
pub type lh_entry_free_fn = unsafe extern "C" fn(_: *mut crate::src::json_object::lh_entry) -> ();
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object_iterator {
    pub opaque_: *const core::ffi::c_void,
}
impl json_object_iterator {
    pub const fn new() -> Self {
        json_object_iterator {
            opaque_: (0 as *const core::ffi::c_void),
        }
    }
}
impl std::default::Default for json_object_iterator {
    fn default() -> Self {
        json_object_iterator::new()
    }
}
#[inline]
extern "C" fn lh_table_head(
    mut t: *const crate::src::json_object::lh_table,
) -> *mut crate::src::json_object::lh_entry {
    return unsafe { (*t).head };
}
#[inline]
extern "C" fn lh_entry_next(
    mut e: *const crate::src::json_object::lh_entry,
) -> *mut crate::src::json_object::lh_entry {
    return unsafe { (*e).next };
}
#[inline]
extern "C" fn lh_entry_v(
    mut e: *const crate::src::json_object::lh_entry,
) -> *mut core::ffi::c_void {
    return (unsafe { (*e).v }) as uintptr_t as *mut libc::c_void;
}
static mut kObjectEndIterValue: *const core::ffi::c_void = 0 as *const libc::c_void;
#[no_mangle]
pub extern "C" fn json_object_iter_begin(
    mut obj: *mut crate::src::json_object::json_object,
) -> crate::src::json_object_iterator::json_object_iterator {
    let mut iter: crate::src::json_object_iterator::json_object_iterator = json_object_iterator {
        opaque_: 0 as *const libc::c_void,
    };
    let mut pTable: *mut crate::src::json_object::lh_table = 0 as *mut lh_table;
    pTable = json_object_get_object(obj);
    iter.opaque_ = lh_table_head(pTable) as *const libc::c_void;
    return iter;
}
#[no_mangle]
pub extern "C" fn json_object_iter_end(
    mut _obj: *const crate::src::json_object::json_object,
) -> crate::src::json_object_iterator::json_object_iterator {
    let mut iter: crate::src::json_object_iterator::json_object_iterator = json_object_iterator {
        opaque_: 0 as *const libc::c_void,
    };
    iter.opaque_ = unsafe { kObjectEndIterValue };
    return iter;
}
#[no_mangle]
pub extern "C" fn json_object_iter_next(
    mut iter: *mut crate::src::json_object_iterator::json_object_iterator,
) {
    let mut fresh0 = unsafe { &mut ((*iter).opaque_) };
    *fresh0 = lh_entry_next((unsafe { (*iter).opaque_ }) as *const lh_entry) as *const libc::c_void;
}
#[no_mangle]
pub extern "C" fn json_object_iter_peek_name<'a1>(
    mut iter: Option<&'a1 crate::src::json_object_iterator::json_object_iterator>,
) -> *const i8 {
    return (unsafe { (*((*((iter).clone()).unwrap()).opaque_ as *const lh_entry)).k }) as *const i8;
}
#[no_mangle]
pub extern "C" fn json_object_iter_peek_value<'a1>(
    mut iter: Option<&'a1 crate::src::json_object_iterator::json_object_iterator>,
) -> *mut crate::src::json_object::json_object {
    return lh_entry_v((*((iter).clone()).unwrap()).opaque_ as *const lh_entry) as *mut json_object;
}
#[no_mangle]
pub extern "C" fn json_object_iter_equal<'a1, 'a2>(
    mut iter1: Option<&'a1 crate::src::json_object_iterator::json_object_iterator>,
    mut iter2: Option<&'a2 crate::src::json_object_iterator::json_object_iterator>,
) -> i32 {
    return ((*((iter1).clone()).unwrap()).opaque_ == (*((iter2).clone()).unwrap()).opaque_) as i32;
}
#[no_mangle]
pub extern "C" fn json_object_iter_init_default()
-> crate::src::json_object_iterator::json_object_iterator {
    let mut iter: crate::src::json_object_iterator::json_object_iterator = json_object_iterator {
        opaque_: 0 as *const libc::c_void,
    };
    iter.opaque_ = 0 as *const libc::c_void;
    return iter;
}

