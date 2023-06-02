use ::libc;
extern "C" {
    
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    
    
    
    
    
    
    
}
pub use crate::src::debug::mc_set_debug;
pub use crate::src::json_object::json_object_get_object;
pub use crate::src::json_object::json_object_new_object;
pub use crate::src::json_object::json_object_new_string;
pub use crate::src::json_object::json_object_object_add;
pub use crate::src::json_object::json_object_object_del;
pub use crate::src::json_object::json_object_put;
pub use crate::src::json_object::json_object;
pub type uintptr_t = crate::src::json_object::uintptr_t;
// #[derive(Copy, Clone)]

pub type lh_entry = crate::src::json_object::lh_entry;
// #[derive(Copy, Clone)]

pub type lh_table = crate::src::json_object::lh_table;
pub type lh_equal_fn = crate::src::json_object::lh_equal_fn;
pub type lh_hash_fn = crate::src::json_object::lh_hash_fn;
pub type lh_entry_free_fn = crate::src::json_object::lh_entry_free_fn;
#[inline]
unsafe extern "C" fn lh_entry_next(mut e: *const lh_entry) -> *mut lh_entry {
    return (*e).next;
}
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
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut my_object: *mut json_object = json_object_new_object();
    json_object_object_add(
        my_object,
        b"foo1\0" as *const u8 as *const libc::c_char,
        json_object_new_string(b"bar1\0" as *const u8 as *const libc::c_char),
    );
    json_object_object_add(
        my_object,
        b"foo2\0" as *const u8 as *const libc::c_char,
        json_object_new_string(b"bar2\0" as *const u8 as *const libc::c_char),
    );
    json_object_object_add(
        my_object,
        b"deleteme\0" as *const u8 as *const libc::c_char,
        json_object_new_string(b"bar2\0" as *const u8 as *const libc::c_char),
    );
    json_object_object_add(
        my_object,
        b"foo3\0" as *const u8 as *const libc::c_char,
        json_object_new_string(b"bar3\0" as *const u8 as *const libc::c_char),
    );
    printf(
        b"==== delete-in-loop test starting ====\n\0" as *const u8 as *const libc::c_char,
    );
    let mut orig_count: libc::c_int = 0 as libc::c_int;
    let mut key0: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut val0: *mut json_object = 0 as *mut json_object;
    let mut entrykey0: *mut lh_entry = lh_table_head(json_object_get_object(my_object));
    let mut entry_nextkey0: *mut lh_entry = 0 as *mut lh_entry;
    while !({
        if !entrykey0.is_null() {
            key0 = lh_entry_k(entrykey0) as *mut libc::c_char;
            val0 = lh_entry_v(entrykey0) as *mut json_object;
            entry_nextkey0 = lh_entry_next(entrykey0);
        }
        entrykey0
    })
        .is_null()
    {
        printf(
            b"Key at index %d is [%s] %d\0" as *const u8 as *const libc::c_char,
            orig_count,
            key0,
            (val0 == 0 as *mut libc::c_void as *mut json_object) as libc::c_int,
        );
        if strcmp(key0, b"deleteme\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            json_object_object_del(my_object, key0);
            printf(b" (deleted)\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b" (kept)\n\0" as *const u8 as *const libc::c_char);
        }
        orig_count += 1;
        entrykey0 = entry_nextkey0;
    }
    printf(
        b"==== replace-value first loop starting ====\n\0" as *const u8
            as *const libc::c_char,
    );
    let mut original_key: *const libc::c_char = 0 as *const libc::c_char;
    orig_count = 0 as libc::c_int;
    let mut key: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut val: *mut json_object = 0 as *mut json_object;
    let mut entrykey: *mut lh_entry = lh_table_head(json_object_get_object(my_object));
    let mut entry_nextkey: *mut lh_entry = 0 as *mut lh_entry;
    while !({
        if !entrykey.is_null() {
            key = lh_entry_k(entrykey) as *mut libc::c_char;
            val = lh_entry_v(entrykey) as *mut json_object;
            entry_nextkey = lh_entry_next(entrykey);
        }
        entrykey
    })
        .is_null()
    {
        printf(
            b"Key at index %d is [%s] %d\n\0" as *const u8 as *const libc::c_char,
            orig_count,
            key,
            (val == 0 as *mut libc::c_void as *mut json_object) as libc::c_int,
        );
        orig_count += 1;
        if !(strcmp(key, b"foo2\0" as *const u8 as *const libc::c_char)
            != 0 as libc::c_int)
        {
            printf(
                b"replacing value for key [%s]\n\0" as *const u8 as *const libc::c_char,
                key,
            );
            original_key = key;
            json_object_object_add(
                my_object,
                key,
                json_object_new_string(b"zzz\0" as *const u8 as *const libc::c_char),
            );
        }
        entrykey = entry_nextkey;
    }
    printf(b"==== second loop starting ====\n\0" as *const u8 as *const libc::c_char);
    let mut new_count: libc::c_int = 0 as libc::c_int;
    let mut retval: libc::c_int = 0 as libc::c_int;
    let mut key2: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut val2: *mut json_object = 0 as *mut json_object;
    let mut entrykey2: *mut lh_entry = lh_table_head(json_object_get_object(my_object));
    let mut entry_nextkey2: *mut lh_entry = 0 as *mut lh_entry;
    while !({
        if !entrykey2.is_null() {
            key2 = lh_entry_k(entrykey2) as *mut libc::c_char;
            val2 = lh_entry_v(entrykey2) as *mut json_object;
            entry_nextkey2 = lh_entry_next(entrykey2);
        }
        entrykey2
    })
        .is_null()
    {
        printf(
            b"Key at index %d is [%s] %d\n\0" as *const u8 as *const libc::c_char,
            new_count,
            key2,
            (val2 == 0 as *mut libc::c_void as *mut json_object) as libc::c_int,
        );
        new_count += 1;
        if !(strcmp(key2, b"foo2\0" as *const u8 as *const libc::c_char)
            != 0 as libc::c_int)
        {
            printf(
                b"pointer for key [%s] does %smatch\n\0" as *const u8
                    as *const libc::c_char,
                key2,
                if key2 == original_key as *mut libc::c_char {
                    b"\0" as *const u8 as *const libc::c_char
                } else {
                    b"NOT \0" as *const u8 as *const libc::c_char
                },
            );
            if key2 != original_key as *mut libc::c_char {
                retval = 1 as libc::c_int;
            }
        }
        entrykey2 = entry_nextkey2;
    }
    if new_count != orig_count {
        printf(
            b"mismatch between original count (%d) and new count (%d)\n\0" as *const u8
                as *const libc::c_char,
            orig_count,
            new_count,
        );
        retval = 1 as libc::c_int;
    }
    json_object_put(my_object);
    return retval;
}
pub fn main() {
    let mut args: Vec::<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::std::ptr::null_mut());
    unsafe {
        ::std::process::exit(
            main_0(
                (args.len() - 1) as libc::c_int,
                args.as_mut_ptr() as *mut *mut libc::c_char,
            ) as i32,
        )
    }
}
