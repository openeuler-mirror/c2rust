use :: libc;
extern "C" {
    pub type json_object;
    fn printf(_: *const i8, _: ...) -> i32;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn json_object_put(obj: *mut json_object) -> i32;
    fn json_object_new_object() -> *mut json_object;
    fn json_object_get_object(obj: *const json_object) -> *mut lh_table;
    fn json_object_object_add(obj: *mut json_object, key: *const i8, val: *mut json_object) -> i32;
    fn json_object_object_del(obj: *mut json_object, key: *const i8);
    fn mc_set_debug(debug: i32);
    fn json_object_new_string(s: *const i8) -> *mut json_object;
}
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
extern "C" fn lh_entry_next(mut e: *const lh_entry) -> *mut lh_entry {
    return unsafe { (*e).next };
}
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
fn main_0(mut _argc: i32, mut _argv: *mut *mut i8) -> i32 {
    let mut my_object: *mut json_object = unsafe { json_object_new_object() };
    (unsafe { json_object_object_add(
        my_object,
        b"foo1\0" as *const u8 as *const i8,
        json_object_new_string(b"bar1\0" as *const u8 as *const i8),
    ) });
    (unsafe { json_object_object_add(
        my_object,
        b"foo2\0" as *const u8 as *const i8,
        json_object_new_string(b"bar2\0" as *const u8 as *const i8),
    ) });
    (unsafe { json_object_object_add(
        my_object,
        b"deleteme\0" as *const u8 as *const i8,
        json_object_new_string(b"bar2\0" as *const u8 as *const i8),
    ) });
    (unsafe { json_object_object_add(
        my_object,
        b"foo3\0" as *const u8 as *const i8,
        json_object_new_string(b"bar3\0" as *const u8 as *const i8),
    ) });
    (unsafe { printf(b"==== delete-in-loop test starting ====\n\0" as *const u8 as *const i8) });
    let mut orig_count: i32 = 0 as i32;
    let mut key0: *mut i8 = 0 as *mut i8;
    let mut val0: *mut json_object = 0 as *mut json_object;
    let mut entrykey0: *mut lh_entry = lh_table_head(unsafe { json_object_get_object(my_object) });
    let mut entry_nextkey0: *mut lh_entry = 0 as *mut lh_entry;
    while !({
        if !entrykey0.is_null() {
            key0 = lh_entry_k(entrykey0) as *mut i8;
            val0 = lh_entry_v(entrykey0) as *mut json_object;
            entry_nextkey0 = lh_entry_next(entrykey0);
        }
        entrykey0
    })
    .is_null()
    {
        (unsafe { printf(
            b"Key at index %d is [%s] %d\0" as *const u8 as *const i8,
            orig_count,
            key0,
            (val0 == 0 as *mut libc::c_void as *mut json_object) as i32,
        ) });
        if (unsafe { strcmp(key0, b"deleteme\0" as *const u8 as *const i8) }) == 0 as i32 {
            (unsafe { json_object_object_del(my_object, key0) });
            (unsafe { printf(b" (deleted)\n\0" as *const u8 as *const i8) });
        } else {
            (unsafe { printf(b" (kept)\n\0" as *const u8 as *const i8) });
        }
        orig_count += 1;
        entrykey0 = entry_nextkey0;
    }
    (unsafe { printf(b"==== replace-value first loop starting ====\n\0" as *const u8 as *const i8) });
    let mut original_key: *const i8 = 0 as *const i8;
    orig_count = 0 as i32;
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
            b"Key at index %d is [%s] %d\n\0" as *const u8 as *const i8,
            orig_count,
            key,
            (val == 0 as *mut libc::c_void as *mut json_object) as i32,
        ) });
        orig_count += 1;
        if !((unsafe { strcmp(key, b"foo2\0" as *const u8 as *const i8) }) != 0 as i32) {
            (unsafe { printf(
                b"replacing value for key [%s]\n\0" as *const u8 as *const i8,
                key,
            ) });
            original_key = key;
            (unsafe { json_object_object_add(
                my_object,
                key,
                json_object_new_string(b"zzz\0" as *const u8 as *const i8),
            ) });
        }
        entrykey = entry_nextkey;
    }
    (unsafe { printf(b"==== second loop starting ====\n\0" as *const u8 as *const i8) });
    let mut new_count: i32 = 0 as i32;
    let mut retval: i32 = 0 as i32;
    let mut key2: *mut i8 = 0 as *mut i8;
    let mut val2: *mut json_object = 0 as *mut json_object;
    let mut entrykey2: *mut lh_entry = lh_table_head(unsafe { json_object_get_object(my_object) });
    let mut entry_nextkey2: *mut lh_entry = 0 as *mut lh_entry;
    while !({
        if !entrykey2.is_null() {
            key2 = lh_entry_k(entrykey2) as *mut i8;
            val2 = lh_entry_v(entrykey2) as *mut json_object;
            entry_nextkey2 = lh_entry_next(entrykey2);
        }
        entrykey2
    })
    .is_null()
    {
        (unsafe { printf(
            b"Key at index %d is [%s] %d\n\0" as *const u8 as *const i8,
            new_count,
            key2,
            (val2 == 0 as *mut libc::c_void as *mut json_object) as i32,
        ) });
        new_count += 1;
        if !((unsafe { strcmp(key2, b"foo2\0" as *const u8 as *const i8) }) != 0 as i32) {
            (unsafe { printf(
                b"pointer for key [%s] does %smatch\n\0" as *const u8 as *const i8,
                key2,
                if key2 == original_key as *mut i8 {
                    b"\0" as *const u8 as *const i8
                } else {
                    b"NOT \0" as *const u8 as *const i8
                },
            ) });
            if key2 != original_key as *mut i8 {
                retval = 1 as i32;
            }
        }
        entrykey2 = entry_nextkey2;
    }
    if new_count != orig_count {
        (unsafe { printf(
            b"mismatch between original count (%d) and new count (%d)\n\0" as *const u8
                as *const i8,
            orig_count,
            new_count,
        ) });
        retval = 1 as i32;
    }
    (unsafe { json_object_put(my_object) });
    return retval;
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
