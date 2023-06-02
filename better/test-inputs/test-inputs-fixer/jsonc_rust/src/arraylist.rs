use :: libc;
extern "C" {
    fn malloc(_: u64) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn bsearch(
        __key: *const libc::c_void,
        __base: *const libc::c_void,
        __nmemb: size_t,
        __size: size_t,
        __compar: __compar_fn_t,
    ) -> *mut libc::c_void;
    fn qsort(__base: *mut libc::c_void, __nmemb: size_t, __size: size_t, __compar: __compar_fn_t);
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
}
pub type size_t = u64;
pub type __compar_fn_t =
    Option<unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> i32>;
pub type array_list_free_fn = unsafe extern "C" fn(*mut libc::c_void) -> ();
#[derive(Copy, Clone)]
#[repr(C)]
pub struct array_list {
    pub array: *mut *mut libc::c_void,
    pub length: size_t,
    pub size: size_t,
    pub free_fn: Option<array_list_free_fn>,
}
#[no_mangle]
pub extern "C" fn array_list_new(mut free_fn: Option<array_list_free_fn>) -> *mut array_list {
    return array_list_new2(free_fn, 32 as i32);
}
#[no_mangle]
pub extern "C" fn array_list_new2(
    mut free_fn: Option<array_list_free_fn>,
    mut initial_size: i32,
) -> *mut array_list {
    let mut arr: *mut array_list = 0 as *mut array_list;
    if initial_size < 0 as i32
        || initial_size as size_t
            >= (9223372036854775807 as i64 as u64)
                .wrapping_mul(2 as u64)
                .wrapping_add(1 as u64)
                .wrapping_div(::std::mem::size_of::<*mut libc::c_void>() as u64)
    {
        return 0 as *mut array_list;
    }
    arr = (unsafe { malloc(::std::mem::size_of::<array_list>() as u64) }) as *mut array_list;
    if arr.is_null() {
        return 0 as *mut array_list;
    }
    (unsafe { (*arr).size = initial_size as size_t });
    (unsafe { (*arr).length = 0 as i32 as size_t });
    let fresh0 = unsafe { &mut ((*arr).free_fn) };
    *fresh0 = free_fn;
    let fresh1 = unsafe { &mut ((*arr).array) };
    *fresh1 = (unsafe { malloc(((*arr).size).wrapping_mul(::std::mem::size_of::<*mut libc::c_void>() as u64)) })
        as *mut *mut libc::c_void;
    if (*fresh1).is_null() {
        (unsafe { free(arr as *mut libc::c_void) });
        return 0 as *mut array_list;
    }
    return arr;
}
#[no_mangle]
pub extern "C" fn array_list_free(mut arr: *mut array_list) {
    let mut i: size_t = 0;
    i = 0 as i32 as size_t;
    while i < (unsafe { (*arr).length }) {
        if !(unsafe { *((*arr).array).offset(i as isize) }).is_null() {
            (unsafe { ((*arr).free_fn).expect("non-null function pointer")(
                *((*arr).array).offset(i as isize),
            ) });
        }
        i = i.wrapping_add(1);
    }
    (unsafe { free((*arr).array as *mut libc::c_void) });
    (unsafe { free(arr as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn array_list_get_idx(mut arr: *mut array_list, mut i: size_t) -> *mut libc::c_void {
    if i >= (unsafe { (*arr).length }) {
        return 0 as *mut libc::c_void;
    }
    return unsafe { *((*arr).array).offset(i as isize) };
}
extern "C" fn array_list_expand_internal(mut arr: *mut array_list, mut max: size_t) -> i32 {
    let mut t: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut new_size: size_t = 0;
    if max < (unsafe { (*arr).size }) {
        return 0 as i32;
    }
    if (unsafe { (*arr).size })
        >= (9223372036854775807 as i64 as u64)
            .wrapping_mul(2 as u64)
            .wrapping_add(1 as u64)
            .wrapping_div(2 as i32 as u64)
    {
        new_size = max;
    } else {
        new_size = (unsafe { (*arr).size }) << 1 as i32;
        if new_size < max {
            new_size = max;
        }
    }
    if new_size
        > (!(0 as i32 as size_t)).wrapping_div(::std::mem::size_of::<*mut libc::c_void>() as u64)
    {
        return -(1 as i32);
    }
    t = unsafe { realloc(
        (*arr).array as *mut libc::c_void,
        new_size.wrapping_mul(::std::mem::size_of::<*mut libc::c_void>() as u64),
    ) };
    if t.is_null() {
        return -(1 as i32);
    }
    let fresh2 = unsafe { &mut ((*arr).array) };
    *fresh2 = t as *mut *mut libc::c_void;
    (unsafe { (*arr).size = new_size });
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn array_list_shrink(mut arr: *mut array_list, mut empty_slots: size_t) -> i32 {
    let mut t: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut new_size: size_t = 0;
    if empty_slots
        >= (9223372036854775807 as i64 as u64)
            .wrapping_mul(2 as u64)
            .wrapping_add(1 as u64)
            .wrapping_div(::std::mem::size_of::<*mut libc::c_void>() as u64)
            .wrapping_sub(unsafe { (*arr).length })
    {
        return -(1 as i32);
    }
    new_size = (unsafe { (*arr).length }).wrapping_add(empty_slots);
    if new_size == (unsafe { (*arr).size }) {
        return 0 as i32;
    }
    if new_size > (unsafe { (*arr).size }) {
        return array_list_expand_internal(arr, new_size);
    }
    if new_size == 0 as i32 as u64 {
        new_size = 1 as i32 as size_t;
    }
    t = unsafe { realloc(
        (*arr).array as *mut libc::c_void,
        new_size.wrapping_mul(::std::mem::size_of::<*mut libc::c_void>() as u64),
    ) };
    if t.is_null() {
        return -(1 as i32);
    }
    let fresh3 = unsafe { &mut ((*arr).array) };
    *fresh3 = t as *mut *mut libc::c_void;
    (unsafe { (*arr).size = new_size });
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn array_list_put_idx(
    mut arr: *mut array_list,
    mut idx: size_t,
    mut data: *mut libc::c_void,
) -> i32 {
    if idx
        > (9223372036854775807 as i64 as u64)
            .wrapping_mul(2 as u64)
            .wrapping_add(1 as u64)
            .wrapping_sub(1 as i32 as u64)
    {
        return -(1 as i32);
    }
    if array_list_expand_internal(arr, idx.wrapping_add(1 as i32 as u64)) != 0 {
        return -(1 as i32);
    }
    if idx < (unsafe { (*arr).length }) && !(unsafe { *((*arr).array).offset(idx as isize) }).is_null() {
        (unsafe { ((*arr).free_fn).expect("non-null function pointer")(*((*arr).array).offset(idx as isize)) });
    }
    let fresh4 = unsafe { &mut (*((*arr).array).offset(idx as isize)) };
    *fresh4 = data;
    if idx > (unsafe { (*arr).length }) {
        (unsafe { memset(
            ((*arr).array).offset((*arr).length as isize) as *mut libc::c_void,
            0 as i32,
            idx.wrapping_sub((*arr).length)
                .wrapping_mul(::std::mem::size_of::<*mut libc::c_void>() as u64),
        ) });
    }
    if (unsafe { (*arr).length }) <= idx {
        (unsafe { (*arr).length = idx.wrapping_add(1 as i32 as u64) });
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn array_list_add(mut arr: *mut array_list, mut data: *mut libc::c_void) -> i32 {
    let mut idx: size_t = unsafe { (*arr).length };
    if idx
        > (9223372036854775807 as i64 as u64)
            .wrapping_mul(2 as u64)
            .wrapping_add(1 as u64)
            .wrapping_sub(1 as i32 as u64)
    {
        return -(1 as i32);
    }
    if array_list_expand_internal(arr, idx.wrapping_add(1 as i32 as u64)) != 0 {
        return -(1 as i32);
    }
    let fresh5 = unsafe { &mut (*((*arr).array).offset(idx as isize)) };
    *fresh5 = data;
    let fresh6 = unsafe { &mut ((*arr).length) };
    *fresh6 = (*fresh6).wrapping_add(1);
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn array_list_sort(
    mut arr: *mut array_list,
    mut compar: Option<unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> i32>,
) {
    (unsafe { qsort(
        (*arr).array as *mut libc::c_void,
        (*arr).length,
        ::std::mem::size_of::<*mut libc::c_void>() as u64,
        compar,
    ) });
}
#[no_mangle]
pub extern "C" fn array_list_bsearch(
    mut key: *mut *const libc::c_void,
    mut arr: *mut array_list,
    mut compar: Option<unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> i32>,
) -> *mut libc::c_void {
    return unsafe { bsearch(
        key as *const libc::c_void,
        (*arr).array as *const libc::c_void,
        (*arr).length,
        ::std::mem::size_of::<*mut libc::c_void>() as u64,
        compar,
    ) };
}
#[no_mangle]
pub extern "C" fn array_list_length(mut arr: *mut array_list) -> size_t {
    return unsafe { (*arr).length };
}
#[no_mangle]
pub extern "C" fn array_list_del_idx(
    mut arr: *mut array_list,
    mut idx: size_t,
    mut count: size_t,
) -> i32 {
    let mut i: size_t = 0;
    let mut stop: size_t = 0;
    if idx
        > (9223372036854775807 as i64 as u64)
            .wrapping_mul(2 as u64)
            .wrapping_add(1 as u64)
            .wrapping_sub(count)
    {
        return -(1 as i32);
    }
    stop = idx.wrapping_add(count);
    if idx >= (unsafe { (*arr).length }) || stop > (unsafe { (*arr).length }) {
        return -(1 as i32);
    }
    i = idx;
    while i < stop {
        if !(unsafe { *((*arr).array).offset(i as isize) }).is_null() {
            (unsafe { ((*arr).free_fn).expect("non-null function pointer")(
                *((*arr).array).offset(i as isize),
            ) });
        }
        i = i.wrapping_add(1);
    }
    (unsafe { memmove(
        ((*arr).array).offset(idx as isize) as *mut libc::c_void,
        ((*arr).array).offset(stop as isize) as *const libc::c_void,
        ((*arr).length)
            .wrapping_sub(stop)
            .wrapping_mul(::std::mem::size_of::<*mut libc::c_void>() as u64),
    ) });
    let fresh7 = unsafe { &mut ((*arr).length) };
    *fresh7 = (*fresh7 as u64).wrapping_sub(count) as size_t as size_t;
    return 0 as i32;
}
