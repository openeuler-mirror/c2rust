use ::libc;
extern "C" {
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn bsearch(
        __key: *const libc::c_void,
        __base: *const libc::c_void,
        __nmemb: size_t,
        __size: size_t,
        __compar: __compar_fn_t,
    ) -> *mut libc::c_void;
    fn qsort(
        __base: *mut libc::c_void,
        __nmemb: size_t,
        __size: size_t,
        __compar: __compar_fn_t,
    );
    fn memmove(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
}
pub type size_t = libc::c_ulong;
pub type __compar_fn_t = Option::<
    unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
>;
pub type array_list_free_fn = unsafe extern "C" fn(*mut libc::c_void) -> ();
#[derive(Copy, Clone)]
#[repr(C)]
pub struct array_list {
    pub array: *mut *mut libc::c_void,
    pub length: size_t,
    pub size: size_t,
    pub free_fn: Option::<array_list_free_fn>,
}
#[no_mangle]
pub unsafe extern "C" fn array_list_new(
    mut free_fn: Option::<array_list_free_fn>,
) -> *mut array_list {
    return array_list_new2(free_fn, 32 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn array_list_new2(
    mut free_fn: Option::<array_list_free_fn>,
    mut initial_size: libc::c_int,
) -> *mut array_list {
    let mut arr: *mut array_list = 0 as *mut array_list;
    if initial_size < 0 as libc::c_int
        || initial_size as size_t
            >= (9223372036854775807 as libc::c_long as libc::c_ulong)
                .wrapping_mul(2 as libc::c_ulong)
                .wrapping_add(1 as libc::c_ulong)
                .wrapping_div(
                    ::std::mem::size_of::<*mut libc::c_void>() as libc::c_ulong,
                )
    {
        return 0 as *mut array_list;
    }
    arr = malloc(::std::mem::size_of::<array_list>() as libc::c_ulong)
        as *mut array_list;
    if arr.is_null() {
        return 0 as *mut array_list;
    }
    (*arr).size = initial_size as size_t;
    (*arr).length = 0 as libc::c_int as size_t;
    let ref mut fresh0 = (*arr).free_fn;
    *fresh0 = free_fn;
    let ref mut fresh1 = (*arr).array;
    *fresh1 = malloc(
        ((*arr).size)
            .wrapping_mul(::std::mem::size_of::<*mut libc::c_void>() as libc::c_ulong),
    ) as *mut *mut libc::c_void;
    if (*fresh1).is_null() {
        free(arr as *mut libc::c_void);
        return 0 as *mut array_list;
    }
    return arr;
}
#[no_mangle]
pub unsafe extern "C" fn array_list_free(mut arr: *mut array_list) {
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < (*arr).length {
        if !(*((*arr).array).offset(i as isize)).is_null() {
            ((*arr).free_fn)
                .expect("non-null function pointer")(*((*arr).array).offset(i as isize));
        }
        i = i.wrapping_add(1);
    }
    free((*arr).array as *mut libc::c_void);
    free(arr as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn array_list_get_idx(
    mut arr: *mut array_list,
    mut i: size_t,
) -> *mut libc::c_void {
    if i >= (*arr).length {
        return 0 as *mut libc::c_void;
    }
    return *((*arr).array).offset(i as isize);
}
unsafe extern "C" fn array_list_expand_internal(
    mut arr: *mut array_list,
    mut max: size_t,
) -> libc::c_int {
    let mut t: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut new_size: size_t = 0;
    if max < (*arr).size {
        return 0 as libc::c_int;
    }
    if (*arr).size
        >= (9223372036854775807 as libc::c_long as libc::c_ulong)
            .wrapping_mul(2 as libc::c_ulong)
            .wrapping_add(1 as libc::c_ulong)
            .wrapping_div(2 as libc::c_int as libc::c_ulong)
    {
        new_size = max;
    } else {
        new_size = (*arr).size << 1 as libc::c_int;
        if new_size < max {
            new_size = max;
        }
    }
    if new_size
        > (!(0 as libc::c_int as size_t))
            .wrapping_div(::std::mem::size_of::<*mut libc::c_void>() as libc::c_ulong)
    {
        return -(1 as libc::c_int);
    }
    t = realloc(
        (*arr).array as *mut libc::c_void,
        new_size
            .wrapping_mul(::std::mem::size_of::<*mut libc::c_void>() as libc::c_ulong),
    );
    if t.is_null() {
        return -(1 as libc::c_int);
    }
    let ref mut fresh2 = (*arr).array;
    *fresh2 = t as *mut *mut libc::c_void;
    (*arr).size = new_size;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn array_list_shrink(
    mut arr: *mut array_list,
    mut empty_slots: size_t,
) -> libc::c_int {
    let mut t: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut new_size: size_t = 0;
    if empty_slots
        >= (9223372036854775807 as libc::c_long as libc::c_ulong)
            .wrapping_mul(2 as libc::c_ulong)
            .wrapping_add(1 as libc::c_ulong)
            .wrapping_div(::std::mem::size_of::<*mut libc::c_void>() as libc::c_ulong)
            .wrapping_sub((*arr).length)
    {
        return -(1 as libc::c_int);
    }
    new_size = ((*arr).length).wrapping_add(empty_slots);
    if new_size == (*arr).size {
        return 0 as libc::c_int;
    }
    if new_size > (*arr).size {
        return array_list_expand_internal(arr, new_size);
    }
    if new_size == 0 as libc::c_int as libc::c_ulong {
        new_size = 1 as libc::c_int as size_t;
    }
    t = realloc(
        (*arr).array as *mut libc::c_void,
        new_size
            .wrapping_mul(::std::mem::size_of::<*mut libc::c_void>() as libc::c_ulong),
    );
    if t.is_null() {
        return -(1 as libc::c_int);
    }
    let ref mut fresh3 = (*arr).array;
    *fresh3 = t as *mut *mut libc::c_void;
    (*arr).size = new_size;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn array_list_put_idx(
    mut arr: *mut array_list,
    mut idx: size_t,
    mut data: *mut libc::c_void,
) -> libc::c_int {
    if idx
        > (9223372036854775807 as libc::c_long as libc::c_ulong)
            .wrapping_mul(2 as libc::c_ulong)
            .wrapping_add(1 as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
    {
        return -(1 as libc::c_int);
    }
    if array_list_expand_internal(
        arr,
        idx.wrapping_add(1 as libc::c_int as libc::c_ulong),
    ) != 0
    {
        return -(1 as libc::c_int);
    }
    if idx < (*arr).length && !(*((*arr).array).offset(idx as isize)).is_null() {
        ((*arr).free_fn)
            .expect("non-null function pointer")(*((*arr).array).offset(idx as isize));
    }
    let ref mut fresh4 = *((*arr).array).offset(idx as isize);
    *fresh4 = data;
    if idx > (*arr).length {
        memset(
            ((*arr).array).offset((*arr).length as isize) as *mut libc::c_void,
            0 as libc::c_int,
            idx
                .wrapping_sub((*arr).length)
                .wrapping_mul(
                    ::std::mem::size_of::<*mut libc::c_void>() as libc::c_ulong,
                ),
        );
    }
    if (*arr).length <= idx {
        (*arr).length = idx.wrapping_add(1 as libc::c_int as libc::c_ulong);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn array_list_add(
    mut arr: *mut array_list,
    mut data: *mut libc::c_void,
) -> libc::c_int {
    let mut idx: size_t = (*arr).length;
    if idx
        > (9223372036854775807 as libc::c_long as libc::c_ulong)
            .wrapping_mul(2 as libc::c_ulong)
            .wrapping_add(1 as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
    {
        return -(1 as libc::c_int);
    }
    if array_list_expand_internal(
        arr,
        idx.wrapping_add(1 as libc::c_int as libc::c_ulong),
    ) != 0
    {
        return -(1 as libc::c_int);
    }
    let ref mut fresh5 = *((*arr).array).offset(idx as isize);
    *fresh5 = data;
    let ref mut fresh6 = (*arr).length;
    *fresh6 = (*fresh6).wrapping_add(1);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn array_list_sort(
    mut arr: *mut array_list,
    mut compar: Option::<
        unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
    >,
) {
    qsort(
        (*arr).array as *mut libc::c_void,
        (*arr).length,
        ::std::mem::size_of::<*mut libc::c_void>() as libc::c_ulong,
        compar,
    );
}
#[no_mangle]
pub unsafe extern "C" fn array_list_bsearch(
    mut key: *mut *const libc::c_void,
    mut arr: *mut array_list,
    mut compar: Option::<
        unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
    >,
) -> *mut libc::c_void {
    return bsearch(
        key as *const libc::c_void,
        (*arr).array as *const libc::c_void,
        (*arr).length,
        ::std::mem::size_of::<*mut libc::c_void>() as libc::c_ulong,
        compar,
    );
}
#[no_mangle]
pub unsafe extern "C" fn array_list_length(mut arr: *mut array_list) -> size_t {
    return (*arr).length;
}
#[no_mangle]
pub unsafe extern "C" fn array_list_del_idx(
    mut arr: *mut array_list,
    mut idx: size_t,
    mut count: size_t,
) -> libc::c_int {
    let mut i: size_t = 0;
    let mut stop: size_t = 0;
    if idx
        > (9223372036854775807 as libc::c_long as libc::c_ulong)
            .wrapping_mul(2 as libc::c_ulong)
            .wrapping_add(1 as libc::c_ulong)
            .wrapping_sub(count)
    {
        return -(1 as libc::c_int);
    }
    stop = idx.wrapping_add(count);
    if idx >= (*arr).length || stop > (*arr).length {
        return -(1 as libc::c_int);
    }
    i = idx;
    while i < stop {
        if !(*((*arr).array).offset(i as isize)).is_null() {
            ((*arr).free_fn)
                .expect("non-null function pointer")(*((*arr).array).offset(i as isize));
        }
        i = i.wrapping_add(1);
    }
    memmove(
        ((*arr).array).offset(idx as isize) as *mut libc::c_void,
        ((*arr).array).offset(stop as isize) as *const libc::c_void,
        ((*arr).length)
            .wrapping_sub(stop)
            .wrapping_mul(::std::mem::size_of::<*mut libc::c_void>() as libc::c_ulong),
    );
    let ref mut fresh7 = (*arr).length;
    *fresh7 = (*fresh7 as libc::c_ulong).wrapping_sub(count) as size_t as size_t;
    return 0 as libc::c_int;
}
