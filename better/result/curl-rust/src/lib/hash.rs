use :: libc;
extern "C" {
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn memcmp(_: *const core::ffi::c_void, _: *const core::ffi::c_void, _: u64) -> i32;
}
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::llist::Curl_llist_destroy;
pub use crate::src::lib::llist::Curl_llist_init;
pub use crate::src::lib::llist::Curl_llist_insert_next;
pub use crate::src::lib::llist::Curl_llist_remove;
pub type size_t = u64;
pub type curl_malloc_callback<'a1> =
    Option<unsafe extern "C" fn(_: u64) -> Option<&'a1 mut core::ffi::c_void>>;
pub type curl_free_callback<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>) -> ()>;
pub type Curl_llist_dtor<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: Option<&'a2 mut core::ffi::c_void>,
    ) -> (),
>;
pub type Curl_llist_element = crate::src::lib::http2::Curl_llist_element;
pub type Curl_llist = crate::src::lib::http2::Curl_llist;
pub type hash_function<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>, _: u64, _: u64) -> u64>;
pub type comp_function<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: u64,
        _: Option<&'a2 mut core::ffi::c_void>,
        _: u64,
    ) -> u64,
>;
pub type Curl_hash_dtor<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>) -> ()>;
pub type Curl_hash = crate::src::lib::http2::Curl_hash;
pub type Curl_hash_element = crate::src::lib::conncache::Curl_hash_element;
pub type Curl_hash_iterator<'a> = crate::src::lib::conncache::Curl_hash_iterator<'a>;
extern "C" fn hash_element_dtor(
    mut user: *mut core::ffi::c_void,
    mut element: *mut core::ffi::c_void,
) {
    let mut h: *mut crate::src::lib::http2::Curl_hash = user as *mut Curl_hash;
    let mut e: *mut crate::src::lib::conncache::Curl_hash_element =
        element as *mut Curl_hash_element;
    if !(unsafe { (*e).ptr }).is_null() {
        (unsafe { ((*h).dtor).expect("non-null function pointer")((*e).ptr) });
        let mut fresh0 = unsafe { &mut ((*e).ptr) };
        *fresh0 = 0 as *mut libc::c_void;
    }
    (unsafe { (*e).key_len = 0 as i32 as size_t });
    (unsafe { Curl_cfree.expect("non-null function pointer")(e as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn Curl_hash_init<'a1>(
    mut h: Option<&'a1 mut crate::src::lib::http2::Curl_hash>,
    mut slots: i32,
    mut hfunc: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64, _: u64) -> u64>,
    mut comparator: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: u64,
            _: *mut core::ffi::c_void,
            _: u64,
        ) -> u64,
    >,
    mut dtor: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>,
) -> i32 {
    if slots == 0 || hfunc.is_none() || comparator.is_none() || dtor.is_none() {
        return 1 as i32;
    }
    let mut fresh1 = &mut ((*(borrow_mut(&mut h)).unwrap()).hash_func);
    *fresh1 = hfunc;
    let mut fresh2 = &mut ((*(borrow_mut(&mut h)).unwrap()).comp_func);
    *fresh2 = comparator;
    let mut fresh3 = &mut ((*(borrow_mut(&mut h)).unwrap()).dtor);
    *fresh3 = dtor;
    (*(borrow_mut(&mut h)).unwrap()).size = 0 as i32 as size_t;
    (*(borrow_mut(&mut h)).unwrap()).slots = slots;
    let mut fresh4 = &mut ((*(borrow_mut(&mut h)).unwrap()).table);
    *fresh4 = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
        (slots as u64).wrapping_mul(::std::mem::size_of::<Curl_llist>() as u64),
    ) }) as *mut Curl_llist;
    if !((*(borrow_mut(&mut h)).unwrap()).table).is_null() {
        let mut i: i32 = 0;
        i = 0 as i32;
        while i < slots {
            Curl_llist_init(
                Some(unsafe { &mut *((*(borrow(&h)).unwrap()).table).offset(i as isize) }),
                unsafe { core::intrinsics::transmute::<
                    Option<
                        unsafe extern "C" fn(
                            _: *mut core::ffi::c_void,
                            _: *mut core::ffi::c_void,
                        ) -> (),
                    >,
                    Option<
                        unsafe extern "C" fn(
                            _: *mut core::ffi::c_void,
                            _: *mut core::ffi::c_void,
                        ) -> (),
                    >,
                >(Some(hash_element_dtor)) },
            );
            i += 1;
        }
        return 0 as i32;
    }
    (*(borrow_mut(&mut h)).unwrap()).slots = 0 as i32;
    return 1 as i32;
}
extern "C" fn mk_hash_element(
    mut key: *const core::ffi::c_void,
    mut key_len: u64,
    mut p: *const core::ffi::c_void,
) -> *mut crate::src::lib::conncache::Curl_hash_element {
    let mut he: *mut crate::src::lib::conncache::Curl_hash_element =
        (unsafe { Curl_cmalloc.expect("non-null function pointer")(
            (::std::mem::size_of::<Curl_hash_element>() as u64).wrapping_add(key_len),
        ) }) as *mut Curl_hash_element;
    if !he.is_null() {
        (unsafe { memcpy(((*he).key).as_mut_ptr() as *mut libc::c_void, key, key_len) });
        (unsafe { (*he).key_len = key_len });
        let mut fresh5 = unsafe { &mut ((*he).ptr) };
        *fresh5 = p as *mut libc::c_void;
    }
    return he;
}
#[no_mangle]
pub extern "C" fn Curl_hash_add(
    mut h: *mut crate::src::lib::http2::Curl_hash,
    mut key: *mut core::ffi::c_void,
    mut key_len: u64,
    mut p: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    let mut he: *mut crate::src::lib::conncache::Curl_hash_element = 0 as *mut Curl_hash_element;
    let mut le: *mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut l: *mut crate::src::lib::http2::Curl_llist = (unsafe { &mut *((*h).table).offset(((*h).hash_func)
        .expect("non-null function pointer")(
        key,
        key_len,
        (*h).slots as size_t,
    ) as isize) }) as *mut Curl_llist;
    le = unsafe { (*l).head };
    while !le.is_null() {
        he = (unsafe { (*le).ptr }) as *mut Curl_hash_element;
        if (unsafe { ((*h).comp_func).expect("non-null function pointer")(
            ((*he).key).as_mut_ptr() as *mut libc::c_void,
            (*he).key_len,
            key,
            key_len,
        ) }) != 0
        {
            Curl_llist_remove(l, le, h as *mut libc::c_void);
            let mut fresh6 = unsafe { &mut ((*h).size) };
            *fresh6 = (*fresh6).wrapping_sub(1);
            break;
        } else {
            le = unsafe { (*le).next };
        }
    }
    he = mk_hash_element(key, key_len, p);
    if !he.is_null() {
        Curl_llist_insert_next(l, unsafe { (*l).tail }, he as *const libc::c_void, unsafe { &mut (*he).list });
        let mut fresh7 = unsafe { &mut ((*h).size) };
        *fresh7 = (*fresh7).wrapping_add(1);
        return p;
    }
    return 0 as *mut libc::c_void;
}
#[no_mangle]
pub extern "C" fn Curl_hash_delete(
    mut h: *mut crate::src::lib::http2::Curl_hash,
    mut key: *mut core::ffi::c_void,
    mut key_len: u64,
) -> i32 {
    let mut le: *mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut l: *mut crate::src::lib::http2::Curl_llist = (unsafe { &mut *((*h).table).offset(((*h).hash_func)
        .expect("non-null function pointer")(
        key,
        key_len,
        (*h).slots as size_t,
    ) as isize) }) as *mut Curl_llist;
    le = unsafe { (*l).head };
    while !le.is_null() {
        let mut he: *mut crate::src::lib::conncache::Curl_hash_element =
            (unsafe { (*le).ptr }) as *mut Curl_hash_element;
        if (unsafe { ((*h).comp_func).expect("non-null function pointer")(
            ((*he).key).as_mut_ptr() as *mut libc::c_void,
            (*he).key_len,
            key,
            key_len,
        ) }) != 0
        {
            Curl_llist_remove(l, le, h as *mut libc::c_void);
            let mut fresh8 = unsafe { &mut ((*h).size) };
            *fresh8 = (*fresh8).wrapping_sub(1);
            return 0 as i32;
        }
        le = unsafe { (*le).next };
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn Curl_hash_pick(
    mut h: *mut crate::src::lib::http2::Curl_hash,
    mut key: *mut core::ffi::c_void,
    mut key_len: u64,
) -> *mut core::ffi::c_void {
    let mut le: *mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut l: Option<&'_ mut crate::src::lib::http2::Curl_llist> =
        Option::<&'_ mut crate::src::lib::http2::Curl_llist>::None;
    if !h.is_null() {
        l = Some(
            unsafe { &mut *((*h).table).offset(((*h).hash_func).expect("non-null function pointer")(
                key,
                key_len,
                (*h).slots as size_t,
            ) as isize) },
        );
        le = (*(borrow_mut(&mut l)).unwrap()).head;
        while !le.is_null() {
            let mut he: *mut crate::src::lib::conncache::Curl_hash_element =
                (unsafe { (*le).ptr }) as *mut Curl_hash_element;
            if (unsafe { ((*h).comp_func).expect("non-null function pointer")(
                ((*he).key).as_mut_ptr() as *mut libc::c_void,
                (*he).key_len,
                key,
                key_len,
            ) }) != 0
            {
                return unsafe { (*he).ptr };
            }
            le = unsafe { (*le).next };
        }
    }
    return 0 as *mut libc::c_void;
}
#[no_mangle]
pub extern "C" fn Curl_hash_destroy(mut h: *mut crate::src::lib::http2::Curl_hash) {
    let mut i: i32 = 0;
    i = 0 as i32;
    while i < (unsafe { (*h).slots }) {
        Curl_llist_destroy(
            unsafe { &mut *((*h).table).offset(i as isize) },
            h as *mut libc::c_void,
        );
        i += 1;
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")((*h).table as *mut libc::c_void) });
    let mut fresh9 = unsafe { &mut ((*h).table) };
    *fresh9 = 0 as *mut Curl_llist;
    (unsafe { (*h).size = 0 as i32 as size_t });
    (unsafe { (*h).slots = 0 as i32 });
}
#[no_mangle]
pub extern "C" fn Curl_hash_clean(mut h: *mut crate::src::lib::http2::Curl_hash) {
    Curl_hash_clean_with_criterium(h, 0 as *mut core::ffi::c_void, None);
}
#[no_mangle]
pub extern "C" fn Curl_hash_clean_with_criterium(
    mut h: *mut crate::src::lib::http2::Curl_hash,
    mut user: *mut core::ffi::c_void,
    mut comp: Option<
        unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut core::ffi::c_void) -> i32,
    >,
) {
    let mut le: *mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut lnext: *mut crate::src::lib::http2::Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut list: *mut crate::src::lib::http2::Curl_llist =
        0 as *mut crate::src::lib::http2::Curl_llist;
    let mut i: i32 = 0;
    if h.is_null() {
        return;
    }
    i = 0 as i32;
    while i < (unsafe { (*h).slots }) {
        list = (unsafe { &mut *((*h).table).offset(i as isize) }) as *mut Curl_llist;
        le = unsafe { (*list).head };
        while !le.is_null() {
            let mut he: *mut crate::src::lib::conncache::Curl_hash_element =
                (unsafe { (*le).ptr }) as *mut Curl_hash_element;
            lnext = unsafe { (*le).next };
            if comp.is_none() || (unsafe { comp.expect("non-null function pointer")(user, (*he).ptr) }) != 0 {
                Curl_llist_remove(list, le, h as *mut libc::c_void);
                let mut fresh10 = unsafe { &mut ((*h).size) };
                *fresh10 = (*fresh10).wrapping_sub(1);
            }
            le = lnext;
        }
        i += 1;
    }
}
#[no_mangle]
pub extern "C" fn Curl_hash_str(
    mut key: *mut core::ffi::c_void,
    mut key_length: u64,
    mut slots_num: u64,
) -> u64 {
    let mut key_str: *const i8 = key as *const i8;
    let mut end: *const i8 = unsafe { key_str.offset(key_length as isize) };
    let mut h: u64 = 5381 as i32 as size_t;
    while key_str < end {
        h = (h as u64).wrapping_add(h << 5 as i32) as size_t as size_t;
        let mut fresh11 = key_str;
        key_str = unsafe { key_str.offset(1) };
        h ^= (unsafe { *fresh11 }) as u64;
    }
    return h.wrapping_rem(slots_num);
}
#[no_mangle]
pub extern "C" fn Curl_str_key_compare(
    mut k1: *mut core::ffi::c_void,
    mut key1_len: u64,
    mut k2: *mut core::ffi::c_void,
    mut key2_len: u64,
) -> u64 {
    if key1_len == key2_len && (unsafe { memcmp(k1, k2, key1_len) }) == 0 {
        return 1 as i32 as size_t;
    }
    return 0 as i32 as size_t;
}
#[no_mangle]
pub extern "C" fn Curl_hash_start_iterate<'a1, 'a2, 'a3>(
    mut hash: Option<&'a1 mut crate::src::lib::http2::Curl_hash>,
    mut iter: Option<&'a2 mut crate::src::lib::conncache::Curl_hash_iterator<'a3>>,
) where
    'a1: 'a3,
    'a3: 'a1,
{
    let mut fresh12 = &mut ((*(borrow_mut(&mut iter)).unwrap()).hash);
    *fresh12 = hash;
    (*(borrow_mut(&mut iter)).unwrap()).slot_index = 0 as i32;
    let mut fresh13 = &mut ((*(borrow_mut(&mut iter)).unwrap()).current_element);
    *fresh13 = 0 as *mut Curl_llist_element;
}
#[no_mangle]
pub extern "C" fn Curl_hash_next_element<'a1>(
    mut iter: *mut crate::src::lib::conncache::Curl_hash_iterator<'a1>,
) -> *mut crate::src::lib::conncache::Curl_hash_element {
    let mut h: Option<&'_ mut crate::src::lib::http2::Curl_hash> = borrow_mut(unsafe { &mut (*iter).hash });
    if !(unsafe { (*iter).current_element }).is_null() {
        let mut fresh14 = unsafe { &mut ((*iter).current_element) };
        *fresh14 = unsafe { (*(*iter).current_element).next };
    }
    if (unsafe { (*iter).current_element }).is_null() {
        let mut i: i32 = 0;
        i = unsafe { (*iter).slot_index };
        while i < (*(borrow(&h)).unwrap()).slots {
            if !(unsafe { (*((*(borrow(&h)).unwrap()).table).offset(i as isize)).head }).is_null() {
                let mut fresh15 = unsafe { &mut ((*iter).current_element) };
                *fresh15 = unsafe { (*((*(borrow(&h)).unwrap()).table).offset(i as isize)).head };
                (unsafe { (*iter).slot_index = i + 1 as i32 });
                break;
            } else {
                i += 1;
            }
        }
    }
    if !(unsafe { (*iter).current_element }).is_null() {
        let mut he: *mut crate::src::lib::conncache::Curl_hash_element =
            (unsafe { (*(*iter).current_element).ptr }) as *mut Curl_hash_element;
        return he;
    }
    let mut fresh16 = unsafe { &mut ((*iter).current_element) };
    *fresh16 = 0 as *mut Curl_llist_element;
    return 0 as *mut crate::src::lib::conncache::Curl_hash_element;
}
use crate::laertes_rt::*;
