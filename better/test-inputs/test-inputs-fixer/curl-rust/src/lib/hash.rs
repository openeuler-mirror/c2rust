use :: libc;
extern "C" {
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: u64) -> i32;
    fn Curl_llist_init(_: *mut Curl_llist, _: Curl_llist_dtor);
    fn Curl_llist_insert_next(
        _: *mut Curl_llist,
        _: *mut Curl_llist_element,
        _: *const libc::c_void,
        node: *mut Curl_llist_element,
    );
    fn Curl_llist_remove(_: *mut Curl_llist, _: *mut Curl_llist_element, _: *mut libc::c_void);
    fn Curl_llist_destroy(_: *mut Curl_llist, _: *mut libc::c_void);
    static mut Curl_cmalloc: curl_malloc_callback;
    static mut Curl_cfree: curl_free_callback;
}
pub type size_t = u64;
pub type curl_malloc_callback = Option<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
pub type curl_free_callback = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type Curl_llist_dtor = Option<unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_llist_element {
    pub ptr: *mut libc::c_void,
    pub prev: *mut Curl_llist_element,
    pub next: *mut Curl_llist_element,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_llist {
    pub head: *mut Curl_llist_element,
    pub tail: *mut Curl_llist_element,
    pub dtor: Curl_llist_dtor,
    pub size: size_t,
}
pub type hash_function = Option<unsafe extern "C" fn(*mut libc::c_void, size_t, size_t) -> size_t>;
pub type comp_function =
    Option<unsafe extern "C" fn(*mut libc::c_void, size_t, *mut libc::c_void, size_t) -> size_t>;
pub type Curl_hash_dtor = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_hash {
    pub table: *mut Curl_llist,
    pub hash_func: hash_function,
    pub comp_func: comp_function,
    pub dtor: Curl_hash_dtor,
    pub slots: i32,
    pub size: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_hash_element {
    pub list: Curl_llist_element,
    pub ptr: *mut libc::c_void,
    pub key_len: size_t,
    pub key: [i8; 1],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_hash_iterator {
    pub hash: *mut Curl_hash,
    pub slot_index: i32,
    pub current_element: *mut Curl_llist_element,
}
extern "C" fn hash_element_dtor(mut user: *mut libc::c_void, mut element: *mut libc::c_void) {
    let mut h: *mut Curl_hash = user as *mut Curl_hash;
    let mut e: *mut Curl_hash_element = element as *mut Curl_hash_element;
    if !(unsafe { (*e).ptr }).is_null() {
        (unsafe { ((*h).dtor).expect("non-null function pointer")((*e).ptr) });
        let fresh0 = unsafe { &mut ((*e).ptr) };
        *fresh0 = 0 as *mut libc::c_void;
    }
    (unsafe { (*e).key_len = 0 as i32 as size_t });
    (unsafe { Curl_cfree.expect("non-null function pointer")(e as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn Curl_hash_init(
    mut h: *mut Curl_hash,
    mut slots: i32,
    mut hfunc: hash_function,
    mut comparator: comp_function,
    mut dtor: Curl_hash_dtor,
) -> i32 {
    if slots == 0 || hfunc.is_none() || comparator.is_none() || dtor.is_none() {
        return 1 as i32;
    }
    let fresh1 = unsafe { &mut ((*h).hash_func) };
    *fresh1 = hfunc;
    let fresh2 = unsafe { &mut ((*h).comp_func) };
    *fresh2 = comparator;
    let fresh3 = unsafe { &mut ((*h).dtor) };
    *fresh3 = dtor;
    (unsafe { (*h).size = 0 as i32 as size_t });
    (unsafe { (*h).slots = slots });
    let fresh4 = unsafe { &mut ((*h).table) };
    *fresh4 = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
        (slots as u64).wrapping_mul(::std::mem::size_of::<Curl_llist>() as u64),
    ) }) as *mut Curl_llist;
    if !(unsafe { (*h).table }).is_null() {
        let mut i: i32 = 0;
        i = 0 as i32;
        while i < slots {
            (unsafe { Curl_llist_init(
                &mut *((*h).table).offset(i as isize),
                ::std::mem::transmute::<
                    Option<unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> ()>,
                    Curl_llist_dtor,
                >(Some(
                    hash_element_dtor
                        as unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> (),
                )),
            ) });
            i += 1;
        }
        return 0 as i32;
    }
    (unsafe { (*h).slots = 0 as i32 });
    return 1 as i32;
}
extern "C" fn mk_hash_element(
    mut key: *const libc::c_void,
    mut key_len: size_t,
    mut p: *const libc::c_void,
) -> *mut Curl_hash_element {
    let mut he: *mut Curl_hash_element = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
        (::std::mem::size_of::<Curl_hash_element>() as u64).wrapping_add(key_len),
    ) }) as *mut Curl_hash_element;
    if !he.is_null() {
        (unsafe { memcpy(((*he).key).as_mut_ptr() as *mut libc::c_void, key, key_len) });
        (unsafe { (*he).key_len = key_len });
        let fresh5 = unsafe { &mut ((*he).ptr) };
        *fresh5 = p as *mut libc::c_void;
    }
    return he;
}
#[no_mangle]
pub extern "C" fn Curl_hash_add(
    mut h: *mut Curl_hash,
    mut key: *mut libc::c_void,
    mut key_len: size_t,
    mut p: *mut libc::c_void,
) -> *mut libc::c_void {
    let mut he: *mut Curl_hash_element = 0 as *mut Curl_hash_element;
    let mut le: *mut Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut l: *mut Curl_llist = (unsafe { &mut *((*h).table).offset(((*h).hash_func)
        .expect("non-null function pointer")(
        key, key_len, (*h).slots as size_t
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
            (unsafe { Curl_llist_remove(l, le, h as *mut libc::c_void) });
            let fresh6 = unsafe { &mut ((*h).size) };
            *fresh6 = (*fresh6).wrapping_sub(1);
            break;
        } else {
            le = unsafe { (*le).next };
        }
    }
    he = mk_hash_element(key, key_len, p);
    if !he.is_null() {
        (unsafe { Curl_llist_insert_next(l, (*l).tail, he as *const libc::c_void, &mut (*he).list) });
        let fresh7 = unsafe { &mut ((*h).size) };
        *fresh7 = (*fresh7).wrapping_add(1);
        return p;
    }
    return 0 as *mut libc::c_void;
}
#[no_mangle]
pub extern "C" fn Curl_hash_delete(
    mut h: *mut Curl_hash,
    mut key: *mut libc::c_void,
    mut key_len: size_t,
) -> i32 {
    let mut le: *mut Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut l: *mut Curl_llist = (unsafe { &mut *((*h).table).offset(((*h).hash_func)
        .expect("non-null function pointer")(
        key, key_len, (*h).slots as size_t
    ) as isize) }) as *mut Curl_llist;
    le = unsafe { (*l).head };
    while !le.is_null() {
        let mut he: *mut Curl_hash_element = (unsafe { (*le).ptr }) as *mut Curl_hash_element;
        if (unsafe { ((*h).comp_func).expect("non-null function pointer")(
            ((*he).key).as_mut_ptr() as *mut libc::c_void,
            (*he).key_len,
            key,
            key_len,
        ) }) != 0
        {
            (unsafe { Curl_llist_remove(l, le, h as *mut libc::c_void) });
            let fresh8 = unsafe { &mut ((*h).size) };
            *fresh8 = (*fresh8).wrapping_sub(1);
            return 0 as i32;
        }
        le = unsafe { (*le).next };
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn Curl_hash_pick(
    mut h: *mut Curl_hash,
    mut key: *mut libc::c_void,
    mut key_len: size_t,
) -> *mut libc::c_void {
    let mut le: *mut Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut l: *mut Curl_llist = 0 as *mut Curl_llist;
    if !h.is_null() {
        l = (unsafe { &mut *((*h).table).offset(((*h).hash_func).expect("non-null function pointer")(
            key,
            key_len,
            (*h).slots as size_t,
        ) as isize) }) as *mut Curl_llist;
        le = unsafe { (*l).head };
        while !le.is_null() {
            let mut he: *mut Curl_hash_element = (unsafe { (*le).ptr }) as *mut Curl_hash_element;
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
pub extern "C" fn Curl_hash_destroy(mut h: *mut Curl_hash) {
    let mut i: i32 = 0;
    i = 0 as i32;
    while i < (unsafe { (*h).slots }) {
        (unsafe { Curl_llist_destroy(
            &mut *((*h).table).offset(i as isize),
            h as *mut libc::c_void,
        ) });
        i += 1;
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")((*h).table as *mut libc::c_void) });
    let fresh9 = unsafe { &mut ((*h).table) };
    *fresh9 = 0 as *mut Curl_llist;
    (unsafe { (*h).size = 0 as i32 as size_t });
    (unsafe { (*h).slots = 0 as i32 });
}
#[no_mangle]
pub extern "C" fn Curl_hash_clean(mut h: *mut Curl_hash) {
    Curl_hash_clean_with_criterium(h, 0 as *mut libc::c_void, None);
}
#[no_mangle]
pub extern "C" fn Curl_hash_clean_with_criterium(
    mut h: *mut Curl_hash,
    mut user: *mut libc::c_void,
    mut comp: Option<unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> i32>,
) {
    let mut le: *mut Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut lnext: *mut Curl_llist_element = 0 as *mut Curl_llist_element;
    let mut list: *mut Curl_llist = 0 as *mut Curl_llist;
    let mut i: i32 = 0;
    if h.is_null() {
        return;
    }
    i = 0 as i32;
    while i < (unsafe { (*h).slots }) {
        list = (unsafe { &mut *((*h).table).offset(i as isize) }) as *mut Curl_llist;
        le = unsafe { (*list).head };
        while !le.is_null() {
            let mut he: *mut Curl_hash_element = (unsafe { (*le).ptr }) as *mut Curl_hash_element;
            lnext = unsafe { (*le).next };
            if comp.is_none() || (unsafe { comp.expect("non-null function pointer")(user, (*he).ptr) }) != 0 {
                (unsafe { Curl_llist_remove(list, le, h as *mut libc::c_void) });
                let fresh10 = unsafe { &mut ((*h).size) };
                *fresh10 = (*fresh10).wrapping_sub(1);
            }
            le = lnext;
        }
        i += 1;
    }
}
#[no_mangle]
pub extern "C" fn Curl_hash_str(
    mut key: *mut libc::c_void,
    mut key_length: size_t,
    mut slots_num: size_t,
) -> size_t {
    let mut key_str: *const i8 = key as *const i8;
    let mut end: *const i8 = unsafe { key_str.offset(key_length as isize) };
    let mut h: size_t = 5381 as i32 as size_t;
    while key_str < end {
        h = (h as u64).wrapping_add(h << 5 as i32) as size_t as size_t;
        let fresh11 = key_str;
        key_str = unsafe { key_str.offset(1) };
        h ^= (unsafe { *fresh11 }) as u64;
    }
    return h.wrapping_rem(slots_num);
}
#[no_mangle]
pub extern "C" fn Curl_str_key_compare(
    mut k1: *mut libc::c_void,
    mut key1_len: size_t,
    mut k2: *mut libc::c_void,
    mut key2_len: size_t,
) -> size_t {
    if key1_len == key2_len && (unsafe { memcmp(k1, k2, key1_len) }) == 0 {
        return 1 as i32 as size_t;
    }
    return 0 as i32 as size_t;
}
#[no_mangle]
pub extern "C" fn Curl_hash_start_iterate(
    mut hash: *mut Curl_hash,
    mut iter: *mut Curl_hash_iterator,
) {
    let fresh12 = unsafe { &mut ((*iter).hash) };
    *fresh12 = hash;
    (unsafe { (*iter).slot_index = 0 as i32 });
    let fresh13 = unsafe { &mut ((*iter).current_element) };
    *fresh13 = 0 as *mut Curl_llist_element;
}
#[no_mangle]
pub extern "C" fn Curl_hash_next_element(
    mut iter: *mut Curl_hash_iterator,
) -> *mut Curl_hash_element {
    let mut h: *mut Curl_hash = unsafe { (*iter).hash };
    if !(unsafe { (*iter).current_element }).is_null() {
        let fresh14 = unsafe { &mut ((*iter).current_element) };
        *fresh14 = unsafe { (*(*iter).current_element).next };
    }
    if (unsafe { (*iter).current_element }).is_null() {
        let mut i: i32 = 0;
        i = unsafe { (*iter).slot_index };
        while i < (unsafe { (*h).slots }) {
            if !(unsafe { (*((*h).table).offset(i as isize)).head }).is_null() {
                let fresh15 = unsafe { &mut ((*iter).current_element) };
                *fresh15 = unsafe { (*((*h).table).offset(i as isize)).head };
                (unsafe { (*iter).slot_index = i + 1 as i32 });
                break;
            } else {
                i += 1;
            }
        }
    }
    if !(unsafe { (*iter).current_element }).is_null() {
        let mut he: *mut Curl_hash_element =
            (unsafe { (*(*iter).current_element).ptr }) as *mut Curl_hash_element;
        return he;
    }
    let fresh16 = unsafe { &mut ((*iter).current_element) };
    *fresh16 = 0 as *mut Curl_llist_element;
    return 0 as *mut Curl_hash_element;
}
