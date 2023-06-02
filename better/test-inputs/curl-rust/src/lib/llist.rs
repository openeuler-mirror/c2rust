use ::libc;
pub type size_t = libc::c_ulong;
pub type Curl_llist_dtor = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> (),
>;
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
#[no_mangle]
pub unsafe extern "C" fn Curl_llist_init(
    mut l: *mut Curl_llist,
    mut dtor: Curl_llist_dtor,
) {
    (*l).size = 0 as libc::c_int as size_t;
    let ref mut fresh0 = (*l).dtor;
    *fresh0 = dtor;
    let ref mut fresh1 = (*l).head;
    *fresh1 = 0 as *mut Curl_llist_element;
    let ref mut fresh2 = (*l).tail;
    *fresh2 = 0 as *mut Curl_llist_element;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_llist_insert_next(
    mut list: *mut Curl_llist,
    mut e: *mut Curl_llist_element,
    mut p: *const libc::c_void,
    mut ne: *mut Curl_llist_element,
) {
    let ref mut fresh3 = (*ne).ptr;
    *fresh3 = p as *mut libc::c_void;
    if (*list).size == 0 as libc::c_int as libc::c_ulong {
        let ref mut fresh4 = (*list).head;
        *fresh4 = ne;
        let ref mut fresh5 = (*(*list).head).prev;
        *fresh5 = 0 as *mut Curl_llist_element;
        let ref mut fresh6 = (*(*list).head).next;
        *fresh6 = 0 as *mut Curl_llist_element;
        let ref mut fresh7 = (*list).tail;
        *fresh7 = ne;
    } else {
        let ref mut fresh8 = (*ne).next;
        *fresh8 = if !e.is_null() { (*e).next } else { (*list).head };
        let ref mut fresh9 = (*ne).prev;
        *fresh9 = e;
        if e.is_null() {
            let ref mut fresh10 = (*(*list).head).prev;
            *fresh10 = ne;
            let ref mut fresh11 = (*list).head;
            *fresh11 = ne;
        } else if !((*e).next).is_null() {
            let ref mut fresh12 = (*(*e).next).prev;
            *fresh12 = ne;
        } else {
            let ref mut fresh13 = (*list).tail;
            *fresh13 = ne;
        }
        if !e.is_null() {
            let ref mut fresh14 = (*e).next;
            *fresh14 = ne;
        }
    }
    let ref mut fresh15 = (*list).size;
    *fresh15 = (*fresh15).wrapping_add(1);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_llist_remove(
    mut list: *mut Curl_llist,
    mut e: *mut Curl_llist_element,
    mut user: *mut libc::c_void,
) {
    let mut ptr: *mut libc::c_void = 0 as *mut libc::c_void;
    if e.is_null() || (*list).size == 0 as libc::c_int as libc::c_ulong {
        return;
    }
    if e == (*list).head {
        let ref mut fresh16 = (*list).head;
        *fresh16 = (*e).next;
        if ((*list).head).is_null() {
            let ref mut fresh17 = (*list).tail;
            *fresh17 = 0 as *mut Curl_llist_element;
        } else {
            let ref mut fresh18 = (*(*e).next).prev;
            *fresh18 = 0 as *mut Curl_llist_element;
        }
    } else {
        if ((*e).prev).is_null() {
            let ref mut fresh19 = (*list).head;
            *fresh19 = (*e).next;
        } else {
            let ref mut fresh20 = (*(*e).prev).next;
            *fresh20 = (*e).next;
        }
        if ((*e).next).is_null() {
            let ref mut fresh21 = (*list).tail;
            *fresh21 = (*e).prev;
        } else {
            let ref mut fresh22 = (*(*e).next).prev;
            *fresh22 = (*e).prev;
        }
    }
    ptr = (*e).ptr;
    let ref mut fresh23 = (*e).ptr;
    *fresh23 = 0 as *mut libc::c_void;
    let ref mut fresh24 = (*e).prev;
    *fresh24 = 0 as *mut Curl_llist_element;
    let ref mut fresh25 = (*e).next;
    *fresh25 = 0 as *mut Curl_llist_element;
    let ref mut fresh26 = (*list).size;
    *fresh26 = (*fresh26).wrapping_sub(1);
    if ((*list).dtor).is_some() {
        ((*list).dtor).expect("non-null function pointer")(user, ptr);
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_llist_destroy(
    mut list: *mut Curl_llist,
    mut user: *mut libc::c_void,
) {
    if !list.is_null() {
        while (*list).size > 0 as libc::c_int as libc::c_ulong {
            Curl_llist_remove(list, (*list).tail, user);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_llist_count(mut list: *mut Curl_llist) -> size_t {
    return (*list).size;
}
