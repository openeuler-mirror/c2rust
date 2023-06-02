use ::libc;
pub type size_t = crate::src::lib::altsvc::size_t;
pub type Curl_llist_dtor = crate::src::lib::altsvc::Curl_llist_dtor;
// #[derive(Copy, Clone)]

pub type Curl_llist_element = crate::src::lib::altsvc::Curl_llist_element;
// #[derive(Copy, Clone)]

pub type Curl_llist = crate::src::lib::altsvc::Curl_llist;
#[no_mangle]
pub unsafe extern "C" fn Curl_llist_init(
    mut l: *mut Curl_llist,
    mut dtor: Curl_llist_dtor,
) {
    (*l).size = 0 as i32 as size_t;
    let fresh0 = &mut ((*l).dtor);
    *fresh0 = dtor;
    let fresh1 = &mut ((*l).head);
    *fresh1 = 0 as *mut Curl_llist_element;
    let fresh2 = &mut ((*l).tail);
    *fresh2 = 0 as *mut Curl_llist_element;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_llist_insert_next(
    mut list: *mut Curl_llist,
    mut e: *mut Curl_llist_element,
    mut p: *const libc::c_void,
    mut ne: *mut Curl_llist_element,
) {
    let fresh3 = &mut ((*ne).ptr);
    *fresh3 = p as *mut libc::c_void;
    if (*list).size == 0 as i32 as u64 {
        let fresh4 = &mut ((*list).head);
        *fresh4 = ne;
        let fresh5 = &mut ((*(*list).head).prev);
        *fresh5 = 0 as *mut Curl_llist_element;
        let fresh6 = &mut ((*(*list).head).next);
        *fresh6 = 0 as *mut Curl_llist_element;
        let fresh7 = &mut ((*list).tail);
        *fresh7 = ne;
    } else {
        let fresh8 = &mut ((*ne).next);
        *fresh8 = if !e.is_null() { (*e).next } else { (*list).head };
        let fresh9 = &mut ((*ne).prev);
        *fresh9 = e;
        if e.is_null() {
            let fresh10 = &mut ((*(*list).head).prev);
            *fresh10 = ne;
            let fresh11 = &mut ((*list).head);
            *fresh11 = ne;
        } else if !((*e).next).is_null() {
            let fresh12 = &mut ((*(*e).next).prev);
            *fresh12 = ne;
        } else {
            let fresh13 = &mut ((*list).tail);
            *fresh13 = ne;
        }
        if !e.is_null() {
            let fresh14 = &mut ((*e).next);
            *fresh14 = ne;
        }
    }
    let fresh15 = &mut ((*list).size);
    *fresh15 = (*fresh15).wrapping_add(1);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_llist_remove(
    mut list: *mut Curl_llist,
    mut e: *mut Curl_llist_element,
    mut user: *mut libc::c_void,
) {
    let mut ptr: *mut libc::c_void = 0 as *mut libc::c_void;
    if e.is_null() || (*list).size == 0 as i32 as u64 {
        return;
    }
    if e == (*list).head {
        let fresh16 = &mut ((*list).head);
        *fresh16 = (*e).next;
        if ((*list).head).is_null() {
            let fresh17 = &mut ((*list).tail);
            *fresh17 = 0 as *mut Curl_llist_element;
        } else {
            let fresh18 = &mut ((*(*e).next).prev);
            *fresh18 = 0 as *mut Curl_llist_element;
        }
    } else {
        if ((*e).prev).is_null() {
            let fresh19 = &mut ((*list).head);
            *fresh19 = (*e).next;
        } else {
            let fresh20 = &mut ((*(*e).prev).next);
            *fresh20 = (*e).next;
        }
        if ((*e).next).is_null() {
            let fresh21 = &mut ((*list).tail);
            *fresh21 = (*e).prev;
        } else {
            let fresh22 = &mut ((*(*e).next).prev);
            *fresh22 = (*e).prev;
        }
    }
    ptr = (*e).ptr;
    let fresh23 = &mut ((*e).ptr);
    *fresh23 = 0 as *mut libc::c_void;
    let fresh24 = &mut ((*e).prev);
    *fresh24 = 0 as *mut Curl_llist_element;
    let fresh25 = &mut ((*e).next);
    *fresh25 = 0 as *mut Curl_llist_element;
    let fresh26 = &mut ((*list).size);
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
        while (*list).size > 0 as i32 as u64 {
            Curl_llist_remove(list, (*list).tail, user);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_llist_count(mut list: *mut Curl_llist) -> size_t {
    return (*list).size;
}
