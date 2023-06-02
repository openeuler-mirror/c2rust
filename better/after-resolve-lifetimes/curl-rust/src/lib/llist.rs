use ::libc;
pub type size_t = u64;
pub type Curl_llist_dtor<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: Option<&'a2 mut core::ffi::c_void>,) -> ()>;
// #[derive(Copy, Clone)]

pub type Curl_llist_element = crate::src::lib::http2::Curl_llist_element;
// #[derive(Copy, Clone)]

pub type Curl_llist = crate::src::lib::http2::Curl_llist;
#[no_mangle]
pub unsafe extern "C" fn Curl_llist_init<'a1>(
    mut l: Option<&'a1 mut crate::src::lib::http2::Curl_llist>,
    mut dtor: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut core::ffi::c_void,) -> ()>,
) {
    (*(borrow_mut(&mut l)).unwrap()).size = 0 as i32 as size_t;
    let mut fresh0 = &mut ((*(borrow_mut(&mut l)).unwrap()).dtor);
    *fresh0 = dtor;
    let mut fresh1 = &mut ((*(borrow_mut(&mut l)).unwrap()).head);
    *fresh1 = 0 as *mut Curl_llist_element;
    let mut fresh2 = &mut ((*(borrow_mut(&mut l)).unwrap()).tail);
    *fresh2 = 0 as *mut Curl_llist_element;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_llist_insert_next(
    mut list: * mut crate::src::lib::http2::Curl_llist,
    mut e: * mut crate::src::lib::http2::Curl_llist_element,
    mut p: * const core::ffi::c_void,
    mut ne: * mut crate::src::lib::http2::Curl_llist_element,
) {
    let mut fresh3 = &mut ((*ne).ptr);
    *fresh3 = p as *mut libc::c_void;
    if (*list).size == 0 as i32 as u64 {
        let mut fresh4 = &mut ((*list).head);
        *fresh4 = ne;
        let mut fresh5 = &mut ((*(*list).head).prev);
        *fresh5 = 0 as *mut Curl_llist_element;
        let mut fresh6 = &mut ((*(*list).head).next);
        *fresh6 = 0 as *mut Curl_llist_element;
        let mut fresh7 = &mut ((*list).tail);
        *fresh7 = ne;
    } else {
        let mut fresh8 = &mut ((*ne).next);
        *fresh8 = if !e.is_null() { (*e).next } else { (*list).head };
        let mut fresh9 = &mut ((*ne).prev);
        *fresh9 = e;
        if e.is_null() {
            let mut fresh10 = &mut ((*(*list).head).prev);
            *fresh10 = ne;
            let mut fresh11 = &mut ((*list).head);
            *fresh11 = ne;
        } else if !((*e).next).is_null() {
            let mut fresh12 = &mut ((*(*e).next).prev);
            *fresh12 = ne;
        } else {
            let mut fresh13 = &mut ((*list).tail);
            *fresh13 = ne;
        }
        if !e.is_null() {
            let mut fresh14 = &mut ((*e).next);
            *fresh14 = ne;
        }
    }
    let mut fresh15 = &mut ((*list).size);
    *fresh15 = (*fresh15).wrapping_add(1);
}
#[no_mangle]
pub unsafe extern "C" fn Curl_llist_remove(
    mut list: * mut crate::src::lib::http2::Curl_llist,
    mut e: * mut crate::src::lib::http2::Curl_llist_element,
    mut user: * mut core::ffi::c_void,
) {
    let mut ptr: * mut core::ffi::c_void = 0 as *mut libc::c_void;
    if e.is_null() || (*list).size == 0 as i32 as u64 {
        return;
    }
    if e == (*list).head {
        let mut fresh16 = &mut ((*list).head);
        *fresh16 = (*e).next;
        if ((*list).head).is_null() {
            let mut fresh17 = &mut ((*list).tail);
            *fresh17 = 0 as *mut Curl_llist_element;
        } else {
            let mut fresh18 = &mut ((*(*e).next).prev);
            *fresh18 = 0 as *mut Curl_llist_element;
        }
    } else {
        if ((*e).prev).is_null() {
            let mut fresh19 = &mut ((*list).head);
            *fresh19 = (*e).next;
        } else {
            let mut fresh20 = &mut ((*(*e).prev).next);
            *fresh20 = (*e).next;
        }
        if ((*e).next).is_null() {
            let mut fresh21 = &mut ((*list).tail);
            *fresh21 = (*e).prev;
        } else {
            let mut fresh22 = &mut ((*(*e).next).prev);
            *fresh22 = (*e).prev;
        }
    }
    ptr = (*e).ptr;
    let mut fresh23 = &mut ((*e).ptr);
    *fresh23 = 0 as *mut libc::c_void;
    let mut fresh24 = &mut ((*e).prev);
    *fresh24 = 0 as *mut Curl_llist_element;
    let mut fresh25 = &mut ((*e).next);
    *fresh25 = 0 as *mut Curl_llist_element;
    let mut fresh26 = &mut ((*list).size);
    *fresh26 = (*fresh26).wrapping_sub(1);
    if ((*list).dtor).is_some() {
        ((*list).dtor).expect("non-null function pointer")(user, ptr);
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_llist_destroy(
    mut list: * mut crate::src::lib::http2::Curl_llist,
    mut user: * mut core::ffi::c_void,
) {
    if !list.is_null() {
        while (*list).size > 0 as i32 as u64 {
            Curl_llist_remove(list, (*list).tail, user);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_llist_count(mut list: * mut crate::src::lib::http2::Curl_llist) -> u64 {
    return (*list).size;
}
use crate::laertes_rt::*;
