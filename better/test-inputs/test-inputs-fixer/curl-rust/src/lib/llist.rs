use :: libc;
pub type size_t = u64;
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
#[no_mangle]
pub extern "C" fn Curl_llist_init(mut l: *mut Curl_llist, mut dtor: Curl_llist_dtor) {
    (unsafe { (*l).size = 0 as i32 as size_t });
    let fresh0 = unsafe { &mut ((*l).dtor) };
    *fresh0 = dtor;
    let fresh1 = unsafe { &mut ((*l).head) };
    *fresh1 = 0 as *mut Curl_llist_element;
    let fresh2 = unsafe { &mut ((*l).tail) };
    *fresh2 = 0 as *mut Curl_llist_element;
}
#[no_mangle]
pub extern "C" fn Curl_llist_insert_next(
    mut list: *mut Curl_llist,
    mut e: *mut Curl_llist_element,
    mut p: *const libc::c_void,
    mut ne: *mut Curl_llist_element,
) {
    let fresh3 = unsafe { &mut ((*ne).ptr) };
    *fresh3 = p as *mut libc::c_void;
    if (unsafe { (*list).size }) == 0 as i32 as u64 {
        let fresh4 = unsafe { &mut ((*list).head) };
        *fresh4 = ne;
        let fresh5 = unsafe { &mut ((*(*list).head).prev) };
        *fresh5 = 0 as *mut Curl_llist_element;
        let fresh6 = unsafe { &mut ((*(*list).head).next) };
        *fresh6 = 0 as *mut Curl_llist_element;
        let fresh7 = unsafe { &mut ((*list).tail) };
        *fresh7 = ne;
    } else {
        let fresh8 = unsafe { &mut ((*ne).next) };
        *fresh8 = if !e.is_null() {
            unsafe { (*e).next }
        } else {
            unsafe { (*list).head }
        };
        let fresh9 = unsafe { &mut ((*ne).prev) };
        *fresh9 = e;
        if e.is_null() {
            let fresh10 = unsafe { &mut ((*(*list).head).prev) };
            *fresh10 = ne;
            let fresh11 = unsafe { &mut ((*list).head) };
            *fresh11 = ne;
        } else if !(unsafe { (*e).next }).is_null() {
            let fresh12 = unsafe { &mut ((*(*e).next).prev) };
            *fresh12 = ne;
        } else {
            let fresh13 = unsafe { &mut ((*list).tail) };
            *fresh13 = ne;
        }
        if !e.is_null() {
            let fresh14 = unsafe { &mut ((*e).next) };
            *fresh14 = ne;
        }
    }
    let fresh15 = unsafe { &mut ((*list).size) };
    *fresh15 = (*fresh15).wrapping_add(1);
}
#[no_mangle]
pub extern "C" fn Curl_llist_remove(
    mut list: *mut Curl_llist,
    mut e: *mut Curl_llist_element,
    mut user: *mut libc::c_void,
) {
    let mut ptr: *mut libc::c_void = 0 as *mut libc::c_void;
    if e.is_null() || (unsafe { (*list).size }) == 0 as i32 as u64 {
        return;
    }
    if e == (unsafe { (*list).head }) {
        let fresh16 = unsafe { &mut ((*list).head) };
        *fresh16 = unsafe { (*e).next };
        if (unsafe { (*list).head }).is_null() {
            let fresh17 = unsafe { &mut ((*list).tail) };
            *fresh17 = 0 as *mut Curl_llist_element;
        } else {
            let fresh18 = unsafe { &mut ((*(*e).next).prev) };
            *fresh18 = 0 as *mut Curl_llist_element;
        }
    } else {
        if (unsafe { (*e).prev }).is_null() {
            let fresh19 = unsafe { &mut ((*list).head) };
            *fresh19 = unsafe { (*e).next };
        } else {
            let fresh20 = unsafe { &mut ((*(*e).prev).next) };
            *fresh20 = unsafe { (*e).next };
        }
        if (unsafe { (*e).next }).is_null() {
            let fresh21 = unsafe { &mut ((*list).tail) };
            *fresh21 = unsafe { (*e).prev };
        } else {
            let fresh22 = unsafe { &mut ((*(*e).next).prev) };
            *fresh22 = unsafe { (*e).prev };
        }
    }
    ptr = unsafe { (*e).ptr };
    let fresh23 = unsafe { &mut ((*e).ptr) };
    *fresh23 = 0 as *mut libc::c_void;
    let fresh24 = unsafe { &mut ((*e).prev) };
    *fresh24 = 0 as *mut Curl_llist_element;
    let fresh25 = unsafe { &mut ((*e).next) };
    *fresh25 = 0 as *mut Curl_llist_element;
    let fresh26 = unsafe { &mut ((*list).size) };
    *fresh26 = (*fresh26).wrapping_sub(1);
    if unsafe { ((*list).dtor).is_some() } {
        (unsafe { ((*list).dtor).expect("non-null function pointer")(user, ptr) });
    }
}
#[no_mangle]
pub extern "C" fn Curl_llist_destroy(mut list: *mut Curl_llist, mut user: *mut libc::c_void) {
    if !list.is_null() {
        while (unsafe { (*list).size }) > 0 as i32 as u64 {
            Curl_llist_remove(list, unsafe { (*list).tail }, user);
        }
    }
}
#[no_mangle]
pub extern "C" fn Curl_llist_count(mut list: *mut Curl_llist) -> size_t {
    return unsafe { (*list).size };
}
