use :: libc;
extern "C" {
    fn curl_slist_append(_: *mut curl_slist, _: *const i8) -> *mut curl_slist;
    fn curl_slist_free_all(_: *mut curl_slist);
    fn malloc(_: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_slist {
    pub data: *mut i8,
    pub next: *mut curl_slist,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct slist_wc {
    pub first: *mut curl_slist,
    pub last: *mut curl_slist,
}
#[no_mangle]
pub extern "C" fn slist_wc_append(mut list: *mut slist_wc, mut data: *const i8) -> *mut slist_wc {
    let mut new_item: *mut curl_slist = unsafe { curl_slist_append(0 as *mut curl_slist, data) };
    if new_item.is_null() {
        return 0 as *mut slist_wc;
    }
    if list.is_null() {
        list = (unsafe { malloc(::std::mem::size_of::<slist_wc>() as u64) }) as *mut slist_wc;
        if list.is_null() {
            (unsafe { curl_slist_free_all(new_item) });
            return 0 as *mut slist_wc;
        }
        let fresh0 = unsafe { &mut ((*list).first) };
        *fresh0 = new_item;
        let fresh1 = unsafe { &mut ((*list).last) };
        *fresh1 = new_item;
        return list;
    }
    let fresh2 = unsafe { &mut ((*(*list).last).next) };
    *fresh2 = new_item;
    let fresh3 = unsafe { &mut ((*list).last) };
    *fresh3 = unsafe { (*(*list).last).next };
    return list;
}
#[no_mangle]
pub extern "C" fn slist_wc_free_all(mut list: *mut slist_wc) {
    if list.is_null() {
        return;
    }
    (unsafe { curl_slist_free_all((*list).first) });
    (unsafe { free(list as *mut libc::c_void) });
}
