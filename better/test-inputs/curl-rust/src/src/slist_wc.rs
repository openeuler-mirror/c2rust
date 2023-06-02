use ::libc;
extern "C" {
    fn curl_slist_append(_: *mut curl_slist, _: *const libc::c_char) -> *mut curl_slist;
    fn curl_slist_free_all(_: *mut curl_slist);
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_slist {
    pub data: *mut libc::c_char,
    pub next: *mut curl_slist,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct slist_wc {
    pub first: *mut curl_slist,
    pub last: *mut curl_slist,
}
#[no_mangle]
pub unsafe extern "C" fn slist_wc_append(
    mut list: *mut slist_wc,
    mut data: *const libc::c_char,
) -> *mut slist_wc {
    let mut new_item: *mut curl_slist = curl_slist_append(0 as *mut curl_slist, data);
    if new_item.is_null() {
        return 0 as *mut slist_wc;
    }
    if list.is_null() {
        list = malloc(::std::mem::size_of::<slist_wc>() as libc::c_ulong)
            as *mut slist_wc;
        if list.is_null() {
            curl_slist_free_all(new_item);
            return 0 as *mut slist_wc;
        }
        let ref mut fresh0 = (*list).first;
        *fresh0 = new_item;
        let ref mut fresh1 = (*list).last;
        *fresh1 = new_item;
        return list;
    }
    let ref mut fresh2 = (*(*list).last).next;
    *fresh2 = new_item;
    let ref mut fresh3 = (*list).last;
    *fresh3 = (*(*list).last).next;
    return list;
}
#[no_mangle]
pub unsafe extern "C" fn slist_wc_free_all(mut list: *mut slist_wc) {
    if list.is_null() {
        return;
    }
    curl_slist_free_all((*list).first);
    free(list as *mut libc::c_void);
}
