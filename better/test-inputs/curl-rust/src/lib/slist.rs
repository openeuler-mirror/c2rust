use ::libc;
extern "C" {
    static mut Curl_cmalloc: curl_malloc_callback;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_cstrdup: curl_strdup_callback;
}
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_slist {
    pub data: *mut libc::c_char,
    pub next: *mut curl_slist,
}
pub type curl_malloc_callback = Option::<
    unsafe extern "C" fn(size_t) -> *mut libc::c_void,
>;
pub type curl_free_callback = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type curl_strdup_callback = Option::<
    unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
>;
unsafe extern "C" fn slist_get_last(mut list: *mut curl_slist) -> *mut curl_slist {
    let mut item: *mut curl_slist = 0 as *mut curl_slist;
    if list.is_null() {
        return 0 as *mut curl_slist;
    }
    item = list;
    while !((*item).next).is_null() {
        item = (*item).next;
    }
    return item;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_slist_append_nodup(
    mut list: *mut curl_slist,
    mut data: *mut libc::c_char,
) -> *mut curl_slist {
    let mut last: *mut curl_slist = 0 as *mut curl_slist;
    let mut new_item: *mut curl_slist = 0 as *mut curl_slist;
    new_item = Curl_cmalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<curl_slist>() as libc::c_ulong) as *mut curl_slist;
    if new_item.is_null() {
        return 0 as *mut curl_slist;
    }
    let ref mut fresh0 = (*new_item).next;
    *fresh0 = 0 as *mut curl_slist;
    let ref mut fresh1 = (*new_item).data;
    *fresh1 = data;
    if list.is_null() {
        return new_item;
    }
    last = slist_get_last(list);
    let ref mut fresh2 = (*last).next;
    *fresh2 = new_item;
    return list;
}
#[no_mangle]
pub unsafe extern "C" fn curl_slist_append(
    mut list: *mut curl_slist,
    mut data: *const libc::c_char,
) -> *mut curl_slist {
    let mut dupdata: *mut libc::c_char = Curl_cstrdup
        .expect("non-null function pointer")(data);
    if dupdata.is_null() {
        return 0 as *mut curl_slist;
    }
    list = Curl_slist_append_nodup(list, dupdata);
    if list.is_null() {
        Curl_cfree.expect("non-null function pointer")(dupdata as *mut libc::c_void);
    }
    return list;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_slist_duplicate(
    mut inlist: *mut curl_slist,
) -> *mut curl_slist {
    let mut outlist: *mut curl_slist = 0 as *mut curl_slist;
    let mut tmp: *mut curl_slist = 0 as *mut curl_slist;
    while !inlist.is_null() {
        tmp = curl_slist_append(outlist, (*inlist).data);
        if tmp.is_null() {
            curl_slist_free_all(outlist);
            return 0 as *mut curl_slist;
        }
        outlist = tmp;
        inlist = (*inlist).next;
    }
    return outlist;
}
#[no_mangle]
pub unsafe extern "C" fn curl_slist_free_all(mut list: *mut curl_slist) {
    let mut next: *mut curl_slist = 0 as *mut curl_slist;
    let mut item: *mut curl_slist = 0 as *mut curl_slist;
    if list.is_null() {
        return;
    }
    item = list;
    loop {
        next = (*item).next;
        Curl_cfree
            .expect("non-null function pointer")((*item).data as *mut libc::c_void);
        let ref mut fresh3 = (*item).data;
        *fresh3 = 0 as *mut libc::c_char;
        Curl_cfree.expect("non-null function pointer")(item as *mut libc::c_void);
        item = next;
        if next.is_null() {
            break;
        }
    };
}
