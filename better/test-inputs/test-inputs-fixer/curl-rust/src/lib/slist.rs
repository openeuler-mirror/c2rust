use :: libc;
extern "C" {
    static mut Curl_cmalloc: curl_malloc_callback;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_cstrdup: curl_strdup_callback;
}
pub type size_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_slist {
    pub data: *mut i8,
    pub next: *mut curl_slist,
}
pub type curl_malloc_callback = Option<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
pub type curl_free_callback = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type curl_strdup_callback = Option<unsafe extern "C" fn(*const i8) -> *mut i8>;
extern "C" fn slist_get_last(mut list: *mut curl_slist) -> *mut curl_slist {
    let mut item: *mut curl_slist = 0 as *mut curl_slist;
    if list.is_null() {
        return 0 as *mut curl_slist;
    }
    item = list;
    while !(unsafe { (*item).next }).is_null() {
        item = unsafe { (*item).next };
    }
    return item;
}
#[no_mangle]
pub extern "C" fn Curl_slist_append_nodup(
    mut list: *mut curl_slist,
    mut data: *mut i8,
) -> *mut curl_slist {
    let mut last: *mut curl_slist = 0 as *mut curl_slist;
    let mut new_item: *mut curl_slist = 0 as *mut curl_slist;
    new_item = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<curl_slist>() as u64
    ) }) as *mut curl_slist;
    if new_item.is_null() {
        return 0 as *mut curl_slist;
    }
    let fresh0 = unsafe { &mut ((*new_item).next) };
    *fresh0 = 0 as *mut curl_slist;
    let fresh1 = unsafe { &mut ((*new_item).data) };
    *fresh1 = data;
    if list.is_null() {
        return new_item;
    }
    last = slist_get_last(list);
    let fresh2 = unsafe { &mut ((*last).next) };
    *fresh2 = new_item;
    return list;
}
#[no_mangle]
pub extern "C" fn curl_slist_append(
    mut list: *mut curl_slist,
    mut data: *const i8,
) -> *mut curl_slist {
    let mut dupdata: *mut i8 = unsafe { Curl_cstrdup.expect("non-null function pointer")(data) };
    if dupdata.is_null() {
        return 0 as *mut curl_slist;
    }
    list = Curl_slist_append_nodup(list, dupdata);
    if list.is_null() {
        (unsafe { Curl_cfree.expect("non-null function pointer")(dupdata as *mut libc::c_void) });
    }
    return list;
}
#[no_mangle]
pub extern "C" fn Curl_slist_duplicate(mut inlist: *mut curl_slist) -> *mut curl_slist {
    let mut outlist: *mut curl_slist = 0 as *mut curl_slist;
    let mut tmp: *mut curl_slist = 0 as *mut curl_slist;
    while !inlist.is_null() {
        tmp = curl_slist_append(outlist, unsafe { (*inlist).data });
        if tmp.is_null() {
            curl_slist_free_all(outlist);
            return 0 as *mut curl_slist;
        }
        outlist = tmp;
        inlist = unsafe { (*inlist).next };
    }
    return outlist;
}
#[no_mangle]
pub extern "C" fn curl_slist_free_all(mut list: *mut curl_slist) {
    let mut next: *mut curl_slist = 0 as *mut curl_slist;
    let mut item: *mut curl_slist = 0 as *mut curl_slist;
    if list.is_null() {
        return;
    }
    item = list;
    loop {
        next = unsafe { (*item).next };
        (unsafe { Curl_cfree.expect("non-null function pointer")((*item).data as *mut libc::c_void) });
        let fresh3 = unsafe { &mut ((*item).data) };
        *fresh3 = 0 as *mut i8;
        (unsafe { Curl_cfree.expect("non-null function pointer")(item as *mut libc::c_void) });
        item = next;
        if next.is_null() {
            break;
        }
    }
}
