use ::libc;
extern "C" {
    
    
    fn malloc(_: u64) -> * mut core::ffi::c_void;
    fn free(__ptr: * mut core::ffi::c_void);
}
pub use crate::src::lib::slist::curl_slist_append;
pub use crate::src::lib::slist::curl_slist_free_all;
// #[derive(Copy, Clone)]

pub type curl_slist = crate::src::lib::http2::curl_slist;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct slist_wc {
    pub first: * mut crate::src::lib::http2::curl_slist,
    pub last: * mut crate::src::lib::http2::curl_slist,
}
impl slist_wc {
    pub const fn new() -> Self {
        slist_wc {
        first: (0 as * mut crate::src::lib::http2::curl_slist),
        last: (0 as * mut crate::src::lib::http2::curl_slist)
        }
    }
}

impl std::default::Default for slist_wc {
    fn default() -> Self { slist_wc::new() }
}

#[no_mangle]
pub unsafe extern "C" fn slist_wc_append(
    mut list: * mut crate::src::src::slist_wc::slist_wc,
    mut data: * const i8,
) -> * mut crate::src::src::slist_wc::slist_wc {
    let mut new_item: * mut crate::src::lib::http2::curl_slist = curl_slist_append(0 as *mut curl_slist, data);
    if new_item.is_null() {
        return 0 as *mut slist_wc;
    }
    if list.is_null() {
        list = malloc(::std::mem::size_of::<slist_wc>() as u64)
            as *mut slist_wc;
        if list.is_null() {
            curl_slist_free_all(new_item);
            return 0 as *mut slist_wc;
        }
        let mut fresh0 = &mut ((*list).first);
        *fresh0 = new_item;
        let mut fresh1 = &mut ((*list).last);
        *fresh1 = new_item;
        return list;
    }
    let mut fresh2 = &mut ((*(*list).last).next);
    *fresh2 = new_item;
    let mut fresh3 = &mut ((*list).last);
    *fresh3 = (*(*list).last).next;
    return list;
}
#[no_mangle]
pub unsafe extern "C" fn slist_wc_free_all(mut list: * mut crate::src::src::slist_wc::slist_wc) {
    if list.is_null() {
        return;
    }
    curl_slist_free_all((*list).first);
    free(list as *mut libc::c_void);
}
use crate::laertes_rt::*;
