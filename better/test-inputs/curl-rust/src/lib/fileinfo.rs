use ::libc;
extern "C" {
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_ccalloc: curl_calloc_callback;
}
pub type __time_t = libc::c_long;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type curl_off_t = libc::c_long;
pub type curlfiletype = libc::c_uint;
pub const CURLFILETYPE_UNKNOWN: curlfiletype = 8;
pub const CURLFILETYPE_DOOR: curlfiletype = 7;
pub const CURLFILETYPE_SOCKET: curlfiletype = 6;
pub const CURLFILETYPE_NAMEDPIPE: curlfiletype = 5;
pub const CURLFILETYPE_DEVICE_CHAR: curlfiletype = 4;
pub const CURLFILETYPE_DEVICE_BLOCK: curlfiletype = 3;
pub const CURLFILETYPE_SYMLINK: curlfiletype = 2;
pub const CURLFILETYPE_DIRECTORY: curlfiletype = 1;
pub const CURLFILETYPE_FILE: curlfiletype = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_fileinfo {
    pub filename: *mut libc::c_char,
    pub filetype: curlfiletype,
    pub time: time_t,
    pub perm: libc::c_uint,
    pub uid: libc::c_int,
    pub gid: libc::c_int,
    pub size: curl_off_t,
    pub hardlinks: libc::c_long,
    pub strings: C2RustUnnamed,
    pub flags: libc::c_uint,
    pub b_data: *mut libc::c_char,
    pub b_size: size_t,
    pub b_used: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub time: *mut libc::c_char,
    pub perm: *mut libc::c_char,
    pub user: *mut libc::c_char,
    pub group: *mut libc::c_char,
    pub target: *mut libc::c_char,
}
pub type curl_free_callback = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type curl_calloc_callback = Option::<
    unsafe extern "C" fn(size_t, size_t) -> *mut libc::c_void,
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
pub struct fileinfo {
    pub info: curl_fileinfo,
    pub list: Curl_llist_element,
}
#[no_mangle]
pub unsafe extern "C" fn Curl_fileinfo_alloc() -> *mut fileinfo {
    return Curl_ccalloc
        .expect(
            "non-null function pointer",
        )(1 as libc::c_int as size_t, ::std::mem::size_of::<fileinfo>() as libc::c_ulong)
        as *mut fileinfo;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_fileinfo_cleanup(mut finfo: *mut fileinfo) {
    if finfo.is_null() {
        return;
    }
    Curl_cfree
        .expect("non-null function pointer")((*finfo).info.b_data as *mut libc::c_void);
    let ref mut fresh0 = (*finfo).info.b_data;
    *fresh0 = 0 as *mut libc::c_char;
    Curl_cfree.expect("non-null function pointer")(finfo as *mut libc::c_void);
}
