use :: libc;
extern "C" {
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_ccalloc: curl_calloc_callback;
}
pub type __time_t = i64;
pub type time_t = __time_t;
pub type size_t = u64;
pub type curl_off_t = i64;
pub type curlfiletype = u32;
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
    pub filename: *mut i8,
    pub filetype: curlfiletype,
    pub time: time_t,
    pub perm: u32,
    pub uid: i32,
    pub gid: i32,
    pub size: curl_off_t,
    pub hardlinks: i64,
    pub strings: C2RustUnnamed,
    pub flags: u32,
    pub b_data: *mut i8,
    pub b_size: size_t,
    pub b_used: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub time: *mut i8,
    pub perm: *mut i8,
    pub user: *mut i8,
    pub group: *mut i8,
    pub target: *mut i8,
}
pub type curl_free_callback = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type curl_calloc_callback = Option<unsafe extern "C" fn(size_t, size_t) -> *mut libc::c_void>;
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
pub extern "C" fn Curl_fileinfo_alloc() -> *mut fileinfo {
    return (unsafe { Curl_ccalloc.expect("non-null function pointer")(
        1 as i32 as size_t,
        ::std::mem::size_of::<fileinfo>() as u64,
    ) }) as *mut fileinfo;
}
#[no_mangle]
pub extern "C" fn Curl_fileinfo_cleanup(mut finfo: *mut fileinfo) {
    if finfo.is_null() {
        return;
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")((*finfo).info.b_data as *mut libc::c_void) });
    let fresh0 = unsafe { &mut ((*finfo).info.b_data) };
    *fresh0 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(finfo as *mut libc::c_void) });
}
