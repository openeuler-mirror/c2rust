use :: libc;
extern "C" {}
pub use crate::src::lib::easy::Curl_ccalloc;
pub use crate::src::lib::easy::Curl_cfree;
pub type __time_t = i64;
pub type time_t = i64;
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
    pub filetype: u32,
    pub time: i64,
    pub perm: u32,
    pub uid: i32,
    pub gid: i32,
    pub size: i64,
    pub hardlinks: i64,
    pub strings: crate::src::lib::fileinfo::C2RustUnnamed,
    pub flags: u32,
    pub b_data: *mut i8,
    pub b_size: u64,
    pub b_used: u64,
}
impl curl_fileinfo {
    pub const fn new() -> Self {
        curl_fileinfo {
            filename: (0 as *mut i8),
            filetype: 0,
            time: 0,
            perm: 0,
            uid: 0,
            gid: 0,
            size: 0,
            hardlinks: 0,
            strings: crate::src::lib::fileinfo::C2RustUnnamed::new(),
            flags: 0,
            b_data: (0 as *mut i8),
            b_size: 0,
            b_used: 0,
        }
    }
}
impl std::default::Default for curl_fileinfo {
    fn default() -> Self {
        curl_fileinfo::new()
    }
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
impl C2RustUnnamed {
    pub const fn new() -> Self {
        C2RustUnnamed {
            time: (0 as *mut i8),
            perm: (0 as *mut i8),
            user: (0 as *mut i8),
            group: (0 as *mut i8),
            target: (0 as *mut i8),
        }
    }
}
impl std::default::Default for C2RustUnnamed {
    fn default() -> Self {
        C2RustUnnamed::new()
    }
}
pub type curl_free_callback<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>) -> ()>;
pub type curl_calloc_callback<'a1> =
    Option<unsafe extern "C" fn(_: u64, _: u64) -> Option<&'a1 mut core::ffi::c_void>>;
pub type Curl_llist_element = crate::src::lib::http2::Curl_llist_element;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct fileinfo {
    pub info: crate::src::lib::fileinfo::curl_fileinfo,
    pub list: crate::src::lib::http2::Curl_llist_element,
}
impl fileinfo {
    pub const fn new() -> Self {
        fileinfo {
            info: crate::src::lib::fileinfo::curl_fileinfo::new(),
            list: crate::src::lib::http2::Curl_llist_element::new(),
        }
    }
}
impl std::default::Default for fileinfo {
    fn default() -> Self {
        fileinfo::new()
    }
}
#[no_mangle]
pub extern "C" fn Curl_fileinfo_alloc() -> *mut crate::src::lib::fileinfo::fileinfo {
    return (unsafe { Curl_ccalloc.expect("non-null function pointer")(
        1 as i32 as size_t,
        ::std::mem::size_of::<fileinfo>() as u64,
    ) }) as *mut fileinfo;
}
#[no_mangle]
pub extern "C" fn Curl_fileinfo_cleanup(mut finfo: *mut crate::src::lib::fileinfo::fileinfo) {
    if finfo.is_null() {
        return;
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")((*finfo).info.b_data as *mut libc::c_void) });
    let mut fresh0 = unsafe { &mut ((*finfo).info.b_data) };
    *fresh0 = 0 as *mut i8;
    (unsafe { Curl_cfree.expect("non-null function pointer")(finfo as *mut libc::c_void) });
}

