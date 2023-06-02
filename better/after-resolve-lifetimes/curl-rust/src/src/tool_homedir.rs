use ::libc;
extern "C" {
    
    
    fn geteuid() -> u32;
    fn strdup(_: * const i8) -> * mut i8;
    fn close(__fd: i32) -> i32;
    fn free(__ptr: * mut core::ffi::c_void);
    fn getpwuid(__uid: u32) -> * mut crate::src::lib::curl_ntlm_wb::passwd;
    fn open(__file: * const i8, __oflag: i32, _: ...) -> i32;
    
}
pub use crate::src::lib::escape::curl_free;
pub use crate::src::lib::getenv::curl_getenv;
pub use crate::src::lib::mprintf::curl_maprintf;
pub type __uid_t = u32;
pub type __gid_t = u32;
// #[derive(Copy, Clone)]

pub type passwd = crate::src::lib::curl_ntlm_wb::passwd;
unsafe extern "C" fn GetEnv(mut variable: * const i8) -> * mut i8 {
    let mut dupe: * mut i8 = 0 as *mut i8;
    let mut env: * mut i8 = 0 as *mut i8;
    env = curl_getenv(variable);
    if env.is_null() {
        return 0 as *mut i8;
    }
    dupe = strdup(env);
    curl_free(env as *mut libc::c_void);
    return dupe;
}
#[no_mangle]
pub unsafe extern "C" fn homedir(mut fname: * const i8) -> * mut i8 {
    let mut home: * mut i8 = 0 as *mut i8;
    home = GetEnv(b"CURL_HOME\0" as *const u8 as *const i8);
    if !home.is_null() {
        return home;
    }
    if !fname.is_null() {
        home = GetEnv(b"XDG_CONFIG_HOME\0" as *const u8 as *const i8);
        if !home.is_null() {
            let mut c: * mut i8 = curl_maprintf(
                b"%s/%s\0" as *const u8 as *const i8,
                home,
                fname,
            );
            if !c.is_null() {
                let mut fd: i32 = open(c, 0 as i32);
                curl_free(c as *mut libc::c_void);
                if fd >= 0 as i32 {
                    close(fd);
                    return home;
                }
            }
            free(home as *mut libc::c_void);
        }
    }
    home = GetEnv(b"HOME\0" as *const u8 as *const i8);
    if !home.is_null() {
        return home;
    }
    let mut pw: * mut crate::src::lib::curl_ntlm_wb::passwd = getpwuid(geteuid());
    if !pw.is_null() {
        home = (*pw).pw_dir;
        if !home.is_null() && *home.offset(0 as i32 as isize) as i32 != 0
        {
            home = strdup(home);
        } else {
            home = 0 as *mut i8;
        }
    }
    return home;
}
use crate::laertes_rt::*;
