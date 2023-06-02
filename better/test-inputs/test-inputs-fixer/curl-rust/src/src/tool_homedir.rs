use :: libc;
extern "C" {
    fn curl_getenv(variable: *const i8) -> *mut i8;
    fn curl_free(p: *mut libc::c_void);
    fn geteuid() -> __uid_t;
    fn strdup(_: *const i8) -> *mut i8;
    fn close(__fd: i32) -> i32;
    fn free(__ptr: *mut libc::c_void);
    fn getpwuid(__uid: __uid_t) -> *mut passwd;
    fn open(__file: *const i8, __oflag: i32, _: ...) -> i32;
    fn curl_maprintf(format: *const i8, _: ...) -> *mut i8;
}
pub type __uid_t = u32;
pub type __gid_t = u32;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct passwd {
    pub pw_name: *mut i8,
    pub pw_passwd: *mut i8,
    pub pw_uid: __uid_t,
    pub pw_gid: __gid_t,
    pub pw_gecos: *mut i8,
    pub pw_dir: *mut i8,
    pub pw_shell: *mut i8,
}
extern "C" fn GetEnv(mut variable: *const i8) -> *mut i8 {
    let mut dupe: *mut i8 = 0 as *mut i8;
    let mut env: *mut i8 = 0 as *mut i8;
    env = unsafe { curl_getenv(variable) };
    if env.is_null() {
        return 0 as *mut i8;
    }
    dupe = unsafe { strdup(env) };
    (unsafe { curl_free(env as *mut libc::c_void) });
    return dupe;
}
#[no_mangle]
pub extern "C" fn homedir(mut fname: *const i8) -> *mut i8 {
    let mut home: *mut i8 = 0 as *mut i8;
    home = GetEnv(b"CURL_HOME\0" as *const u8 as *const i8);
    if !home.is_null() {
        return home;
    }
    if !fname.is_null() {
        home = GetEnv(b"XDG_CONFIG_HOME\0" as *const u8 as *const i8);
        if !home.is_null() {
            let mut c: *mut i8 = unsafe { curl_maprintf(b"%s/%s\0" as *const u8 as *const i8, home, fname) };
            if !c.is_null() {
                let mut fd: i32 = unsafe { open(c, 0 as i32) };
                (unsafe { curl_free(c as *mut libc::c_void) });
                if fd >= 0 as i32 {
                    (unsafe { close(fd) });
                    return home;
                }
            }
            (unsafe { free(home as *mut libc::c_void) });
        }
    }
    home = GetEnv(b"HOME\0" as *const u8 as *const i8);
    if !home.is_null() {
        return home;
    }
    let mut pw: *mut passwd = unsafe { getpwuid(geteuid()) };
    if !pw.is_null() {
        home = unsafe { (*pw).pw_dir };
        if !home.is_null() && (unsafe { *home.offset(0 as i32 as isize) }) as i32 != 0 {
            home = unsafe { strdup(home) };
        } else {
            home = 0 as *mut i8;
        }
    }
    return home;
}
