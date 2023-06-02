use ::libc;
extern "C" {
    fn curl_getenv(variable: *const libc::c_char) -> *mut libc::c_char;
    fn curl_free(p: *mut libc::c_void);
    fn geteuid() -> __uid_t;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn free(__ptr: *mut libc::c_void);
    fn getpwuid(__uid: __uid_t) -> *mut passwd;
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...) -> libc::c_int;
    fn curl_maprintf(format: *const libc::c_char, _: ...) -> *mut libc::c_char;
}
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct passwd {
    pub pw_name: *mut libc::c_char,
    pub pw_passwd: *mut libc::c_char,
    pub pw_uid: __uid_t,
    pub pw_gid: __gid_t,
    pub pw_gecos: *mut libc::c_char,
    pub pw_dir: *mut libc::c_char,
    pub pw_shell: *mut libc::c_char,
}
unsafe extern "C" fn GetEnv(mut variable: *const libc::c_char) -> *mut libc::c_char {
    let mut dupe: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut env: *mut libc::c_char = 0 as *mut libc::c_char;
    env = curl_getenv(variable);
    if env.is_null() {
        return 0 as *mut libc::c_char;
    }
    dupe = strdup(env);
    curl_free(env as *mut libc::c_void);
    return dupe;
}
#[no_mangle]
pub unsafe extern "C" fn homedir(mut fname: *const libc::c_char) -> *mut libc::c_char {
    let mut home: *mut libc::c_char = 0 as *mut libc::c_char;
    home = GetEnv(b"CURL_HOME\0" as *const u8 as *const libc::c_char);
    if !home.is_null() {
        return home;
    }
    if !fname.is_null() {
        home = GetEnv(b"XDG_CONFIG_HOME\0" as *const u8 as *const libc::c_char);
        if !home.is_null() {
            let mut c: *mut libc::c_char = curl_maprintf(
                b"%s/%s\0" as *const u8 as *const libc::c_char,
                home,
                fname,
            );
            if !c.is_null() {
                let mut fd: libc::c_int = open(c, 0 as libc::c_int);
                curl_free(c as *mut libc::c_void);
                if fd >= 0 as libc::c_int {
                    close(fd);
                    return home;
                }
            }
            free(home as *mut libc::c_void);
        }
    }
    home = GetEnv(b"HOME\0" as *const u8 as *const libc::c_char);
    if !home.is_null() {
        return home;
    }
    let mut pw: *mut passwd = getpwuid(geteuid());
    if !pw.is_null() {
        home = (*pw).pw_dir;
        if !home.is_null() && *home.offset(0 as libc::c_int as isize) as libc::c_int != 0
        {
            home = strdup(home);
        } else {
            home = 0 as *mut libc::c_char;
        }
    }
    return home;
}
