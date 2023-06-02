use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn curl_getenv(variable: *const i8) -> *mut i8;
    fn fclose(__stream: *mut FILE) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut FILE;
    fn fgets(__s: *mut i8, __n: i32, __stream: *mut FILE) -> *mut i8;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strtok_r(__s: *mut i8, __delim: *const i8, __save_ptr: *mut *mut i8) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn geteuid() -> __uid_t;
    fn getpwuid_r(
        __uid: __uid_t,
        __resultbuf: *mut passwd,
        __buffer: *mut i8,
        __buflen: size_t,
        __result: *mut *mut passwd,
    ) -> i32;
    fn Curl_strcasecompare(first: *const i8, second: *const i8) -> i32;
    fn curl_maprintf(format: *const i8, _: ...) -> *mut i8;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_cstrdup: curl_strdup_callback;
}
pub type __uid_t = u32;
pub type __gid_t = u32;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type size_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: i32,
    pub _IO_read_ptr: *mut i8,
    pub _IO_read_end: *mut i8,
    pub _IO_read_base: *mut i8,
    pub _IO_write_base: *mut i8,
    pub _IO_write_ptr: *mut i8,
    pub _IO_write_end: *mut i8,
    pub _IO_buf_base: *mut i8,
    pub _IO_buf_end: *mut i8,
    pub _IO_save_base: *mut i8,
    pub _IO_backup_base: *mut i8,
    pub _IO_save_end: *mut i8,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: i32,
    pub _flags2: i32,
    pub _old_offset: __off_t,
    pub _cur_column: u16,
    pub _vtable_offset: i8,
    pub _shortbuf: [i8; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: i32,
    pub _unused2: [i8; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type curl_free_callback = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type curl_strdup_callback = Option<unsafe extern "C" fn(*const i8) -> *mut i8>;
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
pub type host_lookup_state = u32;
pub const MACDEF: host_lookup_state = 3;
pub const HOSTVALID: host_lookup_state = 2;
pub const HOSTFOUND: host_lookup_state = 1;
pub const NOTHING: host_lookup_state = 0;
extern "C" fn parsenetrc(
    mut host: *const i8,
    mut loginp: *mut *mut i8,
    mut passwordp: *mut *mut i8,
    mut login_changed: *mut bool,
    mut password_changed: *mut bool,
    mut netrcfile: *mut i8,
) -> i32 {
    let mut file: *mut FILE = 0 as *mut FILE;
    let mut retcode: i32 = 1 as i32;
    let mut login: *mut i8 = unsafe { *loginp };
    let mut password: *mut i8 = unsafe { *passwordp };
    let mut specific_login: bool = !login.is_null() && (unsafe { *login }) as i32 != 0 as i32;
    let mut login_alloc: bool = 0 as i32 != 0;
    let mut password_alloc: bool = 0 as i32 != 0;
    let mut state: host_lookup_state = NOTHING;
    let mut state_login: i8 = 0 as i32 as i8;
    let mut state_password: i8 = 0 as i32 as i8;
    let mut state_our_login: i32 = 0 as i32;
    file = unsafe { fopen(netrcfile, b"r\0" as *const u8 as *const i8) };
    if !file.is_null() {
        let mut tok: *mut i8 = 0 as *mut i8;
        let mut tok_buf: *mut i8 = 0 as *mut i8;
        let mut done: bool = 0 as i32 != 0;
        let mut netrcbuffer: [i8; 4096] = [0; 4096];
        let mut netrcbuffsize: i32 = ::std::mem::size_of::<[i8; 4096]>() as u64 as i32;
        's_69: while !done && !(unsafe { fgets(netrcbuffer.as_mut_ptr(), netrcbuffsize, file) }).is_null() {
            if state as u32 == MACDEF as i32 as u32 {
                if !(netrcbuffer[0 as i32 as usize] as i32 == '\n' as i32
                    || netrcbuffer[0 as i32 as usize] as i32 == '\r' as i32)
                {
                    continue;
                }
                state = NOTHING;
            }
            tok = unsafe { strtok_r(
                netrcbuffer.as_mut_ptr(),
                b" \t\n\0" as *const u8 as *const i8,
                &mut tok_buf,
            ) };
            if !tok.is_null() && (unsafe { *tok }) as i32 == '#' as i32 {
                continue;
            }
            while !tok.is_null() {
                if !login.is_null()
                    && (unsafe { *login }) as i32 != 0
                    && (!password.is_null() && (unsafe { *password }) as i32 != 0)
                {
                    done = 1 as i32 != 0;
                    break;
                } else {
                    match state as u32 {
                        0 => {
                            if (unsafe { Curl_strcasecompare(b"macdef\0" as *const u8 as *const i8, tok) }) != 0
                            {
                                state = MACDEF;
                            } else if (unsafe { Curl_strcasecompare(
                                b"machine\0" as *const u8 as *const i8,
                                tok,
                            ) }) != 0
                            {
                                state = HOSTFOUND;
                            } else if (unsafe { Curl_strcasecompare(
                                b"default\0" as *const u8 as *const i8,
                                tok,
                            ) }) != 0
                            {
                                state = HOSTVALID;
                                retcode = 0 as i32;
                            }
                        }
                        3 => {
                            if (unsafe { strlen(tok) }) == 0 {
                                state = NOTHING;
                            }
                        }
                        1 => {
                            if (unsafe { Curl_strcasecompare(host, tok) }) != 0 {
                                state = HOSTVALID;
                                retcode = 0 as i32;
                            } else {
                                state = NOTHING;
                            }
                        }
                        2 => {
                            if state_login != 0 {
                                if specific_login {
                                    state_our_login = unsafe { Curl_strcasecompare(login, tok) };
                                } else if login.is_null() || (unsafe { strcmp(login, tok) }) != 0 {
                                    if login_alloc {
                                        (unsafe { Curl_cfree.expect("non-null function pointer")(
                                            login as *mut libc::c_void,
                                        ) });
                                        login_alloc = 0 as i32 != 0;
                                    }
                                    login = unsafe { Curl_cstrdup.expect("non-null function pointer")(tok) };
                                    if login.is_null() {
                                        retcode = -(1 as i32);
                                        break 's_69;
                                    } else {
                                        login_alloc = 1 as i32 != 0;
                                    }
                                }
                                state_login = 0 as i32 as i8;
                            } else if state_password != 0 {
                                if (state_our_login != 0 || !specific_login)
                                    && (password.is_null() || (unsafe { strcmp(password, tok) }) != 0)
                                {
                                    if password_alloc {
                                        (unsafe { Curl_cfree.expect("non-null function pointer")(
                                            password as *mut libc::c_void,
                                        ) });
                                        password_alloc = 0 as i32 != 0;
                                    }
                                    password =
                                        unsafe { Curl_cstrdup.expect("non-null function pointer")(tok) };
                                    if password.is_null() {
                                        retcode = -(1 as i32);
                                        break 's_69;
                                    } else {
                                        password_alloc = 1 as i32 != 0;
                                    }
                                }
                                state_password = 0 as i32 as i8;
                            } else if (unsafe { Curl_strcasecompare(b"login\0" as *const u8 as *const i8, tok) })
                                != 0
                            {
                                state_login = 1 as i32 as i8;
                            } else if (unsafe { Curl_strcasecompare(
                                b"password\0" as *const u8 as *const i8,
                                tok,
                            ) }) != 0
                            {
                                state_password = 1 as i32 as i8;
                            } else if (unsafe { Curl_strcasecompare(
                                b"machine\0" as *const u8 as *const i8,
                                tok,
                            ) }) != 0
                            {
                                state = HOSTFOUND;
                                state_our_login = 0 as i32;
                            }
                        }
                        _ => {}
                    }
                    tok = unsafe { strtok_r(
                        0 as *mut i8,
                        b" \t\n\0" as *const u8 as *const i8,
                        &mut tok_buf,
                    ) };
                }
            }
        }
        if retcode == 0 {
            (unsafe { *login_changed = 0 as i32 != 0 });
            (unsafe { *password_changed = 0 as i32 != 0 });
            if login_alloc {
                if !(unsafe { *loginp }).is_null() {
                    (unsafe { Curl_cfree.expect("non-null function pointer")(*loginp as *mut libc::c_void) });
                }
                (unsafe { *loginp = login });
                (unsafe { *login_changed = 1 as i32 != 0 });
            }
            if password_alloc {
                if !(unsafe { *passwordp }).is_null() {
                    (unsafe { Curl_cfree.expect("non-null function pointer")(*passwordp as *mut libc::c_void) });
                }
                (unsafe { *passwordp = password });
                (unsafe { *password_changed = 1 as i32 != 0 });
            }
        } else {
            if login_alloc {
                (unsafe { Curl_cfree.expect("non-null function pointer")(login as *mut libc::c_void) });
            }
            if password_alloc {
                (unsafe { Curl_cfree.expect("non-null function pointer")(password as *mut libc::c_void) });
            }
        }
        (unsafe { fclose(file) });
    }
    return retcode;
}
#[no_mangle]
pub extern "C" fn Curl_parsenetrc(
    mut host: *const i8,
    mut loginp: *mut *mut i8,
    mut passwordp: *mut *mut i8,
    mut login_changed: *mut bool,
    mut password_changed: *mut bool,
    mut netrcfile: *mut i8,
) -> i32 {
    let mut retcode: i32 = 1 as i32;
    let mut filealloc: *mut i8 = 0 as *mut i8;
    if netrcfile.is_null() {
        let mut home: *mut i8 = 0 as *mut i8;
        let mut homea: *mut i8 = unsafe { curl_getenv(b"HOME\0" as *const u8 as *const i8) };
        if !homea.is_null() {
            home = homea;
        } else {
            let mut pw: passwd = passwd {
                pw_name: 0 as *mut i8,
                pw_passwd: 0 as *mut i8,
                pw_uid: 0,
                pw_gid: 0,
                pw_gecos: 0 as *mut i8,
                pw_dir: 0 as *mut i8,
                pw_shell: 0 as *mut i8,
            };
            let mut pw_res: *mut passwd = 0 as *mut passwd;
            let mut pwbuf: [i8; 1024] = [0; 1024];
            if (unsafe { getpwuid_r(
                geteuid(),
                &mut pw,
                pwbuf.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 1024]>() as u64,
                &mut pw_res,
            ) }) == 0
                && !pw_res.is_null()
            {
                home = pw.pw_dir;
            }
        }
        if home.is_null() {
            return retcode;
        }
        filealloc = unsafe { curl_maprintf(
            b"%s%s.netrc\0" as *const u8 as *const i8,
            home,
            b"/\0" as *const u8 as *const i8,
        ) };
        if filealloc.is_null() {
            (unsafe { Curl_cfree.expect("non-null function pointer")(homea as *mut libc::c_void) });
            return -(1 as i32);
        }
        retcode = parsenetrc(
            host,
            loginp,
            passwordp,
            login_changed,
            password_changed,
            filealloc,
        );
        (unsafe { Curl_cfree.expect("non-null function pointer")(filealloc as *mut libc::c_void) });
        (unsafe { Curl_cfree.expect("non-null function pointer")(homea as *mut libc::c_void) });
    } else {
        retcode = parsenetrc(
            host,
            loginp,
            passwordp,
            login_changed,
            password_changed,
            netrcfile,
        );
    }
    return retcode;
}
