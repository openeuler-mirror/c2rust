use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn curl_getenv(variable: *const libc::c_char) -> *mut libc::c_char;
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    fn fgets(
        __s: *mut libc::c_char,
        __n: libc::c_int,
        __stream: *mut FILE,
    ) -> *mut libc::c_char;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strtok_r(
        __s: *mut libc::c_char,
        __delim: *const libc::c_char,
        __save_ptr: *mut *mut libc::c_char,
    ) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn geteuid() -> __uid_t;
    fn getpwuid_r(
        __uid: __uid_t,
        __resultbuf: *mut passwd,
        __buffer: *mut libc::c_char,
        __buflen: size_t,
        __result: *mut *mut passwd,
    ) -> libc::c_int;
    fn Curl_strcasecompare(
        first: *const libc::c_char,
        second: *const libc::c_char,
    ) -> libc::c_int;
    fn curl_maprintf(format: *const libc::c_char, _: ...) -> *mut libc::c_char;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_cstrdup: curl_strdup_callback;
}
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type curl_free_callback = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type curl_strdup_callback = Option::<
    unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
>;
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
pub type host_lookup_state = libc::c_uint;
pub const MACDEF: host_lookup_state = 3;
pub const HOSTVALID: host_lookup_state = 2;
pub const HOSTFOUND: host_lookup_state = 1;
pub const NOTHING: host_lookup_state = 0;
unsafe extern "C" fn parsenetrc(
    mut host: *const libc::c_char,
    mut loginp: *mut *mut libc::c_char,
    mut passwordp: *mut *mut libc::c_char,
    mut login_changed: *mut bool,
    mut password_changed: *mut bool,
    mut netrcfile: *mut libc::c_char,
) -> libc::c_int {
    let mut file: *mut FILE = 0 as *mut FILE;
    let mut retcode: libc::c_int = 1 as libc::c_int;
    let mut login: *mut libc::c_char = *loginp;
    let mut password: *mut libc::c_char = *passwordp;
    let mut specific_login: bool = !login.is_null()
        && *login as libc::c_int != 0 as libc::c_int;
    let mut login_alloc: bool = 0 as libc::c_int != 0;
    let mut password_alloc: bool = 0 as libc::c_int != 0;
    let mut state: host_lookup_state = NOTHING;
    let mut state_login: libc::c_char = 0 as libc::c_int as libc::c_char;
    let mut state_password: libc::c_char = 0 as libc::c_int as libc::c_char;
    let mut state_our_login: libc::c_int = 0 as libc::c_int;
    file = fopen(netrcfile, b"r\0" as *const u8 as *const libc::c_char);
    if !file.is_null() {
        let mut tok: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut tok_buf: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut done: bool = 0 as libc::c_int != 0;
        let mut netrcbuffer: [libc::c_char; 4096] = [0; 4096];
        let mut netrcbuffsize: libc::c_int = ::std::mem::size_of::<
            [libc::c_char; 4096],
        >() as libc::c_ulong as libc::c_int;
        's_69: while !done
            && !(fgets(netrcbuffer.as_mut_ptr(), netrcbuffsize, file)).is_null()
        {
            if state as libc::c_uint == MACDEF as libc::c_int as libc::c_uint {
                if !(netrcbuffer[0 as libc::c_int as usize] as libc::c_int == '\n' as i32
                    || netrcbuffer[0 as libc::c_int as usize] as libc::c_int
                        == '\r' as i32)
                {
                    continue;
                }
                state = NOTHING;
            }
            tok = strtok_r(
                netrcbuffer.as_mut_ptr(),
                b" \t\n\0" as *const u8 as *const libc::c_char,
                &mut tok_buf,
            );
            if !tok.is_null() && *tok as libc::c_int == '#' as i32 {
                continue;
            }
            while !tok.is_null() {
                if !login.is_null() && *login as libc::c_int != 0
                    && (!password.is_null() && *password as libc::c_int != 0)
                {
                    done = 1 as libc::c_int != 0;
                    break;
                } else {
                    match state as libc::c_uint {
                        0 => {
                            if Curl_strcasecompare(
                                b"macdef\0" as *const u8 as *const libc::c_char,
                                tok,
                            ) != 0
                            {
                                state = MACDEF;
                            } else if Curl_strcasecompare(
                                    b"machine\0" as *const u8 as *const libc::c_char,
                                    tok,
                                ) != 0
                                {
                                state = HOSTFOUND;
                            } else if Curl_strcasecompare(
                                    b"default\0" as *const u8 as *const libc::c_char,
                                    tok,
                                ) != 0
                                {
                                state = HOSTVALID;
                                retcode = 0 as libc::c_int;
                            }
                        }
                        3 => {
                            if strlen(tok) == 0 {
                                state = NOTHING;
                            }
                        }
                        1 => {
                            if Curl_strcasecompare(host, tok) != 0 {
                                state = HOSTVALID;
                                retcode = 0 as libc::c_int;
                            } else {
                                state = NOTHING;
                            }
                        }
                        2 => {
                            if state_login != 0 {
                                if specific_login {
                                    state_our_login = Curl_strcasecompare(login, tok);
                                } else if login.is_null() || strcmp(login, tok) != 0 {
                                    if login_alloc {
                                        Curl_cfree
                                            .expect(
                                                "non-null function pointer",
                                            )(login as *mut libc::c_void);
                                        login_alloc = 0 as libc::c_int != 0;
                                    }
                                    login = Curl_cstrdup
                                        .expect("non-null function pointer")(tok);
                                    if login.is_null() {
                                        retcode = -(1 as libc::c_int);
                                        break 's_69;
                                    } else {
                                        login_alloc = 1 as libc::c_int != 0;
                                    }
                                }
                                state_login = 0 as libc::c_int as libc::c_char;
                            } else if state_password != 0 {
                                if (state_our_login != 0 || !specific_login)
                                    && (password.is_null() || strcmp(password, tok) != 0)
                                {
                                    if password_alloc {
                                        Curl_cfree
                                            .expect(
                                                "non-null function pointer",
                                            )(password as *mut libc::c_void);
                                        password_alloc = 0 as libc::c_int != 0;
                                    }
                                    password = Curl_cstrdup
                                        .expect("non-null function pointer")(tok);
                                    if password.is_null() {
                                        retcode = -(1 as libc::c_int);
                                        break 's_69;
                                    } else {
                                        password_alloc = 1 as libc::c_int != 0;
                                    }
                                }
                                state_password = 0 as libc::c_int as libc::c_char;
                            } else if Curl_strcasecompare(
                                    b"login\0" as *const u8 as *const libc::c_char,
                                    tok,
                                ) != 0
                                {
                                state_login = 1 as libc::c_int as libc::c_char;
                            } else if Curl_strcasecompare(
                                    b"password\0" as *const u8 as *const libc::c_char,
                                    tok,
                                ) != 0
                                {
                                state_password = 1 as libc::c_int as libc::c_char;
                            } else if Curl_strcasecompare(
                                    b"machine\0" as *const u8 as *const libc::c_char,
                                    tok,
                                ) != 0
                                {
                                state = HOSTFOUND;
                                state_our_login = 0 as libc::c_int;
                            }
                        }
                        _ => {}
                    }
                    tok = strtok_r(
                        0 as *mut libc::c_char,
                        b" \t\n\0" as *const u8 as *const libc::c_char,
                        &mut tok_buf,
                    );
                }
            }
        }
        if retcode == 0 {
            *login_changed = 0 as libc::c_int != 0;
            *password_changed = 0 as libc::c_int != 0;
            if login_alloc {
                if !(*loginp).is_null() {
                    Curl_cfree
                        .expect(
                            "non-null function pointer",
                        )(*loginp as *mut libc::c_void);
                }
                *loginp = login;
                *login_changed = 1 as libc::c_int != 0;
            }
            if password_alloc {
                if !(*passwordp).is_null() {
                    Curl_cfree
                        .expect(
                            "non-null function pointer",
                        )(*passwordp as *mut libc::c_void);
                }
                *passwordp = password;
                *password_changed = 1 as libc::c_int != 0;
            }
        } else {
            if login_alloc {
                Curl_cfree
                    .expect("non-null function pointer")(login as *mut libc::c_void);
            }
            if password_alloc {
                Curl_cfree
                    .expect("non-null function pointer")(password as *mut libc::c_void);
            }
        }
        fclose(file);
    }
    return retcode;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_parsenetrc(
    mut host: *const libc::c_char,
    mut loginp: *mut *mut libc::c_char,
    mut passwordp: *mut *mut libc::c_char,
    mut login_changed: *mut bool,
    mut password_changed: *mut bool,
    mut netrcfile: *mut libc::c_char,
) -> libc::c_int {
    let mut retcode: libc::c_int = 1 as libc::c_int;
    let mut filealloc: *mut libc::c_char = 0 as *mut libc::c_char;
    if netrcfile.is_null() {
        let mut home: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut homea: *mut libc::c_char = curl_getenv(
            b"HOME\0" as *const u8 as *const libc::c_char,
        );
        if !homea.is_null() {
            home = homea;
        } else {
            let mut pw: passwd = passwd {
                pw_name: 0 as *mut libc::c_char,
                pw_passwd: 0 as *mut libc::c_char,
                pw_uid: 0,
                pw_gid: 0,
                pw_gecos: 0 as *mut libc::c_char,
                pw_dir: 0 as *mut libc::c_char,
                pw_shell: 0 as *mut libc::c_char,
            };
            let mut pw_res: *mut passwd = 0 as *mut passwd;
            let mut pwbuf: [libc::c_char; 1024] = [0; 1024];
            if getpwuid_r(
                geteuid(),
                &mut pw,
                pwbuf.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
                &mut pw_res,
            ) == 0 && !pw_res.is_null()
            {
                home = pw.pw_dir;
            }
        }
        if home.is_null() {
            return retcode;
        }
        filealloc = curl_maprintf(
            b"%s%s.netrc\0" as *const u8 as *const libc::c_char,
            home,
            b"/\0" as *const u8 as *const libc::c_char,
        );
        if filealloc.is_null() {
            Curl_cfree.expect("non-null function pointer")(homea as *mut libc::c_void);
            return -(1 as libc::c_int);
        }
        retcode = parsenetrc(
            host,
            loginp,
            passwordp,
            login_changed,
            password_changed,
            filealloc,
        );
        Curl_cfree.expect("non-null function pointer")(filealloc as *mut libc::c_void);
        Curl_cfree.expect("non-null function pointer")(homea as *mut libc::c_void);
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
