use ::libc;
extern "C" {
    
    
    
    
    fn fclose(__stream: *mut FILE) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut FILE;
    fn fgets(
        __s: *mut i8,
        __n: i32,
        __stream: *mut FILE,
    ) -> *mut i8;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strtok_r(
        __s: *mut i8,
        __delim: *const i8,
        __save_ptr: *mut *mut i8,
    ) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn geteuid() -> __uid_t;
    fn getpwuid_r(
        __uid: __uid_t,
        __resultbuf: *mut passwd,
        __buffer: *mut i8,
        __buflen: size_t,
        __result: *mut *mut passwd,
    ) -> i32;
    
    
    
    
}
pub use crate::src::lib::getenv::curl_getenv;
pub use crate::src::lib::mprintf::curl_maprintf;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cstrdup;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub type __uid_t = crate::src::lib::conncache::__uid_t;
pub type __gid_t = crate::src::lib::curl_ntlm_wb::__gid_t;
pub type __off_t = crate::src::lib::http2::__off_t;
pub type __off64_t = crate::src::lib::http2::__off64_t;
pub type size_t = crate::src::lib::http2::size_t;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = crate::src::lib::http2::_IO_lock_t;
pub type FILE = crate::src::lib::http2::FILE;
pub type curl_free_callback = crate::src::lib::http2::curl_free_callback;
pub type curl_strdup_callback = crate::src::lib::altsvc::curl_strdup_callback;
// #[derive(Copy, Clone)]

pub type passwd = crate::src::lib::curl_ntlm_wb::passwd;
pub type host_lookup_state = u32;
pub const MACDEF: host_lookup_state = 3;
pub const HOSTVALID: host_lookup_state = 2;
pub const HOSTFOUND: host_lookup_state = 1;
pub const NOTHING: host_lookup_state = 0;
unsafe extern "C" fn parsenetrc(
    mut host: *const i8,
    mut loginp: *mut *mut i8,
    mut passwordp: *mut *mut i8,
    mut login_changed: *mut bool,
    mut password_changed: *mut bool,
    mut netrcfile: *mut i8,
) -> i32 {
    let mut file: *mut FILE = 0 as *mut FILE;
    let mut retcode: i32 = 1 as i32;
    let mut login: *mut i8 = *loginp;
    let mut password: *mut i8 = *passwordp;
    let mut specific_login: bool = !login.is_null()
        && *login as i32 != 0 as i32;
    let mut login_alloc: bool = 0 as i32 != 0;
    let mut password_alloc: bool = 0 as i32 != 0;
    let mut state: host_lookup_state = NOTHING;
    let mut state_login: i8 = 0 as i32 as i8;
    let mut state_password: i8 = 0 as i32 as i8;
    let mut state_our_login: i32 = 0 as i32;
    file = fopen(netrcfile, b"r\0" as *const u8 as *const i8);
    if !file.is_null() {
        let mut tok: *mut i8 = 0 as *mut i8;
        let mut tok_buf: *mut i8 = 0 as *mut i8;
        let mut done: bool = 0 as i32 != 0;
        let mut netrcbuffer: [i8; 4096] = [0; 4096];
        let mut netrcbuffsize: i32 = ::std::mem::size_of::<
            [i8; 4096],
        >() as u64 as i32;
        's_69: while !done
            && !(fgets(netrcbuffer.as_mut_ptr(), netrcbuffsize, file)).is_null()
        {
            if state as u32 == MACDEF as i32 as u32 {
                if !(netrcbuffer[0 as i32 as usize] as i32 == '\n' as i32
                    || netrcbuffer[0 as i32 as usize] as i32
                        == '\r' as i32)
                {
                    continue;
                }
                state = NOTHING;
            }
            tok = strtok_r(
                netrcbuffer.as_mut_ptr(),
                b" \t\n\0" as *const u8 as *const i8,
                &mut tok_buf,
            );
            if !tok.is_null() && *tok as i32 == '#' as i32 {
                continue;
            }
            while !tok.is_null() {
                if !login.is_null() && *login as i32 != 0
                    && (!password.is_null() && *password as i32 != 0)
                {
                    done = 1 as i32 != 0;
                    break;
                } else {
                    match state as u32 {
                        0 => {
                            if Curl_strcasecompare(
                                b"macdef\0" as *const u8 as *const i8,
                                tok,
                            ) != 0
                            {
                                state = MACDEF;
                            } else if Curl_strcasecompare(
                                    b"machine\0" as *const u8 as *const i8,
                                    tok,
                                ) != 0
                                {
                                state = HOSTFOUND;
                            } else if Curl_strcasecompare(
                                    b"default\0" as *const u8 as *const i8,
                                    tok,
                                ) != 0
                                {
                                state = HOSTVALID;
                                retcode = 0 as i32;
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
                                retcode = 0 as i32;
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
                                        login_alloc = 0 as i32 != 0;
                                    }
                                    login = Curl_cstrdup
                                        .expect("non-null function pointer")(tok);
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
                                    && (password.is_null() || strcmp(password, tok) != 0)
                                {
                                    if password_alloc {
                                        Curl_cfree
                                            .expect(
                                                "non-null function pointer",
                                            )(password as *mut libc::c_void);
                                        password_alloc = 0 as i32 != 0;
                                    }
                                    password = Curl_cstrdup
                                        .expect("non-null function pointer")(tok);
                                    if password.is_null() {
                                        retcode = -(1 as i32);
                                        break 's_69;
                                    } else {
                                        password_alloc = 1 as i32 != 0;
                                    }
                                }
                                state_password = 0 as i32 as i8;
                            } else if Curl_strcasecompare(
                                    b"login\0" as *const u8 as *const i8,
                                    tok,
                                ) != 0
                                {
                                state_login = 1 as i32 as i8;
                            } else if Curl_strcasecompare(
                                    b"password\0" as *const u8 as *const i8,
                                    tok,
                                ) != 0
                                {
                                state_password = 1 as i32 as i8;
                            } else if Curl_strcasecompare(
                                    b"machine\0" as *const u8 as *const i8,
                                    tok,
                                ) != 0
                                {
                                state = HOSTFOUND;
                                state_our_login = 0 as i32;
                            }
                        }
                        _ => {}
                    }
                    tok = strtok_r(
                        0 as *mut i8,
                        b" \t\n\0" as *const u8 as *const i8,
                        &mut tok_buf,
                    );
                }
            }
        }
        if retcode == 0 {
            *login_changed = 0 as i32 != 0;
            *password_changed = 0 as i32 != 0;
            if login_alloc {
                if !(*loginp).is_null() {
                    Curl_cfree
                        .expect(
                            "non-null function pointer",
                        )(*loginp as *mut libc::c_void);
                }
                *loginp = login;
                *login_changed = 1 as i32 != 0;
            }
            if password_alloc {
                if !(*passwordp).is_null() {
                    Curl_cfree
                        .expect(
                            "non-null function pointer",
                        )(*passwordp as *mut libc::c_void);
                }
                *passwordp = password;
                *password_changed = 1 as i32 != 0;
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
        let mut homea: *mut i8 = curl_getenv(
            b"HOME\0" as *const u8 as *const i8,
        );
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
            if getpwuid_r(
                geteuid(),
                &mut pw,
                pwbuf.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 1024]>() as u64,
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
            b"%s%s.netrc\0" as *const u8 as *const i8,
            home,
            b"/\0" as *const u8 as *const i8,
        );
        if filealloc.is_null() {
            Curl_cfree.expect("non-null function pointer")(homea as *mut libc::c_void);
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
