
extern "C" {
    fn strerror(_: i32) -> *mut i8;
    fn getenv(name: *const i8) -> *mut i8;
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub errno_value: i32,
    pub errno_str: *const i8,
}
impl C2RustUnnamed {
    pub const fn new() -> Self {
        C2RustUnnamed {
            errno_value: 0,
            errno_str: (0 as *const i8),
        }
    }
}
impl std::default::Default for C2RustUnnamed {
    fn default() -> Self {
        C2RustUnnamed::new()
    }
}
static mut errno_list: [crate::src::strerror_override::C2RustUnnamed; 36] = [C2RustUnnamed {
    errno_value: 0,
    errno_str: (0 as *const i8),
}; 36];
static mut _json_c_strerror_enable: i32 = 0 as i32;
static mut errno_buf: [i8; 128] = unsafe {
    * core :: intrinsics :: transmute :: < & '_ [u8 ; 128] , & '_ mut [i8 ; 128] > (b"ERRNO=\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" ,)
};
#[no_mangle]
pub extern "C" fn _json_c_strerror(mut errno_in: i32) -> *mut i8 {
    let mut start_idx: i32 = 0;
    let mut digbuf: [i8; 20] = [0; 20];
    let mut ii: i32 = 0;
    let mut jj: i32 = 0;
    if (unsafe { _json_c_strerror_enable }) == 0 {
        (unsafe { _json_c_strerror_enable =
            if (getenv(b"_JSON_C_STRERROR_ENABLE\0" as *const u8 as *const i8)).is_null() {
                -(1 as i32)
            } else {
                1 as i32
            } });
    }
    if (unsafe { _json_c_strerror_enable }) == -(1 as i32) {
        return unsafe { strerror(errno_in) };
    }
    ii = 0 as i32;
    while !(unsafe { errno_list[ii as usize].errno_str }).is_null() {
        let mut errno_str: *const i8 = unsafe { errno_list[ii as usize].errno_str };
        if (unsafe { errno_list[ii as usize].errno_value }) != errno_in {
            ii += 1;
        } else {
            start_idx =
                (::std::mem::size_of::<[i8; 7]>() as u64).wrapping_sub(1 as i32 as u64) as i32;
            jj = 0 as i32;
            while (unsafe { *errno_str.offset(jj as isize) }) as i32 != '\u{0}' as i32 {
                (unsafe { errno_buf[start_idx as usize] = *errno_str.offset(jj as isize) });
                jj += 1;
                start_idx += 1;
            }
            (unsafe { errno_buf[start_idx as usize] = '\u{0}' as i32 as i8 });
            return unsafe { errno_buf.as_mut_ptr() };
        }
    }
    ii = 0 as i32;
    while errno_in >= 10 as i32 {
        digbuf[ii as usize] =
            (*(unsafe { core::intrinsics::transmute::<&'_ [u8; 11], &'_ [i8; 11]>(b"0123456789\0") }))
                [(errno_in % 10 as i32) as usize];
        errno_in /= 10 as i32;
        ii += 1;
    }
    digbuf[ii as usize] =
        (*(unsafe { core::intrinsics::transmute::<&'_ [u8; 11], &'_ [i8; 11]>(b"0123456789\0") }))
            [(errno_in % 10 as i32) as usize];
    start_idx = (::std::mem::size_of::<[i8; 7]>() as u64).wrapping_sub(1 as i32 as u64) as i32;
    while ii >= 0 as i32 {
        (unsafe { errno_buf[start_idx as usize] = digbuf[ii as usize] });
        ii -= 1;
        start_idx += 1;
    }
    (unsafe { errno_buf[start_idx as usize] = '\u{0}' as i32 as i8 });
    return unsafe { errno_buf.as_mut_ptr() };
}
extern "C" fn run_static_initializers() {
    (unsafe { errno_list = [
        {
            let mut init = C2RustUnnamed {
                errno_value: 1 as i32,
                errno_str: &*(b"undef_EPERM\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 2 as i32,
                errno_str: &*(b"undef_ENOENT\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 3 as i32,
                errno_str: &*(b"undef_ESRCH\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 4 as i32,
                errno_str: &*(b"undef_EINTR\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 5 as i32,
                errno_str: &*(b"undef_EIO\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 6 as i32,
                errno_str: &*(b"undef_ENXIO\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 7 as i32,
                errno_str: &*(b"undef_E2BIG\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 8 as i32,
                errno_str: &*(b"undef_ENOEXEC\0" as *const u8 as *const i8)
                    .offset(6 as i32 as isize) as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 9 as i32,
                errno_str: &*(b"undef_EBADF\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 10 as i32,
                errno_str: &*(b"undef_ECHILD\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 35 as i32,
                errno_str: &*(b"undef_EDEADLK\0" as *const u8 as *const i8)
                    .offset(6 as i32 as isize) as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 12 as i32,
                errno_str: &*(b"undef_ENOMEM\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 13 as i32,
                errno_str: &*(b"undef_EACCES\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 14 as i32,
                errno_str: &*(b"undef_EFAULT\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 15 as i32,
                errno_str: &*(b"undef_ENOTBLK\0" as *const u8 as *const i8)
                    .offset(6 as i32 as isize) as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 16 as i32,
                errno_str: &*(b"undef_EBUSY\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 17 as i32,
                errno_str: &*(b"undef_EEXIST\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 18 as i32,
                errno_str: &*(b"undef_EXDEV\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 19 as i32,
                errno_str: &*(b"undef_ENODEV\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 20 as i32,
                errno_str: &*(b"undef_ENOTDIR\0" as *const u8 as *const i8)
                    .offset(6 as i32 as isize) as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 21 as i32,
                errno_str: &*(b"undef_EISDIR\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 22 as i32,
                errno_str: &*(b"undef_EINVAL\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 23 as i32,
                errno_str: &*(b"undef_ENFILE\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 24 as i32,
                errno_str: &*(b"undef_EMFILE\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 25 as i32,
                errno_str: &*(b"undef_ENOTTY\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 26 as i32,
                errno_str: &*(b"undef_ETXTBSY\0" as *const u8 as *const i8)
                    .offset(6 as i32 as isize) as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 27 as i32,
                errno_str: &*(b"undef_EFBIG\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 28 as i32,
                errno_str: &*(b"undef_ENOSPC\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 29 as i32,
                errno_str: &*(b"undef_ESPIPE\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 30 as i32,
                errno_str: &*(b"undef_EROFS\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 31 as i32,
                errno_str: &*(b"undef_EMLINK\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 32 as i32,
                errno_str: &*(b"undef_EPIPE\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 33 as i32,
                errno_str: &*(b"undef_EDOM\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 34 as i32,
                errno_str: &*(b"undef_ERANGE\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 11 as i32,
                errno_str: &*(b"undef_EAGAIN\0" as *const u8 as *const i8).offset(6 as i32 as isize)
                    as *const i8,
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                errno_value: 0 as i32,
                errno_str: (0 as *mut i8),
            };
            init
        },
    ] });
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn() -> (); 1] = [run_static_initializers];

