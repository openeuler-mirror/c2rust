use ::libc;
extern "C" {
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn exit(_: libc::c_int) -> !;
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub arg: *const libc::c_char,
    pub flag: libc::c_int,
}
static mut format_args: [C2RustUnnamed; 4] = [
    {
        let mut init = C2RustUnnamed {
            arg: b"plain\0" as *const u8 as *const libc::c_char,
            flag: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            arg: b"spaced\0" as *const u8 as *const libc::c_char,
            flag: (1 as libc::c_int) << 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            arg: b"pretty\0" as *const u8 as *const libc::c_char,
            flag: (1 as libc::c_int) << 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            arg: b"pretty_tab\0" as *const u8 as *const libc::c_char,
            flag: (1 as libc::c_int) << 3 as libc::c_int,
        };
        init
    },
];
#[no_mangle]
pub unsafe extern "C" fn parse_flags(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut arg_idx: libc::c_int = 0;
    let mut sflags: libc::c_int = 0 as libc::c_int;
    arg_idx = 1 as libc::c_int;
    while arg_idx < argc {
        let mut jj: libc::c_int = 0;
        jj = 0 as libc::c_int;
        while jj
            < (::std::mem::size_of::<[C2RustUnnamed; 4]>() as libc::c_ulong)
                .wrapping_div(::std::mem::size_of::<C2RustUnnamed>() as libc::c_ulong)
                as libc::c_int
        {
            if strcasecmp(*argv.offset(arg_idx as isize), format_args[jj as usize].arg)
                == 0 as libc::c_int
            {
                sflags |= format_args[jj as usize].flag;
                break;
            } else {
                jj += 1;
            }
        }
        if jj as libc::c_ulong
            == (::std::mem::size_of::<[C2RustUnnamed; 4]>() as libc::c_ulong)
                .wrapping_div(::std::mem::size_of::<C2RustUnnamed>() as libc::c_ulong)
        {
            printf(
                b"Unknown arg: %s\n\0" as *const u8 as *const libc::c_char,
                *argv.offset(arg_idx as isize),
            );
            exit(1 as libc::c_int);
        }
        arg_idx += 1;
    }
    return sflags;
}
