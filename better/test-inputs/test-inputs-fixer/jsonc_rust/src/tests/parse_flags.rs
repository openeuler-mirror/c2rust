
extern "C" {
    fn printf(_: *const i8, _: ...) -> i32;
    fn strcasecmp(_: *const i8, _: *const i8) -> i32;
    fn exit(_: i32) -> !;
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub arg: *const i8,
    pub flag: i32,
}
static mut format_args: [C2RustUnnamed; 4] = [
    {
        let mut init = C2RustUnnamed {
            arg: b"plain\0" as *const u8 as *const i8,
            flag: 0 as i32,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            arg: b"spaced\0" as *const u8 as *const i8,
            flag: (1 as i32) << 0 as i32,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            arg: b"pretty\0" as *const u8 as *const i8,
            flag: (1 as i32) << 1 as i32,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            arg: b"pretty_tab\0" as *const u8 as *const i8,
            flag: (1 as i32) << 3 as i32,
        };
        init
    },
];
#[no_mangle]
pub extern "C" fn parse_flags(mut argc: i32, mut argv: *mut *mut i8) -> i32 {
    let mut arg_idx: i32 = 0;
    let mut sflags: i32 = 0 as i32;
    arg_idx = 1 as i32;
    while arg_idx < argc {
        let mut jj: i32 = 0;
        jj = 0 as i32;
        while jj
            < (::std::mem::size_of::<[C2RustUnnamed; 4]>() as u64)
                .wrapping_div(::std::mem::size_of::<C2RustUnnamed>() as u64) as i32
        {
            if (unsafe { strcasecmp(*argv.offset(arg_idx as isize), format_args[jj as usize].arg) }) == 0 as i32
            {
                sflags |= unsafe { format_args[jj as usize].flag };
                break;
            } else {
                jj += 1;
            }
        }
        if jj as u64
            == (::std::mem::size_of::<[C2RustUnnamed; 4]>() as u64)
                .wrapping_div(::std::mem::size_of::<C2RustUnnamed>() as u64)
        {
            (unsafe { printf(
                b"Unknown arg: %s\n\0" as *const u8 as *const i8,
                *argv.offset(arg_idx as isize),
            ) });
            (unsafe { exit(1 as i32) });
        }
        arg_idx += 1;
    }
    return sflags;
}
