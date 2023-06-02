use ::libc;
extern "C" {
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    
}
pub use crate::src::random_seed::json_c_get_random_seed;
pub type ptrdiff_t = libc::c_long;
pub type size_t = crate::src::apps::json_parse::size_t;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = crate::src::json_object::__uint32_t;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = crate::src::json_object::uint32_t;
pub type uintptr_t = crate::src::json_object::uintptr_t;
// #[derive(Copy, Clone)]

pub type lh_entry = crate::src::json_object::lh_entry;
pub type json_bool = crate::src::json_object::json_bool;
// #[derive(Copy, Clone)]

pub type lh_table = crate::src::json_object::lh_table;
pub type lh_equal_fn = crate::src::json_object::lh_equal_fn;
pub type lh_hash_fn = crate::src::json_object::lh_hash_fn;
pub type lh_entry_free_fn = crate::src::json_object::lh_entry_free_fn;
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub ptr: *const libc::c_void,
    pub i: size_t,
}
#[inline]
unsafe extern "C" fn lh_entry_v(mut e: *const lh_entry) -> *mut libc::c_void {
    return (*e).v as uintptr_t as *mut libc::c_void;
}
#[inline]
unsafe extern "C" fn lh_get_hash(
    mut t: *const lh_table,
    mut k: *const libc::c_void,
) -> libc::c_ulong {
    return ((*t).hash_fn).expect("non-null function pointer")(k);
}
static mut char_hash_fn: Option::<lh_hash_fn> = unsafe {
    Some(lh_char_hash as unsafe extern "C" fn(*const libc::c_void) -> libc::c_ulong)
};
#[no_mangle]
pub unsafe extern "C" fn json_global_set_string_hash(h: libc::c_int) -> libc::c_int {
    match h {
        0 => {
            char_hash_fn = Some(
                lh_char_hash
                    as unsafe extern "C" fn(*const libc::c_void) -> libc::c_ulong,
            );
        }
        1 => {
            char_hash_fn = Some(
                lh_perllike_str_hash
                    as unsafe extern "C" fn(*const libc::c_void) -> libc::c_ulong,
            );
        }
        _ => return -(1 as libc::c_int),
    }
    return 0 as libc::c_int;
}
 extern "C" fn lh_ptr_hash(mut k: *const libc::c_void) -> libc::c_ulong {
    return (k as ptrdiff_t as libc::c_ulong).wrapping_mul(0x9e370001 as libc::c_ulong)
        >> 4 as libc::c_int
        & (9223372036854775807 as libc::c_long as libc::c_ulong)
            .wrapping_mul(2 as libc::c_ulong)
            .wrapping_add(1 as libc::c_ulong);
}
#[no_mangle]
pub extern "C" fn lh_ptr_equal(
    mut k1: *const libc::c_void,
    mut k2: *const libc::c_void,
) -> libc::c_int {
    return (k1 == k2) as libc::c_int;
}
unsafe extern "C" fn hashlittle(
    mut key: *const libc::c_void,
    mut length: size_t,
    mut initval: uint32_t,
) -> uint32_t {
    let mut a: uint32_t = 0;
    let mut b: uint32_t = 0;
    let mut c: uint32_t = 0;
    let mut u: C2RustUnnamed = C2RustUnnamed {
        ptr: 0 as *const libc::c_void,
    };
    c = (0xdeadbeef as libc::c_uint)
        .wrapping_add(length as uint32_t)
        .wrapping_add(initval);
    b = c;
    a = b;
    u.ptr = key;
    if 1 as libc::c_int != 0
        && u.i & 0x3 as libc::c_int as libc::c_ulong == 0 as libc::c_int as libc::c_ulong
    {
        let mut k: *const uint32_t = key as *const uint32_t;
        while length > 12 as libc::c_int as libc::c_ulong {
            a = (a as libc::c_uint).wrapping_add(*k.offset(0 as libc::c_int as isize))
                as uint32_t as uint32_t;
            b = (b as libc::c_uint).wrapping_add(*k.offset(1 as libc::c_int as isize))
                as uint32_t as uint32_t;
            c = (c as libc::c_uint).wrapping_add(*k.offset(2 as libc::c_int as isize))
                as uint32_t as uint32_t;
            a = (a as libc::c_uint).wrapping_sub(c) as uint32_t as uint32_t;
            a ^= c << 4 as libc::c_int | c >> 32 as libc::c_int - 4 as libc::c_int;
            c = (c as libc::c_uint).wrapping_add(b) as uint32_t as uint32_t;
            b = (b as libc::c_uint).wrapping_sub(a) as uint32_t as uint32_t;
            b ^= a << 6 as libc::c_int | a >> 32 as libc::c_int - 6 as libc::c_int;
            a = (a as libc::c_uint).wrapping_add(c) as uint32_t as uint32_t;
            c = (c as libc::c_uint).wrapping_sub(b) as uint32_t as uint32_t;
            c ^= b << 8 as libc::c_int | b >> 32 as libc::c_int - 8 as libc::c_int;
            b = (b as libc::c_uint).wrapping_add(a) as uint32_t as uint32_t;
            a = (a as libc::c_uint).wrapping_sub(c) as uint32_t as uint32_t;
            a ^= c << 16 as libc::c_int | c >> 32 as libc::c_int - 16 as libc::c_int;
            c = (c as libc::c_uint).wrapping_add(b) as uint32_t as uint32_t;
            b = (b as libc::c_uint).wrapping_sub(a) as uint32_t as uint32_t;
            b ^= a << 19 as libc::c_int | a >> 32 as libc::c_int - 19 as libc::c_int;
            a = (a as libc::c_uint).wrapping_add(c) as uint32_t as uint32_t;
            c = (c as libc::c_uint).wrapping_sub(b) as uint32_t as uint32_t;
            c ^= b << 4 as libc::c_int | b >> 32 as libc::c_int - 4 as libc::c_int;
            b = (b as libc::c_uint).wrapping_add(a) as uint32_t as uint32_t;
            length = (length as libc::c_ulong)
                .wrapping_sub(12 as libc::c_int as libc::c_ulong) as size_t as size_t;
            k = k.offset(3 as libc::c_int as isize);
        }
        match length {
            12 => {
                c = (c as libc::c_uint)
                    .wrapping_add(*k.offset(2 as libc::c_int as isize)) as uint32_t
                    as uint32_t;
                b = (b as libc::c_uint)
                    .wrapping_add(*k.offset(1 as libc::c_int as isize)) as uint32_t
                    as uint32_t;
                a = (a as libc::c_uint)
                    .wrapping_add(*k.offset(0 as libc::c_int as isize)) as uint32_t
                    as uint32_t;
            }
            11 => {
                c = (c as libc::c_uint)
                    .wrapping_add(
                        *k.offset(2 as libc::c_int as isize)
                            & 0xffffff as libc::c_int as libc::c_uint,
                    ) as uint32_t as uint32_t;
                b = (b as libc::c_uint)
                    .wrapping_add(*k.offset(1 as libc::c_int as isize)) as uint32_t
                    as uint32_t;
                a = (a as libc::c_uint)
                    .wrapping_add(*k.offset(0 as libc::c_int as isize)) as uint32_t
                    as uint32_t;
            }
            10 => {
                c = (c as libc::c_uint)
                    .wrapping_add(
                        *k.offset(2 as libc::c_int as isize)
                            & 0xffff as libc::c_int as libc::c_uint,
                    ) as uint32_t as uint32_t;
                b = (b as libc::c_uint)
                    .wrapping_add(*k.offset(1 as libc::c_int as isize)) as uint32_t
                    as uint32_t;
                a = (a as libc::c_uint)
                    .wrapping_add(*k.offset(0 as libc::c_int as isize)) as uint32_t
                    as uint32_t;
            }
            9 => {
                c = (c as libc::c_uint)
                    .wrapping_add(
                        *k.offset(2 as libc::c_int as isize)
                            & 0xff as libc::c_int as libc::c_uint,
                    ) as uint32_t as uint32_t;
                b = (b as libc::c_uint)
                    .wrapping_add(*k.offset(1 as libc::c_int as isize)) as uint32_t
                    as uint32_t;
                a = (a as libc::c_uint)
                    .wrapping_add(*k.offset(0 as libc::c_int as isize)) as uint32_t
                    as uint32_t;
            }
            8 => {
                b = (b as libc::c_uint)
                    .wrapping_add(*k.offset(1 as libc::c_int as isize)) as uint32_t
                    as uint32_t;
                a = (a as libc::c_uint)
                    .wrapping_add(*k.offset(0 as libc::c_int as isize)) as uint32_t
                    as uint32_t;
            }
            7 => {
                b = (b as libc::c_uint)
                    .wrapping_add(
                        *k.offset(1 as libc::c_int as isize)
                            & 0xffffff as libc::c_int as libc::c_uint,
                    ) as uint32_t as uint32_t;
                a = (a as libc::c_uint)
                    .wrapping_add(*k.offset(0 as libc::c_int as isize)) as uint32_t
                    as uint32_t;
            }
            6 => {
                b = (b as libc::c_uint)
                    .wrapping_add(
                        *k.offset(1 as libc::c_int as isize)
                            & 0xffff as libc::c_int as libc::c_uint,
                    ) as uint32_t as uint32_t;
                a = (a as libc::c_uint)
                    .wrapping_add(*k.offset(0 as libc::c_int as isize)) as uint32_t
                    as uint32_t;
            }
            5 => {
                b = (b as libc::c_uint)
                    .wrapping_add(
                        *k.offset(1 as libc::c_int as isize)
                            & 0xff as libc::c_int as libc::c_uint,
                    ) as uint32_t as uint32_t;
                a = (a as libc::c_uint)
                    .wrapping_add(*k.offset(0 as libc::c_int as isize)) as uint32_t
                    as uint32_t;
            }
            4 => {
                a = (a as libc::c_uint)
                    .wrapping_add(*k.offset(0 as libc::c_int as isize)) as uint32_t
                    as uint32_t;
            }
            3 => {
                a = (a as libc::c_uint)
                    .wrapping_add(
                        *k.offset(0 as libc::c_int as isize)
                            & 0xffffff as libc::c_int as libc::c_uint,
                    ) as uint32_t as uint32_t;
            }
            2 => {
                a = (a as libc::c_uint)
                    .wrapping_add(
                        *k.offset(0 as libc::c_int as isize)
                            & 0xffff as libc::c_int as libc::c_uint,
                    ) as uint32_t as uint32_t;
            }
            1 => {
                a = (a as libc::c_uint)
                    .wrapping_add(
                        *k.offset(0 as libc::c_int as isize)
                            & 0xff as libc::c_int as libc::c_uint,
                    ) as uint32_t as uint32_t;
            }
            0 => return c,
            _ => {}
        }
    } else if 1 as libc::c_int != 0
            && u.i & 0x1 as libc::c_int as libc::c_ulong
                == 0 as libc::c_int as libc::c_ulong
        {
        let mut k_0: *const uint16_t = key as *const uint16_t;
        let mut k8: *const uint8_t = 0 as *const uint8_t;
        while length > 12 as libc::c_int as libc::c_ulong {
            a = (a as libc::c_uint)
                .wrapping_add(
                    (*k_0.offset(0 as libc::c_int as isize) as libc::c_uint)
                        .wrapping_add(
                            (*k_0.offset(1 as libc::c_int as isize) as uint32_t)
                                << 16 as libc::c_int,
                        ),
                ) as uint32_t as uint32_t;
            b = (b as libc::c_uint)
                .wrapping_add(
                    (*k_0.offset(2 as libc::c_int as isize) as libc::c_uint)
                        .wrapping_add(
                            (*k_0.offset(3 as libc::c_int as isize) as uint32_t)
                                << 16 as libc::c_int,
                        ),
                ) as uint32_t as uint32_t;
            c = (c as libc::c_uint)
                .wrapping_add(
                    (*k_0.offset(4 as libc::c_int as isize) as libc::c_uint)
                        .wrapping_add(
                            (*k_0.offset(5 as libc::c_int as isize) as uint32_t)
                                << 16 as libc::c_int,
                        ),
                ) as uint32_t as uint32_t;
            a = (a as libc::c_uint).wrapping_sub(c) as uint32_t as uint32_t;
            a ^= c << 4 as libc::c_int | c >> 32 as libc::c_int - 4 as libc::c_int;
            c = (c as libc::c_uint).wrapping_add(b) as uint32_t as uint32_t;
            b = (b as libc::c_uint).wrapping_sub(a) as uint32_t as uint32_t;
            b ^= a << 6 as libc::c_int | a >> 32 as libc::c_int - 6 as libc::c_int;
            a = (a as libc::c_uint).wrapping_add(c) as uint32_t as uint32_t;
            c = (c as libc::c_uint).wrapping_sub(b) as uint32_t as uint32_t;
            c ^= b << 8 as libc::c_int | b >> 32 as libc::c_int - 8 as libc::c_int;
            b = (b as libc::c_uint).wrapping_add(a) as uint32_t as uint32_t;
            a = (a as libc::c_uint).wrapping_sub(c) as uint32_t as uint32_t;
            a ^= c << 16 as libc::c_int | c >> 32 as libc::c_int - 16 as libc::c_int;
            c = (c as libc::c_uint).wrapping_add(b) as uint32_t as uint32_t;
            b = (b as libc::c_uint).wrapping_sub(a) as uint32_t as uint32_t;
            b ^= a << 19 as libc::c_int | a >> 32 as libc::c_int - 19 as libc::c_int;
            a = (a as libc::c_uint).wrapping_add(c) as uint32_t as uint32_t;
            c = (c as libc::c_uint).wrapping_sub(b) as uint32_t as uint32_t;
            c ^= b << 4 as libc::c_int | b >> 32 as libc::c_int - 4 as libc::c_int;
            b = (b as libc::c_uint).wrapping_add(a) as uint32_t as uint32_t;
            length = (length as libc::c_ulong)
                .wrapping_sub(12 as libc::c_int as libc::c_ulong) as size_t as size_t;
            k_0 = k_0.offset(6 as libc::c_int as isize);
        }
        k8 = k_0 as *const uint8_t;
        let mut current_block_102: u64;
        match length {
            12 => {
                c = (c as libc::c_uint)
                    .wrapping_add(
                        (*k_0.offset(4 as libc::c_int as isize) as libc::c_uint)
                            .wrapping_add(
                                (*k_0.offset(5 as libc::c_int as isize) as uint32_t)
                                    << 16 as libc::c_int,
                            ),
                    ) as uint32_t as uint32_t;
                b = (b as libc::c_uint)
                    .wrapping_add(
                        (*k_0.offset(2 as libc::c_int as isize) as libc::c_uint)
                            .wrapping_add(
                                (*k_0.offset(3 as libc::c_int as isize) as uint32_t)
                                    << 16 as libc::c_int,
                            ),
                    ) as uint32_t as uint32_t;
                a = (a as libc::c_uint)
                    .wrapping_add(
                        (*k_0.offset(0 as libc::c_int as isize) as libc::c_uint)
                            .wrapping_add(
                                (*k_0.offset(1 as libc::c_int as isize) as uint32_t)
                                    << 16 as libc::c_int,
                            ),
                    ) as uint32_t as uint32_t;
                current_block_102 = 3812947724376655173;
            }
            11 => {
                c = (c as libc::c_uint)
                    .wrapping_add(
                        (*k8.offset(10 as libc::c_int as isize) as uint32_t)
                            << 16 as libc::c_int,
                    ) as uint32_t as uint32_t;
                current_block_102 = 17716880846291894159;
            }
            10 => {
                current_block_102 = 17716880846291894159;
            }
            9 => {
                c = (c as libc::c_uint)
                    .wrapping_add(*k8.offset(8 as libc::c_int as isize) as libc::c_uint)
                    as uint32_t as uint32_t;
                current_block_102 = 12253739152035783869;
            }
            8 => {
                current_block_102 = 12253739152035783869;
            }
            7 => {
                b = (b as libc::c_uint)
                    .wrapping_add(
                        (*k8.offset(6 as libc::c_int as isize) as uint32_t)
                            << 16 as libc::c_int,
                    ) as uint32_t as uint32_t;
                current_block_102 = 3862714763397931078;
            }
            6 => {
                current_block_102 = 3862714763397931078;
            }
            5 => {
                b = (b as libc::c_uint)
                    .wrapping_add(*k8.offset(4 as libc::c_int as isize) as libc::c_uint)
                    as uint32_t as uint32_t;
                current_block_102 = 926614003985312789;
            }
            4 => {
                current_block_102 = 926614003985312789;
            }
            3 => {
                a = (a as libc::c_uint)
                    .wrapping_add(
                        (*k8.offset(2 as libc::c_int as isize) as uint32_t)
                            << 16 as libc::c_int,
                    ) as uint32_t as uint32_t;
                current_block_102 = 15738368575629814624;
            }
            2 => {
                current_block_102 = 15738368575629814624;
            }
            1 => {
                a = (a as libc::c_uint)
                    .wrapping_add(*k8.offset(0 as libc::c_int as isize) as libc::c_uint)
                    as uint32_t as uint32_t;
                current_block_102 = 3812947724376655173;
            }
            0 => return c,
            _ => {
                current_block_102 = 3812947724376655173;
            }
        }
        match current_block_102 {
            3862714763397931078 => {
                b = (b as libc::c_uint)
                    .wrapping_add(*k_0.offset(2 as libc::c_int as isize) as libc::c_uint)
                    as uint32_t as uint32_t;
                a = (a as libc::c_uint)
                    .wrapping_add(
                        (*k_0.offset(0 as libc::c_int as isize) as libc::c_uint)
                            .wrapping_add(
                                (*k_0.offset(1 as libc::c_int as isize) as uint32_t)
                                    << 16 as libc::c_int,
                            ),
                    ) as uint32_t as uint32_t;
            }
            12253739152035783869 => {
                b = (b as libc::c_uint)
                    .wrapping_add(
                        (*k_0.offset(2 as libc::c_int as isize) as libc::c_uint)
                            .wrapping_add(
                                (*k_0.offset(3 as libc::c_int as isize) as uint32_t)
                                    << 16 as libc::c_int,
                            ),
                    ) as uint32_t as uint32_t;
                a = (a as libc::c_uint)
                    .wrapping_add(
                        (*k_0.offset(0 as libc::c_int as isize) as libc::c_uint)
                            .wrapping_add(
                                (*k_0.offset(1 as libc::c_int as isize) as uint32_t)
                                    << 16 as libc::c_int,
                            ),
                    ) as uint32_t as uint32_t;
            }
            17716880846291894159 => {
                c = (c as libc::c_uint)
                    .wrapping_add(*k_0.offset(4 as libc::c_int as isize) as libc::c_uint)
                    as uint32_t as uint32_t;
                b = (b as libc::c_uint)
                    .wrapping_add(
                        (*k_0.offset(2 as libc::c_int as isize) as libc::c_uint)
                            .wrapping_add(
                                (*k_0.offset(3 as libc::c_int as isize) as uint32_t)
                                    << 16 as libc::c_int,
                            ),
                    ) as uint32_t as uint32_t;
                a = (a as libc::c_uint)
                    .wrapping_add(
                        (*k_0.offset(0 as libc::c_int as isize) as libc::c_uint)
                            .wrapping_add(
                                (*k_0.offset(1 as libc::c_int as isize) as uint32_t)
                                    << 16 as libc::c_int,
                            ),
                    ) as uint32_t as uint32_t;
            }
            926614003985312789 => {
                a = (a as libc::c_uint)
                    .wrapping_add(
                        (*k_0.offset(0 as libc::c_int as isize) as libc::c_uint)
                            .wrapping_add(
                                (*k_0.offset(1 as libc::c_int as isize) as uint32_t)
                                    << 16 as libc::c_int,
                            ),
                    ) as uint32_t as uint32_t;
            }
            15738368575629814624 => {
                a = (a as libc::c_uint)
                    .wrapping_add(*k_0.offset(0 as libc::c_int as isize) as libc::c_uint)
                    as uint32_t as uint32_t;
            }
            _ => {}
        }
    } else {
        let mut k_1: *const uint8_t = key as *const uint8_t;
        while length > 12 as libc::c_int as libc::c_ulong {
            a = (a as libc::c_uint)
                .wrapping_add(*k_1.offset(0 as libc::c_int as isize) as libc::c_uint)
                as uint32_t as uint32_t;
            a = (a as libc::c_uint)
                .wrapping_add(
                    (*k_1.offset(1 as libc::c_int as isize) as uint32_t)
                        << 8 as libc::c_int,
                ) as uint32_t as uint32_t;
            a = (a as libc::c_uint)
                .wrapping_add(
                    (*k_1.offset(2 as libc::c_int as isize) as uint32_t)
                        << 16 as libc::c_int,
                ) as uint32_t as uint32_t;
            a = (a as libc::c_uint)
                .wrapping_add(
                    (*k_1.offset(3 as libc::c_int as isize) as uint32_t)
                        << 24 as libc::c_int,
                ) as uint32_t as uint32_t;
            b = (b as libc::c_uint)
                .wrapping_add(*k_1.offset(4 as libc::c_int as isize) as libc::c_uint)
                as uint32_t as uint32_t;
            b = (b as libc::c_uint)
                .wrapping_add(
                    (*k_1.offset(5 as libc::c_int as isize) as uint32_t)
                        << 8 as libc::c_int,
                ) as uint32_t as uint32_t;
            b = (b as libc::c_uint)
                .wrapping_add(
                    (*k_1.offset(6 as libc::c_int as isize) as uint32_t)
                        << 16 as libc::c_int,
                ) as uint32_t as uint32_t;
            b = (b as libc::c_uint)
                .wrapping_add(
                    (*k_1.offset(7 as libc::c_int as isize) as uint32_t)
                        << 24 as libc::c_int,
                ) as uint32_t as uint32_t;
            c = (c as libc::c_uint)
                .wrapping_add(*k_1.offset(8 as libc::c_int as isize) as libc::c_uint)
                as uint32_t as uint32_t;
            c = (c as libc::c_uint)
                .wrapping_add(
                    (*k_1.offset(9 as libc::c_int as isize) as uint32_t)
                        << 8 as libc::c_int,
                ) as uint32_t as uint32_t;
            c = (c as libc::c_uint)
                .wrapping_add(
                    (*k_1.offset(10 as libc::c_int as isize) as uint32_t)
                        << 16 as libc::c_int,
                ) as uint32_t as uint32_t;
            c = (c as libc::c_uint)
                .wrapping_add(
                    (*k_1.offset(11 as libc::c_int as isize) as uint32_t)
                        << 24 as libc::c_int,
                ) as uint32_t as uint32_t;
            a = (a as libc::c_uint).wrapping_sub(c) as uint32_t as uint32_t;
            a ^= c << 4 as libc::c_int | c >> 32 as libc::c_int - 4 as libc::c_int;
            c = (c as libc::c_uint).wrapping_add(b) as uint32_t as uint32_t;
            b = (b as libc::c_uint).wrapping_sub(a) as uint32_t as uint32_t;
            b ^= a << 6 as libc::c_int | a >> 32 as libc::c_int - 6 as libc::c_int;
            a = (a as libc::c_uint).wrapping_add(c) as uint32_t as uint32_t;
            c = (c as libc::c_uint).wrapping_sub(b) as uint32_t as uint32_t;
            c ^= b << 8 as libc::c_int | b >> 32 as libc::c_int - 8 as libc::c_int;
            b = (b as libc::c_uint).wrapping_add(a) as uint32_t as uint32_t;
            a = (a as libc::c_uint).wrapping_sub(c) as uint32_t as uint32_t;
            a ^= c << 16 as libc::c_int | c >> 32 as libc::c_int - 16 as libc::c_int;
            c = (c as libc::c_uint).wrapping_add(b) as uint32_t as uint32_t;
            b = (b as libc::c_uint).wrapping_sub(a) as uint32_t as uint32_t;
            b ^= a << 19 as libc::c_int | a >> 32 as libc::c_int - 19 as libc::c_int;
            a = (a as libc::c_uint).wrapping_add(c) as uint32_t as uint32_t;
            c = (c as libc::c_uint).wrapping_sub(b) as uint32_t as uint32_t;
            c ^= b << 4 as libc::c_int | b >> 32 as libc::c_int - 4 as libc::c_int;
            b = (b as libc::c_uint).wrapping_add(a) as uint32_t as uint32_t;
            length = (length as libc::c_ulong)
                .wrapping_sub(12 as libc::c_int as libc::c_ulong) as size_t as size_t;
            k_1 = k_1.offset(12 as libc::c_int as isize);
        }
        let mut current_block_153: u64;
        match length {
            12 => {
                c = (c as libc::c_uint)
                    .wrapping_add(
                        (*k_1.offset(11 as libc::c_int as isize) as uint32_t)
                            << 24 as libc::c_int,
                    ) as uint32_t as uint32_t;
                current_block_153 = 1262026176713787085;
            }
            11 => {
                current_block_153 = 1262026176713787085;
            }
            10 => {
                current_block_153 = 15858282676831961289;
            }
            9 => {
                current_block_153 = 146692467702409633;
            }
            8 => {
                current_block_153 = 14834600852249877621;
            }
            7 => {
                current_block_153 = 12102259348290012528;
            }
            6 => {
                current_block_153 = 2808938937800950174;
            }
            5 => {
                current_block_153 = 5825461582505334826;
            }
            4 => {
                current_block_153 = 6100629464535663547;
            }
            3 => {
                current_block_153 = 10219713304939013295;
            }
            2 => {
                current_block_153 = 3089853308412511092;
            }
            1 => {
                current_block_153 = 3354027100822146892;
            }
            0 => return c,
            _ => {
                current_block_153 = 2704538829018177290;
            }
        }
        match current_block_153 {
            1262026176713787085 => {
                c = (c as libc::c_uint)
                    .wrapping_add(
                        (*k_1.offset(10 as libc::c_int as isize) as uint32_t)
                            << 16 as libc::c_int,
                    ) as uint32_t as uint32_t;
                current_block_153 = 15858282676831961289;
            }
            _ => {}
        }
        match current_block_153 {
            15858282676831961289 => {
                c = (c as libc::c_uint)
                    .wrapping_add(
                        (*k_1.offset(9 as libc::c_int as isize) as uint32_t)
                            << 8 as libc::c_int,
                    ) as uint32_t as uint32_t;
                current_block_153 = 146692467702409633;
            }
            _ => {}
        }
        match current_block_153 {
            146692467702409633 => {
                c = (c as libc::c_uint)
                    .wrapping_add(*k_1.offset(8 as libc::c_int as isize) as libc::c_uint)
                    as uint32_t as uint32_t;
                current_block_153 = 14834600852249877621;
            }
            _ => {}
        }
        match current_block_153 {
            14834600852249877621 => {
                b = (b as libc::c_uint)
                    .wrapping_add(
                        (*k_1.offset(7 as libc::c_int as isize) as uint32_t)
                            << 24 as libc::c_int,
                    ) as uint32_t as uint32_t;
                current_block_153 = 12102259348290012528;
            }
            _ => {}
        }
        match current_block_153 {
            12102259348290012528 => {
                b = (b as libc::c_uint)
                    .wrapping_add(
                        (*k_1.offset(6 as libc::c_int as isize) as uint32_t)
                            << 16 as libc::c_int,
                    ) as uint32_t as uint32_t;
                current_block_153 = 2808938937800950174;
            }
            _ => {}
        }
        match current_block_153 {
            2808938937800950174 => {
                b = (b as libc::c_uint)
                    .wrapping_add(
                        (*k_1.offset(5 as libc::c_int as isize) as uint32_t)
                            << 8 as libc::c_int,
                    ) as uint32_t as uint32_t;
                current_block_153 = 5825461582505334826;
            }
            _ => {}
        }
        match current_block_153 {
            5825461582505334826 => {
                b = (b as libc::c_uint)
                    .wrapping_add(*k_1.offset(4 as libc::c_int as isize) as libc::c_uint)
                    as uint32_t as uint32_t;
                current_block_153 = 6100629464535663547;
            }
            _ => {}
        }
        match current_block_153 {
            6100629464535663547 => {
                a = (a as libc::c_uint)
                    .wrapping_add(
                        (*k_1.offset(3 as libc::c_int as isize) as uint32_t)
                            << 24 as libc::c_int,
                    ) as uint32_t as uint32_t;
                current_block_153 = 10219713304939013295;
            }
            _ => {}
        }
        match current_block_153 {
            10219713304939013295 => {
                a = (a as libc::c_uint)
                    .wrapping_add(
                        (*k_1.offset(2 as libc::c_int as isize) as uint32_t)
                            << 16 as libc::c_int,
                    ) as uint32_t as uint32_t;
                current_block_153 = 3089853308412511092;
            }
            _ => {}
        }
        match current_block_153 {
            3089853308412511092 => {
                a = (a as libc::c_uint)
                    .wrapping_add(
                        (*k_1.offset(1 as libc::c_int as isize) as uint32_t)
                            << 8 as libc::c_int,
                    ) as uint32_t as uint32_t;
                current_block_153 = 3354027100822146892;
            }
            _ => {}
        }
        match current_block_153 {
            3354027100822146892 => {
                a = (a as libc::c_uint)
                    .wrapping_add(*k_1.offset(0 as libc::c_int as isize) as libc::c_uint)
                    as uint32_t as uint32_t;
            }
            _ => {}
        }
    }
    c ^= b;
    c = (c as libc::c_uint)
        .wrapping_sub(
            b << 14 as libc::c_int | b >> 32 as libc::c_int - 14 as libc::c_int,
        ) as uint32_t as uint32_t;
    a ^= c;
    a = (a as libc::c_uint)
        .wrapping_sub(
            c << 11 as libc::c_int | c >> 32 as libc::c_int - 11 as libc::c_int,
        ) as uint32_t as uint32_t;
    b ^= a;
    b = (b as libc::c_uint)
        .wrapping_sub(
            a << 25 as libc::c_int | a >> 32 as libc::c_int - 25 as libc::c_int,
        ) as uint32_t as uint32_t;
    c ^= b;
    c = (c as libc::c_uint)
        .wrapping_sub(
            b << 16 as libc::c_int | b >> 32 as libc::c_int - 16 as libc::c_int,
        ) as uint32_t as uint32_t;
    a ^= c;
    a = (a as libc::c_uint)
        .wrapping_sub(c << 4 as libc::c_int | c >> 32 as libc::c_int - 4 as libc::c_int)
        as uint32_t as uint32_t;
    b ^= a;
    b = (b as libc::c_uint)
        .wrapping_sub(
            a << 14 as libc::c_int | a >> 32 as libc::c_int - 14 as libc::c_int,
        ) as uint32_t as uint32_t;
    c ^= b;
    c = (c as libc::c_uint)
        .wrapping_sub(
            b << 24 as libc::c_int | b >> 32 as libc::c_int - 24 as libc::c_int,
        ) as uint32_t as uint32_t;
    return c;
}
unsafe extern "C" fn lh_perllike_str_hash(mut k: *const libc::c_void) -> libc::c_ulong {
    let mut rkey: *const libc::c_char = k as *const libc::c_char;
    let mut hashval: libc::c_uint = 1 as libc::c_int as libc::c_uint;
    while *rkey != 0 {
        let fresh0 = rkey;
        rkey = rkey.offset(1);
        hashval = hashval
            .wrapping_mul(33 as libc::c_int as libc::c_uint)
            .wrapping_add(*fresh0 as libc::c_uint);
    }
    return hashval as libc::c_ulong;
}
unsafe extern "C" fn lh_char_hash(mut k: *const libc::c_void) -> libc::c_ulong {
    static mut random_seed: libc::c_int = -(1 as libc::c_int);
    if random_seed == -(1 as libc::c_int) {
        let mut seed: libc::c_int = 0;
        loop {
            seed = json_c_get_random_seed();
            if !(seed == -(1 as libc::c_int)) {
                break;
            }
        }
        (::std::intrinsics::atomic_cxchg(&mut random_seed, -(1 as libc::c_int), seed)).0;
    }
    return hashlittle(
        k as *const libc::c_char as *const libc::c_void,
        strlen(k as *const libc::c_char),
        random_seed as uint32_t,
    ) as libc::c_ulong;
}
#[no_mangle]
pub unsafe extern "C" fn lh_char_equal(
    mut k1: *const libc::c_void,
    mut k2: *const libc::c_void,
) -> libc::c_int {
    return (strcmp(k1 as *const libc::c_char, k2 as *const libc::c_char)
        == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn lh_table_new(
    mut size: libc::c_int,
    mut free_fn: Option::<lh_entry_free_fn>,
    mut hash_fn: Option::<lh_hash_fn>,
    mut equal_fn: Option::<lh_equal_fn>,
) -> *mut lh_table {
    let mut i: libc::c_int = 0;
    let mut t: *mut lh_table = 0 as *mut lh_table;
    if size > 0 as libc::c_int {} else {
        __assert_fail(
            b"size > 0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/linkhash.c\0" as *const u8 as *const libc::c_char,
            504 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 84],
                &[libc::c_char; 84],
            >(
                b"struct lh_table *lh_table_new(int, lh_entry_free_fn *, lh_hash_fn *, lh_equal_fn *)\0",
            ))
                .as_ptr(),
        );
    }
    t = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::std::mem::size_of::<lh_table>() as libc::c_ulong,
    ) as *mut lh_table;
    if t.is_null() {
        return 0 as *mut lh_table;
    }
    (*t).count = 0 as libc::c_int;
    (*t).size = size;
    let ref mut fresh1 = (*t).table;
    *fresh1 = calloc(
        size as libc::c_ulong,
        ::std::mem::size_of::<lh_entry>() as libc::c_ulong,
    ) as *mut lh_entry;
    if ((*t).table).is_null() {
        free(t as *mut libc::c_void);
        return 0 as *mut lh_table;
    }
    let ref mut fresh2 = (*t).free_fn;
    *fresh2 = free_fn;
    let ref mut fresh3 = (*t).hash_fn;
    *fresh3 = hash_fn;
    let ref mut fresh4 = (*t).equal_fn;
    *fresh4 = equal_fn;
    i = 0 as libc::c_int;
    while i < size {
        let ref mut fresh5 = (*((*t).table).offset(i as isize)).k;
        *fresh5 = -(1 as libc::c_int) as *mut libc::c_void;
        i += 1;
    }
    return t;
}
#[no_mangle]
pub unsafe extern "C" fn lh_kchar_table_new(
    mut size: libc::c_int,
    mut free_fn: Option::<lh_entry_free_fn>,
) -> *mut lh_table {
    return lh_table_new(
        size,
        free_fn,
        char_hash_fn,
        Some(
            lh_char_equal
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
}
#[no_mangle]
pub unsafe extern "C" fn lh_kptr_table_new(
    mut size: libc::c_int,
    mut free_fn: Option::<lh_entry_free_fn>,
) -> *mut lh_table {
    return lh_table_new(
        size,
        free_fn,
        Some(lh_ptr_hash as unsafe extern "C" fn(*const libc::c_void) -> libc::c_ulong),
        Some(
            lh_ptr_equal
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
}
#[no_mangle]
pub unsafe extern "C" fn lh_table_resize(
    mut t: *mut lh_table,
    mut new_size: libc::c_int,
) -> libc::c_int {
    let mut new_t: *mut lh_table = 0 as *mut lh_table;
    let mut ent: *mut lh_entry = 0 as *mut lh_entry;
    new_t = lh_table_new(new_size, None, (*t).hash_fn, (*t).equal_fn);
    if new_t.is_null() {
        return -(1 as libc::c_int);
    }
    ent = (*t).head;
    while !ent.is_null() {
        let mut h: libc::c_ulong = lh_get_hash(new_t, (*ent).k);
        let mut opts: libc::c_uint = 0 as libc::c_int as libc::c_uint;
        if (*ent).k_is_constant != 0 {
            opts = ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint;
        }
        if lh_table_insert_w_hash(new_t, (*ent).k, (*ent).v, h, opts) != 0 as libc::c_int
        {
            lh_table_free(new_t);
            return -(1 as libc::c_int);
        }
        ent = (*ent).next;
    }
    free((*t).table as *mut libc::c_void);
    let ref mut fresh6 = (*t).table;
    *fresh6 = (*new_t).table;
    (*t).size = new_size;
    let ref mut fresh7 = (*t).head;
    *fresh7 = (*new_t).head;
    let ref mut fresh8 = (*t).tail;
    *fresh8 = (*new_t).tail;
    free(new_t as *mut libc::c_void);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn lh_table_free(mut t: *mut lh_table) {
    let mut c: *mut lh_entry = 0 as *mut lh_entry;
    if ((*t).free_fn).is_some() {
        c = (*t).head;
        while !c.is_null() {
            ((*t).free_fn).expect("non-null function pointer")(c);
            c = (*c).next;
        }
    }
    free((*t).table as *mut libc::c_void);
    free(t as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn lh_table_insert_w_hash(
    mut t: *mut lh_table,
    mut k: *const libc::c_void,
    mut v: *const libc::c_void,
    h: libc::c_ulong,
    opts: libc::c_uint,
) -> libc::c_int {
    let mut n: libc::c_ulong = 0;
    if (*t).count as libc::c_double >= (*t).size as libc::c_double * 0.66f64 {
        let mut new_size: libc::c_int = if (*t).size
            > 2147483647 as libc::c_int / 2 as libc::c_int
        {
            2147483647 as libc::c_int
        } else {
            (*t).size * 2 as libc::c_int
        };
        if (*t).size == 2147483647 as libc::c_int
            || lh_table_resize(t, new_size) != 0 as libc::c_int
        {
            return -(1 as libc::c_int);
        }
    }
    n = h.wrapping_rem((*t).size as libc::c_ulong);
    while !((*((*t).table).offset(n as isize)).k
        == -(1 as libc::c_int) as *mut libc::c_void as *const libc::c_void
        || (*((*t).table).offset(n as isize)).k
            == -(2 as libc::c_int) as *mut libc::c_void as *const libc::c_void)
    {
        n = n.wrapping_add(1);
        if n as libc::c_int == (*t).size {
            n = 0 as libc::c_int as libc::c_ulong;
        }
    }
    let ref mut fresh9 = (*((*t).table).offset(n as isize)).k;
    *fresh9 = k;
    (*((*t).table).offset(n as isize))
        .k_is_constant = (opts
        & ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint) as libc::c_int;
    let ref mut fresh10 = (*((*t).table).offset(n as isize)).v;
    *fresh10 = v;
    let ref mut fresh11 = (*t).count;
    *fresh11 += 1;
    if ((*t).head).is_null() {
        let ref mut fresh12 = (*t).tail;
        *fresh12 = &mut *((*t).table).offset(n as isize) as *mut lh_entry;
        let ref mut fresh13 = (*t).head;
        *fresh13 = *fresh12;
        let ref mut fresh14 = (*((*t).table).offset(n as isize)).prev;
        *fresh14 = 0 as *mut lh_entry;
        let ref mut fresh15 = (*((*t).table).offset(n as isize)).next;
        *fresh15 = *fresh14;
    } else {
        let ref mut fresh16 = (*(*t).tail).next;
        *fresh16 = &mut *((*t).table).offset(n as isize) as *mut lh_entry;
        let ref mut fresh17 = (*((*t).table).offset(n as isize)).prev;
        *fresh17 = (*t).tail;
        let ref mut fresh18 = (*((*t).table).offset(n as isize)).next;
        *fresh18 = 0 as *mut lh_entry;
        let ref mut fresh19 = (*t).tail;
        *fresh19 = &mut *((*t).table).offset(n as isize) as *mut lh_entry;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn lh_table_insert(
    mut t: *mut lh_table,
    mut k: *const libc::c_void,
    mut v: *const libc::c_void,
) -> libc::c_int {
    return lh_table_insert_w_hash(
        t,
        k,
        v,
        lh_get_hash(t, k),
        0 as libc::c_int as libc::c_uint,
    );
}
#[no_mangle]
pub unsafe extern "C" fn lh_table_lookup_entry_w_hash(
    mut t: *mut lh_table,
    mut k: *const libc::c_void,
    h: libc::c_ulong,
) -> *mut lh_entry {
    let mut n: libc::c_ulong = h.wrapping_rem((*t).size as libc::c_ulong);
    let mut count: libc::c_int = 0 as libc::c_int;
    while count < (*t).size {
        if (*((*t).table).offset(n as isize)).k
            == -(1 as libc::c_int) as *mut libc::c_void as *const libc::c_void
        {
            return 0 as *mut lh_entry;
        }
        if (*((*t).table).offset(n as isize)).k
            != -(2 as libc::c_int) as *mut libc::c_void as *const libc::c_void
            && ((*t).equal_fn)
                .expect(
                    "non-null function pointer",
                )((*((*t).table).offset(n as isize)).k, k) != 0
        {
            return &mut *((*t).table).offset(n as isize) as *mut lh_entry;
        }
        n = n.wrapping_add(1);
        if n as libc::c_int == (*t).size {
            n = 0 as libc::c_int as libc::c_ulong;
        }
        count += 1;
    }
    return 0 as *mut lh_entry;
}
#[no_mangle]
pub unsafe extern "C" fn lh_table_lookup_entry(
    mut t: *mut lh_table,
    mut k: *const libc::c_void,
) -> *mut lh_entry {
    return lh_table_lookup_entry_w_hash(t, k, lh_get_hash(t, k));
}
#[no_mangle]
pub unsafe extern "C" fn lh_table_lookup_ex(
    mut t: *mut lh_table,
    mut k: *const libc::c_void,
    mut v: *mut *mut libc::c_void,
) -> json_bool {
    let mut e: *mut lh_entry = lh_table_lookup_entry(t, k);
    if !e.is_null() {
        if !v.is_null() {
            *v = lh_entry_v(e);
        }
        return 1 as libc::c_int;
    }
    if !v.is_null() {
        *v = 0 as *mut libc::c_void;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn lh_table_delete_entry(
    mut t: *mut lh_table,
    mut e: *mut lh_entry,
) -> libc::c_int {
    let mut n: ptrdiff_t = e.offset_from((*t).table) as libc::c_long;
    if n < 0 as libc::c_int as libc::c_long {
        return -(2 as libc::c_int);
    }
    if (*((*t).table).offset(n as isize)).k
        == -(1 as libc::c_int) as *mut libc::c_void as *const libc::c_void
        || (*((*t).table).offset(n as isize)).k
            == -(2 as libc::c_int) as *mut libc::c_void as *const libc::c_void
    {
        return -(1 as libc::c_int);
    }
    let ref mut fresh20 = (*t).count;
    *fresh20 -= 1;
    if ((*t).free_fn).is_some() {
        ((*t).free_fn).expect("non-null function pointer")(e);
    }
    let ref mut fresh21 = (*((*t).table).offset(n as isize)).v;
    *fresh21 = 0 as *const libc::c_void;
    let ref mut fresh22 = (*((*t).table).offset(n as isize)).k;
    *fresh22 = -(2 as libc::c_int) as *mut libc::c_void;
    if (*t).tail == &mut *((*t).table).offset(n as isize) as *mut lh_entry
        && (*t).head == &mut *((*t).table).offset(n as isize) as *mut lh_entry
    {
        let ref mut fresh23 = (*t).tail;
        *fresh23 = 0 as *mut lh_entry;
        let ref mut fresh24 = (*t).head;
        *fresh24 = *fresh23;
    } else if (*t).head == &mut *((*t).table).offset(n as isize) as *mut lh_entry {
        let ref mut fresh25 = (*(*(*t).head).next).prev;
        *fresh25 = 0 as *mut lh_entry;
        let ref mut fresh26 = (*t).head;
        *fresh26 = (*(*t).head).next;
    } else if (*t).tail == &mut *((*t).table).offset(n as isize) as *mut lh_entry {
        let ref mut fresh27 = (*(*(*t).tail).prev).next;
        *fresh27 = 0 as *mut lh_entry;
        let ref mut fresh28 = (*t).tail;
        *fresh28 = (*(*t).tail).prev;
    } else {
        let ref mut fresh29 = (*(*((*t).table).offset(n as isize)).prev).next;
        *fresh29 = (*((*t).table).offset(n as isize)).next;
        let ref mut fresh30 = (*(*((*t).table).offset(n as isize)).next).prev;
        *fresh30 = (*((*t).table).offset(n as isize)).prev;
    }
    let ref mut fresh31 = (*((*t).table).offset(n as isize)).prev;
    *fresh31 = 0 as *mut lh_entry;
    let ref mut fresh32 = (*((*t).table).offset(n as isize)).next;
    *fresh32 = *fresh31;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn lh_table_delete(
    mut t: *mut lh_table,
    mut k: *const libc::c_void,
) -> libc::c_int {
    let mut e: *mut lh_entry = lh_table_lookup_entry(t, k);
    if e.is_null() {
        return -(1 as libc::c_int);
    }
    return lh_table_delete_entry(t, e);
}
#[no_mangle]
pub unsafe extern "C" fn lh_table_length(mut t: *mut lh_table) -> libc::c_int {
    return (*t).count;
}
