use :: libc;
extern "C" {
    fn __assert_fail(
        __assertion: *const i8,
        __file: *const i8,
        __line: u32,
        __function: *const i8,
    ) -> !;
    fn calloc(_: u64, _: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn strlen(_: *const i8) -> u64;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn json_c_get_random_seed() -> i32;
}
pub type ptrdiff_t = i64;
pub type size_t = u64;
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uintptr_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct lh_entry {
    pub k: *const libc::c_void,
    pub k_is_constant: i32,
    pub v: *const libc::c_void,
    pub next: *mut lh_entry,
    pub prev: *mut lh_entry,
}
pub type json_bool = i32;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct lh_table {
    pub size: i32,
    pub count: i32,
    pub head: *mut lh_entry,
    pub tail: *mut lh_entry,
    pub table: *mut lh_entry,
    pub free_fn: Option<lh_entry_free_fn>,
    pub hash_fn: Option<lh_hash_fn>,
    pub equal_fn: Option<lh_equal_fn>,
}
pub type lh_equal_fn = unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> i32;
pub type lh_hash_fn = unsafe extern "C" fn(*const libc::c_void) -> u64;
pub type lh_entry_free_fn = unsafe extern "C" fn(*mut lh_entry) -> ();
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub ptr: *const libc::c_void,
    pub i: size_t,
}
#[inline]
extern "C" fn lh_entry_v(mut e: *const lh_entry) -> *mut libc::c_void {
    return (unsafe { (*e).v }) as uintptr_t as *mut libc::c_void;
}
#[inline]
extern "C" fn lh_get_hash(mut t: *const lh_table, mut k: *const libc::c_void) -> u64 {
    return unsafe { ((*t).hash_fn).expect("non-null function pointer")(k) };
}
static mut char_hash_fn: Option<lh_hash_fn> =
     Some(lh_char_hash as unsafe extern "C" fn(*const libc::c_void) -> u64);
#[no_mangle]
pub extern "C" fn json_global_set_string_hash(h: i32) -> i32 {
    match h {
        0 => {
            (unsafe { char_hash_fn = Some(lh_char_hash as unsafe extern "C" fn(*const libc::c_void) -> u64) });
        }
        1 => {
            (unsafe { char_hash_fn =
                Some(lh_perllike_str_hash as unsafe extern "C" fn(*const libc::c_void) -> u64) });
        }
        _ => return -(1 as i32),
    }
    return 0 as i32;
}
extern "C" fn lh_ptr_hash(mut k: *const libc::c_void) -> u64 {
    return (k as ptrdiff_t as u64).wrapping_mul(0x9e370001 as u64) >> 4 as i32
        & (9223372036854775807 as i64 as u64)
            .wrapping_mul(2 as u64)
            .wrapping_add(1 as u64);
}
#[no_mangle]
pub extern "C" fn lh_ptr_equal(mut k1: *const libc::c_void, mut k2: *const libc::c_void) -> i32 {
    return (k1 == k2) as i32;
}
extern "C" fn hashlittle(
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
    c = (0xdeadbeef as u32)
        .wrapping_add(length as uint32_t)
        .wrapping_add(initval);
    b = c;
    a = b;
    u.ptr = key;
    if 1 as i32 != 0 && (unsafe { u.i }) & 0x3 as i32 as u64 == 0 as i32 as u64 {
        let mut k: *const uint32_t = key as *const uint32_t;
        while length > 12 as i32 as u64 {
            a = (a as u32).wrapping_add(unsafe { *k.offset(0 as i32 as isize) }) as uint32_t as uint32_t;
            b = (b as u32).wrapping_add(unsafe { *k.offset(1 as i32 as isize) }) as uint32_t as uint32_t;
            c = (c as u32).wrapping_add(unsafe { *k.offset(2 as i32 as isize) }) as uint32_t as uint32_t;
            a = (a as u32).wrapping_sub(c) as uint32_t as uint32_t;
            a ^= c << 4 as i32 | c >> 32 as i32 - 4 as i32;
            c = (c as u32).wrapping_add(b) as uint32_t as uint32_t;
            b = (b as u32).wrapping_sub(a) as uint32_t as uint32_t;
            b ^= a << 6 as i32 | a >> 32 as i32 - 6 as i32;
            a = (a as u32).wrapping_add(c) as uint32_t as uint32_t;
            c = (c as u32).wrapping_sub(b) as uint32_t as uint32_t;
            c ^= b << 8 as i32 | b >> 32 as i32 - 8 as i32;
            b = (b as u32).wrapping_add(a) as uint32_t as uint32_t;
            a = (a as u32).wrapping_sub(c) as uint32_t as uint32_t;
            a ^= c << 16 as i32 | c >> 32 as i32 - 16 as i32;
            c = (c as u32).wrapping_add(b) as uint32_t as uint32_t;
            b = (b as u32).wrapping_sub(a) as uint32_t as uint32_t;
            b ^= a << 19 as i32 | a >> 32 as i32 - 19 as i32;
            a = (a as u32).wrapping_add(c) as uint32_t as uint32_t;
            c = (c as u32).wrapping_sub(b) as uint32_t as uint32_t;
            c ^= b << 4 as i32 | b >> 32 as i32 - 4 as i32;
            b = (b as u32).wrapping_add(a) as uint32_t as uint32_t;
            length = (length as u64).wrapping_sub(12 as i32 as u64) as size_t as size_t;
            k = unsafe { k.offset(3 as i32 as isize) };
        }
        match length {
            12 => {
                c = (c as u32).wrapping_add(unsafe { *k.offset(2 as i32 as isize) }) as uint32_t as uint32_t;
                b = (b as u32).wrapping_add(unsafe { *k.offset(1 as i32 as isize) }) as uint32_t as uint32_t;
                a = (a as u32).wrapping_add(unsafe { *k.offset(0 as i32 as isize) }) as uint32_t as uint32_t;
            }
            11 => {
                c = (c as u32).wrapping_add((unsafe { *k.offset(2 as i32 as isize) }) & 0xffffff as i32 as u32)
                    as uint32_t as uint32_t;
                b = (b as u32).wrapping_add(unsafe { *k.offset(1 as i32 as isize) }) as uint32_t as uint32_t;
                a = (a as u32).wrapping_add(unsafe { *k.offset(0 as i32 as isize) }) as uint32_t as uint32_t;
            }
            10 => {
                c = (c as u32).wrapping_add((unsafe { *k.offset(2 as i32 as isize) }) & 0xffff as i32 as u32)
                    as uint32_t as uint32_t;
                b = (b as u32).wrapping_add(unsafe { *k.offset(1 as i32 as isize) }) as uint32_t as uint32_t;
                a = (a as u32).wrapping_add(unsafe { *k.offset(0 as i32 as isize) }) as uint32_t as uint32_t;
            }
            9 => {
                c = (c as u32).wrapping_add((unsafe { *k.offset(2 as i32 as isize) }) & 0xff as i32 as u32)
                    as uint32_t as uint32_t;
                b = (b as u32).wrapping_add(unsafe { *k.offset(1 as i32 as isize) }) as uint32_t as uint32_t;
                a = (a as u32).wrapping_add(unsafe { *k.offset(0 as i32 as isize) }) as uint32_t as uint32_t;
            }
            8 => {
                b = (b as u32).wrapping_add(unsafe { *k.offset(1 as i32 as isize) }) as uint32_t as uint32_t;
                a = (a as u32).wrapping_add(unsafe { *k.offset(0 as i32 as isize) }) as uint32_t as uint32_t;
            }
            7 => {
                b = (b as u32).wrapping_add((unsafe { *k.offset(1 as i32 as isize) }) & 0xffffff as i32 as u32)
                    as uint32_t as uint32_t;
                a = (a as u32).wrapping_add(unsafe { *k.offset(0 as i32 as isize) }) as uint32_t as uint32_t;
            }
            6 => {
                b = (b as u32).wrapping_add((unsafe { *k.offset(1 as i32 as isize) }) & 0xffff as i32 as u32)
                    as uint32_t as uint32_t;
                a = (a as u32).wrapping_add(unsafe { *k.offset(0 as i32 as isize) }) as uint32_t as uint32_t;
            }
            5 => {
                b = (b as u32).wrapping_add((unsafe { *k.offset(1 as i32 as isize) }) & 0xff as i32 as u32)
                    as uint32_t as uint32_t;
                a = (a as u32).wrapping_add(unsafe { *k.offset(0 as i32 as isize) }) as uint32_t as uint32_t;
            }
            4 => {
                a = (a as u32).wrapping_add(unsafe { *k.offset(0 as i32 as isize) }) as uint32_t as uint32_t;
            }
            3 => {
                a = (a as u32).wrapping_add((unsafe { *k.offset(0 as i32 as isize) }) & 0xffffff as i32 as u32)
                    as uint32_t as uint32_t;
            }
            2 => {
                a = (a as u32).wrapping_add((unsafe { *k.offset(0 as i32 as isize) }) & 0xffff as i32 as u32)
                    as uint32_t as uint32_t;
            }
            1 => {
                a = (a as u32).wrapping_add((unsafe { *k.offset(0 as i32 as isize) }) & 0xff as i32 as u32)
                    as uint32_t as uint32_t;
            }
            0 => return c,
            _ => {}
        }
    } else if 1 as i32 != 0 && (unsafe { u.i }) & 0x1 as i32 as u64 == 0 as i32 as u64 {
        let mut k_0: *const uint16_t = key as *const uint16_t;
        let mut k8: *const uint8_t = 0 as *const uint8_t;
        while length > 12 as i32 as u64 {
            a = (a as u32).wrapping_add(
                ((unsafe { *k_0.offset(0 as i32 as isize) }) as u32)
                    .wrapping_add(((unsafe { *k_0.offset(1 as i32 as isize) }) as uint32_t) << 16 as i32),
            ) as uint32_t as uint32_t;
            b = (b as u32).wrapping_add(
                ((unsafe { *k_0.offset(2 as i32 as isize) }) as u32)
                    .wrapping_add(((unsafe { *k_0.offset(3 as i32 as isize) }) as uint32_t) << 16 as i32),
            ) as uint32_t as uint32_t;
            c = (c as u32).wrapping_add(
                ((unsafe { *k_0.offset(4 as i32 as isize) }) as u32)
                    .wrapping_add(((unsafe { *k_0.offset(5 as i32 as isize) }) as uint32_t) << 16 as i32),
            ) as uint32_t as uint32_t;
            a = (a as u32).wrapping_sub(c) as uint32_t as uint32_t;
            a ^= c << 4 as i32 | c >> 32 as i32 - 4 as i32;
            c = (c as u32).wrapping_add(b) as uint32_t as uint32_t;
            b = (b as u32).wrapping_sub(a) as uint32_t as uint32_t;
            b ^= a << 6 as i32 | a >> 32 as i32 - 6 as i32;
            a = (a as u32).wrapping_add(c) as uint32_t as uint32_t;
            c = (c as u32).wrapping_sub(b) as uint32_t as uint32_t;
            c ^= b << 8 as i32 | b >> 32 as i32 - 8 as i32;
            b = (b as u32).wrapping_add(a) as uint32_t as uint32_t;
            a = (a as u32).wrapping_sub(c) as uint32_t as uint32_t;
            a ^= c << 16 as i32 | c >> 32 as i32 - 16 as i32;
            c = (c as u32).wrapping_add(b) as uint32_t as uint32_t;
            b = (b as u32).wrapping_sub(a) as uint32_t as uint32_t;
            b ^= a << 19 as i32 | a >> 32 as i32 - 19 as i32;
            a = (a as u32).wrapping_add(c) as uint32_t as uint32_t;
            c = (c as u32).wrapping_sub(b) as uint32_t as uint32_t;
            c ^= b << 4 as i32 | b >> 32 as i32 - 4 as i32;
            b = (b as u32).wrapping_add(a) as uint32_t as uint32_t;
            length = (length as u64).wrapping_sub(12 as i32 as u64) as size_t as size_t;
            k_0 = unsafe { k_0.offset(6 as i32 as isize) };
        }
        k8 = k_0 as *const uint8_t;
        let mut current_block_102: u64;
        match length {
            12 => {
                c = (c as u32).wrapping_add(
                    ((unsafe { *k_0.offset(4 as i32 as isize) }) as u32)
                        .wrapping_add(((unsafe { *k_0.offset(5 as i32 as isize) }) as uint32_t) << 16 as i32),
                ) as uint32_t as uint32_t;
                b = (b as u32).wrapping_add(
                    ((unsafe { *k_0.offset(2 as i32 as isize) }) as u32)
                        .wrapping_add(((unsafe { *k_0.offset(3 as i32 as isize) }) as uint32_t) << 16 as i32),
                ) as uint32_t as uint32_t;
                a = (a as u32).wrapping_add(
                    ((unsafe { *k_0.offset(0 as i32 as isize) }) as u32)
                        .wrapping_add(((unsafe { *k_0.offset(1 as i32 as isize) }) as uint32_t) << 16 as i32),
                ) as uint32_t as uint32_t;
                current_block_102 = 3812947724376655173;
            }
            11 => {
                c = (c as u32)
                    .wrapping_add(((unsafe { *k8.offset(10 as i32 as isize) }) as uint32_t) << 16 as i32)
                    as uint32_t as uint32_t;
                current_block_102 = 17716880846291894159;
            }
            10 => {
                current_block_102 = 17716880846291894159;
            }
            9 => {
                c = (c as u32).wrapping_add((unsafe { *k8.offset(8 as i32 as isize) }) as u32) as uint32_t
                    as uint32_t;
                current_block_102 = 12253739152035783869;
            }
            8 => {
                current_block_102 = 12253739152035783869;
            }
            7 => {
                b = (b as u32)
                    .wrapping_add(((unsafe { *k8.offset(6 as i32 as isize) }) as uint32_t) << 16 as i32)
                    as uint32_t as uint32_t;
                current_block_102 = 3862714763397931078;
            }
            6 => {
                current_block_102 = 3862714763397931078;
            }
            5 => {
                b = (b as u32).wrapping_add((unsafe { *k8.offset(4 as i32 as isize) }) as u32) as uint32_t
                    as uint32_t;
                current_block_102 = 926614003985312789;
            }
            4 => {
                current_block_102 = 926614003985312789;
            }
            3 => {
                a = (a as u32)
                    .wrapping_add(((unsafe { *k8.offset(2 as i32 as isize) }) as uint32_t) << 16 as i32)
                    as uint32_t as uint32_t;
                current_block_102 = 15738368575629814624;
            }
            2 => {
                current_block_102 = 15738368575629814624;
            }
            1 => {
                a = (a as u32).wrapping_add((unsafe { *k8.offset(0 as i32 as isize) }) as u32) as uint32_t
                    as uint32_t;
                current_block_102 = 3812947724376655173;
            }
            0 => return c,
            _ => {
                current_block_102 = 3812947724376655173;
            }
        }
        match current_block_102 {
            3862714763397931078 => {
                b = (b as u32).wrapping_add((unsafe { *k_0.offset(2 as i32 as isize) }) as u32) as uint32_t
                    as uint32_t;
                a = (a as u32).wrapping_add(
                    ((unsafe { *k_0.offset(0 as i32 as isize) }) as u32)
                        .wrapping_add(((unsafe { *k_0.offset(1 as i32 as isize) }) as uint32_t) << 16 as i32),
                ) as uint32_t as uint32_t;
            }
            12253739152035783869 => {
                b = (b as u32).wrapping_add(
                    ((unsafe { *k_0.offset(2 as i32 as isize) }) as u32)
                        .wrapping_add(((unsafe { *k_0.offset(3 as i32 as isize) }) as uint32_t) << 16 as i32),
                ) as uint32_t as uint32_t;
                a = (a as u32).wrapping_add(
                    ((unsafe { *k_0.offset(0 as i32 as isize) }) as u32)
                        .wrapping_add(((unsafe { *k_0.offset(1 as i32 as isize) }) as uint32_t) << 16 as i32),
                ) as uint32_t as uint32_t;
            }
            17716880846291894159 => {
                c = (c as u32).wrapping_add((unsafe { *k_0.offset(4 as i32 as isize) }) as u32) as uint32_t
                    as uint32_t;
                b = (b as u32).wrapping_add(
                    ((unsafe { *k_0.offset(2 as i32 as isize) }) as u32)
                        .wrapping_add(((unsafe { *k_0.offset(3 as i32 as isize) }) as uint32_t) << 16 as i32),
                ) as uint32_t as uint32_t;
                a = (a as u32).wrapping_add(
                    ((unsafe { *k_0.offset(0 as i32 as isize) }) as u32)
                        .wrapping_add(((unsafe { *k_0.offset(1 as i32 as isize) }) as uint32_t) << 16 as i32),
                ) as uint32_t as uint32_t;
            }
            926614003985312789 => {
                a = (a as u32).wrapping_add(
                    ((unsafe { *k_0.offset(0 as i32 as isize) }) as u32)
                        .wrapping_add(((unsafe { *k_0.offset(1 as i32 as isize) }) as uint32_t) << 16 as i32),
                ) as uint32_t as uint32_t;
            }
            15738368575629814624 => {
                a = (a as u32).wrapping_add((unsafe { *k_0.offset(0 as i32 as isize) }) as u32) as uint32_t
                    as uint32_t;
            }
            _ => {}
        }
    } else {
        let mut k_1: *const uint8_t = key as *const uint8_t;
        while length > 12 as i32 as u64 {
            a = (a as u32).wrapping_add((unsafe { *k_1.offset(0 as i32 as isize) }) as u32) as uint32_t
                as uint32_t;
            a = (a as u32).wrapping_add(((unsafe { *k_1.offset(1 as i32 as isize) }) as uint32_t) << 8 as i32)
                as uint32_t as uint32_t;
            a = (a as u32).wrapping_add(((unsafe { *k_1.offset(2 as i32 as isize) }) as uint32_t) << 16 as i32)
                as uint32_t as uint32_t;
            a = (a as u32).wrapping_add(((unsafe { *k_1.offset(3 as i32 as isize) }) as uint32_t) << 24 as i32)
                as uint32_t as uint32_t;
            b = (b as u32).wrapping_add((unsafe { *k_1.offset(4 as i32 as isize) }) as u32) as uint32_t
                as uint32_t;
            b = (b as u32).wrapping_add(((unsafe { *k_1.offset(5 as i32 as isize) }) as uint32_t) << 8 as i32)
                as uint32_t as uint32_t;
            b = (b as u32).wrapping_add(((unsafe { *k_1.offset(6 as i32 as isize) }) as uint32_t) << 16 as i32)
                as uint32_t as uint32_t;
            b = (b as u32).wrapping_add(((unsafe { *k_1.offset(7 as i32 as isize) }) as uint32_t) << 24 as i32)
                as uint32_t as uint32_t;
            c = (c as u32).wrapping_add((unsafe { *k_1.offset(8 as i32 as isize) }) as u32) as uint32_t
                as uint32_t;
            c = (c as u32).wrapping_add(((unsafe { *k_1.offset(9 as i32 as isize) }) as uint32_t) << 8 as i32)
                as uint32_t as uint32_t;
            c = (c as u32).wrapping_add(((unsafe { *k_1.offset(10 as i32 as isize) }) as uint32_t) << 16 as i32)
                as uint32_t as uint32_t;
            c = (c as u32).wrapping_add(((unsafe { *k_1.offset(11 as i32 as isize) }) as uint32_t) << 24 as i32)
                as uint32_t as uint32_t;
            a = (a as u32).wrapping_sub(c) as uint32_t as uint32_t;
            a ^= c << 4 as i32 | c >> 32 as i32 - 4 as i32;
            c = (c as u32).wrapping_add(b) as uint32_t as uint32_t;
            b = (b as u32).wrapping_sub(a) as uint32_t as uint32_t;
            b ^= a << 6 as i32 | a >> 32 as i32 - 6 as i32;
            a = (a as u32).wrapping_add(c) as uint32_t as uint32_t;
            c = (c as u32).wrapping_sub(b) as uint32_t as uint32_t;
            c ^= b << 8 as i32 | b >> 32 as i32 - 8 as i32;
            b = (b as u32).wrapping_add(a) as uint32_t as uint32_t;
            a = (a as u32).wrapping_sub(c) as uint32_t as uint32_t;
            a ^= c << 16 as i32 | c >> 32 as i32 - 16 as i32;
            c = (c as u32).wrapping_add(b) as uint32_t as uint32_t;
            b = (b as u32).wrapping_sub(a) as uint32_t as uint32_t;
            b ^= a << 19 as i32 | a >> 32 as i32 - 19 as i32;
            a = (a as u32).wrapping_add(c) as uint32_t as uint32_t;
            c = (c as u32).wrapping_sub(b) as uint32_t as uint32_t;
            c ^= b << 4 as i32 | b >> 32 as i32 - 4 as i32;
            b = (b as u32).wrapping_add(a) as uint32_t as uint32_t;
            length = (length as u64).wrapping_sub(12 as i32 as u64) as size_t as size_t;
            k_1 = unsafe { k_1.offset(12 as i32 as isize) };
        }
        let mut current_block_153: u64;
        match length {
            12 => {
                c = (c as u32)
                    .wrapping_add(((unsafe { *k_1.offset(11 as i32 as isize) }) as uint32_t) << 24 as i32)
                    as uint32_t as uint32_t;
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
                c = (c as u32)
                    .wrapping_add(((unsafe { *k_1.offset(10 as i32 as isize) }) as uint32_t) << 16 as i32)
                    as uint32_t as uint32_t;
                current_block_153 = 15858282676831961289;
            }
            _ => {}
        }
        match current_block_153 {
            15858282676831961289 => {
                c = (c as u32)
                    .wrapping_add(((unsafe { *k_1.offset(9 as i32 as isize) }) as uint32_t) << 8 as i32)
                    as uint32_t as uint32_t;
                current_block_153 = 146692467702409633;
            }
            _ => {}
        }
        match current_block_153 {
            146692467702409633 => {
                c = (c as u32).wrapping_add((unsafe { *k_1.offset(8 as i32 as isize) }) as u32) as uint32_t
                    as uint32_t;
                current_block_153 = 14834600852249877621;
            }
            _ => {}
        }
        match current_block_153 {
            14834600852249877621 => {
                b = (b as u32)
                    .wrapping_add(((unsafe { *k_1.offset(7 as i32 as isize) }) as uint32_t) << 24 as i32)
                    as uint32_t as uint32_t;
                current_block_153 = 12102259348290012528;
            }
            _ => {}
        }
        match current_block_153 {
            12102259348290012528 => {
                b = (b as u32)
                    .wrapping_add(((unsafe { *k_1.offset(6 as i32 as isize) }) as uint32_t) << 16 as i32)
                    as uint32_t as uint32_t;
                current_block_153 = 2808938937800950174;
            }
            _ => {}
        }
        match current_block_153 {
            2808938937800950174 => {
                b = (b as u32)
                    .wrapping_add(((unsafe { *k_1.offset(5 as i32 as isize) }) as uint32_t) << 8 as i32)
                    as uint32_t as uint32_t;
                current_block_153 = 5825461582505334826;
            }
            _ => {}
        }
        match current_block_153 {
            5825461582505334826 => {
                b = (b as u32).wrapping_add((unsafe { *k_1.offset(4 as i32 as isize) }) as u32) as uint32_t
                    as uint32_t;
                current_block_153 = 6100629464535663547;
            }
            _ => {}
        }
        match current_block_153 {
            6100629464535663547 => {
                a = (a as u32)
                    .wrapping_add(((unsafe { *k_1.offset(3 as i32 as isize) }) as uint32_t) << 24 as i32)
                    as uint32_t as uint32_t;
                current_block_153 = 10219713304939013295;
            }
            _ => {}
        }
        match current_block_153 {
            10219713304939013295 => {
                a = (a as u32)
                    .wrapping_add(((unsafe { *k_1.offset(2 as i32 as isize) }) as uint32_t) << 16 as i32)
                    as uint32_t as uint32_t;
                current_block_153 = 3089853308412511092;
            }
            _ => {}
        }
        match current_block_153 {
            3089853308412511092 => {
                a = (a as u32)
                    .wrapping_add(((unsafe { *k_1.offset(1 as i32 as isize) }) as uint32_t) << 8 as i32)
                    as uint32_t as uint32_t;
                current_block_153 = 3354027100822146892;
            }
            _ => {}
        }
        match current_block_153 {
            3354027100822146892 => {
                a = (a as u32).wrapping_add((unsafe { *k_1.offset(0 as i32 as isize) }) as u32) as uint32_t
                    as uint32_t;
            }
            _ => {}
        }
    }
    c ^= b;
    c = (c as u32).wrapping_sub(b << 14 as i32 | b >> 32 as i32 - 14 as i32) as uint32_t
        as uint32_t;
    a ^= c;
    a = (a as u32).wrapping_sub(c << 11 as i32 | c >> 32 as i32 - 11 as i32) as uint32_t
        as uint32_t;
    b ^= a;
    b = (b as u32).wrapping_sub(a << 25 as i32 | a >> 32 as i32 - 25 as i32) as uint32_t
        as uint32_t;
    c ^= b;
    c = (c as u32).wrapping_sub(b << 16 as i32 | b >> 32 as i32 - 16 as i32) as uint32_t
        as uint32_t;
    a ^= c;
    a = (a as u32).wrapping_sub(c << 4 as i32 | c >> 32 as i32 - 4 as i32) as uint32_t as uint32_t;
    b ^= a;
    b = (b as u32).wrapping_sub(a << 14 as i32 | a >> 32 as i32 - 14 as i32) as uint32_t
        as uint32_t;
    c ^= b;
    c = (c as u32).wrapping_sub(b << 24 as i32 | b >> 32 as i32 - 24 as i32) as uint32_t
        as uint32_t;
    return c;
}
extern "C" fn lh_perllike_str_hash(mut k: *const libc::c_void) -> u64 {
    let mut rkey: *const i8 = k as *const i8;
    let mut hashval: u32 = 1 as i32 as u32;
    while (unsafe { *rkey }) != 0 {
        let fresh0 = rkey;
        rkey = unsafe { rkey.offset(1) };
        hashval = hashval
            .wrapping_mul(33 as i32 as u32)
            .wrapping_add((unsafe { *fresh0 }) as u32);
    }
    return hashval as u64;
}
extern "C" fn lh_char_hash(mut k: *const libc::c_void) -> u64 {
    static mut random_seed: i32 = -(1 as i32);
    if (unsafe { random_seed }) == -(1 as i32) {
        let mut seed: i32 = 0;
        loop {
            seed = unsafe { json_c_get_random_seed() };
            if !(seed == -(1 as i32)) {
                break;
            }
        }
        (unsafe { ::std::intrinsics::atomic_cxchg(&mut random_seed, -(1 as i32), seed) }).0;
    }
    return hashlittle(
        k as *const i8 as *const libc::c_void,
        unsafe { strlen(k as *const i8) },
        (unsafe { random_seed }) as uint32_t,
    ) as u64;
}
#[no_mangle]
pub extern "C" fn lh_char_equal(mut k1: *const libc::c_void, mut k2: *const libc::c_void) -> i32 {
    return ((unsafe { strcmp(k1 as *const i8, k2 as *const i8) }) == 0 as i32) as i32;
}
#[no_mangle]
pub extern "C" fn lh_table_new(
    mut size: i32,
    mut free_fn: Option<lh_entry_free_fn>,
    mut hash_fn: Option<lh_hash_fn>,
    mut equal_fn: Option<lh_equal_fn>,
) -> *mut lh_table {
    let mut i: i32 = 0;
    let mut t: *mut lh_table = 0 as *mut lh_table;
    if size > 0 as i32 {
    } else {
        (unsafe { __assert_fail (b"size > 0\0" as * const u8 as * const i8 , b"/home/xial/json-c/linkhash.c\0" as * const u8 as * const i8 , 504 as i32 as u32 , (* :: std :: mem :: transmute :: < & [u8 ; 84] , & [i8 ; 84] , > (b"struct lh_table *lh_table_new(int, lh_entry_free_fn *, lh_hash_fn *, lh_equal_fn *)\0" ,)) . as_ptr () ,) }) ;
    }
    t = (unsafe { calloc(1 as i32 as u64, ::std::mem::size_of::<lh_table>() as u64) }) as *mut lh_table;
    if t.is_null() {
        return 0 as *mut lh_table;
    }
    (unsafe { (*t).count = 0 as i32 });
    (unsafe { (*t).size = size });
    let fresh1 = unsafe { &mut ((*t).table) };
    *fresh1 = (unsafe { calloc(size as u64, ::std::mem::size_of::<lh_entry>() as u64) }) as *mut lh_entry;
    if (unsafe { (*t).table }).is_null() {
        (unsafe { free(t as *mut libc::c_void) });
        return 0 as *mut lh_table;
    }
    let fresh2 = unsafe { &mut ((*t).free_fn) };
    *fresh2 = free_fn;
    let fresh3 = unsafe { &mut ((*t).hash_fn) };
    *fresh3 = hash_fn;
    let fresh4 = unsafe { &mut ((*t).equal_fn) };
    *fresh4 = equal_fn;
    i = 0 as i32;
    while i < size {
        let fresh5 = unsafe { &mut ((*((*t).table).offset(i as isize)).k) };
        *fresh5 = -(1 as i32) as *mut libc::c_void;
        i += 1;
    }
    return t;
}
#[no_mangle]
pub extern "C" fn lh_kchar_table_new(
    mut size: i32,
    mut free_fn: Option<lh_entry_free_fn>,
) -> *mut lh_table {
    return lh_table_new(
        size,
        free_fn,
        unsafe { char_hash_fn },
        Some(
            lh_char_equal as unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> i32,
        ),
    );
}
#[no_mangle]
pub extern "C" fn lh_kptr_table_new(
    mut size: i32,
    mut free_fn: Option<lh_entry_free_fn>,
) -> *mut lh_table {
    return lh_table_new(
        size,
        free_fn,
        Some(lh_ptr_hash as unsafe extern "C" fn(*const libc::c_void) -> u64),
        Some(lh_ptr_equal as unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> i32),
    );
}
#[no_mangle]
pub extern "C" fn lh_table_resize(mut t: *mut lh_table, mut new_size: i32) -> i32 {
    let mut new_t: *mut lh_table = 0 as *mut lh_table;
    let mut ent: *mut lh_entry = 0 as *mut lh_entry;
    new_t = lh_table_new(new_size, None, unsafe { (*t).hash_fn }, unsafe { (*t).equal_fn });
    if new_t.is_null() {
        return -(1 as i32);
    }
    ent = unsafe { (*t).head };
    while !ent.is_null() {
        let mut h: u64 = lh_get_hash(new_t, unsafe { (*ent).k });
        let mut opts: u32 = 0 as i32 as u32;
        if (unsafe { (*ent).k_is_constant }) != 0 {
            opts = ((1 as i32) << 2 as i32) as u32;
        }
        if lh_table_insert_w_hash(new_t, unsafe { (*ent).k }, unsafe { (*ent).v }, h, opts) != 0 as i32 {
            lh_table_free(new_t);
            return -(1 as i32);
        }
        ent = unsafe { (*ent).next };
    }
    (unsafe { free((*t).table as *mut libc::c_void) });
    let fresh6 = unsafe { &mut ((*t).table) };
    *fresh6 = unsafe { (*new_t).table };
    (unsafe { (*t).size = new_size });
    let fresh7 = unsafe { &mut ((*t).head) };
    *fresh7 = unsafe { (*new_t).head };
    let fresh8 = unsafe { &mut ((*t).tail) };
    *fresh8 = unsafe { (*new_t).tail };
    (unsafe { free(new_t as *mut libc::c_void) });
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn lh_table_free(mut t: *mut lh_table) {
    let mut c: *mut lh_entry = 0 as *mut lh_entry;
    if unsafe { ((*t).free_fn).is_some() } {
        c = unsafe { (*t).head };
        while !c.is_null() {
            (unsafe { ((*t).free_fn).expect("non-null function pointer")(c) });
            c = unsafe { (*c).next };
        }
    }
    (unsafe { free((*t).table as *mut libc::c_void) });
    (unsafe { free(t as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn lh_table_insert_w_hash(
    mut t: *mut lh_table,
    mut k: *const libc::c_void,
    mut v: *const libc::c_void,
    h: u64,
    opts: u32,
) -> i32 {
    let mut n: u64 = 0;
    if (unsafe { (*t).count }) as f64 >= (unsafe { (*t).size }) as f64 * 0.66f64 {
        let mut new_size: i32 = if (unsafe { (*t).size }) > 2147483647 as i32 / 2 as i32 {
            2147483647 as i32
        } else {
            (unsafe { (*t).size }) * 2 as i32
        };
        if (unsafe { (*t).size }) == 2147483647 as i32 || lh_table_resize(t, new_size) != 0 as i32 {
            return -(1 as i32);
        }
    }
    n = h.wrapping_rem((unsafe { (*t).size }) as u64);
    while !((unsafe { (*((*t).table).offset(n as isize)).k })
        == -(1 as i32) as *mut libc::c_void as *const libc::c_void
        || (unsafe { (*((*t).table).offset(n as isize)).k })
            == -(2 as i32) as *mut libc::c_void as *const libc::c_void)
    {
        n = n.wrapping_add(1);
        if n as i32 == (unsafe { (*t).size }) {
            n = 0 as i32 as u64;
        }
    }
    let fresh9 = unsafe { &mut ((*((*t).table).offset(n as isize)).k) };
    *fresh9 = k;
    (unsafe { (*((*t).table).offset(n as isize)).k_is_constant =
        (opts & ((1 as i32) << 2 as i32) as u32) as i32 });
    let fresh10 = unsafe { &mut ((*((*t).table).offset(n as isize)).v) };
    *fresh10 = v;
    let fresh11 = unsafe { &mut ((*t).count) };
    *fresh11 += 1;
    if (unsafe { (*t).head }).is_null() {
        let fresh12 = unsafe { &mut ((*t).tail) };
        *fresh12 = (unsafe { &mut *((*t).table).offset(n as isize) }) as *mut lh_entry;
        let fresh13 = unsafe { &mut ((*t).head) };
        *fresh13 = *fresh12;
        let fresh14 = unsafe { &mut ((*((*t).table).offset(n as isize)).prev) };
        *fresh14 = 0 as *mut lh_entry;
        let fresh15 = unsafe { &mut ((*((*t).table).offset(n as isize)).next) };
        *fresh15 = *fresh14;
    } else {
        let fresh16 = unsafe { &mut ((*(*t).tail).next) };
        *fresh16 = (unsafe { &mut *((*t).table).offset(n as isize) }) as *mut lh_entry;
        let fresh17 = unsafe { &mut ((*((*t).table).offset(n as isize)).prev) };
        *fresh17 = unsafe { (*t).tail };
        let fresh18 = unsafe { &mut ((*((*t).table).offset(n as isize)).next) };
        *fresh18 = 0 as *mut lh_entry;
        let fresh19 = unsafe { &mut ((*t).tail) };
        *fresh19 = (unsafe { &mut *((*t).table).offset(n as isize) }) as *mut lh_entry;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn lh_table_insert(
    mut t: *mut lh_table,
    mut k: *const libc::c_void,
    mut v: *const libc::c_void,
) -> i32 {
    return lh_table_insert_w_hash(t, k, v, lh_get_hash(t, k), 0 as i32 as u32);
}
#[no_mangle]
pub extern "C" fn lh_table_lookup_entry_w_hash(
    mut t: *mut lh_table,
    mut k: *const libc::c_void,
    h: u64,
) -> *mut lh_entry {
    let mut n: u64 = h.wrapping_rem((unsafe { (*t).size }) as u64);
    let mut count: i32 = 0 as i32;
    while count < (unsafe { (*t).size }) {
        if (unsafe { (*((*t).table).offset(n as isize)).k })
            == -(1 as i32) as *mut libc::c_void as *const libc::c_void
        {
            return 0 as *mut lh_entry;
        }
        if (unsafe { (*((*t).table).offset(n as isize)).k })
            != -(2 as i32) as *mut libc::c_void as *const libc::c_void
            && (unsafe { ((*t).equal_fn).expect("non-null function pointer")(
                (*((*t).table).offset(n as isize)).k,
                k,
            ) }) != 0
        {
            return (unsafe { &mut *((*t).table).offset(n as isize) }) as *mut lh_entry;
        }
        n = n.wrapping_add(1);
        if n as i32 == (unsafe { (*t).size }) {
            n = 0 as i32 as u64;
        }
        count += 1;
    }
    return 0 as *mut lh_entry;
}
#[no_mangle]
pub extern "C" fn lh_table_lookup_entry(
    mut t: *mut lh_table,
    mut k: *const libc::c_void,
) -> *mut lh_entry {
    return lh_table_lookup_entry_w_hash(t, k, lh_get_hash(t, k));
}
#[no_mangle]
pub extern "C" fn lh_table_lookup_ex(
    mut t: *mut lh_table,
    mut k: *const libc::c_void,
    mut v: *mut *mut libc::c_void,
) -> json_bool {
    let mut e: *mut lh_entry = lh_table_lookup_entry(t, k);
    if !e.is_null() {
        if !v.is_null() {
            (unsafe { *v = lh_entry_v(e) });
        }
        return 1 as i32;
    }
    if !v.is_null() {
        (unsafe { *v = 0 as *mut libc::c_void });
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn lh_table_delete_entry(mut t: *mut lh_table, mut e: *mut lh_entry) -> i32 {
    let mut n: ptrdiff_t = (unsafe { e.offset_from((*t).table) }) as i64;
    if n < 0 as i32 as i64 {
        return -(2 as i32);
    }
    if (unsafe { (*((*t).table).offset(n as isize)).k })
        == -(1 as i32) as *mut libc::c_void as *const libc::c_void
        || (unsafe { (*((*t).table).offset(n as isize)).k })
            == -(2 as i32) as *mut libc::c_void as *const libc::c_void
    {
        return -(1 as i32);
    }
    let fresh20 = unsafe { &mut ((*t).count) };
    *fresh20 -= 1;
    if unsafe { ((*t).free_fn).is_some() } {
        (unsafe { ((*t).free_fn).expect("non-null function pointer")(e) });
    }
    let fresh21 = unsafe { &mut ((*((*t).table).offset(n as isize)).v) };
    *fresh21 = 0 as *const libc::c_void;
    let fresh22 = unsafe { &mut ((*((*t).table).offset(n as isize)).k) };
    *fresh22 = -(2 as i32) as *mut libc::c_void;
    if (unsafe { (*t).tail }) == (unsafe { &mut *((*t).table).offset(n as isize) }) as *mut lh_entry
        && (unsafe { (*t).head }) == (unsafe { &mut *((*t).table).offset(n as isize) }) as *mut lh_entry
    {
        let fresh23 = unsafe { &mut ((*t).tail) };
        *fresh23 = 0 as *mut lh_entry;
        let fresh24 = unsafe { &mut ((*t).head) };
        *fresh24 = *fresh23;
    } else if (unsafe { (*t).head }) == (unsafe { &mut *((*t).table).offset(n as isize) }) as *mut lh_entry {
        let fresh25 = unsafe { &mut ((*(*(*t).head).next).prev) };
        *fresh25 = 0 as *mut lh_entry;
        let fresh26 = unsafe { &mut ((*t).head) };
        *fresh26 = unsafe { (*(*t).head).next };
    } else if (unsafe { (*t).tail }) == (unsafe { &mut *((*t).table).offset(n as isize) }) as *mut lh_entry {
        let fresh27 = unsafe { &mut ((*(*(*t).tail).prev).next) };
        *fresh27 = 0 as *mut lh_entry;
        let fresh28 = unsafe { &mut ((*t).tail) };
        *fresh28 = unsafe { (*(*t).tail).prev };
    } else {
        let fresh29 = unsafe { &mut ((*(*((*t).table).offset(n as isize)).prev).next) };
        *fresh29 = unsafe { (*((*t).table).offset(n as isize)).next };
        let fresh30 = unsafe { &mut ((*(*((*t).table).offset(n as isize)).next).prev) };
        *fresh30 = unsafe { (*((*t).table).offset(n as isize)).prev };
    }
    let fresh31 = unsafe { &mut ((*((*t).table).offset(n as isize)).prev) };
    *fresh31 = 0 as *mut lh_entry;
    let fresh32 = unsafe { &mut ((*((*t).table).offset(n as isize)).next) };
    *fresh32 = *fresh31;
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn lh_table_delete(mut t: *mut lh_table, mut k: *const libc::c_void) -> i32 {
    let mut e: *mut lh_entry = lh_table_lookup_entry(t, k);
    if e.is_null() {
        return -(1 as i32);
    }
    return lh_table_delete_entry(t, e);
}
#[no_mangle]
pub extern "C" fn lh_table_length(mut t: *mut lh_table) -> i32 {
    return unsafe { (*t).count };
}
