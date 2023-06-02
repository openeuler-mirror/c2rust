use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type json_object;
    fn __assert_fail(
        __assertion: *const i8,
        __file: *const i8,
        __line: u32,
        __function: *const i8,
    ) -> !;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const i8, _: ...) -> i32;
    fn printf(_: *const i8, _: ...) -> i32;
    fn snprintf(_: *mut i8, _: u64, _: *const i8, _: ...) -> i32;
    fn putchar(__c: i32) -> i32;
    fn puts(__s: *const i8) -> i32;
    fn abort() -> !;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn json_object_put(obj: *mut json_object) -> i32;
    fn json_object_to_json_string(obj: *mut json_object) -> *const i8;
    fn json_object_new_object() -> *mut json_object;
    fn json_object_object_length(obj: *const json_object) -> i32;
    fn json_object_object_add(obj: *mut json_object, key: *const i8, val: *mut json_object) -> i32;
    fn json_object_new_int(i: int32_t) -> *mut json_object;
    fn json_object_get_string(obj: *mut json_object) -> *const i8;
    fn json_tokener_parse(str: *const i8) -> *mut json_object;
}
pub type size_t = u64;
pub type __int32_t = i32;
pub type __off_t = i64;
pub type __off64_t = i64;
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
pub type int32_t = __int32_t;
#[no_mangle]
pub extern "C" fn print_hex(mut s: *const i8) {
    let mut iter: *const i8 = s;
    let mut ch: u8 = 0;
    loop {
        let fresh0 = iter;
        iter = unsafe { iter.offset(1) };
        ch = (unsafe { *fresh0 }) as u8;
        if !(ch as i32 != 0 as i32) {
            break;
        }
        if ',' as i32 != ch as i32 {
            (unsafe { printf(b"%x \0" as *const u8 as *const i8, ch as i32) });
        } else {
            (unsafe { printf(b",\0" as *const u8 as *const i8) });
        }
    }
    (unsafe { putchar('\n' as i32) });
}
extern "C" fn test_lot_of_adds() {
    let mut ii: i32 = 0;
    let mut key: [i8; 50] = [0; 50];
    let mut jobj: *mut json_object = unsafe { json_object_new_object() };
    if !jobj.is_null() {
    } else {
        (unsafe { __assert_fail(
            b"jobj != NULL\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test4.c\0" as *const u8 as *const i8,
            39 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_lot_of_adds(void)\0"))
                .as_ptr(),
        ) });
    }
    ii = 0 as i32;
    while ii < 500 as i32 {
        (unsafe { snprintf(
            key.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 50]>() as u64,
            b"k%d\0" as *const u8 as *const i8,
            ii,
        ) });
        let mut iobj: *mut json_object = unsafe { json_object_new_int(ii) };
        if !iobj.is_null() {
        } else {
            (unsafe { __assert_fail(
                b"iobj != NULL\0" as *const u8 as *const i8,
                b"/home/xial/json-c/tests/test4.c\0" as *const u8 as *const i8,
                44 as i32 as u32,
                (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_lot_of_adds(void)\0"))
                    .as_ptr(),
            ) });
        }
        if (unsafe { json_object_object_add(jobj, key.as_mut_ptr(), iobj) }) != 0 {
            (unsafe { fprintf(
                stderr,
                b"FAILED to add object #%d\n\0" as *const u8 as *const i8,
                ii,
            ) });
            (unsafe { abort() });
        }
        ii += 1;
    }
    (unsafe { printf(
        b"%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(jobj),
    ) });
    if (unsafe { json_object_object_length(jobj) }) == 500 as i32 {
    } else {
        (unsafe { __assert_fail(
            b"json_object_object_length(jobj) == 500\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test4.c\0" as *const u8 as *const i8,
            52 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"void test_lot_of_adds(void)\0"))
                .as_ptr(),
        ) });
    }
    (unsafe { json_object_put(jobj) });
}
fn main_0() -> i32 {
    let mut input: *const i8 = b"\"\\ud840\\udd26,\\ud840\\udd27,\\ud800\\udd26,\\ud800\\udd27\"\0"
        as *const u8 as *const i8;
    let mut expected: *const i8 =
        b"\xF0\xA0\x84\xA6,\xF0\xA0\x84\xA7,\xF0\x90\x84\xA6,\xF0\x90\x84\xA7\0" as *const u8
            as *const i8;
    let mut parse_result: *mut json_object = unsafe { json_tokener_parse(input) };
    let mut unjson: *const i8 = unsafe { json_object_get_string(parse_result) };
    (unsafe { printf(b"input: %s\n\0" as *const u8 as *const i8, input) });
    let mut strings_match: i32 = ((unsafe { strcmp(expected, unjson) }) == 0) as i32;
    let mut retval: i32 = 0 as i32;
    if strings_match != 0 {
        (unsafe { printf(
            b"JSON parse result is correct: %s\n\0" as *const u8 as *const i8,
            unjson,
        ) });
        (unsafe { puts(b"PASS\0" as *const u8 as *const i8) });
    } else {
        (unsafe { printf(b"JSON parse result doesn't match expected string\n\0" as *const u8 as *const i8) });
        (unsafe { printf(b"expected string bytes: \0" as *const u8 as *const i8) });
        print_hex(expected);
        (unsafe { printf(b"parsed string bytes:   \0" as *const u8 as *const i8) });
        print_hex(unjson);
        (unsafe { puts(b"FAIL\0" as *const u8 as *const i8) });
        retval = 1 as i32;
    }
    (unsafe { json_object_put(parse_result) });
    test_lot_of_adds();
    return retval;
}
pub fn main() {
     ::std::process::exit(main_0() as i32)
}
