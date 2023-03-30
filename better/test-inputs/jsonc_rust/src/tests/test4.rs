use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type json_object;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn putchar(__c: libc::c_int) -> libc::c_int;
    fn puts(__s: *const libc::c_char) -> libc::c_int;
    fn abort() -> !;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn json_object_put(obj: *mut json_object) -> libc::c_int;
    fn json_object_to_json_string(obj: *mut json_object) -> *const libc::c_char;
    fn json_object_new_object() -> *mut json_object;
    fn json_object_object_length(obj: *const json_object) -> libc::c_int;
    fn json_object_object_add(
        obj: *mut json_object,
        key: *const libc::c_char,
        val: *mut json_object,
    ) -> libc::c_int;
    fn json_object_new_int(i: int32_t) -> *mut json_object;
    fn json_object_get_string(obj: *mut json_object) -> *const libc::c_char;
    fn json_tokener_parse(str: *const libc::c_char) -> *mut json_object;
}
pub type size_t = libc::c_ulong;
pub type __int32_t = libc::c_int;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
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
pub type int32_t = __int32_t;
#[no_mangle]
pub unsafe extern "C" fn print_hex(mut s: *const libc::c_char) {
    let mut iter: *const libc::c_char = s;
    let mut ch: libc::c_uchar = 0;
    loop {
        let fresh0 = iter;
        iter = iter.offset(1);
        ch = *fresh0 as libc::c_uchar;
        if !(ch as libc::c_int != 0 as libc::c_int) {
            break;
        }
        if ',' as i32 != ch as libc::c_int {
            printf(b"%x \0" as *const u8 as *const libc::c_char, ch as libc::c_int);
        } else {
            printf(b",\0" as *const u8 as *const libc::c_char);
        }
    }
    putchar('\n' as i32);
}
unsafe extern "C" fn test_lot_of_adds() {
    let mut ii: libc::c_int = 0;
    let mut key: [libc::c_char; 50] = [0; 50];
    let mut jobj: *mut json_object = json_object_new_object();
    if !jobj.is_null() {} else {
        __assert_fail(
            b"jobj != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test4.c\0" as *const u8 as *const libc::c_char,
            39 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 28],
                &[libc::c_char; 28],
            >(b"void test_lot_of_adds(void)\0"))
                .as_ptr(),
        );
    }
    ii = 0 as libc::c_int;
    while ii < 500 as libc::c_int {
        snprintf(
            key.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 50]>() as libc::c_ulong,
            b"k%d\0" as *const u8 as *const libc::c_char,
            ii,
        );
        let mut iobj: *mut json_object = json_object_new_int(ii);
        if !iobj.is_null() {} else {
            __assert_fail(
                b"iobj != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/xial/json-c/tests/test4.c\0" as *const u8 as *const libc::c_char,
                44 as libc::c_int as libc::c_uint,
                (*::std::mem::transmute::<
                    &[u8; 28],
                    &[libc::c_char; 28],
                >(b"void test_lot_of_adds(void)\0"))
                    .as_ptr(),
            );
        }
        if json_object_object_add(jobj, key.as_mut_ptr(), iobj) != 0 {
            fprintf(
                stderr,
                b"FAILED to add object #%d\n\0" as *const u8 as *const libc::c_char,
                ii,
            );
            abort();
        }
        ii += 1;
    }
    printf(
        b"%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(jobj),
    );
    if json_object_object_length(jobj) == 500 as libc::c_int {} else {
        __assert_fail(
            b"json_object_object_length(jobj) == 500\0" as *const u8
                as *const libc::c_char,
            b"/home/xial/json-c/tests/test4.c\0" as *const u8 as *const libc::c_char,
            52 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 28],
                &[libc::c_char; 28],
            >(b"void test_lot_of_adds(void)\0"))
                .as_ptr(),
        );
    }
    json_object_put(jobj);
}
unsafe fn main_0() -> libc::c_int {
    let mut input: *const libc::c_char = b"\"\\ud840\\udd26,\\ud840\\udd27,\\ud800\\udd26,\\ud800\\udd27\"\0"
        as *const u8 as *const libc::c_char;
    let mut expected: *const libc::c_char = b"\xF0\xA0\x84\xA6,\xF0\xA0\x84\xA7,\xF0\x90\x84\xA6,\xF0\x90\x84\xA7\0"
        as *const u8 as *const libc::c_char;
    let mut parse_result: *mut json_object = json_tokener_parse(input);
    let mut unjson: *const libc::c_char = json_object_get_string(parse_result);
    printf(b"input: %s\n\0" as *const u8 as *const libc::c_char, input);
    let mut strings_match: libc::c_int = (strcmp(expected, unjson) == 0) as libc::c_int;
    let mut retval: libc::c_int = 0 as libc::c_int;
    if strings_match != 0 {
        printf(
            b"JSON parse result is correct: %s\n\0" as *const u8 as *const libc::c_char,
            unjson,
        );
        puts(b"PASS\0" as *const u8 as *const libc::c_char);
    } else {
        printf(
            b"JSON parse result doesn't match expected string\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(b"expected string bytes: \0" as *const u8 as *const libc::c_char);
        print_hex(expected);
        printf(b"parsed string bytes:   \0" as *const u8 as *const libc::c_char);
        print_hex(unjson);
        puts(b"FAIL\0" as *const u8 as *const libc::c_char);
        retval = 1 as libc::c_int;
    }
    json_object_put(parse_result);
    test_lot_of_adds();
    return retval;
}
pub fn main() {
    unsafe { ::std::process::exit(main_0() as i32) }
}
