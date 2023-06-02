use :: libc;
extern "C" {
    pub type json_object;
    fn __assert_fail(
        __assertion: *const i8,
        __file: *const i8,
        __line: u32,
        __function: *const i8,
    ) -> !;
    fn printf(_: *const i8, _: ...) -> i32;
    fn mc_set_debug(debug: i32);
    fn sprintbuf(p: *mut printbuf, msg: *const i8, _: ...) -> i32;
    fn json_object_get(obj: *mut json_object) -> *mut json_object;
    fn json_object_put(obj: *mut json_object) -> i32;
    fn json_object_to_json_string(obj: *mut json_object) -> *const i8;
    fn json_object_to_json_string_ext(obj: *mut json_object, flags: i32) -> *const i8;
    fn json_object_set_serializer(
        jso: *mut json_object,
        to_string_func: Option<json_object_to_json_string_fn>,
        userdata: *mut libc::c_void,
        user_delete: Option<json_object_delete_fn>,
    );
    fn json_object_new_object() -> *mut json_object;
    fn json_object_object_add(obj: *mut json_object, key: *const i8, val: *mut json_object) -> i32;
    fn json_object_new_int(i: int32_t) -> *mut json_object;
    fn json_object_new_double(d: f64) -> *mut json_object;
    fn json_object_double_to_json_string(
        jso: *mut json_object,
        pb: *mut printbuf,
        level: i32,
        flags: i32,
    ) -> i32;
    fn json_object_new_string(s: *const i8) -> *mut json_object;
}
pub type __int32_t = i32;
pub type int32_t = __int32_t;
pub type uintptr_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct printbuf {
    pub buf: *mut i8,
    pub bpos: i32,
    pub size: i32,
}
pub type json_object_delete_fn = unsafe extern "C" fn(*mut json_object, *mut libc::c_void) -> ();
pub type json_object_to_json_string_fn =
    unsafe extern "C" fn(*mut json_object, *mut printbuf, i32, i32) -> i32;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct myinfo {
    pub value: i32,
}
static mut freeit_was_called: i32 = 0 as i32;
extern "C" fn freeit(mut _jso: *mut json_object, mut userdata: *mut libc::c_void) {
    let mut info: *mut myinfo = userdata as *mut myinfo;
    (unsafe { printf(
        b"freeit, value=%d\n\0" as *const u8 as *const i8,
        (*info).value,
    ) });
    (unsafe { freeit_was_called = 1 as i32 });
}
extern "C" fn custom_serializer(
    mut _o: *mut json_object,
    mut pb: *mut printbuf,
    mut _level: i32,
    mut _flags: i32,
) -> i32 {
    (unsafe { sprintbuf(pb, b"Custom Output\0" as *const u8 as *const i8) });
    return 0 as i32;
}
fn main_0(mut _argc: i32, mut _argv: *mut *mut i8) -> i32 {
    let mut my_object: *mut json_object = 0 as *mut json_object;
    let mut my_sub_object: *mut json_object = 0 as *mut json_object;
    (unsafe { printf(b"Test setting, then resetting a custom serializer:\n\0" as *const u8 as *const i8) });
    my_object = unsafe { json_object_new_object() };
    (unsafe { json_object_object_add(
        my_object,
        b"abc\0" as *const u8 as *const i8,
        json_object_new_int(12 as i32),
    ) });
    (unsafe { json_object_object_add(
        my_object,
        b"foo\0" as *const u8 as *const i8,
        json_object_new_string(b"bar\0" as *const u8 as *const i8),
    ) });
    (unsafe { printf(
        b"my_object.to_string(standard)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(my_object),
    ) });
    let mut userdata: myinfo = {
        let mut init = myinfo { value: 123 as i32 };
        init
    };
    (unsafe { json_object_set_serializer(
        my_object,
        Some(
            custom_serializer
                as unsafe extern "C" fn(*mut json_object, *mut printbuf, i32, i32) -> i32,
        ),
        &mut userdata as *mut myinfo as *mut libc::c_void,
        Some(freeit as unsafe extern "C" fn(*mut json_object, *mut libc::c_void) -> ()),
    ) });
    (unsafe { printf(
        b"my_object.to_string(custom serializer)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(my_object),
    ) });
    (unsafe { printf(
        b"Next line of output should be from the custom freeit function:\n\0" as *const u8
            as *const i8,
    ) });
    (unsafe { freeit_was_called = 0 as i32 });
    (unsafe { json_object_set_serializer(my_object, None, 0 as *mut libc::c_void, None) });
    if (unsafe { freeit_was_called }) != 0 {
    } else {
        (unsafe { __assert_fail(
            b"freeit_was_called\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_serializer.c\0" as *const u8 as *const i8,
            52 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    (unsafe { printf(
        b"my_object.to_string(standard)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(my_object),
    ) });
    (unsafe { json_object_put(my_object) });
    my_object = unsafe { json_object_new_object() };
    (unsafe { printf(
        b"Check that the custom serializer isn't free'd until the last json_object_put:\n\0"
            as *const u8 as *const i8,
    ) });
    (unsafe { json_object_set_serializer(
        my_object,
        Some(
            custom_serializer
                as unsafe extern "C" fn(*mut json_object, *mut printbuf, i32, i32) -> i32,
        ),
        &mut userdata as *mut myinfo as *mut libc::c_void,
        Some(freeit as unsafe extern "C" fn(*mut json_object, *mut libc::c_void) -> ()),
    ) });
    (unsafe { json_object_get(my_object) });
    (unsafe { json_object_put(my_object) });
    (unsafe { printf(
        b"my_object.to_string(custom serializer)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(my_object),
    ) });
    (unsafe { printf(
        b"Next line of output should be from the custom freeit function:\n\0" as *const u8
            as *const i8,
    ) });
    (unsafe { freeit_was_called = 0 as i32 });
    (unsafe { json_object_put(my_object) });
    if (unsafe { freeit_was_called }) != 0 {
    } else {
        (unsafe { __assert_fail(
            b"freeit_was_called\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_serializer.c\0" as *const u8 as *const i8,
            71 as i32 as u32,
            (*::std::mem::transmute::<&[u8; 23], &[i8; 23]>(b"int main(int, char **)\0")).as_ptr(),
        ) });
    }
    my_object = unsafe { json_object_new_object() };
    my_sub_object = unsafe { json_object_new_double(1.0f64) };
    (unsafe { json_object_object_add(
        my_object,
        b"double\0" as *const u8 as *const i8,
        my_sub_object,
    ) });
    (unsafe { printf(
        b"Check that the custom serializer does not include nul byte:\n\0" as *const u8
            as *const i8,
    ) });
    (unsafe { json_object_set_serializer(
        my_sub_object,
        Some(
            json_object_double_to_json_string
                as unsafe extern "C" fn(*mut json_object, *mut printbuf, i32, i32) -> i32,
        ),
        b"%125.0f\0" as *const u8 as *const i8 as *const libc::c_void as uintptr_t
            as *mut libc::c_void,
        None,
    ) });
    (unsafe { printf(
        b"my_object.to_string(custom serializer)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string_ext(my_object, (1 as i32) << 2 as i32),
    ) });
    (unsafe { json_object_put(my_object) });
    return 0 as i32;
}
pub fn main() {
    let mut args: Vec<*mut i8> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::std::ptr::null_mut());
     {
        ::std::process::exit(
            main_0((args.len() - 1) as i32, args.as_mut_ptr() as *mut *mut i8) as i32,
        )
    }
}
