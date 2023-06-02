use :: libc;
extern "C" {
    fn __assert_fail(
        __assertion: *const i8,
        __file: *const i8,
        __line: u32,
        __function: *const i8,
    ) -> !;
    fn printf(_: *const i8, _: ...) -> i32;
}
pub use crate::src::{
    debug::mc_set_debug,
    json_object::{
        json_object, json_object_double_to_json_string, json_object_get, json_object_new_double,
        json_object_new_int, json_object_new_object, json_object_new_string,
        json_object_object_add, json_object_put, json_object_set_serializer,
        json_object_to_json_string, json_object_to_json_string_ext,
    },
    printbuf::sprintbuf,
};
pub type __int32_t = i32;
pub type int32_t = i32;
pub type uintptr_t = u64;
pub type printbuf = crate::src::apps::json_parse::printbuf;
pub type json_object_delete_fn = unsafe extern "C" fn(
    _: *mut crate::src::json_object::json_object,
    _: *mut core::ffi::c_void,
) -> ();
pub type json_object_to_json_string_fn = unsafe extern "C" fn(
    _: *mut crate::src::json_object::json_object,
    _: *mut crate::src::apps::json_parse::printbuf,
    _: i32,
    _: i32,
) -> i32;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct myinfo {
    pub value: i32,
}
impl myinfo {
    pub const fn new() -> Self {
        myinfo { value: 0 }
    }
}
impl std::default::Default for myinfo {
    fn default() -> Self {
        myinfo::new()
    }
}
static mut freeit_was_called: i32 = 0 as i32;
extern "C" fn freeit(
    mut _jso: *mut crate::src::json_object::json_object,
    mut userdata: *mut core::ffi::c_void,
) {
    let mut info: *mut crate::src::tests::test_set_serializer::myinfo = userdata as *mut myinfo;
    (unsafe { printf(
        b"freeit, value=%d\n\0" as *const u8 as *const i8,
        (*info).value,
    ) });
    (unsafe { freeit_was_called = 1 as i32 });
}
extern "C" fn custom_serializer(
    mut _o: *mut crate::src::json_object::json_object,
    mut pb: *mut crate::src::apps::json_parse::printbuf,
    mut _level: i32,
    mut _flags: i32,
) -> i32 {
    (unsafe { sprintbuf(pb, b"Custom Output\0" as *const u8 as *const i8) });
    return 0 as i32;
}
fn main_0(mut _argc: i32, mut _argv: *mut *mut i8) -> i32 {
    let mut my_object: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    let mut my_sub_object: *mut crate::src::json_object::json_object = 0 as *mut json_object;
    (unsafe { printf(b"Test setting, then resetting a custom serializer:\n\0" as *const u8 as *const i8) });
    my_object = json_object_new_object();
    json_object_object_add(
        my_object,
        b"abc\0" as *const u8 as *const i8,
        json_object_new_int(12 as i32),
    );
    json_object_object_add(
        my_object,
        b"foo\0" as *const u8 as *const i8,
        json_object_new_string(b"bar\0" as *const u8 as *const i8),
    );
    (unsafe { printf(
        b"my_object.to_string(standard)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(my_object),
    ) });
    let mut userdata: crate::src::tests::test_set_serializer::myinfo = {
        let mut init = myinfo { value: 123 as i32 };
        init
    };
    json_object_set_serializer(
        my_object,
        Some(custom_serializer),
        &mut userdata as *mut myinfo as *mut libc::c_void,
        Some(freeit),
    );
    (unsafe { printf(
        b"my_object.to_string(custom serializer)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(my_object),
    ) });
    (unsafe { printf(
        b"Next line of output should be from the custom freeit function:\n\0" as *const u8
            as *const i8,
    ) });
    (unsafe { freeit_was_called = 0 as i32 });
    json_object_set_serializer(my_object, None, 0 as *mut libc::c_void, None);
    if (unsafe { freeit_was_called }) != 0 {
    } else {
        (unsafe { __assert_fail(
            b"freeit_was_called\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_serializer.c\0" as *const u8 as *const i8,
            52 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    (unsafe { printf(
        b"my_object.to_string(standard)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(my_object),
    ) });
    json_object_put(my_object);
    my_object = json_object_new_object();
    (unsafe { printf(
        b"Check that the custom serializer isn't free'd until the last json_object_put:\n\0"
            as *const u8 as *const i8,
    ) });
    json_object_set_serializer(
        my_object,
        Some(custom_serializer),
        &mut userdata as *mut myinfo as *mut libc::c_void,
        Some(freeit),
    );
    json_object_get(my_object);
    json_object_put(my_object);
    (unsafe { printf(
        b"my_object.to_string(custom serializer)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(my_object),
    ) });
    (unsafe { printf(
        b"Next line of output should be from the custom freeit function:\n\0" as *const u8
            as *const i8,
    ) });
    (unsafe { freeit_was_called = 0 as i32 });
    json_object_put(my_object);
    if (unsafe { freeit_was_called }) != 0 {
    } else {
        (unsafe { __assert_fail(
            b"freeit_was_called\0" as *const u8 as *const i8,
            b"/home/xial/json-c/tests/test_set_serializer.c\0" as *const u8 as *const i8,
            71 as i32 as u32,
            (*core::intrinsics::transmute::<&'_ [u8; 23], &'_ [i8; 23]>(
                b"int main(int, char **)\0",
            ))
            .as_ptr(),
        ) });
    }
    my_object = json_object_new_object();
    my_sub_object = json_object_new_double(1.0f64);
    json_object_object_add(
        my_object,
        b"double\0" as *const u8 as *const i8,
        my_sub_object,
    );
    (unsafe { printf(
        b"Check that the custom serializer does not include nul byte:\n\0" as *const u8
            as *const i8,
    ) });
    json_object_set_serializer(
        my_sub_object,
        Some(json_object_double_to_json_string),
        b"%125.0f\0" as *const u8 as *const i8 as *const libc::c_void as uintptr_t
            as *mut libc::c_void,
        None,
    );
    (unsafe { printf(
        b"my_object.to_string(custom serializer)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string_ext(my_object, (1 as i32) << 2 as i32),
    ) });
    json_object_put(my_object);
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

