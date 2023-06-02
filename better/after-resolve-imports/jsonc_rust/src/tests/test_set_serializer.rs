use ::libc;
extern "C" {
    
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::debug::mc_set_debug;
pub use crate::src::json_object::json_object_double_to_json_string;
pub use crate::src::json_object::json_object_get;
pub use crate::src::json_object::json_object_new_double;
pub use crate::src::json_object::json_object_new_int;
pub use crate::src::json_object::json_object_new_object;
pub use crate::src::json_object::json_object_new_string;
pub use crate::src::json_object::json_object_object_add;
pub use crate::src::json_object::json_object_put;
pub use crate::src::json_object::json_object_set_serializer;
pub use crate::src::json_object::json_object_to_json_string;
pub use crate::src::json_object::json_object_to_json_string_ext;
pub use crate::src::printbuf::sprintbuf;
pub use crate::src::json_object::json_object;
pub type __int32_t = crate::src::json_object::__int32_t;
pub type int32_t = crate::src::json_object::int32_t;
pub type uintptr_t = crate::src::json_object::uintptr_t;
// #[derive(Copy, Clone)]

pub type printbuf = crate::src::apps::json_parse::printbuf;
pub type json_object_delete_fn = crate::src::json_object::json_object_delete_fn;
pub type json_object_to_json_string_fn = crate::src::json_object::json_object_to_json_string_fn;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct myinfo {
    pub value: libc::c_int,
}
static mut freeit_was_called: libc::c_int = 0 as libc::c_int;
unsafe extern "C" fn freeit(mut jso: *mut json_object, mut userdata: *mut libc::c_void) {
    let mut info: *mut myinfo = userdata as *mut myinfo;
    printf(b"freeit, value=%d\n\0" as *const u8 as *const libc::c_char, (*info).value);
    freeit_was_called = 1 as libc::c_int;
}
unsafe extern "C" fn custom_serializer(
    mut o: *mut json_object,
    mut pb: *mut printbuf,
    mut level: libc::c_int,
    mut flags: libc::c_int,
) -> libc::c_int {
    sprintbuf(pb, b"Custom Output\0" as *const u8 as *const libc::c_char);
    return 0 as libc::c_int;
}
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut my_object: *mut json_object = 0 as *mut json_object;
    let mut my_sub_object: *mut json_object = 0 as *mut json_object;
    printf(
        b"Test setting, then resetting a custom serializer:\n\0" as *const u8
            as *const libc::c_char,
    );
    my_object = json_object_new_object();
    json_object_object_add(
        my_object,
        b"abc\0" as *const u8 as *const libc::c_char,
        json_object_new_int(12 as libc::c_int),
    );
    json_object_object_add(
        my_object,
        b"foo\0" as *const u8 as *const libc::c_char,
        json_object_new_string(b"bar\0" as *const u8 as *const libc::c_char),
    );
    printf(
        b"my_object.to_string(standard)=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(my_object),
    );
    let mut userdata: myinfo = {
        let mut init = myinfo {
            value: 123 as libc::c_int,
        };
        init
    };
    json_object_set_serializer(
        my_object,
        Some(
            custom_serializer
                as unsafe extern "C" fn(
                    *mut json_object,
                    *mut printbuf,
                    libc::c_int,
                    libc::c_int,
                ) -> libc::c_int,
        ),
        &mut userdata as *mut myinfo as *mut libc::c_void,
        Some(freeit as unsafe extern "C" fn(*mut json_object, *mut libc::c_void) -> ()),
    );
    printf(
        b"my_object.to_string(custom serializer)=%s\n\0" as *const u8
            as *const libc::c_char,
        json_object_to_json_string(my_object),
    );
    printf(
        b"Next line of output should be from the custom freeit function:\n\0"
            as *const u8 as *const libc::c_char,
    );
    freeit_was_called = 0 as libc::c_int;
    json_object_set_serializer(my_object, None, 0 as *mut libc::c_void, None);
    if freeit_was_called != 0 {} else {
        __assert_fail(
            b"freeit_was_called\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_serializer.c\0" as *const u8
                as *const libc::c_char,
            52 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    printf(
        b"my_object.to_string(standard)=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(my_object),
    );
    json_object_put(my_object);
    my_object = json_object_new_object();
    printf(
        b"Check that the custom serializer isn't free'd until the last json_object_put:\n\0"
            as *const u8 as *const libc::c_char,
    );
    json_object_set_serializer(
        my_object,
        Some(
            custom_serializer
                as unsafe extern "C" fn(
                    *mut json_object,
                    *mut printbuf,
                    libc::c_int,
                    libc::c_int,
                ) -> libc::c_int,
        ),
        &mut userdata as *mut myinfo as *mut libc::c_void,
        Some(freeit as unsafe extern "C" fn(*mut json_object, *mut libc::c_void) -> ()),
    );
    json_object_get(my_object);
    json_object_put(my_object);
    printf(
        b"my_object.to_string(custom serializer)=%s\n\0" as *const u8
            as *const libc::c_char,
        json_object_to_json_string(my_object),
    );
    printf(
        b"Next line of output should be from the custom freeit function:\n\0"
            as *const u8 as *const libc::c_char,
    );
    freeit_was_called = 0 as libc::c_int;
    json_object_put(my_object);
    if freeit_was_called != 0 {} else {
        __assert_fail(
            b"freeit_was_called\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/tests/test_set_serializer.c\0" as *const u8
                as *const libc::c_char,
            71 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 23],
                &[libc::c_char; 23],
            >(b"int main(int, char **)\0"))
                .as_ptr(),
        );
    }
    my_object = json_object_new_object();
    my_sub_object = json_object_new_double(1.0f64);
    json_object_object_add(
        my_object,
        b"double\0" as *const u8 as *const libc::c_char,
        my_sub_object,
    );
    printf(
        b"Check that the custom serializer does not include nul byte:\n\0" as *const u8
            as *const libc::c_char,
    );
    json_object_set_serializer(
        my_sub_object,
        Some(
            json_object_double_to_json_string
                as unsafe extern "C" fn(
                    *mut json_object,
                    *mut printbuf,
                    libc::c_int,
                    libc::c_int,
                ) -> libc::c_int,
        ),
        b"%125.0f\0" as *const u8 as *const libc::c_char as *const libc::c_void
            as uintptr_t as *mut libc::c_void,
        None,
    );
    printf(
        b"my_object.to_string(custom serializer)=%s\n\0" as *const u8
            as *const libc::c_char,
        json_object_to_json_string_ext(my_object, (1 as libc::c_int) << 2 as libc::c_int),
    );
    json_object_put(my_object);
    return 0 as libc::c_int;
}
pub fn main() {
    let mut args: Vec::<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::std::ptr::null_mut());
    unsafe {
        ::std::process::exit(
            main_0(
                (args.len() - 1) as libc::c_int,
                args.as_mut_ptr() as *mut *mut libc::c_char,
            ) as i32,
        )
    }
}
