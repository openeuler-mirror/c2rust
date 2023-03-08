use ::libc;
extern "C" {
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    
    
    
    
    
    
    
}
pub use crate::json_object::json_c_set_serialization_double_format;
pub use crate::json_object::json_object_double_to_json_string;
pub use crate::json_object::json_object_new_double;
pub use crate::json_object::json_object_put;
pub use crate::json_object::json_object_set_serializer;
pub use crate::json_object::json_object_to_json_string;
pub use crate::json_object::json_object_to_json_string_ext;
pub use crate::json_object::__uint32_t;
pub use crate::json_object::uint32_t;
// #[derive(Copy, Clone)]

pub use crate::apps::json_parse::printbuf;
// #[derive(Copy, Clone)]

pub use crate::json_object::json_object;
pub use crate::json_object::json_object_delete_fn;
pub use crate::json_object::json_object_to_json_string_fn;
pub use crate::json_object::json_type;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
#[no_mangle]
pub static mut zero_dot_zero: libc::c_double = 0.0f64;
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut obj: *mut json_object = json_object_new_double(0.5f64);
    let mut udata: [libc::c_char; 5] = *::std::mem::transmute::<
        &[u8; 5],
        &mut [libc::c_char; 5],
    >(b"test\0");
    printf(b"Test default serializer:\n\0" as *const u8 as *const libc::c_char);
    printf(
        b"obj.to_string(standard)=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    printf(
        b"Test default serializer with custom userdata:\n\0" as *const u8
            as *const libc::c_char,
    );
    let ref mut fresh0 = (*obj)._userdata;
    *fresh0 = udata.as_mut_ptr() as *mut libc::c_void;
    printf(
        b"obj.to_string(userdata)=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    printf(
        b"Test explicit serializer with custom userdata:\n\0" as *const u8
            as *const libc::c_char,
    );
    json_object_set_serializer(
        obj,
        Some(
            json_object_double_to_json_string
                as unsafe extern "C" fn(
                    *mut json_object,
                    *mut printbuf,
                    libc::c_int,
                    libc::c_int,
                ) -> libc::c_int,
        ),
        udata.as_mut_ptr() as *mut libc::c_void,
        None,
    );
    printf(
        b"obj.to_string(custom)=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    printf(b"Test reset serializer:\n\0" as *const u8 as *const libc::c_char);
    json_object_set_serializer(obj, None, 0 as *mut libc::c_void, None);
    printf(
        b"obj.to_string(reset)=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    json_object_put(obj);
    printf(b"Test no zero reset serializer:\n\0" as *const u8 as *const libc::c_char);
    obj = json_object_new_double(3.1415000f64);
    let mut data: [libc::c_char; 6] = *::std::mem::transmute::<
        &[u8; 6],
        &mut [libc::c_char; 6],
    >(b"%.17g\0");
    json_object_set_serializer(
        obj,
        Some(
            json_object_double_to_json_string
                as unsafe extern "C" fn(
                    *mut json_object,
                    *mut printbuf,
                    libc::c_int,
                    libc::c_int,
                ) -> libc::c_int,
        ),
        data.as_mut_ptr() as *mut libc::c_void,
        None,
    );
    printf(
        b"obj.to_string(reset)=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string_ext(obj, 4 as libc::c_int),
    );
    json_object_put(obj);
    obj = json_object_new_double(0.52381f64);
    printf(
        b"obj.to_string(default format)=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    if json_c_set_serialization_double_format(
        b"x%0.3fy\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    ) < 0 as libc::c_int
    {
        printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    printf(
        b"obj.to_string(with global format)=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    if json_c_set_serialization_double_format(
        b"T%0.2fX\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    ) < 0 as libc::c_int
    {
        printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    printf(
        b"obj.to_string(with thread format)=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    if json_c_set_serialization_double_format(
        b"Ttttttttttttt%0.2fxxxxxxxxxxxxxxxxxxX\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    ) < 0 as libc::c_int
    {
        printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    printf(
        b"obj.to_string(long thread format)=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    if json_c_set_serialization_double_format(0 as *const libc::c_char, 1 as libc::c_int)
        < 0 as libc::c_int
    {
        printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    printf(
        b"obj.to_string(back to global format)=%s\n\0" as *const u8
            as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    if json_c_set_serialization_double_format(0 as *const libc::c_char, 0 as libc::c_int)
        < 0 as libc::c_int
    {
        printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    printf(
        b"obj.to_string(back to default format)=%s\n\0" as *const u8
            as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    json_object_put(obj);
    obj = json_object_new_double(12.0f64);
    printf(
        b"obj(12.0).to_string(default format)=%s\n\0" as *const u8
            as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    if json_c_set_serialization_double_format(
        b"%.0f\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    ) < 0 as libc::c_int
    {
        printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    printf(
        b"obj(12.0).to_string(%%.0f)=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    if json_c_set_serialization_double_format(
        b"%.0g\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    ) < 0 as libc::c_int
    {
        printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    printf(
        b"obj(12.0).to_string(%%.0g)=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    if json_c_set_serialization_double_format(
        b"%.2g\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    ) < 0 as libc::c_int
    {
        printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    printf(
        b"obj(12.0).to_string(%%.1g)=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    if json_c_set_serialization_double_format(0 as *const libc::c_char, 0 as libc::c_int)
        < 0 as libc::c_int
    {
        printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    json_object_put(obj);
    obj = json_object_new_double(-12.0f64);
    printf(
        b"obj(-12.0).to_string(default format)=%s\n\0" as *const u8
            as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    json_object_put(obj);
    obj = json_object_new_double(zero_dot_zero / zero_dot_zero);
    printf(
        b"obj(0.0/0.0)=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    json_object_put(obj);
    obj = json_object_new_double(1.0f64 / zero_dot_zero);
    printf(
        b"obj(1.0/0.0)=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    json_object_put(obj);
    obj = json_object_new_double(-1.0f64 / zero_dot_zero);
    printf(
        b"obj(-1.0/0.0)=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(obj),
    );
    json_object_put(obj);
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
