use :: libc;
extern "C" {
    fn printf(_: *const i8, _: ...) -> i32;
    fn json_object_put(obj: *mut json_object) -> i32;
    fn json_object_to_json_string(obj: *mut json_object) -> *const i8;
    fn json_object_to_json_string_ext(obj: *mut json_object, flags: i32) -> *const i8;
    fn json_object_set_serializer(
        jso: *mut json_object,
        to_string_func: Option<json_object_to_json_string_fn>,
        userdata: *mut libc::c_void,
        user_delete: Option<json_object_delete_fn>,
    );
    fn json_object_new_double(d: f64) -> *mut json_object;
    fn json_c_set_serialization_double_format(
        double_format: *const i8,
        global_or_thread: i32,
    ) -> i32;
    fn json_object_double_to_json_string(
        jso: *mut json_object,
        pb: *mut printbuf,
        level: i32,
        flags: i32,
    ) -> i32;
}
pub type __uint32_t = u32;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct printbuf {
    pub buf: *mut i8,
    pub bpos: i32,
    pub size: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct json_object {
    pub o_type: json_type,
    pub _ref_count: uint32_t,
    pub _to_json_string: Option<json_object_to_json_string_fn>,
    pub _pb: *mut printbuf,
    pub _user_delete: Option<json_object_delete_fn>,
    pub _userdata: *mut libc::c_void,
}
pub type json_object_delete_fn = unsafe extern "C" fn(*mut json_object, *mut libc::c_void) -> ();
pub type json_object_to_json_string_fn =
    unsafe extern "C" fn(*mut json_object, *mut printbuf, i32, i32) -> i32;
pub type json_type = u32;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
#[no_mangle]
pub static mut zero_dot_zero: f64 = 0.0f64;
fn main_0(mut _argc: i32, mut _argv: *mut *mut i8) -> i32 {
    let mut obj: *mut json_object = unsafe { json_object_new_double(0.5f64) };
    let mut udata: [i8; 5] = *(unsafe { ::std::mem::transmute::<&[u8; 5], &mut [i8; 5]>(b"test\0") });
    (unsafe { printf(b"Test default serializer:\n\0" as *const u8 as *const i8) });
    (unsafe { printf(
        b"obj.to_string(standard)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    (unsafe { printf(b"Test default serializer with custom userdata:\n\0" as *const u8 as *const i8) });
    let fresh0 = unsafe { &mut ((*obj)._userdata) };
    *fresh0 = udata.as_mut_ptr() as *mut libc::c_void;
    (unsafe { printf(
        b"obj.to_string(userdata)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    (unsafe { printf(b"Test explicit serializer with custom userdata:\n\0" as *const u8 as *const i8) });
    (unsafe { json_object_set_serializer(
        obj,
        Some(
            json_object_double_to_json_string
                as unsafe extern "C" fn(*mut json_object, *mut printbuf, i32, i32) -> i32,
        ),
        udata.as_mut_ptr() as *mut libc::c_void,
        None,
    ) });
    (unsafe { printf(
        b"obj.to_string(custom)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    (unsafe { printf(b"Test reset serializer:\n\0" as *const u8 as *const i8) });
    (unsafe { json_object_set_serializer(obj, None, 0 as *mut libc::c_void, None) });
    (unsafe { printf(
        b"obj.to_string(reset)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    (unsafe { json_object_put(obj) });
    (unsafe { printf(b"Test no zero reset serializer:\n\0" as *const u8 as *const i8) });
    obj = unsafe { json_object_new_double(3.1415000f64) };
    let mut data: [i8; 6] = *(unsafe { ::std::mem::transmute::<&[u8; 6], &mut [i8; 6]>(b"%.17g\0") });
    (unsafe { json_object_set_serializer(
        obj,
        Some(
            json_object_double_to_json_string
                as unsafe extern "C" fn(*mut json_object, *mut printbuf, i32, i32) -> i32,
        ),
        data.as_mut_ptr() as *mut libc::c_void,
        None,
    ) });
    (unsafe { printf(
        b"obj.to_string(reset)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string_ext(obj, 4 as i32),
    ) });
    (unsafe { json_object_put(obj) });
    obj = unsafe { json_object_new_double(0.52381f64) };
    (unsafe { printf(
        b"obj.to_string(default format)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    if (unsafe { json_c_set_serialization_double_format(b"x%0.3fy\0" as *const u8 as *const i8, 0 as i32) })
        < 0 as i32
    {
        (unsafe { printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { printf(
        b"obj.to_string(with global format)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    if (unsafe { json_c_set_serialization_double_format(b"T%0.2fX\0" as *const u8 as *const i8, 1 as i32) })
        < 0 as i32
    {
        (unsafe { printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { printf(
        b"obj.to_string(with thread format)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    if (unsafe { json_c_set_serialization_double_format(
        b"Ttttttttttttt%0.2fxxxxxxxxxxxxxxxxxxX\0" as *const u8 as *const i8,
        1 as i32,
    ) }) < 0 as i32
    {
        (unsafe { printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { printf(
        b"obj.to_string(long thread format)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    if (unsafe { json_c_set_serialization_double_format(0 as *const i8, 1 as i32) }) < 0 as i32 {
        (unsafe { printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { printf(
        b"obj.to_string(back to global format)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    if (unsafe { json_c_set_serialization_double_format(0 as *const i8, 0 as i32) }) < 0 as i32 {
        (unsafe { printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { printf(
        b"obj.to_string(back to default format)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    (unsafe { json_object_put(obj) });
    obj = unsafe { json_object_new_double(12.0f64) };
    (unsafe { printf(
        b"obj(12.0).to_string(default format)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    if (unsafe { json_c_set_serialization_double_format(b"%.0f\0" as *const u8 as *const i8, 0 as i32) })
        < 0 as i32
    {
        (unsafe { printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { printf(
        b"obj(12.0).to_string(%%.0f)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    if (unsafe { json_c_set_serialization_double_format(b"%.0g\0" as *const u8 as *const i8, 0 as i32) })
        < 0 as i32
    {
        (unsafe { printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { printf(
        b"obj(12.0).to_string(%%.0g)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    if (unsafe { json_c_set_serialization_double_format(b"%.2g\0" as *const u8 as *const i8, 0 as i32) })
        < 0 as i32
    {
        (unsafe { printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { printf(
        b"obj(12.0).to_string(%%.1g)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    if (unsafe { json_c_set_serialization_double_format(0 as *const i8, 0 as i32) }) < 0 as i32 {
        (unsafe { printf(
            b"ERROR: json_c_set_serialization_double_format() failed\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { json_object_put(obj) });
    obj = unsafe { json_object_new_double(-12.0f64) };
    (unsafe { printf(
        b"obj(-12.0).to_string(default format)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    (unsafe { json_object_put(obj) });
    obj = unsafe { json_object_new_double(zero_dot_zero / zero_dot_zero) };
    (unsafe { printf(
        b"obj(0.0/0.0)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    (unsafe { json_object_put(obj) });
    obj = unsafe { json_object_new_double(1.0f64 / zero_dot_zero) };
    (unsafe { printf(
        b"obj(1.0/0.0)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    (unsafe { json_object_put(obj) });
    obj = unsafe { json_object_new_double(-1.0f64 / zero_dot_zero) };
    (unsafe { printf(
        b"obj(-1.0/0.0)=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(obj),
    ) });
    (unsafe { json_object_put(obj) });
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
