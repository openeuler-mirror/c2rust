use ::libc;
extern "C" {
    pub type json_object;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn json_object_put(obj: *mut json_object) -> libc::c_int;
    fn json_object_to_json_string_ext(
        obj: *mut json_object,
        flags: libc::c_int,
    ) -> *const libc::c_char;
    fn json_object_array_length(obj: *const json_object) -> size_t;
    fn json_object_array_get_idx(
        obj: *const json_object,
        idx: size_t,
    ) -> *mut json_object;
    fn json_object_get_double(obj: *const json_object) -> libc::c_double;
    fn mc_set_debug(debug: libc::c_int);
    fn json_tokener_parse(str: *const libc::c_char) -> *mut json_object;
    fn setlocale(
        __category: libc::c_int,
        __locale: *const libc::c_char,
    ) -> *mut libc::c_char;
}
pub type size_t = libc::c_ulong;
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut new_obj: *mut json_object = 0 as *mut json_object;
    setlocale(1 as libc::c_int, b"de_DE\0" as *const u8 as *const libc::c_char);
    let mut buf1: [libc::c_char; 10] = [0; 10];
    let mut buf2: [libc::c_char; 10] = [0; 10];
    snprintf(
        buf1.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 10]>() as libc::c_ulong,
        b"%f\0" as *const u8 as *const libc::c_char,
        0.1f64,
    );
    new_obj = json_tokener_parse(
        b"[1.2,3.4,123456.78,5.0,2.3e10]\0" as *const u8 as *const libc::c_char,
    );
    snprintf(
        buf2.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 10]>() as libc::c_ulong,
        b"%f\0" as *const u8 as *const libc::c_char,
        0.1f64,
    );
    if strcmp(buf1.as_mut_ptr(), buf2.as_mut_ptr()) != 0 as libc::c_int {
        printf(
            b"ERROR: Original locale not restored \"%s\" != \"%s\"\0" as *const u8
                as *const libc::c_char,
            buf1.as_mut_ptr(),
            buf2.as_mut_ptr(),
        );
    }
    setlocale(1 as libc::c_int, b"C\0" as *const u8 as *const libc::c_char);
    printf(b"new_obj.to_string()=[\0" as *const u8 as *const libc::c_char);
    let mut ii: libc::c_uint = 0;
    ii = 0 as libc::c_int as libc::c_uint;
    while (ii as libc::c_ulong) < json_object_array_length(new_obj) {
        let mut val: *mut json_object = json_object_array_get_idx(new_obj, ii as size_t);
        printf(
            b"%s%.2lf\0" as *const u8 as *const libc::c_char,
            if ii > 0 as libc::c_int as libc::c_uint {
                b",\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            json_object_get_double(val),
        );
        ii = ii.wrapping_add(1);
    }
    printf(b"]\n\0" as *const u8 as *const libc::c_char);
    printf(
        b"new_obj.to_string()=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string_ext(new_obj, (1 as libc::c_int) << 2 as libc::c_int),
    );
    json_object_put(new_obj);
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
