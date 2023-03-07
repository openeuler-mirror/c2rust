use ::libc;
extern "C" {
    pub type json_object;
    fn json_object_put(obj: *mut json_object) -> libc::c_int;
    fn json_object_to_json_string_ext(
        obj: *mut json_object,
        flags: libc::c_int,
    ) -> *const libc::c_char;
    fn json_object_new_double(d: libc::c_double) -> *mut json_object;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
}
unsafe fn main_0() -> libc::c_int {
    let mut json: *mut json_object = 0 as *mut json_object;
    json = json_object_new_double(1.0f64);
    printf(
        b"json = %s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string_ext(json, (1 as libc::c_int) << 1 as libc::c_int),
    );
    json_object_put(json);
    json = json_object_new_double(-1.0f64);
    printf(
        b"json = %s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string_ext(json, (1 as libc::c_int) << 1 as libc::c_int),
    );
    json_object_put(json);
    json = json_object_new_double(1.23f64);
    printf(
        b"json = %s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string_ext(json, (1 as libc::c_int) << 1 as libc::c_int),
    );
    json_object_put(json);
    json = json_object_new_double(123456789.0f64);
    printf(
        b"json = %s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string_ext(json, (1 as libc::c_int) << 1 as libc::c_int),
    );
    json_object_put(json);
    json = json_object_new_double(123456789.123f64);
    printf(
        b"json = %s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string_ext(json, (1 as libc::c_int) << 1 as libc::c_int),
    );
    json_object_put(json);
    return 0 as libc::c_int;
}
pub fn main() {
    unsafe { ::std::process::exit(main_0() as i32) }
}
