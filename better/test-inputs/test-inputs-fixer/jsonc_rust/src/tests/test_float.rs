
extern "C" {
    pub type json_object;
    fn json_object_put(obj: *mut json_object) -> i32;
    fn json_object_to_json_string_ext(obj: *mut json_object, flags: i32) -> *const i8;
    fn json_object_new_double(d: f64) -> *mut json_object;
    fn printf(_: *const i8, _: ...) -> i32;
}
fn main_0() -> i32 {
    let mut json: *mut json_object = 0 as *mut json_object;
    json = unsafe { json_object_new_double(1.0f64) };
    (unsafe { printf(
        b"json = %s\n\0" as *const u8 as *const i8,
        json_object_to_json_string_ext(json, (1 as i32) << 1 as i32),
    ) });
    (unsafe { json_object_put(json) });
    json = unsafe { json_object_new_double(-1.0f64) };
    (unsafe { printf(
        b"json = %s\n\0" as *const u8 as *const i8,
        json_object_to_json_string_ext(json, (1 as i32) << 1 as i32),
    ) });
    (unsafe { json_object_put(json) });
    json = unsafe { json_object_new_double(1.23f64) };
    (unsafe { printf(
        b"json = %s\n\0" as *const u8 as *const i8,
        json_object_to_json_string_ext(json, (1 as i32) << 1 as i32),
    ) });
    (unsafe { json_object_put(json) });
    json = unsafe { json_object_new_double(123456789.0f64) };
    (unsafe { printf(
        b"json = %s\n\0" as *const u8 as *const i8,
        json_object_to_json_string_ext(json, (1 as i32) << 1 as i32),
    ) });
    (unsafe { json_object_put(json) });
    json = unsafe { json_object_new_double(123456789.123f64) };
    (unsafe { printf(
        b"json = %s\n\0" as *const u8 as *const i8,
        json_object_to_json_string_ext(json, (1 as i32) << 1 as i32),
    ) });
    (unsafe { json_object_put(json) });
    return 0 as i32;
}
pub fn main() {
     ::std::process::exit(main_0() as i32)
}
