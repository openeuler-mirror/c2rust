
extern "C" {
    pub type json_object;
    fn printf(_: *const i8, _: ...) -> i32;
    fn json_object_put(obj: *mut json_object) -> i32;
    fn json_object_to_json_string(obj: *mut json_object) -> *const i8;
    fn mc_set_debug(debug: i32);
    fn json_tokener_parse(str: *const i8) -> *mut json_object;
}
fn main_0(mut _argc: i32, mut _argv: *mut *mut i8) -> i32 {
    let mut new_obj: *mut json_object = 0 as *mut json_object;
    new_obj = unsafe { json_tokener_parse (b"/* more difficult test case */{ \"glossary\": { \"title\": \"example glossary\", \"GlossDiv\": { \"title\": \"S\", \"GlossList\": [ { \"ID\": \"SGML\", \"SortAs\": \"SGML\", \"GlossTerm\": \"Standard Generalized Markup Language\", \"Acronym\": \"SGML\", \"Abbrev\": \"ISO 8879:1986\", \"GlossDef\": \"A meta-markup language, used to create markup languages such as DocBook.\", \"GlossSeeAlso\": [\"GML\", \"XML\", \"markup\"] } ] } } }\0" as * const u8 as * const i8 ,) } ;
    (unsafe { printf(
        b"new_obj.to_string()=%s\n\0" as *const u8 as *const i8,
        json_object_to_json_string(new_obj),
    ) });
    (unsafe { json_object_put(new_obj) });
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
