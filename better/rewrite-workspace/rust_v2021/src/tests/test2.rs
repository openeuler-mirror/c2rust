use ::libc;
extern "C" {
    
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    
    
    
    
}
pub use crate::json_object::json_object;
pub use crate::debug::mc_set_debug;
pub use crate::json_object::json_object_put;
pub use crate::json_object::json_object_to_json_string;
pub use crate::json_tokener::json_tokener_parse;
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut new_obj: *mut json_object = 0 as *mut json_object;
    new_obj = json_tokener_parse(
        b"/* more difficult test case */{ \"glossary\": { \"title\": \"example glossary\", \"GlossDiv\": { \"title\": \"S\", \"GlossList\": [ { \"ID\": \"SGML\", \"SortAs\": \"SGML\", \"GlossTerm\": \"Standard Generalized Markup Language\", \"Acronym\": \"SGML\", \"Abbrev\": \"ISO 8879:1986\", \"GlossDef\": \"A meta-markup language, used to create markup languages such as DocBook.\", \"GlossSeeAlso\": [\"GML\", \"XML\", \"markup\"] } ] } } }\0"
            as *const u8 as *const libc::c_char,
    );
    printf(
        b"new_obj.to_string()=%s\n\0" as *const u8 as *const libc::c_char,
        json_object_to_json_string(new_obj),
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
