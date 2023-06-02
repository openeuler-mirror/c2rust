use ::libc;
extern "C" {
    fn memcpy(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    
    
    
}
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_crealloc;
pub type size_t = u64;
pub type curl_malloc_callback<'a1> = Option<unsafe extern "C"  fn(_: u64,) -> Option<&'a1 mut core::ffi::c_void>>;
pub type curl_free_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> ()>;
pub type curl_realloc_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: u64,) -> Option<&'a2 mut core::ffi::c_void>>;
#[no_mangle]
pub unsafe extern "C" fn Curl_memdup(
    mut src: * const core::ffi::c_void,
    mut length: u64,
) -> * mut core::ffi::c_void {
    let mut buffer: * mut core::ffi::c_void = Curl_cmalloc
        .expect("non-null function pointer")(length);
    if buffer.is_null() {
        return 0 as *mut libc::c_void;
    }
    memcpy(buffer, src, length);
    return buffer;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_saferealloc(
    mut ptr: * mut core::ffi::c_void,
    mut size: u64,
) -> * mut core::ffi::c_void {
    let mut datap: * mut core::ffi::c_void = Curl_crealloc
        .expect("non-null function pointer")(ptr, size);
    if size != 0 && datap.is_null() {
        Curl_cfree.expect("non-null function pointer")(ptr);
    }
    return datap;
}
use crate::laertes_rt::*;
