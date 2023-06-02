use ::libc;
extern "C" {
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> *mut libc::c_void;
    
    
    
}
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_crealloc;
pub type size_t = crate::src::lib::altsvc::size_t;
pub type curl_malloc_callback = crate::src::lib::altsvc::curl_malloc_callback;
pub type curl_free_callback = crate::src::lib::altsvc::curl_free_callback;
pub type curl_realloc_callback = crate::src::lib::dynbuf::curl_realloc_callback;
#[no_mangle]
pub unsafe extern "C" fn Curl_memdup(
    mut src: *const libc::c_void,
    mut length: size_t,
) -> *mut libc::c_void {
    let mut buffer: *mut libc::c_void = Curl_cmalloc
        .expect("non-null function pointer")(length);
    if buffer.is_null() {
        return 0 as *mut libc::c_void;
    }
    memcpy(buffer, src, length);
    return buffer;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_saferealloc(
    mut ptr: *mut libc::c_void,
    mut size: size_t,
) -> *mut libc::c_void {
    let mut datap: *mut libc::c_void = Curl_crealloc
        .expect("non-null function pointer")(ptr, size);
    if size != 0 && datap.is_null() {
        Curl_cfree.expect("non-null function pointer")(ptr);
    }
    return datap;
}
