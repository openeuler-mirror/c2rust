use ::libc;
extern "C" {
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    static mut Curl_cmalloc: curl_malloc_callback;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_crealloc: curl_realloc_callback;
}
pub type size_t = libc::c_ulong;
pub type curl_malloc_callback = Option::<
    unsafe extern "C" fn(size_t) -> *mut libc::c_void,
>;
pub type curl_free_callback = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type curl_realloc_callback = Option::<
    unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void,
>;
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
