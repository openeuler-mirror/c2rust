use ::libc;
extern "C" {
    fn pthread_create(
        __newthread: * mut u64,
        __attr: * const crate::src::lib::curl_threads::pthread_attr_t,
        __start_routine: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> * mut core::ffi::c_void>,
        __arg: * mut core::ffi::c_void,
    ) -> i32;
    fn pthread_join(
        __th: u64,
        __thread_return: * mut * mut core::ffi::c_void,
    ) -> i32;
    fn pthread_detach(__th: u64) -> i32;
    
    
}
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub type size_t = u64;
pub type pthread_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_attr_t {
    pub __size: [i8; 56],
    pub __align: i64,
}
pub type curl_malloc_callback<'a1> = Option<unsafe extern "C"  fn(_: u64,) -> Option<&'a1 mut core::ffi::c_void>>;
pub type curl_free_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_actual_call {
    pub func: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> u32>,
    pub arg: * mut core::ffi::c_void,
}
impl Curl_actual_call {
    pub const fn new() -> Self {
        Curl_actual_call {
        func: None,
        arg: (0 as * mut core::ffi::c_void)
        }
    }
}

impl std::default::Default for Curl_actual_call {
    fn default() -> Self { Curl_actual_call::new() }
}

unsafe extern "C" fn curl_thread_create_thunk(
    mut arg: * mut core::ffi::c_void,
) -> * mut core::ffi::c_void {
    let mut ac: * mut crate::src::lib::curl_threads::Curl_actual_call = arg as *mut Curl_actual_call;
    let mut func: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> u32> = (*ac)
        .func;
    let mut real_arg: * mut core::ffi::c_void = (*ac).arg;
    Curl_cfree.expect("non-null function pointer")(ac as *mut libc::c_void);
    (Some(func.expect("non-null function pointer")))
        .expect("non-null function pointer")(real_arg);
    return 0 as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_thread_create(
    mut func: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> u32>,
    mut arg: * mut core::ffi::c_void,
) -> * mut u64 {
    let mut t: * mut u64 = Curl_cmalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<pthread_t>() as u64) as *mut pthread_t;
    let mut ac: * mut crate::src::lib::curl_threads::Curl_actual_call = Curl_cmalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<Curl_actual_call>() as u64)
        as *mut Curl_actual_call;
    if !ac.is_null() && !t.is_null() {
        let mut fresh0 = &mut ((*ac).func);
        *fresh0 = func;
        let mut fresh1 = &mut ((*ac).arg);
        *fresh1 = arg;
        if !(pthread_create(
            t,
            0 as *const pthread_attr_t,
            Some(
                curl_thread_create_thunk,
            ),
            ac as *mut libc::c_void,
        ) != 0 as i32)
        {
            return t;
        }
    }
    Curl_cfree.expect("non-null function pointer")(t as *mut libc::c_void);
    Curl_cfree.expect("non-null function pointer")(ac as *mut libc::c_void);
    return 0 as *mut pthread_t;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_thread_destroy(mut hnd: * mut u64) {
    if !hnd.is_null() {
        pthread_detach(*hnd);
        Curl_cfree.expect("non-null function pointer")(hnd as *mut libc::c_void);
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_thread_join<'a1>(mut hnd: Option<&'a1 mut * mut u64>) -> i32 {
    let mut ret: i32 = (pthread_join(**(borrow_mut(&mut hnd)).unwrap(), 0 as *mut *mut libc::c_void)
        == 0 as i32) as i32;
    Curl_cfree.expect("non-null function pointer")(*(borrow_mut(&mut hnd)).unwrap() as *mut libc::c_void);
    *(borrow_mut(&mut hnd)).unwrap() = 0 as *mut pthread_t;
    return ret;
}
use crate::laertes_rt::*;
