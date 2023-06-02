use :: libc;
extern "C" {
    fn pthread_create(
        __newthread: *mut pthread_t,
        __attr: *const pthread_attr_t,
        __start_routine: Option<unsafe extern "C" fn(*mut libc::c_void) -> *mut libc::c_void>,
        __arg: *mut libc::c_void,
    ) -> i32;
    fn pthread_join(__th: pthread_t, __thread_return: *mut *mut libc::c_void) -> i32;
    fn pthread_detach(__th: pthread_t) -> i32;
    static mut Curl_cmalloc: curl_malloc_callback;
    static mut Curl_cfree: curl_free_callback;
}
pub type size_t = u64;
pub type pthread_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_attr_t {
    pub __size: [i8; 56],
    pub __align: i64,
}
pub type curl_malloc_callback = Option<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
pub type curl_free_callback = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_actual_call {
    pub func: Option<unsafe extern "C" fn(*mut libc::c_void) -> u32>,
    pub arg: *mut libc::c_void,
}
extern "C" fn curl_thread_create_thunk(mut arg: *mut libc::c_void) -> *mut libc::c_void {
    let mut ac: *mut Curl_actual_call = arg as *mut Curl_actual_call;
    let mut func: Option<unsafe extern "C" fn(*mut libc::c_void) -> u32> = unsafe { (*ac).func };
    let mut real_arg: *mut libc::c_void = unsafe { (*ac).arg };
    (unsafe { Curl_cfree.expect("non-null function pointer")(ac as *mut libc::c_void) });
    (unsafe { (Some(func.expect("non-null function pointer"))).expect("non-null function pointer")(real_arg) });
    return 0 as *mut libc::c_void;
}
#[no_mangle]
pub extern "C" fn Curl_thread_create(
    mut func: Option<unsafe extern "C" fn(*mut libc::c_void) -> u32>,
    mut arg: *mut libc::c_void,
) -> *mut pthread_t {
    let mut t: *mut pthread_t =
        (unsafe { Curl_cmalloc.expect("non-null function pointer")(::std::mem::size_of::<pthread_t>() as u64) })
            as *mut pthread_t;
    let mut ac: *mut Curl_actual_call = (unsafe { Curl_cmalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<Curl_actual_call>() as u64,
    ) }) as *mut Curl_actual_call;
    if !ac.is_null() && !t.is_null() {
        let fresh0 = unsafe { &mut ((*ac).func) };
        *fresh0 = func;
        let fresh1 = unsafe { &mut ((*ac).arg) };
        *fresh1 = arg;
        if !((unsafe { pthread_create(
            t,
            0 as *const pthread_attr_t,
            Some(
                curl_thread_create_thunk
                    as unsafe extern "C" fn(*mut libc::c_void) -> *mut libc::c_void,
            ),
            ac as *mut libc::c_void,
        ) }) != 0 as i32)
        {
            return t;
        }
    }
    (unsafe { Curl_cfree.expect("non-null function pointer")(t as *mut libc::c_void) });
    (unsafe { Curl_cfree.expect("non-null function pointer")(ac as *mut libc::c_void) });
    return 0 as *mut pthread_t;
}
#[no_mangle]
pub extern "C" fn Curl_thread_destroy(mut hnd: *mut pthread_t) {
    if !hnd.is_null() {
        (unsafe { pthread_detach(*hnd) });
        (unsafe { Curl_cfree.expect("non-null function pointer")(hnd as *mut libc::c_void) });
    }
}
#[no_mangle]
pub extern "C" fn Curl_thread_join(mut hnd: *mut *mut pthread_t) -> i32 {
    let mut ret: i32 = ((unsafe { pthread_join(**hnd, 0 as *mut *mut libc::c_void) }) == 0 as i32) as i32;
    (unsafe { Curl_cfree.expect("non-null function pointer")(*hnd as *mut libc::c_void) });
    (unsafe { *hnd = 0 as *mut pthread_t });
    return ret;
}
