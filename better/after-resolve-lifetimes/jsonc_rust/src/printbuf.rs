use ::libc;
extern "C" {
    fn __errno_location() -> * mut i32;
    fn vsnprintf(
        _: * mut i8,
        _: u64,
        _: * const i8,
        _: core::ffi::VaList,
    ) -> i32;
    fn vasprintf(
        __ptr: * mut * mut i8,
        __f: * const i8,
        __arg: core::ffi::VaList,
    ) -> i32;
    fn malloc(_: u64) -> * mut core::ffi::c_void;
    fn calloc(_: u64, _: u64) -> * mut core::ffi::c_void;
    fn realloc(_: * mut core::ffi::c_void, _: u64) -> * mut core::ffi::c_void;
    fn free(__ptr: * mut core::ffi::c_void);
    fn memcpy(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn memset(
        _: * mut core::ffi::c_void,
        _: i32,
        _: u64,
    ) -> * mut core::ffi::c_void;
}
pub type __builtin_va_list = [crate::src::debug::__va_list_tag; 1];
// #[derive(Copy, Clone)]

pub type __va_list_tag = crate::src::debug::__va_list_tag;
pub type va_list = [crate::src::debug::__va_list_tag; 1];
// #[derive(Copy, Clone)]

pub type printbuf = crate::src::apps::json_parse::printbuf;
#[no_mangle]
pub unsafe extern "C" fn printbuf_new() -> * mut crate::src::apps::json_parse::printbuf {
    let mut p: * mut crate::src::apps::json_parse::printbuf = 0 as *mut printbuf;
    p = calloc(
        1 as i32 as u64,
        ::std::mem::size_of::<printbuf>() as u64,
    ) as *mut printbuf;
    if p.is_null() {
        return 0 as *mut printbuf;
    }
    (*p).size = 32 as i32;
    (*p).bpos = 0 as i32;
    let mut fresh0 = &mut ((*p).buf);
    *fresh0 = malloc((*p).size as u64) as *mut i8;
    if (*fresh0).is_null() {
        free(p as *mut libc::c_void);
        return 0 as *mut printbuf;
    }
    *((*p).buf).offset(0 as i32 as isize) = '\u{0}' as i32 as i8;
    return p;
}
unsafe extern "C" fn printbuf_extend(
    mut p: * mut crate::src::apps::json_parse::printbuf,
    mut min_size: i32,
) -> i32 {
    let mut t: * mut i8 = 0 as *mut i8;
    let mut new_size: i32 = 0;
    if (*p).size >= min_size {
        return 0 as i32;
    }
    if min_size > 2147483647 as i32 - 8 as i32 {
        *__errno_location() = 27 as i32;
        return -(1 as i32);
    }
    if (*p).size > 2147483647 as i32 / 2 as i32 {
        new_size = min_size + 8 as i32;
    } else {
        new_size = (*p).size * 2 as i32;
        if new_size < min_size + 8 as i32 {
            new_size = min_size + 8 as i32;
        }
    }
    t = realloc((*p).buf as *mut libc::c_void, new_size as u64)
        as *mut i8;
    if t.is_null() {
        return -(1 as i32);
    }
    (*p).size = new_size;
    let mut fresh1 = &mut ((*p).buf);
    *fresh1 = t;
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn printbuf_memappend(
    mut p: * mut crate::src::apps::json_parse::printbuf,
    mut buf: * const i8,
    mut size: i32,
) -> i32 {
    if size < 0 as i32
        || size > 2147483647 as i32 - (*p).bpos - 1 as i32
    {
        *__errno_location() = 27 as i32;
        return -(1 as i32);
    }
    if (*p).size <= (*p).bpos + size + 1 as i32 {
        if printbuf_extend(p, (*p).bpos + size + 1 as i32) < 0 as i32 {
            return -(1 as i32);
        }
    }
    memcpy(
        ((*p).buf).offset((*p).bpos as isize) as *mut libc::c_void,
        buf as *const libc::c_void,
        size as u64,
    );
    (*p).bpos += size;
    *((*p).buf).offset((*p).bpos as isize) = '\u{0}' as i32 as i8;
    return size;
}
#[no_mangle]
pub unsafe extern "C" fn printbuf_memset(
    mut pb: * mut crate::src::apps::json_parse::printbuf,
    mut offset: i32,
    mut charvalue: i32,
    mut len: i32,
) -> i32 {
    let mut size_needed: i32 = 0;
    if offset == -(1 as i32) {
        offset = (*pb).bpos;
    }
    if len < 0 as i32 || offset < -(1 as i32)
        || len > 2147483647 as i32 - offset
    {
        *__errno_location() = 27 as i32;
        return -(1 as i32);
    }
    size_needed = offset + len;
    if (*pb).size < size_needed {
        if printbuf_extend(pb, size_needed) < 0 as i32 {
            return -(1 as i32);
        }
    }
    if (*pb).bpos < offset {
        memset(
            ((*pb).buf).offset((*pb).bpos as isize) as *mut libc::c_void,
            '\u{0}' as i32,
            (offset - (*pb).bpos) as u64,
        );
    }
    memset(
        ((*pb).buf).offset(offset as isize) as *mut libc::c_void,
        charvalue,
        len as u64,
    );
    if (*pb).bpos < size_needed {
        (*pb).bpos = size_needed;
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn sprintbuf(
    mut p: * mut crate::src::apps::json_parse::printbuf,
    mut msg: * const i8,
    mut args: ...
) -> i32 {
    let mut ap: core::ffi::VaListImpl;
    let mut t: * mut i8 = 0 as *mut i8;
    let mut size: i32 = 0;
    let mut buf: [i8; 128] = [0; 128];
    ap = args.clone();
    size = vsnprintf(
        buf.as_mut_ptr(),
        128 as i32 as u64,
        msg,
        ap.as_va_list(),
    );
    if size < 0 as i32 || size > 127 as i32 {
        ap = args.clone();
        size = vasprintf(&mut t, msg, ap.as_va_list());
        if size < 0 as i32 {
            return -(1 as i32);
        }
        size = printbuf_memappend(p, t, size);
        free(t as *mut libc::c_void);
    } else {
        size = printbuf_memappend(p, buf.as_mut_ptr(), size);
    }
    return size;
}
#[no_mangle]
pub unsafe extern "C" fn printbuf_reset(mut p: * mut crate::src::apps::json_parse::printbuf) {
    *((*p).buf).offset(0 as i32 as isize) = '\u{0}' as i32 as i8;
    (*p).bpos = 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn printbuf_free(mut p: * mut crate::src::apps::json_parse::printbuf) {
    if !p.is_null() {
        free((*p).buf as *mut libc::c_void);
        free(p as *mut libc::c_void);
    }
}
use crate::laertes_rt::*;
