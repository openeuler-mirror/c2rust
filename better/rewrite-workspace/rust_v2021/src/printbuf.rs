use ::libc;
extern "C" {
    fn __errno_location() -> *mut libc::c_int;
    fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::std::ffi::VaList,
    ) -> libc::c_int;
    fn vasprintf(
        __ptr: *mut *mut libc::c_char,
        __f: *const libc::c_char,
        __arg: ::std::ffi::VaList,
    ) -> libc::c_int;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
}
pub use crate::debug::__builtin_va_list;
// #[derive(Copy, Clone)]

pub use crate::debug::__va_list_tag;
pub use crate::debug::va_list;
// #[derive(Copy, Clone)]

pub use crate::apps::json_parse::printbuf;
#[no_mangle]
pub unsafe extern "C" fn printbuf_new() -> *mut printbuf {
    let mut p: *mut printbuf = 0 as *mut printbuf;
    p = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::std::mem::size_of::<printbuf>() as libc::c_ulong,
    ) as *mut printbuf;
    if p.is_null() {
        return 0 as *mut printbuf;
    }
    (*p).size = 32 as libc::c_int;
    (*p).bpos = 0 as libc::c_int;
    let ref mut fresh0 = (*p).buf;
    *fresh0 = malloc((*p).size as libc::c_ulong) as *mut libc::c_char;
    if (*fresh0).is_null() {
        free(p as *mut libc::c_void);
        return 0 as *mut printbuf;
    }
    *((*p).buf).offset(0 as libc::c_int as isize) = '\u{0}' as i32 as libc::c_char;
    return p;
}
unsafe extern "C" fn printbuf_extend(
    mut p: *mut printbuf,
    mut min_size: libc::c_int,
) -> libc::c_int {
    let mut t: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut new_size: libc::c_int = 0;
    if (*p).size >= min_size {
        return 0 as libc::c_int;
    }
    if min_size > 2147483647 as libc::c_int - 8 as libc::c_int {
        *__errno_location() = 27 as libc::c_int;
        return -(1 as libc::c_int);
    }
    if (*p).size > 2147483647 as libc::c_int / 2 as libc::c_int {
        new_size = min_size + 8 as libc::c_int;
    } else {
        new_size = (*p).size * 2 as libc::c_int;
        if new_size < min_size + 8 as libc::c_int {
            new_size = min_size + 8 as libc::c_int;
        }
    }
    t = realloc((*p).buf as *mut libc::c_void, new_size as libc::c_ulong)
        as *mut libc::c_char;
    if t.is_null() {
        return -(1 as libc::c_int);
    }
    (*p).size = new_size;
    let ref mut fresh1 = (*p).buf;
    *fresh1 = t;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn printbuf_memappend(
    mut p: *mut printbuf,
    mut buf: *const libc::c_char,
    mut size: libc::c_int,
) -> libc::c_int {
    if size < 0 as libc::c_int
        || size > 2147483647 as libc::c_int - (*p).bpos - 1 as libc::c_int
    {
        *__errno_location() = 27 as libc::c_int;
        return -(1 as libc::c_int);
    }
    if (*p).size <= (*p).bpos + size + 1 as libc::c_int {
        if printbuf_extend(p, (*p).bpos + size + 1 as libc::c_int) < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
    }
    memcpy(
        ((*p).buf).offset((*p).bpos as isize) as *mut libc::c_void,
        buf as *const libc::c_void,
        size as libc::c_ulong,
    );
    (*p).bpos += size;
    *((*p).buf).offset((*p).bpos as isize) = '\u{0}' as i32 as libc::c_char;
    return size;
}
#[no_mangle]
pub unsafe extern "C" fn printbuf_memset(
    mut pb: *mut printbuf,
    mut offset: libc::c_int,
    mut charvalue: libc::c_int,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut size_needed: libc::c_int = 0;
    if offset == -(1 as libc::c_int) {
        offset = (*pb).bpos;
    }
    if len < 0 as libc::c_int || offset < -(1 as libc::c_int)
        || len > 2147483647 as libc::c_int - offset
    {
        *__errno_location() = 27 as libc::c_int;
        return -(1 as libc::c_int);
    }
    size_needed = offset + len;
    if (*pb).size < size_needed {
        if printbuf_extend(pb, size_needed) < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
    }
    if (*pb).bpos < offset {
        memset(
            ((*pb).buf).offset((*pb).bpos as isize) as *mut libc::c_void,
            '\u{0}' as i32,
            (offset - (*pb).bpos) as libc::c_ulong,
        );
    }
    memset(
        ((*pb).buf).offset(offset as isize) as *mut libc::c_void,
        charvalue,
        len as libc::c_ulong,
    );
    if (*pb).bpos < size_needed {
        (*pb).bpos = size_needed;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn sprintbuf(
    mut p: *mut printbuf,
    mut msg: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut ap: ::std::ffi::VaListImpl;
    let mut t: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut size: libc::c_int = 0;
    let mut buf: [libc::c_char; 128] = [0; 128];
    ap = args.clone();
    size = vsnprintf(
        buf.as_mut_ptr(),
        128 as libc::c_int as libc::c_ulong,
        msg,
        ap.as_va_list(),
    );
    if size < 0 as libc::c_int || size > 127 as libc::c_int {
        ap = args.clone();
        size = vasprintf(&mut t, msg, ap.as_va_list());
        if size < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        size = printbuf_memappend(p, t, size);
        free(t as *mut libc::c_void);
    } else {
        size = printbuf_memappend(p, buf.as_mut_ptr(), size);
    }
    return size;
}
#[no_mangle]
pub unsafe extern "C" fn printbuf_reset(mut p: *mut printbuf) {
    *((*p).buf).offset(0 as libc::c_int as isize) = '\u{0}' as i32 as libc::c_char;
    (*p).bpos = 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn printbuf_free(mut p: *mut printbuf) {
    if !p.is_null() {
        free((*p).buf as *mut libc::c_void);
        free(p as *mut libc::c_void);
    }
}
