use :: libc;
extern "C" {
    fn __errno_location() -> *mut i32;
    fn vsnprintf(_: *mut i8, _: u64, _: *const i8, _: ::std::ffi::VaList) -> i32;
    fn vasprintf(__ptr: *mut *mut i8, __f: *const i8, __arg: ::std::ffi::VaList) -> i32;
    fn malloc(_: u64) -> *mut libc::c_void;
    fn calloc(_: u64, _: u64) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: u32,
    pub fp_offset: u32,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type va_list = __builtin_va_list;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct printbuf {
    pub buf: *mut i8,
    pub bpos: i32,
    pub size: i32,
}
#[no_mangle]
pub extern "C" fn printbuf_new() -> *mut printbuf {
    let mut p: *mut printbuf = 0 as *mut printbuf;
    p = (unsafe { calloc(1 as i32 as u64, ::std::mem::size_of::<printbuf>() as u64) }) as *mut printbuf;
    if p.is_null() {
        return 0 as *mut printbuf;
    }
    (unsafe { (*p).size = 32 as i32 });
    (unsafe { (*p).bpos = 0 as i32 });
    let fresh0 = unsafe { &mut ((*p).buf) };
    *fresh0 = (unsafe { malloc((*p).size as u64) }) as *mut i8;
    if (*fresh0).is_null() {
        (unsafe { free(p as *mut libc::c_void) });
        return 0 as *mut printbuf;
    }
    (unsafe { *((*p).buf).offset(0 as i32 as isize) = '\u{0}' as i32 as i8 });
    return p;
}
extern "C" fn printbuf_extend(mut p: *mut printbuf, mut min_size: i32) -> i32 {
    let mut t: *mut i8 = 0 as *mut i8;
    let mut new_size: i32 = 0;
    if (unsafe { (*p).size }) >= min_size {
        return 0 as i32;
    }
    if min_size > 2147483647 as i32 - 8 as i32 {
        (unsafe { *__errno_location() = 27 as i32 });
        return -(1 as i32);
    }
    if (unsafe { (*p).size }) > 2147483647 as i32 / 2 as i32 {
        new_size = min_size + 8 as i32;
    } else {
        new_size = (unsafe { (*p).size }) * 2 as i32;
        if new_size < min_size + 8 as i32 {
            new_size = min_size + 8 as i32;
        }
    }
    t = (unsafe { realloc((*p).buf as *mut libc::c_void, new_size as u64) }) as *mut i8;
    if t.is_null() {
        return -(1 as i32);
    }
    (unsafe { (*p).size = new_size });
    let fresh1 = unsafe { &mut ((*p).buf) };
    *fresh1 = t;
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn printbuf_memappend(
    mut p: *mut printbuf,
    mut buf: *const i8,
    mut size: i32,
) -> i32 {
    if size < 0 as i32 || size > 2147483647 as i32 - (unsafe { (*p).bpos }) - 1 as i32 {
        (unsafe { *__errno_location() = 27 as i32 });
        return -(1 as i32);
    }
    if (unsafe { (*p).size }) <= (unsafe { (*p).bpos }) + size + 1 as i32 {
        if printbuf_extend(p, (unsafe { (*p).bpos }) + size + 1 as i32) < 0 as i32 {
            return -(1 as i32);
        }
    }
    (unsafe { memcpy(
        ((*p).buf).offset((*p).bpos as isize) as *mut libc::c_void,
        buf as *const libc::c_void,
        size as u64,
    ) });
    (unsafe { (*p).bpos += size });
    (unsafe { *((*p).buf).offset((*p).bpos as isize) = '\u{0}' as i32 as i8 });
    return size;
}
#[no_mangle]
pub extern "C" fn printbuf_memset(
    mut pb: *mut printbuf,
    mut offset: i32,
    mut charvalue: i32,
    mut len: i32,
) -> i32 {
    let mut size_needed: i32 = 0;
    if offset == -(1 as i32) {
        offset = unsafe { (*pb).bpos };
    }
    if len < 0 as i32 || offset < -(1 as i32) || len > 2147483647 as i32 - offset {
        (unsafe { *__errno_location() = 27 as i32 });
        return -(1 as i32);
    }
    size_needed = offset + len;
    if (unsafe { (*pb).size }) < size_needed {
        if printbuf_extend(pb, size_needed) < 0 as i32 {
            return -(1 as i32);
        }
    }
    if (unsafe { (*pb).bpos }) < offset {
        (unsafe { memset(
            ((*pb).buf).offset((*pb).bpos as isize) as *mut libc::c_void,
            '\u{0}' as i32,
            (offset - (*pb).bpos) as u64,
        ) });
    }
    (unsafe { memset(
        ((*pb).buf).offset(offset as isize) as *mut libc::c_void,
        charvalue,
        len as u64,
    ) });
    if (unsafe { (*pb).bpos }) < size_needed {
        (unsafe { (*pb).bpos = size_needed });
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn sprintbuf(mut p: *mut printbuf, mut msg: *const i8, mut args: ...) -> i32 {
    let mut ap: ::std::ffi::VaListImpl;
    let mut t: *mut i8 = 0 as *mut i8;
    let mut size: i32 = 0;
    let mut buf: [i8; 128] = [0; 128];
    ap = args.clone();
    size = vsnprintf(buf.as_mut_ptr(), 128 as i32 as u64, msg, ap.as_va_list());
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
pub extern "C" fn printbuf_reset(mut p: *mut printbuf) {
    (unsafe { *((*p).buf).offset(0 as i32 as isize) = '\u{0}' as i32 as i8 });
    (unsafe { (*p).bpos = 0 as i32 });
}
#[no_mangle]
pub extern "C" fn printbuf_free(mut p: *mut printbuf) {
    if !p.is_null() {
        (unsafe { free((*p).buf as *mut libc::c_void) });
        (unsafe { free(p as *mut libc::c_void) });
    }
}
