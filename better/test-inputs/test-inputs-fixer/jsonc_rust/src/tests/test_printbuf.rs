use :: libc;
extern "C" {
    fn printf(_: *const i8, _: ...) -> i32;
    fn malloc(_: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn strlen(_: *const i8) -> u64;
    fn mc_set_debug(debug: i32);
    fn printbuf_new() -> *mut printbuf;
    fn printbuf_memappend(p: *mut printbuf, buf: *const i8, size: i32) -> i32;
    fn printbuf_memset(pb: *mut printbuf, offset: i32, charvalue: i32, len: i32) -> i32;
    fn sprintbuf(p: *mut printbuf, msg: *const i8, _: ...) -> i32;
    fn printbuf_reset(p: *mut printbuf);
    fn printbuf_free(p: *mut printbuf);
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct printbuf {
    pub buf: *mut i8,
    pub bpos: i32,
    pub size: i32,
}
extern "C" fn test_basic_printbuf_memset() {
    let mut pb: *mut printbuf = 0 as *mut printbuf;
    (unsafe { printf(
        b"%s: starting test\n\0" as *const u8 as *const i8,
        (*::std::mem::transmute::<&[u8; 27], &[i8; 27]>(b"test_basic_printbuf_memset\0")).as_ptr(),
    ) });
    pb = unsafe { printbuf_new() };
    (unsafe { sprintbuf(pb, b"blue:%d\0" as *const u8 as *const i8, 1 as i32) });
    (unsafe { printbuf_memset(pb, -(1 as i32), 'x' as i32, 52 as i32) });
    (unsafe { printf(
        b"Buffer contents:%.*s\n\0" as *const u8 as *const i8,
        (*pb).bpos,
        (*pb).buf,
    ) });
    (unsafe { printbuf_free(pb) });
    (unsafe { printf(
        b"%s: end test\n\0" as *const u8 as *const i8,
        (*::std::mem::transmute::<&[u8; 27], &[i8; 27]>(b"test_basic_printbuf_memset\0")).as_ptr(),
    ) });
}
extern "C" fn test_printbuf_memset_length() {
    let mut pb: *mut printbuf = 0 as *mut printbuf;
    (unsafe { printf(
        b"%s: starting test\n\0" as *const u8 as *const i8,
        (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"test_printbuf_memset_length\0")).as_ptr(),
    ) });
    pb = unsafe { printbuf_new() };
    (unsafe { printbuf_memset(pb, -(1 as i32), ' ' as i32, 0 as i32) });
    (unsafe { printbuf_memset(pb, -(1 as i32), ' ' as i32, 0 as i32) });
    (unsafe { printbuf_memset(pb, -(1 as i32), ' ' as i32, 0 as i32) });
    (unsafe { printbuf_memset(pb, -(1 as i32), ' ' as i32, 0 as i32) });
    (unsafe { printbuf_memset(pb, -(1 as i32), ' ' as i32, 0 as i32) });
    (unsafe { printf(
        b"Buffer length: %d\n\0" as *const u8 as *const i8,
        (*pb).bpos,
    ) });
    (unsafe { printbuf_memset(pb, -(1 as i32), ' ' as i32, 2 as i32) });
    (unsafe { printbuf_memset(pb, -(1 as i32), ' ' as i32, 4 as i32) });
    (unsafe { printbuf_memset(pb, -(1 as i32), ' ' as i32, 6 as i32) });
    (unsafe { printf(
        b"Buffer length: %d\n\0" as *const u8 as *const i8,
        (*pb).bpos,
    ) });
    (unsafe { printbuf_memset(pb, -(1 as i32), ' ' as i32, 6 as i32) });
    (unsafe { printf(
        b"Buffer length: %d\n\0" as *const u8 as *const i8,
        (*pb).bpos,
    ) });
    (unsafe { printbuf_memset(pb, -(1 as i32), ' ' as i32, 8 as i32) });
    (unsafe { printbuf_memset(pb, -(1 as i32), ' ' as i32, 10 as i32) });
    (unsafe { printbuf_memset(pb, -(1 as i32), ' ' as i32, 10 as i32) });
    (unsafe { printbuf_memset(pb, -(1 as i32), ' ' as i32, 10 as i32) });
    (unsafe { printbuf_memset(pb, -(1 as i32), ' ' as i32, 20 as i32) });
    (unsafe { printf(
        b"Buffer length: %d\n\0" as *const u8 as *const i8,
        (*pb).bpos,
    ) });
    (unsafe { printbuf_memset(pb, 0 as i32, 'x' as i32, 30 as i32) });
    (unsafe { printf(
        b"Buffer length: %d\n\0" as *const u8 as *const i8,
        (*pb).bpos,
    ) });
    (unsafe { printbuf_memset(pb, 0 as i32, 'x' as i32, (*pb).bpos + 1 as i32) });
    (unsafe { printf(
        b"Buffer length: %d\n\0" as *const u8 as *const i8,
        (*pb).bpos,
    ) });
    (unsafe { printbuf_free(pb) });
    (unsafe { printf(
        b"%s: end test\n\0" as *const u8 as *const i8,
        (*::std::mem::transmute::<&[u8; 28], &[i8; 28]>(b"test_printbuf_memset_length\0")).as_ptr(),
    ) });
}
extern "C" fn test_printbuf_memappend(mut before_resize: *mut i32) {
    let mut pb: *mut printbuf = 0 as *mut printbuf;
    let mut initial_size: i32 = 0;
    (unsafe { printf(
        b"%s: starting test\n\0" as *const u8 as *const i8,
        (*::std::mem::transmute::<&[u8; 24], &[i8; 24]>(b"test_printbuf_memappend\0")).as_ptr(),
    ) });
    pb = unsafe { printbuf_new() };
    (unsafe { printf(
        b"Buffer length: %d\n\0" as *const u8 as *const i8,
        (*pb).bpos,
    ) });
    initial_size = unsafe { (*pb).size };
    while (unsafe { (*pb).size }) == initial_size {
        if (unsafe { (*pb).size }) - (unsafe { (*pb).bpos }) > 1 as i32 {
            (unsafe { memcpy(
                ((*pb).buf).offset((*pb).bpos as isize) as *mut libc::c_void,
                b"x\0" as *const u8 as *const i8 as *const libc::c_void,
                1 as i32 as u64,
            ) });
            (unsafe { (*pb).bpos += 1 as i32 });
            (unsafe { *((*pb).buf).offset((*pb).bpos as isize) = '\u{0}' as i32 as i8 });
        } else {
            (unsafe { printbuf_memappend(pb, b"x\0" as *const u8 as *const i8, 1 as i32) });
        }
    }
    (unsafe { *before_resize = (*pb).bpos - 1 as i32 });
    (unsafe { printf(
        b"Appended %d bytes for resize: [%s]\n\0" as *const u8 as *const i8,
        *before_resize + 1 as i32,
        (*pb).buf,
    ) });
    (unsafe { printbuf_reset(pb) });
    if (unsafe { (*pb).size }) - (unsafe { (*pb).bpos }) > 3 as i32 {
        (unsafe { memcpy(
            ((*pb).buf).offset((*pb).bpos as isize) as *mut libc::c_void,
            b"bluexyz123\0" as *const u8 as *const i8 as *const libc::c_void,
            3 as i32 as u64,
        ) });
        (unsafe { (*pb).bpos += 3 as i32 });
        (unsafe { *((*pb).buf).offset((*pb).bpos as isize) = '\u{0}' as i32 as i8 });
    } else {
        (unsafe { printbuf_memappend(pb, b"bluexyz123\0" as *const u8 as *const i8, 3 as i32) });
    }
    (unsafe { printf(
        b"Partial append: %d, [%s]\n\0" as *const u8 as *const i8,
        (*pb).bpos,
        (*pb).buf,
    ) });
    let mut with_nulls: [i8; 4] = [
        'a' as i32 as i8,
        'b' as i32 as i8,
        '\u{0}' as i32 as i8,
        'c' as i32 as i8,
    ];
    (unsafe { printbuf_reset(pb) });
    if (unsafe { (*pb).size }) - (unsafe { (*pb).bpos }) > ::std::mem::size_of::<[i8; 4]>() as u64 as i32 {
        (unsafe { memcpy(
            ((*pb).buf).offset((*pb).bpos as isize) as *mut libc::c_void,
            with_nulls.as_mut_ptr() as *const libc::c_void,
            ::std::mem::size_of::<[i8; 4]>() as u64 as i32 as u64,
        ) });
        (unsafe { (*pb).bpos += ::std::mem::size_of::<[i8; 4]>() as u64 as i32 });
        (unsafe { *((*pb).buf).offset((*pb).bpos as isize) = '\u{0}' as i32 as i8 });
    } else {
        (unsafe { printbuf_memappend(
            pb,
            with_nulls.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 4]>() as u64 as i32,
        ) });
    }
    (unsafe { printf(
        b"With embedded \\0 character: %d, [%s]\n\0" as *const u8 as *const i8,
        (*pb).bpos,
        (*pb).buf,
    ) });
    (unsafe { printbuf_free(pb) });
    pb = unsafe { printbuf_new() };
    let mut data: *mut i8 = (unsafe { malloc(*before_resize as u64) }) as *mut i8;
    (unsafe { memset(data as *mut libc::c_void, 'X' as i32, *before_resize as u64) });
    if (unsafe { (*pb).size }) - (unsafe { (*pb).bpos }) > (unsafe { *before_resize }) {
        (unsafe { memcpy(
            ((*pb).buf).offset((*pb).bpos as isize) as *mut libc::c_void,
            data as *const libc::c_void,
            *before_resize as u64,
        ) });
        (unsafe { (*pb).bpos += *before_resize });
        (unsafe { *((*pb).buf).offset((*pb).bpos as isize) = '\u{0}' as i32 as i8 });
    } else {
        (unsafe { printbuf_memappend(pb, data, *before_resize) });
    }
    (unsafe { printf(
        b"Append to just before resize: %d, [%s]\n\0" as *const u8 as *const i8,
        (*pb).bpos,
        (*pb).buf,
    ) });
    (unsafe { free(data as *mut libc::c_void) });
    (unsafe { printbuf_free(pb) });
    pb = unsafe { printbuf_new() };
    data = (unsafe { malloc((*before_resize + 1 as i32) as u64) }) as *mut i8;
    (unsafe { memset(
        data as *mut libc::c_void,
        'X' as i32,
        (*before_resize + 1 as i32) as u64,
    ) });
    if (unsafe { (*pb).size }) - (unsafe { (*pb).bpos }) > (unsafe { *before_resize }) + 1 as i32 {
        (unsafe { memcpy(
            ((*pb).buf).offset((*pb).bpos as isize) as *mut libc::c_void,
            data as *const libc::c_void,
            (*before_resize + 1 as i32) as u64,
        ) });
        (unsafe { (*pb).bpos += *before_resize + 1 as i32 });
        (unsafe { *((*pb).buf).offset((*pb).bpos as isize) = '\u{0}' as i32 as i8 });
    } else {
        (unsafe { printbuf_memappend(pb, data, *before_resize + 1 as i32) });
    }
    (unsafe { printf(
        b"Append to just after resize: %d, [%s]\n\0" as *const u8 as *const i8,
        (*pb).bpos,
        (*pb).buf,
    ) });
    (unsafe { free(data as *mut libc::c_void) });
    (unsafe { printbuf_free(pb) });
    pb = unsafe { printbuf_new() };
    (unsafe { printbuf_memappend(
        pb,
        b"XXXXXXXXXXXXXXXX\0" as *const u8 as *const i8,
        (::std::mem::size_of::<[i8; 17]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
    ) });
    (unsafe { printf(
        b"Buffer size after printbuf_strappend(): %d, [%s]\n\0" as *const u8 as *const i8,
        (*pb).bpos,
        (*pb).buf,
    ) });
    (unsafe { printbuf_free(pb) });
    (unsafe { printf(
        b"%s: end test\n\0" as *const u8 as *const i8,
        (*::std::mem::transmute::<&[u8; 24], &[i8; 24]>(b"test_printbuf_memappend\0")).as_ptr(),
    ) });
}
extern "C" fn test_sprintbuf(mut before_resize: i32) {
    let mut pb: *mut printbuf = 0 as *mut printbuf;
    let mut max_char : * const i8 = b"if string is greater than stack buffer, then use dynamic string with vasprintf.  Note: some implementation of vsnprintf return -1  if output is truncated whereas some return the number of bytes that  would have been written - this code handles both cases.\0" as * const u8 as * const i8 ;
    (unsafe { printf(
        b"%s: starting test\n\0" as *const u8 as *const i8,
        (*::std::mem::transmute::<&[u8; 15], &[i8; 15]>(b"test_sprintbuf\0")).as_ptr(),
    ) });
    pb = unsafe { printbuf_new() };
    (unsafe { printf(
        b"Buffer length: %d\n\0" as *const u8 as *const i8,
        (*pb).bpos,
    ) });
    let mut data: *mut i8 = (unsafe { malloc((before_resize + 1 as i32 + 1 as i32) as u64) }) as *mut i8;
    (unsafe { memset(
        data as *mut libc::c_void,
        'X' as i32,
        (before_resize + 1 as i32 + 1 as i32) as u64,
    ) });
    (unsafe { *data.offset((before_resize + 1 as i32) as isize) = '\u{0}' as i32 as i8 });
    (unsafe { sprintbuf(pb, b"%s\0" as *const u8 as *const i8, data) });
    (unsafe { free(data as *mut libc::c_void) });
    (unsafe { printf(
        b"sprintbuf to just after resize(%d+1): %d, [%s], strlen(buf)=%d\n\0" as *const u8
            as *const i8,
        before_resize,
        (*pb).bpos,
        (*pb).buf,
        strlen((*pb).buf) as i32,
    ) });
    (unsafe { printbuf_reset(pb) });
    (unsafe { sprintbuf(pb, b"plain\0" as *const u8 as *const i8) });
    (unsafe { printf(
        b"%d, [%s]\n\0" as *const u8 as *const i8,
        (*pb).bpos,
        (*pb).buf,
    ) });
    (unsafe { sprintbuf(pb, b"%d\0" as *const u8 as *const i8, 1 as i32) });
    (unsafe { printf(
        b"%d, [%s]\n\0" as *const u8 as *const i8,
        (*pb).bpos,
        (*pb).buf,
    ) });
    (unsafe { sprintbuf(pb, b"%d\0" as *const u8 as *const i8, 2147483647 as i32) });
    (unsafe { printf(
        b"%d, [%s]\n\0" as *const u8 as *const i8,
        (*pb).bpos,
        (*pb).buf,
    ) });
    (unsafe { sprintbuf(
        pb,
        b"%d\0" as *const u8 as *const i8,
        -(2147483647 as i32) - 1 as i32,
    ) });
    (unsafe { printf(
        b"%d, [%s]\n\0" as *const u8 as *const i8,
        (*pb).bpos,
        (*pb).buf,
    ) });
    (unsafe { sprintbuf(
        pb,
        b"%s\0" as *const u8 as *const i8,
        b"%s\0" as *const u8 as *const i8,
    ) });
    (unsafe { printf(
        b"%d, [%s]\n\0" as *const u8 as *const i8,
        (*pb).bpos,
        (*pb).buf,
    ) });
    (unsafe { sprintbuf(pb, max_char) });
    (unsafe { printf(
        b"%d, [%s]\n\0" as *const u8 as *const i8,
        (*pb).bpos,
        (*pb).buf,
    ) });
    (unsafe { printbuf_free(pb) });
    (unsafe { printf(
        b"%s: end test\n\0" as *const u8 as *const i8,
        (*::std::mem::transmute::<&[u8; 15], &[i8; 15]>(b"test_sprintbuf\0")).as_ptr(),
    ) });
}
fn main_0(mut _argc: i32, mut _argv: *mut *mut i8) -> i32 {
    let mut before_resize: i32 = 0 as i32;
    test_basic_printbuf_memset();
    (unsafe { printf(b"========================================\n\0" as *const u8 as *const i8) });
    test_printbuf_memset_length();
    (unsafe { printf(b"========================================\n\0" as *const u8 as *const i8) });
    test_printbuf_memappend(&mut before_resize);
    (unsafe { printf(b"========================================\n\0" as *const u8 as *const i8) });
    test_sprintbuf(before_resize);
    (unsafe { printf(b"========================================\n\0" as *const u8 as *const i8) });
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
