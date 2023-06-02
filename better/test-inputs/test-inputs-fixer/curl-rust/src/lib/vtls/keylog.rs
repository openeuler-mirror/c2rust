use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn curl_getenv(variable: *const i8) -> *mut i8;
    fn fclose(__stream: *mut FILE) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut FILE;
    fn setvbuf(__stream: *mut FILE, __buf: *mut i8, __modes: i32, __n: size_t) -> i32;
    fn fputs(__s: *const i8, __stream: *mut FILE) -> i32;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn strlen(_: *const i8) -> u64;
    static mut Curl_cfree: curl_free_callback;
}
pub type __off_t = i64;
pub type __off64_t = i64;
pub type size_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: i32,
    pub _IO_read_ptr: *mut i8,
    pub _IO_read_end: *mut i8,
    pub _IO_read_base: *mut i8,
    pub _IO_write_base: *mut i8,
    pub _IO_write_ptr: *mut i8,
    pub _IO_write_end: *mut i8,
    pub _IO_buf_base: *mut i8,
    pub _IO_buf_end: *mut i8,
    pub _IO_save_base: *mut i8,
    pub _IO_backup_base: *mut i8,
    pub _IO_save_end: *mut i8,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: i32,
    pub _flags2: i32,
    pub _old_offset: __off_t,
    pub _cur_column: u16,
    pub _vtable_offset: i8,
    pub _shortbuf: [i8; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: i32,
    pub _unused2: [i8; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type curl_free_callback = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
static mut keylog_file_fp: *mut FILE = 0 as *const FILE as *mut FILE;
#[no_mangle]
pub extern "C" fn Curl_tls_keylog_open() {
    let mut keylog_file_name: *mut i8 = 0 as *mut i8;
    if (unsafe { keylog_file_fp }).is_null() {
        keylog_file_name = unsafe { curl_getenv(b"SSLKEYLOGFILE\0" as *const u8 as *const i8) };
        if !keylog_file_name.is_null() {
            (unsafe { keylog_file_fp = fopen(keylog_file_name, b"a\0" as *const u8 as *const i8) });
            if !(unsafe { keylog_file_fp }).is_null() {
                if (unsafe { setvbuf(
                    keylog_file_fp,
                    0 as *mut i8,
                    1 as i32,
                    4096 as i32 as size_t,
                ) }) != 0
                {
                    (unsafe { fclose(keylog_file_fp) });
                    (unsafe { keylog_file_fp = 0 as *mut FILE });
                }
            }
            (unsafe { Curl_cfree.expect("non-null function pointer")(keylog_file_name as *mut libc::c_void) });
            keylog_file_name = 0 as *mut i8;
        }
    }
}
#[no_mangle]
pub extern "C" fn Curl_tls_keylog_close() {
    if !(unsafe { keylog_file_fp }).is_null() {
        (unsafe { fclose(keylog_file_fp) });
        (unsafe { keylog_file_fp = 0 as *mut FILE });
    }
}
#[no_mangle]
pub extern "C" fn Curl_tls_keylog_enabled() -> bool {
    return !(unsafe { keylog_file_fp }).is_null();
}
#[no_mangle]
pub extern "C" fn Curl_tls_keylog_write_line(mut line: *const i8) -> bool {
    let mut linelen: size_t = 0;
    let mut buf: [i8; 256] = [0; 256];
    if (unsafe { keylog_file_fp }).is_null() || line.is_null() {
        return 0 as i32 != 0;
    }
    linelen = unsafe { strlen(line) };
    if linelen == 0 as i32 as u64
        || linelen > (::std::mem::size_of::<[i8; 256]>() as u64).wrapping_sub(2 as i32 as u64)
    {
        return 0 as i32 != 0;
    }
    (unsafe { memcpy(
        buf.as_mut_ptr() as *mut libc::c_void,
        line as *const libc::c_void,
        linelen,
    ) });
    if (unsafe { *line.offset(linelen.wrapping_sub(1 as i32 as u64) as isize) }) as i32 != '\n' as i32 {
        let fresh0 = linelen;
        linelen = linelen.wrapping_add(1);
        buf[fresh0 as usize] = '\n' as i32 as i8;
    }
    buf[linelen as usize] = '\u{0}' as i32 as i8;
    (unsafe { fputs(buf.as_mut_ptr(), keylog_file_fp) });
    return 1 as i32 != 0;
}
#[no_mangle]
pub extern "C" fn Curl_tls_keylog_write(
    mut label: *const i8,
    mut client_random: *const u8,
    mut secret: *const u8,
    mut secretlen: size_t,
) -> bool {
    let mut hex: *const i8 = b"0123456789ABCDEF\0" as *const u8 as *const i8;
    let mut pos: size_t = 0;
    let mut i: size_t = 0;
    let mut line: [i8; 195] = [0; 195];
    if (unsafe { keylog_file_fp }).is_null() {
        return 0 as i32 != 0;
    }
    pos = unsafe { strlen(label) };
    if pos > (::std::mem::size_of::<[i8; 32]>() as u64).wrapping_sub(1 as i32 as u64)
        || secretlen == 0
        || secretlen > 48 as i32 as u64
    {
        return 0 as i32 != 0;
    }
    (unsafe { memcpy(
        line.as_mut_ptr() as *mut libc::c_void,
        label as *const libc::c_void,
        pos,
    ) });
    let fresh1 = pos;
    pos = pos.wrapping_add(1);
    line[fresh1 as usize] = ' ' as i32 as i8;
    i = 0 as i32 as size_t;
    while i < 32 as i32 as u64 {
        let fresh2 = pos;
        pos = pos.wrapping_add(1);
        line[fresh2 as usize] =
            unsafe { *hex.offset((*client_random.offset(i as isize) as i32 >> 4 as i32) as isize) };
        let fresh3 = pos;
        pos = pos.wrapping_add(1);
        line[fresh3 as usize] =
            unsafe { *hex.offset((*client_random.offset(i as isize) as i32 & 0xf as i32) as isize) };
        i = i.wrapping_add(1);
    }
    let fresh4 = pos;
    pos = pos.wrapping_add(1);
    line[fresh4 as usize] = ' ' as i32 as i8;
    i = 0 as i32 as size_t;
    while i < secretlen {
        let fresh5 = pos;
        pos = pos.wrapping_add(1);
        line[fresh5 as usize] =
            unsafe { *hex.offset((*secret.offset(i as isize) as i32 >> 4 as i32) as isize) };
        let fresh6 = pos;
        pos = pos.wrapping_add(1);
        line[fresh6 as usize] =
            unsafe { *hex.offset((*secret.offset(i as isize) as i32 & 0xf as i32) as isize) };
        i = i.wrapping_add(1);
    }
    let fresh7 = pos;
    pos = pos.wrapping_add(1);
    line[fresh7 as usize] = '\n' as i32 as i8;
    line[pos as usize] = '\u{0}' as i32 as i8;
    (unsafe { fputs(line.as_mut_ptr(), keylog_file_fp) });
    return 1 as i32 != 0;
}
