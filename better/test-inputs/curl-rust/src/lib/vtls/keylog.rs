use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn curl_getenv(variable: *const libc::c_char) -> *mut libc::c_char;
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    fn setvbuf(
        __stream: *mut FILE,
        __buf: *mut libc::c_char,
        __modes: libc::c_int,
        __n: size_t,
    ) -> libc::c_int;
    fn fputs(__s: *const libc::c_char, __stream: *mut FILE) -> libc::c_int;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    static mut Curl_cfree: curl_free_callback;
}
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type curl_free_callback = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
static mut keylog_file_fp: *mut FILE = 0 as *const FILE as *mut FILE;
#[no_mangle]
pub unsafe extern "C" fn Curl_tls_keylog_open() {
    let mut keylog_file_name: *mut libc::c_char = 0 as *mut libc::c_char;
    if keylog_file_fp.is_null() {
        keylog_file_name = curl_getenv(
            b"SSLKEYLOGFILE\0" as *const u8 as *const libc::c_char,
        );
        if !keylog_file_name.is_null() {
            keylog_file_fp = fopen(
                keylog_file_name,
                b"a\0" as *const u8 as *const libc::c_char,
            );
            if !keylog_file_fp.is_null() {
                if setvbuf(
                    keylog_file_fp,
                    0 as *mut libc::c_char,
                    1 as libc::c_int,
                    4096 as libc::c_int as size_t,
                ) != 0
                {
                    fclose(keylog_file_fp);
                    keylog_file_fp = 0 as *mut FILE;
                }
            }
            Curl_cfree
                .expect(
                    "non-null function pointer",
                )(keylog_file_name as *mut libc::c_void);
            keylog_file_name = 0 as *mut libc::c_char;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_tls_keylog_close() {
    if !keylog_file_fp.is_null() {
        fclose(keylog_file_fp);
        keylog_file_fp = 0 as *mut FILE;
    }
}
#[no_mangle]
pub unsafe extern "C" fn Curl_tls_keylog_enabled() -> bool {
    return !keylog_file_fp.is_null();
}
#[no_mangle]
pub unsafe extern "C" fn Curl_tls_keylog_write_line(
    mut line: *const libc::c_char,
) -> bool {
    let mut linelen: size_t = 0;
    let mut buf: [libc::c_char; 256] = [0; 256];
    if keylog_file_fp.is_null() || line.is_null() {
        return 0 as libc::c_int != 0;
    }
    linelen = strlen(line);
    if linelen == 0 as libc::c_int as libc::c_ulong
        || linelen
            > (::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong)
                .wrapping_sub(2 as libc::c_int as libc::c_ulong)
    {
        return 0 as libc::c_int != 0;
    }
    memcpy(buf.as_mut_ptr() as *mut libc::c_void, line as *const libc::c_void, linelen);
    if *line.offset(linelen.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
        as libc::c_int != '\n' as i32
    {
        let fresh0 = linelen;
        linelen = linelen.wrapping_add(1);
        buf[fresh0 as usize] = '\n' as i32 as libc::c_char;
    }
    buf[linelen as usize] = '\u{0}' as i32 as libc::c_char;
    fputs(buf.as_mut_ptr(), keylog_file_fp);
    return 1 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_tls_keylog_write(
    mut label: *const libc::c_char,
    mut client_random: *const libc::c_uchar,
    mut secret: *const libc::c_uchar,
    mut secretlen: size_t,
) -> bool {
    let mut hex: *const libc::c_char = b"0123456789ABCDEF\0" as *const u8
        as *const libc::c_char;
    let mut pos: size_t = 0;
    let mut i: size_t = 0;
    let mut line: [libc::c_char; 195] = [0; 195];
    if keylog_file_fp.is_null() {
        return 0 as libc::c_int != 0;
    }
    pos = strlen(label);
    if pos
        > (::std::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) || secretlen == 0
        || secretlen > 48 as libc::c_int as libc::c_ulong
    {
        return 0 as libc::c_int != 0;
    }
    memcpy(line.as_mut_ptr() as *mut libc::c_void, label as *const libc::c_void, pos);
    let fresh1 = pos;
    pos = pos.wrapping_add(1);
    line[fresh1 as usize] = ' ' as i32 as libc::c_char;
    i = 0 as libc::c_int as size_t;
    while i < 32 as libc::c_int as libc::c_ulong {
        let fresh2 = pos;
        pos = pos.wrapping_add(1);
        line[fresh2
            as usize] = *hex
            .offset(
                (*client_random.offset(i as isize) as libc::c_int >> 4 as libc::c_int)
                    as isize,
            );
        let fresh3 = pos;
        pos = pos.wrapping_add(1);
        line[fresh3
            as usize] = *hex
            .offset(
                (*client_random.offset(i as isize) as libc::c_int & 0xf as libc::c_int)
                    as isize,
            );
        i = i.wrapping_add(1);
    }
    let fresh4 = pos;
    pos = pos.wrapping_add(1);
    line[fresh4 as usize] = ' ' as i32 as libc::c_char;
    i = 0 as libc::c_int as size_t;
    while i < secretlen {
        let fresh5 = pos;
        pos = pos.wrapping_add(1);
        line[fresh5
            as usize] = *hex
            .offset(
                (*secret.offset(i as isize) as libc::c_int >> 4 as libc::c_int) as isize,
            );
        let fresh6 = pos;
        pos = pos.wrapping_add(1);
        line[fresh6
            as usize] = *hex
            .offset(
                (*secret.offset(i as isize) as libc::c_int & 0xf as libc::c_int) as isize,
            );
        i = i.wrapping_add(1);
    }
    let fresh7 = pos;
    pos = pos.wrapping_add(1);
    line[fresh7 as usize] = '\n' as i32 as libc::c_char;
    line[pos as usize] = '\u{0}' as i32 as libc::c_char;
    fputs(line.as_mut_ptr(), keylog_file_fp);
    return 1 as libc::c_int != 0;
}
