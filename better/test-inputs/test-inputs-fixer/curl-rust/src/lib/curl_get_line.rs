use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn fgets(__s: *mut i8, __n: i32, __stream: *mut FILE) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
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
#[no_mangle]
pub extern "C" fn Curl_get_line(mut buf: *mut i8, mut len: i32, mut input: *mut FILE) -> *mut i8 {
    let mut partial: bool = 0 as i32 != 0;
    loop {
        let mut b: *mut i8 = unsafe { fgets(buf, len, input) };
        if b.is_null() {
            break;
        }
        let mut rlen: size_t = unsafe { strlen(b) };
        if rlen != 0 && (unsafe { *b.offset(rlen.wrapping_sub(1 as i32 as u64) as isize) }) as i32 == '\n' as i32
        {
            if partial {
                partial = 0 as i32 != 0;
            } else {
                return b;
            }
        } else {
            partial = 1 as i32 != 0;
        }
    }
    return 0 as *mut i8;
}
