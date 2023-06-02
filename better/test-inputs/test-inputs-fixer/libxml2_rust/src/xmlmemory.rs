use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type _xmlMutex;
    fn fclose(__stream: *mut FILE) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut FILE;
    fn fprintf(_: *mut FILE, _: *const i8, _: ...) -> i32;
    fn sscanf(_: *const i8, _: *const i8, _: ...) -> i32;
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn malloc(_: u64) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn getenv(__name: *const i8) -> *mut i8;
    static mut xmlMemStrdup: xmlStrdupFunc;
    static mut xmlRealloc: xmlReallocFunc;
    static mut xmlMallocAtomic: xmlMallocFunc;
    static mut xmlMalloc: xmlMallocFunc;
    static mut xmlFree: xmlFreeFunc;
    fn xmlNewMutex() -> xmlMutexPtr;
    fn xmlFreeMutex(tok: xmlMutexPtr);
    fn xmlMutexUnlock(tok: xmlMutexPtr);
    fn xmlMutexLock(tok: xmlMutexPtr);
    fn __xmlGenericErrorContext() -> *mut *mut libc::c_void;
    fn __xmlGenericError() -> *mut xmlGenericErrorFunc;
}
pub type size_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
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
pub type xmlGenericErrorFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
pub type xmlReallocFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void>;
pub type xmlStrdupFunc = Option<unsafe extern "C" fn(*const i8) -> *mut i8>;
pub type xmlMutexPtr = *mut xmlMutex;
pub type xmlMutex = _xmlMutex;
pub type MEMHDR = memnod;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct memnod {
    pub mh_tag: u32,
    pub mh_type: u32,
    pub mh_number: u64,
    pub mh_size: size_t,
    pub mh_file: *const i8,
    pub mh_line: u32,
}
static mut xmlMemInitialized: i32 = 0 as i32;
static mut debugMemSize: u64 = 0 as i32 as u64;
static mut debugMemBlocks: u64 = 0 as i32 as u64;
static mut debugMaxMemSize: u64 = 0 as i32 as u64;
static mut xmlMemMutex: xmlMutexPtr = 0 as *const xmlMutex as xmlMutexPtr;
static mut block: u32 = 0 as i32 as u32;
static mut xmlMemStopAtBlock: u32 = 0 as i32 as u32;
static mut xmlMemTraceBlockAt: *mut libc::c_void = 0 as *const libc::c_void as *mut libc::c_void;
#[no_mangle]
pub extern "C" fn xmlMallocBreakpoint() {
    (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
        *__xmlGenericErrorContext(),
        b"xmlMallocBreakpoint reached on block %d\n\0" as *const u8 as *const i8,
        xmlMemStopAtBlock,
    ) });
}
#[no_mangle]
pub extern "C" fn xmlMallocLoc(
    mut size: size_t,
    mut file: *const i8,
    mut line: i32,
) -> *mut libc::c_void {
    let mut p: *mut MEMHDR = 0 as *mut MEMHDR;
    let mut ret: *mut libc::c_void = 0 as *mut libc::c_void;
    if (unsafe { xmlMemInitialized }) == 0 {
        xmlInitMemory();
    }
    if size
        > (-(1 as i32) as size_t).wrapping_sub(
            (::std::mem::size_of::<MEMHDR>() as u64)
                .wrapping_add((::std::mem::size_of::<f64>() as u64).wrapping_sub(1 as i32 as u64))
                .wrapping_div(::std::mem::size_of::<f64>() as u64)
                .wrapping_mul(::std::mem::size_of::<f64>() as u64),
        )
    {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlMallocLoc : Unsigned overflow\n\0" as *const u8 as *const i8,
        ) });
        xmlMemoryDump();
        return 0 as *mut libc::c_void;
    }
    p = (unsafe { malloc(
        (::std::mem::size_of::<MEMHDR>() as u64)
            .wrapping_add((::std::mem::size_of::<f64>() as u64).wrapping_sub(1 as i32 as u64))
            .wrapping_div(::std::mem::size_of::<f64>() as u64)
            .wrapping_mul(::std::mem::size_of::<f64>() as u64)
            .wrapping_add(size),
    ) }) as *mut MEMHDR;
    if p.is_null() {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlMallocLoc : Out of free space\n\0" as *const u8 as *const i8,
        ) });
        xmlMemoryDump();
        return 0 as *mut libc::c_void;
    }
    (unsafe { (*p).mh_tag = 0x5aa5 as u32 });
    (unsafe { (*p).mh_size = size });
    (unsafe { (*p).mh_type = 1 as i32 as u32 });
    let fresh0 = unsafe { &mut ((*p).mh_file) };
    *fresh0 = file;
    (unsafe { (*p).mh_line = line as u32 });
    (unsafe { xmlMutexLock(xmlMemMutex) });
    (unsafe { block = block.wrapping_add(1) });
    (unsafe { (*p).mh_number = block as u64 });
    (unsafe { debugMemSize = debugMemSize.wrapping_add(size) });
    (unsafe { debugMemBlocks = debugMemBlocks.wrapping_add(1) });
    if (unsafe { debugMemSize }) > (unsafe { debugMaxMemSize }) {
        (unsafe { debugMaxMemSize = debugMemSize });
    }
    (unsafe { xmlMutexUnlock(xmlMemMutex) });
    if (unsafe { xmlMemStopAtBlock }) as u64 == (unsafe { (*p).mh_number }) {
        xmlMallocBreakpoint();
    }
    ret = (unsafe { (p as *mut i8).offset(
        (::std::mem::size_of::<MEMHDR>() as u64)
            .wrapping_add((::std::mem::size_of::<f64>() as u64).wrapping_sub(1 as i32 as u64))
            .wrapping_div(::std::mem::size_of::<f64>() as u64)
            .wrapping_mul(::std::mem::size_of::<f64>() as u64) as isize,
    ) }) as *mut libc::c_void;
    if (unsafe { xmlMemTraceBlockAt }) == ret {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"%p : Malloc(%lu) Ok\n\0" as *const u8 as *const i8,
            xmlMemTraceBlockAt,
            size,
        ) });
        xmlMallocBreakpoint();
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlMallocAtomicLoc(
    mut size: size_t,
    mut file: *const i8,
    mut line: i32,
) -> *mut libc::c_void {
    let mut p: *mut MEMHDR = 0 as *mut MEMHDR;
    let mut ret: *mut libc::c_void = 0 as *mut libc::c_void;
    if (unsafe { xmlMemInitialized }) == 0 {
        xmlInitMemory();
    }
    if size
        > (-(1 as i32) as size_t).wrapping_sub(
            (::std::mem::size_of::<MEMHDR>() as u64)
                .wrapping_add((::std::mem::size_of::<f64>() as u64).wrapping_sub(1 as i32 as u64))
                .wrapping_div(::std::mem::size_of::<f64>() as u64)
                .wrapping_mul(::std::mem::size_of::<f64>() as u64),
        )
    {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlMallocAtomicLoc : Unsigned overflow\n\0" as *const u8 as *const i8,
        ) });
        xmlMemoryDump();
        return 0 as *mut libc::c_void;
    }
    p = (unsafe { malloc(
        (::std::mem::size_of::<MEMHDR>() as u64)
            .wrapping_add((::std::mem::size_of::<f64>() as u64).wrapping_sub(1 as i32 as u64))
            .wrapping_div(::std::mem::size_of::<f64>() as u64)
            .wrapping_mul(::std::mem::size_of::<f64>() as u64)
            .wrapping_add(size),
    ) }) as *mut MEMHDR;
    if p.is_null() {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlMallocAtomicLoc : Out of free space\n\0" as *const u8 as *const i8,
        ) });
        xmlMemoryDump();
        return 0 as *mut libc::c_void;
    }
    (unsafe { (*p).mh_tag = 0x5aa5 as u32 });
    (unsafe { (*p).mh_size = size });
    (unsafe { (*p).mh_type = 4 as i32 as u32 });
    let fresh1 = unsafe { &mut ((*p).mh_file) };
    *fresh1 = file;
    (unsafe { (*p).mh_line = line as u32 });
    (unsafe { xmlMutexLock(xmlMemMutex) });
    (unsafe { block = block.wrapping_add(1) });
    (unsafe { (*p).mh_number = block as u64 });
    (unsafe { debugMemSize = debugMemSize.wrapping_add(size) });
    (unsafe { debugMemBlocks = debugMemBlocks.wrapping_add(1) });
    if (unsafe { debugMemSize }) > (unsafe { debugMaxMemSize }) {
        (unsafe { debugMaxMemSize = debugMemSize });
    }
    (unsafe { xmlMutexUnlock(xmlMemMutex) });
    if (unsafe { xmlMemStopAtBlock }) as u64 == (unsafe { (*p).mh_number }) {
        xmlMallocBreakpoint();
    }
    ret = (unsafe { (p as *mut i8).offset(
        (::std::mem::size_of::<MEMHDR>() as u64)
            .wrapping_add((::std::mem::size_of::<f64>() as u64).wrapping_sub(1 as i32 as u64))
            .wrapping_div(::std::mem::size_of::<f64>() as u64)
            .wrapping_mul(::std::mem::size_of::<f64>() as u64) as isize,
    ) }) as *mut libc::c_void;
    if (unsafe { xmlMemTraceBlockAt }) == ret {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"%p : Malloc(%lu) Ok\n\0" as *const u8 as *const i8,
            xmlMemTraceBlockAt,
            size,
        ) });
        xmlMallocBreakpoint();
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlMemMalloc(mut size: size_t) -> *mut libc::c_void {
    return xmlMallocLoc(size, b"none\0" as *const u8 as *const i8, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlReallocLoc(
    mut ptr: *mut libc::c_void,
    mut size: size_t,
    mut file: *const i8,
    mut line: i32,
) -> *mut libc::c_void {
    let mut p: *mut MEMHDR = 0 as *mut MEMHDR;
    let mut tmp: *mut MEMHDR = 0 as *mut MEMHDR;
    let mut number: u64 = 0;
    if ptr.is_null() {
        return xmlMallocLoc(size, file, line);
    }
    if (unsafe { xmlMemInitialized }) == 0 {
        xmlInitMemory();
    }
    p = (unsafe { (ptr as *mut i8).offset(
        -((::std::mem::size_of::<MEMHDR>() as u64)
            .wrapping_add((::std::mem::size_of::<f64>() as u64).wrapping_sub(1 as i32 as u64))
            .wrapping_div(::std::mem::size_of::<f64>() as u64)
            .wrapping_mul(::std::mem::size_of::<f64>() as u64) as isize),
    ) }) as *mut libc::c_void as *mut MEMHDR;
    number = unsafe { (*p).mh_number };
    if (unsafe { xmlMemStopAtBlock }) as u64 == number {
        xmlMallocBreakpoint();
    }
    if (unsafe { (*p).mh_tag }) != 0x5aa5 as u32 {
        debugmem_tag_error(p as *mut libc::c_void);
    } else {
        (unsafe { (*p).mh_tag = !(0x5aa5 as u32) });
        (unsafe { xmlMutexLock(xmlMemMutex) });
        (unsafe { debugMemSize = debugMemSize.wrapping_sub((*p).mh_size) });
        (unsafe { debugMemBlocks = debugMemBlocks.wrapping_sub(1) });
        (unsafe { xmlMutexUnlock(xmlMemMutex) });
        if size
            > (-(1 as i32) as size_t).wrapping_sub(
                (::std::mem::size_of::<MEMHDR>() as u64)
                    .wrapping_add(
                        (::std::mem::size_of::<f64>() as u64).wrapping_sub(1 as i32 as u64),
                    )
                    .wrapping_div(::std::mem::size_of::<f64>() as u64)
                    .wrapping_mul(::std::mem::size_of::<f64>() as u64),
            )
        {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"xmlReallocLoc : Unsigned overflow\n\0" as *const u8 as *const i8,
            ) });
            xmlMemoryDump();
            return 0 as *mut libc::c_void;
        }
        tmp = (unsafe { realloc(
            p as *mut libc::c_void,
            (::std::mem::size_of::<MEMHDR>() as u64)
                .wrapping_add((::std::mem::size_of::<f64>() as u64).wrapping_sub(1 as i32 as u64))
                .wrapping_div(::std::mem::size_of::<f64>() as u64)
                .wrapping_mul(::std::mem::size_of::<f64>() as u64)
                .wrapping_add(size),
        ) }) as *mut MEMHDR;
        if tmp.is_null() {
            (unsafe { free(p as *mut libc::c_void) });
        } else {
            p = tmp;
            if (unsafe { xmlMemTraceBlockAt }) == ptr {
                (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"%p : Realloced(%lu -> %lu) Ok\n\0" as *const u8 as *const i8,
                    xmlMemTraceBlockAt,
                    (*p).mh_size,
                    size,
                ) });
                xmlMallocBreakpoint();
            }
            (unsafe { (*p).mh_tag = 0x5aa5 as u32 });
            (unsafe { (*p).mh_number = number });
            (unsafe { (*p).mh_type = 2 as i32 as u32 });
            (unsafe { (*p).mh_size = size });
            let fresh2 = unsafe { &mut ((*p).mh_file) };
            *fresh2 = file;
            (unsafe { (*p).mh_line = line as u32 });
            (unsafe { xmlMutexLock(xmlMemMutex) });
            (unsafe { debugMemSize = debugMemSize.wrapping_add(size) });
            (unsafe { debugMemBlocks = debugMemBlocks.wrapping_add(1) });
            if (unsafe { debugMemSize }) > (unsafe { debugMaxMemSize }) {
                (unsafe { debugMaxMemSize = debugMemSize });
            }
            (unsafe { xmlMutexUnlock(xmlMemMutex) });
            return (unsafe { (p as *mut i8).offset(
                (::std::mem::size_of::<MEMHDR>() as u64)
                    .wrapping_add(
                        (::std::mem::size_of::<f64>() as u64).wrapping_sub(1 as i32 as u64),
                    )
                    .wrapping_div(::std::mem::size_of::<f64>() as u64)
                    .wrapping_mul(::std::mem::size_of::<f64>() as u64) as isize,
            ) }) as *mut libc::c_void;
        }
    }
    return 0 as *mut libc::c_void;
}
#[no_mangle]
pub extern "C" fn xmlMemRealloc(mut ptr: *mut libc::c_void, mut size: size_t) -> *mut libc::c_void {
    return xmlReallocLoc(ptr, size, b"none\0" as *const u8 as *const i8, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlMemFree(mut ptr: *mut libc::c_void) {
    let mut p: *mut MEMHDR = 0 as *mut MEMHDR;
    let mut target: *mut i8 = 0 as *mut i8;
    if ptr.is_null() {
        return;
    }
    if ptr == -(1 as i32) as *mut libc::c_void {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"trying to free pointer from freed area\n\0" as *const u8 as *const i8,
        ) });
    } else {
        if (unsafe { xmlMemTraceBlockAt }) == ptr {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"%p : Freed()\n\0" as *const u8 as *const i8,
                xmlMemTraceBlockAt,
            ) });
            xmlMallocBreakpoint();
        }
        target = ptr as *mut i8;
        p = (unsafe { (ptr as *mut i8).offset(
            -((::std::mem::size_of::<MEMHDR>() as u64)
                .wrapping_add((::std::mem::size_of::<f64>() as u64).wrapping_sub(1 as i32 as u64))
                .wrapping_div(::std::mem::size_of::<f64>() as u64)
                .wrapping_mul(::std::mem::size_of::<f64>() as u64) as isize),
        ) }) as *mut libc::c_void as *mut MEMHDR;
        if (unsafe { (*p).mh_tag }) != 0x5aa5 as u32 {
            debugmem_tag_error(p as *mut libc::c_void);
        } else {
            if (unsafe { xmlMemStopAtBlock }) as u64 == (unsafe { (*p).mh_number }) {
                xmlMallocBreakpoint();
            }
            (unsafe { (*p).mh_tag = !(0x5aa5 as u32) });
            (unsafe { memset(target as *mut libc::c_void, -(1 as i32), (*p).mh_size) });
            (unsafe { xmlMutexLock(xmlMemMutex) });
            (unsafe { debugMemSize = debugMemSize.wrapping_sub((*p).mh_size) });
            (unsafe { debugMemBlocks = debugMemBlocks.wrapping_sub(1) });
            (unsafe { xmlMutexUnlock(xmlMemMutex) });
            (unsafe { free(p as *mut libc::c_void) });
            return;
        }
    }
    (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
        *__xmlGenericErrorContext(),
        b"xmlMemFree(%p) error\n\0" as *const u8 as *const i8,
        ptr,
    ) });
    xmlMallocBreakpoint();
}
#[no_mangle]
pub extern "C" fn xmlMemStrdupLoc(
    mut str: *const i8,
    mut file: *const i8,
    mut line: i32,
) -> *mut i8 {
    let mut s: *mut i8 = 0 as *mut i8;
    let mut size: size_t = (unsafe { strlen(str) }).wrapping_add(1 as i32 as u64);
    let mut p: *mut MEMHDR = 0 as *mut MEMHDR;
    if (unsafe { xmlMemInitialized }) == 0 {
        xmlInitMemory();
    }
    if size
        > (-(1 as i32) as size_t).wrapping_sub(
            (::std::mem::size_of::<MEMHDR>() as u64)
                .wrapping_add((::std::mem::size_of::<f64>() as u64).wrapping_sub(1 as i32 as u64))
                .wrapping_div(::std::mem::size_of::<f64>() as u64)
                .wrapping_mul(::std::mem::size_of::<f64>() as u64),
        )
    {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlMemStrdupLoc : Unsigned overflow\n\0" as *const u8 as *const i8,
        ) });
        xmlMemoryDump();
        return 0 as *mut i8;
    }
    p = (unsafe { malloc(
        (::std::mem::size_of::<MEMHDR>() as u64)
            .wrapping_add((::std::mem::size_of::<f64>() as u64).wrapping_sub(1 as i32 as u64))
            .wrapping_div(::std::mem::size_of::<f64>() as u64)
            .wrapping_mul(::std::mem::size_of::<f64>() as u64)
            .wrapping_add(size),
    ) }) as *mut MEMHDR;
    if p.is_null() {
        return 0 as *mut i8;
    } else {
        (unsafe { (*p).mh_tag = 0x5aa5 as u32 });
        (unsafe { (*p).mh_size = size });
        (unsafe { (*p).mh_type = 3 as i32 as u32 });
        let fresh3 = unsafe { &mut ((*p).mh_file) };
        *fresh3 = file;
        (unsafe { (*p).mh_line = line as u32 });
        (unsafe { xmlMutexLock(xmlMemMutex) });
        (unsafe { block = block.wrapping_add(1) });
        (unsafe { (*p).mh_number = block as u64 });
        (unsafe { debugMemSize = debugMemSize.wrapping_add(size) });
        (unsafe { debugMemBlocks = debugMemBlocks.wrapping_add(1) });
        if (unsafe { debugMemSize }) > (unsafe { debugMaxMemSize }) {
            (unsafe { debugMaxMemSize = debugMemSize });
        }
        (unsafe { xmlMutexUnlock(xmlMemMutex) });
        s = (unsafe { (p as *mut i8).offset(
            (::std::mem::size_of::<MEMHDR>() as u64)
                .wrapping_add((::std::mem::size_of::<f64>() as u64).wrapping_sub(1 as i32 as u64))
                .wrapping_div(::std::mem::size_of::<f64>() as u64)
                .wrapping_mul(::std::mem::size_of::<f64>() as u64) as isize,
        ) }) as *mut libc::c_void as *mut i8;
        if (unsafe { xmlMemStopAtBlock }) as u64 == (unsafe { (*p).mh_number }) {
            xmlMallocBreakpoint();
        }
        (unsafe { strcpy(s, str) });
        if (unsafe { xmlMemTraceBlockAt }) == s as *mut libc::c_void {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"%p : Strdup() Ok\n\0" as *const u8 as *const i8,
                xmlMemTraceBlockAt,
            ) });
            xmlMallocBreakpoint();
        }
        return s;
    };
}
#[no_mangle]
pub extern "C" fn xmlMemoryStrdup(mut str: *const i8) -> *mut i8 {
    return xmlMemStrdupLoc(str, b"none\0" as *const u8 as *const i8, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlMemUsed() -> i32 {
    let mut res: i32 = 0;
    (unsafe { xmlMutexLock(xmlMemMutex) });
    res = (unsafe { debugMemSize }) as i32;
    (unsafe { xmlMutexUnlock(xmlMemMutex) });
    return res;
}
#[no_mangle]
pub extern "C" fn xmlMemBlocks() -> i32 {
    let mut res: i32 = 0;
    (unsafe { xmlMutexLock(xmlMemMutex) });
    res = (unsafe { debugMemBlocks }) as i32;
    (unsafe { xmlMutexUnlock(xmlMemMutex) });
    return res;
}
#[no_mangle]
pub extern "C" fn xmlMemDisplayLast(mut fp: *mut FILE, mut nbBytes: i64) {
    let mut old_fp: *mut FILE = fp;
    if nbBytes <= 0 as i32 as i64 {
        return;
    }
    if fp.is_null() {
        fp = unsafe { fopen(
            b".memorylist\0" as *const u8 as *const i8,
            b"w\0" as *const u8 as *const i8,
        ) };
        if fp.is_null() {
            return;
        }
    }
    (unsafe { fprintf(
        fp,
        b"Memory list not compiled (MEM_LIST not defined !)\n\0" as *const u8 as *const i8,
    ) });
    if old_fp.is_null() {
        (unsafe { fclose(fp) });
    }
}
#[no_mangle]
pub extern "C" fn xmlMemDisplay(mut fp: *mut FILE) {
    let mut old_fp: *mut FILE = fp;
    if fp.is_null() {
        fp = unsafe { fopen(
            b".memorylist\0" as *const u8 as *const i8,
            b"w\0" as *const u8 as *const i8,
        ) };
        if fp.is_null() {
            return;
        }
    }
    (unsafe { fprintf(
        fp,
        b"Memory list not compiled (MEM_LIST not defined !)\n\0" as *const u8 as *const i8,
    ) });
    if old_fp.is_null() {
        (unsafe { fclose(fp) });
    }
}
extern "C" fn debugmem_tag_error(mut p: *mut libc::c_void) {
    (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
        *__xmlGenericErrorContext(),
        b"Memory tag error occurs :%p \n\t bye\n\0" as *const u8 as *const i8,
        p,
    ) });
}
#[no_mangle]
pub extern "C" fn xmlMemShow(mut fp: *mut FILE, mut _nr: i32) {
    if !fp.is_null() {
        (unsafe { fprintf(
            fp,
            b"      MEMORY ALLOCATED : %lu, MAX was %lu\n\0" as *const u8 as *const i8,
            debugMemSize,
            debugMaxMemSize,
        ) });
    }
}
#[no_mangle]
pub extern "C" fn xmlMemoryDump() {}
#[no_mangle]
pub extern "C" fn xmlInitMemory() -> i32 {
    let mut breakpoint: *mut i8 = 0 as *mut i8;
    if (unsafe { xmlMemInitialized }) != 0 {
        return -(1 as i32);
    }
    (unsafe { xmlMemInitialized = 1 as i32 });
    (unsafe { xmlMemMutex = xmlNewMutex() });
    breakpoint = unsafe { getenv(b"XML_MEM_BREAKPOINT\0" as *const u8 as *const i8) };
    if !breakpoint.is_null() {
        (unsafe { sscanf(
            breakpoint,
            b"%ud\0" as *const u8 as *const i8,
            &mut xmlMemStopAtBlock as *mut u32,
        ) });
    }
    breakpoint = unsafe { getenv(b"XML_MEM_TRACE\0" as *const u8 as *const i8) };
    if !breakpoint.is_null() {
        (unsafe { sscanf(
            breakpoint,
            b"%p\0" as *const u8 as *const i8,
            &mut xmlMemTraceBlockAt as *mut *mut libc::c_void,
        ) });
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlCleanupMemory() {
    if (unsafe { xmlMemInitialized }) == 0 as i32 {
        return;
    }
    (unsafe { xmlFreeMutex(xmlMemMutex) });
    (unsafe { xmlMemMutex = 0 as xmlMutexPtr });
    (unsafe { xmlMemInitialized = 0 as i32 });
}
#[no_mangle]
pub extern "C" fn xmlMemSetup(
    mut freeFunc: xmlFreeFunc,
    mut mallocFunc: xmlMallocFunc,
    mut reallocFunc: xmlReallocFunc,
    mut strdupFunc: xmlStrdupFunc,
) -> i32 {
    if freeFunc.is_none() {
        return -(1 as i32);
    }
    if mallocFunc.is_none() {
        return -(1 as i32);
    }
    if reallocFunc.is_none() {
        return -(1 as i32);
    }
    if strdupFunc.is_none() {
        return -(1 as i32);
    }
    (unsafe { xmlFree = freeFunc });
    (unsafe { xmlMalloc = mallocFunc });
    (unsafe { xmlMallocAtomic = mallocFunc });
    (unsafe { xmlRealloc = reallocFunc });
    (unsafe { xmlMemStrdup = strdupFunc });
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlMemGet(
    mut freeFunc: *mut xmlFreeFunc,
    mut mallocFunc: *mut xmlMallocFunc,
    mut reallocFunc: *mut xmlReallocFunc,
    mut strdupFunc: *mut xmlStrdupFunc,
) -> i32 {
    if !freeFunc.is_null() {
        (unsafe { *freeFunc = xmlFree });
    }
    if !mallocFunc.is_null() {
        (unsafe { *mallocFunc = xmlMalloc });
    }
    if !reallocFunc.is_null() {
        (unsafe { *reallocFunc = xmlRealloc });
    }
    if !strdupFunc.is_null() {
        (unsafe { *strdupFunc = xmlMemStrdup });
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlGcMemSetup(
    mut freeFunc: xmlFreeFunc,
    mut mallocFunc: xmlMallocFunc,
    mut mallocAtomicFunc: xmlMallocFunc,
    mut reallocFunc: xmlReallocFunc,
    mut strdupFunc: xmlStrdupFunc,
) -> i32 {
    if freeFunc.is_none() {
        return -(1 as i32);
    }
    if mallocFunc.is_none() {
        return -(1 as i32);
    }
    if mallocAtomicFunc.is_none() {
        return -(1 as i32);
    }
    if reallocFunc.is_none() {
        return -(1 as i32);
    }
    if strdupFunc.is_none() {
        return -(1 as i32);
    }
    (unsafe { xmlFree = freeFunc });
    (unsafe { xmlMalloc = mallocFunc });
    (unsafe { xmlMallocAtomic = mallocAtomicFunc });
    (unsafe { xmlRealloc = reallocFunc });
    (unsafe { xmlMemStrdup = strdupFunc });
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlGcMemGet(
    mut freeFunc: *mut xmlFreeFunc,
    mut mallocFunc: *mut xmlMallocFunc,
    mut mallocAtomicFunc: *mut xmlMallocFunc,
    mut reallocFunc: *mut xmlReallocFunc,
    mut strdupFunc: *mut xmlStrdupFunc,
) -> i32 {
    if !freeFunc.is_null() {
        (unsafe { *freeFunc = xmlFree });
    }
    if !mallocFunc.is_null() {
        (unsafe { *mallocFunc = xmlMalloc });
    }
    if !mallocAtomicFunc.is_null() {
        (unsafe { *mallocAtomicFunc = xmlMallocAtomic });
    }
    if !reallocFunc.is_null() {
        (unsafe { *reallocFunc = xmlRealloc });
    }
    if !strdupFunc.is_null() {
        (unsafe { *strdupFunc = xmlMemStrdup });
    }
    return 0 as i32;
}
