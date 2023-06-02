use ::libc;
extern "C" {
    pub type _IO_wide_data;
    
    
    
    fn fclose(__stream: * mut crate::src::tree::_IO_FILE) -> i32;
    fn fopen(_: * const i8, _: * const i8) -> * mut crate::src::tree::_IO_FILE;
    fn fprintf(_: * mut crate::src::tree::_IO_FILE, _: * const i8, _: ...) -> i32;
    fn sscanf(_: * const i8, _: * const i8, _: ...) -> i32;
    fn memset(
        _: * mut core::ffi::c_void,
        _: i32,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn strcpy(_: * mut i8, _: * const i8) -> * mut i8;
    fn strlen(_: * const i8) -> u64;
    fn malloc(_: u64) -> * mut core::ffi::c_void;
    fn realloc(_: * mut core::ffi::c_void, _: u64) -> * mut core::ffi::c_void;
    fn free(__ptr: * mut core::ffi::c_void);
    fn getenv(__name: * const i8) -> * mut i8;
    static mut xmlMemStrdup: Option<unsafe extern "C"  fn(_: * const i8,) -> * mut i8>;
    static mut xmlRealloc: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: u64,) -> * mut core::ffi::c_void>;
    static mut xmlMallocAtomic: Option<unsafe extern "C"  fn(_: u64,) -> * mut core::ffi::c_void>;
    static mut xmlMalloc: Option<unsafe extern "C"  fn(_: u64,) -> * mut core::ffi::c_void>;
    static mut xmlFree: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>;
    
    
    
    
    fn __xmlGenericErrorContext() -> * mut * mut core::ffi::c_void;
    fn __xmlGenericError() -> * mut Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
}
pub use crate::src::threads::xmlFreeMutex;
pub use crate::src::threads::xmlMutexLock;
pub use crate::src::threads::xmlMutexUnlock;
pub use crate::src::threads::xmlNewMutex;
pub use crate::src::threads::_xmlMutex;
pub use crate::src::xmllint::_IO_marker;
pub use crate::src::xmlsave::_IO_codecvt;
pub type size_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::tree::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::tree::_IO_FILE;
pub type xmlGenericErrorFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
pub type xmlFreeFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C"  fn(_: u64,) -> * mut core::ffi::c_void>;
pub type xmlReallocFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: u64,) -> * mut core::ffi::c_void>;
pub type xmlStrdupFunc = Option<unsafe extern "C"  fn(_: * const i8,) -> * mut i8>;
pub type xmlMutexPtr = * mut crate::src::threads::_xmlMutex;
pub type xmlMutex = crate::src::threads::_xmlMutex;
pub type MEMHDR = crate::src::xmlmemory::memnod;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct memnod {
    pub mh_tag: u32,
    pub mh_type: u32,
    pub mh_number: u64,
    pub mh_size: u64,
    pub mh_file: * const i8,
    pub mh_line: u32,
}
impl memnod {
    pub const fn new() -> Self {
        memnod {
        mh_tag: 0,
        mh_type: 0,
        mh_number: 0,
        mh_size: 0,
        mh_file: (0 as * const i8),
        mh_line: 0
        }
    }
}

impl std::default::Default for memnod {
    fn default() -> Self { memnod::new() }
}

static mut xmlMemInitialized: i32 = 0 as i32;
static mut debugMemSize: u64 = 0 as i32 as u64;
static mut debugMemBlocks: u64 = 0 as i32 as u64;
static mut debugMaxMemSize: u64 = 0 as i32 as u64;
static mut xmlMemMutex: * mut crate::src::threads::_xmlMutex = 0 as *const xmlMutex as xmlMutexPtr;
static mut block: u32 = 0 as i32 as u32;
static mut xmlMemStopAtBlock: u32 = 0 as i32 as u32;
static mut xmlMemTraceBlockAt: * mut core::ffi::c_void = 0 as *const libc::c_void
    as *mut libc::c_void;
#[no_mangle]
pub unsafe extern "C" fn xmlMallocBreakpoint() {
    (*__xmlGenericError())
        .expect(
            "non-null function pointer",
        )(
        *__xmlGenericErrorContext(),
        b"xmlMallocBreakpoint reached on block %d\n\0" as *const u8
            as *const i8,
        xmlMemStopAtBlock,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlMallocLoc(
    mut size: u64,
    mut file: * const i8,
    mut line: i32,
) -> * mut core::ffi::c_void {
    let mut p: * mut crate::src::xmlmemory::memnod = 0 as *mut MEMHDR;
    let mut ret: * mut core::ffi::c_void = 0 as *mut libc::c_void;
    if xmlMemInitialized == 0 {
        xmlInitMemory();
    }
    if size
        > (-(1 as i32) as size_t)
            .wrapping_sub(
                (::std::mem::size_of::<MEMHDR>() as u64)
                    .wrapping_add(
                        (::std::mem::size_of::<f64>() as u64)
                            .wrapping_sub(1 as i32 as u64),
                    )
                    .wrapping_div(
                        ::std::mem::size_of::<f64>() as u64,
                    )
                    .wrapping_mul(
                        ::std::mem::size_of::<f64>() as u64,
                    ),
            )
    {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlMallocLoc : Unsigned overflow\n\0" as *const u8 as *const i8,
        );
        xmlMemoryDump();
        return 0 as *mut libc::c_void;
    }
    p = malloc(
        (::std::mem::size_of::<MEMHDR>() as u64)
            .wrapping_add(
                (::std::mem::size_of::<f64>() as u64)
                    .wrapping_sub(1 as i32 as u64),
            )
            .wrapping_div(::std::mem::size_of::<f64>() as u64)
            .wrapping_mul(::std::mem::size_of::<f64>() as u64)
            .wrapping_add(size),
    ) as *mut MEMHDR;
    if p.is_null() {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlMallocLoc : Out of free space\n\0" as *const u8 as *const i8,
        );
        xmlMemoryDump();
        return 0 as *mut libc::c_void;
    }
    (*p).mh_tag = 0x5aa5 as u32;
    (*p).mh_size = size;
    (*p).mh_type = 1 as i32 as u32;
    let fresh0 = &mut ((*p).mh_file);
    *fresh0 = file;
    (*p).mh_line = line as u32;
    xmlMutexLock(xmlMemMutex);
    block = block.wrapping_add(1);
    (*p).mh_number = block as u64;
    debugMemSize = debugMemSize.wrapping_add(size);
    debugMemBlocks = debugMemBlocks.wrapping_add(1);
    if debugMemSize > debugMaxMemSize {
        debugMaxMemSize = debugMemSize;
    }
    xmlMutexUnlock(xmlMemMutex);
    if xmlMemStopAtBlock as u64 == (*p).mh_number {
        xmlMallocBreakpoint();
    }
    ret = (p as *mut i8)
        .offset(
            (::std::mem::size_of::<MEMHDR>() as u64)
                .wrapping_add(
                    (::std::mem::size_of::<f64>() as u64)
                        .wrapping_sub(1 as i32 as u64),
                )
                .wrapping_div(::std::mem::size_of::<f64>() as u64)
                .wrapping_mul(::std::mem::size_of::<f64>() as u64)
                as isize,
        ) as *mut libc::c_void;
    if xmlMemTraceBlockAt == ret {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"%p : Malloc(%lu) Ok\n\0" as *const u8 as *const i8,
            xmlMemTraceBlockAt,
            size,
        );
        xmlMallocBreakpoint();
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlMallocAtomicLoc(
    mut size: u64,
    mut file: * const i8,
    mut line: i32,
) -> * mut core::ffi::c_void {
    let mut p: * mut crate::src::xmlmemory::memnod = 0 as *mut MEMHDR;
    let mut ret: * mut core::ffi::c_void = 0 as *mut libc::c_void;
    if xmlMemInitialized == 0 {
        xmlInitMemory();
    }
    if size
        > (-(1 as i32) as size_t)
            .wrapping_sub(
                (::std::mem::size_of::<MEMHDR>() as u64)
                    .wrapping_add(
                        (::std::mem::size_of::<f64>() as u64)
                            .wrapping_sub(1 as i32 as u64),
                    )
                    .wrapping_div(
                        ::std::mem::size_of::<f64>() as u64,
                    )
                    .wrapping_mul(
                        ::std::mem::size_of::<f64>() as u64,
                    ),
            )
    {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlMallocAtomicLoc : Unsigned overflow\n\0" as *const u8
                as *const i8,
        );
        xmlMemoryDump();
        return 0 as *mut libc::c_void;
    }
    p = malloc(
        (::std::mem::size_of::<MEMHDR>() as u64)
            .wrapping_add(
                (::std::mem::size_of::<f64>() as u64)
                    .wrapping_sub(1 as i32 as u64),
            )
            .wrapping_div(::std::mem::size_of::<f64>() as u64)
            .wrapping_mul(::std::mem::size_of::<f64>() as u64)
            .wrapping_add(size),
    ) as *mut MEMHDR;
    if p.is_null() {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlMallocAtomicLoc : Out of free space\n\0" as *const u8
                as *const i8,
        );
        xmlMemoryDump();
        return 0 as *mut libc::c_void;
    }
    (*p).mh_tag = 0x5aa5 as u32;
    (*p).mh_size = size;
    (*p).mh_type = 4 as i32 as u32;
    let fresh1 = &mut ((*p).mh_file);
    *fresh1 = file;
    (*p).mh_line = line as u32;
    xmlMutexLock(xmlMemMutex);
    block = block.wrapping_add(1);
    (*p).mh_number = block as u64;
    debugMemSize = debugMemSize.wrapping_add(size);
    debugMemBlocks = debugMemBlocks.wrapping_add(1);
    if debugMemSize > debugMaxMemSize {
        debugMaxMemSize = debugMemSize;
    }
    xmlMutexUnlock(xmlMemMutex);
    if xmlMemStopAtBlock as u64 == (*p).mh_number {
        xmlMallocBreakpoint();
    }
    ret = (p as *mut i8)
        .offset(
            (::std::mem::size_of::<MEMHDR>() as u64)
                .wrapping_add(
                    (::std::mem::size_of::<f64>() as u64)
                        .wrapping_sub(1 as i32 as u64),
                )
                .wrapping_div(::std::mem::size_of::<f64>() as u64)
                .wrapping_mul(::std::mem::size_of::<f64>() as u64)
                as isize,
        ) as *mut libc::c_void;
    if xmlMemTraceBlockAt == ret {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"%p : Malloc(%lu) Ok\n\0" as *const u8 as *const i8,
            xmlMemTraceBlockAt,
            size,
        );
        xmlMallocBreakpoint();
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemMalloc(mut size: u64) -> * mut core::ffi::c_void {
    return xmlMallocLoc(
        size,
        b"none\0" as *const u8 as *const i8,
        0 as i32,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlReallocLoc(
    mut ptr: * mut core::ffi::c_void,
    mut size: u64,
    mut file: * const i8,
    mut line: i32,
) -> * mut core::ffi::c_void {
    let mut p: * mut crate::src::xmlmemory::memnod = 0 as *mut MEMHDR;
    let mut tmp: * mut crate::src::xmlmemory::memnod = 0 as *mut MEMHDR;
    let mut number: u64 = 0;
    if ptr.is_null() {
        return xmlMallocLoc(size, file, line);
    }
    if xmlMemInitialized == 0 {
        xmlInitMemory();
    }
    p = (ptr as *mut i8)
        .offset(
            -((::std::mem::size_of::<MEMHDR>() as u64)
                .wrapping_add(
                    (::std::mem::size_of::<f64>() as u64)
                        .wrapping_sub(1 as i32 as u64),
                )
                .wrapping_div(::std::mem::size_of::<f64>() as u64)
                .wrapping_mul(::std::mem::size_of::<f64>() as u64)
                as isize),
        ) as *mut libc::c_void as *mut MEMHDR;
    number = (*p).mh_number;
    if xmlMemStopAtBlock as u64 == number {
        xmlMallocBreakpoint();
    }
    if (*p).mh_tag != 0x5aa5 as u32 {
        debugmem_tag_error(p as *mut libc::c_void);
    } else {
        (*p).mh_tag = !(0x5aa5 as u32);
        xmlMutexLock(xmlMemMutex);
        debugMemSize = debugMemSize.wrapping_sub((*p).mh_size);
        debugMemBlocks = debugMemBlocks.wrapping_sub(1);
        xmlMutexUnlock(xmlMemMutex);
        if size
            > (-(1 as i32) as size_t)
                .wrapping_sub(
                    (::std::mem::size_of::<MEMHDR>() as u64)
                        .wrapping_add(
                            (::std::mem::size_of::<f64>() as u64)
                                .wrapping_sub(1 as i32 as u64),
                        )
                        .wrapping_div(
                            ::std::mem::size_of::<f64>() as u64,
                        )
                        .wrapping_mul(
                            ::std::mem::size_of::<f64>() as u64,
                        ),
                )
        {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"xmlReallocLoc : Unsigned overflow\n\0" as *const u8
                    as *const i8,
            );
            xmlMemoryDump();
            return 0 as *mut libc::c_void;
        }
        tmp = realloc(
            p as *mut libc::c_void,
            (::std::mem::size_of::<MEMHDR>() as u64)
                .wrapping_add(
                    (::std::mem::size_of::<f64>() as u64)
                        .wrapping_sub(1 as i32 as u64),
                )
                .wrapping_div(::std::mem::size_of::<f64>() as u64)
                .wrapping_mul(::std::mem::size_of::<f64>() as u64)
                .wrapping_add(size),
        ) as *mut MEMHDR;
        if tmp.is_null() {
            free(p as *mut libc::c_void);
        } else {
            p = tmp;
            if xmlMemTraceBlockAt == ptr {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"%p : Realloced(%lu -> %lu) Ok\n\0" as *const u8
                        as *const i8,
                    xmlMemTraceBlockAt,
                    (*p).mh_size,
                    size,
                );
                xmlMallocBreakpoint();
            }
            (*p).mh_tag = 0x5aa5 as u32;
            (*p).mh_number = number;
            (*p).mh_type = 2 as i32 as u32;
            (*p).mh_size = size;
            let fresh2 = &mut ((*p).mh_file);
            *fresh2 = file;
            (*p).mh_line = line as u32;
            xmlMutexLock(xmlMemMutex);
            debugMemSize = debugMemSize.wrapping_add(size);
            debugMemBlocks = debugMemBlocks.wrapping_add(1);
            if debugMemSize > debugMaxMemSize {
                debugMaxMemSize = debugMemSize;
            }
            xmlMutexUnlock(xmlMemMutex);
            return (p as *mut i8)
                .offset(
                    (::std::mem::size_of::<MEMHDR>() as u64)
                        .wrapping_add(
                            (::std::mem::size_of::<f64>() as u64)
                                .wrapping_sub(1 as i32 as u64),
                        )
                        .wrapping_div(
                            ::std::mem::size_of::<f64>() as u64,
                        )
                        .wrapping_mul(
                            ::std::mem::size_of::<f64>() as u64,
                        ) as isize,
                ) as *mut libc::c_void;
        }
    }
    return 0 as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemRealloc(
    mut ptr: * mut core::ffi::c_void,
    mut size: u64,
) -> * mut core::ffi::c_void {
    return xmlReallocLoc(
        ptr,
        size,
        b"none\0" as *const u8 as *const i8,
        0 as i32,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemFree(mut ptr: * mut core::ffi::c_void) {
    let mut p: * mut crate::src::xmlmemory::memnod = 0 as *mut MEMHDR;
    let mut target: * mut i8 = 0 as *mut i8;
    if ptr.is_null() {
        return;
    }
    if ptr == -(1 as i32) as *mut libc::c_void {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"trying to free pointer from freed area\n\0" as *const u8
                as *const i8,
        );
    } else {
        if xmlMemTraceBlockAt == ptr {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"%p : Freed()\n\0" as *const u8 as *const i8,
                xmlMemTraceBlockAt,
            );
            xmlMallocBreakpoint();
        }
        target = ptr as *mut i8;
        p = (ptr as *mut i8)
            .offset(
                -((::std::mem::size_of::<MEMHDR>() as u64)
                    .wrapping_add(
                        (::std::mem::size_of::<f64>() as u64)
                            .wrapping_sub(1 as i32 as u64),
                    )
                    .wrapping_div(
                        ::std::mem::size_of::<f64>() as u64,
                    )
                    .wrapping_mul(
                        ::std::mem::size_of::<f64>() as u64,
                    ) as isize),
            ) as *mut libc::c_void as *mut MEMHDR;
        if (*p).mh_tag != 0x5aa5 as u32 {
            debugmem_tag_error(p as *mut libc::c_void);
        } else {
            if xmlMemStopAtBlock as u64 == (*p).mh_number {
                xmlMallocBreakpoint();
            }
            (*p).mh_tag = !(0x5aa5 as u32);
            memset(target as *mut libc::c_void, -(1 as i32), (*p).mh_size);
            xmlMutexLock(xmlMemMutex);
            debugMemSize = debugMemSize.wrapping_sub((*p).mh_size);
            debugMemBlocks = debugMemBlocks.wrapping_sub(1);
            xmlMutexUnlock(xmlMemMutex);
            free(p as *mut libc::c_void);
            return;
        }
    }
    (*__xmlGenericError())
        .expect(
            "non-null function pointer",
        )(
        *__xmlGenericErrorContext(),
        b"xmlMemFree(%p) error\n\0" as *const u8 as *const i8,
        ptr,
    );
    xmlMallocBreakpoint();
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemStrdupLoc(
    mut str: * const i8,
    mut file: * const i8,
    mut line: i32,
) -> * mut i8 {
    let mut s: * mut i8 = 0 as *mut i8;
    let mut size: u64 = (strlen(str)).wrapping_add(1 as i32 as u64);
    let mut p: * mut crate::src::xmlmemory::memnod = (0 as * mut crate::src::xmlmemory::memnod);
    if xmlMemInitialized == 0 {
        xmlInitMemory();
    }
    if size
        > (-(1 as i32) as size_t)
            .wrapping_sub(
                (::std::mem::size_of::<MEMHDR>() as u64)
                    .wrapping_add(
                        (::std::mem::size_of::<f64>() as u64)
                            .wrapping_sub(1 as i32 as u64),
                    )
                    .wrapping_div(
                        ::std::mem::size_of::<f64>() as u64,
                    )
                    .wrapping_mul(
                        ::std::mem::size_of::<f64>() as u64,
                    ),
            )
    {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlMemStrdupLoc : Unsigned overflow\n\0" as *const u8
                as *const i8,
        );
        xmlMemoryDump();
        return 0 as *mut i8;
    }
    p = malloc(
        (::std::mem::size_of::<MEMHDR>() as u64)
            .wrapping_add(
                (::std::mem::size_of::<f64>() as u64)
                    .wrapping_sub(1 as i32 as u64),
            )
            .wrapping_div(::std::mem::size_of::<f64>() as u64)
            .wrapping_mul(::std::mem::size_of::<f64>() as u64)
            .wrapping_add(size),
    ) as *mut MEMHDR;
    if p.is_null() {
        return 0 as *mut i8
    } else {
        (*p).mh_tag = 0x5aa5 as u32;
        (*p).mh_size = size;
        (*p).mh_type = 3 as i32 as u32;
        let fresh3 = &mut ((*p).mh_file);
        *fresh3 = file;
        (*p).mh_line = line as u32;
        xmlMutexLock(xmlMemMutex);
        block = block.wrapping_add(1);
        (*p).mh_number = block as u64;
        debugMemSize = debugMemSize.wrapping_add(size);
        debugMemBlocks = debugMemBlocks.wrapping_add(1);
        if debugMemSize > debugMaxMemSize {
            debugMaxMemSize = debugMemSize;
        }
        xmlMutexUnlock(xmlMemMutex);
        s = (p as *mut i8)
            .offset(
                (::std::mem::size_of::<MEMHDR>() as u64)
                    .wrapping_add(
                        (::std::mem::size_of::<f64>() as u64)
                            .wrapping_sub(1 as i32 as u64),
                    )
                    .wrapping_div(
                        ::std::mem::size_of::<f64>() as u64,
                    )
                    .wrapping_mul(
                        ::std::mem::size_of::<f64>() as u64,
                    ) as isize,
            ) as *mut libc::c_void as *mut i8;
        if xmlMemStopAtBlock as u64 == (*p).mh_number {
            xmlMallocBreakpoint();
        }
        strcpy(s, str);
        if xmlMemTraceBlockAt == s as *mut libc::c_void {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"%p : Strdup() Ok\n\0" as *const u8 as *const i8,
                xmlMemTraceBlockAt,
            );
            xmlMallocBreakpoint();
        }
        return s;
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemoryStrdup(
    mut str: * const i8,
) -> * mut i8 {
    return xmlMemStrdupLoc(
        str,
        b"none\0" as *const u8 as *const i8,
        0 as i32,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemUsed() -> i32 {
    let mut res: i32 = 0;
    xmlMutexLock(xmlMemMutex);
    res = debugMemSize as i32;
    xmlMutexUnlock(xmlMemMutex);
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemBlocks() -> i32 {
    let mut res: i32 = 0;
    xmlMutexLock(xmlMemMutex);
    res = debugMemBlocks as i32;
    xmlMutexUnlock(xmlMemMutex);
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemDisplayLast(
    mut fp: * mut crate::src::tree::_IO_FILE,
    mut nbBytes: i64,
) {
    let mut old_fp: * mut crate::src::tree::_IO_FILE = fp;
    if nbBytes <= 0 as i32 as i64 {
        return;
    }
    if fp.is_null() {
        fp = fopen(
            b".memorylist\0" as *const u8 as *const i8,
            b"w\0" as *const u8 as *const i8,
        );
        if fp.is_null() {
            return;
        }
    }
    fprintf(
        fp,
        b"Memory list not compiled (MEM_LIST not defined !)\n\0" as *const u8
            as *const i8,
    );
    if old_fp.is_null() {
        fclose(fp);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemDisplay(mut fp: * mut crate::src::tree::_IO_FILE) {
    let mut old_fp: * mut crate::src::tree::_IO_FILE = fp;
    if fp.is_null() {
        fp = fopen(
            b".memorylist\0" as *const u8 as *const i8,
            b"w\0" as *const u8 as *const i8,
        );
        if fp.is_null() {
            return;
        }
    }
    fprintf(
        fp,
        b"Memory list not compiled (MEM_LIST not defined !)\n\0" as *const u8
            as *const i8,
    );
    if old_fp.is_null() {
        fclose(fp);
    }
}
unsafe extern "C" fn debugmem_tag_error(mut p: * mut core::ffi::c_void) {
    (*__xmlGenericError())
        .expect(
            "non-null function pointer",
        )(
        *__xmlGenericErrorContext(),
        b"Memory tag error occurs :%p \n\t bye\n\0" as *const u8 as *const i8,
        p,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemShow(mut fp: * mut crate::src::tree::_IO_FILE, mut nr: i32) {
    if !fp.is_null() {
        fprintf(
            fp,
            b"      MEMORY ALLOCATED : %lu, MAX was %lu\n\0" as *const u8
                as *const i8,
            debugMemSize,
            debugMaxMemSize,
        );
    }
}
#[no_mangle]
pub extern "C" fn xmlMemoryDump() {}
#[no_mangle]
pub unsafe extern "C" fn xmlInitMemory() -> i32 {
    let mut breakpoint: * mut i8 = 0 as *mut i8;
    if xmlMemInitialized != 0 {
        return -(1 as i32);
    }
    xmlMemInitialized = 1 as i32;
    xmlMemMutex = xmlNewMutex();
    breakpoint = getenv(b"XML_MEM_BREAKPOINT\0" as *const u8 as *const i8);
    if !breakpoint.is_null() {
        sscanf(
            breakpoint,
            b"%ud\0" as *const u8 as *const i8,
            &mut xmlMemStopAtBlock as *mut u32,
        );
    }
    breakpoint = getenv(b"XML_MEM_TRACE\0" as *const u8 as *const i8);
    if !breakpoint.is_null() {
        sscanf(
            breakpoint,
            b"%p\0" as *const u8 as *const i8,
            &mut xmlMemTraceBlockAt as *mut *mut libc::c_void,
        );
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCleanupMemory() {
    if xmlMemInitialized == 0 as i32 {
        return;
    }
    xmlFreeMutex(xmlMemMutex);
    xmlMemMutex = 0 as xmlMutexPtr;
    xmlMemInitialized = 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemSetup(
    mut freeFunc: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>,
    mut mallocFunc: Option<unsafe extern "C"  fn(_: u64,) -> * mut core::ffi::c_void>,
    mut reallocFunc: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: u64,) -> * mut core::ffi::c_void>,
    mut strdupFunc: Option<unsafe extern "C"  fn(_: * const i8,) -> * mut i8>,
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
    xmlFree = freeFunc;
    xmlMalloc = mallocFunc;
    xmlMallocAtomic = mallocFunc;
    xmlRealloc = reallocFunc;
    xmlMemStrdup = strdupFunc;
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemGet<'a1, 'a2, 'a3, 'a4>(
    mut freeFunc: Option<&'a1 mut Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>>,
    mut mallocFunc: Option<&'a2 mut Option<unsafe extern "C"  fn(_: u64,) -> * mut core::ffi::c_void>>,
    mut reallocFunc: Option<&'a3 mut Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: u64,) -> * mut core::ffi::c_void>>,
    mut strdupFunc: Option<&'a4 mut Option<unsafe extern "C"  fn(_: * const i8,) -> * mut i8>>,
) -> i32 {
    if !borrow(& freeFunc).is_none() {
        *(borrow_mut(&mut freeFunc)).unwrap() = xmlFree;
    }
    if !borrow(& mallocFunc).is_none() {
        *(borrow_mut(&mut mallocFunc)).unwrap() = xmlMalloc;
    }
    if !borrow(& reallocFunc).is_none() {
        *(borrow_mut(&mut reallocFunc)).unwrap() = xmlRealloc;
    }
    if !borrow(& strdupFunc).is_none() {
        *(borrow_mut(&mut strdupFunc)).unwrap() = xmlMemStrdup;
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGcMemSetup(
    mut freeFunc: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>,
    mut mallocFunc: Option<unsafe extern "C"  fn(_: u64,) -> * mut core::ffi::c_void>,
    mut mallocAtomicFunc: Option<unsafe extern "C"  fn(_: u64,) -> * mut core::ffi::c_void>,
    mut reallocFunc: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: u64,) -> * mut core::ffi::c_void>,
    mut strdupFunc: Option<unsafe extern "C"  fn(_: * const i8,) -> * mut i8>,
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
    xmlFree = freeFunc;
    xmlMalloc = mallocFunc;
    xmlMallocAtomic = mallocAtomicFunc;
    xmlRealloc = reallocFunc;
    xmlMemStrdup = strdupFunc;
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGcMemGet<'a1, 'a2, 'a3, 'a4, 'a5>(
    mut freeFunc: Option<&'a1 mut Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>>,
    mut mallocFunc: Option<&'a2 mut Option<unsafe extern "C"  fn(_: u64,) -> * mut core::ffi::c_void>>,
    mut mallocAtomicFunc: Option<&'a3 mut Option<unsafe extern "C"  fn(_: u64,) -> * mut core::ffi::c_void>>,
    mut reallocFunc: Option<&'a4 mut Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: u64,) -> * mut core::ffi::c_void>>,
    mut strdupFunc: Option<&'a5 mut Option<unsafe extern "C"  fn(_: * const i8,) -> * mut i8>>,
) -> i32 {
    if !borrow(& freeFunc).is_none() {
        *(borrow_mut(&mut freeFunc)).unwrap() = xmlFree;
    }
    if !borrow(& mallocFunc).is_none() {
        *(borrow_mut(&mut mallocFunc)).unwrap() = xmlMalloc;
    }
    if !borrow(& mallocAtomicFunc).is_none() {
        *(borrow_mut(&mut mallocAtomicFunc)).unwrap() = xmlMallocAtomic;
    }
    if !borrow(& reallocFunc).is_none() {
        *(borrow_mut(&mut reallocFunc)).unwrap() = xmlRealloc;
    }
    if !borrow(& strdupFunc).is_none() {
        *(borrow_mut(&mut strdupFunc)).unwrap() = xmlMemStrdup;
    }
    return 0 as i32;
}
use crate::laertes_rt::*;
