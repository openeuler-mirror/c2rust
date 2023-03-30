use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcpy(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    static mut xmlMemStrdup: xmlStrdupFunc;
    static mut xmlRealloc: xmlReallocFunc;
    static mut xmlMallocAtomic: xmlMallocFunc;
    static mut xmlMalloc: xmlMallocFunc;
    static mut xmlFree: xmlFreeFunc;
    
    
    
    
    
    
}
pub use crate::src::globals::__xmlGenericError;
pub use crate::src::globals::__xmlGenericErrorContext;
pub use crate::src::threads::xmlFreeMutex;
pub use crate::src::threads::xmlMutexLock;
pub use crate::src::threads::xmlMutexUnlock;
pub use crate::src::threads::xmlNewMutex;
pub use crate::src::threads::_xmlMutex;
pub use crate::src::HTMLparser::size_t;
pub use crate::src::HTMLtree::__off_t;
pub use crate::src::HTMLtree::__off64_t;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLtree::_IO_FILE;
pub use crate::src::HTMLtree::_IO_lock_t;
pub use crate::src::HTMLtree::FILE;
pub use crate::src::HTMLparser::xmlGenericErrorFunc;
pub use crate::src::HTMLparser::xmlFreeFunc;
pub use crate::src::HTMLparser::xmlMallocFunc;
pub use crate::src::HTMLparser::xmlReallocFunc;
pub use crate::src::encoding::xmlStrdupFunc;
pub use crate::src::dict::xmlMutexPtr;
pub use crate::src::dict::xmlMutex;
pub type MEMHDR = memnod;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct memnod {
    pub mh_tag: libc::c_uint,
    pub mh_type: libc::c_uint,
    pub mh_number: libc::c_ulong,
    pub mh_size: size_t,
    pub mh_file: *const libc::c_char,
    pub mh_line: libc::c_uint,
}
static mut xmlMemInitialized: libc::c_int = 0 as libc::c_int;
static mut debugMemSize: libc::c_ulong = 0 as libc::c_int as libc::c_ulong;
static mut debugMemBlocks: libc::c_ulong = 0 as libc::c_int as libc::c_ulong;
static mut debugMaxMemSize: libc::c_ulong = 0 as libc::c_int as libc::c_ulong;
static mut xmlMemMutex: xmlMutexPtr = 0 as *const xmlMutex as xmlMutexPtr;
static mut block: libc::c_uint = 0 as libc::c_int as libc::c_uint;
static mut xmlMemStopAtBlock: libc::c_uint = 0 as libc::c_int as libc::c_uint;
static mut xmlMemTraceBlockAt: *mut libc::c_void = 0 as *const libc::c_void
    as *mut libc::c_void;
#[no_mangle]
pub unsafe extern "C" fn xmlMallocBreakpoint() {
    (*__xmlGenericError())
        .expect(
            "non-null function pointer",
        )(
        *__xmlGenericErrorContext(),
        b"xmlMallocBreakpoint reached on block %d\n\0" as *const u8
            as *const libc::c_char,
        xmlMemStopAtBlock,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlMallocLoc(
    mut size: size_t,
    mut file: *const libc::c_char,
    mut line: libc::c_int,
) -> *mut libc::c_void {
    let mut p: *mut MEMHDR = 0 as *mut MEMHDR;
    let mut ret: *mut libc::c_void = 0 as *mut libc::c_void;
    if xmlMemInitialized == 0 {
        xmlInitMemory();
    }
    if size
        > (-(1 as libc::c_int) as size_t)
            .wrapping_sub(
                (::std::mem::size_of::<MEMHDR>() as libc::c_ulong)
                    .wrapping_add(
                        (::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                    )
                    .wrapping_div(
                        ::std::mem::size_of::<libc::c_double>() as libc::c_ulong,
                    )
                    .wrapping_mul(
                        ::std::mem::size_of::<libc::c_double>() as libc::c_ulong,
                    ),
            )
    {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlMallocLoc : Unsigned overflow\n\0" as *const u8 as *const libc::c_char,
        );
        xmlMemoryDump();
        return 0 as *mut libc::c_void;
    }
    p = malloc(
        (::std::mem::size_of::<MEMHDR>() as libc::c_ulong)
            .wrapping_add(
                (::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            )
            .wrapping_div(::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
            .wrapping_add(size),
    ) as *mut MEMHDR;
    if p.is_null() {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlMallocLoc : Out of free space\n\0" as *const u8 as *const libc::c_char,
        );
        xmlMemoryDump();
        return 0 as *mut libc::c_void;
    }
    (*p).mh_tag = 0x5aa5 as libc::c_uint;
    (*p).mh_size = size;
    (*p).mh_type = 1 as libc::c_int as libc::c_uint;
    let ref mut fresh0 = (*p).mh_file;
    *fresh0 = file;
    (*p).mh_line = line as libc::c_uint;
    xmlMutexLock(xmlMemMutex);
    block = block.wrapping_add(1);
    (*p).mh_number = block as libc::c_ulong;
    debugMemSize = debugMemSize.wrapping_add(size);
    debugMemBlocks = debugMemBlocks.wrapping_add(1);
    if debugMemSize > debugMaxMemSize {
        debugMaxMemSize = debugMemSize;
    }
    xmlMutexUnlock(xmlMemMutex);
    if xmlMemStopAtBlock as libc::c_ulong == (*p).mh_number {
        xmlMallocBreakpoint();
    }
    ret = (p as *mut libc::c_char)
        .offset(
            (::std::mem::size_of::<MEMHDR>() as libc::c_ulong)
                .wrapping_add(
                    (::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                )
                .wrapping_div(::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                as isize,
        ) as *mut libc::c_void;
    if xmlMemTraceBlockAt == ret {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"%p : Malloc(%lu) Ok\n\0" as *const u8 as *const libc::c_char,
            xmlMemTraceBlockAt,
            size,
        );
        xmlMallocBreakpoint();
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlMallocAtomicLoc(
    mut size: size_t,
    mut file: *const libc::c_char,
    mut line: libc::c_int,
) -> *mut libc::c_void {
    let mut p: *mut MEMHDR = 0 as *mut MEMHDR;
    let mut ret: *mut libc::c_void = 0 as *mut libc::c_void;
    if xmlMemInitialized == 0 {
        xmlInitMemory();
    }
    if size
        > (-(1 as libc::c_int) as size_t)
            .wrapping_sub(
                (::std::mem::size_of::<MEMHDR>() as libc::c_ulong)
                    .wrapping_add(
                        (::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                    )
                    .wrapping_div(
                        ::std::mem::size_of::<libc::c_double>() as libc::c_ulong,
                    )
                    .wrapping_mul(
                        ::std::mem::size_of::<libc::c_double>() as libc::c_ulong,
                    ),
            )
    {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlMallocAtomicLoc : Unsigned overflow\n\0" as *const u8
                as *const libc::c_char,
        );
        xmlMemoryDump();
        return 0 as *mut libc::c_void;
    }
    p = malloc(
        (::std::mem::size_of::<MEMHDR>() as libc::c_ulong)
            .wrapping_add(
                (::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            )
            .wrapping_div(::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
            .wrapping_add(size),
    ) as *mut MEMHDR;
    if p.is_null() {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlMallocAtomicLoc : Out of free space\n\0" as *const u8
                as *const libc::c_char,
        );
        xmlMemoryDump();
        return 0 as *mut libc::c_void;
    }
    (*p).mh_tag = 0x5aa5 as libc::c_uint;
    (*p).mh_size = size;
    (*p).mh_type = 4 as libc::c_int as libc::c_uint;
    let ref mut fresh1 = (*p).mh_file;
    *fresh1 = file;
    (*p).mh_line = line as libc::c_uint;
    xmlMutexLock(xmlMemMutex);
    block = block.wrapping_add(1);
    (*p).mh_number = block as libc::c_ulong;
    debugMemSize = debugMemSize.wrapping_add(size);
    debugMemBlocks = debugMemBlocks.wrapping_add(1);
    if debugMemSize > debugMaxMemSize {
        debugMaxMemSize = debugMemSize;
    }
    xmlMutexUnlock(xmlMemMutex);
    if xmlMemStopAtBlock as libc::c_ulong == (*p).mh_number {
        xmlMallocBreakpoint();
    }
    ret = (p as *mut libc::c_char)
        .offset(
            (::std::mem::size_of::<MEMHDR>() as libc::c_ulong)
                .wrapping_add(
                    (::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                )
                .wrapping_div(::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                as isize,
        ) as *mut libc::c_void;
    if xmlMemTraceBlockAt == ret {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"%p : Malloc(%lu) Ok\n\0" as *const u8 as *const libc::c_char,
            xmlMemTraceBlockAt,
            size,
        );
        xmlMallocBreakpoint();
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemMalloc(mut size: size_t) -> *mut libc::c_void {
    return xmlMallocLoc(
        size,
        b"none\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlReallocLoc(
    mut ptr: *mut libc::c_void,
    mut size: size_t,
    mut file: *const libc::c_char,
    mut line: libc::c_int,
) -> *mut libc::c_void {
    let mut p: *mut MEMHDR = 0 as *mut MEMHDR;
    let mut tmp: *mut MEMHDR = 0 as *mut MEMHDR;
    let mut number: libc::c_ulong = 0;
    if ptr.is_null() {
        return xmlMallocLoc(size, file, line);
    }
    if xmlMemInitialized == 0 {
        xmlInitMemory();
    }
    p = (ptr as *mut libc::c_char)
        .offset(
            -((::std::mem::size_of::<MEMHDR>() as libc::c_ulong)
                .wrapping_add(
                    (::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                )
                .wrapping_div(::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                as isize),
        ) as *mut libc::c_void as *mut MEMHDR;
    number = (*p).mh_number;
    if xmlMemStopAtBlock as libc::c_ulong == number {
        xmlMallocBreakpoint();
    }
    if (*p).mh_tag != 0x5aa5 as libc::c_uint {
        debugmem_tag_error(p as *mut libc::c_void);
    } else {
        (*p).mh_tag = !(0x5aa5 as libc::c_uint);
        xmlMutexLock(xmlMemMutex);
        debugMemSize = debugMemSize.wrapping_sub((*p).mh_size);
        debugMemBlocks = debugMemBlocks.wrapping_sub(1);
        xmlMutexUnlock(xmlMemMutex);
        if size
            > (-(1 as libc::c_int) as size_t)
                .wrapping_sub(
                    (::std::mem::size_of::<MEMHDR>() as libc::c_ulong)
                        .wrapping_add(
                            (::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                        )
                        .wrapping_div(
                            ::std::mem::size_of::<libc::c_double>() as libc::c_ulong,
                        )
                        .wrapping_mul(
                            ::std::mem::size_of::<libc::c_double>() as libc::c_ulong,
                        ),
                )
        {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"xmlReallocLoc : Unsigned overflow\n\0" as *const u8
                    as *const libc::c_char,
            );
            xmlMemoryDump();
            return 0 as *mut libc::c_void;
        }
        tmp = realloc(
            p as *mut libc::c_void,
            (::std::mem::size_of::<MEMHDR>() as libc::c_ulong)
                .wrapping_add(
                    (::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                )
                .wrapping_div(::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
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
                        as *const libc::c_char,
                    xmlMemTraceBlockAt,
                    (*p).mh_size,
                    size,
                );
                xmlMallocBreakpoint();
            }
            (*p).mh_tag = 0x5aa5 as libc::c_uint;
            (*p).mh_number = number;
            (*p).mh_type = 2 as libc::c_int as libc::c_uint;
            (*p).mh_size = size;
            let ref mut fresh2 = (*p).mh_file;
            *fresh2 = file;
            (*p).mh_line = line as libc::c_uint;
            xmlMutexLock(xmlMemMutex);
            debugMemSize = debugMemSize.wrapping_add(size);
            debugMemBlocks = debugMemBlocks.wrapping_add(1);
            if debugMemSize > debugMaxMemSize {
                debugMaxMemSize = debugMemSize;
            }
            xmlMutexUnlock(xmlMemMutex);
            return (p as *mut libc::c_char)
                .offset(
                    (::std::mem::size_of::<MEMHDR>() as libc::c_ulong)
                        .wrapping_add(
                            (::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                        )
                        .wrapping_div(
                            ::std::mem::size_of::<libc::c_double>() as libc::c_ulong,
                        )
                        .wrapping_mul(
                            ::std::mem::size_of::<libc::c_double>() as libc::c_ulong,
                        ) as isize,
                ) as *mut libc::c_void;
        }
    }
    return 0 as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemRealloc(
    mut ptr: *mut libc::c_void,
    mut size: size_t,
) -> *mut libc::c_void {
    return xmlReallocLoc(
        ptr,
        size,
        b"none\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemFree(mut ptr: *mut libc::c_void) {
    let mut p: *mut MEMHDR = 0 as *mut MEMHDR;
    let mut target: *mut libc::c_char = 0 as *mut libc::c_char;
    if ptr.is_null() {
        return;
    }
    if ptr == -(1 as libc::c_int) as *mut libc::c_void {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"trying to free pointer from freed area\n\0" as *const u8
                as *const libc::c_char,
        );
    } else {
        if xmlMemTraceBlockAt == ptr {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"%p : Freed()\n\0" as *const u8 as *const libc::c_char,
                xmlMemTraceBlockAt,
            );
            xmlMallocBreakpoint();
        }
        target = ptr as *mut libc::c_char;
        p = (ptr as *mut libc::c_char)
            .offset(
                -((::std::mem::size_of::<MEMHDR>() as libc::c_ulong)
                    .wrapping_add(
                        (::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                    )
                    .wrapping_div(
                        ::std::mem::size_of::<libc::c_double>() as libc::c_ulong,
                    )
                    .wrapping_mul(
                        ::std::mem::size_of::<libc::c_double>() as libc::c_ulong,
                    ) as isize),
            ) as *mut libc::c_void as *mut MEMHDR;
        if (*p).mh_tag != 0x5aa5 as libc::c_uint {
            debugmem_tag_error(p as *mut libc::c_void);
        } else {
            if xmlMemStopAtBlock as libc::c_ulong == (*p).mh_number {
                xmlMallocBreakpoint();
            }
            (*p).mh_tag = !(0x5aa5 as libc::c_uint);
            memset(target as *mut libc::c_void, -(1 as libc::c_int), (*p).mh_size);
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
        b"xmlMemFree(%p) error\n\0" as *const u8 as *const libc::c_char,
        ptr,
    );
    xmlMallocBreakpoint();
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemStrdupLoc(
    mut str: *const libc::c_char,
    mut file: *const libc::c_char,
    mut line: libc::c_int,
) -> *mut libc::c_char {
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut size: size_t = (strlen(str)).wrapping_add(1 as libc::c_int as libc::c_ulong);
    let mut p: *mut MEMHDR = 0 as *mut MEMHDR;
    if xmlMemInitialized == 0 {
        xmlInitMemory();
    }
    if size
        > (-(1 as libc::c_int) as size_t)
            .wrapping_sub(
                (::std::mem::size_of::<MEMHDR>() as libc::c_ulong)
                    .wrapping_add(
                        (::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                    )
                    .wrapping_div(
                        ::std::mem::size_of::<libc::c_double>() as libc::c_ulong,
                    )
                    .wrapping_mul(
                        ::std::mem::size_of::<libc::c_double>() as libc::c_ulong,
                    ),
            )
    {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlMemStrdupLoc : Unsigned overflow\n\0" as *const u8
                as *const libc::c_char,
        );
        xmlMemoryDump();
        return 0 as *mut libc::c_char;
    }
    p = malloc(
        (::std::mem::size_of::<MEMHDR>() as libc::c_ulong)
            .wrapping_add(
                (::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            )
            .wrapping_div(::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
            .wrapping_add(size),
    ) as *mut MEMHDR;
    if p.is_null() {
        return 0 as *mut libc::c_char
    } else {
        (*p).mh_tag = 0x5aa5 as libc::c_uint;
        (*p).mh_size = size;
        (*p).mh_type = 3 as libc::c_int as libc::c_uint;
        let ref mut fresh3 = (*p).mh_file;
        *fresh3 = file;
        (*p).mh_line = line as libc::c_uint;
        xmlMutexLock(xmlMemMutex);
        block = block.wrapping_add(1);
        (*p).mh_number = block as libc::c_ulong;
        debugMemSize = debugMemSize.wrapping_add(size);
        debugMemBlocks = debugMemBlocks.wrapping_add(1);
        if debugMemSize > debugMaxMemSize {
            debugMaxMemSize = debugMemSize;
        }
        xmlMutexUnlock(xmlMemMutex);
        s = (p as *mut libc::c_char)
            .offset(
                (::std::mem::size_of::<MEMHDR>() as libc::c_ulong)
                    .wrapping_add(
                        (::std::mem::size_of::<libc::c_double>() as libc::c_ulong)
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                    )
                    .wrapping_div(
                        ::std::mem::size_of::<libc::c_double>() as libc::c_ulong,
                    )
                    .wrapping_mul(
                        ::std::mem::size_of::<libc::c_double>() as libc::c_ulong,
                    ) as isize,
            ) as *mut libc::c_void as *mut libc::c_char;
        if xmlMemStopAtBlock as libc::c_ulong == (*p).mh_number {
            xmlMallocBreakpoint();
        }
        strcpy(s, str);
        if xmlMemTraceBlockAt == s as *mut libc::c_void {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"%p : Strdup() Ok\n\0" as *const u8 as *const libc::c_char,
                xmlMemTraceBlockAt,
            );
            xmlMallocBreakpoint();
        }
        return s;
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemoryStrdup(
    mut str: *const libc::c_char,
) -> *mut libc::c_char {
    return xmlMemStrdupLoc(
        str,
        b"none\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemUsed() -> libc::c_int {
    let mut res: libc::c_int = 0;
    xmlMutexLock(xmlMemMutex);
    res = debugMemSize as libc::c_int;
    xmlMutexUnlock(xmlMemMutex);
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemBlocks() -> libc::c_int {
    let mut res: libc::c_int = 0;
    xmlMutexLock(xmlMemMutex);
    res = debugMemBlocks as libc::c_int;
    xmlMutexUnlock(xmlMemMutex);
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemDisplayLast(
    mut fp: *mut FILE,
    mut nbBytes: libc::c_long,
) {
    let mut old_fp: *mut FILE = fp;
    if nbBytes <= 0 as libc::c_int as libc::c_long {
        return;
    }
    if fp.is_null() {
        fp = fopen(
            b".memorylist\0" as *const u8 as *const libc::c_char,
            b"w\0" as *const u8 as *const libc::c_char,
        );
        if fp.is_null() {
            return;
        }
    }
    fprintf(
        fp,
        b"Memory list not compiled (MEM_LIST not defined !)\n\0" as *const u8
            as *const libc::c_char,
    );
    if old_fp.is_null() {
        fclose(fp);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemDisplay(mut fp: *mut FILE) {
    let mut old_fp: *mut FILE = fp;
    if fp.is_null() {
        fp = fopen(
            b".memorylist\0" as *const u8 as *const libc::c_char,
            b"w\0" as *const u8 as *const libc::c_char,
        );
        if fp.is_null() {
            return;
        }
    }
    fprintf(
        fp,
        b"Memory list not compiled (MEM_LIST not defined !)\n\0" as *const u8
            as *const libc::c_char,
    );
    if old_fp.is_null() {
        fclose(fp);
    }
}
unsafe extern "C" fn debugmem_tag_error(mut p: *mut libc::c_void) {
    (*__xmlGenericError())
        .expect(
            "non-null function pointer",
        )(
        *__xmlGenericErrorContext(),
        b"Memory tag error occurs :%p \n\t bye\n\0" as *const u8 as *const libc::c_char,
        p,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemShow(mut fp: *mut FILE, mut nr: libc::c_int) {
    if !fp.is_null() {
        fprintf(
            fp,
            b"      MEMORY ALLOCATED : %lu, MAX was %lu\n\0" as *const u8
                as *const libc::c_char,
            debugMemSize,
            debugMaxMemSize,
        );
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemoryDump() {}
#[no_mangle]
pub unsafe extern "C" fn xmlInitMemory() -> libc::c_int {
    let mut breakpoint: *mut libc::c_char = 0 as *mut libc::c_char;
    if xmlMemInitialized != 0 {
        return -(1 as libc::c_int);
    }
    xmlMemInitialized = 1 as libc::c_int;
    xmlMemMutex = xmlNewMutex();
    breakpoint = getenv(b"XML_MEM_BREAKPOINT\0" as *const u8 as *const libc::c_char);
    if !breakpoint.is_null() {
        sscanf(
            breakpoint,
            b"%ud\0" as *const u8 as *const libc::c_char,
            &mut xmlMemStopAtBlock as *mut libc::c_uint,
        );
    }
    breakpoint = getenv(b"XML_MEM_TRACE\0" as *const u8 as *const libc::c_char);
    if !breakpoint.is_null() {
        sscanf(
            breakpoint,
            b"%p\0" as *const u8 as *const libc::c_char,
            &mut xmlMemTraceBlockAt as *mut *mut libc::c_void,
        );
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCleanupMemory() {
    if xmlMemInitialized == 0 as libc::c_int {
        return;
    }
    xmlFreeMutex(xmlMemMutex);
    xmlMemMutex = 0 as xmlMutexPtr;
    xmlMemInitialized = 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemSetup(
    mut freeFunc: xmlFreeFunc,
    mut mallocFunc: xmlMallocFunc,
    mut reallocFunc: xmlReallocFunc,
    mut strdupFunc: xmlStrdupFunc,
) -> libc::c_int {
    if freeFunc.is_none() {
        return -(1 as libc::c_int);
    }
    if mallocFunc.is_none() {
        return -(1 as libc::c_int);
    }
    if reallocFunc.is_none() {
        return -(1 as libc::c_int);
    }
    if strdupFunc.is_none() {
        return -(1 as libc::c_int);
    }
    xmlFree = freeFunc;
    xmlMalloc = mallocFunc;
    xmlMallocAtomic = mallocFunc;
    xmlRealloc = reallocFunc;
    xmlMemStrdup = strdupFunc;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlMemGet(
    mut freeFunc: *mut xmlFreeFunc,
    mut mallocFunc: *mut xmlMallocFunc,
    mut reallocFunc: *mut xmlReallocFunc,
    mut strdupFunc: *mut xmlStrdupFunc,
) -> libc::c_int {
    if !freeFunc.is_null() {
        *freeFunc = xmlFree;
    }
    if !mallocFunc.is_null() {
        *mallocFunc = xmlMalloc;
    }
    if !reallocFunc.is_null() {
        *reallocFunc = xmlRealloc;
    }
    if !strdupFunc.is_null() {
        *strdupFunc = xmlMemStrdup;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGcMemSetup(
    mut freeFunc: xmlFreeFunc,
    mut mallocFunc: xmlMallocFunc,
    mut mallocAtomicFunc: xmlMallocFunc,
    mut reallocFunc: xmlReallocFunc,
    mut strdupFunc: xmlStrdupFunc,
) -> libc::c_int {
    if freeFunc.is_none() {
        return -(1 as libc::c_int);
    }
    if mallocFunc.is_none() {
        return -(1 as libc::c_int);
    }
    if mallocAtomicFunc.is_none() {
        return -(1 as libc::c_int);
    }
    if reallocFunc.is_none() {
        return -(1 as libc::c_int);
    }
    if strdupFunc.is_none() {
        return -(1 as libc::c_int);
    }
    xmlFree = freeFunc;
    xmlMalloc = mallocFunc;
    xmlMallocAtomic = mallocAtomicFunc;
    xmlRealloc = reallocFunc;
    xmlMemStrdup = strdupFunc;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGcMemGet(
    mut freeFunc: *mut xmlFreeFunc,
    mut mallocFunc: *mut xmlMallocFunc,
    mut mallocAtomicFunc: *mut xmlMallocFunc,
    mut reallocFunc: *mut xmlReallocFunc,
    mut strdupFunc: *mut xmlStrdupFunc,
) -> libc::c_int {
    if !freeFunc.is_null() {
        *freeFunc = xmlFree;
    }
    if !mallocFunc.is_null() {
        *mallocFunc = xmlMalloc;
    }
    if !mallocAtomicFunc.is_null() {
        *mallocAtomicFunc = xmlMallocAtomic;
    }
    if !reallocFunc.is_null() {
        *reallocFunc = xmlRealloc;
    }
    if !strdupFunc.is_null() {
        *strdupFunc = xmlMemStrdup;
    }
    return 0 as libc::c_int;
}
