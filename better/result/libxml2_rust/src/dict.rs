use :: libc;
extern "C" {
    fn xmlStrQEqual(pref: *const u8, name: *const u8, str: *const u8) -> i32;
    fn rand_r(__seed: *mut u32) -> i32;
    fn time(__timer: *mut i64) -> i64;
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn memset(_: *mut core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn memcmp(_: *const core::ffi::c_void, _: *const core::ffi::c_void, _: u64) -> i32;
    fn strlen(_: *const i8) -> u64;
    fn xmlMutexUnlock(tok: *mut crate::src::globals::_xmlMutex);
    fn xmlNewMutex() -> *mut crate::src::globals::_xmlMutex;
    fn xmlMutexLock(tok: *mut crate::src::globals::_xmlMutex);
    fn xmlFreeMutex(tok: *mut crate::src::globals::_xmlMutex);
}
pub use crate::src::globals::_xmlMutex;
pub use crate::src::globals::xmlFree;
pub use crate::src::globals::xmlMalloc;
pub type xmlChar = u8;
pub type size_t = u64;
pub type __uint32_t = u32;
pub type __time_t = i64;
pub type xmlMutexPtr = *mut crate::src::globals::_xmlMutex;
pub type xmlMutex = crate::src::globals::_xmlMutex;
pub type time_t = i64;
pub type uint32_t = u32;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDict {
    pub ref_counter: i32,
    pub dict: *mut crate::src::dict::_xmlDictEntry,
    pub size: u64,
    pub nbElems: u32,
    pub strings: *mut crate::src::dict::_xmlDictStrings,
    pub subdict: *mut crate::src::dict::_xmlDict,
    pub seed: i32,
    pub limit: u64,
}
impl _xmlDict {
    pub const fn new() -> Self {
        _xmlDict {
            ref_counter: 0,
            dict: (0 as *mut crate::src::dict::_xmlDictEntry),
            size: 0,
            nbElems: 0,
            strings: (0 as *mut crate::src::dict::_xmlDictStrings),
            subdict: (0 as *mut crate::src::dict::_xmlDict),
            seed: 0,
            limit: 0,
        }
    }
}
impl std::default::Default for _xmlDict {
    fn default() -> Self {
        _xmlDict::new()
    }
}
pub type xmlDictStringsPtr = *mut crate::src::dict::_xmlDictStrings;
pub type xmlDictStrings = crate::src::dict::_xmlDictStrings;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDictStrings {
    pub next: *mut crate::src::dict::_xmlDictStrings,
    pub free: *mut u8,
    pub end: *mut u8,
    pub size: u64,
    pub nbStrings: u64,
    pub array: [u8; 1],
}
impl _xmlDictStrings {
    pub const fn new() -> Self {
        _xmlDictStrings {
            next: (0 as *mut crate::src::dict::_xmlDictStrings),
            free: (0 as *mut u8),
            end: (0 as *mut u8),
            size: 0,
            nbStrings: 0,
            array: [0],
        }
    }
}
impl std::default::Default for _xmlDictStrings {
    fn default() -> Self {
        _xmlDictStrings::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDictEntry {
    pub next: *mut crate::src::dict::_xmlDictEntry,
    pub name: *const u8,
    pub len: u32,
    pub valid: i32,
    pub okey: u64,
}
impl _xmlDictEntry {
    pub const fn new() -> Self {
        _xmlDictEntry {
            next: (0 as *mut crate::src::dict::_xmlDictEntry),
            name: (0 as *const u8),
            len: 0,
            valid: 0,
            okey: 0,
        }
    }
}
impl std::default::Default for _xmlDictEntry {
    fn default() -> Self {
        _xmlDictEntry::new()
    }
}
pub type xmlDictPtr = *mut crate::src::dict::_xmlDict;
pub type xmlDict = crate::src::dict::_xmlDict;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
pub type xmlDictEntry = crate::src::dict::_xmlDictEntry;
pub type xmlMallocFunc = Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
pub type xmlDictEntryPtr = *mut crate::src::dict::_xmlDictEntry;
static mut xmlDictMutex: *mut crate::src::globals::_xmlMutex = 0 as *const xmlMutex as xmlMutexPtr;
static mut xmlDictInitialized: i32 = 0 as i32;
static mut rand_seed: u32 = 0 as i32 as u32;
#[no_mangle]
pub extern "C" fn xmlInitializeDict() -> i32 {
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn __xmlInitializeDict() -> i32 {
    if (unsafe { xmlDictInitialized }) != 0 {
        return 1 as i32;
    }
    (unsafe { xmlDictMutex = xmlNewMutex() });
    if (unsafe { xmlDictMutex }).is_null() {
        return 0 as i32;
    }
    (unsafe { xmlMutexLock(xmlDictMutex) });
    (unsafe { rand_seed = time(0 as *mut time_t) as u32 });
    (unsafe { rand_r(&mut rand_seed) });
    (unsafe { xmlDictInitialized = 1 as i32 });
    (unsafe { xmlMutexUnlock(xmlDictMutex) });
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn __xmlRandom() -> i32 {
    let mut ret: i32 = 0;
    if (unsafe { xmlDictInitialized }) == 0 as i32 {
        __xmlInitializeDict();
    }
    (unsafe { xmlMutexLock(xmlDictMutex) });
    ret = unsafe { rand_r(&mut rand_seed) };
    (unsafe { xmlMutexUnlock(xmlDictMutex) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlDictCleanup() {
    if (unsafe { xmlDictInitialized }) == 0 {
        return;
    }
    (unsafe { xmlFreeMutex(xmlDictMutex) });
    (unsafe { xmlDictInitialized = 0 as i32 });
}
extern "C" fn xmlDictAddString(
    mut dict: *mut crate::src::dict::_xmlDict,
    mut name: *const u8,
    mut namelen: u32,
) -> *const u8 {
    let mut current_block: u64;
    let mut pool: *mut crate::src::dict::_xmlDictStrings = 0 as *mut xmlDictStrings;
    let mut ret: *const u8 = 0 as *const xmlChar;
    let mut size: u64 = 0 as i32 as size_t;
    let mut limit: u64 = 0 as i32 as size_t;
    pool = unsafe { (*dict).strings };
    loop {
        if pool.is_null() {
            current_block = 13183875560443969876;
            break;
        }
        if (unsafe { ((*pool).end).offset_from((*pool).free) }) as i64 as size_t > namelen as u64 {
            current_block = 16549717771175460023;
            break;
        }
        if (unsafe { (*pool).size }) > size {
            size = unsafe { (*pool).size };
        }
        limit = (limit as u64).wrapping_add(unsafe { (*pool).size }) as size_t as size_t;
        pool = unsafe { (*pool).next };
    }
    match current_block {
        13183875560443969876 => {
            if pool.is_null() {
                if (unsafe { (*dict).limit }) > 0 as i32 as u64
                    && limit > (unsafe { (*dict).limit })
                {
                    return 0 as *const xmlChar;
                }
                if size == 0 as i32 as u64 {
                    size = 1000 as i32 as size_t;
                } else {
                    size = (size as u64).wrapping_mul(4 as i32 as u64) as size_t as size_t;
                }
                if size < (4 as i32 as u32).wrapping_mul(namelen) as u64 {
                    size = (4 as i32 as u32).wrapping_mul(namelen) as size_t;
                }
                pool = (unsafe {
                    xmlMalloc.expect("non-null function pointer")(
                        (::std::mem::size_of::<xmlDictStrings>() as u64).wrapping_add(size),
                    )
                }) as xmlDictStringsPtr;
                if pool.is_null() {
                    return 0 as *const xmlChar;
                }
                (unsafe { (*pool).size = size });
                (unsafe { (*pool).nbStrings = 0 as i32 as size_t });
                let fresh0 = unsafe { &mut ((*pool).free) };
                *fresh0 = (unsafe { &mut *((*pool).array).as_mut_ptr().offset(0 as i32 as isize) })
                    as *mut xmlChar;
                let fresh1 = unsafe { &mut ((*pool).end) };
                *fresh1 = (unsafe { &mut *((*pool).array).as_mut_ptr().offset(size as isize) })
                    as *mut xmlChar;
                let fresh2 = unsafe { &mut ((*pool).next) };
                *fresh2 = unsafe { (*dict).strings };
                let fresh3 = unsafe { &mut ((*dict).strings) };
                *fresh3 = pool;
            }
        }
        _ => {}
    }
    ret = unsafe { (*pool).free };
    (unsafe {
        memcpy(
            (*pool).free as *mut libc::c_void,
            name as *const libc::c_void,
            namelen as u64,
        )
    });
    let fresh4 = unsafe { &mut ((*pool).free) };
    *fresh4 = unsafe { (*fresh4).offset(namelen as isize) };
    let fresh5 = unsafe { &mut ((*pool).free) };
    let mut fresh6 = *fresh5;
    *fresh5 = unsafe { (*fresh5).offset(1) };
    (unsafe { *fresh6 = 0 as i32 as xmlChar });
    let fresh7 = unsafe { &mut ((*pool).nbStrings) };
    *fresh7 = (*fresh7).wrapping_add(1);
    return ret;
}
extern "C" fn xmlDictAddQString(
    mut dict: *mut crate::src::dict::_xmlDict,
    mut prefix: *const u8,
    mut plen: u32,
    mut name: *const u8,
    mut namelen: u32,
) -> *const u8 {
    let mut current_block: u64;
    let mut pool: *mut crate::src::dict::_xmlDictStrings = 0 as *mut xmlDictStrings;
    let mut ret: *const u8 = 0 as *const xmlChar;
    let mut size: u64 = 0 as i32 as size_t;
    let mut limit: u64 = 0 as i32 as size_t;
    if prefix.is_null() {
        return xmlDictAddString(dict, name, namelen);
    }
    pool = unsafe { (*dict).strings };
    loop {
        if pool.is_null() {
            current_block = 13536709405535804910;
            break;
        }
        if (unsafe { ((*pool).end).offset_from((*pool).free) }) as i64 as size_t
            > namelen.wrapping_add(plen).wrapping_add(1 as i32 as u32) as u64
        {
            current_block = 7192883661880266812;
            break;
        }
        if (unsafe { (*pool).size }) > size {
            size = unsafe { (*pool).size };
        }
        limit = (limit as u64).wrapping_add(unsafe { (*pool).size }) as size_t as size_t;
        pool = unsafe { (*pool).next };
    }
    match current_block {
        13536709405535804910 => {
            if pool.is_null() {
                if (unsafe { (*dict).limit }) > 0 as i32 as u64
                    && limit > (unsafe { (*dict).limit })
                {
                    return 0 as *const xmlChar;
                }
                if size == 0 as i32 as u64 {
                    size = 1000 as i32 as size_t;
                } else {
                    size = (size as u64).wrapping_mul(4 as i32 as u64) as size_t as size_t;
                }
                if size
                    < (4 as i32 as u32)
                        .wrapping_mul(namelen.wrapping_add(plen).wrapping_add(1 as i32 as u32))
                        as u64
                {
                    size = (4 as i32 as u32)
                        .wrapping_mul(namelen.wrapping_add(plen).wrapping_add(1 as i32 as u32))
                        as size_t;
                }
                pool = (unsafe {
                    xmlMalloc.expect("non-null function pointer")(
                        (::std::mem::size_of::<xmlDictStrings>() as u64).wrapping_add(size),
                    )
                }) as xmlDictStringsPtr;
                if pool.is_null() {
                    return 0 as *const xmlChar;
                }
                (unsafe { (*pool).size = size });
                (unsafe { (*pool).nbStrings = 0 as i32 as size_t });
                let fresh8 = unsafe { &mut ((*pool).free) };
                *fresh8 = (unsafe { &mut *((*pool).array).as_mut_ptr().offset(0 as i32 as isize) })
                    as *mut xmlChar;
                let fresh9 = unsafe { &mut ((*pool).end) };
                *fresh9 = (unsafe { &mut *((*pool).array).as_mut_ptr().offset(size as isize) })
                    as *mut xmlChar;
                let fresh10 = unsafe { &mut ((*pool).next) };
                *fresh10 = unsafe { (*dict).strings };
                let fresh11 = unsafe { &mut ((*dict).strings) };
                *fresh11 = pool;
            }
        }
        _ => {}
    }
    ret = unsafe { (*pool).free };
    (unsafe {
        memcpy(
            (*pool).free as *mut libc::c_void,
            prefix as *const libc::c_void,
            plen as u64,
        )
    });
    let fresh12 = unsafe { &mut ((*pool).free) };
    *fresh12 = unsafe { (*fresh12).offset(plen as isize) };
    let fresh13 = unsafe { &mut ((*pool).free) };
    let mut fresh14 = *fresh13;
    *fresh13 = unsafe { (*fresh13).offset(1) };
    (unsafe { *fresh14 = ':' as i32 as xmlChar });
    (unsafe {
        memcpy(
            (*pool).free as *mut libc::c_void,
            name as *const libc::c_void,
            namelen as u64,
        )
    });
    let fresh15 = unsafe { &mut ((*pool).free) };
    *fresh15 = unsafe { (*fresh15).offset(namelen as isize) };
    let fresh16 = unsafe { &mut ((*pool).free) };
    let mut fresh17 = *fresh16;
    *fresh16 = unsafe { (*fresh16).offset(1) };
    (unsafe { *fresh17 = 0 as i32 as xmlChar });
    let fresh18 = unsafe { &mut ((*pool).nbStrings) };
    *fresh18 = (*fresh18).wrapping_add(1);
    return ret;
}
extern "C" fn xmlDictComputeBigKey(mut data: *const u8, mut namelen: i32, mut seed: i32) -> u32 {
    let mut hash: u32 = 0;
    let mut i: i32 = 0;
    if namelen <= 0 as i32 || data.is_null() {
        return 0 as i32 as uint32_t;
    }
    hash = seed as uint32_t;
    i = 0 as i32;
    while i < namelen {
        hash = (hash as u32).wrapping_add((unsafe { *data.offset(i as isize) }) as u32) as uint32_t
            as uint32_t;
        hash = (hash as u32).wrapping_add(hash << 10 as i32) as uint32_t as uint32_t;
        hash ^= hash >> 6 as i32;
        i += 1;
    }
    hash = (hash as u32).wrapping_add(hash << 3 as i32) as uint32_t as uint32_t;
    hash ^= hash >> 11 as i32;
    hash = (hash as u32).wrapping_add(hash << 15 as i32) as uint32_t as uint32_t;
    return hash;
}
extern "C" fn xmlDictComputeBigQKey(
    mut prefix: *const u8,
    mut plen: i32,
    mut name: *const u8,
    mut len: i32,
    mut seed: i32,
) -> u64 {
    let mut hash: u32 = 0;
    let mut i: i32 = 0;
    hash = seed as uint32_t;
    i = 0 as i32;
    while i < plen {
        hash = (hash as u32).wrapping_add((unsafe { *prefix.offset(i as isize) }) as u32)
            as uint32_t as uint32_t;
        hash = (hash as u32).wrapping_add(hash << 10 as i32) as uint32_t as uint32_t;
        hash ^= hash >> 6 as i32;
        i += 1;
    }
    hash = (hash as u32).wrapping_add(':' as i32 as u32) as uint32_t as uint32_t;
    hash = (hash as u32).wrapping_add(hash << 10 as i32) as uint32_t as uint32_t;
    hash ^= hash >> 6 as i32;
    i = 0 as i32;
    while i < len {
        hash = (hash as u32).wrapping_add((unsafe { *name.offset(i as isize) }) as u32) as uint32_t
            as uint32_t;
        hash = (hash as u32).wrapping_add(hash << 10 as i32) as uint32_t as uint32_t;
        hash ^= hash >> 6 as i32;
        i += 1;
    }
    hash = (hash as u32).wrapping_add(hash << 3 as i32) as uint32_t as uint32_t;
    hash ^= hash >> 11 as i32;
    hash = (hash as u32).wrapping_add(hash << 15 as i32) as uint32_t as uint32_t;
    return hash as u64;
}
extern "C" fn xmlDictComputeFastKey(mut name: *const u8, mut namelen: i32, mut seed: i32) -> u64 {
    let mut value: u64 = seed as u64;
    if name.is_null() {
        return 0 as i32 as u64;
    }
    value = value.wrapping_add((unsafe { *name }) as u64);
    value <<= 5 as i32;
    if namelen > 10 as i32 {
        value = value.wrapping_add((unsafe { *name.offset((namelen - 1 as i32) as isize) }) as u64);
        namelen = 10 as i32;
    }
    let mut current_block_16: u64;
    match namelen {
        10 => {
            value = value.wrapping_add((unsafe { *name.offset(9 as i32 as isize) }) as u64);
            current_block_16 = 4712646747277482294;
        }
        9 => {
            current_block_16 = 4712646747277482294;
        }
        8 => {
            current_block_16 = 7244956010693875373;
        }
        7 => {
            current_block_16 = 17573653595028029515;
        }
        6 => {
            current_block_16 = 11089524544337135140;
        }
        5 => {
            current_block_16 = 18235174393473213413;
        }
        4 => {
            current_block_16 = 16104263797903159467;
        }
        3 => {
            current_block_16 = 11324303184752563449;
        }
        2 => {
            current_block_16 = 1900231684298568950;
        }
        _ => {
            current_block_16 = 2838571290723028321;
        }
    }
    match current_block_16 {
        4712646747277482294 => {
            value = value.wrapping_add((unsafe { *name.offset(8 as i32 as isize) }) as u64);
            current_block_16 = 7244956010693875373;
        }
        _ => {}
    }
    match current_block_16 {
        7244956010693875373 => {
            value = value.wrapping_add((unsafe { *name.offset(7 as i32 as isize) }) as u64);
            current_block_16 = 17573653595028029515;
        }
        _ => {}
    }
    match current_block_16 {
        17573653595028029515 => {
            value = value.wrapping_add((unsafe { *name.offset(6 as i32 as isize) }) as u64);
            current_block_16 = 11089524544337135140;
        }
        _ => {}
    }
    match current_block_16 {
        11089524544337135140 => {
            value = value.wrapping_add((unsafe { *name.offset(5 as i32 as isize) }) as u64);
            current_block_16 = 18235174393473213413;
        }
        _ => {}
    }
    match current_block_16 {
        18235174393473213413 => {
            value = value.wrapping_add((unsafe { *name.offset(4 as i32 as isize) }) as u64);
            current_block_16 = 16104263797903159467;
        }
        _ => {}
    }
    match current_block_16 {
        16104263797903159467 => {
            value = value.wrapping_add((unsafe { *name.offset(3 as i32 as isize) }) as u64);
            current_block_16 = 11324303184752563449;
        }
        _ => {}
    }
    match current_block_16 {
        11324303184752563449 => {
            value = value.wrapping_add((unsafe { *name.offset(2 as i32 as isize) }) as u64);
            current_block_16 = 1900231684298568950;
        }
        _ => {}
    }
    match current_block_16 {
        1900231684298568950 => {
            value = value.wrapping_add((unsafe { *name.offset(1 as i32 as isize) }) as u64);
        }
        _ => {}
    }
    return value;
}
extern "C" fn xmlDictComputeFastQKey(
    mut prefix: *const u8,
    mut plen: i32,
    mut name: *const u8,
    mut len: i32,
    mut seed: i32,
) -> u64 {
    let mut value: u64 = seed as u64;
    if plen == 0 as i32 {
        value = value.wrapping_add((30 as i32 as u64).wrapping_mul(':' as i32 as u64));
    } else {
        value = value.wrapping_add((30 as i32 * (unsafe { *prefix }) as i32) as u64);
    }
    if len > 10 as i32 {
        let mut offset: i32 = len - (plen + 1 as i32 + 1 as i32);
        if offset < 0 as i32 {
            offset = len - (10 as i32 + 1 as i32);
        }
        value = value.wrapping_add((unsafe { *name.offset(offset as isize) }) as u64);
        len = 10 as i32;
        if plen > 10 as i32 {
            plen = 10 as i32;
        }
    }
    let mut current_block_20: u64;
    match plen {
        10 => {
            value = value.wrapping_add((unsafe { *prefix.offset(9 as i32 as isize) }) as u64);
            current_block_20 = 8290107711210295691;
        }
        9 => {
            current_block_20 = 8290107711210295691;
        }
        8 => {
            current_block_20 = 7038770548287051377;
        }
        7 => {
            current_block_20 = 10770133212036609160;
        }
        6 => {
            current_block_20 = 12600003426392199789;
        }
        5 => {
            current_block_20 = 16012330138488115495;
        }
        4 => {
            current_block_20 = 1411058975029915551;
        }
        3 => {
            current_block_20 = 8768901130990501272;
        }
        2 => {
            current_block_20 = 8280968883510158391;
        }
        1 => {
            current_block_20 = 14259685586177370419;
        }
        _ => {
            current_block_20 = 17478428563724192186;
        }
    }
    match current_block_20 {
        8290107711210295691 => {
            value = value.wrapping_add((unsafe { *prefix.offset(8 as i32 as isize) }) as u64);
            current_block_20 = 7038770548287051377;
        }
        _ => {}
    }
    match current_block_20 {
        7038770548287051377 => {
            value = value.wrapping_add((unsafe { *prefix.offset(7 as i32 as isize) }) as u64);
            current_block_20 = 10770133212036609160;
        }
        _ => {}
    }
    match current_block_20 {
        10770133212036609160 => {
            value = value.wrapping_add((unsafe { *prefix.offset(6 as i32 as isize) }) as u64);
            current_block_20 = 12600003426392199789;
        }
        _ => {}
    }
    match current_block_20 {
        12600003426392199789 => {
            value = value.wrapping_add((unsafe { *prefix.offset(5 as i32 as isize) }) as u64);
            current_block_20 = 16012330138488115495;
        }
        _ => {}
    }
    match current_block_20 {
        16012330138488115495 => {
            value = value.wrapping_add((unsafe { *prefix.offset(4 as i32 as isize) }) as u64);
            current_block_20 = 1411058975029915551;
        }
        _ => {}
    }
    match current_block_20 {
        1411058975029915551 => {
            value = value.wrapping_add((unsafe { *prefix.offset(3 as i32 as isize) }) as u64);
            current_block_20 = 8768901130990501272;
        }
        _ => {}
    }
    match current_block_20 {
        8768901130990501272 => {
            value = value.wrapping_add((unsafe { *prefix.offset(2 as i32 as isize) }) as u64);
            current_block_20 = 8280968883510158391;
        }
        _ => {}
    }
    match current_block_20 {
        8280968883510158391 => {
            value = value.wrapping_add((unsafe { *prefix.offset(1 as i32 as isize) }) as u64);
            current_block_20 = 14259685586177370419;
        }
        _ => {}
    }
    match current_block_20 {
        14259685586177370419 => {
            value = value.wrapping_add((unsafe { *prefix.offset(0 as i32 as isize) }) as u64);
        }
        _ => {}
    }
    len -= plen;
    if len > 0 as i32 {
        value = value.wrapping_add(':' as i32 as u64);
        len -= 1;
    }
    let mut current_block_36: u64;
    match len {
        10 => {
            value = value.wrapping_add((unsafe { *name.offset(9 as i32 as isize) }) as u64);
            current_block_36 = 16778855680919949423;
        }
        9 => {
            current_block_36 = 16778855680919949423;
        }
        8 => {
            current_block_36 = 17869296276999015210;
        }
        7 => {
            current_block_36 = 5309407416788998794;
        }
        6 => {
            current_block_36 = 7515937090034470222;
        }
        5 => {
            current_block_36 = 4953035719795365622;
        }
        4 => {
            current_block_36 = 16676005767965041358;
        }
        3 => {
            current_block_36 = 8784458375054248129;
        }
        2 => {
            current_block_36 = 563573333189432338;
        }
        1 => {
            current_block_36 = 8480119504522294706;
        }
        _ => {
            current_block_36 = 2543120759711851213;
        }
    }
    match current_block_36 {
        16778855680919949423 => {
            value = value.wrapping_add((unsafe { *name.offset(8 as i32 as isize) }) as u64);
            current_block_36 = 17869296276999015210;
        }
        _ => {}
    }
    match current_block_36 {
        17869296276999015210 => {
            value = value.wrapping_add((unsafe { *name.offset(7 as i32 as isize) }) as u64);
            current_block_36 = 5309407416788998794;
        }
        _ => {}
    }
    match current_block_36 {
        5309407416788998794 => {
            value = value.wrapping_add((unsafe { *name.offset(6 as i32 as isize) }) as u64);
            current_block_36 = 7515937090034470222;
        }
        _ => {}
    }
    match current_block_36 {
        7515937090034470222 => {
            value = value.wrapping_add((unsafe { *name.offset(5 as i32 as isize) }) as u64);
            current_block_36 = 4953035719795365622;
        }
        _ => {}
    }
    match current_block_36 {
        4953035719795365622 => {
            value = value.wrapping_add((unsafe { *name.offset(4 as i32 as isize) }) as u64);
            current_block_36 = 16676005767965041358;
        }
        _ => {}
    }
    match current_block_36 {
        16676005767965041358 => {
            value = value.wrapping_add((unsafe { *name.offset(3 as i32 as isize) }) as u64);
            current_block_36 = 8784458375054248129;
        }
        _ => {}
    }
    match current_block_36 {
        8784458375054248129 => {
            value = value.wrapping_add((unsafe { *name.offset(2 as i32 as isize) }) as u64);
            current_block_36 = 563573333189432338;
        }
        _ => {}
    }
    match current_block_36 {
        563573333189432338 => {
            value = value.wrapping_add((unsafe { *name.offset(1 as i32 as isize) }) as u64);
            current_block_36 = 8480119504522294706;
        }
        _ => {}
    }
    match current_block_36 {
        8480119504522294706 => {
            value = value.wrapping_add((unsafe { *name.offset(0 as i32 as isize) }) as u64);
        }
        _ => {}
    }
    return value;
}
#[no_mangle]
pub extern "C" fn xmlDictCreate() -> *mut crate::src::dict::_xmlDict {
    let mut dict: *mut crate::src::dict::_xmlDict = 0 as *mut xmlDict;
    if (unsafe { xmlDictInitialized }) == 0 {
        if __xmlInitializeDict() == 0 {
            return 0 as xmlDictPtr;
        }
    }
    dict = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlDict>() as u64)
    }) as xmlDictPtr;
    if !dict.is_null() {
        (unsafe { (*dict).ref_counter = 1 as i32 });
        (unsafe { (*dict).limit = 0 as i32 as size_t });
        (unsafe { (*dict).size = 128 as i32 as size_t });
        (unsafe { (*dict).nbElems = 0 as i32 as u32 });
        let fresh19 = unsafe { &mut ((*dict).dict) };
        *fresh19 = (unsafe {
            xmlMalloc.expect("non-null function pointer")(
                (128 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlDictEntry>() as u64),
            )
        }) as *mut _xmlDictEntry;
        let fresh20 = unsafe { &mut ((*dict).strings) };
        *fresh20 = 0 as xmlDictStringsPtr;
        let fresh21 = unsafe { &mut ((*dict).subdict) };
        *fresh21 = 0 as *mut _xmlDict;
        if !(unsafe { (*dict).dict }).is_null() {
            (unsafe {
                memset(
                    (*dict).dict as *mut libc::c_void,
                    0 as i32,
                    (128 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlDictEntry>() as u64),
                )
            });
            (unsafe { (*dict).seed = __xmlRandom() });
            return dict;
        }
        (unsafe { xmlFree.expect("non-null function pointer")(dict as *mut libc::c_void) });
    }
    return 0 as xmlDictPtr;
}
#[no_mangle]
pub extern "C" fn xmlDictCreateSub(
    mut sub: *mut crate::src::dict::_xmlDict,
) -> *mut crate::src::dict::_xmlDict {
    let mut dict: *mut crate::src::dict::_xmlDict = xmlDictCreate();
    if !dict.is_null() && !sub.is_null() {
        (unsafe { (*dict).seed = (*sub).seed });
        let fresh22 = unsafe { &mut ((*dict).subdict) };
        *fresh22 = sub;
        xmlDictReference(unsafe { (*dict).subdict });
    }
    return dict;
}
#[no_mangle]
pub extern "C" fn xmlDictReference(mut dict: *mut crate::src::dict::_xmlDict) -> i32 {
    if (unsafe { xmlDictInitialized }) == 0 {
        if __xmlInitializeDict() == 0 {
            return -(1 as i32);
        }
    }
    if dict.is_null() {
        return -(1 as i32);
    }
    (unsafe { xmlMutexLock(xmlDictMutex) });
    let fresh23 = unsafe { &mut ((*dict).ref_counter) };
    *fresh23 += 1;
    (unsafe { xmlMutexUnlock(xmlDictMutex) });
    return 0 as i32;
}
extern "C" fn xmlDictGrow(mut dict: *mut crate::src::dict::_xmlDict, mut size: u64) -> i32 {
    let mut key: u64 = 0;
    let mut okey: u64 = 0;
    let mut oldsize: u64 = 0;
    let mut i: u64 = 0;
    let mut iter: *mut crate::src::dict::_xmlDictEntry = 0 as *mut xmlDictEntry;
    let mut next: *mut crate::src::dict::_xmlDictEntry = 0 as *mut xmlDictEntry;
    let mut olddict: *mut crate::src::dict::_xmlDictEntry = 0 as *mut _xmlDictEntry;
    let mut ret: i32 = 0 as i32;
    let mut keep_keys: i32 = 1 as i32;
    if dict.is_null() {
        return -(1 as i32);
    }
    if size < 8 as i32 as u64 {
        return -(1 as i32);
    }
    if size > (8 as i32 * 2048 as i32) as u64 {
        return -(1 as i32);
    }
    oldsize = unsafe { (*dict).size };
    olddict = unsafe { (*dict).dict };
    if olddict.is_null() {
        return -(1 as i32);
    }
    if oldsize == 128 as i32 as u64 {
        keep_keys = 0 as i32;
    }
    let fresh24 = unsafe { &mut ((*dict).dict) };
    *fresh24 = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            size.wrapping_mul(::std::mem::size_of::<xmlDictEntry>() as u64),
        )
    }) as *mut _xmlDictEntry;
    if (unsafe { (*dict).dict }).is_null() {
        let fresh25 = unsafe { &mut ((*dict).dict) };
        *fresh25 = olddict;
        return -(1 as i32);
    }
    (unsafe {
        memset(
            (*dict).dict as *mut libc::c_void,
            0 as i32,
            size.wrapping_mul(::std::mem::size_of::<xmlDictEntry>() as u64),
        )
    });
    (unsafe { (*dict).size = size });
    i = 0 as i32 as size_t;
    while i < oldsize {
        if !((unsafe { (*olddict.offset(i as isize)).valid }) == 0 as i32) {
            if keep_keys != 0 {
                okey = unsafe { (*olddict.offset(i as isize)).okey };
            } else {
                okey = if (unsafe { (*dict).size }) == 128 as i32 as u64 {
                    xmlDictComputeFastKey(
                        unsafe { (*olddict.offset(i as isize)).name },
                        (unsafe { (*olddict.offset(i as isize)).len }) as i32,
                        unsafe { (*dict).seed },
                    )
                } else {
                    xmlDictComputeBigKey(
                        unsafe { (*olddict.offset(i as isize)).name },
                        (unsafe { (*olddict.offset(i as isize)).len }) as i32,
                        unsafe { (*dict).seed },
                    ) as u64
                };
            }
            key = okey.wrapping_rem(unsafe { (*dict).size });
            if (unsafe { (*((*dict).dict).offset(key as isize)).valid }) == 0 as i32 {
                (unsafe {
                    memcpy(
                        &mut *((*dict).dict).offset(key as isize) as *mut _xmlDictEntry
                            as *mut libc::c_void,
                        &mut *olddict.offset(i as isize) as *mut _xmlDictEntry
                            as *const libc::c_void,
                        ::std::mem::size_of::<xmlDictEntry>() as u64,
                    )
                });
                let fresh26 = unsafe { &mut ((*((*dict).dict).offset(key as isize)).next) };
                *fresh26 = 0 as *mut _xmlDictEntry;
                (unsafe { (*((*dict).dict).offset(key as isize)).okey = okey });
            } else {
                let mut entry: *mut crate::src::dict::_xmlDictEntry = 0 as *mut xmlDictEntry;
                entry = (unsafe {
                    xmlMalloc.expect("non-null function pointer")(
                        ::std::mem::size_of::<xmlDictEntry>() as u64,
                    )
                }) as xmlDictEntryPtr;
                if !entry.is_null() {
                    let fresh27 = unsafe { &mut ((*entry).name) };
                    *fresh27 = unsafe { (*olddict.offset(i as isize)).name };
                    (unsafe { (*entry).len = (*olddict.offset(i as isize)).len });
                    (unsafe { (*entry).okey = okey });
                    let fresh28 = unsafe { &mut ((*entry).next) };
                    *fresh28 = unsafe { (*((*dict).dict).offset(key as isize)).next };
                    (unsafe { (*entry).valid = 1 as i32 });
                    let fresh29 = unsafe { &mut ((*((*dict).dict).offset(key as isize)).next) };
                    *fresh29 = entry;
                } else {
                    ret = -(1 as i32);
                }
            }
        }
        i = i.wrapping_add(1);
    }
    i = 0 as i32 as size_t;
    while i < oldsize {
        iter = unsafe { (*olddict.offset(i as isize)).next };
        while !iter.is_null() {
            next = unsafe { (*iter).next };
            if keep_keys != 0 {
                okey = unsafe { (*iter).okey };
            } else {
                okey = if (unsafe { (*dict).size }) == 128 as i32 as u64 {
                    xmlDictComputeFastKey(
                        unsafe { (*iter).name },
                        (unsafe { (*iter).len }) as i32,
                        unsafe { (*dict).seed },
                    )
                } else {
                    xmlDictComputeBigKey(
                        unsafe { (*iter).name },
                        (unsafe { (*iter).len }) as i32,
                        unsafe { (*dict).seed },
                    ) as u64
                };
            }
            key = okey.wrapping_rem(unsafe { (*dict).size });
            if (unsafe { (*((*dict).dict).offset(key as isize)).valid }) == 0 as i32 {
                (unsafe {
                    memcpy(
                        &mut *((*dict).dict).offset(key as isize) as *mut _xmlDictEntry
                            as *mut libc::c_void,
                        iter as *const libc::c_void,
                        ::std::mem::size_of::<xmlDictEntry>() as u64,
                    )
                });
                let fresh30 = unsafe { &mut ((*((*dict).dict).offset(key as isize)).next) };
                *fresh30 = 0 as *mut _xmlDictEntry;
                (unsafe { (*((*dict).dict).offset(key as isize)).valid = 1 as i32 });
                (unsafe { (*((*dict).dict).offset(key as isize)).okey = okey });
                (unsafe { xmlFree.expect("non-null function pointer")(iter as *mut libc::c_void) });
            } else {
                let fresh31 = unsafe { &mut ((*iter).next) };
                *fresh31 = unsafe { (*((*dict).dict).offset(key as isize)).next };
                (unsafe { (*iter).okey = okey });
                let fresh32 = unsafe { &mut ((*((*dict).dict).offset(key as isize)).next) };
                *fresh32 = iter;
            }
            iter = next;
        }
        i = i.wrapping_add(1);
    }
    (unsafe { xmlFree.expect("non-null function pointer")(olddict as *mut libc::c_void) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlDictFree(mut dict: *mut crate::src::dict::_xmlDict) {
    let mut i: u64 = 0;
    let mut iter: *mut crate::src::dict::_xmlDictEntry = 0 as *mut xmlDictEntry;
    let mut next: *mut crate::src::dict::_xmlDictEntry = 0 as *mut xmlDictEntry;
    let mut inside_dict: i32 = 0 as i32;
    let mut pool: *mut crate::src::dict::_xmlDictStrings = 0 as *mut xmlDictStrings;
    let mut nextp: *mut crate::src::dict::_xmlDictStrings = 0 as *mut xmlDictStrings;
    if dict.is_null() {
        return;
    }
    if (unsafe { xmlDictInitialized }) == 0 {
        if __xmlInitializeDict() == 0 {
            return;
        }
    }
    (unsafe { xmlMutexLock(xmlDictMutex) });
    let fresh33 = unsafe { &mut ((*dict).ref_counter) };
    *fresh33 -= 1;
    if (unsafe { (*dict).ref_counter }) > 0 as i32 {
        (unsafe { xmlMutexUnlock(xmlDictMutex) });
        return;
    }
    (unsafe { xmlMutexUnlock(xmlDictMutex) });
    if !(unsafe { (*dict).subdict }).is_null() {
        xmlDictFree(unsafe { (*dict).subdict });
    }
    if !(unsafe { (*dict).dict }).is_null() {
        i = 0 as i32 as size_t;
        while i < (unsafe { (*dict).size }) && (unsafe { (*dict).nbElems }) > 0 as i32 as u32 {
            iter = (unsafe { &mut *((*dict).dict).offset(i as isize) }) as *mut _xmlDictEntry;
            if !((unsafe { (*iter).valid }) == 0 as i32) {
                inside_dict = 1 as i32;
                while !iter.is_null() {
                    next = unsafe { (*iter).next };
                    if inside_dict == 0 {
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(iter as *mut libc::c_void)
                        });
                    }
                    let fresh34 = unsafe { &mut ((*dict).nbElems) };
                    *fresh34 = (*fresh34).wrapping_sub(1);
                    inside_dict = 0 as i32;
                    iter = next;
                }
            }
            i = i.wrapping_add(1);
        }
        (unsafe { xmlFree.expect("non-null function pointer")((*dict).dict as *mut libc::c_void) });
    }
    pool = unsafe { (*dict).strings };
    while !pool.is_null() {
        nextp = unsafe { (*pool).next };
        (unsafe { xmlFree.expect("non-null function pointer")(pool as *mut libc::c_void) });
        pool = nextp;
    }
    (unsafe { xmlFree.expect("non-null function pointer")(dict as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlDictLookup(
    mut dict: *mut crate::src::dict::_xmlDict,
    mut name: *const u8,
    mut len: i32,
) -> *const u8 {
    let mut key: u64 = 0;
    let mut okey: u64 = 0;
    let mut nbi: u64 = 0 as i32 as u64;
    let mut entry: *mut crate::src::dict::_xmlDictEntry = 0 as *mut xmlDictEntry;
    let mut insert: *mut crate::src::dict::_xmlDictEntry = 0 as *mut xmlDictEntry;
    let mut ret: *const u8 = 0 as *const xmlChar;
    let mut l: u32 = 0;
    if dict.is_null() || name.is_null() {
        return 0 as *const xmlChar;
    }
    if len < 0 as i32 {
        l = (unsafe { strlen(name as *const i8) }) as u32;
    } else {
        l = len as u32;
    }
    if (unsafe { (*dict).limit }) > 0 as i32 as u64 && l as u64 >= (unsafe { (*dict).limit })
        || l > (2147483647 as i32 / 2 as i32) as u32
    {
        return 0 as *const xmlChar;
    }
    okey = if (unsafe { (*dict).size }) == 128 as i32 as u64 {
        xmlDictComputeFastKey(name, l as i32, unsafe { (*dict).seed })
    } else {
        xmlDictComputeBigKey(name, l as i32, unsafe { (*dict).seed }) as u64
    };
    key = okey.wrapping_rem(unsafe { (*dict).size });
    if (unsafe { (*((*dict).dict).offset(key as isize)).valid }) == 0 as i32 {
        insert = 0 as xmlDictEntryPtr;
    } else {
        insert = (unsafe { &mut *((*dict).dict).offset(key as isize) }) as *mut _xmlDictEntry;
        while !(unsafe { (*insert).next }).is_null() {
            if (unsafe { (*insert).okey }) == okey && (unsafe { (*insert).len }) == l {
                if (unsafe {
                    memcmp(
                        (*insert).name as *const libc::c_void,
                        name as *const libc::c_void,
                        l as u64,
                    )
                }) == 0
                {
                    return unsafe { (*insert).name };
                }
            }
            nbi = nbi.wrapping_add(1);
            insert = unsafe { (*insert).next };
        }
        if (unsafe { (*insert).okey }) == okey && (unsafe { (*insert).len }) == l {
            if (unsafe {
                memcmp(
                    (*insert).name as *const libc::c_void,
                    name as *const libc::c_void,
                    l as u64,
                )
            }) == 0
            {
                return unsafe { (*insert).name };
            }
        }
    }
    if !(unsafe { (*dict).subdict }).is_null() {
        let mut skey: u64 = 0;
        if (unsafe { (*dict).size }) == 128 as i32 as u64
            && (unsafe { (*(*dict).subdict).size }) != 128 as i32 as u64
            || (unsafe { (*dict).size }) != 128 as i32 as u64
                && (unsafe { (*(*dict).subdict).size }) == 128 as i32 as u64
        {
            skey = if (unsafe { (*(*dict).subdict).size }) == 128 as i32 as u64 {
                xmlDictComputeFastKey(name, l as i32, unsafe { (*(*dict).subdict).seed })
            } else {
                xmlDictComputeBigKey(name, l as i32, unsafe { (*(*dict).subdict).seed }) as u64
            };
        } else {
            skey = okey;
        }
        key = skey.wrapping_rem(unsafe { (*(*dict).subdict).size });
        if (unsafe { (*((*(*dict).subdict).dict).offset(key as isize)).valid }) != 0 as i32 {
            let mut tmp: *mut crate::src::dict::_xmlDictEntry = 0 as *mut xmlDictEntry;
            tmp = (unsafe { &mut *((*(*dict).subdict).dict).offset(key as isize) })
                as *mut _xmlDictEntry;
            while !(unsafe { (*tmp).next }).is_null() {
                if (unsafe { (*tmp).okey }) == skey && (unsafe { (*tmp).len }) == l {
                    if (unsafe {
                        memcmp(
                            (*tmp).name as *const libc::c_void,
                            name as *const libc::c_void,
                            l as u64,
                        )
                    }) == 0
                    {
                        return unsafe { (*tmp).name };
                    }
                }
                nbi = nbi.wrapping_add(1);
                tmp = unsafe { (*tmp).next };
            }
            if (unsafe { (*tmp).okey }) == skey && (unsafe { (*tmp).len }) == l {
                if (unsafe {
                    memcmp(
                        (*tmp).name as *const libc::c_void,
                        name as *const libc::c_void,
                        l as u64,
                    )
                }) == 0
                {
                    return unsafe { (*tmp).name };
                }
            }
        }
        key = okey.wrapping_rem(unsafe { (*dict).size });
    }
    ret = xmlDictAddString(dict, name, l);
    if ret.is_null() {
        return 0 as *const xmlChar;
    }
    if insert.is_null() {
        entry = (unsafe { &mut *((*dict).dict).offset(key as isize) }) as *mut _xmlDictEntry;
    } else {
        entry = (unsafe {
            xmlMalloc.expect("non-null function pointer")(
                ::std::mem::size_of::<xmlDictEntry>() as u64
            )
        }) as xmlDictEntryPtr;
        if entry.is_null() {
            return 0 as *const xmlChar;
        }
    }
    let fresh35 = unsafe { &mut ((*entry).name) };
    *fresh35 = ret;
    (unsafe { (*entry).len = l });
    let fresh36 = unsafe { &mut ((*entry).next) };
    *fresh36 = 0 as *mut _xmlDictEntry;
    (unsafe { (*entry).valid = 1 as i32 });
    (unsafe { (*entry).okey = okey });
    if !insert.is_null() {
        let fresh37 = unsafe { &mut ((*insert).next) };
        *fresh37 = entry;
    }
    let fresh38 = unsafe { &mut ((*dict).nbElems) };
    *fresh38 = (*fresh38).wrapping_add(1);
    if nbi > 3 as i32 as u64
        && (unsafe { (*dict).size }) <= (8 as i32 * 2048 as i32 / 2 as i32 / 3 as i32) as u64
    {
        if xmlDictGrow(
            dict,
            ((3 as i32 * 2 as i32) as u64).wrapping_mul(unsafe { (*dict).size }),
        ) != 0 as i32
        {
            return 0 as *const xmlChar;
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlDictExists<'a1>(
    mut dict: Option<&'a1 mut crate::src::dict::_xmlDict>,
    mut name: *const u8,
    mut len: i32,
) -> *const u8 {
    let mut key: u64 = 0;
    let mut okey: u64 = 0;
    let mut nbi: u64 = 0 as i32 as u64;
    let mut insert: *mut crate::src::dict::_xmlDictEntry = 0 as *mut xmlDictEntry;
    let mut l: u32 = 0;
    if borrow(&dict).is_none() || name.is_null() {
        return 0 as *const xmlChar;
    }
    if len < 0 as i32 {
        l = (unsafe { strlen(name as *const i8) }) as u32;
    } else {
        l = len as u32;
    }
    if (*(borrow(&dict)).unwrap()).limit > 0 as i32 as u64
        && l as u64 >= (*(borrow(&dict)).unwrap()).limit
        || l > (2147483647 as i32 / 2 as i32) as u32
    {
        return 0 as *const xmlChar;
    }
    okey = if (*(borrow(&dict)).unwrap()).size == 128 as i32 as u64 {
        xmlDictComputeFastKey(name, l as i32, (*(borrow_mut(&mut dict)).unwrap()).seed)
    } else {
        xmlDictComputeBigKey(name, l as i32, (*(borrow_mut(&mut dict)).unwrap()).seed) as u64
    };
    key = okey.wrapping_rem((*(borrow(&dict)).unwrap()).size);
    if (unsafe { (*((*(borrow(&dict)).unwrap()).dict).offset(key as isize)).valid }) == 0 as i32 {
        insert = 0 as xmlDictEntryPtr;
    } else {
        insert = (unsafe { &mut *((*(borrow(&dict)).unwrap()).dict).offset(key as isize) })
            as *mut _xmlDictEntry;
        while !(unsafe { (*insert).next }).is_null() {
            if (unsafe { (*insert).okey }) == okey && (unsafe { (*insert).len }) == l {
                if (unsafe {
                    memcmp(
                        (*insert).name as *const libc::c_void,
                        name as *const libc::c_void,
                        l as u64,
                    )
                }) == 0
                {
                    return unsafe { (*insert).name };
                }
            }
            nbi = nbi.wrapping_add(1);
            insert = unsafe { (*insert).next };
        }
        if (unsafe { (*insert).okey }) == okey && (unsafe { (*insert).len }) == l {
            if (unsafe {
                memcmp(
                    (*insert).name as *const libc::c_void,
                    name as *const libc::c_void,
                    l as u64,
                )
            }) == 0
            {
                return unsafe { (*insert).name };
            }
        }
    }
    if !((*(borrow(&dict)).unwrap()).subdict).is_null() {
        let mut skey: u64 = 0;
        if (*(borrow(&dict)).unwrap()).size == 128 as i32 as u64
            && (unsafe { (*(*(borrow(&dict)).unwrap()).subdict).size }) != 128 as i32 as u64
            || (*(borrow(&dict)).unwrap()).size != 128 as i32 as u64
                && (unsafe { (*(*(borrow(&dict)).unwrap()).subdict).size }) == 128 as i32 as u64
        {
            skey = if (unsafe { (*(*(borrow(&dict)).unwrap()).subdict).size }) == 128 as i32 as u64
            {
                xmlDictComputeFastKey(
                    name,
                    l as i32,
                    unsafe { (*(*(borrow_mut(&mut dict)).unwrap()).subdict).seed },
                )
            } else {
                xmlDictComputeBigKey(
                    name,
                    l as i32,
                    unsafe { (*(*(borrow_mut(&mut dict)).unwrap()).subdict).seed },
                ) as u64
            };
        } else {
            skey = okey;
        }
        key = skey.wrapping_rem(unsafe { (*(*(borrow(&dict)).unwrap()).subdict).size });
        if (unsafe { (*((*(*(borrow(&dict)).unwrap()).subdict).dict).offset(key as isize)).valid })
            != 0 as i32
        {
            let mut tmp: *mut crate::src::dict::_xmlDictEntry = 0 as *mut xmlDictEntry;
            tmp = (unsafe {
                &mut *((*(*(borrow(&dict)).unwrap()).subdict).dict).offset(key as isize)
            }) as *mut _xmlDictEntry;
            while !(unsafe { (*tmp).next }).is_null() {
                if (unsafe { (*tmp).okey }) == skey && (unsafe { (*tmp).len }) == l {
                    if (unsafe {
                        memcmp(
                            (*tmp).name as *const libc::c_void,
                            name as *const libc::c_void,
                            l as u64,
                        )
                    }) == 0
                    {
                        return unsafe { (*tmp).name };
                    }
                }
                nbi = nbi.wrapping_add(1);
                tmp = unsafe { (*tmp).next };
            }
            if (unsafe { (*tmp).okey }) == skey && (unsafe { (*tmp).len }) == l {
                if (unsafe {
                    memcmp(
                        (*tmp).name as *const libc::c_void,
                        name as *const libc::c_void,
                        l as u64,
                    )
                }) == 0
                {
                    return unsafe { (*tmp).name };
                }
            }
        }
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlDictQLookup(
    mut dict: *mut crate::src::dict::_xmlDict,
    mut prefix: *const u8,
    mut name: *const u8,
) -> *const u8 {
    let mut okey: u64 = 0;
    let mut key: u64 = 0;
    let mut nbi: u64 = 0 as i32 as u64;
    let mut entry: *mut crate::src::dict::_xmlDictEntry = 0 as *mut xmlDictEntry;
    let mut insert: *mut crate::src::dict::_xmlDictEntry = 0 as *mut xmlDictEntry;
    let mut ret: *const u8 = 0 as *const xmlChar;
    let mut len: u32 = 0;
    let mut plen: u32 = 0;
    let mut l: u32 = 0;
    if dict.is_null() || name.is_null() {
        return 0 as *const xmlChar;
    }
    if prefix.is_null() {
        return xmlDictLookup(dict, name, -(1 as i32));
    }
    len = (unsafe { strlen(name as *const i8) }) as u32;
    l = len;
    plen = (unsafe { strlen(prefix as *const i8) }) as u32;
    len = len.wrapping_add((1 as i32 as u32).wrapping_add(plen));
    okey = if prefix.is_null() {
        if (unsafe { (*dict).size }) == 128 as i32 as u64 {
            xmlDictComputeFastKey(name, l as i32, unsafe { (*dict).seed })
        } else {
            xmlDictComputeBigKey(name, l as i32, unsafe { (*dict).seed }) as u64
        }
    } else if (unsafe { (*dict).size }) == 128 as i32 as u64 {
        xmlDictComputeFastQKey(
            prefix,
            plen as i32,
            name,
            l as i32,
            unsafe { (*dict).seed },
        )
    } else {
        xmlDictComputeBigQKey(
            prefix,
            plen as i32,
            name,
            l as i32,
            unsafe { (*dict).seed },
        )
    };
    key = okey.wrapping_rem(unsafe { (*dict).size });
    if (unsafe { (*((*dict).dict).offset(key as isize)).valid }) == 0 as i32 {
        insert = 0 as xmlDictEntryPtr;
    } else {
        insert = (unsafe { &mut *((*dict).dict).offset(key as isize) }) as *mut _xmlDictEntry;
        while !(unsafe { (*insert).next }).is_null() {
            if (unsafe { (*insert).okey }) == okey
                && (unsafe { (*insert).len }) == len
                && (unsafe { xmlStrQEqual(prefix, name, (*insert).name) }) != 0
            {
                return unsafe { (*insert).name };
            }
            nbi = nbi.wrapping_add(1);
            insert = unsafe { (*insert).next };
        }
        if (unsafe { (*insert).okey }) == okey
            && (unsafe { (*insert).len }) == len
            && (unsafe { xmlStrQEqual(prefix, name, (*insert).name) }) != 0
        {
            return unsafe { (*insert).name };
        }
    }
    if !(unsafe { (*dict).subdict }).is_null() {
        let mut skey: u64 = 0;
        if (unsafe { (*dict).size }) == 128 as i32 as u64
            && (unsafe { (*(*dict).subdict).size }) != 128 as i32 as u64
            || (unsafe { (*dict).size }) != 128 as i32 as u64
                && (unsafe { (*(*dict).subdict).size }) == 128 as i32 as u64
        {
            skey = if prefix.is_null() {
                if (unsafe { (*(*dict).subdict).size }) == 128 as i32 as u64 {
                    xmlDictComputeFastKey(name, l as i32, unsafe { (*(*dict).subdict).seed })
                } else {
                    xmlDictComputeBigKey(name, l as i32, unsafe { (*(*dict).subdict).seed })
                        as u64
                }
            } else if (unsafe { (*(*dict).subdict).size }) == 128 as i32 as u64 {
                xmlDictComputeFastQKey(
                    prefix,
                    plen as i32,
                    name,
                    l as i32,
                    unsafe { (*(*dict).subdict).seed },
                )
            } else {
                xmlDictComputeBigQKey(
                    prefix,
                    plen as i32,
                    name,
                    l as i32,
                    unsafe { (*(*dict).subdict).seed },
                )
            };
        } else {
            skey = okey;
        }
        key = skey.wrapping_rem(unsafe { (*(*dict).subdict).size });
        if (unsafe { (*((*(*dict).subdict).dict).offset(key as isize)).valid }) != 0 as i32 {
            let mut tmp: *mut crate::src::dict::_xmlDictEntry = 0 as *mut xmlDictEntry;
            tmp = (unsafe { &mut *((*(*dict).subdict).dict).offset(key as isize) })
                as *mut _xmlDictEntry;
            while !(unsafe { (*tmp).next }).is_null() {
                if (unsafe { (*tmp).okey }) == skey
                    && (unsafe { (*tmp).len }) == len
                    && (unsafe { xmlStrQEqual(prefix, name, (*tmp).name) }) != 0
                {
                    return unsafe { (*tmp).name };
                }
                nbi = nbi.wrapping_add(1);
                tmp = unsafe { (*tmp).next };
            }
            if (unsafe { (*tmp).okey }) == skey
                && (unsafe { (*tmp).len }) == len
                && (unsafe { xmlStrQEqual(prefix, name, (*tmp).name) }) != 0
            {
                return unsafe { (*tmp).name };
            }
        }
        key = okey.wrapping_rem(unsafe { (*dict).size });
    }
    ret = xmlDictAddQString(dict, prefix, plen, name, l);
    if ret.is_null() {
        return 0 as *const xmlChar;
    }
    if insert.is_null() {
        entry = (unsafe { &mut *((*dict).dict).offset(key as isize) }) as *mut _xmlDictEntry;
    } else {
        entry = (unsafe {
            xmlMalloc.expect("non-null function pointer")(
                ::std::mem::size_of::<xmlDictEntry>() as u64
            )
        }) as xmlDictEntryPtr;
        if entry.is_null() {
            return 0 as *const xmlChar;
        }
    }
    let fresh39 = unsafe { &mut ((*entry).name) };
    *fresh39 = ret;
    (unsafe { (*entry).len = len });
    let fresh40 = unsafe { &mut ((*entry).next) };
    *fresh40 = 0 as *mut _xmlDictEntry;
    (unsafe { (*entry).valid = 1 as i32 });
    (unsafe { (*entry).okey = okey });
    if !insert.is_null() {
        let fresh41 = unsafe { &mut ((*insert).next) };
        *fresh41 = entry;
    }
    let fresh42 = unsafe { &mut ((*dict).nbElems) };
    *fresh42 = (*fresh42).wrapping_add(1);
    if nbi > 3 as i32 as u64
        && (unsafe { (*dict).size }) <= (8 as i32 * 2048 as i32 / 2 as i32 / 3 as i32) as u64
    {
        xmlDictGrow(
            dict,
            ((3 as i32 * 2 as i32) as u64).wrapping_mul(unsafe { (*dict).size }),
        );
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlDictOwns(
    mut dict: *mut crate::src::dict::_xmlDict,
    mut str: *const u8,
) -> i32 {
    let mut pool: *mut crate::src::dict::_xmlDictStrings = 0 as *mut xmlDictStrings;
    if dict.is_null() || str.is_null() {
        return -(1 as i32);
    }
    pool = unsafe { (*dict).strings };
    while !pool.is_null() {
        if str
            >= (unsafe { &mut *((*pool).array).as_mut_ptr().offset(0 as i32 as isize) })
                as *mut xmlChar as *const xmlChar
            && str <= (unsafe { (*pool).free }) as *const xmlChar
        {
            return 1 as i32;
        }
        pool = unsafe { (*pool).next };
    }
    if !(unsafe { (*dict).subdict }).is_null() {
        return xmlDictOwns(unsafe { (*dict).subdict }, str);
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlDictSize<'a1>(mut dict: Option<&'a1 mut crate::src::dict::_xmlDict>) -> i32 {
    if borrow(&dict).is_none() {
        return -(1 as i32);
    }
    if !((*(borrow_mut(&mut dict)).unwrap()).subdict).is_null() {
        return ((*(borrow(&dict)).unwrap()).nbElems)
            .wrapping_add(unsafe { (*(*(borrow(&dict)).unwrap()).subdict).nbElems })
            as i32;
    }
    return (*(borrow(&dict)).unwrap()).nbElems as i32;
}
#[no_mangle]
pub extern "C" fn xmlDictSetLimit(
    mut dict: *mut crate::src::dict::_xmlDict,
    mut limit: u64,
) -> u64 {
    let mut ret: u64 = 0;
    if dict.is_null() {
        return 0 as i32 as size_t;
    }
    ret = unsafe { (*dict).limit };
    (unsafe { (*dict).limit = limit });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlDictGetUsage<'a1>(
    mut dict: Option<&'a1 mut crate::src::dict::_xmlDict>,
) -> u64 {
    let mut pool: *mut crate::src::dict::_xmlDictStrings = 0 as *mut xmlDictStrings;
    let mut limit: u64 = 0 as i32 as size_t;
    if borrow(&dict).is_none() {
        return 0 as i32 as size_t;
    }
    pool = (*(borrow_mut(&mut dict)).unwrap()).strings;
    while !pool.is_null() {
        limit = (limit as u64).wrapping_add(unsafe { (*pool).size }) as size_t as size_t;
        pool = unsafe { (*pool).next };
    }
    return limit;
}
use crate::laertes_rt::*;
